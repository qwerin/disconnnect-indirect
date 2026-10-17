use std::time::{Duration, Instant};

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use reqwest::header::{HeaderMap, ACCEPT, AUTHORIZATION, CONTENT_TYPE, LOCATION, SET_COOKIE};
use reqwest::{Method, Response, StatusCode, Url};
use serde_json::Value;
use tokio::sync::Mutex;
use tracing::{debug, error, info, trace, warn};

use crate::error::{error_chain, Error, Result};
use crate::models::{
    completion_code, extract_process_number, find_stat_record, DeleteProcess, Protocol, Query,
    SignonBody, SubmitProcess,
};
use crate::text::{sanitize, truncate_sanitized as truncate};

const API_PREFIX: &str = "/cdwebconsole/svc";
/// Fixní XSRF hodnota pro sign-on ("checkit" v base64) – viz dokumentace CDWS.
const SIGNON_XSRF: &str = "Y2hlY2tpdA==";
const XSRF_HEADER: &str = "X-XSRF-TOKEN";
/// Maximální délka JWT / XSRF tokenu ze sign-on (ochrana proti zlému serveru).
const MAX_TOKEN_LEN: usize = 16 * 1024;
/// Výchozí limit velikosti odpovědi.
pub const DEFAULT_MAX_RESPONSE_BYTES: u64 = 64 * 1024 * 1024;

/// Jak se autentizovat vůči C:D uzlu.
#[derive(Clone)]
pub enum Credentials {
    /// Uživatel a heslo C:D uzlu (posílá se jako HTTP Basic při sign-on).
    Basic { user: String, password: String },
    /// Certifikátová autentizace: PEM obsahující klientský certifikát + privátní klíč.
    /// CDWS musí mít otisk certifikátu v `application.properties`.
    Certificate { identity_pem: Vec<u8> },
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Credentials::Basic { user, .. } => {
                write!(f, "Basic {{ user: {user:?}, password: *** }}")
            }
            Credentials::Certificate { .. } => write!(f, "Certificate {{ .. }}"),
        }
    }
}

/// Konfigurace klienta.
#[derive(Debug, Clone)]
pub struct Config {
    /// Base URL Connect:Direct Web Services, např. `https://cdws.example.com:9443`.
    pub base_url: String,
    /// Hostname/IP C:D uzlu, ke kterému se CDWS připojí.
    pub node_host: String,
    /// API port C:D uzlu (typicky 1363).
    pub node_port: u16,
    pub protocol: Protocol,
    pub credentials: Credentials,
    /// Další důvěryhodné CA certifikáty (PEM) pro HTTPS k CDWS.
    pub extra_root_certs_pem: Vec<Vec<u8>>,
    /// Vypne ověřování TLS certifikátu CDWS. Jen pro testovací prostředí!
    pub accept_invalid_certs: bool,
    pub timeout: Duration,
    /// Při 401 se automaticky znovu přihlásí a request jednou zopakuje.
    pub auto_resignon: bool,
    /// Maximální velikost těla odpovědi v bajtech (ochrana paměti), výchozí 64 MiB.
    pub max_response_bytes: u64,
}

impl Config {
    pub fn new(
        base_url: impl Into<String>,
        node_host: impl Into<String>,
        user: impl Into<String>,
        password: impl Into<String>,
    ) -> Self {
        Self {
            base_url: base_url.into(),
            node_host: node_host.into(),
            node_port: 1363,
            protocol: Protocol::Tcpip,
            credentials: Credentials::Basic {
                user: user.into(),
                password: password.into(),
            },
            extra_root_certs_pem: Vec::new(),
            accept_invalid_certs: false,
            timeout: Duration::from_secs(120),
            auto_resignon: true,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
        }
    }
}

#[derive(Debug, Clone)]
struct Session {
    authorization: String,
    xsrf: String,
}

/// Async klient pro Connect:Direct Web Services REST API.
///
/// Klient je `Send + Sync`, lze ho sdílet přes `Arc` mezi tasky.
/// Session (JWT + XSRF token) se získá líně při prvním volání.
pub struct CdClient {
    http: reqwest::Client,
    cfg: Config,
    session: Mutex<Option<Session>>,
}

impl CdClient {
    pub fn new(cfg: Config) -> Result<Self> {
        if !cfg.base_url.starts_with("http://") && !cfg.base_url.starts_with("https://") {
            return Err(Error::Config(
                "base_url must start with http:// or https://".into(),
            ));
        }

        let parsed = Url::parse(&cfg.base_url)
            .map_err(|e| Error::Config(format!("invalid base_url: {e}")))?;
        if parsed.query().is_some() || parsed.fragment().is_some() || !parsed.username().is_empty()
        {
            return Err(Error::Config(
                "base_url must not contain credentials, query or fragment".into(),
            ));
        }
        if cfg.timeout.is_zero() {
            return Err(Error::Config("timeout must be greater than zero".into()));
        }
        if cfg.max_response_bytes == 0 {
            return Err(Error::Config(
                "max_response_bytes must be greater than zero".into(),
            ));
        }

        let mut builder = reqwest::Client::builder()
            // CDWS nepřesměrovává; přesměrování by mohlo poslat session token cizímu serveru
            .redirect(reqwest::redirect::Policy::none())
            .cookie_store(true)
            .timeout(cfg.timeout)
            .tls_danger_accept_invalid_certs(cfg.accept_invalid_certs);

        for pem in &cfg.extra_root_certs_pem {
            if !contains_pem_block(pem, "CERTIFICATE") {
                return Err(Error::Config(
                    "CA certificate is not a PEM `CERTIFICATE` block".into(),
                ));
            }
            let cert = reqwest::Certificate::from_pem(pem)
                .map_err(|e| Error::Config(format!("invalid CA certificate: {e}")))?;
            // přidá se k systémovým kořenovým certifikátům (rustls-platform-verifier)
            builder = builder.tls_certs_merge([cert]);
        }

        if let Credentials::Certificate { identity_pem } = &cfg.credentials {
            if !contains_pem_block(identity_pem, "CERTIFICATE")
                || !contains_pem_block(identity_pem, "PRIVATE KEY")
            {
                return Err(Error::Config(
                    "client identity PEM must contain a certificate and a private key".into(),
                ));
            }
            let id = reqwest::Identity::from_pem(identity_pem)
                .map_err(|e| Error::Config(format!("invalid client identity PEM: {e}")))?;
            builder = builder.identity(id);
        }

        if cfg.accept_invalid_certs {
            warn!(base_url = %cfg.base_url, "TLS certificate verification is DISABLED");
        }
        debug!(
            base_url = %cfg.base_url,
            node = %cfg.node_host,
            port = cfg.node_port,
            protocol = cfg.protocol.as_str(),
            extra_ca_certs = cfg.extra_root_certs_pem.len(),
            timeout_s = cfg.timeout.as_secs(),
            "CDWS client created"
        );

        Ok(Self {
            http: builder.build()?,
            cfg,
            session: Mutex::new(None),
        })
    }

    fn url(&self, path: &str) -> Result<Url> {
        build_url(&self.cfg.base_url, path)
    }

    // ---------------------------------------------------------------- session

    /// Explicitní přihlášení. Vrací tělo odpovědi CDWS.
    pub async fn sign_on(&self) -> Result<Value> {
        let mut guard = self.session.lock().await;
        let (session, body) = self.do_sign_on().await?;
        *guard = Some(session);
        Ok(body)
    }

    async fn do_sign_on(&self) -> Result<(Session, Value)> {
        let body = SignonBody {
            ip_address: &self.cfg.node_host,
            port: self.cfg.node_port,
            protocol: self.cfg.protocol.as_str(),
        };

        let req = self
            .http
            .post(self.url("signon")?)
            .header(CONTENT_TYPE, "application/json")
            .header(ACCEPT, "application/json")
            .header(XSRF_HEADER, SIGNON_XSRF)
            .json(&body);

        let (req, auth_kind, user) = match &self.cfg.credentials {
            Credentials::Basic { user, password } => {
                let token = B64.encode(format!("{user}:{password}"));
                (
                    req.header(AUTHORIZATION, format!("Basic {token}")),
                    "basic",
                    user.as_str(),
                )
            }
            Credentials::Certificate { .. } => (
                req.header("CertificateAuthentication", "true"),
                "certificate",
                "-",
            ),
        };

        info!(
            node = %self.cfg.node_host,
            port = self.cfg.node_port,
            protocol = self.cfg.protocol.as_str(),
            auth = auth_kind,
            user,
            "signing on to Connect:Direct"
        );
        let started = Instant::now();

        let resp = req.send().await.inspect_err(|e| {
            error!(error = %sanitize(&error_chain(e)), "sign-on request failed");
        })?;
        let status = resp.status();
        let headers = resp.headers().clone();
        if status.is_redirection() {
            let body = redirect_refused(&headers);
            error!(status = status.as_u16(), body = %sanitize(&body), "sign-on rejected");
            return Err(Error::Api { status, body });
        }
        let text = read_body(resp, self.cfg.max_response_bytes).await?;
        let elapsed_ms = started.elapsed().as_millis() as u64;
        if !status.is_success() {
            error!(
                status = status.as_u16(),
                elapsed_ms,
                body = %truncate(&text, 500),
                "sign-on rejected"
            );
            return Err(Error::Api { status, body: text });
        }

        let authorization = header_str(&headers, "authorization").ok_or_else(|| {
            error!("sign-on response has no Authorization header");
            Error::MissingHeader("Authorization")
        })?;
        let xsrf = header_str(&headers, "_csrf")
            .or_else(|| header_str(&headers, XSRF_HEADER))
            .or_else(|| {
                let v = xsrf_from_cookies(&headers);
                if v.is_some() {
                    debug!("XSRF token taken from XSRF-TOKEN cookie");
                }
                v
            })
            .ok_or_else(|| {
                error!("sign-on response has no _csrf header or XSRF-TOKEN cookie");
                Error::MissingHeader("_csrf")
            })?;
        if authorization.len() > MAX_TOKEN_LEN || xsrf.len() > MAX_TOKEN_LEN {
            error!("sign-on token exceeds {MAX_TOKEN_LEN} bytes");
            return Err(Error::InvalidInput(format!(
                "sign-on token exceeds {MAX_TOKEN_LEN} bytes"
            )));
        }
        info!(elapsed_ms, "signed on");

        Ok((
            Session {
                authorization,
                xsrf,
            },
            parse_body(&text),
        ))
    }

    async fn current_session(&self) -> Result<Session> {
        let mut guard = self.session.lock().await;
        if let Some(s) = guard.as_ref() {
            return Ok(s.clone());
        }
        let (s, _) = self.do_sign_on().await?;
        *guard = Some(s.clone());
        Ok(s)
    }

    /// Odhlášení a zahození session. Volejte na konci práce (Drop nemůže být async).
    pub async fn sign_out(&self) -> Result<()> {
        let session = self.session.lock().await.take();
        if let Some(s) = session {
            let resp = self
                .http
                .delete(self.url("signout")?)
                .header(AUTHORIZATION, &s.authorization)
                .header(XSRF_HEADER, &s.xsrf)
                .header(ACCEPT, "application/json")
                .send()
                .await?;
            check(resp, self.cfg.max_response_bytes)
                .await
                .inspect_err(|e| warn!(error = %sanitize(&error_chain(e)), "sign-out failed"))?;
            info!("signed out");
        }
        Ok(())
    }

    // ---------------------------------------------------------------- generic

    /// Obecné volání libovolného CDWS endpointu (netmap, user proxy, ...).
    /// `path` je relativní k `/cdwebconsole/svc/`.
    pub async fn call(
        &self,
        method: Method,
        path: &str,
        query: &Query,
        body: Option<&Value>,
    ) -> Result<Value> {
        let url = self.url(path).inspect_err(|e| {
            warn!(error = %sanitize(&e.to_string()), "rejected API path");
        })?;
        let path = url.path().to_string();
        let path = path.as_str();
        let mut retried = false;
        loop {
            let s = self.current_session().await?;
            debug!(%method, path, query = ?query.params, retry = retried, "request");
            if let Some(b) = body {
                trace!(%method, path, body = %sanitize(&b.to_string()), "request body");
            }
            let started = Instant::now();
            let mut req = self
                .http
                .request(method.clone(), url.clone())
                .header(AUTHORIZATION, &s.authorization)
                .header(XSRF_HEADER, &s.xsrf)
                .header(ACCEPT, "application/json");
            if !query.params.is_empty() {
                req = req.query(&query.params);
            }
            if let Some(b) = body {
                req = req.json(b);
            }

            let resp = req.send().await.inspect_err(|e| {
                error!(%method, path, error = %sanitize(&error_chain(e)), "request failed");
            })?;
            let status = resp.status();
            if status == StatusCode::UNAUTHORIZED && self.cfg.auto_resignon && !retried {
                warn!(%method, path, "session rejected (401), signing on again");
                retried = true;
                *self.session.lock().await = None;
                continue;
            }
            let result = check(resp, self.cfg.max_response_bytes).await;
            let elapsed_ms = started.elapsed().as_millis() as u64;
            match &result {
                Ok(v) => {
                    debug!(%method, path, status = status.as_u16(), elapsed_ms, "response");
                    trace!(%method, path, body = %sanitize(&v.to_string()), "response body");
                }
                Err(Error::Api { status, body }) => warn!(
                    %method,
                    path,
                    status = status.as_u16(),
                    elapsed_ms,
                    body = %truncate(body, 500),
                    "CDWS returned an error"
                ),
                Err(e) => error!(
                    %method,
                    path,
                    error = %sanitize(&error_chain(e)),
                    "reading response failed"
                ),
            }
            return result;
        }
    }

    // ---------------------------------------------------------------- API

    /// Verze CDWS (endpoint existuje od CDWS 6.3.0.9).
    pub async fn version(&self) -> Result<Value> {
        self.call(Method::GET, "version", &Query::new(), None).await
    }

    /// Submit procesu. Číslo procesu z odpovědi získáte přes
    /// [`crate::extract_process_number`].
    pub async fn submit_process(&self, p: &SubmitProcess) -> Result<Value> {
        info!(
            process = %describe_process(&p.process_file),
            snode = %sanitize(&p.secondary_node),
            hold = %sanitize(&p.hold),
            max_delay = %sanitize(&p.max_delay),
            "submitting process"
        );
        let body = serde_json::to_value(p)?;
        let resp = self
            .call(
                Method::POST,
                "processcontrolcriterias",
                &Query::new(),
                Some(&body),
            )
            .await?;
        match extract_process_number(&resp) {
            Some(n) => info!(process_number = n, "process submitted"),
            None => warn!("process submitted, but no process number found in response"),
        }
        Ok(resp)
    }

    /// Zkratka: submit procesu zadaného textem.
    pub async fn submit_text(&self, process_text: impl Into<String>) -> Result<Value> {
        self.submit_process(&SubmitProcess::new(process_text)).await
    }

    /// Výpis procesů ve frontě (Select Process).
    pub async fn select_process(&self, q: &Query) -> Result<Value> {
        self.call(Method::GET, "processcontrolcriterias", q, None)
            .await
    }

    /// Smazání procesu z fronty.
    pub async fn delete_process(&self, d: &DeleteProcess) -> Result<Value> {
        if d.is_empty_filter() {
            return Err(Error::InvalidProcess(
                "delete needs processName, processNumber, submitter or secondaryNode".into(),
            ));
        }
        info!(
            process_name = %sanitize(&d.process_name),
            process_number = %sanitize(&d.process_number),
            snode = %sanitize(&d.secondary_node),
            submitter = %sanitize(&d.submitter),
            force = %sanitize(&d.force),
            "deleting process"
        );
        let body = serde_json::to_value(d)?;
        self.call(
            Method::DELETE,
            "processcontrolcriterias",
            &Query::new(),
            Some(&body),
        )
        .await
    }

    /// Select Statistics.
    pub async fn select_statistics(&self, q: &Query) -> Result<Value> {
        self.call(Method::GET, "selectstatistics", q, None).await
    }

    /// Polluje statistiky, dokud se neobjeví záznam `PRED` (Process End),
    /// a vrátí ho. Completion code z něj vytáhnete přes [`crate::completion_code`].
    ///
    /// Pozn.: hledání záznamu je heuristické – ověřte názvy polí ve statistikách
    /// vaší verze CDWS. Alternativa: submit s `max_delay("unlimited")`.
    pub async fn wait_for_process_end(
        &self,
        process_number: u64,
        poll: Duration,
        timeout: Duration,
    ) -> Result<Value> {
        info!(
            process_number,
            poll_ms = poll.as_millis() as u64,
            timeout_s = timeout.as_secs(),
            "waiting for process to finish"
        );
        let start = Instant::now();
        let mut polls = 0u32;
        loop {
            polls += 1;
            let stats = self
                .select_statistics(&Query::process_number(process_number))
                .await?;
            if let Some(rec) = find_stat_record(&stats, "PRED") {
                let ccode = completion_code(rec);
                let elapsed_s = start.elapsed().as_secs();
                match ccode.as_deref() {
                    Some("0") => {
                        info!(
                            process_number,
                            ccode = "0",
                            elapsed_s,
                            polls,
                            "process finished OK"
                        )
                    }
                    other => warn!(
                        process_number,
                        ccode = %sanitize(other.unwrap_or("?")),
                        elapsed_s,
                        polls,
                        "process finished with non-zero completion code"
                    ),
                }
                return Ok(rec.clone());
            }
            if start.elapsed() >= timeout {
                error!(process_number, polls, "timed out waiting for process");
                return Err(Error::Timeout(process_number));
            }
            debug!(process_number, polls, "process still running");
            tokio::time::sleep(poll).await;
        }
    }
}

// -------------------------------------------------------------------- helpers

/// Hrubá kontrola, že PEM obsahuje blok daného typu (např. `CERTIFICATE`,
/// `PRIVATE KEY` pokryje i `RSA PRIVATE KEY` / `EC PRIVATE KEY`).
fn contains_pem_block(pem: &[u8], kind: &str) -> bool {
    let text = String::from_utf8_lossy(pem);
    text.lines()
        .any(|l| l.starts_with("-----BEGIN ") && l.contains(kind) && l.ends_with("-----"))
}

/// Sestaví URL endpointu a ověří, že zůstane pod `<base>/cdwebconsole/svc/`.
///
/// Cesta smí obsahovat jen `A–Z a–z 0–9 / _ - .` a žádný segment `.`/`..`
/// (ochrana proti `../`, `%2e%2e`, vkládání query a podobným trikům).
pub(crate) fn build_url(base: &str, path: &str) -> Result<Url> {
    let ok_chars = path
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '_' | '-' | '.'));
    let bad_segment = path.split('/').any(|seg| seg == "." || seg == "..");
    if !ok_chars || bad_segment || path.len() > 512 {
        return Err(Error::InvalidInput(format!(
            "invalid API path `{}` (allowed: letters, digits, / _ - . ; use Query for parameters)",
            truncate(path, 200)
        )));
    }
    let base_url = Url::parse(base).map_err(|e| Error::Config(format!("invalid base_url: {e}")))?;
    let prefix = format!("{}{}/", base_url.path().trim_end_matches('/'), API_PREFIX);
    let raw = format!(
        "{}{}/{}",
        base.trim_end_matches('/'),
        API_PREFIX,
        path.trim_start_matches('/')
    );
    let url =
        Url::parse(&raw).map_err(|e| Error::InvalidInput(format!("invalid API path: {e}")))?;
    if url.origin() != base_url.origin()
        || !url.path().starts_with(&prefix)
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(Error::InvalidInput(format!(
            "API path `{}` escapes {prefix}",
            truncate(path, 200)
        )));
    }
    Ok(url)
}

/// Přečte tělo odpovědi nejvýše do `limit` bajtů.
async fn read_body(mut resp: Response, limit: u64) -> Result<String> {
    if resp.content_length().is_some_and(|len| len > limit) {
        warn!(limit, "response Content-Length exceeds limit");
        return Err(Error::ResponseTooLarge { limit });
    }
    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = resp.chunk().await? {
        if buf.len() as u64 + chunk.len() as u64 > limit {
            warn!(limit, "response body exceeds limit");
            return Err(Error::ResponseTooLarge { limit });
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

fn redirect_refused(headers: &HeaderMap) -> String {
    let loc = headers
        .get(LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("?");
    format!(
        "redirect to {} refused (redirects are not followed)",
        truncate(loc, 200)
    )
}

/// Krátký popis procesu pro log: první řádek textu, nebo cesta k .cdp souboru.
fn describe_process(process_file: &str) -> String {
    let first = process_file.lines().next().unwrap_or("").trim();
    truncate(first, 120)
}

fn header_str(h: &HeaderMap, name: &str) -> Option<String> {
    h.get(name)?
        .to_str()
        .ok()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
}

/// Fallback: XSRF token z cookie `XSRF-TOKEN`.
fn xsrf_from_cookies(h: &HeaderMap) -> Option<String> {
    h.get_all(SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find_map(|c| {
            let first = c.split(';').next()?.trim();
            let (k, v) = first.split_once('=')?;
            (k.eq_ignore_ascii_case("XSRF-TOKEN") && !v.is_empty()).then(|| v.to_string())
        })
}

fn parse_body(text: &str) -> Value {
    if text.trim().is_empty() {
        Value::Null
    } else {
        serde_json::from_str(text).unwrap_or_else(|_| Value::String(text.to_string()))
    }
}

async fn check(resp: Response, limit: u64) -> Result<Value> {
    let status = resp.status();
    if status.is_redirection() {
        return Err(Error::Api {
            status,
            body: redirect_refused(resp.headers()),
        });
    }
    let text = read_body(resp, limit).await?;
    if status.is_success() {
        Ok(parse_body(&text))
    } else {
        Err(Error::Api { status, body: text })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const BASE: &str = "https://cdws.example.com:9443";

    #[test]
    fn builds_normal_paths() {
        assert_eq!(
            build_url(BASE, "signon").unwrap().as_str(),
            "https://cdws.example.com:9443/cdwebconsole/svc/signon"
        );
        assert_eq!(
            build_url(&format!("{BASE}/"), "/netmap/nodes")
                .unwrap()
                .path(),
            "/cdwebconsole/svc/netmap/nodes"
        );
        // base za reverzní proxy s vlastní cestou
        assert_eq!(
            build_url("https://h/proxy/", "version").unwrap().path(),
            "/proxy/cdwebconsole/svc/version"
        );
    }

    #[test]
    fn rejects_escapes_and_injection() {
        for bad in [
            "../../../etc/passwd",
            "a/../../b",
            "%2e%2e/%2e%2e/admin",
            "..%2fadmin",
            "version?admin=true",
            "version#x",
            "a\\..\\b",
            "a b",
            "a\nb",
            ".",
            "x/./y",
            "https://evil.example.com/",
        ] {
            assert!(build_url(BASE, bad).is_err(), "{bad:?} must be rejected");
        }
    }

    #[test]
    fn leading_slashes_stay_inside_prefix() {
        let url = build_url(BASE, "//evil.example.com/x").unwrap();
        assert_eq!(url.host_str(), Some("cdws.example.com"));
        assert_eq!(url.path(), "/cdwebconsole/svc/evil.example.com/x");
    }

    #[test]
    fn rejects_bad_base() {
        assert!(build_url("not a url", "x").is_err());
    }

    #[test]
    fn describes_process_safely() {
        assert_eq!(describe_process("P PROCESS\nSNODE=X"), "P PROCESS");
        assert_eq!(describe_process("\u{1b}[2J PROCESS"), "\\u{1b}[2J PROCESS");
    }

    fn traversal_path() -> impl Strategy<Value = String> {
        prop_oneof![
            any::<String>(),
            "[a-z./%2eE?#\\\\:@ -]{0,30}",
            prop::collection::vec(
                prop_oneof![Just(".."), Just("."), Just("%2e%2e"), Just("a"), Just("")],
                0..6
            )
            .prop_map(|v| v.join("/")),
        ]
    }

    proptest! {
        #[test]
        fn prop_url_never_escapes_api_prefix(path in traversal_path()) {
            if let Ok(url) = build_url(BASE, &path) {
                prop_assert!(url.path().starts_with("/cdwebconsole/svc/"), "{url}");
                prop_assert_eq!(url.host_str(), Some("cdws.example.com"));
                prop_assert_eq!(url.port(), Some(9443));
                prop_assert!(url.query().is_none() && url.fragment().is_none());
                prop_assert!(!url.path().split('/').any(|s| s == ".." || s == "."));
            }
        }
    }
}
