use std::time::{Duration, Instant};

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use reqwest::header::{HeaderMap, ACCEPT, AUTHORIZATION, CONTENT_TYPE, SET_COOKIE};
use reqwest::{Method, Response, StatusCode};
use serde_json::Value;
use tokio::sync::Mutex;

use crate::error::{Error, Result};
use crate::models::{find_stat_record, DeleteProcess, Protocol, Query, SignonBody, SubmitProcess};

const API_PREFIX: &str = "/cdwebconsole/svc";
/// Fixní XSRF hodnota pro sign-on ("checkit" v base64) – viz dokumentace CDWS.
const SIGNON_XSRF: &str = "Y2hlY2tpdA==";
const XSRF_HEADER: &str = "X-XSRF-TOKEN";

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

        let mut builder = reqwest::Client::builder()
            .cookie_store(true)
            .timeout(cfg.timeout)
            .danger_accept_invalid_certs(cfg.accept_invalid_certs);

        for pem in &cfg.extra_root_certs_pem {
            if !contains_pem_block(pem, "CERTIFICATE") {
                return Err(Error::Config(
                    "CA certificate is not a PEM `CERTIFICATE` block".into(),
                ));
            }
            let cert = reqwest::Certificate::from_pem(pem)
                .map_err(|e| Error::Config(format!("invalid CA certificate: {e}")))?;
            builder = builder.add_root_certificate(cert);
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

        Ok(Self {
            http: builder.build()?,
            cfg,
            session: Mutex::new(None),
        })
    }

    fn url(&self, path: &str) -> String {
        format!(
            "{}{}/{}",
            self.cfg.base_url.trim_end_matches('/'),
            API_PREFIX,
            path.trim_start_matches('/')
        )
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

        let mut req = self
            .http
            .post(self.url("signon"))
            .header(CONTENT_TYPE, "application/json")
            .header(ACCEPT, "application/json")
            .header(XSRF_HEADER, SIGNON_XSRF)
            .json(&body);

        req = match &self.cfg.credentials {
            Credentials::Basic { user, password } => {
                let token = B64.encode(format!("{user}:{password}"));
                req.header(AUTHORIZATION, format!("Basic {token}"))
            }
            Credentials::Certificate { .. } => req.header("CertificateAuthentication", "true"),
        };

        let resp = req.send().await?;
        let status = resp.status();
        let headers = resp.headers().clone();
        let text = resp.text().await?;
        if !status.is_success() {
            return Err(Error::Api { status, body: text });
        }

        let authorization =
            header_str(&headers, "authorization").ok_or(Error::MissingHeader("Authorization"))?;
        let xsrf = header_str(&headers, "_csrf")
            .or_else(|| header_str(&headers, XSRF_HEADER))
            .or_else(|| xsrf_from_cookies(&headers))
            .ok_or(Error::MissingHeader("_csrf"))?;

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
                .delete(self.url("signout"))
                .header(AUTHORIZATION, &s.authorization)
                .header(XSRF_HEADER, &s.xsrf)
                .header(ACCEPT, "application/json")
                .send()
                .await?;
            check(resp).await?;
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
        let mut retried = false;
        loop {
            let s = self.current_session().await?;
            let mut req = self
                .http
                .request(method.clone(), self.url(path))
                .header(AUTHORIZATION, &s.authorization)
                .header(XSRF_HEADER, &s.xsrf)
                .header(ACCEPT, "application/json");
            if !query.params.is_empty() {
                req = req.query(&query.params);
            }
            if let Some(b) = body {
                req = req.json(b);
            }

            let resp = req.send().await?;
            if resp.status() == StatusCode::UNAUTHORIZED && self.cfg.auto_resignon && !retried {
                retried = true;
                *self.session.lock().await = None;
                continue;
            }
            return check(resp).await;
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
        let body = serde_json::to_value(p)?;
        self.call(
            Method::POST,
            "processcontrolcriterias",
            &Query::new(),
            Some(&body),
        )
        .await
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
        let start = Instant::now();
        loop {
            let stats = self
                .select_statistics(&Query::process_number(process_number))
                .await?;
            if let Some(rec) = find_stat_record(&stats, "PRED") {
                return Ok(rec.clone());
            }
            if start.elapsed() >= timeout {
                return Err(Error::Timeout(process_number));
            }
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

async fn check(resp: Response) -> Result<Value> {
    let status = resp.status();
    let text = resp.text().await?;
    if status.is_success() {
        Ok(parse_body(&text))
    } else {
        Err(Error::Api { status, body: text })
    }
}
