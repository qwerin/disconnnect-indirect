//! `cdctl` – CLI nad knihovnou connect-direct.
//!
//! Nastavení se skládá v pořadí priorit:
//! přepínač > proměnná prostředí > konfigurační soubor > výchozí hodnota.
//!
//! * konfigurace: `/etc/cdctl/config.toml` (nebo `--config` / `CDCTL_CONFIG`), viz `config.example.toml`
//! * log: `/var/log/cdctl/cdctl.<datum>.log` (nebo `[log] dir` / `--log-dir` / `CDCTL_LOG_DIR`)

mod config;
mod logging;

use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use clap::{Args, Parser, Subcommand};
use connect_direct::{
    completion_code, error_chain, extract_process_number, sanitize, CdClient, Config, CopyProcess,
    DeleteProcess, Direction, Disp, Method, Protocol, Query, SubmitProcess,
};
use serde_json::Value;
use tracing::{debug, error, info, warn, Instrument};

use config::{Loaded, LogFormat, Rotation, MAX_INPUT_FILE_BYTES};
use logging::{LogHandle, LogSettings};

static STDOUT_CLOSED: AtomicBool = AtomicBool::new(false);

/// Zápis na stdout. Zavřená roura (`cdctl … | head`) není chyba – zbytek výstupu se zahodí.
fn out(s: &str) {
    if STDOUT_CLOSED.load(Ordering::Relaxed) {
        return;
    }
    let mut o = std::io::stdout().lock();
    if let Err(e) = o.write_all(s.as_bytes()).and_then(|_| o.flush()) {
        STDOUT_CLOSED.store(true, Ordering::Relaxed);
        if e.kind() != std::io::ErrorKind::BrokenPipe {
            let _ = writeln!(std::io::stderr(), "warning: cannot write to stdout: {e}");
        }
    }
}

/// Řádek na stderr – zneškodněný (žádné escape sekvence ze serveru do terminálu)
/// a bez paniky, když je stderr zavřený.
macro_rules! errln {
    ($($t:tt)*) => {{
        let line = sanitize(&format!($($t)*));
        let _ = writeln!(std::io::stderr(), "{line}");
    }};
}

#[derive(Parser)]
#[command(
    name = "cdctl",
    version,
    about = "CLI pro IBM Connect:Direct Web Services",
    after_help = "Konfigurace: /etc/cdctl/config.toml (--config), log: /var/log/cdctl (--log-dir)."
)]
struct Cli {
    /// Konfigurační soubor (výchozí /etc/cdctl/config.toml, pokud existuje)
    #[arg(long, env = "CDCTL_CONFIG", global = true)]
    config: Option<PathBuf>,
    #[command(flatten)]
    conn: Conn,
    #[command(flatten)]
    log: LogArgs,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Args)]
struct Conn {
    /// Base URL CDWS, např. https://cdws:9443
    #[arg(long, env = "CDWS_URL", global = true)]
    url: Option<String>,
    /// Host C:D uzlu
    #[arg(long, env = "CD_NODE_HOST", global = true)]
    node_host: Option<String>,
    /// API port C:D uzlu (výchozí 1363)
    #[arg(long, env = "CD_NODE_PORT", global = true, value_parser = clap::value_parser!(u16).range(1..))]
    node_port: Option<u16>,
    /// TCPIP | NONE | TLS1.2 | TLS1.3 | ... (výchozí TCPIP)
    #[arg(long, env = "CD_PROTOCOL", global = true)]
    protocol: Option<String>,
    #[arg(long, env = "CD_USER", global = true)]
    user: Option<String>,
    #[arg(long, env = "CD_PASSWORD", global = true, hide_env_values = true)]
    password: Option<String>,
    /// PEM s CA certifikátem CDWS
    #[arg(long, env = "CDWS_CA_CERT", global = true)]
    ca_cert: Option<PathBuf>,
    /// Neověřovat TLS certifikát (jen test!)
    #[arg(long, env = "CDWS_INSECURE", global = true)]
    insecure: bool,
    /// Timeout HTTP požadavku v sekundách (výchozí 120)
    #[arg(long, env = "CDWS_TIMEOUT", global = true, value_parser = clap::value_parser!(u64).range(1..))]
    timeout: Option<u64>,
}

#[derive(Args)]
struct LogArgs {
    /// Adresář logů (výchozí /var/log/cdctl)
    #[arg(long, env = "CDCTL_LOG_DIR", global = true)]
    log_dir: Option<PathBuf>,
    /// error | warn | info | debug | trace, nebo filtr např. "connect_direct=debug,info"
    #[arg(long, env = "CDCTL_LOG_LEVEL", global = true)]
    log_level: Option<String>,
    /// Formát logu
    #[arg(long, env = "CDCTL_LOG_FORMAT", global = true, value_enum)]
    log_format: Option<LogFormat>,
    /// Logovat zároveň na stderr
    #[arg(long, env = "CDCTL_LOG_STDERR", global = true)]
    log_stderr: bool,
}

#[derive(Subcommand)]
enum Cmd {
    /// Verze CDWS
    Version,
    /// Submit procesu z lokálního .cdp souboru (pošle se jeho text)
    Submit {
        /// Lokální .cdp soubor
        #[arg(long, conflicts_with = "server_file")]
        file: Option<PathBuf>,
        /// Cesta k .cdp souboru na serveru C:D
        #[arg(long)]
        server_file: Option<String>,
        /// Přepsat SNODE
        #[arg(long)]
        snode: Option<String>,
        #[command(flatten)]
        wait: WaitArgs,
    },
    /// Odeslat soubor PNODE -> SNODE
    Send(CopyArgs),
    /// Stáhnout soubor SNODE -> PNODE
    Receive(CopyArgs),
    /// Statistiky procesu
    Stats {
        #[arg(long)]
        process_number: Option<u64>,
        #[arg(long)]
        process_name: Option<String>,
    },
    /// Procesy ve frontě
    Processes {
        #[arg(long)]
        process_number: Option<u64>,
        #[arg(long)]
        process_name: Option<String>,
    },
    /// Smazat proces z fronty
    Delete {
        #[arg(long)]
        process_number: u64,
        #[arg(long)]
        force: bool,
    },
    /// Libovolné volání: cdctl raw GET netmapnodes -q name=X --json '{...}'
    Raw {
        method: String,
        path: String,
        #[arg(short, long = "query", value_parser = parse_kv)]
        query: Vec<(String, String)>,
        #[arg(long)]
        json: Option<String>,
    },
    /// Vypsat výslednou konfiguraci a umístění logu (heslo se nevypisuje)
    Config,
}

impl Cmd {
    fn name(&self) -> &'static str {
        match self {
            Cmd::Version => "version",
            Cmd::Submit { .. } => "submit",
            Cmd::Send(_) => "send",
            Cmd::Receive(_) => "receive",
            Cmd::Stats { .. } => "stats",
            Cmd::Processes { .. } => "processes",
            Cmd::Delete { .. } => "delete",
            Cmd::Raw { .. } => "raw",
            Cmd::Config => "config",
        }
    }
}

#[derive(Args)]
struct CopyArgs {
    #[arg(long)]
    snode: String,
    #[arg(long)]
    from: String,
    #[arg(long)]
    to: String,
    /// Jméno procesu (max 8 znaků)
    #[arg(long, default_value = "CDCTL")]
    name: String,
    /// NEW | OLD | MOD | RPL | SHR
    #[arg(long, default_value = "RPL")]
    disp: Disp,
    /// SYSOPTS pro FROM, vloženo doslova (např. '":datatype=text:"')
    #[arg(long)]
    from_sysopts: Option<String>,
    #[arg(long)]
    to_sysopts: Option<String>,
    /// Jen vypsat vygenerovaný proces, nic neposílat
    #[arg(long)]
    dry_run: bool,
    #[command(flatten)]
    wait: WaitArgs,
}

#[derive(Args)]
struct WaitArgs {
    /// Počkat na dokončení procesu (polling statistik)
    #[arg(long)]
    wait: bool,
    /// Timeout čekání v sekundách
    #[arg(long, default_value_t = 600)]
    wait_timeout: u64,
}

type BoxError = Box<dyn std::error::Error + Send + Sync>;

fn parse_kv(s: &str) -> Result<(String, String), String> {
    s.split_once('=')
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .ok_or_else(|| format!("expected key=value, got `{s}`"))
}

// ------------------------------------------------------------------ settings

/// Výsledné nastavení připojení.
struct ConnSettings {
    url: Option<String>,
    node_host: Option<String>,
    node_port: u16,
    protocol: String,
    user: Option<String>,
    password: Option<String>,
    ca_cert: Option<PathBuf>,
    insecure: bool,
    timeout: Duration,
    max_response_bytes: u64,
}

fn conn_settings(cli: &Conn, f: &config::ConnectionSection) -> ConnSettings {
    ConnSettings {
        url: cli.url.clone().or_else(|| f.url.clone()),
        node_host: cli.node_host.clone().or_else(|| f.node_host.clone()),
        node_port: cli.node_port.or(f.node_port).unwrap_or(1363),
        protocol: cli
            .protocol
            .clone()
            .or_else(|| f.protocol.clone())
            .unwrap_or_else(|| "TCPIP".into()),
        user: cli.user.clone().or_else(|| f.user.clone()),
        password: cli.password.clone().or_else(|| f.password.clone()),
        ca_cert: cli.ca_cert.clone().or_else(|| f.ca_cert.clone()),
        insecure: cli.insecure || f.insecure.unwrap_or(false),
        timeout: Duration::from_secs(cli.timeout.or(f.timeout_secs).unwrap_or(120)),
        max_response_bytes: f
            .max_response_mb
            .unwrap_or(config::DEFAULT_MAX_RESPONSE_MB)
            .saturating_mul(1024 * 1024),
    }
}

fn log_settings(cli: &LogArgs, f: &config::LogSection) -> LogSettings {
    let (dir, dir_explicit) = match cli.log_dir.clone().or_else(|| f.dir.clone()) {
        Some(d) => (d, true),
        None => (config::default_log_dir(), false),
    };
    LogSettings {
        dir,
        dir_explicit,
        fallback_dir: config::fallback_log_dir(),
        file: f
            .file
            .clone()
            .unwrap_or_else(|| config::DEFAULT_LOG_FILE.into()),
        level: cli
            .log_level
            .clone()
            .or_else(|| f.level.clone())
            .unwrap_or_else(|| config::DEFAULT_LOG_LEVEL.into()),
        format: cli.log_format.or(f.format).unwrap_or(LogFormat::Text),
        rotation: f.rotation.unwrap_or(Rotation::Daily),
        max_files: f.max_files.unwrap_or(config::DEFAULT_MAX_LOG_FILES),
        stderr: cli.log_stderr || f.stderr.unwrap_or(false),
    }
}

fn build_client(c: &ConnSettings) -> Result<CdClient, BoxError> {
    let need = |v: &Option<String>, what: &str| -> Result<String, BoxError> {
        v.clone()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| format!("missing {what}").into())
    };
    let url = need(&c.url, "CDWS_URL / --url / [connection] url")?;
    let host = need(
        &c.node_host,
        "CD_NODE_HOST / --node-host / [connection] node_host",
    )?;
    let user = need(&c.user, "CD_USER / --user / [connection] user")?;
    if c.password.as_deref().unwrap_or("").is_empty() {
        warn!("no password configured (CD_PASSWORD / --password / [connection] password)");
    }

    let mut cfg = Config::new(url, host, user, c.password.clone().unwrap_or_default());
    cfg.node_port = c.node_port;
    cfg.protocol = c.protocol.parse::<Protocol>().unwrap();
    cfg.accept_invalid_certs = c.insecure;
    cfg.timeout = c.timeout;
    cfg.max_response_bytes = c.max_response_bytes;
    if let Some(p) = &c.ca_cert {
        let pem = config::read_limited(p, MAX_INPUT_FILE_BYTES)
            .map_err(|e| format!("CA certificate: {e}"))?;
        cfg.extra_root_certs_pem.push(pem);
    }
    Ok(CdClient::new(cfg)?)
}

// ------------------------------------------------------------------ helpers

fn print(v: &Value) {
    // serde_json escapuje řídicí znaky v řetězcích, výstup je bezpečný pro terminál
    let mut text = serde_json::to_string_pretty(v).unwrap_or_else(|_| v.to_string());
    text.push('\n');
    out(&text);
}

/// Argumenty příkazové řádky pro log – s maskovaným heslem.
fn sanitized_args() -> String {
    let mut out = Vec::new();
    let mut mask_next = false;
    for a in std::env::args().skip(1) {
        if mask_next {
            out.push("***".to_string());
            mask_next = false;
        } else if a == "--password" {
            out.push(a);
            mask_next = true;
        } else if a.starts_with("--password=") {
            out.push("--password=***".to_string());
        } else {
            out.push(a);
        }
    }
    sanitize(&out.join(" "))
}

fn os_user() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "?".into())
}

fn run_id() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!(
        "{:08x}",
        (nanos as u64 ^ (std::process::id() as u64) << 32) as u32
    )
}

async fn submit_and_maybe_wait(
    client: &CdClient,
    sp: SubmitProcess,
    w: &WaitArgs,
) -> Result<bool, BoxError> {
    let resp = client.submit_process(&sp).await?;
    print(&resp);
    if !w.wait {
        return Ok(true);
    }
    let pnum =
        extract_process_number(&resp).ok_or("process number not found in submit response")?;
    errln!("Čekám na dokončení procesu {pnum} ...");
    let rec = client
        .wait_for_process_end(
            pnum,
            Duration::from_secs(5),
            Duration::from_secs(w.wait_timeout),
        )
        .await?;
    print(&rec);
    let cc = completion_code(&rec);
    errln!("Completion code: {}", cc.as_deref().unwrap_or("?"));
    Ok(matches!(cc.as_deref(), Some("0") | None))
}

fn copy_process(dir: Direction, a: &CopyArgs) -> CopyProcess {
    let mut p = CopyProcess::new(dir, &a.name, &a.snode, &a.from, &a.to).disp(a.disp);
    if let Some(s) = &a.from_sysopts {
        p = p.from_sysopts(s);
    }
    if let Some(s) = &a.to_sysopts {
        p = p.to_sysopts(s);
    }
    p
}

fn query(n: Option<u64>, name: &Option<String>) -> Query {
    let mut q = Query::new();
    if let Some(n) = n {
        q = q.param("processNumber", n.to_string());
    }
    if let Some(name) = name {
        q = q.param("processName", name);
    }
    q
}

fn show_config(loaded: &Loaded, conn: &ConnSettings, ls: &LogSettings, log: &LogHandle) {
    use std::fmt::Write as _;
    let opt = |v: &Option<String>| v.clone().unwrap_or_else(|| "(not set)".into());
    let config_file = match &loaded.path {
        Some(p) => p.display().to_string(),
        None => format!(
            "(none – {} not found, using defaults)",
            config::default_config_path().display()
        ),
    };
    let password = if conn.password.as_deref().unwrap_or("").is_empty() {
        "(not set)"
    } else {
        "*** (set)"
    };
    let ca_cert = conn
        .ca_cert
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "(system roots)".into());

    let mut t = String::new();
    let _ = writeln!(t, "config file   : {config_file}");
    let _ = writeln!(t, "[connection]");
    let _ = writeln!(t, "  url         : {}", opt(&conn.url));
    let _ = writeln!(
        t,
        "  node        : {}:{}",
        opt(&conn.node_host),
        conn.node_port
    );
    let _ = writeln!(t, "  protocol    : {}", conn.protocol);
    let _ = writeln!(t, "  user        : {}", opt(&conn.user));
    let _ = writeln!(t, "  password    : {password}");
    let _ = writeln!(t, "  ca_cert     : {ca_cert}");
    let _ = writeln!(t, "  insecure    : {}", conn.insecure);
    let _ = writeln!(t, "  timeout     : {} s", conn.timeout.as_secs());
    let _ = writeln!(
        t,
        "  max response: {} MiB",
        conn.max_response_bytes / (1024 * 1024)
    );
    let _ = writeln!(t, "[log]");
    let _ = writeln!(t, "  file        : {}", log.current_file_hint(ls).display());
    if let Some((from, why)) = &log.fell_back_from {
        let _ = writeln!(t, "  (fallback – {} not writable: {why})", from.display());
    }
    let _ = writeln!(t, "  level       : {}", ls.level);
    let _ = writeln!(t, "  format      : {}", ls.format);
    let _ = writeln!(
        t,
        "  rotation    : {} (keep {} files)",
        ls.rotation, ls.max_files
    );
    let _ = writeln!(t, "  stderr      : {}", ls.stderr);

    // hodnoty z konfigurace mohou obsahovat cokoli – do terminálu jen zneškodněné
    let safe: Vec<String> = t.lines().map(sanitize).collect();
    out(&(safe.join("\n") + "\n"));
}

// ------------------------------------------------------------------ run

async fn run(
    cli: Cli,
    loaded: &Loaded,
    ls: &LogSettings,
    log: &LogHandle,
) -> Result<bool, BoxError> {
    let conn = conn_settings(&cli.conn, &loaded.cfg.connection);
    debug!(
        url = conn.url.as_deref().unwrap_or("-"),
        node = conn.node_host.as_deref().unwrap_or("-"),
        port = conn.node_port,
        protocol = %conn.protocol,
        user = conn.user.as_deref().unwrap_or("-"),
        password_set = conn.password.as_deref().is_some_and(|p| !p.is_empty()),
        insecure = conn.insecure,
        timeout_s = conn.timeout.as_secs(),
        "effective connection settings"
    );

    if let Cmd::Config = &cli.cmd {
        show_config(loaded, &conn, ls, log);
        return Ok(true);
    }

    // dry-run nepotřebuje připojení
    if let Cmd::Send(a) | Cmd::Receive(a) = &cli.cmd {
        if a.dry_run {
            let dir = if matches!(cli.cmd, Cmd::Send(_)) {
                Direction::Send
            } else {
                Direction::Receive
            };
            let text = copy_process(dir, a).render()?;
            info!(direction = ?dir, process = %sanitize(&a.name), "dry run, process not submitted");
            out(&text);
            return Ok(true);
        }
    }

    let client = build_client(&conn)?;
    let ok = match &cli.cmd {
        Cmd::Version => {
            print(&client.version().await?);
            true
        }
        Cmd::Submit {
            file,
            server_file,
            snode,
            wait,
        } => {
            let process_file = match (file, server_file) {
                (Some(f), _) => {
                    info!(file = %sanitize(&f.display().to_string()), "submitting local process file");
                    config::read_limited_string(f, MAX_INPUT_FILE_BYTES)?
                }
                (None, Some(s)) => {
                    info!(server_file = %sanitize(s), "submitting process file on server");
                    s.clone()
                }
                (None, None) => return Err("use --file or --server-file".into()),
            };
            let mut sp = SubmitProcess::new(process_file);
            if let Some(s) = snode {
                sp = sp.secondary_node(s);
            }
            submit_and_maybe_wait(&client, sp, wait).await?
        }
        Cmd::Send(a) | Cmd::Receive(a) => {
            let dir = if matches!(cli.cmd, Cmd::Send(_)) {
                Direction::Send
            } else {
                Direction::Receive
            };
            info!(
                direction = ?dir,
                snode = %sanitize(&a.snode),
                from = %sanitize(&a.from),
                to = %sanitize(&a.to),
                process = %sanitize(&a.name),
                disp = ?a.disp,
                wait = a.wait.wait,
                "file transfer requested"
            );
            let text = copy_process(dir, a).render()?;
            submit_and_maybe_wait(&client, SubmitProcess::new(text), &a.wait).await?
        }
        Cmd::Stats {
            process_number,
            process_name,
        } => {
            print(
                &client
                    .select_statistics(&query(*process_number, process_name))
                    .await?,
            );
            true
        }
        Cmd::Processes {
            process_number,
            process_name,
        } => {
            print(
                &client
                    .select_process(&query(*process_number, process_name))
                    .await?,
            );
            true
        }
        Cmd::Delete {
            process_number,
            force,
        } => {
            let mut d = DeleteProcess::by_number(*process_number);
            if *force {
                d = d.force();
            }
            print(&client.delete_process(&d).await?);
            true
        }
        Cmd::Raw {
            method,
            path,
            query: q,
            json,
        } => {
            let method = Method::from_bytes(method.to_ascii_uppercase().as_bytes())?;
            let body: Option<Value> = json.as_deref().map(serde_json::from_str).transpose()?;
            let mut query = Query::new();
            for (k, v) in q {
                query = query.param(k, v);
            }
            info!(%method, path = %sanitize(path), "raw API call");
            print(&client.call(method, path, &query, body.as_ref()).await?);
            true
        }
        Cmd::Config => unreachable!("handled above"),
    };

    if let Err(e) = client.sign_out().await {
        errln!("warning: sign-out failed: {}", error_chain(&e));
    }
    Ok(ok)
}

async fn run_logged(cli: Cli, loaded: Loaded, ls: LogSettings, log: &LogHandle) -> ExitCode {
    let span = tracing::info_span!("cdctl", run = %run_id());
    async move {
        let started = Instant::now();
        info!(
            version = env!("CARGO_PKG_VERSION"),
            command = cli.cmd.name(),
            args = %sanitized_args(),
            pid = std::process::id(),
            os_user = %os_user(),
            config = %loaded
                .path
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "(none)".into()),
            "cdctl started"
        );
        if let Some((from, why)) = &log.fell_back_from {
            warn!(
                from = %from.display(),
                reason = %why,
                to = %log.dir.display(),
                "default log directory not writable, using fallback"
            );
        }
        if let Some(w) = &loaded.permission_warning {
            warn!("{w}");
            errln!("warning: {w}");
        }

        let result = run(cli, &loaded, &ls, log).await;
        let elapsed_ms = started.elapsed().as_millis() as u64;
        match result {
            Ok(true) => {
                info!(exit_code = 0, elapsed_ms, "cdctl finished");
                ExitCode::SUCCESS
            }
            Ok(false) => {
                warn!(
                    exit_code = 2,
                    elapsed_ms, "cdctl finished: process ended with non-zero completion code"
                );
                ExitCode::from(2)
            }
            Err(e) => {
                let msg = sanitize(&error_chain(e.as_ref()));
                error!(exit_code = 1, elapsed_ms, error = %msg, "cdctl failed");
                errln!("error: {msg}");
                ExitCode::FAILURE
            }
        }
    }
    .instrument(span)
    .await
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let loaded = match config::load(cli.config.as_deref()) {
        Ok(l) => l,
        Err(e) => {
            errln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };

    let ls = log_settings(&cli.log, &loaded.cfg.log);
    if ls.level.trim().is_empty() {
        errln!("error: log level must not be empty");
        return ExitCode::FAILURE;
    }
    let log = match logging::init(&ls) {
        Ok(h) => h,
        Err(e) => {
            errln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };
    if let Some((from, why)) = &log.fell_back_from {
        errln!(
            "warning: cannot write log to {} ({why}); logging to {} instead",
            from.display(),
            log.dir.display()
        );
    }

    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            errln!("error: cannot start async runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    let code = rt.block_on(run_logged(cli, loaded, ls, &log));
    drop(rt);
    drop(log); // flush logu
    code
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_definition_is_valid() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }

    #[test]
    fn flags_override_config_file() {
        let file = config::parse(
            r#"
            [connection]
            url = "https://from-file"
            node_host = "file-node"
            node_port = 2000
            user = "file-user"
            insecure = true
            timeout_secs = 30
            [log]
            dir = "/file/logs"
            level = "debug"
            format = "json"
            rotation = "never"
            max_files = 3
            "#,
        )
        .unwrap();
        let cli = Cli::parse_from([
            "cdctl",
            "--url",
            "https://from-flag",
            "--log-level",
            "warn",
            "version",
        ]);
        let c = conn_settings(&cli.conn, &file.connection);
        assert_eq!(c.url.as_deref(), Some("https://from-flag"));
        assert_eq!(c.node_host.as_deref(), Some("file-node"));
        assert_eq!(c.node_port, 2000);
        assert!(c.insecure);
        assert_eq!(c.timeout, Duration::from_secs(30));

        let l = log_settings(&cli.log, &file.log);
        assert_eq!(l.level, "warn");
        assert_eq!(l.dir, PathBuf::from("/file/logs"));
        assert!(l.dir_explicit);
        assert_eq!(l.format, LogFormat::Json);
        assert_eq!(l.rotation, Rotation::Never);
        assert_eq!(l.max_files, 3);
    }

    #[test]
    fn defaults_without_config() {
        let cli = Cli::parse_from(["cdctl", "version"]);
        let empty = config::FileConfig::default();
        let c = conn_settings(&cli.conn, &empty.connection);
        assert_eq!(c.node_port, 1363);
        assert_eq!(c.protocol, "TCPIP");
        assert_eq!(c.timeout, Duration::from_secs(120));
        let l = log_settings(&cli.log, &empty.log);
        assert_eq!(l.dir, config::default_log_dir());
        assert!(!l.dir_explicit);
        assert_eq!(l.file, "cdctl.log");
        assert_eq!(l.level, "info");
        assert_eq!(l.rotation, Rotation::Daily);
        assert_eq!(l.max_files, 14);
    }

    #[test]
    fn run_ids_are_hex() {
        let id = run_id();
        assert_eq!(id.len(), 8);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
