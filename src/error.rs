use reqwest::StatusCode;

/// Chyby, které může vrátit klient Connect:Direct.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Síťová / TLS / HTTP chyba na úrovni reqwest.
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// CDWS odpověděl ne-2xx stavem.
    #[error("CDWS returned {status}: {body}")]
    Api { status: StatusCode, body: String },

    /// Sign-on prošel, ale v odpovědi chybí očekávaná hlavička.
    #[error("sign-on succeeded but response header `{0}` is missing")]
    MissingHeader(&'static str),

    /// Neplatná konfigurace klienta (URL, certifikát, ...).
    #[error("invalid configuration: {0}")]
    Config(String),

    /// Neplatný vstup pro generování procesu (jméno, cesta, ...).
    #[error("invalid process definition: {0}")]
    InvalidProcess(String),

    /// Proces nedoběhl v zadaném čase.
    #[error("timed out waiting for process {0} to finish")]
    Timeout(u64),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
