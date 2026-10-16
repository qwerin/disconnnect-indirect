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

/// Celý řetězec příčin chyby v jednom řádku, např.
/// `error sending request …: client error (Connect): tcp connect error: Connection refused`.
/// Příčiny, jejichž text už je obsažen v předchozí zprávě, se vynechají.
pub fn error_chain(e: &(dyn std::error::Error + 'static)) -> String {
    let mut out = e.to_string();
    let mut cur = e.source();
    while let Some(src) = cur {
        let msg = src.to_string();
        if !out.contains(&msg) {
            out.push_str(": ");
            out.push_str(&msg);
        }
        cur = src.source();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct Leaf;
    impl std::fmt::Display for Leaf {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("Connection refused")
        }
    }
    impl std::error::Error for Leaf {}

    #[derive(Debug)]
    struct Mid(Leaf);
    impl std::fmt::Display for Mid {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("tcp connect error")
        }
    }
    impl std::error::Error for Mid {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            Some(&self.0)
        }
    }

    #[test]
    fn chain_joins_sources() {
        assert_eq!(
            error_chain(&Mid(Leaf)),
            "tcp connect error: Connection refused"
        );
        assert_eq!(error_chain(&Leaf), "Connection refused");
    }

    #[test]
    fn chain_skips_duplicated_messages() {
        let e = Error::Config("bad".into());
        assert_eq!(error_chain(&e), "invalid configuration: bad");
    }
}
