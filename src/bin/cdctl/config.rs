//! Konfigurační soubor `cdctl` (TOML).
//!
//! Pořadí priorit: přepínač na příkazové řádce > proměnná prostředí > konfigurační soubor > výchozí hodnota.

use std::fmt;
use std::path::{Path, PathBuf};

use serde::Deserialize;

/// Celý konfigurační soubor.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileConfig {
    #[serde(default)]
    pub connection: ConnectionSection,
    #[serde(default)]
    pub log: LogSection,
}

/// Sekce `[connection]`.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionSection {
    pub url: Option<String>,
    pub node_host: Option<String>,
    pub node_port: Option<u16>,
    pub protocol: Option<String>,
    pub user: Option<String>,
    pub password: Option<String>,
    pub ca_cert: Option<PathBuf>,
    pub insecure: Option<bool>,
    pub timeout_secs: Option<u64>,
    /// Limit velikosti odpovědi serveru v MiB (výchozí 64).
    pub max_response_mb: Option<u64>,
}

/// Sekce `[log]`.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogSection {
    pub dir: Option<PathBuf>,
    pub file: Option<String>,
    pub level: Option<String>,
    pub format: Option<LogFormat>,
    pub rotation: Option<Rotation>,
    pub max_files: Option<usize>,
    pub stderr: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    Text,
    Json,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum Rotation {
    Minutely,
    Hourly,
    Daily,
    Never,
}

impl fmt::Display for LogFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            LogFormat::Text => "text",
            LogFormat::Json => "json",
        })
    }
}

impl fmt::Display for Rotation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Rotation::Minutely => "minutely",
            Rotation::Hourly => "hourly",
            Rotation::Daily => "daily",
            Rotation::Never => "never",
        })
    }
}

pub const DEFAULT_LOG_FILE: &str = "cdctl.log";
pub const DEFAULT_LOG_LEVEL: &str = "info";
pub const DEFAULT_MAX_LOG_FILES: usize = 14;
pub const DEFAULT_MAX_RESPONSE_MB: u64 = 64;
/// Limit pro konfigurační soubor, .cdp soubor i PEM certifikát (ochrana proti /dev/zero apod.).
pub const MAX_INPUT_FILE_BYTES: u64 = 1024 * 1024;

/// Přečte soubor nejvýše do `max` bajtů; větší (nebo nekonečný, např. /dev/zero) odmítne.
pub fn read_limited(path: &Path, max: u64) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let file =
        std::fs::File::open(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    if file.metadata().map(|m| m.is_dir()).unwrap_or(false) {
        return Err(format!("cannot read {}: is a directory", path.display()));
    }
    let mut buf = Vec::new();
    file.take(max + 1)
        .read_to_end(&mut buf)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    if buf.len() as u64 > max {
        return Err(format!(
            "{} is too large (limit {max} bytes)",
            path.display()
        ));
    }
    Ok(buf)
}

/// Jako [`read_limited`], navíc vyžaduje platné UTF-8.
pub fn read_limited_string(path: &Path, max: u64) -> Result<String, String> {
    String::from_utf8(read_limited(path, max)?)
        .map_err(|_| format!("{} is not valid UTF-8 text", path.display()))
}

/// Název souboru logu: bez cesty, ne prázdný, ne skrytý, bez řídicích znaků.
pub fn validate_log_file_name(name: &str) -> Result<(), String> {
    let bad = name.is_empty()
        || name.len() > 200
        || name.starts_with('.')
        || name.contains(['/', '\\', ':'])
        || name.chars().any(connect_direct::is_dangerous_char);
    if bad {
        Err(format!(
            "invalid log file name `{}`: must be a plain file name like `cdctl.log` (no path, not starting with a dot)",
            connect_direct::sanitize(name)
        ))
    } else {
        Ok(())
    }
}

/// Kontrola hodnot, které parser přijme, ale nedávají smysl.
pub fn validate(c: &FileConfig) -> Result<(), String> {
    if c.connection.node_port == Some(0) {
        return Err("[connection] node_port must be 1-65535".into());
    }
    if c.connection.timeout_secs == Some(0) {
        return Err("[connection] timeout_secs must be at least 1".into());
    }
    if let Some(mb) = c.connection.max_response_mb {
        if mb == 0 || mb > 4096 {
            return Err("[connection] max_response_mb must be 1-4096".into());
        }
    }
    if let Some(f) = &c.log.file {
        validate_log_file_name(f).map_err(|e| format!("[log] file: {e}"))?;
    }
    if let Some(l) = &c.log.level {
        if l.trim().is_empty() {
            return Err("[log] level must not be empty".into());
        }
    }
    if c.log.dir.as_ref().is_some_and(|d| d.as_os_str().is_empty()) {
        return Err("[log] dir must not be empty".into());
    }
    Ok(())
}

/// Výchozí cesta ke konfiguraci: `/etc/cdctl/config.toml` (Windows: `%ProgramData%\cdctl\config.toml`).
pub fn default_config_path() -> PathBuf {
    if cfg!(windows) {
        program_data().join("cdctl").join("config.toml")
    } else {
        PathBuf::from("/etc/cdctl/config.toml")
    }
}

/// Výchozí adresář logů: `/var/log/cdctl` (Windows: `%ProgramData%\cdctl\log`).
pub fn default_log_dir() -> PathBuf {
    if cfg!(windows) {
        program_data().join("cdctl").join("log")
    } else {
        PathBuf::from("/var/log/cdctl")
    }
}

/// Náhradní adresář, když výchozí `/var/log/cdctl` není zapisovatelný (běh bez roota):
/// `$XDG_STATE_HOME/cdctl/log`, `~/.local/state/cdctl/log`, na Windows `%LOCALAPPDATA%\cdctl\log`.
pub fn fallback_log_dir() -> Option<PathBuf> {
    let non_empty = |k: &str| {
        std::env::var_os(k)
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
    };
    if cfg!(windows) {
        return non_empty("LOCALAPPDATA").map(|p| p.join("cdctl").join("log"));
    }
    non_empty("XDG_STATE_HOME")
        .map(|p| p.join("cdctl").join("log"))
        .or_else(|| non_empty("HOME").map(|h| h.join(".local/state/cdctl/log")))
}

fn program_data() -> PathBuf {
    std::env::var_os("ProgramData")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
}

/// Výsledek načtení konfigurace.
#[derive(Debug, Default)]
pub struct Loaded {
    pub cfg: FileConfig,
    /// Cesta k použitému souboru (None = žádný soubor, jen výchozí hodnoty).
    pub path: Option<PathBuf>,
    /// Varování o příliš volných právech souboru s heslem.
    pub permission_warning: Option<String>,
}

/// Načte konfiguraci. Explicitně zadaný soubor musí existovat;
/// výchozí soubor se použije, jen pokud existuje.
pub fn load(explicit: Option<&Path>) -> Result<Loaded, String> {
    let (path, must_exist) = match explicit {
        Some(p) => (p.to_path_buf(), true),
        None => (default_config_path(), false),
    };
    if !path.exists() {
        return if must_exist {
            Err(format!("config file {} does not exist", path.display()))
        } else {
            Ok(Loaded::default())
        };
    }
    let text = read_limited_string(&path, MAX_INPUT_FILE_BYTES)
        .map_err(|e| format!("config file: {e}"))?;
    let cfg = parse(&text).map_err(|e| format!("invalid config file {}: {e}", path.display()))?;
    validate(&cfg).map_err(|e| format!("invalid config file {}: {e}", path.display()))?;
    let permission_warning = if cfg.connection.password.is_some() {
        insecure_permissions(&path)
    } else {
        None
    };
    Ok(Loaded {
        cfg,
        path: Some(path),
        permission_warning,
    })
}

pub fn parse(text: &str) -> Result<FileConfig, toml::de::Error> {
    toml::from_str(text)
}

#[cfg(unix)]
fn insecure_permissions(path: &Path) -> Option<String> {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(path).ok()?.permissions().mode() & 0o777;
    (mode & 0o077 != 0).then(|| {
        format!(
            "config file {} contains a password but is readable by group/others (mode {mode:o}); run: chmod 600 {}",
            path.display(),
            path.display()
        )
    })
}

#[cfg(not(unix))]
fn insecure_permissions(_path: &Path) -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const FULL: &str = r#"
        [connection]
        url = "https://cdws:9443"
        node_host = "cdnode1"
        node_port = 2363
        protocol = "TLS1.2"
        user = "cduser"
        password = "secret"
        ca_cert = "/etc/cdctl/ca.pem"
        insecure = false
        timeout_secs = 60

        [log]
        dir = "/srv/logs/cdctl"
        file = "transfers.log"
        level = "connect_direct=debug,info"
        format = "json"
        rotation = "hourly"
        max_files = 48
        stderr = true
    "#;

    #[test]
    fn parses_full_config() {
        let c = parse(FULL).unwrap();
        assert_eq!(c.connection.url.as_deref(), Some("https://cdws:9443"));
        assert_eq!(c.connection.node_port, Some(2363));
        assert_eq!(c.connection.timeout_secs, Some(60));
        assert_eq!(c.log.dir, Some(PathBuf::from("/srv/logs/cdctl")));
        assert_eq!(c.log.format, Some(LogFormat::Json));
        assert_eq!(c.log.rotation, Some(Rotation::Hourly));
        assert_eq!(c.log.max_files, Some(48));
        assert_eq!(c.log.stderr, Some(true));
    }

    #[test]
    fn empty_config_is_valid() {
        let c = parse("").unwrap();
        assert!(c.connection.url.is_none());
        assert!(c.log.dir.is_none());
    }

    #[test]
    fn example_config_in_repo_parses() {
        let text = include_str!("../../../config.example.toml");
        parse(text).unwrap();
    }

    #[test]
    fn unknown_keys_are_rejected() {
        let err = parse("[log]\nlevle = \"debug\"\n").unwrap_err();
        assert!(err.to_string().contains("levle"));
        assert!(parse("[unknown]\nx = 1\n").is_err());
    }

    #[test]
    fn invalid_enum_values_are_rejected() {
        assert!(parse("[log]\nformat = \"xml\"\n").is_err());
        assert!(parse("[log]\nrotation = \"weekly\"\n").is_err());
    }

    #[test]
    fn explicit_missing_file_is_error() {
        let err = load(Some(Path::new("/definitely/not/here.toml"))).unwrap_err();
        assert!(err.contains("does not exist"));
    }

    #[test]
    fn loads_file_and_reports_path() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("c.toml");
        std::fs::write(&p, "[connection]\nuser = \"u\"\n").unwrap();
        let l = load(Some(&p)).unwrap();
        assert_eq!(l.path.as_deref(), Some(p.as_path()));
        assert_eq!(l.cfg.connection.user.as_deref(), Some("u"));
        assert!(l.permission_warning.is_none());
    }

    #[cfg(unix)]
    #[test]
    fn warns_on_world_readable_password() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("c.toml");
        std::fs::write(&p, "[connection]\npassword = \"x\"\n").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load(Some(&p)).unwrap().permission_warning.is_some());
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(load(Some(&p)).unwrap().permission_warning.is_none());
    }

    #[test]
    fn defaults_are_sane() {
        if cfg!(unix) {
            assert_eq!(default_log_dir(), PathBuf::from("/var/log/cdctl"));
            assert_eq!(
                default_config_path(),
                PathBuf::from("/etc/cdctl/config.toml")
            );
        }
        assert!(default_log_dir().ends_with("log") || default_log_dir().ends_with("cdctl"));
    }

    #[test]
    fn rejects_nonsense_values() {
        for bad in [
            "[connection]\nnode_port = 0\n",
            "[connection]\ntimeout_secs = 0\n",
            "[connection]\nmax_response_mb = 0\n",
            "[log]\nfile = \"../../escaped.log\"\n",
            "[log]\nfile = \"/\"\n",
            "[log]\nfile = \"\"\n",
            "[log]\nfile = \".hidden\"\n",
            "[log]\nfile = 'C:\\x.log'\n",
            "[log]\nlevel = \" \"\n",
            "[log]\ndir = \"\"\n",
        ] {
            let c = parse(bad).unwrap();
            assert!(validate(&c).is_err(), "{bad:?} must be rejected");
        }
        assert!(validate(&parse(FULL).unwrap()).is_ok());
    }

    #[test]
    fn read_limited_rejects_large_and_directories() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("big");
        std::fs::write(&p, vec![b'a'; 101]).unwrap();
        assert!(read_limited(&p, 100).unwrap_err().contains("too large"));
        assert_eq!(read_limited(&p, 101).unwrap().len(), 101);
        assert!(read_limited(dir.path(), 100).is_err());
        let bin = dir.path().join("bin");
        std::fs::write(&bin, [0xff, 0xfe]).unwrap();
        assert!(read_limited_string(&bin, 100)
            .unwrap_err()
            .contains("UTF-8"));
    }

    #[cfg(unix)]
    #[test]
    fn read_limited_survives_dev_zero() {
        let err = read_limited(Path::new("/dev/zero"), 1024).unwrap_err();
        assert!(err.contains("too large"));
    }

    proptest::proptest! {
        #[test]
        fn prop_config_parser_never_panics(text in proptest::prelude::any::<String>()) {
            if let Ok(c) = parse(&text) {
                let _ = validate(&c);
            }
        }

        #[test]
        fn prop_valid_log_file_names_stay_in_dir(name in proptest::prelude::any::<String>()) {
            if validate_log_file_name(&name).is_ok() {
                let p = Path::new("/var/log/cdctl").join(&name);
                proptest::prop_assert_eq!(p.parent(), Some(Path::new("/var/log/cdctl")));
            }
        }
    }
}
