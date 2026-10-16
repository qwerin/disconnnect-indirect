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
    let text = std::fs::read_to_string(&path)
        .map_err(|e| format!("cannot read config file {}: {e}", path.display()))?;
    let cfg = parse(&text).map_err(|e| format!("invalid config file {}: {e}", path.display()))?;
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
}
