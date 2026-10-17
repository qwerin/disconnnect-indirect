//! Logování `cdctl` do souboru (výchozí `/var/log/cdctl/cdctl.log`) s rotací.

use std::io::{self, Write};
use std::path::{Path, PathBuf};

use tracing::Subscriber;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_appender::rolling::{self, RollingFileAppender};
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer};

use crate::config::{LogFormat, Rotation};

/// Výsledné nastavení logování (po sloučení přepínačů, env a konfigurace).
#[derive(Debug, Clone)]
pub struct LogSettings {
    pub dir: PathBuf,
    /// Adresář zadal uživatel (přepínač/env/config) – při chybě se nepoužije fallback.
    pub dir_explicit: bool,
    pub fallback_dir: Option<PathBuf>,
    pub file: String,
    pub level: String,
    pub format: LogFormat,
    pub rotation: Rotation,
    pub max_files: usize,
    pub stderr: bool,
}

/// Drží background writer – musí žít do konce programu, jinak se ztratí poslední řádky.
pub struct LogHandle {
    _guard: WorkerGuard,
    /// Adresář, kam se skutečně loguje.
    pub dir: PathBuf,
    /// Když se nepodařilo použít výchozí adresář: (původní adresář, důvod).
    pub fell_back_from: Option<(PathBuf, String)>,
}

impl LogHandle {
    /// Aktuální soubor logu (s rotací obsahuje datum, např. `cdctl.2026-10-16.log`).
    pub fn current_file_hint(&self, s: &LogSettings) -> PathBuf {
        let (prefix, suffix) = split_file_name(&s.file);
        let name = match (s.rotation, suffix) {
            (Rotation::Never, Some(sfx)) => format!("{prefix}.{sfx}"),
            (Rotation::Never, None) => prefix.to_string(),
            (_, Some(sfx)) => format!("{prefix}.<date>.{sfx}"),
            (_, None) => format!("{prefix}.<date>"),
        };
        self.dir.join(name)
    }
}

/// Inicializuje globální tracing subscriber.
pub fn init(s: &LogSettings) -> Result<LogHandle, String> {
    let filter = EnvFilter::try_new(&s.level)
        .map_err(|e| format!("invalid log level `{}`: {e}", s.level))?;

    let (appender, dir, fell_back_from) = open_appender(s)?;
    let (writer, guard) = tracing_appender::non_blocking(appender);

    // Textový log chrání proti padělání řádků Sanitizing writer; JSON escapuje sám.
    let file_layer = match s.format {
        LogFormat::Text => make_layer(Sanitizing(writer), LogFormat::Text),
        LogFormat::Json => make_layer(writer, LogFormat::Json),
    };
    let stderr_layer = s.stderr.then(|| {
        make_layer(
            Sanitizing(std::io::stderr as fn() -> io::Stderr),
            LogFormat::Text,
        )
    });

    tracing_subscriber::registry()
        .with(filter)
        .with(file_layer)
        .with(stderr_layer)
        .try_init()
        .map_err(|e| format!("cannot initialise logging: {e}"))?;

    Ok(LogHandle {
        _guard: guard,
        dir,
        fell_back_from,
    })
}

type Opened = (RollingFileAppender, PathBuf, Option<(PathBuf, String)>);

/// Otevře log v nastaveném adresáři; výchozí (neexplicitní) adresář může spadnout do fallbacku.
pub fn open_appender(s: &LogSettings) -> Result<Opened, String> {
    match build_appender(&s.dir, s) {
        Ok(a) => Ok((a, s.dir.clone(), None)),
        Err(e) if s.dir_explicit => Err(format!(
            "cannot write log to {}: {e} (change [log] dir in config, --log-dir or CDCTL_LOG_DIR)",
            s.dir.display()
        )),
        Err(e) => {
            let Some(fb) = &s.fallback_dir else {
                return Err(format!(
                    "cannot write log to {}: {e} and no fallback directory is available",
                    s.dir.display()
                ));
            };
            build_appender(fb, s)
                .map(|a| (a, fb.clone(), Some((s.dir.clone(), e.clone()))))
                .map_err(|e2| {
                    format!(
                        "cannot write log to {} ({e}) nor to {} ({e2}); set [log] dir in config, --log-dir or CDCTL_LOG_DIR",
                        s.dir.display(),
                        fb.display()
                    )
                })
        }
    }
}

fn build_appender(dir: &Path, s: &LogSettings) -> Result<RollingFileAppender, String> {
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let (prefix, suffix) = split_file_name(&s.file);
    let rotation = match s.rotation {
        Rotation::Minutely => rolling::Rotation::MINUTELY,
        Rotation::Hourly => rolling::Rotation::HOURLY,
        Rotation::Daily => rolling::Rotation::DAILY,
        Rotation::Never => rolling::Rotation::NEVER,
    };
    let mut b = RollingFileAppender::builder()
        .rotation(rotation)
        .filename_prefix(prefix);
    if let Some(sfx) = suffix {
        b = b.filename_suffix(sfx);
    }
    if s.max_files > 0 && s.rotation != Rotation::Never {
        b = b.max_log_files(s.max_files);
    }
    b.build(dir).map_err(|e| e.to_string())
}

/// `cdctl.log` -> (`cdctl`, Some(`log`)), `cdctl` -> (`cdctl`, None).
fn split_file_name(name: &str) -> (&str, Option<&str>) {
    match name.rsplit_once('.') {
        Some((p, s)) if !p.is_empty() && !s.is_empty() => (p, Some(s)),
        _ => (name, None),
    }
}

/// MakeWriter, který v každé události zneškodní řídicí znaky (nové řádky, ESC, bidi…)
/// kromě koncového `\n` – data ze serveru ani z argumentů tak nemohou padělat řádky logu
/// ani poslat escape sekvence do terminálu.
pub struct Sanitizing<M>(pub M);

impl<'a, M: MakeWriter<'a>> MakeWriter<'a> for Sanitizing<M> {
    type Writer = SanitizingWriter<M::Writer>;
    fn make_writer(&'a self) -> Self::Writer {
        SanitizingWriter(self.0.make_writer())
    }
}

pub struct SanitizingWriter<W>(W);

impl<W: Write> Write for SanitizingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let text = String::from_utf8_lossy(buf);
        let (body, newline) = match text.strip_suffix('\n') {
            Some(b) => (b, "\n"),
            None => (&*text, ""),
        };
        if body.chars().any(connect_direct::is_dangerous_char) {
            let mut clean = connect_direct::sanitize(body);
            clean.push_str(newline);
            self.0.write_all(clean.as_bytes())?;
        } else {
            self.0.write_all(buf)?;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

fn make_layer<S, W>(writer: W, format: LogFormat) -> Box<dyn Layer<S> + Send + Sync>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    W: for<'w> MakeWriter<'w> + Send + Sync + 'static,
{
    let layer = tracing_subscriber::fmt::layer()
        .with_writer(writer)
        .with_ansi(false)
        .with_target(true);
    match format {
        LogFormat::Text => layer.boxed(),
        LogFormat::Json => layer
            .json()
            .with_current_span(true)
            .with_span_list(false)
            .boxed(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(dir: PathBuf, explicit: bool, fallback: Option<PathBuf>) -> LogSettings {
        LogSettings {
            dir,
            dir_explicit: explicit,
            fallback_dir: fallback,
            file: "cdctl.log".into(),
            level: "info".into(),
            format: LogFormat::Text,
            rotation: Rotation::Never,
            max_files: 0,
            stderr: false,
        }
    }

    /// Cesta, kterou nejde vytvořit na žádném OS (adresář pod obyčejným souborem).
    fn unwritable(tmp: &Path) -> PathBuf {
        let f = tmp.join("a-file");
        std::fs::write(&f, "x").unwrap();
        f.join("sub")
    }

    #[test]
    fn splits_file_names() {
        assert_eq!(split_file_name("cdctl.log"), ("cdctl", Some("log")));
        assert_eq!(split_file_name("a.b.txt"), ("a.b", Some("txt")));
        assert_eq!(split_file_name("cdctl"), ("cdctl", None));
        assert_eq!(split_file_name(".hidden"), (".hidden", None));
    }

    #[test]
    fn writes_into_configured_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("nested/logs");
        let (_, used, fb) = open_appender(&settings(dir.clone(), true, None)).unwrap();
        assert_eq!(used, dir);
        assert!(fb.is_none());
        assert!(dir.join("cdctl.log").exists());
    }

    #[test]
    fn explicit_unwritable_dir_is_an_error() {
        let tmp = tempfile::tempdir().unwrap();
        let fb = tmp.path().join("fallback");
        let err = open_appender(&settings(unwritable(tmp.path()), true, Some(fb.clone())))
            .err()
            .unwrap();
        assert!(err.contains("cannot write log"));
        assert!(!fb.exists(), "explicit dir must not fall back");
    }

    #[test]
    fn default_unwritable_dir_falls_back() {
        let tmp = tempfile::tempdir().unwrap();
        let bad = unwritable(tmp.path());
        let fb = tmp.path().join("fallback");
        let (_, used, from) =
            open_appender(&settings(bad.clone(), false, Some(fb.clone()))).unwrap();
        assert_eq!(used, fb);
        assert_eq!(from.unwrap().0, bad);
        assert!(fb.join("cdctl.log").exists());
    }

    #[test]
    fn both_unwritable_is_an_error() {
        let tmp = tempfile::tempdir().unwrap();
        let bad = unwritable(tmp.path());
        let err = open_appender(&settings(bad.clone(), false, Some(bad.join("x"))))
            .err()
            .unwrap();
        assert!(err.contains("nor to"));
        assert!(open_appender(&settings(bad, false, None)).is_err());
    }

    #[test]
    fn rotated_file_name_contains_date() {
        let tmp = tempfile::tempdir().unwrap();
        let mut s = settings(tmp.path().to_path_buf(), true, None);
        s.rotation = Rotation::Daily;
        s.max_files = 3;
        let (_, _, _) = open_appender(&s).unwrap();
        let names: Vec<String> = std::fs::read_dir(tmp.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names.len(), 1, "{names:?}");
        assert!(names[0].starts_with("cdctl.20") && names[0].ends_with(".log"));
    }

    #[test]
    fn sanitizing_writer_neutralises_forged_lines() {
        let mut out = Vec::new();
        {
            let mut w = SanitizingWriter(&mut out);
            w.write_all(b"INFO ok body=boom\nINFO forged\x1b[2J\n")
                .unwrap();
            w.write_all(b"INFO clean line\n").unwrap();
        }
        let text = String::from_utf8(out).unwrap();
        assert_eq!(text.lines().count(), 2, "{text}");
        assert!(text.contains("boom\\nINFO forged\\u{1b}[2J"));
        assert!(!text.contains('\u{1b}'));
    }

    proptest::proptest! {
        #[test]
        fn prop_sanitizing_writer_emits_single_line(bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..300)) {
            let mut input = bytes.clone();
            input.push(b'\n');
            let mut out = Vec::new();
            SanitizingWriter(&mut out).write_all(&input).unwrap();
            let text = String::from_utf8_lossy(&out);
            proptest::prop_assert_eq!(text.matches('\n').count(), 1);
            proptest::prop_assert!(text.ends_with('\n'));
            proptest::prop_assert!(!text.trim_end_matches('\n').chars().any(connect_direct::is_dangerous_char));
        }
    }
}
