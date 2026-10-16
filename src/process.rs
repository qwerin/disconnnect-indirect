//! Generátor textu Connect:Direct procesu (COPY) – aby se nemusel psát ručně.

use crate::error::{Error, Result};

/// Dispozice cílového souboru (`DISP=`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Disp {
    New,
    Old,
    Mod,
    #[default]
    Rpl,
    Shr,
}

impl Disp {
    fn as_str(self) -> &'static str {
        match self {
            Disp::New => "NEW",
            Disp::Old => "OLD",
            Disp::Mod => "MOD",
            Disp::Rpl => "RPL",
            Disp::Shr => "SHR",
        }
    }
}

impl std::str::FromStr for Disp {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        Ok(match s.to_ascii_uppercase().as_str() {
            "NEW" => Disp::New,
            "OLD" => Disp::Old,
            "MOD" => Disp::Mod,
            "RPL" => Disp::Rpl,
            "SHR" => Disp::Shr,
            other => return Err(Error::InvalidProcess(format!("unknown DISP `{other}`"))),
        })
    }
}

/// Směr přenosu z pohledu PNODE (uzlu, na kterém proces běží).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// PNODE -> SNODE
    Send,
    /// SNODE -> PNODE
    Receive,
}

/// Jednokrokový COPY proces.
///
/// ```
/// use connect_direct::{CopyProcess, Disp};
/// let text = CopyProcess::send("PAYOUT", "PARTNER01", "/data/out/pay.csv", "/in/pay.csv")
///     .disp(Disp::Rpl)
///     .from_sysopts("\":datatype=text:\"")
///     .render()
///     .unwrap();
/// assert!(text.starts_with("PAYOUT PROCESS"));
/// ```
#[derive(Debug, Clone)]
pub struct CopyProcess {
    name: String,
    snode: String,
    direction: Direction,
    from: String,
    to: String,
    disp: Disp,
    hold: bool,
    step: String,
    from_sysopts: Option<String>,
    to_sysopts: Option<String>,
}

impl CopyProcess {
    pub fn new(
        direction: Direction,
        name: impl Into<String>,
        snode: impl Into<String>,
        from: impl Into<String>,
        to: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            snode: snode.into(),
            direction,
            from: from.into(),
            to: to.into(),
            disp: Disp::default(),
            hold: false,
            step: "STEP01".into(),
            from_sysopts: None,
            to_sysopts: None,
        }
    }

    /// Odeslání souboru z PNODE na SNODE.
    pub fn send(
        name: impl Into<String>,
        snode: impl Into<String>,
        from: impl Into<String>,
        to: impl Into<String>,
    ) -> Self {
        Self::new(Direction::Send, name, snode, from, to)
    }

    /// Stažení souboru ze SNODE na PNODE.
    pub fn receive(
        name: impl Into<String>,
        snode: impl Into<String>,
        from: impl Into<String>,
        to: impl Into<String>,
    ) -> Self {
        Self::new(Direction::Receive, name, snode, from, to)
    }

    pub fn disp(mut self, disp: Disp) -> Self {
        self.disp = disp;
        self
    }

    pub fn hold(mut self, hold: bool) -> Self {
        self.hold = hold;
        self
    }

    pub fn step_label(mut self, label: impl Into<String>) -> Self {
        self.step = label.into();
        self
    }

    /// Hodnota vložená doslova za `SYSOPTS=` ve FROM bloku (včetně uvozovek).
    pub fn from_sysopts(mut self, raw: impl Into<String>) -> Self {
        self.from_sysopts = Some(raw.into());
        self
    }

    /// Hodnota vložená doslova za `SYSOPTS=` v TO bloku (včetně uvozovek).
    pub fn to_sysopts(mut self, raw: impl Into<String>) -> Self {
        self.to_sysopts = Some(raw.into());
        self
    }

    /// Vyrenderuje text procesu, připravený pro `SubmitProcess::new(text)`.
    pub fn render(&self) -> Result<String> {
        validate_label("process name", &self.name)?;
        validate_label("step label", &self.step)?;
        validate_node(&self.snode)?;
        let from = quote_path(&self.from)?;
        let to = quote_path(&self.to)?;
        for s in [&self.from_sysopts, &self.to_sysopts].into_iter().flatten() {
            if s.contains(['\n', '\r']) {
                return Err(Error::InvalidProcess(
                    "SYSOPTS must not contain newlines".into(),
                ));
            }
        }

        let (from_node, to_node) = match self.direction {
            Direction::Send => ("PNODE", "SNODE"),
            Direction::Receive => ("SNODE", "PNODE"),
        };

        let mut p = String::new();
        p.push_str(&format!("{} PROCESS\n", self.name.to_ascii_uppercase()));
        p.push_str(&format!("    SNODE={}\n", self.snode));
        p.push_str(&format!(
            "    HOLD={}\n",
            if self.hold { "YES" } else { "NO" }
        ));
        p.push_str(&format!("{} COPY\n", self.step.to_ascii_uppercase()));
        p.push_str("    FROM (\n");
        p.push_str(&format!("        FILE={from}\n"));
        p.push_str(&format!("        {from_node}\n"));
        if let Some(s) = &self.from_sysopts {
            p.push_str(&format!("        SYSOPTS={s}\n"));
        }
        p.push_str("    )\n");
        p.push_str("    TO (\n");
        p.push_str(&format!("        FILE={to}\n"));
        p.push_str(&format!("        {to_node}\n"));
        p.push_str(&format!("        DISP={}\n", self.disp.as_str()));
        if let Some(s) = &self.to_sysopts {
            p.push_str(&format!("        SYSOPTS={s}\n"));
        }
        p.push_str("    )\n");
        p.push_str("PEND\n");
        Ok(p)
    }
}

/// Jméno procesu / label kroku: 1–8 znaků, začíná písmenem, dál jen písmena a číslice.
fn validate_label(what: &str, s: &str) -> Result<()> {
    let ok = (1..=8).contains(&s.len())
        && s.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
        && s.chars().all(|c| c.is_ascii_alphanumeric());
    if ok {
        Ok(())
    } else {
        Err(Error::InvalidProcess(format!(
            "{what} `{s}` must be 1-8 alphanumeric chars starting with a letter"
        )))
    }
}

fn validate_node(s: &str) -> Result<()> {
    let ok = (1..=16).contains(&s.len())
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "._-@#$".contains(c));
    if ok {
        Ok(())
    } else {
        Err(Error::InvalidProcess(format!("invalid SNODE name `{s}`")))
    }
}

/// Cesty s mezerami nebo speciálními znaky obalí uvozovkami.
fn quote_path(path: &str) -> Result<String> {
    if path.is_empty() || path.contains(['"', '\n', '\r']) {
        return Err(Error::InvalidProcess(format!("invalid file path `{path}`")));
    }
    let needs_quotes = path
        .chars()
        .any(|c| c.is_whitespace() || "(),=;&".contains(c));
    Ok(if needs_quotes {
        format!("\"{path}\"")
    } else {
        path.to_string()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_send() {
        let p = CopyProcess::send("tf01", "CDNODE2", "/tmp/a b.txt", "/in/a.txt")
            .render()
            .unwrap();
        assert!(p.contains("TF01 PROCESS"));
        assert!(p.contains("FILE=\"/tmp/a b.txt\"\n        PNODE"));
        assert!(p.contains("FILE=/in/a.txt\n        SNODE\n        DISP=RPL"));
        assert!(p.trim_end().ends_with("PEND"));
    }

    #[test]
    fn renders_receive_swaps_nodes() {
        let p = CopyProcess::receive("GET1", "N2", "/r/x", "/l/x")
            .render()
            .unwrap();
        assert!(p.contains("FILE=/r/x\n        SNODE"));
        assert!(p.contains("FILE=/l/x\n        PNODE"));
    }

    #[test]
    fn rejects_bad_name() {
        assert!(CopyProcess::send("TOOLONGNAME", "N", "/a", "/b")
            .render()
            .is_err());
        assert!(CopyProcess::send("1ABC", "N", "/a", "/b").render().is_err());
    }
}
