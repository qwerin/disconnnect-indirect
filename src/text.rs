//! Bezpečné zacházení s nedůvěryhodným textem (odpovědi serveru, cesty, argumenty).

/// Znaky, které nesmí projít do logu, terminálu ani textu procesu:
/// řídicí znaky (vč. ESC a nového řádku), oddělovače řádků/odstavců,
/// obousměrné (bidi) přepínače a BOM / zero-width no-break space.
pub fn is_dangerous_char(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{2028}'
                | '\u{2029}'
                | '\u{200E}'
                | '\u{200F}'
                | '\u{202A}'..='\u{202E}'
                | '\u{2066}'..='\u{2069}'
                | '\u{FEFF}'
        )
}

/// Zneškodní text pro log nebo terminál: nebezpečné znaky nahradí escape sekvencí
/// (`\n`, `\r`, `\t`, `\u{1b}`, …). Brání padělání řádků logu a terminálovým escape útokům.
pub fn sanitize(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if is_dangerous_char(c) {
            out.extend(c.escape_default());
        } else {
            out.push(c);
        }
    }
    out
}

/// Zkrátí text na nejvýše `max` bajtů (na hranici znaku) a zneškodní ho.
pub(crate) fn truncate_sanitized(s: &str, max: usize) -> String {
    if s.len() <= max {
        return sanitize(s);
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}… ({} bytes total)", sanitize(&s[..end]), s.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn escapes_newlines_and_escape_sequences() {
        assert_eq!(sanitize("a\nb"), "a\\nb");
        assert_eq!(sanitize("\u{1b}[31mred"), "\\u{1b}[31mred");
        assert_eq!(sanitize("x\u{202E}y"), "x\\u{202e}y");
        assert_eq!(sanitize("Žluťoučký kůň"), "Žluťoučký kůň");
    }

    #[test]
    fn truncates_on_char_boundary() {
        let s = "ěěěěěě"; // 2 bajty na znak
        let t = truncate_sanitized(s, 5);
        assert!(t.starts_with("ěě…"), "{t}");
        assert_eq!(truncate_sanitized("abc", 10), "abc");
    }

    proptest! {
        #[test]
        fn prop_sanitize_removes_all_dangerous_chars(s in any::<String>()) {
            let out = sanitize(&s);
            prop_assert!(!out.chars().any(is_dangerous_char));
            // bezpečný text se nemění
            if !s.chars().any(is_dangerous_char) {
                prop_assert_eq!(out, s);
            }
        }

        #[test]
        fn prop_truncate_never_panics(s in any::<String>(), max in 0usize..64) {
            let out = truncate_sanitized(&s, max);
            prop_assert!(!out.chars().any(is_dangerous_char));
        }
    }
}
