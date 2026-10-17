//! Property-based „fuzz“ testy veřejného API (proptest).
//!
//! Výchozí počet případů je 256 na test; v CI se pouští i s `PROPTEST_CASES=20000`.

use connect_direct::{
    completion_code, extract_process_number, find_stat_record, is_dangerous_char, sanitize,
    CopyProcess, Direction, Disp,
};
use proptest::prelude::*;
use serde_json::Value;

/// Řetězce bohaté na znaky, kterými se dá rozbít jazyk procesů.
fn nasty_string() -> impl Strategy<Value = String> {
    prop_oneof![
        any::<String>(),
        "[a-zA-Z0-9 /()\"',;=&\\\\\n\r\t\u{1b}\u{2028}\u{202e}.:*-]{0,40}",
        Just("x ) TO ( FILE=/etc/shadow PNODE ) PEND".to_string()),
        Just("\":a:\" ) PEND".to_string()),
        Just("/a\nPEND".to_string()),
    ]
}

/// Rozdělí text procesu na tokeny mimo uvozovky/apostrofy (jako parser C:D).
/// Vrací None, když uvozovky nejsou vyvážené.
fn tokenize(p: &str) -> Option<Vec<String>> {
    let (mut tokens, mut cur) = (Vec::new(), String::new());
    let (mut dq, mut sq, mut esc) = (false, false, false);
    for c in p.chars() {
        if dq {
            cur.push(c);
            match (c, esc) {
                ('\\', false) => esc = true,
                ('"', false) => dq = false,
                _ => esc = false,
            }
        } else if sq {
            cur.push(c);
            if c == '\'' {
                sq = false;
            }
        } else if c.is_whitespace() {
            if !cur.is_empty() {
                tokens.push(std::mem::take(&mut cur));
            }
        } else {
            cur.push(c);
            match c {
                '"' => dq = true,
                '\'' => sq = true,
                _ => {}
            }
        }
    }
    if dq || sq {
        return None;
    }
    if !cur.is_empty() {
        tokens.push(cur);
    }
    Some(tokens)
}

fn arb_json() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        any::<i64>().prop_map(Value::from),
        any::<u64>().prop_map(Value::from),
        any::<f64>()
            .prop_map(|f| serde_json::Number::from_f64(f).map_or(Value::Null, Value::Number)),
        nasty_string().prop_map(Value::String),
        Just(Value::String("PRED".into())),
    ];
    leaf.prop_recursive(8, 256, 8, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..8).prop_map(Value::Array),
            prop::collection::vec(
                (
                    prop_oneof![
                        Just("processNumber".to_string()),
                        Just("pnum".to_string()),
                        Just("recordId".to_string()),
                        Just("ccode".to_string()),
                        any::<String>()
                    ],
                    inner
                ),
                0..8
            )
            .prop_map(|kv| Value::Object(kv.into_iter().collect())),
        ]
    })
}

proptest! {
    /// Žádný vstup nesmí změnit strukturu procesu (vložit krok, ukončit blok, PEND…).
    #[test]
    fn prop_render_never_injects(
        name in nasty_string(),
        snode in nasty_string(),
        from in nasty_string(),
        to in nasty_string(),
        from_sys in proptest::option::of(nasty_string()),
        to_sys in proptest::option::of(nasty_string()),
        receive in any::<bool>(),
    ) {
        let dir = if receive { Direction::Receive } else { Direction::Send };
        let mut p = CopyProcess::new(dir, &name, &snode, &from, &to).disp(Disp::Rpl);
        if let Some(s) = &from_sys { p = p.from_sysopts(s); }
        if let Some(s) = &to_sys { p = p.to_sysopts(s); }

        let Ok(text) = p.render() else { return Ok(()); };

        // 1) žádné nebezpečné znaky kromě konců řádků
        prop_assert!(!text.chars().any(|c| c != '\n' && is_dangerous_char(c)), "{text:?}");

        // 2) kostra tokenů mimo uvozovky je přesně daná
        let tokens = tokenize(&text).expect("balanced quotes");
        let (from_node, to_node) = if receive { ("SNODE", "PNODE") } else { ("PNODE", "SNODE") };
        let mut expected: Vec<String> = vec![
            name.to_ascii_uppercase(), "PROCESS".into(), format!("SNODE={snode}"), "HOLD=NO".into(),
            "STEP01".into(), "COPY".into(), "FROM".into(), "(".into(), "FILE=*".into(), from_node.into(),
        ];
        if from_sys.is_some() { expected.push("SYSOPTS=*".into()); }
        expected.extend([")".into(), "TO".into(), "(".into(), "FILE=*".into(), to_node.into(), "DISP=RPL".into()]);
        if to_sys.is_some() { expected.push("SYSOPTS=*".into()); }
        expected.extend([")".into(), "PEND".into()]);

        prop_assert_eq!(tokens.len(), expected.len(), "{:?}\n{}", tokens, text);
        for (t, e) in tokens.iter().zip(&expected) {
            match e.strip_suffix('*') {
                Some(prefix) => prop_assert!(t.starts_with(prefix), "{t} !~ {e}\n{text}"),
                None => prop_assert_eq!(t, e),
            }
        }
    }

    /// Heuristiky nad odpověďmi serveru nesmí spadnout na žádném JSONu.
    #[test]
    fn prop_json_heuristics_never_panic(v in arb_json()) {
        let _ = extract_process_number(&v);
        if let Some(rec) = find_stat_record(&v, "PRED") {
            if let Some(cc) = completion_code(rec) {
                prop_assert!(!sanitize(&cc).chars().any(is_dangerous_char));
            }
        }
    }
}
