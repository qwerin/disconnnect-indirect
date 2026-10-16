# connect-direct

[![CI](https://github.com/qwerin/disconnnect-indirect/actions/workflows/ci.yml/badge.svg)](https://github.com/qwerin/disconnnect-indirect/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Async Rust klient (a CLI `cdctl`) pro **IBM Sterling Connect:Direct Web Services (CDWS)** REST API.

Funkce: sign-on/sign-out se správou JWT + XSRF tokenu, automatický re-login při 401,
submit procesu (text nebo `.cdp` na serveru), generátor COPY procesů, select/delete process,
select statistics, čekání na dokončení procesu, verze CDWS a obecné `call()` pro ostatní
endpointy (netmap, user proxy, Secure+, …). TLS přes rustls, vlastní CA i certifikátová autentizace.

## Knihovna

```toml
[dependencies]
connect-direct = { git = "https://github.com/qwerin/disconnnect-indirect", default-features = false }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

```rust
use std::time::Duration;
use connect_direct::*;

#[tokio::main]
async fn main() -> Result<()> {
    let mut cfg = Config::new("https://cdws:9443", "cdnode1", "cduser", "secret");
    cfg.extra_root_certs_pem.push(std::fs::read("cdws-ca.pem").unwrap());
    let cd = CdClient::new(cfg)?;

    let text = CopyProcess::send("PAYOUT", "PARTNER01", "/data/out/pay.csv", "/in/pay.csv")
        .disp(Disp::Rpl)
        .render()?;
    let resp = cd.submit_process(&SubmitProcess::new(text)).await?;

    if let Some(pnum) = extract_process_number(&resp) {
        let end = cd.wait_for_process_end(pnum, Duration::from_secs(5), Duration::from_secs(600)).await?;
        println!("ccode = {:?}", completion_code(&end));
    }

    // jakýkoli jiný endpoint relativně k /cdwebconsole/svc/
    let v = cd.call(Method::GET, "version", &Query::new(), None).await?;
    println!("{v}");

    cd.sign_out().await
}
```

## CLI

```bash
cargo install --git https://github.com/qwerin/disconnnect-indirect
export CDWS_URL=https://cdws:9443 CD_NODE_HOST=cdnode1 CD_USER=cduser CD_PASSWORD=secret
# volitelně: CD_NODE_PORT=1363 CD_PROTOCOL=TLS1.2 CDWS_CA_CERT=ca.pem CDWS_INSECURE=true

cdctl version
cdctl send    --snode PARTNER01 --from /out/a.csv --to /in/a.csv --name PAYOUT --wait
cdctl receive --snode PARTNER01 --from /out/b.csv --to /in/b.csv --dry-run   # jen vypíše proces
cdctl submit  --file ./muj_proces.cdp --wait
cdctl submit  --server-file /opt/cdunix/process/send.cdp
cdctl stats   --process-number 126
cdctl processes
cdctl delete  --process-number 126 --force
cdctl raw GET netmapnodes -q name=PARTNER01
```

Exit kód: `0` OK, `2` proces skončil s nenulovým completion code, `1` chyba.

## Poznámky k API

- Sign-on: `POST /cdwebconsole/svc/signon` s `Authorization: Basic …` a fixním
  `X-XSRF-TOKEN: Y2hlY2tpdA==`; tělo `{"ipAddress", "port", "protocol"}`.
  Z odpovědi se bere hlavička `Authorization` (JWT) a `_csrf` (XSRF token pro další volání).
- Pokud vaše verze CDWS čeká v sign-on jiný název pole pro port, upravte `SignonBody` v `src/models.rs`.
- Tvar JSON odpovědí se mezi verzemi CDWS liší, proto API vrací `serde_json::Value`.
  `extract_process_number` a `wait_for_process_end` hledají pole heuristicky
  (`processNumber`, záznam `PRED`, `ccode`) – ověřte proti `https://<cdws>/cdws-doc/` vaší instalace.
  Spolehlivější alternativa k pollingu: `SubmitProcess::new(..).max_delay("unlimited")`.
- `/version` endpoint existuje od CDWS 6.3.0.9.
- `CDWS_INSECURE` / `accept_invalid_certs` vypíná ověřování TLS – používejte jen v testu.

## Vývoj

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test
```

Pull requesty a issues jsou vítány – hlavně zkušenosti s reálnými odpověďmi různých verzí CDWS,
ať jde heuristiku ve `models.rs` nahradit pevně typovanými strukturami.

## Licence

[MIT](LICENSE)

---

*Neoficiální projekt, není spojen s IBM. IBM, Sterling a Connect:Direct jsou ochranné známky
společnosti International Business Machines Corporation.*
