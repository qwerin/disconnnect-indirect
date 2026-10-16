# connect-direct

[![CI](https://github.com/qwerin/disconnnect-indirect/actions/workflows/ci.yml/badge.svg)](https://github.com/qwerin/disconnnect-indirect/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Async Rust klient (a CLI `cdctl`) pro **IBM Sterling Connect:Direct Web Services (CDWS)** REST API.

Funkce: sign-on/sign-out se správou JWT + XSRF tokenu, automatický re-login při 401,
submit procesu (text nebo `.cdp` na serveru), generátor COPY procesů, select/delete process,
select statistics, čekání na dokončení procesu, verze CDWS a obecné `call()` pro ostatní
endpointy (netmap, user proxy, Secure+, …). TLS přes rustls, vlastní CA i certifikátová autentizace.

## Stažení (Linux amd64)

Hotová statická binárka `cdctl` (musl, bez závislostí na glibc/OpenSSL – běží na RHEL, SLES, Ubuntu, Alpine…)
je u každého [release](https://github.com/qwerin/disconnnect-indirect/releases):

```bash
curl -LO https://github.com/qwerin/disconnnect-indirect/releases/latest/download/cdctl-x86_64-unknown-linux-musl.tar.gz
curl -LO https://github.com/qwerin/disconnnect-indirect/releases/latest/download/cdctl-x86_64-unknown-linux-musl.tar.gz.sha256
sha256sum -c cdctl-x86_64-unknown-linux-musl.tar.gz.sha256
tar xzf cdctl-x86_64-unknown-linux-musl.tar.gz && ./cdctl --version
```

Build z každého commitu v `main` je také v záložce *Actions* jako artefakt `cdctl-linux-amd64`.

**Vydání nové verze:** zvednout `version` v `Cargo.toml`, commit, pak `git tag v0.2.0 && git push --tags`.
Workflow ověří, že tag odpovídá verzi, sestaví binárku a založí GitHub Release.

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

## Konfigurace a logování

`cdctl` čte konfiguraci z `/etc/cdctl/config.toml` (jiný soubor: `--config` / `CDCTL_CONFIG`).
Priorita: **přepínač > proměnná prostředí > konfigurační soubor > výchozí hodnota**.
Kompletní ukázka s komentáři je v [`config.example.toml`](config.example.toml).

```toml
[connection]
url       = "https://cdws.example.com:9443"
node_host = "cdnode1.example.com"
user      = "cduser"
# password = "..."          # raději CD_PASSWORD; se heslem v souboru: chmod 600

[log]
dir       = "/var/log/cdctl" # výchozí
level     = "info"           # nebo "connect_direct=debug,info", "trace"
format    = "text"           # text | json
rotation  = "daily"          # minutely | hourly | daily | never
max_files = 14
```

Každé spuštění se loguje do `/var/log/cdctl/cdctl.<datum>.log`: start (verze, příkaz, argumenty, PID, uživatel,
použitá konfigurace), přihlášení k uzlu, každé HTTP volání se stavem a dobou trvání (`debug`), opakované
přihlášení po 401, požadované přenosy (směr, SNODE, zdroj, cíl), číslo odeslaného procesu, výsledek
a completion code, chyby včetně celé příčiny (např. `tcp connect error: Connection refused`) a konec
s exit kódem. Řádky jednoho spuštění spojuje `run=<id>`; na úrovni `trace` jdou do logu i těla
požadavků a odpovědí.

Hesla, Basic autentizace, JWT a XSRF tokeny se **do logu nikdy nezapisují** (ověřeno testem na úrovni `trace`),
heslo zadané přepínačem `--password` se v logu maskuje.

Když `/var/log/cdctl` není zapisovatelný (běh bez roota), použije se `~/.local/state/cdctl/log`
a vypíše se varování. Explicitně nastavený adresář se nenahrazuje – když do něj nejde zapisovat, `cdctl` skončí chybou.

Nasazení na server:

```bash
sudo install -d -o cduser -g cduser -m 750 /var/log/cdctl
sudo install -d -m 755 /etc/cdctl
sudo install -o cduser -g cduser -m 600 config.example.toml /etc/cdctl/config.toml
cdctl config      # výsledná konfigurace a cesta k logu (heslo se nevypisuje)
```

Knihovna sama loguje přes [`tracing`](https://crates.io/crates/tracing) (target `connect_direct`);
v aplikaci stačí nastavit libovolný `tracing` subscriber.

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

## Vývoj a testy

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features          # unit + integrační + CLI + doc testy
cargo test --no-default-features   # jen knihovna, bez CLI
```

Testy nepotřebují reálný Connect:Direct – běží proti mock CDWS serveru ([wiremock](https://crates.io/crates/wiremock)):

- `src/*` – unit testy generátoru procesů, serializace a heuristik nad odpověďmi
- `tests/client.rs` – knihovna: sign-on (Basic i certifikát), XSRF z hlavičky i cookie, re-login při 401,
  sdílená session při souběžných voláních, submit/select/delete, statistiky, polling a timeout, chybové stavy
- `tests/cli.rs` – binárka `cdctl`: dry-run, validace vstupů, exit kódy, všechny subpříkazy end-to-end,
  konfigurační soubor a priority, logování (obsah, JSON formát, úrovně, žádné úniky hesel/tokenů, chybné cesty)

CI (GitHub Actions) spouští rustfmt, clippy, testy na Linuxu/macOS/Windows (stable + beta),
kontrolu MSRV (Rust 1.88), build dokumentace, měření pokrytí (cargo-llvm-cov) a bezpečnostní audit
závislostí (cargo-deny). Navíc jednou týdně.

Pull requesty a issues jsou vítány – hlavně zkušenosti s reálnými odpověďmi různých verzí CDWS,
ať jde heuristiku ve `models.rs` nahradit pevně typovanými strukturami.

## Licence

[MIT](LICENSE)

---

*Neoficiální projekt, není spojen s IBM. IBM, Sterling a Connect:Direct jsou ochranné známky
společnosti International Business Machines Corporation.*
