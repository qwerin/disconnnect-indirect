# Changelog

Všechny podstatné změny projektu. Formát vychází z [Keep a Changelog](https://keepachangelog.com/cs/1.1.0/),
verze se řídí [sémantickým verzováním](https://semver.org/lang/cs/) (do 1.0.0 může minor verze rozbít API).

Každá změna se zapisuje do sekce **[Unreleased]**; při vydání se sekce přejmenuje na novou verzi.
Text sekce se použije jako popis GitHub Release a CI hlídá, že verze z `Cargo.toml` tu má záznam.

## [Unreleased]

### Přidáno
- `CHANGELOG.md`; popis GitHub Release se generuje z odpovídající sekce changelogu.
- CI kontroluje, že verze z `Cargo.toml` má v changelogu záznam; release se bez něj nevydá.

## [0.3.1] - 2026-10-17

Audit všech závislostí (cargo-deny + RustSec, crates.io, strom závislostí): žádné známé zranitelnosti,
žádné neudržované ani stažené crates, jen permisivní licence, jen crates.io.

### Změněno
- Aktualizace závislostí: `reqwest` 0.12 → 0.13 (řada 0.12 už nedostává opravy), `toml` 0.9 → 1.1,
  `base64` 0.22 → 0.23, `rcgen` 0.13 → 0.14 (jen testy). Z binárky zmizely duplicitní verze crates.
- TLS: `rustls` s kryptografií `aws-lc-rs` (dříve `ring`).
- **Certifikát CDWS se ověřuje proti systémovému úložišti certifikátů** (`rustls-platform-verifier`),
  dříve proti certifikátům zabudovaným v binárce. `ca_cert` / `--ca-cert` se přidává k systémovým.
  Na systému bez balíčku `ca-certificates` je nutné zadat `--ca-cert`.
- Statická binárka vzrostla z 3,6 na 7,2 MB (kvůli `aws-lc-rs`).
- Text chyby `Error::Api` zkracuje tělo odpovědi na 300 bajtů (dříve celé HTML stránky do terminálu);
  celé tělo zůstává v poli `body`.

### Přidáno
- Release obsahuje `THIRD-PARTY-LICENSES.txt` s licencemi všech 127 crates zkompilovaných do binárky
  (`scripts/third_party_licenses.py`).
- `deny.toml` s pravidly pro závislosti; CI spouští plné `cargo deny check` při každém pushi a jednou týdně.
- Dependabot pro Rust crates i GitHub Actions.

### Bezpečnost
- Všechny GitHub Actions připnuté na konkrétní commit (SHA) a povýšené (`checkout` v7, `upload-artifact` v7,
  `download-artifact` v8, `action-gh-release` v3); checkout bez uloženého tokenu (`persist-credentials: false`).
- Zakázané závislosti OpenSSL / `native-tls` – TLS je čistě v Rustu.

## [0.3.0] - 2026-10-17

Odolnost proti zlým vstupům. Nová sada útoků (`scripts/saboteur`, 37 útoků) – verze 0.2.0 jich odrazila 10,
tato verze všech 37.

### Bezpečnost
- Klient nesleduje HTTP přesměrování – zlý server mohl přesměrováním získat session token (`X-XSRF-TOKEN`).
- Cesty API jsou omezené na `/cdwebconsole/svc/`; `../`, `%2e%2e`, `?` a `#` se odmítnou
  (dříve `cdctl raw GET ../../etc/passwd` mířil mimo API).
- Generátor procesů nedovolí změnit strukturu procesu: `SYSOPTS` musí být jeden token nebo korektně
  uzavřený řetězec (dříve šlo vložit vlastní krok, např. `RUN TASK`); cesty s řídicími a bidi znaky se odmítnou.
- Limit velikosti odpovědi serveru (výchozí 64 MiB, `[connection] max_response_mb`) a tokenů ze sign-on (16 KiB).
- Limit 1 MiB pro konfigurační soubor, `.cdp` soubor a certifikát (`/dev/zero` dříve vyčerpal paměť).
- Název souboru logu musí být prostý název – dříve šlo zapsat log mimo adresář logů, i do `/`.
- Řídicí znaky z dat (nové řádky, ESC, bidi) se v logu i na terminálu escapují – nejde padělat řádky logu
  ani poslat escape sekvence do terminálu.

### Opraveno
- `cdctl … | head` už nekončí pádem („Broken pipe“).
- Odmítá se nulový timeout a port, prázdná úroveň logu a `base_url` s přihlašovacími údaji, query nebo fragmentem.
- Cesty obsahující `'` se uzavírají do uvozovek; uzavřená cesta nesmí končit zpětným lomítkem.

### Přidáno
- `scripts/saboteur/run.sh` se zlým CDWS serverem; běží v CI.
- Property testy (proptest) pro strukturu procesů, sestavení URL, zpracování JSON, parser konfigurace
  a zápis logu; v CI s 20 000 náhodnými vstupy na test.
- Veřejné funkce `connect_direct::sanitize` a `is_dangerous_char`.

### Změněno (API knihovny)
- `Error` je `#[non_exhaustive]`, nové varianty `InvalidInput` a `ResponseTooLarge`.
- `Config` má nové pole `max_response_bytes`.

## [0.2.0] - 2026-10-16

### Přidáno
- Konfigurační soubor `/etc/cdctl/config.toml` (`--config`, `CDCTL_CONFIG`) se sekcemi `[connection]` a `[log]`;
  priorita přepínač > proměnná prostředí > soubor > výchozí hodnota; neznámé klíče jsou chyba.
- Logování do `/var/log/cdctl` s rotací (minutely/hourly/daily/never), počtem uchovaných souborů, formátem
  text/JSON, filtrem úrovní a volitelným výpisem na stderr; bez práv k `/var/log` se použije `~/.local/state/cdctl/log`.
- Záznam každého spuštění (`run=<id>`): příkaz, argumenty, uživatel, přenosy, číslo procesu, completion code,
  exit kód a doba běhu.
- Příkaz `cdctl config` – výsledná konfigurace a cesta k logu.
- Knihovna loguje přes `tracing`; funkce `error_chain` pro celý řetězec příčin chyby.
- `--timeout` / `CDWS_TIMEOUT`; `config.example.toml` v release balíčku.

### Bezpečnost
- Hesla, tokeny a Basic autentizace se nikdy nelogují; heslo z `--password` se v logu maskuje.
- Varování, když je konfigurační soubor s heslem čitelný pro ostatní uživatele.

## [0.1.0] - 2026-10-16

První vydání.

### Přidáno
- Async klient pro IBM Sterling Connect:Direct Web Services: sign-on/sign-out (Basic i certifikát),
  automatické opětovné přihlášení při 401, submit/select/delete procesu, statistiky, čekání na konec procesu,
  obecné volání libovolného endpointu.
- `CopyProcess` – generátor COPY procesů (send/receive, DISP, SYSOPTS).
- CLI `cdctl` (`version`, `send`, `receive`, `submit`, `stats`, `processes`, `delete`, `raw`).
- Unit, integrační a CLI testy proti mock serveru; CI na Linuxu, macOS a Windows; MSRV 1.88.
- Release workflow se statickou binárkou pro Linux amd64.

[Unreleased]: https://github.com/qwerin/disconnnect-indirect/compare/v0.3.1...HEAD
[0.3.1]: https://github.com/qwerin/disconnnect-indirect/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/qwerin/disconnnect-indirect/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/qwerin/disconnnect-indirect/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/qwerin/disconnnect-indirect/releases/tag/v0.1.0
