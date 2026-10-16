//! Společné pomocné funkce pro integrační testy – mock CDWS server nad wiremock.
#![allow(dead_code)]

use std::time::Duration;

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use connect_direct::{CdClient, Config};
use serde_json::{json, Value};
use wiremock::matchers::{body_json, header, method, path};
use wiremock::{Mock, MockBuilder, MockServer, ResponseTemplate};

pub const USER: &str = "cduser";
pub const PASSWORD: &str = "secret";
pub const NODE: &str = "cdnode1";
pub const JWT: &str = "jwt-1";
pub const CSRF: &str = "csrf-1";
/// Fixní XSRF hodnota, kterou CDWS vyžaduje při sign-on.
pub const SIGNON_XSRF: &str = "Y2hlY2tpdA==";

/// Celá cesta k endpointu, např. `svc("signon")` -> `/cdwebconsole/svc/signon`.
pub fn svc(p: &str) -> String {
    format!("/cdwebconsole/svc/{p}")
}

pub fn basic_auth() -> String {
    format!("Basic {}", B64.encode(format!("{USER}:{PASSWORD}")))
}

pub fn signon_body() -> Value {
    json!({ "ipAddress": NODE, "port": 1363, "protocol": "TCPIP" })
}

/// Úspěšná odpověď na sign-on s danými tokeny v hlavičkách.
pub fn signon_ok(jwt: &str, csrf: &str) -> ResponseTemplate {
    ResponseTemplate::new(200)
        .insert_header("Authorization", jwt)
        .insert_header("_csrf", csrf)
        .set_body_json(json!({ "message": "Signon is successful" }))
}

/// Matcher pro sign-on, který ověří hlavičky i tělo požadavku.
pub fn signon_matcher() -> MockBuilder {
    Mock::given(method("POST"))
        .and(path(svc("signon")))
        .and(header("X-XSRF-TOKEN", SIGNON_XSRF))
        .and(header("Authorization", basic_auth().as_str()))
        .and(body_json(signon_body()))
}

/// Mock úspěšného sign-on.
pub fn signon_mock(jwt: &str, csrf: &str) -> Mock {
    signon_matcher().respond_with(signon_ok(jwt, csrf))
}

/// Request builder, který vyžaduje session hlavičky z úspěšného sign-on.
pub fn authed(m: &str, p: &str, jwt: &str) -> MockBuilder {
    Mock::given(method(m))
        .and(path(svc(p)))
        .and(header("Authorization", jwt))
        .and(header("X-XSRF-TOKEN", CSRF))
}

pub fn config(server: &MockServer) -> Config {
    let mut cfg = Config::new(server.uri(), NODE, USER, PASSWORD);
    cfg.timeout = Duration::from_secs(10);
    cfg
}

pub fn client(server: &MockServer) -> CdClient {
    CdClient::new(config(server)).expect("client builds")
}

/// Statistiky s koncem procesu (PRED) a daným completion code.
pub fn stats_with_end(pnum: u64, ccode: &str) -> Value {
    json!([
        { "recordId": "PSTR", "processNumber": pnum, "ccode": "0" },
        { "recordId": "CTRC", "processNumber": pnum, "ccode": "0" },
        { "recordId": "PRED", "processNumber": pnum, "ccode": ccode }
    ])
}

/// Statistiky běžícího procesu (bez PRED).
pub fn stats_running(pnum: u64) -> Value {
    json!([{ "recordId": "PSTR", "processNumber": pnum, "ccode": "0" }])
}
