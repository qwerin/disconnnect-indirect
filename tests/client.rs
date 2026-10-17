//! Integrační testy knihovny proti mock CDWS serveru.

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::*;
use connect_direct::{
    completion_code, extract_process_number, CdClient, Config, CopyProcess, Credentials,
    DeleteProcess, Error, Method, Protocol, Query, SubmitProcess,
};
use serde_json::{json, Value};
use wiremock::matchers::{body_partial_json, header, method, path, query_param};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

// ------------------------------------------------------------------ sign-on

#[tokio::test]
async fn sign_on_sends_credentials_and_returns_body() {
    let server = MockServer::start().await;
    signon_mock(JWT, CSRF).expect(1).mount(&server).await;

    let body = client(&server).sign_on().await.unwrap();
    assert_eq!(body["message"], "Signon is successful");
}

#[tokio::test]
async fn session_tokens_are_used_for_subsequent_calls() {
    let server = MockServer::start().await;
    signon_mock(JWT, CSRF).expect(1).mount(&server).await;
    authed("GET", "version", JWT)
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "version": "6.4.0" })))
        .expect(2)
        .mount(&server)
        .await;

    let c = client(&server);
    assert_eq!(c.version().await.unwrap()["version"], "6.4.0");
    // druhé volání už nesmí dělat nový sign-on
    assert_eq!(c.version().await.unwrap()["version"], "6.4.0");
}

#[tokio::test]
async fn sign_on_uses_configured_port_and_protocol() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(svc("signon")))
        .and(body_partial_json(
            json!({ "ipAddress": NODE, "port": 2363, "protocol": "TLS1.2" }),
        ))
        .respond_with(signon_ok(JWT, CSRF))
        .expect(1)
        .mount(&server)
        .await;

    let mut cfg = config(&server);
    cfg.node_port = 2363;
    cfg.protocol = Protocol::Tls12;
    CdClient::new(cfg).unwrap().sign_on().await.unwrap();
}

#[tokio::test]
async fn sign_on_failure_is_reported_as_api_error() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(svc("signon")))
        .respond_with(ResponseTemplate::new(401).set_body_string("bad credentials"))
        .mount(&server)
        .await;

    match client(&server).sign_on().await {
        Err(Error::Api { status, body }) => {
            assert_eq!(status.as_u16(), 401);
            assert_eq!(body, "bad credentials");
        }
        other => panic!("expected Api error, got {other:?}"),
    }
}

#[tokio::test]
async fn missing_authorization_header_is_an_error() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(svc("signon")))
        .respond_with(ResponseTemplate::new(200).insert_header("_csrf", CSRF))
        .mount(&server)
        .await;

    assert!(matches!(
        client(&server).sign_on().await,
        Err(Error::MissingHeader("Authorization"))
    ));
}

#[tokio::test]
async fn missing_xsrf_token_is_an_error() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(svc("signon")))
        .respond_with(ResponseTemplate::new(200).insert_header("Authorization", JWT))
        .mount(&server)
        .await;

    assert!(matches!(
        client(&server).sign_on().await,
        Err(Error::MissingHeader("_csrf"))
    ));
}

#[tokio::test]
async fn xsrf_token_falls_back_to_cookie() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(svc("signon")))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Authorization", JWT)
                .insert_header("Set-Cookie", "XSRF-TOKEN=from-cookie; Path=/; Secure"),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(svc("version")))
        .and(header("X-XSRF-TOKEN", "from-cookie"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "ok": true })))
        .expect(1)
        .mount(&server)
        .await;

    client(&server).version().await.unwrap();
}

#[tokio::test]
async fn certificate_auth_sends_flag_instead_of_basic_auth() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(svc("signon")))
        .and(header("CertificateAuthentication", "true"))
        .and(header("X-XSRF-TOKEN", SIGNON_XSRF))
        .and(|req: &Request| !req.headers.contains_key("authorization"))
        .respond_with(signon_ok(JWT, CSRF))
        .expect(1)
        .mount(&server)
        .await;

    let key = rcgen::generate_simple_self_signed(vec!["client.test".into()]).unwrap();
    let pem = format!("{}{}", key.cert.pem(), key.signing_key.serialize_pem());

    let mut cfg = config(&server);
    cfg.credentials = Credentials::Certificate {
        identity_pem: pem.into_bytes(),
    };
    CdClient::new(cfg).unwrap().sign_on().await.unwrap();
}

// ------------------------------------------------------------- re-login

#[tokio::test]
async fn expired_session_triggers_single_relogin_and_retry() {
    let server = MockServer::start().await;
    // 1. sign-on -> jwt-1, 2. sign-on -> jwt-2
    signon_mock(JWT, CSRF)
        .up_to_n_times(1)
        .expect(1)
        .mount(&server)
        .await;
    signon_mock("jwt-2", CSRF).expect(1).mount(&server).await;

    authed("POST", "processcontrolcriterias", JWT)
        .respond_with(ResponseTemplate::new(401))
        .expect(1)
        .mount(&server)
        .await;
    authed("POST", "processcontrolcriterias", "jwt-2")
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([{ "processNumber": 7 }])))
        .expect(1)
        .mount(&server)
        .await;

    let resp = client(&server).submit_text("P PROCESS").await.unwrap();
    assert_eq!(extract_process_number(&resp), Some(7));
}

#[tokio::test]
async fn persistent_401_is_returned_after_one_retry() {
    let server = MockServer::start().await;
    signon_mock(JWT, CSRF).expect(2).mount(&server).await;
    authed("GET", "version", JWT)
        .respond_with(ResponseTemplate::new(401).set_body_string("nope"))
        .expect(2)
        .mount(&server)
        .await;

    match client(&server).version().await {
        Err(Error::Api { status, .. }) => assert_eq!(status.as_u16(), 401),
        other => panic!("expected 401, got {other:?}"),
    }
}

#[tokio::test]
async fn auto_resignon_can_be_disabled() {
    let server = MockServer::start().await;
    signon_mock(JWT, CSRF).expect(1).mount(&server).await;
    authed("GET", "version", JWT)
        .respond_with(ResponseTemplate::new(401))
        .expect(1)
        .mount(&server)
        .await;

    let mut cfg = config(&server);
    cfg.auto_resignon = false;
    let err = CdClient::new(cfg).unwrap().version().await.unwrap_err();
    assert!(matches!(err, Error::Api { status, .. } if status.as_u16() == 401));
}

#[tokio::test]
async fn concurrent_calls_share_one_sign_on() {
    let server = MockServer::start().await;
    signon_matcher()
        .respond_with(signon_ok(JWT, CSRF).set_delay(Duration::from_millis(100)))
        .expect(1)
        .mount(&server)
        .await;
    authed("GET", "version", JWT)
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .expect(10)
        .mount(&server)
        .await;

    let c = Arc::new(client(&server));
    let tasks: Vec<_> = (0..10)
        .map(|_| {
            let c = c.clone();
            tokio::spawn(async move { c.version().await })
        })
        .collect();
    for t in tasks {
        t.await.unwrap().unwrap();
    }
}

// ------------------------------------------------------------- sign-out

#[tokio::test]
async fn sign_out_sends_delete_and_next_call_signs_on_again() {
    let server = MockServer::start().await;
    signon_mock(JWT, CSRF).expect(2).mount(&server).await;
    authed("DELETE", "signout", JWT)
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;
    authed("GET", "version", JWT)
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .expect(2)
        .mount(&server)
        .await;

    let c = client(&server);
    c.version().await.unwrap();
    c.sign_out().await.unwrap();
    c.version().await.unwrap();
}

#[tokio::test]
async fn sign_out_without_session_is_noop() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&server)
        .await;

    client(&server).sign_out().await.unwrap();
}

// ------------------------------------------------------------- processes

#[tokio::test]
async fn submit_process_sends_all_fields() {
    let server = MockServer::start().await;
    signon_mock(JWT, CSRF).mount(&server).await;

    let text = CopyProcess::send("PAYOUT", "PARTNER01", "/out/a.csv", "/in/a.csv")
        .render()
        .unwrap();
    let expected_text = text.clone();

    authed("POST", "processcontrolcriterias", JWT)
        .and(body_partial_json(json!({
            "processFile": expected_text,
            "secondaryNode": "OVERRIDE",
            "hold": "yes",
            "maxDelay": "unlimited",
            "newName": "RENAMED"
        })))
        .and(|req: &Request| {
            serde_json::from_slice::<Value>(&req.body)
                .ok()
                .and_then(|v| v.as_object().map(|o| o.len()))
                == Some(18)
        })
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([{
            "messageCode": 200, "message": "Process submitted", "processNumber": 126
        }])))
        .expect(1)
        .mount(&server)
        .await;

    let sp = SubmitProcess::new(text)
        .secondary_node("OVERRIDE")
        .hold("yes")
        .max_delay("unlimited")
        .new_name("RENAMED");
    let resp = client(&server).submit_process(&sp).await.unwrap();
    assert_eq!(extract_process_number(&resp), Some(126));
}

#[tokio::test]
async fn select_process_passes_query() {
    let server = MockServer::start().await;
    signon_mock(JWT, CSRF).mount(&server).await;
    authed("GET", "processcontrolcriterias", JWT)
        .and(query_param("processName", "PAYOUT"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .expect(1)
        .mount(&server)
        .await;

    client(&server)
        .select_process(&Query::process_name("PAYOUT"))
        .await
        .unwrap();
}

#[tokio::test]
async fn delete_process_sends_json_body() {
    let server = MockServer::start().await;
    signon_mock(JWT, CSRF).mount(&server).await;
    authed("DELETE", "processcontrolcriterias", JWT)
        .and(body_partial_json(
            json!({ "processNumber": "126", "force": "yes" }),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([{ "messageCode": 200 }])))
        .expect(1)
        .mount(&server)
        .await;

    client(&server)
        .delete_process(&DeleteProcess::by_number(126).force())
        .await
        .unwrap();
}

#[tokio::test]
async fn delete_without_filter_is_rejected_locally() {
    let server = MockServer::start().await;
    Mock::given(wiremock::matchers::any())
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&server)
        .await;

    let err = client(&server)
        .delete_process(&DeleteProcess::default())
        .await
        .unwrap_err();
    assert!(matches!(err, Error::InvalidProcess(_)));
}

// ------------------------------------------------------------- statistics

#[tokio::test]
async fn select_statistics_passes_query() {
    let server = MockServer::start().await;
    signon_mock(JWT, CSRF).mount(&server).await;
    authed("GET", "selectstatistics", JWT)
        .and(query_param("processNumber", "126"))
        .and(query_param("extra", "x"))
        .respond_with(ResponseTemplate::new(200).set_body_json(stats_with_end(126, "0")))
        .expect(1)
        .mount(&server)
        .await;

    let stats = client(&server)
        .select_statistics(&Query::process_number(126).param("extra", "x"))
        .await
        .unwrap();
    assert!(stats.as_array().unwrap().len() == 3);
}

#[tokio::test]
async fn wait_for_process_end_polls_until_pred() {
    let server = MockServer::start().await;
    signon_mock(JWT, CSRF).mount(&server).await;
    authed("GET", "selectstatistics", JWT)
        .respond_with(ResponseTemplate::new(200).set_body_json(stats_running(126)))
        .up_to_n_times(2)
        .expect(2)
        .mount(&server)
        .await;
    authed("GET", "selectstatistics", JWT)
        .respond_with(ResponseTemplate::new(200).set_body_json(stats_with_end(126, "4")))
        .expect(1)
        .mount(&server)
        .await;

    let rec = client(&server)
        .wait_for_process_end(126, Duration::from_millis(10), Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(rec["recordId"], "PRED");
    assert_eq!(completion_code(&rec).as_deref(), Some("4"));
}

#[tokio::test]
async fn wait_for_process_end_times_out() {
    let server = MockServer::start().await;
    signon_mock(JWT, CSRF).mount(&server).await;
    authed("GET", "selectstatistics", JWT)
        .respond_with(ResponseTemplate::new(200).set_body_json(stats_running(9)))
        .mount(&server)
        .await;

    let err = client(&server)
        .wait_for_process_end(9, Duration::from_millis(10), Duration::from_millis(80))
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Timeout(9)));
}

// ------------------------------------------------------------- generic / bodies

#[tokio::test]
async fn generic_call_supports_any_endpoint() {
    let server = MockServer::start().await;
    signon_mock(JWT, CSRF).mount(&server).await;
    authed("PUT", "netmapnodes", JWT)
        .and(query_param("name", "PARTNER01"))
        .and(body_partial_json(json!({ "maxPnode": 10 })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "updated": true })))
        .expect(1)
        .mount(&server)
        .await;

    let v = client(&server)
        .call(
            Method::PUT,
            "/netmapnodes",
            &Query::new().param("name", "PARTNER01"),
            Some(&json!({ "maxPnode": 10 })),
        )
        .await
        .unwrap();
    assert_eq!(v["updated"], true);
}

#[tokio::test]
async fn non_json_and_empty_bodies_are_handled() {
    let server = MockServer::start().await;
    signon_mock(JWT, CSRF).mount(&server).await;
    authed("GET", "version", JWT)
        .respond_with(ResponseTemplate::new(200).set_body_string("6.4.0.1"))
        .mount(&server)
        .await;
    authed("GET", "empty", JWT)
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;

    let c = client(&server);
    assert_eq!(c.version().await.unwrap(), Value::String("6.4.0.1".into()));
    assert_eq!(
        c.call(Method::GET, "empty", &Query::new(), None)
            .await
            .unwrap(),
        Value::Null
    );
}

#[tokio::test]
async fn server_error_keeps_status_and_body() {
    let server = MockServer::start().await;
    signon_mock(JWT, CSRF).mount(&server).await;
    authed("GET", "selectstatistics", JWT)
        .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
        .mount(&server)
        .await;

    let err = client(&server)
        .select_statistics(&Query::new())
        .await
        .unwrap_err();
    match &err {
        Error::Api { status, body } => {
            assert_eq!(status.as_u16(), 500);
            assert_eq!(body, "boom");
        }
        other => panic!("unexpected {other:?}"),
    }
    assert!(err.to_string().contains("500"));
}

#[tokio::test]
async fn trailing_slash_in_base_url_is_ok() {
    let server = MockServer::start().await;
    signon_mock(JWT, CSRF).expect(1).mount(&server).await;

    let mut cfg = config(&server);
    cfg.base_url = format!("{}/", server.uri());
    CdClient::new(cfg).unwrap().sign_on().await.unwrap();
}

// ------------------------------------------------------------- config

#[test]
fn base_url_without_scheme_is_rejected() {
    let cfg = Config::new("cdws:9443", NODE, USER, PASSWORD);
    assert!(matches!(CdClient::new(cfg), Err(Error::Config(_))));
}

#[test]
fn invalid_client_identity_is_rejected() {
    let mut cfg = Config::new("https://cdws:9443", NODE, USER, PASSWORD);
    cfg.credentials = Credentials::Certificate {
        identity_pem: b"not a pem".to_vec(),
    };
    assert!(matches!(CdClient::new(cfg), Err(Error::Config(_))));
}

#[test]
fn invalid_ca_certificate_is_rejected() {
    let mut cfg = Config::new("https://cdws:9443", NODE, USER, PASSWORD);
    cfg.extra_root_certs_pem.push(b"garbage".to_vec());
    assert!(CdClient::new(cfg).is_err());
}

#[test]
fn valid_ca_certificate_is_accepted() {
    let key = rcgen::generate_simple_self_signed(vec!["cdws.test".into()]).unwrap();
    let mut cfg = Config::new("https://cdws:9443", NODE, USER, PASSWORD);
    cfg.extra_root_certs_pem.push(key.cert.pem().into_bytes());
    assert!(CdClient::new(cfg).is_ok());
}

#[test]
fn credentials_debug_hides_password() {
    let c = Credentials::Basic {
        user: "u".into(),
        password: "topsecret".into(),
    };
    let s = format!("{c:?}");
    assert!(s.contains("***"));
    assert!(!s.contains("topsecret"));
}

// ------------------------------------------------------------- záškodník (regrese)

#[tokio::test]
async fn redirect_on_sign_on_is_not_followed() {
    let server = MockServer::start().await;
    let attacker = MockServer::start().await;
    Mock::given(wiremock::matchers::any())
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&attacker)
        .await;
    Mock::given(method("POST"))
        .and(path(svc("signon")))
        .respond_with(
            ResponseTemplate::new(302)
                .insert_header("Location", format!("{}/steal", attacker.uri())),
        )
        .mount(&server)
        .await;

    let err = client(&server).sign_on().await.unwrap_err();
    assert!(
        matches!(err, Error::Api { status, ref body } if status.as_u16() == 302 && body.contains("refused"))
    );
}

#[tokio::test]
async fn redirect_on_call_does_not_leak_session_token() {
    let server = MockServer::start().await;
    let attacker = MockServer::start().await;
    Mock::given(wiremock::matchers::any())
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&attacker)
        .await;
    signon_mock(JWT, CSRF).mount(&server).await;
    authed("GET", "version", JWT)
        .respond_with(
            ResponseTemplate::new(307)
                .insert_header("Location", format!("{}/steal", attacker.uri())),
        )
        .mount(&server)
        .await;

    let err = client(&server).version().await.unwrap_err();
    assert!(matches!(err, Error::Api { status, .. } if status.as_u16() == 307));
}

#[tokio::test]
async fn oversized_response_is_rejected() {
    let server = MockServer::start().await;
    signon_mock(JWT, CSRF).mount(&server).await;
    authed("GET", "version", JWT)
        .respond_with(ResponseTemplate::new(200).set_body_string("x".repeat(4096)))
        .mount(&server)
        .await;

    let mut cfg = config(&server);
    cfg.max_response_bytes = 1024;
    let err = CdClient::new(cfg).unwrap().version().await.unwrap_err();
    assert!(matches!(err, Error::ResponseTooLarge { limit: 1024 }));
}

#[tokio::test]
async fn huge_sign_on_token_is_rejected() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(svc("signon")))
        .respond_with(signon_ok(&"A".repeat(20_000), CSRF))
        .mount(&server)
        .await;

    let err = client(&server).sign_on().await.unwrap_err();
    assert!(matches!(err, Error::InvalidInput(_)), "{err:?}");
}

#[tokio::test]
async fn path_traversal_is_rejected_before_any_request() {
    let server = MockServer::start().await;
    Mock::given(wiremock::matchers::any())
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&server)
        .await;

    let c = client(&server);
    for p in [
        "../../etc/passwd",
        "%2e%2e/admin",
        "version?admin=1",
        "a\nb",
    ] {
        let err = c
            .call(Method::GET, p, &Query::new(), None)
            .await
            .unwrap_err();
        assert!(matches!(err, Error::InvalidInput(_)), "{p:?}: {err:?}");
    }
}

#[test]
fn dangerous_configs_are_rejected() {
    for url in [
        "https://user:pw@cdws:9443",
        "https://cdws:9443/?x=1",
        "https://cdws:9443/#f",
    ] {
        let cfg = Config::new(url, NODE, USER, PASSWORD);
        assert!(matches!(CdClient::new(cfg), Err(Error::Config(_))), "{url}");
    }
    let mut cfg = Config::new("https://cdws:9443", NODE, USER, PASSWORD);
    cfg.timeout = Duration::ZERO;
    assert!(matches!(CdClient::new(cfg), Err(Error::Config(_))));
    let mut cfg = Config::new("https://cdws:9443", NODE, USER, PASSWORD);
    cfg.max_response_bytes = 0;
    assert!(matches!(CdClient::new(cfg), Err(Error::Config(_))));
}

#[tokio::test]
async fn long_error_bodies_are_shortened_in_messages_only() {
    let server = MockServer::start().await;
    signon_mock(JWT, CSRF).mount(&server).await;
    let body = format!("<html>{}</html>", "x".repeat(10_000));
    authed("GET", "version", JWT)
        .respond_with(ResponseTemplate::new(422).set_body_string(body.clone()))
        .mount(&server)
        .await;

    let err = client(&server).version().await.unwrap_err();
    assert!(err.to_string().len() < 400, "{}", err.to_string().len());
    assert!(err.to_string().contains("bytes total"));
    match err {
        Error::Api { body: full, .. } => assert_eq!(full, body),
        other => panic!("{other:?}"),
    }
}
