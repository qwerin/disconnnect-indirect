//! Testy CLI `cdctl` – spouští skutečnou binárku proti mock CDWS serveru.

mod common;

use assert_cmd::Command;
use common::*;
use predicates::prelude::*;
use serde_json::json;
use wiremock::matchers::{body_partial_json, query_param};
use wiremock::{MockServer, ResponseTemplate};

const ENV_VARS: [&str; 8] = [
    "CDWS_URL",
    "CD_NODE_HOST",
    "CD_NODE_PORT",
    "CD_PROTOCOL",
    "CD_USER",
    "CD_PASSWORD",
    "CDWS_CA_CERT",
    "CDWS_INSECURE",
];

/// `cdctl` s vyčištěným prostředím (bez připojení).
fn cdctl() -> Command {
    let mut cmd = Command::cargo_bin("cdctl").unwrap();
    for v in ENV_VARS {
        cmd.env_remove(v);
    }
    cmd
}

/// `cdctl` napojený na mock server.
fn cdctl_for(server: &MockServer) -> Command {
    let mut cmd = cdctl();
    cmd.env("CDWS_URL", server.uri())
        .env("CD_NODE_HOST", NODE)
        .env("CD_USER", USER)
        .env("CD_PASSWORD", PASSWORD);
    cmd
}

/// assert_cmd je blokující – spustíme ho mimo async runtime.
async fn run(mut cmd: Command) -> assert_cmd::assert::Assert {
    tokio::task::spawn_blocking(move || cmd.assert())
        .await
        .unwrap()
}

async fn mount_signon_and_signout(server: &MockServer) {
    signon_mock(JWT, CSRF).mount(server).await;
    authed("DELETE", "signout", JWT)
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(server)
        .await;
}

// ------------------------------------------------------------------ offline

#[test]
fn help_lists_subcommands() {
    cdctl().arg("--help").assert().success().stdout(
        predicate::str::contains("send")
            .and(predicate::str::contains("receive"))
            .and(predicate::str::contains("stats"))
            .and(predicate::str::contains("raw")),
    );
}

#[test]
fn version_flag_works() {
    cdctl()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("cdctl"));
}

#[test]
fn dry_run_send_prints_process() {
    cdctl()
        .args([
            "send",
            "--snode",
            "PARTNER01",
            "--from",
            "/out/pay roll.csv",
            "--to",
            "/in/pay.csv",
            "--name",
            "PAYOUT",
            "--disp",
            "new",
            "--dry-run",
        ])
        .assert()
        .success()
        .stdout(
            predicate::str::starts_with("PAYOUT PROCESS")
                .and(predicate::str::contains("SNODE=PARTNER01"))
                .and(predicate::str::contains("FILE=\"/out/pay roll.csv\""))
                .and(predicate::str::contains("DISP=NEW"))
                .and(predicate::str::contains("PEND")),
        );
}

#[test]
fn dry_run_receive_swaps_nodes() {
    cdctl()
        .args([
            "receive",
            "--snode",
            "N2",
            "--from",
            "/r/x",
            "--to",
            "/l/x",
            "--dry-run",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "FILE=/r/x\n        SNODE\n    )\n    TO (\n        FILE=/l/x\n        PNODE",
        ));
}

#[test]
fn invalid_process_name_fails() {
    cdctl()
        .args([
            "send",
            "--snode",
            "N",
            "--from",
            "/a",
            "--to",
            "/b",
            "--name",
            "WAYTOOLONGNAME",
            "--dry-run",
        ])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("invalid process definition"));
}

#[test]
fn invalid_disp_is_rejected_by_parser() {
    cdctl()
        .args([
            "send",
            "--snode",
            "N",
            "--from",
            "/a",
            "--to",
            "/b",
            "--disp",
            "XYZ",
            "--dry-run",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("DISP"));
}

#[test]
fn missing_connection_settings_fail() {
    cdctl()
        .arg("version")
        .assert()
        .code(1)
        .stderr(predicate::str::contains("missing CDWS_URL"));
}

#[test]
fn submit_requires_file_or_server_file() {
    cdctl()
        .env("CDWS_URL", "http://127.0.0.1:9")
        .env("CD_NODE_HOST", NODE)
        .env("CD_USER", USER)
        .arg("submit")
        .assert()
        .code(1)
        .stderr(predicate::str::contains("--file or --server-file"));
}

// ------------------------------------------------------------------ online

#[tokio::test(flavor = "multi_thread")]
async fn version_prints_json() {
    let server = MockServer::start().await;
    mount_signon_and_signout(&server).await;
    authed("GET", "version", JWT)
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "version": "6.4.0" })))
        .expect(1)
        .mount(&server)
        .await;

    let mut cmd = cdctl_for(&server);
    cmd.arg("version");
    run(cmd)
        .await
        .success()
        .stdout(predicate::str::contains("\"version\": \"6.4.0\""));
}

#[tokio::test(flavor = "multi_thread")]
async fn send_and_wait_success_exits_zero() {
    let server = MockServer::start().await;
    mount_signon_and_signout(&server).await;
    authed("POST", "processcontrolcriterias", JWT)
        .and(body_partial_json(json!({ "secondaryNode": "" })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([{ "processNumber": 126 }])))
        .expect(1)
        .mount(&server)
        .await;
    authed("GET", "selectstatistics", JWT)
        .and(query_param("processNumber", "126"))
        .respond_with(ResponseTemplate::new(200).set_body_json(stats_with_end(126, "0")))
        .expect(1)
        .mount(&server)
        .await;

    let mut cmd = cdctl_for(&server);
    cmd.args([
        "send",
        "--snode",
        "PARTNER01",
        "--from",
        "/out/a",
        "--to",
        "/in/a",
        "--wait",
    ]);
    run(cmd)
        .await
        .success()
        .stdout(predicate::str::contains("\"processNumber\": 126"))
        .stderr(predicate::str::contains("Completion code: 0"));
}

#[tokio::test(flavor = "multi_thread")]
async fn nonzero_completion_code_exits_two() {
    let server = MockServer::start().await;
    mount_signon_and_signout(&server).await;
    authed("POST", "processcontrolcriterias", JWT)
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "processNumber": "55" })))
        .mount(&server)
        .await;
    authed("GET", "selectstatistics", JWT)
        .respond_with(ResponseTemplate::new(200).set_body_json(stats_with_end(55, "8")))
        .mount(&server)
        .await;

    let mut cmd = cdctl_for(&server);
    cmd.args([
        "receive",
        "--snode",
        "PARTNER01",
        "--from",
        "/r",
        "--to",
        "/l",
        "--wait",
    ]);
    run(cmd)
        .await
        .code(2)
        .stderr(predicate::str::contains("Completion code: 8"));
}

#[tokio::test(flavor = "multi_thread")]
async fn submit_file_sends_its_content() {
    let server = MockServer::start().await;
    mount_signon_and_signout(&server).await;

    let content = "MYPROC PROCESS\n    SNODE=X\nPEND\n";
    let file = std::env::temp_dir().join(format!("cdctl-test-{}.cdp", std::process::id()));
    std::fs::write(&file, content).unwrap();

    authed("POST", "processcontrolcriterias", JWT)
        .and(body_partial_json(
            json!({ "processFile": content, "secondaryNode": "OTHER" }),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([{ "processNumber": 1 }])))
        .expect(1)
        .mount(&server)
        .await;

    let mut cmd = cdctl_for(&server);
    cmd.arg("submit")
        .arg("--file")
        .arg(&file)
        .args(["--snode", "OTHER"]);
    let assert = run(cmd).await;
    let _ = std::fs::remove_file(&file);
    assert.success();
}

#[tokio::test(flavor = "multi_thread")]
async fn submit_server_file_sends_path() {
    let server = MockServer::start().await;
    mount_signon_and_signout(&server).await;
    authed("POST", "processcontrolcriterias", JWT)
        .and(body_partial_json(
            json!({ "processFile": "/opt/cd/process/send.cdp" }),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([{ "processNumber": 2 }])))
        .expect(1)
        .mount(&server)
        .await;

    let mut cmd = cdctl_for(&server);
    cmd.args(["submit", "--server-file", "/opt/cd/process/send.cdp"]);
    run(cmd).await.success();
}

#[tokio::test(flavor = "multi_thread")]
async fn stats_processes_and_delete() {
    let server = MockServer::start().await;
    signon_mock(JWT, CSRF).mount(&server).await;
    authed("DELETE", "signout", JWT)
        .respond_with(ResponseTemplate::new(200))
        .expect(3)
        .mount(&server)
        .await;
    authed("GET", "selectstatistics", JWT)
        .and(query_param("processNumber", "126"))
        .respond_with(ResponseTemplate::new(200).set_body_json(stats_with_end(126, "0")))
        .expect(1)
        .mount(&server)
        .await;
    authed("GET", "processcontrolcriterias", JWT)
        .and(query_param("processName", "PAYOUT"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .expect(1)
        .mount(&server)
        .await;
    authed("DELETE", "processcontrolcriterias", JWT)
        .and(body_partial_json(
            json!({ "processNumber": "126", "force": "yes" }),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([{ "messageCode": 200 }])))
        .expect(1)
        .mount(&server)
        .await;

    let mut cmd = cdctl_for(&server);
    cmd.args(["stats", "--process-number", "126"]);
    run(cmd)
        .await
        .success()
        .stdout(predicate::str::contains("PRED"));

    let mut cmd = cdctl_for(&server);
    cmd.args(["processes", "--process-name", "PAYOUT"]);
    run(cmd).await.success();

    let mut cmd = cdctl_for(&server);
    cmd.args(["delete", "--process-number", "126", "--force"]);
    run(cmd).await.success();
}

#[tokio::test(flavor = "multi_thread")]
async fn raw_call_passes_method_query_and_body() {
    let server = MockServer::start().await;
    mount_signon_and_signout(&server).await;
    authed("POST", "netmapnodes", JWT)
        .and(query_param("name", "PARTNER01"))
        .and(body_partial_json(json!({ "maxPnode": 5 })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "created": true })))
        .expect(1)
        .mount(&server)
        .await;

    let mut cmd = cdctl_for(&server);
    cmd.args([
        "raw",
        "post",
        "netmapnodes",
        "-q",
        "name=PARTNER01",
        "--json",
        r#"{"maxPnode":5}"#,
    ]);
    run(cmd)
        .await
        .success()
        .stdout(predicate::str::contains("\"created\": true"));
}

#[tokio::test(flavor = "multi_thread")]
async fn api_error_exits_one() {
    let server = MockServer::start().await;
    signon_mock(JWT, CSRF).mount(&server).await;
    authed("GET", "version", JWT)
        .respond_with(ResponseTemplate::new(500).set_body_string("internal"))
        .mount(&server)
        .await;

    let mut cmd = cdctl_for(&server);
    cmd.arg("version");
    run(cmd)
        .await
        .code(1)
        .stderr(predicate::str::contains("500").and(predicate::str::contains("internal")));
}
