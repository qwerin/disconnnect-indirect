//! Testy CLI `cdctl` – spouští skutečnou binárku proti mock CDWS serveru.

mod common;

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use assert_cmd::Command;
use common::*;
use predicates::prelude::*;
use serde_json::json;
use wiremock::matchers::{body_partial_json, query_param};
use wiremock::{MockServer, ResponseTemplate};

const ENV_VARS: [&str; 14] = [
    "CDWS_URL",
    "CD_NODE_HOST",
    "CD_NODE_PORT",
    "CD_PROTOCOL",
    "CD_USER",
    "CD_PASSWORD",
    "CDWS_CA_CERT",
    "CDWS_INSECURE",
    "CDWS_TIMEOUT",
    "CDCTL_CONFIG",
    "CDCTL_LOG_DIR",
    "CDCTL_LOG_LEVEL",
    "CDCTL_LOG_FORMAT",
    "CDCTL_LOG_STDERR",
];

/// Sdílený adresář pro testy, které logy nezkoumají (uvnitř target/tmp).
fn shared_tmp() -> &'static Path {
    static DIR: OnceLock<PathBuf> = OnceLock::new();
    DIR.get_or_init(|| {
        let d = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("cli-shared");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("empty.toml"), "").unwrap();
        d
    })
}

/// `cdctl` s vyčištěným prostředím: prázdná konfigurace, logy do target/tmp
/// (testy nikdy nesahají na /etc/cdctl ani /var/log).
fn cdctl() -> Command {
    let mut cmd = Command::cargo_bin("cdctl").unwrap();
    for v in ENV_VARS {
        cmd.env_remove(v);
    }
    cmd.env("CDCTL_CONFIG", shared_tmp().join("empty.toml"))
        .env("CDCTL_LOG_DIR", shared_tmp().join("logs"));
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

/// `cdctl` řízený jen konfiguračním souborem (žádné env pro připojení ani log).
fn cdctl_with_config(config: &Path) -> Command {
    let mut cmd = cdctl();
    cmd.env("CDCTL_CONFIG", config).env_remove("CDCTL_LOG_DIR");
    cmd
}

/// Zapíše konfigurační soubor do `dir` a vrátí jeho cestu.
fn write_config(dir: &Path, body: &str) -> PathBuf {
    let p = dir.join("config.toml");
    std::fs::write(&p, body).unwrap();
    p
}

/// Konfigurace připojení na mock server + log do `<dir>/logs`.
fn config_for(server: &MockServer, dir: &Path, log_extra: &str) -> PathBuf {
    let logs = dir.join("logs");
    write_config(
        dir,
        &format!(
            "[connection]\nurl = \"{}\"\nnode_host = \"{NODE}\"\nuser = \"{USER}\"\npassword = \"{PASSWORD}\"\n\n[log]\ndir = '{}'\nrotation = \"never\"\n{log_extra}\n",
            server.uri(),
            logs.display()
        ),
    )
}

fn with_args<const N: usize>(mut cmd: Command, args: [&str; N]) -> Command {
    cmd.args(args);
    cmd
}

/// Obsah všech souborů v adresáři logů.
fn read_logs(dir: &Path) -> String {
    let mut out = String::new();
    for e in std::fs::read_dir(dir).unwrap() {
        out.push_str(&std::fs::read_to_string(e.unwrap().path()).unwrap());
    }
    out
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

// ------------------------------------------------------------------ config + logging

#[tokio::test(flavor = "multi_thread")]
async fn config_file_drives_connection_and_logging_without_leaking_secrets() {
    let server = MockServer::start().await;
    mount_signon_and_signout(&server).await;
    authed("GET", "version", JWT)
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "version": "6.4.0" })))
        .expect(1)
        .mount(&server)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    // trace = nejpodrobnější úroveň, i tak nesmí v logu být heslo ani tokeny
    let cfg = config_for(&server, tmp.path(), "level = \"trace\"");
    run(with_args(cdctl_with_config(&cfg), ["version"]))
        .await
        .success();

    let log = read_logs(&tmp.path().join("logs"));
    for needle in [
        "cdctl started",
        "version",
        "signing on to Connect:Direct",
        "signed on",
        "signed out",
        "cdctl finished",
        "exit_code=0",
        "run=",
    ] {
        assert!(log.contains(needle), "log is missing `{needle}`:\n{log}");
    }
    for secret in [
        PASSWORD,
        JWT,
        CSRF,
        basic_auth().trim_start_matches("Basic "),
    ] {
        assert!(!log.contains(secret), "log leaks `{secret}`:\n{log}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn transfer_is_logged_as_audit_trail() {
    let server = MockServer::start().await;
    mount_signon_and_signout(&server).await;
    authed("POST", "processcontrolcriterias", JWT)
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([{ "processNumber": 126 }])))
        .mount(&server)
        .await;
    authed("GET", "selectstatistics", JWT)
        .respond_with(ResponseTemplate::new(200).set_body_json(stats_with_end(126, "0")))
        .mount(&server)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    let cfg = config_for(&server, tmp.path(), "");
    run(with_args(
        cdctl_with_config(&cfg),
        [
            "send",
            "--snode",
            "PARTNER01",
            "--from",
            "/out/pay.csv",
            "--to",
            "/in/pay.csv",
            "--name",
            "PAYOUT",
            "--wait",
        ],
    ))
    .await
    .success();

    let log = read_logs(&tmp.path().join("logs"));
    for needle in [
        "file transfer requested",
        "PARTNER01",
        "/out/pay.csv",
        "/in/pay.csv",
        "submitting process",
        "PAYOUT PROCESS",
        "process submitted",
        "process_number=126",
        "waiting for process to finish",
        "process finished OK",
    ] {
        assert!(log.contains(needle), "log is missing `{needle}`:\n{log}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn failures_are_logged() {
    let server = MockServer::start().await;
    signon_mock(JWT, CSRF).mount(&server).await;
    authed("GET", "version", JWT)
        .respond_with(ResponseTemplate::new(500).set_body_string("internal"))
        .mount(&server)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    let cfg = config_for(&server, tmp.path(), "");
    run(with_args(cdctl_with_config(&cfg), ["version"]))
        .await
        .code(1);

    let log = read_logs(&tmp.path().join("logs"));
    assert!(
        log.contains("WARN") && log.contains("CDWS returned an error"),
        "{log}"
    );
    assert!(log.contains("status=500"), "{log}");
    assert!(
        log.contains("ERROR") && log.contains("cdctl failed"),
        "{log}"
    );
    assert!(log.contains("exit_code=1"), "{log}");
}

#[tokio::test(flavor = "multi_thread")]
async fn json_log_format_produces_json_lines() {
    let server = MockServer::start().await;
    mount_signon_and_signout(&server).await;
    authed("GET", "version", JWT)
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&server)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    let cfg = config_for(&server, tmp.path(), "format = \"json\"");
    run(with_args(cdctl_with_config(&cfg), ["version"]))
        .await
        .success();

    let log = read_logs(&tmp.path().join("logs"));
    let lines: Vec<serde_json::Value> = log
        .lines()
        .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("not JSON ({e}): {l}")))
        .collect();
    assert!(lines.len() >= 4);
    for l in &lines {
        assert!(l["timestamp"].is_string() && l["level"].is_string(), "{l}");
        assert!(l["span"]["run"].is_string(), "missing run id: {l}");
    }
    assert!(lines
        .iter()
        .any(|l| l["fields"]["message"] == "cdctl started"));
}

#[tokio::test(flavor = "multi_thread")]
async fn log_level_filters_messages() {
    let server = MockServer::start().await;
    mount_signon_and_signout(&server).await;
    authed("GET", "version", JWT)
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&server)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    let cfg = config_for(&server, tmp.path(), "level = \"warn\"");
    run(with_args(cdctl_with_config(&cfg), ["version"]))
        .await
        .success();
    let log = read_logs(&tmp.path().join("logs"));
    assert!(!log.contains("cdctl started"), "{log}");
    assert!(!log.contains("INFO"), "{log}");
}

#[tokio::test(flavor = "multi_thread")]
async fn flags_and_env_override_config_file() {
    let server = MockServer::start().await;
    mount_signon_and_signout(&server).await;
    authed("GET", "version", JWT)
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&server)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    let cfg = write_config(
        tmp.path(),
        &format!(
            "[connection]\nurl = \"http://127.0.0.1:9\"\nnode_host = \"{NODE}\"\nuser = \"{USER}\"\n[log]\ndir = '{}'\nlevel = \"error\"\n",
            tmp.path().join("cfg-logs").display()
        ),
    );
    let flag_logs = tmp.path().join("flag-logs");
    let mut cmd = cdctl_with_config(&cfg);
    cmd.env("CDWS_URL", server.uri()) // env > soubor
        .env("CD_PASSWORD", PASSWORD)
        .arg("--log-dir")
        .arg(&flag_logs) // přepínač > soubor
        .args(["--log-level", "info", "version"]);
    run(cmd).await.success();

    assert!(!tmp.path().join("cfg-logs").exists());
    assert!(read_logs(&flag_logs).contains("cdctl started"));
}

#[test]
fn password_on_command_line_is_masked_in_log() {
    let tmp = tempfile::tempdir().unwrap();
    let logs = tmp.path().join("logs");
    cdctl()
        .arg("--log-dir")
        .arg(&logs)
        .args([
            "--password",
            "topsecret",
            "send",
            "--snode",
            "N",
            "--from",
            "/a",
            "--to",
            "/b",
            "--dry-run",
        ])
        .assert()
        .success();
    let log = read_logs(&logs);
    assert!(log.contains("--password ***"), "{log}");
    assert!(!log.contains("topsecret"), "{log}");
}

#[test]
fn log_stderr_flag_mirrors_log_to_stderr() {
    cdctl()
        .args([
            "--log-stderr",
            "send",
            "--snode",
            "N",
            "--from",
            "/a",
            "--to",
            "/b",
            "--dry-run",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("cdctl started").and(predicate::str::contains("dry run")));
}

#[test]
fn unwritable_explicit_log_dir_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let file = tmp.path().join("not-a-dir");
    std::fs::write(&file, "x").unwrap();
    cdctl()
        .arg("--log-dir")
        .arg(file.join("logs"))
        .args([
            "send",
            "--snode",
            "N",
            "--from",
            "/a",
            "--to",
            "/b",
            "--dry-run",
        ])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("cannot write log"));
}

#[test]
fn missing_explicit_config_fails() {
    cdctl()
        .env("CDCTL_CONFIG", "/definitely/missing/cdctl.toml")
        .arg("config")
        .assert()
        .code(1)
        .stderr(predicate::str::contains("does not exist"));
}

#[test]
fn invalid_config_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = write_config(tmp.path(), "[log]\nlevle = \"debug\"\n");
    cdctl_with_config(&cfg)
        .arg("config")
        .assert()
        .code(1)
        .stderr(
            predicate::str::contains("invalid config file").and(predicate::str::contains("levle")),
        );
}

#[test]
fn invalid_log_level_fails() {
    cdctl()
        .args(["--log-level", "connect_direct=nonsense", "config"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("invalid log level"));
}

#[test]
fn config_command_shows_effective_settings_with_masked_password() {
    let tmp = tempfile::tempdir().unwrap();
    let logs = tmp.path().join("logs");
    let cfg = write_config(
        tmp.path(),
        &format!(
            "[connection]\nurl = \"https://cdws:9443\"\nnode_host = \"n1\"\nnode_port = 2363\nuser = \"u\"\npassword = \"hunter2\"\n[log]\ndir = '{}'\nlevel = \"debug\"\nrotation = \"hourly\"\nmax_files = 48\n",
            logs.display()
        ),
    );
    cdctl_with_config(&cfg)
        .arg("config")
        .assert()
        .success()
        .stdout(
            predicate::str::contains("https://cdws:9443")
                .and(predicate::str::contains("n1:2363"))
                .and(predicate::str::contains("*** (set)"))
                .and(predicate::str::contains("hunter2").not())
                .and(predicate::str::contains(logs.display().to_string()))
                .and(predicate::str::contains("hourly (keep 48 files)"))
                .and(predicate::str::contains("debug")),
        );
}

#[cfg(unix)]
#[test]
fn world_readable_config_with_password_warns() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().unwrap();
    let cfg = write_config(
        tmp.path(),
        &format!(
            "[connection]\npassword = \"x\"\n[log]\ndir = '{}'\n",
            tmp.path().join("logs").display()
        ),
    );
    std::fs::set_permissions(&cfg, std::fs::Permissions::from_mode(0o644)).unwrap();
    cdctl_with_config(&cfg)
        .arg("config")
        .assert()
        .success()
        .stderr(predicate::str::contains("chmod 600"));
    assert!(read_logs(&tmp.path().join("logs")).contains("chmod 600"));
}

#[test]
fn connection_error_reports_root_cause() {
    // port, na kterém nic neposlouchá
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let tmp = tempfile::tempdir().unwrap();
    let logs = tmp.path().join("logs");
    cdctl()
        .env("CDWS_URL", format!("http://127.0.0.1:{port}"))
        .env("CD_NODE_HOST", NODE)
        .env("CD_USER", USER)
        .arg("--log-dir")
        .arg(&logs)
        .arg("version")
        .assert()
        .code(1)
        .stderr(
            predicate::str::contains("error sending request")
                .and(predicate::str::contains("connect")),
        );
    let log = read_logs(&logs);
    assert!(
        log.contains("sign-on request failed") && log.contains("connect"),
        "{log}"
    );
}
