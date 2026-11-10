//! `lodeline-server` logs to stderr, at `info` unless `RUST_LOG` sets another level (#560).

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

const INFO_LINE: &str = "read API enabled";
const LISTENER_LINE: &str = "starting lodeline-server";

fn write_config(dir: &Path, extra: &str) -> PathBuf {
    let events = dir.join("events");
    std::fs::create_dir(&events).unwrap();
    let config = dir.join("server.yaml");
    std::fs::write(
        &config,
        format!(
            "bind: '127.0.0.1:0'\nevents_out_dir: '{}'\npolicy_bundle_path: '{}'\n{extra}",
            events.display(),
            dir.join("policy.json").display()
        ),
    )
    .unwrap();
    config
}

/// Starts `serve` and returns what it logs up to the listener line, which is a
/// `warn` on plain HTTP and comes after the `info` line.
fn log_until_listener(rust_log: Option<&str>) -> String {
    let dir = tempfile::tempdir().unwrap();
    let config = write_config(dir.path(), "");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_lodeline-server"));
    cmd.args(["serve", "--config"])
        .arg(&config)
        .env_remove("RUST_LOG")
        .env("LODELINE_SERVER_READ_TOKEN", "log-level-test")
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    if let Some(level) = rust_log {
        cmd.env("RUST_LOG", level);
    }
    let mut child = cmd.spawn().unwrap();
    let stderr = child.stderr.take().unwrap();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });

    let deadline = Instant::now() + Duration::from_secs(30);
    let mut log = String::new();
    while !log.contains(LISTENER_LINE) {
        let left = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(left) {
            Ok(line) => log += &format!("{line}\n"),
            Err(_) => break,
        }
    }
    child.kill().unwrap();
    child.wait().unwrap();
    assert!(
        log.contains(LISTENER_LINE),
        "RUST_LOG={rust_log:?}: no listener line on stderr:\n{log}"
    );
    log
}

#[test]
fn serve_logs_info_by_default_and_rust_log_overrides_it() {
    let default = log_until_listener(None);
    assert!(
        default.contains(INFO_LINE),
        "no info line without RUST_LOG:\n{default}"
    );

    let warn = log_until_listener(Some("warn"));
    assert!(
        !warn.contains(INFO_LINE),
        "RUST_LOG=warn kept an info line:\n{warn}"
    );
}

#[test]
fn enroll_token_writes_only_the_token_on_stdout() {
    let dir = tempfile::tempdir().unwrap();
    let tokens = dir.path().join("tokens.json");
    let config = write_config(
        dir.path(),
        &format!(
            "enroll_tokens_path: '{}'\nlicense:\n  path: 'unused'\n",
            tokens.display()
        ),
    );
    let out = Command::new(env!("CARGO_BIN_EXE_lodeline-server"))
        .args(["enroll-token", "--config"])
        .arg(&config)
        .args([
            "--host-id",
            "6f1d2c3b-4a5e-4f60-8a7b-9c0d1e2f3a4b",
            "--ttl",
            "1h",
        ])
        .env_remove("RUST_LOG")
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(stdout.lines().count(), 1, "stdout:\n{stdout}");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("`license.path` is no longer used"),
        "{out:?}"
    );
}
