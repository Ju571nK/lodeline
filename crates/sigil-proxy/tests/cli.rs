#![cfg(unix)]
//! Binary-level tests: AC-14 (no start without --config), AC-12 (signals,
//! second instance), D-02 item 4 (token CLI).

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_sigil-proxy");

fn write(dir: &Path, name: &str, mode: u32) {
    let p = dir.join(name);
    std::fs::write(&p, "x").unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
}

fn fixture() -> (tempfile::TempDir, std::path::PathBuf) {
    let t = tempfile::tempdir().unwrap();
    for f in ["cert.pem", "key.pem"] {
        write(t.path(), f, 0o600);
    }
    write(t.path(), "ca.pem", 0o644);
    let cfg = t.path().join("proxy.yaml");
    std::fs::write(
        &cfg,
        "proxy_id: px-1\ncontrol_plane_url: https://server.example:8443\nstate_dir: state\n\
         client_cert_file: cert.pem\nclient_key_file: key.pem\nca_file: ca.pem\n\
         limits:\n  shutdown_grace_secs: 2\n",
    )
    .unwrap();
    (t, cfg)
}

fn status_json(dir: &Path) -> Option<serde_json::Value> {
    serde_json::from_slice(&std::fs::read(dir.join("state/status.json")).ok()?).ok()
}

fn wait_for(mut f: impl FnMut() -> bool) -> bool {
    let end = Instant::now() + Duration::from_secs(10);
    while Instant::now() < end {
        if f() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

#[test]
fn run_without_config_fails_and_binds_nothing() {
    let out = Command::new(BIN).arg("run").output().unwrap();
    assert!(!out.status.success());
    assert!(out.status.code() != Some(0));
}

#[test]
fn check_config_exit_codes() {
    let (t, cfg) = fixture();
    let ok = Command::new(BIN)
        .args(["check-config", "--config"])
        .arg(&cfg)
        .output()
        .unwrap();
    assert_eq!(ok.status.code(), Some(0));
    std::fs::set_permissions(
        t.path().join("key.pem"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    let bad = Command::new(BIN)
        .args(["check-config", "--config"])
        .arg(&cfg)
        .output()
        .unwrap();
    assert_eq!(bad.status.code(), Some(2));
    let missing = Command::new(BIN)
        .args(["check-config", "--config", "/nonexistent/proxy.yaml"])
        .output()
        .unwrap();
    assert_eq!(missing.status.code(), Some(2));
}

#[test]
fn version_prints() {
    let out = Command::new(BIN).arg("version").output().unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).starts_with("sigil-proxy "));
}

#[test]
fn token_new_prints_token_once_and_verifier() {
    let (_t, cfg) = fixture();
    let out = Command::new(BIN)
        .args(["token", "new", "--principal", "alice", "--config"])
        .arg(&cfg)
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    let token = stdout
        .lines()
        .find_map(|l| l.strip_prefix("token: "))
        .unwrap();
    let ver = stdout
        .lines()
        .find_map(|l| l.strip_prefix("verifier_sha256: "))
        .unwrap();
    assert_eq!(token.len(), 64);
    assert_eq!(ver.len(), 64);
    assert_eq!(
        stdout.matches(token).count(),
        1,
        "token printed exactly once"
    );
    assert!(!String::from_utf8_lossy(&out.stderr).contains(token));
    assert_eq!(ver, sigil_proxy::token::verifier(token));

    let bad = Command::new(BIN)
        .args(["token", "new", "--principal", "bad name", "--config"])
        .arg(&cfg)
        .output()
        .unwrap();
    assert!(!bad.status.success());
}

/// AC-12/AC-14: run holds the lock, a second instance fails, SIGTERM stops
/// cleanly with status `stopped`; health reads the file and opens nothing.
#[test]
fn run_lock_signal_and_health() {
    let (t, cfg) = fixture();
    let mut child = Command::new(BIN)
        .args(["run", "--config"])
        .arg(&cfg)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    assert!(
        wait_for(|| status_json(t.path()).is_some_and(|s| s["run_state"] == "running")),
        "status never became running"
    );
    let s = status_json(t.path()).unwrap();
    assert_eq!(s["forwarding"], false);
    assert_eq!(s["config_state"], "none");
    let epoch = s["epoch_id"].as_str().unwrap().to_string();

    let second = Command::new(BIN)
        .args(["run", "--config"])
        .arg(&cfg)
        .output()
        .unwrap();
    assert!(!second.status.success(), "second instance must fail");

    let health = Command::new(BIN)
        .args(["health", "--config"])
        .arg(&cfg)
        .output()
        .unwrap();
    assert_eq!(health.status.code(), Some(0));
    let h = String::from_utf8_lossy(&health.stdout);
    assert!(
        h.contains("alive: true") && h.contains("forwarding: false"),
        "{h}"
    );

    // SAFETY: signalling our own child.
    unsafe { libc::kill(child.id() as i32, libc::SIGTERM) };
    let status = child.wait().unwrap();
    assert!(status.success(), "{status:?}");
    let s = status_json(t.path()).unwrap();
    assert_eq!(s["run_state"], "stopped");

    // restart keeps the epoch and comes back not forwarding
    let mut again = Command::new(BIN)
        .args(["run", "--config"])
        .arg(&cfg)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    assert!(wait_for(
        || status_json(t.path()).is_some_and(|s| s["run_state"] == "running")
    ));
    let s = status_json(t.path()).unwrap();
    assert_eq!(s["epoch_id"], epoch.as_str());
    assert_eq!(s["forwarding"], false);
    // SAFETY: signalling our own child.
    unsafe { libc::kill(again.id() as i32, libc::SIGINT) };
    assert!(again.wait().unwrap().success());

    let after = Command::new(BIN)
        .args(["health", "--config"])
        .arg(&cfg)
        .output()
        .unwrap();
    assert_eq!(after.status.code(), Some(1), "stopped proxy is not alive");
}
