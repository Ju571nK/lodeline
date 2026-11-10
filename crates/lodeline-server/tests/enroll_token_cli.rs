//! `lodeline-server enroll-token`: which host_ids and which accounts it accepts.
#![cfg(unix)]

use std::path::Path;
use std::process::{Command, Output};

fn config(dir: &Path) -> std::path::PathBuf {
    let p = dir.join("server.yaml");
    std::fs::write(
        &p,
        format!(
            "bind: \"127.0.0.1:8443\"\nevents_out_dir: \"{d}/events\"\npolicy_bundle_path: \"{d}/p.json\"\nenroll_tokens_path: \"{d}/tokens.json\"\n",
            d = dir.display()
        ),
    )
    .unwrap();
    p
}

fn enroll_token(cfg: &Path, host_id: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_lodeline-server"))
        .args(["enroll-token", "--config"])
        .arg(cfg)
        .args(["--host-id", host_id, "--ttl", "1h"])
        .output()
        .unwrap()
}

#[test]
fn only_a_canonical_v4_host_id_gets_a_token() {
    let d = tempfile::tempdir().unwrap();
    let cfg = config(d.path());
    for bad in [
        "3F2C6A1E-8B4D-4C2A-9E7F-1A2B3C4D5E6F",
        "{3f2c6a1e-8b4d-4c2a-9e7f-1a2b3c4d5e6f}",
        "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
        "host-a",
    ] {
        let o = enroll_token(&cfg, bad);
        assert!(!o.status.success(), "{bad}");
        assert!(
            String::from_utf8_lossy(&o.stderr).contains("version 4"),
            "{bad}"
        );
    }
    assert!(
        !d.path().join("tokens.json").exists(),
        "nothing is written for a refused id"
    );
    let ok = enroll_token(&cfg, "3f2c6a1e-8b4d-4c2a-9e7f-1a2b3c4d5e6f");
    assert!(ok.status.success(), "{ok:?}");
}

/// Needs root. Run by CI under `sudo` with `--ignored`.
#[test]
#[ignore = "needs root"]
fn as_root_a_directory_owned_by_another_account_is_refused_and_nothing_is_written() {
    let d = tempfile::tempdir().unwrap();
    std::fs::set_permissions(
        d.path(),
        std::os::unix::fs::PermissionsExt::from_mode(0o755),
    )
    .unwrap();
    let state = d.path().join("state");
    std::fs::create_dir(&state).unwrap();
    std::os::unix::fs::chown(&state, Some(65534), Some(65534)).unwrap();
    let cfg = d.path().join("server.yaml");
    std::fs::write(
        &cfg,
        format!(
            "bind: \"127.0.0.1:8443\"\nevents_out_dir: \"{d}/events\"\npolicy_bundle_path: \"{d}/p.json\"\nenroll_tokens_path: \"{s}/tokens.json\"\n",
            d = d.path().display(),
            s = state.display()
        ),
    )
    .unwrap();
    let o = enroll_token(&cfg, "3f2c6a1e-8b4d-4c2a-9e7f-1a2b3c4d5e6f");
    assert!(!o.status.success());
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(
        err.contains("uid 65534") && err.contains("sudo -u"),
        "{err}"
    );
    assert_eq!(
        std::fs::read_dir(&state).unwrap().count(),
        0,
        "nothing was written"
    );
}
