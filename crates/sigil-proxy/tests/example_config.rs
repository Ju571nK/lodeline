#![cfg(unix)]
//! The packaged example (`config/proxy.example.yaml`) must stay a valid
//! bootstrap: rewrite its placeholder paths to a temp dir with files of the
//! right modes and expect `check-config` to exit 0 (AC-14 packaging support).

use std::os::unix::fs::PermissionsExt;
use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_sigil-proxy");

#[test]
fn example_config_passes_check_config() {
    let example = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../config/proxy.example.yaml"
    ))
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().to_str().unwrap();
    let text = example
        .replace("/etc/sigil/proxy/", &format!("{root}/"))
        .replace("/var/lib/sigil-proxy", &format!("{root}/state"));
    assert!(
        !text.contains("/etc/sigil/proxy/"),
        "unrewritten placeholder path"
    );
    for (name, mode) in [
        ("listener.crt", 0o644),
        ("listener.key", 0o600),
        ("client.crt", 0o644),
        ("client.key", 0o600),
        ("ca.pem", 0o644),
        ("example-upstream.secret", 0o600),
    ] {
        let p = dir.path().join(name);
        std::fs::write(&p, "x").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
    }
    let cfg = dir.path().join("proxy.yaml");
    std::fs::write(&cfg, text).unwrap();
    let out = Command::new(BIN)
        .args(["check-config", "--config"])
        .arg(&cfg)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "check-config failed: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}
