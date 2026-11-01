//! Drives the `lodeline-sign` binary directly: keygen → sign → verify roundtrip
//! ends with verify exiting 0 and inspect printing the right metadata.

use std::process::Command;
use tempfile::tempdir;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_lodeline-sign")
}

fn sign_cli(yaml: &str) -> (std::process::Output, bool) {
    let dir = tempdir().unwrap();
    let key_path = dir.path().join("k.json");
    let yaml_path = dir.path().join("p.yaml");
    let signed_path = dir.path().join("signed.json");
    std::fs::write(&yaml_path, yaml).unwrap();
    let keygen = Command::new(bin())
        .args(["keygen", "--id", "k1", "--out"])
        .arg(&key_path)
        .output()
        .unwrap();
    assert!(keygen.status.success());
    let out = Command::new(bin())
        .args(["sign", "--in"])
        .arg(&yaml_path)
        .arg("--key")
        .arg(&key_path)
        .args(["--policy-version", "2"])
        .args(["--valid-until", "2027-06-15T00:00:00Z"])
        .arg("--out")
        .arg(&signed_path)
        .output()
        .unwrap();
    let wrote_file = signed_path.exists();
    (out, wrote_file)
}

#[track_caller]
fn assert_sign_refuses(yaml: &str, expected_reason: &str) {
    let (out, wrote_file) = sign_cli(yaml);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "sign accepted {yaml:?}");
    assert!(!wrote_file, "sign wrote a bundle for {yaml:?}");
    assert!(stderr.contains(expected_reason), "stderr: {stderr}");
}

#[test]
fn sign_refuses_a_document_the_agent_cannot_load() {
    assert_sign_refuses("version: 2\n", "unsupported policy version 2");
    assert_sign_refuses("not: a policy\n", "version");
    assert_sign_refuses(
        "version: 1\nhook_deny_rules:\n  - id: bad\n    match:\n      kind: bash\n      command:\n        kind: regex\n        pattern: '('\n",
        "bad",
    );
    assert_sign_refuses(
        "version: 1\nrule_packs:\n  - id: bad-pack\n    pack_version: 1\n    tool: gemini\n    scope: {kind: user_global}\n    watched_paths: []\n    rules:\n      - id: r\n        on_file: x\n        format: json\n        selector: $.x\n        matcher: {kind: regex, pattern: '('}\n        emit: {kind: sandbox_disabled}\n",
        "bad-pack",
    );
    assert_sign_refuses(
        "version: 1\ntargets:\n  - id: bad-target\n    description: d\n    tier: standard\n    platform: any\n    paths: ['/tmp/[']\n",
        "bad-target",
    );
}

#[test]
fn sign_leaves_a_merge_to_the_host_because_a_bundle_never_merges_overrides() {
    let (out, wrote_file) =
        sign_cli("version: 1\noverrides:\n  - id: no-such-target\n    disabled: true\n");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(wrote_file);
}

#[test]
fn sign_accepts_a_target_written_for_another_os() {
    let (out, wrote_file) = sign_cli(
        "version: 1\ntargets:\n  - id: tools\n    description: d\n    tier: standard\n    platform: windows\n    recursive: true\n    paths: ['C:\\tools\\']\n",
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(wrote_file);
}

#[test]
fn keygen_sign_verify_inspect_roundtrip_via_cli() {
    let dir = tempdir().unwrap();
    let key_path = dir.path().join("k.json");
    let yaml_path = dir.path().join("p.yaml");
    let signed_path = dir.path().join("signed.json");
    let keystore_path = dir.path().join("policy-signing-pubkeys.pem");

    std::fs::write(&yaml_path, "version: 1\nfoo: bar\n").unwrap();

    // 1. keygen
    let out = Command::new(bin())
        .args(["keygen", "--id", "k1", "--out"])
        .arg(&key_path)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "keygen failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Build a keystore that includes the freshly-generated pubkey.
    let key_bytes = std::fs::read(&key_path).unwrap();
    let key_json: serde_json::Value = serde_json::from_slice(&key_bytes).unwrap();
    let pubkey_b64 = key_json["ed25519_pubkey_b64"].as_str().unwrap();
    let store = serde_json::json!({
        "pubkeys": [{
            "id": "k1",
            "ed25519_pubkey_b64": pubkey_b64,
            "valid_from": "2026-01-01T00:00:00Z",
            "valid_until": "2027-12-31T00:00:00Z"
        }]
    });
    std::fs::write(&keystore_path, serde_json::to_vec(&store).unwrap()).unwrap();

    // 2. sign
    let out = Command::new(bin())
        .args(["sign", "--in"])
        .arg(&yaml_path)
        .arg("--key")
        .arg(&key_path)
        .args(["--policy-version", "7"])
        .args(["--valid-until", "2027-06-15T00:00:00Z"])
        .arg("--out")
        .arg(&signed_path)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "sign failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // 3. verify (now within keystore validity window AND envelope validity)
    let out = Command::new(bin())
        .args(["verify", "--in"])
        .arg(&signed_path)
        .arg("--keystore")
        .arg(&keystore_path)
        .args(["--now", "2026-06-15T00:00:00Z"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "verify failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    // 4. inspect
    let out = Command::new(bin())
        .args(["inspect", "--in"])
        .arg(&signed_path)
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("signing_pubkey_id : k1"));
    assert!(stdout.contains("policy_version    : 7"));
    assert!(stdout.contains("valid_until       : 2027-06-15"));
}

#[test]
fn verify_fails_when_keystore_missing_pubkey() {
    let dir = tempdir().unwrap();
    let key_path = dir.path().join("k.json");
    let yaml_path = dir.path().join("p.yaml");
    let signed_path = dir.path().join("signed.json");
    let keystore_path = dir.path().join("policy-signing-pubkeys.pem");

    std::fs::write(&yaml_path, "version: 1\n").unwrap();

    Command::new(bin())
        .args(["keygen", "--id", "k1", "--out"])
        .arg(&key_path)
        .output()
        .unwrap();

    Command::new(bin())
        .args(["sign", "--in"])
        .arg(&yaml_path)
        .arg("--key")
        .arg(&key_path)
        .args(["--policy-version", "1"])
        .args(["--valid-until", "2027-06-15T00:00:00Z"])
        .arg("--out")
        .arg(&signed_path)
        .output()
        .unwrap();

    // Empty keystore.
    std::fs::write(&keystore_path, br#"{"pubkeys":[]}"#).unwrap();

    let out = Command::new(bin())
        .args(["verify", "--in"])
        .arg(&signed_path)
        .arg("--keystore")
        .arg(&keystore_path)
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "verify should fail with empty keystore"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("FAIL") || stderr.contains("pubkey unknown"));
}
