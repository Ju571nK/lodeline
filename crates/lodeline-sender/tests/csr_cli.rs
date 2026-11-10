//! `lodeline-sender csr` writes a new key and CSR and never replaces an existing file.

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

const HOST_ID: &str = "3f2c6a1e-8b4d-4c2a-9e7f-1a2b3c4d5e6f";

fn csr(host_id: &str, key: &Path, csr: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_lodeline-sender"))
        .args(["csr", "--host-id", host_id, "--key-out"])
        .arg(key)
        .arg("--csr-out")
        .arg(csr)
        .output()
        .unwrap()
}

#[test]
fn writes_a_private_key_and_a_csr() {
    let dir = tempfile::tempdir().unwrap();
    let (key, req) = (dir.path().join("host.key"), dir.path().join("host.csr"));
    let out = csr(HOST_ID, &key, &req);
    assert!(out.status.success(), "{out:?}");

    let key_pem = fs::read_to_string(&key).unwrap();
    assert!(key_pem.starts_with("-----BEGIN PRIVATE KEY-----"));
    assert!(fs::read_to_string(&req)
        .unwrap()
        .starts_with("-----BEGIN CERTIFICATE REQUEST-----"));
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains(&format!("CN={HOST_ID}")), "{stdout}");
    assert!(
        !stdout.contains("PRIVATE KEY"),
        "key material never printed"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&key).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "key mode {mode:o}");
    }
}

#[test]
fn refuses_to_overwrite_an_existing_key_or_csr() {
    let dir = tempfile::tempdir().unwrap();
    let (key, req) = (dir.path().join("host.key"), dir.path().join("host.csr"));
    assert!(csr(HOST_ID, &key, &req).status.success());
    let (key_before, req_before) = (fs::read(&key).unwrap(), fs::read(&req).unwrap());

    let out = csr(HOST_ID, &key, &dir.path().join("other.csr"));
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("never overwritten"));
    assert_eq!(fs::read(&key).unwrap(), key_before);
    assert!(!dir.path().join("other.csr").exists());

    let other_key = dir.path().join("other.key");
    let out = csr(HOST_ID, &other_key, &req);
    assert!(!out.status.success());
    assert_eq!(fs::read(&req).unwrap(), req_before);
    assert!(
        !other_key.exists(),
        "no key is left behind when the CSR path is taken"
    );
}

#[test]
fn rejects_a_host_id_that_is_not_a_uuid() {
    let dir = tempfile::tempdir().unwrap();
    let (key, req) = (dir.path().join("host.key"), dir.path().join("host.csr"));
    let out = csr("hostA", &key, &req);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("must be a UUID"));
    assert!(!key.exists() && !req.exists());
}
