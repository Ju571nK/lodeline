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

#[cfg(unix)]
#[test]
fn a_link_in_the_key_path_is_named_and_not_called_an_existing_file() {
    let dir = tempfile::tempdir().unwrap();
    let real = dir.path().join("real");
    fs::create_dir(&real).unwrap();
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let req = dir.path().join("host.csr");
    let out = csr(HOST_ID, &link.join("host.key"), &req);
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("must be a directory, not a link"), "{err}");
    assert!(!err.contains("never overwritten"), "{err}");
    assert!(!err.contains("stays root-owned"), "{err}");
    assert!(!req.exists(), "no CSR is left behind");
}

#[cfg(unix)]
#[test]
fn an_unwritable_key_directory_is_named_and_not_called_an_existing_file() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let closed = dir.path().join("closed");
    fs::create_dir(&closed).unwrap();
    fs::set_permissions(&closed, fs::Permissions::from_mode(0o555)).unwrap();
    // root writes anywhere, so only assert where the directory is really closed
    if fs::File::create(closed.join("probe")).is_ok() {
        return;
    }
    let req = dir.path().join("host.csr");
    let out = csr(HOST_ID, &closed.join("host.key"), &req);
    fs::set_permissions(&closed, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("cannot create") && err.contains("host.key"),
        "{err}"
    );
    assert!(!err.contains("never overwritten"), "{err}");
    assert!(!req.exists());
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

#[cfg(unix)]
mod as_root {
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    fn run_as_root(parent: &Path) -> (std::path::PathBuf, Output) {
        // SAFETY: geteuid has no preconditions.
        assert_eq!(unsafe { libc::geteuid() }, 0, "run this test as root");
        let dir = parent.join("keys");
        fs::create_dir(&dir).unwrap();
        std::os::unix::fs::chown(&dir, Some(65534), Some(65533)).unwrap();
        let key = dir.join("host.key");
        let out = csr(HOST_ID, &key, &parent.join("host.csr"));
        (key, out)
    }

    /// Needs root, and a root-owned closed directory below `/root`. CI runs it in a
    /// root container with `--ignored`.
    #[test]
    #[ignore = "needs root"]
    fn root_gives_the_key_to_a_directory_owner_only_under_a_closed_root_owned_parent() {
        let closed = tempfile::Builder::new().tempdir_in("/root").unwrap();
        let (key, out) = run_as_root(closed.path());
        assert!(out.status.success(), "{out:?}");
        let m = fs::metadata(&key).unwrap();
        assert_eq!((m.uid(), m.gid(), m.mode() & 0o7777), (65534, 65533, 0o600));
        assert!(!String::from_utf8_lossy(&out.stderr).contains("stays root-owned"));

        let open = tempfile::Builder::new().tempdir_in("/root").unwrap();
        fs::set_permissions(open.path(), fs::Permissions::from_mode(0o777)).unwrap();
        let (key, out) = run_as_root(open.path());
        assert!(out.status.success(), "{out:?}");
        assert_eq!(fs::metadata(&key).unwrap().uid(), 0, "stays root-owned");
        assert!(String::from_utf8_lossy(&out.stderr).contains("stays root-owned"));
    }
}
