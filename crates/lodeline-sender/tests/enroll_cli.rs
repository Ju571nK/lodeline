//! `lodeline-sender enroll` through the real binary: exit codes that need no server.

use std::process::{Command, Output};

fn enroll(args: &[&std::ffi::OsStr]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_lodeline-sender"))
        .arg("enroll")
        .args(args)
        .output()
        .unwrap()
}

#[cfg(windows)]
#[test]
fn windows_is_refused_for_now() {
    let out = enroll(&["host.json".as_ref()]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("not supported on Windows yet"));
}

#[cfg(unix)]
mod unix {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn file(dir: &std::path::Path, body: &str) -> std::path::PathBuf {
        let p = dir.join("host.json");
        std::fs::write(&p, body).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        p
    }

    #[test]
    fn a_bad_file_exits_2_and_never_prints_the_token() {
        let d = tempfile::tempdir().unwrap();
        let p = file(d.path(), r#"{"lodeline_enrollment": 1, "token": 12345678}"#);
        let out = enroll(&[p.as_os_str()]);
        assert_eq!(out.status.code(), Some(2), "{out:?}");
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(
            err.contains("host.json") && !err.contains("12345678"),
            "{err}"
        );
        assert!(out.stdout.is_empty());
    }

    #[test]
    fn another_format_version_exits_2_with_the_upgrade_hint() {
        let d = tempfile::tempdir().unwrap();
        let p = file(d.path(), r#"{"lodeline_enrollment": 2}"#);
        let out = enroll(&[p.as_os_str()]);
        assert_eq!(out.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&out.stderr).contains("upgrade lodeline-sender"));
    }

    #[test]
    fn a_missing_file_exits_2() {
        let out = enroll(&["/nonexistent/host.json".as_ref()]);
        assert_eq!(out.status.code(), Some(2));
    }
}
