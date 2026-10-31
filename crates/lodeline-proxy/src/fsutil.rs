//! Race-free opening of sensitive and public files.
//!
//! Both helpers open with `O_NOFOLLOW` first and then inspect the opened
//! descriptor (`fstat`), so a path swapped for a symlink or another file between
//! check and use cannot be followed.
//!
//! Only the final path component is protected against symlinks. Parent
//! directories are NOT walked: protecting them is the installer's job
//! (state and config directories are created 0700 by the service unit).

use std::fs::File;
use std::io;
use std::path::Path;

fn open_nofollow(path: &Path) -> io::Result<File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .map_err(|e| {
                if e.raw_os_error() == Some(libc::ELOOP) {
                    io::Error::new(io::ErrorKind::InvalidInput, "must not be a symlink")
                } else {
                    e
                }
            })
    }
    #[cfg(not(unix))]
    {
        // No O_NOFOLLOW equivalent: reject symlinks up front (racy, best effort).
        if std::fs::symlink_metadata(path)?.file_type().is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "must not be a symlink",
            ));
        }
        File::open(path)
    }
}

fn require_regular(f: &File) -> io::Result<std::fs::Metadata> {
    let md = f.metadata()?;
    if !md.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "must be a regular file",
        ));
    }
    Ok(md)
}

/// Open a secret file (`O_NOFOLLOW | O_RDONLY`): the descriptor must be a
/// regular file owned by the current user with no group/other permission bits.
pub fn open_private_file(path: &Path) -> io::Result<File> {
    let f = open_nofollow(path)?;
    let md = require_regular(&f)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: geteuid has no preconditions.
        if md.uid() != unsafe { libc::geteuid() } {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "must be owned by the current user",
            ));
        }
        if md.mode() & 0o077 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "must not be accessible by group or others (chmod 600)",
            ));
        }
    }
    #[cfg(not(unix))]
    let _ = md;
    Ok(f)
}

/// Open a non-secret file (certificate, CA bundle): `O_NOFOLLOW`, regular file,
/// no owner or mode rule.
pub fn open_public_file(path: &Path) -> io::Result<File> {
    let f = open_nofollow(path)?;
    require_regular(&f)?;
    Ok(f)
}

/// Read a whole private file through [`open_private_file`].
pub fn read_private_file(path: &Path) -> io::Result<Vec<u8>> {
    use std::io::Read;
    let mut buf = Vec::new();
    open_private_file(path)?.read_to_end(&mut buf)?;
    Ok(buf)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    fn mk(dir: &Path, name: &str, mode: u32) -> std::path::PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, "x").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
        p
    }

    #[test]
    fn private_file_accepts_0600_and_rejects_symlink_and_group_readable() {
        let t = tempfile::tempdir().unwrap();
        let ok = mk(t.path(), "ok", 0o600);
        assert!(open_private_file(&ok).is_ok());
        assert_eq!(read_private_file(&ok).unwrap(), b"x");

        let link = t.path().join("link");
        symlink(&ok, &link).unwrap();
        let e = open_private_file(&link).unwrap_err();
        assert!(e.to_string().contains("symlink"), "{e}");

        for mode in [0o640, 0o604, 0o660, 0o644] {
            let p = mk(t.path(), "loose", mode);
            let e = open_private_file(&p).unwrap_err();
            assert_eq!(e.kind(), io::ErrorKind::PermissionDenied, "{mode:o}");
        }
        assert!(open_private_file(t.path()).is_err(), "directory rejected");
        assert!(open_private_file(&t.path().join("missing")).is_err());
    }

    #[test]
    fn public_file_allows_any_mode_but_not_symlink_or_dir() {
        let t = tempfile::tempdir().unwrap();
        let p = mk(t.path(), "pub", 0o644);
        assert!(open_public_file(&p).is_ok());
        let link = t.path().join("link");
        symlink(&p, &link).unwrap();
        assert!(open_public_file(&link).is_err());
        assert!(open_public_file(t.path()).is_err());
    }
}
