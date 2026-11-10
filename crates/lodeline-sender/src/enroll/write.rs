//! Writes for `lodeline-sender enroll` and `csr` that never replace a file and never
//! follow a link planted in a directory another account owns.
//!
//! The shape follows `lodeline-proxy`'s `fsutil.rs`: open with `O_NOFOLLOW`, then
//! inspect the open descriptor. A sender-local copy keeps `lodeline-sender` from
//! depending on the proxy crate.
//!
//! Ownership rule. A file may be given to its directory's owner only through
//! `fchown` on a descriptor this run created with create-new, and only when that
//! directory is not root-owned. The owner of an existing file, a path, a lock or a
//! directory is never changed.

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

/// An open directory on Unix, so its owner is read from the descriptor; nothing elsewhere.
#[cfg(unix)]
type Dir = File;
#[cfg(not(unix))]
type Dir = ();

/// Most bytes a pre-existing file in a directory another account owns is read for.
pub const MAX_READ: u64 = 64 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub enum Put {
    Written,
    /// The target already held exactly these bytes.
    Same,
}

#[derive(Debug)]
pub enum PutError {
    /// The target exists with other content. It is never replaced.
    Conflict,
    /// The temporary name is taken, by an earlier crashed run or by a run in progress.
    StaleTemp(PathBuf),
    Io(io::Error),
}

impl fmt::Display for PutError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Conflict => f.write_str("it exists with other content and is never replaced"),
            Self::StaleTemp(p) => write!(
                f,
                "{} exists: another enroll is running, or an earlier run stopped half way. \
                 Remove that file and run again",
                p.display()
            ),
            Self::Io(e) => write!(f, "{e}"),
        }
    }
}

impl From<io::Error> for PutError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

fn invalid(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg.to_owned())
}

/// Open a directory without following a link at its last component.
#[cfg(unix)]
pub fn open_dir(dir: &Path) -> io::Result<Dir> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(dir)
        .map_err(|e| match e.raw_os_error() {
            Some(libc::ELOOP | libc::ENOTDIR) => invalid("must be a directory, not a link"),
            _ => e,
        })
}

#[cfg(not(unix))]
pub fn open_dir(dir: &Path) -> io::Result<Dir> {
    if std::fs::symlink_metadata(dir)?.is_dir() {
        Ok(())
    } else {
        Err(invalid("must be a directory"))
    }
}

/// Read a file that may already exist in a directory another account owns.
/// `None` when it is absent. It must be a regular file with one link, at most
/// [`MAX_READ`] bytes, and is opened without following a link or blocking on a FIFO.
pub fn read_existing(path: &Path) -> io::Result<Option<Vec<u8>>> {
    let mut opts = OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    opts.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    #[cfg(not(unix))]
    if std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err(invalid("must not be a link"));
    }
    let f = match opts.open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        #[cfg(unix)]
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => {
            return Err(invalid("must not be a link"))
        }
        Err(e) => return Err(e),
    };
    let md = f.metadata()?;
    if !md.is_file() {
        return Err(invalid("must be a regular file"));
    }
    #[cfg(unix)]
    if md.nlink() != 1 {
        return Err(invalid("must not have another hard link"));
    }
    let mut buf = Vec::new();
    f.take(MAX_READ + 1).read_to_end(&mut buf)?;
    if buf.len() as u64 > MAX_READ {
        return Err(invalid("is larger than 64 KiB"));
    }
    Ok(Some(buf))
}

/// Give `file`, which this run just created, to the owner of `dir`, when that is
/// not root. A file root created has owner 0, which is how root is detected here.
#[cfg(unix)]
fn give_to_dir_owner(file: &File, dir: &Dir) -> io::Result<()> {
    let (fm, dm) = (file.metadata()?, dir.metadata()?);
    if fm.uid() == 0 && dm.uid() != 0 {
        std::os::unix::fs::fchown(file, Some(dm.uid()), Some(dm.gid()))?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn give_to_dir_owner(_file: &File, _dir: &Dir) -> io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn sync_dir(dir: &Dir) -> io::Result<()> {
    dir.sync_all()
}

#[cfg(not(unix))]
fn sync_dir(_dir: &Dir) -> io::Result<()> {
    Ok(())
}

fn temp_name(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".tmp");
    path.with_file_name(name)
}

/// Write `bytes` to `path` with `mode`, without ever replacing a file. Absent means
/// write, identical means [`Put::Same`], different means [`PutError::Conflict`].
pub fn put(path: &Path, bytes: &[u8], mode: u32) -> Result<Put, PutError> {
    put_with(path, bytes, mode, || {})
}

/// [`put`] with a hook that runs after the temporary file is durable and before it
/// is linked into place, so a test can create the target in that window.
pub fn put_with(
    path: &Path,
    bytes: &[u8],
    mode: u32,
    between: impl FnOnce(),
) -> Result<Put, PutError> {
    let dir = match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    };
    let dirf = open_dir(dir)?;
    let verdict = |cur: Option<Vec<u8>>| match cur {
        Some(c) if c == bytes => Some(Ok(Put::Same)),
        Some(_) => Some(Err(PutError::Conflict)),
        None => None,
    };
    if let Some(r) = verdict(read_existing(path)?) {
        return r;
    }
    let tmp = temp_name(path);
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    opts.mode(mode);
    #[cfg(not(unix))]
    let _ = mode;
    let f = match opts.open(&tmp) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => return Err(PutError::StaleTemp(tmp)),
        Err(e) => return Err(e.into()),
    };
    let filled = (|| -> io::Result<()> {
        // The mode is set on the descriptor so a umask cannot narrow it.
        #[cfg(unix)]
        f.set_permissions(std::fs::Permissions::from_mode(mode))?;
        (&f).write_all(bytes)?;
        f.sync_all()?;
        give_to_dir_owner(&f, &dirf)
    })();
    drop(f);
    if let Err(e) = filled {
        let _ = std::fs::remove_file(&tmp);
        return Err(e.into());
    }
    between();
    let linked = std::fs::hard_link(&tmp, path);
    let _ = std::fs::remove_file(&tmp);
    match linked {
        Ok(()) => {
            sync_dir(&dirf)?;
            Ok(Put::Written)
        }
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            verdict(read_existing(path)?).unwrap_or(Err(PutError::Conflict))
        }
        Err(e) => Err(PutError::Io(io::Error::new(
            e.kind(),
            format!("{e} (a link must be possible in this directory)"),
        ))),
    }
}

/// Where an ancestor of an output directory is not safe for root to write under.
#[cfg(unix)]
pub fn untrusted_ancestor(dir: &Path, top: &Path, owner_uid: u32) -> io::Result<Option<PathBuf>> {
    let parent = dir.parent().unwrap_or(Path::new("/"));
    let canon = std::fs::canonicalize(parent)
        .map_err(|e| io::Error::new(e.kind(), format!("{e}; create {} first", parent.display())))?;
    for a in canon.ancestors() {
        let md = std::fs::metadata(a)?;
        if !md.is_dir() || md.uid() != owner_uid || md.mode() & 0o022 != 0 {
            return Ok(Some(a.to_path_buf()));
        }
        if a == top {
            break;
        }
    }
    Ok(None)
}

/// Root's ancestor walk is a Unix rule; `enroll` is refused on Windows before it runs.
#[cfg(not(unix))]
pub fn untrusted_ancestor(
    _dir: &Path,
    _top: &Path,
    _owner_uid: u32,
) -> io::Result<Option<PathBuf>> {
    Ok(None)
}

/// Make sure `dir` exists as a directory. When it is missing it is created with
/// `mode`: only the last component as root, which has already checked the
/// ancestors, and every component otherwise. Returns whether it was created.
pub fn ensure_dir(dir: &Path, mode: u32, only_last: bool) -> io::Result<bool> {
    match open_dir(dir) {
        Ok(_) => return Ok(false),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    if only_last {
        std::fs::create_dir(dir)?;
    } else {
        std::fs::create_dir_all(dir)?;
    }
    #[cfg(unix)]
    open_dir(dir)?.set_permissions(std::fs::Permissions::from_mode(mode))?;
    #[cfg(not(unix))]
    let _ = mode;
    Ok(true)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use std::os::unix::net::UnixListener;

    fn mode(p: &Path) -> u32 {
        std::fs::metadata(p).unwrap().mode() & 0o7777
    }

    fn canary(dir: &Path) -> (PathBuf, Vec<u8>, u32, u32) {
        let p = dir.join("canary");
        std::fs::write(&p, b"canary").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o640)).unwrap();
        let m = std::fs::metadata(&p).unwrap();
        (p, b"canary".to_vec(), m.mode(), m.uid())
    }

    fn assert_canary_untouched(c: &(PathBuf, Vec<u8>, u32, u32)) {
        let m = std::fs::metadata(&c.0).unwrap();
        assert_eq!(std::fs::read(&c.0).unwrap(), c.1, "canary content");
        assert_eq!((m.mode(), m.uid()), (c.2, c.3), "canary mode and owner");
    }

    #[test]
    fn absent_is_written_same_is_same_other_is_conflict() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("f");
        assert!(matches!(put(&p, b"one", 0o644), Ok(Put::Written)));
        assert_eq!(mode(&p), 0o644);
        assert!(matches!(put(&p, b"one", 0o644), Ok(Put::Same)));
        assert!(matches!(put(&p, b"two", 0o644), Err(PutError::Conflict)));
        assert_eq!(std::fs::read(&p).unwrap(), b"one");
        assert!(!temp_name(&p).exists(), "no temporary file is left behind");
    }

    #[test]
    fn modes_survive_a_077_umask() {
        let d = tempfile::tempdir().unwrap();
        // SAFETY: umask has no preconditions; restored before the asserts run.
        let old = unsafe { libc::umask(0o077) };
        let a = put(&d.path().join("pub"), b"x", 0o644);
        let b = put(&d.path().join("key"), b"x", 0o600);
        let c = ensure_dir(&d.path().join("sub"), 0o755, true);
        unsafe { libc::umask(old) };
        a.unwrap();
        b.unwrap();
        c.unwrap();
        assert_eq!(mode(&d.path().join("pub")), 0o644);
        assert_eq!(mode(&d.path().join("key")), 0o600);
        assert_eq!(mode(&d.path().join("sub")), 0o755);
    }

    #[test]
    fn a_target_created_between_fsync_and_link_is_a_conflict() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("f");
        let r = put_with(&p, b"mine", 0o644, || {
            std::fs::write(&p, b"theirs").unwrap()
        });
        assert!(matches!(r, Err(PutError::Conflict)), "{r:?}");
        assert_eq!(std::fs::read(&p).unwrap(), b"theirs");
        assert!(!temp_name(&p).exists());
    }

    #[test]
    fn a_target_that_appears_with_the_same_bytes_is_same() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("f");
        let r = put_with(&p, b"same", 0o644, || std::fs::write(&p, b"same").unwrap());
        assert!(matches!(r, Ok(Put::Same)), "{r:?}");
    }

    #[test]
    fn a_link_fifo_or_hard_link_at_the_target_is_refused_and_the_canary_stays() {
        for kind in ["symlink", "fifo", "hardlink", "dangling"] {
            let d = tempfile::tempdir().unwrap();
            let c = canary(d.path());
            let p = d.path().join("client.key");
            match kind {
                "symlink" => symlink(&c.0, &p).unwrap(),
                "dangling" => symlink(d.path().join("nowhere"), &p).unwrap(),
                "hardlink" => std::fs::hard_link(&c.0, &p).unwrap(),
                _ => {
                    let cs = std::ffi::CString::new(p.to_str().unwrap()).unwrap();
                    // SAFETY: a valid NUL-terminated path.
                    assert_eq!(unsafe { libc::mkfifo(cs.as_ptr(), 0o600) }, 0);
                }
            }
            let r = put(&p, b"new", 0o600);
            assert!(
                matches!(r, Err(PutError::Io(_)) | Err(PutError::Conflict)),
                "{kind}: {r:?}"
            );
            assert_canary_untouched(&c);
            assert!(!temp_name(&p).exists(), "{kind}");
        }
    }

    #[test]
    fn a_fifo_at_the_target_does_not_hang_a_read() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("client.crt");
        let cs = std::ffi::CString::new(p.to_str().unwrap()).unwrap();
        // SAFETY: a valid NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(cs.as_ptr(), 0o600) }, 0);
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || tx.send(read_existing(&p).is_err()).ok());
        assert_eq!(rx.recv_timeout(std::time::Duration::from_secs(5)), Ok(true));
    }

    #[test]
    fn a_planted_name_at_the_temp_path_is_refused_not_removed_or_followed() {
        for kind in ["symlink", "fifo", "hardlink", "file"] {
            let d = tempfile::tempdir().unwrap();
            let c = canary(d.path());
            let p = d.path().join("client.key");
            let t = temp_name(&p);
            match kind {
                "symlink" => symlink(&c.0, &t).unwrap(),
                "hardlink" => std::fs::hard_link(&c.0, &t).unwrap(),
                "file" => std::fs::write(&t, b"x").unwrap(),
                _ => {
                    let cs = std::ffi::CString::new(t.to_str().unwrap()).unwrap();
                    // SAFETY: a valid NUL-terminated path.
                    assert_eq!(unsafe { libc::mkfifo(cs.as_ptr(), 0o600) }, 0);
                }
            }
            let r = put(&p, b"new", 0o600);
            assert!(matches!(r, Err(PutError::StaleTemp(_))), "{kind}: {r:?}");
            assert!(std::fs::symlink_metadata(&t).is_ok(), "{kind}: kept");
            assert!(!p.exists(), "{kind}: nothing written");
            assert_canary_untouched(&c);
        }
    }

    #[test]
    fn a_socket_or_oversized_file_at_the_target_is_refused() {
        let d = tempfile::tempdir().unwrap();
        let s = d.path().join("sock");
        let _l = UnixListener::bind(&s).unwrap();
        assert!(read_existing(&s).is_err());
        let big = d.path().join("big");
        std::fs::write(&big, vec![b'a'; MAX_READ as usize + 1]).unwrap();
        assert!(read_existing(&big).is_err());
        assert_eq!(read_existing(&d.path().join("none")).unwrap(), None);
    }

    #[test]
    fn a_directory_that_is_a_link_is_not_followed() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir(d.path().join("real")).unwrap();
        symlink(d.path().join("real"), d.path().join("link")).unwrap();
        assert!(put(&d.path().join("link").join("f"), b"x", 0o644).is_err());
        assert!(!d.path().join("real/f").exists());
        assert!(open_dir(&d.path().join("link")).is_err());
        assert!(ensure_dir(&d.path().join("link"), 0o755, true).is_err());
    }

    #[test]
    fn an_own_directory_changes_no_owner() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("f");
        put(&p, b"x", 0o600).unwrap();
        let (f, dm) = (
            std::fs::metadata(&p).unwrap(),
            std::fs::metadata(d.path()).unwrap(),
        );
        assert_eq!((f.uid(), f.gid()), (dm.uid(), dm.gid()));
    }

    #[test]
    fn ancestors_must_be_owned_by_the_owner_and_closed_to_group_and_others() {
        let d = tempfile::tempdir().unwrap();
        let me = std::fs::metadata(d.path()).unwrap().uid();
        let a = d.path().join("a");
        let b = a.join("b");
        std::fs::create_dir_all(&b).unwrap();
        let top = std::fs::canonicalize(d.path()).unwrap();
        for dir in [&a, &b] {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        assert_eq!(untrusted_ancestor(&b.join("c"), &top, me).unwrap(), None);
        std::fs::set_permissions(&a, std::fs::Permissions::from_mode(0o775)).unwrap();
        assert_eq!(
            untrusted_ancestor(&b.join("c"), &top, me).unwrap(),
            Some(std::fs::canonicalize(&a).unwrap())
        );
        std::fs::set_permissions(&a, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            untrusted_ancestor(&b.join("c"), &top, me.wrapping_add(1)).unwrap(),
            Some(std::fs::canonicalize(&b).unwrap())
        );
        let e = untrusted_ancestor(&d.path().join("x/y"), &top, me).unwrap_err();
        assert!(e.to_string().contains("create"), "{e}");
    }

    /// Needs root. Run by CI under `sudo` with `--ignored`.
    #[test]
    #[ignore = "needs root"]
    fn as_root_a_file_takes_the_owner_of_a_non_root_directory_and_a_planted_link_gets_nothing() {
        // SAFETY: geteuid has no preconditions.
        assert_eq!(unsafe { libc::geteuid() }, 0, "run this test as root");
        let d = tempfile::tempdir().unwrap();
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let sub = d.path().join("sender");
        std::fs::create_dir(&sub).unwrap();
        std::os::unix::fs::chown(&sub, Some(65534), Some(65533)).unwrap();

        put(&sub.join("client.key"), b"key", 0o600).unwrap();
        let m = std::fs::metadata(sub.join("client.key")).unwrap();
        assert_eq!((m.uid(), m.gid(), m.mode() & 0o7777), (65534, 65533, 0o600));

        // A root-owned directory keeps root as the owner.
        put(&d.path().join("root.yaml"), b"x", 0o644).unwrap();
        assert_eq!(
            std::fs::metadata(d.path().join("root.yaml")).unwrap().uid(),
            0
        );

        // The account that owns the directory plants a link to a root-only file.
        let canary = d.path().join("shadow");
        std::fs::write(&canary, b"root only").unwrap();
        std::fs::set_permissions(&canary, std::fs::Permissions::from_mode(0o600)).unwrap();
        for name in ["client.crt", "client.crt.tmp"] {
            symlink(&canary, sub.join(name)).unwrap();
        }
        assert!(put(&sub.join("client.crt"), b"new", 0o644).is_err());
        let m = std::fs::metadata(&canary).unwrap();
        assert_eq!((m.uid(), m.mode() & 0o7777), (0, 0o600), "canary unchanged");
        assert_eq!(std::fs::read(&canary).unwrap(), b"root only");
    }
}
