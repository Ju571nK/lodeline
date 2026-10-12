//! `state_dir`: exclusive lock, proxy_id binding and epoch (control-plane.md
//! §1.3 "Re-registration" and "state_dir loss" rows; contracts README M1).
//!
//! Layout (all files 0600, directory 0700):
//! * `lock`          flock(LOCK_EX) held for the process lifetime
//! * `binding.json`  `{schema_version, proxy_id, epoch_id}`
//! * `status.json`   written by [`crate::lifecycle`]
//! * `applied.json`  `{schema_version, proxy_id, revision, config_hash}`: the
//!   revision high-water mark ONLY (never the config itself, which needs a fresh
//!   fetch after a restart, control-plane.md §6.3). It stops a restarted proxy
//!   from accepting a rolled-back server revision.

use std::fs::File;
#[cfg(unix)]
use std::fs::OpenOptions;
#[cfg(unix)]
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sigil_proxy_api::Id;
use thiserror::Error;

pub const LOCK_FILE: &str = "lock";
pub const BINDING_FILE: &str = "binding.json";
pub const STATUS_FILE: &str = "status.json";
pub const APPLIED_FILE: &str = "applied.json";

#[derive(Debug, Error)]
pub enum StateError {
    #[error("state_dir {path}: {reason}")]
    Dir { path: String, reason: String },
    #[error("another sigil-proxy instance holds the lock on this state_dir")]
    Locked,
    #[error(
        "state_dir is bound to a different proxy_id; refusing to start. Drain or abandon the \
         spool and use a new state_dir for the new proxy_id"
    )]
    BoundToDifferentProxy,
    // OPEN: an unreadable binding is refused rather than treated as "lost state".
    // A new epoch loses server-side continuity (producer_epoch_change), so the
    // operator must delete binding.json deliberately.
    #[error("binding file is unreadable or invalid ({0}); delete it to start a new epoch")]
    BadBinding(String),
    // Same stance as the binding: an unreadable mark is refused, not ignored.
    // Ignoring it would silently allow a rollback; the operator deletes the file
    // deliberately to accept any revision.
    #[error(
        "applied revision file is unreadable or invalid ({0}); delete applied.json to accept any \
         revision"
    )]
    BadAppliedRevision(String),
    #[error("i/o error on {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
    #[error("state_dir locking is not supported on this platform")]
    Unsupported,
}

fn io_err(path: &Path, source: std::io::Error) -> StateError {
    StateError::Io {
        path: path.display().to_string(),
        source,
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Binding {
    schema_version: u32,
    proxy_id: String,
    epoch_id: String,
}

/// The persisted revision high-water mark.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppliedMark {
    pub schema_version: u32,
    pub proxy_id: String,
    pub revision: i64,
    /// Lowercase hex SHA-256 `config_hash` of that revision.
    pub config_hash: String,
}

/// An opened, locked state directory. The lock is released when dropped.
#[derive(Debug)]
pub struct StateDir {
    dir: PathBuf,
    proxy_id: Id,
    epoch_id: String,
    new_epoch: bool,
    _lock: File,
}

impl StateDir {
    pub fn open(dir: &Path, proxy_id: &Id) -> Result<StateDir, StateError> {
        prepare_dir(dir)?;
        let lock = acquire_lock(&dir.join(LOCK_FILE))?;

        let binding_path = dir.join(BINDING_FILE);
        let (epoch_id, new_epoch) = match crate::fsutil::read_private_file(&binding_path) {
            Ok(bytes) => {
                let b: Binding = serde_json::from_slice(&bytes)
                    .map_err(|_| StateError::BadBinding("parse error".into()))?;
                if b.schema_version != 1 || sigil_proxy_api::Uuid::new(b.epoch_id.clone()).is_err()
                {
                    return Err(StateError::BadBinding("unexpected content".into()));
                }
                if Id::new(b.proxy_id.clone()).is_err() {
                    return Err(StateError::BadBinding("unexpected content".into()));
                }
                if b.proxy_id != proxy_id.as_str() {
                    return Err(StateError::BoundToDifferentProxy);
                }
                (b.epoch_id, false)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // New or lost state: fresh random epoch (new K/key_id come with the
                // registry work, not here).
                let epoch = uuid::Uuid::new_v4().hyphenated().to_string();
                let b = Binding {
                    schema_version: 1,
                    proxy_id: proxy_id.as_str().to_string(),
                    epoch_id: epoch.clone(),
                };
                let bytes = serde_json::to_vec_pretty(&b).expect("binding serializes");
                write_atomic(dir, BINDING_FILE, &bytes)?;
                (epoch, true)
            }
            Err(e) => return Err(io_err(&binding_path, e)),
        };
        Ok(StateDir {
            dir: dir.to_path_buf(),
            proxy_id: proxy_id.clone(),
            epoch_id,
            new_epoch,
            _lock: lock,
        })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }
    pub fn proxy_id(&self) -> &Id {
        &self.proxy_id
    }
    pub fn epoch_id(&self) -> &str {
        &self.epoch_id
    }
    /// True when this open created the epoch (state was new or lost).
    pub fn is_new_epoch(&self) -> bool {
        self.new_epoch
    }

    /// The persisted high-water mark. `Ok(None)` is a normal first start. A
    /// corrupt, foreign, symlinked or loose-permission file is an error (fail
    /// closed).
    pub fn read_applied(&self) -> Result<Option<AppliedMark>, StateError> {
        let path = self.dir.join(APPLIED_FILE);
        let bytes = match crate::fsutil::read_private_file(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(io_err(&path, e)),
        };
        let m: AppliedMark = serde_json::from_slice(&bytes)
            .map_err(|_| StateError::BadAppliedRevision("parse error".into()))?;
        let hash_ok = m.config_hash.len() == 64
            && m.config_hash
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
        if m.schema_version != 1 || m.revision < 1 || !hash_ok {
            return Err(StateError::BadAppliedRevision("unexpected content".into()));
        }
        if m.proxy_id != self.proxy_id.as_str() {
            return Err(StateError::BadAppliedRevision("other proxy_id".into()));
        }
        Ok(Some(m))
    }

    /// Persist the high-water mark (owner-only, tmp + fsync + rename + dir fsync).
    pub fn write_applied(&self, revision: i64, config_hash: &str) -> Result<(), StateError> {
        let m = AppliedMark {
            schema_version: 1,
            proxy_id: self.proxy_id.as_str().to_string(),
            revision,
            config_hash: config_hash.to_string(),
        };
        let bytes = serde_json::to_vec_pretty(&m).expect("mark serializes");
        write_atomic(&self.dir, APPLIED_FILE, &bytes)
    }

    /// Atomically replace a file in the state directory.
    pub fn write_atomic(&self, name: &str, bytes: &[u8]) -> Result<(), StateError> {
        write_atomic(&self.dir, name, bytes)
    }
}

#[cfg(unix)]
fn prepare_dir(dir: &Path) -> Result<(), StateError> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    let derr = |reason: &str| StateError::Dir {
        path: dir.display().to_string(),
        reason: reason.to_string(),
    };
    match std::fs::symlink_metadata(dir) {
        Ok(md) => {
            if md.file_type().is_symlink() {
                return Err(derr("must not be a symlink"));
            }
            if !md.is_dir() {
                return Err(derr("not a directory"));
            }
            // SAFETY: geteuid has no preconditions.
            if md.uid() != unsafe { libc::geteuid() } {
                return Err(derr("must be owned by the current user"));
            }
            if md.mode() & 0o077 != 0 {
                return Err(derr(
                    "must not be accessible by group or others (chmod 700)",
                ));
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(dir)
                .map_err(|e| io_err(dir, e))?;
        }
        Err(e) => return Err(io_err(dir, e)),
    }
    Ok(())
}

#[cfg(not(unix))]
fn prepare_dir(_dir: &Path) -> Result<(), StateError> {
    Err(StateError::Unsupported)
}

#[cfg(unix)]
fn open_private(path: &Path, truncate: bool) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(truncate)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}

#[cfg(unix)]
fn acquire_lock(path: &Path) -> Result<File, StateError> {
    use std::os::fd::AsRawFd;
    let f = open_private(path, false).map_err(|e| io_err(path, e))?;
    // SAFETY: valid open fd.
    let rc = unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc != 0 {
        let e = std::io::Error::last_os_error();
        return Err(if e.kind() == std::io::ErrorKind::WouldBlock {
            StateError::Locked
        } else {
            io_err(path, e)
        });
    }
    Ok(f)
}

#[cfg(not(unix))]
fn acquire_lock(_path: &Path) -> Result<File, StateError> {
    Err(StateError::Unsupported)
}

/// Read-only liveness probe used by `health`: true when some process holds the
/// lock. Creates nothing and binds nothing.
#[cfg(unix)]
pub fn lock_is_held(dir: &Path) -> bool {
    use std::os::fd::AsRawFd;
    let Ok(f) = File::open(dir.join(LOCK_FILE)) else {
        return false;
    };
    // SAFETY: valid open fd. A shared lock conflicts with the holder's exclusive one.
    let rc = unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) };
    rc != 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::WouldBlock
}

#[cfg(not(unix))]
pub fn lock_is_held(_dir: &Path) -> bool {
    false
}

/// tmp file + fsync + rename + directory fsync.
#[cfg(unix)]
fn write_atomic(dir: &Path, name: &str, bytes: &[u8]) -> Result<(), StateError> {
    let tmp = dir.join(format!(".{name}.tmp"));
    let dest = dir.join(name);
    // A stale tmp can only come from a crashed earlier holder of the lock.
    let _ = std::fs::remove_file(&tmp);
    let mut f = open_private(&tmp, true).map_err(|e| io_err(&tmp, e))?;
    f.write_all(bytes).map_err(|e| io_err(&tmp, e))?;
    f.sync_all().map_err(|e| io_err(&tmp, e))?;
    drop(f);
    std::fs::rename(&tmp, &dest).map_err(|e| io_err(&dest, e))?;
    File::open(dir)
        .and_then(|d| d.sync_all())
        .map_err(|e| io_err(dir, e))?;
    Ok(())
}

#[cfg(not(unix))]
fn write_atomic(_dir: &Path, _name: &str, _bytes: &[u8]) -> Result<(), StateError> {
    Err(StateError::Unsupported)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn id(s: &str) -> Id {
        Id::new(s).unwrap()
    }

    /// AC-12 (PX-013): a second instance on the same state_dir fails.
    #[test]
    fn lock_contention() {
        let t = tempfile::tempdir().unwrap();
        let d = t.path().join("st");
        let first = StateDir::open(&d, &id("px-1")).unwrap();
        assert!(matches!(
            StateDir::open(&d, &id("px-1")),
            Err(StateError::Locked)
        ));
        assert!(lock_is_held(&d));
        drop(first);
        assert!(!lock_is_held(&d));
        StateDir::open(&d, &id("px-1")).unwrap();
    }

    /// AC-12: restart keeps the epoch.
    #[test]
    fn restart_keeps_epoch() {
        let t = tempfile::tempdir().unwrap();
        let d = t.path().join("st");
        let a = StateDir::open(&d, &id("px-1")).unwrap();
        assert!(a.is_new_epoch());
        let epoch = a.epoch_id().to_string();
        assert!(sigil_proxy_api::Uuid::new(epoch.clone()).is_ok());
        drop(a);
        let b = StateDir::open(&d, &id("px-1")).unwrap();
        assert!(!b.is_new_epoch());
        assert_eq!(b.epoch_id(), epoch);
    }

    /// AC-12: deleting the state gives a new epoch.
    #[test]
    fn deleting_state_gives_new_epoch() {
        let t = tempfile::tempdir().unwrap();
        let d = t.path().join("st");
        let a = StateDir::open(&d, &id("px-1")).unwrap();
        let epoch = a.epoch_id().to_string();
        drop(a);
        std::fs::remove_file(d.join(BINDING_FILE)).unwrap();
        let b = StateDir::open(&d, &id("px-1")).unwrap();
        assert!(b.is_new_epoch());
        assert_ne!(b.epoch_id(), epoch);
    }

    /// PX-001/D-02: a state_dir bound to another proxy_id is refused, and the
    /// binding is left untouched.
    #[test]
    fn mismatched_proxy_id_is_refused() {
        let t = tempfile::tempdir().unwrap();
        let d = t.path().join("st");
        let a = StateDir::open(&d, &id("px-1")).unwrap();
        let epoch = a.epoch_id().to_string();
        drop(a);
        assert!(matches!(
            StateDir::open(&d, &id("px-2")),
            Err(StateError::BoundToDifferentProxy)
        ));
        let again = StateDir::open(&d, &id("px-1")).unwrap();
        assert_eq!(again.epoch_id(), epoch);
    }

    #[test]
    fn corrupt_binding_is_refused_not_reset() {
        let t = tempfile::tempdir().unwrap();
        let d = t.path().join("st");
        drop(StateDir::open(&d, &id("px-1")).unwrap());
        std::fs::write(d.join(BINDING_FILE), "{").unwrap();
        assert!(matches!(
            StateDir::open(&d, &id("px-1")),
            Err(StateError::BadBinding(_))
        ));
    }

    #[test]
    fn permissions_and_atomic_write() {
        let t = tempfile::tempdir().unwrap();
        let d = t.path().join("st");
        let s = StateDir::open(&d, &id("px-1")).unwrap();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&d), 0o700);
        assert_eq!(mode(&d.join(LOCK_FILE)), 0o600);
        assert_eq!(mode(&d.join(BINDING_FILE)), 0o600);
        s.write_atomic("x.json", b"1").unwrap();
        s.write_atomic("x.json", b"2").unwrap();
        assert_eq!(std::fs::read(d.join("x.json")).unwrap(), b"2");
        assert_eq!(mode(&d.join("x.json")), 0o600);
        assert!(!d.join(".x.json.tmp").exists());
    }

    #[test]
    fn existing_group_accessible_dir_is_refused() {
        let t = tempfile::tempdir().unwrap();
        let d = t.path().join("st");
        std::fs::create_dir(&d).unwrap();
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            StateDir::open(&d, &id("px-1")),
            Err(StateError::Dir { .. })
        ));
    }

    const H: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    #[test]
    fn applied_mark_roundtrip_missing_and_bad() {
        let t = tempfile::tempdir().unwrap();
        let dir = t.path().join("st");
        let id = Id::new("px-1").unwrap();
        let sd = StateDir::open(&dir, &id).unwrap();
        // missing file: normal first start
        assert_eq!(sd.read_applied().unwrap(), None);
        // round trip, owner-only
        sd.write_applied(7, H).unwrap();
        let m = sd.read_applied().unwrap().unwrap();
        assert_eq!((m.revision, m.config_hash.as_str()), (7, H));
        let mode = std::fs::metadata(dir.join(APPLIED_FILE))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        let path = dir.join(APPLIED_FILE);
        // corrupt / foreign / out of range: refused
        for bad in [
            "not json".to_string(),
            r#"{"schema_version":1,"proxy_id":"px-1","revision":0,"config_hash":""#.to_string()
                + H
                + r#""}"#,
            r#"{"schema_version":2,"proxy_id":"px-1","revision":3,"config_hash":""#.to_string()
                + H
                + r#""}"#,
            r#"{"schema_version":1,"proxy_id":"px-1","revision":3,"config_hash":"zz"}"#.to_string(),
            r#"{"schema_version":1,"proxy_id":"other","revision":3,"config_hash":""#.to_string()
                + H
                + r#""}"#,
            r#"{"schema_version":1,"proxy_id":"px-1","revision":3,"config_hash":""#.to_string()
                + H
                + r#"","x":1}"#,
        ] {
            std::fs::write(&path, bad).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            assert!(
                matches!(sd.read_applied(), Err(StateError::BadAppliedRevision(_))),
                "accepted a bad mark"
            );
        }
        // loose permissions and a symlink: refused
        sd.write_applied(7, H).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(sd.read_applied().is_err());
        std::fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(dir.join(LOCK_FILE), &path).unwrap();
        assert!(sd.read_applied().is_err());
    }
}
