//! #553: in-memory index of the token file for the enrollment listener.
//!
//! A deny-only filter that runs before the mint lock and before any CSR
//! parse, so an unknown token costs one `stat` and no file read. The file is
//! read again only when its `(len, mtime, inode)` stamp changes, never on a
//! miss. Every write by `TokenStore` replaces the file, so the length, the inode
//! or the mtime changes (a prune followed by an added entry can keep the length).
//!
//! The index can only deny wrongly, never grant: the only entries removed are
//! ones spent or expired more than an hour ago (the HTTP mint prunes them), which
//! the check refuses anyway and which then read as `not_found`. `used_at` is
//! never cleared, `host_id` and `expires_at` never change, and `redeem` checks the
//! token again under the flock and the mint lock.

use super::tokens::{hash_token, RedeemErr, TokenEntry, TokenStore};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::io::Read;
use std::path::PathBuf;
use std::time::SystemTime;
use time::OffsetDateTime;

pub struct TokenIndex {
    path: PathBuf,
    snap: Mutex<Option<Snap>>,
}

struct Snap {
    stamp: Stamp,
    /// A parse error belongs to the bytes, so it is kept with their stamp.
    entries: Result<HashMap<String, TokenEntry>, String>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Stamp {
    Absent,
    File {
        len: u64,
        mtime: SystemTime,
        ino: u64,
    },
}

impl Stamp {
    fn of(m: &std::fs::Metadata) -> Stamp {
        #[cfg(unix)]
        let ino = std::os::unix::fs::MetadataExt::ino(m);
        #[cfg(not(unix))]
        let ino = 0;
        Stamp::File {
            len: m.len(),
            mtime: m.modified().unwrap_or(SystemTime::UNIX_EPOCH),
            ino,
        }
    }
}

impl TokenIndex {
    pub fn new(path: PathBuf) -> Self {
        TokenIndex {
            path,
            snap: Mutex::new(None),
        }
    }

    /// The verdict `TokenStore::check` would give, from memory. Open and read
    /// errors are never cached, so the next call tries again.
    pub fn check(
        &self,
        plaintext: &str,
        host_id: &str,
        now: OffsetDateTime,
    ) -> Result<(), RedeemErr> {
        let stamp = match std::fs::metadata(&self.path) {
            Ok(m) => Stamp::of(&m),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Stamp::Absent,
            Err(e) => return Err(RedeemErr::Io(format!("stat token store: {e}"))),
        };
        let mut snap = self.snap.lock();
        if snap.as_ref().is_none_or(|s| s.stamp != stamp) {
            *snap = Some(self.load(stamp)?);
        }
        let entries = match &snap.as_ref().expect("loaded above").entries {
            Ok(m) => m,
            Err(e) => return Err(RedeemErr::Io(e.clone())),
        };
        entries
            .get(&hash_token(plaintext))
            .ok_or(RedeemErr::NotFound)?
            .verdict(host_id, now)
    }

    /// The stamp comes from the open file, so it always describes the bytes
    /// parsed. A path swapped after the `stat` shows up as a new stamp on the
    /// next call.
    fn load(&self, stamp: Stamp) -> Result<Snap, RedeemErr> {
        let absent = || Snap {
            stamp: Stamp::Absent,
            entries: Ok(HashMap::new()),
        };
        if stamp == Stamp::Absent {
            return Ok(absent());
        }
        let io = |what: &str, e: std::io::Error| RedeemErr::Io(format!("{what} token store: {e}"));
        let mut f = match std::fs::File::open(&self.path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(absent()),
            Err(e) => return Err(io("open", e)),
        };
        let stamp = Stamp::of(&f.metadata().map_err(|e| io("stat", e))?);
        let mut bytes = Vec::new();
        f.read_to_end(&mut bytes).map_err(|e| io("read", e))?;
        let entries = serde_json::from_slice::<TokenStore>(&bytes)
            .map(|s| {
                s.tokens
                    .into_iter()
                    .map(|t| (t.token_hash.clone(), t))
                    .collect()
            })
            .map_err(|e| format!("parse token store: {e}"));
        Ok(Snap { stamp, entries })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::Duration;

    fn now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_900_000_000).unwrap()
    }

    fn issue(p: &std::path::Path, host: &str, ttl: Duration) -> String {
        TokenStore::issue(p, host, now() + ttl, now()).unwrap()
    }

    #[test]
    fn finds_tokens_issued_after_the_first_load() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("t.json");
        let idx = TokenIndex::new(p.clone());
        assert_eq!(idx.check("x", "h", now()), Err(RedeemErr::NotFound));
        let a = issue(&p, "h", Duration::hours(1));
        let b = issue(&p, "h", Duration::hours(1));
        assert_eq!(idx.check(&a, "h", now()), Ok(()));
        assert_eq!(idx.check(&b, "h", now()), Ok(()));
        assert_eq!(idx.check("x", "h", now()), Err(RedeemErr::NotFound));
    }

    #[test]
    fn reasons_match_the_token_store() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("t.json");
        let idx = TokenIndex::new(p.clone());
        let used = issue(&p, "h", Duration::hours(1));
        TokenStore::mark_used(&p, &used, "h", now()).unwrap();
        let expired = issue(&p, "h", Duration::seconds(-1));
        let live = issue(&p, "h", Duration::hours(1));
        for (tok, host) in [
            (&used, "h"),
            (&expired, "h"),
            (&live, "other"),
            (&live, "h"),
        ] {
            assert_eq!(
                idx.check(tok, host, now()),
                TokenStore::check(&p, tok, host, now()),
                "{host}"
            );
        }
        assert_eq!(idx.check(&used, "h", now()), Err(RedeemErr::Used));
        assert_eq!(idx.check(&expired, "h", now()), Err(RedeemErr::Expired));
        assert_eq!(idx.check(&live, "x", now()), Err(RedeemErr::HostMismatch));
    }

    /// Rewrite the file in place with bytes of the same length and put the
    /// mtime back, so the stamp does not change.
    fn overwrite_keeping_stamp(p: &std::path::Path, bytes: &[u8]) {
        let m = std::fs::metadata(p).unwrap();
        assert_eq!(m.len() as usize, bytes.len());
        let f = std::fs::OpenOptions::new().write(true).open(p).unwrap();
        std::io::Write::write_all(&mut &f, bytes).unwrap();
        f.set_modified(m.modified().unwrap()).unwrap();
        drop(f);
        assert_eq!(Stamp::of(&std::fs::metadata(p).unwrap()), Stamp::of(&m));
    }

    #[test]
    fn a_miss_never_reads_the_file() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("t.json");
        let tok = issue(&p, "h", Duration::hours(1));
        let idx = TokenIndex::new(p.clone());
        assert_eq!(idx.check(&tok, "h", now()), Ok(()));
        let len = std::fs::metadata(&p).unwrap().len() as usize;
        overwrite_keeping_stamp(&p, &vec![b'#'; len]);
        assert_eq!(idx.check("unknown", "h", now()), Err(RedeemErr::NotFound));
        assert_eq!(idx.check(&tok, "h", now()), Ok(()));
    }

    #[test]
    fn a_parse_error_lasts_until_the_file_changes() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("t.json");
        std::fs::write(&p, br#"{"tokens":[}}"#).unwrap();
        let idx = TokenIndex::new(p.clone());
        assert!(matches!(idx.check("x", "h", now()), Err(RedeemErr::Io(_))));
        overwrite_keeping_stamp(&p, br#"{"tokens":[]}"#);
        assert!(matches!(idx.check("x", "h", now()), Err(RedeemErr::Io(_))));
        std::fs::write(&p, br#"{"tokens": []}"#).unwrap();
        assert_eq!(idx.check("x", "h", now()), Err(RedeemErr::NotFound));
    }

    #[cfg(unix)]
    #[test]
    fn an_unreadable_file_is_tried_again_without_a_stamp_change() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("t.json");
        let tok = issue(&p, "h", Duration::hours(1));
        let stamp = |p: &std::path::Path| Stamp::of(&std::fs::metadata(p).unwrap());
        let before = stamp(&p);
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o000)).unwrap();
        if std::fs::File::open(&p).is_ok() {
            eprintln!("skip: running as root, mode 000 does not stop reads");
            return;
        }
        let idx = TokenIndex::new(p.clone());
        assert!(matches!(idx.check(&tok, "h", now()), Err(RedeemErr::Io(_))));
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(stamp(&p), before, "chmod must not change the stamp");
        assert_eq!(idx.check(&tok, "h", now()), Ok(()));
    }

    #[test]
    fn a_missing_file_is_not_found_until_created() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("t.json");
        let idx = TokenIndex::new(p.clone());
        assert_eq!(idx.check("x", "h", now()), Err(RedeemErr::NotFound));
        let tok = issue(&p, "h", Duration::hours(1));
        assert_eq!(idx.check(&tok, "h", now()), Ok(()));
    }
}
