//! Management verifier file and credential check (control-plane §0.1, §2.2).
//!
//! The file holds only SHA-256 verifiers of 256-bit bearer tokens, never the
//! tokens. Each entry is bound to one management-caller cert fingerprint.
//!
//! Reload policy (DECIDED here, matches control-plane §2.2 "Reload failure"):
//! FAIL CLOSED. If the file cannot be re-read or validated, the in-memory
//! entries are dropped: NO management credential is active and every
//! management route answers 404 until a valid file loads. The server never
//! keeps serving from the previous in-memory set (a revoked or rotated-out
//! credential must not stay alive because someone broke the file). The caller
//! fingerprint set is the one exception: it is retained from the last good
//! load, but only to keep rejecting those certs on host routes (the safe
//! direction), never to authenticate anything. A change is picked up on
//! SIGHUP or, lazily, when the file's (mtime, length, inode) differs at the
//! next management request. A boot-time error refuses to start.
//!
//! Editing the file: write a new file and `rename` it over the old one (tmp +
//! rename), or send SIGHUP after an in-place edit. An in-place edit is also
//! noticed lazily (mtime/length/ctime/mode change), but a half-written file is read
//! as broken and denies everything until the write completes. Reloads are
//! serialized by a mutex.

use anyhow::{bail, Context, Result};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sigil_proxy_api::verifier;
use std::collections::HashSet;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// At most this many non-expired entries per scope (rotation overlap).
pub const MAX_ACTIVE_PER_SCOPE: usize = 2;
const MAX_ENTRIES: usize = 32;
pub const MAX_FILE_BYTES: u64 = 64 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    Config,
    Identity,
}

impl Scope {
    pub fn as_str(self) -> &'static str {
        match self {
            Scope::Config => "config",
            Scope::Identity => "identity",
        }
    }
}

impl std::str::FromStr for Scope {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "config" => Ok(Scope::Config),
            "identity" => Ok(Scope::Identity),
            other => Err(format!("unknown scope {other:?} (config|identity)")),
        }
    }
}

/// One entry of the verifier file.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifierEntry {
    pub key_id: String,
    pub name: String,
    /// Lowercase-hex SHA-256 of the bearer token string.
    pub verifier: String,
    pub scope: Scope,
    /// blake3 hex of the management-caller leaf DER this entry is bound to.
    pub caller_cert_fingerprint: String,
    /// RFC 3339; absent = no expiry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_after: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileFormat {
    entries: Vec<VerifierEntry>,
}

#[derive(Clone, Debug)]
struct Loaded {
    entry: VerifierEntry,
    not_after: Option<time::OffsetDateTime>,
}

/// What the server knows about a verified caller.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Principal {
    pub key_id: String,
    pub name: String,
    pub scope: Scope,
    pub caller_fingerprint: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnauthReason {
    MissingBearer,
    BadBearer,
    /// Valid token presented from a different caller cert.
    WrongCertBinding,
    Expired,
}

impl UnauthReason {
    pub fn as_str(self) -> &'static str {
        match self {
            UnauthReason::MissingBearer => "missing_bearer",
            UnauthReason::BadBearer => "bad_bearer",
            UnauthReason::WrongCertBinding => "wrong_cert_binding",
            UnauthReason::Expired => "expired",
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum AuthOutcome {
    /// The verifier file is broken or empty: behave as unconfigured (404).
    Denied,
    /// 401. The key id is set once the token itself was recognised.
    Unauthorized(UnauthReason, Option<String>),
    Ok(Principal),
}

/// (mtime, length, inode, ctime sec, ctime nsec, mode, uid). ctime moves on
/// chmod/chown, but two changes inside one filesystem timestamp tick can leave
/// it equal, so mode and owner are part of the stamp too: a permission fix is
/// always noticed.
pub type Stamp = (Option<SystemTime>, u64, u64, i64, i64, u32, u32);

struct State {
    entries: Vec<Loaded>,
    callers: HashSet<String>,
    ok: bool,
    stamp: Option<Stamp>,
}

pub struct MgmtAuth {
    path: PathBuf,
    state: RwLock<State>,
    /// Serializes reloads (SIGHUP task and lazy refresh from requests).
    reload_lock: parking_lot::Mutex<()>,
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn stamp_of(meta: &std::fs::Metadata) -> Stamp {
    #[cfg(unix)]
    let (ino, cs, cn, mode, uid) = {
        use std::os::unix::fs::MetadataExt;
        (
            meta.ino(),
            meta.ctime(),
            meta.ctime_nsec(),
            meta.mode(),
            meta.uid(),
        )
    };
    #[cfg(not(unix))]
    let (ino, cs, cn, mode, uid) = (0, 0, 0, 0, 0);
    (meta.modified().ok(), meta.len(), ino, cs, cn, mode, uid)
}

/// Open `path` as a secret file: regular file, not a symlink (O_NOFOLLOW),
/// owned by the current user, mode without group/other bits. The checks run
/// on the opened fd. Reads at most `max` bytes (more is an error).
pub fn read_owner_only_file(path: &Path, max: u64) -> Result<(Vec<u8>, Stamp)> {
    let lmeta =
        std::fs::symlink_metadata(path).with_context(|| format!("stat {}", path.display()))?;
    if lmeta.file_type().is_symlink() {
        bail!("{} must not be a symlink", path.display());
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW);
    }
    let file = opts
        .open(path)
        .with_context(|| format!("open {}", path.display()))?;
    let meta = file.metadata()?;
    if !meta.is_file() {
        bail!("{} is not a regular file", path.display());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if meta.permissions().mode() & 0o077 != 0 {
            bail!("{} must be owner-only (mode 0600)", path.display());
        }
        // SAFETY: geteuid has no preconditions.
        if meta.uid() != unsafe { libc::geteuid() } {
            bail!("{} must be owned by the current user", path.display());
        }
    }
    let mut buf = Vec::new();
    file.take(max + 1).read_to_end(&mut buf)?;
    if buf.len() as u64 > max {
        bail!("{} is too large", path.display());
    }
    Ok((buf, stamp_of(&meta)))
}

/// `key_id` rule shared by the loader and `verifier-new`.
pub fn validate_key_id(key_id: &str) -> Result<()> {
    let ok = !key_id.is_empty()
        && key_id.len() <= 64
        && key_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    if !ok {
        bail!("invalid key_id (1..=64 of [A-Za-z0-9._-])");
    }
    Ok(())
}

/// `name` rule shared by the loader and `verifier-new`.
pub fn validate_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 128 || name.chars().any(char::is_control) {
        bail!("invalid name (1..=128 bytes, no control characters)");
    }
    Ok(())
}

fn validate(file: FileFormat, now: time::OffsetDateTime) -> Result<Vec<Loaded>> {
    if file.entries.len() > MAX_ENTRIES {
        bail!("too many verifier entries (max {MAX_ENTRIES})");
    }
    let mut out: Vec<Loaded> = Vec::new();
    for e in file.entries {
        validate_key_id(&e.key_id)?;
        validate_name(&e.name).with_context(|| format!("key_id {}", e.key_id))?;
        if !is_hex64(&e.verifier) {
            bail!("verifier of key_id {} is not 64 lowercase hex", e.key_id);
        }
        if !is_hex64(&e.caller_cert_fingerprint) {
            bail!(
                "caller_cert_fingerprint of key_id {} is not 64 lowercase hex",
                e.key_id
            );
        }
        let not_after = match &e.not_after {
            None => None,
            Some(s) => Some(
                time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339)
                    .with_context(|| format!("not_after of key_id {}", e.key_id))?,
            ),
        };
        if out.iter().any(|o| o.entry.key_id == e.key_id) {
            bail!("duplicate key_id {}", e.key_id);
        }
        if out.iter().any(|o| o.entry.verifier == e.verifier) {
            bail!("duplicate verifier (key_id {})", e.key_id);
        }
        out.push(Loaded {
            entry: e,
            not_after,
        });
    }
    for scope in [Scope::Config, Scope::Identity] {
        let active = out
            .iter()
            .filter(|l| l.entry.scope == scope && l.not_after.is_none_or(|t| t > now))
            .count();
        if active > MAX_ACTIVE_PER_SCOPE {
            bail!(
                "more than {MAX_ACTIVE_PER_SCOPE} active {} entries",
                scope.as_str()
            );
        }
    }
    Ok(out)
}

fn load_file(path: &Path) -> Result<(Vec<Loaded>, Stamp)> {
    let (bytes, stamp) = read_owner_only_file(path, MAX_FILE_BYTES)?;
    let file: FileFormat = serde_json::from_slice(&bytes).context("parse verifier file")?;
    Ok((validate(file, time::OffsetDateTime::now_utc())?, stamp))
}

fn callers_of(entries: &[Loaded]) -> HashSet<String> {
    entries
        .iter()
        .map(|l| l.entry.caller_cert_fingerprint.clone())
        .collect()
}

fn observed_stamp(path: &Path) -> Option<Stamp> {
    std::fs::symlink_metadata(path).ok().map(|m| stamp_of(&m))
}

impl MgmtAuth {
    /// Boot-time load. Any error refuses boot.
    pub fn load(path: &Path) -> Result<Self> {
        let (entries, stamp) = load_file(path)
            .with_context(|| format!("management verifier file {}", path.display()))?;
        if entries.is_empty() {
            bail!("management verifier file has no entries");
        }
        let callers = callers_of(&entries);
        Ok(Self {
            path: path.to_path_buf(),
            state: RwLock::new(State {
                entries,
                callers,
                ok: true,
                stamp: Some(stamp),
            }),
            reload_lock: parking_lot::Mutex::new(()),
        })
    }

    /// Re-read the file now (SIGHUP). Fail closed, see the module docs.
    pub fn reload(&self) {
        let _serial = self.reload_lock.lock();
        let observed = observed_stamp(&self.path);
        match load_file(&self.path) {
            Ok((entries, stamp)) if !entries.is_empty() => {
                let callers = callers_of(&entries);
                *self.state.write() = State {
                    entries,
                    callers,
                    ok: true,
                    stamp: Some(stamp),
                };
                tracing::info!("management verifier file reloaded");
            }
            other => {
                let mut g = self.state.write();
                if g.ok || g.stamp != observed {
                    let why = match other {
                        Err(e) => format!("{e:#}"),
                        Ok(_) => "no entries".to_string(),
                    };
                    tracing::error!(
                        reason = %why,
                        "ALERT management verifier reload failed: all management credentials are denied until a valid file loads"
                    );
                }
                g.entries.clear();
                g.ok = false;
                g.stamp = observed;
            }
        }
    }

    /// Reload when the file changed since the last look (or cannot be stat'ed).
    pub fn refresh_if_changed(&self) {
        let now = observed_stamp(&self.path);
        let same = now.is_some() && self.state.read().stamp == now;
        if !same {
            self.reload();
        }
    }

    /// Snapshot of the caller fingerprints (boot-time cross-checks).
    pub fn caller_fingerprints(&self) -> impl Iterator<Item = String> {
        self.state
            .read()
            .callers
            .iter()
            .cloned()
            .collect::<Vec<_>>()
            .into_iter()
    }

    /// True if `fp` is a management-caller cert fingerprint (last good load).
    pub fn is_caller(&self, fp: &str) -> bool {
        self.state.read().callers.contains(fp)
    }

    /// Authenticate a bearer presented from caller cert `caller_fp`.
    /// Order: the token must verify (constant-time over every entry), its
    /// entry must be bound to this caller cert, and it must not be expired.
    pub fn authenticate(
        &self,
        caller_fp: &str,
        token: Option<&str>,
        now: time::OffsetDateTime,
    ) -> AuthOutcome {
        let g = self.state.read();
        if !g.ok || g.entries.is_empty() {
            return AuthOutcome::Denied;
        }
        let Some(token) = token else {
            return AuthOutcome::Unauthorized(UnauthReason::MissingBearer, None);
        };
        let mut hit: Option<&Loaded> = None;
        for l in &g.entries {
            // No early exit: every entry is compared.
            if verifier::verify(token, &l.entry.verifier) && hit.is_none() {
                hit = Some(l);
            }
        }
        let Some(l) = hit else {
            return AuthOutcome::Unauthorized(UnauthReason::BadBearer, None);
        };
        let key_id = Some(l.entry.key_id.clone());
        if !crate::auth::ct_eq(
            l.entry.caller_cert_fingerprint.as_bytes(),
            caller_fp.as_bytes(),
        ) {
            return AuthOutcome::Unauthorized(UnauthReason::WrongCertBinding, key_id);
        }
        if l.not_after.is_some_and(|t| t <= now) {
            return AuthOutcome::Unauthorized(UnauthReason::Expired, key_id);
        }
        AuthOutcome::Ok(Principal {
            key_id: l.entry.key_id.clone(),
            name: l.entry.name.clone(),
            scope: l.entry.scope,
            caller_fingerprint: caller_fp.to_string(),
        })
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    const FP: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const FP2: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn entry(id: &str, token: &str, scope: Scope, fp: &str, na: Option<&str>) -> VerifierEntry {
        VerifierEntry {
            key_id: id.into(),
            name: id.into(),
            verifier: verifier::verifier_for(token),
            scope,
            caller_cert_fingerprint: fp.into(),
            not_after: na.map(str::to_string),
        }
    }

    fn write(p: &Path, entries: Vec<VerifierEntry>, mode: u32) {
        std::fs::write(p, serde_json::to_vec(&FileFormat { entries }).unwrap()).unwrap();
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    fn now() -> time::OffsetDateTime {
        time::OffsetDateTime::now_utc()
    }

    #[test]
    fn auth_order_binding_and_expiry() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("v.json");
        write(
            &p,
            vec![
                entry("a", "tok-a", Scope::Config, FP, None),
                entry(
                    "old",
                    "tok-old",
                    Scope::Identity,
                    FP,
                    Some("2000-01-01T00:00:00Z"),
                ),
            ],
            0o600,
        );
        let m = MgmtAuth::load(&p).unwrap();
        assert!(m.is_caller(FP) && !m.is_caller(FP2));
        assert!(matches!(
            m.authenticate(FP, None, now()),
            AuthOutcome::Unauthorized(UnauthReason::MissingBearer, None)
        ));
        assert!(matches!(
            m.authenticate(FP, Some("nope"), now()),
            AuthOutcome::Unauthorized(UnauthReason::BadBearer, None)
        ));
        assert!(matches!(
            m.authenticate(FP2, Some("tok-a"), now()),
            AuthOutcome::Unauthorized(UnauthReason::WrongCertBinding, Some(_))
        ));
        assert!(matches!(
            m.authenticate(FP, Some("tok-old"), now()),
            AuthOutcome::Unauthorized(UnauthReason::Expired, Some(_))
        ));
        match m.authenticate(FP, Some("tok-a"), now()) {
            AuthOutcome::Ok(p) => assert_eq!((p.key_id.as_str(), p.scope), ("a", Scope::Config)),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn load_validation() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("v.json");
        let e = |i: &str, t: &str, s| entry(i, t, s, FP, None);
        // Three active in one scope: refused. Two + an expired third: fine.
        write(
            &p,
            vec![
                e("1", "t1", Scope::Config),
                e("2", "t2", Scope::Config),
                e("3", "t3", Scope::Config),
            ],
            0o600,
        );
        assert!(MgmtAuth::load(&p).is_err());
        write(
            &p,
            vec![
                e("1", "t1", Scope::Config),
                e("2", "t2", Scope::Config),
                entry("3", "t3", Scope::Config, FP, Some("2000-01-01T00:00:00Z")),
                e("4", "t4", Scope::Identity),
            ],
            0o600,
        );
        assert!(MgmtAuth::load(&p).is_ok());
        // Duplicate key_id, duplicate verifier, bad hex, empty file.
        write(
            &p,
            vec![e("1", "t1", Scope::Config), e("1", "t2", Scope::Config)],
            0o600,
        );
        assert!(MgmtAuth::load(&p).is_err());
        write(
            &p,
            vec![e("1", "t1", Scope::Config), e("2", "t1", Scope::Config)],
            0o600,
        );
        assert!(MgmtAuth::load(&p).is_err());
        let mut bad = e("1", "t1", Scope::Config);
        bad.verifier = "XYZ".into();
        write(&p, vec![bad], 0o600);
        assert!(MgmtAuth::load(&p).is_err());
        write(&p, vec![], 0o600);
        assert!(MgmtAuth::load(&p).is_err());
        std::fs::write(&p, b"{\"entries\":[],\"extra\":1}").unwrap();
        assert!(MgmtAuth::load(&p).is_err(), "unknown field");
    }

    #[test]
    fn perms_symlink_and_missing_refuse() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("v.json");
        write(&p, vec![entry("1", "t", Scope::Config, FP, None)], 0o640);
        assert!(MgmtAuth::load(&p).is_err(), "group-readable");
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(MgmtAuth::load(&p).is_err(), "world-readable");
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(MgmtAuth::load(&p).is_ok());
        let l = d.path().join("link.json");
        std::os::unix::fs::symlink(&p, &l).unwrap();
        assert!(MgmtAuth::load(&l).is_err(), "symlink");
        assert!(MgmtAuth::load(&d.path().join("missing.json")).is_err());
    }

    #[test]
    fn reload_failure_denies_everything_until_fixed() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("v.json");
        write(&p, vec![entry("1", "t1", Scope::Config, FP, None)], 0o600);
        let m = MgmtAuth::load(&p).unwrap();
        assert!(matches!(
            m.authenticate(FP, Some("t1"), now()),
            AuthOutcome::Ok(_)
        ));
        // Break the file (garbage, different length).
        std::fs::write(&p, b"not json at all").unwrap();
        m.refresh_if_changed();
        assert_eq!(m.authenticate(FP, Some("t1"), now()), AuthOutcome::Denied);
        assert!(m.is_caller(FP), "caller set kept for host-route rejection");
        // Still broken: stays denied.
        m.refresh_if_changed();
        assert_eq!(m.authenticate(FP, Some("t1"), now()), AuthOutcome::Denied);
        // Fixed with a rotated token: the old one is gone, the new one works.
        write(
            &p,
            vec![entry("2", "t2-new-token", Scope::Config, FP, None)],
            0o600,
        );
        m.refresh_if_changed();
        assert!(matches!(
            m.authenticate(FP, Some("t2-new-token"), now()),
            AuthOutcome::Ok(_)
        ));
        assert!(matches!(
            m.authenticate(FP, Some("t1"), now()),
            AuthOutcome::Unauthorized(UnauthReason::BadBearer, None)
        ));
        // Loosened permissions on reload also fail closed.
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        m.reload();
        assert_eq!(
            m.authenticate(FP, Some("t2-new-token"), now()),
            AuthOutcome::Denied
        );
    }
}
