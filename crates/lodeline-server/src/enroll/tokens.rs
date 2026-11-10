//! #184 — enrollment token store.
//!
//! On-disk JSON: `{ "tokens": [ { token_hash, host_id, expires_at, used_at } ] }`.
//! Tokens are 32 random bytes (OsRng), URL-safe base64; only `blake3(plaintext)`
//! hex is stored — the plaintext is returned once by the CLI and never persisted.
//!
//! Single-use is enforced by stamping `used_at`. The read-modify-write is
//! protected by a cross-process advisory flock (see `lock.rs`) so the CLI's
//! `issue()` and the server's `check`/`mark_used` can't lose a write. Writes are
//! atomic (tmp+rename) preserving 0600.
//!
//! The HTTP mint (`issue_capped`) also prunes under that flock: an entry spent or
//! expired more than [`RETAIN`] ago is dropped, and the file may hold at most
//! `max_tokens` entries (unspent, plus spent or expired within the last hour, and
//! counting tokens the CLI made). Only entries `verdict` already refuses are
//! removed, so a removed token can only turn a denial's reason into `not_found`,
//! never grant one. The server's own clock decides: a step forward of more than an
//! hour at the moment of a mint can drop a token that is still live in real time,
//! which the host then sees as a refusal. The CLI neither prunes nor is capped.
//!
//! The handler splits redeem into `check` (verify only) and `mark_used` (stamp)
//! so the spec's commit order holds: validate → reserve(token) → sign → … . In
//! practice the handler RESERVES before signing by calling `mark_used` up front;
//! `check` is the pre-validate. Both take the flock.

use super::lock::FileLock;
use serde::{Deserialize, Serialize};
use std::path::Path;
use time::OffsetDateTime;

/// How long a spent or expired entry stays in the file before a mint drops it.
pub const RETAIN: time::Duration = time::Duration::hours(1);

/// Why `issue_capped` made no token.
#[derive(Debug, PartialEq, Eq)]
pub enum MintRefused {
    /// The host already has an unspent, unexpired token (whoever made it).
    Outstanding,
    /// The file already holds `max_tokens` entries after pruning.
    Full,
    Io(String),
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TokenStore {
    pub tokens: Vec<TokenEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenEntry {
    /// `blake3(plaintext).to_hex()`.
    pub token_hash: String,
    pub host_id: String,
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option", default)]
    pub used_at: Option<OffsetDateTime>,
}

impl TokenEntry {
    /// Spent or expired more than [`RETAIN`] ago.
    fn prunable(&self, now: OffsetDateTime) -> bool {
        self.used_at.is_some_and(|u| u + RETAIN < now) || self.expires_at + RETAIN < now
    }

    /// Unused, unexpired and bound to `host_id`, checked in this order so the
    /// most specific reason comes back for logging.
    pub fn verdict(&self, host_id: &str, now: OffsetDateTime) -> Result<(), RedeemErr> {
        if self.used_at.is_some() {
            return Err(RedeemErr::Used);
        }
        if now > self.expires_at {
            return Err(RedeemErr::Expired);
        }
        if self.host_id != host_id {
            return Err(RedeemErr::HostMismatch);
        }
        Ok(())
    }
}

/// Redeem failure reasons. The HTTP layer collapses Expired/Used/HostMismatch/
/// NotFound into a single generic `enrollment_denied` (no token-state leak); the
/// specific reason is logged/audited internally.
#[derive(Debug, PartialEq, Eq)]
pub enum RedeemErr {
    NotFound,
    Expired,
    Used,
    HostMismatch,
    Io(String),
}

impl std::fmt::Display for RedeemErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RedeemErr::NotFound => write!(f, "not_found"),
            RedeemErr::Expired => write!(f, "expired"),
            RedeemErr::Used => write!(f, "used"),
            RedeemErr::HostMismatch => write!(f, "host_mismatch"),
            RedeemErr::Io(e) => write!(f, "io: {e}"),
        }
    }
}

/// blake3 hex digest of a plaintext token.
pub fn hash_token(plaintext: &str) -> String {
    blake3::hash(plaintext.as_bytes()).to_hex().to_string()
}

impl TokenStore {
    fn read(path: &Path) -> Result<TokenStore, RedeemErr> {
        match std::fs::read(path) {
            Ok(b) => serde_json::from_slice(&b)
                .map_err(|e| RedeemErr::Io(format!("parse token store: {e}"))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(TokenStore::default()),
            Err(e) => Err(RedeemErr::Io(format!("read token store: {e}"))),
        }
    }

    /// Atomic write (tmp in same dir + rename), 0600.
    fn write_atomic(path: &Path, store: &TokenStore) -> Result<(), RedeemErr> {
        let bytes = serde_json::to_vec_pretty(store)
            .map_err(|e| RedeemErr::Io(format!("serialize: {e}")))?;
        write_atomic_0600(path, &bytes).map_err(|e| RedeemErr::Io(format!("write: {e}")))
    }

    /// Issue a fresh token for `host_id` with the given expiry. Returns the
    /// plaintext (URL-safe base64) ONCE; only the hash is stored. Takes the
    /// cross-process flock for the whole read-modify-write.
    pub fn issue(
        path: &Path,
        host_id: &str,
        expires_at: OffsetDateTime,
        _now: OffsetDateTime,
    ) -> Result<String, RedeemErr> {
        let _lock =
            FileLock::acquire_exclusive(path).map_err(|e| RedeemErr::Io(format!("lock: {e}")))?;
        let plaintext = generate_token();
        let mut store = Self::read(path)?;
        store.tokens.push(TokenEntry {
            token_hash: hash_token(&plaintext),
            host_id: host_id.to_string(),
            expires_at,
            used_at: None,
        });
        Self::write_atomic(path, &store)?;
        Ok(plaintext)
    }

    /// The HTTP mint: under the flock, prune, refuse when the host has a live token
    /// or the file is full, else add one entry. Nothing is written on a refusal.
    pub fn issue_capped(
        path: &Path,
        host_id: &str,
        expires_at: OffsetDateTime,
        now: OffsetDateTime,
        max_tokens: usize,
    ) -> Result<String, MintRefused> {
        let io = |e: RedeemErr| MintRefused::Io(e.to_string());
        let _lock =
            FileLock::acquire_exclusive(path).map_err(|e| MintRefused::Io(format!("lock: {e}")))?;
        let mut store = Self::read(path).map_err(io)?;
        store.tokens.retain(|t| !t.prunable(now));
        if store.tokens.iter().any(|t| t.verdict(host_id, now).is_ok()) {
            return Err(MintRefused::Outstanding);
        }
        if store.tokens.len() >= max_tokens {
            return Err(MintRefused::Full);
        }
        let plaintext = generate_token();
        store.tokens.push(TokenEntry {
            token_hash: hash_token(&plaintext),
            host_id: host_id.to_string(),
            expires_at,
            used_at: None,
        });
        Self::write_atomic(path, &store).map_err(io)?;
        Ok(plaintext)
    }

    /// Remove the entry of `plaintext` (a mint whose audit line could not be
    /// written). Takes the flock.
    pub fn discard(path: &Path, plaintext: &str) -> Result<(), RedeemErr> {
        let _lock =
            FileLock::acquire_exclusive(path).map_err(|e| RedeemErr::Io(format!("lock: {e}")))?;
        let mut store = Self::read(path)?;
        let hash = hash_token(plaintext);
        store.tokens.retain(|t| t.token_hash != hash);
        Self::write_atomic(path, &store)
    }

    /// Verify a token WITHOUT consuming it: must exist, be unused, unexpired,
    /// and bound to `host_id`. Order of checks intentionally returns the most
    /// specific reason for internal logging. Takes the flock (consistent read).
    pub fn check(
        path: &Path,
        plaintext: &str,
        host_id: &str,
        now: OffsetDateTime,
    ) -> Result<(), RedeemErr> {
        let _lock =
            FileLock::acquire_exclusive(path).map_err(|e| RedeemErr::Io(format!("lock: {e}")))?;
        let store = Self::read(path)?;
        let hash = hash_token(plaintext);
        store
            .tokens
            .iter()
            .find(|t| t.token_hash == hash)
            .ok_or(RedeemErr::NotFound)?
            .verdict(host_id, now)
    }

    /// Durably stamp `used_at` (reserve the token) under the flock. Re-validates
    /// existence + unused so a concurrent stamp can't double-spend. This is the
    /// reserve-before-sign step in the handler's commit order.
    pub fn mark_used(
        path: &Path,
        plaintext: &str,
        host_id: &str,
        now: OffsetDateTime,
    ) -> Result<(), RedeemErr> {
        let _lock =
            FileLock::acquire_exclusive(path).map_err(|e| RedeemErr::Io(format!("lock: {e}")))?;
        let mut store = Self::read(path)?;
        let hash = hash_token(plaintext);
        let entry = store
            .tokens
            .iter_mut()
            .find(|t| t.token_hash == hash)
            .ok_or(RedeemErr::NotFound)?;
        entry.verdict(host_id, now)?;
        entry.used_at = Some(now);
        Self::write_atomic(path, &store)?;
        Ok(())
    }
}

/// 32 bytes OsRng → URL-safe base64 (no padding).
fn generate_token() -> String {
    use rand_core::{OsRng, RngCore};
    let mut b = [0u8; 32];
    OsRng.fill_bytes(&mut b);
    data_encoding::BASE64URL_NOPAD.encode(&b)
}

/// Atomic write via tmp-in-same-dir + rename, mode 0600.
fn write_atomic_0600(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let mut tmp = tempfile::Builder::new()
        .prefix(".tokens-")
        .tempfile_in(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = tmp
            .as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600));
    }
    tmp.write_all(bytes)?;
    tmp.as_file().sync_all()?;
    tmp.persist(path).map_err(std::io::Error::other)?;
    // #184 P2: fsync the PARENT directory so the rename is durable — a crash
    // can't lose the rename and resurrect a used token.
    fsync_parent_dir(dir);
    Ok(())
}

/// Best-effort fsync of a directory entry so a preceding rename is durable.
/// Directory fsync is a no-op / unsupported on some platforms; ignore errors.
fn fsync_parent_dir(dir: &Path) {
    if let Ok(f) = std::fs::File::open(dir) {
        let _ = f.sync_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::Duration;

    fn now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_900_000_000).unwrap()
    }

    #[test]
    fn issue_stores_hash_not_plaintext() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("t.json");
        let now = now();
        let tok = TokenStore::issue(&p, "host-1", now + Duration::hours(1), now).unwrap();
        let disk = std::fs::read_to_string(&p).unwrap();
        assert!(!disk.contains(&tok), "plaintext must never hit disk");
        assert!(disk.contains(&hash_token(&tok)), "hash must be stored");
    }

    #[test]
    fn check_then_mark_used_single_use() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("t.json");
        let now = now();
        let tok = TokenStore::issue(&p, "host-1", now + Duration::hours(1), now).unwrap();
        assert!(TokenStore::check(&p, &tok, "host-1", now).is_ok());
        assert!(TokenStore::mark_used(&p, &tok, "host-1", now).is_ok());
        // reused → Used (both check and mark_used)
        assert_eq!(
            TokenStore::check(&p, &tok, "host-1", now),
            Err(RedeemErr::Used)
        );
        assert_eq!(
            TokenStore::mark_used(&p, &tok, "host-1", now),
            Err(RedeemErr::Used)
        );
    }

    #[test]
    fn expired_token_rejected() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("t.json");
        let now = now();
        let tok = TokenStore::issue(&p, "host-3", now - Duration::seconds(1), now).unwrap();
        assert_eq!(
            TokenStore::check(&p, &tok, "host-3", now),
            Err(RedeemErr::Expired)
        );
    }

    #[test]
    fn host_mismatch_rejected() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("t.json");
        let now = now();
        let tok = TokenStore::issue(&p, "host-2", now + Duration::hours(1), now).unwrap();
        assert_eq!(
            TokenStore::check(&p, &tok, "host-X", now),
            Err(RedeemErr::HostMismatch)
        );
    }

    #[test]
    fn unknown_token_not_found() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("t.json");
        let now = now();
        let _ = TokenStore::issue(&p, "host-1", now + Duration::hours(1), now).unwrap();
        assert_eq!(
            TokenStore::check(&p, "bogus", "host-1", now),
            Err(RedeemErr::NotFound)
        );
    }

    fn put(p: &Path, entries: &[(&str, OffsetDateTime, Option<OffsetDateTime>)]) {
        let store = TokenStore {
            tokens: entries
                .iter()
                .map(|(h, e, u)| TokenEntry {
                    token_hash: (*h).into(),
                    host_id: (*h).into(),
                    expires_at: *e,
                    used_at: *u,
                })
                .collect(),
        };
        TokenStore::write_atomic(p, &store).unwrap();
    }

    fn hashes(p: &Path) -> Vec<String> {
        let mut v: Vec<_> = TokenStore::read(p)
            .unwrap()
            .tokens
            .into_iter()
            .map(|t| t.token_hash)
            .collect();
        v.sort();
        v
    }

    #[test]
    fn issue_capped_prunes_only_what_verdict_refuses_and_keeps_the_rest() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("t.json");
        let n = now();
        let (m59, m61) = (Duration::minutes(59), Duration::minutes(61));
        put(
            &p,
            &[
                ("live", n + Duration::hours(1), None),
                ("spent59", n + Duration::hours(1), Some(n - m59)),
                ("spent61", n + Duration::hours(1), Some(n - m61)),
                ("expired59", n - m59, None),
                ("expired61", n - m61, None),
            ],
        );
        let tok = TokenStore::issue_capped(&p, "new", n + Duration::hours(1), n, 100).unwrap();
        let mut want = vec![
            "live".to_string(),
            "spent59".into(),
            "expired59".into(),
            hash_token(&tok),
        ];
        want.sort();
        assert_eq!(hashes(&p), want);
        // the survivors are still judged as before
        assert_eq!(
            TokenStore::check(&p, "unknown", "live", n),
            Err(RedeemErr::NotFound)
        );
    }

    #[test]
    fn issue_capped_cap_counts_every_entry_and_a_refusal_writes_nothing() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("t.json");
        let n = now();
        TokenStore::issue(&p, "cli-made", n + Duration::hours(1), n).unwrap();
        TokenStore::issue_capped(&p, "a", n + Duration::hours(1), n, 3).unwrap();
        TokenStore::issue_capped(&p, "b", n + Duration::hours(1), n, 3).unwrap();
        let before = std::fs::read(&p).unwrap();
        assert_eq!(
            TokenStore::issue_capped(&p, "c", n + Duration::hours(1), n, 3),
            Err(MintRefused::Full)
        );
        assert_eq!(std::fs::read(&p).unwrap(), before, "no new bytes");
        // an hour later the two expired entries are gone and room is back
        let later = n + Duration::hours(2) + Duration::minutes(1);
        TokenStore::issue_capped(&p, "c", later + Duration::hours(1), later, 3).unwrap();
        assert_eq!(TokenStore::read(&p).unwrap().tokens.len(), 1);
    }

    #[test]
    fn issue_capped_refuses_a_second_live_token_for_one_host_whoever_made_the_first() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("t.json");
        let n = now();
        let cli = TokenStore::issue(&p, "h", n + Duration::hours(1), n).unwrap();
        assert_eq!(
            TokenStore::issue_capped(&p, "h", n + Duration::hours(1), n, 10),
            Err(MintRefused::Outstanding)
        );
        // other hosts are unaffected
        TokenStore::issue_capped(&p, "other", n + Duration::hours(1), n, 10).unwrap();
        // spent without a certificate: a new token is allowed
        TokenStore::mark_used(&p, &cli, "h", n).unwrap();
        TokenStore::issue_capped(&p, "h", n + Duration::hours(1), n, 10).unwrap();
        // expired: allowed too
        let p2 = d.path().join("t2.json");
        TokenStore::issue(&p2, "h", n - Duration::seconds(1), n).unwrap();
        TokenStore::issue_capped(&p2, "h", n + Duration::hours(1), n, 10).unwrap();
    }

    #[test]
    fn discard_removes_exactly_one_entry() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("t.json");
        let n = now();
        let a = TokenStore::issue_capped(&p, "a", n + Duration::hours(1), n, 10).unwrap();
        let b = TokenStore::issue_capped(&p, "b", n + Duration::hours(1), n, 10).unwrap();
        TokenStore::discard(&p, &a).unwrap();
        assert_eq!(hashes(&p), vec![hash_token(&b)]);
    }

    /// The flock is a no-op off unix (`lock.rs`), so only there do writers exclude each other.
    #[cfg(unix)]
    #[test]
    fn issue_capped_cli_issue_and_redeem_lose_nothing_under_threads() {
        use std::sync::Arc;
        let d = tempfile::tempdir().unwrap();
        let p = Arc::new(d.path().join("t.json"));
        let n = now();
        let seed = TokenStore::issue(&p, "redeemed", n + Duration::hours(1), n).unwrap();
        let mut joins = Vec::new();
        for t in 0..8 {
            let pa = p.clone();
            joins.push(std::thread::spawn(move || {
                (0..5)
                    .map(|i| {
                        let h = format!("mint-{t}-{i}");
                        let tok =
                            TokenStore::issue_capped(&pa, &h, n + Duration::hours(1), n, 1000)
                                .unwrap();
                        (h, tok)
                    })
                    .collect::<Vec<_>>()
            }));
            let pb = p.clone();
            joins.push(std::thread::spawn(move || {
                (0..5)
                    .map(|i| {
                        let h = format!("cli-{t}-{i}");
                        let tok = TokenStore::issue(&pb, &h, n + Duration::hours(1), n).unwrap();
                        (h, tok)
                    })
                    .collect::<Vec<_>>()
            }));
        }
        let redeem = {
            let p = p.clone();
            std::thread::spawn(move || {
                TokenStore::mark_used(&p, &seed, "redeemed", n).unwrap();
            })
        };
        let mut made: Vec<(String, String)> =
            joins.into_iter().flat_map(|j| j.join().unwrap()).collect();
        redeem.join().unwrap();
        assert_eq!(made.len(), 80);
        for (h, tok) in made.drain(..) {
            assert!(TokenStore::check(&p, &tok, &h, n).is_ok(), "{h} was lost");
        }
        assert_eq!(TokenStore::read(&p).unwrap().tokens.len(), 81);
    }
}
