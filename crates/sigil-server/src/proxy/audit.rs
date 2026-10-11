//! Signed append-only audit stream for proxy management (`proxy-management-audit.jsonl`,
//! control-plane §2.2). Same mechanism as `enroll/audit.rs` (ed25519 over
//! canonical JSON, blake3 hash chain, fsync per line, the server audit key)
//! in a separate stream with its own record shape. The signed record carries
//! `stream: "proxy-mgmt"` for domain separation from the other streams.
//!
//! The record is appended BEFORE the effect. An append error makes the
//! handler answer 503 without any effect. Records never carry tokens,
//! verifiers or config bodies.
//!
//! Boot (`MgmtAudit::open`) verifies the whole file: sequence, hash chain,
//! content hash and (for records signed by this server's key) the signature.
//! Any problem refuses boot, with one exception (DECIDED): an unterminated
//! FINAL line is a torn append from a crash. It is moved byte for byte to
//! `<file>.torn.<epoch-seconds>` (error-level log) and the chain continues
//! from the last complete record. The file is opened with O_NOFOLLOW and must
//! be owner-only and owned by the server user.

use crate::audit_key::AuditKey;
use anyhow::{bail, Context, Result};
use ed25519_dalek::{Signer, Verifier};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sigil_core::audit::GENESIS_PREV_HASH;
use sigil_core::policy::canonical::to_canonical_bytes;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

pub const AUDIT_FILE: &str = "proxy-management-audit.jsonl";
pub const ASSERTED: &str = "asserted_by_caller";
pub const STREAM: &str = "proxy-mgmt";

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MgmtAuditRecord {
    pub v: u8,
    /// Domain separation: always [`STREAM`].
    pub stream: String,
    pub seq: u64,
    pub occurred_at: String,
    pub request_id: String,
    /// The action of the route that was called (`proxy.register`,
    /// `proxy.fingerprint_register`, `proxy.disable`, `proxy.enable`,
    /// `proxy.retire`), or `proxy.fingerprint_promote` for the server's own
    /// promotion on first use of `fp_next`.
    pub action: String,
    /// Empty when the request named none (or none valid).
    pub proxy_id: String,
    /// `ok`, `persist_failed`, or a fixed error code string (`unauthorized`,
    /// `forbidden`, `already_exists`, ...).
    pub result: String,
    pub http_status: u16,
    /// Fixed internal sub-reason (auth denials, promotion); never request data.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// How many identical auth denials this record stands for (rate-limited
    /// denials are coalesced per caller and reason).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to_state: Option<String>,
    /// Reserved for config PUT (S3).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_revision: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to_revision: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_hash: Option<String>,
    /// The fingerprint a registration or promotion is about (public data).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_fingerprint: Option<String>,
    /// Fingerprints dropped by a fingerprint replace on a disabled entry
    /// (comma-separated: old current, old next).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replaced_fingerprint: Option<String>,
    /// VERIFIED: the management key that authenticated. Empty if none did.
    pub management_key_id: String,
    pub scope: String,
    /// VERIFIED: the management-caller cert (blake3 of the leaf DER).
    pub caller_fingerprint: String,
    /// ASSERTED by the caller (header), never used for authorization.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_by_assurance: Option<String>,
    pub prev_hash: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SignedMgmtRecord {
    #[serde(flatten)]
    pub record: MgmtAuditRecord,
    pub hash: String,
    pub sig: String,
    pub pubkey_id: String,
}

/// The caller-supplied part of a record; `seq`, `prev_hash`, `v` and `stream`
/// are added.
#[derive(Clone, Debug, Default)]
pub struct AuditEntry {
    pub request_id: String,
    pub action: String,
    pub proxy_id: String,
    pub result: String,
    pub http_status: u16,
    pub reason: Option<String>,
    pub count: Option<u32>,
    pub from_state: Option<String>,
    pub to_state: Option<String>,
    pub subject_fingerprint: Option<String>,
    pub replaced_fingerprint: Option<String>,
    pub management_key_id: String,
    pub scope: String,
    pub caller_fingerprint: String,
    pub requested_by: Option<String>,
}

#[derive(Debug)]
pub enum AuditAppendError {
    Io(std::io::Error),
    Canonical(String),
    Chain(String),
}

impl std::fmt::Display for AuditAppendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuditAppendError::Io(e) => write!(f, "io: {e}"),
            AuditAppendError::Canonical(e) => write!(f, "canonical: {e}"),
            AuditAppendError::Chain(e) => write!(f, "chain: {e}"),
        }
    }
}

/// Owner-only, owned-by-us, regular-file check on an open fd.
fn check_meta(meta: &std::fs::Metadata) -> std::io::Result<()> {
    let bad = |m: &str| std::io::Error::new(std::io::ErrorKind::PermissionDenied, m.to_string());
    if !meta.is_file() {
        return Err(bad("audit path is not a regular file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(bad("audit file must be owner-only"));
        }
        // SAFETY: geteuid has no preconditions.
        if meta.uid() != unsafe { libc::geteuid() } {
            return Err(bad("audit file must be owned by the server user"));
        }
    }
    Ok(())
}

fn open_checked(path: &Path, append: bool) -> std::io::Result<std::fs::File> {
    let mut o = std::fs::OpenOptions::new();
    if append {
        o.create(true).append(true);
    } else {
        o.read(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.custom_flags(libc::O_NOFOLLOW);
        if append {
            o.mode(0o600);
        }
    }
    let f = o.open(path)?;
    check_meta(&f.metadata()?)?;
    Ok(f)
}

/// Whole file, or `None` when it does not exist.
fn read_file(path: &Path) -> std::io::Result<Option<Vec<u8>>> {
    let mut f = match open_checked(path, false) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let mut b = Vec::new();
    f.read_to_end(&mut b)?;
    Ok(Some(b))
}

/// Length of the prefix that ends with the last `\n`.
fn complete_len(bytes: &[u8]) -> usize {
    bytes.iter().rposition(|b| *b == b'\n').map_or(0, |i| i + 1)
}

fn lines(complete: &[u8]) -> impl Iterator<Item = &[u8]> {
    complete
        .split(|b| *b == b'\n')
        .filter(|l| !l.iter().all(u8::is_ascii_whitespace))
}

/// Verify a whole (newline-terminated) file. Returns `(next_seq, prev_hash)`.
fn verify_chain(complete: &[u8], key: &AuditKey) -> Result<(u64, String)> {
    let vk = key.signing_key.verifying_key();
    let (mut seq, mut prev) = (0u64, GENESIS_PREV_HASH.to_string());
    for (i, line) in lines(complete).enumerate() {
        let n = i + 1;
        let rec: SignedMgmtRecord =
            serde_json::from_slice(line).with_context(|| format!("audit line {n}: malformed"))?;
        if rec.record.stream != STREAM {
            bail!("audit line {n}: wrong stream");
        }
        if rec.record.seq != seq {
            bail!("audit line {n}: sequence break");
        }
        if rec.record.prev_hash != prev {
            bail!("audit line {n}: hash chain broken");
        }
        let canon = to_canonical_bytes(&rec.record)
            .map_err(|e| anyhow::anyhow!("audit line {n}: canonical: {e}"))?;
        if blake3::hash(&canon).to_hex().to_string() != rec.hash {
            bail!("audit line {n}: content hash mismatch");
        }
        if rec.pubkey_id == key.pubkey_id {
            let raw = data_encoding::BASE64
                .decode(rec.sig.as_bytes())
                .map_err(|_| anyhow::anyhow!("audit line {n}: bad signature encoding"))?;
            let arr: [u8; 64] = raw
                .as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("audit line {n}: bad signature length"))?;
            vk.verify(&canon, &ed25519_dalek::Signature::from_bytes(&arr))
                .map_err(|_| anyhow::anyhow!("audit line {n}: signature invalid"))?;
        } else {
            tracing::warn!(
                line = n,
                "audit record signed by another key; chain and hash checked only"
            );
        }
        prev = rec.hash;
        seq += 1;
    }
    Ok((seq, prev))
}

#[derive(Deserialize)]
struct Tail {
    seq: u64,
    hash: String,
}

/// `(next_seq, prev_hash)` from the tail of the file at runtime. An
/// unterminated tail is refused (appending would glue onto it).
fn resume_chain(path: &Path) -> Result<(u64, String), AuditAppendError> {
    let Some(bytes) = read_file(path).map_err(AuditAppendError::Io)? else {
        return Ok((0, GENESIS_PREV_HASH.to_string()));
    };
    if bytes.last().is_some_and(|b| *b != b'\n') {
        return Err(AuditAppendError::Chain(
            "unterminated tail line (restart recovers it)".into(),
        ));
    }
    let Some(last) = lines(&bytes).last() else {
        return Ok((0, GENESIS_PREV_HASH.to_string()));
    };
    let t: Tail = serde_json::from_slice(last)
        .map_err(|_| AuditAppendError::Chain("unparsable tail line".into()))?;
    Ok((t.seq + 1, t.hash))
}

pub struct MgmtAudit {
    path: PathBuf,
    key: AuditKey,
    /// Serializes appends and caches `(next_seq, prev_hash)`; reset on error.
    chain: Mutex<Option<(u64, String)>>,
}

impl MgmtAudit {
    /// Boot: verify the existing file, recover a torn final line, or fail.
    pub fn open(dir: &Path, key: AuditKey) -> Result<Self> {
        let path = dir.join(AUDIT_FILE);
        let ctx = || format!("proxy management audit {}", path.display());
        if let Some(bytes) = read_file(&path).with_context(ctx)? {
            let keep = complete_len(&bytes);
            verify_chain(&bytes[..keep], &key).with_context(ctx)?;
            if keep < bytes.len() {
                let torn = move_torn_tail(&path, &bytes, keep).with_context(ctx)?;
                tracing::error!(
                    moved_to = %torn.display(),
                    bytes = bytes.len() - keep,
                    "ALERT proxy management audit had an unterminated final line (torn append); moved aside, chain continues from the last complete record"
                );
            }
        }
        Ok(Self {
            path,
            key,
            chain: Mutex::new(None),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn pubkey_id(&self) -> &str {
        &self.key.pubkey_id
    }

    /// Build, sign and durably append one record.
    pub fn append(&self, e: AuditEntry) -> Result<SignedMgmtRecord, AuditAppendError> {
        let mut g = self.chain.lock();
        let r = self.append_locked(&mut g, e);
        if r.is_err() {
            *g = None;
        }
        r
    }

    fn append_locked(
        &self,
        chain: &mut Option<(u64, String)>,
        e: AuditEntry,
    ) -> Result<SignedMgmtRecord, AuditAppendError> {
        let (seq, prev_hash) = match chain.take() {
            Some(c) => c,
            None => resume_chain(&self.path)?,
        };
        let occurred_at = time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        let record = MgmtAuditRecord {
            v: 1,
            stream: STREAM.to_string(),
            seq,
            occurred_at,
            request_id: e.request_id,
            action: e.action,
            proxy_id: e.proxy_id,
            result: e.result,
            http_status: e.http_status,
            reason: e.reason,
            count: e.count,
            from_state: e.from_state,
            to_state: e.to_state,
            from_revision: None,
            to_revision: None,
            config_hash: None,
            subject_fingerprint: e.subject_fingerprint,
            replaced_fingerprint: e.replaced_fingerprint,
            management_key_id: e.management_key_id,
            scope: e.scope,
            caller_fingerprint: e.caller_fingerprint,
            requested_by_assurance: e.requested_by.as_ref().map(|_| ASSERTED.to_string()),
            requested_by: e.requested_by,
            prev_hash,
        };
        let canonical =
            to_canonical_bytes(&record).map_err(|e| AuditAppendError::Canonical(e.to_string()))?;
        let hash = blake3::hash(&canonical).to_hex().to_string();
        let sig = self.key.signing_key.sign(&canonical);
        let signed = SignedMgmtRecord {
            record,
            hash,
            sig: data_encoding::BASE64.encode(&sig.to_bytes()),
            pubkey_id: self.key.pubkey_id.clone(),
        };
        let mut line =
            serde_json::to_vec(&signed).map_err(|e| AuditAppendError::Canonical(e.to_string()))?;
        line.push(b'\n');

        let mut f = open_checked(&self.path, true).map_err(AuditAppendError::Io)?;
        f.write_all(&line).map_err(AuditAppendError::Io)?;
        f.sync_all().map_err(AuditAppendError::Io)?;
        *chain = Some((signed.record.seq + 1, signed.hash.clone()));
        Ok(signed)
    }

    /// Records with `seq >= cursor`, at most `limit`. The second value is the
    /// cursor of the next page (`None` at the end). An unterminated final line
    /// (an append in flight) is skipped. This scans from the start of the file
    /// on every call; an index by seq is a possible later optimisation.
    pub fn read(&self, cursor: u64, limit: usize) -> Result<(Vec<SignedMgmtRecord>, Option<u64>)> {
        let Some(bytes) = read_file(&self.path)? else {
            return Ok((Vec::new(), None));
        };
        let mut out = Vec::new();
        let mut next = None;
        for line in lines(&bytes[..complete_len(&bytes)]) {
            let rec: SignedMgmtRecord = match serde_json::from_slice(line) {
                Ok(r) => r,
                Err(_) => bail!("corrupt audit line"),
            };
            if rec.record.seq < cursor {
                continue;
            }
            if out.len() == limit {
                next = Some(rec.record.seq);
                break;
            }
            out.push(rec);
        }
        Ok((out, next))
    }
}

/// Copy the torn tail to `<file>.torn.<epoch>` (never overwriting), then cut
/// the audit file back to its last complete line.
fn move_torn_tail(path: &Path, bytes: &[u8], keep: usize) -> Result<PathBuf> {
    let epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let mut torn_path = None;
    for n in 0..100u32 {
        let mut name = path.as_os_str().to_owned();
        name.push(format!(".torn.{epoch}"));
        if n > 0 {
            name.push(format!(".{n}"));
        }
        let p = PathBuf::from(name);
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        match o.open(&p) {
            Ok(mut f) => {
                f.write_all(&bytes[keep..])?;
                f.sync_all()?;
                torn_path = Some(p);
                break;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e.into()),
        }
    }
    let torn_path = torn_path.context("no free .torn file name")?;
    let f = std::fs::OpenOptions::new().write(true).open(path)?;
    f.set_len(keep as u64)?;
    f.sync_all()?;
    Ok(torn_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(action: &str) -> AuditEntry {
        AuditEntry {
            request_id: "r".into(),
            action: action.into(),
            proxy_id: "px".into(),
            result: "ok".into(),
            http_status: 200,
            management_key_id: "k".into(),
            scope: "identity".into(),
            caller_fingerprint: "cf".into(),
            requested_by: Some("alice".into()),
            ..Default::default()
        }
    }

    fn open(d: &Path) -> Result<MgmtAudit> {
        MgmtAudit::open(d, AuditKey::load_or_create(d).unwrap())
    }

    #[test]
    fn chain_signature_cursor_and_resume() {
        let d = tempfile::tempdir().unwrap();
        let a = open(d.path()).unwrap();
        let r0 = a.append(entry("proxy.register")).unwrap();
        let r1 = a.append(entry("proxy.disable")).unwrap();
        assert_eq!(r0.record.seq, 0);
        assert_eq!(r0.record.stream, STREAM);
        assert_eq!(r0.record.prev_hash, GENESIS_PREV_HASH);
        assert_eq!(r1.record.prev_hash, r0.hash);
        assert_eq!(r0.record.requested_by_assurance.as_deref(), Some(ASSERTED));
        let (p1, n1) = a.read(0, 1).unwrap();
        assert_eq!((p1.len(), n1), (1, Some(1)));
        let (p2, n2) = a.read(1, 10).unwrap();
        assert_eq!((p2.len(), n2), (1, None));
        // A fresh instance verifies the whole file and resumes the chain.
        let b = open(d.path()).unwrap();
        let r2 = b.append(entry("proxy.enable")).unwrap();
        assert_eq!((r2.record.seq, r2.record.prev_hash), (2, r1.hash));
    }

    #[test]
    fn torn_final_line_is_moved_aside_and_chain_continues() {
        let d = tempfile::tempdir().unwrap();
        let a = open(d.path()).unwrap();
        a.append(entry("proxy.register")).unwrap();
        let r1 = a.append(entry("proxy.disable")).unwrap();
        let path = d.path().join(AUDIT_FILE);
        let before = std::fs::read(&path).unwrap();
        let torn = br#"{"v":1,"stream":"proxy-mgmt","seq":2,"occ"#;
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        f.write_all(torn).unwrap();
        drop(f);
        // A reader during the in-flight append skips the partial line.
        assert_eq!(a.read(0, 10).unwrap().0.len(), 2);
        // An append at runtime refuses to glue onto it.
        let a2 = open_no_recover(d.path());
        assert!(a2.append(entry("proxy.enable")).is_err());

        let b = open(d.path()).unwrap();
        assert_eq!(
            std::fs::read(&path).unwrap(),
            before,
            "cut back to the last full line"
        );
        let moved: Vec<_> = std::fs::read_dir(d.path())
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.to_string_lossy().contains(".jsonl.torn."))
            .collect();
        assert_eq!(moved.len(), 1);
        assert_eq!(std::fs::read(&moved[0]).unwrap(), torn, "byte for byte");
        let r2 = b.append(entry("proxy.enable")).unwrap();
        assert_eq!((r2.record.seq, r2.record.prev_hash), (2, r1.hash));
    }

    /// An instance that skipped boot recovery (to exercise the runtime guard).
    fn open_no_recover(d: &Path) -> MgmtAudit {
        MgmtAudit {
            path: d.join(AUDIT_FILE),
            key: AuditKey::load_or_create(d).unwrap(),
            chain: Mutex::new(None),
        }
    }

    #[test]
    fn other_corruption_refuses_boot() {
        let d = tempfile::tempdir().unwrap();
        let a = open(d.path()).unwrap();
        a.append(entry("proxy.register")).unwrap();
        a.append(entry("proxy.disable")).unwrap();
        let path = d.path().join(AUDIT_FILE);
        let good = std::fs::read_to_string(&path).unwrap();
        // Malformed complete line.
        std::fs::write(&path, format!("{good}{{garbage\n")).unwrap();
        assert!(open(d.path()).is_err());
        // Tampered content (hash mismatch).
        std::fs::write(&path, good.replace("\"proxy.disable\"", "\"proxy.retire\"")).unwrap();
        assert!(open(d.path()).is_err());
        // Valid hash but forged signature: recompute hash, keep old sig.
        let mut lines: Vec<serde_json::Value> = good
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        lines[1]["result"] = "forged".into();
        let rec: MgmtAuditRecord = serde_json::from_value(lines[1].clone()).unwrap();
        lines[1]["hash"] = blake3::hash(&to_canonical_bytes(&rec).unwrap())
            .to_hex()
            .to_string()
            .into();
        let forged: String = lines.iter().map(|l| format!("{l}\n")).collect();
        std::fs::write(&path, forged).unwrap();
        let e = open(d.path()).err().expect("refused");
        assert!(format!("{e:#}").contains("signature invalid"), "{e:#}");
        // Broken chain (first line removed).
        let second = good.lines().nth(1).unwrap();
        std::fs::write(&path, format!("{second}\n")).unwrap();
        assert!(open(d.path()).is_err());
        // Wrong permissions / symlink.
        std::fs::write(&path, &good).unwrap();
        assert!(open(d.path()).is_ok());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(open(d.path()).is_err());
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            let real = d.path().join("real.jsonl");
            std::fs::rename(&path, &real).unwrap();
            std::os::unix::fs::symlink(&real, &path).unwrap();
            assert!(open(d.path()).is_err(), "symlink");
        }
    }
}
