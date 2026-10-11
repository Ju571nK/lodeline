//! Signed append-only audit stream for proxy management (`proxy-management-audit.jsonl`,
//! control-plane §2.2). Same mechanism as `enroll/audit.rs` (ed25519 over
//! canonical JSON, blake3 hash chain, fsync per line, the server audit key)
//! in a separate stream with its own record shape.
//!
//! The record is appended BEFORE the effect. An append error makes the
//! handler answer 503 without any effect. A corrupt tail is an error (the
//! enrollment stream restarts at genesis; here that would hide tampering).
//! Records never carry tokens, verifiers or config bodies.

use crate::audit_key::AuditKey;
use anyhow::{bail, Context, Result};
use ed25519_dalek::Signer;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sigil_core::audit::GENESIS_PREV_HASH;
use sigil_core::policy::canonical::to_canonical_bytes;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

pub const AUDIT_FILE: &str = "proxy-management-audit.jsonl";
pub const ASSERTED: &str = "asserted_by_caller";

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MgmtAuditRecord {
    pub v: u8,
    pub seq: u64,
    pub occurred_at: String,
    pub request_id: String,
    /// `proxy.register`, `proxy.fingerprint_register`, `proxy.fingerprint_promote`,
    /// `proxy.disable`, `proxy.enable`, `proxy.retire`, or `auth.denied`.
    pub action: String,
    /// Empty when the request named none (or none valid).
    pub proxy_id: String,
    /// `ok` or a fixed error code string.
    pub result: String,
    pub http_status: u16,
    /// Fixed internal sub-reason for `auth.denied`; never request data.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
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

/// The caller-supplied part of a record; `seq`, `prev_hash` and `v` are added.
#[derive(Clone, Debug, Default)]
pub struct AuditEntry {
    pub request_id: String,
    pub action: String,
    pub proxy_id: String,
    pub result: String,
    pub http_status: u16,
    pub reason: Option<String>,
    pub from_state: Option<String>,
    pub to_state: Option<String>,
    pub subject_fingerprint: Option<String>,
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

#[derive(Deserialize)]
struct Tail {
    seq: u64,
    hash: String,
}

fn resume_chain(path: &Path) -> Result<(u64, String), AuditAppendError> {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok((0, GENESIS_PREV_HASH.to_string()))
        }
        Err(e) => return Err(AuditAppendError::Io(e)),
    };
    let Some(last) = content.lines().rfind(|l| !l.trim().is_empty()) else {
        return Ok((0, GENESIS_PREV_HASH.to_string()));
    };
    let t: Tail = serde_json::from_str(last)
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
    /// Boot check: the existing chain tail must be readable.
    pub fn open(dir: &Path, key: AuditKey) -> Result<Self> {
        let path = dir.join(AUDIT_FILE);
        resume_chain(&path)
            .map_err(|e| anyhow::anyhow!("{e}"))
            .with_context(|| format!("proxy management audit {}", path.display()))?;
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
            seq,
            occurred_at,
            request_id: e.request_id,
            action: e.action,
            proxy_id: e.proxy_id,
            result: e.result,
            http_status: e.http_status,
            reason: e.reason,
            from_state: e.from_state,
            to_state: e.to_state,
            from_revision: None,
            to_revision: None,
            config_hash: None,
            subject_fingerprint: e.subject_fingerprint,
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

        let mut opts = std::fs::OpenOptions::new();
        opts.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&self.path).map_err(AuditAppendError::Io)?;
        f.write_all(&line).map_err(AuditAppendError::Io)?;
        f.sync_all().map_err(AuditAppendError::Io)?;
        *chain = Some((signed.record.seq + 1, signed.hash.clone()));
        Ok(signed)
    }

    /// Records with `seq >= cursor`, at most `limit`. The second value is the
    /// cursor of the next page (`None` at the end).
    pub fn read(&self, cursor: u64, limit: usize) -> Result<(Vec<SignedMgmtRecord>, Option<u64>)> {
        let f = match std::fs::File::open(&self.path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((Vec::new(), None)),
            Err(e) => return Err(e.into()),
        };
        let mut out = Vec::new();
        let mut next = None;
        for line in std::io::BufReader::new(f).lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let rec: SignedMgmtRecord = match serde_json::from_str(&line) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier;

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

    #[test]
    fn chain_signature_cursor_and_resume() {
        let d = tempfile::tempdir().unwrap();
        let key = AuditKey::load_or_create(d.path()).unwrap();
        let a = MgmtAudit::open(d.path(), key).unwrap();
        let r0 = a.append(entry("proxy.register")).unwrap();
        let r1 = a.append(entry("proxy.disable")).unwrap();
        assert_eq!(r0.record.seq, 0);
        assert_eq!(r0.record.prev_hash, GENESIS_PREV_HASH);
        assert_eq!(r1.record.prev_hash, r0.hash);
        assert_eq!(r0.record.requested_by_assurance.as_deref(), Some(ASSERTED));
        // Signature verifies over the canonical record.
        let canon = to_canonical_bytes(&r1.record).unwrap();
        assert_eq!(blake3::hash(&canon).to_hex().to_string(), r1.hash);
        let raw = data_encoding::BASE64.decode(r1.sig.as_bytes()).unwrap();
        let sig = ed25519_dalek::Signature::from_bytes(&raw.as_slice().try_into().unwrap());
        a.key
            .signing_key
            .verifying_key()
            .verify(&canon, &sig)
            .unwrap();
        // Paging.
        let (p1, n1) = a.read(0, 1).unwrap();
        assert_eq!((p1.len(), n1), (1, Some(1)));
        let (p2, n2) = a.read(1, 10).unwrap();
        assert_eq!((p2.len(), n2), (1, None));
        // A fresh instance resumes the chain from disk.
        let key2 = AuditKey::load_or_create(d.path()).unwrap();
        let b = MgmtAudit::open(d.path(), key2).unwrap();
        let r2 = b.append(entry("proxy.enable")).unwrap();
        assert_eq!((r2.record.seq, r2.record.prev_hash), (2, r1.hash));
    }

    #[test]
    fn corrupt_tail_refuses() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join(AUDIT_FILE), b"{garbage\n").unwrap();
        let key = AuditKey::load_or_create(d.path()).unwrap();
        assert!(MgmtAudit::open(d.path(), key).is_err());
    }
}
