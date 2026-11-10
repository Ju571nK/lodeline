//! #184 — signed enrollment audit log (`enrollment-audit.jsonl`).
//!
//! FAIL-CLOSED: if the signed append fails, the handler returns 500 and does NOT
//! return the cert. Each line is an ed25519-signed record over canonical+blake3
//! bytes, hash-chained to the prior line (same primitives as the audit chain
//! in `lodeline-core::audit`, but a distinct record shape). The appended line is
//! fsync'd before we report success.

use ed25519_dalek::Signer;
use lodeline_core::audit::GENESIS_PREV_HASH;
use lodeline_core::policy::canonical::to_canonical_bytes;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::Path;

/// The signed payload. Carries the enrollment decision plus the fingerprints
/// needed to investigate a mis-issuance.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EnrollmentAuditRecord {
    pub v: u8,
    pub seq: u64,
    pub ts: String,
    pub host_id: String,
    /// `outcome` ∈ {"issued","denied","token_minted"}.
    pub decision: String,
    /// Internal reason (e.g. "ok", "token_expired", "host_mismatch", "sign_failed").
    pub reason: String,
    /// blake3 of the submitted CSR PEM bytes.
    pub csr_fingerprint: String,
    /// blake3 of the issued cert PEM bytes (empty when denied).
    pub cert_fingerprint: String,
    /// Issued cert serial hex (empty when denied).
    pub serial: String,
    /// not_after of the issued cert, rfc3339 (empty when denied). For a
    /// `token_minted` line, the expiry of the minted token.
    pub not_after: String,
    /// Caller (TLS peer) cert fingerprint — blake3 hex of the leaf DER, as
    /// plumbed by `tls_accept::PeerCertAcceptor` (#194). Empty when the
    /// request carried no peer identity (plain-HTTP dev mode).
    pub caller_fingerprint: String,
    /// `token_minted` only: the `key_id` of the verifier entry that authenticated
    /// the mint call. VERIFIED by the server. Absent on every other line, and
    /// then not serialized, so older lines keep their bytes, hash and signature.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub management_key_id: Option<String>,
    /// `token_minted` only: the subject the caller says it acts for. ASSERTED, as
    /// the caller reported it; nothing here checked it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_by_asserted: Option<String>,
    pub prev_hash: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SignedEnrollmentRecord {
    #[serde(flatten)]
    pub record: EnrollmentAuditRecord,
    pub hash: String,
    pub sig: String,
    pub pubkey_id: String,
}

#[derive(Debug)]
pub enum AuditAppendError {
    Io(std::io::Error),
    Canonical(String),
}

impl std::fmt::Display for AuditAppendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuditAppendError::Io(e) => write!(f, "io: {e}"),
            AuditAppendError::Canonical(e) => write!(f, "canonical: {e}"),
        }
    }
}

/// blake3 hex of arbitrary bytes (CSR/cert fingerprints).
pub fn fingerprint(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

/// Resume the chain from an existing jsonl file: returns (next_seq, prev_hash).
/// A missing/empty/corrupt-tail file starts a fresh genesis chain.
fn resume_chain(path: &Path) -> (u64, String) {
    let Ok(content) = std::fs::read_to_string(path) else {
        return (0, GENESIS_PREV_HASH.to_string());
    };
    let last = content.lines().rfind(|l| !l.trim().is_empty());
    match last.and_then(|l| serde_json::from_str::<SignedEnrollmentRecord>(l).ok()) {
        Some(s) => (s.record.seq + 1, s.hash),
        None => (0, GENESIS_PREV_HASH.to_string()),
    }
}

/// Build, sign, and durably append one enrollment record. fsync's the line.
/// FAIL-CLOSED: any error propagates so the handler can 500 and withhold the
/// cert.
#[allow(clippy::too_many_arguments)]
pub fn append(
    path: &Path,
    key: &crate::audit_key::AuditKey,
    host_id: &str,
    decision: &str,
    reason: &str,
    csr_fingerprint: &str,
    cert_fingerprint: &str,
    serial: &str,
    not_after: &str,
    caller_fingerprint: &str,
    ts: &str,
) -> Result<SignedEnrollmentRecord, AuditAppendError> {
    append_record(
        path,
        key,
        EnrollmentAuditRecord {
            v: 1,
            seq: 0,
            ts: ts.to_string(),
            host_id: host_id.to_string(),
            decision: decision.to_string(),
            reason: reason.to_string(),
            csr_fingerprint: csr_fingerprint.to_string(),
            cert_fingerprint: cert_fingerprint.to_string(),
            serial: serial.to_string(),
            not_after: not_after.to_string(),
            caller_fingerprint: caller_fingerprint.to_string(),
            management_key_id: None,
            requested_by_asserted: None,
            prev_hash: String::new(),
        },
    )
}

/// The line of one minted token. The caller holds `en.mint`, like every writer.
#[allow(clippy::too_many_arguments)]
pub fn append_mint(
    path: &Path,
    key: &crate::audit_key::AuditKey,
    host_id: &str,
    token_expires_at: &str,
    caller_fingerprint: &str,
    management_key_id: &str,
    requested_by_asserted: Option<&str>,
    ts: &str,
) -> Result<SignedEnrollmentRecord, AuditAppendError> {
    append_record(
        path,
        key,
        EnrollmentAuditRecord {
            v: 1,
            seq: 0,
            ts: ts.to_string(),
            host_id: host_id.to_string(),
            decision: "token_minted".to_string(),
            reason: "ok".to_string(),
            csr_fingerprint: String::new(),
            cert_fingerprint: String::new(),
            serial: String::new(),
            not_after: token_expires_at.to_string(),
            caller_fingerprint: caller_fingerprint.to_string(),
            management_key_id: Some(management_key_id.to_string()),
            requested_by_asserted: requested_by_asserted.map(str::to_string),
            prev_hash: String::new(),
        },
    )
}

/// Sets `seq` and `prev_hash` from the file, signs and appends.
fn append_record(
    path: &Path,
    key: &crate::audit_key::AuditKey,
    mut record: EnrollmentAuditRecord,
) -> Result<SignedEnrollmentRecord, AuditAppendError> {
    (record.seq, record.prev_hash) = resume_chain(path);
    let canonical =
        to_canonical_bytes(&record).map_err(|e| AuditAppendError::Canonical(e.to_string()))?;
    let hash = blake3::hash(&canonical).to_hex().to_string();
    let sig = key.signing_key.sign(&canonical);
    let signed = SignedEnrollmentRecord {
        record,
        hash,
        sig: data_encoding::BASE64.encode(&sig.to_bytes()),
        pubkey_id: key.pubkey_id.clone(),
    };
    let line =
        serde_json::to_string(&signed).map_err(|e| AuditAppendError::Canonical(e.to_string()))?;
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(AuditAppendError::Io)?;
        }
    }
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(AuditAppendError::Io)?;
    f.write_all(line.as_bytes()).map_err(AuditAppendError::Io)?;
    f.write_all(b"\n").map_err(AuditAppendError::Io)?;
    f.sync_all().map_err(AuditAppendError::Io)?;
    Ok(signed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier;

    fn key(dir: &Path) -> crate::audit_key::AuditKey {
        crate::audit_key::AuditKey::load_or_create(dir).unwrap()
    }

    fn verify_line(signed: &SignedEnrollmentRecord, k: &crate::audit_key::AuditKey) -> bool {
        let canonical = to_canonical_bytes(&signed.record).unwrap();
        if blake3::hash(&canonical).to_hex().to_string() != signed.hash {
            return false;
        }
        let raw = data_encoding::BASE64.decode(signed.sig.as_bytes()).unwrap();
        let arr: [u8; 64] = raw.as_slice().try_into().unwrap();
        let sig = ed25519_dalek::Signature::from_bytes(&arr);
        k.signing_key
            .verifying_key()
            .verify(&canonical, &sig)
            .is_ok()
    }

    #[test]
    fn append_two_chains_and_verifies() {
        let d = tempfile::tempdir().unwrap();
        let k = key(d.path());
        let p = d.path().join("enrollment-audit.jsonl");
        let a = append(
            &p,
            &k,
            "host-1",
            "issued",
            "ok",
            "csrfp",
            "certfp",
            "0a",
            "2026-07-01T00:00:00Z",
            "callerfp",
            "2026-06-23T00:00:00Z",
        )
        .unwrap();
        let b = append(
            &p,
            &k,
            "host-2",
            "denied",
            "token_expired",
            "csrfp2",
            "",
            "",
            "",
            "",
            "2026-06-23T00:01:00Z",
        )
        .unwrap();
        assert_eq!(a.record.seq, 0);
        assert_eq!(a.record.prev_hash, GENESIS_PREV_HASH);
        assert_eq!(a.record.caller_fingerprint, "callerfp");
        assert_eq!(b.record.caller_fingerprint, "");
        assert_eq!(b.record.seq, 1);
        assert_eq!(b.record.prev_hash, a.hash, "chain link");
        assert!(verify_line(&a, &k));
        assert!(verify_line(&b, &k));
        // two physical lines
        let n = std::fs::read_to_string(&p)
            .unwrap()
            .lines()
            .filter(|l| !l.trim().is_empty())
            .count();
        assert_eq!(n, 2);
    }

    #[test]
    fn mint_line_carries_two_extra_fields_and_chains_with_the_others() {
        let d = tempfile::tempdir().unwrap();
        let k = key(d.path());
        let p = d.path().join("enrollment-audit.jsonl");
        let a = append(&p, &k, "h1", "issued", "ok", "c", "f", "0a", "n", "cf", "t").unwrap();
        let m = append_mint(
            &p,
            &k,
            "h2",
            "2026-07-01T00:00:00Z",
            "callerfp",
            "key-1",
            Some("alice"),
            "t2",
        )
        .unwrap();
        let m2 = append_mint(&p, &k, "h3", "x", "callerfp", "key-1", None, "t3").unwrap();
        assert_eq!(m.record.prev_hash, a.hash);
        assert_eq!(m2.record.prev_hash, m.hash);
        assert!(verify_line(&m, &k) && verify_line(&m2, &k));
        let lines: Vec<serde_json::Value> = std::fs::read_to_string(&p)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(lines[1]["decision"], "token_minted");
        assert_eq!(lines[1]["reason"], "ok");
        assert_eq!(lines[1]["not_after"], "2026-07-01T00:00:00Z");
        assert_eq!(lines[1]["management_key_id"], "key-1");
        assert_eq!(lines[1]["requested_by_asserted"], "alice");
        assert_eq!(lines[1]["caller_fingerprint"], "callerfp");
        for f in ["csr_fingerprint", "cert_fingerprint", "serial"] {
            assert_eq!(lines[1][f], "");
        }
        assert!(lines[0].get("management_key_id").is_none());
        assert!(
            lines[2].get("requested_by_asserted").is_none(),
            "absent is skipped"
        );
    }

    /// Exact file bytes for a fixed key and fixed inputs.
    #[test]
    fn golden_lines_for_fixed_key() {
        let d = tempfile::tempdir().unwrap();
        let k = crate::audit_key::AuditKey {
            signing_key: ed25519_dalek::SigningKey::from_bytes(&[0x42; 32]),
            pubkey_id: "lodeline-audit-golden".into(),
            pubkey_b64: String::new(),
        };
        let p = d.path().join("enrollment-audit.jsonl");
        append(
            &p,
            &k,
            "host-1",
            "issued",
            "ok",
            "csrfp",
            "certfp",
            "0a",
            "2026-07-01T00:00:00Z",
            "callerfp",
            "2026-06-23T00:00:00Z",
        )
        .unwrap();
        append(
            &p,
            &k,
            "host-2",
            "denied",
            "token_expired",
            "csrfp2",
            "",
            "",
            "",
            "",
            "2026-06-23T00:01:00Z",
        )
        .unwrap();
        assert_eq!(
            std::fs::read_to_string(&p).unwrap(),
            concat!(
                r#"{"v":1,"seq":0,"ts":"2026-06-23T00:00:00Z","host_id":"host-1","decision":"issued","reason":"ok","csr_fingerprint":"csrfp","cert_fingerprint":"certfp","serial":"0a","not_after":"2026-07-01T00:00:00Z","caller_fingerprint":"callerfp","prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","hash":"3ec6321c36d41c2e05b588c26c7486a3520eecb2f54b19738fd7d56d080b5ac9","sig":"Wr08FYgTx16t0JLLzHTMPX8eDkmYySY5VDoQgAlthdLrbuWfmrAepAv6AuksiX6Q86hTBBe43Bg/oWBypqxPDA==","pubkey_id":"lodeline-audit-golden"}"#,
                "\n",
                r#"{"v":1,"seq":1,"ts":"2026-06-23T00:01:00Z","host_id":"host-2","decision":"denied","reason":"token_expired","csr_fingerprint":"csrfp2","cert_fingerprint":"","serial":"","not_after":"","caller_fingerprint":"","prev_hash":"3ec6321c36d41c2e05b588c26c7486a3520eecb2f54b19738fd7d56d080b5ac9","hash":"58c9109f6f60858707742c636e51a155fe583094fbb7d2753a64817a8d0facc8","sig":"lfwR0C2g4OXgd0CU4anVDq+9o55zPa8mvsx4qR4DtH796sIBzJoVkf1fR8SQd3Xixr1HSwMIPOsmNp8rdaYqBQ==","pubkey_id":"lodeline-audit-golden"}"#,
                "\n",
            )
        );
    }
}
