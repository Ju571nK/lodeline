//! #553: state for `POST /v1/renew`. Per host id the server remembers the newest
//! certificate it issued (`Head`), rebuilt at boot from the signed audit file and
//! updated by both issuing routes under the mint lock. A host renews only from
//! its head, or from the head's predecessor with the same CSR when the answer was
//! lost, at most `MAX_ISSUANCES` times.

use super::audit::SignedEnrollmentRecord;
use rustls::pki_types::{CertificateDer, UnixTime};
use rustls::server::danger::ClientCertVerifier;
use rustls::server::WebPkiClientVerifier;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;

/// Certificates issued for one presented certificate: the first and two repeats.
const MAX_ISSUANCES: u32 = 3;

/// Audit `reason` of a renewal refused because the certificate is not the head.
pub const SUPERSEDED: &str = "renewal_superseded";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Head {
    pub serial: String,
    /// The certificate the head was issued for, when the server saw it.
    pub prev_serial: Option<String>,
    /// blake3 of the CSR bytes that produced the head.
    pub csr_fp: String,
    pub issued_count: u32,
}

pub struct Renewal {
    verifier: Arc<dyn ClientCertVerifier>,
    heads: parking_lot::Mutex<HashMap<String, Head>>,
    /// Fingerprints of presented certificates whose first denial is in the audit file.
    denied: parking_lot::Mutex<HashSet<String>>,
}

/// Lowercase hex without separators or leading zeros, so openssl's and
/// x509-parser's spellings of one serial compare equal.
pub fn norm_serial(s: &str) -> String {
    let hex: String = s
        .chars()
        .filter(char::is_ascii_hexdigit)
        .map(|c| c.to_ascii_lowercase())
        .collect();
    hex.trim_start_matches('0').to_string()
}

impl Renewal {
    /// `None` (renewal off) when the CA cannot be loaded or the audit file exists
    /// but cannot be read. A missing file means no heads; lines that do not parse
    /// are skipped and counted.
    pub fn load(ca_cert: &Path, audit: &Path) -> Option<Renewal> {
        let mut roots = rustls::RootCertStore::empty();
        let added = crate::tls_accept::load_certs(ca_cert)
            .map_err(|e| e.to_string())
            .and_then(|c| roots.add(c[0].clone()).map_err(|e| e.to_string()));
        if let Err(e) = added {
            tracing::error!(error = %e, "renew: enrollment CA not usable as a trust anchor; renewal disabled");
            return None;
        }
        let verifier = match WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(rustls::crypto::ring::default_provider()),
        )
        .build()
        {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(error = %e, "renew: cannot build the certificate verifier; renewal disabled");
                return None;
            }
        };
        let bytes = match std::fs::read(audit) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => {
                tracing::error!(path = %audit.display(), error = %e, "renew: cannot read the enrollment audit file; renewal disabled");
                return None;
            }
        };
        let (heads, denied, bad) = scan(&String::from_utf8_lossy(&bytes));
        if bad > 0 {
            tracing::warn!(lines = bad, "renew: skipped audit lines that do not parse");
        }
        Some(Renewal {
            verifier,
            heads: heads.into(),
            denied: denied.into(),
        })
    }

    /// The leaf verifies against the enrollment CA alone at `now`, for client auth.
    pub fn verify(&self, leaf_der: &[u8], now_unix: i64) -> bool {
        let now =
            UnixTime::since_unix_epoch(std::time::Duration::from_secs(now_unix.max(0) as u64));
        self.verifier
            .verify_client_cert(&CertificateDer::from(leaf_der), &[], now)
            .is_ok()
    }

    /// The head rule. A host with no entry is allowed.
    pub fn permits(&self, host: &str, presented: &str, csr_fp: &str) -> bool {
        match self.heads.lock().get(host) {
            None => true,
            Some(h) => {
                h.serial == presented
                    || (h.prev_serial.as_deref() == Some(presented)
                        && h.csr_fp == csr_fp
                        && h.issued_count < MAX_ISSUANCES)
            }
        }
    }

    pub fn record_renewal(&self, host: &str, serial: &str, csr_fp: &str, presented: &str) {
        let serial = norm_serial(serial);
        let mut heads = self.heads.lock();
        if serial.is_empty() {
            heads.remove(host);
            return;
        }
        let issued_count = match heads.get(host) {
            Some(h) if h.prev_serial.as_deref() == Some(presented) && h.csr_fp == csr_fp => {
                h.issued_count + 1
            }
            _ => 1,
        };
        let head = Head {
            serial,
            prev_serial: Some(presented.to_string()),
            csr_fp: csr_fp.to_string(),
            issued_count,
        };
        heads.insert(host.to_string(), head);
    }

    pub fn record_enrollment(&self, host: &str, serial: &str, csr_fp: &str) {
        let serial = norm_serial(serial);
        let mut heads = self.heads.lock();
        if serial.is_empty() {
            heads.remove(host);
            return;
        }
        let head = Head {
            serial,
            prev_serial: None,
            csr_fp: csr_fp.to_string(),
            issued_count: 1,
        };
        heads.insert(host.to_string(), head);
    }

    /// True once per presented certificate: the caller chains that denial.
    pub fn first_denial(&self, presented_fp: &str) -> bool {
        self.denied.lock().insert(presented_fp.to_string())
    }

    pub fn head(&self, host: &str) -> Option<Head> {
        self.heads.lock().get(host).cloned()
    }
}

type Scan = (HashMap<String, Head>, HashSet<String>, usize);

/// Read the audit file in order. A renewal line that repeats the previous head's CSR and
/// caller counts as a repeat; any other renewal replaces the head.
fn scan(text: &str) -> Scan {
    let mut heads: HashMap<String, Head> = HashMap::new();
    let mut callers: HashMap<String, String> = HashMap::new();
    let mut denied = HashSet::new();
    let mut bad = 0;
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let Ok(signed) = serde_json::from_str::<SignedEnrollmentRecord>(line) else {
            bad += 1;
            continue;
        };
        let r = signed.record;
        match (r.decision.as_str(), r.reason.as_str()) {
            ("issued", reason) => {
                let serial = norm_serial(&r.serial);
                let old = heads.remove(&r.host_id);
                if serial.is_empty() {
                    continue;
                }
                let renewed = reason == "renewed";
                let repeat = renewed
                    && old.as_ref().is_some_and(|h| h.csr_fp == r.csr_fingerprint)
                    && callers.get(&r.host_id) == Some(&r.caller_fingerprint);
                let (prev_serial, issued_count) = match old {
                    Some(h) if repeat => (h.prev_serial, h.issued_count + 1),
                    Some(h) if renewed => (Some(h.serial), 1),
                    _ => (None, 1),
                };
                callers.insert(r.host_id.clone(), r.caller_fingerprint);
                let head = Head {
                    serial,
                    prev_serial,
                    csr_fp: r.csr_fingerprint,
                    issued_count,
                };
                heads.insert(r.host_id, head);
            }
            ("denied", SUPERSEDED) => {
                denied.insert(r.caller_fingerprint);
            }
            _ => {}
        }
    }
    (heads, denied, bad)
}
