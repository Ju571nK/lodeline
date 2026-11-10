//! #184 — enrollment state: intermediate CA paths + boot validation + mint
//! serialization.
//!
//! Boot validation (codex-hardened rev3) — ALL must pass or the feature is
//! DISABLED (returns None ⇒ every `/v1/enroll` route 404s):
//!   0. mTLS is configured on the server (the full TLS triple). Token-only cert
//!      minting must never be reachable over cleartext HTTP. (fix A)
//!   1. cert + key + tokens paths all configured AND host_allowlist configured.
//!   2. the host_allowlist file EXISTS and loads as a restrictive `Some(set)`
//!      (possibly empty). A missing/permit-all allowlist disables enrollment so
//!      a token-minted host can never bypass the allowlist gate. (fix B)
//!   3. openssl resolvable (absolute path captured once).
//!   4. CA cert is `CA:TRUE` (basicConstraints).
//!   5. CA key matches the cert (modulus / pubkey agreement, via openssl).
//!   6. (unix) CA key file mode is NOT looser than 0600.

pub mod audit;
pub mod index;
pub mod listener;
pub mod lock;
pub mod renewal;
pub mod sign;
pub mod tokens;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};

/// Default issued client-cert validity. Short by design (re-enroll replaces
/// revocation in the MVP).
const DEFAULT_CERT_DAYS: u32 = 30;

pub struct EnrollState {
    pub ca_cert_path: PathBuf,
    pub ca_key_path: PathBuf,
    pub tokens_path: PathBuf,
    /// `<events_out_dir parent>/enrollment-audit.jsonl` — set by build_state.
    pub audit_path: PathBuf,
    /// Absolute path to the openssl binary, resolved once at boot.
    pub openssl_path: PathBuf,
    pub cert_days: u32,
    /// #194.1 — optional allowlist of caller (TLS client-cert) fingerprints
    /// permitted to enroll, normalized to lowercase hex at load. `None` ⇒ any
    /// mTLS fleet member may redeem a token; `Some([])` ⇒ deny-all.
    pub issuer_fingerprints: Option<Vec<String>>,
    /// Serializes the whole mint critical section:
    /// issuer-check → CN-check → reserve(token) → sign → allowlist → audit.
    pub mint: Mutex<()>,
    /// #553: the enrollment listener's pre-check of `tokens_path`.
    pub index: index::TokenIndex,
    /// #553: counts and logs the enrollment listener's denials.
    pub deny_log: Arc<crate::proxy::ingest::DenyLog>,
    /// #553: `POST /v1/renew`. `None` ⇒ the route answers 404 (the audit file
    /// could not be read, or the CA is not usable as a trust anchor).
    pub renewal: Option<renewal::Renewal>,
}

impl EnrollState {
    /// Construct + validate. Returns `None` (feature off) unless every gate
    /// passes. `allowlist_path` is the on-disk `hosts.json` path — required,
    /// since auto-add is the point of enrollment, and it MUST load as a
    /// restrictive `Some(set)`. `mtls_enabled` reflects the server's TLS triple;
    /// enrollment is refused over cleartext HTTP.
    #[allow(clippy::too_many_arguments)]
    pub fn load(
        ca_cert: Option<&Path>,
        ca_key: Option<&Path>,
        tokens: Option<&Path>,
        allowlist_path: Option<&Path>,
        mtls_enabled: bool,
        cert_days: Option<u32>,
        audit_path: PathBuf,
        issuer_fingerprints: Option<Vec<String>>,
    ) -> Option<EnrollState> {
        // fix A: never expose token-only cert minting over cleartext HTTP.
        if !mtls_enabled {
            if ca_cert.is_some() || ca_key.is_some() || tokens.is_some() {
                tracing::warn!(
                    "enroll: enrollment paths set but server mTLS is not configured; enrollment disabled (token-only minting must not be reachable over cleartext HTTP)"
                );
            }
            return None;
        }
        let (cert, key, toks) = (ca_cert?, ca_key?, tokens?);
        let Some(allowlist_path) = allowlist_path else {
            tracing::warn!(
                "enroll: host_allowlist_path not configured; enrollment disabled (allowlist is required)"
            );
            return None;
        };
        // fix B: the allowlist file MUST exist and load as a restrictive set
        // (possibly empty). A missing/permit-all allowlist ⇒ disable enrollment,
        // never leave it on with a permit-all allowlist.
        match crate::allowlist::load(Some(allowlist_path)) {
            Ok(Some(_set)) => {}
            Ok(None) => {
                tracing::warn!(
                    path = %allowlist_path.display(),
                    "enroll: host_allowlist file missing (permit-all); enrollment disabled (a restrictive allowlist is required)"
                );
                return None;
            }
            Err(e) => {
                tracing::warn!(
                    path = %allowlist_path.display(),
                    error = %e,
                    "enroll: host_allowlist file unloadable; enrollment disabled"
                );
                return None;
            }
        }
        // Enrolling rewrites the allowlist AFTER the token is spent, so a path the
        // service cannot rewrite must disable enrollment here, not fail a request.
        if let Err(e) = crate::allowlist::check_rewritable(allowlist_path) {
            tracing::error!(
                path = %allowlist_path.display(),
                error = %e,
                "enroll: cannot write next to host_allowlist_path (the service must be able to \
                 rewrite the file); enrollment disabled"
            );
            return None;
        }
        if !cert.is_file() || !key.is_file() {
            tracing::warn!("enroll: ca cert/key missing on disk; enrollment disabled");
            return None;
        }
        let openssl = match sign::resolve_openssl() {
            Some(p) => p,
            None => {
                tracing::warn!("enroll: openssl not found on PATH; enrollment disabled");
                return None;
            }
        };
        if let Err(msg) = openssl_runs(&openssl) {
            tracing::error!("enroll: {msg}; enrollment disabled");
            return None;
        }
        if !key_mode_ok(key) {
            tracing::error!(
                path = %key.display(),
                "enroll: CA key file mode is looser than 0600; enrollment disabled"
            );
            return None;
        }
        if let Err(msg) = check_ca_files(&openssl, cert, key) {
            tracing::error!("enroll: {msg}; enrollment disabled");
            return None;
        }
        // #194.1 — normalize issuer fingerprints to lowercase hex once, at
        // boot, and VALIDATE them (codex review): a blake3 fingerprint is
        // exactly 64 hex chars, so a typo'd entry can never match anything —
        // it would silently lock the operator out. Malformed entries disable
        // enrollment loudly instead. Duplicates are removed. `Some([])` is
        // kept as-is: deny-all, so an empty list in the config surfaces
        // immediately rather than silently disabling the gate.
        let issuer_fingerprints = match issuer_fingerprints {
            None => None,
            Some(list) => {
                let mut norm: Vec<String> = Vec::with_capacity(list.len());
                for raw in &list {
                    let f = raw.trim().to_ascii_lowercase();
                    if f.len() != 64 || !f.bytes().all(|b| b.is_ascii_hexdigit()) {
                        tracing::error!(
                            entry = %raw,
                            "enroll: enroll_issuer_fingerprints entry is not 64 hex chars \
                             (blake3 of the client cert DER); enrollment disabled"
                        );
                        return None;
                    }
                    if !norm.contains(&f) {
                        norm.push(f);
                    }
                }
                Some(norm)
            }
        };
        match issuer_fingerprints.as_deref() {
            Some([]) => tracing::warn!(
                "enroll: enroll_issuer_fingerprints is EMPTY — every /v1/enroll caller will be denied"
            ),
            Some(list) => tracing::info!(
                entries = list.len(),
                "enroll: issuer cert-fingerprint binding enabled (#194.1)"
            ),
            None => {}
        }
        tracing::info!(
            cert = %cert.display(),
            "enroll: enabled (intermediate CA validated)"
        );
        let renewal = renewal::Renewal::load(cert, &audit_path);
        Some(EnrollState {
            ca_cert_path: cert.to_path_buf(),
            ca_key_path: key.to_path_buf(),
            tokens_path: toks.to_path_buf(),
            audit_path,
            openssl_path: openssl,
            cert_days: cert_days.unwrap_or(DEFAULT_CERT_DAYS),
            issuer_fingerprints,
            mint: Mutex::new(()),
            index: index::TokenIndex::new(toks.to_path_buf()),
            deny_log: Arc::new(crate::proxy::ingest::DenyLog::new("enroll request refused")),
            renewal,
        })
    }
}

/// Run `openssl version` so a binary the service may not execute (an SELinux or
/// permission denial) is reported as that, not as a bad CA cert later.
fn openssl_runs(openssl: &Path) -> Result<(), String> {
    match Command::new(openssl)
        .env_remove("OPENSSL_CONF")
        .arg("version")
        .output()
    {
        Ok(o) if o.status.success() => Ok(()),
        Ok(o) => Err(format!(
            "openssl at {} ran but failed ({}): {}",
            openssl.display(),
            o.status,
            String::from_utf8_lossy(&o.stderr).trim()
        )),
        Err(e) => Err(format!("cannot run openssl at {}: {e}", openssl.display())),
    }
}

/// (unix) True iff the key file mode has NO group/other permission bits.
#[cfg(unix)]
fn key_mode_ok(key: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    match std::fs::metadata(key) {
        Ok(m) => m.permissions().mode() & 0o077 == 0,
        Err(_) => false,
    }
}
#[cfg(not(unix))]
fn key_mode_ok(_key: &Path) -> bool {
    true
}

/// The boot checks on the CA files, in the order that names the real cause.
fn check_ca_files(openssl: &Path, cert: &Path, key: &Path) -> Result<(), String> {
    for p in [cert, key] {
        if let Err(e) = std::fs::File::open(p) {
            return Err(format!("cannot read {} ({e})", p.display()));
        }
    }
    if !ca_cert_is_ca(openssl, cert) {
        return Err(format!(
            "configured CA cert {} is not CA:TRUE",
            cert.display()
        ));
    }
    key_matches_cert(openssl, cert, key)
}

/// Verify the cert advertises `CA:TRUE` via `openssl x509 -text`.
fn ca_cert_is_ca(openssl: &Path, cert: &Path) -> bool {
    let out = Command::new(openssl)
        .env_remove("OPENSSL_CONF")
        .arg("x509")
        .arg("-in")
        .arg(cert)
        .args(["-noout", "-text"])
        .output();
    match out {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout)
            .to_lowercase()
            .contains("ca:true"),
        _ => false,
    }
}

/// Verify the private key matches the cert by comparing public-key hashes.
/// Algorithm-agnostic: `-pubkey` from cert and from key must be byte-identical.
fn key_matches_cert(openssl: &Path, cert: &Path, key: &Path) -> Result<(), String> {
    let cert_pub = Command::new(openssl)
        .env_remove("OPENSSL_CONF")
        .arg("x509")
        .arg("-in")
        .arg(cert)
        .args(["-noout", "-pubkey"])
        .output();
    let key_pub = Command::new(openssl)
        .env_remove("OPENSSL_CONF")
        .arg("pkey")
        .arg("-in")
        .arg(key)
        .args(["-pubout"])
        .output();
    match (cert_pub, key_pub) {
        (Ok(c), Ok(k))
            if c.status.success()
                && k.status.success()
                && !c.stdout.is_empty()
                && c.stdout == k.stdout =>
        {
            Ok(())
        }
        _ => Err("CA key does not match CA cert".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Write a restrictive (empty) allowlist file so the fix-B gate passes.
    fn write_allowlist(dir: &Path) -> PathBuf {
        let p = dir.join("hosts.json");
        std::fs::write(&p, r#"{"hosts":[]}"#).unwrap();
        p
    }

    #[test]
    fn load_none_when_any_path_absent() {
        let d = tempfile::tempdir().unwrap();
        let al = write_allowlist(d.path());
        let s = EnrollState::load(
            Some(&PathBuf::from("/x.crt")),
            None,
            Some(&PathBuf::from("/t.json")),
            Some(&al),
            true, // mtls on
            None,
            PathBuf::from("/tmp/a.jsonl"),
            None,
        );
        assert!(s.is_none());
    }

    #[test]
    fn load_none_when_allowlist_absent() {
        // even with all CA paths "present" as strings, no allowlist path ⇒ off
        let s = EnrollState::load(
            Some(&PathBuf::from("/x.crt")),
            Some(&PathBuf::from("/x.key")),
            Some(&PathBuf::from("/t.json")),
            None,
            true, // mtls on
            None,
            PathBuf::from("/tmp/a.jsonl"),
            None,
        );
        assert!(s.is_none());
    }

    /// fix A: enrollment paths set but server mTLS not configured ⇒ disabled.
    #[test]
    fn load_none_when_mtls_disabled() {
        let d = tempfile::tempdir().unwrap();
        let al = write_allowlist(d.path());
        let s = EnrollState::load(
            Some(&PathBuf::from("/x.crt")),
            Some(&PathBuf::from("/x.key")),
            Some(&PathBuf::from("/t.json")),
            Some(&al),
            false, // mtls OFF ⇒ must refuse
            None,
            d.path().join("a.jsonl"),
            None,
        );
        assert!(s.is_none(), "no mTLS ⇒ enrollment must be disabled");
    }

    /// fix A (full positive control): a real valid CA enrolls ONLY with mTLS on;
    /// flipping mTLS off disables it.
    #[test]
    fn load_none_when_mtls_disabled_even_with_valid_ca() {
        let Some(openssl) = sign::resolve_openssl() else {
            return;
        };
        let d = tempfile::tempdir().unwrap();
        let (cert, key) = make_ca(&openssl, d.path());
        let al = write_allowlist(d.path());
        let toks = d.path().join("t.json");
        let s = EnrollState::load(
            Some(&cert),
            Some(&key),
            Some(&toks),
            Some(&al),
            false, // mtls OFF
            Some(30),
            d.path().join("a.jsonl"),
            None,
        );
        assert!(s.is_none(), "valid CA still disabled when mTLS is off");
    }

    /// fix B: allowlist path configured but the FILE is missing ⇒ enrollment
    /// disabled (never permit-all under enrollment).
    #[test]
    fn load_none_when_allowlist_file_missing() {
        let Some(openssl) = sign::resolve_openssl() else {
            return;
        };
        let d = tempfile::tempdir().unwrap();
        let (cert, key) = make_ca(&openssl, d.path());
        let toks = d.path().join("t.json");
        let missing = d.path().join("hosts.json"); // never created
        let s = EnrollState::load(
            Some(&cert),
            Some(&key),
            Some(&toks),
            Some(&missing),
            true, // mtls on
            Some(30),
            d.path().join("a.jsonl"),
            None,
        );
        assert!(
            s.is_none(),
            "missing allowlist file (permit-all) ⇒ enrollment disabled"
        );
    }

    #[test]
    fn load_none_when_cert_missing_on_disk() {
        let d = tempfile::tempdir().unwrap();
        let al = write_allowlist(d.path());
        let s = EnrollState::load(
            Some(&d.path().join("nope.crt")),
            Some(&d.path().join("nope.key")),
            Some(&d.path().join("t.json")),
            Some(&al),
            true,
            None,
            d.path().join("a.jsonl"),
            None,
        );
        assert!(s.is_none());
    }

    /// Full positive: a real CA:TRUE cert+matching key, 0600, validates.
    #[test]
    fn load_some_with_valid_intermediate_ca() {
        let Some(openssl) = sign::resolve_openssl() else {
            eprintln!("openssl not present; skipping");
            return;
        };
        let d = tempfile::tempdir().unwrap();
        let (cert, key) = make_ca(&openssl, d.path());
        let al = write_allowlist(d.path());
        let toks = d.path().join("t.json");
        let s = EnrollState::load(
            Some(&cert),
            Some(&key),
            Some(&toks),
            Some(&al),
            true,
            Some(30),
            d.path().join("a.jsonl"),
            None,
        );
        assert!(s.is_some(), "valid CA should enable enrollment");
        assert_eq!(s.unwrap().cert_days, 30);
    }

    /// #194.1 — issuer fingerprints are normalized (trim + lowercase) at load;
    /// absent stays `None`; an empty list is preserved (deny-all).
    #[test]
    fn load_normalizes_issuer_fingerprints() {
        let Some(openssl) = sign::resolve_openssl() else {
            return;
        };
        let d = tempfile::tempdir().unwrap();
        let (cert, key) = make_ca(&openssl, d.path());
        let al = write_allowlist(d.path());
        let toks = d.path().join("t.json");
        let load = |issuers: Option<Vec<String>>| {
            EnrollState::load(
                Some(&cert),
                Some(&key),
                Some(&toks),
                Some(&al),
                true,
                Some(30),
                d.path().join("a.jsonl"),
                issuers,
            )
        };
        let hexfp = "AB".repeat(32); // 64 hex chars, uppercase
        let s = load(Some(vec![format!("  {hexfp}  "), hexfp.to_lowercase()])).unwrap();
        assert_eq!(
            s.issuer_fingerprints,
            Some(vec!["ab".repeat(32)]),
            "trimmed + lowercased + deduped"
        );
        let s = load(Some(vec![])).unwrap();
        assert_eq!(s.issuer_fingerprints, Some(vec![]), "empty kept = deny-all");
        let s = load(None).unwrap();
        assert_eq!(s.issuer_fingerprints, None, "absent stays permissive");
        // codex review — malformed entries (wrong length / non-hex) can never
        // match a blake3 fingerprint; they disable enrollment loudly instead
        // of silently locking the operator out.
        assert!(
            load(Some(vec!["abcdef0123".to_string()])).is_none(),
            "short entry rejected"
        );
        assert!(
            load(Some(vec!["zz".repeat(32)])).is_none(),
            "non-hex entry rejected"
        );
    }

    /// An openssl the service cannot run is reported as that, with its path.
    #[cfg(unix)]
    #[test]
    fn openssl_runs_names_the_path_when_it_cannot_run() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let fake = d.path().join("openssl");
        std::fs::write(&fake, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o644)).unwrap();
        let msg = openssl_runs(&fake).unwrap_err();
        assert!(msg.contains("cannot run openssl"), "{msg}");
        assert!(msg.contains(&fake.display().to_string()), "{msg}");
        assert!(!msg.contains("CA:TRUE"), "{msg}");

        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(openssl_runs(&fake).is_ok());
        std::fs::write(&fake, "#!/bin/sh\necho no >&2\nexit 3\n").unwrap();
        let msg = openssl_runs(&fake).unwrap_err();
        assert!(
            msg.contains("ran but failed") && msg.contains("no"),
            "{msg}"
        );
    }

    /// An allowlist the service cannot rewrite disables enrollment at boot.
    #[cfg(unix)]
    #[test]
    fn load_none_when_allowlist_dir_is_read_only() {
        use std::os::unix::fs::PermissionsExt;
        let Some(openssl) = sign::resolve_openssl() else {
            return;
        };
        let d = tempfile::tempdir().unwrap();
        let (cert, key) = make_ca(&openssl, d.path());
        let ro = d.path().join("ro");
        std::fs::create_dir(&ro).unwrap();
        let al = write_allowlist(&ro);
        std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o555)).unwrap();
        // root ignores the mode bits, so only assert where the dir really is read-only
        let really_ro = std::fs::File::create(ro.join("x")).is_err();
        let s = EnrollState::load(
            Some(&cert),
            Some(&key),
            Some(&d.path().join("t.json")),
            Some(&al),
            true,
            Some(30),
            d.path().join("a.jsonl"),
            None,
        );
        std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o755)).unwrap();
        if really_ro {
            assert!(
                s.is_none(),
                "unwritable allowlist dir must disable enrollment"
            );
        }
    }

    /// A non-CA (CA:FALSE) cert must be rejected.
    #[test]
    fn load_none_when_cert_not_ca() {
        let Some(openssl) = sign::resolve_openssl() else {
            return;
        };
        let d = tempfile::tempdir().unwrap();
        let (cert, key) = make_leaf_cert(&openssl, d.path());
        let al = write_allowlist(d.path());
        let s = EnrollState::load(
            Some(&cert),
            Some(&key),
            Some(&d.path().join("t.json")),
            Some(&al),
            true,
            None,
            d.path().join("a.jsonl"),
            None,
        );
        assert!(s.is_none(), "CA:FALSE cert must disable enrollment");
    }

    #[cfg(unix)]
    #[test]
    fn boot_check_says_unreadable_for_a_cert_the_account_cannot_read() {
        use std::os::unix::fs::PermissionsExt;
        let Some(openssl) = sign::resolve_openssl() else {
            return;
        };
        let d = tempfile::tempdir().unwrap();
        let (cert, key) = make_ca(&openssl, d.path());
        std::fs::set_permissions(&cert, std::fs::Permissions::from_mode(0o000)).unwrap();
        // root reads any file, so only assert where the certificate is really unreadable
        if std::fs::File::open(&cert).is_ok() {
            return;
        }
        let msg = check_ca_files(&openssl, &cert, &key).unwrap_err();
        assert!(msg.starts_with("cannot read "), "{msg}");
        assert!(msg.contains(cert.to_str().unwrap()), "{msg}");
        assert!(
            !msg.contains("CA:TRUE") && !msg.contains("does not match"),
            "{msg}"
        );
    }

    #[test]
    fn boot_check_keeps_the_other_causes() {
        let Some(openssl) = sign::resolve_openssl() else {
            return;
        };
        let d = tempfile::tempdir().unwrap();
        let (leaf, leaf_key) = make_leaf_cert(&openssl, d.path());
        let msg = check_ca_files(&openssl, &leaf, &leaf_key).unwrap_err();
        assert!(msg.contains("is not CA:TRUE"), "{msg}");
        let o = tempfile::tempdir().unwrap();
        let (cert, _key) = make_ca(&openssl, o.path());
        let (_c, other_key) = make_ca(&openssl, d.path());
        assert_eq!(
            check_ca_files(&openssl, &cert, &other_key).unwrap_err(),
            "CA key does not match CA cert"
        );
    }

    #[cfg(unix)]
    #[test]
    fn key_check_says_unreadable_for_a_key_the_account_cannot_read() {
        use std::os::unix::fs::PermissionsExt;
        let Some(openssl) = sign::resolve_openssl() else {
            return;
        };
        let d = tempfile::tempdir().unwrap();
        let (cert, key) = make_ca(&openssl, d.path());
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o000)).unwrap();
        // root reads any file, so only assert where the key is really unreadable
        if std::fs::File::open(&key).is_ok() {
            return;
        }
        let msg = check_ca_files(&openssl, &cert, &key).unwrap_err();
        assert!(msg.starts_with("cannot read "), "{msg}");
        assert!(msg.contains(key.to_str().unwrap()), "{msg}");
        assert!(!msg.contains("does not match"), "{msg}");
    }

    #[test]
    fn key_check_says_unreadable_for_a_missing_key() {
        let Some(openssl) = sign::resolve_openssl() else {
            return;
        };
        let d = tempfile::tempdir().unwrap();
        let (cert, _key) = make_ca(&openssl, d.path());
        let gone = d.path().join("gone.key");
        let msg = check_ca_files(&openssl, &cert, &gone).unwrap_err();
        assert!(msg.starts_with("cannot read "), "{msg}");
        assert!(msg.contains(gone.to_str().unwrap()), "{msg}");
    }

    #[test]
    fn key_check_says_mismatch_for_another_cas_key() {
        let Some(openssl) = sign::resolve_openssl() else {
            return;
        };
        let d = tempfile::tempdir().unwrap();
        let (cert, key) = make_ca(&openssl, d.path());
        let other = tempfile::tempdir().unwrap();
        let (_c2, key2) = make_ca(&openssl, other.path());
        assert_eq!(
            check_ca_files(&openssl, &cert, &key2).unwrap_err(),
            "CA key does not match CA cert"
        );
        assert!(check_ca_files(&openssl, &cert, &key).is_ok());
    }

    fn make_ca(openssl: &Path, dir: &Path) -> (PathBuf, PathBuf) {
        let key = dir.join("ca.key");
        let crt = dir.join("ca.crt");
        run(
            openssl,
            &[
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
                "-out",
                key.to_str().unwrap(),
            ],
        );
        run(
            openssl,
            &[
                "req",
                "-x509",
                "-new",
                "-key",
                key.to_str().unwrap(),
                "-days",
                "3650",
                "-subj",
                "/CN=test-ca",
                "-addext",
                "basicConstraints=critical,CA:TRUE",
                "-out",
                crt.to_str().unwrap(),
            ],
        );
        set_0600(&key);
        (crt, key)
    }

    fn make_leaf_cert(openssl: &Path, dir: &Path) -> (PathBuf, PathBuf) {
        let key = dir.join("leaf.key");
        let crt = dir.join("leaf.crt");
        run(
            openssl,
            &[
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
                "-out",
                key.to_str().unwrap(),
            ],
        );
        run(
            openssl,
            &[
                "req",
                "-x509",
                "-new",
                "-key",
                key.to_str().unwrap(),
                "-days",
                "3650",
                "-subj",
                "/CN=leaf",
                "-addext",
                "basicConstraints=critical,CA:FALSE",
                "-out",
                crt.to_str().unwrap(),
            ],
        );
        set_0600(&key);
        (crt, key)
    }

    fn run(openssl: &Path, args: &[&str]) {
        let o = Command::new(openssl).args(args).output().unwrap();
        assert!(
            o.status.success(),
            "openssl {args:?}: {}",
            String::from_utf8_lossy(&o.stderr)
        );
    }

    #[cfg(unix)]
    fn set_0600(p: &Path) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    #[cfg(not(unix))]
    fn set_0600(_p: &Path) {}
}
