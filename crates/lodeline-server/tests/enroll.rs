//! #184 — in-process integration tests for `POST /v1/enroll` (B-mint) via
//! `tower::ServiceExt::oneshot`. Builds a REAL intermediate CA with openssl,
//! issues tokens through the token store, generates a host keypair + CSR, and
//! drives the endpoint end-to-end. Happy path → 200 + cert verifies vs the CA +
//! CN==host_id + clientAuth EKU + host added to allowlist + a signed audit line.
//! Negatives: expired→403, reused→403, CN!=host_id→403, bad CSR→400, off→404.
//!
//! These tests require `openssl` on PATH (CI ubuntu/macos/rocky all have it).

use axum::body::Body;
use axum::http::{Request, StatusCode};
use lodeline_server::app::{build_router, AppState};
use lodeline_server::auth::ReadToken;
use lodeline_server::enroll::tokens::TokenStore;
use lodeline_server::enroll::EnrollState;
use lodeline_server::fleet_index::FleetIndex;
use lodeline_server::persist::HighWater;
use lodeline_server::tls_accept::PeerIdentity;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use time::{Duration, OffsetDateTime};
use tower::ServiceExt;

fn openssl() -> PathBuf {
    lodeline_server::enroll::sign::resolve_openssl().expect("openssl must be installed")
}

fn run(args: &[&std::ffi::OsStr]) {
    let o = Command::new(openssl()).args(args).output().unwrap();
    assert!(
        o.status.success(),
        "openssl {args:?}: {}",
        String::from_utf8_lossy(&o.stderr)
    );
}

/// Make a CA:TRUE intermediate-style CA (self-signed for test purposes — the
/// leaf still verifies against it). Returns (cert_path, key_path), key at 0600.
fn make_ca(dir: &Path) -> (PathBuf, PathBuf) {
    let key = dir.join("ca.key");
    let crt = dir.join("ca.crt");
    run(&[
        "genpkey".as_ref(),
        "-algorithm".as_ref(),
        "RSA".as_ref(),
        "-pkeyopt".as_ref(),
        "rsa_keygen_bits:2048".as_ref(),
        "-out".as_ref(),
        key.as_os_str(),
    ]);
    run(&[
        "req".as_ref(),
        "-x509".as_ref(),
        "-new".as_ref(),
        "-key".as_ref(),
        key.as_os_str(),
        "-days".as_ref(),
        "3650".as_ref(),
        "-subj".as_ref(),
        "/CN=test-int-ca".as_ref(),
        "-addext".as_ref(),
        "basicConstraints=critical,CA:TRUE".as_ref(),
        "-out".as_ref(),
        crt.as_os_str(),
    ]);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    (crt, key)
}

/// Generate a host key + CSR with the given CN. Returns the CSR PEM.
fn make_csr(dir: &Path, cn: &str) -> String {
    let key = dir.join(format!("{cn}.key"));
    let csr = dir.join(format!("{cn}.csr"));
    run(&[
        "genpkey".as_ref(),
        "-algorithm".as_ref(),
        "RSA".as_ref(),
        "-pkeyopt".as_ref(),
        "rsa_keygen_bits:2048".as_ref(),
        "-out".as_ref(),
        key.as_os_str(),
    ]);
    let subj = format!("/CN={cn}");
    run(&[
        "req".as_ref(),
        "-new".as_ref(),
        "-key".as_ref(),
        key.as_os_str(),
        "-subj".as_ref(),
        subj.as_ref(),
        "-out".as_ref(),
        csr.as_os_str(),
    ]);
    std::fs::read_to_string(&csr).unwrap()
}

/// Verify a leaf cert against the CA via `openssl verify`.
fn verify_leaf(dir: &Path, ca: &Path, leaf_pem: &str) -> bool {
    let leaf = dir.join("leaf-verify.crt");
    std::fs::write(&leaf, leaf_pem).unwrap();
    Command::new(openssl())
        .arg("verify")
        .arg("-CAfile")
        .arg(ca)
        .arg(&leaf)
        .output()
        .unwrap()
        .status
        .success()
}

fn cert_text(dir: &Path, leaf_pem: &str) -> String {
    let leaf = dir.join("leaf-text.crt");
    std::fs::write(&leaf, leaf_pem).unwrap();
    let o = Command::new(openssl())
        .arg("x509")
        .arg("-in")
        .arg(&leaf)
        .args(["-noout", "-text"])
        .output()
        .unwrap();
    String::from_utf8_lossy(&o.stdout).into_owned()
}

/// Build an AppState with enrollment enabled (or not). `enroll` toggles whether
/// EnrollState is configured. Uses a fresh audit key in `scratch`. A restrictive
/// (empty) allowlist file is written so EnrollState::load's fix-B gate passes,
/// and the in-memory allowlist starts as the same restrictive `Some(set)`.
fn state(scratch: &Path, with_enroll: bool) -> Arc<AppState> {
    state_with_issuers(scratch, with_enroll, None)
}

/// Same as `state`, with an optional #194.1 issuer-fingerprint allowlist.
fn state_with_issuers(
    scratch: &Path,
    with_enroll: bool,
    issuer_fingerprints: Option<Vec<String>>,
) -> Arc<AppState> {
    let tokens_path = scratch.join("tokens.json");
    let allowlist_path = scratch.join("hosts.json");
    // restrictive (empty) on-disk allowlist — required when enrollment is on.
    std::fs::write(&allowlist_path, r#"{"hosts":[]}"#).unwrap();
    let in_mem_allowlist = lodeline_server::allowlist::load(Some(&allowlist_path)).unwrap();
    let enroll = if with_enroll {
        let (cert, key) = make_ca(scratch);
        EnrollState::load(
            Some(&cert),
            Some(&key),
            Some(&tokens_path),
            Some(&allowlist_path),
            true, // mtls on (fix A) — tests drive the handler directly
            Some(30),
            scratch.join("enrollment-audit.jsonl"),
            issuer_fingerprints,
        )
    } else {
        None
    };
    let audit_key = lodeline_server::audit_key::AuditKey::load_or_create(scratch);
    Arc::new(AppState {
        events_out_dir: scratch.to_path_buf(),
        policy_bundle_path: scratch.join("signed-policy.json"),
        rule_packs_bundle_path: None,
        artifacts_dir: None,
        high_water_path: scratch.join(".high-water.json"),
        allowlist: parking_lot::RwLock::new(in_mem_allowlist),
        high_water: Mutex::new(HighWater::default()),
        fleet_index: FleetIndex::new(),
        read_token: ReadToken(None),
        active_window_days: 7,
        audit_key,
        audit_head: Mutex::new(None),
        allowlist_path: Some(allowlist_path),
        enroll,
        events_require_cert_host_match: false,
    })
}

async fn post_enroll(
    app: &axum::Router,
    token: &str,
    host_id: &str,
    csr_pem: &str,
) -> (StatusCode, serde_json::Value) {
    post_enroll_as(app, token, host_id, csr_pem, None).await
}

/// Like `post_enroll`, but optionally injects a `PeerIdentity` request
/// extension — exactly what `PeerCertAcceptor` does on a live mTLS connection.
async fn post_enroll_as(
    app: &axum::Router,
    token: &str,
    host_id: &str,
    csr_pem: &str,
    peer: Option<Arc<PeerIdentity>>,
) -> (StatusCode, serde_json::Value) {
    let body = serde_json::json!({
        "token": token,
        "host_id": host_id,
        "csr_pem": csr_pem,
    });
    let mut builder = Request::builder()
        .method("POST")
        .uri("/v1/enroll")
        .header("content-type", "application/json");
    if let Some(peer) = peer {
        builder = builder.extension(peer);
    }
    let resp = app
        .clone()
        .oneshot(
            builder
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

/// A synthetic caller identity, as the acceptor would build from the leaf DER.
fn peer_with_fingerprint(fp: &str) -> Arc<PeerIdentity> {
    Arc::new(PeerIdentity {
        fingerprint: fp.to_string(),
        cn: Some("issuer-box".to_string()),
        san_dns: vec![],
        ..Default::default()
    })
}

const HOST: &str = "018f9c1a-0000-7000-8000-000000000001";

#[tokio::test]
async fn happy_path_issues_verifiable_clientauth_cert() {
    let dir = tempfile::tempdir().unwrap();
    let st = state(dir.path(), true);
    let en = st.enroll.as_ref().unwrap();
    let tokens_path = en.tokens_path.clone();
    let ca_cert = en.ca_cert_path.clone();
    let audit_path = en.audit_path.clone();
    let allowlist_path = st.allowlist_path.clone().unwrap();
    let now = OffsetDateTime::now_utc();
    let token = TokenStore::issue(&tokens_path, HOST, now + Duration::hours(1), now).unwrap();
    let csr = make_csr(dir.path(), HOST);

    let app = build_router(st);
    let (status, body) = post_enroll(&app, &token, HOST, &csr).await;
    assert_eq!(status, StatusCode::OK, "body={body}");

    let cert = body["client_cert_pem"].as_str().unwrap();
    assert!(cert.contains("BEGIN CERTIFICATE"));
    assert_eq!(body["host_id"], HOST);
    assert!(
        verify_leaf(dir.path(), &ca_cert, cert),
        "leaf must verify vs CA"
    );
    let text = cert_text(dir.path(), cert);
    let lc = text.to_lowercase();
    assert!(
        lc.contains("tls web client authentication"),
        "clientAuth EKU"
    );
    assert!(
        !lc.contains("tls web server authentication"),
        "no serverAuth"
    );
    assert!(text.contains(HOST), "CN/SAN must carry host_id");

    // host added to allowlist file
    let hosts = std::fs::read_to_string(&allowlist_path).unwrap();
    assert!(hosts.contains(HOST), "host added to allowlist");

    // exactly one audit line written and it is an "issued" decision
    let audit = std::fs::read_to_string(&audit_path).unwrap();
    let lines: Vec<&str> = audit.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(lines.len(), 1, "one audit line");
    assert!(lines[0].contains("\"decision\":\"issued\""));
    assert!(lines[0].contains(HOST));
}

#[tokio::test]
async fn reused_token_is_denied_403() {
    let dir = tempfile::tempdir().unwrap();
    let st = state(dir.path(), true);
    let tokens_path = st.enroll.as_ref().unwrap().tokens_path.clone();
    let now = OffsetDateTime::now_utc();
    let token = TokenStore::issue(&tokens_path, HOST, now + Duration::hours(1), now).unwrap();
    let csr = make_csr(dir.path(), HOST);
    let app = build_router(st);

    let (s1, _) = post_enroll(&app, &token, HOST, &csr).await;
    assert_eq!(s1, StatusCode::OK);
    let (s2, body) = post_enroll(&app, &token, HOST, &csr).await;
    assert_eq!(s2, StatusCode::FORBIDDEN);
    assert_eq!(body["error"]["code"], "enrollment_denied");
}

#[tokio::test]
async fn expired_token_is_denied_403() {
    let dir = tempfile::tempdir().unwrap();
    let st = state(dir.path(), true);
    let tokens_path = st.enroll.as_ref().unwrap().tokens_path.clone();
    let now = OffsetDateTime::now_utc();
    // expires in the past
    let token = TokenStore::issue(&tokens_path, HOST, now - Duration::seconds(1), now).unwrap();
    let csr = make_csr(dir.path(), HOST);
    let app = build_router(st);

    let (status, body) = post_enroll(&app, &token, HOST, &csr).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"]["code"], "enrollment_denied");
}

#[tokio::test]
async fn cn_not_equal_host_id_is_denied_403() {
    let dir = tempfile::tempdir().unwrap();
    let st = state(dir.path(), true);
    let tokens_path = st.enroll.as_ref().unwrap().tokens_path.clone();
    let now = OffsetDateTime::now_utc();
    let token = TokenStore::issue(&tokens_path, HOST, now + Duration::hours(1), now).unwrap();
    // CSR CN is a DIFFERENT valid uuid than the host_id we send.
    let other = "018f9c1a-0000-7000-8000-0000000000ff";
    let csr = make_csr(dir.path(), other);
    let app = build_router(st);

    let (status, body) = post_enroll(&app, &token, HOST, &csr).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"]["code"], "enrollment_denied");
}

#[tokio::test]
async fn bad_csr_is_400() {
    let dir = tempfile::tempdir().unwrap();
    let st = state(dir.path(), true);
    let tokens_path = st.enroll.as_ref().unwrap().tokens_path.clone();
    let now = OffsetDateTime::now_utc();
    let token = TokenStore::issue(&tokens_path, HOST, now + Duration::hours(1), now).unwrap();
    let app = build_router(st);

    let (status, body) = post_enroll(&app, &token, HOST, "this is not a csr").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body={body}");
    assert_eq!(body["error"]["code"], "bad_request");
}

#[tokio::test]
async fn bad_host_id_is_400() {
    let dir = tempfile::tempdir().unwrap();
    let st = state(dir.path(), true);
    let tokens_path = st.enroll.as_ref().unwrap().tokens_path.clone();
    let now = OffsetDateTime::now_utc();
    let token = TokenStore::issue(&tokens_path, HOST, now + Duration::hours(1), now).unwrap();
    let csr = make_csr(dir.path(), HOST);
    let app = build_router(st);

    let (status, body) = post_enroll(&app, &token, "not-a-uuid", &csr).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["code"], "bad_request");
}

#[tokio::test]
async fn feature_off_is_404() {
    let dir = tempfile::tempdir().unwrap();
    let st = state(dir.path(), false); // no enroll configured
    let csr = make_csr(dir.path(), HOST);
    let app = build_router(st);

    let (status, body) = post_enroll(&app, "irrelevant", HOST, &csr).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"]["code"], "enroll_not_configured");
}

#[tokio::test]
async fn unknown_token_is_denied_403() {
    let dir = tempfile::tempdir().unwrap();
    let st = state(dir.path(), true);
    let csr = make_csr(dir.path(), HOST);
    let app = build_router(st);

    let (status, body) = post_enroll(&app, "totally-bogus-token", HOST, &csr).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"]["code"], "enrollment_denied");
}

/// fix F: after a successful enroll the in-memory allowlist permits the host
/// WITHOUT a server restart. The in-memory set starts restrictive (empty), so
/// `permits` would be false before enrollment and must be true after.
#[tokio::test]
async fn enroll_updates_in_memory_allowlist() {
    use lodeline_server::allowlist::permits;
    let dir = tempfile::tempdir().unwrap();
    let st = state(dir.path(), true);
    // before: restrictive empty set ⇒ host is NOT permitted.
    assert!(
        !permits(&st.allowlist.read(), HOST),
        "host must be gated out before enroll"
    );
    let tokens_path = st.enroll.as_ref().unwrap().tokens_path.clone();
    let now = OffsetDateTime::now_utc();
    let token = TokenStore::issue(&tokens_path, HOST, now + Duration::hours(1), now).unwrap();
    let csr = make_csr(dir.path(), HOST);

    // Keep a handle to state to inspect the in-memory set after the call.
    let st_for_check = st.clone();
    let app = build_router(st);
    let (status, body) = post_enroll(&app, &token, HOST, &csr).await;
    assert_eq!(status, StatusCode::OK, "body={body}");

    // after: in-memory set now permits the host (no restart needed).
    assert!(
        permits(&st_for_check.allowlist.read(), HOST),
        "host must be permitted in-memory right after enroll"
    );
}

/// fix C: with NO audit key the audit append fails-closed (500) and — because
/// the audit append now runs BEFORE the durable allowlist grant — the host must
/// NOT be left allowlisted (neither on disk nor in memory).
#[tokio::test]
async fn audit_failure_does_not_grant_allowlist() {
    use lodeline_server::allowlist::permits;
    let dir = tempfile::tempdir().unwrap();
    let mut st = state(dir.path(), true);
    // Drop the audit key so the issued-audit append fails closed.
    Arc::get_mut(&mut st).unwrap().audit_key = None;
    let allowlist_path = st.allowlist_path.clone().unwrap();
    let tokens_path = st.enroll.as_ref().unwrap().tokens_path.clone();
    let now = OffsetDateTime::now_utc();
    let token = TokenStore::issue(&tokens_path, HOST, now + Duration::hours(1), now).unwrap();
    let csr = make_csr(dir.path(), HOST);

    let st_for_check = st.clone();
    let app = build_router(st);
    let (status, body) = post_enroll(&app, &token, HOST, &csr).await;
    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "audit-key-absent must 500, body={body}"
    );
    // The durable allowlist grant must NOT have happened (audit ran first).
    let hosts = std::fs::read_to_string(&allowlist_path).unwrap();
    assert!(
        !hosts.contains(HOST),
        "host must NOT be allowlisted on disk when audit failed: {hosts}"
    );
    assert!(
        !permits(&st_for_check.allowlist.read(), HOST),
        "host must NOT be permitted in-memory when audit failed"
    );
}

// --- #194.1 — caller (issuer) cert binding -----------------------------------

/// Read the enrollment audit JSONL as parsed JSON values.
fn audit_lines(path: &Path) -> Vec<serde_json::Value> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

const ISSUER_FP: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

#[tokio::test]
async fn issuer_list_with_matching_peer_is_allowed() {
    let dir = tempfile::tempdir().unwrap();
    let st = state_with_issuers(dir.path(), true, Some(vec![ISSUER_FP.to_string()]));
    let en = st.enroll.as_ref().unwrap();
    let (tokens_path, audit_path) = (en.tokens_path.clone(), en.audit_path.clone());
    let now = OffsetDateTime::now_utc();
    let token = TokenStore::issue(&tokens_path, HOST, now + Duration::hours(1), now).unwrap();
    let csr = make_csr(dir.path(), HOST);
    let app = build_router(st);

    let peer = peer_with_fingerprint(ISSUER_FP);
    let (status, body) = post_enroll_as(&app, &token, HOST, &csr, Some(peer)).await;
    assert_eq!(status, StatusCode::OK, "body={body}");

    // The issued audit record carries the caller's fingerprint.
    let lines = audit_lines(&audit_path);
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0]["decision"], "issued");
    assert_eq!(lines[0]["caller_fingerprint"], ISSUER_FP);
}

#[tokio::test]
async fn issuer_list_with_wrong_fingerprint_is_denied_403_generic() {
    let dir = tempfile::tempdir().unwrap();
    let st = state_with_issuers(dir.path(), true, Some(vec![ISSUER_FP.to_string()]));
    let en = st.enroll.as_ref().unwrap();
    let (tokens_path, audit_path) = (en.tokens_path.clone(), en.audit_path.clone());
    let now = OffsetDateTime::now_utc();
    let token = TokenStore::issue(&tokens_path, HOST, now + Duration::hours(1), now).unwrap();
    let csr = make_csr(dir.path(), HOST);
    let app = build_router(st);

    let wrong = peer_with_fingerprint(&"b".repeat(64));
    let (status, body) = post_enroll_as(&app, &token, HOST, &csr, Some(wrong)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    // SAME body as every token failure — no oracle for "wrong caller".
    assert_eq!(
        body,
        serde_json::json!({"error": {"code": "enrollment_denied", "message": "enrollment denied"}})
    );

    // Denial is audited with the internal reason + caller fingerprint.
    let lines = audit_lines(&audit_path);
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0]["decision"], "denied");
    assert_eq!(lines[0]["reason"], "issuer_not_allowed");
    assert_eq!(lines[0]["caller_fingerprint"], "b".repeat(64));

    // The gate runs BEFORE the token is touched: the same token still works
    // for an authorized caller.
    let ok_peer = peer_with_fingerprint(ISSUER_FP);
    let (status, body) = post_enroll_as(&app, &token, HOST, &csr, Some(ok_peer)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "token must not be spent, body={body}"
    );
}

#[tokio::test]
async fn issuer_list_with_no_peer_identity_is_denied_403() {
    let dir = tempfile::tempdir().unwrap();
    let st = state_with_issuers(dir.path(), true, Some(vec![ISSUER_FP.to_string()]));
    let tokens_path = st.enroll.as_ref().unwrap().tokens_path.clone();
    let now = OffsetDateTime::now_utc();
    let token = TokenStore::issue(&tokens_path, HOST, now + Duration::hours(1), now).unwrap();
    let csr = make_csr(dir.path(), HOST);
    let app = build_router(st);

    let (status, body) = post_enroll_as(&app, &token, HOST, &csr, None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"]["code"], "enrollment_denied");
}

/// Uppercase config entries are normalized: a lowercase-hex caller still matches.
#[tokio::test]
async fn issuer_list_entries_are_normalized_to_lowercase() {
    let dir = tempfile::tempdir().unwrap();
    let st = state_with_issuers(dir.path(), true, Some(vec![ISSUER_FP.to_ascii_uppercase()]));
    let tokens_path = st.enroll.as_ref().unwrap().tokens_path.clone();
    let now = OffsetDateTime::now_utc();
    let token = TokenStore::issue(&tokens_path, HOST, now + Duration::hours(1), now).unwrap();
    let csr = make_csr(dir.path(), HOST);
    let app = build_router(st);

    let peer = peer_with_fingerprint(ISSUER_FP);
    let (status, body) = post_enroll_as(&app, &token, HOST, &csr, Some(peer)).await;
    assert_eq!(status, StatusCode::OK, "body={body}");
}

/// An EMPTY issuer list is deny-all (operator error surfaces fast).
#[tokio::test]
async fn issuer_list_empty_denies_all() {
    let dir = tempfile::tempdir().unwrap();
    let st = state_with_issuers(dir.path(), true, Some(vec![]));
    let tokens_path = st.enroll.as_ref().unwrap().tokens_path.clone();
    let now = OffsetDateTime::now_utc();
    let token = TokenStore::issue(&tokens_path, HOST, now + Duration::hours(1), now).unwrap();
    let csr = make_csr(dir.path(), HOST);
    let app = build_router(st);

    let peer = peer_with_fingerprint(ISSUER_FP);
    let (status, _) = post_enroll_as(&app, &token, HOST, &csr, Some(peer)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

/// List unset ⇒ pre-#194 behavior: a peer identity may be present or absent;
/// either way enrollment succeeds and the audit carries the real caller
/// fingerprint ("" when absent — covered by the other happy-path test).
#[tokio::test]
async fn no_issuer_list_still_records_caller_fingerprint_when_present() {
    let dir = tempfile::tempdir().unwrap();
    let st = state(dir.path(), true);
    let en = st.enroll.as_ref().unwrap();
    let (tokens_path, audit_path) = (en.tokens_path.clone(), en.audit_path.clone());
    let now = OffsetDateTime::now_utc();
    let token = TokenStore::issue(&tokens_path, HOST, now + Duration::hours(1), now).unwrap();
    let csr = make_csr(dir.path(), HOST);
    let app = build_router(st);

    let peer = peer_with_fingerprint(ISSUER_FP);
    let (status, body) = post_enroll_as(&app, &token, HOST, &csr, Some(peer)).await;
    assert_eq!(status, StatusCode::OK, "body={body}");
    let lines = audit_lines(&audit_path);
    assert_eq!(lines[0]["caller_fingerprint"], ISSUER_FP);
}

/// Absent peer + no issuer list: the audit caller_fingerprint is "" (empty),
/// never fabricated.
#[tokio::test]
async fn absent_peer_audits_empty_caller_fingerprint() {
    let dir = tempfile::tempdir().unwrap();
    let st = state(dir.path(), true);
    let en = st.enroll.as_ref().unwrap();
    let (tokens_path, audit_path) = (en.tokens_path.clone(), en.audit_path.clone());
    let now = OffsetDateTime::now_utc();
    let token = TokenStore::issue(&tokens_path, HOST, now + Duration::hours(1), now).unwrap();
    let csr = make_csr(dir.path(), HOST);
    let app = build_router(st);

    let (status, _) = post_enroll(&app, &token, HOST, &csr).await;
    assert_eq!(status, StatusCode::OK);
    let lines = audit_lines(&audit_path);
    assert_eq!(lines[0]["caller_fingerprint"], "");
}

// --- #553: the enrollment listener ------------------------------------------
//
// These drive `enroll::listener::serve` on 127.0.0.1:0 with the TLS config,
// acceptor, router and HTTP settings `main` uses. Each test runs its own
// listener, so each has its own rate-limit budget of 10 connections.

use lodeline_server::enroll::listener;
use std::net::SocketAddr;

const HOST2: &str = "018f9c1a-0000-7000-8000-000000000002";

/// A server certificate for 127.0.0.1 from the test CA in `dir`.
fn make_server_cert(dir: &Path) -> (PathBuf, PathBuf) {
    let key = dir.join("server.key");
    let csr = dir.join("server.csr");
    let crt = dir.join("server.crt");
    let ext = dir.join("server.ext");
    std::fs::write(
        &ext,
        "subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n",
    )
    .unwrap();
    run(&[
        "req".as_ref(),
        "-new".as_ref(),
        "-newkey".as_ref(),
        "rsa:2048".as_ref(),
        "-nodes".as_ref(),
        "-keyout".as_ref(),
        key.as_os_str(),
        "-subj".as_ref(),
        "/CN=127.0.0.1".as_ref(),
        "-out".as_ref(),
        csr.as_os_str(),
    ]);
    run(&[
        "x509".as_ref(),
        "-req".as_ref(),
        "-in".as_ref(),
        csr.as_os_str(),
        "-CA".as_ref(),
        dir.join("ca.crt").as_os_str(),
        "-CAkey".as_ref(),
        dir.join("ca.key").as_os_str(),
        "-set_serial".as_ref(),
        "0x5a01".as_ref(),
        "-days".as_ref(),
        "1".as_ref(),
        "-extfile".as_ref(),
        ext.as_os_str(),
        "-out".as_ref(),
        crt.as_os_str(),
    ]);
    (crt, key)
}

/// Serve the enrollment listener for `st` (enrollment on, CA in `dir`).
async fn listen(dir: &Path, st: Arc<AppState>) -> SocketAddr {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (crt, key) = make_server_cert(dir);
    let tls = listener::tls_config(&crt, &key).unwrap();
    let sock = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = sock.local_addr().unwrap();
    tokio::spawn(listener::serve(sock, tls, st));
    addr
}

/// A client that trusts the test CA and offers no client certificate.
fn anon_client(dir: &Path) -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .use_rustls_tls()
        .add_root_certificate(
            reqwest::Certificate::from_pem(&std::fs::read(dir.join("ca.crt")).unwrap()).unwrap(),
        )
}

async fn post_listener(
    client: &reqwest::Client,
    addr: SocketAddr,
    body: &serde_json::Value,
) -> reqwest::Result<(
    reqwest::StatusCode,
    reqwest::header::HeaderMap,
    serde_json::Value,
)> {
    let r = client
        .post(format!("https://127.0.0.1:{}/v1/enroll", addr.port()))
        .json(body)
        .send()
        .await?;
    let (status, headers) = (r.status(), r.headers().clone());
    let json = r.json().await.unwrap_or(serde_json::Value::Null);
    Ok((status, headers, json))
}

fn enroll_body(token: &str, host_id: &str, csr_pem: &str) -> serde_json::Value {
    serde_json::json!({"token": token, "host_id": host_id, "csr_pem": csr_pem})
}

fn issue(st: &AppState, host: &str, ttl: Duration) -> String {
    let now = OffsetDateTime::now_utc();
    let path = &st.enroll.as_ref().unwrap().tokens_path;
    TokenStore::issue(path, host, now + ttl, now).unwrap()
}

#[tokio::test]
async fn listener_enrolls_a_host_without_a_client_certificate() {
    use lodeline_server::allowlist::permits;
    let dir = tempfile::tempdir().unwrap();
    let st = state(dir.path(), true);
    let token = issue(&st, HOST, Duration::hours(1));
    let csr = make_csr(dir.path(), HOST);
    let addr = listen(dir.path(), st.clone()).await;
    let client = anon_client(dir.path()).build().unwrap();

    let (status, _, body) = post_listener(&client, addr, &enroll_body(&token, HOST, &csr))
        .await
        .unwrap();
    assert_eq!(status, 200, "body={body}");
    let cert = body["client_cert_pem"].as_str().unwrap();
    assert!(verify_leaf(dir.path(), &dir.path().join("ca.crt"), cert));
    assert!(
        cert_text(dir.path(), cert).contains(HOST),
        "CN/SAN carry host_id"
    );
    let hosts = std::fs::read_to_string(st.allowlist_path.as_ref().unwrap()).unwrap();
    assert!(hosts.contains(HOST), "host added to the allowlist file");
    assert!(permits(&st.allowlist.read(), HOST), "and in memory");
    let lines = audit_lines(&st.enroll.as_ref().unwrap().audit_path);
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0]["decision"], "issued");
    assert_eq!(lines[0]["caller_fingerprint"], "");
}

/// Every denial before the reserve answers like the main path, spends
/// nothing and writes no chain line; only the redeemed token is chained.
#[tokio::test]
async fn listener_denials_before_the_reserve_spend_nothing_and_are_not_chained() {
    let dir = tempfile::tempdir().unwrap();
    let st = state(dir.path(), true);
    let audit_path = st.enroll.as_ref().unwrap().audit_path.clone();
    let token = issue(&st, HOST, Duration::hours(1));
    let expired = issue(&st, HOST, Duration::seconds(-1));
    let csr = make_csr(dir.path(), HOST);
    let csr2 = make_csr(dir.path(), HOST2);
    let addr = listen(dir.path(), st.clone()).await;
    let client = anon_client(dir.path()).build().unwrap();
    let post = |b: serde_json::Value| {
        let client = client.clone();
        async move { post_listener(&client, addr, &b).await.unwrap() }
    };

    for (what, body) in [
        ("unknown token", enroll_body("x", HOST, &csr)),
        ("expired token", enroll_body(&expired, HOST, &csr)),
        ("host mismatch", enroll_body(&token, HOST2, &csr2)),
        ("cn mismatch", enroll_body(&token, HOST, &csr2)),
    ] {
        let (status, _, body) = post(body).await;
        assert_eq!(status, 403, "{what}: {body}");
        assert_eq!(body["error"]["code"], "enrollment_denied", "{what}");
    }
    let big = "A".repeat(listener::MAX_BODY + 1);
    let (status, _, _) = post(enroll_body(&token, HOST, &big)).await;
    assert_eq!(status, 413, "oversized body");
    let no_type = client
        .post(format!("https://127.0.0.1:{}/v1/enroll", addr.port()))
        .body(enroll_body(&token, HOST, &csr).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(no_type.status(), 415, "no content-type");
    assert!(audit_lines(&audit_path).is_empty(), "no chain line yet");

    let (status, _, body) = post(enroll_body(&token, HOST, &csr)).await;
    assert_eq!(status, 200, "token was not spent: {body}");
    let (status, _, _) = post(enroll_body(&token, HOST, &csr)).await;
    assert_eq!(status, 403, "spent token");
    let lines = audit_lines(&audit_path);
    assert_eq!(lines.len(), 1, "only the redeem is chained");
    assert_eq!(lines[0]["decision"], "issued");
}

#[tokio::test]
async fn listener_answers_busy_while_a_mint_holds_the_lock() {
    let dir = tempfile::tempdir().unwrap();
    let st = state(dir.path(), true);
    let token = issue(&st, HOST, Duration::hours(1));
    let csr = make_csr(dir.path(), HOST);
    let addr = listen(dir.path(), st.clone()).await;
    let client = anon_client(dir.path()).build().unwrap();

    let (locked_tx, locked_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let holder = {
        let st = st.clone();
        std::thread::spawn(move || {
            let _g = st.enroll.as_ref().unwrap().mint.lock().unwrap();
            locked_tx.send(()).unwrap();
            release_rx.recv().unwrap();
        })
    };
    locked_rx.recv().unwrap();
    let (status, headers, body) = post_listener(&client, addr, &enroll_body(&token, HOST, &csr))
        .await
        .unwrap();
    assert_eq!(status, 503, "{body}");
    assert_eq!(body["error"]["code"], "busy");
    assert_eq!(headers["retry-after"], "1");
    release_tx.send(()).unwrap();
    holder.join().unwrap();
    let (status, _, body) = post_listener(&client, addr, &enroll_body(&token, HOST, &csr))
        .await
        .unwrap();
    assert_eq!(status, 200, "same token after the lock is free: {body}");
}

#[tokio::test]
async fn listener_serves_only_post_enroll() {
    let dir = tempfile::tempdir().unwrap();
    let st = state(dir.path(), true);
    let addr = listen(dir.path(), st).await;
    let client = anon_client(dir.path()).build().unwrap();
    let url = |p: &str| format!("https://127.0.0.1:{}{p}", addr.port());
    for (method, path) in [
        (reqwest::Method::GET, "/v1/healthz"),
        (reqwest::Method::POST, "/v1/events"),
        (reqwest::Method::GET, "/v1/artifacts"),
        (reqwest::Method::GET, "/v1/enroll"),
    ] {
        let r = client
            .request(method.clone(), url(path))
            .send()
            .await
            .unwrap();
        assert!(
            r.status() == 404 || r.status() == 405,
            "{method} {path}: {}",
            r.status()
        );
    }
}

/// The limit is per connection, so the test fires back to back and needs no
/// wall-clock spacing: 20 connections inside one refill window cannot all pass.
#[tokio::test]
async fn listener_rate_limits_connections_per_source() {
    let dir = tempfile::tempdir().unwrap();
    let st = state(dir.path(), true);
    let addr = listen(dir.path(), st).await;
    let client = anon_client(dir.path()).build().unwrap();
    let body = enroll_body("x", HOST, "csr");
    let mut answered = 0;
    let mut refused = None;
    for i in 0..20 {
        match post_listener(&client, addr, &body).await {
            Ok((status, _, _)) => {
                assert_eq!(status, 403);
                answered += 1;
            }
            Err(e) => {
                assert!(e.is_connect(), "dropped before TLS: {e:?}");
                refused = Some(i);
                break;
            }
        }
    }
    assert!(answered >= 10, "the burst is served: {answered}");
    assert!(refused.is_some(), "a later connection is dropped");
}

/// HTTP/2 multiplexes streams on one connection; only the first reaches the
/// handler, the rest get 421 without it.
#[tokio::test]
async fn listener_serves_one_request_per_http2_connection() {
    let dir = tempfile::tempdir().unwrap();
    let st = state(dir.path(), true);
    let addr = listen(dir.path(), st).await;
    let client = anon_client(dir.path())
        .http2_prior_knowledge()
        .build()
        .unwrap();
    let body = enroll_body("x", HOST, "csr");
    let mut statuses = Vec::new();
    for _ in 0..20 {
        let (status, _, _) = post_listener(&client, addr, &body).await.unwrap();
        statuses.push(status.as_u16());
    }
    assert_eq!(statuses[0], 403, "{statuses:?}");
    assert!(statuses[1..].iter().all(|s| *s == 421), "{statuses:?}");
}

/// A raw TLS client to the listener, trusting the test CA.
async fn raw_tls(
    dir: &Path,
    addr: SocketAddr,
) -> tokio_rustls::client::TlsStream<tokio::net::TcpStream> {
    let mut roots = rustls::RootCertStore::empty();
    let pem = std::fs::read(dir.join("ca.crt")).unwrap();
    for c in rustls_pemfile::certs(&mut &pem[..]) {
        roots.add(c.unwrap()).unwrap();
    }
    let cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let name = rustls::pki_types::ServerName::try_from("127.0.0.1").unwrap();
    tokio_rustls::TlsConnector::from(Arc::new(cfg))
        .connect(name, tcp)
        .await
        .unwrap()
}

/// Two pipelined HTTP/1.1 keep-alive requests: one answer, then close.
#[tokio::test]
async fn listener_serves_one_request_per_http1_connection() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let dir = tempfile::tempdir().unwrap();
    let st = state(dir.path(), true);
    let addr = listen(dir.path(), st).await;
    let body = serde_json::to_string(&enroll_body("x", HOST, "csr")).unwrap();
    let req = format!(
        "POST /v1/enroll HTTP/1.1\r\nhost: 127.0.0.1\r\nconnection: keep-alive\r\n\
         content-type: application/json\r\ncontent-length: {}\r\n\r\n{body}",
        body.len()
    );
    let mut tls = raw_tls(dir.path(), addr).await;
    tls.write_all(format!("{req}{req}").as_bytes())
        .await
        .unwrap();
    let mut out = Vec::new();
    let _ = tls.read_to_end(&mut out).await;
    let out = String::from_utf8_lossy(&out);
    assert_eq!(out.matches("HTTP/1.1 ").count(), 1, "{out}");
    assert!(out.starts_with("HTTP/1.1 403"), "{out}");
    assert!(
        out.to_ascii_lowercase().contains("connection: close"),
        "{out}"
    );

    let client = anon_client(dir.path()).build().unwrap();
    for _ in 0..2 {
        let (status, headers, _) = post_listener(&client, addr, &enroll_body("x", HOST, "csr"))
            .await
            .unwrap();
        assert_eq!(status, 403);
        assert_eq!(headers["connection"], "close", "keep-alive client");
    }
}

#[tokio::test]
async fn listener_closes_an_idle_connection_near_the_deadline() {
    use tokio::io::AsyncReadExt;
    let dir = tempfile::tempdir().unwrap();
    let st = state(dir.path(), true);
    let addr = listen(dir.path(), st).await;
    let t0 = std::time::Instant::now();
    let mut tls = raw_tls(dir.path(), addr).await;
    let mut buf = [0u8; 64];
    let _ = tokio::time::timeout(
        listener::CONN_LIFETIME + std::time::Duration::from_secs(5),
        tls.read(&mut buf),
    )
    .await
    .expect("closed by the server before the test timeout");
    let took = t0.elapsed();
    assert!(
        took >= listener::CONN_LIFETIME - std::time::Duration::from_millis(500)
            && took <= listener::CONN_LIFETIME + std::time::Duration::from_secs(2),
        "{took:?}"
    );
}

/// The listener never asks for a client certificate, so a client that holds
/// a fleet certificate is still anonymous in the chain.
#[tokio::test]
async fn listener_never_reads_a_client_certificate() {
    let dir = tempfile::tempdir().unwrap();
    let st = state(dir.path(), true);
    let token = issue(&st, HOST, Duration::hours(1));
    let token2 = issue(&st, HOST2, Duration::hours(1));
    let csr = make_csr(dir.path(), HOST);
    let csr2 = make_csr(dir.path(), HOST2);
    let addr = listen(dir.path(), st.clone()).await;
    let (status, _, body) = post_listener(
        &anon_client(dir.path()).build().unwrap(),
        addr,
        &enroll_body(&token, HOST, &csr),
    )
    .await
    .unwrap();
    assert_eq!(status, 200);
    let mut identity = std::fs::read(dir.path().join(format!("{HOST}.key"))).unwrap();
    identity.extend_from_slice(body["client_cert_pem"].as_str().unwrap().as_bytes());
    let fleet = anon_client(dir.path())
        .identity(reqwest::Identity::from_pem(&identity).unwrap())
        .build()
        .unwrap();
    let (status, _, body) = post_listener(&fleet, addr, &enroll_body(&token2, HOST2, &csr2))
        .await
        .unwrap();
    assert_eq!(status, 200, "{body}");
    let lines = audit_lines(&st.enroll.as_ref().unwrap().audit_path);
    assert_eq!(lines.len(), 2);
    assert!(lines.iter().all(|l| l["caller_fingerprint"] == ""));
}

/// One `AppState` behind both listeners: one chain, one allowlist, one
/// single-use rule.
#[tokio::test]
async fn a_token_redeemed_through_each_listener_shares_one_chain() {
    let dir = tempfile::tempdir().unwrap();
    let st = state(dir.path(), true);
    let audit_path = st.enroll.as_ref().unwrap().audit_path.clone();
    let token_a = issue(&st, HOST, Duration::hours(1));
    let token_b = issue(&st, HOST2, Duration::hours(1));
    let csr_a = make_csr(dir.path(), HOST);
    let csr_b = make_csr(dir.path(), HOST2);
    let addr = listen(dir.path(), st.clone()).await;
    let client = anon_client(dir.path()).build().unwrap();
    let main = build_router(st.clone());
    let fleet_peer = || Some(peer_with_fingerprint(ISSUER_FP));

    let (status, _, body) = post_listener(&client, addr, &enroll_body(&token_a, HOST, &csr_a))
        .await
        .unwrap();
    assert_eq!(status, 200, "{body}");
    let (status, body) = post_enroll_as(&main, &token_b, HOST2, &csr_b, fleet_peer()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let hosts = std::fs::read_to_string(st.allowlist_path.as_ref().unwrap()).unwrap();
    assert!(hosts.contains(HOST) && hosts.contains(HOST2), "{hosts}");
    let lines = audit_lines(&audit_path);
    assert_eq!(lines.len(), 2);
    assert_eq!(
        (lines[0]["seq"].as_u64(), lines[1]["seq"].as_u64()),
        (Some(0), Some(1))
    );
    assert_eq!(lines[1]["prev_hash"], lines[0]["hash"]);
    assert_eq!(lines[0]["caller_fingerprint"], "");
    assert_eq!(lines[1]["caller_fingerprint"], ISSUER_FP);

    let (status, _) = post_enroll_as(&main, &token_a, HOST, &csr_a, fleet_peer()).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _, _) = post_listener(&client, addr, &enroll_body(&token_b, HOST2, &csr_b))
        .await
        .unwrap();
    assert_eq!(status, 403);
    let lines = audit_lines(&audit_path);
    assert_eq!(lines.len(), 3, "only the main path chains its denial");
    assert_eq!(lines[2]["reason"], "token_used");
    assert_eq!(lines[2]["prev_hash"], lines[1]["hash"]);
}

/// `serve` refuses an enroll_listener when enrollment is off (here: no
/// enroll paths), before it opens any socket.
#[test]
fn server_refuses_an_enroll_listener_without_enrollment() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("server.yaml");
    // Single-quoted YAML keeps Windows backslashes literal.
    let d = dir.path().display();
    std::fs::write(
        &cfg,
        format!(
            "bind: '127.0.0.1:0'\nevents_out_dir: '{d}/events'\n\
             policy_bundle_path: '{d}/policy.json'\ntls_cert_path: '{d}/s.crt'\n\
             tls_key_path: '{d}/s.key'\nclient_ca_path: '{d}/ca.pem'\n\
             events_require_cert_host_match: true\nenroll_listener:\n  bind: '127.0.0.1:1'\n"
        ),
    )
    .unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_lodeline-server"))
        .args(["serve", "--config"])
        .arg(&cfg)
        .env_remove("LODELINE_SERVER_READ_TOKEN")
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("enroll_listener is set but enrollment is off"),
        "{stderr}"
    );
}
