//! #553: `POST /v1/renew`. Test certificates come from rcgen with an exact
//! `notBefore` and `notAfter`; the route's rules run through `renew_at`, which takes
//! `now`, so a 30 day certificate can be renewed at day 16 and its successor at
//! day 46. The two live TLS tests at the end use a real handshake.
//!
//! Needs `openssl` on PATH, as the enroll tests do.

use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode};
use lodeline_server::app::{build_router, AppState};
use lodeline_server::auth::ReadToken;
use lodeline_server::enroll::audit::SignedEnrollmentRecord;
use lodeline_server::enroll::renewal::norm_serial;
use lodeline_server::enroll::tokens::TokenStore;
use lodeline_server::enroll::EnrollState;
use lodeline_server::fleet_index::FleetIndex;
use lodeline_server::persist::HighWater;
use lodeline_server::routes::renew::renew_at;
use lodeline_server::tls_accept::{PeerCertAcceptor, PeerIdentity};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, PublicKeyData, SanType,
};
use serde_json::Value;
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, Mutex};
use time::{Duration, OffsetDateTime};
use tower::ServiceExt;

const HOST: &str = "018f9c1a-0000-7000-8000-00000000aa01";
const OTHER: &str = "018f9c1a-0000-7000-8000-00000000aa02";

fn openssl() -> PathBuf {
    lodeline_server::enroll::sign::resolve_openssl().expect("openssl must be installed")
}

fn ca_named(name: &str) -> CertifiedIssuer<'static, KeyPair> {
    let key = KeyPair::generate().unwrap();
    let mut p = CertificateParams::new(vec![]).unwrap();
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p.distinguished_name.push(DnType::CommonName, name);
    CertifiedIssuer::self_signed(p, key).unwrap()
}

/// A client certificate for `cn` valid from `nb` to `na`.
fn leaf(
    issuer: &CertifiedIssuer<'_, KeyPair>,
    key: &KeyPair,
    cn: &str,
    nb: OffsetDateTime,
    na: OffsetDateTime,
) -> String {
    let mut p = CertificateParams::new(vec![cn.to_string()]).unwrap();
    p.distinguished_name.push(DnType::CommonName, cn);
    p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    p.not_before = nb;
    p.not_after = na;
    p.signed_by(key, issuer).unwrap().pem()
}

fn csr(cn: &str, key: &KeyPair) -> String {
    let mut p = CertificateParams::new(vec![]).unwrap();
    p.distinguished_name.push(DnType::CommonName, cn);
    p.serialize_request(key).unwrap().pem().unwrap()
}

fn der(pem: &str) -> Vec<u8> {
    rustls_pemfile::certs(&mut pem.as_bytes())
        .next()
        .unwrap()
        .unwrap()
        .to_vec()
}

fn peer(pem: &str) -> PeerIdentity {
    PeerIdentity::from_der(&der(pem))
}

fn now() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}

/// A 30 day certificate that is `age_days` old now.
fn aged(env: &Env, key: &KeyPair, cn: &str, age: Duration) -> String {
    let nb = now() - age;
    leaf(&env.ca, key, cn, nb, nb + Duration::days(30))
}

struct Env {
    dir: tempfile::TempDir,
    ca: CertifiedIssuer<'static, KeyPair>,
}

impl Env {
    fn new() -> Env {
        let dir = tempfile::tempdir().unwrap();
        // An RSA enrollment CA made by openssl, as in the enroll tests: openssl signs
        // with SHA-256 for RSA on every platform, and with SHA-1 for EC on LibreSSL.
        let key = dir.path().join("ca.key");
        let o = Command::new(openssl())
            .args([
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
                "-out",
            ])
            .arg(&key)
            .output()
            .unwrap();
        assert!(o.status.success());
        let pair = KeyPair::from_pem_and_sign_algo(
            &std::fs::read_to_string(&key).unwrap(),
            &rcgen::PKCS_RSA_SHA256,
        )
        .unwrap();
        let mut p = CertificateParams::new(vec![]).unwrap();
        p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        p.distinguished_name.push(DnType::CommonName, "enroll-ca");
        let ca = CertifiedIssuer::self_signed(p, pair).unwrap();
        std::fs::write(dir.path().join("ca.crt"), ca.pem()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        Env { dir, ca }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn audit(&self) -> PathBuf {
        self.path("enrollment-audit.jsonl")
    }

    /// A server over this directory. `hosts` rewrites the allowlist; `None` keeps it.
    fn state_with(&self, hosts: Option<&[&str]>, enroll: bool) -> Arc<AppState> {
        let allowlist_path = self.path("hosts.json");
        if let Some(hosts) = hosts {
            let body = serde_json::json!({ "hosts": hosts });
            std::fs::write(&allowlist_path, body.to_string()).unwrap();
        }
        let allowlist = lodeline_server::allowlist::load(Some(&allowlist_path)).unwrap();
        let en = enroll
            .then(|| {
                EnrollState::load(
                    Some(&self.path("ca.crt")),
                    Some(&self.path("ca.key")),
                    Some(&self.path("tokens.json")),
                    Some(&allowlist_path),
                    true,
                    Some(30),
                    self.audit(),
                    None,
                )
            })
            .flatten();
        let audit_key = lodeline_server::audit_key::AuditKey::load_or_create(self.dir.path());
        Arc::new(AppState {
            events_out_dir: self.dir.path().to_path_buf(),
            policy_bundle_path: self.path("signed-policy.json"),
            rule_packs_bundle_path: None,
            artifacts_dir: None,
            high_water_path: self.path(".high-water.json"),
            allowlist: parking_lot::RwLock::new(allowlist),
            high_water: Mutex::new(HighWater::default()),
            fleet_index: FleetIndex::new(),
            read_token: ReadToken(None),
            active_window_days: 7,
            audit_key,
            audit_head: Mutex::new(None),
            allowlist_path: Some(allowlist_path),
            enroll: en,
            events_require_cert_host_match: false,
        })
    }

    fn state(&self, hosts: &[&str]) -> Arc<AppState> {
        self.state_with(Some(hosts), true)
    }

    /// A restart: a new state over the same files.
    fn restart(&self) -> Arc<AppState> {
        self.state_with(None, true)
    }

    fn audit_lines(&self) -> Vec<Value> {
        std::fs::read_to_string(self.audit())
            .unwrap_or_default()
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    fn lines_with(&self, decision: &str, reason: &str) -> usize {
        self.audit_lines()
            .iter()
            .filter(|l| l["decision"] == decision && l["reason"] == reason)
            .count()
    }

    /// The real enroll route, as a host redeeming a token. Returns the 200 body.
    async fn enroll(&self, st: &Arc<AppState>, host: &str, key: &KeyPair) -> Value {
        let en = st.enroll.as_ref().unwrap();
        let t = now();
        let token = TokenStore::issue(&en.tokens_path, host, t + Duration::hours(1), t).unwrap();
        let body = serde_json::json!({
            "token": token, "host_id": host, "csr_pem": csr(host, key),
        });
        let resp = build_router(st.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/enroll")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = resp.status();
        let (_, json) = read(resp).await;
        assert_eq!(status, StatusCode::OK, "{json}");
        json
    }
}

async fn read(resp: axum::response::Response) -> (HeaderMap, Value) {
    let headers = resp.headers().clone();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        headers,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn call(
    st: &Arc<AppState>,
    who: Option<&PeerIdentity>,
    csr_pem: &str,
    at: OffsetDateTime,
) -> (StatusCode, HeaderMap, Value) {
    let resp = renew_at(st, who, csr_pem, at);
    let status = resp.status();
    let (h, b) = read(resp).await;
    (status, h, b)
}

fn spki_of_cert(pem: &str) -> Vec<u8> {
    let d = der(pem);
    let (_, c) = x509_parser::parse_x509_certificate(&d).unwrap();
    c.public_key().raw.to_vec()
}

fn openssl_verifies(env: &Env, leaf_pem: &str) -> bool {
    let f = env.path("check.crt");
    std::fs::write(&f, leaf_pem).unwrap();
    Command::new(openssl())
        .args(["verify", "-CAfile"])
        .arg(env.path("ca.crt"))
        .arg(&f)
        .output()
        .unwrap()
        .status
        .success()
}

#[tokio::test]
async fn in_window_renewal_issues_a_verifiable_cert_for_the_new_key() {
    let env = Env::new();
    let st = env.state(&[HOST]);
    assert!(!env.audit().exists(), "no audit file: no heads, renewal on");
    let old_key = KeyPair::generate().unwrap();
    let old = aged(&env, &old_key, HOST, Duration::days(20));
    let new_key = KeyPair::generate().unwrap();
    let csr_pem = csr(HOST, &new_key);

    let (status, _, body) = call(&st, Some(&peer(&old)), &csr_pem, now()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let cert = body["client_cert_pem"].as_str().unwrap();
    assert_eq!(body["host_id"], HOST);
    assert!(body["ca_chain_pem"]
        .as_str()
        .unwrap()
        .contains("BEGIN CERTIFICATE"));
    assert!(openssl_verifies(&env, cert), "verifies against the CA");
    assert_eq!(
        spki_of_cert(cert),
        new_key.subject_public_key_info(),
        "new key"
    );
    let d = der(cert);
    let (_, c) = x509_parser::parse_x509_certificate(&d).unwrap();
    let days = (c.validity().not_after.timestamp() - now().unix_timestamp()) / 86400;
    assert!((29..=30).contains(&days), "enroll_cert_days out: {days}");
    let san = c.subject_alternative_name().unwrap().unwrap();
    assert_eq!(san.value.general_names.len(), 1);

    let lines = env.audit_lines();
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0]["decision"], "issued");
    assert_eq!(lines[0]["reason"], "renewed");
    assert_eq!(lines[0]["host_id"], HOST);
    assert_eq!(
        lines[0]["caller_fingerprint"],
        blake3::hash(&der(&old)).to_hex().to_string()
    );
    assert_eq!(
        lines[0]["csr_fingerprint"],
        blake3::hash(csr_pem.as_bytes()).to_hex().to_string()
    );
    assert_eq!(
        norm_serial(lines[0]["serial"].as_str().unwrap()),
        norm_serial(body["serial"].as_str().unwrap())
    );
}

#[tokio::test]
async fn before_half_of_the_validity_is_409_with_retry_after_and_writes_nothing() {
    let env = Env::new();
    let st = env.state(&[HOST]);
    let key = KeyPair::generate().unwrap();
    let csr_pem = csr(HOST, &KeyPair::generate().unwrap());

    let young = aged(&env, &key, HOST, Duration::days(5));
    let (status, h, _) = call(&st, Some(&peer(&young)), &csr_pem, now()).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(h["retry-after"], "3600", "capped at one hour");

    let near = aged(&env, &key, HOST, Duration::days(15) - Duration::seconds(90));
    let (status, h, _) = call(&st, Some(&peer(&near)), &csr_pem, now()).await;
    assert_eq!(status, StatusCode::CONFLICT);
    let wait: i64 = h["retry-after"].to_str().unwrap().parse().unwrap();
    assert!(
        (85..=95).contains(&wait),
        "seconds to the half point: {wait}"
    );

    assert!(!env.audit().exists(), "nothing written");
    assert!(st
        .enroll
        .as_ref()
        .unwrap()
        .renewal
        .as_ref()
        .unwrap()
        .head(HOST)
        .is_none());
}

#[tokio::test]
async fn an_expired_peer_on_a_live_request_is_refused() {
    let env = Env::new();
    let st = env.state(&[HOST]);
    let old = aged(
        &env,
        &KeyPair::generate().unwrap(),
        HOST,
        Duration::days(20),
    );
    let csr_pem = csr(HOST, &KeyPair::generate().unwrap());
    // Valid at the real time, past its notAfter at the request's `now`.
    let (status, _, _) = call(&st, Some(&peer(&old)), &csr_pem, now() + Duration::days(11)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(!env.audit().exists());
}

#[tokio::test]
async fn a_host_off_the_allowlist_is_refused() {
    let env = Env::new();
    let st = env.state(&[OTHER]);
    let old = aged(
        &env,
        &KeyPair::generate().unwrap(),
        HOST,
        Duration::days(20),
    );
    let csr_pem = csr(HOST, &KeyPair::generate().unwrap());
    let (status, _, _) = call(&st, Some(&peer(&old)), &csr_pem, now()).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(!env.audit().exists());
}

#[tokio::test]
async fn a_leaf_from_another_ca_is_refused_even_with_the_same_subject_name() {
    let env = Env::new();
    let st = env.state(&[HOST]);
    let csr_pem = csr(HOST, &KeyPair::generate().unwrap());
    let nb = now() - Duration::days(20);
    let make = |name: &str| {
        let other = ca_named(name);
        leaf(
            &other,
            &KeyPair::generate().unwrap(),
            HOST,
            nb,
            nb + Duration::days(30),
        )
    };
    // Same subject name as the enrollment CA, different key: a name-only issuer check passes it.
    let same_name = make("enroll-ca");
    let other_name = make("another-ca");
    for pem in [same_name, other_name] {
        let (status, _, _) = call(&st, Some(&peer(&pem)), &csr_pem, now()).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }
    assert!(!env.audit().exists());
}

#[tokio::test]
async fn a_cn_that_is_not_a_uuid_or_no_peer_is_refused() {
    let env = Env::new();
    let st = env.state(&["not-a-uuid", HOST]);
    let csr_pem = csr("not-a-uuid", &KeyPair::generate().unwrap());
    let bad = aged(
        &env,
        &KeyPair::generate().unwrap(),
        "not-a-uuid",
        Duration::days(20),
    );
    let (status, _, _) = call(&st, Some(&peer(&bad)), &csr_pem, now()).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _, _) = call(&st, None, &csr(HOST, &KeyPair::generate().unwrap()), now()).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn a_csr_for_another_host_is_400() {
    let env = Env::new();
    let st = env.state(&[HOST, OTHER]);
    let old = aged(
        &env,
        &KeyPair::generate().unwrap(),
        HOST,
        Duration::days(20),
    );
    let csr_pem = csr(OTHER, &KeyPair::generate().unwrap());
    let (status, _, _) = call(&st, Some(&peer(&old)), &csr_pem, now()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(!env.audit().exists());
}

#[tokio::test]
async fn a_csr_carrying_the_presented_certificates_key_is_400() {
    let env = Env::new();
    let st = env.state(&[HOST]);
    let key = KeyPair::generate().unwrap();
    let old = aged(&env, &key, HOST, Duration::days(20));
    let (status, _, body) = call(&st, Some(&peer(&old)), &csr(HOST, &key), now()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(!env.audit().exists());
}

#[tokio::test]
async fn a_certificate_that_is_no_longer_the_head_cannot_renew_with_another_csr() {
    let env = Env::new();
    let st = env.state(&[HOST]);
    let old = peer(&aged(
        &env,
        &KeyPair::generate().unwrap(),
        HOST,
        Duration::days(20),
    ));
    let first = csr(HOST, &KeyPair::generate().unwrap());
    let (status, _, _) = call(&st, Some(&old), &first, now()).await;
    assert_eq!(status, StatusCode::OK);

    let other = csr(HOST, &KeyPair::generate().unwrap());
    let (status, _, _) = call(&st, Some(&old), &other, now()).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(env.lines_with("issued", "renewed"), 1);
}

#[tokio::test]
async fn the_same_csr_may_repeat_and_the_fourth_issuance_is_refused() {
    let env = Env::new();
    let st = env.state(&[HOST]);
    let old = peer(&aged(
        &env,
        &KeyPair::generate().unwrap(),
        HOST,
        Duration::days(20),
    ));
    let same = csr(HOST, &KeyPair::generate().unwrap());
    let mut serials = Vec::new();
    for _ in 0..3 {
        let (status, _, body) = call(&st, Some(&old), &same, now()).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        serials.push(body["serial"].as_str().unwrap().to_string());
    }
    serials.dedup();
    assert_eq!(serials.len(), 3, "a fresh certificate each time");
    let (status, _, _) = call(&st, Some(&old), &same, now()).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "fourth issuance");
    assert_eq!(env.lines_with("issued", "renewed"), 3);
}

#[tokio::test]
async fn a_re_enrollment_cuts_off_a_certificate_from_the_older_chain() {
    let env = Env::new();
    let st = env.state(&[HOST]);
    let old = aged(
        &env,
        &KeyPair::generate().unwrap(),
        HOST,
        Duration::days(20),
    );
    let (status, _, body) = call(
        &st,
        Some(&peer(&old)),
        &csr(HOST, &KeyPair::generate().unwrap()),
        now(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let renewed = peer(body["client_cert_pem"].as_str().unwrap());
    let later = now() + Duration::days(16);
    let fresh = csr(HOST, &KeyPair::generate().unwrap());

    let enrolled = env.enroll(&st, HOST, &KeyPair::generate().unwrap()).await;
    let (status, _, _) = call(&st, Some(&renewed), &fresh, later).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "the older chain is cut off");
    let newest = peer(enrolled["client_cert_pem"].as_str().unwrap());
    let (status, _, body) = call(&st, Some(&newest), &fresh, later).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the re-enrolled certificate renews: {body}"
    );
}

#[tokio::test]
async fn only_the_first_denial_per_presented_certificate_is_chained() {
    let env = Env::new();
    let st = env.state(&[HOST]);
    let old = peer(&aged(
        &env,
        &KeyPair::generate().unwrap(),
        HOST,
        Duration::days(20),
    ));
    let (status, _, _) = call(
        &st,
        Some(&old),
        &csr(HOST, &KeyPair::generate().unwrap()),
        now(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    for _ in 0..3 {
        let other = csr(HOST, &KeyPair::generate().unwrap());
        let (status, _, _) = call(&st, Some(&old), &other, now()).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }
    assert_eq!(env.lines_with("denied", "renewal_superseded"), 1);
    assert_eq!(env.audit_lines().len(), 2);
    // A restart remembers it as well.
    let st2 = env.restart();
    let other = csr(HOST, &KeyPair::generate().unwrap());
    let (status, _, _) = call(&st2, Some(&old), &other, now()).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(env.lines_with("denied", "renewal_superseded"), 1);
}

#[tokio::test]
async fn a_successor_renews_at_its_own_half_point() {
    let env = Env::new();
    let st = env.state(&[HOST]);
    // Day 16 of 30: the first certificate renews.
    let c0 = peer(&aged(
        &env,
        &KeyPair::generate().unwrap(),
        HOST,
        Duration::days(16),
    ));
    let (status, _, body) = call(
        &st,
        Some(&c0),
        &csr(HOST, &KeyPair::generate().unwrap()),
        now(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let c1 = peer(body["client_cert_pem"].as_str().unwrap());
    let next = csr(HOST, &KeyPair::generate().unwrap());

    // The successor is 1 day old at day 17 and 31 days old past its own expiry.
    let (status, _, _) = call(&st, Some(&c1), &next, now() + Duration::days(1)).await;
    assert_eq!(status, StatusCode::CONFLICT, "too early for the successor");
    // Day 46 counted from the first certificate is 15 days and 1 hour into the successor.
    let (status, _, body) = call(
        &st,
        Some(&c1),
        &next,
        now() + Duration::days(15) + Duration::hours(1),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn a_restart_keeps_the_head() {
    let env = Env::new();
    let st = env.state(&[HOST]);
    let first = env.enroll(&st, HOST, &KeyPair::generate().unwrap()).await;
    let e0 = peer(first["client_cert_pem"].as_str().unwrap());
    let later = now() + Duration::days(16);
    let same = csr(HOST, &KeyPair::generate().unwrap());
    let (status, _, _) = call(&st, Some(&e0), &same, later).await;
    assert_eq!(status, StatusCode::OK);

    let st2 = env.restart();
    let other = csr(HOST, &KeyPair::generate().unwrap());
    let (status, _, _) = call(&st2, Some(&e0), &other, later).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "the predecessor with another CSR"
    );
    let (status, _, body) = call(&st2, Some(&e0), &same, later).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the predecessor with the same CSR: {body}"
    );
}

#[tokio::test]
async fn a_bad_line_in_the_audit_file_is_skipped_and_the_heads_survive() {
    let env = Env::new();
    let st = env.state(&[]);
    let a = env.enroll(&st, HOST, &KeyPair::generate().unwrap()).await;
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(env.audit())
        .unwrap();
    f.write_all(b"this line is not json\n").unwrap();
    drop(f);
    let b = env.enroll(&st, OTHER, &KeyPair::generate().unwrap()).await;

    let st2 = env.restart();
    let rn = st2
        .enroll
        .as_ref()
        .unwrap()
        .renewal
        .as_ref()
        .expect("renewal on");
    assert_eq!(
        rn.head(HOST).unwrap().serial,
        norm_serial(a["serial"].as_str().unwrap())
    );
    assert_eq!(
        rn.head(OTHER).unwrap().serial,
        norm_serial(b["serial"].as_str().unwrap())
    );
}

#[tokio::test]
async fn an_unreadable_audit_file_turns_renewal_off_and_leaves_enrollment_on() {
    let env = Env::new();
    // A directory where the file should be: reading it fails with an error other than not-found.
    std::fs::create_dir(env.audit()).unwrap();
    let st = env.state(&[HOST]);
    let en = st.enroll.as_ref().expect("enrollment stays on");
    assert!(en.renewal.is_none());
    let old = aged(
        &env,
        &KeyPair::generate().unwrap(),
        HOST,
        Duration::days(20),
    );
    let (status, _, _) = call(
        &st,
        Some(&peer(&old)),
        &csr(HOST, &KeyPair::generate().unwrap()),
        now(),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_failed_audit_append_is_a_500_that_changes_nothing_and_a_retry_succeeds() {
    let env = Env::new();
    let st = env.state(&[HOST]);
    let old = peer(&aged(
        &env,
        &KeyPair::generate().unwrap(),
        HOST,
        Duration::days(20),
    ));
    let same = csr(HOST, &KeyPair::generate().unwrap());
    std::fs::create_dir(env.audit()).unwrap();
    let (status, _, body) = call(&st, Some(&old), &same, now()).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(
        body.get("client_cert_pem").is_none(),
        "no certificate in the answer"
    );
    assert!(st
        .enroll
        .as_ref()
        .unwrap()
        .renewal
        .as_ref()
        .unwrap()
        .head(HOST)
        .is_none());

    std::fs::remove_dir(env.audit()).unwrap();
    let (status, _, body) = call(&st, Some(&old), &same, now()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(env.lines_with("issued", "renewed"), 1);
}

#[tokio::test]
async fn enrollment_off_is_404() {
    let env = Env::new();
    let st = env.state_with(Some(&[HOST]), false);
    let old = aged(
        &env,
        &KeyPair::generate().unwrap(),
        HOST,
        Duration::days(20),
    );
    let (status, _, _) = call(
        &st,
        Some(&peer(&old)),
        &csr(HOST, &KeyPair::generate().unwrap()),
        now(),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[test]
fn a_409_returns_while_another_thread_holds_the_mint_lock() {
    let env = Env::new();
    let st = env.state(&[HOST]);
    let young = aged(&env, &KeyPair::generate().unwrap(), HOST, Duration::days(5));
    let who = peer(&young);
    let csr_pem = csr(HOST, &KeyPair::generate().unwrap());
    let st2 = st.clone();
    let _held = st.enroll.as_ref().unwrap().mint.lock().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(renew_at(&st2, Some(&who), &csr_pem, now()).status());
    });
    let status = rx
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect("the cheap gates must not wait for the mint lock");
    assert_eq!(status, StatusCode::CONFLICT);
}

#[test]
fn signing_and_the_audit_write_wait_for_the_mint_lock() {
    let env = Env::new();
    let st = env.state(&[HOST]);
    let who = peer(&aged(
        &env,
        &KeyPair::generate().unwrap(),
        HOST,
        Duration::days(20),
    ));
    let csr_pem = csr(HOST, &KeyPair::generate().unwrap());
    let st2 = st.clone();
    let held = st.enroll.as_ref().unwrap().mint.lock().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(renew_at(&st2, Some(&who), &csr_pem, now()).status());
    });
    assert!(
        rx.recv_timeout(std::time::Duration::from_millis(1500))
            .is_err(),
        "an issuance must not run while another thread holds the mint lock"
    );
    assert!(!env.audit().exists());
    drop(held);
    let status = rx.recv_timeout(std::time::Duration::from_secs(30)).unwrap();
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn renewals_and_enrollments_at_once_leave_one_unbroken_chain() {
    let env = Env::new();
    let hosts: Vec<String> = (0..6)
        .map(|i| format!("018f9c1a-0000-7000-8000-00000000bb{i:02}"))
        .collect();
    let refs: Vec<&str> = hosts.iter().map(String::as_str).collect();
    let st = env.state(&refs);
    for h in &hosts {
        let old = peer(&aged(
            &env,
            &KeyPair::generate().unwrap(),
            h,
            Duration::days(20),
        ));
        let csr_pem = csr(h, &KeyPair::generate().unwrap());
        let st1 = st.clone();
        let renew = tokio::task::spawn_blocking(move || {
            renew_at(&st1, Some(&old), &csr_pem, now()).status()
        });
        let enroll_key = KeyPair::generate().unwrap();
        let enroll = env.enroll(&st, h, &enroll_key);
        let (r, _) = tokio::join!(renew, enroll);
        assert_eq!(r.unwrap(), StatusCode::OK);
    }
    let text = std::fs::read_to_string(env.audit()).unwrap();
    let mut prev = "0".repeat(64);
    let mut n = 0;
    for (i, l) in text.lines().enumerate() {
        let s: SignedEnrollmentRecord = serde_json::from_str(l).unwrap();
        assert_eq!(s.record.seq, i as u64, "no gap");
        assert_eq!(s.record.prev_hash, prev, "no fork");
        prev = s.hash;
        n += 1;
    }
    assert_eq!(n, 12, "six renewals and six enrollments");
}

#[tokio::test]
async fn a_body_over_the_cap_is_413_and_other_content_types_are_refused() {
    let env = Env::new();
    let st = env.state(&[HOST]);
    let old = Arc::new(peer(&aged(
        &env,
        &KeyPair::generate().unwrap(),
        HOST,
        Duration::days(20),
    )));
    let post = |ct: &str, body: String| {
        let req = Request::builder()
            .method("POST")
            .uri("/v1/renew")
            .header("content-type", ct)
            .extension(old.clone())
            .body(Body::from(body))
            .unwrap();
        build_router(st.clone()).oneshot(req)
    };
    let big = serde_json::json!({ "csr_pem": "A".repeat(40 * 1024) }).to_string();
    assert_eq!(
        post("application/json", big).await.unwrap().status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
    assert_eq!(
        post("text/plain", "{}".into()).await.unwrap().status(),
        StatusCode::UNSUPPORTED_MEDIA_TYPE
    );
}

/// A live mutual TLS server whose client CA is the enrollment CA. Counts the
/// requests that reach the router.
struct Live {
    url: String,
    hits: Arc<std::sync::atomic::AtomicUsize>,
    handle: axum_server::Handle,
}

async fn live(env: &Env, st: Arc<AppState>) -> Live {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let srv_key = KeyPair::generate().unwrap();
    let mut p = CertificateParams::new(vec![]).unwrap();
    p.subject_alt_names = vec![SanType::IpAddress("127.0.0.1".parse().unwrap())];
    p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let srv_pem = p.signed_by(&srv_key, &env.ca).unwrap().pem();
    let certs = vec![rustls::pki_types::CertificateDer::from(der(&srv_pem))];
    let key = rustls_pemfile::private_key(&mut srv_key.serialize_pem().as_bytes())
        .unwrap()
        .unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls::pki_types::CertificateDer::from(der(&env.ca.pem())))
        .unwrap();
    let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .unwrap();
    let cfg = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)
        .unwrap();
    let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = hits.clone();
    let app = build_router(st).layer(axum::middleware::from_fn(
        move |req: axum::extract::Request, next: axum::middleware::Next| {
            let counter = counter.clone();
            async move {
                counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                next.run(req).await
            }
        },
    ));
    let handle = axum_server::Handle::new();
    let h = handle.clone();
    let tls = axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(cfg));
    tokio::spawn(async move {
        axum_server::bind("127.0.0.1:0".parse().unwrap())
            .handle(h)
            .acceptor(PeerCertAcceptor::new(tls))
            .serve(app.into_make_service())
            .await
            .unwrap();
    });
    let addr = handle.listening().await.expect("server must bind");
    Live {
        url: format!("https://127.0.0.1:{}/v1/renew", addr.port()),
        hits,
        handle,
    }
}

fn client(env: &Env, cert_pem: &str, key: &KeyPair) -> reqwest::Client {
    let id = format!("{}{}", key.serialize_pem(), cert_pem);
    reqwest::Client::builder()
        .use_rustls_tls()
        .add_root_certificate(reqwest::Certificate::from_pem(env.ca.pem().as_bytes()).unwrap())
        .identity(reqwest::Identity::from_pem(id.as_bytes()).unwrap())
        .build()
        .unwrap()
}

#[tokio::test]
async fn live_tls_a_leaf_past_its_notafter_fails_the_handshake_and_the_handler_never_runs() {
    let env = Env::new();
    let live = live(&env, env.state(&[HOST])).await;
    let key = KeyPair::generate().unwrap();
    let nb = now() - Duration::days(40);
    let expired = leaf(&env.ca, &key, HOST, nb, nb + Duration::days(30));
    let body = serde_json::json!({ "csr_pem": csr(HOST, &KeyPair::generate().unwrap()) });
    let res = client(&env, &expired, &key)
        .post(&live.url)
        .json(&body)
        .send()
        .await;
    assert!(res.is_err(), "the handshake must fail");
    assert_eq!(
        live.hits.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "no request reached the router"
    );
    live.handle.shutdown();
}

#[tokio::test]
async fn live_tls_a_valid_leaf_in_its_window_gets_200_over_a_real_handshake() {
    let env = Env::new();
    let live = live(&env, env.state(&[HOST])).await;
    let key = KeyPair::generate().unwrap();
    let cert = aged(&env, &key, HOST, Duration::days(20));
    let new_key = KeyPair::generate().unwrap();
    let body = lodeline_fleet_api::renewal::RenewRequest {
        csr_pem: csr(HOST, &new_key),
    };
    let resp = client(&env, &cert, &key)
        .post(&live.url)
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let answer: lodeline_fleet_api::renewal::RenewResponse = resp.json().await.unwrap();
    assert_eq!(answer.host_id, HOST);
    assert_eq!(
        spki_of_cert(&answer.client_cert_pem),
        new_key.subject_public_key_info()
    );
    assert_eq!(live.hits.load(std::sync::atomic::Ordering::SeqCst), 1);
    live.handle.shutdown();
}
