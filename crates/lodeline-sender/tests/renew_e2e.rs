//! #553: the sender renews its own certificate and key.
//!
//! Scenario tests drive one wake of the renewer at a time (`Renewer::step` takes the
//! clock) against a mock `POST /v1/renew` that signs with the real signer. The
//! headline test runs the real server and the real sender runtime and checks that a
//! host is still served with a fresh certificate after its first one has expired.
//!
//! Needs `openssl` on PATH, as the server's enroll tests do.
#![cfg(unix)]

mod common;

use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use axum::routing::post;
use axum::{Json, Router};
use lodeline_fleet_api::renewal::RenewRequest;
use lodeline_sender::heartbeat::{self, SharedStats};
use lodeline_sender::renew::pair::{leaf, Paths};
use lodeline_sender::renew::{RenewCtx, Renewer};
use lodeline_sender::transport::ClientHandle;
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair,
};
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, Mutex};
use time::{Duration, OffsetDateTime};
use tokio_util::sync::CancellationToken;

const HOST: &str = "3f2c6a1e-8b4d-4c2a-9e7f-1a2b3c4d5e6f";
const OTHER: &str = "5a1c6a1e-8b4d-4c2a-9e7f-1a2b3c4d5e70";

fn openssl() -> PathBuf {
    lodeline_server::enroll::sign::resolve_openssl().expect("openssl must be installed")
}

/// An RSA enrollment CA made by openssl, as the server's tests do: the signer then
/// uses SHA-256 on every platform.
struct Pki {
    dir: tempfile::TempDir,
    ca: CertifiedIssuer<'static, KeyPair>,
}

impl Pki {
    fn new() -> Pki {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("ca.key");
        let out = Command::new(openssl())
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
        assert!(out.status.success());
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
        std::fs::set_permissions(&key, std::os::unix::fs::PermissionsExt::from_mode(0o600))
            .unwrap();
        Pki { dir, ca }
    }

    fn files(&self) -> CaFiles {
        CaFiles {
            crt: self.dir.path().join("ca.crt"),
            key: self.dir.path().join("ca.key"),
            pem: self.ca.pem(),
        }
    }

    /// A client certificate for `key`, valid from `nb` to `na`, followed by the CA.
    fn mint(&self, key: &KeyPair, host: &str, nb: OffsetDateTime, na: OffsetDateTime) -> String {
        let mut p = CertificateParams::new(vec![host.to_string()]).unwrap();
        p.distinguished_name.push(DnType::CommonName, host);
        p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        p.not_before = nb;
        p.not_after = na;
        format!(
            "{}{}",
            p.signed_by(key, &self.ca).unwrap().pem(),
            self.ca.pem()
        )
    }
}

#[derive(Clone)]
struct CaFiles {
    crt: PathBuf,
    key: PathBuf,
    pem: String,
}

impl CaFiles {
    /// What the real signer makes for a CSR: 30 days, SAN pinned to `host`, then the CA.
    fn sign(&self, csr: &str, host: &str) -> String {
        let cert = lodeline_server::enroll::sign::sign_csr(
            &openssl(),
            &self.crt,
            &self.key,
            csr,
            host,
            30,
        )
        .unwrap();
        format!("{cert}{}", self.pem)
    }
}

/// A host's files: the live pair and the CA, in one directory.
struct Host {
    dir: tempfile::TempDir,
    paths: Paths,
}

impl Host {
    /// A pair whose certificate runs from `nb` to `na`.
    fn new(pki: &Pki, nb: OffsetDateTime, na: OffsetDateTime) -> Host {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::new(
            &dir.path().join("client.crt"),
            &dir.path().join("client.key"),
            &dir.path().join("server-ca.pem"),
        );
        let host = Host { dir, paths };
        host.install(pki, nb, na);
        std::fs::write(&host.paths.ca, pki.ca.pem()).unwrap();
        host
    }

    /// What `enroll` does: a new key and certificate in the live names.
    fn install(&self, pki: &Pki, nb: OffsetDateTime, na: OffsetDateTime) {
        let key = KeyPair::generate().unwrap();
        std::fs::write(&self.paths.key, key.serialize_pem()).unwrap();
        std::fs::write(&self.paths.crt, pki.mint(&key, HOST, nb, na)).unwrap();
    }

    fn crt(&self) -> String {
        std::fs::read_to_string(&self.paths.crt).unwrap()
    }

    fn key(&self) -> String {
        std::fs::read_to_string(&self.paths.key).unwrap()
    }

    fn not_after(&self) -> i64 {
        leaf(self.crt().as_bytes()).unwrap().not_after
    }

    fn next_files(&self) -> Vec<bool> {
        [
            &self.paths.key_next,
            &self.paths.csr_next,
            &self.paths.crt_next,
        ]
        .iter()
        .map(|p| p.exists())
        .collect()
    }

    fn renewer(&self, url: &str) -> (Renewer, SharedStats, ClientHandle) {
        let (stats, client) = (
            heartbeat::shared(),
            ClientHandle::from(reqwest::Client::new()),
        );
        let paths = &self.paths;
        let r = Renewer::new(RenewCtx {
            client: client.clone(),
            stats: stats.clone(),
            server_base_url: url.to_string(),
            host_id: HOST.to_string(),
            paths: Paths::new(&paths.crt, &paths.key, &paths.ca),
            shutdown: CancellationToken::new(),
        });
        (r, stats, client)
    }
}

/// A reply of the mock: status, `Retry-After`, body.
type Reply = (u16, Option<&'static str>, String);

/// `POST /v1/renew`, answered by `reply(n, csr)` for the n-th request. Keeps the CSRs.
struct Mock {
    url: String,
    csrs: Arc<Mutex<Vec<String>>>,
}

type Replier = Box<dyn Fn(usize, &str) -> Reply + Send + Sync>;

struct MockState {
    csrs: Arc<Mutex<Vec<String>>>,
    reply: Replier,
}

impl Mock {
    async fn start(reply: impl Fn(usize, &str) -> Reply + Send + Sync + 'static) -> Mock {
        Mock::on("127.0.0.1:0", reply).await
    }

    async fn on(addr: &str, reply: impl Fn(usize, &str) -> Reply + Send + Sync + 'static) -> Mock {
        let csrs = Arc::new(Mutex::new(Vec::new()));
        let st = Arc::new(MockState {
            csrs: csrs.clone(),
            reply: Box::new(reply),
        });
        let app = Router::new()
            .route("/v1/renew", post(handle))
            .with_state(st);
        let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Mock { url, csrs }
    }

    fn hits(&self) -> usize {
        self.csrs.lock().unwrap().len()
    }
}

async fn handle(
    State(st): State<Arc<MockState>>,
    Json(req): Json<RenewRequest>,
) -> impl IntoResponse {
    let n = {
        let mut csrs = st.csrs.lock().unwrap();
        csrs.push(req.csr_pem.clone());
        csrs.len()
    };
    let (status, retry_after, body) = (st.reply)(n, &req.csr_pem);
    let mut resp = (StatusCode::from_u16(status).unwrap(), body).into_response();
    if let Some(v) = retry_after {
        resp.headers_mut()
            .insert(header::RETRY_AFTER, v.parse().unwrap());
    }
    resp
}

/// A reply that is the real signer's certificate for the CSR, pinned to `host`.
fn issued(pki: &Pki, host: &'static str) -> impl Fn(usize, &str) -> Reply + Send + Sync + 'static {
    let ca = pki.files();
    move |_, csr| {
        let cert = ca.sign(csr, host);
        let (leaf_pem, chain) = cert.split_at(cert.find("-----END CERTIFICATE-----").unwrap() + 25);
        let body = serde_json::json!({
            "ca_chain_pem": chain, "client_cert_pem": leaf_pem, "host_id": host,
            "not_after": "n", "serial": "1",
        });
        (200, None, body.to_string())
    }
}

fn ago(days: i64) -> OffsetDateTime {
    OffsetDateTime::now_utc() - Duration::days(days)
}

/// A host 25 days into a 30 day certificate: past 75% of it, so renewal is due.
fn due_host(pki: &Pki) -> Host {
    Host::new(pki, ago(25), ago(-5))
}

#[tokio::test]
async fn a_renewal_replaces_key_and_certificate_swaps_the_client_and_leaves_no_next_file() {
    let pki = Pki::new();
    let host = due_host(&pki);
    let (key0, crt0, na0) = (host.key(), host.crt(), host.not_after());
    let mock = Mock::start(issued(&pki, HOST)).await;
    let (mut r, stats, _) = host.renewer(&mock.url);
    assert_eq!(
        stats.read().client_cert_expires_at,
        None,
        "nothing has set the expiry yet"
    );

    r.step(OffsetDateTime::now_utc()).await;

    assert_eq!(mock.hits(), 1);
    assert_ne!(host.key(), key0, "a new key");
    assert_ne!(host.crt(), crt0, "a new certificate");
    assert!(host.not_after() > na0 + 20 * 86_400, "30 days from now");
    assert_eq!(host.next_files(), [false; 3]);
    assert_eq!(
        stats
            .read()
            .client_cert_expires_at
            .map(|t| t.unix_timestamp()),
        Some(host.not_after()),
        "the status file reports the new expiry"
    );

    // A second renewal is not tried early: the new certificate is days from its target.
    let wait = r
        .step(OffsetDateTime::now_utc() + Duration::seconds(5))
        .await;
    assert_eq!(mock.hits(), 1);
    assert!(wait >= std::time::Duration::from_secs(60), "{wait:?}");
}

#[tokio::test]
async fn a_server_that_is_down_changes_nothing_and_the_next_wake_resends_the_same_csr() {
    let pki = Pki::new();
    let host = due_host(&pki);
    let (key0, crt0) = (host.key(), host.crt());
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let (mut r, _, _) = host.renewer(&format!("http://127.0.0.1:{port}"));
    let t0 = OffsetDateTime::now_utc();
    r.step(t0).await;
    assert_eq!(
        (host.key(), host.crt()),
        (key0, crt0),
        "the live pair is untouched"
    );
    assert_eq!(
        host.next_files(),
        [true, true, false],
        "the next key and CSR stay"
    );
    let csr = std::fs::read_to_string(&host.paths.csr_next).unwrap();

    let mock = Mock::on(&format!("127.0.0.1:{port}"), issued(&pki, HOST)).await;
    r.step(t0 + Duration::minutes(3)).await;
    assert_eq!(
        mock.csrs.lock().unwrap().as_slice(),
        [csr],
        "the same CSR bytes"
    );
    assert_eq!(host.next_files(), [false; 3]);
    assert!(host.not_after() > t0.unix_timestamp() + 20 * 86_400);
}

#[tokio::test]
async fn an_answer_for_another_host_or_another_key_never_replaces_the_pair() {
    let pki = Pki::new();
    let host = due_host(&pki);
    let (key0, crt0) = (host.key(), host.crt());
    let (p, stranger) = (Arc::new(Pki::new()), Arc::new(KeyPair::generate().unwrap()));
    let sign_for_other_host = issued(&pki, OTHER);
    let ca = pki.ca.pem();
    let wrong_key = move |_: usize, _: &str| -> Reply {
        let cert = p.mint(&stranger, HOST, ago(1), ago(-30));
        let body = serde_json::json!({
            "ca_chain_pem": ca, "client_cert_pem": cert, "host_id": HOST, "not_after": "n", "serial": "1",
        });
        (200, None, body.to_string())
    };
    for (what, mock) in [
        ("another host", Mock::start(sign_for_other_host).await),
        ("another key and CA", Mock::start(wrong_key).await),
    ] {
        let (mut r, _, _) = host.renewer(&mock.url);
        r.step(OffsetDateTime::now_utc()).await;
        assert_eq!(mock.hits(), 1, "{what}");
        assert_eq!(
            (host.key(), host.crt()),
            (key0.clone(), crt0.clone()),
            "{what}"
        );
        assert!(!host.paths.crt_next.exists(), "{what}: nothing was stored");
    }
}

#[tokio::test]
async fn a_live_answer_that_does_not_expire_later_than_the_live_certificate_is_not_used() {
    let pki = Arc::new(Pki::new());
    let host = due_host(&pki);
    let (key0, crt0) = (host.key(), host.crt());
    let (p, key_next, ca) = (pki.clone(), host.paths.key_next.clone(), pki.ca.pem());
    let shorter = move |_: usize, _: &str| -> Reply {
        let key = KeyPair::from_pem(&std::fs::read_to_string(&key_next).unwrap()).unwrap();
        // The live certificate has 5 days left; this one is for the new key and 3.
        let cert = p.mint(&key, HOST, ago(1), ago(-3));
        let body = serde_json::json!({
            "ca_chain_pem": ca, "client_cert_pem": cert, "host_id": HOST, "not_after": "n", "serial": "1",
        });
        (200, None, body.to_string())
    };
    let mock = Mock::start(shorter).await;
    let (mut r, _, _) = host.renewer(&mock.url);
    r.step(OffsetDateTime::now_utc()).await;
    assert_eq!(mock.hits(), 1);
    assert_eq!((host.key(), host.crt()), (key0, crt0));
    assert!(!host.paths.crt_next.exists(), "nothing was stored");
}

#[tokio::test]
async fn a_live_pair_that_does_not_match_ends_the_wake_with_no_request_and_no_rename() {
    let pki = Pki::new();
    let host = due_host(&pki);
    let mock = Mock::start(issued(&pki, HOST)).await;
    let (mut r, _, _) = host.renewer(&mock.url);
    std::fs::write(
        &host.paths.key,
        KeyPair::generate().unwrap().serialize_pem(),
    )
    .unwrap();
    let (key0, crt0) = (host.key(), host.crt());
    let wait = r.step(OffsetDateTime::now_utc()).await;
    assert_eq!(wait.as_secs(), 300);
    assert_eq!(mock.hits(), 0, "no request");
    assert_eq!((host.key(), host.crt()), (key0, crt0));
    assert_eq!(host.next_files(), [false; 3], "nothing was made");
}

#[tokio::test]
async fn a_file_settle_cannot_read_ends_the_wake_with_no_request_and_no_rename() {
    let pki = Pki::new();
    let host = due_host(&pki);
    let mock = Mock::start(issued(&pki, HOST)).await;
    let (mut r, _, _) = host.renewer(&mock.url);
    // A link where `client.crt.next` goes: `settle` refuses to read it.
    std::os::unix::fs::symlink(&host.paths.crt, &host.paths.crt_next).unwrap();
    let (key0, crt0) = (host.key(), host.crt());
    r.step(OffsetDateTime::now_utc()).await;
    assert_eq!(mock.hits(), 0, "no request");
    assert_eq!((host.key(), host.crt()), (key0, crt0));
    assert!(!host.paths.key_next.exists(), "no new key was made");
}

#[tokio::test]
async fn a_live_pair_replaced_on_disk_is_picked_up_in_a_wake_that_is_not_clean_but_nothing_is_sent()
{
    let pki = Pki::new();
    let host = due_host(&pki);
    let mock = Mock::start(issued(&pki, HOST)).await;
    let (mut r, stats, _) = host.renewer(&mock.url);
    // A link where `client.crt.next` goes keeps every wake from being clean.
    std::os::unix::fs::symlink(&host.paths.crt, &host.paths.crt_next).unwrap();

    // An `enroll` run by hand replaced the pair.
    host.install(&pki, ago(1), ago(-29));
    let (key1, crt1) = (host.key(), host.crt());
    r.step(OffsetDateTime::now_utc()).await;
    assert_eq!(mock.hits(), 0, "no request");
    assert_eq!((host.key(), host.crt()), (key1, crt1), "no rename");
    assert_eq!(
        stats
            .read()
            .client_cert_expires_at
            .map(|t| t.unix_timestamp()),
        Some(host.not_after()),
        "the new pair is in use"
    );

    // A pair that does not match is not picked up.
    let before = stats.read().client_cert_expires_at;
    std::fs::write(
        &host.paths.key,
        KeyPair::generate().unwrap().serialize_pem(),
    )
    .unwrap();
    host.install(&pki, ago(1), ago(-29));
    std::fs::write(
        &host.paths.key,
        KeyPair::generate().unwrap().serialize_pem(),
    )
    .unwrap();
    r.step(OffsetDateTime::now_utc()).await;
    assert_eq!(
        stats.read().client_cert_expires_at,
        before,
        "the old client stays"
    );
    assert_eq!(mock.hits(), 0);
}

#[tokio::test]
async fn a_wake_that_cannot_settle_keeps_the_old_client_when_the_live_pair_does_not_fit() {
    let pki = Pki::new();
    let host = due_host(&pki);
    let mock = Mock::start(issued(&pki, HOST)).await;
    let log = Log::default();
    let _guard = log.capture();
    let (mut r, stats, _) = host.renewer(&mock.url);
    let before = stats.read().client_cert_expires_at;
    // A link where `client.crt.next` goes keeps `settle` from finishing.
    std::os::unix::fs::symlink(&host.paths.crt, &host.paths.crt_next).unwrap();
    // A certificate that runs longer than the loaded one, with a key that is not its own.
    host.install(&pki, ago(1), ago(-60));
    std::fs::write(
        &host.paths.key,
        KeyPair::generate().unwrap().serialize_pem(),
    )
    .unwrap();
    r.step(OffsetDateTime::now_utc()).await;
    assert_eq!(stats.read().client_cert_expires_at, before);
    assert_eq!(log.lines_with("cannot settle the renewal files"), 1);
    assert_eq!(
        log.lines_with("keeping the current client"),
        0,
        "no load was tried"
    );
    assert_eq!(mock.hits(), 0);
}

#[tokio::test]
async fn a_next_file_that_is_not_read_is_named_in_the_error_line() {
    let pki = Pki::new();
    let host = due_host(&pki);
    let mock = Mock::start(issued(&pki, HOST)).await;
    let log = Log::default();
    let _guard = log.capture();
    let (mut r, _, _) = host.renewer(&mock.url);
    std::os::unix::fs::symlink(&host.paths.crt, &host.paths.crt_next).unwrap();
    r.step(OffsetDateTime::now_utc()).await;
    assert_eq!(log.lines_with("client.crt.next"), 1);
    assert_eq!(log.lines_with("cannot settle the renewal files"), 1);
}

#[tokio::test]
async fn an_unparseable_next_file_does_not_stop_renewal_and_no_bad_bytes_are_sent() {
    for junk in ["crt", "empty crt", "key", "csr"] {
        let pki = Pki::new();
        let host = due_host(&pki);
        let mock = Mock::start(issued(&pki, HOST)).await;
        let (mut r, _, _) = host.renewer(&mock.url);
        let k1 = KeyPair::generate().unwrap();
        let csr = lodeline_sender::csr::csr_for(&k1, HOST).unwrap();
        std::fs::write(&host.paths.key_next, k1.serialize_pem()).unwrap();
        std::fs::write(&host.paths.csr_next, &csr).unwrap();
        match junk {
            "crt" => std::fs::write(&host.paths.crt_next, "garbage").unwrap(),
            "empty crt" => std::fs::write(&host.paths.crt_next, "").unwrap(),
            "key" => std::fs::write(&host.paths.key_next, "garbage").unwrap(),
            _ => std::fs::write(&host.paths.csr_next, "garbage").unwrap(),
        }
        let (key0, na0) = (host.key(), host.not_after());
        r.step(OffsetDateTime::now_utc()).await;
        assert_eq!(mock.hits(), 1, "{junk}");
        let sent = mock.csrs.lock().unwrap()[0].clone();
        assert!(sent.contains("CERTIFICATE REQUEST"), "{junk}: {sent}");
        assert_ne!(host.key(), key0, "{junk}: renewed");
        assert!(host.not_after() > na0, "{junk}");
        assert_eq!(host.next_files(), [false; 3], "{junk}");
    }
}

thread_local! {
    static CURRENT: std::cell::RefCell<Option<Log>> = const { std::cell::RefCell::new(None) };
}

struct Route;

impl std::io::Write for Route {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        CURRENT.with(|c| {
            c.borrow_mut()
                .as_mut()
                .map(|l| l.write(b))
                .unwrap_or(Ok(b.len()))
        })
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct Capture;

impl Drop for Capture {
    fn drop(&mut self) {
        CURRENT.with(|c| *c.borrow_mut() = None);
    }
}

/// Collects what `tracing` prints.
#[derive(Clone, Default)]
struct Log(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Log {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Log {
    /// One global subscriber that writes to the calling thread's log: scoped subscribers
    /// racing on a shared call site lose events.
    fn capture(&self) -> Capture {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| {
            tracing::subscriber::set_global_default(
                tracing_subscriber::fmt()
                    .with_writer(|| Route)
                    .with_ansi(false)
                    .finish(),
            )
            .unwrap();
        });
        CURRENT.with(|c| *c.borrow_mut() = Some(self.clone()));
        Capture
    }

    fn lines_with(&self, needle: &str) -> usize {
        String::from_utf8_lossy(&self.0.lock().unwrap())
            .lines()
            .filter(|l| l.contains(needle))
            .count()
    }
}

#[tokio::test]
async fn a_refusal_is_not_retried_quickly_and_is_logged_once_per_period() {
    for (status, needle) in [
        (403u16, "already issued three certificates"),
        (404, "does not offer renewal"),
    ] {
        let pki = Pki::new();
        // 500 s into a 600 s certificate: due, 100 s left, so a refusal waits 60 s.
        let now = OffsetDateTime::now_utc();
        let host = Host::new(
            &pki,
            now - Duration::seconds(500),
            now + Duration::seconds(100),
        );
        let mock = Mock::start(move |_, _| (status, None, String::new())).await;
        let log = Log::default();
        let _guard = log.capture();
        let (mut r, _, _) = host.renewer(&mock.url);
        r.step(now).await;
        r.step(now + Duration::seconds(10)).await;
        r.step(now + Duration::seconds(30)).await;
        assert_eq!(mock.hits(), 1, "{status}: not retried inside the wait");
        r.step(now + Duration::seconds(61)).await;
        assert_eq!(mock.hits(), 2, "{status}: tried again after it");
        assert_eq!(
            log.lines_with(needle),
            1,
            "{status}: one line for both attempts"
        );
        assert!(!host.next_files()[2]);
    }
}

#[tokio::test]
async fn files_that_are_not_clean_at_start_are_logged_once_then_once_per_period() {
    let pki = Pki::new();
    let host = Host::new(&pki, ago(10), ago(-30));
    // A key that does not belong to the certificate: `settle` cannot repair it.
    std::fs::write(
        &host.paths.key,
        KeyPair::generate().unwrap().serialize_pem(),
    )
    .unwrap();
    let log = Log::default();
    let _guard = log.capture();
    let now = OffsetDateTime::now_utc();
    let logged = lodeline_sender::renew::settle_at_start(&host.paths, HOST);
    assert_eq!(log.lines_with("do not match"), 1, "the start logs it");
    let (mut r, _, _) = host.renewer("http://127.0.0.1:9");
    r.already_logged(logged, now);
    r.step(now).await;
    assert_eq!(
        log.lines_with("do not match"),
        1,
        "the first wake stays quiet"
    );
    r.step(now + Duration::seconds(3601)).await;
    assert_eq!(log.lines_with("do not match"), 2, "again after the period");
}

#[tokio::test]
async fn run_does_not_log_again_at_its_first_wake_what_the_start_logged() {
    let pki = Pki::new();
    let host = Host::new(&pki, ago(10), ago(-30));
    std::fs::write(
        &host.paths.key,
        KeyPair::generate().unwrap().serialize_pem(),
    )
    .unwrap();
    let log = Log::default();
    let _guard = log.capture();
    let logged = lodeline_sender::renew::settle_at_start(&host.paths, HOST);
    // Cancelled before the start: `run` makes its first wake, then stops.
    let shutdown = CancellationToken::new();
    shutdown.cancel();
    lodeline_sender::renew::run(
        RenewCtx {
            client: ClientHandle::from(reqwest::Client::new()),
            stats: heartbeat::shared(),
            server_base_url: "http://127.0.0.1:9".into(),
            host_id: HOST.to_string(),
            paths: Paths::new(&host.paths.crt, &host.paths.key, &host.paths.ca),
            shutdown,
        },
        logged,
    )
    .await;
    assert_eq!(log.lines_with("do not match"), 1, "the start's line only");
}

#[tokio::test]
async fn too_early_waits_for_the_servers_retry_after() {
    let pki = Pki::new();
    let host = due_host(&pki);
    let mock = Mock::start(|_, _| (409, Some("120"), String::new())).await;
    let (mut r, _, _) = host.renewer(&mock.url);
    let now = OffsetDateTime::now_utc();
    let wait = r.step(now).await;
    assert_eq!(wait.as_secs(), 120);
    r.step(now + Duration::seconds(60)).await;
    assert_eq!(mock.hits(), 1);
    r.step(now + Duration::seconds(121)).await;
    assert_eq!(mock.hits(), 2);
}

#[tokio::test]
async fn an_expired_pair_waits_on_disk_and_a_pair_that_appears_is_used_without_a_restart() {
    let pki = Pki::new();
    let host = Host::new(&pki, ago(10), ago(1));
    let mock = Mock::start(issued(&pki, HOST)).await;
    let log = Log::default();
    let _guard = log.capture();
    let (mut r, stats, _) = host.renewer(&mock.url);
    let wait = r.step(OffsetDateTime::now_utc()).await;
    assert_eq!(mock.hits(), 0, "no network attempt after expiry");
    assert_eq!(wait.as_secs(), 300, "the disk is read again in 5 min");
    assert_eq!(log.lines_with("expired at"), 1);
    assert_eq!(stats.read().client_cert_expires_at, None);

    host.install(&pki, ago(0), ago(-30));
    r.step(OffsetDateTime::now_utc()).await;
    assert_eq!(
        stats
            .read()
            .client_cert_expires_at
            .map(|t| t.unix_timestamp()),
        Some(host.not_after()),
        "the new pair is in use"
    );
}

#[tokio::test]
async fn a_directory_that_cannot_be_written_turns_renewal_off_with_one_error_and_the_sender_still_sends(
) {
    use std::os::unix::fs::PermissionsExt;
    if unsafe { libc::geteuid() } == 0 {
        return; // root writes anywhere
    }
    let pki = Pki::new();
    let host = due_host(&pki);
    let mock = Mock::start(issued(&pki, HOST)).await;
    std::fs::set_permissions(host.dir.path(), std::fs::Permissions::from_mode(0o500)).unwrap();
    let log = Log::default();
    let guard = log.capture();
    let (mut r, _, _) = host.renewer(&mock.url);
    r.step(OffsetDateTime::now_utc()).await;
    r.step(OffsetDateTime::now_utc() + Duration::seconds(1))
        .await;
    drop(guard);
    assert_eq!(mock.hits(), 0, "no renewal request");
    assert_eq!(
        log.lines_with("renewal is off: this account cannot create files"),
        1
    );
    assert_eq!(
        log.lines_with("and renewal is off"),
        1,
        "the reminder is rate limited too"
    );

    // The events still go: the whole runtime runs over this directory.
    let (addr, state) = common::spawn_mock().await;
    let events = tempfile::tempdir().unwrap();
    let id = uuid::Uuid::from_u128(7);
    std::fs::write(
        events.path().join("events-1.jsonl"),
        format!("{{\"event_id\":\"{id}\",\"payload\":\"a\"}}\n"),
    )
    .unwrap();
    let state_dir = tempfile::tempdir().unwrap();
    let shutdown = CancellationToken::new();
    let config = lodeline_sender::config::SenderConfig {
        server_base_url: format!("http://{addr}"),
        client_cert_path: Some(host.paths.crt.clone()),
        client_key_path: Some(host.paths.key.clone()),
        server_ca_path: Some(host.paths.ca.clone()),
        events_dir: events.path().to_path_buf(),
        offset_path: state_dir.path().join("sender-offset.json"),
        agent_control: host.dir.path().join("control.sock"),
        dead_letter_dir: events.path().join("dead-letter"),
        max_batch_events: 256,
        max_batch_bytes: 1024 * 1024,
        policy_poll_interval: std::time::Duration::from_secs(600),
        host_id: None,
    };
    let task = tokio::spawn(lodeline_sender::runtime::run(
        lodeline_sender::runtime::RuntimeCtx {
            config: config.clone(),
            host_id: HOST.into(),
            agent_version: "1".into(),
            sender_version: "1".into(),
            shutdown: shutdown.clone(),
        },
    ));
    let start = std::time::Instant::now();
    while state.lock().await.received_batches.is_empty() && start.elapsed().as_secs() < 10 {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    let sent = state.lock().await.received_batches.len();
    shutdown.cancel();
    let _ = task.await;
    std::fs::set_permissions(host.dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(sent, 1, "the batch was delivered with renewal off");
}

#[tokio::test]
async fn a_crash_between_the_renames_is_repaired_before_the_sender_builds_its_client() {
    let pki = Pki::new();
    let host = due_host(&pki);
    // The key was renamed; the certificate was not. The pair on disk does not match.
    let new_key = KeyPair::generate().unwrap();
    std::fs::write(&host.paths.key, new_key.serialize_pem()).unwrap();
    std::fs::write(
        &host.paths.crt_next,
        pki.mint(&new_key, HOST, ago(0), ago(-30)),
    )
    .unwrap();

    let (addr, state) = common::spawn_mock().await;
    let events = tempfile::tempdir().unwrap();
    let id = uuid::Uuid::from_u128(9);
    std::fs::write(
        events.path().join("events-1.jsonl"),
        format!("{{\"event_id\":\"{id}\",\"payload\":\"a\"}}\n"),
    )
    .unwrap();
    let state_dir = tempfile::tempdir().unwrap();
    let shutdown = CancellationToken::new();
    let task = tokio::spawn(lodeline_sender::runtime::run(
        lodeline_sender::runtime::RuntimeCtx {
            config: lodeline_sender::config::SenderConfig {
                server_base_url: format!("http://{addr}"),
                client_cert_path: Some(host.paths.crt.clone()),
                client_key_path: Some(host.paths.key.clone()),
                server_ca_path: Some(host.paths.ca.clone()),
                events_dir: events.path().to_path_buf(),
                offset_path: state_dir.path().join("sender-offset.json"),
                agent_control: state_dir.path().join("control.sock"),
                dead_letter_dir: state_dir.path().join("dead-letter"),
                max_batch_events: 256,
                max_batch_bytes: 1024 * 1024,
                policy_poll_interval: std::time::Duration::from_secs(600),
                host_id: None,
            },
            host_id: HOST.into(),
            agent_version: "1".into(),
            sender_version: "1".into(),
            shutdown: shutdown.clone(),
        },
    ));
    let start = std::time::Instant::now();
    while state.lock().await.received_batches.is_empty() && start.elapsed().as_secs() < 10 {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    let started = !task.is_finished();
    shutdown.cancel();
    let _ = task.await;
    assert!(
        started,
        "the sender started instead of failing on the split pair"
    );
    assert_eq!(state.lock().await.received_batches.len(), 1);
    assert_eq!(host.next_files(), [false; 3]);
    assert!(leaf(host.crt().as_bytes()).unwrap().pubkey == new_key.public_key_raw());
}

#[tokio::test]
async fn a_request_in_flight_finishes_on_the_old_client_and_the_next_one_uses_the_new_client() {
    // The server tells the two clients apart by a header and holds the first request.
    #[derive(Clone, Default)]
    struct Seen(Arc<Mutex<Vec<String>>>);
    let seen = Seen::default();
    let app = Router::new()
        .route(
            "/",
            axum::routing::get(
                |State(s): State<Seen>, h: axum::http::HeaderMap| async move {
                    let who = h["x-client"].to_str().unwrap().to_string();
                    s.0.lock().unwrap().push(who.clone());
                    if who == "old" {
                        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
                    }
                    who
                },
            ),
        )
        .with_state(seen.clone());
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/", l.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    let tagged = |tag: &'static str| {
        let mut h = reqwest::header::HeaderMap::new();
        h.insert("x-client", tag.parse().unwrap());
        reqwest::Client::builder()
            .default_headers(h)
            .build()
            .unwrap()
    };
    let handle = ClientHandle::from(tagged("old"));

    let in_flight = {
        let (client, url) = (handle.get(), url.clone());
        tokio::spawn(async move { client.get(url).send().await.unwrap().text().await.unwrap() })
    };
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    handle.set(tagged("new"));
    let later = handle
        .get()
        .get(&url)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    assert_eq!(later, "new");
    assert_eq!(
        in_flight.await.unwrap(),
        "old",
        "the request in flight completed on the old client"
    );
    assert_eq!(
        seen.0.lock().unwrap().as_slice(),
        ["old", "new"],
        "each was sent once"
    );
}

// ---- The headline: a host stays online past its first certificate's notAfter -------

use lodeline_server::app::{build_router, AppState};
use lodeline_server::auth::ReadToken;
use lodeline_server::enroll::EnrollState;
use lodeline_server::fleet_index::FleetIndex;
use lodeline_server::persist::HighWater;
use lodeline_server::tls_accept::{PeerCertAcceptor, PeerIdentity};

/// The real main listener: mutual TLS whose client CA is the enrollment CA, serving
/// the real router with enrollment and renewal on. Records which certificate each
/// request presented, and when.
struct Live {
    port: u16,
    seen: Arc<Mutex<Vec<(std::time::Instant, String)>>>,
    handle: axum_server::Handle,
    _dir: tempfile::TempDir,
}

fn der(pem: &str) -> Vec<u8> {
    rustls_pemfile::certs(&mut pem.as_bytes())
        .next()
        .unwrap()
        .unwrap()
        .to_vec()
}

async fn live(pki: &Pki) -> Live {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let allow = d.join("hosts.json");
    std::fs::write(&allow, serde_json::json!({ "hosts": [HOST] }).to_string()).unwrap();
    let ca = pki.files();
    let enroll = EnrollState::load(
        Some(&ca.crt),
        Some(&ca.key),
        Some(&d.join("tokens.json")),
        Some(&allow),
        true,
        Some(30),
        d.join("enrollment-audit.jsonl"),
        None,
    );
    let st = Arc::new(AppState {
        events_out_dir: d.to_path_buf(),
        policy_bundle_path: d.join("signed-policy.json"),
        rule_packs_bundle_path: None,
        artifacts_dir: None,
        high_water_path: d.join(".high-water.json"),
        allowlist: parking_lot::RwLock::new(
            lodeline_server::allowlist::load(Some(&allow)).unwrap(),
        ),
        high_water: Mutex::new(HighWater::default()),
        fleet_index: FleetIndex::new(),
        read_token: ReadToken(None),
        active_window_days: 7,
        audit_key: lodeline_server::audit_key::AuditKey::load_or_create(d),
        audit_head: Mutex::new(None),
        allowlist_path: Some(allow),
        enroll,
        events_require_cert_host_match: false,
    });
    let srv_key = KeyPair::generate().unwrap();
    let mut p = CertificateParams::new(vec![]).unwrap();
    p.subject_alt_names = vec![rcgen::SanType::IpAddress("127.0.0.1".parse().unwrap())];
    p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let srv_pem = p.signed_by(&srv_key, &pki.ca).unwrap().pem();
    let key = rustls_pemfile::private_key(&mut srv_key.serialize_pem().as_bytes())
        .unwrap()
        .unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls::pki_types::CertificateDer::from(der(&ca.pem)))
        .unwrap();
    let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .unwrap();
    let cfg = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            vec![rustls::pki_types::CertificateDer::from(der(&srv_pem))],
            key,
        )
        .unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    let app = build_router(st).layer(axum::middleware::from_fn(
        move |req: axum::extract::Request, next: axum::middleware::Next| {
            let log = log.clone();
            async move {
                if let Some(peer) = req.extensions().get::<Arc<PeerIdentity>>() {
                    log.lock()
                        .unwrap()
                        .push((std::time::Instant::now(), peer.fingerprint.clone()));
                }
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
    let addr = handle.listening().await.expect("the server must bind");
    Live {
        port: addr.port(),
        seen,
        handle,
        _dir: dir,
    }
}

fn fingerprint(pem: &str) -> String {
    PeerIdentity::from_der(&der(pem)).fingerprint
}

/// Events keep coming for the whole run, so the sender never idles.
fn feed_events(dir: PathBuf, stop: CancellationToken) {
    tokio::spawn(async move {
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join("events-1.jsonl"))
            .unwrap();
        while !stop.is_cancelled() {
            let evt = lodeline_sender::data_task::local_event(
                HOST,
                lodeline_core::event::Evidence::TlsFailure {
                    reason: "probe".into(),
                },
            );
            std::io::Write::write_all(
                &mut f,
                format!("{}\n", serde_json::to_string(&evt).unwrap()).as_bytes(),
            )
            .unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        }
    });
}

/// A host whose first certificate lasts 15 s runs the real sender against the real
/// server. Renewal is due at 9 to 11 s. The server verifies a client certificate at the
/// handshake only, and the sender keeps one connection open while events flow, so a
/// request that merely succeeds after `notAfter` proves nothing: the old connection can
/// carry it. The test therefore asks the server which certificate each request
/// presented, and builds a fresh client from the files on disk.
#[tokio::test(flavor = "multi_thread")]
async fn a_host_stays_online_past_its_first_certificates_notafter() {
    let pki = Pki::new();
    let srv = live(&pki).await;
    let t0 = OffsetDateTime::now_utc().replace_nanosecond(0).unwrap();
    let first_na = t0 + Duration::seconds(15);
    let host = Host::new(&pki, t0, first_na);
    let first_fp = fingerprint(&host.crt());

    let state_dir = tempfile::tempdir().unwrap();
    let events = tempfile::tempdir().unwrap();
    let (stop, shutdown) = (CancellationToken::new(), CancellationToken::new());
    feed_events(events.path().to_path_buf(), stop.clone());
    let config = lodeline_sender::config::SenderConfig {
        server_base_url: format!("https://127.0.0.1:{}", srv.port),
        client_cert_path: Some(host.paths.crt.clone()),
        client_key_path: Some(host.paths.key.clone()),
        server_ca_path: Some(host.paths.ca.clone()),
        events_dir: events.path().to_path_buf(),
        offset_path: state_dir.path().join("sender-offset.json"),
        agent_control: state_dir.path().join("control.sock"),
        dead_letter_dir: state_dir.path().join("dead-letter"),
        max_batch_events: 256,
        max_batch_bytes: 1024 * 1024,
        policy_poll_interval: std::time::Duration::from_secs(600),
        host_id: None,
    };
    let task = tokio::spawn(lodeline_sender::runtime::run(
        lodeline_sender::runtime::RuntimeCtx {
            config: config.clone(),
            host_id: HOST.into(),
            agent_version: "1".into(),
            sender_version: "1".into(),
            shutdown: shutdown.clone(),
        },
    ));

    // Wait until 3 s after the first certificate expired.
    let until = (first_na + Duration::seconds(3) - OffsetDateTime::now_utc()).max(Duration::ZERO);
    tokio::time::sleep(until.unsigned_abs()).await;
    let crt_now = host.crt();
    let renewed_fp = fingerprint(&crt_now);
    let acked = lodeline_sender::state::load(&config.offset_path)
        .unwrap()
        .map(|s| s.last_acked_sequence);
    let seen: Vec<String> = srv
        .seen
        .lock()
        .unwrap()
        .iter()
        .map(|(_, fp)| fp.clone())
        .collect();

    // A fresh client from the files on disk gets through the handshake.
    let fresh = lodeline_sender::transport::build_client(
        Some(&host.paths.crt),
        Some(&host.paths.key),
        Some(&host.paths.ca),
    )
    .unwrap();
    let health = fresh
        .get(format!("https://127.0.0.1:{}/v1/healthz", srv.port))
        .send()
        .await;

    // And the running sender keeps delivering on the new certificate.
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    let acked_later = lodeline_sender::state::load(&config.offset_path)
        .unwrap()
        .map(|s| s.last_acked_sequence);
    let seen_later = srv
        .seen
        .lock()
        .unwrap()
        .iter()
        .map(|(_, fp)| fp.clone())
        .collect::<Vec<_>>();
    stop.cancel();
    shutdown.cancel();
    let _ = task.await;
    srv.handle.shutdown();

    assert_ne!(renewed_fp, first_fp, "the certificate on disk is a new one");
    assert!(
        host.not_after() > first_na.unix_timestamp() + 20 * 86_400,
        "valid for the server's 30 days"
    );
    assert_eq!(host.next_files(), [false; 3]);
    assert!(
        seen.contains(&first_fp),
        "the first certificate was in use before"
    );
    assert!(
        seen.contains(&renewed_fp),
        "the server saw a request that presented the renewed certificate"
    );
    assert!(
        health.is_ok_and(|r| r.status().is_success()),
        "a fresh client from the files on disk is served"
    );
    assert!(acked_later > acked, "events are still acknowledged after the first certificate expired: {acked:?} then {acked_later:?}");
    assert!(
        seen_later.iter().rev().take(3).all(|fp| *fp == renewed_fp),
        "the latest requests carry the renewed certificate"
    );
}
