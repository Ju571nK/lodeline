//! `lodeline-sender enroll` against the real enrollment listener of `lodeline-server`.
//!
//! The PKI comes from `openssl`, as in the server's own tests. Each test runs its
//! own listener, so each has its own budget of 10 connections.
#![cfg(unix)]

use lodeline_core::state::HashCache;
use lodeline_sender::enroll::claim::Claim;
use lodeline_sender::enroll::net::Pacing;
use lodeline_sender::enroll::{run, Args, Env, Layout};
use lodeline_server::app::AppState;
use lodeline_server::auth::ReadToken;
use lodeline_server::enroll::tokens::TokenStore;
use lodeline_server::enroll::{listener, EnrollState};
use lodeline_server::fleet_index::FleetIndex;
use lodeline_server::persist::HighWater;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use time::{Duration, OffsetDateTime};

const HOST: &str = "3f2c6a1e-8b4d-4c2a-9e7f-1a2b3c4d5e6f";
const OTHER: &str = "5a1c6a1e-8b4d-4c2a-9e7f-1a2b3c4d5e70";

fn openssl() -> PathBuf {
    lodeline_server::enroll::sign::resolve_openssl().expect("openssl must be installed")
}

fn ossl(args: &[&std::ffi::OsStr]) {
    let o = Command::new(openssl()).args(args).output().unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
}

fn ca(dir: &Path, name: &str) {
    let (key, crt) = (dir.join("ca.key"), dir.join("ca.crt"));
    let subj = format!("/CN={name}");
    ossl(&[
        "genpkey".as_ref(),
        "-algorithm".as_ref(),
        "RSA".as_ref(),
        "-pkeyopt".as_ref(),
        "rsa_keygen_bits:2048".as_ref(),
        "-out".as_ref(),
        key.as_os_str(),
    ]);
    ossl(&[
        "req".as_ref(),
        "-x509".as_ref(),
        "-new".as_ref(),
        "-key".as_ref(),
        key.as_os_str(),
        "-days".as_ref(),
        "3650".as_ref(),
        "-subj".as_ref(),
        subj.as_ref(),
        "-addext".as_ref(),
        "basicConstraints=critical,CA:TRUE".as_ref(),
        "-out".as_ref(),
        crt.as_os_str(),
    ]);
    // The server refuses a CA key that others can read.
    std::fs::set_permissions(&key, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
}

/// A server certificate for 127.0.0.1 signed by the CA in `ca_dir`, written to `dir`.
fn server_cert(dir: &Path, ca_dir: &Path) -> (PathBuf, PathBuf) {
    let (key, csr, crt, ext) = (
        dir.join("server.key"),
        dir.join("server.csr"),
        dir.join("server.crt"),
        dir.join("server.ext"),
    );
    std::fs::write(
        &ext,
        "subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n",
    )
    .unwrap();
    ossl(&[
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
    ossl(&[
        "x509".as_ref(),
        "-req".as_ref(),
        "-in".as_ref(),
        csr.as_os_str(),
        "-CA".as_ref(),
        ca_dir.join("ca.crt").as_os_str(),
        "-CAkey".as_ref(),
        ca_dir.join("ca.key").as_os_str(),
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

struct Server {
    st: Arc<AppState>,
    addr: std::net::SocketAddr,
    task: tokio::task::JoinHandle<anyhow::Result<()>>,
    dir: tempfile::TempDir,
}

/// Enrollment on, issuing under the CA in `enroll_ca`, serving a certificate from `tls_ca`.
async fn server(tls_ca: Option<&Path>) -> Server {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    ca(d, "test-ca");
    let allow = d.join("hosts.json");
    std::fs::write(&allow, r#"{"hosts":[]}"#).unwrap();
    let enroll = EnrollState::load(
        Some(&d.join("ca.crt")),
        Some(&d.join("ca.key")),
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
    let (crt, key) = server_cert(d, tls_ca.unwrap_or(d));
    let tls = listener::tls_config(&crt, &key).unwrap();
    let sock = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = sock.local_addr().unwrap();
    let task = tokio::spawn(listener::serve(sock, tls, st.clone()));
    Server {
        st,
        addr,
        task,
        dir,
    }
}

impl Server {
    fn ca_pem(&self) -> String {
        std::fs::read_to_string(self.dir.path().join("ca.crt")).unwrap()
    }
    fn token(&self, host: &str) -> String {
        let now = OffsetDateTime::now_utc();
        let path = &self.st.enroll.as_ref().unwrap().tokens_path;
        TokenStore::issue(path, host, now + Duration::hours(1), now).unwrap()
    }
    fn issued_lines(&self) -> usize {
        std::fs::read_to_string(self.dir.path().join("enrollment-audit.jsonl"))
            .unwrap_or_default()
            .lines()
            .filter(|l| l.contains("\"issued\""))
            .count()
    }
    /// Redeem `token` with a fresh key, to prove whether enroll had spent it.
    async fn redeem(&self, token: &str, host: &str) -> u16 {
        let key = lodeline_sender::csr::new_key().unwrap();
        let csr = lodeline_sender::csr::csr_for(&key, host).unwrap();
        let client = reqwest::Client::builder()
            .use_rustls_tls()
            .tls_built_in_root_certs(false)
            .add_root_certificate(reqwest::Certificate::from_pem(self.ca_pem().as_bytes()).unwrap())
            .build()
            .unwrap();
        client
            .post(format!("https://127.0.0.1:{}/v1/enroll", self.addr.port()))
            .json(&serde_json::json!({"token": token, "host_id": host, "csr_pem": csr}))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16()
    }
}

struct Host {
    dir: tempfile::TempDir,
}

impl Host {
    fn new() -> Self {
        Self {
            dir: tempfile::tempdir().unwrap(),
        }
    }
    fn p(&self, rel: &str) -> PathBuf {
        self.dir.path().join(rel)
    }
    fn file(&self, name: &str, server: &Server, token: &str, host: &str, ca_pem: &str) -> PathBuf {
        let url = format!("https://127.0.0.1:{}", server.addr.port());
        let body = serde_json::json!({
            "lodeline_enrollment": 1, "host_id": host, "token": token,
            "enroll_url": url, "server_url": url, "server_ca_pem": ca_pem,
            "policy_keystore": {"pubkeys": [{
                "id": "k1", "ed25519_pubkey_b64": data_encoding::BASE64.encode(&[9u8; 32]),
                "valid_from": "2020-01-01T00:00:00Z", "valid_until": "2099-01-01T00:00:00Z"}]},
        });
        let p = self.p(name);
        std::fs::write(&p, serde_json::to_vec(&body).unwrap()).unwrap();
        std::fs::set_permissions(&p, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
        p
    }
    fn args(&self, file: PathBuf) -> Args {
        std::fs::create_dir_all(self.p("s")).unwrap();
        Args {
            file,
            config: Some(self.p("s/sender.yaml")),
            state_db: Some(self.p("s/state.db")),
            events_dir: Some(self.p("s/events")),
            control_socket: Some(self.p("s/ctl.sock")),
            keystore: Some(self.p("s/ks.pem")),
            sender_dir: Some(self.p("s/sender")),
        }
    }
    fn exists(&self, rel: &str) -> bool {
        self.p(rel).exists()
    }
}

fn claim_in_process(l: &Layout, host_id: &str) -> Claim {
    use lodeline_core::host_meta::HostIdClaim;
    let db = l.state_db.as_ref().unwrap();
    match HashCache::open(db)
        .unwrap()
        .host_meta_claim_host_id(host_id)
        .unwrap()
    {
        HostIdClaim::Claimed | HostIdClaim::AlreadySet => Claim::Done,
        HostIdClaim::Conflict { .. } => Claim::Conflict,
    }
}

async fn enroll(args: &Args, pacing: Pacing) -> i32 {
    let claim = |l: &Layout, h: &str| claim_in_process(l, h);
    let env = Env {
        root: false,
        claim: &claim,
        pacing,
        top: PathBuf::from("/"),
    };
    run(args, &env).await
}

async fn go(args: &Args) -> i32 {
    enroll(
        args,
        Pacing {
            network_waits: vec![std::time::Duration::from_millis(50); 2],
        },
    )
    .await
}

fn mode(p: &Path) -> u32 {
    std::os::unix::fs::MetadataExt::mode(&std::fs::metadata(p).unwrap()) & 0o7777
}

#[tokio::test(flavor = "multi_thread")]
async fn enrolls_a_host_and_writes_every_file() {
    let s = server(None).await;
    let h = Host::new();
    let args = h.args(h.file("host.json", &s, &s.token(HOST), HOST, &s.ca_pem()));
    assert_eq!(go(&args).await, 0);

    assert_eq!(mode(&h.p("s/sender/client.key")), 0o600);
    for f in ["s/sender/client.crt", "s/ks.pem", "s/sender.yaml"] {
        assert_eq!(mode(&h.p(f)), 0o644, "{f}");
    }
    assert_eq!(mode(&h.p("s/sender")), 0o750);
    assert!(std::fs::read_to_string(h.p("s/sender/client.key"))
        .unwrap()
        .starts_with("-----BEGIN PRIVATE KEY"));
    assert_eq!(s.issued_lines(), 1);

    let cfg = lodeline_sender::config::SenderConfig::load(&h.p("s/sender.yaml")).unwrap();
    assert_eq!(cfg.host_id.as_deref(), Some(HOST));
    assert_eq!(cfg.client_key_path, Some(h.p("s/sender/client.key")));
    assert_eq!(cfg.server_ca_path, Some(h.p("s/server-ca.pem")));
    assert!(h.exists("s/server-ca.pem"));
    lodeline_core::policy::pubkeys::Keystore::load_from_file(h.p("s/ks.pem")).unwrap();
    let db = HashCache::open(&h.p("s/state.db")).unwrap();
    assert!(matches!(
        db.host_meta_claim_host_id(HOST).unwrap(),
        lodeline_core::host_meta::HostIdClaim::AlreadySet
    ));
    // The sender's own P-256 certificate is under the CA and names the host.
    let crt = std::fs::read_to_string(h.p("s/sender/client.crt")).unwrap();
    assert!(crt.starts_with("-----BEGIN CERTIFICATE"));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_rerun_after_success_makes_no_request() {
    let s = server(None).await;
    let h = Host::new();
    let args = h.args(h.file("host.json", &s, &s.token(HOST), HOST, &s.ca_pem()));
    assert_eq!(go(&args).await, 0);
    let before: Vec<_> = [
        "s/sender/client.key",
        "s/sender/client.crt",
        "s/sender.yaml",
    ]
    .iter()
    .map(|f| std::fs::read(h.p(f)).unwrap())
    .collect();
    s.task.abort();
    let _ = s.task.await;
    // With the listener gone, any request would end in exit 6.
    assert_eq!(go(&args).await, 0);
    let after: Vec<_> = [
        "s/sender/client.key",
        "s/sender/client.crt",
        "s/sender.yaml",
    ]
    .iter()
    .map(|f| std::fs::read(h.p(f)).unwrap())
    .collect();
    assert_eq!(before, after);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_lost_certificate_needs_a_new_token_and_keeps_the_key() {
    let s = server(None).await;
    let h = Host::new();
    let file = h.file("host.json", &s, &s.token(HOST), HOST, &s.ca_pem());
    let args = h.args(file);
    assert_eq!(go(&args).await, 0);
    let key = std::fs::read(h.p("s/sender/client.key")).unwrap();
    std::fs::remove_file(h.p("s/sender/client.crt")).unwrap();

    assert_eq!(go(&args).await, 5, "the same token is spent");
    assert!(!h.exists("s/sender/client.crt"));
    let again = h.args(h.file("host2.json", &s, &s.token(HOST), HOST, &s.ca_pem()));
    assert_eq!(go(&again).await, 0);
    assert_eq!(std::fs::read(h.p("s/sender/client.key")).unwrap(), key);
    assert!(h.exists("s/sender/client.crt"));
    assert_eq!(s.issued_lines(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_ca_in_the_file_that_the_listener_does_not_chain_to_stops_before_the_token_is_sent() {
    let s = server(None).await;
    let other = tempfile::tempdir().unwrap();
    ca(other.path(), "other-ca");
    let other_pem = std::fs::read_to_string(other.path().join("ca.crt")).unwrap();
    let h = Host::new();
    let token = s.token(HOST);
    let args = h.args(h.file("host.json", &s, &token, HOST, &other_pem));
    assert_eq!(go(&args).await, 6);
    assert_eq!(
        s.redeem(&token, HOST).await,
        200,
        "the token was never sent"
    );
    assert!(!h.exists("s/sender.yaml") && !h.exists("s/ks.pem"));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_spent_token_exits_5_and_writes_no_config() {
    let s = server(None).await;
    let h = Host::new();
    let token = s.token(HOST);
    assert_eq!(s.redeem(&token, HOST).await, 200);
    let args = h.args(h.file("host.json", &s, &token, HOST, &s.ca_pem()));
    assert_eq!(go(&args).await, 5);
    for f in [
        "s/server-ca.pem",
        "s/ks.pem",
        "s/sender.yaml",
        "s/sender/client.crt",
    ] {
        assert!(!h.exists(f), "{f}");
    }
    assert!(
        h.exists("s/sender/client.key"),
        "the key is kept for the next token"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_busy_server_is_retried() {
    let s = server(None).await;
    let h = Host::new();
    let args = h.args(h.file("host.json", &s, &s.token(HOST), HOST, &s.ca_pem()));
    let (tx, rx) = std::sync::mpsc::channel();
    let st = s.st.clone();
    let holder = std::thread::spawn(move || {
        let _g = st.enroll.as_ref().unwrap().mint.lock().unwrap();
        tx.send(()).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(1500));
    });
    rx.recv().unwrap();
    assert_eq!(go(&args).await, 0);
    holder.join().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn an_existing_config_with_other_content_stops_the_run_before_the_claim() {
    let s = server(None).await;
    let h = Host::new();
    let token = s.token(HOST);
    let args = h.args(h.file("host.json", &s, &token, HOST, &s.ca_pem()));
    std::fs::write(h.p("s/sender.yaml"), "server_base_url: https://x\n").unwrap();
    let claimed = AtomicBool::new(false);
    let claim = |_: &Layout, _: &str| {
        claimed.store(true, Ordering::SeqCst);
        Claim::Done
    };
    let env = Env {
        root: false,
        claim: &claim,
        pacing: Pacing::default(),
        top: PathBuf::from("/"),
    };
    assert_eq!(run(&args, &env).await, 4);
    assert!(!claimed.load(Ordering::SeqCst));
    assert_eq!(
        std::fs::read_to_string(h.p("s/sender.yaml")).unwrap(),
        "server_base_url: https://x\n"
    );
    assert_eq!(s.redeem(&token, HOST).await, 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_host_with_another_host_id_exits_3_with_no_key() {
    let s = server(None).await;
    let h = Host::new();
    let token = s.token(HOST);
    let args = h.args(h.file("host.json", &s, &token, HOST, &s.ca_pem()));
    HashCache::open(&h.p("s/state.db"))
        .unwrap()
        .host_meta_claim_host_id(OTHER)
        .unwrap();
    assert_eq!(go(&args).await, 3);
    assert!(!h.exists("s/sender/client.key"));
    assert_eq!(s.redeem(&token, HOST).await, 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_file_for_another_host_on_an_enrolled_host_exits_3_and_changes_nothing() {
    let s = server(None).await;
    let h = Host::new();
    let args = h.args(h.file("host.json", &s, &s.token(HOST), HOST, &s.ca_pem()));
    assert_eq!(go(&args).await, 0);
    let files = [
        "s/sender/client.key",
        "s/sender/client.crt",
        "s/sender.yaml",
        "s/ks.pem",
    ];
    let before: Vec<_> = files
        .iter()
        .map(|f| std::fs::read(h.p(f)).unwrap())
        .collect();

    let token = s.token(OTHER);
    let other = h.args(h.file("other.json", &s, &token, OTHER, &s.ca_pem()));
    assert_eq!(go(&other).await, 3);
    let after: Vec<_> = files
        .iter()
        .map(|f| std::fs::read(h.p(f)).unwrap())
        .collect();
    assert_eq!(before, after);
    assert_eq!(
        s.redeem(&token, OTHER).await,
        200,
        "the token was never sent"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_certificate_under_a_root_missing_from_the_file_is_saved_as_rejected() {
    // The listener's certificate chains to `tls`; the host certificate is issued under `s`'s CA.
    let tls = tempfile::tempdir().unwrap();
    ca(tls.path(), "tls-ca");
    let s = server(Some(tls.path())).await;
    let h = Host::new();
    let tls_pem = std::fs::read_to_string(tls.path().join("ca.crt")).unwrap();
    let args = h.args(h.file("host.json", &s, &s.token(HOST), HOST, &tls_pem));
    assert_eq!(go(&args).await, 5);
    assert!(!h.exists("s/sender/client.crt"));
    assert_eq!(mode(&h.p("s/sender/client.crt.rejected")), 0o644);
    assert!(!h.exists("s/sender.yaml"));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_user_without_the_path_flags_is_refused_before_anything_is_written() {
    let s = server(None).await;
    let h = Host::new();
    let token = s.token(HOST);
    let mut args = h.args(h.file("host.json", &s, &token, HOST, &s.ca_pem()));
    args.keystore = None;
    assert_eq!(go(&args).await, 1);
    assert!(!h.exists("s/state.db"));
    assert_eq!(s.redeem(&token, HOST).await, 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_bad_enrollment_file_exits_2() {
    let h = Host::new();
    let p = h.p("host.json");
    std::fs::write(&p, "{\"lodeline_enrollment\": 2}").unwrap();
    std::fs::set_permissions(&p, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
    assert_eq!(go(&h.args(p)).await, 2);
    assert_eq!(go(&h.args(h.p("missing.json"))).await, 2);
}

/// Uses up the source's 10 connections, then enrolls: the reset is retried after the
/// first backoff and the bucket has refilled by then. Takes about 10 s.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "waits 10 s for the listener's rate limit to refill"]
async fn a_rate_limited_connection_is_retried_and_succeeds() {
    let s = server(None).await;
    let h = Host::new();
    let args = h.args(h.file("host.json", &s, &s.token(HOST), HOST, &s.ca_pem()));
    for _ in 0..10 {
        let _ = s.redeem("x", HOST).await;
    }
    assert_eq!(enroll(&args, Pacing::default()).await, 0);
}
