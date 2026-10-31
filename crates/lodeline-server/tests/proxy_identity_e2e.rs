//! T-11 S1 — live-TLS e2e for the proxy identity guard (PX-008/009, AC-04).
//!
//! Real rustls handshakes with two test CAs (host CA, proxy CA) in one client
//! bundle, as production does (control-plane §1.1). openssl builds the PKI;
//! reqwest is the mTLS client. Binds 127.0.0.1:0.

use lodeline_proxy_api::{ApiError, ErrorCode};
use lodeline_server::app::{build_router_with_proxy, AppState};
use lodeline_server::auth::ReadToken;
use lodeline_server::config::ServerConfig;
use lodeline_server::fleet_index::FleetIndex;
use lodeline_server::persist::HighWater;
use lodeline_server::proxy::identity::proxy_san;
use lodeline_server::proxy::registry::{ProxyRecord, ProxyState};
use lodeline_server::proxy::ProxyContext;
use lodeline_server::tls_accept::PeerCertAcceptor;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};

/// Unique certificate serial per leaf (hex with 0x prefix). Passing `-set_serial`
/// avoids the shared `ca.srl` state file of `-CAcreateserial`.
fn next_serial() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(1);
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos() as u64);
    format!("0x{:x}", (t << 20) | N.fetch_add(1, Ordering::Relaxed))
}

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

fn genkey(path: &Path) {
    run(&[
        "genpkey".as_ref(),
        "-algorithm".as_ref(),
        "RSA".as_ref(),
        "-pkeyopt".as_ref(),
        "rsa_keygen_bits:2048".as_ref(),
        "-out".as_ref(),
        path.as_os_str(),
    ]);
}

/// Self-signed CA `<name>.crt`/`<name>.key` with subject CN=`cn`.
fn make_ca(dir: &Path, name: &str, cn: &str) {
    let key = dir.join(format!("{name}.key"));
    genkey(&key);
    let subj = format!("/CN={cn}");
    run(&[
        "req".as_ref(),
        "-x509".as_ref(),
        "-new".as_ref(),
        "-key".as_ref(),
        key.as_os_str(),
        "-days".as_ref(),
        "1".as_ref(),
        "-subj".as_ref(),
        subj.as_ref(),
        "-addext".as_ref(),
        "basicConstraints=critical,CA:TRUE".as_ref(),
        "-addext".as_ref(),
        "subjectKeyIdentifier=hash".as_ref(),
        "-out".as_ref(),
        dir.join(format!("{name}.crt")).as_os_str(),
    ]);
}

/// Leaf signed by CA `ca`. Returns (crt, key).
fn make_leaf(dir: &Path, ca: &str, name: &str, cn: &str, ext: &str) -> (PathBuf, PathBuf) {
    let key = dir.join(format!("{name}.key"));
    let csr = dir.join(format!("{name}.csr"));
    let crt = dir.join(format!("{name}.crt"));
    let extf = dir.join(format!("{name}.ext"));
    std::fs::write(&extf, ext).unwrap();
    genkey(&key);
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
    run(&[
        "x509".as_ref(),
        "-req".as_ref(),
        "-in".as_ref(),
        csr.as_os_str(),
        "-CA".as_ref(),
        dir.join(format!("{ca}.crt")).as_os_str(),
        "-CAkey".as_ref(),
        dir.join(format!("{ca}.key")).as_os_str(),
        "-set_serial".as_ref(),
        next_serial().as_str().as_ref(),
        "-days".as_ref(),
        "1".as_ref(),
        "-extfile".as_ref(),
        extf.as_os_str(),
        "-out".as_ref(),
        crt.as_os_str(),
    ]);
    (crt, key)
}

fn proxy_leaf(dir: &Path, name: &str, proxy_id: &str) -> (PathBuf, PathBuf) {
    let ext = format!(
        "subjectAltName=DNS:{}\nextendedKeyUsage=clientAuth\nbasicConstraints=CA:FALSE\nauthorityKeyIdentifier=keyid\n",
        proxy_san(proxy_id)
    );
    make_leaf(dir, "proxyca", name, proxy_id, &ext)
}

const HOST: &str = "018f9c1a-0000-7000-8000-0000000000e2";

fn host_leaf(dir: &Path, name: &str) -> (PathBuf, PathBuf) {
    let ext = format!(
        "subjectAltName=DNS:{HOST}\nextendedKeyUsage=clientAuth\nbasicConstraints=CA:FALSE\n"
    );
    make_leaf(dir, "hostca", name, HOST, &ext)
}

fn fingerprint(crt: &Path) -> String {
    let pem = std::fs::read(crt).unwrap();
    let mut rd = std::io::BufReader::new(&pem[..]);
    let certs: Vec<_> = rustls_pemfile::certs(&mut rd)
        .collect::<Result<_, _>>()
        .unwrap();
    blake3::hash(certs[0].as_ref()).to_hex().to_string()
}

fn state(dir: &Path) -> Arc<AppState> {
    Arc::new(AppState {
        events_out_dir: dir.to_path_buf(),
        policy_bundle_path: dir.join("signed-policy.json"),
        rule_packs_bundle_path: None,
        artifacts_dir: None,
        high_water_path: dir.join(".high-water.json"),
        allowlist: parking_lot::RwLock::new(None),
        high_water: Mutex::new(HighWater::default()),
        fleet_index: FleetIndex::new(),
        read_token: ReadToken(None),
        active_window_days: 7,
        audit_key: None,
        audit_head: Mutex::new(None),
        allowlist_path: None,
        enroll: None,
        events_require_cert_host_match: false,
    })
}

fn rec(id: &str, st: ProxyState, cur: Option<String>, next: Option<String>) -> ProxyRecord {
    ProxyRecord {
        proxy_id: id.into(),
        display_name: id.into(),
        state: st,
        fp_current: cur,
        fp_next: next,
        created_at: "2026-10-11T00:00:00Z".into(),
        updated_at: "2026-10-11T00:00:00Z".into(),
    }
}

fn tls_config(server_crt: &Path, server_key: &Path, bundle: &Path) -> rustls::ServerConfig {
    let read = |p: &Path| std::fs::read(p).unwrap();
    let certs: Vec<_> = rustls_pemfile::certs(&mut std::io::BufReader::new(&read(server_crt)[..]))
        .collect::<Result<_, _>>()
        .unwrap();
    let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(&read(server_key)[..]))
        .unwrap()
        .unwrap();
    let cas: Vec<_> = rustls_pemfile::certs(&mut std::io::BufReader::new(&read(bundle)[..]))
        .collect::<Result<_, _>>()
        .unwrap();
    let mut roots = rustls::RootCertStore::empty();
    for c in cas {
        roots.add(c).unwrap();
    }
    let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .unwrap();
    rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)
        .unwrap()
}

fn client(trust: &Path, crt: &Path, key: &Path) -> reqwest::Client {
    let mut id = std::fs::read(key).unwrap();
    id.extend_from_slice(&std::fs::read(crt).unwrap());
    reqwest::Client::builder()
        .use_rustls_tls()
        .add_root_certificate(
            reqwest::Certificate::from_pem(&std::fs::read(trust).unwrap()).unwrap(),
        )
        .identity(reqwest::Identity::from_pem(&id).unwrap())
        .build()
        .unwrap()
}

/// Test PKI: host CA, proxy CA, bundle of both, server leaf.
struct Pki {
    dir: tempfile::TempDir,
}

impl Pki {
    fn new() -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        make_ca(d, "hostca", "test-host-ca");
        make_ca(d, "proxyca", "test-proxy-ca");
        let mut bundle = std::fs::read(d.join("hostca.crt")).unwrap();
        bundle.extend(std::fs::read(d.join("proxyca.crt")).unwrap());
        std::fs::write(d.join("bundle.pem"), bundle).unwrap();
        make_leaf(
            d,
            "hostca",
            "server",
            "localhost",
            "subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n",
        );
        Pki { dir }
    }
    fn p(&self, f: &str) -> PathBuf {
        self.dir.path().join(f)
    }
    fn config(&self) -> ServerConfig {
        let y = format!(
            "bind: \"127.0.0.1:0\"\ntls_cert_path: {c}\ntls_key_path: {k}\nclient_ca_path: {b}\n\
             events_out_dir: {e}\npolicy_bundle_path: {pb}\n\
             proxy:\n  ca_path: {pca}\n  registry_path: {r}\n  registry_init: true\n",
            c = self.p("server.crt").display(),
            k = self.p("server.key").display(),
            b = self.p("bundle.pem").display(),
            e = self.dir.path().display(),
            pb = self.p("signed-policy.json").display(),
            pca = self.p("proxyca.crt").display(),
            r = self.p("proxies.json").display(),
        );
        serde_yaml::from_str(&y).unwrap()
    }
    /// Spawn the server; `with_proxy=false` is the proxy-section-absent case.
    async fn spawn(&self, with_proxy: bool) -> (u16, Option<Arc<ProxyContext>>) {
        let ctx = if with_proxy {
            Some(Arc::new(
                ProxyContext::load(&self.config()).unwrap().unwrap(),
            ))
        } else {
            None
        };
        let tls = axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(tls_config(
            &self.p("server.crt"),
            &self.p("server.key"),
            &self.p("bundle.pem"),
        )));
        let app = build_router_with_proxy(state(self.dir.path()), ctx.clone());
        let handle = axum_server::Handle::new();
        let h = handle.clone();
        tokio::spawn(async move {
            axum_server::bind("127.0.0.1:0".parse().unwrap())
                .handle(h)
                .acceptor(PeerCertAcceptor::new(tls))
                .serve(app.into_make_service())
                .await
                .unwrap();
        });
        let addr = handle.listening().await.expect("server must bind");
        (addr.port(), ctx)
    }
    fn client_for(&self, crt: &Path, key: &Path) -> reqwest::Client {
        client(&self.p("hostca.crt"), crt, key)
    }
}

/// Everything compared byte-for-byte in the 404 assertions.
#[derive(Debug, PartialEq, Eq)]
struct Resp {
    status: u16,
    content_type: Option<String>,
    content_length: Option<String>,
    body: Vec<u8>,
}

async fn to_resp(r: reqwest::Response) -> Resp {
    let h = |n: &str| r.headers().get(n).map(|v| v.to_str().unwrap().to_string());
    let (content_type, content_length) = (h("content-type"), h("content-length"));
    let status = r.status().as_u16();
    Resp {
        status,
        content_type,
        content_length,
        body: r.bytes().await.unwrap().to_vec(),
    }
}

async fn get(c: &reqwest::Client, port: u16, path: &str) -> Resp {
    to_resp(
        c.get(format!("https://127.0.0.1:{port}{path}"))
            .send()
            .await
            .unwrap(),
    )
    .await
}

/// Identity passed, no config issued yet: 404 with the `config_unavailable` body,
/// which must not be mistaken for `proxy_unknown`.
fn assert_config_unavailable(r: &Resp) {
    assert_eq!(r.status, 404);
    assert_eq!(
        r.body,
        serde_json::to_vec(&ApiError::from_code(ErrorCode::ConfigUnavailable)).unwrap()
    );
}

fn json_resp(status: u16, body: Vec<u8>) -> Resp {
    Resp {
        status,
        content_type: Some("application/json".into()),
        content_length: Some(body.len().to_string()),
        body,
    }
}

fn proxy_unknown() -> Resp {
    json_resp(
        404,
        serde_json::to_vec(&ApiError::from_code(ErrorCode::ProxyUnknown)).unwrap(),
    )
}

fn host_unknown() -> Resp {
    json_resp(404, br#"{"error":"host_unknown"}"#.to_vec())
}

#[tokio::test]
async fn proxy_cert_reaches_config_after_passing_check() {
    let pki = Pki::new();
    let (crt, key) = proxy_leaf(pki.dir.path(), "px1", "px1");
    let (port, ctx) = pki.spawn(true).await;
    ctx.unwrap()
        .registry
        .seed_for_test(rec(
            "px1",
            ProxyState::Active,
            Some(fingerprint(&crt)),
            None,
        ))
        .unwrap();
    let c = pki.client_for(&crt, &key);
    assert_config_unavailable(&get(&c, port, "/v1/proxy-config").await);
    assert_config_unavailable(&get(&c, port, "/v1/proxies/px1/config").await);
    // Path id differing from the cert's proxy_id is an identity mismatch.
    assert_eq!(
        get(&c, port, "/v1/proxies/other/config").await,
        proxy_unknown()
    );
}

#[tokio::test]
async fn identity_failures_are_byte_identical_404() {
    let pki = Pki::new();
    let d = pki.dir.path();
    let (ok_crt, _) = proxy_leaf(d, "px1", "px1");
    let (un_crt, un_key) = proxy_leaf(d, "ghost", "ghost");
    let (fp_crt, fp_key) = proxy_leaf(d, "px2", "px2");
    let (pend_crt, pend_key) = proxy_leaf(d, "px3", "px3");
    let (hcrt, hkey) = host_leaf(d, "agent");
    // Class confusion: a HOST-CA leaf carrying a valid-looking proxy SAN, and
    // registered under that proxy_id.
    let (cc_crt, cc_key) = make_leaf(
        d,
        "hostca",
        "confused",
        "px9",
        &format!(
            "subjectAltName=DNS:{}\nextendedKeyUsage=clientAuth\nbasicConstraints=CA:FALSE\n",
            proxy_san("px9")
        ),
    );
    let (port, ctx) = pki.spawn(true).await;
    let reg = &ctx.unwrap().registry;
    reg.seed_for_test(rec(
        "px9",
        ProxyState::Active,
        Some(fingerprint(&cc_crt)),
        None,
    ))
    .unwrap();
    reg.seed_for_test(rec(
        "px1",
        ProxyState::Active,
        Some(fingerprint(&ok_crt)),
        None,
    ))
    .unwrap();
    // px2 registered with a DIFFERENT fingerprint than the cert presented.
    reg.seed_for_test(rec(
        "px2",
        ProxyState::Active,
        Some(fingerprint(&ok_crt)),
        None,
    ))
    .unwrap();
    reg.seed_for_test(rec(
        "px3",
        ProxyState::Pending,
        Some(fingerprint(&pend_crt)),
        None,
    ))
    .unwrap();
    for (name, crt, key) in [
        (
            "host-CA leaf with proxy SAN + registered fp",
            &cc_crt,
            &cc_key,
        ),
        ("unknown proxy", &un_crt, &un_key),
        ("fingerprint mismatch", &fp_crt, &fp_key),
        ("pending", &pend_crt, &pend_key),
        ("host cert", &hcrt, &hkey),
    ] {
        let c = pki.client_for(crt, key);
        assert_eq!(
            get(&c, port, "/v1/proxy-config").await,
            proxy_unknown(),
            "{name}"
        );
    }
}

#[tokio::test]
async fn disabled_and_retired_answer_fixed_codes_and_next_fp_is_accepted() {
    let pki = Pki::new();
    let d = pki.dir.path();
    let (crt, key) = proxy_leaf(d, "px1", "px1");
    let (ncrt, nkey) = proxy_leaf(d, "px1n", "px1");
    let (port, ctx) = pki.spawn(true).await;
    let reg = &ctx.unwrap().registry;
    reg.seed_for_test(rec(
        "px1",
        ProxyState::Active,
        Some(fingerprint(&crt)),
        Some(fingerprint(&ncrt)),
    ))
    .unwrap();
    // fp_next works.
    let r = get(&pki.client_for(&ncrt, &nkey), port, "/v1/proxy-config").await;
    assert_config_unavailable(&r);
    for (st, code) in [
        (ProxyState::Disabled, ErrorCode::Disabled),
        (ProxyState::Retired, ErrorCode::Retired),
    ] {
        reg.seed_for_test(rec("px1", st, Some(fingerprint(&crt)), None))
            .unwrap();
        let r = get(&pki.client_for(&crt, &key), port, "/v1/proxy-config").await;
        assert_eq!(
            r,
            json_resp(403, serde_json::to_vec(&ApiError::from_code(code)).unwrap())
        );
    }
}

#[tokio::test]
async fn proxy_cert_is_rejected_on_host_routes_and_host_cert_still_works() {
    let pki = Pki::new();
    let d = pki.dir.path();
    let (pcrt, pkey) = proxy_leaf(d, "px1", "px1");
    let (hcrt, hkey) = host_leaf(d, "agent");
    let (port, ctx) = pki.spawn(true).await;
    let ctx2 = ctx.unwrap();
    ctx2.registry
        .seed_for_test(rec(
            "px1",
            ProxyState::Active,
            Some(fingerprint(&pcrt)),
            None,
        ))
        .unwrap();
    let pc = pki.client_for(&pcrt, &pkey);
    let hc = pki.client_for(&hcrt, &hkey);
    // Issuer-only rule: an UNREGISTERED proxy-CA leaf is rejected too.
    let (ucrt, ukey) = proxy_leaf(d, "ghost", "ghost");
    let uc = pki.client_for(&ucrt, &ukey);
    // holds_fingerprint alone: a HOST-CA leaf whose fingerprint is registered.
    let (rcrt, rkey) = host_leaf(d, "agent-registered");
    ctx2.registry
        .seed_for_test(rec(
            "pxh",
            ProxyState::Active,
            Some(fingerprint(&rcrt)),
            None,
        ))
        .unwrap();
    let rc = pki.client_for(&rcrt, &rkey);
    for path in [
        format!("/v1/policy?host_id={HOST}"),
        format!("/v1/rule-packs?host_id={HOST}"),
    ] {
        for (who, c) in [
            ("proxy", &pc),
            ("unregistered proxy", &uc),
            ("registered host", &rc),
        ] {
            assert_eq!(get(c, port, &path).await, host_unknown(), "{who} {path}");
        }
    }
    // POST /v1/events with a proxy cert: rejected before the body is parsed
    // (an empty/invalid body would otherwise be a 4xx from the extractor).
    let r = pc
        .post(format!("https://127.0.0.1:{port}/v1/events"))
        .body("not json")
        .send()
        .await
        .unwrap();
    assert_eq!(to_resp(r).await, host_unknown());
    // A host cert passes the guard (reaches the handler: no policy bundle).
    let r = get(&hc, port, &format!("/v1/policy?host_id={HOST}")).await;
    assert_eq!(r.status, 404);
    assert_eq!(r.body, br#"{"error":"no_policy"}"#.to_vec());
}

#[tokio::test]
async fn proxy_section_absent_means_no_proxy_routes() {
    let pki = Pki::new();
    let d = pki.dir.path();
    let (pcrt, pkey) = proxy_leaf(d, "px1", "px1");
    let (port, ctx) = pki.spawn(false).await;
    assert!(ctx.is_none());
    let pc = pki.client_for(&pcrt, &pkey);
    // Same answer as any unknown route (axum's empty 404), not proxy_unknown.
    let r = get(&pc, port, "/v1/proxy-config").await;
    assert_eq!(r.status, 404);
    assert!(r.body.is_empty(), "{:?}", String::from_utf8_lossy(&r.body));
    assert_eq!(r, get(&pc, port, "/v1/definitely-not-a-route").await);
}

#[test]
fn boot_refuses_identical_host_and_proxy_ca_dn() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    make_ca(d, "hostca", "same-dn-ca");
    make_ca(d, "proxyca", "same-dn-ca");
    let mut bundle = std::fs::read(d.join("hostca.crt")).unwrap();
    bundle.extend(std::fs::read(d.join("proxyca.crt")).unwrap());
    std::fs::write(d.join("bundle.pem"), bundle).unwrap();
    let y = format!(
        "bind: \"127.0.0.1:0\"\ntls_cert_path: /x/s.crt\ntls_key_path: /x/s.key\n\
         client_ca_path: {b}\nevents_out_dir: /x/e\npolicy_bundle_path: /x/p.json\n\
         proxy:\n  ca_path: {pca}\n  registry_path: {r}\n",
        b = d.join("bundle.pem").display(),
        pca = d.join("proxyca.crt").display(),
        r = d.join("proxies.json").display(),
    );
    let cfg: ServerConfig = serde_yaml::from_str(&y).unwrap();
    let err = ProxyContext::load(&cfg).err().expect("must refuse");
    assert!(format!("{err:#}").contains("share subject DN"), "{err:#}");
}

#[test]
fn boot_refuses_proxy_ca_missing_from_client_bundle() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    make_ca(d, "hostca", "host-ca");
    make_ca(d, "proxyca", "proxy-ca");
    let y = format!(
        "bind: \"127.0.0.1:0\"\ntls_cert_path: /x/s.crt\ntls_key_path: /x/s.key\n\
         client_ca_path: {b}\nevents_out_dir: /x/e\npolicy_bundle_path: /x/p.json\n\
         proxy:\n  ca_path: {pca}\n  registry_path: {r}\n",
        b = d.join("hostca.crt").display(),
        pca = d.join("proxyca.crt").display(),
        r = d.join("proxies.json").display(),
    );
    let cfg: ServerConfig = serde_yaml::from_str(&y).unwrap();
    assert!(ProxyContext::load(&cfg).is_err());
}

#[test]
fn boot_refuses_bundle_with_only_the_proxy_ca() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    make_ca(d, "proxyca", "proxy-ca");
    let y = format!(
        "bind: \"127.0.0.1:0\"\ntls_cert_path: /x/s.crt\ntls_key_path: /x/s.key\n\
         client_ca_path: {b}\nevents_out_dir: /x/e\npolicy_bundle_path: /x/p.json\n\
         proxy:\n  ca_path: {b}\n  registry_path: {r}\n  registry_init: true\n",
        b = d.join("proxyca.crt").display(),
        r = d.join("proxies.json").display(),
    );
    let cfg: ServerConfig = serde_yaml::from_str(&y).unwrap();
    let err = ProxyContext::load(&cfg).err().expect("must refuse");
    assert!(format!("{err:#}").contains("no CA other"), "{err:#}");
}

#[test]
fn boot_refuses_missing_registry_unless_init() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    make_ca(d, "hostca", "host-ca");
    make_ca(d, "proxyca", "proxy-ca");
    let mut bundle = std::fs::read(d.join("hostca.crt")).unwrap();
    bundle.extend(std::fs::read(d.join("proxyca.crt")).unwrap());
    std::fs::write(d.join("bundle.pem"), bundle).unwrap();
    let y = |init: &str| {
        format!(
            "bind: \"127.0.0.1:0\"\ntls_cert_path: /x/s.crt\ntls_key_path: /x/s.key\n\
             client_ca_path: {b}\nevents_out_dir: /x/e\npolicy_bundle_path: /x/p.json\n\
             proxy:\n  ca_path: {pca}\n  registry_path: {r}\n{init}",
            b = d.join("bundle.pem").display(),
            pca = d.join("proxyca.crt").display(),
            r = d.join("proxies.json").display(),
        )
    };
    let cfg: ServerConfig = serde_yaml::from_str(&y("")).unwrap();
    assert!(ProxyContext::load(&cfg).is_err());
    let cfg: ServerConfig = serde_yaml::from_str(&y("  registry_init: true\n")).unwrap();
    assert!(ProxyContext::load(&cfg).unwrap().is_some());
    // Now the file exists, so no init flag is needed.
    let cfg: ServerConfig = serde_yaml::from_str(&y("")).unwrap();
    assert!(ProxyContext::load(&cfg).unwrap().is_some());
}
