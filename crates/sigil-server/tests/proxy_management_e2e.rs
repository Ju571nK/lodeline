//! T-11 S2a — live-TLS e2e for proxy management (PX-008/012, AC-13).
//!
//! Real rustls handshakes; openssl builds the PKI (host CA, proxy CA, one
//! bundle, as production). reqwest is the mTLS client. Binds 127.0.0.1:0.

#![cfg(unix)]

use sigil_proxy_api::verifier::verifier_for;
use sigil_proxy_api::{ApiError, ErrorCode};
use sigil_server::app::{build_router_with_proxy, AppState};
use sigil_server::auth::ReadToken;
use sigil_server::config::ServerConfig;
use sigil_server::fleet_index::FleetIndex;
use sigil_server::persist::HighWater;
use sigil_server::proxy::audit::AUDIT_FILE;
use sigil_server::proxy::cli::{self, ConnArgs, ProxyCommand};
use sigil_server::proxy::identity::proxy_san;
use sigil_server::proxy::registry::ProxyState;
use sigil_server::proxy::verifiers::{Scope, VerifierEntry};
use sigil_server::proxy::ProxyContext;
use sigil_server::tls_accept::PeerCertAcceptor;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};

const READ_TOKEN: &str = "read-bearer-token";
const T_ID: &str = "tok-identity-CANARY-7f3a";
const T_CFG: &str = "tok-config-CANARY-9b1c";
const T_OTHER: &str = "tok-other-caller";
const T_EXPIRED: &str = "tok-expired";
const HOST: &str = "018f9c1a-0000-7000-8000-0000000000e2";
const FP_A: &str = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";

// ---- PKI helpers (same approach as proxy_identity_e2e.rs) -------------------

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
    sigil_server::enroll::sign::resolve_openssl().expect("openssl must be installed")
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

fn host_leaf(dir: &Path, name: &str, host_id: &str) -> (PathBuf, PathBuf) {
    let ext = format!(
        "subjectAltName=DNS:{host_id}\nextendedKeyUsage=clientAuth\nbasicConstraints=CA:FALSE\n"
    );
    make_leaf(dir, "hostca", name, host_id, &ext)
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
        read_token: ReadToken(Some(READ_TOKEN.into())),
        active_window_days: 7,
        audit_key: None,
        audit_head: Mutex::new(None),
        allowlist_path: None,
        enroll: None,
        events_require_cert_host_match: false,
    })
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

fn entry(id: &str, token: &str, scope: Scope, fp: &str, na: Option<&str>) -> VerifierEntry {
    VerifierEntry {
        key_id: id.into(),
        name: format!("{id}-name"),
        verifier: verifier_for(token),
        scope,
        caller_cert_fingerprint: fp.into(),
        not_after: na.map(str::to_string),
    }
}

fn write_verifiers(path: &Path, entries: &[VerifierEntry]) {
    std::fs::write(
        path,
        serde_json::to_vec(&serde_json::json!({"entries": entries})).unwrap(),
    )
    .unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

/// Test PKI + a running server with management enabled.
struct Fx {
    dir: tempfile::TempDir,
    port: u16,
    ctx: Arc<ProxyContext>,
    mgmt: (PathBuf, PathBuf),
    mgmt_fp: String,
}

impl Fx {
    fn p(&self, f: &str) -> PathBuf {
        self.dir.path().join(f)
    }
    fn mgmt_client(&self) -> reqwest::Client {
        client(&self.p("hostca.crt"), &self.mgmt.0, &self.mgmt.1)
    }
    fn client_for(&self, crt: &Path, key: &Path) -> reqwest::Client {
        client(&self.p("hostca.crt"), crt, key)
    }

    fn prepare(
        extra_entries: impl FnOnce(&str, &str) -> Vec<VerifierEntry>,
    ) -> (tempfile::TempDir, (PathBuf, PathBuf), String) {
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
        let mgmt = host_leaf(d, "mgmt", "mgmt-operator");
        let (m2, _) = host_leaf(d, "mgmt2", "mgmt-operator-2");
        let (fp, fp2) = (fingerprint(&mgmt.0), fingerprint(&m2));
        write_verifiers(&d.join("verifiers.json"), &extra_entries(&fp, &fp2));
        (dir, mgmt, fp)
    }

    fn default_entries(fp: &str, fp2: &str) -> Vec<VerifierEntry> {
        vec![
            entry("idk", T_ID, Scope::Identity, fp, None),
            entry("cfgk", T_CFG, Scope::Config, fp, None),
            entry("othk", T_OTHER, Scope::Identity, fp2, None),
            entry(
                "expk",
                T_EXPIRED,
                Scope::Config,
                fp,
                Some("2000-01-01T00:00:00Z"),
            ),
        ]
    }

    fn config(dir: &Path) -> ServerConfig {
        let p = |f: &str| dir.join(f).display().to_string();
        let y = format!(
            "bind: \"127.0.0.1:0\"\ntls_cert_path: {}\ntls_key_path: {}\nclient_ca_path: {}\n\
             events_out_dir: {}\npolicy_bundle_path: {}\n\
             proxy:\n  ca_path: {}\n  registry_path: {}\n  registry_init: true\n  management_verifiers: {}\n",
            p("server.crt"),
            p("server.key"),
            p("bundle.pem"),
            dir.display(),
            p("signed-policy.json"),
            p("proxyca.crt"),
            p("proxies.json"),
            p("verifiers.json"),
        );
        serde_yaml::from_str(&y).unwrap()
    }

    async fn start(dir: tempfile::TempDir, mgmt: (PathBuf, PathBuf), mgmt_fp: String) -> Fx {
        let d = dir.path();
        let ctx = Arc::new(ProxyContext::load(&Self::config(d)).unwrap().unwrap());
        let tls = axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(tls_config(
            &d.join("server.crt"),
            &d.join("server.key"),
            &d.join("bundle.pem"),
        )));
        let app = build_router_with_proxy(state(d), Some(ctx.clone()));
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
        let port = handle.listening().await.expect("server must bind").port();
        Fx {
            dir,
            port,
            ctx,
            mgmt,
            mgmt_fp,
        }
    }

    async fn new() -> Fx {
        let (dir, mgmt, fp) = Self::prepare(Self::default_entries);
        Self::start(dir, mgmt, fp).await
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Resp {
    status: u16,
    content_type: Option<String>,
    body: Vec<u8>,
}

impl Resp {
    fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).unwrap_or(serde_json::Value::Null)
    }
    fn code(&self) -> String {
        self.json()["error"]["code"]
            .as_str()
            .unwrap_or("")
            .to_string()
    }
}

async fn send(
    c: &reqwest::Client,
    port: u16,
    method: &str,
    path: &str,
    bearer: Option<&str>,
    body: Option<&str>,
) -> Resp {
    let url = format!("https://127.0.0.1:{port}{path}");
    let mut rb = if method == "GET" {
        c.get(url)
    } else {
        c.post(url)
    };
    if let Some(b) = bearer {
        rb = rb.bearer_auth(b);
    }
    if let Some(b) = body {
        rb = rb
            .header("content-type", "application/json")
            .body(b.to_string());
    }
    let r = rb.send().await.unwrap();
    let content_type = r
        .headers()
        .get("content-type")
        .map(|v| v.to_str().unwrap().to_string());
    Resp {
        status: r.status().as_u16(),
        content_type,
        body: r.bytes().await.unwrap().to_vec(),
    }
}

fn err_body(code: ErrorCode) -> Vec<u8> {
    serde_json::to_vec(&ApiError::from_code(code)).unwrap()
}

/// Identity passed, no config issued yet: 404 `config_unavailable`.
fn assert_config_unavailable(r: &Resp) {
    assert_eq!(r.status, 404);
    assert_eq!(r.body, err_body(ErrorCode::ConfigUnavailable));
}

/// No usable identity: the byte-identical 404 `proxy_unknown`.
fn assert_proxy_unknown(r: &Resp) {
    assert_eq!(r.status, 404);
    assert_eq!(r.body, err_body(ErrorCode::ProxyUnknown));
}

fn audit_lines(fx: &Fx) -> Vec<serde_json::Value> {
    std::fs::read_to_string(fx.p(AUDIT_FILE))
        .unwrap_or_default()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

fn reg_body(id: &str) -> String {
    format!(r#"{{"proxy_id":"{id}","display_name":"Proxy {id}"}}"#)
}

fn fp_body(fp: &str) -> String {
    format!(r#"{{"fingerprint":"{fp}"}}"#)
}

// ---- tests -------------------------------------------------------------------

#[tokio::test]
async fn check_order_404_401_binding_403_expired() {
    let fx = Fx::new().await;
    let d = fx.dir.path();
    let (pcrt, pkey) = proxy_leaf(d, "px-cert", "pxc");
    let (hcrt, hkey) = host_leaf(d, "agent", HOST);
    let mc = fx.mgmt_client();
    let port = fx.port;

    // Reference "unknown route" answers per caller class (axum's empty 404).
    let hc = fx.client_for(&hcrt, &hkey);
    let pc = fx.client_for(&pcrt, &pkey);
    let unknown_h = send(&hc, port, "GET", "/v1/proxies/x/nothing", None, None).await;
    let unknown_p = send(&pc, port, "GET", "/v1/proxies/x/nothing", None, None).await;
    assert_eq!(unknown_h.status, 404);
    assert!(unknown_h.body.is_empty());
    assert_eq!(unknown_h, unknown_p);

    // (1) Not a management-caller cert: 404 identical to an unknown route, even
    // with a valid bearer, for every management route and for wrong methods.
    for (who, c, unknown) in [("host", &hc, &unknown_h), ("proxy", &pc, &unknown_p)] {
        for (m, path, body) in [
            ("POST", "/v1/proxies", Some(reg_body("pxa"))),
            // GET /v1/proxies is the read listing since S5; a wrong method on
            // the management path must still look like an unknown route.
            ("PUT", "/v1/proxies", None),
            ("POST", "/v1/proxies/pxa/fingerprints", Some(fp_body(FP_A))),
            ("POST", "/v1/proxies/pxa/disable", None),
            ("POST", "/v1/proxies/pxa/enable", None),
            ("POST", "/v1/proxies/pxa/retire", None),
        ] {
            let r = send(c, port, m, path, Some(T_ID), body.as_deref()).await;
            assert_eq!(&r, unknown, "{who} {m} {path}");
        }
    }
    assert!(fx.ctx.registry.get("pxa").is_none());

    // (2) Management cert, bearer missing / wrong / read token: 401.
    let r = send(
        &mc,
        port,
        "POST",
        "/v1/proxies",
        None,
        Some(&reg_body("pxa")),
    )
    .await;
    assert_eq!((r.status, r.code().as_str()), (401, "unauthorized"));
    assert_eq!(r.body, err_body(ErrorCode::Unauthorized));
    for bad in ["nope", READ_TOKEN, ""] {
        let r = send(
            &mc,
            port,
            "POST",
            "/v1/proxies",
            Some(bad),
            Some(&reg_body("pxa")),
        )
        .await;
        assert_eq!(r.status, 401, "bearer {bad:?}");
    }
    // Asserted requested_by is never authorization.
    let r = fx
        .mgmt_client()
        .post(format!("https://127.0.0.1:{port}/v1/proxies"))
        .header("x-sigil-requested-by", "root")
        .body(reg_body("pxa"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 401);

    // (3) A valid token from a DIFFERENT caller cert: 401 (bound entry).
    let r = send(
        &mc,
        port,
        "POST",
        "/v1/proxies",
        Some(T_OTHER),
        Some(&reg_body("pxa")),
    )
    .await;
    assert_eq!(r.status, 401);

    // (4) Expired entry: 401 (also where its scope would have sufficed).
    let r = send(
        &mc,
        port,
        "POST",
        "/v1/proxies/pxa/disable",
        Some(T_EXPIRED),
        None,
    )
    .await;
    assert_eq!(r.status, 401);

    // (5) Scope: config token on identity routes, identity token on disable: 403.
    for (path, body) in [
        ("/v1/proxies", Some(reg_body("pxa"))),
        ("/v1/proxies/pxa/fingerprints", Some(fp_body(FP_A))),
        ("/v1/proxies/pxa/enable", None),
        ("/v1/proxies/pxa/retire", None),
    ] {
        let r = send(&mc, port, "POST", path, Some(T_CFG), body.as_deref()).await;
        assert_eq!((r.status, r.code().as_str()), (403, "forbidden"), "{path}");
    }
    let r = send(
        &mc,
        port,
        "POST",
        "/v1/proxies/pxa/disable",
        Some(T_ID),
        None,
    )
    .await;
    assert_eq!(r.status, 403);

    // No state change from any of the above.
    assert!(fx.ctx.registry.get("pxa").is_none());
    // Denials were audited (401/403), without request data.
    let lines = audit_lines(&fx);
    assert!(lines
        .iter()
        .any(|l| l["http_status"] == 401 && l["reason"] == "wrong_cert_binding"));
    assert!(lines
        .iter()
        .any(|l| l["http_status"] == 401 && l["reason"] == "expired"));
    assert!(lines
        .iter()
        .any(|l| l["http_status"] == 403 && l["reason"] == "scope_insufficient"));
    assert!(lines
        .iter()
        .all(|l| l["caller_fingerprint"] == fx.mgmt_fp.as_str()));
}

#[tokio::test]
async fn lifecycle_transitions_rotation_and_illegal_moves() {
    let fx = Fx::new().await;
    let d = fx.dir.path();
    let (acrt, akey) = proxy_leaf(d, "px1a", "px1");
    let (bcrt, bkey) = proxy_leaf(d, "px1b", "px1");
    let (a_fp, b_fp) = (fingerprint(&acrt), fingerprint(&bcrt));
    let mc = fx.mgmt_client();
    let port = fx.port;
    let pa = fx.client_for(&acrt, &akey);
    let pb = fx.client_for(&bcrt, &bkey);
    let id = |path: &str, body: Option<String>| {
        let mc = mc.clone();
        let path = path.to_string();
        async move { send(&mc, port, "POST", &path, Some(T_ID), body.as_deref()).await }
    };
    let cfg = |path: &str| {
        let mc = mc.clone();
        let path = path.to_string();
        async move { send(&mc, port, "POST", &path, Some(T_CFG), None).await }
    };

    // Register: 201, pending; duplicate 409; bad bodies 422.
    let r = id("/v1/proxies", Some(reg_body("px1"))).await;
    assert_eq!(r.status, 201, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.json()["proxy"]["state"], "pending");
    assert_eq!(
        id("/v1/proxies", Some(reg_body("px1"))).await.code(),
        "already_exists"
    );
    for bad in [
        r#"{"proxy_id":"Bad_Id","display_name":"x"}"#.to_string(),
        r#"{"proxy_id":"ok","display_name":""}"#.to_string(),
        r#"{"proxy_id":"ok","display_name":"x","extra":1}"#.to_string(),
        "not json".to_string(),
    ] {
        let r = id("/v1/proxies", Some(bad)).await;
        assert_eq!((r.status, r.code().as_str()), (422, "semantic_invalid"));
    }
    // A pending proxy has no usable identity yet: proxy_unknown.
    assert_proxy_unknown(&send(&pa, port, "GET", "/v1/proxy-config", None, None).await);

    // Illegal while pending: disable and enable.
    assert_eq!(cfg("/v1/proxies/px1/disable").await.code(), "invalid_state");
    assert_eq!(
        id("/v1/proxies/px1/enable", None).await.code(),
        "invalid_state"
    );

    // First fingerprint becomes current and activates.
    let r = id("/v1/proxies/px1/fingerprints", Some(fp_body(&a_fp))).await;
    assert_eq!(r.status, 200);
    let rec = fx.ctx.registry.get("px1").unwrap();
    assert_eq!(rec.state, ProxyState::Active);
    assert_eq!(rec.fp_current.as_deref(), Some(a_fp.as_str()));
    assert_config_unavailable(&send(&pa, port, "GET", "/v1/proxy-config", None, None).await);

    // Fingerprint validation and uniqueness (own, and another id's).
    assert_eq!(
        id("/v1/proxies/px1/fingerprints", Some(fp_body("XYZ")))
            .await
            .status,
        422
    );
    assert_eq!(
        id("/v1/proxies/px1/fingerprints", Some(fp_body(&a_fp)))
            .await
            .code(),
        "already_exists"
    );
    assert_eq!(id("/v1/proxies", Some(reg_body("px2"))).await.status, 201);
    let r = id("/v1/proxies/px2/fingerprints", Some(fp_body(&a_fp))).await;
    assert_eq!((r.status, r.code().as_str()), (409, "already_exists"));
    assert_eq!(
        fx.ctx.registry.get("px2").unwrap().state,
        ProxyState::Pending
    );

    // Second fingerprint is fp_next; both are accepted; using next promotes it.
    assert_eq!(
        id("/v1/proxies/px1/fingerprints", Some(fp_body(&b_fp)))
            .await
            .status,
        200
    );
    let rec = fx.ctx.registry.get("px1").unwrap();
    assert_eq!(rec.fp_next.as_deref(), Some(b_fp.as_str()));
    assert_config_unavailable(&send(&pa, port, "GET", "/v1/proxy-config", None, None).await);
    assert_eq!(
        fx.ctx.registry.get("px1").unwrap().fp_next.as_deref(),
        Some(b_fp.as_str())
    );
    assert_config_unavailable(&send(&pb, port, "GET", "/v1/proxy-config", None, None).await);
    let rec = fx.ctx.registry.get("px1").unwrap();
    assert_eq!(
        (rec.fp_current.as_deref(), rec.fp_next),
        (Some(b_fp.as_str()), None)
    );
    // The old fingerprint is dropped at the first request with next.
    let r = send(&pa, port, "GET", "/v1/proxy-config", None, None).await;
    assert_eq!(r.body, err_body(ErrorCode::ProxyUnknown));
    // The promotion is in the audit trail.
    assert!(audit_lines(&fx)
        .iter()
        .any(|l| l["action"] == "proxy.fingerprint_promote"
            && l["proxy_id"] == "px1"
            && l["subject_fingerprint"] == b_fp.as_str()));
    // Persisted: a reload from disk sees the promotion.
    let reopened =
        sigil_server::proxy::registry::ProxyRegistry::open(&fx.p("proxies.json"), false).unwrap();
    assert_eq!(
        reopened.get("px1").unwrap().fp_current.as_deref(),
        Some(b_fp.as_str())
    );

    // Disable (config scope) -> proxy gets the fixed 403 disabled; twice is 409.
    assert_eq!(cfg("/v1/proxies/px1/disable").await.status, 200);
    let r = send(&pb, port, "GET", "/v1/proxy-config", None, None).await;
    assert_eq!((r.status, r.body), (403, err_body(ErrorCode::Disabled)));
    assert_eq!(cfg("/v1/proxies/px1/disable").await.code(), "invalid_state");
    // Re-enable needs identity scope: config token is 403 and changes nothing.
    assert_eq!(cfg("/v1/proxies/px1/enable").await.status, 403);
    assert_eq!(
        fx.ctx.registry.get("px1").unwrap().state,
        ProxyState::Disabled
    );
    assert_eq!(id("/v1/proxies/px1/enable", None).await.status, 200);
    assert_config_unavailable(&send(&pb, port, "GET", "/v1/proxy-config", None, None).await);
    assert_eq!(
        id("/v1/proxies/px1/enable", None).await.code(),
        "invalid_state"
    );

    // A disabled entry's fingerprint can be replaced before enable.
    assert_eq!(cfg("/v1/proxies/px1/disable").await.status, 200);
    assert_eq!(
        id("/v1/proxies/px1/fingerprints", Some(fp_body(&a_fp)))
            .await
            .status,
        200
    );
    let rec = fx.ctx.registry.get("px1").unwrap();
    assert_eq!(
        (rec.state, rec.fp_current.as_deref(), rec.fp_next),
        (ProxyState::Disabled, Some(a_fp.as_str()), None)
    );
    assert_eq!(id("/v1/proxies/px1/enable", None).await.status, 200);
    assert_eq!(
        send(&pb, port, "GET", "/v1/proxy-config", None, None)
            .await
            .body,
        err_body(ErrorCode::ProxyUnknown)
    );

    // Retire is terminal: proxy gets 403 retired; enable/disable/fingerprint/
    // retire/register all 409; the id is never reused.
    assert_eq!(id("/v1/proxies/px1/retire", None).await.status, 200);
    let r = send(&pa, port, "GET", "/v1/proxy-config", None, None).await;
    assert_eq!((r.status, r.body), (403, err_body(ErrorCode::Retired)));
    for (path, body) in [
        ("/v1/proxies/px1/enable", None),
        ("/v1/proxies/px1/retire", None),
        ("/v1/proxies/px1/fingerprints", Some(fp_body(&b_fp))),
    ] {
        let r = id(path, body).await;
        assert_eq!(
            (r.status, r.code().as_str()),
            (409, "invalid_state"),
            "{path}"
        );
    }
    assert_eq!(cfg("/v1/proxies/px1/disable").await.code(), "invalid_state");
    assert_eq!(
        id("/v1/proxies", Some(reg_body("px1"))).await.code(),
        "already_exists"
    );
    assert_eq!(
        fx.ctx.registry.get("px1").unwrap().state,
        ProxyState::Retired
    );

    // A pending entry can be retired.
    assert_eq!(id("/v1/proxies/px2/retire", None).await.status, 200);

    // Unknown ids: 404 proxy_unknown for an authenticated, scoped caller.
    for path in ["/v1/proxies/ghost/enable", "/v1/proxies/Bad_Id/retire"] {
        let r = id(path, None).await;
        assert_eq!(
            (r.status, r.body),
            (404, err_body(ErrorCode::ProxyUnknown)),
            "{path}"
        );
    }
    assert_eq!(cfg("/v1/proxies/ghost/disable").await.status, 404);
}

#[tokio::test]
async fn audit_is_written_before_the_effect_and_failure_is_503() {
    let fx = Fx::new().await;
    let mc = fx.mgmt_client();
    let port = fx.port;
    let r = send(
        &mc,
        port,
        "POST",
        "/v1/proxies",
        Some(T_ID),
        Some(&reg_body("pxa")),
    )
    .await;
    assert_eq!(r.status, 201);
    assert_eq!(
        send(
            &mc,
            port,
            "POST",
            "/v1/proxies/pxa/fingerprints",
            Some(T_ID),
            Some(&fp_body(FP_A))
        )
        .await
        .status,
        200
    );
    // Ordering: the audit file already holds the record of the effect.
    let lines = audit_lines(&fx);
    assert!(lines
        .iter()
        .any(|l| l["action"] == "proxy.register" && l["result"] == "ok"));

    // Break the audit stream: a directory where the file is.
    let af = fx.p(AUDIT_FILE);
    let bak = fx.p("audit.bak");
    std::fs::rename(&af, &bak).unwrap();
    std::fs::create_dir(&af).unwrap();

    let r = send(
        &mc,
        port,
        "POST",
        "/v1/proxies",
        Some(T_ID),
        Some(&reg_body("pxb")),
    )
    .await;
    assert_eq!((r.status, r.code().as_str()), (503, "audit_unavailable"));
    assert!(
        fx.ctx.registry.get("pxb").is_none(),
        "no effect without audit"
    );
    let r = send(
        &mc,
        port,
        "POST",
        "/v1/proxies/pxa/disable",
        Some(T_CFG),
        None,
    )
    .await;
    assert_eq!(r.status, 503);
    assert_eq!(
        fx.ctx.registry.get("pxa").unwrap().state,
        ProxyState::Active
    );
    // A refusal that cannot be audited is also 503 (audit precedes every answer).
    let r = send(
        &mc,
        port,
        "POST",
        "/v1/proxies/pxa/enable",
        Some(T_ID),
        None,
    )
    .await;
    assert_eq!(r.status, 503);
    let r = send(
        &mc,
        port,
        "POST",
        "/v1/proxies",
        Some("wrong"),
        Some(&reg_body("pxb")),
    )
    .await;
    assert_eq!(r.status, 503);
    // The persisted file did not change either.
    let reopened =
        sigil_server::proxy::registry::ProxyRegistry::open(&fx.p("proxies.json"), false).unwrap();
    assert!(reopened.get("pxb").is_none());
    assert_eq!(reopened.get("pxa").unwrap().state, ProxyState::Active);

    // Repair: the chain resumes from the restored file and the action works.
    std::fs::remove_dir(&af).unwrap();
    std::fs::rename(&bak, &af).unwrap();
    let r = send(
        &mc,
        port,
        "POST",
        "/v1/proxies/pxa/disable",
        Some(T_CFG),
        None,
    )
    .await;
    assert_eq!(r.status, 200);
    let lines = audit_lines(&fx);
    for w in lines.windows(2) {
        assert_eq!(w[1]["prev_hash"], w[0]["hash"], "hash chain intact");
        assert_eq!(
            w[1]["seq"].as_u64().unwrap(),
            w[0]["seq"].as_u64().unwrap() + 1
        );
    }
}

#[tokio::test]
async fn audit_records_carry_no_secrets_and_label_requested_by_as_asserted() {
    let fx = Fx::new().await;
    let port = fx.port;
    let mc = fx.mgmt_client();
    let post = |path: &'static str, bearer: &'static str, body: Option<String>| {
        let c = fx.mgmt_client();
        async move {
            let mut rb = c
                .post(format!("https://127.0.0.1:{port}{path}"))
                .bearer_auth(bearer)
                .header("x-sigil-requested-by", "alice@example");
            if let Some(b) = body {
                rb = rb.body(b);
            }
            rb.send().await.unwrap().status().as_u16()
        }
    };
    assert_eq!(post("/v1/proxies", T_ID, Some(reg_body("pxa"))).await, 201);
    assert_eq!(post("/v1/proxies/pxa/disable", T_ID, None).await, 403);
    assert_eq!(
        post("/v1/proxies/pxa/disable", "CANARY-WRONG-bearer", None).await,
        401
    );
    assert_eq!(post("/v1/proxies", T_ID, Some(reg_body("pxa"))).await, 409);

    let raw = std::fs::read_to_string(fx.p(AUDIT_FILE)).unwrap();
    for secret in [
        T_ID.to_string(),
        T_CFG.to_string(),
        "CANARY-WRONG-bearer".to_string(),
        verifier_for(T_ID),
        verifier_for(T_CFG),
        verifier_for("CANARY-WRONG-bearer"),
        "Bearer".to_string(),
    ] {
        assert!(!raw.contains(&secret), "audit file leaks {secret}");
    }
    let lines = audit_lines(&fx);
    let reg = &lines[0];
    assert_eq!(reg["action"], "proxy.register");
    assert_eq!(reg["management_key_id"], "idk");
    assert_eq!(reg["scope"], "identity");
    assert_eq!(reg["requested_by"], "alice@example");
    assert_eq!(reg["requested_by_assurance"], "asserted_by_caller");
    assert_eq!(reg["to_state"], "pending");
    assert!(reg["request_id"].as_str().unwrap().len() >= 32);
    assert!(lines
        .iter()
        .any(|l| l["result"] == "already_exists" && l["http_status"] == 409));
    assert!(lines
        .iter()
        .any(|l| l["result"] == "unauthorized" && l["management_key_id"] == ""));

    // Audit read API: read bearer only, paging, no secrets.
    let r = send(&mc, port, "GET", "/v1/proxy-management-audit", None, None).await;
    assert_eq!(r.status, 401);
    let r = send(
        &mc,
        port,
        "GET",
        "/v1/proxy-management-audit",
        Some(T_ID),
        None,
    )
    .await;
    assert_eq!(r.status, 401, "a management token is not the read bearer");
    let r = send(
        &mc,
        port,
        "GET",
        "/v1/proxy-management-audit?limit=2",
        Some(READ_TOKEN),
        None,
    )
    .await;
    assert_eq!(r.status, 200);
    let j = r.json();
    assert_eq!(j["records"].as_array().unwrap().len(), 2);
    assert_eq!(j["next_cursor"], "2");
    let r2 = send(
        &mc,
        port,
        "GET",
        "/v1/proxy-management-audit?cursor=2&limit=100",
        Some(READ_TOKEN),
        None,
    )
    .await;
    let j2 = r2.json();
    assert_eq!(j2["records"].as_array().unwrap().len(), lines.len() - 2);
    assert!(j2["next_cursor"].is_null());
    for body in [&r.body, &r2.body] {
        let s = String::from_utf8_lossy(body);
        assert!(!s.contains("CANARY") && !s.contains(&verifier_for(T_ID)));
    }
    let r = send(
        &mc,
        port,
        "GET",
        "/v1/proxy-management-audit?cursor=abc",
        Some(READ_TOKEN),
        None,
    )
    .await;
    assert_eq!((r.status, r.code().as_str()), (422, "invalid_cursor"));
}

#[tokio::test]
async fn management_cert_is_a_separate_class_in_both_directions() {
    let fx = Fx::new().await;
    let d = fx.dir.path();
    let port = fx.port;
    let mc = fx.mgmt_client();
    let (pcrt, pkey) = proxy_leaf(d, "pxz", "pxz");
    let (hcrt, hkey) = host_leaf(d, "agent", HOST);
    let hc = fx.client_for(&hcrt, &hkey);
    let pc = fx.client_for(&pcrt, &pkey);
    // Make the proxy a real one so its failures are not just "unregistered".
    let r = send(
        &mc,
        port,
        "POST",
        "/v1/proxies",
        Some(T_ID),
        Some(&reg_body("pxz")),
    )
    .await;
    assert_eq!(r.status, 201);
    let fp = fingerprint(&pcrt);
    let r = send(
        &mc,
        port,
        "POST",
        "/v1/proxies/pxz/fingerprints",
        Some(T_ID),
        Some(&fp_body(&fp)),
    )
    .await;
    assert_eq!(r.status, 200);

    // Management cert on host routes: rejected before the body is parsed.
    let host_unknown = br#"{"error":"host_unknown"}"#.to_vec();
    for path in [
        format!("/v1/policy?host_id={HOST}"),
        format!("/v1/rule-packs?host_id={HOST}"),
        "/v1/fleet/hosts".into(),
    ] {
        let r = send(&mc, port, "GET", &path, Some(READ_TOKEN), None).await;
        assert_eq!((r.status, &r.body), (404, &host_unknown), "{path}");
    }
    let r = send(&mc, port, "POST", "/v1/events", None, Some("not json")).await;
    assert_eq!(r.body, host_unknown);
    // healthz stays open to any verified cert.
    assert_eq!(
        send(&mc, port, "GET", "/v1/healthz", None, None)
            .await
            .status,
        200
    );
    // Management cert on proxy routes: proxy_unknown.
    let r = send(&mc, port, "GET", "/v1/proxy-config", None, None).await;
    assert_eq!(r.body, err_body(ErrorCode::ProxyUnknown));
    // A host cert still works on host routes (baseline).
    let r = send(
        &hc,
        port,
        "GET",
        &format!("/v1/policy?host_id={HOST}"),
        None,
        None,
    )
    .await;
    assert_eq!(r.body, br#"{"error":"no_policy"}"#.to_vec());

    // Proxy cert on every management route, with a VALID bearer: same 404 as
    // an unknown route, no state change.
    let before = fx.ctx.registry.get("pxz").unwrap();
    let r = send(
        &pc,
        port,
        "POST",
        "/v1/proxies/pxz/disable",
        Some(T_CFG),
        None,
    )
    .await;
    assert_eq!(r.status, 404);
    assert!(r.body.is_empty());
    assert_eq!(fx.ctx.registry.get("pxz").unwrap(), before);
    // Proxy cert and host cert on the audit route: rejected / readable by class.
    let r = send(
        &pc,
        port,
        "GET",
        "/v1/proxy-management-audit",
        Some(READ_TOKEN),
        None,
    )
    .await;
    assert_eq!(r.body, host_unknown);
    let r = send(
        &hc,
        port,
        "GET",
        "/v1/proxy-management-audit",
        Some(READ_TOKEN),
        None,
    )
    .await;
    assert_eq!(
        r.status, 200,
        "manager (host-class cert + read bearer) can read the audit"
    );
    let r = send(
        &mc,
        port,
        "GET",
        "/v1/proxy-management-audit",
        Some(READ_TOKEN),
        None,
    )
    .await;
    assert_eq!(
        r.status, 200,
        "operator CLI (management cert + read bearer) can read the audit"
    );
}

#[tokio::test]
async fn reload_failure_denies_all_management_until_fixed() {
    let fx = Fx::new().await;
    let port = fx.port;
    let mc = fx.mgmt_client();
    let vf = fx.p("verifiers.json");
    let good = std::fs::read(&vf).unwrap();
    assert_eq!(
        send(
            &mc,
            port,
            "POST",
            "/v1/proxies",
            Some(T_ID),
            Some(&reg_body("pxa"))
        )
        .await
        .status,
        201
    );

    // Break it: every management request is a 404 (even with a valid token).
    std::fs::write(&vf, b"garbage").unwrap();
    let r = send(
        &mc,
        port,
        "POST",
        "/v1/proxies",
        Some(T_ID),
        Some(&reg_body("pxb")),
    )
    .await;
    assert_eq!((r.status, r.body.len()), (404, 0));
    assert!(fx.ctx.registry.get("pxb").is_none());
    // The management cert stays off the host routes even while the file is bad.
    let r = send(
        &mc,
        port,
        "GET",
        &format!("/v1/policy?host_id={HOST}"),
        None,
        None,
    )
    .await;
    assert_eq!(r.status, 404);
    assert_eq!(r.body, br#"{"error":"host_unknown"}"#.to_vec());
    // Loosened permissions also deny.
    std::fs::write(&vf, &good).unwrap();
    std::fs::set_permissions(&vf, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(
        send(
            &mc,
            port,
            "POST",
            "/v1/proxies",
            Some(T_ID),
            Some(&reg_body("pxb"))
        )
        .await
        .status,
        404
    );
    // Fixed: back in service (no restart).
    std::fs::set_permissions(&vf, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(
        send(
            &mc,
            port,
            "POST",
            "/v1/proxies",
            Some(T_ID),
            Some(&reg_body("pxb"))
        )
        .await
        .status,
        201
    );

    // Rotation without restart: swap the token set, old token dies, new works
    // (explicit reload, as SIGHUP would do).
    let mut e = Fx::default_entries(&fx.mgmt_fp, &fx.mgmt_fp);
    e[0] = entry("idk2", "rotated-token", Scope::Identity, &fx.mgmt_fp, None);
    e.truncate(2);
    write_verifiers(&vf, &e);
    fx.ctx.mgmt.as_ref().unwrap().reload();
    assert_eq!(
        send(
            &mc,
            port,
            "POST",
            "/v1/proxies",
            Some(T_ID),
            Some(&reg_body("pxc"))
        )
        .await
        .status,
        401
    );
    assert_eq!(
        send(
            &mc,
            port,
            "POST",
            "/v1/proxies",
            Some("rotated-token"),
            Some(&reg_body("pxc"))
        )
        .await
        .status,
        201
    );
}

#[test]
fn boot_refuses_bad_verifier_files() {
    let (dir, _mgmt, _fp) = Fx::prepare(Fx::default_entries);
    let d = dir.path();
    let cfg = Fx::config(d);
    assert!(ProxyContext::load(&cfg).is_ok());
    let vf = d.join("verifiers.json");
    // Group/world readable.
    std::fs::set_permissions(&vf, std::fs::Permissions::from_mode(0o640)).unwrap();
    let e = ProxyContext::load(&cfg).err().expect("must refuse");
    assert!(format!("{e:#}").contains("owner-only"), "{e:#}");
    std::fs::set_permissions(&vf, std::fs::Permissions::from_mode(0o600)).unwrap();
    // Symlink.
    let link = d.join("link.json");
    std::os::unix::fs::symlink(&vf, &link).unwrap();
    let mut cfg2 = cfg.clone();
    cfg2.proxy.as_mut().unwrap().management_verifiers = Some(link);
    let e = ProxyContext::load(&cfg2).err().expect("must refuse");
    assert!(format!("{e:#}").contains("symlink"), "{e:#}");
    // Missing, and not a regular file.
    cfg2.proxy.as_mut().unwrap().management_verifiers = Some(d.join("missing.json"));
    assert!(ProxyContext::load(&cfg2).is_err());
    cfg2.proxy.as_mut().unwrap().management_verifiers = Some(d.to_path_buf());
    assert!(ProxyContext::load(&cfg2).is_err());
    // Three active entries in one scope.
    let fp = fingerprint(&d.join("mgmt.crt"));
    let three: Vec<_> = (0..3)
        .map(|i| entry(&format!("k{i}"), &format!("t{i}"), Scope::Config, &fp, None))
        .collect();
    write_verifiers(&vf, &three);
    let e = ProxyContext::load(&cfg).err().expect("must refuse");
    assert!(format!("{e:#}").contains("active"), "{e:#}");
    // A management caller fingerprint that is also a registered proxy cert.
    write_verifiers(&vf, &[entry("k", "t", Scope::Config, &fp, None)]);
    let ctx = ProxyContext::load(&cfg).unwrap().unwrap();
    drop(ctx);
    let reg =
        sigil_server::proxy::registry::ProxyRegistry::open(&d.join("proxies.json"), false).unwrap();
    reg.seed_for_test(sigil_server::proxy::registry::ProxyRecord {
        proxy_id: "pxq".into(),
        display_name: "q".into(),
        state: ProxyState::Active,
        fp_current: Some(fp),
        fp_next: None,
        created_at: "2026-10-11T00:00:00Z".into(),
        updated_at: "2026-10-11T00:00:00Z".into(),
    })
    .unwrap();
    let e = ProxyContext::load(&cfg).err().expect("must refuse");
    assert!(
        format!("{e:#}").contains("also a registered proxy"),
        "{e:#}"
    );
}

#[test]
fn proxy_section_without_verifiers_has_no_management_surface() {
    let (dir, _m, _fp) = Fx::prepare(Fx::default_entries);
    let mut cfg = Fx::config(dir.path());
    cfg.proxy.as_mut().unwrap().management_verifiers = None;
    let ctx = ProxyContext::load(&cfg).unwrap().unwrap();
    assert!(ctx.mgmt.is_none() && ctx.audit.is_none());
}

#[tokio::test]
async fn operator_cli_end_to_end() {
    // Token + verifier entry produced by `verifier-new` itself.
    let (dir, mgmt, mgmt_fp) = Fx::prepare(|_, _| Vec::new());
    let (t_id, e_id) =
        cli::new_verifier(Scope::Identity, &mgmt_fp, Some("cli-id"), None, None).unwrap();
    let (t_cfg, e_cfg) =
        cli::new_verifier(Scope::Config, &mgmt_fp, Some("cli-cfg"), None, None).unwrap();
    write_verifiers(&dir.path().join("verifiers.json"), &[e_id, e_cfg]);
    let fx = Fx::start(dir, mgmt, mgmt_fp).await;
    let d = fx.dir.path();
    let (pcrt, _pkey) = proxy_leaf(d, "pxcli", "pxcli");
    // openssl leaves the key group/world readable here: the CLI refuses it.
    std::fs::set_permissions(&fx.mgmt.1, std::fs::Permissions::from_mode(0o644)).unwrap();

    let write_secret = |name: &str, content: &str, mode: u32| {
        let p = fx.p(name);
        std::fs::write(&p, content).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
        p
    };
    let conn = |token_file: PathBuf| ConnArgs {
        server_url: format!("https://127.0.0.1:{}", fx.port),
        cert: fx.mgmt.0.clone(),
        key: fx.mgmt.1.clone(),
        ca: fx.p("hostca.crt"),
        token_file,
        requested_by: Some("cli-operator".into()),
    };
    let id_tok = write_secret("id.tok", &format!("{t_id}\n"), 0o600);
    let cfg_tok = write_secret("cfg.tok", &t_cfg, 0o600);
    let read_tok = write_secret("read.tok", READ_TOKEN, 0o600);

    let refused = cli::run(ProxyCommand::Disable {
        conn: conn(id_tok.clone()),
        proxy_id: "pxcli".into(),
    })
    .await;
    assert!(refused.is_err(), "group/world-readable --key is refused");
    std::fs::set_permissions(&fx.mgmt.1, std::fs::Permissions::from_mode(0o600)).unwrap();

    cli::run(ProxyCommand::Register {
        conn: conn(id_tok.clone()),
        proxy_id: "pxcli".into(),
        display_name: "CLI proxy".into(),
    })
    .await
    .unwrap();
    assert_eq!(
        fx.ctx.registry.get("pxcli").unwrap().state,
        ProxyState::Pending
    );
    cli::run(ProxyCommand::Fingerprint {
        conn: conn(id_tok.clone()),
        proxy_id: "pxcli".into(),
        fingerprint: None,
        cert_file: Some(pcrt.clone()),
    })
    .await
    .unwrap();
    let rec = fx.ctx.registry.get("pxcli").unwrap();
    assert_eq!(
        (rec.state, rec.fp_current),
        (ProxyState::Active, Some(fingerprint(&pcrt)))
    );
    cli::run(ProxyCommand::Disable {
        conn: conn(cfg_tok.clone()),
        proxy_id: "pxcli".into(),
    })
    .await
    .unwrap();
    assert_eq!(
        fx.ctx.registry.get("pxcli").unwrap().state,
        ProxyState::Disabled
    );
    // Wrong scope and illegal transitions surface as errors (non-zero exit).
    assert!(cli::run(ProxyCommand::Enable {
        conn: conn(cfg_tok.clone()),
        proxy_id: "pxcli".into()
    })
    .await
    .is_err());
    cli::run(ProxyCommand::Enable {
        conn: conn(id_tok.clone()),
        proxy_id: "pxcli".into(),
    })
    .await
    .unwrap();
    cli::run(ProxyCommand::Retire {
        conn: conn(id_tok.clone()),
        proxy_id: "pxcli".into(),
    })
    .await
    .unwrap();
    assert!(cli::run(ProxyCommand::Enable {
        conn: conn(id_tok.clone()),
        proxy_id: "pxcli".into()
    })
    .await
    .is_err());
    // The asserted operator name reached the audit trail.
    assert!(audit_lines(&fx)
        .iter()
        .any(|l| l["requested_by"] == "cli-operator"));
    // Audit read via the CLI (read bearer in the token file).
    cli::run(ProxyCommand::Audit {
        conn: conn(read_tok.clone()),
        cursor: None,
        limit: Some(5),
    })
    .await
    .unwrap();
    assert!(cli::run(ProxyCommand::Audit {
        conn: conn(id_tok.clone()),
        cursor: None,
        limit: None
    })
    .await
    .is_err());

    // Token-file hygiene: loose permissions, symlink, http:// URL are refused
    // before any request is made.
    let loose = write_secret("loose.tok", &t_id, 0o644);
    let cmd = |tf: PathBuf, url: Option<&str>| {
        let mut c = conn(tf);
        if let Some(u) = url {
            c.server_url = u.into();
        }
        ProxyCommand::Disable {
            conn: c,
            proxy_id: "pxcli".into(),
        }
    };
    assert!(cli::run(cmd(loose, None)).await.is_err());
    let link = fx.p("link.tok");
    std::os::unix::fs::symlink(&id_tok, &link).unwrap();
    assert!(cli::run(cmd(link, None)).await.is_err());
    assert!(cli::run(cmd(id_tok, Some("http://127.0.0.1:1")))
        .await
        .is_err());
}

// ---- review-fix tests --------------------------------------------------------

/// Register `id` and give it two proxy certs (current, next) through the API.
async fn proxy_with_two_certs(fx: &Fx, id: &str) -> ((PathBuf, PathBuf), (PathBuf, PathBuf)) {
    let d = fx.dir.path();
    let a = proxy_leaf(d, &format!("{id}a"), id);
    let b = proxy_leaf(d, &format!("{id}b"), id);
    let mc = fx.mgmt_client();
    let p = |path: String, body: Option<String>| {
        let mc = mc.clone();
        let port = fx.port;
        async move { send(&mc, port, "POST", &path, Some(T_ID), body.as_deref()).await }
    };
    assert_eq!(
        p("/v1/proxies".into(), Some(reg_body(id))).await.status,
        201
    );
    for crt in [&a.0, &b.0] {
        let r = p(
            format!("/v1/proxies/{id}/fingerprints"),
            Some(fp_body(&fingerprint(crt))),
        )
        .await;
        assert_eq!(r.status, 200);
    }
    (a, b)
}

#[tokio::test]
async fn management_cert_fingerprint_cannot_be_registered_as_a_proxy() {
    let fx = Fx::new().await;
    let mc = fx.mgmt_client();
    assert_eq!(
        send(
            &mc,
            fx.port,
            "POST",
            "/v1/proxies",
            Some(T_ID),
            Some(&reg_body("pxa"))
        )
        .await
        .status,
        201
    );
    let r = send(
        &mc,
        fx.port,
        "POST",
        "/v1/proxies/pxa/fingerprints",
        Some(T_ID),
        Some(&fp_body(&fx.mgmt_fp)),
    )
    .await;
    assert_eq!((r.status, r.code().as_str()), (409, "already_exists"));
    assert_eq!(
        fx.ctx.registry.get("pxa").unwrap().state,
        ProxyState::Pending
    );
}

#[tokio::test]
async fn auth_denials_are_coalesced_and_records_are_domain_separated() {
    let fx = Fx::new().await;
    let mc = fx.mgmt_client();
    for _ in 0..5 {
        let r = send(
            &mc,
            fx.port,
            "POST",
            "/v1/proxies",
            Some("wrong"),
            Some(&reg_body("pxa")),
        )
        .await;
        assert_eq!(r.status, 401);
    }
    let lines = audit_lines(&fx);
    let denials: Vec<_> = lines
        .iter()
        .filter(|l| l["reason"] == "bad_bearer")
        .collect();
    assert_eq!(
        denials.len(),
        1,
        "one record per caller and reason per window"
    );
    assert!(lines.iter().all(|l| l["stream"] == "proxy-mgmt"));
    // A different reason from the same caller is its own record.
    let r = send(
        &mc,
        fx.port,
        "POST",
        "/v1/proxies",
        None,
        Some(&reg_body("pxa")),
    )
    .await;
    assert_eq!(r.status, 401);
    assert_eq!(audit_lines(&fx).len(), 2);
}

#[tokio::test]
async fn disabled_fingerprint_replace_records_the_replaced_one() {
    let fx = Fx::new().await;
    let (a, b) = proxy_with_two_certs(&fx, "px1").await;
    let mc = fx.mgmt_client();
    let port = fx.port;
    assert_eq!(
        send(
            &mc,
            port,
            "POST",
            "/v1/proxies/px1/disable",
            Some(T_CFG),
            None
        )
        .await
        .status,
        200
    );
    let fresh = "e5".repeat(32);
    assert_eq!(
        send(
            &mc,
            port,
            "POST",
            "/v1/proxies/px1/fingerprints",
            Some(T_ID),
            Some(&fp_body(&fresh))
        )
        .await
        .status,
        200
    );
    let lines = audit_lines(&fx);
    let last = lines
        .iter()
        .rfind(|l| l["action"] == "proxy.fingerprint_register")
        .unwrap();
    assert_eq!(
        last["replaced_fingerprint"],
        format!("{},{}", fingerprint(&a.0), fingerprint(&b.0))
    );
    assert_eq!(last["subject_fingerprint"], fresh.as_str());
}

#[tokio::test]
async fn promotion_with_audit_down_is_served_but_not_promoted_and_no_false_record() {
    let fx = Fx::new().await;
    let (a, b) = proxy_with_two_certs(&fx, "px1").await;
    let (a_fp, b_fp) = (fingerprint(&a.0), fingerprint(&b.0));
    let pb = fx.client_for(&b.0, &b.1);
    let before = audit_lines(&fx).len();

    let af = fx.p(AUDIT_FILE);
    let bak = fx.p("audit.bak");
    std::fs::rename(&af, &bak).unwrap();
    std::fs::create_dir(&af).unwrap();

    // Served with the next fingerprint, but the old one stays current.
    assert_config_unavailable(&send(&pb, fx.port, "GET", "/v1/proxy-config", None, None).await);
    let rec = fx.ctx.registry.get("px1").unwrap();
    assert_eq!(
        (rec.fp_current.as_deref(), rec.fp_next.as_deref()),
        (Some(a_fp.as_str()), Some(b_fp.as_str()))
    );

    std::fs::remove_dir(&af).unwrap();
    std::fs::rename(&bak, &af).unwrap();
    // No record was written for the failed attempt; the retry is rate limited,
    // so an immediate second request does not promote either.
    assert_eq!(audit_lines(&fx).len(), before);
    assert_config_unavailable(&send(&pb, fx.port, "GET", "/v1/proxy-config", None, None).await);
    let rec = fx.ctx.registry.get("px1").unwrap();
    assert_eq!(rec.fp_current.as_deref(), Some(a_fp.as_str()));
    assert_eq!(audit_lines(&fx).len(), before);
}

#[tokio::test]
async fn concurrent_management_writes_and_promotions_lose_no_update() {
    let fx = Fx::new().await;
    let mut set = Vec::new();
    for i in 0..3 {
        let d = format!("pd{i}");
        let certs = proxy_with_two_certs(&fx, &d).await;
        set.push((d, true, certs));
        let f = format!("pf{i}");
        let certs = proxy_with_two_certs(&fx, &f).await;
        set.push((f, false, certs));
    }
    let c_of = |id: &str| format!("c{}", &id[2..]).repeat(32);
    let mut tasks = Vec::new();
    for (id, is_disable, (_a, b)) in &set {
        let pb = fx.client_for(&b.0, &b.1);
        let mc = fx.mgmt_client();
        let c_fp = c_of(id);
        let (port, id, is_disable) = (fx.port, id.clone(), *is_disable);
        tasks.push(tokio::spawn(async move {
            let proxy = send(&pb, port, "GET", "/v1/proxy-config", None, None);
            let mgmt = async {
                if is_disable {
                    send(
                        &mc,
                        port,
                        "POST",
                        &format!("/v1/proxies/{id}/disable"),
                        Some(T_CFG),
                        None,
                    )
                    .await
                } else {
                    send(
                        &mc,
                        port,
                        "POST",
                        &format!("/v1/proxies/{id}/fingerprints"),
                        Some(T_ID),
                        Some(&fp_body(&c_fp)),
                    )
                    .await
                }
            };
            let (p, m) = tokio::join!(proxy, mgmt);
            (p.status, m.status)
        }));
    }
    for t in tasks {
        let (_p, m) = t.await.unwrap();
        assert_eq!(m, 200);
    }
    let reopened =
        sigil_server::proxy::registry::ProxyRegistry::open(&fx.p("proxies.json"), false).unwrap();
    for (id, is_disable, (a, b)) in &set {
        let (a_fp, b_fp) = (fingerprint(&a.0), fingerprint(&b.0));
        for reg in [&fx.ctx.registry, &reopened] {
            let rec = reg.get(id).unwrap();
            let cur = rec.fp_current.as_deref().unwrap().to_string();
            if *is_disable {
                assert_eq!(rec.state, ProxyState::Disabled, "{id}: disable not lost");
                let ok = (cur == a_fp && rec.fp_next.as_deref() == Some(b_fp.as_str()))
                    || (cur == b_fp && rec.fp_next.is_none());
                assert!(ok, "{id}: inconsistent fingerprints {rec:?}");
            } else {
                assert_eq!(rec.state, ProxyState::Active);
                assert_eq!(
                    rec.fp_next.as_deref(),
                    Some(c_of(id).as_str()),
                    "{id}: new next lost"
                );
                assert!(cur == a_fp || cur == b_fp, "{id}: {rec:?}");
            }
        }
    }
    let lines = audit_lines(&fx);
    for w in lines.windows(2) {
        assert_eq!(
            w[1]["prev_hash"], w[0]["hash"],
            "audit chain intact under concurrency"
        );
    }
}

#[tokio::test]
async fn sighup_reloads_the_verifier_file() {
    let fx = Fx::new().await;
    sigil_server::proxy::spawn_sighup_reload(fx.ctx.clone()).unwrap();
    let newcaller = "d9".repeat(32);
    assert!(!fx.ctx.mgmt.as_ref().unwrap().is_caller(&newcaller));
    let mut e = Fx::default_entries(&fx.mgmt_fp, &fx.mgmt_fp);
    e.truncate(2);
    e.push(entry(
        "sighup",
        "tok-sighup",
        Scope::Config,
        &newcaller,
        None,
    ));
    write_verifiers(&fx.p("verifiers.json"), &e);
    // SAFETY: plain kill(2) to our own pid; the handler above is installed.
    unsafe { libc::kill(libc::getpid(), libc::SIGHUP) };
    let mut seen = false;
    for _ in 0..60 {
        if fx.ctx.mgmt.as_ref().unwrap().is_caller(&newcaller) {
            seen = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(
        seen,
        "SIGHUP did not reload (no request triggered a lazy refresh)"
    );
}
