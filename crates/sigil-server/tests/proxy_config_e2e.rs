//! T-11 S3 — live-TLS e2e for the proxy config DTO, config PUT/GET and status
//! ingest (PX-008/016, AC-12/13; control-plane §6, ledger L6b).
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
use sigil_server::proxy::identity::proxy_san;
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

// ---- PKI helpers (same approach as proxy_identity_e2e.rs) -------------------

/// Unique certificate serial per leaf (hex with 0x prefix). Avoids the shared
/// `ca.srl` file that `-CAcreateserial` races on when leaves are made in parallel.
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
    #[allow(dead_code)]
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
    let mut rb = c.request(reqwest::Method::from_bytes(method.as_bytes()).unwrap(), url);
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

// ---- S3 helpers ---------------------------------------------------------------

fn err_body(code: ErrorCode) -> Vec<u8> {
    serde_json::to_vec(&ApiError::from_code(code)).unwrap()
}

fn audit_lines(fx: &Fx) -> Vec<serde_json::Value> {
    std::fs::read_to_string(fx.p(AUDIT_FILE))
        .unwrap_or_default()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

fn config_puts(fx: &Fx) -> Vec<serde_json::Value> {
    audit_lines(fx)
        .into_iter()
        .filter(|l| l["action"] == "proxy.config_put")
        .collect()
}

/// A proxy with one active certificate and its client.
struct Px {
    id: String,
    client: reqwest::Client,
}

async fn proxy(fx: &Fx, id: &str) -> Px {
    let cert = proxy_leaf(fx.dir.path(), id, id);
    let mc = fx.mgmt_client();
    let r = send(
        &mc,
        fx.port,
        "POST",
        "/v1/proxies",
        Some(T_ID),
        Some(&format!(
            r#"{{"proxy_id":"{id}","display_name":"Proxy {id}"}}"#
        )),
    )
    .await;
    assert_eq!(r.status, 201);
    let r = send(
        &mc,
        fx.port,
        "POST",
        &format!("/v1/proxies/{id}/fingerprints"),
        Some(T_ID),
        Some(&format!(r#"{{"fingerprint":"{}"}}"#, fingerprint(&cert.0))),
    )
    .await;
    assert_eq!(r.status, 200);
    let client = fx.client_for(&cert.0, &cert.1);
    Px {
        id: id.into(),
        client,
    }
}

fn spec(proxy_id: &str, token: &str) -> serde_json::Value {
    serde_json::json!({
        "proxy_id": proxy_id,
        "allowed_origins": ["https://app.example.com"],
        "routes": [{
            "route_id": "r1",
            "upstream_url": "https://api.example.com/mcp",
            "credential_ref": "gh",
            "principals": [{"principal_id": "claude", "verifier": verifier_for(token)}],
        }],
    })
}

fn put_body(expected: u64, spec: &serde_json::Value) -> String {
    serde_json::json!({"expected_revision": expected, "config": spec}).to_string()
}

async fn put(fx: &Fx, id: &str, bearer: Option<&str>, body: &str) -> Resp {
    send(
        &fx.mgmt_client(),
        fx.port,
        "PUT",
        &format!("/v1/proxies/{id}/config"),
        bearer,
        Some(body),
    )
    .await
}

async fn get_cfg(fx: &Fx, px: &Px, path: Option<&str>) -> Resp {
    let own = format!("/v1/proxies/{}/config", px.id);
    send(&px.client, fx.port, "GET", path.unwrap_or(&own), None, None).await
}

fn status_body(proxy_id: &str, epoch: &str, seq: u32, gaps: Vec<serde_json::Value>) -> String {
    serde_json::json!({
        "schema_version": 1, "report_id": uid(5000 + seq), "proxy_id": proxy_id,
        "epoch_id": epoch, "status_sequence": seq, "sent_at": "2026-10-11T00:00:00Z",
        "config": {"state": "none", "applied_revision": null,
            "observed_desired_revision": null, "expires_at": null},
        "spool": {"state": "ok", "depth_events": 0, "unsent_events": 0, "bytes": 0,
            "capacity_bytes": 1000, "oldest_unsent_age_seconds": null,
            "quarantined_events": 0},
        "registry": {"pending_entries": 0, "sync_stalled": false},
        "central": {"last_ingest_ack_at": null, "consecutive_failures": 0},
        "routes": [], "counters": {"auth_failures": [], "unmatched_cancels": []},
        "gaps": gaps, "last_assigned_sequence": 0,
    })
    .to_string()
}

const EPOCH: &str = "00000000-0000-4000-8000-0000000000e1";

fn uid(n: u32) -> String {
    format!("00000000-0000-4000-8000-{n:012x}")
}

fn outage(n: u32, ended: serde_json::Value) -> serde_json::Value {
    serde_json::json!({"kind": "central_outage", "gap_id": uid(n),
        "detected_at": "2026-10-11T00:00:00Z", "started_at": "2026-10-11T00:00:00Z",
        "ended_at": ended})
}

fn quarantine(n: u32, code: &str) -> serde_json::Value {
    serde_json::json!({"kind": "event_quarantined", "gap_id": uid(n),
        "detected_at": "2026-10-11T00:00:00Z", "event_ids": [uid(900)], "code": code})
}

async fn post_status(fx: &Fx, px: &Px, body: &str) -> Resp {
    send(
        &px.client,
        fx.port,
        "POST",
        "/v1/proxy-status",
        None,
        Some(body),
    )
    .await
}

// ---- tests ---------------------------------------------------------------------

#[tokio::test]
async fn put_requires_config_scope_and_management_cert() {
    let fx = Fx::new().await;
    let a = proxy(&fx, "pxa").await;
    let body = put_body(0, &spec("pxa", "tok-a"));

    // config scope: ok, server assigns revision 1
    let r = put(&fx, "pxa", Some(T_CFG), &body).await;
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.json()["revision"], 1);
    let hash = r.json()["config_hash"].as_str().unwrap().to_string();
    assert_eq!(hash.len(), 64);

    // identity scope is not enough (exact match), no bearer, wrong bearer
    let r = put(&fx, "pxa", Some(T_ID), &body).await;
    assert_eq!((r.status, r.code().as_str()), (403, "forbidden"));
    let r = put(&fx, "pxa", None, &body).await;
    assert_eq!((r.status, r.code().as_str()), (401, "unauthorized"));
    let r = put(&fx, "pxa", Some("nope"), &body).await;
    assert_eq!(r.status, 401);

    // a proxy cert never reaches the management route: empty 404
    let r = send(
        &a.client,
        fx.port,
        "PUT",
        "/v1/proxies/pxa/config",
        Some(T_CFG),
        Some(&body),
    )
    .await;
    assert_eq!((r.status, r.body.len()), (404, 0));
    // neither does a host cert
    let host = host_leaf(fx.dir.path(), "host1", HOST);
    let hc = fx.client_for(&host.0, &host.1);
    let r = send(
        &hc,
        fx.port,
        "PUT",
        "/v1/proxies/pxa/config",
        Some(T_CFG),
        Some(&body),
    )
    .await;
    assert_eq!((r.status, r.body.len()), (404, 0));

    // unknown proxy: 404 proxy_unknown for an authenticated, scoped caller
    let r = put(&fx, "ghost", Some(T_CFG), &put_body(0, &spec("ghost", "t"))).await;
    assert_eq!(r.body, err_body(ErrorCode::ProxyUnknown));
    assert_eq!(r.status, 404);

    // The accepted PUT was audited with revisions and hash; nothing secret.
    let puts = config_puts(&fx);
    let ok = puts.iter().find(|l| l["result"] == "ok").unwrap();
    assert_eq!(ok["from_revision"], 0);
    assert_eq!(ok["to_revision"], 1);
    assert_eq!(ok["config_hash"], hash.as_str());
    assert_eq!(ok["scope"], "config");
    assert_eq!(ok["proxy_id"], "pxa");
    let raw = std::fs::read_to_string(fx.p(AUDIT_FILE)).unwrap();
    assert!(!raw.contains(&verifier_for("tok-a")), "verifier in audit");
    assert!(!raw.contains("api.example.com"), "config body in audit");
    assert!(puts.iter().any(|l| l["result"] == "forbidden"));
}

#[tokio::test]
async fn revision_conflict_and_stale_revision_are_409() {
    let fx = Fx::new().await;
    let a = proxy(&fx, "pxa").await;
    let s = spec("pxa", "tok-a");
    assert_eq!(
        put(&fx, "pxa", Some(T_CFG), &put_body(0, &s)).await.status,
        200
    );

    // first-config revision again (stale), and ahead
    for expected in [0u64, 2, 99] {
        let r = put(&fx, "pxa", Some(T_CFG), &put_body(expected, &s)).await;
        assert_eq!(
            (r.status, r.code().as_str()),
            (409, "revision_conflict"),
            "expected_revision {expected}"
        );
    }
    let r = put(&fx, "pxa", Some(T_CFG), &put_body(1, &s)).await;
    assert_eq!((r.status, r.json()["revision"].clone()), (200, 2.into()));
    // revision 1 is stale now
    let r = put(&fx, "pxa", Some(T_CFG), &put_body(1, &s)).await;
    assert_eq!(r.status, 409);
    let cur = get_cfg(&fx, &a, None).await.json();
    assert_eq!(cur["revision"], 2);

    // refusals are audited with the revision they saw
    let conflicts: Vec<_> = config_puts(&fx)
        .into_iter()
        .filter(|l| l["result"] == "revision_conflict")
        .collect();
    assert_eq!(conflicts.len(), 4);
    assert!(conflicts.iter().all(|l| l["http_status"] == 409));
    assert_eq!(conflicts[0]["from_revision"], 1);
    assert_eq!(conflicts[3]["from_revision"], 2);

    // a retired proxy takes no config
    let r = send(
        &fx.mgmt_client(),
        fx.port,
        "POST",
        "/v1/proxies/pxa/retire",
        Some(T_ID),
        None,
    )
    .await;
    assert_eq!(r.status, 200);
    let r = put(&fx, "pxa", Some(T_CFG), &put_body(2, &s)).await;
    assert_eq!((r.status, r.code().as_str()), (409, "invalid_state"));
}

#[tokio::test]
async fn invalid_configs_are_422_and_store_nothing() {
    let fx = Fx::new().await;
    let a = proxy(&fx, "pxa").await;
    let mut cases: Vec<(&str, serde_json::Value)> = Vec::new();
    let mk = |f: &dyn Fn(&mut serde_json::Value)| {
        let mut s = spec("pxa", "tok-a");
        f(&mut s);
        s
    };
    let url = |u: &'static str| {
        mk(&move |s: &mut serde_json::Value| s["routes"][0]["upstream_url"] = u.into())
    };
    cases.push(("userinfo", url("https://user:SECRETPW@api.example.com/x")));
    cases.push(("query", url("https://api.example.com/x?token=SECRETQ")));
    cases.push(("fragment", url("https://api.example.com/x#f")));
    cases.push(("http non-loopback", url("http://api.example.com/x")));
    cases.push(("ssrf metadata", url("https://169.254.169.254/latest")));
    cases.push(("ssrf private", url("https://10.0.0.5/x")));
    cases.push(("ssrf v6 ula", url("https://[fd00::1]/x")));
    cases.push(("numeric host", url("https://2130706433/x")));
    cases.push(("bad scheme", url("file:///etc/passwd")));
    cases.push((
        "proxy_id differs from path",
        mk(&|s| s["proxy_id"] = "pxb".into()),
    ));
    cases.push((
        "unknown field",
        mk(&|s| s["routes"][0]["upstream_id"] = "u".into()),
    ));
    cases.push(("server-stamped field", mk(&|s| s["revision"] = 9.into())));
    cases.push((
        "duplicate route",
        mk(&|s| {
            let r = s["routes"][0].clone();
            s["routes"] = serde_json::json!([r.clone(), r]);
        }),
    ));
    cases.push((
        "duplicate principal",
        mk(&|s| {
            let p = s["routes"][0]["principals"][0].clone();
            s["routes"][0]["principals"] = serde_json::json!([p.clone(), p]);
        }),
    ));
    cases.push((
        "verifier not hex64",
        mk(&|s| s["routes"][0]["principals"][0]["verifier"] = "abc".into()),
    ));
    cases.push((
        "E below R + M",
        mk(&|s| {
            s["max_offline_retry_age_seconds"] = 7_000_000.into();
            s["event_retention_seconds"] = 7_100_000.into();
        }),
    ));
    cases.push((
        "R out of range",
        mk(&|s| s["max_offline_retry_age_seconds"] = 10.into()),
    ));
    cases.push((
        "origin with path",
        mk(&|s| s["allowed_origins"] = serde_json::json!(["https://app.example.com/x"])),
    ));
    let n_cases = cases.len();
    for (name, s) in cases {
        let r = put(&fx, "pxa", Some(T_CFG), &put_body(0, &s)).await;
        assert_eq!(
            (r.status, r.code().as_str()),
            (422, "semantic_invalid"),
            "{name}"
        );
        let text = String::from_utf8_lossy(&r.body);
        assert!(!text.contains("SECRET"), "{name}: input echoed");
    }
    for raw in [
        "",
        "{",
        "[]",
        r#"{"expected_revision":0}"#,
        r#"{"expected_revision":"0","config":{}}"#,
    ] {
        let r = put(&fx, "pxa", Some(T_CFG), raw).await;
        assert_eq!(r.status, 422, "{raw:?}");
    }
    // oversize body: 413 from the body limit
    let big = format!("{{\"pad\":\"{}\"}}", "x".repeat(300 * 1024));
    assert_eq!(put(&fx, "pxa", Some(T_CFG), &big).await.status, 413);

    // nothing was stored; the revision counter did not move
    assert!(fx.ctx.store.config("pxa").is_none());
    let r = get_cfg(&fx, &a, None).await;
    assert_eq!((r.status, r.code().as_str()), (404, "config_unavailable"));
    let r = put(&fx, "pxa", Some(T_CFG), &put_body(0, &spec("pxa", "tok-a"))).await;
    assert_eq!(
        r.status, 200,
        "revision 0 is still current after only refusals"
    );
    // The 422s were audited too.
    assert!(
        config_puts(&fx)
            .iter()
            .filter(|l| l["http_status"] == 422)
            .count()
            >= n_cases
    );

    // Loopback http is fine.
    let ok = mk(&|s| {
        s["routes"][0]["upstream_url"] = "http://127.0.0.1:9000/mcp".into();
        s["routes"][0]["route_id"] = "r2".into();
    });
    assert_eq!(
        put(&fx, "pxa", Some(T_CFG), &put_body(1, &ok)).await.status,
        200
    );
}

#[tokio::test]
async fn audit_failure_is_503_and_nothing_is_stored() {
    let fx = Fx::new().await;
    let a = proxy(&fx, "pxa").await;
    let s = spec("pxa", "tok-a");
    assert_eq!(
        put(&fx, "pxa", Some(T_CFG), &put_body(0, &s)).await.status,
        200
    );
    let state_file = fx.p("proxy-state.json");
    let before = std::fs::read(&state_file).unwrap();

    let af = fx.p(AUDIT_FILE);
    let bak = fx.p("audit.bak");
    std::fs::rename(&af, &bak).unwrap();
    std::fs::create_dir(&af).unwrap();

    let mut s2 = s.clone();
    s2["allowed_origins"] = serde_json::json!(["https://other.example.com"]);
    let r = put(&fx, "pxa", Some(T_CFG), &put_body(1, &s2)).await;
    assert_eq!((r.status, r.code().as_str()), (503, "audit_unavailable"));
    // a refusal that cannot be audited is also 503
    let r = put(&fx, "pxa", Some(T_CFG), &put_body(0, &s2)).await;
    assert_eq!(r.status, 503);

    assert_eq!(fx.ctx.store.config("pxa").unwrap().config.revision.get(), 1);
    assert_eq!(
        std::fs::read(&state_file).unwrap(),
        before,
        "file untouched"
    );
    let cur = get_cfg(&fx, &a, None).await.json();
    assert_eq!(cur["revision"], 1);
    assert_eq!(
        cur["allowed_origins"],
        serde_json::json!(["https://app.example.com"])
    );

    // repair: the chain resumes and the same PUT now lands as revision 2
    std::fs::remove_dir(&af).unwrap();
    std::fs::rename(&bak, &af).unwrap();
    let r = put(&fx, "pxa", Some(T_CFG), &put_body(1, &s2)).await;
    assert_eq!((r.status, r.json()["revision"].clone()), (200, 2.into()));
    // the audit record for revision 2 exists (it was written before the store)
    assert!(config_puts(&fx)
        .iter()
        .any(|l| l["result"] == "ok" && l["to_revision"] == 2));
}

#[tokio::test]
async fn persist_failure_after_audit_is_recorded_and_changes_nothing() {
    let fx = Fx::new().await;
    let a = proxy(&fx, "pxa").await;
    let s = spec("pxa", "tok-a");
    assert_eq!(
        put(&fx, "pxa", Some(T_CFG), &put_body(0, &s)).await.status,
        200
    );
    // the state file cannot be replaced
    let sf = fx.p("proxy-state.json");
    std::fs::remove_file(&sf).unwrap();
    std::fs::create_dir(&sf).unwrap();
    std::fs::write(sf.join("x"), b"x").unwrap();
    let r = put(&fx, "pxa", Some(T_CFG), &put_body(1, &s)).await;
    assert_eq!(r.status, 500);
    assert_eq!(get_cfg(&fx, &a, None).await.json()["revision"], 1);
    let puts = config_puts(&fx);
    let n = puts.len();
    assert_eq!(puts[n - 1]["result"], "persist_failed");
    assert_eq!(
        puts[n - 2]["result"],
        "ok",
        "the audit preceded the failed effect"
    );
}

#[tokio::test]
async fn a_proxy_gets_only_its_own_config() {
    let fx = Fx::new().await;
    let a = proxy(&fx, "pxa").await;
    let b = proxy(&fx, "pxb").await;

    // no config yet: fixed 404 config_unavailable (distinct from proxy_unknown)
    for p in [&a, &b] {
        for path in [None, Some("/v1/proxy-config")] {
            let r = get_cfg(&fx, p, path).await;
            assert_eq!((r.status, r.code().as_str()), (404, "config_unavailable"));
            assert_eq!(r.body, err_body(ErrorCode::ConfigUnavailable));
        }
    }

    assert_eq!(
        put(&fx, "pxa", Some(T_CFG), &put_body(0, &spec("pxa", "tok-a")))
            .await
            .status,
        200
    );
    let mut sb = spec("pxb", "tok-b");
    sb["routes"][0]["upstream_url"] = "https://b.example.net/mcp".into();
    let rb = put(&fx, "pxb", Some(T_CFG), &put_body(0, &sb)).await;
    assert_eq!(rb.status, 200);

    for (p, tok, other_tok, host, other_host) in [
        (&a, "tok-a", "tok-b", "api.example.com", "b.example.net"),
        (&b, "tok-b", "tok-a", "b.example.net", "api.example.com"),
    ] {
        for path in [None, Some("/v1/proxy-config")] {
            let r = get_cfg(&fx, p, path).await;
            assert_eq!(r.status, 200);
            let text = String::from_utf8(r.body.clone()).unwrap();
            assert!(text.contains(&verifier_for(tok)));
            assert!(text.contains(host));
            assert!(!text.contains(&verifier_for(other_tok)), "foreign verifier");
            assert!(!text.contains(other_host), "foreign route");
            let cfg = sigil_proxy_api::parse_config(&r.body).unwrap();
            assert_eq!(cfg.proxy_id.as_str(), p.id);
            assert_eq!(cfg.revision.get(), 1);
            assert_eq!(cfg.ttl_seconds, 300);
            assert_eq!(cfg.max_offline_retry_age_seconds, 2_592_000);
            assert_eq!(cfg.event_retention_seconds, 7_776_000);
        }
    }

    // asking for the other proxy's path is the same bytes as an unknown id
    let cross = get_cfg(&fx, &a, Some("/v1/proxies/pxb/config")).await;
    let ghost = get_cfg(&fx, &a, Some("/v1/proxies/ghost/config")).await;
    assert_eq!(cross.body, err_body(ErrorCode::ProxyUnknown));
    assert_eq!((cross.status, &cross.body), (ghost.status, &ghost.body));
    assert_eq!(cross.status, 404);

    // management and host certs are not proxy identities
    let r = send(
        &fx.mgmt_client(),
        fx.port,
        "GET",
        "/v1/proxies/pxa/config",
        Some(T_CFG),
        None,
    )
    .await;
    assert_eq!(r.body, err_body(ErrorCode::ProxyUnknown));
    let host = host_leaf(fx.dir.path(), "host2", HOST);
    let hc = fx.client_for(&host.0, &host.1);
    let r = send(
        &hc,
        fx.port,
        "GET",
        "/v1/proxy-config",
        Some(READ_TOKEN),
        None,
    )
    .await;
    assert_eq!(r.body, err_body(ErrorCode::ProxyUnknown));

    // hash: PUT answer == hash of the served document, stable across fetches
    // and across key order of the served JSON.
    let want = {
        let r = put(&fx, "pxa", Some(T_CFG), &put_body(1, &spec("pxa", "tok-a"))).await;
        r.json()["config_hash"].as_str().unwrap().to_string()
    };
    let g1 = get_cfg(&fx, &a, None).await;
    let g2 = get_cfg(&fx, &a, Some("/v1/proxy-config")).await;
    let c1 = sigil_proxy_api::parse_config(&g1.body).unwrap();
    let c2 = sigil_proxy_api::parse_config(&g2.body).unwrap();
    assert_eq!(c1.config_hash().as_str(), want);
    assert_eq!(c2.config_hash().as_str(), want);
    let v = g1.json();
    let mut m: Vec<_> = v.as_object().unwrap().iter().collect();
    m.reverse();
    let reordered = format!(
        "{{{}}}",
        m.iter()
            .map(|(k, v)| format!("{}:{}", serde_json::to_string(k).unwrap(), v))
            .collect::<Vec<_>>()
            .join(",")
    );
    let c3 = sigil_proxy_api::parse_config(reordered.as_bytes()).unwrap();
    assert_eq!(c3.config_hash().as_str(), want);
    // the other proxy's config hashes differently
    assert_ne!(
        sigil_proxy_api::parse_config(&get_cfg(&fx, &b, None).await.body)
            .unwrap()
            .config_hash()
            .as_str(),
        want
    );
}

#[tokio::test]
async fn disabled_and_retired_proxies_get_403_on_get_and_status() {
    let fx = Fx::new().await;
    let a = proxy(&fx, "pxa").await;
    assert_eq!(
        put(&fx, "pxa", Some(T_CFG), &put_body(0, &spec("pxa", "tok-a")))
            .await
            .status,
        200
    );
    assert_eq!(
        post_status(&fx, &a, &status_body("pxa", EPOCH, 1, vec![]))
            .await
            .status,
        200
    );
    let mc = fx.mgmt_client();
    let r = send(
        &mc,
        fx.port,
        "POST",
        "/v1/proxies/pxa/disable",
        Some(T_CFG),
        None,
    )
    .await;
    assert_eq!(r.status, 200);

    for path in [None, Some("/v1/proxy-config")] {
        let r = get_cfg(&fx, &a, path).await;
        assert_eq!((r.status, r.code().as_str()), (403, "disabled"));
        assert_eq!(r.body, err_body(ErrorCode::Disabled));
        assert!(!String::from_utf8_lossy(&r.body).contains(&verifier_for("tok-a")));
    }
    let r = post_status(
        &fx,
        &a,
        &status_body("pxa", EPOCH, 2, vec![quarantine(1, "conflict")]),
    )
    .await;
    assert_eq!((r.status, r.code().as_str()), (403, "disabled"));
    let e = fx.ctx.store.entry("pxa").unwrap();
    assert!(e.gaps.is_empty(), "nothing from a disabled proxy is stored");
    assert_eq!(e.status.unwrap().status_sequence.get(), 1);

    // a config can still be staged while disabled
    let r = put(
        &fx,
        "pxa",
        Some(T_CFG),
        &put_body(1, &spec("pxa", "tok-a2")),
    )
    .await;
    assert_eq!(r.status, 200);

    // enable: back to 200
    let r = send(
        &mc,
        fx.port,
        "POST",
        "/v1/proxies/pxa/enable",
        Some(T_ID),
        None,
    )
    .await;
    assert_eq!(r.status, 200);
    assert_eq!(get_cfg(&fx, &a, None).await.json()["revision"], 2);

    // retire: 403 retired on both
    let r = send(
        &mc,
        fx.port,
        "POST",
        "/v1/proxies/pxa/retire",
        Some(T_ID),
        None,
    )
    .await;
    assert_eq!(r.status, 200);
    let r = get_cfg(&fx, &a, None).await;
    assert_eq!((r.status, r.code().as_str()), (403, "retired"));
    let r = post_status(&fx, &a, &status_body("pxa", EPOCH, 3, vec![])).await;
    assert_eq!((r.status, r.code().as_str()), (403, "retired"));
}

#[tokio::test]
async fn status_upsert_identity_and_validation() {
    let fx = Fx::new().await;
    let a = proxy(&fx, "pxa").await;
    let b = proxy(&fx, "pxb").await;

    let r = post_status(&fx, &a, &status_body("pxa", EPOCH, 5, vec![])).await;
    assert_eq!(r.status, 200);
    let resp = sigil_proxy_api::parse_status_response(&r.body).unwrap();
    assert!(resp.state_applied);
    assert!(resp.acknowledged_gap_ids.is_empty() && resp.duplicate_gap_ids.is_empty());
    let seen = fx.ctx.store.last_seen("pxa").unwrap();
    assert!(!seen.is_empty());
    assert!(fx.ctx.store.last_seen("pxb").is_none());

    // lower and equal sequence: state not applied, but accepted
    for seq in [4, 5] {
        let r = post_status(&fx, &a, &status_body("pxa", EPOCH, seq, vec![])).await;
        assert_eq!(r.status, 200);
        assert!(
            !sigil_proxy_api::parse_status_response(&r.body)
                .unwrap()
                .state_applied
        );
    }
    assert_eq!(
        fx.ctx
            .store
            .entry("pxa")
            .unwrap()
            .status
            .unwrap()
            .status_sequence
            .get(),
        5
    );
    // higher applies; a new epoch applies at a low sequence
    let r = post_status(&fx, &a, &status_body("pxa", EPOCH, 6, vec![])).await;
    assert!(
        sigil_proxy_api::parse_status_response(&r.body)
            .unwrap()
            .state_applied
    );
    let e2 = "00000000-0000-4000-8000-0000000000e2";
    let r = post_status(&fx, &a, &status_body("pxa", e2, 1, vec![])).await;
    assert!(
        sigil_proxy_api::parse_status_response(&r.body)
            .unwrap()
            .state_applied
    );

    // body proxy_id of another proxy, or an unknown one: the same 404 bytes,
    // evaluated before the rest of the body (this body is otherwise invalid)
    let wrong = status_body("pxb", EPOCH, 7, vec![]);
    let r = post_status(&fx, &a, &wrong).await;
    assert_eq!(r.body, err_body(ErrorCode::ProxyUnknown));
    assert_eq!(r.status, 404);
    let r2 = post_status(&fx, &a, r#"{"proxy_id":"ghost","junk":true}"#).await;
    assert_eq!((r2.status, &r2.body), (404, &r.body));
    assert!(
        fx.ctx.store.entry("pxb").is_none(),
        "nothing written for pxb"
    );
    // and pxb's own post is stored under pxb only
    assert_eq!(post_status(&fx, &b, &wrong).await.status, 200);
    assert_eq!(
        fx.ctx
            .store
            .entry("pxb")
            .unwrap()
            .status
            .unwrap()
            .proxy_id
            .as_str(),
        "pxb"
    );

    // schema errors: 422 semantic_invalid, nothing echoed
    for raw in [
        "".to_string(),
        "{".into(),
        r#"{"proxy_id":"pxa"}"#.into(),
        r#"{"proxy_id":7}"#.into(),
        status_body("pxa", EPOCH, 8, vec![]).replace("\"gaps\"", "\"surprise\":1,\"gaps\""),
        status_body("pxa", EPOCH, 8, vec![])
            .replace("\"schema_version\":1", "\"schema_version\":2"),
    ] {
        let r = post_status(&fx, &a, &raw).await;
        assert_eq!(
            (r.status, r.code().as_str()),
            (422, "semantic_invalid"),
            "{raw:.60}"
        );
    }
    // a host cert is not a proxy identity
    let host = host_leaf(fx.dir.path(), "host3", HOST);
    let hc = fx.client_for(&host.0, &host.1);
    let r = send(&hc, fx.port, "POST", "/v1/proxy-status", None, Some(&wrong)).await;
    assert_eq!(r.body, err_body(ErrorCode::ProxyUnknown));
    // GET is not a status method
    let r = send(&a.client, fx.port, "GET", "/v1/proxy-status", None, None).await;
    assert_eq!(r.status, 405);
}

#[tokio::test]
async fn gap_upsert_is_idempotent_and_illegal_mutation_is_409() {
    let fx = Fx::new().await;
    let a = proxy(&fx, "pxa").await;
    let parse = |r: &Resp| sigil_proxy_api::parse_status_response(&r.body).unwrap();
    let ids = |v: &[sigil_proxy_api::Uuid]| -> Vec<String> {
        v.iter().map(|u| u.as_str().to_string()).collect()
    };

    let gaps = vec![
        quarantine(1, "conflict"),
        outage(2, serde_json::Value::Null),
    ];
    let r = post_status(&fx, &a, &status_body("pxa", EPOCH, 1, gaps.clone())).await;
    assert_eq!(r.status, 200);
    let p = parse(&r);
    assert_eq!(ids(&p.acknowledged_gap_ids), vec![uid(1), uid(2)]);
    assert!(p.duplicate_gap_ids.is_empty());

    // resend (even with a stale sequence): duplicates, nothing changes
    let r = post_status(&fx, &a, &status_body("pxa", EPOCH, 1, gaps.clone())).await;
    let p = parse(&r);
    assert!(!p.state_applied);
    assert!(p.acknowledged_gap_ids.is_empty());
    assert_eq!(ids(&p.duplicate_gap_ids), vec![uid(1), uid(2)]);
    assert_eq!(fx.ctx.store.entry("pxa").unwrap().gaps.len(), 2);

    // the only legal mutation: outage ended_at null -> value
    let closed = outage(2, "2026-10-11T00:30:00Z".into());
    let r = post_status(&fx, &a, &status_body("pxa", EPOCH, 2, vec![closed.clone()])).await;
    assert_eq!(ids(&parse(&r).acknowledged_gap_ids), vec![uid(2)]);
    let r = post_status(&fx, &a, &status_body("pxa", EPOCH, 3, vec![closed])).await;
    assert_eq!(ids(&parse(&r).duplicate_gap_ids), vec![uid(2)]);

    // illegal: closed outage reopened / re-ended, and a content change
    let seq_before = fx
        .ctx
        .store
        .entry("pxa")
        .unwrap()
        .status
        .unwrap()
        .status_sequence
        .get();
    for (i, bad) in [
        outage(2, serde_json::Value::Null),
        outage(2, "2026-10-11T00:45:00Z".into()),
    ]
    .into_iter()
    .enumerate()
    {
        // a legal new gap rides along at index 1 and must not be applied
        let new_gap = quarantine(70 + i as u32, "conflict");
        let r = post_status(
            &fx,
            &a,
            &status_body("pxa", EPOCH, 10 + i as u32, vec![bad, new_gap]),
        )
        .await;
        assert_eq!((r.status, r.code().as_str()), (409, "conflict"));
        let items = r.json()["error"]["items"].clone();
        assert_eq!(items.as_array().unwrap().len(), 1);
        assert_eq!(items[0]["index"], 0);
        assert_eq!(items[0]["gap_id"], uid(2).as_str());
        assert_eq!(items[0]["code"], "conflict");
        assert!(items[0].get("event_id").is_none());
        // the typed client parses it
        let e = sigil_proxy_api::parse_api_error(&r.body).unwrap();
        assert_eq!(
            e.error.items.unwrap()[0].gap_id.as_ref().unwrap().as_str(),
            uid(2)
        );
    }
    let r = post_status(
        &fx,
        &a,
        &status_body("pxa", EPOCH, 20, vec![quarantine(1, "semantic_invalid")]),
    )
    .await;
    assert_eq!(r.status, 409);
    assert_eq!(r.json()["error"]["items"][0]["gap_id"], uid(1).as_str());

    let e = fx.ctx.store.entry("pxa").unwrap();
    assert_eq!(e.gaps.len(), 2, "nothing from a 409 report was stored");
    assert_eq!(e.status.unwrap().status_sequence.get(), seq_before);
}

#[tokio::test]
async fn config_and_status_survive_a_restart() {
    let fx = Fx::new().await;
    let a = proxy(&fx, "pxa").await;
    let r = put(&fx, "pxa", Some(T_CFG), &put_body(0, &spec("pxa", "tok-a"))).await;
    let hash = r.json()["config_hash"].as_str().unwrap().to_string();
    let g = vec![quarantine(1, "conflict")];
    assert_eq!(
        post_status(&fx, &a, &status_body("pxa", EPOCH, 3, g))
            .await
            .status,
        200
    );
    let path = fx.p("proxy-state.json");
    let meta = std::fs::metadata(&path).unwrap();
    assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    // no temp files left behind
    let strays: Vec<_> = std::fs::read_dir(fx.dir.path())
        .unwrap()
        .filter_map(Result::ok)
        .filter(|e| e.file_name().to_string_lossy().starts_with(".proxy-state-"))
        .collect();
    assert!(strays.is_empty());

    let reopened = sigil_server::proxy::store::ProxyStore::open(&path).unwrap();
    let e = reopened.entry("pxa").unwrap();
    assert_eq!(e.config.unwrap().config_hash, hash);
    assert_eq!(e.status.unwrap().status_sequence.get(), 3);
    assert_eq!(e.gaps.len(), 1);
    assert!(e.last_seen.is_some());
}

#[test]
fn ttl_and_margin_bounds_are_boot_checked() {
    let base = "bind: \"127.0.0.1:0\"\ntls_cert_path: /e/s.crt\ntls_key_path: /e/s.key\n\
        client_ca_path: /e/ca.pem\nevents_out_dir: /d/e\npolicy_bundle_path: /d/p.json\n\
        proxy:\n  ca_path: /e/proxy-ca.pem\n  registry_path: /d/proxies.json\n";
    let dir = tempfile::tempdir().unwrap();
    let load = |extra: &str| {
        let p = dir.path().join("server.yaml");
        std::fs::write(&p, format!("{base}{extra}")).unwrap();
        ServerConfig::load(&p)
    };
    let ok = load("").unwrap().proxy.unwrap();
    assert_eq!(
        (ok.config_ttl(), ok.ack_loss_margin()),
        (300, 7 * 24 * 3600)
    );
    assert_eq!(ok.state_path(), std::path::Path::new("/d/proxy-state.json"));
    assert!(load("  config_ttl_seconds: 60\n").is_ok());
    assert!(load("  config_ttl_seconds: 900\n").is_ok());
    for bad in [
        "  config_ttl_seconds: 59\n",
        "  config_ttl_seconds: 901\n",
        "  ack_loss_margin_seconds: 3599\n",
        "  ack_loss_margin_seconds: 2592001\n",
    ] {
        assert!(load(bad).is_err(), "{bad}");
    }
}
