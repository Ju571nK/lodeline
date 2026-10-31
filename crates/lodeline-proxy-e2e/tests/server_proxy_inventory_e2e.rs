#![cfg(unix)]
//! T-13a-server (#304): `POST /v1/proxy-inventory` and the inventory read
//! views over real loopback rustls mTLS.
//!
//! Real handshakes (openssl builds a host CA and a proxy CA in one bundle, as
//! production); reqwest is the mTLS client. The proxy registry, route scopes
//! and registry entries are seeded through the server's public store APIs, so
//! this file tests the transport, the identity classes and the inventory
//! pipeline, not the proxy-side producer (T-13b). PKI helpers are copied from
//! `server_proxy_query_e2e.rs` (sharing them is tracked in #284).
//!
//! Requirements: PX-005, PX-010, PX-011; acceptance AC-02, AC-05.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use lodeline_proxy_api::verifier::verifier_for;
use lodeline_proxy_api::{parse_config, RegistryEntry};
use lodeline_server::app::{build_router_with_proxy, AppState};
use lodeline_server::auth::ReadToken;
use lodeline_server::config::ServerConfig;
use lodeline_server::fleet_index::FleetIndex;
use lodeline_server::persist::HighWater;
use lodeline_server::proxy::identity::proxy_san;
use lodeline_server::proxy::registry::{ProxyRecord, ProxyState};
use lodeline_server::proxy::store::{ProxyEntry, StoredConfig};
use lodeline_server::proxy::ProxyContext;
use lodeline_server::tls_accept::PeerCertAcceptor;
use serde_json::{json, Value};

const READ_BEARER: &str = "read-bearer";
const CANARY_NAME: &str = "canarytoolname7f3a";
const SCOPE: &str = "cs-0123456789abcdef0123456789abcdef";

// ---------------------------------------------------------------- openssl

fn find_openssl() -> Option<PathBuf> {
    [
        "/usr/bin/openssl",
        "/opt/homebrew/bin/openssl",
        "/opt/homebrew/opt/openssl@3/bin/openssl",
        "/usr/local/bin/openssl",
        "/usr/local/opt/openssl@3/bin/openssl",
    ]
    .iter()
    .map(PathBuf::from)
    .find(|p| p.exists())
}

fn run_ossl(ossl: &Path, args: &[&std::ffi::OsStr]) {
    let o = Command::new(ossl)
        .env_remove("OPENSSL_CONF")
        .args(args)
        .output()
        .unwrap();
    assert!(
        o.status.success(),
        "openssl {args:?}: {}",
        String::from_utf8_lossy(&o.stderr)
    );
}

struct Pki {
    dir: tempfile::TempDir,
    ossl: PathBuf,
    serial: AtomicUsize,
}

impl Pki {
    fn p(&self, f: &str) -> PathBuf {
        self.dir.path().join(f)
    }

    fn ca(&self, name: &str, cn: &str, serial: &str) {
        let key = self.p(&format!("{name}.key"));
        run_ossl(
            &self.ossl,
            &[
                "req".as_ref(),
                "-x509".as_ref(),
                "-new".as_ref(),
                "-newkey".as_ref(),
                "rsa:2048".as_ref(),
                "-nodes".as_ref(),
                "-keyout".as_ref(),
                key.as_os_str(),
                "-days".as_ref(),
                "2".as_ref(),
                "-set_serial".as_ref(),
                serial.as_ref(),
                "-subj".as_ref(),
                format!("/CN={cn}").as_ref(),
                "-addext".as_ref(),
                "basicConstraints=critical,CA:TRUE".as_ref(),
                "-addext".as_ref(),
                "subjectKeyIdentifier=hash".as_ref(),
                "-out".as_ref(),
                self.p(&format!("{name}.crt")).as_os_str(),
            ],
        );
    }

    /// CA-signed RSA-2048 leaf, `-set_serial` (never `-CAcreateserial`).
    fn leaf(&self, ca: &str, name: &str, cn: &str, ext: &str) -> (PathBuf, PathBuf) {
        let (key, csr, crt, extf) = (
            self.p(&format!("{name}.key")),
            self.p(&format!("{name}.csr")),
            self.p(&format!("{name}.crt")),
            self.p(&format!("{name}.ext")),
        );
        std::fs::write(&extf, ext).unwrap();
        run_ossl(
            &self.ossl,
            &[
                "req".as_ref(),
                "-new".as_ref(),
                "-newkey".as_ref(),
                "rsa:2048".as_ref(),
                "-nodes".as_ref(),
                "-keyout".as_ref(),
                key.as_os_str(),
                "-subj".as_ref(),
                format!("/CN={cn}").as_ref(),
                "-out".as_ref(),
                csr.as_os_str(),
            ],
        );
        let serial = format!("{}", 100 + self.serial.fetch_add(1, Ordering::Relaxed));
        run_ossl(
            &self.ossl,
            &[
                "x509".as_ref(),
                "-req".as_ref(),
                "-in".as_ref(),
                csr.as_os_str(),
                "-CA".as_ref(),
                self.p(&format!("{ca}.crt")).as_os_str(),
                "-CAkey".as_ref(),
                self.p(&format!("{ca}.key")).as_os_str(),
                "-set_serial".as_ref(),
                serial.as_ref(),
                "-days".as_ref(),
                "2".as_ref(),
                "-extfile".as_ref(),
                extf.as_os_str(),
                "-out".as_ref(),
                crt.as_os_str(),
            ],
        );
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        (crt, key)
    }
}

/// `None` when openssl is missing and `CI` is unset (skip); panics under CI.
fn pki() -> Option<Pki> {
    let Some(ossl) = find_openssl() else {
        assert!(
            std::env::var_os("CI").is_none(),
            "openssl CLI not found but CI is set"
        );
        eprintln!("skipped: openssl CLI not found");
        return None;
    };
    let pki = Pki {
        dir: tempfile::tempdir().unwrap(),
        ossl,
        serial: AtomicUsize::new(0),
    };
    pki.ca("hostca", "ing-host-ca", "1");
    pki.ca("proxyca", "ing-proxy-ca", "2");
    let mut bundle = std::fs::read(pki.p("hostca.crt")).unwrap();
    bundle.extend(std::fs::read(pki.p("proxyca.crt")).unwrap());
    std::fs::write(pki.p("bundle.pem"), bundle).unwrap();
    pki.leaf(
        "hostca",
        "server",
        "localhost",
        "subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n",
    );
    Some(pki)
}

fn fingerprint(crt: &Path) -> String {
    let pem = std::fs::read(crt).unwrap();
    let certs: Vec<_> = rustls_pemfile::certs(&mut std::io::BufReader::new(&pem[..]))
        .collect::<Result<_, _>>()
        .unwrap();
    blake3::hash(certs[0].as_ref()).to_hex().to_string()
}

fn mtls_client(trust: &Path, crt: &Path, key: &Path) -> reqwest::Client {
    let mut id = std::fs::read(key).unwrap();
    id.extend_from_slice(&std::fs::read(crt).unwrap());
    reqwest::Client::builder()
        .use_rustls_tls()
        .pool_max_idle_per_host(0)
        .add_root_certificate(
            reqwest::Certificate::from_pem(&std::fs::read(trust).unwrap()).unwrap(),
        )
        .identity(reqwest::Identity::from_pem(&id).unwrap())
        .build()
        .unwrap()
}

fn tls_config(pki: &Pki) -> rustls::ServerConfig {
    let rd = |f: &str| std::fs::read(pki.p(f)).unwrap();
    let certs: Vec<_> = rustls_pemfile::certs(&mut std::io::BufReader::new(&rd("server.crt")[..]))
        .collect::<Result<_, _>>()
        .unwrap();
    let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(&rd("server.key")[..]))
        .unwrap()
        .unwrap();
    let mut roots = rustls::RootCertStore::empty();
    for c in rustls_pemfile::certs(&mut std::io::BufReader::new(&rd("bundle.pem")[..])) {
        roots.add(c.unwrap()).unwrap();
    }
    let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .unwrap();
    rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)
        .unwrap()
}

fn app_state(dir: &Path) -> Arc<AppState> {
    Arc::new(AppState {
        events_out_dir: dir.to_path_buf(),
        policy_bundle_path: dir.join("signed-policy.json"),
        rule_packs_bundle_path: None,
        artifacts_dir: None,
        high_water_path: dir.join(".high-water.json"),
        allowlist: parking_lot::RwLock::new(None),
        high_water: Mutex::new(HighWater::default()),
        fleet_index: FleetIndex::new(),
        read_token: ReadToken(Some("read-bearer".into())),
        active_window_days: 7,
        audit_key: None,
        audit_head: Mutex::new(None),
        allowlist_path: None,
        enroll: None,
        events_require_cert_host_match: false,
    })
}

// ----------------------------------------------------------------- fixtures

fn uuid(n: u32) -> String {
    format!("00000000-0000-4000-8000-{n:012}")
}
fn mref(n: u32) -> String {
    format!("00000000-0000-8000-8000-{n:012}")
}
const KID: &str = "kid-000000000000000000000001";

fn report(proxy: &str, n: u32, members: &[u32], cmp: Value) -> Value {
    json!({
        "schema_version": 1, "report_id": uuid(2000 + n), "proxy_id": proxy,
        "epoch_id": uuid(3000), "observed_at": format!("2026-10-10T00:00:{:02}Z", n),
        "scope": {"upstream_id": "up1", "credential_scope_id": SCOPE,
            "protocol_version": "2025-11-25", "observation_source": "proxy_live"},
        "canon": "sigil-tooldef-fp-v1", "key_id": KID, "completeness": "complete",
        "pages_observed": 1, "inventory_id": uuid(1000 + n),
        "members": members.iter().map(|m| mref(*m)).collect::<Vec<_>>(),
        "comparison": cmp,
    })
}

fn incomplete(proxy: &str, n: u32) -> Value {
    json!({
        "schema_version": 1, "report_id": uuid(2000 + n), "proxy_id": proxy,
        "epoch_id": uuid(3000), "observed_at": format!("2026-10-10T00:00:{:02}Z", n),
        "scope": {"upstream_id": "up1", "credential_scope_id": SCOPE,
            "protocol_version": "2025-11-25", "observation_source": "proxy_live"},
        "canon": "sigil-tooldef-fp-v1", "key_id": KID, "completeness": "incomplete",
        "pages_observed": 2, "incomplete_reason": "page_error",
    })
}

fn entry(proxy: &str, n: u32) -> RegistryEntry {
    serde_json::from_value(json!({
        "proxy_id": proxy, "metadata_ref": mref(n), "upstream_id": "up1",
        "credential_scope_id": SCOPE, "protocol_version": "2025-11-25",
        "observation_source": "proxy_live", "canon": "sigil-tooldef-fp-v1", "key_id": KID,
        "fingerprint": format!("{:064x}", 0xabc0_0000u64 + u64::from(n)),
        "observed_at": "2026-10-10T00:00:00Z",
        "definition": {"name": CANARY_NAME},
    }))
    .unwrap()
}

fn config_for(proxy: &str) -> StoredConfig {
    let v = json!({
        "schema_version": 1, "proxy_id": proxy, "revision": 1,
        "issued_at": "2026-10-11T00:00:00Z", "expires_at": "2026-10-11T00:05:00Z",
        "ttl_seconds": 300, "mode": "observe",
        "max_offline_retry_age_seconds": 2592000, "event_retention_seconds": 7776000,
        "allowed_origins": ["https://app.example.com"],
        "routes": [{"route_id": "r1", "upstream_id": "up1",
            "upstream_url": "https://api.example.com/mcp", "upstream_protocol": "2025-11-25",
            "credential_ref": "gh", "credential_scope_id": SCOPE}],
        "principals": [{"principal_id": "claude",
            "verifiers": [{"key_id": "k1", "verifier": verifier_for("client-tok")}],
            "routes": ["r1"]}],
    });
    StoredConfig {
        config: parse_config(v.to_string().as_bytes()).unwrap(),
        config_hash: "0".repeat(64),
        updated_at: "2026-10-11T00:00:00Z".into(),
    }
}

struct Env {
    pki: Pki,
    port: u16,
    a: reqwest::Client,
    b: reqwest::Client,
    host: reqwest::Client,
    _server: tokio::task::JoinHandle<()>,
}

impl Env {
    async fn start(pki: Pki) -> Env {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let d = pki.dir.path().to_path_buf();
        let p = |f: &str| d.join(f).display().to_string();
        let y = format!(
            "bind: \"127.0.0.1:0\"\ntls_cert_path: {}\ntls_key_path: {}\nclient_ca_path: {}\n\
             events_out_dir: {}\npolicy_bundle_path: {}\n\
             proxy:\n  ca_path: {}\n  registry_path: {}\n  registry_init: true\n",
            p("server.crt"),
            p("server.key"),
            p("bundle.pem"),
            d.display(),
            p("signed-policy.json"),
            p("proxyca.crt"),
            p("proxies.json"),
        );
        let cfg: ServerConfig = serde_yaml::from_str(&y).unwrap();
        let ctx = Arc::new(ProxyContext::load(&cfg).unwrap().unwrap());

        let mut clients = Vec::new();
        for id in ["px-a", "px-b"] {
            let cert = pki.leaf(
                "proxyca",
                id,
                id,
                &format!(
                    "subjectAltName=DNS:{}\nextendedKeyUsage=clientAuth\nbasicConstraints=CA:FALSE\nauthorityKeyIdentifier=keyid\n",
                    proxy_san(id)
                ),
            );
            ctx.registry
                .seed_for_test(ProxyRecord {
                    proxy_id: id.into(),
                    display_name: id.into(),
                    state: ProxyState::Active,
                    fp_current: Some(fingerprint(&cert.0)),
                    fp_next: None,
                    created_at: "2026-10-01T00:00:00Z".into(),
                    updated_at: "2026-10-01T00:00:00Z".into(),
                })
                .unwrap();
            ctx.store
                .begin()
                .commit(
                    id,
                    ProxyEntry {
                        config: Some(config_for(id)),
                        ..Default::default()
                    },
                )
                .unwrap();
            let all: Vec<RegistryEntry> = (1..=20).map(|n| entry(id, n)).collect();
            ctx.metadata.register(id, &all, 1_000).unwrap();
            clients.push(mtls_client(&pki.p("hostca.crt"), &cert.0, &cert.1));
        }
        let host = pki.leaf(
            "hostca",
            "host",
            "host-1",
            "subjectAltName=DNS:host-1\nextendedKeyUsage=clientAuth\nbasicConstraints=CA:FALSE\n",
        );
        let host_client = mtls_client(&pki.p("hostca.crt"), &host.0, &host.1);

        let tls = axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(tls_config(&pki)));
        let app = build_router_with_proxy(app_state(&d), Some(ctx.clone()));
        let handle = axum_server::Handle::new();
        let h = handle.clone();
        let task = tokio::spawn(async move {
            let _ = axum_server::bind("127.0.0.1:0".parse().unwrap())
                .handle(h)
                .acceptor(PeerCertAcceptor::new(tls))
                .serve(app.into_make_service())
                .await;
        });
        let port = handle.listening().await.expect("bound").port();
        let b = clients.pop().unwrap();
        let a = clients.pop().unwrap();
        Env {
            pki,
            port,
            a,
            b,
            host: host_client,
            _server: task,
        }
    }

    fn url(&self, path: &str) -> String {
        format!("https://127.0.0.1:{}{path}", self.port)
    }

    async fn post(&self, c: &reqwest::Client, body: String) -> (u16, String) {
        let r = c
            .post(self.url("/v1/proxy-inventory"))
            .header("content-type", "application/json")
            .body(body)
            .send()
            .await
            .unwrap();
        (r.status().as_u16(), r.text().await.unwrap())
    }

    async fn get(&self, c: &reqwest::Client, path: &str, bearer: bool) -> (u16, String) {
        let mut r = c.get(self.url(path));
        if bearer {
            r = r.bearer_auth(READ_BEARER);
        }
        let r = r.send().await.unwrap();
        (r.status().as_u16(), r.text().await.unwrap())
    }

    async fn items(&self, path: &str) -> Vec<Value> {
        let (s, t) = self.get(&self.host, path, true).await;
        assert_eq!(s, 200, "{t}");
        serde_json::from_str::<Value>(&t).unwrap()["items"]
            .as_array()
            .unwrap()
            .clone()
    }
}

fn code(t: &str) -> String {
    serde_json::from_str::<Value>(t).unwrap()["error"]["code"]
        .as_str()
        .unwrap_or("")
        .to_string()
}

#[tokio::test]
async fn inventory_over_mtls_ingest_projection_and_read() {
    let Some(pki) = pki() else { return };
    let env = Env::start(pki).await;
    let mut seen: Vec<String> = Vec::new();

    // First listing, then the second one with an add, a change and a removal.
    let (s, t) = env
        .post(
            &env.a,
            report("px-a", 1, &[1, 2, 3], json!({"kind": "initial_baseline"})).to_string(),
        )
        .await;
    assert_eq!(s, 200, "{t}");
    seen.push(t);
    let second = report(
        "px-a",
        2,
        &[1, 4, 5],
        json!({"kind": "compared", "previous_inventory_id": uuid(1001), "changes": [
            {"change": "changed", "metadata_ref": mref(4), "previous_metadata_ref": mref(2)},
            {"change": "removed", "metadata_ref": mref(3)},
            {"change": "added", "metadata_ref": mref(5)}]}),
    );
    let (s, t) = env.post(&env.a, second.to_string()).await;
    assert_eq!(s, 200, "{t}");
    seen.push(t);
    // an incomplete observation changes nothing but adds a gap
    let (s, t) = env.post(&env.a, incomplete("px-a", 3).to_string()).await;
    assert_eq!(s, 200, "{t}");
    // a retransmission is an idempotent 200
    let (s, t) = env.post(&env.a, second.to_string()).await;
    assert_eq!(s, 200);
    assert_eq!(
        serde_json::from_str::<Value>(&t).unwrap()["duplicate"],
        true
    );
    // different content under the same report id is a 409
    let mut other = second.clone();
    other["pages_observed"] = json!(9);
    let (s, t) = env.post(&env.a, other.to_string()).await;
    assert_eq!((s, code(&t).as_str()), (409, "conflict"));
    seen.push(t);

    // Refusals: every identity failure is the same 404 as an unknown proxy.
    let (s, unknown) = env
        .post(
            &env.a,
            report("px-b", 7, &[1], json!({"kind": "initial_baseline"})).to_string(),
        )
        .await;
    assert_eq!((s, code(&unknown).as_str()), (404, "proxy_unknown"));
    let (s, t) = env.post(&env.host, "{}".into()).await;
    assert_eq!((s, code(&t).as_str()), (404, "proxy_unknown"));
    assert_eq!(t, unknown, "a host certificate looks like an unknown proxy");
    // unregistered ref: 424 with the ref
    let (s, t) = env
        .post(
            &env.a,
            report("px-a", 8, &[1, 99], json!({"kind": "initial_baseline"})).to_string(),
        )
        .await;
    assert_eq!((s, code(&t).as_str()), (424, "metadata_ref_pending"));
    assert!(t.contains(&mref(99)));
    // oversized body is refused before it is parsed
    let (s, t) = env.post(&env.a, " ".repeat(4 * 1024 * 1024 + 1)).await;
    assert_eq!((s, code(&t).as_str()), (413, "payload_too_large"));
    seen.push(t);

    // Read views with a host certificate and the read bearer.
    let snaps = env.items("/v1/proxies/px-a/inventory-snapshots").await;
    assert_eq!(snaps.len(), 2);
    assert_eq!(snaps[0]["inventory_id"], uuid(1002).as_str());
    assert_eq!(snaps[0]["comparison_state"], "compared");
    assert_eq!(snaps[0]["is_latest"], true);
    assert_eq!(snaps[1]["is_first_baseline"], true);
    let drift = env.items("/v1/proxies/px-a/drift").await;
    assert_eq!(drift.len(), 3);
    assert!(env
        .items("/v1/proxies/px-a/rebaseline-markers")
        .await
        .is_empty());
    assert!(env
        .items("/v1/proxies/px-b/inventory-snapshots")
        .await
        .is_empty());
    let (s, detail) = env.get(&env.host, "/v1/proxies/px-a", true).await;
    assert_eq!(s, 200);
    let d: Value = serde_json::from_str(&detail).unwrap();
    assert_eq!(d["open_gap_counts"]["inventory_incomplete"], 1);
    assert_eq!(d["audit_gaps"][0]["kind"], "inventory_incomplete");
    // paging
    let (s, t) = env
        .get(&env.host, "/v1/proxies/px-a/drift?limit=2", true)
        .await;
    assert_eq!(s, 200);
    assert!(serde_json::from_str::<Value>(&t).unwrap()["next_cursor"].is_string());

    // Read auth over TLS: no bearer 401, proxy cert refused, unknown proxy 404.
    let (s, _) = env.get(&env.host, "/v1/proxies/px-a/drift", false).await;
    assert_eq!(s, 401);
    let (s, t) = env.get(&env.a, "/v1/proxies/px-a/drift", true).await;
    assert_eq!((s, t.contains("host_unknown")), (404, true));
    let (s, t) = env.get(&env.host, "/v1/proxies/px-zz/drift", true).await;
    assert_eq!((s, code(&t).as_str()), (404, "proxy_unknown"));
    // no client certificate: the handshake fails
    let anon = reqwest::Client::builder()
        .use_rustls_tls()
        .add_root_certificate(
            reqwest::Certificate::from_pem(&std::fs::read(env.pki.p("hostca.crt")).unwrap())
                .unwrap(),
        )
        .build()
        .unwrap();
    assert!(anon
        .post(env.url("/v1/proxy-inventory"))
        .body("{}")
        .send()
        .await
        .is_err());

    // px-b's own listing is separate, and the tool content never appears.
    let (s, t) = env
        .post(
            &env.b,
            report("px-b", 1, &[1, 2], json!({"kind": "initial_baseline"})).to_string(),
        )
        .await;
    assert_eq!(s, 200, "{t}");
    assert_eq!(
        env.items("/v1/proxies/px-b/inventory-snapshots")
            .await
            .len(),
        1
    );
    assert_eq!(
        env.items("/v1/proxies/px-a/inventory-snapshots")
            .await
            .len(),
        2
    );
    for path in [
        "/v1/proxies/px-a",
        "/v1/proxies/px-a/inventory-snapshots",
        "/v1/proxies/px-a/drift",
    ] {
        seen.push(env.get(&env.host, path, true).await.1);
    }
    for t in &seen {
        assert!(!t.contains(CANARY_NAME) && !t.contains("abc0000"), "{t}");
    }
}
