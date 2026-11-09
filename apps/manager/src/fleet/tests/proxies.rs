//! The proxy reads against a real `lodeline-server` with a proxy section, in process.
//!
//! The server's proxy DTOs only serialize, so there is no server type to decode with. Instead
//! the console's body, encoded again, must equal the server's JSON minus the keys the console
//! does not read. A field the server adds, renames or drops, or an enum value the console does
//! not know, shows up as a difference here.
//!
//! The TLS acceptor is replaced by a layer that sets the peer identity it would set, a
//! host-class certificate, and narrows the read scope with the server's test hook.

use std::path::Path;
use std::process::Command;
use std::sync::Arc;

use axum::extract::Request as HttpRequest;
use axum::middleware::Next;
use lodeline_server::app::build_router_with_proxy;
use lodeline_server::config::ServerConfig;
use lodeline_server::proxy::query::TestScope;
use lodeline_server::proxy::registry::{ProxyRecord, ProxyState};
use lodeline_server::proxy::store::ProxyEntry;
use lodeline_server::proxy::ProxyContext;
use lodeline_server::tls_accept::PeerIdentity;

use super::*;

const HOST_CA: &str = "CN=test-host-ca";

fn make_ca(dir: &Path, name: &str, cn: &str) {
    let openssl = lodeline_server::enroll::sign::resolve_openssl().expect("openssl");
    let key = dir.join(format!("{name}.key"));
    let crt = dir.join(format!("{name}.crt"));
    let key = key.to_str().unwrap();
    for args in [
        vec![
            "genpkey",
            "-algorithm",
            "EC",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-out",
            key,
        ],
        vec![
            "req",
            "-x509",
            "-new",
            "-key",
            key,
            "-days",
            "1",
            "-subj",
            &format!("/CN={cn}"),
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "subjectKeyIdentifier=hash",
            "-out",
            crt.to_str().unwrap(),
        ],
    ] {
        let out = Command::new(&openssl).args(&args).output().unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

fn rfc3339(secs_ago: i64) -> String {
    (chrono::Utc::now() - chrono::Duration::seconds(secs_ago))
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// A status report as a proxy sends it. `older` leaves out what proxies before the fields omit.
fn status(proxy: &str, older: bool) -> Value {
    let mut s = json!({
        "schema_version": 1, "report_id": "00000000-0000-4000-8000-000000000900",
        "proxy_id": proxy, "epoch_id": "11111111-1111-4111-8111-111111111111",
        "status_sequence": 5, "sent_at": "2026-11-09T00:00:00Z",
        "config": {"state": "valid", "applied_revision": 2, "observed_desired_revision": 3,
            "expires_at": "2026-11-09T00:05:00Z", "max_offline_retry_age_seconds": 2592000,
            "event_retention_seconds": 7776000, "config_hash": "0".repeat(64)},
        "spool": {"state": "degraded", "depth_events": 4, "unsent_events": 3, "bytes": 99,
            "capacity_bytes": 1000, "oldest_unsent_age_seconds": 7, "quarantined_events": 1,
            "quarantined_bytes": 512},
        "registry": {"pending_entries": 2, "sync_stalled": false, "quarantined_entries": 1,
            "poisoned_entries": 0, "discarded_reports": 3},
        "central": {"last_ingest_ack_at": "2026-11-09T00:00:00Z", "consecutive_failures": 9,
            "ingest_stopped": true},
        "routes": [{"upstream_id": "up1", "state": "degraded", "reason": "health_check_failed"},
            {"upstream_id": "up2", "state": "supported"}],
        "counters": {"auth_failures": [], "unmatched_cancels": []},
        "gaps": [], "last_assigned_sequence": 7,
    });
    if older {
        s["spool"]
            .as_object_mut()
            .unwrap()
            .remove("quarantined_bytes");
        s["central"]
            .as_object_mut()
            .unwrap()
            .remove("ingest_stopped");
        for k in [
            "quarantined_entries",
            "poisoned_entries",
            "discarded_reports",
        ] {
            s["registry"].as_object_mut().unwrap().remove(k);
        }
    }
    s
}

fn config(proxy: &str, revision: i64) -> Value {
    json!({
        "config": {
            "schema_version": 1, "proxy_id": proxy, "revision": revision,
            "issued_at": "2026-11-09T00:00:00Z", "expires_at": "2026-11-09T00:05:00Z",
            "ttl_seconds": 300, "mode": "observe",
            "max_offline_retry_age_seconds": 2592000, "event_retention_seconds": 7776000,
            "allowed_origins": ["https://origin.example"],
            "routes": [{"route_id": "r1", "upstream_id": "up1",
                "upstream_url": "https://upstream.example/mcp",
                "upstream_protocol": "2025-11-25", "credential_ref": "cred-ref",
                "credential_scope_id": "cs-0123456789abcdef0123456789abcdef"}],
            "principals": [{"principal_id": "claude",
                "verifiers": [{"key_id": "k1", "verifier": "0".repeat(64)}],
                "routes": ["r1"]}],
        },
        "config_hash": "0".repeat(64),
        "updated_at": "2026-11-09T00:00:00Z",
    })
}

fn entry(proxy: &str, older: bool) -> ProxyEntry {
    serde_json::from_value(json!({
        "config": config(proxy, 3),
        "status": status(proxy, older),
        "last_seen": rfc3339(10),
        "status_received_at": rfc3339(12),
        "gaps": [{"kind": "event_quarantined", "gap_id": "00000000-0000-4000-8000-000000000301",
            "detected_at": "2026-11-09T00:01:00Z",
            "event_ids": ["00000000-0000-4000-8000-000000000302"], "code": "semantic_invalid"}],
    }))
    .unwrap()
}

/// A server with px-a (current proxy), px-b (outside the read scope), px-c (registered, never
/// connected) and px-d (an older proxy).
async fn serve_with_proxies(dir: &Path) -> String {
    make_ca(dir, "hostca", "test-host-ca");
    make_ca(dir, "proxyca", "test-proxy-ca");
    let mut bundle = std::fs::read(dir.join("hostca.crt")).unwrap();
    bundle.extend(std::fs::read(dir.join("proxyca.crt")).unwrap());
    std::fs::write(dir.join("bundle.pem"), bundle).unwrap();
    let path = |f: &str| dir.join(f).display().to_string();
    let cfg: ServerConfig = serde_json::from_value(json!({
        "bind": "127.0.0.1:0", "tls_cert_path": path("server.crt"),
        "tls_key_path": path("server.key"), "client_ca_path": path("bundle.pem"),
        "events_out_dir": dir.display().to_string(),
        "policy_bundle_path": path("signed-policy.json"),
        "proxy": {"ca_path": path("proxyca.crt"), "registry_path": path("proxies.json"),
            "registry_init": true},
    }))
    .unwrap();
    let ctx = Arc::new(ProxyContext::load(&cfg).unwrap().unwrap());
    for (n, id) in ["px-a", "px-b", "px-c", "px-d"].into_iter().enumerate() {
        let state = if id == "px-c" {
            ProxyState::Pending
        } else {
            ProxyState::Active
        };
        ctx.registry
            .seed_for_test(ProxyRecord {
                proxy_id: id.into(),
                display_name: format!("Proxy {id}"),
                state,
                fp_current: Some(format!("{:064x}", n + 1)),
                fp_next: None,
                created_at: "2026-11-01T00:00:00Z".into(),
                updated_at: "2026-11-01T00:00:00Z".into(),
            })
            .unwrap();
    }
    for (id, older) in [("px-a", false), ("px-b", false), ("px-d", true)] {
        let txn = ctx.store.begin();
        txn.commit(id, entry(id, older)).unwrap();
    }
    let host_peer = Arc::new(PeerIdentity {
        fingerprint: "c".repeat(64),
        cn: Some("console".into()),
        san_dns: vec![],
        issuer_dn: Some(HOST_CA.into()),
        issuer_aki: None,
    });
    let app = build_router_with_proxy(fleet_state(dir), Some(ctx)).layer(
        axum::middleware::from_fn(move |mut req: HttpRequest, next: Next| {
            let peer = host_peer.clone();
            async move {
                req.extensions_mut().insert(peer);
                req.extensions_mut().insert(TestScope(vec![
                    "px-a".into(),
                    "px-c".into(),
                    "px-d".into(),
                ]));
                next.run(req).await
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    url
}

async fn raw(url: &str, path: &str) -> (u16, Vec<u8>) {
    let resp = reqwest::Client::new()
        .get(format!("{url}{path}"))
        .bearer_auth(READ_TOKEN)
        .send()
        .await
        .unwrap();
    (resp.status().as_u16(), resp.bytes().await.unwrap().to_vec())
}

/// The server's JSON without the keys the console does not read.
fn without_unread(mut v: Value, detail: bool) -> Value {
    let o = v.as_object_mut().unwrap();
    o.remove("current_epoch_id");
    if detail {
        o.remove("outages");
        o.remove("counters");
    }
    v
}

fn list(cursor: &str, limit: i64, connection_state: &str) -> Request {
    Request::Proxies(ProxiesParams {
        cursor: cursor.into(),
        limit,
        connection_state: connection_state.into(),
        ..Default::default()
    })
}

#[tokio::test]
async fn the_http_client_reads_the_proxy_routes_of_a_real_server() {
    let dir = temp_dir("proxies");
    let url = serve_with_proxies(&dir.0).await;
    let client = HttpClient::new(&url, READ_TOKEN, None, http::TIMEOUT).unwrap();

    let (status, body) = raw(&url, "/v1/proxies").await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    let Response::Proxies(page) = &*client.get(list("", 0, "")).await.unwrap() else {
        panic!("not a proxy page")
    };
    let mut want: Value = serde_json::from_slice(&body).unwrap();
    for item in want["items"].as_array_mut().unwrap() {
        *item = without_unread(item.take(), false);
    }
    assert_eq!(serde_json::to_value(page).unwrap(), want);
    let ids: Vec<_> = page.items.iter().map(|s| s.proxy_id.as_str()).collect();
    assert_eq!(
        ids,
        ["px-a", "px-c", "px-d"],
        "px-b is outside the read scope"
    );
    assert_eq!(
        page.items[1].connection_state,
        ConnectionState::NeverConnected
    );
    assert_eq!(page.items[1].spool, None);

    for id in ["px-a", "px-d"] {
        let (status, body) = raw(&url, &format!("/v1/proxies/{id}")).await;
        assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
        let reply = client.get(Request::ProxyById(id.into())).await.unwrap();
        let want = without_unread(serde_json::from_slice(&body).unwrap(), true);
        assert_eq!(serde_json::to_value(&*reply).unwrap(), want, "{id}");
    }
    let Response::Proxy(a) = &*client.get(Request::ProxyById("px-a".into())).await.unwrap() else {
        panic!("not a proxy")
    };
    assert_eq!(a.central.as_ref().unwrap().ingest_stopped, Some(true));
    assert_eq!(
        a.summary.spool.as_ref().unwrap().state,
        SpoolState::Degraded
    );
    assert_eq!(a.registry.as_ref().unwrap().discarded_reports, Some(3));
    assert_eq!(
        (a.summary.desired_revision, a.summary.applied_revision),
        (Some(3), Some(2))
    );
    assert!(!a.summary.config_in_sync);
    assert_eq!(a.audit_gaps[0].kind, "event_quarantined");
    let Response::Proxy(d) = &*client.get(Request::ProxyById("px-d".into())).await.unwrap() else {
        panic!("not a proxy")
    };
    assert_eq!(d.summary.spool.as_ref().unwrap().quarantined_bytes, None);
    assert_eq!(d.central.as_ref().unwrap().ingest_stopped, None);
    assert_eq!(d.registry.as_ref().unwrap().poisoned_entries, None);

    // Outside the scope and unknown: the same bytes, and the same error.
    let (b_status, b_body) = raw(&url, "/v1/proxies/px-b").await;
    let (z_status, z_body) = raw(&url, "/v1/proxies/px-zz").await;
    assert_eq!((b_status, &b_body), (z_status, &z_body));
    assert_eq!(b_status, 404);
    for id in ["px-b", "px-zz"] {
        let err = client.get(Request::ProxyById(id.into())).await.unwrap_err();
        assert_eq!(err, FleetError::NotFound, "{id}");
    }

    // The server's cursor goes back unchanged, and works only with the filters it came from.
    let Response::Proxies(first) = &*client.get(list("", 1, "")).await.unwrap() else {
        panic!("not a proxy page")
    };
    let cursor = first.next_cursor.clone().expect("a second page");
    let Response::Proxies(second) = &*client.get(list(&cursor, 1, "")).await.unwrap() else {
        panic!("not a proxy page")
    };
    assert_eq!(second.items[0].proxy_id, "px-c");
    for (req, want) in [
        (list(&cursor, 1, "connected"), FleetError::InvalidCursor),
        (list("not-a-cursor", 1, ""), FleetError::InvalidCursor),
        (list("", 1, "asleep"), FleetError::InvalidFilter),
        (list("", 501, ""), FleetError::InvalidFilter),
    ] {
        assert_eq!(client.get(req.clone()).await.unwrap_err(), want, "{req:?}");
    }
}

#[tokio::test]
async fn a_server_without_a_proxy_section_has_no_proxy_reads() {
    let dir = temp_dir("no-proxies");
    let url = serve(&dir.0).await;
    let client = HttpClient::new(&url, READ_TOKEN, None, http::TIMEOUT).unwrap();
    for req in [list("", 0, ""), Request::ProxyById("px-a".into())] {
        let err = client.get(req.clone()).await.unwrap_err();
        assert_eq!(err, FleetError::ProxyReadsUnavailable, "{req:?}");
    }
}
