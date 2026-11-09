//! The proxy and invocation reads against a real `lodeline-server` with a proxy section, in
//! process.
//!
//! The server's proxy DTOs only serialize, so there is no server type to decode with. Instead
//! the console's body, encoded again, must equal the server's JSON minus the keys the console
//! does not read. A field the server adds, renames or drops, or an enum value the console does
//! not know, shows up as a difference here. The seed holds every lifecycle and outcome, and an
//! open and a closed gap; `every_server_enum_value_decodes` covers the other enums, and fails to
//! compile when the server adds a value.
//!
//! The TLS acceptor is replaced by a layer that sets the peer identity it would set, a
//! host-class certificate, and narrows the read scope with the server's test hook.

use std::path::Path;
use std::process::Command;
use std::sync::Arc;

use axum::extract::Request as HttpRequest;
use axum::middleware::Next;
use lodeline_proxy_api::ProxyEvent;
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
            {"upstream_id": "up2", "state": "supported"},
            {"upstream_id": "up3", "state": "unsupported", "reason": "upstream_version_unsupported"},
            {"upstream_id": "up4", "state": "disabled"}],
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

const EPOCH: &str = "11111111-1111-4111-8111-111111111111";

fn uuid(n: u32) -> String {
    format!("00000000-0000-4000-8000-{n:012}")
}

fn started(inv: u32, method: &str, tool: Option<Value>) -> (&'static str, Value) {
    let protocol = if method == "tools/call" {
        "2025-11-25"
    } else {
        "unknown"
    };
    let mut p = json!({
        "invocation_id": uuid(inv), "upstream_id": "up1", "route_revision": 1,
        "protocol_version": protocol, "method": method,
        "actor": {"actor_id": "actor-1", "actor_kind": "non_human",
            "authentication_method": "bearer", "evidence_source": "proxy_credential_mapping"},
    });
    if let Some(t) = tool {
        p["tool"] = t;
    }
    ("invocation.started", p)
}

fn completed(inv: u32, outcome: &str, delivery: &str) -> (&'static str, Value) {
    let p = json!({"invocation_id": uuid(inv), "outcome": outcome, "delivery_state": delivery,
        "duration_ms": 12, "response_bytes": 34});
    ("invocation.completed", p)
}

fn cancelled(inv: u32) -> (&'static str, Value) {
    let p = json!({"invocation_id": uuid(inv)});
    ("invocation.cancel_requested", p)
}

/// `payloads` as one proxy's events, numbered from sequence 1, with event IDs from `first_id`.
fn events(proxy: &str, first_id: u32, payloads: Vec<(&str, Value)>) -> Vec<ProxyEvent> {
    let mut seq = 0;
    payloads
        .into_iter()
        .map(|(event_type, payload)| {
            seq += 1;
            let v = json!({
                "schema_version": 1, "event_id": uuid(first_id + seq), "proxy_id": proxy,
                "epoch_id": EPOCH, "sequence": seq,
                "occurred_at": format!("2026-11-09T00:{:02}:{:02}Z", seq / 60, seq % 60),
                "event_type": event_type, "payload": payload,
            });
            lodeline_proxy_api::parse_event(v.to_string().as_bytes()).unwrap()
        })
        .collect()
}

/// px-a's invocations: 1 started, 2 to 7 completed with each outcome, 8 a completion without its
/// start, 9 a cancel without a start, 10 a success that contradicts its malformed start, and 11
/// a ping with 32 cancels, more events than a detail lists.
fn seed_invocations(ctx: &ProxyContext) {
    let ident = json!({"status": "identified",
        "metadata_ref": "00000000-0000-8000-8000-000000000001"});
    let mut a = vec![started(1, "tools/list", None)];
    let outcomes = [
        ("success", "sent"),
        ("tool_error", "sent"),
        ("protocol_error", "not_sent"),
        ("timeout", "unknown"),
        ("unknown", "unknown"),
        ("denied", "not_sent"),
    ];
    for (inv, (outcome, delivery)) in (2..).zip(outcomes) {
        a.push(started(inv, "tools/call", Some(ident.clone())));
        a.push(completed(inv, outcome, delivery));
    }
    a.push(completed(8, "success", "sent"));
    a.push(cancelled(9));
    let malformed = json!({"status": "unavailable", "reason": "malformed"});
    a.push(started(10, "tools/call", Some(malformed)));
    a.push(completed(10, "success", "sent"));
    a.push(started(11, "ping", None));
    a.extend((0..32).map(|_| cancelled(11)));
    let mut a = events("px-a", 100, a);
    let now = chrono::Utc::now().timestamp();
    // Sequence 2 arrives last, so the server opens a sequence gap and then closes it.
    let late = a.remove(1);
    ctx.ledger.insert_batch("px-a", &a, now).unwrap();
    ctx.ledger.insert_batch("px-a", &[late], now).unwrap();
    for (proxy, first_id, inv) in [("px-b", 200, 12), ("px-d", 300, 13)] {
        let e = events(proxy, first_id, vec![started(inv, "ping", None)]);
        ctx.ledger.insert_batch(proxy, &e, now).unwrap();
    }
}

/// A server with px-a (current proxy), px-b (outside the read scope), px-c (registered, never
/// connected) and px-d (an older proxy), and the invocations of `seed_invocations`.
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
    seed_invocations(&ctx);
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

/// An invocation body without the reserved `decision`, which the console does not read.
fn without_decision(mut v: Value) -> Value {
    v.as_object_mut().unwrap().remove("decision");
    v
}

fn invocations(cursor: &str, limit: i64, proxy_id: &str, lifecycle: &str) -> Request {
    Request::Invocations(InvocationsParams {
        cursor: cursor.into(),
        limit,
        proxy_id: proxy_id.into(),
        lifecycle: lifecycle.into(),
        ..Default::default()
    })
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
    let gaps: Vec<_> = a
        .audit_gaps
        .iter()
        .map(|g| (g.kind.as_str(), g.state))
        .collect();
    assert!(
        gaps.contains(&("event_quarantined", GapState::Open)),
        "{gaps:?}"
    );
    assert!(
        gaps.contains(&("sequence_gap", GapState::Closed)),
        "{gaps:?}"
    );
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
async fn the_http_client_reads_the_invocation_routes_of_a_real_server() {
    let dir = temp_dir("invocations");
    let url = serve_with_proxies(&dir.0).await;
    let client = HttpClient::new(&url, READ_TOKEN, None, http::TIMEOUT).unwrap();

    let (status, body) = raw(&url, "/v1/proxy-invocations").await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    let Response::Invocations(page) = &*client.get(invocations("", 0, "", "")).await.unwrap()
    else {
        panic!("not an invocation page")
    };
    let mut want: Value = serde_json::from_slice(&body).unwrap();
    for item in want["items"].as_array_mut().unwrap() {
        *item = without_decision(item.take());
    }
    assert_eq!(serde_json::to_value(page).unwrap(), want);
    assert_eq!(page.next_cursor, None);
    assert!(
        page.items.iter().all(|i| i.proxy_id != "px-b"),
        "px-b is outside the read scope"
    );
    let lifecycles: Vec<_> = page.items.iter().map(|i| i.lifecycle).collect();
    let outcomes: Vec<_> = page.items.iter().filter_map(|i| i.outcome).collect();
    for l in [
        Lifecycle::Started,
        Lifecycle::Completed,
        Lifecycle::CompletionWithoutStart,
        Lifecycle::CancelWithoutStart,
        Lifecycle::IntegrityConflict,
    ] {
        assert!(lifecycles.contains(&l), "the seed has {l:?}");
    }
    for o in [
        Outcome::Success,
        Outcome::ToolError,
        Outcome::ProtocolError,
        Outcome::Timeout,
        Outcome::Unknown,
        Outcome::Denied,
    ] {
        assert!(outcomes.contains(&o), "the seed has {o:?}");
    }

    for item in &page.items {
        let id = &item.invocation_id;
        let (status, body) = raw(&url, &format!("/v1/proxy-invocations/{id}")).await;
        assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
        let reply = client
            .get(Request::InvocationById(id.clone()))
            .await
            .unwrap();
        let want = without_decision(serde_json::from_slice(&body).unwrap());
        assert_eq!(serde_json::to_value(&*reply).unwrap(), want, "{id}");
    }
    let detail = |n| {
        let c = &client;
        async move {
            match &*c.get(Request::InvocationById(uuid(n))).await.unwrap() {
                Response::Invocation(d) => d.clone(),
                other => panic!("not an invocation: {other:?}"),
            }
        }
    };
    let without_start = detail(8).await.invocation;
    assert_eq!(
        (without_start.lifecycle, without_start.outcome),
        (Lifecycle::CompletionWithoutStart, None)
    );
    assert_eq!(without_start.reported_outcome, Some(Outcome::Success));
    let conflict = detail(10).await.invocation;
    assert_eq!(
        (conflict.lifecycle, conflict.outcome),
        (Lifecycle::IntegrityConflict, None)
    );
    assert_eq!(conflict.reported_outcome, Some(Outcome::Success));
    assert_eq!(conflict.flags, ["completion_contradicts_start"]);
    let many = detail(11).await;
    assert_eq!(
        (many.events_total, many.events_truncated, many.events.len()),
        (33, true, 32)
    );

    // Outside the scope, unknown, and not a UUID: the same bytes, and the same error.
    let (b_status, b_body) = raw(&url, &format!("/v1/proxy-invocations/{}", uuid(12))).await;
    let (z_status, z_body) = raw(&url, &format!("/v1/proxy-invocations/{}", uuid(99))).await;
    assert_eq!((b_status, &b_body), (z_status, &z_body));
    assert_eq!(b_status, 404);
    for id in [uuid(12), uuid(99), "not-a-uuid".into()] {
        let err = client.get(Request::InvocationById(id.clone())).await;
        assert_eq!(err.unwrap_err(), FleetError::NotFound, "{id}");
    }

    // A proxy filter outside the scope reads as an unknown proxy: an empty list.
    for (proxy, want) in [("px-b", 0), ("px-zz", 0), ("px-d", 1)] {
        let reply = client.get(invocations("", 0, proxy, "")).await.unwrap();
        let Response::Invocations(p) = &*reply else {
            panic!("not an invocation page")
        };
        assert_eq!(p.items.len(), want, "{proxy}");
    }

    // The server's cursor goes back unchanged, and works only with the filters it came from.
    let Response::Invocations(first) = &*client.get(invocations("", 2, "px-a", "")).await.unwrap()
    else {
        panic!("not an invocation page")
    };
    let cursor = first.next_cursor.clone().expect("a second page");
    let Response::Invocations(second) = &*client
        .get(invocations(&cursor, 2, "px-a", ""))
        .await
        .unwrap()
    else {
        panic!("not an invocation page")
    };
    assert_eq!(second.items.len(), 2);
    assert!(second.items.iter().all(|i| first
        .items
        .iter()
        .all(|f| f.invocation_id != i.invocation_id)));
    for (req, want) in [
        (
            invocations(&cursor, 2, "px-a", "completed"),
            FleetError::InvalidCursor,
        ),
        (invocations(&cursor, 2, "", ""), FleetError::InvalidCursor),
        (
            invocations("not-a-cursor", 2, "", ""),
            FleetError::InvalidCursor,
        ),
        (invocations("", 2, "", "asleep"), FleetError::InvalidFilter),
        (invocations("", 501, "", ""), FleetError::InvalidFilter),
    ] {
        assert_eq!(client.get(req.clone()).await.unwrap_err(), want, "{req:?}");
    }
}

/// Each value of the server's enums decodes to the console's matching value, never `unknown`.
/// The matches have no wildcard, so a value the server adds fails to compile here.
#[test]
fn every_server_enum_value_decodes() {
    use lodeline_proxy_api::event::Outcome as SOutcome;
    use lodeline_proxy_api::status::{
        ConfigState as SConfig, RouteState as SRoute, SpoolState as SSpool,
    };
    use lodeline_server::proxy::projection::Lifecycle as SLifecycle;
    use lodeline_server::proxy::query::ConnectionState as SConnection;

    fn decodes<S: Serialize, C: serde::de::DeserializeOwned + PartialEq + std::fmt::Debug>(
        server: S,
        console: C,
    ) {
        let wire = serde_json::to_value(server).unwrap();
        assert_eq!(
            serde_json::from_value::<C>(wire.clone()).unwrap(),
            console,
            "{wire}"
        );
    }
    for v in [
        SConnection::Connected,
        SConnection::Disconnected,
        SConnection::NeverConnected,
    ] {
        decodes(
            v,
            match v {
                SConnection::Connected => ConnectionState::Connected,
                SConnection::Disconnected => ConnectionState::Disconnected,
                SConnection::NeverConnected => ConnectionState::NeverConnected,
            },
        );
    }
    for v in [
        SConfig::None,
        SConfig::Valid,
        SConfig::Expired,
        SConfig::Disabled,
    ] {
        decodes(
            v,
            match v {
                SConfig::None => ConfigState::None,
                SConfig::Valid => ConfigState::Valid,
                SConfig::Expired => ConfigState::Expired,
                SConfig::Disabled => ConfigState::Disabled,
            },
        );
    }
    for v in [SSpool::Ok, SSpool::Degraded, SSpool::Full] {
        decodes(
            v,
            match v {
                SSpool::Ok => SpoolState::Ok,
                SSpool::Degraded => SpoolState::Degraded,
                SSpool::Full => SpoolState::Full,
            },
        );
    }
    for v in [
        SRoute::Supported,
        SRoute::Degraded,
        SRoute::Unsupported,
        SRoute::Disabled,
    ] {
        decodes(
            v,
            match v {
                SRoute::Supported => RouteState::Supported,
                SRoute::Degraded => RouteState::Degraded,
                SRoute::Unsupported => RouteState::Unsupported,
                SRoute::Disabled => RouteState::Disabled,
            },
        );
    }
    for v in [
        SLifecycle::Started,
        SLifecycle::Completed,
        SLifecycle::CompletionWithoutStart,
        SLifecycle::CancelWithoutStart,
        SLifecycle::IntegrityConflict,
    ] {
        decodes(
            v.as_str(),
            match v {
                SLifecycle::Started => Lifecycle::Started,
                SLifecycle::Completed => Lifecycle::Completed,
                SLifecycle::CompletionWithoutStart => Lifecycle::CompletionWithoutStart,
                SLifecycle::CancelWithoutStart => Lifecycle::CancelWithoutStart,
                SLifecycle::IntegrityConflict => Lifecycle::IntegrityConflict,
            },
        );
    }
    for v in [
        SOutcome::Success,
        SOutcome::ToolError,
        SOutcome::ProtocolError,
        SOutcome::Timeout,
        SOutcome::Unknown,
        SOutcome::Denied,
    ] {
        decodes(
            v,
            match v {
                SOutcome::Success => Outcome::Success,
                SOutcome::ToolError => Outcome::ToolError,
                SOutcome::ProtocolError => Outcome::ProtocolError,
                SOutcome::Timeout => Outcome::Timeout,
                SOutcome::Unknown => Outcome::Unknown,
                SOutcome::Denied => Outcome::Denied,
            },
        );
    }
}

#[tokio::test]
async fn a_server_without_a_proxy_section_has_no_proxy_reads() {
    let dir = temp_dir("no-proxies");
    let url = serve(&dir.0).await;
    let client = HttpClient::new(&url, READ_TOKEN, None, http::TIMEOUT).unwrap();
    for req in [
        list("", 0, ""),
        Request::ProxyById("px-a".into()),
        invocations("", 0, "", ""),
        Request::InvocationById(uuid(1)),
    ] {
        let err = client.get(req.clone()).await.unwrap_err();
        assert_eq!(err, FleetError::ProxyReadsUnavailable, "{req:?}");
    }
}
