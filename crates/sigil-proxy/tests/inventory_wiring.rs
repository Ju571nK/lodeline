#![cfg(unix)]
//! T-13c (#312): the relay's `tools/list` observations reach the inventory engine
//! (`InventorySink`), and the registry-conflict path rewrites the spool
//! (`SpoolConflictHandler`, `CheckedSource`). The production wiring in
//! `lifecycle.rs` is covered end to end by `sigil-proxy-e2e/tests/inventory_e2e.rs`.

use std::collections::HashSet;
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use serde_json::{json, Value};
use sigil_proxy::ingest_client::EventSource;
use sigil_proxy::inventory::{CursorHasher, InventoryEngine, InventoryLimits};
use sigil_proxy::inventory_sink::{InventoryHandle, InventorySink, RouteScopes};
use sigil_proxy::limits::Limits;
use sigil_proxy::mcp::observation::{
    CallRef, Cause, Completed, Delivery, Method, NextCursor, Observation, ObservationSink, Outcome,
    PageUnavailable, RequestStarted, ToolDescriptor, ToolListCapture, ToolListPage,
};
use sigil_proxy::mcp::{RequestId, ToolField, ToolName};
use sigil_proxy::registry_client::{
    with_ingest_stall, CheckedSource, ConflictReporter, SpoolConflictHandler,
};
use sigil_proxy::registry_key::ScopeKey;
use sigil_proxy::registry_store::{RegistryStore, ToolLookup};
use sigil_proxy::spool::{Spool, SpoolConfig};
use sigil_proxy::status_report::{GapQueue, RegistryProbe, RegistrySnapshot};
use sigil_proxy_api::{GapReport, ProxyEvent};

const EPOCH: &str = "0f0f0f0f-1111-4222-8333-444444444444";

fn dir() -> tempfile::TempDir {
    let d = tempfile::tempdir().unwrap();
    std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    d
}

fn scope() -> ScopeKey {
    ScopeKey::live("px-1", "up-1", "cs-1")
}

struct Rig {
    sink: Arc<InventorySink>,
    handle: InventoryHandle,
    store: RegistryStore,
    _d: tempfile::TempDir,
    seq: u64,
}

fn rig() -> Rig {
    let d = dir();
    let (store, _) = RegistryStore::open(d.path(), "px-1").unwrap();
    let engine = InventoryEngine::new(store.clone(), EPOCH, InventoryLimits::default());
    let scopes = RouteScopes::new();
    scopes.replace([("r1".to_string(), "up-1".to_string(), "cs-1".to_string())]);
    let (sink, handle) =
        InventorySink::start(engine, CursorHasher::new().unwrap(), scopes, "px-1").unwrap();
    Rig {
        sink,
        handle,
        store,
        _d: d,
        seq: 0,
    }
}

fn tool(name: &str, desc: &str) -> ToolDescriptor {
    ToolDescriptor {
        name: ToolName::parse(name).unwrap(),
        definition: json!({"name": name, "description": desc,
                           "inputSchema": {"type": "object"}})
        .to_string()
        .into(),
    }
}

impl Rig {
    /// One `tools/list` call through the sink: its start, then its completion.
    async fn call(&mut self, principal: &str, cursor: bool, capture: Option<ToolListCapture>) {
        self.call_cause(principal, cursor, capture, Cause::None)
            .await
    }

    async fn call_cause(
        &mut self,
        principal: &str,
        cursor: bool,
        capture: Option<ToolListCapture>,
        cause: Cause,
    ) {
        self.seq += 1;
        let call = CallRef {
            seq: self.seq,
            route_id: "r1".into(),
            principal_id: principal.into(),
        };
        let id = RequestId::from_raw("1").unwrap();
        let started = RequestStarted {
            call: call.clone(),
            method: Method::ToolsList,
            request_id: id.clone(),
            tool: ToolField::NotApplicable,
            list_cursor: cursor,
            task_augmented: false,
            request_bytes: 10,
            received_at: SystemTime::now(),
        };
        self.sink.request_started(&started).await;
        self.sink.observe(Observation::Completed(Completed {
            call,
            method: Method::ToolsList,
            request_id: id,
            outcome: Outcome::Success,
            delivery: Delivery::Sent,
            cause,
            http_status: Some(200),
            response_bytes: 10,
            duration: Duration::from_millis(1),
            completed_at: SystemTime::now(),
            cancel_requested: false,
            tool_list: capture,
        }));
    }

    fn page(tools: Vec<ToolDescriptor>, next: Option<&str>) -> Option<ToolListCapture> {
        Some(ToolListCapture::Page(ToolListPage {
            tools,
            next_cursor: next.map(|n| NextCursor::new(n).unwrap()),
        }))
    }

    /// Drain the worker; the open chains end as `session_ended`.
    async fn finish(self) -> (RegistryStore, tempfile::TempDir) {
        self.handle.shutdown().await;
        (self.store, self._d)
    }
}

fn reports(store: &RegistryStore) -> Vec<Value> {
    store
        .pending_reports(100)
        .unwrap()
        .iter()
        .map(|r| serde_json::from_slice(&r.body).unwrap())
        .collect()
}

#[tokio::test]
async fn a_paginated_listing_through_the_sink_commits_a_baseline_snapshot() {
    let mut r = rig();
    r.call(
        "pr",
        false,
        Rig::page(vec![tool("a", "1"), tool("b", "2")], Some("CURSOR-1")),
    )
    .await;
    r.call("pr", true, Rig::page(vec![tool("c", "3")], None))
        .await;
    let (store, _d) = r.finish().await;
    let snap = store.latest_snapshot(&scope()).unwrap().expect("snapshot");
    let mut names: Vec<_> = snap.members.iter().map(|(_, n)| n.clone()).collect();
    names.sort();
    assert_eq!(names, vec!["a", "b", "c"]);
    let rep = reports(&store);
    assert_eq!(rep.len(), 1);
    assert_eq!(rep[0]["completeness"], "complete");
    assert_eq!(rep[0]["comparison"]["kind"], "initial_baseline");
    assert!(matches!(
        store.lookup_tool(&scope(), "b").unwrap(),
        ToolLookup::Found(_)
    ));
}

#[tokio::test]
async fn a_changed_listing_is_reported_as_drift() {
    let mut r = rig();
    r.call("pr", false, Rig::page(vec![tool("a", "1")], None))
        .await;
    r.call("pr", false, Rig::page(vec![tool("a", "CHANGED")], None))
        .await;
    let (store, _d) = r.finish().await;
    let rep = reports(&store);
    assert_eq!(rep.len(), 2);
    assert_eq!(rep[1]["comparison"]["kind"], "compared");
    assert_eq!(rep[1]["comparison"]["changes"][0]["change"], "changed");
}

fn incomplete_reason(store: &RegistryStore) -> Vec<String> {
    reports(store)
        .iter()
        .filter(|r| r["completeness"] == "incomplete")
        .map(|r| r["incomplete_reason"].as_str().unwrap().to_string())
        .collect()
}

#[tokio::test]
async fn relay_page_errors_map_to_incomplete_reasons() {
    let cases = [
        (PageUnavailable::NoSuccess, "page_error"),
        (PageUnavailable::Unobservable, "page_error"),
        (PageUnavailable::Unparseable, "page_error"),
        (PageUnavailable::TooLarge, "size_limit_exceeded"),
        (PageUnavailable::TooManyTools, "tool_limit_exceeded"),
        (PageUnavailable::CursorInvalid, "cursor_invalid"),
    ];
    for (u, want) in cases {
        let mut r = rig();
        r.call("pr", false, Some(ToolListCapture::Unavailable(u)))
            .await;
        let (store, _d) = r.finish().await;
        assert_eq!(incomplete_reason(&store), vec![want], "{u:?}");
        assert!(store.latest_snapshot(&scope()).unwrap().is_none());
    }
}

#[tokio::test]
async fn a_call_without_a_capture_is_a_page_error_or_access_denied() {
    let mut r = rig();
    r.call("pr", false, None).await;
    let (store, _d) = r.finish().await;
    assert_eq!(incomplete_reason(&store), vec!["page_error"]);

    let mut r = rig();
    r.call_cause("pr", false, None, Cause::UpstreamAuthRejected)
        .await;
    let (store, _d) = r.finish().await;
    assert_eq!(incomplete_reason(&store), vec!["access_denied"]);
}

#[tokio::test]
async fn a_failed_page_leaves_the_latest_snapshot_in_place() {
    let mut r = rig();
    r.call("pr", false, Rig::page(vec![tool("a", "1")], None))
        .await;
    r.call(
        "pr",
        false,
        Some(ToolListCapture::Unavailable(PageUnavailable::NoSuccess)),
    )
    .await;
    let (store, _d) = r.finish().await;
    assert_eq!(
        store
            .latest_snapshot(&scope())
            .unwrap()
            .unwrap()
            .members
            .len(),
        1
    );
    assert_eq!(incomplete_reason(&store), vec!["page_error"]);
}

#[tokio::test]
async fn a_continuation_without_a_chain_start_is_cursor_invalid() {
    let mut r = rig();
    r.call("pr", true, Rig::page(vec![tool("a", "1")], None))
        .await;
    let (store, _d) = r.finish().await;
    assert_eq!(incomplete_reason(&store), vec!["cursor_invalid"]);
    assert!(store.latest_snapshot(&scope()).unwrap().is_none());
}

#[tokio::test]
async fn session_end_closes_an_unfinished_chain() {
    let mut r = rig();
    r.call("pr", false, Rig::page(vec![tool("a", "1")], Some("C")))
        .await;
    r.sink.end_session("pr");
    // The worker is ordered: shutdown drains behind the session end.
    let (store, _d) = r.finish().await;
    // Exactly one report: the chain was closed once (by the session end), not
    // again by the shutdown.
    assert_eq!(incomplete_reason(&store), vec!["session_ended"]);
}

#[tokio::test]
async fn shutdown_closes_every_open_chain() {
    let mut r = rig();
    r.call("p1", false, Rig::page(vec![tool("a", "1")], Some("C")))
        .await;
    r.call("p2", false, Rig::page(vec![tool("a", "1")], Some("C")))
        .await;
    let (store, _d) = r.finish().await;
    assert_eq!(
        incomplete_reason(&store),
        vec!["session_ended", "session_ended"]
    );
}

#[tokio::test]
async fn principals_do_not_share_a_chain() {
    let mut r = rig();
    r.call("p1", false, Rig::page(vec![tool("a", "1")], Some("C")))
        .await;
    // p2's continuation has no chain of its own.
    r.call("p2", true, Rig::page(vec![tool("a", "1")], None))
        .await;
    let (store, _d) = r.finish().await;
    let reasons = incomplete_reason(&store);
    assert!(
        reasons.contains(&"cursor_invalid".to_string()),
        "{reasons:?}"
    );
    assert!(store.latest_snapshot(&scope()).unwrap().is_none());
}

#[tokio::test]
async fn a_route_without_a_known_scope_is_ignored() {
    let mut r = rig();
    r.seq += 1;
    let call = CallRef {
        seq: r.seq,
        route_id: "unknown-route".into(),
        principal_id: "pr".into(),
    };
    r.sink.observe(Observation::Completed(Completed {
        call,
        method: Method::ToolsList,
        request_id: RequestId::from_raw("1").unwrap(),
        outcome: Outcome::Success,
        delivery: Delivery::Sent,
        cause: Cause::None,
        http_status: Some(200),
        response_bytes: 1,
        duration: Duration::from_millis(1),
        completed_at: SystemTime::now(),
        cancel_requested: false,
        tool_list: Rig::page(vec![tool("a", "1")], None),
    }));
    let (store, _d) = r.finish().await;
    assert!(reports(&store).is_empty());
}

#[tokio::test]
async fn the_sink_prints_no_content() {
    let r = rig();
    let s = format!("{:?} {:?}", r.sink, tool("SECRET-TOOL", "SECRET-DESC"));
    assert!(!s.contains("SECRET"), "{s}");
    r.handle.shutdown().await;
}

// ------------------------------------------------------------- the stall flag

#[test]
fn sync_stalled_is_the_registry_sync_or_the_ingest_holds() {
    let snap = |stalled| RegistrySnapshot {
        pending_entries: 3,
        sync_stalled: stalled,
        ..Default::default()
    };
    let flag = Arc::new(AtomicBool::new(false));
    let inner: RegistryProbe = Arc::new(move || Some(snap(false)));
    let p = with_ingest_stall(inner, flag.clone());
    assert!(!p().unwrap().sync_stalled);
    flag.store(true, Ordering::Relaxed);
    let got = p().unwrap();
    assert!(got.sync_stalled);
    assert_eq!(got.pending_entries, 3);
    // The registry's own stall stays.
    flag.store(false, Ordering::Relaxed);
    let p2 = with_ingest_stall(Arc::new(move || Some(snap(true))), flag);
    assert!(p2().unwrap().sync_stalled);
    // An unreadable registry stays unreadable.
    let p3 = with_ingest_stall(Arc::new(|| None), Arc::new(AtomicBool::new(true)));
    assert!(p3().is_none());
}

// ---------------------------------------------------- the registry-conflict path

fn mref(n: u32) -> String {
    format!("00000000-0000-8000-8000-{n:012}")
}

fn uid(n: u32) -> String {
    format!("00000000-0000-4000-8000-{n:012x}")
}

fn call_event(n: u32, m: &str) -> ProxyEvent {
    serde_json::from_value(json!({
        "schema_version": 1, "event_id": uid(n), "proxy_id": "px-1",
        "epoch_id": EPOCH, "sequence": 1,
        "occurred_at": "2026-10-14T00:00:00Z",
        "event_type": "invocation.started",
        "payload": {"invocation_id": uid(7000 + n), "upstream_id": "up-1",
            "route_revision": 1, "protocol_version": "2025-11-25", "method": "tools/call",
            "actor": {"actor_id": "a1", "actor_kind": "non_human",
                "authentication_method": "bearer",
                "evidence_source": "proxy_credential_mapping"},
            "tool": {"status": "identified", "metadata_ref": m}}
    }))
    .unwrap()
}

struct Conflict {
    spool: Spool,
    store: RegistryStore,
    gaps: GapQueue,
    reporter: ConflictReporter,
    refs: Vec<String>,
    d: tempfile::TempDir,
}

/// A registry with two ACKed entries and a spool with one unsent start for each
/// and one for an unrelated ref.
async fn conflict_rig() -> Conflict {
    let d = dir();
    let (store, _) = RegistryStore::open(d.path(), "px-1").unwrap();
    let mut engine = InventoryEngine::new(store.clone(), EPOCH, InventoryLimits::default());
    let key = sigil_proxy::inventory::ListingKey {
        session: 1,
        scope: scope(),
    };
    let t = |n: &str| sigil_proxy::inventory::ToolInput {
        name: n.into(),
        definition: json!({"name": n, "inputSchema": {"type": "object"}}).to_string(),
    };
    let progress = engine
        .observe_page(
            &key,
            sigil_proxy::inventory::PageInput::Tools {
                request_cursor: None,
                tools: vec![t("a"), t("b")],
                next_cursor: None,
            },
        )
        .unwrap();
    let sigil_proxy::inventory::ListingProgress::Complete(c) = progress else {
        panic!("{progress:?}")
    };
    let refs: Vec<String> = c.tools.iter().map(|(_, r)| r.clone()).collect();
    store.mark_acked(&refs).unwrap();
    let sd = tempfile::tempdir().unwrap();
    let spool = Spool::open(SpoolConfig::new(
        sd.path(),
        "px-1",
        EPOCH,
        true,
        &Limits::default(),
    ))
    .unwrap();
    spool.append_async(call_event(1, &refs[0])).await.unwrap();
    spool.append_async(call_event(2, &refs[1])).await.unwrap();
    spool.append_async(call_event(3, &mref(77))).await.unwrap();
    let gaps = GapQueue::new();
    let reporter = ConflictReporter::new(
        store.clone(),
        gaps.clone(),
        Box::new(SpoolConflictHandler::new(spool.clone())),
    );
    std::mem::forget(sd);
    Conflict {
        spool,
        store,
        gaps,
        reporter,
        refs,
        d,
    }
}

fn tool_of(e: &ProxyEvent) -> Value {
    serde_json::to_value(e).unwrap()["payload"]["tool"].clone()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_conflict_rewrites_the_dependent_starts_and_names_them_in_the_gap() {
    let c = conflict_rig().await;
    let r = c.reporter.clone();
    let mref0 = c.refs[0].clone();
    let n = tokio::task::spawn_blocking(move || {
        r.report_conflict(
            &mref0,
            sigil_proxy_api::status::ConflictDetector::Central409,
        )
        .unwrap()
    })
    .await
    .unwrap();
    assert_eq!(n, 1);
    let mut s = c.spool.clone();
    let got = s.next_events_async(10, &HashSet::new()).await;
    assert_eq!(got.len(), 3);
    assert_eq!(
        tool_of(&got[0]),
        json!({"status": "metadata_unavailable", "reason": "registry_conflict"})
    );
    // Other refs are untouched.
    assert_eq!(tool_of(&got[1])["status"], "identified");
    assert_eq!(tool_of(&got[2])["status"], "identified");
    let gaps = c.gaps.pending_batch();
    let GapReport::RegistryConflict(g) = &gaps[0] else {
        panic!("{gaps:?}")
    };
    assert_eq!(g.event_ids[0].as_str(), uid(1));
    let _ = (&c.store, &c.d);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_checked_source_catches_a_tampered_entry_before_events_are_sent() {
    let c = conflict_rig().await;
    // The local registry file is edited behind the proxy's back.
    let conn = rusqlite::Connection::open(c.d.path().join("registry.sqlite3")).unwrap();
    conn.execute(
        "UPDATE entries SET fingerprint = ?1 WHERE metadata_ref = ?2",
        rusqlite::params!["0".repeat(64), c.refs[0]],
    )
    .unwrap();
    drop(conn);
    let mut src = CheckedSource::new(c.spool.clone(), c.reporter.clone());
    let got = src.next_events_async(10, &HashSet::new()).await;
    assert_eq!(got.len(), 3);
    // The tampered ref never leaves: its start went out rewritten.
    assert_eq!(tool_of(&got[0])["status"], "metadata_unavailable");
    assert_eq!(tool_of(&got[1])["status"], "identified");
    let gaps = c.gaps.pending_batch();
    let GapReport::RegistryConflict(g) = &gaps[0] else {
        panic!("{gaps:?}")
    };
    assert_eq!(
        g.detected_by,
        sigil_proxy_api::status::ConflictDetector::LocalHashCheck
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn events_appended_after_a_conflict_do_not_carry_the_quarantined_ref() {
    let c = conflict_rig().await;
    let r = c.reporter.clone();
    let mref0 = c.refs[0].clone();
    tokio::task::spawn_blocking(move || {
        r.report_conflict(
            &mref0,
            sigil_proxy_api::status::ConflictDetector::Central409,
        )
        .unwrap()
    })
    .await
    .unwrap();
    // A later start that still names the quarantined entry.
    c.spool
        .append_async(call_event(9, &c.refs[0]))
        .await
        .unwrap();
    let mut src = CheckedSource::new(c.spool.clone(), c.reporter.clone());
    let got = src.next_events_async(10, &HashSet::new()).await;
    assert_eq!(got.len(), 4);
    for e in &got {
        assert_ne!(
            tool_of(e),
            json!({"status": "identified", "metadata_ref": c.refs[0]})
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_checked_source_passes_clean_batches_through() {
    let c = conflict_rig().await;
    let mut src = CheckedSource::new(c.spool.clone(), c.reporter.clone());
    let got = src.next_events_async(10, &HashSet::new()).await;
    assert_eq!(got.len(), 3);
    assert!(got.iter().all(|e| tool_of(e)["status"] == "identified"));
    assert!(c.gaps.pending_batch().is_empty());
}
