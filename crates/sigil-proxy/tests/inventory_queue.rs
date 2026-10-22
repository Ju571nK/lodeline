#![cfg(all(unix, feature = "test-util"))]
//! T-13c (#312): a full observation queue drops pages, and a dropped page can
//! only make a listing incomplete, never complete. Needs the worker pause knob
//! (`test-util`).

use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, SystemTime};

use serde_json::{json, Value};
use sigil_proxy::inventory::{CursorHasher, InventoryEngine, InventoryLimits};
use sigil_proxy::inventory_sink::{InventorySink, RouteScopes, QUEUE_DEPTH};
use sigil_proxy::mcp::observation::{
    CallRef, Cause, Completed, Delivery, Method, NextCursor, Observation, ObservationSink, Outcome,
    RequestStarted, ToolDescriptor, ToolListCapture, ToolListPage,
};
use sigil_proxy::mcp::{RequestId, ToolField, ToolName};
use sigil_proxy::registry_key::ScopeKey;
use sigil_proxy::registry_store::RegistryStore;

const EPOCH: &str = "0f0f0f0f-1111-4222-8333-444444444444";

fn page(name: &str, next: Option<&str>) -> Option<ToolListCapture> {
    Some(ToolListCapture::Page(ToolListPage {
        tools: vec![ToolDescriptor {
            name: ToolName::parse(name).unwrap(),
            definition: json!({"name": name, "inputSchema": {"type": "object"}})
                .to_string()
                .into(),
        }],
        next_cursor: next.map(|n| NextCursor::new(n).unwrap()),
    }))
}

#[tokio::test]
async fn a_dropped_page_never_makes_a_listing_complete() {
    let d = tempfile::tempdir().unwrap();
    std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let (store, _) = RegistryStore::open(d.path(), "px-1").unwrap();
    let engine = InventoryEngine::new(store.clone(), EPOCH, InventoryLimits::default());
    let scopes = RouteScopes::new();
    scopes.replace([("r1".to_string(), "up-1".to_string(), "cs-1".to_string())]);
    let hasher = CursorHasher::new().unwrap();
    let (sink, handle) = InventorySink::start(engine, hasher.clone(), scopes, "px-1").unwrap();

    let mut seq = 0u64;
    let mut send = |principal: &str, cursor: Option<&str>, capture| {
        seq += 1;
        let call = CallRef {
            seq,
            route_id: "r1".into(),
            principal_id: principal.into(),
        };
        let id = RequestId::from_raw("1").unwrap();
        let started = RequestStarted {
            call: call.clone(),
            method: Method::ToolsList,
            request_id: id.clone(),
            tool: ToolField::NotApplicable,
            list_cursor: cursor.map(|c| hasher.tag(c)),
            task_augmented: false,
            request_bytes: 1,
            received_at: SystemTime::now(),
        };
        drop(sink.request_started(&started));
        sink.observe(Observation::Completed(Completed {
            call,
            method: Method::ToolsList,
            request_id: id,
            outcome: Outcome::Success,
            delivery: Delivery::Sent,
            cause: Cause::None,
            http_status: Some(200),
            response_bytes: 1,
            duration: Duration::from_millis(1),
            completed_at: SystemTime::now(),
            cancel_requested: false,
            tool_list: capture,
        }));
    };

    // Page 1 is queued, then the worker stalls and the queue fills up with other
    // principals' pages, so the page that would complete the listing is dropped.
    sink.pause_worker_for_test(true);
    send("pr", None, page("a", Some("C1")));
    // The worker may already hold page 1 (paused on its next message): one slot
    // more than the queue depth is needed at most.
    for i in 0..(QUEUE_DEPTH + 2) {
        send(&format!("filler{i}"), None, page("f", Some("F")));
    }
    send("pr", Some("C1"), page("b", None));
    assert!(sink.dropped_pages() > 0, "the queue overflowed");
    sink.pause_worker_for_test(false);
    handle.shutdown().await;

    let reports: Vec<Value> = store
        .pending_reports(1000)
        .unwrap()
        .iter()
        .map(|r| serde_json::from_slice(&r.body).unwrap())
        .collect();
    assert!(
        reports.iter().all(|r| r["completeness"] == "incomplete"),
        "no listing may be complete"
    );
    assert!(store
        .latest_snapshot(&ScopeKey::live("px-1", "up-1", "cs-1"))
        .unwrap()
        .is_none());
}
