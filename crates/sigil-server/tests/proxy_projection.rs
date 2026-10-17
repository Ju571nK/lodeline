//! T-11 S5 slice A — projection (L2), schema v2 + migration, invocation-granular
//! sweep, tail gaps (L4/F13) and the ledger read API (L3). No HTTP here.

use serde_json::{json, Value};
use sigil_proxy_api::{canonical_event_bytes, parse_event, ProxyEvent};
use sigil_server::proxy::ledger::{GapKind, Ledger, LedgerError, LedgerOptions, SCHEMA_VERSION};
use sigil_server::proxy::projection::{
    project, Flag, InvocationFilter, Lifecycle, Projection, ProjectionInput, TailGapChange,
    TimeBasis, ToolInfo,
};
use std::path::Path;

const EP1: &str = "11111111-1111-4111-8111-111111111111";
const EP2: &str = "22222222-2222-4222-8222-222222222222";

fn uuid(n: u32) -> String {
    format!("00000000-0000-4000-8000-{n:012}")
}

fn mref(n: u32) -> String {
    format!("00000000-0000-8000-8000-{n:012}")
}

fn envelope(
    proxy: &str,
    epoch: &str,
    seq: i64,
    event_n: u32,
    event_type: &str,
    payload: Value,
) -> ProxyEvent {
    let v = json!({
        "schema_version": 1,
        "event_id": uuid(event_n),
        "proxy_id": proxy,
        "epoch_id": epoch,
        "sequence": seq,
        "occurred_at": format!("2026-10-10T00:00:{:02}Z", seq % 60),
        "event_type": event_type,
        "payload": payload,
    });
    parse_event(v.to_string().as_bytes()).unwrap()
}

/// Start on `upstream`. `tool` is only for `tools/call`.
#[allow(clippy::too_many_arguments)]
fn start_full(
    proxy: &str,
    epoch: &str,
    seq: i64,
    event_n: u32,
    inv: u32,
    method: &str,
    protocol: &str,
    tool: Option<Value>,
    upstream: &str,
    actor: &str,
) -> ProxyEvent {
    let mut payload = json!({
        "invocation_id": uuid(inv),
        "upstream_id": upstream,
        "route_revision": 1,
        "protocol_version": protocol,
        "method": method,
        "actor": {
            "actor_id": actor,
            "actor_kind": "non_human",
            "authentication_method": "bearer",
            "evidence_source": "proxy_credential_mapping"
        }
    });
    if let Some(t) = tool {
        payload["tool"] = t;
    }
    envelope(proxy, epoch, seq, event_n, "invocation.started", payload)
}

fn start(
    proxy: &str,
    seq: i64,
    event_n: u32,
    inv: u32,
    method: &str,
    tool: Option<Value>,
) -> ProxyEvent {
    let protocol = if method == "tools/call" {
        "2025-11-25"
    } else {
        "unknown"
    };
    start_full(
        proxy, EP1, seq, event_n, inv, method, protocol, tool, "up1", "actor-1",
    )
}

fn ident(n: u32) -> Value {
    json!({"status": "identified", "metadata_ref": mref(n)})
}

fn malformed() -> Value {
    json!({"status": "unavailable", "reason": "malformed"})
}

fn done(
    proxy: &str,
    seq: i64,
    event_n: u32,
    inv: u32,
    outcome: &str,
    delivery: &str,
    reason: Option<&str>,
) -> ProxyEvent {
    let mut payload = json!({
        "invocation_id": uuid(inv),
        "outcome": outcome,
        "delivery_state": delivery,
        "duration_ms": 12,
        "response_bytes": 34
    });
    if let Some(r) = reason {
        payload["reason"] = json!(r);
    }
    envelope(proxy, EP1, seq, event_n, "invocation.completed", payload)
}

fn cancel(proxy: &str, seq: i64, event_n: u32, inv: u32) -> ProxyEvent {
    envelope(
        proxy,
        EP1,
        seq,
        event_n,
        "invocation.cancel_requested",
        json!({"invocation_id": uuid(inv)}),
    )
}

/// Pure projection of events with fixed per-event `created_seq`/`received_at`.
fn pure(events: &[ProxyEvent]) -> Projection {
    let inputs: Vec<ProjectionInput> = events
        .iter()
        .map(|e| ProjectionInput {
            event: e.clone(),
            created_seq: e.sequence.get(),
            received_at: 100 + e.sequence.get(),
        })
        .collect();
    project(&inputs).unwrap()
}

fn norm(mut p: Projection) -> Projection {
    p.created_seq = 0;
    p
}

fn open(dir: &Path) -> Ledger {
    Ledger::open(&dir.join("l.sqlite"), LedgerOptions::default()).unwrap()
}

fn inv_of(l: &Ledger, proxy: &str, inv: u32) -> Projection {
    l.get_invocation(proxy, &uuid(inv))
        .unwrap()
        .unwrap()
        .invocation
}

// ---------------------------------------------------------------------------
// L2 cases (pure)
// ---------------------------------------------------------------------------

#[test]
fn l2_start_only_is_started_never_success() {
    let p = pure(&[start("px", 1, 1, 1, "ping", None)]);
    assert_eq!(p.lifecycle, Lifecycle::Started);
    assert!(p.outcome.is_none() && p.reported_outcome.is_none());
    assert!(p.flags.is_empty() && p.decision.is_none() && !p.epoch_superseded);
    assert_eq!(p.method.as_deref(), Some("ping"));
    assert_eq!(p.event_count, 1);
}

#[test]
fn l2_completion_then_start_equals_start_then_completion() {
    let s = start("px", 1, 1, 1, "ping", None);
    let c = done("px", 2, 2, 1, "success", "sent", None);
    let a = pure(&[s.clone(), c.clone()]);
    let b = pure(&[c, s]);
    assert_eq!(a, b);
    assert_eq!(a.lifecycle, Lifecycle::Completed);
    assert_eq!(a.outcome.as_deref(), Some("success"));
    assert_eq!(a.delivery_state.as_deref(), Some("sent"));
    assert_eq!((a.duration_ms, a.response_bytes), (Some(12), Some(34)));
    assert!(a.reported_outcome.is_none());
    assert_eq!(a.upstream_id.as_deref(), Some("up1"));
    assert_eq!(a.actor.as_ref().unwrap().actor_id, "actor-1");
}

#[test]
fn l2_cancel_after_completion_keeps_the_outcome() {
    let p = pure(&[
        start("px", 1, 1, 1, "ping", None),
        done("px", 2, 2, 1, "success", "sent", None),
        cancel("px", 3, 3, 1),
    ]);
    assert_eq!(p.lifecycle, Lifecycle::Completed);
    assert!(p.cancel_observed);
    assert_eq!(p.outcome.as_deref(), Some("success"));
}

#[test]
fn l2_completion_only_withholds_outcome() {
    let p = pure(&[done("px", 1, 1, 1, "success", "sent", None)]);
    assert_eq!(p.lifecycle, Lifecycle::CompletionWithoutStart);
    assert!(p.outcome.is_none() && p.delivery_state.is_none());
    assert_eq!(p.reported_outcome.as_deref(), Some("success"));
    assert_eq!(p.reported_delivery_state.as_deref(), Some("sent"));
    assert!(p.method.is_none() && p.upstream_id.is_none() && p.actor.is_none());
    assert!(p.started_at.is_none() && p.completed_at.is_some());
}

#[test]
fn l2_equal_retransmission_is_unchanged() {
    let s = start("px", 1, 1, 1, "ping", None);
    let once = pure(std::slice::from_ref(&s));
    let twice = pure(&[s.clone(), s]);
    assert_eq!(once, twice);
}

#[test]
fn l2_malformed_start_with_success_is_integrity_conflict() {
    let s = start("px", 1, 1, 1, "tools/call", Some(malformed()));
    let c = done("px", 2, 2, 1, "success", "sent", None);
    let p = pure(&[s.clone(), c.clone()]);
    assert_eq!(p.lifecycle, Lifecycle::IntegrityConflict);
    assert!(p.outcome.is_none());
    assert_eq!(p.reported_outcome.as_deref(), Some("success"));
    assert_eq!(p.flags, vec![Flag::CompletionContradictsStart]);
    assert_eq!(
        p.tool,
        Some(ToolInfo::Unavailable {
            reason: "malformed".into()
        })
    );
    assert_eq!(p, pure(&[c, s]));
}

#[test]
fn l2_malformed_start_with_denied_not_sent_is_completed() {
    for (outcome, d) in [("denied", "not_sent"), ("protocol_error", "not_sent")] {
        let p = pure(&[
            start("px", 1, 1, 1, "tools/call", Some(malformed())),
            done("px", 2, 2, 1, outcome, d, None),
        ]);
        assert_eq!(p.lifecycle, Lifecycle::Completed, "{outcome}");
        assert_eq!(p.outcome.as_deref(), Some(outcome));
        assert!(p.flags.is_empty());
    }
}

#[test]
fn l2_reason_vs_method_rules() {
    let tc = start("px", 1, 1, 1, "tools/call", Some(ident(1)));
    let version = done(
        "px",
        2,
        2,
        1,
        "protocol_error",
        "sent",
        Some("upstream_version_unsupported"),
    );
    assert_eq!(
        pure(&[tc.clone(), version]).lifecycle,
        Lifecycle::IntegrityConflict
    );
    let init = start("px", 1, 1, 1, "initialize", None);
    let version = done(
        "px",
        2,
        2,
        1,
        "protocol_error",
        "sent",
        Some("upstream_version_unsupported"),
    );
    assert_eq!(pure(&[init, version]).lifecycle, Lifecycle::Completed);
    // modern_request_unsupported needs method unknown + protocol unknown
    let modern = || {
        done(
            "px",
            2,
            2,
            1,
            "protocol_error",
            "not_sent",
            Some("modern_request_unsupported"),
        )
    };
    assert_eq!(
        pure(&[start("px", 1, 1, 1, "unknown", None), modern()]).lifecycle,
        Lifecycle::Completed
    );
    assert_eq!(
        pure(&[start("px", 1, 1, 1, "ping", None), modern()]).lifecycle,
        Lifecycle::IntegrityConflict
    );
    // task_augmentation: not_sent -> unknown method, sent -> tools/call
    let task = |d: &str| {
        done(
            "px",
            2,
            2,
            1,
            "protocol_error",
            d,
            Some("task_augmentation_unsupported"),
        )
    };
    assert_eq!(
        pure(&[start("px", 1, 1, 1, "unknown", None), task("not_sent")]).lifecycle,
        Lifecycle::Completed
    );
    assert_eq!(
        pure(&[tc.clone(), task("not_sent")]).lifecycle,
        Lifecycle::IntegrityConflict
    );
    assert_eq!(
        pure(&[tc.clone(), task("sent")]).lifecycle,
        Lifecycle::Completed
    );
    assert_eq!(
        pure(&[start("px", 1, 1, 1, "ping", None), task("sent")]).lifecycle,
        Lifecycle::IntegrityConflict
    );
}

#[test]
fn l2_two_starts_with_different_tool_binding_conflict() {
    let a = start("px", 1, 1, 1, "tools/call", Some(ident(1)));
    let b = start("px", 2, 2, 1, "tools/call", Some(ident(2)));
    let p = pure(&[a, b]);
    assert_eq!(p.lifecycle, Lifecycle::IntegrityConflict);
    assert_eq!(p.flags, vec![Flag::StartBindingConflict]);
    assert!(p.outcome.is_none() && p.reported_outcome.is_none());
}

#[test]
fn l2_equal_duplicates_only_flag() {
    let p = pure(&[
        start("px", 1, 1, 1, "ping", None),
        start("px", 2, 2, 1, "ping", None),
        done("px", 3, 3, 1, "success", "sent", None),
        done("px", 4, 4, 1, "success", "sent", None),
    ]);
    assert_eq!(p.lifecycle, Lifecycle::Completed);
    assert_eq!(p.outcome.as_deref(), Some("success"));
    assert_eq!(
        p.flags,
        vec![Flag::DuplicateCompletion, Flag::DuplicateStart]
    );
    assert_eq!(p.event_count, 4);
}

#[test]
fn l2_two_different_completions_conflict() {
    let p = pure(&[
        start("px", 1, 1, 1, "ping", None),
        done("px", 2, 2, 1, "success", "sent", None),
        done("px", 3, 3, 1, "tool_error", "sent", None),
    ]);
    assert_eq!(p.lifecycle, Lifecycle::IntegrityConflict);
    assert_eq!(p.flags, vec![Flag::DuplicateCompletion]);
    assert!(p.outcome.is_none());
    // the same without a start is also a conflict, not completion_without_start
    let q = pure(&[
        done("px", 2, 2, 1, "success", "sent", None),
        done("px", 3, 3, 1, "tool_error", "sent", None),
    ]);
    assert_eq!(q.lifecycle, Lifecycle::IntegrityConflict);
}

#[test]
fn l2_cancel_only_and_late_start() {
    let c = cancel("px", 1, 1, 1);
    let p = pure(std::slice::from_ref(&c));
    assert_eq!(p.lifecycle, Lifecycle::CancelWithoutStart);
    assert!(p.cancel_observed && p.outcome.is_none());
    // completion first becomes completed when a consistent start arrives
    let d = done("px", 2, 2, 1, "success", "sent", None);
    assert_eq!(
        pure(std::slice::from_ref(&d)).lifecycle,
        Lifecycle::CompletionWithoutStart
    );
    let s = start("px", 3, 3, 1, "ping", None);
    assert_eq!(pure(&[d, s]).lifecycle, Lifecycle::Completed);
}

// ---------------------------------------------------------------------------
// Ledger: arrival-order independence, resend, epochs
// ---------------------------------------------------------------------------

fn permutations(n: usize) -> Vec<Vec<usize>> {
    fn go(cur: &mut Vec<usize>, used: &mut Vec<bool>, out: &mut Vec<Vec<usize>>) {
        if cur.len() == used.len() {
            out.push(cur.clone());
            return;
        }
        for i in 0..used.len() {
            if !used[i] {
                used[i] = true;
                cur.push(i);
                go(cur, used, out);
                cur.pop();
                used[i] = false;
            }
        }
    }
    let mut out = Vec::new();
    go(&mut Vec::new(), &mut vec![false; n], &mut out);
    out
}

type Scenario = fn(&str, u32) -> Vec<ProxyEvent>;

fn scenarios() -> Vec<(&'static str, Scenario)> {
    fn k(inv: u32, i: u32) -> u32 {
        inv * 10 + i
    }
    vec![
        ("start+completion+cancel", |px, inv| {
            vec![
                start(px, 1, k(inv, 1), inv, "ping", None),
                done(px, 2, k(inv, 2), inv, "success", "sent", None),
                cancel(px, 3, k(inv, 3), inv),
            ]
        }),
        ("malformed+success+cancel", |px, inv| {
            vec![
                start(px, 1, k(inv, 1), inv, "tools/call", Some(malformed())),
                done(px, 2, k(inv, 2), inv, "success", "sent", None),
                cancel(px, 3, k(inv, 3), inv),
            ]
        }),
        ("two starts with different refs + completion", |px, inv| {
            vec![
                start(px, 1, k(inv, 1), inv, "tools/call", Some(ident(1))),
                start(px, 2, k(inv, 2), inv, "tools/call", Some(ident(2))),
                done(px, 3, k(inv, 3), inv, "success", "sent", None),
            ]
        }),
        ("two different completions + start", |px, inv| {
            vec![
                done(px, 1, k(inv, 1), inv, "success", "sent", None),
                done(px, 2, k(inv, 2), inv, "tool_error", "sent", None),
                start(px, 3, k(inv, 3), inv, "ping", None),
            ]
        }),
        ("equal duplicates of start and completion", |px, inv| {
            vec![
                start(px, 1, k(inv, 1), inv, "ping", None),
                start(px, 2, k(inv, 2), inv, "ping", None),
                done(px, 3, k(inv, 3), inv, "success", "sent", None),
                done(px, 4, k(inv, 4), inv, "success", "sent", None),
            ]
        }),
    ]
}

#[test]
fn projection_is_independent_of_arrival_order() {
    let d = tempfile::tempdir().unwrap();
    let l = open(d.path());
    let mut idx = 0u32;
    for (name, make) in scenarios() {
        let mut reference: Option<Projection> = None;
        for order in permutations(make("probe", 1).len()) {
            idx += 1;
            let (px, inv) = (format!("px{idx}"), 1000 + idx);
            let events = make(&px, inv);
            for &i in &order {
                // received_at is fixed per event, like the pure inputs
                let at = 100 + events[i].sequence.get();
                l.insert_batch(&px, std::slice::from_ref(&events[i]), at)
                    .unwrap();
            }
            let stored = norm(inv_of(&l, &px, inv));
            let mut expect = norm(pure(&events));
            expect.proxy_id = px.clone();
            assert_eq!(stored, expect, "{name} order {order:?}");
            // proxy/invocation ids differ per run; compare the rest across runs
            let mut cmp = stored.clone();
            cmp.proxy_id.clear();
            cmp.invocation_id.clear();
            match &reference {
                None => reference = Some(cmp),
                Some(r) => assert_eq!(&cmp, r, "{name} order {order:?}"),
            }
        }
    }
}

#[test]
fn whole_batch_in_any_order_gives_the_same_projection() {
    let d = tempfile::tempdir().unwrap();
    let l = open(d.path());
    let mut idx = 0u32;
    let mut reference: Option<Projection> = None;
    for order in permutations(3) {
        idx += 1;
        let (px, inv) = (format!("pb{idx}"), 2000 + idx);
        let events = [
            start(&px, 1, inv * 10 + 1, inv, "ping", None),
            done(&px, 2, inv * 10 + 2, inv, "success", "sent", None),
            cancel(&px, 3, inv * 10 + 3, inv),
        ];
        let batch: Vec<ProxyEvent> = order.iter().map(|&i| events[i].clone()).collect();
        l.insert_batch(&px, &batch, 500).unwrap();
        let mut p = norm(inv_of(&l, &px, inv));
        p.proxy_id.clear();
        p.invocation_id.clear();
        match &reference {
            None => reference = Some(p),
            Some(r) => assert_eq!(&p, r),
        }
    }
}

#[test]
fn resend_is_idempotent_and_keeps_created_seq() {
    let d = tempfile::tempdir().unwrap();
    let l = open(d.path());
    let batch = vec![
        start("px", 1, 1, 1, "ping", None),
        done("px", 2, 2, 1, "success", "sent", None),
    ];
    l.insert_batch("px", &batch, 100).unwrap();
    let before = l.get_invocation("px", &uuid(1)).unwrap().unwrap();
    // resend later, whole and partial, and with an in-batch repeat
    for resend in [
        batch.clone(),
        vec![batch[1].clone()],
        vec![batch[0].clone(), batch[0].clone()],
    ] {
        let out = l.insert_batch("px", &resend, 9_000).unwrap();
        assert!(out.accepted.is_empty());
        assert_eq!(l.get_invocation("px", &uuid(1)).unwrap().unwrap(), before);
    }
    assert_eq!(before.events_total, 2);
    assert_eq!(before.invocation.last_received_at, 100);
}

#[test]
fn later_events_update_the_projection_and_keep_its_list_position() {
    let d = tempfile::tempdir().unwrap();
    let l = open(d.path());
    l.insert_batch("px", &[start("px", 1, 1, 1, "ping", None)], 100)
        .unwrap();
    l.insert_batch("px", &[start("px", 2, 2, 2, "ping", None)], 101)
        .unwrap();
    let first = inv_of(&l, "px", 1);
    assert_eq!(first.lifecycle, Lifecycle::Started);
    l.insert_batch("px", &[done("px", 3, 3, 1, "success", "sent", None)], 102)
        .unwrap();
    let after = inv_of(&l, "px", 1);
    assert_eq!(after.lifecycle, Lifecycle::Completed);
    assert_eq!(after.created_seq, first.created_seq);
    assert_eq!(
        (after.first_received_at, after.last_received_at),
        (100, 102)
    );
    let page = l
        .list_invocations(&InvocationFilter::default(), None, 10)
        .unwrap();
    let order: Vec<&str> = page
        .items
        .iter()
        .map(|p| p.invocation_id.as_str())
        .collect();
    assert_eq!(order, vec![uuid(2), uuid(1)]);
}

#[test]
fn conflicting_batch_leaves_no_projection() {
    let d = tempfile::tempdir().unwrap();
    let l = open(d.path());
    l.insert_batch("px", &[start("px", 1, 1, 1, "ping", None)], 100)
        .unwrap();
    // second event reuses sequence 1 -> 409; the new invocation must not appear
    let bad = vec![
        start("px", 2, 2, 7, "ping", None),
        start("px", 1, 3, 8, "ping", None),
    ];
    assert!(matches!(
        l.insert_batch("px", &bad, 101),
        Err(LedgerError::Conflicts(_))
    ));
    assert!(l.get_invocation("px", &uuid(7)).unwrap().is_none());
    // dry run (check_batch) stores nothing either
    l.check_batch("px", &[start("px", 5, 5, 9, "ping", None)], 102)
        .unwrap();
    assert!(l.get_invocation("px", &uuid(9)).unwrap().is_none());
}

#[test]
fn epoch_superseded_follows_the_latest_epoch() {
    let d = tempfile::tempdir().unwrap();
    let l = open(d.path());
    l.insert_batch("px", &[start("px", 1, 1, 1, "ping", None)], 100)
        .unwrap();
    assert!(!inv_of(&l, "px", 1).epoch_superseded);
    // newer epoch announced by an event of another invocation
    let e2 = start_full(
        "px", EP2, 1, 2, 2, "ping", "unknown", None, "up1", "actor-1",
    );
    l.insert_batch("px", &[e2], 101).unwrap();
    let old = inv_of(&l, "px", 1);
    assert_eq!(old.lifecycle, Lifecycle::Started);
    assert!(old.epoch_superseded, "start-only in a superseded epoch");
    assert!(!inv_of(&l, "px", 2).epoch_superseded);
    // still outcome-less, and a completed invocation is never superseded
    assert!(old.outcome.is_none());
    l.insert_batch("px", &[done("px", 2, 3, 1, "success", "sent", None)], 102)
        .unwrap();
    let c = inv_of(&l, "px", 1);
    assert_eq!(c.lifecycle, Lifecycle::Completed);
    assert!(!c.epoch_superseded);
}

// ---------------------------------------------------------------------------
// Schema v2, migration
// ---------------------------------------------------------------------------

/// The v1 schema, verbatim from before S5.
const V1_SCHEMA: &str = "
CREATE TABLE events (
    created_seq   INTEGER PRIMARY KEY AUTOINCREMENT,
    proxy_id      TEXT NOT NULL,
    event_id      TEXT NOT NULL,
    epoch_id      TEXT NOT NULL,
    sequence      INTEGER NOT NULL,
    invocation_id TEXT NOT NULL,
    event_type    TEXT NOT NULL,
    occurred_at   TEXT NOT NULL,
    received_at   INTEGER NOT NULL,
    canonical     BLOB NOT NULL,
    sha256        BLOB NOT NULL,
    size          INTEGER NOT NULL,
    UNIQUE (proxy_id, event_id),
    UNIQUE (proxy_id, epoch_id, sequence)
);
CREATE INDEX events_received ON events (proxy_id, received_at);
CREATE INDEX events_invocation ON events (invocation_id);
CREATE TABLE tombstones (
    proxy_id    TEXT NOT NULL,
    event_id    TEXT NOT NULL,
    epoch_id    TEXT NOT NULL,
    sequence    INTEGER NOT NULL,
    sha256      BLOB NOT NULL,
    received_at INTEGER NOT NULL,
    PRIMARY KEY (proxy_id, event_id),
    UNIQUE (proxy_id, epoch_id, sequence)
) WITHOUT ROWID;
CREATE INDEX tombstones_received ON tombstones (received_at);
CREATE TABLE epochs (
    ord              INTEGER PRIMARY KEY AUTOINCREMENT,
    proxy_id         TEXT NOT NULL,
    epoch_id         TEXT NOT NULL,
    highest_sequence INTEGER NOT NULL,
    last_received_at INTEGER NOT NULL,
    UNIQUE (proxy_id, epoch_id)
);
CREATE TABLE gaps (
    rowid_seq         INTEGER PRIMARY KEY AUTOINCREMENT,
    gap_id            TEXT NOT NULL UNIQUE,
    proxy_id          TEXT NOT NULL,
    kind              TEXT NOT NULL,
    detected_at       INTEGER NOT NULL,
    epoch_id          TEXT NOT NULL,
    previous_epoch_id TEXT,
    from_sequence     INTEGER,
    to_sequence       INTEGER,
    open              INTEGER NOT NULL,
    closed_at         INTEGER,
    present           INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX gaps_open ON gaps (proxy_id, epoch_id, open, from_sequence);
CREATE TABLE invocations (
    invocation_id    TEXT PRIMARY KEY,
    proxy_id         TEXT NOT NULL,
    last_received_at INTEGER NOT NULL
) WITHOUT ROWID;
CREATE TABLE usage (
    proxy_id       TEXT PRIMARY KEY,
    event_rows     INTEGER NOT NULL,
    event_bytes    INTEGER NOT NULL,
    tombstone_rows INTEGER NOT NULL
) WITHOUT ROWID;
";

/// Create a v1 ledger file holding `events` (received_at = 100 + sequence),
/// the way the pre-S5 ledger left them. `corrupt` garbles one stored event.
fn build_v1(path: &Path, events: &[ProxyEvent], corrupt: Option<usize>) {
    {
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        o.open(path).unwrap();
    }
    let c = rusqlite::Connection::open(path).unwrap();
    c.pragma_update(None, "journal_mode", "WAL").unwrap();
    c.execute_batch(V1_SCHEMA).unwrap();
    for (i, e) in events.iter().enumerate() {
        use sha2::{Digest, Sha256};
        let mut canonical = canonical_event_bytes(e);
        let digest = Sha256::digest(&canonical).to_vec();
        if corrupt == Some(i) {
            canonical = b"{\"not\":\"an event\"}".to_vec();
        }
        let at = 100 + e.sequence.get();
        let inv = e.payload.invocation_id().as_str().to_string();
        c.execute(
            "INSERT INTO events (proxy_id, event_id, epoch_id, sequence, invocation_id, event_type,
                 occurred_at, received_at, canonical, sha256, size)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
            rusqlite::params![
                e.proxy_id.as_str(),
                e.event_id.as_str(),
                e.epoch_id.as_str(),
                e.sequence.get(),
                inv,
                serde_json::to_value(e.payload.event_type())
                    .unwrap()
                    .as_str()
                    .unwrap(),
                e.occurred_at.as_str(),
                at,
                canonical,
                digest,
                canonical.len() as i64
            ],
        )
        .unwrap();
        c.execute(
            "INSERT INTO tombstones VALUES (?1,?2,?3,?4,?5,?6)",
            rusqlite::params![
                e.proxy_id.as_str(),
                e.event_id.as_str(),
                e.epoch_id.as_str(),
                e.sequence.get(),
                digest,
                at
            ],
        )
        .unwrap();
        c.execute(
            "INSERT INTO invocations VALUES (?1,?2,?3) ON CONFLICT (invocation_id)
                 DO UPDATE SET last_received_at = excluded.last_received_at",
            rusqlite::params![inv, e.proxy_id.as_str(), at],
        )
        .unwrap();
    }
    c.execute(
        "INSERT INTO epochs (proxy_id, epoch_id, highest_sequence, last_received_at)
         VALUES ('px', ?1, 6, 106)",
        [EP1],
    )
    .unwrap();
    // one open v1 gap (sequence 4 never arrived)
    c.execute(
        "INSERT INTO gaps (gap_id, proxy_id, kind, detected_at, epoch_id, from_sequence,
             to_sequence, open) VALUES ('g1','px','sequence_gap',105,?1,4,4,1)",
        [EP1],
    )
    .unwrap();
    c.execute_batch(
        "INSERT INTO usage SELECT proxy_id, COUNT(*), SUM(size), COUNT(*) FROM events GROUP BY proxy_id;
         PRAGMA user_version = 1;",
    )
    .unwrap();
}

fn v1_events() -> Vec<ProxyEvent> {
    vec![
        start("px", 1, 1, 1, "ping", None),
        done("px", 2, 2, 1, "success", "sent", None),
        start("px", 3, 3, 2, "tools/call", Some(malformed())),
        // sequence 4 missing
        done("px", 5, 5, 2, "success", "sent", None),
        done("px", 6, 6, 3, "success", "sent", None), // completion without start
    ]
}

fn user_version(path: &Path) -> i64 {
    let c = rusqlite::Connection::open(path).unwrap();
    c.pragma_query_value(None, "user_version", |r| r.get(0))
        .unwrap()
}

fn table_exists(path: &Path, name: &str) -> bool {
    let c = rusqlite::Connection::open(path).unwrap();
    c.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
        [name],
        |r| r.get(0),
    )
    .unwrap()
}

#[test]
fn migration_v1_to_v2_rebuilds_projections() {
    assert_eq!(SCHEMA_VERSION, 2);
    let d = tempfile::tempdir().unwrap();
    let path = d.path().join("l.sqlite");
    build_v1(&path, &v1_events(), None);
    assert_eq!(user_version(&path), 1);

    let l = Ledger::open(&path, LedgerOptions::default()).unwrap();
    assert_eq!(user_version(&path), 2);
    let p1 = inv_of(&l, "px", 1);
    assert_eq!(
        (p1.lifecycle, p1.outcome.as_deref()),
        (Lifecycle::Completed, Some("success"))
    );
    assert_eq!(p1.event_count, 2);
    let p2 = inv_of(&l, "px", 2);
    assert_eq!(p2.lifecycle, Lifecycle::IntegrityConflict);
    assert_eq!(p2.flags, vec![Flag::CompletionContradictsStart]);
    let p3 = inv_of(&l, "px", 3);
    assert_eq!(p3.lifecycle, Lifecycle::CompletionWithoutStart);
    assert_eq!(p3.reported_outcome.as_deref(), Some("success"));
    // equals what the pure function says, ordered by created_seq like ingest
    let page = l
        .list_invocations(&InvocationFilter::default(), None, 10)
        .unwrap();
    let order: Vec<&str> = page
        .items
        .iter()
        .map(|p| p.invocation_id.as_str())
        .collect();
    assert_eq!(order, vec![uuid(3), uuid(2), uuid(1)]);
    // the v1 gap survives and reads with tail=false
    let gaps = l.gaps("px").unwrap();
    assert_eq!(gaps.len(), 1);
    assert!(gaps[0].open && !gaps[0].tail);
    // new ingest after migration works, closes the v1 gap and updates a projection
    l.insert_batch("px", &[start("px", 4, 4, 3, "ping", None)], 200)
        .unwrap();
    assert_eq!(inv_of(&l, "px", 3).lifecycle, Lifecycle::Completed);
    assert!(!l.gaps("px").unwrap()[0].open);
    drop(l);
    // reopening a v2 file does not migrate again
    let l = Ledger::open(&path, LedgerOptions::default()).unwrap();
    assert_eq!(inv_of(&l, "px", 3).lifecycle, Lifecycle::Completed);
}

#[test]
fn failed_migration_leaves_the_file_at_v1() {
    let d = tempfile::tempdir().unwrap();
    let path = d.path().join("l.sqlite");
    // event index 3 (inv 2, sequence 5) cannot be decoded
    build_v1(&path, &v1_events(), Some(3));
    assert!(Ledger::open(&path, LedgerOptions::default()).is_err());
    assert_eq!(user_version(&path), 1);
    assert!(!table_exists(&path, "projections"));
    let c = rusqlite::Connection::open(&path).unwrap();
    let has_tail: bool = c
        .query_row(
            "SELECT COUNT(*) > 0 FROM pragma_table_info('gaps') WHERE name = 'tail'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(!has_tail, "gaps.tail must be rolled back too");
    let n: i64 = c
        .query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 5);
}

#[test]
fn newer_schema_is_still_refused() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("l.sqlite");
    drop(Ledger::open(&p, LedgerOptions::default()).unwrap());
    rusqlite::Connection::open(&p)
        .unwrap()
        .pragma_update(None, "user_version", 3)
        .unwrap();
    assert!(Ledger::open(&p, LedgerOptions::default()).is_err());
}

#[test]
fn projection_table_carries_no_content_columns() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("l.sqlite");
    drop(Ledger::open(&p, LedgerOptions::default()).unwrap());
    let c = rusqlite::Connection::open(&p).unwrap();
    let mut st = c
        .prepare("SELECT name FROM pragma_table_info('projections')")
        .unwrap();
    let cols: Vec<String> = st
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    for c in &cols {
        for bad in [
            "argument",
            "result",
            "tool_name",
            "session",
            "token",
            "payload",
            "error",
        ] {
            assert!(!c.contains(bad), "{c}");
        }
    }
    for must in [
        "proxy_id",
        "upstream_id",
        "actor_id",
        "method",
        "outcome",
        "lifecycle",
        "tool_ref",
        "created_seq",
        "first_received_at",
        "started_at_s",
    ] {
        assert!(cols.iter().any(|c| c == must), "{must}");
    }
}

// ---------------------------------------------------------------------------
// Sweep
// ---------------------------------------------------------------------------

#[test]
fn sweep_expires_whole_invocations_and_keeps_tombstones() {
    let d = tempfile::tempdir().unwrap();
    let l = open(d.path());
    // inv 1: events at 100 and 500; inv 2: only at 100
    l.insert_batch("px", &[start("px", 1, 1, 1, "ping", None)], 100)
        .unwrap();
    l.insert_batch("px", &[start("px", 2, 2, 2, "ping", None)], 100)
        .unwrap();
    l.insert_batch("px", &[done("px", 3, 3, 1, "success", "sent", None)], 500)
        .unwrap();
    let st = l.sweep(700, &|_| 300).unwrap();
    // cutoff 400: inv 2 (last 100) expires, inv 1 (last 500) stays whole
    assert_eq!((st.events, st.projections), (1, 1));
    assert!(l.get_invocation("px", &uuid(2)).unwrap().is_none());
    let kept = l.get_invocation("px", &uuid(1)).unwrap().unwrap();
    assert_eq!((kept.events_total, kept.events.len()), (2, 2));
    assert!(l.stored_event("px", &uuid(1)).unwrap().is_some());
    assert!(l.stored_event("px", &uuid(3)).unwrap().is_some());
    assert!(l.stored_event("px", &uuid(2)).unwrap().is_none());
    // tombstones stay: a resend of an expired event is still a duplicate
    let out = l
        .insert_batch("px", &[start("px", 2, 2, 2, "ping", None)], 701)
        .unwrap();
    assert!(out.accepted.is_empty() && out.duplicate.len() == 1);
    assert!(l.get_invocation("px", &uuid(2)).unwrap().is_none());
    let u = l.usage("px").unwrap();
    assert_eq!((u.event_rows, u.tombstone_rows), (2, 3));
    // later: the rest expires as a unit
    let st = l.sweep(900, &|_| 300).unwrap();
    assert_eq!((st.events, st.projections), (2, 1));
    assert!(l.get_invocation("px", &uuid(1)).unwrap().is_none());
    assert_eq!(l.usage("px").unwrap().event_rows, 0);
    assert!(l
        .list_invocations(&InvocationFilter::default(), None, 10)
        .unwrap()
        .items
        .is_empty());
}

#[test]
fn sweep_boundary_keeps_an_invocation_at_exactly_e() {
    let d = tempfile::tempdir().unwrap();
    let l = open(d.path());
    l.insert_batch("px", &[start("px", 1, 1, 1, "ping", None)], 100)
        .unwrap();
    let st = l.sweep(400, &|_| 300).unwrap();
    assert_eq!(st.projections, 0, "kept while now - last_received_at <= E");
    let st = l.sweep(401, &|_| 300).unwrap();
    assert_eq!(st.projections, 1);
}

// ---------------------------------------------------------------------------
// Tail gaps
// ---------------------------------------------------------------------------

fn seq_ev(seq: i64) -> ProxyEvent {
    start("px", seq, seq as u32, seq as u32 + 5000, "ping", None)
}

#[test]
fn tail_gap_create_extend_close_and_record_kept() {
    let d = tempfile::tempdir().unwrap();
    let l = open(d.path());
    l.insert_batch("px", &[seq_ev(1), seq_ev(2), seq_ev(3)], 100)
        .unwrap();
    // nothing missing yet
    assert_eq!(
        l.note_last_assigned("px", EP1, 3, 110).unwrap(),
        TailGapChange::Unchanged
    );
    assert_eq!(
        l.note_last_assigned("px", EP1, 2, 110).unwrap(),
        TailGapChange::Unchanged
    );
    assert!(l.gaps("px").unwrap().is_empty());

    assert_eq!(
        l.note_last_assigned("px", EP1, 5, 110).unwrap(),
        TailGapChange::Created
    );
    let g = l.gaps("px").unwrap();
    assert_eq!(g.len(), 1);
    assert!(g[0].tail && g[0].open && g[0].kind == GapKind::SequenceGap);
    assert_eq!((g[0].from_sequence, g[0].to_sequence), (Some(4), Some(5)));
    // extended, not duplicated; same or lower value changes nothing
    assert_eq!(
        l.note_last_assigned("px", EP1, 7, 120).unwrap(),
        TailGapChange::Extended
    );
    assert_eq!(
        l.note_last_assigned("px", EP1, 7, 121).unwrap(),
        TailGapChange::Unchanged
    );
    assert_eq!(
        l.note_last_assigned("px", EP1, 6, 122).unwrap(),
        TailGapChange::Unchanged
    );
    let g = l.gaps("px").unwrap();
    assert_eq!(g.len(), 1);
    assert_eq!((g[0].from_sequence, g[0].to_sequence), (Some(4), Some(7)));
    assert_eq!(
        l.open_gap_counts("px").unwrap().get("sequence_gap"),
        Some(&1)
    );

    // 4 arrives: tail shrinks to 5..7
    l.insert_batch("px", &[seq_ev(4)], 130).unwrap();
    let g = l.gaps("px").unwrap();
    assert_eq!(g.len(), 1);
    assert!(g[0].tail && g[0].open);
    assert_eq!((g[0].from_sequence, g[0].to_sequence), (Some(5), Some(7)));
    // 6 arrives out of order: 5 becomes an ordinary gap, tail is 7..7
    l.insert_batch("px", &[seq_ev(6)], 131).unwrap();
    let g = l.gaps("px").unwrap();
    assert_eq!(g.len(), 2);
    let tail = g.iter().find(|x| x.tail).unwrap();
    let plain = g.iter().find(|x| !x.tail).unwrap();
    assert_eq!((tail.from_sequence, tail.to_sequence), (Some(7), Some(7)));
    assert_eq!((plain.from_sequence, plain.to_sequence), (Some(5), Some(5)));
    assert!(plain.open);
    // 7 arrives: the tail closes and stays listed
    l.insert_batch("px", &[seq_ev(7)], 132).unwrap();
    let g = l.gaps("px").unwrap();
    let tail = g.iter().find(|x| x.tail).unwrap();
    assert!(!tail.open && tail.closed_at == Some(132));
    // 5 arrives: the ordinary gap closes; nothing is open, nothing removed
    l.insert_batch("px", &[seq_ev(5)], 133).unwrap();
    let g = l.gaps("px").unwrap();
    assert_eq!(g.len(), 2);
    assert!(g.iter().all(|x| !x.open));
    assert!(l.open_gap_counts("px").unwrap().is_empty());

    // a new report after the old tail closed opens a new one
    assert_eq!(
        l.note_last_assigned("px", EP1, 9, 140).unwrap(),
        TailGapChange::Created
    );
    let g = l.gaps("px").unwrap();
    assert_eq!(g.len(), 3);
    assert_eq!((g[2].from_sequence, g[2].to_sequence), (Some(8), Some(9)));
    // an event beyond the reported tail turns it into a plain missing range
    l.insert_batch("px", &[seq_ev(12)], 150).unwrap();
    let g = l.gaps("px").unwrap();
    assert_eq!(g.len(), 3);
    assert!(!g[2].tail && g[2].open);
    assert_eq!((g[2].from_sequence, g[2].to_sequence), (Some(8), Some(11)));
    // and it closes like any ordinary gap when 8..=11 arrive
    l.insert_batch("px", &[seq_ev(8), seq_ev(9), seq_ev(10), seq_ev(11)], 160)
        .unwrap();
    assert!(l.gaps("px").unwrap().iter().all(|x| !x.open));
}

#[test]
fn tail_gap_before_any_event_of_the_epoch() {
    let d = tempfile::tempdir().unwrap();
    let l = open(d.path());
    assert_eq!(
        l.note_last_assigned("px", EP1, 3, 10).unwrap(),
        TailGapChange::Created
    );
    let g = l.gaps("px").unwrap();
    assert_eq!(
        (g[0].from_sequence, g[0].to_sequence, g[0].tail),
        (Some(1), Some(3), true)
    );
    l.insert_batch("px", &[seq_ev(1), seq_ev(2), seq_ev(3)], 20)
        .unwrap();
    let g = l.gaps("px").unwrap();
    assert!(g
        .iter()
        .filter(|x| x.kind == GapKind::SequenceGap)
        .all(|x| !x.open));
    // scoped per proxy: another proxy never sees it
    assert!(l.gaps("other").unwrap().is_empty());
}

// ---------------------------------------------------------------------------
// Read API
// ---------------------------------------------------------------------------

#[test]
fn read_api_is_scoped_by_proxy() {
    let d = tempfile::tempdir().unwrap();
    let l = open(d.path());
    // two proxies; distinct invocation ids (SV-1)
    for (px, base) in [("pa", 10u32), ("pb", 20u32)] {
        let evs: Vec<ProxyEvent> = (1..=3)
            .map(|i| start(px, i as i64, base + i, base + i, "ping", None))
            .collect();
        l.insert_batch(px, &evs, 100).unwrap();
    }
    // gaps for pa only (skip sequence 5)
    l.insert_batch("pa", &[start("pa", 5, 99, 99, "ping", None)], 101)
        .unwrap();

    let only = |px: &str| InvocationFilter {
        proxy_id: Some(px.into()),
        ..Default::default()
    };
    let a = l.list_invocations(&only("pa"), None, 100).unwrap();
    let b = l.list_invocations(&only("pb"), None, 100).unwrap();
    assert_eq!((a.items.len(), b.items.len()), (4, 3));
    assert!(a.items.iter().all(|p| p.proxy_id == "pa"));
    assert!(b.items.iter().all(|p| p.proxy_id == "pb"));
    assert!(l
        .list_invocations(&only("nobody"), None, 100)
        .unwrap()
        .items
        .is_empty());
    assert_eq!(
        l.list_invocations(&InvocationFilter::default(), None, 100)
            .unwrap()
            .items
            .len(),
        7
    );

    // detail: another proxy's invocation looks unknown
    assert!(l.get_invocation("pa", &uuid(11)).unwrap().is_some());
    assert!(l.get_invocation("pb", &uuid(11)).unwrap().is_none());

    // gaps and counts
    assert_eq!(l.gaps_page("pa", 50).unwrap().total, 1);
    assert_eq!(l.gaps_page("pb", 50).unwrap().total, 0);
    assert!(l.gaps_page("pb", 50).unwrap().items.is_empty());
    assert_eq!(
        l.open_gap_counts("pa").unwrap().get("sequence_gap"),
        Some(&1)
    );
    assert!(l.open_gap_counts("pb").unwrap().is_empty());
}

#[test]
fn list_filters_and_outcome_only_matches_completed() {
    let d = tempfile::tempdir().unwrap();
    let l = open(d.path());
    l.insert_batch(
        "px",
        &[
            start_full(
                "px",
                EP1,
                1,
                1,
                1,
                "tools/call",
                "2025-11-25",
                Some(ident(1)),
                "up1",
                "alice",
            ),
            done("px", 2, 2, 1, "success", "sent", None),
            start_full("px", EP1, 3, 3, 2, "ping", "unknown", None, "up2", "bob"),
            done("px", 4, 4, 3, "success", "sent", None), // completion without start
            start("px", 5, 5, 4, "tools/call", Some(malformed())),
            done("px", 6, 6, 4, "success", "sent", None), // integrity conflict
            start("px", 7, 7, 5, "ping", None),           // started
        ],
        1000,
    )
    .unwrap();
    let list = |f: InvocationFilter| -> Vec<String> {
        l.list_invocations(&f, None, 100)
            .unwrap()
            .items
            .into_iter()
            .map(|p| p.invocation_id)
            .collect()
    };
    let f = |f: fn(&mut InvocationFilter)| {
        let mut x = InvocationFilter::default();
        f(&mut x);
        x
    };
    assert_eq!(
        list(f(|x| x.outcome = Some("success".into()))),
        vec![uuid(1)]
    );
    assert_eq!(
        list(f(|x| x.lifecycle = Some(Lifecycle::CompletionWithoutStart))),
        vec![uuid(3)]
    );
    assert_eq!(
        list(f(|x| x.lifecycle = Some(Lifecycle::IntegrityConflict))),
        vec![uuid(4)]
    );
    assert_eq!(
        list(f(|x| x.lifecycle = Some(Lifecycle::Started))),
        vec![uuid(5), uuid(2)]
    );
    assert_eq!(
        list(f(|x| x.actor_id = Some("alice".into()))),
        vec![uuid(1)]
    );
    assert_eq!(
        list(f(|x| x.upstream_id = Some("up2".into()))),
        vec![uuid(2)]
    );
    assert_eq!(
        list(f(|x| x.method = Some("tools/call".into()))),
        vec![uuid(4), uuid(1)]
    );
    assert_eq!(list(f(|x| x.tool_ref = Some(mref(1)))), vec![uuid(1)]);
    assert!(list(f(|x| x.tool_ref = Some(mref(9)))).is_empty());
    // reported values are never matched by the outcome filter
    assert_eq!(
        list(f(|x| x.outcome = Some("denied".into()))),
        Vec::<String>::new()
    );
}

#[test]
fn time_filters_use_the_chosen_basis_half_open() {
    let d = tempfile::tempdir().unwrap();
    let l = open(d.path());
    // occurred_at = 2026-10-10T00:00:<seq>Z
    let t0 = sigil_server::proxy::projection::timestamp_secs("2026-10-10T00:00:00Z").unwrap();
    l.insert_batch("px", &[start("px", 10, 1, 1, "ping", None)], 1000)
        .unwrap();
    l.insert_batch("px", &[start("px", 20, 2, 2, "ping", None)], 2000)
        .unwrap();
    l.insert_batch("px", &[done("px", 30, 3, 3, "success", "sent", None)], 3000)
        .unwrap();
    let ids = |f: InvocationFilter| -> Vec<String> {
        l.list_invocations(&f, None, 100)
            .unwrap()
            .items
            .into_iter()
            .map(|p| p.invocation_id)
            .collect()
    };
    let recv = |from, to| InvocationFilter {
        from,
        to,
        ..Default::default()
    };
    assert_eq!(ids(recv(Some(1000), Some(2000))), vec![uuid(1)]);
    assert_eq!(ids(recv(Some(2000), None)), vec![uuid(3), uuid(2)]);
    assert_eq!(ids(recv(None, Some(1000))), Vec::<String>::new());
    let occ = |from, to| InvocationFilter {
        from,
        to,
        time_basis: TimeBasis::Occurred,
        ..Default::default()
    };
    // started_at for starts, completed_at for a completion-only record
    assert_eq!(ids(occ(Some(t0 + 10), Some(t0 + 20))), vec![uuid(1)]);
    assert_eq!(ids(occ(Some(t0 + 20), None)), vec![uuid(3), uuid(2)]);
}

#[test]
fn keyset_paging_walks_everything_once_newest_first() {
    let d = tempfile::tempdir().unwrap();
    let l = open(d.path());
    let evs: Vec<ProxyEvent> = (1..=25)
        .map(|i| start("px", i, i as u32, i as u32, "ping", None))
        .collect();
    l.insert_batch("px", &evs, 100).unwrap();
    let mut seen = Vec::new();
    let mut key = None;
    let mut pages = 0;
    loop {
        let page = l
            .list_invocations(&InvocationFilter::default(), key, 10)
            .unwrap();
        pages += 1;
        seen.extend(page.items.iter().map(|p| p.invocation_id.clone()));
        match page.next_key {
            Some(k) => key = Some(k),
            None => break,
        }
    }
    assert_eq!(pages, 3);
    let want: Vec<String> = (1..=25).rev().map(uuid).collect();
    assert_eq!(seen, want);
    // a row that changes later does not move
    l.insert_batch("px", &[done("px", 26, 26, 1, "success", "sent", None)], 101)
        .unwrap();
    let page = l
        .list_invocations(&InvocationFilter::default(), None, 100)
        .unwrap();
    assert_eq!(page.items.last().unwrap().invocation_id, uuid(1));
}

#[test]
fn list_limit_is_capped_at_500() {
    let d = tempfile::tempdir().unwrap();
    let l = open(d.path());
    let evs: Vec<ProxyEvent> = (1..=520)
        .map(|i| start("px", i, i as u32, i as u32, "ping", None))
        .collect();
    l.insert_batch("px", &evs, 100).unwrap();
    let page = l
        .list_invocations(&InvocationFilter::default(), None, 100_000)
        .unwrap();
    assert_eq!(page.items.len(), 500);
    assert!(page.next_key.is_some());
    let rest = l
        .list_invocations(&InvocationFilter::default(), page.next_key, 100_000)
        .unwrap();
    assert_eq!(rest.items.len(), 20);
    assert!(rest.next_key.is_none());
    // limit 0 is treated as 1, never as "everything"
    assert_eq!(
        l.list_invocations(&InvocationFilter::default(), None, 0)
            .unwrap()
            .items
            .len(),
        1
    );
}

#[test]
fn detail_returns_at_most_32_identifier_only_events() {
    let d = tempfile::tempdir().unwrap();
    let l = open(d.path());
    let mut evs = vec![start("px", 1, 1, 1, "ping", None)];
    evs.extend((2..=40).map(|i| cancel("px", i, i as u32, 1)));
    l.insert_batch("px", &evs, 100).unwrap();
    let d = l.get_invocation("px", &uuid(1)).unwrap().unwrap();
    assert_eq!(d.events.len(), 32);
    assert_eq!(d.events_total, 40);
    assert!(d.events_truncated);
    assert_eq!(d.events[0].event_type, "invocation.started");
    assert_eq!(d.events[1].event_type, "invocation.cancel_requested");
    assert!(d
        .events
        .windows(2)
        .all(|w| w[0].created_seq < w[1].created_seq));
    assert_eq!(d.events[0].event_id, uuid(1));
    assert_eq!(d.events[0].epoch_id, EP1);
    assert_eq!(d.events[0].sequence, 1);
    assert!(d.invocation.cancel_observed);
    // a small one is not truncated
    l.insert_batch("px", &[start("px", 41, 41, 2, "ping", None)], 100)
        .unwrap();
    let s = l.get_invocation("px", &uuid(2)).unwrap().unwrap();
    assert_eq!(
        (s.events.len(), s.events_total, s.events_truncated),
        (1, 1, false)
    );
}

#[test]
fn gaps_page_is_capped_newest_first_with_total() {
    let d = tempfile::tempdir().unwrap();
    let l = open(d.path());
    // odd sequences only: 59 gaps (2, 4, ..., 118)
    let evs: Vec<ProxyEvent> = (0..60).map(|i| seq_ev(2 * i + 1)).collect();
    l.insert_batch("px", &evs, 100).unwrap();
    let page = l.gaps_page("px", 1000).unwrap();
    assert_eq!(page.total, 59);
    assert_eq!(page.items.len(), 50);
    assert_eq!(page.items[0].from_sequence, Some(118));
    assert!(page
        .items
        .windows(2)
        .all(|w| w[0].from_sequence > w[1].from_sequence));
    assert_eq!(l.gaps_page("px", 5).unwrap().items.len(), 5);
    assert_eq!(
        l.open_gap_counts("px").unwrap().get("sequence_gap"),
        Some(&59)
    );
}

#[test]
fn reads_do_not_wait_for_the_writer_mutex() {
    let d = tempfile::tempdir().unwrap();
    let l = open(d.path());
    l.insert_batch("px", &[seq_ev(1), seq_ev(3)], 100).unwrap();
    let got = l.with_writer_locked(|| {
        (
            l.list_invocations(&InvocationFilter::default(), None, 10)
                .unwrap()
                .items
                .len(),
            l.get_invocation("px", &uuid(5001)).unwrap().is_some(),
            l.gaps_page("px", 10).unwrap().total,
            l.open_gap_counts("px").unwrap().len(),
        )
    });
    assert_eq!(got, (2, true, 1, 1));
}

#[cfg(unix)]
#[test]
fn read_connection_applies_the_same_path_safety_checks() {
    use std::os::unix::fs::PermissionsExt;
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("l.sqlite");
    drop(Ledger::open(&p, LedgerOptions::default()).unwrap());
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o640)).unwrap();
    assert!(Ledger::open(&p, LedgerOptions::default()).is_err());
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
    let link = d.path().join("link.sqlite");
    std::os::unix::fs::symlink(&p, &link).unwrap();
    assert!(Ledger::open(&link, LedgerOptions::default()).is_err());
    assert!(Ledger::open(&p, LedgerOptions::default()).is_ok());
}

// ---------------------------------------------------------------------------
// Review fixes: M1..M5, L1..L5
// ---------------------------------------------------------------------------

use sigil_server::proxy::ledger::LedgerCaps;

#[test]
fn m1_event_cap_flags_and_bounds_the_recompute() {
    let d = tempfile::tempdir().unwrap();
    let l = open(d.path());
    let mut evs = vec![start("px", 1, 1, 1, "ping", None)];
    evs.extend((2..=300).map(|i| cancel("px", i, i as u32, 1)));
    l.insert_batch("px", &evs, 100).unwrap();
    let det = l.get_invocation("px", &uuid(1)).unwrap().unwrap();
    assert_eq!(det.events_total, 300);
    assert!(det.events_truncated);
    assert_eq!(det.invocation.lifecycle, Lifecycle::Started);
    assert_eq!(det.invocation.flags, vec![Flag::EventLimit]);
    // beyond the cap a contradicting completion is not considered (documented:
    // the result past the cap depends on arrival order), but it is counted
    l.insert_batch(
        "px",
        &[done("px", 301, 301, 1, "success", "sent", None)],
        101,
    )
    .unwrap();
    let p = inv_of(&l, "px", 1);
    assert_eq!(p.lifecycle, Lifecycle::Started);
    assert_eq!(p.event_count, 301);
    assert!(p.flags.contains(&Flag::EventLimit));
    // exactly at the cap there is no flag
    let mut small = vec![start("px", 400, 400, 2, "ping", None)];
    small.extend((401..=655).map(|i| cancel("px", i, i as u32, 2)));
    l.insert_batch("px", &small, 100).unwrap();
    let q = inv_of(&l, "px", 2);
    assert_eq!(q.event_count, 256);
    assert!(q.flags.is_empty());
}

#[test]
fn m1_many_equal_events_are_deduped_by_content_before_comparison() {
    let mut evs: Vec<ProxyEvent> = (1..=100)
        .map(|i| start("px", i, i as u32, 1, "ping", None))
        .collect();
    evs.extend((101..=150).map(|i| done("px", i, i as u32, 1, "success", "sent", None)));
    let p = pure(&evs);
    assert_eq!(p.lifecycle, Lifecycle::Completed);
    assert_eq!(
        p.flags,
        vec![Flag::DuplicateCompletion, Flag::DuplicateStart]
    );
    assert_eq!(p.event_count, 150);
}

#[test]
fn m2_allowed_proxies_scope_and_paging_stays_full() {
    let d = tempfile::tempdir().unwrap();
    let l = open(d.path());
    // interleave so a post-filter would return short pages
    for i in 1..=10u32 {
        for (px, base) in [("pa", 100u32), ("pb", 200u32), ("pc", 300u32)] {
            l.insert_batch(
                px,
                &[start(px, i as i64, base + i, base + i, "ping", None)],
                100,
            )
            .unwrap();
        }
    }
    let allowed = |v: &[&str]| InvocationFilter {
        allowed_proxies: Some(v.iter().map(|s| s.to_string()).collect()),
        ..Default::default()
    };
    let mut seen = Vec::new();
    let mut key = None;
    loop {
        let page = l.list_invocations(&allowed(&["pa"]), key, 3).unwrap();
        if page.next_key.is_some() {
            assert_eq!(page.items.len(), 3, "full page under allowed_proxies");
        }
        seen.extend(page.items);
        match page.next_key {
            Some(k) => key = Some(k),
            None => break,
        }
    }
    assert_eq!(seen.len(), 10);
    assert!(seen.iter().all(|p| p.proxy_id == "pa"));
    assert!(l
        .list_invocations(&allowed(&[]), None, 10)
        .unwrap()
        .items
        .is_empty());
    let two = l
        .list_invocations(&allowed(&["pa", "pb"]), None, 100)
        .unwrap();
    assert_eq!(two.items.len(), 20);
    assert!(two.items.iter().all(|p| p.proxy_id != "pc"));
    // combined with an explicit proxy_id (AND)
    let mut f = allowed(&["pa", "pb"]);
    f.proxy_id = Some("pb".into());
    let r = l.list_invocations(&f, None, 100).unwrap();
    assert_eq!(r.items.len(), 10);
    assert!(r.items.iter().all(|p| p.proxy_id == "pb"));
    f.proxy_id = Some("pc".into());
    assert!(l.list_invocations(&f, None, 100).unwrap().items.is_empty());
}

#[test]
fn m3_closed_tail_names_what_arrived_and_prefix_inherits_detection_time() {
    let d = tempfile::tempdir().unwrap();
    let l = open(d.path());
    l.insert_batch("px", &[seq_ev(1), seq_ev(2), seq_ev(3)], 5)
        .unwrap();
    l.note_last_assigned("px", EP1, 8, 10).unwrap(); // tail 4..=8 detected at 10
    l.insert_batch("px", &[seq_ev(6)], 50).unwrap(); // prefix 4..=5, tail 7..=8
    let g = l.gaps("px").unwrap();
    let prefix = g.iter().find(|x| !x.tail).unwrap();
    assert_eq!(
        (prefix.from_sequence, prefix.to_sequence),
        (Some(4), Some(5))
    );
    assert_eq!(prefix.detected_at, 10, "inherits the tail's detected_at");
    l.insert_batch("px", &[seq_ev(8)], 60).unwrap(); // the last one arrives first
    let g = l.gaps("px").unwrap();
    let tail = g.iter().find(|x| x.tail).unwrap();
    assert!(!tail.open);
    // never claims a missing range: it names the sequence that arrived
    assert_eq!((tail.from_sequence, tail.to_sequence), (Some(8), Some(8)));
    let seven = g.iter().find(|x| x.from_sequence == Some(7)).unwrap();
    assert!(
        !seven.tail && seven.open,
        "7 is still missing as an ordinary gap"
    );
    assert_eq!(seven.detected_at, 10);
}

#[test]
fn m4_filter_and_time_queries_use_the_new_indexes() {
    let d = tempfile::tempdir().unwrap();
    let l = open(d.path());
    l.insert_batch("px", &[start("px", 1, 1, 1, "ping", None)], 100)
        .unwrap();
    let c = rusqlite::Connection::open(d.path().join("l.sqlite")).unwrap();
    let plan = |sql: &str| -> String {
        let mut st = c.prepare(&format!("EXPLAIN QUERY PLAN {sql}")).unwrap();
        let rows: Vec<String> = st
            .query_map([], |r| r.get::<_, String>(3))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        rows.join(" | ")
    };
    let lifecycle = plan(
        "SELECT * FROM projections p WHERE p.proxy_id = 'px' AND p.lifecycle = 'started'
         AND p.created_seq < 99 ORDER BY p.created_seq DESC LIMIT 11",
    );
    assert!(
        lifecycle.contains("projections_proxy_lifecycle"),
        "{lifecycle}"
    );
    let upstream = plan(
        "SELECT * FROM projections p WHERE p.proxy_id = 'px' AND p.upstream_id = 'up1'
         ORDER BY p.created_seq DESC LIMIT 11",
    );
    assert!(
        upstream.contains("projections_proxy_upstream"),
        "{upstream}"
    );
    let range = plan(
        "SELECT count(*) FROM projections p WHERE p.proxy_id = 'px' AND p.first_received_at >= 1
         AND p.first_received_at < 999",
    );
    assert!(range.contains("projections_proxy_received"), "{range}");
    let time = plan(
        "SELECT * FROM projections p WHERE p.proxy_id = 'px' AND p.first_received_at >= 1
         AND p.first_received_at < 999 ORDER BY p.created_seq DESC LIMIT 11",
    );
    assert!(time.contains("projections_proxy_"), "{time}");
    let gaps = plan("SELECT * FROM gaps WHERE proxy_id = 'px' ORDER BY rowid_seq DESC LIMIT 50");
    assert!(gaps.contains("gaps_proxy_rowid"), "{gaps}");
    let counts =
        plan("SELECT kind, COUNT(*) FROM gaps WHERE proxy_id = 'px' AND open = 1 GROUP BY kind");
    assert!(counts.contains("gaps_proxy_open_kind"), "{counts}");
}

#[test]
fn m4_read_query_time_limit_returns_query_timeout_and_recovers() {
    let d = tempfile::tempdir().unwrap();
    let l = open(d.path());
    l.insert_batch("px", &[seq_ev(1)], 100).unwrap();
    l.set_read_timeout_for_test(50);
    let slow =
        "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c WHERE x < 2000000000)
                SELECT count(*) FROM c";
    let err = l.read_scalar_for_test(slow).unwrap_err();
    assert_eq!(err, LedgerError::QueryTimeout);
    assert_eq!(
        err.error_code(),
        Some(sigil_proxy_api::ErrorCode::StorageUnavailable)
    );
    // the pooled connections are not left interrupted
    l.set_read_timeout_for_test(5_000);
    for _ in 0..8 {
        assert_eq!(
            l.list_invocations(&InvocationFilter::default(), None, 10)
                .unwrap()
                .items
                .len(),
            1
        );
    }
}

#[test]
fn m4_concurrent_reads_run_on_the_pool_without_the_writer() {
    let d = tempfile::tempdir().unwrap();
    let l = open(d.path());
    let evs: Vec<ProxyEvent> = (1..=50).map(seq_ev).collect();
    l.insert_batch("px", &evs, 100).unwrap();
    l.with_writer_locked(|| {
        std::thread::scope(|s| {
            for _ in 0..8 {
                s.spawn(|| {
                    for _ in 0..20 {
                        let p = l
                            .list_invocations(&InvocationFilter::default(), None, 100)
                            .unwrap();
                        assert_eq!(p.items.len(), 50);
                    }
                });
            }
        });
    });
}

#[test]
fn l1_reader_opens_without_create_and_applies_path_checks_alone() {
    let d = tempfile::tempdir().unwrap();
    let missing = d.path().join("nope.sqlite");
    assert!(Ledger::open_read_only_probe(&missing).is_err());
    assert!(!missing.exists(), "the reader must not create the file");
    let p = d.path().join("l.sqlite");
    drop(Ledger::open(&p, LedgerOptions::default()).unwrap());
    assert!(Ledger::open_read_only_probe(&p).is_ok());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let link = d.path().join("link.sqlite");
        std::os::unix::fs::symlink(&p, &link).unwrap();
        assert!(Ledger::open_read_only_probe(&link).is_err());
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(Ledger::open_read_only_probe(&p).is_err());
    }
}

#[test]
fn l3_stale_epoch_report_opens_no_tail_but_a_new_epoch_does() {
    let d = tempfile::tempdir().unwrap();
    let l = open(d.path());
    l.insert_batch("px", &[seq_ev(1)], 100).unwrap();
    let e2 = start_full(
        "px", EP2, 1, 90, 90, "ping", "unknown", None, "up1", "actor-1",
    );
    l.insert_batch("px", &[e2], 101).unwrap();
    // EP1 is known but no longer the latest: ignored
    assert_eq!(
        l.note_last_assigned("px", EP1, 50, 110).unwrap(),
        TailGapChange::Unchanged
    );
    assert!(l.gaps("px").unwrap().iter().all(|g| !g.tail));
    assert_eq!(
        l.note_last_assigned("px", EP2, 4, 111).unwrap(),
        TailGapChange::Created
    );
    // an epoch with no row yet (first events not arrived) is accepted
    const EP3: &str = "33333333-3333-4333-8333-333333333333";
    assert_eq!(
        l.note_last_assigned("px", EP3, 2, 112).unwrap(),
        TailGapChange::Created
    );
}

#[test]
fn l5_tail_in_a_new_epoch_with_epoch_change_gap() {
    let d = tempfile::tempdir().unwrap();
    let l = open(d.path());
    l.insert_batch("px", &[seq_ev(1)], 100).unwrap();
    assert_eq!(
        l.note_last_assigned("px", EP2, 3, 110).unwrap(),
        TailGapChange::Created
    );
    let e = start_full(
        "px", EP2, 2, 91, 91, "ping", "unknown", None, "up1", "actor-1",
    );
    l.insert_batch("px", &[e], 120).unwrap();
    let g = l.gaps("px").unwrap();
    assert!(g
        .iter()
        .any(|x| x.kind == GapKind::ProducerEpochChange && x.open));
    let prefix = g
        .iter()
        .find(|x| x.kind == GapKind::SequenceGap && !x.tail)
        .unwrap();
    assert_eq!(
        (
            prefix.epoch_id.as_str(),
            prefix.from_sequence,
            prefix.to_sequence
        ),
        (EP2, Some(1), Some(1))
    );
    assert_eq!(prefix.detected_at, 110);
    let tail = g.iter().find(|x| x.tail).unwrap();
    assert!(tail.open);
    assert_eq!((tail.from_sequence, tail.to_sequence), (Some(3), Some(3)));
}

#[test]
fn l5_prefix_older_than_t_stays_open_when_filled() {
    let d = tempfile::tempdir().unwrap();
    let opts = LedgerOptions {
        tombstone_retention_secs: 1000,
        caps: LedgerCaps::default(),
    };
    let l = Ledger::open(&d.path().join("l.sqlite"), opts).unwrap();
    l.insert_batch("px", &[seq_ev(1)], 5).unwrap();
    l.note_last_assigned("px", EP1, 6, 10).unwrap(); // tail 2..=6 at t=10
    l.insert_batch("px", &[seq_ev(4)], 10_000).unwrap(); // prefix 2..=3 inherits t=10
    l.insert_batch("px", &[seq_ev(2), seq_ev(3)], 10_001)
        .unwrap();
    let g = l.gaps("px").unwrap();
    let prefix = g.iter().find(|x| !x.tail).unwrap();
    assert_eq!(prefix.detected_at, 10);
    assert!(
        prefix.open,
        "evidence older than T cannot close it (safe direction)"
    );
}

#[test]
fn l5_open_gap_cap_hit_by_a_tail_split_rolls_back() {
    let d = tempfile::tempdir().unwrap();
    let l = open(d.path());
    let evs: Vec<ProxyEvent> = (0..10_000).map(|i| seq_ev(2 * i + 1)).collect();
    l.insert_batch("px", &evs, 100).unwrap();
    assert_eq!(
        l.open_gap_counts("px").unwrap().get("sequence_gap"),
        Some(&9_999)
    );
    assert_eq!(
        l.note_last_assigned("px", EP1, 20_003, 110).unwrap(),
        TailGapChange::Created
    );
    // 20002 would split off a prefix gap: one open gap too many
    let r = l.insert_batch("px", &[seq_ev(20_002)], 120);
    assert_eq!(r, Err(LedgerError::StorageLimit));
    assert!(l.stored_event("px", &uuid(20_002)).unwrap().is_none());
    assert!(l
        .get_invocation("px", &uuid(20_002 + 5000))
        .unwrap()
        .is_none());
    let g = l.gaps("px").unwrap();
    let tail = g.iter().find(|x| x.tail).unwrap();
    assert!(tail.open);
    assert_eq!(
        (tail.from_sequence, tail.to_sequence),
        (Some(20_000), Some(20_003))
    );
    // the cap also refuses to create a further tail
    assert_eq!(
        l.note_last_assigned("px", EP2, 5, 130).map(|_| ()),
        Err(LedgerError::StorageLimit)
    );
}

#[test]
fn l5_storage_limit_and_check_batch_leave_no_projection() {
    let d = tempfile::tempdir().unwrap();
    let opts = LedgerOptions {
        tombstone_retention_secs: 86_400,
        caps: LedgerCaps::new(2, 1 << 30, 100, 1 << 30),
    };
    let l = Ledger::open(&d.path().join("l.sqlite"), opts).unwrap();
    l.insert_batch("px", &[seq_ev(1), seq_ev(2)], 100).unwrap();
    let r = l.insert_batch("px", &[seq_ev(3)], 101);
    assert_eq!(r, Err(LedgerError::StorageLimit));
    assert!(l.get_invocation("px", &uuid(5003)).unwrap().is_none());
    assert_eq!(
        l.list_invocations(&InvocationFilter::default(), None, 10)
            .unwrap()
            .items
            .len(),
        2
    );
    // dry run never stores, whatever it returns
    let _ = l.check_batch("px", &[seq_ev(9)], 102);
    assert!(l.get_invocation("px", &uuid(5009)).unwrap().is_none());
}

#[test]
fn l5_keyset_paging_with_inserts_between_pages() {
    let d = tempfile::tempdir().unwrap();
    let l = open(d.path());
    let evs: Vec<ProxyEvent> = (1..=10).map(seq_ev).collect();
    l.insert_batch("px", &evs, 100).unwrap();
    let p1 = l
        .list_invocations(&InvocationFilter::default(), None, 4)
        .unwrap();
    let ids1: Vec<String> = p1.items.iter().map(|p| p.invocation_id.clone()).collect();
    assert_eq!(
        ids1,
        (7..=10).rev().map(|i| uuid(i + 5000)).collect::<Vec<_>>()
    );
    // new invocations and a completion of an old one land between the pages
    l.insert_batch("px", &[seq_ev(11), seq_ev(12)], 101)
        .unwrap();
    l.insert_batch(
        "px",
        &[done("px", 13, 13, 8 + 5000, "success", "sent", None)],
        102,
    )
    .unwrap();
    let p2 = l
        .list_invocations(&InvocationFilter::default(), p1.next_key, 100)
        .unwrap();
    let ids2: Vec<String> = p2.items.iter().map(|p| p.invocation_id.clone()).collect();
    assert_eq!(
        ids2,
        (1..=6).rev().map(|i| uuid(i + 5000)).collect::<Vec<_>>()
    );
    assert!(p2.next_key.is_none());
}
