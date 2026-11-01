//! Contract tests for the wire DTOs.
//!
//! Ported from `docs/specs/lodeline-proxy/contracts/check_schema.py`: the contract
//! example round-trip, every rejected category of the event schema at least once,
//! the status `config` rules, representative status gap/counter/bound cases, and
//! registry entry/view/upload cases.
//!
//! NOT ported (the Python checker keeps them; they are reference models or
//! schema-meta checks, not DTO behaviour):
//!   * the full outcome x delivery x reason product (only the boundary cases are here);
//!   * the dedup `LedgerModel` (ledger behaviour is out of scope; only the canonical
//!     full-event comparison helper is tested);
//!   * batch-error models (`submit_batch`), registry ingest model, gap-hash model;
//!   * request-ID matching, startup/epoch-loss model, `metadata_ref` derivation
//!     and fingerprint reference models (proxy-local crypto, not wire shape);
//!   * retention, projection, cross-event semantic, cursor, inventory/marker,
//!     counter-merge and status-upsert models;
//!   * schema self-validation, format-checker preflight and `python -O` guards;
//!   * most registry/status mutation permutations (one per category is ported).
//!
//! Inventory report: the `reg_report` schema cases are ported at the end of this file
//! (same labels as `check_schema.py`); `maxItems`/`uniqueItems` are enforced. The
//! I-1..I-8 server rules and the drift/marker projection stay with the server.

use lodeline_proxy_api::canonical::{canonical_event_bytes, compare_for_dedup, DedupComparison};
use lodeline_proxy_api::event::{IngestRequest, IngestResponse};
use lodeline_proxy_api::registry::{InventoryReport, UploadRequest, UploadResponse};
use lodeline_proxy_api::status::StatusResponse;
use lodeline_proxy_api::{
    parse_api_error, parse_event, parse_event_batch, parse_ingest_response, parse_inventory_report,
    parse_status, parse_status_response, parse_upload, parse_upload_response, ErrorCategory,
    ParseError, Validate,
};
use lodeline_proxy_api::{ApiError, EntryView, ErrorCode, ProxyEvent, ProxyStatus, RegistryEntry};
use serde_json::{json, Value};

const EXAMPLE: &str =
    include_str!("../../../docs/specs/lodeline-proxy/contracts/invocation-started.example.json");
const INT64_MAX: i64 = i64::MAX;

fn example() -> Value {
    serde_json::from_str(EXAMPLE).unwrap()
}

fn set(mut v: Value, path: &[&str], new: Value) -> Value {
    let mut cur = &mut v;
    for key in &path[..path.len() - 1] {
        cur = cur.get_mut(*key).unwrap();
    }
    cur.as_object_mut()
        .unwrap()
        .insert(path[path.len() - 1].into(), new);
    v
}

fn del(mut v: Value, path: &[&str]) -> Value {
    let mut cur = &mut v;
    for key in &path[..path.len() - 1] {
        cur = cur.get_mut(*key).unwrap();
    }
    cur.as_object_mut()
        .unwrap()
        .remove(path[path.len() - 1])
        .unwrap();
    v
}

fn completion() -> Value {
    json!({
        "schema_version": 1,
        "event_id": "01998932-4100-7000-8000-000000000003",
        "proxy_id": "proxy-demo",
        "epoch_id": "3f1c9a52-6b0e-4d2a-9c1e-7a5b2d8e4f10",
        "sequence": 3,
        "occurred_at": "2026-09-27T08:00:01Z",
        "event_type": "invocation.completed",
        "payload": {
            "invocation_id": "01998932-4100-7000-8000-000000000002",
            "outcome": "success", "delivery_state": "sent",
            "duration_ms": 1200, "response_bytes": 32
        }
    })
}

fn cancel() -> Value {
    json!({
        "schema_version": 1,
        "event_id": "01998932-4100-7000-8000-000000000004",
        "proxy_id": "proxy-demo",
        "epoch_id": "3f1c9a52-6b0e-4d2a-9c1e-7a5b2d8e4f10",
        "sequence": 2,
        "occurred_at": "2026-09-27T08:00:00Z",
        "event_type": "invocation.cancel_requested",
        "payload": {"invocation_id": "01998932-4100-7000-8000-000000000002"}
    })
}

fn accepted(v: &Value) -> ProxyEvent {
    serde_json::from_value::<ProxyEvent>(v.clone())
        .unwrap_or_else(|e| panic!("expected accept, got {e}: {v}"))
}

fn rejected(label: &str, v: &Value) {
    assert!(
        serde_json::from_value::<ProxyEvent>(v.clone()).is_err(),
        "event case {label} was accepted: {v}"
    );
}

fn reject_all(cases: Vec<(String, Value)>) {
    for (label, v) in cases {
        rejected(&label, &v);
    }
}

// ---------------------------------------------------------------- events: positive

#[test]
fn example_round_trips_exactly() {
    let event: ProxyEvent = serde_json::from_str(EXAMPLE).unwrap();
    assert_eq!(serde_json::to_value(&event).unwrap(), example());
}

#[test]
fn positive_event_variants_round_trip() {
    let mut cases = vec![completion(), cancel()];
    for reason in [
        "not_in_inventory",
        "no_complete_inventory",
        "ambiguous_in_inventory",
        "registry_conflict",
    ] {
        cases.push(set(
            example(),
            &["payload", "tool"],
            json!({"status": "metadata_unavailable", "reason": reason}),
        ));
    }
    cases.push(set(
        example(),
        &["payload", "tool"],
        json!({"status": "unavailable", "reason": "malformed"}),
    ));
    for (path, v) in [
        (vec!["occurred_at"], json!("2026-09-27T08:00:00.5Z")),
        (vec!["occurred_at"], json!("2026-09-27T08:00:00.123456789Z")),
        (vec!["occurred_at"], json!("2026-12-31T23:59:59.999999999Z")),
        (vec!["occurred_at"], json!("2028-02-29T00:00:00Z")),
        (
            vec!["epoch_id"],
            json!("9b2e4c71-0d3a-4f6b-8e5c-1a7d9f3b2c64"),
        ),
        (vec!["sequence"], json!(INT64_MAX)),
        (vec!["payload", "route_revision"], json!(INT64_MAX)),
        (
            vec!["payload", "actor", "credential_owner_id"],
            json!("team-ops"),
        ),
        (vec!["payload", "actor", "actor_kind"], json!("unknown")),
        (
            vec!["payload", "actor", "authentication_method"],
            json!("mtls"),
        ),
    ] {
        cases.push(set(example(), &path, v));
    }
    for method in ["initialize", "ping", "tools/list", "unknown"] {
        let mut e = del(example(), &["payload", "tool"]);
        e = set(e, &["payload", "method"], json!(method));
        if method == "initialize" {
            e = set(e, &["payload", "protocol_version"], json!("unknown"));
        }
        cases.push(e);
    }
    for field in ["duration_ms", "response_bytes"] {
        cases.push(set(completion(), &["payload", field], json!(INT64_MAX)));
    }
    // Representative allowed outcome/delivery/reason combinations.
    for (o, d, r) in [
        (
            "protocol_error",
            "not_sent",
            Some("modern_request_unsupported"),
        ),
        (
            "protocol_error",
            "sent",
            Some("task_augmentation_unsupported"),
        ),
        (
            "protocol_error",
            "not_sent",
            Some("task_augmentation_unsupported"),
        ),
        (
            "protocol_error",
            "sent",
            Some("upstream_capability_unsupported"),
        ),
        ("unknown", "unknown", Some("cancel_no_response")),
        ("unknown", "not_sent", Some("cancelled_before_dispatch")),
        ("denied", "not_sent", None),
        ("timeout", "unknown", None),
        ("tool_error", "sent", None),
    ] {
        let mut e = set(completion(), &["payload", "outcome"], json!(o));
        e = set(e, &["payload", "delivery_state"], json!(d));
        if let Some(r) = r {
            e = set(e, &["payload", "reason"], json!(r));
        }
        cases.push(e);
    }
    for v in &cases {
        let event = accepted(v);
        assert_eq!(&serde_json::to_value(&event).unwrap(), v);
    }
}

// ---------------------------------------------------------------- events: rejected

#[test]
fn rejects_closed_object_and_identity_violations() {
    let ex = example();
    let mut cases: Vec<(String, Value)> = vec![
        (
            "raw arguments".into(),
            set(
                ex.clone(),
                &["payload", "arguments"],
                json!({"token": "canary"}),
            ),
        ),
        (
            "unknown schema".into(),
            set(ex.clone(), &["schema_version"], json!(2)),
        ),
        (
            "human self claim".into(),
            set(
                ex.clone(),
                &["payload", "actor", "actor_kind"],
                json!("human"),
            ),
        ),
        (
            "bad event uuid".into(),
            set(ex.clone(), &["event_id"], json!("invalid")),
        ),
        (
            "zero sequence".into(),
            set(ex.clone(), &["sequence"], json!(0)),
        ),
        (
            "raw error".into(),
            set(completion(), &["payload", "raw_error"], json!("canary")),
        ),
        (
            "raw result".into(),
            set(completion(), &["payload", "result"], json!("canary")),
        ),
        (
            "unknown event".into(),
            set(ex.clone(), &["event_type"], json!("unknown")),
        ),
        (
            "raw tool name".into(),
            set(
                ex.clone(),
                &["payload", "tool_name"],
                json!("canary-secret"),
            ),
        ),
        (
            "tool object raw name".into(),
            set(
                ex.clone(),
                &["payload", "tool", "name"],
                json!("canary-secret"),
            ),
        ),
        (
            "raw metadata ref".into(),
            set(
                ex.clone(),
                &["payload", "tool", "metadata_ref"],
                json!("canary-secret"),
            ),
        ),
        (
            "cancel as terminal outcome".into(),
            set(
                completion(),
                &["payload", "outcome"],
                json!("cancel_requested"),
            ),
        ),
        (
            "cancel raw reason".into(),
            set(cancel(), &["payload", "reason"], json!("canary-secret")),
        ),
        (
            "cancel outcome".into(),
            set(cancel(), &["payload", "outcome"], json!("success")),
        ),
        (
            "missing actor".into(),
            del(ex.clone(), &["payload", "actor"]),
        ),
        (
            "missing tool on tools/call".into(),
            del(ex.clone(), &["payload", "tool"]),
        ),
        (
            "top-level extra".into(),
            set(ex.clone(), &["extra"], json!(1)),
        ),
        (
            "payload not an object".into(),
            set(ex.clone(), &["payload"], json!([])),
        ),
        (
            "payload null".into(),
            set(ex.clone(), &["payload"], Value::Null),
        ),
        ("envelope as array".into(), json!([])),
        (
            "actor as array".into(),
            set(
                ex.clone(),
                &["payload", "actor"],
                json!([
                    "client-demo",
                    "non_human",
                    "bearer",
                    "proxy_credential_mapping"
                ]),
            ),
        ),
        // event_type cannot change with an identical payload.
        (
            "type swapped to cancel".into(),
            set(
                ex.clone(),
                &["event_type"],
                json!("invocation.cancel_requested"),
            ),
        ),
    ];
    for bad in [
        json!("canary-secret"),
        json!("not-a-date"),
        json!(""),
        json!("2026-09-27T08:00:00Z\n"),
        json!("2026-09-27T08:00:00+00:00"),
        json!("2026-09-27t08:00:00z"),
        json!("2026-09-27 08:00:00Z"),
        json!("2026-09-27T08:00:00.1234567890Z"),
        json!("2026-13-01T00:00:00Z"),
        json!("2026-02-30T00:00:00Z"),
        json!("2027-02-29T00:00:00Z"),
        json!("2026-12-31T23:59:60Z"),
        json!(1727424000),
    ] {
        cases.push((
            format!("occurred_at {bad}"),
            set(ex.clone(), &["occurred_at"], bad),
        ));
    }
    for (label, value) in [
        ("raw", json!("canary-secret")),
        ("empty", json!("")),
        ("uppercase", json!("3F1C9A52-6B0E-4D2A-9C1E-7A5B2D8E4F10")),
        ("integer", json!(1)),
        ("newline", json!("3f1c9a52-6b0e-4d2a-9c1e-7a5b2d8e4f10\n")),
    ] {
        cases.push((
            format!("epoch_id {label}"),
            set(ex.clone(), &["epoch_id"], value),
        ));
    }
    cases.push(("epoch_id missing".into(), del(ex.clone(), &["epoch_id"])));
    for path in [
        vec!["event_id"],
        vec!["payload", "invocation_id"],
        vec!["payload", "tool", "metadata_ref"],
    ] {
        cases.push((
            format!("uppercase {path:?}"),
            set(
                ex.clone(),
                &path,
                json!("0C635E55-7E09-8E3D-978F-4B88870428F1"),
            ),
        ));
        cases.push((
            format!("newline {path:?}"),
            set(
                ex.clone(),
                &path,
                json!("0c635e55-7e09-8e3d-978f-4b88870428f1\n"),
            ),
        ));
    }
    for path in [
        vec!["proxy_id"],
        vec!["payload", "upstream_id"],
        vec!["payload", "actor", "actor_id"],
    ] {
        cases.push((
            format!("id newline {path:?}"),
            set(ex.clone(), &path, json!("proxy-demo\n")),
        ));
    }
    reject_all(cases);
}

#[test]
fn rejects_actor_provenance_violations() {
    let ex = example();
    let a = |field: &str, v: Value| set(ex.clone(), &["payload", "actor", field], v);
    reject_all(vec![
        (
            "missing evidence_source".into(),
            del(ex.clone(), &["payload", "actor", "evidence_source"]),
        ),
        (
            "client-asserted evidence".into(),
            a("evidence_source", json!("client_asserted")),
        ),
        (
            "authentication none".into(),
            a("authentication_method", json!("none")),
        ),
        (
            "authentication unknown".into(),
            a("authentication_method", json!("unknown")),
        ),
        (
            "missing authentication".into(),
            del(ex.clone(), &["payload", "actor", "authentication_method"]),
        ),
        ("human flag".into(), a("human", json!(true))),
        (
            "client tool-use id".into(),
            a("client_tool_use_id", json!("toolu_canary")),
        ),
        (
            "clientInfo".into(),
            a("client_info", json!({"name": "canary"})),
        ),
        (
            "raw owner".into(),
            a("credential_owner_id", json!("canary secret")),
        ),
        ("owner null".into(), a("credential_owner_id", Value::Null)),
        (
            "_meta in payload".into(),
            set(
                ex.clone(),
                &["payload", "_meta"],
                json!({"claudecode/toolUseId": "x"}),
            ),
        ),
    ]);
}

#[test]
fn rejects_tool_state_violations() {
    let ex = example();
    let ref_ = ex["payload"]["tool"]["metadata_ref"].clone();
    let t = |tool: Value| set(ex.clone(), &["payload", "tool"], tool);
    reject_all(vec![
        (
            "withdrawn unresolved".into(),
            t(json!({"status": "unavailable", "reason": "unresolved"})),
        ),
        (
            "unavailable plus reference".into(),
            t(json!({"status": "unavailable", "reason": "malformed", "metadata_ref": ref_})),
        ),
        (
            "metadata_unavailable plus reference".into(),
            t(
                json!({"status": "metadata_unavailable", "reason": "not_in_inventory", "metadata_ref": ref_}),
            ),
        ),
        (
            "metadata_unavailable without reason".into(),
            t(json!({"status": "metadata_unavailable"})),
        ),
        (
            "cross-status reason".into(),
            t(json!({"status": "unavailable", "reason": "not_in_inventory"})),
        ),
        (
            "cross-status reason 2".into(),
            t(json!({"status": "metadata_unavailable", "reason": "malformed"})),
        ),
        (
            "raw name on metadata_unavailable".into(),
            t(
                json!({"status": "metadata_unavailable", "reason": "not_in_inventory", "name": "canary"}),
            ),
        ),
        (
            "random v4 reference".into(),
            t(
                json!({"status": "identified", "metadata_ref": "0c635e55-7e09-4e3d-978f-4b88870428f1"}),
            ),
        ),
        (
            "bad variant nibble".into(),
            t(
                json!({"status": "identified", "metadata_ref": "0c635e55-7e09-8e3d-478f-4b88870428f1"}),
            ),
        ),
        ("empty tool".into(), t(json!({}))),
        (
            "identified without reference".into(),
            t(json!({"status": "identified"})),
        ),
        (
            "unavailable without reason".into(),
            t(json!({"status": "unavailable"})),
        ),
        ("tool null".into(), t(Value::Null)),
        (
            "tool on tools/list".into(),
            set(ex.clone(), &["payload", "method"], json!("tools/list")),
        ),
    ]);
}

#[test]
fn rejects_unsafe_audit_vocabulary() {
    let ex = example();
    let mut cases = Vec::new();
    for field in ["method", "protocol_version"] {
        for value in [
            json!("canary-secret"),
            json!(""),
            Value::Null,
            json!({"secret": "canary"}),
            json!("2026-07-28"),
            json!("2025-06-18"),
            json!("tasks/get"),
        ] {
            cases.push((
                format!("{field} {value}"),
                set(ex.clone(), &["payload", field], value),
            ));
        }
    }
    let init = set(
        del(ex.clone(), &["payload", "tool"]),
        &["payload", "method"],
        json!("initialize"),
    );
    cases.push(("initialize with negotiated version".into(), init));
    for bad in [
        json!("canary-secret"),
        json!("cancel_requested"),
        json!("timeout"),
        json!(""),
        Value::Null,
        json!("registry_conflict"),
        json!("upstream_unsupported"),
        json!("2026-07-28"),
    ] {
        cases.push((
            format!("completion reason {bad}"),
            set(completion(), &["payload", "reason"], bad),
        ));
    }
    cases.push((
        "raw modern method".into(),
        set(
            del(ex.clone(), &["payload", "tool"]),
            &["payload", "method"],
            json!("server/discover"),
        ),
    ));
    cases.push((
        "raw task field on start".into(),
        set(ex.clone(), &["payload", "task"], json!({"ttl": 60000})),
    ));
    reject_all(cases);
}

#[test]
fn rejects_inconsistent_completion_matrix() {
    for (o, d, r) in [
        ("success", "not_sent", None),
        ("success", "unknown", None),
        ("tool_error", "not_sent", None),
        ("denied", "sent", None),
        ("denied", "unknown", None),
        ("success", "sent", Some("task_augmentation_unsupported")),
        (
            "protocol_error",
            "unknown",
            Some("task_augmentation_unsupported"),
        ),
        (
            "protocol_error",
            "not_sent",
            Some("upstream_capability_unsupported"),
        ),
        (
            "protocol_error",
            "unknown",
            Some("upstream_version_unsupported"),
        ),
        ("protocol_error", "sent", Some("modern_request_unsupported")),
        ("unknown", "not_sent", Some("cancel_no_response")),
        ("unknown", "sent", Some("cancelled_before_dispatch")),
        ("timeout", "not_sent", Some("cancel_no_response")),
    ] {
        let mut e = set(completion(), &["payload", "outcome"], json!(o));
        e = set(e, &["payload", "delivery_state"], json!(d));
        if let Some(r) = r {
            e = set(e, &["payload", "reason"], json!(r));
        }
        rejected(&format!("{o}/{d}/{r:?}"), &e);
    }
}

#[test]
fn rejects_out_of_bound_and_non_integer_numbers() {
    let ex = example();
    let mut cases = Vec::new();
    for path in [vec!["sequence"], vec!["payload", "route_revision"]] {
        for bad in [
            json!(0),
            json!(-1),
            json!(1.0),
            json!(true),
            json!(2u64.pow(63)),
            json!(1e70),
        ] {
            cases.push((format!("{path:?} {bad}"), set(ex.clone(), &path, bad)));
        }
    }
    for field in ["duration_ms", "response_bytes"] {
        for bad in [
            json!(-1),
            json!(1.0),
            json!(2u64.pow(63)),
            json!("1"),
            Value::Null,
        ] {
            cases.push((
                format!("{field} {bad}"),
                set(completion(), &["payload", field], bad),
            ));
        }
    }
    reject_all(cases);
}

#[test]
fn rejects_float_integer_tokens() {
    // A standard JSON Schema validator accepts 1.0; the contract does not.
    for token in ["1.0", "1e0", "1E0", "1.00"] {
        let text = EXAMPLE.replacen("\"sequence\": 1,", &format!("\"sequence\": {token},"), 1);
        assert_ne!(text, EXAMPLE);
        assert!(
            serde_json::from_str::<ProxyEvent>(&text).is_err(),
            "token {token}"
        );
    }
}

// ---------------------------------------------------------------- dedup

#[test]
fn canonical_comparison_follows_the_dedup_rule() {
    let stored = accepted(&completion());
    let same_reordered: ProxyEvent = serde_json::from_str(
        r#"{"payload":{"response_bytes":32,"duration_ms":1200,"delivery_state":"sent","outcome":"success","invocation_id":"01998932-4100-7000-8000-000000000002"},
            "event_type":"invocation.completed","occurred_at":"2026-09-27T08:00:01Z","sequence":3,
            "epoch_id":"3f1c9a52-6b0e-4d2a-9c1e-7a5b2d8e4f10","proxy_id":"proxy-demo",
            "event_id":"01998932-4100-7000-8000-000000000003","schema_version":1}"#,
    )
    .unwrap();
    assert_eq!(
        canonical_event_bytes(&stored),
        canonical_event_bytes(&same_reordered)
    );
    assert_eq!(
        compare_for_dedup(&stored, &same_reordered),
        DedupComparison::Duplicate
    );

    for (label, changed) in [
        (
            "timestamp spelling",
            set(
                completion(),
                &["occurred_at"],
                json!("2026-09-27T08:00:01.0Z"),
            ),
        ),
        (
            "payload field",
            set(completion(), &["payload", "duration_ms"], json!(1201)),
        ),
        ("sequence", set(completion(), &["sequence"], json!(4))),
        (
            "epoch",
            set(
                completion(),
                &["epoch_id"],
                json!("9b2e4c71-0d3a-4f6b-8e5c-1a7d9f3b2c64"),
            ),
        ),
    ] {
        let other = accepted(&changed);
        assert_eq!(
            compare_for_dedup(&stored, &other),
            DedupComparison::Conflict,
            "{label}"
        );
    }
}

// ---------------------------------------------------------------- status

fn hash() -> String {
    "ab".repeat(32)
}

fn ts() -> &'static str {
    "2026-10-10T02:00:00Z"
}

fn uid(n: u32) -> String {
    format!("00000000-0000-4000-8000-{n:012x}")
}

fn status() -> Value {
    json!({
        "schema_version": 1, "report_id": uid(1), "proxy_id": "proxy-demo",
        "epoch_id": "3f1c9a52-6b0e-4d2a-9c1e-7a5b2d8e4f10", "status_sequence": 7,
        "last_assigned_sequence": 12, "sent_at": ts(),
        "config": {"state": "valid", "applied_revision": 4, "observed_desired_revision": 5,
                   "expires_at": "2026-10-11T02:00:00Z", "last_update_error": "fetch_failed",
                   "config_hash": hash(), "max_offline_retry_age_seconds": 2592000,
                   "event_retention_seconds": 7776000},
        "spool": {"state": "ok", "depth_events": 12, "unsent_events": 3, "bytes": 4096,
                  "capacity_bytes": 1073741824, "oldest_unsent_age_seconds": 40,
                  "quarantined_events": 0},
        "registry": {"pending_entries": 0, "sync_stalled": false},
        "central": {"last_ingest_ack_at": "2026-10-10T01:59:30Z", "consecutive_failures": 0},
        "routes": [{"upstream_id": "fixture", "state": "supported"},
                   {"upstream_id": "tasks-upstream", "state": "unsupported",
                    "reason": "upstream_capability_unsupported"}],
        "counters": {"auth_failures": [
                        {"upstream_id": "fixture", "reason": "credential_invalid", "count": 3},
                        {"upstream_id": null, "reason": "credential_missing", "count": 1}],
                     "unmatched_cancels": [
                        {"upstream_id": "fixture", "reason": "window_expired", "count": 2}]},
        "gaps": []
    })
}

fn metadata_ref() -> String {
    "3f4720a0-484d-8103-a955-96953753827d".into()
}

fn gaps() -> Vec<Value> {
    vec![
        json!({"gap_id": uid(10), "kind": "registry_conflict", "detected_at": ts(),
               "metadata_ref": metadata_ref(), "key_id": "kid-3c8e1f0a9b7d42e6a1c5f804",
               "event_ids": [uid(11)], "affected_event_count": 1, "detected_by": "central_409"}),
        json!({"gap_id": uid(12), "kind": "event_quarantined", "detected_at": ts(),
               "event_ids": [uid(13)], "code": "conflict"}),
        json!({"gap_id": uid(14), "kind": "local_record_failed", "detected_at": ts(),
               "count": 1, "invocation_ids": [uid(15)]}),
        json!({"gap_id": uid(16), "kind": "spool_expired", "detected_at": ts(),
               "epoch_id": uid(17), "from_sequence": 3, "to_sequence": 9, "count": 7}),
        json!({"gap_id": uid(18), "kind": "unrecorded_calls", "detected_at": ts(), "count": 4,
               "from_at": "2026-10-10T01:00:00Z", "to_at": "2026-10-10T01:05:00Z"}),
        json!({"gap_id": uid(19), "kind": "central_outage", "detected_at": ts(),
               "started_at": "2026-10-10T01:00:00Z", "ended_at": null}),
    ]
}

#[test]
fn parse_status_reports_the_first_bad_gap_index() {
    let mut v = status();
    let mut g = gaps();
    g[2]["count"] = json!(0); // local_record_failed needs count >= 1
    g[4]["surprise"] = json!(1);
    v["gaps"] = json!(g);
    let e = lodeline_proxy_api::parse_status(v.to_string().as_bytes()).unwrap_err();
    assert_eq!(e.index(), Some(2), "first bad gap");
    // a failure elsewhere has no index
    let mut v = status();
    v["gaps"] = json!(gaps());
    v["spool"]["bytes"] = json!(-1);
    let e = lodeline_proxy_api::parse_status(v.to_string().as_bytes()).unwrap_err();
    assert_eq!(e.index(), None);
    // an unknown gap kind is attributable too
    let mut v = status();
    v["gaps"] = json!([gaps()[0].clone(), {"gap_id": uid(40), "kind": "nope"}]);
    let e = lodeline_proxy_api::parse_status(v.to_string().as_bytes()).unwrap_err();
    assert_eq!(e.index(), Some(1));
}

fn status_ok(v: &Value) {
    let s: ProxyStatus = serde_json::from_value(v.clone()).unwrap_or_else(|e| panic!("{e}: {v}"));
    assert_eq!(&serde_json::to_value(&s).unwrap(), v);
}

fn status_bad(label: &str, v: Value) {
    assert!(
        serde_json::from_value::<ProxyStatus>(v.clone()).is_err(),
        "status case {label} was accepted"
    );
}

fn with_config(over: &[(&str, Value)]) -> Value {
    let mut cfg = status()["config"].clone();
    for (k, v) in over {
        cfg[*k] = v.clone();
    }
    set(status(), &["config"], cfg)
}

#[test]
fn status_positive_cases_round_trip() {
    status_ok(&status());
    status_ok(&set(status(), &["gaps"], Value::Array(gaps())));
    status_ok(&set(
        status(),
        &["config"],
        json!({"state": "none", "applied_revision": null, "observed_desired_revision": null, "expires_at": null}),
    ));
    for state in ["none", "valid", "expired", "disabled"] {
        status_ok(&with_config(&[("state", json!(state))]));
    }
    for err in [
        "stale_revision",
        "validation_failed",
        "fetch_failed",
        "apply_failed",
        "config_hash_mismatch",
    ] {
        status_ok(&with_config(&[("last_update_error", json!(err))]));
    }
    // config_hash is optional for none/expired.
    for state in ["none", "expired"] {
        let cfg = del(status()["config"].clone(), &["config_hash"]);
        status_ok(&set(
            status(),
            &["config"],
            set(cfg, &["state"], json!(state)),
        ));
    }
    let resp =
        json!({"state_applied": false, "acknowledged_gap_ids": [uid(1)], "duplicate_gap_ids": []});
    let parsed: StatusResponse = serde_json::from_value(resp.clone()).unwrap();
    assert_eq!(serde_json::to_value(parsed).unwrap(), resp);
}

#[test]
fn status_config_hash_required_when_valid_or_disabled() {
    for state in ["valid", "disabled"] {
        let cfg = del(status()["config"].clone(), &["config_hash"]);
        status_bad(
            &format!("{state} without config_hash"),
            set(status(), &["config"], set(cfg, &["state"], json!(state))),
        );
    }
    // valid additionally needs the echoed R/E values.
    let cfg = json!({"state": "valid", "applied_revision": 4, "observed_desired_revision": 5,
                     "expires_at": "2026-10-11T02:00:00Z", "config_hash": hash()});
    status_bad("valid without R/E", set(status(), &["config"], cfg));
}

#[test]
fn status_rejected_cases() {
    let h = hash();
    let spool = status()["spool"].clone();
    let counters =
        |auth: Value, cancels: Value| json!({"auth_failures": auth, "unmatched_cancels": cancels});
    let cases: Vec<(&str, Value)> = vec![
        (
            "state raw",
            with_config(&[("state", json!("canary-secret"))]),
        ),
        (
            "state suspended",
            with_config(&[("state", json!("suspended"))]),
        ),
        (
            "error raw",
            with_config(&[("last_update_error", json!("canary-secret"))]),
        ),
        (
            "error revision_regression",
            with_config(&[("last_update_error", json!("revision_regression"))]),
        ),
        (
            "hash uppercase",
            with_config(&[("config_hash", json!(h.to_uppercase()))]),
        ),
        (
            "hash short",
            with_config(&[("config_hash", json!(&h[..63]))]),
        ),
        (
            "hash newline",
            with_config(&[("config_hash", json!(format!("{h}\n")))]),
        ),
        ("hash integer", with_config(&[("config_hash", json!(1))])),
        (
            "R below bound",
            with_config(&[("max_offline_retry_age_seconds", json!(0))]),
        ),
        (
            "R above 90 days",
            with_config(&[("max_offline_retry_age_seconds", json!(91 * 86400))]),
        ),
        (
            "E float",
            with_config(&[("event_retention_seconds", json!(1.0))]),
        ),
        (
            "applied_revision zero",
            with_config(&[("applied_revision", json!(0))]),
        ),
        (
            "missing last_assigned_sequence",
            del(status(), &["last_assigned_sequence"]),
        ),
        (
            "negative last_assigned_sequence",
            set(status(), &["last_assigned_sequence"], json!(-1)),
        ),
        ("missing epoch", del(status(), &["epoch_id"])),
        ("missing gaps", del(status(), &["gaps"])),
        (
            "top-level actor",
            set(status(), &["actor"], json!({"actor_id": "agent-1"})),
        ),
        (
            "top-level token",
            set(status(), &["token"], json!("canary-secret")),
        ),
        (
            "sent_at not a date",
            set(status(), &["sent_at"], json!("canary-secret")),
        ),
        (
            "status_sequence zero",
            set(status(), &["status_sequence"], json!(0)),
        ),
        (
            "schema_version 2",
            set(status(), &["schema_version"], json!(2)),
        ),
        (
            "spool state raw",
            set(
                status(),
                &["spool"],
                set(spool.clone(), &["state"], json!("canary")),
            ),
        ),
        (
            "spool negative",
            set(
                status(),
                &["spool"],
                set(spool.clone(), &["bytes"], json!(-1)),
            ),
        ),
        (
            "spool zero capacity",
            set(
                status(),
                &["spool"],
                set(spool.clone(), &["capacity_bytes"], json!(0)),
            ),
        ),
        (
            "route state raw",
            set(
                status(),
                &["routes"],
                json!([{"upstream_id": "fixture", "state": "canary"}]),
            ),
        ),
        (
            "route reason raw",
            set(
                status(),
                &["routes"],
                json!([{"upstream_id": "fixture", "state": "degraded", "reason": "canary-secret"}]),
            ),
        ),
        (
            "257 routes",
            set(
                status(),
                &["routes"],
                Value::Array(vec![json!({"upstream_id": "f", "state": "supported"}); 257]),
            ),
        ),
        (
            "counter unknown reason",
            set(
                status(),
                &["counters"],
                counters(
                    json!([{"upstream_id": "fixture", "reason": "canary-secret", "count": 1}]),
                    json!([]),
                ),
            ),
        ),
        (
            "counter reason on wrong list",
            set(
                status(),
                &["counters"],
                counters(
                    json!([{"upstream_id": "fixture", "reason": "window_expired", "count": 1}]),
                    json!([]),
                ),
            ),
        ),
        (
            "counter with actor",
            set(
                status(),
                &["counters"],
                counters(
                    json!([{"upstream_id": "fixture", "reason": "credential_invalid", "count": 1, "actor_id": "agent-1"}]),
                    json!([]),
                ),
            ),
        ),
        (
            "counter negative",
            set(
                status(),
                &["counters"],
                counters(
                    json!([{"upstream_id": "fixture", "reason": "credential_invalid", "count": -1}]),
                    json!([]),
                ),
            ),
        ),
        (
            "counter float",
            set(
                status(),
                &["counters"],
                counters(
                    json!([]),
                    json!([{"upstream_id": "fixture", "reason": "window_expired", "count": 1.0}]),
                ),
            ),
        ),
        (
            "counter missing route key",
            set(
                status(),
                &["counters"],
                counters(
                    json!([{"reason": "credential_invalid", "count": 1}]),
                    json!([]),
                ),
            ),
        ),
        (
            "counters missing list",
            set(status(), &["counters"], json!({"auth_failures": []})),
        ),
        (
            "1537 counters",
            set(
                status(),
                &["counters"],
                counters(
                    Value::Array(vec![
                        json!({"upstream_id": null, "reason": "credential_missing", "count": 1});
                        1537
                    ]),
                    json!([]),
                ),
            ),
        ),
    ];
    for (label, v) in cases {
        status_bad(label, v);
    }
}

#[test]
fn status_gap_rejected_cases() {
    let g = gaps();
    let with = |gap: Value| set(status(), &["gaps"], json!([gap]));
    let rc = g[0].clone();
    let cases: Vec<(&str, Value)> = vec![
        (
            "raw name in gap",
            with(set(rc.clone(), &["name"], json!("json_ok"))),
        ),
        (
            "gap carries fingerprint",
            with(set(rc.clone(), &["fingerprint"], json!(hash()))),
        ),
        (
            "registry gap without ids",
            with(set(rc.clone(), &["event_ids"], json!([]))),
        ),
        (
            "registry gap 101 ids",
            with(set(
                rc.clone(),
                &["event_ids"],
                Value::Array((0..101).map(|n| json!(uid(100 + n))).collect()),
            )),
        ),
        (
            "registry gap duplicate ids",
            with(set(rc.clone(), &["event_ids"], json!([uid(11), uid(11)]))),
        ),
        (
            "registry gap without affected count",
            with(del(rc.clone(), &["affected_event_count"])),
        ),
        (
            "registry gap zero affected count",
            with(set(rc.clone(), &["affected_event_count"], json!(0))),
        ),
        (
            "registry gap bad detector",
            with(set(rc.clone(), &["detected_by"], json!("canary-secret"))),
        ),
        (
            "quarantine unknown code",
            with(set(g[1].clone(), &["code"], json!("canary-secret"))),
        ),
        (
            "quarantine with payload",
            with(set(
                g[1].clone(),
                &["payload"],
                json!({"arguments": "canary"}),
            )),
        ),
        (
            "unknown gap kind",
            with(set(g[5].clone(), &["kind"], json!("canary"))),
        ),
        ("gap without kind", with(del(g[5].clone(), &["kind"]))),
        ("gap without gap_id", with(del(g[5].clone(), &["gap_id"]))),
        (
            "local_record_failed zero count",
            with(set(g[2].clone(), &["count"], json!(0))),
        ),
        (
            "spool_expired without epoch",
            with(del(g[3].clone(), &["epoch_id"])),
        ),
        (
            "central_outage without ended_at",
            with(del(g[5].clone(), &["ended_at"])),
        ),
        (
            "101 gaps",
            set(status(), &["gaps"], Value::Array(vec![g[5].clone(); 101])),
        ),
    ];
    for (label, v) in cases {
        status_bad(label, v);
    }
}

// ---------------------------------------------------------------- registry

fn entry() -> Value {
    json!({
        "proxy_id": "proxy-demo", "metadata_ref": metadata_ref(), "upstream_id": "fixture",
        "credential_scope_id": "scope-1", "protocol_version": "2025-11-25",
        "observation_source": "proxy_live", "canon": "sigil-tooldef-fp-v1",
        "key_id": "kid-3c8e1f0a9b7d42e6a1c5f804", "fingerprint": hash(),
        "observed_at": "2026-10-10T00:00:00Z",
        "definition": {"name": "json_ok", "inputSchema": {"type": "object"}}
    })
}

#[test]
fn registry_entry_view_and_upload_round_trip() {
    let e: RegistryEntry = serde_json::from_value(entry()).unwrap();
    assert_eq!(serde_json::to_value(&e).unwrap(), entry());

    let view = json!({
        "proxy_id": "proxy-demo", "metadata_ref": metadata_ref(), "upstream_id": "fixture",
        "credential_scope_id": "scope-1", "protocol_version": "2025-11-25",
        "observation_source": "proxy_live", "canon": "sigil-tooldef-fp-v1",
        "key_id": "kid-3c8e1f0a9b7d42e6a1c5f804", "first_observed_at": ts(),
        "last_observed_at": ts(), "registered_at": ts(), "content_state": "present"
    });
    let v: EntryView = serde_json::from_value(view.clone()).unwrap();
    assert_eq!(serde_json::to_value(&v).unwrap(), view);

    let up = json!({"schema_version": 1, "proxy_id": "proxy-demo", "entries": [entry()]});
    let parsed: UploadRequest = serde_json::from_value(up.clone()).unwrap();
    assert_eq!(serde_json::to_value(&parsed).unwrap(), up);
    let resp = json!({"registered_metadata_refs": [metadata_ref()], "duplicate_metadata_refs": []});
    let parsed: UploadResponse = serde_json::from_value(resp.clone()).unwrap();
    assert_eq!(serde_json::to_value(&parsed).unwrap(), resp);
}

#[test]
fn registry_equality_ignores_volatile_fields() {
    let a: RegistryEntry = serde_json::from_value(entry()).unwrap();
    let b: RegistryEntry = serde_json::from_value(set(
        set(entry(), &["observed_at"], json!("2026-10-10T01:00:00Z")),
        &["definition"],
        json!({"name": "other"}),
    ))
    .unwrap();
    assert!(a.immutable_eq(&b));
    let c: RegistryEntry =
        serde_json::from_value(set(entry(), &["fingerprint"], json!("11".repeat(32)))).unwrap();
    assert!(!a.immutable_eq(&c));
}

#[test]
fn registry_rejected_cases() {
    let bad = |label: &str, v: Value| {
        assert!(
            serde_json::from_value::<RegistryEntry>(v).is_err(),
            "entry case {label} accepted"
        );
    };
    bad("empty definition", set(entry(), &["definition"], json!({})));
    bad(
        "definition array",
        set(entry(), &["definition"], json!([1])),
    );
    bad("missing definition", del(entry(), &["definition"]));
    bad("extra field", set(entry(), &["extra"], json!(1)));
    bad(
        "v4 metadata_ref",
        set(
            entry(),
            &["metadata_ref"],
            json!("0c635e55-7e09-4e3d-978f-4b88870428f1"),
        ),
    );
    bad("key_id short", set(entry(), &["key_id"], json!("kid-abc")));
    bad(
        "fingerprint uppercase",
        set(entry(), &["fingerprint"], json!(hash().to_uppercase())),
    );
    bad(
        "protocol version other",
        set(entry(), &["protocol_version"], json!("2026-07-28")),
    );
    bad(
        "canon other",
        set(entry(), &["canon"], json!("sigil-tooldef-fp-v2")),
    );
    bad(
        "source other",
        set(entry(), &["observation_source"], json!("offline")),
    );
    bad(
        "observed_at bad",
        set(entry(), &["observed_at"], json!("2026-02-30T00:00:00Z")),
    );

    let view_bad = |label: &str, field: &str, v: Value| {
        let mut view = json!({
            "proxy_id": "proxy-demo", "metadata_ref": metadata_ref(), "upstream_id": "fixture",
            "credential_scope_id": "scope-1", "protocol_version": "2025-11-25",
            "observation_source": "proxy_live", "canon": "sigil-tooldef-fp-v1",
            "key_id": "kid-3c8e1f0a9b7d42e6a1c5f804", "registered_at": ts(), "content_state": "present"
        });
        view[field] = v;
        assert!(
            serde_json::from_value::<EntryView>(view).is_err(),
            "view case {label} accepted"
        );
    };
    view_bad("view fingerprint", "fingerprint", json!(hash()));
    view_bad("view definition", "definition", json!({"name": "x"}));
    view_bad("view content_state", "content_state", json!("hidden"));

    let up =
        |entries: Value| json!({"schema_version": 1, "proxy_id": "proxy-demo", "entries": entries});
    assert!(serde_json::from_value::<UploadRequest>(up(json!([]))).is_err());
    assert!(serde_json::from_value::<UploadRequest>(up(Value::Array(vec![entry(); 101]))).is_err());
    let dup = json!({"registered_metadata_refs": [metadata_ref(), metadata_ref()], "duplicate_metadata_refs": []});
    assert!(serde_json::from_value::<UploadResponse>(dup).is_err());
}

// ---------------------------------------------------------------- errors and ingest bodies

#[test]
fn error_object_round_trips_and_tolerates_unknown_codes() {
    let body = json!({"error": {"code": "conflict", "message": "Event conflict.", "items": [
        {"index": 1, "event_id": uid(1), "code": "conflict"},
        {"index": 2, "event_id": uid(2), "code": "sequence_conflict"}]}});
    let e: ApiError = serde_json::from_value(body.clone()).unwrap();
    assert_eq!(e.error.code, ErrorCode::Conflict);
    assert_eq!(serde_json::to_value(&e).unwrap(), body);

    let pending = json!({"error": {"code": "metadata_ref_pending", "message": "Pending.",
        "items": [{"index": 0, "event_id": uid(3), "code": "metadata_ref_pending"}],
        "pending_metadata_refs": [metadata_ref()]}});
    let e: ApiError = serde_json::from_value(pending.clone()).unwrap();
    assert_eq!(e.error.code.http_status(), Some(424));
    assert_eq!(serde_json::to_value(&e).unwrap(), pending);

    let gap = json!({"error": {"code": "conflict", "message": "Gap conflict.",
        "items": [{"index": 0, "gap_id": uid(4), "code": "conflict"}]}});
    assert!(serde_json::from_value::<ApiError>(gap).is_ok());

    // 422 items carry the index only.
    let schema = json!({"error": {"code": "schema_invalid", "message": "Invalid.",
        "items": [{"index": 1, "code": "schema_invalid"}]}});
    assert!(serde_json::from_value::<ApiError>(schema).is_ok());

    let future = json!({"error": {"code": "brand_new_code", "message": "x"}});
    let e: ApiError = serde_json::from_value(future.clone()).unwrap();
    assert_eq!(e.error.code, ErrorCode::parse("brand_new_code"));
    assert!(!e.error.code.is_known());
    assert_eq!(serde_json::to_value(&e).unwrap(), future);

    for code in [
        "proxy_unknown",
        "registry_conflict",
        "invocation_owner_conflict",
        "revision_conflict",
        "disabled",
        "retired",
        "semantic_invalid",
        "invalid_status",
        "invalid_cursor",
        "invalid_filter",
        "config_unavailable",
    ] {
        assert_eq!(ErrorCode::parse(code).as_str(), code);
        assert!(ErrorCode::parse(code).is_known());
    }
    assert_eq!(ErrorCode::ProxyUnknown.http_status(), Some(404));
    assert_eq!(ErrorCode::Retired.http_status(), None);
}

#[test]
fn error_object_rejects_malformed_shapes() {
    let bad = |v: Value| assert!(serde_json::from_value::<ApiError>(v).is_err());
    bad(json!({"error": {"code": "conflict"}}));
    bad(json!({"error": {"code": "conflict", "message": "x", "items": [{"code": "conflict"}]}}));
    bad(
        json!({"error": {"code": "conflict", "message": "x", "items": [{"index": -1, "code": "conflict"}]}}),
    );
    bad(
        json!({"error": {"code": "conflict", "message": "x", "pending_metadata_refs": [metadata_ref()]}}),
    );
    bad(
        json!({"error": {"code": "metadata_ref_pending", "message": "x", "pending_metadata_refs": ["canary-secret"]}}),
    );
    bad(json!({"error": [], "extra": 1}));
}

#[test]
fn ingest_bodies() {
    let req = json!({"events": [example(), completion()]});
    let parsed: IngestRequest = serde_json::from_value(req.clone()).unwrap();
    assert_eq!(serde_json::to_value(&parsed).unwrap(), req);
    assert!(serde_json::from_value::<IngestRequest>(json!({"events": []})).is_err());
    assert!(
        serde_json::from_value::<IngestRequest>(json!({"events": vec![example(); 101]})).is_err()
    );
    assert!(
        serde_json::from_value::<IngestRequest>(json!({"events": [example()], "x": 1})).is_err()
    );
    let resp = json!({"accepted_event_ids": [uid(1)], "duplicate_event_ids": [uid(2)]});
    let parsed: IngestResponse = serde_json::from_value(resp.clone()).unwrap();
    assert_eq!(serde_json::to_value(&parsed).unwrap(), resp);
}

// ---------------------------------------------------------------- review fixes

#[derive(Clone, Copy)]
enum Seg {
    K(&'static str),
    I(usize),
}

fn set_deep(mut v: Value, path: &[Seg], new: Value) -> Value {
    let mut cur = &mut v;
    for seg in &path[..path.len() - 1] {
        cur = match seg {
            Seg::K(k) => cur.get_mut(*k).unwrap(),
            Seg::I(i) => cur.get_mut(*i).unwrap(),
        };
    }
    match path[path.len() - 1] {
        Seg::K(k) => {
            cur.as_object_mut().unwrap().insert(k.into(), new);
        }
        Seg::I(i) => cur[i] = new,
    }
    v
}

type Entry = fn(&[u8]) -> Result<(), ParseError>;

struct Point {
    name: &'static str,
    parse: Entry,
    doc: Value,
    lenient: bool,
    enum_slot: Option<Vec<Seg>>,
    type_slot: Vec<Seg>,
}

fn points() -> Vec<Point> {
    use Seg::{I, K};
    vec![
        Point {
            name: "event",
            parse: |b| parse_event(b).map(drop),
            doc: example(),
            lenient: false,
            enum_slot: Some(vec![K("payload"), K("method")]),
            type_slot: vec![K("sequence")],
        },
        Point {
            name: "batch",
            parse: |b| parse_event_batch(b).map(drop),
            doc: json!({"events": [example()]}),
            lenient: false,
            enum_slot: Some(vec![K("events"), I(0), K("event_type")]),
            type_slot: vec![K("events"), I(0), K("sequence")],
        },
        Point {
            name: "status",
            parse: |b| parse_status(b).map(drop),
            doc: status(),
            lenient: false,
            enum_slot: Some(vec![K("spool"), K("state")]),
            type_slot: vec![K("status_sequence")],
        },
        Point {
            name: "upload",
            parse: |b| parse_upload(b).map(drop),
            doc: json!({"schema_version": 1, "proxy_id": "proxy-demo", "entries": [entry()]}),
            lenient: false,
            enum_slot: Some(vec![K("entries"), I(0), K("canon")]),
            type_slot: vec![K("schema_version")],
        },
        Point {
            name: "inventory",
            parse: |b| parse_inventory_report(b).map(drop),
            doc: inv_initial(),
            lenient: false,
            enum_slot: Some(vec![K("comparison"), K("kind")]),
            type_slot: vec![K("pages_observed")],
        },
        Point {
            name: "api_error",
            parse: |b| parse_api_error(b).map(drop),
            doc: json!({"error": {"code": "conflict", "message": "x"}}),
            lenient: true,
            enum_slot: None,
            type_slot: vec![K("error"), K("items")],
        },
        Point {
            name: "ingest_response",
            parse: |b| parse_ingest_response(b).map(drop),
            doc: json!({"accepted_event_ids": [], "duplicate_event_ids": []}),
            lenient: true,
            enum_slot: None,
            type_slot: vec![K("accepted_event_ids")],
        },
        Point {
            name: "status_response",
            parse: |b| parse_status_response(b).map(drop),
            doc: json!({"state_applied": true, "acknowledged_gap_ids": [], "duplicate_gap_ids": []}),
            lenient: true,
            enum_slot: None,
            type_slot: vec![K("state_applied")],
        },
        Point {
            name: "upload_response",
            parse: |b| parse_upload_response(b).map(drop),
            doc: json!({"registered_metadata_refs": [], "duplicate_metadata_refs": []}),
            lenient: true,
            enum_slot: None,
            type_slot: vec![K("registered_metadata_refs")],
        },
    ]
}

const CANARY: &str = "CANARY-SECRET-42";

fn assert_no_canary(name: &str, case: &str, e: &ParseError) {
    for text in [format!("{e:?}"), format!("{e}")] {
        assert!(!text.contains("CANARY"), "{name}/{case} leaked: {text}");
    }
}

#[test]
fn parse_entry_points_accept_valid_documents() {
    for p in points() {
        let bytes = serde_json::to_vec(&p.doc).unwrap();
        (p.parse)(&bytes).unwrap_or_else(|e| panic!("{}: {e}", p.name));
    }
}

#[test]
fn parse_errors_never_echo_input() {
    for p in points() {
        let mut cases: Vec<(&str, Value)> = Vec::new();
        let mut with_extra = p.doc.clone();
        with_extra
            .as_object_mut()
            .unwrap()
            .insert(CANARY.into(), json!(CANARY));
        cases.push(("unknown field", with_extra));
        if let Some(slot) = &p.enum_slot {
            cases.push((
                "unknown variant",
                set_deep(p.doc.clone(), slot, json!(CANARY)),
            ));
        }
        cases.push((
            "wrong type",
            set_deep(p.doc.clone(), &p.type_slot, json!(CANARY)),
        ));
        cases.push(("float", set_deep(p.doc.clone(), &p.type_slot, json!(1.5))));
        for (case, doc) in cases {
            let bytes = serde_json::to_vec(&doc).unwrap();
            match (p.parse)(&bytes) {
                Ok(()) => assert!(
                    p.lenient && case == "unknown field",
                    "{}/{case} accepted",
                    p.name
                ),
                Err(e) => {
                    assert_ne!(e.category(), ErrorCategory::Syntax, "{}/{case}", p.name);
                    assert_no_canary(p.name, case, &e);
                }
            }
        }
        let broken = format!("{{\"{CANARY}\": ");
        let e = (p.parse)(broken.as_bytes()).unwrap_err();
        assert_eq!(e.category(), ErrorCategory::Syntax);
        assert_no_canary(p.name, "syntax", &e);
        let e = (p.parse)(format!("[\"{CANARY}\"]").as_bytes()).unwrap_err();
        assert_no_canary(p.name, "array", &e);
        let e = (p.parse)(format!("{{}} {CANARY}").as_bytes()).unwrap_err();
        assert_eq!(e.category(), ErrorCategory::Syntax);
        assert_no_canary(p.name, "trailing", &e);
    }
}

/// Bytes the old text-based classifier looked for, plus the duplicate-key marker.
const FORGED: [&str; 3] = ["\u{1}S", "\u{1}L", "\u{1}D"];

#[test]
fn forged_markers_in_input_never_change_the_category() {
    for p in points() {
        for mark in FORGED {
            let text = format!("{mark}CANARY");
            // String-value cases are defence in depth (serde Debug-escapes them);
            // the key and variant cases are the ones that exercised the old bug.
            // (label, plain document, forged document): the category must match.
            let mut cases: Vec<(&str, Value, Value)> = Vec::new();
            // Marker inside a string value of the wrong-typed slot.
            cases.push((
                "string value",
                set_deep(p.doc.clone(), &p.type_slot, json!("CANARY")),
                set_deep(p.doc.clone(), &p.type_slot, json!(text)),
            ));
            // Marker inside an object key.
            let mut plain = p.doc.clone();
            plain
                .as_object_mut()
                .unwrap()
                .insert("CANARY".into(), json!(1));
            let mut forged = p.doc.clone();
            forged
                .as_object_mut()
                .unwrap()
                .insert(text.clone(), json!(1));
            cases.push(("object key", plain, forged));
            // Marker as an unknown enum variant.
            if let Some(slot) = &p.enum_slot {
                cases.push((
                    "unknown variant",
                    set_deep(p.doc.clone(), slot, json!("CANARY")),
                    set_deep(p.doc.clone(), slot, json!(text)),
                ));
            }
            for (case, plain, forged) in cases {
                let ctx = format!("{}/{case}/{mark:?}", p.name);
                let plain_res = (p.parse)(&serde_json::to_vec(&plain).unwrap());
                let forged_res = (p.parse)(&serde_json::to_vec(&forged).unwrap());
                match (plain_res, forged_res) {
                    (Ok(()), Ok(())) => assert!(p.lenient, "{ctx}"),
                    (Err(a), Err(b)) => {
                        assert_eq!(a, b, "{ctx}");
                        assert!(
                            matches!(b.category(), ErrorCategory::Schema),
                            "{ctx}: {b:?}"
                        );
                        assert_no_canary(p.name, &ctx, &b);
                    }
                    (a, b) => panic!("{ctx}: diverged {a:?} vs {b:?}"),
                }
            }
        }
    }
}

#[test]
fn genuine_limit_and_semantic_survive_adversarial_content() {
    let bytes = |v: Value| serde_json::to_vec(&v).unwrap();
    // `definition` is free-form, so marker bytes in its keys and values are valid
    // input and the failure below is the only reason the document is rejected.
    for mark in FORGED {
        let mut e = entry();
        e["definition"] =
            json!({"name": format!("{mark}n"), (format!("{mark}k")): format!("{mark}v")});
        let up = |entries: Vec<Value>| {
            bytes(json!({"schema_version": 1, "proxy_id": "proxy-demo", "entries": entries}))
        };
        // Sanity: the document is accepted on its own.
        parse_upload(&up(vec![e.clone()])).unwrap();
        // Limit: too many entries.
        let r = parse_upload(&up(vec![e.clone(); 101])).unwrap_err();
        assert_eq!(r.category(), ErrorCategory::Limit, "{mark:?} count");
        let r = parse_upload(&up(vec![])).unwrap_err();
        assert_eq!(r.category(), ErrorCategory::Limit, "{mark:?} empty");
        // Lenient response body: the marker key is an ignored unknown field, so the
        // only failures are the genuine uniqueness (Semantic) and count (Limit) rules.
        let refs = |n: usize, same: bool| {
            let v: Vec<String> = (0..n)
                .map(|i| format!("3f4720a0-484d-8103-a955-{:012x}", if same { 0 } else { i }))
                .collect();
            bytes(json!({
                "registered_metadata_refs": v, "duplicate_metadata_refs": [],
                (format!("{mark}k")): format!("{mark}v")
            }))
        };
        parse_upload_response(&refs(2, false)).unwrap();
        let r = parse_upload_response(&refs(2, true)).unwrap_err();
        assert_eq!(r.category(), ErrorCategory::Semantic, "{mark:?} unique");
        let r = parse_upload_response(&refs(101, false)).unwrap_err();
        assert_eq!(r.category(), ErrorCategory::Limit, "{mark:?} refs count");
    }
    // Event batch: genuine Limit without any extra content.
    let many = json!({"events": vec![example(); 101]});
    assert_eq!(
        parse_event_batch(&bytes(many)).unwrap_err().category(),
        ErrorCategory::Limit
    );
}

#[test]
fn stale_signal_from_direct_serde_use_does_not_leak_into_parse() {
    // Direct serde use of a failing semantic rule leaves no state that a later
    // schema failure in parse_* could pick up.
    let bad = set(completion(), &["payload", "outcome"], json!("denied"));
    assert!(serde_json::from_value::<ProxyEvent>(bad).is_err());
    let schema_bad = set(example(), &["sequence"], json!(0));
    let e = parse_event(&serde_json::to_vec(&schema_bad).unwrap()).unwrap_err();
    assert_eq!(e.category(), ErrorCategory::Schema);
    // And a semantic failure after a clean parse is still reported.
    parse_event(&serde_json::to_vec(&example()).unwrap()).unwrap();
    let bad = set(completion(), &["payload", "outcome"], json!("denied"));
    let e = parse_event(&serde_json::to_vec(&bad).unwrap()).unwrap_err();
    assert_eq!(e.category(), ErrorCategory::Semantic);
}

#[test]
fn new_error_codes_golden_table() {
    let table = [
        (
            "storage_limit",
            ErrorCode::StorageLimit,
            503,
            "Storage limit reached.",
        ),
        (
            "storage_unavailable",
            ErrorCode::StorageUnavailable,
            503,
            "Storage is unavailable.",
        ),
        (
            "payload_too_large",
            ErrorCode::PayloadTooLarge,
            413,
            "Request body is too large.",
        ),
        (
            "rate_limited",
            ErrorCode::RateLimited,
            429,
            "Too many requests.",
        ),
    ];
    for (text, code, status, message) in table {
        assert_eq!(code.as_str(), text);
        assert_eq!(ErrorCode::parse(text), code);
        assert!(code.is_known());
        assert_eq!(code.http_status(), Some(status));
        assert_eq!(code.fixed_message(), message);
        let body = ApiError::from_code(code.clone());
        assert_eq!(body.error.message, message);
        assert_eq!(
            serde_json::to_value(&body).unwrap(),
            json!({"error": {"code": text, "message": message}})
        );
        let back: ApiError = serde_json::from_value(serde_json::to_value(&body).unwrap()).unwrap();
        assert_eq!(back.error.code, code);
    }
}

#[test]
fn parse_rejects_duplicate_keys() {
    for p in points() {
        let text = serde_json::to_string(&p.doc).unwrap();
        let rest = text.trim_start_matches('{');
        let dup = format!("{{\"{CANARY}\":1,\"{CANARY}\":2,{rest}");
        let e = (p.parse)(dup.as_bytes()).unwrap_err();
        assert_eq!(e.category(), ErrorCategory::Schema, "{}", p.name);
        assert_no_canary(p.name, "duplicate", &e);
    }
    // Nested duplicate inside an otherwise valid event.
    let text = EXAMPLE.replacen(
        "\"upstream_id\": \"fixture\",",
        "\"upstream_id\": \"fixture\", \"upstream_id\": \"other\",",
        1,
    );
    assert_ne!(text, EXAMPLE);
    assert_eq!(
        parse_event(text.as_bytes()).unwrap_err().category(),
        ErrorCategory::Schema
    );
}

#[test]
fn parse_categories_and_indices() {
    let bytes = |v: Value| serde_json::to_vec(&v).unwrap();
    // Semantic: cross-field rule.
    let bad_matrix = set(completion(), &["payload", "outcome"], json!("denied"));
    assert_eq!(
        parse_event(&bytes(bad_matrix)).unwrap_err().category(),
        ErrorCategory::Semantic
    );
    let cfg = del(status()["config"].clone(), &["config_hash"]);
    let s = set(status(), &["config"], cfg);
    assert_eq!(
        parse_status(&bytes(s)).unwrap_err().category(),
        ErrorCategory::Semantic
    );
    // Limit: counts and sizes.
    let many = json!({"events": vec![example(); 101]});
    assert_eq!(
        parse_event_batch(&bytes(many)).unwrap_err().category(),
        ErrorCategory::Limit
    );
    let none = json!({"events": []});
    assert_eq!(
        parse_event_batch(&bytes(none)).unwrap_err().category(),
        ErrorCategory::Limit
    );
    let huge = vec![b' '; 1024 * 1024 + 1];
    assert_eq!(
        parse_event_batch(&huge).unwrap_err().category(),
        ErrorCategory::Limit
    );
    let too_many_gaps = set(
        status(),
        &["gaps"],
        Value::Array(vec![gaps()[5].clone(); 101]),
    );
    assert_eq!(
        parse_status(&bytes(too_many_gaps)).unwrap_err().category(),
        ErrorCategory::Limit
    );
    // Schema with the index of the first bad element.
    let batch =
        json!({"events": [example(), set(example(), &["sequence"], json!(0)), completion()]});
    let e = parse_event_batch(&bytes(batch)).unwrap_err();
    assert_eq!((e.category(), e.index()), (ErrorCategory::Schema, Some(1)));
    let up = json!({"schema_version": 1, "proxy_id": "p",
        "entries": [entry(), set(entry(), &["canon"], json!("x"))]});
    assert_eq!(parse_upload(&bytes(up)).unwrap_err().index(), Some(1));
}

#[test]
fn validate_is_recursive_for_hand_built_values() {
    use lodeline_proxy_api::event::{DeliveryState, Outcome};
    use lodeline_proxy_api::status::ConfigState;
    use lodeline_proxy_api::{EventPayload, GapReport};

    let good: ProxyStatus =
        serde_json::from_value(set(status(), &["gaps"], Value::Array(gaps()))).unwrap();
    assert!(good.validate().is_ok());

    let mut s = good.clone();
    s.config.config_hash = None; // state is valid
    assert!(s.validate().is_err(), "config rule");

    let mut s = good.clone();
    s.config.state = ConfigState::Valid;
    s.config.max_offline_retry_age_seconds = Some(1);
    assert!(s.validate().is_err(), "config range");

    let mut s = good.clone();
    if let GapReport::RegistryConflict(g) = &mut s.gaps[0] {
        g.event_ids.clear();
    }
    assert!(s.validate().is_err(), "gap rule through ProxyStatus");
    assert!(s.gaps[0].validate().is_err(), "GapReport::validate");

    let mut s = good.clone();
    if let GapReport::LocalRecordFailed(g) = &mut s.gaps[2] {
        let id = g.invocation_ids[0].clone();
        g.invocation_ids.push(id);
    }
    assert!(s.validate().is_err(), "gap uniqueness");

    let mut s = good.clone();
    for _ in 0..1537 {
        let c = s.counters.auth_failures[0].clone();
        s.counters.auth_failures.push(c);
    }
    assert!(s.validate().is_err(), "counters limit");

    let batch: IngestRequest =
        serde_json::from_value(json!({"events": [example(), completion()]})).unwrap();
    assert!(batch.validate().is_ok());
    let mut b = batch.clone();
    if let EventPayload::Completed(c) = &mut b.events[1].payload {
        c.outcome = Outcome::Success;
        c.delivery_state = DeliveryState::NotSent;
    }
    assert!(b.validate().is_err(), "event matrix through IngestRequest");
    let mut b = batch;
    b.events.clear();
    assert!(b.validate().is_err(), "empty batch");

    let up: UploadRequest =
        serde_json::from_value(json!({"schema_version": 1, "proxy_id": "p", "entries": [entry()]}))
            .unwrap();
    assert!(up.validate().is_ok());
    let mut u = up;
    u.entries[0].definition = json!({});
    assert!(u.validate().is_err(), "entry rule through UploadRequest");
}

#[test]
fn timestamp_requires_year_one() {
    rejected(
        "year 0",
        &set(example(), &["occurred_at"], json!("0000-01-01T00:00:00Z")),
    );
    accepted(&set(
        example(),
        &["occurred_at"],
        json!("0001-01-01T00:00:00Z"),
    ));
}

#[test]
fn registry_conflict_gap_count_covers_listed_ids() {
    let gap = |count: u64| {
        let g = set(gaps()[0].clone(), &["event_ids"], json!([uid(1), uid(2)]));
        set(
            status(),
            &["gaps"],
            json!([set(g, &["affected_event_count"], json!(count))]),
        )
    };
    status_bad("count 1 < 2 ids", gap(1));
    status_ok(&gap(2));
    status_ok(&gap(500));
}

#[test]
fn unknown_error_codes_are_opaque_and_bounded() {
    assert_eq!(ErrorCode::parse("conflict"), ErrorCode::Conflict);
    assert_eq!(
        ErrorCode::parse("registry_conflict"),
        ErrorCode::RegistryConflict
    );
    let long = "a".repeat(65);
    let max = "a".repeat(64);
    assert_eq!(ErrorCode::parse(&max).as_str(), max);
    for bad in [
        long.as_str(),
        "Conflict",
        "bad-code",
        "with space",
        "",
        "CANARY-SECRET-42",
        "ünï",
    ] {
        let c = ErrorCode::parse(bad);
        assert!(!c.is_known());
        assert_eq!(c.as_str(), "unknown", "{bad:?}");
        assert!(!format!("{c:?}").contains("CANARY"));
    }
    let body = json!({"error": {"code": "CANARY-SECRET-42", "message": "x"}});
    let e = parse_api_error(&serde_json::to_vec(&body).unwrap()).unwrap();
    assert_eq!(e.error.code.as_str(), "unknown");
    assert!(!serde_json::to_string(&e).unwrap().contains("CANARY"));
}

#[test]
fn response_bodies_ignore_unknown_fields_but_emit_closed() {
    let body = json!({"error": {"code": "conflict", "message": "m", "future": {"a": 1},
        "items": [{"index": 0, "code": "conflict", "future": 1}]}, "trace": "t"});
    let e = parse_api_error(&serde_json::to_vec(&body).unwrap()).unwrap();
    assert_eq!(
        serde_json::to_value(&e).unwrap(),
        json!({"error": {"code": "conflict", "message": "m",
            "items": [{"index": 0, "code": "conflict"}]}})
    );
    let r =
        parse_ingest_response(br#"{"accepted_event_ids":[],"duplicate_event_ids":[],"extra":1}"#)
            .unwrap();
    assert_eq!(
        serde_json::to_value(&r).unwrap(),
        json!({"accepted_event_ids": [], "duplicate_event_ids": []})
    );
    assert!(parse_status_response(
        br#"{"state_applied":true,"acknowledged_gap_ids":[],"duplicate_gap_ids":[],"x":1}"#
    )
    .is_ok());
    assert!(parse_upload_response(
        br#"{"registered_metadata_refs":[],"duplicate_metadata_refs":[],"x":1}"#
    )
    .is_ok());
    // Content rules still apply to lenient bodies.
    assert!(
        parse_ingest_response(br#"{"accepted_event_ids":["BAD"],"duplicate_event_ids":[]}"#)
            .is_err()
    );
}

#[test]
fn error_item_carries_at_most_one_id() {
    let both = json!({"index": 0, "event_id": uid(1), "gap_id": uid(2), "code": "conflict"});
    let body = json!({"error": {"code": "conflict", "message": "m", "items": [both]}});
    assert_eq!(
        parse_api_error(&serde_json::to_vec(&body).unwrap())
            .unwrap_err()
            .category(),
        ErrorCategory::Semantic
    );
    let item: lodeline_proxy_api::ErrorItem =
        serde_json::from_value(json!({"index": 0, "event_id": uid(1), "code": "conflict"}))
            .unwrap();
    let mut two = item.clone();
    two.gap_id = two.event_id.clone();
    let e = ApiError::from_code(ErrorCode::Conflict).with_items(vec![item]);
    assert!(e.validate().is_ok());
    let e = e.with_items(vec![two]);
    assert!(e.validate().is_err());
}

#[test]
fn api_error_constructor_uses_fixed_messages() {
    for code in [
        "proxy_unknown",
        "conflict",
        "sequence_conflict",
        "registry_conflict",
        "invocation_owner_conflict",
        "revision_conflict",
        "disabled",
        "retired",
        "metadata_ref_pending",
        "semantic_invalid",
        "schema_invalid",
        "invalid_status",
        "invalid_cursor",
        "invalid_filter",
        "something_new",
    ] {
        let code = ErrorCode::parse(code);
        let e = ApiError::from_code(code.clone());
        assert_eq!(e.error.message, code.fixed_message());
        assert!(!e.error.message.is_empty());
        assert!(e.validate().is_ok());
        let round: ApiError = serde_json::from_value(serde_json::to_value(&e).unwrap()).unwrap();
        assert_eq!(round, e);
    }
    let e = ApiError::from_code(ErrorCode::MetadataRefPending)
        .with_pending_metadata_refs(vec![serde_json::from_value(json!(metadata_ref())).unwrap()]);
    assert!(e.validate().is_ok());
}

// ---------------------------------------------------------------- inventory report

fn v8(n: u32) -> String {
    format!("00000000-0000-8000-8000-{n:012x}")
}

fn inv_report(over: &[(&str, Value)]) -> Value {
    let mut v = json!({
        "schema_version": 1, "report_id": uid(900), "proxy_id": "proxy-demo",
        "epoch_id": "3f1c9a52-6b0e-4d2a-9c1e-7a5b2d8e4f10",
        "observed_at": "2026-10-10T01:00:00Z",
        "scope": {"upstream_id": "fixture", "credential_scope_id": "scope-1",
                  "protocol_version": "2025-11-25", "observation_source": "proxy_live"},
        "canon": "sigil-tooldef-fp-v1", "key_id": "kid-3c8e1f0a9b7d42e6a1c5f804",
        "completeness": "complete", "pages_observed": 2,
        "inventory_id": uid(910), "members": [v8(1), v8(2)],
        "comparison": {"kind": "initial_baseline"}
    });
    for (k, val) in over {
        v[*k] = val.clone();
    }
    v
}

fn inv_initial() -> Value {
    inv_report(&[])
}

fn inv_incomplete(over: &[(&str, Value)]) -> Value {
    let mut v = inv_report(&[
        ("completeness", json!("incomplete")),
        ("incomplete_reason", json!("page_error")),
        ("pages_observed", json!(1)),
    ]);
    for k in ["inventory_id", "members", "comparison"] {
        v.as_object_mut().unwrap().remove(k);
    }
    for (k, val) in over {
        v[*k] = val.clone();
    }
    v
}

fn inv_compared_comparison() -> Value {
    json!({"kind": "compared", "previous_inventory_id": uid(910), "changes": [
        {"change": "changed", "metadata_ref": v8(3), "previous_metadata_ref": v8(1)},
        {"change": "removed", "metadata_ref": v8(2)},
        {"change": "added", "metadata_ref": v8(4)}]})
}

fn inv_rebaseline_comparison() -> Value {
    json!({"kind": "rebaseline", "previous_inventory_id": uid(910), "reason": "key_rotation",
           "links": [{"from_metadata_ref": v8(1), "to_metadata_ref": v8(5),
                      "definition_comparison": "identical"}]})
}

fn inv_rebaseline() -> Value {
    inv_report(&[
        ("inventory_id", json!(uid(913))),
        ("key_id", json!(format!("kid-{}", "ab".repeat(12)))),
        ("members", json!([v8(5), v8(6)])),
        ("comparison", inv_rebaseline_comparison()),
    ])
}

#[test]
fn inventory_positive_cases_round_trip() {
    let mut cases = vec![
        inv_initial(),
        inv_report(&[
            ("inventory_id", json!(uid(911))),
            ("members", json!([v8(3), v8(4)])),
            ("comparison", inv_compared_comparison()),
        ]),
        inv_report(&[(
            "comparison",
            json!({"kind": "compared", "previous_inventory_id": uid(910), "changes": []}),
        )]),
        inv_rebaseline(),
        inv_incomplete(&[]),
        inv_report(&[("members", json!([]))]),
        inv_report(&[("comparison", {
            let mut c = inv_rebaseline_comparison();
            c["reason"] = json!("canon_version_change");
            c["links"][0]["definition_comparison"] = json!("not_comparable");
            c
        })]),
        inv_report(&[("pages_observed", json!(0))]),
        inv_report(&[("observed_at", json!("2026-10-10T01:00:00.123456789Z"))]),
    ];
    for reason in [
        "page_limit_exceeded",
        "tool_limit_exceeded",
        "size_limit_exceeded",
        "page_error",
        "cursor_invalid",
        "access_denied",
        "session_ended",
        "canonicalization_failed",
        "ambiguous_name",
    ] {
        cases.push(inv_incomplete(&[("incomplete_reason", json!(reason))]));
    }
    let members: Vec<String> = (0..10_000).map(v8).collect();
    cases.push(inv_report(&[("members", json!(members))]));
    for doc in cases {
        let r: InventoryReport = serde_json::from_value(doc.clone())
            .unwrap_or_else(|e| panic!("inventory case rejected: {e}: {doc}"));
        assert_eq!(serde_json::to_value(&r).unwrap(), doc);
        assert!(r.validate().is_ok());
        parse_inventory_report(&serde_json::to_vec(&doc).unwrap()).unwrap();
    }
}

#[test]
fn inventory_rejected_cases() {
    let compared = || inv_report(&[("comparison", inv_compared_comparison())]);
    let rebase = inv_rebaseline;
    let with_cmp = |base: Value, k: &str, v: Value| set(base, &["comparison", k], v);
    let many_members: Vec<String> = (0..10_001).map(v8).collect();
    let many_changes: Vec<Value> = (0..20_001)
        .map(|i| json!({"change": "added", "metadata_ref": v8(i)}))
        .collect();
    let many_links: Vec<Value> = (0..10_001)
        .map(|i| {
            json!({"from_metadata_ref": v8(i), "to_metadata_ref": v8(i),
                   "definition_comparison": "identical"})
        })
        .collect();
    let cases: Vec<(&str, Value)> = vec![
        (
            "incomplete with changes-bearing comparison",
            set(
                inv_incomplete(&[]),
                &["comparison"],
                inv_compared_comparison(),
            ),
        ),
        (
            "incomplete with members",
            set(inv_incomplete(&[]), &["members"], json!([v8(1)])),
        ),
        (
            "incomplete with inventory_id",
            set(inv_incomplete(&[]), &["inventory_id"], json!(uid(914))),
        ),
        (
            "incomplete without reason",
            del(inv_incomplete(&[]), &["incomplete_reason"]),
        ),
        (
            "incomplete raw reason",
            set(
                inv_incomplete(&[]),
                &["incomplete_reason"],
                json!("canary-secret"),
            ),
        ),
        (
            "complete without comparison",
            del(inv_initial(), &["comparison"]),
        ),
        ("complete without members", del(inv_initial(), &["members"])),
        (
            "complete without inventory_id",
            del(inv_initial(), &["inventory_id"]),
        ),
        (
            "complete with incomplete_reason",
            set(inv_initial(), &["incomplete_reason"], json!("page_error")),
        ),
        (
            "rebaseline with changes",
            with_cmp(
                rebase(),
                "changes",
                json!([{"change": "added", "metadata_ref": v8(1)}]),
            ),
        ),
        (
            "compared with links",
            with_cmp(compared(), "links", json!([])),
        ),
        (
            "compared without changes",
            set(
                inv_initial(),
                &["comparison"],
                json!({"kind": "compared", "previous_inventory_id": uid(910)}),
            ),
        ),
        (
            "initial with previous",
            set(
                inv_initial(),
                &["comparison"],
                json!({"kind": "initial_baseline", "previous_inventory_id": uid(910)}),
            ),
        ),
        (
            "unknown comparison kind",
            set(inv_initial(), &["comparison"], json!({"kind": "approved"})),
        ),
        (
            "comparison missing kind",
            set(inv_initial(), &["comparison"], json!({})),
        ),
        (
            "comparison array",
            set(inv_initial(), &["comparison"], json!([])),
        ),
        (
            "rebaseline unknown reason",
            with_cmp(rebase(), "reason", json!("state_loss")),
        ),
        (
            "rebaseline without links",
            del(rebase(), &["comparison", "links"]),
        ),
        (
            "changed without previous",
            with_cmp(
                compared(),
                "changes",
                json!([{"change": "changed", "metadata_ref": v8(3)}]),
            ),
        ),
        (
            "added with previous",
            with_cmp(
                compared(),
                "changes",
                json!([{"change": "added", "metadata_ref": v8(3), "previous_metadata_ref": v8(1)}]),
            ),
        ),
        (
            "unknown change",
            with_cmp(
                compared(),
                "changes",
                json!([{"change": "renamed", "metadata_ref": v8(3)}]),
            ),
        ),
        ("change array", with_cmp(compared(), "changes", json!([[]]))),
        (
            "raw name in members",
            set(inv_initial(), &["members"], json!(["json_ok"])),
        ),
        (
            "duplicate members",
            set(inv_initial(), &["members"], json!([v8(1), v8(1)])),
        ),
        (
            "10001 members",
            set(inv_initial(), &["members"], json!(many_members)),
        ),
        (
            "20001 changes",
            with_cmp(compared(), "changes", json!(many_changes)),
        ),
        (
            "10001 links",
            with_cmp(rebase(), "links", json!(many_links)),
        ),
        (
            "route_revision in scope",
            set(inv_initial(), &["scope", "route_revision"], json!(1)),
        ),
        (
            "scope daemon cache",
            set(
                inv_initial(),
                &["scope", "observation_source"],
                json!("daemon_cache"),
            ),
        ),
        (
            "scope missing field",
            del(inv_initial(), &["scope", "upstream_id"]),
        ),
        (
            "canon v2",
            set(inv_initial(), &["canon"], json!("sigil-tooldef-fp-v2")),
        ),
        (
            "negative pages",
            set(inv_initial(), &["pages_observed"], json!(-1)),
        ),
        (
            "float pages",
            set(inv_initial(), &["pages_observed"], json!(1.0)),
        ),
        (
            "pages above int64",
            set(inv_initial(), &["pages_observed"], json!(u64::MAX)),
        ),
        (
            "tool names list",
            set(inv_initial(), &["tools"], json!(["json_ok"])),
        ),
        (
            "v4 member",
            set(
                inv_initial(),
                &["members"],
                json!(["0c635e55-7e09-4e3d-978f-4b88870428f1"]),
            ),
        ),
        (
            "bad key_id",
            set(inv_initial(), &["key_id"], json!("kid-abc")),
        ),
        (
            "bad schema_version",
            set(inv_initial(), &["schema_version"], json!(2)),
        ),
        (
            "observed_at calendar",
            set(
                inv_initial(),
                &["observed_at"],
                json!("2026-02-30T00:00:00Z"),
            ),
        ),
        (
            "null members",
            set(inv_initial(), &["members"], Value::Null),
        ),
        (
            "null incomplete_reason",
            set(inv_initial(), &["incomplete_reason"], Value::Null),
        ),
        (
            "link comparison raw",
            with_cmp(
                rebase(),
                "links",
                json!([{"from_metadata_ref": v8(1), "to_metadata_ref": v8(5),
                        "definition_comparison": "canary-secret"}]),
            ),
        ),
        (
            "link with key",
            with_cmp(
                rebase(),
                "links",
                json!([{"from_metadata_ref": v8(1), "to_metadata_ref": v8(5),
                        "definition_comparison": "identical", "key": "canary-secret"}]),
            ),
        ),
        ("missing report_id", del(inv_initial(), &["report_id"])),
        ("missing epoch_id", del(inv_initial(), &["epoch_id"])),
        (
            "missing pages_observed",
            del(inv_initial(), &["pages_observed"]),
        ),
    ];
    for (label, doc) in cases {
        assert!(
            serde_json::from_value::<InventoryReport>(doc.clone()).is_err(),
            "inventory case {label} accepted"
        );
        let e = parse_inventory_report(&serde_json::to_vec(&doc).unwrap()).expect_err(label);
        assert_ne!(e.category(), ErrorCategory::Syntax, "{label}");
        assert_no_canary("inventory", label, &e);
    }
}

#[test]
fn inventory_error_categories_and_validate() {
    let cat = |v: Value| {
        parse_inventory_report(&serde_json::to_vec(&v).unwrap())
            .unwrap_err()
            .category()
    };
    let too_many: Vec<String> = (0..10_001).map(v8).collect();
    assert_eq!(
        cat(set(inv_initial(), &["members"], json!(too_many))),
        ErrorCategory::Limit
    );
    assert_eq!(
        cat(set(inv_initial(), &["members"], json!([v8(1), v8(1)]))),
        ErrorCategory::Semantic
    );
    assert_eq!(
        cat(del(inv_initial(), &["members"])),
        ErrorCategory::Semantic
    );
    assert_eq!(
        cat(set(inv_initial(), &["x"], json!(1))),
        ErrorCategory::Schema
    );
    // Hand-built values are checked by validate().
    let mut r: InventoryReport = serde_json::from_value(inv_initial()).unwrap();
    r.members = None;
    assert!(r.validate().is_err());
    // Duplicate keys are refused by the byte-level entry point.
    let dup = br#"{"schema_version":1,"schema_version":1}"#;
    assert_eq!(
        parse_inventory_report(dup).unwrap_err().category(),
        ErrorCategory::Schema
    );
}

#[test]
fn error_item_metadata_ref_for_registry_conflict() {
    let item = json!({"index": 0, "metadata_ref": v8(1), "code": "registry_conflict"});
    let body = json!({"error": {"code": "registry_conflict", "message": "m", "items": [item]}});
    let parsed = parse_api_error(&serde_json::to_vec(&body).unwrap()).unwrap();
    assert_eq!(serde_json::to_value(&parsed).unwrap(), body);
    // Optional: other items still round-trip without emitting the key.
    let plain = json!({"error": {"code": "conflict", "message": "m", "items": [
        {"index": 0, "event_id": uid(1), "code": "conflict"}]}});
    let parsed = parse_api_error(&serde_json::to_vec(&plain).unwrap()).unwrap();
    assert_eq!(serde_json::to_value(&parsed).unwrap(), plain);
    // Shape and exclusivity.
    for bad in [
        json!({"index": 0, "metadata_ref": "canary-secret", "code": "registry_conflict"}),
        json!({"index": 0, "metadata_ref": "0c635e55-7e09-4e3d-978f-4b88870428f1", "code": "registry_conflict"}),
        json!({"index": 0, "metadata_ref": Value::Null, "code": "registry_conflict"}),
    ] {
        let body = json!({"error": {"code": "registry_conflict", "message": "m", "items": [bad]}});
        let e = parse_api_error(&serde_json::to_vec(&body).unwrap()).unwrap_err();
        assert_no_canary("api_error", "metadata_ref", &e);
    }
    let both =
        json!({"index": 0, "metadata_ref": v8(1), "event_id": uid(1), "code": "registry_conflict"});
    let body = json!({"error": {"code": "registry_conflict", "message": "m", "items": [both]}});
    assert_eq!(
        parse_api_error(&serde_json::to_vec(&body).unwrap())
            .unwrap_err()
            .category(),
        ErrorCategory::Semantic
    );
}

#[test]
fn spool_quarantined_bytes_is_optional_and_round_trips() {
    use lodeline_proxy_api::parse_status;
    let old = parse_status(&serde_json::to_vec(&status()).unwrap()).unwrap();
    assert!(old.spool.quarantined_bytes.is_none());
    assert!(serde_json::to_value(&old).unwrap()["spool"]
        .get("quarantined_bytes")
        .is_none());

    let mut v = status();
    v["spool"]["quarantined_bytes"] = json!(4096);
    let new = parse_status(&serde_json::to_vec(&v).unwrap()).unwrap();
    assert_eq!(new.spool.quarantined_bytes.unwrap().get(), 4096);
    assert_eq!(serde_json::to_value(&new).unwrap()["spool"], v["spool"]);

    for bad in [json!(-1), json!(1.5), json!("1"), json!(null)] {
        let mut b = status();
        b["spool"]["quarantined_bytes"] = bad.clone();
        assert!(
            parse_status(&serde_json::to_vec(&b).unwrap()).is_err(),
            "{bad}"
        );
    }
}

#[test]
fn central_ingest_stopped_is_optional_and_round_trips() {
    use lodeline_proxy_api::parse_status;
    let old = parse_status(&serde_json::to_vec(&status()).unwrap()).unwrap();
    assert!(old.central.ingest_stopped.is_none());
    assert!(serde_json::to_value(&old).unwrap()["central"]
        .get("ingest_stopped")
        .is_none());

    for stopped in [true, false] {
        let mut v = status();
        v["central"]["ingest_stopped"] = json!(stopped);
        let new = parse_status(&serde_json::to_vec(&v).unwrap()).unwrap();
        assert_eq!(new.central.ingest_stopped, Some(stopped));
        assert_eq!(serde_json::to_value(&new).unwrap()["central"], v["central"]);
    }

    for bad in [json!(1), json!("true"), json!(null)] {
        let mut b = status();
        b["central"]["ingest_stopped"] = bad.clone();
        assert!(
            parse_status(&serde_json::to_vec(&b).unwrap()).is_err(),
            "{bad}"
        );
    }
}

#[test]
fn registry_counters_are_optional_and_round_trip() {
    use lodeline_proxy_api::parse_status;
    // Old shape (a proxy that predates the counters): accepted, fields absent,
    // and not invented on the way back out.
    let old = parse_status(&serde_json::to_vec(&status()).unwrap()).unwrap();
    assert!(old.registry.quarantined_entries.is_none());
    assert!(old.registry.poisoned_entries.is_none());
    assert!(old.registry.discarded_reports.is_none());
    let back = serde_json::to_value(&old).unwrap();
    assert_eq!(
        back["registry"],
        json!({"pending_entries": 0, "sync_stalled": false})
    );

    // New shape.
    let mut v = status();
    v["registry"] = json!({"pending_entries": 2, "sync_stalled": true,
        "quarantined_entries": 1, "poisoned_entries": 3, "discarded_reports": 0});
    let new = parse_status(&serde_json::to_vec(&v).unwrap()).unwrap();
    assert_eq!(new.registry.quarantined_entries.unwrap().get(), 1);
    assert_eq!(new.registry.poisoned_entries.unwrap().get(), 3);
    assert_eq!(new.registry.discarded_reports.unwrap().get(), 0);
    assert_eq!(
        serde_json::to_value(&new).unwrap()["registry"],
        v["registry"]
    );

    // A partial set is fine; bad values and unknown members are not.
    let mut p = status();
    p["registry"] = json!({"pending_entries": 0, "sync_stalled": false, "poisoned_entries": 4});
    let part = parse_status(&serde_json::to_vec(&p).unwrap()).unwrap();
    assert_eq!(part.registry.poisoned_entries.unwrap().get(), 4);
    assert!(part.registry.quarantined_entries.is_none());
    for bad in [json!(-1), json!(1.5), json!("1"), json!(null), json!(true)] {
        let mut b = status();
        b["registry"] =
            json!({"pending_entries": 0, "sync_stalled": false, "discarded_reports": bad});
        assert!(
            parse_status(&serde_json::to_vec(&b).unwrap()).is_err(),
            "{bad}"
        );
    }
    let mut u = status();
    u["registry"] = json!({"pending_entries": 0, "sync_stalled": false, "other": 1});
    assert!(parse_status(&serde_json::to_vec(&u).unwrap()).is_err());
}
