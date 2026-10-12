//! `POST /v1/proxy-status` (ledger L6b): state snapshot, gap upsert, ACK.
//!
//! Identity is the mTLS peer (the guard has verified it); a body `proxy_id`
//! must equal it, else 404 `proxy_unknown`, evaluated before anything else in
//! the body. Disabled and retired proxies are answered 403 by the guard.
//!
//! The pure part ([`apply`]) decides snapshot and gap outcomes against the
//! stored entry. Nothing is stored unless the whole report is acceptable (a
//! gap conflict applies nothing from the report, including `last_seen`).

use super::guard::VerifiedProxy;
use super::store::{ProxyEntry, MAX_EPOCHS_SEEN, MAX_GAPS_PER_PROXY};
use super::ProxyContext;
use axum::body::Bytes;
use axum::extract::{Extension, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use sigil_proxy_api::canonical::canonical_json;
use sigil_proxy_api::{
    parse_status, ApiError, ErrorCode, ErrorItem, GapReport, ProxyStatus, StatusResponse, Uuid,
};
use std::sync::Arc;

pub const STATUS_PATH: &str = "/v1/proxy-status";
/// Request body cap. 100 gaps of 100 event ids and the counter lists fit well
/// below it.
pub const MAX_STATUS_BODY: usize = 1024 * 1024;

fn gap_id(g: &GapReport) -> &Uuid {
    match g {
        GapReport::RegistryConflict(x) => &x.gap_id,
        GapReport::EventQuarantined(x) => &x.gap_id,
        GapReport::LocalRecordFailed(x) => &x.gap_id,
        GapReport::SpoolExpired(x) => &x.gap_id,
        GapReport::UnrecordedCalls(x) => &x.gap_id,
        GapReport::CentralOutage(x) => &x.gap_id,
    }
}

fn push_unique(list: &mut Vec<Uuid>, id: &Uuid) {
    if !list.contains(id) {
        list.push(id.clone());
    }
}

fn canon(g: &GapReport) -> Vec<u8> {
    canonical_json(&serde_json::to_value(g).unwrap_or(serde_json::Value::Null))
}

/// What a gap upsert does.
#[derive(Debug, PartialEq, Eq)]
enum GapOutcome {
    Store,
    Duplicate,
    /// `central_outage.ended_at` null to a value, nothing else different.
    CloseOutage,
    Conflict,
}

fn classify_gap(existing: Option<&GapReport>, incoming: &GapReport) -> GapOutcome {
    let Some(old) = existing else {
        return GapOutcome::Store;
    };
    if canon(old) == canon(incoming) {
        return GapOutcome::Duplicate;
    }
    if let (GapReport::CentralOutage(o), GapReport::CentralOutage(n)) = (old, incoming) {
        let same_but_end =
            o.gap_id == n.gap_id && o.detected_at == n.detected_at && o.started_at == n.started_at;
        if same_but_end && o.ended_at.is_none() && n.ended_at.is_some() {
            return GapOutcome::CloseOutage;
        }
    }
    GapOutcome::Conflict
}

#[derive(Debug, PartialEq)]
pub enum ApplyError {
    /// 409 `conflict`, with one item per conflicting gap.
    Conflicts(Vec<ErrorItem>),
    /// More gap records than [`MAX_GAPS_PER_PROXY`] would be kept (503).
    GapCapacity,
}

/// Applies a validated report to the stored entry. Pure: returns the new entry
/// and the response, or the reason nothing may be stored.
pub fn apply(
    cur: &ProxyEntry,
    mut st: ProxyStatus,
    now: &str,
) -> Result<(ProxyEntry, StatusResponse), ApplyError> {
    let mut next = cur.clone();

    // Gaps first: they are independent of the snapshot (a stale epoch or a
    // lower sequence never drops a gap).
    let gaps = std::mem::take(&mut st.gaps);
    let mut conflicts = Vec::new();
    let (mut ack, mut dup): (Vec<Uuid>, Vec<Uuid>) = (Vec::new(), Vec::new());
    for (index, incoming) in gaps.into_iter().enumerate() {
        let id = gap_id(&incoming).clone();
        let pos = next.gaps.iter().position(|g| gap_id(g) == &id);
        match classify_gap(pos.map(|i| &next.gaps[i]), &incoming) {
            GapOutcome::Store => {
                next.gaps.push(incoming);
                push_unique(&mut ack, &id);
            }
            GapOutcome::CloseOutage => {
                if let Some(i) = pos {
                    next.gaps[i] = incoming;
                }
                push_unique(&mut ack, &id);
            }
            GapOutcome::Duplicate => {
                if !ack.contains(&id) {
                    push_unique(&mut dup, &id);
                }
            }
            GapOutcome::Conflict => conflicts.push(ErrorItem {
                index: u32::try_from(index).unwrap_or(u32::MAX),
                event_id: None,
                gap_id: Some(id),
                code: ErrorCode::Conflict,
            }),
        }
    }
    if !conflicts.is_empty() {
        return Err(ApplyError::Conflicts(conflicts));
    }
    if next.gaps.len() > MAX_GAPS_PER_PROXY {
        return Err(ApplyError::GapCapacity);
    }

    // Snapshot: new epoch (never applied before) or a higher sequence in the
    // current one.
    let epoch = st.epoch_id.as_str().to_string();
    let state_applied = match &cur.status {
        None => !cur.epochs_seen.contains(&epoch),
        Some(prev) if prev.epoch_id == st.epoch_id => {
            st.status_sequence.get() > prev.status_sequence.get()
        }
        Some(_) => !cur.epochs_seen.contains(&epoch),
    };
    if state_applied {
        if cur
            .status
            .as_ref()
            .is_none_or(|p| p.epoch_id != st.epoch_id)
        {
            next.epochs_seen.retain(|e| e != &epoch);
            next.epochs_seen.push(epoch);
            while next.epochs_seen.len() > MAX_EPOCHS_SEEN {
                next.epochs_seen.remove(0);
            }
        }
        next.status = Some(st);
    }
    next.last_seen = Some(now.to_string());
    Ok((
        next,
        StatusResponse {
            state_applied,
            acknowledged_gap_ids: ack,
            duplicate_gap_ids: dup,
        },
    ))
}

#[derive(Deserialize)]
struct Peek {
    proxy_id: Option<serde_json::Value>,
}

fn json_error(status: StatusCode, e: ApiError) -> Response {
    (
        status,
        Json(serde_json::to_value(e).unwrap_or(serde_json::Value::Null)),
    )
        .into_response()
}

fn fixed(code: ErrorCode, status: StatusCode) -> Response {
    json_error(status, ApiError::from_code(code))
}

fn now_rfc3339() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

/// The report handler's work, in a blocking context (the store fsyncs).
pub fn handle(ctx: &ProxyContext, peer_id: &str, body: &[u8]) -> Response {
    // Identity before anything else in the body (ledger L6b): a body proxy_id
    // that is a string and differs from the peer's is the same 404 as an
    // unknown proxy, whatever else is wrong with the body.
    if let Ok(Peek {
        proxy_id: Some(serde_json::Value::String(bid)),
    }) = serde_json::from_slice::<Peek>(body)
    {
        if bid != peer_id {
            return super::guard::proxy_unknown();
        }
    }
    let st = match parse_status(body) {
        Ok(s) => s,
        Err(_) => {
            return fixed(ErrorCode::SemanticInvalid, StatusCode::UNPROCESSABLE_ENTITY);
        }
    };
    if st.proxy_id.as_str() != peer_id {
        return super::guard::proxy_unknown();
    }
    let txn = ctx.store.begin();
    let cur = txn.entry(peer_id);
    match apply(&cur, st, &now_rfc3339()) {
        Err(ApplyError::Conflicts(items)) => json_error(
            StatusCode::CONFLICT,
            ApiError::from_code(ErrorCode::Conflict).with_items(items),
        ),
        Err(ApplyError::GapCapacity) => fixed(
            ErrorCode::parse("storage_limit"),
            StatusCode::SERVICE_UNAVAILABLE,
        ),
        Ok((next, resp)) => match txn.commit(peer_id, next) {
            Ok(()) => {
                Json(serde_json::to_value(resp).unwrap_or(serde_json::Value::Null)).into_response()
            }
            Err(e) => {
                tracing::error!(error = %e, "proxy state persist failed (status report)");
                fixed(
                    ErrorCode::parse("internal"),
                    StatusCode::INTERNAL_SERVER_ERROR,
                )
            }
        },
    }
}

pub async fn post_status(
    State(ctx): State<Arc<ProxyContext>>,
    Extension(id): Extension<VerifiedProxy>,
    body: Bytes,
) -> Response {
    tokio::task::spawn_blocking(move || handle(&ctx, &id.proxy_id, &body))
        .await
        .unwrap_or_else(|_| {
            fixed(
                ErrorCode::parse("internal"),
                StatusCode::INTERNAL_SERVER_ERROR,
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    const E1: &str = "00000000-0000-4000-8000-0000000000e1";
    const E2: &str = "00000000-0000-4000-8000-0000000000e2";
    const NOW: &str = "2026-10-11T01:00:00Z";

    fn uid(n: u32) -> String {
        format!("00000000-0000-4000-8000-{n:012x}")
    }

    fn outage(n: u32, ended: Value) -> Value {
        json!({"kind": "central_outage", "gap_id": uid(n),
            "detected_at": "2026-10-11T00:00:00Z", "started_at": "2026-10-11T00:00:00Z",
            "ended_at": ended})
    }

    fn quarantine(n: u32, code: &str) -> Value {
        json!({"kind": "event_quarantined", "gap_id": uid(n),
            "detected_at": "2026-10-11T00:00:00Z", "event_ids": [uid(900)], "code": code})
    }

    fn report(epoch: &str, seq: i64, gaps: Vec<Value>) -> ProxyStatus {
        let v = json!({
            "schema_version": 1, "report_id": uid(1000 + seq as u32), "proxy_id": "px-1",
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
        });
        parse_status(&serde_json::to_vec(&v).unwrap()).unwrap()
    }

    fn ids(v: &[Uuid]) -> Vec<String> {
        v.iter().map(|u| u.as_str().to_string()).collect()
    }

    #[test]
    fn snapshot_rules() {
        let cur = ProxyEntry::default();
        let (e1, r) = apply(&cur, report(E1, 5, vec![]), NOW).unwrap();
        assert!(r.state_applied);
        assert_eq!(e1.last_seen.as_deref(), Some(NOW));
        // lower and equal sequence: not applied, last_seen still moves
        let (e2, r) = apply(&e1, report(E1, 4, vec![]), "later").unwrap();
        assert!(!r.state_applied);
        assert_eq!(e2.status.as_ref().unwrap().status_sequence.get(), 5);
        assert_eq!(e2.last_seen.as_deref(), Some("later"));
        assert!(
            !apply(&e1, report(E1, 5, vec![]), NOW)
                .unwrap()
                .1
                .state_applied
        );
        // higher: applied
        let (e3, r) = apply(&e2, report(E1, 6, vec![]), NOW).unwrap();
        assert!(r.state_applied);
        // new epoch resets the sequence
        let (e4, r) = apply(&e3, report(E2, 1, vec![]), NOW).unwrap();
        assert!(r.state_applied);
        assert_eq!(e4.status.as_ref().unwrap().epoch_id.as_str(), E2);
        // a replay of the old epoch is not new
        let (e5, r) = apply(&e4, report(E1, 99, vec![]), NOW).unwrap();
        assert!(!r.state_applied);
        assert_eq!(e5.status.as_ref().unwrap().epoch_id.as_str(), E2);
        // the stored snapshot never carries gaps
        assert!(e4.status.unwrap().gaps.is_empty());
    }

    #[test]
    fn gap_upsert_is_idempotent_and_acked() {
        let g = vec![quarantine(1, "conflict"), outage(2, Value::Null)];
        let (e1, r) = apply(&ProxyEntry::default(), report(E1, 1, g.clone()), NOW).unwrap();
        assert_eq!(ids(&r.acknowledged_gap_ids), vec![uid(1), uid(2)]);
        assert!(r.duplicate_gap_ids.is_empty());
        assert_eq!(e1.gaps.len(), 2);
        // resend: duplicates, nothing new stored
        let (e2, r) = apply(&e1, report(E1, 2, g.clone()), NOW).unwrap();
        assert!(r.acknowledged_gap_ids.is_empty());
        assert_eq!(ids(&r.duplicate_gap_ids), vec![uid(1), uid(2)]);
        assert_eq!(e2.gaps, e1.gaps);
        // a stale epoch never drops a gap
        let (e3, r) = apply(&e2, report(E1, 1, vec![quarantine(3, "conflict")]), NOW).unwrap();
        assert!(!r.state_applied);
        assert_eq!(ids(&r.acknowledged_gap_ids), vec![uid(3)]);
        assert_eq!(e3.gaps.len(), 3);
    }

    #[test]
    fn outage_may_only_close() {
        let open = vec![outage(2, Value::Null)];
        let (e1, _) = apply(&ProxyEntry::default(), report(E1, 1, open), NOW).unwrap();
        // null -> value: updated and acked
        let closed = vec![outage(2, json!("2026-10-11T00:30:00Z"))];
        let (e2, r) = apply(&e1, report(E1, 2, closed.clone()), NOW).unwrap();
        assert_eq!(ids(&r.acknowledged_gap_ids), vec![uid(2)]);
        match &e2.gaps[0] {
            GapReport::CentralOutage(o) => assert!(o.ended_at.is_some()),
            _ => panic!("kind changed"),
        }
        // resending the closed one is a duplicate
        let (_, r) = apply(&e2, report(E1, 3, closed), NOW).unwrap();
        assert_eq!(ids(&r.duplicate_gap_ids), vec![uid(2)]);
        // closed -> another value, closed -> null: conflict
        for v in [json!("2026-10-11T00:31:00Z"), Value::Null] {
            let err = apply(&e2, report(E1, 4, vec![outage(2, v)]), NOW).unwrap_err();
            let ApplyError::Conflicts(items) = err else {
                panic!("expected conflicts")
            };
            assert_eq!(items.len(), 1);
            assert_eq!(items[0].index, 0);
            assert_eq!(items[0].gap_id.as_ref().unwrap().as_str(), uid(2));
            assert_eq!(items[0].code, ErrorCode::Conflict);
        }
        // an open outage with a different start is not a close
        let mut other = outage(2, json!("2026-10-11T00:30:00Z"));
        other["started_at"] = json!("2026-10-11T00:00:01Z");
        assert!(apply(&e1, report(E1, 2, vec![other]), NOW).is_err());
    }

    #[test]
    fn any_other_difference_conflicts_and_applies_nothing() {
        let (e1, _) = apply(
            &ProxyEntry::default(),
            report(E1, 1, vec![quarantine(1, "conflict")]),
            NOW,
        )
        .unwrap();
        // same id, different content; a good new gap rides along at index 1
        let err = apply(
            &e1,
            report(
                E1,
                2,
                vec![quarantine(1, "semantic_invalid"), quarantine(9, "conflict")],
            ),
            "later",
        )
        .unwrap_err();
        let ApplyError::Conflicts(items) = err else {
            panic!()
        };
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].index, 0);
        // same id, different kind
        let err = apply(&e1, report(E1, 2, vec![outage(1, Value::Null)]), NOW).unwrap_err();
        assert!(matches!(err, ApplyError::Conflicts(_)));
        // two conflicts are both listed with their indexes
        let (e2, _) = apply(&e1, report(E1, 2, vec![quarantine(2, "conflict")]), NOW).unwrap();
        let err = apply(
            &e2,
            report(
                E1,
                3,
                vec![
                    quarantine(1, "sequence_conflict"),
                    quarantine(2, "semantic_invalid"),
                ],
            ),
            NOW,
        )
        .unwrap_err();
        let ApplyError::Conflicts(items) = err else {
            panic!()
        };
        assert_eq!(
            items.iter().map(|i| i.index).collect::<Vec<_>>(),
            vec![0, 1]
        );
    }

    #[test]
    fn same_gap_twice_in_one_report() {
        let g = quarantine(1, "conflict");
        let (e, r) = apply(
            &ProxyEntry::default(),
            report(E1, 1, vec![g.clone(), g.clone()]),
            NOW,
        )
        .unwrap();
        assert_eq!(e.gaps.len(), 1);
        assert_eq!(ids(&r.acknowledged_gap_ids), vec![uid(1)]);
        assert!(r.duplicate_gap_ids.is_empty(), "no id in both lists");
        r.validate_lists();
        let bad = apply(
            &ProxyEntry::default(),
            report(E1, 1, vec![g, quarantine(1, "semantic_invalid")]),
            NOW,
        );
        assert!(matches!(bad, Err(ApplyError::Conflicts(_))));
    }

    #[test]
    fn gap_capacity_is_bounded() {
        let mut cur = ProxyEntry::default();
        for n in 0..MAX_GAPS_PER_PROXY as u32 {
            cur.gaps
                .push(serde_json::from_value(quarantine(10_000 + n, "conflict")).unwrap());
        }
        let err = apply(&cur, report(E1, 1, vec![quarantine(1, "conflict")]), NOW).unwrap_err();
        assert_eq!(err, ApplyError::GapCapacity);
        // re-sending a known one still works at the cap
        assert!(apply(
            &cur,
            report(E1, 1, vec![quarantine(10_000, "conflict")]),
            NOW
        )
        .is_ok());
    }

    trait Lists {
        fn validate_lists(&self);
    }
    impl Lists for StatusResponse {
        fn validate_lists(&self) {
            assert!(sigil_proxy_api::Validate::validate(self).is_ok());
        }
    }
}
