//! `POST /v1/proxy-inventory` (T-13a-server, issue #304): inventory reports.
//!
//! Spec: registry.md R5/R7 (report, I-1..I-8, projection, Cases), decisions.md
//! "T-13/T-14 범위" (separate endpoint, O-4). PX-005/010/011, AC-02/05/06.
//!
//! Answer order, first match wins (the identity layer runs before this handler
//! and before any body byte is read):
//!
//! | Step | Condition | Answer |
//! |---|---|---|
//! | guard | no/unknown/mismatched identity | 404 `proxy_unknown` |
//! | guard | disabled / retired | 403 `disabled` / `retired` |
//! | slot | all ingest slots busy | 429 `rate_limited` (body unread) |
//! | body | more than 4 MiB | 413 `payload_too_large` (before any parse) |
//! | identity-in-body | body `proxy_id` != mTLS identity | 404 `proxy_unknown` |
//! | parse | schema/syntax/conditional-field rules | 422 `semantic_invalid` (no value echoed) / 413 for a count bound |
//! | I-4 | `report_id` stored with an equal canonical report | 200 (duplicate), nothing re-judged |
//! | I-1 | scope not assigned to this proxy; a ref registered under another proxy; a known previous snapshot failing I-3/I-6/I-7/I-8 | 422 `semantic_invalid` |
//! | I-4 | `report_id` (or the snapshot id) taken by a different report | 409 `conflict` |
//! | I-2 | a ref (member, change or link) nobody registered | 424 `metadata_ref_pending` + `pending_metadata_refs` |
//! | store | cap reached / store failed | 503 `storage_limit` / `storage_unavailable` |
//! | commit | stored and projected | 200 `{report_id, duplicate}` |
//!
//! Precedence 422 > 409 > 424 as for `POST /v1/proxy-events`; nothing is stored
//! for any non-200 answer. 200 is sent only after the ledger commit, which also
//! holds the projection (drift, markers, gaps), so a 200 is durable.
//!
//! OPEN: the 200 body is not part of the contract (the api crate has no
//! response type). `{report_id, duplicate}` is a candidate; a producer must
//! treat any 200 as the ACK.
//!
//! OPEN: I-2 is applied to every ref the report names (members, `changes`,
//! `links`), not to members only; a ref that is registered under another proxy
//! is a 422 (as SV-3 for events), not a 424 that could never resolve.
//!
//! OPEN: member refs are not cross-checked against their registry entry's
//! `key_id`/`canon`/scope; the contract lists no such rule.

use super::guard::{proxy_unknown, VerifiedProxy};
use super::ingest::{acquire_slot, api_response, differs, fixed, read_body, storage_error};
use super::ledger_inventory::{report_digest, InventoryOutcome, RefCheck};
use super::metadata::RefLookup;
use super::ProxyContext;
use axum::body::Body;
use axum::extract::{Extension, State};
use axum::http::{Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use sigil_proxy_api::{
    parse_inventory_report, ApiError, Change, Comparison, Completeness, ErrorCategory, ErrorCode,
    InventoryReport, MetadataRef,
};
use std::collections::BTreeMap;
use std::sync::Arc;

pub const INVENTORY_PATH: &str = "/v1/proxy-inventory";
/// Request body cap. The contract sets none (about 450 KB at 10,000 members,
/// more with many `changes`); 4 MiB is an initial test value (D-04).
pub const MAX_INVENTORY_BODY: usize = 4 * 1024 * 1024;

/// A string `proxy_id` in the raw body that is not the caller's, read before
/// the typed parse (so a malformed neighbour field cannot hide it).
fn foreign_proxy_id_in_body(body: &[u8], peer_id: &str) -> bool {
    let Ok(serde_json::Value::Object(doc)) = serde_json::from_slice::<serde_json::Value>(body)
    else {
        return false;
    };
    differs(doc.get("proxy_id"), peer_id)
}

fn ack(report_id: &str, duplicate: bool) -> Response {
    Json(serde_json::json!({ "report_id": report_id, "duplicate": duplicate })).into_response()
}

/// Every ref a report names, de-duplicated, in a stable order.
fn named_refs(r: &InventoryReport) -> BTreeMap<&str, &MetadataRef> {
    let mut out = BTreeMap::new();
    for m in r.members.iter().flatten() {
        out.insert(m.as_str(), m);
    }
    match r.comparison.as_ref() {
        Some(Comparison::Compared { changes, .. }) => {
            for c in changes {
                match c {
                    Change::Added { metadata_ref } | Change::Removed { metadata_ref } => {
                        out.insert(metadata_ref.as_str(), metadata_ref);
                    }
                    Change::Changed {
                        metadata_ref,
                        previous_metadata_ref,
                    } => {
                        out.insert(metadata_ref.as_str(), metadata_ref);
                        out.insert(previous_metadata_ref.as_str(), previous_metadata_ref);
                    }
                }
            }
        }
        Some(Comparison::Rebaseline { links, .. }) => {
            for l in links {
                out.insert(l.from_metadata_ref.as_str(), &l.from_metadata_ref);
                out.insert(l.to_metadata_ref.as_str(), &l.to_metadata_ref);
            }
        }
        _ => {}
    }
    out
}

/// How far a report's `observed_at` (the proxy's clock) may be ahead of the
/// server's receipt time. Chain order uses the producer clock, so a clock far
/// in the future would pin a chain's "latest" snapshot; beyond this skew the
/// report is a 422 `semantic_invalid`. A past `observed_at` is always accepted
/// (a spooled report may be old). Initial test value (D-04).
pub const MAX_OBSERVED_AHEAD_SECS: i64 = 300;

/// Blocking body of the handler: validate against the registry, then store.
pub fn handle(ctx: &ProxyContext, peer_id: &str, body: &[u8]) -> Response {
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    handle_at(ctx, peer_id, body, now)
}

/// [`handle`] with the server clock (unix seconds) given, for tests.
pub fn handle_at(ctx: &ProxyContext, peer_id: &str, body: &[u8], now: i64) -> Response {
    if foreign_proxy_id_in_body(body, peer_id) {
        ctx.ingest_log.note("inventory", "identity_mismatch");
        return proxy_unknown();
    }
    let report = match parse_inventory_report(body) {
        Ok(r) => r,
        Err(e) => {
            if e.category() == ErrorCategory::Limit {
                ctx.ingest_log.note("inventory", "payload_too_large");
                return fixed(ErrorCode::PayloadTooLarge);
            }
            ctx.ingest_log.note("inventory", "invalid");
            return fixed(ErrorCode::SemanticInvalid);
        }
    };
    if report.proxy_id.as_str() != peer_id {
        ctx.ingest_log.note("inventory", "identity_mismatch");
        return proxy_unknown();
    }
    let digest = report_digest(&report);

    // I-4: an equal report already stored is a duplicate. It is not re-judged
    // against the (since changed) route scopes or the registry.
    match ctx
        .ledger
        .inventory_report_equal(peer_id, report.report_id.as_str(), &digest)
    {
        Ok(true) => {
            super::ingest::touch_last_seen(ctx, peer_id);
            return ack(report.report_id.as_str(), true);
        }
        Ok(false) => {}
        Err(e) => return storage_error(&e),
    }

    // Producer clock bound (see MAX_OBSERVED_AHEAD_SECS).
    let observed = super::projection::timestamp_secs(report.observed_at.as_str());
    if observed.is_none_or(|o| o > now.saturating_add(MAX_OBSERVED_AHEAD_SECS)) {
        ctx.ingest_log.note("inventory", "observed_at_ahead");
        return fixed(ErrorCode::SemanticInvalid);
    }

    // I-1: the scope is one the server assigned to this proxy and upstream.
    if !ctx.store.scope_assigned(
        peer_id,
        report.scope.upstream_id.as_str(),
        report.scope.credential_scope_id.as_str(),
    ) {
        ctx.ingest_log.note("inventory", "semantic_invalid");
        return fixed(ErrorCode::SemanticInvalid);
    }

    // I-2: every ref the report names is registered for this proxy.
    let mut refs = RefCheck::default();
    if report.completeness == Completeness::Complete {
        let named = named_refs(&report);
        let keys: Vec<&str> = named.keys().copied().collect();
        let found = match ctx.metadata.lookup(peer_id, &keys) {
            Ok(f) => f,
            Err(_) => return fixed(ErrorCode::StorageUnavailable),
        };
        for (r, lookup) in named.values().zip(found) {
            match lookup {
                RefLookup::Own(_) => {}
                RefLookup::OtherProxy => refs.other_proxy = true,
                RefLookup::Unknown => refs.unregistered.push((*r).clone()),
            }
        }
    }

    match ctx
        .ledger
        .ingest_inventory(peer_id, &report, &digest, &refs, now)
    {
        Ok(InventoryOutcome::Accepted) => {
            super::ingest::touch_last_seen(ctx, peer_id);
            ack(report.report_id.as_str(), false)
        }
        Ok(InventoryOutcome::Duplicate) => {
            super::ingest::touch_last_seen(ctx, peer_id);
            ack(report.report_id.as_str(), true)
        }
        Ok(InventoryOutcome::Invalid) => {
            ctx.ingest_log.note("inventory", "semantic_invalid");
            fixed(ErrorCode::SemanticInvalid)
        }
        Ok(InventoryOutcome::Conflict) => {
            ctx.ingest_log.note("inventory", "conflict");
            fixed(ErrorCode::Conflict)
        }
        Ok(InventoryOutcome::Pending(pending)) => {
            ctx.ingest_log.note("inventory", "metadata_ref_pending");
            api_response(
                StatusCode::from_u16(424).unwrap_or(StatusCode::FAILED_DEPENDENCY),
                ApiError::from_code(ErrorCode::MetadataRefPending)
                    .with_pending_metadata_refs(pending),
            )
        }
        Err(e) => {
            ctx.ingest_log.note("inventory", "storage");
            storage_error(&e)
        }
    }
}

/// Handler: take an ingest slot, read the capped body (with timeout), run
/// [`handle`] on the blocking pool while holding the slot.
pub async fn post_inventory(
    State(ctx): State<Arc<ProxyContext>>,
    Extension(id): Extension<VerifiedProxy>,
    req: Request<Body>,
) -> Response {
    let slot = match acquire_slot(&ctx, &id.proxy_id, "inventory") {
        Ok(s) => s,
        Err(r) => return *r,
    };
    let body = match read_body(&ctx, req.into_body(), MAX_INVENTORY_BODY, "inventory").await {
        Ok(b) => b,
        Err(r) => return *r,
    };
    let r = tokio::task::spawn_blocking(move || {
        let r = handle(&ctx, &id.proxy_id, &body);
        drop(slot);
        r
    })
    .await;
    r.unwrap_or_else(|_| fixed(ErrorCode::StorageUnavailable))
}
