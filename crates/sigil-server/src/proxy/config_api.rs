//! `PUT /v1/proxies/{id}/config` (management, `config` scope) and
//! `GET /v1/proxies/{id}/config` / `GET /v1/proxy-config` (proxy identity).
//!
//! PUT order after the management guard (control-plane §2.2, S2a pattern):
//! unknown `proxy_id` (404) -> body validation (422) -> state and revision
//! (409). Every outcome is audited BEFORE its effect; an audit failure answers
//! 503 and stores nothing. The revision is assigned by the server
//! (`expected_revision + 1`), the operator cannot choose it.
//!
//! GET restamps `issued_at`/`expires_at`/`ttl_seconds` on every fetch. That is
//! the TTL refresh of control-plane §6.2 (M-1); the stamps are excluded from
//! `config_hash`, so a refresh never looks like a new config.

use super::guard::{proxy_unknown, VerifiedProxy};
use super::identity::is_dns_label;
use super::mgmt::{
    api_error, audit_of, audit_unavailable, internal, state_str, Actor, MgmtRequest,
};
use super::store::{ProxyEntry, StoredConfig};
use super::ProxyContext;
use axum::body::Bytes;
use axum::extract::{Extension, Path, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use sigil_proxy_api::{parse_config_put, ErrorCode, PositiveI64, Timestamp};
use std::sync::Arc;
use time::OffsetDateTime;

/// Body cap of the config PUT: 256 routes with up to 1024 principals in total
/// stay far below it.
pub const MAX_PUT_BODY: usize = 256 * 1024;

/// UTC RFC 3339 at second resolution, the shape `Timestamp` accepts.
fn stamp(t: OffsetDateTime) -> Timestamp {
    let t = t.replace_nanosecond(0).unwrap_or(t);
    let text = t
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default();
    Timestamp::new(text).unwrap_or_else(|_| unreachable!("Rfc3339 UTC at second resolution"))
}

fn refuse(
    actor: &Actor<'_>,
    proxy_id: &str,
    code: ErrorCode,
    state: Option<super::registry::ProxyState>,
    from_revision: Option<u64>,
) -> Response {
    let status = code.http_status().unwrap_or(500);
    let mut e = actor.entry(proxy_id, Some(code.clone()), status);
    e.from_state = state.map(|s| state_str(s).into());
    e.from_revision = from_revision;
    match audit_of(actor.ctx).append(e) {
        Ok(_) => api_error(code),
        Err(err) => {
            tracing::error!(error = %err, "management audit append failed");
            audit_unavailable()
        }
    }
}

/// Blocking body of the PUT handler.
pub fn put_config(ctx: &ProxyContext, req: &MgmtRequest, path_id: &str, body: &[u8]) -> Response {
    use super::mgmt::MgmtRoute;
    let actor = Actor {
        ctx,
        req,
        route: MgmtRoute::ConfigPut,
    };
    if !is_dns_label(path_id) {
        return refuse(&actor, "", ErrorCode::ProxyUnknown, None, None);
    }
    let id = path_id;
    // Lock order: registry, then store. Held through audit and persist.
    let rtxn = ctx.registry.begin();
    let Some(rec) = rtxn.get(id) else {
        return refuse(&actor, id, ErrorCode::ProxyUnknown, None, None);
    };
    let st = Some(rec.state);

    let Ok(parsed) = parse_config_put(body) else {
        return refuse(&actor, id, ErrorCode::SemanticInvalid, st, None);
    };
    if parsed.config.proxy_id.as_str() != id {
        return refuse(&actor, id, ErrorCode::SemanticInvalid, st, None);
    }
    let stxn = ctx.store.begin();
    let cur = stxn.entry(id);
    let cur_rev = cur.revision();
    let expected = parsed.expected_revision.get() as u64;

    let Some(next_rev) = cur_rev
        .checked_add(1)
        .and_then(|r| i64::try_from(r).ok())
        .and_then(|r| PositiveI64::new(r).ok())
    else {
        // Revision counter exhausted (2^63-1): nothing more can be issued.
        return refuse(&actor, id, ErrorCode::SemanticInvalid, st, Some(cur_rev));
    };
    let now = OffsetDateTime::now_utc();
    let ttl = i64::from(ctx.config_ttl);
    let issued_at = stamp(now);
    let expires_at = stamp(now + time::Duration::seconds(ttl));
    let Ok(cfg) = parsed
        .config
        .into_config(next_rev, issued_at, expires_at, ttl)
    else {
        return refuse(&actor, id, ErrorCode::SemanticInvalid, st, Some(cur_rev));
    };
    // Ledger L1: E >= R + M, with M a server setting.
    if cfg.event_retention_seconds
        < cfg.max_offline_retry_age_seconds + i64::from(ctx.ack_loss_margin)
    {
        return refuse(&actor, id, ErrorCode::SemanticInvalid, st, Some(cur_rev));
    }
    if rec.state == super::registry::ProxyState::Retired {
        return refuse(&actor, id, ErrorCode::InvalidState, st, Some(cur_rev));
    }
    if expected != cur_rev {
        return refuse(&actor, id, ErrorCode::RevisionConflict, st, Some(cur_rev));
    }

    let hash = cfg.config_hash().as_str().to_string();
    let mut ok = actor.entry(id, None, 200);
    ok.from_state = st.map(|s| state_str(s).into());
    ok.from_revision = Some(cur_rev);
    ok.to_revision = Some(next_rev.get() as u64);
    ok.config_hash = Some(hash.clone());
    // Audit BEFORE the effect.
    if let Err(e) = audit_of(ctx).append(ok) {
        tracing::error!(error = %e, "management audit append failed");
        return audit_unavailable();
    }
    let updated_at = stamp(now).as_str().to_string();
    let new = ProxyEntry {
        config: Some(StoredConfig {
            config: cfg,
            config_hash: hash.clone(),
            updated_at,
        }),
        ..cur
    };
    match stxn.commit(id, new) {
        Ok(()) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "request_id": req.request_id,
                "revision": next_rev.get(),
                "config_hash": hash,
            })),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "proxy state persist failed after audit");
            let mut f = actor.entry(id, Some(ErrorCode::parse("persist_failed")), 500);
            f.from_revision = Some(cur_rev);
            f.config_hash = Some(hash);
            let _ = audit_of(ctx).append(f);
            internal()
        }
    }
}

pub async fn put_config_handler(
    State(ctx): State<Arc<ProxyContext>>,
    Extension(req): Extension<Arc<MgmtRequest>>,
    Path(id): Path<String>,
    body: Bytes,
) -> Response {
    tokio::task::spawn_blocking(move || put_config(&ctx, &req, &id, &body))
        .await
        .unwrap_or_else(|_| internal())
}

/// `GET /v1/proxies/{id}/config` and `GET /v1/proxy-config`. The identity is
/// the guard's verified proxy (path id equal to it, or no path id), so only
/// that proxy's own config can be returned. No config yet is 404
/// `config_unavailable`; unknown/mismatched identities never get here (404
/// `proxy_unknown`), disabled and retired get 403 from the guard.
pub async fn get_own_config(
    State(ctx): State<Arc<ProxyContext>>,
    Extension(who): Extension<VerifiedProxy>,
) -> Response {
    let Some(stored) = ctx.store.config(&who.proxy_id) else {
        return (
            StatusCode::NOT_FOUND,
            [(header::CACHE_CONTROL, "no-store")],
            Json(
                serde_json::to_value(sigil_proxy_api::ApiError::from_code(
                    ErrorCode::ConfigUnavailable,
                ))
                .unwrap_or_default(),
            ),
        )
            .into_response();
    };
    // Defence in depth: the store is keyed by proxy_id and boot checks that the
    // key and the document agree; never serve a document of another proxy.
    if stored.config.proxy_id.as_str() != who.proxy_id {
        tracing::error!("stored config does not belong to its key; refusing to serve it");
        return proxy_unknown();
    }
    let now = OffsetDateTime::now_utc();
    let ttl = i64::from(ctx.config_ttl);
    let cfg = stored
        .config
        .restamped(stamp(now), stamp(now + time::Duration::seconds(ttl)), ttl);
    (
        StatusCode::OK,
        [(header::CACHE_CONTROL, "no-store")],
        Json(serde_json::to_value(cfg).unwrap_or_default()),
    )
        .into_response()
}
