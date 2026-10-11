//! Proxy-route guard and host-route cross-rejection (control-plane §1.2).
//!
//! Proxy order: mTLS proxy class, SAN proxy_id, (path id), registry lookup,
//! fingerprint (current|next), state. Every identity failure, including a
//! pending entry, yields one byte-identical 404 `proxy_unknown`. This runs as
//! a layer BEFORE any body extraction.

use super::identity::{proxy_id_from_san, PeerClass};
use super::registry::{ProxyRecord, ProxyState};
use super::ProxyContext;
use crate::tls_accept::PeerIdentity;
use axum::body::Body;
use axum::extract::State;
use axum::http::{header, Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use sigil_proxy_api::{ApiError, ErrorCode};
use std::sync::Arc;

pub const PROXY_CONFIG_PATH: &str = "/v1/proxy-config";
const PROXIES_PREFIX: &str = "/v1/proxies/";

fn json_error(status: StatusCode, code: ErrorCode) -> Response {
    let body = serde_json::to_vec(&ApiError::from_code(code)).unwrap_or_default();
    (
        status,
        [(header::CONTENT_TYPE, "application/json")],
        Body::from(body),
    )
        .into_response()
}

/// The single identity-failure answer. Same bytes for unknown proxy, wrong
/// fingerprint, host cert, pending entry and path-id mismatch.
pub fn proxy_unknown() -> Response {
    json_error(StatusCode::NOT_FOUND, ErrorCode::ProxyUnknown)
}

fn is_proxy_path(path: &str) -> bool {
    path == PROXY_CONFIG_PATH || path.starts_with(PROXIES_PREFIX)
}

/// `Some(id)` for `/v1/proxies/{id}/...`.
fn path_proxy_id(path: &str) -> Option<&str> {
    path.strip_prefix(PROXIES_PREFIX)
        .and_then(|r| r.split('/').next())
}

/// Identity check. `Err` carries the response to send.
fn check(
    ctx: &ProxyContext,
    peer: Option<&PeerIdentity>,
    path: &str,
) -> Result<ProxyRecord, Box<Response>> {
    let peer = peer.ok_or_else(|| Box::new(proxy_unknown()))?;
    if ctx.ca.classify(peer) != PeerClass::Proxy {
        return Err(Box::new(proxy_unknown()));
    }
    let id = proxy_id_from_san(&peer.san_dns, peer.cn.as_deref())
        .ok_or_else(|| Box::new(proxy_unknown()))?;
    if path_proxy_id(path).is_some_and(|p| p != id) {
        return Err(Box::new(proxy_unknown()));
    }
    let rec = ctx
        .registry
        .get(&id)
        .ok_or_else(|| Box::new(proxy_unknown()))?;
    if !rec.matches_fingerprint(&peer.fingerprint) {
        return Err(Box::new(proxy_unknown()));
    }
    match rec.state {
        ProxyState::Active => Ok(rec),
        // Pending: registered but not yet activated, so indistinguishable 404.
        ProxyState::Pending => Err(Box::new(proxy_unknown())),
        // OPEN: control-plane §10 q4a — HTTP status of the disabled/retired
        // answers is undecided; 403 is a placeholder.
        ProxyState::Disabled => Err(Box::new(json_error(
            StatusCode::FORBIDDEN,
            ErrorCode::Disabled,
        ))),
        ProxyState::Retired => Err(Box::new(json_error(
            StatusCode::FORBIDDEN,
            ErrorCode::Retired,
        ))),
    }
}

/// Layer for proxy routes (installed with `route_layer`, so it runs before the
/// handler and its extractors).
pub async fn proxy_guard(
    State(ctx): State<Arc<ProxyContext>>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let peer = req.extensions().get::<Arc<PeerIdentity>>().cloned();
    match check(&ctx, peer.as_deref(), req.uri().path()) {
        Ok(_) => next.run(req).await,
        Err(resp) => *resp,
    }
}

/// Reject proxy-class (and ambiguous, and registry-held) certs on every
/// non-proxy route except the health probe. Runs before routing/body parsing.
///
/// Body is the non-revealing host-route shape (`host_unknown`, no host_id
/// echo: the request is not parsed, and nothing about the registry leaks).
/// DECIDED (orchestrator, L1): the no-echo body is deliberate; recorded in
/// decisions.md. It differs from the handler's own `host_unknown` only by the
/// missing `host_id` field.
///
/// A missing PeerIdentity is fail-closed: with `proxy:` configured mTLS is
/// mandatory, so a request without an identity should not exist; if one
/// appears (listener misconfiguration) it is rejected, never waved through.
// NOTE (L5): only /v1/healthz is exempt; any new unauthenticated probe route
// must be added here deliberately.
pub async fn host_route_guard(
    State(ctx): State<Arc<ProxyContext>>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let path = req.uri().path();
    if !is_proxy_path(path) && path != crate::app::HEALTHZ_PATH {
        let allowed = req
            .extensions()
            .get::<Arc<PeerIdentity>>()
            .is_some_and(|peer| {
                ctx.ca.classify(peer) == PeerClass::Host
                    && !ctx.registry.holds_fingerprint(&peer.fingerprint)
            });
        if !allowed {
            return (
                StatusCode::NOT_FOUND,
                axum::Json(serde_json::json!({"error": "host_unknown"})),
            )
                .into_response();
        }
    }
    next.run(req).await
}

async fn not_implemented() -> StatusCode {
    // Placeholder until the config DTO (S3). Reached only after a passing check.
    StatusCode::NOT_IMPLEMENTED
}

/// Proxy routes, each behind [`proxy_guard`].
pub fn router(ctx: Arc<ProxyContext>) -> Router {
    use axum::middleware::from_fn_with_state;
    Router::new()
        .route(
            PROXY_CONFIG_PATH,
            get(not_implemented).route_layer(from_fn_with_state(ctx.clone(), proxy_guard)),
        )
        .route(
            "/v1/proxies/:proxy_id/config",
            get(not_implemented).route_layer(from_fn_with_state(ctx, proxy_guard)),
        )
}
