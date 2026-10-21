//! Read views of the inventory projection (T-13a-server, issue #304).
//!
//! Spec: registry.md R7b; ledger-and-query.md L3 (limit, opaque cursor, filters,
//! `{items, next_cursor}`, 404 for unknown or out-of-scope targets).
//! PX-005/010/016, AC-02/05.
//!
//! * `GET /v1/proxies/{id}/inventory-snapshots`
//! * `GET /v1/proxies/{id}/drift`
//! * `GET /v1/proxies/{id}/rebaseline-markers`
//!
//! Same authentication as the S5 read API (host-class mTLS certificate plus the
//! read bearer; proxy, management and registry-held certificates get the
//! host-route `host_unknown` answer) and the same scope function
//! ([`read_scope`]). An unknown proxy and an out-of-scope proxy are one
//! byte-identical 404 `proxy_unknown`. Order is the ledger commit counter,
//! descending, so rows never move; the cursor is bound to endpoint, proxy,
//! order and normalised filters. Responses carry refs and identifiers only:
//! no tool name, definition, fingerprint or key (PX-010).
//!
//! Filters: `upstream_id`, `credential_scope_id`, `change` (drift only), and
//! `from`/`to` on `received_at` (snapshots) or `detected_at` (drift, markers,
//! which is the receipt time of the report that produced them). Endpoint names
//! are candidates (registry.md R7b).

use super::guard::proxy_unknown;
use super::ledger_inventory::InvFilter;
use super::query::{
    blocking, decode_cursor, encode_cursor, filter_hash, guarded, parse_enum, parse_id,
    parse_limit, parse_params, parse_time, read_scope, visible, Page, QErr,
};
use super::ProxyContext;
use crate::auth::ReadToken;
use axum::extract::{Path, RawQuery, State};
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;
use std::sync::Arc;

pub const SNAPSHOTS_SEGMENT: &str = "inventory-snapshots";
pub const DRIFT_SEGMENT: &str = "drift";
pub const MARKERS_SEGMENT: &str = "rebaseline-markers";

#[derive(Clone, Copy)]
enum View {
    Snapshots,
    Drift,
    Markers,
}

impl View {
    fn name(self) -> &'static str {
        match self {
            View::Snapshots => SNAPSHOTS_SEGMENT,
            View::Drift => DRIFT_SEGMENT,
            View::Markers => MARKERS_SEGMENT,
        }
    }
    fn order(self) -> &'static str {
        match self {
            View::Snapshots => "snap_seq.desc",
            View::Drift => "drift_seq.desc",
            View::Markers => "marker_seq.desc",
        }
    }
}

/// The three read routes. Other methods keep the plain 404 these paths had
/// before (no 405 hint), like `GET /v1/proxies/{id}`.
pub fn router(ctx: Arc<ProxyContext>, read_token: ReadToken) -> Router {
    let route = |mr: axum::routing::MethodRouter<Arc<ProxyContext>>| {
        guarded(mr, &ctx, &read_token).fallback(|| async { StatusCode::NOT_FOUND })
    };
    Router::new()
        .route(
            "/v1/proxies/:proxy_id/inventory-snapshots",
            route(get(list_snapshots)),
        )
        .route("/v1/proxies/:proxy_id/drift", route(get(list_drift)))
        .route(
            "/v1/proxies/:proxy_id/rebaseline-markers",
            route(get(list_markers)),
        )
        .with_state(ctx)
}

async fn list_snapshots(
    State(ctx): State<Arc<ProxyContext>>,
    parts: Parts,
    Path(proxy_id): Path<String>,
    RawQuery(q): RawQuery,
) -> Response {
    list(ctx, parts, proxy_id, q, View::Snapshots).await
}

async fn list_drift(
    State(ctx): State<Arc<ProxyContext>>,
    parts: Parts,
    Path(proxy_id): Path<String>,
    RawQuery(q): RawQuery,
) -> Response {
    list(ctx, parts, proxy_id, q, View::Drift).await
}

async fn list_markers(
    State(ctx): State<Arc<ProxyContext>>,
    parts: Parts,
    Path(proxy_id): Path<String>,
    RawQuery(q): RawQuery,
) -> Response {
    list(ctx, parts, proxy_id, q, View::Markers).await
}

async fn list(
    ctx: Arc<ProxyContext>,
    parts: Parts,
    proxy_id: String,
    q: Option<String>,
    view: View,
) -> Response {
    let scope = read_scope(&ctx, &parts.extensions);
    // Unknown and out-of-scope are one answer, before any filter is looked at.
    match ctx.registry.get(&proxy_id) {
        Some(r) if visible(&scope, &r.proxy_id) => {}
        _ => return proxy_unknown(),
    }
    match list_inner(ctx, proxy_id, q, view).await {
        Ok(r) => r,
        Err(e) => e.into_response(),
    }
}

fn items_of<T: Serialize>(items: &[T]) -> Vec<serde_json::Value> {
    items
        .iter()
        .map(|i| serde_json::to_value(i).unwrap_or_default())
        .collect()
}

async fn list_inner(
    ctx: Arc<ProxyContext>,
    proxy_id: String,
    q: Option<String>,
    view: View,
) -> Result<Response, QErr> {
    let allowed: &[&str] = match view {
        View::Drift => &[
            "upstream_id",
            "credential_scope_id",
            "change",
            "from",
            "to",
            "limit",
            "cursor",
        ],
        _ => &[
            "upstream_id",
            "credential_scope_id",
            "from",
            "to",
            "limit",
            "cursor",
        ],
    };
    let mut p = parse_params(q.as_deref(), allowed)?;
    let limit = parse_limit(&mut p)?;
    let f = InvFilter {
        upstream_id: p.remove("upstream_id").map(|v| parse_id(&v)).transpose()?,
        credential_scope_id: p
            .remove("credential_scope_id")
            .map(|v| parse_id(&v))
            .transpose()?,
        change: p
            .remove("change")
            .map(|v| parse_enum(&v, &["added", "removed", "changed"]))
            .transpose()?,
        from: p.remove("from").map(|v| parse_time(&v)).transpose()?,
        to: p.remove("to").map(|v| parse_time(&v)).transpose()?,
    };
    let norm = format!(
        "upstream_id={};credential_scope_id={};change={};from={};to={}",
        f.upstream_id.as_deref().unwrap_or(""),
        f.credential_scope_id.as_deref().unwrap_or(""),
        f.change.as_deref().unwrap_or(""),
        f.from.map_or(String::new(), |v| v.to_string()),
        f.to.map_or(String::new(), |v| v.to_string()),
    );
    // The proxy is part of the endpoint binding: a cursor cannot be replayed
    // against another proxy's list.
    let hash = filter_hash(&format!("{}:{proxy_id}", view.name()), view.order(), &norm);
    let after = match p.remove("cursor") {
        None => None,
        Some(c) => match decode_cursor(&c, &hash)? {
            serde_json::Value::Number(n) => match n.as_i64() {
                Some(k) if k > 0 => Some(k),
                _ => return Err(QErr::Cursor),
            },
            _ => return Err(QErr::Cursor),
        },
    };
    let (items, next_key) = blocking(move || {
        let l = &ctx.ledger;
        Ok(match view {
            View::Snapshots => {
                let pg = l.list_inventory_snapshots(&proxy_id, &f, after, limit)?;
                (items_of(&pg.items), pg.next_key)
            }
            View::Drift => {
                let pg = l.list_inventory_drift(&proxy_id, &f, after, limit)?;
                (items_of(&pg.items), pg.next_key)
            }
            View::Markers => {
                let pg = l.list_inventory_markers(&proxy_id, &f, after, limit)?;
                (items_of(&pg.items), pg.next_key)
            }
        })
    })
    .await?;
    let next_cursor = next_key.map(|k| encode_cursor(serde_json::Value::from(k), &hash));
    Ok(Json(Page { items, next_cursor }).into_response())
}
