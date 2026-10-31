//! Management routes: auth guard, lifecycle handlers, audit read
//! (control-plane §0.1, §1.3, §2.2, §3.2).
//!
//! Check order, pinned once (`mgmt_guard`, a layer that runs before routing so
//! even wrong-method probes see the same answers):
//! 1. not a management-caller cert, or no mTLS identity: 404, an empty body
//!    byte-identical to the router's unknown-route answer;
//! 2. verifier file unusable (fail closed): the same 404;
//! 3. bearer missing, wrong, bound to another caller cert, or expired: 401;
//! 4. scope insufficient: 403.
//!
//! Expiry is evaluated with the bearer (before scope) because an expired
//! credential is not an authenticated principal. Steps 3 and 4 are audited
//! (before the response), coalesced to one record per caller cert and reason
//! per minute that carries a `count`. Steps 1 and 2 are not audited (an
//! unauthenticated flood must not cost an fsync per request); a request that
//! carries a bearer there only feeds a rate-limited warning. The verifier file
//! is refreshed BEFORE the cert is classified, so a rotated caller list is
//! honoured on the very next request.
//!
//! After the guard, handlers run in this order: unknown `proxy_id` (404
//! `proxy_unknown`; the caller is already authenticated and scoped, so
//! existence is not hidden from it and an operator needs the answer), body
//! validation (422), state or uniqueness (409). Every outcome is audited
//! BEFORE its effect; an append failure answers 503 with no effect.

use super::audit::{AuditEntry, MgmtAudit};
use super::identity::{is_dns_label, PeerClass};
use super::lifecycle::{self, Denied};
use super::registry::{ProxyRecord, ProxyState};
use super::verifiers::{AuthOutcome, Principal, Scope};
use super::ProxyContext;
use crate::auth::{extract_bearer, require_bearer, ReadToken};
use crate::tls_accept::PeerIdentity;
use axum::body::Body;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Extension, Path, Query, State};
use axum::http::{HeaderMap, Request, StatusCode};
use axum::middleware::{from_fn_with_state, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use lodeline_proxy_api::{ApiError, ErrorCode};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

pub const AUDIT_PATH: &str = "/v1/proxy-management-audit";
pub const REGISTER_PATH: &str = "/v1/proxies";
pub const REQUESTED_BY_HEADER: &str = "x-lodeline-requested-by";
const MAX_BODY: usize = 16 * 1024;
const MAX_REQUESTED_BY: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MgmtRoute {
    Register,
    Fingerprints,
    Disable,
    Enable,
    Retire,
    /// `PUT /v1/proxies/{id}/config` (`GET` on the same path is a proxy route).
    ConfigPut,
}

impl MgmtRoute {
    pub fn required_scope(self) -> Scope {
        match self {
            MgmtRoute::Disable | MgmtRoute::ConfigPut => Scope::Config,
            _ => Scope::Identity,
        }
    }

    pub fn action(self) -> &'static str {
        match self {
            MgmtRoute::Register => "proxy.register",
            MgmtRoute::Fingerprints => "proxy.fingerprint_register",
            MgmtRoute::Disable => "proxy.disable",
            MgmtRoute::Enable => "proxy.enable",
            MgmtRoute::Retire => "proxy.retire",
            MgmtRoute::ConfigPut => "proxy.config_put",
        }
    }
}

/// Management route of `path` (any method) and the path's proxy id segment.
pub fn route_of(path: &str) -> Option<(MgmtRoute, Option<&str>)> {
    if path == REGISTER_PATH {
        return Some((MgmtRoute::Register, None));
    }
    let rest = path.strip_prefix("/v1/proxies/")?;
    let (id, verb) = rest.split_once('/')?;
    let route = match verb {
        "fingerprints" => MgmtRoute::Fingerprints,
        "disable" => MgmtRoute::Disable,
        "enable" => MgmtRoute::Enable,
        "retire" => MgmtRoute::Retire,
        "config" => MgmtRoute::ConfigPut,
        _ => return None,
    };
    Some((route, Some(id)))
}

/// Verified facts about one management request, set by the guard.
#[derive(Clone, Debug)]
pub struct MgmtRequest {
    pub principal: Principal,
    pub request_id: String,
    /// ASSERTED by the caller; recorded, never used for authorization.
    pub requested_by: Option<String>,
}

fn now_rfc3339() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

pub(super) fn api_error(code: ErrorCode) -> Response {
    let status = code
        .http_status()
        .and_then(|s| StatusCode::from_u16(s).ok())
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    (
        status,
        Json(serde_json::to_value(ApiError::from_code(code)).unwrap_or_default()),
    )
        .into_response()
}

/// 503 when the audit record cannot be written; nothing else happened.
pub(super) fn audit_unavailable() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(
            serde_json::to_value(ApiError::from_code(ErrorCode::parse("audit_unavailable")))
                .unwrap_or_default(),
        ),
    )
        .into_response()
}

pub(super) fn internal() -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(
            serde_json::to_value(ApiError::from_code(ErrorCode::parse("internal")))
                .unwrap_or_default(),
        ),
    )
        .into_response()
}

fn requested_by(headers: &HeaderMap) -> Option<String> {
    let v = headers.get(REQUESTED_BY_HEADER)?.to_str().ok()?;
    let s: String = v
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_REQUESTED_BY)
        .collect();
    let s = s.trim().to_string();
    (!s.is_empty()).then_some(s)
}

pub(super) fn audit_of(ctx: &ProxyContext) -> &MgmtAudit {
    ctx.audit.as_ref().expect("management implies audit")
}

/// Layer over the whole router; acts only on management paths.
pub async fn mgmt_guard(
    State(ctx): State<Arc<ProxyContext>>,
    mut req: Request<Body>,
    next: Next,
) -> Response {
    let Some((route, path_id)) = route_of(req.uri().path()) else {
        return next.run(req).await;
    };
    // `/v1/proxies/{id}/config` is shared with the proxy-identity GET: only PUT
    // is a management request, every other method goes to the router (the GET
    // handler sits behind the proxy guard, anything else is a 405).
    if route == MgmtRoute::ConfigPut && req.method() != axum::http::Method::PUT {
        return next.run(req).await;
    }
    // `/v1/proxies` is shared with the read-bearer listing `GET /v1/proxies`
    // (S5): a GET (or HEAD) is that read request, not a registration. Every
    // other method keeps the management answers (a wrong-method probe still
    // sees the same 404/401/403 as POST).
    if route == MgmtRoute::Register
        && matches!(
            *req.method(),
            axum::http::Method::GET | axum::http::Method::HEAD
        )
    {
        return next.run(req).await;
    }
    let (Some(auth), Some(_)) = (ctx.mgmt.as_ref(), ctx.audit.as_ref()) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    auth.refresh_if_changed();
    let has_bearer = req
        .headers()
        .contains_key(axum::http::header::AUTHORIZATION);
    let peer = req.extensions().get::<Arc<PeerIdentity>>().cloned();
    let Some(peer) = peer.filter(|p| ctx.peer_class(p) == PeerClass::Management) else {
        if has_bearer {
            ctx.note_probe("not_a_management_caller_cert");
        }
        return StatusCode::NOT_FOUND.into_response();
    };
    let request_id = uuid::Uuid::now_v7().to_string();
    let asserted = requested_by(req.headers());
    let token = extract_bearer(req.headers()).filter(|t| !t.is_empty());
    let proxy_id = path_id
        .filter(|i| is_dns_label(i))
        .unwrap_or_default()
        .to_string();
    let base = AuditEntry {
        request_id: request_id.clone(),
        action: route.action().to_string(),
        proxy_id,
        caller_fingerprint: peer.fingerprint.clone(),
        requested_by: asserted.clone(),
        ..Default::default()
    };
    match auth.authenticate(&peer.fingerprint, token, time::OffsetDateTime::now_utc()) {
        AuthOutcome::Denied => {
            if has_bearer {
                ctx.note_probe("verifier_file_unusable");
            }
            StatusCode::NOT_FOUND.into_response()
        }
        AuthOutcome::Unauthorized(reason, key_id) => {
            let Some(count) = ctx.deny_check(&peer.fingerprint, reason.as_str()) else {
                return api_error(ErrorCode::Unauthorized);
            };
            let entry = AuditEntry {
                result: "unauthorized".into(),
                http_status: 401,
                reason: Some(reason.as_str().into()),
                count: (count > 1).then_some(count),
                management_key_id: key_id.unwrap_or_default(),
                ..base
            };
            denied(ctx, entry, ErrorCode::Unauthorized).await
        }
        AuthOutcome::Ok(p) if p.scope != route.required_scope() => {
            let Some(count) = ctx.deny_check(&peer.fingerprint, "scope_insufficient") else {
                return api_error(ErrorCode::Forbidden);
            };
            let entry = AuditEntry {
                result: "forbidden".into(),
                http_status: 403,
                reason: Some("scope_insufficient".into()),
                count: (count > 1).then_some(count),
                management_key_id: p.key_id.clone(),
                scope: p.scope.as_str().into(),
                ..base
            };
            denied(ctx, entry, ErrorCode::Forbidden).await
        }
        AuthOutcome::Ok(principal) => {
            req.extensions_mut().insert(Arc::new(MgmtRequest {
                principal,
                request_id,
                requested_by: asserted,
            }));
            next.run(req).await
        }
    }
}

async fn denied(ctx: Arc<ProxyContext>, entry: AuditEntry, code: ErrorCode) -> Response {
    let (fp, reason) = (
        entry.caller_fingerprint.clone(),
        entry.reason.clone().unwrap_or_default(),
    );
    let c2 = ctx.clone();
    let r = tokio::task::spawn_blocking(move || audit_of(&c2).append(entry)).await;
    match r {
        Ok(Ok(_)) => {
            ctx.deny_audited(&fp, &reason);
            api_error(code)
        }
        Ok(Err(e)) => {
            tracing::error!(error = %e, "management audit append failed");
            audit_unavailable()
        }
        Err(_) => internal(),
    }
}

// ---- DTOs ----------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegisterBody {
    proxy_id: String,
    display_name: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FingerprintBody {
    fingerprint: String,
}

/// Public view of a registry entry. Fingerprints are public data (blake3 of a
/// certificate); no secret exists in a record.
#[derive(Serialize)]
pub struct ProxyView {
    pub proxy_id: String,
    pub display_name: String,
    pub state: ProxyState,
    pub fp_current: Option<String>,
    pub fp_next: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

impl From<&ProxyRecord> for ProxyView {
    fn from(r: &ProxyRecord) -> Self {
        Self {
            proxy_id: r.proxy_id.clone(),
            display_name: r.display_name.clone(),
            state: r.state,
            fp_current: r.fp_current.clone(),
            fp_next: r.fp_next.clone(),
            created_at: r.created_at.clone(),
            updated_at: r.updated_at.clone(),
        }
    }
}

pub(super) fn state_str(s: ProxyState) -> &'static str {
    match s {
        ProxyState::Pending => "pending",
        ProxyState::Active => "active",
        ProxyState::Disabled => "disabled",
        ProxyState::Retired => "retired",
    }
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

// ---- handlers ------------------------------------------------------------

/// Per-request audit helper bound to the verified principal.
pub(super) struct Actor<'a> {
    pub(super) ctx: &'a ProxyContext,
    pub(super) req: &'a MgmtRequest,
    pub(super) route: MgmtRoute,
}

impl Actor<'_> {
    pub(super) fn entry(&self, proxy_id: &str, code: Option<ErrorCode>, status: u16) -> AuditEntry {
        AuditEntry {
            request_id: self.req.request_id.clone(),
            action: self.route.action().into(),
            proxy_id: proxy_id.into(),
            result: code.map_or("ok".into(), |c| c.as_str().to_string()),
            http_status: status,
            management_key_id: self.req.principal.key_id.clone(),
            scope: self.req.principal.scope.as_str().into(),
            caller_fingerprint: self.req.principal.caller_fingerprint.clone(),
            requested_by: self.req.requested_by.clone(),
            ..Default::default()
        }
    }

    /// Audit a refusal, then answer it. 503 when the audit cannot be written.
    fn deny(&self, proxy_id: &str, code: ErrorCode, from: Option<ProxyState>) -> Response {
        let status = code.http_status().unwrap_or(500);
        let mut e = self.entry(proxy_id, Some(code.clone()), status);
        e.from_state = from.map(|s| state_str(s).into());
        match audit_of(self.ctx).append(e) {
            Ok(_) => api_error(code),
            Err(err) => {
                tracing::error!(error = %err, "management audit append failed");
                audit_unavailable()
            }
        }
    }

    /// Audit the success BEFORE the effect. `Err` carries the 503.
    fn pre_commit(
        &self,
        old: Option<&ProxyRecord>,
        new: &ProxyRecord,
        fp: Option<&str>,
        replaced: Option<String>,
    ) -> Result<(), Box<Response>> {
        let mut e = self.entry(&new.proxy_id, None, 200);
        e.replaced_fingerprint = replaced;
        e.from_state = old.map(|r| state_str(r.state).into());
        e.to_state = Some(state_str(new.state).into());
        e.subject_fingerprint = fp.map(str::to_string);
        audit_of(self.ctx).append(e).map(|_| ()).map_err(|err| {
            tracing::error!(error = %err, "management audit append failed");
            Box::new(audit_unavailable())
        })
    }

    /// Persist (inside the registry transaction), or report the failure. The
    /// audit already says `ok`; a follow-up record states the effect failed.
    fn commit(
        &self,
        txn: super::registry::RegistryTxn<'_>,
        new: ProxyRecord,
        status: StatusCode,
    ) -> Response {
        let view = ProxyView::from(&new);
        let id = new.proxy_id.clone();
        match txn.commit(new) {
            Ok(()) => (
                status,
                Json(serde_json::json!({
                    "request_id": self.req.request_id,
                    "proxy": view,
                })),
            )
                .into_response(),
            Err(e) => {
                tracing::error!(error = %e, "registry persist failed after audit");
                let _ = audit_of(self.ctx).append(self.entry(
                    &id,
                    Some(ErrorCode::parse("persist_failed")),
                    500,
                ));
                internal()
            }
        }
    }
}

fn perform(
    ctx: &ProxyContext,
    req: &MgmtRequest,
    route: MgmtRoute,
    path_id: Option<&str>,
    body: &[u8],
) -> Response {
    let actor = Actor { ctx, req, route };
    let now = now_rfc3339();

    if route == MgmtRoute::Register {
        let Ok(b) = serde_json::from_slice::<RegisterBody>(body) else {
            return actor.deny("", ErrorCode::SemanticInvalid, None);
        };
        let name_ok = !b.display_name.is_empty()
            && b.display_name.chars().count() <= 128
            && !b.display_name.chars().any(char::is_control);
        if !is_dns_label(&b.proxy_id) || !name_ok {
            return actor.deny("", ErrorCode::SemanticInvalid, None);
        }
        let txn = ctx.registry.begin();
        if let Some(existing) = txn.get(&b.proxy_id) {
            return actor.deny(&b.proxy_id, ErrorCode::AlreadyExists, Some(existing.state));
        }
        let new = lifecycle::new_pending(&b.proxy_id, &b.display_name, &now);
        if let Err(r) = actor.pre_commit(None, &new, None, None) {
            return *r;
        }
        return actor.commit(txn, new, StatusCode::CREATED);
    }

    let Some(id) = path_id.filter(|i| is_dns_label(i)) else {
        return actor.deny("", ErrorCode::ProxyUnknown, None);
    };
    let txn = ctx.registry.begin();
    let Some(cur) = txn.get(id) else {
        return actor.deny(id, ErrorCode::ProxyUnknown, None);
    };
    let (result, fp) = match route {
        MgmtRoute::Fingerprints => {
            let fp = match serde_json::from_slice::<FingerprintBody>(body) {
                Ok(b) if is_hex64(&b.fingerprint) => b.fingerprint,
                _ => return actor.deny(id, ErrorCode::SemanticInvalid, Some(cur.state)),
            };
            // A management-caller cert fingerprint can never be a proxy's.
            let owner = txn.fingerprint_owner(&fp).or_else(|| {
                ctx.mgmt
                    .as_ref()
                    .is_some_and(|m| m.is_caller(&fp))
                    .then(|| "management-caller".to_string())
            });
            (
                lifecycle::add_fingerprint(&cur, &fp, owner.as_deref(), &now),
                Some(fp),
            )
        }
        MgmtRoute::Disable => (lifecycle::disable(&cur, &now), None),
        MgmtRoute::Enable => (lifecycle::enable(&cur, &now), None),
        MgmtRoute::Retire => (lifecycle::retire(&cur, &now), None),
        MgmtRoute::Register | MgmtRoute::ConfigPut => unreachable!(),
    };
    match result {
        Err(Denied::InvalidState) => actor.deny(id, ErrorCode::InvalidState, Some(cur.state)),
        Err(Denied::FingerprintInUse) => actor.deny(id, ErrorCode::AlreadyExists, Some(cur.state)),
        Ok(new) => {
            // A fingerprint replace on a disabled entry drops the old ones.
            let replaced = (route == MgmtRoute::Fingerprints && cur.state == ProxyState::Disabled)
                .then(|| {
                    [cur.fp_current.as_deref(), cur.fp_next.as_deref()]
                        .into_iter()
                        .flatten()
                        .collect::<Vec<_>>()
                        .join(",")
                })
                .filter(|s| !s.is_empty());
            if let Err(r) = actor.pre_commit(Some(&cur), &new, fp.as_deref(), replaced) {
                return *r;
            }
            actor.commit(txn, new, StatusCode::OK)
        }
    }
}

async fn run(
    ctx: Arc<ProxyContext>,
    req: Arc<MgmtRequest>,
    route: MgmtRoute,
    id: Option<String>,
    body: Bytes,
) -> Response {
    tokio::task::spawn_blocking(move || perform(&ctx, &req, route, id.as_deref(), &body))
        .await
        .unwrap_or_else(|_| internal())
}

async fn register(
    State(ctx): State<Arc<ProxyContext>>,
    Extension(req): Extension<Arc<MgmtRequest>>,
    body: Bytes,
) -> Response {
    run(ctx, req, MgmtRoute::Register, None, body).await
}

macro_rules! id_handler {
    ($name:ident, $route:expr) => {
        async fn $name(
            State(ctx): State<Arc<ProxyContext>>,
            Extension(req): Extension<Arc<MgmtRequest>>,
            Path(id): Path<String>,
            body: Bytes,
        ) -> Response {
            run(ctx, req, $route, Some(id), body).await
        }
    };
}
id_handler!(fingerprints, MgmtRoute::Fingerprints);
id_handler!(disable, MgmtRoute::Disable);
id_handler!(enable, MgmtRoute::Enable);
id_handler!(retire, MgmtRoute::Retire);

#[derive(Deserialize)]
pub struct AuditQuery {
    cursor: Option<String>,
    limit: Option<u32>,
}

/// `GET /v1/proxy-management-audit` under the read bearer. The cursor is the
/// `seq` of the first record of the page; `next_cursor` is null at the end.
async fn get_audit(State(ctx): State<Arc<ProxyContext>>, Query(q): Query<AuditQuery>) -> Response {
    let cursor = match q.cursor.as_deref() {
        None => 0,
        Some(c) => match c.parse::<u64>() {
            Ok(n) => n,
            Err(_) => return api_error(ErrorCode::InvalidCursor),
        },
    };
    let limit = q.limit.unwrap_or(100).clamp(1, 1000) as usize;
    let r = tokio::task::spawn_blocking(move || audit_of(&ctx).read(cursor, limit)).await;
    match r {
        Ok(Ok((records, next))) => Json(serde_json::json!({
            "records": records,
            "next_cursor": next.map(|n| n.to_string()),
        }))
        .into_response(),
        _ => internal(),
    }
}

/// Management routes plus the audit read route. Mounted only when the
/// verifier file is configured. The guard is a separate layer
/// ([`mgmt_guard`]) installed on the merged router.
pub fn router(ctx: Arc<ProxyContext>, read_token: ReadToken) -> Router {
    let mgmt = Router::new()
        .route(REGISTER_PATH, post(register))
        .route("/v1/proxies/:proxy_id/fingerprints", post(fingerprints))
        .route("/v1/proxies/:proxy_id/disable", post(disable))
        .route("/v1/proxies/:proxy_id/enable", post(enable))
        .route("/v1/proxies/:proxy_id/retire", post(retire))
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .with_state(ctx.clone());
    let config = Router::new()
        .route(
            "/v1/proxies/:proxy_id/config",
            put(super::config_api::put_config_handler),
        )
        .layer(DefaultBodyLimit::max(super::config_api::MAX_PUT_BODY))
        .with_state(ctx.clone());
    let audit = Router::new()
        .route(
            AUDIT_PATH,
            get(get_audit).route_layer(from_fn_with_state(read_token, require_bearer)),
        )
        .with_state(ctx);
    mgmt.merge(config).merge(audit)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_table() {
        assert_eq!(route_of("/v1/proxies"), Some((MgmtRoute::Register, None)));
        assert_eq!(
            route_of("/v1/proxies/px-1/disable"),
            Some((MgmtRoute::Disable, Some("px-1")))
        );
        assert_eq!(
            route_of("/v1/proxies/px/config"),
            Some((MgmtRoute::ConfigPut, Some("px")))
        );
        assert_eq!(route_of("/v1/proxies/px/disable/x"), None);
        assert_eq!(route_of("/v1/proxies/"), None);
        assert_eq!(route_of("/v1/proxy-config"), None);
        assert_eq!(MgmtRoute::Disable.required_scope(), Scope::Config);
        assert_eq!(MgmtRoute::ConfigPut.required_scope(), Scope::Config);
        assert_eq!(MgmtRoute::ConfigPut.action(), "proxy.config_put");
        for r in [
            MgmtRoute::Register,
            MgmtRoute::Fingerprints,
            MgmtRoute::Enable,
            MgmtRoute::Retire,
        ] {
            assert_eq!(r.required_scope(), Scope::Identity);
        }
    }

    #[test]
    fn requested_by_is_sanitised() {
        let mut h = HeaderMap::new();
        h.insert(
            REQUESTED_BY_HEADER,
            "  alice\u{7} "
                .parse()
                .unwrap_or_else(|_| "alice".parse().unwrap()),
        );
        assert_eq!(requested_by(&h).as_deref(), Some("alice"));
        h.insert(REQUESTED_BY_HEADER, "x".repeat(500).parse().unwrap());
        assert_eq!(requested_by(&h).unwrap().len(), MAX_REQUESTED_BY);
        h.insert(REQUESTED_BY_HEADER, "   ".parse().unwrap());
        assert_eq!(requested_by(&h), None);
    }
}
