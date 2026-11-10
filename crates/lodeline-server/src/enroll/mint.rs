//! #553: `POST /v1/enroll-tokens`, the HTTP mint of enrollment tokens.
//!
//! The caller is the fleet console. It needs three things, checked in this order
//! by [`guard`], a layer of this route alone that runs before the body is read:
//! 1. a pinned client certificate (its fingerprint is listed in the mint's own
//!    verifier file) on a mutual TLS connection, else 404 with an empty body, the
//!    router's own answer for an unknown route, for every method;
//! 2. a bearer that matches an entry bound to that certificate and is not
//!    expired, else 401;
//! 3. scope `enroll`, else 403.
//!
//! Only then does the handler look at the method (405), the content type (415),
//! the size (413) and the body (422). Refusals are counted and logged through
//! the rate-limited [`DenyLog`](crate::proxy::ingest::DenyLog) and never reach the
//! signed chain, so a caller without both secrets cannot grow it.
//!
//! The mint itself holds `en.mint` and, inside it, the token flock:
//! `host_exists` (409) when the host is on the allowlist or has a certificate
//! head, then `TokenStore::issue_capped` (prune, `token_outstanding` 409,
//! `too_many_tokens` 429, write), then the signed `token_minted` line, then the
//! 201. Holding `en.mint` through the append keeps the chain single-writer. If the
//! line cannot be written the entry is removed again and the answer is 503, so no
//! plaintext leaves without both records.

use super::audit;
use super::tokens::{MintRefused, TokenStore};
use super::EnrollState;
use crate::app::SharedState;
use crate::config::EnrollMintConfig;
use crate::proxy::verifiers::{AuthOutcome, MgmtAuth, Principal, Scope};
use crate::routes::enroll::err;
use crate::tls_accept::PeerIdentity;
use anyhow::{bail, Context, Result};
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use lodeline_fleet_api::mint::{MintRequest, MintResponse};
use std::sync::Arc;
use time::OffsetDateTime;

/// Request body cap.
pub const MAX_BODY: usize = 1024;
/// Route name in the deny log.
const ROUTE: &str = "enroll-tokens";

/// The mint's settings and credential, set on `EnrollState` at boot.
pub struct MintApi {
    pub auth: MgmtAuth,
    pub ttl: time::Duration,
    pub max_tokens: usize,
}

/// What the guard verified about one request.
pub struct MintCall {
    pub principal: Principal,
    /// ASSERTED by the caller; recorded, never used to authorize.
    pub requested_by: Option<String>,
}

impl MintApi {
    /// Every refusal of the start rules that do not need the proxy context.
    pub fn boot(
        cfg: &EnrollMintConfig,
        enroll: Option<&EnrollState>,
        has_audit_key: bool,
    ) -> Result<MintApi> {
        let Some(en) = enroll else {
            bail!("enroll_mint is set but enrollment is off; see the enroll warning above");
        };
        if en.renewal.is_none() {
            bail!(
                "enroll_mint is set but the renewal record is not loaded (the enrollment CA is \
                 not usable as a trust anchor, or the enrollment audit file is unreadable); \
                 the mint needs it to refuse a host that already has a certificate"
            );
        }
        if !has_audit_key {
            bail!(
                "enroll_mint is set but the audit signing key is unavailable; \
                 a mint with no audit trail is refused"
            );
        }
        let auth = MgmtAuth::load(&cfg.verifiers).context("enroll_mint.verifiers")?;
        if !auth.only_scope(Scope::Enroll) {
            bail!(
                "enroll_mint.verifiers {} holds an entry whose scope is not enroll",
                cfg.verifiers.display()
            );
        }
        Ok(MintApi {
            auth,
            ttl: time::Duration::seconds(cfg.ttl_seconds() as i64),
            max_tokens: cfg.max_tokens() as usize,
        })
    }

    /// A mint caller must be neither a registered proxy nor a caller of the proxy
    /// management API: in proxy mode that certificate's class is not a host's, and
    /// the route would answer 404 to it.
    pub fn check_proxy_overlap(&self, ctx: &crate::proxy::ProxyContext) -> Result<()> {
        for fp in self.auth.caller_fingerprints() {
            if ctx.registry.holds_fingerprint(&fp) {
                bail!("enroll_mint caller fingerprint {fp} is also a registered proxy fingerprint");
            }
            if ctx.mgmt.as_ref().is_some_and(|m| m.is_caller(&fp)) {
                bail!(
                    "enroll_mint caller fingerprint {fp} is also a proxy management caller \
                     (proxy.management_verifiers)"
                );
            }
        }
        Ok(())
    }
}

fn mint_api(st: &SharedState) -> Option<&MintApi> {
    st.enroll.as_ref()?.mint_api.as_ref()
}

fn refuse(st: &SharedState, reason: &'static str, resp: Response) -> Response {
    if let Some(en) = st.enroll.as_ref() {
        en.deny_log.note(ROUTE, reason);
    }
    resp
}

/// Layer on the mint route only (a `MethodRouter::layer`, since `any` is the
/// method router's fallback and `route_layer` would not reach it); see the module
/// docs for the order.
pub async fn guard(State(st): State<SharedState>, mut req: Request, next: Next) -> Response {
    let Some(api) = mint_api(&st) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    api.auth.refresh_if_changed();
    let not_found = |reason| refuse(&st, reason, StatusCode::NOT_FOUND.into_response());
    let peer = req.extensions().get::<Arc<PeerIdentity>>().cloned();
    let Some(peer) = peer.filter(|p| api.auth.is_caller(&p.fingerprint)) else {
        return not_found("not_a_mint_caller_cert");
    };
    let token = crate::auth::extract_bearer(req.headers());
    match api
        .auth
        .authenticate(&peer.fingerprint, token, OffsetDateTime::now_utc())
    {
        AuthOutcome::Denied => not_found("verifier_file_unusable"),
        AuthOutcome::Unauthorized(reason, _) => {
            let code = err(StatusCode::UNAUTHORIZED, "unauthorized", "unauthorized");
            refuse(&st, reason.as_str(), code)
        }
        AuthOutcome::Ok(p) if p.scope != Scope::Enroll => {
            let code = err(StatusCode::FORBIDDEN, "forbidden", "forbidden");
            refuse(&st, "scope_insufficient", code)
        }
        AuthOutcome::Ok(principal) => {
            let requested_by = crate::proxy::mgmt::requested_by(req.headers());
            req.extensions_mut().insert(Arc::new(MintCall {
                principal,
                requested_by,
            }));
            next.run(req).await
        }
    }
}

fn json_content_type(h: &HeaderMap) -> bool {
    h.get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .is_some_and(|m| m.trim().eq_ignore_ascii_case("application/json"))
}

/// The route handler, behind [`guard`]. Mounted for every method so a wrong
/// method from an authenticated caller is a 405 and from anyone else a 404.
pub async fn post_mint(
    State(st): State<SharedState>,
    Extension(call): Extension<Arc<MintCall>>,
    req: Request<Body>,
) -> Response {
    if req.method() != Method::POST {
        return (
            StatusCode::METHOD_NOT_ALLOWED,
            [(header::ALLOW, "POST")],
            Json(
                serde_json::json!({"error": {"code": "method_not_allowed", "message": "use POST"}}),
            ),
        )
            .into_response();
    }
    if !json_content_type(req.headers()) {
        return err(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported_media_type",
            "content type must be application/json",
        );
    }
    let too_large = || {
        err(
            StatusCode::PAYLOAD_TOO_LARGE,
            "payload_too_large",
            "body too large",
        )
    };
    let declared = req
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok());
    if declared.is_some_and(|n| n > MAX_BODY) {
        return too_large();
    }
    let Ok(bytes) = axum::body::to_bytes(req.into_body(), MAX_BODY).await else {
        return too_large();
    };
    let Ok(body) = serde_json::from_slice::<MintRequest>(&bytes) else {
        return err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_request",
            "the body must be {\"host_id\": \"<uuid>\"} and nothing else",
        );
    };
    if !lodeline_core::host_meta::is_canonical_v4(&body.host_id) {
        return err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_host_id",
            "host_id must be a lowercase, hyphenated version 4 UUID",
        );
    }
    match tokio::task::spawn_blocking(move || mint(&st, &call, &body.host_id)).await {
        Ok(resp) => resp,
        Err(e) => {
            tracing::error!(error = %e, "enroll: mint task failed");
            err(StatusCode::INTERNAL_SERVER_ERROR, "internal", "mint failed")
        }
    }
}

fn rfc3339(t: OffsetDateTime) -> String {
    t.format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

fn mint(st: &SharedState, call: &MintCall, host_id: &str) -> Response {
    let (Some(en), Some(api)) = (st.enroll.as_ref(), mint_api(st)) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(key) = st.audit_key.as_ref() else {
        tracing::error!("enroll: no audit key; refusing to mint without an audit trail");
        return err(
            StatusCode::SERVICE_UNAVAILABLE,
            "audit_unavailable",
            "audit unavailable",
        );
    };
    // The same lock every other writer of the chain and the allowlist holds.
    let _mint = match en.mint.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    let now = OffsetDateTime::now_utc();
    let host_known = matches!(&*st.allowlist.read(), Some(set) if set.contains(host_id))
        || en
            .renewal
            .as_ref()
            .is_some_and(|r| r.head(host_id).is_some());
    if host_known {
        return err(
            StatusCode::CONFLICT,
            "host_exists",
            "this host id is already on the allowlist or has a certificate from this server; use lodeline-server enroll-token to re-enroll it",
        );
    }
    let expires_at = now + api.ttl;
    let token = match TokenStore::issue_capped(
        &en.tokens_path,
        host_id,
        expires_at,
        now,
        api.max_tokens,
    ) {
        Ok(t) => t,
        Err(MintRefused::Outstanding) => {
            return err(
                StatusCode::CONFLICT,
                "token_outstanding",
                "this host id already has an unspent token that has not expired",
            );
        }
        Err(MintRefused::Full) => {
            en.deny_log.note(ROUTE, "mint_cap");
            return err(
                    StatusCode::TOO_MANY_REQUESTS,
                    "too_many_tokens",
                    "too many tokens are unspent or were spent or expired in the last hour; try again later",
                );
        }
        Err(MintRefused::Io(e)) => {
            tracing::error!(error = %e, "enroll: mint token store failed");
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "token_store_error",
                "token store error",
            );
        }
    };
    let (expires, ts) = (rfc3339(expires_at), rfc3339(now));
    if let Err(e) = audit::append_mint(
        &en.audit_path,
        key,
        host_id,
        &expires,
        &call.principal.caller_fingerprint,
        &call.principal.key_id,
        call.requested_by.as_deref(),
        &ts,
    ) {
        tracing::error!(error = %e, host_id, "enroll: mint audit append failed; token withdrawn");
        if let Err(e) = TokenStore::discard(&en.tokens_path, &token) {
            tracing::error!(error = %e, host_id, "enroll: could not remove the entry of a withdrawn token; it expires unused");
        }
        return err(
            StatusCode::SERVICE_UNAVAILABLE,
            "audit_unavailable",
            "audit unavailable; no token was made",
        );
    }
    tracing::info!(
        host_id,
        key_id = %call.principal.key_id,
        caller_fingerprint = %call.principal.caller_fingerprint,
        requested_by_asserted = call.requested_by.as_deref(),
        expires_at = %expires,
        "enroll: token minted"
    );
    (
        StatusCode::CREATED,
        [(header::CACHE_CONTROL, "no-store")],
        Json(MintResponse {
            expires_at: expires,
            host_id: host_id.to_string(),
            token,
        }),
    )
        .into_response()
}
