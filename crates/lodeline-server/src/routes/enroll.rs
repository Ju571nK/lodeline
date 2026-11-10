//! #184 — `POST /v1/enroll` (B-mint). Signs a host CSR into a per-host mTLS
//! CLIENT cert using the operator's intermediate CA, gated by a single-use,
//! TTL, per-host enrollment token.
//!
//! Auth: NO read-bearer layer — the enroll token in the body is the credential;
//! mTLS still gates at the TLS layer (PMS-mediated). Feature off ⇒ 404.
//!
//! #553: the enrollment listener (`enroll::listener`) serves this route with no
//! client certificate through `post_enroll_listener`. Both handlers share
//! `redeem`, and a `Caller` decides the issuer gate, the audit caller
//! fingerprint, and whether a denial before the reserve is chained (main
//! listener) or only counted and logged (enrollment listener).
//!
//! COMMIT ORDER (codex-hardened, prevents double-mint):
//!   lock mint Mutex
//!   → recompute now/ts (a token that expired while queued is rejected) (fix G)
//!   → issuer gate (#194.1): when `enroll_issuer_fingerprints` is configured,
//!     the TLS caller's cert fingerprint must be on the list — checked BEFORE
//!     any CSR parsing or token access
//!   → validate (UUID host_id, CSR size/PEM, CSR CN == host_id)
//!   → RESERVE the token (durably stamp used_at + write) BEFORE signing
//!   → sign (openssl, fixed profile, random serial, post-sign inspection)
//!   → audit append (signed, fsync, FAIL-CLOSED) (fix C: BEFORE the durable grant)
//!   → allowlist add (atomic file) + in-memory allowlist insert (fix F)
//!   → 200 with cert.
//! Any failure AFTER reserve ⇒ 500 and NO cert (token is spent; operator
//! re-issues). The token is never signed against twice. The signed audit append
//! happens BEFORE the durable allowlist grant so a failed audit can never leave
//! a host allowlisted without an issuance record (both still ⇒ 500 + no cert).
//!
//! External error generalization: every token failure (expired/used/mismatch/
//! not-found) AND every issuer-gate failure returns the single generic
//! `403 {"error":{"code":"enrollment_denied"}}`. The specific reason is logged
//! + audited internally. 404 (off) and 400 (malformed) stay distinct.

use crate::app::SharedState;
use crate::enroll::audit;
use crate::enroll::listener::{ConnLife, ROUTE};
use crate::enroll::sign::{self, SignError};
use crate::enroll::tokens::{RedeemErr, TokenStore};
use crate::enroll::EnrollState;
use crate::tls_accept::PeerIdentity;
use axum::extract::rejection::JsonRejection;
use axum::extract::{ConnectInfo, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use serde::Deserialize;
use serde_json::json;
use std::net::SocketAddr;
use std::sync::{Arc, TryLockError};

#[derive(Debug, Deserialize)]
pub struct EnrollReq {
    pub token: String,
    pub host_id: String,
    pub csr_pem: String,
}

/// Who sent an enroll request. It decides the issuer gate, the audit
/// `caller_fingerprint`, and where a denial before the reserve goes.
pub enum Caller {
    /// Main listener: the verified mTLS peer (None only in plain-HTTP dev mode).
    Fleet(Option<Arc<PeerIdentity>>),
    /// #553 enrollment listener: no client certificate, only the TCP peer.
    Anonymous(SocketAddr),
}

impl Caller {
    fn fingerprint(&self) -> String {
        match self {
            Caller::Fleet(Some(p)) => p.fingerprint.clone(),
            Caller::Fleet(None) | Caller::Anonymous(_) => String::new(),
        }
    }
}

pub async fn post_enroll(
    State(st): State<SharedState>,
    // #194 — injected per-connection by `tls_accept::PeerCertAcceptor`.
    // Absent over plain HTTP (dev mode) or if rustls reported no peer cert.
    peer: Option<Extension<Arc<PeerIdentity>>>,
    Json(req): Json<EnrollReq>,
) -> Response {
    // Feature off ⇒ 404 (indistinguishable from "route absent").
    let Some(en) = st.enroll.as_ref() else {
        return enroll_off();
    };
    if let Some(resp) = bad_fields(&req) {
        return resp;
    }
    // Serialize the entire mint critical section across requests.
    let _mint = match en.mint.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(), // poisoned: proceed (no shared mutable state held)
    };
    redeem(&st, en, &req, &Caller::Fleet(peer.map(|Extension(p)| p)))
}

/// #553: `POST /v1/enroll` on the enrollment listener. The token is checked
/// against the in-memory index before the mint lock and before any CSR parse.
/// The mint lock is only tried, so an anonymous caller never queues.
pub async fn post_enroll_listener(
    State(st): State<SharedState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(conn): Extension<Arc<ConnLife>>,
    body: Result<Json<EnrollReq>, JsonRejection>,
) -> Response {
    let Some(en) = st.enroll.as_ref() else {
        return enroll_off();
    };
    let req = match body {
        Ok(Json(req)) => req,
        Err(rejection) => {
            if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE {
                en.deny_log
                    .note_from(ROUTE, "payload_too_large", Some(addr.ip()));
            }
            return rejection.into_response();
        }
    };
    let _in_handler = conn.enter();
    if let Some(resp) = bad_fields(&req) {
        return resp;
    }
    let st2 = st.clone();
    let work = tokio::task::spawn_blocking(move || {
        let Some(en) = st2.enroll.as_ref() else {
            return enroll_off();
        };
        if let Err(e) = en
            .index
            .check(&req.token, &req.host_id, time::OffsetDateTime::now_utc())
        {
            let noted = en
                .deny_log
                .note_from(ROUTE, denial_reason(&e), Some(addr.ip()));
            if let RedeemErr::Io(msg) = &e {
                // Once per deny-log window, not once per request.
                if noted {
                    tracing::error!(error = %msg, "enroll: token index read failed");
                }
                return err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "sign_failed",
                    "token store error",
                );
            }
            return enrollment_denied();
        }
        let _mint = match en.mint.try_lock() {
            Ok(g) => g,
            Err(TryLockError::Poisoned(p)) => p.into_inner(),
            Err(TryLockError::WouldBlock) => {
                en.deny_log.note_from(ROUTE, "busy", Some(addr.ip()));
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    [(header::RETRY_AFTER, "1")],
                    Json(json!({"error": {"code": "busy", "message": "another enrollment is running; retry"}})),
                )
                    .into_response();
            }
        };
        redeem(&st2, en, &req, &Caller::Anonymous(addr))
    });
    match work.await {
        Ok(resp) => resp,
        Err(e) => {
            tracing::error!(error = %e, "enroll: mint task failed");
            err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "sign_failed",
                "enrollment failed",
            )
        }
    }
}

/// Input validation (distinct 400, before touching any token).
fn bad_fields(req: &EnrollReq) -> Option<Response> {
    if uuid::Uuid::parse_str(&req.host_id).is_err() {
        return Some(err(
            StatusCode::BAD_REQUEST,
            "bad_request",
            "host_id must be a UUID",
        ));
    }
    if req.token.is_empty() {
        return Some(err(StatusCode::BAD_REQUEST, "bad_request", "missing token"));
    }
    if req.csr_pem.len() > sign::MAX_CSR_BYTES {
        return Some(err(StatusCode::BAD_REQUEST, "bad_request", "csr too large"));
    }
    None
}

/// Everything after the mint lock, shared by both listeners. The caller holds
/// `en.mint`.
fn redeem(st: &SharedState, en: &EnrollState, req: &EnrollReq, caller: &Caller) -> Response {
    // Real caller fingerprint for ALL audit outcomes ("" when absent). #194
    let caller_fp = caller.fingerprint();
    let csr_fp = audit::fingerprint(req.csr_pem.as_bytes());

    // fix G: capture `now` AFTER acquiring the mint lock so a token that expired
    // while queued behind the lock is correctly rejected.
    let now = time::OffsetDateTime::now_utc();
    let ts = now
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default();

    // 0. #194.1 — issuer gate. When configured, the TLS caller must present a
    //    client cert whose fingerprint is on the operator's issuer list.
    //    Runs BEFORE any CSR parsing (openssl on attacker input) or token
    //    access; answered with the same generic 403 as token failures so an
    //    unauthorized caller learns nothing (no oracle).
    if let Some(allowed) = en.issuer_fingerprints.as_deref() {
        let permitted =
            matches!(caller, Caller::Fleet(Some(p)) if allowed.contains(&p.fingerprint));
        if !permitted {
            tracing::warn!(
                host_id = %req.host_id,
                caller_fingerprint = %caller_fp,
                "enroll: caller cert not in enroll_issuer_fingerprints"
            );
            deny(
                st,
                en,
                caller,
                &req.host_id,
                "issuer_not_allowed",
                &csr_fp,
                &ts,
            );
            return enrollment_denied();
        }
    }

    // 1. CSR sanity: parse + verify the CSR, extract CN, require CN == host_id.
    let cn = match sign::csr_cn(&en.openssl_path, &req.csr_pem) {
        Ok(c) => c,
        Err(SignError::BadCsr(_)) => {
            return err(StatusCode::BAD_REQUEST, "bad_request", "invalid csr");
        }
        Err(e) => {
            tracing::error!(error = %e, "enroll: csr parse failed");
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "sign_failed",
                "csr inspect failed",
            );
        }
    };
    if cn != req.host_id {
        // CN mismatch is a token-scope denial → generic enrollment_denied.
        deny(st, en, caller, &req.host_id, "cn_mismatch", &csr_fp, &ts);
        return enrollment_denied();
    }

    // 2. Pre-check the token (cheap, gives the specific internal reason).
    if let Err(e) = TokenStore::check(&en.tokens_path, &req.token, &req.host_id, now) {
        let reason = denial_reason(&e);
        deny(st, en, caller, &req.host_id, reason, &csr_fp, &ts);
        // I/O errors are a server fault (500); everything else is a denial.
        if let RedeemErr::Io(msg) = &e {
            tracing::error!(error = %msg, "enroll: token store read failed");
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "sign_failed",
                "token store error",
            );
        }
        return enrollment_denied();
    }

    // 3. RESERVE the token (durable used_at stamp) BEFORE signing. After this
    //    point the token is spent; any failure ⇒ 500 + no cert (safe re-issue).
    if let Err(e) = TokenStore::mark_used(&en.tokens_path, &req.token, &req.host_id, now) {
        let reason = denial_reason(&e);
        deny(st, en, caller, &req.host_id, reason, &csr_fp, &ts);
        if matches!(e, RedeemErr::Io(_)) {
            tracing::error!(error = %e, "enroll: token reserve write failed");
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "sign_failed",
                "token reserve failed",
            );
        }
        // Lost a race (used/expired since check): still a denial.
        return enrollment_denied();
    }

    // 4. Sign.
    let cert = match sign::sign_csr(
        &en.openssl_path,
        &en.ca_cert_path,
        &en.ca_key_path,
        &req.csr_pem,
        &req.host_id,
        en.cert_days,
    ) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, host_id = %req.host_id, "enroll: signing failed (token already spent)");
            record_denied(
                st,
                en,
                &req.host_id,
                "sign_failed",
                &csr_fp,
                &caller_fp,
                &ts,
            );
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "sign_failed",
                "signing failed",
            );
        }
    };
    let cert_fp = audit::fingerprint(cert.as_bytes());
    let (serial, not_after) = sign::issued_meta(&en.openssl_path, &cert);

    // 5. Audit append — FAIL-CLOSED, and BEFORE the durable allowlist grant
    //    (fix C). No key ⇒ cannot audit ⇒ 500, no cert. A failed audit must
    //    never leave a host durably allowlisted without an issuance record.
    let Some(key) = st.audit_key.as_ref() else {
        tracing::error!("enroll: no audit key; refusing to issue without an audit trail");
        return err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "sign_failed",
            "audit unavailable",
        );
    };
    if let Err(e) = audit::append(
        &en.audit_path,
        key,
        &req.host_id,
        "issued",
        "ok",
        &csr_fp,
        &cert_fp,
        &serial,
        &not_after,
        &caller_fp,
        &ts,
    ) {
        tracing::error!(error = %e, "enroll: audit append failed (token already spent)");
        return err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "sign_failed",
            "audit append failed",
        );
    }
    if let Some(rn) = en.renewal.as_ref() {
        rn.record_enrollment(&req.host_id, &serial, &csr_fp);
    }

    // 6. Allowlist add (atomic file). Required — failure ⇒ 500, no cert. Runs
    //    AFTER the audit append so the issuance is always recorded first.
    if let Some(p) = st.allowlist_path.as_ref() {
        if let Err(e) = crate::allowlist::add_host_atomic(p, &req.host_id) {
            tracing::error!(error = %e, "enroll: allowlist add failed (token already spent)");
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "sign_failed",
                "allowlist update failed",
            );
        }
        // fix F: reflect the file add in the in-memory allowlist so the newly
        // enrolled host is accepted on POST /v1/events without a restart. If the
        // in-memory set is permit-all (None) we leave it as-is (still permits).
        let mut guard = st.allowlist.write();
        if let Some(set) = guard.as_mut() {
            set.insert(req.host_id.clone());
        }
    }

    let chain = std::fs::read_to_string(&en.ca_cert_path).unwrap_or_default();
    let peer = match caller {
        Caller::Anonymous(addr) => Some(tracing::field::display(addr)),
        Caller::Fleet(_) => None,
    };
    tracing::info!(host_id = %req.host_id, serial = %serial, peer, "enroll: issued client cert");
    (
        StatusCode::OK,
        Json(json!({
            "client_cert_pem": cert,
            "ca_chain_pem": chain,
            "host_id": req.host_id,
            "not_after": not_after,
            "serial": serial,
        })),
    )
        .into_response()
}

fn denial_reason(e: &RedeemErr) -> &'static str {
    match e {
        RedeemErr::NotFound => "token_not_found",
        RedeemErr::Expired => "token_expired",
        RedeemErr::Used => "token_used",
        RedeemErr::HostMismatch => "host_mismatch",
        RedeemErr::Io(_) => "token_store_io",
    }
}

/// A denial before the token is reserved. A fleet caller's goes to the signed
/// chain, as before #553; an anonymous caller's is only counted and logged, so
/// the listener cannot grow the chain.
fn deny(
    st: &SharedState,
    en: &EnrollState,
    caller: &Caller,
    host_id: &str,
    reason: &'static str,
    csr_fp: &str,
    ts: &str,
) {
    match caller {
        Caller::Fleet(_) => {
            record_denied(st, en, host_id, reason, csr_fp, &caller.fingerprint(), ts)
        }
        Caller::Anonymous(addr) => {
            en.deny_log.note_from(ROUTE, reason, Some(addr.ip()));
        }
    }
}

/// Append a fail-closed-but-best-effort denial audit line. A denial that can't
/// be audited is logged (we still return the denial; we are not issuing a cert).
fn record_denied(
    st: &SharedState,
    en: &EnrollState,
    host_id: &str,
    reason: &str,
    csr_fp: &str,
    caller_fp: &str,
    ts: &str,
) {
    let Some(key) = st.audit_key.as_ref() else {
        tracing::warn!(host_id, reason, "enroll: denied (no audit key to record)");
        return;
    };
    if let Err(e) = audit::append(
        &en.audit_path,
        key,
        host_id,
        "denied",
        reason,
        csr_fp,
        "",
        "",
        "",
        caller_fp,
        ts,
    ) {
        tracing::error!(error = %e, host_id, reason, "enroll: failed to audit denial");
    }
}

fn enrollment_denied() -> Response {
    // Single generic response for ALL token failures (no state leak).
    err(
        StatusCode::FORBIDDEN,
        "enrollment_denied",
        "enrollment denied",
    )
}

fn enroll_off() -> Response {
    err(
        StatusCode::NOT_FOUND,
        "enroll_not_configured",
        "enrollment is not enabled",
    )
}

pub(crate) fn err(code: StatusCode, body_code: &str, message: &str) -> Response {
    (
        code,
        Json(json!({"error": {"code": body_code, "message": message}})),
    )
        .into_response()
}
