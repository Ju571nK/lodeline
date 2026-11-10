//! #553: `POST /v1/renew`. A host presents its current client certificate on the
//! main listener and posts a CSR for a new key; the enrollment CA issues a new
//! certificate for the same host id, with a signed audit line.
//!
//! `renew_at` runs the rules in order, taking `now` as a parameter:
//!   1. enrollment on and the renewal state loaded, else 404
//!   2. a peer certificate whose CN is a canonical UUID (the host id), else 403
//!   3. the leaf verifies against the enrollment CA alone at `now`, else 403
//!   4. the host is on the allowlist, else 403
//!   5. `now` is past half of the certificate's validity, else 409 + Retry-After
//!      (2 to 5 are cheap and run before the mint lock)
//!   6. under the mint lock, the head rule, else 403
//!   7. the CSR names the host and carries a key the leaf does not, else 400
//!   8. sign, audit (fail closed), record the head, answer 200
//!
//! The route never writes the allowlist and never takes the token lock.

use crate::app::{AppState, SharedState};
use crate::enroll::audit;
use crate::enroll::renewal::norm_serial;
use crate::enroll::sign::{self, SignError};
use crate::routes::enroll::err;
use crate::tls_accept::{hex_lower, PeerIdentity};
use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use lodeline_fleet_api::renewal::{RenewRequest, RenewResponse};
use std::sync::Arc;
use time::OffsetDateTime;
use x509_parser::prelude::FromDer;

const ROUTE: &str = "renew";
/// Longest `Retry-After` the route sends, in seconds.
const MAX_RETRY_AFTER: i64 = 3600;

pub async fn post_renew(
    State(st): State<SharedState>,
    peer: Option<Extension<Arc<PeerIdentity>>>,
    Json(req): Json<RenewRequest>,
) -> Response {
    let peer = peer.map(|Extension(p)| p);
    let work = tokio::task::spawn_blocking(move || {
        renew_at(
            &st,
            peer.as_deref(),
            &req.csr_pem,
            OffsetDateTime::now_utc(),
        )
    });
    work.await.unwrap_or_else(|e| {
        tracing::error!(error = %e, "renew: task failed");
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "sign_failed",
            "renewal failed",
        )
    })
}

/// What the rules read from the presented certificate.
struct Leaf {
    not_before: i64,
    not_after: i64,
    serial: String,
    spki: Vec<u8>,
}

fn parse_leaf(der: &[u8]) -> Option<Leaf> {
    let (_, c) = x509_parser::parse_x509_certificate(der).ok()?;
    Some(Leaf {
        not_before: c.validity().not_before.timestamp(),
        not_after: c.validity().not_after.timestamp(),
        serial: norm_serial(&hex_lower(c.raw_serial())),
        spki: c.public_key().raw.to_vec(),
    })
}

fn csr_spki(csr_pem: &str) -> Option<Vec<u8>> {
    let (_, pem) = x509_parser::pem::parse_x509_pem(csr_pem.as_bytes()).ok()?;
    let (_, csr) =
        x509_parser::certification_request::X509CertificationRequest::from_der(&pem.contents)
            .ok()?;
    Some(csr.certification_request_info.subject_pki.raw.to_vec())
}

fn is_uuid(cn: &str) -> bool {
    cn.len() == 36 && uuid::Uuid::parse_str(cn).is_ok()
}

fn bad_request(msg: &str) -> Response {
    err(StatusCode::BAD_REQUEST, "bad_request", msg)
}

fn server_error(msg: &str) -> Response {
    err(StatusCode::INTERNAL_SERVER_ERROR, "sign_failed", msg)
}

pub fn renew_at(
    st: &AppState,
    peer: Option<&PeerIdentity>,
    csr_pem: &str,
    now: OffsetDateTime,
) -> Response {
    let Some(en) = st.enroll.as_ref() else {
        return off();
    };
    let Some(rn) = en.renewal.as_ref() else {
        return off();
    };
    let deny = |reason: &'static str| {
        en.deny_log.note(ROUTE, reason);
        err(StatusCode::FORBIDDEN, "renewal_denied", "renewal denied")
    };
    let now_unix = now.unix_timestamp();

    let Some(peer) = peer else {
        return deny("no_peer");
    };
    let Some(host) = peer.cn.as_deref().filter(|cn| is_uuid(cn)) else {
        return deny("bad_identity");
    };
    if !rn.verify(&peer.der, now_unix) {
        return deny("not_issued_by_enrollment_ca");
    }
    if !crate::allowlist::permits(&st.allowlist.read(), host) {
        return deny("not_allowlisted");
    }
    let Some(leaf) = parse_leaf(&peer.der) else {
        return deny("unreadable_certificate");
    };
    let half = leaf.not_before + (leaf.not_after - leaf.not_before) / 2;
    if now_unix < half {
        let wait = (half - now_unix).clamp(1, MAX_RETRY_AFTER);
        return (
            StatusCode::CONFLICT,
            [(header::RETRY_AFTER, wait.to_string())],
            Json(lodeline_fleet_api::ErrorBody::new(
                "too_early",
                "the certificate is not yet past half of its validity",
            )),
        )
            .into_response();
    }

    let _mint = en.mint.lock().unwrap_or_else(|p| p.into_inner());
    let csr_fp = audit::fingerprint(csr_pem.as_bytes());
    let ts = now
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default();
    if !rn.permits(host, &leaf.serial, &peer.fingerprint, &csr_fp) {
        let resp = deny("superseded");
        // Chained once per presented certificate, and remembered only once the line is
        // written. With no audit key or a failed append, every denial still reaches the
        // rate-limited log line above.
        let key = st
            .audit_key
            .as_ref()
            .filter(|_| !rn.denial_chained(&peer.fingerprint));
        if let Some(key) = key {
            let reason = crate::enroll::renewal::SUPERSEDED;
            match audit::append(
                &en.audit_path,
                key,
                host,
                "denied",
                reason,
                &csr_fp,
                "",
                "",
                "",
                &peer.fingerprint,
                &ts,
            ) {
                Ok(_) => rn.mark_denial_chained(&peer.fingerprint),
                Err(e) => {
                    tracing::error!(error = %e, host_id = host, "renew: failed to audit denial");
                }
            }
        }
        return resp;
    }

    let cn = match sign::csr_cn(&en.openssl_path, csr_pem) {
        Ok(cn) => cn,
        Err(SignError::BadCsr(_)) => return bad_request("invalid csr"),
        Err(e) => {
            tracing::error!(error = %e, "renew: csr parse failed");
            return server_error("csr inspect failed");
        }
    };
    if cn != host {
        return bad_request("csr must name the host of the presented certificate");
    }
    match csr_spki(csr_pem) {
        None => return bad_request("invalid csr"),
        Some(k) if k == leaf.spki => return bad_request("csr must carry a new key"),
        Some(_) => {}
    }

    let Some(key) = st.audit_key.as_ref() else {
        tracing::error!("renew: no audit key; refusing to issue without an audit trail");
        return server_error("audit unavailable");
    };
    let cert = match sign::sign_csr(
        &en.openssl_path,
        &en.ca_cert_path,
        &en.ca_key_path,
        csr_pem,
        host,
        en.cert_days,
    ) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, host_id = host, "renew: signing failed");
            return server_error("signing failed");
        }
    };
    let (serial, not_after) = sign::issued_meta(&en.openssl_path, &cert);
    if let Err(e) = audit::append(
        &en.audit_path,
        key,
        host,
        "issued",
        "renewed",
        &csr_fp,
        &audit::fingerprint(cert.as_bytes()),
        &serial,
        &not_after,
        &peer.fingerprint,
        &ts,
    ) {
        tracing::error!(error = %e, "renew: audit append failed");
        return server_error("audit append failed");
    }
    rn.record_renewal(host, &serial, &csr_fp, &peer.fingerprint);

    tracing::info!(host_id = host, serial = %serial, "renew: issued client cert");
    let chain = std::fs::read_to_string(&en.ca_cert_path).unwrap_or_default();
    (
        StatusCode::OK,
        Json(RenewResponse {
            ca_chain_pem: chain,
            client_cert_pem: cert,
            host_id: host.to_string(),
            not_after,
            serial,
        }),
    )
        .into_response()
}

fn off() -> Response {
    err(
        StatusCode::NOT_FOUND,
        "enroll_not_configured",
        "enrollment is not enabled",
    )
}
