//! `GET /api/v1/enrollment` and `POST /api/v1/enrollment/files` (#553): a signed-in operator asks
//! for a host's enrollment file. The console asks the server to mint a token, builds the file
//! and answers with its bytes. It stores nothing, and the token is in no log and no error body.

use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Extension;
use lodeline_fleet_api::mint::MintResponse;
use serde::Deserialize;
use serde_json::json;

use crate::api::{read_body, write_json};
use crate::auth::Subject;
use crate::enroll::{
    is_canonical_v4, new_host_id, origin_of, Active, Enroll, MintError, TemplateError,
};
use crate::server::{error_response, AppState};

const BODY_LIMIT: usize = 1024;

pub async fn status(
    State(s): State<AppState>,
    Extension(Subject(who)): Extension<Subject>,
) -> Response {
    let mut res = match &*s.enroll {
        Enroll::Off(missing) => write_json(&json!({"enabled": false, "missing": missing})),
        Enroll::On(on) => match on.template.load() {
            Ok(l) => write_json(&json!({
                "enabled": true,
                "can_enroll": on.may_enroll(&who),
                "server_url": l.server_url,
                "enroll_url": l.enroll_url,
                "ca": &l.cas,
                "policy_keys": &l.keys,
            })),
            Err(e) => unusable(&e),
        },
    };
    res.headers_mut().insert(
        header::CACHE_CONTROL,
        "no-store".parse().expect("static value"),
    );
    res
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileRequest {
    host_id: Option<String>,
}

pub async fn make_file(
    State(s): State<AppState>,
    Extension(Subject(who)): Extension<Subject>,
    req: Request,
) -> Response {
    let Enroll::On(on) = &*s.enroll else {
        return error_response(
            StatusCode::NOT_FOUND,
            "enrollment_not_configured",
            "host enrollment is not configured on this console",
        );
    };
    if !request_is_ours(req.headers(), &on.public_origin) {
        return error_response(
            StatusCode::FORBIDDEN,
            "origin_not_allowed",
            "this request did not come from the console's own page",
        );
    }
    if !on.may_enroll(&who) {
        return error_response(
            StatusCode::FORBIDDEN,
            "not_an_enroller",
            "this account may not make enrollment files",
        );
    }
    let body = match read_body(req, BODY_LIMIT).await {
        Ok(body) => body.and_then(|b| serde_json::from_slice::<FileRequest>(&b).ok()),
        Err(e) => return e.into_response(),
    };
    let Some(body) = body else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "the body must be {} or {\"host_id\": \"<version 4 UUID>\"}",
        );
    };
    let host_id = match body.host_id {
        Some(h) if is_canonical_v4(&h) => h,
        Some(_) => {
            return error_response(
                StatusCode::UNPROCESSABLE_ENTITY,
                "invalid_host_id",
                "host_id must be a lowercase, hyphenated version 4 UUID",
            )
        }
        None => match new_host_id() {
            Ok(h) => h,
            Err(_) => {
                return error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal",
                    "could not make a host id",
                )
            }
        },
    };
    make(on, &who, &host_id).await
}

async fn make(on: &Active, who: &str, host_id: &str) -> Response {
    // Read and size-check the fixed parts first, so a bad setting costs no token.
    let loaded = match on.template.load().and_then(|l| {
        l.render(host_id, &"x".repeat(64), &"x".repeat(256))
            .map(|_| l)
    }) {
        Ok(l) => l,
        Err(e) => return unusable(&e),
    };
    let minted = match on.enroller.mint(host_id, who).await {
        Ok(m) if answer_is_sound(host_id, &m) => m,
        Ok(_) => return mint_failed(who, MintError::Failed),
        Err(e) => return mint_failed(who, e),
    };
    let file = match loaded.render(host_id, &minted.expires_at, &minted.token) {
        Ok(f) => f,
        Err(e) => return unusable(&e),
    };
    eprintln!(
        "enroll: file made subject={who:?} host_id={host_id} expires_at={}",
        minted.expires_at
    );
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE.as_str(), "application/json".to_owned()),
            (
                header::CONTENT_DISPOSITION.as_str(),
                format!("attachment; filename=\"lodeline-enroll-{host_id}.json\""),
            ),
            (header::CACHE_CONTROL.as_str(), "no-store".to_owned()),
            ("x-lodeline-enroll-host-id", host_id.to_owned()),
            ("x-lodeline-enroll-expires-at", minted.expires_at),
        ],
        file,
    )
        .into_response()
}

/// What the reader of the file would accept, so a bad answer is an error here and not a file
/// that fails on the host: the id asked for, a usable token, an RFC 3339 expiry.
fn answer_is_sound(host_id: &str, m: &MintResponse) -> bool {
    m.host_id == host_id
        && (1..=256).contains(&m.token.len())
        && !m.token.chars().any(char::is_whitespace)
        && chrono::DateTime::parse_from_rfc3339(&m.expires_at).is_ok()
}

/// The origin rule, run before anything else on this route: `Origin` is present, one value, and
/// is the configured origin; `Sec-Fetch-Site`, when sent, says `same-origin`; the body is JSON.
/// There is no `Referer` fallback.
fn request_is_ours(h: &HeaderMap, configured: &str) -> bool {
    let mut origins = h.get_all(header::ORIGIN).iter();
    let origin_ok = match (origins.next(), origins.next()) {
        (Some(v), None) => v
            .to_str()
            .ok()
            .and_then(origin_of)
            .is_some_and(|o| o == configured),
        _ => false,
    };
    let fetch_ok = h
        .get_all("sec-fetch-site")
        .iter()
        .all(|v| v.as_bytes() == b"same-origin");
    let json = h
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.as_bytes().split(|&b| b == b';').next())
        .is_some_and(|t| t.trim_ascii().eq_ignore_ascii_case(b"application/json"));
    origin_ok && fetch_ok && json
}

fn mint_failed(who: &str, e: MintError) -> Response {
    let (status, code, message) = match e {
        MintError::HostExists => (StatusCode::CONFLICT, "host_exists", "the server already knows this host id. Use a new host id, or make a token on the server with `lodeline-server enroll-token`."),
        MintError::TokenOutstanding => (StatusCode::CONFLICT, "token_outstanding", "a token for this host id is still valid. Use the file made for it, wait until it expires, or make a token on the server with `lodeline-server enroll-token`."),
        MintError::LimitReached => (StatusCode::TOO_MANY_REQUESTS, "enrollment_limit_reached", "the server holds the most tokens it allows. Try again later."),
        MintError::Unavailable => (StatusCode::BAD_GATEWAY, "enroll_unavailable", "the server has no token endpoint here, or it does not accept this console's mint certificate."),
        MintError::Refused => (StatusCode::BAD_GATEWAY, "enroll_refused", "the server refused this console's mint credential."),
        MintError::Failed => (StatusCode::BAD_GATEWAY, "enroll_failed", "the server did not make a token. No file was made."),
    };
    eprintln!("enroll: refused subject={who:?} code={code}");
    error_response(status, code, message)
}

fn unusable(e: &TemplateError) -> Response {
    error_response(StatusCode::BAD_GATEWAY, "enroll_failed", &e.to_string())
}

#[cfg(test)]
mod tests;
