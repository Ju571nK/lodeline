//! Session verification, matching Go's `auth.Signer.Verify` (golang-jwt v5) and the
//! `RequireAuth` middleware. Login, logout and signing come later with the rest of auth.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::de::{Deserialize, Deserializer, MapAccess, Visitor};
use serde_json::{Map, Value};

use crate::server::error_response;

pub const COOKIE_NAME: &str = "lodeline_session";
const ISSUER: &str = "lodeline-manager";
/// The claims golang-jwt's RegisteredClaims decodes.
const REGISTERED: [&str; 7] = ["iss", "sub", "aud", "exp", "nbf", "iat", "jti"];
/// Seconds from year 1 to 1970: Go's `time.Unix` adds them and wraps past `i64::MAX`.
const UNIX_TO_INTERNAL: i64 = 62_135_596_800;

#[derive(Debug, PartialEq, Eq)]
pub enum VerifyError {
    /// Malformed, wrong algorithm, bad signature or bad claims. Callers do not say which.
    Invalid,
    /// The signature is valid and `exp` has passed, whatever else is wrong with the claims.
    Expired,
}

pub struct Signer {
    key: DecodingKey,
}

/// The subject `require_auth` established, for the handlers behind it.
#[derive(Clone, Debug)]
pub struct Subject(pub String);

impl Signer {
    pub fn new(secret: &[u8]) -> Self {
        Self {
            key: DecodingKey::from_secret(secret),
        }
    }

    /// Returns the session subject.
    pub fn verify(&self, token: &str) -> Result<String, VerifyError> {
        self.verify_at(token, SystemTime::now())
    }

    fn verify_at(&self, token: &str, now: SystemTime) -> Result<String, VerifyError> {
        if token.is_empty() {
            return Err(VerifyError::Invalid);
        }
        // jsonwebtoken checks only the algorithm and the signature; the claim rules below are
        // golang-jwt's, which differ from jsonwebtoken's defaults (60 s leeway, `exp` required).
        let mut validation = Validation::new(Algorithm::HS256);
        validation.leeway = 0;
        validation.validate_exp = false;
        validation.validate_nbf = false;
        validation.validate_aud = false;
        validation.required_spec_claims.clear();
        let raw = jsonwebtoken::decode::<Members<Value>>(token, &self.key, &validation)
            .map_err(|_| VerifyError::Invalid)?
            .claims;
        // Go's encoding/json matches keys case-insensitively and the last one wins, so a key that
        // differs from a registered claim only by case, or a repeated one, is refused here.
        let mut claims = Map::new();
        for (key, value) in raw.0 {
            let folded = go_fold(&key);
            if let Some(name) = REGISTERED.iter().find(|name| **name == folded) {
                if key != *name || claims.insert(key, value).is_some() {
                    return Err(VerifyError::Invalid);
                }
            }
        }

        // Decoding into golang-jwt's RegisteredClaims fails on a mistyped claim.
        let exp = numeric_date(claims.get("exp"))?;
        let nbf = numeric_date(claims.get("nbf"))?;
        numeric_date(claims.get("iat"))?;
        let iss = string_claim(claims.get("iss"))?;
        let sub = string_claim(claims.get("sub"))?;
        string_claim(claims.get("jti"))?;
        audience(claims.get("aud"))?;

        // Claims are whole seconds, so comparing whole seconds of `now` is exact.
        let now = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as f64;
        // golang-jwt joins every claim error, and callers test for expiry first.
        // Past Go's time range the expiry wraps into the past: `as` saturates, the add overflows.
        let past_go_range = |exp: f64| (exp as i64).checked_add(UNIX_TO_INTERNAL).is_none();
        if exp.is_some_and(|exp| now >= exp || past_go_range(exp)) {
            return Err(VerifyError::Expired);
        }
        // iat is not checked: golang-jwt v5 skips it unless asked. A missing exp or nbf passes.
        if nbf.is_some_and(|nbf| now < nbf) || iss != ISSUER || sub.is_empty() {
            return Err(VerifyError::Invalid);
        }
        Ok(sub.to_owned())
    }
}

/// A JSON object with every key in order and repeats kept, for Go's rules on keys: a value for
/// any other JSON type fails to decode.
pub struct Members<V>(pub Vec<(String, V)>);

impl<'de, V: Deserialize<'de>> Deserialize<'de> for Members<V> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Entries<V>(std::marker::PhantomData<V>);
        impl<'de, V: Deserialize<'de>> Visitor<'de> for Entries<V> {
            type Value = Members<V>;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a JSON object")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Members<V>, A::Error> {
                let mut entries = Vec::new();
                while let Some(entry) = map.next_entry()? {
                    entries.push(entry);
                }
                Ok(Members(entries))
            }
        }
        d.deserialize_map(Entries(std::marker::PhantomData))
    }
}

/// Lowercases `key` the way Go's case-insensitive field match folds it onto ASCII: ASCII letters,
/// U+017F (long s) and U+212A (Kelvin sign) are the only runes that fold to ASCII.
pub fn go_fold(key: &str) -> String {
    key.chars()
        .map(|c| match c {
            '\u{17f}' => 's',
            '\u{212a}' => 'k',
            c => c.to_ascii_lowercase(),
        })
        .collect()
}

/// golang-jwt's NumericDate: a JSON number, or a string holding one, floored to the second.
fn numeric_date(v: Option<&Value>) -> Result<Option<f64>, VerifyError> {
    let n = match v {
        None | Some(Value::Null) => return Ok(None),
        Some(Value::Number(n)) => n.as_f64(),
        Some(Value::String(s)) => serde_json::from_str::<serde_json::Number>(s)
            .ok()
            .filter(|_| !s.starts_with(char::is_whitespace) && !s.ends_with(char::is_whitespace))
            .and_then(|n| n.as_f64()),
        Some(_) => None,
    };
    n.map(|n| Some(n.floor())).ok_or(VerifyError::Invalid)
}

fn string_claim(v: Option<&Value>) -> Result<&str, VerifyError> {
    match v {
        None | Some(Value::Null) => Ok(""),
        Some(Value::String(s)) => Ok(s),
        Some(_) => Err(VerifyError::Invalid),
    }
}

fn audience(v: Option<&Value>) -> Result<(), VerifyError> {
    match v {
        None | Some(Value::Null | Value::String(_)) => Ok(()),
        Some(Value::Array(items)) if items.iter().all(Value::is_string) => Ok(()),
        Some(_) => Err(VerifyError::Invalid),
    }
}

/// The first `lodeline_session` cookie across all `Cookie` lines, parsed as Go's
/// `Request.Cookie` does: pairs with invalid value bytes are skipped.
fn session_cookie(headers: &HeaderMap) -> Option<&str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .flat_map(|line| line.as_bytes().split(|&b| b == b';'))
        .filter_map(|part| {
            let part = part.trim_ascii();
            let (name, value) = match part.iter().position(|&b| b == b'=') {
                Some(i) => (&part[..i], &part[i + 1..]),
                None => (part, &b""[..]),
            };
            if name.trim_ascii() != COOKIE_NAME.as_bytes() {
                return None;
            }
            let value = match value {
                [b'"', inner @ .., b'"'] => inner,
                v => v,
            };
            let valid = |b: &u8| (0x20..0x7f).contains(b) && !b"\";\\".contains(b);
            value
                .iter()
                .all(valid)
                .then(|| std::str::from_utf8(value).ok())
                .flatten()
        })
        .next()
}

/// Go's `RequireAuth`: 401 `unauthorized` with no or an empty cookie, 401 `session_expired`
/// for an expired but otherwise valid token, 401 `unauthorized` for any other failure.
pub async fn require_auth(
    State(signer): State<Arc<Signer>>,
    mut req: Request,
    next: Next,
) -> Response {
    let unauthorized = |code, message| error_response(StatusCode::UNAUTHORIZED, code, message);
    let token = match session_cookie(req.headers()) {
        Some(token) if !token.is_empty() => token,
        _ => return unauthorized("unauthorized", "session cookie missing"),
    };
    match signer.verify(token) {
        Ok(subject) => {
            req.extensions_mut().insert(Subject(subject));
            next.run(req).await
        }
        Err(VerifyError::Expired) => {
            unauthorized("session_expired", "session expired, please log in again")
        }
        Err(VerifyError::Invalid) => unauthorized("unauthorized", "invalid session"),
    }
}

#[cfg(test)]
mod tests;
