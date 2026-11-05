//! The `/api/v1` handlers, by area, and the Go request and response forms they share.

pub mod auth;
pub mod fleet;
pub mod ratelimit;
pub mod triage;

use std::pin::Pin;
use std::time::Duration;

use axum::body::HttpBody;
use axum::extract::Request;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::value::RawValue;

use crate::auth::Members;
use crate::config;
use crate::server::error_response;
use crate::triage::go_compact;

/// Go's `httputil.WriteJSON` with status 200, escaped as Go's encoder escapes. Go writes the status and `Content-Type` before it
/// encodes, so a body it cannot encode leaves an empty 200.
pub fn write_json<T: Serialize + ?Sized>(body: &T) -> Response {
    let body = serde_json::to_string(body)
        .map(|s| go_compact(&s) + "\n")
        .unwrap_or_default();
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        body,
    )
        .into_response()
}

/// A query string as Go's `url.ParseQuery` reads it: pairs split at `&`, a pair holding `;` or
/// a bad escape dropped, `+` read as a space.
pub struct Query(Vec<(String, String)>);

impl Query {
    pub fn parse(raw: Option<&str>) -> Self {
        let unescape = |s: &str| {
            config::unescape(&s.replace('+', " ")).map(|b| String::from_utf8_lossy(&b).into_owned())
        };
        let pairs = raw
            .unwrap_or_default()
            .split('&')
            .filter(|kv| !kv.is_empty() && !kv.contains(';'))
            .filter_map(|kv| {
                let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
                Some((unescape(k)?, unescape(v)?))
            })
            .collect();
        Self(pairs)
    }

    pub fn all<'a>(&'a self, key: &'a str) -> impl Iterator<Item = &'a str> {
        self.0
            .iter()
            .filter(move |(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    /// The first value, or `""`.
    pub fn get(&self, key: &str) -> &str {
        self.0
            .iter()
            .find(|(k, _)| k == key)
            .map_or("", |(_, v)| v.as_str())
    }

    /// Go's `strconv.Atoi`; 0 when unset.
    pub fn limit(&self) -> Result<i64, &'static str> {
        match self.get("limit") {
            "" => Ok(0),
            v => v.parse().map_err(|_| "limit must be an integer"),
        }
    }
}

/// Go's `maxNestingDepth`: a body may nest arrays and objects 10000 deep, and no deeper.
const MAX_DEPTH: usize = 10_000;

/// A login body: a username and a password.
pub const LOGIN_BODY_LIMIT: usize = 64 << 10;
/// A triage body: an event's evidence snapshot or a note. `lodeline-server` takes at most 2 MiB a
/// request, so any event it holds fits.
pub const TRIAGE_BODY_LIMIT: usize = 4 << 20;
const BODY_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Why a body was not read.
#[derive(Debug, PartialEq, Eq)]
pub enum BodyError {
    NotJson,
    TooLarge,
    TimedOut,
}

impl IntoResponse for BodyError {
    fn into_response(self) -> Response {
        match self {
            Self::NotJson => error_response(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "unsupported_media_type",
                "Content-Type must be application/json",
            ),
            Self::TooLarge => error_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                "body_too_large",
                "request body is too large",
            ),
            Self::TimedOut => error_response(
                StatusCode::REQUEST_TIMEOUT,
                "request_timeout",
                "request body took too long",
            ),
        }
    }
}

/// The body a frame at a time up to the end of its first JSON value, as Go's decoder reads it.
/// `Ok(None)` when a read fails before the value ends or the value nests deeper than Go allows.
/// An error before any of it is read when `Content-Type` is not `application/json` (any case,
/// parameters ignored), once the value runs past `limit` bytes, which are all that is held, or
/// when the body has not arrived within 30 s.
pub async fn read_body(req: Request, limit: usize) -> Result<Option<Vec<u8>>, BodyError> {
    let json = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .is_some_and(|t| t.trim().eq_ignore_ascii_case("application/json"));
    if !json {
        return Err(BodyError::NotJson);
    }
    let read = async {
        let mut body = req.into_body();
        let (mut buf, mut scan, mut over) = (Vec::new(), Scan::default(), false);
        loop {
            match scan.feed(&buf) {
                None => return Ok(None),
                Some(true) => break,
                Some(false) if over => return Err(BodyError::TooLarge),
                Some(false) => {}
            }
            let frame = std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)).await;
            let Some(frame) = frame else { break };
            let Ok(frame) = frame else { return Ok(None) };
            if let Ok(data) = frame.into_data() {
                let room = limit - buf.len();
                over = data.len() > room;
                buf.extend_from_slice(&data[..data.len().min(room)]);
            }
        }
        Ok(Some(buf))
    };
    tokio::time::timeout(BODY_READ_TIMEOUT, read)
        .await
        .unwrap_or(Err(BodyError::TimedOut))
}

/// How much of a body's first JSON value has been read.
#[derive(Default)]
struct Scan {
    scanned: usize,
    first: Option<usize>,
    depth: usize,
    in_string: bool,
    escaped: bool,
}

impl Scan {
    /// Scans the bytes added since the last call: `true` once `buf` holds all that `go_object`
    /// reads, `None` once the value nests deeper than Go allows.
    fn feed(&mut self, buf: &[u8]) -> Option<bool> {
        for (i, &b) in buf.iter().enumerate().skip(self.scanned) {
            self.scanned = i + 1;
            if self.in_string {
                match (self.escaped, b) {
                    (true, _) => self.escaped = false,
                    (false, b'\\') => self.escaped = true,
                    (false, b'"') => self.in_string = false,
                    _ => {}
                }
                continue;
            }
            if self.first.is_none() && !json_space(b) {
                self.first = Some(i);
            }
            match (self.first, b) {
                // Not an object: four bytes tell `null` from a value Go rejects.
                (Some(f), _) if buf[f] != b'{' => return Some(buf.len() >= f + 4),
                (_, b'"') => self.in_string = true,
                (_, b'{' | b'[') => {
                    self.depth += 1;
                    if self.depth > MAX_DEPTH {
                        return None;
                    }
                }
                (_, b'}' | b']') => {
                    self.depth -= 1;
                    if self.depth == 0 {
                        return Some(true);
                    }
                }
                _ => {}
            }
        }
        Some(false)
    }
}

fn json_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\r')
}

pub fn field<T: DeserializeOwned>(value: &RawValue) -> Option<Option<T>> {
    serde_json::from_str(value.get()).ok()
}

/// Sets `slot` unless the value is `null`; `None` when the value has the wrong type.
pub fn set<T: DeserializeOwned>(slot: &mut T, value: &RawValue) -> Option<()> {
    if let Some(v) = field(value)? {
        *slot = v;
    }
    Some(())
}

/// The first JSON value of a body as Go's `json.Decoder` reads it into a struct: the members
/// of an object in order, repeats kept so the last one wins; no members for `null`; `None` for
/// any other value or a syntax error. Bytes after the first value are not read.
///
/// shortcut: invalid UTF-8 and lone surrogate escapes fail here; Go reads them as U+FFFD. Fix
/// when a client sends them.
pub fn go_object(raw: &[u8]) -> Option<Vec<(String, Box<RawValue>)>> {
    // Go's scanner ends a top-level literal at its last letter, whatever follows.
    let start = raw
        .iter()
        .position(|&b| !json_space(b))
        .unwrap_or(raw.len());
    if raw[start..].starts_with(b"null") {
        return Some(Vec::new());
    }
    let mut values =
        serde_json::Deserializer::from_slice(raw).into_iter::<Members<Box<RawValue>>>();
    values.next()?.ok().map(|m| m.0)
}
