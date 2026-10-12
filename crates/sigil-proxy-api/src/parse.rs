//! Byte-level entry points with errors that never echo input.
//!
//! `serde_json` error text names unknown fields, variants and offending values.
//! Anything read from the network must therefore be parsed with these functions;
//! the returned [`ParseError`] carries a fixed category and, for batches, the
//! array index of the first bad element, and nothing else.
//!
//! Every entry point also rejects duplicate JSON object keys (category
//! [`ErrorCategory::Schema`]); plain `serde_json` silently keeps the last one.
//!
//! Bodies the proxy reads from the server ([`parse_api_error`],
//! [`parse_ingest_response`], [`parse_status_response`],
//! [`parse_upload_response`]) ignore unknown fields; request bodies are closed.

use std::fmt;

use serde::de::{DeserializeOwned, Error as _, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Number, Value};

use crate::config::{ProxyConfig, PutConfigRequest};
use crate::error::{ApiError, MARK_LIMIT, MARK_SEMANTIC};
use crate::event::{IngestRequest, IngestResponse, ProxyEvent};
use crate::registry::{RegistryEntry, UploadRequest, UploadResponse};
use crate::status::{GapReport, ProxyStatus, StatusResponse};

/// Largest accepted event batch body (README: 1 MiB).
pub const MAX_EVENT_BATCH_BYTES: usize = 1024 * 1024;

const MARK_DUPLICATE: &str = "\u{1}D";

/// Fixed failure category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorCategory {
    /// Not well-formed JSON (or trailing data, or nesting too deep).
    Syntax,
    /// Well-formed JSON that does not match the schema: unknown field or
    /// variant, wrong type, bad format, duplicate key.
    Schema,
    /// Schema-valid parts that violate a cross-field or uniqueness rule.
    Semantic,
    /// A size or count bound was exceeded.
    Limit,
}

/// Parse failure. Carries no input text, no key names and no serde message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseError {
    category: ErrorCategory,
    index: Option<usize>,
}

impl ParseError {
    fn new(category: ErrorCategory) -> Self {
        Self {
            category,
            index: None,
        }
    }

    pub fn category(&self) -> ErrorCategory {
        self.category
    }

    /// Array index of the first failing element of a batch, when known.
    pub fn index(&self) -> Option<usize> {
        self.index
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let what = match self.category {
            ErrorCategory::Syntax => "malformed JSON",
            ErrorCategory::Schema => "schema violation",
            ErrorCategory::Semantic => "semantic violation",
            ErrorCategory::Limit => "limit exceeded",
        };
        match self.index {
            Some(i) => write!(f, "{what} at item {i}"),
            None => f.write_str(what),
        }
    }
}

impl std::error::Error for ParseError {}

fn classify(e: &serde_json::Error) -> ErrorCategory {
    use serde_json::error::Category;
    match e.classify() {
        Category::Io | Category::Syntax | Category::Eof => ErrorCategory::Syntax,
        Category::Data => {
            // Only the fixed markers are inspected; the message text is dropped.
            let text = e.to_string();
            if text.contains(MARK_LIMIT) {
                ErrorCategory::Limit
            } else if text.contains(MARK_SEMANTIC) {
                ErrorCategory::Semantic
            } else {
                ErrorCategory::Schema
            }
        }
    }
}

/// A JSON value that refuses duplicate object keys.
struct Strict(Value);

impl<'de> Deserialize<'de> for Strict {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(StrictVisitor)
    }
}

struct StrictVisitor;

impl<'de> Visitor<'de> for StrictVisitor {
    type Value = Strict;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON value")
    }

    fn visit_bool<E>(self, v: bool) -> Result<Strict, E> {
        Ok(Strict(Value::Bool(v)))
    }
    fn visit_i64<E>(self, v: i64) -> Result<Strict, E> {
        Ok(Strict(Value::Number(v.into())))
    }
    fn visit_u64<E>(self, v: u64) -> Result<Strict, E> {
        Ok(Strict(Value::Number(v.into())))
    }
    fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<Strict, E> {
        Number::from_f64(v)
            .map(|n| Strict(Value::Number(n)))
            .ok_or_else(|| E::custom("non-finite number"))
    }
    fn visit_str<E>(self, v: &str) -> Result<Strict, E> {
        Ok(Strict(Value::String(v.to_owned())))
    }
    fn visit_string<E>(self, v: String) -> Result<Strict, E> {
        Ok(Strict(Value::String(v)))
    }
    fn visit_unit<E>(self) -> Result<Strict, E> {
        Ok(Strict(Value::Null))
    }
    fn visit_none<E>(self) -> Result<Strict, E> {
        Ok(Strict(Value::Null))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Strict, A::Error> {
        let mut items = Vec::new();
        while let Some(Strict(v)) = seq.next_element()? {
            items.push(v);
        }
        Ok(Strict(Value::Array(items)))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Strict, A::Error> {
        let mut out = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if out.contains_key(&key) {
                return Err(A::Error::custom(MARK_DUPLICATE));
            }
            let Strict(v) = map.next_value()?;
            out.insert(key, v);
        }
        Ok(Strict(Value::Object(out)))
    }
}

fn parse_value(bytes: &[u8]) -> Result<Value, ParseError> {
    let mut de = serde_json::Deserializer::from_slice(bytes);
    let Strict(value) = Strict::deserialize(&mut de).map_err(|e| ParseError::new(classify(&e)))?;
    de.end().map_err(|e| ParseError::new(classify(&e)))?;
    Ok(value)
}

/// First element of `value[field]` that does not parse as `E`.
fn first_bad<E: DeserializeOwned>(value: &Value, field: &str) -> Option<usize> {
    value
        .get(field)?
        .as_array()?
        .iter()
        .position(|el| E::deserialize(el).is_err())
}

fn parse_doc<T: DeserializeOwned>(
    bytes: &[u8],
    bad_element: Option<fn(&Value) -> Option<usize>>,
) -> Result<T, ParseError> {
    let value = parse_value(bytes)?;
    T::deserialize(&value).map_err(|e| ParseError {
        category: classify(&e),
        index: bad_element.and_then(|f| f(&value)),
    })
}

/// Parses one event envelope.
pub fn parse_event(bytes: &[u8]) -> Result<ProxyEvent, ParseError> {
    parse_doc(bytes, None)
}

/// Parses a `POST /v1/proxy-events` body: `{events:[...]}`, 1..=100 events, at
/// most [`MAX_EVENT_BATCH_BYTES`]. `index` names the first bad event.
pub fn parse_event_batch(bytes: &[u8]) -> Result<IngestRequest, ParseError> {
    if bytes.len() > MAX_EVENT_BATCH_BYTES {
        return Err(ParseError::new(ErrorCategory::Limit));
    }
    parse_doc(bytes, Some(|v| first_bad::<ProxyEvent>(v, "events")))
}

/// Parses a `POST /v1/proxy-status` body. `index` names the first gap that does
/// not parse on its own; it is `None` when the failure is not inside `gaps`.
pub fn parse_status(bytes: &[u8]) -> Result<ProxyStatus, ParseError> {
    parse_doc(bytes, Some(|v| first_bad::<GapReport>(v, "gaps")))
}

/// Parses a `GET /v1/proxies/{id}/config` body (closed: see [`crate::config`]).
pub fn parse_config(bytes: &[u8]) -> Result<ProxyConfig, ParseError> {
    parse_doc(bytes, None)
}

/// Parses a `PUT /v1/proxies/{id}/config` body.
pub fn parse_config_put(bytes: &[u8]) -> Result<PutConfigRequest, ParseError> {
    parse_doc(bytes, None)
}

/// Parses a `POST /v1/proxy-metadata` body. `index` names the first bad entry.
pub fn parse_upload(bytes: &[u8]) -> Result<UploadRequest, ParseError> {
    parse_doc(bytes, Some(|v| first_bad::<RegistryEntry>(v, "entries")))
}

/// Parses an error body read from the server (unknown fields ignored).
pub fn parse_api_error(bytes: &[u8]) -> Result<ApiError, ParseError> {
    parse_doc(bytes, None)
}

/// Parses a 200 body of `POST /v1/proxy-events` (unknown fields ignored).
pub fn parse_ingest_response(bytes: &[u8]) -> Result<IngestResponse, ParseError> {
    parse_doc(bytes, None)
}

/// Parses a 200 body of `POST /v1/proxy-status` (unknown fields ignored).
pub fn parse_status_response(bytes: &[u8]) -> Result<StatusResponse, ParseError> {
    parse_doc(bytes, None)
}

/// Parses a 200 body of `POST /v1/proxy-metadata` (unknown fields ignored).
pub fn parse_upload_response(bytes: &[u8]) -> Result<UploadResponse, ParseError> {
    parse_doc(bytes, None)
}
