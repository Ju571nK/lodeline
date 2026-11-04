//! The read-only client for `lodeline-server`'s `/v1/*` API, Go's `internal/fleet`: the HTTP
//! client, the built-in mock fleet, the read cache in front of either, and bounded retry.

pub mod cache;
mod http;
mod mock;
pub mod wire;

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;

pub use http::HttpClient;
pub use mock::Mock;
pub use wire::*;

use crate::config::Config;

/// What the console asks the fleet for. One variant per endpoint the handlers use.
#[derive(Clone, Debug, PartialEq)]
pub enum Request {
    Healthz,
    Meta,
    Events(EventsParams),
    EventById(String),
    Hosts(HostsParams),
    HostById(String),
    Risk(RiskParams),
    Compliance(ComplianceParams),
}

/// `GET /v1/events` filters. Empty and zero values are left out of the upstream query.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct EventsParams {
    pub cursor: String,
    pub limit: i64,
    pub host_ids: Vec<String>,
    pub since: GoTime,
    pub until: GoTime,
    pub evidence_kinds: Vec<String>,
    pub severity: Vec<String>,
    pub source: Vec<String>,
    pub min_ai_guard_bucket: String,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct HostsParams {
    pub cursor: String,
    pub limit: i64,
    pub status: Vec<String>,
    pub bucket: Vec<String>,
    pub sort: String,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct RiskParams {
    pub cursor: String,
    pub limit: i64,
    pub tool: Vec<String>,
    pub min_bucket: String,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct ComplianceParams {
    pub cursor: String,
    pub limit: i64,
}

/// One fleet body, as the handlers relay it.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(untagged)]
#[allow(
    clippy::large_enum_variant,
    reason = "bodies are created once and shared in an Arc"
)]
pub enum Response {
    Healthz(Healthz),
    Meta(Meta),
    Events(EventsPage),
    Event(Event),
    Hosts(HostsPage),
    Host(HostDetail),
    Risk(RiskPage),
    Compliance(CompliancePage),
}

#[derive(Clone, Debug, PartialEq)]
pub enum FleetError {
    /// 404 from an ID lookup: no such event or host.
    NotFound,
    /// 404 from any other endpoint: the server runs without a read token.
    ReadApiDisabled,
    Unauthorized,
    /// 503 while the server rebuilds its index; `retry_after` from the header, 5 s by default.
    ServiceUnavailable {
        retry_after: Duration,
    },
    /// Any other status. `code` comes from the error body, or is `unknown`.
    Api {
        status: u16,
        code: String,
        message: String,
    },
    /// No usable answer: connection failure, timeout, or a body that does not decode.
    Transport(String),
}

impl FleetError {
    /// Only a 503 is retried. Go's retry also names network timeouts, but `net/http` reports a
    /// client timeout as `context.DeadlineExceeded`, which Go checks first, so Go never retries
    /// one, and a timed-out read is not served from stale cache either.
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::ServiceUnavailable { .. })
    }
}

impl fmt::Display for FleetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => f.write_str("fleet: not found"),
            Self::ReadApiDisabled => f.write_str("fleet: read API disabled on lodeline-server"),
            Self::Unauthorized => f.write_str("fleet: unauthorized"),
            Self::ServiceUnavailable { retry_after } => {
                write!(
                    f,
                    "fleet: service unavailable (retry after {retry_after:?})"
                )
            }
            Self::Api {
                status,
                code,
                message,
            } => write!(f, "fleet: {status} {code}: {message}"),
            Self::Transport(e) => write!(f, "fleet: {e}"),
        }
    }
}

pub type Reply = Result<Arc<Response>, FleetError>;
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A source of fleet bodies. Implementations must be safe to share between requests.
pub trait Client: Send + Sync {
    fn get(&self, req: Request) -> BoxFuture<'_, Reply>;
}

/// Bounded retry around idempotent fleet reads (Go's `RetryPolicy`).
#[derive(Clone, Copy, Debug)]
pub struct RetryPolicy {
    pub max_attempts: u32,
    pub max_delay: Duration,
}

pub const DEFAULT_RETRY: RetryPolicy = RetryPolicy {
    max_attempts: 3,
    max_delay: Duration::from_secs(5),
};

/// Runs `fetch` until it succeeds, fails with an error that is not retried, or uses up the
/// attempts. Between attempts it waits the upstream's `Retry-After`; zero or more than
/// `max_delay` waits `max_delay`, as in Go.
pub async fn retry<F, Fut>(policy: RetryPolicy, mut fetch: F) -> Reply
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Reply>,
{
    let mut attempt = 1;
    loop {
        let err = match fetch().await {
            Ok(v) => return Ok(v),
            Err(e) => e,
        };
        let FleetError::ServiceUnavailable { retry_after } = err else {
            return Err(err);
        };
        if attempt >= policy.max_attempts {
            return Err(err);
        }
        let wait = if retry_after.is_zero() || retry_after > policy.max_delay {
            policy.max_delay
        } else {
            retry_after
        };
        tokio::time::sleep(wait).await;
        attempt += 1;
    }
}

/// The client `cfg` selects: the mock fleet or the HTTP client, behind the read cache unless
/// `FLEET_CACHE_DISABLED=1`. The cache keeps data for the SPA's poll interval and serves it
/// stale for 12 times as long while it refreshes.
pub fn from_config(cfg: &Config) -> Result<Arc<dyn Client>, String> {
    let base: Arc<dyn Client> = if cfg.mock_fleet {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock after 1970");
        Arc::new(Mock::new(now.as_secs() as i64))
    } else {
        Arc::new(
            HttpClient::new(
                &cfg.server_base_url,
                &cfg.server_read_token,
                cfg.server_tls.as_ref(),
                http::TIMEOUT,
            )
            .map_err(|e| {
                format!(
                    "fleet client (LODELINE_SERVER_CA_PATH, LODELINE_SERVER_CLIENT_CERT_PATH): {}",
                    http::causes(&e)
                )
            })?,
        )
    };
    if cfg.fleet_cache_disabled {
        return Ok(base);
    }
    Ok(Arc::new(cache::CachingClient::new(
        base,
        cache::CacheConfig {
            ttl: cfg.fleet_poll_interval,
            max_stale: 12 * cfg.fleet_poll_interval,
            max_entries: usize::try_from(cfg.fleet_cache_max_entries).unwrap_or(0),
        },
    )))
}

impl Request {
    /// The endpoint's name in the cache, which also picks its freshness tier; `None` for
    /// healthz, which is never cached.
    fn endpoint(&self) -> Option<&'static str> {
        Some(match self {
            Self::Healthz => return None,
            Self::Meta => "meta",
            Self::Events(_) => "events",
            Self::EventById(_) => "event_by_id",
            Self::Hosts(_) => "hosts",
            Self::HostById(_) => "host_by_id",
            Self::Risk(_) => "risk",
            Self::Compliance(_) => "compliance",
        })
    }

    /// The upstream query as Go's `url.Values.Encode` writes it: keys sorted, values
    /// query-escaped, list filters comma-joined.
    pub fn query(&self) -> String {
        let mut q: Vec<(&str, String)> = Vec::new();
        let mut set = |k, v: String| {
            if !v.is_empty() {
                q.push((k, v));
            }
        };
        let limit = |n: i64| if n > 0 { n.to_string() } else { String::new() };
        let time = |t: &GoTime| {
            if t.is_zero() {
                String::new()
            } else {
                t.format_utc_seconds()
            }
        };
        match self {
            Self::Events(p) => {
                set("cursor", p.cursor.clone());
                set("limit", limit(p.limit));
                set("host_id", p.host_ids.join(","));
                set("since", time(&p.since));
                set("until", time(&p.until));
                set("evidence_kind", p.evidence_kinds.join(","));
                set("severity", p.severity.join(","));
                set("source", p.source.join(","));
                set("min_ai_guard_bucket", p.min_ai_guard_bucket.clone());
            }
            Self::Hosts(p) => {
                set("cursor", p.cursor.clone());
                set("limit", limit(p.limit));
                set("status", p.status.join(","));
                set("bucket", p.bucket.join(","));
                set("sort", p.sort.clone());
            }
            Self::Risk(p) => {
                set("cursor", p.cursor.clone());
                set("limit", limit(p.limit));
                set("tool", p.tool.join(","));
                set("min_bucket", p.min_bucket.clone());
            }
            Self::Compliance(p) => {
                set("cursor", p.cursor.clone());
                set("limit", limit(p.limit));
            }
            Self::Healthz | Self::Meta | Self::EventById(_) | Self::HostById(_) => {}
        }
        q.sort_by_key(|(k, _)| *k);
        q.iter()
            .map(|(k, v)| format!("{k}={}", query_escape(v)))
            .collect::<Vec<_>>()
            .join("&")
    }

    /// The cache key: endpoint plus its query, or plus the ID for a lookup.
    fn cache_key(&self) -> Option<String> {
        let suffix = match self {
            Self::EventById(id) | Self::HostById(id) => id.clone(),
            _ => self.query(),
        };
        Some(format!("{}|{suffix}", self.endpoint()?))
    }
}

/// Go's `url.QueryEscape`.
fn query_escape(s: &str) -> String {
    escape(
        s,
        |b| b.is_ascii_alphanumeric() || b"-._~".contains(&b),
        true,
    )
}

/// Go's `url.PathEscape`, for one path segment.
pub fn path_escape(s: &str) -> String {
    escape(
        s,
        |b| b.is_ascii_alphanumeric() || b"-._~$&+:=@".contains(&b),
        false,
    )
}

/// Go's own escaping of a whole URL path, which decides whether Go keeps the raw path.
pub fn escape_path(s: &str) -> String {
    escape(
        s,
        |b| b.is_ascii_alphanumeric() || b"$&*+,-./:;=@_~".contains(&b),
        false,
    )
}

fn escape(s: &str, keep: impl Fn(u8) -> bool, space_as_plus: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if keep(b) {
            out.push(b as char);
        } else if b == b' ' && space_as_plus {
            out.push('+');
        } else {
            out += &format!("%{b:02X}");
        }
    }
    out
}

#[cfg(test)]
mod tests;
