//! The fleet client for a real `lodeline-server` (Go's `internal/fleet/http.go`).

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use reqwest::header::{ACCEPT, RETRY_AFTER};
use serde::Deserialize;
use serde_json::Value;

use super::{go_decode, path_escape, BoxFuture, Client, FleetError, Reply, Request, Response};
use crate::config::ServerTls;

/// The whole exchange, body included, as Go's `http.Client.Timeout`.
pub const TIMEOUT: Duration = Duration::from_secs(5);

/// The largest 200 body read. The console asks for at most 100 items a page, and
/// `lodeline-server` takes at most 2 MiB a request (axum's default body limit), so a stored event
/// is under 2 MiB and a page under 200 MiB, plus what re-encoding adds.
const BODY_LIMIT: usize = 256 << 20;
/// The largest error body read: the server's own are a short JSON object.
const ERROR_BODY_LIMIT: usize = 64 << 10;

/// The `Retry-After` wait when a 503 has none, or one that is not whole seconds.
const DEFAULT_RETRY_AFTER: Duration = Duration::from_secs(5);

pub struct HttpClient {
    base_url: String,
    token: String,
    http: reqwest::Client,
    body_limit: usize,
}

impl HttpClient {
    /// The client trusts the OS store, as Go does. `tls` adds the mTLS client certificate, and a
    /// CA that replaces the OS store.
    pub fn new(
        base_url: &str,
        token: &str,
        tls: Option<&ServerTls>,
        timeout: Duration,
    ) -> reqwest::Result<Self> {
        let mut builder = reqwest::Client::builder()
            .timeout(timeout)
            .tls_built_in_webpki_certs(false)
            .proxy(env_proxy(|k| std::env::var(k).ok()));
        if let Some(tls) = tls {
            if !tls.roots.is_empty() {
                builder = builder.tls_built_in_root_certs(false);
            }
            for root in &tls.roots {
                builder = builder.add_root_certificate(root.clone());
            }
            if let Some(identity) = &tls.identity {
                builder = builder.identity(identity.clone());
            }
        }
        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_owned(),
            token: token.to_owned(),
            http: builder.build()?,
            body_limit: BODY_LIMIT,
        })
    }

    async fn fetch(&self, req: Request) -> Reply {
        let (path, by_id) = match &req {
            Request::Healthz => ("/v1/healthz".to_owned(), false),
            Request::Meta => ("/v1/meta".to_owned(), false),
            Request::Events(_) => ("/v1/events".to_owned(), false),
            Request::EventById(id) => (format!("/v1/events/{}", path_escape(id)), true),
            Request::Hosts(_) => ("/v1/fleet/hosts".to_owned(), false),
            Request::HostById(id) => (format!("/v1/fleet/hosts/{}", path_escape(id)), true),
            Request::Risk(_) => ("/v1/fleet/risk".to_owned(), false),
            Request::Compliance(_) => ("/v1/fleet/compliance".to_owned(), false),
        };
        let mut url = format!("{}{path}", self.base_url);
        let query = req.query();
        if !query.is_empty() {
            url = format!("{url}?{query}");
        }
        let transport =
            |e: reqwest::Error| FleetError::Transport(format!("GET {path}: {}", causes(&e)));

        let mut builder = self.http.get(&url).header(ACCEPT, "application/json");
        // Healthz is the one endpoint the server serves without the read token.
        if req != Request::Healthz {
            builder = builder.bearer_auth(&self.token);
        }
        let resp = builder.send().await.map_err(transport)?;
        let status = resp.status().as_u16();
        match status {
            200 => {
                let limit = self.body_limit;
                let body = read_capped(resp, limit)
                    .await
                    .map_err(transport)?
                    .ok_or_else(|| {
                        FleetError::Transport(format!("GET {path}: body over {limit} bytes"))
                    })?;
                decode(&req, &body)
                    .map(Arc::new)
                    .map_err(|e| FleetError::Transport(format!("decode {path}: {e}")))
            }
            401 => Err(FleetError::Unauthorized),
            // A lookup reaches its 404 only through an enabled read API.
            404 if by_id => Err(FleetError::NotFound),
            404 => Err(FleetError::ReadApiDisabled),
            503 => Err(FleetError::ServiceUnavailable {
                retry_after: parse_retry_after(resp.headers().get(RETRY_AFTER)),
            }),
            _ => {
                let body = read_capped(resp, ERROR_BODY_LIMIT)
                    .await
                    .ok()
                    .flatten()
                    .unwrap_or_default();
                Err(api_error(status, &body))
            }
        }
    }
}

impl Client for HttpClient {
    fn get(&self, req: Request) -> BoxFuture<'_, Reply> {
        Box::pin(self.fetch(req))
    }
}

/// Go's `http.ProxyFromEnvironment`: `HTTPS_PROXY` for https and `HTTP_PROXY` for http, each
/// name read upper case first, hosts in `NO_PROXY` exempt, and never a proxy for `localhost` or a
/// loopback address.
pub fn env_proxy(get: impl Fn(&str) -> Option<String>) -> reqwest::Proxy {
    let var = |name: &str| {
        [name.to_owned(), name.to_lowercase()]
            .into_iter()
            .find_map(|n| get(&n).filter(|v| !v.is_empty()))
            .unwrap_or_default()
    };
    let (http, https, no) = (var("HTTP_PROXY"), var("HTTPS_PROXY"), var("NO_PROXY"));
    // Go's `*` entry covers IP literals too; hyper-util's applies to domain names only.
    let all = no.split(',').any(|p| p.trim() == "*");
    let matcher = hyper_util::client::proxy::matcher::Matcher::builder()
        .http(http.clone())
        .https(https.clone())
        .no(no)
        .build();
    reqwest::Proxy::custom(move |url| {
        let host = url.host_str()?;
        let ip = host.trim_start_matches('[').trim_end_matches(']');
        let loopback = ip
            .parse::<IpAddr>()
            .is_ok_and(|ip| ip.to_canonical().is_loopback());
        if all || host == "localhost" || loopback {
            return None;
        }
        matcher.intercept(&url.as_str().parse::<hyper::Uri>().ok()?)?;
        Some(if url.scheme() == "https" {
            https.clone()
        } else {
            http.clone()
        })
    })
}

/// The whole body, or `None` past `limit` bytes without reading the rest.
pub async fn read_capped(
    mut res: reqwest::Response,
    limit: usize,
) -> reqwest::Result<Option<Vec<u8>>> {
    let mut body = Vec::new();
    while let Some(chunk) = res.chunk().await? {
        if body.len() + chunk.len() > limit {
            return Ok(None);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(Some(body))
}

/// The error and each cause under it, as Go's wrapped errors print.
pub(super) fn causes(e: &dyn std::error::Error) -> String {
    let mut out = e.to_string();
    let mut next = e.source();
    while let Some(cause) = next {
        out += &format!(": {cause}");
        next = cause.source();
    }
    out
}

/// Decodes the first JSON value of `body`, as Go's `json.Decoder` does, into the endpoint's type.
pub(super) fn decode(req: &Request, body: &[u8]) -> serde_json::Result<Response> {
    let v = serde_json::Deserializer::from_slice(body)
        .into_iter::<Value>()
        .next()
        .unwrap_or_else(|| {
            Err(serde_json::Error::io(
                std::io::ErrorKind::UnexpectedEof.into(),
            ))
        })?;
    Ok(match req {
        Request::Healthz => Response::Healthz(go_decode(v)?),
        Request::Meta => Response::Meta(decode_meta(v)?),
        Request::Events(_) => Response::Events(go_decode(v)?),
        Request::EventById(_) => Response::Event(go_decode(v)?),
        Request::Hosts(_) => Response::Hosts(go_decode(v)?),
        Request::HostById(_) => Response::Host(go_decode(v)?),
        Request::Risk(_) => Response::Risk(go_decode(v)?),
        Request::Compliance(_) => Response::Compliance(go_decode(v)?),
    })
}

/// `lodeline-server` 0.8 and earlier report the active-host count inside `license`, which v0.9.0
/// replaced with `fleet`. The rest of `license` is dropped.
fn decode_meta(v: Value) -> serde_json::Result<super::Meta> {
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct Legacy {
        license: Option<License>,
    }
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct License {
        current_host_count: i64,
        active_window_days: i64,
    }
    let mut meta: super::Meta = go_decode(v.clone())?;
    let legacy: Legacy = go_decode(v)?;
    if let (None, Some(l)) = (&meta.fleet, legacy.license) {
        meta.fleet = Some(super::ActiveHosts {
            active_host_count: l.current_host_count,
            active_window_days: l.active_window_days,
        });
    }
    Ok(meta)
}

/// Delta seconds only (RFC 9110); anything else waits the default.
fn parse_retry_after(v: Option<&reqwest::header::HeaderValue>) -> Duration {
    v.and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<i64>().ok())
        .and_then(|n| u64::try_from(n).ok())
        .map_or(DEFAULT_RETRY_AFTER, Duration::from_secs)
}

/// The `{"error": {"code", "message"}}` body, or code `unknown` with the body text.
fn api_error(status: u16, body: &[u8]) -> FleetError {
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct Wire {
        error: Detail,
    }
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct Detail {
        code: String,
        message: String,
    }
    let wire = serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|v| go_decode::<Wire>(v).ok());
    match wire {
        Some(w) if !w.error.code.is_empty() => FleetError::Api {
            status,
            code: w.error.code,
            message: w.error.message,
        },
        _ => FleetError::Api {
            status,
            code: "unknown".into(),
            message: String::from_utf8_lossy(body).trim().to_owned(),
        },
    }
}

#[cfg(test)]
mod tests;
