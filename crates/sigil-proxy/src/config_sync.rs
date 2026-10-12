//! Remote config fetch and apply (T-12c1, control-plane.md §5.2, §6.2-§6.4).
//!
//! * [`ConfigSync`] is the pure state machine: it takes fetch results and the
//!   monotonic clock, parses with `sigil_proxy_api::parse_config`, builds a
//!   [`RouteTable`] and swaps it into the [`TableHandle`]. It reads no network.
//! * [`MtlsFetcher`] (unix) does the `GET /v1/proxy-config` over mTLS.
//! * [`run_sync`] polls, with jitter, and enforces the TTL deadline.
//!
//! Rules, all fail closed:
//! * The deadline is `receipt + ttl_seconds` on the monotonic clock. `expires_at`
//!   is display only and never read.
//! * A failed fetch, parse, build or ordering check keeps the last good table
//!   until its deadline, never extends it, and then the table is removed (the
//!   listener answers 401).
//! * A revision below the highest one ever applied (the high-water mark, kept
//!   after expiry) is never applied.
//! * Nothing is persisted: a restarted proxy needs a fresh fetch (§6.3 "Restart",
//!   decided 2026-10-10). The high-water mark is therefore per process.
//! * The remote config is never merged with the local bootstrap. The local
//!   credentials and limits are constraints: an unknown `credential_ref` or an
//!   origin outside its binding fails the whole apply, and remote limits can only
//!   lower the local ones.

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use sigil_proxy_api::status::{ConfigState, LastUpdateError};
use sigil_proxy_api::{ConfigRoute, ProxyConfig};
use tokio::time::Instant;

use crate::bootstrap::Credential;
use crate::limits::{Limits, RemoteLimits};
use crate::route::{PrincipalSpec, RouteSpec, RouteTable, TableHandle, VerifierSpec};

/// Largest config body accepted from the server. The PUT cap is 1 MiB; a fetched
/// document carries a few extra stamps, so 4 MiB is generous and still bounded.
pub const MAX_CONFIG_BYTES: usize = 4 * 1024 * 1024;

/// Result of one fetch attempt, already reduced to what the state machine needs.
/// No variant carries a body other than the config document itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchResult {
    /// `200` with the raw body (not yet validated).
    Config(Vec<u8>),
    /// `403` with the fixed `disabled` (or `retired`) code (§6.2 M-10).
    Disabled,
    /// `503`: the server's boot gate. A retryable miss, not an apply failure.
    Unavailable,
    /// Transport error, timeout, oversized body or any other status.
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncOutcome {
    /// A new revision was built and installed.
    Applied { revision: i64 },
    /// Same revision and hash: the deadline was extended.
    Refreshed,
    /// The proxy was told it is disabled; the table was removed.
    Disabled,
    /// Nothing changed (or the old config stays) for this reason.
    Kept(LastUpdateError),
}

/// What the lifecycle publishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncStatus {
    pub config_state: ConfigState,
    pub last_update_error: Option<LastUpdateError>,
}

/// Why a parsed config could not become a table. Fixed categories only.
struct BuildError;

/// Unix seconds of a validated RFC 3339 timestamp.
fn unix_of(ts: &sigil_proxy_api::Timestamp) -> Option<i64> {
    time::OffsetDateTime::parse(ts.as_str(), &time::format_description::well_known::Rfc3339)
        .ok()
        .map(|t| t.unix_timestamp())
}

fn remote_limits(r: &ConfigRoute) -> RemoteLimits {
    let pos = |v: Option<i64>| v.and_then(|n| u64::try_from(n).ok()).filter(|n| *n > 0);
    match &r.limits {
        None => RemoteLimits::default(),
        Some(l) => RemoteLimits {
            max_request_bytes: pos(l.max_request_bytes),
            max_response_bytes: pos(l.max_response_bytes),
            request_timeout_seconds: pos(l.request_timeout_seconds),
        },
    }
}

/// Map the config DTO to the route builder's input. The config-wide
/// `allowed_origins` applies to every route; principals are attached to the routes
/// they name. `allow_private_destination` is always false: the DTO has no such
/// field yet (contract OPEN), so a private destination is refused (fail closed).
fn route_specs(cfg: &ProxyConfig) -> Result<Vec<RouteSpec>, BuildError> {
    let mut out = Vec::with_capacity(cfg.routes.len());
    for r in &cfg.routes {
        let mut principals = Vec::new();
        for p in cfg
            .principals
            .iter()
            .filter(|p| p.routes.iter().any(|id| id == &r.route_id))
        {
            let mut verifiers = Vec::new();
            for v in &p.verifiers {
                let not_after = match &v.not_after {
                    None => None,
                    Some(ts) => Some(unix_of(ts).ok_or(BuildError)?),
                };
                verifiers.push(VerifierSpec {
                    verifier: v.verifier.clone(),
                    not_after,
                });
            }
            principals.push(PrincipalSpec {
                principal_id: p.principal_id.clone(),
                verifiers,
            });
        }
        out.push(RouteSpec {
            route_id: r.route_id.clone(),
            upstream_url: r.upstream_url.clone(),
            credential_ref: r.credential_ref.as_str().to_string(),
            principals,
            allowed_origins: cfg.allowed_origins.clone(),
            allow_private_destination: false,
            limits: remote_limits(r),
        });
    }
    Ok(out)
}

struct Applied {
    revision: i64,
    hash: String,
}

/// The apply state machine. Owns no I/O.
pub struct ConfigSync {
    proxy_id: String,
    credentials: BTreeMap<String, Credential>,
    limits: Limits,
    table: TableHandle,
    /// Highest revision applied by this process; survives expiry and disable.
    high_water: Option<Applied>,
    /// Monotonic deadline of the installed table. `None` means no table.
    deadline: Option<Instant>,
    /// `ttl_seconds` of the last accepted config, used to pace polling.
    last_ttl: Option<i64>,
    state: ConfigState,
    last_error: Option<LastUpdateError>,
}

impl ConfigSync {
    /// `initial` is the lifecycle's startup state (`none`, `expired` or
    /// `disabled`); a `valid` initial state is never accepted.
    pub fn new(
        proxy_id: &str,
        credentials: BTreeMap<String, Credential>,
        limits: Limits,
        table: TableHandle,
        initial: ConfigState,
    ) -> ConfigSync {
        ConfigSync {
            proxy_id: proxy_id.to_string(),
            credentials,
            limits,
            table,
            high_water: None,
            deadline: None,
            last_ttl: None,
            state: if initial == ConfigState::Valid {
                ConfigState::Expired
            } else {
                initial
            },
            last_error: None,
        }
    }

    pub fn status(&self) -> SyncStatus {
        SyncStatus {
            config_state: self.state,
            last_update_error: self.last_error,
        }
    }

    pub fn deadline(&self) -> Option<Instant> {
        self.deadline
    }

    pub fn last_ttl_seconds(&self) -> Option<i64> {
        self.last_ttl
    }

    pub fn applied_revision(&self) -> Option<i64> {
        self.high_water.as_ref().map(|a| a.revision)
    }

    /// Remove the table once its deadline has passed. Idempotent.
    pub fn expire(&mut self, now: Instant) {
        if self.deadline.is_some_and(|d| now >= d) {
            self.table.set(None);
            self.deadline = None;
            self.state = ConfigState::Expired;
        }
    }

    fn keep(&mut self, e: LastUpdateError) -> SyncOutcome {
        self.last_error = Some(e);
        SyncOutcome::Kept(e)
    }

    /// Feed one fetch result received at `now` (monotonic, the receipt time).
    pub fn on_fetch(&mut self, now: Instant, result: FetchResult) -> SyncOutcome {
        self.expire(now);
        match result {
            FetchResult::Failed | FetchResult::Unavailable => {
                self.keep(LastUpdateError::FetchFailed)
            }
            FetchResult::Disabled => {
                // Stop new calls at once (§6.2 M-10). The high-water mark stays.
                self.table.set(None);
                self.deadline = None;
                self.state = ConfigState::Disabled;
                self.last_error = None;
                SyncOutcome::Disabled
            }
            FetchResult::Config(body) => self.on_config(now, &body),
        }
    }

    fn on_config(&mut self, now: Instant, body: &[u8]) -> SyncOutcome {
        let cfg = match sigil_proxy_api::parse_config(body) {
            Ok(c) => c,
            Err(_) => return self.keep(LastUpdateError::ValidationFailed),
        };
        if cfg.proxy_id.as_str() != self.proxy_id {
            return self.keep(LastUpdateError::ValidationFailed);
        }
        let revision = cfg.revision.get();
        let hash = cfg.config_hash().as_str().to_string();
        let ttl = cfg.ttl_seconds;
        // `parse_config` validated 60..=900; re-check so a changed parser can
        // never produce a negative or huge duration here.
        let Ok(ttl_secs) = u64::try_from(ttl) else {
            return self.keep(LastUpdateError::ValidationFailed);
        };

        let mut refresh = false;
        if let Some(hw) = &self.high_water {
            if revision < hw.revision {
                // Server counter restored lower: keep, do not extend (§6.2).
                return self.keep(LastUpdateError::StaleRevision);
            }
            if revision == hw.revision {
                if hash != hw.hash {
                    return self.keep(LastUpdateError::ConfigHashMismatch);
                }
                refresh = true;
            }
        }

        // A refresh of an installed table only extends the deadline. If the table
        // is gone (expired or disabled), the same revision is installed again.
        if refresh && self.deadline.is_some() {
            self.deadline = Some(now + Duration::from_secs(ttl_secs));
            self.last_ttl = Some(ttl);
            self.state = ConfigState::Valid;
            self.last_error = None;
            return SyncOutcome::Refreshed;
        }

        let table = match route_specs(&cfg).and_then(|s| {
            RouteTable::build(&s, &self.credentials, &self.limits).map_err(|_| BuildError)
        }) {
            Ok(t) => t,
            Err(_) => return self.keep(LastUpdateError::ApplyFailed),
        };
        self.table.set(Some(table));
        self.high_water = Some(Applied { revision, hash });
        self.deadline = Some(now + Duration::from_secs(ttl_secs));
        self.last_ttl = Some(ttl);
        self.state = ConfigState::Valid;
        self.last_error = None;
        if refresh {
            SyncOutcome::Refreshed
        } else {
            SyncOutcome::Applied { revision }
        }
    }
}

// ------------------------------------------------------------------ polling

pub type FetchFuture<'a> = Pin<Box<dyn Future<Output = FetchResult> + Send + 'a>>;

pub trait Fetcher: Send + Sync {
    fn fetch(&self) -> FetchFuture<'_>;
}

#[derive(Debug, Clone, Copy)]
pub struct SyncParams {
    /// Poll interval after a success, capped at a third of the TTL.
    pub poll: Duration,
    /// Retry interval after a failed fetch.
    pub retry: Duration,
}

impl Default for SyncParams {
    /// Proposed values of §6.3 (unmeasured): poll 30 s with jitter.
    fn default() -> Self {
        SyncParams {
            poll: Duration::from_secs(30),
            retry: Duration::from_secs(5),
        }
    }
}

/// `d` scaled by a random factor in `[0.8, 1.2]`. Without OS randomness there is
/// no jitter (the interval is still bounded).
fn jitter(d: Duration) -> Duration {
    let mut b = [0u8; 2];
    if getrandom::getrandom(&mut b).is_err() {
        return d;
    }
    let f = u16::from_le_bytes(b) as u64; // 0..=65535
    let permille = 800 + f * 400 / 65535;
    d * permille as u32 / 1000
}

fn next_poll_delay(sync: &ConfigSync, ok: bool, p: &SyncParams) -> Duration {
    if !ok {
        return jitter(p.retry);
    }
    let cap = sync
        .last_ttl_seconds()
        .and_then(|t| u64::try_from(t).ok())
        .map_or(p.poll, |t| Duration::from_secs(t / 3));
    jitter(p.poll.min(cap))
}

/// Poll until `shutdown` completes. `on_status` is called after every change of
/// the published status (including expiry that happens between polls).
///
/// The TTL deadline is enforced by its own timer, also while a fetch is in
/// flight, so a slow server cannot keep an expired table alive.
pub async fn run_sync<F, S>(
    mut sync: ConfigSync,
    fetcher: &F,
    params: SyncParams,
    mut on_status: S,
    shutdown: impl Future<Output = ()>,
) where
    F: Fetcher + ?Sized,
    S: FnMut(SyncStatus),
{
    tokio::pin!(shutdown);
    let mut last = sync.status();
    let mut next_poll = Instant::now();
    loop {
        // Wait for the next poll, expiring the table on time.
        loop {
            let wake = sync.deadline().map_or(next_poll, |d| d.min(next_poll));
            tokio::select! {
                _ = &mut shutdown => return,
                _ = tokio::time::sleep_until(wake) => {}
            }
            sync.expire(Instant::now());
            publish(&sync, &mut last, &mut on_status);
            if Instant::now() >= next_poll {
                break;
            }
        }

        // Fetch, still watching the deadline.
        let result = {
            let fetch = fetcher.fetch();
            tokio::pin!(fetch);
            loop {
                let dl = sync.deadline();
                tokio::select! {
                    _ = &mut shutdown => return,
                    r = &mut fetch => break r,
                    _ = async {
                        match dl {
                            Some(d) => tokio::time::sleep_until(d).await,
                            None => std::future::pending::<()>().await,
                        }
                    } => {
                        sync.expire(Instant::now());
                        publish(&sync, &mut last, &mut on_status);
                    }
                }
            }
        };
        let now = Instant::now();
        let outcome = sync.on_fetch(now, result);
        tracing::info!(outcome = outcome_label(outcome), "config fetch");
        publish(&sync, &mut last, &mut on_status);
        let ok = matches!(
            outcome,
            SyncOutcome::Applied { .. } | SyncOutcome::Refreshed | SyncOutcome::Disabled
        );
        next_poll = now + next_poll_delay(&sync, ok, &params);
    }
}

fn outcome_label(o: SyncOutcome) -> &'static str {
    match o {
        SyncOutcome::Applied { .. } => "applied",
        SyncOutcome::Refreshed => "refreshed",
        SyncOutcome::Disabled => "disabled",
        SyncOutcome::Kept(LastUpdateError::StaleRevision) => "kept_stale_revision",
        SyncOutcome::Kept(LastUpdateError::ValidationFailed) => "kept_validation_failed",
        SyncOutcome::Kept(LastUpdateError::FetchFailed) => "kept_fetch_failed",
        SyncOutcome::Kept(LastUpdateError::ApplyFailed) => "kept_apply_failed",
        SyncOutcome::Kept(LastUpdateError::ConfigHashMismatch) => "kept_config_hash_mismatch",
    }
}

fn publish(sync: &ConfigSync, last: &mut SyncStatus, on_status: &mut impl FnMut(SyncStatus)) {
    let now = sync.status();
    if now != *last {
        *last = now;
        on_status(now);
    }
}

// ------------------------------------------------------------- mTLS fetcher

#[cfg(unix)]
pub use mtls::MtlsFetcher;

#[cfg(unix)]
mod mtls {
    use super::*;
    use crate::bootstrap::{split_host_port, Bootstrap};
    use bytes::Bytes;
    use http_body_util::{BodyExt, Empty, Limited};
    use hyper_util::rt::TokioIo;
    use std::path::PathBuf;

    /// Per-attempt bound: connect, handshake, request and body together.
    const FETCH_TIMEOUT: Duration = Duration::from_secs(10);

    pub struct MtlsFetcher {
        host: String,
        port: u16,
        authority: String,
        path: String,
        ca_file: PathBuf,
        cert_file: PathBuf,
        key_file: PathBuf,
        timeout: Duration,
    }

    impl MtlsFetcher {
        /// `None` when `control_plane_url` cannot be split (the bootstrap already
        /// validated it, so this does not happen for a loaded bootstrap).
        pub fn from_bootstrap(b: &Bootstrap) -> Option<MtlsFetcher> {
            let rest = b.control_plane_url.strip_prefix("https://")?;
            let (authority, prefix) = match rest.find('/') {
                Some(i) => (&rest[..i], rest[i..].trim_end_matches('/')),
                None => (rest, ""),
            };
            let (host, port) = split_host_port(authority).ok()?;
            let host = host
                .strip_prefix('[')
                .and_then(|h| h.strip_suffix(']'))
                .unwrap_or(&host)
                .to_string();
            Some(MtlsFetcher {
                authority: authority.to_ascii_lowercase(),
                host,
                port: port.unwrap_or(443),
                path: format!("{prefix}/v1/proxy-config"),
                ca_file: b.ca_file.clone(),
                cert_file: b.client_cert_file.clone(),
                key_file: b.client_key_file.clone(),
                timeout: FETCH_TIMEOUT,
            })
        }

        /// Test hook: a different per-attempt bound.
        pub fn with_timeout(mut self, t: Duration) -> Self {
            self.timeout = t;
            self
        }

        async fn get(&self) -> Option<FetchResult> {
            let connector =
                crate::tls::control_plane_connector(&self.ca_file, &self.cert_file, &self.key_file)
                    .ok()?;
            let name = crate::tls::server_name(&self.host)?;
            let tcp = tokio::net::TcpStream::connect((self.host.as_str(), self.port))
                .await
                .ok()?;
            let _ = tcp.set_nodelay(true);
            let tls = connector.connect(name, tcp).await.ok()?;
            let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
                .await
                .ok()?;
            tokio::spawn(async move {
                let _ = conn.await;
            });
            let req = http::Request::builder()
                .method(http::Method::GET)
                .uri(&self.path)
                .header(http::header::HOST, self.authority.as_str())
                .header(http::header::ACCEPT, "application/json")
                .header(http::header::CONNECTION, "close")
                .body(Empty::<Bytes>::new())
                .ok()?;
            let resp = sender.send_request(req).await.ok()?;
            let (parts, body) = resp.into_parts();
            let status = parts.status;
            if status == http::StatusCode::SERVICE_UNAVAILABLE {
                return Some(FetchResult::Unavailable);
            }
            let bytes = Limited::new(body, MAX_CONFIG_BYTES)
                .collect()
                .await
                .ok()?
                .to_bytes();
            Some(match status {
                s if s == http::StatusCode::OK => FetchResult::Config(bytes.to_vec()),
                s if s == http::StatusCode::FORBIDDEN => {
                    match sigil_proxy_api::parse_api_error(&bytes) {
                        Ok(e)
                            if matches!(
                                e.error.code,
                                sigil_proxy_api::ErrorCode::Disabled
                                    | sigil_proxy_api::ErrorCode::Retired
                            ) =>
                        {
                            FetchResult::Disabled
                        }
                        _ => FetchResult::Failed,
                    }
                }
                _ => FetchResult::Failed,
            })
        }
    }

    impl Fetcher for MtlsFetcher {
        fn fetch(&self) -> FetchFuture<'_> {
            Box::pin(async move {
                match tokio::time::timeout(self.timeout, self.get()).await {
                    Ok(Some(r)) => r,
                    // Transport error, timeout, bad TLS material: all fetch_failed.
                    // The cause is not logged (it can carry paths or peer data).
                    _ => FetchResult::Failed,
                }
            })
        }
    }
}

/// Windows: the control-plane client is unix-only until the Windows proxy
/// service is verified; every fetch fails, so the proxy never forwards.
#[cfg(not(unix))]
pub struct MtlsFetcher;

#[cfg(not(unix))]
impl MtlsFetcher {
    pub fn from_bootstrap(_: &crate::bootstrap::Bootstrap) -> Option<MtlsFetcher> {
        Some(MtlsFetcher)
    }
}

#[cfg(not(unix))]
impl Fetcher for MtlsFetcher {
    fn fetch(&self) -> FetchFuture<'_> {
        Box::pin(async { FetchResult::Failed })
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use serde_json::{json, Value};
    use std::os::unix::fs::PermissionsExt;

    const ORIGIN: &str = "https://api.example.com";

    struct Fx {
        _dir: tempfile::TempDir,
        creds: BTreeMap<String, Credential>,
    }

    fn fx() -> Fx {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("secret");
        std::fs::write(&p, "UPSTREAM-SECRET-VALUE\n").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        let creds = BTreeMap::from([(
            "gh".to_string(),
            Credential {
                secret_file: p,
                upstream_origins: vec![ORIGIN.to_string()],
            },
        )]);
        Fx { _dir: dir, creds }
    }

    fn sync(f: &Fx, table: &TableHandle) -> ConfigSync {
        ConfigSync::new(
            "px-1",
            f.creds.clone(),
            Limits::default(),
            table.clone(),
            ConfigState::None,
        )
    }

    fn v(tok: &str) -> String {
        sigil_proxy_api::verifier_for(tok)
    }

    fn cfg(revision: i64, ttl: i64, cred: &str, verifiers: Value) -> Value {
        json!({
            "schema_version": 1, "proxy_id": "px-1", "revision": revision,
            "issued_at": "2026-10-11T00:00:00Z", "expires_at": "2026-10-11T00:05:00Z",
            "ttl_seconds": ttl, "mode": "observe",
            "max_offline_retry_age_seconds": 2592000, "event_retention_seconds": 7776000,
            "allowed_origins": ["https://app.example.com"],
            "routes": [{"route_id": "r1", "upstream_id": "up-r1",
                "upstream_url": "https://api.example.com/mcp",
                "upstream_protocol": "2025-11-25", "credential_ref": cred,
                "credential_scope_id": "cs-0123456789abcdef0123456789abcdef"}],
            "principals": [{"principal_id": "claude", "verifiers": verifiers, "routes": ["r1"]}],
        })
    }

    fn std_cfg(revision: i64) -> Value {
        cfg(
            revision,
            300,
            "gh",
            json!([{"key_id": "k1", "verifier": v("tok-1")}]),
        )
    }

    fn body(v: &Value) -> FetchResult {
        FetchResult::Config(serde_json::to_vec(v).unwrap())
    }

    fn authenticates(t: &TableHandle, tok: &str) -> bool {
        t.current()
            .and_then(|t| t.route("r1").map(|r| r.authenticate(tok).is_some()))
            .unwrap_or(false)
    }

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    #[test]
    fn applies_a_valid_config() {
        let f = fx();
        let table = TableHandle::new();
        let mut s = sync(&f, &table);
        assert_eq!(s.status().config_state, ConfigState::None);
        let t0 = Instant::now();
        assert_eq!(
            s.on_fetch(t0, body(&std_cfg(5))),
            SyncOutcome::Applied { revision: 5 }
        );
        assert_eq!(s.status().config_state, ConfigState::Valid);
        assert_eq!(s.status().last_update_error, None);
        assert!(authenticates(&table, "tok-1"));
        // deadline = receipt + ttl on the monotonic clock
        assert_eq!(s.deadline(), Some(t0 + secs(300)));
        // the allowed_origins of the document reach the route
        assert!(table
            .current()
            .unwrap()
            .route("r1")
            .unwrap()
            .origin_allowed("https://app.example.com"));
    }

    /// A failed fetch/parse/build keeps the last good table until its deadline and
    /// never extends it; after the deadline the table is gone (fail closed).
    #[test]
    fn last_good_until_expiry_then_fail_closed() {
        let f = fx();
        let table = TableHandle::new();
        let mut s = sync(&f, &table);
        let t0 = Instant::now();
        s.on_fetch(t0, body(&std_cfg(1)));
        let deadline = s.deadline().unwrap();

        let bad_cred = cfg(
            2,
            300,
            "missing",
            json!([{"key_id":"k1","verifier": v("tok-2")}]),
        );
        let mut wrong_proxy = std_cfg(2);
        wrong_proxy["proxy_id"] = json!("other");
        let failures = [
            (FetchResult::Failed, LastUpdateError::FetchFailed),
            (FetchResult::Unavailable, LastUpdateError::FetchFailed),
            (
                FetchResult::Config(b"not json".to_vec()),
                LastUpdateError::ValidationFailed,
            ),
            (body(&wrong_proxy), LastUpdateError::ValidationFailed),
            (body(&bad_cred), LastUpdateError::ApplyFailed),
        ];
        for (i, (r, want)) in failures.into_iter().enumerate() {
            let at = t0 + secs(10 + i as u64);
            assert_eq!(s.on_fetch(at, r), SyncOutcome::Kept(want));
            assert_eq!(s.status().last_update_error, Some(want));
            // old config stays, deadline untouched, still valid
            assert!(authenticates(&table, "tok-1"), "{want:?}");
            assert!(!authenticates(&table, "tok-2"), "{want:?}");
            assert_eq!(s.deadline(), Some(deadline));
            assert_eq!(s.status().config_state, ConfigState::Valid);
        }
        // a failed apply did not advance the high-water mark
        assert_eq!(s.applied_revision(), Some(1));
        // just before the deadline: still served; at it: gone
        s.expire(deadline - Duration::from_millis(1));
        assert!(authenticates(&table, "tok-1"));
        s.expire(deadline);
        assert!(table.current().is_none());
        assert_eq!(s.status().config_state, ConfigState::Expired);
        // a later failure keeps it closed
        s.on_fetch(deadline + secs(1), FetchResult::Failed);
        assert!(table.current().is_none());
    }

    #[test]
    fn revision_ordering() {
        let f = fx();
        let table = TableHandle::new();
        let mut s = sync(&f, &table);
        let t0 = Instant::now();
        s.on_fetch(t0, body(&std_cfg(5)));
        let d0 = s.deadline().unwrap();

        // lower revision: never applied, never extends, stale_revision
        let r = s.on_fetch(t0 + secs(100), body(&std_cfg(4)));
        assert_eq!(r, SyncOutcome::Kept(LastUpdateError::StaleRevision));
        assert_eq!(s.deadline(), Some(d0));
        assert_eq!(s.applied_revision(), Some(5));

        // same revision, same hash: refresh, extends the deadline from receipt
        let r = s.on_fetch(t0 + secs(100), body(&std_cfg(5)));
        assert_eq!(r, SyncOutcome::Refreshed);
        assert_eq!(s.deadline(), Some(t0 + secs(400)));
        assert_eq!(s.status().last_update_error, None);

        // same revision, different hash: fault, no extension, old config kept
        let mut other = std_cfg(5);
        other["allowed_origins"] = json!(["https://evil.example.com"]);
        let d1 = s.deadline();
        let r = s.on_fetch(t0 + secs(200), body(&other));
        assert_eq!(r, SyncOutcome::Kept(LastUpdateError::ConfigHashMismatch));
        assert_eq!(s.deadline(), d1);
        assert!(!table
            .current()
            .unwrap()
            .route("r1")
            .unwrap()
            .origin_allowed("https://evil.example.com"));

        // higher revision: applied (new verifier replaces the old one)
        let next = cfg(
            6,
            300,
            "gh",
            json!([{"key_id":"k2","verifier": v("tok-2")}]),
        );
        assert_eq!(
            s.on_fetch(t0 + secs(210), body(&next)),
            SyncOutcome::Applied { revision: 6 }
        );
        assert!(authenticates(&table, "tok-2"));
        assert!(!authenticates(&table, "tok-1"));
    }

    /// The high-water mark survives expiry: an older revision is refused even
    /// with no table, and the same revision is installed again.
    #[test]
    fn high_water_survives_expiry() {
        let f = fx();
        let table = TableHandle::new();
        let mut s = sync(&f, &table);
        let t0 = Instant::now();
        s.on_fetch(t0, body(&std_cfg(5)));
        let past = t0 + secs(301);
        s.expire(past);
        assert!(table.current().is_none());

        assert_eq!(
            s.on_fetch(past, body(&std_cfg(4))),
            SyncOutcome::Kept(LastUpdateError::StaleRevision)
        );
        assert!(table.current().is_none());
        assert_eq!(s.status().config_state, ConfigState::Expired);

        // same revision + hash after expiry: the table is installed again
        let r = s.on_fetch(past + secs(1), body(&std_cfg(5)));
        assert_eq!(r, SyncOutcome::Refreshed);
        assert!(authenticates(&table, "tok-1"));
        assert_eq!(s.deadline(), Some(past + secs(301)));
        assert_eq!(s.status().config_state, ConfigState::Valid);
    }

    #[test]
    fn disabled_stops_new_calls_at_once_and_recovers() {
        let f = fx();
        let table = TableHandle::new();
        let mut s = sync(&f, &table);
        let t0 = Instant::now();
        s.on_fetch(t0, body(&std_cfg(5)));
        assert_eq!(
            s.on_fetch(t0 + secs(5), FetchResult::Disabled),
            SyncOutcome::Disabled
        );
        assert!(table.current().is_none());
        assert_eq!(s.status().config_state, ConfigState::Disabled);
        assert_eq!(s.deadline(), None);
        // re-enabled: the same revision comes back and is installed
        s.on_fetch(t0 + secs(30), body(&std_cfg(5)));
        assert!(authenticates(&table, "tok-1"));
        assert_eq!(s.status().config_state, ConfigState::Valid);
        // an older one is still refused after disable
        s.on_fetch(t0 + secs(40), FetchResult::Disabled);
        assert_eq!(
            s.on_fetch(t0 + secs(50), body(&std_cfg(3))),
            SyncOutcome::Kept(LastUpdateError::StaleRevision)
        );
        assert!(table.current().is_none());
    }

    /// A valid-looking initial state is never trusted (restart needs a fetch).
    #[test]
    fn initial_valid_is_expired() {
        let f = fx();
        let s = ConfigSync::new(
            "px-1",
            f.creds.clone(),
            Limits::default(),
            TableHandle::new(),
            ConfigState::Valid,
        );
        assert_eq!(s.status().config_state, ConfigState::Expired);
    }

    /// #260: `not_after` per verifier from the document, two-verifier overlap.
    #[test]
    fn verifier_not_after_from_config() {
        let f = fx();
        let table = TableHandle::new();
        let mut s = sync(&f, &table);
        let verifiers = json!([
            {"key_id": "old", "verifier": v("old-tok"), "not_after": "2001-01-01T00:00:00Z"},
            {"key_id": "new", "verifier": v("new-tok"), "not_after": "2999-01-01T00:00:00Z"},
        ]);
        s.on_fetch(Instant::now(), body(&cfg(1, 300, "gh", verifiers)));
        assert!(
            !authenticates(&table, "old-tok"),
            "expired verifier accepted"
        );
        assert!(authenticates(&table, "new-tok"));
        // a verifier with a future deadline works until then (overlap)
        let overlap = json!([
            {"key_id": "old", "verifier": v("old-tok"), "not_after": "2999-01-01T00:00:00Z"},
            {"key_id": "new", "verifier": v("new-tok")},
        ]);
        s.on_fetch(Instant::now(), body(&cfg(2, 300, "gh", overlap)));
        assert!(authenticates(&table, "old-tok"));
        assert!(authenticates(&table, "new-tok"));
    }

    /// #260: remote limits only lower the local values, per route.
    #[test]
    fn remote_limits_min_with_local() {
        let f = fx();
        let table = TableHandle::new();
        let local = Limits {
            max_request_body_bytes: 1000,
            call_timeout_secs: 60,
            ..Limits::default()
        };
        let mut s = ConfigSync::new(
            "px-1",
            f.creds.clone(),
            local.clone(),
            table.clone(),
            ConfigState::None,
        );
        let mut c = std_cfg(1);
        c["routes"][0]["limits"] = json!({
            "max_request_bytes": 10,          // lower: wins
            "request_timeout_seconds": 600,   // higher: ignored
        });
        s.on_fetch(Instant::now(), body(&c));
        let t = table.current().unwrap();
        let l = t.route("r1").unwrap().limits();
        assert_eq!(l.max_request_body_bytes, 10);
        assert_eq!(l.call_timeout_secs, 60);
        assert_eq!(l.max_json_response_bytes, local.max_json_response_bytes);
    }

    /// #260: proxy and server share one origin normalisation.
    #[test]
    fn origin_normalisation_is_shared() {
        for s in [
            "https://A.Example.com:443",
            "http://LOCALHOST:80",
            "https://api.example.com/x",
            "http://api.example.com",
            "https://[::1]:8443",
            "ftp://x",
            "https://u@x",
        ] {
            assert_eq!(
                crate::bootstrap::normalize_origin(s),
                sigil_proxy_api::origin::normalize_origin(s),
                "{s}"
            );
        }
    }

    struct Scripted(std::sync::Mutex<std::collections::VecDeque<FetchResult>>);

    impl Fetcher for Scripted {
        fn fetch(&self) -> FetchFuture<'_> {
            Box::pin(async move {
                self.0
                    .lock()
                    .unwrap()
                    .pop_front()
                    .unwrap_or(FetchResult::Failed)
            })
        }
    }

    /// The polling loop: applies, then a failing server cannot keep the table past
    /// its TTL, and the published status follows. Uses the paused tokio clock.
    #[tokio::test(start_paused = true)]
    async fn poll_loop_enforces_the_ttl() {
        let f = fx();
        let table = TableHandle::new();
        let s = sync(&f, &table);
        let first = body(&cfg(
            1,
            60,
            "gh",
            json!([{"key_id":"k1","verifier": v("tok-1")}]),
        ));
        let fetcher = Scripted(std::sync::Mutex::new([first].into()));
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen2 = seen.clone();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let table2 = table.clone();
        let probe = async move {
            // 10 s in: applied and valid
            tokio::time::sleep(secs(10)).await;
            let up = authenticates(&table2, "tok-1");
            // 59 s in: the server has been failing since the first poll, but
            // the deadline (60 s from receipt) has not been reached
            tokio::time::sleep(secs(49)).await;
            let still = authenticates(&table2, "tok-1");
            // 65 s in: gone
            tokio::time::sleep(secs(6)).await;
            let gone = table2.current().is_none();
            let _ = tx.send(());
            (up, still, gone)
        };
        let run = run_sync(
            s,
            &fetcher,
            SyncParams {
                poll: secs(20),
                retry: secs(5),
            },
            move |st| seen2.lock().unwrap().push(st),
            async {
                let _ = rx.await;
            },
        );
        let (_, (up, still, gone)) = tokio::join!(run, probe);
        assert!(up, "applied after the first poll");
        assert!(still, "kept until the deadline despite failed fetches");
        assert!(gone, "removed after the deadline");
        let seen = seen.lock().unwrap();
        assert_eq!(seen.first().unwrap().config_state, ConfigState::Valid);
        assert_eq!(seen.last().unwrap().config_state, ConfigState::Expired);
        assert_eq!(
            seen.last().unwrap().last_update_error,
            Some(LastUpdateError::FetchFailed)
        );
    }
}
