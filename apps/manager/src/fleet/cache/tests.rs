//! Go's `internal/fleet/cache_test.go`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use super::*;
use crate::fleet::{Event, EventsPage, EventsParams, Healthz, InventoryView, Meta};

/// Counts upstream calls per endpoint, and answers with a generation marker so a test can tell
/// a fresh body from a stale one. It can be slowed down or told to fail.
#[derive(Default)]
struct Counting {
    calls: Mutex<HashMap<&'static str, usize>>,
    generation: AtomicU64,
    delay: Mutex<Duration>,
    err: Mutex<Option<FleetError>>,
}

fn marker(g: u64) -> String {
    format!("gen-{g}")
}

impl Counting {
    fn count(&self, endpoint: &str) -> usize {
        self.calls
            .lock()
            .unwrap()
            .get(endpoint)
            .copied()
            .unwrap_or(0)
    }

    fn set_generation(&self, g: u64) {
        self.generation.store(g, Ordering::SeqCst);
    }
}

impl Client for Counting {
    fn get(&self, req: Request) -> BoxFuture<'_, Reply> {
        Box::pin(async move {
            let name = match &req {
                Request::Healthz => "healthz",
                Request::Artifacts => "artifacts",
                other => other.endpoint().unwrap(),
            };
            *self.calls.lock().unwrap().entry(name).or_default() += 1;
            let delay = *self.delay.lock().unwrap();
            tokio::time::sleep(delay).await;
            if let Some(e) = self.err.lock().unwrap().clone() {
                return Err(e);
            }
            let m = marker(self.generation.load(Ordering::SeqCst));
            Ok(Arc::new(match req {
                Request::Events(_) => Response::Events(EventsPage {
                    next_cursor: Some(m),
                    ..Default::default()
                }),
                Request::Meta => Response::Meta(Meta {
                    server_version: m,
                    ..Default::default()
                }),
                Request::Healthz => Response::Healthz(Healthz {
                    status: m,
                    ..Default::default()
                }),
                _ => Response::Event(Event {
                    event_id: m,
                    ..Default::default()
                }),
            }))
        })
    }

    fn artifact(&self, _: ArtifactName) -> BoxFuture<'_, Result<Download, FleetError>> {
        *self.calls.lock().unwrap().entry("artifact").or_default() += 1;
        Box::pin(async { Err(FleetError::NotFound) })
    }
}

fn events() -> Request {
    Request::Events(EventsParams::default())
}

fn events_for(hosts: &[&str]) -> Request {
    Request::Events(EventsParams {
        host_ids: hosts.iter().map(|h| h.to_string()).collect(),
        ..Default::default()
    })
}

fn generation(r: &Response) -> String {
    match r {
        Response::Events(p) => p.next_cursor.clone().unwrap(),
        Response::Meta(m) => m.server_version.clone(),
        other => panic!("unexpected {other:?}"),
    }
}

/// TTL 100 ms, stale up to 1 s, 128 keys.
fn test_config() -> CacheConfig {
    CacheConfig {
        ttl: Duration::from_millis(100),
        max_stale: Duration::from_secs(1),
        max_entries: 128,
    }
}

struct ManualClock(Arc<Mutex<Instant>>);

impl ManualClock {
    fn new() -> Self {
        Self(Arc::new(Mutex::new(Instant::now())))
    }

    fn clock(&self) -> Clock {
        let now = self.0.clone();
        Arc::new(move || *now.lock().unwrap())
    }

    fn advance(&self, d: Duration) {
        *self.0.lock().unwrap() += d;
    }
}

fn cache(up: &Arc<Counting>, cfg: CacheConfig, clock: Option<&ManualClock>) -> CachingClient {
    let next: Arc<dyn Client> = up.clone();
    match clock {
        Some(c) => CachingClient::with_clock(next, cfg, c.clock()),
        None => CachingClient::new(next, cfg),
    }
}

async fn eventually(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(2);
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
}

/// Concurrent misses for one key make exactly one upstream call.
#[tokio::test]
async fn concurrent_misses_collapse_into_one_call() {
    let up = Arc::new(Counting::default());
    *up.delay.lock().unwrap() = Duration::from_millis(50);
    let c = cache(&up, test_config(), None);
    let tasks: Vec<_> = (0..50)
        .map(|_| {
            let c = c.clone();
            tokio::spawn(async move { c.get(events()).await })
        })
        .collect();
    for t in tasks {
        assert!(t.await.unwrap().is_ok());
    }
    assert_eq!(up.count("events"), 1, "single flight collapses the herd");
}

#[tokio::test]
async fn a_second_call_within_the_ttl_hits_the_cache() {
    let up = Arc::new(Counting::default());
    let c = cache(&up, test_config(), None);
    let first = c.get(events()).await.unwrap();
    let second = c.get(events()).await.unwrap();
    assert_eq!(up.count("events"), 1);
    assert_eq!(generation(&first), generation(&second));
}

/// Past the TTL but within the stale limit, a read gets the stale body at once and starts one
/// background refresh; a later read sees the refreshed body.
#[tokio::test]
async fn stale_while_revalidate() {
    let clock = ManualClock::new();
    let up = Arc::new(Counting::default());
    let c = cache(&up, test_config(), Some(&clock));
    assert_eq!(generation(&c.get(events()).await.unwrap()), "gen-0");

    clock.advance(Duration::from_millis(200));
    up.set_generation(1);
    let stale = c.get(events()).await.unwrap();
    assert_eq!(generation(&stale), "gen-0", "the stale read does not wait");

    eventually("the refresh", || up.count("events") == 2).await;
    let deadline = Instant::now() + Duration::from_secs(2);
    while generation(&c.get(events()).await.unwrap()) != "gen-1" {
        assert!(Instant::now() < deadline, "never saw the refreshed gen-1");
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    assert_eq!(up.count("events"), 2, "prime and one background refresh");
}

/// Past the stale limit, a 503 falls back to the last body.
#[tokio::test]
async fn serves_stale_while_the_upstream_rebuilds() {
    let clock = ManualClock::new();
    let up = Arc::new(Counting::default());
    let c = cache(&up, test_config(), Some(&clock));
    let first = c.get(events()).await.unwrap();

    clock.advance(Duration::from_secs(5));
    *up.err.lock().unwrap() = Some(FleetError::ServiceUnavailable {
        retry_after: Duration::from_secs(1),
    });
    let got = c.get(events()).await.expect("the last good body");
    assert_eq!(generation(&got), generation(&first));
}

#[tokio::test]
async fn healthz_is_never_cached() {
    let up = Arc::new(Counting::default());
    let c = cache(&up, test_config(), None);
    for _ in 0..3 {
        c.get(Request::Healthz).await.unwrap();
    }
    assert_eq!(up.count("healthz"), 3);
}

/// Distinct keys past the bound evict the oldest fetches.
#[tokio::test]
async fn evicts_beyond_max_entries() {
    let up = Arc::new(Counting::default());
    let cfg = CacheConfig {
        max_entries: 4,
        ..test_config()
    };
    let c = cache(&up, cfg, None);
    let names: Vec<String> = (0..20).map(|i| format!("host-{i}")).collect();
    for name in &names {
        c.get(events_for(&[name])).await.unwrap();
    }
    assert_eq!(c.len(), 4);
    assert!(c.cached(&events_for(&["host-19"])).is_some());
    assert!(
        c.cached(&events_for(&["host-15"])).is_none(),
        "oldest fetch goes first"
    );
}

#[tokio::test]
async fn a_zero_config_still_caches() {
    let up = Arc::new(Counting::default());
    let c = cache(&up, CacheConfig::default(), None);
    c.get(events()).await.unwrap();
    c.get(events()).await.unwrap();
    assert_eq!(up.count("events"), 1, "defaults give a non-zero TTL");
}

/// Metadata stays fresh 12 times longer than live data.
#[tokio::test]
async fn per_endpoint_ttl() {
    let clock = ManualClock::new();
    let up = Arc::new(Counting::default());
    let cfg = CacheConfig {
        ttl: Duration::from_millis(20),
        max_stale: Duration::from_secs(1),
        max_entries: 128,
    };
    let c = cache(&up, cfg, Some(&clock));
    c.get(Request::Meta).await.unwrap();
    c.get(events()).await.unwrap();

    clock.advance(Duration::from_millis(100));
    c.get(events()).await.unwrap();
    eventually("the events refresh", || up.count("events") == 2).await;

    c.get(Request::Meta).await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        up.count("meta"),
        1,
        "the metadata TTL outlasts the live one"
    );
}

/// The upstream call runs on its own, so it completes and is cached after the reader has gone:
/// both a background refresh and a miss whose caller gave up mid-call.
#[tokio::test]
async fn upstream_calls_outlive_their_callers() {
    let clock = ManualClock::new();
    let up = Arc::new(Counting::default());
    let c = cache(&up, test_config(), Some(&clock));
    c.get(events()).await.unwrap();
    clock.advance(Duration::from_millis(200));
    up.set_generation(1);
    assert_eq!(generation(&c.get(events()).await.unwrap()), "gen-0");
    eventually("the refreshed body", || {
        c.cached(&events())
            .is_some_and(|r| generation(&r) == "gen-1")
    })
    .await;

    *up.delay.lock().unwrap() = Duration::from_millis(50);
    let req = events_for(&["gone"]);
    let gave_up = tokio::time::timeout(Duration::from_millis(5), c.get(req.clone())).await;
    assert!(gave_up.is_err());
    eventually("the abandoned miss", || c.cached(&req).is_some()).await;
}

/// Past the stale limit, an error other than a 503 shows: a revoked token is not masked.
#[tokio::test]
async fn surfaces_a_terminal_error_past_the_stale_limit() {
    let clock = ManualClock::new();
    let up = Arc::new(Counting::default());
    let c = cache(&up, test_config(), Some(&clock));
    c.get(events()).await.unwrap();
    clock.advance(Duration::from_secs(5));
    *up.err.lock().unwrap() = Some(FleetError::Unauthorized);
    assert_eq!(c.get(events()).await.unwrap_err(), FleetError::Unauthorized);
}

/// The key tells `["a", "b"]` from `["a b"]` and from `["a,b"]`'s spelling of itself.
#[tokio::test]
async fn distinct_list_params_do_not_collide() {
    let up = Arc::new(Counting::default());
    let c = cache(&up, test_config(), None);
    c.get(events_for(&["a", "b"])).await.unwrap();
    c.get(events_for(&["a b"])).await.unwrap();
    assert_eq!(up.count("events"), 2);
}

/// A burst of stale reads for one key starts one background refresh, not one per read.
#[tokio::test]
async fn one_background_refresh_per_key() {
    let clock = ManualClock::new();
    let up = Arc::new(Counting::default());
    let c = cache(&up, test_config(), Some(&clock));
    c.get(events()).await.unwrap();
    clock.advance(Duration::from_millis(200));
    *up.delay.lock().unwrap() = Duration::from_millis(80);
    let tasks: Vec<_> = (0..50)
        .map(|_| {
            let c = c.clone();
            tokio::spawn(async move { c.get(events()).await })
        })
        .collect();
    for t in tasks {
        t.await.unwrap().unwrap();
    }
    eventually("the refresh", || up.count("events") == 2).await;
    assert_eq!(c.background_refreshes(), 1);
}

/// Panics on its first call, then answers.
#[derive(Default)]
struct PanicsOnce(AtomicU64);

impl Client for PanicsOnce {
    fn get(&self, _: Request) -> BoxFuture<'_, Reply> {
        Box::pin(async move {
            if self.0.fetch_add(1, Ordering::SeqCst) == 0 {
                panic!("fetch panicked");
            }
            Ok(Arc::new(Response::Events(EventsPage::default())))
        })
    }

    fn artifact(&self, _: ArtifactName) -> BoxFuture<'_, Result<Download, FleetError>> {
        unreachable!("no release file reads here")
    }
}

#[tokio::test]
async fn a_panicking_fetch_ends_its_flight() {
    let c = CachingClient::new(Arc::new(PanicsOnce::default()), CacheConfig::default());
    let err = c.get(events()).await.unwrap_err();
    assert!(matches!(err, FleetError::Transport(_)), "{err}");
    assert!(c.0.state.lock().unwrap().flights.is_empty());
    c.get(events())
        .await
        .expect("the next call starts a new fetch");
}

#[tokio::test]
async fn proxy_reads_have_keys_of_their_own() {
    let up = Arc::new(Counting::default());
    let c = cache(&up, test_config(), None);
    let host = Request::HostById("same-id".into());
    let proxy = Request::ProxyById("same-id".into());
    let proxies = Request::Proxies(crate::fleet::ProxiesParams::default());
    let invocation = Request::InvocationById("same-id".into());
    let invocations = Request::Invocations(crate::fleet::InvocationsParams::default());
    let view = |v, proxy_id: &str| {
        Request::Inventory(
            v,
            crate::fleet::InventoryParams {
                proxy_id: proxy_id.into(),
                ..Default::default()
            },
        )
    };
    let snapshots = view(InventoryView::Snapshots, "same-id");
    let drift = view(InventoryView::Drift, "same-id");
    let markers = view(InventoryView::Markers, "same-id");
    let other_drift = view(InventoryView::Drift, "other-id");
    let reads = [
        &host,
        &proxy,
        &proxies,
        &invocation,
        &invocations,
        &snapshots,
        &drift,
        &markers,
        &other_drift,
    ];
    for req in reads.iter().chain(reads.iter()) {
        c.get((*req).clone()).await.unwrap();
    }
    assert_eq!(
        [
            "host_by_id",
            "proxy_by_id",
            "proxies",
            "proxy_invocation_by_id",
            "proxy_invocations",
            "proxy_inventory_snapshots",
            "proxy_rebaseline_markers",
        ]
        .map(|e| up.count(e)),
        [1; 7],
        "each read is fetched once, under its own key"
    );
    assert_eq!(up.count("proxy_drift"), 2, "one key per proxy");
    assert_eq!(c.len(), 9);
}

/// The release file list and each file go to the server every time.
#[tokio::test]
async fn release_files_are_never_cached() {
    let up = Arc::new(Counting::default());
    let c = cache(&up, CacheConfig::default(), None);
    let name = ArtifactName::parse("SHA256SUMS").unwrap();
    for _ in 0..2 {
        c.get(Request::Artifacts).await.unwrap();
        assert!(matches!(
            c.artifact(name.clone()).await,
            Err(FleetError::NotFound)
        ));
    }
    assert_eq!((up.count("artifacts"), up.count("artifact")), (2, 2));
    assert_eq!(c.len(), 0);
}
