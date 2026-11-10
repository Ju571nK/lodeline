//! The fleet read cache (Go's `internal/fleet/cache.go`): stale-while-revalidate, one upstream
//! call per key at a time, and a bound on the number of keys, dropping the oldest fetch first.
//!
//! Per key, by the age of the cached body:
//! - below the TTL: served from the cache;
//! - below the stale limit: served from the cache, and one background refresh starts;
//! - older: refreshed while the caller waits, falling back to the old body only on a 503;
//! - not cached: fetched while the caller waits.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::watch;

use super::{ArtifactName, BoxFuture, Client, Download, FleetError, Reply, Request, Response};

/// How much longer metadata and past events stay fresh than live data.
const SLOW_TIER: u32 = 12;

#[derive(Clone, Copy, Debug, Default)]
pub struct CacheConfig {
    /// Fresh below this age; zero means 5 s.
    pub ttl: Duration,
    /// Served stale, with a refresh, below this age; zero means 60 s.
    pub max_stale: Duration,
    /// Most keys held; zero means 512.
    pub max_entries: usize,
}

#[derive(Clone, Copy)]
struct Policy {
    ttl: Duration,
    max_stale: Duration,
}

pub type Clock = Arc<dyn Fn() -> Instant + Send + Sync>;

#[derive(Clone)]
pub struct CachingClient(Arc<Inner>);

struct Inner {
    next: Arc<dyn Client>,
    live: Policy,
    max_entries: usize,
    clock: Clock,
    state: Mutex<State>,
    /// Background refreshes started; tests check the one-per-key cap.
    refreshes: AtomicU64,
}

type Flight = watch::Receiver<Option<Reply>>;

#[derive(Default)]
struct State {
    items: HashMap<String, Entry>,
    /// Fetch order, oldest first, by a sequence number in `Entry`.
    order: BTreeMap<u64, String>,
    next_seq: u64,
    /// Upstream calls under way, by key; later callers wait for the same answer.
    flights: HashMap<String, Flight>,
    /// Keys with a background refresh under way.
    refreshing: HashSet<String>,
}

struct Entry {
    val: Arc<Response>,
    fetched_at: Instant,
    seq: u64,
}

impl CachingClient {
    pub fn new(next: Arc<dyn Client>, cfg: CacheConfig) -> Self {
        Self::with_clock(next, cfg, Arc::new(Instant::now))
    }

    pub fn with_clock(next: Arc<dyn Client>, cfg: CacheConfig, clock: Clock) -> Self {
        let or = |d: Duration, default| if d.is_zero() { default } else { d };
        Self(Arc::new(Inner {
            next,
            live: Policy {
                ttl: or(cfg.ttl, Duration::from_secs(5)),
                max_stale: or(cfg.max_stale, Duration::from_secs(60)),
            },
            max_entries: if cfg.max_entries == 0 {
                512
            } else {
                cfg.max_entries
            },
            clock,
            state: Mutex::default(),
            refreshes: AtomicU64::new(0),
        }))
    }

    #[cfg(test)]
    pub fn background_refreshes(&self) -> u64 {
        self.0.refreshes.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.0.state.lock().unwrap().items.len()
    }

    #[cfg(test)]
    pub fn cached(&self, req: &Request) -> Option<Arc<Response>> {
        let key = req.cache_key()?;
        Some(self.0.state.lock().unwrap().items.get(&key)?.val.clone())
    }
}

impl Client for CachingClient {
    fn get(&self, req: Request) -> BoxFuture<'_, Reply> {
        Box::pin(self.0.clone().get(req))
    }

    fn artifact(&self, name: ArtifactName) -> BoxFuture<'_, Result<Download, FleetError>> {
        self.0.next.artifact(name)
    }
}

impl Inner {
    fn policy(&self, endpoint: &str) -> Policy {
        match endpoint {
            // Metadata changes rarely, and a past event never changes.
            "meta" | "event_by_id" => Policy {
                ttl: SLOW_TIER * self.live.ttl,
                max_stale: SLOW_TIER * self.live.max_stale,
            },
            _ => self.live,
        }
    }

    async fn get(self: Arc<Self>, req: Request) -> Reply {
        let (Some(endpoint), Some(key)) = (req.endpoint(), req.cache_key()) else {
            // A health probe must show the upstream as it is now.
            return self.next.get(req).await;
        };
        let pol = self.policy(endpoint);
        let now = (self.clock)();
        let cached = {
            let st = self.state.lock().unwrap();
            st.items.get(&key).map(|e| (e.val.clone(), e.fetched_at))
        };
        let Some((val, fetched_at)) = cached else {
            return self.flight(key, req).await;
        };
        let age = now.saturating_duration_since(fetched_at);
        if age < pol.ttl {
            return Ok(val);
        }
        if age < pol.max_stale {
            if self.state.lock().unwrap().refreshing.insert(key.clone()) {
                self.refreshes.fetch_add(1, Ordering::Relaxed);
                let inner = self.clone();
                tokio::spawn(async move {
                    let _ = inner.flight(key.clone(), req).await;
                    inner.state.lock().unwrap().refreshing.remove(&key);
                });
            }
            return Ok(val);
        }
        match self.flight(key, req).await {
            // The dashboard shows old data rather than none while the server rebuilds; any
            // other error, such as a revoked token, must show.
            Err(e) if e.is_retryable() => Ok(val),
            other => other,
        }
    }

    /// One upstream call per key at a time; every caller for the key gets its answer. The call
    /// runs as its own task, so it finishes and is cached even when every caller has gone.
    async fn flight(self: &Arc<Self>, key: String, req: Request) -> Reply {
        let mut rx = {
            let mut st = self.state.lock().unwrap();
            match st.flights.get(&key) {
                Some(rx) => rx.clone(),
                None => {
                    let (tx, rx) = watch::channel(None);
                    st.flights.insert(key.clone(), rx.clone());
                    let inner = self.clone();
                    tokio::spawn(async move {
                        // Ends the flight even if the fetch panics; waiters then see `tx` gone.
                        let landing = Landing(inner.clone(), key.clone());
                        let reply = inner.next.get(req).await;
                        if let Ok(val) = &reply {
                            let now = (inner.clock)();
                            let mut st = inner.state.lock().unwrap();
                            st.store(key, val.clone(), now, inner.max_entries);
                        }
                        drop(landing);
                        tx.send_replace(Some(reply));
                    });
                    rx
                }
            }
        };
        let reply = rx.wait_for(Option::is_some).await.map(|r| r.clone());
        match reply {
            Ok(reply) => reply.expect("waited for an answer"),
            Err(_) => Err(FleetError::Transport("upstream call ended".into())),
        }
    }
}

/// Removes its key's flight when dropped.
struct Landing(Arc<Inner>, String);

impl Drop for Landing {
    fn drop(&mut self) {
        let mut st = self.0.state.lock().unwrap_or_else(|e| e.into_inner());
        st.flights.remove(&self.1);
    }
}

impl State {
    /// Stores `val` as the newest fetch, then drops the oldest fetches beyond `max`.
    fn store(&mut self, key: String, val: Arc<Response>, now: Instant, max: usize) {
        let seq = self.next_seq;
        self.next_seq += 1;
        if let Some(old) = self.items.insert(
            key.clone(),
            Entry {
                val,
                fetched_at: now,
                seq,
            },
        ) {
            self.order.remove(&old.seq);
        }
        self.order.insert(seq, key);
        while self.items.len() > max {
            let Some((_, oldest)) = self.order.pop_first() else {
                break;
            };
            self.items.remove(&oldest);
        }
    }
}

#[cfg(test)]
mod tests;
