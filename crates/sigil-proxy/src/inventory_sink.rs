//! The producer side of the relay's observation seam for the inventory (T-13c,
//! PX-005/006).
//!
//! [`InventorySink`] implements [`ObservationSink`]: it adapts the relay's
//! `tools/list` observations ([`ToolListCapture`]) into the plain
//! [`PageInput`]s of the [`InventoryEngine`] and hands them to ONE dedicated
//! worker thread that owns the engine (its work is blocking SQLite). The relay
//! never waits for the engine: observations go through a bounded queue and a full
//! queue DROPS the page. A dropped page can only make a listing incomplete: the
//! next request's cursor then no longer matches what the engine expects, so the
//! chain ends as `cursor_invalid`, and a chain whose last page was dropped ends
//! as `session_ended`. A drop never completes a listing falsely.
//!
//! Mapping of the relay's page classes to the engine's `incomplete_reason`
//! (`inventory.rs` `PageInput::Failed`):
//!
//! | relay | engine |
//! |---|---|
//! | `PageUnavailable::NoSuccess`, `Unobservable`, `Unparseable` | `page_error` |
//! | `PageUnavailable::TooLarge` | `size_limit_exceeded` |
//! | `PageUnavailable::TooManyTools` | `tool_limit_exceeded` |
//! | `PageUnavailable::CursorInvalid` | `cursor_invalid` |
//! | `tools/list` call with no capture, upstream 401/403 | `access_denied` |
//! | `tools/list` call with no capture, anything else | `page_error` |
//!
//! Cursor identity. The relay keeps only whether the request carried a cursor
//! (never the value, see `RequestStarted::list_cursor`). The adapter therefore
//! treats a request that carries one as the continuation the chain expects (the
//! tag of the previous page's `nextCursor`), and a request without one as a chain
//! start. A client that sends a cursor other than the one it was handed is not
//! detected by this adapter. // OPEN: carry a cursor tag from the relay.
//!
//! Sessions. The relay has no session id yet (T-12b2), so the principal of the
//! call stands in for it: one listing chain per (principal, scope). A new chain
//! start (no cursor) ends an unfinished one as `session_ended`; so does
//! [`InventorySink::end_session`] (T-12b2 calls it with the real session) and
//! [`InventoryHandle::shutdown`] for every chain still open.
//!
//! Nothing here logs or stores a tool name, a definition, a cursor or a
//! credential; `Debug` of every type prints no content.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, RwLock};
use std::thread::JoinHandle;

use sigil_proxy_api::registry::IncompleteReason;

use crate::inventory::{
    CursorHasher, CursorTag, InventoryEngine, ListingKey, PageInput, ToolInput,
};
use crate::mcp::observation::{
    Cause, Completed, Method, Observation, ObservationSink, PageUnavailable, RequestStarted,
    SinkFuture, StartVerdict, ToolListCapture,
};
use crate::registry_key::ScopeKey;

/// Pages queued for the engine worker. Beyond it a page is dropped (counted).
pub const QUEUE_DEPTH: usize = 256;
/// `tools/list` calls remembered between their start and their completion.
const MAX_INFLIGHT: usize = 4096;
/// Chains whose expected next cursor is remembered.
const MAX_EXPECT: usize = 1024;

/// `route_id -> (upstream_id, credential_scope_id)` of the applied config. The
/// config sync fills it on every apply; the sink reads it per observation.
#[derive(Clone, Default)]
pub struct RouteScopes(Arc<RwLock<HashMap<String, (String, String)>>>);

impl std::fmt::Debug for RouteScopes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RouteScopes")
    }
}

impl RouteScopes {
    pub fn new() -> RouteScopes {
        RouteScopes::default()
    }

    /// Replace the whole map (a new applied config).
    pub fn replace(&self, routes: impl IntoIterator<Item = (String, String, String)>) {
        let map = routes.into_iter().map(|(r, u, c)| (r, (u, c))).collect();
        *self.0.write().unwrap_or_else(|p| p.into_inner()) = map;
    }

    fn get(&self, route_id: &str) -> Option<(String, String)> {
        self.0
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .get(route_id)
            .cloned()
    }
}

enum Msg {
    Page(Box<(ListingKey, PageInput)>),
    EndSession(u64),
    EndAll,
    Stop,
}

#[derive(Default)]
struct State {
    /// `seq -> request carried a cursor`, for `tools/list` calls in flight.
    inflight: HashMap<u64, bool>,
    /// The tag of the `nextCursor` last handed out per chain.
    expect: HashMap<ListingKey, CursorTag>,
    sessions: HashMap<String, u64>,
    next_session: u64,
}

/// The [`ObservationSink`] feeding the inventory engine.
pub struct InventorySink {
    proxy_id: String,
    hasher: CursorHasher,
    unknown: CursorTag,
    scopes: RouteScopes,
    state: Mutex<State>,
    tx: SyncSender<Msg>,
    dropped: AtomicU64,
}

impl std::fmt::Debug for InventorySink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InventorySink").finish_non_exhaustive()
    }
}

/// Owns the worker thread. [`InventoryHandle::shutdown`] ends every open chain
/// and waits for the queue to drain.
pub struct InventoryHandle {
    tx: SyncSender<Msg>,
    join: Option<JoinHandle<()>>,
}

impl InventorySink {
    /// Start the worker. `hasher` is the process's one [`CursorHasher`].
    pub fn start(
        engine: InventoryEngine,
        hasher: CursorHasher,
        scopes: RouteScopes,
        proxy_id: &str,
    ) -> std::io::Result<(Arc<InventorySink>, InventoryHandle)> {
        let (tx, rx) = sync_channel(QUEUE_DEPTH);
        let join = std::thread::Builder::new()
            .name("sigil-inventory".into())
            .spawn(move || worker(engine, rx))?;
        let unknown = hasher.tag("\u{0}sigil-unknown-cursor");
        let sink = Arc::new(InventorySink {
            proxy_id: proxy_id.to_string(),
            hasher,
            unknown,
            scopes,
            state: Mutex::new(State::default()),
            tx: tx.clone(),
            dropped: AtomicU64::new(0),
        });
        Ok((
            sink,
            InventoryHandle {
                tx,
                join: Some(join),
            },
        ))
    }

    /// Pages dropped because the engine could not keep up.
    pub fn dropped_pages(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// The session behind `principal` ended: close its chains as
    /// `session_ended` (T-12b2 calls this with the real session).
    pub fn end_session(&self, principal_id: &str) {
        let session = {
            let mut st = self.lock();
            let s = st.sessions.remove(principal_id);
            if let Some(s) = s {
                st.expect.retain(|k, _| k.session != s);
            }
            s
        };
        if let Some(s) = session {
            let _ = self.tx.try_send(Msg::EndSession(s));
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn send(&self, m: Msg) {
        match self.tx.try_send(m) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                tracing::warn!("inventory queue full: a tools/list page was dropped");
            }
            Err(TrySendError::Disconnected(_)) => {}
        }
    }

    fn completed(&self, c: &Completed) {
        let had_cursor = self.lock().inflight.remove(&c.call.seq).unwrap_or(false);
        let Some((upstream_id, credential_scope_id)) = self.scopes.get(&c.call.route_id) else {
            return;
        };
        let scope = ScopeKey::live(&self.proxy_id, &upstream_id, &credential_scope_id);
        let mut st = self.lock();
        let session = match st.sessions.get(&c.call.principal_id) {
            Some(s) => *s,
            None => {
                st.next_session += 1;
                let s = st.next_session;
                st.sessions.insert(c.call.principal_id.clone(), s);
                s
            }
        };
        let key = ListingKey { session, scope };
        let request_cursor = if had_cursor {
            Some(st.expect.get(&key).copied().unwrap_or(self.unknown))
        } else {
            None
        };
        let page = match &c.tool_list {
            Some(ToolListCapture::Page(p)) => PageInput::Tools {
                request_cursor,
                tools: p
                    .tools
                    .iter()
                    .map(|t| ToolInput {
                        name: t.name.as_str().to_string(),
                        definition: t.definition.to_string(),
                    })
                    .collect(),
                next_cursor: p.next_cursor.as_ref().map(|n| self.hasher.tag(n.as_str())),
            },
            Some(ToolListCapture::Unavailable(u)) => PageInput::Failed {
                request_cursor,
                reason: map_unavailable(*u),
            },
            None => PageInput::Failed {
                request_cursor,
                reason: if c.cause == Cause::UpstreamAuthRejected {
                    IncompleteReason::AccessDenied
                } else {
                    IncompleteReason::PageError
                },
            },
        };
        match &page {
            PageInput::Tools {
                next_cursor: Some(n),
                ..
            } => {
                if st.expect.len() >= MAX_EXPECT && !st.expect.contains_key(&key) {
                    // Forgetting makes later cursors `cursor_invalid`: fail closed.
                    st.expect.clear();
                }
                st.expect.insert(key.clone(), *n);
            }
            _ => {
                st.expect.remove(&key);
            }
        }
        drop(st);
        self.send(Msg::Page(Box::new((key, page))));
    }
}

fn map_unavailable(u: PageUnavailable) -> IncompleteReason {
    match u {
        PageUnavailable::NoSuccess
        | PageUnavailable::Unobservable
        | PageUnavailable::Unparseable => IncompleteReason::PageError,
        PageUnavailable::TooLarge => IncompleteReason::SizeLimitExceeded,
        PageUnavailable::TooManyTools => IncompleteReason::ToolLimitExceeded,
        PageUnavailable::CursorInvalid => IncompleteReason::CursorInvalid,
    }
}

impl ObservationSink for InventorySink {
    fn request_started<'a>(&'a self, s: &'a RequestStarted) -> SinkFuture<'a, StartVerdict> {
        if s.method == Method::ToolsList {
            let mut st = self.lock();
            if st.inflight.len() >= MAX_INFLIGHT {
                // A call that never completes cannot pile up forever. A forgotten
                // flag reads as "no cursor": the request then starts a chain.
                st.inflight.clear();
            }
            st.inflight.insert(s.call.seq, s.list_cursor);
        }
        Box::pin(std::future::ready(StartVerdict::Proceed))
    }

    fn observe(&self, o: Observation) {
        if let Observation::Completed(c) = o {
            if c.method == Method::ToolsList {
                self.completed(&c);
            }
        }
    }
}

fn worker(mut engine: InventoryEngine, rx: Receiver<Msg>) {
    while let Ok(m) = rx.recv() {
        match m {
            Msg::Page(p) => {
                let (key, page) = *p;
                if engine.observe_page(&key, page).is_err() {
                    // Fixed text only: the error carries no content.
                    tracing::error!("inventory engine could not record a page");
                }
            }
            Msg::EndSession(s) => {
                if engine.end_session(s).is_err() {
                    tracing::error!("inventory engine could not close a session");
                }
            }
            Msg::EndAll => {
                // Every session id ever used is below `u64::MAX`; the engine closes
                // the chains of one session at a time.
                let keys = engine.open_sessions();
                for s in keys {
                    if engine.end_session(s).is_err() {
                        tracing::error!("inventory engine could not close a session");
                    }
                }
            }
            Msg::Stop => return,
        }
    }
}

impl InventoryHandle {
    /// End every open chain (`session_ended`), drain the queue and stop the
    /// worker. Call after the relay stopped, so no page is still arriving.
    pub async fn shutdown(mut self) {
        let tx = self.tx.clone();
        let join = self.join.take();
        let _ = tokio::task::spawn_blocking(move || {
            let _ = tx.send(Msg::EndAll);
            let _ = tx.send(Msg::Stop);
            if let Some(j) = join {
                let _ = j.join();
            }
        })
        .await;
    }
}

impl Drop for InventoryHandle {
    fn drop(&mut self) {
        // Not shut down explicitly (a startup error): stop without waiting on a
        // tokio worker.
        if let Some(j) = self.join.take() {
            let _ = self.tx.try_send(Msg::Stop);
            drop(j);
        }
    }
}
