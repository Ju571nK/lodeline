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
//! Cursor identity. The relay tags the request's `params.cursor` with the
//! process's keyed [`CursorHasher`] (`RequestStarted::list_cursor`; the raw value
//! is never kept, logged or compared) and this sink tags a page's `nextCursor`
//! with a clone of the same hasher. The tag goes to the engine as the page's
//! `request_cursor`, and the engine accepts a continuation only if it equals the
//! `nextCursor` tag of the previous page of that chain. A stale or invented
//! cursor and a retried page therefore end the chain as `cursor_invalid`, and so
//! does an interleaved second listing of the same principal whose cursor differs.
//! The check compares cursor STRINGS: if two interleaved listings are handed
//! identical cursor strings by the upstream, either's continuation is accepted
//! into the one chain the engine holds (one chain per principal and scope, never a
//! second one), so no snapshot can mix two chains' pages; the worst case is a
//! listing the upstream itself made ambiguous, which is harmless.
//!
//! The sink keeps one fact per `tools/list` call between its start and its
//! completion: the request's cursor tag. If that fact is missing at completion
//! (the table was cleared at [`MAX_INFLIGHT`], or the call was never started) the
//! page cannot be placed in a chain, so it fails closed: the chain in progress, if
//! any, ends as `page_error`, and nothing starts or completes a chain.
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
pub const MAX_INFLIGHT: usize = 4096;

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
    /// The relay's state for a page was lost: end the chain as `reason`.
    Abort(Box<ListingKey>, IncompleteReason),
    EndAll,
    Stop,
}

#[derive(Default)]
struct State {
    /// `seq -> the tag of the request's cursor` (`None`: no cursor), for the
    /// `tools/list` calls in flight.
    inflight: HashMap<u64, Option<CursorTag>>,
    sessions: HashMap<String, u64>,
    next_session: u64,
}

/// The [`ObservationSink`] feeding the inventory engine.
pub struct InventorySink {
    proxy_id: String,
    hasher: CursorHasher,
    scopes: RouteScopes,
    state: Mutex<State>,
    tx: SyncSender<Msg>,
    dropped: AtomicU64,
    #[cfg(any(test, feature = "test-util"))]
    paused: Arc<std::sync::atomic::AtomicBool>,
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
        #[cfg(any(test, feature = "test-util"))]
        let paused = Arc::new(std::sync::atomic::AtomicBool::new(false));
        #[cfg(any(test, feature = "test-util"))]
        let worker_paused = paused.clone();
        let join = std::thread::Builder::new()
            .name("sigil-inventory".into())
            .spawn(move || {
                worker(
                    engine,
                    rx,
                    #[cfg(any(test, feature = "test-util"))]
                    worker_paused,
                )
            })?;
        let sink = Arc::new(InventorySink {
            proxy_id: proxy_id.to_string(),
            hasher,
            scopes,
            state: Mutex::new(State::default()),
            tx: tx.clone(),
            dropped: AtomicU64::new(0),
            #[cfg(any(test, feature = "test-util"))]
            paused,
        });
        Ok((
            sink,
            InventoryHandle {
                tx,
                join: Some(join),
            },
        ))
    }

    /// Test knob: stop the worker from taking messages, so the queue can fill.
    #[cfg(any(test, feature = "test-util"))]
    pub fn pause_worker_for_test(&self, on: bool) {
        self.paused.store(on, Ordering::SeqCst);
    }

    /// Pages dropped because the engine could not keep up.
    pub fn dropped_pages(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// The session behind `principal` ended: close its chains as
    /// `session_ended` (T-12b2 calls this with the real session).
    pub fn end_session(&self, principal_id: &str) {
        let session = { self.lock().sessions.remove(principal_id) };
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
        let request_cursor = self.lock().inflight.remove(&c.call.seq);
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
        drop(st);
        // Fail closed: without the request's cursor fact the page has no place in
        // any chain (see the module doc).
        let Some(request_cursor) = request_cursor else {
            self.send(Msg::Abort(Box::new(key), IncompleteReason::PageError));
            return;
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
                // A call that never completes cannot pile up forever. A cleared
                // fact makes its completion fail closed (`page_error`), it never
                // reads as "no cursor".
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

fn worker(
    mut engine: InventoryEngine,
    rx: Receiver<Msg>,
    #[cfg(any(test, feature = "test-util"))] paused: Arc<std::sync::atomic::AtomicBool>,
) {
    while let Ok(m) = rx.recv() {
        #[cfg(any(test, feature = "test-util"))]
        while paused.load(Ordering::SeqCst) {
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        match m {
            Msg::Page(p) => {
                let (key, page) = *p;
                if engine.observe_page(&key, page).is_err() {
                    // Fixed text only: the error carries no content.
                    tracing::error!("inventory engine could not record a page");
                }
            }
            Msg::Abort(key, reason) => {
                if engine.abort_chain(&key, reason).is_err() {
                    tracing::error!("inventory engine could not record an aborted page");
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
