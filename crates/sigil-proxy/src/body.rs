//! Metered response body (PX-013, D-04). Wraps the upstream body and enforces,
//! while the bytes pass through UNCHANGED:
//! - the JSON response / SSE event / per-call byte limits,
//! - the idle (between frames) and whole-call timeouts,
//!
//! and holds the admission permits until the body ends or is dropped.
//!
//! A violation ends the stream with an error. hyper then aborts the downstream
//! connection, which the client sees as a truncated response (outcome unknown;
//! the call already reached upstream).

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http_body::{Body, Frame};
use hyper::body::Incoming;
use tokio::sync::OwnedSemaphorePermit;
use tokio::time::{Instant, Sleep};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyLimit {
    ResponseTooLarge,
    SseEventTooLarge,
    CallTooLarge,
    IdleTimeout,
    CallTimeout,
}

impl std::fmt::Display for BodyLimit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            BodyLimit::ResponseTooLarge => "response exceeds the JSON response limit",
            BodyLimit::SseEventTooLarge => "SSE event exceeds the event limit",
            BodyLimit::CallTooLarge => "call exceeds the accumulated response limit",
            BodyLimit::IdleTimeout => "upstream response idle timeout",
            BodyLimit::CallTimeout => "call timeout",
        })
    }
}

impl std::error::Error for BodyLimit {}

/// Tracks the size of the current SSE event across chunk boundaries. An event
/// ends at an empty line; line terminators are `\n`, `\r\n` or `\r`.
#[derive(Debug, Default)]
pub struct SseEventTracker {
    event_bytes: u64,
    line_len: u64,
    after_cr: bool,
}

impl SseEventTracker {
    /// Feed bytes. Returns `Err` when one event grows beyond `max`.
    pub fn feed(&mut self, data: &[u8], max: u64) -> Result<(), BodyLimit> {
        for &b in data {
            self.event_bytes += 1;
            if self.event_bytes > max {
                return Err(BodyLimit::SseEventTooLarge);
            }
            if self.after_cr && b == b'\n' {
                // second half of CRLF: part of the same terminator. If the CR
                // just closed an event, this LF belongs to no event.
                self.after_cr = false;
                if self.event_bytes == 1 {
                    self.event_bytes = 0;
                }
                continue;
            }
            if b == b'\r' || b == b'\n' {
                self.after_cr = b == b'\r';
                if self.line_len == 0 {
                    self.event_bytes = 0; // blank line: event complete
                }
                self.line_len = 0;
            } else {
                self.after_cr = false;
                self.line_len += 1;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyMode {
    /// Plain response: the JSON response limit applies.
    Json,
    /// Observable SSE: the per-event limit applies.
    Sse,
    /// A content-encoded stream: the bytes are opaque, so neither the JSON
    /// nor the event limit can be applied. Only the call cap and timeouts.
    // OPEN: T-12b must treat encoded bodies as unobservable and must never
    // decode them without a size cap (decompression bomb).
    Opaque,
}

pub struct Limits {
    pub mode: BodyMode,
    pub max_json_bytes: u64,
    pub max_sse_event_bytes: u64,
    pub max_call_bytes: u64,
    pub idle: Duration,
    pub call_deadline: Instant,
}

/// Admission permits (total, route, principal). Dropped with the body.
pub struct Permits(#[allow(dead_code)] pub Vec<OwnedSemaphorePermit>);

pub struct MeteredBody {
    inner: Incoming,
    lim: Limits,
    total: u64,
    sse: SseEventTracker,
    idle: Pin<Box<Sleep>>,
    deadline: Pin<Box<Sleep>>,
    _permits: Permits,
}

impl MeteredBody {
    pub fn new(inner: Incoming, lim: Limits, permits: Permits) -> Self {
        let idle = Box::pin(tokio::time::sleep(lim.idle));
        let deadline = Box::pin(tokio::time::sleep_until(lim.call_deadline));
        MeteredBody {
            inner,
            lim,
            total: 0,
            sse: SseEventTracker::default(),
            idle,
            deadline,
            _permits: permits,
        }
    }
}

impl Body for MeteredBody {
    type Data = Bytes;
    type Error = Box<dyn std::error::Error + Send + Sync>;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        let this = &mut *self;
        if this.deadline.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Some(Err(BodyLimit::CallTimeout.into())));
        }
        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Pending => {
                if this.idle.as_mut().poll(cx).is_ready() {
                    return Poll::Ready(Some(Err(BodyLimit::IdleTimeout.into())));
                }
                Poll::Pending
            }
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(Box::new(e)))),
            Poll::Ready(Some(Ok(frame))) => {
                this.idle.as_mut().reset(Instant::now() + this.lim.idle);
                if let Some(d) = frame.data_ref() {
                    this.total += d.len() as u64;
                    if this.total > this.lim.max_call_bytes {
                        return Poll::Ready(Some(Err(BodyLimit::CallTooLarge.into())));
                    }
                    match this.lim.mode {
                        BodyMode::Sse => {
                            if let Err(e) = this.sse.feed(d, this.lim.max_sse_event_bytes) {
                                return Poll::Ready(Some(Err(e.into())));
                            }
                        }
                        BodyMode::Json if this.total > this.lim.max_json_bytes => {
                            return Poll::Ready(Some(Err(BodyLimit::ResponseTooLarge.into())));
                        }
                        BodyMode::Json | BodyMode::Opaque => {}
                    }
                }
                Poll::Ready(Some(Ok(frame)))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn feed_all(chunks: &[&[u8]], max: u64) -> Result<(), BodyLimit> {
        let mut t = SseEventTracker::default();
        for c in chunks {
            t.feed(c, max)?;
        }
        Ok(())
    }

    /// AC-07: the event limit is per event, not per stream, across any
    /// terminator style and any chunk boundary.
    #[test]
    fn sse_tracker_counts_per_event() {
        // many small events never trip a small limit
        let ev = b"data: x\n\n";
        let many: Vec<&[u8]> = (0..50).map(|_| &ev[..]).collect();
        assert_eq!(feed_all(&many, 9), Ok(()));
        assert_eq!(feed_all(&many, 8), Err(BodyLimit::SseEventTooLarge));
        // CRLF and CR terminators end events too
        let crlf = b"data: x\r\n\r\n";
        let many: Vec<&[u8]> = (0..50).map(|_| &crlf[..]).collect();
        assert_eq!(feed_all(&many, 11), Ok(()));
        let cr = b"data: x\r\r";
        let many: Vec<&[u8]> = (0..50).map(|_| &cr[..]).collect();
        assert_eq!(feed_all(&many, 9), Ok(()));
        // an event split across chunks at every position is counted whole
        let one = b"data: aaaa\ndata: bbbb\n\n";
        for i in 0..one.len() {
            assert_eq!(feed_all(&[&one[..i], &one[i..]], one.len() as u64), Ok(()));
            assert!(feed_all(&[&one[..i], &one[i..]], one.len() as u64 - 1).is_err());
        }
        // an event with no blank line grows without bound
        let big = vec![b'a'; 100];
        assert!(feed_all(&[&big], 99).is_err());
    }
}
