//! When calls are sent, and how many may be in flight.
//!
//! Open loop: call `seq` is due at `start + seq / rate`, whatever happened to
//! earlier calls; each call is its own task, so a slow call never delays the
//! next one's start (no coordinated omission). Each call waits for a permit of
//! its lane, and that wait is part of its latency: a lane is one principal, so
//! the lane caps keep every principal under the proxy's per-principal limit,
//! and a slow proxy shows up as queueing here. Latency starts when the call
//! task runs. How late that was after the due time (timer and scheduler delay
//! of the driver itself) is recorded apart as the send lag.
//!
//! Closed loop: a fixed number of workers each send the next call as soon as the
//! previous one is answered. Latency runs from the send; the result is the
//! sustainable throughput at that concurrency.

use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Serialize;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::Instant;

use crate::outcome::Outcome;
use crate::stats::Recorder;

#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Mode {
    /// `rate` calls/s, at most `cap` in flight.
    Open { rate: f64, cap: usize },
    /// `concurrency` workers back to back.
    Closed { concurrency: usize },
}

impl Mode {
    pub fn concurrency(&self) -> usize {
        match *self {
            Mode::Open { cap, .. } => cap,
            Mode::Closed { concurrency } => concurrency,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Window {
    pub warmup: Duration,
    pub measure: Duration,
}

/// When call `seq` is due, from the start of the run.
pub fn offset(seq: u64, rate: f64) -> Duration {
    Duration::from_secs_f64(seq as f64 / rate)
}

/// How many calls are due in the first `d` of a run.
pub fn calls_in(d: Duration, rate: f64) -> u64 {
    (d.as_secs_f64() * rate).ceil() as u64
}

/// `total` slots over `lanes` lanes, as even as possible.
pub fn split(total: usize, lanes: usize) -> Vec<usize> {
    (0..lanes)
        .map(|j| total / lanes + usize::from(j < total % lanes))
        .collect()
}

#[derive(Debug, Clone, Copy)]
pub struct Call {
    pub seq: u64,
    pub lane: usize,
}

/// Run the load and record every call. `lanes` is clamped to the concurrency so
/// no lane is left without a slot; `call` only sees lanes below that.
pub async fn drive<F, Fut>(mode: Mode, lanes: usize, w: Window, call: F) -> Recorder
where
    F: Fn(Call) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Outcome> + Send + 'static,
{
    let lanes = lanes.clamp(1, mode.concurrency().max(1));
    let call = Arc::new(call);
    let rec = Arc::new(Mutex::new(Recorder::default()));
    let start = Instant::now();
    let warm_end = start + w.warmup;
    let end = warm_end + w.measure;
    let mut set = JoinSet::new();
    match mode {
        Mode::Open { rate, cap } => {
            let sems: Vec<Arc<Semaphore>> = split(cap, lanes)
                .into_iter()
                .map(|n| Arc::new(Semaphore::new(n)))
                .collect();
            for seq in 0..calls_in(w.warmup + w.measure, rate) {
                let due = start + offset(seq, rate);
                tokio::time::sleep_until(due).await;
                let lane = (seq % lanes as u64) as usize;
                let (sem, call, rec) = (sems[lane].clone(), call.clone(), rec.clone());
                set.spawn(async move {
                    let ready = Instant::now();
                    let _permit = sem.acquire_owned().await.expect("never closed");
                    let out = call(Call { seq, lane }).await;
                    let done = Instant::now();
                    rec.lock()
                        .unwrap()
                        .record(due >= warm_end, done - ready, ready - due, &out);
                });
                while let Some(r) = set.try_join_next() {
                    r.expect("call task");
                }
            }
        }
        Mode::Closed { concurrency } => {
            let next = Arc::new(AtomicU64::new(0));
            for (lane, workers) in split(concurrency, lanes).into_iter().enumerate() {
                for _ in 0..workers {
                    let (next, call, rec) = (next.clone(), call.clone(), rec.clone());
                    set.spawn(async move {
                        loop {
                            let sent = Instant::now();
                            if sent >= end {
                                return;
                            }
                            let seq = next.fetch_add(1, Ordering::Relaxed);
                            let out = call(Call { seq, lane }).await;
                            let done = Instant::now();
                            rec.lock().unwrap().record(
                                sent >= warm_end,
                                done - sent,
                                Duration::ZERO,
                                &out,
                            );
                        }
                    });
                }
            }
        }
    }
    while let Some(r) = set.join_next().await {
        r.expect("call task");
    }
    Arc::into_inner(rec)
        .expect("all tasks joined")
        .into_inner()
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stats::{near, quantiles};

    #[test]
    fn due_times_and_counts() {
        assert_eq!(offset(0, 100.0), Duration::ZERO);
        assert_eq!(offset(100, 100.0), Duration::from_secs(1));
        assert_eq!(offset(3, 4.0), Duration::from_millis(750));
        assert_eq!(calls_in(Duration::from_secs(300), 100.0), 30_000);
        assert_eq!(calls_in(Duration::from_millis(1001), 1000.0), 1001);
    }

    #[test]
    fn slots_split_evenly() {
        assert_eq!(split(32, 4), vec![8, 8, 8, 8]);
        assert_eq!(split(10, 4), vec![3, 3, 2, 2]);
        assert_eq!(split(1, 1), vec![1]);
        assert_eq!(split(64, 8).iter().sum::<usize>(), 64);
    }

    /// Tracks in-flight calls, overall and per lane, and when each call is sent.
    #[derive(Default)]
    struct Probe {
        now: Vec<AtomicU64>,
        max: Vec<AtomicU64>,
        sends: Mutex<Vec<(u64, Instant)>>,
    }

    impl Probe {
        fn new(lanes: usize) -> Arc<Probe> {
            Arc::new(Probe {
                now: (0..=lanes).map(|_| AtomicU64::new(0)).collect(),
                max: (0..=lanes).map(|_| AtomicU64::new(0)).collect(),
                sends: Mutex::default(),
            })
        }

        fn enter(&self, i: usize) {
            let n = self.now[i].fetch_add(1, Ordering::SeqCst) + 1;
            self.max[i].fetch_max(n, Ordering::SeqCst);
        }

        fn max(&self, i: usize) -> u64 {
            self.max[i].load(Ordering::SeqCst)
        }

        /// A call that takes `d`. Slot `lanes` of the counters is the total.
        fn call(
            self: &Arc<Self>,
            lanes: usize,
            d: Duration,
        ) -> impl Fn(Call) -> std::pin::Pin<Box<dyn Future<Output = Outcome> + Send>> + Send + Sync
        {
            let p = self.clone();
            move |c: Call| {
                let p = p.clone();
                Box::pin(async move {
                    p.sends.lock().unwrap().push((c.seq, Instant::now()));
                    p.enter(c.lane);
                    p.enter(lanes);
                    tokio::time::sleep(d).await;
                    p.now[c.lane].fetch_sub(1, Ordering::SeqCst);
                    p.now[lanes].fetch_sub(1, Ordering::SeqCst);
                    Outcome::Ok
                })
            }
        }
    }

    fn window(warmup_ms: u64, measure_ms: u64) -> Window {
        Window {
            warmup: Duration::from_millis(warmup_ms),
            measure: Duration::from_millis(measure_ms),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn open_loop_sends_on_schedule() {
        let p = Probe::new(2);
        let mode = Mode::Open {
            rate: 100.0,
            cap: 4,
        };
        let r = drive(
            mode,
            2,
            window(0, 1000),
            p.call(2, Duration::from_millis(5)),
        )
        .await;
        assert_eq!(r.ok(), 100);
        let sends = p.sends.lock().unwrap().clone();
        assert_eq!(sends.len(), 100);
        let t0 = sends.iter().find(|s| s.0 == 0).unwrap().1;
        for (seq, at) in sends {
            assert_eq!(at - t0, Duration::from_millis(10 * seq), "call {seq}");
        }
        let q = quantiles(&r.latency);
        assert!(near(q.p50, 5.0) && near(q.max, 5.0), "{q:?}");
        assert_eq!(quantiles(&r.send_lag).max, 0.001, "never late (1 us floor)");
        assert_eq!(p.max(2), 1, "5 ms calls 10 ms apart never overlap");
    }

    #[tokio::test(start_paused = true)]
    async fn the_cap_bounds_in_flight_and_the_wait_is_counted() {
        let p = Probe::new(2);
        // 100 calls due within 100 ms, 4 slots of 50 ms: 80 calls/s at most.
        let mode = Mode::Open {
            rate: 1000.0,
            cap: 4,
        };
        let r = drive(
            mode,
            2,
            window(0, 100),
            p.call(2, Duration::from_millis(50)),
        )
        .await;
        assert_eq!(r.ok(), 100);
        assert_eq!((p.max(0), p.max(1), p.max(2)), (2, 2, 4));
        let q = quantiles(&r.latency);
        // The last call is due at 99 ms and sent after 24 rounds of 50 ms.
        // Waiting for a lane slot counts: it is not driver lag.
        assert!(q.max >= 1150.0 && q.max <= 1160.0, "{q:?}");
        assert!(q.p50 > 500.0, "queueing is latency, not hidden: {q:?}");
        assert_eq!(
            quantiles(&r.send_lag).max,
            0.001,
            "every call task ran on time"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn warmup_calls_are_counted_but_not_measured() {
        let p = Probe::new(1);
        let mode = Mode::Open {
            rate: 100.0,
            cap: 8,
        };
        let r = drive(
            mode,
            1,
            window(500, 500),
            p.call(1, Duration::from_millis(1)),
        )
        .await;
        assert_eq!(r.ok(), 50);
        assert_eq!(r.all_ok(), 100);
        assert_eq!(r.latency.len(), 50);
    }

    #[tokio::test(start_paused = true)]
    async fn closed_loop_keeps_every_worker_busy() {
        let p = Probe::new(2);
        let mode = Mode::Closed { concurrency: 3 };
        let r = drive(
            mode,
            2,
            window(0, 1000),
            p.call(2, Duration::from_millis(10)),
        )
        .await;
        assert_eq!(r.ok(), 300);
        assert_eq!((p.max(0), p.max(1), p.max(2)), (2, 1, 3));
        assert!(near(quantiles(&r.latency).p99, 10.0));
    }

    #[tokio::test(start_paused = true)]
    async fn lanes_never_outnumber_slots() {
        let p = Probe::new(4);
        let mode = Mode::Open {
            rate: 100.0,
            cap: 2,
        };
        let r = drive(mode, 4, window(0, 100), p.call(4, Duration::from_millis(1))).await;
        assert_eq!(r.ok(), 10);
        assert_eq!((p.max(2), p.max(3)), (0, 0), "only lanes 0 and 1 are used");
    }
}
