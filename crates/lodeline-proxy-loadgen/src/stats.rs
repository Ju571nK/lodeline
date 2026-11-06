//! Latency histograms and the numbers a report carries.

use std::collections::BTreeMap;
use std::time::Duration;

use hdrhistogram::Histogram;
use serde::Serialize;

use crate::outcome::Outcome;

/// Microseconds, 3 significant digits (0.1% resolution), up to one hour.
fn histogram() -> Histogram<u64> {
    Histogram::new_with_bounds(1, 3_600_000_000, 3).expect("static bounds are valid")
}

/// Everything one run records. Calls whose scheduled time falls in the warm-up
/// only count outcomes, so a report can still check every call that was sent.
pub struct Recorder {
    /// From the call becoming ready to send (open loop: its task runs, before
    /// it waits for a lane slot; closed loop: the send) to the complete reply,
    /// successful calls only.
    pub latency: Histogram<u64>,
    /// Open loop: how late each measured call's task ran after its due time.
    pub send_lag: Histogram<u64>,
    pub outcomes: BTreeMap<String, u64>,
    pub warmup_outcomes: BTreeMap<String, u64>,
}

impl Default for Recorder {
    fn default() -> Self {
        Recorder {
            latency: histogram(),
            send_lag: histogram(),
            outcomes: BTreeMap::new(),
            warmup_outcomes: BTreeMap::new(),
        }
    }
}

fn micros(d: Duration) -> u64 {
    u64::try_from(d.as_micros()).unwrap_or(u64::MAX).max(1)
}

impl Recorder {
    pub fn record(&mut self, measured: bool, latency: Duration, lag: Duration, outcome: &Outcome) {
        let map = if measured {
            &mut self.outcomes
        } else {
            &mut self.warmup_outcomes
        };
        *map.entry(outcome.key()).or_default() += 1;
        if measured {
            self.send_lag.saturating_record(micros(lag));
            if *outcome == Outcome::Ok {
                self.latency.saturating_record(micros(latency));
            }
        }
    }

    pub fn ok(&self) -> u64 {
        self.outcomes.get("ok").copied().unwrap_or(0)
    }

    pub fn all_ok(&self) -> u64 {
        self.ok() + self.warmup_outcomes.get("ok").copied().unwrap_or(0)
    }
}

/// The outcomes of `map` other than `ok`.
pub fn non_ok(map: &BTreeMap<String, u64>) -> BTreeMap<String, u64> {
    map.iter()
        .filter(|(k, _)| k.as_str() != "ok")
        .map(|(k, v)| (k.clone(), *v))
        .collect()
}

/// Milliseconds.
#[derive(Debug, Clone, Copy, Serialize, PartialEq)]
pub struct Quantiles {
    pub count: u64,
    pub min: f64,
    pub mean: f64,
    pub p50: f64,
    pub p90: f64,
    pub p95: f64,
    pub p99: f64,
    pub p999: f64,
    pub max: f64,
}

/// Within the histogram's 0.1% resolution of `want`.
#[cfg(test)]
pub(crate) fn near(got: f64, want: f64) -> bool {
    (got - want).abs() <= want.abs() * 0.001 + 0.001
}

fn ms(us: u64) -> f64 {
    us as f64 / 1000.0
}

/// Each value is the upper end of its histogram bucket, at most 0.1% high.
pub fn quantiles(h: &Histogram<u64>) -> Quantiles {
    let q = |p: f64| ms(h.value_at_quantile(p));
    Quantiles {
        count: h.len(),
        min: if h.is_empty() { 0.0 } else { ms(h.min()) },
        mean: (h.mean()).round() / 1000.0,
        p50: q(0.50),
        p90: q(0.90),
        p95: q(0.95),
        p99: q(0.99),
        p999: q(0.999),
        max: ms(h.max()),
    }
}

/// Proxied minus direct, per quantile, in milliseconds. This compares two
/// distributions; it is not the added time of any single call (validation.md 5).
#[derive(Debug, Clone, Copy, Serialize, PartialEq)]
pub struct Added {
    pub p50: f64,
    pub p95: f64,
    pub p99: f64,
    pub max: f64,
}

pub fn added(direct: &Quantiles, proxied: &Quantiles) -> Added {
    let d = |a: f64, b: f64| ((b - a) * 1000.0).round() / 1000.0;
    Added {
        p50: d(direct.p50, proxied.p50),
        p95: d(direct.p95, proxied.p95),
        p99: d(direct.p99, proxied.p99),
        max: d(direct.max, proxied.max),
    }
}

/// Median and range of per-round values.
#[derive(Debug, Clone, Copy, Serialize, PartialEq)]
pub struct Spread {
    pub median: f64,
    pub min: f64,
    pub max: f64,
}

pub fn spread(values: &[f64]) -> Option<Spread> {
    let mut v: Vec<f64> = values.to_vec();
    v.sort_by(f64::total_cmp);
    let n = v.len();
    let median = match n {
        0 => return None,
        _ if n % 2 == 1 => v[n / 2],
        _ => (v[n / 2 - 1] + v[n / 2]) / 2.0,
    };
    Some(Spread {
        median,
        min: v[0],
        max: v[n - 1],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quantiles_of_a_known_distribution() {
        let mut r = Recorder::default();
        // 1..=1000 ms, each once.
        for i in 1..=1000u64 {
            r.record(true, Duration::from_millis(i), Duration::ZERO, &Outcome::Ok);
        }
        let q = quantiles(&r.latency);
        assert_eq!(q.count, 1000);
        assert!(near(q.p50, 500.0), "{q:?}");
        assert!(near(q.p90, 900.0), "{q:?}");
        assert!(near(q.p95, 950.0), "{q:?}");
        assert!(near(q.p99, 990.0), "{q:?}");
        assert!(near(q.p999, 999.0), "{q:?}");
        assert!(near(q.max, 1000.0), "{q:?}");
        assert!(near(q.min, 1.0), "{q:?}");
        assert!(near(q.mean, 500.5), "{q:?}");
    }

    #[test]
    fn sub_millisecond_values_keep_microseconds() {
        let mut r = Recorder::default();
        for _ in 0..99 {
            r.record(
                true,
                Duration::from_micros(250),
                Duration::ZERO,
                &Outcome::Ok,
            );
        }
        r.record(
            true,
            Duration::from_micros(2_500),
            Duration::ZERO,
            &Outcome::Ok,
        );
        let q = quantiles(&r.latency);
        assert!(
            near(q.p50, 0.25) && near(q.p99, 0.25) && near(q.max, 2.5),
            "{q:?}"
        );
    }

    #[test]
    fn errors_and_warmup_stay_out_of_the_latency() {
        let mut r = Recorder::default();
        let busy = Outcome::Http {
            status: 429,
            code: Some("too_many_requests".into()),
        };
        r.record(true, Duration::from_millis(1), Duration::ZERO, &busy);
        r.record(
            false,
            Duration::from_millis(900),
            Duration::ZERO,
            &Outcome::Ok,
        );
        r.record(
            true,
            Duration::from_millis(5),
            Duration::from_micros(30),
            &Outcome::Ok,
        );
        assert_eq!(r.latency.len(), 1);
        assert!(near(quantiles(&r.latency).p50, 5.0));
        assert_eq!(r.ok(), 1);
        assert_eq!(r.all_ok(), 2);
        assert_eq!(
            non_ok(&r.outcomes),
            BTreeMap::from([("http_429_too_many_requests".to_string(), 1)])
        );
        assert_eq!(r.send_lag.len(), 2, "lag counts every measured send");
    }

    #[test]
    fn added_is_proxied_minus_direct_per_quantile() {
        let q = |p50, p95, p99, max| Quantiles {
            count: 1,
            min: 0.0,
            mean: 0.0,
            p50,
            p90: 0.0,
            p95,
            p99,
            p999: 0.0,
            max,
        };
        let a = added(&q(1.0, 2.0, 3.0, 9.0), &q(3.5, 4.25, 2.0, 20.0));
        assert_eq!(
            a,
            Added {
                p50: 2.5,
                p95: 2.25,
                p99: -1.0,
                max: 11.0
            }
        );
    }

    #[test]
    fn spread_is_median_and_range() {
        assert_eq!(spread(&[]), None);
        assert_eq!(
            spread(&[3.0, 1.0, 2.0]),
            Some(Spread {
                median: 2.0,
                min: 1.0,
                max: 3.0
            })
        );
        assert_eq!(spread(&[4.0, 1.0, 2.0, 3.0]).unwrap().median, 2.5);
    }
}
