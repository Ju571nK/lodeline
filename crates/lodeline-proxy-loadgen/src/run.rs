//! Rounds of direct and proxied runs, alternating, and the report they make.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::Context;
use serde::Serialize;

use crate::client::{http_client, Lane, Target};
use crate::schedule::{drive, Call, Mode, Window};
use crate::stats::{added, non_ok, quantiles, spread, Added, Quantiles, Spread};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SideName {
    Direct,
    Proxied,
}

#[derive(Debug, Clone)]
pub struct Side {
    pub name: SideName,
    /// One per lane.
    pub targets: Vec<Target>,
}

#[derive(Debug, Clone)]
pub struct Plan {
    pub mode: Mode,
    pub window: Window,
    pub rounds: usize,
    pub request_bytes: usize,
    pub reply_bytes: usize,
    pub timeout: Duration,
    /// The load server's `/_load/counters`, read before and after every run.
    pub counters_url: Option<String>,
    pub note: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RunReport {
    pub side: SideName,
    pub round: usize,
    pub lanes: usize,
    /// Every call sent, warm-up included.
    pub sent: u64,
    pub measured: u64,
    pub ok: u64,
    pub ok_per_s: f64,
    pub errors: BTreeMap<String, u64>,
    pub warmup_errors: BTreeMap<String, u64>,
    /// Successful measured calls only.
    pub latency_ms: Quantiles,
    pub send_lag_ms: Quantiles,
    /// `tools/call` the load server answered during this run, warm-up included.
    pub upstream_tools_calls: Option<u64>,
    /// Successful replies, warm-up included; equal to the upstream count
    /// when nothing was retried or lost.
    pub ok_all: u64,
}

#[derive(Debug, Serialize)]
pub struct RoundAdded {
    pub round: usize,
    pub added_ms: Added,
}

#[derive(Debug, Serialize)]
pub struct AddedSummary {
    pub p50: Spread,
    pub p95: Spread,
    pub p99: Spread,
    pub max: Spread,
}

#[derive(Debug, Serialize)]
pub struct Env {
    pub os: &'static str,
    pub arch: &'static str,
    pub cpus: usize,
    pub loadgen_version: &'static str,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub schema: &'static str,
    pub started_unix_s: u64,
    pub note: Option<String>,
    pub env: Env,
    pub mode: Mode,
    pub warmup_s: f64,
    pub measure_s: f64,
    pub rounds: usize,
    pub request_bytes: usize,
    pub reply_bytes: usize,
    pub timeout_s: f64,
    pub runs: Vec<RunReport>,
    /// Per round, proxied minus direct (only when both sides ran).
    pub added: Vec<RoundAdded>,
    pub added_summary: Option<AddedSummary>,
}

async fn upstream_calls(
    http: &reqwest::Client,
    url: &Option<String>,
) -> anyhow::Result<Option<u64>> {
    let Some(url) = url else { return Ok(None) };
    let v: serde_json::Value = http
        .get(url)
        .send()
        .await
        .with_context(|| format!("GET {url}"))?
        .json()
        .await
        .context("counters body")?;
    Ok(v["tools_calls"].as_u64())
}

async fn run_one(plan: &Plan, side: &Side, round: usize) -> anyhow::Result<RunReport> {
    let http = http_client(plan.timeout)?;
    let mut lanes = Vec::new();
    // `drive` uses at most one lane per slot.
    for t in side.targets.iter().take(plan.mode.concurrency().max(1)) {
        lanes.push(
            Lane::open(
                http.clone(),
                t.clone(),
                plan.request_bytes,
                plan.reply_bytes,
            )
            .await
            .with_context(|| format!("{:?} lane {} setup", side.name, lanes.len()))?,
        );
    }
    let lanes = Arc::new(lanes);
    let before = upstream_calls(&http, &plan.counters_url).await?;
    let tag = match side.name {
        SideName::Direct => 'd',
        SideName::Proxied => 'p',
    };
    let l = lanes.clone();
    let rec = drive(plan.mode, lanes.len(), plan.window, move |c: Call| {
        let l = l.clone();
        async move {
            l[c.lane]
                .call(c.seq, &format!("{tag}{round}-{}", c.seq))
                .await
        }
    })
    .await;
    let after = upstream_calls(&http, &plan.counters_url).await?;
    for lane in lanes.iter() {
        lane.close().await;
    }
    let measured: u64 = rec.outcomes.values().sum();
    let sent = measured + rec.warmup_outcomes.values().sum::<u64>();
    Ok(RunReport {
        side: side.name,
        round,
        lanes: lanes.len(),
        sent,
        measured,
        ok: rec.ok(),
        ok_per_s: (rec.ok() as f64 / plan.window.measure.as_secs_f64() * 10.0).round() / 10.0,
        errors: non_ok(&rec.outcomes),
        warmup_errors: non_ok(&rec.warmup_outcomes),
        latency_ms: quantiles(&rec.latency),
        send_lag_ms: quantiles(&rec.send_lag),
        upstream_tools_calls: before.zip(after).and_then(|(b, a)| a.checked_sub(b)),
        ok_all: rec.all_ok(),
    })
}

/// Run every round: each side in the order given, one after the other.
pub async fn run(plan: &Plan, sides: &[Side]) -> anyhow::Result<Report> {
    let started_unix_s = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let mut runs = Vec::new();
    for round in 1..=plan.rounds {
        for side in sides {
            let r = run_one(plan, side, round).await?;
            eprintln!("{}", run_line(&r));
            runs.push(r);
        }
    }
    let added_rounds: Vec<RoundAdded> = (1..=plan.rounds)
        .filter_map(|round| {
            let q = |n| runs.iter().find(|r| r.round == round && r.side == n);
            let (d, p) = (q(SideName::Direct)?, q(SideName::Proxied)?);
            Some(RoundAdded {
                round,
                added_ms: added(&d.latency_ms, &p.latency_ms),
            })
        })
        .collect();
    let col = |f: fn(&Added) -> f64| -> Vec<f64> {
        added_rounds.iter().map(|a| f(&a.added_ms)).collect()
    };
    let added_summary = (|| {
        Some(AddedSummary {
            p50: spread(&col(|a| a.p50))?,
            p95: spread(&col(|a| a.p95))?,
            p99: spread(&col(|a| a.p99))?,
            max: spread(&col(|a| a.max))?,
        })
    })();
    Ok(Report {
        schema: "lodeline-proxy-loadgen.report/1",
        started_unix_s,
        note: plan.note.clone(),
        env: Env {
            os: std::env::consts::OS,
            arch: std::env::consts::ARCH,
            cpus: std::thread::available_parallelism().map_or(0, |n| n.get()),
            loadgen_version: env!("CARGO_PKG_VERSION"),
        },
        mode: plan.mode,
        warmup_s: plan.window.warmup.as_secs_f64(),
        measure_s: plan.window.measure.as_secs_f64(),
        rounds: plan.rounds,
        request_bytes: plan.request_bytes,
        reply_bytes: plan.reply_bytes,
        timeout_s: plan.timeout.as_secs_f64(),
        runs,
        added: added_rounds,
        added_summary,
    })
}

fn errors_text(e: &BTreeMap<String, u64>) -> String {
    if e.is_empty() {
        return "none".into();
    }
    e.iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn run_line(r: &RunReport) -> String {
    let q = &r.latency_ms;
    let upstream = match r.upstream_tools_calls {
        Some(u) if u == r.ok_all => format!("upstream={u} (matches ok)"),
        Some(u) => format!("upstream={u} MISMATCH ok_all={}", r.ok_all),
        None => "upstream=unchecked".into(),
    };
    format!(
        "round {} {:?}: ok={}/{} {:.1}/s p50={:.3} p95={:.3} p99={:.3} max={:.3} ms lag_p99={:.3} ms errors: {} {upstream}",
        r.round,
        r.side,
        r.ok,
        r.measured,
        r.ok_per_s,
        q.p50,
        q.p95,
        q.p99,
        q.max,
        r.send_lag_ms.p99,
        errors_text(&r.errors),
    )
}

/// A short human summary of a report.
pub fn summary(rep: &Report) -> String {
    let mut s = String::new();
    let _ = writeln!(
        s,
        "mode {:?}, warmup {} s + measure {} s, {} round(s), request {} B, reply {} B, {} {} cpus={}",
        rep.mode, rep.warmup_s, rep.measure_s, rep.rounds, rep.request_bytes, rep.reply_bytes,
        rep.env.os, rep.env.arch, rep.env.cpus
    );
    for r in &rep.runs {
        let _ = writeln!(s, "{}", run_line(r));
        if !r.warmup_errors.is_empty() {
            let _ = writeln!(s, "  warm-up errors: {}", errors_text(&r.warmup_errors));
        }
    }
    for a in &rep.added {
        let m = a.added_ms;
        let _ = writeln!(
            s,
            "round {} added (proxied - direct): p50={:.3} p95={:.3} p99={:.3} max={:.3} ms",
            a.round, m.p50, m.p95, m.p99, m.max
        );
    }
    if let Some(a) = &rep.added_summary {
        let f = |x: &Spread| format!("{:.3} ({:.3} to {:.3})", x.median, x.min, x.max);
        let _ = writeln!(
            s,
            "added, median of rounds (range): p50 {} p95 {} p99 {} max {} ms",
            f(&a.p50),
            f(&a.p95),
            f(&a.p99),
            f(&a.max)
        );
    }
    let errs: u64 = rep.runs.iter().flat_map(|r| r.errors.values()).sum();
    let mism = rep
        .runs
        .iter()
        .filter(|r| r.upstream_tools_calls.is_some_and(|u| u != r.ok_all))
        .count();
    let _ = writeln!(
        s,
        "measured errors: {errs}, upstream count mismatches: {mism}"
    );
    s
}
