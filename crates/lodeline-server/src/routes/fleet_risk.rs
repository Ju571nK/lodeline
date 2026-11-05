//! GET /v1/fleet/risk — 1-row-per-host sorted by max bucket descending.

use crate::app::SharedState;
use crate::fleet_index::HostSummary;
use axum::extract::{Query, State};
use axum::response::IntoResponse;
use axum::Json;
use lodeline_core::event::AiGuardBucket;
use lodeline_fleet_api::{RiskQuery, RiskRow, RowsPage};

fn clamp_limit(req: Option<u32>) -> usize {
    req.unwrap_or(100).clamp(1, 1000) as usize
}

fn min_bucket(s: &Option<String>) -> AiGuardBucket {
    match s.as_deref() {
        Some("medium") => AiGuardBucket::Medium,
        Some("high") => AiGuardBucket::High,
        Some("critical") => AiGuardBucket::Critical,
        _ => AiGuardBucket::Low,
    }
}

fn bucket_rank(b: AiGuardBucket) -> u8 {
    use AiGuardBucket::*;
    match b {
        Low => 1,
        Medium => 2,
        High => 3,
        Critical => 4,
    }
}

pub async fn get_fleet_risk(
    State(state): State<SharedState>,
    Query(q): Query<RiskQuery>,
) -> impl IntoResponse {
    let limit = clamp_limit(q.limit);
    let min = bucket_rank(min_bucket(&q.min_bucket));
    let tool_filter: Option<Vec<String>> = q
        .tool
        .as_ref()
        .map(|v| v.split(',').map(|s| s.trim().to_string()).collect());

    // Collect (host, top_tool, top_entry) for each host that has any risk meeting filters.
    let mut rows: Vec<(
        HostSummary,
        lodeline_core::event::AiTool,
        crate::fleet_index::RiskEntry,
    )> = Vec::new();
    for h in state.fleet_index.snapshot_all() {
        let mut top: Option<(lodeline_core::event::AiTool, crate::fleet_index::RiskEntry)> = None;
        for (tool, entry) in &h.current_risk {
            if let Some(tf) = &tool_filter {
                let tstr = super::wire_str(tool);
                if !tf.iter().any(|t| t == &tstr) {
                    continue;
                }
            }
            if bucket_rank(entry.bucket) < min {
                continue;
            }
            let pick = top
                .as_ref()
                .map(|(_, e)| bucket_rank(entry.bucket) > bucket_rank(e.bucket))
                .unwrap_or(true);
            if pick {
                top = Some((*tool, entry.clone()));
            }
        }
        if let Some((tool, entry)) = top {
            rows.push((h, tool, entry));
        }
    }
    rows.sort_by(|a, b| {
        bucket_rank(b.2.bucket)
            .cmp(&bucket_rank(a.2.bucket))
            .then_with(|| {
                b.2.score
                    .partial_cmp(&a.2.score)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
    });

    let start = match &q.cursor {
        None => 0,
        Some(c) => rows
            .iter()
            .position(|(h, _, _)| &h.host_id == c)
            .map(|i| i + 1)
            .unwrap_or(rows.len()),
    };
    let end = (start + limit).min(rows.len());
    let page: Vec<RiskRow> = rows[start..end]
        .iter()
        .map(|(h, tool, entry)| RiskRow {
            host_id: h.host_id.clone(),
            hostname: h.hostname().map(str::to_string),
            score: f64::from(entry.score),
            bucket: super::wire_str(&entry.bucket),
            top_tool: super::wire_str(tool),
            reasons_count: entry.reasons.len() as u64,
            assessed_ts: super::rfc3339(entry.assessed_ts),
            open_alert_count_24h: h.counts_24h.sum_alerts(),
            source: Some(super::risk_source(entry)),
        })
        .collect();
    let next_cursor = if end < rows.len() {
        rows.get(end - 1).map(|(h, _, _)| h.host_id.clone())
    } else {
        None
    };
    Json(RowsPage {
        next_cursor,
        rows: page,
    })
}
