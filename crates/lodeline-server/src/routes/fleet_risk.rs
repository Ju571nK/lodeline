//! GET /v1/fleet/risk: 1-row-per-host sorted by bucket, then score, then host id.

use crate::app::SharedState;
use crate::fleet_index::{HostSummary, RiskEntry};
use axum::extract::{Query, State};
use axum::response::IntoResponse;
use axum::Json;
use lodeline_core::event::AiGuardBucket;
use lodeline_fleet_api::{RiskPage, RiskQuery, RiskRow};

fn clamp_limit(req: Option<u32>) -> usize {
    req.unwrap_or(100).clamp(1, 1000) as usize
}

/// Whether `entry` beats `held` for a host's top tool: a higher bucket, then a higher score.
/// Readings that tie on both keep the tool visited first, which is `AiTool` order.
fn outranks(entry: &RiskEntry, held: &RiskEntry) -> bool {
    entry
        .rank()
        .cmp(&held.rank())
        .then_with(|| entry.score.total_cmp(&held.score))
        .is_gt()
}

pub async fn get_fleet_risk(
    State(state): State<SharedState>,
    Query(q): Query<RiskQuery>,
) -> impl IntoResponse {
    let limit = clamp_limit(q.limit);
    let min = q
        .min_bucket
        .as_deref()
        .map_or(1, |name| AiGuardBucket::from_name(name).rank(0.0));
    let tool_filter: Option<Vec<String>> = q
        .tool
        .as_ref()
        .map(|v| v.split(',').map(|s| s.trim().to_string()).collect());
    let selected = |tool: &lodeline_core::event::AiTool| {
        tool_filter
            .as_ref()
            .is_none_or(|tf| tf.contains(&super::wire_str(tool)))
    };
    let mut not_assessed: u64 = 0;

    // Collect (host, top_tool, top_entry) for each host that has any risk meeting filters.
    let mut rows: Vec<(HostSummary, lodeline_core::event::AiTool, RiskEntry)> = Vec::new();
    for h in state.fleet_index.snapshot_all() {
        let failing = h
            .risk_sources
            .iter()
            .any(|(key, (_, source))| source.failure().is_some() && selected(&key.0));
        if failing && !h.current_risk.keys().any(selected) {
            not_assessed += 1;
        }
        let mut top: Option<(lodeline_core::event::AiTool, RiskEntry)> = None;
        for (tool, entry) in &h.current_risk {
            if !selected(tool) {
                continue;
            }
            if entry.rank() < min {
                continue;
            }
            let pick = top
                .as_ref()
                .map(|(_, e)| outranks(entry, e))
                .unwrap_or(true);
            if pick {
                top = Some((tool.clone(), entry.clone()));
            }
        }
        if let Some((tool, entry)) = top {
            rows.push((h, tool, entry));
        }
    }
    rows.sort_by(|a, b| {
        b.2.rank()
            .cmp(&a.2.rank())
            .then_with(|| b.2.score.total_cmp(&a.2.score))
            .then_with(|| a.0.host_id.cmp(&b.0.host_id))
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
            unassessed_since: h.unassessed_since(tool).map(super::rfc3339),
        })
        .collect();
    let next_cursor = if end < rows.len() {
        rows.get(end - 1).map(|(h, _, _)| h.host_id.clone())
    } else {
        None
    };
    Json(RiskPage {
        next_cursor,
        not_assessed_host_count: Some(not_assessed),
        rows: page,
    })
}
