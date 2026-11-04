//! GET /v1/fleet/hosts — list (paged, filterable, sortable)
//! GET /v1/fleet/hosts/{host_id} — single host detail (full host_meta block)

use super::{error_response, rfc3339, wire_str};
use crate::app::SharedState;
use crate::fleet_index::{HostSummary, RiskEntry};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use lodeline_core::event::{HostMetaSnapshot, NetworkInterface};
use lodeline_fleet_api as api;
use time::OffsetDateTime;

fn clamp_limit(req: Option<u32>) -> usize {
    req.unwrap_or(100).clamp(1, 1000) as usize
}

fn classify_status(last_seen: Option<OffsetDateTime>, now: OffsetDateTime) -> &'static str {
    match last_seen {
        None => "disconnected",
        Some(ts) => {
            let age = now - ts;
            if age <= time::Duration::minutes(5) {
                "healthy"
            } else if age <= time::Duration::hours(1) {
                "stale"
            } else {
                "disconnected"
            }
        }
    }
}

fn list_filter_match(
    h: &HostSummary,
    now: OffsetDateTime,
    status_filter: &Option<Vec<String>>,
    bucket_filter: &Option<Vec<String>>,
) -> bool {
    if let Some(ss) = status_filter {
        let s = classify_status(h.last_seen_ts, now);
        if !ss.iter().any(|x| x == s) {
            return false;
        }
    }
    if let Some(bf) = bucket_filter {
        let max = max_bucket_str(h);
        match max {
            Some(b) => {
                if !bf.iter().any(|x| x == b) {
                    return false;
                }
            }
            None => {
                if !bf.iter().any(|x| x == "low") {
                    return false;
                }
            } // no risk ≈ low
        }
    }
    true
}

fn max_bucket_str(h: &HostSummary) -> Option<&'static str> {
    use lodeline_core::event::AiGuardBucket::*;
    let mut max: Option<lodeline_core::event::AiGuardBucket> = None;
    for entry in h.current_risk.values() {
        let new_rank = bucket_rank(entry.bucket);
        let cur_rank = max.map(bucket_rank).unwrap_or(0);
        if new_rank >= cur_rank {
            max = Some(entry.bucket);
        }
    }
    max.map(|b| match b {
        Low => "low",
        Medium => "medium",
        High => "high",
        Critical => "critical",
    })
}

fn bucket_rank(b: lodeline_core::event::AiGuardBucket) -> u8 {
    use lodeline_core::event::AiGuardBucket::*;
    match b {
        Low => 1,
        Medium => 2,
        High => 3,
        Critical => 4,
    }
}

fn comma_split(s: &Option<String>) -> Option<Vec<String>> {
    s.as_ref()
        .map(|v| v.split(',').map(|p| p.trim().to_string()).collect())
}

pub async fn get_fleet_hosts(
    State(state): State<SharedState>,
    Query(q): Query<api::HostsQuery>,
) -> impl IntoResponse {
    let now = OffsetDateTime::now_utc();
    let limit = clamp_limit(q.limit);
    let status_filter = comma_split(&q.status);
    let bucket_filter = comma_split(&q.bucket);
    let sort = q.sort.as_deref().unwrap_or("last_seen");

    let mut all: Vec<HostSummary> = state
        .fleet_index
        .snapshot_all()
        .into_iter()
        .filter(|h| list_filter_match(h, now, &status_filter, &bucket_filter))
        .collect();

    match sort {
        "risk" => {
            all.sort_by_key(|h| std::cmp::Reverse(bucket_rank(top_bucket(h))));
        }
        "host_id" => {
            all.sort_by_key(|h| h.host_id.clone());
        }
        _ => {
            // last_seen desc
            all.sort_by_key(|h| std::cmp::Reverse(h.last_seen_ts));
        }
    }

    // Cursor walk: skip everything up to and including the cursor's host_id.
    let start = match &q.cursor {
        None => 0usize,
        Some(c) => all
            .iter()
            .position(|h| &h.host_id == c)
            .map(|i| i + 1)
            .unwrap_or(all.len()),
    };
    let end = (start + limit).min(all.len());
    let hosts: Vec<api::HostListItem> = all[start..end]
        .iter()
        .map(|h| render_host_summary_list(h, now))
        .collect();
    let next_cursor = if end < all.len() {
        all.get(end - 1).map(|h| h.host_id.clone())
    } else {
        None
    };

    Json(api::HostsPage {
        hosts,
        next_cursor,
        total_estimated: all.len() as u64,
    })
    .into_response()
}

fn top_bucket(h: &HostSummary) -> lodeline_core::event::AiGuardBucket {
    use lodeline_core::event::AiGuardBucket::*;
    h.current_risk
        .values()
        .map(|e| e.bucket)
        .max_by_key(|b| bucket_rank(*b))
        .unwrap_or(Low)
}

fn render_risk_block(h: &HostSummary) -> Option<api::CurrentRisk> {
    if h.current_risk.is_empty() {
        return None;
    }
    let by_tool = h
        .current_risk
        .iter()
        .map(|(tool, entry)| {
            let risk = api::ToolRisk {
                assessed_ts: rfc3339(entry.assessed_ts),
                bucket: wire_str(&entry.bucket),
                score: f64::from(entry.score),
            };
            (wire_str(tool), risk)
        })
        .collect();
    let max_score = h
        .current_risk
        .values()
        .map(|e| e.score)
        .fold(0f32, f32::max);
    Some(api::CurrentRisk {
        by_tool,
        max_bucket: wire_str(&top_bucket(h)),
        max_score: f64::from(max_score),
    })
}

fn render_host_summary_list(h: &HostSummary, now: OffsetDateTime) -> api::HostListItem {
    api::HostListItem {
        agent_version: h.agent_version.clone(),
        current_risk: render_risk_block(h),
        host_id: h.host_id.clone(),
        hostname: h.hostname().map(str::to_string),
        last_seen_ts: h.last_seen_ts.map(rfc3339),
        open_event_counts_24h: api::EventCounts {
            info: h.counts_24h.sum_info(),
            warn: h.counts_24h.sum_warn(),
        },
        status: classify_status(h.last_seen_ts, now).into(),
    }
}

// `render_host_meta` and `render_assessment` (and `get_fleet_host_by_id` for
// `PolicyState` and `AgentHealth`) destructure their source type with no `..`,
// so a field added to it fails to compile there until the wire type decides on
// it. `HostSummary`, the other `RiskEntry` reads and `HourlyBuckets` are read
// field by field and get no such check.

fn render_host_meta(m: &HostMetaSnapshot) -> api::HostMeta {
    let HostMetaSnapshot {
        hostname,
        os_name,
        os_version,
        kernel_version,
        architecture,
        interfaces,
        default_gateway_v4,
        default_gateway_v6,
        dns_servers,
    } = m;
    let interfaces = interfaces
        .iter()
        .map(|i| {
            let NetworkInterface {
                name,
                mac,
                ipv4,
                ipv6,
            } = i;
            api::NetworkInterface {
                ipv4: ipv4.clone(),
                ipv6: ipv6.clone(),
                mac: mac.clone(),
                name: name.clone(),
            }
        })
        .collect();
    api::HostMeta {
        architecture: architecture.clone(),
        default_gateway_v4: default_gateway_v4.clone(),
        default_gateway_v6: default_gateway_v6.clone(),
        dns_servers: dns_servers.clone(),
        hostname: hostname.clone(),
        interfaces,
        kernel_version: kernel_version.clone(),
        os_name: os_name.clone(),
        os_version: os_version.clone(),
    }
}

fn render_assessment(entry: &RiskEntry) -> api::AiGuardAssessment {
    let RiskEntry {
        controls,
        score,
        bucket,
        assessed_ts,
        is_reattestation,
        scope,
        reasons,
    } = entry;
    let controls = controls.as_ref().map(|cs| {
        cs.iter()
            .map(|c| {
                let lodeline_core::event::AiGuardControl {
                    id,
                    source_path,
                    setting,
                    value,
                } = c;
                api::AiGuardControl {
                    id: id.clone(),
                    setting: setting.clone(),
                    // Paths arrive as JSON strings, so they are always UTF-8.
                    source_path: source_path.to_string_lossy().into_owned(),
                    value: value.clone(),
                }
            })
            .collect()
    });
    api::AiGuardAssessment {
        assessed_ts: rfc3339(*assessed_ts),
        bucket: wire_str(bucket),
        controls,
        is_reattestation: *is_reattestation,
        reasons: reasons
            .iter()
            .map(|r| serde_json::to_value(r).expect("reason serializes"))
            .collect(),
        scope: serde_json::to_value(scope).expect("scope serializes"),
        score: f64::from(*score),
    }
}

pub async fn get_fleet_host_by_id(
    State(state): State<SharedState>,
    Path(host_id): Path<String>,
) -> impl IntoResponse {
    let now = OffsetDateTime::now_utc();
    let Some(h) = state.fleet_index.get_host(&host_id) else {
        return error_response(StatusCode::NOT_FOUND, "not_found", "host_id not in index");
    };

    // Detail = the list row plus the detail blocks.
    let api::HostListItem {
        agent_version,
        current_risk,
        host_id,
        hostname,
        last_seen_ts,
        open_event_counts_24h,
        status,
    } = render_host_summary_list(&h, now);
    let crate::fleet_index::PolicyState {
        last_applied_policy_version,
        policy_expired_active,
        last_policy_reload_ts,
    } = &h.policy_state;
    let crate::fleet_index::AgentHealth {
        last_heartbeat_ts,
        hash_p99_ms_latest,
        jsonl_above_soft_floor_latest,
    } = &h.agent_health;

    Json(api::HostDetail {
        agent_health: api::AgentHealth {
            hash_p99_ms_latest: *hash_p99_ms_latest,
            jsonl_above_soft_floor_latest: *jsonl_above_soft_floor_latest,
            last_heartbeat_ts: last_heartbeat_ts.map(rfc3339),
            recent_channel_stalls_24h: h.counts_24h.sum_channel_stalls(),
            recent_sender_lag_critical_24h: h.counts_24h.sum_sender_lag_critical(),
            recent_watcher_degraded_24h: h.counts_24h.sum_watcher_degraded(),
        },
        agent_version,
        ai_guard: api::AiGuard {
            by_tool: h
                .current_risk
                .iter()
                .map(|(tool, entry)| (wire_str(tool), render_assessment(entry)))
                .collect(),
        },
        current_risk,
        host_id,
        host_meta: h.latest_host_meta.as_ref().map(render_host_meta),
        hostname,
        last_seen_ts,
        open_event_counts_24h,
        policy_state: api::PolicyState {
            last_applied_policy_version: *last_applied_policy_version,
            last_policy_reload_ts: last_policy_reload_ts.map(rfc3339),
            policy_expired_active: *policy_expired_active,
        },
        status,
    })
    .into_response()
}
