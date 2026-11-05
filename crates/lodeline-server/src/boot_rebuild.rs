//! Boot rebuild — walk events_out_dir/<host_id>/received-YYYY-MM-DD.jsonl
//! in chronological order, apply each event to a HostSummary, and return the
//! built map for swap-in to FleetIndex.

use crate::fleet_index::HostSummary;
use crate::fleet_index_update::{apply_event, apply_event_received_between};
use lodeline_core::event::Event;
use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use time::OffsetDateTime;

/// Walk all per-host JSONL files under `events_out_dir`, apply each line to
/// a HostSummary, return the built map. Corrupt lines are skipped with a
/// `tracing::warn!`. Caller (`main.rs`) calls `FleetIndex::replace(...)` with
/// the result before opening the HTTP listener.
pub fn rebuild_from_jsonl(events_out_dir: &Path) -> std::io::Result<HashMap<String, HostSummary>> {
    let mut out: HashMap<String, HostSummary> = HashMap::new();

    let entries = match std::fs::read_dir(events_out_dir) {
        Ok(it) => it,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(e),
    };

    let mut files: Vec<(PathBuf, String)> = Vec::new();
    for ent in entries.flatten() {
        let host_dir = ent.path();
        if !host_dir.is_dir() {
            continue;
        }
        let host_id = match ent.file_name().to_str().map(str::to_string) {
            Some(s) => s,
            None => continue,
        };
        if host_id.starts_with('.') {
            continue; // skip .high-water.json and friends
        }
        if uuid::Uuid::parse_str(&host_id).is_err() {
            tracing::warn!(host_id = %host_id, "skip non-UUID host dir (boot rebuild)");
            continue;
        }
        let host_files = match std::fs::read_dir(&host_dir) {
            Ok(it) => it,
            Err(_) => continue,
        };
        for f in host_files.flatten() {
            let path = f.path();
            let name = match f.file_name().to_str().map(str::to_string) {
                Some(s) => s,
                None => continue,
            };
            if name.starts_with("received-") && name.ends_with(".jsonl") {
                files.push((path, name));
            }
        }
    }
    // Sort by file basename (the YYYY-MM-DD prefix makes this chronological).
    files.sort_by_key(|(_, name)| name.clone());

    let boot = OffsetDateTime::now_utc();
    for (path, name) in files {
        // Each line takes the receive time of the first batch record that ends
        // at or after it (`persist::receive_times_path`), its own batch's unless
        // a record was lost. A line after the last record, as in a file written
        // before receive times were kept, knows only its UTC receive day, so
        // rebuild prunes by the day's start and caps times at its end or at
        // boot. A reading can then outlive 48h by up to two days until the
        // host's next live reading, and by up to one day after it.
        let times: Vec<(u64, OffsetDateTime)> =
            std::fs::read_to_string(crate::persist::receive_times_path(&path))
                .unwrap_or_default()
                .lines()
                .filter_map(|l| {
                    let (end, ts) = l.split_once(' ')?;
                    let ts =
                        OffsetDateTime::parse(ts, &time::format_description::well_known::Rfc3339)
                            .ok()?;
                    Some((end.parse().ok()?, ts))
                })
                .collect();
        let day = name
            .get("received-".len()..)
            .and_then(|d| d.strip_suffix(".jsonl"))
            .and_then(|d| {
                time::Date::parse(d, time::macros::format_description!("[year]-[month]-[day]")).ok()
            });
        // A name with no day bounds nothing, so its events prune nothing.
        let (earliest, latest) = match day.and_then(|d| Some((d, d.next_day()?))) {
            Some((d, next)) => (
                d.midnight().assume_utc(),
                next.midnight().assume_utc().min(boot),
            ),
            None => (OffsetDateTime::UNIX_EPOCH, boot),
        };
        let f = match std::fs::File::open(&path) {
            Ok(f) => f,
            Err(e) => {
                tracing::warn!(?path, error = ?e, "skip unreadable jsonl");
                continue;
            }
        };
        let mut reader = BufReader::new(f);
        let mut line = String::new();
        let mut offset = 0u64;
        loop {
            line.clear();
            let n = match reader.read_line(&mut line) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) => {
                    tracing::warn!(?path, error = ?e, "read_line failed; stop file");
                    break;
                }
            };
            offset += n as u64;
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<Event>(line.trim_end()) {
                Ok(event) => {
                    let entry = out
                        .entry(event.host_id.clone())
                        .or_insert_with(|| HostSummary::new(event.host_id.clone()));
                    match times.get(times.partition_point(|(end, _)| *end < offset)) {
                        Some(&(_, received)) => apply_event(entry, &event, received),
                        None => apply_event_received_between(entry, &event, earliest, latest),
                    }
                }
                Err(e) => {
                    tracing::warn!(?path, error = ?e, bytes = n, "skip corrupt jsonl line");
                }
            }
        }
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::tempdir;

    // Valid UUIDs for host-dir names (the guard rejects non-UUIDs).
    const HID: &str = "0190b8a0-1111-7abc-8def-000000000001";

    fn write_line(p: &Path, line: &serde_json::Value) {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(p)
            .unwrap();
        writeln!(f, "{line}").unwrap();
    }

    fn host_meta_event(host_id: &str, hostname: &str, ts: &str) -> serde_json::Value {
        json!({
            "schema_version": 1,
            "event_id": uuid::Uuid::now_v7().to_string(),
            "ts": ts,
            "host_id": host_id,
            "agent_version": "0.5.0",
            "severity": "info",
            "source": {"kind": "agent"},
            "subject": {"kind": "self"},
            "evidence": {
                "kind": "host_meta_snapshot",
                "snapshot": {
                    "hostname": hostname,
                    "os_name": null, "os_version": null, "kernel_version": null,
                    "architecture": null, "interfaces": [],
                    "default_gateway_v4": null, "default_gateway_v6": null,
                    "dns_servers": []
                },
                "is_reattestation": false
            },
            "target_id": null
        })
    }

    #[test]
    fn rebuild_empty_dir_returns_empty_map() {
        let dir = tempdir().unwrap();
        let map = rebuild_from_jsonl(dir.path()).unwrap();
        assert!(map.is_empty());
    }

    #[test]
    fn rebuild_nonexistent_dir_returns_empty_map() {
        let map = rebuild_from_jsonl(Path::new("/nonexistent/never/exists")).unwrap();
        assert!(map.is_empty());
    }

    #[test]
    fn rebuild_picks_up_host_meta_snapshot() {
        let dir = tempdir().unwrap();
        let host_dir = dir.path().join(HID);
        std::fs::create_dir_all(&host_dir).unwrap();
        let file = host_dir.join("received-2026-05-17.jsonl");
        write_line(
            &file,
            &host_meta_event(HID, "alice", "2026-05-17T12:00:00Z"),
        );
        let map = rebuild_from_jsonl(dir.path()).unwrap();
        assert_eq!(map.len(), 1);
        let h = map.get(HID).unwrap();
        assert_eq!(h.hostname(), Some("alice"));
    }

    #[test]
    fn rebuild_applies_events_in_chronological_order_across_files() {
        let dir = tempdir().unwrap();
        let host_dir = dir.path().join(HID);
        std::fs::create_dir_all(&host_dir).unwrap();
        let f_old = host_dir.join("received-2026-05-16.jsonl");
        let f_new = host_dir.join("received-2026-05-17.jsonl");
        write_line(
            &f_old,
            &host_meta_event(HID, "old-name", "2026-05-16T12:00:00Z"),
        );
        write_line(
            &f_new,
            &host_meta_event(HID, "new-name", "2026-05-17T12:00:00Z"),
        );
        let map = rebuild_from_jsonl(dir.path()).unwrap();
        // newer overrides older
        assert_eq!(map.get(HID).unwrap().hostname(), Some("new-name"));
    }

    fn reading(tool: &str, user: &str, ts: &str) -> serde_json::Value {
        json!({
            "schema_version": 1,
            "event_id": uuid::Uuid::now_v7().to_string(),
            "ts": ts,
            "host_id": HID,
            "agent_version": "0.5.0",
            "severity": "warn",
            "source": {"kind": "agent"},
            "subject": {"kind": "self"},
            "evidence": {
                "kind": "ai_guard_risk_assessed",
                "tool": tool,
                "scope": {"kind": "user_global"},
                "score": 7.0,
                "bucket": "critical",
                "reasons": [],
                "is_reattestation": false,
                "user": user
            },
            "target_id": null
        })
    }

    /// Rebuilds `(file name, reading)` pairs and returns the tools left in
    /// `current_risk`.
    fn rebuilt_tools(files: &[(&str, serde_json::Value)]) -> Vec<lodeline_core::event::AiTool> {
        let dir = tempdir().unwrap();
        let host_dir = dir.path().join(HID);
        std::fs::create_dir_all(&host_dir).unwrap();
        for (name, line) in files {
            write_line(&host_dir.join(name), line);
        }
        let map = rebuild_from_jsonl(dir.path()).unwrap();
        map[HID].current_risk.keys().copied().collect()
    }

    #[test]
    fn rebuild_keeps_a_reading_live_ingest_keeps() {
        use lodeline_core::event::AiTool;
        // Codex at T. Claude Code arrives at T+25h, just after midnight, dated
        // days ahead. Live ingest cuts at T-23h, so the Codex reading stays.
        let tools = rebuilt_tools(&[
            (
                "received-2026-05-16.jsonl",
                reading("codex", "alice", "2026-05-16T23:30:00Z"),
            ),
            (
                "received-2026-05-18.jsonl",
                reading("claude_code", "bob", "2026-05-20T12:00:00Z"),
            ),
        ]);
        assert_eq!(tools, [AiTool::ClaudeCode, AiTool::Codex]);
    }

    #[test]
    fn rebuild_drops_a_reading_older_than_48h_and_a_day() {
        use lodeline_core::event::AiTool;
        let tools = rebuilt_tools(&[
            (
                "received-2026-05-10.jsonl",
                reading("codex", "alice", "2026-05-10T12:00:00Z"),
            ),
            (
                "received-2026-05-13.jsonl",
                reading("claude_code", "bob", "2026-05-13T12:00:00Z"),
            ),
        ]);
        assert_eq!(tools, [AiTool::ClaudeCode]);
    }

    #[test]
    fn rebuild_never_prunes_by_a_file_with_no_receive_day() {
        use lodeline_core::event::AiTool;
        let tools = rebuilt_tools(&[
            (
                "received-2026-05-17.jsonl",
                reading("codex", "alice", "2026-05-17T12:00:00Z"),
            ),
            (
                "received-unknown.jsonl",
                reading("claude_code", "bob", "2099-01-01T00:00:00Z"),
            ),
        ]);
        assert_eq!(tools, [AiTool::ClaudeCode, AiTool::Codex]);
    }

    #[test]
    fn rebuild_caps_a_future_dated_reading_at_its_receive_day() {
        let dir = tempdir().unwrap();
        let host_dir = dir.path().join(HID);
        std::fs::create_dir_all(&host_dir).unwrap();
        let file = host_dir.join("received-2026-05-17.jsonl");
        write_line(&file, &reading("codex", "alice", "2026-05-17T12:00:00Z"));
        write_line(
            &file,
            &reading("claude_code", "bob", "2026-05-20T12:00:00Z"),
        );
        let map = rebuild_from_jsonl(dir.path()).unwrap();
        let h = map.get(HID).unwrap();
        assert!(
            h.current_risk
                .contains_key(&lodeline_core::event::AiTool::Codex),
            "a future-dated reading pruned the host's other readings on replay"
        );
        assert_eq!(h.current_risk.len(), 2);
    }

    #[test]
    fn rebuild_caps_times_at_the_persisted_receive_time() {
        use time::macros::datetime;
        let dir = tempdir().unwrap();
        let host_dir = dir.path().join(HID);
        std::fs::create_dir_all(&host_dir).unwrap();
        let file = host_dir.join("received-2026-05-17.jsonl");
        write_line(
            &file,
            &host_meta_event(HID, "alice", "2026-05-20T12:00:00Z"),
        );
        let end = std::fs::metadata(&file).unwrap().len();
        std::fs::write(
            crate::persist::receive_times_path(&file),
            format!("{end} 2026-05-17T08:00:00Z\n"),
        )
        .unwrap();
        let h = &rebuild_from_jsonl(dir.path()).unwrap()[HID];
        assert_eq!(h.last_seen_ts, Some(datetime!(2026-05-17 08:00 UTC)));

        // A line after the last record falls back to the end of the receive day.
        write_line(
            &file,
            &host_meta_event(HID, "alice", "2026-05-20T12:00:00Z"),
        );
        let h = &rebuild_from_jsonl(dir.path()).unwrap()[HID];
        assert_eq!(h.last_seen_ts, Some(datetime!(2026-05-18 00:00 UTC)));
    }

    #[test]
    fn rebuild_without_receive_times_caps_times_at_boot() {
        let dir = tempdir().unwrap();
        let host_dir = dir.path().join(HID);
        std::fs::create_dir_all(&host_dir).unwrap();
        let now = OffsetDateTime::now_utc();
        let ahead = (now + time::Duration::days(3))
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap();
        let today = now.date();
        write_line(
            &host_dir.join(format!(
                "received-{:04}-{:02}-{:02}.jsonl",
                today.year(),
                u8::from(today.month()),
                today.day()
            )),
            &host_meta_event(HID, "alice", &ahead),
        );
        let seen = rebuild_from_jsonl(dir.path()).unwrap()[HID].last_seen_ts;
        assert!(
            seen.is_some_and(|t| t <= OffsetDateTime::now_utc()),
            "{seen:?}"
        );
    }

    #[test]
    fn rebuild_skips_corrupt_lines() {
        let dir = tempdir().unwrap();
        let host_dir = dir.path().join(HID);
        std::fs::create_dir_all(&host_dir).unwrap();
        let file = host_dir.join("received-2026-05-17.jsonl");
        write_line(&file, &serde_json::json!("not-an-object"));
        write_line(
            &file,
            &host_meta_event(HID, "alice", "2026-05-17T12:00:00Z"),
        );
        let map = rebuild_from_jsonl(dir.path()).unwrap();
        // good line still applied; bad line warned + skipped
        assert_eq!(map.get(HID).unwrap().hostname(), Some("alice"));
    }

    #[test]
    fn rebuild_ignores_hidden_files_like_high_water() {
        let dir = tempdir().unwrap();
        // not a host_id dir — should be skipped
        std::fs::write(dir.path().join(".high-water.json"), "{}").unwrap();
        let map = rebuild_from_jsonl(dir.path()).unwrap();
        assert!(map.is_empty());
    }

    #[test]
    fn rebuild_skips_non_uuid_host_dir() {
        let dir = tempdir().unwrap();
        let bogus = dir.path().join("not-a-uuid");
        std::fs::create_dir_all(&bogus).unwrap();
        write_line(
            &bogus.join("received-2026-05-17.jsonl"),
            &host_meta_event("not-a-uuid", "x", "2026-05-17T12:00:00Z"),
        );
        let map = rebuild_from_jsonl(dir.path()).unwrap();
        assert!(map.is_empty(), "non-UUID host dir must be skipped");
    }
}
