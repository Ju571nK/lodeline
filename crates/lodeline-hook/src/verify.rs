//! tamper-evidence (#100): compare the recorded install baseline against the
//! live agent settings file. Pure (filesystem read only) — no IPC here.
use crate::install;
use lodeline_core::hook_proto::DriftKind;
use serde::Deserialize;
use std::path::Path;

/// Subset of hook-registration-<agent>.json we compare against (serde ignores the rest).
#[derive(Deserialize, Debug, Clone)]
pub struct Baseline {
    pub agent: String,
    pub settings_path: String,
    pub command: String,
    pub matcher: String,
    pub block_hash: String,
    #[serde(default)]
    pub fail_closed: Option<bool>,
}

/// A detected drift. `None` from `check()`/`check_one()` means clean.
#[derive(Debug, Clone, PartialEq)]
pub struct DriftReport {
    pub kind: DriftKind,
    pub settings_path: String,
    pub expected_command_hash: String,
    pub observed_command_hash: Option<String>,
    pub expected_matcher: Option<String>,
    pub observed_matcher: Option<String>,
    pub expected_fail_closed: Option<bool>,
    pub observed_fail_closed: Option<bool>,
    /// More than one entry of ours, such as one an upgrade from another folder
    /// left behind. Sent as `CommandDrift`, which an older agent can read.
    pub duplicate_entries: bool,
}

/// Load the baseline, or None if absent/unreadable/malformed.
pub fn load_baseline(path: &Path) -> Option<Baseline> {
    let raw = std::fs::read(path).ok()?;
    serde_json::from_slice(&raw).ok()
}

fn absent(path: &str) -> DriftReport {
    DriftReport {
        kind: DriftKind::BaselineAbsent,
        settings_path: path.into(),
        expected_command_hash: String::new(),
        observed_command_hash: None,
        expected_matcher: None,
        observed_matcher: None,
        expected_fail_closed: None,
        observed_fail_closed: None,
        duplicate_entries: false,
    }
}

/// Full check: None when clean, Some(report) on any drift (incl. baseline_absent).
pub fn check(agent: &str) -> Option<DriftReport> {
    let Some(bp) = install::baseline_path(agent) else {
        return Some(absent(&format!("<unknown agent {agent}>")));
    };
    let Some(b) = load_baseline(&bp) else {
        return Some(absent(&bp.to_string_lossy()));
    };
    check_one(&b)
}

/// Compare one baseline against its live settings file. None = clean.
/// Dispatches by agent format: Cursor gets a 3-pass algorithm (missing > command > fail-mode);
/// Claude/codex use the NestedPreToolUse path (entry_missing -> command_drift -> matcher_drift).
/// A second entry of ours is command_drift with `duplicate_entries` set.
pub fn check_one(b: &Baseline) -> Option<DriftReport> {
    match install::agent_format(&b.agent) {
        Some(install::HookFormat::Cursor) => check_one_cursor(b),
        _ => check_one_claude(b), // NestedPreToolUse (claude-code/codex) + unknown fall back
    }
}

/// Claude/codex path (verbatim original check_one logic).
/// Order: entry_missing -> command_drift -> matcher_drift.
fn check_one_claude(b: &Baseline) -> Option<DriftReport> {
    let exe = lodeline_core::paths::command_exe(&b.command).to_string();
    let root: serde_json::Value = std::fs::read(&b.settings_path)
        .ok()
        .and_then(|raw| serde_json::from_slice(&raw).ok())
        // treat both an absent and a corrupt settings file as "entry not present" —
        // the lodeline entry simply can't be found, yielding EntryMissing.
        .unwrap_or(serde_json::Value::Null);
    let groups = root
        .get("hooks")
        .and_then(|h| h.get("PreToolUse"))
        .and_then(|p| p.as_array())
        .map_or(&[][..], Vec::as_slice);
    let Some((entry, live_cmd)) = install::nested_ours(groups, &exe, &b.agent).next() else {
        return Some(DriftReport {
            kind: DriftKind::EntryMissing,
            settings_path: b.settings_path.clone(),
            expected_command_hash: b.block_hash.clone(),
            observed_command_hash: None,
            expected_matcher: Some(b.matcher.clone()),
            observed_matcher: None,
            expected_fail_closed: None,
            observed_fail_closed: None,
            duplicate_entries: false,
        });
    };

    // block_hash was written as blake3(full command string), the same inner command.
    let observed_hash = blake3::hash(live_cmd.as_bytes()).to_hex().to_string();
    let observed_matcher = entry
        .get("matcher")
        .and_then(|m| m.as_str())
        .map(String::from);

    // Entries match by shape, so a repointed binary is CommandDrift too.
    let duplicate_entries = install::count_lodeline_entries(&root, &exe, &b.agent) > 1;
    if duplicate_entries || observed_hash != b.block_hash {
        return Some(DriftReport {
            kind: DriftKind::CommandDrift,
            settings_path: b.settings_path.clone(),
            expected_command_hash: b.block_hash.clone(),
            observed_command_hash: Some(observed_hash),
            expected_matcher: Some(b.matcher.clone()),
            observed_matcher,
            expected_fail_closed: None,
            observed_fail_closed: None,
            duplicate_entries,
        });
    }
    if observed_matcher.as_deref() != Some(b.matcher.as_str()) {
        return Some(DriftReport {
            kind: DriftKind::MatcherDrift,
            settings_path: b.settings_path.clone(),
            expected_command_hash: b.block_hash.clone(),
            observed_command_hash: Some(observed_hash),
            expected_matcher: Some(b.matcher.clone()),
            observed_matcher,
            expected_fail_closed: None,
            observed_fail_closed: None,
            duplicate_entries: false,
        });
    }
    None // clean
}

/// Cursor path: 3-pass drift check.
/// Cursor writes our entry into BOTH `beforeShellExecution` and
/// `beforeMCPExecution`; both must be present and consistent, or an attacker
/// could strip coverage from one event. `failClosed` is a Cursor-native field
/// (gates whether a crashing hook blocks vs passes through) — absent from the
/// Claude/Codex format, which is why only this path checks it.
/// Pass 1 reports an event without our entry. It goes first.
/// Pass 2 reports a second entry of ours, or a command hash that differs.
/// Pass 3 reports a failClosed that differs from the baseline.
fn check_one_cursor(b: &Baseline) -> Option<DriftReport> {
    use install::{
        cursor_entry_command, cursor_entry_fail_closed, cursor_entry_is_ours, CURSOR_EVENTS,
    };
    use lodeline_core::paths::command_exe;
    let exe = command_exe(&b.command).to_string();
    let root: serde_json::Value = std::fs::read(&b.settings_path)
        .ok()
        .and_then(|raw| serde_json::from_slice(&raw).ok())
        .unwrap_or(serde_json::Value::Null);
    let our = |ev: &str| -> Option<serde_json::Value> {
        root.get("hooks")
            .and_then(|h| h.get(ev))
            .and_then(|a| a.as_array())
            .and_then(|arr| arr.iter().find(|e| cursor_entry_is_ours(e, &exe)).cloned())
    };
    let entries: Vec<(&str, Option<serde_json::Value>)> =
        CURSOR_EVENTS.iter().map(|ev| (*ev, our(ev))).collect();

    // Pass 1. An event is missing our entry.
    if entries.iter().any(|(_, e)| e.is_none()) {
        return Some(DriftReport {
            kind: DriftKind::EntryMissing,
            settings_path: b.settings_path.clone(),
            expected_command_hash: b.block_hash.clone(),
            observed_command_hash: None,
            expected_matcher: None,
            observed_matcher: None,
            expected_fail_closed: None,
            observed_fail_closed: None,
            duplicate_entries: false,
        });
    }
    // Pass 2. A second entry of ours, or a command hash that differs.
    let duplicate_entries =
        install::count_lodeline_entries(&root, &exe, &b.agent) > CURSOR_EVENTS.len();
    for (_, e) in &entries {
        let v = e.as_ref().unwrap(); // guaranteed Some past PASS 1
                                     // cursor_entry_is_ours already matched on the command, so command is present past PASS 1
        let cmd = cursor_entry_command(v).unwrap_or("");
        let observed = blake3::hash(cmd.as_bytes()).to_hex().to_string();
        if duplicate_entries || observed != b.block_hash {
            return Some(DriftReport {
                kind: DriftKind::CommandDrift,
                settings_path: b.settings_path.clone(),
                expected_command_hash: b.block_hash.clone(),
                observed_command_hash: Some(observed),
                expected_matcher: None,
                observed_matcher: None,
                expected_fail_closed: None,
                observed_fail_closed: None,
                duplicate_entries,
            });
        }
    }
    // Pass 3. A failClosed that differs from the baseline.
    let expected_fc = b.fail_closed.unwrap_or(false);
    for (_, e) in &entries {
        let v = e.as_ref().unwrap(); // guaranteed Some past PASS 1
        let observed_fc = cursor_entry_fail_closed(v);
        if observed_fc != expected_fc {
            return Some(DriftReport {
                kind: DriftKind::FailModeDrift,
                settings_path: b.settings_path.clone(),
                expected_command_hash: b.block_hash.clone(),
                observed_command_hash: None,
                expected_matcher: None,
                observed_matcher: None,
                expected_fail_closed: Some(expected_fc),
                observed_fail_closed: Some(observed_fc),
                duplicate_entries: false,
            });
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::path::Path;

    fn baseline(dir: &Path, exe: &str, matcher: &str) -> Baseline {
        let cmd = format!("{exe} claude-code --capture redacted");
        Baseline {
            agent: "claude-code".into(),
            settings_path: dir.join("settings.json").to_string_lossy().into_owned(),
            command: cmd.clone(),
            matcher: matcher.into(),
            block_hash: blake3::hash(cmd.as_bytes()).to_hex().to_string(),
            fail_closed: None,
        }
    }
    fn write_settings(b: &Baseline, json: &str) {
        let mut f = std::fs::File::create(&b.settings_path).unwrap();
        f.write_all(json.as_bytes()).unwrap();
    }

    #[test]
    fn clean_when_settings_match_baseline() {
        let dir = tempfile::tempdir().unwrap();
        let b = baseline(dir.path(), "/usr/bin/lodeline-hook", "*");
        write_settings(
            &b,
            r#"{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"/usr/bin/lodeline-hook claude-code --capture redacted"}]}]}}"#,
        );
        assert_eq!(check_one(&b), None);
    }

    #[test]
    fn clean_when_quoted_path_with_spaces_matches_baseline() {
        let dir = tempfile::tempdir().unwrap();
        let b = baseline(
            dir.path(),
            r#""C:/Program Files/Lodeline/lodeline-hook.exe""#,
            "*",
        );
        let settings = serde_json::json!({"hooks":{"PreToolUse":[
            {"matcher":"*","hooks":[{"type":"command","command":"\"C:/Program Files/Other/tool.exe\" run"}]},
            {"matcher":"*","hooks":[{"type":"command","command":b.command}]}
        ]}});
        write_settings(&b, &settings.to_string());
        assert_eq!(check_one(&b), None);
    }

    #[test]
    fn entry_missing_when_no_lodeline_entry() {
        let dir = tempfile::tempdir().unwrap();
        let b = baseline(dir.path(), "/usr/bin/lodeline-hook", "*");
        write_settings(
            &b,
            r#"{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"/other/tool run"}]}]}}"#,
        );
        assert_eq!(check_one(&b).unwrap().kind, DriftKind::EntryMissing);
    }

    #[test]
    fn command_drift_when_command_changed() {
        let dir = tempfile::tempdir().unwrap();
        let b = baseline(dir.path(), "/usr/bin/lodeline-hook", "*");
        write_settings(
            &b,
            r#"{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"/usr/bin/lodeline-hook claude-code --capture raw"}]}]}}"#,
        );
        assert_eq!(check_one(&b).unwrap().kind, DriftKind::CommandDrift);
    }

    #[test]
    fn matcher_drift_when_matcher_narrowed() {
        let dir = tempfile::tempdir().unwrap();
        let b = baseline(dir.path(), "/usr/bin/lodeline-hook", "*");
        write_settings(
            &b,
            r#"{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"/usr/bin/lodeline-hook claude-code --capture redacted"}]}]}}"#,
        );
        let r = check_one(&b).unwrap();
        assert_eq!(r.kind, DriftKind::MatcherDrift);
        assert_eq!(r.observed_matcher.as_deref(), Some("Bash"));
    }

    fn nested_settings(cmds: &[&str]) -> String {
        serde_json::json!({"hooks":{"PreToolUse": cmds.iter()
            .map(|c| serde_json::json!({"matcher":"*","hooks":[{"type":"command","command":c}]}))
            .collect::<Vec<_>>()}})
        .to_string()
    }

    const OLD_CMD: &str =
        r"\\?\C:\Users\alice\lodeline-0.12.2\lodeline-hook.exe claude-code --capture redacted";

    #[test]
    fn duplicate_left_by_an_upgrade_is_drift() {
        let dir = tempfile::tempdir().unwrap();
        let b = baseline(
            dir.path(),
            "C:/Users/alice/lodeline-0.12.3/lodeline-hook.exe",
            "*",
        );
        for cmds in [[OLD_CMD, &b.command], [&b.command, &b.command]] {
            write_settings(&b, &nested_settings(&cmds));
            let r = check_one(&b).expect("a second entry of ours is drift");
            assert_eq!(r.kind, DriftKind::CommandDrift);
            assert!(r.duplicate_entries);
        }
    }

    #[test]
    fn our_entry_at_another_path_is_command_drift() {
        let dir = tempfile::tempdir().unwrap();
        let b = baseline(
            dir.path(),
            "C:/Users/alice/lodeline-0.12.3/lodeline-hook.exe",
            "*",
        );
        write_settings(&b, &nested_settings(&[OLD_CMD]));
        let r = check_one(&b).unwrap();
        assert_eq!(r.kind, DriftKind::CommandDrift);
        assert!(!r.duplicate_entries);
    }

    #[test]
    fn our_hook_after_a_user_hook_in_one_group_is_clean() {
        let dir = tempfile::tempdir().unwrap();
        let b = baseline(dir.path(), "/usr/bin/lodeline-hook", "*");
        let settings = serde_json::json!({"hooks":{"PreToolUse":[{"matcher":"*","hooks":[
            {"type":"command","command":"/u/mine.sh"},
            {"type":"command","command":b.command},
        ]}]}});
        write_settings(&b, &settings.to_string());
        assert_eq!(check_one(&b), None);
    }

    #[test]
    fn two_of_ours_in_one_group_is_a_duplicate() {
        let dir = tempfile::tempdir().unwrap();
        let b = baseline(dir.path(), "/usr/bin/lodeline-hook", "*");
        let settings = serde_json::json!({"hooks":{"PreToolUse":[{"matcher":"*","hooks":[
            {"type":"command","command":b.command},
            {"type":"command","command":"/old/lodeline-hook claude-code --capture raw"},
        ]}]}});
        write_settings(&b, &settings.to_string());
        assert!(check_one(&b).unwrap().duplicate_entries);
    }

    #[test]
    fn a_leftover_sigil_hook_entry_beside_ours_is_drift() {
        let dir = tempfile::tempdir().unwrap();
        let b = baseline(dir.path(), "/usr/bin/lodeline-hook", "*");
        let old = "/usr/bin/sigil-hook claude-code --capture redacted";
        write_settings(&b, &nested_settings(&[&b.command, old]));
        let r = check_one(&b).unwrap();
        assert_eq!(r.kind, DriftKind::CommandDrift);
        assert!(r.duplicate_entries);
    }

    #[test]
    fn a_wrapper_around_our_binary_is_not_a_duplicate() {
        let dir = tempfile::tempdir().unwrap();
        let b = baseline(dir.path(), "/usr/bin/lodeline-hook", "*");
        let wrap = format!("bash -c '{}'", b.command);
        write_settings(
            &b,
            &nested_settings(&[&wrap, "/other/tool run", &b.command]),
        );
        assert_eq!(check_one(&b), None);
    }

    #[test]
    fn entry_missing_when_settings_file_absent() {
        let dir = tempfile::tempdir().unwrap();
        let b = baseline(dir.path(), "/usr/bin/lodeline-hook", "*"); // settings.json never written
        assert_eq!(check_one(&b).unwrap().kind, DriftKind::EntryMissing);
    }

    #[test]
    fn baseline_absent_when_no_baseline() {
        assert!(load_baseline(Path::new("/nonexistent/hook-registration.json")).is_none());
    }

    // --- enforce-install baseline tests (#100 regression) ---

    /// An enforce-mode baseline is clean when the settings file contains the
    /// exact enforce command string that was written at install time.
    #[test]
    fn clean_for_enforce_install_baseline() {
        let dir = tempfile::tempdir().unwrap();
        let exe = "/usr/bin/lodeline-hook";
        let enforce_cmd =
            format!("{exe} claude-code --enforce --on-failure open --capture redacted");
        let b = Baseline {
            agent: "claude-code".into(),
            settings_path: dir
                .path()
                .join("settings.json")
                .to_string_lossy()
                .into_owned(),
            command: enforce_cmd.clone(),
            matcher: "*".into(),
            block_hash: blake3::hash(enforce_cmd.as_bytes()).to_hex().to_string(),
            fail_closed: None,
        };
        // Settings registered WITH the enforce command => clean (no drift).
        let mut f = std::fs::File::create(&b.settings_path).unwrap();
        write!(
            f,
            r#"{{"hooks":{{"PreToolUse":[{{"matcher":"*","hooks":[{{"type":"command","command":"{enforce_cmd}"}}]}}]}}}}"#
        )
        .unwrap();
        assert_eq!(
            check_one(&b),
            None,
            "enforce baseline must be clean against matching settings"
        );
    }

    /// An enforce-mode baseline detects drift when the settings file contains
    /// only the observe command (the bug this fix addresses: verify spuriously
    /// reported command_drift right after 'install --enforce --write').
    #[test]
    fn command_drift_when_observe_command_in_enforce_baseline() {
        let dir = tempfile::tempdir().unwrap();
        let exe = "/usr/bin/lodeline-hook";
        let enforce_cmd =
            format!("{exe} claude-code --enforce --on-failure open --capture redacted");
        let observe_cmd = format!("{exe} claude-code --capture redacted");
        let b = Baseline {
            agent: "claude-code".into(),
            settings_path: dir
                .path()
                .join("settings.json")
                .to_string_lossy()
                .into_owned(),
            command: enforce_cmd.clone(),
            matcher: "*".into(),
            block_hash: blake3::hash(enforce_cmd.as_bytes()).to_hex().to_string(),
            fail_closed: None,
        };
        // Settings registered with the OBSERVE command while baseline expects ENFORCE
        // => command_drift (this is the genuine tamper signal, not a false positive).
        let mut f = std::fs::File::create(&b.settings_path).unwrap();
        write!(
            f,
            r#"{{"hooks":{{"PreToolUse":[{{"matcher":"*","hooks":[{{"type":"command","command":"{observe_cmd}"}}]}}]}}}}"#
        )
        .unwrap();
        let report = check_one(&b).expect("should detect drift");
        assert_eq!(
            report.kind,
            DriftKind::CommandDrift,
            "downgrade from enforce to observe command must be reported as command_drift"
        );
    }

    // --- Cursor verify tests ---

    fn cursor_baseline(dir: &Path, fail_closed: bool) -> Baseline {
        let exe = "/usr/bin/lodeline-hook";
        let cmd = format!(
            "{exe} cursor --enforce --on-failure {} --capture redacted",
            if fail_closed { "closed" } else { "open" }
        );
        Baseline {
            agent: "cursor".into(),
            settings_path: dir.join("hooks.json").to_string_lossy().into_owned(),
            command: cmd.clone(),
            matcher: "*".into(),
            fail_closed: Some(fail_closed),
            block_hash: blake3::hash(cmd.as_bytes()).to_hex().to_string(),
        }
    }

    fn write_cursor_settings(b: &Baseline, sh: &str, mcp: &str) {
        let json = format!(
            r#"{{"version":1,"hooks":{{"beforeShellExecution":[{sh}],"beforeMCPExecution":[{mcp}]}}}}"#
        );
        std::fs::write(&b.settings_path, json).unwrap();
    }

    #[test]
    fn cursor_clean() {
        let dir = tempfile::tempdir().unwrap();
        let b = cursor_baseline(dir.path(), true);
        let entry = format!(r#"{{"command":"{}","failClosed":true}}"#, b.command);
        write_cursor_settings(&b, &entry, &entry);
        assert_eq!(check_one(&b), None);
    }

    #[test]
    fn cursor_entry_missing_in_one_event() {
        let dir = tempfile::tempdir().unwrap();
        let b = cursor_baseline(dir.path(), true);
        let entry = format!(r#"{{"command":"{}","failClosed":true}}"#, b.command);
        write_cursor_settings(&b, &entry, ""); // mcp event empty → missing
        assert_eq!(check_one(&b).unwrap().kind, DriftKind::EntryMissing);
    }

    #[test]
    fn cursor_command_drift() {
        let dir = tempfile::tempdir().unwrap();
        let b = cursor_baseline(dir.path(), true);
        let tampered = format!(
            r#"{{"command":"{} --capture raw","failClosed":true}}"#,
            b.command
        );
        write_cursor_settings(&b, &tampered, &tampered);
        assert_eq!(check_one(&b).unwrap().kind, DriftKind::CommandDrift);
    }

    #[test]
    fn cursor_fail_mode_drift_when_failclosed_flipped() {
        let dir = tempfile::tempdir().unwrap();
        let b = cursor_baseline(dir.path(), true); // baseline expects failClosed=true
        let downgraded = format!(r#"{{"command":"{}","failClosed":false}}"#, b.command);
        write_cursor_settings(&b, &downgraded, &downgraded); // command intact, only failClosed flipped
        let r = check_one(&b).unwrap();
        assert_eq!(r.kind, DriftKind::FailModeDrift);
        assert_eq!(r.expected_fail_closed, Some(true));
        assert_eq!(r.observed_fail_closed, Some(false));
    }

    #[test]
    fn cursor_duplicate_in_one_event_is_drift() {
        let dir = tempfile::tempdir().unwrap();
        let b = cursor_baseline(dir.path(), true);
        let entry = format!(r#"{{"command":"{}","failClosed":true}}"#, b.command);
        let old = r#"{"command":"/opt/lodeline-0.12.2/lodeline-hook cursor --capture redacted"}"#;
        write_cursor_settings(&b, &format!("{old},{entry}"), &entry);
        let r = check_one(&b).unwrap();
        assert_eq!(r.kind, DriftKind::CommandDrift);
        assert!(r.duplicate_entries);
    }

    #[test]
    fn missing_precedence_beats_command() {
        let dir = tempfile::tempdir().unwrap();
        let b = cursor_baseline(dir.path(), true);
        let drifted = format!(
            r#"{{"command":"{} --capture raw","failClosed":true}}"#,
            b.command
        );
        write_cursor_settings(&b, &drifted, ""); // shell drifted, mcp missing → report EntryMissing
        assert_eq!(check_one(&b).unwrap().kind, DriftKind::EntryMissing);
    }
}
