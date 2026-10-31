//! Hook entries written by `sigil-hook`, the binary's name before the Lodeline
//! rename. They point at a command that upgrades removed, so install and
//! uninstall take them out. Nothing else in a settings file is touched.

use crate::install::{agent_format, HookFormat, CURSOR_EVENTS};
use serde_json::Value;
use std::path::Path;

/// `<path>/sigil-hook <agent> ... --capture <mode>`, the only shape old installs
/// wrote. An unquoted Windows path with a space splits into several tokens, so
/// the binary is searched for rather than read from the first token.
pub(crate) fn is_legacy_command(cmd: &str) -> bool {
    let tokens: Vec<&str> = cmd.split_whitespace().collect();
    tokens.contains(&"--capture")
        && tokens.windows(2).any(|pair| {
            let name = pair[0].rsplit(['/', '\\']).next().unwrap_or(pair[0]);
            matches!(name, "sigil-hook" | "sigil-hook.exe")
                && (agent_format(pair[1]).is_some() || pair[1] == "grok")
        })
}

fn command_is_legacy(hook: &Value) -> bool {
    hook.get("command")
        .and_then(Value::as_str)
        .is_some_and(is_legacy_command)
}

/// Drop legacy inner hooks, and an entry only when that empties it, so a user's
/// hook sharing the entry survives. Returns how many hooks went.
fn strip_nested(entries: &mut Vec<Value>) -> usize {
    let mut removed = 0;
    entries.retain_mut(|entry| {
        let Some(hooks) = entry.get_mut("hooks").and_then(Value::as_array_mut) else {
            return true;
        };
        let before = hooks.len();
        hooks.retain(|h| !command_is_legacy(h));
        removed += before - hooks.len();
        hooks.len() == before || !hooks.is_empty()
    });
    removed
}

fn strip_flat(entries: &mut Vec<Value>) -> usize {
    let before = entries.len();
    entries.retain(|e| !command_is_legacy(e));
    before - entries.len()
}

/// Remove every legacy entry for `agent` and return the number removed.
pub(crate) fn strip_entries(root: &mut Value, agent: &str) -> usize {
    let Some(hooks) = root.get_mut("hooks") else {
        return 0;
    };
    match agent_format(agent) {
        Some(HookFormat::NestedPreToolUse) => hooks
            .get_mut("PreToolUse")
            .and_then(Value::as_array_mut)
            .map_or(0, strip_nested),
        Some(HookFormat::Cursor) => {
            let mut removed = 0;
            for ev in CURSOR_EVENTS {
                if let Some(entries) = hooks.get_mut(ev).and_then(Value::as_array_mut) {
                    removed += strip_flat(entries);
                }
            }
            removed
        }
        None => 0,
    }
}

/// Number of legacy entries `strip_entries` would remove.
pub(crate) fn count_entries(root: &Value, agent: &str) -> usize {
    strip_entries(&mut root.clone(), agent)
}

/// `~/.grok/hooks/sigil-hook.json` beside the new file. Removed once nothing but
/// legacy hooks remain in it; a file holding other hooks is rewritten without
/// ours. A file that cannot be read as ours is left alone.
pub(crate) fn retire_grok_file(path: &Path) -> std::io::Result<bool> {
    let Ok(raw) = std::fs::read(path) else {
        return Ok(false);
    };
    let Ok(mut root) = serde_json::from_slice::<Value>(&raw) else {
        return Ok(false);
    };
    let Some(entries) = root
        .pointer_mut("/hooks/PreToolUse")
        .and_then(Value::as_array_mut)
    else {
        return Ok(false);
    };
    if strip_nested(entries) == 0 {
        return Ok(false);
    }
    if entries.is_empty() {
        std::fs::remove_file(path)?;
    } else {
        std::fs::write(path, serde_json::to_vec_pretty(&root)?)?;
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::install::{merge_into, merge_into_enforce, remove_from};
    use serde_json::json;

    const OLD: &str = "/usr/bin/sigil-hook claude-code --capture redacted";
    const NEW_EXE: &str = "/usr/bin/lodeline-hook";

    fn nested(cmds: &[&str]) -> Value {
        json!({ "matcher": "*", "hooks": cmds.iter()
            .map(|c| json!({ "type": "command", "command": c }))
            .collect::<Vec<_>>() })
    }

    #[test]
    fn recognises_only_the_shape_old_installs_wrote() {
        assert!(is_legacy_command(OLD));
        assert!(is_legacy_command(
            "/opt/x/sigil-hook codex --enforce --on-failure open --capture raw"
        ));
        assert!(is_legacy_command(
            r"C:\Users\A B\.local\bin\sigil-hook.exe cursor --capture redacted"
        ));
        assert!(!is_legacy_command(
            "/usr/bin/lodeline-hook claude-code --capture raw"
        ));
        assert!(!is_legacy_command(
            "/opt/my-sigil-hook claude-code --capture raw"
        ));
        assert!(!is_legacy_command("/opt/other/sigil-hook --verbose"));
        assert!(!is_legacy_command("./audit.sh sigil-hook --capture raw"));
    }

    #[test]
    fn install_replaces_old_entry_and_keeps_other_hooks() {
        let mut root = json!({ "theme": "dark", "hooks": {
            "PostToolUse": [nested(&[OLD])],
            "PreToolUse": [nested(&["./mine.sh"]), nested(&[OLD])],
        }});
        assert!(merge_into(&mut root, NEW_EXE, "claude-code", "redacted"));
        assert_eq!(
            root["hooks"]["PreToolUse"],
            json!([
                nested(&["./mine.sh"]),
                nested(&["/usr/bin/lodeline-hook claude-code --capture redacted"]),
            ])
        );
        assert_eq!(root["theme"], "dark");
        assert_eq!(root["hooks"]["PostToolUse"], json!([nested(&[OLD])]));
    }

    #[test]
    fn rerun_changes_nothing() {
        let mut root = json!({ "hooks": { "PreToolUse": [nested(&[OLD])] } });
        assert!(merge_into(&mut root, NEW_EXE, "codex", "redacted"));
        let after_first = root.clone();
        assert!(!merge_into(&mut root, NEW_EXE, "codex", "redacted"));
        assert_eq!(root, after_first);
    }

    #[test]
    fn new_entry_already_present_loses_only_the_old_duplicate() {
        let new = "/usr/bin/lodeline-hook codex --capture redacted";
        let mut root = json!({ "hooks": { "PreToolUse": [nested(&[new]), nested(&[OLD])] } });
        assert!(merge_into(&mut root, NEW_EXE, "codex", "redacted"));
        assert_eq!(root["hooks"]["PreToolUse"], json!([nested(&[new])]));
    }

    #[test]
    fn a_user_hook_sharing_the_entry_survives() {
        let mut root = json!({ "hooks": { "PreToolUse": [nested(&["./mine.sh", OLD])] } });
        assert_eq!(strip_entries(&mut root, "claude-code"), 1);
        assert_eq!(root["hooks"]["PreToolUse"], json!([nested(&["./mine.sh"])]));
    }

    #[test]
    fn cursor_events_are_both_replaced() {
        let old = "/usr/bin/sigil-hook cursor --capture redacted";
        let mut root = json!({ "version": 1, "hooks": {
            "beforeShellExecution": [{ "command": old }, { "command": "./mine" }],
            "beforeMCPExecution": [{ "command": old }],
        }});
        assert!(merge_into_enforce(
            &mut root, NEW_EXE, "cursor", "redacted", "open"
        ));
        let shell = root["hooks"]["beforeShellExecution"].as_array().unwrap();
        assert_eq!(shell[0]["command"], "./mine");
        assert_eq!(shell.len(), 2);
        assert_eq!(
            root["hooks"]["beforeMCPExecution"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(count_entries(&root, "cursor"), 0);
    }

    #[test]
    fn uninstall_removes_old_entries_too() {
        let mut root =
            json!({ "hooks": { "PreToolUse": [nested(&[OLD]), nested(&["./mine.sh"])] } });
        assert_eq!(count_entries(&root, "claude-code"), 1);
        assert!(remove_from(&mut root, NEW_EXE, "claude-code"));
        assert_eq!(root["hooks"]["PreToolUse"], json!([nested(&["./mine.sh"])]));
    }

    #[test]
    fn absent_hooks_stay_absent() {
        let mut root = json!({ "theme": "dark" });
        assert_eq!(strip_entries(&mut root, "claude-code"), 0);
        assert_eq!(root, json!({ "theme": "dark" }));
    }

    #[test]
    fn grok_file_goes_when_only_ours_and_is_rewritten_when_shared() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sigil-hook.json");
        let old = "/usr/bin/sigil-hook grok --capture redacted";
        let ours = json!({ "hooks": { "PreToolUse": [nested(&[old])] } });
        std::fs::write(&path, ours.to_string()).unwrap();
        assert!(retire_grok_file(&path).unwrap());
        assert!(!path.exists());
        assert!(!retire_grok_file(&path).unwrap());

        let shared = json!({ "hooks": { "PreToolUse": [nested(&[old, "./mine.sh"])] } });
        std::fs::write(&path, shared.to_string()).unwrap();
        assert!(retire_grok_file(&path).unwrap());
        let left: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(left["hooks"]["PreToolUse"], json!([nested(&["./mine.sh"])]));

        std::fs::write(&path, "not json").unwrap();
        assert!(!retire_grok_file(&path).unwrap());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "not json");
    }
}
