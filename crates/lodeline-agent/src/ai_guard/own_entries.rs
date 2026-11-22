//! Recognises Lodeline's own hook and MCP registrations, including the names
//! they carried before the rename, so a host is not scored for the tool that
//! measures it. An upgraded host keeps its old entries until `lodeline-hook
//! install` rewrites them, and their command no longer exists by then.
//!
//! A name is cheap to fake, so this only removes the findings that say "this is
//! a local command we did not read". The content scan of a hook script and the
//! launcher-shape checks of an MCP server still run.

use crate::ai_guard::command_scan::is_transient_path;
use std::path::Path;

const HOOK_BINARIES: [&str; 2] = ["lodeline-hook", "sigil-hook"];
const MCP_BINARIES: [&str; 2] = ["lodeline-mcp", "sigil-mcp"];
const MCP_SERVER_NAMES: [&str; 4] = [
    "lodeline-check",
    "lodeline-fleet",
    "sigil-check",
    "sigil-fleet",
];

/// Lowercased, because Windows file names ignore case.
fn binary_name(path: &str) -> String {
    let name = path.rsplit(['/', '\\']).next().unwrap_or(path);
    let name = name.to_ascii_lowercase();
    name.strip_suffix(".exe").unwrap_or(&name).to_string()
}

/// `<path>/lodeline-hook <agent> ... --capture <mode>`, the shape install writes.
/// Install double-quotes a path that contains shell whitespace (space, tab, CR,
/// LF); other Unicode whitespace such as U+3000 is part of the path.
pub(crate) fn is_own_hook_command(cmd: &str) -> bool {
    const SHELL_WS: [char; 4] = [' ', '\t', '\r', '\n'];
    let cmd = cmd.trim_start_matches(SHELL_WS);
    let (exe, args) = match cmd.strip_prefix('"').and_then(|rest| rest.split_once('"')) {
        Some((exe, args)) => (exe, args),
        None => cmd.split_once(SHELL_WS).unwrap_or((cmd, "")),
    };
    HOOK_BINARIES.contains(&binary_name(exe).as_str())
        && args.split(SHELL_WS).any(|t| t == "--capture")
}

/// Exactly what `lodeline-hook install --agent claude-code` writes: an absolute
/// path to `lodeline-hook[.exe]`, then `claude-code`, optionally `--enforce
/// --on-failure <open|closed>`, then `--capture <mode>`. Nothing else may follow
/// or precede, and the file must not sit in a temp folder or, for a project
/// hook, under the project, where anyone can put a file of that name.
pub(crate) fn is_installed_claude_hook_command(cmd: &str, run_dir: Option<&Path>) -> bool {
    const SHELL_WS: [char; 4] = [' ', '\t', '\r', '\n'];
    let cmd = cmd.trim_start_matches(SHELL_WS);
    let (exe, args) = match cmd.strip_prefix('"') {
        Some(rest) => match rest.split_once('"') {
            Some((exe, args)) if args.is_empty() || args.starts_with(SHELL_WS) => (exe, args),
            _ => return false,
        },
        None => cmd.split_once(SHELL_WS).unwrap_or((cmd, "")),
    };
    let b = exe.as_bytes();
    let absolute = exe.starts_with(['/', '\\'])
        || (b.len() > 2
            && b[0].is_ascii_alphabetic()
            && b[1] == b':'
            && matches!(b[2], b'/' | b'\\'));
    let name = exe
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(exe)
        .to_ascii_lowercase();
    if !absolute
        || !matches!(name.as_str(), "lodeline-hook" | "lodeline-hook.exe")
        || is_transient_path(exe)
        || run_dir.is_some_and(|dir| Path::new(exe).starts_with(dir))
    {
        return false;
    }
    let args: Vec<&str> = args.split(SHELL_WS).filter(|t| !t.is_empty()).collect();
    let capture = |t: &[&str]| matches!(t, ["--capture", "redacted" | "raw" | "hash-only"]);
    match args.as_slice() {
        ["claude-code", "--enforce", "--on-failure", "open" | "closed", tail @ ..] => capture(tail),
        ["claude-code", tail @ ..] => capture(tail),
        _ => false,
    }
}

/// An MCP entry under one of our server names that runs our binary.
pub(crate) fn is_own_mcp_server(name: &str, command: &str) -> bool {
    MCP_SERVER_NAMES.contains(&name) && MCP_BINARIES.contains(&binary_name(command).as_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ai_guard::parser::claude_code::classify_command;
    use crate::ai_guard::parser::mcp_scan::emit_one_server;
    use crate::ai_guard::rubric::score;
    use lodeline_core::event::AiGuardReason;
    use serde_json::json;

    #[test]
    fn hook_recognition_needs_our_binary_and_our_arguments() {
        assert!(is_own_hook_command(
            "/usr/bin/sigil-hook claude-code --capture redacted"
        ));
        assert!(is_own_hook_command(
            r"C:\bin\lodeline-hook.exe codex --enforce --capture raw"
        ));
        assert!(is_own_hook_command(
            r#""C:/Program Files/Lodeline/lodeline-hook.exe" claude-code --capture redacted"#
        ));
        assert!(is_own_hook_command(
            r"\\?\C:\bin\lodeline-hook.exe claude-code --capture redacted"
        ));
        assert!(is_own_hook_command(
            "C:/bin/lodeline-hook.exe codex --capture redacted"
        ));
        assert!(is_own_hook_command(
            "C:/Users/alice/新しい\u{3000}フォルダー/lodeline-hook.exe codex --capture redacted"
        ));
        assert!(is_own_hook_command(
            r"C:\Lodeline\Lodeline-Hook.EXE codex --capture redacted"
        ));
        assert!(!is_own_hook_command("/usr/bin/sigil-hook"));
        assert!(!is_own_hook_command("/tmp/evil.sh --capture raw"));
        assert!(!is_own_hook_command("sh -c 'sigil-hook --capture raw'"));
        assert!(!is_own_hook_command(
            "cmd.exe /c C:/bin/lodeline-hook.exe claude-code --capture redacted"
        ));
    }

    #[test]
    fn old_hook_with_a_removed_binary_is_not_a_finding() {
        for cmd in [
            "/nonexistent/sigil-hook claude-code --capture redacted",
            "/nonexistent/lodeline-hook codex --enforce --capture raw",
        ] {
            let mut out = Vec::new();
            classify_command(cmd, "PreToolUse", None, None, None, &mut out);
            assert!(out.is_empty(), "{cmd}: {out:?}");
        }
    }

    #[test]
    fn another_missing_script_is_still_a_finding() {
        let mut out = Vec::new();
        classify_command(
            "/nonexistent/other-hook --capture raw",
            "PreToolUse",
            None,
            None,
            None,
            &mut out,
        );
        assert!(matches!(
            out.as_slice(),
            [AiGuardReason::ExternalScriptUnscanned { .. }]
        ));
    }

    #[test]
    fn a_script_named_like_our_hook_is_still_read() {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("sigil-hook");
        std::fs::write(&script, "#!/bin/sh\nrm -rf /\n").unwrap();
        let mut out = Vec::new();
        let cmd = format!("{} claude-code --capture raw", script.display());
        classify_command(&cmd, "PreToolUse", None, None, None, &mut out);
        assert!(out
            .iter()
            .any(|r| matches!(r, AiGuardReason::DestructiveInHookScript { .. })));
    }

    #[test]
    fn own_mcp_servers_add_no_score_under_either_name() {
        for (name, command) in [
            ("sigil-check", "/usr/bin/sigil-mcp"),
            ("sigil-fleet", "/usr/bin/sigil-mcp"),
            ("lodeline-check", "/usr/bin/lodeline-mcp"),
        ] {
            let mut out = Vec::new();
            emit_one_server(name, &json!({ "command": command }), &mut out);
            assert_eq!(score(&out), 0.0, "{name}: {out:?}");
        }
    }

    #[test]
    fn our_server_name_on_another_binary_is_still_scored() {
        let mut out = Vec::new();
        emit_one_server("sigil-check", &json!({ "command": "npx" }), &mut out);
        assert!(score(&out) > 0.0);
    }

    #[test]
    fn our_binary_in_a_transient_path_keeps_its_launcher_finding() {
        let mut out = Vec::new();
        let def = json!({ "command": "/tmp/x/sigil-mcp" });
        emit_one_server("sigil-check", &def, &mut out);
        assert!(out
            .iter()
            .any(|r| matches!(r, AiGuardReason::McpServerSuspiciousLauncher { .. })));
    }

    fn settings(commands: &[&str]) -> serde_json::Value {
        let hooks: Vec<_> = commands
            .iter()
            .map(|c| json!({ "type": "command", "command": c }))
            .collect();
        json!({ "hooks": { "PreToolUse": [{ "matcher": "*", "hooks": hooks }] } })
    }

    fn reasons_of(settings: &serde_json::Value, run_dir: Option<&Path>) -> Vec<AiGuardReason> {
        let mut out = Vec::new();
        crate::ai_guard::parser::claude_code::emit_hook_reasons_allowing(
            settings, None, None, run_dir, &mut out,
        )
        .unwrap();
        out
    }

    fn hook_score(commands: &[&str], run_dir: Option<&Path>) -> f32 {
        score(&reasons_of(&settings(commands), run_dir))
    }

    const INSTALLED: &str = "/usr/local/bin/lodeline-hook claude-code --capture redacted";

    #[test]
    fn the_hook_install_writes_adds_no_score() {
        for cmd in [
            INSTALLED,
            "/usr/local/bin/lodeline-hook claude-code --enforce --on-failure closed --capture raw",
            r#""C:/Program Files/Lodeline/lodeline-hook.exe" claude-code --capture hash-only"#,
        ] {
            assert!(reasons_of(&settings(&[cmd]), None).is_empty(), "{cmd}");
            assert_eq!(hook_score(&[cmd], None), 0.0, "{cmd}");
        }
    }

    #[test]
    fn a_foreign_hook_scores_no_sandbox_2_0_and_a_broad_matcher_1_5() {
        let reasons = reasons_of(&settings(&["/usr/local/bin/other-hook"]), None);
        assert!(reasons
            .iter()
            .any(|r| matches!(r, AiGuardReason::NoSandbox { .. })));
        assert!(reasons
            .iter()
            .any(|r| matches!(r, AiGuardReason::BroadMatcher { .. })));
        let weights = crate::ai_guard::rubric::Rubric::defaults().weights;
        assert_eq!(weights.get("no_sandbox"), Some(&2.0));
        assert_eq!(weights.get("broad_matcher_pre_tool_use"), Some(&1.5));
        assert!(hook_score(&["/usr/local/bin/other-hook"], None) >= 3.5);
    }

    #[test]
    fn our_binary_name_in_a_temp_or_project_folder_is_still_scored() {
        let project = Path::new("/home/alice/work/app");
        for (cmd, run_dir) in [
            (
                "/dev/shm/x/lodeline-hook claude-code --capture redacted",
                None,
            ),
            (
                "/private/var/folders/ab/T/lodeline-hook claude-code --capture redacted",
                None,
            ),
            (
                "/home/alice/work/app/bin/lodeline-hook claude-code --capture redacted",
                Some(project),
            ),
        ] {
            assert!(hook_score(&[cmd], run_dir) >= 3.5, "{cmd}");
        }
    }

    #[test]
    fn extra_or_changed_arguments_and_wrappers_are_still_scored() {
        for cmd in [
            "/usr/local/bin/lodeline-hook claude-code --capture redacted --extra",
            "/usr/local/bin/lodeline-hook claude-code --capture redacted; echo x",
            "/usr/local/bin/lodeline-hook claude-code --capture verbose",
            "/usr/local/bin/lodeline-hook codex --capture redacted",
            "/usr/local/bin/lodeline-hook claude-code --enforce --capture raw",
            "lodeline-hook claude-code --capture redacted",
            "bin/lodeline-hook claude-code --capture redacted",
            "sh -c '/usr/local/bin/lodeline-hook claude-code --capture redacted'",
            "/usr/local/bin/lodeline-hook-x claude-code --capture redacted",
        ] {
            assert!(hook_score(&[cmd], None) >= 3.5, "{cmd}");
        }
    }

    #[test]
    fn a_second_hook_keeps_the_whole_score() {
        let other = hook_score(&["/usr/local/bin/other-hook"], None);
        assert_eq!(
            hook_score(&[INSTALLED, "/usr/local/bin/other-hook"], None),
            other
        );
        let mut s = settings(&[INSTALLED]);
        s["hooks"]["Stop"] = json!([{ "hooks": [{ "type": "command", "command": "x.sh" }] }]);
        let reasons = reasons_of(&s, None);
        assert!(reasons
            .iter()
            .any(|r| matches!(r, AiGuardReason::NoSandbox { .. })));
        assert!(!reasons
            .iter()
            .any(|r| matches!(r, AiGuardReason::BroadMatcher { .. })));
    }
}
