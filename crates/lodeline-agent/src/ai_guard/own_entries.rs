//! Recognises Lodeline's own hook and MCP registrations, including the names
//! they carried before the rename, so a host is not scored for the tool that
//! measures it. An upgraded host keeps its old entries until `lodeline-hook
//! install` rewrites them, and their command no longer exists by then.
//!
//! A name is cheap to fake, so this only removes the findings that say "this is
//! a local command we did not read". The content scan of a hook script and the
//! launcher-shape checks of an MCP server still run.

const HOOK_BINARIES: [&str; 2] = ["lodeline-hook", "sigil-hook"];
const MCP_BINARIES: [&str; 2] = ["lodeline-mcp", "sigil-mcp"];
const MCP_SERVER_NAMES: [&str; 4] = [
    "lodeline-check",
    "lodeline-fleet",
    "sigil-check",
    "sigil-fleet",
];

fn binary_name(path: &str) -> &str {
    let name = path.rsplit(['/', '\\']).next().unwrap_or(path);
    name.strip_suffix(".exe").unwrap_or(name)
}

/// `<path>/lodeline-hook <agent> ... --capture <mode>`, the shape install writes.
pub(crate) fn is_own_hook_command(cmd: &str) -> bool {
    let mut tokens = cmd.split_whitespace();
    tokens
        .next()
        .is_some_and(|exe| HOOK_BINARIES.contains(&binary_name(exe)))
        && tokens.any(|t| t == "--capture")
}

/// An MCP entry under one of our server names that runs our binary.
pub(crate) fn is_own_mcp_server(name: &str, command: &str) -> bool {
    MCP_SERVER_NAMES.contains(&name) && MCP_BINARIES.contains(&binary_name(command))
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
        assert!(!is_own_hook_command("/usr/bin/sigil-hook"));
        assert!(!is_own_hook_command("/tmp/evil.sh --capture raw"));
        assert!(!is_own_hook_command("sh -c 'sigil-hook --capture raw'"));
    }

    #[test]
    fn old_hook_with_a_removed_binary_is_not_a_finding() {
        for cmd in [
            "/nonexistent/sigil-hook claude-code --capture redacted",
            "/nonexistent/lodeline-hook codex --enforce --capture raw",
        ] {
            let mut out = Vec::new();
            classify_command(cmd, "PreToolUse", &mut out);
            assert!(out.is_empty(), "{cmd}: {out:?}");
        }
    }

    #[test]
    fn another_missing_script_is_still_a_finding() {
        let mut out = Vec::new();
        classify_command(
            "/nonexistent/other-hook --capture raw",
            "PreToolUse",
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
        classify_command(&cmd, "PreToolUse", &mut out);
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
}
