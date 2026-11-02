use super::HookAdapter;
use crate::redact::capture;
use lodeline_core::event::AiTool;
use lodeline_core::hook_proto::*;
use std::path::{Component, Path, PathBuf};

/// Codex CLI `PreToolUse` hook. Codex deliberately reuses the Claude Code hook
/// shape (`tool_name` / `tool_input` / `tool_use_id`, plus `turn_id` and a
/// Codex-only `permission_mode`), so this mirrors the Claude adapter. Measured
/// on codex-cli 0.164.0: the shell tool arrives as `Bash` and edits as
/// `apply_patch`, and both carry their text in `tool_input.command`.
pub struct Codex;

/// Target paths of an apply_patch body, read the way codex rust-v0.166.0
/// (parser.rs, streaming_parser.rs) reads them: headers match the trimmed line,
/// but inside an Update hunk only trailing space is trimmed, so ` *** Add File:`
/// there is a context line. `*** Move to:` counts only right after its Update
/// header. Body lines start with `+`, `-`, ` ` or `@@` and are never headers.
fn patch_paths(patch: &str) -> Vec<&str> {
    let lines: Vec<&str> = patch.trim().lines().collect();
    // Codex's lenient mode also takes the patch wrapped in a heredoc.
    let lines = match lines.as_slice() {
        [first, inner @ .., last]
            if matches!(*first, "<<EOF" | "<<'EOF'" | "<<\"EOF\"")
                && last.ends_with("EOF")
                && inner.len() >= 2 =>
        {
            inner
        }
        all => all,
    };
    let mut paths = Vec::new();
    let (mut in_update, mut after_update_header) = (false, false);
    for line in lines
        .iter()
        .skip_while(|l| l.trim() != "*** Begin Patch")
        .skip(1)
    {
        let l = if in_update {
            line.trim_end()
        } else {
            line.trim()
        };
        if l == "*** End Patch" {
            break;
        }
        let move_to = after_update_header.then(|| l.strip_prefix("*** Move to: "));
        after_update_header = false;
        if let Some(path) = move_to.flatten() {
            paths.push(path);
        } else if let Some(path) = l.strip_prefix("*** Update File: ") {
            (in_update, after_update_header) = (true, true);
            paths.push(path);
        } else if let Some(path) = l
            .strip_prefix("*** Add File: ")
            .or_else(|| l.strip_prefix("*** Delete File: "))
        {
            in_update = false;
            paths.push(path);
        }
    }
    paths
}

/// `path` joined onto `cwd` when relative, with `.` and `..` folded lexically
/// (no filesystem access), so rules on absolute paths see what Codex writes.
fn resolve(cwd: Option<&str>, path: &str) -> String {
    let joined = match cwd {
        Some(cwd) => Path::new(cwd).join(path),
        None => return path.to_string(),
    };
    let mut out = PathBuf::new();
    for c in joined.components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            c => out.push(c),
        }
    }
    out.to_string_lossy().into_owned()
}

impl HookAdapter for Codex {
    fn agent(&self) -> AiTool {
        AiTool::Codex
    }

    fn normalize(
        &self,
        p: &serde_json::Value,
        level: CaptureLevel,
    ) -> Result<HookInvocation, CaptureStatus> {
        let tool = p
            .get("tool_name")
            .and_then(|v| v.as_str())
            .ok_or(CaptureStatus::Malformed)?;
        let input = p
            .get("tool_input")
            .cloned()
            .unwrap_or(serde_json::Value::Null);

        let action = if let Some(rest) = tool.strip_prefix("mcp__") {
            let mut it = rest.splitn(2, "__");
            let server = it.next().unwrap_or("").to_string();
            let mcp_tool = it.next().unwrap_or("").to_string();
            let args = serde_json::to_string(&input).unwrap_or_default();
            let c = capture(&args, level);
            HookAction::McpCall {
                server,
                tool: mcp_tool,
                args_hash: c.hash,
                args_preview: c.preview,
            }
        } else if tool == "apply_patch" {
            let patch = input.get("command").and_then(|v| v.as_str()).unwrap_or("");
            let cwd = p.get("cwd").and_then(|v| v.as_str());
            let paths = patch_paths(patch)
                .into_iter()
                .map(|path| resolve(cwd, path));
            super::file_edit(paths.collect(), level)
        } else if let Some(cmd) = input.get("command").and_then(|v| v.as_str()) {
            // Shell tool — keyed on the command field, not the exact tool_name.
            let c = capture(cmd, level);
            HookAction::Bash {
                command_hash: c.hash,
                command_preview: c.preview,
            }
        } else if matches!(tool, "Edit" | "Write") || input.get("file_path").is_some() {
            let path = input
                .get("file_path")
                .and_then(|v| v.as_str())
                .unwrap_or(tool);
            super::file_edit(vec![path.to_string()], level)
        } else {
            let detail = serde_json::to_string(&input).unwrap_or_default();
            let c = capture(&detail, level);
            HookAction::Other {
                label: tool.to_string(),
                detail_hash: c.hash,
                detail_preview: c.preview,
            }
        };

        Ok(HookInvocation {
            agent: AiTool::Codex,
            // Codex provides `session_id`; fall back to `turn_id` for correlation.
            agent_session_id: p
                .get("session_id")
                .and_then(|v| v.as_str())
                .or_else(|| p.get("turn_id").and_then(|v| v.as_str()))
                .map(String::from),
            tool_use_id: p
                .get("tool_use_id")
                .and_then(|v| v.as_str())
                .map(String::from),
            action,
            capture_level: level,
            capture_status: CaptureStatus::Ok,
            cwd: p.get("cwd").and_then(|v| v.as_str()).map(String::from),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_shell_command() {
        let p = serde_json::json!({
            "session_id":"s1","tool_use_id":"t1","turn_id":"turn1","cwd":"/repo",
            "tool_name":"shell","tool_input":{"command":"cargo test"}
        });
        let inv = Codex.normalize(&p, CaptureLevel::Redacted).unwrap();
        assert_eq!(inv.agent, AiTool::Codex);
        assert_eq!(inv.agent_session_id.as_deref(), Some("s1"));
        match inv.action {
            HookAction::Bash {
                command_preview, ..
            } => assert_eq!(command_preview.unwrap(), "cargo test"),
            _ => panic!("expected Bash"),
        }
    }

    #[test]
    fn falls_back_to_turn_id_for_session() {
        let p = serde_json::json!({
            "turn_id":"turn9","tool_name":"shell","tool_input":{"command":"ls"}
        });
        let inv = Codex.normalize(&p, CaptureLevel::Redacted).unwrap();
        assert_eq!(inv.agent_session_id.as_deref(), Some("turn9"));
    }

    #[test]
    fn normalizes_mcp_tool() {
        let p = serde_json::json!({
            "tool_name":"mcp__github__create_issue","tool_input":{"title":"x"}
        });
        match Codex.normalize(&p, CaptureLevel::Redacted).unwrap().action {
            HookAction::McpCall { server, tool, .. } => {
                assert_eq!(server, "github");
                assert_eq!(tool, "create_issue");
            }
            _ => panic!("expected McpCall"),
        }
    }

    fn patch_preview(p: serde_json::Value) -> String {
        match Codex.normalize(&p, CaptureLevel::Raw).unwrap().action {
            HookAction::FileEdit { path_preview, .. } => path_preview.unwrap(),
            other => panic!("expected FileEdit, got {other:?}"),
        }
    }

    // Shape captured from codex-cli 0.164.0 `codex exec`: the patch text rides
    // in `tool_input.command`, the same field the shell tool uses.
    #[test]
    fn apply_patch_is_file_edit_on_header_paths() {
        let p = serde_json::json!({
            "tool_name":"apply_patch","tool_input":{"command":
                "*** Begin Patch\n*** Update File: /repo/a.txt\n*** Move to: /repo/c.txt\n\
                 @@\n-rm -rf /\n+hello\n*** Add File: /repo/b.txt\n+*** Delete File: /etc/x\n\
                 *** Delete File: /repo/old.txt\n*** End Patch"}
        });
        assert_eq!(
            patch_preview(p),
            "/repo/a.txt\n/repo/c.txt\n/repo/b.txt\n/repo/old.txt"
        );
    }

    // codex rust-v0.166.0 streaming_parser.rs: headers match the trimmed line,
    // except inside an Update hunk, where only trailing space is trimmed and a
    // line with a leading space is a context line.
    #[test]
    fn apply_patch_headers_follow_codex_whitespace_rules() {
        let p = serde_json::json!({
            "tool_name":"apply_patch","tool_input":{"command":
                "*** Begin Patch\n \t*** Add File: /etc/x\n+hi\n*** Update File: /repo/a.txt  \n\
                 *** Move to: /repo/c.txt \n@@\n-old\n *** Update File: /etc/context-only\n+new\n\
                 *** Delete File: /repo/old.txt\t\n*** End Patch\n"}
        });
        assert_eq!(
            patch_preview(p),
            "/etc/x\n/repo/a.txt\n/repo/c.txt\n/repo/old.txt"
        );
    }

    #[test]
    fn apply_patch_reads_codex_heredoc_wrapper() {
        let p = serde_json::json!({
            "tool_name":"apply_patch","tool_input":{"command":
                "<<'EOF'\n*** Begin Patch\n*** Add File: /etc/x\n+hi\n*** End Patch\nEOF\n"}
        });
        assert_eq!(patch_preview(p), "/etc/x");
    }

    // Paths on Windows are not `/`-rooted, so the expected strings are Unix only.
    #[cfg(unix)]
    #[test]
    fn apply_patch_resolves_relative_paths_against_cwd() {
        let p = serde_json::json!({
            "cwd":"/repo/sub","tool_name":"apply_patch","tool_input":{"command":
                "*** Begin Patch\n*** Add File: .env\n+X=1\n*** Update File: ../lib/x.rs\n\
                 *** Move to: ./y/../z.rs\n@@\n-a\n+b\n*** Delete File: /abs/old\n*** End Patch"}
        });
        assert_eq!(
            patch_preview(p),
            "/repo/sub/.env\n/repo/lib/x.rs\n/repo/sub/z.rs\n/abs/old"
        );
    }

    #[test]
    fn unknown_tool_is_other() {
        let p = serde_json::json!({"tool_name":"update_plan","tool_input":{"plan":"x"}});
        match Codex.normalize(&p, CaptureLevel::Redacted).unwrap().action {
            HookAction::Other { label, .. } => assert_eq!(label, "update_plan"),
            _ => panic!("expected Other"),
        }
    }
}
