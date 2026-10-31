//! Phase 3b.6 — Continue.dev (VSCode/JetBrains 확장) parser. Reads the
//! user-global `~/.continue/config.json` and maps mcpServers /
//! customCommands to `AiGuardReason`.
//!
//! Schema notes: Continue's config.json has evolved across versions.
//! Top-level `mcpServers` is observed as both an object map ({"name": {...}})
//! and an array of {"name": "...", ...} objects in the wild. The parser
//! handles both shapes. Other surfaces (models, contextProviders, rules)
//! are deliberately out of scope for Phase 3b.6.
//!
//! Continue uses nothing but the `name`, `description` and `params` of a
//! `slashCommands` entry: its schema says `step` "has no effect", and the
//! name picks a built-in. A custom command is `{name, prompt, description}`,
//! so its `prompt` is the only text here that reaches the model.

use crate::ai_guard::parser::{AiGuardParser, AssessError};
use crate::ai_guard::rubric;
use lodeline_core::event::{AiGuardReason, AiGuardScope, AiTool};
use serde_json::Value;
use std::path::{Path, PathBuf};

pub struct ContinueDevParser;

impl AiGuardParser for ContinueDevParser {
    fn tool(&self) -> AiTool {
        AiTool::ContinueDev
    }

    fn scope(&self) -> AiGuardScope {
        AiGuardScope::Application {
            app: "continue".into(),
        }
    }

    fn watched_paths(&self, home_dir: &Path) -> Vec<PathBuf> {
        vec![home_dir.join(".continue").join("config.json")]
    }

    fn assess(&self, home_dir: &Path) -> Result<Vec<AiGuardReason>, AssessError> {
        let path = home_dir.join(".continue").join("config.json");
        let Some(val) = super::read_json_optional(&path)? else {
            return Ok(Vec::new());
        };
        let mut out = Vec::new();
        emit_mcp_reasons(&val, &mut out);
        emit_custom_command_reasons(&val, &mut out);
        Ok(out)
    }
}

/// Continue mcpServers shape varies between v1 (object map keyed by name)
/// and v2 (array of objects with `name` field). Handle both.
pub(crate) fn emit_mcp_reasons(settings: &Value, out: &mut Vec<AiGuardReason>) {
    let Some(node) = settings.get("mcpServers") else {
        return;
    };
    if let Some(obj) = node.as_object() {
        for (name, def) in obj {
            emit_one_mcp(name, def, out);
        }
    } else if let Some(arr) = node.as_array() {
        for def in arr {
            let name = def
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("(unnamed)");
            emit_one_mcp(name, def, out);
        }
    }
}

fn emit_one_mcp(name: &str, def: &Value, out: &mut Vec<AiGuardReason>) {
    super::mcp_scan::emit_one_server(name, def, out);
}

pub(crate) fn emit_custom_command_reasons(settings: &Value, out: &mut Vec<AiGuardReason>) {
    let Some(arr) = settings.get("customCommands").and_then(Value::as_array) else {
        return;
    };
    for prompt in arr
        .iter()
        .filter_map(|entry| entry.get("prompt").and_then(Value::as_str))
    {
        if let Some(pat) = rubric::first_destructive_pattern(prompt) {
            out.push(AiGuardReason::DestructiveInInlineCommand {
                pattern: pat.to_string(),
                hook_event: "custom_command".to_string(),
                snippet: prompt.chars().take(80).collect(),
            });
        }
    }
}

/// Phase 3b.6.1 — per-repo Continue.dev parser. Spawned by runtime /
/// policy_reload after discovery; each instance carries its own repo
/// root and emits AiGuardRiskAssessed with scope=Project{path:repo_root}.
pub struct ContinueDevProjectParser {
    pub repo_root: PathBuf,
}

impl AiGuardParser for ContinueDevProjectParser {
    fn tool(&self) -> AiTool {
        AiTool::ContinueDev
    }

    fn scope(&self) -> AiGuardScope {
        AiGuardScope::Project {
            path: self.repo_root.clone(),
        }
    }

    fn watched_paths(&self, _home_dir: &Path) -> Vec<PathBuf> {
        vec![self.repo_root.join(".continue").join("config.json")]
    }

    fn assess(&self, _home_dir: &Path) -> Result<Vec<AiGuardReason>, AssessError> {
        let path = self.repo_root.join(".continue").join("config.json");
        let Some(val) = super::read_json_optional(&path)? else {
            return Ok(Vec::new());
        };
        let mut out = Vec::new();
        emit_mcp_reasons(&val, &mut out);
        // #154 Option B — Continue auto-loads repo-local `.continue/` config and
        // spawns its mcpServers (StdioClientTransport) on workspace config load
        // with NO per-server approval (source-verified: MCPManagerSingleton marks
        // new servers refresh=true -> refreshConnections -> connectClient). The
        // only gate is VS Code Workspace Trust (absent in JetBrains) — the same
        // one-keypress folder-trust trigger TrustFall describes. Amplify off the
        // MCP-only reasons here, BEFORE the custom-command prompt reasons
        // (which can also emit DestructiveInInlineCommand) join `out`.
        if super::mcp_scan::has_local_or_risky_mcp(&out) {
            out.push(AiGuardReason::ProjectMcpAutoEnabled {
                mechanism: "folder-trust autorun (default)".to_string(),
            });
        }
        emit_custom_command_reasons(&val, &mut out);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn write_config(home: &Path, contents: &str) -> PathBuf {
        let dir = home.join(".continue");
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("config.json");
        std::fs::write(&p, contents).unwrap();
        p
    }

    #[test]
    fn empty_config_is_clean() {
        let dir = tempdir().unwrap();
        write_config(dir.path(), "");
        let p = ContinueDevParser;
        assert!(p.assess(dir.path()).unwrap().is_empty());
    }

    #[test]
    fn whitespace_config_is_clean() {
        let dir = tempdir().unwrap();
        write_config(dir.path(), "  \n\t ");
        let p = ContinueDevParser;
        assert!(p.assess(dir.path()).unwrap().is_empty());
    }

    #[test]
    fn missing_config_returns_empty_vec() {
        let dir = tempdir().unwrap();
        let p = ContinueDevParser;
        assert!(p.assess(dir.path()).unwrap().is_empty());
    }

    #[test]
    fn empty_object_returns_empty_vec() {
        let dir = tempdir().unwrap();
        write_config(dir.path(), "{}");
        let p = ContinueDevParser;
        assert!(p.assess(dir.path()).unwrap().is_empty());
    }

    #[test]
    fn corrupt_json_returns_parse_error() {
        let dir = tempdir().unwrap();
        write_config(dir.path(), "{ not json");
        let p = ContinueDevParser;
        let err = p.assess(dir.path()).unwrap_err();
        assert!(matches!(err, AssessError::Parse { .. }), "got {err:?}");
    }

    #[test]
    fn mcp_object_form_local_command_emits_no_sandbox() {
        let dir = tempdir().unwrap();
        write_config(
            dir.path(),
            r#"{"mcpServers": {"fs": {"command": "node", "args": ["mcp.js"]}}}"#,
        );
        let p = ContinueDevParser;
        let reasons = p.assess(dir.path()).unwrap();
        assert!(reasons.iter().any(|r| matches!(
            r,
            AiGuardReason::NoSandbox { executor } if executor == "mcp_command"
        )));
        assert!(
            reasons
                .iter()
                .any(|r| matches!(r, AiGuardReason::McpServerLocalCommand { .. })),
            "#125: expected McpServerLocalCommand in {reasons:?}"
        );
    }

    #[test]
    fn mcp_array_form_local_command_emits_no_sandbox() {
        let dir = tempdir().unwrap();
        write_config(
            dir.path(),
            r#"{"mcpServers": [{"name": "fs", "command": "node", "args": ["mcp.js"]}]}"#,
        );
        let p = ContinueDevParser;
        let reasons = p.assess(dir.path()).unwrap();
        assert!(reasons.iter().any(|r| matches!(
            r,
            AiGuardReason::NoSandbox { executor } if executor == "mcp_command"
        )));
        assert!(
            reasons
                .iter()
                .any(|r| matches!(r, AiGuardReason::McpServerLocalCommand { .. })),
            "#125: expected McpServerLocalCommand in {reasons:?}"
        );
    }

    #[test]
    fn mcp_remote_url_emits_remote() {
        let dir = tempdir().unwrap();
        write_config(
            dir.path(),
            r#"{"mcpServers": [{"name": "remote", "url": "https://mcp.example.com"}]}"#,
        );
        let p = ContinueDevParser;
        let reasons = p.assess(dir.path()).unwrap();
        assert!(reasons.iter().any(|r| matches!(
            r,
            AiGuardReason::McpServerRemote { server_name, url }
                if server_name == "remote" && url == "https://mcp.example.com"
        )));
    }

    #[test]
    fn mcp_uppercase_scheme_emits_remote() {
        let dir = tempdir().unwrap();
        write_config(
            dir.path(),
            r#"{"mcpServers": [{"name": "remote", "url": "HtTpS://mcp.example.com"}]}"#,
        );
        let p = ContinueDevParser;
        let reasons = p.assess(dir.path()).unwrap();
        assert!(
            reasons.iter().any(|r| matches!(
                r,
                AiGuardReason::McpServerRemote { server_name, .. }
                    if server_name == "remote"
            )),
            "expected McpServerRemote for HtTpS:// (mixed-case) url, got {reasons:?}"
        );
    }

    #[test]
    fn custom_command_prompt_with_destructive_pattern_emits_destructive() {
        let dir = tempdir().unwrap();
        write_config(
            dir.path(),
            r#"{"customCommands": [{"name": "danger", "prompt": "rm -rf /tmp/lodeline-test"}]}"#,
        );
        let p = ContinueDevParser;
        let reasons = p.assess(dir.path()).unwrap();
        assert!(reasons.iter().any(|r| matches!(
            r,
            AiGuardReason::DestructiveInInlineCommand { hook_event, .. }
                if hook_event == "custom_command"
        )));
    }

    #[test]
    fn fields_continue_does_not_run_are_not_assessed() {
        let dir = tempdir().unwrap();
        let script = dir.path().join("step.sh");
        std::fs::write(&script, "#!/bin/sh\nrm -rf ~/work\n").unwrap();
        let config = serde_json::json!({
            "slashCommands": [
                {"name": "lint", "step": script},
                {"name": "danger", "run": "rm -rf /tmp/lodeline-test"},
                {"name": "edit", "prompt": "rm -rf /tmp/lodeline-test"}
            ],
            "customCommands": [
                {"name": "x", "prompt": "Explain this", "command": "rm -rf /tmp/lodeline-test"}
            ]
        });
        write_config(dir.path(), &config.to_string());
        let p = ContinueDevParser;
        assert!(p.assess(dir.path()).unwrap().is_empty());
        assert!(p.collect_external_script_paths(dir.path()).is_empty());
        let project = ContinueDevProjectParser {
            repo_root: dir.path().to_path_buf(),
        };
        assert!(project.assess(dir.path()).unwrap().is_empty());
        assert!(project.collect_external_script_paths(dir.path()).is_empty());
    }

    #[test]
    fn safe_custom_command_emits_nothing() {
        let dir = tempdir().unwrap();
        write_config(
            dir.path(),
            r#"{"customCommands": [{"name": "ok", "prompt": "echo hello"}]}"#,
        );
        let p = ContinueDevParser;
        let reasons = p.assess(dir.path()).unwrap();
        assert!(reasons.is_empty(), "got {reasons:?}");
    }

    #[test]
    fn scope_is_application_continue() {
        let p = ContinueDevParser;
        assert_eq!(
            p.scope(),
            AiGuardScope::Application {
                app: "continue".into()
            }
        );
    }

    #[test]
    fn tool_is_continue_dev() {
        let p = ContinueDevParser;
        assert_eq!(p.tool(), AiTool::ContinueDev);
    }

    #[test]
    fn project_parser_missing_config_returns_empty() {
        let dir = tempdir().unwrap();
        let p = ContinueDevProjectParser {
            repo_root: dir.path().to_path_buf(),
        };
        assert!(p
            .assess(std::path::Path::new("/unused"))
            .unwrap()
            .is_empty());
    }

    #[test]
    fn project_parser_destructive_custom_command_is_detected() {
        let dir = tempdir().unwrap();
        let repo = dir.path().join("repoX");
        let cdir = repo.join(".continue");
        std::fs::create_dir_all(&cdir).unwrap();
        std::fs::write(
            cdir.join("config.json"),
            r#"{"customCommands": [{"name": "danger", "prompt": "rm -rf /tmp/lodeline-3b6.1"}]}"#,
        )
        .unwrap();
        let p = ContinueDevProjectParser {
            repo_root: repo.clone(),
        };
        let reasons = p.assess(std::path::Path::new("/unused")).unwrap();
        assert!(reasons.iter().any(|r| matches!(
            r,
            AiGuardReason::DestructiveInInlineCommand { hook_event, .. }
                if hook_event == "custom_command"
        )));
    }

    #[test]
    fn project_parser_scope_is_project_with_repo_root_path() {
        let dir = tempdir().unwrap();
        let repo = dir.path().to_path_buf();
        let p = ContinueDevProjectParser {
            repo_root: repo.clone(),
        };
        assert_eq!(p.scope(), AiGuardScope::Project { path: repo });
    }

    #[test]
    fn project_parser_tool_is_continue_dev_same_as_user_global() {
        let p = ContinueDevProjectParser {
            repo_root: std::path::PathBuf::from("/x"),
        };
        assert_eq!(p.tool(), AiTool::ContinueDev);
    }

    #[test]
    fn mcp_object_form_emits_local_command_reason() {
        let dir = tempdir().unwrap();
        write_config(
            dir.path(),
            r#"{"mcpServers": {"fs": {"command": "/tmp/x", "args": ["m.js"]}}}"#,
        );
        let reasons = ContinueDevParser.assess(dir.path()).unwrap();
        assert!(
            reasons.iter().any(|r| matches!(r,
            AiGuardReason::McpServerLocalCommand { server_name, .. } if server_name=="fs")),
            "expected McpServerLocalCommand in {reasons:?}"
        );
    }

    #[test]
    fn mcp_array_form_emits_local_command_reason() {
        let dir = tempdir().unwrap();
        write_config(
            dir.path(),
            r#"{"mcpServers": [{"name": "fs", "command": "/tmp/x", "args": ["m.js"]}]}"#,
        );
        let reasons = ContinueDevParser.assess(dir.path()).unwrap();
        assert!(reasons.iter().any(|r| matches!(r,
            AiGuardReason::McpServerLocalCommand { server_name, .. } if server_name=="fs")));
    }

    #[test]
    fn project_parser_corrupt_json_returns_parse_error() {
        let dir = tempdir().unwrap();
        let repo = dir.path();
        std::fs::create_dir_all(repo.join(".continue")).unwrap();
        std::fs::write(repo.join(".continue").join("config.json"), "{ not json").unwrap();
        let p = ContinueDevProjectParser {
            repo_root: repo.to_path_buf(),
        };
        let err = p.assess(std::path::Path::new("/unused")).unwrap_err();
        assert!(matches!(err, AssessError::Parse { .. }), "got {err:?}");
    }

    fn write_project_config(repo: &Path, body: &str) {
        let cd = repo.join(".continue");
        std::fs::create_dir_all(&cd).unwrap();
        std::fs::write(cd.join("config.json"), body).unwrap();
    }

    #[test]
    fn project_local_mcp_emits_auto_enabled() {
        // #154: a repo-committed local-command MCP server -> ProjectMcpAutoEnabled
        // (Continue auto-spawns it on workspace config load, no per-server prompt).
        let dir = tempdir().unwrap();
        write_project_config(
            dir.path(),
            r#"{"mcpServers": {"fs": {"command": "/tmp/x", "args": ["m.js"]}}}"#,
        );
        let out = ContinueDevProjectParser {
            repo_root: dir.path().to_path_buf(),
        }
        .assess(std::path::Path::new("/unused"))
        .unwrap();
        assert!(
            out.iter().any(|r| matches!(
                r, AiGuardReason::ProjectMcpAutoEnabled { mechanism }
                    if mechanism == "folder-trust autorun (default)"
            )),
            "got {out:?}"
        );
    }

    #[test]
    fn project_benign_remote_mcp_no_auto_enabled() {
        // #154: remote-only project MCP launches no local code -> no amplify.
        let dir = tempdir().unwrap();
        write_project_config(
            dir.path(),
            r#"{"mcpServers": {"r": {"url": "https://api.example/mcp"}}}"#,
        );
        let out = ContinueDevProjectParser {
            repo_root: dir.path().to_path_buf(),
        }
        .assess(std::path::Path::new("/unused"))
        .unwrap();
        assert!(
            !out.iter()
                .any(|r| matches!(r, AiGuardReason::ProjectMcpAutoEnabled { .. })),
            "benign remote must not amplify; got {out:?}"
        );
    }

    #[test]
    fn project_amplifier_ignores_non_mcp_destructive_reasons() {
        // #154: the amplifier keys only on MCP-derived reasons. A destructive
        // custom command alongside a benign remote-only MCP must NOT auto-enable.
        let dir = tempdir().unwrap();
        write_project_config(
            dir.path(),
            r#"{"mcpServers": {"r": {"url": "https://api.example/mcp"}},
                "customCommands": [{"name": "danger", "prompt": "rm -rf /tmp/lodeline-test"}]}"#,
        );
        let out = ContinueDevProjectParser {
            repo_root: dir.path().to_path_buf(),
        }
        .assess(std::path::Path::new("/unused"))
        .unwrap();
        // Sanity: the destructive custom-command reason IS present (test is real)…
        assert!(
            out.iter().any(|r| matches!(
                r, AiGuardReason::DestructiveInInlineCommand { hook_event, .. }
                    if hook_event == "custom_command"
            )),
            "fixture should produce a destructive custom-command reason; got {out:?}"
        );
        // …but it must NOT be mistaken for an auto-launching project MCP.
        assert!(
            !out.iter()
                .any(|r| matches!(r, AiGuardReason::ProjectMcpAutoEnabled { .. })),
            "destructive custom command (not MCP) must not trigger the amplifier; got {out:?}"
        );
    }
}
