//! #199 — MCP servers Claude Code stores in `~/.claude.json`: user scope at
//! the top-level `mcpServers`, local scope under `projects.<path>.mcpServers`.
//! The file also holds account, OAuth and per-project session state, so only
//! those subtrees are deserialized; serde skips every other key unread.

use lodeline_core::event::AiGuardReason;
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;

/// Same memory guard as the MCP baseline; real files are well under 1 MiB.
const MAX_CLAUDE_JSON_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ClaudeJsonMcp {
    #[serde(default)]
    mcp_servers: Value,
    #[serde(default)]
    projects: Option<BTreeMap<String, LenientProject>>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProjectMcp {
    #[serde(default)]
    mcp_servers: Value,
    #[serde(default)]
    disabled_mcp_servers: Value,
}

/// A project entry that is not the expected shape (e.g. `null`) loads as empty
/// instead of failing the whole file.
#[derive(Debug)]
struct LenientProject(ProjectMcp);

impl<'de> Deserialize<'de> for LenientProject {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let v = Value::deserialize(d)?;
        Ok(Self(serde_json::from_value(v).unwrap_or_default()))
    }
}

/// Read Claude Code's `.claude.json` at `path`. A missing, oversized, unreadable or malformed
/// file yields no servers: it must not blind the settings checks, and the
/// error text is not logged because it can quote file content.
pub(crate) fn read(path: &Path) -> ClaudeJsonMcp {
    let mut bytes = Vec::new();
    let read = std::fs::File::open(path)
        .and_then(|f| f.take(MAX_CLAUDE_JSON_BYTES + 1).read_to_end(&mut bytes));
    match read {
        Ok(_) if bytes.len() as u64 > MAX_CLAUDE_JSON_BYTES => {
            tracing::warn!(path = %path.display(), "claude code: .claude.json exceeds size cap; MCP servers not scanned");
            ClaudeJsonMcp::default()
        }
        Ok(_) => serde_json::from_slice(&bytes).unwrap_or_else(|_| {
            tracing::warn!(path = %path.display(), "claude code: unparsable .claude.json; MCP servers not scanned");
            ClaudeJsonMcp::default()
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => ClaudeJsonMcp::default(),
        Err(_) => {
            tracing::warn!(path = %path.display(), "claude code: unreadable .claude.json; MCP servers not scanned");
            ClaudeJsonMcp::default()
        }
    }
}

impl ClaudeJsonMcp {
    /// `(name, definition)` of every server Claude Code can connect to: all
    /// user-scope servers, plus local-scope servers of projects that still
    /// exist and do not list the server in their `disabledMcpServers`.
    pub(crate) fn servers(&self) -> Vec<(&str, &Value)> {
        let mut out: Vec<(&str, &Value)> = entries(&self.mcp_servers).collect();
        for (project, LenientProject(p)) in self.projects.iter().flatten() {
            // Skip only a clean not-found: an unmounted volume or a hung mount
            // errors instead, and its servers stay in scope.
            if Path::new(project).try_exists().is_ok_and(|exists| !exists) {
                continue;
            }
            let disabled = p.disabled_mcp_servers.as_array();
            out.extend(entries(&p.mcp_servers).filter(|(name, _)| {
                !disabled.is_some_and(|d| d.iter().any(|v| v.as_str() == Some(name)))
            }));
        }
        out
    }
}

fn entries(servers: &Value) -> impl Iterator<Item = (&str, &Value)> {
    servers
        .as_object()
        .into_iter()
        .flatten()
        .map(|(k, v)| (k.as_str(), v))
}

/// Score each server once. Claude Code connects a name once per project, so
/// an identical definition in several scopes, or one already in settings
/// `mcpServers`, is a single server.
pub(crate) fn emit_mcp_reasons(
    servers: &[(&str, &Value)],
    settings: &Value,
    out: &mut Vec<AiGuardReason>,
) {
    let mut seen: Vec<(&str, &Value)> =
        entries(settings.get("mcpServers").unwrap_or(&Value::Null)).collect();
    for &(name, def) in servers {
        if !seen.contains(&(name, def)) {
            super::mcp_scan::emit_one_server(name, def, out);
            seen.push((name, def));
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::ai_guard::parser::claude_code::ClaudeCodeParser;
    use crate::ai_guard::parser::AiGuardParser;
    use lodeline_core::event::AiGuardReason;
    use std::path::Path;
    use tempfile::tempdir;

    fn write_claude_json(home: &Path, contents: &str) {
        std::fs::write(home.join(".claude.json"), contents).unwrap();
    }

    fn mcp_reasons(home: &Path) -> Vec<AiGuardReason> {
        ClaudeCodeParser::default()
            .assess(home)
            .unwrap()
            .into_iter()
            .filter(|r| {
                matches!(
                    r,
                    AiGuardReason::McpServerRemote { .. }
                        | AiGuardReason::McpServerLocalCommand { .. }
                )
            })
            .collect()
    }

    fn server_names(reasons: &[AiGuardReason]) -> Vec<&str> {
        let mut names: Vec<&str> = reasons
            .iter()
            .filter_map(|r| match r {
                AiGuardReason::McpServerRemote { server_name, .. }
                | AiGuardReason::McpServerLocalCommand { server_name, .. } => {
                    Some(server_name.as_str())
                }
                _ => None,
            })
            .collect();
        names.sort_unstable();
        names
    }

    #[test]
    fn user_scope_servers_are_scored_without_a_settings_file() {
        let home = tempdir().unwrap();
        write_claude_json(
            home.path(),
            r#"{"mcpServers":{"remote":{"type":"http","url":"https://mcp.example.com/mcp"},
                "local":{"type":"stdio","command":"npx","args":["-y","pkg"]}}}"#,
        );
        let reasons = mcp_reasons(home.path());
        assert_eq!(server_names(&reasons), ["local", "remote"], "{reasons:?}");
    }

    /// `CLAUDE_CONFIG_DIR` moves `~/.claude` to the folder and `~/.claude.json`
    /// into it, so the default locations are no longer read.
    #[test]
    fn config_dir_replaces_the_default_locations() {
        let home = tempdir().unwrap();
        let config = tempdir().unwrap();
        write_claude_json(
            config.path(),
            r#"{"mcpServers":{"moved":{"command":"npx"}}}"#,
        );
        std::fs::write(
            config.path().join("settings.json"),
            r#"{"permissions":{"allow":["Bash:*"]}}"#,
        )
        .unwrap();
        write_claude_json(
            home.path(),
            r#"{"mcpServers":{"default":{"command":"npx"}}}"#,
        );
        let parser = ClaudeCodeParser::with_config_dir(Some(config.path().to_path_buf()));

        let reasons = parser.assess(home.path()).unwrap();

        assert!(
            reasons
                .iter()
                .any(|r| matches!(r, AiGuardReason::PermissionsAllowBroad { .. })),
            "{reasons:?}"
        );
        assert_eq!(server_names(&reasons), ["moved"], "{reasons:?}");
        let watched = parser.watched_paths(home.path());
        assert!(watched.contains(&config.path().join(".claude.json")));
        assert!(!watched.contains(&home.path().join(".claude.json")));
    }

    #[test]
    fn local_scope_servers_of_two_projects_are_scored() {
        let home = tempdir().unwrap();
        let (a, b) = (tempdir().unwrap(), tempdir().unwrap());
        write_claude_json(
            home.path(),
            &serde_json::json!({"projects": {
                a.path().to_str().unwrap(): {"mcpServers": {"a-remote": {"url": "https://a.example/mcp"}}},
                b.path().to_str().unwrap(): {"mcpServers": {"b-local": {"command": "node", "args": ["s.js"]}}},
                "/nonexistent/lodeline-test-project": {"mcpServers": {"stale": {"command": "node"}}}
            }})
            .to_string(),
        );
        let reasons = mcp_reasons(home.path());
        assert_eq!(
            server_names(&reasons),
            ["a-remote", "b-local"],
            "{reasons:?}"
        );
    }

    #[test]
    fn project_missing_on_disk_is_skipped() {
        let home = tempdir().unwrap();
        let gone = home.path().join("gone");
        write_claude_json(
            home.path(),
            &serde_json::json!({"projects": {
                gone.to_str().unwrap(): {"mcpServers": {"stale": {"command": "node"}}}
            }})
            .to_string(),
        );
        assert!(mcp_reasons(home.path()).is_empty());
    }

    #[test]
    fn malformed_project_entry_does_not_drop_other_servers() {
        let home = tempdir().unwrap();
        let a = tempdir().unwrap();
        write_claude_json(
            home.path(),
            &serde_json::json!({
                "mcpServers": {"u": {"url": "https://u.example/mcp"}},
                "projects": {
                    "/x": null,
                    "/y": "text",
                    a.path().to_str().unwrap(): {"mcpServers": {"l": {"command": "node"}}}
                }
            })
            .to_string(),
        );
        assert_eq!(server_names(&mcp_reasons(home.path())), ["l", "u"]);
    }

    #[test]
    fn null_projects_keeps_user_scope_servers() {
        let home = tempdir().unwrap();
        write_claude_json(
            home.path(),
            r#"{"mcpServers":{"u":{"url":"https://u.example/mcp"}},"projects":null}"#,
        );
        assert_eq!(server_names(&mcp_reasons(home.path())), ["u"]);
    }

    /// `try_exists` errors on a path with an embedded NUL on every platform,
    /// which stands in for an unmounted volume: the servers stay in scope.
    #[test]
    fn project_whose_existence_check_errors_keeps_its_servers() {
        let home = tempdir().unwrap();
        write_claude_json(
            home.path(),
            &serde_json::json!({"projects": {
                "/unmounted\u{0}volume": {"mcpServers": {"kept": {"command": "node"}}}
            }})
            .to_string(),
        );
        assert_eq!(server_names(&mcp_reasons(home.path())), ["kept"]);
    }

    #[test]
    fn server_disabled_in_its_project_is_skipped() {
        let home = tempdir().unwrap();
        let a = tempdir().unwrap();
        write_claude_json(
            home.path(),
            &serde_json::json!({"projects": {a.path().to_str().unwrap(): {
                "mcpServers": {"off": {"command": "node"}, "on": {"command": "node"}},
                "disabledMcpServers": ["off"]
            }}})
            .to_string(),
        );
        assert_eq!(server_names(&mcp_reasons(home.path())), ["on"]);
    }

    #[test]
    fn identical_server_in_settings_and_claude_json_is_scored_once() {
        let home = tempdir().unwrap();
        let a = tempdir().unwrap();
        let def = serde_json::json!({"url": "https://same.example/mcp"});
        std::fs::create_dir_all(home.path().join(".claude")).unwrap();
        std::fs::write(
            home.path().join(".claude").join("settings.json"),
            serde_json::json!({"mcpServers": {"same": def}}).to_string(),
        )
        .unwrap();
        write_claude_json(
            home.path(),
            &serde_json::json!({"mcpServers": {"same": def},
                "projects": {a.path().to_str().unwrap(): {"mcpServers": {"same": def}}}})
            .to_string(),
        );
        assert_eq!(server_names(&mcp_reasons(home.path())), ["same"]);
    }

    #[test]
    fn malformed_claude_json_does_not_blind_settings_checks() {
        let home = tempdir().unwrap();
        std::fs::create_dir_all(home.path().join(".claude")).unwrap();
        std::fs::write(
            home.path().join(".claude").join("settings.json"),
            r#"{"permissions":{"deny":[]}}"#,
        )
        .unwrap();
        write_claude_json(home.path(), "{ not json");
        let reasons = ClaudeCodeParser::default().assess(home.path()).unwrap();
        assert!(
            reasons
                .iter()
                .any(|r| matches!(r, AiGuardReason::PermissionsDenyEmpty)),
            "{reasons:?}"
        );
        assert!(mcp_reasons(home.path()).is_empty());
    }

    #[test]
    fn secrets_and_other_keys_never_reach_the_output() {
        let home = tempdir().unwrap();
        let a = tempdir().unwrap();
        write_claude_json(
            home.path(),
            &serde_json::json!({
                "oauthAccount": {"accessToken": "SECRET-oauth-token"},
                "primaryApiKey": "SECRET-api-key",
                "mcpServers": {"u": {"type": "http", "url": "https://u.example/mcp",
                    "headers": {"Authorization": "Bearer SECRET-header"}}},
                "projects": {a.path().to_str().unwrap(): {
                    "lastSessionFirstPrompt": "SECRET-prompt",
                    "mcpServers": {"l": {"command": "node", "args": ["s.js"],
                        "env": {"API_KEY": "SECRET-env-value"}}}
                }}
            })
            .to_string(),
        );
        let reasons = ClaudeCodeParser::default().assess(home.path()).unwrap();
        assert_eq!(server_names(&reasons), ["l", "u"]);
        let emitted = serde_json::to_string(&reasons).unwrap();
        assert!(!emitted.contains("SECRET"), "{emitted}");
    }
}
