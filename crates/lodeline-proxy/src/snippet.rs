//! `lodeline-proxy snippet`: text for one client config entry. Pure: it reads
//! and writes no file, makes no request and never receives a token.

use crate::bootstrap::normalize_origin;
use crate::cli::SnippetClient;
use lodeline_proxy_api::Id;

/// What `snippet` prints: the entry (stdout) and a line naming its file (stderr).
pub struct Snippet {
    pub entry: String,
    pub note: String,
}

fn valid_name(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

fn valid_env_name(s: &str) -> bool {
    let mut chars = s.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// A bearer token is 64 hex characters; a value of that shape is a token, not a name.
fn token_shaped(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
}

fn quote(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_default()
}

/// Builds the snippet, or the message to print for the first refused argument.
pub fn render(
    client: SnippetClient,
    name: &str,
    url: &str,
    route: &str,
    token_env: &str,
) -> Result<Snippet, String> {
    if Id::new(route).is_err() {
        return Err("--route does not match the id pattern".into());
    }
    if !valid_name(name) {
        return Err(
            "--name may use only letters, digits, underscore and hyphen \
                    (a dot would make a nested TOML table in Codex)"
                .into(),
        );
    }
    let base = normalize_origin(url).map_err(|e| format!("--url refused: {e}"))?;
    if !valid_env_name(token_env) {
        return Err(
            "--token-env must be an environment variable name ([A-Za-z_][A-Za-z0-9_]*)".into(),
        );
    }
    if token_shaped(token_env) {
        return Err(
            "--token-env looks like a token value, not a variable name; \
                    pass the name of the variable that holds the token"
                .into(),
        );
    }
    let route_url = format!("{base}/mcp/{route}");
    Ok(match client {
        SnippetClient::ClaudeCode => Snippet {
            entry: pretty(serde_json::json!({
                "type": "http",
                "url": route_url,
                "headers": { "Authorization": format!("Bearer ${{{token_env}}}") },
            })),
            note: format!(
                "# claude-code: add under mcpServers in ~/.claude.json or .mcp.json, or run \
                 `claude mcp add-json --scope user {name} '<entry>'`. Use a variable name of your \
                 own: Claude Code reads credential names such as ANTHROPIC_AUTH_TOKEN as empty \
                 in a remote server's headers."
            ),
        },
        SnippetClient::Cursor => Snippet {
            entry: pretty(serde_json::json!({
                "url": route_url,
                "headers": { "Authorization": format!("Bearer ${{env:{token_env}}}") },
            })),
            note: format!(
                "# cursor: add under mcpServers as \"{name}\" in ~/.cursor/mcp.json or \
                 .cursor/mcp.json. The editor needs {token_env} in its own process environment."
            ),
        },
        SnippetClient::Codex => Snippet {
            entry: format!(
                "[mcp_servers.{name}]\nurl = {}\nbearer_token_env_var = {}\n",
                quote(&route_url),
                quote(token_env)
            ),
            note:
                "# codex: add to ~/.codex/config.toml, or .codex/config.toml of a trusted project."
                    .into(),
        },
    })
}

fn pretty(v: serde_json::Value) -> String {
    let mut s = serde_json::to_string_pretty(&v).unwrap_or_default();
    s.push('\n');
    s
}
