use crate::local::LocalUpstream;
use lodeline_core::assess::AssessInput;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, Content, Implementation, ServerCapabilities, ServerInfo};
use rmcp::schemars;
use rmcp::{tool, tool_handler, tool_router, ErrorData as McpError, ServerHandler};
use serde::Deserialize;
use std::sync::Arc;

fn ok(v: serde_json::Value) -> Result<CallToolResult, McpError> {
    Ok(CallToolResult::success(vec![Content::text(v.to_string())]))
}

/// Parameters for the `assess` tool. All fields are optional; exactly one
/// "mode" must be provided: either `command` (command mode) or `mcp_server`
/// (MCP server definition mode). Passing neither or both is an invalid-params
/// error — the tool never silently produces an Allow.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct AssessParams {
    /// Shell command to pre-flight (command mode).
    pub command: Option<String>,
    /// Arguments for the shell command (command mode, optional).
    #[serde(default)]
    pub args: Option<Vec<String>>,
    /// MCP server definition JSON object to pre-flight (mcp_server mode).
    pub mcp_server: Option<serde_json::Value>,
    /// Name of the MCP server (required when `mcp_server` is provided).
    pub server_name: Option<String>,
}

#[derive(Clone)]
pub struct LodelineLocal {
    upstream: Arc<LocalUpstream>,
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl LodelineLocal {
    pub fn new(upstream: Arc<LocalUpstream>) -> Self {
        Self {
            upstream,
            tool_router: Self::tool_router(),
        }
    }

    #[tool(
        description = "This machine's AI-tool risk headline: per (tool, scope) risk band + score, \
                          plus reasons_count, the distinct reason_kinds and last-assessed time. A `failed_sources` list appears only when a tool's config could not be read or parsed, and then that tool's score may be stale. Use for 'what's my AI risk?'."
    )]
    async fn my_risk(&self) -> Result<CallToolResult, McpError> {
        let r = self.upstream.doctor_report().await?;
        let failed: Vec<lodeline_core::control_proto::FailedSource> = vec![];
        if failed.is_empty() {
            return ok(serde_json::json!({ "latest_risk": r.latest_risk }));
        }
        ok(serde_json::json!({ "latest_risk": r.latest_risk, "failed_sources": failed }))
    }

    #[tool(
        description = "Why this machine is rated the way it is: effective rubric (weights/overrides), \
                          active parsers per (tool, scope), loaded rule packs, unknown override keys."
    )]
    async fn my_guard_detail(&self) -> Result<CallToolResult, McpError> {
        let r = self.upstream.doctor_report().await?;
        ok(serde_json::json!({
            "effective_rubric": r.effective_rubric,
            "parsers": r.parsers,
            "rule_packs": r.rule_packs,
            "unknown_override_keys": r.unknown_override_keys,
        }))
    }

    #[tool(
        description = "Concrete surface Lodeline found on this machine: per-repo workspace discovery \
                          counts per tool, and external hook-script watch summary."
    )]
    async fn my_findings(&self) -> Result<CallToolResult, McpError> {
        let r = self.upstream.doctor_report().await?;
        ok(serde_json::json!({ "per_repo": r.per_repo, "ext_scripts": r.ext_scripts }))
    }

    #[tool(
        description = "Pre-flight a proposed shell command or a single MCP server definition \
                       against THIS host's currently loaded Lodeline policy (rubric + deny rules). \
                       Returns a risk band, score, reasons, any deny-rule match, and a decision \
                       (allow/warn/deny). For faithful deny-rule parity with what the hook would \
                       block at runtime, put the FULL command line in `command` (args is optional \
                       and only aids structural scanning). Read-only; does not execute anything."
    )]
    async fn assess(
        &self,
        Parameters(p): Parameters<AssessParams>,
    ) -> Result<CallToolResult, McpError> {
        let input = match (p.command, p.mcp_server) {
            // Command mode.
            (Some(command), None) => AssessInput::Command {
                command,
                args: p.args.unwrap_or_default(),
            },
            // MCP server definition mode.
            (None, Some(def)) => {
                if !def.is_object() {
                    return Err(McpError::invalid_params(
                        "`mcp_server` must be a JSON object",
                        None,
                    ));
                }
                let server_name = p.server_name.filter(|s| !s.is_empty()).ok_or_else(|| {
                    McpError::invalid_params(
                        "`server_name` is required (non-empty) when `mcp_server` is provided",
                        None,
                    )
                })?;
                AssessInput::McpServer {
                    server_name,
                    definition: def,
                }
            }
            // Neither provided.
            (None, None) => {
                return Err(McpError::invalid_params(
                    "exactly one of `command` or `mcp_server` must be provided",
                    None,
                ));
            }
            // Both provided.
            (Some(_), Some(_)) => {
                return Err(McpError::invalid_params(
                    "exactly one of `command` or `mcp_server` must be provided (not both)",
                    None,
                ));
            }
        };

        let verdict = self.upstream.assess(input).await?;
        ok(serde_json::to_value(&verdict)
            .map_err(|e| McpError::internal_error(e.to_string(), None))?)
    }
}

#[tool_handler]
impl ServerHandler for LodelineLocal {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            // Single-host identity: this server only ever exposes THIS machine's
            // posture. Operators who want the fleet run `lodeline-fleet` instead.
            server_info: Implementation {
                name: "lodeline-check".to_string(),
                ..Implementation::from_build_env()
            },
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            instructions: Some(
                "Read-only view of THIS machine's Lodeline AI Guard posture (no fleet, no server). \
                 Start with my_risk, explain with my_guard_detail, list findings with my_findings. \
                 Use assess to pre-flight a proposed shell command or MCP server definition \
                 against the loaded policy before executing it. \
                 There are no write or remediation tools."
                    .to_string(),
            ),
            ..Default::default()
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use lodeline_core::assess::{AssessVerdict, Decision};
    use lodeline_core::control_proto::{DoctorAiGuardReport, PerRepoSummary, Response};
    use lodeline_core::event::AiGuardBucket;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    /// Stands up a canned UnixListener that replies to a single
    /// `DoctorAiGuardReport` request, mirroring `local.rs`'s test harness.
    fn canned_agent(socket: std::path::PathBuf) -> tokio::task::JoinHandle<()> {
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (rd, mut wr) = stream.into_split();
            let mut line = String::new();
            BufReader::new(rd).read_line(&mut line).await.unwrap();
            let resp = Response {
                ok: true,
                stats: None,
                apply_policy: None,
                policy_status: None,
                targets: None,
                risk: None,
                error: None,
                doctor_ai_guard: Some(DoctorAiGuardReport {
                    parsers: vec![],
                    rule_packs: vec![],
                    ext_scripts: Default::default(),
                    per_repo: PerRepoSummary {
                        continue_dev: 0,
                        claude_code: 2,
                        codex: 0,
                    },
                    latest_risk: vec![],
                    effective_rubric: vec![],
                    unknown_override_keys: vec![],
                }),
                assess_verdict: None,
            };
            let mut bytes = serde_json::to_vec(&resp).unwrap();
            bytes.push(b'\n');
            wr.write_all(&bytes).await.unwrap();
        })
    }

    fn text(res: &CallToolResult) -> String {
        res.content
            .iter()
            .filter_map(|c| c.as_text().map(|t| t.text.clone()))
            .collect::<Vec<_>>()
            .join("")
    }

    #[tokio::test]
    async fn my_risk_returns_latest_risk() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("control.sock");
        let srv = canned_agent(socket.clone());
        let local = LodelineLocal::new(Arc::new(LocalUpstream::new(socket)));
        let res = local.my_risk().await.unwrap();
        assert_eq!(res.is_error, Some(false));
        assert!(text(&res).contains("latest_risk"));
        srv.await.unwrap();
    }

    /// Answers the doctor report and the risk request, in either order, each
    /// on its own connection.
    fn canned_risk_agent(
        socket: std::path::PathBuf,
        failed: Vec<lodeline_core::control_proto::FailedSource>,
    ) -> tokio::task::JoinHandle<()> {
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        tokio::spawn(async move {
            for _ in 0..2 {
                let (stream, _) = listener.accept().await.unwrap();
                let (rd, mut wr) = stream.into_split();
                let mut line = String::new();
                BufReader::new(rd).read_line(&mut line).await.unwrap();
                let mut resp = Response {
                    ok: true,
                    stats: None,
                    apply_policy: None,
                    policy_status: None,
                    targets: None,
                    risk: None,
                    error: None,
                    doctor_ai_guard: None,
                    assess_verdict: None,
                };
                if line.contains("doctor_ai_guard_report") {
                    resp.doctor_ai_guard = Some(DoctorAiGuardReport {
                        parsers: vec![],
                        rule_packs: vec![],
                        ext_scripts: Default::default(),
                        per_repo: PerRepoSummary {
                            continue_dev: 0,
                            claude_code: 0,
                            codex: 0,
                        },
                        latest_risk: vec![],
                        effective_rubric: vec![],
                        unknown_override_keys: vec![],
                    });
                } else {
                    resp.risk = Some(lodeline_core::control_proto::RiskPayload {
                        assessments: vec![],
                        failed_sources: failed.clone(),
                    });
                }
                let mut bytes = serde_json::to_vec(&resp).unwrap();
                bytes.push(b'\n');
                wr.write_all(&bytes).await.unwrap();
            }
        })
    }

    async fn my_risk_json(
        failed: Vec<lodeline_core::control_proto::FailedSource>,
    ) -> serde_json::Value {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("control.sock");
        let srv = canned_risk_agent(socket.clone(), failed);
        let local = LodelineLocal::new(Arc::new(LocalUpstream::new(socket)));
        let res = local.my_risk().await.unwrap();
        srv.abort();
        serde_json::from_str(&text(&res)).unwrap()
    }

    #[tokio::test]
    async fn my_risk_names_a_source_whose_config_failed() {
        let v = my_risk_json(vec![lodeline_core::control_proto::FailedSource {
            tool: lodeline_core::event::AiTool::Codex,
            scope: lodeline_core::event::AiGuardScope::UserGlobal,
            user: Some("alice".into()),
            error_kind: "parse".into(),
            path: "/home/alice/.codex/config.toml".into(),
            failing_since: "2026-11-20T01:00:00Z".into(),
            last_assessed_ts: None,
        }])
        .await;
        assert_eq!(v["failed_sources"][0]["error_kind"], "parse", "got: {v}");
        assert_eq!(
            v["failed_sources"][0]["path"], "/home/alice/.codex/config.toml",
            "got: {v}"
        );
    }

    #[tokio::test]
    async fn my_risk_adds_no_key_when_nothing_failed() {
        let v = my_risk_json(vec![]).await;
        assert!(v.get("failed_sources").is_none(), "got: {v}");
        assert!(v.get("latest_risk").is_some(), "got: {v}");
    }

    #[tokio::test]
    async fn my_findings_returns_per_repo() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("control.sock");
        let srv = canned_agent(socket.clone());
        let local = LodelineLocal::new(Arc::new(LocalUpstream::new(socket)));
        let res = local.my_findings().await.unwrap();
        assert_eq!(res.is_error, Some(false));
        assert!(text(&res).contains("per_repo"));
        srv.await.unwrap();
    }

    /// Stands up a canned UnixListener that replies to a single `Assess`
    /// request with a known `AssessVerdict`.
    fn canned_assess_agent(
        socket: std::path::PathBuf,
        verdict: AssessVerdict,
    ) -> tokio::task::JoinHandle<()> {
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (rd, mut wr) = stream.into_split();
            let mut line = String::new();
            BufReader::new(rd).read_line(&mut line).await.unwrap();
            let resp = Response {
                ok: true,
                stats: None,
                apply_policy: None,
                policy_status: None,
                targets: None,
                risk: None,
                error: None,
                doctor_ai_guard: None,
                assess_verdict: Some(verdict),
            };
            let mut bytes = serde_json::to_vec(&resp).unwrap();
            bytes.push(b'\n');
            wr.write_all(&bytes).await.unwrap();
        })
    }

    /// Canned upstream returns a known AssessVerdict; the tool returns a
    /// JSON result containing the expected decision and band.
    #[tokio::test]
    async fn assess_tool_returns_verdict() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("assess_tool.sock");
        let expected = AssessVerdict {
            bucket: AiGuardBucket::High,
            score: 7.5,
            reasons: vec![],
            deny_match: None,
            decision: Decision::Deny,
        };
        let srv = canned_assess_agent(socket.clone(), expected);
        let local = LodelineLocal::new(Arc::new(LocalUpstream::new(socket)));
        let res = local
            .assess(Parameters(AssessParams {
                command: Some("rm".to_string()),
                args: Some(vec!["-rf".to_string(), "/".to_string()]),
                mcp_server: None,
                server_name: None,
            }))
            .await
            .unwrap();
        assert_eq!(res.is_error, Some(false));
        let body = text(&res);
        assert!(body.contains("deny"), "expected 'deny' in: {body}");
        assert!(body.contains("high"), "expected 'high' band in: {body}");
        srv.await.unwrap();
    }

    /// Neither `command` nor `mcp_server` provided → invalid-params McpError.
    /// Both provided → invalid-params McpError.
    #[tokio::test]
    async fn assess_tool_requires_exactly_one_mode() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("xor_test.sock");
        // No socket needed — validation fires before any IPC.
        let local = LodelineLocal::new(Arc::new(LocalUpstream::new(socket)));

        // Neither mode.
        let err = local
            .assess(Parameters(AssessParams {
                command: None,
                args: None,
                mcp_server: None,
                server_name: None,
            }))
            .await
            .unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("exactly one"),
            "expected 'exactly one' in: {msg}"
        );

        // Both modes simultaneously.
        let err2 = local
            .assess(Parameters(AssessParams {
                command: Some("ls".to_string()),
                args: None,
                mcp_server: Some(serde_json::json!({"transport": "stdio"})),
                server_name: Some("x".to_string()),
            }))
            .await
            .unwrap_err();
        let msg2 = format!("{err2:?}");
        assert!(
            msg2.contains("exactly one"),
            "expected 'exactly one' in: {msg2}"
        );
    }

    /// `mcp_server` is not a JSON object (string/array) → invalid-params McpError.
    #[tokio::test]
    async fn assess_tool_mcp_non_object_errors() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("non_obj_test.sock");
        let local = LodelineLocal::new(Arc::new(LocalUpstream::new(socket)));

        // JSON string — not an object.
        let err = local
            .assess(Parameters(AssessParams {
                command: None,
                args: None,
                mcp_server: Some(serde_json::Value::String("bad".to_string())),
                server_name: Some("s".to_string()),
            }))
            .await
            .unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("object"),
            "expected 'object' error msg in: {msg}"
        );

        // JSON array — also not an object.
        let err2 = local
            .assess(Parameters(AssessParams {
                command: None,
                args: None,
                mcp_server: Some(serde_json::json!(["a", "b"])),
                server_name: Some("s".to_string()),
            }))
            .await
            .unwrap_err();
        let msg2 = format!("{err2:?}");
        assert!(
            msg2.contains("object"),
            "expected 'object' error msg in: {msg2}"
        );
    }
}
