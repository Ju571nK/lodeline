//! Pins what released servers do with evidence kinds added after them.

#[allow(dead_code)]
#[path = "fixtures/released/v0_12_6_event.rs"]
mod released;

use lodeline_core::event::{AiGuardScope, AiTool, Event, Evidence, Severity, SourceKind, Subject};
use time::macros::datetime;

#[test]
fn released_server_accepts_ai_guard_assess_failed_as_unknown() {
    let ev = Event {
        schema_version: lodeline_core::event::SCHEMA_VERSION,
        event_id: uuid::Uuid::now_v7(),
        ts: datetime!(2026-11-03 10:00 UTC),
        host_id: "h".into(),
        agent_version: "0.13.0".into(),
        severity: Severity::Warn,
        source: SourceKind::Agent,
        subject: Subject::Self_,
        evidence: Evidence::AiGuardAssessFailed {
            tool: AiTool::ClaudeCode,
            scope: AiGuardScope::UserGlobal,
            user: Some("alice".into()),
            rule_pack_id: Some("acme-extended".into()),
            tool_label: Some("Acme CLI".into()),
            error_kind: "unreadable".into(),
            path: "/Users/alice/.claude/settings.json".into(),
            failing_since: datetime!(2026-11-03 10:00 UTC),
            last_assessed_ts: Some(datetime!(2026-11-02 09:00 UTC)),
            is_reattestation: false,
        },
        target_id: None,
    };
    let wire = serde_json::to_value(&ev).unwrap();
    assert_eq!(wire["evidence"]["kind"], "ai_guard_assess_failed");
    let old: released::Event = serde_json::from_value(wire).expect("v0.12.6 rejects the event");
    assert!(matches!(old.evidence, released::Evidence::Unknown));
    assert_eq!(old.event_id, ev.event_id);
}

/// One sample per reason kind, fields in declaration order, so the bytes a
/// build writes can be compared with these strings.
const KNOWN_REASONS: &[&str] = &[
    r#"{"kind":"destructive_in_inline_command","pattern":"p","hook_event":"PreToolUse","snippet":"s"}"#,
    r#"{"kind":"destructive_in_hook_script","pattern":"p","hook_event":"PreToolUse","script_path":"/h/a.sh","snippet":"s","source_chain":["/h/a.sh"]}"#,
    r#"{"kind":"external_script_unscanned","hook_event":"PreToolUse","script_path":"/x.sh"}"#,
    r#"{"kind":"no_sandbox","executor":"host_shell"}"#,
    r#"{"kind":"broad_matcher","hook_event":"PreToolUse","matcher":".*"}"#,
    r#"{"kind":"permissions_deny_empty"}"#,
    r#"{"kind":"permissions_allow_broad","rule":"Bash(*)"}"#,
    r#"{"kind":"sandbox_disabled"}"#,
    r#"{"kind":"mcp_server_remote","server_name":"s","url":"https://example.com"}"#,
    r#"{"kind":"mcp_server_local_command","server_name":"s","command":"npx"}"#,
    r#"{"kind":"trusted_mcp_server","server_name":"s"}"#,
    r#"{"kind":"auto_approval_enabled","mode":"yolo"}"#,
    r#"{"kind":"mcp_server_suspicious_launcher","server_name":"s","command":"bash","shape":"shell","evidence":"bash -c"}"#,
    r#"{"kind":"project_mcp_auto_enabled","mechanism":"enableAllProjectMcpServers"}"#,
    r#"{"kind":"instruction_file_directive","path":"/r/AGENTS.md","directive_kind":"override_marker","snippet":"s"}"#,
    r#"{"kind":"unattended_scheduled_task","name":"n"}"#,
    r#"{"kind":"mcp_tool_instruction_override","server":"s","tool":"t","pattern":"p"}"#,
    r#"{"kind":"mcp_tool_hidden_text","server":"s","tool":"t","text_kind":"bidi"}"#,
    r#"{"kind":"mcp_tool_name_shadow","tool":"t","servers":["a","b"]}"#,
    r#"{"kind":"mcp_tool_surface_drift","server":"s","tool":"t","baseline_hash":"a","current_hash":"b"}"#,
    r#"{"kind":"mcp_unapproved_new_tool","server":"s","tool":"t","current_hash":"b"}"#,
    r#"{"kind":"mcp_schema_privilege_expansion","server":"s","tool":"t"}"#,
    r#"{"kind":"mcp_read_only_hint_contradiction","server":"s","tool":"t"}"#,
    r#"{"kind":"auto_mode_defaults_dropped","list":"soft_deny"}"#,
    r#"{"kind":"hook_forwards_tool_calls","hook_event":"PreToolUse","destination":"example.com"}"#,
    r#"{"kind":"unattended_loop_prompt","source":"user"}"#,
    r#"{"kind":"standing_command_approval","pattern":"git"}"#,
    r#"{"kind":"mcp_tools_auto_approved","server_name":"s","tools":["t"]}"#,
    r#"{"kind":"project_settings_plugin_enabled","plugins":["p@m"]}"#,
    r#"{"kind":"project_settings_helper_command","key":"apiKeyHelper"}"#,
    r#"{"kind":"project_settings_env_override","variable":"V","effect":"redirect","destination":"example.com"}"#,
    r#"{"kind":"project_settings_env_override","variable":"V","effect":"exec_code"}"#,
    r#"{"kind":"project_settings_ui_command","key":"statusLine"}"#,
    r#"{"kind":"project_settings_marketplace","name":"m","source":"github:o/r"}"#,
];

#[test]
fn known_reasons_keep_their_released_bytes() {
    use lodeline_core::event::AiGuardReason;
    for wire in KNOWN_REASONS {
        let old: released::AiGuardReason = serde_json::from_str(wire).expect(wire);
        assert_eq!(serde_json::to_string(&old).unwrap(), *wire);
        let new: AiGuardReason = serde_json::from_str(wire).expect(wire);
        assert!(!matches!(new, AiGuardReason::Unknown(_)), "{wire}");
        assert_eq!(serde_json::to_string(&new).unwrap(), *wire);
    }
}

#[test]
fn unknown_reason_kind_keeps_the_event_and_the_object() {
    use lodeline_core::event::AiGuardReason;
    let wire = serde_json::json!({
        "schema_version": 1, "event_id": uuid::Uuid::now_v7(), "ts": "2026-11-03T10:00:00Z",
        "host_id": "h", "agent_version": "0.14.0", "severity": "warn",
        "source": {"kind": "agent"}, "subject": {"kind": "self"},
        "evidence": {"kind": "ai_guard_risk_assessed", "tool": "codex",
            "scope": {"kind": "user_global"}, "score": 3.0, "bucket": "medium",
            "reasons": [{"kind": "sandbox_disabled"},
                {"kind": "future_reason", "detail": {"n": 2}, "path": "/x"}],
            "is_reattestation": false}
    });
    assert!(
        serde_json::from_value::<released::Event>(wire.clone()).is_err(),
        "v0.12.6 rejects an event with an unknown reason kind"
    );
    let ev: Event = serde_json::from_value(wire.clone()).unwrap();
    let Evidence::AiGuardRiskAssessed { reasons, .. } = &ev.evidence else {
        panic!("{:?}", ev.evidence)
    };
    assert_eq!(reasons[0], AiGuardReason::SandboxDisabled);
    assert!(matches!(&reasons[1], AiGuardReason::Unknown(_)));
    assert_eq!(
        serde_json::to_value(reasons).unwrap(),
        wire["evidence"]["reasons"]
    );
    for not_an_object in [r#""sandbox_disabled""#, "7", "null"] {
        assert!(serde_json::from_str::<AiGuardReason>(not_an_object).is_err());
    }
}
