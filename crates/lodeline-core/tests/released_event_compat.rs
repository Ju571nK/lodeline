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
