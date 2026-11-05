// lodeline-core `src/event.rs` as released in v0.12.6 (commit 968cb54), with
// its two `#[cfg(test)]` modules removed. Do not edit: it stands for the
// event type that released servers decode with.

//! Posture event types.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;
use time::OffsetDateTime;
use uuid::Uuid;

/// Coarse severity. Phase 1 emits only `Info` and `Warn`.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Warn,
}

/// Confidence in an inferred (non-definitive) signal. v1 emits only `Low`.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

/// Origin of an event.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SourceKind {
    FileSystem,
    Agent,
    /// lodeline-hook runtime observation (#64).
    AgentHook,
    /// Forward-compat fallback (see Evidence::Unknown).
    #[serde(other)]
    Unknown,
}

/// Technical identifier of the observed thing.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Subject {
    Path {
        value: PathBuf,
    },
    #[serde(rename = "self")]
    Self_,
}

/// A filesystem change kind.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum FileChangeKind {
    Created,
    Modified,
    Removed,
    Renamed,
}

/// Quality marker on a `FileChange` event.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceQuality {
    /// Single event, clean debounce window.
    Definitive,
    /// Multiple events coalesced inside the debounce window.
    BestEffort,
    /// Event spent > 1 s in any queue before reaching the sink.
    Delayed,
    /// Observation could not be fully captured (e.g., file removed before hash).
    Incomplete,
}

/// Why the agent is shutting down abnormally.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AgentDyingReason {
    Panic,
    UnrecoverableSinkError,
    Signal,
}

/// Spec §3.8.2 rejection reasons. Stable wire strings — operators filter by
/// these in the SIEM, so renames are breaking changes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicySignatureInvalidReason {
    /// `signing_pubkey_id` not present in the keystore at all.
    PubkeyUnknown,
    /// Keystore entry exists but `now` is outside its validity window.
    PubkeyInactive,
    /// Pubkey resolved but ed25519 verification failed against the canonical bytes.
    SignatureInvalid,
    /// `now >= signed_envelope.valid_until`.
    Expired,
    /// `policy_version <= host_meta.last_applied_policy_version` (replay or rollback).
    VersionRegression,
    /// The signature is good but the agent could not load the document at boot.
    ParseFailed,
}

/// Phase 3b.1 — which AI coding agent is being assessed.
/// Stable wire strings — operators filter by these in the SIEM, so renames are
/// breaking changes.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum AiTool {
    ClaudeCode,
    Codex,
    /// Phase 3b.6 — Claude Desktop (Anthropic.app), application-form companion to ClaudeCode CLI.
    ClaudeDesktop,
    /// Phase 3b.6 — Continue.dev VSCode/JetBrains extension.
    ContinueDev,
    /// Phase 3b.7 — Gemini CLI (google-gemini/gemini-cli). Wire string: "gemini".
    Gemini,
    /// Phase 3b.7 — Cursor IDE. Wire string: "cursor".
    Cursor,
    /// Antigravity (Google) — successor to Gemini CLI (Gemini CLI sunset
    /// 2026-06-18). Config reuses the `~/.gemini/` tree. Wire string: "antigravity".
    Antigravity,
    /// Grok Build (xAI) terminal coding agent. Wire string: "grok".
    Grok,
    /// Phase 3b.7.5 — an operator-defined tool with no built-in parser. Wire
    /// string: "other". The human name rides `tool_label` (rule pack + event),
    /// never inside the enum, so AiTool stays Copy + a bare-string wire value.
    Other,
}

/// Phase 3b.1 — where the assessment applies on the host.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AiGuardScope {
    /// `~/.claude/`, `~/.codex/` — user's global config.
    UserGlobal,
    /// Operator-added paths in policy.yaml not under user-global.
    Project { path: PathBuf },
    /// Phase 3b.6 — application/IDE-installed AI agent (Claude Desktop, Continue.dev, ...).
    /// `app` is a stable snake_case identifier matching the parser
    /// (e.g., "claude_desktop", "continue").
    Application { app: String },
}

/// Phase 3b.1 — auto-derived from `score`. low <1 / medium <4 / high <7 / critical 7+.
/// Stable wire strings — operators filter by these in the SIEM, so renames are
/// breaking changes.
///
/// Variants are declared in ascending severity order so `#[derive(PartialOrd, Ord)]`
/// produces the correct ordering: Low < Medium < High < Critical. Required by the
/// assess engine's enforce-bucket threshold comparison (#149).
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum AiGuardBucket {
    Low,
    Medium,
    High,
    Critical,
}

/// Phase 3b.1 — one finding inside an `AiGuardRiskAssessed` event.
/// Stable wire strings — operators filter by these in the SIEM, so renames are
/// breaking changes.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AiGuardReason {
    /// Inline shell command in a hook contains a destructive pattern.
    DestructiveInInlineCommand {
        pattern: String,
        hook_event: String,
        snippet: String,
    },
    /// Same, but the destructive pattern was in a script file we read
    /// (convention dir like `~/.claude/hooks/`).
    DestructiveInHookScript {
        pattern: String,
        hook_event: String,
        script_path: PathBuf,
        snippet: String,
        /// 3b.3.1 — chain of script paths from the entry hook down to the
        /// file where the pattern matched. Empty = match was in the entry
        /// (back-compat with 3b.3 emissions). Populated form is
        /// `[entry, ..., matched_file]`.
        #[serde(default)]
        source_chain: Vec<PathBuf>,
    },
    /// Hook command points to an external script we did NOT scan
    /// (path outside known convention dir). 3b.3 marker.
    ExternalScriptUnscanned {
        hook_event: String,
        script_path: PathBuf,
    },
    /// Hook executes in host shell with no sandbox boundary.
    NoSandbox {
        executor: String,
    },
    /// Hook matcher catches all/most tool invocations.
    BroadMatcher {
        hook_event: String,
        matcher: String,
    },
    /// Permission deny array empty / missing.
    PermissionsDenyEmpty,
    /// Permission allow includes a wildcard rule.
    PermissionsAllowBroad {
        rule: String,
    },
    /// Codex sandbox is fully disabled: top-level `sandbox_mode = "danger-full-access"`.
    /// Codex-only reason — Claude Code uses `NoSandbox{executor:"host_shell"}`
    /// instead, since Claude Code has no built-in sandbox concept.
    SandboxDisabled,
    /// MCP server pointing at a remote URL was added.
    McpServerRemote {
        server_name: String,
        url: String,
    },
    /// MCP server using a local command (stdio transport) was added.
    /// Phase 3b.7 — rule pack engine emits this when a `command:` key is
    /// found under `mcpServers.*` in Gemini/Cursor settings files.
    McpServerLocalCommand {
        server_name: String,
        command: String,
    },
    /// Phase 3b.8 — an MCP server skips per-tool confirmation for every tool
    /// it exposes: Gemini `trust: true`, or (#200) Codex
    /// `default_tools_approval_mode = "approve"`.
    TrustedMcpServer {
        server_name: String,
    },
    /// Phase 3b.8 — the agent's default approval mode auto-approves a class
    /// of tool calls without prompting (e.g. Gemini `defaultApprovalMode: "auto_edit"`).
    AutoApprovalEnabled {
        mode: String,
    },
    /// #127 — stdio MCP launcher matches an attack shape (shell + inline-exec
    /// flag, or a transient/writable path in command or args). Emitted in
    /// ADDITION to the `McpServerLocalCommand` baseline.
    McpServerSuspiciousLauncher {
        server_name: String,
        /// The config's `command` string, verbatim.
        command: String,
        shape: LauncherShape,
        /// Token that triggered the verdict — `"bash -c"`-style for shell,
        /// the matched path string (command itself or one arg) for
        /// transient_path.
        evidence: String,
    },
    /// #145 — a committed project config pre-approves project-scope MCP
    /// servers so they auto-launch on folder-trust (TrustFall class). The
    /// `mechanism` names the specific auto-enable signal (a settings key, or
    /// a tool's folder-trust default). Emitted as POSTURE; the launched
    /// server's own command is scored separately via `emit_one_server`.
    ProjectMcpAutoEnabled {
        mechanism: String,
    },
    /// #146 — a repo-local agent instruction file (CLAUDE.md / AGENTS.md /
    /// .cursorrules / .cursor/rules) contains a high-signal exec or
    /// prompt-injection directive. POSTURE only (advisory, never a hook block).
    InstructionFileDirective {
        path: PathBuf,
        directive_kind: InstructionDirectiveKind,
        snippet: String,
    },
    /// #191 — an unattended, recurring Claude Code scheduled task is configured
    /// (`~/.claude/scheduled-tasks/<name>/SKILL.md` exists). The readable,
    /// persistent equivalent of a loop/goal running without a human in the
    /// loop. POSTURE only; `name` is the task subdir name.
    UnattendedScheduledTask {
        name: String,
    },
    /// #148 — an MCP tool's advertised description (or its namespace
    /// description) contains an imperative aimed at the model/client rather
    /// than documenting the tool — i.e. prompt injection embedded in tool
    /// metadata ("ignore previous instructions", "do not tell the user", a
    /// `<important>` marker, …). `pattern` names the matched detector for
    /// evidence. POSTURE only. Static — no baseline needed.
    McpToolInstructionOverride {
        server: String,
        tool: String,
        pattern: String,
    },
    /// #148 — an MCP tool surface (description / namespace description /
    /// input schema) contains hidden or deceptive Unicode: zero-width chars,
    /// bidi controls, other control/format codepoints, or homoglyph mixing.
    /// `kind` is the sub-class ("zero_width" | "bidi" | "control" |
    /// "homoglyph"). POSTURE only. Static.
    McpToolHiddenText {
        server: String,
        tool: String,
        /// Sub-class of hidden text. Named `text_kind` (not `kind`) because the
        /// enum is internally tagged with `tag = "kind"`.
        text_kind: String,
    },
    /// #148 — the same MCP tool name is advertised by two or more distinct
    /// servers (name shadowing / tool squatting): a malicious server can
    /// shadow a trusted tool's name so calls route to it. `servers` lists the
    /// colliding server names. POSTURE only. Cross-tool (computed over the
    /// whole snapshot, not per-tool).
    McpToolNameShadow {
        tool: String,
        servers: Vec<String>,
    },
    /// Cached metadata differs from the daemon's first observed baseline.
    /// Advisory only: a baseline is not a user approval or a signature.
    McpToolSurfaceDrift {
        server: String,
        tool: String,
        baseline_hash: String,
        current_hash: String,
    },
    McpUnapprovedNewTool {
        server: String,
        tool: String,
        current_hash: String,
    },
    McpSchemaPrivilegeExpansion {
        server: String,
        tool: String,
    },
    /// Server-supplied readOnlyHint conflicts with an execution/write parameter.
    /// This heuristic does not prove the implementation writes or skips approval.
    McpReadOnlyHintContradiction {
        server: String,
        tool: String,
    },
    /// #199 — a classifier-mediated auto-approval mode (Claude Code's
    /// `autoMode`) had its built-in safety rules discarded. The deny lists
    /// splice the defaults in via a `"$defaults"` marker; a list written
    /// without it silently replaces them rather than extending them, so the
    /// shipped protections stop applying. `list` names which one
    /// (`soft_deny` | `hard_deny`). POSTURE only. Static.
    AutoModeDefaultsDropped {
        list: String,
    },
    /// #199 — a hook forwards the tool call off-box instead of running a local
    /// command: Claude Code's `http` hook type POSTs the full tool-call JSON to
    /// a URL, so every intercepted call (and its arguments) leaves the machine.
    /// `destination` is the configured URL host, `hook_event` the event it is
    /// registered on. POSTURE only. Static.
    HookForwardsToolCalls {
        hook_event: String,
        destination: String,
    },
    /// #199 — a default prompt for unattended, session-scoped scheduled runs
    /// exists on disk (`loop.md`). Same class as
    /// [`AiGuardReason::UnattendedScheduledTask`]: work that repeats with no
    /// human watching. `source` is `user` or `project`. POSTURE only. Static.
    UnattendedLoopPrompt {
        source: String,
    },
    /// #200 — a standing rule auto-approves commands by prefix without
    /// prompting (Codex's `~/.codex/rules/*.rules`
    /// `prefix_rule(pattern=[…], decision="allow")`). Unlike a session
    /// approval this persists, so every future command matching the prefix
    /// runs unattended. `pattern` is the approved prefix. POSTURE only. Static.
    StandingCommandApproval {
        pattern: String,
    },
    /// #200 — a Codex MCP server lets named tools run without approval
    /// (per-tool `approval_mode = "approve"`). Narrower than
    /// [`AiGuardReason::TrustedMcpServer`], which covers every tool. `tools`
    /// holds sorted tool names only. POSTURE only. Static.
    McpToolsAutoApproved {
        server_name: String,
        tools: Vec<String>,
    },
    /// #199 — a repository's Claude Code settings enable a plugin. Claude Code
    /// applies a project `enabledPlugins` at session start, before the
    /// workspace trust dialog and in `claude -p`, and a plugin can ship hooks
    /// and MCP servers. `plugins` lists the `name@marketplace` keys; one
    /// finding per file, since committing team plugins is the documented use.
    /// POSTURE only.
    ProjectSettingsPluginEnabled {
        plugins: Vec<String>,
    },
    /// #199 — a repository's Claude Code settings hold a helper command
    /// (`apiKeyHelper` and its siblings). `claude -p` and the SDK run it in a
    /// folder that was never trusted. `key` names the setting; the command is
    /// not recorded, because a helper can embed a credential. #200 — also
    /// Codex `notify` (`key = "notify"`), a program run after every turn,
    /// from user or system config. POSTURE only.
    ProjectSettingsHelperCommand {
        key: String,
    },
    /// #199 — a repository's Claude Code `env` block sets a variable that
    /// reroutes traffic, loads code into subprocesses, or weakens TLS checks.
    /// It applies at startup in `claude -p`; interactive sessions wait for the
    /// trust dialog. `effect` is `redirect` | `exec_code` | `weaken_tls`, and
    /// `destination` the target host of a `redirect`. The value itself is not
    /// recorded. #200 — also Codex config: `variable` is then the config key
    /// (`openai_base_url`, `model_providers.<id>.base_url`, or
    /// `shell_environment_policy.set.<NAME>`). POSTURE only.
    ProjectSettingsEnvOverride {
        variable: String,
        effect: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        destination: Option<String>,
    },
    /// #199 — a repository's Claude Code settings run an interface command
    /// (`statusLine`, `subagentStatusLine`, `fileSuggestion`). It runs only in
    /// an interactive session, after the workspace trust dialog. `key` names
    /// the setting; the command is not recorded. POSTURE only.
    ProjectSettingsUiCommand {
        key: String,
    },
    /// #199 — a repository's Claude Code settings register a plugin
    /// marketplace. Claude Code honors it only after the workspace trust
    /// dialog, in `claude -p` too. `source` is the source type with its GitHub
    /// repo or URL host, never a full URL. POSTURE only.
    ProjectSettingsMarketplace {
        name: String,
        source: String,
    },
}

/// #146 — category of instruction-file directive. Stable wire strings
/// (SIEM filter keys; renames are breaking).
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InstructionDirectiveKind {
    FetchPipe,
    Destructive,
    Obfuscation,
    OverrideMarker,
}

/// #127 — classification of a suspicious stdio MCP launcher. Stable wire
/// strings ("shell" / "transient_path") — SIEM filter keys, renames are
/// breaking changes.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LauncherShape {
    Shell,
    TransientPath,
}

/// Persisted form of a hook observation (#64). Distinct from the IPC
/// `hook_proto::HookInvocation` so the SIEM schema and the IPC schema evolve
/// independently. `peer_uid` is stamped by the agent from the kernel
/// (`SO_PEERCRED`), never self-reported by the hook.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct HookInvocationEvidence {
    pub agent: AiTool,
    pub peer_uid: u32,
    pub agent_session_id: Option<String>,
    pub tool_use_id: Option<String>,
    /// Normalized action kind: "bash" | "powershell" | "file_edit" | "mcp_call" | "other".
    pub action_kind: String,
    /// Tool name when `action_kind == "other"`, else `None`. Carries the
    /// original tool name (e.g. "WebFetch") for non-Bash/Edit/MCP tools.
    pub other_label: Option<String>,
    /// blake3 over the raw pre-mask normalized action (lowercase hex).
    pub action_hash: String,
    /// Redacted/capped preview, or `None` under hash_only.
    pub action_preview: Option<String>,
    pub capture_level: String,
    pub capture_status: String,
}

/// lodeline-hook Stage 2 (#100). A consequential decision outcome — a deny, or a
/// degradation where enforcement could not be evaluated. NOT emitted on allow
/// (observe already records every invocation via HookInvocation).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct HookDecisionEvidence {
    pub agent: AiTool,
    pub peer_uid: u32,
    pub agent_session_id: Option<String>,
    pub tool_use_id: Option<String>,
    /// Normalized action kind: "bash" | "powershell" | "file_edit" | "mcp_call" | "other".
    pub action_kind: String,
    pub action_hash: String,
    pub action_preview: Option<String>,
    /// "deny" | "fail_open_error" | "fail_closed_error".
    /// `fail_*_error` values are reserved for the daemon-reachable-but-failed
    /// degradation path (follow-on); slice 1's pre-compiled evaluator emits only "deny".
    pub decision: String,
    pub rule_id: Option<String>,
    pub deny_reason: Option<String>,
    /// "observe" | "enforce".
    pub enforcement_mode: String,
    pub capture_level: String,
}

/// lodeline-hook tamper-evidence (#100). A detected drift between the recorded
/// hook registration baseline and the live agent settings file.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct HookConfigDriftEvidence {
    pub agent: AiTool,
    pub peer_uid: u32,
    /// "baseline_absent" | "entry_missing" | "command_drift" | "matcher_drift".
    pub drift_kind: String,
    pub settings_path: String,
    pub expected_command_hash: String,
    pub observed_command_hash: Option<String>,
    pub expected_matcher: Option<String>,
    pub observed_matcher: Option<String>,
}

/// lodeline-hook silence-detection (#107). A low-confidence tamper hint: an agent
/// recently observed using its hook went hook-silent while its session files
/// were still being written. Detection, not proof; a knowledgeable same-uid
/// attacker is out of model.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct PossibleHookActivitySilentEvidence {
    pub agent: AiTool,
    pub uid: Option<u32>,
    #[serde(with = "time::serde::rfc3339")]
    pub last_hook_seen_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    pub last_session_activity_at: Option<OffsetDateTime>,
    pub window_secs: u64,
    pub probe_kind: String,
    // blake3 of the matched session path — NEVER the raw path.
    pub path_hash: Option<String>,
    pub probe_error: Option<String>,
    pub scan_truncated: bool,
    pub confidence: Confidence,
}

/// Phase 3b.4-pre — full host identity / OS / network snapshot, emitted by
/// host_meta_snapshot_task. Surfaces hostname (so server-side fleet views
/// can label hosts with something human-readable instead of UUIDs) plus
/// OS and network metadata for additional fleet attribution.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub struct HostMetaSnapshot {
    /// Local hostname per the OS (e.g., "alice-macbook-pro").
    pub hostname: Option<String>,

    /// OS name (e.g., "macOS", "Rocky Linux", "Windows").
    pub os_name: Option<String>,
    /// OS version string (e.g., "14.5", "9.3", "11").
    pub os_version: Option<String>,
    /// Kernel version (e.g., "23.5.0", "5.14.0-427.20.1.el9_4.x86_64").
    pub kernel_version: Option<String>,
    /// CPU architecture (e.g., "x86_64", "aarch64").
    pub architecture: Option<String>,

    /// All non-loopback network interfaces with assigned addresses.
    pub interfaces: Vec<NetworkInterface>,
    /// IPv4 default gateway, if discoverable.
    pub default_gateway_v4: Option<String>,
    /// IPv6 default gateway, if discoverable.
    pub default_gateway_v6: Option<String>,
    /// Configured DNS resolver IPs (system resolver only — not per-interface).
    pub dns_servers: Vec<String>,
}

/// Phase 3b.4-pre — one network interface inside a `HostMetaSnapshot`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub struct NetworkInterface {
    /// Interface name (e.g., "en0", "eth0", "Ethernet 1").
    pub name: String,
    /// MAC address as colon-separated lowercase hex
    /// (e.g., "00:1b:44:11:3a:b7"). None for interfaces without an L2
    /// address (loopback excluded upstream).
    pub mac: Option<String>,
    /// IPv4 addresses assigned, each as "addr/prefix" (e.g., "10.0.1.42/24").
    pub ipv4: Vec<String>,
    /// IPv6 addresses assigned, each as "addr/prefix" (e.g., "fe80::1/64").
    pub ipv6: Vec<String>,
}

/// The observation payload of an event.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Evidence {
    FileChange {
        change_kind: FileChangeKind,
        before_hash: Option<String>,
        after_hash: Option<String>,
        recheck_hash: Option<String>,
        rename_from: Option<PathBuf>,
        size_after: Option<u64>,
        evidence_quality: EvidenceQuality,
    },
    Heartbeat {
        uptime_s: u64,
        is_final: bool,
        channel_stall_events_total: u64,
        events_emitted_total: u64,
        events_by_kind: BTreeMap<String, u64>,
        hash_p50_ms: u32,
        hash_p99_ms: u32,
        watcher_backend: String,
        state_db_size_bytes: u64,
        #[serde(with = "time::serde::rfc3339::option")]
        last_log_rotation_ts: Option<OffsetDateTime>,
        /// Phase 2: agent's currently-applied policy version (0 if none yet).
        last_applied_policy_version: i64,
        /// Phase 2: `true` iff the active envelope's valid_until is in the past.
        policy_expired_active: bool,
        /// Phase 2: `true` iff `events/` is currently above the GC soft floor.
        jsonl_above_soft_floor: bool,
    },
    PermissionMissing {
        resource: String,
        platform_hint: String,
    },
    ChannelStall {
        channel: String,
        blocked_seconds_in_window: f32,
        block_events_in_window: u64,
        #[serde(with = "time::serde::rfc3339")]
        first_block_ts: OffsetDateTime,
    },
    WatcherDegraded {
        from: String,
        to: String,
        reason: String,
    },
    AgentDying {
        reason: AgentDyingReason,
        detail: String,
        task: Option<String>,
    },
    RateLimitExceeded {
        target_id: String,
        count_dropped_in_window: u64,
        common_path_prefix: PathBuf,
    },
    /// Spec §3.10: hw_fingerprint changed while host_id stayed the same.
    /// Emitted by the agent when the freshly-computed fingerprint differs
    /// from the persisted one in `state.db`.
    HostIdFingerprintDrift {
        /// Previously-persisted fingerprint hex (blake3 → 64 chars).
        prev_fingerprint: String,
        /// Freshly-computed fingerprint hex.
        new_fingerprint: String,
    },
    /// Spec §3.9: emitted exactly once per GC cycle that crossed the
    /// hard ceiling (size or age). Operators dashboard on this — non-zero
    /// rate means the host is permanently behind on shipping.
    AgentJsonlForceGc {
        /// Total bytes in `events/` at the time of the cycle.
        total_bytes: u64,
        /// Age in seconds of the oldest segment at the time of the cycle.
        oldest_segment_age_s: u64,
        /// How many segments were deleted in the cycle.
        segments_deleted: u32,
        /// Of those, how many were past the sender offset.
        segments_skipped_past_sender: u32,
    },
    /// Spec §3.9: emitted whenever the GC deleted at least one segment
    /// that the sender had NOT yet shipped. One event per cycle (NOT per file).
    SenderSkippedSegment {
        /// Number of segments dropped past the sender in this cycle.
        count: u32,
        /// Filename of the OLDEST segment dropped past the sender (operators
        /// can grep their SIEM around this segment's expected event-id range).
        oldest_dropped_filename: String,
    },
    /// Spec §3.8.2: a `SignedPolicyResponse` was rejected by the verification
    /// chain. Emitted by the agent when an inbound envelope fails any check;
    /// the policy is NOT applied and `last_applied_policy_version` is NOT
    /// advanced.
    PolicySignatureInvalid {
        /// Which check failed.
        reason: PolicySignatureInvalidReason,
        /// `signing_pubkey_id` from the rejected response (operator triage).
        signing_pubkey_id: String,
        /// `policy_version` claimed by the rejected envelope.
        policy_version_in_envelope: i64,
        /// The agent's current `last_applied_policy_version` at rejection time.
        last_applied_policy_version: i64,
    },
    /// Spec §3.10: emitted exactly once when a freshly-verified policy is
    /// committed to disk + state.db. Operators use this to confirm rollouts.
    PolicyReloaded {
        /// The new `last_applied_policy_version`.
        policy_version: i64,
    },
    /// Emitted exactly once when a freshly-verified rule-pack bundle is
    /// committed to disk + state.db. Sibling of `PolicyReloaded` for the
    /// SEPARATE rule-packs watermark, so operators can distinguish a rule-pack
    /// rollout from a policy rollout in the SIEM.
    RulePackBundleApplied {
        /// The new `last_applied_rule_packs_version`.
        version: i64,
    },
    /// Spec §3.10: emitted exactly once per "transition into expired".
    /// The agent continues to enforce the expired policy until a replacement
    /// arrives — `valid_until` is informational, not blocking. (Spec §1.4
    /// "Active policy passing valid_until" — agent keeps applying the last
    /// good policy on the local file system; SIEM operators triage.)
    PolicyExpiredActive {
        /// The version of the policy whose `valid_until` was crossed.
        policy_version: i64,
        /// RFC 3339 — when `valid_until` was crossed.
        #[serde(with = "time::serde::rfc3339")]
        valid_until: time::OffsetDateTime,
    },
    /// Sender saw HTTP 409 from /v1/events: host_id bound to a different cert.
    HostIdConflict { observed_status: u16 },
    /// Sender saw HTTP 426 from /v1/events: agent is two minor versions or older.
    AgentTooOld {
        observed_status: u16,
        agent_version: String,
    },
    /// Sender's client cert past `valid_until` or close to it.
    CertExpired {
        #[serde(with = "time::serde::rfc3339")]
        cert_expires_at: time::OffsetDateTime,
    },
    /// TLS handshake failure (CA mismatch, expired cert, etc.).
    TlsFailure { reason: String },
    /// Per-event hard rejection logged locally for operator audit.
    EventUnprocessableLocal {
        original_event_id: uuid::Uuid,
        server_reason: String,
    },
    /// Server returned 200 without `high_water_event_id` (or other shape break).
    ServerProtocolViolation { detail: String },
    /// `oldest_unsent_age` exceeded the agent's JSONL retention window.
    SenderLagCritical {
        lag_events: u64,
        lag_bytes: u64,
        oldest_unsent_age_s: u64,
    },
    /// Phase 3b.1 — periodic + change-triggered assessment of an AI coding
    /// agent's local guard surface (hooks, permissions, sandbox).
    /// Emitted by ai_guard_task. Lodeline measures, does not block.
    AiGuardRiskAssessed {
        /// None = unreported; Some(empty) = inspected with no active observations.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        controls: Option<Vec<AiGuardControl>>,
        tool: AiTool,
        scope: AiGuardScope,
        /// 0.0..=10.0 (CVSS-style continuous; higher = more risk).
        score: f32,
        /// Auto-derived from `score` (low <1 / medium <4 / high <7 / critical 7+).
        bucket: AiGuardBucket,
        /// Per-finding breakdown. Empty array = clean assessment.
        reasons: Vec<AiGuardReason>,
        /// `true` iff this is the periodic re-attestation heartbeat (no
        /// reason or control change since last emission). `false` = something changed.
        is_reattestation: bool,
        /// Phase 3b.7.2 — Some(pack id) when emitted by an operator rule-pack
        /// parser; None (omitted) for built-in structural parsers. Forward-compat.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        rule_pack_id: Option<String>,
        /// Phase 3b.7.5 — human-readable name of an `AiTool::Other` tool, from the
        /// rule pack's `tool_label`. None (omitted) for built-in tools. Forward-compat.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        tool_label: Option<String>,
        /// #329 — the OS account whose home was assessed, when a root agent
        /// assesses each user's configs. None (omitted) for the agent's own
        /// home and for project scopes, the shape older agents emit.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        user: Option<String>,
    },
    /// #147 — a dangerous self-config toggle flipped OFF→ON between snapshots
    /// (auto-approve / sandbox-off / broad-allow / project-MCP-autorun). One-time
    /// change event; the standing state rides the normal AiGuardRiskAssessed reasons.
    AiGuardToggleDrift {
        tool: AiTool,
        scope: AiGuardScope,
        /// The dangerous-toggle kind that turned on, e.g. "auto_approval_enabled".
        toggle: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        rule_pack_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        tool_label: Option<String>,
        /// #329 — same as `AiGuardRiskAssessed.user`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        user: Option<String>,
    },
    /// Phase 3b.4-pre — periodic snapshot of host identity + network + OS
    /// metadata. Emitted by host_meta_snapshot_task on boot, every 24h, and
    /// whenever the snapshot's canonical hash differs from the last
    /// emission. Lodeline measures, does not block.
    HostMetaSnapshot {
        snapshot: HostMetaSnapshot,
        /// `true` iff this is the periodic 24h re-attestation (snapshot
        /// unchanged since last emit). `false` = boot scan or change detected.
        is_reattestation: bool,
    },
    /// lodeline-hook Stage 1 (#64). One observed agent tool call.
    HookInvocation(HookInvocationEvidence),
    /// lodeline-hook Stage 2 (#100). A deny / degradation decision outcome.
    HookDecision(HookDecisionEvidence),
    /// lodeline-hook tamper-evidence (#100). Hook registration drift vs the install baseline.
    HookConfigDrift(HookConfigDriftEvidence),
    /// #107 — low-confidence hook-silence hint.
    PossibleHookActivitySilent(PossibleHookActivitySilentEvidence),
    /// Forward-compat: an evidence kind this build doesn't recognize. A newer
    /// producer's variant deserializes here instead of failing the whole event.
    #[serde(other)]
    Unknown,
}

/// Supported configuration observations, not runtime enforcement attestations.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct AiGuardControl {
    /// Stable, namespaced ID; unknown future IDs remain readable.
    pub id: String,
    pub source_path: PathBuf,
    pub setting: String,
    /// Parser-allowlisted restriction value, never a raw configuration object.
    pub value: serde_json::Value,
}

/// Schema version. Bumps follow the policy in spec section 3.3.
pub const SCHEMA_VERSION: u32 = 1;

/// `env!("CARGO_PKG_VERSION")` of the agent crate at build time.
pub const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// A single posture event.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Event {
    pub schema_version: u32,
    pub event_id: Uuid,
    #[serde(with = "time::serde::rfc3339")]
    pub ts: OffsetDateTime,
    pub host_id: String,
    pub agent_version: String,
    pub severity: Severity,
    pub source: SourceKind,
    pub subject: Subject,
    pub evidence: Evidence,
    pub target_id: Option<String>,
}

impl Event {
    /// Convenience builder used in tests and by callers that have all fields ready.
    pub fn new_file_change(
        ts: OffsetDateTime,
        host_id: impl Into<String>,
        path: PathBuf,
        evidence: Evidence,
        target_id: Option<String>,
    ) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            event_id: Uuid::now_v7(),
            ts,
            host_id: host_id.into(),
            agent_version: AGENT_VERSION.to_string(),
            severity: Severity::Warn,
            source: SourceKind::FileSystem,
            subject: Subject::Path { value: path },
            evidence,
            target_id,
        }
    }
}
