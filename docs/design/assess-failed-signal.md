# Assess-failed signal and current_risk attribution

Status: proposal. Rollout steps 2 (Option B1), 3 (Option A3 ingest on the
server), 4 (console), 5 (Option A3 emission in the agent) and 6 (docs) are
implemented. Step 1 is implemented for `AiGuardReason` only: `AiTool`,
`AiGuardBucket` and `AiGuardScope` still reject an unknown value. Tracks two
items from issue #333.

This document covers two gaps in how AI Guard posture reaches the fleet:

1. A parser whose assessment fails sends no signal of its own, so the console
   and the SIEM show a stale score or nothing.
2. `current_risk` names the riskiest score per tool but not which user or rule
   pack produced it.

Both touch the wire or the fleet API, so the compatibility rules come first.
Each item then gets its options, a recommendation, and the console and SIEM
work it implies. The rollout order and the test plan close the document.

## What older servers reject

Every option below must survive a fleet where agents, servers and the console
upgrade at different times. These facts hold for `origin/main` and for the
released v0.12.2 server. They were checked by reading the code and by
deserializing probe events against `lodeline_core::event::Event`.

The server decodes each event in `validate`
(`crates/lodeline-server/src/events_route.rs:55-67`). A decode error returns
`malformed_payload` for that event (`events_route.rs:56-58`). Only accepted
events go into `to_persist` (`events_route.rs:126-142`), so a rejected event
never reaches the server JSONL, the fleet index or a SIEM that reads the server
JSONL. The sender records each rejection as a local `event_unprocessable_local`
dead letter (`crates/lodeline-sender/src/data_task.rs:342-357`) and then
advances its offset (`data_task.rs:382`). The sender does not retry the event.

| Change on the wire | Older server | Where |
|---|---|---|
| Unknown `AiGuardReason` kind inside `reasons` | Rejects the whole event, through v0.12.6. Servers released after v0.12.6 have rollout step 1 and accept it as `AiGuardReason::Unknown` | `AiGuardReason` is internally tagged with no `#[serde(other)]` fallback (`crates/lodeline-core/src/event.rs:162-164`) |
| Unknown evidence `kind` | Accepts it as `Evidence::Unknown` | `#[serde(other)]` at `event.rs:783-786`, present since v0.3.0 (commit `29d09e0`, #83) |
| Unknown field on a known evidence kind | Accepts it and ignores the field | No `deny_unknown_fields` on `Event` or `Evidence` |
| Unknown `AiTool` value | Rejects the whole event | No fallback on `AiTool` (`event.rs:105-107`) |
| Unknown `AiGuardBucket` value | Rejects the whole event | No fallback on `AiGuardBucket` (`event.rs:150-152`) |
| Unknown `AiGuardScope` kind | Rejects the whole event | No fallback on `AiGuardScope` (`event.rs:130-132`) |
| `score: null` | Rejects the whole event | `score` is a required `f32` |
| `schema_version` other than 1 | Rejects every event with `schema_mismatch` | `events_route.rs:60-62`, `SCHEMA_VERSION` at `event.rs:801` |

Two more facts shape the options:

- The server persists the raw payload (`crates/lodeline-server/src/persist.rs:125`),
  so an accepted event keeps its unknown kind and unknown fields in the server
  JSONL. The fleet index has no handling of its own for `Evidence::Unknown`
  (`crates/lodeline-server/src/fleet_index_update.rs:194`). It still updates the
  host's `agent_version`, `last_seen_ts` and 24h severity counts, as for every
  event.
- The SIEM runbook ingests the agent's own JSONL
  (`docs/runbook/siem-rules.md:8`), which no server ever filters. A SIEM on that
  path sees every new kind, field and reason as soon as the agent upgrades.

The console decodes fleet API responses with Go `encoding/json`, which ignores
unknown fields, and `sigil-manager/internal` never calls
`DisallowUnknownFields`. Reasons stay raw `json.RawMessage`
(`sigil-manager/internal/fleet/client.go:353`). An additive field in the fleet
API is therefore safe for an older console.

The rule that follows: a new agent must never put an unknown reason kind, tool,
bucket or scope kind into an event that an older server will decode. A new
evidence kind and a new optional field are both safe. Rollout step 1 is
implemented for reason kinds, but it protects only servers that have it, so the
rule still holds.

## Item A: an explicit assess-failed signal

### How a failure behaves today

This section describes the agent before rollout step 5, which replaced this
behavior with `ai_guard_assess_failed`.

`eval_and_maybe_emit` (`crates/lodeline-agent/src/ai_guard/task.rs:206-232`)
handles an `assess_posture` error in two ways:

- On a change-driven cycle, the agent logs and sends nothing.
- On the 24h heartbeat, the agent re-sends the cached reasons from
  `CachedAssessment` as a reattestation with a fresh `ts`.

That gives the two failure modes from #333:

- **A user can freeze their own reading.** The user makes a config the parser
  reads unreadable, for example by padding it past its size cap, while making a
  risky change. The old clean reading keeps arriving every 24h as if it were
  current.
- **A restart loses the reading.** `CachedAssessment` lives only in memory. After
  an agent restart a failing parser has nothing to re-send, so the agent sends
  nothing, and since v0.12.0 (#332) the server prunes that source after 48h.

The agent does know when the last good assessment happened while it runs
(`CachedAssessment.last_assessed_ts`, `task.rs:60`). It forgets it on restart.

### Option A1: a new reason kind

The agent adds `{"kind": "assess_failed", "since": "...", "error_kind": "..."}`
to `reasons` on an `ai_guard_risk_assessed` event.

- **Wire shape.** No new event. One new `AiGuardReason` variant.
- **Older servers.** Every such event is rejected as `malformed_payload`. Each
  24h reattestation of that source is rejected too, so the source never reaches
  the server. The server must upgrade first, and the agent has no way to learn
  the server version before it sends.
- **Older agents.** No change.
- **Console.** Must recognize the reason kind and stop treating the score as a
  real reading.
- **SIEM.** Filters on `evidence.reasons[].kind`. The score on the event is
  still a number, so score-based rules see a value that measures nothing.

A reason is a finding that the rubric scores. A failure is the absence of a
finding, so this option mixes the two and breaks every server in the field. It
is not viable.

### Option A2: a field on `ai_guard_risk_assessed`

The agent keeps sending `ai_guard_risk_assessed` and adds an optional object:

```json
"assess_failure": {
  "error_kind": "unreadable",
  "failing_since": "2026-11-03T10:00:00Z",
  "last_assessed_ts": "2026-11-02T09:00:00Z"
}
```

`score`, `bucket` and `reasons` carry the last good reading.

- **Older servers.** They accept the event and ignore the field, so they show
  the stale reading as current. That is the freeze from today, unchanged.
- **Restart case.** After a restart there is no last good reading, but `score`,
  `bucket` and `reasons` are required. The agent must either send nothing,
  which is today's behavior, or send a placeholder such as `0.0` and `low`. An
  older server and every score-based SIEM rule would read that placeholder as a
  clean host. Neither choice fixes the restart case.
- **Older agents.** No change.
- **Console.** Reads the new field and shows "unassessed since" next to the
  score.
- **SIEM.** A field filter works, but the event still carries a real-looking
  score, so a rule that does not know the field keeps trusting it.

A2 is the smallest change, but it cannot express "no reading at all", and it
keeps the misleading score on every path that does not know the field.

### Option A3: a new evidence kind (recommended)

The agent sends a separate event whenever a parser fails:

```json
"evidence": {
  "kind": "ai_guard_assess_failed",
  "tool": "claude_code",
  "scope": {"kind": "user_global"},
  "user": "alice",
  "rule_pack_id": null,
  "tool_label": null,
  "error_kind": "unreadable",
  "path": "/Users/alice/.claude/settings.json",
  "failing_since": "2026-11-03T10:00:00Z",
  "last_assessed_ts": "2026-11-02T09:00:00Z",
  "is_reattestation": false
}
```

Field rules:

- `tool`, `scope`, `user`, `rule_pack_id` and `tool_label` follow
  `ai_guard_risk_assessed` exactly, so the event maps to the same
  `RiskSourceKey` (`crates/lodeline-server/src/fleet_index.rs:9`). `user`,
  `rule_pack_id` and `tool_label` are omitted when `None`.
- `error_kind` is a string, not a Rust enum without a fallback, so a later value
  can never fail decoding on an older server. Start with `unreadable`,
  `too_large` and `parse`.
- `path` is the file that failed. It carries no file content and no free-form
  error text, so nothing from the config leaks.
- `failing_since` is the first failure the running agent saw for this source.
  After a restart it resets to the first failure since the restart.
- `last_assessed_ts` is `CachedAssessment.last_assessed_ts`, or `null` after a
  restart.
- `severity` is `warn`.

Agent behavior:

- The agent sends `ai_guard_assess_failed` on the cycle that first fails, on
  either trigger.
- While the source keeps failing, the 24h heartbeat re-sends it with
  `is_reattestation: true`. The agent stops re-sending the cached reading
  (`task.rs:222-229`), which removes the freeze.
- The first successful assessment after a failure always emits
  `ai_guard_risk_assessed`, even when the reasons match the cache. Without that
  rule, an unchanged config would wait up to 24h for the heartbeat to clear the
  failure.

Server behavior:

- The fleet index handles the new kind next to `ai_guard_risk_assessed`. If the
  source already has a reading, the server keeps the score and marks it
  unassessed since `failing_since`. If it has none, the server stores an
  unassessed source with no score.
- Each failure report refreshes the source's prune time, capped at the receive
  time as the fix for future-dated readings already does. A source that keeps
  reporting failure is never pruned. A source that stops sending both readings
  and failures drops after 48h, as today.
- The next `ai_guard_risk_assessed` for that source replaces the entry and
  clears the unassessed mark.
- A stale score still counts toward the tool's `current_risk`. The server never
  shows an unassessed source as clean.

Compatibility:

- **Older servers.** Every release since v0.3.0 accepts the event as
  `Evidence::Unknown` and writes the raw event to its JSONL. The fleet index
  still updates the host's `agent_version`, `last_seen_ts` and 24h counts. Each
  failure and each heartbeat re-send adds one to the host's
  `open_event_counts_24h.warn`
  (`crates/lodeline-server/src/routes/fleet_hosts.rs:223`). The event is not an
  alert, and `current_risk` does not change. Because a new agent stops re-sending
  the stale reading, a v0.12 server drops the failing source after 48h instead of
  showing the frozen reading. A pre-v0.12 server keeps the last reading forever,
  as it does today.
- **Older agents.** They never send the kind. A new server behaves exactly as
  today for them.
- **Upgrade order.** Either side can go first without lost events. Upgrade the
  server first so that the agents' change shows up as "unassessed" and not as a
  source that disappears.

Fleet API shape, additive only:

- The host list and host detail get a new top-level `ai_guard_unassessed`
  field: a map from tool to `{since, last_assessed_ts, sources: [...]}`, where
  each source carries `scope`, `user`, `rule_pack_id`, `error_kind` and `path`.
  The field is `null` when nothing is failing.
- `current_risk.by_tool.<tool>` and the host detail's `ai_guard.by_tool.<tool>`
  gain `unassessed_since` when the tool's top reading is stale.
- `current_risk` itself stays `null` for a host that has failures but no score.
  Putting a score-less tool into `by_tool` would make an older console decode
  `score` as `0` and show a clean host.

Console work (sigil-manager):

- Read `ai_guard_unassessed` and `unassessed_since`. Show an "unassessed since X"
  badge on the fleet table, the risk table and the host's AI Guard panel.
- Render `ai_guard_assess_failed` in the event timeline. `/v1/events` returns
  raw JSONL, so the console already receives the kind and must not drop or
  mislabel it.
- Update the fleet API contract (§5.3, §5.4, §5.5) for the new fields. The root
  session files that issue in the manager repo.

SIEM impact:

- A new `evidence.kind` to alert on. Suggested rule: alert when
  `ai_guard_assess_failed` for a `(host_id, tool, scope, user, rule_pack_id)`
  has a `failing_since` older than one hour and no later
  `ai_guard_risk_assessed` for that source.
- Score-based rules stop seeing frozen readings, because the agent no longer
  re-sends them.
- Do not add the kind to `alerts_definition_default`
  (`crates/lodeline-server/src/routes/meta.rs:16-20`) at first. A user saving
  an invalid JSON file mid-edit fails one cycle, and an alert on every such
  failure is noise. Revisit this after field data.

**Recommendation.** Use A3, because it is the only option that expresses "no
reading" without a fake score, and every server since v0.3.0 accepts it. The
agent stops re-sending stale readings, which closes the freeze, and the server
holds the source's slot while failures keep arriving, which closes the restart
gap.

## Item B: attribution for the max in `current_risk`

### What the server returns today

Since #329 the server keeps one reading per `(tool, scope, user, rule_pack_id)`
in `risk_sources` and folds them into `current_risk`, the riskiest reading per
tool (`fleet_index_update.rs:68-121`). `RiskEntry`
(`crates/lodeline-server/src/fleet_index.rs:14-25`) keeps `scope` but drops
`user` and `rule_pack_id`. As a result:

- The host list's `current_risk.by_tool` renders `score`, `bucket` and
  `assessed_ts` (`crates/lodeline-server/src/routes/fleet_hosts.rs:182-210`).
- The host detail's `ai_guard.by_tool` serializes `RiskEntry`, so it adds
  `scope` and `reasons` (`fleet_hosts.rs:280-291`).
- `/v1/fleet/risk` renders `top_tool` and nothing about the source
  (`crates/lodeline-server/src/routes/fleet_risk.rs:106-117`).

On a host where a root agent assesses every user, an operator sees "Claude Code
critical" and must search the event stream to learn whose config it is.

The event already carries `user` and `rule_pack_id`, so every option here is a
server and console change only. No agent change and no wire change are needed.

### Option B1: attribute the top reading (recommended)

Add one object to each `by_tool` entry and to each `/v1/fleet/risk` row:

```json
"source": {
  "scope": {"kind": "user_global"},
  "user": "alice",
  "rule_pack_id": "acme-extended",
  "tool_label": null
}
```

- **Wire.** No change. The server copies `user`, `rule_pack_id` and
  `tool_label` from the event into `RiskEntry`.
- **Older servers.** The object is absent. Because the attribution is one
  object, the console can tell "older server" (no `source`) from "agent's own
  home" (`source.user` is `null`). Bare `user` and `rule_pack_id` fields could
  not make that distinction, because `user: null` already means the agent's
  own home or a project scope (`event.rs` comment on `AiGuardRiskAssessed.user`).
- **Older agents.** They omit `user`, so `source.user` is `null`. That is the
  correct meaning for a non-root agent.
- **Upgrade order.** Server first. An older console ignores the object.
- **Console.** Show the user and the rule pack next to the tool's score in the
  fleet table, the risk table and the host panel.
- **SIEM.** None. SIEM rules already see `user` and `rule_pack_id` on every
  event. The max is a server rollup that the SIEM does not receive.

### Option B2: return every source

Add `sources: [...]` to each `by_tool` entry, with one row per `risk_sources`
entry for that tool, each holding `source`, `score`, `bucket` and `assessed_ts`.

- **Compatibility.** Same as B1: additive, server first, no agent change.
- **Cost.** The host list returns up to `limit` hosts, and a root agent on a
  shared machine can report one reading per user per tool per pack. The list
  payload grows with users times tools times packs for every host on the page.
- **Console.** Can render a per-user breakdown on the host page.
- **SIEM.** None.

B2 answers a broader question than #333 asks. If the host page wants the
breakdown later, add `sources` to the host detail route only and keep the list
on B1.

### Option B3: a separate endpoint

Add `GET /v1/fleet/hosts/{host_id}/risk_sources` and leave `current_risk`
unchanged.

- **Compatibility.** An older server returns 404, which the console must handle.
- **Console.** The fleet table still cannot show who produced the max without
  one extra request per host, which is the cost that B1 avoids.
- **SIEM.** None.

**Recommendation.** Use B1, because it answers "whose config is this" on every
surface that shows the score, at the cost of one small object per tool. Keep B2
as a later, detail-only addition if the host page needs a per-user table.

## Rollout order

1. **Server hardening, independent of both items.** Add an unknown-kind fallback
   to `AiGuardReason` so that a future reason kind cannot drop a whole event. Do
   the same for `AiTool` and `AiGuardBucket`, or decode them as strings in the
   server's ingest path. Ship this in the next server release. It protects only
   servers that have it, so agents must still follow the rule from the
   compatibility section for years.
2. **Server: B1.** Add `source` to `RiskEntry` and to the three routes. No agent
   dependency.
3. **Server: A3 ingest.** Handle `ai_guard_assess_failed` in the fleet index and
   render `ai_guard_unassessed` and `unassessed_since`. Ship it in the same
   release as step 2 if possible.
4. **Console.** Read `source`, `ai_guard_unassessed` and `unassessed_since`.
   Render the new event kind. The contract update lands in the manager repo
   through an issue.
5. **Agent: A3 emission.** Emit `ai_guard_assess_failed`, stop re-sending stale
   readings, and force an emit on recovery. Every server since v0.3.0 accepts
   the new events. On a server without step 3, a failing source drops out of
   `current_risk` without notice 48h after its last reading. This step waits
   for step 3 so that the source shows as unassessed instead.
6. **Docs.** Add the SIEM rule for `ai_guard_assess_failed` to
   `docs/runbook/siem-rules.md` and describe the new fields in the server docs.

## Test plan

Compatibility:

- A test in `lodeline-core` that decodes an `ai_guard_assess_failed` event with
  the v0.12.2 `Event` type, for example from a vendored copy of that release's
  `event.rs`, and asserts `Evidence::Unknown`. This pins the claim that older
  servers accept the kind.
- A test that an `ai_guard_risk_assessed` event with an unknown reason kind
  still decodes after step 1. Before step 1 it fails, which documents the
  current rejection.

Agent (`crates/lodeline-agent/src/ai_guard/task.rs`):

- A parser that fails on the first cycle emits one `ai_guard_assess_failed` with
  `last_assessed_ts: null`.
- A parser that succeeds and then fails emits `ai_guard_assess_failed` with
  `last_assessed_ts` set to the good cycle and does not re-send the cached
  reasons on the next heartbeat.
- A heartbeat while still failing re-sends `ai_guard_assess_failed` with
  `is_reattestation: true` and an unchanged `failing_since`.
- Recovery with reasons equal to the cache still emits `ai_guard_risk_assessed`.

Server (`crates/lodeline-server/src/fleet_index_update.rs` and the route tests):

- A failure report for a source with a reading keeps the score, sets
  `unassessed_since`, and keeps the source past 48h while reports keep arriving.
- A failure report for a source with no reading produces `ai_guard_unassessed`
  and leaves `current_risk` `null`.
- A reading after a failure clears the unassessed mark.
- A future-dated failure report cannot extend its own life or prune other
  sources, which reuses the receive-time cap from the future-timestamp fix.
- Boot replay from JSONL rebuilds the same unassessed state as live ingest.
- `current_risk.by_tool.<tool>.source` names the user and rule pack of the
  riskiest reading, and the tie on score picks the newest reading.
- `/v1/fleet/risk` rows carry `source` for `top_tool`.

End to end:

- On the 2-node AWS test environment, run a v0.12.2 server with a new agent and
  make a watched config unreadable. Confirm that the server accepts the failure
  event and writes it to JSONL, and that the source drops after 48h.
- Repeat with a new server and console. Confirm that the console shows
  "unassessed since X" with the user and the rule pack, and that the badge
  clears after the file is fixed.
