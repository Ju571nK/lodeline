# Recommended SIEM rules for Lodeline

Lodeline itself does not enforce these rules — they live in the customer's SIEM.

## Splunk inputs.conf

```
[monitor:///var/log/lodeline/events-*.jsonl]
sourcetype = lodeline:event:json
disabled   = false
```

## Datadog Agent

```yaml
logs:
  - type: file
    path: /var/log/lodeline/events-*.jsonl
    service: lodeline
    source: lodeline
```

## Heartbeat absence (host went silent)

```
trigger:  evidence.kind == "heartbeat" absent for 90s by host_id
severity: medium
action:   page on-call security
```

## Idempotent dedup (spec 1.4)

```
key:    (host_id, target_id, evidence.after_hash, floor(ts to 60s))
keep:   first; drop subsequent
```

## Critical-tier integrity recheck mismatch

```
trigger:  evidence.kind == "file_change"
          AND evidence.recheck_hash IS NOT NULL
          AND evidence.recheck_hash != evidence.after_hash
severity: high
note:     transient state existed between change and recheck
```

## Channel stall warning

```
trigger:  count(evidence.kind == "channel_stall") > 3 in 5min by host_id
severity: low
```

## Rate-limit exceeded

```
trigger:  evidence.kind == "rate_limit_exceeded" by host_id
severity: medium
note:     a process is generating events faster than 100/sec for one target
```

## AI Guard assessment failed

```
source:   (host_id, evidence.tool, evidence.scope, evidence.user, evidence.rule_pack_id)
trigger:  evidence.kind == "ai_guard_assess_failed"
          AND evidence.failing_since < now - 1h
          AND no evidence.kind == "ai_guard_risk_assessed" for the same source
              with ts > evidence.failing_since
severity: medium
note:     the parser could not read or parse a config, so the source has no
          current reading
```

Read the fields this way:

- `failing_since` is the first failure the running agent saw for the source. It
  stays the same until a good reading. It resets when the agent restarts, and
  the first report after a restart has `last_assessed_ts: null`.
- The agent sends the event on the first failure and again when `error_kind` or
  `path` changes. While the source keeps failing, it re-sends the event every
  24h with `is_reattestation: true` and the same `failing_since`. Key the rule
  on the source, not on the event, so a re-send does not open a second alert.
- `error_kind` is an open string. Today it is `unreadable` (the agent could not
  read the file) or `parse` (it read the file and could not parse it). Treat any
  other value as a failure too.
- `user` and `rule_pack_id` are absent when they do not apply. Absent `user`
  means the agent's own home or a project. Absent `rule_pack_id` means the
  built-in rules. Match them as null in the source key.
- The first good assessment after a failure always sends `ai_guard_risk_assessed`,
  even when the reasons equal the last reading, so the rule clears on the next
  cycle.
- A failing source is re-sent every 24h, so a source whose latest failure event
  is older than 48h has stopped reporting. The agent has stopped, or the user
  was removed from the host. The heartbeat absence rule covers a silent agent.
  Limit this rule to sources with a failure event in the last 48h.

Score-based rules no longer see a frozen reading. While a source fails, the
agent sends the failure event and does not re-send the last reading.

`ai_guard_assess_failed` is not in `/v1/meta` `alerts_definition_default`, so the
server's `open_alert_count_24h` does not count it. It still counts in
`open_event_counts_24h.warn`.
