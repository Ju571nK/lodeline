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
check:    on a schedule, for each source take its latest ai_guard_assess_failed event F
trigger:  F.failing_since < now - 1h
          AND F.ts > now - 48h
          AND no evidence.kind == "ai_guard_risk_assessed" for the same source
              with ts > F.failing_since
severity: medium
note:     the parser could not read or parse a config, so the source has no
          current reading
```

Run the check on a schedule. If your SIEM evaluates a rule only when an event
arrives, the first alert comes at the first 24h re-send that arrives more than
1h after `failing_since`, so up to about 25h after `failing_since`.

Read the fields this way:

- `failing_since` is the first failure the running agent saw for the source. It
  stays the same until a good reading. It resets when the agent restarts, which
  also restarts the 1h age.
- `last_assessed_ts` is `null` until the agent has a good reading for the
  source since it started. That covers the first report after a restart and a
  source that has never read cleanly.
- The agent sends the event on the first failure and again when `error_kind` or
  `path` changes. While the source keeps failing, it re-sends the event every
  24h with the same `failing_since`. The re-send carries `is_reattestation: true`
  only when `error_kind` and `path` are unchanged. A re-send with a changed kind
  or path carries `false`. Key the rule on the source, not on the event, so a
  re-send does not open a second alert.
- `error_kind` is an open string. Today it is `unreadable` (the agent could not
  read the file) or `parse` (it read the file and could not parse it). Treat any
  other value as a failure too.
- `user` and `rule_pack_id` are absent when they do not apply. Absent `user`
  means the agent's own home or a project. Absent `rule_pack_id` means the
  built-in rules. Match them as null in the source key.
- The first good assessment after a failure always sends `ai_guard_risk_assessed`,
  even when the reasons equal the last reading, so the rule's last condition is
  met as soon as the source reads again.
- A source whose latest failure event is older than 48h has stopped reporting.
  The agent has stopped, the user was removed from the host, or a policy change
  removed the rule pack or project. The heartbeat absence rule covers a silent
  agent.

For agents from the release that carries #481, score-based rules no longer see a
frozen reading. While a source fails, the agent sends the failure event and does
not re-send the last reading.

`ai_guard_assess_failed` is not in `/v1/meta` `alerts_definition_default`, so the
server's `open_alert_count_24h` does not count it. It still counts in
`open_event_counts_24h.warn`.
