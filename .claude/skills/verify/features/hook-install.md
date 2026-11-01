# Hook install

`lodeline-hook install` prints the hook registration for an AI agent and changes nothing unless the user passes `--write`. Written registrations can be checked for drift with `verify` and removed with `uninstall`. The hook observes by default. Blocking needs `--enforce`, and with no verdict available it fails open unless the user chose `--on-failure closed`.

## Sub-features

- `hook-preview` prints the settings block and writes nothing.
- `hook-write` merges the entry into the temp HOME's settings and records a baseline.
- `hook-verify` reports `[OK]` on a match and `[DRIFT]` with exit code `2` after tampering.
- `hook-uninstall` previews, then removes only the Lodeline entry.
- `hook-enforce-open` allows when no verdict is available.
- `hook-enforce-closed` denies when no verdict is available and fail-closed was chosen.

## How to get to it (user POV)

- Run `lodeline-hook install --agent <agent>` to preview, for `claude-code`, `codex`, `cursor`, `antigravity`, or `grok`.
- Add `--write` to apply it.
- Run `lodeline-hook verify --agent <agent>` and `lodeline-hook uninstall --agent <agent> [--write]`.
- An AI agent runs `lodeline-hook claude-code [--enforce] [--on-failure open|closed]` as a PreToolUse hook, with a JSON payload on stdin.

## Driving it with drive.sh

Preconditions:

- `drive.sh doctor "$RUN"` exits 0.
- The temp HOME is empty.

- **Preview.** Run `drive.sh run "$RUN" hook-preview -- lodeline-hook install --agent claude-code`. Exit code `0`. Stdout starts with `// Merge this into`, names a path under `scratch/home/.claude/settings.json`, and holds a `PreToolUse` block with `claude-code --capture redacted`.
- **Preview side effects.** Run `drive.sh run "$RUN" hook-preview-files -- find ../home ../state ../config -type f`. Stdout is empty.
- **Other agents.** Repeat the preview with `--agent codex`, `--agent cursor`, `--agent antigravity`, and `--agent grok`, each with its own label. Exit code `0` for each, and `find` stays empty.
- **Write.** Run `drive.sh run "$RUN" hook-write -- lodeline-hook install --agent claude-code --write`. Stderr holds `installed for claude-code in` and a scratch path.
- **Stored result.** Run `drive.sh run "$RUN" hook-write-files -- find ../home ../state -type f`. Stdout lists `../home/.claude/settings.json`, `../state/lodeline/hook-index.json`, and `../state/lodeline/hook-registration-claude-code.json`.
- **Verify match.** Run `drive.sh run "$RUN" hook-verify-ok -- lodeline-hook verify --agent claude-code`. Exit code `0`, stdout `[OK]    hook registration matches baseline`.
- **Detect drift.** Tamper and verify. Run `drive.sh run "$RUN" hook-tamper -- sh -c 'printf "{}" > "$HOME/.claude/settings.json"'` and `drive.sh run "$RUN" hook-verify-drift -- lodeline-hook verify --agent claude-code`. The second exits `2` with `[DRIFT] ... (entry_missing)`.
- **Uninstall.** Reinstall, preview the removal, then apply it. Run `drive.sh run "$RUN" hook-rewrite -- lodeline-hook install --agent claude-code --write`, `drive.sh run "$RUN" hook-uninstall-preview -- lodeline-hook uninstall --agent claude-code`, and `drive.sh run "$RUN" hook-uninstall -- lodeline-hook uninstall --agent claude-code --write`. The preview's stderr holds `would remove 1 entry/entries`, the apply's holds `removed 1 entry/entries`, and `.claude/settings.json` then has an empty `PreToolUse` array.
- **Default does not block.** Send a destructive payload through the hook with no daemon. Run `printf '%s' '{"tool_name":"Bash","tool_input":{"command":"rm -rf /tmp/x"},"hook_event_name":"PreToolUse"}' | drive.sh run "$RUN" hook-enforce-open -- lodeline-hook claude-code --enforce`. Exit code `0` and empty stdout.
- **Opt-in fail-closed.** Run `printf '%s' '{"tool_name":"Bash","tool_input":{"command":"rm -rf /tmp/x"},"hook_event_name":"PreToolUse"}' | drive.sh run "$RUN" hook-enforce-closed -- lodeline-hook claude-code --enforce --on-failure closed`. Exit code `0`, and stdout holds `"permissionDecision":"deny"` and `rule fail_closed`.

## Gotchas

- A deny for Claude Code is JSON on stdout with exit code `0`. Assert on stdout, not on the exit code.
- `hook-enforce-closed` shows the failure path only. A real rule deny needs a live daemon, so it stays with `cargo test -p lodeline-hook`.
- Registered commands hold the absolute path of the binary, which is a personal path. Replace it before you quote it.
- Without `LODELINE_HOOK_SOCKET` and `LODELINE_HOOK_DECIDE_SOCKET`, the hook prefers `/var/run/lodeline/*.sock` when those exist. `drive.sh` sets both.
- `--force` on `antigravity` calls the external `agy` CLI. Keep it out of every drive with `--write`.
