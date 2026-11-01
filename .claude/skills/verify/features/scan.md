# Scan posture

`lodeline scan` reads installed AI agents' configs once and prints a posture score, a per-tool table, and advice. It needs no daemon, policy, or state.db, and it always exits 0 because it reports and does not gate.

## Sub-features

- `scan-empty` reports `LOW (0.0)` and lists every tool as not configured.
- `scan-user-global` scores a risky config under `$HOME`.
- `scan-project` adds rows for the current directory when it carries project markers.
- `scan-advice` prints `How to reduce` hints and changes no config.

## How to get to it (user POV)

- Run `lodeline scan` in a terminal, from any directory.

## Driving it with drive.sh

Preconditions:

- `drive.sh doctor "$RUN"` exits 0.
- The temp HOME is empty.

- **Empty home.** Scan before seeding. Run `drive.sh run "$RUN" scan-empty -- lodeline scan`. Exit code `0`, stdout starts with `Lodeline scan — LOW (0.0)`, and it contains `0 tools assessed · 0 findings` and `7 tools not configured`.
- **Seed risky config.** Add a local-command MCP server. Run `drive.sh run "$RUN" scan-seed -- sh -c 'mkdir -p "$HOME/.cursor" && printf "%s" "{\"mcpServers\":{\"x\":{\"command\":\"npx\",\"args\":[\"-y\",\"evil\"]}}}" > "$HOME/.cursor/mcp.json"'`. Exit code `0`.
- **Scored row.** Scan again. Run `drive.sh run "$RUN" scan-risky -- lodeline scan`. Exit code `0`, the headline reads `MEDIUM (2.5)`, a `cursor` row shows `application:cursor` with `mcp_server_local_command`, and `How to reduce` lists that kind.
- **Project markers.** Add `AGENTS.md` to the working directory. Run `drive.sh run "$RUN" scan-project-seed -- sh -c 'printf "# fixture\n" > AGENTS.md'` and `drive.sh run "$RUN" scan-project -- lodeline scan`. Rows for `claude-code` and `codex` show a `project:` scope that ends in `scratch/project`.
- **Measures only.** Confirm that the scan changed nothing. Run `drive.sh run "$RUN" scan-side-effects -- find ../home ../state ../config -type f`. The only file listed is `../home/.cursor/mcp.json`.

## Gotchas

- `/var/folders` prints as `/private/var/folders` in `project:` scopes on macOS. Match on the suffix.
- Exit code `0` proves nothing, because scan always exits 0. Assert on the report text.
- Files under `/Library/Application Support/ClaudeCode`, `/etc/claude-code`, or `/etc/codex` add rows or controls on a host that has them.
- A scan from the repo root picks up the repo's own `AGENTS.md`. `drive.sh` starts in `scratch/project`, so keep it there.
