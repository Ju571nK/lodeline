# Grok Build and Cursor coverage

This page says what Lodeline reads from Grok Build and Cursor hook configuration, what it does not read, and why. Lodeline measures posture. It does not block anything and it does not change a Grok or Cursor setting.

Checked on 2026-11-15 against the official Grok Build documentation at https://docs.x.ai/build (hooks, settings, settings reference, enterprise) and Cursor's hooks page at https://cursor.com/docs/hooks. The Grok build installed for this check is 0.2.32, and `cursor-agent` is 2026.11.11. Neither was run beyond `--version`. The 1.0.x behavior in this page comes from the xAI documentation and from the measurement of Grok 1.0.70 recorded in `docs/research/cursor-grok-hook-scopes-2026-11-03.md`. No Cursor Desktop build was available.

## Grok Build: files read

| File | Row it feeds | Read |
|---|---|---|
| `~/.grok/hooks/*.json` | User | Yes. Every file, merged per event in file-name order. |
| `[hooks]` in `~/.grok/config.toml` | User | Yes. |
| `[mcp_servers.<name>]` in `~/.grok/config.toml` | User | Yes. A server with `enabled = false` is skipped. |
| `<repo>/.grok/hooks/*.json` | Project | Yes. |
| `[mcp_servers.<name>]` in `<repo>/.grok/config.toml` | Project | Yes. |
| `[hooks]` in `<repo>/.grok/config.toml` | Project | No. Grok 1.0.70 did not load it, so reading it would report a hook that does not run. |
| `~/.grok/managed_config.toml`, `/etc/grok/managed_config.toml` | None | No. |
| `~/.grok/requirements.toml`, `/etc/grok/requirements.toml` | None | No. |
| `~/.grok/trusted_folders.toml` | None | No. |
| `[compat.claude]` and `[compat.cursor]` switches | None | No. |
| `GROK_HOME` | None | Not followed. `~/.grok` is always read. |

A hook file uses Claude Code's matcher groups, and the `config.toml` table uses Codex's shape, so each goes through that tool's reader and the existing hook reason kinds. A file that does not parse is skipped with a warning and does not hide the other files or the MCP servers. A `config.toml` that does not parse is reported as a read error for that row.

An entry of type `http` (the hooks page lists `command` and `http`) goes through the same reader as a Claude Code `http` hook. Lodeline does not treat it as a separate Grok case.

## Grok Build: what is not read

**Managed and requirements files.** The settings page lists `managed_config.toml` and `requirements.toml` under `~/.grok/` and `/etc/grok/`. The enterprise page orders the layers from `/etc/grok/managed_config.toml` (lowest) to `/etc/grok/requirements.toml` (highest), and says settings in `requirements.toml` cannot be overridden by lower layers. A hook or MCP server an organization pins in one of these files is not in a Lodeline row. The official pages that were read do not show where hooks sit inside these files. Only release notes mirrored on a third-party site describe `[[hooks.<Event>]]` tables there, and that was not confirmed against a primary source. The installed 0.2.32 predates the files, so the table shape has not been measured, and Lodeline does not guess it.

**Folder trust.** Grok runs project hooks only for a trusted folder. The hooks page says the decision is stored in `~/.grok/trusted_folders.toml`, and that it covers project MCP and LSP servers too. The file format is not documented in the pages that were read, and Lodeline does not read it. A committed `.grok/hooks/*.json` is therefore scored whether or not the folder is trusted, so a project hook Grok would refuse still counts toward the score. Reporting trust would need an event field that does not exist. Whether a declined trust prompt also leaves the user hook file `~/.grok/hooks/lodeline-hook.json` unloaded for that session is not verified, because only a run on a 1.0.x build settles it.

**Cross-tool switches.** Grok also reads Claude Code hook files (`.claude/settings.json`) and Cursor hook files (`.cursor/hooks.json`), and loads MCP servers from `~/.claude.json`, `.cursor/mcp.json` and `.mcp.json`. The settings reference lists `[compat.claude]` and `[compat.cursor]` with the keys `skills`, `rules`, `agents`, `mcps` and `hooks`, all on by default. Lodeline scores the Claude Code and Cursor files with their own readers whether or not Grok would run them. A switch set to `false` does not lower a score.

**`GROK_HOME`.** The settings page says `$GROK_HOME` moves the home folder. Lodeline reads `~/.grok` only.

## Grok Build: the daemon does not find projects

`lodeline scan` finds a Grok project when the current folder has `.grok/hooks/` or `.grok/config.toml`. The daemon has no Grok project list, because there is no `grok_workspaces` policy key, so it never watches or re-assesses a Grok project. The Cursor and Codex equivalents are `cursor_workspaces` and `codex_workspaces`. Until a key exists, run `lodeline scan` in a Grok project to see its row.

## Grok Build: hooks fail open

The hooks page states: "Exit code 0 allows, exit code 2 denies. Everything else, timeouts, crashes, malformed output, is fail-open: the failure is recorded in the session but the tool call proceeds. Only an explicit `deny` blocks." Only `PreToolUse` can block. The default `timeout` is 5 seconds. The pages that were read show no fail-closed switch for Grok. The Lodeline Grok hook adapter blocks with the JSON `{"decision":"deny"}`, as the page describes. A hook that crashes or times out lets the call through, so a blocking hook is a control that can fail silently.

## Cursor

Cursor `hooks.json` files are covered by their own readers: user, enterprise and project files are scored, and team hooks are not, because Cursor holds them in memory and not in a file the agent owns. The scopes and precedence are in `docs/research/cursor-grok-hook-scopes-2026-11-03.md`.

**What was not run.** The deny path was not run on an installed Cursor Desktop build, so it is not known whether Cursor 3.11 enforces only `deny`. Cursor's hooks page documents `permission`, `agent_message` and `updated_input`, and says it does not state that `allow` or `ask` are ignored. It documents `failClosed`: hook failures (crash, timeout, non-zero exit code, no output) block the action instead of allowing it through, and a permission hook blocks on invalid JSON or an invalid response even when `failClosed` is false. Exit code 2 blocks. Other exit codes fail open by default. Forum reports say `ask` is ignored in some modes, and the reports do not agree on versions. They are not official, and they were not reconciled.

**What Lodeline relies on.** Only `deny` (or exit code 2). How `allow` and `ask` behave depends on the Cursor version and on the agent's permission mode, and is not verified here. The check needs an installed Desktop build and a run in each permission mode. The `cursor-agent` command line tool is a different code path from Desktop, and running it needs an account and a network session.

## Not verified

- Official xAI release notes. The page returned a block page to an automated fetch, so release facts here come only from the documentation pages.
- Hook tables inside `managed_config.toml` and `requirements.toml`, and the format of `trusted_folders.toml`.
- Grok 1.0.x behavior after a declined trust prompt.
- Any Cursor Desktop behavior.
