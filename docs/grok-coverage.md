# Grok Build and Cursor coverage

This page says what Lodeline reads from Grok Build and Cursor hook configuration, what it does not read, and why. Lodeline measures posture. It does not block anything and it does not change a Grok or Cursor setting.

Checked on 2026-11-15 against the official Grok Build documentation at https://docs.x.ai/build (hooks, settings, settings reference, enterprise) and Cursor's hooks page at https://cursor.com/docs/hooks. The Grok build installed for this check is 0.2.32, and `cursor-agent` is 2026.11.11. Neither was run beyond `--version`. The 1.0.x behavior in this page comes from the xAI documentation, from the measurement of Grok 1.0.70 recorded in `docs/research/cursor-grok-hook-scopes-2026-11-03.md`, and from a measurement of Grok 1.0.77 made on 2026-11-15 with `grok inspect --json` and a scratch home. No Cursor Desktop build was available.

## Grok Build: files read

| File | Row it feeds | Read |
|---|---|---|
| `~/.grok/hooks/*.json` | User | Yes. Every file, merged per event in file-name order. |
| `[hooks]` in `~/.grok/config.toml` | User | Yes. |
| `[mcp_servers.<name>]` in `~/.grok/config.toml` | User | Yes. A server with `enabled = false` is skipped. |
| `<repo>/.grok/hooks/*.json` | Project | Yes. Skipped when the project root is a home folder, because the user row reads that folder. |
| `[mcp_servers.<name>]` in `<repo>/.grok/config.toml` | Project | Yes. Skipped when the project root is a home folder, for the same reason. |
| `[hooks]` in `<repo>/.grok/config.toml` | Project | No. Grok 1.0.70 did not load it, so reading it would report a hook that does not run. |
| `[[hooks.<Event>]]` and `[mcp_servers.<name>]` in `~/.grok/managed_config.toml`, `/etc/grok/managed_config.toml` | User | Yes. A server with `enabled = false` is skipped. |
| `[[hooks.<Event>]]` and `[mcp_servers.<name>]` in `~/.grok/requirements.toml`, `/etc/grok/requirements.toml` | User | Yes. A server with `enabled = false` is skipped. |
| `~/.grok/trusted_folders.toml` | None | No. |
| `[compat.claude]` and `[compat.cursor]` switches | None | No. |
| `GROK_HOME` | None | Not followed. `~/.grok` is always read. |

A hook file uses Claude Code's matcher groups, and the `config.toml` table uses Codex's shape, so each goes through that tool's reader and the existing hook reason kinds. A file that does not parse is skipped with a warning and does not hide the other files or the MCP servers. A `config.toml`, `managed_config.toml` or `requirements.toml` that does not parse is reported as a read error for that row.

An entry of type `http` (the hooks page lists `command` and `http`) is scored only in `hooks/*.json`, where it goes through the same reader as a Claude Code `http` hook. An `http` hook in `~/.grok/config.toml`, `managed_config.toml` or `requirements.toml` (or the same names under `/etc/grok`) is not scored today, because those tables go through the Codex reader, which reports no `http` hook. Grok loads an `http` hook from these files.

## Grok Build: what is not read

**Managed and requirements files.** These are read, in the user row. The settings page lists `managed_config.toml` and `requirements.toml` under `~/.grok/` and `/etc/grok/`, and the enterprise page orders the layers from `/etc/grok/managed_config.toml` (lowest) to `/etc/grok/requirements.toml` (highest). The table shape was measured on Grok 1.0.77 on 2026-11-15 with `grok inspect --json` and a scratch home: `[[hooks.<Event>]]` tables (inline and nested forms) and `[mcp_servers]` load from `managed_config.toml`, `requirements.toml` and `config.toml`. Managed hooks always load. The other two load only once the folder is trusted, and Lodeline scores them either way. A group without an inner `hooks` array does not load, so it adds nothing. A file that does not parse is reported as a read error for that row. The `/etc/grok` files were not measured, because the measurement could not write there. They are read by the same code. Lodeline does not check the signature of a synced `requirements.toml`, so it cannot tell an enforced hook from one that loads as the user's own. Grok's own bundled `10-hooks.md` in the 1.0.77 package says the same.

**Folder trust.** Grok runs project hooks only for a trusted folder. The hooks page says the decision is stored in `~/.grok/trusted_folders.toml`, and that it covers project MCP and LSP servers too. The file format is not documented in the pages that were read, and Lodeline does not read it. A committed `.grok/hooks/*.json` is therefore scored whether or not the folder is trusted, so a project hook Grok would refuse still counts toward the score. Reporting trust would need an event field that does not exist. User hook files (`~/.grok/hooks/*.json`) load only in a trusted folder as well, per the measurement of 1.0.70 in the research note and Grok's bundled `10-hooks.md` in 1.0.77. Home, filesystem roots and headless runs count as trusted. Lodeline scores the user row whether or not the folder is trusted.

**Cross-tool switches.** Grok also reads Claude Code hook files (`.claude/settings.json`) and Cursor hook files (`.cursor/hooks.json`), and loads MCP servers from `~/.claude.json`, `.cursor/mcp.json` and `.mcp.json`. The settings reference lists `[compat.claude]` and `[compat.cursor]` with the keys `skills`, `rules`, `agents`, `mcps` and `hooks`, all on by default. Lodeline scores the Claude Code and Cursor files with their own readers whether or not Grok would run them. A switch set to `false` does not lower a score.

**`GROK_HOME`.** The settings page says `$GROK_HOME` moves the home folder. Lodeline reads `~/.grok` only.

## Grok Build: how the daemon finds projects

`lodeline scan` finds a Grok project when the current folder has `.grok/hooks/` or `.grok/config.toml`. The daemon finds Grok projects through the `grok_workspaces` policy field, which works like `cursor_workspaces` and `codex_workspaces`. It lists workspace roots:

```yaml
grok_workspaces:
  - "~/src"
```

The daemon looks one level below each root. A folder that has a `.grok/hooks/` folder or a `.grok/config.toml` file is a Grok project: the daemon scores it in the project row and watches its hook files and its `config.toml`, so a change to one of them scores the project again. A folder that has neither, such as one with only other files under `.grok/`, is not a project and gets no row.

The daemon lists the projects when it starts and again on each policy reload, which `lodeline reload` or an applied signed policy starts. A project created after that is found at the next reload or restart. An agent older than the field ignores it, so upgrade agents before you sign a policy that sets it.

## Grok Build: hooks fail open

The hooks page (https://docs.x.ai/build/features/hooks) says that exit code 0 allows and exit code 2 denies, that every other outcome (a timeout, a crash, malformed output) fails open, so the failure is recorded in the session and the tool call proceeds, and that only an explicit `deny` blocks. Only `PreToolUse` can block. The default `timeout` is 5 seconds. The pages that were read show no fail-closed switch for Grok. The Lodeline Grok hook adapter blocks with the JSON `{"decision":"deny"}`, as the page describes. A hook that crashes or times out lets the call through, so a blocking hook is a control that can fail silently.

## Cursor

Cursor `hooks.json` files are covered by their own readers: user, enterprise and project files are scored, and team hooks are not, because Cursor holds them in memory and not in a file the agent owns. The scopes and precedence are in `docs/research/cursor-grok-hook-scopes-2026-11-03.md`.

**What was not run.** The deny path was not run on an installed Cursor Desktop build, so it is not known whether Cursor 3.11 enforces only `deny`. Cursor's hooks page (https://cursor.com/docs/hooks) documents `permission`, `agent_message` and `updated_input`. It says that `ask` is accepted by the schema but not enforced for `preToolUse` today, that `ask` is not supported for `subagentStart` and is treated as `deny`, and that `preToolUse` can deny the call but Cursor ignores `updated_input`. It documents `failClosed`: hook failures (crash, timeout, non-zero exit code, no output) block the action instead of allowing it through, and a permission hook blocks on invalid JSON or an invalid response even when `failClosed` is false. Exit code 2 blocks. Other exit codes fail open by default.

**What Lodeline relies on.** Only `deny` (or exit code 2). How `allow` and `ask` behave depends on the Cursor version and on the agent's permission mode, and is not verified here. The check needs an installed Desktop build and a run in each permission mode. The `cursor-agent` command line tool is a different code path from Desktop, and running it needs an account and a network session.

## Not verified

- Official xAI release notes. The page returned a block page to an automated fetch, so release facts here come only from the documentation pages.
- The format of `trusted_folders.toml`.
- Any Cursor Desktop behavior.
