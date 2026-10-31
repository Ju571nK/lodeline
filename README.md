# Lodeline

**A config scanner for AI coding agents.** Claude Code, Codex, and Cursor can run
whatever their config allows. Lodeline scores what that is, in one command,
before something does.

> Formerly Sigil. Upgrading an existing install? See the
> [migration guide](docs/migrate-from-sigil.md).

![License](https://img.shields.io/badge/license-Apache%202.0-blue)
![macOS](https://img.shields.io/badge/macOS-supported-success)
![Linux](https://img.shields.io/badge/Linux-supported-success)
![Windows](https://img.shields.io/badge/Windows-supported-success)
![Rust](https://img.shields.io/badge/Rust-1.88-orange)
![Status](https://img.shields.io/badge/status-alpha-yellow)

A coding agent doesn't ask before it runs a hook, launches an MCP server, or
skips its sandbox. Those decisions live in config files you never open. Lodeline
reads them and tells you how exposed you are.

```sh
curl --proto '=https' --tlsv1.2 -fsSL https://raw.githubusercontent.com/Ju571nK/lodeline/main/install.sh | sh
lodeline scan
```

```
Lodeline scan — CRITICAL (7.5)
2 tools assessed · 5 findings

TOOL         SCOPE               SCORE  BUCKET    TOP FINDINGS
claude-code  user-global           7.5  critical  no_sandbox, broad_matcher (+1 more)
cursor       application:cursor    2.5  medium    mcp_server_local_command, no_sandbox

5 tools not configured: antigravity, claude-desktop, codex, continue-dev, gemini

How to reduce
  no_sandbox                     The agent runs with no sandbox boundary — enable the tool's sandbox or limit what it can run.
  broad_matcher                  A broad hook matcher catches most or all tool calls — scope it to specific tools.
  destructive_in_inline_command  A hook runs a destructive shell command inline — review and remove it.
  mcp_server_local_command       An MCP server auto-launches a local command — review or remove it, or run it sandboxed.

Run `lodeline scan --json` for full detail.
```

![Lodeline scoring a config: a clean repo sits at 0 / low until a wildcard PreToolUse hook running rm -rf $HOME lands, and Lodeline re-scores it 7.5 / critical](https://raw.githubusercontent.com/Ju571nK/lodeline/main/docs/lodeline-mcp-codex01-en.gif)

> Your EDR sees the command that ran. Lodeline sees the permission that let it run.

Runs on your machine · no account · nothing leaves the box · macOS / Linux / Windows · Rust · Apache-2.0

[**Try the 60-second tour →**](https://sigilworks.net/)

---

## What it catches

The misconfigurations that turn a helpful agent into a foothold:

- **No sandbox** — the agent runs with full reach into your host. `no_sandbox`
- **Wildcard hooks** — a `.*` `PreToolUse` matcher that lets any tool call through, or a hook that runs a destructive inline command. `broad_matcher` · `destructive_in_inline_command`
- **Local-command MCP servers** — an `mcp.json` server set to auto-launch a shell or binary. `mcp_server_local_command`
- **Empty deny lists** — permissions that look configured but block nothing. `permissions_deny_empty`
- **Prompt-injection in instruction files** — directives planted to steer the agent off-task.

Across the agents you actually run: **Claude Code, Codex, Cursor, Gemini CLI, Antigravity, Continue.dev, Claude Desktop.**

It re-scores the moment a config changes — a clean repo at `0 / low` jumps to
`critical` the instant a risky hook lands.

---

## Why your linter and EDR miss this

- A **linter / SAST** reads *your* source. It says nothing about what your agent is *allowed* to do.
- An **EDR** flags the process *after* it launches. By then the permission that allowed it already existed.
- **Lodeline** reads that permission surface (sandbox, hooks, MCP, instruction files) and scores it *before* anything runs.

It measures. It doesn't block by default. Blocking exists, but it is opt-in, so your agent keeps working.

---

## Running agents on several machines?

If you've got Claude Code and Codex grinding away unattended on a rack of Mac
minis, each box has its own posture and you can't eyeball them all. The same scan
rolls up across machines, so one view tells you which host is riskiest and why —
optionally shipped to your SIEM and a fleet dashboard.

That's the **fleet** side: a client agent on every machine, hash-anchored events
over mTLS to a central server, signed policy pushed back down, read-only MCP for
operators. It's there when you need it and invisible when you don't.

→ [Fleet setup](docs/install-server.md) · [lodeline-manager dashboard](https://github.com/Ju571nK/lodeline-manager) · [architecture](#how-it-works)

---

## Install

```sh
# personal (default): lodeline + lodeline-mcp + lodeline-hook, no server
curl --proto '=https' --tlsv1.2 -fsSL https://raw.githubusercontent.com/Ju571nK/lodeline/main/install.sh | sh

# fleet: adds lodeline-sender + lodeline-server + lodeline-sign
curl --proto '=https' --tlsv1.2 -fsSL https://raw.githubusercontent.com/Ju571nK/lodeline/main/install.sh | LODELINE_PROFILE=fleet sh
```

Linux `.deb`/`.rpm` and Windows `.zip` are on the [releases page](https://github.com/Ju571nK/lodeline/releases/latest).
Every release ships a `SHA256SUMS` (the installer verifies it) and a build-provenance attestation.
Full guide: [docs/install-personal.md](docs/install-personal.md).

---

## Ask your agent about its own risk

`lodeline-mcp` exposes the score over plain MCP, so an AI client can read its own
posture and explain it:

- `lodeline-check` — this host only (the default a coding agent registers): `my_risk`, `my_guard_detail`, `my_findings`
- `lodeline-fleet` — read-only fleet view for operators (GET only)

No vendor plugin, no write path by construction.

---

## How it works

A small Rust agent watches the config and posture files on each machine, hashes
them, and emits JSONL posture events. Locally that's all you need. For a fleet,
`lodeline-sender` ships those events over mTLS to `lodeline-server`, which feeds your
SIEM and the optional `lodeline-manager` dashboard and pushes signed policy back.

The workspace has twelve crates with clear roles (`lodeline-agent`, `lodeline-sender`,
`lodeline-server`, `lodeline-mcp`, `lodeline-hook`, `lodeline-signer`, `lodeline-core`,
and others). `lodeline-core` is `forbid(unsafe_code)`. Built on rustls, ed25519,
blake3, notify, and axum.

---

## Status

Lodeline is **alpha**, built and maintained by one person. It **measures posture and
does not block** by default. [`SECURITY.md`](SECURITY.md) is honest that there's
no SLA. The Linux runtime is a working foundation with rough edges (watch limits,
coverage signaling) still on the [roadmap](ROADMAP.md). Use it to *see* your
exposure today; don't treat it as a managed enterprise control yet.

Apache-2.0 · issues and discussions welcome · [landing](https://sigilworks.net/)
