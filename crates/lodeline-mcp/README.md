# lodeline-mcp

Read-only MCP server for Lodeline security posture. One binary, two modes
auto-detected from the environment — both read-only by construction (no
write/remediation tools). The modes have **distinct server names** so an MCP
client (and you) can tell them apart:

- **`lodeline-check`** — Local mode (default, no `LODELINE_SERVER_BASE_URL`). Reads the
  local `lodeline-agent`'s control socket and exposes **only this machine's** AI
  Guard posture. No server, no fleet. This is what an AI coding agent (Claude
  Code/Desktop, Codex, …) registers on a developer's box. See
  [lodeline-check](#lodeline-check-this-hosts-own-posture-no-server) below.
- **`lodeline-fleet`** — Fleet mode (`LODELINE_SERVER_BASE_URL` set). Exposes a
  `lodeline-server`'s GET read API as MCP tools so an **operator** can read and
  reason over a whole fleet's posture. Run it beside `lodeline-server` /
  `lodeline-manager`, not as the default an agent gets.

## Tools
`lodeline-check` (this host): `my_risk`, `my_guard_detail`, `my_findings`, `assess` (pre-flight a proposed command / MCP server against the loaded policy).
`lodeline-fleet` (operators): `list_hosts`, `get_host`, `fleet_risk`,
`fleet_compliance`, `query_events`, `get_event`, `get_policy`, `server_meta`,
`healthz`.

## Register with an MCP client

The fastest, paste-proof way — `--print-config` stamps the **absolute path** of
the running binary, so it works even when the client doesn't see your shell PATH.
It emits `lodeline-check` (single host, no server) as the default, with `lodeline-fleet`
shown as a commented operator add-on:

```sh
lodeline-mcp --print-config codex     # Codex (~/.codex/config.toml)
lodeline-mcp --print-config claude    # Claude Code / Claude Desktop (mcpServers JSON)
lodeline-mcp --print-config hermes    # Hermes Agent (config.yaml mcp_servers:)
lodeline-mcp --print-config openclaw  # OpenClaw (~/.openclaw/openclaw.json mcpServers)
lodeline-mcp --print-config           # all of the above
```

The local surface also exposes an `assess` tool that pre-flights a proposed
command or MCP server definition against this host's loaded policy. See
[examples/integrations/](../../examples/integrations/) for ready-to-use OpenClaw
and Hermes setups.

Claude Desktop / Code (stdio), single host — no env needed:

```json
{
  "mcpServers": {
    "lodeline-check": { "command": "/absolute/path/to/lodeline-mcp" }
  }
}
```

> **`command` must be an absolute path** (or a name on the *client's* PATH). MCP
> clients are usually GUI/login-launched and don't inherit your interactive shell
> PATH, and a build-from-source binary lives at `target/release/lodeline-mcp` —
> never on PATH.
>
> **Troubleshooting — `MCP startup failed: No such file or directory (os error 2)`**:
> the client can't find the binary. Use the absolute path (run
> `lodeline-mcp --print-config <client>` to get a correct block).

## lodeline-check (this host's own posture, no server)

With `LODELINE_SERVER_BASE_URL` unset, `lodeline-mcp` runs as **`lodeline-check`**: it reads
the running local `lodeline-agent`'s control socket and exposes this machine's AI
Guard posture as `my_risk` (per-tool risk band/score), `my_guard_detail` (rubric,
parsers, rule packs), and `my_findings` (per-repo discovery + watched hook
scripts). It can never see another host.

The socket path defaults to the same location `lodeline-agent` uses
(`$XDG_RUNTIME_DIR/lodeline/control.sock`, `/var/run/lodeline/control.sock` as root,
or `/tmp/lodeline-<uid>/control.sock`); override with `LODELINE_AGENT_CONTROL_SOCKET`.
v1 expects the agent and `lodeline-mcp` to run as the **same user** (the control
socket is `0660`); root-daemon + group access is tracked in #10.

## lodeline-fleet (operators — fleet-wide, via lodeline-server)

For operators who want the whole fleet, point `lodeline-mcp` at a `lodeline-server`'s
read API. This is a separate registration (`lodeline-fleet`), run alongside
`lodeline-server` / `lodeline-manager` — not the default a coding agent gets.

| Var | Meaning |
|-----|---------|
| `LODELINE_SERVER_BASE_URL` | read API base, e.g. `http://127.0.0.1:9090` (proxy) or `https://host:8443` |
| `LODELINE_SERVER_READ_TOKEN` | bearer token |
| `LODELINE_CLIENT_CERT` / `LODELINE_CLIENT_KEY` / `LODELINE_CA_CERT` | optional, for direct mTLS to `:8443` (omit when using a bearer-only reverse proxy) |

```json
{
  "mcpServers": {
    "lodeline-fleet": {
      "command": "/absolute/path/to/lodeline-mcp",
      "env": {
        "LODELINE_SERVER_BASE_URL": "http://127.0.0.1:9090",
        "LODELINE_SERVER_READ_TOKEN": "..."
      }
    }
  }
}
```

Configuration is validated at startup, but connectivity is not probed — an
unreachable `LODELINE_SERVER_BASE_URL` or bad token surfaces on the first tool
call (with a clear error), not at launch. Logs go to stderr; stdout is the
MCP JSON-RPC channel.
