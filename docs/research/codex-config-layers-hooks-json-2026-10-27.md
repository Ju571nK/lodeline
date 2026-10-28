# Codex Config Layers and `hooks.json`

Checked 2026-10-27 against `openai/codex` main and the locally installed
codex-cli 0.164.0 (latest release `rust-v0.164.0`). Only static reads were
run; no hook was executed.

## What the source says

`codex-rs/config/src/loader/mod.rs` documents the config layers in ascending
precedence: packaged defaults, macOS managed preferences, system
(`/etc/codex/config.toml`, `%ProgramData%\OpenAI\Codex\config.toml`), cloud
bundle fragments, user (`${CODEX_HOME}/config.toml`), a selected profile
(`${CODEX_HOME}/<name>.config.toml`), `${PWD}/config.toml`, `.codex/config.toml`
in parent directories, the repository's `.codex/config.toml`, and runtime
flags. The cwd, tree, and repo layers are disabled for untrusted directories.

`codex-rs/config/src/merge.rs` merges layers with the higher layer winning:
tables merge key by key, other values are replaced.

`codex-rs/hooks/src/engine/discovery.rs` does not merge hooks. It walks every
layer from low to high and loads hooks from both the layer's `config.toml`
`[hooks]` table and `hooks.json` in the layer's folder, warning when a layer
uses both. An unreadable or invalid `hooks.json` is skipped with a warning.
Hooks from system, MDM, and cloud-managed layers are managed and run without
a trust check. Other hooks run only when `[hooks.state."<key>"]` in config
records a `trusted_hash` matching the handler, unless trust is bypassed.

## What the local install shows

`~/.codex/hooks.json` exists here, written by a terminal app, with one inline
command hook for each of nine events (including `Interrupt`). Each has a
`[hooks.state]` entry with `enabled = true` and a `trusted_hash`, so Codex
runs them. Sigil did not read this file before this change. `/etc/codex/`
does not exist on this machine.

## What Sigil reads now

- `hooks.json` in `~/.codex/`, in a repository's `.codex/`, and in the system
  folder, through the same emitter as the `[hooks]` table. A repository with
  only `.codex/hooks.json` is discovered.
- The system `config.toml` under the user one. `sandbox_mode`,
  `approval_policy`, and `mcp_servers` are read from the merged value; hooks
  are read per layer. A parse error in the system file is reported the same
  way as one in the user file, since Codex will not start either way.

`sigil scan` on this machine gives the same Codex result before and after:
the nine hooks are benign inline commands. A copy of the file with one added
`rm -rf` handler is reported only after the change.

Not covered: profile layers, `CODEX_HOME`, `${PWD}/config.toml`, parent
`.codex/` directories, managed preferences, and cloud bundles. Reasons carry
no field naming the layer that produced them.

## Hook trust state (2026-10-28)

Checked against `rust-v0.164.0` (`hooks/src/engine/discovery.rs`,
`hooks/src/config_rules.rs`, `hooks/src/lib.rs`, `config/src/fingerprint.rs`);
the trust functions are unchanged on main.

- The state key is `<source path>:<event>:<group index>:<handler index>`. The
  source path is the `hooks.json` or `config.toml` path as Codex resolved it,
  the event is snake case (`pre_tool_use`, `interrupt`), and both indexes
  count every entry, including `prompt` handlers Codex skips.
- State is read only from the user layer and session flags, so a repository's
  own `.codex/config.toml` cannot trust its hooks. Codex trims stored keys.
- A non-managed hook runs when `enabled` is not `false` and `trusted_hash`
  equals the hook's current hash. No stored hash is `Untrusted`, a different
  one is `Modified`; neither runs. Managed hooks ignore both fields.
- The current hash is `sha256:` over sorted JSON of a normalized handler
  (for example with the timeout filled in). `--dangerously-bypass-hook-trust`
  runs enabled hooks without trust for one invocation.

Sigil now skips a non-managed hook that has no `trusted_hash` or has
`enabled = false`. It does not recompute the hash, so a modified hook is
still reported: the normalization changes between releases, and a false
mismatch would hide a hook that runs. The key is tried with the path as Sigil
sees it and with symlinks resolved. A repository parser watches the user
`config.toml`, where trusting a repository hook is recorded.

On this machine the nine `~/.codex/hooks.json` hooks match their stored keys.
In a fake-home copy with each command replaced by `rm -rf` and the state
keys moved to the copy, all nine are reported (as modified hooks, kept on
purpose), and an added handler with no state entry is not. Not covered: a
hook run under the bypass flag, plugin hooks (`<plugin>@<marketplace>:` keys),
and profile or session-flag state.
