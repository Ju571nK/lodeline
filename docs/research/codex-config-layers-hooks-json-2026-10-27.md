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

Not covered: hook trust state (configured hooks are reported whether or not
they are trusted), profile layers, `CODEX_HOME`, `${PWD}/config.toml`, parent
`.codex/` directories, managed preferences, and cloud bundles. Reasons carry
no field naming the layer that produced them.
