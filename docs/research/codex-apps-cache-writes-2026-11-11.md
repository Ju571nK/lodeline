# Codex apps cache writes

Checked 2026-11-11 against `openai/codex` tag `rust-v0.167.0` (`codex-cli 0.167.0`).
The files read are identical on `main` (commit `c1934fc9`) the same day. Only
static reads were run.

## What Codex does

- `codex-rs/connectors/src/connector_runtime/persistence.rs` names the two
  folders (`CODEX_APPS_TOOLS_CACHE_DIR = "cache/codex_apps_tools"`,
  `CODEX_APPS_SERVER_INFO_CACHE_DIR = "cache/codex_apps_server_info"`).
- `persist_codex_apps_cache` serializes the tool snapshot and the server info
  and writes both files, one call each of `write_codex_apps_cache_file`. That
  function makes a `NamedTempFile::new_in(parent)`, writes the bytes, and
  calls `temporary.persist(cache_path)`: a temporary file in the same folder,
  then a rename over the target. It does not compare with the existing file.
- `codex-rs/connectors/src/connector_runtime/mod.rs`,
  `publish_runtime_if_newest_accepted_with`, calls `persist` for every
  accepted fetch ("Keep the generation guard through persistence"). The fetch
  sources are `ConnectorRuntimeFetchSource::Startup` and `HardRefresh`. The
  disk cache is written only when `ConnectorRuntimeDiskCache::Enabled`.
- The serialized structs (`CodexAppsToolsDiskCache`,
  `CodexAppsServerInfoDiskCache`) hold no time stamp, so an unchanged tool list
  gives the same bytes again.

## What follows for the agent

A host that runs Codex gets a write of both files at each start and each
refresh, whether or not the content changed. The agent records a `file_change`
event for a write to a watched path, also when the hash is unchanged, and the
server counts it in the 24 hour warning count. So the two folders are not
default watch targets. The Codex parser still reads them at every assessment.
The write rate is read from the source, not measured.
