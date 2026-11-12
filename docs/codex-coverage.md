# Codex coverage

This page says what Lodeline reads from Codex configuration and where its reading stops. Checked against Codex 0.167.0 unless a line names another version.

## Profiles

When `config.toml` sets `profile = "<name>"` and holds a `[profiles.<name>]` table, Lodeline lays that table over the user layer before it assesses the file. A key in the table replaces the same key in the user layer and leaves the others. A name with no table, or a table with no `profile` key, changes nothing.

Codex 0.167.0 no longer loads the legacy `profile` key. It stops with the error "legacy `profile` config is no longer supported; use `--profile` with `<name>.config.toml` instead". A `[profiles.<name>]` table without the key still loads and does nothing. Lodeline still reads the legacy key because hosts can run an older Codex that honors it, so on a 0.167.0 host it can report a setting that Codex refuses to start with.

Profile files passed with `--profile`, such as `p.config.toml`, are not read. The flag is runtime state that a daemon cannot see.

## Approval policy

The granular `approval_policy` table is read on purpose. It only turns prompts into rejections, so it is not a finding by itself. The requirements allowlist still names `untrusted`.

## Hook trust

Lodeline reads hook trust from the trust state in the user config. A hook whose stored hash no longer matches is still reported as running. Codex skips such a hook, so Lodeline over-reports a modified hook. It does not compare the hash, because the input to that hash changes between Codex releases and a wrong mismatch would hide a hook that runs.
