# Codex coverage

This page says what Lodeline reads from Codex configuration and where its reading stops. It was checked on Codex 0.167.0. For each claim about profiles, the check ran `codex debug prompt-input`, which loads configuration and prints without contacting a service, against a scratch `CODEX_HOME` that held only the file under test.

## Profiles

Lodeline does not apply the legacy `profile = "<name>"` key or the `[profiles.<name>]` tables. Codex 0.167.0 stops with the error "legacy `profile` config is no longer supported; use `--profile` with `<name>.config.toml` instead" when `config.toml` sets the key, with or without the table. A `[profiles.<name>]` table without the key loads and has no effect. A profile table therefore never runs, and reporting it would report a setting Codex does not use. The release that removed the key is not known.

Files passed with `--profile`, such as `p.config.toml`, are not read. The flag is runtime state that a daemon cannot see.

## Approval policy

The granular `approval_policy` table is read on purpose. It only turns prompts into rejections, so it is not a finding by itself. The requirements allowlist still names `untrusted`.

## Hook trust

Lodeline reads hook trust from the trust state in the user config. A hook whose stored hash no longer matches is still reported as running. Codex skips such a hook, so Lodeline over-reports a modified hook. It does not compare the hash, because the input to that hash changes between Codex releases and a wrong mismatch would hide a hook that runs.
