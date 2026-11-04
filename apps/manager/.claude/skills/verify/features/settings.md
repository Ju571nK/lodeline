# Settings

The Settings page shows whether the console can reach the fleet read API, what the server reports about itself, and the audit status. It keeps server liveness separate from read API errors.

## Sub-features

- `settings-connection` shows `Connected (authenticated)` when the read API works.
- `settings-metadata` shows the server version and the fleet size.
- `settings-audit` shows the signed audit head or says why none exists.
- `settings-retry` rechecks the connection with `Retry connection`.
- `settings-errors` shows `Reachable` with a read API error, and labels cached metadata.

## How to get to it (user POV)

- Choose the `Settings` link in the top navigation.
- Open `/settings` directly.
- Send `GET /api/v1/fleet/meta` and `GET /api/v1/fleet/healthz`.

## Driving it with drive.sh

Preconditions:

- Doctor exits 0.
- For the API steps, log in for the API as [Login and session](./login-session.md) shows.

- **Connected state.** Run `drive.sh e2e "$RUN" settings-browser tests/e2e/investigation.spec.ts -g 'Settings labels stale'`. Exit code `0` with 1 test passed. Only its first step reaches the binary, the one that shows `Connected (authenticated)`. The trace shows that step.
- **Metadata.** Run `drive.sh api "$RUN" settings-meta GET /api/v1/fleet/meta`. Status `200` with `server_version` and `alerts_definition_default`.
- **Liveness.** Run `drive.sh api "$RUN" settings-healthz GET /api/v1/fleet/healthz`. Status `200` with `status` set to `ok`.
- **Stubbed error states.** Run `drive.sh e2e "$RUN" settings-errors tests/e2e/investigation.spec.ts -g 'Settings'`. Exit code `0` with 6 tests passed. These prove rendering only.

## Gotchas

- Every `settings-errors` state is a browser stub on `/api/v1/fleet/meta`. No run produces those responses from the binary, because the mock never fails. Report the upstream failure paths as unverified.
- The mock's metadata has no `audit_head` field, so the real binary never shows a signed head in this setup.
