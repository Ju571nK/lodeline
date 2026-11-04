# Host detail

The host page shows one host's metadata, its AI Guard risk, its policy and agent health, its observed security settings, and its recent events. It stays readable for a host that has reported almost nothing.

## Sub-features

- `host-open` opens the page from a hostname link.
- `host-panels` renders the metadata, health, and recent events panels.
- `host-not-found` shows a panel for an unknown id.
- `host-null-heavy` renders a disconnected host with no metadata and no assessments.
- `host-observed-controls` shows the observed settings that the host API returns.

## How to get to it (user POV)

- Choose a hostname in the Risk, Events, or Compliance table.
- Open `/hosts/<host_id>` directly.
- Open `/hosts/<host_id>?event=<event_id>` to open an event on the page.
- Send `GET /api/v1/fleet/hosts/<host_id>`.

## Driving it with drive.sh

Preconditions:

- Doctor exits 0.
- For the API steps, log in for the API as [Login and session](./login-session.md) shows.
- The fixtures hold `alice-mbp` as `5a7c3e91-aaaa-bbbb-cccc-111111111111` and a host with a null hostname as `5a7c3e91-aaaa-bbbb-cccc-444444444444`.

- **Browser journey.** Run `drive.sh e2e "$RUN" host-browser tests/e2e/fleet.spec.ts -g 'hostname opens|host detail shows|unknown host id|null-heavy|observed controls survive'`. Exit code `0` with 5 tests passed.
- **Host read.** Run `drive.sh api "$RUN" host GET /api/v1/fleet/hosts/5a7c3e91-aaaa-bbbb-cccc-111111111111`. Status `200` with `hostname` set to `alice-mbp`.
- **Null-heavy host.** Run `drive.sh api "$RUN" host-null GET /api/v1/fleet/hosts/5a7c3e91-aaaa-bbbb-cccc-444444444444`. Status `200` with `hostname` set to `null`.
- **Unknown host.** Run `drive.sh api "$RUN" host-404 GET /api/v1/fleet/hosts/00000000-0000-0000-0000-000000000000`. Status `404` with code `not_found`.

## Gotchas

- The `observed controls survive...` test reads the real host API first, then stubs one read for the low-risk case. Only the first half proves the binary.
- The `?event=` entry point is covered only by a stubbed test in `investigation.spec.ts`. Report it as skipped, or add a test first.
- The `observed controls survive...` test saves `observed-controls-host.png` with its trace, under the label's evidence folder.
