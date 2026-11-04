# Fleet pages

The Fleet section shows every host through four tabs: Devices, Risk, Events, and Compliance. Each tab reads from the fleet API, keeps its filters in the URL, and links to host detail.

## Sub-features

- `fleet-redirect` sends `/fleet` to `/fleet/risk`.
- `fleet-header` shows the active host count from the fleet metadata.
- `fleet-risk` lists the hosts with risk and filters by minimum bucket.
- `fleet-events` lists events and filters by kind.
- `fleet-compliance` shows the policy state of each host.
- `fleet-devices` lists all hosts, compares agent versions, and filters by status.

## How to get to it (user POV)

- Choose the `Fleet` link in the top navigation.
- Open `/fleet` directly.
- Choose the `Devices`, `Risk`, `Events`, or `Compliance` tab.
- Send `GET /api/v1/fleet/risk`, `/compliance`, `/events`, `/hosts`, or `/meta`.

## Driving it with drive.sh

Preconditions:

- Doctor exits 0.
- For the API steps, log in for the API as [Login and session](./login-session.md) shows.

- **Browser journey.** Run `drive.sh e2e "$RUN" fleet-browser tests/e2e/fleet.spec.ts -g 'redirect|active host count|tab switching|min_bucket|AI Guard chip'`. Exit code `0` with 6 tests passed.
- **Risk rows.** Run `drive.sh api "$RUN" risk GET /api/v1/fleet/risk`. Status `200` with 4 `rows`.
- **Risk filter.** Run `drive.sh api "$RUN" risk-critical GET '/api/v1/fleet/risk?min_bucket=critical'`. Status `200` with 2 `rows`, for `eve-workstation` and `alice-mbp`.
- **Compliance rows.** Run `drive.sh api "$RUN" compliance GET /api/v1/fleet/compliance`. Status `200` with `rows`.
- **Events.** Run `drive.sh api "$RUN" events GET '/api/v1/fleet/events?limit=5'`. Status `200` with 5 `events` and a `next_cursor`.
- **Bad query.** Run `drive.sh api "$RUN" events-bad GET '/api/v1/fleet/events?limit=notanumber'`. Status `400` with code `invalid_query`.
- **Devices data.** Run `drive.sh api "$RUN" hosts GET /api/v1/fleet/hosts` and `drive.sh api "$RUN" hosts-down GET '/api/v1/fleet/hosts?status=disconnected'`. Status `200`, with 5 hosts in the first response and 1 host in the second.
- **Metadata.** Run `drive.sh api "$RUN" meta GET /api/v1/fleet/meta`. Status `200` with `fleet.active_host_count` set to `5`.

## Gotchas

- `devices.spec.ts` stubs the hosts endpoint for the whole test. It proves the Devices tab rendering only. Report the Devices tab against the binary as skipped, and prove the data with the `hosts` captures.
- The paging tests in `investigation.spec.ts` stub the endpoints. Real cursors from a `lodeline-server` stay unverified.
- `server_version` is `0.5.0-mock` on this instance. It is a fixture value, not a real server version.
- The `-g` pattern also matches a test title in `login.spec.ts`, so keep the spec path.
