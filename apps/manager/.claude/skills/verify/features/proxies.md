# Proxies

The Proxies pages list the Lodeline Proxy instances that `lodeline-server` knows and show one proxy's last report: config revisions and state, spool, central ingest, registry sync, route health, and audit gaps. They only read; no page offers a control that changes a proxy.

## Sub-features

- `proxies-list` lists every proxy with its connection state, report time, open gaps, config and spool.
- `proxies-filter` narrows the list by connection state and config sync through the URL.
- `proxy-detail` shows one proxy's report, with a degraded spool labeled as a stopped ingest when the proxy says so.
- `proxy-older` labels what an older proxy leaves out, and a gap list the server capped.
- `proxy-not-found` shows one panel for an unknown proxy and one outside the read range.
- `proxy-reads-unavailable` names a server that does not serve proxy reads.

## How to get to it (user POV)

- Choose **Proxies** in the top nav.
- Open `/proxies`, or `/proxies?connection=<state>&sync=<in_sync|out_of_sync>`.
- Choose a proxy name in the list, or open `/proxies/<proxy_id>` directly.
- Send `GET /api/v1/fleet/proxies` or `GET /api/v1/fleet/proxies/<proxy_id>`.

## Driving it with drive.sh

Preconditions:

- Doctor exits 0.
- For the API steps, log in for the API as [Login and session](./login-session.md) shows.
- The mock serves `testdata/mock-proxies.json`: `px-edge-01` (connected, in sync), `px-edge-02` (connected, out of sync, ingest stopped, spool degraded), `px-lab-03` (disconnected, expired config, quarantined bytes `null`, no registry counters, 3 dropped gaps), `px-new-04` (never connected, no report) and `px-off-05` (config disabled).

- **Browser journey.** Run `drive.sh e2e "$RUN" proxies-browser tests/e2e/proxies.spec.ts`. Exit code `0`, and the runner prints `6 passed`: the `setup` login and 5 tests. The tests save `proxies-list.png`, `proxy-detail-ingest-stopped.png` and `proxy-detail-older.png` under the label's evidence folder.
- **List read.** Run `drive.sh api "$RUN" proxies GET /api/v1/fleet/proxies`. Status `200` with 5 `items` and `next_cursor` set to `null`.
- **Cursor.** Run `drive.sh api "$RUN" proxies-page GET '/api/v1/fleet/proxies?limit=2'`, then `drive.sh api "$RUN" proxies-page-2 GET '/api/v1/fleet/proxies?limit=2&cursor=px-edge-02'`. The first holds `px-edge-01` and `px-edge-02` with `next_cursor` `px-edge-02`; the second starts at `px-lab-03`.
- **Refused cursor.** Run `drive.sh api "$RUN" proxies-bad-cursor GET '/api/v1/fleet/proxies?cursor=px-unknown'`. Status `422` with code `invalid_cursor`.
- **Detail read.** Run `drive.sh api "$RUN" proxy GET /api/v1/fleet/proxies/px-edge-02`. Status `200` with `central.ingest_stopped` `true` and `spool.state` `degraded`.
- **Unknown proxy.** Run `drive.sh api "$RUN" proxy-404 GET /api/v1/fleet/proxies/px-missing`. Status `404` with code `not_found`.

## Gotchas

- The mock's cursor is the last proxy ID of a page. A real server's cursor is opaque base64url and is bound to the filters; the console passes either back unchanged.
- `a server without proxy reads is named as such` stubs the proxy endpoints with `page.route`. The parity suite's `live-proxies-not-mounted` and `live-proxy-not-mounted` cases prove the binary's answer, and `src/fleet/tests/proxies.rs` proves the real server's 404.
- The list shows `Degraded` without the ingest-stop label, because only the detail API carries `central.ingest_stopped`.
