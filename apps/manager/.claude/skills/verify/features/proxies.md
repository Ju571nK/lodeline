# Proxies

The Proxies pages list the Lodeline Proxy instances that `lodeline-server` knows and show one proxy's last report: config revisions and state, spool, central ingest, registry sync, route health, and audit gaps. A proxy's page also lists its inventory snapshots, drift and re-baseline markers, by reference only. The invocation pages list the calls that went through the proxies and show one call's projection and event envelopes. They only read; no page offers a control that changes a proxy.

## Sub-features

- `proxies-list` lists every proxy with its connection state, report time, open gaps, config and spool.
- `proxies-filter` narrows the list by connection state and config sync through the URL.
- `proxy-detail` shows one proxy's report, with a degraded spool labeled as a stopped ingest when the proxy says so.
- `proxy-older` labels what an older proxy leaves out, and a gap list the server capped.
- `proxy-not-found` shows one panel for an unknown proxy and one outside the read range.
- `proxy-reads-unavailable` names a server that does not serve proxy reads.
- `invocations-list` lists invocations newest first, for all proxies or one, and narrows them by lifecycle, outcome and method through the URL.
- `invocation-flagged` shows a `completion_without_start` or `integrity_conflict` invocation as flagged, with the proxy's claim as secondary text and never as success.
- `invocation-truncated` says how many events the server did not return when `events_truncated` is true.
- `invocation-not-found` shows one panel for an unknown invocation and one whose proxy is outside the read range.
- `inventory-snapshots` lists a proxy's snapshots newest first, with each chain, comparison state and key, and says that incomplete observations are audit gaps.
- `inventory-drift` lists observed changes by reference under "Observed change", never as approved.
- `inventory-markers` lists re-baseline markers with their cause, key change and links.
- `inventory-incomplete` keeps an `inventory_incomplete` observation in the audit gap list and out of the snapshots.
- `proxies-nav` keeps the **Proxies** nav item active on the proxy and invocation pages.

## How to get to it (user POV)

- Choose **Proxies** in the top nav.
- Open `/proxies`, or `/proxies?connection=<state>&sync=<in_sync|out_of_sync>`.
- Choose a proxy name in the list, or open `/proxies/<proxy_id>` directly.
- Send `GET /api/v1/fleet/proxies` or `GET /api/v1/fleet/proxies/<proxy_id>`.
- Choose **All invocations** on the Proxies page, or **Invocations of this proxy** on a proxy's page.
- Open `/proxy-invocations`, or `/proxy-invocations?proxy=<proxy_id>&lifecycle=<lifecycle>&outcome=<outcome>&method=<method>`.
- Choose an invocation ID in the list, or open `/proxy-invocations/<invocation_id>` directly.
- Send `GET /api/v1/fleet/proxy-invocations` or `GET /api/v1/fleet/proxy-invocations/<invocation_id>`.
- On a proxy's page, choose **Snapshots**, **Drift** or **Re-baseline markers** in the Inventory card, or open `/proxies/<proxy_id>?inventory=<inventory-snapshots|drift|rebaseline-markers>`.
- Send `GET /api/v1/fleet/proxies/<proxy_id>/inventory-snapshots`, `/drift` or `/rebaseline-markers`.

## Driving it with drive.sh

Preconditions:

- Doctor exits 0.
- For the API steps, log in for the API as [Login and session](./login-session.md) shows.
- The mock serves `testdata/mock-proxies.json`: `px-edge-01` (connected, in sync), `px-edge-02` (connected, out of sync, ingest stopped, spool degraded), `px-lab-03` (disconnected, expired config, quarantined bytes `null`, no registry counters, 3 dropped gaps), `px-new-04` (never connected, no report) and `px-off-05` (config disabled).
- The mock serves `testdata/mock-proxy-inventory.json`: `px-edge-01` has 5 snapshots (IDs ending in `502` to `506`), 4 drift records (`603` to `606`, one of each change and a second add) and 1 marker (`702`, declared key rotation). `px-edge-02` has 5 snapshots, among them a `pending_previous` (`512`) and an `inconsistent` (`510`), no drift and 1 marker (`711`, undeclared key change). `px-lab-03` has 2 snapshots and 1 marker (`721`, epoch change) next to its `inventory_incomplete` gap. The other proxies have empty views.
- The mock serves `testdata/mock-proxy-invocations.json`: 10 invocations whose IDs end in `401` to `410`. `401` is a `completion_without_start` and `402` an `integrity_conflict`, both on `px-edge-02` and both reported as success by the proxy. `404` is a completed timeout with 40 events, of which 32 are listed. `407` is a `started` invocation on `px-lab-03` whose epoch was superseded.

- **Browser journey.** Run `drive.sh e2e "$RUN" proxies-browser tests/e2e/proxies.spec.ts`. Exit code `0`, and the runner prints `6 passed`: the `setup` login and 5 tests. The tests save `proxies-list.png`, `proxy-detail-ingest-stopped.png` and `proxy-detail-older.png` under the label's evidence folder.
- **List read.** Run `drive.sh api "$RUN" proxies GET /api/v1/fleet/proxies`. Status `200` with 5 `items` and `next_cursor` set to `null`.
- **Cursor.** Run `drive.sh api "$RUN" proxies-page GET '/api/v1/fleet/proxies?limit=2'`, then `drive.sh api "$RUN" proxies-page-2 GET '/api/v1/fleet/proxies?limit=2&cursor=px-edge-02'`. The first holds `px-edge-01` and `px-edge-02` with `next_cursor` `px-edge-02`; the second starts at `px-lab-03`.
- **Refused cursor.** Run `drive.sh api "$RUN" proxies-bad-cursor GET '/api/v1/fleet/proxies?cursor=px-unknown'`. Status `422` with code `invalid_cursor`.
- **Detail read.** Run `drive.sh api "$RUN" proxy GET /api/v1/fleet/proxies/px-edge-02`. Status `200` with `central.ingest_stopped` `true` and `spool.state` `degraded`.
- **Unknown proxy.** Run `drive.sh api "$RUN" proxy-404 GET /api/v1/fleet/proxies/px-missing`. Status `404` with code `not_found`.
- **Invocation browser journey.** Run `drive.sh e2e "$RUN" invocations-browser tests/e2e/proxy-invocations.spec.ts`. Exit code `0`, and the runner prints `6 passed`: the `setup` login and 5 tests. The tests save `invocations-list.png`, `invocation-detail-flagged.png` and `invocation-detail-truncated.png` under the label's evidence folder.
- **Invocation list read.** Run `drive.sh api "$RUN" invocations GET /api/v1/fleet/proxy-invocations`. Status `200` with 10 `items` and `next_cursor` set to `null`.
- **Invocation cursor.** Run `drive.sh api "$RUN" invocations-page GET '/api/v1/fleet/proxy-invocations?limit=3'`, then `drive.sh api "$RUN" invocations-page-2 GET '/api/v1/fleet/proxy-invocations?limit=3&cursor=00000000-0000-4000-8000-000000000403'`. The first holds `401` to `403` with that `next_cursor`; the second starts at `404`.
- **Cursor from other filters.** Run `drive.sh api "$RUN" invocations-bad-cursor GET '/api/v1/fleet/proxy-invocations?proxy_id=px-edge-02&cursor=00000000-0000-4000-8000-000000000403'`. Status `422` with code `invalid_cursor`.
- **Truncated detail.** Run `drive.sh api "$RUN" invocation GET /api/v1/fleet/proxy-invocations/00000000-0000-4000-8000-000000000404`. Status `200` with `events_total` `40`, `events_truncated` `true` and 32 `events`.
- **Unknown invocation.** Run `drive.sh api "$RUN" invocation-404 GET /api/v1/fleet/proxy-invocations/00000000-0000-4000-8000-000000000999`. Status `404` with code `not_found` and message `invocation not found`.
- **Inventory browser journey.** Run `drive.sh e2e "$RUN" inventory-browser tests/e2e/proxy-inventory.spec.ts`. Exit code `0`, and the runner prints `6 passed`: the `setup` login and 5 tests. The tests save `inventory-snapshots.png`, `inventory-drift.png`, `inventory-markers.png` and `inventory-incomplete-gap.png` under the label's evidence folder.
- **Snapshots read.** Run `drive.sh api "$RUN" snapshots GET /api/v1/fleet/proxies/px-edge-01/inventory-snapshots`. Status `200` with 5 `items`, the first `compared` and `is_latest` `true`, and `next_cursor` `null`.
- **Drift read.** Run `drive.sh api "$RUN" drift GET '/api/v1/fleet/proxies/px-edge-01/drift?change=changed'`. Status `200` with 1 item whose `previous_metadata_ref` ends in `802`.
- **Refused drift filter.** Run `drive.sh api "$RUN" drift-bad GET '/api/v1/fleet/proxies/px-edge-01/drift?change=approved'`. Status `422` with code `invalid_filter`.
- **Markers read.** Run `drive.sh api "$RUN" markers GET /api/v1/fleet/proxies/px-edge-02/rebaseline-markers`. Status `200` with 1 item whose `cause` is `key_change_undeclared` and `drift_computed` `false`.
- **Inventory of an unknown proxy.** Run `drive.sh api "$RUN" inventory-404 GET /api/v1/fleet/proxies/px-missing/drift`. Status `404` with code `not_found` and message `proxy not found`.

## Gotchas

- The mock's cursor is the last proxy ID of a page. A real server's cursor is opaque base64url and is bound to the filters; the console passes either back unchanged.
- `a server without proxy reads is named as such` stubs the proxy endpoints with `page.route`. The parity suite's `live-proxies-not-mounted` and `live-proxy-not-mounted` cases prove the binary's answer, and `src/fleet/tests/proxies.rs` proves the real server's 404.
- The list shows `Degraded` without the ingest-stop label, because only the detail API carries `central.ingest_stopped`.
- The mock refuses the filter values the server refuses, but it checks IDs and times less strictly: it accepts any ID and reads `from` and `to` with the console's own time parser. `src/fleet/tests/proxies.rs` runs the server's invocation routes with every lifecycle and outcome.
- The invocation pages have no time range control; `from`, `to`, `time_basis`, `upstream_id`, `actor_id` and `tool_ref` reach the server only through the API.
- The inventory views have no filter control; `upstream_id`, `credential_scope_id`, `change`, `from` and `to` reach the server only through the API. `src/fleet/tests/proxies.rs` runs the server's inventory routes with every comparison state, change and marker cause.
- A tab switch fades the tab colors. Take a screenshot with `animations: 'disabled'`, or it can show the old tab underlined.
