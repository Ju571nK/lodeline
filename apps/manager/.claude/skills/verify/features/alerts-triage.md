# Alerts queue and triage

The queue lists high and critical AI Guard events. Events that repeat one finding share a row. An analyst opens a row in a slide-over, assigns it, acknowledges it, and adds notes. The fleet is read-only, so triage state lives in the console's own SQLite file.

## Sub-features

- `alerts-queue` renders the fixture events as rows.
- `alerts-group` collapses repeats of one finding (same host, tool, scope, user, reasons and triage status) into one row with a count, and titles a row by its first reason and the number of other kinds. Triage actions on a collapsed row apply to every event of it.
- `alerts-detail` opens a row in the slide-over, with its reasons, grouped by kind with a count and collapsed when a kind repeats, and its observed settings.
- `alerts-filter` narrows the queue with the `Critical` severity chip.
- `alerts-shortcuts` opens the keyboard cheatsheet with `?`.
- `alerts-drawer-nav` moves through the queue with the previous and next buttons and shows the position, such as `3 of 7`. `j`, `k` and the arrow keys do the same.
- `alerts-drawer-width` starts the drawer wider than 420 px on a large window, resizes it by dragging its left edge or with the arrow keys on the focused edge, remembers the width in the browser, and takes the full width under 900 px.
- `alerts-full-page` opens `Open full page` at `/alerts/<event_id>` and returns with `Back to alerts` to the list with its filters. The host id in the drawer links to `/hosts/<host_id>`.
- `triage-assign-ack` assigns a row, acknowledges it, and keeps the state after a reload.
- `triage-note` appends a note to a triage row.

## How to get to it (user POV)

- Sign in. The console lands on `/alerts`.
- Choose the `Alerts` link in the top navigation.
- Open `/alerts?query=<text>` directly.
- Open `/alerts?alert=<event_id>` to open the slide-over on one event. A reload keeps it open.
- Open `/alerts/<event_id>` for the same alert at full width. Filters ride along in the query string.
- Press `c` in the slide-over to acknowledge the row, or `?` to open the cheatsheet.
- Send `POST /api/v1/triage/upsert` and `POST /api/v1/triage/note`.

## Driving it with drive.sh

Preconditions:

- Doctor exits 0.
- The triage tables are empty, so run this feature on a new run.

- **Assessment failure in the slide-over.** Run `drive.sh e2e "$RUN" assess-failed tests/e2e/alerts.spec.ts -g 'assessment failure'`. Exit code `0`, and the runner prints `2 passed`. The queue has no row for the `ai_guard_assess_failed` event, because it is not a default alert kind, and `/alerts?alert=<its id>` shows its error, path and source.
- **Assign and acknowledge in the browser.** Run `drive.sh e2e "$RUN" triage-browser tests/e2e/alerts.spec.ts -g 'assign \+ acknowledge'`. Exit code `0`, and the runner prints `2 passed`: the `setup` login and this test. After the reload, the screenshot shows the slide-over with `ACKNOWLEDGED` and the assignee `alice`.
- **Stored row.** Run `drive.sh db "$RUN" triage-row 'select host_id,event_id,status,assignee from triage'`. One row with status `acknowledged` and assignee `alice`. Copy its `host_id` and `event_id`.
- **Transition log.** Run `drive.sh db "$RUN" triage-log 'select actor,from_status,to_status from triage_log'`. Two rows, `admin||open` and `admin|open|acknowledged`.
- **API second view.** Log in for the API as [Login and session](./login-session.md) shows, then run `drive.sh api "$RUN" triage-read GET /api/v1/triage/<host_id>/<event_id>`. Status `200` with `row.status` set to `acknowledged`, `row.assignee` set to `alice`, and two `log` entries.
- **Queue feed.** Run `drive.sh api "$RUN" events-triaged GET '/api/v1/fleet/events?limit=5'`. The event with the copied id has a `triage` object with `acknowledged` and `alice`.
- **Note.** Run `drive.sh api "$RUN" note POST /api/v1/triage/note '{"host_id":"<host_id>","event_id":"<event_id>","body":"verify note"}'`. Status `200` with `author` set to `admin`. Then run `drive.sh db "$RUN" note-row 'select author,body from triage_notes'`. One row, `admin|verify note`.
- **Drawer navigation, width and full page.** Run `drive.sh e2e "$RUN" alerts-drawer tests/e2e/alerts.spec.ts -g 'alert detail drawer'`. Exit code `0`, and the runner prints `8 passed`: the `setup` login and 7 tests. These cover `alerts-drawer-nav`, `alerts-drawer-width` and `alerts-full-page`.
- **Rest of the queue.** Run `drive.sh e2e "$RUN" alerts-rest tests/e2e/alerts.spec.ts -g 'queue renders|slide-over|source_chain|gemini|severity filter|cheatsheet|observation context'`. Exit code `0`, and the runner prints `8 passed`: the `setup` login and 7 tests. These cover `alerts-queue`, `alerts-detail`, `alerts-filter`, and `alerts-shortcuts`.
- **Repeated alerts.** Run `drive.sh e2e "$RUN" alerts-group tests/e2e/alerts.spec.ts -g 'repeated alerts'` on a new run, after the stored-row steps above. Exit code `0`, and the runner prints `5 passed`: the `setup` login and 4 tests. The Claude Desktop `No Sandbox` finding is one row with `×2` and its scope, opening it opens the newest of the two events, the header and the drawer position both count rows, and acknowledging the row leaves one `ACK` row that still shows `×2`.

## Gotchas

- No spec types in the note box, whose placeholder starts `Add a note`. Report the browser path of `triage-note` as skipped, or add a test first.
- No spec presses `c`. The assign test clicks `Acknowledge`. Report the keyboard path as skipped.
- The `repeated alerts` tests use the two Claude Desktop `No Sandbox` events of the fixture. The last test acknowledges both of them, so it writes a triage row and belongs in its own run.
- `event_id` values change on every start. Copy them from this run.
- The assign spec picks the first row, so a second run of it in one instance updates the same row and the log grows. Start a new run for a clean count.
- The first upsert needs `evidence_snapshot`, or the API returns `400`. A note on a missing triage row returns `404`.
- The `observation context` test saves `observed-controls-event.png` with its trace, under the label's evidence folder.
- The `Alerts can search beyond...` test in `investigation.spec.ts` stubs the events endpoint.
