# Alerts queue and triage

The queue lists high and critical AI Guard events. An analyst opens a row in a slide-over, assigns it, acknowledges it, and adds notes. The fleet is read-only, so triage state lives in the console's own SQLite file.

## Sub-features

- `alerts-queue` renders the fixture events as rows.
- `alerts-detail` opens a row in the slide-over, with its reasons and observed settings.
- `alerts-filter` narrows the queue with the `Critical` severity chip.
- `alerts-shortcuts` opens the keyboard cheatsheet with `?`.
- `triage-assign-ack` assigns a row, acknowledges it, and keeps the state after a reload.
- `triage-note` appends a note to a triage row.

## How to get to it (user POV)

- Sign in. The console lands on `/alerts`.
- Choose the `Alerts` link in the top navigation.
- Open `/alerts?query=<text>` directly.
- Open `/alerts?alert=<event_id>` to open the slide-over on one event. A reload keeps it open.
- Press `c` in the slide-over to acknowledge the row, or `?` to open the cheatsheet.
- Send `POST /api/v1/triage/upsert` and `POST /api/v1/triage/note`.

## Driving it with drive.sh

Preconditions:

- Doctor exits 0.
- The triage tables are empty, so run this feature on a new run.

- **Assign and acknowledge in the browser.** Run `drive.sh e2e "$RUN" triage-browser tests/e2e/alerts.spec.ts -g 'assign \+ acknowledge'`. Exit code `0`, and the runner prints `2 passed`: the `setup` login and this test. After the reload, the screenshot shows the slide-over with `ACKNOWLEDGED` and the assignee `alice`.
- **Stored row.** Run `drive.sh db "$RUN" triage-row 'select host_id,event_id,status,assignee from triage'`. One row with status `acknowledged` and assignee `alice`. Copy its `host_id` and `event_id`.
- **Transition log.** Run `drive.sh db "$RUN" triage-log 'select actor,from_status,to_status from triage_log'`. Two rows, `admin||open` and `admin|open|acknowledged`.
- **API second view.** Log in for the API as [Login and session](./login-session.md) shows, then run `drive.sh api "$RUN" triage-read GET /api/v1/triage/<host_id>/<event_id>`. Status `200` with `row.status` set to `acknowledged`, `row.assignee` set to `alice`, and two `log` entries.
- **Queue feed.** Run `drive.sh api "$RUN" events-triaged GET '/api/v1/fleet/events?limit=5'`. The event with the copied id has a `triage` object with `acknowledged` and `alice`.
- **Note.** Run `drive.sh api "$RUN" note POST /api/v1/triage/note '{"host_id":"<host_id>","event_id":"<event_id>","body":"verify note"}'`. Status `200` with `author` set to `admin`. Then run `drive.sh db "$RUN" note-row 'select author,body from triage_notes'`. One row, `admin|verify note`.
- **Rest of the queue.** Run `drive.sh e2e "$RUN" alerts-rest tests/e2e/alerts.spec.ts -g 'queue renders|slide-over|source_chain|gemini|severity filter|cheatsheet|observation context'`. Exit code `0`, and the runner prints `8 passed`: the `setup` login and 7 tests. These cover `alerts-queue`, `alerts-detail`, `alerts-filter`, and `alerts-shortcuts`.

## Gotchas

- No spec types in the note box, whose placeholder starts `Add a note`. Report the browser path of `triage-note` as skipped, or add a test first.
- No spec presses `c`. The assign test clicks `Acknowledge`. Report the keyboard path as skipped.
- `event_id` values change on every start. Copy them from this run.
- The assign spec picks the first row, so a second run of it in one instance updates the same row and the log grows. Start a new run for a clean count.
- The first upsert needs `evidence_snapshot`, or the API returns `400`. A note on a missing triage row returns `404`.
- The `observation context` test saves `observed-controls-event.png` with its trace, under the label's evidence folder.
- The `Alerts can search beyond...` test in `investigation.spec.ts` stubs the events endpoint.
