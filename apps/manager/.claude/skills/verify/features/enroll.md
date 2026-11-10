# Enroll a host

The Enroll a host page makes a host's single-use enrollment file and has the browser save it. It lists what the file will hold, with the CA and policy key fingerprints. After a click it shows the host id, the expiry and the steps for a Linux host installed from the packages. With `MOCK_FLEET=1` the console uses a mock mint, so the token in the file works nowhere. `drive.sh new` sets `LODELINE_PUBLIC_ORIGIN` to the run's own origin, which the POST route needs.

## Sub-features

- `enroll-table` lists the server URL, the enrollment URL, the CA certificates and the policy keys.
- `enroll-make` saves `lodeline-enroll-<host_id>.json` and shows the host id, the expiry, the secret notice and the steps.
- `enroll-bad-host-id` refuses a host id that is not a lower-case, hyphenated version 4 UUID, before any request leaves the page.
- `enroll-error` shows one alert with a cause and an action for each error code of the route.
- `enroll-status` answers `GET /api/v1/enrollment` with what a file would hold.
- `enroll-origin` refuses a POST without the console's own `Origin` with 403 `origin_not_allowed`.

## How to get to it (user POV)

- Choose **Enroll a host** in the top nav.
- Open `/enroll` directly.
- Send `GET /api/v1/enrollment` or `POST /api/v1/enrollment/files`.

## Driving it with drive.sh

Preconditions:

- Doctor exits 0.
- For the API steps, log in for the API as [Login and session](./login-session.md) shows.

- **Table and file.** Run `drive.sh e2e "$RUN" enroll-browser tests/e2e/enroll.spec.ts`. Exit code `0`, and the runner prints `5 passed`: the `setup` login and the four tests. `enroll.png` shows the table and `enroll-made.png` the page after the click. The test saves the file and checks that its `host_id` is a version 4 UUID and its `lodeline_enrollment` is 1.
- **Bad host id and an error.** The same run covers a bad host id (no request) and `enroll_unavailable`. The error test stubs the POST, so it proves rendering only.
- **Status.** Run `drive.sh api "$RUN" enroll-status GET /api/v1/enrollment`. Status `200`, `enabled` true, `can_enroll` true, and the mock CA and policy key.
- **Origin.** Run `drive.sh api "$RUN" enroll-origin POST /api/v1/enrollment/files '{}'`. Status `403` with code `origin_not_allowed`, because curl sends no `Origin`.

## Gotchas

- The mock token works nowhere and no run reaches a real `lodeline-server`. The mint, mutual TLS, the server's `host_exists` and `token_outstanding` answers and `lodeline-sender enroll` are not driven here. `src/api/enrollment/tests.rs` and the real-stack run of the pull request that added the page cover them.
- `LODELINE_PUBLIC_ORIGIN` is `http://localhost:<port>`. A browser opened at `127.0.0.1:<port>` sends another origin and gets 403 `origin_not_allowed`. Open the page at `localhost`, as the specs do.
- The download goes to Playwright's download handler, so a real browser's download manager and its prompts are not driven.
