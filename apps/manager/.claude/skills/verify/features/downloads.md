# Downloads

The Downloads page lists the release files in the server's `artifacts_dir` and lets a signed-in user save one in the browser. The console reads the files from `lodeline-server` with its own read token and streams each one to the browser. The page says that the console does not check the files.

## Sub-features

- `downloads-list` lists every file name the server sends, each as a link to `/api/v1/fleet/artifacts/<name>`.
- `downloads-save` saves a file through the browser's download manager, with the server's name and bytes.
- `downloads-not-configured` names the `server.yaml` setting and the install guide section when the server has no `artifacts_dir`.
- `downloads-bad-name` refuses a name the server would refuse with 400 `bad_filename`, before any request leaves the console.

## How to get to it (user POV)

- Choose **Downloads** in the top nav.
- Open `/downloads` directly.
- Send `GET /api/v1/fleet/artifacts` or `GET /api/v1/fleet/artifacts/<name>`.

## Driving it with drive.sh

Preconditions:

- Doctor exits 0.
- For the API steps, log in for the API as [Login and session](./login-session.md) shows.

- **List and save.** Run `drive.sh e2e "$RUN" downloads-browser tests/e2e/downloads.spec.ts -g 'saves one'`. Exit code `0`, and the runner prints `2 passed`: the `setup` login and this test. The test saves `build-manifest.json` and compares its text. `downloads.png` shows the list.
- **Not configured.** Run `drive.sh e2e "$RUN" downloads-off tests/e2e/downloads.spec.ts -g 'without artifacts_dir'`. Exit code `0`. This test stubs `/api/v1/fleet/artifacts`, so it proves rendering only.
- **Index.** Run `drive.sh api "$RUN" downloads-index GET /api/v1/fleet/artifacts`. Status `200` with the four mock names under `artifacts`.
- **One file.** Run `drive.sh api "$RUN" downloads-file GET /api/v1/fleet/artifacts/SHA256SUMS`. Status `200`, `content-type: application/octet-stream`, `content-disposition: attachment; filename="SHA256SUMS"` and a one-line mock text body.
- **Bad name.** Run `drive.sh api "$RUN" downloads-bad GET '/api/v1/fleet/artifacts/..%2Fserver.yaml'`. Status `400` with code `bad_filename`.

## Gotchas

- The mock files are one line of text each, whatever their names say. A size, a large file or a slow transfer is not driven here. `src/fleet/tests/artifacts.rs` streams a 3 MiB file from a real `lodeline-server` in process, and `src/fleet/http/tests.rs` covers the stall limit.
- No run produces `artifacts_not_configured`, `read_api_disabled` or `certificate_refused` from the binary, because the mock never fails. Report those as unverified here.
- A failed download shows in the browser's download manager, not on the page. No spec covers it.
