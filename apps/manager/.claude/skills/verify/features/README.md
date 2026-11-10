# lodeline-manager verification map

This directory is the maintained source for verifying the user-facing behavior of the console. Read the index before you drive the app, then use the matching feature file as the recipe.

## Baseline preconditions

- `drive.sh` means `.claude/skills/verify/drive.sh`. Run it from `apps/manager`.
- `drive.sh new` printed a run id, and `drive.sh doctor "$RUN"` exits 0.
- The instance has empty triage tables. Start a new run if a recipe needs them empty and an earlier recipe wrote to them.
- The API recipes that need a session start with the login in [Log in for the API](./login-session.md#driving-it-with-drivesh).
- Never drive an instance that this run did not start.

## Driving conventions

- `drive.sh e2e` drives the real browser. `drive.sh api` drives the HTTP API. `drive.sh db` reads the SQLite file.
- Treat each command as literal, except `<label>` values that you need to make unique and ids that you copy from this run.
- A label is single-use across a run.
- Prefer ARIA roles and accessible names when you add a test to a spec.
- A recipe that a spec does not cover in the browser says so. Report that entry point as skipped.

## Proof and skip reporting

- Browser proof is the Playwright exit code plus `trace.zip` and `test-finished-1.png` for each test.
- API proof is the `.cmd`, `.status`, and `.body` files of the capture.
- Mutation proof includes a second view through `drive.sh db` or `drive.sh api`.
- Report every result as verified, skipped, or failed, with the feature ID and the entry point.
- Report what `MOCK_FLEET=1` replaced. See [What the mock hides](../SKILL.md#what-the-mock-hides).

## Feature entry contract

Each feature file starts with an H1 title and one paragraph that describes the user-visible behavior. It then uses exactly four H2 sections in this order.

1. `Sub-features` lists short IDs with one line for each behavior.
2. `How to get to it (user POV)` lists every user entry point.
3. `Driving it with drive.sh` starts with `Preconditions:` and uses labeled bullets that pair each action with an exact command and an observable result.
4. `Gotchas` lists traps that can waste or invalidate a run.

If the fixtures lack a precondition that a journey needs, the journey reports a failure and the reason goes in `Gotchas`. Never weaken a journey to make it pass.

## Features

- [Login and session](./login-session.md) covers local sign-in, session persistence, logout, and the API session.
- [Alerts queue and triage](./alerts-triage.md) covers the queue, the slide-over, assign and acknowledge, notes, and the stored triage row.
- [Fleet pages](./fleet-views.md) covers the Risk, Events, Compliance, and Devices tabs.
- [Host detail](./host-detail.md) covers the host page, its panels, and the not-found and null-heavy states.
- [Proxies](./proxies.md) covers the read-only proxy and invocation lists and details, a proxy's inventory snapshots, drift and re-baseline markers, the filters and cursor, flagged invocations, truncated event lists, and the not-found and unavailable states.
- [Downloads](./downloads.md) covers the list of the server's release files, saving one in the browser, the not-configured state, and the refused file name.
- [Enroll a host](./enroll.md) covers the page that makes a host's enrollment file, its table of what the file holds, the saved file, the host id check and the error texts.
- [Settings](./settings.md) covers the connection state, the server metadata, and the audit status.
