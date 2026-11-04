# Login and session

An administrator signs in with a username and a password, stays signed in across a reload, and signs out from the top navigation. Every page except `/login` redirects to `/login` without a session.

## Sub-features

- `login-redirect` sends an anonymous visitor from `/` to `/login`.
- `login-success` signs in, lands on `/alerts`, and survives a reload.
- `login-wrong-password` shows an inline error and stays on `/login`.
- `login-local-only` hides the organization sign-in link when OIDC is not configured.
- `logout` clears the session and returns to `/login`.
- `session-api` issues and clears the `lodeline_session` cookie through the API.

## How to get to it (user POV)

- Open `/` without a session.
- Open `/login` directly.
- Choose the `Log out` button in the top navigation.
- Send `POST /api/v1/auth/login` and `POST /api/v1/auth/logout`.

## Driving it with drive.sh

Preconditions:

- Doctor exits 0.

- **Browser journey.** Run `drive.sh e2e "$RUN" login-browser tests/e2e/login.spec.ts`. Exit code `0`, and the runner prints `5 passed`: the `setup` login and one test for each of `login-redirect`, `login-success`, `login-wrong-password`, and `logout`.
- **Local sign-in only.** Run `drive.sh e2e "$RUN" login-local tests/e2e/oidc.spec.ts -g 'unconfigured provider'`. Exit code `0`, and the runner prints `2 passed`: the `setup` login and this test.
- **Anonymous read.** Run `drive.sh api "$RUN" me-anon GET /api/v1/auth/me`. Status `401` with code `unauthorized`.
- **Sign-in methods.** Run `drive.sh api "$RUN" methods GET /api/v1/auth/methods`. Status `200` with `{"local":true,"oidc":false}`.
- **Wrong password.** Run `drive.sh api "$RUN" login-bad POST /api/v1/auth/login '{"username":"admin","password":"wrong"}'`. Status `401` with code `invalid_credentials`.
- **Log in for the API.** Run `drive.sh api "$RUN" login POST /api/v1/auth/login '{"username":"admin","password":"test-password"}'`. Status `200` with `username` and `expires_at`. `login.headers` shows `Set-Cookie` with `HttpOnly` and `SameSite=Lax`.
- **Session read.** Run `drive.sh api "$RUN" me GET /api/v1/auth/me`. Status `200` with `username` set to `admin`.
- **Logout.** Run `drive.sh api "$RUN" logout POST /api/v1/auth/logout`. Status `200` with `{"status":"ok"}`. `logout.headers` shows `Max-Age=0`.
- **Session gone.** Run `drive.sh api "$RUN" me-after GET /api/v1/auth/me`. Status `401`.

## Gotchas

- The `drive.sh api` cookie jar and the browser session are separate. A browser login does not log in `api`.
- A failed login waits 250 ms on purpose. Do not read that delay as a slow server.
- `expires_at` has a different format in the login and `/auth/me` responses. Assert on the format that each endpoint returns.
- The `Secure` flag is absent because `LODELINE_INSECURE_COOKIE=1` is set. This feature does not prove the production cookie.
- Every login attempt counts against 10 a minute for `127.0.0.1`, loopback included, success or not. This feature makes 8 (Doctor 1, `login-browser` 4 with its setup login, `login-local` 1 through its setup login, `login-bad` and `login` 1 each) within a minute or two, so run its steps in order and do not add a second `e2e all` in the same minute. A `429` with `Retry-After` is the limiter, not a failure of the feature; wait that many seconds.
- `drive.sh` cannot prove the limit for other clients: the server listens on loopback only and `TRUSTED_PROXIES` is unset. `src/api/ratelimit/tests.rs` and the parity limiter cases cover it. `oidc.spec.ts` stubs the OIDC routes.
