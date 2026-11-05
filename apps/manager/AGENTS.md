# lodeline-manager

`lodeline-manager` is the fleet web console: a Rust server with a React SPA in `web/`. It is a
read-only consumer of `lodeline-server`'s fleet read API, documented in
[`docs/specs/fleet-api/contract.md`](../../docs/specs/fleet-api/contract.md). It writes only its
own triage notes. Lodeline measures and does not block, and the console keeps that framing in
its UI text and docs.

This folder is its own Cargo workspace. The root workspace does not build it,
`.github/workflows/manager.yml` tests it, root `ci.yml` ignores `apps/**`, and
`.github/workflows/release.yml` ships it. Its version is the root workspace version, and a
release prep bumps both (`tests/test_release_manifest.py` checks it).

## Build and test

```sh
cd apps/manager/web
npm ci
npm run lint            # biome
npm test -- --run       # vitest
npm run build           # writes web/dist

cd ..
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo +1.88 check --all-targets --locked   # MSRV
```

`build.rs` embeds `web/dist` into the binary, and a placeholder page when `web/dist` is
absent. Build `web/dist` before a release build, and set `LODELINE_MANAGER_REQUIRE_DIST=1`
so a missing `web/dist` fails the build:

```sh
LODELINE_MANAGER_REQUIRE_DIST=1 cargo build --release
```

The release binary is `target/release/lodeline-manager`. It reads only environment variables
(`.env.example`); README.md has a mock-fleet run command.

Playwright e2e (`npm run e2e` in `web/`) starts the binary at `MANAGER_BIN`, or
`../target/release/lodeline-manager` when it is unset. With `CARGO_TARGET_DIR` set, pass
`MANAGER_BIN` explicitly. Each run gets its own triage database in a temp dir, or
`E2E_TRIAGE_DB_PATH`.

The parity recorder (`npm run parity` in `web/`) compares the binary's HTTP responses with
goldens, most recorded from the Go console it replaced. See
[`web/tests/parity/README.md`](web/tests/parity/README.md). The `e2e and parity` job in
`manager.yml` runs both suites against a release binary with the SPA embedded.

To drive the console in a browser and capture evidence, use the verify skill in
[`.claude/skills/verify/`](.claude/skills/verify/SKILL.md).

`src/server.rs` holds the route table, which must match `ROUTES` in
`web/tests/parity/cases.ts` (a unit test checks it). The console does not have to match Go.
The goldens are a regression check: when a change intentionally differs from a Go golden,
record that golden from the Rust build, leave every other golden as it is, and list the
difference in the PR. The parity README says how.

`src/auth.rs` signs and checks the session token, `src/auth/oidc.rs` is the OIDC login, and
`src/api/auth.rs` and `src/api/ratelimit.rs` are the auth routes and the login limiter. The
limiter keys on the connection's peer and reads `X-Forwarded-For` only from `TRUSTED_PROXIES`
(README.md, "Behind a reverse proxy"). Sessions are stateless: logout clears the cookie and does
not revoke the token. Two things must stay compatible with the Go console: a session token it
signed must keep verifying under the same `JWT_SECRET`, and an OIDC user's identity, `oidc:`
plus the SHA-256 of the JSON pair `[issuer, subject]`, must not change, because triage rows
record it. `src/auth/tests.rs` and `src/auth/oidc/tests.rs` check both.

`src/fleet/` reads the server's API. `src/fleet/wire.rs` holds the bodies in the shape the SPA
gets, and `src/fleet/tests.rs` checks them against a `lodeline-server` run in process and its
`lodeline-fleet-api` types, so a change to a server route or that crate can fail `cargo test`
here. The mock fleet is `testdata/mock-fleet.json` (see `testdata/README.md`).

`src/triage.rs` owns the console's SQLite file. It must stay readable by, and sortable with, the
Go build's: keep the schema text, the pragmas and the fixed-width timestamp layout as they are.
Its tests open the Go-written `testdata/triage.sqlite` through a copy.

`docs/specs/` holds the design specs written for the Go console. They record the design
decisions, and the file paths they name are the Go layout. Comments that say "as in Go" give
the reason for a behavior that keeps the Go console's answer.
