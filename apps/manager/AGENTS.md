# lodeline-manager

`lodeline-manager` is the fleet web console: a Rust server with a React SPA in `web/`. It is a
consumer of `lodeline-server`'s fleet read API, documented in
[`docs/specs/fleet-api/contract.md`](../../docs/specs/fleet-api/contract.md). It writes its own
triage notes and, for host enrollment files only, asks the server to mint a single-use
enrollment token through a management credential that is separate from the read token
(`POST /v1/enroll-tokens`, [`docs/install-server.md`](../../docs/install-server.md) section 3.6).
The read token never gains write authority, the console never holds the policy signing key, a
host private key or the enrollment CA key, and it keeps no enrollment file and no token.
Lodeline measures and does not block, and the console keeps that framing in its UI text and
docs.

It also reads the release files in the server's `artifacts_dir`: `GET /v1/artifacts` and
`GET /v1/artifacts/{filename}` (`crates/lodeline-server/src/routes/artifacts.rs`). The Downloads
page lists them and streams one to a signed-in browser, so the read token never leaves the
console. These are reads too and need no write authority. It does not check the files, and
its text must not say that they are signed or verified.

It also reads the server's Lodeline Proxy status and invocations: `GET /v1/proxies`,
`GET /v1/proxies/{id}`, `GET /v1/proxy-invocations` and `GET /v1/proxy-invocations/{id}`
([ledger-and-query.md L2 to L4](../../docs/specs/lodeline-proxy/contracts/ledger-and-query.md)),
and a proxy's inventory views: `GET /v1/proxies/{id}/inventory-snapshots`, `/drift` and
`/rebaseline-markers` ([registry.md R5 and R7b](../../docs/specs/lodeline-proxy/contracts/registry.md)).
That is the proxy scope M0 of #458: proxy reads only, still read-only against the server. Do not
add a proxy write route or a control that changes a proxy (register, disable, enable, retire,
config). The operator CLI on the server does those. The only management credential the console
holds is the enrollment mint credential (`LODELINE_ENROLL_MINT_*`). It has the scope `enroll`
and cannot touch a proxy.

The enrollment file route (#553) is `src/enroll.rs` (the settings, the file template and the
mint client) and `src/api/enrollment.rs` (`GET /api/v1/enrollment` and
`POST /api/v1/enrollment/files`, the two entries at the end of `ROUTES`). The POST runs an
origin rule before anything else: `Origin` must equal `LODELINE_PUBLIC_ORIGIN`,
`Sec-Fetch-Site`, when sent, must be `same-origin`, and the body must be JSON. The older POST
routes do not have that rule yet. The mint client is its own `reqwest::Client` with its own
certificate, follows no redirect and never retries. Do not log, print or put the token in an
error. The bearer type has no `Display` and a `Debug` that prints a fixed word.

The inventory views carry references, counts and identifiers, never a tool name or definition,
and the console fetches no metadata content: a display permission for it (`proxy.metadata`) is
still an open producer decision. A drift record is an observed change, never an approval. An
incomplete observation is an `inventory_incomplete` audit gap on the proxy detail, not a
snapshot.

An invocation shows an outcome only when its lifecycle is `completed`. A
`completion_without_start` or `integrity_conflict` record is flagged, and its `reported_*`
values are the proxy's uncorroborated claim, never a headline value. `invocationStatus` in
`web/src/lib/proxy.ts` is the one place that decides this; do not decide it in a component.

This folder is its own Cargo workspace. The root workspace does not build it,
`.github/workflows/manager.yml` tests it, root `ci.yml` ignores `apps/**`, and
`.github/workflows/release.yml` ships it. Its version is the root workspace version, and a
release prep bumps the root and `apps/manager/Cargo.toml` and `apps/manager/Cargo.lock`
(`tests/test_release_manifest.py` checks it).

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
here. The proxy bodies are `src/fleet/proxy.rs`, which keeps the server's nulls and absent
fields, and `src/fleet/tests/proxies.rs` checks them against the server's proxy routes run in
process. `src/fleet/tests/artifacts.rs` checks the release file routes against a server run in
process, through the console's own router. The mock fleet is `testdata/mock-fleet.json`,
`testdata/mock-proxies.json`, `testdata/mock-proxy-invocations.json` and
`testdata/mock-proxy-inventory.json` (see `testdata/README.md`), plus the release files in
`src/fleet/mock.rs`.

`src/triage.rs` owns the console's SQLite file. It must stay readable by, and sortable with, the
Go build's: keep the schema text, the pragmas and the fixed-width timestamp layout as they are.
Its tests open the Go-written `testdata/triage.sqlite` through a copy.

`docs/specs/` holds the design specs written for the Go console. They record the design
decisions, and the file paths they name are the Go layout. Comments that say "as in Go" give
the reason for a behavior that keeps the Go console's answer.
