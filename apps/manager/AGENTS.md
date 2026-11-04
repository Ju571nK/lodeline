# lodeline-manager

`lodeline-manager` is the fleet web console: a Rust server with a React SPA in `web/`. It is a
read-only consumer of `lodeline-server`'s fleet read API, documented in
[`docs/specs/fleet-api/contract.md`](../../docs/specs/fleet-api/contract.md). It writes only its
own triage notes. Lodeline measures and does not block, and the console keeps that framing in
its UI text and docs.

This folder is its own Cargo workspace. The root workspace does not build it,
`.github/workflows/manager.yml` tests it, and root `ci.yml` ignores `apps/**`.

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
cargo +1.88 check --locked   # MSRV
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
`MANAGER_BIN` explicitly.

The parity recorder (`npm run parity` in `web/`) compares the binary's HTTP responses with goldens
recorded from the Go implementation. See [`web/tests/parity/README.md`](web/tests/parity/README.md).

The port is in progress. `src/server.rs` holds the route table, which must match `ROUTES` in
`web/tests/parity/cases.ts` (a unit test checks it). Routes whose handlers are not ported yet
answer 501 after their method and session checks. Each ported behavior must match the Go
goldens; an intended difference needs an `allowlist.json` entry with its reason. Never record
goldens from the Rust binary.

`src/fleet/` reads the server's API. `src/fleet/wire.rs` holds the bodies in the shape the SPA
gets, and `src/fleet/tests.rs` checks them against a `lodeline-server` run in process and its
`lodeline-fleet-api` types, so a change to a server route or that crate can fail `cargo test`
here. The mock fleet is `testdata/mock-fleet.json` (see `testdata/README.md`).

`src/triage.rs` owns the console's SQLite file. It must stay readable by, and sortable with, the
Go build's: keep the schema text, the pragmas and the fixed-width timestamp layout as they are.
Its tests open the Go-written `testdata/triage.sqlite` through a copy.

Until the port lands, the imported specs in `docs/specs/` and some comments still describe the
Go implementation, and the Playwright e2e suite does not pass yet.
