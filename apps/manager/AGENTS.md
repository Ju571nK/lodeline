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

Playwright e2e (`npm run e2e` in `web/`) starts the binary at `MANAGER_BIN`, or
`../target/release/lodeline-manager` when it is unset.

The parity recorder (`npm run parity` in `web/`) compares the binary's HTTP responses with goldens
recorded from the Go implementation. See [`web/tests/parity/README.md`](web/tests/parity/README.md).

Until the Rust port lands, the imported specs in `docs/specs/` and some comments still describe
the Go implementation, and the Playwright e2e suite does not run yet because it needs the Rust
binary.
