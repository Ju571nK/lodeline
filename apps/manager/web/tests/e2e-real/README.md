# Real-stack browser run

`npm run e2e:real` drives the console's proxy pages in Chromium against a real `lodeline-server`
instead of the mock fleet that `npm run e2e` uses. It exists because the mock specs assert
values that the mock fixtures define, so a change in what the server sends is invisible to them.

Run it from `apps/manager/web` after `npm run build` and a release build of the console:

```sh
npm run build
(cd .. && LODELINE_MANAGER_REQUIRE_DIST=1 cargo build --release)
npm run e2e:real
```

`MANAGER_BIN` names another console binary. The first run also compiles the console's test
build, which can take minutes.

## What it starts

`playwright.real.config.ts` starts two processes, in order, on `REAL_STACK_PORT` (default 18381)
and the port after it:

1. The ignored Rust test `serve_seeded_proxies_until_killed` in
   `apps/manager/src/fleet/tests/proxies.rs`. It serves the same seed as the contract test
   (three proxies in the read scope, the invocations and the inventory) from an in-process
   `lodeline-server` until it is stopped. `cargo test` skips it, so nothing but this run keeps it
   working; run it here after a change to that file.
2. The console binary, reading that server over plain HTTP with the read token of the contract
   test. The enrollment route stays off, because its settings are all or nothing.

The specs assert on values the seed defines. The seed's last contact is a few seconds old at the
server start and the server reads a proxy as disconnected after about 90 seconds, so the files
are numbered and the list spec, which reads connection state, runs first.

## What it does not cover

- mTLS. The in-process server takes its peer identity from a test layer, so the read
  certificate and the certificate checks are not exercised.
- A real proxy. The seed writes the registry, the status reports and the events directly; no
  proxy sends them.
- A server without a `proxy:` section. The launcher starts one variant only.
- The alerts, fleet and device pages. They run on the mock fleet and are not covered here.
