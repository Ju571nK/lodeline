# lodeline-manager

Read-only web console for a `lodeline-server` fleet. This folder holds the Rust port of
[lodeline-manager](https://github.com/Ju571nK/lodeline-manager). It is a scaffold: the binary
prints a version line and does not serve anything yet.

This is its own Cargo workspace. The root workspace does not build it, and
`.github/workflows/manager.yml` tests it.

```sh
cd apps/manager
cargo test
cargo +1.88 check --locked   # MSRV
```

`build.rs` embeds `web/dist` when it exists and a placeholder page otherwise. Set
`LODELINE_MANAGER_REQUIRE_DIST=1` to make a missing `web/dist` a build error.
