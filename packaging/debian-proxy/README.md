# Debian maintainer-script skeletons (sigil-proxy)

Referenced by `maintainer-scripts` in `[package.metadata.deb]`
(`crates/sigil-proxy/Cargo.toml`). cargo-deb substitutes the `#DEBHELPER#`
token in each with the systemd integration snippet derived from
`[package.metadata.deb.systemd-units]` (daemon-reload on install; stop on
remove; **no** enable/start). The proxy package never loads an SELinux module:
the proxy domain is deferred to hardware verification and runs unconfined.

Keep the literal string `#DEBHELPER#` out of comments in these files.
