# OS packages

Lodeline ships five `.deb` / `.rpm` packages — one per binary crate. They install
the binary, optional systemd unit, and example config to standard FHS paths.

## What's in each package

| Package | Binary | Systemd unit | Example config |
| --- | --- | --- | --- |
| `lodeline` | `/usr/bin/lodeline` | `lodeline.service` | `/etc/lodeline/policy.yaml.example` |
| `lodeline-sender` | `/usr/bin/lodeline-sender` | `lodeline-sender.service` | `/etc/lodeline/sender.yaml.example` |
| `lodeline-server` | `/usr/bin/lodeline-server` | `lodeline-server.service` | `/etc/lodeline/server.yaml.example` |
| `lodeline-signer` | `/usr/bin/lodeline-sign` | — | — |
| `lodeline-proxy` | `/usr/bin/lodeline-proxy` | `lodeline-proxy.service` | `/etc/lodeline/proxy.yaml.example` |

All systemd units are installed **disabled**. Nothing starts on install — the
operator decides.

`lodeline`, `lodeline-sender` and `lodeline-server` share the `lodeline` user and group, so
each ships the same sysusers (and, for `lodeline` and `lodeline-sender`, tmpfiles)
entries under its own file name: `lodeline.conf`, `lodeline-sender.conf`,
`lodeline-server.conf` in `/usr/lib/sysusers.d/` and `/usr/lib/tmpfiles.d/`. dpkg
refuses two packages owning one path, so a shared name would block installing
them on the same host (#252). The sources under `packaging/sysusers.d/` and
`packaging/tmpfiles.d/` carry the same names because cargo-deb names its
generated postinst calls after the source file; keep the copies identical (CI
compares them).

`lodeline-proxy` runs as its own `lodeline-proxy` user and group (its own sysusers file),
ships no live `/etc/lodeline/proxy.yaml` (only the `.example`), its
post-install does `daemon-reload` only (no enable, no start, no SELinux module),
and it uses its own `StateDirectory=lodeline-proxy` (`/var/lib/lodeline-proxy`), never
shared with another daemon. Copy the example, create the referenced certificate,
key and secret files (private files owned by `lodeline-proxy`, mode 0600), run
`lodeline-proxy check-config --config /etc/lodeline/proxy.yaml`, then
`systemctl enable --now lodeline-proxy`. The SELinux domain for the proxy is
deferred to hardware verification; until then it runs unconfined.

Across a reboot the proxy ages spool rows by wall clock, so it orders itself after
`time-sync.target`. That target only waits when a wait service is enabled.
With chrony, enable `chrony-wait.service`: it gives up after 3 minutes, so a
host that cannot reach a time source still starts the proxy. With
systemd-timesyncd, `systemd-time-wait-sync.service` waits with no timeout, so
the proxy never starts until the clock syncs; do not enable it on hosts that
may run without a time source. Without a wait service, the proxy can start
before the first sync, and that clock step can expire events of an earlier boot into
quarantine.

## Building

Pure-Rust packagers, so this runs on macOS or Linux:

```sh
cargo install cargo-deb cargo-generate-rpm     # one-time
packaging/build.sh                              # build all 5 packages, both formats
packaging/build.sh sender                       # only lodeline-sender, both formats
packaging/build.sh signer rpm                   # only lodeline-signer .rpm
packaging/build.sh proxy                        # only lodeline-proxy, both formats
packaging/build.sh deb                          # all 5 packages, .deb only
```

Args (any order, both optional):

| Arg | Values | Default |
| --- | --- | --- |
| `<what>` | `agent`, `sender`, `server`, `signer`, `proxy`, `all` | `all` |
| `<format>` | `deb`, `rpm` | both formats |

**Build a release package on Linux** (or cross-compile) — the packagers just
bundle whatever is at `target/release/<bin>`, so a package built on macOS
contains a macOS binary. CI builds and install-tests all 5 `.rpm`s on the
`rocky9` job (`rpm -qpl`, `rpm -i`, `<bin> --help`, `rpm -e`); the `debian12`
job builds and install-tests the `.deb`s the same way.

The metadata lives in `[package.metadata.deb]` / `[package.metadata.generate-rpm]`
in each crate's `Cargo.toml`; the deb maintainer-script skeletons are in
[`packaging/debian/`](debian/) (agent), [`packaging/debian-sender/`](debian-sender/),
and [`packaging/debian-server/`](debian-server/), and [`packaging/debian-proxy/`](debian-proxy/). `lodeline-signer` has no skeleton
dir — operator CLI, no systemd integration.

## Installing

The filenames embed the version and host arch — adjust to match what
`packaging/build.sh` printed (e.g. `lodeline-sender-0.1.0-1.x86_64.rpm`,
`lodeline-sender_0.1.0-1_amd64.deb`):

```sh
# RHEL / Rocky / Fedora
sudo dnf install ./target/generate-rpm/lodeline-sender-*.rpm

# Debian / Ubuntu
sudo apt install ./target/debian/lodeline-sender_*.deb
```

Then for any of the three daemons, drop a config in place and start it. Agent first (defaults work without a config), then sender / server which need TLS materials:

```sh
# agent
sudo cp /etc/lodeline/policy.yaml.example /etc/lodeline/policy.yaml   # optional — defaults apply if absent
sudo systemctl enable --now lodeline
journalctl -u lodeline -f
```

A signed policy or rule-pack bundle does not write `/etc/lodeline`, which the agent's
unit keeps read-only. It lands in `/var/lib/lodeline/applied/`, and each file there
replaces the content of its namesake in `/etc/lodeline`, so a hand edit of that file has
no effect while the applied one exists. `lodeline show paths` prints the file in force.
To go back to the local file, delete the applied one and run `sudo lodeline reload`.
After that, `lodeline status` still reports the signed version and its expiry while the
local file runs, and only a higher version lands. If `/etc/lodeline` has no
`policy.yaml`, deleting the applied one keeps the previous policy with a warning in the
log until a restart, which loads the defaults. A root agent with `--state-db` elsewhere
and no `--policy` still applies into `/var/lib/lodeline/applied/`, away from that state
database. A host that an older agent applied into keeps loading that file from
`/etc/lodeline` until the next apply.

```sh
# sender
sudo cp /etc/lodeline/sender.yaml.example /etc/lodeline/sender.yaml
sudo $EDITOR /etc/lodeline/sender.yaml
sudo systemctl enable --now lodeline-sender
journalctl -u lodeline-sender -f

# server
sudo cp /etc/lodeline/server.yaml.example /etc/lodeline/server.yaml
sudo $EDITOR /etc/lodeline/server.yaml
sudo systemctl enable --now lodeline-server
journalctl -u lodeline-server -f
```

`lodeline-signer` is a one-shot operator CLI — no service to start:

```sh
# Keypair goes wherever you want — the signer package doesn't create /etc/lodeline/.
lodeline-sign keygen --id ops-2026 --out ./signing-key.json
lodeline-sign sign \
    --in policy.yaml --key ./signing-key.json \
    --policy-version 1 --valid-until 2026-06-15T00:00:00Z \
    --out signed-policy.json
lodeline-sign verify \
    --keystore /etc/lodeline/policy-signing-pubkeys.pem \
    --in signed-policy.json
```

## Uninstalling

```sh
sudo dnf remove lodeline-sender         # or: sudo apt remove lodeline-sender
sudo dnf remove lodeline-server         # etc.
sudo dnf remove lodeline-signer
sudo dnf remove lodeline
```

Daemon package scripts stop & disable the unit on removal. State under
`/var/lib/lodeline` (agent, sender) and `/var/lib/lodeline-server` (server, events
also land here) plus logs under `/var/log/lodeline` (agent events) are left in
place — remove them by hand if you want a clean slate.
