# OS packages

Sigil ships five `.deb` / `.rpm` packages — one per binary crate. They install
the binary, optional systemd unit, and example config to standard FHS paths.

## What's in each package

| Package | Binary | Systemd unit | Example config |
| --- | --- | --- | --- |
| `sigil` | `/usr/bin/sigil` | `sigil.service` | `/etc/sigil/policy.yaml.example` |
| `sigil-sender` | `/usr/bin/sigil-sender` | `sigil-sender.service` | `/etc/sigil/sender.yaml.example` |
| `sigil-server` | `/usr/bin/sigil-server` | `sigil-server.service` | `/etc/sigil/server.yaml.example` |
| `sigil-signer` | `/usr/bin/sigil-sign` | — | — |
| `sigil-proxy` | `/usr/bin/sigil-proxy` | `sigil-proxy.service` | `/etc/sigil/proxy.yaml.example` |

All systemd units are installed **disabled**. Nothing starts on install — the
operator decides.

`sigil`, `sigil-sender` and `sigil-server` share the `sigil` user and group, so
each ships the same sysusers (and, for `sigil` and `sigil-sender`, tmpfiles)
entries under its own file name: `sigil.conf`, `sigil-sender.conf`,
`sigil-server.conf` in `/usr/lib/sysusers.d/` and `/usr/lib/tmpfiles.d/`. dpkg
refuses two packages owning one path, so a shared name would block installing
them on the same host (#252).

`sigil-proxy` runs as its own `sigil-proxy` user and group (its own sysusers file),
ships no live `/etc/sigil/proxy.yaml` (only the `.example`), its
post-install does `daemon-reload` only (no enable, no start, no SELinux module),
and it uses its own `StateDirectory=sigil-proxy` (`/var/lib/sigil-proxy`), never
shared with another daemon. Copy the example, create the referenced certificate,
key and secret files (private files owned by `sigil-proxy`, mode 0600), run
`sigil-proxy check-config --config /etc/sigil/proxy.yaml`, then
`systemctl enable --now sigil-proxy`. The SELinux domain for the proxy is
deferred to hardware verification; until then it runs unconfined.

## Building

Pure-Rust packagers, so this runs on macOS or Linux:

```sh
cargo install cargo-deb cargo-generate-rpm     # one-time
packaging/build.sh                              # build all 5 packages, both formats
packaging/build.sh sender                       # only sigil-sender, both formats
packaging/build.sh signer rpm                   # only sigil-signer .rpm
packaging/build.sh proxy                        # only sigil-proxy, both formats
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
and [`packaging/debian-server/`](debian-server/), and [`packaging/debian-proxy/`](debian-proxy/). `sigil-signer` has no skeleton
dir — operator CLI, no systemd integration.

## Installing

The filenames embed the version and host arch — adjust to match what
`packaging/build.sh` printed (e.g. `sigil-sender-0.1.0-1.x86_64.rpm`,
`sigil-sender_0.1.0-1_amd64.deb`):

```sh
# RHEL / Rocky / Fedora
sudo dnf install ./target/generate-rpm/sigil-sender-*.rpm

# Debian / Ubuntu
sudo apt install ./target/debian/sigil-sender_*.deb
```

Then for any of the three daemons, drop a config in place and start it. Agent first (defaults work without a config), then sender / server which need TLS materials:

```sh
# agent
sudo cp /etc/sigil/policy.yaml.example /etc/sigil/policy.yaml   # optional — defaults apply if absent
sudo systemctl enable --now sigil
journalctl -u sigil -f

# sender
sudo cp /etc/sigil/sender.yaml.example /etc/sigil/sender.yaml
sudo $EDITOR /etc/sigil/sender.yaml
sudo systemctl enable --now sigil-sender
journalctl -u sigil-sender -f

# server
sudo cp /etc/sigil/server.yaml.example /etc/sigil/server.yaml
sudo $EDITOR /etc/sigil/server.yaml
sudo systemctl enable --now sigil-server
journalctl -u sigil-server -f
```

`sigil-signer` is a one-shot operator CLI — no service to start:

```sh
# Keypair goes wherever you want — the signer package doesn't create /etc/sigil/.
sigil-sign keygen --id ops-2026 --out ./signing-key.json
sigil-sign sign \
    --in policy.yaml --key ./signing-key.json \
    --policy-version 1 --valid-until 2026-06-15T00:00:00Z \
    --out signed-policy.json
sigil-sign verify \
    --keystore /etc/sigil/policy-signing-pubkeys.pem \
    --in signed-policy.json
```

## Uninstalling

```sh
sudo dnf remove sigil-sender         # or: sudo apt remove sigil-sender
sudo dnf remove sigil-server         # etc.
sudo dnf remove sigil-signer
sudo dnf remove sigil
```

Daemon package scripts stop & disable the unit on removal. State under
`/var/lib/sigil` (agent, sender) and `/var/lib/sigil-server` (server, events
also land here) plus logs under `/var/log/sigil` (agent events) are left in
place — remove them by hand if you want a clean slate.
