# Migrate from Sigil to Lodeline

Stub. The docs pass writes this guide. These are the facts the code relies on.

## Packages

- `.deb`: `lodeline*` Conflicts, Replaces and Provides `sigil*`.
- `.rpm`: `lodeline*` Obsoletes and Provides `sigil*`.
- Upgrade every Sigil package on the host together. `/etc/sigil` moves only once
  no old binary is left. Rerun `/usr/libexec/<package>/migrate-from-sigil
  <agent|sender|server|proxy>` to finish a staged upgrade.

## What post-install moves

| Old | New | Package |
|---|---|---|
| `/etc/sigil` | `/etc/lodeline` | any, once no old binary is left |
| `/etc/sigil-server` | `/etc/lodeline-server` | `lodeline-server` |
| `/var/lib/sigil`, `/var/log/sigil` | `/var/lib/lodeline`, `/var/log/lodeline` | `lodeline` |
| `/var/lib/sigil-sender`, `/var/log/sigil-sender` | `lodeline-sender` paths | `lodeline-sender` |
| `/var/lib/sigil-server`, `/var/log/sigil-server` | `lodeline-server` paths | `lodeline-server` |
| `/var/lib/sigil-proxy`, `/var/log/sigil-proxy` | `lodeline-proxy` paths | `lodeline-proxy` |

Nothing is overwritten or deleted. If the new path already has content, both stay
and the script says so. Files owned by the `sigil` user and group, or `sigil-proxy`,
move to their `lodeline` counterparts. The old accounts stay.

## What an operator must do

- Enable the new units. Packages never enable a service, and the old unit's enabled
  state does not carry over: `systemctl enable --now lodeline`, and likewise for
  `lodeline-sender`, `lodeline-server` and `lodeline-proxy`.
- Edit config files that name old absolute paths, such as `/etc/sigil/client.crt`
  in `sender.yaml`. The script lists them and does not edit them.
- Rename every `SIGIL_*` env var to `LODELINE_*`. There is no fallback.
- Run `lodeline-hook install --agent <agent> --write` for each agent, repeating any
  `--enforce` flags. It replaces old `sigil-hook` entries. Without `--enforce` an
  enforcing hook comes back as observe-only.
- Re-register MCP clients: `sigil-check` becomes `lodeline-check`, `sigil-fleet`
  becomes `lodeline-fleet`, and the command becomes `lodeline-mcp`.
- Move per-user paths by hand: `~/.config/sigil`, `~/.local/state/sigil`, and on
  Windows `ProgramData\Sigil`. No package owns them.
- Update `x-sigil-requested-by` to `x-lodeline-requested-by` in management API
  clients. `x-sigil-*` headers are no longer stripped by the proxy.

## Unchanged on purpose

Fleet certificates keep working: the proxy SAN is still
`<proxy_id>.proxy.sigil.invalid`. Signed policy, deployments, audit chains and
registry fingerprints verify as before because their hash domains did not change.
