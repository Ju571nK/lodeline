# Migrate from Sigil to Lodeline

Sigil is now Lodeline. This guide lists every step an operator takes to upgrade an
existing install. It names the old paths on purpose.

There is no `sigil` shim and no `SIGIL_*` fallback. The old name collided with
another tool's command, and removing that collision is the point of the rename.
Each section below ends with what happens if you do nothing.

## Summary

| Area | Old | New |
|---|---|---|
| Binaries | `sigil`, `sigil-hook`, `sigil-mcp`, `sigil-sender`, `sigil-server`, `sigil-sign`, `sigil-proxy` | `lodeline`, `lodeline-hook`, `lodeline-mcp`, `lodeline-sender`, `lodeline-server`, `lodeline-sign`, `lodeline-proxy` |
| Packages | `sigil`, `sigil-sender`, `sigil-server`, `sigil-proxy` | `lodeline`, `lodeline-sender`, `lodeline-server`, `lodeline-proxy` |
| Env vars | `SIGIL_*` | `LODELINE_*` |
| Units | `sigil*.service` | `lodeline*.service` |
| MCP servers | `sigil-check`, `sigil-fleet` | `lodeline-check`, `lodeline-fleet` |
| HTTP headers | `x-sigil-*` | `x-lodeline-*` |
| Manager cookies | `sigil_session`, `sigil_oidc_binding` | `lodeline_session`, `lodeline_oidc_binding` |

## 1. Binaries and packages

**Linux packages.** Install the new `.deb` or `.rpm` for each Sigil package on the
host. They replace the old ones.

- `.deb`: each `lodeline*` package declares Conflicts, Replaces and Provides for
  the matching `sigil*` package.
- `.rpm`: each `lodeline*` package declares Obsoletes and Provides for the
  matching `sigil*` package.

Upgrade every Sigil package on the host in the same run. The shared `/etc/sigil`
directory moves only after no old binary is left, so a partial upgrade leaves it
in place and prints a notice.

**Script installs and Windows `.zip`.** Run the new installer. It writes the new
binary names and does not remove the old ones. Delete the old `sigil*` binaries
by hand, including `%LOCALAPPDATA%\Programs\sigil` on Windows. The installer's
`SIGIL_INSTALL_DIR` is now `LODELINE_INSTALL_DIR`, with the same defaults under
the new name.

**If you do nothing.** Old script-installed binaries keep running as they were,
and nothing updates them. Old packages stay until you replace them.

## 2. Config, state and log paths

The package post-install script runs `migrate-from-sigil` for you. It moves each
old directory to the new path only when the new path has no real content, and it
never deletes data.

| Old | New | Moved by package |
|---|---|---|
| `/etc/sigil` | `/etc/lodeline` | any, once no old binary is left |
| `/etc/sigil-server` | `/etc/lodeline-server` | `lodeline-server` |
| `/var/lib/sigil`, `/var/log/sigil` | `/var/lib/lodeline`, `/var/log/lodeline` | `lodeline` |
| `/var/lib/sigil-sender`, `/var/log/sigil-sender` | `/var/lib/lodeline-sender`, `/var/log/lodeline-sender` | `lodeline-sender` |
| `/var/lib/sigil-server`, `/var/log/sigil-server` | `/var/lib/lodeline-server`, `/var/log/lodeline-server` | `lodeline-server` |
| `/var/lib/sigil-proxy`, `/var/log/sigil-proxy` | `/var/lib/lodeline-proxy`, `/var/log/lodeline-proxy` | `lodeline-proxy` |

Rules for each directory:

- The new path is absent: the old directory is renamed onto it.
- The new path is empty or holds only packaged `*.example` files: the old entries
  move in and the example files stay.
- The new path has real content: both stay where they are, and the script says
  so. Merge them by hand.

Files owned by the `sigil` user and group, or by `sigil-proxy`, move to the
matching `lodeline` account. The old accounts stay on the host.

If the post-install run was staged or interrupted, finish it by hand. Pick the
component that matches the package:

```sh
/usr/libexec/lodeline/migrate-from-sigil agent
/usr/libexec/lodeline-sender/migrate-from-sigil sender
/usr/libexec/lodeline-server/migrate-from-sigil server
/usr/libexec/lodeline-proxy/migrate-from-sigil proxy
```

The script is safe to run again.

**Config contents.** The script does not edit files. A config that names an old
absolute path, such as `/etc/sigil/client.crt` in `sender.yaml`, keeps pointing at
the old path. The script lists each such file. Edit them.

**Per-user paths.** No package owns these, so move them yourself:

| Platform | Old | New |
|---|---|---|
| Linux, macOS | `~/.config/sigil` | `~/.config/lodeline` |
| Linux, macOS | `~/.local/state/sigil` | `~/.local/state/lodeline` |
| Windows | `%LOCALAPPDATA%\Sigil` | `%LOCALAPPDATA%\Lodeline` |
| Windows | `%ProgramData%\Sigil` | `%ProgramData%\Lodeline` |

The control socket moves from `/var/run/sigil/control.sock` to
`/var/run/lodeline/control.sock`, and the Windows named pipe from
`\\.\pipe\sigil-control` to `\\.\pipe\lodeline-control`. Both are created at
start, so there is nothing to move.

**If you do nothing.** On a Linux package upgrade the script handles the system
paths, and only the config edits and per-user paths above remain. On macOS,
Windows and script installs nothing moves. The new binaries start with built-in
defaults, with no policy, keys or history, while your old files sit unused.

## 3. Environment variables

Rename every `SIGIL_*` variable to `LODELINE_*`. Only the prefix changes. Update
shell profiles, unit drop-ins, CI secrets and container definitions.

| Variable | Used by |
|---|---|
| `LODELINE_PROFILE`, `LODELINE_VERSION`, `LODELINE_INSTALL_DIR` | installers |
| `LODELINE_BASE_URL`, `LODELINE_BASE_TOKEN` | installers, fetching from a server instead of GitHub |
| `LODELINE_AGENT_CONTROL_SOCKET` | agent and CLI |
| `LODELINE_HOOK_SOCKET`, `LODELINE_HOOK_DECIDE_SOCKET` | `lodeline-hook` |
| `LODELINE_HOST_ID` | agent host identity |
| `LODELINE_LOG` | log filter |
| `LODELINE_SERVER_BASE_URL`, `LODELINE_SERVER_READ_TOKEN` | `lodeline-mcp` fleet mode |
| `LODELINE_CA_CERT`, `LODELINE_CLIENT_CERT`, `LODELINE_CLIENT_KEY` | `lodeline-mcp` direct mTLS |
| `LODELINE_BUILD_SIGNING_KEY`, `LODELINE_BUILD_PUBKEYS`, `LODELINE_BUILD_TARGET` | release builds |

Other `LODELINE_*` names are test and demo switches. List every name the code
reads with `git grep -hoE 'LODELINE_[A-Z0-9_]+' | sort -u`.

**If you do nothing.** The old variables are ignored. A fleet-mode `lodeline-mcp`
starts without its server URL and token and falls back to local mode. A sender or
server that took a secret from `SIGIL_*` starts without it.

## 4. systemd units

The new packages ship `lodeline.service`, `lodeline-sender.service`,
`lodeline-server.service` and `lodeline-proxy.service`. They use the matching
`lodeline` user and group, sysusers entries and tmpfiles rules.

Packages never enable or start a service, and the old unit's enabled state does
not carry over. After the upgrade, enable what you ran before:

```sh
systemctl daemon-reload
systemctl enable --now lodeline            # agent
systemctl enable --now lodeline-sender
systemctl enable --now lodeline-server
systemctl enable --now lodeline-proxy
```

Move any unit drop-ins from `/etc/systemd/system/sigil*.service.d/` to
`/etc/systemd/system/lodeline*.service.d/`. On SELinux hosts the policy module is
now `lodeline`, with domains such as `lodeline_agent_t`.

**macOS and Windows.** No package installs a service there, so you wrote it by
hand and you replace it by hand. On macOS, unload the `com.sigil.agent` LaunchDaemon
and remove `/Library/LaunchDaemons/com.sigil.agent.plist`. Then create
`com.lodeline.agent.plist` that runs `lodeline`, as in
[the macOS guide](install-macos-agent.md), and load it. On Windows, remove any
service named `Sigil` and any scheduled task that runs `sigil.exe`, then register
the new binary under the name `Lodeline`.

**If you do nothing.** The old package is gone and its unit with it. No Lodeline
service runs until you enable it, so the host stops reporting posture and
stops receiving policy.

## 5. Hooks

Old hook entries run `sigil-hook`, which an upgrade removes. Re-register them
with the new binary for each agent, repeating any flags you used before:

```sh
lodeline-hook install --agent claude-code --write
lodeline-hook install --agent codex --enforce --write
```

`lodeline-hook install` finds its own old `sigil-hook` entries in the agent's
settings, replaces them, and leaves every other hook alone. It is safe to run
again. `lodeline-hook uninstall` removes both old and new entries. For Grok it
also retires the old `~/.grok/hooks/sigil-hook.json` file.

Install is observe-only unless you pass `--enforce`. An enforcing hook comes back
as observe-only if you leave the flag off, so repeat it.

If the installer added its read-only allowlist to `~/.claude/settings.json`, that
file still holds `Bash(sigil:*)` in `permissions.allow` and `Bash(sigil run:*)`
and `Bash(sigil-hook:*)` in `permissions.deny`. Add the `lodeline` equivalents and
remove the old rules. The installer prints the snippet again when you rerun it.

**If you do nothing.** Each old entry points at a missing command. The agent
reports a hook error or skips the hook, depending on the agent. Observation
and any enforcement stop until you re-register. The scanner still recognises old
`sigil-hook` entries as Lodeline's own, so a half-upgraded host does not flag
itself.

## 6. MCP client config

`lodeline-mcp` registers under new server names. Update each MCP client, such as
Claude Desktop, Claude Code, Codex or Cursor:

| Old | New |
|---|---|
| server `sigil-check` | server `lodeline-check` |
| server `sigil-fleet` | server `lodeline-fleet` |
| command `sigil-mcp` | command `lodeline-mcp` |

Tool names (`my_risk`, `my_guard_detail`, `my_findings`) do not change. Prompts
and saved allow-lists in the client that name `sigil-check` need the same edit.

**If you do nothing.** The client tries to launch `sigil-mcp`, which no longer
exists, and the server shows as failed. The scanner treats the old entry as
Lodeline's own, so it adds no finding for it.

## 7. HTTP headers

The management API reads `x-lodeline-requested-by` instead of
`x-sigil-requested-by`. Update every client and reverse proxy that sets it. The
proxy treats any `x-lodeline-*` request header as its own auth header. It no
longer strips `x-sigil-*`, which now pass through as ordinary headers.

**If you do nothing.** Management calls lose the requester name in the audit
trail. Do not rely on the old header for any auth decision.

## 8. Fleet certificates and signed policy

Certificates keep working. You do not reissue them. The proxy certificate SAN is
still `<proxy_id>.proxy.sigil.invalid`, and the server only accepts that suffix.

Signed policy, deployments, audit chains, registry fingerprints and release
manifests verify as before. Their hash and signature domains and the release key
id (`sigil-build-2026b`) did not change.

Check three things on each fleet host after the move:

- The sender's config points at the new certificate paths under `/etc/lodeline`.
- The server's `client_ca_path` and the manager's CA path resolve under the new
  directories.
- `lodeline-sign verify` still passes on your current policy bundle.

**If you do nothing.** The certificates are fine. A sender that still names
`/etc/sigil/...` fails to find them once the directory has moved.

## 9. The manager

`lodeline-manager` renames its env vars, cookies and repository.

| Old | New |
|---|---|
| `SIGIL_SERVER_BASE_URL` | `LODELINE_SERVER_BASE_URL` |
| `SIGIL_SERVER_READ_TOKEN` | `LODELINE_SERVER_READ_TOKEN` |
| `SIGIL_SERVER_CA_PATH` | `LODELINE_SERVER_CA_PATH` |
| `SIGIL_SERVER_CLIENT_CERT_PATH` | `LODELINE_SERVER_CLIENT_CERT_PATH` |
| `SIGIL_SERVER_CLIENT_KEY_PATH` | `LODELINE_SERVER_CLIENT_KEY_PATH` |
| `SIGIL_INSECURE_COOKIE` | `LODELINE_INSECURE_COOKIE` |
| cookie `sigil_session` | cookie `lodeline_session` |
| cookie `sigil_oidc_binding` | cookie `lodeline_oidc_binding` |
| `/etc/sigil-manager/` | `/etc/lodeline-manager/` |

The read token on the server side is `LODELINE_SERVER_READ_TOKEN` too. Set the
same value in both places.

**If you do nothing.** The manager cannot find its server URL or token and
stops at startup with a config error about the missing variables, unless
`MOCK_FLEET=1`. After you set the new variables, every
user signs in once more because the old session cookie is not read. An OIDC
sign-in that began before the upgrade fails once and works on retry.

## What stays the same

Hash and signature domains, the release key id, the proxy SAN suffix and the
`sigilworks.net` domain keep their old bytes or names on purpose, because
changing them would break verification of existing bundles and stored data.

Everything else keeps its meaning: the policy format, the event schema, the
exit codes and the "measures, does not block by default" behaviour.

## Check the result

```sh
lodeline --version
lodeline scan
lodeline doctor
systemctl status lodeline lodeline-sender lodeline-server lodeline-proxy
```

`lodeline scan` should print a `Lodeline scan` summary. If it reports no policy or
no history on a host that had both, the move in section 2 did not run. Run
`migrate-from-sigil` again and read what it prints.
