# Lodeline SELinux policy (#69)

Confines the three de-rooted lodeline daemons (#10) into dedicated SELinux domains
on RHEL-family systems (Rocky/RHEL/Fedora) instead of leaving them in
`unconfined_service_t`:

| daemon             | domain              | binary type              |
|--------------------|---------------------|--------------------------|
| `lodeline` (agent) | `lodeline_agent_t`  | `lodeline_agent_exec_t`  |
| `lodeline-sender`  | `lodeline_sender_t` | `lodeline_sender_exec_t` |
| `lodeline-server`  | `lodeline_server_t` | `lodeline_server_exec_t` |

State/log/runtime get dedicated file types (`lodeline_var_lib_t`, `lodeline_var_log_t`,
`lodeline_conf_t`, `lodeline_*_var_lib_t`, …). The agent can read any file (it does
file-integrity monitoring by design) but is otherwise tightly confined; the
sender/server only touch their own state, the agent's event log/socket, and the
network they need.

## Why `init_nnp_daemon_domain`

The units keep systemd's `NoNewPrivileges=yes` plus sandboxing
(`ProtectSystem=strict`, `ProtectKernelModules=yes`, …). Under `NoNewPrivileges`
the kernel blocks the exec-time SELinux domain transition unless the policy
grants `process2:nnp_transition` — otherwise it falls back to a *bounded*
transition and is denied. `init_nnp_daemon_domain(...)` grants exactly that, so
the daemons get **both** the systemd hardening **and** SELinux confinement with
no unit drop-in.

## Build + install (Rocky/RHEL 9)

```sh
sudo dnf install -y selinux-policy-devel   # provides the devel Makefile
make -f /usr/share/selinux/devel/Makefile lodeline.pp
sudo semodule -i lodeline.pp
sudo restorecon -Rv /usr/bin/lodeline* /var/lib/lodeline* /var/log/lodeline* /etc/lodeline
sudo systemctl restart lodeline lodeline-server lodeline-sender   # whichever are installed
```

Verify confinement + zero denials:

```sh
ps -eZ | grep lodeline          # → lodeline_agent_t / lodeline_sender_t / lodeline_server_t
sudo ausearch -m avc -ts recent | grep lodeline   # → nothing
```

Remove: `sudo semodule -r lodeline`.

Verified enforcing-clean on Rocky Linux 9.7 (aarch64) with all three daemons
running (0 AVC denials, even with `dontaudit` disabled).

> The `.deb` path is unaffected — Debian/Ubuntu use AppArmor, not SELinux. An
> AppArmor profile would be a sibling follow-up.
