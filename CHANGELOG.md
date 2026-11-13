# Changelog

All notable changes to Lodeline are recorded here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the workspace and
`apps/manager` use a single SemVer version across all crates. Full release notes for tagged
releases also appear under [GitHub Releases](https://github.com/Ju571nK/lodeline/releases).

## [Unreleased]

### Changed

- **Agent.** The agent records a write to a watched file only when the bytes differ from the last
  recorded or start-up state. A rewrite with the same bytes, and a mode or owner change that leaves
  the bytes alone, is no longer recorded, so `events_emitted_total`, `events_by_kind` and the
  `show stats` totals are lower than before for the same activity. AI Guard still reassesses on every
  write. A file that is gone or unreadable forgets its baseline, and so does the old path of a rename, so
  recreating that path with the same bytes is recorded. No event or wire format changes.

- The Claude Code assessment reads `allowedHttpHookUrls` from the managed, user and project
  settings files and merges the lists. An `http` hook whose URL no pattern can match, or any
  `http` hook when the list is empty, no longer gives `HookForwardsToolCalls`, because Claude
  Code does not run it. The managed hooks are still reported, and a pattern the Claude Code
  documentation leaves open (whether `*` crosses `/` and `:`, how scheme and port match) keeps
  the hook reported. The user scope also reports a control `claude_code.configured.allowedHttpHookUrls`
  that holds the number of patterns and never a URL. No reason kind or event field is added.
  A project row also reports a user `http` hook that the project's own list admits, because
  Claude Code merges the lists and runs it there. The path and query of a URL match a pattern
  without case.
- The agent keeps a table of link spellings and uses it to name an event path the way the watched path was written, so an event under a link's target can match a target given as the link. The table is empty in this release, so no event path, baseline key or counter changes.

## [0.14.5] - 2026-11-12

**Upgrade order.** Upgrade the server first, then the hosts, and the console last if you want to
enroll hosts from it. A v0.14.5 sender that is set to renew uses `POST /v1/renew`, which a v0.14.4
server already has, so the server needs this release only for the mint route. A v0.14.4 server still
works with a v0.14.5 sender, agent and console. Against a server older than v0.14.4 the renew route
answers 404: a sender that is set to renew logs an error line for each refused attempt, from 60% to
75% of the certificate's validity until it expires (once every six hours for a 30 day certificate),
keeps delivering events, and the host must be enrolled again before its certificate expires. This
release adds no event kind and no reason kind, changes no event on the wire and no fleet API
response (`lodeline-fleet-api` gains a `mint` module, which only the server and the console use). No
package script, unit file, tmpfiles entry or SELinux module changed, so the packaged policy is the
one of v0.14.4. No package or release asset is added or removed, the console is still an archive
with no OS package, and `lodeline-proxy` is still not a release asset.

**Hosts.** A sender renews its certificate only where `sender.yaml` has
`renew_client_cert: true`, which `lodeline-sender enroll` writes from this version. It renews on
Linux and macOS, between 60% and 75% of the certificate's validity. A host enrolled with a v0.14.4
`enroll` does not have the line: add it and restart the sender, or its certificate still ends after
`enroll_cert_days` and the host must be enrolled again (`enroll` run again on such a host keeps the
file and prints what to set). A sender without the line does nothing about certificates, as a
v0.14.4 sender did; if it has a client certificate, a client key and a server CA set, it logs one
`info` line at start saying so, and `lodeline-sender doctor` shows it on its `certificate renewal`
line. A fleet whose certificates you make yourself sees only that line.
Adding the line does not help such a host, because the server renews only certificates its
enrollment CA issued: it joins by enrolling once. If a sender that is set to renew cannot (the
sender account cannot create files in the directory of `client.key` or of `client.crt`, it does not
own `client.key`, the key is not PKCS#8, or the key and the certificate do not match), it logs an
error that says why when it starts, repeats a line at most once an hour, and keeps delivering
events. Renewal is off on Windows.

The agent counts a file change once now, so a host's `events_emitted_total` and the `file_change`
count in `events_by_kind` (also `lodeline show stats` and the `status` line) can look lower than
before the upgrade; the recorded events are the same. When the files change, a host can record new
`file_change` events for Claude Code skills, agents, hooks and managed settings files, which the
default policy now watches. An AI Guard score can go up (a higher score is riskier), not down,
where a subagent below a repository subfolder declares a hook; the two new managed settings
controls change the controls an assessment reports, not its score.

**Server and console.** `POST /v1/enroll-tokens` is off unless `enroll_mint:` is in
`server.yaml`, so an existing `server.yaml` needs no change. A server older than v0.14.5 ignores
the key without a word. A server whose `host_allowlist_path` names a file that does not exist now
logs one warning at start; it starts as before. With the key, the server does not start unless the
other settings in `docs/install-server.md` section 3.6 are in place. `lodeline-server proxy verifier-new` takes
`--scope enroll` and `--caller-cert`, and its stderr advice text changed; the entry it prints and
the stdout bearer did not, and the guide's `sed` command reads only the entry. The console
makes enrollment files only when all eight settings are set (the three `LODELINE_ENROLL_MINT_*`,
the four `LODELINE_ENROLL_FILE_*` and `LODELINE_PUBLIC_ORIGIN`). With none set it behaves as before,
and its Enroll a host page says it cannot
make files yet and names the settings; a partial set stops the console at start. A console that
does not use enrollment sets nothing new. A v0.14.5 console against an older server answers
`enroll_unavailable` for enrollment and reads the fleet as before, and an older console works
against a v0.14.5 server. The console's only write to the server is the mint request, made with its
own credential; it was read-only before.

**Read token.** `docs/install-server.md` ("Read API token", in section 5) now puts the token in a
root-only `EnvironmentFile`. A server whose token is in an `Environment=` drop-in has it readable
by every account on the host through `systemctl show`. Move it to a root-only file as that
section shows and restart the server. Nothing breaks if you do not.

### Added

- The fleet console makes a host's enrollment file (`GET /api/v1/enrollment` and
  `POST /api/v1/enrollment/files`). A signed-in operator asks; the console asks the server for a
  single-use token with its own mint credential (`LODELINE_ENROLL_MINT_TOKEN`,
  `LODELINE_ENROLL_MINT_CERT_PATH`, `LODELINE_ENROLL_MINT_KEY_PATH`), builds the file from its
  settings (`LODELINE_ENROLL_FILE_*`) and answers with the file's bytes. It keeps no token and no
  file. The POST accepts only a request whose `Origin` is `LODELINE_PUBLIC_ORIGIN`, and
  `LODELINE_ENROLL_SUBJECTS` can limit it to some subjects. It is off unless all eight settings
  are set (see "Enroll a host" in `apps/manager/README.md`) (#575, #553).
- The web console has an Enroll a host page (`/enroll`, in the top navigation). It shows what a
  file will hold (the server and enrollment URLs, the CA certificates and the policy keys with
  their SHA-256 fingerprints), makes the file on one click and has the browser save it, and then
  shows the host id, the expiry and the steps on a Linux host installed from the packages. It
  never parses or keeps the file, and its error texts say what to do next, including how to make a
  new file for a host whose `enroll` stopped halfway (#576, #553).
- `POST /v1/enroll-tokens` makes a single-use enrollment token over HTTP, for the fleet console to
  use (`docs/install-server.md` section 3.6). It is off unless `enroll_mint:` is in `server.yaml`,
  and needs a pinned client certificate, a bearer with the new scope `enroll` from its own verifier
  file (`lodeline-server proxy verifier-new --scope enroll --caller-cert <pem>`), and the enrollment
  listener. It refuses a host id that is on the allowlist or has a certificate this server issued,
  or that has a live token, keeps at most `enroll_mint.max_tokens` entries in the token file
  (pruning ones spent or expired more than an hour ago), and writes one signed `token_minted` line
  per token, with the verified key id and the subject the caller reported, to the enrollment audit
  file (#574, #553).
- `lodeline-sender` renews its own client certificate and key before they expire. From the
  validity of the certificate it holds, it renews between 60% and 75% of it, at a point set by
  its host_id. Renewal is on for a host that `enroll` set up, which writes
  `renew_client_cert: true` into `sender.yaml`; a sender without that line does what it did
  before (it touches no file and sends no request) and logs one info line at start that says
  so. It sends a new key's CSR to `POST /v1/renew`, checks the answer
  on the host (key, host_id, chain to the server CA, client-auth purpose, validity), and only
  then replaces `client.key` and `client.crt` through `.next` files, with a directory sync after
  each rename. One repair step runs at start and at every wake and brings any state a crash
  leaves to a matching pair, so a host never loses its pair. The HTTP client used for events and
  policy lives in one handle and is replaced once after a renewal. Refusals (403, 404) and an
  approaching expiry are logged loudly, at most once an hour; after expiry the sender keeps
  running and uses a new pair as soon as it appears on disk, without a restart. A certificate
  directory the sender account cannot write, or a live key that the sender account does not own,
  turns renewal off with one error line; the key and the certificate may sit in two directories,
  and each `.next` file is renamed in its own. A wake whose repair step was not clean sends no
  request and renames nothing; a stored answer that cannot be checked because an input cannot be
  read drops nothing, and one that fails its check is dropped alone, so the same request is sent
  again. A `.next` file that is there and does not parse, empty or for another key included,
  is dropped, so it cannot stop renewal (a bad request file alone, so the key it was made for
  stays); one the sender will not read is named in the error
  line, and a live pair replaced on disk is still loaded in a wake that ended on such an error.
  Renewal reads PKCS#8 keys only: a live `client.key` in another form is logged with its own
  line and the certificate is not renewed until the key is converted or the host enrolls again. A new answer
  must expire later than the certificate in use, as a stored one must. `enroll`
  names the steps for an expired host when it exits 4. Renewal is off on Windows. `lodeline-sender
  doctor` shows only the sender's decision, on a `certificate renewal` line.
  `docs/install-server.md` has a new section 3.5. (#572, #553, #580)
- `lodeline-sender doctor` prints a `certificate renewal` line after the client certificate
  lines. It reads the decision the sender takes at start: `[INFO]` `off` where `sender.yaml` has
  a whole identity and no `renew_client_cert` (the state to expect where you make the
  certificates yourself), `[WARN]` where the line is set and a path setting is missing, `[INFO]` on
  Windows, `[OK]` `on` otherwise. It makes no network call and does not read the key, so it does
  not repeat the ownership and key form checks the sender makes at start. (#581)
- AI Guard reports two more Claude Code controls from the managed settings files:
  `permissions.blockReadsOutsideWorkingDirectories` and
  `permissions.blockWritesOutsideWorkingDirectories`, each when its value is `true`. No score, reason
  kind or event field changes. (#582, #539)
- AI Guard now reads the frontmatter hooks of subagents in `<subfolder>/.claude/agents/` below a
  repository, as it already does for nested skills, under the same folder bounds. Claude Code
  loads such a subagent for a session started in that subfolder, not for one at the root, so the
  assessment can report a hook the root session never runs; changes to these files are noticed at
  the next assessment, not by the watcher. (#593, #539)

### Changed

- `docs/install-server.md` section 3.6 now gives one command that turns the output of
  `proxy verifier-new` into a valid verifier file (the output holds advice lines before the entry),
  and says that a file that does not load stops the server at start. The "Read API token" block
  puts the token in a root-only `EnvironmentFile` instead of `Environment=`, which every account on
  the host can read with `systemctl show`. The console README says where its read certificate
  comes from and that it is not the mint certificate. (#578)
- `lodeline-server` logs one warning at start when `host_allowlist_path` is set and the file does
  not exist. The server starts as before, with no restriction; the line says so and that the
  server reads the file at start only. (#581)
- `docs/install-server.md` section 3 says where the host id for a certificate you make yourself
  comes from (`lodeline show host-id`, `lodeline init-host-id`) and that the id goes into the
  allowlist file first. Section 3.5 names the `doctor` line, and section 3.1 and
  `config/server.example.yaml` say what a configured allowlist path without a file means. (#581)
- `docs/install-macos-agent.md` and `docs/install-windows-agent.md` say that `lodeline show paths`
  prints a path with a wildcard as the pattern, not the files it matches, and name two folders the
  agent creates: `state.mcp-baselines` next to the state database, and on macOS and Linux the
  socket folder under `$TMPDIR` that a non-root agent uses when `XDG_RUNTIME_DIR` is not set. The
  example policy in section 3 of the macOS guide gains the `description` the agent requires. (#590)
- The built-in scheduled task entry (`~/.claude/scheduled-tasks/*/SKILL.md`) now matches a
  `SKILL.md` one folder below the scheduled tasks folder only, so a deeper `SKILL.md` no longer
  records a file change. Operator patterns are unchanged. (#592)

### Fixed

- `lodeline-sender` logs a renewal-file problem found at start once, not twice within seconds. The
  first wake of the renewal loop no longer repeats the line the start just wrote, and the line
  comes again only after an hour. The two messages of `lodeline-sender enroll` that point to
  `lodeline show host-id` say to use `sudo` when `enroll` ran with `sudo` (#577).
- AI Guard now reassesses Claude Code as soon as a skill or subagent file is added or changed in
  `~/.claude/skills/<name>/SKILL.md`, `~/.claude/agents/` or a repository's `.claude/skills` or
  `.claude/agents`, within the limits below. Before, no watch target covered these files, so the agent read them only at the
  next heartbeat or with a change to another watched file. Hosts also record a `file_change` event
  for each edit (hashes and sizes, never file text). Limits: at start the watcher scans no existing file. A folder
  that appears after the agent started, or one that a policy reload adds, is scanned once, and files
  that match no watched pattern are dropped. Events for a file reached through a symbolic link to a
  single skill, or through a folder linked after the agent started, do not match; the next heartbeat
  reads such files. A `skills` folder that is itself a link and exists at start works. On Linux the
  watcher uses one inotify watch per subfolder. When the kernel refuses a watch (the per-user
  inotify limit) the agent goes on, the folder keeps the watches already placed and is tried again
  every few seconds, and this is logged at debug level only; files without a watch are read at the
  next heartbeat. On Linux, when the agent reads the creation of a folder under a watched root, or
  of one moved in, it also reads the files already in it, after visiting at most 512 files and
  folders per new folder (a skill copied in with `cp -r`, a checkout or an unpack); a file written
  during the short time (usually milliseconds, longer for a very large folder) between that read and
  the placing of the watch may still wait for the next heartbeat. Skills below a
  subfolder of a project and skills of `--add-dir` folders are read but not watched.
  The skills and scheduled tasks entries (`skills/*/SKILL.md`, `scheduled-tasks/*/SKILL.md`) name
  one folder per skill, as the assessment reads them: a `SKILL.md` deeper in a skill (inside its
  `node_modules`, say) is not watched. Subagent files and hooks match at any depth.
  A skill folder, a subagent file or a settings file that is itself a symbolic link is read at
  each assessment, but an edit of its target records no file change and starts no assessment;
  the next assessment reads it.
  (#582, #539, #586, #591, #592)
- AI Guard now reassesses as soon as a file changes in the Claude Code user hooks folder
  (`~/.claude/hooks/`) or in a discovered repository's `.claude/hooks/` folder, or in the Claude
  Code managed settings drop-in folder (`managed-settings.d/*.json`). Before, these entries named
  the folder itself, which matches no file in it, so such an edit reached the agent only at the
  next heartbeat or with a change to another watched file. Hosts also record a `file_change` event
  for each such edit (hashes and sizes, never file text). The limits of the skills and agents entry
  above apply to the hooks folders too. The Windows entries use the same patterns and were not
  tried on a device. A policy of your own that lists a folder path still matches only the folder:
  write `folder/*`. The two Codex apps cache folders (`~/.codex/cache/codex_apps_tools/` and
  `codex_apps_server_info/`) are not watch targets, as in every release so far, where their entries
  matched no file. Codex rewrites both folders each time it fetches its tool list, at start and on
  a refresh, also when the bytes are the same, and each write would record a `file_change` event.
  The Codex parser reads both folders at each assessment. A change there is read at the next agent
  start or heartbeat (24 hours), not at once. (#583, #582, #584)
- The agent counted each file change twice in `lodeline show stats`, in the `lodeline status`
  line and in the heartbeat's `events_emitted_total` (and the `file_change` entry of
  `events_by_kind`). The recorded events were never doubled; only the counters were. The numbers
  are right now, so a host's total can look lower after the upgrade. (#589)
- The agent now records a baseline at start, and at a policy reload, for the files that a pattern
  watch entry of a critical target matches, as it already did for a plain path. Before, the first
  change of a skill, subagent, hook script or managed settings file after a start had no hash
  before it, or one left by an earlier run. For each pattern entry the agent visits at most 8192
  files and folders, hashes at most 2048 files and does not follow symbolic links; past a bound,
  one warning is logged and the first event for a file not reached has no `before_hash`, as before.
  Files nearest the pattern's folder are read first, so the bound cuts the deepest files. A file
  reached only through a symbolic link gets no baseline. At a policy reload the baseline of a
  pattern-matched file is read again, as for a plain path, so a change that is being processed in
  that instant can be recorded with the same hash before and after. (#588)
- AI Guard now reassesses Claude Code when a file changes below a watched folder that is itself a
  symbolic link, such as `~/.claude/skills`, `~/.claude/agents` or `~/.claude/hooks` linked to a
  dotfiles folder. Before, the change was recorded as a `file_change` event but started no
  assessment until the next heartbeat. (#591)

## [0.14.4] - 2026-11-11

**Upgrade order.** Upgrade the server first. The agent, the sender and the web console can stay at
v0.14.3 against a v0.14.4 server, and a v0.14.4 server accepts v0.14.3 hosts and consoles. This
release adds no event kind and no reason kind, no event changes on the wire, and no fleet API
response changes. The new routes (`POST /v1/renew` on the main listener, and `POST /v1/enroll` on
the enrollment listener) and the new types in `lodeline-fleet-api` are additions. The web console
changes nothing at this version, so it shows the same against a v0.14.3 server and a v0.14.4 server.
The one order that matters is for a new enrollment: `lodeline-sender enroll` needs a server at
v0.14.4 with `enroll_listener` set, so upgrade the server before you enroll a host with it. The
enrollment listener is off unless `enroll_listener` is set, and an existing `server.yaml` needs no
change for it. No package or release asset is added or removed, and `lodeline-proxy` is still not a
release asset.

**Server operators.** A server with enrollment on whose `host_allowlist_path` is
`/etc/lodeline/host-allowlist.json` needs this, in this order, after the package upgrade: copy the
file to `/var/lib/lodeline-server/` and give it to `lodeline`, run `restorecon -R
/var/lib/lodeline-server` on an SELinux host, set `host_allowlist_path` to the new path in
`server.yaml`, restart `lodeline-server`, check that enrollment is on (the server's journal shows a line that starts with `enroll: enabled`), then delete the old file.
Keep the old file until the restart, because a server that finds no file at its configured path
accepts events from every host that holds a valid certificate. The rpm restarts a running service
during the upgrade, before you have done this. If you do nothing, the server starts, logs an `enroll:` error that names
the path, keeps serving events and the console API, and leaves enrollment off. Renewal is off with
it. A server with `enroll_listener` set in `server.yaml` does not start. Hosts that are already
enrolled keep working. A server without enrollment needs nothing. The server packages now depend on
`openssl`, so the package manager installs it. The packaged unit now sets
`TMPDIR=/var/lib/lodeline-server`, so a server that runs from a copy of the unit file needs that
line. On an rpm host, the package scriptlet builds the SELinux module again and loads it during the
upgrade only when `/usr/share/selinux/devel/Makefile` exists (the `selinux-policy-devel` package).
That module lets the server run `openssl`. On a host that had the module loaded before and has no
Makefile, the old module stays, and the server logs `enroll: cannot run openssl` and leaves
enrollment off until you load the new module as `packaging/selinux/README.md` describes. A host
that never had the module loaded is not affected. The three rpm packages now remove the shared
SELinux module together with the last of them.

**Certificates.** The sender does not call `POST /v1/renew` in this release. A certificate that
enrollment issues still lasts `enroll_cert_days` (30 by default), and the host must be enrolled
again with a new token before it expires, unless a host or its deployment tool (for example
Ansible or Intune) calls the route by hand (`docs/install-server.md` §3.4). Apart from the cases
below, renewal is on whenever enrollment is on and has no setting. At
start the server reads `enrollment-audit.jsonl`. A missing file means no entries, lines that do not
parse are skipped with one warning, and a file that exists but cannot be read turns renewal off with
a `renew:` error, while enrollment keeps working. A server whose `openssl` defaults to SHA-1 for an
EC key, such as the LibreSSL that ships with macOS, issued host certificates that its own listener
refuses. Such a host certificate, issued before the upgrade, never worked and must be issued again
with a new token. A server on OpenSSL 3 sees no change.

**Scripts and logs.** `lodeline-server enroll-token` now accepts only a lowercase, hyphenated
version 4 host_id, and refuses to run as root when the token file's directory belongs to another
account. A script that passes another form of the host_id, or runs it with plain `sudo` where that
directory belongs to `lodeline`, fails: use `sudo -u lodeline`. `lodeline-server` and
`lodeline-sender` now log to stderr, and at `info` when `RUST_LOG` is unset, so a default install
writes more lines to the journal, and a script that reads their logs from stdout must read stderr. The
sender's repeated read-failure warning is limited to one line a minute. The packaged sender now
creates `/var/lib/lodeline-sender` at install or upgrade, owned by `lodeline:lodeline` with mode
0750. As root, `lodeline-sender csr --key-out` gives the key to the owner of the key's directory
only when the path has no link and every parent is a root-owned directory that group and others
cannot write to. `lodeline init-host-id` is new, and a host that already has a host_id is unchanged. The two
changed messages and the install guide need nothing from you.

### Added

- `lodeline-server` renews a host's client certificate. `POST /v1/renew` on the main (mutual
  TLS) listener takes the host's current certificate as the credential and a CSR for a new key,
  and answers with a certificate for the same host_id from the enrollment CA, with the fields
  `/v1/enroll` returns and one signed `issued` audit line with the reason `renewed`. The route
  is on whenever enrollment is on and has no setting. It answers only when the certificate
  verifies against the enrollment CA alone, the host is on the allowlist, and more than half of
  the certificate's validity has passed (409 with `Retry-After` before that). A host renews only
  from the newest certificate the server issued for it, rebuilt at start from the audit file and
  updated by both issuing routes, so a re-enrollment ends renewal for the older chain; one
  presented certificate gets at most three certificates (a lost answer may repeat the same CSR),
  and the first refusal for each is chained into the audit file. A missing audit file starts with
  no entries, lines that do not parse are skipped, and a file that cannot be read turns renewal
  off. `docs/install-server.md` has a new section 3.4 and no longer says that short lifetimes or
  re-enrollment stand in for revocation: it says what removes a host and what keeps working until
  `notAfter`. The sender does not call the route yet. (#569, #553)
- `lodeline-sender enroll <file>` enrolls a host from one enrollment file: a JSON document,
  `"lodeline_enrollment": 1`, that carries the host_id, the single-use token, the two listener
  addresses, the CA roots and the policy keystore. It stores the host_id through `lodeline
  init-host-id`, makes the host's P-256 key, sends one CSR to the enrollment listener while it
  trusts only the CA in the file, checks the certificate it gets back, and writes the client
  key and certificate, the server CA, the keystore and `sender.yaml`. It enables and starts
  nothing. Before it writes anything it prints what the file makes the host trust, with each CA
  and policy key fingerprint. Every refusal that needs no server runs before the host_id claim,
  the key is durable before the token is sent, and a rerun reads the files on disk, so it either
  finishes without a request or says when a new token is needed. A certificate that fails the
  checks is saved as `client.crt.rejected`, and the run exits 5. The exit codes are 0 to 6, and
  the format, the order and the reruns are in `docs/install-server.md` §3.3. As root, a file
  takes the owner of its directory only through the descriptor of a file the run just created,
  and only when that directory is not root-owned; it never changes the owner of an existing
  file or directory, and it refuses a link, a FIFO or a hard link where it writes. The format
  type is in `lodeline-fleet-api`. The packaged sender now creates `/var/lib/lodeline-sender`
  as `lodeline:lodeline` 0750 at install. `enroll` is not supported on Windows yet. `lodeline-sender
  csr --key-out` writes its key through the same routine. Run as root, it gives the key to the
  owner of the key's directory only when that directory's path has no link in it and every
  parent of it is a root-owned directory that group and others cannot write to; otherwise the key stays
  root-owned and `csr` says so. (#564, #553)
- `lodeline init-host-id <uuid>` gives a host its host_id before the agent's first run, so an
  operator can issue the host's enrollment token first. It writes only when the host's
  `state.db` has no host_id, follows the global `--state-db` (pass the same one as
  `lodeline run`), and prints the `state.db` path it used. It exits 0 when the host has that
  host_id, 3 when it already has another one (it names that id and writes nothing), 2 for an id
  that is not a lowercase, hyphenated version 4 UUID, and 1 for any other error. It stores the id
  exactly as given, because the server compares host_ids as exact strings. The hardened build
  keeps the command. The agent's first run now stores its new host_id only when the row is
  empty, so the two never store different ids, and two processes that open a new `state.db` at
  once no longer fail with "database is locked". The deb and rpm install tests now check that
  the agent package installs disabled and stopped. (#557, #553)
- `lodeline-server` can serve `POST /v1/enroll` on a second TLS port, `enroll_listener.bind`,
  for hosts that have no client certificate yet. The port presents the main server certificate,
  asks for no client certificate and serves only that route. Both ports share one token file,
  one audit chain and one allowlist, so a token works once on either port. The port checks a
  token against an in-memory copy of the token file before the mint lock and before any CSR
  parse, and reads the file again only when its size, modification time or inode changes. Only
  the request that redeems a token writes to `enrollment-audit.jsonl`. Every other denial on the
  port is counted and logged with its source address. Per source address the port takes 10
  connections, then 1 every 6 s (IPv6 counts per /64). It serves one request per connection on
  HTTP/1.1 and HTTP/2, holds at most 64 connections, closes each one 15 s after accept unless
  its request is being processed, and takes bodies up to 17 KiB. A host over its limit sees the
  connection closed before the TLS handshake. A request that finds another enrollment running
  gets `503 busy` with `Retry-After: 1`. The server refuses to start when the listener is set
  without mTLS, with `enroll_issuer_fingerprints`, without
  `events_require_cert_host_match: true`, on the `bind` address, or with enrollment off. The
  main port, its answers and its audit lines do not change. The install guide now says to run
  `enroll-token` as the service account, because a root run leaves files the server cannot
  open. (#559, #553)

### Changed

- The documented and example `host_allowlist_path` is now
  `/var/lib/lodeline-server/host-allowlist.json`. The server rewrites that file each time a
  host enrolls, and the packaged unit makes only `/var/lib/lodeline-server` and
  `/var/log/lodeline-server` writable. A server whose allowlist is at
  `/etc/lodeline/host-allowlist.json` must copy the file to `/var/lib/lodeline-server/` (owned by
  `lodeline`, and on SELinux hosts run `restorecon -R /var/lib/lodeline-server`), set
  `host_allowlist_path` to the new path, restart, check that enrollment is on (the server's journal shows a line that starts with `enroll: enabled`), and then delete the
  old file. A server that finds no file at its configured path accepts events from every host that
  holds a valid certificate, so the old file stays until the restart. With enrollment on, the server now checks at
  boot that it can write next to the allowlist. If it cannot, it logs an `enroll:` error, leaves
  enrollment off, and exits when `enroll_listener` is set. With `enroll_listener` set, a server whose allowlist cannot be
  rewritten does not start, so event intake stops until the file is moved. Without
  `enroll_listener`, only enrollment is off. (#567, #566)

### Fixed

- `lodeline-server` no longer logs `CA key does not match CA cert` when the enrollment CA key or
  certificate file cannot be read. It logs `cannot read <path> (<OS error>)`, and keeps `does not
  match` for a real mismatch. Enrollment stays off in both cases. (#568)
- `lodeline-sender csr` says `an existing file is never overwritten` only when the file exists.
  A link in the path, an unwritable directory or another failure now prints its own cause, and
  the `key stays root-owned` hint prints only after the key was written. (#568)
- `docs/install-server.md` now gives `server.key` to `root:lodeline` with mode 0640, as the
  unit's comment says, and the enrollment CA key to `lodeline` with mode 0600. It adds a step
  to take `ca.key` and `int.key` off the server, says the unit runs as `lodeline`, lists every
  case of `enroll` exit 4, and shows the policy keystore layout with a complete enrollment
  file. (#568)
- `docs/install-server.md` closes the places a literal install left to guesswork. Section 5
  has one complete `server.yaml` for a packaged server with mutual TLS and enrollment. The
  guide gives a command to take `ca.key` off the server, removes `int.csr`, `int.crt` and
  `ca.srl` after the intermediate is installed, gives the path of `enrollment-audit.jsonl`, and
  shows how to make the policy keystore from `signing-key.json`, with the key id and the
  validity span. It says that a host added to the allowlist by hand needs a restart, that
  the server rewrites the allowlist as 0600 owned by `lodeline`, that a client presents the
  leaf and then the intermediate, and what to open on a host with neither firewalld nor ufw.
  (#571)
- Enrollment now works on a packaged Linux server. On a host with the packages installed and
  SELinux enforcing, it failed three ways. The SELinux module did not let `lodeline_server_t`
  run `openssl`, which signing uses, so enrollment was off and the log blamed the CA
  certificate. The unit left `/tmp` read-only, so signing answered 500. The documented
  allowlist path could not be rewritten, so every enrollment spent its token and answered 500.
  The module now allows the server to run `openssl` (`corecmd_exec_bin`). The unit sets
  `TMPDIR=/var/lib/lodeline-server`, so signing makes its temporary files in the state directory.
  When the server cannot run `openssl`, the boot check now says so and names the path instead of
  reporting a CA certificate that is not `CA:TRUE`. The server packages depend on `openssl`. The
  three RPMs now remove the shared `lodeline` SELinux module with the last of them, where before
  `rpm -e` left it installed. (#567, #566)
- `lodeline-server enroll-token` now refuses before it writes anything when it runs as root and
  the token file's directory belongs to another account, and tells the operator to run it as
  that account (`sudo -u lodeline`). A token file made by root there is one the server cannot
  write, so every enrollment answered `500 token store error`. It also accepts only a lowercase,
  hyphenated version 4 host_id, the form `lodeline init-host-id` stores, so it no longer issues a
  token that the agent's host_id can never match. No file's owner is changed. (#564, #553)
- `lodeline-server` and `lodeline-sender` log at `info` when `RUST_LOG` is unset, as
  `lodeline-proxy` does. Before, they wrote only errors, so a default install showed no startup
  line, no warning, and no sender retry in `journalctl`. `RUST_LOG` still sets the level,
  for example `RUST_LOG=warn`. Both binaries now write their logs to stderr instead of stdout, so
  a warning no longer comes before the token on the stdout of `lodeline-server enroll-token`. The
  journal keeps both streams, but a script that reads their logs from stdout must read stderr
  now. (#561, #560)
- `lodeline-sender` logged one `read_next_batch failed` warning per second while a spool file
  stayed unreadable, about 86,000 lines a day now that warnings show by default. It now logs the
  first failure at once, then at most one line a minute that carries how many failures it left
  out. A successful read resets this. The retry timing is unchanged. (#562, #560)
- On a server whose `openssl` defaults to SHA-1 for an EC key, such as the LibreSSL that ships
  with macOS, an enrollment CA with an EC key issued host certificates signed with ECDSA and
  SHA-1. The server's own listener refuses those, so a host it had enrolled was refused at its
  first connection. Signing now asks for SHA-256. Servers on OpenSSL 3 already signed with
  SHA-256 and issue the same certificates as before. (#570)

## [0.14.3] - 2026-11-10

**Upgrade order.** The agent, the sender, the server and the web console can be upgraded in any
order. This release adds no event kind and no reason kind, and the agent's events are unchanged
on the wire. AI Guard now watches more Claude Code files, so hosts record more `file_change`
events. A host's findings can change after its agent is upgraded, because a project row at the
home folder no longer repeats the findings for `~/.claude/loop.md`. The server's fleet API and
its proxy routes send the same fields as in v0.14.2, and only the order of `audit_gaps` in
`GET /v1/proxies/{id}` changes. An existing `server.yaml` needs no change. Without
`proxy.stale_after_seconds`, a proxy still reads `disconnected` after 90 s without contact, and
a value outside 60 to 300 stops the server at boot. The sender has a new `lodeline-sender csr`
subcommand, and no package or release asset is added or removed. The console's Downloads page
reads `GET /v1/artifacts`, a route that the server has served since v0.7.0, with the credentials
that the console already uses. Against a server without `artifacts_dir`, the page says that the
server does not serve release files and names the `server.yaml` setting. `lodeline-proxy` is
still not a release asset.

### Added

- `lodeline-server` has a new `proxy.stale_after_seconds` setting. It sets how long a proxy can
  go without contact before `GET /v1/proxies` and `GET /v1/proxies/{id}` report it as
  `disconnected`. Before, this time was fixed at 90 s. The default is still 90 s. A value outside
  60 to 300 s stops the server at boot. The 60 s floor is two proxy heartbeat intervals, so a
  healthy proxy does not read `disconnected` between two heartbeats. (#549)
- `lodeline-sender csr --host-id <uuid> --key-out <file> --csr-out <file>` makes a host's
  enrollment key and CSR on the host. It writes a new ECDSA P-256 private key (PKCS#8 PEM,
  created with mode 0600 on unix) and a PEM CSR whose subject is only `CN=<host_id>`, which a PMS
  sends to `POST /v1/enroll`. It refuses a host_id that is not a UUID and never replaces an
  existing file. Before, this step needed the `openssl` binary, which Windows does not ship. The
  `openssl req` command still works. The sender now uses `rcgen` on the `ring` backend that its
  TLS client already links. (#554, #553)
- The web console has a Downloads page. It lists the release files that the server's operator put
  in `artifacts_dir`, and a signed-in user can save one in the browser. The console reads the
  files from `lodeline-server` with its own read token and client certificate, and streams each
  one as it arrives, so nobody has to put the read token on a host to fetch them. The console
  does not check the files. A server without `artifacts_dir` gets a page that names the
  `server.yaml` setting. The console API adds `GET /api/v1/fleet/artifacts` and
  `GET /api/v1/fleet/artifacts/{filename}`. (#555, #553)

### Fixed

- AI Guard now reassesses Claude Code as soon as `~/.claude/CLAUDE.md`, `~/.claude/loop.md`, a
  scheduled task's `~/.claude/scheduled-tasks/<name>/SKILL.md` or a repository's
  `.claude/loop.md` changes. Before, no watch target covered these files, so the agent read an
  edit only at the next heartbeat or with a change to another watched file. The shipped Claude
  Code user-global target and the per-repository target now include them, so hosts also record
  a `file_change` event for each edit, as for `settings.json`. These events carry hashes and
  sizes, never file text, and a scheduled task's event path includes the task's folder name.
  (#550)
- A project row whose root is the home folder, such as the one `lodeline scan` adds when started
  there, no longer reads `~/.claude/loop.md`. Before, the user row and the project row both read
  that file, so one prompt's findings appeared twice. The user row still reports it. (#550)
- The web console names a client certificate that the server refuses. A server with a `proxy:`
  section answers every read with 404 `host_unknown` when the console's client certificate is
  not from the host client CA, for example when it is from the proxy CA. The Fleet, Alerts and
  Settings pages then said that the read API was disabled and to set
  `LODELINE_SERVER_READ_TOKEN`, even with the token set. A host's page said that the host was not
  found, and the Proxies page said that proxy reads were not available. These pages now say that
  the server did not accept the console's client certificate, and to issue it from the host
  client CA as "Proxy reads" in `apps/manager/README.md` describes. The console relays this
  answer with the code `certificate_refused`. (#551)
- The web console no longer logs three Content Security Policy errors on every page. The build
  inlined the smallest JetBrains Mono subsets (Cyrillic extended and Vietnamese) as `data:`
  URLs, which the console's `font-src 'self'` policy blocks, so the browser could not use them.
  The build now writes every font as a file that the console serves. (#551)
- `GET /v1/proxies/{id}` now lists a proxy's open audit gaps before its closed ones in
  `audit_gaps`, newest first within each group, still at most 50. Before, the list was newest
  first only, so 50 newer closed gaps could push an older open gap out of it. Under steady
  traffic, out-of-order ingest leaves closed `sequence_gap` records, and the proxy page then
  showed a count of open gaps with none of them in the list. When more than 50 gaps are open,
  the list shows 50 of them, and `open_gap_count` and `open_gap_counts` give the full count.
  The web console shows the list in the server's order and says so above it. (#552)

## [0.14.2] - 2026-11-09

**Upgrade order.** The agent, the server and the web console can be upgraded in any order.
This release adds no event kind and no reason kind, and the agent's events are unchanged on the
wire. AI Guard now scans more Claude Code files, so a host's score can rise after its agent is
upgraded. The server changes only in its tests, so its fleet API and its proxy routes are the
same as in v0.14.1. The console's new proxy pages read routes that a server serves only when
`server.yaml` has a `proxy:` section. Such a server requires a client certificate on every
connection, so a console that already shows its fleet needs no new setting. For a new setup,
"Proxy reads" in `apps/manager/README.md` lists the certificate settings. Against a server
without the section, the Proxies page says that proxy reads are not available, and the other
pages work as before. `lodeline-proxy` is still not a release asset.

### Added

- The web console shows the server's Lodeline proxies on a new Proxies page. The list shows each
  proxy's connection, config and spool state and when it was last seen, and filters by
  connection state and config sync. A proxy's page shows its config revisions, spool, central
  ingest, registry sync, route health and audit gaps. When the server has stopped a proxy's
  ingest, its degraded spool reads as stopped ingest, not as a storage fault. Quarantined events
  show next to the spool depth, and a non-zero `audit_gaps_dropped` marks the gap list
  incomplete. Before, the console showed nothing about proxies. The console reads
  `GET /v1/proxies` and `GET /v1/proxies/{id}` and relays them as `GET /api/v1/fleet/proxies`
  and `GET /api/v1/fleet/proxies/{proxy_id}`. No page changes a proxy, and the console holds no
  management credential. (#542)
- The web console lists the MCP requests that went through a proxy on a new Proxy invocations
  page, with method, status, duration and flags. The Proxies page links to all requests, and a
  proxy's page links to its own. A request's page shows the request, timing, completion and
  events, and says when the server truncated the event list. Only a completed request shows an
  outcome. A completion without a start and an integrity conflict are flagged and never read as
  success. An outcome that the proxy reported and the server could not corroborate shows only as
  secondary text. Before, the console showed no requests. The console reads
  `GET /v1/proxy-invocations` and `GET /v1/proxy-invocations/{id}` and passes every server
  filter through. (#543)
- A proxy's page in the web console ends with an Inventory card with three tabs: Snapshots,
  Drift and Re-baseline markers. They list what the proxy's upstreams exposed over time, each
  observed change, and each point where a baseline was reset. The rows show references and
  counts only, never tool names or metadata content, and drift reads as an observed change,
  never as an approval. Before, the console showed no inventory. The console reads
  `GET /v1/proxies/{id}/inventory-snapshots`, `/drift` and `/rebaseline-markers`. (#544)

### Changed

- AI Guard now scans the prompt of a Claude Code scheduled task
  (`~/.claude/scheduled-tasks/<name>/SKILL.md`) and of a loop prompt (`.claude/loop.md` in a
  project, `~/.claude/loop.md` for the user) for the same directives as `CLAUDE.md`, such as a
  download piped into a shell. Before, these files counted only as present. A matched line is the
  finding's snippet, as for `CLAUDE.md`. Scores can rise on upgrade, also for a task whose prompt
  runs destructive shell commands on purpose. No reason kind is new. (#191)

### Fixed

- The web console's event detail for `ai_guard_risk_assessed` and `ai_guard_toggle_drift` has a
  Source row that names the assessed user, such as `user alice · built-in rules`, or
  `agent's own home · built-in rules` when the event has no `user`. Before, the detail showed
  `user` only in the raw evidence, so the readings that a root agent sends for two users looked
  the same. For toggle drift, the Source row replaces the Rule pack row, because it names the
  rule pack. (#537)

## [0.14.1] - 2026-11-09

**Upgrade order.** The agent and the server can be upgraded in either order. This release
adds no event kind and no reason kind, and the agent's events are unchanged on the wire. The
AI Guard fixes below change which findings a host reports, so a host's score can change after
its agent is upgraded. The server's fleet API and the web console are unchanged, so the server
and the console can also be upgraded in either order. If the server has a `proxy` section, its
first start migrates `proxy-metadata.sqlite` to a new format, and a v0.14.0 server then refuses
to start with that file. Back the file up before the upgrade if you might roll back.
`lodeline-proxy` is still not a release asset. A proxy built from this release creates event
ids as UUIDv7. A v0.14.0 server accepts them, and a spool written by an older proxy keeps
working with its stored ids unchanged.

### Added

- `lodeline-server proxy delete-content --proxy-id <id> --metadata-ref <ref>` deletes the stored
  definition of one proxy registry entry, for example for a privacy request, and keeps the
  entry's stub so ingest still recognises the ref. It calls the new management route
  `POST /v1/proxies/{id}/metadata/{metadata_ref}/delete-content` (`identity` scope). Freed pages
  are zeroed and the write-ahead log is truncated after the commit, so the file keeps no copy.
  If a reader holds the log and the truncate does not complete, the server logs an error, the
  old content can stay in the log until the next checkpoint, and running the command again
  retries the truncate. The command can be repeated and answers 200 each time. A ref with no
  entry for that proxy answers 404 with the new error code `metadata_ref_unknown`. Each call is
  recorded in the management audit as `proxy.metadata_content_delete` with the ref, never the
  definition. A later upload of the same entry does not restore the definition.
- `lodeline-server` now deletes the inventory snapshots of a chain that a key rotation or a
  canon change has ended. Before, the old chain's snapshots stayed forever, and the registry
  entries they named were never deleted either, so a proxy that rotated keys grew until HTTP
  503 `storage_limit`. A chain ends when a later snapshot of another chain for the same scope is
  stored and does not wait for an earlier one. Once that snapshot was received more than
  `event_retention_seconds` ago, the ended chain's snapshots, members and rotation links are
  deleted. The result does not depend on the order in which snapshots arrived.
- `lodeline-server` now deletes proxy registry entries that nothing it keeps names any more.
  Before, `proxy-metadata.sqlite` never deleted an entry, so a proxy that kept uploading new
  entries reached its storage cap and got HTTP 503 `storage_limit`. After each ledger sweep, an
  entry is deleted when no stored start event, inventory member, rotation link, drift record or
  held `registry_conflict` gap names it, and its last upload is older than the proxy's
  `max_offline_retry_age_seconds` plus `ack_loss_margin_seconds`. A byte-identical upload
  restarts that clock. A start or report that names a deleted entry gets 424
  `metadata_ref_pending`, and the proxy uploads the entry again. The first start migrates the
  file to a new format, which a v0.14.0 server does not open.
- `lodeline-proxy health` and the local `status.json` now show the spool state that the status
  report sends to the server. Before, an operator on the host could not see that the proxy refused
  calls because its event spool had stopped. `status.json` has a new optional `spool` section, such
  as `{"state": "degraded", "reason": "fsync_failed"}`, and `health` prints a matching line, such as
  `spool: Degraded (FsyncFailed)`. The reason is one of `fsync_failed` (a failed storage sync stopped
  the spool until restart), `writer_stopped`, `gap_reserve_exhausted`, `storage_failed`, or
  `ingest_stopped`, and appears only while the state is degraded. The status report to the server
  does not change. Files written by an older proxy still read, and `health` prints `spool: unknown`
  for them. The exit code of `health` does not change.

### Fixed

- On macOS and Linux, a Claude Code, Codex or Cursor hook command that runs a script under `~`,
  such as `~/x.sh` or `bash ~/hooks/check.sh`, now has that script's content scanned. Before, the
  script was reported as unscanned and a destructive command in it was missed. `~` is read as the
  home whose settings name the hook, so a root agent scanning alice's hooks reads alice's home. A
  quoted `"~/x.sh"`, a Claude Code exec-form hook (`args` set), and every hook on Windows keep `~`
  as written, because the shell those run through does not read it as the home.
- On macOS and Linux, a hook command whose script starts with `$HOME/` or `${HOME}/`, such as
  `$HOME/x.sh` or `bash "$HOME/x.sh"`, now has that script's content scanned the same way. Before,
  `$HOME/x.sh` was reported as unscanned, and `bash "$HOME/x.sh"` added no hook finding at all. The
  shell reads `$HOME` unquoted and inside double quotes, as in `"$HOME"/x.sh`, so these now read
  the home whose settings name the hook. A single-quoted `'$HOME/x.sh'`, a different variable such
  as `$HOME_DIR/x.sh`, a Claude Code exec-form hook, and every hook on Windows keep the word as
  written. The words after a `$HOME` script are now treated as its arguments, which are data, as
  for any script path, so `bash $HOME/x.sh rm -rf /` reports the script and not an inline command.
- The Codex project scan now reads the system config (`/etc/codex/config.toml`,
  `%ProgramData%\OpenAI\Codex\config.toml`) under the user and project layers for sandbox
  settings. A project `default_permissions` profile that only the system config defines, with a
  `write` entry on the whole disk or the home folder, was missed and now scores `sandbox_disabled`.
  A system `sandbox_mode` such as `read-only` now keeps a project `[sandbox_workspace_write]` table
  from scoring when no higher layer picks `workspace-write`, because Codex ignores the table then.
- Codex sandbox scoring now resolves paths against the home folder and the config folder as Codex
  does. A `writable_roots` entry or a `write` path in a `[permissions]` profile that names the home
  folder or a parent of it, such as `/home` or `~/../alice` for the home `/home/alice`, was missed
  and now scores `sandbox_disabled`. A relative `writable_roots` entry resolves against the folder
  of the config that set it, so `..` in the user config names the home folder with the default
  `CODEX_HOME` and now scores. A profile path now drops `.` and folds `..`, so `/.` and `~/.`
  score too. On macOS and Linux, a drive root such as `C:\` in a profile no longer scores, because
  Codex refuses the profile there.
- Codex `[sandbox_workspace_write] writable_roots` scoring now folds `.` and `..` as Codex does.
  An absolute or `~` entry that resolves to the root, the home folder or a parent of it, such as
  `/.`, `/..` or `~/.`, was missed and now scores `sandbox_disabled`. On macOS and Linux,
  `C:\`, `C:/`, `\` and `~\` are relative paths to Codex and no longer score as writing
  everywhere; on Windows they still do. The hint for `workspace_write_network` now names
  `network_access` instead of asking to enable the sandbox.
- Claude Code managed MCP scoring no longer over-reports three cases. With a `managed-mcp.json`
  deployed, a project's `.mcp.json` servers and its `enableAllProjectMcpServers` or
  `enabledMcpjsonServers` key are no longer scored, because Claude Code loads only the managed set.
  A `managedMcpServers` entry that Claude Code drops (not an `https://` http or sse server, a name
  with characters other than letters, digits, `-` and `_`, a `command`, `args`, `env` or
  `headersHelper` member, or a `${VAR}` reference) is no longer scored, and a user server of the
  same name is scored again. A managed server that a `deniedMcpServers` entry in managed or user
  settings matches by `serverName`, by exact `serverCommand`, or by `serverUrl` (exact, or a full
  host followed by `/*`) is no longer scored. An MCP server URL without the slashes after the
  scheme, such as `https:host`, which URL parsers accept, is now scored as remote.
- Claude Code hook scoring is closer to what Claude Code runs. A `*` matcher whose handlers all
  have an `if` rule that matches every path under home or the working directory, such as
  `Edit(~/**)` or `Read(./**)`, is now reported as a broad matcher; before, it was a missed
  finding. Only file tools (Read, Edit, Write, NotebookEdit) take these path anchors, so
  `Bash(./*)` stays narrowed. An `if` rule with a tool-name glob, such as `mcp__*(x)`, or with an
  argument other than `*` on WebFetch, Skill or an MCP tool, such as `WebFetch(**)`, matches no
  call, so its group is no longer reported as broad. A user-level `disableAllHooks: true` now
  turns off project hooks when the project files leave it unset. In Codex, a permission profile
  entry `"C:/**" = "write"` is no longer reported as a disabled sandbox, because Codex rejects it
  as not absolute.
- The Codex `.rules` scan now reads strings, comments and calls as Codex's Starlark does. A
  `decision="\x61llow"` rule, or one using `\u`, `\U` or octal escapes, was a missed standing
  approval. `//` is floor division, not a comment, so a rule after `n = 7 // 2;` on the same line
  was missed and a rule with a `// decision="prompt"` line inside its call was reported as an
  allow. `x . prefix_rule(...)` with spaces around the dot is an attribute call and is no longer
  reported. A program path that is a folder right under the root other than `/bin` and `/sbin`,
  such as `/data/alice`, is now reported as `<redacted>` like `/home/alice`.
- `lodeline-proxy` now uploads a registry entry again when the server answers an event batch
  with 424 `metadata_ref_pending` for it. Before, only an inventory 424 did that, and an event
  424 only held the events. When the server lacked an entry the proxy held as acknowledged, for
  example after the server restarted without its `proxy-metadata.sqlite`, starts that named the
  entry stayed held until the offline retry age passed and were then lost as `spool_expired`.
  Now the next registry sync uploads the entry and the held starts are accepted.
- `lodeline-proxy` now stops its event spool for good when a storage sync (fsync) fails, and
  refuses every call until you restart it. Before, the spool kept running after a failed fsync,
  and the next successful fsync cleared its degraded state. On Linux the kernel reports a
  writeback error only once and can drop the data it did not write, so that later success
  proved nothing. After a power loss, a call the proxy had forwarded could be missing from the
  spool, and event sequences already sent to the server could be assigned again. Now, after a
  failed fsync, the proxy answers new calls with HTTP 503 `audit_unavailable`, sends no more
  events, reports `spool.state: degraded` in its status report until it restarts, and logs an
  error that starts with `spool fsync failed`. To recover, check the disk that holds the state
  directory (kernel log, device health, free space), fix or replace it, and then restart the
  proxy. The restart recovers the spool from its write-ahead log. Starts of the failed batch,
  which were refused, can appear as start-only records after the restart. They were never
  forwarded.
- `lodeline-proxy run` now finishes its shutdown within one `limits.shutdown_grace_secs` after
  the stop signal. Before, the relay drain, the audit producer drain and the wait for cancelled
  blocking work each had a full grace of their own. With the default 30 seconds a stalled
  shutdown could take about 90 seconds, past the shipped unit's `TimeoutStopSec=45`, and systemd
  killed the proxy before it recorded `stopped`. The grace now counts once from the signal, and
  each later step gets only the time left. The audit producer drain still gets at least 0.5
  seconds, and its gap handover keeps its own 5-second bound, so the default still fits in 45
  seconds. A late step has less time than before, so more in-flight completions can end as
  counted gaps instead of spool records. That is the trade for recording `stopped` before
  systemd kills the proxy. When the wait for blocking work times out, the warning now names how
  many handles of the gap queue and the registry are still held. If you raise
  `shutdown_grace_secs`, raise `TimeoutStopSec` too.
- `lodeline-proxy run` now records `stopped` only after the work its shutdown cancelled has let
  go of the state directory. Before, a registry, ingest or status report step that was waiting
  on blocking work when the shutdown cancelled it kept running and could still write the state
  after `stopped` was recorded. A new run in the same process could then fail with `another
  lodeline-proxy instance holds the lock on this state_dir`. The wait counts against
  `limits.shutdown_grace_secs`.
- `lodeline-hook install --agent codex` and `lodeline-hook verify --agent codex` now warn when
  Codex's `[features] hooks` is `false`, or the older `codex_hooks` is `false`. Codex then runs
  no hooks, so the registered hook never runs. Before, both commands reported success and said
  nothing. The warning names the file and the key and says to set `hooks = true` under
  `[features]`. For a pin in the system `requirements.toml`, which an administrator manages, it
  says instead that the pin is set there and that a change to the user's own Codex config does
  not take effect. A `hooks` or `codex_hooks` value that is not `true` or `false` stops Codex
  from loading its config, and the warning says so. It reads the user `config.toml` (`$CODEX_HOME` or `~/.codex`), the system
  `config.toml`, and a pin in the system `requirements.toml`, as AI Guard does. A config that
  does not parse gets a warning too. The install still writes the hook, and exit codes do not
  change. `lodeline doctor` reports the same check for a registered Codex hook and, as for any
  warning, exits `1`.
- `lodeline-proxy` now reuses idle upstream connections. Before, it opened a new upstream
  connection, and a new TLS session for an https upstream, for every forwarded call. Under
  sustained load each closed connection held a local port in TIME_WAIT. On macOS the ports ran
  out within about 2 seconds, and from then on most calls failed with HTTP 502
  `upstream_unavailable`. In a local 30-second run at 8 or 32 concurrent clients, 86 to 87% of
  calls failed this way. Each route now keeps its own idle connections. A connection is reused
  only after its previous response was read to the end, only within 1 second of going idle,
  and only to an address that the destination check allowed for the new call. DNS is still
  resolved and checked for every call. A route keeps at most as many idle connections as
  its concurrent call limit (`max_calls_per_route`, 16 by default) and closes the oldest when
  it has more. A config apply starts every route with no idle connections. A call is still
  sent once and never sent again on another connection. The same run now has no failed calls
  and at most 67 sockets in TIME_WAIT.

### Changed

- `lodeline-proxy` now creates proxy event ids (`event_id`) as time-ordered UUIDv7 instead of
  random UUIDv4, so the spool's unique index on them grows at one end. In local measurements this
  cut the distinct spool pages written per 1,024 commands from about 1,006 to 225. The id format
  and the contract do not change, and ids already stored stay as they are. A v7 id carries its
  creation time to the millisecond, which the event already records in `occurred_at`. On an AWS
  t4g.small with gp3 storage at 64 concurrent clients, the median rose from 1,277 to 3,238 calls/s,
  p99 fell from 236 ms to 34.9 ms, and disk writes per call fell from 2.38 to 0.44.
  See `docs/specs/lodeline-proxy/execution.md` (2026-11-08).
- `lodeline-proxy` now copies its spool's write-ahead log into the database on a background
  thread, so calls in flight no longer wait for each checkpoint. Before, the spool writer ran
  the checkpoint itself every 512 commands, and every call in flight waited for it. The
  background checkpoint runs every 1,024 commands, and the writer waits for it only when the
  log reaches 2,048 commands. A failed fsync on the background thread stops the spool as a
  failed fsync on the writer does. On an AWS t4g.small with gp3 storage at 32 concurrent
  clients, p99 fell from 273 ms to 86 ms and throughput fell 2.5%, from 1,193 to 1,163 calls/s
  (median of 7 alternating runs). The write-ahead log grows larger than before, up to about
  31 MiB in that test. See `docs/specs/lodeline-proxy/execution.md` (2026-11-08).
- `lodeline-proxy` now commits each group of queued spool records in one transaction. Before,
  group commit shared one fsync, but each record still wrote the same pages to the write-ahead
  log again, so the proxy wrote as much per call as before group commit. If a group commit
  fails, its completion and cancel records are now refused too, not only its start records. On
  an AWS t4g.small with gp3 storage at 64 concurrent clients, the proxy's writes per call fell
  from 76.8 KB to 24.5 KB and p99 fell from 330 ms to 237 ms (median of 3 alternating runs).
  At 32 clients p99 rose from 175 ms to 266 ms. The background checkpoint above addresses that.
  See `docs/specs/lodeline-proxy/execution.md` (2026-11-08).
- `lodeline-proxy` now commits spool records that are already queued together and covers them
  with one fsync (group commit). Before, every concurrent `invocation.started` record waited for
  its own fsync, which capped proxied throughput at about 400 calls/s on an AWS gp3 volume. A
  call is still forwarded only after the fsync that covers its start record returns, and a lone
  call commits as before with no added wait. If that fsync fails, every start record in the
  group is refused. On a busy shared local machine at 64 concurrent clients, proxied throughput
  rose from 222 to 756 calls/s (median of 3 alternating runs). Treat that as indicative only.
  On one AWS t4g.small (2 vCPU, aarch64, Amazon Linux 2023; spool and local collector on the
  same 3,000 IOPS gp3 volume), proxied throughput at 64 concurrent clients rose from 471 to 752
  calls/s and at 32 from 468 to 742. A single client stayed at about 355 calls/s (median of 3
  alternating rounds, no errors). Under that closed-loop load the median added latency fell
  (p50 117 to 27 ms at 64 clients), but the tail grew: p95 178 to 340 ms and p99 212 to 557 ms
  at 64 clients, and p99 124 to 338 ms at 32. The cause of the tail growth was not measured.
  At 100 calls/s on a fresh stack (2 rounds per side) added p99 did not change (about 15 ms).
  Right after a heavy closed-loop run on the same disk it was higher.
  See `docs/specs/lodeline-proxy/decisions.md` and
  `docs/specs/lodeline-proxy/execution.md` (2026-11-07).

## [0.14.0] - 2026-11-07

**Upgrade order.** The agent and the server can be upgraded in either order. This release
adds no event kind and no reason kind, and the agent's events are unchanged on the wire. If
you run the web console, upgrade the server first and then the console. A console of this
release against an older server shows no "not assessed" notice on the Risk tab, and an older
console ignores the new `not_assessed_host_count` field. The console is now a release asset.
Before you start it, check `.env` for a `JWT_SECRET`, `LODELINE_SERVER_READ_TOKEN` or
`ADMIN_PASSWORD_BCRYPT` copied from an earlier `.env.example`. The console refuses to start
with those values. The server now writes a `.received-YYYY-MM-DD.jsonl.recv` file beside each
event file, and a v0.13 server ignores these files if you roll back. `lodeline-proxy` is still
not a release asset. Its changes here do not change what it sends to the server.

### Added

- `lodeline doctor` now starts each hook exe that `lodeline-hook install` registered, with
  `--version`, no stdin and a 2-second limit, and warns about each one that cannot start. Before,
  nothing on the host reported such a hook. On Windows, Smart App Control or a WDAC policy can
  block an unsigned `lodeline-hook.exe` while `lodeline.exe` still runs. Claude Code then logs
  hook status 126 and runs the tool, Codex shows nothing, no event reaches the agent, and an
  `--enforce` deny rule has no effect. Doctor now prints `[WARN] hook <agent>: cannot start
  <path>: blocked by Windows Application Control (Smart App Control or WDAC); hooks will not run`
  and exits `1`. A missing or non-executable hook gets the same warning with the OS error. A hook
  that starts prints `[OK]`, and one still running at the limit is stopped and reported as started.
  Doctor starts only an absolute path whose file name is `lodeline-hook` or `lodeline-hook.exe`. For
  any other command it prints `[WARN] hook <agent>: not started: <exe> is not an absolute path to
  lodeline-hook` and runs nothing. Doctor does not run this check as root. See the Platform
  section of `docs/install-personal.md`.
- Releases now ship the `lodeline-manager` web console. Each release has a
  `lodeline-manager-<version>-<target>.tar.gz` archive (`.zip` on Windows) for the same five
  targets as the agent, with the SPA built in, so an operator no longer builds the console from
  source. The archive also holds `.env.example`, `LICENSE`, `NOTICE` and a short README.
  `SHA256SUMS`, the build provenance attestation and the signed `build-manifest.json` cover the
  binary, and the release's native verify jobs check that it runs and prints the release version.
  The manifest keeps schema version 1 and now lists 35 binaries; `lodeline doctor
  --verify-self` of the agent binaries is unchanged. `lodeline-manager --version` prints the
  version, which now follows the workspace version, so a release prep bumps
  `apps/manager/Cargo.toml` and `apps/manager/Cargo.lock` with the root. See
  `apps/manager/README.md`. There are no `.deb`, `.rpm` or container images for the console yet.
- The web console's Risk tab now says when hosts are missing from it because they have
  failing AI Guard sources and no score, such as "1 host is not assessed", with a link to those
  hosts in the Devices tab. Before, such a host was absent from the Risk tab, and an empty
  table read "No hosts above the selected risk level." The Devices tab gains a "Failing AI
  Guard sources, no score" filter over loaded devices for the link. The link is left out while
  a `tool` filter is set, because the Devices filter spans all tools. `GET /v1/fleet/risk` gains
  `not_assessed_host_count`, the number of hosts with a failing source for a selected tool and
  no reading for any selected tool. `tool` applies to it, `min_bucket` does not, and every page
  carries the count for the whole result. These hosts still get no score and no row. The change
  is additive. Older consoles ignore the field, and with an older server that omits it the
  console shows no notice. (#485)

### Changed

- `lodeline-proxy` now fsyncs the spool only for `invocation.started` records. Completion and
  cancel records and ingest acknowledgements commit without their own fsync and become durable
  at the next start commit or spool checkpoint. The start record is still durable before the call
  is forwarded. A process crash loses nothing. A power loss or OS crash can drop the completion,
  cancel and acknowledgement records written since the last start commit or checkpoint. A call
  whose completion is dropped shows as a start-only call. A dropped acknowledgement makes the
  proxy send those events again, and the server counts them as duplicates. The proxy sends the
  server only spool rows that an fsync covers, so a sequence number the server has seen is never
  assigned again. SQLite
  checkpoints no longer run inside a commit. They run in the maintenance pass, when the ingest
  client finds only rows that are not yet durable, and after every 512 spool commands, which
  bounds the WAL (18 MiB high-water on the test node). On an AWS t4g.small with gp3 storage, the
  added latency of a sequential `tools/call` went from 3.44 ms to 2.95 ms p50 (median of 5
  alternating runs of 200 calls), with 1.0 instead of 2.1 WAL fsyncs per call. p99 did not change
  measurably. See `docs/specs/lodeline-proxy/decisions.md` (2026-11-06).
- AI Guard reports a Codex `prefix_rule(..., decision="allow")` whose prefix can run any
  program as `permissions_allow_broad`, next to its `standing_command_approval`. A prefix is
  broad when it is one that Codex itself refuses to suggest as a standing approval, such as
  `["bash", "-c"]`, `["python3"]`, `["sudo"]`, `["rm"]` or `["git"]`, or a shorter prefix of
  one, such as `["npm"]` for `["npm", "run"]`. Codex runs a command that such a rule allows with
  no prompt and outside the sandbox. The finding's `rule` is spelled from that list, for example
  `prefix_rule(pattern=["python3", "-c"])`, so no path or argument from the rules file leaves
  the host. A narrow prefix such as `["git", "status"]` is reported as before. This is an
  existing reason kind, so every server version accepts it. A broad rule now adds the
  `permissions_allow_broad` weight on top of `standing_command_approval`. Both weigh 2.0, so one
  `["git"]` rule scores 4.0 instead of 2.0, and several such rules reach the 10.0 cap. (#200)
- AI Guard no longer reports Codex config hooks when Codex has hooks turned off with
  `[features] hooks = false` or the older name `codex_hooks = false`. The merged system, user
  and project config decides, and a `[features]` pin in the system `requirements.toml` wins over
  config. A pin from MDM or cloud policy, a `--profile` file and a `--disable hooks` flag are not
  read. (#200)
- `lodeline-manager` refuses to start when `JWT_SECRET`, `LODELINE_SERVER_READ_TOKEN` or
  `ADMIN_PASSWORD_BCRYPT` still holds the example value from an earlier `.env.example`, and the
  error names the variable. Those values were public. `.env.example` now leaves the secrets
  empty and shows how to generate each one.

### Fixed

- `lodeline-proxy` no longer refuses a `tools/call` with HTTP 503 `audit_unavailable` when
  more than four registry lookups overlap on a healthy registry. Each call start reads the
  registry in one of four lookup slots. A start that found all four taken was refused at once,
  as if the registry could not be read. On an AWS node at 8 concurrent clients, 4 to 13 of
  every 800 `tools/call` were refused this way. A lookup now waits for a slot within its
  2-second lookup timeout. It fails at once only when every slot is held by a read past its own
  deadline, so a stuck registry still ties up at most four threads. The audit writer's lookup
  for refusal records uses the same path, so overlap no longer drops those records either.
- `lodeline-proxy` no longer refuses healthy calls with HTTP 503 `audit_unavailable` under
  sustained concurrent load. The audit writer stored one completion at a time and waited for
  each before the next, while the call starts committed side by side, so its queue of 1024
  records filled within about 1,300 calls in a local test. From then on the proxy refused new
  calls, and the completions that found the queue full were lost and reported as
  `local_record_failed` gaps. A local run of 8 clients making 400 `ping` calls each had about
  1,300 of 3,200 calls refused this way, and `tools/call` behaved the same. The writer now hands
  its whole queue to the spool at once. Start records are still durable before the proxy
  forwards a call, and a full or failing spool still refuses calls as before.
- `lodeline-server` no longer lets an agent clock that runs ahead keep a host `healthy` or
  empty its 24-hour counts. It used to take a host's `last_seen_ts` and the hour of each
  24-hour count from the event's own timestamp. One event dated days ahead then kept the host
  `healthy` and counted as active in `/v1/meta` for those days, and it moved the counts window
  so that the host's correctly dated events stopped counting. These fields now use the earlier
  of the event's timestamp and the time the server received it. `last_heartbeat_ts` and
  `last_policy_reload_ts` follow the same rule. An agent clock that runs behind is not
  corrected, because the server cannot tell it from events that arrive late. So that a restart
  gives the same result, the server now records when it received each batch, in a
  `.received-YYYY-MM-DD.jsonl.recv` file beside each event file. Event files written before
  this change carry no receive time, and a restart caps their times at the end of the receive
  day or at the restart, whichever is earlier. In a file that already holds lines from before the
  upgrade, those lines take the receive time of the first batch the upgraded server appends,
  which is later than their true receive time, on the same day, and earlier than the
  restart that rebuilds them. The event's own timestamp is unchanged in stored
  events, SIEM output and `/v1/events`. (#442)
- AI Guard now reads the Claude Code local settings file where current Claude Code keeps it.
  Since v2.1.211, "Yes, and don't ask again" saves its allow rules to
  `.claude/settings.local.json` at the git repository root, and a linked worktree uses the
  main checkout's file. A project in a worktree or in a repository subdirectory now scores that
  file together with its own copy. The root file wins a key both set, and the permission lists
  of both apply. As Claude Code does, the root file is not used on Windows, when the root is
  the home directory, or when the root, its `.git` or its `.claude` has another owner. A root
  file that cannot be read or parsed is ignored, and the project keeps its own findings. A
  repository whose only Claude Code file is `.claude/settings.local.json` or `.claude/loop.md`
  is now discovered, and `lodeline scan` uses the same markers as the agent. Hooks in skills
  under `<subdir>/.claude/skills/` below the repository root are now scored with the project,
  because Claude Code loads such a skill once Claude works on a file in that folder. The walk
  skips hidden, `node_modules` and `target` folders and symlinked directories. No reason kind
  is new, so every server accepts these events. Scores can go up for such projects. (#199)

## [0.13.0] - 2026-11-05

**Upgrade order.** Upgrade the fleet server first, then the agents. The server learns the
`ai_guard_assess_failed` event and the new `source` and unassessed fields. The web console
reads them from the server. The console is not a release asset, so if you run it, rebuild it
from this release as `apps/manager/README.md` describes after you upgrade the server. An agent
on this release still works with an older server. Every server since v0.3.0 accepts
`ai_guard_assess_failed` and only counts it as a warn event. On a v0.12 server, though, a
source that keeps failing drops out of `current_risk` 48h after its last reading, because the
agent no longer re-sends the old reading. On a server of this release it shows as unassessed
instead. A server older than v0.12 keeps showing the last reading. A console of this release
against an older server looks as before.

### Added

- `lodeline-server` now says which reading each tool's risk score comes from. Each tool in
  `current_risk.by_tool` of `GET /v1/fleet/hosts` and `GET /v1/fleet/hosts/{host_id}`, each
  tool in the host detail's `ai_guard.by_tool`, and each `GET /v1/fleet/risk` row get a
  `source` object with the reading's `scope`, `user`, `rule_pack_id` and `tool_label`. On a
  host where a root agent assesses every user, an operator can see whose config and which rule
  pack produced the score without searching the event stream. `user`, `rule_pack_id` and
  `tool_label` are `null` when the event omits them, so `user: null` means the agent's own home
  or a project. When two readings tie on score, the newest is shown, as before. The server
  builds `source` the same way on ingest and on rebuild from JSONL. The change is additive. No
  agent or event change is needed, and older consoles ignore the field. (#333)

- `lodeline-server` now accepts the `ai_guard_assess_failed` evidence kind, which says that a
  parser could not assess one source, and shows that source as unassessed instead of current
  or clean. If the source has a reading, the score stays in `current_risk`, and the tool's
  `current_risk.by_tool` entry, its host detail `ai_guard.by_tool` entry and a
  `GET /v1/fleet/risk` row for it get `unassessed_since`. A new top-level `ai_guard_unassessed`
  on `GET /v1/fleet/hosts` and `GET /v1/fleet/hosts/{host_id}` lists each tool's failing
  sources with their `scope`, `user`, `rule_pack_id`, `error_kind` and `path`, and is `null`
  when none fails. A host with failures but no reading keeps `current_risk: null`. Each failure
  report keeps the source from being dropped, so a source that keeps failing stays listed; one
  that stops sending both readings and failures still drops after 48h. The next reading clears
  the mark. The server rebuilds the same state from JSONL on start. Released servers since
  v0.3.0 accept it and only count it, and older consoles ignore the new fields.
  `lodeline-core` gains the `Evidence::AiGuardAssessFailed` variant. (#333)

- The web console shows who produced each AI Guard score and which sources it could not
  assess. The Devices table, the Risk table and the host's AI Guard panel name the user and
  the rule pack next to a tool's score, or "agent's own home" when the server reports no user.
  A score whose parser has failed since shows "Unassessed since" with the time, and a host
  with failing sources but no score shows "Not assessed" with the same mark, never a clean
  state. The host page lists each failing source with its error and path. The event timeline
  shows an `ai_guard_assess_failed` event as "AI Guard assessment failed" with its tool, and
  the event slide-over shows its error, path, source and times. It is not a default alert. With
  a server that sends none of these fields, the console looks as before. (#469)

### Changed

- The SIEM runbook gains a rule for `ai_guard_assess_failed`, and the fleet API contract now
  says `open_alert_count_24h` counts events that match `alerts_definition_default`, not every
  warn event. (#333)

- The agent now reports a failed AI Guard assessment instead of re-sending the last reading.
  When a parser cannot read or parse a config, the agent sends an `ai_guard_assess_failed`
  event for that source with `error_kind` (`unreadable` or `parse`), the failing `path`,
  `failing_since` and the time of the last good reading, which is `null` when the agent has
  none since it started. It sends the event on the first failure, again when the error kind
  or path changes, and on each 24h heartbeat while the source keeps failing. A heartbeat
  re-send carries `is_reattestation: true` only when `error_kind` and `path` are unchanged.
  `failing_since` stays the first failure the running agent saw until a good reading. The
  event carries no file content and no error text. The first good reading after a failure is
  always sent, even when it equals the last one. Before, a failing source sent nothing on a
  change, and its heartbeat re-sent the last reading as if it were current. `lodeline show
  risk` still lists a failing source's last good reading with its original time, and leaves
  out a source that has failed since the agent started. Every server since v0.3.0 accepts
  the event. A v0.12 or later server without `ai_guard_assess_failed` ingest drops a failing
  source 48h after its last reading. A server older than v0.12 keeps showing the last
  reading. (#333)

- `lodeline-server` now accepts an `ai_guard_risk_assessed` event that holds a reason it
  cannot read, such as a reason kind added by a newer agent. Before, it rejected the whole
  event as `malformed_payload`, so the reading never reached the server JSONL or the fleet
  index. A known reason kind with fields this server cannot decode is accepted the same way,
  and is no longer rejected. The reason must still be an object with a string `kind`, so a
  reason without one, or with a number such as `{"kind":7}`, still rejects the event. The
  server keeps the reading and serves that reason in `ai_guard.by_tool.<tool>.reasons` as
  the same JSON value the agent sent, though its keys may come back in a different order.
  `/v1/events` returns the event as stored, which is the payload the agent sent, not
  re-encoded. The reason counts in `reasons_count`. The server reads the score from the
  event, so an unknown reason does not change it. An unknown `tool`, `bucket` or `scope`
  still rejects the event. Older servers still reject an unknown reason kind, so agents must
  not send one. `lodeline-core` gains `AiGuardReason::Unknown`. A rule pack whose `emit` is
  not a reason the agent knows fails to load as before, and the error now shows the `emit`
  object instead of naming the unknown kind or the missing field. (#333)

### Fixed

- The agent stamps an AI Guard reading's event and its cached copy with one time, so the
  `last_assessed_ts` of a later `ai_guard_assess_failed` event equals that reading's `ts`. (#333)

- The web console shows a reason kind or tool that is not a string as "Unknown" instead of
  failing to render the page. (#333)

- The console's event timeline shows `ai_guard_risk_assessed` as "AI Guard risk assessed" and
  `ai_guard_toggle_drift` as "AI Guard toggle drift", next to "AI Guard assessment failed".
  (#333)

## [0.12.6] - 2026-11-05

### Changed

- The web console moved into this repository under `apps/manager`. It was the separate
  `lodeline-manager` repository, which is now archived. The console is rewritten in Rust and
  serves the same web UI. It starts from the Go console's environment and reads its session
  cookies and triage database without a migration. It is not yet published as a release
  artifact, so build it from source as `apps/manager/README.md` describes. Three of its
  differences from the Go console may need action. Behind a reverse proxy, set the new `TRUSTED_PROXIES`, or every client
  shares the proxy's 10 logins a minute. Loopback is no longer exempt from the login limit.
  Login and triage `POST` requests get 415 unless their `Content-Type` is `application/json`.
  (#468)

- On Windows, the agent's control pipe `\\.\pipe\lodeline-control` now grants access
  explicitly, only to the account that runs the agent, SYSTEM, and Administrators. Before,
  it used the default pipe permissions, which also gave every user read access. No caller
  loses access, because every control request needs read and write access. The agent no
  longer joins a control pipe that another process already serves. It retries for about
  5.5 seconds, so a restarted agent can take over from the previous one, then logs an
  error that names the pipe and exits with status 1. The `lodeline` CLI and `lodeline-sender`
  now open the pipe with only the access a client needs.

### Fixed

- `lodeline-server` no longer counts a resent batch again in the fleet index. When the
  sender sent a batch that the server had already stored, the server wrote nothing but
  still added the batch to the 24h counts, such as `open_event_counts_24h` and
  `open_alert_count_24h`. The counts then went down after a restart. The fleet index now
  takes only the events the server writes, so live counts match the counts after a
  restart. The response to the sender does not change. (#441)

## [0.12.5] - 2026-11-03

### Fixed

- On Windows, `lodeline-hook` in its default capture mode now sends hook events to the
  agent. Before, it recorded nothing on Windows, and drift reports from
  `lodeline-hook verify` were not delivered either. The agent listens on a named pipe for
  them. If another process already uses the pipe name, the agent retries for about 5.5
  seconds, then does not open the hook pipe and keeps running. Like the enforce pipe, the
  hook pipe lets signed-in local users connect, so a hook in another session reaches an
  agent that runs as a service. (#445)

- On Windows, the agent no longer opens the enforce pipe `\\.\pipe\lodeline-hook-decide`
  when another process already uses that name. It retries for about 5.5 seconds, so a
  restarted agent can take over from the previous one, then logs an error that names the
  pipe and keeps running, and hooks follow `--on-failure`. The pipe now grants access
  explicitly. Signed-in local users can connect to it to ask for a verdict, which is what
  lets a hook in another session reach an agent that runs as a service. A hook that runs
  as a different Windows user than the agent needs both the hook and the agent from this
  release or later, so upgrade them together. (#446)

## [0.12.4] - 2026-11-03

### Fixed

- `lodeline-hook install --write` from a new release folder now replaces the entry
  that an older version wrote from another folder. Before, the old entry stayed beside
  the new one. On Windows that old entry used the `\\?\` path form, which fails on every
  tool call under Git Bash. An old entry whose path has a space and no quotes is found
  too. `uninstall` now removes Lodeline's entries at any path. A wrapper such as
  `cmd.exe /c` or `bash -c` is still left alone. (#443)
- In Claude Code, Codex and Antigravity, install and uninstall now remove only
  Lodeline's own command from a hook group. Before, they removed the whole group, so a
  user's hook in the same group was lost. Install writes its command in a group of its
  own. (#443)
- `verify` now reports `command_drift` when more than one Lodeline entry is present, or
  when the entry points at another binary. A leftover `sigil-hook` entry beside the new
  one counts, so `verify` reports `command_drift` until `install --write` removes it.
  (#443)

## [0.12.3] - 2026-11-03

### Added

- The scanner now reads every Cursor `hooks.json` layer. These are the user file, the
  enterprise file (macOS, Linux and Windows paths), and the project file. Command hooks
  are scored like other hook commands. Prompt hooks are not scored. A `hooks.json` that
  does not parse is skipped with a warning. The daemon now watches a Cursor project's
  `hooks.json`. (#430)

- A new Grok Build parser reads user and project hook files, user `[hooks]` in
  `~/.grok/config.toml`, and MCP servers in the user and project `config.toml`.
  `lodeline scan` picks up a Grok project by `.grok/hooks/` or `.grok/config.toml`. The
  daemon does not yet discover Grok projects. (#430)

- Lodeline's own Grok hook now adds a small score for its broad matcher, the same way
  Lodeline's own Claude Code hook already does. Hosts with it installed may see a
  slightly higher score. (#430)

### Fixed

- Running `lodeline scan` from the home folder no longer scores your Codex config a
  second time as a project. Codex does not load its own home folder as a project layer,
  so those findings were duplicates. A home folder that is a repository is handled the
  same way. The project's `AGENTS.md` is still scanned. (#427)

- On Windows, `lodeline-hook install` now writes a hook command that Claude Code and
  Codex can run. It used to write a `\\?\C:\...` path with backslashes. Claude Code runs
  hooks in Git Bash, which drops the backslashes, so the command failed and the hook did
  nothing. The path now uses forward slashes for every agent. A path with a space is
  quoted. That runs under Git Bash, but not under PowerShell, which Codex uses on
  Windows, as does Claude Code without Git Bash. Install prints a warning in that case.
  Keep `lodeline-hook.exe` in a folder whose path has no spaces. Reinstalling over an
  existing entry replaces it. If you installed hooks on Windows, rerun
  `lodeline-hook install --write` for each agent after you upgrade. (#428)

- On a host where the agent runs as root, a user-global rule pack now reads each user's
  home. It used to resolve `~` and `$HOME` from the agent's own environment, so it never
  read any user's config. Other variables in a rule-pack path still come from the
  agent's environment. (#429)

- When the agent's home and a user's home are two spellings of the same folder, for
  example through a symlink or `sudo` without `-H`, that home is now read and reported
  once instead of twice. Findings on a symlinked home now show the resolved path, so
  each affected reading sends one new event after the upgrade. (#429)

- A corrupt or unsupported shared MCP baseline file no longer stops the Codex MCP
  assessment for every home. It is treated as absent and logged. (#429)

- `lodeline-proxy` now deletes a local registry entry once the server has acknowledged it
  and every event that references it, so the local registry no longer grows without
  limit. While the server is unreachable, queued complete inventory reports are capped at
  256. Past the cap, the oldest one that is not the latest for its scope is dropped, and
  the next report restates its baseline. Every dropped report, complete or incomplete, is
  counted in `registry.discarded_reports` in the proxy status. (#432)

- The `lodeline scan` table now lines up when a scope path has non-ASCII characters,
  such as a Korean user folder or an accented name. Column widths used to count bytes,
  so the columns after such a path were out of line. The JSON output is unchanged.
  (#434)

- The agent now notices a rule-pack file that changed or was removed without a file-watcher
  event. With `--poll`, and on file systems where the watcher only sees whole-second times,
  a rule-pack file written and then deleted or edited within the same second could leave the
  old rule pack in force until some other change. The agent now checks the file every 5
  seconds against the one in force and reloads when they differ. (#433)

- `lodeline scan` and `lodeline-hook install|uninstall --agent codex` now use `CODEX_HOME`
  when it is set, as Codex does. Before, they always used `~/.codex`, so the scan showed
  no Codex settings and the hook was written to a file Codex does not read. With `--home`,
  scan ignores `CODEX_HOME`. The background agent does not read it. (#438)

- `lodeline-server` no longer drops a host's other AI Guard readings early when one
  agent's clock runs ahead. It used to age readings by the agent's own timestamp, so one
  reading dated days ahead made the 48-hour cleanup remove the host's other readings, and
  that reading stayed too long. Readings are now aged by the earlier of their timestamp and
  the time the server received them. The event's own timestamp is unchanged in stored data,
  SIEM output and the API. (#436)

- A root `lodeline-agent` now re-lists the host's users every 15 minutes. Users added
  after it started are assessed, and the readings of removed users are dropped. On Linux
  it also reads the system user database, so directory users (SSSD, LDAP) with a home
  folder in `/home`, or beside a local user's home, are included. Users with UIDs above 65535 are now included too.
  (#437)

- A root agent now watches other users' external hook scripts. A change to one
  re-assesses the user whose settings run it. (#437)

## [0.12.2] - 2026-11-03

### Added

- The scanner now scores the keys in a repository's `.claude/settings.json` and
  `settings.local.json` that run commands or redirect traffic, and reports five new
  reason kinds. `project_settings_plugin_enabled` (2.5) is `enabledPlugins` set to
  `true`, which Claude Code applies at session start before the trust prompt and under
  `-p`. `project_settings_helper_command` (2.0) is `apiKeyHelper`, `awsAuthRefresh`,
  `awsCredentialExport`, `gcpAuthRefresh`, or `otelHeadersHelper`, which `claude -p` and
  the SDK use in a folder you never trusted. `project_settings_env_override` (2.0) is an
  `env` variable that redirects traffic, loads code, or weakens TLS. `project_settings_ui_command`
  (1.0) is `statusLine`, `subagentStatusLine`, or `fileSuggestion`, which run only in
  interactive sessions after trust. `project_settings_marketplace` (1.0) is
  `extraKnownMarketplaces` or `additionalMarketplaces`, honored after trust. Loopback
  redirects are skipped, and user-scope settings are not scored. Number and boolean `env`
  values count as strings. The first three kinds are drift toggles, so a key that appears
  after the agent starts raises a drift alert, and a key already present at start does not.
  Evidence holds only key names, variable names, plugin and marketplace names, and hosts.
  It never holds a command or an `env` value. A name with other characters, and a GitHub
  repository with userinfo, is recorded as `<redacted>`. Blocking stays opt-in. Upgrade
  `lodeline-server` before the agents. An older server rejects the Claude Code
  project-scope risk reading from a newer agent, only that one event and not the batch,
  so the fleet view keeps that host's last reading until the server is upgraded. Other
  events, drift alerts included, still arrive. (#199)

- The scanner now reads Claude Code MCP servers from `~/.claude.json`. That file holds
  the user-scope servers (top-level `mcpServers`) and the local-scope servers
  (`projects.<path>.mcpServers`), which is where `claude mcp add` writes. Each server
  goes through the same MCP checks as a `.mcp.json` server, so a host can show new
  `mcp_server_*` and `no_sandbox` findings, and a host that has only `~/.claude.json`
  now shows a Claude Code row. The scanner reads only the `mcpServers` subtrees and each
  project's `disabledMcpServers` list. It never reads OAuth, account, or session data,
  or any server's `env` or `headers`, and it does not report credentials in a remote
  server URL. A file over 16 MiB, or one that does not parse, is skipped with a warning.
  A malformed project entry is skipped and the rest load. The scanner skips servers
  disabled for their project, and local servers of a project whose directory no longer
  exists. If the directory check fails, for example on an unmounted volume, it keeps
  those servers. It scores an identical definition once. It does not yet read plugin
  MCP servers. For `managed-mcp.json`, see the Changed section. For `CLAUDE_CONFIG_DIR`,
  see the Fixed section. (#199)

- The Codex scanner now scores `approval_policy` and `default_permissions` in a
  repository's `.codex/config.toml`, and the rule files in the repository's
  `.codex/rules/`. The user scan also reads the system `/etc/codex/rules` folder, which
  Codex always loads. The agent watches both new rules folders. Project settings count at
  full weight whatever the project's trust level, because Codex asks for folder trust
  again on each start and the prompt does not list the project's settings. A new reason
  kind, `mcp_tools_auto_approved` (1.0), reports an MCP server with a tool set to
  `approval_mode = "approve"`, and its evidence holds the server name and the tool names.
  A server with `default_tools_approval_mode = "approve"` reports the existing
  `trusted_mcp_server`. Evidence from repository and system rules records only the
  program name, which is the basename when it uses safe characters, is at most 32
  characters, and is not shaped like a token. Otherwise it records `<redacted>`. Evidence
  from `~/.codex/rules` is unchanged. Upgrade `lodeline-server` before the agents. An
  older server rejects the one event that carries `mcp_tools_auto_approved`, not the
  batch. The scanner does not yet read Codex profile layers, `apps.*.tools` approval
  modes, or custom `[permissions.x]` profiles. (#200)

### Changed

- `lodeline-hook install --agent codex` now prints a trust step. Codex runs a user-level
  hook only after you trust it, and skips an untrusted hook with no warning. After you
  install, open `/hooks` in Codex and trust the Lodeline hook. Reinstalling changes the
  hook command, so trust it again. The old step of enabling hooks in `config.toml` is
  gone, because `hooks` is on by default in Codex. Blocking stays opt-in. (#200)

- A host with a Claude Code settings file and no effective `defaultMode` now reports
  an `auto_approval_enabled` finding with mode `auto (built-in default)`, and its score
  rises. Claude Code 2.1.283 and later starts interactive sessions in `auto` when no
  `defaultMode` is set, so the scanner scores the auto classifier and runs the
  `autoMode` defaults check. The scanner cannot read the installed Claude Code version,
  so it assumes 2.1.283 or later. `claude -p` sessions, unsupported models, HIPAA
  configurations, and organization policy can still start in default mode, and the
  finding's hint says so. The scanner now resolves the start mode in Claude Code's order.
  Managed settings come first (`managed-settings.json`, then its drop-ins in alphabetical
  order), then the user file. `disableAutoMode: "disable"` turns auto off, including an
  explicit `auto`. It is accepted at the top level or under `permissions`, in user, local,
  or managed settings. `auto` or `bypassPermissions` in a local or project file does not
  take effect in Claude Code, so the scanner no longer scores it. A local `auto` reports
  the built-in default, and a local `bypassPermissions` starts in default mode. A project
  `acceptEdits` is now scored. Allow rules that Claude Code skips (`*`, `**`, `B*`,
  `mcp__*`) no longer count as `permissions_allow_broad`. `Bash(*)` and
  `mcp__<server>__*` still do. Rule ids are unchanged. The agent does not emit a drift
  event on upgrade, because it holds the drift baseline in memory. The scanner does not
  yet read server-managed settings, the macOS managed-settings plist, or the Windows
  registry. (#199)
- Claude Code `PowerShell` and `Monitor` calls now reach `lodeline-hook` rules. A
  `Bash` command rule now also matches a `Monitor` call that has a `command`, and a
  new `powershell` action that carries the raw `PowerShell` command text. A
  `Monitor` WebSocket watch (`ws`) stays `Other`. A rule matches the raw text with its
  own regex, case-sensitive unless it starts with `(?i)`, so `rm\s+-rf` does not match
  `Remove-Item -Recurse`, `ri`, or an upper-case spelling. To cover PowerShell, write
  the PowerShell forms and add `(?i)`. The shell normalizer and the `bash_indirection`
  rules do not run on PowerShell text, because the normalizer reads PowerShell's
  backtick escape as command substitution. A rule written as `Other` with label
  `PowerShell` or `Monitor` no longer matches command calls. Move it to a `Bash` rule.
  Blocking through `lodeline-hook` stays opt-in. A new `lodeline-hook` that talks to an
  older agent sends an action the agent cannot decode, so the hook takes its
  `--on-failure` mode. The default `open` allows the call. With `--on-failure closed`,
  every PowerShell call is blocked until the agent is upgraded, so upgrade the agent
  before the hook on fail-closed installs. An older hook with a newer agent works as
  before. (#199)
- The Codex scanner now follows current Codex, checked against `rust-v0.166.0`. A
  `prefix_rule` with no `decision` counts as an allow, as Codex treats it.
  `default_permissions = ":danger-full-access"` now reports `sandbox_disabled`. The
  highest config layer that sets `default_permissions` or `sandbox_mode` decides, and
  within one layer `default_permissions` wins. MCP servers with `enabled = false` are no
  longer reported, because Codex does not start them. The scores of hosts with these
  settings change on upgrade. (#200)

- The Claude Code scanner now scores the content of managed settings files, not only
  their restriction controls. It reads `managed-settings.json` and then
  `managed-settings.d/*.json` in name order, and applies the checks it runs on user
  settings: hooks with a broad matcher, hooks that forward to an http URL, hooks that run
  a destructive or unscanned script, broad `permissions.allow` rules, `autoMode` lists
  that drop `$defaults`, and the managed `defaultMode`. Evidence ends in
  `(managed file)`, and weights match user scope. Managed hooks always run, so a host
  with managed settings can now score higher than before. A host with managed settings
  and no `~/.claude/settings.json` is now scored. A managed file that sets permissions
  but no mode reports Claude Code's built-in `auto` start mode. A managed file with only
  unrelated keys, such as `sandbox`, still reports nothing. `autoMode` lists combine
  across user and managed settings, and one `$defaults` in either file keeps the
  defaults. A hook or allow rule that appears in both user and managed files is scored
  once, and the agent watches the scripts that managed hooks run. No new reason kind is
  added, so older servers accept the events. The scanner does not read the macOS managed
  preferences domain, the Windows registry, or server-managed settings. Two hooks with
  the same event and matcher but different commands in user and managed files count as
  one. (#413)

- The Claude Code scanner now honors `disableAllHooks`. When it is `true` in effect, the
  scanner stops scoring the hooks Claude Code turns off. These are the hooks in settings
  files and in skill and agent frontmatter. In project settings they also include the
  `statusLine`, `subagentStatusLine`, and `fileSuggestion` commands. The scanner reads
  the setting in Claude Code's precedence order: managed, then local, project, and user.
  Only a managed `disableAllHooks: true` turns off managed hooks, so managed hooks are
  still scored otherwise. A host that turns hooks off now scores lower. The scanner does
  not yet let a user-level `disableAllHooks: true` stop project hooks from being scored.
  No new reason kind is added. (#415)

- The scanner now scores each Claude Code `PermissionRequest` hook as a standing
  approval, the way it scores an auto-approval mode. A `PermissionRequest` hook can answer
  Claude Code's permission prompts, so a host with one can approve tool calls that a
  person would otherwise confirm. A hook that only logs still scores, because the scanner
  cannot tell it from an approving hook by reading the settings file. Evidence names only
  the tool or matcher and never the hook's condition text. The scanner reports at most a
  fixed number of these hooks per file. No new reason kind is added, so older servers
  accept the events. (#415)
- The Codex scanner now follows `default_permissions = "<name>"` to the matching
  `[permissions.<name>]` profile and along its `extends` chain, in user and project
  config. A profile that grants filesystem write on `:root`, `/`, `~`, or a drive root
  now reports `sandbox_disabled`, and a trailing `/**` on those paths counts the same.
  Extra writable paths and network-only openness are not scored. No new reason kind is
  added, so older servers accept the events. The score of a host with a wide-open
  profile rises on upgrade. (#414)

- Codex MCP server and app auto-approval now follow each tool's effective approval
  mode, which is the tool's own setting or else the default of its server or app. The
  scanner honors `enabled_tools` and `disabled_tools`. A server whose default is
  `approve` but whose tools all prompt is no longer reported as `trusted_mcp_server`,
  unless tools that the config does not name keep the `approve` default. The scanner now
  reads `[apps.<id>]` and `[apps._default]`, and reports `[apps._default]` set to
  `approve` as its own finding. It skips apps with `enabled = false` and tools turned off
  by `default_tools_enabled = false`. No new reason kind is added. The score of a host
  falls when the tools of its servers all prompt. (#414)

- The Claude Code scanner now reads MCP servers from the managed settings folder. It
  reads `managed-mcp.json` and the managed `managedMcpServers` setting, and scores each
  server with the same checks it runs on user MCP servers. Evidence ends in
  `(managed file)`, and a remote URL shows only `scheme://host[:port]`. The agent
  watches `managed-mcp.json` for changes. No new reason kind is added, so older servers
  accept the events. (#418)

- The Claude Code scanner now follows how Claude Code treats `managed-mcp.json`. While
  that file is deployed, Claude Code loads only the managed servers and stops loading
  the user's own, so the scanner no longer scores the servers in `~/.claude.json`. A
  managed server with the same name as a user server replaces it. A `managed-mcp.json`
  that cannot be parsed counts as not deployed, so the scanner still scores user
  servers. The score of a host can rise because of its managed servers, or fall because
  its user servers are no longer loaded. The scanner can still over-report in three
  cases. It scores project `.mcp.json` servers while `managed-mcp.json` is deployed,
  though Claude Code does not load them. It scores `managedMcpServers` entries that
  Claude Code would reject. It does not apply `deniedMcpServers` to managed servers.
  (#418)
- The Codex scanner now scores `network_rule(host=..., decision="allow")` in Codex rules
  files as a standing approval, the same way it scores `prefix_rule`. The evidence is the
  host only. A later `deny` for the same host cancels the approval, and a later `allow`
  adds it back, as Codex does. The scanner skips wildcard hosts, because Codex rejects
  them. No new reason kind is added. The score of a host with an allowed network rule
  rises on upgrade. (#417)

- The Codex scanner now scores `network_access = true` under `[sandbox_workspace_write]`
  when the effective sandbox is `workspace-write`. That is the case when the config sets
  it, and also the default for a trusted or untrusted project. This scores lower than a
  disabled sandbox. A `writable_roots` list that includes `/`, `~`, or a drive root is
  scored as a disabled sandbox. The daemon cannot tell which project is active, so it
  scores a user-level `network_access = true` when any project is trusted or untrusted.
  No new reason kind is added. Scores can rise on upgrade. (#417)

- On Windows, the Codex hook check now reads the `command_windows` command (or
  `commandWindows`) of a hook, because Codex runs that command there. A Codex hook with
  an `mcp_tool` handler is now reported as forwarding tool calls, as for Claude Code. The
  scanner still reports an `mcp_tool` hook that points at a local server. No new reason
  kind is added. (#417)

- The Codex scanner now scores `approvals_reviewer = "auto_review"`, and its older
  spelling `guardian_subagent`, as an auto-approval at low weight. With this setting a
  model reviewer can approve a request when no person is involved. The scanner scores it
  only when the approval policy in effect sends requests to the reviewer. Those policies
  are `on-request`, its alias `on-failure`, and granular. A project's policy applies, or
  else the user's. The scanner does not yet read Codex `[profiles.*]`, `requirements.toml`
  `allowed_approvals_reviewers`, or the system config layer for this check. These
  findings reuse existing reason kinds, so older servers accept the events. In score
  breakdowns they appear under the `project_settings_*` names. The score of a host with
  this setting falls on upgrade. (#422)

- The Codex scanner now reads three more keys in the user's Codex config. It reports
  `notify` as a command that Codex runs, and names the key only, never the arguments of
  the program. It reports a non-default `openai_base_url`, or a `base_url` on the selected
  model provider that Codex honors, as a traffic redirect, and shows the host only. It does
  not report built-in providers whose `base_url` Codex ignores, such as `ollama` and
  `lmstudio`. A repository's `.codex/config.toml` cannot set `notify`, `openai_base_url`,
  or provider settings, so the scanner reads only the user file for them. The scanner also
  reports `shell_environment_policy.set` in user and project config, and names the
  variables only, never the values. These findings reuse existing reason kinds, so older
  servers accept the events. In score breakdowns they appear under the `project_settings_*`
  names. (#422)

- The scanner now runs the same instruction-file check on the user's
  `~/.codex/AGENTS.override.md`, or else `~/.codex/AGENTS.md`, that it runs on a
  repository's `AGENTS.md`. No new reason kind is added. (#422)

### Fixed

- A Claude Code host whose managed settings set `permissions.deny` rules no longer gets
  a "deny list empty" finding. Managed deny rules now count toward the deny list. (#413)

- A Claude Code hook with a broad matcher, such as `*`, is no longer reported as a broad
  matcher when every handler has an `if` condition of the form `Tool(arg)` with a
  specific argument, for example `Bash(git *)`. The condition limits the handler to
  those calls. Conditions that do not narrow, such as `Bash`, `*`, and `Edit(**)`, still
  leave the hook reported. (#415)

- `lodeline scan` now honors `CLAUDE_CONFIG_DIR`. When you set it, Claude Code reads
  its user settings, `.claude.json` MCP servers, hooks, `CLAUDE.md`, skills, and agents
  from that directory instead of `~/.claude` and `~/.claude.json`, and the scan now
  reads the same files from the same place. The scan showed such a user as "not
  configured" for Claude Code. An empty value falls back to the home directory, and a
  relative value resolves against the current directory, as in Claude Code. Managed
  settings paths do not change. `lodeline scan --home` ignores the variable, because
  it belongs to the user who runs the command. The agent service does not honor it,
  because a service cannot see a user's shell environment. A host whose user sets
  `CLAUDE_CONFIG_DIR` can still show "not configured" for Claude Code in fleet scores.
  (#411)

- `lodeline-hook` now treats a Codex `apply_patch` call as a file edit. Codex sends the
  patch text in `tool_input.command`, so the hook reported every patch as a Bash
  command. Command deny rules matched against the patch text, and file-edit rules never
  saw the edit. The hook now reads the target paths from the patch headers (`*** Add File:`,
  `*** Update File:`, `*** Delete File:`, and `*** Move to:`) and never reads the patch
  body. It checks every target path, and a file-edit rule denies the call if any path
  matches. A relative path resolves against the call's working directory. Upgrade the
  agent before the hook. A newer hook with an older agent works, but the older agent
  checks only a 256-byte preview of the joined paths, so in practice it checks only the
  first path of a multi-file patch. Hash-only mode sends no paths and still fails open.
  (#200)

- `lodeline reload`, `lodeline show stats|policy-status|targets|risk`, and the live
  AI Guard section of `lodeline doctor` now use `--control-socket` when you give it.
  They ignored the flag and always dialed the default socket, so against an agent
  started on another socket they failed with `cannot reach the lodeline daemon at
  .../control.sock`. Without the flag they dial the same default as before. On Linux,
  the `doctor` socket-permission check follows the flag too. On Windows the flag is
  still ignored and these commands use the default named pipe. `lodeline status`
  already honored the flag. (#392)
- `lodeline scan` output and posture events no longer carry credentials from a URL.
  They used to report a remote MCP server's URL as configured, and the destination of a
  Claude Code `http` hook, including any userinfo, path, query, and fragment. They now
  report only `scheme://host[:port]`. The path is dropped too, because hosted MCP
  servers put per-user tokens in path segments. A URL is reported as `<unparseable-url>`
  when its host is not plain ASCII (an IDN host), its host is longer than 253
  characters, its port is above 65535, or it is a bare token with no dot or colon. A
  rule pack that puts a URL value into a message field gets the same redacted form.
  Rule matching still runs on the full configured value, so a rule that matches a
  scheme such as `http://` behaves as before. The reported reasons change text on
  upgrade, so expect one fresh assessment for each affected host. (#403)
- Four AI Guard fixes for Claude Code configuration and rule-pack messages. When
  managed settings set `permissions.defaultMode`, a project `defaultMode` such as
  `acceptEdits` is no longer scored, because the managed value decides the start mode.
  A `~/.claude.json` whose `projects` key is `null` is no longer dropped, so its
  user-scope servers load. A rule-pack message that interpolates a configured value now
  reports a value under a key ending in `url`, `uri`, `endpoint`, `address`, or `host`,
  or one that starts with `scheme://`, as `scheme://host[:port]`, and keeps a bare host
  such as `localhost`. Any other value keeps its text except a `user:password@` part,
  which becomes `<redacted>@`. A plain `user@host` and an image digest (`@sha256:`) stay
  as they are. A password that contains an unencoded `?` or `#` is not detected. The
  hint for the built-in auto mode also names HIPAA configurations as starting in default
  mode. (#199)
- The Codex scanner no longer puts a command's arguments into event evidence. A
  standing approval in a Codex rules file (`prefix_rule` with an allow decision) used to
  record the rule's whole command prefix, and the later words of a command can hold
  tokens. Every rules layer (user `~/.codex/rules`, `/etc/codex/rules`, and project) now
  reports only the program name. A program path whose parent folder is a home folder,
  such as `/home/alice` or `C:\Users\alice`, is reported as `<redacted>` so that a user
  name does not appear. A Windows path now reduces to its file name (`C:\x\y.exe`
  becomes `y.exe`) instead of being redacted whole. (#410)
- The Codex rules scanner now reads strings the way Starlark does. An escaped quote, a
  raw string, or a triple-quoted string no longer makes it skip a real allow rule, and
  `prefix_rule(` inside a string, or called as a method, is no longer counted as a rule. (#410)

- `lodeline-mcp` in fleet mode no longer writes the full `LODELINE_SERVER_BASE_URL` to
  its log or to the MCP client. It logged the value as written at startup. When it could
  not reach the server, it also returned an error to the MCP client that held the base
  URL and the request URL. A base URL with a user name, password, path, or query string
  appeared in both places. Both now show only `scheme://host[:port]`, or `<redacted>` when
  the URL does not parse. The read token was never logged or returned. Logs and MCP
  client transcripts from earlier versions still hold the base URL as written. (#412)

- `lodeline assess`, `lodeline show`, and `lodeline doctor` no longer treat a
  `policy.yaml` they cannot check as absent. A permission error on the policy folder, or
  a path component that is a file, used to make all three use the built-in defaults
  without saying so. Now only a missing file means "no policy", and a missing file still
  uses the defaults as before. `lodeline assess` exits 1 with `policy load failed` and
  the file name. `lodeline show` exits with the read error. `lodeline doctor` prints
  `[ERROR] cannot read policy` and counts it. The agent service already failed on such
  errors, and a `rule-packs.yaml` read error already behaved this way. (#416)

- On macOS, the agent no longer misses a watched file whose name has non-ASCII
  characters, such as Korean. APFS keeps a name in the Unicode form it was created with
  (NFC or NFD), and FSEvents reports those bytes, while policy paths are usually NFC. A
  file created in NFD under an NFC policy path did not match, or matched without its
  earlier hash. The agent now converts event paths and policy paths to NFC in one place,
  before matching and before the hash cache, so the match, the earlier hash, and the
  reported path agree. Reported paths for such files are now NFC. ASCII paths are
  unchanged, and Linux and Windows still match paths byte for byte, because those file
  systems treat NFC and NFD as different names. After you upgrade, a file that a wildcard
  pattern matches and whose stored name is NFD can report once as "created" without an
  earlier hash, because its saved state used the NFD name. Files that the policy names
  exactly are hashed again at start. On macOS volumes that are not APFS or HFS+, such as
  SMB, NFS, or exFAT, opening the NFC form of an NFD name can fail, so the hash for such
  a file can fail. (#419)

- On macOS, `lodeline-hook` file-edit deny rules now match a path whether the rule and
  the tool call spell an accented name in composed (NFC) or decomposed (NFD) form. A
  rule for a name such as `café` used to miss a tool call that spelled the same name the
  other way. Regex rules written for the decomposed form keep matching. A `not_equals`
  rule now treats two Unicode spellings of one name as the same path. A rule whose regex
  would become invalid after normalization stays loaded as written. Other platforms
  compare paths as before. (#423)

- `lodeline-proxy` no longer restarts its quarantine allowance each time it restarts.
  After a run of server refusals it stops sending and quarantines at most one event per
  `max_backoff`, but it kept the count of that run in memory. Under the packaged
  restart-on-failure, every restart allowed the full run again, so quarantine during a
  long run of refusals had no limit. The count is now saved as `single_quarantines` in
  `gap_queue.json`, and only an HTTP 200 from the server clears it. A proxy that restarts
  at the limit still sends one request per `max_backoff`, so the next 200 clears it
  without operator action. The field is present only while such a run is in progress. An
  older `lodeline-proxy` refuses to start on a `gap_queue.json` that holds it, so to
  downgrade during a run, wait for a 200 first or remove `single_quarantines` from
  `gap_queue.json` while the proxy is stopped. (#420)

- `lodeline-mcp` no longer includes the fleet read token in its config's debug output.
  The debug output shows the server URL without credentials, path, or query. No caller
  printed it before. This keeps a future one from doing so. (#424)

- A project's Codex `approvals_reviewer = "auto_review"` finding now respects an
  `approval_policy` set in the system Codex config when the user config sets none. A
  host-wide `never` no longer produces that finding. Changes to the system config now
  rescan projects. (#425)

## [0.12.1] - 2026-11-02

### Added

- `lodeline status` shows whether a fleet host really reaches `lodeline-server`. A
  running `lodeline-sender` now writes `sender-status.json` next to its offset file,
  at start, on a change of state, and every 30 seconds. The file has mode `0640` and
  holds only timestamps and enums, never a URL, token, or server message. `status`
  reads the file with no network call and shows never reported, awaiting contact,
  connected, failing, stale (no report for 90 seconds), or unreadable. It also shows
  whether the client certificate is valid, expires within 7 days, or has expired.
  In `lodeline status --json`, `fleet.link` carries these states and
  `fleet.client_cert` is new. `schema_version` is now 2 because the `unknown` link
  state is gone. The status file is not authenticated: it is a local diagnostic, and
  anyone able to write its directory can make it say anything. In the packaged layout
  that is the `lodeline` user and root.

- `lodeline-sender doctor` now runs real checks: config, certificate and key files
  and their permissions, certificate expiry, events directory, agent control
  endpoint, and status file. It exits 1 on a failure. It previously printed four
  `[OK]` lines without checking anything. It makes no network call and never reads
  the key.

- `lodeline status` and `lodeline status --json` show whether Lodeline is healthy
  on this host: which components are installed, whether the agent is running, and
  the configured `lodeline-server`. A host with no sender config reads as single
  host. The command is read-only and needs no daemon, no fleet, and no network.
  `--sender-config` names the config of a sender started with `--config`. The data
  comes from the new `lodeline-diag` library, which a later diagnostic UI will use
  too. The JSON carries `schema_version`. A build with `--no-default-features`
  leaves the command and the library out.

- lodeline-proxy status reports now carry `central.ingest_stopped: true` while
  ingest is stopped (see Fixed), and the proxy reports `spool.state` as `degraded`
  instead of `ok` during that time. The field is sent only when true, and absent
  reads as false. The server's proxy detail API returns it under `central`.
  `lodeline-proxy health` prints it too; its exit code does not change. Upgrade
  lodeline-server first: its status parser rejects unknown fields, so an older
  server refuses the status reports of a stopped proxy. A proxy that is not stopped
  reports to an older server as before. Downgrading lodeline-server fails at boot
  only while the stored proxy state holds `ingest_stopped`, because older servers
  reject unknown fields. The server stores it when a proxy's last report was sent
  while stopped, and the next report after the stop ends removes it. Otherwise
  remove the field from the stored proxy state by hand. (#339)

### Fixed

- A policy reload that keeps the previous state now runs again on each 5-second root
  tick until it finishes, and a new wake clears the record of earlier failures. A
  policy file or rule-pack bundle that is fixed by hand or returns loads within about
  5 seconds, with no `lodeline reload`. The log has one line per wake and one per new
  reason, so a retry with the same reason logs nothing. The warning `rule-packs.yaml
  unusable; retaining last good bundle` replaces two earlier messages, and an empty
  bundle now warns once. The cold-load error for a corrupt bundle names the reason. A
  deny-rule validation or compile failure keeps the previous evaluator and does not
  retry. While a bundle stays unusable, a retry applies a changed or removed policy
  file and compares nothing else, so other changes wait for a wake. A retry can load a
  valid file that the operator is still saving, without `lodeline reload`, but only
  after a failed reload.

- A signed policy or rule-pack bundle now applies on a packaged or root agent with no
  `--policy`. The agent wrote these files to `/etc/lodeline`, which `lodeline.service`
  keeps read-only, so every apply failed with `Read-only file system (os error 30)` and
  the host stayed on its old policy. Applies now land in
  `/var/lib/lodeline/applied/policy.yaml` and `rule-packs.yaml`. Each applied file
  replaces the content of its namesake in `/etc/lodeline`, as an apply over that file
  did before, and the two files resolve separately. `/etc/lodeline` is no longer
  written, so a hand edit there has no effect while the applied file exists. To go
  back to the local file, delete the applied one and run `lodeline reload`. A host that
  an older agent applied into keeps loading that file, with its version intact, until
  the next apply lands in the new path. Nothing in `/etc` is moved or deleted.
  `lodeline show paths` and `lodeline doctor` now print the file in force. `--policy`,
  non-root agents, and Windows do not change. `lodeline assess` reads the applied
  files first. On the packaged Linux install `/var/lib/lodeline` is `0750 root:lodeline`,
  so a user outside the `lodeline` group gets one warning on stderr and a verdict from
  `/etc/lodeline`, which can miss signed rules. Add such a user to the group. Any other
  error checking an applied file also gives one warning and a verdict from
  `/etc/lodeline`. After the applied file is deleted, `lodeline status` keeps reporting
  the signed version and its expiry while the local file runs, and only a higher
  version lands.

- A reload on a host with no policy file now loads the built-in defaults and any
  rule-pack bundle, as a boot does. It used to keep the previous state, so a bundle
  applied to such a host had no effect until a restart. A policy file that was loaded
  and has since gone missing still keeps the previous state, with a warning, until the
  file returns or the agent restarts. That includes deleting an applied policy with no
  file in `/etc/lodeline`.

- A policy path that cannot be checked, such as one under a regular file, now stops the
  boot, for non-root agents too. It used to count as no policy file, so the agent ran
  on the built-in defaults.

- On Unix, a signed apply into a new directory now syncs that directory into its
  parent before the file lands, so a power loss no longer removes the file while its
  version stays recorded. The agent synced the file into the directory but not the
  directory into its parent. A boot that finds the policy file's directory missing
  creates it and syncs it the same way. An existing directory is left as it is. Windows
  does no directory sync.

- `lodeline run` without `--policy` now loads the policy at its default path at
  boot. Before, boot read a policy file only
  with `--policy`, while a signed apply and a reload used the default path. A restart
  dropped the deny rules and targets of an applied policy while `lodeline status`
  still showed its version, and redelivering that version did not restore them. The
  default path is `/etc/lodeline/policy.yaml` as root, and
  `$XDG_CONFIG_HOME/lodeline/policy.yaml` or `~/.config/lodeline/policy.yaml`
  otherwise.
  - A policy you placed at that path by hand now loads at boot too, as the install
    guides describe. A file that cannot be read or parsed, or that overrides a
    built-in id this OS does not have, stops the boot, as it does with `--policy`.
    Check any file at that path before you upgrade. `lodeline doctor` reports one
    that fails to parse.
  - `lodeline show config`, `show paths`, and `doctor` read the same file when
    `--policy` is absent.
  - `config/policy.example.yaml` no longer overrides a macOS-only target, which would
    stop the boot on Linux and Windows. If you copied the old example to
    `policy.yaml` on either, remove its `shadow-ai-binaries-macos` override before
    you upgrade.

- On Unix, boot and the next apply now sync the config directory before they finish an
  apply that stopped after its rename. Before, the applied version could be recorded
  while the rename was not yet durable, so a power loss could leave the record ahead of
  the file. If the sync fails, the apply stays pending and the next boot or apply settles
  it. A signed apply also works when `--policy` is a bare file name; before, it failed
  every time at the directory sync, after the file had already moved.

- The agent keeps the applied version and expiry of a signed policy or rule-pack
  bundle across a restart. An apply now records its version, the blake3 of its bytes,
  and its `valid_until` in `state.db` before the file moves, and promotes them after
  the rename. Boot compares that record with the file on disk: if the bytes match, the
  apply is finished, and if not, the record is dropped and a retry applies. Before, a
  stop between the rename and the record left the version behind the file, and an
  older signed version could then replace the newest. If this repair fails, the agent
  stops at boot instead of serving a stale version.
  - A running agent makes the same check before every apply. Before, an apply that
    failed after the rename, at the directory sync or the record write, left the
    version behind the file while the agent kept running, and an older signed version
    could then replace the newest. It is now refused with `version_regression`, and
    the status, the expiry, and the loaded policy follow the finished apply. If the
    check fails, that apply returns an error and writes nothing. A retry of the
    document that failed finishes it and gets `version_regression`, because it is
    already applied.
  - `policy_status` now reports the real `active_envelope_valid_until` and
    `policy_expired_active` after a restart. The expiry monitor checks at boot, so a
    restart on an expired policy reports `policy_expired_active` at once instead of
    after 60 seconds.
  - Boot no longer reads the YAML `version:` key of `policy.yaml` as an envelope
    version. A host that has only a local policy now reports version 0, and a first
    envelope v1 applies. Before, it reported 1 and refused v1 with
    `version_regression`.
  - Upgrade: new tables are added to `state.db` at open. A host keeps its recorded
    version. Its expiry is unknown until the next apply: `active_envelope_valid_until`
    stays `null`, `policy_expired_active` stays `false`, `lodeline show policy-status` prints
    `(unknown until the next apply)` and `unknown`, and `lodeline status` prints
    `expiry unknown until the next apply`. A recorded policy version of exactly 1 with
    no expiry reads as no envelope, because older agents wrote it for any local file.
    This also applies to a host that really applied v1: it reports version 0 until the
    next apply, and accepts v1 again. No envelope is lower than v1, so this cannot
    lower a policy.
  - Downgrade: an older agent ignores the new tables and keeps reading the same
    version columns. A version it applies has no expiry row, so a later upgrade reads
    that expiry as unknown.
  - `lodeline status --json` adds `valid_until` to `signed_policy`.

- `lodeline-sender` now waits before it retries after it fails to save its offset.
  Before, it sent the same batch again at once, in a tight loop, and wrote the
  server's per-event rejections to the dead-letter directory each time. It now uses
  the same backoff as a server error, 5 seconds doubling to 5 minutes. The offset
  stays where it was, so the batch is sent again whole and no event is skipped.

- `lodeline-sender` now caps the server text it stores in the dead-letter directory
  at 512 bytes, cut on a character boundary and marked with `…`. Before, a status
  body, an unparseable reply, a batch rejection, or a per-event rejection reason went
  in whole, so a misbehaving server could fill the disk of a host. The directory
  holds one file a day. When it starts a new file it keeps 30 at most, removes the
  oldest, and logs how many. It never removes the file it just wrote, even when the
  clock was set back. A batch reply gets at most 20 per-event rejection entries. The
  rest are counted in one `server_protocol_violation` entry, so each batch adds at
  most 21 entries however many events the server rejects. A file has no size limit
  within its day beyond these bounds.

- `lodeline-sender` now gives up on a request to `lodeline-server` that gets no answer.
  The HTTP client had no timeout, so a server that accepted a connection and never
  replied held the request open and the link state stayed `connected` with an aging
  last success. A connection now has 10 seconds to open and a whole request 120
  seconds. A full 1 MiB batch, the default size, fits that on a link of about 70
  kbit/s. A timed-out request counts as a network failure and the link state shows
  `failing`. So does a timeout or a dropped connection while the sender reads the
  response body. Before, that counted as a protocol violation and wrote a dead letter
  on each retry, and on a policy poll that got a 404 it read as an unknown host. The
  same holds when the status is an error: a 409 whose body is cut off is now retried
  as a network failure, not treated as a permanent rejection. A
  body that arrives and does not parse is still a protocol violation.

- `lodeline-hook --enforce --on-failure closed` now covers a panic and a watchdog exit.
  Both left empty stdout and exit 0, which most agents read as allow, so an operator
  who chose closed mode got allow on those paths. Each now gives the agent's deny
  output, the same as when no verdict is available. The hook writes one response at
  most, so a late failure path cannot add a second one. The default open mode does
  not change: a panic or a watchdog exit stays silent with exit 0. A signal or an
  abort still ends the process with nothing written.
  With `--enforce --on-failure closed`, an unknown agent name now exits 2 with a reason
  on stderr, where it exited 0 before. With `--on-failure open` it still exits 0.

- A path template with non-ASCII text, such as `$HOME/한국어/설정.json`, now expands
  to that same text. Before, `expand` pushed each byte of the literal text as a
  separate character, so the path came out as mojibake and a target with a
  non-ASCII path never matched a file. `lodeline doctor` reported such a file as
  "not present". Token parsing is unchanged, and a bad token still returns
  `Malformed`. (#379)

- Policy and rule-pack applies now run one at a time. Before, an older version sent
  at the same moment as a newer one could pass the version check and land last, so
  the file on disk and the recorded version moved backward. An apply now reads the
  recorded version, verifies, writes, and publishes the result under one lock, so an
  older version is refused with `version_regression` and changes nothing. Status
  requests and policy reloads do not take that lock. The recorded versions also
  refuse to go down on their own: a lower version returns
  `StateError::WouldLowerVersion` and leaves the value as it was, and `apply` reports
  that as an internal error.

- A signed policy or rule-pack bundle that the agent could not load at boot is now
  refused. Before, such a document passed `apply`, advanced the version, and then
  stopped the next boot or turned hook deny rules off. `apply` now rejects it with
  `parse_failed` before anything is written, so the policy on disk, the version, and
  the running policy stay as they were. This covers an unsupported `version`, text
  that is not UTF-8, a hook deny rule or rule-pack regex that does not compile, a
  target path that does not compile as a glob, a `hook_silence.tick_secs` of 0 with
  an agent enabled, and a policy that does not merge over the defaults of the host.
  `lodeline-sign sign` now stops on the same mistakes before it signs, and it writes
  no bundle, with two limits. It does not check the merge, because the file does not
  say whether it is a policy or a bundle, and only a policy has to merge. It checks the target paths for its own OS and for `platform: any`, so
  a target for another OS is checked by `apply` on that OS.
  `lodeline-sign verify` reports the same document errors.

- `lodeline-sender` stopped asking for a policy or rule-pack bundle when the server
  sent it, before the agent answered. If the agent was down, every later poll got a
  `304` and the document stayed undelivered until the next publish or a sender
  restart. The sender now asks until the agent settles the document. It retries at
  the poll interval after an outage or an agent failure. It stops when the agent
  applies the document or refuses it as an old version, which only a new document
  can change. Every other refusal can lift with the document unchanged, because the
  host's clock, its keystore, or the agent's version also decides it. The sender
  offers such a document on every 12th poll with no restart, which is 24 full fetches
  a day at the default interval. Each refused offer also records a warning event.
  `policy-etag.txt` and `rule-packs-etag.txt` now take effect at startup, so a
  restart no longer fetches a settled document and the agent no longer records a
  version regression for it. If you reset the agent's `state.db` and keep the sender
  state, publish a new document or remove those two files.

- `lodeline-sender` reported every TLS failure as a network failure, so the
  `tls_failure` dead-letter event was never written. It now finds the TLS cause in
  the error chain, and it writes one event per failure streak, whatever the reason text,
  separately for events and policy, because that directory has no rotation.
  Stored reasons hold the cause only, never the request URL.

- `lodeline-sender` treated the 404 of a server with no policy as an unknown host and
  wrote a `host_id_conflict` dead-letter event at each poll. It now treats that
  answer as no change.

- `lodeline-proxy`: a server that refuses every event by index no longer moves the
  whole queue into quarantine. These answers now count toward the existing limit of
  8 answers, not 8 events, and only a 200 clears the count. An SV-3..SV-5 answer
  names every bad event in its batch, so a 2000-event storm quarantines 800 events
  before the limit, and an unparseable shape quarantines 8. Past the limit ingest is
  stopped: the proxy backs off and quarantines one event per max backoff period
  (300 s), however many events the answer names. That keeps loss to at most 288
  events per day and stops a permanent refusal from blocking good events behind it
  until R. The measured mean is about 449 s per event, about 192 per day, so about
  R/449 s events drain: about 5770 in a 30-day R. After a server upgrade the next
  retry comes within 360 s (300 s max backoff plus 20% jitter) and the first 200
  clears the stop. At a batch size of 100, about 7.4% of events refused on the parse
  path, about 8 in 108, stops ingest. At 1 in 10 refused, throughput falls below
  0.1 events/s, and only refused events are quarantined. (#339)

- lodeline-proxy no longer scans the spool's `events` table for acknowledged rows
  on each maintenance pass, so appends wait less behind it. The new partial index
  is added to existing spools on open, with no schema version change.

- lodeline-proxy no longer sorts every unsent event to find the oldest one after each
  acknowledged batch. At 1M unsent events that took about 21 ms on the writer
  thread, so appends waited behind it. The query now walks `idx_unsent` and takes
  about 2 microseconds. (#359)

- lodeline-proxy status said the spool was `ok` while the relay already refused calls.
  The status reported `full` only when no byte was left, but admission refuses any
  event larger than the room that remains. Both now use one rule. The status is
  `full` when an event of `event_max_bytes` (16 KiB by default) no longer fits, so
  `ok` means every allowed event is admitted. A smaller event can still fit while
  the status says `full`. (#362)

- lodeline-proxy refuses a `limits:` config whose `spool_max_bytes` minus
  `spool_gap_reserve_bytes` is below `event_max_bytes`. Such a spool reported
  `full` from the start while it still admitted smaller events. (#362)

- lodeline-proxy, stopped by a server that answers 409 or 422 without naming an
  event: the client sent two requests every 5 seconds, because each unnamed answer
  cleared the backoff. It now sends one request per max backoff (300 s with 20%
  jitter), and loses at most one event per period. In a 4500 s paused-clock test,
  requests fell from about 1750 to between 11 and 19. Once the client is stopped, a
  good event behind a refused one waits one to two backoff periods, about 449 s on
  average and about 660 s at most. (#363)

- `lodeline scan` no longer lists a tool as not configured when another scope of
  the same tool was assessed or failed to parse.

- With the SELinux module from `packaging/selinux/lodeline.te` loaded in Enforcing
  mode, `lodeline-server` could not listen on its default port 8443. It failed with
  `Permission denied (os error 13)` and systemd restarted it in a loop. The audit log
  showed a denied `name_bind` on `http_port_t`, the label 8443 carries, because the
  policy allowed only unreserved ports. `lodeline_server_t` can now bind `http_port_t`
  ports as well. Only hosts that built and loaded the module (it needs
  `selinux-policy-devel`) were affected, in every release since the module was added.
  Without the module the daemons run unconfined and nothing changes. Upgrade. If you
  loaded the module by hand from `packaging/selinux/README.md`, rebuild and reload it,
  then restart `lodeline-server`. On Amazon Linux 2023 (aarch64, Enforcing), the
  server then listens on 8443 and all three daemons run confined with no lodeline
  denials. (#397)

## [0.12.0] - 2026-10-31

### Changed

- **Breaking:** Sigil is now Lodeline. Binaries, packages, units, paths, `SIGIL_*`
  env vars and `x-sigil-*` headers all take the new name, and there is no `sigil`
  shim. Hash and signature domains, the release key id and the proxy SAN keep
  their old bytes so existing bundles, stored data and certificates still verify.
  The new `.deb` and `.rpm` packages replace the old ones and move config and state
  to the new paths. Follow [docs/migrate-from-sigil.md](docs/migrate-from-sigil.md)
  when you upgrade: it lists every step an operator must take.

### Added

- lodeline-proxy status reports now carry `spool.quarantined_bytes`, and the
  server's proxy list API returns `spool.quarantined_events` and
  `spool.quarantined_bytes` (the latter null for a proxy that has not reported
  it), so operators can watch quarantine growth. Upgrade lodeline-server first:
  its status parser rejects unknown fields, so a proxy that sends the new field
  to an older server has its status reports refused (#302). Downgrading lodeline-server after a new
  proxy has reported fails at boot until `quarantined_bytes` is removed from the
  stored proxy state, because older servers reject unknown fields.

### Fixed

- The lodeline-proxy systemd unit now sets `StateDirectoryMode=0700`. It was
  0750, which systemd reapplies on every start, and lodeline-proxy refuses a
  state directory with group or other access, so the packaged proxy could not
  start at the default path.
- lodeline-proxy now deletes a quarantined spool row once its `quarantined_at` is
  older than Q, the server-issued `event_retention_seconds` (E). This covers
  every code, `registry_conflict_original` included. Before this, quarantine
  only grew. The server keeps the matching gap for E after its `detected_at`,
  which is no later than `quarantined_at`, so local evidence lives at least as
  long as the server must keep the gap. Two known limits: proxy clock skew, and
  a gap delivered to the server more than E after the quarantine (an outage
  of at least E; R + E for `spool_expired`). Nothing is deleted
  until the proxy has applied a config that carries E. Each maintenance batch
  that deletes rows logs the count, never the content (#302).
- A wall-clock step no longer ages lodeline-proxy spool rows within a boot. An NTP
  step forward of R or more used to quarantine every unsent event at once, and a
  step of Q or more purged quarantine evidence early. A backward step delayed
  both. Each unsent event and quarantine row now has a `(boot_id, boot clock)`
  stamp, and age uses the boot clock within the boot of the stamp, restarts
  included. Across boots, or for a row with no stamp, age uses the wall clock as
  before. Timestamps on the wire stay wall clock. The stamps are in additive
  tables with the same schema version, so an older binary still opens the
  database (Refs #302).
- The lodeline-proxy systemd unit now orders itself after `time-sync.target`.
  Across a reboot spool age uses the wall clock, so a host that booted with a
  wrong RTC could misjudge the age of older rows until the first clock step. The
  target only waits when a wait service is enabled; the packaging README says
  which one to use (#302).
- On Unix, lodeline-proxy opens its spool and registry databases with
  `SQLITE_OPEN_NOFOLLOW` under the resolved state directory. This closes the
  gap between the symlink check and the open, where the file could be swapped
  for a symlink. Windows keeps the check-then-open behaviour (#302).
- The packaged `/etc/lodeline/sender.yaml.example` now tails `/var/log/lodeline`,
  where the root agent writes `events-*.jsonl`. It pointed at
  `/var/log/lodeline/events`, so a sender configured from it shipped nothing and
  logged no error. A `sender.yaml` copied from an older example needs
  `events_dir: "/var/log/lodeline"` (#328).
- The agent's spool GC now sees how far lodeline-sender has shipped. It looked
  for `<events_dir>/sender-offset.json` in a format the sender never wrote,
  while the sender writes `/var/lib/lodeline-sender/sender-offset.json`. So the
  soft floor never freed shipped segments, and at the hard ceiling the GC
  force-deleted them and raised a data-loss alarm for data already delivered.
  A sender with a non-default `offset_path` still leaves the GC without a
  sender record. Only a root agent reads it; a per-user agent's spool is not
  tailed by the packaged sender (#331).
- lodeline-sender no longer skips the same-day rotations of a segment. The agent
  writes `events-D.jsonl` and then, past 100 MiB, `events-D-001.jsonl`, but
  string order puts `-001` first, so the sender jumped from `events-D.jsonl`
  to the next day and never shipped `-001` onward. The spool GC used the same
  order to pick the live segment and to decide what was shipped. Segments are
  now ordered by date and sequence number everywhere, including
  `lodeline show events`. Rotations a sender already skipped before the upgrade
  stay unshipped. A sender that started on an existing backlog may also
  re-send or skip a few segments once after upgrading (#331).

- An agent running as root on Linux or macOS now assesses every user's AI
  agent configs, not just root's own home. Each user's readings carry a new
  optional `user` field on `ai_guard_risk_assessed` and
  `ai_guard_toggle_drift`; readings for the agent's own home and for projects
  omit it as before. lodeline-server now reports, per tool, the riskiest of a
  host's readings instead of the last one received, so one clean user or
  project no longer hides another. Readings older than 48 hours (a removed
  repo, user or rule pack) stop counting; when a config cannot be read on the
  daily heartbeat, the agent re-sends its last reading so the risk does not age
  out. A root agent used to report score 0
  for a host whose users had risky hooks. `lodeline show risk` and `lodeline doctor`
  print the user next to the scope. Codex MCP tool baselines are now kept per
  home; an existing baseline still applies to the home that wrote it. Rule
  packs still assess only the agent's own home. Windows services still assess
  only their own profile (#329).

## [0.11.0] - 2026-10-30

### Added

- A Claude Code hook script is now scanned when its interpreter follows
  `NAME=value` assignments or an `env` launcher
  (`/usr/bin/env -i bash ./check.sh`), is `bash.exe`, or carries options
  (`bash -euo pipefail ./check.sh`). These commands used to be checked only
  as inline text, so the script itself was not read (#199).

- Codex hook commands are now read the same way as Claude Code ones. A script
  run through an interpreter (`bash ./check.sh`) is scanned, and a command
  chained after a script (`./ok.sh && rm -rf ~`) is checked. Codex used to
  read a script only when the command started with its path, and then
  ignored the rest of the line.

### Changed

- Continue's `slashCommands` entries and `customCommands[].command` are no
  longer assessed, and a script named by `step` is no longer watched.
  Continue uses none of their `step`, `run` or `prompt` text: `step` is
  documented as having no effect, a slash command resolves only by name to a
  built-in, and a custom command has no `command` field. Destructive text in
  these fields used to be reported as a hook command. A custom command's
  `prompt`, which Continue sends to the model, is still scanned.
  Fleet consumers no longer see `hook_event: "slash_command"` from this
  version on (Ju571nK/sigil-manager#40).

- Codex hooks that Codex will not run are no longer assessed. A hook outside
  the system layer runs only when `~/.codex/config.toml` records a
  `trusted_hash` for it under `[hooks.state]` and does not set
  `enabled = false`. Hooks with no trust entry, or turned off, used to be
  reported as if they ran. A hook whose trusted hash is out of date is still
  reported. Hooks run with `--dangerously-bypass-hook-trust` are not seen
  (#200).

## [0.10.0] - 2026-10-28

### Added

- `sigil-server` has an optional `proxy:` config section and a
  `sigil-server proxy` operator command for the Sigil Proxy that is still in
  development. With the section set, the server registers proxies, issues
  their config, and accepts their status, events, metadata and inventory
  reports. It also serves `/v1/proxies`, `/v1/proxy-invocations` and the
  management audit log for reading. Without the section the server behaves as
  before. The `sigil-proxy` binary and packages are not part of this release.

- Claude Code hooks declared in skill (`skills/<name>/SKILL.md`) and subagent
  (`agents/**/*.md`) frontmatter are now assessed, at user and project scope,
  with the same reasons as `settings.json` hooks. A repository that ships only
  `.claude/skills/` or `.claude/agents/` is now discovered (#199).
- A hook command of the form `bash <script>` (or `sh`, `zsh`, `dash`) now has
  its script scanned, as a command starting with a script path already did.
  A command chained after a script (`./ok.sh && rm -rf ~`) is now checked
  inline as well; before, a command starting with a script path was not
  checked inline at all. The script's own arguments are not checked.
- Codex hooks in `hooks.json` are now assessed next to the `[hooks]` table of
  `config.toml`, in `~/.codex/`, in a repository's `.codex/`, and in the
  system config folder. A repository that ships only `.codex/hooks.json` is
  now discovered (#200).
- The Codex system config layer (`/etc/codex/config.toml`, or
  `%ProgramData%\OpenAI\Codex\config.toml` on Windows) is now read under the
  user config, as Codex layers them: `~/.codex/config.toml` overrides its
  scalar settings, `mcp_servers` tables merge, and the hooks of both layers
  are assessed (#200).

### Fixed

- The declared minimum supported Rust version is now 1.88 (was 1.78). The
  committed lockfile already required 1.88: edition-2024 dependencies (for
  example `rmcp` and `idna_adapter`) fail on 1.78, and `darling` 0.23 needs
  1.88. A new CI job checks the workspace with the declared toolchain so the
  value stays accurate (#240).
- The `sigil`, `sigil-sender` and `sigil-server` `.deb` packages can now be
  installed on the same host. They all shipped
  `/usr/lib/sysusers.d/sigil.conf`, so dpkg refused the second one;
  `sigil-sender` and `sigil-server` now install the same content as
  `sigil-sender.conf` / `sigil-server.conf` (also in `tmpfiles.d` for
  `sigil-sender`). The `.rpm` packages use the same names. CI now installs all
  packages together (#252).

## [0.9.1] - 2026-10-10

### Fixed

- `GET /v1/meta.audit_head` no longer pairs the chain head's `pubkey_id` with
  the server's current audit key when the two differ (for example after the
  key was regenerated or the chain was moved between installs). `pubkey` is now
  reported only when the current key signed the head; otherwise it is omitted,
  and `pubkey_id` names the key to verify with. The head is also reported when
  no audit key is loaded. The server logs a warning at startup when the head's
  key is not the one it holds (#237).

## [0.9.0] - 2026-10-09

### Added

- Define the targeted deployment v2 core manifest contract, domain-separated
  signature verification, paired artifact validation, and replay/migration
  checks with a shared golden fixture (#230, first stage). Runtime activation,
  server distribution, and signer CLI integration are not enabled yet.
- Add a FULL-synchronous transactional deployment store and agent preparation
  coordinator (#230, second stage). Commit manifest, both artifacts, and replay
  state together; reverify on recovery and compile one coherent policy/rubric/
  evaluator generation before publication. This remains an internal API, not
  daemon activation or an `applied` acknowledgement.

### Changed

- `GET /v1/meta` reports the active host count and its rolling window under
  `fleet` (`{"active_host_count": <u32>, "active_window_days": <u32>}`). The
  window is configured with the new top-level `active_window_days` key in
  server config (default 7).

### Deprecated

- The `license:` block in server config. `license.active_window_days` is still
  honored when top-level `active_window_days` is absent; `license.path` is
  ignored. Both log a warning at startup; configs that contain the block keep
  loading.

### Removed

- The license verification module (`sigil_core::license`), the server's boot
  license load, and the `license` object in `GET /v1/meta`; active host count
  and window are now reported under `fleet`.
- The `sigil-sign license` subcommand.
- `sigil-server` no longer appends records to `license-audit.jsonl`. An
  existing chain is left untouched: its head is still read at startup and
  exposed as `/v1/meta.audit_head`, the record format is frozen, and
  `sigil-sign verify-audit` still verifies it.

### Fixed

- Native (glibc) `.rpm` builds use rpm's `find-requires` for dependency
  generation. With Rust 1.99+ binaries, cargo-generate-rpm's builtin fallback
  wrote weak glibc version references as unsatisfiable requirements such as
  `libc.so.6(GLIBC_2.18)[WEAK](64bit)`, so `rpm -i` failed on Rocky 9.
  `packaging/build.sh` now stops with an error when `find-requires` is missing
  for a dynamic build. Release packages are static musl builds and were not
  affected (#234).

## [0.8.3] - 2026-09-13

### Fixed

- Drain the agent pipeline on Unix SIGINT/SIGTERM and Windows Ctrl-C. Release
  retained channel senders, stop IPC acceptance, drain accepted requests for up
  to five seconds, and remove Unix socket files. Supervise failures concurrently
  and report a nonzero exit on storage errors or a 30-second shutdown timeout
  instead of waiting indefinitely (#225).
- Resolve wildcard directory ancestors into concrete watch roots and rediscover
  matches every five seconds with native and polling backends. Catch up newly
  discovered or replaced directories without recursively watching broad parent
  trees, and preserve shared-root ownership across policy reloads (#223).

## [0.8.2] - 2026-09-12

### Fixed

- Retry absent or replaced filesystem watch roots every five seconds without
  recursively watching parent directories. Replay current files after successful
  subscription, cancel recovery when targets are removed, and retain failed
  registrations for retry with both native and polling backends (#219).

## [0.8.1] - 2026-09-12

### Fixed

- Include all 30 binaries from the five Linux, macOS, and Windows release
  archives in the signed build manifest. Preserve canonical binary names for
  Windows `.exe` files so `sigil doctor --verify-self` can find them (#221).
- Block signed release publication unless native runners for all five targets
  verify their downloaded agent and reject a tampered manifest. Add regression
  tests for incomplete archives, duplicate entries, and unsafe archive members.

## [0.8.0] - 2026-09-12

### Added

- Report-only AI Guard controls across scan, daemon, IPC, event history, and
  fleet detail (#207). Controls preserve absent versus empty reporting and
  never reduce risk scores or suppress findings.
- Allowlisted Claude managed-file and Codex requirements-file observations
  with exact source paths (#199, #200). `configured` controls describe local
  files only, not effective cloud/MDM policy or verified runtime enforcement.
- Persistent, per-server MCP metadata baselines beside state.db (#201).
  Detect changed surfaces, new tools, schema expansion, and advisory read-only
  hint contradictions; scan server-info text and v3/v4 cache fields. Repeated
  changes retain distinct evidence hashes. One-shot scan remains stateless.
- Claude auto-mode/default-rule, non-command hook, loop-prompt, and Codex
  standing-approval detection from the earlier #199/#200 increment (#206).
- Antigravity enforcement adapter limited to the hardware-verified contract
  (#208), with compatibility re-probe evidence (#202). Existing unsupported
  modes remain gated.

### Fixed

- Preserve inherited Claude permission rules when merging local settings
  instead of losing broad allows behind an unrelated override (#216).
- Scan all MCP cache variants so an older clean snapshot cannot hide poisoned
  metadata; enforce the schema text cap for a single oversized string (#217).
- Add default watcher coverage for MCP caches and local managed policies,
  and resolve canonical parser paths on macOS (#218).
- Detect broad Antigravity permission allows (#209).

### Upgrade Notes

- Upgrade sigil-server before agents: new MCP reason variants require an
  updated consumer. Manager rendering of controls remains a companion change.
- MCP baselines are first-observed references, not user approvals. Review
  metadata before deliberately resetting a reference. Keep the baseline
  directory protected with the agent's state files.
- #199/#200 remain open for other configuration scopes and effective-policy
  verification. Missing watch directories created after startup may require
  restart; the heartbeat fallback remains in place (#219).

## [0.7.2] - 2026-07-26

### Security

- **Bash deny rules are matched against the command a shell would actually run**
  (#198). Rules previously ran the operator's regex at the raw command string,
  but the shell rewrites that string before `execve`, so any re-spelling that
  survives the rewrite defeated the rule — `r''m -rf /`, `rm${IFS}-rf${IFS}/`,
  `X=rm; $X -rf /`, `sudo rm -rf /`, `sh -c 'rm -rf /'`. (This is the class
  Adversa AI published as GuardFall, which bypassed plaintext denylists in 10 of
  11 OSS coding agents.) On a blocking path a bypassable matcher is worse than no
  rule, because it reads as coverage that is not there.

  A rule written as `rm -rf /` now also denies quote and escape re-spellings,
  `$IFS` word splitting, variables assigned earlier in the line, ANSI-C quoting
  (`$'\x72\x6d'`), wrapper commands (`sudo`, `env`, `nice`, `timeout 5`,
  `xargs`), `-c` string payloads (`sh -c`, `bash -lc`, `su -c`), commands fed to
  a shell on stdin (`bash <<< '…'`, `sh <<EOF … EOF`), mid-command redirections
  (`rm >/dev/null -rf /`), compound-statement context, and trailing comments.
  Normalized segments are matched **in addition to** the raw string, so existing
  rule packs keep firing unchanged; a rule that fires only after rewriting says
  so in the deny reason.

  Normalization refuses to guess in the other direction, since an invented
  command means denying legitimate work: `r$(printf x)m -rf /` is not `rm`
  (the shell runs `rxm`), a `cat <<EOF` body stays data while a `bash <<EOF`
  body is commands, `su rm` switches to a user, and `timeout rm -rf /` never
  ran anything.

### Added

- **Static MCP tool-metadata poisoning detection** (#148). The Codex tool cache
  (`~/.codex/cache/codex_apps_tools/*.json`) holds tool descriptions and input
  schemas that the model reads but the user never sees — the payload surface for
  the poisoning technique Microsoft warned about on 2026-06-30. Three new
  findings: `mcp_tool_instruction_override` (imperative directives aimed at the
  agent inside tool metadata), `mcp_tool_hidden_text` (zero-width, bidi,
  control, or homoglyph characters), and `mcp_tool_name_shadow` (two servers
  offering the same tool name). Bounded and defensive against hostile input.
- **New deny-rule shape `bash_indirection`** (#198). Constructs whose effect
  cannot be known without running them — `$(...)`, backticks, process
  substitution, `eval`, unmodeled parameter expansions, pipelines feeding a
  shell — are reported rather than guessed at, so an operator can deny on the
  shape instead of enumerating spellings. Values: `command_substitution`,
  `eval`, `pipe_to_shell`, `unresolved_command_variable`, `unparsable`.
  Exceeding a size or segment bound always reports `unparsable`, so a text
  rule's silence is never mistaken for safety.
- **`sigil-server` binds enrollment to issuer certs and can require a
  cert↔host_id match** (#194). `enroll_issuer_fingerprints` lists the blake3
  fingerprints of client certs permitted to call `POST /v1/enroll`; a caller not
  on the list is denied before its token is consumed, so a leaked token is
  useless without the issuer cert. The opt-in `events_require_cert_host_match`
  requires a `POST /v1/events` client cert whose CN or SAN DNS entry matches the
  envelope's `host_id`, blocking an enrolled host from impersonating another.
  Both rest on new per-connection TLS peer-certificate identity; enrollment
  audit records now carry the caller fingerprint.

### Documentation

- `config/server.example.yaml` documents the enrollment (#184), peer-cert
  (#194), and artifact-serving (#182) keys, with a test that keeps the example
  in step with the config schema (#196).
- `docs/install-personal.md` explains how bash deny rules are matched, what a
  plain rule now covers, and what it deliberately does not (#198).

## [0.7.1] - 2026-07-02

### Added

- **Autonomous / unattended Claude Code config is flagged** (#191). Loop/goal-style
  features run repeated work unattended; if the agent runs without guardrails the
  blast radius grows, so the readable signals are now measured:
  `permissions.defaultMode` of `auto` / `bypassPermissions` / `acceptEdits` in
  `~/.claude/settings.json` surfaces as `auto_approval_enabled` (flowing into
  scan, #147 toggle-drift, and remediation hints), and each
  `~/.claude/scheduled-tasks/<name>/SKILL.md` — the readable, persistent
  equivalent of a loop — emits a new `unattended_scheduled_task` finding.
  Session-only state (an active `/loop`, `/goal` conditions, cloud `/schedule`
  routines) leaves no on-disk trace and is documented as out of scope.
- **`sigil scan` remediation hints** (#188 follow-up). Every finding now carries a
  one-line advisory "how to reduce it": the human output gains a `How to reduce`
  section after the table (distinct finding kinds, highest-impact first) and
  `--json` adds a `hint` field per reason. Advisory only — Sigil measures, it
  does not block or auto-edit.
- **Personal install offers a read-only Claude Code allowlist** (#188). Driving
  sigil from inside an AI agent caused a per-command permission-prompt storm.
  The personal `install.sh` / `install.ps1` now offer (opt-in, terminal consent
  only, never silent) to add `Bash(sigil:*)` to `~/.claude/settings.json`
  permissions.allow with an explicit deny of `sigil run` and `sigil-hook`, so
  the daemon and hook-enforce are never silently granted to the agent.

## [0.7.0] - 2026-06-28

### Added

- **Dangerous-toggle drift detection** (#147). When a coding agent's config
  silently flips a self-escalation toggle on — auto-approve, sandbox-off,
  broad-allow, or project-MCP-autorun — the daemon emits a one-time
  `AiGuardToggleDrift` security event (the CVE-2025-53773 `chat.tools.autoApprove`
  class). Fires only on the OFF→ON transition vs the previous hashed snapshot
  (baseline-safe across restarts; re-arms on off→on→off→on); classified as a
  fleet alert. Works over reason kinds, so rule-pack-emitted toggles are covered.
- **`sigil-server` enrollment endpoint (B-mint)** (#184). `POST /v1/enroll` signs
  a host CSR into a per-host mTLS client cert using an operator-provided
  intermediate CA (root stays offline), gated by a single-use, TTL, per-host
  token (`sigil-server enroll-token`). Fixed client-cert profile + post-sign
  inspection, allowlist auto-add, signed enrollment audit; enrollment refuses to
  run without mTLS + a restrictive allowlist. Lets a PMS bootstrap host identity
  without hand-running openssl per host. Hardware-verified on Rocky 9 aarch64.
- **`sigil-server` signed-artifact serving** (#182). `GET /v1/artifacts[/<file>]`
  serves the release binaries (tarballs/zips, `.deb`/`.rpm`, `SHA256SUMS`,
  build-manifest) read-only from an operator-populated `artifacts_dir`, so an
  air-gapped fleet/PMS can pull from the server instead of GitHub. Bearer-gated,
  path-traversal-hardened; `install.sh`/`install.ps1` gained `SIGIL_BASE_URL` +
  `SIGIL_BASE_TOKEN` to fetch from it.
## [0.6.2] - 2026-06-21

### Added

- **`sigil scan` — one-shot, daemon-free posture score** (#174). The fastest
  personal read: it reads each installed agent's user-global config once
  (`~/.claude`, `~/.codex`, `~/.cursor`, …) plus the current directory if it is a
  project, scores them with the default rubric, and prints a headline (worst-scope
  bucket + score) and a per-tool table — no daemon, no `state.db`, no policy.
  `--json` emits the full report; the command always exits 0 (a read-out, not a
  gate). Closes the gap behind the one-line installers ("install → score").
- **One-line installer for all three OSes** (#172, #171). New `install.ps1` is the
  Windows counterpart to `install.sh` (`irm …/install.ps1 | iex`): arch-detected
  (x64 / ARM64), checksum-verified, installs the personal profile to
  `%LOCALAPPDATA%\Programs\sigil` and adds it to PATH. `install.sh` now resolves
  Linux **aarch64** (the musl tarball it had been wrongly rejecting), so the
  one-liner works on Graviton/Ampere and RHEL/Rocky 9 aarch64. Script installs
  avoid code-signing friction (Gatekeeper/SmartScreen) by design.
### Fixed

- **`sigil doctor` no longer warns about a control socket on a non-root install**
  (#178). The check hardcoded `/var/run/sigil/control.sock` and expected it
  root-owned, so a non-root personal user got a spurious `Permission denied`
  warning (and a non-zero exit) about a socket the non-root daemon never binds.
  Doctor now resolves the same XDG/tmp fallback path the daemon uses and expects
  ownership by the invoking user.
- **`install.sh` suggests how to install a missing tool** (#179). On a minimal
  RHEL-family / container host without `tar` (or `curl`), the bare "missing
  required tool" message now appends the host package manager's one-liner
  (`sudo dnf install -y tar`, `sudo apt-get install -y …`, etc.).
- **macOS install guide corrected** (#176). It claimed `install.sh` installs all
  six binaries; the personal default is three. Added a 30-second personal
  quickstart and framed the rest as the operator deployment.

## [0.6.0] - 2026-06-16

### Added

- **OpenClaw / Hermes integration glue for `assess`** (#151). `sigil-mcp
  --print-config` now emits ready-to-paste blocks for `hermes` (a `config.yaml`
  `mcp_servers:` entry) and `openclaw` (a `~/.openclaw/openclaw.json` `mcpServers`
  entry), alongside the existing `codex`/`claude`. New `examples/integrations/`
  carries a drop-in OpenClaw `SKILL.md` (pre-flights commands via `sigil assess`)
  and a Hermes `config.yaml` snippet, plus a README describing the reusable
  pre-flight contract (assess → decision → allow/warn/deny).
- **`assess` — a callable pre-flight risk check** (#149). A new primitive scores a
  *proposed* shell command or a single MCP server definition against this host's
  loaded policy (the same rubric + rule-pack deny rules the agent enforces), and
  returns a risk band, score, reasons, any deny-rule match, and a decision
  (allow / warn / deny). Where the existing read surfaces report standing posture
  ("what is my risk right now?"), `assess` answers "is *this action* risky / would
  Sigil block it?" before it runs. Exposed two ways:
  - **`sigil assess` CLI** — `--command "<cmd>"` (or `--mcp-config <file>` /
    `--mcp-stdin --mcp-name <name>`), evaluated against the on-disk policy
    (no daemon required). Prints a one-line JSON verdict and maps the decision to
    exit codes (allow/warn → 0, deny → 2, usage/policy-load error → 1; `--fail-on-warn`
    makes warn → 2) so it can gate a shell pre-flight.
  - **`assess` MCP tool** (local surface) — evaluates against the running agent's
    *live* loaded policy via the existing control IPC. Read-only; executes nothing.
  Malformed or oversize input fails closed (error, never an allow verdict).

### Fixed

- **The local `rule-packs.yaml` watcher re-arms when the config dir is recreated
  at runtime** (#135). The dedicated hot-reload watcher previously gave up
  permanently if its config directory was absent at start, and a by-inode watch
  went silent if the directory was deleted and re-created while the agent ran. It
  now watches the grandparent directory (always present — `~/.config`, `/etc`,
  `$HOME`) and re-arms the parent-directory watch whenever the config dir
  (re)appears, so local rule-pack edits keep hot-reloading across a dir recreate.
- **A transient empty `rule-packs.yaml` read retains the active bundle instead of
  clearing it** (#135). A non-atomic `cp` truncates the destination to zero bytes
  before writing; that empty window was treated as "file removed" and momentarily
  dropped the local rule packs (and their enforcement) until the next reload. A
  zero-byte / whitespace-only read is now retained as last-good. To deliberately
  clear the bundle, remove the file (honored as before) or write a valid empty
  document; only a real removal clears.

## [0.5.1] - 2026-06-12

### Fixed

- **The agent `.deb` is published in releases again** (#138). The agent package
  is named `sigil`, so cargo-deb emits `sigil_<ver>-1_<arch>.deb` (underscore) —
  and the release job's `sigil-*` (hyphen) artifact globs silently skipped it
  in the checksums, the provenance attestation, and the release upload, while
  every other artifact matched. Affected v0.4.0 and v0.5.0 (the agent `.rpm`
  shipped throughout). The globs are now `sigil*`; this release carries the
  agent `.deb` for both x86_64 and aarch64, restoring `apt install` of the
  agent (personal profile: `sigil` + `sigil-mcp` + `sigil-hook`) on
  Debian/Ubuntu.

## [0.5.0] - 2026-06-11

### Added

- **Personal / Fleet install profiles** (#134). Sigil now installs as one of two
  profiles from a single release. `install.sh` takes `SIGIL_PROFILE=personal|fleet`
  (default `personal`): **personal** installs `sigil` + `sigil-mcp` + `sigil-hook`
  for local self-assessment with no server; **fleet** adds `sigil-sender`,
  `sigil-server`, and `sigil-sign` for the signed server-push path. The `sigil`
  `.deb`/`.rpm` package now bundles `sigil-mcp` and `sigil-hook` (so installing the
  `sigil` package is the personal profile). See
  [docs/install-personal.md](docs/install-personal.md).
- **Local rule-pack hot-reload** (#134). A dedicated filesystem watcher on
  `rule-packs.yaml` (beside `policy.yaml`) hot-reloads locally-distributed rule
  packs — e.g. pulled from a git repository — without a server, honoring `--poll`.
  Corrupt edits retain the last-good bundle (a broken `git pull` will not drop your
  active packs); a deliberately removed file clears the bundle layer. The local
  reload path validates deny-rule IDs and compiles regexes with keep-previous
  semantics, matching the signed-bundle path minus the signature. Local rule packs
  are unsigned — their trust boundary is the git repository they come from, and
  they carry `hook_deny_rules` enforcement authority, so use only trusted sources.

### Changed

- **`install.sh` default now installs three binaries, not six** (#134). A plain
  `curl … | sh` installs the `personal` set (`sigil`, `sigil-mcp`, `sigil-hook`).
  Existing users who need the server components must install with
  `SIGIL_PROFILE=fleet`. Personal is Unix-first (`sigil-mcp` local mode and
  `sigil-hook` enforce are Unix-only; Windows has partial support via the tarball).

### Fixed

- **Empty / whitespace AI-tool config is treated as clean, not a parse error**
  (#131). A zero-byte or whitespace-only tool config file (e.g. an empty
  `~/.gemini/config/mcp_config.json`) no longer drops that tool from assessment
  with an EOF parse error — closing a silent coverage hole found via two-machine
  dogfooding. Shared `read_json_optional` helper across the JSON config parsers.

### CI

- **Build-provenance attestation is non-blocking** (#130). A transient Sigstore
  Rekor outage during the release attestation step no longer blocks publishing
  already-built, already-signed artifacts; re-run the job to (re-)attach
  attestations. The enforced trust root remains the ed25519 build-manifest
  signature.

## [0.4.0] - 2026-06-10

### Added

- **`sigil-hook` Stage 2 — in-domain enforcement (block)** (#100). The same
  `PreToolUse` hook that observed tool calls in Stage 1 can now also *decide* and
  **deny** a disallowed call at the agent tool boundary. Delivered per-agent: a
  generalized `deny_output` trait with **Claude Code** (#106), **Codex** (#111),
  **Cursor** (#119), and **Grok Build (xAI)** (#118) adapters. Each agent's deny
  contract is honored exactly (Cursor `permission`, Grok `decision`), including
  Cursor's explicit-allow seam so `--on-failure closed` is genuinely fail-closed.
  Enforcement stays advisory-at-root and open-source/in-tree, never claiming
  tamper-resistant runtime command security.
- **Tamper-evidence — hook config-drift detection** (#109, #120). A new
  `sigil-hook verify` compares the live agent settings against a per-agent
  recorded baseline (`hook-registration-<agent>.json`) and reports drift:
  missing hook, repointed binary, narrowed matcher, or a flipped fail-mode
  (`DriftKind::FailModeDrift`). Format-aware verify with per-agent baselines so
  enforce and tamper-evidence stay symmetric.
- **Hook-activity silence detection** (#107). First-class detection of a hook
  that has gone quiet (absence/silence), closing the gap where a disabled or
  bypassed hook would otherwise look identical to an idle one.
- **Signed distribution of hook deny rules** (#115). Hook deny policy now rides
  the existing signed-bundle pipeline, so enforce rules are distributed with the
  same provenance guarantees as rule packs.
- **AI Guard — MCP stdio launcher attack-shape scoring** (#127). A new
  `McpServerSuspiciousLauncher` reason scores a stdio MCP launcher that is a
  shell with an inline-exec flag (`bash -c`, including POSIX bundled forms like
  `-lc`) or that resolves into a transient/writable path (`/tmp`, `/dev/shm`,
  `/run/user`, Windows `Temp`, `~/.cache`, …) — lifting the attacker-injected
  launcher shape (the 2026 zero-click MCP incident class) above the benign
  stdio baseline. Two independently operator-tunable rubric keys.

### Changed

- **Uniform local stdio MCP command detection across all parsers** (#125, #126).
  Every per-agent parser now routes its per-server MCP definition through one
  shared `emit_one_server`, closing the divergence where Codex and Claude Code
  never read a local `command` at all and others only partially scored it.
- **`show risk --tool` accepts every known tool** (#121, #124). The flag is
  driven from a single source of truth, so Antigravity, Claude Desktop, and
  Continue are accepted alongside the others (no more `exit 2` on a valid tool),
  with a legacy `claude_code` alias preserved.

### Fixed

- **FS-watch e2e tests hardened against parallel-load flake** (#108). Watcher
  tests that dropped a single startup-window write now use continuous writers or
  retry loops, and the control-IPC connect budget is configurable — eliminating
  a class of load-dependent failures rather than a single flake.

### Security

- Stopped tracking a local `.codex/` Codex CLI config that had leaked a test
  bearer token and an internal server address into the public repo; the token
  was rotated.

### Internal

- Measurement pilot quantifying the hardcoded-parser → rule-pack migration
  (#102): a 26-case Antigravity parity harness proving the migration is
  net-negative today (DSL is type-blind and cannot express the destructive
  inline-command scan), with no runtime change. Documents the decision to keep
  the imperative parser kernel.

## [0.3.0] - 2026-06-04

### Added

- **`sigil-hook` — runtime observe at the agent tool boundary** (#64). A new
  in-tree crate that AI coding agents invoke as a `PreToolUse` hook to *observe*
  each command at the moment it is about to run, complementing the static config
  scanning of the AI Guard. Stage 1 is measurement-only (no blocking) and runs
  as a separate process over IPC, keeping the hook surface decoupled from the
  agent binary. Ships adapters and install/uninstall for **Claude Code, Codex,
  Cursor, and Antigravity** (#83, #85, #88, #89) — Antigravity installs through
  its native `agy plugin` bundle (#91). Architecture is documented in the README
  (#84).
- **Antigravity AI Guard support** (#86, #87). A static parser for Antigravity's
  global config plus a per-repo parser wired into `workspace_discovery`, with a
  new `antigravity_workspaces` policy field — so Antigravity is scored like the
  other built-in tools, per-repo included.
- **Rule-pack `scope = Project { path }` + per-repo discovery** (#92, 3b.7.2).
  Operator-defined rule packs can now target per-repo scopes and hook into the
  existing `workspace_discovery`, getting per-repo instances like the built-ins.
  Events carry a `rule_pack_id` (forward-compatible) and the agent keys parser
  state by `(tool, scope, pack_id)`.
- **Generic `AiTool::Other` for operator rule packs** (#95, 3b.7.5). In-house and
  third-party AI tools can be scored without a code change, via the `Other` tool
  variant plus a `tool_label` carried on the pack and emitted on events
  (UserGlobal scope).
- **Server-side signed rule-pack distribution** (#96, 3b.7.4). `sigil-server`
  serves a signed rule-pack-set bundle over `GET /v1/rule-packs`, versioned
  independently from policy; the agent fetches, verifies the signed envelope,
  and merges in three layers (defaults < policy < bundle). Operators push packs
  centrally instead of editing each host.
- **DSL Tier 2 — conditional rule blocks** (#101, 3b.7.1). A rule-pack rule may
  carry `when` gate conditions (`selector` + `matcher` + optional `negate`,
  ANDed) that must all hold for it to emit — giving operator packs compound
  detection the flat Tier-1 grammar could not express. Gated behind
  `pack_version: 2`; an empty `when` is byte-identical to prior behavior.

### Fixed

- **Antigravity approval key is `toolPermission`** (#90), corrected against
  on-hardware behavior so the static parser reads the right setting.
- **`AntigravityProjectParser` now reconciles on hot-reload** (#94, fixes #93) —
  a per-repo Antigravity parser added by a policy reload is assessed without
  waiting for the next file change.
- **`sigil doctor --state-db` override and optional sender mTLS** (#99, fixes
  #97/#98). `doctor` accepts a state-db path override, and the sender's mTLS
  client identity is now optional (the three cert paths may be omitted to run
  against a plain-HTTP dev server) — both surfaced by two-machine E2E testing.

## [0.2.1] - 2026-06-01

### Added

- **aarch64 prebuilt binaries, `.deb`/`.rpm`, and an ed25519-signed build
  manifest** (#12, #13). Releases now ship `x86_64` **and** `aarch64` Linux
  packages, plus a `build-manifest.json` whose per-arch blake3 hashes are signed
  with the compiled-in `SIGIL_BUILD_PUBKEYS` trust anchor; `sigil doctor
  --verify-self` checks the running binary against it. `packaging/build.sh
  --target` cross-builds the OS packages.
- **`sigil-mcp --print-config [codex|claude]`** (#72). Emits a ready-to-paste MCP
  client registration block that pins the binary's **absolute** path, so
  registration works even when the client doesn't inherit your shell `PATH`.
- **SELinux policy module for the three daemons** (#69). Ships
  `packaging/selinux/sigil.{te,fc}` and loads it from the `.rpm` post-install
  (guarded — a no-op without the SELinux policy devel toolchain), confining the
  agent, sender, and server into dedicated domains
  (`sigil_agent_t`/`sigil_sender_t`/`sigil_server_t`) that coexist with the
  units' `NoNewPrivileges=yes` hardening. Verified enforcing-clean on Rocky 9.
- **`sigil-mcp` local mode — individual self-assessment, no server** (#55).
  When `SIGIL_SERVER_BASE_URL` is unset, `sigil-mcp` reads the local
  `sigil-agent` control socket instead of a fleet read API and exposes *this
  machine's* AI Guard posture as three read-only MCP tools — `my_risk`,
  `my_guard_detail`, `my_findings`. Mode is auto-detected; the control wire
  types moved to `sigil-core::control_proto` so the MCP client and the agent
  share one contract.
- **Dedicated `sigil` system group/user + `root:sigil` ownership** (#10 slice 1,
  closes #4). Declarative `sysusers.d`/`tmpfiles.d` create the `sigil`
  group/user and own `/var/lib/sigil`, `/var/log/sigil`, `/run/sigil` as
  `root:sigil 0750`. The agent and sender units run `root:sigil` (`User=root` +
  `Group=sigil`), so the control socket becomes `root:sigil 0660`. The agent
  package applies both at install (deb postinst + rpm scriptlet, guarded and
  idempotent). Foundation for de-rooting the sender/server daemons in later
  slices; the agent stays root for file-integrity monitoring.
- **`sigil-server` runs as the unprivileged `sigil` user** (#10 slice 2). The
  server unit switches from `User=root` to `User=sigil` + `Group=sigil`; systemd
  owns its `StateDirectory`/`LogsDirectory` (`/var/lib/sigil-server`,
  `/var/log/sigil-server`) as `sigil:sigil 0750`. The server package now creates
  the `sigil` user at install (sysusers.d via deb postinst + rpm scriptlet,
  idempotent), so a standalone server install resolves `User=sigil` before start.
  No code change — the server binds a non-privileged port (`:8443`) and writes
  only under its state dir. When mTLS is enabled, the operator must make
  `tls_key_path` readable by the `sigil` user.
- **`sigil-sender` runs as the unprivileged `sigil` user** (#10 slice 2). The
  sender unit switches from `User=root` to `User=sigil` (keeping `Group=sigil`)
  and writes only its own state/log dirs — `StateDirectory=sigil-sender` /
  `LogsDirectory=sigil-sender` (`/var/lib/sigil-sender`, `/var/log/sigil-sender`,
  owned `sigil:sigil 0750`). It still *reads* the agent's `root:sigil` spool and
  connects to the control socket via the `sigil` group, and no longer declares a
  `RuntimeDirectory`. `offset_path` and `dead_letter_dir` now default to the
  sender-owned dirs when omitted.

  **Breaking (operator action on upgrade):** an existing `/etc/sigil/sender.yaml`
  that sets `offset_path: /var/lib/sigil/sender-offset.json` and
  `dead_letter_dir: /var/log/sigil/dead-letter` must move them to
  `/var/lib/sigil-sender/sender-offset.json` and `/var/log/sigil-sender/dead-letter`
  (or delete both lines to take the new defaults) — the non-root sender cannot
  write the agent's `root:sigil` dirs. To preserve the read position (avoid
  re-shipping the spool), move the offset file too:
  `install -o sigil -g sigil -m700 -d /var/lib/sigil-sender && mv /var/lib/sigil/sender-offset.json /var/lib/sigil-sender/ && chown sigil:sigil /var/lib/sigil-sender/sender-offset.json`.

### Fixed

- **`query_events` multi-host filter** (#73). The MCP `query_events` tool and the
  server read API disagreed on the `host_id` filter encoding — repeated params
  tripped the server's `serde_urlencoded` deserializer ("expected a sequence",
  HTTP 400). Both sides now use one comma-separated `host_id` param.
- **`sigil-mcp` local-mode socket trust** (#57). The local upstream now verifies
  the control-socket peer is root or the current user (via
  `UnixStream::peer_cred`) before trusting its `DoctorAiGuardReport`, closing a
  local security-telemetry spoofing gap where another user could serve a
  fabricated "all-clear" posture. Returns a distinct `UntrustedPeer` error.
- **`sigil doctor` events-dir check now validates the owner, not just the group**
  (#60). `classify_events_dir_perms` previously checked only group + mode, so a
  dir owned by a non-root user with group `sigil` and mode `0750` was falsely
  reported as `root:sigil`-hardened while that owner could still mutate it. It
  now warns on a non-root owner, mirroring the control-socket classifier.
- **Standalone `sigil-sender` install no longer fails on `Group=sigil`** (#61).
  The sender unit runs `root:sigil`, but the sender package neither created the
  group nor depended on the agent package, so a sender-only install left
  `systemctl enable --now sigil-sender` failing on group credential resolution.
  The sender package now ships and applies the same idempotent
  `sysusers.d`/`tmpfiles.d` `sigil.conf` as the agent package.

### Changed

- **`sigil-mcp` defaults to single-host `sigil-check`; the fleet view is the
  operator-only `sigil-fleet`** (#80). The two auto-detected modes now register
  under distinct MCP server names: `sigil-check` (no server URL) exposes only
  *this* host's posture and is what `--print-config` emits by default, while the
  fleet-wide `sigil-fleet` (pointed at a `sigil-server` read API) is documented
  as an operator surface to run beside `sigil-server` / `sigil-manager`. No tools
  were removed — naming, default posture, and docs only.
- `sigil doctor`'s events-directory permission check is refactored around a pure
  `classify_events_dir_perms` classifier (mirrors the existing socket
  classifier) and validates `root:sigil` ownership; behavior is unchanged, the
  decision logic is now unit-tested.

## [0.2.0]

### Added

- **`sigil-mcp` — read-only fleet MCP server** (#51). Exposes a `sigil-server`'s
  GET read API as Model Context Protocol tools so an MCP client (Claude
  Desktop/Code) can read and reason over fleet posture. Shipped in `install.sh`
  and the prebuilt release archives alongside the other binaries.

_Releases at or before 0.2.0 are documented in
[GitHub Releases](https://github.com/Ju571nK/sigil/releases)._
