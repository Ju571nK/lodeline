# Manual pre-release test runbook

Five scenarios that automation cannot cover.

## 1. macOS Full Disk Access flow

1. Install Lodeline without granting FDA. Run `lodeline doctor` — expect `[WARN]
   Full Disk Access: NOT granted`.
2. Run the daemon. Confirm a `permission_missing` event appears in
   `/var/log/lodeline/events-*.jsonl`.
3. Open System Settings → Privacy & Security → Full Disk Access. Add
   `/usr/local/bin/lodeline`.
4. Send SIGHUP: `sudo launchctl kickstart -k system/com.lodeline.agent`.
5. Confirm next heartbeat's `events_by_kind` no longer contains
   `permission_missing`.

## 2. Windows Service registration

1. `sc create Lodeline binPath= "C:\Program Files\Lodeline\lodeline.exe run" start= auto`
2. `sc start Lodeline` — confirm Event Viewer shows successful start.
3. Modify a watched config file; confirm event in `%ProgramData%\Lodeline\events`.
4. `sc stop Lodeline` — confirm graceful shutdown (final heartbeat with
   `is_final: true` in the events file).

## 3. Real SIEM ingest

1. Configure Splunk Universal Forwarder per `siem-rules.md`.
2. Run Lodeline, generate events via test changes.
3. Search Splunk: `index=main sourcetype=lodeline:event:json`.
4. Force a rotation (write 100 MB or wait for midnight UTC). Confirm rotated
   files are picked up without gaps.

## 4. EDR coexistence

1. Install Lodeline on a workstation running CrowdStrike Falcon (or Defender ATP).
2. Confirm Lodeline daemon process is not flagged or blocked.
3. Confirm both agents continue running for 24 hours.

## 5. MDM dry-run

1. Use Jamf Pro (macOS) or Intune (Windows) to deploy the signed installer
   package.
2. After deployment, run `lodeline doctor` on the target machine.
3. Expect exit code 0 or 1 with only known `[WARN]` lines (e.g., FDA
   pending grant).
