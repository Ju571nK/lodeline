# Go-written test fixtures

These files come from one parity recorder run against the Go `lodeline-manager` at
`Ju571nK/lodeline-manager@e4fb077`. The Rust port uses them to check that it reads data the Go
build wrote. They are test-only. The credentials behind them are throwaway values made for the
parity suite, set in `web/tests/parity/env.ts`, and they protect nothing.

- `triage.sqlite`: the mock-mode triage database after the full parity table ran, all written by
  Go. It holds two triage rows. The first has three status changes and two notes, and matches the
  `triage-get` golden. The second was inserted with `evidence_snapshot: null`, which Go stores as
  the JSON text `null` (`triage-upsert-null-snapshot`), and holds two notes from the note-body
  cases (`triage-get-bob`). The copy uses a rollback journal; Go
  itself opens the file in WAL mode.
- `session-token.txt`: the session cookie value Go issued at the recorder's login, signed with the
  parity `JWT_SECRET` and `JWT_TTL_HOURS=87600`, so it stays valid for ten years.
- `recording.json`: the mock seed of that run (the mock derives event IDs and times from it), the
  admin username, the TTL, and the key of the triage row.

To produce them again, run the recorder against the Go build with `PARITY_TESTDATA=1`, as
described in `web/tests/parity/README.md`:

```sh
cd apps/manager/web
PARITY_UPDATE=1 PARITY_TESTDATA=1 MANAGER_BIN=/path/to/go/lodeline-manager npm run parity
```
