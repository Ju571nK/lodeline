# Go-written test fixtures

`mock-fleet.json` is the Go mock fleet, which the binary embeds for `MOCK_FLEET=1`. The other
files come from one parity recorder run against the Go `lodeline-manager` at
`Ju571nK/lodeline-manager@e4fb077`. The Rust port uses them to check that it reads data the Go
build wrote. They are test-only. The credentials behind them are throwaway values made for the
parity suite, set in `web/tests/parity/env.ts`, and they protect nothing.

- `triage.sqlite`: the mock-mode triage database after the parity table ran, all written by Go.
  It was recorded before the `triage-*-snapshot-*` cases joined the table, so it holds two triage
  rows. The first has three status changes and two notes, and matches the
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

## mock-fleet.json

The fixtures of Go's `internal/fleet/mock.go` at `e4fb077`, written once by
`mock-fleet-dump_test.go.txt` so the Rust port serves the same fleet without a hand port. To
write it again, copy that file into `internal/fleet/` of a `lodeline-manager` checkout at
`e4fb077` as `zz_dump_mock_test.go`, then run:

```sh
MOCK_DUMP_PATH=$PWD/mock-fleet.json go test -run TestDumpMock -count=1 ./internal/fleet
```

Fixtures added after the dump are not in Go's mock: the `source`, `unassessed_since` and
`ai_guard_unassessed` fields on alice-mbp and carol-dev, the host frank-ci, and its
`ai_guard_assess_failed` event. A new event must sit at its index times 44 minutes before the
seed, the spacing the parity recorder assumes for event IDs.

The file differs from Go's encoded bodies in three ways, which `src/fleet/mock.rs` undoes:

- Times under `ts`, `*_ts`, `since` and `*_since` keys are second offsets from the seed. The binary adds the seed,
  its start time truncated to the second, as Go's mock does.
- Events have no `event_id`. The binary derives each one from the event time and the event's
  position, with the same function as Go.
- IPv4 addresses are hex, `ipv4:` and eight digits, so the file holds no dotted addresses. The
  binary writes them dotted again, and the parity goldens compare the dotted form.

## mock-proxies.json

The proxy details the mock fleet serves for `/api/v1/fleet/proxies*`, written for this console:
no Go console had proxy reads. Each object is a `GET /v1/proxies/{id}` body as
`src/fleet/proxy.rs` reads it, in `proxy_id` order. Numbers under `*_at`, `last_seen` and
`*as_of` keys are second offsets from the seed, which `src/fleet/mock.rs` turns into times. The
five proxies cover a connected proxy in sync, a stopped ingest with a degraded spool, an older
proxy (`quarantined_bytes` `null`, no registry counters) with dropped gaps, a proxy that never
reported, and a disabled config.

## jose-cases.json

ID token headers and key sets, each with whether go-oidc v3.21.0 and go-jose v4.1.4 accept the
token, written by `jose-cases_test.go.txt`. `src/auth/oidc/tests.rs` serves each key set from the
fake provider and checks that the Rust port gives the same answer, except for the few cases it
lists as refused here. The RSA, EC and Ed25519 keys and certificates in it are made fresh on each
run and protect nothing. To write it again, copy that file into `internal/auth/` of a
`lodeline-manager` checkout at `e4fb077` as `zz_jose_cases_test.go`, then run:

```sh
JOSE_CASES_PATH=$PWD/jose-cases.json go test -run TestDumpJoseCases -count=1 ./internal/auth
```
