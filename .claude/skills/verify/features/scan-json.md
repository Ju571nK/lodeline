# Scan JSON

`lodeline scan --json` prints the full scan report as JSON for scripts. It carries the same headline and findings as the human report, plus the detail behind each finding and an advisory `hint` on each reason.

## Sub-features

- `scan-json-shape` emits `headline`, `results`, `not_configured`, and `errors`.
- `scan-json-reason` gives each reason a `kind` and a `hint`.
- `scan-json-error` reports an unreadable config in `errors` and still exits 0.

## How to get to it (user POV)

- Run `lodeline scan --json` in a terminal.

## Driving it with drive.sh

Preconditions:

- `drive.sh doctor "$RUN"` exits 0.
- The temp HOME is empty.

- **Empty shape.** Scan an empty home. Run `drive.sh run "$RUN" json-empty -- lodeline scan --json`. Exit code `0`, `headline.bucket` is `low`, `headline.tools_assessed` is `0`, and `results` and `errors` are empty.
- **Seed risky config.** Run `drive.sh run "$RUN" json-seed -- sh -c 'mkdir -p "$HOME/.cursor" && printf "%s" "{\"mcpServers\":{\"x\":{\"command\":\"npx\",\"args\":[\"-y\",\"evil\"]}}}" > "$HOME/.cursor/mcp.json"'`. Exit code `0`.
- **Reason detail.** Scan again. Run `drive.sh run "$RUN" json-risky -- lodeline scan --json`. `headline.bucket` is `medium`, and the `cursor` result holds a reason with `kind` `mcp_server_local_command`, `server_name` `x`, and a non-empty `hint`.
- **Assert by parser.** Check the stored stdout from outside the sandbox, not by eye. Run `python3 -c 'import json,sys; r=json.load(open(sys.argv[1])); c=[x for x in r["results"] if x["tool"]=="cursor"][0]; assert any(k["kind"]=="mcp_server_local_command" and k["hint"] for k in c["reasons"]); print("ok")' "${TMPDIR:-/tmp}/lodeline-verify/$RUN/evidence/json-risky.stdout"`. It prints `ok`.
- **Parse failure.** Break the config. Run `drive.sh run "$RUN" json-bad-seed -- sh -c 'printf "{not json" > "$HOME/.cursor/mcp.json"'` and `drive.sh run "$RUN" json-bad -- lodeline scan --json`. Exit code `0`, and `errors` holds a `cursor` entry.

## Gotchas

- `drive.sh run` shows only the first 40 lines. Read the full `.stdout` file for assertions.
- Key order and row order are not a contract beyond worst score first. Select a row by `tool` and `scope`.
- `project:` scopes in JSON carry a resolved path. On macOS it starts with `/private`.
