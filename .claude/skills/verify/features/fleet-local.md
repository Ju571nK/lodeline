# Fleet local

An operator signs a policy with `lodeline-sign`, and `lodeline-server` serves it to hosts with an ETag. Locally this runs with a throwaway key on loopback in plain HTTP, which the server allows when no mTLS paths are set. The result proves signing, verification, and the HTTP routes. It does not prove mTLS or a host applying the policy.

## Sub-features

- `fleet-sign` generates a keypair and signs a policy, and refuses a document no agent could load.
- `fleet-verify` accepts a signed bundle and rejects a version regression.
- `fleet-serve` serves `/v1/healthz` and `/v1/policy`, with `304` on a matching ETag.
- `fleet-read-auth` requires a bearer token on read routes such as `/v1/meta`.

## How to get to it (user POV)

- Run `lodeline-sign keygen`, `sign`, `inspect`, and `verify` on a workstation.
- Run `lodeline-server serve --config <server.yaml>` and call its HTTP routes.

## Driving it with drive.sh

Preconditions:

- `drive.sh doctor "$RUN"` exits 0.
- `lsof -nP -iTCP:18443 -sTCP:LISTEN` prints nothing. If the port is taken, use another port in the steps below. Never kill the holder.

- **Seed.** Run `drive.sh run "$RUN" fleet-seed -- sh -c 'mkdir -p ../fleet/events && printf "version: 1\nhost_id_strategy: hostname\n" > ../fleet/policy.yaml && printf "bind: \"127.0.0.1:18443\"\nevents_out_dir: \"%s/../fleet/events\"\npolicy_bundle_path: \"%s/../fleet/signed-policy.json\"\n" "$PWD" "$PWD" > ../fleet/server.yaml'`. Exit code `0`.
- **Keygen.** Run `drive.sh run "$RUN" fleet-keygen -- lodeline-sign keygen --id verify-key --out ../fleet/key.json`. Stdout holds `wrote keypair`.
- **Sign.** Run `drive.sh run "$RUN" fleet-sign -- lodeline-sign sign --in ../fleet/policy.yaml --key ../fleet/key.json --policy-version 2 --valid-until 2030-01-01T00:00:00Z --out ../fleet/signed-policy.json`. Stdout holds `signed policy_version=2` and an `etag:` line.
- **Refuse unloadable.** Run `drive.sh run "$RUN" fleet-refuse -- sh -c 'printf "version: 2\n" > ../fleet/bad.yaml; lodeline-sign sign --in ../fleet/bad.yaml --key ../fleet/key.json --policy-version 3 --valid-until 2030-01-01T00:00:00Z --out ../fleet/bad.json'`. Exit code `1`, stderr holds `unsupported policy version 2`, and `../fleet/bad.json` does not exist.
- **Inspect.** Run `drive.sh run "$RUN" fleet-inspect -- lodeline-sign inspect --in ../fleet/signed-policy.json`. Stdout holds `signing_pubkey_id : verify-key` and `policy_version    : 2`.
- **Keystore.** Run `drive.sh run "$RUN" fleet-keystore -- sh -c 'pub=$(sed -n "s/.*\"ed25519_pubkey_b64\": *\"\([^\"]*\)\".*/\1/p" ../fleet/key.json); printf "{\"pubkeys\":[{\"id\":\"verify-key\",\"ed25519_pubkey_b64\":\"%s\",\"valid_from\":\"2026-01-01T00:00:00Z\",\"valid_until\":\"2031-01-01T00:00:00Z\"}]}" "$pub" > ../fleet/keystore.pem'`. Exit code `0`.
- **Verify.** Run `drive.sh run "$RUN" fleet-verify -- lodeline-sign verify --in ../fleet/signed-policy.json --keystore ../fleet/keystore.pem`. Stdout `OK: pubkey_id=verify-key policy_version=2`.
- **Reject regression.** Run `drive.sh run "$RUN" fleet-regress -- lodeline-sign verify --in ../fleet/signed-policy.json --keystore ../fleet/keystore.pem --last-applied 5`. Exit code `1`, stderr holds `policy_version regression`.
- **Serve.** Run `drive.sh bg "$RUN" fleet-server -- env LODELINE_SERVER_READ_TOKEN=verify-token lodeline-server serve --config ../fleet/server.yaml`. Then run `drive.sh doctor "$RUN"`, which reports `fleet-server is up`.
- **Health.** Run `drive.sh run "$RUN" fleet-health -- curl -s --retry 10 --retry-delay 1 --retry-connrefused http://127.0.0.1:18443/v1/healthz`. Stdout holds `"status":"ok"`.
- **Fetch policy.** Run `drive.sh run "$RUN" fleet-policy -- sh -c 'curl -s -D ../fleet/headers -o ../fleet/got.json "http://127.0.0.1:18443/v1/policy?host_id=00000000-0000-4000-8000-000000000001"; cat ../fleet/headers'` and `drive.sh run "$RUN" fleet-policy-verify -- lodeline-sign verify --in ../fleet/got.json --keystore ../fleet/keystore.pem`. The first shows `200 OK` and an `etag` header, and the second prints `OK: pubkey_id=verify-key policy_version=2`.
- **ETag.** Run `drive.sh run "$RUN" fleet-304 -- sh -c 'tag=$(tr -d "\r" < ../fleet/headers | sed -n "s/^etag: //p"); curl -s -o /dev/null -w "%{http_code}\n" -H "If-None-Match: $tag" "http://127.0.0.1:18443/v1/policy?host_id=00000000-0000-4000-8000-000000000001"'`. Stdout `304`.
- **Read auth.** Run `drive.sh run "$RUN" fleet-meta-401 -- curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:18443/v1/meta` and `drive.sh run "$RUN" fleet-meta -- curl -s -H 'Authorization: Bearer verify-token' http://127.0.0.1:18443/v1/meta`. The first prints `401`. The second prints JSON with `server_version`.

## Gotchas

- Run `drive.sh cleanup "$RUN"` when done. It stops the server by recorded pid, and scratch deletion takes the throwaway key with it.
- `/v1/policy` without `host_id` answers `400`.
- The served bundle is reserialized JSON, so it differs from the file on disk byte for byte. Prove it with `lodeline-sign verify`, not `cmp`.
- `If-None-Match` takes the ETag as the header gives it, with no added quotes. A quoted value answers `200`.
- The stderr of `fleet-server` warns `PLAIN HTTP — no mTLS`. That is expected here and is not a supported deployment.
- Never use a real signing key or a real `server.yaml`. Stored `.cmd` files hold only the throwaway token.
