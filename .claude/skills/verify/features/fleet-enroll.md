# Fleet enroll

An operator enrolls a host with `lodeline-sender enroll <file>`. The command stores the host_id through the agent, makes the host key, redeems a single-use token at the enrollment listener while trusting only the CA in the file, checks the certificate, and writes the client key and certificate, the server CA, the policy keystore and `sender.yaml`. Locally this runs against a real `lodeline-server` with mTLS and an enrollment listener on loopback, with a throwaway CA and the six path flags that make a user-mode run. The result proves the command, its files, its reruns and refusals, and that the sender then delivers an event over mTLS. It does not prove the packaged layout: the owners that systemd and tmpfiles give, the root run and SELinux labels stay with a run on a real host.

## Sub-features

- `enroll-run` enrolls a host from a file made with the documented `jq` template, and writes five files with their modes.
- `enroll-deliver` starts the sender with those files and delivers an event to a server that requires the certificate to match the host_id.
- `enroll-rerun` makes no request when the host is already enrolled.
- `enroll-refuse` exits 3 for another host_id, 5 for a spent token, 6 for a CA the listener does not chain to, 2 for a bad file, 4 for a config that exists, and 1 without root or the path flags.
- `enroll-rate-limit` retries a connection the listener dropped and then succeeds.

## How to get to it (user POV)

- Run `lodeline-server enroll-token`, make the file with `jq`, and run `lodeline-sender enroll <file>` on the host.
- Run `lodeline-sender start` with the written `sender.yaml`.

## Driving it with drive.sh

Preconditions:

- `drive.sh doctor "$RUN"` exits 0.
- `lsof -nP -iTCP:18443 -iTCP:18444 -sTCP:LISTEN` prints nothing. If a port is taken, use other ports in the steps below. Never kill the holder.
- `openssl` and `jq` are on `/usr/bin` or `/bin`.
- `drive.sh` refuses root, so every run here is the user-mode layout. `$E` below is `${TMPDIR:-/tmp}/lodeline-verify/$RUN/evidence`.

- **PKI.** Run `drive.sh run "$RUN" enroll-pki -- sh -c 'mkdir -p ../fleet/events && cd ../fleet && openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out ca.key 2>/dev/null && openssl req -x509 -new -key ca.key -days 30 -subj /CN=verify-root -addext basicConstraints=critical,CA:TRUE -out ca.crt && openssl req -new -newkey rsa:2048 -nodes -keyout server.key -subj /CN=127.0.0.1 -out server.csr 2>/dev/null && printf "subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n" > server.ext && openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 30 -extfile server.ext -out server.crt 2>/dev/null && openssl req -new -newkey rsa:2048 -nodes -keyout int.key -subj /CN=verify-enroll-int -out int.csr 2>/dev/null && printf "basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n" > int.ext && openssl x509 -req -in int.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 30 -extfile int.ext -out int.crt 2>/dev/null && chmod 600 ca.key server.key int.key && openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout other.key -subj /CN=other-root -days 30 -out other.crt 2>/dev/null && ls'`. Exit code `0`, and stdout lists `ca.crt`, `int.crt` and `other.crt`.
- **Keystore and server config.** Run `drive.sh run "$RUN" enroll-config -- sh -c 'cd ../fleet && lodeline-sign keygen --id verify-key --out key.json && pub=$(sed -n "s/.*\"ed25519_pubkey_b64\": *\"\([^\"]*\)\".*/\1/p" key.json) && printf "{\"pubkeys\":[{\"id\":\"verify-key\",\"ed25519_pubkey_b64\":\"%s\",\"valid_from\":\"2026-01-01T00:00:00Z\",\"valid_until\":\"2031-01-01T00:00:00Z\"}]}" "$pub" > keystore.pem && printf "{\"hosts\":[]}" > hosts.json && F=$PWD && printf "bind: \"127.0.0.1:18443\"\nevents_out_dir: \"%s/events\"\npolicy_bundle_path: \"%s/signed-policy.json\"\ntls_cert_path: \"%s/server.crt\"\ntls_key_path: \"%s/server.key\"\nclient_ca_path: \"%s/ca.crt\"\nevents_require_cert_host_match: true\nhost_allowlist_path: \"%s/hosts.json\"\nenroll_ca_cert_path: \"%s/int.crt\"\nenroll_ca_key_path: \"%s/int.key\"\nenroll_tokens_path: \"%s/tokens.json\"\nenroll_listener:\n  bind: \"127.0.0.1:18444\"\n" $F $F $F $F $F $F $F $F $F > server.yaml'`. Exit code `0`.
- **File maker.** Run `drive.sh run "$RUN" enroll-mkfile -- sh -c 'cat > ../fleet/mkfile.sh' <<'EOF'` with the script below on stdin. It is the `jq` template of `docs/install-server.md` section 3.3, with the `sudo -u lodeline` left out because the run is already the server's user.

  ```sh
  # usage: mkfile.sh <name> <ca.pem> [host_id]    (run from scratch/project)
  set -eu
  cd ../fleet
  H=${3:-$(uuidgen | tr A-Z a-z)}
  T=$(lodeline-server enroll-token --config server.yaml --host-id "$H" --ttl 10m 2>/dev/null)
  (umask 077; jq -n --arg host_id "$H" --arg token "$T" \
    --arg enroll_url https://127.0.0.1:18444 --arg server_url https://127.0.0.1:18443 \
    --rawfile server_ca_pem "$2" --slurpfile ks keystore.pem \
    '{lodeline_enrollment: 1, host_id: $host_id, token: $token, enroll_url: $enroll_url,
      server_url: $server_url, server_ca_pem: $server_ca_pem, policy_keystore: $ks[0]}' > "$1.json")
  echo "$H" > "$1.host"
  ```

  Exit code `0`. `../fleet/mkfile.sh` exists.
- **Serve.** Run `drive.sh bg "$RUN" enroll-server -- env LODELINE_SERVER_READ_TOKEN=verify-token lodeline-server serve --config ../fleet/server.yaml`. Then run `drive.sh doctor "$RUN"`, which reports `enroll-server is up`. `$E/enroll-server.stderr` holds `enrollment endpoint enabled` and `enroll_bind=127.0.0.1:18444`.
- **File for host A.** Run `drive.sh run "$RUN" enroll-file-a -- sh ../fleet/mkfile.sh a ca.crt`. Exit code `0`, and `../fleet/a.json` is mode 0600.
- **Enroll.** Run `drive.sh run "$RUN" enroll-a -- lodeline-sender --config ../fleet/s/sender.yaml enroll ../fleet/a.json --state-db ../fleet/s/state.db --events-dir ../fleet/s/events --control-socket ../fleet/s/ctl.sock --keystore ../fleet/s/ks.pem --sender-dir ../fleet/s/sender`. Exit code `0`. Stdout holds `Enrolled host`, the five files with `mode 0600` for the key and `mode 0644` for the others, and `enrolling blocks nothing`. Stderr holds `This enrollment file makes this host trust`, the CA subject `CN=verify-root` with its SHA-256, the key id `verify-key`, and `The main port answered over mTLS.` The enrollment file's token never appears in stdout or stderr.
- **Stored host_id.** Run `drive.sh run "$RUN" enroll-show -- sh -c 'cd ../fleet && lodeline --state-db s/state.db show host-id | cmp - a.host && echo same'`. Stdout `same`.
- **Seed an event.** Run `drive.sh run "$RUN" enroll-seed -- sh -c 'cd ../fleet && H=$(cat a.host) && mkdir -p s/events && printf "{\"schema_version\":1,\"event_id\":\"018f9c1a-0000-7000-8000-000000000002\",\"ts\":\"2026-07-01T00:00:00Z\",\"host_id\":\"%s\",\"agent_version\":\"0.1.0\",\"severity\":\"warn\",\"source\":{\"kind\":\"agent\"},\"subject\":{\"kind\":\"self\"},\"evidence\":{\"kind\":\"host_id_conflict\",\"observed_status\":200},\"target_id\":null}\n" "$H" > s/events/events-1.jsonl && wc -l s/events/events-1.jsonl'`. Stdout `1 s/events/events-1.jsonl`.
- **Deliver.** Run `drive.sh bg "$RUN" enroll-sender -- lodeline-sender --config ../fleet/s/sender.yaml start`, wait 8 seconds with `/bin/sleep 8`, then run `drive.sh run "$RUN" enroll-delivered -- sh -c 'cd ../fleet && cat events/$(cat a.host)/*.jsonl && cat s/sender/sender-offset.json'`. Stdout holds the event line with the host's `host_id`, and `last_acked_sequence":1`. The server required the certificate to match the host_id (`events_require_cert_host_match: true`), so a certificate for another host would have been answered 404.
- **Rerun.** Run `wc -l < "$E/enroll-server.stderr"`, then `drive.sh run "$RUN" enroll-rerun -- lodeline-sender --config ../fleet/s/sender.yaml enroll ../fleet/a.json --state-db ../fleet/s/state.db --events-dir ../fleet/s/events --control-socket ../fleet/s/ctl.sock --keystore ../fleet/s/ks.pem --sender-dir ../fleet/s/sender`, then count again. Exit code `0`, stdout holds `already enrolled` and `no request was made`, and the line count of the server's stderr is the same.
- **Another host_id.** Run `drive.sh run "$RUN" enroll-file-b -- sh ../fleet/mkfile.sh b ca.crt`, then the **Enroll** command with `../fleet/b.json` as `enroll-other-host`. Exit code `3`, stderr holds `already has another host_id`, and `cmp` of `../fleet/s/sender.yaml` before and after shows no change.
- **Lost certificate.** Run `drive.sh run "$RUN" enroll-lose-cert -- rm ../fleet/s/sender/client.crt`, then the **Rerun** command as `enroll-lost`. Exit code `5`, stderr holds `refused` and `An earlier run may have spent this token`, and `../fleet/s/sender/client.key` is unchanged.
- **Wrong CA.** Run `drive.sh run "$RUN" enroll-file-c -- sh ../fleet/mkfile.sh c other.crt`, then run the **Enroll** command with `../fleet/c.json` and every path under `../fleet/s2/` instead of `../fleet/s/` as `enroll-wrong-ca`. Exit code `6`, stderr holds `does not trust`, and `../fleet/s2/sender.yaml` does not exist. Then run `drive.sh run "$RUN" enroll-redeem -- sh -c 'cd ../fleet && H=$(cat c.host) && lodeline-sender csr --host-id "$H" --key-out c.key --csr-out c.csr >/dev/null && jq -n --arg t "$(jq -r .token c.json)" --arg h "$H" --rawfile c c.csr "{token: \$t, host_id: \$h, csr_pem: \$c}" | curl -s -o /dev/null -w "%{http_code}\n" --cacert ca.crt -H "content-type: application/json" -d @- https://127.0.0.1:18444/v1/enroll'`. Stdout `200`, so the wrong-CA run never sent the token.
- **Existing config.** Run `drive.sh run "$RUN" enroll-file-d -- sh ../fleet/mkfile.sh d ca.crt`, then `drive.sh run "$RUN" enroll-seed-config -- sh -c 'mkdir -p ../fleet/s4 && printf "server_base_url: https://other.example.com\n" > ../fleet/s4/sender.yaml'`, then the **Enroll** command with `../fleet/d.json` and every path under `../fleet/s4/` as `enroll-existing`. Exit code `4`, stderr holds `exists with other content`, and `../fleet/s4/state.db` does not exist.
- **Bad file and no flags.** Run `drive.sh run "$RUN" enroll-bad-file -- sh -c 'printf "{\"lodeline_enrollment\": 2}" > ../fleet/bad.json && chmod 600 ../fleet/bad.json && lodeline-sender enroll ../fleet/bad.json'`. Exit code `2`, stderr holds `upgrade lodeline-sender`. Then run `drive.sh run "$RUN" enroll-no-flags -- lodeline-sender enroll ../fleet/d.json`. Exit code `1`, stderr holds `run as root (sudo), or pass all of` and `d.json` is unchanged.
- **Rate limit.** Run `drive.sh run "$RUN" enroll-file-e -- sh ../fleet/mkfile.sh e ca.crt`, then `drive.sh run "$RUN" enroll-burst -- sh -c 'for i in 1 2 3 4 5 6 7 8 9 10 11 12; do curl -s -o /dev/null --cacert ../fleet/ca.crt -d x https://127.0.0.1:18444/v1/enroll; done; echo done'`, then the **Enroll** command with `../fleet/e.json` and every path under `../fleet/s3/` as `enroll-rate-limited`. Exit code `0` after about ten seconds, and stderr holds `could not reach` and `trying again in 10 s`.

## Gotchas

- Run `drive.sh cleanup "$RUN"` when done. It stops the server and the sender by recorded pid, and scratch deletion takes the throwaway CA, the keys and the tokens with it.
- Each enrollment token is single use. Every file maker call issues a new token, and a failed run that spent one needs a new file.
- The listener allows 10 connections per source, then one every 6 s, and a failed TLS handshake counts. Run the steps in order and do not repeat the burst step within a minute of the first enrollments.
- One line of the events file is the event itself, not an envelope. A wrapped line is accepted by the sender and dead-lettered by the server as `malformed_payload`.
- The paths in `sender.yaml` keep the `..` the flags carried, so they are absolute but not tidy. They still resolve.
- Without root, `enroll` needs all six path flags. The agent's `state.db` default would otherwise land in the user's XDG directory while the other files went to system paths.
- `lodeline-sender enroll` never enables or starts a service. The `bg` steps start the sender by hand.
