# API

Base `http://127.0.0.1:8000/api/v1/`, JSON both ways, same origin as the UI.
Bytes and big integers are lowercase hex strings. Times are in ms except `scanned_at` (ISO UTC).
Sample responses for every case are in `contract/mock/`. If you need a field changed, tell Johan.

## Errors

Errors come back as `{"error": {"code": "...", "message": "..."}}` with the status below.
DNS and network failures during a scan are not errors: they return 200 with an inconclusive verdict.
If `probes` is empty or missing, the scan did not run those probes. The UI should say so and not crash.

| status | code | when |
|---|---|---|
| 400 | invalid_host | bad hostname (spaces, odd chars, leading `-`, IP, local suffix, too long) |
| 422 | blocked_address | host resolves to a non-public address |
| 422 | ipv6_only_unsupported | no IPv4 answer |
| 422 | no_public_ipv4 | IPv4 answers exist but none are public |
| 422 | invalid_request | bad body or extra fields |
| 404 | no_session | booth session unknown |
| 409 | attack_running | a Q-Day attack is already running |
| 409 | lab_switching | lab mode switch in progress |
| 503 | client_unavailable | OpenSSL missing, LibreSSL, or older than 3.5 |
| 500 | internal | anything else |

## GET /health

```json
{"ok": true,
 "openssl": {"version": "OpenSSL 3.6.4", "path": "/opt/homebrew/opt/openssl@3/bin/openssl", "ok": true},
 "trace_supported": true,
 "ca_file": "/opt/homebrew/etc/openssl@3/cert.pem",
 "kem": {"library": "cryptography", "version": "47.0.0"},
 "booth_bits": 40}
```

If `ok` is false there is also `problems`: a list of short strings. The UI shows them in a red banner.

## POST /scan

Body: `{"host": "google.com"}` and nothing else.

```json
{"schema": "harvestlab.scan/1",
 "target": {"kind": "public", "input": "google.com", "host": "google.com", "ip": "142.250.0.1", "port": 443, "family": "ipv4", "addresses_seen": 2},
 "scanned_at": "2026-10-09T21:30:00Z", "elapsed_ms": 812, "cache_age_s": null,
 "client_profile": "OpenSSL 3.6.4",
 "probes": {
  "default": {"offer": "default", "outcome": "ok", "reason": null,
    "group": "X25519MLKEM768", "group_class": "hybrid",
    "tls": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384", "sig_type": "ecdsa_secp256r1_sha256",
    "peer_cert": "CN=*.google.com", "verified_peername": "google.com",
    "key_share": {"client": [{"group": "X25519MLKEM768", "len": 1216}, {"group": "X25519", "len": 32}],
                  "server": {"group": "X25519MLKEM768", "len": 1120}},
    "elapsed_ms": 640, "exit_code": 0, "trace_bytes": 24310,
    "cmd": ["/opt/homebrew/opt/openssl@3/bin/openssl", "s_client", "...", "-msgfile", "<tmp>"],
    "raw": "..."},
  "hybrid_only": {"offer": "X25519MLKEM768", "...": "same fields, key_share may be null"},
  "classical_only": {"offer": "X25519:secp256r1:secp384r1", "...": "same fields, key_share may be null"}},
 "cert": {"key_class": "EC P-256", "verified": true},
 "verdict": {"label": "hybrid_observed", "rule": "1",
   "headline": "This connection negotiated a hybrid key agreement.",
   "qualifier": "Observed once, from one OpenSSL client profile.",
   "notes": [], "reason": null},
 "pq_note": "Hybrid key agreement protects recorded traffic. It does not make the certificate quantum-safe.",
 "footer": "One vantage point, one time, three offers from one OpenSSL build (OpenSSL 3.6.4)."}
```

- `outcome`: ok, timeout, net_refused, net_other, cert_fail, hs_refused, proto_refused, other_alert, local_error, parse_fail, output_cap
- `group_class`: hybrid, classical, or null
- `key_share` null means there was no trace. The UI then shows reference sizes and says they were not read from this scan.
- `reason` is `{"code": "...", "text": "..."}` or null, never a bare string.
- `verdict.label` is one of hybrid_observed, hybrid_supported_not_chosen, classical_observed, inconclusive.
- For inconclusive, `reason.code` is one of cert_verify, anomaly, no_tls13_handshake, timeout, dns_failure, connection_refused, other. `probes` can be `{}`.
- Headlines: hybrid_observed "This connection negotiated a hybrid key agreement."; hybrid_supported_not_chosen "Hybrid is supported, but this client profile was not given it."; classical_observed "Classical key agreement observed; hybrid not established."; inconclusive "We could not finish this scan. That is the honest answer."
- Do not use the words quantum-safe, secure, insecure or grade for a verdict.

## Lab

Modes: classical, hybrid, stop.

- `GET /lab/status` gives `{"mode": "classical", "alive": true, "pid": 4242, "switch_ms": 51}`. If the server died: mode "down", alive false, pid and switch_ms null. This never waits on the switch lock.
- `POST /lab/mode` with `{"mode": "hybrid"}` returns the same shape, only after the server accepts connections. 409 `lab_switching` if a switch is already running.
- `POST /lab/scan` (no body) returns the same shape as /scan with `target` set to `{"kind": "lab", "input": "lab", "host": "localhost", "ip": "127.0.0.1", "port": 8443, "family": "ipv4", "addresses_seen": 1}`. classical gives classical_observed, hybrid gives hybrid_observed, stop gives inconclusive with reason connection_refused.

## Booth

`POST /booth/send`, body `{"classical_message": "...", "hybrid_message": "..."}`. Each message is 1 to 64 bytes of UTF-8. Optional `"bits": 40` or `36`.

```json
{"session": "b3f1c2", "bits": 40, "p_bits": 40,
 "kem": {"library": "cryptography", "version": "47.0.0"},
 "warnings": [],
 "wire_bytes": {"classical": {"m1": 15, "m2": 5, "m3": 55, "total": 75},
                "hybrid": {"m1": 1199, "m2": 1093, "m3": 50, "total": 2342}},
 "transcript": {"v": 1, "session": "b3f1c2", "created": "2026-10-09T21:40:00Z",
   "channels": {
     "classical": {"M1": {"v": 1, "ch": "classical", "bits": 40, "p": "...", "g": "04", "A": "..."},
                   "M2": {"v": 1, "ch": "classical", "B": "..."},
                   "M3": {"v": 1, "ch": "classical", "nonce": "...", "aead_ct": "..."}},
     "hybrid": {"M1": {"...": "same as classical plus ek (1184 bytes)"},
                "M2": {"...": "B plus kem_ct (1088 bytes)"},
                "M3": {"...": "nonce, aead_ct"}}}},
 "transcript_sha256": "9f2c...",
 "legit": {"classical": {"ok": true}, "hybrid": {"ok": true}}}
```

- The transcript has only the public fields shown. No exponents, keys or secrets, ever.
- `legit` only says whether the real receiver could decrypt. It does not repeat the plaintext.
- `warnings` can include `same_plaintext`.
- `transcript_sha256` is SHA-256 of the transcript as canonical JSON (sorted keys, no spaces, UTF-8). The UI shows it next to the recorded bytes and the attacker's first event repeats it.

`POST /booth/qday`, body `{"session": "b3f1c2"}`. Runs the attacker as a separate process (killed at 10 s) and returns every event in one response. 404 `no_session`, 409 `attack_running`.

```json
{"session": "b3f1c2", "bits": 40, "real_ms": 241,
 "events": [
  {"v": 1, "run": "r1", "ch": null, "t_ms": 0, "type": "input", "transcript_sha256": "9f2c...", "bytes": 3120},
  {"v": 1, "run": "r1", "ch": "classical", "t_ms": 3, "type": "start", "bits": 40, "q_bits": 39, "m": 741455},
  {"v": 1, "run": "r1", "ch": "classical", "t_ms": 20, "type": "baby", "done": 8192, "total": 741455, "pct": 1.1},
  {"v": 1, "run": "r1", "ch": "classical", "t_ms": 90, "type": "giant", "done": 8192, "max": 741455, "pct_upper": 1.1},
  {"v": 1, "run": "r1", "ch": "classical", "t_ms": 118, "type": "found", "exp_hex": "...", "baby_steps": 741455, "giant_steps": 302144, "ms": 115},
  {"v": 1, "run": "r1", "ch": "classical", "t_ms": 119, "type": "derive", "th_hex": "a1b2c3d4e5f60718", "ikm_parts": 1},
  {"v": 1, "run": "r1", "ch": "classical", "t_ms": 120, "type": "decrypt", "ok": true, "plaintext": "invented secret one"},
  {"v": 1, "run": "r1", "ch": "hybrid", "t_ms": 240, "type": "decrypt", "ok": false, "reason": "aead_tag_mismatch",
   "note": "DH secret recovered; ML-KEM contribution unavailable.",
   "guess": "ml_kem_secret=32_zero_bytes (a labeled guess, not an attack on ML-KEM)"},
  {"v": 1, "run": "r1", "ch": null, "t_ms": 241, "type": "done", "total_ms": 241, "peak_rss_bytes": 103000000}],
 "verdict": {"legit_classical_ok": true, "legit_hybrid_ok": true, "attacker_classical_ok": true,
   "hybrid_exception": "InvalidTag", "errors": [], "demo_verdict": "PASS"}}
```

- Event types: input, start, baby, giant, found, derive, decrypt, done, error, fallback. Every event has `v, run, ch, t_ms, type`. `ch` is classical, hybrid or null. Events added by the backend carry `"src": "orchestrator"`.
- An `error` event has `code` and `msg`. Codes: bad_json, bad_version, bad_group, bad_share, bad_schema, not_found, internal, timeout, transport, spawn_failed, reset.
- If the hybrid zero-secret guess ever works, the hybrid decrypt event gets `"unexpected": true`.
- `demo_verdict` is PASS only if legit_classical_ok, legit_hybrid_ok and attacker_classical_ok are true, hybrid_exception is exactly "InvalidTag", and errors is empty. Otherwise FAIL. The UI shows the locked state only on PASS. An attacker exit code of 0 proves nothing by itself.
- The UI replays the events over about 1.6 s with the caption "Replayed at readable speed (1.6 s) | real attack: {real_ms} ms". Expect roughly 190 to 280 events at 40 bits.

## POST /reset

No body. Returns `{"ok": true, "lab_mode": "classical", "cleared": ["sessions", "attacker"]}`. Kills a running attacker, clears booth sessions and the scan cache, puts the lab back to classical. Safe to call any time.

## Who owns what

| piece | owner |
|---|---|
| probe runner, scan and lab routes (`backend/scan/api.py`, `lab/`) | A |
| parser, verdict, scan response assembly (`backend/scan/parse*`, `verdict*`) | Johan |
| booth router (`backend/booth/api.py`) | B |
| app assembly, /health, /reset, static files mounted last (`backend/main.py`) | Johan |
| UI (`ui/`) | C |
