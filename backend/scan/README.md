# Scanner + Lab (teammate A)

Folders: `backend/scan/` (except Johan's `parse*` / `verdict*`) and `lab/`.

## Files

| File | What it does |
|---|---|
| `openssl_env.py` | Finds OpenSSL by absolute path (`HL_OPENSSL`), refuses LibreSSL or < 3.5, checks `-trace`, finds the public CA file (`HL_CA_FILE`), builds the minimal child env. |
| `hostcheck.py` | Validates typed text before any DNS, resolves once (2 s), blocks if ANY answer is non-public, pins the first public IPv4. |
| `procutil.py` | Starts children in their own process group; kill-and-reap; pidfile helpers. Never kills by name. |
| `runner.py` | Runs ONE `s_client` probe: deadline, 64 KB output cap, 256 KB private trace file, success predicate, outcome + reason, key_share sizes from the trace. |
| `probes.py` | Three probes in parallel on one pinned IP; one scan at a time. `scan_public(text)` and `scan_lab()` (no input). |
| `api.py` | `router` with `POST /scan`, `POST /lab/scan`, `POST /lab/mode`, `GET /lab/status`. |
| `localguard.py` | ASGI middleware: exact Host allowlist, rejects foreign `Origin` and `Sec-Fetch-Site: cross-site`. |
| `interim.py` | TEMPORARY truth table, used only while `verdict.py` does not exist. Delete when Johan's lands. |
| `record.py` | Saves one real scan of a host YOU type as a dated recording in `recordings/`. |
| `devserver.py` | DEV ONLY app to test these routes without `main.py`. |
| `lab/make_certs.py` | Lab CA + leaf (ECDSA P-256, localhost/127.0.0.1/::1, 5 days) + a `wrong` cert for the cert test. Refuses unless git ignores `lab/certs/`. |
| `lab/labctl.py` | Lab `s_server` on 127.0.0.1:8443: modes, pidfile, switch lock, readiness check, lock-free status. |

## Commands (from the repo root, venv active)

```bash
python -m backend.scan.openssl_env
python -m lab.make_certs
python -m lab.labctl classical
python -m backend.scan.devserver
python -m backend.scan.record google.com --network "Ensign venue wifi"
python -m unittest backend.scan.tests.test_hostcheck backend.scan.tests.test_runner lab.tests.test_lab backend.scan.tests.test_api
```

Live checks are opt-in: `HL_LIVE=1` (real DNS for localtest.me) and `HL_LIVE_HOST=<host you typed>`.
Env: `HL_OPENSSL`, `HL_CA_FILE`, `HL_PROBE_DEADLINE_S` (default 5, clamped 4..8), `HL_LAB_STATE_DIR` (pidfile + server log; default the OS temp dir, outside the repo).

## What `backend/main.py` needs from A (see `devserver.py` for working code)

1. At startup: `check_openssl()`; refuse to start on `OpenSSLUnavailable`.
2. At startup: `LAB.startup()` (cleans a server left by a crashed run), then `LAB.set_mode("classical")`. At shutdown: `LAB.shutdown()`.
3. `app.add_middleware(LocalOnlyGuard)` and a `RequestValidationError` handler returning 422 `invalid_request`.
4. `app.include_router(backend.scan.api.router)` before the static mount.
5. `/health` can use `check_openssl()` -> `path`, `version`, `trace_supported`, `ca_file`.
6. `/reset` calls `lab.labctl.reset()` (lab back to classical; raises `LabError("lab_switching")` if a switch is running).

## Interface for Johan's `verdict.py`

`assemble(scan, problem=None) -> scan`, adding `cert`, `verdict`, `pq_note`, `footer`.
`scan` already has `schema, target, scanned_at, elapsed_ms, cache_age_s, client_profile, probes`.
`problem` is `None` or `{"code": "dns_failure", "text": ...}` (then `probes == {}`).
Probe `reason.code` values: `timeout, connection_refused, connect_failed, cert_verify, handshake_failure, protocol_version, tls_alert, connection_closed, output_cap, parse_fail, local_error`.
`api.py` falls back to `interim.py` ONLY if `backend/scan/verdict.py` is missing; if it exists but is broken, startup fails loudly.

## Contract questions for Johan

- LocalOnlyGuard answers **403** `invalid_request`; the table has no 403 row.
- A second scan waits for the first; if the slot is held too long it returns 500 `internal` (no busy code in the contract).
- Lab start problems (port 8443 held by a foreign pid, missing or expiring certs) return 500 `internal` with a plain-English message.
- `no_public_ipv4` never fires: any non-public answer already gives `blocked_address`.
- **yellow** passed its test on OpenSSL 3.5.5 (`-serverpref -groups X25519:X25519MLKEM768`): default probe gets X25519, hybrid-only succeeds, verdict `hybrid_supported_not_chosen`. Re-run `lab.tests.test_lab` on the demo Mac (3.6.4), then add `yellow` to the contract enum; `api.py` needs a one-word change.

## Known differences on Windows dev laptops (the demo is the Mac)

- `SYSTEMROOT` must be in the child env or OpenSSL has no entropy.
- A refused connect takes about 2 s and OpenSSL prints `errno=0`; the runner confirms with one Python connect. The Mac refuses instantly with errno 61.
- Lab switches take about 150 to 300 ms on Windows (process start cost).
