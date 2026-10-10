# Booth handoff (Teammate B)

This is a passive-recording teaching demonstration, with a deliberately tiny,
unauthenticated DH group. It is not TLS or X25519. A classical BSGS attack recovers
toy DH; the hybrid key also requires an ML-KEM secret absent from the recording.
One failed zero-secret guess demonstrates only that this guess failed.

## Run from the repository root

Use Python 3.12 or newer and the team's single virtual environment. Install the
exact verified package versions from `backend/booth/requirements.txt`.

Windows:

```
.venv/Scripts/python.exe -m pip install -r backend/booth/requirements.txt
.venv/Scripts/python.exe -m backend.booth.cli --bits 40
.venv/Scripts/python.exe -m backend.booth.cli --bits 40 --benchmark 20
.venv/Scripts/python.exe -m unittest backend.booth.test_protocol backend.booth.test_controls backend.booth.test_runner -v
```

On the demo Mac substitute `.venv/bin/python`. Repeat the ML-KEM round trip and
20-run benchmark there; ThinkPad measurements do not establish demo-Mac timing.
Manual `--bits 36` exists. There is no automatic fallback. The `32`-bit group is
available only to the protocol test harness, not the booth CLI or API.

The CLI's default text is invented. Judges should enter invented messages,
never real secrets. CLI output includes the recovered classical plaintext.
Keep recordings and CLI output out of Git.

## Integration agreement pending republication

These API shapes follow Johan's previously published `contract/api.md` from
this event. The replacement repository currently has no contract file. Johan
should republish or confirm the agreement before the UI is integrated.

Johan includes `backend.booth.api.router` in the main FastAPI app before its
static-file mount. The two synchronous booth handlers are:

- `POST /api/v1/booth/send` with `{"classical_message":"invented text","hybrid_message":"invented text"}`; optional manual `bits` is 36 or 40.
- `POST /api/v1/booth/qday` with `{"session":"identifier returned by send"}`, returning the complete event list.

Each message is 1 to 64 UTF-8 bytes. Return fields include public `transcript`,
`transcript_sha256`, real `bits`/`p_bits`, public payload `wire_bytes`, the exact
`kem` implementation, and `legit.classical.ok` / `legit.hybrid.ok`. The wire encoding is
specified in `SPEC.md`. The UI shows the full recording digest, real measured
attack time, and the caption:

> Replayed at readable speed (1.6 s) | real attack: N ms

Only `verdict.demo_verdict == "PASS"` authorizes demo success. `verdict.legit_hybrid_ok` must be
true before displaying locked. Every hybrid attack summary retains the guess
label `ml_kem_secret=32_zero_bytes (a labeled guess, not an attack on ML-KEM)`. Only the specific `InvalidTag` exception is
a rejected guess; any other failure is an error.

Johan's global `/api/v1/reset` must call `backend.booth.api.reset_booth()` in
addition to resetting the lab. No competing global Reset endpoint is defined
here. Run one uvicorn worker on `127.0.0.1`; no reload during the demonstration.
The API defaults to 40 bits. Setting `HARVEST_BOOTH_BITS=36` before starting it is
the manual size switch. Overlapping attacks receive HTTP 409 `attack_running`;
an unknown or cleared session receives HTTP 404 `no_session`; invalid requests
receive HTTP 422 `invalid_request`.
Reset kills the tracked child and invalidates the recording; the next send works.

## Isolation, limits, and evidence

The attacker is a separate `python -I -u` process with a temporary working
directory, minimal environment, stdin-only transcript input, flushed JSON-line
events, and no imports from booth modules. This is process separation, not an OS
security boundary. It validates the public group independently and builds fresh
BSGS dictionaries. Baby progress completes; giant progress can stop early.

The runner kills the child at 10 seconds, bounds event output, drains both pipes,
keeps only the last 2000 stderr bytes, and closes pipes in cleanup. A failed
positive control, wrong plaintext, damaged recording, wrong digest, incomplete
events, unexpected successful guess, or any error prevents PASS.

The production sender returns only an allowlisted public recording and checks;
it drops references to the exponents and ML-KEM private material after sending.
The real ML-KEM contribution is captured only inside `test_controls.py` for the
disclosure test. No production attacker path accepts it.

The sender also tries a DH-only hybrid key as a control. If that key decrypts,
the verdict fails even if the zero-secret guess fails. This catches omission of
the ML-KEM contribution. Controls are not portrayed as attacks.

Contract clarification for Johan: the previous example includes input plaintext in both
`legit` objects. The teammate brief explicitly forbids plaintext in send/API
responses, allowing only classical attacker output. This implementation returns
only `ok` in `legit` and omits those plaintext fields. Please reconcile the
contract; no other teammate's files were edited. `wire_bytes` follows the
contract's decoded-public-payload counts; it excludes JSON and canonical hash
framing. The attacker input `bytes` counts the complete canonical JSON recording.

Libraries to credit in the root README (Johan owns that file):
[cryptography](https://cryptography.io/),
[FastAPI](https://fastapi.tiangolo.com/), and
[uvicorn](https://www.uvicorn.org/).

## Review and rehearsal

Review the protocol byte layout with Johan and explain each submitted function.
Record the checks performed in the PR description. Johan merges to main.

Questions to rehearse: Why does a successful legitimate hybrid decrypt matter?
Why isn't rejecting one zero-secret guess a proof of ML-KEM security? How does
the disclosure control distinguish a missing contribution from broken encryption?
