"""Run the transcript-only attacker with bounded time, output, and cancellation."""

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import threading
import time

from .group import BoothError
from .protocol import canonical_json, send

ATTACKER = Path(__file__).with_name("attacker.py").resolve()
GUESS = "ml_kem_secret=32_zero_bytes (a labeled guess, not an attack on ML-KEM)"


def evaluate(sent, events, returncode, expected_classical_hash):
    """Exit status alone cannot authorize a PASS."""
    errors = [event for event in events if event.get("type") == "error"]
    decrypts = [event for event in events if event.get("type") == "decrypt"]
    classical = [e for e in decrypts if e.get("ch") == "classical"]
    hybrid = [e for e in decrypts if e.get("ch") == "hybrid"]
    classical_ok = (len(classical) == 1 and classical[0].get("ok") is True
                    and isinstance(classical[0].get("plaintext"), str)
                    and hashlib.sha256(classical[0]["plaintext"].encode("utf-8")).hexdigest()
                    == expected_classical_hash)
    hybrid_exception = hybrid[0].get("exception") if len(hybrid) == 1 else None
    hybrid_ok = (len(hybrid) == 1 and hybrid[0].get("ok") is False
                 and hybrid[0].get("reason") == "aead_tag_mismatch"
                 and hybrid_exception == "InvalidTag"
                 and hybrid[0].get("guess") == GUESS
                 and hybrid[0].get("unexpected") is False)
    inputs = [e for e in events if e.get("type") == "input"]
    complete = (events and events[0].get("type") == "input"
                and events[-1].get("type") == "done" and len(inputs) == 1
                and inputs[0].get("transcript_sha256") == sent["transcript_sha256"]
                and returncode == 0)
    recovered_both = True
    for channel in ("classical", "hybrid"):
        found = [e for e in events if e.get("type") == "found" and e.get("ch") == channel]
        exponent_hex = found[0].get("exp_hex") if len(found) == 1 else None
        if not isinstance(exponent_hex, str) or re.fullmatch(r"[0-9a-f]{1,10}", exponent_hex) is None:
            recovered_both = False
            continue
        m1 = sent["transcript"]["channels"][channel]["M1"]
        p, g, A = (int(m1[name], 16) for name in ("p", "g", "A"))
        exponent = int(exponent_hex, 16)
        if not 1 <= exponent < (p - 1) // 2 or pow(g, exponent, p) != A:
            recovered_both = False
    passed = bool(sent["legit_classical_ok"] and sent["legit_hybrid_ok"] and sent["combiner_control_ok"]
                  and recovered_both
                  and classical_ok and hybrid_ok and complete and not errors)
    return {"legit_classical_ok": sent["legit_classical_ok"],
            "combiner_control_ok": sent["combiner_control_ok"],
            "legit_hybrid_ok": sent["legit_hybrid_ok"],
            "attacker_classical_ok": classical_ok, "hybrid_exception": hybrid_exception,
            "guess": GUESS, "errors": errors,
            "demo_verdict": "PASS" if passed else "FAIL"}


class Booth:
    def __init__(self, bits=40, timeout=10):
        if bits not in (36, 40):
            raise ValueError("Production booth supports only 36 or 40 bits.")
        self.bits, self.timeout = bits, timeout
        self._lock = threading.RLock()
        self._sent = None
        self._expected = None
        self._running = False
        self._process = None
        self._generation = 0
        self.python = str(Path(sys.executable).resolve())

    def send(self, classical, hybrid, bits=None):
        with self._lock:
            if self._running:
                raise BoothError("attack_running", "An attack is already running. Wait or reset.")
            chosen = self.bits if bits is None else bits
            if type(chosen) is not int or chosen not in (36, 40):
                raise BoothError("invalid_request", "Choose a 36- or 40-bit toy modulus.")
            sent = send(classical, hybrid, chosen)
            self._expected = hashlib.sha256(classical.encode("utf-8")).hexdigest()
            self._sent = sent
            # Return a detached public copy; callers cannot mutate internal state.
            return json.loads(canonical_json(sent))

    def reset(self):
        with self._lock:
            self._generation += 1
            process = self._process
            self._sent, self._expected = None, None
            if process is not None and process.poll() is None:
                process.kill()
            return {"booth": "reset"}

    def qday(self, session=None):
        with self._lock:
            if self._running:
                raise BoothError("attack_running", "An attack is already running. Wait or reset.")
            if self._sent is None:
                raise BoothError("no_session", "Send two invented messages before starting Q-Day.")
            if session is not None and session != self._sent["transcript"]["session"]:
                raise BoothError("no_session", "That recording is unknown or was cleared by Reset.")
            self._running = True
            sent, expected = self._sent, self._expected
            generation = self._generation
        process = None
        events, stderr_tail, returncode = [], "", None
        started = time.perf_counter()
        run = sent["transcript"]["session"]

        def failure(code, message):
            events.append({"v": 1, "run": run, "ch": None, "src": "orchestrator",
                           "t_ms": round((time.perf_counter() - started) * 1000, 3),
                           "type": "error", "code": code, "msg": message})

        try:
            environment = {}
            if os.name == "nt":
                for name in ("SystemRoot", "WINDIR"):
                    if name in os.environ:
                        environment[name] = os.environ[name]
            with tempfile.TemporaryDirectory(prefix="harvest-booth-", ignore_cleanup_errors=True) as directory:
                try:
                    with self._lock:
                        if generation != self._generation:
                            failure("reset", "The attack was cancelled by Reset.")
                        else:
                            process = subprocess.Popen(
                                [self.python, "-I", "-u", str(ATTACKER)], cwd=directory,
                                env=environment, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
                            self._process = process
                except OSError:
                    failure("spawn_failed", "The separate attacker could not start.")
                if process is not None:
                    # Drain both pipes continuously; bound memory even on a broken child.
                    chunks, tail = bytearray(), bytearray()
                    overflow = threading.Event()

                    def drain(pipe, output, limit, keep_tail=False):
                        while True:
                            chunk = pipe.read(4096)
                            if not chunk:
                                return
                            output.extend(chunk)
                            if len(output) > limit:
                                if keep_tail:
                                    del output[:-limit]
                                else:
                                    del output[limit:]
                                    overflow.set()
                                    if process.poll() is None:
                                        process.kill()
                                    return

                    workers = [threading.Thread(target=drain, args=(process.stdout, chunks, 2_000_000), daemon=True),
                               threading.Thread(target=drain, args=(process.stderr, tail, 2000, True), daemon=True)]
                    for worker in workers:
                        worker.start()
                    try:
                        process.stdin.write(canonical_json(sent["transcript"]))
                        process.stdin.close()
                        process.wait(timeout=self.timeout)
                    except subprocess.TimeoutExpired:
                        if process.poll() is None:
                            process.kill()
                        process.wait()
                        failure("timeout", "The attacker exceeded its time limit.")
                    except (BrokenPipeError, OSError):
                        if process.poll() is None:
                            process.kill()
                        process.wait()
                        failure("transport", "The attacker connection closed unexpectedly.")
                    for worker in workers:
                        worker.join()
                    returncode = process.returncode
                    stderr_tail = tail.decode("utf-8", errors="replace")
                    if overflow.is_set():
                        failure("transport", "The attacker produced too much output.")
                    if generation != self._generation:
                        events.clear()
                        failure("reset", "The attack was cancelled by Reset.")
                    elif not events:
                        try:
                            if not chunks.endswith(b"\n"):
                                raise ValueError("incomplete line")
                            lines = chunks.decode("utf-8").splitlines()
                            if len(lines) > 1000:
                                raise ValueError("too many events")
                            for line in lines:
                                event = json.loads(line)
                                if not isinstance(event, dict) or event.get("v") != 1 or event.get("run") != run:
                                    raise ValueError("wrong event")
                                if event.get("ch") not in (None, "classical", "hybrid") or not isinstance(event.get("t_ms"), (int, float)):
                                    raise ValueError("wrong event")
                                if event.get("type") not in ("input", "start", "baby", "giant", "found", "derive", "decrypt", "done", "error"):
                                    raise ValueError("wrong event")
                                events.append(event)
                        except (ValueError, UnicodeError, RecursionError):
                            events.clear()
                            failure("transport", "The attacker returned an incomplete or invalid event.")
                    if returncode != 0 and not any(e["type"] == "error" for e in events):
                        failure("internal", "The attacker exited without completing the demo.")
                    for pipe in (process.stdin, process.stdout, process.stderr):
                        if pipe is not None and not pipe.closed:
                            pipe.close()
        except OSError:
            failure("internal", "The attacker could not complete process cleanup. Reset and try again.")
        finally:
            if process is not None:
                if process.poll() is None:
                    process.kill()
                process.wait()
                for pipe in (process.stdin, process.stdout, process.stderr):
                    if pipe is not None and not pipe.closed:
                        pipe.close()
            with self._lock:
                self._process = None
                self._running = False
        total_ms = round((time.perf_counter() - started) * 1000, 3)
        with self._lock:
            if generation != self._generation and not any(e.get("code") == "reset" for e in events):
                events.clear()
                failure("reset", "The attack was cancelled by Reset.")
            verdict = evaluate(sent, events, returncode, expected)
        return {"events": events, **verdict, "total_ms": total_ms, "bits": sent["bits"],
                "replay_ms": 1600, "stderr_tail": stderr_tail}
