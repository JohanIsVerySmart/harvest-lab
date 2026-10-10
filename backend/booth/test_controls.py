"""End-to-end controls for the transcript-only Q-Day attacker."""

import copy
import hashlib
import json
import math
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

from . import kem, protocol
from .runner import evaluate


ATTACKER = Path(__file__).with_name("attacker.py").resolve()


def bsgs(base, target, modulus, order):
    """Recover x where target=base**x mod modulus, for the subgroup order."""
    width = math.isqrt(order - 1) + 1
    babies = {}
    value = 1
    for j in range(width):
        babies.setdefault(value, j)
        value = value * base % modulus
    factor = pow(pow(base, width, modulus), -1, modulus)
    giant = target
    for i in range(width + 1):
        if giant in babies:
            candidate = i * width + babies[giant]
            if candidate < order and pow(base, candidate, modulus) == target:
                return candidate
        giant = giant * factor % modulus
    raise AssertionError("BSGS did not recover the public DH exponent")


def run_attacker(transcript, timeout=4):
    if not ATTACKER.is_file():
        raise AssertionError(f"standalone attacker is not available yet: {ATTACKER}")
    env = {name: os.environ[name] for name in ("SystemRoot", "WINDIR")
           if name in os.environ}
    started = time.perf_counter()
    with tempfile.TemporaryDirectory(prefix="booth-test-attacker-",
                                     dir=str(ATTACKER.parent)) as directory:
        completed = subprocess.run(
            [sys.executable, "-I", "-u", str(ATTACKER)],
            cwd=directory, env=env, input=protocol.canonical_json(transcript),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout,
            check=False)
    elapsed = time.perf_counter() - started
    try:
        events = [json.loads(line) for line in completed.stdout.decode("utf-8").splitlines()]
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise AssertionError("attacker did not return valid JSON events") from exc
    return completed.returncode, events, elapsed


def assert_complete_channel_cracks(test, transcript, events):
    found = [event for event in events if event.get("type") == "found"]
    test.assertEqual(len(found), 2, "attacker must report exactly one recovered exponent per channel")
    test.assertEqual({event.get("ch") for event in found}, {"classical", "hybrid"})
    for event in found:
        channel = event["ch"]
        record = transcript["channels"][channel]
        width = (record["M1"]["bits"] + 7) // 8
        p = int.from_bytes(bytes.fromhex(record["M1"]["p"]), "big")
        g = int.from_bytes(bytes.fromhex(record["M1"]["g"]), "big")
        A = int.from_bytes(bytes.fromhex(record["M1"]["A"]), "big")
        exponent = int(event["exp_hex"], 16)
        test.assertLess(exponent, (p - 1) // 2)
        test.assertEqual(pow(g, exponent, p), A,
                         f"reported {channel} exponent does not recover that channel's public A")
        test.assertEqual(len(bytes.fromhex(record["M1"]["A"])), width)

        baby_events = [item for item in events
                       if item.get("type") == "baby" and item.get("ch") == channel]
        test.assertTrue(baby_events, f"missing {channel} baby-step progress")
        final = baby_events[-1]
        test.assertEqual(final.get("done"), final.get("total"),
                         f"{channel} baby-step progress did not reach 100%")


def assert_no_hybrid_plaintext(test, events, expected_plaintext):
    for event in events:
        if event.get("ch") == "hybrid":
            test.assertNotIn("plaintext", event,
                             "hybrid plaintext must not appear in API or attacker events")
            test.assertNotIn(expected_plaintext, json.dumps(event, ensure_ascii=True))


class HybridControlTests(unittest.TestCase):
    def captured_send(self, classical="learn later", hybrid="resistant later"):
        captured = []
        original = kem.encaps

        def capture(public_key):
            result = original(public_key)
            captured.append(result[0])
            return result

        with patch.object(protocol.kem, "encaps", side_effect=capture):
            sent = protocol.send(classical, hybrid, bits=32)
        self.assertEqual(len(captured), 1)
        return sent, classical, hybrid, captured[0]

    def check_hybrid_key_paths(self, sent, plaintext, real_kem_secret):
        record = sent["transcript"]["channels"]["hybrid"]
        p, g, q, A, B, width, salt, info, nonce, ciphertext = protocol.handshake_parts(record, "hybrid")
        exponent = bsgs(g, A, p, q)
        dh_secret = pow(B, exponent, p).to_bytes(width, "big")

        zero_key = protocol.derive_key(bytes(32) + dh_secret, salt, info)
        with self.assertRaises(InvalidTag) as caught:
            AESGCM(zero_key).decrypt(nonce, ciphertext, salt)
        self.assertIsInstance(caught.exception, InvalidTag)

        dh_only_key = protocol.derive_key(dh_secret, salt, info)
        with self.assertRaises(InvalidTag) as caught:
            AESGCM(dh_only_key).decrypt(nonce, ciphertext, salt)
        self.assertIsInstance(caught.exception, InvalidTag)

        hybrid_key = protocol.derive_key(real_kem_secret + dh_secret, salt, info)
        self.assertEqual(AESGCM(hybrid_key).decrypt(nonce, ciphertext, salt),
                         plaintext.encode("utf-8"))
        return (p, g, q, A, B, width, salt, info, nonce, ciphertext, dh_secret)

    def test_zero_kem_guess_dh_only_and_real_hybrid_control(self):
        sent, classical_plaintext, hybrid_plaintext, shared_secret = self.captured_send()
        self.assertNotIn(shared_secret.hex(), protocol.canonical_json(sent).decode("ascii"))
        parts = self.check_hybrid_key_paths(sent, hybrid_plaintext, shared_secret)
        self.assertTrue(sent["legit_classical_ok"])
        self.assertTrue(sent["legit_hybrid_ok"])

        record = sent["transcript"]["channels"]["classical"]
        p, g, q, A, B, width, salt, info, nonce, ciphertext = protocol.handshake_parts(record, "classical")
        exponent = bsgs(g, A, p, q)
        dh_secret = pow(B, exponent, p).to_bytes(width, "big")
        key = protocol.derive_key(dh_secret, salt, info)
        self.assertEqual(AESGCM(key).decrypt(nonce, ciphertext, salt),
                         classical_plaintext.encode("utf-8"))
        self.assertEqual(len(parts[-1]), 4)

    def test_dropped_kem_ikm_makes_hybrid_dh_only_and_evaluation_fail(self):
        original = protocol.derive_key

        def drop_hybrid_kem(ikm, salt, info):
            if len(ikm) > 4:
                ikm = ikm[32:]
            return original(ikm, salt, info)

        with patch.object(protocol, "derive_key", side_effect=drop_hybrid_kem):
            forged = protocol.send("learn later", "resistant later", bits=32)

        record = forged["transcript"]["channels"]["hybrid"]
        p, g, q, A, B, width, salt, info, nonce, ciphertext = protocol.handshake_parts(record, "hybrid")
        exponent = bsgs(g, A, p, q)
        dh_secret = pow(B, exponent, p).to_bytes(width, "big")
        dh_only_key = original(dh_secret, salt, info)
        self.assertEqual(AESGCM(dh_only_key).decrypt(nonce, ciphertext, salt),
                         b"resistant later")

        returncode, events, _ = run_attacker(forged["transcript"])
        expected = hashlib.sha256(b"learn later").hexdigest()
        verdict = evaluate(forged, events, returncode, expected)
        assert_no_hybrid_plaintext(self, events, "resistant later")
        self.assertEqual(verdict["demo_verdict"], "FAIL")
        self.assertTrue(verdict["attacker_classical_ok"])
        self.assertFalse(verdict["combiner_control_ok"])

    def test_twenty_fresh_random_transcripts_with_isolated_attacker(self):
        durations = []
        for _ in range(20):
            classical = "C-" + os.urandom(12).hex()
            hybrid = "H-" + os.urandom(12).hex()
            sent = protocol.send(classical, hybrid, bits=32)
            returncode, events, elapsed = run_attacker(sent["transcript"])
            durations.append(elapsed)
            expected = hashlib.sha256(classical.encode("utf-8")).hexdigest()
            verdict = evaluate(sent, events, returncode, expected)
            assert_complete_channel_cracks(self, sent["transcript"], events)
            assert_no_hybrid_plaintext(self, events, hybrid)
            self.assertEqual(verdict["demo_verdict"], "PASS")
            if not durations[:-1]:
                missing_hybrid_recovery = [e for e in events if not (e.get("ch") == "hybrid" and e.get("type") == "found")]
                self.assertEqual(evaluate(sent, missing_hybrid_recovery, 0, expected)["demo_verdict"], "FAIL")
            self.assertTrue(any(event.get("type") == "input"
                                and event.get("transcript_sha256") == sent["transcript_sha256"]
                                for event in events))
            self.assertLess(elapsed, 2.0, "measured isolated attacker run exceeded two seconds")
        self.assertEqual(len(durations), 20)

    def test_damaged_classical_ciphertext_cannot_pass_on_exit_zero(self):
        sent = protocol.send("learn later", "resistant later", bits=32)
        damaged = copy.deepcopy(sent["transcript"])
        channel = damaged["channels"]["classical"]
        raw = bytearray.fromhex(channel["M3"]["aead_ct"])
        raw[-1] ^= 1
        channel["M3"]["aead_ct"] = raw.hex()
        sent["transcript"] = damaged
        sent["transcript_sha256"] = protocol.digest(damaged)
        sent["bytes"] = len(protocol.canonical_json(damaged))

        returncode, events, _ = run_attacker(damaged)
        verdict = evaluate(sent, events, returncode, hashlib.sha256(b"learn later").hexdigest())
        assert_no_hybrid_plaintext(self, events, "resistant later")
        self.assertEqual(verdict["demo_verdict"], "FAIL")
        if returncode == 0:
            self.assertFalse(verdict["attacker_classical_ok"])


if __name__ == "__main__":
    unittest.main()
