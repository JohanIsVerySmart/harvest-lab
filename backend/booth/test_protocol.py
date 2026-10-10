"""Public protocol boundary and positive-control tests."""

import copy
import json
import unittest
from unittest.mock import patch

from . import group, protocol
from .group import BoothError


class ProtocolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = protocol.send("control", "hybrid control", bits=32)
        cls.transcript = cls.result["transcript"]

    def test_legitimate_controls_and_transcript_digest(self):
        self.assertTrue(self.result["legit_classical_ok"])
        self.assertTrue(self.result["legit_hybrid_ok"])
        self.assertEqual(protocol.digest(self.transcript), self.result["transcript_sha256"])
        self.assertEqual(protocol.validate_transcript(self.transcript), self.transcript)

    def test_public_transcript_has_no_private_material(self):
        forbidden = {"a", "b", "dk", "K", "key", "secret", "plaintext",
                     "private", "private_key", "secret_key", "sk", "exponent",
                     "dh_secret", "kem_secret", "client_ikm", "server_ikm"}

        def visit(value):
            if isinstance(value, dict):
                for name, nested in value.items():
                    self.assertNotIn(name, forbidden)
                    visit(nested)
            elif isinstance(value, list):
                for nested in value:
                    visit(nested)

        visit(self.result)
        injected = copy.deepcopy(self.transcript)
        injected["channels"]["hybrid"]["M1"]["private_key"] = "should never be accepted"
        with self.assertRaises(BoothError) as caught:
            protocol.validate_transcript(injected)
        self.assertEqual(caught.exception.code, "bad_transcript")

    def test_message_byte_boundaries_and_utf8(self):
        self.assertEqual(protocol.message_bytes("x"), b"x")
        self.assertEqual(len(protocol.message_bytes("a" * 64)), 64)
        self.assertEqual(len(protocol.message_bytes("😀" * 16)), 64)
        for text in ("", "a" * 65, "😀" * 17):
            with self.subTest(text_length=len(text)):
                with self.assertRaises(BoothError) as caught:
                    protocol.message_bytes(text)
                self.assertEqual(caught.exception.code, "invalid_request")
        with self.assertRaises(BoothError) as caught:
            protocol.message_bytes("\ud800")
        self.assertEqual(caught.exception.code, "invalid_request")

    def test_bad_group_and_bad_share(self):
        classical = copy.deepcopy(self.transcript["channels"]["classical"])
        width = (classical["M1"]["bits"] + 7) // 8
        classical["M1"]["p"] = (int(classical["M1"]["p"], 16) - 2).to_bytes(width, "big").hex()
        with self.assertRaises(BoothError) as caught:
            protocol.handshake_parts(classical, "classical")
        self.assertEqual(caught.exception.code, "bad_group")

        classical = copy.deepcopy(self.transcript["channels"]["classical"])
        classical["M1"]["A"] = (0).to_bytes(width, "big").hex()
        with self.assertRaises(BoothError) as caught:
            protocol.handshake_parts(classical, "classical")
        self.assertEqual(caught.exception.code, "bad_share")

    def test_hex_fields_reject_newlines(self):
        classical = copy.deepcopy(self.transcript["channels"]["classical"])
        value = classical["M1"]["p"]
        classical["M1"]["p"] = value[:-1] + "\n"
        with self.assertRaises(BoothError) as caught:
            protocol.handshake_parts(classical, "classical")
        self.assertEqual(caught.exception.code, "bad_hex")

    def test_duplicate_keys_and_deep_json_are_bad_json(self):
        with self.assertRaises(BoothError) as caught:
            protocol.load_transcript(b'{"v":1,"v":1}')
        self.assertEqual(caught.exception.code, "bad_json")

        deeply_nested = (b"[" * 2000) + b"0" + (b"]" * 2000)
        with self.assertRaises(BoothError) as caught:
            protocol.load_transcript(deeply_nested)
        self.assertEqual(caught.exception.code, "bad_json")

    def test_fixed_width_dh_retains_leading_zero_bytes(self):
        p, g, q = group.fresh_group(32)
        width = (p.bit_length() + 7) // 8
        exponents = []
        for exponent in range(1, min(q, 100_001)):
            if pow(g, exponent, p).to_bytes(width, "big")[0] == 0:
                exponents.append(exponent)
                if len(exponents) == 2:
                    break
        self.assertEqual(len(exponents), 2, "could not find two leading-zero public values")
        a, b = exponents
        with patch("backend.booth.group.secrets.randbelow", side_effect=[a - 1, b - 1]):
            A, B, client, server = group.exchange(p, g, q)
        self.assertEqual(A.to_bytes(width, "big")[0], 0)
        self.assertEqual(B.to_bytes(width, "big")[0], 0)
        self.assertEqual(len(client), width)
        self.assertEqual(len(server), width)
        self.assertEqual(client[0], 0)
        self.assertEqual(server[0], 0)
        self.assertEqual(client, server)
        self.assertEqual(client, pow(B, a, p).to_bytes(width, "big"))


class KemTests(unittest.TestCase):
    def test_mlkem_768_wrapper_roundtrip_when_available(self):
        try:
            from . import kem
        except (ImportError, ModuleNotFoundError) as exc:
            self.skipTest(f"ML-KEM wrapper is not available: {exc}")
        public, private = kem.keygen()
        server_secret, ciphertext = kem.encaps(public)
        client_secret = kem.decaps(private, ciphertext)
        self.assertEqual(len(public), 1184)
        self.assertEqual(len(ciphertext), 1088)
        self.assertEqual(len(server_secret), 32)
        self.assertEqual(client_secret, server_secret)


if __name__ == "__main__":
    unittest.main()
