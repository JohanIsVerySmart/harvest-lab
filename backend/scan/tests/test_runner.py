"""Runner tests: timeout kills, output cap, temp trace removed, classification.

    python -m unittest backend.scan.tests.test_runner -v

The stderr samples below were captured from real OpenSSL 3.5.5 runs against
local test servers (wrong cert, TLS 1.2-only, classical-only) on Oct 9.
"""
import glob
import os
import sys
import tempfile
import time
import unittest

from backend.scan.openssl_env import check_openssl
from backend.scan.runner import (
    OUTPUT_CAP, RunResult, classify, parse_brief, parse_trace_key_share, run_capped, run_probe,
)

OK_HYBRID = """Connecting to 142.251.153.119
CONNECTION ESTABLISHED
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_256_GCM_SHA384
Peer certificate: CN=www.google.com
Hash used: SHA256
Signature type: ecdsa_secp256r1_sha256
Verification: OK
Verified peername: www.google.com
Negotiated TLS1.3 group: X25519MLKEM768
DONE
"""
OK_CLASSICAL_P256 = OK_HYBRID.replace(
    "Negotiated TLS1.3 group: X25519MLKEM768", "Peer Temp Key: ECDH, prime256v1, 256 bits"
)
CERT_FAIL = """Connecting to 127.0.0.1
depth=0 CN=Harvest Lab WRONG cert
verify error:num=18:self-signed certificate
C0340000:error:0A000086:SSL routines:tls_post_process_server_certificate:certificate verify failed:../openssl-3.5.5/ssl/statem/statem_clnt.c:2124:
"""
PROTO = """Connecting to 127.0.0.1
CC5C0000:error:0A00042E:SSL routines:ssl3_read_bytes:tlsv1 alert protocol version:../openssl-3.5.5/ssl/record/rec_layer_s3.c:918:SSL alert number 70
"""
HS_FAIL = """Connecting to 127.0.0.1
9CB10000:error:0A000410:SSL routines:ssl3_read_bytes:ssl/tls alert handshake failure:../openssl-3.5.5/ssl/record/rec_layer_s3.c:918:SSL alert number 40
"""
# macOS wording, written from memory of OpenSSL's format (not captured tonight).
REFUSED_MAC = """80EB1A01:error:8000003D:system library:BIO_connect:Connection refused:crypto/bio/bio_sock2.c:178:calling connect()
80EB1A01:error:10000067:BIO routines:BIO_connect:connect error:crypto/bio/bio_sock2.c:180:
connect:errno=61
"""
# A server can choose its certificate subject. Scary words there must not matter.
SPOOFED_SUBJECT = OK_HYBRID.replace(
    "Peer certificate: CN=www.google.com",
    "Peer certificate: CN=verify error: alert handshake failure connect:errno=61",
)

TRACE_HRR = """Sent TLS Record
    ClientHello, Length=337
        extension_type=key_share(51), length=139
            NamedGroup: secp521r1 (P-521) (25)
            key_exchange:  (len=133): 0400A3
Received TLS Record
    ServerHello, Length=84
        extension_type=key_share(51), length=2
            NamedGroup: X25519MLKEM768 (4588)
Sent TLS Record
    ClientHello, Length=1420
        extension_type=supported_groups(10), length=6
            X25519MLKEM768 (4588)
        extension_type=key_share(51), length=1222
            NamedGroup: X25519MLKEM768 (4588)
            key_exchange:  (len=1216): 3268
Received TLS Record
    ServerHello, Length=1206
        extension_type=key_share(51), length=1124
            NamedGroup: X25519MLKEM768 (4588)
            key_exchange:  (len=1120): 57B5
    EncryptedExtensions, Length=2
"""


def result(stderr, exit_code=1, timed_out=False, capped=False):
    return RunResult(exit_code, "", stderr, timed_out, capped, 10)


def outcome_of(stderr, exit_code=1):
    run = result(stderr, exit_code)
    return classify(run, parse_brief(stderr), "127.0.0.1", 443, 5)


class RunCapped(unittest.TestCase):
    def test_timeout_kills_and_reaps(self):
        start = time.monotonic()
        run = run_capped([sys.executable, "-c", "import time; time.sleep(30)"], None, 1.0)
        self.assertTrue(run.timed_out)
        self.assertIsNotNone(run.exit_code)  # reaped: a real exit status exists
        self.assertLess(time.monotonic() - start, 4)

    def test_output_cap_stops_child(self):
        run = run_capped([sys.executable, "-c", "import sys; sys.stdout.write('x' * 300000); sys.stdout.flush(); import time; time.sleep(30)"], None, 10)
        self.assertTrue(run.output_capped)
        self.assertFalse(run.timed_out)
        self.assertLessEqual(len(run.stdout), OUTPUT_CAP)

    def test_normal_exit(self):
        run = run_capped([sys.executable, "-c", "print('hello')"], None, 5)
        self.assertEqual((run.exit_code, run.stdout.strip(), run.timed_out), (0, "hello", False))


class Classify(unittest.TestCase):
    def test_ok_hybrid(self):
        brief = parse_brief(OK_HYBRID)
        self.assertEqual(brief["groups"], ["X25519MLKEM768"])
        self.assertEqual(outcome_of(OK_HYBRID, 0), ("ok", None))

    def test_ok_p256_name(self):
        self.assertEqual(parse_brief(OK_CLASSICAL_P256)["groups"], ["secp256r1"])
        self.assertEqual(outcome_of(OK_CLASSICAL_P256, 0)[0], "ok")

    def test_failures(self):
        table = [
            (CERT_FAIL, "cert_fail", "cert_verify"),
            (PROTO, "proto_refused", "protocol_version"),
            (HS_FAIL, "hs_refused", "handshake_failure"),
            (REFUSED_MAC, "net_refused", "connection_refused"),
        ]
        for stderr, outcome, code in table:
            with self.subTest(outcome=outcome):
                got_outcome, reason = outcome_of(stderr)
                self.assertEqual((got_outcome, reason["code"]), (outcome, code))

    def test_spoofed_subject_is_still_ok(self):
        self.assertEqual(outcome_of(SPOOFED_SUBJECT, 0), ("ok", None))

    def test_two_established_lines_is_not_ok(self):
        doubled = OK_HYBRID.replace("CONNECTION ESTABLISHED", "CONNECTION ESTABLISHED\nCONNECTION ESTABLISHED")
        self.assertEqual(outcome_of(doubled, 0)[0], "parse_fail")

    def test_no_group_line_is_not_ok(self):
        missing = OK_HYBRID.replace("Negotiated TLS1.3 group: X25519MLKEM768\n", "")
        self.assertEqual(outcome_of(missing, 0)[0], "parse_fail")

    def test_timeout_flag_wins_over_exit_code(self):
        run = result("", exit_code=-9, timed_out=True)
        self.assertEqual(classify(run, parse_brief(""), "1.2.3.4", 443, 5)[0], "timeout")
        run = result("", exit_code=-9, timed_out=False)  # SIGKILL exit alone is not a timeout
        self.assertNotEqual(classify(run, parse_brief(""), "1.2.3.4", 443, 5)[0], "timeout")


class TraceKeyShare(unittest.TestCase):
    def test_hello_retry_uses_last_hellos(self):
        self.assertEqual(
            parse_trace_key_share(TRACE_HRR),
            {"client": [{"group": "X25519MLKEM768", "len": 1216}],
             "server": {"group": "X25519MLKEM768", "len": 1120}},
        )

    def test_incomplete_trace_is_none(self):
        self.assertIsNone(parse_trace_key_share("Sent TLS Record\n    ClientHello, Length=3\n"))


class TempTraceRemoved(unittest.TestCase):
    def test_trace_file_deleted_after_probe(self):
        pattern = os.path.join(tempfile.gettempdir(), "hl-*.trace")
        before = set(glob.glob(pattern))
        info = check_openssl()
        record = run_probe("default", info["path"], "127.0.0.1", 9, "localhost", info["ca_file"], 5)
        self.assertEqual(record["outcome"], "net_refused")
        self.assertIn("<tmp>", record["cmd"])
        self.assertEqual(set(glob.glob(pattern)) - before, set())


if __name__ == "__main__":
    unittest.main()
