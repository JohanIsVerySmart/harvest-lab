"""API tests against a REAL server process (backend.scan.devserver on :8000).

    python -m unittest backend.scan.tests.test_api -v

Needs ports 8000 and 8443 free. Public scans only run against a host YOU
type: set HL_LIVE_HOST=google.com to include one.
"""
import http.client
import json
import os
import subprocess
import sys
import time
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
GOOD_HOST = "127.0.0.1:8000"


def call(method, path, body=None, headers=None):
    conn = http.client.HTTPConnection("127.0.0.1", 8000, timeout=30)
    all_headers = {"Host": GOOD_HOST}
    if body is not None:
        all_headers["Content-Type"] = "application/json"
    all_headers.update(headers or {})
    conn.request(method, path, body=None if body is None else json.dumps(body), headers=all_headers)
    resp = conn.getresponse()
    data = resp.read()
    conn.close()
    return resp.status, json.loads(data) if data else None


class Api(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = subprocess.Popen(
            [sys.executable, "-m", "backend.scan.devserver"],
            cwd=REPO_ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        deadline = time.monotonic() + 20
        while True:
            try:
                if call("GET", "/api/v1/lab/status")[1]["mode"] == "classical":
                    break
            except OSError:
                pass
            if time.monotonic() > deadline:
                cls.server.kill()
                raise RuntimeError("devserver did not start")
            time.sleep(0.2)

    @classmethod
    def tearDownClass(cls):
        call("POST", "/api/v1/lab/mode", {"mode": "stop"})
        cls.server.terminate()
        cls.server.wait(timeout=10)

    def assert_error(self, response, status, code):
        self.assertEqual(response[0], status, response)
        self.assertEqual(response[1]["error"]["code"], code)
        self.assertTrue(response[1]["error"]["message"])

    # --- input that must never reach DNS or OpenSSL ---

    def test_bad_hosts(self):
        for host in ["localhost", "127.0.0.1", "https://google.com/x", "-oX.com", "a.local", " "]:
            with self.subTest(host=host):
                self.assert_error(call("POST", "/api/v1/scan", {"host": host}), 400, "invalid_host")

    def test_extra_field_and_bad_body(self):
        self.assert_error(call("POST", "/api/v1/scan", {"host": "google.com", "port": 8443}), 422, "invalid_request")
        self.assert_error(call("POST", "/api/v1/scan", {}), 422, "invalid_request")
        self.assert_error(call("POST", "/api/v1/scan", {"host": 5}), 422, "invalid_request")
        self.assert_error(call("POST", "/api/v1/lab/mode", {"mode": "yellow"}), 422, "invalid_request")
        self.assert_error(call("POST", "/api/v1/lab/mode", {"mode": "classical; rm -rf /"}), 422, "invalid_request")

    def test_dns_failure_is_200_inconclusive(self):
        # A made-up top-level domain: the root servers say NXDOMAIN, no host is contacted.
        status, body = call("POST", "/api/v1/scan", {"host": "no-such-host.harvestlab-made-up-tld"})
        self.assertEqual(status, 200)
        self.assertEqual(body["probes"], {})
        self.assertEqual(body["verdict"]["label"], "inconclusive")
        self.assertEqual(body["verdict"]["reason"]["code"], "dns_failure")

    # --- local API protection ---

    def test_foreign_origin_and_host_rejected(self):
        status, body = call("POST", "/api/v1/lab/mode", {"mode": "stop"}, {"Origin": "http://evil.example"})
        self.assertEqual((status, body["error"]["code"]), (403, "invalid_request"))
        status, _ = call("GET", "/api/v1/lab/status", headers={"Host": "evil.example:8000"})
        self.assertEqual(status, 403)
        status, _ = call("GET", "/api/v1/lab/status", headers={"Sec-Fetch-Site": "cross-site"})
        self.assertEqual(status, 403)
        status, _ = call("GET", "/api/v1/lab/status", headers={"Origin": "http://127.0.0.1:8000"})
        self.assertEqual(status, 200)

    def test_lab_mutations_are_post_only(self):
        self.assertEqual(call("GET", "/api/v1/lab/mode")[0], 405)
        self.assertEqual(call("GET", "/api/v1/lab/scan")[0], 405)

    # --- the FIX flow through HTTP ---

    def test_lab_flow(self):
        expected = [
            ("classical", "classical_observed", None),
            ("hybrid", "hybrid_observed", None),
            ("classical", "classical_observed", None),
            ("stop", "inconclusive", "connection_refused"),
            ("classical", "classical_observed", None),
        ]
        for mode, label, reason in expected:
            with self.subTest(mode=mode):
                status, st = call("POST", "/api/v1/lab/mode", {"mode": mode})
                self.assertEqual(status, 200, st)
                self.assertEqual(st["mode"], mode)
                self.assertIsInstance(st["switch_ms"], int)
                status, scan = call("POST", "/api/v1/lab/scan")
                self.assertEqual(status, 200)
                self.assertEqual(scan["schema"], "harvestlab.scan/1")
                self.assertEqual(scan["target"]["kind"], "lab")
                self.assertEqual(scan["verdict"]["label"], label)
                if reason:
                    self.assertEqual(scan["verdict"]["reason"]["code"], reason)
                self.assertEqual(call("GET", "/api/v1/lab/status")[1]["mode"], mode)

    @unittest.skipUnless(os.environ.get("HL_LIVE_HOST"), "set HL_LIVE_HOST=<host you typed>")
    def test_live_public_scan(self):
        host = os.environ["HL_LIVE_HOST"]
        status, scan = call("POST", "/api/v1/scan", {"host": host})
        self.assertEqual(status, 200)
        self.assertEqual(scan["target"]["kind"], "public")
        self.assertEqual(set(scan["probes"]), {"default", "hybrid_only", "classical_only"})
        print(f"\n    {host}: {scan['verdict']['label']} via {scan['probes']['default']['group']} in {scan['elapsed_ms']} ms")


if __name__ == "__main__":
    unittest.main()
