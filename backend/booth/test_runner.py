"""Actual isolated process cancellation, timeout, and HTTP boundary checks."""

import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
import time
import unittest
import urllib.error
import urllib.request
from unittest.mock import patch

from .group import BoothError
from .runner import Booth


class RunnerTests(unittest.TestCase):
    def test_no_session_and_spawn_failure(self):
        booth = Booth(36)
        with self.assertRaises(BoothError):
            booth.qday()
        booth.send("invented", "invented hybrid")
        booth.python = str(Path(__file__).with_name("missing-python.exe"))
        result = booth.qday()
        self.assertEqual(result["demo_verdict"], "FAIL")
        self.assertEqual(result["errors"][0]["code"], "spawn_failed")
        self.assertFalse(booth._running)

    def test_timeout_kills_real_process(self):
        booth = Booth(36, timeout=0.00001)
        booth.send("invented", "invented hybrid")
        result = booth.qday()
        self.assertEqual(result["demo_verdict"], "FAIL")
        self.assertIn("timeout", [e["code"] for e in result["errors"]])
        self.assertIsNone(booth._process)
        self.assertFalse(booth._running)

    def test_reset_cancels_and_double_click_is_guarded(self):
        booth = Booth(40)
        booth.send("invented", "invented hybrid")
        results = []
        worker = threading.Thread(target=lambda: results.append(booth.qday()))
        worker.start()
        deadline = time.monotonic() + 2
        while booth._process is None and worker.is_alive() and time.monotonic() < deadline:
            time.sleep(0.001)
        self.assertIsNotNone(booth._process)
        child = booth._process
        with self.assertRaises(BoothError) as caught:
            booth.qday()
        self.assertEqual(caught.exception.code, "attack_running")
        booth.reset()
        worker.join(5)
        self.assertFalse(worker.is_alive())
        self.assertIsNotNone(child.poll())
        self.assertEqual(results[0]["demo_verdict"], "FAIL")
        self.assertIn("reset", [e["code"] for e in results[0]["errors"]])
        with self.assertRaises(BoothError):
            booth.qday()
        booth.send("new invented", "new hybrid")
        self.assertEqual(booth.qday()["demo_verdict"], "PASS")


class HttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        cls.base = f"http://127.0.0.1:{port}"
        env = os.environ.copy()
        env["HARVEST_BOOTH_BITS"] = "36"
        script = ("from fastapi import FastAPI; from backend.booth.api import router; "
                  "import uvicorn; app=FastAPI(); app.include_router(router); "
                  f"uvicorn.run(app,host='127.0.0.1',port={port},log_level='error')")
        cls.server = subprocess.Popen([sys.executable, "-c", script], env=env,
                                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            try:
                urllib.request.urlopen(cls.base + "/openapi.json", timeout=1).close()
                return
            except (OSError, urllib.error.URLError):
                if cls.server.poll() is not None:
                    raise RuntimeError("Test API server failed to start")
                time.sleep(0.05)
        cls.server.kill()
        cls.server.wait()
        raise RuntimeError("Test API server did not start")

    @classmethod
    def tearDownClass(cls):
        if cls.server.poll() is None:
            cls.server.terminate()
        cls.server.wait(timeout=5)

    def post(self, endpoint, raw):
        request = urllib.request.Request(self.base + "/api/v1/booth/" + endpoint,
                                         data=raw, headers={"Content-Type": "application/json"}, method="POST")
        try:
            response = urllib.request.urlopen(request, timeout=10)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            return response.status, json.loads(response.read())

    def test_actual_http_send_attack_and_invalid_requests(self):
        for raw in (b"{", b"[]", b"null", b'{"classical_message":"","hybrid_message":"x"}',
                    b'{"classical_message":7,"hybrid_message":"x"}', b'{"extra":"x"}',
                    b'{"classical_message":"x","hybrid_message":"y","bits":null}'):
            status, result = self.post("send", raw)
            self.assertEqual(status, 422)
            self.assertEqual(result["error"]["code"], "invalid_request")
        status, sent = self.post("send", json.dumps({"classical_message": "invented HTTP", "hybrid_message": "invented hybrid HTTP"}).encode())
        self.assertEqual(status, 200)
        self.assertTrue(sent["legit"]["hybrid"]["ok"])
        status, missing = self.post("qday", b'{"session":"unknown"}')
        self.assertEqual(status, 404)
        self.assertEqual(missing["error"]["code"], "no_session")
        status, attack = self.post("qday", json.dumps({"session": sent["session"]}).encode())
        self.assertEqual(status, 200)
        self.assertEqual(attack["verdict"]["demo_verdict"], "PASS")
        self.assertEqual(attack["verdict"]["hybrid_exception"], "InvalidTag")
        self.assertEqual(attack["events"][0]["transcript_sha256"], sent["transcript_sha256"])


if __name__ == "__main__":
    unittest.main()
