"""Lab fixtures: the team's pass tests run against LOCAL servers only.

    python -m unittest lab.tests.test_lab -v

Needs lab certs (python -m lab.make_certs) and free ports 8443 and 8444.
"""
import json
import os
import socket
import subprocess
import time
import unittest

from backend.scan import interim, procutil, probes
from backend.scan.openssl_env import LAB_CA_FILE, check_openssl, child_env
from lab import labctl
from lab.labctl import CERT_DIR, LAB, LabError, accepts


def lab_verdict():
    scan, problem = probes.scan_lab()
    return interim.assemble(scan, problem)


class LabModes(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        LAB.startup()

    @classmethod
    def tearDownClass(cls):
        LAB.set_mode("stop")

    def test_classical_red_hybrid_green_then_regression_caught(self):
        LAB.set_mode("classical")
        scan = lab_verdict()
        self.assertEqual(scan["target"]["kind"], "lab")
        self.assertEqual(scan["probes"]["default"]["group"], "X25519")
        self.assertEqual(scan["verdict"]["label"], "classical_observed")

        LAB.set_mode("hybrid")
        scan = lab_verdict()
        self.assertEqual(scan["probes"]["default"]["group"], "X25519MLKEM768")
        self.assertEqual(scan["probes"]["default"]["key_share"]["server"]["len"], 1120)
        self.assertEqual(scan["verdict"]["label"], "hybrid_observed")

        LAB.set_mode("classical")
        self.assertEqual(lab_verdict()["verdict"]["label"], "classical_observed")

    def test_yellow_is_supported_not_chosen(self):
        LAB.set_mode("yellow")
        scan = lab_verdict()
        self.assertEqual(scan["probes"]["default"]["group"], "X25519")
        self.assertEqual(scan["probes"]["default"]["key_share"]["client"][0]["len"], 1216)
        self.assertEqual(scan["probes"]["hybrid_only"]["group"], "X25519MLKEM768")
        self.assertEqual(scan["verdict"]["label"], "hybrid_supported_not_chosen")

    def test_stopped_is_inconclusive_connection_refused(self):
        LAB.set_mode("stop")
        self.assertEqual(LAB.status()["mode"], "stop")
        scan = lab_verdict()
        self.assertEqual(scan["verdict"]["label"], "inconclusive")
        self.assertEqual(scan["verdict"]["reason"]["code"], "connection_refused")

    def test_dead_server_shows_down_and_restarts(self):
        LAB.set_mode("classical")
        procutil.kill_and_reap(LAB._proc)  # simulate a crash
        self.assertEqual(LAB.status(), {"mode": "down", "alive": False, "pid": None, "switch_ms": None})
        self.assertTrue(LAB.set_mode("hybrid")["alive"])

    def test_switch_in_progress_is_refused_and_status_still_answers(self):
        LAB.set_mode("classical")
        LAB._lock.acquire()
        try:
            with self.assertRaises(LabError) as ctx:
                LAB.set_mode("hybrid")
            self.assertEqual(ctx.exception.code, "lab_switching")
            self.assertEqual(LAB.status()["mode"], "classical")  # lock-free read
        finally:
            LAB._lock.release()

    def test_foreign_program_on_8443_is_never_killed(self):
        LAB.set_mode("stop")
        foreign = socket.socket()
        foreign.bind(("127.0.0.1", 8443))
        foreign.listen()
        try:
            start = time.monotonic()
            with self.assertRaises(LabError) as ctx:
                LAB.set_mode("classical")
            self.assertIn("in use", ctx.exception.message)
            self.assertLess(time.monotonic() - start, labctl.PORT_FREE_TIMEOUT_S + 3)
            self.assertTrue(accepts())  # the foreign listener is still alive
        finally:
            foreign.close()
        self.assertTrue(LAB.set_mode("classical")["alive"])

    def test_stale_pidfile_is_not_trusted(self):
        LAB.set_mode("stop")
        # A pidfile pointing at THIS test process: its command line is not our
        # s_server, so it must not be killed, and start must still work.
        labctl.STATE_DIR.mkdir(parents=True, exist_ok=True)
        labctl.PIDFILE.write_text(json.dumps({"pid": os.getpid(), "mode": "classical"}))
        status = LAB.set_mode("classical")
        self.assertTrue(status["alive"])
        self.assertNotEqual(status["pid"], os.getpid())

    def test_ten_rapid_switches(self):
        times = []
        for i in range(10):
            status = LAB.set_mode("hybrid" if i % 2 else "classical")
            self.assertTrue(status["alive"])
            times.append(status["switch_ms"])
        print(f"\n    switch_ms over 10 switches: {times}")

    def test_expiring_leaf_is_refused(self):
        saved = labctl.MIN_LEAF_LIFE
        labctl.MIN_LEAF_LIFE = labctl.datetime.timedelta(days=365)
        try:
            with self.assertRaises(LabError):
                labctl.check_leaf_cert()
        finally:
            labctl.MIN_LEAF_LIFE = saved


class WrongCertificate(unittest.TestCase):
    """A server whose cert is not from the lab CA must scan as cert_fail."""

    def test_wrong_cert_is_cert_fail_inconclusive(self):
        openssl = check_openssl()["path"]
        argv = labctl.server_argv(openssl, "hybrid", CERT_DIR / "wrong.pem", CERT_DIR / "wrong.key", port=8444)
        server = procutil.spawn(argv, child_env(openssl), subprocess.DEVNULL, subprocess.DEVNULL)
        try:
            deadline = time.monotonic() + 5
            while not accepts(8444):
                self.assertLess(time.monotonic(), deadline, "test server did not start")
                time.sleep(0.01)
            probe_set = probes._run_three(openssl, "127.0.0.1", 8444, "localhost", str(LAB_CA_FILE))
        finally:
            procutil.kill_and_reap(server)
        self.assertEqual(probe_set["default"]["outcome"], "cert_fail")
        scan = interim.assemble({"probes": probe_set, "client_profile": "test"})
        self.assertEqual(scan["verdict"]["label"], "inconclusive")
        self.assertEqual(scan["verdict"]["reason"]["code"], "cert_verify")


if __name__ == "__main__":
    unittest.main()
