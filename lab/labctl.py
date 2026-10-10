"""Run the lab TLS server (OpenSSL s_server on 127.0.0.1:8443) in a chosen mode.

Modes (a fixed enum; each maps to a FIXED argument list, never free text):
  classical  server groups X25519                 -> scan shows classical_observed
  hybrid     server groups X25519MLKEM768:X25519  -> scan shows hybrid_observed
  stop       no server                            -> scan shows inconclusive (refused)

Switch sequence (one lock, around the switch only):
  stop the old server (our own handle, or a pidfile pid whose command line is
  ours) -> wait until 8443 is free -> start the new one -> wait until it
  accepts a TCP connection -> record the real switch time.

We never kill by process name. If a program we did not start holds 8443, we
refuse with its pid and leave it alone.

CLI:  python -m lab.labctl classical|hybrid|stop|status
"""
import atexit
import datetime
import json
import os
import socket
import sys
import tempfile
import threading
import time
from pathlib import Path

from cryptography import x509

from backend.scan import procutil
from backend.scan.openssl_env import check_openssl, child_env

LAB_HOST, LAB_PORT = "127.0.0.1", 8443
MODES = ("classical", "hybrid", "yellow", "stop")
# yellow: the server supports hybrid but prefers X25519 (-serverpref), so a
# default client gets X25519 while a hybrid-only client still succeeds.
# The API exposes yellow only once Johan adds it to the contract enum.
SERVER_GROUPS = {"classical": "X25519", "hybrid": "X25519MLKEM768:X25519", "yellow": "X25519:X25519MLKEM768"}

CERT_DIR = Path(__file__).resolve().parent / "certs"
LEAF_PEM, LEAF_KEY = CERT_DIR / "leaf.pem", CERT_DIR / "leaf.key"
STATE_DIR = Path(os.environ.get("HL_LAB_STATE_DIR", Path(tempfile.gettempdir()) / "harvestlab-lab"))
PIDFILE = STATE_DIR / "s_server.pid.json"
LOGFILE = STATE_DIR / "s_server.log"  # server stderr noise goes here, never to the UI

PORT_FREE_TIMEOUT_S = 3.0
READY_TIMEOUT_S = 5.0
MIN_LEAF_LIFE = datetime.timedelta(hours=12)


class LabError(Exception):
    """code is "lab_switching" (409 in the contract) or "internal" (500)."""

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code
        self.message = message


def server_argv(openssl, mode, cert=LEAF_PEM, key=LEAF_KEY, port=LAB_PORT):
    # Never add -tls1_2 next to -tls1_3: that combination kills s_server at startup.
    argv = [
        openssl, "s_server",
        "-accept", f"{LAB_HOST}:{port}",
        "-tls1_3",
        "-quiet",  # with stdin from DEVNULL, keeps serving after each client
        "-cert", str(cert), "-key", str(key),
        "-groups", SERVER_GROUPS[mode],
    ]
    if mode == "yellow":
        argv.append("-serverpref")
    return argv


def check_leaf_cert():
    """Fail clearly if the lab certs are missing or the leaf expires within 12 h."""
    if not LEAF_PEM.is_file() or not LEAF_KEY.is_file():
        raise LabError("internal", "Lab certificates are missing. Run: python -m lab.make_certs")
    cert = x509.load_pem_x509_certificate(LEAF_PEM.read_bytes())
    left = cert.not_valid_after_utc - datetime.datetime.now(datetime.timezone.utc)
    if left < MIN_LEAF_LIFE:
        raise LabError("internal", "The lab certificate expires within 12 hours. Run: python -m lab.make_certs --force")


def port_free(port=LAB_PORT):
    """True if nothing is listening on 127.0.0.1:port (we can bind it)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        if not procutil.WINDOWS:
            # Ignore leftover TIME_WAIT sockets; a live listener still blocks the bind.
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((LAB_HOST, port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def accepts(port=LAB_PORT):
    """True if a TCP connect to 127.0.0.1:port succeeds (zsh has no /dev/tcp)."""
    try:
        # Loopback answers in well under 1 ms. A short timeout matters on
        # Windows, where a connect to a closed port waits instead of failing.
        socket.create_connection((LAB_HOST, port), timeout=0.05).close()
        return True
    except OSError:
        return False


def _is_our_server(cmdline):
    return "s_server" in cmdline and f"{LAB_HOST}:{LAB_PORT}" in cmdline


def _log_tail(n=400):
    try:
        return LOGFILE.read_bytes()[-n:].decode("utf-8", "replace").strip()
    except OSError:
        return ""


class Lab:
    def __init__(self):
        self._lock = threading.Lock()
        self._proc = None
        self._mode = "stop"
        self._switch_ms = None
        atexit.register(self.shutdown)

    # --- read side: never takes the switch lock ---

    def status(self):
        proc, mode, switch_ms = self._proc, self._mode, self._switch_ms
        if mode == "stop":
            return {"mode": "stop", "alive": False, "pid": None, "switch_ms": switch_ms}
        if proc is None or proc.poll() is not None:
            return {"mode": "down", "alive": False, "pid": None, "switch_ms": None}
        return {"mode": mode, "alive": True, "pid": proc.pid, "switch_ms": switch_ms}

    # --- write side ---

    def set_mode(self, mode):
        if mode not in MODES:
            raise LabError("internal", f"Unknown lab mode {mode!r}.")
        if not self._lock.acquire(blocking=False):
            raise LabError("lab_switching", "A lab mode switch is already in progress.")
        try:
            start = time.monotonic()
            self._stop_current()
            self._mode = mode
            if mode != "stop":
                self._start(mode)
            self._switch_ms = round((time.monotonic() - start) * 1000)
            return self.status()
        finally:
            self._lock.release()

    def startup(self):
        """At backend start: clean up a server left by a crashed backend."""
        with self._lock:
            self._stop_stale()

    def shutdown(self):
        proc, self._proc = self._proc, None
        if proc is not None:
            procutil.kill_and_reap(proc)
        if proc is not None or PIDFILE.exists():
            self._remove_pidfile()

    # --- internals (called with the lock held) ---

    def _stop_current(self):
        proc, self._proc = self._proc, None
        if proc is not None:
            procutil.kill_and_reap(proc)
            self._remove_pidfile()
        else:
            self._stop_stale()
        deadline = time.monotonic() + PORT_FREE_TIMEOUT_S
        while not port_free():
            if time.monotonic() > deadline:
                holder = procutil.listening_pid(LAB_PORT)
                who = f"foreign pid {holder}" if holder else "a foreign program"
                self._mode = "stop"
                raise LabError("internal", f"Port {LAB_PORT} is in use by {who}. It was not stopped; close it and pick a mode again.")
            time.sleep(0.02)

    def _stop_stale(self):
        """Kill the pidfile's process ONLY if its command line is our s_server."""
        try:
            pid = int(json.loads(PIDFILE.read_text())["pid"])
        except (OSError, ValueError, KeyError, TypeError):
            self._remove_pidfile()
            return
        if procutil.pid_alive(pid) and _is_our_server(procutil.pid_cmdline(pid)):
            procutil.kill_pid(pid)
            deadline = time.monotonic() + 2
            while procutil.pid_alive(pid) and time.monotonic() < deadline:
                time.sleep(0.05)
        self._remove_pidfile()

    def _start(self, mode):
        check_leaf_cert()
        openssl = check_openssl()["path"]
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        argv = server_argv(openssl, mode)
        with open(LOGFILE, "ab") as log:
            log.write(f"\n--- {datetime.datetime.now():%H:%M:%S} start {mode}\n".encode())
            log.flush()
            proc = procutil.spawn(argv, child_env(openssl), log, log)
        self._proc = proc
        PIDFILE.write_text(json.dumps({"pid": proc.pid, "mode": mode, "argv": argv}))

        deadline = time.monotonic() + READY_TIMEOUT_S
        while not accepts():
            if proc.poll() is not None:
                self._proc = None
                self._remove_pidfile()
                raise LabError("internal", f"The lab server exited at startup: {_log_tail() or 'no output'}")
            if time.monotonic() > deadline:
                self._proc = None
                procutil.kill_and_reap(proc)
                self._remove_pidfile()
                raise LabError("internal", f"The lab server did not accept connections within {READY_TIMEOUT_S:g} s.")
            time.sleep(0.01)

    @staticmethod
    def _remove_pidfile():
        try:
            PIDFILE.unlink()
        except FileNotFoundError:
            pass


LAB = Lab()


def reset():
    """For Johan's /api/v1/reset: lab back to classical."""
    return LAB.set_mode("classical")


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in (*MODES, "status"):
        sys.exit("usage: python -m lab.labctl classical|hybrid|stop|status")
    LAB.startup()
    if sys.argv[1] == "status":
        print(json.dumps(LAB.status()))
        sys.exit(0)
    try:
        print(json.dumps(LAB.set_mode(sys.argv[1])))
    except LabError as exc:
        sys.exit(f"ERROR: {exc.message}")
    if sys.argv[1] != "stop":
        # The server belongs to this process; keep it alive until Ctrl+C.
        print("Lab server running. Press Ctrl+C to stop it.")
        try:
            while LAB.status()["alive"]:
                time.sleep(0.5)
            print("Lab server died:", _log_tail())
        except KeyboardInterrupt:
            pass
