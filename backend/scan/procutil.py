"""Start, kill, and reap child processes the same way on macOS and Windows.

Every child gets its own process group, so a timeout can kill it and anything
it started. We never kill by process name: only by a pid we started ourselves,
or by a pidfile pid whose command line we checked first.
"""
import os
import signal
import subprocess
import sys

WINDOWS = sys.platform == "win32"


def spawn(argv, env, stdout, stderr):
    """Start argv (a list, never a shell string) in its own process group."""
    kwargs = {
        "stdin": subprocess.DEVNULL,
        "stdout": stdout,
        "stderr": stderr,
        "env": env,
        "close_fds": True,
    }
    if WINDOWS:
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW
    else:
        kwargs["start_new_session"] = True  # child pid == its process group id
    return subprocess.Popen(argv, **kwargs)


def kill_group(proc):
    """Kill a child we started, plus its group. Safe if it already exited.

    The pid cannot be reused yet: until we reap it with wait(), the dead child
    still holds its pid, so this never hits a stranger.
    """
    if proc.poll() is not None:
        return
    try:
        if WINDOWS:
            proc.kill()
        else:
            os.killpg(proc.pid, signal.SIGKILL)
    except OSError:
        pass  # exited between poll() and kill


def kill_and_reap(proc, wait_s=2.0):
    """Kill (if still running) and wait, so no zombie is left behind."""
    kill_group(proc)
    try:
        proc.wait(timeout=wait_s)
    except subprocess.TimeoutExpired:
        pass
    return proc.returncode


# --- Helpers for a pid we did NOT start in this process (stale pidfile). ---

def _quiet(argv, timeout=5):
    try:
        return subprocess.run(
            argv, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=timeout
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def pid_alive(pid):
    if WINDOWS:
        out = _quiet(["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"])
        return f'"{pid}"' in out
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def pid_cmdline(pid):
    """The full command line of pid, or "" if unknown."""
    if WINDOWS:
        ps = f"(Get-CimInstance Win32_Process -Filter 'ProcessId={int(pid)}').CommandLine"
        return _quiet(["powershell", "-NoProfile", "-Command", ps], timeout=10).strip()
    return _quiet(["/bin/ps", "-o", "command=", "-p", str(int(pid))]).strip()


def kill_pid(pid):
    """Kill a pid whose command line the caller already checked."""
    if WINDOWS:
        _quiet(["taskkill", "/PID", str(int(pid)), "/T", "/F"])
        return
    try:
        if os.getpgid(pid) == pid:  # it leads its own group (we started it that way)
            os.killpg(pid, signal.SIGKILL)
        else:
            os.kill(pid, signal.SIGKILL)
    except OSError:
        pass


def listening_pid(port):
    """Best effort: which pid listens on 127.0.0.1:port? None if unknown."""
    if WINDOWS:
        for line in _quiet(["netstat", "-ano", "-p", "TCP"]).splitlines():
            parts = line.split()
            if (
                len(parts) == 5
                and parts[3] == "LISTENING"
                and parts[1].endswith(f":{port}")
                and parts[4].isdigit()
            ):
                return int(parts[4])
        return None
    out = _quiet(["/usr/sbin/lsof", "-nP", f"-iTCP:{port}", "-sTCP:LISTEN", "-t"]).split()
    return int(out[0]) if out and out[0].isdigit() else None
