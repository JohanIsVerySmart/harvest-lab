"""Run ONE OpenSSL s_client probe and turn its output into a per-probe record.

Safety rules this file follows:
- argv is a list and the binary is an absolute path; never a shell string.
- A hard deadline: on timeout we kill the process group and reap it, and we
  trust our own `timed_out` flag, not the exit code.
- Captured output is capped (64 KB per stream), the trace file at 256 KB.
- We read handshake facts only from OpenSSL's own stderr lines and the private
  trace file. stdout carries server bytes, so we never parse it.
"""
import os
import re
import socket
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass

from backend.scan import procutil
from backend.scan.openssl_env import child_env

OUTPUT_CAP = 64 * 1024
TRACE_CAP = 256 * 1024

# name -> (offer label, extra args, write a trace?)
PROBES = {
    "default": ("default", [], True),
    "hybrid_only": ("X25519MLKEM768", ["-groups", "X25519MLKEM768"], False),
    "classical_only": ("X25519:secp256r1:secp384r1", ["-groups", "X25519:secp256r1:secp384r1"], False),
}

HYBRID_GROUPS = {"X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024"}
CLASSICAL_GROUPS = {
    "X25519", "X448", "secp256r1", "secp384r1", "secp521r1",
    "ffdhe2048", "ffdhe3072", "ffdhe4096", "ffdhe6144", "ffdhe8192",
    "brainpoolP256r1tls13", "brainpoolP384r1tls13", "brainpoolP512r1tls13",
}
_CURVE_ALIASES = {"prime256v1": "secp256r1"}
# IANA codepoints, so trace names like "ecdh_x25519" print as "X25519".
_CODEPOINT_NAMES = {
    23: "secp256r1", 24: "secp384r1", 25: "secp521r1", 29: "X25519", 30: "X448",
    4587: "SecP256r1MLKEM768", 4588: "X25519MLKEM768", 4589: "SecP384r1MLKEM1024",
}

# Lines that OpenSSL itself prints when something fails. Failure words are
# matched ONLY on these lines: a certificate subject can contain any word.
_DIAG_RE = re.compile(r"[0-9A-F]+:error:.*|verify error:.*|connect:errno=.*|(?:read|write):errno=.*|s_client:.*")
_ERRNO_RE = re.compile(r"connect:errno=(\d+)")
_ALERT_RE = re.compile(r"alert number (\d+)")
_REFUSED_ERRNOS = {61, 111, 10061}  # macOS, Linux, Windows


@dataclass
class RunResult:
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool
    output_capped: bool
    elapsed_ms: int


def _drain(stream, buf, cap, on_overflow):
    """Read a pipe to EOF, keeping at most `cap` bytes."""
    overflowed = False
    while True:
        chunk = stream.read1(4096)
        if not chunk:
            return
        room = cap - len(buf)
        if room > 0:
            buf.extend(chunk[:room])
        if len(chunk) > room and not overflowed:
            overflowed = True
            on_overflow()


def run_capped(argv, env, deadline_s, cap=OUTPUT_CAP):
    """Run argv with a deadline and capped output. Always reaps the child."""
    start = time.monotonic()
    proc = procutil.spawn(argv, env, subprocess.PIPE, subprocess.PIPE)
    capped = threading.Event()

    def overflow():
        capped.set()
        procutil.kill_group(proc)

    out, err = bytearray(), bytearray()
    readers = [
        threading.Thread(target=_drain, args=(proc.stdout, out, cap, overflow), daemon=True),
        threading.Thread(target=_drain, args=(proc.stderr, err, cap, overflow), daemon=True),
    ]
    for t in readers:
        t.start()

    timed_out = False
    try:
        proc.wait(timeout=deadline_s)
    except subprocess.TimeoutExpired:
        timed_out = not capped.is_set()
    procutil.kill_and_reap(proc)
    for t in readers:
        t.join(timeout=2)
    proc.stdout.close()
    proc.stderr.close()

    return RunResult(
        exit_code=proc.returncode,
        stdout=out.decode("utf-8", "replace"),
        stderr=err.decode("utf-8", "replace"),
        timed_out=timed_out,
        output_capped=capped.is_set(),
        elapsed_ms=round((time.monotonic() - start) * 1000),
    )


# --- Reading OpenSSL's -brief summary (stderr) ---

def _group_from_temp_key(value):
    """'X25519, 253 bits' -> X25519; 'ECDH, prime256v1, 256 bits' -> secp256r1."""
    parts = [p.strip() for p in value.split(",")]
    name = parts[1] if parts[0] in ("ECDH", "DH") and len(parts) > 2 else parts[0]
    return _CURVE_ALIASES.get(name, name)


def parse_brief(stderr):
    """Pull the brief-mode facts out of OpenSSL's stderr lines."""
    lines = [line.rstrip("\r") for line in stderr.split("\n")]
    fields = {}
    groups = []
    for line in lines:
        for label, key in (
            ("Protocol version: ", "tls"),
            ("Ciphersuite: ", "cipher"),
            ("Peer certificate: ", "peer_cert"),
            ("Signature type: ", "sig_type"),
            ("Verification: ", "verification"),
            ("Verified peername: ", "verified_peername"),
        ):
            if line.startswith(label) and key not in fields:
                fields[key] = line[len(label):]
        if line.startswith("Negotiated TLS1.3 group: "):
            groups.append(line[len("Negotiated TLS1.3 group: "):].strip())
        elif line.startswith("Peer Temp Key: "):
            groups.append(_group_from_temp_key(line[len("Peer Temp Key: "):]))
    return {
        "established": sum(1 for line in lines if line == "CONNECTION ESTABLISHED"),
        "groups": groups,
        "diag": [line for line in lines if _DIAG_RE.fullmatch(line)],
        **fields,
    }


def group_class(group):
    if group in HYBRID_GROUPS:
        return "hybrid"
    if group in CLASSICAL_GROUPS:
        return "classical"
    return None


# --- Reading key_share sizes from the private -trace file ---

# "    ClientHello, Length=1468" (a HelloRetryRequest prints as a ServerHello)
_HS_TYPE_RE = re.compile(r"    (\w+), Length=\d+")
_EXT_RE = re.compile(r"\s*extension_type=(\w+)\(\d+\).*")
# "NamedGroup: ecdh_x25519 (29)" or "NamedGroup: secp521r1 (P-521) (25)"
_GROUP_RE = re.compile(r"\s*NamedGroup: .* \((\d+)\)")
_KE_RE = re.compile(r"\s*key_exchange:\s+\(len=(\d+)\).*")


def parse_trace_key_share(text):
    """Key-share sizes from the LAST ClientHello and the last ServerHello
    that carries a key_exchange (a HelloRetryRequest carries none)."""
    client, server = None, None
    msg, shares, in_key_share, codepoint = None, [], False, None

    def finish():
        nonlocal client, server
        if msg == "ClientHello":
            client = shares
        elif msg == "ServerHello" and shares:
            server = shares[0]

    for line in text.splitlines():
        m = _HS_TYPE_RE.fullmatch(line)
        if m:
            finish()
            msg, shares, in_key_share, codepoint = m.group(1), [], False, None
            continue
        m = _EXT_RE.fullmatch(line)
        if m:
            in_key_share = m.group(1) == "key_share"
            continue
        if not in_key_share:
            continue
        m = _GROUP_RE.fullmatch(line)
        if m:
            codepoint = int(m.group(1))
            continue
        m = _KE_RE.fullmatch(line)
        if m and codepoint is not None:
            name = _CODEPOINT_NAMES.get(codepoint, f"0x{codepoint:04x}")
            shares.append({"group": name, "len": int(m.group(1))})
            codepoint = None
    finish()
    if client is None or server is None:
        return None
    return {"client": client, "server": server}


# --- Deciding the outcome ---

def _tcp_refused(ip, port):
    """Windows OpenSSL prints errno=0 for a refused connect; ask the OS directly."""
    try:
        socket.create_connection((ip, port), timeout=3).close()
    except ConnectionRefusedError:
        return True
    except OSError:
        return False
    return False


def classify(run, brief, ip, port, deadline_s):
    """Return (outcome, reason) following the contract's outcome list."""
    if run.timed_out:
        return "timeout", {"code": "timeout", "text": f"No answer within {deadline_s:g} s, so the probe was stopped."}
    if run.output_capped:
        return "output_cap", {"code": "output_cap", "text": "OpenSSL printed more than 64 KB, so the probe was stopped."}

    diag = brief["diag"]
    if (
        run.exit_code == 0
        and brief["established"] == 1
        and brief.get("verification") == "OK"
        and brief.get("verified_peername")
        and len(brief["groups"]) == 1
        and not diag
    ):
        return "ok", None

    text = "\n".join(diag).lower()
    errno = next((int(m.group(1)) for m in map(_ERRNO_RE.search, diag) if m), None)
    if "verify error:" in text or "certificate verify failed" in text:
        return "cert_fail", {"code": "cert_verify", "text": "The server's certificate did not verify for this host name."}
    if errno is not None:
        if "connection refused" in text or errno in _REFUSED_ERRNOS or (errno == 0 and _tcp_refused(ip, port)):
            return "net_refused", {"code": "connection_refused", "text": f"Nothing accepted a connection on port {port}."}
        return "net_other", {"code": "connect_failed", "text": f"Could not open a TCP connection to port {port} (errno {errno})."}
    alert = _ALERT_RE.search(text)
    if "alert handshake failure" in text or (alert and alert.group(1) == "40"):
        return "hs_refused", {"code": "handshake_failure", "text": "The server ended the handshake: no offered option was acceptable."}
    if "protocol version" in text or "unsupported protocol" in text or (alert and alert.group(1) == "70"):
        return "proto_refused", {"code": "protocol_version", "text": "The server did not accept TLS 1.3 from this client."}
    if alert or "alert" in text:
        number = alert.group(1) if alert else "unknown"
        return "other_alert", {"code": "tls_alert", "text": f"The server sent TLS alert {number} and ended the handshake."}
    if "unexpected eof" in text or "reset" in text or "errno=" in text:
        return "net_other", {"code": "connection_closed", "text": "The connection closed before the handshake finished."}
    if run.exit_code == 0 and not diag:
        return "parse_fail", {"code": "parse_fail", "text": "OpenSSL finished, but its summary did not show exactly one verified TLS 1.3 handshake."}
    return "local_error", {"code": "local_error", "text": f"OpenSSL stopped with exit code {run.exit_code} and no known reason."}


# --- One probe, end to end ---

def build_argv(openssl, ip, port, sni, ca_file, extra, trace_path=None):
    argv = [
        openssl, "s_client",
        "-connect", f"{ip}:{port}",
        "-servername", sni,
        "-verify_hostname", sni,
        "-verify_return_error",
        "-tls1_3",
        "-brief",
        "-CAfile", ca_file, "-no-CApath", "-no-CAstore",
        *extra,
    ]
    if trace_path:
        argv += ["-trace", "-msgfile", trace_path]
    return argv


def run_probe(name, openssl, ip, port, sni, ca_file, deadline_s):
    """Run the named probe and return its contract per-probe record."""
    offer, extra, want_trace = PROBES[name]
    trace_path = None
    if want_trace:
        fd, trace_path = tempfile.mkstemp(prefix="hl-", suffix=".trace")  # mode 0600
        os.close(fd)
    argv = build_argv(openssl, ip, port, sni, ca_file, extra, trace_path)
    try:
        run = run_capped(argv, child_env(openssl), deadline_s)
        trace_bytes, key_share = None, None
        if trace_path:
            trace_bytes = os.path.getsize(trace_path)
            if trace_bytes <= TRACE_CAP:  # over the cap: key_share stays null, not a failure
                with open(trace_path, encoding="utf-8", errors="replace") as f:
                    key_share = parse_trace_key_share(f.read())
    finally:
        if trace_path:
            try:
                os.unlink(trace_path)
            except OSError:
                pass

    brief = parse_brief(run.stderr)
    outcome, reason = classify(run, brief, ip, port, deadline_s)
    group = brief["groups"][0] if len(brief["groups"]) == 1 else None
    return {
        "offer": offer,
        "outcome": outcome,
        "reason": reason,
        "group": group,
        "group_class": group_class(group),
        "tls": brief.get("tls"),
        "cipher": brief.get("cipher"),
        "sig_type": brief.get("sig_type"),
        "peer_cert": brief.get("peer_cert"),
        "verified_peername": brief.get("verified_peername"),
        "key_share": key_share if outcome == "ok" else None,
        "elapsed_ms": run.elapsed_ms,
        "exit_code": run.exit_code,
        "trace_bytes": trace_bytes,
        "cmd": ["<tmp>" if arg == trace_path else arg for arg in argv],
        "raw": run.stderr,
    }
