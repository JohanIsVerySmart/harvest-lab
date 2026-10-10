"""Run the three probes in parallel against one pinned IP; one scan at a time.

scan_public(typed_text) is the ONLY path that takes user input, and it always
goes through hostcheck. scan_lab() takes no input at all: its target is
hardcoded to 127.0.0.1:8443 and it trusts only the lab CA.

Both return (scan, problem): `scan` holds the contract fields this side owns
(schema, target, scanned_at, elapsed_ms, cache_age_s, client_profile, probes)
and `problem` is None or a {code, text} reason (DNS failure). Johan's
assembler adds cert, verdict, pq_note, and footer.
"""
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor, wait
from datetime import datetime, timezone

from backend.scan import hostcheck
from backend.scan.openssl_env import LAB_CA_FILE, OpenSSLUnavailable, check_openssl
from backend.scan.runner import PROBES, run_probe

SCHEMA = "harvestlab.scan/1"
PUBLIC_PORT = 443
LAB_IP, LAB_PORT, LAB_SNI = "127.0.0.1", 8443, "localhost"

_scan_slot = threading.BoundedSemaphore(1)
_openssl_info = None


class ScanBusy(Exception):
    """Another scan held the single slot for too long."""


def probe_deadline_s():
    """HL_PROBE_DEADLINE_S, default 5, clamped to 4..8 (8 only for bad wifi)."""
    try:
        value = float(os.environ.get("HL_PROBE_DEADLINE_S", "5"))
    except ValueError:
        value = 5.0
    return min(8.0, max(4.0, value))


def openssl_info():
    """The checked OpenSSL (path, version, CA file); cached after first success."""
    global _openssl_info
    if _openssl_info is None:
        _openssl_info = check_openssl()
    return _openssl_info


def _now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _run_three(openssl, ip, port, sni, ca_file):
    deadline = probe_deadline_s()
    probes = {}
    with ThreadPoolExecutor(max_workers=3, thread_name_prefix="hl-probe") as pool:
        futures = {
            pool.submit(run_probe, name, openssl, ip, port, sni, ca_file, deadline): name
            for name in PROBES
        }
        # Each runner kills its own child at `deadline`; this is the backstop.
        wait(futures, timeout=deadline + 5)
        for future, name in futures.items():
            try:
                probes[name] = future.result(timeout=0)
            except Exception as exc:  # never let one probe crash the scan
                probes[name] = {
                    "offer": PROBES[name][0], "outcome": "local_error",
                    "reason": {"code": "local_error", "text": f"The probe could not run: {type(exc).__name__}."},
                    "group": None, "group_class": None, "tls": None, "cipher": None,
                    "sig_type": None, "peer_cert": None, "verified_peername": None,
                    "key_share": None, "elapsed_ms": None, "exit_code": None,
                    "trace_bytes": None, "cmd": [], "raw": "",
                }
    return {name: probes[name] for name in PROBES}  # stable order


def _with_slot(fn):
    if not _scan_slot.acquire(timeout=2 * (probe_deadline_s() + 5)):
        raise ScanBusy("Another scan is still running. Try again in a few seconds.")
    try:
        return fn()
    finally:
        _scan_slot.release()


def scan_public(typed):
    """Scan a public host the user typed. Raises ScanRejected for bad input."""
    host = hostcheck.validate_host(typed)  # before any DNS, outside the slot
    info = openssl_info()

    def go():
        start = time.monotonic()
        scanned_at = _now_iso()
        target = {
            "kind": "public", "input": typed, "host": host, "ip": None,
            "port": PUBLIC_PORT, "family": "ipv4", "addresses_seen": 0,
        }
        problem, probes = None, {}
        try:
            resolved = hostcheck.resolve_public_ipv4(host)
        except hostcheck.DnsFailure as exc:
            problem = {"code": "dns_failure", "text": str(exc)}
        else:
            target["ip"] = resolved.ip
            target["addresses_seen"] = len(resolved.addresses)
            probes = _run_three(info["path"], resolved.ip, PUBLIC_PORT, host, info["ca_file"])
        return _scan_dict(target, scanned_at, start, info, probes), problem

    return _with_slot(go)


def scan_lab():
    """Scan the fixed lab target. No user input reaches this function."""
    info = openssl_info()
    if not LAB_CA_FILE.is_file():
        raise OpenSSLUnavailable("Lab CA missing: run python -m lab.make_certs first.")

    def go():
        start = time.monotonic()
        scanned_at = _now_iso()
        target = {
            "kind": "lab", "input": "lab", "host": LAB_SNI, "ip": LAB_IP,
            "port": LAB_PORT, "family": "ipv4", "addresses_seen": 1,
        }
        probes = _run_three(info["path"], LAB_IP, LAB_PORT, LAB_SNI, str(LAB_CA_FILE))
        return _scan_dict(target, scanned_at, start, info, probes), None

    return _with_slot(go)


def _scan_dict(target, scanned_at, start, info, probes):
    return {
        "schema": SCHEMA,
        "target": target,
        "scanned_at": scanned_at,
        "elapsed_ms": round((time.monotonic() - start) * 1000),
        "cache_age_s": None,
        "client_profile": info["version"],
        "probes": probes,
    }
