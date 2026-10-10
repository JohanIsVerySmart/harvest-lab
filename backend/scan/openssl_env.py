"""Find the OpenSSL binary and CA bundle, and refuse to run on a bad OpenSSL.

macOS /usr/bin/openssl is LibreSSL and silently reports X25519 against hybrid
servers, so we only ever use an absolute path to OpenSSL 3.5 or newer.

Run `python -m backend.scan.openssl_env` to print what was found.
"""
import os
import re
import subprocess
import sys
from pathlib import Path

MIN_VERSION = (3, 5)
REPO_ROOT = Path(__file__).resolve().parents[2]
LAB_CA_FILE = REPO_ROOT / "lab" / "certs" / "ca.pem"

if sys.platform == "win32":
    # Dev laptops only. The demo runs on the Mac.
    DEFAULT_OPENSSL = r"C:\Program Files\Git\mingw64\bin\openssl.exe"
    DEFAULT_CA_FILE = r"C:\Program Files\Git\mingw64\etc\ssl\certs\ca-bundle.crt"
else:
    DEFAULT_OPENSSL = "/opt/homebrew/opt/openssl@3/bin/openssl"
    DEFAULT_CA_FILE = "/opt/homebrew/etc/openssl@3/cert.pem"

# "OpenSSL 3.5.5 27 Jan 2026 (Library: ...)". LibreSSL never matches.
_VERSION_RE = re.compile(r"OpenSSL (\d+)\.(\d+)\.(\d+)(?: .*)?")
_TRACE_RE = re.compile(r"^\s*-trace\s", re.MULTILINE)


class OpenSSLUnavailable(RuntimeError):
    """The OpenSSL binary or CA file is missing or not good enough."""


def child_env(openssl_path):
    """The only environment variables an OpenSSL child process gets."""
    if sys.platform == "win32":
        # Without SYSTEMROOT, OpenSSL on Windows cannot get entropy and every
        # handshake fails with "entropy source strength too weak".
        return {
            "OPENSSL_CONF": os.devnull,
            "PATH": str(Path(openssl_path).parent),
            "SYSTEMROOT": os.environ.get("SYSTEMROOT", r"C:\Windows"),
        }
    return {"OPENSSL_CONF": os.devnull, "PATH": "/usr/bin:/bin"}


def _run(openssl_path, args):
    result = subprocess.run(
        [openssl_path, *args],
        env=child_env(openssl_path),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=5,
    )
    return result.stdout + result.stderr


def _absolute_file(env_name, default, what):
    path = os.environ.get(env_name, default)
    if not os.path.isabs(path):
        raise OpenSSLUnavailable(f"{what} must be an absolute path, got {path!r} ({env_name})")
    if not os.path.isfile(path):
        raise OpenSSLUnavailable(f"{what} not found at {path} ({env_name})")
    return path


def check_openssl():
    """Return {path, version, trace_supported, ca_file} or raise OpenSSLUnavailable."""
    path = _absolute_file("HL_OPENSSL", DEFAULT_OPENSSL, "OpenSSL binary")
    try:
        first_line = _run(path, ["version"]).strip().splitlines()[0]
    except (OSError, subprocess.SubprocessError, IndexError) as exc:
        raise OpenSSLUnavailable(f"could not run {path} version: {exc}") from exc

    match = _VERSION_RE.fullmatch(first_line)
    if not match:
        raise OpenSSLUnavailable(f"not OpenSSL (LibreSSL?): {first_line!r}")
    if tuple(int(n) for n in match.group(1, 2)) < MIN_VERSION:
        raise OpenSSLUnavailable(f"OpenSSL 3.5 or newer required, found: {first_line!r}")

    trace_supported = bool(_TRACE_RE.search(_run(path, ["s_client", "-help"])))
    ca_file = _absolute_file("HL_CA_FILE", DEFAULT_CA_FILE, "Public CA bundle")
    return {
        "path": path,
        "version": first_line,
        "trace_supported": trace_supported,
        "ca_file": ca_file,
    }


if __name__ == "__main__":
    try:
        info = check_openssl()
    except OpenSSLUnavailable as exc:
        print(f"REFUSING TO START: {exc}")
        sys.exit(1)
    for key, value in info.items():
        print(f"{key}: {value}")
    print(f"lab_ca_file: {LAB_CA_FILE} (exists: {LAB_CA_FILE.is_file()})")
