"""Validate a typed host name, resolve it once, and refuse anything non-public.

Order matters: validate the text BEFORE any DNS, then resolve once, then
block if ANY answer is non-public ("resolve then block"). That is what stops
names like localtest.me, which is real public DNS pointing at 127.0.0.1.
The port is always 443 and is never chosen by the user.
"""
import ipaddress
import re
import socket
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from dataclasses import dataclass

DNS_TIMEOUT_S = 2.0
MAX_INPUT_CHARS = 1000

BLOCKED_SUFFIXES = (
    "localhost", "local", "internal", "lan", "home.arpa", "arpa",
    "test", "invalid", "example",
)
_FORBIDDEN_CHARS = set("/:@?#\\")
_ASCII_HOST_RE = re.compile(r"[a-z0-9.-]+")
_EXTRA_BLOCKED_NETS = (
    ipaddress.ip_network("100.64.0.0/10"),  # carrier-grade NAT
    ipaddress.ip_network("198.18.0.0/15"),  # benchmarking
)

# getaddrinfo has no timeout of its own, so it runs on a worker thread.
_dns_pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="hl-dns")


class ScanRejected(Exception):
    """A contract error: code is one of the contract error codes."""

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code
        self.message = message


class DnsFailure(Exception):
    """Not an error for the API: it becomes a 200 Inconclusive."""


@dataclass
class Resolved:
    host: str
    ip: str
    addresses: list


def _invalid(message):
    return ScanRejected("invalid_host", message)


def validate_host(raw):
    """Return the normalized ASCII host name or raise ScanRejected(invalid_host)."""
    if not isinstance(raw, str):
        raise _invalid("Type a host name, like example.com.")
    if len(raw) > MAX_INPUT_CHARS:
        raise _invalid("That is far too long to be a host name.")
    host = raw.strip().lower()
    if host.endswith("."):
        host = host[:-1]
    if not host:
        raise _invalid("Type a host name, like example.com.")
    if any(ch in _FORBIDDEN_CHARS or ch.isspace() for ch in host):
        raise _invalid("Type only a host name, like example.com: no https://, path, port, or spaces.")
    if host.startswith("-"):
        raise _invalid("A host name cannot start with '-'.")
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        raise _invalid("That is not a valid host name.") from None
    if len(host) > 253:
        raise _invalid("A host name can be at most 253 characters.")
    if not _ASCII_HOST_RE.fullmatch(host):
        raise _invalid("A host name may only use letters, digits, dots, and hyphens.")

    labels = host.split(".")
    if len(labels) < 2:
        raise _invalid("Type a full host name with a dot, like example.com.")
    for label in labels:
        if not label or len(label) > 63 or label.startswith("-") or label.endswith("-"):
            raise _invalid("That is not a valid host name.")
    # Numeric IP forms (127.0.0.1, 127.1, 0x7f.0.0.1): a real top-level
    # domain is never all digits or 0x-hex, so such a last label means an IP.
    last = labels[-1]
    if last.isdigit() or re.fullmatch(r"0x[0-9a-f]*", last):
        raise _invalid("Type a host name, not an IP address.")
    for suffix in BLOCKED_SUFFIXES:
        if host == suffix or host.endswith("." + suffix):
            raise _invalid(f"Names ending in .{suffix} are local or reserved, so they are not scanned.")
    return host


def is_public(address):
    """True only for globally routable unicast addresses."""
    ip = ipaddress.ip_address(address.split("%", 1)[0])
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped
    if (
        not ip.is_global
        or ip.is_private
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_unspecified
    ):
        return False
    return not any(ip in net for net in _EXTRA_BLOCKED_NETS if net.version == ip.version)


def _lookup(host):
    infos = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
    addresses = []
    for family, _, _, _, sockaddr in infos:
        if family in (socket.AF_INET, socket.AF_INET6) and sockaddr[0] not in addresses:
            addresses.append(sockaddr[0])
    return addresses


def resolve_public_ipv4(host, lookup=_lookup, timeout_s=DNS_TIMEOUT_S):
    """Resolve once; block if ANY answer is non-public; pin the first public IPv4."""
    try:
        addresses = _dns_pool.submit(lookup, host).result(timeout=timeout_s)
    except FutureTimeout:
        raise DnsFailure(f"DNS for {host} did not answer within {timeout_s:g} s.") from None
    except (socket.gaierror, UnicodeError, OSError):
        raise DnsFailure(f"DNS could not find {host}.") from None
    if not addresses:
        raise DnsFailure(f"DNS returned no addresses for {host}.")

    for address in addresses:
        if not is_public(address):
            raise ScanRejected(
                "blocked_address",
                f"{host} points to a private or local address, so it is not scanned.",
            )
    ipv4 = [a for a in addresses if ipaddress.ip_address(a.split("%", 1)[0]).version == 4]
    if not ipv4:
        raise ScanRejected(
            "ipv6_only_unsupported",
            f"{host} has only IPv6 addresses; this scanner uses IPv4 only.",
        )
    return Resolved(host=host, ip=ipv4[0], addresses=addresses)
