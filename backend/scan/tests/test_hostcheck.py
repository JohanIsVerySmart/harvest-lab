"""Host validator table test + resolve-then-block tests (fake DNS, no network).

    python -m unittest backend.scan.tests.test_hostcheck -v
"""
import os
import socket
import time
import unittest

from backend.scan.hostcheck import (
    DnsFailure, ScanRejected, is_public, resolve_public_ipv4, validate_host,
)

ACCEPT = {
    "google.com": "google.com",
    "  Google.COM.  ": "google.com",
    "ensign.edu": "ensign.edu",
    "www.cloudflare.com": "www.cloudflare.com",
    "sub.domain.co.uk": "sub.domain.co.uk",
    "a-b.example.org": "a-b.example.org",
    "bücher.de": "xn--bcher-kva.de",
    "google.com\n": "google.com",  # trimmed, like spaces
}

REJECT = [
    None, 123, "", "   ", ".",
    "https://google.com", "google.com/path", "google.com:443", "user@google.com",
    "goo gle.com", "google.com?x=1", "google.com#top", "google.com\\x", "goo\ngle.com", "google.com\tx",
    "-oProxyCommand=x.com", "a..com", "-a.com", "a-.com", "under_score.com", "com",
    "a" * 64 + ".com", ("abc." * 64) + "com", "x" * 2000,
    # numeric IP forms
    "127.0.0.1", "127.1", "0x7f.1", "0x7f000001", "2130706433", "10.0.0.1", "::1", "[::1]",
    # local and reserved suffixes
    "localhost", "LOCALHOST.", "foo.localhost", "printer.local", "db.internal", "nas.lan",
    "x.home.arpa", "1.0.0.127.in-addr.arpa", "a.test", "a.invalid", "a.example", "example",
]


class ValidateHostTable(unittest.TestCase):
    def test_accepts(self):
        for raw, expected in ACCEPT.items():
            with self.subTest(raw=raw):
                self.assertEqual(validate_host(raw), expected)

    def test_rejects(self):
        for raw in REJECT:
            with self.subTest(raw=raw):
                with self.assertRaises(ScanRejected) as ctx:
                    validate_host(raw)
                self.assertEqual(ctx.exception.code, "invalid_host")
                self.assertTrue(ctx.exception.message)


class IsPublicTable(unittest.TestCase):
    def test_table(self):
        table = {
            "8.8.8.8": True, "1.1.1.1": True, "142.250.72.14": True, "2606:4700::1111": True,
            "127.0.0.1": False, "10.0.0.1": False, "172.16.0.1": False, "192.168.1.1": False,
            "100.64.0.1": False, "198.18.0.1": False, "198.19.255.255": False,
            "169.254.1.1": False, "224.0.0.1": False, "0.0.0.0": False, "240.0.0.1": False,
            "255.255.255.255": False, "::1": False, "::": False, "fe80::1": False,
            "fe80::1%12": False, "fc00::1": False, "ff02::1": False, "::ffff:127.0.0.1": False,
            "::ffff:8.8.8.8": True,
        }
        for address, public in table.items():
            with self.subTest(address=address):
                self.assertEqual(is_public(address), public)


def fake(addresses):
    return lambda host: list(addresses)


class ResolveThenBlock(unittest.TestCase):
    def test_localtest_me_style_name_is_blocked(self):
        # localtest.me is real public DNS that answers 127.0.0.1
        with self.assertRaises(ScanRejected) as ctx:
            resolve_public_ipv4("localtest.me", lookup=fake(["127.0.0.1"]))
        self.assertEqual(ctx.exception.code, "blocked_address")

    def test_any_private_answer_blocks_even_with_public_ones(self):
        with self.assertRaises(ScanRejected) as ctx:
            resolve_public_ipv4("mixed.com", lookup=fake(["8.8.8.8", "10.0.0.1"]))
        self.assertEqual(ctx.exception.code, "blocked_address")

    def test_private_ipv6_answer_blocks(self):
        with self.assertRaises(ScanRejected) as ctx:
            resolve_public_ipv4("v6.com", lookup=fake(["8.8.8.8", "::1"]))
        self.assertEqual(ctx.exception.code, "blocked_address")

    def test_ipv6_only(self):
        with self.assertRaises(ScanRejected) as ctx:
            resolve_public_ipv4("v6only.com", lookup=fake(["2606:4700::1111"]))
        self.assertEqual(ctx.exception.code, "ipv6_only_unsupported")

    def test_pins_first_public_ipv4(self):
        r = resolve_public_ipv4("ok.com", lookup=fake(["2606:4700::1111", "1.1.1.1", "8.8.8.8"]))
        self.assertEqual(r.ip, "1.1.1.1")
        self.assertEqual(len(r.addresses), 3)

    def test_dns_error_is_dns_failure_not_crash(self):
        def boom(host):
            raise socket.gaierror(11001, "not found")
        with self.assertRaises(DnsFailure):
            resolve_public_ipv4("nope.com", lookup=boom)

    def test_dns_timeout(self):
        def slow(host):
            time.sleep(1.0)
            return ["8.8.8.8"]
        start = time.monotonic()
        with self.assertRaises(DnsFailure):
            resolve_public_ipv4("slow.com", lookup=slow, timeout_s=0.2)
        self.assertLess(time.monotonic() - start, 0.9)

    @unittest.skipUnless(os.environ.get("HL_LIVE") == "1", "set HL_LIVE=1 for real DNS")
    def test_live_localtest_me(self):
        with self.assertRaises(ScanRejected) as ctx:
            resolve_public_ipv4("localtest.me")
        self.assertEqual(ctx.exception.code, "blocked_address")


if __name__ == "__main__":
    unittest.main()
