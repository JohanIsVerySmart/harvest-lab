"""Create the lab CA and lab server certificate in the git-ignored lab/certs/.

    python -m lab.make_certs            # refuses to overwrite existing certs
    python -m lab.make_certs --force    # make fresh ones

Files (never committed):
  ca.pem               lab CA certificate (the ONLY trust source of a lab scan)
  ca.key               lab CA private key
  leaf.pem, leaf.key   lab server cert for localhost, 127.0.0.1, ::1
  wrong.pem, wrong.key a self-signed localhost cert NOT from the lab CA, used
                       only by the test that proves a bad cert is caught

Before writing anything this checks with git that lab/certs/ is ignored, and
afterwards it checks `git status` shows nothing new under lab/certs/.
"""
import argparse
import datetime
import ipaddress
import os
import subprocess
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

REPO_ROOT = Path(__file__).resolve().parents[1]
CERT_DIR = REPO_ROOT / "lab" / "certs"
LEAF_DAYS = 5  # must stay valid through the Saturday 1:00-2:30 PM demos
CA_DAYS = 7


def _git(*args):
    return subprocess.run(
        ["git", *args], cwd=REPO_ROOT, capture_output=True, text=True, stdin=subprocess.DEVNULL
    )


def _assert_ignored():
    probe = "lab/certs/leaf.key"
    if _git("check-ignore", "-q", probe).returncode != 0:
        sys.exit(f"REFUSING: git does not ignore {probe}. Fix .gitignore first (lab/certs/).")


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _write(path, data, private=False):
    # Keys get mode 0600 on macOS (Windows ignores the mode).
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600 if private else 0o644)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def _key_pem(key):
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def _cert_pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM)


def _server_cert(subject_key, issuer_name, issuer_key, issuer_ski, now, days, cn):
    san = x509.SubjectAlternativeName([
        x509.DNSName("localhost"),
        x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
        x509.IPAddress(ipaddress.ip_address("::1")),
    ])
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(cn))
        .issuer_name(issuer_name)
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(hours=1))
        .not_valid_after(now + datetime.timedelta(days=days))
        .add_extension(san, critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(subject_key.public_key()), critical=False)
    )
    if issuer_ski is not None:
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(issuer_ski), critical=False
        )
    return builder.sign(issuer_key, hashes.SHA256())


def make_certs(force=False):
    _assert_ignored()
    CERT_DIR.mkdir(parents=True, exist_ok=True)
    if (CERT_DIR / "leaf.pem").exists() and not force:
        sys.exit("lab/certs/leaf.pem already exists. Use --force to replace the lab certs.")

    now = datetime.datetime.now(datetime.timezone.utc)

    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = _name("Harvest Lab Test CA")
    ca_ski = x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key())
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(hours=1))
        .not_valid_after(now + datetime.timedelta(days=CA_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True,
                crl_sign=True, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(ca_ski, critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf_cert = _server_cert(leaf_key, ca_name, ca_key, ca_ski, now, LEAF_DAYS, "localhost")

    wrong_key = ec.generate_private_key(ec.SECP256R1())
    wrong_cert = _server_cert(wrong_key, _name("Harvest Lab WRONG cert"), wrong_key, None, now, LEAF_DAYS, "Harvest Lab WRONG cert")

    _write(CERT_DIR / "ca.key", _key_pem(ca_key), private=True)
    _write(CERT_DIR / "ca.pem", _cert_pem(ca_cert))
    _write(CERT_DIR / "leaf.key", _key_pem(leaf_key), private=True)
    _write(CERT_DIR / "leaf.pem", _cert_pem(leaf_cert))
    _write(CERT_DIR / "wrong.key", _key_pem(wrong_key), private=True)
    _write(CERT_DIR / "wrong.pem", _cert_pem(wrong_cert))

    leftover = _git("status", "--porcelain", "--", "lab/certs").stdout.strip()
    if leftover:
        sys.exit(f"DANGER: git sees cert files, do not commit:\n{leftover}")
    print(f"Wrote lab certs to {CERT_DIR}")
    print(f"Leaf valid until {leaf_cert.not_valid_after_utc:%Y-%m-%d %H:%M} UTC")
    print("git status shows nothing under lab/certs/ (ignored, as required).")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--force", action="store_true", help="replace existing lab certs")
    make_certs(force=parser.parse_args().force)
