"""The single ML-KEM-768 implementation selected by a real round trip."""

from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey, MLKEM768PublicKey


NAME = "cryptography 50.0.2 / ML-KEM-768"
TEACHING_LIBRARY = False


def keygen():
    """Return the public encapsulation key and its private decapsulation key."""
    private = MLKEM768PrivateKey.generate()
    return private.public_key().public_bytes_raw(), private


def encaps(public_key):
    """Encapsulate a fresh shared secret to ``public_key``."""
    return MLKEM768PublicKey.from_public_bytes(public_key).encapsulate()


def decaps(private_key, ciphertext):
    """Recover the shared secret bound to ``ciphertext``."""
    return private_key.decapsulate(ciphertext)
