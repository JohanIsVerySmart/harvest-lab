"""Small safe-prime DH. These groups are deliberately breakable."""

import secrets


class BoothError(ValueError):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def is_prime(n):
    """Deterministic Miller-Rabin for unsigned integers below 2**64."""
    if n < 2 or n >= 2**64:
        return False
    for small in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % small == 0:
            return n == small
    d, shifts = n - 1, 0
    while d % 2 == 0:
        d //= 2
        shifts += 1
    for base in (2, 325, 9375, 28178, 450775, 9780504, 1795265022):
        if base % n == 0:
            continue
        x = pow(base, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(shifts - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def validate_group(p, g, bits):
    if type(bits) is not int or bits not in (32, 36, 40):
        raise BoothError("bad_group", "Use a 36- or 40-bit toy group; 32 bits is test-only.")
    if type(p) is not int or type(g) is not int or p.bit_length() != bits:
        raise BoothError("bad_group", "The toy group has the wrong size.")
    q = (p - 1) // 2
    if not is_prime(p) or not is_prime(q) or g != 4 or pow(g, q, p) != 1:
        raise BoothError("bad_group", "The toy group must be a safe prime with generator 4.")
    return q


def validate_share(value, p, q):
    if type(value) is not int or not 1 < value < p - 1 or pow(value, q, p) != 1:
        raise BoothError("bad_share", "The public DH value is outside the allowed subgroup.")


def fresh_group(bits=40):
    if type(bits) is not int or bits not in (32, 36, 40):
        raise BoothError("bad_group", "Unsupported toy group size.")
    while True:
        q = secrets.randbits(bits - 1) | (1 << (bits - 2)) | 1
        p = 2 * q + 1
        if is_prime(q) and is_prime(p):
            validate_group(p, 4, bits)
            return p, 4, q


def exchange(p, g, q):
    a = secrets.randbelow(q - 1) + 1
    b = secrets.randbelow(q - 1) + 1
    A, B = pow(g, a, p), pow(g, b, p)
    validate_share(A, p, q)
    validate_share(B, p, q)
    width = (p.bit_length() + 7) // 8
    client = pow(B, a, p).to_bytes(width, "big")
    server = pow(A, b, p).to_bytes(width, "big")
    return A, B, client, server
