"""Standalone, transcript-only classical attack for the Harvest Lab booth.

It deliberately imports no booth code: this is the independent verifier used by
the demonstration runner.
"""

import ctypes
import hashlib
import json
import math
import os
import re
import sys
import time
from datetime import datetime

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


TAG = b"HLAB\x00\x01\x00\x00"
CHANNELS = {"classical": b"\x00", "hybrid": b"\x01"}
MAX_INPUT = 65536
MAX_DEPTH = 16


class AttackError(ValueError):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise AttackError("bad_json", "Duplicate transcript fields are not allowed.")
        result[key] = value
    return result


def _finite_error(_value):
    raise AttackError("bad_json", "Non-finite JSON numbers are not allowed.")


def _check_json(value, depth=0):
    if depth > MAX_DEPTH:
        raise AttackError("bad_json", "Transcript nesting is too deep.")
    if isinstance(value, dict):
        for key, nested in value.items():
            if not isinstance(key, str) or not key.isascii():
                raise AttackError("bad_json", "Transcript text must be ASCII.")
            _check_json(nested, depth + 1)
    elif isinstance(value, list):
        for nested in value:
            _check_json(nested, depth + 1)
    elif isinstance(value, str) and not value.isascii():
        raise AttackError("bad_json", "Transcript text must be ASCII.")


def load_input(raw):
    if len(raw) > MAX_INPUT:
        raise AttackError("bad_json", "The recording is too large.")
    try:
        parsed = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique,
                            parse_constant=_finite_error)
    except AttackError:
        raise
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise AttackError("bad_json", "The recording is not valid JSON.") from exc
    _check_json(parsed)
    return parsed


def exact_keys(value, expected):
    if not isinstance(value, dict) or set(value) != set(expected):
        raise AttackError("bad_transcript", "The recording has missing or unexpected fields.")


def hex_bytes(value, size):
    if (not isinstance(value, str) or len(value) != 2 * size
            or re.fullmatch(r"[0-9a-f]+", value) is None):
        raise AttackError("bad_hex", "A public byte field has invalid lowercase hex or length.")
    return bytes.fromhex(value)


def is_prime(number):
    if number < 2 or number >= 2 ** 64:
        return False
    for small in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if number % small == 0:
            return number == small
    odd, shifts = number - 1, 0
    while odd % 2 == 0:
        odd //= 2
        shifts += 1
    for base in (2, 325, 9375, 28178, 450775, 9780504, 1795265022):
        if base % number == 0:
            continue
        witness = pow(base, odd, number)
        if witness in (1, number - 1):
            continue
        for _ in range(shifts - 1):
            witness = witness * witness % number
            if witness == number - 1:
                break
        else:
            return False
    return True


def validate_group(p, g, bits):
    if type(bits) is not int or bits not in (32, 36, 40):
        raise AttackError("bad_group", "Unsupported toy group size.")
    if type(p) is not int or type(g) is not int or p.bit_length() != bits:
        raise AttackError("bad_group", "The toy group has the wrong size.")
    q = (p - 1) // 2
    if not is_prime(p) or not is_prime(q) or g != 4 or pow(g, q, p) != 1:
        raise AttackError("bad_group", "The toy group must be a safe prime with generator 4.")
    return q


def validate_share(value, p, q):
    if type(value) is not int or not 1 < value < p - 1 or pow(value, q, p) != 1:
        raise AttackError("bad_share", "The public DH value is outside the allowed subgroup.")


def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def handshake_parts(record, channel):
    exact_keys(record, ("M1", "M2", "M3"))
    m1, m2, m3 = record["M1"], record["M2"], record["M3"]
    hybrid = channel == "hybrid"
    exact_keys(m1, ("v", "ch", "bits", "p", "g", "A", "ek") if hybrid else
               ("v", "ch", "bits", "p", "g", "A"))
    exact_keys(m2, ("v", "ch", "B", "kem_ct") if hybrid else ("v", "ch", "B"))
    exact_keys(m3, ("v", "ch", "nonce", "aead_ct"))
    for message in (m1, m2, m3):
        if type(message["v"]) is not int or message["v"] != 1 or message["ch"] != channel:
            raise AttackError("bad_transcript", "The recording version or channel is wrong.")
    bits = m1["bits"]
    if type(bits) is not int or bits not in (32, 36, 40):
        raise AttackError("bad_group", "Unsupported toy group size.")
    width = (bits + 7) // 8
    p_raw, g_raw, a_raw = (hex_bytes(m1[name], width) for name in ("p", "g", "A"))
    b_raw = hex_bytes(m2["B"], width)
    p, g, a, b = (int.from_bytes(raw, "big") for raw in (p_raw, g_raw, a_raw, b_raw))
    q = validate_group(p, g, bits)
    validate_share(a, p, q)
    validate_share(b, p, q)
    encapsulation_key = hex_bytes(m1["ek"], 1184) if hybrid else b""
    kem_ciphertext = hex_bytes(m2["kem_ct"], 1088) if hybrid else b""
    header = TAG + CHANNELS[channel] + bits.to_bytes(2, "big") + width.to_bytes(2, "big")
    first = header + p_raw + g_raw + a_raw + len(encapsulation_key).to_bytes(2, "big") + encapsulation_key
    second = header + p_raw + g_raw + a_raw + b_raw + len(kem_ciphertext).to_bytes(2, "big") + kem_ciphertext
    packed = (b"HarvestLab/1 handshake\x00" + len(first).to_bytes(4, "big") + first
              + len(second).to_bytes(4, "big") + second)
    salt = hashlib.sha256(packed).digest()
    info = b"HarvestLab/1 key\x00" + CHANNELS[channel] + a_raw + b_raw + len(kem_ciphertext).to_bytes(2, "big") + kem_ciphertext
    nonce = hex_bytes(m3["nonce"], 12)
    encrypted_text = m3["aead_ct"]
    if not isinstance(encrypted_text, str) or not 34 <= len(encrypted_text) <= 160 or len(encrypted_text) % 2:
        raise AttackError("bad_transcript", "The encrypted message must contain 1 to 64 bytes plus its tag.")
    encrypted = hex_bytes(encrypted_text, len(encrypted_text) // 2)
    return {"bits": bits, "p": p, "g": g, "q": q, "A": a, "B": b,
            "width": width, "salt": salt, "info": info, "nonce": nonce,
            "encrypted": encrypted}


def validate_transcript(transcript):
    exact_keys(transcript, ("v", "session", "created", "channels"))
    if type(transcript["v"]) is not int or transcript["v"] != 1:
        raise AttackError("bad_transcript", "Unsupported recording version.")
    if not isinstance(transcript["session"], str) or not re.fullmatch(r"[0-9a-f]{32}", transcript["session"]):
        raise AttackError("bad_transcript", "Invalid recording session identifier.")
    created = transcript["created"]
    if not isinstance(created, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z", created):
        raise AttackError("bad_transcript", "Invalid recording timestamp.")
    try:
        datetime.fromisoformat(created.replace("Z", "+00:00"))
    except ValueError as exc:
        raise AttackError("bad_transcript", "Invalid recording timestamp.") from exc
    exact_keys(transcript["channels"], CHANNELS)
    return {channel: handshake_parts(transcript["channels"][channel], channel)
            for channel in CHANNELS}


def rss_bytes():
    if os.name == "nt":
        class ProcessMemoryCounters(ctypes.Structure):
            _fields_ = [("cb", ctypes.c_ulong), ("PageFaultCount", ctypes.c_ulong),
                        ("PeakWorkingSetSize", ctypes.c_size_t), ("WorkingSetSize", ctypes.c_size_t),
                        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t), ("QuotaPagedPoolUsage", ctypes.c_size_t),
                        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t), ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                        ("PagefileUsage", ctypes.c_size_t), ("PeakPagefileUsage", ctypes.c_size_t)]
        counters = ProcessMemoryCounters()
        counters.cb = ctypes.sizeof(counters)
        kernel32, psapi = ctypes.windll.kernel32, ctypes.windll.psapi
        kernel32.GetCurrentProcess.restype = ctypes.c_void_p
        psapi.GetProcessMemoryInfo.argtypes = (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong)
        psapi.GetProcessMemoryInfo.restype = ctypes.c_int
        if psapi.GetProcessMemoryInfo(kernel32.GetCurrentProcess(), ctypes.byref(counters), counters.cb):
            return int(counters.PeakWorkingSetSize)
        return None
    try:
        import resource
        value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return int(value if sys.platform == "darwin" else value * 1024)
    except (ImportError, AttributeError):
        return None


def derive(ikm, salt, info):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info).derive(ikm)


def main():
    started = time.perf_counter()
    run = ""

    def emit(event_type, channel=None, **fields):
        event = {"v": 1, "run": run, "ch": channel,
                 "t_ms": round((time.perf_counter() - started) * 1000, 3),
                 "type": event_type}
        event.update(fields)
        print(json.dumps(event, ensure_ascii=True, separators=(",", ":")), flush=True)

    try:
        transcript = load_input(sys.stdin.buffer.read(MAX_INPUT + 1))
        run = transcript.get("session", "") if isinstance(transcript, dict) else ""
        parts = validate_transcript(transcript)
        encoded = canonical_json(transcript)
        emit("input", transcript_sha256=hashlib.sha256(encoded).hexdigest(), bytes=len(encoded))
        def recover_exponent(channel, values):
            channel_started = time.perf_counter()
            q, p, g, target = values["q"], values["p"], values["g"], values["A"]
            root = math.isqrt(q)
            m = root + (root * root < q)
            emit("start", channel, bits=values["bits"], q_bits=q.bit_length(), m=m)
            baby, value = {}, 1
            for step in range(m):
                baby.setdefault(value, step)
                value = value * g % p
                completed = step + 1
                if completed % 8192 == 0 or completed == m:
                    emit("baby", channel, done=completed, total=m,
                         pct=round(completed * 100 / m, 3))
            factor = pow(pow(g, m, p), -1, p)
            gamma = target
            giant_completed = 0
            for giant in range(m + 1):
                baby_step = baby.get(gamma)
                giant_completed = giant + 1
                if baby_step is not None:
                    candidate = giant * m + baby_step
                    if candidate < q and pow(g, candidate, p) == target:
                        emit("giant", channel, done=giant_completed, max=m + 1,
                             pct_upper=round(giant_completed * 100 / (m + 1), 3))
                        emit("found", channel, exp_hex=format(candidate, "x"),
                             baby_steps=m, giant_steps=giant_completed,
                             ms=round((time.perf_counter() - channel_started) * 1000, 3))
                        return candidate
                gamma = gamma * factor % p
                if giant_completed % 8192 == 0 or giant_completed == m + 1:
                    emit("giant", channel, done=giant_completed, max=m + 1,
                         pct_upper=round(giant_completed * 100 / (m + 1), 3))
            raise AttackError("discrete_log_failed", "No exponent was found in the advertised subgroup.")

        classical = parts["classical"]
        exponent = recover_exponent("classical", classical)
        shared = pow(classical["B"], exponent, classical["p"]).to_bytes(classical["width"], "big")
        classical_key = derive(shared, classical["salt"], classical["info"])
        emit("derive", "classical", th_hex=classical["salt"].hex(), ikm_parts=1)
        try:
            plaintext = AESGCM(classical_key).decrypt(classical["nonce"], classical["encrypted"], classical["salt"])
        except InvalidTag as exc:
            raise AttackError("classical_decrypt_failed", "The recovered classical key did not authenticate the message.") from exc
        try:
            plaintext_text = plaintext.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise AttackError("plaintext_encoding", "The recovered classical plaintext is not UTF-8.") from exc
        emit("decrypt", "classical", ok=True, plaintext=plaintext_text)

        hybrid = parts["hybrid"]
        hybrid_exponent = recover_exponent("hybrid", hybrid)
        hybrid_shared = pow(hybrid["B"], hybrid_exponent, hybrid["p"]).to_bytes(hybrid["width"], "big")
        guessed_key = derive(b"\x00" * 32 + hybrid_shared, hybrid["salt"], hybrid["info"])
        guess = "ml_kem_secret=32_zero_bytes (a labeled guess, not an attack on ML-KEM)"
        emit("derive", "hybrid", th_hex=hybrid["salt"].hex(), ikm_parts=2, guess=guess)
        try:
            guessed_plaintext = AESGCM(guessed_key).decrypt(hybrid["nonce"], hybrid["encrypted"], hybrid["salt"])
        except InvalidTag:
            emit("decrypt", "hybrid", ok=False, reason="aead_tag_mismatch", exception="InvalidTag",
                 note="DH secret recovered; ML-KEM contribution unavailable.", guess=guess,
                 unexpected=False)
        else:
            del guessed_plaintext
            emit("decrypt", "hybrid", ok=True, note="DH secret recovered; ML-KEM contribution unavailable.",
                 guess=guess, unexpected=True)
        emit("done", total_ms=round((time.perf_counter() - started) * 1000, 3), peak_rss_bytes=rss_bytes())
        return 0
    except AttackError as exc:
        code = {"bad_transcript": "bad_schema", "bad_hex": "bad_schema",
                "discrete_log_failed": "not_found", "classical_decrypt_failed": "internal",
                "internal_error": "internal"}.get(exc.code, exc.code)
        if code not in {"bad_json", "bad_version", "bad_group", "bad_share", "bad_schema", "not_found", "internal"}:
            code = "internal"
        emit("error", code=code, msg=str(exc))
    except Exception:
        emit("error", code="internal", msg="The attacker could not process this transcript.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
