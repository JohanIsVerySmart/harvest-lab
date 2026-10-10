"""Public wire encoding and real authenticated encryption for the toy booth."""

import hashlib
import json
import re
import secrets
import uuid
from datetime import datetime, timezone

from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .group import BoothError, exchange, fresh_group, validate_group, validate_share
from . import kem

TAG = b"HLAB\x00\x01\x00\x00"
CHANNELS = {"classical": b"\x00", "hybrid": b"\x01"}


def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def digest(transcript):
    return hashlib.sha256(canonical_json(transcript)).hexdigest()


def hex_bytes(value, size):
    if not isinstance(value, str) or len(value) != 2 * size or not re.fullmatch(r"[0-9a-f]+", value):
        raise BoothError("bad_hex", "A public byte field has invalid lowercase hex or length.")
    return bytes.fromhex(value)


def exact_keys(value, expected):
    if not isinstance(value, dict) or set(value) != set(expected):
        raise BoothError("bad_transcript", "The recording has missing or unexpected fields.")


def handshake_parts(record, channel):
    """Validate public fields, then reconstruct SPEC.md's M1/M2 byte layout."""
    exact_keys(record, ("M1", "M2", "M3"))
    m1, m2, m3 = record["M1"], record["M2"], record["M3"]
    hybrid = channel == "hybrid"
    exact_keys(m1, ("v", "ch", "bits", "p", "g", "A", "ek") if hybrid else
               ("v", "ch", "bits", "p", "g", "A"))
    exact_keys(m2, ("v", "ch", "B", "kem_ct") if hybrid else ("v", "ch", "B"))
    exact_keys(m3, ("v", "ch", "nonce", "aead_ct"))
    for msg in (m1, m2, m3):
        if type(msg["v"]) is not int or msg["v"] != 1 or msg["ch"] != channel:
            raise BoothError("bad_transcript", "The recording version or channel is wrong.")
    bits = m1["bits"]
    if type(bits) is not int or bits not in (32, 36, 40):
        raise BoothError("bad_group", "Unsupported toy group size.")
    width = (bits + 7) // 8
    p_raw, g_raw, A_raw = (hex_bytes(m1[x], width) for x in ("p", "g", "A"))
    B_raw = hex_bytes(m2["B"], width)
    p, g, A, B = (int.from_bytes(x, "big") for x in (p_raw, g_raw, A_raw, B_raw))
    q = validate_group(p, g, bits)
    validate_share(A, p, q)
    validate_share(B, p, q)
    ek = hex_bytes(m1["ek"], 1184) if hybrid else b""
    ct = hex_bytes(m2["kem_ct"], 1088) if hybrid else b""
    header = TAG + CHANNELS[channel] + bits.to_bytes(2, "big") + width.to_bytes(2, "big")
    first = header + p_raw + g_raw + A_raw + len(ek).to_bytes(2, "big") + ek
    second = header + p_raw + g_raw + A_raw + B_raw + len(ct).to_bytes(2, "big") + ct
    packed = (b"HarvestLab/1 handshake\x00" + len(first).to_bytes(4, "big") + first
              + len(second).to_bytes(4, "big") + second)
    salt = hashlib.sha256(packed).digest()
    info = b"HarvestLab/1 key\x00" + CHANNELS[channel] + A_raw + B_raw + len(ct).to_bytes(2, "big") + ct
    nonce = hex_bytes(m3["nonce"], 12)
    value = m3["aead_ct"]
    if not isinstance(value, str) or not 34 <= len(value) <= 160 or len(value) % 2:
        raise BoothError("bad_transcript", "The encrypted message must contain 1 to 64 bytes plus its tag.")
    encrypted = hex_bytes(value, len(value) // 2)
    return p, g, q, A, B, width, salt, info, nonce, encrypted


def derive_key(ikm, salt, info):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info).derive(ikm)


def validate_transcript(transcript):
    exact_keys(transcript, ("v", "session", "created", "channels"))
    if type(transcript["v"]) is not int or transcript["v"] != 1:
        raise BoothError("bad_transcript", "Unsupported recording version.")
    if not isinstance(transcript["session"], str) or not re.fullmatch(r"[0-9a-f]{32}", transcript["session"]):
        raise BoothError("bad_transcript", "Invalid recording session identifier.")
    created = transcript["created"]
    if not isinstance(created, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z", created):
        raise BoothError("bad_transcript", "Invalid recording timestamp.")
    try:
        datetime.fromisoformat(created.replace("Z", "+00:00"))
    except ValueError as exc:
        raise BoothError("bad_transcript", "Invalid recording timestamp.") from exc
    exact_keys(transcript["channels"], CHANNELS)
    for channel in CHANNELS:
        handshake_parts(transcript["channels"][channel], channel)
    return transcript


def _unique(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise BoothError("bad_json", "Duplicate recording fields are not allowed.")
        result[name] = value
    return result


def load_transcript(raw):
    if len(raw) > 65536:
        raise BoothError("bad_json", "The recording is too large.")
    try:
        text = raw.decode("utf-8") if isinstance(raw, bytes) else raw
        depth, quoted, escaped = 0, False, False
        for char in text:
            if quoted:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    quoted = False
            elif char == '"':
                quoted = True
            elif char in "[{":
                depth += 1
                if depth > 16:
                    raise ValueError("too deeply nested")
            elif char in "]}":
                depth -= 1
        parsed = json.loads(raw, object_pairs_hook=_unique,
                            parse_constant=lambda _: (_ for _ in ()).throw(ValueError("non-finite")))
    except (ValueError, RecursionError, UnicodeError) as exc:
        raise BoothError("bad_json", "The recording is not valid JSON.") from exc
    return validate_transcript(parsed)


def message_bytes(message):
    if not isinstance(message, str):
        raise BoothError("invalid_request", "Enter text for both messages.")
    try:
        raw = message.encode("utf-8")
    except UnicodeError as exc:
        raise BoothError("invalid_request", "The message contains invalid Unicode.") from exc
    if not 1 <= len(raw) <= 64:
        raise BoothError("invalid_request", "Each message must be 1 to 64 UTF-8 bytes.")
    return raw


def send(classical, hybrid, bits=40):
    """Only public transcript and positive-control booleans leave this function."""
    messages = {"classical": message_bytes(classical), "hybrid": message_bytes(hybrid)}
    p, g, q = fresh_group(bits)
    width = (bits + 7) // 8
    channels, checks, combiner_ok = {}, {}, False
    for channel in CHANNELS:
        A, B, client_dh, server_dh = exchange(p, g, q)
        m1 = {"v": 1, "ch": channel, "bits": bits,
              "p": p.to_bytes(width, "big").hex(), "g": g.to_bytes(width, "big").hex(),
              "A": A.to_bytes(width, "big").hex()}
        m2 = {"v": 1, "ch": channel, "B": B.to_bytes(width, "big").hex()}
        client_ikm, server_ikm = client_dh, server_dh
        if channel == "hybrid":
            ek, private = kem.keygen()
            server_kem, ct = kem.encaps(ek)
            client_kem = kem.decaps(private, ct)
            if client_kem != server_kem:
                raise BoothError("kem_roundtrip_failed", "ML-KEM participants did not agree.")
            m1["ek"], m2["kem_ct"] = ek.hex(), ct.hex()
            client_ikm, server_ikm = client_kem + client_dh, server_kem + server_dh
            del private, client_kem, server_kem
        nonce = secrets.token_bytes(12)
        record = {"M1": m1, "M2": m2, "M3": {"v": 1, "ch": channel,
                   "nonce": nonce.hex(), "aead_ct": (b"\x00" * 17).hex()}}
        *_, salt, info, _, _ = handshake_parts(record, channel)
        outgoing = derive_key(client_ikm, salt, info)
        incoming = derive_key(server_ikm, salt, info)
        encrypted = AESGCM(outgoing).encrypt(nonce, messages[channel], salt)
        checks[channel] = AESGCM(incoming).decrypt(nonce, encrypted, salt) == messages[channel]
        if channel == "hybrid":
            # A missing KEM contribution can still reject the zero-secret guess.
            # This independent DH-only control catches that false success.
            dh_only = derive_key(server_dh, salt, info)
            try:
                AESGCM(dh_only).decrypt(nonce, encrypted, salt)
            except InvalidTag:
                combiner_ok = True
            del dh_only
        record["M3"]["aead_ct"] = encrypted.hex()
        channels[channel] = record
        del client_ikm, server_ikm, client_dh, server_dh, outgoing, incoming
    transcript = {"v": 1, "session": uuid.uuid4().hex,
                  "created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                  "channels": channels}
    validate_transcript(transcript)
    return {"transcript": transcript, "transcript_sha256": digest(transcript),
            "bytes": len(canonical_json(transcript)), "bits": bits, "q_bits": q.bit_length(),
            "kem": kem.NAME, "teaching_library": kem.TEACHING_LIBRARY,
            "legit_classical_ok": checks["classical"], "legit_hybrid_ok": checks["hybrid"],
            "combiner_control_ok": combiner_ok}
