# Booth protocol v1

This file defines the byte contract for the two independent booth channels within Johan's previously published contract/api.md transcript shape from this event. The replacement repository awaits republication of that agreement. Implementations must follow these encodings exactly; do not hash JSON to derive handshake keys.

## Parameters and messages

`channel` is one byte: `0x00` for `classical`, `0x01` for `hybrid`. `bits` is the declared bit length of `p` as an unsigned 16-bit big-endian integer. `w = ceil(bits / 8)` is the fixed width, in bytes, of every DH integer. Integers `p`, `g`, `A`, and `B` are unsigned big-endian values exactly `w` bytes long, retaining leading zero bytes. For public JSON, encode each as exactly `2*w` lowercase hexadecimal digits. The values are public; private exponents and KEM shared secrets must never appear in the transcript.

Every message begins with the 8-byte domain/version tag `b"HLAB\x00\x01\x00\x00"` (ASCII `HLAB`, then version 1 and two reserved zero bytes). It is followed by the channel byte, `bits` (u16 big-endian), and `w` (u16 big-endian). Every variable-length field is encoded as `u16be(length) || field`; fixed-width DH fields are encoded directly without lengths. Reject unsupported versions/channels, inconsistent `bits`/`w`, trailing bytes, or lengths other than those specified below.

`M1` (client to server) is:

```
tag || channel || bits || w || p[w] || g[w] || A[w] ||
    (u16be(1184) || ek[1184]   if hybrid; u16be(0) if classical)
```

For hybrid, `ek` is the ML-KEM-768 encapsulation public key (1184 bytes). For classical, the empty field is present, making the encoding unambiguous.

`M2` (server to client) is:

```
tag || channel || bits || w || p[w] || g[w] || A[w] || B[w] ||
    (u16be(1088) || kemct[1088] if hybrid; u16be(0) if classical)
```

For hybrid, `kemct` is the ML-KEM-768 ciphertext (1088 bytes); it is empty in the classical channel. Repeating the public parameters and `A` binds each reply to its request. A receiver must check those repeated values against its local `M1` before proceeding.

`M3` is the AES-GCM client confirmation: `nonce[12] || ciphertext_and_tag`. AES-GCM appends its 16-byte tag to the ciphertext. Use a fresh random 12-byte nonce for each message. The associated data is the handshake hash `H` defined below. The booth's positive-control plaintext is application-defined and must be the same at both endpoints.

## Handshake key

Let `H = SHA-256(b"HarvestLab/1 handshake\x00" || u32be(len(M1)) || M1 || u32be(len(M2)) || M2)`. This is the handshake hash and the HKDF salt. `A`, `B`, and `kemct` below mean their exact fixed-width/packed field bytes, not their JSON text.

The HKDF info is:

```
b"HarvestLab/1 key\x00" || channel_byte || A[w] || B[w] || u16be(len(kemct)) || kemct
```

Use HKDF-SHA256 to derive 32 bytes. The classical IKM is exactly `DH[w]`, the shared DH element encoded as `w` bytes. The hybrid IKM is exactly `KEMsecret[32] || DH[w]`, in that order, with no extra IKM prefixes or lengths. KEM secret is the 32-byte ML-KEM-768 shared secret. The distinct channel byte and the transcript hash prevent cross-channel key reuse.

For the toy safe-prime group, choose a prime `p = 2q + 1` with prime `q`, and use `g = 4`. Validate `g^q mod p == 1` and `g != 1`. Sample each private exponent uniformly from `1..q-1`, and encode public/shared DH elements at width `w`. Peer values must be in `2..p-2` and satisfy `value^q mod p == 1` before use. These toy parameters are deliberately breakable and are for demonstration only.

## JSON transcript

The transcript object has exactly these top-level keys: `v`, `session`, `created`, `channels`. `v` is integer `1`; `session` is a nonempty string; `created` is an RFC 3339 UTC timestamp ending in `Z`. `channels` has exactly `classical` and `hybrid`. Each channel object has exactly `M1`, `M2`, and `M3`, each represented as an object with the exact keys below.

`M1` has keys `v`, `ch`, `bits`, `p`, `g`, `A`, and `ek` in the hybrid channel; in the classical channel it omits `ek`. `v` is integer `1`, `ch` is the channel name (`"classical"` or `"hybrid"`), and `bits` is an integer. `p`, `g`, and `A` are lowercase hex encodings of exactly `w` bytes each, including leading zero bytes. `ek` is lowercase hex for exactly 1184 bytes.

`M2` has keys `v`, `ch`, and `B` in the classical channel, and those keys plus `kem_ct` in the hybrid channel. `v` is integer `1`; `ch` is the channel name. `B` is lowercase hex for exactly `w` bytes. `kem_ct` is lowercase hex for exactly 1088 bytes. The packed M2 fields `bits`, `p`, `g`, and `A` are taken from the corresponding M1; they are not repeated in the JSON object.

`M3` has exactly the keys `v`, `ch`, `nonce`, and `aead_ct`. `v` is integer `1`; `ch` is the channel name; `nonce` is lowercase hex for exactly 12 bytes; `aead_ct` is lowercase hex for the AES-GCM ciphertext with its 16-byte tag appended. When producing canonical packed M1/M2 for the handshake hash, use the byte layouts above and the M1 values carried by JSON; do not hash JSON encodings in their place.

Reject unknown or missing keys, wrong JSON types, wrong channel/version values, non-ASCII text, malformed or uppercase hex, duplicate JSON keys, and non-finite JSON numbers. Limit transcript input to 65536 bytes and reject excessive nesting; parser recursion failures must be returned as `bad_json` rather than escaping as an exception.

Canonical transcript bytes are UTF-8 JSON serialized with `sort_keys=True`, separators `(',', ':')`, `ensure_ascii=True`, and `allow_nan=False`; no trailing newline is included. The transcript digest is lowercase hex `SHA-256(canonical_transcript_bytes)`. Keep this full-transcript digest separate from the object being hashed (for example, as CLI output), so it is not self-referential. This digest is for transcript identification; the handshake hash above alone feeds HKDF and is also the AES-GCM associated data.
