#!/usr/bin/env python3
"""Independent verifier for Haldir's COSE_Sign1 / deterministic-CBOR wire format.

This is a *second implementation* of the security-critical decode-and-verify path,
written from first principles with no third-party dependencies (Ed25519 per RFC
8032 over hashlib.sha512, plus a minimal deterministic CBOR codec). It exists to
catch a spec ambiguity that a single implementation would hide: if the Rust
encoder and this decoder ever disagree on canonical bytes, the AAD binding, or the
`COSE_Sign1` structure, a vector will fail here (runbook Phase 4; `CL-INTEROP-01`).

For each vector it independently:
  1. decodes the COSE_Sign1 envelope as strict deterministic CBOR,
  2. re-encodes the embedded payload and asserts byte-equality (canonical form),
  3. re-derives the content type and external AAD from the message kind + major
     (never trusting the envelope's self-declared values),
  4. rebuilds the `Sig_structure` and verifies the Ed25519 signature, and
  5. confirms tampering with any byte makes verification fail.

Usage:  python3 tools/interop/verify_cose.py [tools/interop/vectors.json]
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

# --- Ed25519 verification (RFC 8032, reference math over sha512) --------------

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493  # group order
D = (-121665 * pow(121666, P - 2, P)) % P
I = pow(2, (P - 1) // 4, P)  # sqrt(-1) mod P


def _sha512_int(b: bytes) -> int:
    return int.from_bytes(hashlib.sha512(b).digest(), "little")


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * pow(D * y * y + 1, P - 2, P)
    x = pow(xx, (P + 3) // 8, P)
    if (x * x - xx) % P != 0:
        x = (x * I) % P
    if x % 2 != 0:
        x = P - x
    return x


_BY = (4 * pow(5, P - 2, P)) % P
_BX = _xrecover(_BY)
_B = (_BX % P, _BY % P)


def _edwards(pt1: tuple[int, int], pt2: tuple[int, int]) -> tuple[int, int]:
    x1, y1 = pt1
    x2, y2 = pt2
    denom = D * x1 * x2 * y1 * y2
    x3 = (x1 * y2 + x2 * y1) * pow(1 + denom, P - 2, P)
    y3 = (y1 * y2 + x1 * x2) * pow(1 - denom, P - 2, P)
    return (x3 % P, y3 % P)


def _scalarmult(pt: tuple[int, int], e: int) -> tuple[int, int]:
    q = (0, 1)
    while e > 0:
        if e & 1:
            q = _edwards(q, pt)
        pt = _edwards(pt, pt)
        e >>= 1
    return q


def _isoncurve(pt: tuple[int, int]) -> bool:
    x, y = pt
    return (-x * x + y * y - 1 - D * x * x * y * y) % P == 0


def _decodepoint(s: bytes) -> tuple[int, int]:
    y = int.from_bytes(s, "little") & ((1 << 255) - 1)
    x = _xrecover(y)
    if (x & 1) != (s[31] >> 7):
        x = P - x
    pt = (x, y)
    if not _isoncurve(pt):
        raise ValueError("point not on curve")
    return pt


def ed25519_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    if len(signature) != 64 or len(public_key) != 32:
        return False
    try:
        big_r = _decodepoint(signature[:32])
        big_a = _decodepoint(public_key)
    except ValueError:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= L:  # enforce canonical S
        return False
    h = _sha512_int(signature[:32] + public_key + message) % L
    return _scalarmult(_B, s) == _edwards(big_r, _scalarmult(big_a, h))


# --- Minimal deterministic CBOR codec (major types 0-5 only) ------------------
# Values are tagged tuples so decode->encode is exact and type-preserving.


class CborError(Exception):
    pass


def cbor_decode(buf: bytes, i: int = 0):
    if i >= len(buf):
        raise CborError("truncated")
    b = buf[i]
    major, minor = b >> 5, b & 0x1F
    i += 1
    if major == 7:
        # Haldir's deterministic profile uses major 7 only for the booleans
        # false (20) / true (21) — no floats, null, undefined, or other simples.
        if minor == 20:
            return ("bool", False), i
        if minor == 21:
            return ("bool", True), i
        raise CborError(f"unsupported simple/float value {minor}")
    if minor < 24:
        val = minor
    elif minor == 24:
        val = buf[i]
        i += 1
        if val < 24:
            raise CborError("non-shortest 1-byte int")
    elif minor == 25:
        val = int.from_bytes(buf[i : i + 2], "big")
        i += 2
        if val < 0x100:
            raise CborError("non-shortest 2-byte int")
    elif minor == 26:
        val = int.from_bytes(buf[i : i + 4], "big")
        i += 4
        if val < 0x10000:
            raise CborError("non-shortest 4-byte int")
    elif minor == 27:
        val = int.from_bytes(buf[i : i + 8], "big")
        i += 8
        if val < 0x100000000:
            raise CborError("non-shortest 8-byte int")
    else:
        raise CborError(f"unsupported additional info {minor}")
    if major == 0:
        return ("uint", val), i
    if major == 1:
        return ("nint", -1 - val), i
    if major == 2:
        return ("bstr", bytes(buf[i : i + val])), i + val
    if major == 3:
        return ("tstr", bytes(buf[i : i + val]).decode("utf-8")), i + val
    if major == 4:
        arr = []
        for _ in range(val):
            item, i = cbor_decode(buf, i)
            arr.append(item)
        return ("array", arr), i
    if major == 5:
        pairs = []
        prev_key = None
        for _ in range(val):
            key, i = cbor_decode(buf, i)
            value, i = cbor_decode(buf, i)
            if prev_key is not None and _map_key_bytes(key) <= prev_key:
                raise CborError("map keys not in strictly ascending canonical order")
            prev_key = _map_key_bytes(key)
            pairs.append((key, value))
        return ("map", pairs), i
    raise CborError(f"unsupported major type {major}")


def _map_key_bytes(key) -> bytes:
    # Canonical CBOR orders map keys by their encoded bytes.
    return cbor_encode(key)


def _enc_head(major: int, val: int) -> bytes:
    if val < 24:
        return bytes([major << 5 | val])
    if val < 0x100:
        return bytes([major << 5 | 24, val])
    if val < 0x10000:
        return bytes([major << 5 | 25]) + val.to_bytes(2, "big")
    if val < 0x100000000:
        return bytes([major << 5 | 26]) + val.to_bytes(4, "big")
    return bytes([major << 5 | 27]) + val.to_bytes(8, "big")


def cbor_encode(value) -> bytes:
    kind = value[0]
    if kind == "bool":
        return bytes([0xE0 | (21 if value[1] else 20)])
    if kind == "uint":
        return _enc_head(0, value[1])
    if kind == "nint":
        return _enc_head(1, -1 - value[1])
    if kind == "bstr":
        return _enc_head(2, len(value[1])) + value[1]
    if kind == "tstr":
        raw = value[1].encode("utf-8")
        return _enc_head(3, len(raw)) + raw
    if kind == "array":
        return _enc_head(4, len(value[1])) + b"".join(cbor_encode(x) for x in value[1])
    if kind == "map":
        body = b"".join(cbor_encode(k) + cbor_encode(v) for k, v in value[1])
        return _enc_head(5, len(value[1])) + body
    raise CborError(f"cannot encode {kind}")


def cbor_decode_exact(buf: bytes):
    value, end = cbor_decode(buf, 0)
    if end != len(buf):
        raise CborError(f"{len(buf) - end} trailing byte(s)")
    return value


# --- COSE_Sign1 (Haldir profile) ----------------------------------------------

HDR_ALG, HDR_CONTENT_TYPE, HDR_KID, ALG_EDDSA = 1, 3, 4, -8


def content_type_for(kind: str) -> str:
    return f"application/{kind.replace('.', '-')}+cbor"


def external_aad_for(kind: str, schema_major: int) -> bytes:
    return f"{kind}.v{schema_major}".encode()


def _sig_structure(protected: bytes, aad: bytes, payload: bytes) -> bytes:
    return cbor_encode(
        ("array", [("tstr", "Signature1"), ("bstr", protected), ("bstr", aad), ("bstr", payload)])
    )


def verify_envelope(env: bytes, kind: str, schema_major: int, public_key: bytes) -> None:
    """Raise AssertionError/CborError/ValueError on any failure."""
    top = cbor_decode_exact(env)
    if top[0] != "array" or len(top[1]) != 4:
        raise ValueError("COSE_Sign1 must be a 4-element array")
    protected_v, unprotected_v, payload_v, sig_v = top[1]
    if protected_v[0] != "bstr":
        raise ValueError("protected header must be a byte string")
    if unprotected_v != ("map", []):
        raise ValueError("unprotected header bucket must be empty")
    if payload_v[0] != "bstr" or sig_v[0] != "bstr":
        raise ValueError("payload and signature must be byte strings")
    protected, payload, signature = protected_v[1], payload_v[1], sig_v[1]
    if len(signature) != 64:
        raise ValueError("signature must be 64 bytes")

    # Protected header: strictly {alg: EdDSA, content_type, kid}, ascending keys.
    # Enforce the EXACT field set — no missing kid, no extra keys — so this
    # verifier is no laxer than the Rust reference (cose.rs parse_protected
    # rejects unknown keys and requires kid). Otherwise structural drift would
    # not fail a vector, defeating CL-INTEROP-01.
    hdr = cbor_decode_exact(protected)
    if hdr[0] != "map":
        raise ValueError("protected header must be a map")
    if any(k[0] != "uint" for k, _ in hdr[1]):
        raise ValueError("protected header keys must be unsigned integers")
    fields = dict((k[1], v) for k, v in hdr[1])
    if set(fields) != {HDR_ALG, HDR_CONTENT_TYPE, HDR_KID}:
        raise ValueError("protected header must be exactly {alg, content_type, kid}")
    if fields[HDR_KID][0] != "bstr":
        raise ValueError("kid must be a byte string")
    if fields.get(HDR_ALG) != ("nint", ALG_EDDSA):
        raise ValueError("alg must be EdDSA (-8)")
    ct = fields.get(HDR_CONTENT_TYPE)
    if ct is None or ct[0] != "tstr":
        raise ValueError("missing content type")
    if ct[1] != content_type_for(kind):
        raise ValueError(f"content type {ct[1]!r} != derived {content_type_for(kind)!r}")

    # Canonical re-encode equality on the embedded payload.
    if cbor_encode(cbor_decode_exact(payload)) != payload:
        raise ValueError("payload is not canonical deterministic CBOR")

    # Signature over the reconstructed Sig_structure with the derived AAD.
    aad = external_aad_for(kind, schema_major)
    ss = _sig_structure(protected, aad, payload)
    if not ed25519_verify(public_key, ss, signature):
        raise ValueError("Ed25519 signature does not verify")

    # Negative control: a single flipped byte must break verification.
    tampered = bytearray(ss)
    tampered[-1] ^= 0x01
    if ed25519_verify(public_key, bytes(tampered), signature):
        raise ValueError("tampered Sig_structure still verified (verifier is broken)")


def main() -> int:
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).with_name("vectors.json")
    doc = json.loads(path.read_text())
    vectors = doc.get("vectors", [])
    if not vectors:
        print("verify-cose: FAIL: no vectors", file=sys.stderr)
        return 1
    ok = 0
    for v in vectors:
        name = v["name"]
        try:
            verify_envelope(
                bytes.fromhex(v["cose_hex"]),
                v["kind"],
                int(v["schema_major"]),
                bytes.fromhex(v["public_key_hex"]),
            )
        except Exception as exc:  # noqa: BLE001 — report and fail on any error
            print(f"verify-cose: {name}: FAIL: {exc}", file=sys.stderr)
            return 1
        ok += 1
        print(f"verify-cose: {name}: OK")
    print(f"verify-cose: OK ({ok} vector(s) independently verified)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
