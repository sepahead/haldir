# Interop vectors

An independent, second-implementation check of Haldir's `COSE_Sign1` / Ed25519 /
deterministic-CBOR wire format (`CL-INTEROP-01`, runbook Phase 4). A single
implementation cannot catch its own spec ambiguity; a second one over shared
vectors can.

- `emit_interop_vectors` (a `haldir-crypto` example) crafts deterministic
  canonical-CBOR payloads covering every wire major type and integer width,
  signs each as a `COSE_Sign1` with a fixed seed key, and prints the vectors.
- `vectors.json` is the committed output of that emitter.
- `verify_cose.py` is a from-scratch verifier with **no third-party
  dependencies** (Ed25519 per RFC 8032 over `hashlib.sha512`, plus a minimal
  deterministic CBOR codec). For each vector it decodes the envelope, re-encodes
  the payload and asserts byte-equality (canonical form), re-derives the content
  type and external AAD from the kind + major, verifies the signature, and
  confirms that flipping any byte breaks verification.

## Regenerate and verify

```bash
cargo run -p haldir-crypto --example emit_interop_vectors > tools/interop/vectors.json
python3 tools/interop/verify_cose.py tools/interop/vectors.json
```

CI (`interop` job) re-emits the vectors and fails on any diff from the committed
file, then runs the Python verifier — so a wire-format change cannot land silently.
