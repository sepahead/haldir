# Contract golden vectors

Canonical byte layouts for representative Haldir contracts. The authoritative
generator is the Rust round-trip test `haldir-contracts` (`tests_contracts.rs`,
`golden_*_hex_is_stable`); these files are its committed output. `CHECKSUMS.sha256`
pins them so `tools/verify-generated.py` catches drift.

Cross-language (Python/TypeScript) reproduction of these vectors is **not** part of
the P0 deliverable (see `docs/LIMITATIONS.md`); the Rust golden + re-encode-equality
tests pin the canonical encoding within Rust only.

- `haldir-intent-v1.cbor.hex` — canonical `HaldirIntentV1` (see the golden test).
