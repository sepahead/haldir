# ADR-0002 — Strict deterministic CBOR + domain-separated COSE_Sign1/Ed25519

Status: accepted

## Context

Signatures over a canonical form are only meaningful if the bytes are canonical.
CBOR admits many encodings of the same value (indefinite lengths, non-shortest
ints, map-key orderings, floats, tags). If two encodings of "the same" message can
both verify, an attacker can grind a variant that changes meaning while keeping a
valid signature, or replay a message across contexts.

## Decision

Use strict deterministic CBOR: integer map keys, shortest-form integers, no
floats, no tags, no indefinite lengths, and a re-encode-equality check on decode —
a message that does not re-encode to identical bytes is rejected as non-canonical.
Sign with `COSE_Sign1`/Ed25519, binding a domain-separated AAD of the form
`{kind}.v{major}` and a per-kind content type `application/{kind-dashed}+cbor`, so
a signature for one message kind or schema major cannot be lifted to another.

## Consequences

- Verification is exact-bytes; there is no "equivalent encoding" ambiguity.
- Cross-context and cross-version signature reuse is closed by the AAD binding.
- An independent implementation must reproduce the byte layout to interoperate;
  that second implementation is a pending evidence item (`CL-INTEROP-01`).

## Evidence

`haldir-contracts` cbor tests + hostile-parser fuzz-smoke (`CL-CBOR-01`);
`haldir-crypto` cose tests (`CL-COSE-01`).
