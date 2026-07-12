# Security policy

## Status

Haldir Gate is an **experimental research implementation**. It has **not** been through an
independent security review, penetration test, or certification. Do **not** deploy it to
control any physical vehicle or actuator. There is **no production-use status**.

## Reporting a vulnerability

Report suspected vulnerabilities privately to the Sepahead maintainers rather than via a
public issue. Include the exact commit, the affected crate/module and line range, a
reproduction, and the security impact (which invariant it breaks — see the invariant IDs
`A#/S#/T#/P#/F#` in the specification).

## Scope of the security claim

The defensible claim is narrow: **within a declared complete-mediation profile, an
unauthorized controller intent does not become a new plant-facing command, and each
observable stage produces distinguishable evidence.** Haldir does **not** establish that a
neural controller is safe, does not authenticate untrusted sensors by hashing them, does
not replace PX4/plant failsafes, and does not provide the plant authority, wire
`publisher_id` binding, or applied/stop acknowledgements that NCP `v0.8.0` defers.

## Handling of secrets

- No private keys, certificates, tokens, or absolute local paths are committed.
- Development PKI lives only under `range/certs-dev/` and is unmistakably non-production;
  CI fails if a development certificate fingerprint appears in an assurance deployment
  package.
- Logs and receipts never contain signatures, private-key material, full certificates,
  raw untrusted payloads, or sensitive paths.
