# Security policy

## Status

Haldir Gate is an **experimental research implementation**. It has **not** been
through an independent security review, penetration test, or certification. Do
**not** deploy it to control any physical vehicle or actuator. There is **no
production-use status**.

## Reporting a vulnerability

Use GitHub's
[private vulnerability report](https://github.com/sepahead/haldir/security/advisories/new)
instead of a public issue. Include the exact commit, affected crate/module and
line range, a minimal sanitized reproducer, and the security impact, including
the affected `A#/S#/T#/P#/F#` invariant when applicable. Do not include live
secrets, private keys, bearer tokens, device credentials, or production data in
the report.

## Scope of the security claim

The proven mediation claim is `CL-GATE-MEDIATION-01`: **within the in-process P0
route, an unauthorized, misscoped, replayed, or malformed intent does not
produce an accepted reference-plant command.** This is not complete mediation
of a deployed vehicle. Haldir does **not** establish that a neural controller is
safe, authenticate untrusted sensors merely by hashing them, replace PX4/plant
failsafes, or provide plant authority, wire `publisher_id` binding, or the
applied/stop acknowledgements deferred by NCP `v0.8.0`.

## Handling of secrets

- No private-key material, reusable credentials, bearer/OIDC tokens, production
  certificates, or device credentials are intentionally committed.
- Signed release evidence intentionally retains public Sigstore certificates
  and signatures. Synthetic secure-Zenoh evidence retains ephemeral test-PKI
  subjects and fingerprints, but not the generated private keys. These records
  are public verification material, not production credentials or deployment
  proof.
- Historical and qualification records may retain exact non-secret host and
  tool paths. New evidence must normalize developer-host paths unless their
  exact identity is required by a reviewed provenance contract.
- New runtime logs and decision receipts must not contain private keys,
  reusable secrets, raw untrusted payloads, operational certificates, or
  sensitive runtime paths. Public signatures in signed receipts are evidence,
  not secret material.
- The repository provides no production secret loader, protected credential
  custody, assurance deployment, or production-use authorization.
