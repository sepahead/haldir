# Threat model

The draft Haldir 0.9 threat model is
[`docs/release/0.9.0/THREAT-MODEL.md`](release/0.9.0/THREAT-MODEL.md)
(`HALDIR-0.9-T003`). This is a review checkpoint, not a verified requirement:
the machine-readable mirror, offline verifier, claim-ledger entry, exact-commit
evidence, and formal-model corrections are still pending.

The model distinguishes forged signatures from possession of a valid stolen
key, and it separates pure-core tests, configuration, bounded synthetic router
evidence, formal evidence, external assumptions, and absent evidence. Listing a
threat does not imply that Haldir mitigates it. All seven aggregate threat
classes are currently `PARTIAL`. The following remain explicitly
`NOT_CLAIMED`: protected credential custody, a stolen Gate transport credential,
authenticated live state/control provenance, external anti-rewind, complete
mediation, availability, plant application, and physical safety.

This pointer replaces the older P0 summary with the reviewed draft. T003 remains
`open`; this checkpoint does not expand the release contract or evidence scope.
