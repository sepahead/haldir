# Haldir 0.9 release qualification

## Status

This directory is the normative qualification record for Haldir `0.9.0`, the first
public release. It adapts the supplied Haldir 1.0 implementation handoff to a 0.9
release label without weakening any correctness, security, authority, resource-bound,
or evidence gate. NCP protocol versions remain independent of the Haldir version.

The author is **Sepehr Mahmoudian**. Review and independent-assurance roles are
separate from authorship and must name the actual reviewer before their gates can
close. The initial release intentionally has no persistent archive identifier; one
may be added in a later metadata-only release after the supervisor review.

The release remains **NO-GO** until every core requirement in
[`release/0.9.0/requirements.json`](../../../release/0.9.0/requirements.json) is
verified, every optional unsupported claim is removed and explicitly recorded as
`not_claimed`, and the final clean-commit release ceremony passes.

## HALDIR-0.9-T000 — immutable audit cut

Haldir **SHALL** retain a machine-readable audit manifest that binds the untouched
starting source commit and tree, the complete handoff package by SHA-256, the locked
dependency graph, the NCP protocol pin, toolchains, deployment inputs, retained
evidence manifests, repository publication state, and the complete baseline gate log.

The manifest **SHALL NOT** treat the mutable branch name, a GitHub badge, a tag name,
or a local filesystem path as an immutable identity. A tag identity is acceptable only
when its peeled commit is also recorded. The baseline log **SHALL** be captured before
implementation changes and retained byte-for-byte (deterministically compressed for
the repository).

Evidence:

- [`audit-inputs.json`](../../../release/0.9.0/audit-inputs.json) records the initial
  clean `main` cut at commit `1c8862ec93999506c285c0777c82394ebe8ab409`.
- [`baseline-p0r.log.gz`](../../../release/0.9.0/evidence/baseline-p0r.log.gz) is the
  complete output of `bash tools/p0r-exit-gate.sh` on that untouched commit.
- [`baseline-p0r.json`](../../../release/0.9.0/evidence/baseline-p0r.json) records the
  command, uncompressed digest, byte/line counts, and successful exit status.

## Evidence discipline

Task closure requires a stable SHALL/SHALL NOT requirement, applicable positive and
negative tests, the exact commands and results, immutable source/dependency identity,
a ten-lens review, and a residual-risk statement. External reviews, penetration tests,
and supervisor approvals must be performed by real named people; repository authors
must not manufacture those records.

