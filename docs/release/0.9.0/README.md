# Haldir 0.9 release qualification (historical ledger)

> **Current-head notice:** this document describes the preceding 120-task
> `T000..T119` qualification program. Its identities and evidence are retained
> unchanged, but they do not close the later 126-task handoff. The authoritative
> current program is the
> [current-head qualification record](../../../release/0.9.0/current-head/README.md),
> whose tasks are `CH-T000..CH-T125` and whose status remains `NO_GO`.

## Historical status

This directory records the earlier Haldir `0.9.0` qualification attempt. It is
historical input to the current program, not the current release decision. NCP
protocol versions remain independent of the Haldir version.

The author is **Sepehr Mahmoudian**. Review and independent-assurance roles are
separate from authorship and must name the actual reviewer before their gates can
close. The initial release intentionally has no persistent archive identifier; one
may be added in a later metadata-only release after the supervisor review.

The historical ledger remains **NO-GO** until every core requirement in
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
- [`t000-verification.json`](../../../release/0.9.0/evidence/t000-verification.json)
  binds the signed implementation commit to successful exact-commit GitHub CI and
  TLA+ runs and their complete retained logs.

## HALDIR-0.9-T001 — normative authority model

The [normative authority contract](AUTHORITY-CONTRACT.md) defines plant-command
creation, identifies `gate` as the sole Haldir principal authorized to create a
plant command in the claimed secure-reference profile, and separates decision
outcomes from semantic plant actions. Its
[`authority-model.json`](../../../release/0.9.0/authority-model.json) mirror is
checked against the deployment profile, retained live ACL matrix, current closed
Rust vocabularies, Gate construction order, and requirement ledger. Complete
mediation and downstream plant effects remain `NOT_CLAIMED`.

[`t001-verification.json`](../../../release/0.9.0/evidence/t001-verification.json)
binds the signed implementation commit to its successful exact-commit CI and
TLA+ runs and to the complete, digest-checked retained logs.

## HALDIR-0.9-T002 — protection model

The [normative protection model](PROTECTION-MODEL.md) closes the default-deny
inventories of protected subjects, exact routes and internal state resources,
actions, authorization constraints, time domains, and trust roots. Its
[`protection-model.json`](../../../release/0.9.0/protection-model.json) mirror is
checked against T001, all eight principals and all seventeen routes in the
secure-reference profile, the nine current role/key-class/object/domain
bindings, the fifteen logical subject/type mappings (including the router), the
closed decision/action vocabularies, and the relevant Rust time, trust, identity,
deployment, durable-state, and evidence semantics. The inventory explicitly
keeps controller/source timestamps out of freshness authority, separates
opaque IDs, boot/epoch-scoped counters, and same-scope cross-boot ratchets,
binds the exact final-command
constraint set and access tuples, and records current implementation
enforcement as `PARTIAL`.

The per-task [migration record](MIGRATION.md) states that T000–T002 introduce no
Rust API or wire conversion while identifying the semantic/operator impact that
must not be guessed. Exact-run closure JSON and complete logical aggregate and
system job logs are generated from
reviewed specifications by
[`generate-task-evidence.py`](../../../tools/release/generate-task-evidence.py),
not hand-edited.

The checked-in generator is introduced by T002. The original T000 and T001
closure JSON and gzip logs predate it and remain byte-for-byte unchanged; they
are not retroactively relabeled as generated. T002 closure adds separately
named `*-generated-*` supplements that bind those historical signed closure
targets/runs to the signed T002 evidence-tool commit, plus the generated T002
record for its exact implementation CI and formal attempts.

## Evidence discipline

Task closure requires a stable SHALL/SHALL NOT requirement, applicable positive and
negative tests, the exact commands and results, immutable source/dependency identity,
a ten-lens review, and a residual-risk statement. External reviews, penetration tests,
and supervisor approvals must be performed by real named people; repository authors
must not manufacture those records.
