# Current-head handoff errata and execution decisions

These decisions are part of the lead-approved audit cut. They resolve conflicts
that otherwise make the supplied current-head handoff impossible to execute
without either overwriting evidence or pretending that a circular precondition
has already passed.

## Task identity

The repository already contains a 120-task Haldir 0.9 qualification ledger whose
identifiers are `T000` through `T119`. The supplied current-head handoff contains
126 tasks also named `T000` through `T125`. None of the 120 overlapping task
titles are equal. In particular, the repository's existing `T003` is the threat
model, while the handoff's `T003` is the public-surface and claim-tier inventory.

The handoff tasks are therefore represented in this repository as `CH-T000`
through `CH-T125` (`CH` means current-head handoff). Each record retains the
original task ID. Historical evidence may be cited as an input, but its task
identity or closure status must never be transferred to a `CH-*` task. A
machine-readable crosswalk must preserve both namespaces.

## Release label

The handoff's proposed target is `1.0.0`. This implementation program uses
`0.9.0` for the first supervisor-review release. This is a narrowing of release
status, not a waiver of any correctness, security, evidence, or claim gate. The
author is Sepehr Mahmoudian. DOI and Zenodo metadata are intentionally absent.

## Updated audit cut

The handoff froze `9cf56e149a105026b072c9073d7e87b93103966e`.
At entry, clean local and remote `main` were
`2bfcabe5bf9fd6c428f7d50132bd36ec4e147438`, exactly one commit later. The
intervening commit changes `docs/THREAT-MODEL.md` and adds
`docs/release/0.9.0/THREAT-MODEL.md`; it explicitly describes itself as an
incomplete checkpoint. The lead recorded the complete diff, regenerated the
283-file/5,562,467-byte inventory, and reran the full baseline before approving
`2bfcabe5bf9fd6c428f7d50132bd36ec4e147438` as the updated starting cut. The
checkpoint's open work remains open.

## Bootstrap precondition

Every supplied handoff task, including original `T000`, says that a complete
`FILE_REVIEW_LEDGER.csv` and reviewer assignment must already exist. Original
`T001` and `T002` are the tasks that create and assign that ledger, so literal
application is circular.

For `CH-T000` only, the impossible file-ledger precondition is deferred to
`CH-T001` and `CH-T002`. `CH-T000` may freeze the source, master and child
handoffs, downstream heads, workspace packages, model/data/paper disposition,
tools, publication state, and clean baseline. No source or public-claim
implementation work may use that exception. `CH-T001` must produce the complete
inventory, and `CH-T002` must complete explicit file assignments and reviews
before `CH-T003` can close.

## Dependency and concurrency rule

The supplied ledger is a strict single chain: every task after the first depends
on the immediately preceding task. Subagents may prepare independent review,
counterexample, or test evidence in parallel, but task closure and integration
must follow `CH-T000` through `CH-T125` in order. The three advertised lanes do
not override those dependencies.

## Scaffold limitations

The supplied repository-work scripts are input scaffolding, not release gates:

- the tracked-file auditor omits mandated fields and does not reconcile
  filesystem-only, ignored, generated, symlink, binary, provenance, or license
  inputs;
- review-packet balancing ignores criticality, binary review effort, and
  independence;
- claim scanning omits public configuration, package, workflow, schema, and
  source surfaces;
- evidence verification permits an empty manifest and lacks schema, duplicate,
  containment, symlink, and signature controls;
- the frozen-head check omits origin, tree, submodule, signature, tool, package,
  and external-pin identity;
- the supplied convergence schema hard-codes the pre-edit source commit and does
  not require reviewed-file equality, the exact task set, typed waves/evidence,
  or removed-claim dispositions.

Repository-native replacements must correct these gaps before their respective
tasks can close.

## Human review boundary

Automated agents may supply additional review lanes, but they are not represented
as the supervisor or as an independent human security, cryptography, formal, or
deployment reviewer. Any such gate remains pending or its associated strong
claim is removed until a real named reviewer acts.
