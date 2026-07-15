# Current-head qualification bootstrap amendment

This amendment preserves the checksum-bound original Git object for
[`HANDOFF-ERRATA.md`](HANDOFF-ERRATA.md) as an immutable input to the first
current-head manifest. The current-tree publication copy changes only two
review-role phrases to comply with the repository's neutral-language rule; the
signed framework binds that textual delta separately and never substitutes it
for the frozen input object. This amendment records the narrower execution
decision required by the subsequent signed qualification framework. It does not
claim that a missing precondition passed.

## Ledger bootstrap operations

The supplied task chain requires a complete, assigned `FILE_REVIEW_LEDGER.csv`
before every task, while `T001` creates that inventory and `T002` assigns its
reviews. The exception is therefore limited by both task and operation:

- `CH-T000` may freeze the source, handoffs, downstream heads, packages,
  model/data/paper disposition, tools, publication state, and clean baseline
  without a pre-existing ledger. It may not use the exception for
  runtime-source or public-claim implementation work.
- `CH-T001` may generate and reconcile the ledger without pretending that the
  ledger existed before its generator ran. It cannot close until the complete
  inventory has been independently reconciled and retained.
- `CH-T002` may assign and review the completed `CH-T001` inventory without
  pretending that its assignments existed before assignment began. It cannot
  close until every in-scope file has the required explicit assignment and
  review evidence.

This is permission to perform the bootstrap operations, not evidence that their
postconditions passed. The complete ledger and assignments are mandatory before
`CH-T003` can close. The exception does not transfer to `CH-T003` or any later
task.

## CH-T000 retrospective process amendment

The supplied `T000` procedure also requires a repository-wide line-by-line
review and requires the behavior packet and normative cases to be approved
before implementation. Those temporal requirements were not literally met for
the first current-head manifest commit. They are amended, for `CH-T000` only,
as follows:

- the complete repository-wide line-by-line review is deferred to `CH-T001`
  and `CH-T002` and remains a hard blocker for `CH-T003`;
- `CH-T000` must instead review every changed line in the input-freeze and
  qualification-framework implementations, every retained binary by bounded
  parser and exact identity, and all relevant unchanged manifest, gate,
  workflow, trust, and requirement context;
- the missing pre-edit behavior, claim, assumption, consumer, rollback, and
  normative-control packet must be reconstructed from immutable pre-edit Git
  objects and clearly labelled retrospective;
- the retrospective packet is approved only by the signed qualification
  framework and qualification commits that bind its exact control content; no
  earlier timestamp or stable ID alone counts as approval; and
- exact-commit checks and independent automated review of the qualification
  framework must exist before a later data-only activation may mark `CH-T000`
  terminal.

These clauses amend the impossible chronology; they do not say it was
satisfied. They do not waive any technical acceptance case, twenty-lens review,
evidence requirement, dependency, external approval gate, or release gate. The
residual limitation is permanent: retrospective reconstruction proves the
resulting technical record, not what was known before the first edit.

## Human and release boundary

All lead and supporting reviews in this bootstrap may be automated. They must
remain labelled non-human and without external approval authority. This
amendment grants no release, deployment, publication, security-certification,
or field-validation authority.
The overall release state remains `NO_GO`.
