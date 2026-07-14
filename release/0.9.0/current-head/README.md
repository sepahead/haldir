# Current-head 0.9 qualification

This directory records the implementation program derived from the
`2026-07-14` Haldir current-head maximum-effort handoff. The supplied handoff
froze commit `9cf56e149a105026b072c9073d7e87b93103966e`. Before this program began,
`main` had advanced by one documentation checkpoint to
`2bfcabe5bf9fd6c428f7d50132bd36ec4e147438`; the exact intervening diff is
therefore part of the updated audit cut rather than being silently accepted.

The release label is `0.9.0`, as requested for supervisor review. The author is
Sepehr Mahmoudian. No DOI, Zenodo record, or other persistent archive identifier
is assigned in this release program.

Earlier files directly under `release/0.9.0/` are retained as immutable
historical evidence from the preceding qualification program. Their task IDs
must not be relabelled as evidence for the current 126-task handoff. Current
artifacts are bound to their source and requirement identity through
[`audit-inputs.json`](audit-inputs.json) and the current-head requirement ledger;
raw logs do not make independent identity claims.

The retained, checksum-bound inputs include the
[Haldir handoff](handoff/HALDIR_V1_0_CURRENT_HEAD_MAX_EFFORT_HANDOFF.zip), the
[cross-repository handoff](handoff/SEPAHEAD_V1_0_CURRENT_HEAD_CROSS_REPO_RECONCILIATION_HANDOFF.zip),
the master head/index records, the exact local baseline, and raw GitHub CI and
formal-run evidence. Verify the cut offline with:

```sh
python3 tools/release/verify-current-audit.py
python3 -m unittest tools/release/test_verify_current_audit.py
```

`CH-T000` remains open until this manifest has its own signed implementation
commit, exact-commit checks, and a separately signed closure record. A signed
source checkpoint alone is not closure evidence for a newly created manifest.

The release remains `NO_GO` until the current requirements, evidence, review,
cross-repository qualification, and release ceremony are truthfully complete or
the associated optional claims are explicitly removed.
