# Current-head 0.9 qualification

This directory records the implementation program derived from the
`2026-07-14` Haldir current-head maximum-effort handoff. The supplied handoff
froze commit `9cf56e149a105026b072c9073d7e87b93103966e`. Before this program began,
`main` had advanced by one documentation checkpoint to
`2bfcabe5bf9fd6c428f7d50132bd36ec4e147438`; the exact intervening diff is
therefore part of the updated audit cut rather than being silently accepted.

The release label is `0.9.0`, as requested for external review. The author is
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
python3 -I tools/release/test_verify_current_audit.py
python3 -I tools/release/test_current_audit_resource_profile.py
python3 -I tools/release/verify-current-audit.py
```

The verifier requires CPython `3.14.6`; the hosted supply-chain job installs
that exact version through an immutable action commit before running the gate.
The same sequence is wired into `just verify-current-audit`, the supply-chain CI
job, and `tools/p0r-exit-gate.sh`. The resource profiler can also be run in
isolation; it records direct exact-limit and one-unit-over samples for every
declared byte and JSON-structure boundary primitive, while lifecycle timeout
and composition behavior remains the responsibility of the exact verifier test
suite:

```sh
python3 -I tools/release/current-audit-resource-profile.py \
  --output release/0.9.0/current-head/evidence/ch-t000-resource-profile.json
```

## Signed qualification lifecycle

`CH-T000` uses three signed commits after the frozen implementation checkpoint.
The framework commit installs the verifier while every task remains `OPEN`; the
qualification commit binds the exact implementation, evidence, reviews, and
resource profile; the data-only activation commit is the first commit allowed
to mark `CH-T000` terminal. A source or framework checkpoint alone is never
closure evidence.

Every later task and requalification epoch follows one linear signed
`F → I → C → D` transition on the first-parent history:

- `F` appends one epoch registration, its immutable task verifier and tests, a
  freeze contract, and the exactly rendered CI/Just/P0 integration blocks.
- `I` is one signed implementation commit whose changed paths and statuses must
  exactly equal the frozen implementation plan.
- `C` adds the qualification record and its exact evidence and review files. It
  binds the detected `F` and `I` commits; no artifact is required to contain its
  own not-yet-known commit identifier.
- `D` adds the activation record, bounded verifier receipt, activation evidence,
  requirement-ledger transition, and derived active-claim transition. It binds
  `F`, `I`, and `C`, and is detected as the signed commit that first contains
  those exact files.

Epoch-qualified artifacts live under
`tools/release/tasks/ch-tNNN/eNNNN/` and
`release/0.9.0/current-head/tasks/ch-tNNN/eNNNN/`. The append-only registry,
revocation ledger, and active claim state live under `closures/`. The framework
walks every adjacent signed commit, so a protected file cannot be changed and
later restored to evade review. Registered verifiers execute centrally with
ten seconds per invocation, 7,680 aggregate seconds per history walk, and
bounded output. Triggered verifiers run during the walk and every still-active
verifier is forced once against the final head. Each transition must preserve
the exact rendered integration state.

## Verifier trust and upgrade boundary

Registered Python verifiers and their tests are signed and reviewed executable
inputs. A structural scanner restricts their imports and module shape, and a
trusted parent runner owns the result handshake, but those controls do not prove
that a registered program's assertions are semantically honest. That remains a
code-review and evidence boundary.

The programs run as an unprivileged user in a digest-pinned, read-only,
network-disabled Linux container over an isolated exact Git clone. Host-side
execution is restricted to pinned Git, `ssh-keygen`, and Docker commands; the
live worktree, its private Git directory, and any shared Git common directory
are checked for mutation. The local Docker daemon, its socket, and the account
running the gate remain trusted. Endpoint, daemon, image, socket, container ID,
and teardown state are bound and rechecked, but a compromised daemon can defeat
the container boundary.

The independent clean-Linux reproduction is a second attempt-1 GitHub-hosted
run, manually dispatched only after the exact-head push CI run has completed.
It executes the same full gate in a fresh checkout and retains its own raw run,
attempt, and log records. This separates the reproduction from the push event
without presenting either automated run as human review or platform
attestation.

The source-cut signing key and `allowed-signers` file are immutable protocol
roots. There is no in-protocol key rotation: loss or compromise requires
withdrawing this framework, establishing a new signed baseline, and rerunning
the full qualification. Successor tasks likewise cannot edit the exact CI,
Just, P0, wrapper, signer, or central-verifier paths. A necessary framework
upgrade must use the same signed rebaseline and full-qualification path, not an
ordinary `F → I → C → D` task.

An `R` transition may revoke any verified task. It appends a typed revocation,
restores the last valid contiguous prefix, reopens the entire dependent suffix,
rolls back claims and release authority, and requires fresh monotonically
increasing epochs before those tasks can become terminal again. Revocation can
never authorize a tag, release, DOI, archive, or deployment.

## Review and publication boundary

Every task requires an independent review record that identifies the exact
evidence and diff reviewed. Controls must be accepted before implementation.
For every non-special task, a technically distinct automated reviewer may
satisfy that record only where the exact frozen contract permits it and the
record states that the review is non-human and grants no publication or
deployment authority. `CH-T000` is limited to the narrower retrospective
bootstrap process defined by the qualification amendment.

Each `F` contract freezes the reviewer requirement, identity, principal, public
key, actual key fingerprint, role, path, and stated trust basis. Independent
identities are checked out of band before `F`; later detached signatures are
purpose-bound to the task, epoch, `F`/`I` commits, review kind, complete file
record, decision, and timestamps. The registry records that trust decision but
does not independently prove a person's real-world identity.

The frozen affected-surface inventory covers every planned path, its status,
claim relevance, and in-repository and external consumers. Every review must
cover that inventory and its declared consumer context. Deterministic checks
prove inventory completeness and object identity; whether the declared
consumers and semantic effects are correct remains an explicit review judgment.
Qualification limitations must retain the complete cumulative union of prior
limitations, selected-outcome limits, review limits, unresolved finding
dispositions, and every twenty-lens residual. Revocation restores the earlier
union; no later task may silently discard it.

Automated reviews do not satisfy `CH-T115`, which requires real named
independent cryptographic, formal-methods, and secure-deployment reviewers, or
`CH-T120`, which separately requires real named external clean-room validation.
`CH-T124` requires both its independent review and the designated program
lead's recorded disposition, and `CH-T125` requires Sepehr Mahmoudian's signed
release-authority decision. Until each applicable boundary is truthfully
satisfied, that task and its dependent suffix remain `OPEN`.

The release remains `NO_GO` until the current requirements, evidence, review,
cross-repository qualification, and release ceremony are truthfully complete or
the associated optional claims are explicitly removed. No tag or GitHub Release
is authorized while that state persists. DOI, Zenodo, and other archive fields
remain absent or null throughout this 0.9 preparation program.
