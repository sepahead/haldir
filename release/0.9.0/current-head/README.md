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

## Active epoch-18 audit gate

The canonical operator entry point is:

```sh
just verify-current-audit
```

The underlying command, also used by the supply-chain CI job and the P0 exit
gate, is:

```sh
/usr/bin/env -u BASH_ENV -u ENV /bin/bash --noprofile --norc \
  tools/release/current-audit-gate.sh
```

The gate requires CPython `3.14.6`, a `rustup`-managed Cargo `1.96.0`,
`/usr/bin/git`, and the exact GitHub CLI `2.96.0` executable identity pinned by
`tools/release/verify-framework-recovery-fr-0017.py`. The pinned GitHub CLI
artifacts support Linux amd64 and macOS arm64. On macOS, an exact executable at
a nonstandard path may be selected with `HALDIR_FR0017_GH`; on Linux that
variable is reserved for the CI runner's pinned extraction path. Tool
acquisition is outside the gate and may require network access; verification of
the retained Sigstore bundles is forced offline once the exact executable and
bundled trust root are present.

A pass directly verifies the signed FR-0015 active boundary, the intervening
signed linear milestones, and the signed but unqualified FR-0016 repair
boundary. It then verifies the exact FR-0017 repair, qualification, and
activation sequence; commit signatures and linear first-parent ancestry; source
and CI pins; retained hosted-result attestations; and that checked
post-activation successors do not change a protected path. It requires the
checked-out `HEAD` to have exactly one parent and checks the immediate commit
diff for whitespace errors.

That result is intentionally narrow. Epoch 18 does not execute the retired task
verifiers, semantically qualify the implementation in an ordinary successor,
prove mutable GitHub settings at the current head, or grant release,
publication, deployment, tag, archive, DOI, or GitHub Release authority. The
release remains `NO_GO`.

## Historical CH-T000 input cut and verifier

The retained, checksum-bound CH-T000 inputs include the
[Haldir handoff](handoff/HALDIR_V1_0_CURRENT_HEAD_MAX_EFFORT_HANDOFF.zip), the
[cross-repository handoff](handoff/SEPAHEAD_V1_0_CURRENT_HEAD_CROSS_REPO_RECONCILIATION_HANDOFF.zip),
the master head/index records, the exact local baseline, raw GitHub CI and
formal-run evidence, and the bounded resource profile.

`tools/release/verify-current-audit.py`, its legacy test suite, and
`tools/release/current-audit-resource-profile.py` are retained historical
programs. They are not the active operator entry point and are deliberately
inert at epoch 18. Historical resource-profile reproduction must write only to
untracked scratch space, such as `target/`; it must never replace
`evidence/ch-t000-resource-profile.json` or any other retained evidence file.

## Retired task-qualification framework

CH-T000 and the later task epochs used a signed `F → I → C → D` lifecycle:
framework/freeze, implementation, qualification, and data-only activation.
Their append-only registry walked adjacent signed commits, ran registered task
verifiers, maintained active claims, and supported a typed `R` revocation
transition. Registered verifiers were reviewed executable inputs, but their
structural restrictions and signed identities did not prove their assertions
semantically honest.

That retired framework ran registered programs in a digest-pinned, read-only,
network-disabled Linux container over an isolated exact Git clone. Its
clean-Linux reproduction and container-containment statements describe the
historical CH-T000 protocol only. The epoch-18 bridge instead executes directly
on the host with a sanitized environment, pinned executable identities, bounded
subprocess time and output, and protected-worktree checks. It claims no general
host-resource containment.

The historical task, review, revocation, and active-claim records remain
evidence of those earlier transitions. They do not establish that epoch-18
ordinary successors follow the retired lifecycle or have passed its registered
verifiers.

## Epoch-18 trust and recovery boundary

Epoch 18 accepts only signed, linear, scoped milestones after activation.
Protected workflow, signer, recovery, gate, pin, and attestation paths cannot be
changed by an ordinary successor. A necessary change requires a separately
reviewed, intentional signed gate and trust-root replacement protocol.

The retained branch-protection record is a TLS-observed snapshot of mutable
external state, not durable cryptographic proof. The trusted source signer and
repository owner remain inside the threat model; owner-account or GitHub
control-plane compromise is outside the active guarantee.

On suspected signer, owner-account, or GitHub control-plane compromise, stop all
release, tag, publication, and deployment activity. Preserve existing evidence,
do not regenerate or re-sign records, and treat gate results as
non-authoritative until a separately reviewed trust-root replacement protocol
has established a new boundary.

## Review and publication boundary

The current requirement ledger still marks the independent cryptographic,
formal-methods, secure-deployment, and clean-room review tasks `CH-T115` and
`CH-T120` as `OPEN`. Final lead review (`CH-T124`) and the signed
release-authority decision (`CH-T125`) are also `OPEN`. Automated review records
do not satisfy those human and external-review requirements.

Key separation, deterministic checks, and detached signatures do not establish
a reviewer's real-world identity, organizational independence, or independence
from a shared host or operator. Likewise, exact file inventories and digests
prove object identity, not the semantic correctness or completeness of the
declared consumers and effects.

The release remains `NO_GO` until the applicable requirements, evidence,
independent review, cross-repository qualification, and release ceremony are
truthfully complete or the associated optional claims are explicitly removed.
No tag or GitHub Release is authorized while that state persists. DOI, Zenodo,
and other archive fields remain absent or null throughout this 0.9 preparation
program.
