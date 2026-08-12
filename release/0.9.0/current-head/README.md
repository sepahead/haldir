# Current-head 0.9 qualification

This directory records Haldir's current `0.9.0` qualification program. The
release remains `NO_GO`: no record here grants release, tag, publication,
deployment, archive, DOI, or physical-use authority.

Historical task and recovery artifacts remain immutable evidence of their own
stages. They must not be relabelled as proof for a later source head.

## Active epoch-19 signed-lineage gate

The operator entry point is:

```sh
just verify-current-audit
```

CI invokes the same gate with the exact candidate commit:

```sh
/usr/bin/env -u BASH_ENV -u ENV /bin/bash -p --noprofile --norc \
  tools/release/current-audit-gate.sh <commit>
```

The full gate starts Bash in privileged mode so exported shell functions are not
imported, then uses CPython 3.11 or newer, `/usr/bin/git`, an explicitly resolved
Cargo 1.96.0 executable, the immutable signer root in
`release/0.9.0/allowed-signers`, the current pin verifiers, and the compact
`tools/release/verify-current-lineage.py` state machine. The formal workflow uses
the same entry point's `--lineage-only` mode so it verifies its exact subject
without repeating the full supply-chain suite. Both modes require one-parent
linear commits, exact author and committer identity, equal author/committer
timestamps, and the pinned SSH signer. It also checks the candidate diff for
whitespace errors.

### Why epoch 19 exists

Epoch 18 was active through signed commit
`079a8fd227bdf6476d307f792cfcb070d6fc3a8c`. Pull request #19 was then
squash-merged by GitHub as
`97e0c5dc4baa41e471f8c357b3fe7f0264cf7be8`. That object is linear and
GitHub-verified, but it has author email `Sepehr.Mahmoudian@gmail.com`, committer
`GitHub <noreply@github.com>`, and a GitHub PGP signature. Epoch 18 required
author and committer `Sepehr Mahmoudian <sepmhn@gmail.com>`, equal timestamps,
and the pinned SSH signer, so the commit was outside the active authority
contract.

Epoch 19 does not rewrite, bless, or disguise that breach. Its signed recovery
record names the exact breach commit, parent, tree, subject, and classification.
The recovery commit is the breach's direct child and deliberately bootstraps the
new reviewed verifier. This is an owner-signed trust-root transition, not an
independent review.

### State machine

| Stage | Required commit | State | Authority |
| --- | --- | --- | --- |
| observed breach | exact `97e0c5d…` GitHub squash object | no active epoch-19 recovery | none |
| recovery | direct signed child, exact recovery subject and canonical `FR-0019-recovery.json` | `RECOVERED_PENDING_HOSTED_QUALIFICATION` | none |
| activation | direct signed child adding only canonical `FR-0019-activation.json` | `ACTIVE_NO_RELEASE_AUTHORITY` | none |
| ordinary successor | signed one-parent child; protected lineage/workflow paths unchanged | active signed lineage | none beyond source succession |

Activation binds the exact recovery commit/tree, owner-observed successful main
CI and formal runs, the seven GitHub-Actions-bound required contexts, force-push
and deletion denial, exact merge settings, and the writer ruleset's main-ref,
update-rule, repository-source, and sole owner-bypass shape. Those run and
settings observations are intentionally labelled as mutable external state, not
cryptographic proof or release authority.

The previous FR-0017 verifier, tests, result emitter, signer record, and retained
R/Q/A evidence are frozen historical inputs. They no longer execute on current
successors. After activation, the epoch-19 gate, verifier, signer/record roots,
the complete `.github/workflows/` namespace, result emitter, local `just` entry point, normative
delivery instructions, pin policy/data, cargo-deny installer, and its retained
adversarial suite are one protected governance boundary; changing that boundary
requires another explicit signed recovery transition.

## Hosted workflow authority

Both workflows run on pull requests, `main` pushes, and manual dispatch. Feature
pushes do not trigger a duplicate run.

| Event/ref | Substantive checks | Signed lineage subject | Canonical result | OIDC attestation |
| --- | --- | --- | --- | --- |
| pull request | GitHub merge ref | exact PR head | no | no |
| push to `main` | exact pushed commit | exact pushed commit | yes | yes |
| manual dispatch on `main` | exact selected commit | exact selected commit | yes | no |
| manual dispatch elsewhere | exact selected ref | exact selected commit | no | no |

This split is intentional: testing the merge ref detects integration conflicts,
while separately verifying the PR head prevents a synthetic GitHub merge object
from being mistaken for an authorized source commit. Before candidate-tree audit
tooling runs, each workflow extracts `verify-current-lineage.py` from the exact
PR base or, for push/manual dispatch, from the candidate's sole parent. That
predecessor-trusted blob verifies both revisions. Only after it proves protected
governance paths unchanged may tooling from the candidate checkout run; a
self-modifying verifier cannot authorize its own change on any ordinary event.
The one explicit exception is the epoch-19 recovery bootstrap: its exact breach
parent predates this verifier, and the recovery record already declares that
owner-signed trust-root transition. Current hosted results use
`HALDIR_CURRENT_HOSTED_RESULT_V1`, bind exact source/material objects, and grant
no release or deployment authority.

## Exact delivery protocol

GitHub merge buttons are not authorized for this repository. Review occurs in a
pull request, but delivery is the exact already-reviewed commit object:

1. create a one-parent commit with exact author/committer identity and the pinned
   SSH signature;
2. push the feature branch and open the pull request;
3. let required checks test the merge ref and verify the exact PR head;
4. manually dispatch both workflows on the feature ref and require every
   protected context to pass on the exact head;
5. close the pull request without merging;
6. fast-forward the exact object with
   `git push origin <commit>:refs/heads/main`; and
7. verify `origin/main`, the signature, main CI/formal conclusions, branch
   protection, repository merge settings, and writer-allowlist ruleset after
   delivery.

No amend, squash, rebase, cherry-pick, merge commit, or force push is permitted
between review and delivery. See [CONTRIBUTING.md](../../../CONTRIBUTING.md).

The repository control plane disables merge and squash and retains rebase only
because GitHub requires at least one merge method. Required signatures, strict
required checks, linear history, admin enforcement, force-push/deletion denial,
and the active `main` writer allowlist remain enabled.

GitHub commit-metadata rules are available only for organization-owned
repositories on GitHub Enterprise. This repository is user-owned, so the hosted
control plane cannot enforce the exact author/committer email contract. The
remaining rebase button can therefore synthesize an unauthorized commit if an
owner ignores this protocol. The exact-head CI check detects that breach but
cannot prevent the web operation from moving `main`; this is an explicit hosted
delivery risk, not a control we claim to have closed.

These controls are mutable GitHub state. The signed verifier and delivery
protocol remain independently reviewable repository truth, but a compromised
owner, signer, or GitHub control plane remains inside the threat model.

## Historical qualification material

The retained CH-T000 inputs bind the original handoffs, source/dependency/NCP
identities, requirement ledger, raw hosted evidence, and resource profile.
`tools/release/verify-current-audit.py` and older recovery/task verifiers are
historical programs, not the active operator entry point.

Earlier task epochs used signed framework/implementation/qualification/
activation transitions and isolated registered verifiers. Their records prove
only their declared historical transitions. Exact inventories and digests prove
object identity, not semantic correctness or completeness.

## Review and publication boundary

Independent cryptographic, formal-methods, secure-deployment, clean-room, and
final lead review requirements remain open. Automated checks do not establish a
reviewer's real-world identity or organizational independence. No tag or GitHub
Release is authorized until the current requirements, external review,
cross-repository qualification, and signed release ceremony are truthfully
complete or the associated claims are explicitly removed.
