# Contributing to Haldir

## Git discipline (normative)

- Work on a focused branch created from a clean base. One cohesive change per branch/PR.
- Every commit proposed for `main` must be a one-parent SSH-signed commit with
  author and committer exactly `Sepehr Mahmoudian <sepmhn@gmail.com>`, matching
  author/committer timestamps, and the signer pinned in
  `release/0.9.0/allowed-signers`. `just verify-current-audit` checks this contract.
- Open or update a pull request for review and the required CI/formal contexts.
  Substantive tests run against GitHub's merge ref; the supply-chain job
  separately verifies the exact signed PR head. Before candidate-tree audit
  tooling runs, both workflows extract the lineage verifier from the exact
  `main` base on a PR, or from the candidate's sole parent on push/manual
  dispatch, and use that predecessor-trusted blob to verify both revisions. A
  candidate therefore cannot authorize its own verifier or protected-workflow
  changes. The sole exception is the explicitly named epoch-19 recovery
  bootstrap whose breach parent predates this verifier. Direct feature-branch
  pushes intentionally do not start duplicate workflows. Before direct
  delivery, manually dispatch both workflows on the feature ref and require all
  seven contexts to pass on that exact head; pull-request checks attached to a
  synthetic merge ref are not a substitute.
- **Do not use any GitHub merge button.** Merge, squash, and rebase buttons can
  synthesize commits whose committer/signature is GitHub rather than the reviewed
  source signer. After review and exact-head checks pass, close the PR without
  merging and fast-forward the already-reviewed object explicitly:

  ```sh
  git push origin <exact-signed-commit>:refs/heads/main
  ```

  Never recreate, amend, cherry-pick, squash, or rebase the commit between review
  and delivery. Verify the remote object and its checks after the push. GitHub
  commit-metadata rules are unavailable for this user-owned repository, and GitHub
  requires one merge method to remain enabled. The retained rebase button is not
  authorized and is not a security backstop; the exact source-level protocol is
  therefore normative, while hosted settings remain mutable external state.
- Run `cargo fmt --all -- --check` and `git diff --check` before every commit.
- **Never** `git push --force`/`--force-with-lease`, rewrite shared history, move tags, or
  `git reset --hard` on an owner worktree.
- Never commit private keys, captured secrets, bearer tokens, proprietary
  Engram content, production certificates, or device credentials. Normalize new
  developer-host paths unless an exact non-secret path is required by a reviewed
  provenance contract; retained public certificates and historical host-path
  metadata are evidence, not production credentials.
- Keep Haldir, NCP, Crebain, and Engram changes in separate commits and separate PRs.

## Evidence-first rule

Behavioral claims must be backed by machine-readable evidence, not prose. Do not commit a
hand-written "passed" summary without the raw test/command output that supports it.

## Coding rules (enforced by lints + tests)

- `#![forbid(unsafe_code)]` in every crate.
- Document every public Rust item. The workspace `missing_docs` lint is promoted
  to an error by the warning-free CI and documentation lanes.
- No `unwrap`/`expect`/`panic!`/unchecked indexing on data derived from transport, files,
  authorities, policies, controllers, or plants (allowed only in `#[cfg(test)]`).
- No floating-point values in signed authority, policy, replay, or mission-action contracts.
- No network, filesystem, clock, RNG, or plugin access from the pure policy function.
- No unbounded work or retained growth from untrusted input. Runtime authority,
  replay state, channels, histories, retries, parser depth/size, and evidence
  queues must have explicit exhaustion behavior. Caller-owned configuration is
  validated before it becomes authority.
- No `HashMap` where deterministic iteration contributes to a digest or decision (use
  ordered maps / sorted vectors).
- All conversions across units, signs, widths, and clocks use named checked functions with
  property tests.
- Every external dependency is justified in `docs/DEPENDENCY-RATIONALE.md` and pinned in
  `Cargo.lock`.

## Review

Every nontrivial change is reviewed through all twenty lenses below. A reviewer
may mark a lens not applicable only with a concrete reason; silence is not an
`N/A`. A change that widens a security claim must carry evidence for that wider
claim or label it unproven.

1. Authority roots and complete mediation: identify every grant, bypass, and
   side-effect path.
2. Identity, role, subject, key-class, and credential separation.
3. Canonical encoding, closed schemas, versioning, and migration behavior.
4. Cryptographic verification, key validity, secret lifetime, and algorithm
   agility boundaries.
5. Replay resistance, epochs, counters, tombstones, and namespace exhaustion.
6. Clock provenance, freshness, deadlines, regressions, and restart time.
7. Durable ordering, rollback, fork detection, crash recovery, and ambiguous
   commits.
8. Side-effect ordering, cancellation, retries, idempotency, and exactly-once
   claims.
9. Ownership, concurrency, races, task lifecycle, and shutdown behavior.
10. Resource exhaustion: bytes, counts, allocation, CPU, I/O, queues, labels,
    and adversarial work amplification.
11. Arithmetic, units, rounding, numeric domains, overflow, and precision loss.
12. Policy semantics, authority intersections, state transitions, and denial
    completeness.
13. Transport routes, locality, ACLs, sessions, peer identity, and credential
    custody.
14. Plant dynamics, validity, supersession, failsafe behavior, and actuator
    bypasses.
15. Evidence provenance, exact-byte correlation, stage vocabulary, and loss
    semantics.
16. Deployment configuration, artifact identity, executable selection, and
    supply-chain closure.
17. API misuse resistance, capability construction, visibility, compatibility,
    and source breaks.
18. Observability, bounded diagnostics, operator recovery, and failure
    classification.
19. Tests, independent oracles, fault injection, formal models, performance,
    and falsifiability.
20. Claim accuracy, limitations, research validity, release authority, and
    delivery governance.
