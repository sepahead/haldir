# Contributing to Haldir

## Git discipline (normative)

- Work on a focused branch created from a clean base. One cohesive change per branch/PR.
- Run `cargo fmt --all -- --check` and `git diff --check` before every commit.
- **Never** `git push --force`/`--force-with-lease`, rewrite shared history, move tags, or
  `git reset --hard` on an owner worktree.
- Never commit private keys, local absolute paths, captured secrets, proprietary Engram
  content, or device credentials.
- Keep Haldir, NCP, Crebain, and Engram changes in separate commits and separate PRs.

## Evidence-first rule

Behavioral claims must be backed by machine-readable evidence, not prose. Do not commit a
hand-written "passed" summary without the raw test/command output that supports it.

## Coding rules (enforced by lints + tests)

- `#![forbid(unsafe_code)]` in every crate.
- No `unwrap`/`expect`/`panic!`/unchecked indexing on data derived from transport, files,
  authorities, policies, controllers, or plants (allowed only in `#[cfg(test)]`).
- No floating-point values in signed authority, policy, replay, or mission-action contracts.
- No network, filesystem, clock, RNG, or plugin access from the pure policy function.
- No unbounded channel, vector, map, string, parser recursion, retry loop, or evidence queue.
- No `HashMap` where deterministic iteration contributes to a digest or decision (use
  ordered maps / sorted vectors).
- All conversions across units, signs, widths, and clocks use named checked functions with
  property tests.
- Every external dependency is justified in `docs/DEPENDENCY-RATIONALE.md` and pinned in
  `Cargo.lock`.

## Review

Nontrivial changes are reviewed from five lenses: complete mediation & authority; canonical
encoding, signing & replay; time/restart/session/stream/evidence; deterministic fixed-point
policy; and falsifiability/honest-claims. A change that widens a security claim must carry
the evidence that supports the wider claim, or it must be labeled as unproven.
