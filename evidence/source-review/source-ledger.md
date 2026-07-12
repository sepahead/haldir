# Source ledger (P0 baseline)

Recorded for the P0 deliverable. The specification requires re-running the full
organization inventory before any integration release; that (and the private
owner-visible inventory) is out of P0 scope.

## Haldir

- repository: `git@github.com:sepahead/haldir.git`
- base branch: `main` (reviewed commit `2ad8058d2665dabf22e5943d0cdf7aac6f4d1c30`)
- work branch: `feat/haldir-gate-core`

## NCP baseline (immutable, pinned)

- tag: `v0.8.0`
- commit: `2f5bd586d4bb20c90362bb6f5698b7f64057ba4e`
- wire: `0.8`; contract hash: `d1b50a2d8a265276`
- `proto/ncp.proto` sha256: `6f13b12cff76e12fef384f691d11e2944db1f676568c3e780d3f975689131227`
  (measured locally 2026-07-12 from the tagged worktree)
- capability profile: `PRE_AUTHORITY_ACL_ONLY`

## Toolchain

- rustc/cargo `1.96.0`, edition 2024, `forbid(unsafe_code)`.
- crypto: `ed25519-compact` 2.2, `sha2` 0.10, `zeroize` 1, `subtle` 2, `getrandom` 0.2.
- test: `proptest` 1. All available offline in the reviewed cache.

## Consumer repositories (recorded, not audited in P0)

Crebain, Galadriel, Prisoma, pid-rs, Engram, Manwe, Cortexel, and the atlas/data
repositories are present in the local workspace but are **not** part of the P0
trusted computing base and were not audited or modified here (see
`docs/LIMITATIONS.md`). The specification's `repository-classification.csv` and the
full inventory are release-gate deliverables, out of P0 scope.
