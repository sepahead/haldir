# Owner decision, 23 October 2026

The owner authorized breaking changes in Haldir and gave full repository permissions for maintenance work on 23 October 2026.

## Decision

Refresh the pinned RustSec advisory snapshot through the owner-signed epoch-21 lineage transition, before the freshness rule rejects the old snapshot on 27 October 2026 at 15:17 UTC.

## Scope

- The snapshot identity in `tools/pins.toml`, the supply-chain job of `.github/workflows/ci.yml`, its reviewed digest and fragments in `tools/verify-ci-pins.py`, and the recorded measurement in `tools/test_pinned_cargo_deny.py`.
- The reviewed `RUSTSEC-2024-0449` exception in `deny.toml`.
- The documentation of these changes.

## Not authorized by this decision

Release, tag, deployment, or any wider claim.
