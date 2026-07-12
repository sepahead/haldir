# ADR-0007 — In-process P0 scope; durable storage and live transport deferred

Status: accepted

## Context

A reference monitor for a real vehicle needs live secure transport with an
exclusive publisher capability, crash-durable anti-rollback and evidence, a real
neural-backend admission story, and hardware validation. Building all of that at
once buries the one thing worth proving first — that the contract/state/policy
conjunction is correct — under integration risk, and tempts overclaiming.

## Decision

Scope this repository to **P0 `assurance-reference-v1`**: one vehicle, one
controller, one Gate, a deterministic reference plant, `Hold` + local-NED
velocity, entirely in-process. Live transport and the ACL-exclusive publisher are
*modeled* behind typed seams, not run. Durable authenticated storage and a
tamper-evident signed evidence journal (H-B03) are deferred to P1; P0 keeps
anti-rollback and the evidence spool in-process (the spool is lossy on overflow).
No neural runtime, timing, or hardware claim is made.

## Consequences

- What P0 proves is small and honest; what it defers is named, not hidden.
- The deferrals are enumerated as claims (`CL-DURABLE-01`, `CL-LIVE-TRANSPORT-01`,
  `CL-BACKEND-01`, `CL-HARDWARE-01`, `CL-TIMING-01`) marked UNPROVEN or out of
  scope, and `tools/verify-claims.py` guards the authored docs against drifting
  into affirmative versions of them.

## Evidence

`docs/ASSURANCE-PROFILES.md`, `docs/LIMITATIONS.md`, `docs/CLAIM-LEDGER.md`.
