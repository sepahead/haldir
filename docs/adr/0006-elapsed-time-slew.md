# ADR-0006 — Elapsed-time slew bound, capped at the nominal update period

Status: accepted

## Context

The slew check bounds how much a commanded velocity may change from the last
published command, modelling the vehicle's acceleration limit. The original
implementation used a static nominal update period for the time delta regardless
of how much time had actually passed. When commands arrive faster than nominal,
that grants a full nominal step of change over a shorter real interval — a change
the vehicle cannot physically achieve (H-P01). Using the raw elapsed time with no
cap has the opposite hazard: after a long gap the bound grows without limit, so a
stale reference would permit an arbitrary jump.

## Decision

Bound the change by `slew_limit * elapsed_ms / 1000`, where `elapsed_ms` is the
actual monotonic time since the last published command, floored (a shorter
interval permits a smaller change), zero on a clock regression, and capped at
`nominal_update_ms`. Below the cap the bound tracks real elapsed time, closing the
fast-burst hole; at or above it the bound is the conservative nominal envelope,
avoiding the unbounded-gap hazard. A hold sets the reference to zero velocity at
the hold instant, so a velocity command after a hold must ramp up from rest rather
than skip the check (the previous code cleared the reference to none).

## Consequences

- Command streams faster than nominal are correctly tightened; normal-cadence
  streams are unchanged; a stale reference can never grant an unbounded step.
- The bound after a legitimately slow interval stays at the nominal envelope
  (conservative) rather than expanding — accepted as fail-closed.
- The slew reference is cleared at every lease boundary (accept and revoke), so a
  new lease never inherits the previous mission's last-published velocity. The
  first velocity command of a lease (and the first per gate boot) therefore has no
  reference and is bounded only by the absolute component/norm/speed caps — the
  vehicle's true velocity at lease start is not known to the Gate, and that first
  published command establishes the reference for subsequent slew checks.

## Evidence

`haldir-policy-native` `slew_elapsed_ms` / `slew_ok`;
`slew_bound_tracks_actual_elapsed_time`, `hold_sets_slew_reference_to_rest`
(`CL-SLEW-01`).
