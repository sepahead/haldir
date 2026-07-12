# ADR-0003 — Separate ERROR (internal fault) from DENY (authorization refusal)

Status: accepted

## Context

A monitor that collapses "I refuse this request" and "I broke" into one negative
outcome hides faults. An operator reading a stream of DENYs cannot tell a
controller misbehaving from the Gate's own clock regressing or its output builder
failing. Both must produce no output, but they mean very different things.

## Decision

Route every no-output result through a single `respond()` helper keyed on whether
the reason code is an internal-fault code. Authorization refusals (bad signature,
scope mismatch, expired lease, policy denial, rate limit) yield `DecisionOutcomeV1::Deny`
with a `DECIDED_DENY` stage. Internal faults (fault latch, monotonic-clock
regression, TOCTOU revision change, NCP build/validate failure, namespace/counter
exhaustion) yield `DecisionOutcomeV1::Error` with a `DECIDED_ERROR` stage and an
`ERROR_*` reason. Both paths still sign a receipt and emit no plant command.

## Consequences

- Evidence distinguishes "controller was denied" from "Gate faulted"; the latter
  is actionable operationally.
- Fault reasons latch: once the Gate errors on an invariant break, subsequent
  intents keep erroring until re-provisioned, rather than silently recovering.
- Callers that previously treated every non-ALLOW as DENY must handle ERROR.

## Evidence

`haldir-gate` `respond()` / `is_error()`; `clock_regression_latches_and_errors`
(`CL-ERROR-01`).
