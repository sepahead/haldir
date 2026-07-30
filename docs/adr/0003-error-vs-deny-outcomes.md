# ADR-0003 — Separate ERROR (internal fault) from DENY (authorization refusal)

Status: accepted

## Context

A monitor that collapses "I refuse this request" and "I broke" into one negative
outcome hides faults. An operator reading a stream of DENYs cannot tell a
controller misbehaving from the Gate's own clock regressing or its output builder
failing. Both must produce no output, but they mean very different things.

## Decision

Inside `decide_intent`, route every pre-preparation no-output result through a single `respond()` helper keyed on whether
the reason code is an internal-fault code. Authorization refusals (bad signature,
scope mismatch, expired lease, policy denial, rate limit) yield `DecisionOutcomeV1::Deny`
with a `DECIDED_DENY` stage. Internal faults (fault latch, monotonic-clock
regression, an in-decision TOCTOU revision change, NCP build/validate failure, namespace/counter
exhaustion, or malformed action history required by velocity evaluation) yield
`DecisionOutcomeV1::Error` with a `DECIDED_ERROR` stage and an
`ERROR_*` reason. Both paths still sign a receipt and emit no plant command.
Hold evaluation is intentionally independent of motion-duty history so a stop
command remains available; a failure to commit its reported successful
publication still fault-latches under ADR-0008.
Publication-transition failures occur after the signed `AllowPrepared` receipt and
are governed separately by `CL-PUBLICATION-STATE-01`; they do not rewrite that receipt.

## Consequences

- Evidence distinguishes "controller was denied" from "Gate faulted"; the latter
  is actionable operationally.
- Fault reasons latch: once the Gate errors on an invariant break, subsequent
  intents keep erroring until re-provisioned, rather than silently recovering.
- Callers that previously treated every non-ALLOW as DENY must handle ERROR.

## Evidence

`haldir-gate` `respond()` / `is_error()`;
`clock_regression_latches_and_errors`,
`velocity_history_failure_latches_error_and_prepares_no_output`, and
`hold_remains_available_but_failed_success_commit_faults_and_retains_called`
(`CL-ERROR-01`).
