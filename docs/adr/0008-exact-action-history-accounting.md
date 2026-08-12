# ADR-0008 — Exact, validated action-history accounting

Status: accepted; supersedes ADR-0005

## Context

ADR-0005 chose the right bounded representation for non-Hold command horizons:
a disjoint interval union with conservative closest-gap compression. It did not
fully specify interval boundaries, numeric precision, ownership of the rolling
window, validation of retained state, or the distinction between a policy-limit
DENY and a broken accounting invariant.

Those omissions permitted a fail-open boundary. Flooring each retained interval
to whole milliseconds before summation can erase fractional activity. For
example, `5_900_000_001 ns` of retained charge plus a `100 ms` candidate is one
nanosecond over a `6_000 ms` cap, but per-interval flooring reports equality and
allows it. Publicly mutable history and a caller-supplied eviction cutoff also
made the claimed canonical, bounded union unenforceable.

## Decision

Retain ADR-0005's union and conservative compression, with these stricter
semantics:

1. A charged horizon is a non-empty half-open interval `[start, end)`. History
   state is private and exposed read-only. Construction requires a nonzero exact
   retention window and a capacity in `1..=64`.
2. The history owns the policy retention window and derives eviction cutoffs
   internally. Every record operation is fallible and transactional. A
   publication high-water mark survives lease-boundary slew-reference resets,
   preventing chronological rollback.
3. Validation rejects zero/reversed or future-start intervals, unsorted,
   overlapping or touching noncanonical unions, capacity violations, inconsistent
   slew/high-water/motion state, future records, and policy-window mismatch. An
   interval end after evaluation time is valid and remains part of prospective
   accounting.
4. The evaluator forms an exact union of (a) every retained horizon clipped only
   at the owned trailing-window start and (b) the candidate half-open interval
   `[now, now + candidate)`. It does not clip retained horizons at `now`: a
   previously published command's future tail remains chargeable when a shorter
   candidate is wholly contained in it. Candidate overlap is counted once. The
   resulting nanoseconds are compared in widened arithmetic with
   `cap_ms * 1_000_000`; equality is allowed and one nanosecond over denies. When
   capacity suffices, the retained union is exact. Closest-gap compression
   intentionally counts gaps and is conservative; it can over-count, not
   under-count, the original charged intervals.
5. The prospective candidate remains the conservative requested/NCP horizon, not
   the final effective published validity. The effective-validity minimum
   subtracts the publication margin, and byte exposure is bounded by that same
   margin. Therefore, for an ALLOW,
   `candidate >= call_delay + effective_validity` at the latest permitted call,
   so decision-to-call delay cannot create uncharged prospective time.
6. Public evaluators provide typed `try_decide` paths. Invalid action history
   needed for a velocity decision is an internal evaluation error, not
   `DenyDutyLimit`. The integrated Gate fault-latches, signs
   `ErrorInternalFault`, and prepares no output. The legacy infallible evaluator
   remains an explicitly lossy compatibility wrapper.
7. Hold evaluation deliberately does not consult motion-duty history, preserving
   availability of a stop command when that history is malformed. At the
   synchronous in-process reference boundary, a receiver-reported successful
   Hold must transactionally record its exact applied
   `[called_at, active_until)` horizon as well as the publication high-water. A
   newer Hold supersedes the prior horizon end; only overlapping/touching coverage
   preserves the earlier Hold start. If that commit fails, the Gate fault-latches,
   retains `PublishCalled`, returns a typed no-retry error, and cannot issue later
   motion.
8. The publication coordinator locally journals and `sync_data`-confirms a
   publisher-reported success before the synchronous in-process reference
   accounting transition. If accounting then fails, the runtime is consumed and
   the locally confirmed result remains truthful. A declared-live local `Ok`
   cannot drive that transition: NCP v0.8 starts TTL at unobserved plant-local
   arrival, so the live service records ReturnedOk, commits no guessed interval,
   and terminates without later publication authority. Recovery requires explicit
   clearance for every Called-or-later trace, including `ReturnedOk`. This is not
   a power-loss durability, delivery, or application claim.

## Consequences

- Sub-millisecond retained activity and retained future tails cannot disappear at
  the duty boundary.
- Malformed state cannot masquerade as a legitimate controller duty-limit DENY.
- Retained future tails model publication uncertainty even when a newer command
  may supersede them downstream. Together with compression, this can deliberately
  deny early; the claim is exact arithmetic over a conservative retained
  representation, not exact receiver application or physical motion measurement.
- History is boot-local and in-process. The repository does not claim durable
  reconstruction of prior-boot duty; restart remains blocked behind the existing
  Called-or-later clearance rule.
- The experimental pre-1.0 history API becomes intentionally stricter and
  fallible. Public errors are non-exhaustive, have stable codes, implement
  `Display`/`Error`, and source-bearing wrappers preserve available nested
  errors.

## Evidence

`haldir-core` exact/checked duration boundary and conversion tests;
`haldir-policy-native` exact-cap, one-nanosecond-over, fractional-union,
retained-future-tail union, half-open clipping, candidate-overflow,
constructor/window, structural validation, transactional rollback/high-water,
Hold-horizon/supersession, Hold exception, error-chain, widened-reference, and
compression/eviction property tests; `haldir-gate`
`gate_binds_history_capacity_and_window_to_validated_policy`,
`velocity_history_failure_latches_error_and_prepares_no_output`,
`hold_remains_available_but_failed_success_commit_faults_and_retains_called`,
`publisher_ok_history_commit_failure_is_journaled_and_restart_blocked`,
`returned_clock_regression_charges_history_before_faulting`, error-chain tests,
and the configured publication-margin boundary in
`delayed_call_is_rejected_and_reported_failure_blocks_replacement_output`
(`CL-DUTY-01`, `CL-ERROR-01`, `CL-PUBLICATION-STATE-01`).
