# Research protocol (falsifiable hypotheses)

The initial program tests these hypotheses. The P0 core addresses H1–H4 within the
in-process profile; H5 (backend-aware admission) is future work.

- **H1 — Mediation:** within the declared profile, no ordinary controller path
  causes a plant action without a Gate decision.
  *P0:* the reference plant has one command ingress and only Gate-authored commands
  derived from one self-consistent exact NCP frame are accepted; command-related
  model events retain one atomic exact-object session/output/source/digest
  correlation. The output digest binds source epoch/sequence in both profiles;
  NCP v0.8 JSON has no `source_key` field, so that key is in-process correlation
  only in the exact profile (`CL-REFERENCE-PLANT-CORRELATION-01`). `range::*`
  shows every unauthorized intent yields zero application.
  *Deferred:* live-transport bypass campaign (needed for the full A1/A2 claim).
- **H2 — Authority separation:** controller restart/handoff/replay, stale session,
  or stale mission authority cannot seize or refresh the Gate-owned output stream.
  *P0:* two-phase replay, retired epochs, output-stream never reused, session-pair
  scope, deterministic distinction between an exact duplicate and a conflicting
  frame at the latest accepted output position (with older positions rejected as
  stale), and restart invalidates the lease via a fresh boot id
  (state + Gate/reference-plant tests; `CL-REFERENCE-PLANT-CORRELATION-01`).
- **H3 — Transparency:** for allowed requests, Gate preserves the requested
  semantic action within a defined conversion relation and within the deadline
  model. *P0:* `FIXED_POINT_TO_NCP_FLOAT_V1` with proptest round-trip proofs;
  end-to-end allow drives the plant to the commanded velocity; and the reference
  plant applies only complete validity-covered ticks while bounding integer
  velocity change by Euclidean vector magnitude
  (`CL-REFERENCE-PLANT-DYNAMICS-01`).
- **H4 — Fail-closed:** malformed input, policy error, state staleness, fault, and
  overload create no plant-affecting authorization. *P0:* all deny paths produce no
  output; `FAULT_LATCHED` is terminal; corrupt anti-rollback → fault; evidence
  outage never flips a decision.
- **H5 — Backend-aware admission:** the declared bundle/backend evidence predicts
  held-out action behaviour better than a package hash. **Not attempted in P0**
  (no neural runtime; admission is digest-equality only). See `docs/LIMITATIONS.md`.

## Research questions (for the full program, mostly future)

RQ1 residual authority; RQ2 authority composition without overlap under
replay/restart/handoff; RQ3 backend-aware identity; RQ4 operational cost at
20–50 Hz; RQ5 evidence fidelity under crash/partition. P0 provides the composed
in-process authority core (RQ2 partially) and the falsifiable test scaffolding;
RQ1/RQ3/RQ4/RQ5 require the live/transport/backend/performance campaigns that are
out of P0 scope.

## Integrity rules

Preregister thresholds and held-out splits before any behavioural evaluation; pin
every repository/dependency digest; retain negative results; separate development
tuning from final evaluation; distinguish simulation / emulation /
hardware-constrained simulation / physical hardware. None of the behavioural
experiments has been run here.
