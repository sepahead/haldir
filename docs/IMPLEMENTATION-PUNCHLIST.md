<!-- markdownlint-disable MD013 -->
# Haldir Gate — P0 implementation punch-list

Synthesized from an independent five-lens review (complete mediation & authority;
canonical encoding/signing/replay; time/restart/session-stream/evidence; fixed-point
policy; falsifiability/honesty) of the normative specification. IDs `B#/H#/G#/O#` are
stable handles cited in per-milestone reviews. Spec invariants are `A#/S#/T#/P#/F#`.

This file is a **living checklist**: each item is marked `[ ]` open, `[x]` done, or
`[~]` deliberately out of P0 scope (see `docs/LIMITATIONS.md`).

## 1. BLOCKING — miss any and the security claim is false

- `[x]` **B1** 10-way authorization AND commits at one point; a monotonic
  `authorization_revision` is bumped by every invalidation and re-checked immediately
  before output-sequence allocation (TOCTOU). *Verify:* revision property test +
  `authority_revoked_mid_pipeline` yields zero output.
- `[x]` **B2** S6 no-liveness-effect: duplicate/stale/malformed/wrong-session/unauthorized
  input never refreshes lease, watchdog, horizon, source freshness, output authority,
  counters, or any burst/hold/slew timer. Highest-value mediation test.
- `[x]` **B3** Two-phase replay consume/no-consume matrix: checks 1–13 do NOT advance
  replay state; `last_seq` commits after authority/scope checks; check 14+ (source/state/
  action/policy DENY) consume the seq. Retired epoch always rejects; tombstone overflow →
  quiesce, never evict-and-reopen.
- `[x]` **B4** A3 Gate-origin output: intent fields are equality-checked consistency claims,
  never copied into the emitted frame. One differential test: hostile intent fields →
  byte-identical output to benign run.
- `[x]` **B5** `IntentSeq`/`OutputSeq` and `ControllerIntentEpoch`/`GateOutputEpoch` are
  distinct newtypes with NO `From`/`Into` between them. *Verify:* compile-fail test.
- `[x]` **B6** Pin the deterministic-CBOR variant (RFC 8949 §4.2 core-deterministic,
  integer map keys, shortest ints, no floats/tags/indefinite) BEFORE the first golden
  vector; publish rule + a golden vector.
- `[x]` **B7** COSE: verify Ed25519 over exact payload bytes, THEN require decode→re-encode
  equality; external AAD from the verifier's dispatch context, not the payload's self-
  declared kind; `alg`/`kid`/content-type in the protected header; `kid` selects exactly
  one key (no fallback search, no message-supplied algorithm, Ed25519-only, reject
  multi-sig/detached); role must match; reject `DEVELOPMENT_ONLY` under assurance profile.
- `[x]` **B8** Size + rate limits BEFORE signature verification; pre-verify token bucket
  keyed on the authenticated transport principal; bounded outstanding-verification;
  control-plane reserve so revocation/session-close survive a flood.
- `[x]` **B9** Fixed-point core cannot fail open: component types pinned so squared/summed
  terms fit i128; range rejection before norm; overflow → specific DENY (never
  panic/saturate/wrap); prospective integration rounds reach UP.
- `[x]` **B10** Prospective geofence integrates over an upper bound of the published horizon
  (requested validity or hard cap), computed before the Stage-11 min.
- `[x]` **B11** Restart mints a fresh unrepeatable `gate_boot_id`; no active lease/session/
  publication/output-epoch/replay restored; durable monotonic boot counter; latch on
  non-advance or boot_id repeat.
- `[x]` **B12** Anti-rollback store persists only highest terms/epochs + retired identities;
  atomic temp→fsync→rename→fsync-dir, MAC'd under a separate storage key;
  missing/rewound/corrupt → FAULT_LATCHED, never zero-init.
- `[x]` **B13** Monotonic-clock regression while ACTIVE → FAULT_LATCHED; clock-read failure
  → DENY (never "fresh").
- `[x]` **B14** Evidence outage never turns DENY into ALLOW (direction test).
- `[x]` **B15** Reference plant has exactly one command ingress; zero application from any
  non-Gate principal; safe action is plant-owned (Gate only requests).

## 2. HIGH-VALUE correctness

- `[x]` **H1** effective_validity uses the FULL Stage-11 min-set verbatim (lease-remaining and
  lease.max_output_validity distinct; source and state freshness distinct; NCP authority
  when represented; minus a mandatory publication safety margin). Shortening any input
  never increases effective validity.
- `[x]` **H2** One canonical `PublishStageV1`; `UNKNOWN_AFTER_PUBLISH` (F4); append-only by
  `decision_id`; Gate-signed receipt records only stages Gate observed.
- `[~]` **H3** Application-evidence binds session + output-epoch currency (reference-plant model).
- `[x]` **H4** No `HashMap`/`HashSet` where iteration feeds a digest/decision/Cedar context.
- `[x]` **H5** Inclusive/exclusive + expected-reason-code table for every scalar predicate;
  boundary tests assert the `==limit` outcome.
- `[x]` **H6** Reason-code hard/soft classification; deny-precedence; bounded reason vec keeps
  hard denies first; short-circuit yields identical outcome+reasons.
- `[x]` **H7** Slew reference = last **published** command, updated only at output allocation;
  duty under clock rollback → fault/DENY, never wraparound.
- `[x]` **H8** `AclExclusiveV1` and `NcpLeaseV1` stay distinct variants; no `has_authority`
  bool; under PRE_AUTHORITY the wire `authority.term`/`lease_id` are ABSENT.
- `[x]` **H9** COSE content-type ⇔ payload kind ⇔ external-AAD domain all agree; negatives for
  each mismatch; AAD encodes major version.
- `[x]` **H10** Domain-separated, golden-vectored `semantic_intent_digest` /
  `state_snapshot_digest` (per-kind prefix so digest domains cannot collide).
- `[x]` **H11** Structural limits enforced DURING decode; strict ASCII security IDs; reject
  seq 0 / malformed UUID.
- `[x]` **H12** Lease step 13 durably advances accepted-term high-water before exposing active;
  test failure-after-commit (higher term consumed, no active lease).
- `[x]` **H13** Wall-clock jumps don't move a live lease deadline; far-future `controller_t_ns`
  no effect; `controller_t_ns` never becomes final `t`.
- `[x]` **H14** Handoff changes only mission authority; Gate keeps its own output epoch/seq.
- `[x]` **H15** `haldir-contracts` does NOT depend on `haldir-ncp08`; `NcpSessionIdentityV1`/
  `NcpSourceRefV1` are Haldir's own stable types.
- `[x]` **H16** Controller-influenced TTL clamped by the min; `ALLOW_NOT_PUBLISHED_OVERLOAD`
  refreshes nothing and reserves queue capacity before allocating the sequence.
- `[x]` **H17** 1:1 Haldir-UUID `gate_output_epoch` ↔ wire `stream.epoch`; conversion labeled
  `FIXED_POINT_TO_NCP_FLOAT_V1` with monotonicity/finiteness/bounds/error property tests
  over the full i32 domain.

## 3. Plan gaps / sequencing

- `[x]` **G1** Keep Stage 0 ingress and the Stage-12 revision-recheck as their own boundaries.
- `[~]` **G2** Live secure-transport + bypass inventory (Master step K) is OUT of P0 → deliverable
  is relabeled P0-only; `haldir-transport-zenoh` is a documented trait-only seam.
- `[~]` **G3** Actuator-path disposition table needs Crebain + a live bypass campaign (out of P0).
- `[x]` **G4** Assurance profiles + pins + verify + dependency rationale as an entry gate.
- `[x]` **G5** `evidence/<phase>/` with manifest + raw logs + checksums from Phase 1.
- `[x]` **G6** Coding-rule clippy gates from Phase 1.
- `[x]` **G7** Preregister TLA/model properties against invariants; preregister any thresholds.
- `[x]` **G8** Explicit P0 exit gate = strict subset of the Definition-of-Done.
- `[x]` **G9** Mission-authority monotonic-term contract + joint restart test.
- `[~]` **G10** Future `NcpLeaseV1` adapter asserts epoch freshness vs current boot (future profile).

## 4. Overclaiming risks / honesty

- `[x]` **O1** Do not claim `PRE_AUTHORITY_ACL_ONLY` as a *proven live* property from in-process
  tests; it is a declared compatibility profile string here, with the live mTLS/ACL matrix
  UNPROVEN (see LIMITATIONS).
- `[x]` **O2** Phase 14/19 range is a **deterministic in-process** campaign, not live
  complete-mediation; bypass/wrong-route/backend vectors that need live transport or a
  second backend are out of scope and labeled so.
- `[x]` **O3** `applied`/`observed` are reference-plant MODEL values, never physical actuation;
  `validated` requires preregistered criteria.
- `[x]` **O4** No performance phase; any latency numbers carry the "not hard real-time" qualifier
  and p99/p99.9-on-named-hardware is UNPROVEN.
- `[x]` **O5** Mediation claim capped to "enforces contract/state/policy conjunction in-process
  over the declared command route".
- `[x]` **O6** `LIMITATIONS.md` + negative-claims paragraph in README/SECURITY + per-item
  completion checklist with evidence pointers, every "no" mapped to a limitation.

**First-pass order:** B6 → B5 → B1 → B3/B2 → B7/B8 → B9/B10 → B11/B12/B13, with G4/G5/G6
and O1/O2 in force from commit 1.
