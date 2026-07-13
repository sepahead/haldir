<!-- markdownlint-disable MD013 -->
# Haldir Gate — P0 implementation punch-list

Synthesized from an independent five-lens review (complete mediation & authority;
canonical encoding/signing/replay; time/restart/session-stream/evidence; fixed-point
policy; falsifiability/honesty) of the normative specification. IDs `B#/H#/G#/O#` are
stable handles cited in per-milestone reviews. Spec invariants are `A#/S#/T#/P#/F#`.

This file is a **living checklist**: each item is marked `[ ]` open, `[x]` done, or
`[~]` deliberately out of P0 scope (see `docs/LIMITATIONS.md`).

## 1. BLOCKING — miss any and the security claim is false

- `[~]` **B1** 10-way authorization AND commits at one point; `authorization_revision`
  is bumped by invalidations (fault-latch, `revoke_active_lease`) and re-checked
  before output-sequence allocation. **Honest scope:** under the single-threaded
  in-process actor the re-check is structurally present but inert (nothing can race
  the decision); it is scaffolding for a future concurrent actor and is NOT claimed
  to defeat a real mid-pipeline race here. *Verify:* `revoke_active_lease_then_intent_denies`,
  `clock_regression_latches_and_errors` (both in `haldir-gate`).
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
- `[~]` **B8** P0 enforces the 16-KiB envelope bound before signature verification,
  but its per-lease rate limit runs only after verification. A pre-verify token bucket
  keyed on the authenticated transport principal, bounded outstanding verification,
  and a control-plane reserve require the live transport actor and are not implemented
  in P0. The earlier `[x]` marking overstated the code.
- `[x]` **B9** Fixed-point core cannot fail open: component types pinned so squared/summed
  terms fit i128; range rejection before norm; overflow → specific DENY (never
  panic/saturate/wrap); prospective integration rounds reach UP.
- `[x]` **B10** Prospective geofence integrates over an upper bound of the published horizon
  (requested validity or hard cap), computed before the Stage-11 min.
- `[~]` **B11** Restart lease invalidation via a fresh boot id and empty in-memory state
  is modeled and unit-tested (`restart_invalidates_lease_via_new_boot_id`). The durable
  wrapper derives a Gate-bound ID from checked counter + injected entropy, persists the
  last ID, rejects a mismatched authenticated Gate binding, and returns a non-cloneable
  booted-store capability only after commit; the actor's recovered constructor consumes
  that capability and requires its boot ID in configuration. The startup library now
  validates static and anchor profiles plus an explicit `GateRuntimeProfile`: a
  `DeclaredLiveZenoh` template requires exact NCP selection and the compiled `live-zenoh`
  feature before startup-owned backend calls, entropy, locks, or directories. It retains
  the declaration in `StartupReport` and separately mints a private move-only capability
  consumed by the live coordinator typestate, holds the instance lock, and explicitly
  provisions or opens development-local state. Exact reference and copied-report paths
  cannot mint the capability. A separate strict package/owned-artifact verifier, bounded Linux/macOS
  source from a caller-supplied directory capability, and atomic v3 package-plus-boot ratchet now
  exist, but no Gate startup consumes either typestate
  (`CL-DEPLOYMENT-PRIMITIVE-01`). **Still absent:** private Gate glue that makes the authenticated
  declaration mandatory, authenticated/protected artifact-root and credential acquisition,
  semantic artifact loaders, and a deployed external
  non-rewindable anchor, so end-to-end cross-restart protection is not established (see
  `docs/LIMITATIONS.md`). Direct actor construction bypasses template startup.
- `[~]` **B12** Anti-rollback high-water, strict-advance rejection, canonical decode,
  an unambiguous versioned `(logical issuer, vehicle)` term namespace with a
  conservative legacy-scope upgrade read, separate-key authenticated snapshots,
  generation-anchor reconciliation, anchor assurance classification, Unix
  temp→file-sync→rename→directory-sync mechanics, and Gate injection/fault latching
  are unit tested. Durable v3 also distinguishes pristine, package-bound, and migration-required
  state and atomically ratchets one store-global package revision/payload digest for the store's
  authenticated Gate binding with the next
  boot. It rejects legacy/prior-use implicit binding, rollback, same-revision equivocation, and
  plain boot after binding; storage/anchor failure tests cover neither-or-both recovery. The lower
  ratchet still accepts neutral values and is not wired to the verifier or Gate. Development-local startup is wired, but a deployed external
  non-rewindable anchor and child-process crash evidence are absent; therefore the Gate still
  cannot claim cross-restart protection.
- `[~]` **B13** Monotonic-clock regression while ACTIVE now coherently latches both
  enforcement and public process state as `FAULT_LATCHED`. P0 receives a supplied
  `MonoInstant`; real clock-read failure handling belongs to the future runtime.
- `[x]` **B14** Evidence outage never turns DENY into ALLOW (direction test).
  A bounded, locked signed-segment directory manager is also unit tested and the private
  bound coordinator selects it for ordered lifecycle mutation. A test-only coordinator
  seam covers definite pre-terminal-append failure and synthetic ambiguity returned after
  actual terminal append/sync for both publisher result branches. A public service kernel
  selects that coordinator and a private capacity-one slot. The development examples make the
  bound path mandatory only inside an explicit `ProvisionNew` provisioner and separate
  `OpenExisting` bind/shutdown target; direct actors still bypass it and no authenticated
  package makes it universal. No OS-level append/write/
  `sync_data` fault-injection, disk-full, child-process crash, or power-loss campaign exists
  (`CL-GATE-LIFECYCLE-01`, `CL-DURABLE-01`).
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
- `[x]` **H7** Slew reference = last **published** command, updated only after the
  direct modeled actor caller asserts publication returned-ok. The internal coordinator's
  off-by-default concrete method exists only on a Called typestate descended from the
  startup-minted declared-live capability. It rejects a publisher outside the actor's exact
  realm/session route before invocation, consumes a matched strict publisher around one
  await, and journals the observed local result. Test-only futures also cover cold drop,
  pending timeout-as-drop, and panic unwind without converting an unobserved result to
  ReturnedError. A public no-network activation kernel first validates one bounded caller-supplied
  initial state/challenge/signed lease and mints a canonical route capability only from the
  verified controller. The lower consuming service encloses that marked route-bound coordinator,
  preconstructed matched publisher, and one private slot. The outer aggregate can instead retain
  one supplied session wrapper plus internally derived publisher/ingress handles. Its cloneable
  local stop-only handle can latch a request that lets the consuming method return the aggregate
  before receive/retry or wake idle receive, while never request-cancelling an already-selected
  event; a concurrent request then stays latched. The cooperative clones must remain restricted and
  a runner must exclusively use the shutdown-aware method. This is not
  an in-flight timeout, signal runner, or graceful production shutdown. The development target
  opens an external strict-client configuration and immediately shuts down under an outer lock,
  and retained evidence proves those local calls for one fresh fixture with zero processing or
  publication (`CL-LIVE-GATE-DEV-BIND-01`). No authenticated protected-credential/control package
  selects it. Preparation/output allocation
  alone does not mutate history; duty under clock rollback → fault/ERROR, never wraparound.
- `[x]` **H8** `AclExclusiveV1` and `NcpLeaseV1` stay distinct variants; no `has_authority`
  bool; under PRE_AUTHORITY the wire `authority.term`/`lease_id` are ABSENT.
- `[x]` **H9** COSE content-type ⇔ payload kind ⇔ external-AAD domain all agree; negatives for
  each mismatch; AAD encodes major version.
- `[x]` **H10** Domain-separated, golden-vectored `semantic_intent_digest` /
  `state_snapshot_digest` (per-kind prefix so digest domains cannot collide).
- `[x]` **H11** Structural limits enforced DURING decode; strict ASCII security IDs; reject
  seq 0 / malformed UUID. Declared-live activation also rejects a signed lease envelope larger
  than the 64-KiB large-contract profile before consuming the live kernel.
- `[~]` **H12** Lease acceptance reads the maximum of the canonical and legacy term
  namespaces, then commits through an injected term-store interface before consuming
  the challenge or exposing ACTIVE state; an unavailable durable commit latches
  `FAULT_LATCHED` and grants no lease. The default P0 constructor remains
  in-memory. The declared-live activation path additionally checks the signed controller
  intent route against the canonical realm/session/verified-controller route after signature/
  admission verification but before challenge consumption or term commit. Its initial state,
  nonce, and lease delivery remain caller-supplied. An explicit development-local startup path exists, but the deployed external
  anchor and crash campaign required by `CL-DURABLE-01` do not.
- `[x]` **H13** Wall-clock jumps don't move a live lease deadline; far-future `controller_t_ns`
  no effect; `controller_t_ns` never becomes final `t`.
- `[x]` **H14** Handoff changes only mission authority; Gate keeps its own output epoch/seq.
- `[x]` **H15** `haldir-contracts` does NOT depend on `haldir-ncp08`; `NcpSessionIdentityV1`/
  `NcpSourceRefV1` are Haldir's own stable types.
- `[~]` **H16** Controller-influenced TTL is clamped by the full min-set. The P0
  single-thread actor denies allocation failure before frame construction. The internal
  coordinator requires a sealed bounded-pool permit and three logical journal units before
  actor mutation. The public service binds it to one canonical process-local capacity slot,
  and the outer aggregate can retain the transport's bounded intent queue. No separate bounded
  publisher queue/worker exists and no overload loss-summary evidence is emitted.
- `[x]` **H17** 1:1 Haldir-UUID `gate_output_epoch` ↔ wire `stream.epoch`; conversion labeled
  `FIXED_POINT_TO_NCP_FLOAT_V1` with sampled monotonicity/finiteness/bounds/round-trip
  property tests plus an explicitly ignored exhaustive full-i32 sweep. NCP's JSON-safe
  integer boundary is enforced for both source and output sequences.

## 3. Plan gaps / sequencing

- `[x]` **G1** Keep Stage 0 ingress and the Stage-12 revision-recheck as their own boundaries.
- `[~]` **G2** The exact-route/strict-client/bounded-ingress/typed-publisher
  boundary and deterministic direction-specific ACL package now exist. Template startup
  also rejects an inexact or feature-disabled `DeclaredLiveZenoh` declaration before its
  listed backend calls, entropy, locks, or directory access, and its private process-local
  capability now gates concrete coordinator publication. A public no-network activation
  typestate requires bounded initial state/challenge/signed-lease input and derives the intent
  route from the verified controller; the outer aggregate can consume that route-bound result
  plus one supplied session wrapper and derive its publisher/exact ingress internally.
  A local monotonic request latch now preserves the owner across idle stop, without cancelling an
  already-selected event or claiming timeout/supervision behavior. Separate development examples
  now enforce explicit disposable provisioning versus `OpenExisting` live bind/immediate shutdown.
  The declaration and activation delivery are neither authenticated nor durable, and no
  authenticated credential-opening executable or ongoing control loop selects them. A separate
  package primitive verifies and retains exact signed artifact bytes; its optional bounded Linux/macOS
  source captures signed flat leaves from a caller-supplied open directory without reopening them.
  It can also supply neutral values to an atomic package/boot ratchet, but no Gate path consumes
  those stages. The
  retained synthetic ACL campaign proves the fixed final-command/controller-intent subset across all
  configured principals, and the separate retained development campaign proves only concrete
  session-open, aggregate-bind, and immediate local-shutdown returns. Certificate
  lifecycle/reconnect, the full matrix, and bypass inventory remain open; the deliverable is still
  P0-only.
- `[~]` **G3** Actuator-path disposition table needs Crebain + a live bypass campaign (out of P0).
- `[x]` **G4** Assurance profiles + pins + verify + dependency rationale as an entry gate.
- `[x]` **G5** The evidence layout/source ledger and retained live campaign directories now carry
  source-bound manifests, raw logs/configs, results, PKI fingerprint inventories, complete
  checksums, and specialized independent verifiers.
- `[x]` **G6** Coding-rule clippy gates from Phase 1.
- `[x]` **G7** Preregister TLA/model properties against invariants; preregister any thresholds.
- `[x]` **G8** Explicit P0 exit gate = strict subset of the Definition-of-Done.
- `[x]` **G9** Mission-authority monotonic-term contract + joint restart test.
- `[~]` **G10** Future `NcpLeaseV1` adapter asserts epoch freshness vs current boot (future profile).

## 4. Overclaiming risks / honesty

- `[x]` **O1** Do not claim `PRE_AUTHORITY_ACL_ONLY` from in-process tests. The retained
  external mTLS campaign proves only its fixed synthetic command/intent ACL subset; the
  packaged runtime, full matrix, certificate lifecycle, and bypass property remain limited
  exactly as stated in `CL-LIVE-TRANSPORT-01` and `LIMITATIONS.md`.
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
