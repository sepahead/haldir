# Haldir architecture

Haldir is an experimental, one-vehicle reference monitor for mission-level
plant commands. Its core question is narrow: given an untrusted controller
intent, independently held authority, trusted state, and a deterministic local
policy, may Gate create one new plant-facing command now?

This document describes the implemented architecture and the boundary of the
current source tree. It does not turn an implemented library seam into a
deployment, delivery, plant-application, physical-safety, or production claim.
The exact evidence status remains in the [claim ledger](CLAIM-LEDGER.md), and
release use remains `NO_GO`.

## Decision-record map

The [architecture decision records](adr/README.md) state why each load-bearing
mechanism was selected, which alternatives were rejected or deferred, and what
evidence ceiling remains. They do not broaden the claim ledger or close the draft
threat model.

| Architecture area | Decision record |
| --- | --- |
| Fail-closed monitor and Gate-originated output | [ADR-0001](adr/0001-fail-closed-gate-originated-authority.md) |
| Deterministic signed encoding and domain separation | [ADR-0002](adr/0002-deterministic-cbor-and-cose.md) |
| Authorization DENY versus internal ERROR | [ADR-0003](adr/0003-error-vs-deny-outcomes.md) |
| Bounded lease-use accounting | [ADR-0004](adr/0004-fixed-point-token-bucket.md) |
| Elapsed-time command slew | [ADR-0006](adr/0006-elapsed-time-slew.md) |
| One-vehicle in-process reference scope and deferrals | [ADR-0007](adr/0007-p0-scope-and-deferrals.md) |
| Exact half-open action history and conservative compression | [ADR-0008](adr/0008-exact-action-history-accounting.md), superseding [ADR-0005](adr/0005-interval-union-duty.md) |
| Checked policy arithmetic, prospective projection, and a complete bounded reason vector | [ADR-0009](adr/0009-checked-policy-arithmetic-and-complete-reasons.md) |
| Reserve-before-mutate, single-slot publication lifecycle | [ADR-0010](adr/0010-reserve-before-mutate-publication-coordinator.md) |

## Safety objective

The controlling invariant of the composed actor/coordinator path is:

```text
no Gate-authored plant command unless
    Gate is active and non-faulted
  ∧ the exact observed intent bytes authenticate to the leased controller
  ∧ route, boot, session, vehicle, mission, lease, admission, and policy agree
  ∧ the v1 intent names no undefined auxiliary input watermarks
  ∧ the intent position is fresh and consumed once
  ∧ current trusted state names a fresh, retained source position
  ∧ deterministic bounded policy returns ALLOW
  ∧ authorization and causal state still match at the exposure boundary
  ∧ current publication authority permits the exact final route
  ∧ a fresh Gate output position and self-consistent exact frame are allocated
```

Failure before exposure makes no exact frame available to a publisher; an
already prepared private frame may be cancelled or discarded. Failure after the
local `PublishCalled` boundary cannot prove non-delivery, so recovery records
`UnknownAfterPublish` and blocks new decisions pending authenticated external
clearance. A DENY never erases a previously published command; downstream
validity and plant-owned safe behavior remain separate responsibilities.

## Implemented compositions

| Composition | What exists | What does not follow |
| --- | --- | --- |
| `assurance-reference-v1` | Fully in-process signed-intent → actor → modeled NCP frame → deterministic reference plant path | No live transport, physical actuation, complete mediation, or timing evidence |
| `DeclaredLiveZenoh` library path | Durable startup and journal binding, move-only activation, exact-controller ingress binding, a single-owner intent/state/shutdown wait, decision/publication service, and explicit local shutdown | An authenticated runner, protected credential opener, control-plane producer authentication, supervision, restart clearance, delivery, or plant application |
| package-bound startup | Strict signed package verification, exact owned artifact capture, signed-role-to-compiled-pin NCP validation, strict signed Gate-configuration decoding/package cross-binding, four separately verified, role-separated, public-key-distinct revision-scoped snapshot approvals under the package stage's retained bootstrap trust/revocations, cross-store rejection of incompatible `kid` or public-key reuse, derivation and exact matching of live trust/revocation/admission/policy/session/publication/local-cap/signer identities before effects, atomic deployment-revision/boot commit, and exact signed journal-ID enforcement when binding the authenticated format-v2 chain; unbound assurance startup is rejected | Role/key separation does not prove independent organizations or operators; semantically loading the other seven artifact roles, authenticating the artifact root, making journal binding mandatory, binding its filesystem path, proving the running executable, loading protected secrets, or providing an authenticated production runner |

The `haldir-gate` executable is intentionally offline introspection only. The
development examples can provision a disposable fixture and bind then shut down
the live aggregate while processing zero intents. There is no production Gate
daemon in this repository.

## Data and authority flow

```text
                    role-separated authority inputs
                  mission lease  admission  policy  revocation
                         \          |         |        /
                          +---------+---------+-------+
                                            |
remote controller -- signed intent --> bounded ingress
                                            |
caller-supplied trusted state ----------> VehicleActor
  (validated local seam;                    |
   producer auth external)       deterministic policy + replay
                                            |
                         allocate + build exact Gate-owned frame
                                            |
                         opaque PreparedPublication (no byte access)
                                            |
                    cross-check receipt fields against exact frame
                                            |
                         signed receipt -> durable journal sync
                                            |
                           validate authority/state/time/horizon
                                            |
                             signed PublishCalled journal sync
                                            |
                         sample + recheck after the journal sync
                                            |
                             expose that exact frame once
                                            |
                              strict final-route publisher
                                            |
                                 plant / Crebain boundary
```

Application-signing authority and transport authority are distinct. The Gate
application key authenticates receipts and publication evidence. The Gate
transport credential grants the router permission to publish on the final
route. The present NCP v0.8 profile does not make the receiver verify a Gate
application signature on each command, so compromise or reuse of the transport
credential remains outside the enforcement claim.

The public in-process actor accepts raw candidates only through
`BoundedIntentCandidate`, whose private fields enforce the same 16 KiB envelope
and 256-byte route ceilings before hashing, decision-id allocation, signature
work, or state mutation. Failure to construct that value is an ingress rejection,
not a Gate decision, and therefore creates no signed decision receipt. This
length boundary does not authenticate the caller or close the lower actor as a
mediation bypass.

## Runtime ownership and lifecycle

The live path uses linear ownership rather than a shared actor handle:

```text
RunningGate
  -> JournalBoundRunningGate
  -> DeclaredLiveGateKernel
  -> IssuedLiveGateChallenge
  -> LiveIntentRouteBoundGate
  -> DeclaredLiveGateZenohService
  -> { update_trusted_state | process_next_or_state_or_shutdown }*
  -> shutdown
```

- Durable startup commits a fresh boot before returning an actor.
- Journal binding replays the ordered signed history and closes dangling prior
  calls as unknown before runtime authority becomes observable.
- The kernel issues one Gate-signed challenge whose nonce comes from startup's
  cryptographic-entropy contract (`OsEntropy` uses the OS CSPRNG) and whose 30-second lifetime is enforced by Gate
  monotonic time. Only the resulting move-only challenge state can consume one
  bounded caller-supplied state and matching signed lease. The caller can
  neither select/register the nonce nor bypass challenge issuance. The accepted
  controller determines the one canonical intent route. Before the durable
  lease term or one-shot challenge is spent, Gate also requires the lease's
  nominated intent-signing key to be present, unrevoked, assurance-class,
  authorized only as `ControllerIntent`, and enrolled to that controller.
- Binding derives the exact ingress and final publisher from the same supplied
  session wrapper. The concrete publisher retains the complete session id and
  generation and rechecks both against exact-frame semantics and decoded NCP JSON
  before its single transport invocation.
- Every state or intent operation consumes the sole service owner. The aggregate
  can poll one caller-owned, cancellation-safe state receive beside its owned
  intent ingress and shutdown latch without duplicating the actor. Only safe
  continuation returns the owner. This orders state update, decision,
  publication, and shutdown through one API even while intent ingress is quiet.
- A normal state rejection returns the unchanged owner. Clock regression, a
  state-machine classify/commit disagreement, or a terminal publication failure
  destroys it fail-closed.
- Every actual live publisher invocation is terminal, including a local `Ok`.
  NCP v0.8 starts its TTL from plant-local arrival; Gate observes neither that
  arrival nor any authenticated application acknowledgement. The live path
  therefore records the local return, commits no guessed action interval, and
  returns no authority capable of publishing another command. The cooperative
  in-process reference composition can continue only because its caller reports a
  modeled returned-ok instant and exact validity horizon in the same call boundary;
  that report is neither receiver-generated application evidence nor a physical
  action observation.
- Shutdown requests are cooperative and observed only at safe receive
  boundaries. They never cancel an already selected decision/publication.
- Orderly shutdown retains the Gate owner and instance lock through the local
  session-close attempt. Cancellation and process death still require an outer
  supervisor and cannot prove remote session retirement.

Lower public actor and transport APIs remain reusable library surfaces. Rust
module privacy is not process isolation and cannot enforce credential custody.
A deployed profile must give the final-route credential to exactly one hardened
Gate process and close every alternate actuator path before making a mediation
claim.

## Trusted-state model

`TrustedStateSnapshotV1` is an internal decision input, not a controller wire
message. Gate validates:

- exact vehicle and NCP session binding;
- a valid source observed in that session;
- when a lease is active, a source key in that lease's allowlist;
- source receive ≤ snapshot capture ≤ Gate-observed monotonic time;
- nonnegative position and velocity uncertainty;
- a source sequence representable by the implemented NCP v0.8 JSON profile;
- strictly advancing snapshot capture time; and
- bounded boot-local source replay state.

Source epochs are opaque identities. For each source key, the first observed
epoch may attach at any nonzero sequence, sequence then advances strictly, an
epoch change permanently retires the prior epoch, and tombstones are never
evicted. Exhausting the bounded retained-stream set fails closed. The current
state-update seam does not authenticate who constructed the snapshot; a
production control plane must bind an authorized producer and exact received
bytes to this internal type.

Freshness uses only Gate boot-local receive/capture time. Controller time and
source publisher time are provenance, never authority clocks.

## Policy and motion envelope

The native policy is pure fixed-point Rust with checked or widened arithmetic.
[ADR-0009](adr/0009-checked-policy-arithmetic-and-complete-reasons.md)
records the arithmetic, projection, and complete-reason decision, including the
rejected alternatives, assumptions, failure semantics, and software-only claim
ceiling. [ADR-0006](adr/0006-elapsed-time-slew.md) and
[ADR-0008](adr/0008-exact-action-history-accounting.md) separately govern
elapsed-time slew and exact action-history accounting.
It intersects lease limits with the locally admitted executable envelope and
checks, among other constraints:

- action/phase scope, exact digest-bound local-NED frame identity, and
  action-specific plant-mode permission and source/state freshness;
- component and vector-norm speed bounds;
- measured-state-to-command acceleration including velocity uncertainty;
- command slew from the last successfully published command;
- checked half-open duty intervals with conservative retained-future-tail and
  bounded-history over-approximation, continuous-motion bursts, and
  published-Hold dwell; and
- a prospective geofence from exact state capture through the full candidate
  horizon.

Policy evaluation retains every distinct denial found in its fixed evaluation
order, up to the schema bound of 32. Gate signs that complete vector in the deny
receipt; it does not collapse simultaneous failures to the first reason.

Plant mode is executable policy input, not decorative telemetry. Schema-v2
policies carry a bounded, canonical mode-to-action map. An unlisted mode permits
no Gate command; rules remain action-specific so authorizing `Hold` in a
degraded mode cannot implicitly authorize velocity. The mode value is supplied
through the trusted-state boundary, so a live assurance claim still requires an
authenticated state producer and an independently reviewed mapping from
vehicle-specific modes to these identifiers.

The geofence computes an outward-rounded per-axis software projection containing
the requested velocity and measured velocity ± measurement uncertainty. Its
exact-nanosecond interval starts at the trusted snapshot's capture time, includes
the accepted state age at decision, and continues through the latest candidate
command end. It then adds position uncertainty, tracking error, and policy
margin. It does not bound physical acceleration, braking, overshoot,
disturbances, localization error outside the supplied uncertainty, or actuator
behavior. It is therefore a configured authorization envelope, not a validated
reachable-set, vehicle-dynamics, containment, or stopping-distance proof.

## Publication and evidence boundary

[ADR-0010](adr/0010-reserve-before-mutate-publication-coordinator.md) records why
the current one-vehicle composition reserves its complete local lifecycle before
mutation, uses one move-only publication slot, syncs Called before exposure, and
stops rather than retrying after ambiguity.

Prepared output bytes are private. The coordinator reserves journal capacity
before decision mutation. Before accepting the actor's prepared result, it
cross-checks the receipt's decision, complete NCP session, source, state digest,
effective validity, output position, output-frame digest, and transformation
against the self-consistent opaque exact frame. It then syncs the signed
decision, syncs `PublishCalled`, and only then exposes that same frame to one
publisher invocation. Immediately before exposure, the actor rechecks:

- publication-slot ownership;
- authorization revision;
- trusted-state digest;
- active lease and publication authority;
- monotonic call deadline and remaining validity; and
- checked command horizon.

Publisher `Ok` means only that the local transport call returned `Ok`. It is not
delivery, receiver acceptance, application, or physical effect. In the
declared-live path it is therefore a terminal application-unobserved stop, not a
successful continuation. Evidence still records `PublishReturnedOk` because
that is the exact local fact; it does not convert it into plant history.

## Crate boundaries

| Crate | Responsibility |
| --- | --- |
| `haldir-contracts` | Closed canonical wire vocabularies and typed identifiers |
| `haldir-crypto` | COSE/Ed25519 verification, role separation, trust and revocation snapshots |
| `haldir-deployment` | Signed package and exact artifact-byte verification |
| `haldir-durable` | Authenticated snapshots, anchors, atomic file primitives |
| `haldir-state` | Replay, source replay, lease, boot, output, and revision state machines |
| `haldir-core` | Internal immutable decision snapshots and monotonic time |
| `haldir-admission` | Controller/backend admission matching |
| `haldir-policy-native` | Deterministic fixed-point authorization policy |
| `haldir-ncp08` | Closed modeled/exact NCP v0.8 construction and validated exact-command capability |
| `haldir-evidence` | Signed journal segments and publication reduction |
| `haldir-transport-zenoh` | Strict routes, bounded ingress, and typed final publisher |
| `haldir-gate` | Single-vehicle actor, startup, lifecycle, and live ownership composition |
| `haldir-reference-plant` | Session-bound deterministic simulation-only receiver/application model |
| `haldir-range` | Adversarial in-process scenarios |

Dependencies point toward contracts, pure state, and the NCP command boundary.
The non-test Gate dependency graph does not depend on the simulation-only reference
plant; both Gate and the plant use the exact-command capability owned by
`haldir-ncp08`. Transport and the reference plant do not decide authority; Gate
composes them at explicit side-effect boundaries.

## Release boundary

The next architecture milestone is not another policy rule. It is one private,
authenticated deployment shell that, in this order:

1. obtains bootstrap trust and an independently configured package-acceptance
   policy;
2. verifies and resolves the signed package without reopening artifacts;
3. parses closed, versioned artifact schemas and proves their cross-bindings;
4. binds the running executable, state store, journal, runtime/NCP profile,
   router identity, and protected credential identity to those exact bytes;
5. commits the verified package revision/digest with the fresh boot;
6. opens the sole final-route credential and state/control ingresses;
7. runs the single-owner service with bounded timeouts and supervision; and
8. completes authenticated restart clearance and explicit journal/session
   teardown.

Until that shell and the plant-side bypass inventory exist, Haldir remains a
research/reference implementation. See [limitations](LIMITATIONS.md), the
[threat model](release/0.9.0/THREAT-MODEL.md), and the
[roadmap](ROADMAP-STATUS.md).

## Design rules

Future changes should preserve these rules:

1. No controller field becomes a root of trust merely because it is signed.
2. Opaque epochs are compared only for equality; ordered counters are scoped to
   their exact epoch or durable subject.
3. Every accepted untrusted input and every runtime-retained authority, replay,
   queue, history, retry, or recovery state has an explicit hard bound and fails
   closed before exceeding it. Caller-owned configuration buffers are validated
   at their authority boundary; their mere Rust container type is not a security
   claim.
4. Authority changes commit durably before live authority changes.
5. Exact output bytes remain inaccessible until the pre-side-effect evidence
   boundary and final recheck.
6. `published`, `received`, `accepted`, `applied`, and `observed` remain distinct
   evidence stages.
7. New runtime authority must descend from a non-cloneable verified capability,
   not from a report, string profile, or reconstructed boolean.
8. A mechanism does not become a system claim until mandatory composition and
   bypass closure are demonstrated.
