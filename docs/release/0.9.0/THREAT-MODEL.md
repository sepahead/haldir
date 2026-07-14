# Haldir 0.9 normative threat model

Author: **Sepehr Mahmoudian**

> **Draft checkpoint — not verified.** T003 remains `open`. The machine mirror,
> verifier and hostile tests, claim/requirement/migration ledgers, exact-commit
> evidence, CI integration, and the formal corrections named below are pending.
> This draft must not be cited as a closed release guarantee.

## HALDIR-0.9-T003 — forged intent, stolen key, replay, route, state, rollback, and denial threats

The key words **SHALL**, **SHALL NOT**, **MUST**, and **MUST NOT** are
normative. This requirement refines `HALDIR-0.9-T001` and
`HALDIR-0.9-T002`; it does not broaden either claim. It applies to the
declared `haldir-secure-reference-v1` / `PRE_AUTHORITY_ACL_ONLY`
qualification scope and the separately identified in-process, configuration,
retained synthetic, and bounded-formal evidence layers.

Every threat case **SHALL** identify the attacker capability, prerequisites,
protected assets, violated property, current controls, failure and liveness
effects, evidence scope, coverage status, and residual risk. Listing a threat
**SHALL NOT** imply mitigation. A control **SHALL NOT** be described as
implemented merely because a configuration names it, a type can represent it,
or a test double returns success.

### Coverage and evidence vocabulary

The closed coverage states are:

- `MITIGATED_IN_CLAIMED_SCOPE` — an implemented control and executable
  evidence establish the stated narrow result under named assumptions;
- `PARTIAL` — at least one narrow variant is mitigated, but another material
  variant or deployment composition remains open; and
- `NOT_CLAIMED` — no affirmative prevention, detection, containment,
  availability, or recovery claim is made.

The evidence levels are `EXECUTABLE_LOCAL`,
`RETAINED_BOUNDED_SYNTHETIC`, `FORMAL_BOUNDED`,
`CONFIGURATION_ONLY`, `EXTERNAL_ASSUMPTION`, and `NO_EVIDENCE`.
No level silently upgrades into another. In particular, the retained router
campaign is a bounded allow/deny experiment, not credential-custody, flood,
availability, plant-delivery, or complete-mediation evidence.

All seven aggregate threat classes are `PARTIAL`. Their variants retain the
more precise statuses above; an aggregate **SHALL NOT** be promoted above its
least-covered material variant.

### Security objective and failure semantics

Within the exact in-process authorization conjunction, malformed,
unauthenticated, misscoped, stale, replayed, unavailable, or resource-refused
input **SHALL NOT** become a new Gate-authored plant command. Within the
bounded retained router experiment, a principal other than `gate` **SHALL
NOT** publish to the exact final route through the tested ACL path. These are
separate claims.

A failed precondition **SHALL** produce no new command. A denial, later fault,
expiry, or recovery record **SHALL NOT** erase, retract, or prove non-delivery
of bytes already exposed at the publication-call boundary. Ambiguous
publication **SHALL** remain `UNKNOWN_AFTER_PUBLISH` and shall block
replacement until an external clearance authority exists.

`ALLOW(HOLD)` is an authorized zero-velocity action and can create a command.
`DENY` and `ERROR` create no command. Haldir 0.9 has no `HOLD` or
`ESTOP` decision outcome and claims no Haldir-originated ESTOP command.

### Evidence scopes

| Scope | What it establishes | What it does not establish |
| --- | --- | --- |
| `PURE_CORE` | Deterministic parsing, cryptography, scope, replay, freshness, policy, state-transition, and local failure behavior in the tested Rust composition. | Authenticated remote peer identity, protected credential loading, live delivery, or global bypass closure. |
| `SECURE_REFERENCE_CONFIGURATION` | Exact principals, routes, and default-deny directional ACL intent. | Runtime behavior, credential custody, or a running Gate selecting the package. |
| `RETAINED_ROUTER_EXPERIMENT` | The recorded fixed route/principal subset, including cross-controller and final-route denials, under ephemeral test PKI. | Flood resistance, certificate lifecycle/revocation, exclusive CA trust, global handle ownership, plant delivery, or availability. |
| `BOUNDED_FORMAL` | Finite lease/boot/session, intent-epoch, current-output-epoch, and terminal-fault properties enumerated by the model. | Signatures, route authentication, physical-state truth, hostile storage, DoS/liveness, or the Rust/live composition. |
| `EXTERNAL_DEPLOYMENT` | Nothing by repository evidence alone. | Credential custody, external anti-rewind, plant fallback, firmware behavior, complete mediation, production security, and physical safety remain `NOT_CLAIMED`. |

### Protected assets and trust boundaries

The protected assets, subjects, constraints, time domains, and roots are the
closed inventories in `HALDIR-0.9-T002`. The threat model does not redefine
them. The load-bearing boundaries are:

1. transport authentication and router ACL;
2. bounded ingress and exact observed route;
3. canonical COSE/CBOR verification and closed application-key roles;
4. Gate scope, replay, state, policy, and publication transitions;
5. caller-supplied trust, lease, admission, revocation, and trusted-state inputs;
6. authenticated durable snapshot, generation anchor, and evidence journal;
7. exact final-route publication; and
8. the downstream plant/Crebain, firmware, physical process, and local fallback.

No boundary **SHALL** infer authority from a neighboring namespace. A
certificate principal is not an application signer, a valid signature is not a
fresh lease, a signed timestamp is not the Gate authority clock, and a
command-shaped byte string is not evidence of authorization or application.

### Adversary capabilities

The model includes unauthenticated network input; a compromised controller
process; theft of one application key, one transport credential, or both;
compromise of mission, admission, revocation, deployment, Gate, router/CA,
storage, or host authority; a caller able to supply stale or false state; a
storage attacker able to restore older self-consistent bytes; an authenticated
flooder; a caller of lower public APIs; and a malicious or unavailable plant.

Gate-host, router/CA, firmware/plant, and simultaneous Gate-plus-plant-fallback
compromise are outside the reference-monitor trust boundary. Haldir **SHALL
NOT** claim to contain them.

## TH-FORGED-INTENT — forged controller intents

An intent without possession of the enrolled private key is a forgery. A
message produced with a legitimately stolen enrolled key belongs to
`TH-STOLEN-KEYS` instead.

The pure core checks the hard envelope bound before signature verification,
strict deterministic CBOR, exact protected COSE algorithm/`kid`/content type,
empty unprotected security headers, domain-separated external AAD, exact
`kid` resolution, role, key class, revocation, signature, canonical
re-encoding, signer subject, and all signed scope fields. The live service also
checks envelope and route length before actor, clock, journal, or publisher
work. Tampering, an unrelated secret asserted under a trusted `kid`, wrong
role, revoked/development key, wrong actual route, and signed-scope
substitution are executable negative cases.

This mitigates wrong-secret and malformed forgeries within the named local
boundaries. It does not authenticate the producer of a publicly constructible
raw event, protect the enrolled private key, or prove that the router principal
reached the actor. The direct reference `VehicleActor` API hashes receipt
provenance before its internal oversize branch and is a cooperative API, not a
hostile transport boundary. Aggregate status: `PARTIAL`.

## TH-STOLEN-KEYS — valid-key and credential compromise

Cryptography cannot distinguish an authorized signer from an attacker holding
the same private key. A wrong secret under a valid `kid` is a forgery and
**SHALL NOT** be cited as stolen-key containment.

| Compromise | Current consequence and limit |
| --- | --- |
| controller signing key | The attacker remains constrained by the current controller admission, lease, session, route, source/state, policy, replay, rate, and total limits, but can exercise all authority inside that envelope until fresh revocation or lease termination. `PARTIAL`. |
| controller transport credential only | The tested ACL path does not grant final-route publication and a wrong application signature is rejected, but the credential can inject traffic/DoS on its allowed route and peer identity is not propagated into the actor. `PARTIAL`. |
| controller signing plus transport credentials | The attacker can impersonate the controller inside its active authority envelope. Direct final-route publication remains denied to that profile identity in the bounded router experiment. `PARTIAL`. |
| Gate application key | The attacker can forge Gate-signed receipts or evidence if it also reaches the relevant APIs/storage; external witnessing and protected loading are absent. It does not by itself prove possession of the final-route transport credential. `PARTIAL`. |
| Gate transport credential | The router ACL accepts final-route bytes from that principal without validating the Gate application signature or authorization conjunction. Arbitrary unauthorized final-route publication is therefore not prevented by the current profile. `NOT_CLAIMED`. |
| mission/admission/revocation/deployment signing key | Role and object-domain separation limit cross-role use, while the remaining conjunction may limit effects. Valid in-role forgery, custody, detection, propagation, rotation, and recovery remain unproven. `PARTIAL`. |
| router CA/router credential or Gate host/root | The attacker can subvert transport identity, routing, process memory, or loaded secrets. Containment is `NOT_CLAIMED`. |
| storage MAC key or generation-anchor administrator | Authentication or non-rewind protection can be forged/subverted within that root's scope. The local file anchor is explicitly rewritable. `NOT_CLAIMED` for hostile external compromise. |

Trust and revocation snapshots are caller-supplied/static in the current Gate
composition; no authenticated online propagation, protected key loader,
compromise detector, rotation drill, or recovery drill is claimed. Aggregate
status: `PARTIAL`.

## TH-REPLAY — duplicate, reordered, and cross-incarnation input

Replay domains **SHALL** remain typed and scoped:

- Gate challenges are one-shot and bounded;
- controller intent `(epoch, sequence)` positions require first sequence one,
  strictly advance, retain bounded retired-epoch tombstones, and never gain
  liveness from a duplicate;
- leases bind the current Gate boot and exact session pair, and terms ratchet
  within issuer/vehicle scope;
- trusted-state capture time strictly advances within one Gate boot, while
  source position is correlated to the current cache;
- Gate output positions advance within the current output epoch; and
- publication evidence enforces exact linked transition order and represents a
  dangling call as unknown rather than retryable failure.

Forward gaps in an intent sequence are permitted. A stolen controller key can
burn positions and quota. The current journal can detect a fork/gap in present
records but, without an external witness, cannot detect restoration of an older
self-consistent prefix. Copyable frames, reusable lower publishers, real
receiver duplicate handling, exact frame resubmission, and global
`(output epoch, sequence)` non-reuse across deployed restart remain
`NOT_CLAIMED`. Aggregate status: `PARTIAL`.

## TH-ROUTE-CONFUSION — identity, route, direction, and session confusion

For an accepted intent, the observed route **SHALL** equal the signed intent
route and the active lease route. The activation boundary derives the canonical
controller route from the verified, admitted controller before committing
authority. The narrow live coordinator derives the final route from the actor's
realm/session and rejects a publisher-route mismatch before frame exposure.
The deployment profile distinguishes principal, certificate CN, application
role, logical subject, route, and operation direction.

Executable local and retained synthetic cases cover wrong actual routes,
cross-controller routes, unsafe/wildcard route construction, session mismatch,
and non-Gate final-route publication in the bounded ACL subset.

The actor does not receive an authenticated peer principal. Lower raw-event,
actor, session, ingress, and publisher APIs remain public; shared sessions and
credentials are not globally exclusive; stock Zenoh trust is not exclusive
leaf pinning; and alternate ROS/MAVROS/firmware/plant actuator paths are not
closed. Static route equality **SHALL NOT** be called complete mediation.
Aggregate status: `PARTIAL`.

## TH-STALE-STATE — stale, false, or mis-timed authority input

Gate boot-local monotonic time is the only hot-path freshness clock. Missing,
invalid, wrong-vehicle, wrong-session, capture-regressed, wrong-source, expired,
or policy-insufficient state yields no new command. The exact trusted-state
digest and authorization revision are rechecked before publication exposure.
Clock regression or arithmetic failure denies or fault-latches.

Controller and source timestamps are provenance only and **SHALL NOT** create
freshness, validity, lease lifetime, or output time. Opaque identifiers are not
clocks.

The current setter does not authenticate a live state producer, enforce source
`(stream epoch, sequence)` monotonicity, or reject every impossible relation
between producer, receive, and capture times. A trusted or compromised caller
can repackage old truth under a later Gate capture. Sensor truth and end-to-end
age are external. Aggregate status: `PARTIAL`.

## TH-ROLLBACK — state, package, evidence, and deployment rewind

The pure primitives reject corrupt/noncanonical durable snapshots, term and
revocation rewind, deployment-revision rollback, same-revision equivocation,
implicit downgrade after package binding, generation forks/gaps, and boot-ID
reuse. State is committed before live mutation. Publication recovery converts
an ambiguous called tail to linked unknown and fail-closes.

These primitives **SHALL NOT** be represented as deployed external anti-rewind.
The default reference actor uses in-memory state, the local file anchor is in
the same rewritable failure domain, Gate startup does not yet require a
verified/resolved deployment package or package-bound boot ratchet, the
evidence journal lacks an external high-water witness, and power-loss/hostile
filesystem evidence is absent. Rolling back a deployment **SHALL NOT** silently
reuse an old boot, session, lease, key, output epoch/position, schema identity,
or evidence namespace.

End-to-end deployment rollback resistance and rehearsed recovery are
`NOT_CLAIMED`. Aggregate status: `PARTIAL`.

## TH-DENIAL-OF-SERVICE — resource exhaustion and unavailability

Implemented narrow controls include bounded CBOR and signed objects, live
envelope/route/queue limits, bounded challenge/replay/output/publication state,
checked arithmetic and counter exhaustion, lease rate and total limits, a
single publication slot, bounded evidence/journal/recovery quotas, and
conservative journal reservation before decision mutation. Refusal,
exhaustion, and evidence-spool loss **SHALL NOT** grant command authority.

These are safety/resource bounds, not an availability guarantee. There is no
proven pre-verification per-principal limiter, cryptographic concurrency cap,
connection/declaration quota, fairness scheduler, reserved control-plane
capacity, authenticated flood campaign, disk-full/power-loss campaign, live
soak/latency evidence, in-flight publisher timeout, supervisor, or plant-safe
fallback proof. Route-authorized invalid traffic can consume signature,
receipt, journal, and finite recovery resources. The shutdown handle is an
irreversible cooperative denial capability whose clones must be restricted.
After publication ambiguity, permanent refusal without authenticated clearance
is the current safe behavior.

Haldir **SHALL NOT** claim liveness, hard real-time behavior, continued command
availability, or safe physical fallback under DoS. Simultaneous loss of Gate
and the plant-local fallback is `NOT_CLAIMED`. Aggregate status: `PARTIAL`.

## Formal evidence boundary

The current bounded TLA+ run is green for its existing finite model, but it is
not yet acceptable T003 evidence: `LeaseBindsCurrentIncarnation` presently uses
weak `<=` comparisons that would not detect a stale nonzero lease, and
`RetireIntentEpoch` lacks the terminal-fault guard used by the other mutating
actions. Before T003 closure, the model **SHALL** require exact current
boot/session equality, consistent zero/nonzero lease fields, terminal fault
behavior, and a checked temporal property for that terminal behavior.

After those corrections, the bounded model may support only the enumerated
finite lease/boot/session, retired-intent-epoch, current-output-epoch, and fault
properties. It **SHALL NOT** be cited as evidence for signature security,
stolen-key custody, route authentication, physical state truth, hostile durable
rollback, DoS resistance, liveness, or the Rust/live refinement.

## Operator response and residual risk

Suspected key or host compromise requires the external operator to stop relying
on that identity, preserve evidence, revoke and rotate both application and
transport credentials as applicable, establish fresh boot/session/stream
namespaces, and use a plant-owned safe mechanism. Suspected rollback or
ambiguous publication requires quarantine and fresh externally witnessed state;
zero-initialization, silent retry, frame reuse, and guessed clearance are
forbidden. These are required responses, not claims that an authenticated
automated recovery workflow exists.

The release retains these material residual risks:

1. Gate transport credential, router/CA, or Gate host compromise can bypass the
   application conjunction.
2. A stolen controller key retains all authority inside its current lease and
   policy envelope.
3. Protected credential custody, detection, rotation, revocation propagation,
   and recovery are unproven.
4. Trust, control, revocation, and trusted-state acquisition are not
   authenticated end to end.
5. Lower APIs permit resubmission or bypass of the narrow coordinator.
6. Old final-frame behavior at a real receiver is unproven.
7. External anti-rewind, journal witnessing, crash, and power-loss durability
   are unproven.
8. Authenticated flood fairness, control priority, deadlines, and availability
   are unproven.
9. Alternate actuator paths, plant application/fallback, firmware, physical
   safety, and production security are `NOT_CLAIMED`.
10. No independent human security review, penetration test, or certification is
    claimed by T003.

## Machine mirror and closure

T003 closure still requires `release/0.9.0/threat-model.json`,
`tools/release/verify-threat-model.py`, and
`tools/release/test_verify_threat_model.py`. Those pending artifacts must
cross-check T001/T002, the exact profile and retained experiment, current
source/test semantics, the corrected formal model, the requirement ledger, and
this document's digest.

Only the later signed closure with exact-commit evidence may freeze this model
and local drift detection. This checkpoint does not close T003 or any future
implementation task named by a residual variant.
