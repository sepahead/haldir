# Haldir Gate — limitations and what is NOT claimed

This document is normative for honesty. The specification's honesty vocabulary
(*implemented / compiled / tested / validated / published / received / accepted /
applied / observed*) is used exactly. Read it before citing any result.

## What this deliverable is

The **P0 `assurance-reference-v1` profile**: the complete, offline-testable, pure
Rust reference-monitor core. It is **implemented**, **compiled** (rustc 1.96,
edition 2024, `forbid(unsafe_code)`), and **tested** (the full workspace test
suite runs under `cargo test` with `cargo clippy -D warnings` clean).

The defensible claim, stated narrowly:

> Within the in-process P0 profile, the composed Gate enforces the
> contract / state / policy conjunction over the declared command route: an
> unauthorized, malformed, stale, replayed, mission-forbidden, or policy-invalid
> intent does not become a Gate-authored plant command, and each stage the Gate
> actually observes produces distinguishable evidence.

## What is explicitly NOT claimed (out of P0 scope)

None of the following stronger outcomes is established here. No result about them
should be represented as *validated*, *secure*, *complete-mediation*, or *hardware*.

- **Full live secure transport / service proof.** Exact pinned-NCP route builders,
  an off-by-default Zenoh 1.9 TLS-only client boundary, bounded actual-key intent
  ingress, a typed exact-frame publisher, and a deterministic default-deny mTLS/ACL
  package are implemented and statically tested (`CL-TRANSPORT-BOUNDARY-01`). The
  package pins an immutable router image and models Zenoh's separate ingress/egress
  checks so receive permission does not grant publication. A retained synthetic
  campaign now proves the fixed final-command/controller-intent ACL subset across all
  eight configured certificate principals, separate remote sessions, a no-certificate
  negative, and a two-second quiescent quarantine (`CL-LIVE-TRANSPORT-01`). It uses an
  ephemeral test PKI and does **not** prove unknown/revoked/expired certificate behavior,
  reconnect, production credential custody, a runnable Gate selecting this path, a full
  principal×operation×route matrix, or bypass closure. Static configuration equality and
  a local `put()` result remain non-evidence; receiver callbacks are the campaign oracle.
  Stock Zenoh 1.9 also combines public WebPKI roots with the configured CA rather than
  replacing them; the reserved `.invalid` router name is a mitigation, not exclusive
  certificate pinning. Production-grade exclusive router trust requires a patched/
  upgraded transport verifier.
- **`PRE_AUTHORITY_ACL_ONLY` as a deployed runtime property.** It is a declared
  compatibility label and now has the narrow synthetic ACL evidence above. It is still
  not established for a packaged Gate/Crebain deployment, production credentials, or a
  complete actuator/bypass inventory.
- **Exact NCP adapter selection is not a live Gate path.** The off-by-default
  `real-ncp` feature compiles the exact pinned `ncp-core` v0.8.0 revision and its
  frozen-corpus/differential tests pass (`CL-NCP-REAL-01`). Gate startup now carries a
  closed explicit selection, and an exact-selected actor is tested through its Called
  boundary. Current P0 fixtures deliberately choose the dependency-light model, whose bytes
  are not the pinned-NCP JSON accepted by the strict Zenoh publisher. No service requires
  exact mode or wires Zenoh to the actor/coordinator/plant. Exact selection therefore does
  not prove runtime publication, acceptance, application, or ACL exclusivity; a future live
  profile must reject modeled selection before durable startup or authority exposure.
- **Publication lifecycle coordination is internal; its strict binding is not runnable.** The actor keeps
  one explicit `Idle -> Prepared -> PublishCalled` slot. Prepared output is opaque and
  non-cloneable; exact bytes become accessible only after the actor rechecks authority,
  causal state, the safety-margin deadline, and checked active-horizon arithmetic.
  A crate-private split keeps a validated call opaque across journal sync and repeats
  all safety checks at the post-sync exposure instant; failure exposes no frame,
  fault-latches, and conservatively retains `PublishCalled`.
  Preparation/cancellation does not charge published-command history; caller-asserted
  modeled returned-ok charges it once, and an asserted error/timeout consumes the
  resolver, fault-latches, and blocks actor-issued replacement output
  (`CL-PUBLICATION-STATE-01`). A separate crate-private consuming coordinator now owns a
  fused startup/journal aggregate, requires a sealed permit issued by a bounded pool,
  reserves three logical journal units before decision mutation, and locally
  `sync_data`-orders the receipt, linked Called, and terminal record
  (`CL-GATE-LIFECYCLE-01`). Under its off-by-default `live-zenoh` feature, production
  coordinator code derives the exact pinned command route from the actor realm/session,
  terminally rejects a mismatched publisher before frame access or invocation, lends the
  frame only to one awaited call on a matched concrete strict publisher, returns that
  capability only after local `Ok` plus terminal journal success, and returns neither
  runtime nor publisher after error. Pending-future cancellation is
  tested to leave durable Called for restart recovery rather than inventing ReturnedError.
  Result/cancellation tests use a test-only future seam, not a live Zenoh session.

  The pool is not authenticated as one canonical service queue, positive composition uses
  a test-only binder around an already-active actor, and no production control plane,
  queue, worker, or runnable service selects the coordinator. A Called record alone is a
  pre-invocation ambiguity boundary, not evidence that a local transport call began.
  Lower-level actor frame access, the copyable frame type, the reusable publisher API, and
  independently constructible session-backed publishers still permit resubmission outside
  the coordinator binding.

  Restart converts a dangling Called tail to linked `UnknownAfterPublish`, then any
  recovered Called-or-later history blocks decisions indefinitely because no authenticated
  transport/session/plant/history clearance API exists. The construction-time maximum of
  recovered validity and the new actor's current duty window produces only a diagnostic
  timestamp, not an authoritative reconstruction of prior policy/history; elapsed time does
  not clear it. Cancellation/pre-call rejection leaves a locally sync-confirmed Prepared
  trace, so retained trace/journal bounds can eventually quiesce without an
  abandonment or loss-summary record. Coordinator-level append-fault, live-session
  cancellation/timeout, panic, child-process crash, shared clock-origin, and power-loss
  tests are absent. The concrete
  method is compile-tested but not live-invoked; this is not a publication,
  receiver-inactivity, delivery, or application claim.
- **NEST / Engram controllers.** No neural runtime is present. Admission checks
  digest equality only; **no backend behavioural conformance** (running NEST /
  Norse / Rockpool / XyloSim) is performed. Admission levels A1–A6 are structural
  labels here, not earned behavioural evidence.
- **Crebain / PX4-SITL / Gazebo.** No plant-side integration, no MAVROS, no
  simulator. The `haldir-reference-plant` is a deterministic integer point-mass
  **simulation model**. Its `applied` / `observed response` events are **model
  values, never physical actuation**. `reference-kinematic-hold-v1` safe action is
  simulation-only and must not be reused as evidence for any real vehicle.
- **Second backend / NIR / neuromorphic hardware.** Not attempted. No
  backend-aware admission research result exists.
- **Cross-repository plant/controller integration.** A narrow NCP release-tool fix
  now accepts Haldir's exact Cargo comparator, but no Crebain/Engram runtime was
  integrated and no cross-repository change is evidence of plant ownership,
  controller confinement, or delivery/application.
- **Performance.** There is no performance/latency campaign. Any timing number is
  "measured on named host/kernel/load; not hard real-time"; **p99/p99.9 on named
  hardware is UNPROVEN**.
- **TLA+ model scope.** The bounded model now checks green under the SHA-verified
  TLA+ v1.7.4 jar (`CL-FORMAL-01`, GitHub run `29211573130`). This proves only the
  registered finite model; the Rust `model` tests remain an independent executable
  encoding, and neither result proves a wired live service or durable runtime.
- **`missing_docs` hardening.** Deferred; the workspace does not yet
  `deny(missing_docs)`. Crate- and item-level docs are written voluntarily.
- **Durable anti-rollback / restart rollback protection.** The default P0 actor
  constructor still uses an **in-memory** anti-rollback store. A separate recovered
  constructor now accepts only a non-cloneable booted-store capability produced after
  `begin_boot` verifies the authenticated Gate binding and durably commits a fresh
  `BootContext`; the configured boot ID must match that capability. Lease terms commit
  through the injected store before authority becomes active, and an unavailable commit
  terminally faults the actor. The term namespace is versioned canonical CBOR over the
  logical issuer ID and vehicle ID, with the old delimiter-based namespace retained as
  a conservative read-only migration floor. Realm, Gate incarnation, session/output
  epoch, and issuer signing-key ID do not reset that high-water within one store. Because
  the next write upgrades the durable payload shape to v2, a pre-v2 executable rejects
  the rewritten state instead of silently falling back to the stale legacy floor.
  Operational rollback must still restore a compatible binary and its authenticated
  state as one reviewed unit. Durable stores are provisioned and authenticated for one
  Gate ID, so no cross-store or
  cross-Gate transfer of a vehicle's high-water is implemented or claimed. Changing the
  logical issuer ID selects a new namespace; this state primitive does not authorize or
  prove a mission-authority identity migration. The
  HMAC/envelope/anchor mechanism,
  Unix atomic-file backend, boot-ID binding/repeat latch, durable anti-rollback wrapper,
  injection checks, failure ordering, and explicit development-local startup are unit
  tested (`CL-DURABLE-PRIMITIVE-01`, `CL-DURABLE-STARTUP-DEV-01`). The local anchor is
  checksummed but unauthenticated, rewritable with the snapshot, and classified
  `LocalRewritable`; interrupted two-backend genesis provisioning fails closed and needs
  operator repair (`CL-LOCAL-ANCHOR-DEV-01`). No service package loads/protects the
  storage key or selects a deployed external non-rewindable anchor, and no child-process
  kill matrix has established old-or-new
  behavior under actual crashes. Therefore end-to-end **cross-restart** rollback
  protection of B11/B12 remains **NOT established**.
- **Filesystem/platform durability scope.** `AtomicFileSnapshot` uses a same-directory
  `create_new` temporary, file `sync_all`, Unix rename, and parent-directory
  `sync_all`, and assumes a trusted local POSIX filesystem plus exclusive writer.
  It is unsupported on Windows, cannot eliminate ancestor-path races using only
  safe path-based standard-library APIs, and does not claim macOS `F_FULLFSYNC`,
  power-loss, network/FAT/overlay filesystem, or adversarial directory-rewind
  guarantees. A same-filesystem anchor cannot close `CL-DURABLE-01`.
- **Durable evidence lifecycle is not selected by a runnable Gate service.**
  `haldir-evidence::journal` unit-tests a bounded Unix segment format with
  CRC32C-framed opaque records, Gate/boot/key/sequence/previous-digest headers,
  checked genesis/successor construction, signed segment-content digests,
  Ed25519 footers, strict completed-corruption rejection,
  and truncation of only an insufficient final record/footer tail
  (`CL-EVIDENCE-SEGMENT-PRIMITIVE-01`). The manager adds explicit provision/open,
  a retained checked lock, strict chain discovery, injected signer/record verification,
  old-tail signer recovery, rotation, global caps, exact-record retry queries, and an
  opt-in record-count/exact-record-byte-bounded snapshot of verifier-accepted opaque records
  in authenticated segment/append order (`CL-EVIDENCE-MANAGER-01`). Capture is returned
  only after complete open success and legacy open does not retain the snapshot. A
  capture-limit error returns no partial snapshot, but ordinary recovery may already
  have removed an insufficient tail or pending creation artifact. The manager retains
  only the configured signer KID/public key and requires an exact short-lived private-key
  borrow before any append/finish operation that may footer-complete. Opaque manager-affine
  reservations protect one future segment slot plus maximum header/record/footer bytes
  per unit from ordinary appends and rotations. They reserve configured logical quota,
  not physical filesystem blocks or successful future I/O. The staged
  `RunningGate` journal binding now uses that single-owner-compatible shape. A private
  child coordinator can mutate the fused actor/manager only as one consuming aggregate;
  public callers still receive read-only views. The manager still
  assumes one writer and a trusted local parent directory; it has no Gate `TrustStore`
  policy selected by the runtime, automatic retention, OS fault-injection/child-process
  crash proof, or power-loss claim. An assurance-only stateless Gate adapter and
  consume-once ordered publication replay now bind the closed receipt/stage profile to
  exact Gate signer/subject/segment boot and rebuild fresh read-only state
  (`CL-GATE-JOURNAL-REPLAY-01`). Historical evidence is rejected when its key is revoked
  in the supplied snapshot; there is no signed-time key-validity model, snapshot
  freshness proof, or support for other journal record kinds. The replay snapshot
  excludes the newly created current tail, and caller-supplied journal boot options alone
  do not prove a durable Gate boot. An opt-in fused startup API now derives the current
  journal Gate/boot/signer from the actual `RunningGate`, keeps the manager and
  same-verifier replay inseparable, rejects a mismatched or current-boot-resurrected
  tail, and withholds public mutable actor/journal access (`CL-GATE-JOURNAL-BINDING-01`). On
  restart it plans, signs, verifies, and semantic-previews every dangling call's linked
  current-boot `UnknownAfterPublish`, then checks future capture and conservative journal
  quota before prior-tail closure/current-segment creation. Semantic/current-boot-freshness
  failure never closes the old tail; for a nonempty Unknown batch, capture/logical-capacity
  failure also cannot burn a successor. An empty batch keeps ordinary recovery/quiescence
  semantics. Earlier insufficient-tail truncation or pending-artifact
  removal remains possible. Its action is reported on successful open and semantic-replay
  rejection, but another later recovery failure can return without an exact action report.
  Fresh genesis capacity and trace/capture
  compatibility are preflighted before directory access. Journal provision is allowed
  only with freshly provisioned durable Gate state, and restart requires open, but the
  selected journal path itself is not yet committed into the durable Gate configuration.
  Direct `VehicleActor` construction and the in-process spool remain available, and no
  runnable service selects the bound path. The private coordinator can create a locally
  sync-confirmed receipt/Called/publisher-result sequence through its test-only future seam,
  while startup can
  emit recovery Unknown records; neither path emits an abandonment/loss-summary event, and
  no coordinator-level append-fault, child-process crash, or disk-full campaign exists.
  A canonical Gate publication-stage payload and retained-state-bounded pure
  identity/link/transition reducer are now tested
  (`CL-PUBLICATION-EVIDENCE-PRIMITIVE-01`), including construction
  of a distinct-boot `UnknownAfterPublish` payload for a dangling call. Boot IDs are
  random, so the planning helper's not-previously-seen check does not authenticate
  later/current boot provenance, and generic replay permits multiple Unknown events
  from one claimed recovery boot. The primitives do not verify COSE, Gate-role signer
  binding, supplied-value/envelope correspondence, or the envelope size/work bound;
  themselves observe ordered recovered manager records, authenticate the current boot,
  reserve lifecycle capacity, append anything, or alter startup/actor state. The separate
  Gate startup binding closes recovered dangling calls only after authenticated replay and
  bounded precommit; its private lifecycle child adds the narrowly bounded local ordering in
  `CL-GATE-LIFECYCLE-01`. No runnable runtime or child-process crash-durability claim follows.
  Therefore evidence crash durability remains unproven under `CL-DURABLE-01`.
- **Configuration validation is not a deployment-package/ACL proof.** Gate actor
  construction is fallible and verifies its lease cap, receipt signing identity,
  key binding, and any future NCP lease's session/output epoch (`CL-CONFIG-01`). The
  startup library additionally permits only the current ACL profile, but it accepts an
  already-constructed evidence value; it does not load or verify a live ACL package
  (`CL-DURABLE-STARTUP-DEV-01`).
  The current ACL-only evidence type carries no session/output epoch or expected
  route/principal digest, so configuration validation cannot establish runtime final-key
  exclusivity. `CL-LIVE-TRANSPORT-01` is instead limited to its external synthetic ACL
  campaign and does not close this startup/service gap.
- **Production status.** Not production ready, certified, airworthy, or safe for
  deployment. No independent security review has been performed.

## Independent review record

The delivered P0 core was reviewed by an independent five-lens adversarial pass.
It confirmed the canonical-CBOR/COSE, policy fixed-point, and adapter-conversion
cores sound, and surfaced findings that were then fixed and regression-tested:

- **BUG-2 (fixed):** a monotonic-clock regression while ACTIVE now latches a fault
  and denies (`VehicleActor::mono_ok`) instead of extending a live lease deadline.
- **BUG-3 (fixed):** the reference plant no longer mutates output-authority/replay
  state before its reject checks, so a rejected command cannot wedge the live stream.
- **BUG-4 (fixed):** the intent's self-declared `controller_id`/signing-key id are
  now equality-checked against the admitted controller and the verified signer.
- **BUG-5 (fixed):** freshness age now rounds up (fail-closed), closing a sub-ms
  fail-open at the staleness cap.
- **B1 (clarified + wired):** the authorization-revision counter is now bumped by
  fault-latch and by the `revoke_active_lease` invalidation entry point; the
  mid-pipeline TOCTOU re-check remains structurally present but is inert under the
  current single-threaded in-process actor (it is scaffolding for a future
  concurrent actor). It is not claimed to defeat a real mid-pipeline race here.
- **BUG-1 (carved out):** the durable anti-rollback / restart-rollback gap above.

## Mapping to the completion checklist

See [`COMPLETION-CHECKLIST.md`](COMPLETION-CHECKLIST.md) for the per-item yes/no
with evidence pointers; every "no" maps to an entry above. The specification's own
down-label escape hatch is invoked explicitly: this is a narrower experimental
result than its full Definition-of-Done, and the profile/documentation state
exactly what remains unproven.
