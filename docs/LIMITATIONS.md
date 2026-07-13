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
- **Declared-live validation plus a development target is not an authenticated live service.** The off-by-default
  `real-ncp` feature compiles the exact pinned `ncp-core` v0.8.0 revision and its
  frozen-corpus/differential tests pass (`CL-NCP-REAL-01`). `GateConfigTemplate` now carries
  both the closed adapter selection and an explicit `GateRuntimeProfile`.
  `InProcessReference` retains the dependency-light P0 paths. `DeclaredLiveZenoh` is rejected
  unless `live-zenoh` was compiled and `ExactNcpV0_8Json` was selected; that rejection occurs
  before startup-owned backend-trait calls, entropy, locks, or local-directory access. A
  successful `StartupReport` retains the declaration only as observable process-local data.
  Successful declared-live startup separately mints a private, non-cloneable capability. The
  live coordinator constructor consumes it and cross-checks both the retained declaration and
  exact actor wire profile before clock sampling. Its marker is carried through every
  runtime-returning coordinator state; error and fatal paths destroy it. The concrete
  strict-publisher method exists only on the live Called type. Exact `InProcessReference`,
  copied-report, and modeled-actor paths cannot construct that type.

  The declaration is supplied cooperatively by the caller. It is not authenticated, signed,
  loaded from a protected package, or committed into durable state, and it does not prevent
  downgrade on restart. Public `GateConfig` and direct `VehicleActor` construction bypass the
  template-startup check and remain outside the internal capability chain. The process-local
  capability is also not authenticated or durable and does not prevent a service from selecting
  `InProcessReference` after restart. A public feature-gated no-network kernel can consume that
  capability plus one bounded caller-supplied trusted-state/challenge/signed-lease bundle. It
  derives the canonical intent route from the verified, admission-bound controller and rejects a
  differing signed lease route before challenge consumption, durable term commit, revision change,
  or activation. Only the resulting move-only route-bound capability can bind the lower public
  service to a preconstructed matched publisher. A separate outer
  `DeclaredLiveGateZenohService` consumes that same capability, one caller-opened session wrapper,
  and bounded ingress limits; it re-derives the accepted-controller route and internally constructs
  the publisher and exact ingress from the same supplied session lineage. The separate
  `live-gate-dev-smoke` examples use public deterministic fixture keys: an offline target explicitly
  provisions disposable state+journal, while the networked target refuses provisioning, opens that
  existing fixture, performs caller-local activation, consumes a caller-supplied strict-client
  configuration, binds, and immediately invokes explicit shutdown under its own outer lock. It
  receives/processes no intent and invokes no command publication. The retained clean-source
  campaign in `evidence/12-live-gate-dev-smoke` proves one fresh offline `ProvisionNew` followed by
  live `OpenExisting`, strict local session open, concrete aggregate bind, and immediate local
  shutdown return with zero processing/publication (`CL-LIVE-GATE-DEV-BIND-01`). Neither target
  authenticates or continually supplies control/state inputs, loads protected credentials, or
  supplies a plant binding. The retained run proves neither authenticated package/control
  provenance, peer identity, exclusive custom-CA trust or handle ownership, publication, delivery,
  acceptance, application, credential custody, bypass closure, ACL exclusivity, nor remote
  undeclare/session retirement. The target preflights the exact state files and bounded journal namespace before
  committing its fresh boot, publishes its result atomically outside the fixture, and attempts to
  publish a bounded cleanup classification for failures after the outer lock is acquired. Result
  publication is best-effort under storage failure; fixture/result preflight and lock-acquisition
  failures occur before that reporting boundary and produce no result JSON. The disposable
  journal permits at most 32 segments; provisioning consumes the first, and an attempted reopen
  can close the active tail and consume another even if the later session open or bind fails.
  Exhausted or uncertain fixtures must be discarded and reprovisioned rather than treated as a
  restartable production store. The pathname checks and advisory outer lock assume a cooperative,
  trusted host; they are not confinement against a host that replaces directories. The campaign
  runner cleans its named containers, network, image, copied fixture, and ephemeral private-key
  directories on handled exits, but abrupt process/daemon/host loss can leave material below the
  ignored `target/live-gate-dev-smoke/` output and requires manual cleanup. BuildKit caches are not
  retained campaign evidence and are outside that runtime cleanup result. One successful fresh run
  is not crash-durability, retry, reconnect, supervision, or endurance evidence.
- **A public single-owner kernel exists; deployment binding is limited to a disposable smoke.** The actor keeps
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
  (`CL-GATE-LIFECYCLE-01`). Under its off-by-default `live-zenoh` feature, only a coordinator
  descended from the private declared-live startup capability exposes the concrete method.
  Production coordinator code derives the exact pinned command route from the actor
  realm/session, terminally rejects a mismatched publisher before frame access or invocation, lends the
  frame only to one awaited call on a matched concrete strict publisher, returns that
  capability only after local `Ok` plus terminal journal success, and returns neither
  runtime nor publisher after error. Test-only future cases cover dropping the consuming
  future before its first poll without invoking test publisher code, dropping it after
  `Pending` as an external-timeout model, and catching an unwind from a panic while polling
  the test publisher future. All occur after locally sync-confirmed Called and therefore
  reopen as `UnknownAfterPublish` rather than inventing ReturnedError. An explicit local
  publisher error or definite Gate rejection can record ReturnedError. These are not live
  Zenoh tests.

  `DeclaredLiveGateKernel` first consumes the marked coordinator and fail-stop primes an initially
  inactive actor with one caller-supplied trusted state, challenge, and signed lease. The route
  validator runs after signature/admission checks but before the lease's challenge/term/activation
  commit, and the returned `LiveIntentRouteBoundGate` retains the sealed coordinator and exact
  canonical controller route.
  This is static local priming, not authenticated state provenance, signed challenge publication,
  lease delivery, refresh, revocation, or preemption. `DeclaredLiveGateService` consumes only that
  ready capability plus one preconstructed matched publisher, privately owns one fixed capacity
  slot, and returns the sole service owner only on safe continuation. Its input event type remains
  publicly constructible and is not transport provenance evidence; the service enforces only the
  hard envelope and route-length bounds before capacity, clock, and actor work. Cold drop before
  the outer service future's first poll performs no decision/clock sample/Called; pending drop
  after publisher polling destroys the owner after Called. Tests compose an initially inactive
  test-minted marked-live actor, the real journal manager, canonical local activation, and the shared fake-
  publisher binding core; lifecycle/result faults still use test publisher seams. The slot is
  canonical only within that process-local service lifetime; it is not an authenticated deployment
  queue.

  The outer Zenoh aggregate accepts no controller, route, publisher, or raw-event override. It
  retains the supplied session wrapper, an internally declared bounded remote-only exact ingress,
  and the publisher-owning lower service; `process_next` receives from that ingress and keeps a
  journal-capacity or restart-clearance refusal private for ordered retry. An input/key/output-
  capacity refusal is unreachable through the owned topology and fail-stops as an invariant
  violation. A cloneable process-local stop handle is monotonic, and
  `process_next_or_shutdown` returns the same aggregate before a retained retry or wakes an idle
  receive when that request wins the boundary. A successful request call acknowledges only local
  latch acceptance, not aggregate return or cleanup; the owner/future may concurrently drop. The
  legacy `process_next` ignores the latch, and every clone is an irreversible cooperative stop/
  denial capability, so a future runner must restrict clones and exclusively use the
  shutdown-aware method. If a concurrent event is selected before the request is observed, it
  is processed without request-driven cancellation; the request remains latched for the next returned
  owner. There is no timeout for a hung in-flight transport call and no OS-signal runner or
  supervisor uses this API yet. Cancelling the consuming future itself still drops the aggregate,
  so a future runner must signal through the handle and await the ownership-returning transition.
  Its explicit shutdown attempts
  undeclare/drain, then drops the publisher-owning service, then closes the retained wrapper.
  That is local transport cleanup, not a durable evidence-journal footer/finalization operation
  or confirmed remote session retirement. Dropping the service releases its durable instance
  lock before session close returns. The development bind target adds a separate target-local lock
  held from before configuration/session setup through its local aggregate-shutdown return; a production package still
  needs an authenticated, deployment-wide version of that rule.
  Offline tests use an explicit fake session/ingress/publisher seam and prove only local
  composition and ownership ordering; no test opens the concrete session, declares the concrete
  subscriber, or invokes the concrete publisher. `SecureZenohSession` is move-only but wraps a
  shared session, and public borrowing constructors can mint typed ingress/publisher handles before
  the wrapper is consumed. The aggregate therefore does not prove exclusive credentials, a sole
  global session/subscriber/publisher handle, or confirmed remote cleanup after cancellation/drop.
  No production control plane, protected credential-opening package, publisher worker, or supervisor
  selects it, and no graceful production-shutdown property is established. The development target's
  immediate shutdown is only a local cleanup call. A Called record alone is a
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
  abandonment or loss-summary record. Test-only terminal injection covers publisher `Ok`
  and `Err` for a definite failure before terminal append and a synthetic
  `AppendCommitAmbiguous` returned after the real terminal append and sync. Reopen finds
  Unknown in the first case and the exact terminal state in the second; neither the consumed
  bound runtime nor supplied publisher capability is returned after either failure. This does
  not test OS partial writes or sync failures,
  disk-full behavior, real append-commit ambiguity on either recovery side, panic-abort or service
  supervision, live-session cancellation/timeout/panic, child-process crash, a shared
  clock origin, or power loss. The concrete
  method is compile-tested but not live-invoked; the development target never calls it. This is not a publication,
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
- **Deployment-package primitive is not a deployed package loader.** `haldir-deployment`
  strictly verifies one canonical v1.0 COSE package against bootstrap trust, revocations, and
  a separately supplied exact expected deployment authority/Gate/realm/vehicle/class/runtime/
  NCP-wire policy. The standalone API exact-matches that policy but cannot establish where its
  caller obtained it; future Gate glue must source policy from bootstrap state rather than derive
  it from the package. The contract binds distinct nonzero state/journal IDs and one canonical,
  unique logical ID,
  nonzero size, and deployment-artifact-domain digest for every closed required artifact role.
  Its consuming resolver preflights externally supplied per-artifact/total bounds and retains
  caller-owned verified byte buffers behind a resolved typestate, with no path or reopen API.
  Bootstrap-policy provenance, bootstrap-revocation freshness, secure path traversal/opening,
  semantic parsing or use of any artifact, correspondence to the running executable, and NCP
  compatibility-record semantics remain outside that boundary. `GateConfigTemplate` is still
  caller-constructed, and no Gate startup consumes the resolved typestate or proves verification
  precedes its entropy, durable, secret, or network effects. The durable v3 state primitive can
  atomically bind a package revision/payload digest with a fresh boot, but its lower public method
  accepts neutral values and only a later Gate glue typestate can require that they came from this
  verifier. This proves `CL-DEPLOYMENT-PRIMITIVE-01`, not `CL-DEPLOYMENT-PACKAGE-01`.
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
  the current durable payload shape is v3, a pre-v3 executable rejects rewritten state.
  Valid canonical v1/v2 state is preserved only with an explicit `MigrationRequired` package
  marker; unrelated v3 writes preserve that marker, and no package can bind it implicitly. Any
  ordinary use of a pristine v3 store also makes later first package binding migration-required.
  A package-bound store rejects the plain boot path; same revision/digest may restart with a fresh
  boot, a higher revision advances the pair, and rollback or same-revision/different-digest fails
  before mutation. The package pair and boot share one authenticated snapshot commit, but no Gate
  package loader currently selects that path.
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
- **Durable evidence lifecycle is selected only by the disposable development examples.**
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
  Direct `VehicleActor` construction and the in-process spool remain available. The offline
  provisioner and `OpenExisting` bind target make the bound path mandatory only inside those
  explicitly development-only processes; no authenticated deployment package makes it universal.
  The public service kernel and its
  private coordinator can create a locally
  sync-confirmed receipt/Called/publisher-result sequence through its test-only future seam,
  and its test-only cold-drop, pending timeout-as-drop, panic-unwind, and synthetic
  terminal-fault matrix can drive reopen to the journal-supported Unknown or terminal state;
  startup emits the required recovery Unknown records. Neither path emits an
  abandonment/loss-summary event, and no OS-level append/write/`sync_data` fault-injection,
  disk-full, child-process crash, or power-loss campaign exists.
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
  `CL-GATE-LIFECYCLE-01`. No production runtime or child-process crash-durability claim follows.
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
