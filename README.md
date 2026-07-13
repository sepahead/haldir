<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/logo-dark.svg">
    <img alt="Haldir Gate logo" src="assets/logo-light.svg" width="200">
  </picture>
</p>

# Haldir Gate

**Experimental, inline, backend-aware mission-authorization reference monitor for the Sepahead ecosystem.**

Haldir Gate's implemented core accepts a signed, typed controller **intent**, proves that
the requesting controller deployment and mission lease are currently admissible, evaluates
bounded deterministic policy against trusted state, and — only on ALLOW — prepares a fresh
plant-facing NCP command under Gate's own stream. The static secure-reference profile reserves
final-route publication to Gate, and a retained synthetic mTLS campaign has shown that only
Gate among all eight configured certificate principals reached the allowed remote receivers on
that route. The startup library rejects a `DeclaredLiveZenoh` template unless the exact adapter
is selected and the `live-zenoh` feature is compiled, before startup-owned backend calls,
entropy, locks, or directories. An off-by-default no-network kernel now consumes that
startup capability and one bounded caller-supplied initial state/challenge/signed-lease bundle.
Before lease-term commit or activation, it derives the exact intent route from the verified,
admission-bound controller and requires the signed lease route to match. Only that move-only
route-bound capability can create the lower publisher-bound service. A separate outer aggregate
consumes it with one caller-opened session wrapper and bounded ingress limits, then internally
derives the matched publisher and exact accepted-controller-route ingress from the same session lineage
(`CL-LIVE-INGRESS-BINDING-01`). A cloneable local handle latches a request that lets the
shutdown-aware consuming method return the aggregate owner before a retained retry or wake an idle
receive; once an event is selected, request-driven cancellation does not occur and the request
remains latched for the next owner. The request is cooperative: success is not a cleanup
acknowledgment, legacy `process_next` ignores it, and clones must be restricted. No authenticated
runnable Gate service selects the aggregate and authenticates the provenance or delivery of the
caller-supplied state and nonce.
The additional off-by-default `live-gate-dev-smoke` feature now provides two explicitly
development-only examples: one offline provisioner for a disposable local state/journal fixture,
and one `OpenExisting`-only target that locally activates the fresh boot, opens a caller-supplied
strict client configuration, binds the concrete aggregate, and immediately invokes explicit
local shutdown under a separate outer lock. The target processes zero intents and invokes zero
command publications. A retained clean-source synthetic campaign now proves those concrete local
calls and returns against the pinned router and fresh ephemeral Gate PKI for one disposable fixture
(`CL-LIVE-GATE-DEV-BIND-01`; `evidence/12-live-gate-dev-smoke`, source commit
`3a75c039c3e73b999a74741b5633ee43a0a69e97`). It is not selected by an authenticated package
loader, control plane, worker, or supervisor. It has no protected credential loader and proves no peer identity,
credential custody, handle exclusivity, delivery, or remote cleanup. Successful declared-live
startup mints the private move-only capability required by the live coordinator;
exact reference and copied-report paths cannot reach its concrete publisher method. Crebain is
intended to remain the sole owner of final command application and vehicle-specific safe action;
that integration is also still unproven.

> A controller signs a typed Haldir action request. Gate independently validates the
> controller deployment, mission lease, current NCP session, source/state evidence, and
> deterministic policy, then constructs a **new** NCP `CommandFrame` with Gate-owned stream
> position and creation time. In the intended deployment, controllers are provisioned only
> for their exact intent routes and never receive the final-route publication credential;
> the static package and synthetic live command/intent subset test that separation, but no
> packaged Gate/Crebain runtime has established it end to end.

## Status — read this first

This repository is an **experimental research implementation**. It is **not** production
ready, certified, airworthy, or safe for deployment. Honesty vocabulary is normative here:
*implemented*, *compiled*, *tested*, *validated*, *published*, *received*, *accepted*,
*applied*, and *observed* mean exactly what `docs/HALDIR-NCP-V0.8.0-TRIPLE-CHECKED-AUDIT-AND-IMPLEMENTATION-SPECIFICATION-2026.md`
says they mean.

- **Command-authority profile:** `PRE_AUTHORITY_ACL_ONLY` (NCP `v0.8.0`, increment 1).
- **Assurance profile implemented here:** `assurance-reference-v1` — one vehicle, one
  controller, one Gate, one **deterministic reference plant**, `Hold` + local-NED velocity,
  no live network, no neural runtime, no physical hardware.
- **NCP baseline pinned:** tag `v0.8.0`, commit `2f5bd586d4bb20c90362bb6f5698b7f64057ba4e`,
  wire `0.8`, contract hash `d1b50a2d8a265276`; the optional `real-ncp`
  conformance adapter compiles that exact revision and replays its frozen corpus. Gate template
  startup carries both a closed modeled/exact adapter selection and an explicit
  `GateRuntimeProfile` declaration. `InProcessReference` retains the P0 paths;
  `DeclaredLiveZenoh` requires `ExactNcpV0_8Json` plus the compiled `live-zenoh` feature before
  the listed startup-owned backend calls, entropy, locks, or directory access. Successful
  declared-live startup separately retains a private move-only capability required by the
  live coordinator typestate; `StartupReport` remains observation only. The declaration and
  profile choice remain caller-supplied; startup internally derives the unauthenticated,
  process-local capability. A no-network activation typestate additionally requires one
  caller-supplied initial trusted state, nonce, and signed lease, and checks the lease's intent
  route against the canonical realm/session/verified-controller route before authority commits.
  The lower live service consumes that route-bound result plus a preconstructed matched publisher.
  The outer Zenoh aggregate instead derives its publisher and exact ingress internally from one
  supplied session wrapper. Its shutdown-aware consuming method preserves the owner when a local
  request wins at an idle boundary and never request-cancels an already-selected event. The
  request remains cooperative rather than enforced. The separate development smoke target can
  open and immediately close the aggregate from an existing disposable fixture; the retained
  development campaign proves those local calls while processing zero intents and publishing zero
  commands. No authenticated package loader/runtime wiring provides ongoing control/state delivery,
  protected credential custody, a processing loop, or supervision.
  Exact selection is also exercised through durable startup and the actor Called boundary.

A separate, non-runnable deployment primitive strictly verifies a canonical signed package against
separately supplied bootstrap trust and an exact expected authority/Gate/realm/vehicle/profile/
runtime policy. The standalone API does not prove where its caller obtained that policy. It then
consumes and retains one exact owned byte string for every closed required artifact role. On Linux
and macOS,
an optional fused source accepts an already-open directory capability, uses each signed logical ID
as one flat non-dot leaf, opens each leaf once without following its final symlink, captures bounded
bytes from that same handle, and resolves the complete captured set within the same consuming call.
The caller remains responsible for selecting and protecting the root directory. The separate durable v3 anti-rollback
primitive can atomically commit caller-supplied neutral revision/
payload-digest values with a fresh boot, rejecting rollback, same-revision equivocation, implicit
legacy binding, and later plain-boot downgrade. No type-enforced path makes those values originate
at the verifier (`CL-DEPLOYMENT-PRIMITIVE-01`). No Gate startup path consumes the resolved typestate
yet. A separate strict, bounded NCP compatibility-artifact decoder exact-matches the implemented
frozen command subset to every compiled pin, but no private composition binds that proof to the
signed artifact role (`CL-NCP-COMPATIBILITY-01`). There is no authenticated/protected root or
credential opener, semantic use of the other artifacts, or running-binary/configuration binding, so
`CL-DEPLOYMENT-PACKAGE-01` remains unproven.

### What is implemented and tested locally (the P0 pure core)

The complete offline-testable reference-monitor core: canonical contracts, COSE/Ed25519
trust, controller/backend admission, challenge-bound mission leases with anti-rollback,
bounded authority/session/stream/replay state machines with restart semantics, a
fixed-point deterministic policy engine, a deterministic reference plant with staged
evidence, an opaque single-slot prepare/call typestate that gates first command access
on actor revalidation and charges history only on caller-asserted modeled returned-ok
(`CL-PUBLICATION-STATE-01`), the Gate-owned NCP v0.8.0 modeled output adapter plus an
opt-in, explicitly selectable exact upstream adapter (`CL-NCP-REAL-01`), a strict bounded
command-subset compatibility-artifact decoder (`CL-NCP-COMPATIBILITY-01`), a bounded evidence
spool that holds the Gate-signed decision receipts, a bounded locked Unix
signed-segment manager with opt-in bounded ordered recovery snapshots
and manager-affine conservative logical capacity reservations
(`CL-EVIDENCE-MANAGER-01`), a stateless Gate trust/COSE adapter and fresh ordered
publication replay (`CL-GATE-JOURNAL-REPLAY-01`), a staged fused current-boot journal
binding that closes recovered dangling calls with signed successor-boot
`UnknownAfterPublish` records before returning the runtime
(`CL-GATE-JOURNAL-BINDING-01`), a crate-private consuming lifecycle coordinator that
requires a non-cloneable slot from a bounded permit pool, reserves three logical journal
units before decision/output allocation, locally sync-orders the exact receipt,
`PublishCalled`, and local-return record, and keeps a restarted Gate fail-closed when any
called-or-later history needs external clearance. A successful `DeclaredLiveZenoh` plus
exact-NCP startup privately mints a move-only process-local capability. The live coordinator
constructor consumes that capability, cross-checks the retained profile and actor selection
before clock sampling, and carries a private marker through every runtime-returning state;
error and fatal paths destroy it. The off-by-default concrete publisher method exists only on
the resulting live Called type. It
consumes one Called state and one concrete strict publisher, rejects a publisher whose exact
route differs from the coordinator's actor realm/session before frame access or invocation,
awaits a matched publisher once, and returns it only after local `Ok` plus terminal journal
success. Before public service binding, the no-network `DeclaredLiveGateKernel` consumes one
bounded caller-supplied initial trusted-state/challenge/signed-lease bundle. Its validator
derives the canonical intent route from the verified, admission-bound lease controller and
rejects a differing signed route before challenge consumption, durable term commit, revision
change, or activation. The resulting non-cloneable route-bound capability is tested through
fake-publisher service binding. The public `live-zenoh` service kernel then encloses that
coordinator, one concrete publisher, the accepted intent binding, and an internally created
fixed one-slot pool. Its consuming `process_one` API
hard-bounds one raw, publicly constructible `IntentIngressEvent` before capacity, clock, or
actor access and returns the sole service owner only after
a no-output decision, pre-Called rejection, pre-mutation unavailability, or locally successful
publish plus confirmed terminal record. Fatal/cancellation/publisher-error/terminal-boundary
failure paths return no service or publisher capability
(`CL-GATE-LIFECYCLE-01`), canonical linked publication-stage
payload/reduction primitives (`CL-PUBLICATION-EVIDENCE-PRIMITIVE-01`), and
authenticated snapshot/generation-anchor primitives with commit-before-mutation
anti-rollback tests,
Unix atomic-file mechanics, classified local-development recovery, and Gate-bound
durable startup/boot-ID mechanisms (`CL-DURABLE-PRIMITIVE-01`,
`CL-DURABLE-STARTUP-DEV-01`). Template startup validates `DeclaredLiveZenoh` against the
compiled feature and exact adapter before its backend traits, entropy source, lock, or local
directory can be touched. The startup report retains the validated declaration for
observation, while the separate private capability—not the copyable report—authorizes live
coordinator construction. An exact `InProcessReference` startup and a forged report value are
both rejected before coordinator clock access. The declaration is cooperative,
unauthenticated, and not durably committed; public `GateConfig`/direct `VehicleActor`
construction bypasses template startup and cannot mint this coordinator capability. The actor
can consume the non-cloneable booted-store capability returned only after a fresh matching boot
commit, and faults if a term commit is unavailable.
The startup library explicitly provisions or opens those paths, but no service package
loads protected secrets or a deployed external non-rewindable anchor. The direct
`VehicleActor` profile still selects the lossy in-process spool, while the new bound type
remains externally read-only. Only the explicitly development-only smoke example constructs the
live aggregate, and then shuts it down without receiving or processing an intent.
Production declared-live startup with injected in-memory backends and the actual journal manager
is tested through coordinator construction only. Separately, tests wrap an initially inactive
actor and actual journal manager in a test-minted marked capability, then exercise local
state/challenge/signed-lease activation, canonical intent-route validation, and the shared
fake-publisher service-binding core. Decision/Called and publisher-result fault composition still
uses clearly test-only publisher seams. Separate fake session/ingress tests exercise aggregate
binding, journal-capacity retention/retry, closure, drop, and explicit shutdown ordering; no real session is opened. The
same seam proves that a prior request precedes receive and retained retry, while an in-flight
publication reaches its ordinary transition before the latched request is returned. A direct
helper test proves that a later request wakes a pending idle receive. The
service kernel owns one canonical capacity-one pool for its own
process-local lifetime. The outer aggregate retains one supplied session wrapper and internally
derived ingress, but it is not a credential-opening package, exclusive handle owner, separate
publisher worker, supervisor, or runnable transport package. Its local request latch is not an
OS-signal runner, an in-flight timeout, durable-journal finalization, confirmed remote session
retirement, or graceful production shutdown. Publisher-result
ordering, cold drop before first poll, pending timeout-as-drop, panic unwind, and synthetic
terminal-record faults use test-only seams; no live Zenoh session executes the concrete
service/coordinator method in tests. A cold-dropped service `process_one` future never polls
and therefore creates no Called record; after its first poll reaches the publisher await,
pending drop or unwind leaves Called for restart classification as `UnknownAfterPublish`.
The lower-level Called publisher future already exists after Called is sync-confirmed, so even
its cold drop leaves Called. A definite
synthetic terminal failure before append likewise reopens as Unknown, while synthetic
ambiguity injected after an actual terminal append and sync replays that terminal record.
Prepared cancellation or pre-call rejection still leaves unreclaimed Prepared evidence.
Actual OS-I/O, child-process, and power-loss faults remain untested, and end-to-end crash
durability remains out of P0 (`CL-DURABLE-01`). The composed
Gate runtime has its 13-stage decision pipeline,
and a deterministic adversarial range + end-to-end
acceptance campaign.

Every load-bearing claim above is reconciled against its evidence in
[`docs/CLAIM-LEDGER.md`](docs/CLAIM-LEDGER.md); statements not backed by a test or CI gate
there are marked UNPROVEN or out of scope rather than asserted.

The P0 result is not completion of the full project roadmap. The roadmap-wide,
phase-by-phase status and current ecosystem blockers are tracked in
[`docs/ROADMAP-STATUS.md`](docs/ROADMAP-STATUS.md).

### What is deliberately **out of scope** and **not claimed** here

See [`docs/LIMITATIONS.md`](docs/LIMITATIONS.md). In short: exact routes, an
off-by-default strict Zenoh 1.9 mTLS boundary, and a deterministic default-deny ACL
package now exist, and the retained synthetic campaign proves the fixed final-command/
controller-intent ACL subset for its ephemeral test PKI. A public no-network activation and
single-owner live service kernel plus an aggregate-local session/ingress owner exist, but their
initial state/challenge delivery remains caller-supplied. The aggregate has a stop-only local
safe-boundary request handle. A development-only example opens an externally configured session,
binds, and immediately shuts down from a disposable local fixture; retained evidence proves only
those local returns with zero processing/publication and does not select an authenticated ongoing
`DeclaredLiveZenoh` control path. Certificate lifecycle/reconnect, bypass, delivery, remote session
retirement, application, and credential custody remain unproved.
NEST/Engram controllers, Crebain/PX4-SITL, neuromorphic backends
(Norse/Rockpool/XyloSim/SpiNNaker), and physical hardware remain unintegrated; no
application, complete-mediation, production-security, or hardware claim is made.

## Layout

See the normative specification in `docs/` and `docs/ASSURANCE-PROFILES.md`. Crates live
under `crates/`; offline tooling under `tools/`; the configuration-only secure Zenoh fixture
under `deploy/secure-reference-v1/`; formal models under `formal/`; adversarial scenarios
under `crates/haldir-range/`.

## Build

```bash
cargo build --workspace --locked
cargo test  --workspace --locked
cargo build -p haldir-gate --examples --features live-gate-dev-smoke --locked
```

The final command only compiles the development evidence targets. The offline provisioner and
`OpenExisting`-only bind/shutdown example are not a production runbook, and compilation is not
live-session evidence.

From a clean committed tree, a disposable candidate can be generated and independently checked:

```bash
python3 tools/run-live-gate-dev-smoke.py \
  --output target/live-gate-dev-smoke/<unique-run>
python3 tools/verify-live-gate-dev-smoke.py \
  --evidence target/live-gate-dev-smoke/<unique-run>/evidence
```

Use one newly provisioned fixture per campaign. Generator output remains outside retained evidence
until the independent verifier passes and a separate, reviewed promotion places it at
`evidence/12-live-gate-dev-smoke`; neither command changes claim status by itself.

`just ci` (or the equivalent cargo/python commands in `.github/workflows/ci.yml`) is the
canonical gate.

## License

Dual-licensed under [Apache-2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT), at your option.
