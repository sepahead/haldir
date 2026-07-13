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
entropy, locks, or directories. No runnable service selects that declaration, binds it to
strict transport, or proves credential custody. Successful declared-live startup does now
mint the private move-only capability required by the live coordinator; exact reference and
copied-report paths cannot reach its concrete publisher method. Crebain is intended to remain
the sole owner of final command application and vehicle-specific safe action; that integration
is also still unproven.

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
  process-local capability. No runnable service selects either path.
  Exact selection is also exercised through durable startup and the actor Called boundary.

### What is implemented and tested locally (the P0 pure core)

The complete offline-testable reference-monitor core: canonical contracts, COSE/Ed25519
trust, controller/backend admission, challenge-bound mission leases with anti-rollback,
bounded authority/session/stream/replay state machines with restart semantics, a
fixed-point deterministic policy engine, a deterministic reference plant with staged
evidence, an opaque single-slot prepare/call typestate that gates first command access
on actor revalidation and charges history only on caller-asserted modeled returned-ok
(`CL-PUBLICATION-STATE-01`), the Gate-owned NCP v0.8.0 modeled output adapter plus an
opt-in, explicitly selectable exact upstream adapter (`CL-NCP-REAL-01`), a bounded evidence
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
success
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
remains externally read-only and no runnable service selects its internal coordinator.
One test composes the production declared-live startup code with injected in-memory backends
and the actual journal manager through live coordinator construction; activated
decision/Called and route-result composition still uses a clearly test-only binder around a
preactivated actor. The concrete permit pool is a bounded slot primitive, but no canonical
service-wide pool, queue, publisher worker, or runnable transport binding is selected. Publisher-result
ordering, cold drop before first poll, pending timeout-as-drop, panic unwind, and synthetic
terminal-record faults use test-only seams; no live Zenoh session executes the concrete
coordinator method in tests. The consuming future exists only after Called is locally
sync-confirmed, so cold drop, pending drop, and unwind all leave Called for restart
classification as `UnknownAfterPublish`; cold drop is not rejection before Called. A definite
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
controller-intent ACL subset for its ephemeral test PKI. No runnable Gate service selects
the `DeclaredLiveZenoh` startup profile or coordinator path, and certificate
lifecycle/reconnect, bypass, application, and credential custody remain unproved.
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
```

`just ci` (or the equivalent cargo/python commands in `.github/workflows/ci.yml`) is the
canonical gate.

## License

Dual-licensed under [Apache-2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT), at your option.
