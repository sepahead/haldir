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

None of the following is implemented or tested here. No result about them should
be represented as *validated*, *secure*, *complete-mediation*, or *hardware*.

- **Live secure transport / ACL delivery matrix.** There is no running Zenoh
  router, no mTLS, and no principal×route delivery/non-delivery campaign.
  Invariants **A1** (final-key exclusivity) and **A2** (controller confinement)
  are transport-level properties that in-process tests cannot establish.
  `haldir-transport-zenoh` is a documented seam, not an implementation.
- **`PRE_AUTHORITY_ACL_ONLY` as a proven live property.** It is used here as a
  declared compatibility *label* on the modeled adapter; the live ACL-exclusive
  publication property it names is **UNPROVEN** (needs the transport campaign).
- **Exact NCP adapter is not the selected live Gate path.** The off-by-default
  `real-ncp` feature compiles the exact pinned `ncp-core` v0.8.0 revision and its
  frozen-corpus/differential tests pass (`CL-NCP-REAL-01`). The in-process Gate
  still selects the dependency-light modeled adapter, and no Zenoh transport or
  plant delivery is present. Exact wire conformance therefore does not prove live
  publication, acceptance, application, or ACL exclusivity.
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
- **Cross-repository changes** to NCP, Crebain, or Engram. None were made.
- **Performance.** There is no performance/latency campaign. Any timing number is
  "measured on named host/kernel/load; not hard real-time"; **p99/p99.9 on named
  hardware is UNPROVEN**.
- **TLA+ model scope.** The bounded model now checks green under the SHA-verified
  TLA+ v1.7.4 jar (`CL-FORMAL-01`, GitHub run `29211573130`). This proves only the
  registered finite model; the Rust `model` tests remain an independent executable
  encoding, and neither result proves the absent live transport or durable runtime.
- **`missing_docs` hardening.** Deferred; the workspace does not yet
  `deny(missing_docs)`. Crate- and item-level docs are written voluntarily.
- **Durable anti-rollback / restart rollback protection.** The default P0 actor
  constructor still uses an **in-memory** anti-rollback store. A separate recovered
  constructor now accepts only a non-cloneable booted-store capability produced after
  `begin_boot` verifies the authenticated Gate binding and durably commits a fresh
  `BootContext`; the configured boot ID must match that capability. Lease terms commit
  through the injected store before authority becomes active, and an unavailable commit
  terminally faults the actor. The HMAC/envelope/anchor mechanism,
  Unix atomic-file backend, boot-ID binding/repeat latch, durable anti-rollback wrapper,
  injection checks, and failure ordering are unit tested (`CL-DURABLE-PRIMITIVE-01`).
  No runnable service provisions the storage key, entropy, file path, or an external
  non-rewindable anchor, and no child-process kill matrix has established old-or-new
  behavior under actual crashes. Therefore end-to-end **cross-restart** rollback
  protection of B11/B12 remains **NOT established**.
- **Filesystem/platform durability scope.** `AtomicFileSnapshot` uses a same-directory
  `create_new` temporary, file `sync_all`, Unix rename, and parent-directory
  `sync_all`, and assumes a trusted local POSIX filesystem plus exclusive writer.
  It is unsupported on Windows, cannot eliminate ancestor-path races using only
  safe path-based standard-library APIs, and does not claim macOS `F_FULLFSYNC`,
  power-loss, network/FAT/overlay filesystem, or adversarial directory-rewind
  guarantees. A same-filesystem anchor cannot close `CL-DURABLE-01`.
- **Configuration validation is not a deployment-package/ACL proof.** Gate actor
  construction is fallible and verifies its lease cap, receipt signing identity,
  key binding, and any future NCP lease's session/output epoch (`CL-CONFIG-01`).
  The current ACL-only evidence type carries no session/output epoch or expected
  route/principal digest, so configuration validation cannot establish live final-key
  exclusivity; that remains `CL-LIVE-TRANSPORT-01`.
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
