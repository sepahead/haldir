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
- **Real `ncp-core` / Zenoh dependency.** `haldir-ncp08` is a P0 semantic model of
  the NCP v0.8.0 command frame. It is pinned by digest to the real release but
  does not link the upstream crate. Conformance against the upstream frozen
  corpus is not run here.
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
- **TLA+ model checking.** TLC is not installed in this environment.
  `formal/HaldirAuthority.tla` is authored but **not model-checked**; the
  CI-enforced encoding of those invariants is the `model` test module in
  `haldir-state`.
- **`missing_docs` hardening.** Deferred; the workspace does not yet
  `deny(missing_docs)`. Crate- and item-level docs are written voluntarily.
- **Production status.** Not production ready, certified, airworthy, or safe for
  deployment. No independent security review has been performed.

## Mapping to the completion checklist

See [`COMPLETION-CHECKLIST.md`](COMPLETION-CHECKLIST.md) for the per-item yes/no
with evidence pointers; every "no" maps to an entry above. The specification's own
down-label escape hatch is invoked explicitly: this is a narrower experimental
result than its full Definition-of-Done, and the profile/documentation state
exactly what remains unproven.
