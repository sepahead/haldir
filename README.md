# Haldir Gate

**Experimental, inline, backend-aware mission-authorization reference monitor for the Sepahead ecosystem.**

Haldir Gate accepts a signed, typed controller **intent**, proves that the requesting
controller deployment and mission lease are currently admissible, evaluates bounded
deterministic policy against trusted state, and — only on ALLOW — originates a fresh
plant-facing NCP command under Gate's own stream and exclusive final-route publication
capability. Crebain remains the sole owner of final command application and vehicle-specific
safe action.

> A controller signs a typed Haldir action request. Gate independently validates the
> controller deployment, mission lease, current NCP session, source/state evidence, and
> deterministic policy, then constructs a **new** NCP `CommandFrame` with Gate-owned stream
> position and creation time. Controllers never receive the credential or capability that
> publishes the final plant command key.

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
  wire `0.8`, contract hash `d1b50a2d8a265276`.

### What is implemented and tested locally (the P0 pure core)

The complete offline-testable reference-monitor core: canonical contracts, COSE/Ed25519
trust, controller/backend admission, challenge-bound mission leases with anti-rollback,
bounded authority/session/stream/replay state machines with restart semantics, a
fixed-point deterministic policy engine, a deterministic reference plant with staged
evidence, the Gate-owned NCP v0.8.0 output adapter (modeled P0 semantic layer), a bounded evidence
spool that holds the Gate-signed decision receipts (lossy on overflow; a durable,
tamper-evident signed journal is out of P0, see `CL-DURABLE-01`), the composed Gate runtime
with its 13-stage decision pipeline, and a deterministic adversarial range + end-to-end
acceptance campaign.

Every load-bearing claim above is reconciled against its evidence in
[`docs/CLAIM-LEDGER.md`](docs/CLAIM-LEDGER.md); statements not backed by a test or CI gate
there are marked UNPROVEN or out of scope rather than asserted.

### What is deliberately **out of scope** and **not claimed** here

See [`docs/LIMITATIONS.md`](docs/LIMITATIONS.md). In short: live secure-Zenoh mTLS/ACL
delivery matrix, real `ncp-core` dependency wiring, NEST/Engram controllers, PX4-SITL,
neuromorphic backends (Norse/Rockpool/XyloSim/SpiNNaker), cross-repository Crebain/Engram
changes, and physical hardware. These are architected as typed seams but are **not**
implemented or tested in this deliverable, and no claim is made about them.

## Layout

See the normative specification in `docs/` and `docs/ASSURANCE-PROFILES.md`. Crates live
under `crates/`; offline tooling under `tools/`; formal models under `formal/`; adversarial
scenarios under `crates/haldir-range/`.

## Build

```bash
cargo build --workspace --locked
cargo test  --workspace --locked
```

`just ci` (or the equivalent cargo/python commands in `.github/workflows/ci.yml`) is the
canonical gate.

## License

Apache-2.0 OR MIT, inherited from the Sepahead ecosystem.
