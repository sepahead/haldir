# Roadmap status

This is the roadmap-wide status ledger for the normative implementation sequence in
[`HALDIR-NCP-V0.8.0-TRIPLE-CHECKED-AUDIT-AND-IMPLEMENTATION-SPECIFICATION-2026.md`](HALDIR-NCP-V0.8.0-TRIPLE-CHECKED-AUDIT-AND-IMPLEMENTATION-SPECIFICATION-2026.md).
It prevents the green P0 exit gate from being mistaken for completion of the full
ecosystem project. The detailed P0 evidence remains in
[`COMPLETION-CHECKLIST.md`](COMPLETION-CHECKLIST.md) and [`CLAIM-LEDGER.md`](CLAIM-LEDGER.md).

Status vocabulary: **done** means the declared phase gate is backed by current code and
automated evidence; **partial** means useful mechanisms exist but the phase gate is not
fully proven; **not started** means no qualifying implementation/evidence is present.

## Tracked completion gates

- [#2 — machine-readable ecosystem source inventory](https://github.com/sepahead/haldir/issues/2)
- [#3 — durable Gate startup, boot identity, and evidence recovery](https://github.com/sepahead/haldir/issues/3)
- [#4 — secure Zenoh transport and ACL exclusivity](https://github.com/sepahead/haldir/issues/4)
- [#5 — Crebain sole-plant-owner integration](https://github.com/sepahead/haldir/issues/5)
- [#6 — Engram/NEST intent-only integration](https://github.com/sepahead/haldir/issues/6)
- [#7 — backend admission, live range, and performance evidence](https://github.com/sepahead/haldir/issues/7)
- [#8 — first signed experimental release](https://github.com/sepahead/haldir/issues/8)

## Current verdict

The offline P0 reference-monitor core is implemented and its local exit gate passes.
The full Haldir project remains incomplete: production durable recovery, selection
of the exact NCP adapter and strict transport in a runnable Gate, certificate-lifecycle/
reconnect and bypass proof beyond the retained synthetic ACL subset, Crebain and Engram
integration, backend-conformance research, performance/endurance campaigns, and an
experimental release are outstanding.
Those stronger properties remain explicitly unproven or out of scope under
`CL-DURABLE-01`, the limitations inside `CL-LIVE-TRANSPORT-01`, `CL-BACKEND-01`,
`CL-TIMING-01`, and `CL-PRODUCTION-01`.

## Phase ledger

| Normative phase | Status | Current evidence or missing gate |
| --- | --- | --- |
| -1 — design correction | Partial | The NCP 0.7.1 mechanics carry a supersession notice and repository-wide tracking issues now exist, but the full source-fact inventory is absent. |
| 0 — sources, claims, assurance profile | Partial | P0 pins, profiles, limitations, and claim ledger exist; the organization-wide machine-readable inventory does not. |
| 1 — workspace and reproducible CI | Partial | Workspace gates are green and third-party/tool pins are now mechanically checked; release provenance and cross-platform remote evidence remain release work. |
| 2 — canonical contracts and malformed corpus | Done (P0) | Strict deterministic CBOR, golden vectors, structural limits, and hostile parser tests (`CL-CBOR-01`). |
| 3 — signatures, roles, trust | Done (P0) | COSE/Ed25519, domain binding, trust conflict handling, role/subject enforcement (`CL-COSE-01`, `CL-TRUST-01`, `CL-IDENTITY-01`). |
| 4 — controller/backend admission | Partial | Structural digest admission exists; profile reconstruction and behavioral backend equivalence do not (`CL-BACKEND-01`). |
| 5 — challenges, leases, revocation | Partial | One-shot challenges, signed leases/revocation, a collision-free lease-term scope with downgrade-safe migration, checked high-water state, classified generation anchors, Unix atomic files, and explicit development-local Gate startup exist (`CL-DURABLE-PRIMITIVE-01`, `CL-DURABLE-STARTUP-DEV-01`); a service package, deployed external anchor, cross-store transfer, crash campaign, and live preemption do not (`CL-DURABLE-01`, issue #3). |
| 6 — bounded state and formal model | Done (P0) | Rust state/model tests and the exact pinned TLA+ v1.7.4 workflow are green (`CL-FORMAL-01`). |
| 7 — deterministic native policy | Done (P0) | Fixed-point, bounded, fail-closed policy and boundary/property tests (`CL-FIXEDPOINT-01`, `CL-SLEW-01`, `CL-DUTY-01`). |
| 8 — deterministic reference plant | Done (model only) | One-ingress integer simulation distinguishes accepted/applied/observed model events; it is not physical evidence (`CL-HARDWARE-01`). |
| 9 — NCP v0.8.0 adapter | Partial | The immutable baseline, modeled adapter, opt-in exact `ncp-core` JSON/frozen-corpus differential path, and always-on pinned-NCP route builders are tested (`CL-NCP-REAL-01`, `CL-TRANSPORT-BOUNDARY-01`); valid exact JSON also traverses the synthetic live campaign, but the Gate runtime still does not select the exact frame adapter (`CL-LIVE-TRANSPORT-01`). |
| 10 — Gate runtime, queues, journal, receipts | Partial | The 13-stage actor, fallible configuration, boot/store-bound startup, signed receipts, in-memory single-slot publication typestate, canonical linked publication-stage payload/reducer primitives, and a bounded locked evidence directory manager exist (`CL-CONFIG-01`, `CL-PUBLICATION-STATE-01`, `CL-PUBLICATION-EVIDENCE-PRIMITIVE-01`, `CL-DURABLE-STARTUP-DEV-01`, `CL-EVIDENCE-MANAGER-01`); service/package loading, bounded async queues, COSE/journal verifier, capacity reservation, actor journal selection, ordered replay, and crash-tested recovery do not (`CL-DURABLE-01`). |
| 11 — secure Zenoh and ACL proof | Partial | Exact routes, a TLS-only Zenoh 1.9 boundary, bounded ingress, typed exact-command publication, and an immutable-image/default-deny/direction-specific ACL package are statically tested (`CL-TRANSPORT-BOUNDARY-01`). The retained ephemeral-PKI campaign receiver-observes the fixed final-command/controller-intent subset across all configured principals (`CL-LIVE-TRANSPORT-01`). Runnable Gate wiring, certificate lifecycle/reconnect, the full operation/route matrix, production credential custody, and bypass inventory remain open. |
| 12 — Crebain sole plant owner | Not started in Haldir evidence | Current Crebain work is outside this repository; bypass closure and accepted/applied evidence are unproven. |
| 13 — Engram/NEST intent producer | Not started in Haldir evidence | No signed `HaldirIntentV1` producer or leased live controller is integrated. |
| 14 — deterministic acceptance campaign | Partial | The in-process adversarial range and narrow synthetic transport ACL campaign are green (`CL-GATE-MEDIATION-01`, `CL-LIVE-TRANSPORT-01`); backend, service, and plant scenarios remain absent. |
| 15 — PX4-SITL/Gazebo | Not started | No qualifying Haldir integration evidence. |
| 16 — Galadriel advisory evidence | Not started | No advisory-only contract/runtime integration evidence. |
| 17 — trace exports | Not started | No verified export adapters or consumer replay evidence. |
| 18 — backend-aware admission research | Not started | No NEST reconstruction, independent backend, NIR, or XyloSim campaign (`CL-BACKEND-01`). |
| 19 — adversarial range | Partial | P0 contract/state/policy attacks and the synthetic command/intent ACL subset exist; live service bypass, certificate-lifecycle, backend, and plant campaigns do not. |
| 20 — performance and reliability | Not started | No p99/p99.9, overload, soak, or recovery campaign (`CL-TIMING-01`). |
| 21 — first experimental release | Partial | CI/supply-chain hardening is underway; no SBOM, provenance, signed tag, release artifacts, or release evidence (`CL-PRODUCTION-01`). |
| 22 — future NCP authority increments | Not started / upstream-triggered | NCP v0.8.0 still defers plant authority, publisher binding, and apply/stop acknowledgements. |

## Ecosystem re-check (2026-07-13)

- NCP `v0.8.0` remains the latest immutable release and the Haldir pin remains correct:
  commit `2f5bd586d4bb20c90362bb6f5698b7f64057ba4e`, wire `0.8`, contract
  `d1b50a2d8a265276`, proto digest `6f13b12c…131227`.
- NCP `main` at the latest audit was
  `db3fddc170b5235098f540134340ffaa8d9c2d2c`; its post-tag work hardens release
  metadata and consumer-pin checking (including exact Cargo `=0.8.0`) without
  changing the released wire.
- Crebain, Engram, Galadriel, and Prisoma have moved to the v0.8 baseline, so old
  roadmap language telling every consumer to migrate from v0.7.1 is historical.
- Haldir is now registered as an exact-revision NCP consumer and the optional
  adapter validates released JSON `CommandFrame` bytes against the pinned crate and
  frozen corpus. The default in-process Gate still uses its deterministic model.
- Haldir's static secure-reference profile now makes Gate the sole exact-command
  `put` ingress principal and confines each controller to its exact intent route.
  Because Zenoh authorizes publisher ingress and receiver egress separately, the
  generated rules are direction-specific. The source-bound retained campaign now
  receiver-observes that fixed command/intent subset on the pinned router with ephemeral
  certificates and all eight configured principals (`CL-LIVE-TRANSPORT-01`); its stated
  service, lifecycle, trust-union, application, and bypass limitations remain open.

## Next completion slice, reviewed from five lenses

1. **Authority:** turn the tested startup library into a secret/package-loading service;
   add a real external anchor and make the tested durable evidence manager mandatory
   before authority can become active.
2. **Wire/ecosystem:** select the now-tested exact-v0.8 adapter in the runnable
   service, preserving the stable Haldir semantic contracts.
3. **Time/restart/evidence:** prove crash recovery, boot-id uniqueness, and terminal
   evidence semantics under fault injection.
4. **Operations/security:** wire the strict transport into a single-owner Gate
   service using the now-tested in-memory single-slot publication typestate; make
   `PublishCalled` durable/recoverable, then run the remaining operation/route matrix,
   reconnect/revocation/expiry tests, and bypass inventory.
5. **Research/release honesty:** integrate Crebain then Engram in that order, run the
   registered campaigns, and create an experimental release only after every stronger
   claim has direct evidence.
