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
A retained clean-source development campaign now proves the narrow strict-session-open,
aggregate-bind, and immediate local-shutdown observation in `CL-LIVE-GATE-DEV-BIND-01`.
A separate local primitive now verifies strict signed deployment-package bytes, optionally captures
bounded artifact bytes from a caller-supplied Linux/macOS directory capability without a leaf reopen,
resolves and retains the exact bytes, composes the signed NCP role with compiled pins, and supplies
verifier-derived revision/payload-digest values to an atomic package-plus-boot ratchet. Package-bound
Gate startup consumes that stage and exact-matches the signed journal ID when its format-v2 evidence
chain is bound (`CL-DEPLOYMENT-PRIMITIVE-01`).
The full Haldir project remains incomplete: production durable recovery, authenticated mandatory
selection of the exact NCP/internal strict transport path, certificate-lifecycle/reconnect and
bypass proof beyond the retained synthetic ACL subset and narrow development Gate bind/shutdown
campaign, Crebain and Engram integration, backend-conformance research, performance/endurance
campaigns, and an experimental release are outstanding.
Those stronger properties remain explicitly unproven or out of scope under
`CL-DEPLOYMENT-PACKAGE-01`, `CL-LIVE-CONTROL-PLANE-01`, `CL-DURABLE-01`, the
limitations inside `CL-LIVE-TRANSPORT-01`, `CL-BACKEND-01`, `CL-TIMING-01`, and
`CL-PRODUCTION-01`.

The Issue #2 workflow now defines bounded public and owner-local inventory lanes,
source-bound classification decisions, automated factual supersession review, staged
privacy closure, and separate public versus owner-local verification. Exact retained
artifacts control the run state. Automated factual review does not authenticate a
reviewer or establish owner approval, and an inventory seal grants no integration,
phase, publication, or release authority.

## Phase ledger

| Normative phase | Status | Current evidence or missing gate |
| --- | --- | --- |
| -1 — design correction | Partial | The bounded supersession and source-inventory workflow preserves dated history and current-observation boundaries. A retained inventory seal can close only Issue #2's inventory scope; the independent phase reviewer exit remains incomplete. |
| 0 — sources, claims, assurance profile | Partial | P0 pins, profiles, limitations, and claim ledger exist. The bounded workflow can retain machine-readable public inventory plus a private-evidence commitment, but owner approval, independent reviewer authentication, and the broader claim/assurance exit remain unproven. |
| 1 — workspace and reproducible CI | Partial | Workspace gates are green and third-party/tool pins are now mechanically checked; release provenance and cross-platform remote evidence remain release work. |
| 2 — canonical contracts and malformed corpus | Done (P0) | Strict deterministic CBOR, golden vectors, structural limits, and hostile parser tests (`CL-CBOR-01`). |
| 3 — signatures, roles, trust | Done (P0) | COSE/Ed25519, domain binding, trust conflict handling, role/subject enforcement (`CL-COSE-01`, `CL-TRUST-01`, `CL-IDENTITY-01`). |
| 4 — controller/backend admission | Partial | Structural digest admission exists; profile reconstruction and behavioral backend equivalence do not (`CL-BACKEND-01`). |
| 5 — challenges, leases, revocation | Partial | One-shot challenges, signed leases/revocation, a collision-free lease-term scope with downgrade-safe migration, checked high-water state, classified generation anchors, Unix atomic files, explicit development-local Gate startup, runtime-profile validation before the listed startup-owned calls/accesses, a strict signed deployment-package/owned-artifact verifier with an optional bounded Linux/macOS directory-capability source, and an atomic store-global package-plus-boot ratchet for the store's authenticated Gate binding exist (`CL-DURABLE-PRIMITIVE-01`, `CL-DURABLE-STARTUP-DEV-01`, `CL-DEPLOYMENT-PRIMITIVE-01`). Package-bound Gate startup consumes NCP and Gate-configuration stages plus four separately verified, role-separated, public-key-distinct revision-scoped snapshot approvals under the same retained bootstrap trust/revocations; this does not prove independent organizations or operators. It exact-matches every live authorization snapshot/session/publication/cap/signer identity and rejects cross-store `kid` or public-key rebinding before effects, commits the verified package revision/digest with the boot, and exact-matches the signed journal ID when binding format-v2 evidence. An authenticated mandatory runtime package, authenticated/protected artifact-root and credential acquisition, authenticated live control plane, deployed external anchor, cross-store transfer, crash campaign, and live preemption do not (`CL-DEPLOYMENT-PACKAGE-01`, `CL-LIVE-CONTROL-PLANE-01`, `CL-DURABLE-01`, issue #3). |
| 6 — bounded state and formal model | Partial | Rust state/model tests are green. The corrected finite TLA+ source checks exact active-lease incarnation, consistent lease presence, output allocation, retired epochs, and terminal-fault immutability under the pinned v1.7.4 runner locally; current exact-subject hosted evidence is pending (`CL-FORMAL-01`). |
| 7 — deterministic native policy | Done (P0) | Fixed-point, bounded, fail-closed policy; measured-state acceleration; an outward-rounded prospective geofence covering exact state age plus the candidate horizon and requested/measured±uncertain velocity; exact-nanosecond half-open action-history accounting; typed integrity faults; and boundary/reference-property plus Gate integration tests (`CL-FIXEDPOINT-01`, `CL-SLEW-01`, `CL-DUTY-01`, `CL-ERROR-01`). |
| 8 — deterministic reference plant | Done (model only) | One-ingress integer simulation distinguishes accepted/applied/observed model events and carries exact signed sub-millimetre integration remainder across ticks; it is not physical evidence (`CL-HARDWARE-01`). |
| 9 — NCP v0.8.0 adapter | Partial | The immutable baseline, modeled adapter, opt-in exact `ncp-core` JSON/frozen-corpus differential path, closed adapter selection, explicit template runtime profile, and pinned-NCP route builders are tested (`CL-NCP-REAL-01`, `CL-TRANSPORT-BOUNDARY-01`). A strict bounded canonical compatibility-artifact decoder exact-matches the implemented frozen command subset—including its schema/vector digests and enabled increment—to every compiled pin before returning a private-field proof (`CL-NCP-COMPATIBILITY-01`). The deployment resolver consumes that validator together with its exact signed role bytes into `NcpValidatedDeploymentPackage`, then strictly validates the signed Gate configuration; package-bound Gate startup consumes and retains the stronger stage while exact-matching runtime/wire/store and all live configuration identities and atomically ratcheting the verified package with its boot (`CL-DEPLOYMENT-PRIMITIVE-01`). `DeclaredLiveZenoh` requires exact JSON and the live feature before the listed startup-owned effects; successful startup privately mints the live coordinator capability, while reference/copied-report paths cannot. Exact-selected output reaches Called, and valid exact JSON traverses the separate synthetic campaign. The no-network activation capability derives the accepted controller's canonical route before authority commits. The outer aggregate consumes that capability plus one supplied session wrapper, internally derives the matched publisher and exact ingress from the same session lineage, and exposes consuming receive/process/shutdown methods plus a cloneable local safe-boundary request handle (`CL-LIVE-INGRESS-BINDING-01`). The `live-gate-dev-smoke` examples hard-select this exact path: a separate offline provisioner creates a disposable fixture, while the networked target is `OpenExisting`-only and immediately shuts down without processing. A retained clean-source run proves those concrete local calls and returns with zero processing/publication (`CL-LIVE-GATE-DEV-BIND-01`). Full NCP schema/conformance-set identities and reproducible adapter source/build provenance also remain open. |
| 10 — Gate runtime, queues, journal, receipts | Partial | The 13-stage actor, fallible configuration, boot/store-bound startup, declared-live validation, signed receipts, post-sync revalidation, canonical linked publication stages, bounded journal reservations, assurance replay, and fused restart Unknown emission exist. Package-bound startup consumes NCP and strict Gate-configuration stages plus four separately verified role/key-separated snapshot identities rooted in the retained bootstrap verifier state; it exact-matches every runtime snapshot/session/publication/cap/signer identity before effects, atomically commits the package revision/digest with the boot, retains the proof through journal binding, exact-matches the signed journal ID, and rejects unbound assurance startup. The coordinator sync-orders receipt/Called/terminal transitions and blocks after recovered called-or-later history pending external clearance. Live ownership, bounded ingress, consuming state updates, safe-boundary shutdown, and local session cleanup are implemented and tested at their stated library boundary (`CL-STATE-INGRESS-01`, `CL-GATE-LIFECYCLE-01`, `CL-LIVE-GATE-DEV-BIND-01`). This remains no authenticated state/control producer, in-flight timeout, OS-signal runner, journal finalization, confirmed remote retirement, or graceful production daemon. Missing gates include authenticated ongoing challenge/lease/revocation/state delivery, semantic consumption of the other seven deployment roles, mandatory journal/path and running-image binding, protected credential opening, process-wide supervision/locking, bounded asynchronous publication, Prepared loss summaries, OS/disk/crash/power fault injection, reconnect, and authenticated restart clearance (`CL-DEPLOYMENT-PACKAGE-01`, `CL-DURABLE-01`). |
| 11 — secure Zenoh and ACL proof | Partial | Exact routes, a TLS-only Zenoh 1.9 boundary, bounded ingress, typed exact-command publication, and an immutable-image/default-deny/direction-specific ACL package are statically tested (`CL-TRANSPORT-BOUNDARY-01`). The retained ephemeral-PKI campaign receiver-observes the fixed final-command/controller-intent subset across all configured principals (`CL-LIVE-TRANSPORT-01`), and a separate retained development campaign proves one strict Gate session/aggregate bind and immediate local shutdown with zero processing/publication (`CL-LIVE-GATE-DEV-BIND-01`). Certificate lifecycle/reconnect, the full operation/route matrix, production credential custody, peer identity, remote retirement, and bypass inventory remain open. |
| 12 — Crebain sole plant owner | Not started in Haldir evidence | Current Crebain work is outside this repository; bypass closure and accepted/applied evidence are unproven. |
| 13 — Engram/NEST intent producer | Not started in Haldir evidence | No signed `HaldirIntentV1` producer or leased live controller is integrated. |
| 14 — deterministic acceptance campaign | Partial | The in-process adversarial range and narrow synthetic transport ACL campaign are green (`CL-GATE-MEDIATION-01`, `CL-LIVE-TRANSPORT-01`); backend, service, and plant scenarios remain absent. |
| 15 — PX4-SITL/Gazebo | Not started | No qualifying Haldir integration evidence. |
| 16 — Galadriel advisory evidence | Design boundary documented; runtime not started | `GALADRIEL-PID-ADVISORY-CONTRACT.md` fixes the categorical MGW estimand, method separations, and authority noninterference rule. Haldir still has no PID route, schema, principal, policy field, dependency, or runtime evidence. |
| 17 — trace exports | Not started | No verified export adapters or consumer replay evidence. |
| 18 — backend-aware admission research | Not started | No NEST reconstruction, independent backend, NIR, or XyloSim campaign (`CL-BACKEND-01`). |
| 19 — adversarial range | Partial | P0 contract/state/policy attacks and the synthetic command/intent ACL subset exist; live service bypass, certificate-lifecycle, backend, and plant campaigns do not. |
| 20 — performance and reliability | Not started | No p99/p99.9, overload, soak, or recovery campaign (`CL-TIMING-01`). |
| 21 — first experimental release | Partial | Protected CI directly installs exact verified cargo-deny assets, reconstructs the bounded pinned RustSec snapshot, primes locked inputs online, and performs the final audit frozen and network-isolated. Acquisition availability, SBOM, end-to-end provenance, signed tag, reproducible release artifacts, and release evidence remain open (`CL-PRODUCTION-01`). |
| 22 — future NCP authority increments | Not started / upstream-triggered | NCP v0.8.0 still defers plant authority, publisher binding, and apply/stop acknowledgements. |

## NCP provider boundary update (2026-08-10)

NCP repository `main` at
`1ffd3bf9a6c52d0279eb31a56e0664e4eec24d68` is the unreleased and
release-blocked `1.0.0-rc.1` candidate. Its wire is `1.0`, and its compact
`CONTRACT_HASH` is `163acc57d8a62b66`. Haldir's supported immutable baseline
remains the annotated `v0.8.0` tag, which uses a different wire. GitHub's
Releases API currently identifies `v0.5.1`; the newer protocol baselines are
annotated tags, so this ledger does not call `v0.8.0` the latest GitHub release.

Haldir remains pinned to the immutable v0.8 baseline. Native Haldir 1.0
migration and independent qualification are **NOT RUN** and are not
dependency-ready in the NCP ecosystem task ledger. This status update does
not advance a task, phase, gate, or claim and does not change Haldir's pin or
runtime. The dated historical audit cut below remains unchanged.

## Ecosystem re-check (2026-07-13)

- NCP `v0.8.0` remains the latest annotated protocol tag in that historical
  observation, and the Haldir pin remains correct:
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
  frozen corpus. Template startup uses a closed explicit adapter selection plus an explicit
  runtime declaration; `DeclaredLiveZenoh` requires exact selection and the compiled live
  feature before the listed startup-owned backend calls, entropy, locks, or directory access.
  Current P0 fixtures remain `InProcessReference`, while an exact-selected actor is tested
  through Called. Successful
  declared-live startup now privately mints the move-only capability required by the live
  coordinator typestate; exact reference and forged-report paths are rejected before clock
  sampling. The declaration remains process-local. A public no-network kernel now issues one
  Gate-signed, locally expiring challenge from startup entropy; only its move-only successor can
  validate one bounded local state and matching signed lease and mint an exact intent-route
  capability from the verified controller. The outer Zenoh aggregate consumes that result,
  one supplied session wrapper, and validated ingress limits; it internally creates the matched
  publisher and exact accepted-controller-route ingress from the same session lineage. It also
  exposes a local safe-boundary request latch, without an in-flight timeout or signal runner. The
  development smoke examples now have retained clean-source evidence for disposable local
  provisioning followed by `OpenExisting` strict-session open, aggregate bind, and immediate local
  shutdown. They process no intent, publish no command, and do not authenticate the local inputs,
  protect credential custody, or supply ongoing controls (`CL-LIVE-GATE-DEV-BIND-01`).
- Haldir's static secure-reference profile now makes Gate the sole exact-command
  `put` ingress principal and confines each controller to its exact intent route.
  Because Zenoh authorizes publisher ingress and receiver egress separately, the
  generated rules are direction-specific. The source-bound retained campaign now
  receiver-observes that fixed command/intent subset on the pinned router with ephemeral
  certificates and all eight configured principals (`CL-LIVE-TRANSPORT-01`); its stated
  service, lifecycle, trust-union, application, and bypass limitations remain open.
- Gate's off-by-default live feature now compiles a capability-marked consuming
  coordinator-to-concrete-publisher binding, a no-network initial activation/route typestate,
  a crate-private single-owner raw-event kernel with one private output slot, and an outer public
  non-cloneable session/ingress aggregate with consuming receive/process/shutdown methods and a
  separate cloneable local safe-boundary request handle. Tests start from an
  inactive test-minted marked actor and actual journal manager, exercise bounded caller-supplied local
  activation and canonical intent-route binding, then use fake publisher and fake session/ingress
  seams for lifecycle and aggregate orchestration, including request-before-retry and in-flight
  latching without request-driven cancellation. A direct helper test proves idle wake. The concrete
  types and development examples compile; the bind target deliberately calls no receive/process
  method, so it cannot invoke the publisher. The retained campaign proves only its concrete
  session-open, aggregate-bind, and immediate local-shutdown path; no authenticated ongoing control
  path exercises processing through the aggregate (`CL-LIVE-GATE-DEV-BIND-01`).

## Next completion slice, organized as five workstreams

Every change within these workstreams is reviewed against the normative 20-lens
rubric in `CONTRIBUTING.md`; the five headings below organize delivery rather
than narrowing that review.

1. **Authority/evidence:** preserve the retained development smoke and the separately proven
   deployment primitives at their narrow claim boundaries (`CL-LIVE-GATE-DEV-BIND-01`,
   `CL-DEPLOYMENT-PRIMITIVE-01`). Preserve the NCP command-subset decoder and the strict signed
   Gate-configuration composition at their narrow boundaries (`CL-NCP-COMPATIBILITY-01`). Next add
   authenticated/protected artifact-root and credential acquisition, semantic decoders for the
   remaining seven verified artifacts, running-image and journal-path binding, and an authenticated runner
   that makes package-bound Gate startup plus journal binding mandatory. Then add a
   real external anchor and mandatory durable evidence-manager selection before authority can
   become active. The full deployment-package/control-plane claims remain unproven until those gates.
2. **Wire/ecosystem:** make an authenticated service package select the now-tested
   `DeclaredLiveZenoh` profile on every boot, bind that declaration against downgrade, and
   supply the capability-marked exact-v0.8 coordinator with a session-backed strict publisher
   while preserving the stable Haldir semantic contracts.
3. **Time/restart/evidence:** prove crash recovery, boot-id uniqueness, and terminal
   evidence semantics under fault injection.
4. **Operations/security:** turn the aggregate-local accepted-route/session-lineage binding into
   a package that opens and protects credentials, owns authenticated ongoing
   challenge/lease/revocation/state ingress and one bounded
   publisher worker; make that package select and preserve the existing declared-live startup profile
   and capability-marked concrete Called/publisher binding, design
   authenticated restart clearance covering transport/session retirement and recovered
   policy history, then test live-session cancellation/timeout/panic, OS-level append/write/
   `sync_data` fault injection and disk-full behavior, panic-abort/process-manager handling, reconnect, child-process
   crash, the remaining operation/route matrix, and bypass inventory.
5. **Research/release honesty:** integrate Crebain then Engram in that order, run the
   registered campaigns, and create an experimental release only after every stronger
   claim has direct evidence.
