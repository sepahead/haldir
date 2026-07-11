<!--
  haldir — Project Catalog
  Generated design brief. Sections below are individually grounded against the
  crebain / NCP / manwe / melkor / pid-rs source trees; file:line references were
  verified at authoring time and may drift as those repos evolve.
-->

# haldir — Project Catalog

> **2026 review:** This catalog preserves the original idea set. Its ordering and
> several implementation assumptions predate NCP 0.7.1 and the current
> Engram/Crebain integration state. See the
> [2026 project audit](HALDIR-PROJECT-AUDIT-2026.md) for the evidence-checked,
> fifteen-lens ranking, detailed implementation plans, and conditional PhD
> recommendation.

**The security & guardian layer of the `sepahead` defense ecosystem — for military/tactical UAVs and embodied agents.**

`haldir` is named for Lothlórien's *marchwarden*, the sentry who lets nothing cross the border unchallenged. That is its role in the ecosystem. It rides the **NCP** control bus as its own mTLS-anchored `guardian` subject and treats every other node — crebain's fusion, manwe's detectors, melkor's scenes, the operator's commands — as an equal attack surface to be **authenticated, cross-checked, and held accountable**. It gives armed autonomy the three properties that command-and-control in a contested EW/RF/GNSS fight actually requires:

- **Authenticity** — nothing acts on unsigned, unattested, or spoofed data.
- **Authorization** — no command executes outside proven identity and rules-of-engagement.
- **Accountability** — every frame is tamper-evidently recorded, so any engagement can be replayed and proven.

Its posture is **fail-closed and provenance-first**, extending the ecosystem's existing `calibrated_posterior` / `is_simulation_output` honesty culture into cryptography — and it is scrupulous about the line between a **detector** (an advisory screen) and a **control** (an enforced gate), never selling a research probe as a shipped guarantee.

> **Anchors.** Every project below connects to **crebain** (the tactical ARAS counter-UAS app: multi-camera surveillance, YOLO detection, KF/EKF/UKF/PF/IMM fusion, drone physics, ROS/Gazebo) and/or the **NCP** bus (the safety-gated, provenance-first Zenoh control protocol: four QoS planes, `mode`/`ttl_ms`/ESTOP/geofence, default-deny ACL + mTLS). Where a project also touches manwe, melkor, pid-rs, engram, or the defense-meshes corpus, that is noted in its section.

---

## The ten projects

| # | Project | What it defends | Difficulty |
|---|---------|-----------------|-----------|
| 1 | **Palantír-Seal** | End-to-end authenticity of the perception plane (per-frame sensor provenance) | starter |
| 2 | **Rúmil — Shadow Governor** | Command-plane / controller integrity (independent second-opinion safety FSM) | starter |
| 3 | **Haldir Gate** | Command authorization (a fail-closed ROE / rules-of-engagement countersign) | moderate |
| 4 | **Fëanor's Mark** | NCP zero-trust (per-frame command MAC + per-verb RPC authorization) | moderate |
| 5 | **Nénya** | Navigation integrity (GNSS spoof/jam detection + dead-reckoned ride-through) | moderate |
| 6 | **Watchword** | Body integrity at join (firmware + ML-weight attestation gate) | moderate |
| 7 | **Galadriel's Mirror** | Cross-sensor consistency (an information-theoretic spoof detector) | ambitious |
| 8 | **Warden's Eye** | Perception assurance (poisoned-scene gate + adversarial-patch AP regression) | ambitious |
| 9 | **Dwimordene** | Early warning & attacker characterization (a bus honeypot / decoy session) | ambitious |
| 10 | **Border-Muster & the Marchwarden's Roll** | Validation & accountability (cyber-range/CTF + tamper-evident black box) | ambitious |

## How to read this catalog — the roadmap arc

The list is ordered so the earliest projects are the highest-leverage, lowest-risk foundations and the arc escalates in ambition:

- **1–2 (authenticity + an independent watchdog)** are self-contained starters that change no wire contract.
- **3–6 (authorization + identity)** add the enforced gates: rules-of-engagement, per-verb bus authorization, navigation trust, and body attestation.
- **7–9 (detection + deception)** add the harder analytic and active-defense layers.
- **10** ties everything into a self-sharpening range with court-usable accountability.

**Build #1 (Palantír-Seal) first.** Its Ed25519 + BLAKE3 signed-manifest and per-stream hash-chain are the crypto substrate that the Ledger (#10), the honeypot (#9), the SIEM lane, and the zero-trust MAC (#4) all reuse — so it pays down shared cost across the whole roadmap, and its verifier is a read-only observation-plane subscriber (zero control-path risk). **Galadriel's Mirror (#7)** has its own dedicated deep-research design document at [`galadriels-mirror.md`](./galadriels-mirror.md), with the broader PID programme in [`pid-security-and-communication.md`](./pid-security-and-communication.md).

---


## 1. Palantír-Seal — Per-frame sensor provenance

*A C2PA-style Ed25519+BLAKE3 seal riding every `SensorFrame` and `TrackOutput` from capture to the operator overlay, so a replayed or forked sensor feed is quarantined before it can ever become a confirmed track.*

**Difficulty:** starter — a self-contained sign/verify crate plus two shims and a badge; no change to the normative wire contract.

**What it defends:** end-to-end payload authenticity of the perception plane, so false-data injection on the sensor bus cannot silently drive the actuator.

### Threat model

The adversary is a participant that can PUBLISH on the NCP perception plane — the world-writable sensor bus that `SECURITY.md` explicitly calls out as "an equal attack surface," because the controller computes commands *from* `SensorFrame`s. The concrete attack is false-data injection: the attacker never touches the command plane. They emit spoofed or replayed `SensorFrame`s on `{realm}/session/*/sensor/**`, and because `sensor_frame_from_pose` (`crebain/src-tauri/src/ncp/mod.rs:39`) → `publish_sensor` produces bytes indistinguishable from a genuine capture, those bytes flow through `decode_pose_cdr`/`decode_image_cdr` ingest (`crebain/src-tauri/src/transport/zenoh.rs:643`,`:369`) into fusion and reach `calculate_threat_level` (`crebain/src-tauri/src/sensor_fusion.rs:373`).

The existing defenses miss this. Transport mTLS + the Zenoh ACL (`NCP/deploy/zenoh-access-control.json5`) prove *who may publish to the plane* — a `robot` subject — but not *which capture produced these bytes*; any authorized-but-compromised relay re-emits freely. `contract_hash` (`NCP/ncp-core/src/messages.rs:474`, an FNV-1a digest via `fnv1a_hex`, `:1085`) is advisory schema-versioning, not a MAC. And receiver-side `seq` discipline (Wire 0.6: `seq >= 1`, strictly increasing per stream; `SensorFrame.seq`, `:825`) is exactly the check NCP residual threat #4 defeats: alternating *different* captured frames while advancing `seq` monotonically passes seq discipline cleanly. The operator, watching the `DetectionOverlay`, cannot distinguish a genuine capture from an injected one.

### How it works

A **signer shim** wraps the emit seam. At `sensor_frame_from_pose`/`publish_sensor` it computes a detached manifest over the outgoing CDR payload:

```
manifest = Ed25519.sign( BLAKE3(cdr_payload) || seq || t || frame_id || signer_CN || prev_manifest_hash )
```

The `prev_manifest_hash` link makes the per-stream sequence a **hash chain**: each manifest commits to its predecessor, so drop, reorder, replay, *and* live-stream forking are all detectable structurally — a replay reuses a `prev` that no longer matches the receiver's chain head; a fork branches two children off one parent. Because `BLAKE3(cdr_payload)` binds the actual bytes, the seal is end-to-end: it survives multi-hop routing, record/replay, and a compromised-but-authorized relay that transport crypto would happily wave through. This is precisely why MAVLink 2 signs *on top of* link crypto — link auth secures the hop, message signing secures the payload.

The **verifier** is an observation-plane subscriber. It re-derives `BLAKE3(cdr_payload)`, checks the Ed25519 signature against the signer's CN-bound key, and validates chain continuity + `seq` advancement. Its verdict rides through fusion so that each `TrackOutput` (`crebain/src-tauri/src/sensor_fusion.rs:287`) carries a trust stamp, surfaced to the frontend `Detection` type and rendered as a **`TrustBadge`** alongside `drawDetectionBox` in `crebain/src/components/DetectionOverlay.tsx`: **green** (verified), **amber** (unsigned-legacy), **red** (signature-fail / replay / broken-chain / fork). The honest boundary, stated plainly: it authenticates *bytes, not scene veracity* — a correctly signed frame of a dazzled or decoy scene still passes green.

### Ecosystem integration

**crebain.** Two seams, both already isolated. The signer wraps the sensor emit path in `ncp/mod.rs` (`sensor_frame_from_pose` → the `publish_sensor` call at `:261`); the verifier is a new observation-plane subscriber, and the trust field is threaded from `TrackOutput` into the TS `Detection` shape consumed by `DetectionOverlay.tsx`. Rendering the `TrustBadge` is additive — the file today imports `Detection`, `THREAT_LEVEL_COLORS`, and `drawDetectionBox` from `../detection/types` and gains one badge draw per box.

**NCP.** Manifests publish on a **sidecar** key `{realm}/session/{id}/sensor/{name}/provenance`, which falls under the existing `ncp/session/*/sensor/**` grant, so the normative wire contract (`ncp-core/src/messages.rs`, `CONTRACT_HASH`) is untouched and `contract_hash` does not move. Key↔identity reuses the mTLS CN→subject binding the Zenoh ACL already proves; a new `guardian` subject with a read grant is added to `zenoh-access-control.json5` (today only `commander`/`robot`/`observer` exist), and the NCP dependency is version-locked through crebain's `.ncp-consumer` descriptor. This executes the `SECURITY.md` backlog item "consider per-message signing" as a real per-stream MAC.

### First build (MVP) and milestones

**MVP:** a `haldir-seal` sign/verify crate implementing the manifest + per-stream hash chain over the existing `SensorFrame`; a signing shim at the crebain emit seam; a verifying observation-plane subscriber; and the `TrustBadge`. Ship the **hash-chain slice first** — it already catches replay, reorder, and fork with nothing more than a static per-stream keypair.

1. **Chain-only detector + badge** — a hardcoded signer key, green/amber/red surfaced end-to-end. Proves replay/fork rejection in an EW-contested demo.
2. **CN-bound keys via the ACL** — bind the signer key to the proven mTLS CN, add the `guardian` subject, treat unsigned frames on a stream *seen signed* as fail-closed (defeat the downgrade/strip attack).
3. **Fail-closed enforcement** — move the verdict inline at ingest so a `red` frame is dropped *before* fusion, not merely badged. This is the step that turns a detector into an enforced gate.

### Honest limitations and scope

This is a **detector and quarantine, not an enforced command-plane gate** — until milestone 3, the verifier runs as a passive observation-plane subscriber, so a `red` verdict is an operator warning; the frames still transit fusion. The real enforced gates remain `min_confirmation_hits` (M-of-N in the confirmation window, `sensor_fusion.rs:1456`/`:2338`) and the `MEAS_CLUSTER_GATE` Mahalanobis association gate (`:51`). Palantír-Seal only *upgrades* those by pruning injected measurements upstream once wired inline.

It authenticates bytes, not truth: a signed frame of a spoofed, dazzled, or physically decoyed scene passes green — sensor-blinding and adversarial-patch attacks are out of scope (that is a sibling detector's job). Without fail-closed policy it is downgrade-vulnerable: strip the sidecar manifest and the frame degrades to amber "unsigned-legacy," so any deployment MUST pin streams to fail-closed once first seen signed. Finally — and this is the hard 80% — the MVP assumes a static key. **Provisioning, rotation, and revocation** are the genuinely difficult PKI work this project deliberately defers; a stolen-but-unrevoked signer key forges valid seals until rotation.

### Effort, stack, and dependencies

**Stack:** Rust (`ed25519-dalek`, `blake3`), Zenoh, CDR, Tauri 2 + React 19. **Effort:** starter — roughly a 1–2 week MVP for the chain-only slice and badge; the PKI milestones (2–3) are the long tail. **Composes with:** the future haldir PKI/identity module for key provisioning and revocation (milestone 2+); a scene-integrity / anti-spoofing detector to cover the "bytes, not veracity" gap; and any enforced-gate module that consumes the verifier verdict to drop frames pre-fusion.


## 2. Rúmil — Shadow Governor — Bus second-opinion safety FSM

*A passive, read-only replica of the NCP deterministic safety FSM that recomputes the ESTOP/HOLD verdict the plant SHOULD be enforcing and alarms the instant the plant's behavior diverges — the watcher that watches the watcher.*

**Difficulty:** starter — Rúmil reuses the shipped `ncp-core::safety` FSM verbatim rather than reimplementing safety logic; the new code is a subscriber, a comparator, and a timeline lane.

**What it defends:** command-plane / controller integrity — it catches actuations that execute in a mode the situation's own safety verdict would have vetoed, plus the two documented `safety.rs` under-enforcement bugs.

### Threat model

The NCP action plane is the only plane with command authority. The plant's `SafetyGovernor` (`NCP/ncp-core/src/safety.rs`) is the last deterministic gate: it HOLDs on stale sensors, latches ESTOP on a geofence breach or collapsed link, and clamps speed. The adversary here is a **compromised controller or a command-plane injection** that already holds a valid path onto `{realm}/session/{id}/command`. In the deployment ACL (`NCP/deploy/zenoh-access-control.json5`) only the `commander` subject may PUT on `…/command/**`; an attacker who has captured that identity (or the process behind it) issues actuations while the sensors it feeds the plant governor read honest and in-bounds — so the plant `SafetyGovernor` stays green and `ControlStatus.safety_ok` reports `true` even as the craft is driven where a geofence or link verdict says HOLD.

Two shipped `safety.rs` weaknesses widen the same gap. `ChannelValue` (`messages.rs`) carries a free-text `unit: Option<String>` that `clamp_velocity` and the geofence block **never validate** — magnitudes are computed straight off `data`, so a setpoint labeled `cm/s` where the limit assumes `m/s` mis-scales the speed clamp and the fence radius. And the geofence guards only `pos.data.is_empty()`; a **short-but-nonempty vec3** (a position channel arriving with one or two components where three are declared) computes `r = sqrt(Σ cᵢ²)` over the present components, under-reporting the true Euclidean distance and slipping past the `r > radius` ESTOP latch. Nothing on the bus independently audits whether the verdict the plant *enforced* matches the verdict the situation *demanded*.

### How it works

Rúmil imports `ncp-core::safety::{SafetyGovernor, CommandWatchdog}` and `ncp-core::resilience::LinkMonitor` **verbatim** and runs one shadow instance per live session. At session open it builds the shadow with `SafetyGovernor::from_capabilities(&caps)` using the same negotiated `Capabilities` the plant used, so the shadow's `position_channel`, `velocity_channel`, `command_channels` and `SafetyLimits` track the identical handshake — the enforced channels line up exactly.

As a read-only guardian subject it subscribes to `{realm}/session/{id}/sensor/**` (SensorFrame), `…/command` (the observed CommandFrame the controller emitted), and `…/observation` (carrying `ControlStatus`, whose `mode` and `safety_ok` report what the plant actually did). On each tick it feeds the observed `SensorFrame` and `CommandFrame` into `SafetyGovernor::govern(command, sensor, now_s, last_sensor_s)` — the real `&mut self` FSM, ESTOP latch and all — driving `CommandWatchdog::on_command` / `should_hold` from the observed `seq`/`ttl_ms` and `LinkMonitor::on_seq` for the CUSUM jam burst that `note_link` escalates. The result is a fresh, independently-computed `CommandFrame` whose `Mode` (`Init`/`Active`/`Hold`/`Estop`) plus `safety_ok()` is the second opinion.

The comparator then emits a **divergence event** whenever the shadow verdict disagrees with the observed behavior: shadow `Mode::Hold`/`Mode::Estop` (or `safety_ok() == false`) while the observed `CommandFrame.mode == Mode::Active` and `ControlStatus.safety_ok == true`. The critical seam is that the shadow FSM is a *hardened* copy: empty **and short** position vectors fail closed (arity checked against the declared channel width, not just `is_empty()`), and channel `unit` strings are validated against the negotiated spec before the clamp/fence math runs — so the shadow additionally flags the two `safety.rs` bugs even when the plant governor waves them through.

### Ecosystem integration

**crebain.** crebain already links `ncp-core` behind its `ncp` feature (`src-tauri/Cargo.toml`, git tag `v0.6.0`) and drives sessions through `src-tauri/src/ncp/mod.rs`, so Rúmil lives naturally in the same Tauri backend. Each divergence is surfaced as a SOC timeline lane rendered beside `src/components/SensorFusionPanel.tsx`, cross-checked against crebain's observed command mode and `ControlStatus.safety_ok`. With an explicit supervisor grant — and only then — the lane can *recommend* (never silently force) a `SafetyGovernor` supervisor latch; the enforcement stays the plant's.

**NCP.** Rúmil runs as a read-only subscriber on `…/observation` plus the sensor/command taps. The current `observer` subject (`observer-reads`) is scoped to `sensor/**` and `observation` only, so the deployment needs a new **`guardian`** subject rule granting `declare_subscriber` on `…/command/**` as well (read-only — never a PUT rule), preserving the ACL's safety invariant that only `commander` publishes commands. Rúmil ships hardened unit tests reproducing the unit-mismatch and short-vec limitations; those fixes should be **upstreamed into `ncp-core::safety`**, with the shadow retained for controller-compromise coverage the FSM cannot self-detect. It depends on **Nénya (the Mirror)** for the sensor-plane integrity it explicitly does not cover.

### First build (MVP) and milestones

MVP: instantiate the hardened `SafetyGovernor` / `CommandWatchdog` against replayed bus captures (recorded SensorFrame/CommandFrame/observation streams), run `govern` per tick, emit a divergence event on `verdict != observed-mode`, and render a timeline lane. First flag: a scripted controller-compromise trace where the shadow says `Hold` but the plant keeps commanding `Active`.

- **M1 — live tap:** promote from replay to a live `guardian` subscriber over Zenoh on a running session, with per-session shadow lifecycle tied to session open/close.
- **M2 — bug reproduction + upstream:** land the unit-validation and short-vec-arity tests, flag both against a stock plant governor, and open the `ncp-core::safety` upstream fix.
- **M3 — supervisor-recommend:** wire the grant-gated ESTOP-latch *recommendation* path into crebain, with a full audit trail of every divergence and every operator action.

### Honest limitations and scope

Rúmil is a **detector, not an enforced gate** — it observes and alarms; the plant `SafetyGovernor` remains the sole actuator authority (the recommend path only surfaces, never forces). Because it is a shadow of the *same* FSM fed the *same* observed sensors, an honest identity holds: if the sensors are spoofed, the shadow computes the same wrong verdict and stays silent. It therefore catches **command-plane / controller compromise (sensors honest)** and the two `safety.rs` under-enforcement bugs, and **not sensor-plane spoofing** — that is Nénya's (the Mirror's) job. Residual risks: it cannot detect a divergence in the blind window between tap and comparator; a plant running an already-upstreamed FSM will (correctly) stop diverging on the two bugs, leaving only the controller-compromise coverage; and it trusts that the observed command/observation frames themselves reflect what the plant executed.

### Effort, stack, and dependencies

Stack: Rust (reuses `ncp-core::safety` verbatim), Zenoh, Tauri 2 + React 19. Rough effort: a starter-scale build — the FSM is inherited, so work concentrates in the subscriber, the per-session comparator, the ACL `guardian` rule, and the SOC lane. Composes with **Nénya / the Mirror** (sensor-plane integrity, which bounds Rúmil's honest scope) and with the shared haldir SOC surface in crebain beside `SensorFusionPanel.tsx`.


## 3. Haldir Gate — the Marchwarden’s Countersign — ROE / authorization PDP

*A fail-closed policy-decision point astride the action plane that stamps a real Ed25519 countersign on every `CommandFrame` passing ROE / geofence / rate / time-window checks, so a plant receiving any un-countersigned or policy-failing command falls to a zeroed HOLD.*

**Difficulty:** moderate — a new subscriber crate plus a small, verifiable ingress patch; no new physics, no controller changes.

**What it defends:** the action plane against *authorized-by-physics-but-not-by-rules* commands — replayed, out-of-box, or out-of-window setpoints.

### Threat model

The action-plane authority in this stack is `SafetyGovernor` (`NCP/ncp-core/src/safety.rs`, mirrored from `loop.py::SafetyGovernor`). It latches ESTOP on a geofence breach, HOLDs on a stale sensor, and clamps speed against `SafetyLimits`. Every one of those checks is a *physics* predicate: is this pose inside the keep-out volume, is this velocity under the cap, is the sensor fresh. **None of them can answer “is this command authorized, here, now?”** The governor has zero concept of rules-of-engagement, sortie windows, or a per-command duty budget.

That gap is exploitable because the command plane is world-writable by design. `NCP/deploy/zenoh-access-control.json5` says so in its own header — anyone who can reach `ncp/session/*/command/**` can drive an actuator, and the key expression is best-effort `DROP` + express (`ncp-core/src/keys.rs`). The wire-0.6 floor at the crebain tap, `ncp_core::decode_validated::<CommandFrame>` (`crebain/src-tauri/src/ncp/mod.rs:306`), rejects version-incompatible, wrong-kind, and unstamped (`seq < 1`) frames, and `CommandWatchdog` refreshes liveness only on a strictly advancing `seq` — but a *well-formed, correctly-sequenced, geometrically-legal* frame sails straight through `velocity_from_command` (`mod.rs:66`) onto the actuator. A captured intercept command re-broadcast from a prior sortie, or a legal-but-out-of-box setpoint an operator never intended, executes with no authority check beyond the plant FSM.

### How it works

Haldir Gate is a policy-decision point (PDP) that runs *beside* the action plane, not in-line with it. It subscribes **read-only** to `ncp/session/*/command/**`, decodes each `CommandFrame`, and evaluates a compiled ROE ruleset: a keep-in / no-fly polygon, a rate / duty-cycle limit, and a sortie time-window. On a pass it computes a **detached Ed25519 signature** (via `ed25519-dalek`) over the *full canonical serialization* of the frame — `seq`, `t`, `frame_id`, `mode`, `ttl_ms`, and **every entry of the `channels` map** (the same `Map<ChannelValue>` `channels_linear` reads at `mod.rs:151`), plus the active policy version and a fresh nonce bound to `(seq, t)`. Signing the whole field set — not just `velocity_setpoint` — means no actuated channel is forgeable and no auxiliary channel can be smuggled past the signed prefix. Haldir republishes that signature on a sibling countersign subject; it never touches the command itself.

The enforcement seam lives behind crebain’s existing `ncp` Cargo feature (`ncp = ["dep:ncp-core", "dep:ncp-zenoh"]`, gated at `crebain/src-tauri/src/lib.rs:20`). `velocity_from_command` and `CommandPlant::velocity_at` (`mod.rs:130`) gain a countersign check keyed to haldir’s public key; a frame with a missing, stale, or invalid signature falls through the already-proven `Mode::Hold | Mode::Estop => [0.0, 0.0, 0.0]` path (`mod.rs:68`) instead of actuating.

The explicit **safety-vs-liveness tradeoff:** requiring a countersign on *every* frame would make haldir a hard liveness single-point-of-failure — a mid-intercept stall would freeze the airframe. So countersign-required is enforced **only inside the ROE-relevant engagement envelope**, and the plant pre-authorizes a bounded safe-motion class (return-to-base, station-keep, descend) that needs no countersign. A haldir stall therefore degrades to a supervisor-gated HOLD-in-place, not a freeze while closing on a target. Safety (no unauthorized actuation) is fail-closed; liveness (keep flying) is preserved for the pre-authorized envelope.

### Ecosystem integration

**crebain.** The patch is small and behind the `ncp` feature. `decode_validated::<CommandFrame>` ingress (`src-tauri/src/ncp/mod.rs`) gains countersign verification; `velocity_from_command` and `CommandPlant::velocity_at` verify before returning a non-zero twist and otherwise take the existing Hold/Estop zero path. A red **VETO** badge lands in `crebain/src/components/SensorFusionPanel.tsx` (with the detection surface already rendered by `DetectionOverlay.tsx`), reading e.g. `VETO: replay, policy v3, no countersign`.

**NCP.** Haldir needs a new guardian subject in `deploy/zenoh-access-control.json5` — a read-only-on-command, publish-on-countersign role whose **proven mTLS common-name** is the *only* identity crebain trusts to countersign (the ACL already binds `cert_common_names` by exact string equality). `scripts/check_acl_template.py`, which CI runs to enforce the PUT-authority invariants, extends to assert the countersign key expression is writable only by that guardian CN. Conceptually this upgrades the advisory `contract_hash` (`ncp-core/src/messages.rs`, proto-identity on `OpenSession`/`SessionOpened`) into a true **per-frame MAC over the full field set**. It does **not** close the per-verb RPC authorization gap — that is Fëanor’s Mark.

### First build (MVP) and milestones

MVP: a `haldir-gate` crate = action-plane subscriber + a small safe-Rust ROE DSL (polygon + rate + time-window in RON/TOML) + an `ed25519-dalek` countersign publisher; patch crebain ingress to verify; add the VETO badge. A Gazebo replay drives one out-of-box and one replayed command, both vetoed to HOLD.

- **M1** — Verify-only shadow mode: haldir publishes countersigns and the VETO badge lights, but the plant does not yet gate. Measure decision latency inside `ttl_ms`.
- **M2** — Enforced gate inside the engagement envelope, with the pre-authorized safe-motion class carved out; demonstrate a haldir-stall degrades to supervisor-gated HOLD, not a freeze.
- **M3** — Policy hot-reload with version stamping in the countersign, plus a CI ACL check that fails closed if the guardian CN is ever unset.

### Honest limitations and scope

Haldir Gate is an **enforced gate, not a mere detector** — but only within the engagement envelope; the pre-authorized safe-motion class is deliberately *un*-countersigned, so an attacker who can forge a command that plausibly falls inside that bounded class still moves the plant (bounded, safe, but unauthorized). It authenticates *commands*, not the *operator’s intent*: a legitimately-signed but mistaken setpoint inside the polygon and window is countersigned. Replay resistance rests on binding the signature to `(seq, t)` and on the wire’s monotonic-`seq` watchdog; a same-sortie replay within the freshness window before `seq` advances is the residual gap. It does not close the per-verb RPC authorization gap (Fëanor’s Mark) and does not defend the perception plane against false-data injection (a separate haldir module). Key management — issuing, rotating, and revoking the guardian signing key — is out of scope for the MVP and assumed handled by the deployment’s PKI.

### Effort, stack, and dependencies

Stack: Rust (`ed25519-dalek`), Zenoh, a RON/TOML policy DSL, Tauri 2 + React 19 for the VETO badge. Rough effort: ~2–3 weeks for MVP through M2 for one engineer — the crate and DSL are the bulk, the crebain patch is a few dozen lines behind the `ncp` feature. It composes with the world-writable-plane ACL hardening (shared guardian-CN identity), leans on the pre-authorized safe-motion contract that a HOLD-in-place governor module provides, and explicitly hands the RPC-verb authorization problem to Fëanor’s Mark.


## 4. Fëanor’s Mark — NCP zero-trust: per-frame MAC + per-verb RPC authorization

*Give every body on the bus a cryptographic command identity, and split the single RPC key so the ACL can allow `open` while denying a stray robot from `close`-ing the commander's live session.*

**Difficulty:** moderate

**What it defends:** the NCP action and control planes — it stops replayed/forged `CommandFrame`s from driving an actuator and stops a non-owner from stepping or closing a session it does not own.

### Threat model

The adversary is an *authenticated but untrusted* peer on a contested-RF NCP realm: a robot or observer that holds a valid certificate (a captured body, a compromised observer tap) plus a passive attacker who can record and re-inject wire frames. Two concrete NCP-disclosed gaps are in scope.

First, the single control-plane RPC key. `Keys::rpc()` (`NCP/ncp-core/src/keys.rs:60`) resolves to one key-expression, `{realm}/rpc`, and the queryable served by `serve_rpc` (`NCP/ncp-core/src/bus.rs:168`) takes a `QueryHandler`, which is typed `Arc<dyn Fn(&[u8]) -> Vec<u8> + Send + Sync>` (`bus.rs:15`). The handler sees **only the payload bytes** — never the caller's proven mTLS subject. So the JSON-RPC verb (`open`, `step`, `run`, `close`) lives *inside* those bytes where the Zenoh ACL cannot read it, and the ACL is the only layer that sees the certificate common-name. The shipped `deploy/zenoh-access-control.json5` must therefore grant `query` on `{realm}/rpc` to *any* authenticated client so sessions can open at all — which means the same grant lets an observer or a stray robot `close` or `step` **any** session, including the commander's live intercept. This is NCP's own self-flagged P0 (`KNOWN_LIMITATIONS.md`, "Single RPC key per realm prevents per-verb ACL").

Second, replay on the action plane. A `CommandFrame` (`NCP/ncp-core/src/messages.rs:857`) carries a monotonic `seq: i64` but no cryptographic binding. NCP's receiver-side seq discipline closes same-frame replay within a stream, but its own residual admits that *alternating* replays of two different captured frames across expiry windows can still duty-cycle a plant, because a strictly-lower `seq` at expiry is legitimately read as a restarted-controller epoch. And `contract_hash` is an FNV-1a digest (`fnv1a_hex`, `messages.rs:1085`) — advisory integrity, explicitly **not a MAC**. mTLS proves the *channel*; nothing proves a given frame was authored, in order, by the session owner.

### How it works

Two coordinated, deliberately un-clever changes.

**Per-verb key-split (the RPC fix).** Follow NCP's own proposed remedy rather than attempting impossible in-handler CN inspection. Split privileged verbs onto distinct key-expressions — `{realm}/rpc/open` versus `{realm}/rpc/admin` (carrying `step`/`run`/`close`) — by extending `Keys` in `ncp-core/src/keys.rs`. The mTLS-anchored ACL, which *does* see the subject via `cert_common_names`, then gets matching per-verb rules in `zenoh-access-control.json5`: `query` on `.../rpc/open` for any authenticated peer, `query` on `.../rpc/admin` restricted to the `commander` subject. Authorization moves to the one layer that can actually enforce it. This is a wire-touching change to RPC addressing, kept honest via the `.ncp-consumer` pin in crebain and `NCP/scripts/check-consumer-pins.sh`, and unit-testable against the ACL template check (`scripts/check_acl_template.py`).

**Per-frame signature (the replay fix).** Establish a per-session `epoch` nonce at session open — a fresh random negotiated in the `SessionOpened` handshake (`messages.rs:498`) — and publish an Ed25519 detached signature (via `ed25519-dalek`) over the **canonical serialized `CommandFrame` bytes concatenated with `epoch ‖ seq`**, on a parallel `{realm}/session/{id}/command/sig` key alongside the existing `Keys::command` plane (`keys.rs:87`). The commander signs with its session key; the plant verifies before acting. Binding `seq` to `epoch` means a frame captured under a prior epoch fails signature-context verification even if its `seq` looks fresh, and a strictly-monotonic high-water check per epoch rejects stale-`seq` replays. The marginal gain over mTLS is genuine: per-frame **non-repudiation** and ordering integrity that a channel-level mutual-auth handshake cannot provide.

### Ecosystem integration

**crebain.** A ~30-line verifier sits in `crebain/src-tauri/src/ncp/mod.rs`, on the path that `velocity_from_command` (`mod.rs:66`) and `CommandPlant::velocity_at` (`mod.rs:110`) take before a setpoint reaches `/mavros/<ns>/setpoint_velocity/cmd_vel`. It fetches the sibling `.../command/sig`, verifies the Ed25519 signature over the canonical frame plus the session `epoch`, and enforces monotonic `seq`. A stale-epoch or stale-`seq` frame is rejected and the plant **holds ESTOP** rather than actuating — reusing the existing fail-safe-to-zero behavior of `velocity_from_command` under `Mode::Hold`/`Estop`.

**NCP.** Two changes land in `ncp-core`: the key-split in `keys.rs` with matching rules in `deploy/zenoh-access-control.json5`, and the signing/verify layer over `CommandFrame` canonical bytes. On the safety side, the verifier holds the supervisor grant for `SafetyGovernor::reset()` (`NCP/ncp-core/src/safety.rs:160`) — a rejected frame must not clear the latched ESTOP that `govern` maintains. It depends on a sibling haldir PKI/identity module to provision the mTLS trust anchor and issue the per-body certificates the ACL binds to, and on key-management for Ed25519 keypair rotation.

### First build (MVP) and milestones

MVP: ship the key-split plus the per-verb ACL rule — small, high-value, unit-testable to the ACL template check, with the consumer pin bumped in lockstep. Demo: a non-owner `step`/`close` on `.../rpc/admin` is denied live while `open` still succeeds.

1. Add the `ed25519-dalek` signer/verifier over `CommandFrame` canonical bytes; negotiate the `epoch` nonce in `SessionOpened`.
2. Wire the crebain verifier into the `CommandPlant` path; a replayed "dive" frame is rejected on stale epoch/seq and the plant holds ESTOP.
3. Harden: signing-key rotation, an anti-replay policy for legitimate epoch re-anchor, and a signed-vs-unsigned rollout flag.

### Honest limitations and scope

This is NCP's documented backlog executed, not novel cryptography. The verifier is an **enforced gate** — it withholds the setpoint and holds ESTOP — not a passive detector; but its guarantees are bounded. It does **not** turn `contract_hash` into a MAC (that field stays FNV-1a advisory); it adds a *separate* signature. The per-verb ACL is only as strong as the underlying mTLS PKI: a **stolen or unrevoked commander certificate still passes**, so this composes with, and depends on, certificate issuance and revocation elsewhere in haldir. The signature gives integrity and non-repudiation, **not confidentiality** — command contents remain readable to a permitted observer. And the alternating-replay residual is only *narrowed*: closing replay fully requires strict per-epoch monotonicity, which fights the legitimate controller-restart re-anchor NCP needs; the crebain gate resolves the tension by **failing safe** (holding ESTOP on an ambiguous re-anchor) rather than perfectly distinguishing restart from replay. The sensor plane (false-data injection via spoofed `SensorFrame`) is out of scope — a separate ACL concern.

### Effort, stack, and dependencies

**Stack:** Rust (`ed25519-dalek`), Zenoh ACL (json5), `ncp-core` keys. **Effort:** moderate — the key-split MVP is a few days including the wire-pin dance; the signing layer and crebain verifier add roughly one to two weeks. **Composes with:** a haldir PKI/identity module (mTLS anchor, cert issuance/revocation) and key-management (Ed25519 rotation); downstream it hardens the same crebain `CommandPlant`/`SafetyGovernor` path other action-plane haldir modules rely on.


## 5. Nénya — GNSS spoof/jam guardian — Navigation-trust ride-through

*Catches GPS spoofing the instant a UAV's own-ship position stops agreeing with its own inertial/visual motion, inflates track covariance, and forces a recoverable dead-reckoned HOLD instead of letting the spoofer walk the drone through its own geofence.*

**Difficulty:** moderate
**What it defends:** own-ship navigation trust for a geofenced UAV — the perception-plane channel by which GNSS spoofing defeats the fence without ever touching `/command`.

### Threat model

The adversary is electronic warfare: a GPS spoofer or meaconer near a forward-base perimeter drone flying a geofenced patrol orbit. Rather than jam (which merely denies), the spoofer transmits coherent counterfeit GNSS so the aircraft computes a *plausible but wrong* own-ship position, then slowly ramps that position to walk the bird off-station and across the fence.

This defeats the geofence structurally. crebain's `SafetyGovernor::govern` (`NCP/ncp-core/src/safety.rs`) enforces `geofence_radius_m` and `max_speed_mps`, but it enforces them against **plant-reported position** — the same GNSS-derived pose the spoofer controls. A slow position-walk therefore keeps the *reported* aircraft comfortably inside the fence while the *physical* aircraft crosses it. This is the canonical "perception-plane false-data injection defeats the geofence without touching `/command`" failure: no command is ever forged, so the command-plane ACL in `NCP/deploy/zenoh-access-control.json5` — which lets only the `commander` role PUT on `ncp/session/*/command/**` — is bypassed entirely. The attack rides the sensor plane, and crebain today has **no own-ship-integrity check**: `validate_sensor_measurements` (`crebain/src-tauri/src/sensor_fusion.rs:1567`, called from `fusion_process` in `lib.rs`) validates covariance sanity, not agreement between GNSS and the airframe's own motion.

### How it works

Nénya adds a genuinely new **own-ship ego-estimator**: a `nalgebra`-based (`0.35`, already a crebain dependency) IMU + visual-odometry dead-reckoning filter that integrates the airframe's *self-sensed* motion. IMU is already on the wire — `subscribe_imu` (`crebain/src-tauri/src/transport/mod.rs`), `decode_imu_cdr` (`transport/zenoh.rs`), surfaced by the `transport_subscribe_imu` Tauri command — so the estimator consumes an existing feed rather than inventing a transport.

The core is a new safe-Rust `NavTrustMonitor`. Each tick it forms the innovation between the *published* GNSS own-ship pose and the *dead-reckoned* prediction, and gates the squared Mahalanobis distance using the **exact χ²(3) formula crebain already ships**: `MEAS_CLUSTER_GATE = 11.345` (`sensor_fusion.rs:51`), the χ²-inverse-CDF at p=0.99 for 3-DOF position, the same Bar-Shalom gating quantile used in measurement clustering. Because honest GNSS jitter is zero-mean, a single-sample gate would either false-trip on noise or miss a slow walk, so on top of the gate Nénya runs a **CUSUM** on the residual: it accumulates the coherent, one-signed drift a spoof-walk produces and separates it from symmetric sensor noise. This mirrors crebain's existing M-of-N confirmation discipline (`min_confirmation_hits`, default 3 in `sensor_fusion.rs`) — evidence must persist before it counts.

The trust scalar the monitor emits is the seam. Low trust flows into the fusion path near `validate_sensor_measurements`/`process_measurements` to **inflate the GNSS track's fusion covariance**, making the fused solution EW-aware and down-weighting the compromised sensor. On a CUSUM trip (confirmed spoof), crebain repoints the setpoint source: `CommandPlant` (`crebain/src-tauri/src/ncp/mod.rs:110`) is fed the ego-estimator's dead-reckoned solution and a **supervisor-gated HOLD** is requested — the non-latching fail-safe (`Mode::Hold` → zero velocity, `is_holding`), deliberately *not* the latching `ESTOP` that `SafetyGovernor` holds until a supervisor reset. The bird freezes on inertial hold inside the *true* fence.

### Ecosystem integration

**crebain.** Nénya lands as the new `NavTrustMonitor` plus ego-estimator module, wired at two existing seams: the fusion entry (`fusion_process`/`validate_sensor_measurements` in `lib.rs`/`sensor_fusion.rs`) for covariance inflation, and `CommandPlant` (`ncp/mod.rs`) for the HOLD/DR-setpoint switch. On the UI, `SensorFusionPanel.tsx` — which today renders `sensorStatus` and a confidence row but has no EW state — gains an **EW-DEGRADED banner** driven by the trust scalar. It reuses, not forks, the χ²(3) gate constant and the M-of-N confirmation pattern already in the codebase.

**NCP.** Nénya publishes `nav-trust` as a scalar on the free **observation plane**, `ncp/session/*/observation`, decoded through the existing `ObservationFrame`/`observation_scalar` path (`ncp/mod.rs`). Per the ACL template this plane is writable only by the `commander` role and readable by observers — the `robot` role can never publish it — so the trust signal inherits the deployment's per-plane trust model with **zero NCP-repo edits**, registering via a `.ncp-consumer` descriptor rather than a protocol change. It depends on the sibling haldir project **Fëanor's Mark** for the countersign: the HOLD Nénya requests is itself a supervisor-authorized command, so the enforced HOLD should be countersigned rather than self-asserted.

### First build (MVP) and milestones

**MVP.** PX4-SITL/Gazebo patrol orbit; inject a spoof by ramping the *published* GNSS pose while IMU/VO stay honest. The safe-Rust `NavTrustMonitor` + new `nalgebra` ego-estimator compute the residual, CUSUM trips in under a second on a fast walk, `nav-trust=low` publishes, crebain inflates covariance, and `CommandPlant` goes to inertial HOLD. This is the fast-walk demo — the clear win.

**Milestone 2 — bounded-time DR guarantee.** Characterize inertial/VO drift and publish a *bounded-time* dead-reckoning envelope so the HOLD's "true fence" has a stated validity horizon.

**Milestone 3 — EO/VO absolute-fix re-anchor.** Add a terrain/EO absolute-fix cross-check to re-anchor the ego-estimate during a long HOLD, and **flag-not-fully-attribute**: report GNSS/IMU divergence without over-claiming which sensor is the liar.

### Honest limitations and scope

Nénya is a **detector and a covariance/setpoint influence, not a new enforced gate**. The enforced fence still lives in `SafetyGovernor`; Nénya changes *what position that gate sees* and requests a HOLD — it does not itself hard-stop actuation. Two named residual risks stand. First, the **patient meaconer**: an adversary walking the pose slower than combined IMU/VO drift-plus-noise stays under the χ²(3) gate and below the CUSUM slope — the fast-walk MVP demonstrably wins, the patient-spoofer regime is explicitly out of scope for the MVP. Second, the **true fence itself drifts**: inertial dead-reckoning accumulates error over a long HOLD, which is exactly why the bounded-time guarantee and the EO/VO re-anchor exist — and why Nénya flags divergence rather than fully attributing blame.

### Effort, stack, and dependencies

**Stack:** Rust (`nalgebra`), PX4-SITL/Gazebo, Zenoh, Tauri 2 + React 19. **Effort:** moderate — the χ²(3) gate, M-of-N pattern, IMU transport, `CommandPlant`, and observation-plane consumer path all exist; the genuinely new work is the ego-estimator, the CUSUM, and the EO re-anchor. **Composes with:** Fëanor's Mark (countersigned HOLD authorization); shares crebain's fusion covariance and `SafetyGovernor` fail-safe with the wider haldir guardian layer.


## 6. Watchword — Firmware & ML-weight attestation gate at session-open

*The marchwarden challenge: no body crosses from `Mode::Init` to `Mode::Active` until it answers a fresh nonce with a signed measurement of its firmware, binary, and ML weights that matches a golden allowlist.*

**Difficulty:** moderate

**What it defends:** the join moment — it turns an identity-only handshake into an integrity handshake, so a body holding a valid cert but running tampered code or swapped weights is pinned to `HOLD` instead of allowed to actuate.

### Threat model

The bus authenticates *who* is talking, never *what code is talking*. mTLS proves a certificate Common-Name; the NCP handshake in `NCP/ncp-core/src/messages.rs` layers on `OpenSession.contract_hash` / `SessionOpened.contract_hash`, but that value is the `CONTRACT_HASH` constant (`"24e8e6e31e1dec8a"`), an **advisory** FNV-1a digest of the *wire proto* produced by `fnv1a_hex` — it attests that two peers agree on the message schema, not that either peer is running trusted software. Nothing in the join path measures the running binary or the model file.

Two concrete attacks slip through. First, a commander presents a genuine robot cert but has reflashed firmware or side-loaded a modified `crebain` build; every downstream check passes because the identity is real. Second, and more insidious, the perception weights are swapped: `crebain/src-tauri/src/onnx_detector.rs` loads its detector with `create_session(model_path)` → `commit_from_file(model_path)` from a filesystem path, and the CoreML path in `coreml.rs` is equivalent — anyone who can write that file substitutes an `.onnx`/CoreML model that mislabels or suppresses tracks. On the manwe side, `manwe/python/src/manwe/common/contracts.py` does carry a `ModelContract.file_sha256`, but it is optional (defaults `""`, rendered `TODO`), it is a ship-time documentation digest that travels *alongside* the weights, and it is not even in the required set enforced by `missing_fields()`. There is no fresh, challenged, signed verification that the weights actually loaded at power-up match any golden value. The result is proof-of-identity with zero proof-of-integrity at the moment a body is admitted to the realm.

### How it works

`haldir` mints a random nonce and demands a signed **quote** before it will authorize a controller to transition into an actuating mode. The quote is an ed25519 signature (`ed25519-dalek`) over the tuple `{ nonce, crebain_binary_sha256, model_file_sha256, sbom_digest }`, where `sbom_digest` is the build-time SBOM baked into the binary at compile time. On the verifier side `haldir` loads a golden-measurement manifest (a signed TOML allowlist), checks the nonce is the one it just issued (freshness / anti-replay), verifies the agent's ed25519 public key is on the allowlist, and confirms each measured digest matches a golden entry.

The enforcement seam is the mode transition. `NCP/ncp-core/src/safety.rs::SafetyGovernor::govern()` already refuses to forward any frame whose `mode` is not `Mode::Active` (`if !matches!(command.mode, Mode::Active)` → zeroed / `HOLD`), and `SafetyGovernor::from_capabilities` builds that governor from the joining body's `Capabilities`. Watchword does not replace that clamp; it makes a *passing attestation* the precondition on the `Init → Active` authorization keyed to `Capabilities.controller_id`. A body that cannot produce a matching quote is admitted to the perception plane but is never authorized for `Mode::Active`, so `crebain`'s `CommandPlant` / `ncp_core::ActionBuffer` fail-safe to zero velocity (`HOLD`). Attestation state is bound to the same `controller_id` the governor already uses, so there is no second identity to spoof.

### Ecosystem integration

**crebain.** A new feature-gated `attestation-agent` module inside `crebain/src-tauri`, mirroring the existing `ncp` feature (`ncp = ["dep:ncp-core", "dep:ncp-zenoh"]` in `crebain/src-tauri/Cargo.toml`). At detector load it measures its own binary and the resolved `model_path` handed to `onnx_detector.rs` / `coreml.rs`, then ed25519-signs the quote over `haldir`'s nonce. The natural enforcement hook reuses `crebain`'s deliberate opt-in seam: the `ncp_*` commands (`ncp_connect`, `ncp_open_feature_neuron`, `ncp_step_feature_neuron`, `ncp_close`) are defined in `crebain/src-tauri/src/ncp/mod.rs` but intentionally left out of the `tauri::generate_handler!` list in `lib.rs::run()`. A failed quote becomes the precondition that keeps those actuation-capable commands unregistered — an unattested build literally cannot wire its command surface to the frontend.

**NCP.** `haldir` ships as a Zenoh queryable, following the RPC pattern already in `NCP/deploy/zenoh-access-control.json5` (the `commander-serves-rpc` / `client-queries-rpc` rules on `ncp/rpc` using `declare_queryable` / `reply` / `query`). It adds a **new `guardian` ACL subject** with its own key-expr (e.g. `ncp/guardian/attest`) that mints nonces and returns allow/deny, and it upgrades `OpenSession.contract_hash` from the advisory FNV digest toward a real signed attestation quote. The comms-denied-FOB reachability problem is handled fail-**closed**: a local signed cache of the golden manifest lets a body attest without reaching a central authority, and an unresolvable attestation denies `Active` rather than defaulting open. This composes with sibling `haldir` modules that own the guardian trust root and the signed-ACL policy distribution — Watchword consumes their signing key; it does not mint its own.

### First build (MVP) and milestones

MVP: a Rust `attestation-agent` crate that measures binary hash + model SHA-256 + baked SBOM digest and ed25519-signs over a `haldir` nonce, plus a `haldir` queryable that verifies the quote against a golden TOML. Demo: run `crebain` under a privilege-separated agent, swap the `.onnx` model file out from under it, and watch the join get refused to `HOLD`.

- **M1 — measure + sign + verify:** agent crate, nonce protocol, golden-TOML verifier; unit-tested against a known-good and a tampered model.
- **M2 — gate wiring:** bind the verdict to `controller_id` so a failed quote blocks `Init → Active` and keeps the `ncp_*` command surface unregistered; add the fail-closed local manifest cache.
- **M3 — hardware root (v2):** replace software self-measurement with a TPM/DICE PCR quote so the measurement itself is rooted in hardware.

### Honest limitations and scope

Watchword v1 is a **detector-and-enforced-gate**, not a hardware-rooted proof. Without a hardware root of trust the software self-measurement is circular against a reflashing adversary: hostile firmware can forge its own quote, so v1 does **not** stop a fully compromised body that controls its own attestation agent. Its genuinely new value is (a) the ML-weights-at-join check, which nothing in the stack does today, and (b) integrity against an *unprivileged* file swap under privilege separation — the agent's signing key and measurement path sit outside the actuator process, so a low-privilege model-file substitution is caught. Residual risks: a privileged attacker who owns the agent, and the golden-manifest signing key itself, which becomes the new high-value target. The overnight-reflash-and-return interceptor is caught only for the swapped-weights and unprivileged-tamper cases in v1; the full reflash case is the honestly-scoped TPM/DICE v2.

### Effort, stack, and dependencies

**Stack:** Rust (`ed25519-dalek`), Zenoh, TOML manifests; v2 adds TPM/DICE PCR quotes. **Effort:** moderate — the crypto and the queryable are small; the work is in the gating seam and the fail-closed cache semantics. **Composes with:** the `crebain` `ncp` feature and `lib.rs::run()` registration seam, `NCP`'s `SafetyGovernor` (`safety.rs`) and `Capabilities.controller_id`, the `zenoh-access-control.json5` ACL, and sibling `haldir` modules owning the guardian trust root and signed policy distribution.


## 7. Galadriel’s Mirror — PID cross-sensor consistency intrusion-detector

*An information-theoretic SIEM lane that flags a spoofed bearing or an injected ghost track the instant one sensor channel stops SHARING information with the others — the ecosystem-unique detector only sepahead can build, because only it owns both a multimodal C-UAS fuser (crebain) and a bit-reproducible PID library (pid-rs).*

**Difficulty:** ambitious — it requires instrumenting crebain to emit per-modality residuals, and it must earn its complexity against a trivial baseline before it is trusted.

**What it defends:** the multimodal fused track against single-channel false-data injection that is internally self-consistent enough to pass the association gate.

### Threat model

The adversary owns exactly one sensing channel and lies only through it. Concretely: a ground phased-acoustic emitter drags SRP-PHAT peaks to plant a phantom acoustic direction-of-arrival, or an adversarial patch poisons one camera’s contribution to N-view triangulation. Vision and radar still agree on the true inbound; the acoustic (or one camera) channel is quietly steering the fused estimate.

crebain’s fusion front-end cannot see this. In `crebain/src-tauri/src/sensor_fusion.rs`, each `SensorMeasurement` (tagged `modality: SensorModality` ∈ {`Visual`, `Thermal`, `Acoustic`, `Radar`, `Lidar`}) is gated on its own squared Mahalanobis distance against the predicted measurement — `const MEAS_CLUSTER_GATE: f64 = 11.345` and the default `association_threshold: 11.345`, the χ²(3) 0.99 quantile. That gate asks a purely *marginal* question: is this measurement plausible for the current track? A spoof engineered to sit inside the gate is happily associated, and the sliding-window M-of-N confirmation (`min_confirmation_hits: 3`, `confirmation_window: 5`) then *promotes* it, because the phantom is consistent frame-to-frame with itself. No per-channel or cross-channel consistency is ever tested. Worse, the innovation that would expose the lie is a throwaway local: `let innovation = measurement - predicted_measurement;` is consumed by `*state += k * innovation;` and dropped; the IMM likelihood loop computes a local `mahalanobis` and discards it. Nothing about per-modality residual behaviour reaches any plane a guardian could subscribe to.

### How it works

The Mirror’s premise is information-theoretic, not geometric. If every channel is honestly observing the same target, each modality’s innovation stream shares a large *redundant* pool of information about the fused-state target: they are all noisy views of one truth. A spoof injected into a single channel is, by construction, information that channel does **not** share with the others — so redundancy collapses and that channel’s *unique* information spikes.

Over a sliding window, the Mirror aligns four residual streams — vision, radar, acoustic-DOA, and triangulated-3D — against the fused-state target and feeds them to `pid-rs`. It estimates mutual information with `ksg_mi` (`pid-rs/crates/pid-core/src/ksg.rs`), the shared-exclusion redundancy `isx_redundancy` at bivariate and trivariate order (`isx.rs`, `pid2.rs`, `pid3.rs`), and the three invariants that give a *sign-carrying* alarm: `o_information_discrete` (Ω; redundancy-dominated → positive, synergy-dominated → negative), the degree-of-redundancy `red_degree_discrete` (the r-bar), and the degree-of-vulnerability `vul_degree_discrete` (the v-bar) in `invariants.rs`. A clean scene sits redundancy-positive; the moment the acoustic channel decorrelates, Ω flips, r-bar cliffs, and the acoustic term’s Unq rises — a signature no marginal NIS test can produce, because NIS is blind to what the *other* channels are saying.

The exact seam is a new per-modality residual tuple. crebain must publish the `(modality, innovation, S, NIS)` it currently throws away; the Mirror consumes it read-only. Every estimate is bracketed by block-bootstrap CIs (`bootstrap.rs`, `ci.rs`) and gated by the `exp0` validity check (`bin/exp0.rs`, `--strict-gate`) so an alarm is a real redundancy collapse, not a kNN artifact in a low-sample window.

### Ecosystem integration

**crebain.** One small, surgical change on the observation plane: emit the per-modality NIS residual tuples that the Kalman/IMM update in `sensor_fusion.rs` already computes and discards, packaged as `Observation` records (`Observation::vec3` / keyed entries in `ObservationFrame.records`, `NCP/ncp-core/src/messages.rs`) alongside the existing publish path in `crebain/src-tauri/src/ncp/mod.rs`. On the UI, the Mirror renders per-channel trust bars beside `crebain/src/components/DetectionOverlay.tsx` and, via the supervised control path, *recommends* a modality down-weight ahead of the χ²(3) association gate — it advises the operator, it does not silently re-weight the filter.

**NCP.** The Mirror is a read-only guardian subscriber, nothing more. `NCP/deploy/zenoh-access-control.json5` already carves out an “Observers (analysis taps)” subject with `declare_subscriber` **allow** on `ncp/session/*/observation` and `.../sensor/**` and no publish rule anywhere — the fail-closed ACL guarantees it can never command. It registers by committing a `.ncp-consumer` descriptor in the haldir repo (a `cargo_tag` line pinning the agreed `ncp-core`/`ncp-zenoh` git tag; `NCP/INTEGRATING.md`, `scripts/check-consumer-pins.sh`), with **zero** NCP-repo edits, and pins `pid-core` separately in its own Cargo manifest. Its alarms feed the **Border-Muster** ledger and can trip a **Dwimordene** decoy correlation. Enforcement stays where it belongs — the `SafetyGovernor` (`NCP/ncp-core/src/safety.rs`) on the action plane.

### First build (MVP) and milestones

- **MVP.** Offline: `o_information_discrete` + `red_degree_discrete` over 3–4 sequence-aligned channels from replayed manwe/crebain captures, block-bootstrapped and exp0/geometry-gated. Inject a spoofed DOA and show the redundancy trace cliff — plotted *beside* a one-line per-sensor NIS / innovation-whiteness χ² baseline on the same trace, so the added value is visible or the lane is cut.
- **M1.** Instrument `sensor_fusion.rs` to emit the per-modality residual tuples on the observation plane; subscribe live via the Observers ACL.
- **M2.** Real-time sliding-window scoring with the Unq spike / Ω-flip alarm and per-channel trust bars in the crebain UI.
- **M3.** Close the loop: emit an advisory modality down-weight recommendation into the supervised control path and log every alarm to Border-Muster.

### Honest limitations and scope

This is an **advisory screen, not an enforced gate.** It recommends a down-weight; it never mutates the filter or the action plane. It requires a crebain change it does not own (the residual tuples are not published today). It must **earn its complexity**: if the NIS/whiteness baseline catches the same spoofs, the lane is redundant. It runs only in the `pid-rs` exp0-validated low-dimensional band, so at high channel count or short windows it abstains rather than emit kNN noise. It flags *which modality* decorrelated, not *which track* — it cannot fully attribute per-track. And a coordinated multi-channel spoof that keeps channels mutually consistent defeats it by construction; it detects the loss of sharing, not the truth.

### Effort, stack, and dependencies

**Stack:** Rust (`pid-core`/`pid-rs`, safe), Zenoh, Tauri 2 + React 19. **Effort:** ambitious — days for the offline MVP against replay, but the buildable capability gates on the crebain instrumentation (M1) and on beating the baseline. **Composes with:** crebain (fuser + UI), NCP (observation-plane transport + ACL), Border-Muster (alarm ledger), and Dwimordene (decoy correlation) among sibling haldir modules.


## 8. Warden’s Eye (Amon Hen) — Adversarial-perception defense

*A pre-mission assurance gate that refuses melkor scenes whose geometry was hallucinated rather than observed, and quarantines a shipped detector build that loses too much AP to physically-realizable adversarial patches on the real airframes.*

**Difficulty:** ambitious — two honestly-scoped modules, no certified-radius theater; the hard parts are the signed-provenance channel and a faithful physical-patch rendering pipeline.

**What it defends:** the perception supply chain — the 3D scenes melkor hands to crebain, and the detector weights crebain ships to the edge — *before* either reaches a live mission.

### Threat model

Two adversaries, one seam. First, **poisoned geometry.** melkor emits Gaussian-splat scenes as SPZ/PLY/GLB containers (`src/spz_encoder.cpp`, `src/ply_writer.cpp`) that are *unsigned* — there is no provenance binding a container to the SfM photos it was trained from. Worse, `melkor --fill-holes` (`src/densifier.cpp::fillHoles`, deterministic median-spacing densification governed by a `DensifyConfig`) will bridge interior voids anywhere the point cloud is sparse. An attacker who controls hole boundaries — trivial in a low-texture region COLMAP never triangulated — bakes phantom cover: a densified “wall” or an occlusion void that hides a real drone. Because `fillHoles` is deterministic, the phantom is reproducible and looks like ordinary reconstruction.

Second, **printed patches.** The crebain detector zoo is a COCO/YOLO stack (`crebain/src-tauri/src/onnx_detector.rs` over `crate::common::coco`) exported from manwe (`manwe models`, drone/bird/aircraft/helicopter classes). It is exposed to EOT-robust adversarial patches that suppress the drone class — pushing `drone → bird/unknown` (real display labels: DROHNE → VOGEL/UNBEKANNT in `crebain/src/components/DetectionOverlay.tsx`). The attack is cheapest at **AP-small**, exactly the regime of a distant overwatch drone, and the suppressed detection flows straight into the crebain awareness view as empty airspace.

Existing defenses miss both. The NCP action plane is well guarded — `SafetyGovernor` (`NCP/ncp-core/src/safety.rs`) latches ESTOP and the default-DENY `deploy/zenoh-access-control.json5` stops anyone but the `commander` from publishing commands — but neither reasons about *whether the perception it consumed was authentic*. `SimProvenance` in `ncp-core/src/messages.rs` tags whether a frame is simulation output; it does not attest that a splat was observed or that a detector meets spec.

### How it works

Two modules, both fail-closed, neither claiming a formal bound.

**(1) Splat-ingest gate.** At scene load the gate recomputes a **photometric re-render residual**: it rasterizes the candidate splat from the original SfM camera poses and compares each re-render against the corresponding COLMAP input photo (mean per-pixel L1/SSIM over the covisible frustum). Hallucinated geometry betrays itself — where COLMAP had few correspondences, `fillHoles` invented structure the photos never saw, so the residual spikes locally. The residual is scored **only over an explicit signed-provenance channel**: a manifest (SHA-256 over the SPZ payload, the SfM sparse model, and the reference photo set, signed) binds the container to its evidence. Absent a valid signature the gate refuses outright — the residual is meaningless without a trusted reference. The `--fill-holes` density/spherical-harmonic signature (added Gaussians carry a characteristic low-opacity, low-SH-order fingerprint) is a **weaker secondary check**, never the primary decision.

**(2) Adversarial-AP-drop regression.** The harness renders the actual `defense-meshes` GLB airframes (Heron TP, Luna NG, Vector VTOL, …) in Gazebo/Blender, generates physically-realizable patches via **PGD-over-EOT** (random scale, pose, lighting, print-color gamut), textures them onto the airframes, runs the **shipped** CoreML/ONNX model, and measures drone-class AP against baseline. If AP falls below the manwe model contract, the build is quarantined. This is an **empirical certificate**, not a certified radius.

### Ecosystem integration

**crebain.** The splat gate wraps the `scene_load_file` IPC (`src-tauri/src/lib.rs`, the `#[tauri::command]` invoked as `invoke('scene_load_file', { path })`): it resolves the referenced container, runs the signed-manifest + re-render residual check, and returns an error before the scene JSON deserializes — a poisoned scene never renders. The patch regression drives `detect_native_raw` (same file, the cross-platform CoreML/ONNX entry point) against the exported model and gates the build before it reaches an edge node. A green/red border-report panel — styled like the tactical overlay in `DetectionOverlay.tsx` — shows pass/fail per detector × backend.

**NCP.** n/a on the live bus by design: this is a **standalone offline pre-deployment harness**, not a runtime subscriber. The SHA-256 weight/dataset manifest is supply-chain hygiene that belongs inside the melkor/manwe *contracts*, not on the Zenoh planes. Quarantine verdicts can be appended to the build-provenance ledger (Border-Muster) for audit — the same admitted-gaps discipline NCP already keeps in `KNOWN_LIMITATIONS.md`. It composes with the sibling haldir manifest-signing / supply-chain module (which owns key custody) and any provenance-ledger module.

### First build (MVP) and milestones

**MVP.** A Rust/Python harness that (a) renders defense-meshes airframes in Gazebo, runs PGD-over-EOT against the exported ONNX detector, and emits a *signed AP-drop scorecard*; and (b) a Rust SPZ/PLY reader that computes the re-render residual against provided COLMAP photos. One command yields a nightly report card **and** a live “this scene was poisoned” rejection on a `--fill-holes`-tampered SPZ.

**M1 — signed provenance.** Define and sign the manifest schema; wire the `scene_load_file` refusal path end-to-end.
**M2 — faithful patches.** Extend EOT to the real print/lighting distribution; add CoreML alongside ONNX so both shipped backends are gated.
**M3 — border-report panel.** Per-detector × backend Tauri panel; append verdicts to the Border-Muster ledger.

### Honest limitations and scope

This is **not** a certified defense. The re-render residual is a **detector** — a heuristic flag that fires on high reconstruction error — while the only thing with security weight is the **enforced gate**: the fail-closed refusal at `scene_load_file` plus a valid signature. Keep the two distinct. The residual has false positives (legitimately sparse, low-texture, or specular regions) and false negatives (a phantom crafted to keep residual low near covisible pixels). It is also only as trustworthy as its reference photos: an attacker who controls *both* the SfM photos and the container defeats it — the signed-provenance channel narrows but does not close this. The AP-drop regression certifies only the **modeled** EOT distribution on the **rendered** airframes; it says nothing about unseen patches, real-world print/material transfer beyond that distribution, or attacks on classes other than drone. And nothing here protects a drone *in flight* against a novel patch — Warden’s Eye gates builds and scene loads, it is not a runtime perception guard.

### Effort, stack, and dependencies

**Stack:** Rust + Python, Gazebo/Blender, ONNX/CoreML export, PGD-EOT, the `defense-meshes` and `relief-atlas` corpora, Tauri 2. **Effort:** ambitious — roughly a quarter for a credible MVP, most of it in the signed-provenance channel and a physically faithful patch renderer. **Composes with:** the manwe model-contract (AP-small spec and export), melkor’s reconstruction provenance, and the sibling haldir supply-chain / manifest-signing and provenance-ledger modules.


## 9. Dwimordene — Bus honeypot & attacker-deception ward

*A decoy NCP session that looks exactly like a live UAV to anyone probing the bus — but no legitimate node ever touches it, so every write to it is provably hostile, fingerprinted, and tarpitted while the real fleet flies untouched.*

**Difficulty:** ambitious — it must be believable enough to fool a bus scanner, self-contained enough to deploy with zero `ncp-core` edits, and disciplined enough to keep its zero-false-positive guarantee.

**What it defends:** the NCP realm's shared keyspace at the forward base — it plants an early-warning tripwire and an attacker-technique capture surface *before* an adversary ever finds a real effector.

### Threat model

The adversary has reached the realm — network reachability, and possibly a leaked or compromised cert — but does not yet know which session ids drive live effectors. Because NCP addresses *data, not credentials* (`ncp-core/src/keys.rs`: every peer addresses `{realm}/**`, not a server), the natural attack is enumeration: probe `{realm}/session/*/observation` and `{realm}/session/*/sensor` to find a plausible live session, then inject. The two injection vectors are a spoofed `SensorFrame` on the perception plane — false-data injection, and the sensor plane is *itself a control input* that steers the commander (see the explicit note in `deploy/zenoh-access-control.json5`) — or a replayed `command_frame` such as a `descend` on the action plane.

The existing defenses are real but silent. The default-deny Zenoh ACL in `deploy/zenoh-access-control.json5` restricts command-PUT to the `commander` subject and sensor-PUT to `robot`, and the `SafetyGovernor` in `ncp-core/src/safety.rs` latches a zeroed ESTOP frame when a limit is violated. Both are *enforced gates* — they clamp or deny — but neither raises an alarm, attributes a probe, or lets you study a technique. The ACL denies without telling anyone; the `SafetyGovernor` only reacts once a spoofed input has already reached the plant and moved a real track. Today the first sign of probing is a real drone misbehaving. There is no tripwire.

### How it works

haldir stands up a guardian-owned **canary session id** on the real realm. Using the `ncp-core::keys::Keys` builders (`Keys::observation`, `Keys::sensor`) it publishes synthetic `SensorFrame` / `ObservationFrame` JSON on `{realm}/session/{canary}/sensor` and `.../observation` via `NcpBusServer::publish_observation` — the world-readable observation plane — so any observer subscribing to `{realm}/session/*/observation` sees a fully plausible live patrol drone. The frames are driven by a **defense-meshes** render (the `military_drone` GLBs — Heron TP, Luna NG, Vector VTOL) so the phantom's pose and track history look like a moving UAV rather than a static loop.

The trap is the command plane and the RPC. **No** rule in `zenoh-access-control.json5` authorizes any subject to PUT `{realm}/session/{canary}/command/**`, and no commander is configured to open or step the canary id. haldir declares a subscriber on `{realm}/session/{canary}/command/**`; by construction, any sample that arrives is an intrusion — a true zero-false-positive alarm. NCP's RPC is a single queryable at `{realm}/rpc` whose JSON payload carries a `kind` (`"open_session"`, `"step_request"`, `"close_session"`) and a `session_id`; haldir co-declares a *filtering* queryable that replies only when the decoded `session_id == canary`. For every hit it captures the exact technique — replay window, reused `seq`/`ttl_ms`, spoofed-frame structure, verb-confusion (e.g. a `step_request` where a `command_frame` PUT was expected) — and returns a believable but useless tarpit reply (a fake `session_opened`, a canned `observation_frame`) so the attacker believes the injection landed. This is deception, not prevention: it detects and characterizes, then feeds everything else.

### Ecosystem integration

**crebain.** The SOC view reuses `crebain/src/components/DetectionOverlay.tsx` (`Detection[]`, `THREAT_LEVEL_COLORS`, `drawDetectionBox`) and `SensorFusionPanel.tsx` (the `tracks` list with `threat_level`, rendered per `TrackRow`) to show the phantom the attacker believes they are steering — a live view of the decoy engagement. Captured injection signatures are correlated against crebain's real fusion inputs: `sensor_fusion.rs::process_measurements` gates each measurement by Mahalanobis distance against `MEAS_CLUSTER_GATE` (`11.345`, the χ²(3) 0.99 quantile) and confirms a track only after `min_confirmation_hits` (default `3`). An in-progress spoof technique seen on the canary can pre-warn those live tracks — flag frames matching the captured spoofed-`SensorFrame` structure before they clear the gate.

**NCP.** The canary lives at `{realm}/session/{canary}/...`; because its command plane holds no legitimate publisher in `deploy/zenoh-access-control.json5`, any observed write is an alarm on the observation plane. It deploys with **zero `ncp-core` edits**: haldir registers as an NCP consumer by dropping a `.ncp-consumer` descriptor (exactly like `crebain/.ncp-consumer`) so the generic `scripts/check-consumer-pins.sh` / `repin-ncp.sh` tooling pins NCP for it, and it builds only on the public `ncp-core` (`Keys`, `messages`, `NcpBusServer`) and `ncp-zenoh` (`ZenohBus`) crates. Every capture is signed into the sibling haldir **Ledger** and can auto-escalate the **Shadow Governor** and the **Mirror**.

### First build (MVP) and milestones

**MVP.** A Rust guardian service that publishes a synthetic decoy session (canned `SensorFrame` / `ObservationFrame` frames) and logs-plus-alarms on *any* command-plane write or RPC verb targeting the canary id, plus a Tauri 2 + React 19 SOC panel that renders the phantom drone (reusing `DetectionOverlay` / `SensorFusionPanel`) and the captured attacker payload. Demo: run a red-team injector against the realm and watch it get lured onto the decoy, fingerprinted, and tarpitted while the real session is untouched.

**Milestones.**
1. *Believability* — replace canned frames with defense-meshes-driven pose/track playback plus realistic jitter, so a bus observer cannot distinguish the phantom from a live UAV by frame regularity.
2. *Fingerprinting* — structured technique capture (replay window, `seq`/`ttl_ms` reuse, verb-confusion taxonomy), signed into the Ledger with a deterministic per-attacker attribution id.
3. *Correlation and escalation* — wire captured signatures into crebain's fusion pre-warning and auto-escalate to the Shadow Governor and Mirror; broaden the tarpit's response repertoire so it degrades gracefully under a probing adversary.

### Honest limitations and scope

- **It is a detector and deception ward, not an enforced gate.** It observes and lures; it never blocks a write. The actual prevention remains the default-deny ACL (`zenoh-access-control.json5`) and the `SafetyGovernor` ESTOP latch (`ncp-core/src/safety.rs`) — Dwimordene complements them and replaces neither. If the ACL is misconfigured or the realm is open, the honeypot still only characterizes the intrusion on the canary; it cannot stop a parallel write to a *real* session.
- **The zero-false-positive guarantee is conditional.** It holds only while the canary id is guardian-owned and explicitly excluded from every legitimate enumeration or monitoring tool. A well-meaning ops scanner that touches all sessions would trip it, so the canary must be documented as non-operational.
- **Deception is defeatable.** A sophisticated adversary who fingerprints the decoy — no command ever flows back to the phantom, frame statistics too clean, tarpit replies that diverge from a genuine commander — may recognize and avoid it. Tarpitting buys time to revoke a compromised cert; it does not detain an attacker.
- **Attribution is weak without mutual TLS.** The ACL's `cert_common_names` are only *proven* under mTLS; absent that, a capture attributes a technique and a transport identity, not a person.
- **It is not a realm-wide IDS.** It watches one canary keyspace. Coverage scales only with how many canaries you plant and how convincingly they are rendered.

### Effort, stack, and dependencies

**Stack:** Rust (the guardian service, on `ncp-core` + `ncp-zenoh`), Zenoh (the bus), defense-meshes render (the phantom UAV), and a Tauri 2 + React 19 SOC panel reusing crebain's `DetectionOverlay` / `SensorFusionPanel`. **Effort:** ambitious — roughly a few weeks to the MVP tripwire and panel, with the believable rendering and Ledger-signed fingerprinting being the larger, longer tail. **Composes with:** the haldir Ledger (append-only signed capture store), the Shadow Governor (auto-escalation and response), and the Mirror; it leans on crebain for the SOC render surface and on NCP's ACL and `SafetyGovernor` as the enforced backstop it is designed to complement, not supplant.


## 10. Border-Muster & the Marchwarden’s Roll — Cyber-range/CTF + tamper-evident black box

*A Gazebo/ROS cyber-range that weaponizes the defense-meshes corpus into scripted NCP attack scenarios and a scored CTF, with a BLAKE3 hash-chained black box recording every scenario byte-for-byte — the flywheel that generates the very adversary the other nine guardians defend against.*

**Difficulty:** ambitious — it spans a Rust attacker harness, a live Zenoh deployment, a Gazebo world, a signed append-only log, and a Tauri/React replay UI, and it must exercise real seams rather than a mock.

**What it defends:** operator readiness and non-repudiable after-action attribution — it turns documented NCP/crebain threats into live, scored drills and seals an authenticated flight-data record of who commanded what.

### Threat model

The crebain/NCP adversary is the crebain/NCP threat model itself — perception-plane false-data injection, the per-verb RPC ACL gap, the degenerate-geofence bypass, and replay duty-cycling. Today these live only as prose. Concretely: an attacker who reaches the perception plane can publish spoofed `SensorFrame`s (the shape built by `crebain/src-tauri/src/ncp/mod.rs::sensor_frame_from_pose`) clustered inside the `MEAS_CLUSTER_GATE = 11.345` association gate in `crebain/src-tauri/src/sensor_fusion.rs`, satisfying the real sliding-window M-of-N confirmation (`min_confirmation_hits: 3`, `confirmation_window: 5`) so a `TrackStateLabel::Tentative` track is promoted to `Confirmed` — a phantom the fusion pipeline treats as ground truth. The existing defenses miss this because the `SafetyGovernor` (`NCP/ncp-core/src/safety.rs`) governs the *action* plane; it clamps and latches on commands, not on injected perception. The `zenoh-access-control.json5` ACL is key-expression scoped: every RPC verb (`OpenSession`/`StepRequest`/`CloseSession` in `NCP/ncp-core/src/messages.rs`) rides the single `ncp/rpc` key, so `client-queries-rpc` cannot allow open while denying step/close per-verb — an authenticated client can send any verb. And a geofence whose position channel resolves to an empty vector cannot evaluate a breach, so the latch never fires. None of this has been driven end-to-end; operators have never watched it unfold, and the blue-team detectors are unvalidated against a real adversary. When a UAV misbehaves, there is no non-repudiable record of who commanded what.

### How it works

A Rust scenario runner injects **only on the real NCP planes through verified seams** — SAHI and vaporware theater dropped. It opens an mTLS-authenticated Zenoh session and publishes crafted `SensorFrame`s on `ncp/session/*/sensor/**` to drive crebain’s real EKF/fusion promotion; issues verb-confused `StepRequest`/`CloseSession` against `ncp/rpc`; feeds the empty-vector position that neuters the geofence; and replays captured `CommandFrame`s on `ncp/session/*/command/**` with alternating duty cycle to probe the `ttl_ms` HOLD in `NCP/ncp-core/src/resilience.rs::CommandWatchdog`. Gazebo is driven through the existing crebain Tauri commands `transport_spawn_gazebo_model` and `transport_publish_velocity` (`crebain/src-tauri/src/transport/commands.rs`) rendering defense-meshes airframes, so the range is the real stack, not a stub.

In parallel, the **Marchwarden’s Roll** attaches as a zero-control-path, read-only `observer` subscriber (the exact role in `zenoh-access-control.json5`: `declare_subscriber` on the sensor + observation planes, never the action plane). Every observed `SensorFrame`/`CommandFrame`/`ObservationFrame` is folded into an append-only chain: `entry_hash = BLAKE3(prev_hash ‖ frame_bytes ‖ subject ‖ t)`, where `subject` is the mTLS-proven client-cert common-name the ACL binds. Periodically the current head is sealed into an ed25519-signed Merkle anchor (`ed25519-dalek`), giving offline verifiers a compact proof of inclusion and order. The Tauri 2 + React 19 replay viewer reuses crebain’s `DetectionOverlay` and `SensorFusionPanel` (`crebain/src/components/`) to scrub recorded frames; flip one recorded byte and chain re-verification fails, throwing a red **TAMPER** banner naming the exact `frame_id`.

### Ecosystem integration

**crebain.** The range is a first-class crebain consumer: it spawns airframes via `transport_spawn_gazebo_model`, publishes perception via the `sensor_frame_from_pose` shape, and the *first CTF flag* is a ghost track rendering in `DetectionOverlay` under the live `min_confirmation_hits: 3` / `confirmation_window: 5` gate **with no `CommandFrame` ever emitted** — a pure perception compromise. The Roll’s viewer is crebain UI reused verbatim, so an analyst scrubs an incident with the same panels the operator saw live.

**NCP.** The attacker publishes on the live Zenoh perception/action/rpc planes; the Roll binds as the read-only `observer` subject, its entries stamped with the mTLS-proven subject. It exercises the same seams that **Fëanor’s Mark** hardens (the perception-PUT restriction, per-verb RPC authorization, geofence channel validation) and validates the sibling blue-team detector guardians live — a partition or restart is logged as an explicit gap in the chain, never papered over.

### First build (MVP) and milestones

**MVP:** one Gazebo world with three defense-meshes airframes; a Rust scenario runner that publishes spoofed `SensorFrame`s to promote a phantom `Confirmed` track; a React scoreboard; and the append-only BLAKE3 Roll with the tamper-banner replay viewer. First flag: the ghost track appears with no `CommandFrame`. First Roll demo: flip a byte, get the red TAMPER naming the `frame_id`.

**Milestone 2:** add the remaining scripted scenarios — verb-confused RPC, empty-vector geofence, alternating replay — each a scored flag with expected blue-team detection.

**Milestone 3:** ed25519 Merkle anchoring with an offline `verify` CLI, plus a contested-EW convoy-overwatch drill where the sealed Roll proves the injected frame, the `t` the `SafetyGovernor` latched, and whether an operator HOLD zeroed the actuator within `ttl_ms`.

### Honest limitations and scope

The Roll is an **authenticated after-action FDR** — for attribution, ROE/legal review, and training — **not** a claim to close any wire gap. It changes nothing on the live control path. As an off-path tap it *cannot prove it saw all frames*; partitions and restarts are recorded as explicit gaps, not silently dropped, and completeness beyond those markers is not claimed. BLAKE3 chaining plus ed25519 anchors give tamper-evidence and non-repudiation *of what was recorded*, not tamper-*prevention* and not proof of totality. The range validates that detectors *fire*; it does not by itself convert a detector into an enforced gate — that hardening is Fëanor’s Mark’s job, and a green scoreboard means the blue team *noticed*, not that the wire was closed. Residual risks: a scenario that drifts from the shipped crebain/NCP symbols would teach a false model, so scenarios must pin the real gate constants and ACL; and key management for the anchor signer is out of scope for the MVP.

### Effort, stack, and dependencies

**Stack:** Rust (scenario runner + Roll), Gazebo/ROS, Zenoh, `blake3` + `ed25519-dalek` (both new dependencies — neither ships in NCP or crebain today), Tauri 2 + React 19. **Effort:** ambitious — roughly a quarter for a credible MVP, more for full scenario coverage and the signed-anchor verifier. **Composes with:** crebain (transport commands, fusion gate, `DetectionOverlay`/`SensorFusionPanel`), NCP (`zenoh-access-control.json5` observer role, `SafetyGovernor`, `CommandWatchdog`), Fëanor’s Mark (hardens the seams this range attacks), and the sibling blue-team detector guardians it validates live.


