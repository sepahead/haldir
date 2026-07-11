<!-- markdownlint-disable MD013 MD024 -->

# Haldir discussion and decision record — 2026-07-11

## Purpose and authority

This document records the complete reasoning and decisions from the July 2026 Haldir project-selection discussion. It is a synthesized decision record, not a verbatim chat transcript. It preserves the questions asked, evidence inspected, disagreements raised, changes in recommendation, implementation boundaries, PhD assessment, neuromorphic-platform options, and the final constraint that no physical neuromorphic hardware is currently available.

The companion [Haldir project audit](HALDIR-PROJECT-AUDIT-2026.md) remains the authoritative detailed analysis of all ten cybersecurity proposals. This record explains how the recommendation evolved after the audit, especially around neuromorphic hardware and repository coupling.

When the two documents differ, the later decisions here take precedence for project planning:

- physical neuromorphic hardware is **not** an MVP or thesis dependency;
- the research is described as portable-SNN, backend-aware, or neuromorphic-ready assurance;
- Haldir remains a separate repository with contract-level integration;
- Watchword-Neuro is the strongest standalone research proposal;
- Haldir Gate is the system and enforcement spine;
- Border-Muster is the evidence spine.

## Final decisions at a glance

| Question | Decision | Consequence |
| --- | --- | --- |
| Which single non-PID Haldir project should be pursued? | Build one combined program: **Haldir — backend-aware mission authorization and semantic admission for portable SNN controllers**. | Gate supplies enforcement; Watchword-Neuro supplies the research core; Border-Muster supplies evaluation. |
| Is the original Gate proposal enough for a PhD? | No. It is strong engineering and can be a substantial chapter, but the plain reference-monitor/policy-gateway pattern is established. | Doctoral novelty must come from semantic controller identity, cross-backend action-equivalence, failover composition, and adversarial evidence. |
| Is the combined program worthy of part of a PhD? | Yes, conditionally and significantly. | It needs formal questions, baselines, held-out experiments, and explicit kill criteria rather than architecture claims alone. |
| Which proposal ranks first on its own? | Watchword-Neuro. | It must not be deferred or treated as decorative hardware work. |
| Which component should be implemented first? | Gate's authority-boundary spike, together with the minimum contracts and range. | The spike must first prove complete scoped mediation, identity binding, reversion, and timing feasibility. |
| Should Lava be used? | No new dependency on Lava. | Lava is archived; use NIR plus independent backends instead of replacing one monolithic stack with another. |
| Which physical platforms would be preferred if access later appears? | SynSense Xylo/Rockpool first for reproducible constrained deployment; SpiNNaker2 second for flexible real-time control, conditional on access. | Both remain optional validation targets, not committed deliverables. |
| What should be used with no hardware access? | NEST + a bounded manifest/NIR adapter + Rockpool device mapping/validation + XyloSim + an independent open backend such as Norse or snnTorch. | Claims stop at simulator, validated hardware-constrained profile, and backend conformance. |
| Should Haldir be its own repository? | Yes. | It is independently released, audited, keyed, and deployed; it imports no Engram or Crebain internals. |
| How tightly should it couple to the ecosystem? | Loose in source code, tight in versioned contracts, strict in deployment. | Haldir pins NCP APIs, consumes Engram manifests/intents, and emits standard final NCP commands to Crebain. |
| Should hardware SDKs enter the Gate binary? | No. | Vendor-specific compilation/inspection lives in optional adapters or offline admission tools. |
| Should a new integration repository be created now? | No. | Keep Border-Muster under Haldir initially; extract it only after it serves multiple independent controls. |

## Discussion chronology

1. The task began as a choice among ten non-PID Haldir cybersecurity proposals, with particular interest in Engram, Crebain, and neuromorphic hardware.
2. The existing catalog and downloaded audit were compared against the current local repositories rather than accepted at face value.
3. NCP 0.7.1 invalidated several old bug-based proposal rationales, while Crebain and Engram were found to have useful partial paths but no live Engram → Gate → Crebain deployment.
4. Fable 5 at maximum effort and independent reviewers agreed that inline Gate was the best system spine but not a sufficient research novelty claim.
5. The evaluation was rebuilt as ten project lenses plus five advisor lenses with visible weights and scores. Watchword-Neuro became the strongest standalone proposal; Gate became second and remained the enforcement spine.
6. The combined thesis direction became controller-bound mission authorization, semantic SNN deployment identity, cross-backend action-equivalence, and a reproducible adversarial range.
7. Lava was rejected after its archive status was verified. Xylo/Rockpool and SpiNNaker2 were investigated as preferred future physical targets, with SpiNNaker1/EBRAINS as a fallback.
8. The repository boundary was examined. Haldir remained independent, depending narrowly on NCP and integrating with Engram/Crebain only through released contracts and runtime messages.
9. The user then confirmed that no physical neuromorphic hardware is available. The plan was revised to NEST, a bounded manifest/NIR adapter, Rockpool mapping/validation plus XyloSim, and another open software backend, with hardware removed as a deliverable and claim.
10. The final project title and roadmap were updated to emphasize backend-aware semantic admission and mission authorization for portable SNN controllers.

## Starting request and constraints

The project-selection request established the following constraints:

1. Review ten Haldir cybersecurity ideas through ten primary lenses.
2. Add five skeptical lenses from Claude Code Fable 5 at maximum effort.
3. Exclude PID work because Galadriel was already considered complete for selection purposes.
4. Choose one non-PID project with high cybersecurity impact.
5. Prefer a project that fits Crebain, NCP, Engram/Paper2Brain, and the broader `sepahead` ecosystem.
6. Investigate neuromorphic hardware and Engram–Crebain integration without forcing a hardware story.
7. Explain every proposal in detail: what it entails, why it was chosen, how to implement it, how to validate it, and when to stop.
8. Evaluate whether the selected project is significant enough to form part of a PhD.
9. Preserve honesty about current repository state and distinguish implemented evidence from a proposed architecture.
10. Commit and push documentation changes normally, never by force-pushing.

The user later added a decisive practical constraint: **there is no current access to physical neuromorphic hardware**. That does not invalidate the project, but it changes the title, claim boundary, backend choices, roadmap, and publication language.

## Evidence inspected

### Haldir

Haldir was a design/documentation repository rather than an implemented reference monitor. The original catalog contained valuable ideas, but some were based on NCP defects already corrected in later releases. The repository contained no Gate service, live policy path, controller-admission schema, or latency/failure evidence.

### NCP

The inspected NCP revision was `e3e5da4de96e8b291b3c582bd31cf41afbfad3cc`, version 0.7.1. It already supplied:

- typed wire messages and validation;
- explicit command sequence and TTL primitives;
- `ActionBuffer` and configurable `SafetyGovernor` primitives;
- per-verb RPC key separation;
- Zenoh transport and secure deployment examples;
- ACL verification tooling.

Important limitations remained for Haldir:

- a raw subscriber callback exposes key and bytes, not the authenticated publisher certificate principal;
- mTLS and topic/key ACLs do not authorize a particular mission action;
- transport publication does not automatically invoke a trusted plant-side physical governor;
- an ACL on one final command key does not close direct ROS/MAVROS actuator paths;
- no neural-controller semantic identity or Haldir application signature exists in NCP.

### Crebain

The inspected Crebain revision was `08ccafe5392465ea179406665ae936dd561aef6f`, plus local documentation changes. It contained an NCP library path and a 50 Hz `CommandPlant`, but:

- the NCP feature was off by default;
- existing Tauri commands did not start a live product action loop;
- no live Rust callback completed a MAVROS/PX4 actuator path;
- direct ROS/MAVROS command paths existed outside NCP;
- real PX4/ArduPilot integration remained planned work;
- the existing command adapter enforced a narrower sequence/TTL/horizon, exact vec3/unit, and ceiling contract rather than a complete stateful physical monitor.

Therefore the first honest path is a deterministic plant or Gazebo integration. PX4-SITL is a later integration gate, not a current capability.

### Engram / Paper2Brain

The local `engram` checkout corresponds to the `sepahead/Paper2Brain` repository. The inspected committed revision was `12833c7eae49a69095001bb74bf307a86c9012b5`, plus local neurocontrol work.

Engram already provided real value:

- paper/model generation and artifact governance;
- content-addressed artifact integrity;
- a real NEST backend;
- NCP-shaped controller examples;
- production/validation concepts and evidence receipts.

The exact gap was narrower than “Engram has no artifacts,” but still important. Current `NetworkRef` and `NestBackend` did not completely describe or reconstruct a general controller graph with projections, synapse models, weights, delays, codecs, quantization, compiler mapping, and backend semantics. The multi-UAV example used real NEST computation but drove a local kinematic loop rather than Zenoh, Gate, Crebain, or PX4.

The Watchword work must extend, not dismiss, Engram's existing artifact machinery.

## Evaluation process

### Why the downloaded audit was not accepted unchanged

The downloaded audit correctly identified mission authorization as a missing boundary, but several conclusions were too strong:

- its twenty listed weights summed to 104 rather than 100;
- it showed no raw per-proposal score matrix, making the totals irreproducible;
- it compared a broad Gate portfolio against individual components that Gate later absorbed;
- it treated an exact command-key ACL as if it established complete plant mediation;
- it assumed Gate could bind a Zenoh sample to an mTLS common name without a designed identity mechanism;
- it called Phase 1 artifact-bound even though the complete Engram controller representation was deferred;
- it mixed byte preservation with normalization and unresolved multi-controller sequence ownership;
- it treated generic HOLD/zero velocity as physically safe across vehicle classes and phases;
- it initially understated prior art in runtime assurance, reference monitoring, and robot policy enforcement;
- it gave the Gate MVP more neuromorphic specificity than its controller-agnostic action boundary justified.

The resulting revision used exactly ten requested project lenses plus five Fable advisor lenses, exposed every score, made weights sum to 100, and scored each standalone proposal before composing the final program.

### Ten project-selection lenses

1. consequence and unmet need;
2. preventive authority and path to complete mediation;
3. security soundness;
4. NCP fit;
5. Crebain fit;
6. Engram fit;
7. neuromorphic specificity;
8. deliverability;
9. evidence quality and falsifiability;
10. ecosystem leverage.

### Five Fable advisor lenses

1. prior-art distance;
2. formalizable research question;
3. cross-backend generality;
4. publishable evaluation;
5. killability and thesis risk.

### Corrected standalone ranking

| Rank | Proposal | Score / 100 | Interpretation |
| ---: | --- | ---: | --- |
| 1 | Watchword-Neuro | 86.8 | Strongest Engram, neuromorphic, and research contribution. |
| 2 | Haldir Gate | 82.8 | Strongest enforcement/system spine, but lower standalone novelty and neuromorphic specificity. |
| 3 | Border-Muster v2 | 81.6 | Essential evidence infrastructure and possible benchmark contribution. |
| 4 | Vilya | 78.0 | Required deployment identity and least-authority engineering. |
| 5 | Nénya | 75.8 | High-impact navigation integrity, but less aligned with Engram and a crowded field. |
| 6 | Marchwarden secure envelope | 73.8 | Necessary reusable protocol engineering with limited novelty. |
| 7 | Rúmil v2 | 67.0 | Useful independent plant-response monitor if genuine design diversity is achieved. |
| 8 | Warden's Eye | 61.2 | Important perception assurance but broad, crowded, and difficult to validate physically. |
| 9 | Marchwarden's Roll | 59.8 | Useful evidence module; signed/Merkle logs are established. |
| 10 | Dwimordene v2 | 35.6 | Bounded observability spike only until router denial telemetry is proven. |

The scores are a transparent selection heuristic, not statistical or academic evidence. Small differences are not meaningful enough to claim objective superiority. The stable conclusion is the three-part program:

```text
Watchword-Neuro  -> scientific identity/conformance core
Haldir Gate      -> preventive system/enforcement core
Border-Muster    -> reproducible evidence/evaluation core
```

## Fable and independent-review conclusions

Claude Code Fable 5 was run at maximum effort as a skeptical PhD committee advisor with read access to the downloaded audit and the relevant ecosystem repositories. Independent technical and academic reviews were also performed.

All reviews converged on the same high-level verdict:

- building the inline authority boundary first is sound engineering sequencing;
- moving from a detached countersign to exclusive inline publication is a substantive design improvement;
- Gate alone is a reference-monitor/runtime-assurance/PEP-PDP composition, not a novel thesis;
- Watchword-Neuro contains the stronger original research question;
- Border-Muster is necessary to turn architecture into evidence;
- the neuromorphic story must concern controller identity and cross-backend behavior, not simply the fact that NEST produced spikes;
- physical-hardware claims must be conditional on real access and measurements;
- exact score totals must not substitute for related work, hypotheses, baselines, experiments, and negative results.

Fable also noted that the Galadriel material looked like a pre-registered study rather than fully committed outcome evidence. Galadriel remained excluded because the user explicitly declared it complete for selection and required a non-PID project. Haldir does not claim Galadriel's possible future results as part of its novelty.

## Selected program

### Final name under the current access constraint

The preferred current title is:

> **Haldir — backend-aware mission authorization and semantic admission for portable SNN controllers**

“Attested neuromorphic hardware” is intentionally absent. Without a device root of trust and physical access, “attestation” would overstate what can be proven. The project may use the narrower terms “signed admission,” “semantic deployment identity,” “backend-constrained execution profile,” and “neuromorphic-ready.”

### Why this is one coherent Haldir project

The combined program is not a claim that Gate won the ranking by absorbing its competitors. The parts have different roles:

- **Watchword-Neuro** defines the admitted controller and deployment relation.
- **Gate** enforces mission authority over that admitted identity and exact intent.
- **Border-Muster** tests both against baselines, attacks, faults, and backend divergence.
- **Vilya**, signed envelopes, and receipts are necessary supporting system components.

The one-project boundary is the security problem, not a single executable:

> How can an opaque SNN controller receive narrowly scoped mission authority when its execution can move across heterogeneous software and hardware-constrained backends?

The public demonstrations remain benign navigation, inspection, hold/recovery, and simulated plant-control tasks. The project is not a weapons-release or target-selection system, a flight-safety certification, a universal controller-safety proof, or a hard-real-time guarantee derived from ordinary Linux benchmarks.

## Gate and Watchword architecture

### Intended data flow

```text
Engram / controller backend
        |
        | ControllerBundleManifestV1
        | SignedIntentV1(exact NCP CommandFrame bytes)
        v
controller-specific Haldir intent key
        |
        v
Haldir Gate
  - transport/signing identity checks
  - bundle/admission checks
  - lease/replay checks
  - bounded physical and mission predicates
  - Cedar ABAC over typed context
        |
        +--> DecisionReceiptV1 / bounded local spool
        |
        | standard final NCP CommandFrame
        v
Crebain CommandPlant / actuator adapter
        |
        +--> accepted-command and adapter-result evidence
        v
deterministic plant, then Gazebo/MAVROS
```

### Complete scoped mediation

Gate is a reference monitor only inside a declared boundary where every actuator-affecting route is enumerated and closed or independently constrained. The Phase 0 authority graph must include:

- NCP command keys and named-command variants;
- ROS velocity and position publishers;
- MAVROS setpoint topics;
- arm, mode, takeoff, land, and emergency services;
- native callbacks and action-loop lifecycle;
- UI actions, test hooks, and direct developer paths;
- shutdown and reconnect behavior.

For the assurance profile, the controller publishes only to a controller-specific intent key. Haldir alone publishes the final standard NCP command key. Crebain consumes that final key. A static ACL test is insufficient; a live delivery/non-delivery matrix must exercise distinct certificates and recipients.

If an ordinary controller can still reach ROS/MAVROS directly, the result is an inline monitor on one route, not complete mediation of the plant.

### Principal binding

A Zenoh subscription callback currently yields a key and payload rather than the publisher's mTLS certificate identity. Therefore `controller_id` in a key suffix is not authentication by itself.

The MVP uses both:

1. an exact certificate-principal-to-exact-intent-key ACL mapping; and
2. a signed application envelope whose signing key is bound to the admission and lease.

Gate verifies that the key, signing key, claimed controller ID, mission, vehicle, session, lease epoch, controller-bundle digest, and exact inner command bytes agree. No identity field is accepted solely because the controller wrote it into the payload.

### Signed intent

`SignedIntentV1` is a deterministic, domain-separated envelope containing:

- protocol/schema version;
- controller signing-key ID;
- controller and intent-key identity;
- mission, vehicle, NCP session, lease, and lease epoch;
- intent sequence, issued/expiry values, time-basis identifier, and permitted skew/uncertainty;
- controller-bundle and backend-profile digests;
- exact inner NCP `CommandFrame` bytes;
- signature over every preceding field and the protocol domain.

Deterministic CBOR/COSE or an equivalently precise format is preferred over reserialized ordinary JSON. Rust, Python, and TypeScript golden vectors must cover positive, malformed, and adversarial inputs.

Gate evaluates lease lifetime and replay progression against its local monotonic clock, anchored when the lease is admitted. An external timestamp is authoritative only when its source, time basis, synchronization/uncertainty bound, and skew policy are named by the admission; controller wall time is never allowed to create a fresh epoch. Replay state is bounded per controller, vehicle/session, and lease epoch. Legitimate gaps can be accepted; duplicates and stale epochs are rejected. The MVP invalidates every active lease on Gate process restart or host reboot and requires the lease authority to issue a higher, fresh epoch. It restores a durable epoch/replay watermark only to reject old authority; it never tries to reconstruct a pre-restart monotonic deadline. Controller restart or wall-clock reset likewise does not restore or reset authority.

### Downstream sequence ownership

The first version admits one controller per vehicle lease. It can preserve the exact enclosed NCP command bytes on ALLOW while Gate remains the only final-key publisher and validates the controller's sequence progression.

The MVP uses one explicit rule for Gate-authored reversion so it never creates a second uncontrolled sequence producer. Ordinary controller frames are accepted only through `ncp_core::JSON_SAFE_INTEGER_MAX - 1`, reserving the maximum wire sequence for Gate. On reversion, Gate first commits a local durable transition from `ACTIVE` to `TERMINATING/CLOSED`, records the replay watermark and proposed `last_accepted_downstream_seq + 1` frame, and blocks every later frame from that lease/epoch. Only this local state transition is atomic. Gate then attempts and records the Zenoh publication; publication and delivery are not part of the transaction. A crash or publish failure leaves the lease closed and falls back to bounded downstream expiry rather than reopening old authority.

The reversion receipt identifies Gate as the origin and binds the generated bytes, local state commit, publish attempt/result, and any later accepted/applied observation. Normal ALLOW decisions remain byte-preserving; a Gate-authored reversion is a separately modeled exception, not a transformed controller command. Tests cover `MAX - 1`, the reserved `MAX`, arithmetic overflow, crash between state commit and publish, publish failure, and duplicate recovery.

Controller handoff ends the old lease. While the downstream NCP stream remains live, any new frame would have to advance above the reversion sequence. The byte-preserving MVP instead waits until the previous command/reversion TTL, `ActionBuffer` horizon, and watchdog state have expired before activating a fresh higher lease epoch with a potentially lower sequence anchor. If later versions multiplex controllers, Gate terminates the intent protocol and issues every canonical downstream frame with its own sequence. At that point receipts bind exact input and output bytes and explicitly describe the transformation; byte-identity claims end.

### Policy split

The trusted bounded Rust monitor handles numeric, temporal, stateful, and geometric predicates:

- exact schema, shape, frame, units, and finite-value checks;
- command TTL and a deployment-specific cap far below NCP's protocol maximum;
- lease, state, and observation freshness;
- sequence, replay, and epoch state;
- speed, acceleration, slew, and duty windows;
- allowed and denied regions under an explicit coordinate model;
- state uncertainty and source availability;
- phase transition and emergency priority rules;
- per-principal rate and bounded queue limits.

Cedar handles principal/action/resource/context authorization over derived booleans and bounded/scaled integers. It is not the stateful vector-math or hard-real-time engine. Any policy diagnostic or evaluation error overrides an otherwise-allow result.

The MVP physical predicates are reject-only. If a later monitor clamps, normalizes, or rewrites a command, it creates a new output frame and a transformation-bound receipt rather than pretending to preserve bytes.

### Denial and reversion

Denial is not an instantaneous physical veto. A previously allowed command remains effective according to its remaining downstream `CommandFrame.ttl_ms`, `ActionBuffer` horizon semantics, and actuator/flight-controller behavior unless the separately published lease-terminating reversion is delivered and applied. A denial that does not request that transition is expiry-only. A requested reversion whose publish or delivery fails also falls back to bounded expiry while the local lease remains closed; neither path can inject an uncoordinated sequence value or restore the old epoch.

Each vehicle and mission phase therefore has a declared reversion contract. Zero velocity may be suitable for a stationary multirotor experiment but is not a universal safe state for fixed-wing flight, landing, obstacles, or degraded navigation.

The measured/formal bound contains:

```text
detection and decision scheduling
+ explicit reversion publish/delivery delay, when used
+ remaining downstream command validity/horizon for the expiry path
+ one Crebain control tick
+ actuator or flight-controller transition time
```

### Decision and application evidence

`DecisionReceiptV1` can attest:

- exact intent and proposed output digests;
- principal, mission, vehicle, lease, and controller bundle;
- policy, admission, and state-snapshot digests;
- allow/deny/error result and stable reasons;
- sequence/epoch relationship;
- local monotonic processing times and latency, distinguished from any qualified external timestamp and its time basis;
- local publish attempt/result.

A local Zenoh `put()` completion does not prove Crebain received or applied a command. Separate Crebain accepted-command and actuator-adapter-result events are needed for delivery/application evidence. Measured plant response is a further distinct observation.

Evidence is asynchronously appended to a bounded local spool. A remote receipt collector, database, or transparency service never blocks the command worker.

## Controller semantic identity

### Why a file hash is insufficient

A package digest is necessary for byte integrity, but a portable SNN deployment can change behavior while retaining the same high-level model name or claimed topology. Relevant changes include:

- graph topology and connection rules;
- learned weights or weight distributions;
- random seeds and initial state;
- neuron and synapse equations/parameters;
- input preprocessing and spike encoder;
- action decoder, units, frames, and postprocessing;
- timestep, chunking, scheduling, reset, and horizon behavior;
- numerical precision and quantization;
- compiler transforms, placement, routing, and scaling;
- backend/runtime/compiler/driver/firmware versions;
- online plasticity and checkpoint lineage.

### ControllerBundleManifestV1

In the proposed integration, Engram will own the `ControllerBundleManifestV1` schema and produce a profile-complete declarative manifest containing the logical network, execution contract, provenance, and behavioral fixtures. This does not exist completely today; building it is Phase 3 work. Haldir separately owns `ControllerAdmissionProfileV1`, which names the accepted manifest version, required fields, bounded primitive subset, canonicalization rules, and acceptance tests. Haldir records approval of the manifest digest and admission-profile digest through `AdmissionRecordV1`.

The manifest must be sufficient to reconstruct the fixed-weight controller without hidden arbitrary PyNEST code or ambient configuration. This requires extending Engram's current backend with a bounded graph/projection builder for populations, projections, synapse models, weights, delays, stimuli, recorders, and codecs.

The initial controller prohibits online learning. A later adaptive-controller profile would need an approved update rule, permitted state/weight region, checkpoint lineage, update authority, and rollback behavior.

### Identity relations

The project distinguishes three relations:

1. **Byte identity:** the exact artifact bytes match.
2. **Semantic deployment identity:** all security-relevant fields and an approved transformation lineage match.
3. **Authorization-equivalence:** different backend executions may differ internally while Gate decisions and closed-loop actions remain within a pre-declared authorized relation.

The research does not demand identical spike trains. Numerical integration, integer quantization, scheduling, reset semantics, and recurrent dynamics make that unrealistic. The relevant observable is the action boundary and plant trajectory.

### Backend compilation receipt

Haldir owns the backend-neutral `BackendCompilationReceiptV1` schema; each backend adapter produces instances, and a separately versioned Haldir backend-admission profile defines backend-specific required fields and acceptance rules. For each hardware-constrained or software backend, the build/deployment process produces a signed receipt containing:

- canonical logical graph digest;
- adapter/compiler/SDK versions;
- supported/translated neuron primitives;
- timestep, reset, delay, and scheduling choices;
- precision, quantization, and weight-scaling rules;
- placement/routing or configuration digest;
- firmware/runtime identifiers when available;
- calibration or frontend configuration;
- validation-corpus version and results.

By itself, the signature authenticates the signer's assertion about compiler inputs, configuration, load requests, and recorded observations. It proves that compilation or loading occurred only when those stages are independently measured and bound to a trusted build/load agent. Without that measured path and a device-rooted attestation mechanism, it is signed provenance rather than proof of execution, and it does not cryptographically establish what silicon executed.

## PhD assessment

### Direct verdict

The combined Haldir program is significant and worthy of being part of a PhD. It can become a thesis spine if the semantic identity and cross-backend work succeeds. Gate alone is a strong engineering artifact and substantial systems chapter, not sufficient doctoral novelty.

### What is established prior art

The thesis must not claim originality for:

- an inline reference monitor or policy-enforcement point;
- ABAC/Cedar at an action boundary;
- mTLS and key/topic ACLs;
- external runtime assurance for an opaque or neural controller;
- signed messages, provenance, SBOMs, or Merkle evidence logs;
- running a NEST SNN in a control loop;
- NIR as a portable neural representation.

Relevant prior work includes [RTron](https://arxiv.org/abs/2103.12365), [SOTER on ROS](https://arxiv.org/abs/2008.09707), [Neural Simplex](https://arxiv.org/abs/1908.00528), [Black-Box Simplex](https://arxiv.org/abs/2102.12981), [Cedar](https://arxiv.org/abs/2403.04651), [NIR](https://www.nature.com/articles/s41467-024-52259-9), [in-toto](https://www.usenix.org/conference/usenixsecurity19/presentation/torres-arias), [RATS](https://www.rfc-editor.org/rfc/rfc9334), and a 2026 [neuromorphic Simplex-family safety monitor](https://www.sciencedirect.com/science/article/pii/S0925231226006120).

### Plausible original contributions

1. **Controller-Bound Mission Authorization:** a formal relation binding principal, controller identity, deployment profile, codec/timing, mission/vehicle/phase, trusted state, exact intent, lease epoch, final command, and reversion semantics.
2. **Semantic Deployment Identity for SNNs:** a security identity over graph, weights, codec, timestep, quantization, compilation/mapping, runtime, and validation lineage, building on NIR rather than replacing it.
3. **Cross-backend action-equivalence:** a relation predicting authorization decisions and closed-loop trajectory bounds despite internal spike/numeric divergence.
4. **Cyber-to-physical failover composition:** a model connecting leases, replay epochs, state expiry, downstream TTL/horizon, queue overload, crashes, partitions, and vehicle-specific reversion.
5. **Adversarial benchmark:** a reproducible corpus linking valid-credential misuse and controller-deployment substitutions to Gate decisions and plant outcomes.

### Research questions

#### RQ1 — Authorization sufficiency

What is the minimum external contract sufficient for mission authorization of an opaque SNN controller, distinct from physical-envelope safety?

#### RQ2 — Semantic identity

Which logical, codec, timing, numeric, compiler, mapping, runtime, and firmware/profile fields are required for a security-relevant controller identity, and how should approved transformations be classified?

#### RQ3 — Backend portability

Under what action/trajectory relation are two backend executions authorization-equivalent despite spike timing, quantization, reset, and scheduling differences?

#### RQ4 — Bounded policy enforcement

What mission-policy fragment is expressive enough to matter while remaining reviewable and empirically deadline-safe at 20–50 Hz?

#### RQ5 — Reversion composition

How do mission leases compose with state freshness, clock faults, restart, router loss, downstream command validity, action buffering, and plant-specific reversion?

### Hypotheses

- **H1:** Within the declared mediation boundary, controller-bound mission authorization prevents all pre-registered unauthorized delivered actions that remain possible under NCP mTLS/ACL plus an explicitly configured physical governor, within a fixed benign false-denial/mission-completion budget.
- **H2:** In a field-ablation study whose candidate fields, security classifications, mutation corpus, and train/held-out split are fixed before candidate evaluation, every field pre-classified as security-relevant has at least one training-corpus case where omitting it hides an authorization-relevant behavior change; the profile-complete bundle then detects held-out substitutions and classifies held-out approved transformations.
- **H3:** An action/trajectory equivalence relation whose tolerances are fixed from policy/plant margins predicts held-out cross-backend decisions better than spike equality or package-hash equality.
- **H4:** Bounded Rust predicates plus Cedar ABAC sustain the declared 20–50 Hz workload with a pre-registered p99.9 budget, bounded queues/memory, and no missed deadline in the stated campaign.
- **H5:** Loss of fresh authority reaches a declared reversion state within the formally derived detection, delivery/expiry, control-tick, and actuator-transition bound, with no stale epoch regaining authority after restart.

### Required baselines

- direct NCP with mTLS/ACL;
- NCP with explicitly configured `SafetyGovernor`/physical monitor;
- generic Cedar/OPA-style inline PEP;
- detached countersign sidecar;
- RTron-like inline coordination where comparable;
- SOTER/Simplex-style monitor and fallback;
- process/certificate controller identity only;
- package SHA-256 only;
- signed provenance without semantic deployment identity;
- NIR portability tests without mission authorization.

### Publication-sized units

1. **Gate systems paper/chapter:** formal authority/reversion model, bounded implementation, baseline comparison, tail-latency/resource evaluation, and fault campaign.
2. **Watchword research paper/chapter:** profile-complete fixed-weight controller bundle, field-ablation/substitution study, transformation taxonomy, and signed admission.
3. **Cross-backend paper/chapter:** held-out action-equivalence study, benchmark/range, and raw dataset across independent software and hardware-constrained profiles.

## Neuromorphic platform discussion

### Why Lava was removed from the roadmap

Intel archived the public Lava repository on 2026-05-13 and stated that it would not maintain, fix, release, or accept patches for the project while developing a next-generation Loihi architecture and SDK. The replacement was not a dependable implementation target at the time of this decision. See the [official Lava archive notice](https://github.com/lava-nc/lava).

The architectural response is not to choose another all-encompassing framework. Haldir instead separates:

- **NIR or a rigorously mapped subset** for the portable logical graph;
- **ControllerBundleManifestV1** for security-relevant semantics beyond NIR;
- **backend adapters** for compilation, mapping, execution, and evidence;
- **Gate** for backend-independent mission authorization;
- **action/trajectory tests** for behavioral conformance.

This makes backend replacement an experimental variable rather than an architectural rewrite.

### Physical-platform options considered

| Rank/status | Platform | Strength for Haldir | Blocking limitation |
| --- | --- | --- | --- |
| 1 if hardware later becomes available | SynSense Xylo + Rockpool | Accessible dev-kit path, active 2026 maintenance, NIR import/export, constrained integer execution, device-model simulation after validated mapping, strong semantic-identity experiment. | Restricted network/input/output capacity, sensor-oriented variants, beta NIR bridge, sales-mediated hardware, no public device-attestation primitive found. |
| 2, conditional | SpiNNaker2 + py-spinnaker2 | Flexible real-time SNN/control target, NIR import, explicit mapping choices, Brian2 preparation path, bidirectional streaming. | Some dependencies remain private and access-controlled; physical/software access must be confirmed; stack is not claimed production-grade. |
| Remote academic fallback, allocation-dependent | Manchester SpiNNaker1 through EBRAINS | Mature PyNN ecosystem and remote physical system for accepted research. | Access requires an account plus an accepted application/allocation; older hardware and queued remote operation are poorly suited to a live 50 Hz loop. |
| Specialist perception option | SynSense Speck | Strong event-camera/SCNN fit for Warden's Eye. | Not a general portable control substrate. |
| Academic batch-conformance option | BrainScaleS-2 | Mixed-signal accelerated dynamics and PyNN interface provide strong substrate divergence; current NIR documentation lists paths through `hxtorch` and `jaxsnn`. | Remote/batch allocation and accelerated execution are poorly suited to a live 50 Hz Crebain loop; the NIR paths still require bounded-subset and compatibility validation. |
| Not selected | BrainChip Akida | Current commercial inference platform and ONNX-oriented tooling. | More proprietary and less aligned with arbitrary recurrent SNN/NIR controller semantics. |

### SynSense Xylo and Rockpool

Xylo was the lowest-risk first physical target before the no-hardware constraint was stated because:

- Rockpool was actively maintained, with version 3.1.0 released on 2026-07-02. See the [Rockpool changelog](https://rockpool.ai/advanced/CHANGELOG.html).
- Rockpool supported bidirectional NIR import/export for Torch-backed models, although the documentation labeled the API beta. See [Rockpool NIR import/export](https://rockpool.ai/advanced/nir_export_import.html).
- The device-specific mapping and design-rule flow could create a validated hardware configuration, with corresponding execution through `XyloSim`.
- Xylo's fixed integer arithmetic, 8-bit weights, limited fanout, bit-shift decay, fixed timestep, and device limits create meaningful Watchword transformations.
- Current XyloAudio3/XyloIMU documentation and firmware resources existed. See [SynSense developer resources](https://www.synsense.ai/developer/).

Xylo is not a general NEST substitute. Depending on the device, it offers roughly 16 SNN input channels, hundreds to about one thousand hidden neurons, and a small output layer. A controller must be intentionally designed to fit that target.

Rockpool is distributed under AGPL-3.0, with commercial licensing available on request. See the [official repository and license statement](https://github.com/SynSense/rockpool). That is an additional reason not to link Rockpool into the Haldir Gate core. Any distribution plan must receive an appropriate licensing review; process separation alone is not a legal conclusion.

### SpiNNaker2

SpiNNaker2 was the flexible second choice because:

- its NIR adapter maps IF/LIF/CuBa-LIF, linear/affine, convolution, flattening, and pooling primitives;
- conversion configuration exposes timestep, connection delay, reset method, input model, weight scaling, and percentile choices, all useful in a Watchword compilation receipt;
- official documentation describes bidirectional low-latency spike streaming for closed-loop control. See the [streaming tutorials](https://spinnaker2.gitlab.io/py-spinnaker2/tutorials/streaming/introduction.html);
- a Brian2 backend can prepare and debug networks without executing physical hardware;
- single-chip and SpiNNcloud targets share a related programming model.

The official [py-spinnaker2 installation documentation](https://spinnaker2.gitlab.io/py-spinnaker2/) states that some dependencies are private and restricted to users with or obtaining hardware access. Therefore the project cannot promise SpiNNaker2 until access to the complete software chain and a physical/cloud allocation is confirmed in writing.

### Hardware attestation limitation

No public official documentation reviewed for Xylo or SpiNNaker2 exposed a ready device-unique attestation key, signed-model loading chain, measured boot result, or remote-attestation protocol suitable for a strong hardware-bound Watchword claim. This is an inference from the reviewed public material, not proof that no vendor capability exists.

Without a vendor root of trust, a signed backend compilation/deployment receipt authenticates the laboratory signer's provenance statement; it does not by itself prove that compilation, loading, or observation occurred. Those claims require a measured build/load/observation path bound to a trusted agent, and even that does not cryptographically prove the silicon's internal execution. A stronger device claim would require vendor collaboration or an external secure element/TPM combined with a carefully stated device boundary.

## Decision after confirming no hardware access

### Revised claim

The project remains viable and PhD-relevant, but its claim changes from hypothetical hardware attestation to:

> **Backend-aware mission authorization and semantic admission for portable SNN controllers across software and hardware-constrained execution profiles.**

The following descriptions are permitted when supported by evidence:

- portable SNN-controller assurance;
- backend-aware semantic deployment identity;
- simulator and hardware-constrained-profile conformance;
- mission authorization across heterogeneous SNN runtimes;
- neuromorphic-ready architecture;
- quantization/mapping-aware admission.

The following descriptions are not permitted without later physical access:

- validation on physical neuromorphic hardware;
- device-rooted or silicon-rooted attestation;
- simulator-to-silicon equivalence;
- measured physical energy efficiency;
- physical-device timing or fault tolerance;
- security guarantees about Xylo, SpiNNaker, Loihi, or another chip;
- hardware-in-the-loop results.

### Accessible backend stack

The recommended stack under the current constraint is:

1. **NEST** as Engram's reference SNN execution.
2. **NIR** as the portable logical graph where supported.
3. **Rockpool's device-specific mapper and design-rule/configuration validator, followed by XyloSim**, as a public hardware-constrained profile exposing integer quantization, fixed topology/resource limits, and bit-shift dynamics.
4. **Norse or snnTorch** as an additional independent NIR-compatible software runtime when needed to separate a Rockpool-specific result from a broader backend result.
5. **A deterministic non-neural controller fixture** to prove that Gate itself is not dependent on NEST or SNN behavior.
6. **Crebain `CommandPlant` plus a deterministic plant**, followed by Gazebo/MAVROS when its native lifecycle exists.

SpiNNaker2's Brian2/mapping path remains optional because its dependency access may still be restricted even without physical execution. The software-only plan must not depend on receiving that access.

This stack is not a plug-and-play `NEST → NIR → XyloSim` pipeline. NIR's current supported-framework table does not list NEST. The project must declare a bounded common primitive subset in `ControllerAdmissionProfileV1`, then implement an Engram adapter that constructs the NEST execution and the manifest/NIR representation from the same canonical controller description. Conformance tests compare graph structure, parameter tensors, shapes, timestep, reset, delay, codec semantics, digests, and golden action traces before cross-backend results are accepted.

### Why XyloSim remains useful without Xylo hardware

The Rockpool device mapper and its design-rule/configuration validator—not XyloSim alone—exercise and enforce deployability constraints such as:

- graph/resource-fit failures;
- fanout and topology restrictions;
- bounded input/output dimensions;
- generated device-configuration identity.

After a configuration passes those checks, XyloSim provides bit-precise execution of the validated configuration, including weight/state quantization, bit-shift decay, and timestep/reset behavior. XyloSim can also simulate networks larger than the physical device, so successful simulation alone is not proof of hardware fit. A mapper or design-rule rejection is a valid experimental result and must not be bypassed merely to obtain a trace.

This supports a paper about profile-complete semantic deployment descriptions and action-level divergence. It does not support a statement that the simulator perfectly predicts a physical board.

### Software-only cross-backend experiment

For every selected scenario:

1. instantiate the controller from the same profile-complete fixed-weight manifest;
2. execute a reference trace through NEST;
3. map the selected controller through Rockpool's device-specific mapper, pass its design-rule/configuration validation, and execute the validated configuration through XyloSim; record mapping rejection as a first-class result;
4. execute a second independent software profile when feasible;
5. apply the same encoder, decoder, NCP contract, Gate policy, plant, and seeded state corpus;
6. record internal spikes only as diagnostic evidence;
7. compare final decoded actions, Gate ALLOW/DENY decisions, constraint margins, mode transitions, trajectory envelopes, and mission outcomes;
8. evaluate held-out cases using tolerances fixed before seeing their results.

The security substitution battery mutates graph edges, weights, seeds, encoder/decoder, units/frames, timestep, reset, quantization, scaling, backend, compiler/adapter version, mapping, policy, and admission record independently.

### Software-only PhD boundary

The work can still support three serious contributions:

1. profile-complete semantic identity and transformation classification for the declared fixed-weight portable-SNN profile;
2. backend-aware action-equivalence under hardware-constrained numeric profiles;
3. controller-bound mission authorization and formal failure/reversion composition.

Physical hardware becomes optional external validation, a collaboration opportunity, or future work. If a target venue or committee requires a physical neuromorphic result, the claim must be narrowed or a collaborator found; simulation must not be relabeled to satisfy that expectation.

## Repository-boundary decision

### Keep Haldir independent

Haldir should remain its own repository and Gate should run as a separate process. The reasons are security and ownership, not aesthetics:

- Gate has its own threat model, keys, policies, evidence formats, failure behavior, and release cadence.
- Putting Gate inside Engram would place the authorization boundary inside the controller system it supervises.
- Putting Gate inside Crebain would couple mission authorization to one plant and actuator stack.
- Putting Gate inside NCP would make a generic transport/control protocol own Haldir-specific mission and controller-admission semantics.
- A small independent trusted computing base is easier to audit, fuzz, pin, and deploy separately.

Repository separation does not automatically create runtime isolation or complete mediation. The deployment profile, process identity, ACL, host boundary, alternative actuator paths, and failure behavior still need evidence.

### Coupling principle

> **Loose in source code, tight in versioned contracts, strict in deployment and conformance.**

The desired source and runtime directions are:

```text
NCP released API pin
  |-- Haldir NCP adapter
  |-- Engram NCP client, when used
  `-- Crebain NCP bridge

Crebain/NCP state ----------> Engram controller
Crebain/NCP trusted state --> Haldir Gate
Engram controller ----------> Haldir Gate : SignedIntentV1
Haldir Gate ----------------> Crebain     : standard NCP CommandFrame
```

There is no compile-time cycle:

- Haldir depends on released/pinned NCP APIs.
- Engram may optionally depend on a small released Haldir client/contracts package.
- Crebain consumes a standard NCP command and does not need a Haldir dependency.
- Haldir imports no Engram/Paper2Brain or Crebain internals.
- Border-Muster pins released revisions of all components.

### Ownership by repository

| Repository | Owns | Must not own for this design |
| --- | --- | --- |
| NCP | Normative wire messages, standard keys, generic validation, QoS, Zenoh transport, sequence/TTL/action-buffer primitives, generic physical-safety components. | Haldir mission leases, controller admissions, decision receipts, or a Haldir-only role topology in the normative command frame. |
| Haldir | Signed intents, leases, replay/epoch semantics, admission records, policy, deterministic mission predicates, Gate, evidence, Haldir ACL profile, conformance corpus, range. | Neural controller generation, ROS/MAVROS mapping, vendor neural SDK execution, or mutable copies of NCP internals. |
| Engram / Paper2Brain | Controller generation; proposed ownership and production of `ControllerBundleManifestV1`; NEST/NIR/backend execution; codecs; validation fixtures; optional Haldir intent client. | Mission-policy decisions, guardian/final-command key, Haldir admission-profile ownership, or self-approval of an admission record. |
| Crebain | NCP-to-action mapping, `CommandPlant`, 50 Hz action loop, native ROS/MAVROS/Gazebo transport, lifecycle, accepted/applied evidence. | Haldir policy evaluation, controller-artifact approval, or a private Haldir-only final command format. |

### NCP coupling

Haldir should pin the canonical NCP release and use:

- `ncp-core` for normative types and validation;
- `ncp-zenoh` for secure clients, custom-key subscription, and final command publication;
- public APIs only;
- an immutable release/tag in every Haldir release;
- a nightly canary against NCP `main`, never a floating production dependency.

Haldir must not vendor or fork NCP, use a sibling-path dependency, or use Engram's internal NCP mirror as its source. Generic NCP improvements can be upstreamed, such as a declarative authority-matrix verifier, but Haldir must not wait for them to implement its own profile.

### Engram coupling

The proposed Engram integration will produce its Engram-owned `ControllerBundleManifestV1`, describing what it intends to execute. Haldir validates that external manifest against Haldir-owned `ControllerAdmissionProfileV1` and approves both digests through `AdmissionRecordV1`, binding them to allowed controller principals, backends, mission/vehicle classes, policies, validity, and behavior-corpus results. The present Engram backend does not yet provide this complete manifest; Phase 3 must add it.

Haldir treats detailed paper/model data as opaque signed content plus selected typed claims. It does not import `PaperModel`, `NetworkRef`, `NestBackend`, or Engram's artifact store. A small Python SDK may help Engram create golden-compatible signed intents, but it never contains policy authority or guardian keys.

The vendor/runtime compiler adapter belongs with Engram or in a separate optional tool. An independent Haldir admission/inspection tool verifies the resulting manifest/configuration before signing an admission. Gate consumes only the compact signed admission and intent, not the heavy neural SDK.

### Crebain coupling

Crebain remains responsible for:

- registering and managing `NcpHandle`;
- starting/stopping the action loop through its public NCP bridge seam;
- bridging the synchronous nonblocking callback through a bounded channel to the native async transport;
- actuator ownership and reconnect behavior;
- final reversion/shutdown ordering;
- accepted-command, adapter-result, and measured-state evidence;
- disabling direct alternative command paths in the assurance deployment.

Haldir publishes the existing standard final command key. It does not know ROS topics, MAVROS services, or Crebain UI state. Crebain remains usable without Haldir and with its NCP feature disabled in ordinary builds.

### Hardware/backend adapter placement

Vendor SDKs must not enter `haldir-gate`:

- they expand the trusted computing base;
- they change rapidly and may be proprietary or access-restricted;
- Rockpool has AGPL licensing implications;
- backend compilation is not a per-command operation;
- a vendor SDK failure must not block Gate's command hot path.

Optional tools can be structured as:

```text
engram-backend-nest
engram-backend-rockpool-xylo
engram-backend-norse
haldir-inspect-nir
haldir-inspect-xylo-config
haldir-admission-cli
```

The compile/load/inspect phase occurs offline or at session admission. Gate receives a signed `AdmissionRecordV1` and a small declared backend profile.

## Proposed Haldir workspace

```text
haldir/
├── Cargo.toml
├── .ncp-consumer
├── crates/
│   ├── haldir-contracts/
│   │   ├── SignedIntentV1
│   │   ├── DecisionReceiptV1
│   │   ├── MissionLeaseV1
│   │   ├── AdmissionRecordV1
│   │   └── assurance assertion schemas
│   ├── haldir-crypto/
│   │   ├── deterministic encoding
│   │   ├── domain-separated signing
│   │   └── verification-key registry
│   ├── haldir-policy/
│   │   ├── bounded deterministic predicates
│   │   ├── Cedar adapter
│   │   └── lease/replay/duty state
│   ├── haldir-ncp/
│   │   ├── Haldir key construction
│   │   ├── intent subscription
│   │   ├── final command publication
│   │   └── NCP profile mapping
│   ├── haldir-gate/
│   │   └── bounded daemon/worker lifecycle
│   ├── haldir-admission/
│   │   ├── manifest/profile validation
│   │   └── approval record issuance
│   ├── haldir-evidence/
│   │   ├── bounded receipt spool
│   │   └── offline verifier/checkpoints
│   └── haldir-deploy/
│       ├── inventory/config renderer
│       ├── ACL invariant checker
│       └── live authority verifier
├── sdk/
│   └── python/
│       └── optional Engram intent client
├── schemas/
│   ├── controller-admission-profile-v1
│   ├── backend-compilation-receipt-v1
│   └── backend-admission-profile-v1
├── deploy/
│   ├── inventory.example.toml
│   ├── router template
│   └── policy examples
├── conformance/
│   ├── encoding/signature vectors
│   ├── malformed/adversarial corpus
│   └── controller substitution corpus
└── range/
    ├── ecosystem.lock.toml
    ├── reference-controller/
    ├── reference-plant/
    └── scenarios/
```

`haldir-contracts` should wrap opaque inner command bytes and avoid depending on NCP where possible. `haldir-ncp` is the integration layer that understands the NCP `CommandFrame`.

Before code publication, the repository needs an explicit open-source license, `SECURITY.md`, contribution policy, threat model, supported deployment boundary, and responsible-disclosure contact.

## Key and contract boundaries

### Proposed key expressions

Haldir extensions remain outside standard NCP planes:

```text
{realm}/session/{session}/haldir/intent/{controller}
{realm}/session/{session}/haldir/decision
{realm}/session/{session}/haldir/assurance/navigation
{realm}/session/{session}/haldir/assurance/perception
```

The final plant key remains the standard NCP key:

```text
{realm}/session/{session}/command
```

`HaldirKeys` validates Haldir-specific suffixes while delegating realm/session validation to NCP. The controller suffix is routing information, not authenticated identity.

### Contract ownership and versions

| Contract | Owner | Independent version |
| --- | --- | --- |
| `CommandFrame`, `SensorFrame` | NCP | NCP wire version |
| `SignedIntentV1` | Haldir | Haldir extension version |
| `DecisionReceiptV1` | Haldir | Haldir extension version |
| `MissionLeaseV1` | Haldir | Haldir extension version |
| `ControllerBundleManifestV1` | Engram | Engram manifest-schema version |
| `ControllerAdmissionProfileV1` | Haldir | Haldir admission-profile version; pins accepted manifest versions and required subset/rules |
| `BackendCompilationReceiptV1` | Haldir schema; backend adapters produce instances | Haldir receipt-schema version |
| `BackendAdmissionProfileV1` | Haldir | Haldir backend-profile version; defines backend-specific required receipt fields and acceptance rules |
| `AdmissionRecordV1` | Haldir | Haldir extension version |
| Crebain actuator mapping | Crebain | Crebain deployment/profile version |

A Haldir release publishes a compatibility matrix with exact NCP, Zenoh, NEST, NIR, controller-bundle, and backend-adapter versions. No release claim refers to floating `main` branches.

## Test and release ownership

### Haldir CI

- deterministic-encoding golden vectors;
- signature, key-confusion, replay, epoch, and rotation tests;
- duplicate-key/malformed/oversized parser fuzzing;
- policy property and error tests;
- bounded queues, rate limits, and state cardinality;
- reference controller → Gate → reference plant;
- secure-router positive/negative authority matrix;
- policy/lease/state fault injection;
- restart/reboot tests proving active-lease invalidation, stale-epoch rejection from the durable watermark, and mandatory fresh-epoch issuance;
- explicit-reversion tests proving the atomic local state transition, `last_seq + 1`, `MAX - 1`/reserved-`MAX`/overflow handling, state-commit-to-publish crash recovery, publish-failure expiry fallback, same-epoch rejection, and post-expiry new-lease re-anchoring;
- p50/p99/p99.9 and resource benchmarks;
- receipt spool/verifier corruption and truncation tests.

### Engram CI

- proposed Engram manifest contains every field required by the pinned Haldir admission profile, including graph, projections, weights, codecs, timing, and backend configuration;
- controller reconstruction uses no hidden ambient state;
- the common-subset adapter constructs consistent NEST and manifest/NIR representations and passes structural plus golden-trace conformance;
- device-specific mapping/DRC and hardware-constrained execution produce pinned provenance receipts, with mapping rejection retained as a result;
- Haldir client matches released golden vectors;
- controller runs without Haldir installed;
- Engram never evaluates mission policy or holds the guardian key.

### Crebain CI

- final standard NCP command passes the configured plant validation;
- silence/denial follows the documented TTL/horizon/reversion contract;
- action-loop stop and transport disconnect ordering are safe for the test profile;
- native actuator callback is nonblocking and bounded;
- accepted/applied evidence distinguishes observation stages;
- the ordinary non-NCP build remains unchanged;
- no default dependency on Engram or Haldir exists.

### Border-Muster cross-repository range

`range/ecosystem.lock.toml` pins:

- NCP tag and commit;
- Haldir commit;
- Engram/Paper2Brain commit;
- Crebain commit;
- NEST, NIR, Zenoh, policy engine, container, and backend-adapter versions;
- scenario and analysis versions.

Public CI uses public reference fixtures. A private ecosystem workflow may use repository-scoped credentials for private sources, but never copies private code or credentials into Haldir.

Border-Muster remains under Haldir until it becomes a general validator for several independently shipped controls. Premature extraction would add release coordination before a functioning Gate exists.

## Revised implementation roadmap

### Phase 0 — authority and feasibility spike

Deliver:

- complete actuator-authority graph for one Crebain assurance profile;
- exact five-role ACL/configuration profile naming the **controller**, **Gate/guardian**, **robot/Crebain**, **observer**, and **lifecycle** roles;
- live positive and negative delivery matrix;
- controller-key plus signed-intent identity binding;
- one vehicle/phase-specific reversion contract;
- baseline command and plant timing.

Stop or choose an in-process Crebain ingress monitor if Gate cannot become the exclusive authority within the declared test boundary.

### Phase 1 — pure contracts and Gate core

Deliver:

- `SignedIntentV1`, `MissionLeaseV1`, `AdmissionRecordV1`, and `DecisionReceiptV1` specifications;
- Rust implementation and Python golden-vector compatibility;
- bounded parser, replay/lease state, deterministic predicates, and Cedar adapter;
- bounded evidence spool;
- formal state-machine model for lease, TTL, crash, restart, and reversion;
- tests for the lease-terminating explicit-reversion rule, its `last_seq + 1` frame, reserved sequence ceiling, commit/publish crash window, failed-publish expiry fallback, same-epoch rejection, and post-expiry fresh-lease re-anchoring;
- fixture attack corpus and latency/resource benchmarks.

Proceed only if identity is unambiguous, state/resource use is bounded, and the 20–50 Hz target has credible p99.9 headroom.

### Phase 2 — honest software vertical slice

Deliver:

- Engram/NEST controller publishing signed intents through secure Zenoh;
- Gate as the only final command publisher;
- registered Crebain action-loop lifecycle;
- standalone `CommandPlant` and deterministic plant;
- baseline, bypass, malformed-input, replay, overload, crash, partition, and evidence-outage campaigns;
- distinct decision, publish, accepted-command, adapter-result, and measured-state evidence.

Gazebo/MAVROS follows only after the deterministic path is stable. PX4-SITL is optional later integration, not a Phase 2 success requirement.

### Phase 3 — profile-complete fixed-weight controller identity

Deliver:

- bounded controller graph/projection schema and builder;
- fixed-weight nontrivial SNN reconstructed entirely from the bundle;
- Haldir-owned `ControllerAdmissionProfileV1` plus an Engram-owned, profile-complete `ControllerBundleManifestV1`;
- bounded NEST/manifest/NIR common-subset adapter, canonical NIR representation, and explicit mapping gaps;
- signed admission and backend compilation receipt;
- field-ablation and substitution battery;
- held-out approved transformation corpus.

Until this phase succeeds, Gate is identity/mission-bound rather than semantically controller-bound.

### Phase 4 — software and hardware-constrained conformance

Deliver:

- NEST reference execution;
- Rockpool/XyloSim constrained execution;
- another independent open software backend when feasible;
- pre-registered action/trajectory equivalence relation;
- paired seeded and held-out scenarios;
- raw internal and action/plant divergence evidence;
- Gate decision comparison across profiles.

If the relation cannot predict held-out results, publish that boundary and remove backend-independent authorization claims.

### Phase 5 — ecosystem integration and optional external validation

Deliver:

- Gazebo/MAVROS integration if Crebain's native path is ready;
- expanded benign tasks/plants;
- reusable range release and raw dataset;
- optional remote or collaborator-run physical hardware only if access appears.

Physical hardware is not required for the defined software contribution. Any later physical result is labeled separately and includes the exact access, runtime, firmware, mapping, and measurement boundary.

## Acceptance and kill criteria

### Program acceptance

Continue the combined program when:

1. every actuator path in the declared boundary is enumerated and controlled;
2. workload, signing key, intent key, lease, mission, and controller bundle bind unambiguously;
3. single-stream sequence, ceiling, handoff, denial, expiry, restart, and reversion semantics are explicit, including an atomic local close-before-publish transition, failure fallback, and post-expiry re-anchoring after any Gate-authored reversion;
4. the live Engram → secure Zenoh → Gate → Crebain software path exists;
5. authorization meets a pre-registered tail-latency and resource budget;
6. attacks/faults outperform relevant baselines within a benign mission budget;
7. the controller reconstructs from its manifest within the declared fixed-weight admission profile;
8. action-equivalence predicts held-out cross-backend behavior;
9. simulator and hardware-constrained claims remain correctly labeled;
10. the experiment can be reproduced from pinned commits and raw evidence.

### Program reversal

Narrow or reverse the recommendation if:

- an ordinary controller can bypass Gate inside the claimed boundary;
- controller principal and artifact/profile remain self-asserted;
- the declared fixed-weight controller profile cannot be represented without hidden arbitrary code;
- phase-appropriate reversion cannot be demonstrated;
- Gate cannot meet the target timing/resource region;
- policies merely duplicate NCP's configured physical governor;
- cross-backend tolerances are chosen after results or fail on held-out cases;
- the second backend is only a wrapper around the same implementation;
- the contribution reduces to Cedar on a key plus signed logs;
- publications continue to imply physical hardware evidence that does not exist.

### Repository-boundary reversal

Reassess the separate Haldir implementation if:

- Haldir repeatedly needs private Engram or Crebain classes;
- mission authorization requires modifying normative NCP `CommandFrame` fields instead of an external intent/context contract;
- Crebain must consume a private Haldir command representation;
- Engram must evaluate mission policy or hold the guardian key;
- Haldir becomes inseparable from NEST and cannot authorize a deterministic reference controller;
- NCP later implements an equivalent semantic mission-authorization and admission boundary, making Gate a redundant fork.

## What was explicitly rejected

- reviving Fëanor/Rúmil demonstrations around NCP defects already fixed in 0.7.1;
- a detached countersign that never owns the final action path;
- claiming mTLS identity proves a running controller artifact;
- inferring the publisher principal from ordinary Zenoh sample data;
- treating controller ID in a key suffix as authentication;
- claiming immediate HOLD when an earlier command remains valid;
- generic zero velocity as a universal physical safe state;
- hiding geometry, slew, duty, timing, or state-machine logic inside Cedar policies;
- placing a remote evidence collector on the command hot path;
- calling a package hash complete neural controller identity;
- requiring identical spike trains across backends;
- building around archived Lava;
- making unavailable hardware a PhD dependency;
- treating XyloSim or a Brian2 backend as physical hardware;
- putting Gate inside Engram, Crebain, or NCP;
- importing vendor neural SDKs into the Gate core;
- creating a separate integration repository before Gate works;
- force-pushing documentation changes.

## Immediate next implementation decision

The first code milestone should not be a hardware adapter. It should be a small Haldir workspace containing:

1. `haldir-contracts` with deterministic `SignedIntentV1` and lease/admission types;
2. a fixture controller and reference plant;
3. a bounded pure Gate decision core with no networking;
4. a Haldir NCP adapter for one controller-specific intent key and one final session command key;
5. a five-role secure router profile and live authority matrix for controller, Gate/guardian, robot/Crebain, observer, and lifecycle identities;
6. a minimal Border-Muster campaign covering identity mismatch, direct-key bypass, replay, stale lease, malformed input, Gate crash, and bounded expiry/reversion.

Only after this passes should Engram/NEST, Crebain, NIR, XyloSim, or another backend be integrated.

## Final position

The discussion began with a possible inline “neuromorphic policy firewall” and a desire for physical neuromorphic relevance. The evidence changed the recommendation in three important ways:

1. Gate remained the best enforcement architecture, but it lost borrowed novelty and moved to second place as a standalone proposal.
2. Watchword-Neuro became the primary research contribution rather than a later add-on.
3. The absence of physical hardware changed the claim from hardware attestation to backend-aware semantic admission and action-equivalence across software and hardware-constrained profiles.

The final non-forced project is therefore:

> **An independent Haldir security boundary that admits a profile-complete portable SNN controller within a declared fixed-weight controller profile, binds it to narrow mission authority, mediates the final NCP command path, and tests whether authorization remains valid across NEST and independent hardware-constrained/software backends.**

This is impactful open-source cybersecurity engineering even if the research hypotheses fail. It is PhD-worthy as a central strand only if it produces a profile-complete semantic identity within the declared fixed-weight controller profile, a defensible equivalence relation, a formal failure/reversion result, and comparative adversarial evidence.

## References and current platform material

- [Detailed Haldir project audit](HALDIR-PROJECT-AUDIT-2026.md)
- [NCP security model at the inspected revision](https://github.com/sepahead/NCP/blob/e3e5da4de96e8b291b3c582bd31cf41afbfad3cc/SECURITY.md)
- [Crebain NCP bridge handoff at the inspected revision](https://github.com/sepahead/crebain/blob/08ccafe5392465ea179406665ae936dd561aef6f/docs/NCP_BRIDGE_HANDOFF.md)
- [Engram/Paper2Brain neurocontrol backends at the inspected revision](https://github.com/sepahead/Paper2Brain/blob/12833c7eae49a69095001bb74bf307a86c9012b5/backend/neurocontrol/backends.py) — requires `sepahead` access
- [Neuromorphic Intermediate Representation](https://www.nature.com/articles/s41467-024-52259-9)
- [NIR documentation and supported frameworks](https://neuroir.org/docs/)
- [Rockpool 3.1.0 changelog](https://rockpool.ai/advanced/CHANGELOG.html)
- [Rockpool NIR import/export](https://rockpool.ai/advanced/nir_export_import.html)
- [Xylo family architecture and constraints](https://rockpool.ai/devices/xylo-overview.html)
- [SynSense current developer resources](https://www.synsense.ai/developer/)
- [SpiNNaker2 NIR guide](https://spinnaker2.gitlab.io/py-spinnaker2/user_guide/qs-nir.html)
- [SpiNNaker2 real-time streaming guide](https://spinnaker2.gitlab.io/py-spinnaker2/tutorials/streaming/introduction.html)
- [SpiNNaker2 installation/access limitations](https://spinnaker2.gitlab.io/py-spinnaker2/)
- [EBRAINS neuromorphic hardware access](https://wiki.ebrains.eu/bin/view/Collabs/neuromorphic/Getting%20access/)
- [Lava archive notice](https://github.com/lava-nc/lava)
- [RTron](https://arxiv.org/abs/2103.12365)
- [SOTER on ROS](https://arxiv.org/abs/2008.09707)
- [Neural Simplex Architecture](https://arxiv.org/abs/1908.00528)
- [Black-Box Simplex Architecture](https://arxiv.org/abs/2102.12981)
- [Cedar authorization language](https://arxiv.org/abs/2403.04651)
- [RATS architecture](https://www.rfc-editor.org/rfc/rfc9334)
