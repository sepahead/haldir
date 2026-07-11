<!-- markdownlint-disable MD013 MD024 -->

# Haldir project audit 2026

> **Follow-up decision:** Physical neuromorphic hardware is not currently
> available and is no longer a project dependency. See the
> [discussion and decision record](HALDIR-DISCUSSION-DECISIONS-2026.md) for the
> revised software-only backend plan, platform analysis, and independent-repo
> architecture. That later decision record supersedes hardware-dependent wording
> and legacy architecture/contract names in this audit.

## Decision

**Choose one non-PID Haldir program: _Haldir — backend-aware mission authorization and semantic admission for portable SNN controllers_.**

The product spine is **Haldir Gate**, an inline authorization boundary between an authenticated controller intent and the one command stream consumed by Crebain. The research spine is **Watchword-Neuro**, which defines what neural controller was actually admitted, how that identity changes across backends, and when two executions remain authorization-equivalent despite different spike timing or quantization.

This is a significant project and is worthy of being **part of a PhD**. It is not yet a whole thesis, and a plain combination of a Cedar proxy, NEST demonstration, PKI, and signed logs would be strong engineering rather than an original doctoral contribution. The doctoral case becomes credible only if the work delivers:

1. a formal authority and failover model with complete actuator mediation;
2. a security-relevant, backend-aware identity for a spiking controller;
3. a cross-backend action-equivalence relation and evidence from at least two independent backends;
4. a reproducible adversarial benchmark with relevant runtime-assurance baselines.

The recommendation is deliberately conditional. The first implementation phase is a spike designed to falsify it. If Haldir cannot close alternative actuator paths, bind an intent to an authenticated controller and complete artifact, define safe phase-specific reversion, or meet the control-loop latency budget, it should not be presented as a reference monitor or a neuromorphic-security thesis.

## Short answer to the downloaded audit

I agree with its central direction, but not with its level of certainty or its original ranking.

The audit correctly identifies the gap between transport authorization, physical-envelope validation, and mission authorization. An authenticated controller can issue a syntactically valid and physically bounded command that is nevertheless unauthorized for the current mission, vehicle, phase, or admitted controller. An inline boundary with exclusive downstream authority is materially stronger than a detached countersign service.

The audit also makes several claims that the present repositories do not support:

- Its twenty stated weights sum to **104**, not 100, and it provides no raw score matrix. The reported total therefore cannot be reproduced.
- It compares a large Gate portfolio against component proposals that Gate later absorbs. That favors Gate by construction.
- Crebain still has direct ROS/MAVROS command paths outside NCP. Exclusive write authority over one NCP key is not yet complete mediation of the plant.
- A Zenoh subscriber receives a key and payload, not the publisher's mTLS common name. Gate cannot infer controller identity from a sample without an exact identity-to-key ACL mapping, an authenticated intent envelope, or trustworthy publisher metadata.
- Current Engram controller references do not completely encode topology, weights, codec, scheduling, quantization, compiler mapping, or backend configuration. Phase-one Gate therefore cannot honestly be called artifact-bound until that representation exists.
- A denied intent does not instantly stop the previous command. The previous frame remains effective according to its remaining NCP TTL/`ActionBuffer` horizon semantics and downstream failsafe. For explicit reversion, Gate first atomically closes the lease in durable local state, then separately attempts `last_accepted_downstream_seq + 1`; publish failure leaves authority closed and falls back to expiry. A lower sequence can re-anchor only after the downstream stream expires and a fresh lease epoch is issued.
- Current Engram/NEST examples use NCP-shaped objects and a local kinematic plant; they are not a live Engram-to-Zenoh-to-Gate-to-Crebain loop.
- Intel archived the Lava repositories in May 2026. A new roadmap should use a neutral representation such as NIR and select a maintained, accessible second backend after a compatibility spike, rather than assuming Lava is the next step.

The corrected conclusion is therefore narrower:

> Gate is the strongest Haldir ecosystem spine. Watchword-Neuro is the stronger raw research idea. Their intersection can be a substantial PhD strand; neither should borrow certainty from the other before the hard integration and identity problems are solved.

## Evidence boundary

This assessment was made on 2026-07-11 against the following repository revisions. Mutable working-tree changes in sibling repositories were inspected as local evidence but are not part of the Haldir change or commit.

| Repository | Revision inspected | What the evidence establishes |
| --- | --- | --- |
| NCP | `e3e5da4de96e8b291b3c582bd31cf41afbfad3cc` | NCP 0.7.1 has typed validation, units, command TTL/sequence logic, per-verb RPC keys, `SafetyGovernor`, Zenoh transport, ACL examples, and a delivery-based security verifier. No live mTLS/ACL result is committed at this revision. It does not provide message-level application signatures or a neural artifact identity. |
| Engram / Paper2Brain | `12833c7eae49a69095001bb74bf307a86c9012b5` plus local work | The registered neurocontrol backends are `mock` and `nest`. The NEST example is real spiking computation, but its current `NetworkRef` and backend setup are not a complete portable controller description, and its plant loop is local. |
| Crebain | `08ccafe5392465ea179406665ae936dd561aef6f` plus local docs | The NCP library path and 50 Hz `CommandPlant` exist, but NCP is off by default, the Tauri commands are not registered into a live product action loop, and no live MAVROS/PX4 callback completes the path. Direct ROS/MAVROS control paths also exist. |
| Haldir | parent of this document | The repository is currently a project/design repository. No Gate implementation or latency, bypass, or failure evidence exists yet. |

The proposed first honest vertical slice is:

```text
Engram NEST controller
        |
        | SignedIntentV1 on a controller-specific Zenoh key
        v
Haldir Gate --> decision receipt / bounded evidence spool
        |
        | one final NCP session command key
        v
Crebain CommandPlant --> deterministic plant or Gazebo
```

PX4-SITL and HIL are optional later evidence gates. Physical neuromorphic hardware is not currently available and is future collaborator/access-dependent validation, not an MVP or thesis assumption.

## First-principles problem statement

### Assets

- control authority over each vehicle and mission;
- integrity and freshness of controller intents and final commands;
- integrity of the mission policy, lease, vehicle/phase state, and controller admission record;
- availability of a safe reversion path under crash, overload, expiry, and partition;
- traceable evidence about what was admitted, decided, delivered, and observed;
- portability claims made for a neural controller across software and hardware backends.

### Adversaries and failures

- a controller with a valid credential that is compromised or behaves outside its mission role;
- a controller that is correct but deployed with the wrong graph, weights, codec, timestep, mapping, firmware, or backend;
- an unauthorized publisher attempting the final command key or another actuator path;
- replay across a mission, vehicle, session, controller, or lease epoch;
- stale, spoofed, incomplete, or internally inconsistent policy state;
- malformed inputs, parser differentials, duplicate fields, oversized payloads, queue exhaustion, or timing attacks;
- Gate, router, controller, state source, evidence sink, or actuator transport crash and partition;
- policy or artifact rollback;
- GNSS, perception, and state-estimation attacks relevant to later Nénya and Warden's Eye work;
- ordinary numerical divergence between neural backends that is mistaken for malicious substitution.

### Revised invariants

These are design goals until demonstrated. They must not be described as achieved properties of the current ecosystem.

1. **Complete scoped mediation.** Every actuator-affecting path inside the declared experiment boundary passes through one final authority. Direct ROS/MAVROS paths are disabled, removed, or independently constrained and tested.
2. **Authenticated intent binding.** An accepted intent binds a verified principal, exact controller-specific key, signature key, mission/lease epoch, vehicle/session, controller bundle digest, and exact inner command bytes.
3. **One downstream owner.** Gate is the sole publisher of the final NCP command stream. The MVP admits one sequence-producing controller per lease and enforces its progression through `JSON_SAFE_INTEGER_MAX - 1`, reserving the maximum for Gate. A Gate-authored reversion is the sole exception: Gate atomically commits the local lease to `TERMINATING/CLOSED`, then separately attempts `last_accepted_downstream_seq + 1`; failure leaves the lease closed and falls back to expiry. A lower sequence can re-anchor only after downstream expiry under a fresh epoch. Any later multiplexing makes Gate re-sequence every downstream frame explicitly.
4. **Mission and physical checks compose.** Gate enforces mission authorization. NCP supplies typed wire/command primitives, while the declared deployment must place a configured reject-only physical monitor in trusted Gate or Crebain code for units, physical bounds, freshness, and state-dependent constraints. Current transport publication does not automatically invoke `SafetyGovernor`, and neither layer substitutes for a vehicle-specific safe plant/reversion design. If a monitor rewrites or clamps, receipts bind the transformed output rather than claim byte preservation.
5. **Denial has a bound.** The project measures the worst-case time from denial, crash, overload, or partition to a vehicle- and phase-appropriate reversion state. It does not equate zero velocity with safety for every vehicle.
6. **Policy inputs are trustworthy enough for their claim.** State freshness, source, uncertainty, snapshot consistency, restart epoch, and time basis are explicit. Unknown or diagnostic-error states cannot silently become ALLOW.
7. **Evidence is non-blocking.** Receipt generation and local bounded spooling do not make an external evidence sink part of the real-time authorization path.
8. **Artifact identity is semantic.** A file hash is used for integrity, but admission covers the execution-relevant graph, parameters, codec, timing, backend mapping, runtime, and approval lineage.
9. **Portability is behavioral.** Cross-backend claims use action decisions and closed-loop trajectory tolerances, not unrealistic equality of spike trains.
10. **No hardware claim without hardware.** Simulator and emulator results are labeled as such. Neuromorphic-hardware security requires a physical platform or a clearly documented access and measurement plan.

## Evaluation method: ten project lenses plus five Fable advisor lenses

The original request asked for ten lenses and an additional five from Claude Code Fable 5 at maximum effort. This audit uses exactly fifteen. Scores are ordinal judgments from 0 (unsupported or poor) to 5 (strong), not measurements. The weights sum to 100, the raw scores are shown, and the ranking is a selection aid rather than proof of novelty.

### Ten project-selection lenses

| Code | Lens | Weight | Question |
| --- | --- | ---: | --- |
| P1 | Consequence and unmet need | 10 | Does the project prevent a consequential cybersecurity failure not already closed in the ecosystem? |
| P2 | Preventive authority | 8 | Can it prevent an action at the relevant boundary, with a credible path to complete mediation? |
| P3 | Security soundness | 8 | Are identity, replay, time, state, failure, bypass, and least-authority assumptions defensible? |
| P4 | NCP fit | 6 | Does it reuse NCP's current typed contracts and secure transport without reviving solved work? |
| P5 | Crebain fit | 6 | Does it improve the real control path and have a concrete integration seam? |
| P6 | Engram fit | 6 | Does it use Engram's real artifact or neurocontrol capabilities rather than name association? |
| P7 | Neuromorphic specificity | 7 | Is the neural/spiking element material to the security question rather than decorative? |
| P8 | Deliverability | 6 | Can a falsifiable vertical slice be built with present software and explicit external dependencies? |
| P9 | Evidence quality | 6 | Can the result be tested with quantitative acceptance criteria and adversarial cases? |
| P10 | Ecosystem leverage | 7 | Does it create a reusable boundary, contract, dataset, or tool for multiple sepahead projects? |

### Five Fable advisor lenses

| Code | Lens | Weight | Question |
| --- | --- | ---: | --- |
| F1 | Prior-art distance | 7 | After RTron, SOTER, Simplex, runtime enforcement, NIR, and attestation work, what is actually new? |
| F2 | Formalizable research question | 6 | Can the central claim be stated precisely and supported analytically or formally? |
| F3 | Cross-backend generality | 6 | Does the result survive beyond one controller, simulator, vehicle, and repository? |
| F4 | Publishable evaluation | 6 | Is there a credible baseline, attack matrix, dataset, and systems evaluation? |
| F5 | Killability and thesis risk | 5 | Are there early reversal criteria, bounded dependencies, and a useful outcome even if the main hypothesis fails? |

### Reproducible score matrix

The weighted total is `sum(score × weight) / 5`. Equal-looking totals should not be overinterpreted; a one-point raw judgment can move a result by one to two total points. Each row scores the standalone proposal core. The program recommendation combines Gate and Watchword only **after** that comparison; Gate receives no Watchword credit for Engram fit, neuromorphic specificity, or cross-backend research.

| Rank | Proposal | P1 | P2 | P3 | P4 | P5 | P6 | P7 | P8 | P9 | P10 | F1 | F2 | F3 | F4 | F5 | Total / 100 |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | Watchword-Neuro | 4 | 4 | 4 | 4 | 4 | 5 | 5 | 3 | 4 | 5 | 5 | 5 | 5 | 5 | 3 | **86.8** |
| 2 | Haldir Gate | 5 | 4 | 4 | 5 | 5 | 4 | 2 | 3 | 5 | 5 | 3 | 4 | 4 | 5 | 4 | **82.8** |
| 3 | Border-Muster v2 | 4 | 2 | 4 | 5 | 5 | 5 | 4 | 4 | 5 | 5 | 3 | 3 | 4 | 5 | 4 | **81.6** |
| 4 | Vilya | 5 | 4 | 5 | 5 | 5 | 3 | 2 | 4 | 4 | 5 | 2 | 2 | 3 | 4 | 5 | **78.0** |
| 5 | Nénya | 5 | 5 | 4 | 4 | 5 | 2 | 1 | 3 | 5 | 4 | 3 | 4 | 3 | 5 | 3 | **75.8** |
| 6 | Marchwarden secure envelope | 4 | 4 | 5 | 5 | 4 | 3 | 2 | 4 | 4 | 5 | 2 | 3 | 3 | 3 | 4 | **73.8** |
| 7 | Rúmil v2 | 4 | 4 | 4 | 4 | 5 | 2 | 1 | 3 | 5 | 4 | 1 | 3 | 3 | 4 | 3 | **67.0** |
| 8 | Warden's Eye | 5 | 3 | 3 | 3 | 5 | 2 | 1 | 2 | 4 | 3 | 2 | 3 | 3 | 4 | 2 | **61.2** |
| 9 | Marchwarden's Roll | 3 | 1 | 4 | 4 | 3 | 3 | 1 | 5 | 4 | 4 | 1 | 2 | 3 | 3 | 5 | **59.8** |
| 10 | Dwimordene v2 | 2 | 1 | 2 | 4 | 2 | 1 | 1 | 2 | 2 | 2 | 1 | 1 | 2 | 2 | 2 | **35.6** |

### How to interpret the order

- Watchword-Neuro ranks first as a standalone proposal because it has the strongest Engram, neuromorphic, and prior-art-distance case. It becomes the scientific core rather than a decorative future phase.
- Gate ranks second as a standalone proposal and remains the recommended product/system spine because it creates the ecosystem's missing mission-authorization boundary and makes later assurance signals actionable. Its lower Engram, neuromorphic-specificity, and cross-backend scores prevent it from borrowing Watchword's contribution.
- Border-Muster ranks highly because no security or PhD claim is credible without a reproducible range. It is evaluation infrastructure, not by itself the core scientific insight.
- Vilya and the secure envelope are mandatory supporting components but mostly established security engineering.
- Nénya has high standalone safety impact but a weaker Engram/neuromorphic fit and a crowded estimation literature.
- Rúmil, Warden's Eye, the Roll, and Dwimordene remain useful, but they either duplicate crowded areas, lack preventive authority, or depend on observability that is not presently available.

If the weights emphasize near-term product hardening, Gate, Vilya, and the secure envelope rise. If they emphasize doctoral novelty, Watchword-Neuro's lead grows. The stable conclusion is not that one score proves a winner; it is that **Gate, Watchword-Neuro, and Border-Muster form a coherent system–research–evaluation spine**.

## Detailed proposal analyses

### 1. Watchword-Neuro — semantic admission of neural controller deployments

#### What it entails

Watchword-Neuro defines and verifies the security-relevant identity of the controller that Gate is authorizing. A binary or archive hash answers whether bytes changed. It does not answer whether two compiled neural deployments have the same semantics, whether a backend changed timing or quantization, or whether the encoded graph is complete enough to reproduce the authorized behavior.

The audit's conceptual `ControllerBundleV1` is the aggregate of an Engram-owned `ControllerBundleManifestV1` plus every immutable artifact referenced by that manifest. Haldir separately owns `ControllerAdmissionProfileV1`, which declares the bounded subset and acceptance rules. The bundle is composed of:

- source and compiled neuron/synapse module digests;
- logical graph, populations, connection topology/rules, and parameters;
- weights or distributions, initialization seeds, and state initialization;
- input preprocessing, encoder, decoder, postprocessing, and unit/frame contracts;
- stimulus/record mappings and NCP command profile;
- simulation timestep, chunking, reset, scheduling, and clock semantics;
- numerical precision, quantization, partitioning, compiler transforms, and hardware mapping;
- backend, runtime, compiler, driver, firmware, and platform identifiers;
- behavioral fixture corpus, expected action-level tolerances, and validation results;
- provenance, approval signatures, transformation lineage, and revocation/expiry metadata.

NIR should be reused for the portable logical graph where it fits instead of inventing another neural interchange representation. Engram still needs a genuine NEST-to/from-NIR bridge or another complete bounded topology representation, because NIR does not currently make NEST an automatic supported path. SPDX/in-toto-style provenance and RATS/EAT-style attestation roles should likewise be composed rather than replaced with bespoke terminology.

Three different relations must be kept separate:

1. **Byte identity:** exact package and metadata bytes match a digest.
2. **Semantic deployment identity:** every security-relevant execution field and approved transformation matches the admitted bundle/profile.
3. **Authorization-equivalence:** two executions may differ internally, including spike times, while their policy decisions and closed-loop actions stay within an explicitly authorized relation.

#### Why it was chosen

This is the proposal most specifically tied to Engram and neuromorphic systems. Portable neural-controller security has a real gap between conventional supply-chain integrity and behavior across heterogeneous runtimes. The current Engram `NetworkRef` contains a model reference, model name, population sizes, and flat parameters; it does not capture a general network topology, weights, codec, mapping, or full timing semantics. That gap is a concrete implementation problem and a plausible research question.

It ranks first rather than being deferred because the Gate claim depends on it. Without a complete controller identity, Gate can bind authority only to a process/key and claimed artifact digest. Calling that “artifact-bound mission authorization” would be circular.

It also has stronger prior-art distance than Gate, but not a blank slate. NIR already provides a portable graph representation and demonstrates cross-platform execution; NeuroBench provides benchmarking concepts; software supply-chain and remote-attestation standards provide integrity, provenance, and evidence roles. The new work must concern the execution-relevant identity and action-level authorization relation, not merely packaging or hashing a model.

#### Concrete implementation

##### 1. Define the minimum complete NEST bundle

Start with one nontrivial, fixed-weight spiking controller. Refactor Engram so the controller is instantiated entirely from `ControllerBundleManifestV1` and its content-addressed referenced artifacts; prohibit arbitrary PyNEST code execution in the admitted profile. The manifest parser has bounded size/cardinality, canonical serialization, explicit defaults, schema versioning, and deterministic validation.

This requires a new bounded graph/projection builder or a substantial extension of `NestBackend`: its current `open()` creates target populations plus stimulus generators/recorders, but not general population-to-population projections, synapse models, weights, or delays. It also resets/cleans the global NEST kernel, so the MVP deliberately uses one session per process. Later fleet or multi-controller work needs one explicitly combined network or process isolation; it must not imply parallel independent NEST sessions already work.

Extend Engram's content-addressed artifact store so the bundle digest covers the graph, compiled modules, weights, codec, timing, behavior fixtures, and execution profile. Existing compiled-binary and metadata integrity checks remain useful but are not labeled as semantic approval.

The first controller must contain meaningful internal topology and weights. The current multi-UAV example's independent integrate-and-fire populations, monotonic rate decoding, and local kinematic mapping are suitable plumbing evidence but too simple to support a general controller-identity claim.

##### 2. Separate logical identity from deployment identity

Represent the logical network through NIR or a rigorously mapped subset. Record each transformation from logical network to backend-specific deployment as a signed provenance step. The backend profile then binds all execution fields that can change behavior: timestep, reset rules, precision, quantization, optimizer/compiler version, mapping, runtime, firmware, and hardware measurement.

Define which changes imply:

- the same byte artifact;
- a new artifact in the same approved semantic family;
- a new deployment requiring behavioral revalidation;
- a forbidden or unknown transformation.

Do not make one monolithic digest carry all meaning. Use explicit digests for logical model, codec/contract, deployment profile, validation corpus, and final bundle, then bind them in one signed admission statement.

##### 3. Integrate admission with Gate

An offline approver validates the bundle against `ControllerAdmissionProfileV1` and signs an `AdmissionRecordV1` naming both digests, the authorized mission class, vehicle class, backend profile, behavior-corpus result, validity window, and policy constraints. Gate admits a controller only when the signed intent's bundle/profile digests match that current admission and the transport/signing identity is authorized to use it. `AdmissionStatementV1` was the earlier draft name for this record and is not a second protocol type.

For a software backend, self-reported runtime metadata is an input claim, not remote attestation. Stronger evidence later follows a RATS-style model: an attester produces signed measurements, a verifier appraises them against reference values, and Gate consumes a short-lived attestation result. TPM/DICE or platform-specific roots are later work.

##### 4. Define cross-backend conformance at the action boundary

Choose a second independent, maintained and accessible backend after a compatibility spike. Candidate paths include a NIR-supported software backend or SpiNNaker2/Brian2 emulation if its dependency and licensing constraints are acceptable. Lava must not be the committed next step while its public repositories are archived. Physical Loihi or SpiNNaker access is a stretch gate, not an assumption.

Run paired seeded scenario corpora. Compare:

- decoded actions and Gate ALLOW/DENY decisions;
- constraint margins and mode transitions;
- closed-loop trajectory envelopes and mission outcomes;
- rate, timing, energy, and resource measures where meaningful;
- internal spike/statistical differences only as explanatory diagnostics.

Define an authorization-equivalence relation that tolerates backend numerical differences while guaranteeing the action remains in the authorized mission relation. Recurrent networks and quantized mappings are specifically important because naïve spike equality is unlikely to survive.

##### 5. Handle learning explicitly

The initial project prohibits online plasticity. For later adaptive controllers, the admission model must bind an approved update rule, permitted state/weight region, checkpoint lineage, update authority, and rollback behavior. An initial weight digest cannot continue to identify a controller whose weights change online.

#### Milestones

1. Complete schema and canonical test vectors for one fixed-weight NEST controller.
2. Engram instantiation entirely from the bundle; no hidden topology or codec configuration.
3. Signed admission and substitution tests integrated with Gate.
4. A public behavior corpus with seeded benign, boundary, and adversarial scenarios.
5. NIR mapping and one independent software/emulated backend.
6. Action-equivalence analysis and cross-backend results.
7. Physical neuromorphic platform only after access, measurement, and deployment semantics are documented.

#### Validation and baselines

Substitute each field independently: graph edge, weight, seed, encoder, decoder, unit/frame, timestep, reset, quantization, compiler, backend, mapping, firmware, policy, and approval. Test both detectable substitutions and approved transformations. Measure false acceptance/rejection, reproducibility, bundle build/verification time, behavioral drift, and the predictive value of the conformance relation.

Compare against:

- filename or model-name admission;
- whole-package SHA-256 only;
- signed artifact plus ordinary SBOM/provenance;
- NIR round-trip/cross-platform validation without mission authorization;
- behavior-only admission with no artifact/deployment identity.

#### Limitations and kill criteria

A digest does not prove safety or benign intent. A complete manifest can still encode a malicious controller. Software-reported backend data is not hardware attestation. A finite fixture corpus does not prove all behavior. Cross-backend similarity depends on controller, plant, codec, and tolerance and cannot be declared universal.

Stop or reframe the neuromorphic claim if:

- a complete controller cannot be reconstructed from the admitted bundle;
- important execution semantics remain hidden in arbitrary code or ambient backend state;
- the second backend is only a wrapper over the same implementation;
- action-level tolerances are chosen after observing results and cannot predict held-out behavior;
- no hardware access exists but the work continues to claim hardware assurance;
- the contribution reduces to signing a model archive.

#### Research value

Watchword-Neuro supplies the strongest doctoral contribution: a semantic deployment identity and action-equivalence relation for portable spiking controllers. Its value depends on showing which fields are necessary, which transformations preserve what relation, and whether the relation predicts safe authorization behavior across genuinely independent backends.

### 2. Haldir Gate — controller-bound mission authorization

#### What it entails

Haldir Gate is a local, inline policy-enforcement point between controller intent and the final NCP command stream. It answers a question that transport ACLs and physical governors do not answer:

> Is this exact controller deployment, acting under this identity and lease, authorized to issue this exact action to this vehicle in the current mission phase and trusted state?

The first version is deliberately narrow: one controller, one vehicle, one NCP session, one final command key, and a benign navigation or inspection mission. It is not a generic service mesh, fleet orchestrator, weapons-authorization system, or replacement flight controller.

The intended path is:

```text
controller certificate + signing key
             |
             | exact controller-specific intent key
             | SignedIntentV1(exact NCP CommandFrame bytes, context, signature)
             v
     bounded Gate ingress queue
             |
             +--> strict decoding and deterministic checks
             +--> identity / lease / artifact checks
             +--> Cedar ABAC decision
             +--> signed DecisionReceiptV1
             |
             | ALLOW: publish one final NCP session command
             | DENY: bounded expiry, or atomically close local lease state,
             |       then attempt Gate reversion at downstream seq + 1
             v
     Crebain CommandPlant / actuator adapter
```

Gate should not infer identity from a Zenoh sample. The deployment must give each controller an exact intent key and configure the router so only its certificate identity can publish that key. A signed application envelope supplies an independently verifiable binding to the controller signing key. These controls serve different purposes: mTLS/ACL limits the transport principal, while the envelope makes the intent portable, replay-aware, and cryptographically bound to its context.

For the single-controller MVP, the final key is the exact NCP base command key:

```text
{realm}/session/{vehicle_session}/command
```

Using `.../command/{vehicle}` would require Crebain to use named-command subscriptions and redesign its current session-only action-runtime mapping. That is unnecessary for the first experiment.

#### Why it was chosen

Gate has the best ecosystem leverage because it consumes the security-relevant outputs of the other projects:

- Vilya tells Gate which workload identity owns an intent key;
- Watchword-Neuro tells Gate which controller deployment was admitted;
- Nénya can tell Gate whether navigation state is trustworthy enough for a phase;
- Warden's Eye can provide a perception/model assurance assertion;
- Rúmil can provide an independent execution or health signal;
- the Roll preserves Gate's decisions; and
- Border-Muster attacks and measures the entire composition.

Without an enforcement boundary, most of these are alerts or metadata. Gate turns them into preventive decisions. It also fits the present NCP/Crebain separation: NCP already owns typed command validation and transport, while Crebain has the action plant where a final authorized command can be applied.

The reason is practical rather than a novelty claim. Inline ROS coordination, runtime enforcement, Simplex-style assurance, ABAC, and pre-actuation policy already exist in the literature. Gate is chosen because it is the right place to investigate the narrower intersection of mission authorization and portable neural-controller identity.

#### Concrete implementation

##### 1. Establish the authority graph before writing policy

Create a machine-readable graph of every path that can affect actuation in the selected Crebain deployment: NCP command subscribers, ROS publishers, MAVROS setpoint topics, mode/arm/takeoff/land services, UI actions, test hooks, and native callbacks. For the experiment profile, remove or disable every competing path, or place it under an independently tested constraint. A router ACL that protects one NCP key is insufficient while another publisher can still reach MAVROS.

Extend NCP's secure router profile and live verifier. The existing profile grants the `commander` final command authority; the Haldir profile instead grants:

- each controller: write only its exact intent key and read only required state;
- Gate/guardian: read admitted intent keys and write the one final command and evidence keys;
- robot/Crebain: publish approved sensor/state keys and read the final command;
- observer: read-only access to explicitly listed telemetry/evidence;
- lifecycle service: only the session operations it actually requires.

The verifier must prove delivery and non-delivery using distinct certificates. A local Zenoh `put()` returning successfully is not proof that an ACL delivered the sample.

##### 2. Define a versioned signed intent

`SignedIntentV1` should use deterministic CBOR/COSE or another domain-separated canonical encoding with Rust, Python, and TypeScript golden vectors. It should contain:

- protocol and schema version;
- controller signing-key identifier;
- authenticated controller identifier and exact intent key;
- mission, vehicle, NCP session, and lease identifiers;
- lease epoch, intent sequence, issued-at basis, and expiry/horizon;
- admitted controller-bundle digest and backend-profile digest;
- exact inner NCP `CommandFrame` bytes;
- signature over the domain and all preceding fields.

Replay state is keyed by controller, vehicle/session, and lease epoch. It accepts legitimate gaps, rejects duplicates and stale epochs, bounds sequence jumps according to policy, and expires old state. A Gate process restart or host reboot invalidates every active lease and requires the lease authority to issue a fresh higher epoch; a durable watermark is restored only to reject old authority, never to reconstruct a prior monotonic deadline. NCP's own sequence is not a complete application replay protocol because a stream can re-anchor after expiry and because mission/controller epochs have different semantics.

The MVP admits exactly one controller per vehicle lease. On ordinary ALLOW, Gate can preserve the enclosed command bytes exactly, making input/output digest comparison unambiguous. Controller commands stop at `JSON_SAFE_INTEGER_MAX - 1`, reserving `JSON_SAFE_INTEGER_MAX` for reversion. Gate first commits durable local state to `TERMINATING/CLOSED`, stores the watermark and proposed `last_accepted_downstream_seq + 1` frame, and blocks the old epoch; it then separately attempts and records publication. Crash, publish failure, or delivery failure never reopens the lease and instead falls back to bounded expiry. A fresh higher lease epoch may use a lower sequence anchor only after the previous command/reversion TTL, `ActionBuffer` horizon, and watchdog state have expired. If later versions multiplex controllers, Gate should terminate the intent protocol and issue every new canonical downstream `CommandFrame`; receipts must then bind exact input and output bytes and describe the transformation. They must not keep claiming byte identity.

##### 3. Split deterministic checks from ABAC

Use `ncp_core::decode_validated::<CommandFrame>` for the typed NCP contract, preceded by a bounded parser that rejects oversized input and duplicate JSON object keys. The trusted Rust monitor performs operations that are stateful, numeric, temporal, or geometric:

- finite-value, shape, frame, and unit checks;
- horizon, TTL, freshness, and lease timing;
- speed, acceleration, slew, and duty-window accounting;
- allowed-region and denied-volume geometry;
- state-source freshness and uncertainty thresholds;
- monotonic epoch/sequence/replay rules;
- bounded queue, rate, and per-principal resource budgets;
- phase transition and emergency priority rules.

Cedar then evaluates principal/action/resource/context authorization over derived booleans and bounded/scaled integers. Cedar should not be treated as the vector-math engine or the complete stateful monitor. Gate must fail the whole decision closed on policy diagnostics or evaluation errors, even if another policy would otherwise permit it. Policy bundles are signed, versioned, rollback-protected, validated off-path, and atomically activated.

For the MVP these physical predicates are reject-only trusted Gate checks, with a deployment-specific TTL cap far below NCP's protocol maximum. An alternative is an explicitly configured `SafetyGovernor`/physical monitor inside trusted Crebain code. Zenoh `publish_command` does not invoke that governor automatically. Any clamp, normalization, or rewrite ends the byte-preserving path and must appear as a distinct, receipt-bound output frame.

##### 4. Keep the command path bounded

Use the public raw `ZenohBus::subscribe` for custom intent keys and `publish_command` for the final command. The subscription callback should do minimal bounded work and `try_send` into one fixed-capacity worker queue per vehicle/session. Queue overflow is observable and denied; it must not grow memory or block the router callback.

No network service, database, transparency log, or receipt collector belongs synchronously in the decision path. Preload the active policy, controller admission, public keys, and locally required state. Define separate priority and resource budgets for emergency stop or reversion behavior so a valid controller cannot starve it with an intent flood.

`DecisionReceiptV1` records exact intent and output digests, principal, mission/vehicle/lease/controller bundle, policy digest, state-snapshot digest and freshness, decision, stable reason codes, input/output sequences, monotonic local timestamps, and evaluation latency. It distinguishes an authorization decision and local publish attempt/result from delivery or plant application. A separate Crebain accepted-command/adapter-result event or authenticated observer acknowledgement supplies that later evidence. The receipt is signed and appended asynchronously to a bounded local spool. A receipt-sink outage reduces evidence availability but does not widen authorization or stall control.

##### 5. Complete Crebain's live lifecycle

Register and manage `NcpHandle`; add explicit start/stop action-loop operations or own them in a deployment service; call the public `NcpBridge::start_action_loop`/`subscribe_commands` seam with a synchronous nonblocking closure; bridge that closure through a bounded channel to the native async Rust actuator transport; and define shutdown ordering. The existing TypeScript rosbridge UI connection is not directly usable from the Rust callback.

Shutdown must stop new intents, enter the vehicle/phase-specific reversion contract, stop NCP, and only then disconnect the actuator transport. The first integration target is the standalone Crebain `CommandPlant` and deterministic plant. Gazebo/MAVROS follows. PX4-SITL is an integration gate only after arming, offboard mode, command ownership, telemetry, and stop behavior are implemented and tested.

#### Milestones

1. **Pure Gate core:** fixture-driven leases, replay state, deterministic predicates, Cedar adapter, receipts, and property/fuzz tests without networking.
2. **Secure five-role profile:** generated certificates/configuration, exact per-controller key ACLs, final-key exclusivity, and a live authority matrix.
3. **Deterministic vertical slice:** Engram NEST publisher to secure Zenoh, Gate, and standalone Crebain `CommandPlant` with a deterministic plant.
4. **Failure composition:** Gate kill, router partition, queue overload, clock/restart, stale state, and evidence outage with measured deny/failure-to-reversion time.
5. **Gazebo/MAVROS path:** native Crebain actuator callback and complete authority graph.
6. **PX4-SITL and broader policies:** only after the earlier stages meet their criteria.

#### Validation and baselines

The minimum attack matrix covers wrong certificate, wrong intent key, direct final-key write, invalid or stripped signature, field substitution, inner-byte alteration, controller-bundle mismatch, stale lease, cross-mission replay, duplicate and large-jump sequences, malformed/duplicate-key input, policy rollback, slow or invalid policy, stale state, queue overload, Gate crash, router restart, and receipt outage.

Report false allows, false denies, mission-completion impact, p50/p99/p99.9 authorization latency, deadline misses, queue drops, throughput, memory bounds, time-to-reversion, receipt completeness, and exact byte parity for the MVP ALLOW path. Compare at least:

- direct NCP with mTLS/ACL only;
- NCP plus an explicitly configured `SafetyGovernor`;
- a generic Cedar/OPA-style policy enforcement point;
- a RTron-like inline rule monitor where comparable;
- a SOTER/Simplex-style monitor and fallback.

Linux latency measurements support an empirical bounded-operating-region claim, not a hard-real-time proof.

#### Limitations and kill criteria

Gate is not complete mediation until all actuator paths in the declared boundary are closed and continuously tested. It cannot make untrusted state true, make HOLD physically safe, prevent theft of an online signing key, prove that an admitted neural model is benign, or guarantee delivery exactly once over pub/sub.

Stop or reframe the project if any of the following survives the spike:

- an ordinary controller can reach actuation without Gate;
- controller principal, intent key, signature, and bundle identity cannot be bound unambiguously;
- a denial, crash, or partition cannot reach a phase-appropriate reversion within the stated bound;
- the trusted monitor cannot meet the 20–50 Hz tail-latency and resource budget under adversarial load;
- policies needed for the demonstration are merely duplicates of NCP's physical governor;
- the only result is a generic policy proxy with signed logs.

#### Research value

The Gate implementation is an enabling systems artifact. Its defensible research question is narrower: what external command contract is necessary and sufficient to authorize the outputs of an opaque, portable neural controller at mission level, and how do its lease and reversion semantics compose with the plant? That question must be answered with a formal model and comparative evidence, not with architecture alone.

### 3. Border-Muster v2 — reproducible secure-autonomy acceptance range

#### What it entails

Border-Muster is a reproducible experiment harness for the selected Haldir deployment. Its primary output is not a dashboard or a capture-the-flag event. It is a machine-verifiable evidence bundle showing what happened under benign operation, attack, overload, crash, restart, and backend substitution.

The range grows in explicit layers:

1. **Deterministic fast range:** secure Zenoh router, fixture controller, Gate, Crebain `CommandPlant`, deterministic plant, adversarial publishers, and no ROS/PX4 dependency.
2. **Engram/NEST range:** the same path with a real NEST controller refactored behind a bus publisher.
3. **Gazebo/MAVROS range:** native Crebain actuator callback, simulated vehicle dynamics, and independent telemetry.
4. **PX4-SITL campaign:** only after the external toolchain and authority lifecycle are provisioned and tested.
5. **Backend-conformance and HIL campaigns:** second neural backend, then physical hardware when access exists.

Every run uses pinned repository revisions or container digests, a versioned topology and policy, fixed random seeds where determinism is expected, isolated realm/ports, bounded process supervision, explicit timeouts, and machine-readable assertions. Results include the policy and artifact digests, certificate/key identifiers, environment inventory, receipts, router and process events, latency histograms, final plant state, and an explanation for every expected allow or deny.

#### Why it was chosen

The existing ecosystem contains individually useful libraries and examples, but the load-bearing end-to-end claims are still unmeasured: no committed live principal-to-intent binding, no complete authority graph, no Gate, no live Engram-to-Crebain path, no failure-to-reversion campaign, and no cross-backend controller result. Border-Muster turns those unknowns into executable acceptance gates.

It ranks third because it gives every other proposal honest evidence and makes negative results reusable. It is also the most reliable way to prevent a simulation demo from becoming an implicit hardware or flight-safety claim. Its limitation is equally clear: a range tests a declared environment; it does not itself create the security mechanism.

#### Concrete implementation

##### 1. Define a scenario contract

Each scenario contains:

- unique ID, objective, threat actor, preconditions, and expected invariant;
- exact component and configuration manifest;
- controller, vehicle, mission, policy, lease, and bundle identifiers;
- deterministic seed and time-control strategy;
- fault injection schedule and bounded duration;
- expected decisions, reason codes, reversion state, and timing thresholds;
- required evidence files and pass/fail assertions;
- unsupported claims and extrapolation boundary.

Keep orchestration independent from the system under test. The harness should start processes in dependency order, perform readiness probes that exercise real data delivery, inject the fault, collect bounded output, terminate in reverse order, and always preserve the failed evidence bundle. A process being alive or a port being open is not sufficient readiness.

##### 2. Build the deterministic layer first

Use a simple plant with explicit state transition equations and a seeded clock so policy and lease behavior can be tested quickly. Include fixtures for valid and invalid `SignedIntentV1`, state assertions, policy bundles, controller admissions, and NCP frames. This layer runs in CI and supports fuzz/property campaigns without requiring NEST, Gazebo, ROS, or PX4.

Add attackers as first-class processes with their own certificates and resource budgets. Do not simulate ACL denial only by bypassing the router API; prove it with live delivery/non-delivery observations. Preserve router configuration and certificate fingerprints with the result.

##### 3. Add real components one dependency at a time

Refactor the Engram example so it publishes through the secure bus instead of calling a local kinematic plant. Run the same assertion set with the real NEST backend. Then integrate Crebain's native action callback into Gazebo/MAVROS. Only after the command ownership and stop lifecycle work should a PX4-SITL campaign be added.

The local environment should not be called PX4-ready merely because Docker or Conda exists. The range must probe and record the exact Zenoh, ROS, Gazebo, PX4, compiler, backend, and driver versions it actually uses.

##### 4. Implement a stable attack taxonomy

The core campaign includes:

- no certificate, wrong certificate, and controller-to-controller key impersonation;
- unauthorized direct write to the final command or alternative actuator path;
- valid controller credential issuing a wrong mission/vehicle/phase action;
- intent signature stripping, field substitution, replay, and lease-epoch rollback;
- controller graph, weight, codec, timestep, quantization, backend, and policy substitution;
- malformed, duplicate-key, oversized, NaN/Inf, wrong-unit, and stale commands;
- stale or inconsistent state and clock regression;
- Gate kill/restart, router restart/partition, queue overload, slow policy, and controller flood;
- evidence-sink outage, disk pressure, and receipt truncation;
- later GNSS, perception, and plant faults when the relevant projects exist.

Attack code must not contain operational credentials or unsafe field-deployment defaults. Demonstrations remain benign navigation, inspection, or hold/recovery tasks.

##### 5. Produce comparable evidence

Use a common results schema for each baseline and candidate. At minimum record false allows/denies, constraint violations, mission completion, time-to-reversion, p50/p99/p99.9 authorization latency, deadline misses, throughput, queue drops, maximum resident memory, CPU, receipt coverage, and paired command/trajectory divergence. Store raw observations and the analysis version so a graph can be regenerated rather than trusted as an image.

#### Milestones

1. Scenario schema, deterministic plant, fixture controller, and CI smoke campaign.
2. Secure identity/ACL matrix and direct-key-bypass tests.
3. Gate baseline/candidate comparisons and full failure campaign.
4. Real Engram/NEST bus publisher.
5. Crebain/Gazebo integration and independent measured state.
6. PX4-SITL only after a provisioning and lifecycle acceptance test.
7. Cross-backend Watchword campaign and, conditionally, HIL/hardware.

#### Validation and baselines

The range itself needs tests: corrupt expected evidence, kill the orchestrator, reuse ports, change a dependency version, omit a receipt, inject a non-deterministic seed, and verify that the harness fails rather than producing a misleading green result. Repeat runs quantify variance and separate deterministic assertions from distributional thresholds.

The mandatory baseline set is direct NCP, NCP governor, detached countersign, generic inline PEP, and SOTER/Simplex-style fallback where implementable. A Haldir result without a baseline shows operation, not contribution.

#### Limitations and kill criteria

SITL does not establish airworthiness, field attack realism, hard-real-time behavior, or neuromorphic hardware timing. An isolated deterministic plant can hide timing and dynamics failures; a rich simulator can introduce opaque noise and dependency drift. Both layers are therefore required for different questions.

Stop presenting Border-Muster as a research artifact if scenarios are hand-run, evidence cannot be replayed, dependencies are not pinned, failures cannot be attributed, or thresholds are selected after seeing candidate results. Keep it as internal integration testing in that case.

#### Research value

Border-Muster is primarily methodology and infrastructure. It becomes publishable research only if it contributes a new, reusable threat taxonomy, benchmark, dataset, or measurement finding with defensible baselines and external reproducibility. Its strongest role in the PhD is to make Gate and Watchword claims falsifiable.

### 4. Vilya — deployment identity and least-authority trust root

#### What it entails

Vilya is the deployment trust layer that makes Gate's transport identities and authority boundaries reproducible. It provisions separate workload certificates, client keys, intent-signing keys, ACL entries, trust anchors, rotation metadata, and live verification for controller, guardian, robot, lifecycle, and observer roles.

The first version uses a conventional offline or established CA workflow and software-protected keys. Hardware roots, measured boot, TPM/DICE identities, short-lived attestation results, and disconnected revocation are later profiles. This ordering prevents hardware terminology from hiding an unproven software authority model.

Vilya maintains a declarative inventory containing:

- workload and role identifier;
- unique certificate subject/SAN and trust domain;
- exact Zenoh read/write/call key permissions;
- application signing and verification key IDs;
- allowed controller bundle/admission references where applicable;
- issuance, activation, expiry, rotation, revocation epoch, and owner;
- generated router/client configuration digest;
- live verification result and evidence timestamp.

Transport identity and application-signing identity remain distinct. The certificate proves possession of the transport private key and supports router authorization. It does not prove which binary or neural artifact is running. Watchword and an attestation mechanism address that separate question.

#### Why it was chosen

NCP documents the distinction between local command validity, sender authorization, and mTLS identity, and its secure deployment work still requires live evidence for the exact Haldir role matrix. Gate is unsafe if adding a guardian merely widens command authority while leaving a controller able to publish the final key.

Vilya ranks fourth because it closes a real prerequisite with low conceptual risk and benefits every project using NCP. It does not rank higher because issuing certificates and rendering ACLs are well-established engineering, and because identity alone does not solve mission authorization or controller attestation.

#### Concrete implementation

##### 1. Define roles as least-authority statements

Create a versioned role manifest and generate, rather than manually duplicate, router and client configuration. For the Gate profile:

- `controller-A` writes only `.../intent/controller-A` and cannot write final command/evidence/state;
- `controller-B` cannot write or impersonate controller A's intent key;
- `guardian` reads allowed intent/state keys and alone writes the final command;
- `robot` reads the final command and writes only approved measured-state keys;
- `observer` receives selected state and evidence but cannot mutate operational keys;
- `lifecycle` calls only explicit session endpoints.

Use a unique leaf identity per workload because broad shared common names destroy attribution and force overly broad ACLs. Do not use wildcard rules where the router's matching behavior is ambiguous; generate exact entries and test them.

##### 2. Reuse and extend the NCP verifier

Build on NCP's live, delivery-based authority verifier. For every role and operation, attempt the positive and relevant negative action with the correct certificate, another role's certificate, and no certificate. Observe delivery at an authorized recipient. Include query/reply and lifecycle verbs as well as publish/subscribe.

The generated configuration checker catches static widening. The live matrix catches router interpretation, certificate, and deployment errors. Store both results and their configuration/certificate digests.

##### 3. Define rotation and failure behavior

Document and test initial issuance, overlap window, activation, leaf expiry, signing-key rotation, trust-anchor rollover, compromised-key removal, router reload, and recovery from partial rollout. A certificate expiry option can close a link, but it is not a complete revocation strategy, especially for disconnected systems.

Gate admissions and mission leases reference key IDs and epochs. Rotation must not reset replay state silently or allow an old key to regain authority through a stale policy. Emergency recovery keys have narrower, auditable authority and are never ordinary controller keys.

##### 4. Add hardware roots only for a defined claim

A later TPM/DICE profile can protect workload keys and bind evidence to boot measurements. It must define the attester, verifier, reference values, appraisal policy, freshness nonce, and result consumed by Gate. Possession of a hardware-protected key is not automatically proof of controller artifact, runtime integrity, or safe behavior.

#### Milestones

1. Role/inventory schema and deterministic configuration renderer.
2. Five-role certificates, strict router profile, and static authority checker.
3. Live positive/negative delivery matrix including no-certificate tests.
4. Leaf and signing-key rotation without authority widening or replay reset.
5. Compromise and expiry drills with bounded recovery evidence.
6. Conditional TPM/DICE attestation profile.

#### Validation and baselines

Test wrong role, wrong key, no certificate, expired certificate, old trust anchor, revoked signing key, stale configuration, wildcard expansion, controller key impersonation, final-key bypass, policy rollback, and partial rotation. Compare the generated profile with NCP's existing commander/robot/observer profile and show the exact authority delta.

Operational metrics include time to provision/rotate/revoke, configuration drift rate, unauthorized deliveries, false lockouts, overlap duration, and recovery time. The primary security result is an authority matrix with zero unexpected deliveries in the declared profile.

#### Limitations and kill criteria

Vilya does not identify a running process binary, prove a controller artifact, protect a key after a compromised process can invoke it, provide confidentiality beyond the transport, or guarantee revocation during disconnection. An ACL also cannot close an actuator path that bypasses the protected bus.

Stop treating Vilya as a separate project if it becomes only certificate-generation scripts with no live least-authority verifier, rotation experiment, or authority-diff model. In that case it remains a necessary Gate deployment module.

#### Research value

The default Vilya scope has low doctoral novelty. Research is plausible only around a sharply defined problem such as disconnected revocation with bounded authority, composition of workload and controller-artifact identities, or hardware-rooted evidence under intermittent connectivity. For the selected program it is supporting security engineering.

### 5. Nénya — navigation-integrity guardian with enforced degradation

#### What it entails

Nénya is an independent own-ship navigation-integrity service. It detects GNSS spoofing, jamming, timing faults, and inconsistent navigation sources, estimates uncertainty during degradation, and publishes a typed assertion that Gate can enforce.

It is not merely a dashboard alarm and should not be built by reusing Crebain's target-tracking fusion as if it were own-ship navigation. A target estimator and a vehicle navigation integrity monitor have different states, sensor semantics, frames, clocks, observability, and failure modes.

The minimum input contract includes:

- raw GNSS position/velocity, fix type, covariance, satellite/quality indicators, and receiver time status;
- IMU acceleration/angular rate with calibration and covariance;
- barometer and magnetometer where used;
- wheel/visual odometry or another independent motion source where available;
- vehicle mode, commanded motion, local clock status, and source freshness;
- frame/origin metadata for reproducible ECEF/ENU transformations.

The output is a signed or authenticated `NavIntegrityAssertionV1` containing state (`NOMINAL`, `SUSPECT`, `DEGRADED`, `RECOVERING`, `UNKNOWN`), position/velocity uncertainty, contributing sources, freshness, reason codes, detector statistics, allowed duration/operating envelope, and an assertion sequence/epoch.

Gate consumes the assertion as policy state. A degraded assertion can prohibit takeoff or geofence-edge operations, reduce speed/mission area, require a return/hold mode where physically appropriate, or expire mission authority. Detection becomes preventive only through such an enforced response.

#### Why it was chosen

GNSS deception and loss are consequential for autonomous systems, and NCP's current prospective geofence explicitly has a simple local geometry/origin model rather than a navigation-trust subsystem. Crebain has IMU and pose data structures, but not the complete raw GNSS/clock/covariance contract or an independent own-ship integrity estimator.

Nénya ranks fifth because it can prevent a high-impact class of state-dependent policy failures and has clear quantitative tests. It ranks below the Gate/Watchword/range spine because its direct Engram and neuromorphic relevance is weak and the spoof-detection/robust-navigation literature is crowded. Its research claim cannot be “innovation threshold detects spoofing”; it needs a new integrity bound, coordinated-attack result, or enforcement composition.

#### Concrete implementation

##### 1. Add a correct navigation sensor contract

Define NCP profiles or carefully versioned custom messages for raw GNSS, IMU, velocity, VO, clock, and navigation health. Include covariance, frame, units, origin, source timestamp, receive timestamp, sequence, and sensor identity. Reject silent frame/unit defaults.

Implement adapters in a boundary module rather than mixing ROS message quirks into the estimator. Record raw input traces before filtering so attacks and estimator choices can be replayed.

##### 2. Build an independent estimator and detector

Use a documented error-state estimator or similarly auditable model with explicit process and measurement assumptions. Compute whitened innovations, consistency statistics, source-to-source residuals, timing anomalies, and physically plausible acceleration/turn constraints. Persistent low-rate drift requires sequential evidence such as CUSUM/GLRT-style detectors; a one-frame threshold is not enough.

Keep estimation and attack classification separate. An estimator can be inconsistent because of poor calibration, multipath, dropped frames, origin errors, or an attack. The assertion should report confidence and reasons rather than overclaim attribution.

##### 3. Define a bounded degradation state machine

Specify entry/exit guards, hysteresis, minimum dwell, recovery confirmation, and restart behavior for each integrity state. The degraded operating envelope is derived from uncertainty growth and vehicle dynamics, not a fixed promise that dead reckoning remains safe.

For example, a multirotor in open space may use a short, low-speed local hold under bounded IMU/VO uncertainty. A fixed-wing vehicle cannot treat zero velocity as a safe state. Each tested vehicle/phase needs an assured reversion contract and a maximum unsupported-navigation duration.

##### 4. Enforce the assertion through Gate

Give Nénya a distinct workload identity and assertion key. Gate verifies source, sequence, epoch, freshness, and policy compatibility. Unknown, stale, or restarting Nénya state maps to an explicit policy response. The controller cannot publish or override its own integrity assertion.

Avoid a circular dependency in which Nénya trusts only the same GNSS-derived pose that it is supposed to validate or Gate's region check uses a different origin/model. The range must record the exact coordinate transformation and state snapshot used for each decision.

#### Milestones

1. Raw, typed sensor contracts and deterministic ENU/ECEF conversion tests.
2. Nominal estimator on simulated and recorded benign traces.
3. Spoof/jam/timing fault generator and calibrated sequential detector.
4. Typed assertion and degradation/recovery state machine.
5. Gate policies that visibly restrict authority on degraded/stale state.
6. Monte Carlo range, recorded-flight data, then HIL if available.

#### Validation and baselines

Attacks include abrupt offset, slow drift, velocity-only spoof, time shift, coordinated position/velocity spoof, jamming/dropout, multipath-like noise, IMU bias, VO drift, covariance lies, delayed/reordered samples, origin mismatch, and detector restart. Include inject-nothing placebos and benign aggressive maneuvers.

Report false-alarm rate at matched operating points, detection delay, miss rate, maximum undetected displacement, uncertainty calibration, dead-reckoning error growth, time in degraded mode, mission completion, and Gate response time. Compare against raw receiver flags, innovation chi-square, pairwise residual/parity checks, and CUSUM/GLRT baselines.

#### Limitations and kill criteria

Residual tests cannot detect every coordinated attack. Dead reckoning drifts, independent sources can share common failures, simulation does not reproduce all RF/multipath conditions, and a trustworthy assertion does not by itself make the chosen recovery maneuver safe.

Stop or narrow the project if it lacks a genuinely independent source, cannot beat simple residual/sequential baselines at matched false-alarm rate and latency, cannot maintain calibrated uncertainty, or cannot connect a detected condition to a safer enforced action. In that case it may remain a useful sensor-health adapter rather than a research contribution.

#### Research value

The plausible doctoral delta is an enforceable integrity contract that composes calibrated navigation uncertainty with mission authority and a bounded degraded operating envelope. The detector alone is unlikely to be novel. The strongest experiment asks whether the enforced composition reduces unsafe mission actions without making benign missions unusable.

### 6. Marchwarden secure envelope — context-bound intents and receipts

#### What it entails

The secure-envelope project defines the application-layer objects that remain verifiable across router hops, store-and-forward operation, process restarts, and evidence export. Its two core types are the `SignedIntentV1` and `DecisionReceiptV1` used by Gate.

The envelope protects integrity, origin, context binding, and replay semantics for exact bytes. It is not encryption, authorization, physical safety, or proof that the signing process is uncompromised.

`SignedIntentV1` binds:

- protocol domain/version and algorithm suite;
- controller signing key and transport/key binding expectation;
- mission, vehicle, NCP session, lease, and lease epoch;
- controller bundle and deployment-profile digests;
- intent sequence, issued/expiry values, and time-basis identifier;
- exact inner content type and NCP command bytes;
- deterministic signature input.

`DecisionReceiptV1` binds:

- exact signed-intent digest and, if allowed, exact downstream-command digest;
- policy/admission/state snapshot digests and versions;
- allow/deny/error result with stable reason codes;
- input and output sequence/epoch relationship;
- local monotonic processing timestamps plus any explicitly qualified external time;
- Gate identity, signature key, and signature.

#### Why it was chosen

NCP currently relies primarily on transport security and typed validation; a message observed outside the live mTLS session does not carry an application signature or mission/artifact context. Gate needs a stable way to prove what it evaluated and to reject replay across different authority epochs.

It ranks sixth because it is broadly reusable and security-critical, but the primitives are established. Signing canonical messages, context/domain separation, COSE-style envelopes, and replay windows are not by themselves novel. The work is valuable when it supplies precise loss, gap, restart, and handoff semantics for this real-time control path.

#### Concrete implementation

##### 1. Write the protocol specification before the library

Specify canonical deterministic encoding, algorithm identifiers, allowed key types, domain-separation strings, maximum sizes/cardinalities, duplicate-field rejection, extension rules, unknown-critical-field behavior, and signature input as exact byte ranges. Ordinary JSON reserialization is not a signing format.

Use opaque byte strings for the inner NCP frame so the signed content cannot change through parsing or normalization. If Gate later reissues a canonical frame, represent it as a separate output and bind both digests in the receipt.

##### 2. Define replay and restart semantics

Maintain replay state per `(controller_key, mission, vehicle_session, lease_epoch)`. Sequences are monotonically increasing inside an epoch; gaps caused by loss are acceptable; duplicates and old epochs are rejected; implausibly large jumps receive an explicit policy outcome; state is bounded and expires only after the corresponding authority cannot return.

Lease renewal increments an epoch and names the previous epoch. Controller restart does not create authority to reset sequence unilaterally. Signing-key rotation and controller handoff define whether state is transferred, terminated, or quarantined. Model these transitions independently of wall-clock assumptions.

##### 3. Build interoperable libraries and vectors

Implement the first crate in Rust, with a deliberately small API that returns typed verification errors. Publish positive and negative golden vectors for Rust, Python/Engram, and TypeScript where needed. Run mutation and differential tests over encoders/decoders and reject non-canonical encodings even if their semantic map appears equivalent.

Keep private-key access behind a signer interface so software, OS key store, or hardware-backed implementations can be substituted without changing the wire object. Verification never performs network key lookup on the real-time path; active keys and status are preloaded from the signed trust/admission bundle.

##### 4. Integrate without blocking control

Controllers sign before publish. Gate verifies after bounded ingress and before policy. Receipt signing can occur in the decision worker only if its worst-case cost is inside the budget; replication and checkpointing are always asynchronous. If local receipt signing itself misses deadlines, use a preallocated/bounded signer design or an explicitly measured unsigned event followed by batch checkpointing, and state the evidence trade-off.

#### Milestones

1. Versioned wire specification and threat model.
2. Rust implementation, property tests, fuzz targets, and golden vectors.
3. Python and TypeScript interoperability.
4. Gate integration with replay/lease epochs and exact-byte receipts.
5. Key rotation, loss/gap/restart, and cross-realm store-and-forward tests.
6. Formal or exhaustive state-machine analysis of replay/epoch transitions.

#### Validation and baselines

Test signature stripping, unknown algorithms, key confusion, field/context substitution, altered inner bytes, non-canonical encoding, duplicate fields, oversized input, duplicate sequence, stale/future epoch, legitimate loss/gaps, large sequence jumps, restart, handoff, key rotation, clock rewind, and cross-language parity.

Compare transport-only mTLS, signature over inner NCP bytes only, whole-envelope signature without epoch semantics, and the complete context-bound envelope. The comparison should show exactly which attack each additional field/state rule prevents.

#### Limitations and kill criteria

The envelope does not provide confidentiality, authorize its contents, guarantee delivery, establish legal non-repudiation, protect against an online stolen signing key, or prove the controller artifact. Cryptography also cannot resolve unsafe time/lease semantics that the protocol leaves ambiguous.

Stop treating it as a separate research proposal if its only result is a conventional signed wrapper. Keep it as a required Gate protocol module. A standalone contribution would require a demonstrably new and formally analyzed real-time replay/handoff protocol with evidence that existing profiles do not cover the requirement.

#### Research value

The envelope makes the larger research reproducible and auditable, but it is supporting engineering unless the loss/gap/restart/lease composition yields a new protocol result. Its main value is removing ambiguity from Gate and Watchword claims.

### 7. Rúmil v2 — independent execution and plant-response monitor

#### What it entails

Rúmil v2 observes the final authorized command, an independently sourced estimate of measured vehicle behavior, flight-controller mode/health, and eventually actuator acknowledgement or output telemetry. It asks whether the plant responded consistently with the authorized command and a conservative dynamics envelope.

It is not another copy of `ncp_core::SafetyGovernor`. NCP 0.7.1 provides configured `SafetyGovernor` and `ActionBuffer` primitives with regression coverage, while Crebain's present command adapter enforces a narrower sequence/TTL/horizon, exact vec3/unit, and ceiling contract. Raw transport publication does not automatically activate the governor or a stateful plant-side geofence/slew monitor. Rúmil should therefore target independent downstream-response invariants rather than duplicate whichever physical monitor the deployment explicitly configures.

Rúmil instead targets failures visible only after authorization or at a different abstraction:

- sign, axis, frame, unit, or coordinate-transform mismatch at an integration boundary;
- stuck, saturated, delayed, or misrouted actuation;
- motion inconsistent with the final command and calibrated vehicle envelope;
- flight-controller mode mismatch or unexpected mode transition;
- command accepted on the bus but not reflected at the plant;
- controller/plant oscillation or divergence not prohibited by per-frame bounds;
- unauthorized alternative actuator activity inferred from measured response.

#### Why it was chosen

An inline Gate protects what it publishes, not every downstream bug or physical response. Independent execution evidence is valuable for detecting actuator-path bypass, integration mistakes, and unsafe plant behavior after a formally allowed command.

Rúmil ranks seventh because its operational role is strong but its novelty and independence are hard to establish. Runtime assurance and Simplex monitors are mature areas, and current Crebain exposes pose/IMU subscriptions but no proven plant-acknowledgement contract. It must demonstrate different failure coverage rather than revive defects NCP already fixed.

#### Concrete implementation

##### 1. Specify independence explicitly

Create a dependency/common-mode table for every input and computation: clock, coordinate conversion, state estimator, parser, geometry, vehicle model, and transport. “Separate process” is not the same as independent if both monitors use the same code, state topic, GNSS source, or transform.

The initial monitor may share measured pose but use an independently implemented, simpler invariant model. Later evidence should add flight-controller acknowledgements or actuator-output telemetry and, where practical, an independent sensor path. Claims are limited to the independence actually achieved.

##### 2. Add the missing observation contracts

Define typed messages for final Gate command observation, measured pose/velocity with source and uncertainty, flight-controller mode/health, and actuator acknowledgement/output. Correlate observations through explicit session, sequence, timestamps, and bounded latency windows. Do not assume a subscriber observing a command proves the plant accepted or executed it.

Crebain should publish the action that its `CommandPlant` accepted, the actuator adapter's result, and measured vehicle state as separate events. The range then distinguishes authorization failure, delivery failure, adapter failure, and dynamics deviation.

##### 3. Implement conservative reachable-envelope checks

Begin with simple, reviewable vehicle-class invariants: bounded acceleration/turn response, sign/axis consistency, response delay, mode-specific command legality, and a reachable state interval over a short horizon with uncertainty. Calibrate parameters on benign data separate from the attack set.

The monitor reports `ExecutionAssertionV1` with state, invariant margins, correlated command/observation identifiers, freshness, uncertainty, and reason codes. It alarms first. Any ability to inhibit Gate or invoke a separate safety channel is a later safety design requiring priority, authentication, latching, recovery, and conflict-resolution semantics.

##### 4. Analyze prevention separately from detection

A monitor that only publishes an alarm is detective. If Gate consumes the assertion, enforcement delay includes observation, computation, transport, Gate policy, command TTL, and plant response. If Rúmil owns an independent emergency channel, that channel becomes safety-critical and must be protected from both spoofing and denial. The project should not call either design preventive until the closed-loop response is measured.

#### Milestones

1. Dependency/common-mode analysis and explicit non-goals.
2. Accepted-command, adapter-result, mode/health, and measured-state contracts.
3. Deterministic invariant monitor and benign calibration corpus.
4. Fault corpus for axis/unit/sign, delay, stuck actuation, mode mismatch, and unexpected motion.
5. Gazebo/MAVROS measured-state integration.
6. Optional Gate inhibit or independent reversion channel after a safety review.

#### Validation and baselines

Compare an explicitly configured NCP `SafetyGovernor`, Gate-only mission authorization, a simple command-vs-velocity residual, and Rúmil's reachable-envelope monitor. Report detection coverage, false alarms, time to detection/reversion, common-mode failures, uncertainty calibration, and mission impact.

Inject faults after each boundary: Gate output, router delivery, Crebain decode, command plant, actuator adapter, flight-controller mode, dynamics, and measured-state source. A test that mutates only the original NCP frame does not demonstrate independent execution monitoring.

#### Limitations and kill criteria

Shared state and software can create false independence. A conservative model can produce nuisance alarms, while a loose model misses attacks. Measured motion is delayed and confounded by wind, contact, saturation, and estimator error. A monitor cannot infer exact actuator behavior from pose alone.

Stop claiming independent runtime assurance if Rúmil uses the same governor logic and same state source, if it cannot observe downstream acceptance/response, or if it cannot outperform a simple residual baseline at matched false-alarm rate. Retain it as diagnostic telemetry if that is all the evidence supports.

#### Research value

The base proposal is established runtime-monitor engineering. A research contribution would require a novel independence/composition result, a demonstrably different fault-coverage model, or evidence about common-mode failures across authority and plant-response monitors.

### 8. Warden's Eye — model and scene admission with physical-attack regression

#### What it entails

Warden's Eye constrains which perception models and simulation scenes can enter an assurance-mode Crebain deployment, then continuously tests known physical and sensor attack families against the admitted configuration. It combines supply-chain integrity, loader-path closure, reproducible adversarial regression, and an assurance assertion Gate can consume.

The current admission surface is broader than a single model file. Crebain has or documents CoreML model selection, ONNX and TensorRT paths, MLX safetensors, frontend ONNX/configurable paths, filesystem scene loading, browser file import, local storage/autosave, and Gazebo model/XML spawn paths. Protecting one checksum while leaving other loaders and fallback behavior enabled is not complete admission.

An admitted model manifest includes:

- exact file or deterministic directory-tree digest;
- architecture/format, labels, task, and training/provenance references;
- input shape, color/order, resize/crop, normalization, and preprocessing;
- output schema, labels, thresholds, NMS/postprocessing, and unit/frame contract;
- runtime, execution provider, precision/quantization, and permitted fallback;
- behavior-corpus version, acceptance thresholds, and approval signature.

A scene manifest covers every asset, script/plugin, world file, material/texture, spawn parameter, and enabled import/autosave path in the selected simulator profile.

#### Why it was chosen

Perception compromise and physical adversarial effects can induce dangerous but syntactically valid controller actions. Model/scene substitution is also a practical supply-chain risk in an autonomy workbench. Gate can make an assurance status actionable by restricting autonomous modes or mission phases.

Warden's Eye ranks eighth because the impact is high but the scope is wide, the field is crowded, sim-to-real evidence is difficult, and the direct Engram/neuromorphic fit is limited. It is easy to overclaim robustness from a finite attack suite or signed model.

#### Concrete implementation

##### 1. Inventory and close loader/fallback paths

Trace every runtime and UI route that can select, download, import, cache, convert, or fall back to a model or scene. Build an executable seam inventory. In a dedicated assurance mode, choose one native perception runtime first—such as the actually deployed ONNX or CoreML path—and refuse unmanifested fallback. General multi-runtime support comes only after each path has the same admission contract.

For scenes, ensure browser imports, backend file loads, local storage/autosave, Gazebo spawn paths, and plugin/script dependencies all pass through the manifest check or are disabled in assurance mode. Test bypasses from the UI and filesystem, not only the expected backend API.

##### 2. Separate integrity from robustness

The admission service verifies digest, signature, provenance, schema, runtime/profile, and approved fallback. This proves that the selected configuration matches the approval statement. It does not prove the model is robust or benign.

The regression service runs a versioned corpus of patch, texture, occlusion, blur, lighting, weather, compression, camera calibration, dropped/corrupt frame, and sensor-fault conditions. Each scenario has a seed, placement/strength distribution, ground truth, and pre-registered metric/threshold. Results are signed and tied to the exact model, runtime, scene, corpus, and analysis version.

##### 3. Publish a narrow assurance assertion

`PerceptionAssuranceV1` reports model/scene/profile digests, admission status, last regression corpus/result, runtime health, freshness, detected drift/fallback, and reason codes. Gate uses it only for policies justified by the evidence—for example, autonomous target-following may be disabled when the runtime falls back or the admitted model changes. Passing a previous finite regression must not become a universal “safe perception” bit.

##### 4. Add physical evidence in stages

Start with deterministic synthetic regressions, then recorded real imagery, display/print attacks under controlled geometry, and only then field data. Hold out attack configurations and environments from threshold selection. Report confidence intervals and cross-condition transfer, including failures.

#### Milestones

1. Complete model/scene loader and fallback inventory with bypass tests.
2. One enforced assurance-mode runtime and deterministic model manifest.
3. Full selected scene-import closure.
4. Seeded adversarial/sensor-fault regression suite and evidence bundle.
5. Perception assertion integrated with Gate policy.
6. Recorded and controlled physical transfer study.

#### Validation and baselines

Test altered model bytes, directory member, labels, preprocessing, threshold, runtime/provider, quantization, fallback, scene asset, script/plugin, autosave, and browser import. For attacks report task accuracy, precision/recall, calibration, attack success, benign degradation, confidence intervals, transfer, and Gate mission impact.

Compare unsigned/unhashed loading, file hash only, signed complete manifest, standard augmentations, and the proposed regression/admission process. A defense method is only a separate baseline if it is actually implemented and tuned without candidate-data leakage.

#### Limitations and kill criteria

Signed models can be malicious or fragile. Known-attack regression does not cover adaptive attacks. Simulation scenes can hide real optics, printing, weather, and viewpoint effects. Fail-closed perception can itself create denial of service, and degraded mode must be physically safe.

Stop making a robustness claim if performance does not transfer to held-out physical conditions, if loader fallbacks remain outside admission, or if thresholds are set on the evaluation attacks. The result can still be a useful supply-chain control with explicitly narrower claims.

#### Research value

Model/scene admission is established engineering; adversarial perception is a mature and competitive field. Doctoral novelty would require a new defense, a significant physical-transfer result, or a valuable new dataset/benchmark tied to mission-level consequences. Otherwise Warden's Eye is a later ecosystem hardening project.

### 9. Marchwarden's Roll — tamper-evident decision evidence

#### What it entails

The Roll preserves Gate decisions and related security events so an operator or researcher can detect later alteration, replacement, reordering, or truncation within the evidence that was successfully committed and witnessed.

The first version starts with `DecisionReceiptV1` and uses:

- length-delimited, immutable local receipt segments;
- a hash chain or Merkle structure with explicit domain/version;
- a signed checkpoint for each closed segment;
- a bounded local spool with declared retention and full-disk behavior;
- asynchronous replication to an evidence collector;
- an offline verifier that reconstructs order and reports exact gaps/errors;
- an optional independent witness for checkpoint digests;
- a mutable query index that can be rebuilt from immutable segments.

The security language matters. “Tamper-evident” means detectable modification relative to preserved trust anchors. It does not mean append-only storage cannot be deleted, evidence is complete, or the result automatically satisfies legal chain-of-custody requirements.

#### Why it was chosen

Gate decisions are useful only if failures and attacks can be reconstructed, and Border-Muster requires trustworthy evidence bundles. A bounded local ledger also decouples control availability from a remote collector.

The Roll ranks ninth because it is deliverable and reusable but has no preventive authority and little novelty. Signed records, hash chains, Merkle trees, transparency logs, and witnessed checkpoints are established. Its correct place is a Gate/range module unless a new constrained-replication or completeness result emerges.

#### Concrete implementation

##### 1. Specify the evidence and threat boundary

List which events are evidence-bearing: received intent digest, decision receipt, final-command publication result, policy/admission activation, key/lease epoch transition, queue overflow, state staleness, restart, and spool/replication health. Do not log secrets, private keys, raw personal data, or unnecessary sensor payloads.

Define attacker timing. A process that can modify local storage may alter open/uncheckpointed data, delete entire unwitnessed segments, or prevent new events from being recorded. The design detects only what its signed checkpoints and external witnesses make detectable.

##### 2. Implement immutable segments and checkpoints

Use a bounded binary record format with length, version, type, payload digest/content, previous-record or segment commitment, and checksum for corruption diagnostics. Close segments on size/time boundaries, compute a Merkle root or equivalent commitment, sign a checkpoint containing sequence range and prior-checkpoint digest, fsync according to a measured durability policy, then expose it for replication.

Separate the immutable segment store from a query database. A compromised or corrupt index can be discarded and rebuilt. Verification begins from configured trusted signing keys and witnessed checkpoints, not from mutable metadata inside the same directory.

##### 3. Define overload, retention, and privacy behavior

Receipt append and signing use fixed-size queues and bounded disk. When capacity is exhausted, Gate authorization must not silently block indefinitely. The policy may alert and continue with an explicit evidence-degraded state, or expire mission authority for deployments that require complete evidence; that choice is configured and tested rather than hidden.

Retention is expressed by signed tombstone/compaction policy and checkpoint continuity. Replication is authenticated and idempotent. Key rotation records old/new key linkage and preserves verification without granting an old compromised key future authority.

##### 4. Build the verifier before the dashboard

The offline verifier checks encoding, record hashes, ordering, segment roots, checkpoint chain, signatures, key status, expected sequence coverage, and witness consistency. It emits a machine-readable report distinguishing corruption, deletion/gap, unknown key, invalid signature, unwitnessed tail, and policy-permitted retention. Visualization comes later and consumes verifier output.

#### Milestones

1. Evidence schema, threat boundary, retention, and overload policy.
2. Segment writer and offline verifier with golden fixtures.
3. Signed chained checkpoints and key rotation.
4. Bounded spool and asynchronous replication.
5. Independent witness and Border-Muster evidence-bundle integration.
6. Optional query/index/dashboard built from verified data.

#### Validation and baselines

Mutate bits, replace/reorder/duplicate records, truncate an open and closed segment, delete a whole segment, alter the index, use a wrong/old key, break checkpoint rotation, fork two histories, lose the network, fill the disk, crash during append/checkpoint, and restore from replication. The verifier must report which attacks are detectable and which produce an unavoidable unwitnessed gap.

Compare plain JSON logs, signed individual receipts, locally chained segments, and externally witnessed checkpoints. Measure append/sign latency, queue loss, disk overhead, recovery time, verifier throughput, replication lag, and detectable completeness.

#### Limitations and kill criteria

An attacker can delete the entire local store and any segment not yet externally witnessed. A compromised signing key can forge future local evidence until revocation is effective. Cryptographic consistency does not prove sensor truth, event completeness, or legal handling. Evidence collection can expose sensitive operational metadata.

Stop presenting the Roll as an independent proposal if it is only a Merkle-log implementation or a dashboard. Keep the smallest correct spool/verifier/checkpoint module inside Gate and Border-Muster.

#### Research value

The default scope is mature security engineering. Research would require a novel result about accountable evidence under intermittent connectivity, bounded storage, real-time control availability, or independently witnessed completeness. It is not a primary PhD bet.

### 10. Dwimordene v2 — unauthorized-write telemetry and isolated deception

#### What it entails

Dwimordene begins as an observability experiment, not a honeypot product. It determines whether the pinned Zenoh router can expose structured, rate-limited evidence about rejected operations without leaking operational data or weakening ACLs.

An ordinary subscriber cannot observe a write that the router denied, and it cannot see the denied payload. Router trace messages may contain router identity, subject, operation, and key, but a trace-log format is not necessarily a stable audit API. The first question is therefore empirical:

> Can one denied action produce reliable, attributable-enough, bounded telemetry through a supported interface?

If the answer is yes, Dwimordene collects and correlates denial events. If no supported interface exists, the choices are a small upstream/router patch exposing structured audit events or an entirely isolated deception realm/router with synthetic sessions. The original idea of subscribing to a protected decoy key on the operational router does not observe ACL-rejected traffic and should not be built.

#### Why it was chosen

Unauthorized writes and reconnaissance are useful indicators, and denial telemetry would help Vilya, Gate, and Border-Muster measure attacks. Deception can also reveal credential misuse without exposing real control systems.

It ranks last because the central observability assumption is unproven, it is detective rather than preventive, attribution from a certificate is limited, and a decoy can create operational risk. It should receive only a bounded spike until the router interface is demonstrated.

#### Concrete implementation

##### 1. Run the observability spike

Pin the router version and create a minimal two-role ACL. Generate one allowed and one denied publish/query per subject. Inspect supported logs/telemetry and determine whether an event exposes stable fields for router ID, authenticated subject, operation, key expression, outcome, reason, timestamp, and correlation ID.

Repeat under malformed inputs, no certificate, high rate, restart, and configuration reload. Measure event loss, ordering, CPU/memory/log amplification, and whether sensitive payload data appears. Do not parse human trace strings into a permanent security API without an explicit version pin and failure detector.

##### 2. Prefer structured denial events

If supported telemetry is sufficient, define `AuthorizationDenialEventV1`, a rate-limited collector, deduplication window, retention policy, and health signal. Treat subject identity as the presented authenticated credential, not proof of the human or uncompromised process behind it.

If a router change is necessary, keep the patch small: emit structured metadata after an authorization decision, redact payloads, bound cardinality and buffers, expose health/drop counters, and test that telemetry cannot influence the authorization result.

##### 3. Isolate any deception environment

A deception realm uses a separate router, trust anchor, synthetic vehicle/session names, no operational private keys, no route to actuators, strict egress controls, and independent monitoring. Seed only non-sensitive believable metadata. Credential use in the decoy triggers an alert but does not automatically establish attribution or compromise scope.

Do not mirror live commands, mission data, model artifacts, or production certificates. Never make an operational controller depend on the decoy's availability.

##### 4. Integrate as evidence, not authority

Border-Muster uses denial events to verify negative ACL tests and measure telemetry loss under attack. Vilya can compare observed denials to the intended authority graph. Gate may use the signal for operator awareness or rate/credential response outside the immediate command decision, but the decoy is not a trusted state source for per-frame authorization.

#### Milestones

1. Pinned-router denial observability report with one reproducible event.
2. Load, loss, privacy, restart, and format-stability tests.
3. Structured collector or explicit decision to stop.
4. Optional minimal router patch with upstreamability assessment.
5. Optional isolated deception realm and credential-use drill.

#### Validation and baselines

Test every role/verb/key combination, no-certificate traffic, malformed key expressions, event flood, repeated denial, router restart, config reload, collector outage, disk pressure, and clock issues. Verify that denial logging does not include rejected payloads or create a path to operational secrets.

Compare ordinary subscribers, router human logs, structured router events, and isolated decoy traffic. Report coverage, loss, latency, amplification, false correlation, operational overhead, and maintenance cost.

#### Limitations and kill criteria

Denial telemetry cannot see traffic that never reaches the router, and a certificate does not identify the true attacker after credential theft. Absence of decoy interaction is not evidence that no attacker exists. Deception systems can leak information or become pivot points if isolation fails.

Kill the project after the spike if the router exposes no stable supported signal, a patch would be invasive or unmaintainable, telemetry loss/amplification is unacceptable, or a realistic decoy would require operational credentials/data. A short negative feasibility report is a valid result.

#### Research value

As scoped, Dwimordene is a low-priority telemetry feature. It becomes research only with a new observable authorization interface, a rigorous deception/measurement study, or a useful dataset. It should not displace the Gate/Watchword program.

## PhD assessment

### Fable 5 maximum-effort advisor verdict

Claude Code Fable 5 was run at maximum effort as a skeptical PhD committee advisor with read access to the downloaded audit and the Haldir, NCP, Engram, Crebain, Manwë, Melkor, Galadriel, and sepahead repositories. It made no edits.

Its verdict was:

- the downloaded audit is unusually good as an engineering-sequencing document;
- the evidence-based removal of NCP 0.7.1's already-fixed defects is correct;
- moving Gate from a detached countersign to inline exclusive authority is a real design improvement;
- the numerical ranking has false precision and its prevention-heavy lenses partly bake in a Gate win;
- Gate's core pattern is established runtime assurance, reference monitoring, and PEP/PDP architecture;
- the MVP's neuromorphic rationale is decorative unless Watchword-Neuro becomes core;
- controller-artifact identity and cross-backend conformance are the strongest new research unit;
- Gate can support one rigorous systems/measurement paper and a substantial thesis chapter, but “build Gate” is not by itself a PhD.

This revision follows that advice in four ways. It exposes every raw project score and treats the order as a heuristic; separates ecosystem impact from novelty; moves Watchword-Neuro to the scientific core; and adds explicit baselines, hypotheses, negative tests, and reversal criteria.

Fable also noted that Galadriel's repository documentation describes a pre-registered study whose outcome evidence may not yet be committed. The present selection still excludes Galadriel because the user explicitly marked it complete and requested a **non-PID** project. Any remaining Galadriel experiment should stand on its own evidence and must not be counted as novelty delivered by Haldir.

### What existing work already covers

A committee is likely to compare Haldir against at least the following work. The contribution cannot be “an inline monitor for an untrusted neural controller” or “a policy check before robot actuation.”

| Prior work/building block | What it already establishes | Remaining Haldir question |
| --- | --- | --- |
| [Neural Simplex](https://arxiv.org/abs/1908.00528) and [Black-Box Simplex](https://arxiv.org/abs/2102.12981) | Runtime assurance can wrap neural/black-box controllers and switch to trusted behavior. | Can mission authority be bound to a portable controller's semantic deployment identity, with explicit lease and action-level authorization rather than only safety switching? |
| [SOTER on ROS](https://arxiv.org/abs/2008.09707) | Runtime assurance can be integrated with untrusted robotic components and multi-robot applications. | What controller identity, authorization contract, and cross-backend evidence are required for heterogeneous SNN deployments? |
| [RTron](https://arxiv.org/abs/2103.12365) | Inline ROS coordination nodes and mission-specific event-to-action rules can mitigate unsafe/malicious component interactions. | Does bundle-bound authority and a backend-independent action relation add security beyond process/topic rules? |
| [Runtime enforcement for compromised controllers](https://arxiv.org/abs/2105.10668) | A monitor can suppress or correct unsafe behavior from a compromised controller. | How do continuous mission authorization, neural deployment identity, and cyber/physical failover compose in this ecosystem? |
| [Zero Trust Policy Model for agentic CPS](https://arxiv.org/abs/2605.25653) | Typed runtime policy at a physical actuation boundary has been proposed for robot-controlling agents. | Can Haldir provide a working, measured implementation and a neural-controller-specific identity/conformance result rather than repeat the architecture? |
| [A neuromorphic safety monitor for verifiable runtime assurance](https://www.sciencedirect.com/science/article/pii/S0925231226006120) | A Simplex-family framework already models a neuromorphic anomaly monitor as a stochastic sensor and connects measured latency/error rates to a probabilistic safety bound. | Haldir must distinguish admission and mission authority for a portable neuromorphic **controller** from using neuromorphic computation inside an established safety monitor. |
| [Cedar](https://arxiv.org/abs/2403.04651) | A formally modeled authorization language and engine already exist. | Which bounded deterministic streaming predicates and state-machine semantics must surround ABAC for a 20–50 Hz controller? |
| [Neuromorphic Intermediate Representation](https://www.nature.com/articles/s41467-024-52259-9) | Portable neural graphs and cross-platform execution are established, including documented backend divergence. | Which logical and deployment fields form a security identity, and when are divergent executions authorization-equivalent at the action/plant boundary? |
| [NeuroBench](https://www.nature.com/articles/s41467-025-56739-4) | Neuromorphic algorithm/system benchmarking has a common framework. | Can a security benchmark connect artifact substitutions and backend drift to authorization and closed-loop mission outcomes? |
| [in-toto](https://www.usenix.org/conference/usenixsecurity19/presentation/torres-arias) and [RATS architecture (RFC 9334)](https://www.rfc-editor.org/rfc/rfc9334) | Supply-chain step attestation and remote-attestation roles/evidence/appraisal are established. | What neural execution identity and admission statement should these mechanisms carry? |
| [Lava repository status](https://github.com/lava-nc/lava) | Intel's public Lava repositories were archived in May 2026 pending a next-generation SDK. | Select a maintained, accessible backend after a spike; do not make Lava availability a thesis dependency. |

The architecture can still be valuable even when its pieces are known. Systems research often contributes a new abstraction, composition result, failure finding, or evaluation. Haldir must say exactly which of those it delivers.

### What is not a novel contribution

The thesis should not claim originality for:

- using mTLS certificates and ACLs to separate workloads;
- placing a policy enforcement point in front of an actuator topic;
- using Cedar/ABAC to decide principal/action/resource/context permissions;
- signing an intent or receipt with Ed25519 or COSE;
- hashing artifacts, creating an SBOM, or recording provenance;
- storing receipts in a hash chain or Merkle tree;
- wrapping a neural controller with an external safety/runtime monitor;
- running NEST in a control-loop demonstration;
- describing simulation as preparation for neuromorphic hardware.

All are legitimate engineering choices. They become research evidence only when used to support a narrower new claim.

### Plausible original contributions

#### 1. Controller-Bound Mission Authorization

Define a formal authorization relation over:

```text
(principal,
 controller logical identity,
 controller deployment identity,
 codec and timing contract,
 mission / vehicle / phase,
 trusted state snapshot,
 exact intent,
 lease and replay epoch,
 final command and reversion semantics)
```

Show which fields are necessary to prevent a defined substitution or confused-deputy attack and how the relation composes with NCP validity/safety checks.

#### 2. Semantic Deployment Identity for SNNs

Build on NIR and standard provenance/attestation roles to define a security identity that includes graph, weights, codec, timing, quantization, compilation/mapping, runtime/firmware, and validation lineage. Define identity/equivalence classes instead of pretending every approved transform must preserve bytes.

#### 3. Cross-backend action-equivalence

Define and test a relation under which two backend executions are equivalent for authorization even when their spike trains and numerical paths differ. The relation should predict policy decisions and closed-loop trajectory bounds on held-out scenarios.

#### 4. Formal cyber-to-physical failover composition

Model Gate lease, replay epoch, NCP TTL, queue overload, process crash/restart, network partition, state expiry, plant command hold, and vehicle/phase-specific reversion. Prove or exhaustively check stated safety properties inside a declared model and validate its timing assumptions experimentally.

#### 5. Reusable adversarial benchmark

Release a pinned range, threat taxonomy, scenario corpus, baselines, raw results, and verifier that connect valid-credential misuse and neural deployment substitution to final actions and plant trajectories. This is a contribution only if others can reproduce and extend it.

### Research questions and hypotheses

#### RQ1 — Authorization sufficiency

**Question:** What is the minimum external contract sufficient for mission authorization of an opaque neural controller, distinct from physical-envelope safety?

**H1:** For the pre-registered attack corpus, controller-bound mission authorization prevents every unauthorized delivered action that remains possible under NCP mTLS/ACL plus an explicitly configured `SafetyGovernor`, while staying within a pre-registered benign false-denial and mission-completion budget.

The corpus and benign budget must be fixed before candidate results are examined. “Every” refers only to enumerated attacks in the declared authority boundary, not every possible attack.

#### RQ2 — Semantic controller identity

**Question:** Which logical, codec, timing, numerical, compiler, mapping, runtime, and firmware fields are required for a security-relevant SNN deployment identity, and how should approved transformations be classified?

**H2:** In a field-ablation study whose candidate fields, security classifications, mutation corpus, and train/held-out split are fixed before candidate evaluation, every field pre-classified as security-relevant has at least one training-corpus case where omitting it hides an authorization-relevant behavioral change; the profile-complete `ControllerBundleManifestV1` plus referenced artifacts then detects held-out substitutions and classifies held-out approved transformations that whole-file hashing rejects or cannot relate.

#### RQ3 — Backend portability

**Question:** Under what relation can two backend executions be authorization-equivalent despite spike timing, quantization, and scheduling differences?

**H3:** An action/closed-loop equivalence relation, with tolerances derived from policy and plant margins before held-out evaluation, predicts Gate decisions and trajectory envelopes across NEST and a genuinely independent second backend better than spike-level equality or artifact-hash equality.

#### RQ4 — Bounded policy enforcement

**Question:** What policy fragment is expressive enough for useful mission constraints while remaining reviewable and empirically deadline-safe at 20–50 Hz?

**H4:** A split of bounded deterministic Rust predicates and Cedar ABAC sustains 50 Hz with a pre-registered p99.9 budget, no unbounded allocation/queue growth, and no missed control deadline in the declared load campaign, while expressing the selected mission policies without application code hidden inside policy.

#### RQ5 — Failure and reversion composition

**Question:** How do mission leases compose with transport loss, clock faults, restart, NCP TTL, flight-controller state, and vehicle-specific reversion?

**H5:** Under the modeled crash/partition/overload states, loss of fresh authorization reaches the declared reversion state within a formally derived bound containing detection/decision scheduling, publish/delivery delay for an explicit reversion, remaining downstream `CommandFrame.ttl_ms` and `ActionBuffer` horizon drain for the expiry path, one 20 ms Crebain tick, and measured actuator/flight-controller transition time, with no stale lease regaining authority after restart. Gate pre-registers a small deployment TTL cap rather than relying on NCP's much larger protocol maximum.

### Required formal and empirical evidence

#### Formal model

Model at least controller/Gate/router/plant states, principal and signing identities, mission/lease epochs, replay windows, final-stream ownership, NCP TTL, state freshness, policy activation, queue overflow, crash/restart, and partition. TLA+ or an equivalently explicit transition model is suitable for checking:

- no final command without a corresponding accepted intent or an explicitly modeled Gate-authored reversion;
- no stale epoch regains authority;
- at most one active downstream authority per session;
- every loss of fresh authority reaches a modeled reversion state under stated fairness/timing assumptions;
- policy/admission updates are atomic and rollback rules hold.

The model must distinguish cyber fail-closed from physical safety. “No new command” is not automatically a safe physical state.

#### Systems evaluation

Use at least one nontrivial SNN controller, two independent backends, and preferably two benign tasks or plant regimes. The current rate-decoder example is a plumbing fixture, not sufficient experimental breadth. The minimum software path is NEST → secure Zenoh → Gate → Crebain → deterministic plant/Gazebo. PX4-SITL adds integration evidence later.

The baseline set is:

1. direct NCP with mTLS/ACL;
2. NCP plus an explicitly configured `SafetyGovernor`;
3. generic Cedar/OPA-style inline PEP;
4. detached countersign sidecar from the original catalog;
5. RTron-like inline coordination where comparable;
6. SOTER/Simplex-style monitor/fallback;
7. process/certificate identity only;
8. model/package hash only;
9. signed provenance without semantic deployment identity;
10. NIR/cross-platform conformance without Gate authorization.

The attack matrix spans valid-credential wrong mission/phase/vehicle, direct-key and alternate-path bypass, signature/context/replay faults, graph/weight/codec/timestep/quantization/backend/compiler/policy substitution, stale state, clock regression, policy rollback, Gate/router/controller crash, queue overload, receipt outage, and backend semantic drift.

Report false allow/deny, policy constraint violations, mission completion, time-to-reversion, p50/p99/p99.9 latency, deadline misses, throughput/load, memory/queue bounds, receipt completeness, and paired action/trajectory divergence. Publish raw per-run results and analysis code.

#### Hardware evidence boundary

NEST plus a second software or emulated backend supports a claim about portable spiking-controller assurance. It does **not** support a claim about neuromorphic hardware security. Such a claim requires:

- named physical platform and access path;
- documented compiler/runtime/firmware/mapping measurements;
- device-root or externally trustworthy deployment evidence appropriate to the claim;
- timing, energy, numerical, and fault observations on the physical device;
- the same held-out action/trajectory conformance campaign.

If access is unavailable, publish the software result honestly as “backend-aware” or “neuromorphic-ready.” That is still useful and does not make the project unrealistic.

### Publication-sized units

#### Paper/chapter A — Gate: controller-bound mission authorization

Deliver the formal authority/failover model, minimal external contract, implementation, baseline comparison, tail-latency/resource results, and fault campaign. The contribution is the measured contract and composition, not “we put Cedar on a topic.”

#### Paper/chapter B — Watchword-Neuro: semantic SNN deployment identity

Deliver the complete bundle schema, transformation/equivalence model, substitution battery, NIR/Engram integration, and admission protocol. This is the strongest neuromorphic-security paper.

#### Paper/chapter C — cross-backend action-equivalence and benchmark

Deliver paired NEST/second-backend results, the action-equivalence relation, held-out prediction, threat taxonomy, reproducible range, and raw dataset. A physical backend strengthens it but is not silently assumed.

Together these can form a thesis spine on assurance and authorization of portable neural controllers. Gate alone is one substantial systems chapter. Vilya, the secure envelope, and the Roll are system components; Nénya can become a separate research branch if its own novelty bar is met.

## Implementation roadmap with decision gates

### Phase 0 — prove the deployment boundary

Deliver:

- actuator-authority graph for the chosen Crebain profile;
- all direct ROS/MAVROS/UI/test bypass paths disabled or explicitly constrained;
- generated five-role Vilya ACL profile;
- live positive/negative delivery matrix;
- documented vehicle/phase-specific reversion behavior;
- baseline NCP/Crebain latency and fault observations.

**Go only if** Gate can become the exclusive authority inside the declared experiment boundary. Otherwise choose an in-process Crebain ingress monitor and revise the research claim.

### Phase 1 — pure Gate and protocol core

Deliver:

- `SignedIntentV1` and `DecisionReceiptV1` specifications/vectors;
- deterministic bounded monitor plus Cedar adapter;
- lease/replay/policy state machine and formal model;
- bounded queues, rate/priority rules, local evidence spool;
- explicit-reversion tests covering atomic local close-before-publish, `last_seq + 1`, `MAX - 1`/reserved-`MAX`/overflow handling, commit/publish crash recovery, failed-publish expiry fallback, same-epoch rejection, and post-expiry fresh-lease re-anchoring;
- parser/property/fuzz tests and fixture-driven attack corpus.

**Go only if** principal/key/signature/context binding is unambiguous, state is bounded, and p99.9 cost has credible headroom for 50 Hz.

### Phase 2 — honest end-to-end vertical slice

Deliver:

- real Engram/NEST controller publishing over secure Zenoh;
- Gate on the only final NCP session command key;
- registered Crebain NCP lifecycle and standalone `CommandPlant` integration;
- deterministic plant, then Gazebo/MAVROS;
- baseline, bypass, overload, crash, partition, and time-to-reversion results.

**Go only if** the path is genuinely live and every delivered final command/equivalent reversion has a modeled origin. Do not label a local NEST-to-kinematic loop or dormant Crebain feature as this milestone.

### Phase 3 — make the fixed-weight controller profile complete

Deliver:

- profile-complete fixed-weight `ControllerBundleManifestV1` plus referenced artifacts;
- reconstruction of the controller entirely from that bundle;
- Haldir `ControllerAdmissionProfileV1`, signed `AdmissionRecordV1`, and policy integration;
- field-by-field substitution battery and benign transformation cases;
- controller more representative than independent rate populations.

**Go only if** no execution-relevant topology/codec/timing state remains hidden in arbitrary code or ambient configuration. Until then, call Gate identity/mission-bound, not artifact-bound.

### Phase 4 — cross-backend conformance

Deliver:

- NIR mapping or rigorously documented portable subset;
- maintained and accessible second independent backend;
- pre-registered action/trajectory relation and tolerances;
- paired seeded and held-out scenario results;
- published raw divergence and failure cases.

**Go only if** the relation predicts useful behavior on held-out cases. If it does not, publish the boundary/failure result and remove backend-independent authorization claims.

### Phase 5 — optional future physical evidence if access appears

Deliver only after access is real:

- named hardware, runtime/compiler/firmware mapping and measurement plan;
- trustworthy-enough deployment evidence;
- action/trajectory campaign and device timing/energy results;
- documented differences from software/emulated runs.

No physical access means no hardware assurance claim. It does not invalidate Phases 0–4.

### Phase 6 — optional ecosystem extensions

Add Nénya, stronger Vilya hardware roots, Rúmil, Warden's Eye, the Roll, or Dwimordene according to measured need. Each retains its own go/no-go criteria and cannot be counted as completed merely because Gate has an interface for its assertion.

## Final acceptance and reversal criteria

Proceed with the Haldir Gate + Watchword-Neuro program when the focused spike demonstrates all of the following:

1. every actuator path in the declared boundary is enumerated and closed or constrained;
2. the router and application layer bind an intent to the correct workload, signing key, mission/lease, and controller bundle;
3. single-stream sequence, ceiling, handoff, denial, expiry, restart, and reversion semantics are unambiguous, including an atomic local close-before-publish transition, failure fallback, and post-expiry re-anchoring after a Gate-authored reversion;
4. the live Engram → secure Zenoh → Gate → Crebain path exists;
5. authorization stays within the pre-registered 20–50 Hz tail-latency/resource budget;
6. attack and failure campaigns beat the relevant baselines without an unacceptable benign false-denial/mission penalty;
7. one complete SNN controller migrates across two independent backends under a predictive action-level relation;
8. all simulator, emulator, SITL, HIL, and physical-hardware claims remain correctly labeled.

Reverse or narrow the recommendation if complete mediation cannot be achieved, principal/artifact binding remains self-asserted, the complete controller cannot be represented, cross-backend tolerances are post-hoc or useless, safe reversion is not demonstrable, or Gate duplicates existing NCP/Simplex behavior without a new measured result.

## Final recommendation

**Yes, this is significant and worthy of being part of a PhD.** It is unusually well aligned with Crebain, NCP, and Engram because it joins typed control, real actuation integration, neural-controller generation/execution, and cybersecurity at one testable boundary.

**No, the downloaded audit does not yet establish a doctoral contribution.** Its Gate architecture is valuable but largely known; its original scoring is not reproducible; and several key premises—complete mediation, authenticated sample-to-controller binding, full artifact identity, live Crebain integration, safe failure, and backend portability—are currently open work.

The non-forced choice is therefore:

> Build Haldir Gate as the system spine, move Watchword-Neuro into the core research claim, use Border-Muster as the evidence spine, and treat Vilya, secure envelopes, and receipts as necessary supporting engineering.

If the result becomes only a Cedar proxy with a NEST demo and signed logs, it remains an impactful open-source cybersecurity project but should be one engineering chapter, not the claimed novelty of the PhD. If it establishes semantic controller identity, formal failover composition, and cross-backend action-equivalence with adversarial evidence, it can be a central and defensible thesis strand.

## Repository evidence and references

### Local ecosystem evidence

The `Paper2Brain` permalinks below require `sepahead` GitHub access; an anonymous reader may receive a 404 even though the commit-pinned paths are valid for authorized collaborators.

- [NCP security model at the inspected revision](https://github.com/sepahead/NCP/blob/e3e5da4de96e8b291b3c582bd31cf41afbfad3cc/SECURITY.md)
- [NCP known-limitations and fixed-defect ledger](https://github.com/sepahead/NCP/blob/e3e5da4de96e8b291b3c582bd31cf41afbfad3cc/KNOWN_LIMITATIONS.md)
- [NCP key structure](https://github.com/sepahead/NCP/blob/e3e5da4de96e8b291b3c582bd31cf41afbfad3cc/ncp-core/src/keys.rs)
- [NCP Zenoh transport primitives](https://github.com/sepahead/NCP/blob/e3e5da4de96e8b291b3c582bd31cf41afbfad3cc/ncp-zenoh/src/lib.rs)
- [Crebain NCP bridge handoff at the inspected revision](https://github.com/sepahead/crebain/blob/08ccafe5392465ea179406665ae936dd561aef6f/docs/NCP_BRIDGE_HANDOFF.md)
- [Crebain NCP module](https://github.com/sepahead/crebain/blob/08ccafe5392465ea179406665ae936dd561aef6f/src-tauri/src/ncp/mod.rs)
- [Engram neurocontrol session reference](https://github.com/sepahead/Paper2Brain/blob/12833c7eae49a69095001bb74bf307a86c9012b5/backend/neurocontrol/session.py)
- [Engram registered neurocontrol backends](https://github.com/sepahead/Paper2Brain/blob/12833c7eae49a69095001bb74bf307a86c9012b5/backend/neurocontrol/backends.py)
- [Engram NEST multi-UAV example](https://github.com/sepahead/Paper2Brain/blob/12833c7eae49a69095001bb74bf307a86c9012b5/backend/neurocontrol/examples/multi_uav_nest_ncp.py)
- [Engram artifact integrity store](https://github.com/sepahead/Paper2Brain/blob/12833c7eae49a69095001bb74bf307a86c9012b5/backend/api/artifact_store.py)

### Primary related work

- Xu, Zhang, and Bao, [Risk Analysis and Policy Enforcement of Function Interactions in Robot Apps (RTron)](https://arxiv.org/abs/2103.12365), 2021.
- Shivakumar et al., [SOTER on ROS: A Run-Time Assurance Framework on the Robot Operating System](https://arxiv.org/abs/2008.09707), 2020.
- Phan et al., [Neural Simplex Architecture](https://arxiv.org/abs/1908.00528), 2020.
- Mehmood et al., [The Black-Box Simplex Architecture for Runtime Assurance of Autonomous CPS](https://arxiv.org/abs/2102.12981), 2021/2022.
- [Runtime Enforcement of Programmable Logic Controllers](https://arxiv.org/abs/2105.10668), 2021.
- [When Agents Control Robots: A Zero Trust Policy Model for Agentic Cyber-Physical Systems](https://arxiv.org/abs/2605.25653), 2026.
- Kaczmarek, [A neuromorphic safety monitor for verifiable runtime assurance in stochastic control loops](https://www.sciencedirect.com/science/article/pii/S0925231226006120), Neurocomputing, 2026.
- Pedersen et al., [Neuromorphic Intermediate Representation](https://www.nature.com/articles/s41467-024-52259-9), Nature Communications, 2024.
- Yik et al., [NeuroBench](https://www.nature.com/articles/s41467-025-56739-4), Nature Communications, 2025.
- Cutler et al., [Cedar: A New Language for Expressive, Fast, Safe, and Analyzable Authorization](https://arxiv.org/abs/2403.04651), 2024.
- Torres-Arias et al., [in-toto: Providing farm-to-table guarantees for bits and bytes](https://www.usenix.org/conference/usenixsecurity19/presentation/torres-arias), USENIX Security, 2019.
- IETF, [RFC 9334: Remote ATtestation procedureS Architecture](https://www.rfc-editor.org/rfc/rfc9334), 2023.
- Intel, [Lava repository and archive notice](https://github.com/lava-nc/lava), archived 2026.
- SpiNNcloud Systems, [py-spinnaker2 documentation](https://spinnaker2.gitlab.io/py-spinnaker2/), current access/dependency information to be rechecked before selection.
