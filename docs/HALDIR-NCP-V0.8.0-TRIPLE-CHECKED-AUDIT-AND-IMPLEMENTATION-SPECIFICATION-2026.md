<!-- markdownlint-disable MD013 MD024 MD033 MD036 -->

# Haldir Gate — NCP v0.8.0 Triple-Checked Project Audit, Complete Specification, and Agent Implementation Runbook

## Backend-bound mission authorization and inline neuro-control policy enforcement for the Sepahead ecosystem

**Document date:** 2026-07-12
**Normative repository destination:** `docs/HALDIR-NCP-V0.8.0-TRIPLE-CHECKED-AUDIT-AND-IMPLEMENTATION-SPECIFICATION-2026.md`
**Document status:** normative implementation specification and research plan; not an implementation, deployment, certification, operational-readiness, or hardware-readiness claim
**Supersedes for implementation:** NCP 0.7 relay mechanics in `docs/HALDIR-DISCUSSION-DECISIONS-2026.md` and the pre-release NCP 0.8 assumptions in earlier Haldir audit drafts
**Selected project:** **Haldir Gate**, an independent inline application-authorization reference monitor that accepts signed semantic controller intent and originates every plant-facing NCP command
**Current immutable NCP baseline:** tag `v0.8.0`, commit `2f5bd586d4bb20c90362bb6f5698b7f64057ba4e`, wire `0.8`, contract hash `d1b50a2d8a265276`
**NCP release date observed:** 2026-07-12
**NCP capability increment:** increment 1: typed stream/source identity and atomic session generation; plant authority, publisher-ID binding, and applied-command/stop acknowledgements remain deferred
**Initial controller backend:** NEST through the owner's locally audited Engram checkout or a minimal isolated NEST reference adapter
**Initial plant:** deterministic Haldir reference plant, then Crebain, then PX4-SITL/Gazebo
**Safety scope:** benign navigation, inspection, tracking, hold, recovery, and simulated plant control
**Excluded scope:** target selection, weapons employment, engagement decisions, release authority, autonomous lethal action, and claims of operational suitability
**Research focus:** whether mission authorization can be bound to an admitted neural-controller deployment and remain invariant when the execution backend changes

> [!IMPORTANT]
> The NCP baseline changed on the same date as this audit. NCP `v0.8.0` is now an immutable release, not an untagged canary. Any Haldir document or implementation instruction that still says the wire-0.8 line is untagged, pins `a79e6579...`, constructs a top-level `CommandFrame.seq`, lets a controller author the final NCP stream, or reserves a maximum sequence value is obsolete.

> [!IMPORTANT]
> Gate is a **protocol and authority terminator**, not a transparent signed-frame relay. A controller signs a typed Haldir action request. Gate independently validates the controller deployment, mission lease, current NCP session, source/state evidence, and deterministic policy. Gate then constructs a new NCP `CommandFrame` with Gate-owned stream position and creation time. Controllers never receive the credential or capability that publishes the final plant command key.

> [!WARNING]
> NCP `v0.8.0` does **not** yet provide plant-issued command authority, transport-bound `publisher_id`, or normative applied-command/stop acknowledgements. The first Haldir profile therefore depends on exact mTLS principal binding, default-deny ACLs, one exclusive Gate publisher for the final command key, Crebain-owned expiry and safe action, and explicitly staged evidence. It must be labeled `PRE_AUTHORITY_ACL_ONLY`; it must not be represented as equivalent to a future NCP authority increment.

> [!WARNING]
> Current NCP prose is not internally uniform after the release. The immutable tag, executable IDL fields, generated schemas, code, conformance corpus, and release changelog establish the implemented contract. At the time of review, the root README quick-start still constructed the deleted top-level `seq`; an introductory comment in tagged `proto/ncp.proto` still called the full version string `"0.7"` even though the v0.8.0 schemas, code, tests, release, and contract hash establish wire 0.8; the wire-0.8 design record still described the line as untagged; and `NEURO_CYBERNETIC_PROTOCOL.md` was partly updated to wire 0.8 while retaining inherited wire-0.7 sequence/time/restart prose that contradicts the new typed stream/source rules. Comments and examples do not override enforced fields and conformance. The implementation agent must follow the normative-precedence rule in this document and record upstream documentation drift rather than copying stale prose.

> [!CAUTION]
> The public Engram repository currently exposes only a README saying implementation will be open sourced after publication. Earlier claims about a local Engram/NEST controller are local evidence, not public evidence. Before integration, the implementation agent must audit the owner's local checkout, identify its exact commit, reproduce the controller example, capture warnings and outputs, and verify whether the controller artifact fully identifies topology, parameters, weights, delays, codecs, and backend configuration.

## Document control and intended use

This file is deliberately both a decision record and an execution contract. Another coding agent should be able to begin with a clean Haldir checkout, inspect the current Sepahead repositories without damaging them, implement the project in reviewable phases, and produce evidence that distinguishes what was designed, compiled, tested, published, accepted, applied, and physically observed.

The document serves seven functions:

1. **Current-state audit.** It records what changed in NCP `v0.8.0`, where current consumer repositories still lag, and which public claims are contradicted by code or pins.
2. **Problem justification.** It presents primary and recent evidence that authenticated autonomous-system participants can remain harmful and that generic physical safety checks do not answer mission authorization.
3. **Architecture specification.** It fixes authority, trust, session, stream, state, safe-action, and evidence ownership.
4. **Protocol specification.** It defines stable Haldir contracts, encoding, signing, replay, restart, admission, policy, and receipt semantics.
5. **Integration specification.** It assigns explicit roles to NCP, Crebain, `crebain-native`, Engram/NEST, Galadriel, Prisoma, pid-rs, Manwe, Cortexel, Rerun, Silmaril Vision Studio, Hermes-like agents, and data/simulation repositories.
6. **Research protocol.** It defines falsifiable hypotheses and the neuromorphic reason for backend-aware admission.
7. **Agent runbook.** It lists files, APIs, tests, commands, exit gates, evidence artifacts, commit boundaries, and stop conditions.

The implementation agent MUST read the whole document before coding. It MUST execute phases in order unless a phase explicitly permits parallel work. It MUST not convert an unresolved assumption into code merely to keep moving. It MUST record unresolved facts in the source ledger and choose the safer behavior.

### Normative language and honesty vocabulary

The words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** are normative when capitalized.

The following meanings are binding:

- **implemented**: code exists at a named commit;
- **compiled**: the named target compiled under a recorded toolchain and feature set;
- **tested**: the named test command ran and its complete result is retained;
- **validated**: a preregistered acceptance criterion was evaluated against a declared evidence set;
- **published**: a local transport call returned according to its documented semantics;
- **received**: the intended receiver observed exact bytes or a digest-linked decoded object;
- **accepted**: the receiver passed its validation and selection gates;
- **applied**: Crebain or the plant adapter reported actuator-side application;
- **observed response**: independent plant state changed consistently with an applied command;
- **fail closed**: a named failure creates no new authorized plant command and does not refresh a watchdog unless the protocol explicitly requires it;
- **secure**: prohibited unless accompanied by the threat model, deployment profile, identities, routes, and evidence;
- **equivalent backend**: prohibited; use the exact tested relation, metrics, thresholds, scenario domain, and uncertainty;
- **hardware validated**: prohibited for NEST, Brian2, NIR conversion, XyloSim, mapping reports, or any software-only execution;
- **production ready**, **certified**, **airworthy**, **safe for deployment**, and similar claims are outside the initial project.

### Single-project decision

The project is one coherent system, not a catalog of ten independent security utilities:

> **Haldir Gate is an inline, backend-aware mission-authorization reference monitor. An admitted controller signs a canonical semantic intent. Gate proves that the intent is associated with the right controller deployment, mission lease, live NCP session, trusted source state, and deterministic policy state. Gate then originates the complete plant-facing NCP command under Gate's own transport identity and output stream, while Crebain remains the sole owner of final command application and vehicle-specific safe action.**

Trust-root, secure-envelope, admission, policy, and evidence functions are internal Haldir subsystems because a correct Gate cannot exist without them. They are not separate MVP services.

### Definition of done at a glance

The first defensible experimental release exists only when all of the following are evidenced at exact commits:

- the NCP dependency is the immutable `v0.8.0` tag or exact release commit, with the expected proto/schema/conformance digests;
- no controller dependency or example constructs the removed top-level NCP `seq` field;
- controller identities can publish only to their exact Haldir intent routes;
- Gate alone can publish the final NCP command route in the declared realm/session profile;
- no browser, Tauri, ROS, MAVROS, `crebain-native`, developer, replay, or alternate NCP path can apply a competing command in that profile;
- controller intent is canonical and signed, and never embeds final NCP bytes;
- Gate owns final NCP `stream.epoch`, `stream.seq`, publisher-local `t`, exact session pair, verified `source`, and `source_t` mapping;
- duplicate or retired controller intents and duplicate or retired NCP streams do not refresh plant command freshness;
- Gate restart mints a new Gate boot identity and output epoch and restores no active controller mission lease;
- deterministic native policy uses checked fixed-point arithmetic and has complete boundary tests;
- malformed, unauthenticated, stale, replayed, mission-forbidden, state-stale, backend-substituted, or policy-invalid intents create no command;
- allowed action conversion has a documented, checked, test-vector-backed relation;
- Crebain owns expiry, command selection, actuator application, and a named safe-action profile appropriate to the vehicle and mission phase;
- a Gate crash or loss of authorization causes the plant to reach the declared safe-action region within a measured bound;
- decision, output preparation, publication return, receiver receipt, acceptance, application, and observed response are separate evidence stages;
- a real NEST controller drives the deterministic plant and PX4-SITL only through Gate;
- the one-vehicle 50 Hz profile meets preregistered p50, p99, p99.9, deadline-miss, CPU, memory, queue, and recovery targets on named hardware;
- the release includes source pins, source ledger, conformance results, mTLS/ACL delivery matrix, adversarial campaign, fault campaign, SBOM, provenance, limitations, and an explicit `PRE_AUTHORITY_ACL_ONLY` compatibility label.

## Executive determination after the NCP main update

The update strengthens Haldir's foundation and removes one earlier uncertainty. It does not make Haldir redundant.

NCP `v0.8.0` now gives the ecosystem typed publisher-stream identity, typed source correlation, required control-plane `session_id`, and a server-issued session generation that must be validated atomically before side effects. These are exactly the primitives Haldir needs to avoid sequence re-anchoring and causal-order ambiguity.

The release deliberately leaves three controls for later increments:

1. plant-issued command authority;
2. transport-bound publisher identity in the wire contract;
3. applied-command and stop acknowledgements.

Haldir must not recreate those upstream features under incompatible field names. It should use a versioned compatibility profile now and adopt future NCP increments through an adapter when released.

The residual Haldir decision remains:

> May this cryptographically identified and specifically admitted controller deployment request this semantic action for this vehicle, mission, phase, policy revision, source state, and time window now?

NCP can determine that a frame is well-formed, fresh in its publisher stream, associated with a live session, and within configured generic limits. Secure Zenoh can determine that the publisher holds a permitted transport identity. Neither fact establishes mission authority for one controller artifact or backend deployment. A stolen valid identity, wrong admitted artifact, stale mission grant, unsafe backend transformation, or contextually wrong but physically bounded action can still satisfy those lower-level checks.

The resulting architecture is:

```text
mission authority          admission authority          policy authority
       |                            |                           |
       | signed lease               | signed admission          | signed policy
       +----------------------------+---------------------------+
                                    |
trusted NCP sensor/state -----------+-------------------------+
                                                              |
Engram / NEST / future backend                            Haldir Gate
  controller-owned intent stream ---- signed semantic ---->  - exact principal/key binding
  no plant credential                                      - session/source validation
  no final NCP frame                                       - mission/admission checks
                                                            - deterministic stateful policy
                                                            - Gate-owned output allocation
                                                              |
                                                              | newly authored NCP v0.8 command
                                                              | Gate stream + Gate time
                                                              | exact session + verified source
                                                              v
                                                     Crebain CommandPlant
                                                     - receiver validation
                                                     - selection/expiry
                                                     - plant-owned safe action
                                                     - accepted/applied evidence
                                                              |
                                                              v
                                               deterministic plant / PX4-SITL
```

## Triple-check method

“Triple checked” has a precise meaning here. It does not mean reading the same README three times. Every material conclusion is subjected to three independent passes.

### Pass A — source and release truth

For each relevant repository:

1. identify the canonical remote;
2. fetch branches and tags without modifying the owner's checkout;
3. record exact `HEAD`, tag object/commit, dirty state, and tracking branch;
4. inspect dependency manifests and lockfiles, not only README claims;
5. prefer immutable tags and exact commits;
6. hash normative schemas, generated artifacts, conformance vectors, and security documents;
7. run documented tests in a clean worktree or container;
8. record discrepancies between prose, code, generated artifacts, and consumers.

### Pass B — authority and data-flow reconstruction

For every component that can influence the plant:

1. enumerate identities and private-key access;
2. enumerate every publish, query, service, callback, IPC, shared-memory, ROS, MAVROS, browser, and native path;
3. trace controller input to actuator output;
4. assign ownership of session, stream, source, mission lease, admission, policy, publication, expiry, safe action, and evidence;
5. identify any capability that bypasses Gate;
6. verify restart, timeout, duplicate, delayed, and partition behavior;
7. reject any design whose mediation depends on convention rather than capability denial.

### Pass C — contradiction, falsification, and operational proof

For every security or research claim:

1. state the strongest counterexample;
2. compare against the best simpler alternative;
3. identify prior art and remove novelty claims already established elsewhere;
4. preregister a test that can disprove the claim;
5. distinguish local transport return from receiver acceptance and plant application;
6. test fail-closed behavior under crashes and resource exhaustion;
7. preserve negative results and ambiguous tails;
8. apply explicit stop criteria when the architecture cannot meet complete mediation, latency, or evidence integrity.

### Evidence precedence

When sources conflict, use this order:

1. immutable release tag and signed/tagged commit;
2. normative IDL/schema and machine-enforced compatibility rules;
3. generated schemas and frozen conformance corpus;
4. implementation code and tests at the pin;
5. reproducible executions with captured environment and logs;
6. security and design records at the pin;
7. README or website claims;
8. inference, clearly labeled.

A stale README example never overrides a field reserved in the normative proto. A green local demo never proves deployment safety. A local `put()` return never proves that an ACL-denied message was or was not delivered. An archived repository is not assumed absent from an installed system.

## Source baseline and organization-wide audit scope

### Current verified public baseline

The following public state was observed on 2026-07-12. The implementation agent MUST re-run the ledger because branch heads may advance after this document.

> [!NOTE]
> This audit initially observed GitHub-rendered pages that still showed NCP `v0.7.1`/an older `main` head. Raw immutable files and the release page then exposed the same-day `v0.8.0` release. The earlier 0.7.1 conclusion was superseded during the audit. This is why the source-precedence rule favors the immutable tag, proto, schemas, conformance corpus, and changelog over cached rendered pages. The exact observation time and URL response should be retained in `evidence/source-review/web-cache-race.md`.

| Repository | Observed public head or immutable pin | Current Haldir relevance |
| --- | --- | --- |
| `sepahead/NCP` | `v0.8.0`; `2f5bd586d4bb20c90362bb6f5698b7f64057ba4e`; contract `d1b50a2d8a265276` | normative transport/wire baseline |
| `sepahead/haldir` | `2ad8058d2665dabf22e5943d0cdf7aac6f4d1c30` | documentation-only starting point; old relay mechanics require supersession |
| `sepahead/crebain` | `08ccafe5392465ea179406665ae936dd561aef6f` | intended plant/body integration; still pins NCP `v0.7.1` |
| `sepahead/galadriel` | `b9aac83a92fdd62b7eb9fa0f9a7f2b81795acd83` | optional advisory state-quality evidence; still pins NCP `v0.7.1` |
| `sepahead/prisoma` | `64bd881248463e7142d022bb95a5850bcf8fced2` | read-only/offline evidence analysis; NCP observer still pins `v0.7.1` |
| `sepahead/pid-rs` | `70b45f7b75fac06777ea215a73df01209490311a` | offline information-theory baseline only |
| `sepahead/engram` | `a4ce6ab9897dd3f1265b4cacc53f0afc349087cd` | public repository contains no implementation; local audit mandatory |
| `sepahead/manwe` | `4e4c0a62aedb2b438f5439da3e2bc74e3f914bcd` | untrusted/advisory perception or airspace-research evidence only |
| `sepahead/crebain-native` | `6ac8798ab1a50c599a76028442ee5ab33a489fcc` | legacy/alternate direct control-path inventory; must be absent or observer-only |
| `sepahead/cortexel` | public main observed; exact pin required in Phase 0 | read-only evidence/provenance visualization |
| `sepahead/silmaril-vision-studio` | public main observed; exact pin required in Phase 0 | untrusted offline fixture and perturbation generation |
| `sepahead/melkor` | public main observed; exact pin required in Phase 0 | immutable scenario/data input only |
| `sepahead/cobot-atlas` | public main observed; exact pin required in Phase 0 | immutable scenario/data input only |
| `sepahead/relief-atlas` | public main observed; exact pin required in Phase 0 | immutable scenario/data input only |
| `sepahead/hermes-agent` | public main observed; exact pin required in Phase 0 | sandboxed research orchestration only; no control or signing capability |
| `sepahead/rerun` | public main observed; exact pin required in Phase 0 | read-only trace visualization |

The table intentionally does not pretend that every public repository is part of Haldir's trusted computing base. The Sepahead account contains many forks, experiments, assets, and unrelated projects. The implementation agent MUST enumerate the complete account, classify every repository, and deeply audit every first-party repository that can affect one of these boundaries:

- controller creation or execution;
- neural artifact representation or conversion;
- NCP contracts or transport;
- mission/admission/policy authority;
- plant command, ROS, MAVROS, simulator, or actuator paths;
- perception or trusted-state production;
- evidence generation, signing, storage, or visualization;
- scenario/model/fixture supply chain;
- tool-using agents that can modify code, configuration, or evidence.

Unrelated forks may be recorded as `OUTSIDE_RUNTIME_TCB` with a reason. They do not require a line-by-line audit merely because they exist under the same account.

### Ecosystem migration gap created by the NCP v0.8.0 release

At the reviewed heads, NCP had released v0.8.0 while Crebain, Galadriel, and Prisoma still pinned v0.7.1. That is a normal same-day consumer lag, but it invalidates any claim that the current ecosystem already runs one coherent wire. Haldir MUST not bridge the versions by accepting both shapes in one parser or by translating ambiguous top-level sequence semantics in the hot path.

Required sequence:

1. freeze the existing v0.7.1 consumer behavior and tests as migration evidence;
2. migrate Crebain first because it owns the command plant;
3. add new v0.8.0 stream/source/session validation and vectors;
4. prove no deleted `seq` assumptions remain;
5. migrate optional read-only/advisory consumers independently;
6. keep any v0.7 adapter in an isolated crate/process and label it migration-only;
7. declare ecosystem v0.8 compatibility only after every participating deployment manifest, lockfile, and live conformance test is recorded.

### Required organization inventory commands

Use a clean audit worktree and an authenticated GitHub CLI session only when needed for private owner-visible repositories. Do not place tokens in repository files or logs.

```bash
set -euo pipefail
export SEPAHEAD_OWNER="sepahead"
export SEPAHEAD_ROOT="${SEPAHEAD_ROOT:-$HOME/Development/sepahead-github}"
export HALDIR_ROOT="$SEPAHEAD_ROOT/haldir"
mkdir -p "$HALDIR_ROOT/evidence/source-review"

# Public and authenticated-owner-visible inventory. Remove private fields before
# publishing the ledger if the resulting document is public.
gh api --paginate "/users/${SEPAHEAD_OWNER}/repos?per_page=100&type=owner&sort=full_name" \
  --jq '.[] | {name,full_name,html_url,default_branch,archived,fork,private,visibility,updated_at,pushed_at,language,license:(.license.spdx_id // null)}' \
  > "$HALDIR_ROOT/evidence/source-review/public-repositories.jsonl"

gh api --paginate "/user/repos?per_page=100&affiliation=owner&sort=full_name" \
  --jq '.[] | select(.owner.login == env.SEPAHEAD_OWNER) | {name,full_name,html_url,default_branch,archived,fork,private,visibility,updated_at,pushed_at,language,license:(.license.spdx_id // null)}' \
  > "$HALDIR_ROOT/evidence/source-review/owner-visible-repositories.private.jsonl"

chmod 600 "$HALDIR_ROOT/evidence/source-review/owner-visible-repositories.private.jsonl"
```

Create `evidence/source-review/repository-classification.csv` with at least:

```text
repository,exact_head,default_branch,archived,fork,visibility,first_party,
controller_relevance,transport_relevance,plant_relevance,state_relevance,
evidence_relevance,supply_chain_relevance,agentic_tool_relevance,
tcb_class,audit_depth,justification,reviewer,review_date
```

Allowed `tcb_class` values:

- `GATE_RUNTIME_TCB`;
- `PLANT_TCB`;
- `AUTHORITY_TCB`;
- `CONTROLLER_UNTRUSTED_PRODUCER`;
- `TRUSTED_STATE_PRODUCER`;
- `ADVISORY_EVIDENCE_PRODUCER`;
- `OFFLINE_RESEARCH_TOOL`;
- `READ_ONLY_VISUALIZER`;
- `UNTRUSTED_FIXTURE_SOURCE`;
- `LEGACY_BYPASS_RISK`;
- `OUTSIDE_RUNTIME_TCB`;
- `UNRESOLVED`.

No repository may remain `UNRESOLVED` at the first integration release gate.

### Safe local checkout procedure

Never update a dirty owner checkout in place.

```bash
set -euo pipefail
repo="$SEPAHEAD_ROOT/NCP"
git -C "$repo" status --short --branch
git -C "$repo" fetch --all --tags --prune
mkdir -p "$SEPAHEAD_ROOT/.worktrees"

git -C "$repo" worktree add --detach \
  "$SEPAHEAD_ROOT/.worktrees/NCP-v0.8.0-audit" \
  2f5bd586d4bb20c90362bb6f5698b7f64057ba4e

cd "$SEPAHEAD_ROOT/.worktrees/NCP-v0.8.0-audit"
test "$(git rev-parse HEAD)" = "2f5bd586d4bb20c90362bb6f5698b7f64057ba4e"
git status --porcelain=v1 | test ! -s /dev/stdin
```

Record for every repository:

- canonical remote URL;
- local path;
- exact 40-character SHA;
- branch and upstream;
- tags pointing at the commit;
- dirty and untracked state;
- submodules;
- Git LFS pointers;
- toolchain files;
- dependency manifests and lockfiles;
- documented build/test commands;
- executed command, exit status, duration, and complete log digest;
- relevant source path and line range;
- whether each fact is public, private/local, inferred, contradicted, or unresolved.

## NCP v0.8.0 audit

### Immutable release facts

The release notes state that NCP `v0.8.0`:

- uses wire 0.8 and contract hash `d1b50a2d8a265276`;
- deletes the overloaded top-level `seq` in favor of typed `stream` and `source` positions;
- requires `session_id` on the control plane;
- adds a server-issued session generation validated atomically before any side effect;
- closes the stream/source/session finding identified as F-01;
- is increment 1 of the wire-0.8 line;
- defers authority F-02, `publisher_id` binding, and applied-command/stop acknowledgements;
- reports the release gate green and freezes a `conformance/baseline/v0.8.0` corpus.

The implementation agent MUST verify these facts against the immutable tag, not merely `main`:

```bash
cd "$SEPAHEAD_ROOT/.worktrees/NCP-v0.8.0-audit"

git verify-tag v0.8.0 || {
  # An unsigned tag is not automatically invalid, but the absence of a verified
  # signature must be recorded rather than hidden.
  git cat-file -p v0.8.0
}

git rev-list -n 1 v0.8.0
sha256sum proto/ncp.proto schemas/*.json > /tmp/ncp-v080-schema-sha256.txt
find conformance -type f -print0 | sort -z | xargs -0 sha256sum \
  > /tmp/ncp-v080-conformance-sha256.txt
scripts/check.sh 2>&1 | tee /tmp/ncp-v080-check.log
```

### Normative wire semantics Haldir must implement exactly

#### Publisher stream

Every data-producing publisher owns its own `StreamPosition`:

```text
stream = { epoch, seq }
```

For final plant commands, the publisher is Gate. Therefore:

- Gate mints the output epoch;
- Gate starts sequence at one for a new logical stream;
- Gate increments for every new logical command frame;
- a transport retry of the exact same logical command may reuse the exact same bytes and position;
- a different command never reuses a position;
- a controller's intent sequence is not copied into NCP output sequence;
- source sequence is not copied into output sequence;
- sequence numbers do not authorize epoch changes;
- a retired epoch is never reactivated by a very large sequence number.

#### Causal source

`source` identifies the upstream frame that directly caused the current output. It is not a loss counter and not proof that every intervening source frame was processed.

Gate MUST obtain the final source position from its independently received and validated trusted-state cache. A controller may name a source reference it claims to have used, but Gate treats that as a lookup and consistency claim. Gate does not copy unverified source fields into the plant command.

#### Session identity

The effective session identity is the atomic pair:

```text
(session_id, session.generation)
```

Gate and Crebain MUST reject a wrong or stale pair before freshness, policy side effects, state updates, watchdog refresh, output allocation, or plant application. Neither component may repair a missing or inconsistent field from a route, local default, or currently open session.

#### Time

NCP `t` is the current publisher's local monotonic creation time. Therefore final command `t` belongs to Gate. The source publisher's time belongs in `source_t` when the compatibility profile carries it. Wall-clock UTC may appear in evidence metadata, but it is not used for hot-path validity without an explicitly modeled synchronized-time protocol.

#### Receiver stream state

The receiver's stream state must include, at minimum, current session generation, authenticated publisher/route identity, concrete key, and message kind. Haldir MUST not weaken upstream scoping by keeping one global `last_seq`.

Duplicate or stale frames MUST NOT refresh the plant watchdog. A newly observed random epoch MUST NOT displace a live accepted stream merely because its sequence is higher.

### What NCP v0.8.0 still does not give Haldir

| Deferred capability | Immediate Haldir consequence | Future migration |
| --- | --- | --- |
| plant authority F-02 | mTLS and exact ACL make Gate the exclusive final-key publisher; only one Gate output authority exists in the MVP | adopt a Crebain-issued NCP authority lease through the adapter and bind it to Gate/session/key/epoch |
| wire `publisher_id` binding | transport principal and route policy are deployment evidence, not a wire-carried publisher claim | validate future publisher identity against authenticated principal and Gate registration |
| applied-command/stop acknowledgements | Gate receipts end at publication unless Crebain emits separately signed acceptance/application evidence | map Haldir provisional evidence to normative NCP acknowledgements without claiming old events are equivalent |
| standardized safe-action profile | Crebain owns a versioned vehicle/phase-specific safe-action profile outside the NCP command frame | migrate only after upstream semantics match and retain evidence continuity |

### NCP documentation contradiction ledger

The implementation agent MUST open an upstream issue or documentation pull request for each confirmed discrepancy, but Haldir development must not wait for prose cleanup when the immutable contract is unambiguous.

| Location observed on current `main` | Contradiction | Required Haldir treatment |
| --- | --- | --- |
| root `README.md` quick-start and ecosystem text | the quick-start constructs deleted top-level `seq`; the ecosystem text implies coordinated v0.8.0 consumer repins that had not occurred at the reviewed consumer heads | do not copy examples or consumer claims without compiling against the tag and inspecting each manifest/lockfile; build types from proto/schema/examples/tests at `v0.8.0` |
| introductory comment in tagged `proto/ncp.proto` | one descriptive comment still names the full `ncp_version` string as `"0.7"`, while the tagged release, enforced schema/constants, implementation, tests, and contract identity are v0.8.0 | treat executable IDL fields and enforced artifacts as normative; record and upstream-fix the stale comment; never infer a compatibility version from prose alone |
| `docs/wire-0.8-stream-identity.md` | describes the line as untagged and discusses a future tag | preserve as design history, but annotate that `v0.8.0` now exists |
| `NEURO_CYBERNETIC_PROTOCOL.md` | correctly announces released wire 0.8 and points to the typed identity design, but inherited sections still say closed-loop `seq` is top-level, command/observation `t` echoes sensor time, and lower sequence re-anchors after expiry | use it only for unaffected background; implement stream/source/session/time/restart semantics from the tagged proto, schemas, changelog, conformance corpus, and typed-identity record |
| `CHANGELOG.md` footer | comparison link may still start at `v0.7.1` instead of exposing a `v0.8.0` link | release body and tag remain authoritative; file an upstream documentation correction |

Create `evidence/source-review/ncp-documentation-drift.md` with:

- exact NCP commit;
- path and line range;
- stale statement;
- normative conflicting source;
- security or migration impact;
- proposed upstream correction;
- issue/PR URL if created;
- resolution status.

### NCP adapter rule

Only `haldir-ncp08` may import NCP types. Stable Haldir contracts must contain semantic Haldir fields, not generated NCP structs. The adapter's compatibility identity MUST include:

```text
ncp_tag                 = v0.8.0
ncp_commit              = 2f5bd586d4bb20c90362bb6f5698b7f64057ba4e
wire_version            = 0.8
contract_hash           = d1b50a2d8a265276
proto_sha256            = <measured>
schema_set_sha256       = <measured canonical manifest digest>
conformance_set_sha256  = <measured canonical manifest digest>
haldir_adapter_version  = <semver>
haldir_adapter_commit   = <commit>
capability_profile      = PRE_AUTHORITY_ACL_ONLY
```

A dependency bump requires semantic review, corpus replay, mapping-vector replay, and a security sign-off. It is not a routine Renovate-style patch.

## Current consumer and sibling-repository audit

### Crebain

#### Verified current facts

At the reviewed `crebain` head:

- the optional NCP feature still pins `ncp-core` and `ncp-zenoh` to `v0.7.1`;
- the NCP feature is off by default;
- `NcpBridge`, validated feature-neuron RPCs, and a fail-closed 50 Hz `CommandPlant` exist as library APIs;
- Tauri commands are defined but the handle is not managed and the commands are not registered;
- TypeScript NCP glue is imported by no product component;
- the live Crebain–Engram loop is explicitly unimplemented;
- the validated plant callback is not wired to MAVROS by default;
- the normal product contains other ROS/Zenoh/browser/UI and control surfaces that can become alternate plant paths.

#### First-principles conclusion

Crebain is the correct plant owner, but it is not currently a deployed Gate-mediated NCP body. Haldir must not claim that an existing 50 Hz library test proves complete mediation or live PX4 integration.

Crebain must own:

- final command receiver validation;
- command selection and expiry;
- actuator callback execution;
- vehicle/mission-phase safe-action behavior;
- receiver acceptance evidence;
- application evidence;
- observed plant response evidence;
- exclusion of competing action loops.

Haldir must own:

- controller admission and mission authorization;
- semantic request policy;
- Gate output stream and publication;
- decision evidence;
- transport principal/key enforcement for the final route.

#### Required migration sequence

1. Create a dedicated Crebain branch from a clean reviewed head.
2. Migrate all four NCP pins together: Rust manifest, Rust lockfile, JavaScript manifest, JavaScript lockfile.
3. Compile default Crebain unchanged and optional NCP features against `v0.8.0`.
4. Replace every legacy top-level sequence assumption with typed stream/source/session semantics.
5. Add exact session-pair checks before side effects.
6. Add accepted/selected/applied evidence identifiers linked to Haldir `decision_id` and exact NCP frame digest.
7. Introduce one explicit Gate-only command profile and route.
8. Register and manage the optional NCP lifecycle only behind an explicit deployment opt-in.
9. Wire first to the deterministic reference actuator, not MAVROS.
10. Prove stop, close, reconnect, session reopen, duplicate, stale epoch, callback panic, and evidence failure behavior.
11. Inventory and disable or isolate every competing path.
12. Connect PX4-SITL only after the reference plant campaign passes.

### `crebain-native`

Archival status is not a security control. The repository documents ROS/Zenoh data paths, control commands, MAVROS-oriented state and services, and hardware/simulator integration. Installed binaries, old launch files, containers, user credentials, or services may remain live even if the repository is no longer preferred.

The deployment agent MUST prove one of these conditions:

- `crebain-native` is absent from the host and image;
- it runs under an observer-only identity with no command, ROS publication, MAVROS service, or plant callback capability;
- it runs in a physically isolated range with no route to the assured plant;
- it is separately mediated by an equivalent authority boundary, explicitly outside the first Haldir claim.

“Archived on GitHub” is never accepted as evidence of absence.

### Galadriel

Galadriel provides fail-closed cross-sensor statistical-consistency monitoring and optional PID/NCP integration. Its current manifest still pins NCP `v0.7.1`. Its own scientific boundary matters: consistency is not truth, a coordinated or consistency-preserving attack can evade a cross-sensor consistency check, and attribution or PID analysis is not plant authorization.

Haldir integration is advisory:

- consume a signed/digested bounded `AdvisoryEvidenceRefV1`;
- qualify the exact sensors, estimator/configuration, calibration set, time window, and confidence semantics;
- use the evidence for denial, degradation, or policy tightening only after calibration;
- do not let Galadriel directly publish plant commands or issue mission leases;
- do not make its absence a hidden fail-open condition;
- preserve raw state-quality evidence for offline evaluation.

Galadriel is not required for the MVP security claim.

### Prisoma

Prisoma's NCP observer remains pinned to `v0.7.1` at the reviewed head and is explicitly read-only/off the critical path. It is useful for offline information decomposition, run-log analysis, and research comparison. It must not influence hot-path ALLOW decisions in the MVP.

Required boundary:

- consume exported immutable evidence bundles after or asynchronously alongside a run;
- no NCP PUT or ROS/MAVROS credentials;
- no mission/admission/policy signing keys;
- no ability to mutate Gate state;
- label estimator assumptions, sample support, bias, and uncertainty;
- distinguish a scientific statistic from cryptographic authenticity.

### pid-rs

`pid-rs` is a scientific information-theory library, not a runtime access-control or authenticity system. Hashes in run logs identify bytes; they do not authenticate who generated them. Haldir may use pid-rs for offline baselines and exploratory dependence analysis only.

A PID-derived result cannot become a runtime policy prerequisite until:

- estimator validity and sample requirements are preregistered;
- calibration and abstention behavior are measured;
- a bounded deterministic runtime implementation exists;
- its false-allow and false-deny effects are tested;
- an independent policy path can deny safely when the estimator fails.

No such dependency is required for the selected non-PID Gate project.

### Engram and NEST

The public Engram repository provides no inspectable implementation. The owner's local checkout may contain a real NEST backend and controller example, but another agent must regenerate the evidence.

Before writing a Haldir adapter, create `evidence/engram-local-audit/` and record:

1. exact local repository SHA, branch, remotes, dirty state, and untracked files;
2. Python, NEST, compiler, OS, and package versions;
3. backend registry and every implemented/proposed backend;
4. controller artifact schema and whether it represents graph topology, neuron/synapse models, parameters, weights, delays, initialization, codecs, and timestep;
5. command used to run the multi-UAV example;
6. complete stdout/stderr, including NEST cleanup warnings;
7. trajectory and convergence metrics for every vehicle;
8. random seeds and determinism behavior;
9. shutdown/restart behavior;
10. the narrowest process boundary at which semantic Haldir intent can be emitted.

NEST remains the first backend because it is already used locally and yields the shortest path to an honest end-to-end slice. The owner's prior feasibility evidence used NEST 3.9; preserve that exact environment as a historical reproducibility baseline. The current public stable release is NEST 3.10 (June 2026), which makes PyNEST the primary interface, removes the intermediary SLI layer, and supports `pip install nest-simulator`. Therefore the implementation agent MUST run two separate campaigns: first reproduce the exact NEST 3.9 result without silently upgrading it; then port and compare under a pinned NEST 3.10 environment. Record API changes, warnings, controller actions, timing, determinism, and plant trajectories. Haldir must not claim arbitrary paper-to-controller generation unless the artifact path is proven profile-complete.

Primary NEST sources: <https://www.nest-simulator.org/> and <https://nest-simulator.readthedocs.io/en/v3.10/whats_new/v3.10/index.html>.

### Manwe

Manwe is treated as an untrusted or qualified perception producer, not a command authority. Any output entering the Haldir decision context must pass through the same trusted-state qualification path as other perception:

- exact model/configuration digest;
- source and transport identity;
- coordinate-frame and unit contract;
- timestamp/source position;
- uncertainty/calibration semantics;
- bounded parser and payload size;
- replay and stale-state checks;
- explicit policy describing whether the evidence can only deny, can tighten limits, or can support an allow.

### Cortexel and Rerun

Both are read-only evidence visualization consumers. They receive exported, signature-verified, digest-linked traces and no command capabilities. Viewer convenience must not create a control backchannel.

The viewer profile MUST deny:

- NCP PUT/queryable control rights;
- ROS/MAVROS publication and service calls;
- access to Gate, mission, admission, or policy private keys;
- mutation of evidence bundles;
- invoking an unreviewed script against a live plant.

### Silmaril Vision Studio, Melkor, cobot-atlas, and relief-atlas

These projects may supply scenarios, imagery, models, or synthetic fixtures. They are untrusted inputs to an offline range. Every fixture must enter through an immutable manifest containing:

- source repository and exact commit;
- file digest and size;
- license and redistribution constraints;
- generation command and random seed where applicable;
- expected parser/profile;
- known synthetic/real status;
- intended test and prohibited interpretations.

No fixture may carry executable hooks or a privileged path into the Gate runtime.

### Hermes-like agent

A domain-specific Hermes agent may accelerate computational-neuroscience research, source inspection, test generation, and experiment orchestration. It is explicitly outside the authority boundary.

The agent MAY:

- inspect read-only source snapshots;
- propose patches, controller manifests, policies, scenarios, or reports;
- run tests and simulations in a bounded sandbox;
- collect and summarize public scientific evidence;
- create unsigned candidate artifacts.

The agent MUST NOT:

- possess controller production signing keys;
- possess mission, admission, policy, Gate, NCP, Crebain, ROS, MAVROS, or plant credentials;
- sign an admission or mission lease;
- publish to live intent or command routes;
- update a live policy;
- alter retained evidence after signing;
- have unrestricted network or host access;
- approve its own patch or experimental conclusion.

Record model/version, system prompt or configuration digest, tool invocations, source snapshot, generated artifact digest, reviewer, and final human-controlled commit whenever agent output affects research evidence.

## Deep research evidence: Haldir addresses a real and justified problem

### Claim being tested

The project is justified only if all four propositions hold:

1. a real autonomous-system threat remains after transport authentication and topic ACLs;
2. generic message validity and physical bounds do not fully address that threat;
3. inline mission authorization can reduce the residual risk without replacing plant safety;
4. the proposed neuromorphic extension addresses a real translation/admission problem rather than adding novelty theater.

The evidence below supports those propositions while also defining the limits of the claim.

### Evidence tier 1 — NCP itself deliberately leaves an application-authorization boundary

NCP's security model says the default/open transport is unauthenticated until secure transport is configured, a realm is routing rather than identity, and local command governance is defense in depth rather than sender authentication. NCP ships secure deployment assets, but those assets answer transport identity and route permission. NCP `v0.8.0` further strengthens freshness and session fencing, yet its release notes explicitly defer plant authority and publisher-ID binding.

This creates a clear separation:

```text
transport authentication: who owns this transport credential?
ACL: may that principal publish to this route?
wire validation: is the message structurally and temporally valid?
generic governor: is the action within configured platform bounds?
Haldir: may this admitted controller deployment request this action in this mission context now?
plant safety: can the vehicle safely select/apply/fallback from the command?
```

The layers are complementary. Haldir is not justified by claiming NCP is weak; it is justified because NCP intentionally does not encode project-specific mission authority for every controller and plant.

**Primary evidence:** NCP `v0.8.0` release and security model: <https://github.com/sepahead/NCP/releases/tag/v0.8.0> and <https://github.com/sepahead/NCP/blob/v0.8.0/SECURITY.md>.

### Evidence tier 2 — valid robotics credentials can be used for harmful semantic actions

The 2025 MILCOM proof-of-concept on Secure ROS 2 demonstrates a concrete failure mode relevant to Haldir. A compromised package exfiltrated SROS 2 keystore material. Possession of valid credentials allowed the attacker to rejoin as an authenticated participant and publish spoofed control or perception messages without authentication failures. The reported effects included forced braking, sustained acceleration, continuous turning, phantom stop signs, and suppressed detections.

This is not evidence that every SROS 2 or Zenoh deployment is vulnerable in the same way. It is evidence for the narrower principle:

> Valid identity and route permission do not prove that the resulting action is appropriate for the current mission or controller deployment.

Haldir's direct response is to require more than possession of a transport key:

- a controller-specific application signature;
- a backend-specific admission record;
- a challenge- and boot-bound mission lease;
- current policy and session identity;
- trusted source correlation;
- semantic policy evaluation before final command publication.

The design cannot prevent damage when the Gate host, mission authority, or plant TCB is fully compromised. It reduces the impact of a compromised controller process, controller credential, wrong controller artifact, stale grant, or unauthorized direct route within the declared deployment boundary.

**Primary evidence and limitation:** Sakib et al., *Supply Chain Exploitation of Secure ROS 2 Systems*, <https://arxiv.org/abs/2511.00140>. It is a 2025 proof-of-concept on SROS 2/DDS and one autonomous-vehicle testbed, not a direct exploit of NCP, Zenoh, Crebain, or Haldir. Haldir derives the general valid-credential residual, not universal exploitability.

### Evidence tier 3 — zero trust distinguishes authentication from authorization

NIST SP 800-207 states that no implicit trust should be granted merely because of network location or ownership and that subject/device authentication and authorization are discrete functions. Haldir applies the same resource-centered principle to a plant command capability.

The protected resource is not the Zenoh realm or process. It is:

```text
the right to create a specific plant-affecting command under a live mission,
for an admitted controller deployment, against current trusted state
```

A one-time authenticated session is insufficient. Authorization is re-evaluated per intent against changing mission phase, lease validity, state freshness, policy revision, controller admission, and plant session.

**Primary evidence:** NIST SP 800-207, *Zero Trust Architecture*, <https://csrc.nist.gov/pubs/sp/800/207/final>. NIST does not prescribe Haldir's protocol; it supports the narrower separation of authentication, authorization, and resource-specific policy.

### Evidence tier 4 — continual assurance is a recognized defense-autonomy need

DARPA's Assured Autonomy program identifies the difficulty of deploying learning-enabled cyber-physical systems in safety-critical defense applications, emphasizing that data-driven components can be unpredictable and lack the guarantees expected for mission success. Its goal of design-time plus operation-time assurance maps directly to Haldir's split:

- backend/controller admission supplies bounded design-time evidence;
- Gate supplies operation-time authorization and monitoring;
- Crebain supplies plant-side safety and application evidence.

Haldir does not claim to solve learning-enabled system assurance generally. It supplies a concrete enforceable seam where design-time controller evidence is bound to a live mission decision.

**Primary evidence:** DARPA Assured Autonomy, <https://www.darpa.mil/research/programs/assured-autonomy>. This establishes defense relevance and the design-time/operation-time assurance need; it does not validate Haldir's architecture.

### Evidence tier 5 — platform-safe commands can still be mission-wrong

Recent mission-level runtime-assurance research reports that a platform-level monitor may accept a command that remains within immediate driving-safety constraints while skipping required checkpoints, entering a restricted region, or exhausting the remaining mission budget. The proposed monitor checks a candidate before execution against both platform and mission feasibility.

The paper is recent preprint evidence rather than an established standard, and its driving domain is not identical to Crebain UAV control. Its value is conceptual and testable: local physical safety is not identical to mission admissibility.

Haldir therefore models mission phase and mission constraints explicitly rather than treating speed/geofence limits as the full authorization decision. Examples include:

- a velocity vector is within speed bounds but moves before launch authorization;
- a position setpoint is inside the global geofence but enters a mission-specific exclusion region;
- a hold release is physically bounded but issued after the controller's mission lease expired;
- an inspection path is safe but belongs to another vehicle assignment;
- a command is numerically valid but based on stale source state;
- a recovery command is safe in cruise but invalid during landing or maintenance mode.

**Primary evidence and limitation:** Tsai and Hariri, *Mission-Level Runtime Assurance Framework for Autonomous Driving*, <https://arxiv.org/abs/2606.06996>. This is a June 2026 preprint in autonomous driving, not a UAV standard or independent replication; it supplies a concrete counterexample class and an experimental baseline to reproduce, not proof that Haldir succeeds.

### Evidence tier 6 — semantic attacks can remain small and context-aware

USENIX Security 2025 work on automated discovery of semantic attacks in multi-robot navigation shows that small false-data injections can cause position deviation or collisions and can be optimized to remain stealthy relative to sensor noise and spatiotemporal consistency. This supports two Haldir conclusions:

1. the sensor/state plane is part of the control threat model;
2. syntactic validity and simple anomaly thresholds do not establish semantic safety.

Haldir does not attempt to solve arbitrary sensor deception. It requires trusted-state provenance, source freshness, uncertainty, and explicit policy over the evidence used to authorize an action. Galadriel may add advisory consistency evidence, but a consistency monitor cannot make untrusted state true.

**Primary evidence:** Yeke et al., *Automated Discovery of Semantic Attacks in Multi-Robot Navigation Systems*, USENIX Security 2025, <https://www.usenix.org/conference/usenixsecurity25/presentation/yeke>. The work includes simulation, high-fidelity simulation, and Crazyflie experiments; Haldir uses it to justify source/state threat modeling, not to claim general sensor-attack prevention.

### Evidence tier 7 — runtime assurance around neural controllers is established prior art

Simplex, Black-Box Simplex, and Neural Simplex demonstrate that runtime monitoring, safety checks, and fallback around unverified or neural controllers are established research areas. This is important because it prevents an inflated novelty claim.

Haldir's novelty is **not**:

- placing a monitor after a neural controller;
- switching to a safe controller;
- checking a reachability or safety condition;
- signing commands;
- using mTLS or ACLs;
- assigning sequence numbers;
- recording an audit log.

The candidate contribution is the composition and evidence model:

1. backend-specific controller admission;
2. mission-specific delegated intent authority;
3. NCP v0.8 session/stream/source fencing;
4. exclusive Gate-owned plant publication;
5. deterministic mission-context policy;
6. separation of decision, publication, acceptance, application, and observed response;
7. measured authorization relation across NEST and a genuinely different backend.

A paper or project claim must compare against Simplex-style baselines and explain why mission delegation, backend identity, NCP stream ownership, and evidence staging are not reducible to the baseline.

**Primary prior art:** Black-Box Simplex <https://arxiv.org/abs/2102.12981>, Neural Simplex <https://arxiv.org/abs/1908.00528>, SOTER <https://arxiv.org/abs/1808.07921>, and RTron <https://arxiv.org/abs/2103.12365>. Their existence is a novelty constraint, not a reason to omit runtime assurance.

### Evidence tier 8 — backend translation can change the behavior being authorized

Neuromorphic portability is a real systems problem. NIR exists because the ecosystem spans heterogeneous software and hardware representations. Interchange support does not guarantee identical behavior. Backend translation may change:

- neuron and synapse equations;
- discretization and solver behavior;
- timestep and scheduling;
- weight/delay precision;
- rounding, clipping, and quantization;
- reset and initialization;
- graph transformations;
- partitioning, placement, fan-in/fan-out constraints;
- input/output codecs;
- available state and timing semantics.

Rockpool documentation makes quantization and hardware-constrained graph mapping explicit. SpiNNaker2 provides a Brian2-oriented path but some hardware-linked dependencies remain restricted. The original Lava repository was archived in May 2026, making it a poor new foundational dependency unless a maintained successor is identified and independently justified.

The Haldir security question is not whether two backends generate identical spikes. It is:

> Does the deployed backend remain within the behavioral relation and safety/mission assumptions under which this controller was admitted?

Haldir addresses this by binding admission to:

- canonical logical controller artifact;
- controller I/O codec;
- backend/compiler/mapping profile;
- transformation and quantization report;
- exact software/firmware/bitstream digests where available;
- scenario corpus and seeds;
- measured action and trajectory relation;
- deadline, reset, saturation, and perturbation behavior;
- explicit evidence level: software reference, independent simulator, hardware-constrained simulation, emulator, or physical silicon.

NIR is an interchange representation, not an equivalence certificate. XyloSim or Brian2 emulation is not hardware validation. A package hash without backend behavior evidence is insufficient for cross-backend authority.

**Primary evidence:** the NIR paper explicitly notes heterogeneous-stack variability and platform-dependent divergence (<https://www.nature.com/articles/s41467-024-52259-9>); Rockpool documents explicit graph conversion, design-rule checks, resource mapping, and integer quantization (<https://rockpool.ai/advanced/graph_mapping.html> and <https://rockpool.ai/devices/quick-xylo/deploy_to_xylo.html>); SpiNNaker2 documents a Brian2 path while some dependencies remain access-restricted (<https://spinnaker2.gitlab.io/py-spinnaker2/>); and the original Lava repository is archived (<https://github.com/lava-nc/lava>).

### Evidence-to-requirement traceability matrix

This matrix prevents research citations from becoming decoration. Every source must produce a bounded requirement and a test; every source also carries a stated non-claim.

| Evidence | Verified observation | What it does **not** prove | Haldir requirement derived | Falsification or acceptance test |
| --- | --- | --- | --- | --- |
| NCP `v0.8.0` release, proto, conformance baseline | stream/source/session identity is stable for increment 1; authority, wire publisher identity, and apply/stop acknowledgements are deferred | that a deployed realm is authenticated, authorized, or mission-safe | pin immutable v0.8.0; Gate owns command stream/time; use `PRE_AUTHORITY_ACL_ONLY`; never invent deferred fields | compile/conformance at exact tag; reject deleted `seq`; session/key/source adversarial vectors |
| NCP `SECURITY.md` | open/default transport is unauthenticated; realm is routing; mTLS plus ACL must be deployed; local governor is not authentication | that NCP's supplied templates were successfully deployed in Crebain | minimum trust-root work is inside Gate MVP; prove exact identities and receiver-observed delivery | full principal×route×verb matrix; controller final-key write has no Crebain receipt; Gate write does |
| Crebain bridge handoff | a 50 Hz fail-closed library plant exists; product registration, live loop, and MAVROS callback are not enabled | a live Engram→Crebain product integration or safe flight behavior | explicit lifecycle registration, sole callback, receiver/application evidence, plant-specific safe action | clean-build feature tests, deterministic plant campaign, then SITL; no competing callback |
| Secure ROS 2 credential-exfiltration POC | an authenticated participant with stolen valid credentials can inject harmful control/perception semantics | direct exploitability of NCP/Zenoh or proof that application signing alone stops compromise | separate transport identity from application admission/mission authority; minimize controller capabilities | stolen transport credential, stolen signing key, wrong-artifact, and stale-lease tests produce no output |
| NIST SP 800-207 | authentication and authorization are distinct and resource/action policy is continuously evaluated | a Haldir-specific standard or certification | per-intent authorization bound to subject, resource, action, context, and current state | mutate each binding independently; every mismatch denies before output allocation |
| DARPA Assured Autonomy | defense autonomy needs design-time and operation-time assurance for learning-enabled CPS | that this particular policy or neural controller is assured | separate backend admission evidence from inline runtime authorization | admission-only vs Gate-only vs composed baseline; report residual failures |
| Mission-level runtime-assurance preprint | platform-safe actions can remain mission-infeasible in tested driving scenarios | general UAV validity, peer-reviewed consensus, or Haldir effectiveness | mission phase, assignment, exclusion region, and remaining-budget constraints are first-class policy inputs | physically bounded but mission-wrong scenario corpus; compare against NCP governor-only baseline |
| USENIX semantic multi-robot attacks | small, context-aware FDI can cause deviation/collision while preserving stealth constraints in tested systems | that Haldir detects arbitrary sensor deception | source provenance/freshness/uncertainty are explicit; state trust remains a separate boundary | stale, wrong-source, inconsistent, and degraded-state tests; document attacks that still pass |
| Simplex/Neural Simplex/SOTER/RTron | runtime monitors and fallback around complex/neural controllers are prior art | mission delegation, artifact identity, or NCP mediation as solved problems | compare against a Simplex-style safety baseline and keep novelty claim narrow | ablation: Simplex alone, Gate alone, admission alone, composed system |
| NIR paper and documentation | portable primitives bridge many stacks, but implementations can diverge and support subsets | semantic equivalence or profile completeness | canonical restricted controller profile plus importer/exporter and behavioral evidence | graph round-trip, unsupported-feature rejection, held-out behavior comparison |
| Rockpool/Xylo mapping documentation | target mapping performs explicit conversion, DRC, resource assignment, and quantization | actual silicon behavior from XyloSim alone | retain mapping/DRC/quantization receipts and label hardware-constrained simulation separately | mutate mapping/quantization; admission must detect or measured relation must fail |
| SpiNNaker2 documentation | Brian2 emulation is available; some hardware-linked dependencies are restricted | reproducible hardware access or hardware validation | optional later profile only; bind dependency/access state and evidence level | clean public install/emulation proof before adoption; silicon results kept separate |
| Lava archive notice | original Lava repository is read-only and Intel no longer guarantees maintenance | that all Lava forks/successors are unsuitable | do not make archived Lava the default second-backend foundation | candidate matrix must identify maintained owner, security policy, releases, and reproducibility |
| NEST 3.10 release | NEST 3.10 is current; PyNEST is primary and the SLI intermediary was removed | that the owner's NEST 3.9 controller is unchanged under 3.10 | preserve exact 3.9 reproduction and add an explicit 3.10 migration/compatibility campaign | paired 3.9/3.10 controller traces, timing, cleanup, and held-out plant results |
| Galadriel results/limitations | statistical consistency evidence can alert or abstain heavily and is not truth | permission to veto or authorize control | advisory/digest-linked evidence only; policy must name any deny-only calibrated profile | disconnect, missingness, false-alert, stale-evidence, and malicious-sidecar tests |
| Prisoma and pid-rs caveats | useful offline analysis exists, with estimator/support limitations and non-authenticating hashes | runtime authorization or evidence authenticity | read-only exports; external signatures/provenance; no runtime Gate dependency | remove tools and show control unaffected; tampered trace fails signature/digest verification |

### Minimum justification decision rule

Do not build Haldir merely because the architecture is interesting. Proceed with the full Gate project only when this predicate is evidenced:

```text
complete_mediation_feasible
AND exclusive_gate_final_publication_feasible
AND crebain_expiry_and_safe_action_measurable
AND staged_application_evidence_feasible
AND realtime_budget_feasible
AND (
      dynamic_mission_delegation_needed
   OR multiple_or_replaceable_controllers_exist
   OR controller_artifact_identity_matters
   OR controller_compromise_is_in_scope
   OR mission_context_exceeds_generic_governor
   OR backend_transformation_is_part_of_the_program
)
```

If the left-hand conjuncts fail, stop and repair the plant/transport architecture first. If every right-hand reason is false—one static fully trusted controller, no changing mission authority, no backend translation, no alternate route, and no application-level compromise threat—then a separate Gate is probably unjustified. Use NCP mTLS/ACL, NCP/Crebain safety, and a smaller audited plant integration instead.

### Negative case: what Haldir must never claim

Haldir does not establish that a neural controller is scientifically faithful, optimal, non-adversarial, or globally safe. It does not authenticate untrusted sensors merely by hashing them. It does not make a generic zero command a universally safe state. It does not turn NEST, NIR, Brian2, XyloSim, or another software path into neuromorphic-hardware evidence. It does not replace PX4 failsafes, flight-test discipline, platform safety, human authorization, or future NCP plant authority. Its defensible claim is narrower: within a declared complete-mediation profile, it prevents an unauthorized controller intent from becoming a new plant-facing command and produces evidence about each stage it can actually observe.

### Concrete residual threat cases

The project must demonstrate at least these real residual cases:

| Case | Lower-layer checks that may pass | Required Haldir result |
| --- | --- | --- |
| stolen controller transport credential | mTLS identity and ACL route permission | deny because application signature/admission/lease binding is missing or wrong |
| stolen controller signing key but wrong artifact | valid application signature | deny because execution/admission measurement or bundle identity does not match |
| expired mission assignment | valid identity, valid frame, bounded velocity | deny because lease validity or term is stale |
| wrong mission phase | valid lease and bounded command | deny because action/phase transition is not permitted |
| stale source state | structurally valid source reference | deny because source age, epoch, sequence, or state freshness fails |
| replayed old intent | valid signature and old lease | deny without output allocation or watchdog refresh |
| direct final-key bypass | valid or invalid controller payload | transport/ACL denial; no Crebain receipt or application |
| backend substitution | same high-level controller name | deny because backend execution profile/admission differs |
| quantized backend drift | admitted logical artifact but changed mapping | deny admission or fail equivalence threshold before mission lease issuance |
| Gate crash after local publish return | publication may be ambiguous | no false `applied` claim; Crebain expiry/safe action still works |
| physically bounded mission violation | governor accepts numeric bounds | Haldir mission policy denies |
| coordinated state deception | syntax and simple consistency may pass | no universal solve; limit claim, qualify state, test degraded/deny policy |

### Alternative solutions and why they are insufficient alone

#### “Use NCP mTLS and ACLs only”

Necessary but insufficient. They restrict route access and identify a credential holder. They do not bind an admitted neural artifact, mission lease, mission phase, source state, or backend execution profile. The Secure ROS 2 credential-compromise result directly demonstrates the valid-credential residual.

#### “Use the NCP SafetyGovernor only”

Necessary plant defense in depth. Generic speed, geofence, TTL, mode, and freshness checks do not represent every mission assignment or controller-specific permission. Haldir must not duplicate the governor; it adds the mission/application decision.

#### “Put every policy inside Crebain”

Technically possible for one plant, but weaker as an ecosystem design. It couples controller admission and mission-policy semantics to the vehicle application, enlarges Crebain's trusted logic, and makes reuse across plants/controllers harder. The chosen split keeps Crebain responsible for plant safety and Haldir responsible for controller/mission authority. A monolithic Crebain baseline should still be implemented or modeled as a comparison.

#### “Sign final NCP commands at the controller”

Incorrect under NCP v0.8 ownership semantics. It lets the controller claim Gate's publisher stream, time, session binding, and future plant authority. A signature proves origin of bytes, not authorization of their semantic action.

#### “Use Simplex or a fallback controller”

Complementary. Simplex focuses on runtime safety and controller switching. Haldir adds mission delegation, controller/backend admission, exclusive NCP publication, and evidence across multiple authority domains. Crebain may still implement a baseline/fallback controller or safe-action profile.

#### “Certify the controller offline and skip inline mediation”

Offline evidence cannot account for stale/revoked mission leases, wrong live sessions, stale state, replay, runtime backend substitution, controller/process compromise, or direct route misuse. Admission is necessary but not sufficient.

#### “Wait for neuromorphic hardware”

Unnecessary and harmful to evidence quality. The authority problem exists in the current NEST-to-SITL path. The Gate interface should be stabilized against NEST first, then tested against an independent backend, then hardware-constrained simulation, then optional physical hardware. Hardware access should not define the MVP.

#### “Use Lava as the second backend”

Not as the default foundation. The original repository is archived. A maintained successor or fork could be evaluated, but the second backend must be selected through a capability, maintenance, licensing, determinism, timing, and artifact-completeness matrix. NIR-compatible Norse/snnTorch or a bounded Rockpool profile may be better candidates; Rockpool/XyloSim is especially relevant for exposing hardware constraints.

### Problem-justification decision

Haldir passes the justification test under a bounded claim:

- **real threat:** valid credentials and valid messages can still be harmful;
- **real systems gap:** current NCP consumer deployments do not yet provide mission-specific application authorization or complete mediation;
- **useful preventive control:** Gate denies before final command publication;
- **Crebain fit:** Crebain already has an optional 50 Hz command plant but lacks live product integration and exclusive mediation;
- **NCP fit:** v0.8.0 supplies the correct stream/source/session semantics for Gate-owned output;
- **Engram/NEST fit:** a real controller can emit semantic intent without owning plant transport authority;
- **neuromorphic reason:** backend transformation can alter behavior assumed by admission;
- **research novelty boundary:** the contribution is backend-bound mission authority and staged evidence, not generic runtime assurance;
- **falsifiability:** complete mediation, latency, false decisions, backend relation, restart, and application evidence can all fail measurable tests.

The project should stop or narrow its claims if any of these occurs:

- Gate cannot be made the exclusive final publisher;
- Crebain cannot expose reliable expiry and application evidence;
- controller execution identity cannot be measured beyond a self-asserted string;
- backend admission performs no better than a bundle hash in held-out scenarios;
- p99.9 Gate latency or queueing exceeds the command deadline;
- safe action is undefined or cannot be demonstrated;
- evidence cannot distinguish unknown publication/application tails;
- the second backend comparison cannot be specified without changing the controller contract in backend-specific ways.

## Twenty-lens independent audit summary

The project was re-evaluated through twenty distinct questions. Scores are not a substitute for the implementation gates; they show where the design is strong and where evidence is still missing.

| Lens | Question | Current assessment | Required proof |
| --- | --- | --- | --- |
| 1. consequence | Can failure affect a real plant or mission? | high | closed-loop reference plant and SITL |
| 2. empirical gap | Is there present evidence of a gap? | high | NCP boundary, current pins, Secure ROS 2 attack |
| 3. prevention | Does control act before harm? | high | no output on deny; bypass tests |
| 4. complete mediation | Is every plant path covered? | unresolved/high risk | route/process/credential matrix |
| 5. identity | Is the acting entity more than a label? | medium | key roles, measured deployment identity |
| 6. mission authority | Is permission specific and revocable? | design strong | challenge-bound lease tests |
| 7. protocol semantics | Are ordering/session/source meanings sound? | strong with v0.8.0 | upstream corpus + mapping vectors |
| 8. timing | Are deadlines and clocks explicit? | design strong | measured p99.9 and restart tests |
| 9. failure safety | Does crash/partition lead to a named safe state? | unresolved until plant proof | fault campaign |
| 10. evidence integrity | Can decision be separated from application? | design strong | signed staged evidence and crash tails |
| 11. Crebain fit | Does it use an actual product seam? | medium | registered NCP lifecycle and sole plant owner |
| 12. Engram fit | Can a real neural controller drive it? | locally plausible, publicly unverified | exact local audit and NEST run |
| 13. backend invariance | Does Gate remain unchanged across backends? | strong architectural fit | second-backend demonstration |
| 14. neuromorphic justification | Is hardware/backend work causally relevant? | yes for admission | measured translation/quantization effects |
| 15. scientific honesty | Are simulation and hardware claims separated? | strong if rules followed | evidence-level labels |
| 16. novelty | Is the claim beyond prior runtime assurance? | bounded | Simplex baselines and contribution ablation |
| 17. feasibility | Can a useful MVP be built without hardware? | high | NEST → Gate → reference plant/SITL |
| 18. ecosystem reuse | Can other controllers/plants use it? | high by contract | adapter boundaries and second plant/controller fixture |
| 19. maintainability | Can NCP evolution be isolated? | high by design | one versioned adapter and semantic-diff gate |
| 20. falsifiability | Can the central claims be disproved? | high | preregistered kill criteria and negative results |

## Re-baselined implementation decision

The project proceeds with four release profiles:

| Profile | Controller | Plant | NCP capability | Claim |
| --- | --- | --- | --- | --- |
| P0 | deterministic reference controller | deterministic reference plant | local semantic adapter model | contract/state/policy correctness only |
| P1 | isolated NEST controller | deterministic plant | NCP `v0.8.0`, mTLS/ACL exclusive Gate publisher | experimental complete-mediation slice; `PRE_AUTHORITY_ACL_ONLY` |
| P2 | isolated NEST controller | Crebain + PX4-SITL | same NCP profile | measured end-to-end simulated plant authorization |
| P3 | NEST plus independent admitted backend | deterministic plant and SITL | same Gate contract | backend-aware admission research result |

Future NCP authority/publisher/acknowledgement increments create P4. Physical neuromorphic hardware is a separate P5 evidence level and is not a prerequisite for useful Haldir delivery.

## Master execution sequence for the implementation agent

This sequence is the shortest authoritative route through the larger phase manual. It does not waive any later exit gate.

### A. Establish a clean and reviewable starting point

1. Open the owner checkout of `haldir` and record `git status --short --branch`, `git rev-parse HEAD`, remotes, tags, submodules, and untracked files.
2. Do not edit that checkout if it is dirty. Fetch and create a separate branch/worktree from the reviewed commit.
3. Create `docs/HALDIR-NCP-V0.8.0-TRIPLE-CHECKED-AUDIT-AND-IMPLEMENTATION-SPECIFICATION-2026.md` from this artifact in the clean worktree.
4. Add a short supersession notice to `docs/HALDIR-DISCUSSION-DECISIONS-2026.md`; do not delete the historical analysis.
5. Create `evidence/source-review/`, `evidence/commands/`, `evidence/logs/`, and `evidence/manifests/` with a README explaining that generated evidence is retained by digest and large artifacts may live in release storage rather than Git.
6. Create the organization-wide repository inventory and classification described above.
7. For every relevant repository, fetch without merging and create an exact-commit audit worktree.
8. Record the public baseline and any owner-private/local evidence separately. Never publish private paths, tokens, private repository names, or confidential logs by accident.
9. Verify the NCP `v0.8.0` tag resolves to `2f5bd586d4bb20c90362bb6f5698b7f64057ba4e` and record whether the tag has a verifiable signature.
10. Run the NCP release's documented full check and retain the complete log, exit status, duration, environment, and artifact manifest.
11. Hash `proto/ncp.proto`, every generated schema, and the frozen v0.8.0 conformance corpus using a canonical sorted manifest.
12. Open a Haldir issue for every material source contradiction or unresolved fact. Label each `blocking`, `nonblocking`, or `claim-limiting`.

### B. Correct the design before creating runtime code

13. Write `docs/ARCHITECTURE.md` with the exact controller-intent → Gate → NCP-command → Crebain flow.
14. Write `docs/AUTHORITY-MODEL.md` naming admission, mission, policy, session, Gate publication, plant application, and evidence authorities.
15. Write `docs/ASSURANCE-PROFILES.md` defining P0 through P3 and the `PRE_AUTHORITY_ACL_ONLY` limitation.
16. Write `docs/NCP-COMPATIBILITY.md` with the tag, commit, contract hash, schema/corpus digests, deferred features, and documentation drift ledger.
17. Write `docs/THREAT-MODEL.md` with assets, adversaries, assumptions, excluded threats, and the complete-mediation proof obligation.
18. Write `docs/CLAIMS-AND-EVIDENCE.md` mapping every planned claim to a test and stop condition.
19. Review these documents against the NCP proto and current Crebain code. Reject any field or flow that gives a controller final NCP stream ownership.
20. Freeze the first action profile to a small typed set: `Hold`, `VelocityLocalNed`, and, only if needed, a bounded `PositionLocalNed` profile. Do not begin with arbitrary named channel maps.

### C. Scaffold a pure, version-isolated implementation

21. Create the Rust workspace and stable crates in the repository layout specified later in this document.
22. Set one exact Rust toolchain and record it. Use workspace-wide lints, `unsafe_code = "forbid"` where feasible, and deny warnings in CI after the initial scaffold is clean.
23. Keep `haldir-contracts`, `haldir-state`, and `haldir-policy-native` free of Zenoh, NCP generated types, async runtimes, and filesystem side effects.
24. Keep all NCP imports in `haldir-ncp08`.
25. Keep all transport-specific code in `haldir-transport-zenoh`.
26. Keep controller integration outside the Gate binary; controllers communicate only through the intent contract.
27. Add a Python package only for test-vector generation, NEST reference-controller integration, and research analysis. Do not reimplement authorization logic independently in Python.
28. Add CI jobs for formatting, lint, tests, docs, contract vectors, dependency policy, and a minimal no-network deterministic range.

### D. Implement contracts and hostile parsers first

29. Define canonical scalar wrappers for IDs, digests, epochs, sequence numbers, monotonic durations, fixed-point quantities, route names, and bounded text.
30. Implement canonical CBOR validation before signature verification. Reject duplicate keys, indefinite lengths, nonminimal integers, invalid UTF-8, unknown mandatory fields, trailing bytes, and oversize collections.
31. Define COSE signing profiles with explicit protected headers, algorithm, key ID, content type, and message-type domain separation.
32. Define `GateChallengeV1`, `MissionLeaseV1`, `AuthorityRevocationV1`, `HaldirIntentV1`, admission/manifests, policies, decision receipts, application evidence, and status/fault contracts.
33. Generate positive and negative golden vectors from an independent fixture generator.
34. Require Rust to decode, validate, re-encode canonically, and match every positive digest.
35. Require Rust to reject every negative vector with a stable reason class.
36. Add property tests for canonical round trips, limits, integer edges, and signature-byte binding.
37. Add fuzz targets before exposing network ingress.

### E. Implement trust and authority snapshots

38. Define key roles so no key can sign more than one authority domain by default.
39. Implement exact route/principal/controller binding; do not “try every trusted key” until one verifies.
40. Implement a signed Gate boot challenge with a fresh boot identifier and expiration.
41. Implement mission leases bound to Gate boot, controller identity, admission, mission, vehicle, action scope, policy revision or accepted policy set, and validity window.
42. Implement explicit revocation with monotonically increasing terms or revisions and durable rollback protection.
43. Build immutable trust snapshots loaded atomically by the decision pipeline.
44. Test key rotation, overlapping validation windows, revoked old keys, wrong-role keys, wrong Gate boot, wrong vehicle, and policy mismatch.

### F. Implement independent state machines and formal checks

45. Implement Gate boot, NCP session, controller intent stream, Gate output stream, mission lease, admission, policy, trusted-state cache, safe-transition, and evidence-spool state independently.
46. Persist only what is necessary for anti-rollback, retired identities, and evidence integrity. Do not restore an active mission lease after restart.
47. Model the state machines in TLA+ or an equivalent executable formal model before networking.
48. Check invariants for no output on deny, no position reuse for different bytes, no old lease after restart, no stale session side effect, no retired epoch reactivation, and exact Gate-only publication.
49. Add crash points before and after every durable write and publication boundary.
50. Convert every counterexample into a deterministic regression test.

### G. Implement the deterministic policy core

51. Use checked fixed-point arithmetic for all policy-relevant quantities.
52. Define coordinate frames, units, conversion scaling, saturation policy, and representability before implementing bounds.
53. Implement channel and mode allowlists.
54. Implement state/source freshness and uncertainty inflation.
55. Implement component, norm, acceleration, slew, horizon, prospective region, and geofence checks.
56. Implement mission-phase transitions and action-specific permissions.
57. Implement duty-cycle and continuous-motion windows using bounded state.
58. Return typed ALLOW/DENY with stable reason codes and derived bounded action; do not allocate output sequence in the policy function.
59. Add exhaustive boundary, overflow, monotonicity, metamorphic, and state-transition tests.
60. Add Cedar only as a separately measured coarse ABAC layer. Any Cedar diagnostic or adapter error denies. Remove Cedar from P1 if it adds unacceptable latency or semantic ambiguity.

### H. Build the deterministic reference plant and evidence chain

61. Implement a simple kinematic plant with deterministic simulation time and explicit command horizon.
62. Give the plant separate ingress, accepted, selected, applied, and measured-response events.
63. Implement a named safe-action profile and measurable safe region.
64. Support delay, duplicate, reorder, loss, callback stall, process restart, session restart, and clock-fault injection.
65. Link every event by decision ID, exact command digest, stream/source/session identity, and plant tick.
66. Implement a tamper-evident bounded journal without claiming that a hash chain alone provides availability or external authenticity.
67. Define crash-tail states as `unknown` or `ambiguous` when the evidence cannot establish the next stage.
68. Prove that publication return is never automatically labeled `received`, `accepted`, or `applied`.

### I. Implement the immutable NCP v0.8.0 adapter

69. Depend on the immutable tag and lock the exact commit. Fail CI if the resolved source differs.
70. Import and run upstream v0.8.0 conformance and behavior vectors.
71. Parse trusted state using the actual received route and exact atomic session pair.
72. Store source position, source time, receive time, provenance, and qualified state in a bounded cache.
73. Build commands only from a fully approved `GateCommandBuildInputV1`.
74. Allocate Gate output position after every decision and evidence prerequisite succeeds.
75. Set Gate-local monotonic `t` and independently verified source/source time.
76. Serialize once, compute the digest, validate the exact bytes, and make them immutable.
77. Reuse exact bytes/position only for a documented transport retry of the same logical output.
78. Implement no private authority, publisher-ID, or ACK extension fields.
79. Expose the compatibility label `PRE_AUTHORITY_ACL_ONLY` in status and evidence.
80. Add differential tests against NCP reference encoding/decoding where supported.

### J. Implement the Gate runtime with one side-effect boundary

81. Build bounded ingress queues with priority for revocation, session/authority/fault changes, normal intents, and evidence export.
82. Apply cheap route and size admission before expensive parsing or signature checks.
83. Take one atomic authority/policy/state snapshot for each decision.
84. Evaluate stages in the exact order specified later in this document.
85. Allocate no NCP output on malformed, unauthenticated, stale, replayed, forbidden, or policy-denied intent.
86. Journal the signed decision before or atomically with output preparation according to the selected crash-consistency design.
87. Publish the immutable exact bytes once; record the transport return without upgrading the evidence stage.
88. Keep the control path independent of remote evidence collectors and visualizers.
89. Bound every queue, cache, tombstone set, spool, parser, and diagnostic field.
90. Latch a fault when a configured safety-critical local resource is exhausted; do not silently evict authority or replay safety state.

### K. Prove secure transport and complete mediation

91. Create separate identities for controller, Gate, Crebain, observer, lifecycle/session authority, mission authority, admission authority, and policy authority.
92. Issue least-privilege certificates and route policies.
93. Prove every principal × operation × route cell using both publisher-side result and receiver-side observation.
94. Verify that the controller can publish only its own intent route.
95. Verify that only Gate can publish the final command route.
96. Verify that observers cannot publish.
97. Verify that authorities cannot publish plant commands merely because they sign leases or admissions.
98. Inventory processes, launch files, containers, credentials, ROS topics, MAVROS services, Tauri/browser commands, native callbacks, and developer tools.
99. Remove, disable, or observer-confine every bypass before calling P1 complete.
100. Repeat the matrix after certificate rotation, reconnect, router restart, and session reopen.

### L. Integrate Crebain in controlled increments

101. Move all Crebain NCP pins and locks to `v0.8.0` in one dedicated migration change.
102. Keep the default non-NCP product build green.
103. Update the optional adapter to typed stream/source/session semantics.
104. Add receiver event evidence linked to Haldir decision and exact command digest.
105. Register the NCP lifecycle only in an explicit Gate profile.
106. Wire first to the deterministic reference actuator.
107. Prove command expiry and named safe action with Gate loss.
108. Prove no competing product or legacy action loop is active.
109. Connect to PX4-SITL only after all deterministic acceptance cases pass.
110. Treat `crebain-native` as a separately evidenced bypass risk, not as part of the intended command chain.

### M. Integrate the real NEST controller

111. Complete the local Engram audit and freeze the exact controller artifact and environment.
112. Define a narrow state-input and semantic-action contract.
113. Run NEST in an isolated process without Gate or final NCP credentials.
114. Bind every intent to current Gate challenge, mission lease, admission, session, source claim, controller intent stream, and semantic action.
115. Sign the canonical intent under a controller-role key.
116. Publish only to the exact controller intent route.
117. Demonstrate target convergence and safe denial/recovery through the deterministic plant.
118. Repeat against Crebain/PX4-SITL after P1/P2 gates.
119. Preserve NEST warnings and shutdown behavior in evidence; do not relabel feasibility as readiness.

### N. Implement backend-aware admission only after the vertical slice

120. Define a profile-complete portable controller subset.
121. Freeze the logical artifact, codecs, state initialization, timestep, parameters, weights, delays, and allowed transformations.
122. Select a second backend by a documented capability/maintenance matrix, not by novelty alone.
123. Prefer an independently implemented software path first; use NIR only for supported constructs.
124. Produce a backend compilation receipt containing exact source and output digests, tool versions, transformations, quantization, mapping, and warnings.
125. Preregister action, trajectory, safety-margin, deadline, reset, saturation, and perturbation metrics.
126. Split scenarios and seeds into development and held-out sets before final thresholds are examined.
127. Run artifact and mapping mutations to test whether admission detects meaningful substitutions.
128. Issue a backend-specific admission only when thresholds pass.
129. Prove the same Gate binary and `HaldirIntentV1` contract work with both backends.
130. Label Rockpool/XyloSim or Brian2 results as hardware-constrained simulation or emulation, not physical hardware.

### O. Run adversarial, performance, and release gates

131. Execute the complete attack matrix: direct bypass, wrong route, wrong key role, stale/revoked lease, wrong boot, wrong session, replay, delayed retired epoch, stale source, malformed intent, overflow, backend substitution, and evidence outage.
132. Inject Gate crashes at every pipeline boundary.
133. Inject Crebain stalls and verify safe-action timing.
134. Measure p50/p99/p99.9 decision and end-to-end latency with raw histograms.
135. Measure deadline misses, queue depth, memory, CPU, spool growth, false decisions, and availability.
136. Compare against NCP+ACL+governor, package-hash admission, and an appropriate Simplex/runtime-assurance baseline.
137. Retain failed scenarios and negative results.
138. Generate SBOM, build provenance, source/evidence manifests, and limitations.
139. Require independent review of authority, parser/crypto, state machines, complete mediation, Crebain safe action, and research claims.
140. Commit and push normally to a new branch. Never force-push, move tags, rewrite shared history, or merge while mandatory evidence is red.

## Independent integration decision

The surrounding ecosystem does not justify a large all-project runtime. It justifies a small Haldir trusted core with typed, mostly offline seams:

```text
                       admission authority
                    bundle/backend evidence
                              |
mission authority ------ signed lease
                              |
trusted NCP state ------------+----------------------+
                                                     |
Engram/NEST/future backend -- signed semantic intent v
                                              Haldir Gate
                                      deterministic authorization
                                      Gate-owned NCP publication
                                                     |
                                                     v
                                            Crebain CommandPlant
                                                     |
                                             reference plant/SITL

Galadriel -------- advisory evidence ---------> receipts/policy input (not MVP ALLOW)
Prisoma/pid-rs --- verified offline traces ----> research only
Cortexel/Rerun -- verified receipt views ------> read-only UI
crebain-native --- absent or observer-only ------> no plant publication
Manwe ----------- qualified perception --------> Crebain state boundary
Silmaril/assets -- immutable range fixtures ----> offline scenarios only
NIR/Rockpool ---- offline admission evidence --> admission authority
```

The core security claim remains useful without PID, Galadriel, a second neural backend, or physical hardware. Those additions extend evidence and research value after the basic reference-monitor claim is demonstrated.

## What NCP v0.8.0 changes for Haldir

### The legacy conflation that must not return

NCP 0.7 used a top-level sequence in ways that mixed a publisher's delivery order with causal source correlation. A decimating controller could legitimately act on selected sensor frames, yet the downstream sequence model made delivery loss and source selection difficult to distinguish. Haldir's earlier relay design inherited that ambiguity by allowing the controller to author the final frame and downstream sequence.

NCP `v0.8.0` removes the overloaded field and introduces typed stream/source identity. Haldir MUST preserve that separation all the way through the Gate.

### Current typed identities

`StreamPosition` contains an equality-only epoch and a sequence that begins at one and increases for each new logical frame. A fresh logical stream or publisher restart mints a fresh epoch. Epoch values are identifiers, not counters; a larger epoch is not newer. Retired epochs cannot be revived by presenting a very large sequence number.

The effective session identity is the inseparable pair `(session_id, session.generation)`. A receiver validates both before any side effect and never repairs a missing or conflicting field from the route or current local session.

For a closed-loop active command in NCP `v0.8.0`, the final NCP frame carries or derives the current contract's:

- exact `session_id`;
- server-issued session `generation`;
- current publisher's `stream` position;
- direct causal `source` position;
- current publisher's local monotonic creation time `t`;
- source time in `source_t` when present;
- mode, TTL, channels, and provenance fields required by the contract.

Plant authority, wire `publisher_id`, and normative apply/stop acknowledgements are not present in increment 1 and MUST NOT be fabricated as private NCP extension fields.

### Direct design consequences

The controller cannot author the final NCP frame without claiming fields that semantically belong to Gate:

- Gate is the final publisher, so Gate assigns `stream.epoch` and `stream.seq`.
- Gate creates the output, so Gate assigns final `t`.
- Gate is attached to the live plant session, so Gate validates and inserts the exact session pair.
- Gate independently validates causal state before inserting `source` and `source_t`.
- secure transport and ACLs bind the current pre-authority deployment to Gate as the exclusive final-route publisher.
- a future NCP plant-authority lease belongs to Gate, not the controller.

Consequently, `HaldirIntentV1` carries a typed **requested action**, not an embedded NCP `CommandFrame`.

### Current and future compatibility profiles

| NCP profile | Upstream capability | Haldir behavior |
| --- | --- | --- |
| legacy regression only | NCP `v0.7.1` | use only to prove migration tests; do not build new Haldir semantics around it |
| `PRE_AUTHORITY_ACL_ONLY` | NCP `v0.8.0` increment 1 | Gate owns output stream; exact mTLS/ACL makes one Gate the final publisher; session/source/stream rules are enforced; evidence remains staged and Crebain-owned |
| future authority profile | plant-issued authority term/lease | Crebain grants Gate authority bound to session, principal, route, kind, and permitted output epoch; stale authority has no freshness side effect |
| future publisher profile | transport-bound publisher identity | validate publisher identity against authenticated Gate principal and registration; retain controller application signatures for controller attribution |
| future acknowledgement profile | applied-command/stop acknowledgements | map Haldir provisional receiver/application evidence to normative messages only after semantic review |

Stable Haldir public contracts MUST NOT expose NCP generated structs. `haldir-ncp08` converts stable semantic Haldir types into the exact immutable `v0.8.0` contract. Any later NCP version is a new compatibility profile and must pass a semantic-diff and corpus-replay gate.

### Audit map for `HALDIR-DISCUSSION-DECISIONS-2026.md`

The current decision record remains valuable as a historical and project-selection record. The following implementation statements need explicit supersession:

| Existing section | Keep | Replace or qualify |
| --- | --- | --- |
| Purpose, ranking, repository independence, research boundary | Keep | Add a notice that wire mechanics are superseded by this companion plan. |
| NCP evidence based on 0.7.1 | Keep only as historical migration evidence | Replace the implementation baseline with immutable NCP `v0.8.0`; record that authority, publisher identity, and apply/stop acknowledgements remain deferred. |
| Intended flow: `SignedIntentV1(exact NCP CommandFrame bytes)` | No | Replace with `HaldirIntentV1(typed semantic action + source and admission bindings)`. |
| Principal binding | Mostly keep | Bind controller signature to the Haldir intent and admission, not to exact final NCP bytes. |
| Signed intent fields | Partly keep | Remove final NCP frame bytes and controller-authored final sequence/time/authority. Add Gate boot challenge, controller intent stream, source watermarks, semantic command, and policy-relevant digests. |
| Downstream sequence ownership | No | Gate always owns downstream stream position from the first version. Remove reserved maximum sequence and byte-preserving mode. |
| Policy split | Keep with change | Native deterministic Rust policy first; Cedar is optional coarse ABAC after the native core is measured and stable. |
| Denial and reversion | Keep the warning that denial is not instantaneous | Reversion is the next Gate-authored output in Gate's stream or a standardized stop, never a reserved sequence. Plant safe action is Crebain/profile-owned. |
| Decision/application evidence | Keep | Extend with prepared/publish/accepted/applied/ambiguous statuses and exact input/output/semantic relation digests. |
| Controller semantic identity | Keep and strengthen | Make admission levels explicit and distinguish portable logical graph, backend compilation, and observed behavioral evidence. |
| Workspace | Keep concept | Split pure policy, state, NCP adapter, transport, range, and backend-independent admission crates more sharply. |
| CI reversion tests | No | Replace `MAX` tests with Gate stream epoch, restart, authority lease, retired epoch, and ambiguous publish-tail tests. |
| Acceptance criterion for sequence ceiling/re-anchoring | No | Replace with independent controller-intent and Gate-output stream invariants. |

### Five-lens independent analysis

The five lenses below are deliberately different from the original ranking lenses. They test whether the selected design survives contact with first principles rather than whether it merely scores well as a project idea.

## Lens 1 — Is the problem real, residual, and worth defending?

### First-principles question

After transport authentication, topic ACLs, schema validation, TTL, sequence checks, and generic physical bounds are all working, what harmful capability remains?

### Residual threat

A valid identity can still be the wrong actor for the current mission action. This can happen through:

- credential theft or supply-chain compromise of an otherwise authorized controller;
- a legitimate controller running the wrong artifact or configuration;
- a controller with a software defect, numerical instability, stale state, or incorrect codec;
- a controller whose mission authority expired or was revoked;
- a controller that is permitted to publish generally but not to perform a specific action in the current phase;
- a backend transformation that changes behavior while preserving a high-level model name;
- a syntactically and physically bounded command sequence that is unsafe in context;
- a legitimate development or UI path bypassing the declared mediation point.

Recent primary research demonstrates the underlying class of problem. A 2025 SROS2 proof of concept showed that stolen keystore material let an attacker rejoin as an authenticated participant and inject control and perception traffic without authentication failures. Work on MAVLink protocol monitoring observes that compromised components can emit individually legal messages in unsafe sequences. A 2026 monitor-synthesis paper targets syntactically correct but semantically ill-timed commands, and a June 2026 ArduPilot preprint reports short well-formed command sequences causing control degradation and crashes in simulation and on Pixhawk hardware. These sources do not prove Haldir's exact design, but they do establish that identity and message validity alone leave a real semantic authorization gap.

### Why NCP does not make Haldir redundant

NCP correctly treats the realm prefix as routing metadata, not a credential. Its mTLS and ACL profile can establish that only an authenticated commander writes the command plane. Its receiver-side checks reject stale, malformed, duplicate, or generically out-of-bounds traffic. Future authority fencing can ensure that only one live publisher lease controls the plant.

Those mechanisms are necessary. Haldir should reuse them, not duplicate them. Their questions are different:

| Mechanism | Question answered |
| --- | --- |
| mTLS | Which cryptographic network principal connected? |
| Router ACL | May that principal publish to this key or plane? |
| NCP session fencing | Does this frame address the current live session opening? |
| NCP stream discipline | Is this a fresh position in the accepted publisher stream? |
| NCP authority lease | Is this publisher currently fenced in as plant writer? |
| NCP/Crebain physical governor | Is the command structurally and physically within configured generic limits? |
| Haldir admission | Is this controller deployment one that an independent authority approved? |
| Haldir mission lease | May that deployment request this action for this mission, vehicle, and phase now? |
| Haldir stateful mission policy | Is the request permitted given trusted current state and recent action history? |

The strongest reason to build Haldir is therefore not that NCP is weak. It is that a clean generic NCP boundary creates a stable place for Haldir's narrower mission and controller-deployment semantics.

### Adversary-value test

A defense is worth building when it removes a capability that an adversary values. Gate removes the ability of a controller principal to convert arbitrary possession of a command-plane role into arbitrary mission action. It also makes credential compromise less decisive when the attacker lacks:

- a current mission lease bound to the Gate boot challenge;
- an admitted controller bundle and execution profile;
- a fresh controller-intent stream;
- a source reference that matches trusted current state;
- an action allowed by the current mission phase and policy;
- the ability to bypass Gate through another actuator route.

This is preventive, not merely forensic. A denied intent never becomes a final plant command.

### Limitations of the problem claim

Haldir does **not** solve:

- compromise of Gate's own host or signing/plant-authority key;
- malicious or compromised Crebain/plant code that ignores NCP and Haldir;
- false trusted state unless a separate sensor-integrity mechanism exists;
- unsafe behavior inside an allowed command envelope when the policy lacks sufficient dynamics;
- arbitrary adaptive neural controllers in the first profile;
- physical safety certification;
- complete mediation if direct ROS, MAVROS, UI, test, or maintenance paths remain open.

### Lens 1 verdict

**Pass, with a narrow claim.** The problem is real and operationally meaningful. The defensible claim is mission- and deployment-specific authorization of an authenticated controller, not a universal neural-controller safety guarantee.

## Lens 2 — Does the architecture actually control authority?

### First-principles question

Can any principal or path cause actuator-affecting state without passing through the same decision point and authority rules?

### Reference-monitor requirements

For Gate to be a reference monitor within its declared scope, it must be:

- **always invoked:** every scoped controller action passes through Gate;
- **tamper-resistant enough for the claim:** ordinary controller and observer roles cannot modify Gate, its policy, its key registry, or its output authority;
- **small enough to analyze:** the hot-path trusted computing base excludes NEST, Engram, Rockpool, NIR tooling, vendor SDKs, databases, UI frameworks, and remote evidence services;
- **fail-closed:** parse, identity, lease, policy, state, time, and internal errors produce no new plant command;
- **explicit about residual validity:** denying a new intent does not retroactively erase an earlier command still valid at the plant.

### Authority must be layered, not duplicated

The clean hierarchy is:

```text
operator / lifecycle authority
        |
        +--> creates NCP session generation
        +--> selects vehicle safe-action profile
        |
deployment CA + router ACL administrator
        |
        +--> grants Gate the exclusive final-route publication capability now
        |
future Crebain / plant authority service
        |
        +--> issues an NCP plant-authority lease to Gate when upstream supports it
        |
Haldir mission authority
        |
        +--> issues narrow mission-intent lease to admitted controller
        |
admission authority
        |
        +--> approves controller bundle + execution profile
        |
controller
        |
        +--> requests semantic actions; never owns final plant stream
```

The mission lease must not pretend to be an NCP plant lease. The NCP plant lease must not contain Haldir-specific controller semantics. Gate is the composition point: in the current profile it must possess the exclusive authenticated final-route publication capability and a valid controller mission lease before publishing. In a future authority profile it must additionally possess a current Crebain-issued NCP plant-authority lease.

### Why Gate must originate every output

A transparent relay leaves ownership ambiguous. If the controller chooses the final NCP stream position and Gate occasionally injects a reversion, two principals effectively participate in one publisher stream. Reserved sequence values do not solve restart, handoff, authority transition, or retired-epoch semantics. Wire 0.8 makes the flaw explicit because stream identity is scoped to the authenticated publisher.

Gate-originated output provides these invariants:

- one authenticated publisher owns one NCP output stream;
- controller restarts do not alter the plant-facing stream;
- controller handoff changes only Haldir mission authority;
- every ALLOW and every reversion consumes the next Gate sequence;
- final `t` always means Gate's local monotonic creation time;
- final authority always names Gate;
- final session binding is validated by Gate;
- output evidence can unambiguously identify the publisher and transformation.

### Complete-mediation proof obligation

Before using the phrase “inline firewall” or “reference monitor,” produce an actuator-path inventory for each deployment. At minimum enumerate:

- all NCP command keys and named-command variants;
- NCP lifecycle RPCs that change mode or authority;
- ROS 2 velocity, position, trajectory, arm, mode, takeoff, land, and emergency interfaces;
- MAVROS and direct MAVLink setpoint/parameter/service paths;
- Crebain native callbacks and development hooks;
- UI commands and test-only shortcuts;
- reconnection, shutdown, watchdog, and startup defaults;
- maintenance and operator override paths;
- simulator backdoors and direct plant APIs.

For every route, assign one disposition:

- closed in the assurance profile;
- reachable only by an independently authorized safety/lifecycle principal;
- independently constrained by a documented plant safety mechanism;
- outside the declared claim, with the limitation prominent.

A diagram is not proof. Run a live role-operation-recipient matrix with distinct credentials and verify both non-delivery and non-application.

### Lens 2 verdict

**Pass only after redesign.** The repository independence and exclusive final-key publication decisions are correct. The embedded-frame and reserved-sequence design would weaken authority clarity; Gate-originated NCP output fixes it.

## Lens 3 — Are time, restart, ordering, and evidence semantics honest?

### First-principles question

What happens when processes restart, messages are duplicated or delayed, clocks move, the bus returns success before delivery, the evidence disk fails, or Gate crashes at the worst possible instruction boundary?

### Five state namespaces that must never be conflated

Haldir needs five separate identities:

1. **NCP session generation** — which live opening of the plant session is addressed.
2. **Gate NCP output stream** — Gate's output epoch and sequence on the final command key.
3. **Controller Haldir intent stream** — the controller process incarnation and intent sequence.
4. **Haldir mission authority** — mission lease term and lease identifier.
5. **Controller deployment identity** — bundle, admission profile, execution profile, and admission-record revisions.

All five may change independently. A numeric or textual “epoch” shared across them would recreate the ambiguity that NCP 0.8 is removing.

### Time model

The only time suitable for hot-path validity is Gate's local monotonic clock:

- the lease authority may state a maximum duration, but Gate anchors it at local acceptance;
- the controller may include an external timestamp for evidence, but it cannot create freshness;
- final NCP `t` is Gate's local monotonic creation time in the NCP adapter's required units;
- trusted sensor freshness is computed from Gate's receipt state and qualified source timing;
- a host reboot or Gate process restart invalidates active mission leases unless they were explicitly bound to the new boot challenge;
- wall-clock synchronization is optional evidence, never the sole authority basis.

### Restart model

On every Gate process start:

1. generate a random `gate_boot_id`;
2. generate a fresh Gate output stream epoch for each eventual session/key scope;
3. enter `RECOVERING`, load only durable rejection state and policy/admission snapshots;
4. do not restore active monotonic deadlines;
5. require mission leases to bind the new `gate_boot_id`;
6. bind to the live NCP session pair;
7. acquire or confirm NCP plant authority for the new output epoch when that feature exists;
8. remain unable to publish active commands until all bindings are current.

Persisted state is primarily for rejecting old authority, proving evidence, and detecting uncertain tails. It is not a mechanism for resurrecting a pre-crash lease.

### Publication ambiguity

No local transaction can atomically commit both a disk record and a distributed Zenoh publication. The system must model the ambiguity rather than hide it.

A crash can occur:

- before policy decision;
- after ALLOW but before output sequence allocation;
- after sequence allocation but before serialization;
- after a durable `PREPARED` record but before `put()`;
- during `put()`;
- after local `put()` success but before the success record;
- after Crebain acceptance but before receipt correlation;
- after application but before measured-state evidence.

The evidence model therefore uses stages, not a false boolean “executed” field:

- `RECEIVED`;
- `VALIDATED`;
- `POLICY_DENIED` or `POLICY_ALLOWED`;
- `OUTPUT_PREPARED`;
- `PUBLISH_ATTEMPTED`;
- `LOCAL_PUBLISH_RETURNED`;
- `CREBAIN_ACCEPTED`;
- `ADAPTER_APPLIED`;
- `PLANT_OBSERVED`;
- `EXPIRED`;
- `AMBIGUOUS_AFTER_PUBLISH`.

A new Gate epoch after restart prevents an uncertain old sequence from being reused. It does not prove whether the last old frame was delivered.

### Lens 3 verdict

**Pass after replacing exact-once intuition with explicit ambiguity.** NCP wire 0.8 gives Haldir the right primitives. The implementation must preserve their separation and never claim atomic publish-and-receipt behavior.

## Lens 4 — Is the neuromorphic component causally relevant?

### First-principles question

Would the Haldir security result change if NEST were replaced by another simulator or neuromorphic implementation? If not, “neuromorphic” is decoration. If yes, what specific transformation can invalidate authorization?

### The real backend problem

A portable SNN deployment can change through:

- graph lowering and unsupported primitive substitution;
- numerical integration method and timestep;
- reset and refractory semantics;
- input spike encoding and output action decoding;
- weight scaling, clipping, quantization, and saturation;
- placement, routing, fan-in/fan-out, delay, and memory constraints;
- random initial state and seed treatment;
- batching and chunk boundaries;
- runtime/compiler/driver/firmware versions;
- online state persistence and reset behavior.

NIR is a strong interoperability foundation because it expresses model-centric computational graphs across many simulators and hardware targets. Its own published evaluation also makes the critical point for Haldir: continuous-time descriptions must be discretized or mapped to platforms, and those conversions can produce divergent results. NIR solves exchange and common semantics; it does not automatically prove that two deployed executions justify the same mission authority.

That is the precise neuromorphic reason for Haldir:

> Authorization granted to a logical controller should not silently survive a backend transformation that changes action-level behavior beyond an approved relation.

### Why NEST remains the reference backend

NEST is already used in Engram and provides a real computational neuroscience simulator. Reusing it avoids creating a new backend solely to justify the project. NEST should be the reference execution for the first fixed-weight controller profile, not because it is “ground truth” for every chip, but because it is the existing independently testable baseline.

### Choosing a second backend

Do not select a backend by brand prestige. Select it by the independent source of semantic variation it introduces and the ability to reproduce the experiment.

Recommended order:

1. **Norse or another open NIR-capable software backend** for an accessible independent implementation and rapid differential testing.
2. **Rockpool mapping plus XyloSim** for a hardware-constrained, mapped, quantized configuration when the controller fits Xylo's supported topology and resource limits. XyloSim is valuable because it simulates the generated hardware configuration bit-precisely; a mapping rejection is a valid result, not a reason to weaken the profile.
3. **SpiNNaker2's Brian2 path** as an optional additional emulator. Current official documentation still notes private dependencies tied to hardware access, so it should not be an MVP dependency.
4. **Physical hardware** only when actual access, firmware, runtime, measurement, and device-root assumptions are documented.

Do not build a new dependency on Lava: its repositories were archived in May 2026. It may remain a historical comparison but is not a sound new platform foundation.

### Semantic admission, not exact spike equality

Exact spike-train equality across backends is usually the wrong authorization criterion. Haldir should define equivalence at the level that affects the protected plant:

- decoded action class and mode;
- command components and bounded error;
- action timing and omission behavior;
- Gate allow/deny outcome;
- reference-plant trajectory and safety margin;
- reset and fault response.

Internal spikes and membrane traces remain diagnostic evidence. They are not necessarily the acceptance relation.

### Lens 4 verdict

**Pass, with a profile-bounded research claim.** The neuromorphic contribution is justified when it tests whether backend transformations preserve the action-level assumptions under which mission authority was granted. Merely adding another simulator is not enough.

## Lens 5 — Can the work be falsified, delivered, and maintained?

### First-principles question

What small implementation can disprove the architecture early, and what evidence would justify continued investment?

### Minimum falsifiable hypotheses

The initial program should test these hypotheses:

- **H1 — Mediation:** within the declared deployment profile, no ordinary controller route can cause a plant action without a Gate decision.
- **H2 — Authority separation:** controller restart, handoff, replay, stale session traffic, or stale mission authority cannot seize or refresh the Gate-owned NCP output stream.
- **H3 — Transparency:** for allowed requests, Gate preserves the requested semantic action within an explicitly defined conversion relation and within the command deadline.
- **H4 — Fail-closed behavior:** malformed input, policy error, state staleness, Gate crash, evidence outage, and overload do not create or refresh any plant-affecting authorization or command.
- **H5 — Backend-aware admission:** the declared controller bundle and execution profile predict held-out action-level behavior across the selected independent backends better than a package hash or model name alone.

### Early disproof tests

Stop or narrow the design before Engram integration if any of these occurs:

- an ordinary controller can reach Crebain through a direct route in the claimed profile;
- Gate cannot reliably bind its output to the current session generation;
- output-stream restart semantics cannot be made safe under the available NCP increment;
- the pure policy core cannot meet the measured command deadline on the target deployment class;
- the trusted state needed for a policy is unavailable or cannot be correlated to source frames;
- the first controller cannot be represented without hidden arbitrary code;
- the second backend is not independently implemented or produces no meaningful semantic perturbation;
- equivalence thresholds are selected after observing held-out outcomes;
- the result is indistinguishable from “Cedar on a topic plus signed logs.”

### Trusted computing base discipline

The command hot path should include only:

- deterministic Haldir contract parsing and signature verification;
- bounded key/admission/lease lookup;
- local state and stream state machines;
- native deterministic policy predicates;
- the pinned NCP adapter and secure transport client;
- bounded local evidence enqueueing.

It should exclude:

- NEST and all neural execution;
- NIR conversion;
- Rockpool, Xylo, SpiNNaker, or vendor SDKs;
- Python;
- a remote database;
- a remote policy service;
- a web UI;
- an unbounded log formatter;
- runtime controller compilation;
- mission-policy generation by a language model.

### Lens 5 verdict

**Pass with staged scope.** The project is deliverable if Gate's first milestone is a deterministic reference-controller/reference-plant path and if neuromorphic admission is a later, independently falsifiable layer. It becomes high-risk if all ecosystem and backend integrations are attempted before the authority core is proven.

## Corrected system definition

### One-sentence product definition

Haldir Gate is a fail-closed, inline authorization reference monitor that accepts signed, typed controller **intent**, proves that the requesting controller deployment and mission lease are currently admissible, evaluates bounded stateful policy against trusted state, and—only on ALLOW—originates a fresh NCP command under Gate's own stream and exclusive final-route publication capability, including a current NCP plant-authority lease only in a future profile that supports it.

The product is not a generic network firewall. It is an application-layer authority boundary between an untrusted or partially trusted controller and a trusted plant command adapter.

### Security objective

For a declared vehicle, mission, and deployment profile, an actuator-affecting NCP command is eligible for application only when all of the following are simultaneously true:

1. the command was published by the authenticated Gate principal on the exact final command key;
2. the NCP session pair is current;
3. the Gate output stream and exclusive final-route publication profile are current, and any NCP plant-authority lease required by the active compatibility profile is current;
4. the request originated in a fresh, signed Haldir intent from the expected controller deployment key;
5. the referenced controller bundle and backend execution profile have an active admission;
6. an active mission lease permits the requested semantic action for the named vehicle and phase;
7. the primary source reference and all policy-critical state are fresh and match Gate's trusted observations;
8. deterministic policy permits the action and all policy diagnostics are empty;
9. the final NCP frame is generated by the pinned adapter and passes the local NCP validator;
10. the Crebain plant-side adapter independently validates the final frame and applies only a current action or its declared safe-action profile.

This is a conjunction. No single identity, signature, certificate, bundle hash, policy result, or receipt is sufficient by itself.

### Engineering goals

The first release should optimize for these properties, in order:

1. **Complete scoped mediation.** The claimed deployment has no ordinary controller-to-actuator route around Gate.
2. **Authority clarity.** Every authority has one issuer, one scope, one lifetime, and one revocation path.
3. **Fail-closed determinism.** Invalid data, stale state, uncertainty, evaluator failure, and overload cannot create fresh output authority.
4. **Small trusted computing base.** The command path is Rust, bounded, local, and independent of neural runtimes.
5. **Version insulation.** Stable Haldir semantics are separated from an evolving NCP wire adapter.
6. **Operational evidence.** Decision, publication, acceptance, application, and measured response are distinguishable.
7. **Backend-relevant admission.** The admitted identity includes the transformations that can change controller behavior.
8. **Falsifiability.** Each milestone can fail for a specified reason without redefining success.

### Explicit non-goals

The MVP does not attempt to:

- prove a neural controller globally safe;
- infer intent from arbitrary controller code;
- certify PX4, ArduPilot, ROS 2, Zenoh, NEST, or a neuromorphic device;
- provide hard real-time guarantees on an unqualified general-purpose operating system;
- guarantee exactly-once publication or application over Zenoh;
- make a signed receipt prove physical actuation;
- recover an active mission lease after Gate restart;
- support active-active Gate writers;
- support arbitrary command schemas or arbitrary coordinate transforms;
- accept arbitrary Python callbacks as a profile-complete controller;
- claim backend equivalence from equal package names or equal aggregate accuracy;
- replace NCP session fencing, stream validation, transport identity, or plant safety;
- perform weapon selection, release, or targeting decisions.

### Assurance-profile language

Every demonstration and release must name its assurance profile. A useful profile statement has this form:

```text
Profile: haldir-reference-v1
Vehicle/plant: deterministic point-mass plant
Controller route: controller -> Haldir intent key only
Final command route: Gate -> one NCP command key -> Crebain CommandPlant
Direct DDS/MAVROS routes: absent by construction
NCP compatibility: exact commit or immutable tag
Gate writers: one authenticated principal
Controller writers: one authenticated principal per intent key
Command family: body-frame velocity + hold
State source: one NCP pose/velocity stream
Safe action: plant-owned bounded deceleration to hold
Timing claim: measured on named host/kernel/load; not hard real-time
Backend claim: NEST reference only, or named admitted backend profile
```

Do not write “Haldir mediates the vehicle” when the tested profile mediates only one topic while other actuator paths remain open. Use “mediates the declared command route” until the authority graph and live bypass campaign justify the stronger claim.

## Authority and trust architecture

### Authorities are capabilities, not labels

The design should treat each authorization as an explicit capability with a verifier-enforced scope. A string such as `controller_id = alpha` is descriptive until a trusted authority binds it to a key and the receiver verifies that binding.

The minimum authorities are:

| Authority | Issuer | Holder | Scope | Verifier |
| --- | --- | --- | --- | --- |
| Network identity | deployment CA | each service | connect and authenticate as a principal | Zenoh/router and peers |
| Router publication right | router ACL administrator | each principal | exact keys/verbs | router |
| NCP session generation | NCP lifecycle/session service | session participants | one live session opening | NCP receivers |
| Final-route publication capability | deployment CA and router ACL administrator | Gate | authenticated PUT on the exact final command route | router and Crebain deployment profile |
| Future NCP plant authority | Crebain/plant authority issuer | Gate | final command stream for one vehicle/session/epoch | Crebain CommandPlant |
| Gate boot challenge | Gate | mission/admission issuers | bind new leases to this Gate incarnation | Gate |
| Controller deployment identity | admission/key authority | controller signing key | sign intents as one admitted deployment | Gate |
| Controller admission | admission authority | bundle/backend profile | eligible controller deployment relation | Gate |
| Mission-intent lease | mission authority | controller deployment | bounded action scope for one mission/vehicle/Gate boot/session | Gate |
| Policy package approval | policy authority/release process | Gate configuration | exact executable policy snapshot | Gate startup and receipts |
| Evidence signing | Gate/Crebain keys | evidence producer | attest only to that producer's observed stage | evidence consumers |

These authorities should use distinct key roles even if one development CA initially signs several of them. A compromise of an evidence collector must not mint a mission lease. A controller key must not sign an admission. The Gate output key must not be used to sign controller bundles.

### Recommended authority partial order

The effective permission to create a plant command is:

```text
network principal and ACL
        AND
current NCP session
        AND
current exclusive Gate final-route publication capability
        AND
current NCP plant-authority lease when the active compatibility profile supports one
        AND
active controller admission
        AND
active mission-intent lease
        AND
fresh signed controller intent
        AND
fresh trusted state/source
        AND
native mission policy ALLOW
        AND
valid Gate-authored NCP output
        AND
Crebain plant acceptance
```

No lower layer can expand a higher layer's scope:

- an ACL cannot make an expired mission lease valid;
- a mission lease cannot authorize a controller bundle not covered by its admission;
- a policy package cannot make a stale NCP session current;
- an NCP authority lease cannot authorize the controller to bypass Gate;
- a receipt cannot retroactively authorize a denied or missing command.

### Key separation

Use at least these logical key classes:

- `K_gate_transport`: mTLS identity for Gate's Zenoh connection;
- `K_gate_output`: application signing key for Gate decision/output evidence, when output signatures are separate from transport;
- `K_controller_transport[i]`: mTLS identity for controller instance `i`;
- `K_controller_intent[i]`: COSE signing key for controller deployment `i`;
- `K_admission`: signs admission records and revocations;
- `K_mission`: signs mission leases and revocations;
- `K_policy`: signs approved policy packages;
- `K_crebain_evidence`: signs accepted/applied evidence;
- `K_release`: signs release artifacts and provenance, not runtime authority.

For an MVP, Ed25519 is a reasonable application-signature profile because it has deterministic signing and mature implementations. Keep the algorithm identifier in protected COSE headers so a later profile can add another approved algorithm without changing semantic payloads. Do not permit “algorithm supplied by the message” dispatch without a local allowlist.

### Gate exclusively holds final publication now and future plant authority; controllers hold neither

In the current `PRE_AUTHORITY_ACL_ONLY` profile, Gate alone holds the mTLS credential and ACL permission for the exact final route. No controller has that capability. When a future NCP authority increment is available, Crebain should additionally issue the plant-authority lease to Gate, naming:

- the current NCP session pair;
- the Gate authenticated publisher identity;
- the exact final key and message kind;
- the Gate output stream epoch;
- an authority term and lease identifier;
- an expiry or revocation condition;
- the permitted command class, if NCP's authority model supports that restriction.

A neural controller must receive neither the final-route transport credential nor a future NCP plant-authority lease. Its only control capability is a Haldir mission-intent lease that can be exercised through Gate. This avoids two independent systems believing they control the same plant authority.

### Controller handoff

Handoff changes controller-side authority, not plant-facing stream ownership:

1. mission authority revokes or allows the old Haldir lease to expire;
2. Gate marks the old controller intent stream retired and rejects every later frame from it;
3. Gate optionally emits a plant/profile-defined transition action using the next normal Gate output sequence;
4. a new admission and mission lease are activated for the replacement controller;
5. the replacement controller starts a fresh Haldir intent epoch at sequence one;
6. Gate continues its existing NCP output epoch and next sequence when the session and current ACL-exclusive publication authorization remain unchanged; under a future NCP authority profile, the plant-authority term must also remain unchanged.

There is no need for the new controller to know the previous Gate output sequence. There is no reserved maximum. There is no byte-preserving exception.

## Threat model

### Protected assets

The primary assets are:

- authority to affect the plant;
- integrity and freshness of final commands;
- session and stream state;
- mission lease scope and lifetime;
- controller admission and revocation state;
- trusted source/state snapshots used for policy;
- Gate output and evidence signing keys;
- complete-mediation deployment configuration;
- policy package integrity;
- availability of safe expiry and plant-owned fallback;
- evidence needed to reconstruct what each component observed.

Confidentiality of ordinary command data is secondary to integrity and availability for this project, although mTLS should still protect it in deployment.

### Adversaries in scope

The test program should include at least these adversaries:

1. **Unauthenticated network actor.** Can send packets but lacks a trusted certificate.
2. **Wrong authenticated role.** Has a valid observer, UI, or controller certificate but lacks final-key rights.
3. **Compromised controller process.** Holds its transport and intent keys and can emit arbitrary well-formed signed intents within its key's identity.
4. **Stale controller process.** Retains old leases, old session identifiers, old source frames, or retired intent epochs.
5. **Wrong admitted artifact.** Uses a legitimate controller key with a different bundle, profile, codec, backend compilation, or runtime configuration.
6. **Buggy controller.** Produces extreme, oscillatory, stale, malformed, or semantically inappropriate requests without malicious intent.
7. **Compromised evidence service.** Drops, reorders, fabricates its own unsigned records, or becomes unavailable.
8. **Transport fault.** Reorders, duplicates, delays, drops, or partitions traffic.
9. **Clock fault.** Wall clock jumps, monotonic source fails, or controller time resets.
10. **Gate crash/restart.** Occurs before decision, after decision, before publish, after publish, or before evidence completion.
11. **Resource-exhaustion actor.** Sends oversized, deeply nested, high-rate, or expensive-to-verify inputs using a permitted connection.
12. **Backend-drift fault.** Quantization, discretization, mapping, reset, precision, seed, or runtime differences change controller actions.
13. **Operator/configuration error.** Installs an ACL, policy, safe-action profile, or backend profile inconsistent with the claimed deployment.

### Adversaries not solved by Gate alone

The following require a narrower claim or separate controls:

- root compromise of the Gate host, kernel, process memory, or Gate signing key;
- compromise of both the mission and admission authorities sufficient to mint internally consistent malicious authority;
- malicious Crebain code that ignores NCP validation or fabricates application evidence;
- malicious vehicle firmware or actuator hardware;
- physical sensor spoofing not detected by the state-estimation boundary;
- denial of service that prevents both Gate output and the plant's local safe mechanism;
- an undeclared direct actuator path outside the assurance profile;
- malicious NCP/router implementation that violates the pinned conformance contract;
- supply-chain compromise of every verifier and build/release authority.

Haldir can collect evidence relevant to these cases, but it cannot claim to prevent them without additional roots of trust.

### Trust assumptions to write down before coding

Create `docs/THREAT-MODEL.md` and make these assumptions explicit and testable:

- Gate's host monotonic clock does not move backward during one boot; a detected violation latches fault.
- Gate boot identity is fresh and unpredictable.
- Gate can obtain the exact received key and the pinned NCP adapter can validate key/payload equality.
- The deployment router enforces the tested mTLS/ACL policy.
- Only Gate's authenticated principal can write the final command key in the assurance profile.
- Crebain consumes only that final key for the claimed plant route.
- Crebain applies an expired/missing-command safe-action profile locally without requiring Gate.
- Mission and admission trust roots are provisioned out of band and are not writable by controllers.
- Policy-critical state arrives on an authenticated route and is independently observed by Gate.
- Gate never uses controller wall time as a source of authority freshness.
- The first profile has one Gate writer and one active controller lease per vehicle.
- NCP compatibility is pinned to an exact immutable revision or exact experimental commit.

## Non-negotiable invariants

The implementation should encode these as assertions, property tests, model-checking properties, and integration tests. A release must not rely on prose alone.

### Authority invariants

**A1. Final-key exclusivity.** In the declared deployment, only the Gate transport principal can publish the final command key.

**A2. Controller confinement.** A controller principal can publish only its exact Haldir intent key and cannot join an alternate ROS/DDS/MAVROS command path.

**A3. Gate-origin output.** Every final command is newly constructed by Gate; no controller-supplied final NCP frame is forwarded as opaque bytes.

**A4. Plant-authority ownership.** When the NCP authority field exists, every final command carries a current lease issued to Gate, never to the controller.

**A5. Conjunctive authorization.** ALLOW requires current session, admission, mission lease, source/state, controller stream, policy, and output authority simultaneously.

**A6. No receipt authority.** Decision or application receipts can describe authority but cannot create or extend it.

### Session and stream invariants

**S1. Atomic session pair.** `session_id` and `session.generation` are validated as one pair before replay state, TTL state, mode state, evidence state with security consequences, or output sequence allocation changes.

**S2. Separate streams.** Controller intent stream position and Gate NCP output stream position are different types and are never assigned from one another.

**S3. Fresh output epoch per Gate restart.** A Gate process restart creates a new boot ID and a new output stream epoch.

**S4. Monotone output sequence.** Within one Gate output epoch, every new logical output has a strictly increasing sequence starting at one; retries reuse the exact same bytes and sequence.

**S5. Retired intent epochs stay retired.** A controller intent epoch once retired cannot become active again in the same Gate boot/session, regardless of sequence size.

**S6. Duplicate denial has no liveness effect.** Duplicate, stale, malformed, wrong-session, or unauthorized input never refreshes a lease, watchdog, command horizon, source freshness, or output authority.

**S7. Source is correlation, not delivery order.** Primary source references may repeat or jump according to controller behavior; Gate output loss accounting uses Gate's output stream only.

### Time and validity invariants

**T1. Local authority time.** Active lease deadlines are anchored to Gate's local monotonic time at acceptance.

**T2. Controller time is diagnostic.** Controller timestamps may support latency analysis but never create freshness or extend a lease.

**T3. Minimum remaining validity.** Effective output validity is no greater than the minimum of the requested validity, mission lease remaining time, source/state freshness remaining time, policy cap, NCP cap, and plant-authority remaining time.

**T4. No deadline resurrection.** Restart, wall-clock adjustment, reconnection, or replay cannot reconstruct or extend a pre-restart active deadline.

**T5. Time-source failure denies.** A monotonic-clock error or inability to establish required freshness causes DENY or a latched fault; it never defaults to fresh.

### Policy invariants

**P1. Parser before policy.** Policy never receives an unbounded, partially parsed, ambiguous, duplicate-key, noncanonical, or wrong-version request.

**P2. Native hard predicates.** Geometry, numeric bounds, slew, duty, freshness, state machines, and checked arithmetic run in the bounded native core.

**P3. Diagnostics deny.** Any optional Cedar evaluation error or diagnostic converts the overall result to DENY.

**P4. Deny precedence.** Hard safety denial and explicit forbids override permits.

**P5. Immutable decision snapshot.** One decision uses one immutable policy snapshot, admission snapshot, lease snapshot, and state snapshot whose digests are recorded.

**P6. No hidden transformation.** A changed semantic command is represented as a Gate transformation with input/output semantic digests; it is never called byte-preserving.

### Failure and evidence invariants

**F1. Gate crash creates no fresh command.** After Gate stops, no new final command can be produced; plant behavior is bounded by already accepted validity plus local safe-action behavior.

**F2. Evidence outage does not grant authority.** A full or unavailable remote evidence sink cannot turn DENY into ALLOW. The declared profile specifies whether a full local spool causes continued bounded operation or a controlled quiesce.

**F3. Publication is not application.** Local publish return, Crebain receipt, Crebain acceptance, adapter application, and measured plant response are separate evidence stages.

**F4. Ambiguity is explicit.** A crash after publish but before acknowledgement is recorded as `UNKNOWN_AFTER_PUBLISH` when reconstructed; it is not guessed as applied or unapplied.

**F5. Safe action is plant-owned.** Gate can request a transition, but the authoritative fallback on missing/expired commands is implemented and tested in Crebain/the plant profile.

**F6. Bounded resources.** Every queue, history window, parser depth, map size, identifier length, evidence record, and per-principal state table has a configured upper bound and deterministic overflow behavior.

## Identity namespaces and state ownership

### Five namespaces that must remain separate

| Namespace | Example | Owner | Lifetime | Security purpose |
| --- | --- | --- | --- | --- |
| NCP session opening | `(session_id, generation)` | lifecycle/session service | one live session opening | reject stale session traffic |
| Gate NCP output stream | `(gate_output_epoch, output_seq)` | Gate | Gate stream incarnation within a session/authority transition | order and deduplicate final commands |
| Controller Haldir intent stream | `(controller_intent_epoch, intent_seq)` | controller, accepted by Gate | one controller process/logical stream | replay and ordering of signed requests |
| Haldir mission lease | `(mission_lease_term, mission_lease_id)` | mission authority | bounded Gate boot/session/action scope | contextual permission to request actions |
| Admission/deployment revision | `(admission_id, bundle_digest, backend_profile_digest)` | admission authority | until expiry or revocation | identify approved controller execution relation |

A sixth useful namespace is `gate_boot_id`, owned by Gate and regenerated on every process start. It prevents a mission lease or challenge response from surviving a Gate restart.

### State ownership table

| State | Canonical owner | Gate cache behavior | Durable? |
| --- | --- | --- | --- |
| current NCP session pair | lifecycle/session service | subscribe/read, validate before use | cache only; rediscover after restart |
| current plant-publication authorization state | deployment CA/router ACL now; future Crebain/NCP issuer later | verify exact variant | no active restoration; re-prove ACL profile or reacquire future lease |
| Gate boot ID/challenge | Gate | generate | boot ID may be logged; never reused |
| Gate output epoch/sequence | Gate | allocate under one vehicle actor | no active restoration; new epoch after restart |
| active mission lease | mission authority, accepted by Gate | anchor to monotonic deadline | active lease not restored |
| maximum seen lease term/revocation epoch | mission/admission authorities | anti-rollback check | yes, small authenticated store |
| controller intent replay state | Gate | active epoch, last seq, retired tombstones | no active restoration; boot-bound lease invalidates old traffic |
| admission records/revocations | admission authority | verified immutable snapshot | yes, signed records and index |
| policy package | policy release authority | immutable snapshot | yes, signed artifact |
| state/source cache | NCP/Crebain publishers | bounded recent frames | no; refill before ACTIVE |
| decision evidence | Gate | append asynchronously | bounded durable spool according to profile |
| application evidence | Crebain | consume/merge by IDs | external or bounded local store |

### Why active lease state should not be restored

Restoring an active lease after a process restart requires reconstructing a monotonic deadline and every relevant in-memory state transition. That adds complexity while preserving authority across exactly the event where the verifier lost continuity. The safer MVP rule is:

1. restart creates a new Gate boot ID;
2. every previous mission lease is invalid because it binds the old boot ID;
3. Gate starts with no active publication-authorization snapshot and no active controller stream;
4. trusted session/state caches must refill;
5. the current profile re-proves exclusive ACL publication after the prior stream expires; a future profile additionally reacquires plant authority for the new Gate output epoch;
6. mission authority issues a fresh lease for the new challenge;
7. only then can Gate become ACTIVE.

Durable state is used to reject rollback and retain evidence, not to silently continue old authority.

## Stable Haldir contracts

### Contract design rule

Haldir's stable contracts describe semantic authority and evidence. They must not expose an NCP version-specific generated struct as a public field. Version-specific NCP objects are constructed only inside `haldir-ncp08` or a later adapter.

Use one normative schema source, generate language bindings where practical, and maintain hand-written validators that enforce semantic restrictions generated code cannot express. The examples below are deliberately close to Rust and CDDL, but the repository must choose one source of truth and treat every other rendering as generated or tested documentation.

### Encoding and signing profile

#### Canonical payload

Use deterministic CBOR under a strict Haldir application profile:

- one definite-length top-level map;
- definite-length arrays, maps, byte strings, and text strings only;
- shortest integer and length encodings;
- map keys in deterministic encoded-key order;
- no duplicate keys under either encoded or application-level equivalence;
- no CBOR floats in signed Haldir authority objects;
- no tags except those explicitly permitted by the schema;
- no unknown fields in a major version unless they are inside a named extension map whose criticality rules are explicit;
- ASCII-only security identifiers with field-specific length and character restrictions;
- byte strings for digests, nonces, and UUID bytes;
- a maximum nesting depth, map-entry count, array length, and total payload size per message kind;
- exactly one top-level data item with no trailing bytes.

The receiver should decode with limits, validate the semantic object, deterministically re-encode it, and require equality with the signed payload bytes. This prevents two accepted byte representations from naming the same authority object.

#### COSE envelope

Use embedded-payload `COSE_Sign1` for the first application-signature profile:

- protected `alg` is EdDSA/Ed25519;
- protected `kid` selects one locally trusted key record;
- protected content type is a precise value such as `application/haldir-intent+cbor`;
- unprotected headers carry no security decision input;
- external AAD is a fixed domain string for the exact message kind, for example `haldir.intent.v1`;
- the payload repeats its message kind and major/minor version so an envelope cannot be reinterpreted under another schema;
- Gate rejects an algorithm, key, or content type not present in its local allowlist;
- Gate rejects a key whose role, controller, issuer, validity, or revocation state does not match the payload.

Do not accept a caller-selected verification algorithm. Do not fall back from a failed current key to every key in a trust store. Do not accept a key ID from an unprotected header when the protected header is absent.

#### Digest profile

Represent digests as typed values rather than unlabelled hex strings:

```rust
pub enum DigestAlgorithmV1 {
    Sha256,
}

pub struct DigestV1 {
    pub algorithm: DigestAlgorithmV1,
    pub value: [u8; 32],
}
```

Use separate digest domains:

- `raw_envelope_digest`: exact received COSE bytes;
- `payload_digest`: exact canonical CBOR payload bytes;
- `semantic_intent_digest`: canonical typed action and its policy-relevant bindings;
- `output_frame_digest`: exact Gate-created NCP serialization;
- `state_snapshot_digest`: canonical state values used for the decision;
- `policy_snapshot_digest`: exact approved policy package;
- `bundle_digest`, `backend_profile_digest`, and `admission_digest`.

A receipt must name the digest's object and domain. A bare `hash` field is too ambiguous.

#### Parser limits

Start with conservative limits and make them policy-profile values only where operationally necessary:

| Item | Initial limit | Overflow behavior |
| --- | ---: | --- |
| intent COSE envelope | 16 KiB | reject before signature verification |
| lease/admission envelope | 64 KiB | reject |
| evidence event | 32 KiB | truncate only non-signed display metadata; never signed core |
| CBOR nesting depth | 8 | reject |
| map pairs | 64 per map | reject |
| array elements | 256, lower per field | reject |
| identifier | 64 ASCII bytes | reject |
| routing key copy | 256 bytes | reject |
| bounded source watermarks | 8 | reject |
| policy reason codes | 32 | reject and emit internal fault if evaluator exceeds bound |
| signature-verification queue | fixed per principal and global | drop/deny according to overload policy; never unbounded allocate |

Perform the total-size check before parsing and the per-principal rate check before expensive signature verification. Preserve a small authenticated-control reserve so a flood of controller intents cannot starve lease revocation or session-close processing.

### Common scalar types

The stable contract crate should make accidental namespace mixing difficult:

```rust
#[repr(transparent)] pub struct GateBootId([u8; 16]);
#[repr(transparent)] pub struct ChallengeNonce([u8; 32]);
#[repr(transparent)] pub struct MissionLeaseId([u8; 16]);
#[repr(transparent)] pub struct AdmissionId([u8; 16]);
#[repr(transparent)] pub struct DecisionId([u8; 16]);
#[repr(transparent)] pub struct IntentEpoch([u8; 16]);
#[repr(transparent)] pub struct ControllerId(AsciiId<64>);
#[repr(transparent)] pub struct VehicleId(AsciiId<64>);
#[repr(transparent)] pub struct MissionId(AsciiId<64>);
#[repr(transparent)] pub struct GateId(AsciiId<64>);
#[repr(transparent)] pub struct KeyId(Vec<u8>); // bounded by constructor

pub struct NcpSessionIdentityV1 {
    pub session_id: AsciiId<64>,
    pub generation: CanonicalUuidV4String,
}

pub struct HaldirIntentPositionV1 {
    pub epoch: IntentEpoch,
    pub seq: NonZeroU64,
}
```

Do not use one generic `EpochId` or `Sequence` for Gate output, NCP source, mission lease term, and controller intent position. Newtypes prevent a class of valid-looking but semantically wrong assignments.

### `GateChallengeV1`

#### Purpose

A Gate challenge proves liveness of one Gate process incarnation and gives external authorities a one-time value to bind into a lease. It removes the need to trust controller wall time and prevents an old signed lease from becoming active after Gate restart.

#### Fields

```rust
pub struct GateChallengeV1 {
    pub message_kind: FixedString<"haldir.gate_challenge">,
    pub schema_major: u16,                  // 1
    pub schema_minor: u16,
    pub gate_id: GateId,
    pub gate_boot_id: GateBootId,
    pub challenge_nonce: ChallengeNonce,
    pub challenge_seq: NonZeroU64,
    pub realm: AsciiId<64>,
    pub vehicle_id: VehicleId,
    pub ncp_session: NcpSessionIdentityV1,
    pub gate_output_epoch: CanonicalUuidV4String,
    pub gate_key_id: KeyId,
    pub policy_snapshot_digest: DigestV1,
    pub accepted_contract_versions: BoundedVec<ContractVersion, 8>,
    pub ncp_compatibility_id: DigestV1,
}
```

The challenge is signed by Gate. Its local validity deadline is intentionally not an externally authoritative timestamp. Gate stores the nonce in a bounded pending-challenge table with a local monotonic expiry. A lease response is accepted only while that exact challenge remains pending and unused.

#### Processing rules

1. Generate a new `gate_boot_id` and output epoch on every Gate process start.
2. Generate challenge nonces with the operating system CSPRNG; fail startup if entropy is unavailable.
3. Scope one challenge to one realm, vehicle, session pair, Gate output epoch, and policy snapshot.
4. Permit only a small number of pending challenges per vehicle.
5. Mark a nonce consumed before activating the resulting lease.
6. Never reactivate a consumed or expired nonce.
7. On session generation change, expire all pending challenges and active leases for the old pair.
8. On policy replacement, either expire challenges or require the lease to bind the new policy digest explicitly.

### `MissionLeaseV1`

#### Purpose

A mission lease grants a named controller deployment permission to request a bounded class of semantic actions through one Gate boot and one NCP session. It is not a plant command and does not grant final-key publication rights.

#### Fields

```rust
pub struct MissionLeaseV1 {
    pub message_kind: FixedString<"haldir.mission_lease">,
    pub schema_major: u16,
    pub schema_minor: u16,

    pub issuer_id: AsciiId<64>,
    pub issuer_key_id: KeyId,
    pub lease_id: MissionLeaseId,
    pub lease_term: NonZeroU64,

    pub gate_id: GateId,
    pub gate_boot_id: GateBootId,
    pub challenge_nonce: ChallengeNonce,
    pub realm: AsciiId<64>,
    pub vehicle_id: VehicleId,
    pub mission_id: MissionId,
    pub mission_phase: AsciiId<64>,
    pub ncp_session: NcpSessionIdentityV1,
    pub gate_output_epoch: CanonicalUuidV4String,

    pub controller_id: ControllerId,
    pub controller_intent_key: BoundedAscii<256>,
    pub controller_intent_signing_key_id: KeyId,
    pub admission_id: AdmissionId,
    pub admission_digest: DigestV1,
    pub controller_bundle_digest: DigestV1,
    pub backend_profile_digest: DigestV1,

    pub policy_snapshot_digest: DigestV1,
    pub allowed_actions: BoundedSet<ActionClassV1, 16>,
    pub allowed_frames: BoundedSet<CoordinateFrameV1, 8>,
    pub allowed_source_keys: BoundedVec<BoundedAscii<256>, 8>,
    pub limits: MissionLeaseLimitsV1,

    pub max_active_duration_ms: NonZeroU32,
    pub max_intent_rate_millihz: NonZeroU32,
    pub max_total_intents: NonZeroU64,
    pub operator_context_digest: Option<DigestV1>,
}

pub struct MissionLeaseLimitsV1 {
    pub max_output_validity_ms: NonZeroU32,
    pub max_linear_speed_mm_s: NonZeroU32,
    pub max_linear_accel_mm_s2: NonZeroU32,
    pub max_linear_slew_mm_s2: NonZeroU32,
    pub max_source_age_ms: NonZeroU32,
    pub max_state_age_ms: NonZeroU32,
    pub max_continuous_motion_ms: NonZeroU32,
    pub minimum_hold_between_bursts_ms: u32,
}
```

The lease may be stricter than the policy package but never looser. Effective bounds are the intersection of lease, policy, admission, NCP, and plant profile.

#### Lease acceptance algorithm

Under the per-vehicle state lock:

1. check envelope size and canonical encoding;
2. verify protected COSE headers and mission-authority signature;
3. verify issuer role and revocation state;
4. require exact Gate ID, boot ID, challenge nonce, realm, vehicle, session pair, and Gate output epoch;
5. require the policy digest to equal the currently loaded approved snapshot;
6. resolve the admission by ID and digest and require it active;
7. require controller ID, signing key, bundle digest, and backend profile digest to match that admission;
8. require the exact controller intent key to match the configured ACL/profile;
9. validate every numeric limit against local maximums and checked arithmetic;
10. compare `lease_term` to the durable anti-rollback high-water for the issuer/scope;
11. require the challenge to remain pending, unexpired, and unused without consuming it;
12. durably advance the accepted term high-water before exposing the lease as active;
13. consume the challenge nonce only after the durable term commit succeeds;
14. anchor `accepted_at_mono` to the current Gate monotonic time;
15. calculate `expires_at_mono = accepted_at_mono + min(max_active_duration, local_cap)` using checked arithmetic;
16. create an empty controller replay state; and
17. emit a lease-activation evidence event.

A failure at any step leaves no active lease. A failed durable commit leaves the
challenge pending; if snapshot installation succeeded before an external-anchor
failure, recovery may conservatively complete and spend the higher term. An
unexpected challenge-consume failure after a successful term commit likewise spends
the term without activating the lease. Specify and test both edges.

### `AuthorityRevocationV1`

Use one signed revocation form for mission leases, admissions, controller signing keys, and policy packages, with an explicit subject type. A revocation should carry an issuer-monotonic `revocation_epoch` and either a specific object ID/digest or a `revoke_terms_at_or_below` cutoff.

Gate processes revocation on a control-priority queue. Revocation of an active lease immediately prevents new ALLOW decisions. Whether Gate also requests a plant transition is a separately configured response; revocation must not depend on evidence delivery.

### `HaldirIntentV1`

#### Purpose

The intent is a signed request for a semantic action. It is not an NCP frame. It contains no final NCP stream sequence, final publisher timestamp, NCP plant authority, or serialized final frame.

#### Initial command profile

Keep the first profile intentionally small:

```rust
pub enum RequestedActionV1 {
    Hold {
        requested_validity_ms: NonZeroU32,
    },
    VelocityLocalNed {
        north_mm_s: i32,
        east_mm_s: i32,
        down_mm_s: i32,
        requested_validity_ms: NonZeroU32,
    },
}
```

Adding takeoff, land, mode change, arming, waypoint upload, or trajectory segments should require a new reviewed action class and a plant-specific state machine. Do not encode them as magic velocity vectors or free-text command names.

Use fixed-point integer units in the signed semantic object. The NCP adapter performs the one documented conversion to NCP's wire representation using checked range conversion and an explicit rounding rule. The decision receipt binds both the fixed-point semantic digest and exact output bytes.

#### Fields

```rust
pub struct HaldirIntentV1 {
    pub message_kind: FixedString<"haldir.intent">,
    pub schema_major: u16,
    pub schema_minor: u16,

    pub controller_id: ControllerId,
    pub controller_instance_id: [u8; 16],
    pub controller_signing_key_id: KeyId,
    pub actual_intent_key: BoundedAscii<256>,

    pub gate_id: GateId,
    pub gate_boot_id: GateBootId,
    pub realm: AsciiId<64>,
    pub vehicle_id: VehicleId,
    pub mission_id: MissionId,
    pub ncp_session: NcpSessionIdentityV1,

    pub mission_lease_id: MissionLeaseId,
    pub mission_lease_term: NonZeroU64,
    pub admission_id: AdmissionId,
    pub admission_digest: DigestV1,
    pub controller_bundle_digest: DigestV1,
    pub backend_profile_digest: DigestV1,

    pub intent_position: HaldirIntentPositionV1,
    pub controller_t_ns: u64,
    pub primary_source: NcpSourceRefV1,
    pub input_watermarks: BoundedVec<NcpSourceRefV1, 8>,
    pub action: RequestedActionV1,
    pub controller_context_digest: Option<DigestV1>,
}

pub struct NcpSourceRefV1 {
    pub source_key: BoundedAscii<256>,
    pub stream_epoch: CanonicalUuidV4String,
    pub stream_seq: NonZeroU64,
}
```

`actual_intent_key` is the concrete key the controller believes it is signing for. Gate compares it to the actual received sample key; it never trusts a wildcard subscription selector or key suffix alone.

`controller_t_ns` is local to the controller intent epoch. Gate may require it to be nondecreasing for diagnostics, but Gate does not compare it directly with Gate time and does not derive authority freshness from it.

`primary_source` identifies the NCP frame that directly drove the action. Gate finds that exact frame in its independently populated trusted state cache. `input_watermarks` can name additional bounded inputs for fusion, but the first profile should either prohibit them or define exact semantics. Gate sets the final NCP `source` and `source_t` from its trusted cached source, not from controller-supplied time.

#### Intent evaluation order

An intent should pass these checks in this order so cheap, side-effect-free failures precede expensive or stateful work:

1. transport sample and actual key available;
2. raw size and per-principal token-bucket check;
3. bounded COSE/CBOR structural parse;
4. protected header and content-type check;
5. key lookup, role check, revocation check, signature verification;
6. canonical re-encoding equality;
7. schema and identifier validation;
8. actual key equals signed exact intent key;
9. controller identity and key match configured principal binding;
10. Gate ID/boot ID, realm, vehicle, mission, and NCP session pair match current state;
11. active lease ID/term and admission ID/digest match exactly;
12. bundle and backend profile match the admission and lease;
13. controller intent epoch/sequence passes replay state;
14. primary source exists in Gate's cache and is current;
15. all required policy state is available and fresh;
16. action shape, units, range, and checked conversion are valid;
17. deterministic native policy evaluates;
18. optional Cedar coarse authorization evaluates with no diagnostics;
19. effective output validity is computed;
20. Gate output sequence is allocated and the NCP frame is built;
21. the exact output passes the pinned NCP validator;
22. output is published and evidence stages are emitted.

Checks 1–12 must not advance replay state. Check 13 should use a two-phase replay decision: reserve the candidate under the actor lock, then commit it only according to the documented denial semantics. The recommended rule is that any correctly signed, correctly scoped fresh intent consumes its intent sequence even when mission policy denies it. Otherwise an attacker or buggy controller can repeatedly retry the same expensive denied input. Malformed or wrong-authority traffic does not alter replay state.

### Controller intent replay state

Maintain per active lease:

```rust
pub struct ControllerReplayState {
    pub active_epoch: Option<IntentEpoch>,
    pub last_seq: u64,
    pub retired_epochs: BoundedSet<IntentEpoch, MAX_RETIRED_EPOCHS>,
    pub accepted_or_denied_count: u64,
}
```

Rules:

- first valid scoped intent activates its epoch at sequence one unless the profile explicitly permits a higher initial sequence;
- same epoch and `seq <= last_seq` is replay/stale and is rejected with no liveness effect;
- same epoch and `seq > last_seq` is fresh; gaps are recorded but need not deny unless policy requires continuous intent delivery;
- a different epoch is accepted only through an explicit controller-instance transition authorized by the active lease or a fresh lease;
- the old epoch is added to retired tombstones;
- a retired epoch always rejects;
- tombstone overflow causes lease quiesce or requires a fresh lease; it never evicts an arbitrary old epoch and reopens replay;
- lease expiry or revocation retires the active epoch and destroys its ability to influence output.

For the MVP, allow one intent epoch per lease and require a fresh lease after controller restart. This is simpler and stronger than an in-lease epoch-transition protocol.

### `ControllerBundleManifestV1`

#### Purpose

The manifest is the content-addressed, reconstructable description of a controller within one declared admission profile. It should extend Engram's existing artifact governance rather than replace it.

#### Minimum profile-complete content

For a fixed-weight SNN controller, include:

- graph format and schema version;
- ordered node/population definitions and stable IDs;
- neuron and synapse model identifiers with parameter units;
- complete projection topology;
- complete weights and delays or content-addressed immutable tensors;
- initial state and reset semantics;
- simulation/inference time step and scheduling semantics;
- deterministic seed policy and every stochastic source;
- input encoder and normalization parameters;
- output decoder, aggregation window, tie-breaking, saturation, and no-output behavior;
- coordinate-frame and unit mapping;
- controller update cadence and decimation policy;
- numerical precision requirements;
- NIR graph digest and exporter version when NIR is used;
- backend-independent test-vector digest;
- allowed backend transformation classes;
- source tree/release provenance and builder digest;
- explicit list of opaque code dependencies, which must be empty for a profile-complete claim.

#### Example shape

```rust
pub struct ControllerBundleManifestV1 {
    pub message_kind: FixedString<"haldir.controller_bundle">,
    pub schema_major: u16,
    pub schema_minor: u16,
    pub controller_id: ControllerId,
    pub bundle_id: [u8; 16],
    pub admission_profile_id: AsciiId<64>,
    pub logical_graph: ArtifactRefV1,
    pub topology: ArtifactRefV1,
    pub parameter_tensors: BoundedVec<ArtifactRefV1, 64>,
    pub codec: CodecContractV1,
    pub time_contract: ControllerTimeContractV1,
    pub reset_contract: ResetContractV1,
    pub stochastic_contract: StochasticContractV1,
    pub nir_artifact: Option<ArtifactRefV1>,
    pub conformance_vectors: ArtifactRefV1,
    pub build_provenance: ArtifactRefV1,
    pub opaque_dependencies: BoundedVec<ArtifactRefV1, 16>,
}
```

The manifest is profile-complete only when a clean-room builder can reconstruct the admitted controller from declared immutable artifacts without importing hidden topology, weights, codec logic, or arbitrary callbacks from the original repository.

### `ControllerAdmissionProfileV1`

The profile defines the subset for which Haldir makes a semantic identity claim. It should contain:

- permitted graph primitives and neuron/synapse models;
- maximum nodes, projections, tensor bytes, fan-in/fan-out, and recurrent depth as applicable;
- permitted time steps and scheduling rules;
- supported encoder/decoder forms;
- prohibited arbitrary code hooks;
- numeric precision and quantization rules;
- permitted transformations, such as weight quantization or time-constant discretization;
- required backend compilation diagnostics;
- required behavior scenarios, seeds, and held-out split procedure;
- action-level and plant-level equivalence metrics;
- pre-registered thresholds and confidence procedure;
- mandatory adversarial mutations and field-ablation tests;
- exact admission tool versions and trust roots.

Use multiple named profiles rather than silently broadening one profile. For example:

- `fixed-weight-lif-control-v1`;
- `fixed-weight-lif-control-nir-v1`;
- `xylo-constrained-lif-control-v1`.

A controller outside a profile may still run through Gate under identity/mission authorization, but Haldir must label it `OPAQUE_CONTROLLER` and must not claim semantic bundle admission.

### `BackendCompilationReceiptV1`

This receipt records a transformation from a logical admitted bundle to an executable backend profile:

```rust
pub struct BackendCompilationReceiptV1 {
    pub message_kind: FixedString<"haldir.backend_compilation">,
    pub tool_id: AsciiId<64>,
    pub tool_version_digest: DigestV1,
    pub input_bundle_digest: DigestV1,
    pub input_nir_digest: Option<DigestV1>,
    pub backend_family: AsciiId<64>,
    pub backend_version_digest: DigestV1,
    pub target_profile_id: AsciiId<64>,
    pub compiler_options_digest: DigestV1,
    pub executable_artifact_digest: DigestV1,
    pub mapping_report_digest: DigestV1,
    pub quantization_report_digest: Option<DigestV1>,
    pub unsupported_or_approximated_features: BoundedVec<FeatureDiagnosticV1, 64>,
    pub deterministic_build: bool,
    pub conformance_run_digest: DigestV1,
}
```

A successful compiler exit is not enough. Admission should fail when a mandatory primitive is approximated outside the profile, when mapping diagnostics are missing, when the executable digest is not bound, or when conformance evidence does not meet pre-registered criteria.

### `AdmissionRecordV1`

The admission authority signs the exact relation it approves:

```text
logical bundle
+ admission profile
+ backend compilation/execution profile
+ codec/time/reset contracts
+ conformance evidence corpus and thresholds
+ validity/revocation epoch
= admitted controller deployment relation
```

An admission should be backend-specific unless the evidence justifies a narrowly defined backend family. Do not authorize “this model on any NIR backend.” Authorize “this bundle, transformed by this pinned toolchain into this backend profile, under these runtime parameters and test relation.”

### `BackendExecutionProfileV1`

A backend execution profile names the exact runtime semantics under which an executable controller is admitted. It is separate from the logical controller bundle because the same graph can be transformed differently by NEST, another simulator, an emulator, or a hardware mapper.

```rust
pub struct BackendExecutionProfileV1 {
    pub message_kind: FixedString<"haldir.backend_execution_profile">,
    pub schema_major: u16,
    pub schema_minor: u16,
    pub profile_id: AsciiId<64>,
    pub profile_revision: NonZeroU64,
    pub backend_family: AsciiId<64>,
    pub backend_release_digest: DigestV1,
    pub runtime_environment_digest: DigestV1,
    pub executable_artifact_digest: DigestV1,
    pub logical_bundle_digest: DigestV1,
    pub compilation_receipt_digest: Option<DigestV1>,
    pub numeric_profile: NumericExecutionProfileV1,
    pub scheduling_profile: SchedulingProfileV1,
    pub reset_profile: ResetExecutionProfileV1,
    pub codec_digest: DigestV1,
    pub resource_limits: BackendResourceLimitsV1,
    pub allowed_runtime_flags_digest: DigestV1,
    pub hardware_target: Option<HardwareTargetRefV1>,
}
```

The minimum semantic content includes:

- backend name and exact source/package/container digest;
- Python/Rust/native runtime and dependency lock digests;
- numerical type, rounding, saturation, and quantization behavior;
- simulation time step and update ordering;
- event batching, decimation, and output-window semantics;
- initial state, reset, and deterministic seed behavior;
- input and output codec identity;
- thread/device/resource limits;
- target hardware family and configuration digest when applicable;
- all approximated or unsupported features.

A backend profile is immutable. A changed runtime flag, library build, mapping, quantization table, device configuration, or codec creates a new digest and requires a new admission or an explicitly pre-authorized transformation relation.

### `PolicyBundleV1`

The deployment policy is a signed immutable package, not loose TOML read by the hot path. The package binds both declarative limits and the exact evaluator implementation/profile.

```rust
pub struct PolicyBundleV1 {
    pub message_kind: FixedString<"haldir.policy_bundle">,
    pub schema_major: u16,
    pub schema_minor: u16,
    pub policy_id: AsciiId<64>,
    pub policy_revision: NonZeroU64,
    pub issuer_id: AsciiId<64>,
    pub issuer_key_id: KeyId,
    pub native_policy_profile: AsciiId<64>,
    pub native_policy_parameters: NativePolicyParametersV1,
    pub mission_phase_graph: MissionPhaseGraphV1,
    pub required_state_sources: BoundedVec<RequiredStateSourceV1, 16>,
    pub optional_advisory_sources: BoundedVec<AdvisorySourceRuleV1, 16>,
    pub safe_action_profile_ref: SafeActionProfileRefV1,
    pub cedar_bundle: Option<ArtifactRefV1>,
    pub parser_limits: ParserLimitsV1,
    pub queue_limits: QueueLimitsV1,
    pub timing_limits: TimingLimitsV1,
    pub self_test_vectors_digest: DigestV1,
    pub policy_source_digest: DigestV1,
}
```

Validation rules:

1. The package signer must have the `POLICY_AUTHORITY` role for the deployment profile.
2. `policy_revision` must be greater than the stored highest accepted revision for the same `policy_id` unless the package exactly matches the already active digest.
3. Every numeric field must be bounded, use explicit fixed-point units, and pass cross-field consistency checks.
4. A policy may narrow NCP/Crebain safety limits but cannot claim to widen a receiver-enforced limit.
5. Every required state source has an exact key, kind, expected publisher role, units/frame contract, maximum age, and uncertainty rule.
6. Every mission phase transition is explicit; unknown phases and transitions deny.
7. The referenced safe-action profile must be recognized by Crebain for the exact vehicle profile before Gate enters ACTIVE.
8. Optional Cedar policy is signed and digested inside the package. A Cedar evaluation diagnostic converts the whole coarse-authorization result to DENY.
9. Gate runs all package self-test vectors before activation.
10. Activation is atomic per vehicle actor. An intent is evaluated entirely under one immutable policy snapshot.

Policy rollback is prohibited by default. Emergency rollback requires a separately signed rollback authorization naming the exact prior digest and reason; it still creates a new monotonically increasing policy revision.

### `SafeActionProfileRefV1`

Gate refers to, but does not implement, the vehicle-specific plant fallback:

```rust
pub struct SafeActionProfileRefV1 {
    pub profile_id: AsciiId<64>,
    pub profile_revision: NonZeroU64,
    pub vehicle_profile_id: AsciiId<64>,
    pub crebain_profile_digest: DigestV1,
    pub trigger_conditions_digest: DigestV1,
    pub declared_safe_region_digest: DigestV1,
    pub validation_evidence_digest: DigestV1,
}
```

The reference proves that Gate and Crebain agree which profile is configured. It does not make Gate responsible for executing the fallback. The profile's full definition lives with the plant integration and includes:

- command-expiry trigger;
- explicit stop/hold trigger where supported;
- controller/Gate/session loss behavior;
- actuator command or flight-mode transition;
- state prerequisites and failure branches;
- declared safe region rather than a vague “safe” adjective;
- measured transition-time distribution and test environment;
- independent operator stop for any physical experiment.

For the deterministic reference plant, the first profile MAY be `reference-kinematic-hold-v1`, with an exact model-level transition to zero velocity and position hold. That result MUST NOT be reused as evidence for PX4 or a physical vehicle.

### `TrustedStateSnapshotV1`

This is an internal canonical decision input. It is not accepted from a controller and is not necessarily published as a wire message.

```rust
pub struct TrustedStateSnapshotV1 {
    pub snapshot_id: [u8; 16],
    pub gate_boot_id: GateBootId,
    pub vehicle_id: VehicleId,
    pub ncp_session: NcpSessionIdentityV1,
    pub captured_mono_ns: u64,
    pub primary_source: VerifiedSourceStateV1,
    pub auxiliary_sources: BoundedVec<VerifiedSourceStateV1, 15>,
    pub kinematic_state: KinematicStateFixedV1,
    pub uncertainty: StateUncertaintyFixedV1,
    pub mission_phase: AsciiId<64>,
    pub plant_mode: AsciiId<64>,
    pub advisory_evidence: BoundedVec<AdvisoryEvidenceRefV1, 16>,
    pub canonical_digest: DigestV1,
}
```

Each `VerifiedSourceStateV1` retains:

- actual received NCP key;
- authenticated transport principal where available;
- exact session pair;
- source stream epoch and sequence;
- source publisher time and Gate receive time;
- NCP validity result;
- frame, units, and codec/profile identifier;
- finite bounded state values;
- uncertainty/covariance representation and provenance;
- payload digest and canonical normalized-state digest.

Gate constructs the snapshot under the per-vehicle actor from independently ingested state. The controller may name a source position, but cannot supply the state values used for policy. Snapshot construction fails when a required source is absent, stale, wrong-session, wrong-principal, invalid, geometrically incompatible, or outside its bounded conversion domain.

### `AdvisoryEvidenceRefV1`

This type carries Galadriel or another monitor result without granting it authority:

```rust
pub struct AdvisoryEvidenceRefV1 {
    pub producer_id: AsciiId<64>,
    pub evidence_kind: AsciiId<64>,
    pub evidence_schema: AsciiId<64>,
    pub evidence_digest: DigestV1,
    pub source_positions: BoundedVec<NcpSourceRefV1, 8>,
    pub received_mono_ns: u64,
    pub status: AdvisoryStatusV1,
    pub calibrated_for_policy: bool,
}

pub enum AdvisoryStatusV1 {
    NominalAdvisory,
    AttributedInconsistency,
    BroadDegradation,
    UnclassifiedAnomaly,
    InsufficientEvidence,
    StateUnusable,
    ProducerError,
}
```

Rules:

- `NominalAdvisory` never grants ALLOW or relaxes a limit.
- `InsufficientEvidence` never converts to nominal.
- `StateUnusable` may become a deny-only policy input only when `calibrated_for_policy` is true and the signed policy names the producer/profile.
- unknown statuses, schema drift, bad signature, wrong session/source, or stale evidence are ignored for an optional source and deny for a required source.
- Gate records the exact evidence digest but does not copy unbounded detector diagnostics into receipts.

### `PlantPublicationAuthorityStateV1`

The runtime must distinguish the capability available in NCP `v0.8.0` from a future wire-level plant-authority lease. It MUST NOT use one ambiguous boolean such as `has_authority` for both.

```rust
pub enum PlantPublicationAuthorityStateV1 {
    Unavailable {
        reason: PlantPublicationUnavailableReasonV1,
    },
    AclExclusiveV1 {
        gate_transport_principal: PrincipalId,
        final_route_digest: DigestV1,
        certificate_fingerprint: DigestV1,
        acl_policy_digest: DigestV1,
        verified_at_mono_ns: u64,
        compatibility: FixedString<"PRE_AUTHORITY_ACL_ONLY">,
    },
    NcpLeaseV1 {
        gate_transport_principal: PrincipalId,
        final_route_digest: DigestV1,
        session: NcpSessionIdentityV1,
        authority_term: NonZeroU64,
        lease_id: AuthorityLeaseId,
        authorized_output_epoch: CanonicalUuidV4String,
        expires_mono_ns: Option<u64>,
        ncp_compatibility_id: NcpCompatibilityId,
    },
}
```

`AclExclusiveV1` is deployment evidence that one authenticated Gate principal alone is permitted to publish the final route. It is not a plant-issued NCP lease and must never be serialized as one. `NcpLeaseV1` is unavailable until a reviewed upstream NCP release defines it. Receipts and status always record which variant authorized publication.

### `GateStatusV1`

Gate publishes a signed, non-command status object for operators, orchestration, and Cortexel-style visualization:

```rust
pub struct GateStatusV1 {
    pub message_kind: FixedString<"haldir.gate_status">,
    pub gate_id: GateId,
    pub gate_boot_id: GateBootId,
    pub status_stream: HaldirStatusPositionV1,
    pub vehicle_id: VehicleId,
    pub process_state: GateProcessStateV1,
    pub ncp_session: Option<NcpSessionIdentityV1>,
    pub output_epoch: Option<CanonicalUuidV4String>,
    pub mission_lease_id: Option<MissionLeaseId>,
    pub admission_id: Option<AdmissionId>,
    pub policy_snapshot_digest: DigestV1,
    pub state_readiness: StateReadinessV1,
    pub plant_publication_state: PlantPublicationAuthorityStateV1,
    pub evidence_health: EvidenceHealthV1,
    pub last_decision_id: Option<DecisionId>,
    pub emitted_mono_ns: u64,
}
```

Status is read-only and MUST NOT contain private keys, raw certificates, secret paths, full controller payloads, or an administrative action token. A stale status does not prove Gate liveness; consumers validate its own status stream position and freshness. Cortexel/other UIs consume status through an observer identity that has no PUT authority.

### `DeploymentPackageV1`

Gate startup consumes one signed deployment package that binds all configuration required to make authority decisions:

```rust
pub struct DeploymentPackageV1 {
    pub message_kind: FixedString<"haldir.deployment_package">,
    pub deployment_id: AsciiId<64>,
    pub deployment_revision: NonZeroU64,
    pub profile_class: DeploymentClassV1,
    pub gate_id: GateId,
    pub realm: AsciiId<64>,
    pub vehicles: BoundedVec<VehicleDeploymentV1, 32>,
    pub trust_store: TrustStoreManifestV1,
    pub policy_artifacts: BoundedVec<ArtifactRefV1, 32>,
    pub admission_snapshot: ArtifactRefV1,
    pub revocation_snapshot: ArtifactRefV1,
    pub ncp_compatibility: NcpCompatibilityRecordV1,
    pub transport_profile: SecureTransportProfileV1,
    pub evidence_profile: EvidenceSpoolProfileV1,
    pub process_hardening_profile: ProcessHardeningProfileV1,
    pub source_ledger_digest: DigestV1,
}
```

`profile_class` is one of `Development`, `ExperimentalCanary`, `AssuranceSimulation`, or a later reviewed class. The process MUST refuse to emit assurance-grade receipts under `Development`. Production-like classes reject debug bypasses, unsigned intents, missing mTLS, unpinned NCP, unknown safe-action profiles, empty trust roots, or writable arbitrary plugin paths.

### `DecisionReceiptV1`

#### Core fields

```rust
pub struct DecisionReceiptV1 {
    pub message_kind: FixedString<"haldir.decision_receipt">,
    pub decision_id: DecisionId,
    pub gate_id: GateId,
    pub gate_boot_id: GateBootId,
    pub vehicle_id: VehicleId,
    pub mission_id: MissionId,
    pub ncp_session: NcpSessionIdentityV1,

    pub received_key_digest: DigestV1,
    pub raw_envelope_digest: DigestV1,
    pub payload_digest: Option<DigestV1>,
    pub semantic_intent_digest: Option<DigestV1>,
    pub controller_id: Option<ControllerId>,
    pub controller_intent_position: Option<HaldirIntentPositionV1>,
    pub mission_lease_id: Option<MissionLeaseId>,
    pub admission_digest: Option<DigestV1>,
    pub source: Option<NcpSourceRefV1>,

    pub state_snapshot_digest: Option<DigestV1>,
    pub policy_snapshot_digest: DigestV1,
    pub decision: DecisionOutcomeV1,
    pub reason_codes: BoundedVec<DecisionReasonCodeV1, 32>,
    pub effective_validity_ms: Option<u32>,

    pub gate_output_stream: Option<NcpStreamPositionV1>,
    pub output_frame_digest: Option<DigestV1>,
    pub transformation_relation: Option<TransformationRelationV1>,

    pub received_mono_ns: u64,
    pub decided_mono_ns: u64,
    pub publish_stage: PublishStageV1,
}
```

Use stable machine-readable reason codes such as:

- `DENY_WRONG_ACTUAL_KEY`;
- `DENY_SIGNATURE_INVALID`;
- `DENY_SESSION_STALE`;
- `DENY_GATE_BOOT_MISMATCH`;
- `DENY_LEASE_ABSENT`;
- `DENY_LEASE_EXPIRED`;
- `DENY_ADMISSION_REVOKED`;
- `DENY_INTENT_REPLAY`;
- `DENY_SOURCE_UNKNOWN`;
- `DENY_SOURCE_STALE`;
- `DENY_STATE_UNAVAILABLE`;
- `DENY_COMMAND_RANGE`;
- `DENY_SLEW`;
- `DENY_DUTY_LIMIT`;
- `DENY_PHASE_RULE`;
- `DENY_POLICY_DIAGNOSTIC`;
- `DENY_OVERLOAD`;
- `ERROR_INTERNAL_FAULT`.

Human-readable diagnostics can be attached outside the signed core or referenced by a digest. Never place secrets, raw certificates, or unbounded parser errors in the receipt.

#### Evidence stage model

Use an append-only series keyed by `decision_id` rather than rewriting one record in place:

1. `DECIDED_DENY` or `DECIDED_ALLOW`;
2. `OUTPUT_PREPARED` with exact bytes/stream position;
3. `PUBLISH_CALLED`;
4. `PUBLISH_RETURNED_OK` or `PUBLISH_RETURNED_ERROR`;
5. `CREBAIN_RECEIVED`;
6. `CREBAIN_ACCEPTED` or `CREBAIN_REJECTED`;
7. `ADAPTER_APPLIED` or `ADAPTER_FAILED`;
8. `PLANT_OBSERVED` when a measured response is correlated;
9. `UNKNOWN_AFTER_PUBLISH` when a crash prevents determining later stages.

Each producer signs only stages it directly observes. Gate cannot sign `ADAPTER_APPLIED`; Crebain cannot assert what policy Gate evaluated unless it verifies the Gate receipt.

### `ApplicationEvidenceV1`

Crebain evidence should bind:

- Gate `decision_id` carried in a non-authoritative correlation field or side-channel mapping;
- exact final NCP frame digest;
- current session, Gate publisher, stream position, source, and publication-authorization variant (`AclExclusiveV1` now or future NCP lease);
- receive time and local validation result;
- ActionBuffer insertion/selection result;
- plant tick at which the command became active;
- adapter invocation result;
- safe-action transition, when applicable;
- measured state reference after application.

This evidence is essential for operational validation but does not change Gate's authorization result.

## Gate runtime design

### Process decomposition

The command path should be one deployable Rust service with sharply separated internal components:

```text
                    +-----------------------------+
NCP session/status ->| control-plane reactor       |
mission/admission -->| revocation + lease manager  |
                    +---------------+-------------+
                                    |
NCP sensor/state ---> state cache --+-- immutable decision snapshot
                                    |
controller intent -> ingress limits -> signature verifier
                                    |
                                    v
                         per-vehicle decision actor
                         - session/lease/replay
                         - native policy
                         - optional Cedar
                         - output allocation
                                    |
                                    v
                           pinned NCP adapter
                                    |
                                    v
                          final-key publisher
                                    |
                      +-------------+-------------+
                      |                           |
                local evidence spool       Crebain acks/events
```

Recommended crates and responsibilities:

- `haldir-contracts`: stable pure data types, canonical encoding, schemas, golden vectors;
- `haldir-crypto`: COSE profile, key roles, trust store, revocation verification;
- `haldir-core`: pure decision inputs/outputs and invariant-enforcing types;
- `haldir-state`: bounded state machines, actor state, time abstraction, anti-rollback store;
- `haldir-policy-native`: checked fixed-point predicates and bounded history;
- `haldir-policy-cedar`: optional coarse authorization adapter, disabled by default;
- `haldir-admission`: manifest/profile/admission validation, no neural runtime execution in Gate;
- `haldir-ncp08`: exact pinned NCP conversion and validation;
- `haldir-transport-zenoh`: actual-key delivery, subscriptions, publishing, reconnect behavior;
- `haldir-evidence`: append-only signed events and bounded spool;
- `haldir-gate`: process composition, configuration, lifecycle, health;
- `haldir-range`: fixtures, adversarial campaigns, deterministic plant orchestration;
- `haldir-ctl`: offline inspect/verify tooling;
- `haldir-fixtures`: test keys, vectors, manifests, policies, and known-bad corpus.

Neural conversion and execution adapters should live outside the Gate binary, for example under `tools/admission/nest`, `tools/admission/nir`, and `tools/admission/rockpool`.

### Thread and actor model

Use one ordered decision actor per vehicle. All mutable authorization state for that vehicle is owned by that actor:

- current session pair;
- current Gate publication authorization (`AclExclusiveV1` now; a future NCP plant-authority lease in a later compatibility profile);
- active mission lease;
- controller replay state;
- current Gate output epoch and sequence;
- bounded action history for slew and duty;
- process fault/quiesce state;
- current immutable policy/admission snapshots.

Transport callbacks should not mutate those fields directly. They convert a bounded sample into an internal event and submit it to the actor.

A practical initial threading model is:

1. one control-plane task for session, authority, lease, admission, policy, and revocation events;
2. one trusted-state ingest task that parses and validates NCP state into bounded caches;
3. a small fixed signature-verification pool;
4. one single-threaded actor executor shard for a bounded number of vehicles;
5. one output publisher task with a bounded queue per vehicle;
6. one evidence spool task;
7. one low-priority metrics/export task that cannot block the actor.

The signature pool may complete out of order. The vehicle actor must order accepted signed intents by their explicit intent position and reject stale completions. Do not allow verification completion order to become command order.

For the first one-vehicle MVP, eliminate the pool and perform verification in the actor if measured latency is acceptable. Simplicity is a security feature until profiling proves the need for parallelism.

### Priority classes

Use bounded priority queues or separate channels:

1. **highest:** session close/generation change, NCP authority revocation, mission/admission/key revocation, Gate shutdown;
2. **high:** plant safe-action acknowledgement and critical fault events;
3. **normal:** controller intents and trusted state frames;
4. **low:** noncritical evidence shipping, metrics, UI/status queries.

A controller flood must not prevent a revocation or session-close event from being processed. Reserve capacity for highest-priority events and test it under saturation.

### Configuration model

Gate starts from one signed, immutable deployment package containing:

- Gate ID and realm;
- vehicle profiles;
- exact symbolic-to-concrete NCP keys created by the pinned NCP key builder;
- exact Haldir intent keys;
- trust roots and key-role mappings;
- policy package and digest;
- admission trust root and revocation state;
- timing, queue, parser, rate, and state-cache limits;
- safe-action profile references;
- exact NCP compatibility identifier;
- feature flags, with Cedar and future NCP increments explicit;
- evidence-spool capacity and full-disk behavior;
- declared deployment profile ID.

Reject unknown configuration fields and insecure defaults. A production-profile process must not start when:

- mTLS material is missing;
- the final-key ACL test has not been provisioned;
- trust roots are empty;
- an NCP compatibility ID is unpinned;
- parser/queue limits are absent;
- the safe-action profile is unknown to Crebain;
- direct-path closure is not asserted by the deployment package;
- a debug bypass or unsigned-intent mode is enabled.

Development modes must use visibly different profile IDs and cannot emit production-grade receipts.

## Gate startup and shutdown sequence

### Cold startup

Implement startup as an explicit state machine, not a series of best-effort initializers:

1. **Load binary identity.** Record release digest, build provenance, feature set, and process arguments.
2. **Load and verify deployment package.** Verify signature, schema, policy digest, NCP compatibility ID, and trust roots before opening subscriptions.
3. **Lock down process.** Drop unnecessary privileges; set resource limits; configure read-only filesystem, dedicated data/spool directories, and platform sandboxing.
4. **Initialize monotonic time source.** Read twice, verify nondecreasing behavior, and construct an injectable clock abstraction for tests.
5. **Initialize CSPRNG.** Generate `gate_boot_id`, controller-challenge state, evidence stream epoch, and candidate Gate output epochs.
6. **Open anti-rollback store.** Verify its authenticated format and monotonic term indexes. Corruption causes `FAULT_LATCHED`, not a reset to zero.
7. **Load admission and revocation snapshots.** Verify all signatures and build immutable indexes.
8. **Load policy snapshot.** Run self-tests and golden policy vectors; hash the exact executable policy package.
9. **Initialize evidence spool.** Recover complete records, truncate only an incomplete tail according to a documented journal format, and emit a recovery event.
10. **Connect secure transport.** Verify the expected router/server identity and configured realm.
11. **Subscribe control plane.** Session and authority events before controller intents.
12. **Subscribe trusted state.** Begin filling state cache but remain non-active.
13. **Discover current NCP session pair.** Never infer generation from a key.
14. **Mint Gate output epoch.** Bind it to the current session candidate but do not publish a command.
15. **Establish plant publication authorization.** For NCP `v0.8.0`, verify the exact Gate mTLS principal, final-route ACL, current session, and pre-authority stream-transition conditions. Under a future authority profile, additionally receive and validate an NCP authority lease naming or authorizing the new epoch.
16. **Publish signed Gate challenge.** Bind session, output epoch, policy, and NCP compatibility.
17. **Accept mission lease.** Use the full lease acceptance algorithm.
18. **Require state readiness.** Every mandatory state source has a fresh frame and required uncertainty metadata.
19. **Enter ACTIVE.** Only now may controller intents produce output.

Every transition emits a bounded status/evidence event. No startup step should publish a motion command merely to test connectivity. Use a non-actuating health path or the reference plant in development.

### Graceful shutdown

1. stop accepting new controller intents;
2. mark the active mission lease `REVOKING` locally;
3. optionally request the configured safe transition through the next Gate output sequence when session/authority remain valid;
4. wait only for a bounded local publish/ack interval, never indefinitely;
5. relinquish a future NCP plant-authority lease where supported and close the Gate final-route transport capability according to the deployment shutdown procedure;
6. close subscriptions and transport;
7. flush a bounded evidence tail according to policy;
8. zeroize application private-key material where the crypto provider permits;
9. exit.

If a graceful safe-transition publish fails, the plant must still reach its locally configured expiry/watchdog behavior. Shutdown logic must not reopen the lease or retry with a new arbitrary sequence.

### Abrupt crash

The safety argument for abrupt crash is:

- no new Gate commands are created;
- existing accepted command validity is bounded;
- Crebain's ActionBuffer/watchdog eventually stops selecting it;
- Crebain executes the plant-specific safe-action profile;
- on restart, Gate uses a new boot ID and output epoch and cannot reuse the old mission lease;
- before publishing again, it reacquires session state, verifies exclusive final-route publication capability, reacquires any authority lease required by the active profile, restores state readiness, and obtains a fresh mission lease.

Measure every term in this bound. Do not reduce it to “Gate crash causes HOLD within `ttl_ms`” unless the plant profile and measurements prove that exact behavior.

## Exact intent-to-command decision pipeline

### Input event

The internal event submitted to a vehicle actor should retain:

- exact actual routing key bytes;
- exact COSE envelope bytes;
- authenticated transport principal or a verified binding handle when the transport exposes it;
- local receive monotonic timestamp;
- transport metadata needed for diagnostics, bounded and non-authoritative;
- pre-verification rate-limit result.

The actor must never receive a deserialized intent without the exact raw bytes and actual key needed for evidence and binding checks.

### Pipeline with side-effect boundaries

#### Stage 0 — ingress admission

- Reject samples above the raw size limit.
- Apply per-principal, per-key, and global token buckets.
- Enforce a fixed number of outstanding verification jobs.
- Compute a cheap raw digest only after size acceptance.
- Do not allocate proportional to claimed internal lengths.

Outcome: `INGRESS_ACCEPTED` or `DENY_OVERLOAD/OVERSIZE`. No replay or lease state changes.

#### Stage 1 — bounded structural decode

- Parse only the expected COSE structure.
- Reject extra signatures, detached payloads, unsupported header forms, and trailing data.
- Enforce nesting and collection limits during decode.
- Parse protected headers before payload dispatch.

Outcome: structural candidate. No authority lookup beyond the bounded key ID.

#### Stage 2 — cryptographic verification

- Resolve `kid` to one key record.
- Require role `CONTROLLER_INTENT`.
- Check key validity and revocation snapshot.
- Verify COSE signature over protected headers, payload, and fixed external AAD.
- Re-encode payload deterministically and compare bytes.

Outcome: authenticated canonical payload or `DENY_SIGNATURE_INVALID/NONCANONICAL`.

#### Stage 3 — identity and routing binding

Require equality among:

- actual received key;
- signed exact intent key;
- configured key for the controller;
- ACL expectation for the authenticated transport principal;
- controller ID and signing-key binding in admission;
- vehicle/realm represented by configuration.

Do not derive identity only from a routing suffix. When NCP increment 3 exposes publisher identity, use it as an additional checked binding, not as a replacement for the application signature.

#### Stage 4 — current authority snapshot

Under the actor lock, capture one immutable snapshot of:

- Gate boot and process state;
- NCP session pair;
- Gate final-route publication authorization, optional future NCP authority lease, and output epoch;
- active mission lease and deadline;
- admission and revocation revision;
- policy snapshot;
- current trusted source/state cache generation;
- controller replay state and bounded action history.

A later control-plane event can invalidate this snapshot before commit. Therefore the actor must either remain single-threaded through decision/commit or compare an authorization revision number immediately before output allocation.

#### Stage 5 — scope checks

Require exact equality for Gate boot, session, vehicle, mission, lease, admission, bundle, backend profile, and controller key. Compute lease remaining time with checked monotonic arithmetic.

If session generation changed, invalidate the lease before producing a receipt. Stale-generation input must cause zero output and zero watchdog refresh.

#### Stage 6 — controller replay

Evaluate fresh/stale/epoch rules. For a correctly signed and correctly scoped fresh intent, reserve its sequence. Policy DENY consumes the sequence; an internal crash before commit is resolved conservatively on retry by denying the duplicate or requiring a higher sequence.

In the single-threaded actor, the simplest rule is to commit `last_seq` immediately after all authority/scope checks and before expensive stateful policy. This ensures one signed request is evaluated at most once. Record whether the consumed request was allowed or denied.

#### Stage 7 — source and state correlation

Lookup the exact primary NCP source position in Gate's trusted cache. Require:

- same current NCP session pair;
- exact source key allowed by lease and policy;
- source epoch/sequence exists and is not retired;
- source age at decision is within the effective freshness bound;
- required state components and uncertainty fields are present;
- state transform/frame metadata match the policy profile;
- no cache-generation race invalidated the source.

Gate takes `source_t` from the trusted NCP frame. It never accepts a controller-provided source timestamp as authoritative.

For fusion, define whether policy uses the primary source's state snapshot or a state snapshot assembled at decision time. Record exact input watermarks and a canonical state snapshot digest either way.

#### Stage 8 — semantic action validation

Before policy:

- match the action variant to the lease allowlist;
- validate coordinate frame;
- validate integer ranges and signs;
- reject checked-arithmetic overflow;
- reject an unsupported transform;
- require requested validity within hard protocol limits;
- normalize no values silently;
- derive typed quantities such as speed squared using wide checked integers;
- ensure the action can be converted exactly or under the profile's named rounding relation.

#### Stage 9 — deterministic native policy

Evaluate policy in a fixed order and collect bounded reason codes:

1. hard schema/profile checks;
2. session/authority/lease remaining-time checks;
3. source/state freshness and uncertainty;
4. mission phase and action-class rules;
5. absolute local-NED velocity bounds;
6. acceleration and slew from the last applied-or-accepted policy reference, as defined;
7. duty-cycle and continuous-motion windows;
8. geofence/region constraints under one explicit coordinate model;
9. phase transition guards;
10. minimum safe margin and degraded-state restrictions;
11. optional coarse ABAC.

Do not short-circuit in a way that makes timing reveal sensitive policy distinctions unless that is a meaningful threat. It is acceptable to short-circuit before expensive geometry after a hard authority denial.

#### Stage 10 — optional Cedar

Construct Cedar entities and context only from already validated typed values and derived booleans/integers. For example:

```text
principal = Controller::<controller_id>
action    = Action::VelocityLocalNed
resource  = Vehicle::<vehicle_id>
context   = {
  missionPhase: "inspection",
  admissionActive: true,
  sourceFresh: true,
  withinNativeBounds: true,
  leaseTerm: 42,
  speedMillimetersPerSecond: 750
}
```

Treat any nonempty diagnostic/error set as DENY even if Cedar's decision API reports Allow after skipping an errored policy. Pin Cedar version and policy AST digest. Do not fetch policies remotely on the hot path.

#### Stage 11 — effective validity calculation

Calculate:

```text
effective_validity_ms = min(
    intent.requested_validity_ms,
    lease.max_output_validity_ms,
    policy.max_output_validity_ms,
    remaining_lease_ms,
    remaining_source_freshness_ms,
    remaining_state_freshness_ms,
    remaining_ncp_authority_ms,       when represented,
    ncp_protocol_cap_ms,
    crebain_profile_cap_ms
)
```

Subtract a configured processing/publication safety margin. If the result is below the minimum useful validity, DENY rather than emit a frame that will be stale on arrival.

#### Stage 12 — output allocation

Only after an overall ALLOW:

1. confirm the authorization revision has not changed;
2. take the next Gate output sequence using checked increment;
3. construct the NCP session pair from current Gate state;
4. set Gate output stream epoch/sequence;
5. set final `t` from Gate's monotonic clock, scoped to the output epoch;
6. set `source` and `source_t` from the trusted cached primary source;
7. attach Gate's current NCP authority lease when defined;
8. convert the fixed-point semantic action under the named conversion relation;
9. set effective validity;
10. include only NCP fields permitted by the pinned schema;
11. serialize once and run the local NCP validator against exact final bytes.

If serialization or validation fails, latch an internal fault for that adapter/profile and do not publish. A controller cannot cause Gate to fall back to a less strict serializer.

#### Stage 13 — publish and evidence

Create an in-memory immutable output record containing:

- decision ID;
- input and semantic digests;
- exact output bytes and digest;
- Gate output stream position;
- authorization revision;
- decision timestamps.

Enqueue exact output bytes to the bounded publisher. The publisher must not reconstruct the frame from a mutable object. A transport retry uses the same exact bytes and stream sequence; a changed TTL or timestamp is a new logical output requiring the next sequence and a new decision or explicit refresh rule.

If the output queue is full, the decision becomes `ALLOW_NOT_PUBLISHED_OVERLOAD` or an internal DENY before sequence commit, according to the chosen allocation boundary. The recommended implementation reserves output-queue capacity before allocating the sequence. Once a sequence is allocated and exposed in evidence, never reuse it; a gap is safer than reuse.

## Gate-authored NCP output mapping

### Mapping table

| Final NCP field | Source |
| --- | --- |
| `ncp_version` / kind | pinned adapter constant |
| `session_id` | current Gate session snapshot |
| `session.generation` | current Gate session snapshot |
| `stream.epoch` | Gate output state |
| `stream.seq` | Gate output allocator |
| `source.epoch` / `source.seq` | verified primary source from Gate cache |
| `frame_id` | validated coordinate-frame id from the trusted primary source |
| `t` | Gate monotonic creation time |
| `source_t` | trusted source frame, when available |
| `authority.term` / `lease_id` | absent in NCP `v0.8.0`; populated only by a future adapter from a verified Gate-held NCP plant-authority lease |
| command body | checked conversion from `RequestedActionV1` |
| TTL/validity | computed effective minimum |
| publisher identity | transport/NCP binding to Gate, when increment 3 lands |

No final field comes from opaque controller-authored NCP bytes.

### Conversion relation

Document conversion as code and test vectors. For a velocity profile, for example:

```text
NCP linear component = fixed_point_mm_s / 1000.0
rounding = IEEE-754 round-to-nearest ties-to-even through the chosen Rust conversion
accepted input range = values whose converted finite representation remains within profile error
maximum component conversion error = precomputed bound
```

Where exact decimal-to-binary representation is impossible, receipts should say `FIXED_POINT_TO_NCP_FLOAT_V1`, not `IDENTITY`. Property tests must prove monotonicity, finiteness, bounds preservation, and error limits across the full accepted integer domain.

## Runtime state machines

### Gate process state

| State | Entry condition | Permitted behavior | Exit |
| --- | --- | --- | --- |
| `BOOTING` | process start | verify local assets only | `RECOVERING` or `FAULT_LATCHED` |
| `RECOVERING` | local assets valid | connect, recover spool, load session/state | `READY_NO_SESSION` |
| `READY_NO_SESSION` | no current session | no lease activation or output | `SESSION_BOUND` on valid session |
| `SESSION_BOUND` | current session known | acquire output authority, challenge, fill state | `ACTIVE` when all conjuncts hold |
| `ACTIVE` | authority + lease + state ready | evaluate intents and publish allowed outputs | `QUIESCING`, `SESSION_BOUND`, or `FAULT_LATCHED` |
| `QUIESCING` | shutdown/revocation/profile transition | no new ordinary intents; optional bounded transition | exit or `SESSION_BOUND` only through explicit reactivation |
| `FAULT_LATCHED` | invariant/internal trust failure | no ordinary output; expose local health | process restart after operator remediation |

Do not automatically clear `FAULT_LATCHED` because a later input looks valid.

### Session state

```text
UNBOUND
  -> BOUND(session_id, generation)
  -> CLOSING
  -> CLOSED
```

Any new generation for the same session ID invalidates active mission lease, controller replay state, output authority, pending challenges, and state snapshots from the old generation before side effects. The Gate output epoch for the old generation is retired.

### Mission lease state

```text
ABSENT -> PENDING_VERIFICATION -> ACTIVE
ACTIVE -> REVOKING -> REVOKED
ACTIVE -> EXPIRED
ACTIVE -> INVALIDATED_BY_SESSION
ACTIVE -> INVALIDATED_BY_POLICY
ACTIVE -> INVALIDATED_BY_ADMISSION
```

Only `ACTIVE` permits an ALLOW. `REVOKING` blocks new ordinary intents immediately even if an optional safe-transition output is pending.

### Controller stream state

For the MVP:

```text
NONE -> ACTIVE(epoch, last_seq)
ACTIVE -> RETIRED on lease end, controller restart, or explicit handoff
RETIRED -> never ACTIVE under the same lease
```

A fresh controller process obtains a fresh mission lease. This deliberately trades availability for a simpler replay proof.

### Gate output stream state

```text
UNAUTHORIZED(epoch)
  -> AUTHORIZED(epoch, seq=0)
  -> ACTIVE(epoch, seq=n)
  -> TRANSITION_PENDING(new_epoch)
  -> RETIRED(old_epoch)
```

In the NCP `v0.8.0` `PRE_AUTHORITY_ACL_ONLY` profile, `TRANSITION_PENDING` follows the exact upstream same-authenticated-publisher/current-session transition rules and waits until the prior stream is no longer live. Under a future authority profile, a new plant-authority lease names or authorizes the new epoch.

### Safe-transition state

```text
NONE
  -> REQUESTED(reason, profile)
  -> OUTPUT_PREPARED
  -> PUBLISHED
  -> CREBAIN_ACCEPTED
  -> APPLIED
```

Failure terminal states are:

- `PUBLISH_FAILED_EXPIRY_FALLBACK`;
- `UNKNOWN_AFTER_PUBLISH`;
- `CREBAIN_REJECTED_EXPIRY_FALLBACK`;
- `EXPIRED_WITHOUT_EXPLICIT_TRANSITION`.

The mission lease remains closed in every failure state. A failed transition never reopens ordinary command authority.

## Safe action, denial, and reversion

### Separate three concepts

1. **DENY:** Gate refuses to create a new command from the current intent.
2. **Explicit transition request:** Gate creates a new command/stop action under its next normal output sequence.
3. **Plant fallback:** Crebain/vehicle acts when no current command remains or when a local fault is detected.

These are not interchangeable.

### Plant-owned safe-action profile referenced by `SafeActionProfileRefV1`

Crebain should expose or configure a versioned profile containing:

- vehicle/plant class;
- states in which the profile is valid;
- trigger conditions: command expiry, Gate authority loss, ESTOP, session close, adapter fault;
- action sequence and limits;
- required state inputs and degraded behavior;
- maximum transition time assumptions;
- whether the action requires navigation validity;
- acknowledgement and measured-state criteria;
- simulation-only versus hardware-validated status.

Examples must be named narrowly:

- `reference-kinematic-hold-v1`;
- `px4-sitl-hold-v1`;
- `fixed_wing_profile_not_defined` rather than reusing zero velocity.

Gate policy references a safe-action profile ID but does not implement the low-level physical fallback.

### Bound to measure

For crash or revocation, report:

```text
last accepted command remaining validity
+ Crebain selection/watchdog period
+ safe-profile trigger delay
+ adapter/flight-controller command latency
+ plant transition time to the declared safe region
```

For an explicit transition, also report Gate detection/decision and transport delivery. Present median and tail measurements plus worst observed value under the campaign. Do not call the empirical maximum a formal worst case.

## Overload and availability policy

### Bounded degradation

Define overload behavior before testing:

- reject oversized input before signature verification;
- token-bucket each controller principal and key;
- reserve capacity for revocation/session events;
- maintain one latest trusted state per required stream plus a bounded history for source lookup;
- cap outstanding crypto jobs;
- cap actor mailbox and output queue;
- cap evidence spool bytes and records;
- refuse new lease activation when required durable state cannot be committed;
- on sustained command-path overload, stop creating new commands and let plant fallback occur.

### Evidence-spool full behavior

Two profiles are defensible:

- **safety-first operation:** continue bounded authorization while dropping only noncritical export copies, but retain a fixed local signed summary of the loss interval;
- **evidence-required operation:** enter controlled quiesce before the spool is completely full.

Choose one per deployment and test it. Never block the decision actor on an unavailable remote database.

### Cryptographic denial of service

Mitigations include:

- mTLS/ACL before application signature verification;
- exact key-to-principal mapping;
- small envelope limit;
- per-principal pre-verification token bucket;
- fixed verification concurrency;
- no certificate-chain building per intent—use a prevalidated key index;
- constant-size key IDs;
- cached revocation snapshots;
- a dedicated control-plane reserve.

A compromised allowed controller can still consume its allotted verification budget. The plant fallback must remain safe when Gate denies due to that budget.

## Native policy engine design

### Policy inputs

The pure policy core should accept one fully typed snapshot and return one bounded result. It must not perform network I/O, file I/O, dynamic plugin loading, wall-clock reads, or neural inference.

```rust
pub struct PolicyInputV1<'a> {
    pub now: MonoInstant,
    pub controller: &'a AdmittedControllerSnapshot,
    pub lease: &'a ActiveMissionLeaseSnapshot,
    pub session: &'a NcpSessionIdentityV1,
    pub plant_publication: &'a PlantPublicationAuthoritySnapshot,
    pub ncp_plant_authority: Option<&'a NcpPlantAuthoritySnapshot>,
    pub source: &'a TrustedSourceSnapshot,
    pub state: &'a VehicleStateSnapshot,
    pub requested_action: &'a RequestedActionV1,
    pub history: &'a BoundedActionHistory,
    pub mission_phase: &'a MissionPhaseState,
    pub policy: &'a NativePolicySnapshot,
}

pub struct PolicyResultV1 {
    pub outcome: AllowOrDeny,
    pub reason_codes: BoundedVec<DecisionReasonCodeV1, 32>,
    pub effective_limits: EffectiveLimitsV1,
    pub derived_context: CedarContextV1,
    pub state_snapshot_digest: DigestV1,
}
```

All constructors should enforce invariants so the evaluator cannot receive NaN, missing units, unknown coordinate frames, unchecked lengths, or expired authority objects.

### Numeric representation

Use integers and checked arithmetic in the policy core:

- position: millimetres in the profile's local coordinate frame, `i64`;
- linear velocity: millimetres per second, `i32` or `i64`;
- acceleration/slew: millimetres per second squared, `i64`;
- angle: milliradians, normalized only by an explicit checked function;
- angular velocity: milliradians per second;
- time: integer nanoseconds internally, integer milliseconds on contracts;
- uncertainty: nonnegative integer bounds in matching units;
- squared norms: `i128` where necessary to avoid overflow.

Never compute `sqrt` just to compare a vector magnitude with a bound. Compare squared quantities using checked wide multiplication:

```text
vx^2 + vy^2 + vz^2 <= max_speed^2
```

Reject on overflow. Do not saturate security comparisons because saturation can turn an out-of-range value into an allowed boundary value.

### Source/state freshness

For every policy-critical state component, track:

- source stream position;
- session pair;
- local receive monotonic time;
- source publisher time when present, diagnostic only unless a qualified synchronization profile exists;
- frame/coordinate metadata;
- uncertainty bound;
- validity flags;
- cache generation.

Freshness at decision is:

```text
now_mono - local_receive_mono <= effective_max_age
```

This measures residence at Gate, not end-to-end sensor age. A stronger profile may add a qualified source-time uncertainty relation, but it must not silently substitute unsynchronized clocks. Record both values when available.

If one required component is missing, from a stale session, or outside uncertainty limits, deny with a specific reason. Do not fill missing velocity from zero or reuse stale position after a session transition.

### Frame and geometry model

The first profile should support exactly one local navigation frame plus body-frame velocity. Define:

- axis orientation and handedness;
- origin and how it is established;
- transform source and freshness;
- whether altitude/down is positive or negative;
- polygon/volume boundary inclusion rule;
- uncertainty inflation rule;
- integer scaling and overflow bounds.

A conservative region check should inflate forbidden regions and shrink allowed regions by the position uncertainty plus configured safety margin. A point on an ambiguous boundary should deny.

For a velocity command, prospective region enforcement should evaluate the reachable displacement over effective validity, including state uncertainty and a conservative response model. Do not merely check current position. A simple first model is:

```text
reachable_axis = current_position
               + commanded_velocity * validity
               + bounded_tracking_error
               + position_uncertainty
```

Use an over-approximation. Document that it is a policy guard, not a verified flight-dynamics model.

### Slew and acceleration reference

Choose one reference and use it consistently:

- **last Gate-published command** is available immediately but may not have been accepted/applied;
- **last Crebain-accepted command** is stronger but introduces acknowledgement latency;
- **measured vehicle velocity** reflects the plant but may lag and be noisy.

For the deterministic MVP, use both:

1. command-to-command slew against the last Gate-published command;
2. state-to-command mismatch against fresh measured velocity.

Record which reference caused denial. Later profiles may use accepted/applied evidence but must define behavior when acknowledgements are delayed.

### Duty and continuous-motion windows

Maintain bounded ring buffers rather than unbounded histories. Example policy:

- window length: 10 seconds;
- maximum aggregate non-hold command validity: 6 seconds;
- maximum continuous motion without an accepted hold: 2 seconds;
- minimum hold interval before another burst: 500 ms.

Store intervals in Gate monotonic time. On every candidate action:

1. evict intervals ending before the window;
2. intersect remaining intervals with the window;
3. add the candidate effective interval;
4. sum using checked arithmetic;
5. deny if any cap is exceeded.

Decide whether an interval is charged on publish, Crebain acceptance, or application. The MVP should charge on publish because it is locally known and conservative. Do not refund duty because evidence was missing.

### Mission phase state machine

Do not represent mission phase as an arbitrary controller string. Phase is a Gate-owned state established by a signed management action or a trusted lifecycle event.

Example benign profile:

```text
PREFLIGHT -> READY -> INSPECTION -> RETURN -> HOLD -> COMPLETE
                  \-> DEGRADED -> HOLD
any state ---------> ABORTING -> HOLD
```

Each transition has:

- authorized issuer/action;
- source/state preconditions;
- permitted previous states;
- effects on active lease and allowed action classes;
- optional safe-transition requirement;
- evidence reason code.

Controller intent can request only actions permitted in the current Gate-owned phase. It cannot self-declare `mission_phase = inspection` to obtain wider permissions.

### Policy package format

A policy package should contain:

- package schema and ID;
- target Haldir core semantic version range;
- native policy parameters;
- mission phase graph;
- action and frame allowlists;
- source/state requirements;
- geometry artifacts and coordinate-frame metadata;
- optional Cedar policies and entity templates;
- parser/queue/timing limits that affect security;
- safe-action profile reference;
- test-vector corpus and expected reason codes;
- policy-authority signature;
- package digest.

Gate should validate all static constraints at startup. For example, reject a negative margin, a lease cap above a local hard maximum, an empty safe profile, a polygon that fails basic validity checks, or a Cedar package with diagnostics in its self-test corpus.

### Policy evaluation pseudocode

```rust
fn evaluate(input: &PolicyInputV1) -> PolicyResultV1 {
    let mut reasons = BoundedReasons::new();

    require_current_authority(input, &mut reasons);
    require_fresh_source_and_state(input, &mut reasons);
    require_phase_allows_action(input, &mut reasons);
    require_action_within_absolute_bounds(input, &mut reasons);
    require_slew_and_state_consistency(input, &mut reasons);
    require_duty_window(input, &mut reasons);
    require_region_safety(input, &mut reasons);
    require_uncertainty_margin(input, &mut reasons);

    if reasons.any_hard_deny() {
        return PolicyResultV1::deny(reasons, ...);
    }

    let cedar_context = derive_coarse_context(input);
    PolicyResultV1::allow(reasons, effective_limits(input), cedar_context, ...)
}
```

Do not make the evaluator mutate history. The actor commits history only after output allocation/publish according to the documented reference rule. Pure evaluation makes property testing and model comparison much easier.

### Cedar integration boundary

Cedar is useful for reviewable principal/action/resource/context rules, such as:

- controller `survey-v1` may request `VelocityLocalNed` on vehicle `uav-3` only during phase `INSPECTION`;
- a degraded admission class may request only `Hold`;
- a mission lease issued by one authority is forbidden on a vehicle group it does not own.

Cedar is not the place for:

- vector norms;
- coordinate transforms;
- polygon intersection;
- source freshness arithmetic;
- sliding duty windows;
- output sequence allocation;
- restart state;
- safe-action state machines.

Implement the adapter as:

```rust
pub trait CoarseAuthorizer {
    fn authorize(
        &self,
        request: &CedarRequestV1,
        snapshot: &CedarPolicySnapshot,
    ) -> Result<CedarDecisionV1, CedarAdapterError>;
}
```

Overall ALLOW requires `decision == Allow` **and** an empty diagnostics set. Any adapter error denies. Record the Cedar policy digest and diagnostics reason code, not unbounded diagnostic text.

## NCP compatibility adapter

### Isolation rule

Only the NCP adapter crate may import the pinned NCP generated/binding types. The rest of Gate sees stable semantic inputs and stable adapter outputs.

```rust
pub trait NcpCommandAdapter: Send + Sync {
    fn compatibility_id(&self) -> NcpCompatibilityId;

    fn validate_session(
        &self,
        expected: &NcpSessionIdentityV1,
        observed: &ObservedNcpSession,
    ) -> Result<(), NcpAdapterError>;

    fn build_command(
        &self,
        input: &GateCommandBuildInputV1,
    ) -> Result<ExactNcpFrameBytes, NcpAdapterError>;

    fn validate_exact_command(
        &self,
        bytes: &ExactNcpFrameBytes,
        expected: &GateCommandBuildInputV1,
    ) -> Result<(), NcpAdapterError>;

    fn parse_trusted_state(
        &self,
        actual_key: &[u8],
        bytes: &[u8],
        live_session: &NcpSessionIdentityV1,
    ) -> Result<TrustedNcpStateFrame, NcpAdapterError>;
}
```

`ExactNcpFrameBytes` should own immutable bytes and precomputed digest. No caller can modify a field after validation.

### Compatibility identifier

Derive the identifier from:

- NCP protocol/wire version;
- exact schema/proto digest;
- binding/library commit or immutable package digest;
- Haldir adapter source digest/version;
- NCP behavior/conformance corpus version;
- enabled increment set.

A version string such as `0.8` is insufficient. Record the immutable tag, exact commit, contract hash, schema/proto digests, conformance-corpus digest, and Haldir adapter revision.

### NCP v0.8.0 increment-1 behavior

For stream/source/session generation:

- require both session ID and generation on all relevant incoming state;
- use actual received key for key/payload equality;
- index source cache by full stream epoch and sequence;
- mint a fresh Gate output epoch per process restart;
- start output sequence at one;
- reuse exact sequence only for an exact transport retry;
- never derive output sequence from controller intent or source sequence;
- maintain retired output epochs at Crebain according to NCP receiver rules;
- under the `PRE_AUTHORITY_ACL_ONLY` profile, permit a new Gate epoch only under the exact NCP v0.8.0 receiver transition rules, after the prior stream is no longer live, from the same authenticated exclusive Gate principal, in the current session generation.

This `PRE_AUTHORITY_ACL_ONLY` profile is suitable for an experimental single-Gate demonstration. It is not equivalent to plant-issued authority and does not support a high-availability authority handoff claim.

### Future plant-authority behavior

When NCP plant authority lands:

1. Crebain issues or exposes an authority lease to Gate;
2. the lease binds current session, Gate principal, final key/kind, term, lease ID, and output epoch;
3. Gate includes it on every command/stop frame;
4. Crebain validates authority before stream transition or command freshness effects;
5. a new authority term authorizes a new Gate output epoch and retires the old one;
6. stale authority causes rejection with no watchdog refresh;
7. Gate mission leases remain separate and controller-facing.

Add conformance tests for stale term, wrong lease ID, right lease/wrong epoch, right epoch/wrong publisher, revoked authority, and delayed old command after transition.

### Future publisher-identity behavior

Publisher identity in `StreamPosition` should be validated against:

- authenticated transport principal;
- registered Gate publisher identity;
- current session generation;
- exact final key and kind.

It strengthens final-stream attribution. It does not identify the neural bundle or replace controller application signatures because the final publisher is Gate.

### Later acknowledgements and safe-action profiles

When NCP standardizes applied-command/stop acknowledgements and safe-action profiles:

- map Haldir's provisional evidence stages to normative NCP messages;
- retain decision IDs and semantic relation digests as Haldir extensions where NCP does not carry them;
- delete duplicate provisional fields rather than maintaining two sources of truth;
- migrate through versioned adapters and golden cross-version fixtures;
- do not reinterpret an older receipt as a normative acknowledgement.

### Adapter tests

Every adapter version needs:

- NCP upstream conformance corpus;
- Haldir mapping vectors;
- session-pair negative vectors;
- source epoch/sequence vectors;
- output stream restart vectors;
- exact serialization digest vectors across supported languages;
- full accepted integer command-domain conversion properties;
- unknown-field/version rejection;
- actual-key mismatch;
- retired epoch replay;
- duplicate with no watchdog refresh;
- fuzzing of parser and conversion boundaries.

Run the NCP adapter test suite whenever the pinned NCP commit changes. A dependency update is a security-relevant change, not a routine patch bump.

## Secure transport and complete mediation

### Symbolic key roles

Use NCP's own key constructors for NCP keys. In Haldir documentation and ACL generation, refer to symbolic roles:

- `NCP_SESSION_CONTROL_KEY`;
- `NCP_TRUSTED_STATE_KEY[vehicle]`;
- `HALDIR_CHALLENGE_KEY[vehicle]`;
- `HALDIR_INTENT_KEY[vehicle, controller]`;
- `HALDIR_LEASE_CONTROL_KEY[vehicle]`;
- `NCP_FINAL_COMMAND_KEY[vehicle, session]`;
- `HALDIR_DECISION_EVIDENCE_KEY[vehicle]`;
- `CREBAIN_APPLICATION_EVIDENCE_KEY[vehicle]`.

Do not duplicate NCP key grammar in Haldir. Resolve symbols through the pinned adapter/configuration and include the resolved key digest in the deployment package.

### Minimum role matrix

| Role | Publish | Subscribe | Explicitly forbidden |
| --- | --- | --- | --- |
| lifecycle/session | session control/status, future plant-authority control | session replies/status | controller intents, final commands |
| controller `i` | exact intent key `i` | trusted state allowed for its function, Gate challenge/status | final command, other controller intents, lease/admission control, evidence claims |
| Gate | final command, challenge, decision evidence | controller intents, trusted state, session/authority, lease/admission revocation, Crebain evidence | lifecycle mutation except explicit authority protocol |
| Crebain/robot | trusted state, accepted/applied evidence, future plant authority as designed | final command, session control | controller intents, Gate decision claims |
| mission authority | mission lease/revocation control | Gate challenges/status | final command, controller intent |
| admission authority | admission/revocation distribution | bundle submissions in offline workflow | final command, controller intent |
| observer | none or observer-owned query request | evidence/status/state | every command and authority key |
| UI/operator | narrowly scoped management requests | status | raw final command unless separately authorized and mediated |

Generate ACLs from this matrix, verify them statically, and test live delivery/non-delivery with distinct certificates. A successful ACL linter is not a substitute for a live router test.

### Principal-to-key binding

Maintain a signed deployment binding table:

```text
transport principal fingerprint
-> role
-> exact permitted symbolic keys and verbs
-> expected application signing key IDs
-> controller/Gate/service IDs
-> validity/revocation revision
```

At runtime, Gate checks the signed intent key and application signing key even when the transport API cannot expose the publisher certificate on each sample. The router ACL supplies the outer confinement; the application signature supplies end-to-end controller deployment binding.

### Closing ROS/DDS/MAVROS bypasses

For the assurance profile:

1. run neural controllers without ROS/DDS/MAVROS credentials and outside the vehicle DDS domain;
2. place the ROS/MAVROS adapter only inside Crebain or a dedicated plant bridge principal;
3. use network namespaces/container networks so controllers cannot reach DDS discovery or flight-controller endpoints;
4. remove host networking from controller containers;
5. deny controller access to serial devices, CAN, USB flight-controller devices, and Unix sockets used by the plant adapter;
6. inspect source/config for direct publishers and UI callbacks;
7. instrument the deterministic plant and SITL adapter to identify every command ingress;
8. execute live bypass attempts from each role;
9. fail the profile if any unauthorized route affects the plant.

Document residual privileged-host bypass: a root attacker on the deployment host may defeat namespace and device boundaries unless stronger isolation is used.

### Process hardening

Recommended production-profile controls:

- dedicated unprivileged Gate user;
- read-only root filesystem;
- no shell or compiler in the Gate image;
- minimal capabilities; normally none beyond network access and locked memory if justified;
- seccomp/system-call allowlist where maintainable;
- memory and CPU limits with reserved headroom;
- no dynamic library/plugin path writable at runtime;
- private-key access through a least-privilege keystore or restricted file descriptor;
- explicit core-dump policy because dumps can expose keys;
- local spool on a bounded dedicated filesystem;
- reproducible release artifacts and SBOM/provenance;
- startup verification of binary/config/policy digests;
- health endpoints that expose no secret material and cannot mutate authority.

These controls reduce the chance that a non-Gate component acquires Gate's role. They do not convert a compromised kernel into a trusted platform; hardware-rooted measured boot can be a later Watchword/Vilya extension.

## Crebain integration plan

### Current starting point

Crebain's documented NCP path already provides useful library-level components: an off-by-default NCP feature, `NcpBridge`, validated RPC handling, a `CommandPlant`, and a 50 Hz output loop. The product does not currently manage/register the NCP handle and does not implement a live Engram-to-Crebain loop. Treat the library path as the starting seam and the missing product lifecycle as real work.

### Integration principle

Crebain remains the plant-side authority. Haldir does not replace `CommandPlant`; it supplies the only authorized final command stream in the declared profile. Crebain independently validates NCP session, stream, authority, command validity, and plant limits.

### Step 1 — migrate Crebain to the selected NCP revision

Create a dedicated Crebain branch/PR for the NCP migration before Haldir integration:

1. pin one exact NCP wire-0.8 commit for experimental work, or the immutable tag once available;
2. update Rust `ncp-core` and `ncp-zenoh` pins together;
3. update the TypeScript NCP package and both lockfiles together;
4. enable the optional NCP feature in CI on Linux and macOS;
5. replace legacy top-level sequence handling with `stream` and `source`;
6. require payload `session_id` and `session.generation` and compare the actual received key;
7. update `ActionBuffer`/link semantics to use final command `stream`, not causal `source`;
8. update sensor production to assign its own stream and session pair;
9. remove sequence-zero sentinels and use source absence where the wire design requires it;
10. add retired-epoch tombstones and authorized transition behavior;
11. add plant authority validation as soon as increment 2 is available;
12. run upstream conformance vectors plus Crebain-specific 50 Hz tests.

Exit gate: Crebain's optional NCP suite is green against the exact pin, and stale generation/retired epoch/duplicate tests prove no ActionBuffer or watchdog refresh.

### Step 2 — define a Gate-only final command profile

Add a versioned deployment profile to Crebain configuration:

```text
profile_id = crebain-haldir-reference-v1
final_command_key = resolved NCP key
allowed_transport_principal = Gate
allowed_ncp_publisher_id = Gate, when available
required_authority_issuer = Crebain lifecycle
required_safe_action_profile = reference-kinematic-hold-v1
accepted_command_classes = Hold, VelocityLocalNed
maximum_validity_ms = profile-specific
```

The profile must reject direct controller identities even if they possess a general NCP commander role in another development realm.

### Step 3 — register the NCP product lifecycle deliberately

Do not make the feature silently active because it compiled. Add one explicit deployment/user opt-in and then:

1. manage `NcpHandle` in the native application state under one assurance-only lifecycle owner;
2. do **not** register generic browser/Tauri commander commands in the assurance profile; expose only the minimum authenticated lifecycle/status seam required by the deployment;
3. wire connect/open/subscribe/stop/close into one serialized native lifecycle;
4. make reconnect drain and terminate old action loops before replacement;
5. expose current session generation, final-route publication state, and any future plant-authority state to Gate through the chosen authenticated control path;
6. ensure close invalidates the old session before any new loop installs;
7. test cancellation, panic, stuck callback, and reconnect races;
8. keep the unauthenticated development mode visibly separate and impossible in the assurance profile.

Exit gate: a product-level integration test starts and stops one managed 50 Hz loop, proves no loop survives close/reconnect, and records lifecycle evidence.

### Step 4 — add accepted and applied evidence

At minimum, emit two events:

- `CommandAcceptedV1`: exact frame digest, Gate stream position, session, source, authority, ActionBuffer result, local receive/accept time;
- `CommandAppliedV1`: selected frame digest/decision ID, plant tick, adapter result, effective output, safe-action status.

Requirements:

- emit reject evidence for stale session, wrong authority, retired epoch, duplicate, invalid TTL, invalid command, and wrong publisher;
- do not refresh liveness on reject;
- use bounded local queues;
- sign Crebain evidence with a Crebain key;
- provide a deterministic correlation field back to Gate's decision ID without making that field an authority input;
- separate “selected by CommandPlant” from “adapter call returned success” and from measured plant motion.

Exit gate: the range can distinguish `Gate publish returned`, `Crebain received`, `Crebain accepted`, and `adapter applied` for every allowed command.

### Step 5 — make safe action explicit

Replace generic language such as “zero velocity is safe” with a profile implementation:

1. implement `reference-kinematic-hold-v1` in the deterministic plant;
2. define trigger conditions and exact bounded deceleration;
3. define the state region that counts as hold;
4. emit safe-action transition evidence;
5. test command expiry, Gate crash, session close, authority revocation, adapter failure, and state loss;
6. later implement a separate `px4-sitl-hold-v1` with PX4-specific mode and state assumptions;
7. do not reuse either profile for fixed-wing or other vehicle dynamics.

Exit gate: measured time from last usable command to the declared safe region is reproducible under a fault campaign and reported with all constituent delays.

### Step 6 — close direct plant paths

Create a machine-readable authority graph listing every route into the deterministic plant and later MAVROS/PX4. For each route:

- path/key/topic/service/device;
- owning process and principal;
- whether enabled in the assurance profile;
- control used to close or constrain it;
- live test case;
- observed result.

Disable or isolate UI injection, direct ROS publishers, MAVROS setpoint publishers, mode/arm services, native callbacks, and developer hooks in the profile. Test them from controller and observer identities.

Exit gate: every listed unauthorized route is nondelivering and has no measured plant effect. An unlisted discovered route fails the release.

### Step 7 — reference plant before SITL

Use a deterministic plant with explicit state equations and no ROS dependency:

```text
state: position_mm, velocity_mm_s
input: requested velocity, bounded acceleration
step: 20 ms
tracking: deterministic acceleration-limited approach
faults: delayed tick, dropped command, frozen state, adapter error
```

This plant is not realistic flight dynamics. Its purpose is to make authority, timing, replay, expiry, and evidence failures unambiguous.

Only after this path is stable should the integration add Gazebo/PX4-SITL. Preserve the deterministic plant in CI permanently; SITL is slower and less diagnostic.

## Engram and NEST integration plan

### Boundary rule

Engram/controller code produces `HaldirIntentV1`; it does not import Gate internals, own the final NCP stream, hold the plant authority, or evaluate mission policy. Gate does not import NEST.

### Step 1 — define the controller I/O contract

For the first controller, freeze:

- an immutable `nest39-reproduction` environment matching the owner's original run;
- an immutable `nest310-compatibility` environment for the current public release;
- a migration record that treats any action/timing/cleanup difference as evidence, not noise;

- one NCP sensor/state message family;
- exact source stream reference used by each control update;
- encoder from state to spike input;
- NEST simulation time step and number of simulation steps per control update;
- state-reset or state-carry behavior between updates;
- output decoder and no-spike behavior;
- fixed-point semantic command output;
- 20 or 50 Hz intent cadence;
- one deterministic controller-intent epoch per process;
- mission lease and admission bindings.

Write test vectors from source state through encoded spikes, network output, decoded fixed-point action, and final signed intent.

### Step 2 — isolate the controller process

Run the NEST controller as a separate process/container with:

- its own transport certificate restricted to one intent key and required state subscriptions;
- its own application intent signing key;
- no Gate output key;
- no plant NCP authority;
- no ROS/DDS/MAVROS access;
- read-only controller bundle and admission artifacts;
- bounded CPU/memory and input/output queues;
- explicit NEST kernel lifecycle and cleanup.

A NEST warning at process cleanup is a readiness defect even when the controller converges. Add explicit kernel reset/shutdown, join worker threads, and fail tests on unexpected cleanup warnings after known benign messages are allowlisted precisely.

### Step 3 — implement the Haldir intent emitter

The emitter should:

1. receive and validate the current NCP session/state frame through the appropriate NCP client;
2. retain the exact primary source stream position;
3. encode state according to the admitted codec;
4. run one bounded controller update;
5. decode a fixed-point `RequestedActionV1`;
6. populate Gate/boot/session/lease/admission bindings from verified current control state;
7. increment its Haldir intent sequence;
8. set controller-local `controller_t_ns` for diagnostics;
9. canonically encode and COSE-sign the intent;
10. publish only to its exact intent key;
11. never retry by changing the same sequence's bytes; exact transport retry reuses exact bytes;
12. on controller reset, stop and obtain a fresh mission lease rather than minting an in-lease epoch in the MVP.

Keep signing outside the neural model. The model outputs only the semantic action.

### Step 4 — lease and challenge acquisition

A deployment orchestrator, not the neural controller, should:

- verify the Gate challenge;
- select an active admission matching the bundle/backend profile;
- request a mission lease from the mission authority;
- deliver the lease reference and permitted scope to the controller process;
- rotate/revoke controller signing keys;
- stop the controller when Gate boot, session, admission, or lease changes.

The controller does not self-issue its mission lease.

### Step 5 — closed-loop reference demonstration

The first honest vertical slice is:

```text
Crebain reference plant state
 -> NCP sensor frame with session + sensor stream
 -> NEST controller
 -> signed Haldir intent with source reference
 -> Gate decision and Gate-authored NCP output
 -> Crebain CommandPlant at 50 Hz
 -> deterministic plant
 -> accepted/applied/measured evidence
```

Demonstrate one benign convergence task and one hold/recovery task. The test fails if any direct controller command reaches the plant, if an allowed semantic action is changed outside the documented conversion relation, or if a stale source/lease/session produces output.

### Step 6 — package the controller bundle

For the initial fixed-weight profile:

1. extract graph topology and stable node IDs;
2. materialize every weight and delay tensor as immutable content-addressed data;
3. record NEST neuron/synapse model and parameters with units;
4. record NEST version/build digest and simulation resolution;
5. record encoder/decoder, update cadence, state reset, and seed policy;
6. reconstruct the network in a clean environment using only the manifest and artifacts;
7. run golden and held-out vectors;
8. compare semantic actions and reference-plant trajectories;
9. issue an admission only after the clean reconstruction passes.

Until this succeeds, label the NEST controller `identity-bound opaque controller`, not `semantically admitted portable controller`.

## Neuromorphic and backend-aware admission program

### Why this work belongs in Haldir

The security question is not whether a controller can technically execute on another backend. It is whether the evidence used to grant mission authority remains true after representation, discretization, quantization, mapping, scheduling, reset, and runtime changes.

A package hash cannot answer that question. NIR improves interoperability, but it is an intermediate graph representation rather than a proof that two backend executions are action-equivalent. Hardware-constrained toolchains can deliberately approximate dynamics. Haldir's novel opportunity is to bind authority to a declared transformation and measured action-level relation.

### Backend strategy

Use this order:

1. **NEST reference.** Existing real controller path and domain relevance.
2. **Independent open software backend.** Prefer a NIR-capable implementation such as Norse after a capability probe proves that the required primitives are independently implemented. snnTorch is an alternative when its model semantics fit better.
3. **Rockpool mapping and XyloSim.** Use when the controller can be mapped into a named Xylo constrained profile. Treat mapping rejection as evidence that the controller is outside the profile.
4. **SpiNNaker2 Brian2 path.** Optional additional emulation/integration experiment; do not make restricted hardware-linked dependencies an MVP requirement.
5. **Physical hardware.** Separate later validation only with documented access, firmware, runtime, and measurement.

Do not add Lava as a new foundation because its repository is archived. Historical comparison is fine; a new security dependency is not.

### Step 1 — choose a common controller subset

Define a deliberately bounded profile, for example:

```text
fixed-weight-lif-control-nir-v1
- LIF populations only
- static dense/sparse linear projections
- fixed delays from a bounded set
- no online learning
- no arbitrary callbacks
- fixed simulation/control timestep relation
- explicit subtractive or zero reset semantics
- deterministic encoder/decoder
- bounded recurrent graph
- bounded tensor sizes
```

Map each primitive to NEST, NIR, the independent backend, and any Xylo-constrained form. A blank or approximate mapping must be explicit.

### Step 2 — canonical logical representation

Build a canonical graph object independent of Python object identity:

- sort nodes/projections by stable IDs;
- encode model names through a controlled registry;
- normalize units to the profile's fixed representation;
- store tensors in a canonical byte order and dtype;
- hash each tensor and a Merkle-like manifest root;
- record reset, update, and event-order semantics;
- export to NIR and record the exact NIR artifact digest;
- round-trip NIR and compare the canonical logical relation, not raw file ordering alone.

Reject a graph when a required semantic detail cannot be represented.

### Step 3 — backend compilation receipts

For each backend:

1. pin framework and dependency digests;
2. import/reconstruct from the canonical bundle;
3. record every transformation and approximation;
4. record timestep/discretization rules;
5. record numeric precision and quantization;
6. record mapping/resource allocation;
7. record seed and deterministic mode;
8. hash the executable/configuration artifact;
9. run backend self-tests;
10. issue a signed compilation receipt.

For Rockpool/XyloSim, record the mapped hardware configuration and validate that configuration before constructing the bit-precise simulator. Do not call a pre-mapping high-level Rockpool simulation a Xylo-constrained result.

### Step 4 — preregister the equivalence relation

Choose metrics before held-out execution. Recommended layers:

#### Action layer

- exact action class agreement;
- per-component fixed-point error;
- sign agreement near control thresholds;
- command omission/addition rate;
- command timing offset;
- Gate ALLOW/DENY agreement.

#### Trajectory layer

- position and velocity error over time;
- time to convergence/hold;
- maximum overshoot;
- minimum policy safety margin;
- duty and slew violations;
- number/duration of plant safe-action triggers.

#### Internal diagnostic layer

- spike count/rate distributions;
- membrane/state divergence where observable;
- saturation and clipping events;
- reset-event differences.

Internal equality should be diagnostic, not automatically required. The protected relation is at the action and plant layers.

### Step 5 — scenario design

Split scenarios before tuning:

- **development set:** used to debug adapters and select thresholds;
- **validation set:** used once for profile acceptance;
- **held-out test set:** generated or sealed before final evaluation;
- **adversarial set:** boundary states, timing jitter, quantization-sensitive inputs, reset points, source gaps, and near-policy thresholds.

Use paired seeds and identical source traces where possible. Record source trace digests. Do not discard backend runs that produce no spikes or mapping failures; classify them as profile failures.

### Step 6 — field ablation and substitution

Prove that the manifest fields matter by mutating one at a time:

- weight tensor;
- delay;
- reset mode;
- timestep;
- encoder scale;
- decoder window;
- output tie-break;
- seed policy;
- quantization rule;
- backend compiler option;
- coordinate frame;
- source cadence.

The admission validator should reject a mismatched digest. Behavioral tests should detect a meaningful subset. Report fields whose mutation is not detected by the current corpus; they identify weak coverage.

### Step 7 — authorization experiment

Compare at least these schemes:

1. transport identity only;
2. bundle/package hash only;
3. manifest/profile admission without behavioral conformance;
4. Haldir admission with backend compilation receipt and action/trajectory relation;
5. oracle/upper-bound comparator where possible.

Measure prevention of unauthorized or drifted actions, false denials on approved transformations, decision latency, engineering complexity, and evidence completeness.

### Step 8 — issue backend-specific admission

An admission is issued only when:

- the bundle is profile-complete;
- compilation receipt has no prohibited approximation;
- validation and held-out thresholds pass;
- required mutation tests pass;
- toolchain and executable/configuration digests are fixed;
- limitations are recorded;
- the admission authority signs the exact backend relation.

Gate then accepts mission leases only for that exact admission/backend profile digest. Moving from NEST to another backend requires a new compilation receipt and admission, but Gate's enforcement code and Haldir intent schema remain unchanged.

### Hardware claim boundary

Without physical hardware, use these labels precisely:

- `software backend result` for NEST/Norse/snnTorch;
- `hardware-constrained mapped simulation` for a validated Xylo mapping executed in XyloSim;
- `backend emulation result` for SpiNNaker2's Brian2 path;
- `physical hardware result` only for an actual device run with exact device/runtime/firmware evidence.

Never collapse these into “neuromorphic hardware validated.”

## Verification and validation plan

### Test pyramid

The program should maintain five distinct evidence layers:

1. **pure contract and policy tests** — fast, deterministic, exhaustive over bounded cases where possible;
2. **model and property tests** — state-machine interleavings, replay, restart, and arithmetic properties;
3. **live secure transport tests** — real certificates, router ACLs, actual keys, drop/reorder/partition;
4. **closed-loop plant tests** — deterministic plant first, then SITL;
5. **backend-admission experiments** — NEST and independent/hardware-constrained profiles.

A high-level end-to-end pass must not compensate for missing unit/model evidence. Conversely, pure tests do not prove deployment mediation.

### Contract golden vectors

Publish language-neutral vectors for every signed object:

- canonical payload diagnostic representation;
- exact canonical CBOR hex;
- exact protected header bytes;
- external AAD;
- key ID and public key;
- exact COSE envelope hex;
- expected digest values;
- expected parse/verify result;
- expected stable reason code.

Required negative vectors include:

- duplicate map keys;
- non-shortest integers;
- indefinite-length map/string;
- wrong map ordering;
- trailing bytes;
- unknown major version;
- wrong content type;
- algorithm in unprotected header only;
- unknown/retired key ID;
- valid signature under wrong role key;
- changed actual routing key;
- wrong Gate boot ID;
- stale session generation;
- integer overflow boundaries;
- source sequence zero;
- malformed UUID and non-ASCII security ID;
- extra unknown mandatory field;
- oversize envelope.

Run vectors in Rust and any Python/TypeScript tooling that creates leases, manifests, or intents.

### Unit tests

#### Contract crate

- every constructor enforces bounds;
- newtypes cannot cross-assign at compile time;
- canonical re-encoding equality;
- exact digest domains;
- content-type and external-AAD separation;
- no floats accepted in authority payloads;
- unknown field/version behavior.

#### Crypto crate

- key role and subject binding;
- key expiry/revocation;
- no fallback key search;
- malformed signature handling;
- deterministic vector compatibility;
- zeroization/error-path behavior where applicable.

#### State crate

- session generation invalidates all dependent active state;
- lease challenge consumption;
- durable term anti-rollback;
- controller replay gaps/duplicates/retired epochs;
- Gate output sequence allocation and no reuse;
- output epoch transition rules;
- fault latch cannot self-clear;
- tombstone/queue saturation fails closed.

#### Native policy crate

- exact boundary values;
- checked overflow;
- velocity norm without square root;
- uncertainty inflation;
- prospective region checks;
- slew and duty windows;
- mission-phase transitions;
- effective minimum validity;
- missing/stale state;
- deterministic stable reason ordering.

#### NCP adapter

- all upstream conformance vectors;
- exact field-source mapping;
- actual key/payload equality;
- session pair atomic validation;
- source versus stream distinction;
- output conversion error bounds;
- authority lease binding;
- serializer/validator round trip.

### Property-based tests

Use generated bounded inputs to assert:

- a denied input never yields output bytes;
- output validity never exceeds any contributing bound;
- accepted command components remain within lease and policy limits after conversion;
- increasing an absolute command magnitude beyond a hard bound cannot turn DENY into ALLOW;
- shortening a lease or freshness deadline cannot increase effective validity;
- replaying the same scoped intent cannot create a second output;
- changing any signed binding without resigning fails verification;
- a retired epoch never becomes active through a larger sequence;
- Gate output sequences are unique and increasing per epoch;
- Gate restart invalidates all old leases and intents;
- stale session events do not mutate current-session state;
- policy evaluation is deterministic for identical typed snapshots;
- queue/tombstone limits never cause implicit eviction that reopens authority;
- fixed-point-to-NCP conversion is finite, monotone, and bounds preserving.

For geometric policy, generate points and uncertainties around boundaries, including maximum integer magnitudes.

### Fuzzing

Maintain persistent fuzz targets for:

- raw COSE parser;
- bounded CBOR decoder;
- each contract semantic validator;
- key/identifier parser;
- policy package parser;
- NCP state parser with actual key;
- fixed-point conversion;
- evidence journal recovery;
- admission manifest and tensor-reference validation.

Seed fuzzers with all golden and known-bad vectors. Treat panics, excessive allocation, timeout, and inconsistent reason codes as defects. Use allocator and input-size instrumentation to verify bounded behavior.

### Formal model

Create a small TLA+ model before transport integration. Keep data domains tiny and model control state, not numeric geometry.

#### Variables

- `sessionGeneration`;
- `gateBoot`;
- `gateProcessState`;
- `plantAuthorityTerm` and `authorityEpoch`;
- `leaseTerm`, `leaseState`, and bound boot/session/admission;
- `controllerEpoch`, `lastIntentSeq`, `retiredControllerEpochs`;
- `gateEpoch`, `lastOutputSeq`, `retiredGateEpochs`;
- `sourceFresh` and `policyAllows`;
- `outputPrepared`, `publishResult`, `plantAccepted`, `plantApplied`;
- `faultLatched`.

#### Actions

- open/reopen/close session;
- issue/revoke future plant authority or change current ACL-exclusive publication state;
- publish/consume challenge;
- issue/activate/revoke/expire mission lease;
- receive fresh/duplicate/stale/wrong-session intent;
- allow/deny policy;
- allocate/publish/drop/delay command;
- accept/reject/apply at plant;
- Gate crash/restart;
- evidence append/drop;
- controller restart/handoff.

#### Safety properties

- `PlantAccepted => PublishedByGate`;
- `PublishedByGate => CurrentSessionAtAllocation`;
- `PublishedByGate => ExclusiveGatePublicationCapability`;
- `PublishedByGate => CurrentPlantAuthority` when a future authority profile is modeled;
- `PublishedByGate => ActiveMatchingLeaseAtDecision`;
- no two different output bytes share one Gate epoch/sequence;
- retired controller/Gate epochs never reactivate;
- stale generation cannot change current command/watchdog state;
- crash cannot preserve active Haldir lease across new Gate boot;
- DENY cannot produce output;
- evidence state cannot change authorization state.

#### Liveness under explicit fairness assumptions

- a valid current intent is eventually decided when Gate, transport, and actor remain available;
- an expired command eventually ceases to be selected by the plant;
- a revocation is eventually processed when the control-priority queue is serviced;
- a new Gate epoch can become active after an authorized authority transition.

Do not claim unconditional liveness under partition or denial of service. State fairness and delivery assumptions in the model.

### Live transport/ACL campaign

Provision distinct certificates for every role and execute a matrix:

- each role publishes each symbolic key;
- expected recipient delivery/non-delivery is observed;
- wildcard subscriptions receive actual keys and Gate checks exact key equality;
- revoked/expired certificate behavior is tested;
- router restart and reconnect behavior is tested;
- a controller with valid transport identity but invalid application signature is denied;
- a valid controller signature arriving through the wrong exact key is denied;
- direct final-key publication from controller is nondelivering;
- observer/UI cannot publish control or authority messages;
- Gate cannot accidentally publish another vehicle's final key.

Capture router configuration digest and certificate fingerprints with results. Do not put private keys in evidence artifacts.

### Fault-injection campaign

At minimum inject:

- duplicate, gap, reorder, late old epoch, and random new epoch;
- stale/missing session generation;
- source restart and source-frame delay;
- Gate crash before decision;
- crash after sequence allocation but before publish;
- crash after publish return but before evidence append;
- transport publish error;
- partition between Gate and Crebain;
- partition between controller and Gate;
- Crebain action-loop stall;
- evidence collector outage and local spool full;
- monotonic clock abstraction failure/rewind in test build;
- policy package diagnostic/error;
- admission/key/lease revocation during an in-flight intent;
- controller signing flood;
- malformed CBOR/COSE corpus;
- state uncertainty increase;
- safe-action adapter failure;
- session close/reopen with delayed old traffic.

For each fault, specify expected Gate state, whether a new command may appear, expected Crebain selection, safe-action behavior, and evidence status.

### Performance methodology

#### What to measure

Instrument monotonic timestamps for:

- sample receive to ingress acceptance;
- decode;
- key lookup/signature verification;
- actor queue wait;
- scope/replay/source checks;
- native policy;
- optional Cedar;
- output construction/serialization/validation;
- publish queue wait and publish call;
- Crebain receive/accept;
- next 50 Hz plant tick;
- adapter application;
- measured plant response.

#### Workloads

Measure:

- one controller at 20 Hz and 50 Hz;
- maximum declared vehicle/controller count;
- valid ALLOW workload;
- policy DENY workload;
- invalid-signature flood within ACL/rate limits;
- maximum-size valid envelopes;
- evidence collector offline;
- CPU and memory pressure at declared deployment limits;
- session/revocation control event during load.

#### Initial engineering target

A reasonable provisional target for the pure decision plus output serialization path is:

```text
p99.9 <= 2 ms
maximum observed <= 5 ms
at 50 Hz on the named reference host under the declared load
```

This is an early engineering target, not a hard real-time guarantee. Measure the unmediated NCP/Crebain baseline first. Adjust the target only before the final experiment and explain why. Also report CPU, memory, queue high-water, signature rate, and rejected-overload count.

Use HDR-style histograms or another tail-preserving method, warm up deliberately, pin exact host/kernel/build settings, and publish raw samples or histograms. Do not report only averages.

### Closed-loop validation scenarios

The deterministic plant suite should include:

- converge to a benign waypoint/velocity target;
- enter hold;
- bounded controller oscillation rejected by slew/duty policy;
- forbidden region approach rejected prospectively;
- stale state/source denial;
- controller restart and fresh-lease handoff;
- Gate crash and expiry-to-safe action;
- wrong backend/admission substitution;
- session generation rollover;
- delayed old Gate epoch replay;
- allowed semantic transparency comparison against a direct semantic baseline.

For transparency, compare requested fixed-point action to Gate output under the documented conversion relation and compare plant trajectories with and without Gate latency using the same source trace.

### PX4-SITL/Gazebo campaign

Only begin after deterministic exit gates pass. Then:

1. define one multirotor-only safe-action profile;
2. enumerate MAVROS/PX4 command paths and close bypasses;
3. pin PX4, Gazebo, ROS/MAVROS, NCP, Crebain, Gate, and controller revisions;
4. run headless deterministic seeds where possible;
5. test offboard loss, mode transition, hold, state-estimator degradation, and network delay;
6. record that SITL is simulation, not physical flight evidence;
7. retain plant-side safety and an external operator stop outside the research mechanism.

Do not begin with aggressive flight envelopes. The research question is authority composition, not maximum vehicle performance.

## Reproducible CI and release gates

### Pull-request CI

Every PR should run:

- formatting, lint, docs links, and forbidden-feature checks;
- all pure unit/property tests;
- golden vectors in Rust and available tool languages;
- NCP adapter conformance against exact pin;
- a bounded fuzz smoke corpus;
- TLA+ model check for the bounded model;
- deterministic reference-plant scenarios;
- dependency and license policy checks;
- `cargo deny`/audit-equivalent checks with reviewed exceptions;
- release-build reproducibility comparison where practical;
- `git diff --check` and no generated-file drift.

### Nightly/scheduled CI

- longer fuzzing;
- sanitizer/Miri-compatible subsets;
- live Zenoh mTLS/ACL matrix;
- fault/partition campaign;
- performance regression on a stable runner;
- NEST vertical slice;
- independent backend conformance;
- larger model-check domains when feasible;
- dependency-update dry run without changing production pins.

### Release gate

A release candidate requires:

- immutable NCP compatibility target;
- signed deployment and policy package;
- no debug/unsigned intent feature;
- complete golden corpus;
- live ACL matrix green;
- reference-plant fault campaign green;
- documented safe-action profile;
- no ordinary direct plant bypass in the profile;
- signed SBOM/provenance;
- security review of any unsafe Rust and cryptographic key handling;
- published limitations and exact assurance profile;
- reproducible evidence bundle with raw results and commit digests.

## Step-by-step implementation roadmap

### Phase -1 — correct the design record before code

#### Changes

1. Add this document as `docs/HALDIR-NCP-V0.8.0-TRIPLE-CHECKED-AUDIT-AND-IMPLEMENTATION-SPECIFICATION-2026.md`.
2. Add a prominent supersession notice near the top of `HALDIR-DISCUSSION-DECISIONS-2026.md`.
3. Mark the exact-NCP-frame `SignedIntentV1`, byte-preserving ALLOW, reserved maximum sequence, and post-expiry sequence re-anchoring sections as superseded.
4. Add the public NCP wire-0.8 design record and v0.8.0 release to the evidence list and record it as historical design text superseded by the v0.8.0 tag.
5. Replace the immediate milestone wording with a typed-intent/Gate-owned-stream milestone.
6. Open tracking issues for NCP adapter, contracts, core state model, reference plant, ACL range, Crebain integration, NEST bridge, and admission research.

#### Exit gate

Two reviewers can draw the same authority and stream ownership diagram without interpreting contradictory sections.

### Phase 0 — pure contracts and reference decision core

#### Implementation order

1. initialize Rust workspace and deny unsafe code by default;
2. implement scalar newtypes and bounded containers;
3. implement strict canonical CBOR profile;
4. implement COSE Sign1/Ed25519 profile and trust-store roles;
5. publish golden vectors;
6. implement Gate challenge, mission lease, revocation, intent, decision receipt;
7. implement injectable monotonic clock;
8. implement session/lease/replay/output state machines;
9. implement fixed-point action types;
10. implement native policy for hold/local-NED velocity, freshness, bounds, slew, duty, and one rectangular/convex region profile;
11. implement deterministic reference plant library;
12. implement pure end-to-end test: source snapshot -> signed intent -> decision -> semantic output object, with no NCP or network.

#### Exit gates

- all invariants have tests;
- TLA+ bounded model is green;
- malformed corpus does not panic or overallocate;
- Gate restart invalidates active authority;
- no controller-supplied final NCP fields exist in public contracts;
- policy results are deterministic and bounded.

#### Stop conditions

Stop and redesign if canonical cross-language vectors cannot be made stable, active authority survives restart ambiguously, or the state model needs hidden global mutable state.

### Phase 1 — immutable NCP v0.8.0 adapter and reference transport

#### Implementation order

1. pin exact NCP branch commit;
2. implement adapter compatibility ID;
3. implement trusted sensor/session parsing;
4. implement Gate-owned output stream allocation;
5. implement fixed-point action conversion;
6. implement exact serializer/local validator;
7. add upstream conformance vectors;
8. implement secure Zenoh transport wrapper with actual-key delivery;
9. build controller/Gate/plant fixture certificates and ACLs;
10. run one signed fixture controller through Gate to a mock NCP receiver/reference plant;
11. test Gate restart with pre-authority constrained epoch transition;
12. mark artifacts experimental and non-release-compatible until NCP tag.

#### Exit gates

- Gate output uses its own stream, time, session, and source;
- direct final-key controller publication is denied by ACL;
- stale generation and retired epoch cause no receiver liveness effect;
- output mapping vectors are stable;
- measured decision path meets an initial budget.

#### Stop conditions

Stop the integration if NCP's final tagged semantics materially contradict the adapter assumptions; update the stable Haldir core only when the semantic boundary, not merely wire shape, changes.

### Phase 2 — secure Crebain reference-plant integration

#### Implementation order

1. migrate Crebain's optional feature to the selected NCP revision;
2. add stream/source/session-generation receiver behavior;
3. add authority increment when available;
4. deliberately register/manage product lifecycle under an opt-in profile;
5. configure Gate-only final publisher;
6. add accepted/applied evidence;
7. implement deterministic safe-action profile;
8. close and test all deterministic-plant bypasses;
9. execute crash, partition, replay, revocation, and overload campaigns;
10. publish raw evidence and latency breakdown.

#### Exit gates

- complete scoped mediation of the deterministic plant;
- Gate crash produces no fresh command and plant reaches declared safe region within measured bound;
- allowed actions satisfy the conversion relation;
- publication and application evidence remain distinct;
- evidence outage behavior matches the declared profile.

### Phase 3 — Engram/NEST live controller

#### Implementation order

1. freeze sensor/codec/controller update contract;
2. create isolated NEST controller process;
3. provision restricted transport and intent keys;
4. implement signed Haldir intent emitter;
5. fix NEST lifecycle/cleanup warnings;
6. obtain challenge-bound mission lease through orchestrator;
7. run closed loop through Gate and Crebain reference plant;
8. add malicious/buggy controller variants;
9. compare direct semantic baseline to mediated path;
10. retain all evidence by source trace and decision ID.

#### Exit gates

- real NEST computation drives the reference plant only through Gate;
- stale source/session/lease and malformed intents never reach Crebain as commands;
- controller restart requires fresh authority;
- tail latency preserves the declared 20/50 Hz deadline;
- no NEST/Python dependency appears in Gate's binary or hot path.

### Phase 4 — profile-complete NEST bundle admission

#### Implementation order

1. define `fixed-weight-lif-control-v1`;
2. extend Engram manifest/artifact representation to topology, parameters, codec, timing, reset, and seeds;
3. reconstruct controller in a clean environment;
4. create admission validator and compilation receipt;
5. preregister behavior corpus and thresholds;
6. run field ablation/substitution;
7. issue signed admission;
8. require mission lease to bind it;
9. demonstrate wrong bundle/profile/key substitutions are denied.

#### Exit gates

- no hidden arbitrary code is required for reconstruction;
- the admission relation is exact and revocable;
- meaningful field mutations are detected by digest and behavior checks;
- Gate can distinguish admitted and opaque controllers without importing Engram internals.

### Phase 5 — independent backend and NIR conformance

#### Implementation order

1. define NIR-compatible common subset;
2. export and canonicalize NIR artifact;
3. capability-probe Norse or another independent backend;
4. implement backend compilation receipt;
5. preregister action/trajectory equivalence;
6. run development, validation, held-out, and adversarial sets;
7. compare authorization outcomes and plant trajectories;
8. issue or refuse backend-specific admission honestly;
9. publish negative/mapping failures.

#### Exit gates

- second backend is independently implemented;
- thresholds predict held-out outcomes;
- backend drift that matters to mission policy is detected better than package hash alone;
- false denials on approved transforms remain within preregistered bounds.

### Phase 6 — Rockpool/XyloSim hardware-constrained profile

#### Implementation order

1. test whether the controller maps to a named Xylo device profile;
2. record graph mapping, resource, quantization, and approximation reports;
3. validate generated configuration;
4. execute the generated configuration in XyloSim;
5. run the same held-out source traces;
6. compare action/trajectory and Gate decisions;
7. label result hardware-constrained simulation;
8. issue a backend-specific admission only if all criteria pass.

Mapping failure is an acceptable research result and must not be bypassed by silently changing controller topology after threshold selection.

### Phase 7 — PX4-SITL/Gazebo and expanded range

#### Implementation order

1. define multirotor-only profile and safe action;
2. close MAVROS/PX4 bypasses;
3. integrate Crebain adapter;
4. run benign hold/inspection tasks;
5. inject command, session, source, Gate, and network faults;
6. compare baselines;
7. publish simulator limitations;
8. keep physical hardware out of the claim.

### Phase 8 — optional physical validation

Proceed only with actual device/vehicle access, institutional safety review, independent operator stop, and a separate protocol. Physical hardware is not needed to validate Gate's architecture or the software backend research claims.

## Agent execution manual — normative build sequence

The earlier roadmap explains architectural order. This section is the operational contract for another coding agent. Execute it from top to bottom. Do not collapse phases into a mega-change, do not bypass an exit gate because a later integration appears more interesting, and do not use a simulator demonstration to compensate for an incomplete authority or evidence model.

## Agent operating contract

### Git and repository discipline

The agent SHALL:

1. begin from a clean Haldir branch created from the owner's selected base;
2. record the starting commit in the source ledger;
3. use separate worktrees for NCP v0.8.0 release and cross-repository changes;
4. create one focused branch/PR per phase or cohesive subphase;
5. run `git diff --check` before every commit;
6. inspect `git status --short --branch` before and after every command that can generate files;
7. commit generated schemas/vectors only when the generator and regeneration check are included;
8. use normal pushes only;
9. never use `git push --force`, `--force-with-lease`, history rewriting, `git reset --hard` on an owner's worktree, or destructive cleanup of untracked files;
10. never commit private keys, local absolute paths, captured secrets, proprietary Engram content, or device credentials;
11. keep Haldir, NCP, Crebain, and Engram changes in separate commits and preferably separate PRs;
12. include the exact cross-repository compatibility matrix in every integration PR.

Suggested branch names:

```text
spec/haldir-complete-design
feat/contracts-v1
feat/identity-and-authority
feat/policy-reference-plant
feat/ncp-v080-adapter
feat/gate-runtime
range/secure-zenoh-matrix
integration/crebain-command-plant
integration/engram-nest-intent
research/backend-admission
range/px4-sitl
```

Suggested commit prefixes:

```text
docs: ...
contracts: ...
crypto: ...
authority: ...
policy: ...
state: ...
ncp08: ...
gate: ...
range: ...
integration: ...
research: ...
build: ...
security: ...
```

### Evidence-first rule

Every phase creates a directory under:

```text
evidence/<phase-id>-<name>/
```

Each directory MUST contain:

- `README.md`: purpose, exact commands, environment, expected result, actual result, limitations;
- `manifest.json`: repository commits, toolchain versions, configuration digests, start/end timestamps, clean/dirty state;
- `commands.txt`: commands exactly as executed;
- `stdout.log` and `stderr.log`, or one named log per command;
- `checksums.sha256`: checksums of retained artifacts;
- machine-readable result files;
- a statement of whether the exit gate passed.

Generated evidence MAY be excluded from the main Git history when too large, but the manifest, scripts, schemas, checksums, and a stable artifact location MUST be committed. Do not commit a hand-written “passed” summary without raw machine-readable evidence.

### Local setup and immutable pins

Create `tools/pins.toml` as the human-reviewable pin source. It records:

- Rust toolchain and components;
- cargo tool versions used in CI;
- NCP v0.8.0 release commit;
- Zenoh/NCP dependency revisions;
- TLA+/model-checker version and digest;
- Python version and lock-file digest for admission tools;
- NEST version/container digest;
- NIR, Rockpool, optional second backend, and simulator versions when introduced;
- PX4/Gazebo/ROS revisions when introduced.

Create `tools/verify-pins.py` to reject branch names, short SHAs, floating Docker tags, uncommitted lock files, or mismatches between `pins.toml` and manifests.

The first Rust toolchain SHOULD use edition 2024 and an exact stable release reviewed at implementation time. The minimum accepted compiler must be documented. Do not write `channel = "stable"` in release evidence.

### Coding rules

All Haldir Rust crates MUST use:

```rust
#![forbid(unsafe_code)]
#![deny(missing_docs)] // for public library crates after the initial scaffold
```

Runtime code MUST follow these rules:

- no `unwrap`, `expect`, `panic!`, or unchecked indexing on data or state derived from transport, files, authorities, policies, controllers, or plants;
- no floating-point values in signed Haldir authority, policy, replay, or mission-action contracts;
- no network, filesystem, clock, random-number, or plugin access from the pure policy function;
- no dynamic library loading in Gate;
- no arbitrary executable callbacks in admission profiles;
- no unbounded channel, vector, map, string, parser recursion, retry loop, or evidence queue;
- no `HashMap` where deterministic iteration contributes to a digest or decision;
- no human-readable error string as a security decision input;
- no log statement containing signatures, private key material, full certificates, raw untrusted payloads, or sensitive paths;
- typed errors in libraries; process-level context may use a general error wrapper only at the binary boundary;
- all conversions across units, signs, widths, clocks, and float boundaries use named checked functions with property tests;
- every external dependency is justified in `docs/DEPENDENCY-RATIONALE.md` and pinned in `Cargo.lock`.

Recommended lints in workspace configuration include:

```text
clippy::all
clippy::pedantic
clippy::unwrap_used
clippy::expect_used
clippy::panic
clippy::indexing_slicing
clippy::float_cmp
clippy::lossy_float_literal
clippy::cast_possible_truncation
clippy::cast_sign_loss
clippy::cast_precision_loss
```

Apply narrow, documented allowances only at the exact line or module where necessary.

### Standard local checks

Create a `justfile` whose canonical commands are:

```bash
just fmt
just lint
just test
just test-all
just docs
just deny
just conformance
just model
just fuzz-smoke
just range-reference
just verify-generated
just verify-evidence
just ci
```

`just ci` MUST be the same logical gate as pull-request CI. A representative implementation is:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-targets --locked
cargo test --workspace --doc --locked
cargo doc --workspace --no-deps --all-features --locked
cargo deny check
python3 tools/verify-pins.py
python3 tools/verify-generated.py
python3 tools/verify-evidence.py
```

Use `cargo nextest` and coverage tooling only after they are pinned; ordinary `cargo test` remains a fallback so a specialized runner is not the only truth.

### Workspace skeleton

The normative initial layout is:

```text
haldir/
├── Cargo.toml
├── Cargo.lock
├── rust-toolchain.toml
├── deny.toml
├── justfile
├── README.md
├── SECURITY.md
├── CONTRIBUTING.md
├── docs/
│   ├── HALDIR-NCP-V0.8.0-TRIPLE-CHECKED-AUDIT-AND-IMPLEMENTATION-SPECIFICATION-2026.md
│   ├── THREAT-MODEL.md
│   ├── AUTHORITY-GRAPH.md
│   ├── NCP-COMPATIBILITY.md
│   ├── EVIDENCE-SEMANTICS.md
│   ├── ASSURANCE-PROFILES.md
│   ├── DEPENDENCY-RATIONALE.md
│   └── RESEARCH-PROTOCOL.md
├── crates/
│   ├── haldir-contracts/
│   ├── haldir-crypto/
│   ├── haldir-core/
│   ├── haldir-state/
│   ├── haldir-policy-native/
│   ├── haldir-policy-cedar/
│   ├── haldir-admission/
│   ├── haldir-ncp08/
│   ├── haldir-transport-zenoh/
│   ├── haldir-evidence/
│   ├── haldir-reference-plant/
│   ├── haldir-gate/
│   ├── haldir-range/
│   ├── haldir-python/
│   └── haldir-testkit/
├── tools/
│   ├── pins.toml
│   ├── verify-pins.py
│   ├── verify-generated.py
│   ├── verify-evidence.py
│   ├── vector-gen/
│   ├── admission/
│   │   ├── nest/
│   │   ├── nir/
│   │   ├── independent/
│   │   └── rockpool/
│   └── haldir-ctl/
├── contracts/
│   ├── cddl/
│   ├── vectors/
│   ├── malformed/
│   └── generated/
├── policies/
│   ├── reference-v1/
│   └── fixtures/
├── formal/
│   ├── HaldirAuthority.tla
│   ├── HaldirAuthority.cfg
│   ├── HaldirEvidence.tla
│   └── README.md
├── range/
│   ├── compose/
│   ├── zenoh/
│   ├── certs-dev/
│   ├── controller/
│   ├── reference-plant/
│   ├── attacks/
│   ├── scenarios/
│   └── px4/
├── deploy/
│   ├── development/
│   ├── assurance-sim/
│   ├── systemd/
│   └── containers/
├── evidence/
└── .github/workflows/
    ├── ci.yml
    ├── conformance.yml
    ├── formal.yml
    ├── fuzz.yml
    ├── supply-chain.yml
    └── nightly-range.yml
```

If the existing repository has an incompatible layout, preserve useful documentation and migrate in a dedicated scaffold PR. Do not delete historical Haldir documents.

## Phase 0 — freeze sources, claims, and assurance profile

### Objective

Establish an auditable starting point before code and prevent design drift caused by moving sibling branches.

### Files to create

```text
evidence/source-review/source-ledger.json
evidence/source-review/source-ledger.md
evidence/source-review/logs/*
docs/ASSURANCE-PROFILES.md
docs/NCP-COMPATIBILITY.md
tools/pins.toml
tools/verify-pins.py
```

### Steps

1. Execute the repository identity loop defined in the ecosystem review.
2. Fetch remotes without modifying working branches.
3. Create a detached NCP v0.8.0 release worktree at `2f5bd586d4bb20c90362bb6f5698b7f64057ba4e`.
4. Record legacy NCP `v0.7.1` only for consumer-migration regression, and record the NCP `v0.8.0` proto, schema, generated-artifact, and frozen behavior/conformance corpus digests as the implementation baseline.
5. Read NCP `SECURITY.md`, `KNOWN_LIMITATIONS.md`, `AGENTS.md`, wire-0.8 design record, generated bindings, schemas, and behavior vectors.
6. Record whether every NCP v0.8.0 language test is locally runnable. Run only documented commands; retain failures honestly.
7. Audit Crebain's four NCP pins, feature gates, command plant, Tauri registration, browser development injection, direct ROS/MAVROS paths, and security docs.
8. Audit Galadriel, Prisoma, and pid-rs pins and current stated scientific/security limits.
9. Audit `crebain-native` publishers, ROS/MAVROS routes, launch files, credentials, and process/deployment remnants; classify it as absent, disabled, or observer-only.
10. Audit Manwe, Cortexel, Silmaril Vision Studio, Hermes-agent, Rerun, Melkor, and atlas repositories only to the depth required by their declared read-only, fixture, or untrusted-producer role.
11. Perform the local Engram audit described earlier. Do not modify Engram yet.
12. Define `assurance-reference-v1`: one vehicle, one controller, one Gate, one deterministic plant, 50 Hz target, `Hold` and local-NED velocity only, secure Zenoh, no UI, no physical hardware.
13. Define `assurance-px4-sitl-v1` as a future profile with no claim until its phase passes.
14. Open an issue for every unresolved source fact that can affect architecture.

### Required evidence

- source ledger with exact commits;
- NCP conformance command logs;
- Crebain and `crebain-native` path inventories;
- Engram local gap report;
- assurance profile with every in-scope and out-of-scope path;
- no code changes outside docs/tooling.

### Exit gate

Two reviewers can independently identify the exact NCP v0.8.0 release, final command route, controller intent route, plant owner, safe-action owner, and every bypass included in the first assurance profile.

### Prohibited shortcuts

- using `main` or a branch name as a dependency pin;
- treating public Engram README text as implementation evidence;
- beginning NCP adapter code before schema/conformance inspection;
- claiming a test passed when it could not run locally.

### Suggested commit

```text
docs: freeze Haldir source ledger and assurance profile
```

## Phase 1 — scaffold the Rust workspace and CI

### Objective

Create a buildable empty architecture with strict lint, dependency, generation, and evidence gates before behavior is implemented.

### Files and APIs

Create all workspace manifests and empty crates listed above. Each library exposes only a `VERSION` constant and module-level documentation initially. `haldir-gate` and `haldir-ctl` compile to binaries that print an explicit `NOT IMPLEMENTED` error and exit nonzero; they MUST NOT pretend to operate.

Workspace `Cargo.toml` defines:

- edition 2024;
- common license inherited from the existing repository, or no new license decision without owner approval;
- common authors/repository metadata;
- workspace dependency pins;
- release profile with overflow checks retained where practical and panic abort only after analysis of evidence flushing;
- lints inherited by all members.

### Steps

1. Create the directory tree.
2. Add `rust-toolchain.toml` with the reviewed exact toolchain and required components.
3. Add `.editorconfig`, `.gitignore`, and secret-pattern exclusions.
4. Add `deny.toml` for advisory, license, ban, and source checks.
5. Add `justfile` commands.
6. Add PR CI for format, lint, test, docs, dependency checks, generated-file verification, and source pins.
7. Add scheduled jobs as non-blocking placeholders only when they run a real command.
8. Add `SECURITY.md` with private reporting instructions and an explicit no-production-use status.
9. Add `CONTRIBUTING.md` with the evidence and no-force rules.
10. Add a test that scans Haldir-owned Rust source for forbidden `unsafe` and production code for `unwrap`/`expect` allowances.
11. Add a test that rejects committed files matching private-key headers outside `range/certs-dev`, and rejects development certificate fingerprints in assurance deployment packages.
12. Run the entire empty CI locally.

### Exit gate

A fresh clone can run `just ci` without network access after dependencies are cached; every crate builds; generated-file and evidence checks exist; no command path is implemented.

### Suggested commit

```text
build: scaffold bounded Haldir workspace and CI
```

## Phase 2 — implement canonical contracts and malformed corpus

### Objective

Define stable Haldir wire contracts independently of NCP and prove one canonical representation per accepted semantic object.

### Files to create

```text
crates/haldir-contracts/src/
  lib.rs
  scalar.rs
  ids.rs
  digest.rs
  action.rs
  challenge.rs
  lease.rs
  revocation.rs
  intent.rs
  admission.rs
  policy.rs
  receipt.rs
  status.rs
  limits.rs
  canonical.rs
  error.rs
contracts/cddl/*.cddl
contracts/vectors/*.cbor
contracts/vectors/*.json
contracts/malformed/*
tools/vector-gen/*
```

### Exact implementation order

1. Implement bounded ASCII identifiers with constructors that reject empty, overlength, whitespace/control, forbidden separator, and non-ASCII input according to each type.
2. Implement UUID-byte types and canonical UUIDv4 string parsing only where NCP interop requires a string.
3. Implement nonzero bounded integers and fixed-point unit newtypes:
   - `MillimetresPerSecond(i32)`;
   - `MillimetresPerSecondSquared(i32)`;
   - `Milliseconds(u32)`;
   - `MonotonicNanoseconds(u64)`;
   - bounded vector norm operands using widened integer intermediates.
4. Implement `DigestV1` with only SHA-256 enabled.
5. Implement the MVP action exactly:

```rust
pub enum RequestedActionV1 {
    Hold {
        requested_validity_ms: NonZeroU32,
    },
    VelocityLocalNed {
        north_mm_s: i32,
        east_mm_s: i32,
        down_mm_s: i32,
        requested_validity_ms: NonZeroU32,
    },
}
```

6. Implement the contracts defined in this document with bounded fields and no `serde_json::Value`, arbitrary extension maps, or free-text action names.
7. Choose CDDL as the syntax-level source of truth and hand-written Rust semantic validators as the semantic source of truth. Generate documentation/test views; do not generate trusted validators without reviewing them.
8. Implement a strict bounded CBOR decoder that rejects:
   - indefinite lengths;
   - duplicate map keys;
   - non-shortest integer/length encodings;
   - out-of-order map keys under deterministic encoding;
   - floats in signed contracts;
   - unknown top-level fields;
   - tags not explicitly permitted;
   - excessive depth, pairs, elements, strings, or total bytes;
   - trailing data.
9. Deterministically re-encode every decoded object and require byte equality before signature semantics accept it.
10. Generate at least one positive and multiple negative vectors for every message kind.
11. Add language-neutral vector metadata containing payload digest, expected parse result, expected semantic error code, and canonical round-trip status.
12. Add property tests for scalar bounds and encode/decode identity.
13. Add fuzz targets for raw CBOR envelope parsing and every high-value contract.

### Required tests

- canonical map ordering across nested objects;
- duplicate encoded and semantic keys;
- shortest/non-shortest integer variants;
- overlength IDs and boundary lengths;
- integer min/max, zero for nonzero fields, and arithmetic overflow;
- unsupported version/field/action;
- one-bit mutations of valid vectors;
- allocation remains below an asserted budget for maximum accepted payload;
- parser never panics across fuzz corpus.

### Exit gate

Every accepted contract has exactly one canonical byte encoding, all malformed fixtures fail with stable typed errors, and no NCP generated type appears in `haldir-contracts`.

### Suggested commits

```text
contracts: add bounded semantic scalar and action types
contracts: add canonical CBOR schemas and vectors
contracts: add adversarial malformed corpus and fuzz targets
```

## Phase 3 — implement signatures, key roles, and trust snapshots

### Objective

Bind every authority object and controller intent to an explicit application identity and role without conflating mTLS with application signing.

### Files to create

```text
crates/haldir-crypto/src/
  lib.rs
  cose.rs
  ed25519.rs
  key_id.rs
  role.rs
  trust_store.rs
  revocation.rs
  verifier.rs
  signer.rs
  error.rs
range/certs-dev/README.md
range/certs-dev/generate-dev-pki.sh
contracts/vectors/cose/*
```

### Key roles

Implement a closed enum:

```text
GATE_APPLICATION
CONTROLLER_INTENT
MISSION_AUTHORITY
ADMISSION_AUTHORITY
POLICY_AUTHORITY
REVOCATION_AUTHORITY
CREBAIN_EVIDENCE
DEPLOYMENT_AUTHORITY
DEVELOPMENT_ONLY
```

A key record binds:

- protected `kid`;
- algorithm;
- role;
- issuer/trust root;
- subject/controller/Gate/Crebain identity where applicable;
- permitted message kinds;
- validity metadata for audit;
- highest accepted revocation epoch;
- development/assurance class.

### Steps

1. Implement embedded-payload `COSE_Sign1` with protected algorithm, protected key ID, protected content type, and fixed external AAD per message kind.
2. Support Ed25519 only in v1. Reject algorithm negotiation and unprotected security headers.
3. Build a prevalidated immutable trust index. Do not build certificate chains or scan all keys per intent.
4. Implement exact role/message/subject binding before signature acceptance.
5. Implement revocation snapshots and monotonic issuer epochs.
6. Implement a signer interface used by development tools and Gate, with private keys represented by secrecy/zeroization wrappers where supported.
7. Keep application signing keys separate from Zenoh mTLS keys even when they share an operational owner.
8. Generate development PKI in an ignored directory, with unmistakable names and validity. Commit only the generator and public test fixtures needed by CI.
9. Add positive/negative cross-language verification vectors for Python consumers through the future binding.
10. Add tests for wrong AAD, wrong content type, wrong role, wrong subject, revoked key, duplicate key ID, invalid signature, noncanonical payload, and development key in assurance profile.

### Exit gate

No accepted message can be reinterpreted as another kind, a controller key cannot sign a lease or policy, and a transport certificate alone cannot satisfy application intent verification.

### Suggested commit

```text
crypto: add role-bound COSE Ed25519 trust profile
```

## Phase 4 — implement controller bundle and backend admission

### Objective

Create a deterministic admission subsystem that can distinguish an opaque controller from a profile-complete admitted deployment without executing neural code inside Gate.

### Files to create

```text
crates/haldir-admission/src/
  lib.rs
  manifest.rs
  profile.rs
  backend.rs
  receipt.rs
  admission.rs
  snapshot.rs
  mutation.rs
  error.rs
tools/admission/nest/*
policies/fixtures/admission/*
```

### Steps

1. Implement `ControllerBundleManifestV1`, `ControllerAdmissionProfileV1`, `BackendExecutionProfileV1`, `BackendCompilationReceiptV1`, and `AdmissionRecordV1` validation.
2. Add `AdmissionLevelV1`:

```text
A0_PROVENANCE_ONLY
A1_SEMANTIC_RECONSTRUCTION
A2_REFERENCE_CONFORMANCE
A3_ACTION_RELATION
A4_TRAJECTORY_SAFETY_RELATION
A5_HARDWARE_CONSTRAINED_SIMULATION
A6_PHYSICAL_HARDWARE_ATTESTED
OPAQUE_CONTROLLER
```

3. Make each level cumulative and bind exact evidence digests. A higher label without required lower evidence fails validation.
4. Implement immutable admission snapshots keyed by admission ID, digest, controller ID, bundle digest, backend profile digest, and revision.
5. Implement admission revocation and anti-rollback.
6. Create a clean-room NEST reconstruction tool skeleton that reads only a manifest and content-addressed artifacts.
7. Add mutation tests that remove or alter topology, one tensor, delay, neuron parameter, timestep, reset rule, codec, seed policy, backend version, and mapping report.
8. Prove each required mutation changes a digest and either fails reconstruction/conformance or requires a distinct admission.
9. Add an explicit opaque-controller path. It can receive mission authorization only in a profile that permits it; receipts and status label it honestly.
10. Keep admission tooling out of the Gate dependency graph. Gate loads only verified signed admission snapshots.

### Exit gate

Gate can answer, without importing Engram or NEST, whether an exact controller/backend relation is admitted, revoked, opaque, or outside profile.

### Suggested commit

```text
admission: add profile-complete controller deployment records
```

## Phase 5 — implement challenges, mission leases, and revocation

### Objective

Delegate controller request authority to one Gate boot/session/mission without granting plant publication rights.

### Files to create

```text
crates/haldir-core/src/authority.rs
crates/haldir-state/src/authority.rs
crates/haldir-state/src/anti_rollback.rs
tools/haldir-ctl/src/bin/haldir-dev-lease.rs
```

### Steps

1. Implement Gate challenge generation using the OS CSPRNG; fail startup if entropy fails.
2. Store pending challenges in a bounded per-vehicle table with local monotonic deadlines and consumed flags.
3. Implement mission lease acceptance in the exact order specified earlier.
4. Intersect lease limits with policy, admission, NCP, and plant limits; never let a lease widen another authority.
5. Bind one controller intent signing key and exact intent route per lease.
6. For MVP, bind one controller intent epoch per lease; controller restart requires a new challenge and lease.
7. Implement revocation for lease, key, admission, and policy subjects with issuer-monotonic epochs.
8. Implement durable anti-rollback state containing only highest terms/epochs and retired identities. Do not persist active leases.
9. Use atomic snapshot writes: canonical bytes to temporary file, fsync file, rename, fsync directory. Include generation, previous digest, and Gate storage-key signature or MAC under a separate local storage key.
10. On corruption, rollback, or unavailable durable state, enter `FAULT_LATCHED`; do not reset counters.
11. Add a development lease issuer tool that clearly marks outputs `DEVELOPMENT_ONLY` and refuses assurance deployment IDs.
12. Test simultaneous lease candidates, stale challenge, reused nonce, wrong boot/session/policy/admission, lower term, excessive limits, and revocation races.

### Exit gate

A lease valid before Gate restart cannot become active after restart, and no controller lease contains or implies NCP command publication authority.

### Suggested commit

```text
authority: add challenge-bound mission leases and anti-rollback
```

## Phase 6 — implement bounded state machines and formal models

### Objective

Make restart, replay, handoff, session change, and ambiguous publication semantics explicit before adding transport.

### Files to create

```text
crates/haldir-state/src/
  lib.rs
  clock.rs
  gate.rs
  session.rs
  controller_replay.rs
  output_stream.rs
  mission.rs
  authority.rs
  state_cache.rs
  fault.rs
  journal.rs
formal/HaldirAuthority.tla
formal/HaldirAuthority.cfg
formal/HaldirEvidence.tla
formal/README.md
```

### Steps

1. Implement an injectable `MonotonicClock` trait and deterministic test clock.
2. Implement independent state machines for Gate process, NCP session, publication authorization/future plant authority, mission lease, controller replay, Gate output, state readiness, and fault latch.
3. Keep all mutable per-vehicle authorization state owned by one actor object.
4. Implement two-phase replay reservation/commit. Correctly signed and scoped fresh intents consume their intent sequence even when policy denies; malformed/wrong-authority traffic does not.
5. Implement output sequence reservation only after policy ALLOW and output queue capacity reservation.
6. Never reuse an allocated sequence. A publish failure creates a gap and ambiguous evidence, not sequence reuse.
7. Implement restart with new boot ID/output epoch, no active lease restoration, empty state readiness, and mandatory reacquisition.
8. Implement session generation change as a high-priority event that invalidates pending challenges, lease, source cache, and output authorization for the old pair.
9. Model controller handoff as lease replacement and intent epoch replacement; Gate output stream need not change.
10. Model crash points before/after output allocation, serialization, publish call, local return, receipt append, Crebain receive, and application.
11. Write TLA+ properties:

```text
PlantAccepted => PublishedByGate
PublishedByGate => CurrentSessionAtAllocation
PublishedByGate => ActiveMatchingMissionLease
PublishedByGate => CurrentAdmission
PublishedByGate => NativePolicyAllowed
Deny => NoOutputCreated
RetiredIntentEpoch => NeverActiveAgainWithinLease
GateRestart => NoPreRestartLeaseActive
SameOutputPosition => SameExactBytes
ApplicationEvidence => CorrespondingExactOutputDigest
```

12. Run bounded model checking across at least two controllers, two leases, two sessions, restart, revocation, delayed messages, duplicate messages, publish ambiguity, and queue saturation abstractions.
13. Check the model and implementation state-transition tables against each other in a generated documentation test.

### Exit gate

The model finds no invariant violation in the declared bounds, every runtime transition has a typed event/result, and no hidden mutable global authority exists.

### Suggested commits

```text
state: add bounded authority and stream state machines
formal: model restart replay and publication ambiguity
```

## Phase 7 — implement deterministic native policy

### Objective

Create the smallest trustworthy mission policy for `Hold` and local-NED velocity using fixed-point checked arithmetic.

### Files to create

```text
crates/haldir-policy-native/src/
  lib.rs
  input.rs
  output.rs
  bounds.rs
  norm.rs
  slew.rs
  duty.rs
  freshness.rs
  geofence.rs
  uncertainty.rs
  phase.rs
  validity.rs
  reason.rs
  error.rs
policies/reference-v1/*
```

### Required pure API

```rust
pub fn decide(
    authority: &AuthoritySnapshotV1,
    intent: &VerifiedIntentV1,
    state: &TrustedStateSnapshotV1,
    history: &BoundedPolicyHistoryV1,
    policy: &CompiledNativePolicyV1,
    now: MonotonicNanoseconds,
) -> PolicyDecisionV1;
```

The function performs no I/O and cannot allocate without a documented bound.

### Steps

1. Validate action class and exact local-NED frame.
2. Reject each component outside its bound; do not clamp.
3. Compute vector norm with widened integer arithmetic and an overflow-proof comparison against squared maximum speed.
4. Enforce acceleration/slew against the last applied or selected command according to the explicitly chosen reference. Do not compare to the last requested command if it was denied or never applied.
5. Maintain bounded duty and continuous-motion windows in actor state.
6. Validate source and state age using Gate receive monotonic time, not controller time.
7. Perform prospective geofence checks over the effective command horizon using conservative fixed-point integration and uncertainty inflation.
8. Define a bounded rectangular or convex region for the reference plant. Use integer half-space tests; avoid general computational geometry in MVP.
9. Enforce mission-phase transitions and allowed action sets.
10. Compute effective output validity as the minimum of requested validity, remaining lease duration, policy cap, state/source freshness headroom, NCP cap, and plant profile cap.
11. Deny when effective validity is below the configured minimum useful horizon.
12. Return stable machine reason codes and bounded derived values.
13. Create policy self-test vectors embedded by digest in `PolicyBundleV1`.
14. Add optional Cedar only after native policy passes performance. Cedar receives coarse strings/booleans, not raw numeric/geometric responsibility. Any diagnostic error denies.

### Required tests

- every numeric boundary at `limit-1`, `limit`, and `limit+1`;
- negative/down-axis conventions;
- norm corners where components pass but norm fails;
- overflow adversaries;
- stale source/state exactly at boundary;
- lease/policy validity intersection;
- geofence corners and uncertainty inflation;
- last-selected versus last-applied semantics;
- duty-window eviction and clock rollback;
- deterministic result across repeated runs and thread scheduling;
- policy package mutation and rollback.

### Exit gate

The pure policy passes unit, property, fuzz, self-test, and bounded performance tests; no float, network, neural, NCP, Galadriel, PID, or plant SDK dependency exists.

### Suggested commit

```text
policy: add fixed-point mission authorization core
```

## Phase 8 — implement deterministic reference plant and application evidence

### Objective

Create a fast, deterministic oracle that separates command receipt, acceptance, selection, application, fallback, and measured response before Crebain complexity is introduced.

### Files to create

```text
crates/haldir-reference-plant/src/
  lib.rs
  model.rs
  command.rs
  buffer.rs
  safe_action.rs
  evidence.rs
  fault.rs
  clock.rs
range/reference-plant/*
```

### Plant model

Use a discrete kinematic point-mass profile with integer position and velocity units. Define exact update equations, saturation, command validity, and safe-action semantics. The first profile is simulation-only:

```text
state = position_mm[3], velocity_mm_s[3], tick
command = Hold | VelocityLocalNed
rate = 50 Hz fixed simulated time
safe action = transition commanded velocity to zero under declared bounded deceleration, then hold
```

Do not call this universally safe.

### Steps

1. Implement a controllable simulation clock independent of wall time.
2. Implement command ingestion keyed by exact Gate output stream/session/source metadata.
3. Separate events: `Received`, `Validated`, `Accepted`, `Selected`, `Applied`, `Expired`, `SafeActionStarted`, `SafeRegionReached`, `ResponseObserved`.
4. Make all evidence deterministic and canonical.
5. Implement packet drop, delay, reorder, duplicate, partition, process restart, clock fault, and adapter-failure injections.
6. Implement command expiration and the named safe-action profile.
7. Correlate application evidence with exact output digest and decision ID mapping.
8. Add trajectory export for later backend and Prisoma research tools.
9. Add a reference direct-controller baseline used only for differential latency/trajectory comparison, never in the assurance deployment.
10. Prove no hidden default command continues indefinitely.

### Exit gate

Given a seed and event schedule, the plant produces byte-identical evidence and trajectory; every output stage is distinguishable; crash/loss reaches the declared reference safe region within a computed and tested bound.

### Suggested commit

```text
plant: add deterministic command application and safe-action oracle
```

## Phase 9 — implement the immutable-tag-pinned NCP v0.8.0 adapter

### Objective

Translate stable Haldir semantics into the immutable NCP `v0.8.0` release without leaking version-specific generated types into the rest of Haldir.

### Files to create

```text
crates/haldir-ncp08/src/
  lib.rs
  compatibility.rs
  session.rs
  source.rs
  output.rs
  conversion.rs
  validator.rs
  vectors.rs
  error.rs
docs/NCP-COMPATIBILITY.md
```

### Steps

1. Add NCP as an exact 40-character Git revision or a vendored reviewed source package; commit `Cargo.lock`.
2. Compute `NcpCompatibilityRecordV1` from exact commit, proto/schema digests, behavior-vector digest, enabled increment, and Haldir adapter revision.
3. Import NCP generated types only in this crate.
4. Implement actual-key/session validation before state mutation.
5. Implement trusted source normalization retaining exact source epoch/sequence and source time.
6. Implement Gate output allocator interface that receives an already authorized semantic command and immutable current session/source/authority snapshot.
7. Map `Hold` and `VelocityLocalNed` to the exact NCP command channel/profile supported by Crebain. Use the NCP key builder; do not concatenate keys ad hoc.
8. Convert mm/s integer components to NCP finite float values through one named function. Document rounding and maximum error; prove monotonicity and bound preservation.
9. Assign final NCP stream epoch/sequence and `t` from Gate state/time only.
10. Assign source from the independently verified state cache only.
11. NCP v0.8.0 lacks plant authority. Omit it exactly as the schema requires and mark the compatibility profile `PRE_AUTHORITY_ACL_ONLY`; do not create an extension field.
12. Serialize once, validate with NCP's own validator, digest exact bytes, and return an immutable prepared output.
13. Execute all applicable upstream behavior/conformance vectors in CI, including source restart and retired epoch behavior.
14. Add Haldir vectors for session generation mismatch, source restart, output retry same bytes, new logical command next sequence, Gate restart new epoch, and stale retired epoch.
15. Ensure a transport retry reuses exact prepared bytes/sequence while a TTL refresh is a new logical frame with next sequence.

### Exit gate

The adapter is the only crate aware of NCP v0.8.0 structs; every final publisher-owned field comes from Gate; all upstream and Haldir mapping vectors pass.

### Suggested commit

```text
ncp08: add exact-pinned Gate-owned stream adapter
```

## Phase 10 — implement Gate runtime, bounded queues, journal, and receipts

### Objective

Compose the pure subsystems into one one-vehicle service with explicit side-effect boundaries and honest evidence.

### Files to create

```text
crates/haldir-evidence/src/*
crates/haldir-gate/src/
  main.rs
  config.rs
  startup.rs
  actor.rs
  event.rs
  pipeline.rs
  publisher.rs
  status.rs
  shutdown.rs
  health.rs
  metrics.rs
  error.rs
deploy/development/*
deploy/assurance-sim/*
```

### Evidence spool design

Use bounded append-only segment files. Each record contains:

```text
magic | format_version | record_length | record_bytes | CRC32C
```

`record_bytes` is a canonical signed evidence event. A segment header includes Gate ID, boot ID, segment sequence, previous completed-segment digest, and creation metadata. The segment footer includes record count, final digest, and Gate signature.

Rules:

- a local segment chain is acceptable because the local spool is not a lossy transport plane;
- never require a remote collector for command authorization;
- recovery may truncate only an incomplete final record/segment tail;
- corruption of a completed record or signed footer latches a profile-defined fault;
- size and record count are bounded;
- critical decision/output events have reserved capacity;
- export copies may be dropped only under the declared safety-first profile with a signed loss summary;
- an evidence-required profile quiesces before exhaustion.

### Runtime steps

1. Implement signed deployment-package loading and strict unknown-field rejection.
2. Implement startup exactly in the startup state machine defined earlier.
3. Use one per-vehicle actor; start with one vehicle.
4. Implement separate bounded channels for control, state, intent, output, and evidence, with reserved control capacity.
5. Implement ingress byte/rate limits before signature verification.
6. Implement the exact 13-stage intent pipeline.
7. Take one immutable authority/state/policy snapshot per decision.
8. Reserve output queue capacity before output sequence allocation.
9. Append `DECIDED_ALLOW` and `OUTPUT_PREPARED` before calling transport according to a documented local durability policy.
10. Record publish call/return without claiming receive/application.
11. Publish `GateStatusV1` on a separate read-only observer route.
12. Implement graceful shutdown and abrupt-crash recovery semantics.
13. Add health endpoints only over a local Unix socket or authenticated read-only path; no command administration API.
14. Add structured metrics with bounded labels. Never use untrusted IDs as unbounded metric labels.
15. Add a `--check-config` mode that verifies package, trust, policy self-tests, NCP pin, filesystem permissions, and routes without opening command subscriptions.
16. Add a `--development` mode that cannot load assurance keys or emit assurance-class receipts.

### Exit gate

The process can run a pure signed intent through policy to a prepared output/reference plant; every denial creates no output; queues and spool remain bounded; crash-tail evidence is explicit.

### Suggested commits

```text
evidence: add bounded signed event spool

gate: compose one-vehicle authorization runtime
```

## Phase 11 — implement secure Zenoh transport and prove ACL delivery

### Objective

Establish transport identity, exact routes, and complete mediation at the NCP/Haldir bus boundary.

### Files to create

```text
crates/haldir-transport-zenoh/src/*
range/zenoh/router-template.json5
range/zenoh/client-*.json5
range/zenoh/verify-haldir-acl.py
range/compose/secure-reference.yml
```

### Identity set

Provision distinct development identities:

```text
controller-a
controller-b
gate
robot-crebain
observer
mission-authority-service
admission-authority-service
```

Application signing keys remain separate.

### Route policy

- controller A may PUT only its exact intent route;
- controller B may PUT only its exact intent route;
- Gate may GET controller intents, robot state, lifecycle/authority, and may PUT final command, receipts, status, and Gate challenge;
- robot/Crebain may PUT state and application evidence and GET final command;
- observer may GET allowed state/command/evidence/status but PUT nothing;
- authorities may PUT only their exact lease/admission/revocation routes or use an authenticated local orchestration path;
- no controller may PUT any final command route;
- no observer or robot may PUT a command;
- Gate may not publish robot sensor state.

### Steps

1. Adapt NCP's secure client/router templates rather than inventing a new transport security model.
2. Require TLS-only endpoints, mTLS, hostname verification, no multicast/gossip/listeners in clients, and default-deny ACLs.
3. Bind actual received keys and authenticated principals into the transport event.
4. Implement reconnect so a new connection does not revive an old Gate session/lease.
5. Write a live verifier that uses a unique nonce and authenticated observer for every identity×route trial.
6. Require a successful allowed baseline before accepting a forbidden non-delivery result.
7. Use a bounded rejection window plus late-delivery quarantine.
8. Prove a no-certificate client cannot establish the router connection.
9. Run the matrix under normal operation, reconnect, delayed samples, and stale certificates.
10. Retain router/client configs with paths sanitized and certificate fingerprints recorded.

### Exit gate

The full identity×route delivery matrix passes, direct controller final-command publication remains unobserved, and local `put()` return values are not used as proof.

### Suggested commit

```text
transport: add mTLS actual-key delivery and ACL range
```

## Phase 12 — integrate Crebain as the sole plant owner

### Objective

Make Crebain's native `CommandPlant` the only actuator-affecting path in the assurance profile and emit application evidence.

### Cross-repository rule

Create a separate Crebain branch and PR. Haldir MUST remain buildable against the reference plant while Crebain changes are reviewed.

### Crebain changes

1. Migrate all NCP pins together to the selected v0.8.0 compatibility target in a dedicated commit.
2. Update command/session/source handling for wire 0.8.
3. Register and manage the optional NCP lifecycle only under an explicit assurance feature/profile.
4. Choose one native Rust control plane. Do not wire both TypeScript and native command paths.
5. Add a Gate-only final command profile and exact publisher/route expectations.
6. Add a correlation mapping from Gate decision ID to exact NCP output digest without making the correlation field authoritative.
7. Emit signed or authenticated `ApplicationEvidenceV1` stages: received, validated, accepted/rejected, selected, applied/failed, expired, safe-action transition, measured response reference.
8. Define `reference-kinematic-hold-v1` for the deterministic adapter.
9. Disable or remove assurance-build access to browser injection, generic Tauri commander commands, direct GuidanceController output, direct ROS/MAVROS publishers, and test hooks.
10. Inventory arm/mode/takeoff/land and ensure none is in the first profile.
11. Add startup checks proving one actuator owner.
12. Add crash/reconnect/session-generation tests.

### Haldir changes

- verify Crebain evidence signatures/identity outside the ALLOW decision;
- correlate stages by decision/output digest;
- display unknown when evidence is missing;
- add complete-mediation manifest digest to the deployment package.

### Exit gate

A direct controller write cannot reach `CommandPlant`; only Gate-authored commands are accepted; Crebain expiration reaches the reference safe region; application evidence distinguishes every stage.

### Suggested Crebain commits

```text
ncp: migrate optional bridge to NCP v0.8.0
security: make CommandPlant the sole assurance actuator path
ncp: emit command application and safe-action evidence
```

## Phase 13 — integrate Engram/NEST as an isolated intent producer

### Objective

Drive the closed loop with a real NEST controller while preserving the controller/Gate protocol and authority boundary.

### Cross-repository rule

Create a separate Engram branch. Do not expose private Engram implementation in Haldir commits or public evidence if its repository remains non-public.

### Files

Haldir:

```text
crates/haldir-python/*
tools/admission/nest/*
range/controller/nest/*
contracts/vectors/python/*
```

Engram-local files SHOULD be limited to an adapter module, controller manifest/export support, tests, and example configuration.

### Steps

1. Complete the local Engram gap report and reproduce the original NEST 3.9 run in an immutable environment; retain every cleanup warning rather than normalizing it away.
2. Create a separate pinned NEST 3.10 environment, port the controller with the smallest reviewed compatibility change, and run paired 3.9/3.10 golden, held-out, timing, restart, and cleanup comparisons. Do not replace the historical 3.9 evidence with 3.10 results.
3. Resolve or precisely allowlist lifecycle cleanup warnings before presenting a readiness demonstration; an allowlist entry must name version, exact message, cause, and why it cannot mask a leak or incomplete shutdown.
4. Freeze the controller input schema: exact state fields, NCP source position, units/frame, codec, update cadence, missing-input behavior, and maximum processing age.
5. Freeze the output schema to `Hold` or `VelocityLocalNed` only.
6. Implement `haldir-python` with PyO3 or a local sidecar. The Rust contract library performs canonical encoding and signing; Python must not independently reimplement canonical CBOR.
7. Give the controller only its intent mTLS identity and controller application signing key.
8. Do not give it Gate, mission authority, admission authority, Crebain evidence, or NCP final-command keys.
9. Acquire a Gate challenge and development mission lease through an orchestrator; keep the signing authority outside the controller process.
10. Start a fresh intent epoch at sequence one.
11. On each admitted state update, compute the neural controller action, construct the semantic intent, bind source/session/lease/admission/boot, sign, and publish to the exact controller route.
12. Reject or hold locally on controller serialization failure, but rely on Gate as the authorization boundary.
13. Package the exact controller bundle, codec, NEST environment, and conformance traces.
14. Add malicious variants: malformed signature, wrong actual key, stale source, replay, excessive velocity, forbidden phase, stale lease, wrong bundle/profile.
15. Record NEST cleanup and process termination evidence.

### Exit gate

A real NEST computation drives the reference plant only through Haldir and Crebain; no final NCP frame is constructed in Engram; malicious variants create no accepted plant command.

### Suggested commits

Haldir:

```text
bindings: add Rust-authoritative Python intent emitter
range: add isolated NEST controller fixture
```

Engram:

```text
integration: emit signed Haldir semantic intents
artifacts: export profile-complete NEST controller bundle
```

## Phase 14 — run the deterministic end-to-end acceptance campaign

### Objective

Validate the full software vertical slice before PX4 or a second backend.

### Required scenarios

At minimum:

1. allowed hold;
2. allowed bounded local-NED velocity;
3. malformed CBOR/COSE;
4. wrong application key/role;
5. wrong actual intent route;
6. direct final-key bypass;
7. stale/wrong session generation;
8. duplicate/lower intent sequence;
9. retired intent epoch;
10. source restart with command stream continuity;
11. stale/missing source;
12. excessive component and norm;
13. slew/duty/geofence/phase denial;
14. lease expiry/revocation;
15. admission revocation or bundle substitution;
16. Gate restart and old lease replay;
17. Gate crash at every output/evidence boundary;
18. transport partition/drop/reorder/duplicate;
19. output/evidence queue saturation;
20. evidence collector outage and spool full profile;
21. Crebain restart and plant loop stall;
22. safe-action trigger/failure branch.

### Baselines

Run:

- direct semantic controller→reference plant in an isolated non-assurance fixture;
- NCP/Crebain safety without Haldir mission policy;
- full Haldir path.

Compare command/trajectory semantics and overhead; never expose the direct baseline route in the assurance configuration.

### Exit gate

All unauthorized scenarios produce zero accepted plant applications; allowed actions stay within the documented conversion error; crash/fault reaches safe region within measured bound; receipts and application evidence reconstruct the outcome honestly.

### Suggested commit

```text
range: add deterministic Haldir acceptance campaign
```

## Phase 15 — integrate PX4-SITL through Crebain

### Objective

Demonstrate the same authority and intent architecture on a realistic simulated multirotor plant without broadening the action set.

### Steps

1. Pin PX4, simulator, ROS/MAVROS, Crebain, NCP, and Haldir revisions.
2. Create a network/process diagram for every actuator-affecting route.
3. Define exact local-NED frame conventions and test sign/axis transformations.
4. Define `px4-sitl-hold-v1` with entry preconditions, mode transition, watchdog behavior, expected command path, failure branches, and safe region.
5. Keep arm/takeoff/land outside Haldir. Start the scenario in a controlled already-airborne or test-ready state through a separate range setup step that is not presented as Haldir authorization.
6. Route only Gate-authored velocity/hold commands through Crebain's sole actuator callback.
7. Disable alternative offboard publishers and UI controls.
8. Run benign hold and inspection trajectories.
9. Repeat the command, authority, source, Gate, transport, Crebain, and watchdog fault campaign.
10. Measure time to mode transition/safe region and distinguish simulator from physical behavior.
11. Retain PX4 logs, simulator state, Haldir receipts, NCP frames, and Crebain evidence under synchronized correlation IDs.

### Exit gate

The PX4-SITL vehicle is controlled only through Gate for the declared profile, faults stop fresh authority and trigger the named simulated fallback, and no claim extends to physical flight.

### Suggested commits

```text
range: add PX4-SITL assurance profile
integration: connect Crebain CommandPlant to PX4-SITL
```

## Phase 16 — add Galadriel advisory evidence without control authority

### Objective

Use existing cross-sensor work honestly without making an uncalibrated detector a hidden safety controller.

### Steps

1. Pin Galadriel and its NCP compatibility.
2. Define an exact signed advisory envelope or adapter into `AdvisoryEvidenceRefV1`.
3. Give Galadriel read-only sensor/observation access and one advisory-output route; no command rights.
4. Validate session/source positions, producer identity, schema, and freshness.
5. Record advisory status/digest in decision evidence without changing policy.
6. Run missing, stale, incompatible, and `InsufficientEvidence` cases.
7. Add a later experimental policy that denies on `StateUnusable` only after a separate calibration report and policy signature; leave it disabled by default.
8. Prove `NominalAdvisory` cannot widen limits or create ALLOW.
9. Publish current false-alert/abstention limitations alongside experiments.

### Exit gate

Galadriel can disappear, fail, or report nominal without granting authority; the MVP decision path remains functionally identical aside from evidence recording.

### Suggested commit

```text
integration: record Galadriel as advisory state evidence
```

## Phase 17 — export verified traces to Prisoma, pid-rs, Cortexel, and Rerun

### Objective

Provide ecosystem reuse without adding research or visualization code to Gate.

### Files

```text
tools/haldir-ctl/src/bin/haldir-export-research.rs
tools/haldir-ctl/src/bin/haldir-export-viz.rs
contracts/schemas/haldir-research-trace-v1.schema.json
```

### Steps

1. Verify Gate and Crebain signatures and spool segment integrity before export.
2. Emit signed or manifest-anchored JSONL preserving exact source `{epoch,seq}`, controller intent, output stream, decision, policy/admission, application, and response references.
3. Optionally derive Parquet/Rerun/Cortexel artifacts with a manifest back to canonical events.
4. Mark simulation, advisory, uncalibrated, and unknown outcomes.
5. Ensure exporter has no PUT/control credentials.
6. For pid-rs, record exact SHA, estimator regime, preprocessing, support assumptions, seeds, and negative results.
7. For Prisoma, use read-only safe mode and local files; do not expose its unauthenticated development bridges remotely.
8. For Cortexel, enforce mandatory provenance captions and separate decision from application.
9. For Rerun, open only exported immutable recordings or a read-only proxy; the viewer identity has no control-plane credentials.
10. Silmaril outputs are accepted only as separately manifested range fixtures and never through this evidence-export path.

### Exit gate

All research/visual artifacts are reproducible from verified canonical evidence and cannot influence live Gate state.

### Suggested commit

```text
tools: export verified Haldir evidence for offline research and visualization
```

## Phase 18 — implement backend-aware admission research

### Objective

Test the real neuromorphic/security hypothesis: whether backend transformation evidence predicts mission-relevant behavior better than a package hash.

### Stage 18A — profile-complete NEST reference

1. Define `fixed-weight-lif-control-v1` with exact allowed primitives and limits.
2. Extend the Engram artifact path until topology, weights, delays, models, timestep, reset, codecs, seeds, and dependencies are complete.
3. Reconstruct in a clean environment from manifest only.
4. Run reference conformance traces separately under the immutable NEST 3.9 reproduction and NEST 3.10 compatibility environments.
5. Compare semantic actions, timing, reset/cleanup behavior, and reference-plant trajectories; classify every difference as accepted, bounded, or admission-blocking.
6. Issue A1/A2 evidence separately for each environment; never let one version's admission imply the other.

### Stage 18B — independent software backend

1. Capability-probe at least two candidates that support the restricted profile.
2. Select based on semantic fit, maintenance, reproducibility, and implementation independence—not popularity.
3. Implement the same codec and logical graph independently.
4. Preregister action and trajectory thresholds before held-out evaluation.
5. Run development, validation, held-out, and adversarial source traces.
6. Issue or refuse A3/A4 admission honestly.

### Stage 18C — NIR

1. Serialize only the supported common subset.
2. Canonicalize the NIR artifact and bind exporter/importer versions.
3. Round-trip source→NIR→source and source→NIR→target.
4. Compare graph semantics and behavior; do not call a successful parse equivalent.

### Stage 18D — Rockpool/XyloSim

1. Attempt mapping to one named Xylo profile.
2. Retain design-rule, resource, quantization, approximation, generated configuration, and simulator digests.
3. Fail admission on unsupported mandatory features or unreviewed topology changes.
4. Run the held-out closed-loop corpus through XyloSim.
5. Label successful evidence A5 hardware-constrained simulation.

### Stage 18E — optional SpiNNaker2/Brian2

1. Use the public Brian2 emulation path only when dependencies are reproducible.
2. Bind py-spinnaker2/NIR/Brian2 versions and limitations.
3. Do not make hardware claims without actual hardware and private dependency access.

### Metrics

- action agreement and component error;
- no-output/hold disagreement;
- timing/deadline miss rate;
- trajectory divergence over horizon;
- minimum geofence/safety-margin difference;
- Gate ALLOW/DENY disagreement;
- reset/restart sensitivity;
- perturbation/loss/saturation response;
- mapping mutation detection;
- confidence intervals over preregistered scenarios/seeds.

### Exit gate

A backend-specific admission names the exact tested relation and predicts held-out outcomes better than bundle hashing alone, or the experiment publishes a negative result and refuses admission.

### Suggested commits

```text
research: add profile-complete NEST admission corpus
research: evaluate independent backend and NIR relation
research: add Rockpool XyloSim constrained admission profile
```

## Phase 19 — build the adversarial range

### Objective

Continuously test authority, protocol, policy, plant, and evidence failures using current attacks rather than a detached CTF UI.

### Attack modules

Create one deterministic executable/module per attack:

```text
wrong_route
forged_signature
stolen_transport_identity_wrong_app_key
stolen_controller_key_expired_lease
session_generation_replay
intent_replay
retired_epoch_replay
foreign_output_epoch
source_restart
source_spoof_wrong_principal
state_staleness
bundle_substitution
backend_profile_substitution
policy_rollback
revocation_starvation
crypto_flood
queue_saturation
spool_exhaustion
publish_crash_tail
crebain_stall
alternate_ros_bypass
safe_action_failure
```

Each module declares preconditions, expected decision/evidence/plant result, and cleanup. A test is invalid when its precondition was not established.

### Steps

1. Build scenarios from immutable manifests.
2. Give attackers only the credentials implied by the adversary class.
3. Verify successful benign baseline before every denial test.
4. Record actual delivery, not local send return.
5. Inject process kills at deterministic instrumentation points.
6. Exercise burst and sustained loads separately.
7. Run on reference plant in PR CI where feasible; run full secure/PX4 campaigns nightly or manually with retained evidence.
8. Add every discovered bug as a minimized regression fixture.
9. For Silmaril, Melkor, cobot-atlas, or relief-atlas inputs, verify the fixture manifest and digest before scenario launch; treat missing provenance as a scenario setup failure.
10. Prove `crebain-native` cannot publish its documented setpoint routes in the secure deployment.

### Exit gate

Every threat-model adversary maps to at least one executable scenario, and no scenario claims coverage it cannot establish.

### Suggested commit

```text
range: add authority policy and crash adversary corpus
```

## Phase 20 — measure performance, overload, and reliability

### Objective

Prove that inline authorization fits the declared control deadline and fails predictably under load.

### Initial targets

For the named one-vehicle 50 Hz hardware/profile, use design targets—not claims—until measured:

- decision p99 ≤ 2 ms;
- decision p99.9 ≤ 5 ms;
- end-to-end queue age before publish < 10 ms under declared load;
- zero missed 20 ms command deadlines in the preregistered benign campaign;
- bounded RSS and queue depth with no monotonic growth;
- revocation/session-close processing within one actor cycle under controller flood;
- crash/loss safe-region bound measured at p50/p99/max observed, without calling empirical maximum a formal worst case.

### Steps

1. Pin hardware, OS, CPU governor, core affinity, power mode, background load, and build flags.
2. Measure parser, signature, snapshot, native policy, optional Cedar, conversion/serialization, spool append, publish call, Crebain receive, application, and plant response separately.
3. Warm up explicitly; report cold start separately.
4. Use HDR histogram or an equivalent bounded high-dynamic-range recorder.
5. Test valid ALLOW, cheap malformed deny, valid-signature policy deny, worst accepted payload, controller flood, state flood, evidence outage, and reconnect.
6. Measure with and without Cedar; remove Cedar from MVP if it violates budget or adds no review value.
7. Verify memory and file bounds over a long-duration run.
8. Run fault injection during load.
9. Publish raw histograms and scripts.
10. If the target fails, simplify or narrow the declared rate/profile. Do not hide tail latency behind averages.

### Exit gate

The measured profile meets its deadline and resource limits, or the specification is narrowed to the measured rate/hardware with an explicit limitation.

### Suggested commit

```text
perf: add reproducible Gate latency overload and endurance campaign
```

## Phase 21 — harden the supply chain and create the first experimental Haldir release

### Objective

Produce a reproducible, reviewable experimental release without overstating NCP or hardware maturity.

### Steps

1. Freeze all exact source/dependency/tool/container pins.
2. Run dependency advisory/license/source policy.
3. Generate SBOM and build provenance.
4. Build from a clean environment and compare reproducible artifacts where possible.
5. Sign release artifacts and evidence manifests through the owner's release process.
6. Verify no development certificates, keys, paths, debug flags, unsigned-intent modes, or floating revisions are present.
7. Run all contract, conformance, model, fuzz smoke, reference range, secure ACL, Crebain, NEST, and performance gates.
8. Publish the exact assurance profile and limitations.
9. Label the Haldir release `experimental`, identify NCP `v0.8.0` precisely, and label the command-authority profile `PRE_AUTHORITY_ACL_ONLY`.
10. Include rollback/revocation procedure and key-rotation drill evidence.
11. Require independent review of authority graph, parser/crypto, state machine, complete mediation, and claims.

### Release blockers

Do not release when any of these is true:

- a controller still has final command credentials;
- an alternate actuator path remains in the assurance profile;
- live mTLS/ACL delivery evidence is absent;
- active lease can survive Gate restart;
- Crebain safe action is unnamed or unmeasured;
- decision and application evidence are conflated;
- NCP dependency floats;
- latency misses the declared command deadline;
- malformed input can panic or allocate without bound;
- backend admission claims exceed evidence;
- the release claims NCP supplies authority, publisher binding, or application acknowledgements that v0.8.0 does not supply.

### Suggested commit/tag

```text
release: prepare experimental Haldir Gate assurance-sim profile
```

Use an owner-approved annotated tag. Never move or force-update it.

## Phase 22 — adopt future NCP authority, identity, acknowledgements, and safe-action increments

### Objective

Adopt upstream NCP capabilities without changing Haldir's stable semantic intent boundary.

### Trigger

Start only when an immutable NCP release or exact reviewed commit implements the relevant increment with green cross-language conformance.

### Migration sequence

1. create a new `haldir-ncpXX` adapter or new adapter major version;
2. diff normative schema and behavior, not only generated Rust types;
3. update compatibility record and import new vectors;
4. for authority, make Crebain/plant issue a lease to Gate naming the permitted output epoch;
5. validate authority before sequence/epoch state as NCP specifies;
6. remove the pre-authority constrained restart path from the new profile when no longer needed;
7. bind NCP publisher identity to the authenticated Gate principal;
8. adopt applied/stop acknowledgements only after mapping their exact semantics to Haldir evidence stages;
9. adopt standardized safe-action profiles only when the vehicle-specific behavior/evidence is equivalent or stronger;
10. run the entire deterministic, secure, Crebain, NEST, PX4, adversarial, and performance campaign side-by-side against old/new adapters;
11. retire the old adapter through a signed deployment transition, not an in-place silent pin update.

### Exit gate

The same `HaldirIntentV1`, mission/admission model, and native policy operate unchanged; only the versioned NCP adapter and plant authority/evidence plumbing differ.

### Suggested commit

```text
ncp: migrate Gate to released plant-authority increment
```

## Cross-repository pull-request sequence

Use the following sequence unless evidence requires a narrower split:

1. Haldir normative specification and source ledger.
2. Haldir workspace/CI.
3. Haldir contracts and canonical vectors.
4. Haldir crypto/trust roles.
5. Haldir admission contracts.
6. Haldir authority/state/formal model.
7. Haldir native policy/reference plant.
8. Haldir NCP v0.8.0 adapter.
9. Haldir Gate runtime/evidence.
10. Haldir secure Zenoh range.
11. Crebain NCP v0.8.0 release migration.
12. Crebain sole-command-plant/application-evidence integration.
13. Haldir Python intent binding.
14. Engram/NEST intent emitter and complete artifact export.
15. Deterministic end-to-end campaign.
16. Crebain/PX4-SITL profile.
17. Galadriel advisory adapter.
18. Offline research/visual exporters.
19. NEST admission evidence.
20. Independent backend/NIR experiment.
21. Rockpool/XyloSim profile.
22. Performance/hardening/release.

Every PR description MUST contain:

- problem and authority-boundary impact;
- exact repositories/commits tested together;
- threat-model cases added or changed;
- tests and commands;
- evidence link/digest;
- compatibility and rollback plan;
- limitations and claims deliberately not made.

## Final agent completion checklist

Before declaring the project implemented, the agent MUST answer **yes** with evidence to every item:

### Authority

- Does the controller lack every final plant command credential?
- Does Gate alone originate final NCP frames?
- Are mission lease, admission, policy, NCP session, Gate output stream, controller intent stream, boot ID, ACL-exclusive publication capability, and future plant authority separate identities?
- Does restart invalidate active controller delegation?
- Can revocation preempt command traffic under load?

### Protocol

- Are all Haldir authority objects canonical and signed?
- Are parser and queue limits enforced before expensive work?
- Are actual route and authenticated principal bound?
- Are NCP stream/source/session semantics exact for the pin?
- Is a retry byte-identical and a new logical command a new sequence?

### Policy

- Is the policy pure, fixed-point, deterministic, bounded, and profile-specific?
- Are stale/missing state and arithmetic errors deny paths?
- Are limits intersected rather than overwritten?
- Is Cedar optional and diagnostic-fail-closed?

### Plant

- Is `CommandPlant` the sole actuator owner in the profile?
- Is safe action plant-owned, named, and measured?
- Are received, accepted, selected, applied, and observed distinct?
- Are all alternate ROS/MAVROS/browser/developer paths closed or excluded?

### Neural/backend

- Does NEST emit only semantic intent?
- Is the controller artifact reconstructable for the claimed profile?
- Are backend claims tied to exact compilation/runtime evidence and held-out behavior?
- Is Lava absent as a new required dependency?
- Are NIR and XyloSim labeled as representation/hardware-constrained simulation rather than proof of hardware equivalence?

### Evidence and operations

- Can every decision be reconstructed from signed bounded events?
- Are unknown crash-tail outcomes represented honestly?
- Is evidence storage bounded and recovery tested?
- Does the live mTLS/ACL delivery matrix pass?
- Do p99/p99.9 latency and long-run resource measurements meet the declared profile?
- Are exact commits, lockfiles, SBOM, provenance, and limitations published?
- Was every push normal and non-forced?

A single **no** blocks the corresponding assurance claim. The agent may still deliver a narrower experimental result, but it MUST update the profile and documentation to state exactly what remains unproven.

## Recommended repository layout and pull-request sequence

### Repository layout

```text
haldir/
├── Cargo.toml
├── Cargo.lock
├── README.md
├── SECURITY.md
├── LICENSE
├── deny.toml
├── rust-toolchain.toml
├── crates/
│   ├── haldir-contracts/
│   ├── haldir-crypto/
│   ├── haldir-core/
│   ├── haldir-state/
│   ├── haldir-policy-native/
│   ├── haldir-policy-cedar/
│   ├── haldir-admission/
│   ├── haldir-ncp08/
│   ├── haldir-transport-zenoh/
│   ├── haldir-evidence/
│   ├── haldir-reference-plant/
│   ├── haldir-gate/
│   ├── haldir-range/
│   ├── haldir-python/
│   └── haldir-testkit/
├── tools/
│   ├── pins.toml
│   ├── verify-pins.py
│   ├── verify-generated.py
│   ├── verify-evidence.py
│   ├── haldir-ctl/
│   ├── keygen-dev/
│   ├── lease-issuer-dev/
│   ├── admission/
│   │   ├── common/
│   │   ├── nest/
│   │   ├── nir/
│   │   ├── norse/
│   │   └── rockpool/
│   └── vector-gen/
├── range/
│   ├── compose/
│   ├── certs-dev/
│   ├── zenoh/
│   ├── reference-controller/
│   ├── reference-plant/
│   ├── attacks/
│   └── scenarios/
├── formal/
│   ├── HaldirAuthority.tla
│   ├── HaldirAuthority.cfg
│   └── README.md
├── contracts/
│   ├── cddl/
│   ├── vectors/
│   └── schemas/
├── policies/
│   ├── reference-v1/
│   └── test-fixtures/
├── docs/
│   ├── HALDIR-DISCUSSION-DECISIONS-2026.md
│   ├── HALDIR-NCP-V0.8.0-TRIPLE-CHECKED-AUDIT-AND-IMPLEMENTATION-SPECIFICATION-2026.md
│   ├── THREAT-MODEL.md
│   ├── AUTHORITY-GRAPH.md
│   ├── ASSURANCE-PROFILES.md
│   ├── NCP-COMPATIBILITY.md
│   ├── EVIDENCE-SEMANTICS.md
│   └── RESEARCH-PROTOCOL.md
└── .github/workflows/
    ├── ci.yml
    ├── conformance.yml
    ├── formal.yml
    ├── fuzz-smoke.yml
    └── nightly-range.yml
```

Keep development issuers and certificates unmistakably nonproduction. CI should fail if their fingerprints appear in a production-profile package.

### Reviewable PR sequence

1. **ADR/document correction only.** No code; establish NCP 0.8 ownership and supersession.
2. **Bounded scalar/contracts foundation.** No crypto/network.
3. **Canonical CBOR and golden vectors.** Cross-language verifier.
4. **COSE/key-role trust store.** Test-only issuers.
5. **Pure state machines and TLA+ model.** No NCP dependency.
6. **Native policy and deterministic plant.** Fixed-point only.
7. **NCP 0.8 adapter at exact pin.** Conformance corpus.
8. **Secure Zenoh fixture range and ACL matrix.** Reference controller/receiver.
9. **Gate service composition and evidence spool.** One vehicle.
10. **Crebain NCP migration.** Separate Crebain PR.
11. **Crebain product/reference-plant integration and application evidence.**
12. **Engram/NEST intent emitter.** Separate Engram PR plus Haldir range wiring.
13. **Manifest/admission profile.** Clean reconstruction.
14. **Independent backend experiment.**
15. **Rockpool/XyloSim constrained profile.**
16. **PX4-SITL profile.** Only after prior gates.

Avoid a single cross-repository mega-commit. Each repository should remain buildable and honest at every step.

## Research protocol and contribution claim

### Research questions

**RQ1 — residual authority:** How much unsafe semantic action remains possible after mTLS, ACLs, NCP session/stream validity, and generic plant bounds, and how much does Gate prevent within a declared profile?

**RQ2 — authority composition:** Can controller admission, mission lease, NCP session, Gate-owned stream, current ACL-exclusive publication capability, and future NCP plant authority be composed without replay, restart, handoff, or failure creating overlapping authority?

**RQ3 — backend-aware identity:** Which controller representation and transformation evidence best predicts whether mission-relevant action behavior is preserved across NEST and independently implemented or hardware-constrained backends?

**RQ4 — operational cost:** What latency, availability, false-denial, and engineering cost does inline semantic authorization add at 20–50 Hz?

**RQ5 — evidence fidelity:** How accurately can the system distinguish decision, publication, acceptance, application, and physical response under crash and partition?

### Baselines

Compare against:

- NCP transport identity/ACL plus receiver safety only;
- generic physical bounds without mission/context policy;
- a detached signature/receipt sidecar that does not own final publication;
- package hash admission;
- coarse Cedar-only policy at the topic/action boundary;
- Gate without backend-aware admission;
- Gate with manifest only;
- Gate with manifest, compilation receipt, and behavioral relation;
- Black-Box Simplex or another runtime-assurance baseline where the experiment is comparable.

Do not claim novelty merely because the implementation uses a neural controller. Runtime assurance and reference monitors have substantial prior art. The defensible contribution is the exact composition and evaluation of controller deployment identity, backend transformation evidence, mission authority, NCP stream/session fencing, exclusive Gate publication, future plant authority, and staged application evidence.

### Primary dependent variables

- unauthorized command creation rate;
- unauthorized plant application rate;
- attack success rate by adversary class;
- true/false ALLOW and DENY under labeled scenarios;
- time to safe region after faults;
- decision and end-to-end latency distributions;
- missed/expired command rate;
- availability under benign loss/restart;
- backend action disagreement;
- trajectory divergence and minimum safety margin;
- admission mutation-detection rate;
- evidence-stage completeness/ambiguity rate;
- CPU, memory, queue, and spool overhead.

### Experimental integrity

- preregister thresholds and held-out split;
- pin every repository and dependency digest;
- publish scenario/source-trace digests;
- retain negative and failed mappings;
- report all exclusions;
- separate development tuning from final evaluation;
- provide raw evidence and analysis scripts;
- distinguish simulation, emulation, hardware-constrained simulation, and physical hardware;
- use multiple seeds and paired comparisons;
- avoid treating a single controller/task as ecosystem-wide proof.

## Exact edits required in the existing decision record

The historical record should remain readable, but implementation readers need an unmistakable correction. Add a notice immediately after its opening metadata:

> **NCP wire-0.8 supersession notice.** The project-selection conclusions in this record remain current. The implementation mechanics in “Intended data flow,” “Signed intent,” “Downstream sequence ownership,” “Denial and reversion,” the reserved-sequence CI cases, and the sequence/re-anchoring acceptance criterion were written for NCP 0.7.1 and are superseded by `HALDIR-NCP-V0.8.0-TRIPLE-CHECKED-AUDIT-AND-IMPLEMENTATION-SPECIFICATION-2026.md`. Under NCP v0.8.0, controllers sign typed Haldir semantic intents; Gate originates every final NCP command with its own stream, timestamp, current session generation, and verified source. Gate is the exclusive ACL-authorized final publisher in the current `PRE_AUTHORITY_ACL_ONLY` profile and will hold plant authority only after a future NCP authority increment is adopted. No maximum sequence is reserved and no whole-frame byte-preserving relay claim remains.

Then make these direct changes:

1. In the data-flow diagram, replace `SignedIntentV1(exact NCP CommandFrame bytes)` with `HaldirIntentV1(typed semantic action + source/admission bindings)`.
2. In principal binding, replace “exact inner command bytes agree” with “typed semantic intent and all authority/admission/source bindings agree.”
3. Replace the signed-intent field list with the stable contract described here.
4. Replace the entire “Downstream sequence ownership” section with Gate-owned output-stream rules.
5. In the policy section, describe Cedar as optional and retain native fail-closed policy as normative.
6. Replace reserved-maximum reversion with next-normal-sequence explicit transition plus plant-owned fallback.
7. Extend receipts to the staged evidence model.
8. Replace the workspace's `SignedIntentV1` opaque-command type with `HaldirIntentV1` and an NCP adapter crate.
9. Replace CI tests for `MAX - 1`, reserved `MAX`, and sequence re-anchoring with session generation, output epoch transition, authority term, retired epoch, publish ambiguity, and crash/restart tests.
10. Replace acceptance item 3 with the separate controller-intent and Gate-output stream invariants.
11. Update the immediate milestone to begin with contracts/core/reference plant, then the NCP v0.8.0 release adapter.
12. Add the exact public NCP compatibility evidence, evidence-review date, and local-source verification requirements.

Do not delete the historical reasoning that led to the old decision. Mark it superseded so future readers understand why the design changed.

## Open decisions that must be resolved by measurement or upstream NCP

These are not reasons to delay the pure core, but they should remain explicit issues:

1. the future NCP authority, publisher-identity, acknowledgement, and safe-action wire shapes;
2. whether NCP provides a transport-bound publisher identity to Gate's receive path;
3. exact Crebain issuer/lifecycle interface for Gate plant authority;
4. the first production-safe action profile beyond the deterministic plant;
5. whether Cedar adds enough reviewability to justify its TCB/latency cost;
6. exact evidence-spool full behavior for each deployment profile;
7. whether one controller restart per lease is operationally acceptable or an explicit in-lease transition is needed later;
8. the first profile-complete Engram graph subset;
9. which independent backend best matches that subset after capability probing;
10. whether the chosen controller maps honestly to a named Xylo profile;
11. which source-time synchronization profile, if any, is strong enough to supplement Gate receive-time freshness;
12. whether active/passive Gate failover is needed after single-Gate authority semantics are proven.

## Final independent verdict

The Haldir program remains the best fit when stated narrowly:

> **Build an independent, inline mission-authorization reference monitor that terminates signed controller intent, holds the exclusive plant-facing NCP publication capability in the current profile, will hold future NCP plant authority, originates its own NCP 0.8 stream, and binds action permission to an admitted controller/backend deployment and fresh trusted state.**

The project solves a real residual security problem and is directly useful to Crebain even before neuromorphic portability work. It remains backend-independent because NEST, another software backend, and future hardware all emit the same typed Haldir intent. The neuromorphic research is justified only where backend transformations can invalidate the behavioral assumptions under which authority was granted.

The design should be rejected or narrowed if complete mediation cannot be demonstrated, if controller/admission authority remains self-asserted, if Crebain cannot provide a plant-owned expiry/safe-action path, if the core misses the measured command deadline, or if backend-aware admission predicts held-out behavior no better than a package hash.

## Primary-source ledger and audit trail

The implementation repository MUST materialize the claims in this document as machine-readable evidence rather than relying on this prose alone. Create:

```text
evidence/source-review/
├── audit-metadata.json
├── repository-classification.csv
├── repository-heads.jsonl
├── immutable-tags.jsonl
├── dependency-pins.csv
├── ncp-v080-file-digests.txt
├── ncp-v080-conformance-results.json
├── ncp-documentation-drift.md
├── web-cache-race.md
├── public-source-ledger.csv
├── local-private-source-ledger.private.csv
├── command-log.jsonl
└── claim-traceability.csv
```

`public-source-ledger.csv` columns:

```text
source_id,title,canonical_url,source_kind,publisher,publication_date,
retrieved_at_utc,immutable_identifier,local_digest,claim_ids,
limitations,public_or_private,reviewer,review_status
```

`claim-traceability.csv` columns:

```text
claim_id,claim_text,source_ids,inference_or_direct,design_requirement,
test_id,acceptance_threshold,non_claim,owner,status
```

Rules:

1. A branch URL is never an immutable identifier; record the exact commit and content digest.
2. A release note is authoritative for release scope but does not override the normative proto/schema.
3. A README claim is evidence of documentation, not proof of implementation.
4. A private/local Engram fact remains private/local and must not be paraphrased as public evidence.
5. A research paper supports only the population, platform, and experiment it reports; derived requirements must name the inference.
6. Every security claim in a release note must link to at least one test/evidence artifact.
7. Every unresolved contradiction blocks the affected compatibility claim, not necessarily unrelated development.
8. Retrieval timestamps use UTC; runtime validity uses monotonic time and never depends on these timestamps.

## References

### Sepahead ecosystem

- NCP wire-0.8 stream identity design: <https://github.com/sepahead/NCP/blob/v0.8.0/docs/wire-0.8-stream-identity.md>
- NCP security model: <https://github.com/sepahead/NCP/blob/v0.8.0/SECURITY.md>
- Crebain NCP bridge handoff: <https://github.com/sepahead/crebain/blob/main/docs/NCP_BRIDGE_HANDOFF.md>
- Haldir discussion record: <https://github.com/sepahead/haldir/blob/main/docs/HALDIR-DISCUSSION-DECISIONS-2026.md>
- NCP released security boundary: <https://github.com/sepahead/NCP/blob/main/SECURITY.md>
- NCP known limitations: <https://github.com/sepahead/NCP/blob/main/KNOWN_LIMITATIONS.md>
- NCP neuromorphic scope: <https://github.com/sepahead/NCP/blob/main/NEUROMORPHIC.md>
- NCP immutable release: <https://github.com/sepahead/NCP/releases/tag/v0.8.0>
- NCP v0.8.0 normative proto: <https://github.com/sepahead/NCP/blob/v0.8.0/proto/ncp.proto>
- NCP v0.8.0 changelog: <https://github.com/sepahead/NCP/blob/v0.8.0/CHANGELOG.md>
- Crebain security model: <https://github.com/sepahead/crebain/blob/main/SECURITY.md>
- crebain-native archived alternate frontend: <https://github.com/sepahead/crebain-native>
- Galadriel: <https://github.com/sepahead/galadriel>
- Prisoma: <https://github.com/sepahead/prisoma>
- pid-rs: <https://github.com/sepahead/pid-rs>
- Engram public status: <https://github.com/sepahead/engram>
- Manwe integration status: <https://github.com/sepahead/manwe>
- Cortexel visualization/provenance contract: <https://github.com/sepahead/cortexel>
- Silmaril Vision Studio: <https://github.com/sepahead/silmaril-vision-studio>
- Hermes-agent fork: <https://github.com/sepahead/hermes-agent>
- Rerun fork: <https://github.com/sepahead/rerun>
- Haldir reviewed commit: <https://github.com/sepahead/haldir/commit/2ad8058d2665dabf22e5943d0cdf7aac6f4d1c30>
- Crebain reviewed commit: <https://github.com/sepahead/crebain/commit/08ccafe5392465ea179406665ae936dd561aef6f>
- Galadriel reviewed commit: <https://github.com/sepahead/galadriel/commit/b9aac83a92fdd62b7eb9fa0f9a7f2b81795acd83>
- Prisoma reviewed commit: <https://github.com/sepahead/prisoma/commit/64bd881248463e7142d022bb95a5850bcf8fced2>
- pid-rs reviewed commit: <https://github.com/sepahead/pid-rs/commit/70b45f7b75fac06777ea215a73df01209490311a>
- Engram reviewed public commit: <https://github.com/sepahead/engram/commit/a4ce6ab9897dd3f1265b4cacc53f0afc349087cd>
- Manwe reviewed commit: <https://github.com/sepahead/manwe/commit/4e4c0a62aedb2b438f5439da3e2bc74e3f914bcd>
- crebain-native reviewed commit: <https://github.com/sepahead/crebain-native/commit/6ac8798ab1a50c599a76028442ee5ab33a489fcc>

### Independent problem and assurance evidence

- Secure ROS 2 credential-exfiltration and authenticated semantic injection proof-of-concept: <https://arxiv.org/abs/2511.00140>
- NIST SP 800-207, Zero Trust Architecture: <https://csrc.nist.gov/pubs/sp/800/207/final>
- DARPA Assured Autonomy program summary: <https://www.darpa.mil/research/programs/assured-autonomy>
- Mission-Level Runtime Assurance Framework for Autonomous Driving: <https://arxiv.org/abs/2606.06996>
- Automated Discovery of Semantic Attacks in Multi-Robot Navigation Systems, USENIX Security 2025: <https://www.usenix.org/conference/usenixsecurity25/presentation/yeke>
- Black-Box Simplex: <https://arxiv.org/abs/2102.12981>
- Neural Simplex Architecture: <https://arxiv.org/abs/1908.00528>
- SOTER: A Runtime Assurance Framework for Programming Safe Robotics Systems: <https://arxiv.org/abs/1808.07921>
- RTron: A Runtime Assurance Architecture for Component-Based Robotic Systems: <https://arxiv.org/abs/2103.12365>

### Protocol and authorization specifications

- CBOR, RFC 8949: <https://www.rfc-editor.org/rfc/rfc8949>
- COSE structures, RFC 9052: <https://www.rfc-editor.org/rfc/rfc9052>
- EdDSA/Ed25519, RFC 8032: <https://www.rfc-editor.org/rfc/rfc8032>
- Cedar authorization semantics: <https://docs.cedarpolicy.com/auth/authorization.html>
- RATS architecture, RFC 9334: <https://www.rfc-editor.org/rfc/rfc9334>

### Neuromorphic portability and platforms

- NIR paper: <https://www.nature.com/articles/s41467-024-52259-9>
- NIR documentation/framework support: <https://neuroir.org/docs/>
- NIR supported simulators and hardware: <https://neuroir.org/docs/support/>
- Rockpool Xylo overview and constraints: <https://rockpool.ai/devices/xylo-overview.html>
- Rockpool graph mapping: <https://rockpool.ai/advanced/graph_mapping.html>
- Rockpool Xylo deployment, mapping, quantization, and bit-precise simulation: <https://rockpool.ai/devices/quick-xylo/deploy_to_xylo.html>
- SpiNNaker2 documentation: <https://spinnaker2.gitlab.io/py-spinnaker2/>
- Lava archive notice: <https://github.com/lava-nc/lava>
- NEST current release: <https://www.nest-simulator.org/>
- NEST 3.10 release changes: <https://nest-simulator.readthedocs.io/en/v3.10/whats_new/v3.10/index.html>
- Intel neuromorphic computing and Loihi 2 research program: <https://www.intel.com/content/www/us/en/research/neuromorphic-computing.html>

### Runtime assurance and semantic monitoring prior art

- Black-Box Simplex: <https://arxiv.org/abs/2102.12981>
- Neural Simplex Architecture: <https://arxiv.org/abs/1908.00528>
- SOTER: A Runtime Assurance Framework for Programming Safe Robotics Systems: <https://arxiv.org/abs/1808.07921>
- RTron: A Runtime Assurance Architecture for Component-Based Robotic Systems: <https://arxiv.org/abs/2103.12365>
- SOTER on ROS: <https://arxiv.org/abs/2008.09707>
- RTron: <https://arxiv.org/abs/2103.12365>

The implementation must pin exact versions/commits in its own compatibility and research records; these branch/document links are starting references, not immutable dependency identifiers.
