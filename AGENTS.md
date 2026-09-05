# Haldir agent contract

Haldir develops an experimental authorization reference monitor for mission-level plant commands.
This file routes maintainers and coding agents to the owning contracts.
Every result must identify its exact tested scope and remaining limitations.

## Read before changing

Read [README.md](README.md), [CONTRIBUTING.md](CONTRIBUTING.md), and [docs/LIMITATIONS.md](docs/LIMITATIONS.md).
Inspect staged changes, unstaged changes, branches, and worktrees before recovery work.
Preserve another contributor's work and its staged state.
Then read the document that owns the changed surface:

| Surface | Required documents |
| --- | --- |
| Public behavior or claims | [Architecture](docs/ARCHITECTURE.md), [Claim ledger](docs/CLAIM-LEDGER.md), [Assurance profiles](docs/ASSURANCE-PROFILES.md) |
| Trust, signatures, roles, and scope | [Authority graph](docs/AUTHORITY-GRAPH.md), [Authority contract](docs/release/0.9.0/AUTHORITY-CONTRACT.md), [Protection model](docs/release/0.9.0/PROTECTION-MODEL.md) |
| Policy, state, and command creation | [Architecture](docs/ARCHITECTURE.md), [Authority contract](docs/release/0.9.0/AUTHORITY-CONTRACT.md), owning crate types and tests |
| Journal, publication, cancellation, or restart | [Evidence semantics](docs/EVIDENCE-SEMANTICS.md), [Limitations](docs/LIMITATIONS.md) |
| NCP or transport | [NCP compatibility](docs/NCP-COMPATIBILITY.md), [Secure reference](deploy/secure-reference-v1/README.md), [Dependency rationale](docs/DEPENDENCY-RATIONALE.md) |
| Deployment or external integration | [Threat model](docs/release/0.9.0/THREAT-MODEL.md), [Roadmap](docs/ROADMAP-STATUS.md), [Assurance profiles](docs/ASSURANCE-PROFILES.md) |
| Formal model or tool runner | [Formal guide](formal/README.md), exact pinned runner inputs and tests |
| Retained evidence | [Evidence index](evidence/README.md), the exact campaign's owner guide and verifier |
| Release, source lineage, or delivery | [Current-head qualification](release/0.9.0/current-head/README.md), [Contributing](CONTRIBUTING.md), predecessor-trusted verification code |

Inspect the schema, implementation, tests, and existing evidence before editing.
Current requirements, historical observations, and proposed capabilities are different records.

## Working method

1. Compare five to ten credible approaches before each material design decision.
2. State each approach's assumptions, benefits, failure modes, and decisive experiment.
3. Apply all twenty review lenses in [CONTRIBUTING.md](CONTRIBUTING.md).
4. Use independent council review for separable authority, arithmetic, lifecycle, and release decisions.
5. Record disagreements and resolve every failed requirement.
6. Implement generic behavior with explicit typed boundaries.
7. Add a negative control for every new accepted path.
8. Add a positive control for every new rejection path.
9. Freeze source identities, inputs, seeds, bounds, and criteria before inspecting outcomes.
10. Run the complete applicable gate before presenting a publication candidate.

A majority vote cannot override a failed scientific, authority, or provenance requirement.
Do not branch on a fixture name, paper, expected answer, or selected failure case.
Keep random samples separate from challenge cases and synthetic controls.
Retain failed runs and negative results.
Do not replace difficult cases to improve a score.

Recover useful changes at the hunk or component level.
Record retained, integrated, superseded, and rejected work with reasons.
Remove a branch or worktree only after preserving its useful changes and evidence.
Edit only assigned paths during delegated work.

## Authority and action invariants

The implemented composition is P0 `assurance-reference-v1`.
It contains no neural runtime or physical plant.
P1, P2, and P3 are not implemented as complete assurance profiles.

The closed decisions are `ALLOW`, `DENY`, and `ERROR`.
The initial semantic actions are `HOLD` and `VELOCITY_LOCAL_NED`.
A denial or error creates no new plant command.
Do not invent a refusal action, automatic hold, emergency-stop outcome, or implicit fallback.
A denied new intent does not cancel an older command.

Gate creates a fresh command from admitted semantics and its own trusted fields.
Controller command bytes are never forwarded.
A signed controller field cannot create a root of trust.
Require the exact signer, lease, admission, policy, route, session, vehicle, mission, source, and replay joins.
A signature is necessary evidence of the enrolled signer, not sufficient command authority.

Keep application signing and transport credentials separate.
A library type, role label, Boolean, report, or digest does not prove credential custody.
Local Rust ownership does not provide process isolation or a complete actuator-bypass inventory.
Preserve lower-level API and deployment limitations.

The pure policy has no network, filesystem, clock, RNG, or plugin access.
All signed authority, policy, replay, and mission-action contracts remain integer-valued.
Use named checked conversions for units, signs, widths, and time.
A local-NED velocity uses integer millimeters per second.
Acceleration is a different quantity and requires a separately qualified mapping.

Opaque epochs compare for equality within their declared scope.
Ordered counters and ratchets retain exact boot, subject, session, and stream scope.
Freshness uses Gate boot-local monotonic time.
Controller and source publisher timestamps remain provenance.

## Publication and evidence invariants

Preserve the journal-bound coordinator's order:

1. Reserve bounded logical journal capacity before decision mutation.
2. Keep prepared output bytes private.
3. Join the signed decision receipt to the exact prepared frame.
4. Locally sync the decision and linked `PublishCalled` records.
5. Repeat the authority, state, time, and horizon checks after that sync.
6. Expose the same exact frame for one publisher invocation.
7. Record only the local result that was actually observed.

Logical reservation does not preallocate filesystem blocks or guarantee successful I/O.
The reusable actor alone has no mandatory durable-journal guarantee.

Keep constructed, called, returned, received, validated, accepted, selected, applied, and observed stages distinct.
Local publisher `Ok` is not receiver delivery or plant application.
Reference-plant applied and observed values remain simulation model evidence.

Every invoked declared-live publication is terminal, including local `Ok`.
The pinned wire starts TTL at plant-local arrival.
This path observes neither that arrival nor an authenticated application acknowledgment.
Do not fabricate a live action interval or return a fresh publication capability.

A recovered dangling `PublishCalled` becomes `UnknownAfterPublish`.
Called is a pre-invocation ambiguity boundary, not proof that transport code ran.
Do not relabel an unknown outcome as success, failure, or non-delivery.
Recovered called-or-later history blocks decisions.
Elapsed time does not clear it; authenticated restart clearance remains unimplemented.
Invalid or corrupt retained evidence cannot become an empty clean history.

Cooperative shutdown and cancellation are different operations.
A latched stop request does not cancel an already selected publication or prove cleanup.
Preserve the missing supervisor, real timeout, remote-retirement, crash, and power-loss evidence boundaries.

## Optional integrations

Keep the default modeled adapter separate from the optional exact adapter.
The immutable NCP baseline is `v0.8.0` at `2f5bd586d4bb20c90362bb6f5698b7f64057ba4e`.
Its wire is `0.8` and contract hash is `d1b50a2d8a265276`.
Only `haldir-ncp08` owns the stable Haldir-to-NCP conversion.
Do not update a pin as documentation work.

The candidate local NCP direct profile excludes Haldir gating.
Reject a requested gated profile before any endpoint preparation.
Do not substitute direct execution after rejection.
Unsigned local requests and content digests are not signed Haldir intents.
Native Haldir migration and independent qualification remain NOT RUN.

Galadriel and PID evidence cannot grant, restore, refresh, or widen command authority.
No Haldir runtime integration with those evidence sources is qualified here.
Keep Engram/NEST, CREBAIN, Prisoma, and transport relationships at their exact documented scope.
Do not infer a runtime edge from a shared dependency or a portfolio diagram.

Respect externally assigned ownership.
Do not alter an active peer repository, its source, pins, index, branches, or worktrees.
In particular, separate PID development and Engram KG/ingestion work remain outside this task.

## Source, release, and verification

Release `0.9.0` remains `NO_GO`.
The current program uses `CH-T000..CH-T125`.
The preceding `T000..T119` records remain historical and do not close the later handoff.
Do not change claim statuses, acceptance thresholds, protected source, signatures, or historical receipts as prose cleanup.

Read the canonical [justfile](justfile).
Run `just ci` for the complete local P0 gate.
Run focused checks while iterating, and label them as focused.
The exact current-head gate verifies a committed subject, not uncommitted successor bytes.
Keep bootstrap source evidence separate from later exact-commit and hosted qualification.

The Java-dependent formal lane is separate.
Use `just formal-offline` only with verified pinned inputs already available.
Ordinary doctor and Rust commands do not invoke Java.
Do not install or alter shared runtimes to satisfy a local documentation gate.

Run Markdown lint, local link checks, `git diff --check`, and actual SVG render review for changed documentation.
Verify source and index parity before handoff.
Record exact commands, tools, inputs, exit codes, preserved failures, and residual limits.
Keep custody output outside the checkout.

Signed one-parent source lineage, exact author/committer identity, timestamps, signer, and protected delivery rules remain applicable.
Follow explicit owner instructions for the assigned publication workflow.
A rejected protected-main push remains a rejection; do not change settings or use a bypass.
Do not force-push, rewrite shared history, move tags, or reset an owner's worktree.
Delegated work must reach the release owner as an exact reviewable diff before publication.
Do not add AI co-author trailers.

## Technical writing

Use ASD-STE100 Issue 9 as an alignment target, without a full compliance claim.
Use American English, active voice, and one term for one concept.
Keep procedural sentences within 20 words and descriptive sentences within 25 words.
Put the condition before its action.
Keep one topic per paragraph and one instruction per procedural sentence.

Preserve exact identifiers, equations, units, contracts, quotations, licenses, and historical records.
Tables and exact technical literals are exempt from sentence-length targets.
Define every mathematical symbol, assumption, operating bound, and measured unit.
Keep equations, prose, SVGs, and rendered documents consistent.
Provide native scalable diagrams, mobile reading layouts, and a complete prose alternative.

Never place private keys, bearer tokens, production credentials, or proprietary peer data in source or evidence.
Preserve existing public test certificates and historical non-secret metadata at their declared scope.
Use the owning private reporting procedure for sensitive findings.
