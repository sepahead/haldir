# Galadriel PID advisory boundary

## Status

This document is the current Haldir design authority for the relationship between
Galadriel's information-theoretic research outputs and Haldir Gate. It supersedes
the active recommendations in the older non-normative surveys
[`galadriels-mirror.md`](galadriels-mirror.md) and
[`pid-security-and-communication.md`](pid-security-and-communication.md). Those
documents remain historical design records; they do not define a runtime contract.
It also supersedes only the Galadriel/PID clauses, proposed
`AdvisoryEvidenceRefV1` policy role, and Phase 16 policy instructions in
[`HALDIR-NCP-V0.8.0-TRIPLE-CHECKED-AUDIT-AND-IMPLEMENTATION-SPECIFICATION-2026.md`](HALDIR-NCP-V0.8.0-TRIPLE-CHECKED-AUDIT-AND-IMPLEMENTATION-SPECIFICATION-2026.md).
That larger specification remains authoritative for unrelated Haldir work.

The implemented fact is deliberately small:

> Haldir has no runtime PID input, PID route, PID principal, PID policy field, or
> PID-to-command edge. Galadriel PID evidence is advisory research output only.

No code path in Haldir consumes the CREBAIN fixture or the Galadriel study. This
document adds no dependency and widens no release claim. Haldir release `0.9.0`
remains `NO_GO` for deployment.

[![Synthetic latent ENU state and CREBAIN rows feed distinct Galadriel questions; a red
authority firewall separates any advisory evidence from Haldir's independent
command-authorization conjunction](assets/galadriel-pid-advisory-boundary.svg)](assets/galadriel-pid-advisory-boundary.svg)

**Figure 1 — system and authority design.** The top panel separates the synthetic
conformance row from question-specific routes. Direct branches show that operational
consistency and fixed-target MGW are separate analyses, not a fallback chain; the
dataflow-independent latent target enters only MGW. The dashed path is an unimplemented future
evidence-only proposal. The red stop is the load-bearing non-edge: no advisory
field reaches the policy function. The bottom panel is Haldir's existing,
independently authenticated command-authority conjunction.

[Open the figure at full size.](assets/galadriel-pid-advisory-boundary.svg)

## 1. Start from the scientific and decision problems

The ecosystem has three different questions that must not be collapsed into one
“PID detector”:

1. **Operational consistency:** are admitted sensor channels behaving consistently
   enough for Galadriel's declared detector? Galadriel keeps the normalized
   innovation squared (NIS) statistic, its CUSUM sequential-change statistic, and
   signed correlation as three distinct outputs. Its opt-in pairwise KSG
   mutual-information graph is a fourth, uncalibrated dependence companion; it is
   not PID and does not alter the accepted fused verdict.
2. **Scientific target allocation:** for one fixed target and ordered source tuple,
   how does one named PID functional allocate target information among redundancy,
   uniqueness, and synergy? The current exact CREBAIN fixture answers this offline
   with categorical Makkeh–Gutknecht–Wibral (MGW) shared exclusions.
3. **Command authorization:** may Gate create one new plant-facing command now?
   Haldir answers only from authenticated authority, trusted state, replay,
   freshness, route, deterministic policy, and final-recheck inputs.

The third question is not a downstream threshold on either of the first two.

## 2. Grounded CREBAIN law

The bounded fixture is produced by CREBAIN commit
`6ef60fabbf8c8a8008e7a77304d3e095b6b9e91d`, path
`src-tauri/tests/fixtures/crebain_drone_mgw_v1.json`, SHA-256
`82a837415b56c3646386a5c3e6fe28a492906c164edc461249bab7844aa4ebda`.
Galadriel vendors those exact bytes as offline data. CREBAIN does not depend on
Galadriel, run PID, or accept a PID conclusion.

For external East–North–Up truth \(\mathbf p=(E,N,U)\), the ordered pre-fusion
categorical sources are

\[
V=\mathbf 1[N_{\mathrm{visual}}\le1\,\mathrm m],\qquad
R=\mathbf 1[E_{\mathrm{radar}}\le50\,\mathrm m],\qquad
A=\mathbf 1[U_{\mathrm{acoustic}}\le1\,\mathrm m].
\]

The fixture producer derives the targets from its latent ENU scenario state after
constructing the sensor objects and categorical source symbols, but before fusion.
The targets are therefore external to the fusion verdict, Galadriel, and PID; they
are not independently measured field ground truth. They are

\[
T_H=\mathbf 1[E\le50\land N\le1],\qquad
T_V=T_H\,\mathbf 1[U\le1].
\]

The primary question is categorical MGW PID2 \((V,R;T_H)\). The three-source
PID3 \((V,R,A;T_V)\) is exploratory. The producer states that each row came from
a freshly initialized fusion engine. The retained fixture supplies one row time,
a bounded six-field sensor summary, an admitted observation-vector length of
three, and at least one retained projection; every projection that is present
uses the declared prior identifier. It does **not** retain separate per-modality
times, a complete fusion trace, three necessarily present projection objects, or
an independent observation of producer-process isolation. The 64 rows are
custody and exact-law fixtures—not 64 independent flights, a p-value, or a
confidence interval.

The original preregistration named pid-core revision
`1cd2424f7967e1752dcc8e53859e8fdad3566f51`. The implemented dependency adapts
only its evaluator boundary to the clean, remote-reachable pid-core `0.9.0`
revision `bc3aa80fb6025e709c2906a08bce25a4fac40578`, including the bounded
`*_with_budget` calls. The scientific row, sources, targets, source order, and
registered MGW questions remain fixed. pid-rs is a read-only algorithm dependency,
not an NCP peer or Haldir authority. Features that exist only in a dirty pid-rs
worktree are not consumable evidence.

## 3. What categorical MGW contributes

For an antichain coordinate \(\alpha\), the categorical MGW construction provides
informative and misinformative partial atoms and their signed net value:

\[
\Pi_{\alpha}=\Pi^+_{\alpha}-\Pi^-_{\alpha}.
\]

The net atoms reconstruct the target mutual information. For the primary
two-source question,

\[
I(V,R;T_H)=
\Pi_{\mathrm{red}}+
\Pi_{V\setminus R}+
\Pi_{R\setminus V}+
\Pi_{\mathrm{syn}}.
\]

This gives Galadriel something NIS, CUSUM, correlation, and pairwise MI do not: a
**measure-relative, source-ordered allocation of information about one external
target**. It is useful when that allocation is the research question. It is not
automatically useful merely because “synergy” sounds sophisticated.

The atoms are associational/statistical allocations, not causal effects. Source
tuple order is retained as provenance and coordinate identity; it does not imply
that the information relation is temporally ordered. A negative MGW net atom is
a valid signed allocation and must not be clamped. A favorable atom does not prove sensor truth;
an unfavorable atom does not prove deception. The result cannot distinguish an
attacker from a lone truthful sensor facing a coordinated majority without
additional assumptions and evidence.

## 4. Method eligibility—no aliases and no fallback chain

| Object and kind | Question answered | Eligible for the exact fixture? | Haldir consequence |
| --- | --- | --- | --- |
| Categorical MGW functional | Target-specific signed lattice allocation on a declared categorical law | PID2 primary; PID3 exploratory | none; advisory research evidence |
| Exact empirical-count MGW evaluator | Binary64 evaluation of the declared empirical categorical PMF | yes; this is the selected route | no comparator is substituted if it fails |
| Williams–Beer `I_min` functional | A different specific-information redundancy allocation | only as a separately preregistered comparator | never an MGW alias or fallback |
| BROJA functional | Bivariate unique information defined through a constrained distribution family | only for the primary bivariate law, with separate implementation, feasibility, and residual provenance | never an MGW alias or fallback |
| Schick–Poland general construction | General measure-theoretic discrete/continuous PID construction | reference only; no evaluator is selected for this fixture | not an alias for categorical MGW or Ehrlich |
| Ehrlich continuous functional and derived PID2 | Continuous shared-exclusions redundancy and PID2 atoms at a fixed source gauge | no: categorical, repeated, atomic rows | abstain; not interchangeable with MGW |
| Ehrlich nearest-neighbour estimator | Sample estimator for the continuous construction | no: its population/support route is inapplicable here | estimator availability never establishes functional applicability |
| Pairwise KSG MI estimator | Continuous pairwise nonlinear dependence | no: repeated atomic categorical support violates this route's law | abstain; KSG is not PID |
| Co-information invariant | Signed interaction quantity | optional separate diagnostic; not evaluated here | never relabel as a PID atom |
| O-information invariant | System-level high-order redundancy/synergy balance | optional separate diagnostic; not evaluated here | never relabel as a PID atom |
| NIS diagnostic | Magnitude of a covariance-normalized innovation under Galadriel's lifecycle contract | not evaluated by this exact fixture | operational statistic only; separate from CUSUM, correlation, PID, and authority |
| CUSUM diagnostic | Sequential evidence accumulated from the declared innovation statistic and reset rule | not evaluated by this exact fixture | change statistic only; never merge its state or threshold with NIS |
| Signed-correlation diagnostic | Signed pairwise linear association under Galadriel's lifecycle contract | not evaluated by this exact fixture | direction-bearing association only; separate from NIS, CUSUM, PID, and authority |
| Infomorphic objective composition | A learning objective composed from named PID atoms | downstream only | not a new PID functional or control permission |

If future continuous sensor scores are categorized for MGW, the categorizer must
be a physical symbol declared in advance or be fitted on separate calibration
episodes and frozen before evaluation. The resulting object is categorical or
quantized PID—not continuous Ehrlich PID. If the continuous support, gauge, row
law, or estimator assumptions are not established, the continuous route abstains.
Adding noise as a generic tie repair changes the estimand and is not allowed.

Every evidence object must make its source-to-question join explicit. Let

\[
Q=(\text{episode scope},\text{window},\text{ordered sources},
   \text{target identity},\text{law}).
\]

For the registered allocation route,

\[
Q_{\mathrm{MGW2}}=(\mathcal E, W, (V,R), T_H, P_{V,R,T_H}),\qquad
Q_{\mathrm{MGW3}}=(\mathcal E, W, (V,R,A), T_V, P_{V,R,A,T_V}).
\]

Target-free methods use an explicit `TargetFree` identity rather than an absent or
inferred target. NIS, CUSUM, signed correlation, pairwise KSG MI, co-information,
O-information, and categorical MGW each retain their own method and configuration
identity. An output joins only on the complete key
`(question, episode scope, window, source order, target-or-TargetFree, law,
method, configuration)`. A missing, inapplicable, unavailable, resource-rejected,
or failed route remains in that route's status; no other method or target may fill
the slot as a fallback.

## 5. Haldir's noninterference invariant

Let \(x\) be the complete admitted Haldir authority input and \(e\) any PID or
Galadriel advisory object. The current architecture satisfies the statement that
\(e\) is not an argument to either authorization or the plant-command
projection:

\[
\forall x,e,e':\quad
\operatorname{Authorize}(x,e)
=\operatorname{Authorize}(x,e')
=\operatorname{Authorize}(x).
\]

\[
\operatorname{PlantCommand}(x,e)
=\operatorname{PlantCommand}(x,e')
=\operatorname{PlantCommand}(x).
\]

The same exclusion holds while constructing trusted state:

\[
\operatorname{TrustedStateSnapshot}(x,e)
=\operatorname{TrustedStateSnapshot}(x,e')
=\operatorname{TrustedStateSnapshot}(x).
\]

A separately authorized, future audit writer may deliberately retain a different
record without weakening either equality:

\[
\operatorname{AuditRecord}(x,e)\;\text{may differ from}\;
\operatorname{AuditRecord}(x,e').
\]

Equivalently,

\[
e\notin\operatorname{Inputs}(\operatorname{TrustedStateSnapshot}),\qquad
\operatorname{Fields}(e)\cap
\left(
\operatorname{Inputs}(\operatorname{Authorize})\cup
\operatorname{Inputs}(\operatorname{PlantCommand})
\right)=\varnothing.
\]

Haldir's command condition remains the conjunction documented in
[`AUTHORITY-GRAPH.md`](AUTHORITY-GRAPH.md) and the normative release authority
contract. In compact form,

\[
\begin{aligned}
\operatorname{CreateCommand}(x)\iff{}&
\operatorname{Active}(x)\land
\operatorname{AuthenticatedIntent}(x)\land
\operatorname{ScopeMatches}(x)\\
&\land\operatorname{FreshReplaySafe}(x)
\land\operatorname{TrustedState}(x)
\land\operatorname{PolicyAllow}(x)\\
&\land\operatorname{FinalRecheck}(x)
\land\operatorname{AuthorizedRoute}(x).
\end{aligned}
\]

PID evidence cannot grant, widen, restore, refresh, revoke, restrict, deny, or
exercise authority. It cannot enter `TrustedStateSnapshot`, turn `DENY` into
`ALLOW`, or turn `ALLOW` into `DENY`; its absence cannot do either. It does not
become authority by being signed, reproducible, statistically significant, or
favorable. This is the correct current design—not a temporary failure to wire an
obvious feature.

## 6. Future evidence-only adapter: requirements, not implementation

A future Haldir release may choose to retain a bounded reference to an exact
Galadriel evidence object for audit or operator research. Such work is a new
schema, threat-model, and release claim. It is not authorized by this document.

The minimum proposed envelope would bind:

- schema and evidence IDs;
- Galadriel repository, commit, tree, build/toolchain, executable, and output
  digests;
- exact input dataset or fixture digest and episode-row receipt;
- question ID, ordered sources, declared target provenance, law, functional, evaluator,
  coordinate, component, and units;
- a closed, two-axis scientific disposition that keeps eligibility distinct from
  execution request:

  ```text
  Eligibility = Applicable { contract_id }
              | Inapplicable { failed_contract }

  Execution   = NotRequested { reason }
              | Requested {
                    role: Primary | Exploratory | Comparator,
                    outcome: Produced | Unavailable | ResourceRejected | Error
                }
  ```

  A record is well formed only when `Inapplicable` pairs with `NotRequested` and
  `Requested` pairs with `Applicable`. Thus “not selected”, “method does not apply”,
  “requested but unavailable”, “budget rejected”, and “execution error” cannot
  collapse into one missing value;
- generation time as provenance only, plus bounded freshness policy for display;
- explicit `advisory_only`, `calibrated_for_control=false`, and complete limitations;
- an authenticated issuer whose role cannot be confused with controller, mission,
  policy, Gate-application, deployment, or CREBAIN plant-evidence authority.

Haldir must not reuse the existing `CREBAIN_EVIDENCE` key role to authenticate a
Galadriel conclusion. Source-of-row evidence and analysis evidence are different
claims. Adding a dedicated analysis-evidence role would itself require a versioned
role/schema migration and independent custody review.

The adapter, if ever built, must be separately authorized for one bounded audit
route and expose no policy capability. A digest reference may enter a bounded
audit spool; the full scientific payload should remain in a content-addressed
external artifact. Gate must not fetch that artifact automatically. The Haldir
record must omit raw sensor rows, media, location traces, free-text operator data,
and stable person identifiers unless a later purpose-specific schema proves each
field necessary. Data classification, access control, encryption, retention,
redaction, deletion, subject access, and approved pseudonymous identifiers are
separate explicit contracts: a content digest supplies neither secrecy nor
disclosure authority and may itself leak equality or dictionary membership for a
small artifact. This lifecycle framing follows the data-processing and
disassociability vocabulary of the
[NIST Privacy Framework 1.0](https://doi.org/10.6028/NIST.CSWP.01162020).
Spool loss, malformed input, stale input, replay, a negative atom, a favorable
atom, and an unavailable result must all leave the Haldir decision and exact
plant-facing command bytes unchanged. A separate `AuditRecord(x,e)` may vary
with `e`; it remains outside both authorization and the plant-command projection.

The fixed-\(x\) equations are software-path noninterference claims, not
sociotechnical noninterference. An operator, team, or institution can be influenced
by a displayed result and later submit a different authenticated input \(x'\).
Any user interface therefore needs explicit advisory labeling, visible uncertainty
and abstentions, a provenance link from a later human intent to the new authority
input, role-specific training and escalation, and human-factors evaluation for
automation bias, anchoring, alarm fatigue, and responsibility diffusion. Authority
still comes from the authenticated human/policy path, not from the PID object. The
requirements are grounded in the
[NIST AI RMF 1.0](https://doi.org/10.6028/NIST.AI.100-1) treatment of human-AI
roles and oversight and in
[controlled automation-bias evidence](https://doi.org/10.1006/ijhc.1999.0252);
neither source establishes that a particular interface is safe.

If future work proposes an automatic “restrict-only” reaction, it is no longer
this evidence-only architecture. It must be designed and evaluated as a new
Haldir safety policy with an authenticated principal, monotone state machine,
rollback/freshness rules, plant-specific safety proof, denial-completeness tests,
and explicit recovery semantics. The PID object itself still cannot be the
authority.

## 7. Grounding the research in reality

The exact fixture is valuable because it makes semantics and software falsifiable;
it is not a field-performance result. Claims advance only through separate cuts:

1. **Exact finite law:** current row/target reconstruction, categorical MGW values,
   algebraic identities, and a separate 80-digit calculation.
2. **Stochastic simulation:** realistic noise, bias, occlusion, latency, association
   failures, clock offsets, and independent episodes.
3. **Software in the loop:** flight-stack scheduling, message loss/order, coordinate
   transforms, and explicit episode boundaries.
4. **Hardware in the loop:** real drivers, calibration drift, clocks, compute budget,
   restarts, and actuator-bound timing.
5. **Immutable multi-flight replay:** calibration, validation, and evaluation
   missions split before analysis, with missingness and every abstention retained.
6. **Field study:** preregistered scenarios, qualified safety review, human oversight,
   independent reproduction, and explicit deployment exclusions.

Frames within a flight are dependent. Train/test splits, target permutations,
bootstrap schedules, and uncertainty summaries must operate at the independent
episode or mission level. A large frame count is not a large independent sample.

No rung automatically promotes the next, and no scientific rung creates command
authority.

## 8. Falsification-first comparison

PID should be retained only where it answers a registered allocation question or
adds preregistered value over simpler methods. A future drone study should:

- define the threat cell, target, source order, temporal window, categorizer,
  exclusions, seeds, episode split, stopping rule, method routes, outputs, and
  abstention policy in a hashed manifest before viewing PID results;
- compare against the best eligible NIS, CUSUM, signed-correlation,
  parity/innovation, conditional-MI, and joint-statistic baselines on the same
  episode set, without pooling their meanings or status fields;
- report method-specific denominators, failures, resource rejections, and
  missingness bounds rather than complete-case success alone;
- abandon an operational PID proposal if it does not improve the preregistered
  endpoint at matched false-alarm rate and latency;
- preserve a scientifically correct null or negative result instead of forcing a
  control use.

The useful negative conclusion is itself concrete: for the exact atomic fixture,
KSG and continuous Ehrlich PID are inapplicable, while categorical MGW is exact.
That separation is better science than making every method emit a number.

## 9. Twenty-lens review

| Lens | Load-bearing question | Current disposition | Required future evidence |
| ---: | --- | --- | --- |
| 1 | Is command authority complete and mediated? | PID has no authority edge; existing Gate conjunction unchanged | differential no-effect test if an evidence adapter is added |
| 2 | Are identities and roles distinct? | CREBAIN row producer, Galadriel analyzer, and Haldir authorities are distinct | never reuse `CREBAIN_EVIDENCE` for Galadriel analysis |
| 3 | Is encoding closed and versioned? | no Haldir PID schema exists | closed two-axis eligibility/execution record and migration before import |
| 4 | Does a signature prove only origin, not truth? | yes | preserve scientific limitations beside any signature |
| 5 | Are replay and epochs bounded? | not applicable because no route | evidence-only replay/tombstone bounds if added |
| 6 | Is time provenance non-authoritative? | yes | display freshness separate from Gate monotonic authority time |
| 7 | Are rollback and fork states explicit? | no adapter state exists | content-addressed identity and anti-rollback if retained |
| 8 | Can retries or loss change a decision? | no, because PID is absent from policy | demonstrate decision and plant-command invariance under loss and retry; audit bytes may vary |
| 9 | Is ownership/race behavior bounded? | no runtime object | single bounded owner if an adapter is built |
| 10 | Is adversarial work bounded? | no PID work in Haldir | byte/count/CPU ceilings before parse/verify/store |
| 11 | Are units and signed values preserved? | Galadriel uses nats and retains `+`, `−`, and net | Haldir must not normalize signs into trust labels |
| 12 | Is denial complete and monotone? | PID neither grants, restricts, revokes, nor denies | any future restriction is a separately proved policy |
| 13 | Are transport and credential custody separate? | no PID transport | dedicated read-only route/principal if ever added |
| 14 | Is the physical plant boundary honest? | exact CREBAIN fixture is not physical actuation evidence | SITL/HIL/field cuts remain separate |
| 15 | Is evidence provenance exact? | fixture and pid-core pin are exact; final Galadriel execution bundle remains future work | bind commit/tree/toolchain/executable/output |
| 16 | Is supply-chain identity closed? | no Haldir dependency added | pin clean remote-reachable artifacts only |
| 17 | Does the API resist misuse? | strongest state: no API | future type must have no policy or command capability |
| 18 | Are failures visible? | Galadriel has typed scientific states | keep `NotRequested`, `Inapplicable`, `Produced`, `Unavailable`, `ResourceRejected`, and `Error` distinct |
| 19 | Are controls causal and falsifiable? | exact law, algebra, target/source hostile controls exist upstream | add one-coordinate no-effect controls at any Haldir adapter |
| 20 | Are claims, human ownership, and release governance honest? | advisory-only and no deployment claim | qualified human PID review, candidate reproduction, AI disclosure, exact reviewed delivery |

## 10. Complete to-do list

### Current Haldir repository

- [x] State that Haldir has no runtime PID route or authority input.
- [x] Replace the active rotating/leave-one-out PID recommendation with the fixed-
  target, ordered-source categorical MGW boundary.
- [x] Keep operational NIS, CUSUM, signed correlation, pairwise KSG MI,
  co-information, O-information, and offline PID as separate objects.
- [x] Publish the noninterference equation and authority-flow figure.
- [x] Preserve the old design surveys as explicitly superseded history.
- [x] Add no pid-rs, Galadriel, or CREBAIN runtime dependency.
- [ ] Bind the exact final Galadriel publication commit in this document after it
  is reviewed and promoted.
- [ ] Run Haldir's complete documentation, source, claim, release, Rust, Python,
  formal, and visual gates on the final bytes.
- [ ] Deliver one reviewed, one-parent SSH-signed commit through Haldir's exact-
  object protocol; verify hosted checks, remove the review ref, and leave one
  clean `main` worktree.

### Future Galadriel/pid-rs integration

- [ ] Keep pid-rs read-only and pinned to a clean remote-reachable commit.
- [ ] Review method-catalog and public-API changes before changing the pin.
- [ ] Preserve the row/question schema while adapting only the narrow evaluator
  boundary.
- [ ] Re-run the exact CREBAIN fixture, all 66 averaged-atom MGW component checks, algebraic
  identities, Decimal route, and hostile controls after any dependency update.
- [ ] Treat stable categorical PID3 availability as distinct from the open
  108-coordinate formal-assurance programme.
- [ ] Use upstream specified-law, resource-composition, row-receipt, and software-
  identity improvements only after they exist in the exact published commit.
- [ ] Never substitute `I_min`, BROJA, KSG, continuous Ehrlich, or an invariant
  when the registered MGW evaluator abstains or fails.

### Reality-facing drone programme

- [ ] Hash the analysis manifest before viewing results.
- [ ] Define independent missions and synchronized pre-fusion windows.
- [ ] Derive targets independently of sensor observations, fusion, Galadriel
  verdicts, and PID; do not relabel producer-synthetic truth as independent field
  ground truth.
- [ ] Calibrate any categorizer on disjoint episodes and freeze it.
- [ ] Split and resample at episode level; never splice frames across flights.
- [ ] Retain selection/eligibility separately from every requested
  `Produced | Unavailable | ResourceRejected | Error` outcome.
- [ ] Compare eligible methods on the same denominators and publish missingness
  bounds.
- [ ] Advance simulation, SITL, HIL, replay, and field evidence as separate claims.
- [ ] Obtain qualified human PID and control-safety review before any load-bearing
  defense or policy claim.

### Possible evidence-only Haldir adapter

- [ ] Write a new threat model and closed schema; this document is not authority
  to implement it.
- [ ] Introduce a role distinct from every controller, mission, policy, Gate,
  deployment, and CREBAIN plant-evidence role.
- [ ] Bound bytes, fields, identities, retained records, verification work, and
  failure diagnostics before expensive processing.
- [ ] Store only a content-addressed reference in the bounded evidence path.
- [ ] Make eligibility and execution request separate tagged axes; reject
  impossible `Inapplicable + Requested` and `Applicable + Produced-without-request`
  combinations.
- [ ] Authorize the audit writer and route separately without granting any
  decision, trusted-state, policy, or plant-publication capability.
- [ ] Minimize retained data and qualify confidentiality, retention, deletion,
  operator-display, and sociotechnical risks independently of integrity.
- [ ] Prove that missing, stale, malformed, replayed, favorable, negative, and
  unavailable evidence produces byte-identical Haldir decisions and
  plant-facing command outputs for fixed authority input; separately test that
  audit records may vary without entering policy.
- [ ] Keep any automatic restriction proposal outside this adapter and subject it
  to a new Haldir policy/plant-safety qualification.

## 11. Primary and method-defining references

- Abdullah Makkeh, Aaron J. Gutknecht, and Michael Wibral, “Introducing a
  differentiable measure of pointwise shared information,” *Physical Review E*
  103, 032149 (2021),
  [doi:10.1103/PhysRevE.103.032149](https://doi.org/10.1103/PhysRevE.103.032149).
- Aaron J. Gutknecht, Michael Wibral, and Abdullah Makkeh, “Bits and Pieces:
  Understanding Information Decomposition from Part-whole Relationships and
  Formal Logic,” *Proceedings of the Royal Society A* 477, 20210110 (2021),
  [doi:10.1098/rspa.2021.0110](https://doi.org/10.1098/rspa.2021.0110).
- Paul L. Williams and Randall D. Beer, “Nonnegative Decomposition of
  Multivariate Information” (2010),
  [arXiv:1004.2515](https://arxiv.org/abs/1004.2515).
- David A. Ehrlich, Kyle Schick-Poland, Abdullah Makkeh, Felix Lanfermann,
  Patricia Wollstadt, and Michael Wibral, “Partial Information Decomposition for
  Continuous Variables based on Shared Exclusions: Analytical Formulation and
  Estimation,” *Physical Review E* 110, 014115 (2024),
  [doi:10.1103/PhysRevE.110.014115](https://doi.org/10.1103/PhysRevE.110.014115).
- Kyle Schick-Poland, Abdullah Makkeh, Aaron J. Gutknecht, Patricia Wollstadt,
  Anja Sturm, and Michael Wibral, “A partial information decomposition for
  discrete and continuous variables” (2021),
  [arXiv:2106.12393](https://arxiv.org/abs/2106.12393).
- Alexander Kraskov, Harald Stögbauer, and Peter Grassberger, “Estimating mutual
  information,” *Physical Review E* 69, 066138 (2004),
  [doi:10.1103/PhysRevE.69.066138](https://doi.org/10.1103/PhysRevE.69.066138).
- Nils Bertschinger, Johannes Rauh, Eckehard Olbrich, Jürgen Jost, and Nihat Ay,
  “Quantifying Unique Information,” *Entropy* 16, 2161–2183 (2014),
  [doi:10.3390/e16042161](https://doi.org/10.3390/e16042161).
- William J. McGill, “Multivariate information transmission,” *Psychometrika*
  19, 97–116 (1954),
  [doi:10.1007/BF02289159](https://doi.org/10.1007/BF02289159).
- Fernando E. Rosas, Pedro A. M. Mediano, Michael Gastpar, and Henrik J. Jensen,
  “Quantifying high-order interdependencies via multivariate extensions of the
  mutual information,” *Physical Review E* 100, 032305 (2019),
  [doi:10.1103/PhysRevE.100.032305](https://doi.org/10.1103/PhysRevE.100.032305).
- Abdullah Makkeh, Marcel Graetz, Andreas C. Schneider, David A. Ehrlich, Viola
  Priesemann, and Michael Wibral, “A general framework for interpretable neural
  learning based on local information-theoretic goal functions,” *Proceedings
  of the National Academy of Sciences* 122, e2408125122 (2025),
  [doi:10.1073/pnas.2408125122](https://doi.org/10.1073/pnas.2408125122).
- Andreas C. Schneider, Valentin Neuhaus, David A. Ehrlich, Abdullah Makkeh,
  Alexander S. Ecker, Viola Priesemann, and Michael Wibral, “What Should a
  Neuron Aim For? Designing Local Objective Functions Based on Information
  Theory,” *ICLR 2025*,
  [OpenReview:CLE09ESvul](https://openreview.net/forum?id=CLE09ESvul).

The categorical MGW paper, the part-whole derivation, the Williams–Beer lattice
and `I_min` functional, the continuous Ehrlich construction, the Schick-Poland
general construction, KSG, BROJA, the interaction invariants, and the two
infomorphic-objective papers are role-distinct works. The PNAS paper establishes
the earlier bivariate/two-input framework; the ICLR paper develops a
three-input-class local-objective design. Their proximity in one bibliography
does not make them one “Wibral PID,” and neither objective paper supplies
implementation evidence for the CREBAIN fixture.

### Human, privacy, and sequential-detection anchors

- E. S. Page, “Continuous Inspection Schemes,” *Biometrika* 41, 100–115
  (1954), [doi:10.1093/biomet/41.1-2.100](https://doi.org/10.1093/biomet/41.1-2.100).
  This is the method anchor for CUSUM, not evidence that Galadriel's threshold is
  calibrated for an operational threat.
- Elham Tabassi, *Artificial Intelligence Risk Management Framework (AI RMF
  1.0)*, NIST AI 100-1 (2023),
  [doi:10.6028/NIST.AI.100-1](https://doi.org/10.6028/NIST.AI.100-1).
- National Institute of Standards and Technology, *NIST Privacy Framework: A
  Tool for Improving Privacy through Enterprise Risk Management, Version 1.0*
  (2020),
  [doi:10.6028/NIST.CSWP.01162020](https://doi.org/10.6028/NIST.CSWP.01162020).
- Linda J. Skitka, Kathleen L. Mosier, and Mark Burdick, “Does automation bias
  decision-making?”, *International Journal of Human-Computer Studies* 51,
  991–1006 (1999),
  [doi:10.1006/ijhc.1999.0252](https://doi.org/10.1006/ijhc.1999.0252).
