# Partial Information Decomposition across the ecosystem — security & communication

> **Status — design survey with a current component boundary (2026-08-04).**
> Crebain main commit `d7f3006bfac17a8157d22c6a54a23d00c733851c`
> implements a component-tested, exact-opt-in `PidObservation` producer with two
> bounded evidence routes. The reviewed operator-controlled Galadriel PR #43 head,
> `bd2dc86ec9616dc59c6a243735d71792eb494f6d`, implements the strict consumer,
> registry/lifecycle admission, operational receiver, and baseline processing. It
> pins `pid-core` 1.0.0 commit
> `1cd2424f7967e1752dcc8e53859e8fdad3566f51`. That PR remains operator-only.
> A reciprocal current pin, final cross-repository qualification, live-router
> mTLS/ACL evidence, and recorded-stream calibration are **NOT CLAIMED**. The
> scheduler, stream-shedding policy, UI, and automatic down-weight remain proposals.
> The NCP
> analysis is pinned to immutable release `v0.8.0`. Repository HEAD for NCP is the
> unreleased and release-blocked `1.0.0-rc.1` candidate on a different wire; a native
> 1.0 Haldir integration and role qualification are **NOT RUN**. The `BulkBlock` codec
> is usable for local or offline data, but the wire-0.8 `BulkObservation` transport
> envelope is reserved and must not be published. The earlier pid-core 0.9.0 review
> commit `2557f929ed1ba8c1307d62e2763fe79cc953f449` is historical analysis, not the
> current Galadriel candidate pin. Every consumer must retain its resolved source and
> package digest and revalidate the selected APIs. pid-rs is not an NCP
> peer and receives no NCP role receipt.

## Why PID here

Partial Information Decomposition (PID) takes the mutual information that two or more sources carry about a target and splits it into measure-dependent atoms: **redundant** information, **unique** information, and **synergistic** information available only from a joint observation. The canonical synergy example is a parity relation `Z = X ⊕ Y`: `X` and `Y` are each independent of `Z`, yet together they determine it. Two engineering hypotheses have that possible shape: bearing and range can be jointly necessary for a declared localization target, and a covert channel can distribute a relation across at least three observed fields while preserving selected marginals and pairs. Neither example establishes a PID atom without a specified joint distribution, target, measure, and retained experiment.

The ecosystem owns useful components on both sides of this pipeline. Manwe and
Crebain provide multimodal fusion components. Crebain now emits bounded
Galadriel sidecar evidence: scalar NIS and optional raw innovation from each
applied sequential filter update, plus an optional attested
`consistency_projection` from one frozen pre-association prior. The reviewed
Galadriel PR consumes and assembles that evidence and uses matching projections
for its signed-Pearson-correlation baseline. pid-rs provides estimator, invariant,
adjustment, and diagnostic-resampling APIs at the exact candidate pin above.
Frozen NCP wire 0.8 separately correlates a `CommandFrame` with its driving
`SensorFrame` because `CommandFrame.source` copies the complete
`SensorFrame.stream`; such consumers join on `(source.epoch, source.seq)`, not
bare sequence or arrival time. The Galadriel sidecar is a project-owned extension,
not a normative NCP `SensorFrame` or `ObservationFrame`.

The discipline inherited from Prisoma is narrower than the original survey
stated. `exp0 --strict-gate` validates analytic mutual-information recovery in
one built-in Gaussian experiment; it does not accept consumer data, adjudicate an
atom measure, or validate `pid3_isx`. The pid-rs documentation marks atom-measure
selection `not_adjudicated` and the atom-estimator path `blocked`. Full
`pid3_isx` is a mixed-dimensional research reproduction behind explicit opt-ins
and has no consistency result. Therefore no continuous atom in this survey has a
GO gate. Treat those outputs as incomplete research diagnostics with
`calibrated_posterior=false`. Categorical `discrete_sxpid*` implements empirical
shared-exclusions $I^{sx}_\cap$; the legacy Williams–Beer `I_min` comparator is
the separate `imin_pid*` API. Quantization changes the observed variables, and
`I_min` also changes the redundancy measure, so none of these results can be
pooled with a continuous estimate. Each candidate must define a distribution and
endpoint, use callable rejection checks on the actual data, and beat explicit
cheaper baselines in retained evidence.

---

## A. Security applications

The flagship proposal is **Galadriel's Mirror** (see
`docs/galadriels-mirror.md` and its embedded ten-lens appendix), an electronic-
warfare study of cross-sensor/per-modality consistency projections. Crebain and
the reviewed Galadriel PR implement component producer, consumer, and baseline
paths; they do not constitute a qualified deployment. Command-to-sensor
correlation belongs to the separate B3 study. The applications below are related
proposals; none records a deployed monitor.

### A1. Synergy Sniffer — covert exfiltration across telemetry fields that should be independent

**Mechanism.** Sources `X₁…Xₙ` are a panel of quantized telemetry fields the plant model says are marginally independent: low bits of position, confidence, inter-arrival time, a rarely-used metadata integer, and per-modality innovation magnitude. There is **no distinguished target**: this is a structure screen over at least three jointly observed fields. Two target-free variables cannot exhibit the claimed PID synergy; O-information is identically zero at arity two. The defined test is therefore a three-field relation such as `X₃ = X₁ ⊕ X₂`. Under that stated parity model, all three pairwise correlations can remain zero while three-variable co-information and O-information become synergy-dominated. A channel whose second carrier or payload target is unobserved remains invisible to this screen.

**Ecosystem hook.** Frozen NCP wire 0.8 includes a `BulkBlock` columnar codec (`ncp-core/src/bulk.rs`) for self-describing f32/f64/i32/i64 columns of `times`/`values`/`senders`. Use it only for a local ring or offline capture. The corresponding `BulkObservation` network envelope is reserved, is not implemented by every SDK, and must not be published as a transport frame.

**Potential payoff.** In the stated, fully observed three-field parity model, the screen can detect a dependence that pairwise correlation and scalar MI miss. That result does not transfer to two observed carriers, an unobserved payload target, a different distribution, or an adaptive higher-arity channel. The path uses discrete O-information/co-information — no kNN — so it avoids the continuous-estimator gate, but it still needs a finite-sample null and held-out validation.

**Honest limits.** The load-bearing statistic is three-variable
co-information/O-information, one of the cheaper multivariate tests — not an
SxPID atom. `discrete_sxpid3` requires a selected target, so it is outside this
target-free path. The candidate advantage is narrow: it needs at least three
*jointly observed* fields bound by the declared dependence model. A low-entropy
or slowly varying payload can collapse to a pairwise-detectable signal, and a
payload whose required partner is unobserved is invisible. Finite-sample bias in
the composite co-/O-information statistic has no universal direction; the null
and two-bin-count sensitivity study must measure sampling and discretization
artifacts rather than assume a bias sign. The pinned pid-core 1.0.0 candidate API
exposes typed BH and BY adjustments behind a default-off experimental feature,
but no screen applies them automatically. The consumer must predeclare the
hypothesis family, enable and pin that API, justify BH's dependence assumptions
or select BY, and retain the correction provenance.

**MVP.** Select 4–6 numeric columns from an offline `BulkBlock` capture and
predeclare the screened three-field families. Fit the public
`EqualWidthQuantizer`/`QuantizerConfig` on disjoint training or calibration rows,
reuse those edges on evaluation rows, and record baseline
O-information/co-information bands. The internal `quantize_equal_width` helper is
not a public consumer API. Use a block, restricted, or other preregistered
permutation null that preserves the exchangeability structure claimed for the
temporal telemetry; an unrestricted one-field shuffle is invalid unless row
exchangeability is established. Use pinned BH only if its dependence assumptions
are justified; otherwise use pinned BY or a preregistered FWER procedure. Re-run
at two bin counts and report survivors as exploratory dependence findings rather
than exfiltration attribution. Live transport requires an explicit, reviewed
extension and new evidence.

### A2. VLA policy-backdoor / trojan-trigger structural detector (prisoma)

**Mechanism.** Sources `S₁ = V` (vision), `S₂ = L` (language/instruction), optionally `S₃ = D` (world-model/hidden-state); target `T = A` (action token / low-d action projection). The hypothesis is that a clean policy corroborates V and L before acting, while a trojan creates a covert V→A path. Candidate signals are triggered-minus-clean `ΔUnq(V;A)` with a drop in `R(V,L;A)`, or `Syn(V,D;A)` for a preregistered world-model tamper. A chosen ≥3-body distribution can preserve the tested marginals and pairs while changing a joint term, but this must be demonstrated against explicit higher-order baselines rather than called irreducible in advance.

**Ecosystem hook.** Prisoma's `(V,L,D,A)` attack-surface reading, current §2.4
availability–use–effect distinction, and H4 frozen intervention tuple provide the
proposed adversarial map. That H4 tuple binds the intervention construction and dose,
availability-superiority and effect-equivalence margins, outcome, region rule, target
weights, and engagement/support controls. It does not reuse the retired
matched-strength intervention endpoint. A clean per-episode atom-profile artifact would be a future
Prisoma-owned output. Current Engram evidence does not implement or store that
baseline.

**Potential payoff.** A future blinded study could test whether a structural
shift ranks a trigger-affected modality when an input-space anomaly detector sees
no OOD input. Current known-triggered rollouts neither establish trigger-agnostic
detection nor localize compromise; an atom shift ranks statistical discordance,
not its cause.

**Honest limits.** Two hard problems remain. First, the raw VLA embedding has no passing estimator receipt. PLS/PCA or a discrete quantized path is a new estimand, not an automatic repair, and a variance-maximizing projection can discard a low-variance covert feature. The MVP must first show that the selected projection preserves a known injected signal and passes its own gates. Second, `ΔUnq(V;A)` has a cheaper comparator: triggered-minus-clean conditional MI `I(V;A|L)`. Re-scope PID to a ≥3-body attribution or second-opinion hypothesis and require it to beat STRIP, activation clustering, spectral signatures, and paired ΔCMI by the preregistered margin. Availability does not establish causal use, and the D-axis needs VLA internals that Prisoma has not captured.

**MVP.** Offline, compare known-triggered with clean rollouts. Select and preregister a projection, show that it preserves an injected signal, and run callable geometry and estimator checks on those exact features. `exp0 --strict-gate` cannot ingest them and does not validate atoms. Select a paired inference procedure with retained coverage evidence, and require the incomplete PID diagnostic to beat the preregistered STRIP and ΔCMI baselines before any runtime proposal.

### A3. Single-point-of-information map (dual-use offline reading)

Not a standalone detector but a proposed security by-product of the scheduler in
B1. A per-modality leave-one-out loss
`Δᵢ = I(T;S_all) - I(T;S_-i)`, or an independently admitted per-modality unique
atom, is a candidate single-point-of-failure indicator under the declared
distribution. `average_degree_of_vulnerability` returns one global panel scalar
`v̄ = ΣᵢΔᵢ / I(T;S_all)` with typed defined/undefined status; it cannot localize a
modality. A value-of-information scheduler can also amplify attack: a detector-
aware input can inflate apparent value, seize priority, and starve corroborating
inputs. PID measures information available, not causal use. Default-deny
authorization and authenticated transport limit unauthorized injection, while
sensor/model hardening and bounded scheduling policy address authorized or
compromised inputs. This map is advisory attack-surface cartography, never an
enforcement gate.

---

## B. Communication applications

### B1. Value-of-information scheduling under a jammed link

**Mechanism.** A proposed stream-shedding host could score a candidate modality with conditional MI `I(Sᵢ;T | already-sent)`, where `T` is a declared next-step track target. In a two-source PID under a compatible measure, that conditional MI can decompose into a unique plus synergistic term; the identity is not a generic multi-source scheduling theorem. Greedy selection is near-optimal only under stated submodularity or conditional-independence assumptions. Without those assumptions it is a heuristic that must be compared with fixed priority and direct optimization.

**Ecosystem hook.** Frozen NCP wire 0.8 provides per-stream plane and QoS choices, but it does not implement the required cross-stream budget scheduler. A future external host could consume bounded Manwe/Crebain features and emit a separate policy table.

**Potential payoff.** A future scheduler could replace fixed-priority stream shedding with VoI-ranked semantic shedding and test whether it delivers more information per surviving frame when bandwidth collapses.

**Honest limits.** The PID **unique atom is the wrong member of the family** for this job because it excludes value available only through synergy; the naive version therefore needs a separate partner guard. Greedy CMI conditions each selection on what is already scheduled and is the simpler candidate for redundant and synergistic value. A *static offline* priority weight also cannot represent a per-frame VoI change, and the correct ranking depends on which sensors remain available in the episode. The scheduler is an attack amplifier (see A3). Scalar NIS is an O(1)-per-innovation baseline. Whether greedy CMI improves the declared delivery endpoint over NIS or fixed priority is **NOT RUN**.

**MVP.** On a two-modality track, compare greedy conditional MI with NIS magnitude and fixed priority on a retained jamming trace. State and test the conditional-independence or submodularity assumptions needed for a greedy guarantee; otherwise call it a heuristic. Claim value only under a separately calibrated paired comparison. Demote PID atoms to offline incomplete diagnostics.

### B2. Synergy-aware semantic conflation for the Perception plane

**Mechanism.** Sources `Sᵢ` are matching attested common-frame
`consistency_projection` values from the component-tested Crebain producer;
sequential NIS and raw innovations must not be treated as though they share one
prior. Target `T` is a delayed settled track-state increment, not the same-tick
fused state. The candidate sign of `co_information_pairwise` is a research
diagnostic under the selected measure. In a declared distribution, a joint target
relation can be invisible to selected marginals and pairs. The proposal must
demonstrate that regime and compare it with conditional MI, higher-order
baselines, and fixed-priority grouping before any stream policy follows.

**Ecosystem hook.** Crebain main contains the component-tested producer, and the reviewed Galadriel PR contains the strict consumer and baseline. The delayed target, offline co-conflation study, policy table, and stream-level shedding host do not exist as a qualified integration.

**Potential payoff.** Under bandwidth collapse, a future QoS layer could shed streams that evidence suggests are redundant while keeping a candidate synergistic pair together. A collapse in a synergy atom could also be a tamper-screening input. Neither result proves corroboration, spoofing, or source truth.

**Honest limits.** The original KEEP_LAST(1) framing is wrong and is dropped: NCP keeps the newest frame of each modality sub-key and does not perform cross-stream budget shedding. The missing host is an explicit stream-shedding policy. The DOA-plus-range hypothesis changes under scalar projection, and pid-rs has no validated atom gate for this path. `RowResampleScheme::Subsample` returns diagnostic quantiles, not confidence intervals. Before any drop policy, select an estimator-specific calibrated inference procedure and compare target redundancy against conditional-MI and declared higher-order baselines; pairwise MI is not generally equal to a target-redundancy atom.

**MVP.** Use the existing producer and reviewed consumer components to capture
matching attested consistency projections, add a declared delayed target, and
compute co-information plus `pid2_isx` only as incomplete offline diagnostics.
Treat generic resampling output as descriptive. Compare candidate grouping with
fixed-priority and conditional-MI shedding under a separately calibrated
inference procedure. Do not use KEEP_LAST(1) as the comparator.

### B3. Neuro-controller health — synergy/redundancy shift as degraded-mode telemetry (engram)

**Mechanism.** Sources `S₁` and `S₂` are declared low-dimensional readouts of
the perception-encoder and world-model/recurrent populations. Target `T` is a
preregistered scalar or low-dimensional action projection carried by the
actuator `CommandFrame`, not the whole message object. For frozen NCP wire 0.8,
join that command-side projection to the neural readout through the complete
`CommandFrame.source` position, which copies the driving `SensorFrame.stream`.
The candidate signal is a shift in the measure-dependent atom profile between
nominal and degraded episodes, such as action becoming uniquely determined by
one population. The direction remains a hypothesis.

**Ecosystem hook.** NCP wire 0.8 provides an epoch-scoped source-position join for command↔sensor correlation. Offline, whole-episode telemetry changes the sample and latency budget, but its estimator validity is still **NOT RUN**. NCP does not supply the neural readout or prove the proposed coupling useful.

**Potential payoff.** A future experiment could test whether the atom profile distinguishes full sensor-plus-world-model fusion from a degraded reflex. It must not drive fleet down-weighting without an independent, bounded authority and safety design.

**Honest limits.** Kept as a *forward-looking* item, not a runnable MVP, for three reasons. (1) Engram's current controllers are reflex arcs (Braitenberg; pose-error→Poisson→velocity); a distinct world-model population `S₂` does not exist yet. (2) The health direction is unestablished: redundancy can predict ablation robustness in the cited Prisoma setting, so "synergy collapse = degraded" can be inverted. Track all declared atoms and the CI₂ sign; do not assign a direction before evidence. (3) An activation-norm or reconstruction-error OOD monitor is the mandatory cheaper baseline for a scalar health signal, and availability does not certify causal use. High-dimensional population features have no passing receipt here. Any low-dimensional projection or discrete `sxpid2` path must pass its own gates and treat projection choice as a confound.

**MVP (deferred).** Log 1-D readouts of two populations, scalar action, and the
complete driving source position over nominal versus sensor-masked episodes.
After a world-model population exists, fit
`EqualWidthQuantizer`/`QuantizerConfig` on disjoint training or calibration rows
and reuse the fitted edges with `fitted_quantized_sxpid2` on evaluation rows.
Alternatively, use an explicitly declared categorical encoding with
`discrete_sxpid2`. Preregister the null and separately validate the inference
procedure; generic resampling quantiles are diagnostic only. Never join on bare
`seq`.

---

## Summary table

| Application | PID measure | Sources → Target | Ecosystem hook | Sec / Comm | Cheaper baseline? |
|---|---|---|---|---|---|
| Galadriel's Mirror | continuous `I^sx` Red/Syn as incomplete diagnostics | matching common-frame projections → LOO or predictive reference | component-tested Crebain producer + reviewed Galadriel PR consumer; qualification not claimed | Security | Galadriel implements NIS/CUSUM and signed-Pearson-correlation baselines; atom acceptance remains blocked |
| A1 Synergy Sniffer | three-variable `o_information_discrete` + co-information | quantized telemetry triple → no distinguished target | offline `BulkBlock` columns | Security | Pairwise tests miss the stated three-field parity model; other regimes are unproven |
| A2 VLA backdoor detector | `Syn(V,D;A)` (≥3-body); `ΔUnq(V;A)` demoted | V, L, D → A | Prisoma (V,L,D,A); future Prisoma-owned baseline artifact | Security | Paired `ΔI(V;A\|L)` plus STRIP are primary baselines; added PID value is **NOT RUN** |
| A3 Single-point-of-info map | per-modality LOO loss or admitted `Unq`; `v̄` only as a global panel screen | per-modality features → action | Prisoma attack surface | Security | Advisory only; transport authorization and model/sensor hardening remain separate controls |
| B1 VoI jam scheduler | greedy `I(Sᵢ;T\|sent)` heuristic | Manwe scalar features → next-tick state | proposed NCP stream-shedding host | Comm | NIS and fixed priority are mandatory; greedy guarantee needs stated submodularity/conditional-independence assumptions |
| B2 Synergy-aware conflation | `co_information_pairwise` (CI₂) + `pid2_isx` | Crebain common-frame consistency projections → delayed settled state | Crebain `PidObservation` sidecar | Comm | Conditional MI and pairwise statistics are mandatory comparators; target-redundancy equivalence is not assumed |
| B3 Neuro-controller health | `discrete_sxpid2` Syn/Unq (forward-looking) | two population readouts → declared action projection in `CommandFrame` | NCP epoch-scoped source position; Engram | Comm | OOD is the scalar-trust baseline; PID is only a failure-mode-identification candidate, value **NOT RUN** |

---

## Cross-cutting caveats

**Estimator validity is the gate, not an afterthought.** The reviewed
`exp0 --strict-gate` validates analytic MI recovery in its built-in Gaussian
case; it neither accepts consumer data nor validates atom measures or
`pid3_isx`. Continuous atom outputs remain incomplete diagnostics. Temporal
dependence and projection choice need callable checks on the exact data. Generic
resampling spreads and percentiles are descriptive, not calibrated standard
errors or confidence intervals. `Jitter` changes the estimand and is not generic
tie repair; use it only for a declared Gaussian-noise model or a retained noise-
scale sensitivity analysis. Categorical `discrete_sxpid*` preserves the shared-
exclusions measure on changed, categorical variables; `fitted_quantized_sxpid*`
requires quantizer edges learned on training/calibration rows and reused on
evaluation rows. Williams–Beer `I_min` is the separate `imin_pid*` measure. Never
pool any of these with a continuous estimate or with each other. The candidate
pid-rs API provides experimental BH/BY adjustment functions but no automatic
family selection. Each consumer must predeclare the family and dependence policy
and retain provenance.

**Earn your complexity.** The house rule is that every application must answer
"would a marginal or pairwise statistic do?" and survive the comparison.
Pairwise correlation or MI is a mandatory comparator, but it is not generally
equal to target-specific PID redundancy. Sequential value of information is a
conditional-MI problem and is cheaper than a Möbius difference of unique atoms.
A scalar trust number is an OOD-monitor problem and is cheaper than a
decomposition. The candidate added value is restricted to a declared
multi-variable synergy model (B2, A1, or A2) or multi-body discordance ranking as
a second opinion. Each candidate still needs a defined observed-variable model
and head-to-head evidence; none is irreducible across all distributions or
deployments.

**Adversary adaptivity.** A fixed-arity synergy screen is blind to a channel
spread across more fields than the screened arity or run slower than the sampling
window. A VoI scheduler is an attack amplifier: a detector-aware input can inflate
a channel's apparent value and seize priority. If an adversary preserves the
complete tested distribution, no statistic computed only from it has signal;
whether that construction is feasible for a selected plant is a separate
acceptance test. PID measures information *available*, not *causally used*, so it
is never the enforcement layer.

**Advisory, not enforced.** Crebain and the reviewed Galadriel PR implement component producer, consumer, baseline, registry, lifecycle, and receiver paths. They provide no command-authority path, current reciprocal qualification, live-router ACL/mTLS receipt, or recorded calibration. The scheduler and policy applications remain proposals. Frozen NCP wire 0.8's opt-in strict profile makes the authenticated robot/body the sole sensor publisher, the authenticated commander the sole command and observation publisher, and the observer read-only; its default quiet transport is unauthenticated. Security requires a principal-bound default-deny deployment plus sensor/model hardening. PID remains diagnostic instrumentation, never a fail-closed hot-loop gate.

---

## What we rejected and why

- **Target-free SxPID as the covert-channel detector (A1 as originally pitched).** `discrete_sxpid3` requires a selected target. It is removed from the target-free path. The retained proposal screens predeclared triples with O-information/co-information; it makes no claim for two observed variables or an unobserved payload target.
- **The PID unique atom as the online jam-scheduler priority (B1 as pitched).** It excludes value available only through synergy and therefore needs a partner rule. Greedy conditional MI is the simpler candidate because it conditions on what is already scheduled; its performance advantage is **NOT RUN**. PID remains only in the proposed offline SPOF study.
- **The KEEP_LAST(1) framing of semantic conflation (B2 as pitched).** NCP's
  independent per-modality subkeys do not implement cross-stream budget shedding
  or pair-atomic delivery. Asymmetric updates or loss can also leave the latest
  values temporally misaligned. The idea survives only if re-hosted on an explicit
  stream-level shedding and synchronization mechanism that must still be built.
- **`ΔUnq(V;A)` as a primary trojan detector (A2 as pitched).** Paired scalar `ΔI(V;A|L)` and STRIP are the mandatory primary baselines. `Syn(V,D;A)` remains a ≥3-body attribution hypothesis contingent on a projection-preserves-signal result and the still-missing D-axis capture.
- **Neuro-controller synergy-health as a shippable MVP (B3).** The world-model population it reads does not exist on today's reflex controllers, the health direction may be inverted (redundancy, not synergy, likely marks robustness), and its headline trust use is cheaper via an OOD monitor. Kept as a forward-looking telemetry item because frozen NCP wire 0.8 has a complete source-position correlation hook, not because the integration has shipped.
