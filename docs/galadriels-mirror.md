# Galadriel's Mirror

> **Status — non-normative review; component paths exist, qualification does not.**
> Crebain main commit `d7f3006bfac17a8157d22c6a54a23d00c733851c`
> contains a component-tested, exact-opt-in producer with sequential-update NIS
> observations and an optional attested common-frame consistency projection from
> one frozen pre-association prior, plus two bounded named-perception routes,
> lifecycle evidence, and heartbeat accounting. The reviewed operator-controlled
> Galadriel PR #43 head,
> `bd2dc86ec9616dc59c6a243735d71792eb494f6d`, contains the strict two-route
> consumer, registry and lifecycle admission, and a bounded operational receiver.
> That PR remains operator-only. Its current candidate pins `pid-core` 1.0.0 at
> commit `1cd2424f7967e1752dcc8e53859e8fdad3566f51`; the older 0.9 source-review
> pin in this document is historical analysis, not the candidate dependency.
> A reciprocal current producer pin, cross-repository qualification, real-router
> mTLS/ACL evidence, and recorded-stream calibration are **NOT CLAIMED**.
> The UI and any automatic advisory down-weight remain unimplemented here.
> The protocol notes below use Haldir's frozen NCP `v0.8.0` baseline (wire `0.8`,
> commit `2f5bd586d4bb20c90362bb6f5698b7f64057ba4e`). Current NCP HEAD is the
> unreleased and release-blocked `1.0.0-rc.1` candidate on a different wire;
> Haldir's native-1.0 migration and role qualification are **NOT RUN**.
> Crebain's `PidObservation` is an implemented project-owned sidecar record,
> carried in its project-owned envelope over the two registered Perception
> routes consumed by the reviewed Galadriel PR. It is not a normative NCP
> `SensorFrame` or `ObservationFrame`, and it does not extend the frozen wire.
> The Haldir report, UI, and any control-policy state discussed below remain
> unimplemented.

## Summary

Galadriel's Mirror is an advisory cross-sensor consistency design with component-
tested producer and consumer paths but no qualified deployment. Crebain can emit
bounded per-modality evidence, and the reviewed Galadriel PR can receive and
assemble the two routes. The statistical question remains: *does each channel's
attested common-frame projection still corroborate the declared peer reference,
or has one channel gone informationally private?* Under the stated naive single-
channel FDI model, a phantom acoustic DOA or a poisoned camera contribution can
introduce information that honest channels do not share. The hypothesis to test
is a **collapse of that channel's peer corroboration or mutual information with a
leave-one-out consensus reference**. The current components do not validate that
hypothesis, calibrate a posterior, implement the proposed Haldir UI, or authorize
an automatic down-weight.

The one honest sentence: **the Mirror tests whether one channel has stopped
agreeing with a declared peer reference; it cannot prove that channel is lying,
cannot see a spoof that preserves cross-channel agreement, and must beat the best
qualified cheap baseline for each threat cell before any added output is
trusted.**

---

## 1. Threat model

**In scope.** Uncoordinated, cross-inconsistent, supra-window **single-channel**
FDI against a target with at least three jointly observed modalities: a phantom
acoustic bearing injected on the perception plane, an adversarial-patch bias on
one camera feeding N-view triangulation, or a replayed or drifted radar return.
Under this declared model, the test predicts that the suspect channel's matching
common-frame projection stops covarying with a leave-one-out reference made from
at least two peers. With only two modalities, disagreement does not identify
which one is inconsistent.

**The detection boundary against an adaptive adversary.** The Mirror is blind, *by construction and after any estimator hardening*, to:

- **Coordinated ≥2-channel spoofs** and any **physically consistent phantom** (a real decoy drone; a phased acoustic emitter plus an RF replay triangulating to the same false point). These can preserve or raise cross-channel redundancy and can read as a healthy, corroborated track.
- **Complete-distribution-preserving inputs.** If an adversary can keep the
  complete joint distribution consumed by the monitor unchanged, no statistic
  computed only from that distribution has signal. This is an explicit
  adversarial acceptance cell, not an achieved construction for the selected
  Crebain model. Ueda and Kwon (arXiv:2408.10177) instead construct a coordinated
  affine transformation of control commands and observables by exploiting mobile-
  robot plant symmetry; it is a different system-level blind spot, not evidence
  for a covariance-aware single-sensor residual attack.
- **Slow drift below the largest window or decision resolution**, if the selected
  filter and test absorb it into the predicted state. Whether that occurs in this
  model is **NOT RUN**.
- **Majority-spoof inversion:** with only 3–4 modalities, a redundancy collapse says "channel *k* disagrees with the rest"; it cannot distinguish "*k* is the attacker" from "*k* is the lone honest sensor amid spoofed peers." A leave-one-out value remains computable, but its truth interpretation loses an independent anchor.

The Mirror could therefore raise adversary cost; it is **not** a Kerckhoffs guarantee and is **not** a substitute for default-deny authorization, authenticated transport, and sensor hardening. Authentication binds a source principal; it does not prove that an authorized or compromised sensor reports physical truth. The frozen baseline states the perception-plane boundary in the [NCP v0.8.0 security policy](https://github.com/sepahead/NCP/blob/2f5bd586d4bb20c90362bb6f5698b7f64057ba4e/SECURITY.md#L64-L69). The Mirror is a proposed defense-in-depth *second opinion*.

---

## 2. Formal basis

**Sources and target.** Crebain's emitted NIS and optional raw innovation describe
each actually applied filter update; co-located follow-up measurements are
therefore sequentially conditioned and do not share one prior. The only current
cross-channel source with a common reference is the optional attested
`consistency_projection`, computed from one frozen pre-association prior. Write
that projection as $p_i$. A
Mirror study must require matching prior, frame, track, and lifecycle context for
every projection in a window and define its research source stream $X_i$ from
that projection. Sequential NIS remains the per-channel health baseline; it must
not be relabeled as common-prior evidence. A future higher-order estimand would
relate the declared projection streams to a reference target $T$.

**Resolving the circularity (Lens 01).** Do not use the same-tick fused state as
$T$. The Kalman identity $\hat{x}^+ = \hat{x}^- + \sum_i K_i y_i$ explains why
that excluded target is a function of sequential update innovations; it does not
define the Mirror source. A PID against that target can reflect Kalman-gain
weighting, and an attack that moves the fused state can increase the attacking
channel's MI with the corrupted target. The admitted research inputs remain the
matching common-frame projections $p_i$. Three candidate references require
separate validation:

1. **Leave-one-out consensus** $T_{-k} = \mathrm{robust\_combine}\{p_j : j \neq k\}$ (or a separately computed LOO fused state $\hat{x}^{(-k)}$), scoring each channel against a target it did not help build. `average_degree_of_vulnerability(joint_mi, leave_one_out_mis)` can combine caller-supplied MI terms; it does not construct or validate this reference.
2. A **next-step predictive common-frame error** (temporal LOO), which breaks the recursion whereby a persistent attack becomes common-mode.
3. **Ground truth — offline only**, for scenario labeling and held-out evaluation.
   `exp0 --strict-gate` uses its own built-in Gaussian data and cannot ingest this
   reference or any Mirror feature.

**What can move, and what is currently admissible.** Under the naive
single-channel model, the predicted signature is a **collapse of the suspect
channel's MI or other corroboration with the LOO consensus** — its common-frame
projection $p_k$ stops tracking the declared shared latent $M$. It is **not** a
unique-information spike
about the fused state. A future, measure-adjudicated PID study could test signed
per-channel atoms from `pid3_isx`, or a separately defined discrete study could
use `discrete_sxpid_n` and `SxAtom{informative, misinformative, net}`. Neither
path has an atom-estimator acceptance gate today. The pid-rs documentation marks
atom-measure selection `not_adjudicated` and atom-estimator acceptance `blocked`;
full `pid3_isx` is an opt-in mixed-dimensional research reproduction without a
consistency result. Its output is therefore an incomplete research diagnostic,
not a primary operational estimand. A misinformative component, when the measure
is eventually selected, is relative to the chosen target and distribution. It
does not prove deception, compromise, or which source is true.

**Why not just correlation, and why not O-information as primary.** Correlation
and partial correlation are translation-invariant; they do **not** detect a pure
mean shift. A cheap baseline must therefore combine a standardized residual-mean
or CUSUM/GLR test with correlation or parity tests for covariance and dependence
changes. PID's possible added value is a preregistered non-Gaussian or higher-order
inconsistency that those baselines miss. The global Shannon invariants remain
secondary screens: `o_information_discrete` is target-free and non-attributing.
`average_degree_of_redundancy` and `_vulnerability` return a typed
`NormalizedInvariantReport`; `value` is present only when `status == Defined`.
Nonpositive or policy-small denominators produce an explicit undefined status,
never NaN. Any future attribution claim must be per-channel and signed; current
atom diagnostics cannot support that claim.

---

## 3. Estimator & statistical validity

The reviewed `exp0 --strict-gate` has a GO case for **mutual-information
recovery** at **d = 1, n = 4000** on its built-in jointly Gaussian experiment.
It has no consumer-input mode and does not validate an atom measure, `pid3_isx`,
or any Mirror operating point. The Mirror's cadence, autocorrelation, effective
sample count, joint dimension, and estimator validity are **NOT RUN**. Feeding
raw 3-D residuals into a multivariable kNN estimator cannot inherit the
one-dimensional MI result. No continuous atom currently has a GO gate. The
discipline:

**Feature discipline.** Keep scalar NIS $y^\top S^{-1}y$ as the cheap
per-update baseline; its $\chi^2(3)$ reference holds only under the stated model
assumptions, and consecutive co-located values can be conditioned on different
states. For cross-channel comparison, use only matching attested
`consistency_projection` values from the frozen common reference. If a scalar
projection is needed, preregister that transformation and validate the resulting
feature law. A whitened innovation $S^{-1/2}y$ is still a vector and is not
equivalent to scalar NIS. Scalarization lowers ambient dimension but does not
admit a multivariable or atom estimator. Reserve other directional or raw-vector
paths for separately defined research studies.

**Mandatory data checks, necessary but not sufficient.** Run
`intrinsic_dimension_levina_bickel` (k ≥ 3),
`distance_concentration_stats` with a declared refusal rule as
`nn_over_pairwise_mean → 1`, and `sampled_four_point_delta_summary` on every
exact feature path. The sampled four-point summary is descriptive: its observed
maximum is only a sampled lower bound on the finite-data supremum. It is not the
supremum-defined Gromov hyperbolicity constant and cannot be reported as one.
These callable geometry checks can reject a path; they cannot validate an atom
measure or prove estimator consistency. For categorical shared-exclusions
$I^{sx}_\cap$, use explicit categorical encoding with `discrete_sxpid*`, or fit
`EqualWidthQuantizer`/`QuantizerConfig` on training or calibration rows and reuse
those edges with `fitted_quantized_sxpid*` on evaluation rows. The internal
`quantize_equal_width` helper is not a public consumer API. Williams–Beer
`I_min` uses the separate `imin_pid*` comparator and is a different redundancy
measure. Quantized shared-exclusions SxPID, Williams–Beer `I_min`, continuous
$I^{sx}$, and MI-only screens each need separate sample, calibration, and decision
evidence. **Never pool their outputs.**

**Autocorrelation and effective sample size.** Estimate the selected feature's
integrated autocorrelation time $\tau$ per window and predeclare the dependence
and block-length policy. `RowResampleScheme::Subsample` returns raw m-row
diagnostic quantiles. It does **not** provide a calibrated n-row standard error or
confidence interval. Use it only to diagnose sensitivity. No interval or zero-
exclusion gate is available until an estimator-specific procedure has retained
coverage and type-I-error evidence on the exact feature law.

**Fail-closed states.** Treat `NumericalInstability`, `NonFiniteInput`, any invariant report whose status is not `Defined`, and any incomplete resampling distribution as automatic abstention. Do not use `Jitter` as generic tie repair: it changes the estimand and is admissible only when Gaussian observation noise is part of the declared model or as a retained noise-scale sensitivity analysis. Otherwise select an estimator whose support contract matches the data. A consumer must retain the typed failure and label raw resampling quantiles as diagnostics, not confidence intervals. Its UI must render a greyed "no verdict" state, never default green or red.

**Honest cost.** A future qualified Mirror must return "insufficient evidence"
when a sample, geometry, stability, or calibrated-inference gate fails. Because
no atom acceptance gate exists, the current atom path always remains an
incomplete research diagnostic and cannot emit a verdict. Its abstention rate is
**NOT RUN**. Within-window non-stationarity of a maneuvering target violates the
i.i.d. assumption underneath a naive KSG estimate. Overlapping windows also
create dependence that a future multiple-comparison procedure must model or
bound; no such procedure is selected or validated.

---

## 4. Detection & decision

**Feasibility first.** Before any threshold is set, select and validate an estimator-specific uncertainty procedure with retained coverage and type-I-error evidence. The raw pid-rs resampling quantiles cannot clear zero or define a minimum detectable effect. The calibrated uncertainty width, required sample count, and plant-specific FDI damage horizon are **NOT RUN**. If a validated continuous estimator cannot fit inside the measured horizon, it cannot own the tactical alarm. A discrete SxPID or MI-only path needs separate sample, calibration, and latency evidence.

**Statistic.** Compare a nonparametric CUSUM or window-limited GLR with single-window thresholding. Calibrate the complete repeated-look procedure to a target **ARL₀** on held-out dependent streams. Raw block-subsample quantiles are diagnostics and cannot supply this calibration. CUSUM can reduce sensitivity to some transient spikes but does not reject them by construction. Do not select SPRT until a minimum-effect H₁ is fixed.

**False-alarm control under benign decorrelation.** Genuine maneuvers,
occlusion/dropout, and inter-modality latency skew can also collapse peer
corroboration. A future decision rule must therefore test nuisance covariates
available to the consumer: IMM mode probability, per-channel covariance and
measurement availability, GDOP, and jam/SNR flags. The proposed co-onset
discriminator treats broadly correlated transients as a maneuver candidate and a
sustained single-channel change as an FDI candidate. That discriminator is a
hypothesis, not a proven separation, and needs a matched confusion matrix.

**Hysteresis.** Apply M-of-N dwell to a future recommendation, asymmetric on raise versus restore, and bound it by the measured damage horizon. Rate-limit the recommendation so an adversary cannot weaponize false spikes on a healthy channel. Dwell does not authorize an automatic covariance write.

**Two separate error gates.** For each declared decision look, apply a
preregistered FDR/FWER policy to any modality × track × atom family tested at
that look. The reviewed Galadriel candidate pins
`pid-core` 1.0.0 at commit
`1cd2424f7967e1752dcc8e53859e8fdad3566f51`; its experimental API exposes typed
BH and BY adjustments behind a default-off feature, but it does not choose the
hypothesis family or apply a correction automatically. A consumer must pin and
enable that API, justify BH's dependence assumptions or select BY, and retain the
family and adjustment provenance. This within-look correction does **not**
calibrate repeated looks over time. Separately calibrate the complete sequential
procedure—including overlapping windows, dwell, and restore logic—on held-out
dependent streams to its ARL₀, tail-delay, and deadline-miss targets. Neither
gate substitutes for the other.

The residual tension is real and pre-registered: detection delay and FAR trade
off across window fill, estimation, scheduling, repeated-look logic, dwell, and
UI delivery. **If no complete operating point simultaneously satisfies the
measured plant damage-horizon bound and target ARL₀, the module does not ship as
a real-time advisor** — it re-scopes to post-hoc analysis (§7, §10).

---

## 5. Why PID over the cheap baseline

The Mirror must **earn its complexity** against real competitors. Crebain emits
sequential-update scalar NIS evidence, and the reviewed Galadriel PR implements NIS/CUSUM plus a
signed-Pearson-correlation baseline. Those component paths are not externally qualified
or calibrated on recorded streams. A further mandatory comparator is a
**pairwise cross-sensor parity residual** $z_i - z_j$ with its declared covariance
plus CUSUM/GLRT. Exact cost and matched detection performance are **NOT RUN**.

**The head-to-head, by threat cell:** (a) loud phantom; (b) single-channel
perturbation matched to the preregistered first-order baseline; (c) coordinated
input matched to the declared parity baseline across at least three jointly
observed channels. Primary endpoint: **ΔAUROC over the best qualified cheap
baseline for that cell at matched false-alarm rate**, with a committed minimum
effect **≥ 0.05**. Mandatory secondary endpoints are a preregistered high-quantile
end-to-end delay and deadline-miss rate at fixed FAR, each with uncertainty. The
median remains descriptive and cannot clear the plant damage-horizon gate.

**Where PID could win:** a **≥3-channel, declared-baseline-matched,
geometry-admissible** regime — a single-channel higher-order dependence
perturbation, co-associated with a real track, that preserves the preregistered
per-channel NIS distribution and the specific first- and second-order statistics
used by the qualified mean, correlation, and parity baselines, while changing a
declared higher-order cross-channel relation. Geometry admissibility is only a
rejection screen. This regime cannot be
tested with atom outputs until the measure, estimator-consistency, and calibrated
inference blockers are closed. The possible differentiated value is
**per-source discordance ranking** — which channel differs from its peers —
benchmarked separately from raw detection AUROC. The ranking would not identify
the deceptive or truthful source.

**Where it honestly does not win.** Against the declared hypothetical in which
the complete tested joint distribution is preserved, PID and NIS fail together.
The proposed raw four-source, 3-D-innovation plus 3-D-target feature path would be
about 15-D. The retained `d=1, n=4000` result is only a different Gaussian
MI-recovery experiment, and the separate Prisoma d=64 result is NO-GO
(r̄≈28.6 / v̄≈−26.6). Neither result accepts or rejects a Mirror atom. The exact
Mirror geometry is **NOT RUN** and may reject the path. At cold start, the first
full-window score needs `n / effective_sample_rate` to fill the window. The
required `n`, actual effective rate, CPU throughput, rolling post-change delay,
and operational alarm latency are also **NOT RUN**. If a
calibrated paired comparison eventually shows parity matches an admissible
higher-order candidate within the preregistered equivalence margin, ship parity.
The pid-rs raw resampling quantiles cannot make that decision.

---

## 6. crebain integration

**Current producer component.** Crebain commit
`d7f3006bfac17a8157d22c6a54a23d00c733851c` implements an exact-runtime-opt-in
producer behind its `ncp` feature. It records scalar NIS and optional raw
innovation from each applied, sequential filter update. Separately, it can attach
an attested common-frame `consistency_projection` computed from one frozen
pre-association prior. It validates pinned registry, configuration, and executable
identities and publishes only the bounded `galadriel-pid` and
`galadriel-monitor` named-perception routes. Registered fusion calls feed bounded
queues and heartbeat/lifecycle evidence. This is component and in-process
evidence. It does not prove receiver receipt, complete-path latency, live
TLS/mTLS identities, exact-route ACLs, or deployment topology.

**Source alignment.** The component sidecar owns bounded producer identities and
lifecycle correlation; it is not an NCP `SensorFrame`. A cross-channel window
must require complete matching `consistency_projection` attestations, including
their frozen prior, frame, track, and context identities; do not substitute raw
innovation or sequential NIS. Any separate frozen-NCP-0.8 command/sensor analysis
must carry the complete driving `SensorFrame.stream` and join on
complete equality of `(source.epoch, source.seq)` within the bound session,
never bare `seq`, timestamp, or arrival order. Any track identifier is separate
project-local context, not part of the NCP source-position join. Require at least
the preregistered `n_min` co-occurring observations for
the complete declared modality set. A lost or rejected observation invalidates
the affected statistical suffix. Do not add noise to repair ties unless noise is
in the declared model; otherwise use a support-compatible estimator.

**Recommend, never veto.** The original proposal would have scaled measurement
covariance before association, which enlarges the acceptance ellipsoid and can
make a suspect modality associate more easily. The current Crebain producer does
not implement that action. Keep it resolved: route any future post-association,
update-stage-only action from all trust writers through one monotone, floored,
audited arbitration point. Derive $t_{\min}$ from plant-specific state-quality
and safety bounds, prove composition, and test confirmation and closed-loop
behavior. That evidence is **NOT RUN**. Until it exists, emit a recommendation
only. Any action beyond a proven soft bound requires explicit operator
acknowledgment.

**UX (Lenses 05, 09).** Render trust bars as a **separate advisory sibling
layer** beside `DetectionOverlay.tsx` (keep `pointer-events-none`), never inside
`drawDetectionBox` (`src/components/detectionCanvas.ts:56`). Use a palette
**orthogonal** to `THREAT_LEVEL_COLORS` (`src/detection/types.ts:119`) so a
severe-threat box and a suspect-channel bar never collide on
red/amber — trust state is a separate visual channel (hue/shape/hatch). Four
explicit states: **TRUSTED / SUSPECT-INJECTION / DENIED-DEGRADED /
UNKNOWN-ABSTAIN**. The proposed output is a **denial-vs-injection-consistency
2×2**: peer-corroboration collapse with internally coherent NIS supports a
SUSPECT-INJECTION hypothesis; collapse with blown/dropout NIS supports a
DENIED-DEGRADED hypothesis. Neither state identifies an attacker or proves its
label. Every SUSPECT flag shows which peer channels disagree. Never auto-down-
weight a single-sensor track to zero; doing so can suppress a legitimate target
observed by only one modality.

---

## 7. Real-time performance

Crebain's producer uses bounded queues and owned tasks, and Galadriel's reviewed
PR implements bounded receiver paths. Complete-path contention and latency
qualification remain **NOT CLAIMED**. At the reviewed pid-rs source, eligible
low-dimensional Chebyshev KSG/iˢˣ queries use an exact, bit-identical kd-tree
automatically for `n≥128` and at most 16 joint dimensions; other cases use the
brute-force path. Tree queries are typically sublinear but remain `O(n)` in the
worst case, so a complete estimator call remains `O(n²)` worst-case. Some
geometry diagnostics are explicitly `O(n²)`, and resampling diagnostics repeat
the selected work. No exact-candidate, hardware, window, track-count, and two-
process deployment benchmark receipt qualifies the ecosystem path. At cold
start, the first full-window score needs `n / effective_sample_rate` to fill the
window. A warmed rolling detector has a separate post-change delay that requires
calibration.

**Consequence: split the clock.** The component paths carry scalar NIS and
Galadriel implements a baseline, but alarm-grade calibration and latency are not
claimed. Keep any later-admitted higher-order diagnostic offline or on a bounded
background stride unless retained benchmarks prove another budget. Tag every
result with window age, validity status, and clearly labeled resampling
diagnostics; never label raw quantiles as confidence intervals or auto-apply a
stale down-weight. Under load, expose reduced mode and use only a separately
calibrated cheap baseline.

---

## 8. Honesty boundary

The Mirror is advisory: `calibrated_posterior = false`, human-in-the-loop, strictly out of the effector-cue path. Made mechanical rather than sloganeered:

- **It softens, never vetoes.** A future floored, clamped, update-stage-only action must have a plant-specific state-quality and safety bound, a composition proof across all trust writers, and closed-loop tests. That evidence is **NOT RUN**. Until it exists, no automatic down-weight is permitted.
- **It forbids certified attribution.** A future Haldir report may emit a per-
  channel **"uncorroborated-information" advisory score**, never a
  "SPOOFED/LIAR" verdict. On the tin: a corroboration collapse is consistent with
  a spoof, a genuinely unique true detection, legitimate sensor heterogeneity, or
  an estimator artifact. Prisoma's current §2.4 separates representational
  availability, policy use, and closed-loop effect; its H4 protocol tests
  availability against the effect of one frozen intervention rather than inferring
  natural non-use. PID measures information *available*, not what fusion *causally
  used*.
- **Estimator validity is a first-class report and UI state.** The implemented
  producer/consumer sidecar path defines no normative NCP message. Any future
  Haldir report remains project-owned; atom diagnostics are never interpreted as
  verdicts, and failed windows render "no verdict," never default green/red.
- **Distinct advisory idiom.** A "cross-sensor corroboration" meter captioned **ADVISORY — not a gate**, sharing no red/green pass-fail language with the archived Palantir-Seal `TrustBadge` concept or the gate-associated Haldir/Feanor `VETO` idiom. The proposed record carries `calibrated_posterior=false`, an explicit simulation/real-data classification, and the full driving source position. Do not copy wire-0.8 `ObservationFrame` for real-world output: its normative `is_simulation_output` value is `true`. NCP's `contract_hash` exists only in `OpenSession` and `SessionOpened`, not every frame. Every advisory, down-weight, and human ack must be retained in a future Border-Muster ledger before any claim uses it.
- **Naming.** The Mirror is **Galadriel**, not Nenya (the separate GNSS-spoof guardian); the arbitration point and operators key on stable, unambiguous subject IDs, since two guardians writing overlapping fusion seams under confusable names is itself a provenance hazard.
- **The sidecar path is security-sensitive.** The implemented networked
  `PidObservation` route could be spoofed if its deployment lacks authenticated
  integrity and principal binding. The current components do not supply live
  mTLS/ACL qualification. Palantir-Seal is itself only an archived proposal, not
  an available control. Until route security and the soft control bound are
  established independently, received evidence cannot trigger an automatic
  down-weight.

It **must never claim** to prove a channel is lying, to catch a complete-tested-
distribution-preserving input or a cross-channel-consistent coordinated spoof,
or to be a substitute for mTLS plus per-plane ACL. Any future
Haldir UI, alarm policy, or automatic action must remain disabled until the
complete path beats the best qualified cheap baseline for the applicable threat
cell by the preregistered margin.

---

## 9. Evaluation plan

The plan can reuse Manwe's seeded `make_scenario` plus OSPA assets and pid-rs's
runlog machinery. `exp0 --strict-gate` can be reproduced as a separate MI-library
sanity check, but it cannot consume Mirror features or admit atom results.
Crebain now implements the bounded producer component, and the reviewed Galadriel
PR implements the consumer component. The next dependency is a current reciprocal
pin and retained two-process qualification, followed by a falsification-first
calibrated baseline comparison.

1. **Qualify the implemented baseline first.** Crebain emits sequential NIS and
   common-frame consistency projections; the reviewed Galadriel PR implements
   NIS/CUSUM plus signed Pearson correlation on matching projections. Bind the
   current producer and consumer revisions, use the same retained inputs, and
   demonstrate calibration. Innovation whiteness/autocorrelation and the
   covariance-aware parity residual are additional comparators, not implemented
   baseline components.
2. **Pre-register one primary operational statistic** from the cheap baseline
   family — for example, a standardized residual-mean/CUSUM statistic combined
   with a declared parity or correlation statistic — and one endpoint per
   injection class: **paired ΔROC-AUC at matched FAR AND matched latency**,
   predicted sign, and a committed minimum improvement. Any future PID atom is a
   separately preregistered exploratory diagnostic until its measure and estimator
   are admitted. Predeclare every tested family; use BH-FDR only if its dependence
   assumptions are justified, otherwise use BY or a preregistered FWER control.
   **No post-hoc fishing** over the 18 (`pid3_isx`) or 166
   (`discrete_sxpid_n`) antichains.
3. **Map the latency × estimator-validity × AUROC Pareto frontier.** The window
   is a validity axis, not a cosmetic knob. Run callable geometry and estimator
   checks on the exact features; keep the built-in Exp0 MI reproduction separate.
   Retain `RowResampleScheme::Subsample` output only as diagnostic quantiles;
   select and validate an estimator-specific uncertainty procedure before any
   interval or zero-exclusion claim.
4. **Close the current cross-repository gap.** Bind Crebain `d7f3006bfac17a8157d22c6a54a23d00c733851c` and the reviewed Galadriel PR head `bd2dc86ec9616dc59c6a243735d71792eb494f6d`, or later reviewed successors, with reciprocal registry and component identities. Galadriel currently selects `pid-core` 1.0.0 commit `1cd2424f7967e1752dcc8e53859e8fdad3566f51`; retain its resolved source digest and revalidate the chosen APIs. pid-rs is linked algorithm code, not an NCP peer, and has no NCP role receipt or `contract_hash`. Run the red-team corpus through the real producer/consumer components and retain the runlog, seeds, loss states, and artifact hashes.
5. **Calibrate the complete repeated-look process.** Set thresholds and dwell
   ex ante on disjoint calibration scenarios. On held-out clean scenarios with
   clutter and missed detections, report ARL₀, false alarms per track-hour,
   high-quantile delay, and deadline-miss rate with uncertainty. Run an
   **inject-nothing placebo** under the complete sequential policy; a within-look
   BH/BY/FWER correction is not a substitute for this evidence.

**The falsification contract (negative-result-first ABANDON triggers):**
- (a) an admitted higher-order candidate fails to beat the best qualified cheap
  baseline for its threat cell by ΔAUROC 0.05 at matched FAR and latency ⇒
  **ship the baseline and drop that candidate.**
- (b) no atom measure and estimator earn an acceptance receipt at the operating
  window, or callable checks reject the feature path ⇒ **drop atom-level
  attribution** and use only the separately qualified baseline.
- (c) attribution accuracy ≤ chance (1/num-modalities) ⇒ **kill the which-channel claim.**
- (d) the preregistered high-quantile end-to-end delay exceeds the measured plant
  damage horizon, or the deadline-miss rate exceeds its allowed bound with
  uncertainty ⇒ **re-scope to offline analysis.** Report median latency only as
  descriptive context.

Honest caveats carried into the plan: an adversarial cell that preserves the
complete tested joint distribution defeats NIS and Mirror alike, so a naive-
injection library **overstates** detectability if it omits that cell; synthetic
Gaussian clutter will not reproduce non-Gaussian phased-emitter DOA or
adversarial-patch triangulation error; a threshold calibrated on synthetic clean
data may not hold on real Crebain innovation statistics.

---

## 10. Roadmap & MVP

**Completed component slice.** Crebain has a sequential-update NIS producer plus
an optional frozen-prior common-frame consistency projection, bounded two-route
evidence, and lifecycle/heartbeat accounting. The reviewed Galadriel PR has the
strict consumer, registry/lifecycle admission, operational receiver, and baseline
processing. These are component tests, not a reciprocal pin, deployed security
proof, recorded calibration, or accepted UI.

**Next slice.** Establish the reciprocal current component pin and a real-router
mTLS/ACL allow-and-deny campaign. Then calibrate the implemented NIS/CUSUM plus
signed-Pearson baseline on recorded streams, evaluate additional whiteness and
parity comparators, and test a disabled-by-default four-state Haldir advisory UI.
Do not add an automatic down-weight.

**Milestone 1 — estimator harness (offline).** Use the candidate's pinned pid-rs
API with mandatory geometry and sample checks. Treat generic resampling output as
descriptive diagnostics, not calibrated inference. Atom work stays blocked until
a measure is adjudicated, the selected estimator has a consistency or equivalent
acceptance result, and an estimator-specific uncertainty procedure demonstrates
coverage on the declared feature law. A discrete SxPID study is a separate
candidate and needs its own validation.

**Milestone 2 — head-to-head (offline, pre-registered).** Run a red-team
injection library through the exact current producer and consumer component
revisions under a reciprocal pin; compare ΔAUROC and frames-to-alarm with the
best qualified cheap baseline per threat cell. **Gate: pass the falsification contract or stop
here** and ship the qualified baseline-only view.

**Milestone 3 — attribution research & decision calibration.** If M2 passes and
the atom blockers are independently closed, test LOO-consensus per-channel signed
atoms as offline diagnostics. Separately validate the jam-vs-spoof 2×2, CUSUM
with nuisance conditioning, and M-of-N dwell. Control any declared within-look
family with BH only if its dependence assumptions are justified, otherwise BY or
a preregistered FWER procedure. Independently calibrate the full repeated-look
process to its ARL₀ and deadline targets.

**Milestone 4 — possible advisory action.** Only after plant-specific bounds and
closed-loop evidence exist, add a floored, clamped, audited **post-association
update** arbitration point that is separate from `measurement_r_cartesian` at
association; require operator acknowledgment, Border-Muster logging, rate limits,
and hysteresis. Keep any qualified higher-order diagnostic on a bounded background
scheduler.

At every milestone the default posture is **off**, advisory, and one benchmark away from being deleted.

---

## Appendix: 10-Lens Review

This design was reviewed through ten lenses: information-theoretic soundness,
estimator validity and statistical gates, adaptive adversary, baseline
justification, Crebain integration, real-time performance, detection and decision
theory, provenance and honesty, EW/operator UX, and evaluation. The consolidated
proposal above takes precedence if an appendix passage describes an earlier
design state. **The full review record follows.**

### Lens 01 — Information-theoretic soundness

**Question under test.** Does a single-channel false-data injection (FDI) reliably produce redundancy collapse? The answer depends on the joint distribution and the target `T`. The original same-tick fused-target reading is circular and can invert the intended sign.

**What is measured.** Crebain's current component emits scalar NIS and optional
raw innovation from each applied sequential filter update. Only its optional
attested `consistency_projection` is computed against one frozen pre-association
prior. The proposed cross-channel research sources `S_i` must therefore use
matching consistency projections with the same prior, frame, track, and context;
they cannot silently substitute sequential NIS or raw innovation. The proposed
target choices — leave-one-out consensus, next-step common-frame error, or offline ground
truth — are not interchangeable; the same-tick fused state is excluded.

**The circularity failure.** If `T` is the same-tick fused state, the Kalman
update `x̂⁺ = x̂⁻ + Σ Kᵢyᵢ` makes `T` a function of the sequential update
innovations. This equation explains the excluded design; it does not make those
`yᵢ` the current cross-channel source. A PID against that target can reflect
Kalman-gain weighting rather than anomaly. An FDI that moves `x̂` toward a
phantom can also increase an injected channel's MI with the corrupted target.
Over time, a persistent attack can enter the predicted state and make later
residuals more common-mode. The exact atom direction depends on the distribution,
but same-tick fusion creates a decisive attribution confound and is excluded.

**Correct hypothesis.** Under the stated naive-FDI model, the predicted signature
is **MI or other corroboration collapse of the suspect channel against a reference
external to it**, not a unique spike about the fused state. Matching attested
projections share the declared latent `M` under the research model:
`pᵢ = gᵢ(M) + ηᵢ`, with cross-independent `ηᵢ`. A naive phantom projection is
independent of `M`, so the model predicts `I(p_k; T_{-k}) → 0`. Whether and how
that change maps to a redundancy atom depends on the as-yet-unadjudicated PID
measure. The reference must break circularity: a **leave-one-out consensus**
`T_{-k} = robust_combine{p_j : j≠k}`, a separately computed LOO fused state, or a
**next-step predictive common-frame error**. Ground truth exists only offline for
scenario labels and evaluation; Exp0 cannot ingest it. This remains a falsifiable
model prediction, not a universal theorem about FDI.

**O-information is the wrong primary invariant.** `o_information_discrete` is a
single global, target-free scalar: it cannot attribute a channel, and a lone
decorrelated channel among four need not flip its sign. The normalized r̄/v̄ APIs
return `NormalizedInvariantReport`; `value` is `Some` only for
`NormalizedInvariantStatus::Defined`. Nonpositive or policy-small denominators
return typed undefined states, never NaN. Keep Ω/r̄/v̄ as secondary screens. A
future atom-based attribution candidate would have to be signed and per-channel,
but no current atom diagnostic is admitted for that role. A misinformative
component is relative to the selected target, distribution, and measure; it does
not establish deceptive intent or identify which source is true.

**Detectability floor (must be disclosed).** If an adversarial input preserves the
complete joint distribution tested by the monitor, a statistic defined only on
that distribution has no signal; NIS/whiteness and the Mirror share this logical
floor. This is a hypothetical acceptance cell whose feasibility and cost in the
selected multisensor model are **NOT RUN**. It is consistent with the broader
[frozen NCP 0.8 sensor-plane boundary](https://github.com/sepahead/NCP/blob/2f5bd586d4bb20c90362bb6f5698b7f64057ba4e/SECURITY.md#L64-L69),
but that policy does not prove a particular attack construction. PID can earn
complexity only on a preregistered higher-order inconsistency that the selected
baseline misses.

**Required fixes.**
1. Never use fused state (or its update) as `T`; use a LOO consensus, LOO fused
   state, or next-step predictive common-frame error.
2. Test per-channel **MI or corroboration-with-consensus collapse**, not a
   unique-information spike about `T`; do not call the change an atom until the
   measure is selected and the estimator is admitted.
3. Keep `o_information_discrete`, r̄, and v̄ as status-guarded global screens and
   accept a normalized value only when `status == Defined`. Require any future
   attribution result to be per-channel and signed.
4. Evaluate preregistered window lengths with LOO or predictive references; do
   not call a short window protective until its sample validity, delay, and
   common-mode behavior are measured.
5. Preregister the complete-tested-distribution detectability floor and a
   committed non-Gaussian ΔAUROC improvement over the best qualified cheap
   baseline for the threat cell. Drop atom-level claims unless an
   admitted atom estimator separately earns that improvement.

**Residual risk.** A low-shared-information regime can make `r̄`/`v̄` undefined or
leave little signal to attribute; its frequency is **NOT RUN**. Redundancy collapse
also cannot distinguish "`k` is the attacker" from "`k` is the lone honest sensor
amid spoofed peers" without an independent truth anchor. Prisoma's current §2.4
separates representational availability, policy use, and closed-loop effect, and its
H4 protocol tests availability against the effect of one frozen intervention.
Information available in matching `consistency_projection` streams does not establish
what fusion causally used, so an availability-keyed recommendation can misfire.


### Lens 02 — Estimator validity & statistical gates

**Analysis.** The Mirror's proposed alarm — "single-modality FDI produces a
redundancy collapse" — would require an admitted measure and a validated estimator
for `pid2_isx` or `pid3_isx` atoms from finite windows of matching frozen-prior
`consistency_projection` streams.
Those are distribution functionals observed through a KSG/`EhrlichKsg` kNN
estimator with finite-sample bias and variance. The reviewed pid-rs documentation
marks atom-measure selection `not_adjudicated` and atom-estimator acceptance
`blocked`; full `pid3_isx` is an opt-in research reproduction without a
consistency result. Callable geometry checks on the exact feature distribution
are necessary rejection screens, not an atom acceptance test. The Mirror has no
atom receipt, so the continuous atom path is an incomplete research diagnostic,
not merely an operating point waiting to run.

The exact local positive evidence is narrow: `exp0 --strict-gate` compares
mutual-information recovery in its own jointly Gaussian `d=1`,
`n=STRICT_BAND_GATE_N=4000` case with a closed form (`bin/exp0.rs`). It has no
consumer-input option and does not test an atom measure or atom estimator. The
separate default sweep at `n=500`, `dims=[10,64,256]` can expose MI-estimator
breakdown; it cannot qualify an atom band. Crebain's actual per-modality event
rate, window duration, stationarity, autocorrelation, and effective sample count
have not been retained for this proposal. Raw
`SensorMeasurement.position:[f64;3]` values would also create a joint dimension
greater than one. These facts prevent transfer of the one-dimensional MI result.
Every exact Mirror feature path remains **NOT RUN**, while atom acceptance remains
**blocked** independently of that missing execution.

**Concrete findings.**
1. **An alarm can equal an estimator artifact.** KSG underestimation of a strongly
   dependent joint MI can propagate into an atom difference and mimic the proposed
   direction. Exp0 can expose MI-recovery problems in its synthetic cases, but it
   cannot diagnose or admit the atom estimator. Without measure adjudication,
   exact-feature rejection checks, an estimator acceptance result, and separately
   calibrated uncertainty, the proposal cannot distinguish that artifact from an
   FDI effect. Generic pid-rs resampling quantiles are diagnostic only.
2. **Autocorrelation is unevaluated.** Correctly modeled Kalman innovations are
   expected to be white, while maneuver, model mismatch, or attack can introduce
   dependence. Exp0's built-in data are non-temporal and provide no dependence
   receipt for the Mirror. The Mirror must measure integrated autocorrelation time
   τ and derive its block or subsample policy rather than assume a cadence or
   independence.
3. **Degeneracy is fail-closed.** A constant, quantized, or stalled input can collapse the kNN radius and return `NumericalInstability`. r̄/v̄ return a typed undefined status with `value=None` when the denominator is nonpositive or below the selected policy threshold. Prisoma's separate d=64 NO-GO result is a warning that must not be transferred as a quantitative Mirror result.
4. **Neither error layer is calibrated.** Testing 18–166 antichain atoms across
   tracks at one look needs an explicitly selected within-look FDR/FWER procedure.
   Repeating those corrected looks across overlapping windows separately needs
   end-to-end sequential calibration. Library availability alone neither selects
   a family nor establishes dependence assumptions, ARL₀, or deadline behavior.

**Required fixes (ordered).**
1. Keep scalar sequential NIS `yᵀS⁻¹y` as the per-channel health baseline.
   Build cross-channel research features only from matching attested
   `consistency_projection` values. If those projections are scalarized,
   preregister and validate the transformation; `S^{-1/2}y` is a vector, not an
   equivalent scalar. Dimensional reduction does not establish an in-band atom
   estimator.
2. Make exact-data geometry checks mandatory per window:
   `intrinsic_dimension_levina_bickel` (k≥3),
   `distance_concentration_stats` with a declared refusal rule as
   `nn_over_pairwise_mean`→1, and `sampled_four_point_delta_summary`. That API is
   descriptive; its sampled maximum is only a lower bound on the finite-data
   supremum and is not a Gromov hyperbolicity constant. These checks can reject,
   not admit, an
   atom path. Treat categorical shared-exclusions `discrete_sxpid*`, fitted
   `fitted_quantized_sxpid*`, Williams–Beer `imin_pid*`, continuous $I^{sx}$, and
   MI-only as separate candidates with their own evidence. Fit quantizer edges on
   training/calibration rows and reuse them on evaluation rows; never pool the
   resulting estimands.
3. Characterize temporal dependence for each selected feature and statistic.
   Choose any effective-sample-size definition and block/subsample policy only
   through an estimator-specific validation with retained coverage and type-I
   evidence. Do not assume `n_eff=n/τ` or block length ≈ τ as generic KSG/PID
   rules, and do not use either as an atom refusal gate without that evidence.
4. Treat pid-rs resampling spreads and percentiles as diagnostic only; they
   cannot exclude zero or act as confidence intervals. Select an estimator-
   specific inference procedure and demonstrate coverage and type-I control
   before defining a decision gate. Predeclare the within-look family and
   correction, then separately calibrate repeated looks. Treat
   `NumericalInstability`, `NonFiniteInput`, non-`Defined` invariant status, and
   incomplete resampling distributions as fail-closed. Do not use `Jitter` as
   generic repair; it changes the estimand. Benchmark against the best qualified
   cheap baseline at the real window budget.

**Residual risk.** The abstention rate and timing are **NOT RUN**. Raw resampling
diagnostics do not correct within-window non-stationarity or provide calibrated
inference. The revised proposal excludes the same-tick fused state as target
because it creates deterministic coupling. If an adversarial input preserves the
scalar-NIS distribution, that collapsed feed has no signal; whether the selected
plant and attacker permit such a construction is **NOT RUN**.


### Lens 03 — Adversary model & adaptive evasion

**Analysis.** The original proposal stated an unconditional chain:
single-modality FDI → information not shared → redundancy collapse → alarm. That
holds only for injections that fail cross-channel consistency. `isx_redundancy`
and SxPID atoms measure information shared among channels, which is agnostic to
whether that information is true. Prisoma's current §2.4 availability–use–effect
distinction and H4 frozen-intervention protocol make the relevant causal boundary
explicit: a redundancy-preserving spoof is invisible by construction. The adversary
model must therefore test how cheaply an attacker can
manufacture cross-channel agreement, not rank attacks only by magnitude.

**Findings.**

1. **Coordinated multi-channel spoof (silent, by construction).** An adversary controlling ≥2 of {vision, radar, acoustic-DOA, triangulated-3D} — for example, a phased acoustic emitter plus an RF replay — can inject a jointly consistent phantom. Redundancy can be preserved or elevated. With two of four channels compromised, a leave-one-out disagreement no longer identifies the honest subset without an independent trust anchor.

2. **Detector-aware residual shaping.** Access to frozen NCP wire 0.8 is deployment-dependent: the default quiet configuration is unauthenticated, while a strict ACL profile can restrict reads and writes. Haldir's intended strict profile is default-deny. The estimator and decision design are public, so security cannot depend on hiding them. An attacker with sufficient plant knowledge and observation access can try to shape residuals inside the declared null; the feasibility and cost must be part of the red-team campaign rather than assumed impossible.

3. **Slow-drift / walking-the-track below window scale.** The cross-channel path
   compares matching `consistency_projection` values computed from each frame's
   frozen pre-association prior. Across frames, that prior can still advance from
   previously accepted updates. A sufficiently slow drift can therefore be absorbed
   into the evolving predicted state and remain inside the monitor's null in some
   filter/plant models. That is a declared adversarial hypothesis for this campaign,
   not a result transferred from Ueda–Kwon or another cited source. The
   [frozen NCP 0.8 sensor-plane boundary](https://github.com/sepahead/NCP/blob/2f5bd586d4bb20c90362bb6f5698b7f64057ba4e/SECURITY.md#L64-L69)
   states the security boundary but does not prove this detection floor. The exact
   floor is **NOT RUN**.

4. **Attribution inversion in the original fused-target design.** A same-tick or recursively contaminated fused target can move toward a persistent injection and change the honest channels' later residuals. This can invert or confound attribution. The revised proposal therefore excludes the same-tick full fused target and requires an externally evaluated leave-one-out or predictive reference.

5. **Estimator-targeted denial-of-detection.** Geometry failure, radius-collapse `NumericalInstability`, and a non-`Defined` normalized-invariant status require abstention. Near-duplicate residuals or inflated effective dimension can therefore remove detector coverage; the receiver must expose that state rather than fail open. pid-core's experimental BH/BY functions do not define or correct the channel×track×window family automatically.

**Required fixes.**
- Reframe scope in the spec: detects *uncoordinated, cross-inconsistent, supra-window* single-channel FDI only; **not** an authenticity guarantee and **not** a substitute for the strict ACL and mTLS controls described by the [frozen NCP 0.8 sensor-plane boundary](https://github.com/sepahead/NCP/blob/2f5bd586d4bb20c90362bb6f5698b7f64057ba4e/SECURITY.md#L64-L69).
- Evaluate each modality against a declared leave-one-out or next-step predictive reference that it did not construct. Do not reintroduce the same-tick full fused target. The pid-rs leave-one-out invariant helpers do not themselves implement or validate a Crebain reference path.
- Do not treat a hidden window, secret weight, or residual rotation as the security boundary. If randomization is studied as an attacker-cost measure, retain its seed and benchmark it separately; authorization and sensor hardening remain the controls.
- Multi-scale windows plus a published detection floor from a separately calibrated uncertainty procedure; fail-closed abstention with a coverage-loss flag and a predeclared, justified family-error policy.
- Preregister corroboration-preserving and slow-drift attacks as acceptance
  cells; require ΔAUROC over the best qualified cheap baseline for each cell or
  drop the added screen.

**Residual risk.** Coordinated ≥2-channel and physically consistent phantom spoofs can remain invisible after every estimator fix. Source authentication can reject an unauthorized injector and bind an authorized principal, but it cannot prove the physical truth of an authorized or compromised sensor's report. Slow drift below the largest window can stay undetectable. The advisory down-weight is itself a DoS lever: induced unique-info spikes on a healthy channel can cause a harmful recommendation, so any future mechanism needs rate limiting, hysteresis, explicit bounds, and plant tests.


### Lens 04 — Baseline justification (earn the complexity)

**The bar.** The Mirror must beat, at matched false-alarm rate, four cheaper
candidates: (1) per-sensor NIS, `NIS_i = yᵢᵀ Sᵢ⁻¹ yᵢ`, with a χ²(3) reference
under the model assumptions; (2) innovation whiteness/autocorrelation; (3)
CUSUM/GLRT on the innovation sequence; and (4) a cross-sensor pairwise parity
residual `zᵢ − zⱼ` with its declared covariance. Crebain emits NIS, and the
reviewed Galadriel PR implements NIS/CUSUM plus signed Pearson correlation. External
calibration, reciprocal qualification, the additional parity comparator, and the
matched comparison remain **NOT RUN**.

**Finding 1 — the headline attacks require stronger baselines.** The association
gate is a per-measurement Mahalanobis test, so a sufficiently large innovation
under its declared covariance is rejected. A coherent or repeated phantom can
still create or confirm a separate track; the 3-of-5 lifecycle is persistence
logic, not an authenticity proof. The Mirror's candidate advantage is therefore
not "phantom detection" in general. It must be tested separately for in-gate
single-channel inconsistency, persistent false tracks, and higher-order changes.
A standardized residual-mean/CUSUM test is mandatory for first-moment changes;
parity and correlation/cross-covariance tests cover their declared linear
dependence alternatives. No PID advantage is assumed.

**Finding 2 — the candidate added-value regime is narrow.** A declared ≥3-body dependence change can preserve selected first moments, second moments, and pairwise residuals while changing a joint term. That is a candidate regime for `pid3_isx` or `discrete_sxpid_n`, but other higher-order statistics remain comparators. The distribution, attacker capability, and in-regime estimator must all be established.

**Finding 3 — the atom path has no acceptance route.** Exp0's reviewed
`d=1, n=4000` result concerns analytic MI recovery on built-in jointly Gaussian
data. It cannot ingest a Mirror feature and does not validate an atom measure or
estimator. A raw four-source, 3-D-innovation plus 3-D-target design would be about
15-D, but the selected Mirror research feature and dependence structure remain
unmeasured. Prisoma's separate d=64 verdict is **NO-GO** (r̄≈28.6 /
v̄≈−26.6); it warns against transfer but is not a Mirror result. Continuous atom
outputs remain incomplete research diagnostics until measure selection,
estimator acceptance, exact-data rejection checks, and calibrated inference are
all supplied.

**Finding 4 — latency is unevidenced.** The value `n=4000` belongs to the
built-in one-dimensional Gaussian MI experiment and is not a Mirror minimum. At
cold start, the first full-window score from a selected Mirror path needs
`required_n / effective_sample_rate` to fill the window. Estimation, resampling
diagnostics, scheduling, repeated-look logic, and UI work add more delay. After
warm-up, a rolling detector has a distinct post-change delay. The required sample
count, effective independent-sample rate, rolling post-change delay, complete-
path latency, and matched CUSUM latency are **NOT RUN**. A tactical claim cannot
use a nominal sensor rate or the Exp0 sample count as operational evidence.

**Required fixes.**
1. Qualify NIS/CUSUM and signed Pearson correlation, add the declared parity comparator,
   and benchmark any later-admitted PID candidate head-to-head. If a calibrated
   paired comparison places the difference inside the preregistered equivalence
   margin, ship the cheaper baseline. Raw pid-rs resampling quantiles cannot
   establish equivalence.
2. Scope the experiment by threat: (a) loud phantom, (b) a single-channel
   perturbation matched to the preregistered first-order baseline, and (c) a
   coordinated perturbation matched to the declared parity baseline over at least
   three jointly observed channels. Use ΔAUROC over the best qualified cheap
   baseline at matched FAR plus a high-quantile delay and deadline-miss endpoint;
   preregister the effect size and uncertainty rule.
3. Block every atom-level claim until the atom measure is adjudicated and the
   estimator has an acceptance result, then require exact-data geometry checks
   and calibrated inference. Exp0 cannot satisfy this gate. On any independent
   NO-GO, do not render atoms; use only separately qualified baselines.
4. Evaluate an admitted atom path only as a **≥3-channel discordance-ranking /
   second-opinion** candidate over the best qualified cheap baseline. Benchmark discordant-channel
   ranking accuracy, not only detection AUROC; do not promise a unique-atom UX
   result before the estimator is admitted.

**Residual risk.** Even after atom-estimator work, the exact Mirror data can fail
its necessary geometry checks, so the design reduces to its cheap fallback.
Sensor-side FDI remains a fundamental limit described by the [frozen NCP 0.8
sensor-plane boundary](https://github.com/sepahead/NCP/blob/2f5bd586d4bb20c90362bb6f5698b7f64057ba4e/SECURITY.md#L64-L69).
A valid higher-order statistic could test declared joint
dependence across at least three channels, but it would not close that surface.
Genuine maneuvers with inter-modality latency skew can also create corroboration-
collapse false alarms during high-tempo operation.


### Lens 05 — crebain fusion integration

**Analysis.** The original review identified the need for a common reference in
Crebain. Current commit `d7f3006bfac17a8157d22c6a54a23d00c733851c`
implements a component-tested producer with bounded observations,
outcome/miss/summary evidence, two named-perception routes, and heartbeat
accounting. Its NIS and optional raw innovation remain sequential-update evidence;
the separate attested `consistency_projection` supplies the frozen common-frame
reference. A full queue or upstream loss still invalidates the affected
statistical suffix. The remaining defects concern exact projection selection,
external qualification, and inference rather than absence of producer code.

**Finding 1 — the historical common-reference defect has a distinct projection
path.** The original proposal treated residuals from an in-place update loop as
though they shared a prior, but measurement order changes those sequential NIS
and raw-innovation references. Crebain commit
`d7f3006bfac17a8157d22c6a54a23d00c733851c` preserves that truthful sequential
meaning and separately computes an attested `consistency_projection` from one
frozen pre-association prior. Cross-channel work must use matching projections;
it must not relabel all emitted evidence as frozen-prior. That is component
evidence, not external calibration or receiver qualification.

**Finding 2 — dimensionality still blocks transfer.** Scalar sequential NIS gives
the cheap channel-health baseline; the bounded common-frame projection gives the
separate cross-channel research input. Neither transfers Exp0's built-in MI
result or admits `isx_redundancy`. Any scalar transformation of the projection or
other vector study remains a separately defined path with measure selection,
estimator acceptance, exact-data geometry checks, and calibrated inference.

**Finding 3 — the R down-weight seam loosens the very gate it should tighten.** The
proposed `1/trust[modality]` scaling of `measurement_r_cartesian`
(`src-tauri/src/sensor_fusion.rs:285`) would be consumed both at the
association/cluster gate (`r_carts` and clustering at
`src-tauri/src/sensor_fusion.rs:3224-3258`; `MEAS_CLUSTER_GATE` = 11.345 at
`:65`) and at update-time R construction (`:3570-3614`). Inflating R at the gate
enlarges a suspected modality's acceptance ellipsoid, so it can associate more
easily while receiving less update weight. **Fix:** keep Mirror output out of the
association/cluster gate. A future update-stage-only action still creates feedback
because later residuals depend on the changed state; its stability, safe floor,
decay, and composition are **NOT RUN**. Until those tests pass, emit recommendations
only and compute Mirror residuals against a trust-independent prior.

**Remaining fixes.**
- Establish a reciprocal producer/consumer pin and retain real-router allow/deny,
  lifecycle, loss, saturation, and complete-path latency evidence.
- Emit recommendations only until a post-association update action has a composed
  bound and closed-loop evidence; never change association-gate covariance.
- Align any separate NCP command/sensor study on
  exact equality of `(source.epoch, source.seq)` using the complete driving
  `SensorFrame.stream` within the bound session. Keep any track key as separate
  project-local context. For the implemented Galadriel sidecars, use their own
  bounded producer/lifecycle identities and require the complete declared
  modality set. Do not use `Jitter` as generic tie repair. Retain subsample output
  only as diagnostic quantiles and add a separately calibrated uncertainty
  procedure.
- Require every cross-channel research window to contain matching attested
  `consistency_projection` context; never substitute sequential NIS or raw
  innovation as though it shared the frozen prior.
- Keep vector or atom work research-only until its independent blockers close.
- If Haldir adds a UI, render the advisory as a sibling layer beside
  `DetectionOverlay.tsx`, keep `pointer-events-none`, and label it "advisory."

**Residual risk.** In some filter and plant models, a slow persistent drift can
be absorbed into the predicted state and can make peer projections appear less
corroborated or invert a later attribution. Whether that occurs here, and its
exact floor, are **NOT RUN**. Single-modality tracks have no cross-sensor window
by construction and are out of scope. Asynchronous sensor rates can starve the
selected path of support, forcing an honest `InsufficientEvidence` result rather
than an alarm.


### Lens 06 — Real-time systems & performance

**Analysis.** The earlier pid-rs 0.9 source review is historical; the Galadriel
candidate now pins `pid-core` 1.0.0 commit
`1cd2424f7967e1752dcc8e53859e8fdad3566f51`, whose selected path must be
revalidated. The reviewed implementation can select an exact kd-tree for eligible
low-dimensional Chebyshev KSG/iˢˣ inputs at `n≥128` and at most 16 joint
dimensions. The tree is designed to be bit-identical to brute force and can prune
typical queries, but each query remains `O(n)` worst-case and a complete estimator
remains `O(n²)` worst-case. Ineligible metrics or dimensions use brute force, and
geometry diagnostics such as intrinsic dimension and exact dataset diameter have
explicit `O(n²)` work. Resampling diagnostics repeat the selected estimator and
diagnostics; they are not inference. No retained benchmark binds this workload to
the exact candidate commit, features, build, hardware, window, resample count,
and active-track count. Numeric CPU and throughput claims are **NOT RUN**.

**Findings.**

1. **Cold start requires one full window.** The `d=1, n=4000` value belongs to
   Exp0's built-in Gaussian MI-recovery case, not a Mirror atom gate or sample
   minimum. The first full-window score from a selected Mirror path takes
   `required_n / r_eff` seconds to fill at the measured, decorrelated co-
   occurrence rate `r_eff`. Both `required_n` and actual `r_eff` are **NOT RUN**.
   A raw or assumed sensor rate is not evidence. After warm-up, rolling post-
   change delay is a separate quantity and requires calibration.

2. **Throughput is unknown.** The kd-tree invalidates the former all-brute-force timing
   arithmetic. Worst-case `O(n²)` work, brute-force diagnostics, resampling, and per-track
   fan-out still require an explicit budget, but no source-only argument establishes
   sub-Hz or any seconds-per-track figure.

3. **Hot-path isolation is component-tested, not deployment-qualified.** Crebain uses bounded
   queues and owned tasks, but the exact two-process candidate still needs retained contention,
   saturation, and tail-latency evidence. Component existence does not close that gate.

4. **Backpressure drops cannot be assumed missing-at-random.** `try_send` sheds when its
   queue is full. Queue pressure can correlate with maneuvers, spoof onsets, or track-count
   bursts, so a dropped sample invalidates the proposed statistical window.

5. **No streaming-state API is selected.** The current estimator builds its selected
   neighbor-search backend for each call. A sliding Mirror window therefore needs a
   measured stride and rebuild policy. The existence of a kd-tree does not itself provide
   an incremental window algorithm.

**Required fixes.**

- **Keep the fast path cheap.** Externally qualify and calibrate the implemented
  per-observation NIS/CUSUM and signed-Pearson-correlation baseline, add the declared
  parity comparator, and reserve the latency-critical role for that class of
  statistic. Keep atom diagnostics offline until their independent validity,
  fill-time, and compute budgets are measured against the damage horizon.
- **Benchmark the exact selection.** Bind the pid-rs commit, Cargo features, build profile,
  hardware, neighbor backend reported by the API, `n`, dimension, modality set,
  resample count,
  stride, and active-track count. Retain the command, raw output, artifact hash, and
  variance. Test worst-case fallback and geometry-gate work as separate rows.
- **Budget before scheduling.** Use a dedicated capped executor, a fixed per-tick work
  budget, and round-robin fairness across tracks only after the retained benchmark defines
  safe limits. Do not share the fusion mutex or blocking pool.
- **Surface backpressure.** Count `try_send` drops; mark any window that lost samples as
  low-confidence/invalid rather than emitting a clean "all-clear."
- **Tag every local record** with window age, selected neighbor backend, validity-gate
  result, and explicitly labeled diagnostic quantiles or separately calibrated uncertainty. Never auto-apply a stale trust down-weight into
  `measurement_r_cartesian` — recommend only.

**Residual risk.** The exact tree improves eligible typical queries but does not remove
worst-case `O(n²)` estimator work, brute-force diagnostics, resampling cost, window-fill
latency, or track-count amplification. A transient attack can enter and leave before a valid
window closes. Until the exact benchmark, co-occurrence rate, contention test, and
damage-horizon comparison exist, CPU throughput and alarm-grade latency remain **NOT RUN** and
the Mirror cannot be represented as a real-time detector.


### Lens 07 — Detection theory & operating point

**Analysis.** The reviewed Galadriel PR already produces bounded baseline reports
from the implemented sidecar input. Haldir has no UI or policy that converts those
reports, or any future admitted higher-order trace, into an operator advisory.
Any later post-association update action is a separate, evidence-gated control
design and is not part of the detector result. Three problems dominate.

*(1) The operating point may be empty.* Exp0's built-in MI-recovery result does
not establish a Mirror window or admit an atom. Temporal dependence needs a
declared diagnostic treatment, but pid-rs's generic resampling output is not a
calibrated interval. A candidate must abstain on geometry rejection or a
normalized-invariant status other than `Defined`; continuous atom diagnostics
cannot become verdicts while their estimator remains blocked. The plant damage
horizon and an estimator-specific calibrated uncertainty procedure are **NOT
RUN**. The complete chain from window fill through estimation, scheduling,
uncertainty, minimum detectable effect, repeated-look logic, dwell, and UI delay
must close before alarm claims.

*(2) Redundancy collapse is not sufficient for FDI.* Benign maneuvers, occlusion, sensor dropout, and inter-modality timing changes can produce the same direction of disagreement or an undefined invariant. Their exact atom signatures are **NOT RUN**, so a single-atom threshold cannot separate "spoofed" from "degraded."

*(3) Two error currencies are missing.* A per-window threshold does not define
the required per-track-hour false-alarm behavior. A declared modality × track ×
atom family needs within-look control; overlapping repeated looks need separate
end-to-end ARL₀ and deadline calibration. pid-rs can supply experimental BH/BY
adjustment for a defined family, but those functions do not calibrate the
sequential process. SPRT also needs a fixed minimum-effect H1 before it is a
candidate.

**Required fixes (ordered).**

1. **Close the operating-point feasibility chain first.** Select an estimator-specific uncertainty method, demonstrate coverage on the exact dependence model, and show its width at `W ≤ W_damage` is below the MDE. Diagnostic subsample quantiles cannot satisfy this gate. Any discrete or MI-only alternative needs its own evidence.
2. **Nonparametric CUSUM / window-limited GLR** calibrated end to end on held-out dependent streams to a target **ARL0**, not from raw generic-resampling percentiles. Validate transient behavior. Use SPRT only if a minimum-detectable-effect H1 is fixed.
3. **Condition the alarm on benign-decorrelation covariates available to the consumer** — IMM mode probability, per-channel covariance and measurement availability (occlusion, dropout), GDOP, and jam/SNR flags. Test, rather than assume, whether broadly correlated transients distinguish maneuvers from sustained single-channel FDI in the retained scenarios.
4. **M-of-N dwell/hysteresis** on the recommendation, asymmetric on raise versus restore and bounded by `W_damage`. It does not authorize R inflation.
5. **Matched-ARL0 partial-AUC / detection-delay benchmark** versus the best
   qualified cheap baseline for each threat cell on identical data in the low-FAR
   regime. Preregister a minimum win as the earn-its-complexity gate. Isolate the
   in-gate, cross-inconsistent regime as one candidate advantage cell; do not
   assume it is the only one or that PID wins it.
6. **Predeclared within-look FDR/FWER control** across the declared modality ×
   track family. Use BH only if its dependence assumptions are justified;
   otherwise use BY or a preregistered FWER procedure. Independently validate the
   repeated-look ARL₀ and deadline-miss behavior; do not infer either from the
   within-look correction.

**Residual risk.** A hypothetical cross-channel-consistent input can keep the
tested statistic below its MDE; the Mirror is not a guarantee. Ueda–Kwon's
coordinated command-and-observable affine transformation is a separate reminder
that a plant symmetry can create blind spots outside this single-sensor model.
Regime conditioning opens a *masking* attack: inject during an induced maneuver or
occlusion so the nuisance gate suppresses the alarm. ARL0 is only as good as the
regime in which its null was measured; a non-stationary scene can invalidate it.
Given `calibrated_posterior=false`, flapping alarms invite operator fatigue; dwell
is a trust requirement, not only a statistical one.


### Lens 08 — Provenance & honesty boundary

**Analysis.** The haldir catalog separates *detectors* (observe and alarm) from *enforced gates* (withhold actuation), and its advisory proposals use "recommend, never silently force" or "flag-not-fully-attribute" language. The Mirror declares itself advisory (`calibrated_posterior=false`, no gate), but the original trust-map mechanism scales `measurement_r_cartesian` by `1/trust[modality]` **before** association. That is an in-path state change, not a read-only advisory. Increasing `R` enlarges the Mahalanobis acceptance ellipsoid at association, so a suspect measurement can associate more easily, while the same increase drives its Kalman gain toward zero at update. The composition can therefore weaken rejection and suppress measurement influence at the same time. Its effect on state quality, confirmation, and the plant is **NOT RUN**. "Recommends, not silently vetoes" is not a mechanical property until the automatic write is removed or independently bounded and tested.

**Findings.**
1. The original R-inflation seam changes both association and update behavior. It composes multiplicatively with Nénya's proposed GNSS trust write to the same choke point; independently bounded factors do not establish a safe composed bound.
2. A unique-information spike does **not** certify which sensor lies. Under
   Prisoma's current §2.4 availability–use–effect distinction and H4
   frozen-intervention boundary, it can be consistent with a spoof, a genuinely
   unique true detection, legitimate sensor heterogeneity, or an estimator artifact
   on a failed gate. The Mirror must never render "SPOOFED."
3. The original design omitted a first-class *no-verdict* state. When a geometry, sample, stability, typed invariant-status, or calibrated-inference gate fails, an interpreted trust number is not evidence. Raw resampling quantiles cannot satisfy the inference gate. The revised proposal requires explicit abstention.
4. UI risk: a red/green trust bar beside `DetectionOverlay.tsx` can resemble the archived Palantír-Seal `TrustBadge` concept or gate-associated Haldir/Fëanor `VETO` styling. The operator can then mistake an advisory for an enforced gate.
5. A networked advisory can expose detector state, thresholds, or confidence information to each authorized reader, depending on the record design. That can help an informed attacker tune inputs. The risk depends on the selected ACL, transport profile, and fields; read access is not inherently free or universal.

**Required fixes.**
- **Separate recommendation from control.** Keep the association-gate covariance unchanged. A future automatic action may affect update-stage R only after one monotone, floored, audited arbitration point covers *all* trust writers (Mirror + Nénya). Derive `t_min` from a plant-specific state-quality and safety bound, prove composition, and test confirmation and closed-loop behavior. This evidence is **NOT RUN**. Until it exists, emit a recommendation only; anything beyond a proven soft bound requires explicit operator acknowledgment.
- **Forbid certified attribution.** Emit a per-channel "uncorroborated-information" advisory only; adopt Nénya's flag-not-attribute wording. State the four-way ambiguity on the tin.
- **Make estimator validity explicit in the consumer report and UI.** A rejected
  window uses the current public `Verdict::InsufficientEvidence`,
  `CorrVerdict::InsufficientEvidence`, or `FusedVerdict::InsufficientEvidence`
  variant as applicable, retains `calibrated_posterior=false` and typed status,
  and labels any raw resampling output as diagnostic. It includes a confidence
  interval only after a separately validated procedure exists. The UI renders a
  greyed "no verdict," never default green/red. This is project-owned consumer
  report/UI state, not an NCP wire state or producer-side observation.
- **Distinct advisory idiom + provenance.** A "cross-sensor corroboration" meter,
  an explicit "ADVISORY — not a gate" caption, and no shared pass/fail colour
  with enforced badges. A future project-owned Haldir report carries the complete
  driving source identity and explicitly classifies simulation versus real input.
  Do not reuse wire-0.8 `ObservationFrame` for real-world advisory output: that
  frame requires `is_simulation_output=true` and
  `calibrated_posterior=false`. NCP's `contract_hash` is a session-handshake field,
  not per-frame provenance. Log every advisory and, if one is ever qualified,
  every bounded action and human acknowledgment to Border-Muster.
- **Scope the FDI claim and gate on the baseline.** State that it tests only
  cross-inconsistent single-channel injection and is blind to any input that
  preserves the tested joint distribution. Treat Ueda–Kwon's coordinated
  command-and-observable affine-symmetry attack as a separate out-of-scope cell.
  Ship Haldir policy disabled until it beats the best qualified cheap baseline
  for the threat cell by the preregistered ΔAUROC ≥ 0.05.

**Residual risk.** Even bounded, a persistent down-weight on a
healthy-but-heterogeneous channel is a soft denial-of-track. A compromised
producer or consumer process can make the Mirror cry wolf; channel integrity,
principal binding, and process isolation remain separate requirements. The
implemented network routes still need live security qualification. The "Nénya =
the Mirror" naming collision in the catalog is itself a provenance hazard for a
future shared trust seam.


### Lens 09 — EW / operational context & operator UX

**Verdict: needs-hardening.** The Mirror has a plausible physical motivation and
an unvalidated statistical hypothesis; its operational framing must distinguish
electronic-warfare causes. The proposed cross-channel alarm can move in the same
direction for a single spoofed channel and a single jammed or degraded channel
because both can decorrelate one common-frame projection from its peers. The
statistic alone does not distinguish those causes. A future trust bar can report
only a corroboration state unless the implemented NIS/CUSUM plus signed-Pearson
baseline, additional qualified comparators, and independent channel-health
evidence support a narrower label.

**The jam-vs-spoof confound is the central finding.** A jammed acoustic array can
produce incoherent, high-variance, non-white residuals or drop out. A hypothetical
cross-inconsistent injection can instead remain inside its per-channel NIS gate
while disagreeing with peer geometry. The reviewed Galadriel PR already combines
NIS/CUSUM with signed Pearson correlation at component level. This motivates, but does not
validate, a future Haldir 2×2 over {peer corroboration intact/collapsed} ×
{per-channel NIS coherent/blown}. Collapse with coherent NIS supports a
**SUSPECT-INJECTION** hypothesis; collapse with blown NIS or dropout supports
**DENIED-DEGRADED**. Neither state identifies an attacker or proves the cause.

**The estimator can abstain during the difficult regime.** Dropout reduces sample coverage; jamming can create temporal dependence; and asymmetric availability can change the estimand. The frequency and severity of those conditions are not qualified on recorded streams. The advisory UI must wire UNKNOWN-ABSTAIN to geometry, sample, typed invariant, and calibrated-inference gates. Raw resampling quantiles do not clear those gates.

**Severe false-positive class: a legitimate single-modality target.** A target that only one modality observes can carry genuine unique information precisely because nothing corroborates it. A "unique = injection" rule would mislabel that target. The tool is a **corroboration meter, not a lie detector**: it must show which peers disagree and let the operator keep an uncorroborated track.

**Required fixes (ordered):**
1. Externally qualify the existing NIS/CUSUM plus signed-Pearson-correlation baseline,
   then test the jam/spoof 2×2 as a Haldir UI taxonomy. Do not depend on an atom
   result; if an atom estimator is later admitted, expose it only as an additional
   research diagnostic rather than raw atom glyphs.
2. Explicit ABSTAIN trust state, fail-closed, wired to geometry, typed invariant, sample, source-count, and separately calibrated inference gates.
3. Palette orthogonal to `THREAT_LEVEL_COLORS`
   (`src/detection/types.ts:119`) — never reuse the `getThreatLevel`
   green/amber/red, or a suspect-channel bar and a level-4 severe-threat box
   collide.
4. Global channel-health state (per modality: LIVE/DEGRADED/DENIED) resolved *before* per-track attribution; suppress per-track spoof flags on a denied channel to avoid a wall of red during the raid. Emit recommendations only. A future automatic action must use the separately bounded update-stage-only arbitration point and cannot write association-gate covariance.
5. A preregistered within-look family across the live track × modality grid,
   using pid-rs's default-off BH/BY API only after its dependence assumptions and
   provenance are fixed; a separately calibrated repeated-look ARL₀ and deadline-
   miss policy; and a bounded compute budget that degrades to the qualified cheap
   baseline under load with a visible "reduced mode" tag.

**Scenario walk (phantom DOA + FPV raid).** T0 assumes three agreeing channels.
T1 seeds an acoustic-only track; with one source there is no cross-channel
corroboration statistic, so the component must abstain and a modality-count
heuristic already provides the useful fact. T2 assumes a phantom biases a real
co-associated track while acoustic NIS remains nominal and peer corroboration on
matching consistency projections drops. This is the candidate band to compare
with parity, not a demonstrated win. The system emits a recommendation only; it
does not write acoustic R. T3 assumes global acoustic degradation; without
channel-health suppression, many per-track advisories can appear at once. The
proposed Haldir operator product is one per-track corroboration glyph plus a
channel-health strip, with `calibrated_posterior=false` and no effector-cue
authority.

**Residual risk.** A coordinated two-channel spoof can preserve or raise
corroboration and can appear healthy. A green trust state under active EW is not
proof of authenticity. The size of the "single-channel higher-order dependence
perturbation, matched to the qualified cheap baselines, co-associated with a real
track, all channels healthy" regime is **NOT RUN**; it
must be measured before a Haldir alarm or UI is justified.


### Lens 10 — Evaluation & validation plan

**Analysis.** Component and synthetic paths for a preregistered validation exist.
`manwe/python/src/manwe/fusion/scenarios.py::make_scenario` emits seeded
ground-truth trajectories plus noisy, cluttered, partially detected multi-sensor
`frames`, and `fusion/metrics.py::ospa` scores reconstruction.
`pid-runlog::RunLogWriter` can retain byte-reproducible artifacts. Exp0 is only a
separate built-in MI-recovery sanity experiment; it is not a Mirror or atom gate.
For a separate frozen-NCP-wire-0.8 command/sensor study, join
`CommandFrame.source` to the complete driving `SensorFrame.stream`; sequence
values are scoped to their epoch. The simulation-only `ObservationFrame` carries
`is_simulation_output=true` and `calibrated_posterior=false`, and `contract_hash`
appears in the session handshake rather than every frame. A prisoma-style plan
can be specified from these components. What remains absent is an exact reciprocal
producer/consumer pin with recorded cross-repository qualification and a retained
head-to-head calibration campaign.

**Findings.**

1. **The component baseline exists; its operational calibration does not.**
   Crebain commit `d7f3006bfac17a8157d22c6a54a23d00c733851c`
   emits bounded sequential NIS plus optional attested common-frame consistency
   projections, and the reviewed Galadriel PR processes NIS/CUSUM and matching-
   projection signed-Pearson-correlation evidence. A current reciprocal pin, recorded-
   stream calibration, held-out false-alert control, and external two-process
   receipt remain **NOT CLAIMED**.

2. **The window is a primary validity axis, not a free knob.** At cold start, the
   first full-window score requires one window of admitted samples. After warm-up,
   a rolling detector can cross its threshold before one full window of post-change
   samples arrives. That post-change delay requires separate calibration. In the
   explicit scenario `dt=0.5s`, a 10 s window contains about 20 scheduled samples
   before dropout or dependence adjustments. Exp0's unrelated `n=4000` MI fixture
   is not a Mirror minimum. This arithmetic is a scenario warning, not a measured
   Crebain rate. NIS can produce one statistic per observation. The required study
   is a Pareto frontier over complete latency, estimator validity, and ROC-AUC, with
   callable exact-data checks and calibrated inference for each selected path.
   Geometry can reject an atom feature; it cannot admit the atom estimator.

3. **Two uncontrolled error surfaces.** The candidate pid-core API offers
   experimental BH/BY adjustment functions, but library availability does not
   predeclare a within-look family, dependence policy, or invocation. Repeated
   corrected looks across overlapping windows remain a separate sequential
   calibration problem. One primary statistic and endpoint must be preregistered;
   exploratory within-look families need a selected adjustment, while the full
   procedure needs retained ARL₀ and deadline evidence.

4. **Cross-repository qualification gap.** Manwe-only injection does not validate the Crebain/Galadriel stack. Producer and consumer components now exist, but their retained paired fixture is historical, not a reciprocal current-candidate pin. Injections must traverse the exact current producer and consumer revisions under the real loss, lifecycle, and security topology.

**Required fixes.**
- Qualify the implemented NIS/CUSUM plus signed-Pearson component baseline and
  evaluate whiteness/autocorrelation and parity as additional comparators. Select
  the best qualified cheap baseline per threat cell as the falsification yardstick.
- Preregister one primary Mirror statistic and one endpoint per injection class:
  paired ΔROC-AUC over that threat cell's best qualified cheap baseline at
  matched false-alarm rate and complete latency, with a Mirror-specific powered effect
  size. Define and power a separate discordant-channel-ranking endpoint and a
  separate deadline/tail-latency endpoint; do not import retired Prisoma
  Spearman/Kendall thresholds. Predeclare the within-look hypothesis family and
  use BH-FDR only with justified dependence assumptions, otherwise use BY or a
  preregistered FWER control.
- Map the window/latency/n frontier with callable exact-data checks. Reproduce
  Exp0 separately as an MI-library sanity check only. Retain
  `RowResampleScheme::Subsample` as diagnostic output; add an estimator-specific
  calibrated uncertainty procedure with demonstrated coverage. Keep atom results
  blocked until measure and estimator acceptance are independently resolved.
- Run the red-team library through Crebain `d7f3006bfac17a8157d22c6a54a23d00c733851c` and the reviewed Galadriel PR head `bd2dc86ec9616dc59c6a243735d71792eb494f6d`, or reviewed successors under a reciprocal pin. The Galadriel candidate selects `pid-core` 1.0.0 commit `1cd2424f7967e1752dcc8e53859e8fdad3566f51`; retain the resolved source digest and revalidate the selected APIs. pid-rs is linked code, not an NCP peer, and receives no NCP role receipt.
- Write the quantitative ABANDON contract (negative-result-first): (a) a
  higher-order candidate fails to beat the best qualified cheap baseline for the
  threat cell by ΔAUROC ≥ 0.05 at
  matched FAR and latency → ship the baseline and drop that candidate; (b) the
  continuous atom measure or estimator receives NO-GO → drop continuous atom
  attribution, regardless of any discrete result; (c) an independently admitted
  discrete estimator fails its own acceptance gate → drop that discrete path;
  (d) attribution is no better than chance → kill "which-channel"; (e) the
  preregistered high-quantile end-to-end delay or deadline-miss bound fails
  against the measured plant damage horizon → re-scope to offline analysis.
  Retain median latency only as a descriptive statistic.

**Residual risk.** A hypothetical adversary that preserves the complete tested
joint distribution defeats every statistic computed only from that distribution;
a red-team library of naive injections will therefore overstate detectability if
it omits this acceptance cell. Ueda and Kwon's affine-symmetry example instead
coordinates command and observable transformations and illustrates a different
system-model blind spot. Prisoma's current §2.4 availability–use–effect distinction
and H4 frozen-intervention protocol mean a redundancy signature need not track what
the fused estimate causally used. A
quantized shared-exclusions SxPID result changes the observed variables and cannot
validate a continuous result; a Williams–Beer `I_min` result additionally changes
the redundancy measure. None of these passes validates another path.
