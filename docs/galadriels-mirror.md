# Galadriel's Mirror

## Summary

Galadriel's Mirror is a read-only, advisory cross-sensor consistency monitor for **crebain**, the tactical counter-UAS ARAS. It subscribes to per-modality measurement-innovation residuals (vision, radar, acoustic-DOA, N-view-triangulated 3-D) on the NCP observation plane and, over sliding windows, asks a partial-information-decomposition (PID) question: *does each channel's innovation still corroborate the consensus of the others, or has one channel gone informationally private?* A naive single-channel false-data injection (FDI) — a phantom acoustic DOA from a phased emitter, an adversarial patch poisoning one camera's contribution to triangulation — is, by construction, information **not shared** with the honest channels. The provable signature is a **collapse of that channel's redundancy / mutual information with a leave-one-out consensus reference**, surfaced as a per-channel trust bar beside `DetectionOverlay.tsx` and, on sustained evidence, a *recommended* (never silently enforced) modality down-weight ahead of crebain's association gate.

The one honest sentence: **the Mirror can show that one channel has stopped agreeing with the corroborated consensus of the others — it cannot prove that channel is lying, cannot see any spoof that preserves cross-channel agreement, and must earn its complexity against a cheap chi-squared baseline before it is trusted for anything.**

---

## 1. Threat model

**In scope.** Uncoordinated, cross-inconsistent, supra-window **single-channel** FDI against a target being tracked by two or more modalities: a phantom acoustic bearing injected on the perception plane, an adversarial-patch bias on one camera feeding N-view triangulation, a replayed or drifted radar return. These attacks inject information into one channel's innovation that the physically honest channels do not share, so over a window the suspect channel's innovation stops covarying with the others' consensus.

**The detection boundary against an adaptive adversary.** The Mirror is blind, *by construction and after any estimator hardening*, to:

- **Coordinated ≥2-channel spoofs** and any **physically consistent phantom** (a real decoy drone; a phased acoustic emitter plus an RF replay triangulating to the same false point). These *raise* cross-channel redundancy and read as a healthy, corroborated track.
- **Statistics-matching / residual-aware stealthy FDI** (Ueda & Kwon, arXiv:2408.10177; Choi & Jang, WISA'22). An attacker who knows the fused covariance can craft an injection that keeps the suspect innovation inside the redundant core; no atom moves. This is a **fundamental limit shared with the chi-squared baseline**, not a tuning gap.
- **Slow drift below the largest window / bootstrap resolution**, which is absorbed into the fused state as common-mode.
- **Majority-spoof inversion:** with only 3–4 modalities, a redundancy collapse says "channel *k* disagrees with the rest"; it *cannot* distinguish "*k* is the attacker" from "*k* is the lone honest sensor amid three spoofed peers." Leave-one-out consensus is undefined once two channels are compromised.

The Mirror therefore raises adversary cost; it is **not** a Kerckhoffs guarantee and is **not** a substitute for the real closure of the perception-plane surface — default-deny per-plane Zenoh ACL plus mTLS (NCP P0 / SECURITY.md:62-86). It is a defense-in-depth *second opinion*, and it says so on the tin.

---

## 2. Formal basis

**Sources and target.** For a track over a window of *W* frames, the sources are the per-modality innovations $S_i = \{y_i^{(t)}\}$ where $y_i = z_i - H\hat{x}^-$ is measurement *i*'s residual against the **pre-update predicted prior** $\hat{x}^-$, with innovation covariance $S_i = HP^-H^\top + R_i$. The estimand is a per-channel PID atom decomposing how each channel's information relates to a reference target $T$.

**Resolving the circularity (Lens 01).** The naive choice $T = $ *the fused state* is fatal and must never be used. The Kalman update $\hat{x}^+ = \hat{x}^- + \sum_i K_i y_i$ makes $T$ a deterministic function of the very sources, so $\mathrm{PID}(S; \hat{x}^+)$ measures Kalman-gain weighting, fires on the *most trustworthy* sensor, and — critically — a **successful** attack *raises* the poisoned channel's MI with the now-corrupted $T$. The signature would be sign-inverted and the attribution backwards. Three admissible references, in order of preference:

1. **Leave-one-out consensus** $T_{-k} = \mathrm{robust\_combine}\{y_j : j \neq k\}$ (or the LOO fused state $\hat{x}^{(-k)}$), scoring each channel against a target it did not help build. The API already exposes `average_degree_of_vulnerability(joint_mi, leave_one_out_mis)`.
2. The **next-step predictive innovation** (temporal LOO), which breaks the recursion whereby a persistent attack becomes common-mode.
3. **Ground truth — offline only**, for exp0 calibration.

**Which atom moves, and its sign.** The provable signature of naive single-channel FDI is a **collapse of the suspect channel's redundancy / MI with the LOO consensus** — its innovation stops corroborating the honest shared latent $M$. It is **not** a unique-information spike about the fused state. The primary estimand is therefore the **signed per-channel atom** from `pid3_isx` (unique / redundancy against $T_{-k}$) or, in the discrete fallback, the `discrete_sxpid_n` `SxAtom{informative, misinformative, net}`, whose misinformative part $\pi^- = \log[P(t)/P(\mathfrak{t}\cap\bigcup\mathfrak{a})]$ is *exactly* "this source lied about the target."

**Why not just correlation, and why not O-information as primary.** A linear partial-correlation parity check catches first-moment mean-shifts; PID's *only* claim to added value is **non-Gaussian / higher-order** inconsistency where a channel's dependence structure diverges without a detectable mean shift. Meanwhile the global Shannon invariants are demoted to **secondary screens**: `o_information_discrete` (Rosas Ω) is target-free, non-attributing, and need not flip sign when one of four channels decorrelates; `average_degree_of_redundancy`/`_vulnerability` (r̄/v̄) **return NaN unless `joint_mi > 1e-12`**. Attribution must be per-channel and signed, or it is not attribution.

---

## 3. Estimator & statistical validity

The estimators are only trustworthy inside a narrow, gated regime. At crebain's ~10 Hz cadence a real-time window holds **tens** of effectively-independent samples of 3-D innovations — roughly two orders of magnitude short in *n* and several-fold over in *d* relative to pid-rs's only validated band (`exp0 --strict-gate`: **d = 1, n = 4000**, jointly Gaussian). Naively feeding raw 3-D residuals makes the `pid2` joint term a ~9-D kNN query and the alarm a **kNN artifact**. The discipline:

**Dimensional collapse.** Reduce each modality to a **scalar whitened innovation** $S^{-1/2}y$ (equivalently scalar NIS $y^\top S^{-1} y \sim \chi^2(3)$) so the joint PID lives at *d* ≈ 2–4, near the validated band. Run per-axis only when directional structure is explicitly required, as a geometry-gated research escalation. This also makes the head-to-head against the NIS baseline apples-to-apples.

**Mandatory geometry gate, per window, before any atom is interpreted.** `intrinsic_dimension_levina_bickel` (k ≥ 3); `distance_concentration_stats` refusing when `nn_over_pairwise_mean → 1`; δ-hyperbolicity. When continuous $I^{sx}$ is ruled illegal, fall back to **discrete Williams–Beer `I_min`** via `quantize_equal_width`, or to MI-only screening — and **never pool continuous $I^{sx}$ with discrete `I_min` atoms** (they are different measures).

**Autocorrelation and effective sample size.** Estimate the innovation integrated autocorrelation time $\tau$ per window, set the moving-block length ≈ $\tau$ (not exp0's `block_size=1`), compute $n_{\text{eff}} = n/\tau$, and **refuse to emit a verdict below a pre-registered $n_{\text{eff}}$ floor** tied to the chosen measure and dimension. Use `RowResampleScheme::Subsample` (Politis–Romano); the naive with-replacement bootstrap distorts kNN local density.

**Fail-closed states.** Treat `NumericalInstability` (radius collapse on duplicate/quantized/dt=0 replay frames — add seeded `preprocess::Jitter`), `NonFiniteInput`, NaN r̄/v̄ (`joint_mi ≤ 1e-12`), and any `bootstrap_instabilities > 0` as **automatic abstention**. Every window that fails a gate emits `verdict = insufficient-confidence` with `calibrated_posterior = false`, a `gate_passed` flag, and the CI — **not** a trust number. The UI renders a greyed "no verdict" bar, never default-green or default-red.

**Honest cost.** Fully gated, the Mirror falls to "insufficient evidence" in the majority of tactical windows and is silent precisely when a fast verdict is most wanted; within-window non-stationarity of a maneuvering target still violates the i.i.d. assumption underneath every KSG estimate; and streaming FDR across heavily overlapping windows is only approximate. These are accepted, documented limits.

---

## 4. Detection & decision

**Feasibility first.** Before any threshold is set, the operating point must be shown **non-empty**: the block-subsample CI half-width on the per-channel unique/redundancy atom, at a window *W* matched to the FDI **damage horizon** (~3–5 fusion frames, since the gate is χ²(3)=11.345 with 3-of-5 confirmation), must be smaller than the minimum detectable atom change. If the *n* needed for a trustworthy kNN estimate exceeds the damage horizon, the continuous detector alarms *after* corruption is fused — in which case pivot to the discrete SxPID / MI-only screen (lower *n*).

**Statistic.** Replace single-window thresholding with a **nonparametric CUSUM** (or window-limited GLR) on a studentized per-channel atom, z-scored against a permutation / block-bootstrap null, calibrated to a target **ARL₀** (mean time between false alarms per track-hour), *not* a per-window α. CUSUM's persistence bias rejects transient benign spikes. SPRT is ill-posed here: the attacker chooses the atom magnitude, so there is no parametric H₁.

**False-alarm control under benign decorrelation.** Genuine maneuvers, occlusion/dropout, and inter-modality latency skew (acoustic lag) *also* collapse redundancy. The decision is therefore **conditional on nuisance covariates already on the bus**: IMM mode-probability (a `CoordinatedTurnFilter` switch = maneuver), per-channel covariance inflation / measurement availability, GDOP, jam/SNR flags. Alarm only on an atom spike **not** explained by a co-occurring nuisance, using a co-onset discriminator: **a maneuver is a transient, correlated spike across all channels; FDI is a sustained, unique spike on one.**

**Hysteresis.** Apply M-of-N dwell on the alarm mirroring crebain's own 3-of-5 lifecycle, asymmetric on raise vs. restore, gating the down-weight — but **bound the dwell above by the damage horizon** so latency never exceeds the time to corrupt a track. Rate-limit the down-weight recommendation with hysteresis so an adversary cannot weaponize false spikes on a *healthy* channel to down-weight it (attack-via-defense DoS).

**Multiple comparisons.** Apply BH-FDR / FWER across the 4-modality × N-track × antichain grid; pid-core ships **no** multiple-comparison correction, and without it the per-track ARL₀ collapses.

The residual tension is real and pre-registered: detection delay and FAR trade off through dwell length. **If no dwell simultaneously satisfies the damage-horizon latency bound and the target ARL₀, there is no viable runtime operating point and the module does not ship as a real-time advisor** — it re-scopes to a slow attributor (§7, §10).

---

## 5. Why PID over the cheap baseline

The Mirror must **earn its complexity** against a real competitor — not the strawman of per-sensor NIS, which crebain already ships as its association gate (`gated_sq_mahalanobis`, χ²(3)=11.345). The honest baseline is a **pairwise cross-sensor parity residual** $z_i - z_j$ (analytical redundancy) plus **CUSUM/GLRT**, which catches mean-shift FDI at roughly 1/1000 the cost.

**The head-to-head, by threat cell:** (a) loud phantom; (b) first-moment-stealthy single-channel FDI; (c) parity-defeating coordinated 2-channel FDI. Primary endpoint: **ΔAUROC over the best cheap baseline at matched false-alarm rate**, with a committed minimum effect **≥ 0.05**. Mandatory secondary endpoint: **frames-to-alarm at fixed FAR** — a 60-second-late alarm is a miss.

**Where PID strictly wins:** a **≥3-channel, moment-matched, geometry-gate-GO** regime — a coherent single-channel bias, co-associated with a real track, that passes the per-channel χ²(3) gate but is **cross-channel inconsistent in higher-order structure** that parity's linear residual cannot see. The durable, differentiated value is **per-source attribution** — *which* channel is lying — benchmarked separately from raw detection AUROC.

**Where it honestly does not win.** Against statistics-matching FDI, PID and NIS fail together. In the likely deployment geometry (a ~15-D 4-source × 3-D-innovation + 3-D-target joint space; cf. prisoma r̄≈28.6 / v̄≈−26.6 at d=64) the geometry gate may be **permanently NO-GO** and the Mirror reduces to its parity fallback. KSG's i.i.d.-sample appetite means tens of seconds to alarm vs. a few frames for CUSUM — disqualifying at engagement tempo for the *fast* path. The pre-registered kill criterion (prisoma grandplan §14.1) governs: **if parity matches PID within CI, ship parity.**

---

## 6. crebain integration

**The tap (off the hot path).** Add `obs_tx: Option<SyncSender<PidObservation>>` to `MultiSensorFusion` (sensor_fusion.rs:1657), default `None`. In `update_track`'s per-measurement loop (L2061), **freeze the pre-update predicted prior once** before the loop, then for each cluster member compute $y = \text{pos} - \text{prior}[0..3]$ and $S = \text{pos\_cov} + \texttt{measurement\_r\_cartesian}$ against that frozen prior — never against the sequentially-mutated (contaminated) state, which would make each subsequent modality's residual inconsistent with the gate's own math (L1793). Collapse to scalar NIS before emitting. `PidObservation` is POD carrying the **numeric** track id (not `format!("TRK-{:05}")`, to avoid a per-measurement heap allocation) and `try_send` (non-blocking; a slow consumer can never stall fusion). Create the bounded channel and drain thread in Tauri `.setup()` (lib.rs:724, where `Emitter`/`Manager` exist), forwarding via `Emitter::emit("pid-observation", …)`.

**Sequence alignment.** Build windows keyed on `(track_id, timestamp_ms/seq)`; require ≥ `n_min` co-occurring frames per modality pair before scoring; join on `seq`, not arrival time (NCP command↔sensor coupling). Add seeded `Jitter` to defeat kNN radius collapse on duplicate/replay frames. Surface `try_send` drop counts and **invalidate any window that lost samples** — drops are load-correlated with the events of interest.

**Recommend, never veto.** Apply the trust down-weight **only to the update-stage R** — never to the association/cluster `r_carts` (L1898-1902). Scaling R at the gate *inflates* the acceptance ellipsoid, so a suspected-spoofed modality would associate *more* easily — backwards. Route all trust writers (Mirror + Nenya) through a **single monotone, floored, audited arbitration point** at `measurement_r_cartesian` (L177) so they cannot compose multiplicatively to zero a channel. Clamp trust to $[t_{\min}, 1]$ with $t_{\min}$ chosen so the worst-case inflated R **still admits a corroborated measurement through χ²(3)=11.345** and cannot starve the 3-of-5 confirmation. Any down-weight past the soft bound requires explicit operator ack. Bound the factor and decay it back to 1.0.

**UX (Lenses 05, 09).** Render trust bars as a **separate advisory sibling layer** beside `DetectionOverlay.tsx` (keep `pointer-events-none`), never inside `drawDetectionBox`. Use a palette **orthogonal** to `THREAT_LEVEL_COLORS` (types.ts:276) so a severe-threat box and a suspect-channel bar never collide on red/amber — trust state is a separate visual channel (hue/shape/hatch). Four explicit states: **TRUSTED / SUSPECT-INJECTION / DENIED-DEGRADED / UNKNOWN-ABSTAIN**. The primary output is a **jam-vs-spoof 2×2**: PID redundancy-collapse fused with per-channel NIS — collapse **+ internally coherent NIS ⇒ SPOOF**; collapse **+ blown/dropout NIS ⇒ DENIAL** (down-weight, no injection accusation). Every SUSPECT flag shows **which peer channels disagree**. Never auto-down-weight a single-sensor track to zero — that suppresses the radar-dark, acoustically-masked low-observable FPV, the most dangerous real target class.

---

## 7. Real-time performance

Off-hot-path isolation is genuinely sound: a read-only observation-plane subscriber plus bounded `try_send` can never stall fusion. But **in its only trustworthy regime the Mirror is sub-Hz**. All pid-rs kNN is **brute-force O(n²)** per query (no kd-tree/ANN — an external ANN would break the Chebyshev/geometry-gate coupling). A CI-bearing `pid3_isx` at the strict n=4000 band costs **tens of seconds of CPU per track** on 8 cores (~200× bootstrap multiplier over ~10 O(n²) passes). Window-fill latency to accumulate enough decorrelated i.i.d. samples (acoustic DOA the slow channel) is **tens to hundreds of seconds** and is irreducible without abandoning the block-bootstrap trust regime.

**Consequence: split the clock.** The cheap per-sample NIS/whiteness χ² baseline owns the **fast tactical alarm**; the Mirror runs on a **slow stride as a background attributor**. Budget the estimator on a dedicated capped rayon pool (not the fusion `spawn_blocking` pool), expose `n_boot` as a compute knob, and **round-robin across tracks under a fixed per-tick budget** — otherwise a phantom-track saturation attack multiplies tracks, spikes Mirror CPU, forces `try_send` drops, and creates a blind spot precisely under attack. Tag every emission with **window-age, validity gate, and CI**; never auto-apply a stale down-weight. Under load, degrade to NIS-only with a visible **reduced-mode** tag rather than lagging reality with stale-but-confident bars.

---

## 8. Honesty boundary

The Mirror is advisory: `calibrated_posterior = false`, human-in-the-loop, strictly out of the effector-cue path. Made mechanical rather than sloganeered:

- **It softens, never vetoes.** The floored, clamped, single-arbitration-point down-weight is provably too weak to starve a corroborated measurement through the gate or the 3-of-5 confirmation.
- **It forbids certified attribution.** It emits a per-channel **"uncorroborated-information" advisory score**, never a "SPOOFED/LIAR" verdict. On the tin: a redundancy collapse is **equally consistent** with a spoof, a genuinely-unique *true* detection, legitimate sensor heterogeneity, or a kNN artifact (prisoma availability-vs-use gap §H2 — PID measures information *available* in the innovation, not what fusion *causally used*).
- **Estimator validity is a first-class wire state.** Pre-gate atoms are never interpreted; failed windows render "no verdict," never default green/red.
- **Distinct advisory idiom.** A "cross-sensor corroboration" meter captioned **ADVISORY — not a gate**, sharing no red/green pass-fail language with enforced badges (Palantir-Seal `TrustBadge`, Haldir/Feanor VETO). Every frame echoes NCP provenance (`is_simulation_output`, `calibrated_posterior=false`, driving `SensorFrame.seq`); every advisory, down-weight, and human ack is logged to the Border-Muster ledger.
- **Naming.** The Mirror is **Galadriel**, not Nenya (the separate GNSS-spoof guardian); the arbitration point and operators key on stable, unambiguous subject IDs, since two guardians writing overlapping fusion seams under confusable names is itself a provenance hazard.
- **The tap is a root of trust.** If left unsigned, a second attacker can spoof `PidObservation` frames to make the Mirror cry wolf. The tap channel must be Palantir-Seal'd, or the down-weight kept provably too weak to veto — ideally both.

It **must never claim** to prove a channel is lying, to have caught a stealthy or coordinated spoof, or to be a substitute for mTLS + per-plane ACL. It **ships disabled-by-default** until it beats the baseline by the pre-registered margin.

---

## 9. Evaluation plan

The plan is buildable on existing assets (manwe's seeded `make_scenario` + OSPA, the exp0 runlog gate, the shared tap) but is only sound if pre-registered and falsification-first.

1. **Build the NIS / whiteness χ² baseline FIRST**, from the *same* `PidObservation` tap (NIS = $y^\top S^{-1} y \sim \chi^2(3)$). A grep of `crebain/src-tauri/src` confirms it does not yet exist. Same inputs, same seed ⇒ a controlled contest; this is the yardstick the Mirror must beat.
2. **Pre-register one primary composite statistic** (windowed Δr̄ redundancy-collapse, or max per-source Unq atom) and one endpoint per injection class: **paired ΔROC-AUC vs NIS at matched FAR AND matched latency**, predicted sign, committed minimum **ΔAUROC ≥ 0.05** (|ρ| ≥ 0.3, τ̄ ≥ 1/3 for latency/attribution). BH-FDR across the grid. **No post-hoc fishing** over the 18 (`pid3_isx`) / 166 (`discrete_sxpid_n`) antichains.
3. **Map the latency × estimator-validity × AUROC Pareto frontier** — the window is the primary validity axis, not a knob (detection latency ≥ window length by construction; a 10 s window at dt=0.5 s ≈ 20 samples, orders below the strict band). Gate each point with exp0 invariant + geometry checks and moving-block bootstrap CIs on the *actual* Mirror feature vectors.
4. **Close the sim-to-integration gap**: port `make_scenario` frames into `crebain::SensorMeasurement` and run the red-team library (phantom DOA, patch-poisoned triangulation, replay) through the **shipped tap** in `MultiSensorFusion::update_track`, not the manwe Python tracker. Pin `pid-core` v0.4.0 by `contract_hash`; log via `pid-runlog`; seed scenarios and injections.
5. **Control FAR calibration**: set thresholds ex-ante on disjoint calibration scenarios; report FAR at a fixed pre-registered threshold on held-out clean scenarios (with clutter + missed detections); run an **inject-nothing placebo** that must not alarm above α.

**The falsification contract (negative-result-first ABANDON triggers):**
- (a) Mirror fails to beat NIS by ΔAUROC 0.05 at matched FAR + latency ⇒ **ship NIS, drop the PID layer.**
- (b) exp0/geometry NO-GO at the operating window **and** discrete `I_min`/SxPID also fails ⇒ **drop continuous atom-level attribution**, fall back to MI-only / NIS.
- (c) attribution accuracy ≤ chance (1/num-modalities) ⇒ **kill the which-channel claim.**
- (d) median latency beyond the 3-of-5 confirmation horizon ⇒ the advisory is post-hoc, **re-scope to slow attributor.**

Honest caveats carried into the plan: optimal-stealth FDI defeats NIS and Mirror alike, so a naive-injection library **overstates** detectability; synthetic Gaussian clutter will not reproduce non-Gaussian phased-emitter DOA or adversarial-patch triangulation error; a threshold calibrated on synthetic clean data may not hold on real crebain innovation statistics.

---

## 10. Roadmap & MVP

**MVP (buildable first slice).**
1. Land the **read-only tap**: frozen pre-update prior, scalar NIS `PidObservation`, bounded `SyncSender`, drain in `.setup()`, emit `"pid-observation"`. Pure, no state/gain/ordering change.
2. Implement the **NIS / whiteness χ² baseline** on that stream — the mandatory yardstick.
3. Ship the DetectionOverlay **four-state advisory bar** (TRUSTED / SUSPECT / DENIED / ABSTAIN) driven *by the baseline alone*, orthogonal palette, `pointer-events-none`, disabled-by-default.

**Milestone 1 — estimator harness (offline).** Wire `pid-core` with the mandatory geometry gate, $n_{\text{eff}}$ floor, and subsample bootstrap CIs. Run exp0 on real Mirror feature vectors to find whether *any* operating window is GO. If permanently NO-GO, the discrete SxPID fallback is the only live path.

**Milestone 2 — head-to-head (offline, pre-registered).** Red-team injection library through the shipped tap; ΔAUROC + frames-to-alarm vs baseline per threat cell. **Gate: pass the falsification contract or stop here** and ship the baseline-only bar.

**Milestone 3 — attribution & CUSUM.** If M2 passes, add LOO-consensus per-channel signed atoms, the jam-vs-spoof 2×2, CUSUM with nuisance-conditioning and M-of-N dwell, and BH-FDR.

**Milestone 4 — advisory down-weight.** The floored, clamped, audited arbitration point at `measurement_r_cartesian`; operator ack; Border-Muster logging; rate-limit + hysteresis. Background slow-stride scheduler with round-robin budgeting.

At every milestone the default posture is **off**, advisory, and one benchmark away from being deleted.

---

## Appendix: 10-Lens Review

This design was hardened against a ten-lens adversarial review — information-theoretic soundness, estimator validity & statistical gates, adaptive adversary, baseline justification, crebain integration, real-time performance, detection & decision theory, provenance & honesty boundary, EW/operational UX, and evaluation & validation. Every fix each lens demanded is integrated above, and every limitation each lens found is carried forward candidly rather than resolved away. **The full per-lens analyses follow this file, concatenated after it.**

### Lens 01 — Information-theoretic soundness

**Question under test.** Does a single-channel false-data injection (FDI) *provably* produce redundancy collapse and a unique-information spike? Only if the estimand is defined correctly. As written, the thesis is under-specified on the one choice that decides everything — the target `T` — and the default reading of that choice is **circular and sign-inverted**.

**What is measured.** Sources `S_i` are the per-modality innovations `y_i = z_i − Hx̂` (crebain `sensor_fusion.rs`: `innovation` L505/L723/L966, and the proposed tap `y = pos − track[0..3]` at L2061), each 3-D Cartesian (radar polar also 3-D). The target is left as "fused state? next-step innovation? ground-truth track?" — these are not interchangeable, and one of them is fatal.

**The circularity theorem.** If `T` is the fused state, the Kalman update `x̂⁺ = x̂⁻ + Σ Kᵢyᵢ` makes `T` a deterministic affine function of the `S_i`. Three consequences follow. (1) `pid3_isx(S; x̂)` then measures the *Kalman gain weighting*, not anomaly: a low-R, high-confidence honest sensor carries high `unique` by construction → false positives on the most trustworthy channel. (2) A *successful* FDI moves `x̂` toward the phantom, so the poisoned channel's MI with the (now corrupted) `T` **increases** and its unique atom **spikes** — indistinguishable in sign from a good sensor. The advertised "unique-info spike → alarm" is self-fulfilling and non-specific. (3) Temporally, the prediction `x̂⁻` is a recursion of past fused state; a persistent attack corrupts `x̂⁻`, the lie enters *all* channels' innovations, becomes **common-mode redundant**, and the signature *inverts* (redundancy rises). This is exactly the lens's "self-consistent-but-false channel shares information with the state it corrupts," realized at the filter-recursion level.

**Correct estimand.** The provable signature of naive FDI is **redundancy / MI-with-consensus collapse of the suspect channel against a reference external to it**, not a unique spike about the fused state. Honest innovations share a common latent `M` (the target's true unpredicted maneuver + common process noise): `yᵢ = hᵢ(M) + νᵢ`, `νᵢ` cross-independent. A naive phantom is `⊥ M`, so `I(y_k; ref) → 0` and `k`'s redundancy contribution collapses. The reference must break circularity: a **leave-one-out consensus** `T_k = robust_combine{y_j : j≠k}`, the LOO fused state `x̂^(−k)`, or the **next-step predictive innovation** (not yet fused). Ground truth exists only offline, for exp0.

**O-information is the wrong primary invariant.** `o_information_discrete` (`invariants.rs` L169, Rosas Ω = (n−2)H_joint + ΣH(Xᵢ) − ΣH(X₋ᵢ)) is a single global, target-free scalar: it cannot *attribute* a channel, and a lone decorrelated channel among four need not flip its sign (Ω stays redundancy-positive). `r̄`/`v̄` (`average_degree_of_redundancy`) return **NaN unless joint_mi > 1e-12** — a live hazard when near-white innovations carry little shared MI. Keep Ω/r̄/v̄ as coarse *secondary* screens; the **primary** estimand must be signed *per-channel* atoms — `pid3_isx` unique/redundancy or `discrete_sxpid_n`'s `SxAtom{informative, misinformative, net}`, whose **misinformative** part `π⁻ = log[P(t)/P(𝔱∩⋃𝔞)]` is literally "this source lied about the target." Rank the most-anomalous channel first.

**Detectability floor (must be disclosed).** Statistics-matching FDI (Ueda & Kwon 2408.10177, per NCP `SECURITY.md`) keeps `y_k` consistent with `M`; then no atom moves and the Mirror is provably blind — the *same* floor that blinds the NIS/whiteness χ² baseline. PID only earns its complexity on **higher-order / non-Gaussian** inconsistency a second-moment test misses; that must be the pre-registered endpoint.

**Required fixes.**
1. Never use fused state (or its update) as `T`; use a LOO consensus / LOO fused state / next-step predictive innovation.
2. Alarm on per-channel **redundancy / MI-with-consensus collapse** (the unshared-with-honest atom), not a unique-spike about `T`.
3. Make attribution per-channel and signed (`pid3_isx` / `SxAtom.net`); demote `o_information_discrete`, `r̄`, `v̄` to NaN-guarded global screens.
4. Short windows + LOO propagation to defeat temporal common-mode inversion; watch the redundancy *trend*.
5. Pre-register the χ² detectability floor and a committed non-Gaussian ΔAUROC ≥ 0.05 win, or drop atom-level claims.

**Residual risk.** Against a non-maneuvering CV target, innovations are near-white and near-independent (little `M` to share, `r̄`/`v̄` → NaN): the detector is weakest exactly when the scene is "boring." Redundancy collapse also cannot distinguish "`k` is the attacker" from "`k` is the lone honest sensor amid three spoofs" (majority-spoof inversion) — PID has no ground-truth anchor. And per prisoma §H2, it measures information *available* in the innovation, not what fusion *causally used*, so an availability-keyed down-weight can misfire.


### Lens 02 — Estimator validity & statistical gates

**Analysis.** The Mirror's alarm — "single-modality FDI produces a redundancy collapse and a unique-information spike" — is a claim about `pid2_isx`/`pid3_isx` atoms estimated from a *finite, real-time* window of Kalman innovations. Those atoms are functionals of the distribution seen only through a KSG/`EhrlichKsg` kNN estimator with its own bias/variance. prisoma's governing rule applies verbatim: a surprising atom is more likely estimator pathology than a threat until Experiment 0 rules it out. So the load-bearing question is not "does the math work" but "is the operating point inside the exp0-validated band?" It is not, and by a wide margin.

Two numbers decide it. pid-rs enforces GO against a closed form **only** under `--strict-gate`, on a curated band of `d=1`, `n=STRICT_BAND_GATE_N=4000`, jointly-Gaussian, moderate-MI systems (`bin/exp0.rs`). Everything else — the default sweep at `n=500`, `dims=[10,64,256]` — is deliberately in kNN breakdown, where PIVOT/NO-GO is the *expected* outcome. crebain fuses at **~10 Hz** (`sensor_fusion.rs` `OMEGA_CT` note, `dt=0.1`). A window holding `n=4000` samples is **400 s (~6.7 min) of stationary target dynamics per modality** — physically impossible against a maneuvering UAS. A tactical 2–5 s window yields **20–50 fused samples**, fewer per modality (radar/DOA/N-view fire sub-10 Hz and event-driven). After Politis–Romano subsampling (halves n) and autocorrelation deflation, effective sample size `n_eff` is **tens**. Meanwhile each modality's innovation is **3-dimensional** (`SensorMeasurement.position:[f64;3]`, diagonal `covariance:[f64;3]`), so `pid2_isx`'s joint term `I(S1,S2;T)` is a ~9-D kNN query and `pid3_isx` worse — 3–9× above the only validated dimension. The Mirror therefore operates permanently ~2 orders of magnitude below the band in `n` and several-fold above it in `d`.

**Concrete findings.**
1. **Alarm ≡ known artifact.** A unique-info spike from KSG underestimating the strongly-dependent joint MI is *the same* signature the exp0 monotonicity counter (`I(S1,S2;T) ≥ I(Sᵢ;T)`) flags as NON-GO (Kraskov 2004 §III; Gao 2015). At `n_eff`~tens, d≥3, an FDI spike is statistically indistinguishable from this bias.
2. **Autocorrelation.** Consistent Kalman innovations are white (that's the NIS baseline), but maneuver/model-mismatch/attack makes them autocorrelated, and 10 Hz sliding windows overlap heavily. exp0's default `block_size=1` (i.i.d.) is valid only for its non-temporal synthetics; the Mirror needs a block length set from the integrated autocorrelation time τ.
3. **Degeneracy.** A phantom emitter holding constant DOA, or a quantized/stalled sensor, collapses the kNN radius → `NumericalInstability`, and `r̄/v̄` return NaN unless `joint_mi>1e-12`. prisoma already measured the invariants exploding out-of-band (r̄≈28.6, v̄≈−26.6 at d=64) — direct evidence the high-d atoms are garbage.
4. **No multiple-comparison control.** Streaming 18–166 antichain atoms across overlapping windows × tracks with no FDR/FWER inflates false alarms without bound.

**Required fixes (ordered).**
1. Collapse each modality to a **scalar whitened innovation** `ε = S^{-1/2}y` (or scalar NIS) so the joint PID lives at d≈2–4, near the only validated band; run per-axis if directionality is needed.
2. Make the **geometry gate mandatory per window** before any atom is interpreted: `intrinsic_dimension_levina_bickel` (k≥3), `distance_concentration_stats` (refuse if `nn_over_pairwise_mean`→1), δ-hyperbolicity; else fall back to discrete `I_min` (`quantize_equal_width`) or MI-only — never pool the two.
3. Estimate τ per window, set moving-block length ≈ τ, compute `n_eff=n/τ`, and **REFUSE** below a preregistered floor.
4. Require the block-subsample CI on the alarm atom to **exclude zero**; apply FDR across streaming windows. Seeded `Jitter`; treat `NumericalInstability`/`NonFiniteInput`/NaN `r̄,v̄` and `bootstrap_instabilities>0` as automatic fail-closed. Benchmark against NIS/whiteness χ² **at the real window budget**; drop the continuous-PID claim if it cannot win there.

**Residual risk.** Even fully gated, most tactical windows will fall to "insufficient evidence" — the Mirror is silent exactly when it is fastest needed; block bootstrap fixes dependence, not the *within-window non-stationarity* of a maneuvering target; T (fused state) is a deterministic function of the same innovations, injecting near-deterministic coupling that inflates redundancy; and a spoof crafted to match scalar-NIS statistics defeats the collapsed 1-D feed (availability-vs-use gap; Ueda & Kwon).


### Lens 03 — Adversary model & adaptive evasion

**Analysis.** The Mirror's thesis is a conditional the spec states as an unconditional: single-modality FDI is "information NOT shared → redundancy collapse → alarm." That holds *only* for injections that fail cross-channel consistency. `isx_redundancy` / the sxpid atoms measure information **shared among channels**, which is agnostic to whether that shared information is *true*. This is prisoma's availability-vs-use gap (§H2) restated as a security boundary: a redundancy-preserving spoof is invisible by construction. The honest adversary model must therefore be graded by how cheaply the attacker can *manufacture* cross-channel agreement, not by injection magnitude.

**Findings.**

1. **Coordinated multi-channel spoof (silent, by construction).** An adversary controlling ≥2 of {vision, radar, acoustic-DOA, triangulated-3D} — e.g. a phased acoustic emitter plus an RF replay, or simply a real decoy drone every sensor sees — injects a jointly-consistent phantom. Redundancy is *preserved or elevated*. The 4-source lattice (`discrete_sxpid_n`, 166 antichains) can localize an anomalous subset only while a majority stay honest; at 2-of-4 compromised the "consensus" is undefined and attribution collapses.

2. **Detector-aware residual shaping (O-information stationary).** The NCP observation plane is world-readable (`…/observation` read-only pub/sub; open realm is unauthenticated), so the adversary sees the same `PidObservation` stream the Mirror consumes and can replicate the statistic exactly — `pid-core` is open, deterministic, `parallel` bit-identical to serial. Shaping an injected residual sequence to hold windowed `o_information_discrete` / `co_information_pairwise` / unique atoms inside the null band is a precomputable constrained optimization: the adversarial-example analog against the detector.

3. **Slow-drift / walking-the-track below window scale.** Innovation is computed against the **pre-update predicted** fused track (emit seam, `sensor_fusion.rs` L2061). A drift slower than the filter's tracking bandwidth is absorbed into x̂; the per-modality residual stays small and white. This is exactly the residual-monitor blind spot NCP `SECURITY.md`:62-86 cites as *provably undetectable* (Ueda & Kwon 2408.10177; Choi & Jang WISA'22). Any signature with characteristic time > window W, or below block-bootstrap resolution, is under the floor.

4. **Attribution inversion in the Mirror's own core case.** Because the reference is the *fused* state, a persistent single-channel injection pulls x̂ toward the phantom via the Kalman gain (`measurement_r_cartesian`, L177). After a few frames the **honest** channels carry the growing, mutually-redundant innovations while the **spoofed** channel shows a small *unique* residual — redundancy-collapse-plus-unique-spike then fingers the honest majority. Fixed target ⇒ the detector misattributes the exact attack it was built for.

5. **Estimator-targeted denial-of-detection.** The geometry gate, `NumericalInstability` on radius collapse, and `r̄/v̄` returning NaN unless `joint_mi > 1e-12` mean the Mirror *abstains* outside the exp0 band. Near-duplicate residuals or inflated effective dimension force silent abstention; if abstention is fail-open it is a free evasion. `pid-core` also applies **no multiple-comparison correction**, so the channel×track×window grid gives cover under the uncorrected false-alarm rate.

**Required fixes.**
- Reframe scope in the spec: detects *uncoordinated, cross-inconsistent, supra-window* single-channel FDI only; **not** an authenticity guarantee and **not** a substitute for per-plane Zenoh ACL + mTLS (NCP P0 / #7).
- Reference each modality against a **leave-one-out fused target T⁻ᵐ** — `average_degree_of_vulnerability(joint_mi, leave_one_out_mis)` already exposes the LOO path — killing the absorption and attribution-inversion flaws (highest-value change).
- **Randomize W and the reference (LOO vs full) per evaluation from a keyed CSPRNG kept off the observation plane;** keep modality trust-weights / a secret residual rotation secret (Kerckhoffs caveat: cost-raiser, not proof).
- Multi-scale windows + published detection floor (min bias-rate/magnitude given W and CI); fail-closed abstention (fall back to NIS baseline + coverage-loss flag) with FDR control across the grid.
- Preregister redundancy-preserving and slow-drift attacks as an acceptance gate; require ΔAUROC over the NIS baseline (prisoma M5 discipline) or drop the screen.

**Residual risk.** Coordinated ≥2-channel and physically-consistent phantom spoofs remain invisible after every estimator fix — only sensor-side authentication closes them. Slow drift below the largest window stays undetectable. Secret-keying degrades on host compromise or behavioral inference. And the advisory down-weight is itself a DoS lever: induced unique-info spikes on a *healthy* channel get it down-weighted, degrading the track — so recommendations need rate-limiting and hysteresis.


### Lens 04 — Baseline justification (earn the complexity)

**The bar.** The Mirror must beat, at *matched false-alarm rate*, four cheap incumbents: (1) per-sensor NIS, `NIS_i = yᵢᵀ Sᵢ⁻¹ yᵢ ~ χ²(3)`; (2) innovation-whiteness / autocorrelation on each channel's residual stream; (3) CUSUM/GLRT on the innovation sequence for slow biases below the per-sample threshold; and — the competitor the design omits — (4) a **cross-sensor pairwise parity residual** (classical analytical redundancy: compare two modalities' measurements of the same target `T`, `zᵢ − zⱼ`, gated by its known covariance). This omission matters, because crebain already *ships* baseline (1): `gated_sq_mahalanobis` (`sensor_fusion.rs:1793`) computes `d² = diffᵀ S⁻¹ diff` and gates at `χ²(3)=11.345` (`MEAS_CLUSTER_GATE`, `sensor_fusion.rs:51`; mirrored by manwe's `CHI2_99[3]`) before every fuse.

**Finding 1 — the headline attacks are already handled cheaply.** Because the association gate *is* a per-sensor NIS test, any *loud* phantom (a DOA or patch-poisoned camera contribution whose innovation against `T` is large) is out-of-gate and never fused; a phantom that spawns its own track is culled by the 3-of-5 M-of-N lifecycle. So the Mirror's *entire* addressable threat space is attacks that already pass `χ²(3)=11.345` — stealthy, in-gate FDI. The two named attacks (phantom acoustic DOA, single-camera patch in N-view triangulation) inject a *mean shift* into one channel's innovation, which a linear parity / cross-covariance residual detects directly. **PID does not beat parity on any first-moment attack**, and does not beat per-sensor NIS on any loud one.

**Finding 2 — PID's non-reducible regime is narrow.** The one thing pairwise parity cannot see is a *≥3-body* dependence-structure change with matched first *and* second moments: a coordinated multi-channel FDI that preserves every pairwise residual yet cannot reproduce the true 3-way redundancy/synergy — the domain of `pid3_isx` / `discrete_sxpid_n` synergy atoms and `co_information_pairwise`. That is the only regime where complexity is earned on *detection*. It presumes both a very sophisticated attacker and an in-regime estimator.

**Finding 3 — in deployment dimensions the estimator is out-of-regime.** exp0's `--strict-gate` GO band is `d=1, n=4000`, i.i.d. The Mirror's joint space is 4 sources × 3-D innovation + 3-D target ≈ 15-D, autocorrelated, at per-frame rates. prisoma's own real-data verdict is **NO-GO** (`r̄≈28.6`, `v̄≈−26.6` at d=64). There the atoms are kNN artifacts — PID cannot be *trusted*, let alone beat NIS.

**Finding 4 — latency.** KSG needs ~10³–10⁴ effectively-i.i.d. samples (block-bootstrap shrinks the effective count further under autocorrelation). At 30–60 Hz that is tens of seconds of window; CUSUM alarms in a handful of frames. For a counter-UAS engagement a correct alarm 60 s late is a miss.

**Required fixes.**
1. Replace the strawman baseline. Bench PID head-to-head against **pairwise cross-sensor parity + CUSUM/GLRT**, not per-sensor NIS. Adopt prisoma's preregistered kill criterion (grandplan §14.1): if parity matches PID within CI, ship parity.
2. Scope the experiment by threat: (a) loud phantom, (b) first-moment-stealthy single-channel FDI, (c) parity-defeating coordinated 2-channel FDI. Primary endpoint `ΔAUROC` over the *best* cheap baseline at matched FAR, committed effect size `≥ 0.05`; secondary endpoint frames-to-alarm.
3. Gate every atom-level claim on exp0 / geometry-gate GO; on NO-GO the DetectionOverlay trust bars fall back to NIS + parity, never PID atoms.
4. Reposition the Mirror as a **≥3-channel attribution / second-opinion** layer over a parity detector — its per-source unique-atom ranking is the genuine UX win — not as the primary detector; benchmark which-channel-is-lying accuracy, not only detection AUROC.

**Residual risk.** Even correctly baselined, the deployment-dimension geometry gate may be permanently NO-GO, so the Mirror reduces to its parity fallback in the field; sensor-side FDI is a fundamental limit (NCP `SECURITY.md:62-86`; Ueda & Kwon 2408.10177) — PID raises the bar to matching joint dependence across ≥3 channels but does not close it; and genuine maneuvers with inter-modality latency skew (acoustic lag vs. radar) will fire redundancy-collapse false alarms in exactly the high-tempo moments trust matters most.


### Lens 05 — crebain fusion integration

**Analysis.** I traced the proposed tap end-to-end against `crebain/src-tauri/src/sensor_fusion.rs`. The read-only-sidecar thesis is architecturally sound: `fusion_process` (lib.rs L582) already runs under `spawn_blocking` (L588) holding the `FUSION_ENGINE` mutex, so a non-blocking `try_send` on a bounded `SyncSender` cannot stall the fuse, and a dropped observation on a full channel is a benign miss. The per-modality residual the Mirror wants is genuinely recoverable: `associate_measurements` clusters co-located same-class returns (`cluster_measurements`, L1831) but `update_track` (L2019) still receives the individual member `meas_indices`, so the loop at L2061 sees each modality separately. That is the correct tap point. But the diff *as written* has three load-bearing defects.

**Finding 1 — the residual is computed against a contaminated state.** The L2061 loop mutates `track` in place: each `self.kf.update(track, …)` (L2067) pulls the state toward the just-applied measurement before the next iteration. Computing `y = pos − track[0..3]` inside that loop means the second modality's innovation is measured against a state already dragged by the first. That destroys the conditional independence PID assumes, and — critically — it diverges from the association gate, which `gated_sq_mahalanobis` (L1793) evaluates against the *pre-update* prior in Step 2. An attacker whose phantom sorts first (low `covariance`, L2054) pre-pulls the state so honest channels look anomalous. **Fix:** snapshot the predicted prior `(state[0..3], pos_cov)` once before the loop and compute every member's `y, S` against that frozen prior — matching `gated_sq_mahalanobis` exactly.

**Finding 2 — dimensionality breaks the estimator trust band.** Each residual is a 3-vector with a 3×3 `S`; a pairwise modality MI is then 6-D ambient with a 3-D target — far outside the exp0 GO band (d=1, n=4000; prisoma is NO-GO by d=64). **Fix:** collapse each modality to the scalar NIS `yᵀS⁻¹y` (χ²(3) under H0) before PID. This keeps KSG/`isx_redundancy` in-band *and* makes the head-to-head against the NIS/whiteness baseline apples-to-apples. Direction is partly lost, so vector residuals stay a research-gated escalation only after a geometry-gate pass on real window data.

**Finding 3 — the R down-weight seam loosens the very gate it should tighten.** The proposed `1/trust[modality]` scaling of `measurement_r_cartesian` (L177) is consumed both at the association/cluster gate (`r_carts`, L1898-1902; `MEAS_CLUSTER_GATE`=11.345, L51) and at the update R (L2066/2072/2079/…). Inflating R at the gate *enlarges* a suspected modality's acceptance ellipsoid — a spoofed channel associates **more** easily. **Fix:** apply the down-weight only to the update-stage R (Kalman gain), never to the association/cluster gate. Additionally, because a down-weighted honest sensor's innovations then grow (state ignores it), the trust loop is positively unstable; bound the factor and decay it back to 1.0 so each modality is periodically re-tested, and compute Mirror residuals against the trust-*independent* prior.

**Required fixes.**
- Freeze the pre-update prior; compute all cluster residuals against it (gate-consistent).
- Emit scalar NIS per modality; reserve vector residuals for a geometry-gated escalation.
- Down-weight update R only, bounded and decaying; keep the association gate untrimmed.
- Align windows on frame `timestamp_ms`/seq per `track_id`, require ≥ n_min co-occurring frames per modality pair before scoring, add seeded `Jitter` (dt=0 replay frames, L1698, otherwise collapse the kNN radius) and block-bootstrap CIs.
- Plumbing: create the channel + spawn the drain thread in `.setup()` (L724, where `AppHandle`/`Emitter` exist — `fusion_process`/`fusion_init` carry no handle); emit the numeric id, not the `format!("TRK-{:05}")` String (L2166), to avoid a per-measurement heap alloc.
- DetectionOverlay.tsx: render trust bars as a sibling layer, not inside `drawDetectionBox`; keep `pointer-events-none`; label "advisory".

**Residual risk.** A slow-drift, persistent spoof is absorbed into the fused target T, so over a window the honest modalities look non-redundant and attribution can *invert* — the prisoma availability-vs-use caveat made concrete. Single-modality tracks have no cross-sensor window by construction and are simply out of scope. Asynchronous sensor rates can starve n below the trust band, forcing an honest "insufficient support" over an alarm.


### Lens 06 — Real-time systems & performance

**Analysis.** The Mirror's cost is dominated by the pid-core kNN kernels, which are
brute-force by design. `ksg_local_mi_terms` (`ksg.rs:105`) is a genuine `O(n²)`
double loop over samples — an inner distance sweep, an `O(n)` `select_nth_unstable_by`
for the kth radius, then a second `O(n)` neighbor-count pass — so roughly two `O(n²)`
passes per MI term, parallelized across `i` via rayon `map_index_ordered` (`par.rs`).
A full `pid3_isx` window is that MI cost plus the ISX disjunction radii and per-antichain
counts, and the validity gate adds two more brute-force `O(n²)` passes
(`distance_concentration_stats`, `intrinsic_dimension_levina_bickel`, both flagged in
`geometry.rs` as "Experiment-0-scale" only). Call it ~8–10 `O(n²)` passes for one
trusted point estimate. Trust then requires a block-bootstrap CI at the documented
default `n_boot = 200` (`bootstrap.rs:54`), which re-runs the whole estimator per
resample — a ~200× multiplier — and this is *per track*.

**Findings.**

1. **Window-fill latency, not CPU, is the binding constraint.** The estimator is
   trustworthy only in the exp0-validated band (strict GO ⇔ `d=1, n=4000`); the `n=500`
   default deliberately enters kNN breakdown. The i.i.d. gate forces you to *decorrelate*
   innovations before counting them, so the effective sample rate is a fraction of the
   raw sensor rate (acoustic DOA is the slow channel). Even at an optimistic ~10 effective
   Hz, `n=4000` is a ~400 s fill and `n=500` is ~50 s. The first trusted estimate cannot
   exist before that window fills — an order of magnitude slower than a counter-UAS
   engagement (seconds). The Mirror cannot be the fast alarm.

2. **CI-bearing throughput is sub-Hz.** At the strict `n=4000`, one `O(n²)` pass is ~1.6e7
   pairs; ~10 passes × 200 bootstraps is ~2000 passes ≈ tens of seconds of CPU *per track
   even on 8 cores*. At the (untrusted) `n=500` it is ~0.5–1 s/track. Cost scales linearly
   with active track count — and phantom-track injection, the very threat, multiplies
   tracks, so compute blows up exactly under attack.

3. **Hot-path isolation is genuinely sound.** `fusion_process` (`lib.rs:583`) runs on a
   Tauri `spawn_blocking` task under the global `FUSION_ENGINE` mutex; the proposed tap is
   a non-blocking `try_send` on a bounded channel. A read-only observation-plane subscriber
   plus bounded `try_send` means the Mirror can drop work but can never stall fusion. That
   guarantee holds — *provided* the Mirror never shares that mutex or that blocking pool.

4. **Backpressure drops are not missing-at-random.** `try_send` sheds load precisely during
   innovation bursts (maneuvers, spoof onsets) — biasing the window against the samples that
   matter, silently.

5. **No incremental path.** With no kd-tree/ANN, sliding the window by one sample invalidates
   neighbor radii globally; there is no cheap streaming update — only stride recompute.
   Memory, by contrast, is a non-issue: an `n×d` f64 ring per (track, modality) is ~128 KB at
   `n=4000, d=4`, a few MB fleet-wide, and `nn.rs` already reuses scratch.

**Required fixes.**

- **Split the clock.** The cheap per-sample NIS / innovation-whiteness χ² baseline owns the
  latency-critical alarm at fusion rate; the Mirror runs on a slow stride (one estimate per
  ~1–5 s) purely as a background *attributor*. Do not gate its latency to the engagement.
- **Budget the estimator.** Pin `n` to the exp0 band, expose `n_boot` as an explicit
  CPU-budget knob, run on a dedicated size-capped rayon pool (never the fusion
  `spawn_blocking` pool), and **round-robin across tracks under a fixed per-tick budget** so
  track count cannot drive latency.
- **Surface backpressure.** Count `try_send` drops; mark any window that lost samples as
  low-confidence/invalid rather than emitting a clean "all-clear."
- **Tag every emission** with window-age, validity-gate result, and CI; never auto-apply a
  stale trust down-weight into `measurement_r_cartesian` — recommend only.

**Residual risk.** Even fully parallelized, a trusted CI-bearing `pid3_isx` at the strict band
is sub-Hz per track, and window-fill latency (tens to hundreds of seconds) is irreducible
without abandoning the i.i.d./bootstrap trust regime — so a transient single-frame patch or
brief DOA spoof can enter and leave inside one window and never move the redundancy statistic.
There is no path to shrink the `O(n²)` constant without leaving the only estimator exp0 has
validated (an external ANN would break the Chebyshev/geometry-gate coupling). The Mirror is a
forensic confirmer, not a real-time detector; any program expectation of alarm-grade latency
from this screen is unmet.


### Lens 07 — Detection theory & operating point

**Analysis.** The Mirror produces a *trace* — per-window scalar estimates (per-modality `unique_s1`/`unique_s2` from `pid2_isx`, `r̄`/`v̄`, co-information, O-information) — and the entire operational value hinges on the unspecified step that turns that trace into an alarm and then into a `measurement_r_cartesian` down-weight. That step is where cross-sensor consistency monitors usually die, and the current design leaves it blank. Three problems dominate.

*(1) The operating point may be empty.* pid-rs kNN estimators are only trustworthy in the exp0 GO band (jointly-Gaussian, `d=1`, `n=4000`), require i.i.d. samples (autocorrelation biases the estimate — the brief mandates `Subsample`/block-bootstrap), and return NaN outside the geometry gate or when `joint_mi ≤ 1e-12`. A trustworthy `Unq` atom therefore needs a window of thousands of *effectively independent* innovation tuples. But the damage horizon is short: with the association gate at χ²(3)=11.345 and a 3-of-5 confirm lifecycle (`min_confirmation_hits`/`confirmation_window` in `sensor_fusion.rs`), a phantom DOA can walk or capture a track in a handful of fusion frames. If the window `W_valid` needed for a tight `block_bootstrap` CI on `Unq` exceeds `W_damage`, the detector alarms after the corruption is already fused. This chain — window length → CI half-width → minimum detectable unique-info (MDE) → detection delay — is never closed. It must be, first, before any alarm logic is built.

*(2) Redundancy collapse is necessary but not sufficient for FDI.* The thesis ("info not shared → unique spike → alarm") has a fatal confound: benign events produce the identical signature. A hard evasive maneuver flips the IMM to `CoordinatedTurnFilter` and desynchronizes per-modality residuals against a lagging motion model; an occlusion drops a camera from N-view triangulation and inflates that channel's innovation; a jammed RF/radar dropout mechanically collapses shared information (and sends `r̄`/`v̄` to NaN). All three raise a per-channel `Unq` spike with no adversary present. A single-atom threshold cannot separate "spoofed" from "degraded."

*(3) Wrong statistic, wrong FAR currency.* A per-window threshold has no memory and will flap on estimator variance; a per-window α of even 1e-3, sampled every tick across 4 modalities × N tracks with no multiple-comparison correction (pid-rs ships none), yields an unusable false-alarm rate. SPRT is ill-posed — the attacker chooses the unique-info magnitude, so there is no parametric H1.

**Required fixes (ordered).**

1. **Close the operating-point feasibility chain first.** Empirically show the `block_bootstrap` (Subsample) CI half-width on `Unq` at `W ≈ W_damage` is below the MDE. If `W_valid > W_damage`, pivot to `discrete_sxpid`/MI-only screening (lower `n`) — do not build alarm logic on an infeasible estimator.
2. **Nonparametric CUSUM / window-limited GLR** on a studentized per-modality `Unq` (z-scored against a permutation/block-bootstrap null), calibrated to a target **ARL0** (mean time between false alarms per track-hour), not a per-window α. CUSUM's persistence bias rejects transient maneuvers by construction; SPRT only if a minimum-detectable-effect H1 is fixed.
3. **Condition the alarm on benign-decorrelation covariates already on the bus** — IMM mode-probability, per-channel covariance inflation / measurement availability (occlusion, dropout), GDOP, jam/SNR flags. Alarm only on a `Unq` spike *unexplained* by a co-occurring nuisance, and add a co-onset discriminator: a maneuver is a transient, correlated spike across *all* channels; FDI is a *sustained* unique on *one*.
4. **M-of-N dwell/hysteresis** mirroring the crebain lifecycle (3-of-5), asymmetric on raise vs. restore, gating the R-inflation — but bounded above by `W_damage` (fix 1).
5. **Matched-ARL0 partial-AUC / detection-delay benchmark** vs. the per-sensor NIS χ² whiteness baseline on identical data, in the low-FAR regime only; preregister a minimum win (ΔpAUC ≥ 0.05 or a detection-delay reduction) as the earn-its-complexity gate. Isolate the regime where the phantom passes χ²(3) per-channel but is cross-inconsistent — the only place the Mirror can beat NIS.
6. **FDR/FWER control** across the modality × track grid, or the per-track ARL0 collapses.

**Residual risk.** A matched stealthy FDI (Ueda & Kwon 2408.10177) can be crafted cross-channel-consistent, holding `Unq` below the MDE — the Mirror raises attacker cost, not a guarantee. Regime-conditioning (fix 3) opens a *masking* attack: inject during an induced maneuver/occlusion so the nuisance gate suppresses the alarm. And the ARL0 is only as good as the regime its null was measured in — a non-stationary scene silently invalidates the calibrated false-alarm rate. Given `calibrated_posterior=false`, flapping alarms invite operator fatigue; the dwell is a trust requirement, not only a statistical one.


### Lens 08 — Provenance & honesty boundary

**Analysis.** The haldir catalog enforces one load-bearing invariant: every module self-classifies as either a *detector* (observes and alarms — Palantír-Seal, Rúmil, Warden's-Eye residual) or an *enforced gate* (withholds actuation — Haldir Gate, Fëanor's Mark, Watchword), and the advisory ones repeat a discipline verbatim: "recommend, never silently force" (Rúmil), "flag-not-fully-attribute" (Nénya M3). The Mirror declares itself advisory (`calibrated_posterior=false`, no gate). Philosophically it is in the right class. The danger is that its *mechanism* — the trust-map down-weight into `measurement_r_cartesian` (`sensor_fusion.rs:177`), scaling each `r_cart` by `1/trust[modality]` **before** association — is genuinely in-path and upstream of two enforced gates: the χ²(3)=11.345 Mahalanobis association gate and the 3-of-5 M-of-N `min_confirmation_hits` lifecycle. Unlike every other detector, which sits downstream of enforcement or off-path, the Mirror can bias what the enforced gate sees. An unbounded `1/trust` as `trust→0` sends `R→∞`, Kalman gain→0, and pushes a corroborated measurement outside the association gate — the target never confirms. That is a *silent kill-switch* wearing an advisory label. "Recommends, not silently vetoes" is currently rhetoric, not a mechanical property.

**Findings.**
1. The R-inflation seam can veto a modality. It composes multiplicatively with Nénya's GNSS trust write to the same choke point; two bounded factors can still product to zero a channel.
2. A unique-information spike does **not** certify *which* sensor lies. Per the prisoma availability-vs-use gap (§H2), it is equally consistent with (a) a spoof, (b) a genuinely unique true detection (acoustic bearing the cameras cannot see), (c) legitimate sensor heterogeneity, or (d) a kNN artifact outside the exp0 band. The Mirror must never render "SPOOFED".
3. There is no first-class *no-verdict* state. When the geometry gate fails, the exp0 low-d band is exceeded, or the block-bootstrap CI straddles the null, a trust number is an estimator artifact, not evidence.
4. UI risk: a red/green trust bar beside `DetectionOverlay.tsx` reads identically to Palantír-Seal's enforced `TrustBadge` and Haldir/Fëanor `VETO` — the operator over-trusts an advisory as a gate.
5. Publishing the advisory on the free observation plane leaks the detector's own sensitivity boundary to any observer, letting a stealthy injector tune under the redundancy-collapse threshold.

**Required fixes.**
- **Bound the down-weight so it can only soften.** Clamp `trust ∈ [t_min, 1]` with `t_min` chosen so the worst-case inflated `R` still admits a corroborated measurement through χ²(3)=11.345 and cannot starve 3-of-5. Route *all* trust writers (Mirror + Nénya) through one monotone, floored, audited arbitration point. Anything past the soft bound requires an explicit operator/supervisor ack — Rúmil's grant-gated recommend, Nénya's supervisor-gated HOLD.
- **Forbid certified attribution.** Emit a per-channel "uncorroborated-information" advisory only; adopt Nénya's flag-not-attribute wording. State the four-way ambiguity on the tin.
- **Make estimator-validity a wire state.** Every gate-failing window emits `verdict=insufficient-confidence` with `calibrated_posterior=false`, `gate_passed`, and the CI — never a number. UI renders a greyed "no verdict", never default-green/red.
- **Distinct advisory idiom + provenance.** A "cross-sensor corroboration" meter, an explicit "ADVISORY — not a gate" caption, no shared pass/fail colour with enforced badges. Echo NCP provenance (`is_simulation_output`, `calibrated_posterior=false`, driving `SensorFrame.seq`); log every advisory, resulting down-weight, and human ack to Border-Muster.
- **Scope the FDI claim and gate on the baseline.** State it detects only redundancy-breaking single-channel injection and is blind to residual-aware/coordinated FDI (Ueda–Kwon). Ship disabled until it beats the NIS/whiteness χ² baseline by the pre-registered ΔAUROC ≥ 0.05.

**Residual risk.** Even bounded, a persistent down-weight on a healthy-but-heterogeneous channel is a soft denial-of-track; unsigned `PidObservation` tap frames let a second attacker make the Mirror cry wolf; and the "Nénya = the Mirror" naming collision in the catalog is itself a provenance hazard for the shared trust seam.


### Lens 09 — EW / operational context & operator UX

**Verdict: needs-hardening.** The Mirror's physics is sound but its operational framing is not yet honest about electronic warfare. As specified, the core alarm — a redundancy collapse plus a unique-information spike — fires *identically* for the case it wants (a single channel spoofed) and the case it will actually see far more often in combat (a single channel jammed). Both events decorrelate one modality's innovation residual from its peers. The detector cannot tell them apart from the cross-channel statistic alone, and until it can, the trust bars it renders beside `DetectionOverlay.tsx` will mean only "a channel is misbehaving" — which the operator already knows from the cheap per-sensor NIS/whiteness baseline the Mirror is required to beat.

**The jam-vs-spoof confound is the central finding.** A *jammed* acoustic array produces incoherent, high-variance, non-white residuals — or drops out entirely, emptying the per-modality window so the KSG estimator has no samples. A *spoofed* channel (the phantom DOA from a phased emitter) produces a clean, low-variance, internally *coherent* residual that passes its own NIS gate (Ueda & Kwon 2408.10177; the exact FDI that residual monitors provably miss) yet disagrees with the geometry vision and radar see. That difference is the discriminator, and the Mirror must encode it as its primary output — a 2×2 over {cross-channel redundancy intact/collapsed} × {per-channel NIS coherent/blown}. Only *collapse + coherent-NIS* attributes **spoof**; *collapse + blown-NIS/dropout* attributes **denial**, which warrants a down-weight but never an injection accusation.

**The estimator abstains exactly when the operator needs it.** pid-rs is trustworthy only in the exp0 GO band (`bin/exp0.rs`: i.i.d., low-dimensional, adequate `n`). Active EW violates every premise: dropout collapses `n`; jamming makes residuals bursty and autocorrelated (widening `block_bootstrap` CIs); asymmetric availability flips the computation between `pid3_isx` (3 sources) and `pid2_isx` (2 sources), whose atoms are not comparable, so a "redundancy collapse" can be pure source-count arithmetic. The honest consequence is a **three-plus-state trust bar** — TRUSTED / SUSPECT-INJECTION / DENIED-DEGRADED / **UNKNOWN-ABSTAIN** — wired to the geometry gate, the bootstrap CI, a minimum-sample floor, and source-count changes. Under-sampled or out-of-band windows must render as a distinct ABSTAIN glyph, never green.

**Severe false positive for this app: the low-observable FPV.** A radar-dark, acoustically-masked electric quad is *designed* to be single-modality; its vision residual carries unique information about `T` precisely because nothing corroborates it. The Mirror's "unique = injection" thesis flags the most dangerous real target as a spoof. The tool is a **corroboration meter, not a lie detector** — it must say so, show *which* peers disagree, and let the operator keep an uncorroborated track.

**Required fixes (ordered):**
1. Add the jam/spoof 2×2 by fusing the cross-channel PID with the per-channel NIS baseline; make the 2×2 the operator-facing product, not the raw eight atoms.
2. Explicit ABSTAIN trust state, fail-closed, wired to the pid-rs geometry/CI/sample gates and to source-count changes.
3. Palette orthogonal to `THREAT_LEVEL_COLORS` (types.ts:276) — never reuse the getThreatLevel green/amber/red, or a suspect-channel bar and a level-4 severe-threat box collide.
4. Global channel-health state (per modality: LIVE/DEGRADED/DENIED) resolved *before* per-track attribution; suppress per-track spoof flags on a denied channel to avoid a wall-of-red during the raid; down-weight once via `measurement_r_cartesian` (L177).
5. BH-FDR across the live track×modality grid each frame (pid-rs has no multiple-comparison correction) and a bounded compute budget that degrades to NIS-only under load with a visible "reduced mode" tag, so bars never go stale-but-confident.

**Scenario walk (phantom DOA + FPV raid).** T0: three channels agree, all bars green, threat 3 legitimately. T1 phantom seeds an acoustic-only track — but with one source there is no cross-channel PID; the estimator abstains and the bar reads "uncorroborated, acoustic-only," which a trivial modality-count heuristic gives for free (PID adds nothing here). T2 phantom biases a *real* co-associated track (inside the χ²(3)=11.345 gate): acoustic NIS stays nominal, cross-channel redundancy drops — **this is the only band where the Mirror beats the baseline**, and it recommends inflating acoustic R so fusion holds the true raid axis. T3 the swarm's own jamming degrades acoustic globally: without fix #4 every acoustic bar reddens at peak cognitive load. Net: the operator wants one per-track corroboration glyph and a channel-health strip, and must be warned the atoms are advisory (`calibrated_posterior=false`) and out of the effector-cue path.

**Residual risk.** A coordinated two-channel spoof (phantom DOA plus an adversarial-patch camera triangulating to the same phantom point) raises redundancy and greenlights the phantom — out of scope by construction, so a green trust state under active EW is not proof of authenticity. And the "coherent single-channel bias, co-associated with a real track, all channels healthy" band where the Mirror earns its complexity is genuinely narrow; the program must confirm that window is wide enough to justify instrumenting the fusion hot path.


### Lens 10 — Evaluation & validation plan

**Analysis.** The good news first: the substrate a preregistered validation needs already exists. `manwe/python/src/manwe/fusion/scenarios.py::make_scenario` emits seeded ground-truth target trajectories plus noisy, cluttered, partially-detected multi-sensor `frames` (per-modality `MODALITY_NOISE`, `p_detect`, `clutter_rate`), and `fusion/metrics.py::ospa` scores reconstruction. `pid-runlog::RunLogWriter` gives byte-reproducible artifacts, `exp0.rs` gives a GO/PIVOT/NO-GO gate, and NCP frames carry `contract_hash` + `is_simulation_output=true` + `seq` for join-on-`seq` provenance. A prisoma-style plan (§14.8: one primary endpoint per hypothesis, predicted sign, BH-FDR, ex-ante regime selection, simulation-based power as a capture gate) is buildable on these. The bad news is that as described the plan is not yet *sound*, for four concrete reasons.

**Findings.**

1. **The baseline the Mirror must beat does not exist.** `grep` over `crebain/src-tauri/src/` for NIS / whiteness / χ² innovation tests is clean. You cannot run a head-to-head against an unimplemented comparator. Fortunately the baseline is nearly free and *shares the exact inputs*: NIS = `yᵀS⁻¹y ~ χ²(3)` computed from the same `PidObservation{innovation:y, s:S}` tap. Same seed, same scenario, same tap — only the statistic differs, which makes the contest cleanly controlled. Build it first.

2. **The window is the primary validity axis, not a knob.** Detection latency ≥ window length *by construction*, while the continuous pid-rs estimators are trustworthy only at low-d, i.i.d., large-n. At `dt=0.5s` a 10 s window is ~20 innovation samples — below prisoma §9.0's "not estimable at tens" and orders below exp0's strict-band `n=4000`. NIS, by contrast, fires per-sample. So the Mirror carries a structural latency handicap and a structural sample-starvation problem simultaneously; the window ablation is a Pareto frontier (latency × estimator validity × ROC-AUC), gated per-point by the Exp0 invariant checks (monotonicity, `r̄`/`v̄` bounds, Levina–Bickel ID, distance-concentration) run on the *actual* Mirror feature vectors — not accepted as a knob.

3. **Uncontrolled multiple-comparison surface.** pid-core applies "no multiple-comparison correction." Fishing across 18 (`pid3_isx`) or 166 (`discrete_sxpid_n`) antichains × sliding windows × modalities × scenarios makes "false-alarm rate at fixed threshold" meaningless. One primary composite statistic must be preregistered (e.g. windowed redundancy-collapse `Δr̄`, or max per-source `Unq` atom), the rest demoted to exploratory-with-FDR.

4. **Sim-to-integration gap.** Injecting into manwe's Python tracker validates the wrong stack. Injections must flow through crebain's shipped tap (`MultiSensorFusion::update_track`, pre-update residual `y=pos−track[0..3]`, `S=pos_cov+measurement_r_cartesian`, H=[I|0]).

**Required fixes.**
- Implement the NIS/innovation-whiteness baseline from the `PidObservation` tap **before** any Mirror scoring; it is also the falsification yardstick.
- Preregister one primary statistic and one endpoint per injection class: paired ΔROC-AUC vs NIS at matched false-alarm-rate **and matched latency**, predicted > 0, committed minimum effect ΔAUROC ≥ 0.05 (reuse prisoma's sizes; `|ρ|≥0.3`, `τ̄≥1/3` for latency/attribution); BH-FDR across the injection grid.
- Map+gate the window/latency/n frontier with the Exp0 invariant+geometry gate and moving-block-bootstrap CIs (`RowResampleScheme::Subsample`) on real feature vectors.
- Port `make_scenario` `frames` into crebain `SensorMeasurement`; run the red-team library (phantom DOA, patch-poisoned triangulation, replay) through the actual tap; pin pid-core v0.4.0 by `contract_hash`; seed everything.
- Write the quantitative ABANDON contract (negative-result-first): (a) Mirror fails to beat NIS by ΔAUROC ≥ 0.05 at matched FAR+latency → ship NIS, drop PID; (b) Exp0 NO-GO at operating window **and** discrete `I_min`/SxPID also fails → drop continuous atom attribution; (c) attribution ≤ chance (1/#modalities) → kill "which-channel"; (d) median latency > 3-of-5 M-of-N horizon → advisory is post-hoc, re-scope.

**Residual risk.** Even a passing synthetic validation cannot cover *optimal-stealth* FDI shaped to preserve the residual distribution (Ueda & Kwon 2408.10177) — it defeats NIS and the Mirror alike, so a red-team library of naive injections will overstate detectability. The availability-vs-use gap (prisoma §H2) means a redundancy signature need not track what the fused estimate *causally used*. And if the continuous regime is permanently NO-GO at useful latencies, the discrete fallback changes the measure (`I_min ≠ I^sx`), so a discrete pass does not validate the continuous thesis.


