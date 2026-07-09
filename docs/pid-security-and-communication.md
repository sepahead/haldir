# Partial Information Decomposition across the ecosystem — security & communication

## Why PID here

Partial Information Decomposition (PID) takes the mutual information that two or more sources carry about a target and splits it into operationally distinct atoms: **redundant** information (present in either source alone — the corroborating overlap), **unique** information (carried by exactly one source and no other), and **synergistic** information (present only in the *joint* observation, invisible to any source in isolation). The canonical synergy example is a parity relation `Z = X ⊕ Y`: `X` and `Y` are pairwise independent of `Z`, yet together they determine it completely. This is not a statistical curiosity. It is the exact shape of two engineering problems this ecosystem faces every day — a bearing-only sensor and a range-only sensor that jointly localize a target neither can fix alone (synergy you must not split), and a covert channel deliberately built to be pairwise-decorrelated so first-order monitors see nothing (synergy that is the attacker's fingerprint).

The ecosystem is unusually well-positioned to exploit this because it owns *both* ends of the pipeline. On one side, **manwe** and **crebain** provide a real multimodal fuser — SRP/GCC-PHAT acoustic DOA, N-view triangulation, radar range, and a Kalman/EKF/UKF/IMM tracker whose per-measurement innovation `y = z − Hx̂` and covariance `S` are the natural per-modality feature and the natural value-of-information statistic simultaneously. On the other side, **pid-rs** (`pid-core` v0.4.0) is a bit-reproducible PID library: continuous `I^sx` estimators (Ehrlich-KSG), discrete Williams–Beer `I_min` and signed SxPID, target-free O-information/co-information screens, and — critically — a battery of validity gates. The **NCP** bus makes the whole thing observable for free: its pub/sub Observation plane lets a monitor attach read-only, and its `seq`-echo design lets a split-plane observer join a `CommandFrame` to its driving `SensorFrame` by identity rather than arrival time.

The discipline that makes any of this trustworthy is inherited from prisoma. Continuous `I^sx` is a *functional of the distribution* seen only through a finite-sample kNN estimator with real failure modes, so every continuous result must pass Experiment 0 (`exp0 --strict-gate`, GO only certified in the analytic Gaussian band at **d=1, n=4000**) and the geometry gate before its atoms mean anything. High-dimensional embeddings are a documented **NO-GO** (r̄≈28.6, v̄≈−26.6 at d=64) — the gate working, not a bug. `calibrated_posterior=false` is the standing posture: no atom is interpreted on real data pre-gate, and continuous `I^sx` atoms are never pooled with discrete `I_min` atoms. Above all we apply one rule everywhere: **would a cheaper statistic do?** PID earns its complexity only where a marginal correlation, a scalar conditional MI, or an activation-norm OOD monitor provably cannot see the thing that matters. Several ideas below survive because the answer is no; others are demoted to the sliver where PID is irreducible.

---

## A. Security applications

The flagship security system is **Galadriel's Mirror** (see `docs/galadriels-mirror.md` and its ten `mirror-lenses/`), the electronic-warfare PID monitor that watches redundancy/synergy structure between command and sensor streams. The applications here are its siblings and specializations; we do not duplicate the Mirror, we place the other security uses around it.

### A1. Synergy Sniffer — covert exfiltration across telemetry fields that should be independent

**Mechanism.** Sources `X₁…Xₙ` are a panel of quantized telemetry fields the plant model says are marginally independent: low bits of position, confidence, inter-arrival time, a rarely-used metadata integer, per-modality innovation magnitude. There is **no target** — this is a structure screen. On clean telemetry, O-information and pairwise co-information sit near zero. A covert channel that parity-encodes exfil data into two fields drives the pair *synergy-dominated* (co-information flips negative) while leaving pairwise correlation at zero. The carrying signal is negative co-information; signed `discrete_sxpid3` net-synergy is a post-hoc characterizer, not the detector.

**Ecosystem hook.** The NCP Observation plane's `BulkBlock` columnar codec (`ncp-core/src/bulk.rs`) already exposes self-describing f32/f64/i32/i64 columns of `times`/`values`/`senders` — a parse-free panel of exactly the fields to screen, read-only and off the hot loop.

**Payoff.** Catches exfiltration that pairwise-correlation, compression-ratio, and scalar-MI monitors miss *by construction*, because a competent attacker decorrelated the marginals; synergy is the residual they cannot suppress without surrendering joint-encoding capacity. The whole path is discrete `I_min`/co-information — no kNN — so it sidesteps the continuous-estimator validity question entirely and needs no exp0 GO.

**Honest limits.** The load-bearing statistic is co-information/O-information, one of the cheapest multivariate tests — *not* the SxPID atom, and the "target-free SxPID" framing is false (`discrete_sxpid3` requires a target, forcing an unstated pseudo-target choice, so it is characterization only). The synergy-unique win is real but narrow: it needs ≥3 *jointly observed* fields bound by a full-entropy parity relation; a low-entropy or slowly-varying payload collapses to a pairwise-detectable signal (cheaper MI catches it), and a high-entropy payload whose parity partner is *unobserved* is invisible to any observed-variable synergy. Plug-in entropy is biased away from zero, so finite-N co-information is systematically positive on clean data — the two-`num_bins` robustness check catches binning artifacts but not sampling bias. And pid-rs applies **no** multiple-comparison correction, so the screen must be wrapped in a permutation null (shuffle one field to kill 3-way structure while preserving marginals) feeding BH-FDR, with arity capped at 2–3 fields.

**MVP.** Select 4–6 independent numeric columns from a clean `BulkBlock` capture, `quantize_equal_width` at low `num_bins`, record baseline O-info/co-info bands; on live traffic flag any pair/triple whose co-information flips synergy-dominated under a permutation-null BH-FDR, re-run at two `num_bins` to reject binning artifacts, and characterize survivors with signed SxPID.

### A2. VLA policy-backdoor / trojan-trigger structural detector (prisoma)

**Mechanism.** Sources `S₁ = V` (vision), `S₂ = L` (language/instruction), optionally `S₃ = D` (world-model/hidden-state); target `T = A` (action token / low-d action projection). A clean policy corroborates V and L redundantly before acting; a trojan installs a covert V→A pathway. The signal is `ΔUnq(V;A)` triggered-minus-clean corroborated by a drop in `R(V,L;A)`; for a world-model tamper the irreducible atom is `Syn(V,D;A)` (prisoma H7b) — synergy that lives only in the joint `(V,D)` and no marginal or pairwise statistic can see.

**Ecosystem hook.** prisoma's `(V,L,D,A)` attack-surface reading; H3 matched-strength interventions as the perturbation-budget-matched adversarial map; **engram** stores clean per-episode atom profiles as the behavioral baseline the runtime departs from.

**Payoff.** Detects a trigger-activated backdoor by its structural fingerprint *without knowing the trigger a priori*, where input-space anomaly detectors see no OOD input, and localizes the compromised modality by which atom shifted.

**Honest limits.** Two hard problems. First, the estimator is **NO-GO** at raw VLA embedding scale, so the only legal path is PLS/PCA to d≤4 or discrete SxPID on quantized axes — but a stealthy trojan is engineered to be low-salience, and a variance-maximizing PCA will discard exactly the low-variance covert channel. The method is null by construction unless the MVP *first* proves the projection preserves an injected known covert channel. Second, the headline `ΔUnq(V;A)` has a cheaper twin: on triggered rollouts L is clean, so a covert V→A pathway is a rise in scalar conditional MI `I(V;A|L)`, which is low-dimensional and kNN-cheap. This should be re-scoped to a **≥3-body attribution / second-opinion** layer (where `Syn(V,D;A)` is genuinely irreducible), not a primary detector, and must beat STRIP/activation-clustering/spectral-signature scanners *and* the paired-ΔCMI baseline by a preregistered ΔAUROC ≥ 0.05 or be killed. Availability-vs-use (H2) is decisive: PID sees info available, a backdoor *uses* a pathway. The D-axis needs real VLA internals prisoma has not yet captured.

**MVP.** Offline, known-triggered vs clean rollouts; PLS-project V,L to d≤4, prove the projection preserves an injected covert channel, run geometry gate + `exp0 --strict-gate`, compute `ΔUnq(V;A)` and `ΔI(V;A|L)` with `block_bootstrap_paired` CIs excluding zero, require both to beat a STRIP baseline before any runtime monitor.

### A3. Single-point-of-information map (dual-use offline reading)

Not a standalone detector but a security by-product of the scheduler in B1. A modality with high `Unq(V;A)` / high Shannon-invariant vulnerability `v̄` is one whose spoof flips behavior with *no cross-modal corroboration* — a live single-point-of-failure map, computed offline over the same features the QoS scheduler uses, reusing prisoma's `(V,L,D,A)` attack-surface reading. The honest caveat is that a value-of-information scheduler is an **attack amplifier**: residual-undetectable false-data injection (Ueda & Kwon, 2408.10177) can inflate a spoofed channel's apparent unique info to seize scheduling priority and starve the honest corroborators that would expose it. PID measures info *available*, not *used*; the real remedy is per-plane Zenoh ACL + mTLS, not PID. This map is advisory attack-surface cartography, never an enforcement gate.

---

## B. Communication applications

### B1. Value-of-information scheduling under a jammed link

**Mechanism.** When the Zenoh link degrades to a few frames per tick, which modality do you transmit first? Sources `Sᵢ` are manwe's per-modality scalar features (DOA az/el, triangulated 3D point reduced to per-axis, crebain confidence, radar range); target `T` is the next-tick track state. The information-theoretically correct "what do I send next given what I already sent" quantity is **conditional MI** `I(Sᵢ;T | already-sent) = Unq + Syn` — a single greedy-CMI estimate (Krause–Guestrin near-optimal sequential sensor selection) that captures *both* the drop-the-redundant-high-MI case and the keep-the-synergistic-pair case in one shot, with lower variance than a Möbius difference of noisy kNN terms.

**Ecosystem hook.** NCP Action plane (express + RealTime + DROP) and Perception plane QoS scheduling under a jammed link; features from manwe's tracker whose Mahalanobis/NIS gate is simultaneously the VoI signal and the FDI-detection statistic.

**Payoff.** Turns latest-only conflation into VoI-ranked semantic conflation, maximizing information delivered per surviving frame when bandwidth collapses.

**Honest limits.** The PID **unique atom is the wrong member of the family** for this job — it systematically under-counts synergistic modalities, which is why the naive version has to bolt on a "co-schedule the synergistic partner" guard; greedy CMI subsumes both cases and eats even the narrow redundant-modality case where the unique atom would have won. Worse, a *static offline* priority weight cannot see the per-frame VoI spike the pitch advertises (a maneuvering IMM innovation matters exactly when it is non-stationary), and the correct ranking is conditional on which sensors the jam left *alive* this episode — greedy CMI recomputes on surviving frames, a fixed lookup table is blind to the surviving set. And the scheduler is an attack amplifier (see A3). Candid baseline: raw NIS / innovation surprise already prioritizes maneuver frames well at O(1); CMI beats it only on the redundant-but-high-MI frames.

**MVP.** On a two-modality track (DOA + radar range), log scalar features + next-tick state, rank transmission by greedy conditional-MI vs NIS-magnitude over a jamming trace; claim value only if CMI reorders on the redundant-but-high-MI frames with a CI clearing zero. Demote PID proper to the offline SPOF map of A3.

### B2. Synergy-aware semantic conflation for the Perception plane

**Mechanism.** Sources `Sᵢ` are per-modality scalar innovation features from crebain's fusion tap (range-residual from radar, bearing-residual from acoustic DOA, one per modality per track); target `T` is a *delayed* settled track-state increment (the fused estimate a few ticks later, so the target is not the same tick's fusion). The signal is the sign of `co_information_pairwise` (CI₂ = Red − Syn): positive ⇒ redundancy ⇒ droppable, negative ⇒ net synergy ⇒ the pair must ride together as an atomic co-conflation group. This is the one PID niche that is genuinely irreducible: no second-order statistic can see synergy, so per-stream MI would rank bearing-only and range-only as each low-value and shed one — catastrophic.

**Ecosystem hook.** crebain's `PidObservation` `SyncSender` tap (a pure, hot-path-untouched addition to `update_track`), logging per-modality scalar innovations + delayed settled state to a `BulkBlock` ring on the Observation plane; policy computed by a read-only subscriber and applied as a slowly-refreshed co-conflation group table.

**Payoff.** Under bandwidth collapse the QoS layer sheds streams that redundancy proves are corroborated (free bits) while never splitting a synergistic pair, preserving joint localizability. Secondary security payoff: a synergy atom that collapses when a stream is spoofed is a world-model-tamper signal.

**Honest limits.** The original KEEP_LAST(1) framing is **wrong** and is dropped: NCP addresses each modality as its own sub-key, so latest-only conflation keeps the newest frame of *each* key and only drops stale intra-stream frames — it never splits a synergistic pair. The failure mode this actually guards is **stream-level shedding under a bandwidth budget**, a QoS admission-control mechanism that does not exist in NCP today and must be built for this to have a host. Estimand tension: the canonical DOA+range synergy lives in the 2-D angle-radius→Cartesian transform, but the geometry gate forces scalar d=1 per-axis targets, and whether a scalar per-axis increment still exhibits that synergy must be re-argued, not assumed. Sample budget is tight: at 10 Hz, n=4000 is ~6.7 min of stationary dynamics, so a 2–5 s tactical window yields n_eff of order tens after block-subsampling — the offline study builds cleanly, the online policy is throttled to "insufficient evidence" often. Innovations are autocorrelated (maneuvers), mandating block-bootstrap CIs before any drop. Plain pairwise MI already handles the redundancy half; PID earns its keep *only* on the synergy sign.

**MVP.** Add the `PidObservation` tap, log scalar innovations + delayed settled state for one multi-sensor track, offline-compute `co_information_pairwise` + `pid2_isx` with block-bootstrap CIs per modality pair, emit a redundant/unique/synergistic label per pair, and diff against what naive latest-only would have dropped — on a real stream-shedding mechanism, not KEEP_LAST(1).

### B3. Neuro-controller health — synergy/redundancy shift as degraded-mode telemetry (engram)

**Mechanism.** Sources `S₁` = low-d readout of the perception-encoder population, `S₂` = low-d readout of the world-model/recurrent hidden state; target `T` = the actuator `CommandFrame`, joined to the neural readout via the `CommandFrame`→`SensorFrame` `seq` echo. The candidate signal is a shift in the redundant/unique/synergistic profile between nominal and degraded episodes — action becoming *uniquely* determined by one population (world-model bypass, or a population going dark under sensor loss).

**Ecosystem hook.** The NCP `seq`-echo join is exactly the command↔neural coupling this needs and is the one genuinely strong, real part of the idea. As *telemetry* (integrated over whole episodes) it dodges the real-time sample-starvation that dooms online PID.

**Payoff.** A graceful-degradation signal: whether a controller is still doing full sensor+world-model fusion or has dropped to a degraded reflex, letting a collapsed-fusion agent be down-weighted in fleet fusion.

**Honest limits.** Kept as a *forward-looking* item, not a runnable MVP, for three reasons. (1) engram's current controllers are reflex arcs (Braitenberg; pose-error→Poisson→velocity); a distinct world-model population `S₂` does not exist yet, so the two-population MVP is not runnable today. (2) The health *direction* is probably backwards: prisoma's H2 says *redundancy* predicts ablation robustness, and a well-fused predict-then-correct controller is more plausibly redundancy-dominated (Kalman-like, additive) than synergistic, so "synergy collapse = degraded" may be inverted — track both atoms plus the CI₂ sign, do not assume. (3) The headline use (a scalar trust number for fleet down-weighting) is delivered more cheaply by an activation-norm / reconstruction-error OOD monitor; PID's *only* unique contribution is discriminating the failure mode, and the one PID-shaped case (bypass = action available from `S₁` alone) is exactly what availability-vs-use says PID cannot certify. High-d populations are NO-GO, so run discrete `sxpid2` on quantized ≤few-dim projections after a mandatory geometry gate, with the projection choice a standing confound.

**MVP (deferred).** Log 1-D readouts of two populations + scalar action + `seq` over nominal vs sensor-masked episodes, `quantize_equal_width`, compute `discrete_sxpid2` Syn/Unq with a permutation null + block-bootstrap CI — but only once a world-model population exists to read.

---

## Summary table

| Application | PID measure | Sources → Target | Ecosystem hook | Sec / Comm | Cheaper baseline? |
|---|---|---|---|---|---|
| Galadriel's Mirror (flagship) | continuous `I^sx` Red/Syn, command↔sensor | command, sensor streams → track | NCP split-plane `seq` join | Security | See lens 04 — PID only for synergy |
| A1 Synergy Sniffer | `o_information_discrete` + `co_information_pairwise` (SxPID as characterizer) | quantized telemetry panel → none (target-free) | `BulkBlock` columns | Security | **Yes** for lazy channel (gzip/MI); **no** for decorrelated channel |
| A2 VLA backdoor detector | `Syn(V,D;A)` (≥3-body); `ΔUnq(V;A)` demoted | V, L, D → A | prisoma (V,L,D,A); engram baseline | Security | **Yes** — paired `ΔI(V;A\|L)` + STRIP for primary detection; PID only for `Syn(V,D;A)` |
| A3 Single-point-of-info map | `Unq`, `v̄` (offline) | per-modality features → action | prisoma attack surface | Security | Advisory only; real remedy is ACL+mTLS |
| B1 VoI jam scheduler | greedy `I(Sᵢ;T\|sent)` = Unq+Syn (CMI, not unique atom) | manwe scalar features → next-tick state | NCP Action/Perception QoS | Comm | **Yes** — NIS O(1) mostly; CMI only on redundant-high-MI frames |
| B2 Synergy-aware conflation | `co_information_pairwise` (CI₂) + `pid2_isx` | crebain scalar innovations → delayed settled state | crebain `PidObservation` tap | Comm | **No** for synergy sign; yes for redundancy half (pairwise MI) |
| B3 Neuro-controller health | `discrete_sxpid2` Syn/Unq (forward-looking) | two population readouts → CommandFrame | NCP `seq` echo; engram | Comm | **Yes** for scalar trust (OOD monitor); PID only for failure-mode ID |

---

## Cross-cutting caveats

**Estimator validity is the gate, not an afterthought.** Continuous `I^sx` is trustworthy only for i.i.d. samples in low ambient/intrinsic dimension away from near-determinism. Autocorrelation (every tracker innovation under maneuver) biases kNN — use subsample/block-bootstrap, never the naive with-replacement bootstrap. High-d embeddings are NO-GO; project to d≤4 or fall back to discrete PID, and prove the projection preserves the signal you are hunting. Radius collapse on quantized duplicates returns `NumericalInstability` (add seeded jitter), never a wrong finite value. Every continuous claim runs `exp0 --strict-gate` first (GO only at d=1, n=4000, Gaussian), and `calibrated_posterior=false` stands until it passes. Never pool continuous `I^sx` atoms with discrete `I_min` atoms — they are different measures. pid-rs supplies point estimates with *no* multiple-comparison correction, so any screen over many pairs/triples needs your own permutation null + BH-FDR.

**Earn your complexity.** The house rule is that every application must answer "would a marginal statistic do?" and survive it. Redundancy alone is a correlation/pairwise-MI problem — cheaper. Sequential value-of-information is a conditional-MI problem — cheaper than a Möbius difference of unique atoms. A scalar trust number is an OOD-monitor problem — cheaper than a decomposition. PID is irreducible in exactly two places: **synergy** (B2's co-conflation sign, A1's decorrelated channel, A2's `Syn(V,D;A)`), which no second-order statistic can see, and multi-body attribution as a second opinion. Everywhere else, PID is demoted or dropped.

**Adversary adaptivity.** A fixed-arity synergy screen is blind to a channel spread across more fields than the screened arity or run slower than the sampling window. A VoI scheduler is an attack amplifier: residual-undetectable FDI can inflate a spoofed channel's apparent value to seize priority. PID measures information *available*, not *causally used* — the gap attackers exploit — so PID is never the enforcement layer.

**Advisory, not enforced.** Every application here is a read-only Observation-plane monitor or an offline policy engine. None gates the control path. Real security remedies are cryptographic (per-plane Zenoh ACL + mTLS: sensor PUT→body, command PUT→commander); real safety remedies are the `mode`/`ttl_ms` governor. PID is instrumentation and cartography, advisory input to a human or a slow policy refresh — never a fail-closed enforcement gate on the hot loop.

---

## What we rejected and why

- **Target-free SxPID as the covert-channel detector (A1 as originally pitched).** `discrete_sxpid3` requires a target; the truly target-free sufficient detector is O-information/co-information. We kept the idea but demoted SxPID to a post-hoc characterizer and made co-information the detector.
- **The PID unique atom as the online jam-scheduler priority (B1 as pitched).** It under-counts synergy and forces a synergy bolt-on; greedy conditional MI dominates it on its own turf with lower variance. Rebuilt on CMI, PID retained only for the offline SPOF map.
- **The KEEP_LAST(1) framing of semantic conflation (B2 as pitched).** False under NCP's per-modality sub-keying — latest-only never splits a synergistic pair. The idea survives only re-hosted on a stream-level shedding mechanism that must still be built.
- **`ΔUnq(V;A)` as a primary trojan detector (A2 as pitched).** Dominated by scalar `ΔI(V;A|L)`; re-scoped to a ≥3-body attribution second opinion where `Syn(V,D;A)` is irreducible, contingent on a projection-preserves-covert-channel proof and the still-missing D-axis capture.
- **Neuro-controller synergy-health as a shippable MVP (B3).** The world-model population it reads does not exist on today's reflex controllers, the health direction may be inverted (redundancy, not synergy, likely marks robustness), and its headline trust use is cheaper via an OOD monitor. Kept as a forward-looking telemetry item on the strength of the real `seq`-echo hook, not shipped.
