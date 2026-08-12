//! The pure, deterministic, fixed-point policy decision.
//!
//! No I/O, no floats, no allocation beyond the bounded reason vector. All
//! comparisons use checked/widened integer arithmetic; an out-of-range value is
//! never allowed to wrap into an accepted boundary value (punch-list B9). The
//! prospective geofence projection spans exact state-capture time through an
//! upper bound of the published horizon, computed before the effective-validity
//! minimum (B10). This is a configured software envelope, not a physical
//! reachability proof. The slew reference is the last **published** command (H7);
//! measured-state acceleration is a separate vector-norm check against fresh
//! velocity and its uncertainty.

use crate::input::{ActionHistoryError, PolicyInput, ValidatedPolicyInput};
use crate::output::{PolicyDecision, PolicyOutcome};
use crate::policy::{NativePolicyError, NativePolicySnapshot};
use haldir_contracts::action::{ActionClassV1, CoordinateFrameV1, RequestedActionV1};
use haldir_contracts::receipt::DecisionReasonCodeV1 as R;
use haldir_core::snapshot::TrustedStateSnapshotV1;
use haldir_core::time::{MonoDuration, MonoInstant};

const MAX_REASONS: usize = 32;
const NANOS_PER_MILLISECOND: u128 = 1_000_000;
const NANOS_PER_SECOND: i128 = 1_000_000_000;

/// A policy-input failure that prevents a trustworthy authorization decision.
///
/// This is distinct from a normal [`PolicyOutcome::Deny`]: invalid executable
/// policy or malformed accounting state needed for velocity evaluation is an
/// internal failure, not evidence that a controller violated a policy limit.
/// Hold evaluation intentionally does not depend on motion-duty history.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PolicyEvaluationError {
    /// The raw executable policy snapshot is semantically invalid.
    InvalidPolicy(NativePolicyError),
    /// Retained duty or slew-accounting state is malformed.
    ActionHistory(ActionHistoryError),
}

impl PolicyEvaluationError {
    /// Stable machine-readable failure class.
    #[must_use]
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::InvalidPolicy(_) => "POLICY_EVALUATION_INVALID_POLICY",
            Self::ActionHistory(_) => "POLICY_EVALUATION_ACTION_HISTORY",
        }
    }

    /// Stable machine-readable code of the underlying invariant failure.
    #[must_use]
    pub const fn detail_reason_code(self) -> &'static str {
        match self {
            Self::InvalidPolicy(error) => error.reason_code(),
            Self::ActionHistory(error) => error.reason_code(),
        }
    }
}

impl std::fmt::Display for PolicyEvaluationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for PolicyEvaluationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidPolicy(error) => Some(error),
            Self::ActionHistory(error) => Some(error),
        }
    }
}

impl From<ActionHistoryError> for PolicyEvaluationError {
    fn from(error: ActionHistoryError) -> Self {
        Self::ActionHistory(error)
    }
}

/// Evaluate the native mission policy for one intent.
///
/// This compatibility API maps an internal evaluation failure to
/// [`R::DenyPolicyDiagnostic`]. Integrated monitors should use [`try_decide`]
/// so they can report and fault-latch an internal error instead of presenting it
/// as an authorization refusal.
#[must_use]
pub fn decide(input: &PolicyInput<'_>) -> PolicyDecision {
    try_decide(input).unwrap_or_else(|_| deny(vec![R::DenyPolicyDiagnostic]))
}

/// Evaluate a raw native policy, preserving internal evaluation failures.
///
/// # Errors
/// Returns [`PolicyEvaluationError::InvalidPolicy`] for an invalid executable
/// policy. Velocity evaluation returns
/// [`PolicyEvaluationError::ActionHistory`] for malformed retained history;
/// Hold evaluation deliberately remains independent of duty history.
pub fn try_decide(input: &PolicyInput<'_>) -> Result<PolicyDecision, PolicyEvaluationError> {
    input
        .policy
        .validate_for_evaluation()
        .map_err(PolicyEvaluationError::InvalidPolicy)?;
    decide_inner(input)
}

/// Evaluate with a policy whose validation and canonical identity were retained.
///
/// This is the integrated Gate path. Construction of
/// [`crate::ValidatedNativePolicy`] establishes the invariant that lets this
/// function avoid repeated whole-policy validation.
///
/// This compatibility API maps an internal accounting failure to
/// [`R::DenyPolicyDiagnostic`]. Integrated monitors should use
/// [`try_decide_validated`].
#[must_use]
pub fn decide_validated(input: &ValidatedPolicyInput<'_>) -> PolicyDecision {
    try_decide_validated(input).unwrap_or_else(|_| deny(vec![R::DenyPolicyDiagnostic]))
}

/// Evaluate with a retained validated policy, preserving accounting failures.
///
/// # Errors
/// Velocity evaluation returns [`PolicyEvaluationError::ActionHistory`] when
/// retained history cannot be validated or accumulated exactly. Hold evaluation
/// deliberately remains independent of duty history.
pub fn try_decide_validated(
    input: &ValidatedPolicyInput<'_>,
) -> Result<PolicyDecision, PolicyEvaluationError> {
    let input = PolicyInput {
        now: input.now,
        lease: input.lease,
        state: input.state,
        action: input.action,
        history: input.history,
        policy: input.policy.snapshot(),
    };
    decide_inner(&input)
}

fn decide_inner(input: &PolicyInput<'_>) -> Result<PolicyDecision, PolicyEvaluationError> {
    let mut reasons: Vec<R> = Vec::new();
    let p = input.policy;
    let lease = input.lease;
    let st = input.state;
    let now = input.now;
    let class = input.action.class();
    let motion = p
        .motion_envelope_v2()
        .ok_or(PolicyEvaluationError::InvalidPolicy(
            NativePolicyError::MotionEnvelopeV2Required,
        ))?;

    // --- scope / phase ---
    if !lease.permits_action(class) {
        push(&mut reasons, R::DenyScopeMismatch);
    }
    if class == ActionClassV1::VelocityLocalNed && !lease.permits_frame(CoordinateFrameV1::LocalNed)
    {
        push(&mut reasons, R::DenyScopeMismatch);
    }
    if !p.phase_permits(st.mission_phase.as_str(), class) {
        push(&mut reasons, R::DenyPhaseRule);
    }
    if !motion.plant_mode_permits(&st.plant_mode, class) {
        push(&mut reasons, R::DenyPlantMode);
    }

    // --- source / state freshness (B13: a clock regression denies, never "fresh") ---
    if !lease.permits_source_key(st.primary_source.source.source_key.as_str()) {
        push(&mut reasons, R::DenySourceUnknown);
    }
    if !st.primary_source.valid {
        push(&mut reasons, R::DenySourceStale);
    }
    if st.primary_source.receive_mono > st.captured_mono {
        push(&mut reasons, R::DenyStateStale);
    }
    let src_cap =
        u64::from(lease.limits.max_source_age_ms.get()).min(u64::from(p.source_freshness_cap_ms));
    let src_age = age_ms(now, st.primary_source.receive_mono);
    if src_age.is_none_or(|a| a > src_cap) {
        push(&mut reasons, R::DenySourceStale);
    }
    let state_cap =
        u64::from(lease.limits.max_state_age_ms.get()).min(u64::from(p.state_freshness_cap_ms));
    let state_age = age_ms(now, st.captured_mono);
    if state_age.is_none_or(|a| a > state_cap) {
        push(&mut reasons, R::DenyStateStale);
    }

    // --- state uncertainty ---
    if st
        .uncertainty
        .position_mm
        .iter()
        .any(|&u| u < 0 || u > p.max_position_uncertainty_mm)
        || st.uncertainty.velocity_mm_s.iter().any(|&u| u < 0)
    {
        push(&mut reasons, R::DenyUncertainty);
    }

    // --- action-specific numeric checks ---
    if let RequestedActionV1::VelocityLocalNed {
        north_mm_s,
        east_mm_s,
        down_mm_s,
        requested_validity_ms,
    } = *input.action
    {
        // `CoordinateFrameV1::LocalNed` identifies the action semantics, while
        // the digest-bound profile identifier names the exact state/NCP frame in
        // which those semantics are interpreted. Never publish a command by
        // copying an unchecked state-frame label into the adapter.
        if st.primary_source.frame_id != motion.local_ned_frame_id {
            push(&mut reasons, R::DenyScopeMismatch);
        }
        let v = [north_mm_s, east_mm_s, down_mm_s];
        let eff_speed =
            i64::from(lease.limits.max_linear_speed_mm_s.get()).min(i64::from(p.max_speed_mm_s));
        let component_cap = i64::from(p.max_component_mm_s).min(eff_speed);

        // component bounds BEFORE norm
        if v.iter()
            .any(|&c| i128::from(c).abs() > i128::from(component_cap))
        {
            push(&mut reasons, R::DenyCommandRange);
        }
        // norm^2 <= max_speed^2, widened, no sqrt
        if !within_speed(v, eff_speed) {
            push(&mut reasons, R::DenyNormBound);
        }
        // State-to-command acceleration/mismatch is deliberately distinct from
        // command slew. It uses measured velocity, a nominal control-step
        // horizon, and worst-case velocity uncertainty. The signed lease and
        // locally admitted v2 envelope both constrain its vector norm.
        let accel_cap = lease
            .limits
            .max_linear_accel_mm_s2
            .get()
            .min(motion.max_linear_accel_mm_s2);
        if !rate_limited_delta_ok(
            v,
            st.kinematic.velocity_mm_s,
            st.uncertainty.velocity_mm_s,
            accel_cap,
            u64::from(p.nominal_update_ms),
        ) {
            push(&mut reasons, R::DenyAcceleration);
        }
        // slew vs last published command, bounded by ACTUAL elapsed time (H-P01)
        if let Some(prev) = input.history.last_published_velocity_mm_s() {
            let elapsed_ms = input.history.slew_elapsed_ms(now, p.nominal_update_ms);
            let slew_cap = lease
                .limits
                .max_linear_slew_mm_s2
                .get()
                .min(motion.max_linear_slew_mm_s2);
            if !rate_limited_delta_ok(v, prev, [0; 3], slew_cap, elapsed_ms) {
                push(&mut reasons, R::DenySlew);
            }
        }
        // Duty window: retained activity stays nanosecond-exact, while the
        // prospective command is conservatively charged on the requested/NCP
        // horizon (an upper bound on final effective published validity).
        // Equality is allowed; one nanosecond over the configured cap denies.
        let retention_window = MonoDuration::checked_from_millis(u64::from(p.duty_window_ms))
            .ok_or(ActionHistoryError::ArithmeticOverflow)?;
        let candidate = horizon_ms(requested_validity_ms.get(), p);
        let candidate_duration = MonoDuration::checked_from_millis(candidate)
            .ok_or(ActionHistoryError::ArithmeticOverflow)?;
        let charged =
            input
                .history
                .prospective_active_duration(now, retention_window, candidate_duration)?;
        let charged_ns = u128::from(charged.as_nanos());
        let limit_ns = u128::from(p.max_active_ms_in_window) * NANOS_PER_MILLISECOND;
        if charged_ns > limit_ns {
            push(&mut reasons, R::DenyDutyLimit);
        }
        // Burst accounting is publication-based and wall-clock conservative:
        // silence, horizon gaps, and lease boundaries never masquerade as Hold.
        // The requested/NCP candidate upper bound covers both maximum call delay
        // and effective published validity. A new burst is rearmed only by Hold
        // coverage that remains valid through that latest permitted call.
        let continuous_cap_ms = lease
            .limits
            .max_continuous_motion_ms
            .get()
            .min(motion.max_continuous_motion_ms);
        if !continuous_motion_ok(input.history, now, candidate, continuous_cap_ms) {
            push(&mut reasons, R::DenyContinuousMotion);
        }
        let minimum_hold_ms = lease
            .limits
            .minimum_hold_between_bursts_ms
            .max(motion.minimum_hold_between_bursts_ms);
        if !hold_dwell_ok(
            input.history,
            now,
            p.publication_safety_margin_ms,
            minimum_hold_ms,
        ) {
            push(&mut reasons, R::DenyHoldDwell);
        }
        // Prospective software geofence projection from state capture through
        // an upper bound of the published horizon (B10). Accepted state age is
        // part of that projection, not merely a freshness/validity concern.
        if !geofence_ok(st, now, v, candidate, p) {
            push(&mut reasons, R::DenyGeofence);
        }
    }

    if !reasons.is_empty() {
        return Ok(deny(reasons));
    }

    // --- effective validity (H1): full min-set minus publication safety margin ---
    let eff = effective_validity_ms(input, src_cap, src_age, state_cap, state_age);
    if eff >= p.min_useful_validity_ms {
        Ok(PolicyDecision {
            outcome: PolicyOutcome::Allow {
                effective_validity_ms: eff,
            },
            reasons,
        })
    } else {
        Ok(deny(vec![R::DenyValidityTooShort]))
    }
}

fn push(reasons: &mut Vec<R>, code: R) {
    if reasons.len() < MAX_REASONS && !reasons.contains(&code) {
        reasons.push(code);
    }
}

fn deny(mut reasons: Vec<R>) -> PolicyDecision {
    // hard denies first for a stable, bounded reason vector (H6/P4)
    reasons.sort_by_key(|r| u8::from(!r.is_hard_deny()));
    reasons.truncate(MAX_REASONS);
    PolicyDecision {
        outcome: PolicyOutcome::Deny,
        reasons,
    }
}

fn age_ms(now: MonoInstant, earlier: MonoInstant) -> Option<u64> {
    // Round the elapsed age UP so the staleness guard is conservative (fail-closed):
    // a source 50.9 ms old must not pass a 50 ms cap (punch-list BUG-5). `None` on a
    // monotonic regression (`now < earlier`) — the caller treats that as stale.
    now.checked_duration_since(earlier)
        .map(MonoDuration::as_millis_ceil)
}

fn within_speed(v: [i32; 3], max_speed: i64) -> bool {
    let sq: i128 = v.iter().map(|&c| i128::from(c) * i128::from(c)).sum();
    let cap = i128::from(max_speed.max(0));
    sq <= cap * cap
}

fn rate_limited_delta_ok(
    candidate: [i32; 3],
    reference: [i32; 3],
    uncertainty: [i32; 3],
    rate_limit_mm_s2: u32,
    elapsed_ms: u64,
) -> bool {
    // Allowed vector change = rate_limit(mm/s²) * elapsed(ms) / 1000.
    // Floor division is fail-closed. Widened squared comparison avoids sqrt and
    // rejects the sqrt(3) excess that independent component checks would admit.
    let bound = i128::from(rate_limit_mm_s2) * i128::from(elapsed_ms) / 1000;
    let worst_case_squared = candidate
        .iter()
        .zip(reference.iter())
        .zip(uncertainty.iter())
        .map(|((&value, &baseline), &uncertainty)| {
            let worst_case_delta =
                (i128::from(value) - i128::from(baseline)).abs() + i128::from(uncertainty.max(0));
            worst_case_delta * worst_case_delta
        })
        .sum::<i128>();
    worst_case_squared <= bound * bound
}

fn continuous_motion_ok(
    history: &crate::BoundedActionHistory,
    now: MonoInstant,
    candidate_horizon_ms: u64,
    max_continuous_motion_ms: u32,
) -> bool {
    let burst_start_ns = history.motion_burst_started_at().unwrap_or(now).as_nanos();
    let candidate_end_ns =
        u128::from(now.as_nanos()) + u128::from(candidate_horizon_ms) * NANOS_PER_MILLISECOND;
    let continuous_ns = candidate_end_ns.saturating_sub(u128::from(burst_start_ns));
    let limit_ns = u128::from(max_continuous_motion_ms) * NANOS_PER_MILLISECOND;
    continuous_ns <= limit_ns
}

fn hold_dwell_ok(
    history: &crate::BoundedActionHistory,
    now: MonoInstant,
    maximum_call_delay_ms: u32,
    minimum_hold_ms: u32,
) -> bool {
    match (history.hold_started_at(), history.hold_active_until()) {
        (None, None) => true,
        (Some(start), Some(end)) => {
            // `end` is exclusive for actuation, but a new command exactly at end
            // follows a fully covered Hold interval and is therefore admissible.
            let latest_call_ns = u128::from(now.as_nanos())
                + u128::from(maximum_call_delay_ms) * NANOS_PER_MILLISECOND;
            let covered_through_latest_call =
                now >= start && latest_call_ns <= u128::from(end.as_nanos());
            let elapsed_ns = u128::from(now.as_nanos().saturating_sub(start.as_nanos()));
            let required_ns = u128::from(minimum_hold_ms) * NANOS_PER_MILLISECOND;
            covered_through_latest_call && elapsed_ns >= required_ns
        }
        _ => false,
    }
}

fn horizon_ms(requested_validity_ms: u32, p: &NativePolicySnapshot) -> u64 {
    // Upper bound on the published horizon (never smaller than the final validity).
    u64::from(requested_validity_ms).min(u64::from(p.ncp_validity_cap_ms))
}

fn geofence_ok(
    st: &TrustedStateSnapshotV1,
    now: MonoInstant,
    v: [i32; 3],
    horizon_ms: u64,
    p: &NativePolicySnapshot,
) -> bool {
    let Some(state_age) = now.checked_duration_since(st.captured_mono) else {
        return false;
    };
    let Some(candidate_ns) = u128::from(horizon_ms).checked_mul(NANOS_PER_MILLISECOND) else {
        return false;
    };
    let Some(reach_horizon_ns) = u128::from(state_age.as_nanos()).checked_add(candidate_ns) else {
        return false;
    };
    let extra = i128::from(p.tracking_error_mm) + i128::from(p.uncertainty_margin_mm);
    let axes = v
        .iter()
        .zip(st.kinematic.velocity_mm_s.iter())
        .zip(st.uncertainty.velocity_mm_s.iter())
        .zip(st.kinematic.position_mm.iter())
        .zip(st.uncertainty.position_mm.iter())
        .zip(p.geofence.min_mm.iter())
        .zip(p.geofence.max_mm.iter());
    for (
        (
            (
                (((&command_raw, &measured_raw), &velocity_uncertainty_raw), &pos_raw),
                &position_uncertainty_raw,
            ),
            &region_lo,
        ),
        &region_hi,
    ) in axes
    {
        let pos = i128::from(pos_raw);
        let command = i128::from(command_raw);
        let measured = i128::from(measured_raw);
        let velocity_uncertainty = i128::from(velocity_uncertainty_raw.max(0));
        // Project a configured software interval containing both the measured
        // velocity (plus measurement uncertainty) and requested setpoint from
        // state capture through the whole candidate horizon. This does not
        // establish that physical velocity stays inside the interval: no
        // authenticated acceleration, braking, overshoot, disturbance, or
        // actuator model is available here. Magnitudes round outward to a whole
        // millimetre.
        let least_velocity = command.min(measured - velocity_uncertainty);
        let greatest_velocity = command.max(measured + velocity_uncertainty);
        let Some(backward_reach) =
            outward_displacement_mm((-least_velocity).max(0), reach_horizon_ns)
        else {
            return false;
        };
        let Some(forward_reach) =
            outward_displacement_mm(greatest_velocity.max(0), reach_horizon_ns)
        else {
            return false;
        };
        let position_uncertainty = i128::from(position_uncertainty_raw.max(0));
        let Some(fwd) = forward_reach
            .checked_add(extra)
            .and_then(|reach| reach.checked_add(position_uncertainty))
        else {
            return false;
        };
        let Some(back) = backward_reach
            .checked_add(extra)
            .and_then(|reach| reach.checked_add(position_uncertainty))
        else {
            return false;
        };
        let Some(lo) = pos.checked_sub(back) else {
            return false;
        };
        let Some(hi) = pos.checked_add(fwd) else {
            return false;
        };
        // deny on or outside the boundary
        if lo <= i128::from(region_lo) || hi >= i128::from(region_hi) {
            return false;
        }
    }
    true
}

fn outward_displacement_mm(nonnegative_velocity_mm_s: i128, horizon_ns: u128) -> Option<i128> {
    if nonnegative_velocity_mm_s < 0 {
        return None;
    }
    let horizon_ns = i128::try_from(horizon_ns).ok()?;
    nonnegative_velocity_mm_s
        .checked_mul(horizon_ns)?
        .checked_add(NANOS_PER_SECOND - 1)?
        .checked_div(NANOS_PER_SECOND)
}

fn effective_validity_ms(
    input: &PolicyInput<'_>,
    src_cap: u64,
    src_age: Option<u64>,
    state_cap: u64,
    state_age: Option<u64>,
) -> u32 {
    let p = input.policy;
    let lease = input.lease;
    let requested = u64::from(input.action.requested_validity_ms().get());
    let remaining_source = src_cap.saturating_sub(src_age.unwrap_or(u64::MAX));
    let remaining_state = state_cap.saturating_sub(state_age.unwrap_or(u64::MAX));
    let terms: [u64; 8] = [
        requested,
        u64::from(lease.limits.max_output_validity_ms.get()),
        u64::from(p.max_output_validity_ms),
        lease.remaining_ms(input.now),
        remaining_source,
        remaining_state,
        u64::from(p.ncp_validity_cap_ms),
        u64::from(p.plant_validity_cap_ms),
    ];
    let min_term = terms.iter().copied().min().unwrap_or(0);
    let after_margin = min_term.saturating_sub(u64::from(p.publication_safety_margin_ms));
    // `requested` bounds `min_term` to `u32::MAX` today. Keep the fallback
    // fail-closed so a future change to that invariant cannot lengthen an
    // authorization window.
    u32::try_from(after_margin).unwrap_or(0)
}

#[cfg(test)]
mod local_invariant_tests {
    use super::outward_displacement_mm;

    #[test]
    fn outward_projection_rejects_a_negative_private_precondition_in_release_logic() {
        assert_eq!(outward_displacement_mm(-1, 1_000_000_000), None);
    }
}
