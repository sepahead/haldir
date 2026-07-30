//! The pure, deterministic, fixed-point policy decision.
//!
//! No I/O, no floats, no allocation beyond the bounded reason vector. All
//! comparisons use checked/widened integer arithmetic; an out-of-range value is
//! never allowed to wrap into an accepted boundary value (punch-list B9). The
//! prospective geofence integrates over an upper bound of the published horizon,
//! computed before the effective-validity minimum (B10). The slew reference is
//! the last **published** command (H7).

use crate::input::{ActionHistoryError, PolicyInput, ValidatedPolicyInput};
use crate::output::{PolicyDecision, PolicyOutcome};
use crate::policy::{NativePolicyError, NativePolicySnapshot};
use haldir_contracts::action::{ActionClassV1, CoordinateFrameV1, RequestedActionV1};
use haldir_contracts::receipt::DecisionReasonCodeV1 as R;
use haldir_core::snapshot::{ActiveMissionLeaseSnapshot, TrustedStateSnapshotV1};
use haldir_core::time::{MonoDuration, MonoInstant};

const MAX_REASONS: usize = 32;
const NANOS_PER_MILLISECOND: u128 = 1_000_000;

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
        .validate()
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
        // slew vs last published command, bounded by ACTUAL elapsed time (H-P01)
        if let Some(prev) = input.history.last_published_velocity_mm_s() {
            let elapsed_ms = input.history.slew_elapsed_ms(now, p.nominal_update_ms);
            if !slew_ok(v, prev, elapsed_ms, lease) {
                push(&mut reasons, R::DenySlew);
            }
        }
        // Duty window: retained activity stays nanosecond-exact, while the
        // prospective command is conservatively charged on the requested/NCP
        // horizon (an upper bound on final effective published validity).
        // Equality is allowed; one nanosecond over the configured cap denies.
        let retention_window = MonoDuration::checked_from_millis(u64::from(p.duty_window_ms))
            .ok_or(ActionHistoryError::ArithmeticOverflow)?;
        let active = input
            .history
            .active_duration_in_window(now, retention_window)?;
        let candidate = horizon_ms(requested_validity_ms.get(), p);
        let charged_ns = u128::from(active.as_nanos())
            .checked_add(u128::from(candidate) * NANOS_PER_MILLISECOND)
            .ok_or(ActionHistoryError::ArithmeticOverflow)?;
        let limit_ns = u128::from(p.max_active_ms_in_window) * NANOS_PER_MILLISECOND;
        if charged_ns > limit_ns {
            push(&mut reasons, R::DenyDutyLimit);
        }
        // prospective geofence over an upper bound of the published horizon (B10)
        if !geofence_ok(st, v, candidate, p) {
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

fn slew_ok(
    v: [i32; 3],
    prev: [i32; 3],
    elapsed_ms: u64,
    lease: &ActiveMissionLeaseSnapshot,
) -> bool {
    // Allowed change over the elapsed interval = slew_limit(mm/s^2) * elapsed(ms) / 1000.
    let bound: i128 =
        i128::from(lease.limits.max_linear_slew_mm_s2.get()) * i128::from(elapsed_ms) / 1000;
    v.iter()
        .zip(prev.iter())
        .all(|(&a, &b)| (i128::from(a) - i128::from(b)).abs() <= bound)
}

fn horizon_ms(requested_validity_ms: u32, p: &NativePolicySnapshot) -> u64 {
    // Upper bound on the published horizon (never smaller than the final validity).
    u64::from(requested_validity_ms).min(u64::from(p.ncp_validity_cap_ms))
}

fn geofence_ok(
    st: &TrustedStateSnapshotV1,
    v: [i32; 3],
    horizon_ms: u64,
    p: &NativePolicySnapshot,
) -> bool {
    let extra = i128::from(p.tracking_error_mm) + i128::from(p.uncertainty_margin_mm);
    let axes = v
        .iter()
        .zip(st.kinematic.position_mm.iter())
        .zip(st.uncertainty.position_mm.iter())
        .zip(p.geofence.min_mm.iter())
        .zip(p.geofence.max_mm.iter());
    for ((((&vi_raw, &pos_raw), &unc_raw), &region_lo), &region_hi) in axes {
        let pos = i128::from(pos_raw);
        // displacement over the horizon, magnitude rounded UP (over-approximate)
        let vi = i128::from(vi_raw);
        let mag = (vi.abs() * i128::from(horizon_ms) + 999) / 1000;
        let disp = if vi >= 0 { mag } else { -mag };
        let unc = i128::from(unc_raw.max(0));
        let fwd = disp.max(0) + extra + unc;
        let back = (-disp).max(0) + extra + unc;
        let lo = pos - back;
        let hi = pos + fwd;
        // deny on or outside the boundary
        if lo <= i128::from(region_lo) || hi >= i128::from(region_hi) {
            return false;
        }
    }
    true
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
    u32::try_from(after_margin).unwrap_or(u32::MAX)
}
