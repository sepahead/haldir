//! The pure, deterministic, fixed-point policy decision.
//!
//! No I/O, no floats, no allocation beyond the bounded reason vector. All
//! comparisons use checked/widened integer arithmetic; an out-of-range value is
//! never allowed to wrap into an accepted boundary value (punch-list B9). The
//! prospective geofence integrates over an upper bound of the published horizon,
//! computed before the effective-validity minimum (B10). The slew reference is
//! the last **published** command (H7).

use crate::input::PolicyInput;
use crate::output::{PolicyDecision, PolicyOutcome};
use crate::policy::NativePolicySnapshot;
use haldir_contracts::action::{ActionClassV1, CoordinateFrameV1, RequestedActionV1};
use haldir_contracts::receipt::DecisionReasonCodeV1 as R;
use haldir_core::snapshot::{ActiveMissionLeaseSnapshot, TrustedStateSnapshotV1};
use haldir_core::time::MonoInstant;

const MAX_REASONS: usize = 32;

/// Evaluate the native mission policy for one intent.
#[must_use]
pub fn decide(input: &PolicyInput<'_>) -> PolicyDecision {
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
        .any(|&u| u > p.max_position_uncertainty_mm)
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
        // slew vs last published command
        if let Some(prev) = input.history.last_published_velocity_mm_s
            && !slew_ok(v, prev, lease, p)
        {
            push(&mut reasons, R::DenySlew);
        }
        // duty window (charged conservatively on the requested horizon)
        let window_start =
            MonoInstant::from_nanos(now.as_nanos().saturating_sub(ms_to_ns(p.duty_window_ms)));
        let active = input.history.active_ms_in_window(window_start, now);
        let candidate = horizon_ms(requested_validity_ms.get(), p);
        if active.saturating_add(candidate) > u64::from(p.max_active_ms_in_window) {
            push(&mut reasons, R::DenyDutyLimit);
        }
        // prospective geofence over an upper bound of the published horizon (B10)
        if !geofence_ok(st, v, candidate, p) {
            push(&mut reasons, R::DenyGeofence);
        }
    }

    if !reasons.is_empty() {
        return deny(reasons);
    }

    // --- effective validity (H1): full min-set minus publication safety margin ---
    let eff = effective_validity_ms(input, src_cap, src_age, state_cap, state_age);
    if eff >= p.min_useful_validity_ms {
        PolicyDecision {
            outcome: PolicyOutcome::Allow {
                effective_validity_ms: eff,
            },
            reasons,
        }
    } else {
        deny(vec![R::DenyValidityTooShort])
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

fn ms_to_ns(ms: u32) -> u64 {
    u64::from(ms).saturating_mul(1_000_000)
}

fn age_ms(now: MonoInstant, earlier: MonoInstant) -> Option<u64> {
    // Round the elapsed age UP so the staleness guard is conservative (fail-closed):
    // a source 50.9 ms old must not pass a 50 ms cap (punch-list BUG-5). `None` on a
    // monotonic regression (`now < earlier`) — the caller treats that as stale.
    now.checked_duration_since(earlier)
        .map(|d| d.as_nanos().div_ceil(1_000_000))
}

fn within_speed(v: [i32; 3], max_speed: i64) -> bool {
    let sq: i128 = v.iter().map(|&c| i128::from(c) * i128::from(c)).sum();
    let cap = i128::from(max_speed.max(0));
    sq <= cap * cap
}

fn slew_ok(
    v: [i32; 3],
    prev: [i32; 3],
    lease: &ActiveMissionLeaseSnapshot,
    p: &NativePolicySnapshot,
) -> bool {
    // Allowed change over one nominal update = slew_limit(mm/s^2) * update(ms) / 1000.
    let bound: i128 = i128::from(lease.limits.max_linear_slew_mm_s2.get())
        * i128::from(p.nominal_update_ms)
        / 1000;
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
