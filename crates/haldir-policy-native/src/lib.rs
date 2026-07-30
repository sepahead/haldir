//! `haldir-policy-native` — the smallest trustworthy mission policy for `Hold`
//! and local-NED velocity, using fixed-point checked arithmetic.
//!
//! The [`try_decide()`] path validates a raw policy and preserves typed internal
//! failures; [`try_decide_validated()`] accepts a retained
//! [`ValidatedNativePolicy`] so an integrated Gate need not repeat whole-policy
//! work. The infallible [`decide()`] compatibility wrapper remains fail-closed but
//! deliberately loses that error distinction. Evaluation is pure: no I/O, no
//! floats, and no unbounded allocation. An out-of-range value can never wrap into
//! an accepted boundary value, a monotonic-clock regression denies (never
//! "fresh"), duty is accumulated exactly in nanoseconds, the prospective
//! geofence over-approximates the reachable set, and effective validity is the
//! minimum of the full contributing set minus a publication safety margin.
#![forbid(unsafe_code)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::float_cmp
    )
)]

pub mod decide;
pub mod input;
pub mod output;
pub mod policy;

/// Crate version string.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub use decide::{
    PolicyEvaluationError, decide, decide_validated, try_decide, try_decide_validated,
};
pub use input::{
    ActionHistoryError, BoundedActionHistory, MAX_RETAINED_ACTIVE_INTERVALS, PolicyInput,
    PublishedInterval, ValidatedPolicyInput,
};
pub use output::{PolicyDecision, PolicyOutcome};
pub use policy::{
    GeofenceBoxV1, NATIVE_POLICY_DIGEST_SCHEMA_V1, NativePolicyError, NativePolicySnapshot,
    PhaseRuleV1, ValidatedNativePolicy,
};

#[cfg(test)]
mod tests {
    use super::*;
    use core::num::{NonZeroU32, NonZeroU64};
    use haldir_contracts::action::{ActionClassV1, CoordinateFrameV1, RequestedActionV1};
    use haldir_contracts::digest::{DigestDomain, DigestV1};
    use haldir_contracts::ids::*;
    use haldir_contracts::limits::MissionLeaseLimitsV1;
    use haldir_contracts::receipt::DecisionReasonCodeV1 as R;
    use haldir_contracts::scalar::{AsciiId, CanonicalUuidV4String};
    use haldir_contracts::session::{NcpSessionIdentityV1, NcpSourceRefV1};
    use haldir_core::snapshot::{
        ActiveMissionLeaseSnapshot, AdmittedControllerSnapshot, KinematicStateFixedV1,
        StateUncertaintyFixedV1, TrustedStateSnapshotV1, VerifiedSourceStateV1,
    };
    use haldir_core::time::{MonoDuration, MonoInstant};
    use proptest::prelude::*;

    fn dig(s: u8) -> DigestV1 {
        DigestV1::compute(DigestDomain::Payload, &[s])
    }
    fn sess() -> NcpSessionIdentityV1 {
        NcpSessionIdentityV1 {
            session_id: AsciiId::new("sess-1").unwrap(),
            generation: CanonicalUuidV4String::from_random_bytes([1; 16]),
        }
    }

    fn policy() -> NativePolicySnapshot {
        NativePolicySnapshot {
            max_component_mm_s: 3000,
            max_speed_mm_s: 3000,
            max_output_validity_ms: 500,
            min_useful_validity_ms: 50,
            publication_safety_margin_ms: 20,
            source_freshness_cap_ms: 200,
            state_freshness_cap_ms: 200,
            ncp_validity_cap_ms: 1000,
            plant_validity_cap_ms: 1000,
            nominal_update_ms: 20,
            tracking_error_mm: 50,
            uncertainty_margin_mm: 50,
            max_position_uncertainty_mm: 500,
            geofence: GeofenceBoxV1 {
                min_mm: [-100_000, -100_000, -100_000],
                max_mm: [100_000, 100_000, 100_000],
            },
            duty_window_ms: 10_000,
            max_active_ms_in_window: 6000,
            phase_rules: vec![PhaseRuleV1 {
                phase: "INSPECTION".to_owned(),
                allowed: vec![ActionClassV1::Hold, ActionClassV1::VelocityLocalNed],
            }],
        }
    }

    fn lease() -> ActiveMissionLeaseSnapshot {
        ActiveMissionLeaseSnapshot {
            lease_id: MissionLeaseId::new([2; 16]),
            lease_term: 10,
            controller_id: ControllerId::new("survey-v1").unwrap(),
            mission_id: MissionId::new("inspect-1").unwrap(),
            mission_phase: AsciiId::new("INSPECTION").unwrap(),
            vehicle_id: VehicleId::new("uav-1").unwrap(),
            gate_boot_id: GateBootId::new([9; 16]),
            session: sess(),
            gate_output_epoch: GateOutputEpoch::new(CanonicalUuidV4String::from_random_bytes(
                [5; 16],
            )),
            controller: AdmittedControllerSnapshot {
                controller_id: ControllerId::new("survey-v1").unwrap(),
                bundle_digest: dig(4),
                backend_profile_digest: dig(5),
                admission_id: AdmissionId::new([4; 16]),
                admission_digest: dig(3),
            },
            controller_intent_key: "veh/uav-1/haldir/intent/survey-v1".to_owned(),
            controller_intent_signing_key_id: KeyId::new(vec![8, 8]).unwrap(),
            policy_snapshot_digest: dig(1),
            allowed_actions: vec![ActionClassV1::Hold, ActionClassV1::VelocityLocalNed],
            allowed_frames: vec![CoordinateFrameV1::LocalNed],
            allowed_source_keys: vec!["veh/uav-1/state/pose".to_owned()],
            limits: MissionLeaseLimitsV1 {
                max_output_validity_ms: NonZeroU32::new(500).unwrap(),
                max_linear_speed_mm_s: NonZeroU32::new(3000).unwrap(),
                max_linear_accel_mm_s2: NonZeroU32::new(2000).unwrap(),
                max_linear_slew_mm_s2: NonZeroU32::new(100_000).unwrap(),
                max_source_age_ms: NonZeroU32::new(200).unwrap(),
                max_state_age_ms: NonZeroU32::new(200).unwrap(),
                max_continuous_motion_ms: NonZeroU32::new(2000).unwrap(),
                minimum_hold_between_bursts_ms: 500,
            },
            max_intent_rate_millihz: 50_000,
            max_total_intents: 100_000,
            accepted_at_mono: MonoInstant::from_nanos(0),
            expires_at_mono: MonoInstant::from_nanos(60_000_000_000),
        }
    }

    fn state(
        now_ns: u64,
        src_age_ms: u64,
        pos: [i64; 3],
        unc_pos: [i64; 3],
    ) -> TrustedStateSnapshotV1 {
        let recv = MonoInstant::from_nanos(now_ns.saturating_sub(src_age_ms * 1_000_000));
        TrustedStateSnapshotV1 {
            vehicle_id: VehicleId::new("uav-1").unwrap(),
            session: sess(),
            captured_mono: recv,
            primary_source: VerifiedSourceStateV1 {
                source: NcpSourceRefV1 {
                    source_key: haldir_contracts::scalar::BoundedAscii::new("veh/uav-1/state/pose")
                        .unwrap(),
                    stream_epoch: CanonicalUuidV4String::from_random_bytes([2; 16]),
                    stream_seq: SourceSeq::new(NonZeroU64::new(1).unwrap()),
                },
                session: sess(),
                frame_id: haldir_contracts::scalar::BoundedAscii::new("map").unwrap(),
                publisher_t_ns: 0,
                receive_mono: recv,
                valid: true,
            },
            kinematic: KinematicStateFixedV1 {
                position_mm: pos,
                velocity_mm_s: [0, 0, 0],
            },
            uncertainty: StateUncertaintyFixedV1 {
                position_mm: unc_pos,
                velocity_mm_s: [0, 0, 0],
            },
            mission_phase: AsciiId::new("INSPECTION").unwrap(),
            plant_mode: AsciiId::new("NOMINAL").unwrap(),
        }
    }

    fn vel(n: i32, e: i32, d: i32, ms: u32) -> RequestedActionV1 {
        RequestedActionV1::VelocityLocalNed {
            north_mm_s: n,
            east_mm_s: e,
            down_mm_s: d,
            requested_validity_ms: NonZeroU32::new(ms).unwrap(),
        }
    }

    fn history(max_intervals: usize) -> BoundedActionHistory {
        BoundedActionHistory::new(max_intervals, duration_ms(10_000)).unwrap()
    }

    fn duration_ms(milliseconds: u64) -> MonoDuration {
        MonoDuration::checked_from_millis(milliseconds).unwrap()
    }

    fn decide_vel(action: &RequestedActionV1, st: &TrustedStateSnapshotV1) -> PolicyDecision {
        let ls = lease();
        let pl = policy();
        let hist = history(16);
        decide(&PolicyInput {
            now: MonoInstant::from_nanos(1_000_000_000),
            lease: &ls,
            state: st,
            action,
            history: &hist,
            policy: &pl,
        })
    }

    #[test]
    fn happy_path_allows_with_effective_validity() {
        let st = state(1_000_000_000, 10, [0, 0, 0], [10, 10, 10]);
        let d = decide_vel(&vel(500, -250, 0, 300), &st);
        assert!(d.is_allow(), "{:?}", d.reasons);
        // min(300, 500, 500, ~60000, ~190, ~190, 1000, 1000) - 20 = 190-20 = 170
        assert_eq!(d.effective_validity_ms(), Some(170));
    }

    #[test]
    fn component_bound_is_inclusive_at_limit() {
        let st = state(1_000_000_000, 10, [0, 0, 0], [10, 10, 10]);
        // exactly at max_component (3000) with the other two zero -> allowed
        assert!(decide_vel(&vel(3000, 0, 0, 100), &st).is_allow());
        // one over -> DenyCommandRange
        let d = decide_vel(&vel(3001, 0, 0, 100), &st);
        assert!(d.has_reason(R::DenyCommandRange));
    }

    #[test]
    fn norm_bound_catches_components_that_individually_pass() {
        let st = state(1_000_000_000, 10, [0, 0, 0], [10, 10, 10]);
        // each component 2000 <= 3000, but norm = sqrt(3)*2000 ~ 3464 > 3000
        let d = decide_vel(&vel(2000, 2000, 2000, 100), &st);
        assert!(d.has_reason(R::DenyNormBound), "{:?}", d.reasons);
        assert!(!d.has_reason(R::DenyCommandRange));
    }

    #[test]
    fn source_freshness_boundary_and_clock_regression() {
        // well within cap (100 ms of a 200 ms cap) -> allowed (freshness headroom left)
        let st = state(1_000_000_000, 100, [0, 0, 0], [10, 10, 10]);
        assert!(decide_vel(&vel(100, 0, 0, 100), &st).is_allow());
        // exactly AT the cap: the freshness check itself passes (not stale), even though
        // zero remaining headroom then makes the validity too short.
        let st = state(1_000_000_000, 200, [0, 0, 0], [10, 10, 10]);
        let d = decide_vel(&vel(100, 0, 0, 100), &st);
        assert!(
            !d.has_reason(R::DenySourceStale),
            "age==cap must not be stale"
        );
        // one over the cap -> stale
        let st = state(1_000_000_000, 201, [0, 0, 0], [10, 10, 10]);
        assert!(decide_vel(&vel(100, 0, 0, 100), &st).has_reason(R::DenySourceStale));
        // clock regression: receive time in the future relative to `now` -> deny, never fresh
        let mut st = state(1_000_000_000, 0, [0, 0, 0], [10, 10, 10]);
        st.primary_source.receive_mono = MonoInstant::from_nanos(2_000_000_000);
        assert!(decide_vel(&vel(100, 0, 0, 100), &st).has_reason(R::DenySourceStale));

        // A source sample cannot arrive after the snapshot that incorporates it.
        // This causal contradiction is state-stale even when both timestamps are
        // individually in the past relative to the decision clock.
        let mut st = state(1_000_000_000, 10, [0, 0, 0], [10, 10, 10]);
        st.captured_mono = MonoInstant::from_nanos(980_000_000);
        assert!(decide_vel(&vel(100, 0, 0, 100), &st).has_reason(R::DenyStateStale));
    }

    #[test]
    fn freshness_age_rounds_up_no_sub_ms_fail_open() {
        // Regression for BUG-5: a source 200.5 ms old must be STALE against a 200 ms
        // cap (age rounds up, fail-closed), not treated as fresh.
        let mut st = state(1_000_000_000, 0, [0, 0, 0], [10, 10, 10]);
        let over = MonoInstant::from_nanos(1_000_000_000 - (200 * 1_000_000 + 500_000));
        st.primary_source.receive_mono = over;
        st.captured_mono = over;
        assert!(decide_vel(&vel(100, 0, 0, 100), &st).has_reason(R::DenySourceStale));
    }

    #[test]
    fn geofence_denies_motion_toward_boundary() {
        // near +X boundary, commanding +X velocity for a long horizon -> leaves region
        let st = state(1_000_000_000, 10, [99_000, 0, 0], [10, 10, 10]);
        let d = decide_vel(&vel(3000, 0, 0, 500), &st);
        assert!(d.has_reason(R::DenyGeofence), "{:?}", d.reasons);
    }

    #[test]
    fn uncertainty_over_cap_denies() {
        let st = state(1_000_000_000, 10, [0, 0, 0], [501, 0, 0]);
        assert!(decide_vel(&vel(100, 0, 0, 100), &st).has_reason(R::DenyUncertainty));
    }

    #[test]
    fn negative_uncertainty_never_becomes_a_smaller_safety_margin() {
        let mut position = state(1_000_000_000, 10, [0, 0, 0], [-1, 0, 0]);
        assert!(decide_vel(&vel(100, 0, 0, 100), &position).has_reason(R::DenyUncertainty));

        position.uncertainty.position_mm = [0; 3];
        position.uncertainty.velocity_mm_s = [0, -1, 0];
        assert!(decide_vel(&vel(100, 0, 0, 100), &position).has_reason(R::DenyUncertainty));
    }

    #[test]
    fn invalid_public_policy_input_fails_closed() {
        let st = state(1_000_000_000, 10, [0, 0, 0], [10, 10, 10]);
        let lease = lease();
        let mut invalid = policy();
        invalid.uncertainty_margin_mm = -1;
        let history = history(16);
        let action = vel(100, 0, 0, 100);

        let error = try_decide(&PolicyInput {
            now: MonoInstant::from_nanos(1_000_000_000),
            lease: &lease,
            state: &st,
            action: &action,
            history: &history,
            policy: &invalid,
        })
        .unwrap_err();
        assert_eq!(
            error,
            PolicyEvaluationError::InvalidPolicy(NativePolicyError::NegativeSafetyDistance)
        );
        assert_eq!(error.reason_code(), "POLICY_EVALUATION_INVALID_POLICY");
        assert_eq!(
            error.detail_reason_code(),
            "NATIVE_POLICY_NEGATIVE_SAFETY_DISTANCE"
        );

        let decision = decide(&PolicyInput {
            now: MonoInstant::from_nanos(1_000_000_000),
            lease: &lease,
            state: &st,
            action: &action,
            history: &history,
            policy: &invalid,
        });

        assert!(!decision.is_allow());
        assert!(decision.has_reason(R::DenyPolicyDiagnostic));
    }

    #[test]
    fn validated_policy_path_matches_the_fail_closed_public_path() {
        let state = state(1_000_000_000, 10, [0, 0, 0], [10, 10, 10]);
        let lease = lease();
        let policy = policy();
        let validated = ValidatedNativePolicy::new(policy.clone()).unwrap();
        let history = history(16);
        let action = vel(100, 0, 0, 100);
        let now = MonoInstant::from_nanos(1_000_000_000);

        let raw = decide(&PolicyInput {
            now,
            lease: &lease,
            state: &state,
            action: &action,
            history: &history,
            policy: &policy,
        });
        let retained = decide_validated(&PolicyInput {
            now,
            lease: &lease,
            state: &state,
            action: &action,
            history: &history,
            policy: &validated,
        });

        assert_eq!(retained, raw);
    }

    #[test]
    fn validity_too_short_denies() {
        // requested validity below min_useful (50) after margin
        let st = state(1_000_000_000, 10, [0, 0, 0], [10, 10, 10]);
        let d = decide_vel(&vel(100, 0, 0, 40), &st);
        assert!(d.has_reason(R::DenyValidityTooShort), "{:?}", d.reasons);
    }

    #[test]
    fn hold_is_allowed_and_deterministic() {
        let st = state(1_000_000_000, 10, [0, 0, 0], [10, 10, 10]);
        let ls = lease();
        let pl = policy();
        let hist = history(16);
        let action = RequestedActionV1::Hold {
            requested_validity_ms: NonZeroU32::new(300).unwrap(),
        };
        let input = PolicyInput {
            now: MonoInstant::from_nanos(1_000_000_000),
            lease: &ls,
            state: &st,
            action: &action,
            history: &hist,
            policy: &pl,
        };
        let d1 = decide(&input);
        let d2 = decide(&input);
        assert!(d1.is_allow());
        assert_eq!(d1, d2, "policy must be deterministic");
    }

    #[test]
    fn wrong_phase_denies() {
        let mut st = state(1_000_000_000, 10, [0, 0, 0], [10, 10, 10]);
        st.mission_phase = AsciiId::new("HOLD").unwrap();
        let d = decide_vel(&vel(100, 0, 0, 100), &st);
        assert!(d.has_reason(R::DenyPhaseRule));
    }

    fn decide_with_history(
        action: &RequestedActionV1,
        st: &TrustedStateSnapshotV1,
        hist: &BoundedActionHistory,
        now_ns: u64,
    ) -> PolicyDecision {
        let ls = lease();
        let pl = policy();
        decide(&PolicyInput {
            now: MonoInstant::from_nanos(now_ns),
            lease: &ls,
            state: st,
            action,
            history: hist,
            policy: &pl,
        })
    }

    fn try_decide_with_history(
        action: &RequestedActionV1,
        st: &TrustedStateSnapshotV1,
        hist: &BoundedActionHistory,
        now_ns: u64,
    ) -> Result<PolicyDecision, PolicyEvaluationError> {
        let ls = lease();
        let validated = ValidatedNativePolicy::new(policy()).unwrap();
        try_decide_validated(&PolicyInput {
            now: MonoInstant::from_nanos(now_ns),
            lease: &ls,
            state: st,
            action,
            history: hist,
            policy: &validated,
        })
    }

    #[test]
    fn slew_bound_tracks_actual_elapsed_time() {
        // H-P01: the admissible velocity change scales with the ACTUAL elapsed time
        // since the last published command, not a static nominal period. Publish a
        // 100 mm/s command, then request a change of 600 mm/s at two elapsed times.
        // slew_limit = 100_000 mm/s^2, nominal cap = 20 ms.
        let t_prev = 1_000_000_000u64;
        let mut hist = history(16);
        hist.record_velocity(
            [100, 0, 0],
            MonoInstant::from_nanos(t_prev),
            MonoInstant::from_nanos(t_prev + 300_000_000),
        )
        .unwrap();
        // 5 ms later: bound = 100_000 * 5 / 1000 = 500 mm/s < 600 -> DENY_SLEW.
        let now5 = t_prev + 5_000_000;
        let st5 = state(now5, 5, [0, 0, 0], [10, 10, 10]);
        let d5 = decide_with_history(&vel(700, 0, 0, 100), &st5, &hist, now5);
        assert!(d5.has_reason(R::DenySlew), "{:?}", d5.reasons);
        // 20 ms later (at the nominal cap): bound = 2000 mm/s >= 600 -> passes slew.
        let now20 = t_prev + 20_000_000;
        let st20 = state(now20, 5, [0, 0, 0], [10, 10, 10]);
        let d20 = decide_with_history(&vel(700, 0, 0, 100), &st20, &hist, now20);
        assert!(d20.is_allow(), "{:?}", d20.reasons);
    }

    #[test]
    fn duty_union_does_not_double_count_overlap() {
        // H-P02/H-P03: overlapping published horizons are unioned, not summed.
        let mut hist = history(16);
        hist.record_velocity(
            [100, 0, 0],
            MonoInstant::from_nanos(1_000_000_000),
            MonoInstant::from_nanos(2_000_000_000),
        )
        .unwrap();
        hist.record_velocity(
            [100, 0, 0],
            MonoInstant::from_nanos(1_100_000_000),
            MonoInstant::from_nanos(2_100_000_000),
        )
        .unwrap();
        // Two overlapping 1000 ms intervals collapse to one [1.0s, 2.1s] = 1100 ms;
        // a naive sum would report 2000 ms.
        assert_eq!(hist.active_intervals().len(), 1);
        assert_eq!(
            hist.active_duration_in_window(
                MonoInstant::from_nanos(3_000_000_000),
                MonoDuration::checked_from_millis(10_000).unwrap(),
            )
            .unwrap()
            .as_nanos(),
            1_100_000_000
        );
    }

    #[test]
    fn bounded_history_merges_instead_of_dropping() {
        // H-B04: at capacity, the ring must not silently drop an active interval
        // (that would UNDER-count duty). It merges the closest pair instead, which
        // over-approximates (counts gaps as active) and so can only deny more.
        let mut hist = history(2);
        for k in 0..4u64 {
            let s = MonoInstant::from_nanos(k * 1_000_000_000 + 1_000_000_000);
            let e = MonoInstant::from_nanos(k * 1_000_000_000 + 1_100_000_000);
            hist.record_velocity([100, 0, 0], s, e).unwrap();
        }
        assert!(hist.active_intervals().len() <= 2);
        let counted = hist
            .active_duration_in_window(
                MonoInstant::from_nanos(6_000_000_000),
                MonoDuration::checked_from_millis(10_000).unwrap(),
            )
            .unwrap()
            .as_nanos();
        // True active = 4 * 100 ms; merging can only raise the count.
        assert!(counted >= 400_000_000, "under-counted duty: {counted} ns");
    }

    #[test]
    fn hold_sets_slew_reference_to_rest() {
        // A hold commands the vehicle to stop, so the slew reference becomes zero:
        // a velocity command shortly after must ramp up from rest within the slew
        // limit, never unconstrained (previously the reference was cleared to None,
        // silently skipping the slew check).
        let mut hist = history(16);
        let t = 1_000_000_000u64;
        hist.record_hold(MonoInstant::from_nanos(t)).unwrap();
        assert_eq!(hist.last_published_velocity_mm_s(), Some([0, 0, 0]));
        // 3 ms later: bound = 100_000 * 3 / 1000 = 300 mm/s < 500 -> DENY_SLEW.
        let now = t + 3_000_000;
        let st = state(now, 5, [0, 0, 0], [10, 10, 10]);
        let d = decide_with_history(&vel(500, 0, 0, 100), &st, &hist, now);
        assert!(d.has_reason(R::DenySlew), "{:?}", d.reasons);
    }

    #[test]
    fn clear_slew_reference_drops_cross_lease_reference() {
        // A lease boundary must not carry a prior mission's velocity forward as a
        // slew reference (the gate calls this on accept/revoke).
        let mut hist = history(16);
        hist.record_velocity(
            [500, 0, 0],
            MonoInstant::from_nanos(1),
            MonoInstant::from_nanos(2),
        )
        .unwrap();
        assert_eq!(hist.last_published_velocity_mm_s(), Some([500, 0, 0]));
        hist.clear_slew_reference();
        assert_eq!(hist.last_published_velocity_mm_s(), None);
        assert_eq!(hist.last_published_at(), None);
    }

    #[test]
    fn duty_exact_cap_allows_and_one_nanosecond_over_denies() {
        let now = 7_000_000_000;
        let state = state(now, 10, [0, 0, 0], [10, 10, 10]);
        let action = vel(100, 0, 0, 100);

        let mut exactly_at_cap = history(16);
        exactly_at_cap
            .record_velocity(
                [100, 0, 0],
                MonoInstant::from_nanos(0),
                MonoInstant::from_nanos(5_900_000_000),
            )
            .unwrap();
        let exact = try_decide_with_history(&action, &state, &exactly_at_cap, now).unwrap();
        assert!(exact.is_allow(), "{:?}", exact.reasons);

        let mut one_nanosecond_over = history(16);
        one_nanosecond_over
            .record_velocity(
                [100, 0, 0],
                MonoInstant::from_nanos(0),
                MonoInstant::from_nanos(5_900_000_001),
            )
            .unwrap();
        let over = try_decide_with_history(&action, &state, &one_nanosecond_over, now).unwrap();
        assert!(over.has_reason(R::DenyDutyLimit), "{:?}", over.reasons);
    }

    #[test]
    fn disjoint_fractional_intervals_are_summed_before_duty_comparison() {
        let now = 7_000_000_000;
        let state = state(now, 10, [0, 0, 0], [10, 10, 10]);
        let action = vel(100, 0, 0, 100);
        let mut hist = history(16);
        hist.record_velocity(
            [100, 0, 0],
            MonoInstant::from_nanos(0),
            MonoInstant::from_nanos(2_900_000_001),
        )
        .unwrap();
        hist.record_velocity(
            [100, 0, 0],
            MonoInstant::from_nanos(3_000_000_000),
            MonoInstant::from_nanos(6_000_000_000),
        )
        .unwrap();

        assert_eq!(
            hist.active_duration_in_window(MonoInstant::from_nanos(now), duration_ms(10_000),)
                .unwrap()
                .as_nanos(),
            5_900_000_001
        );
        let decision = try_decide_with_history(&action, &state, &hist, now).unwrap();
        assert!(
            decision.has_reason(R::DenyDutyLimit),
            "{:?}",
            decision.reasons
        );
    }

    #[test]
    fn half_open_window_clips_both_boundaries_exactly() {
        let mut hist = history(16);
        hist.record_velocity(
            [100, 0, 0],
            MonoInstant::from_nanos(5_000_000_000),
            MonoInstant::from_nanos(12_000_000_000),
        )
        .unwrap();
        hist.record_velocity(
            [100, 0, 0],
            MonoInstant::from_nanos(18_000_000_000),
            MonoInstant::from_nanos(25_000_000_000),
        )
        .unwrap();

        // [5s, 12s) contributes [10s, 12s); [18s, 25s) contributes
        // [18s, 20s) to the owned [10s, 20s) window.
        assert_eq!(
            hist.active_duration_in_window(
                MonoInstant::from_nanos(20_000_000_000),
                duration_ms(10_000),
            )
            .unwrap()
            .as_nanos(),
            4_000_000_000
        );
    }

    #[test]
    fn history_construction_and_policy_window_are_checked() {
        assert_eq!(
            BoundedActionHistory::new(0, duration_ms(10_000)).unwrap_err(),
            ActionHistoryError::InvalidCapacity
        );
        assert_eq!(
            BoundedActionHistory::new(MAX_RETAINED_ACTIVE_INTERVALS + 1, duration_ms(10_000),)
                .unwrap_err(),
            ActionHistoryError::InvalidCapacity
        );
        assert_eq!(
            BoundedActionHistory::new(1, MonoDuration::from_nanos(0)).unwrap_err(),
            ActionHistoryError::InvalidRetentionWindow
        );
        assert_eq!(
            history(1)
                .active_duration_in_window(MonoInstant::from_nanos(0), duration_ms(9_999))
                .unwrap_err(),
            ActionHistoryError::RetentionWindowMismatch
        );
    }

    #[test]
    fn recording_failures_are_transactional_and_high_water_survives_slew_reset() {
        let mut hist = history(16);
        hist.record_hold(MonoInstant::from_nanos(100)).unwrap();
        hist.clear_slew_reference();
        assert_eq!(hist.last_recorded_at(), Some(MonoInstant::from_nanos(100)));

        let before_regression = hist.clone();
        assert_eq!(
            hist.record_velocity(
                [100, 0, 0],
                MonoInstant::from_nanos(99),
                MonoInstant::from_nanos(200),
            ),
            Err(ActionHistoryError::FutureRecord)
        );
        assert_eq!(hist, before_regression);

        let before_invalid = hist.clone();
        assert_eq!(
            hist.record_velocity(
                [100, 0, 0],
                MonoInstant::from_nanos(101),
                MonoInstant::from_nanos(101),
            ),
            Err(ActionHistoryError::InvalidInterval)
        );
        assert_eq!(hist, before_invalid);
        assert_eq!(
            hist.record_velocity(
                [100, 0, 0],
                MonoInstant::from_nanos(102),
                MonoInstant::from_nanos(101),
            ),
            Err(ActionHistoryError::InvalidInterval)
        );
        assert_eq!(hist, before_invalid);

        let mut future_end = history(1);
        future_end
            .record_velocity(
                [100, 0, 0],
                MonoInstant::from_nanos(200),
                MonoInstant::from_nanos(300),
            )
            .unwrap();
        assert_eq!(
            future_end
                .active_duration_in_window(MonoInstant::from_nanos(250), duration_ms(10_000),)
                .unwrap()
                .as_nanos(),
            50
        );
    }

    #[test]
    fn complete_history_validation_rejects_each_structural_contradiction() {
        let now = MonoInstant::from_nanos(10);

        let mut inconsistent_slew = history(4);
        inconsistent_slew.last_published_velocity_mm_s = Some([0; 3]);
        assert_eq!(
            inconsistent_slew.validate_at(now),
            Err(ActionHistoryError::InconsistentSlewReference)
        );

        let mut future_slew = history(4);
        future_slew.last_recorded_at = Some(now);
        future_slew.last_published_velocity_mm_s = Some([0; 3]);
        future_slew.last_published_at = Some(MonoInstant::from_nanos(11));
        assert_eq!(
            future_slew.validate_at(now),
            Err(ActionHistoryError::FutureSlewReference)
        );

        let mut future_interval = history(4);
        future_interval.last_recorded_at = Some(now);
        future_interval.active_intervals = vec![
            PublishedInterval::new(MonoInstant::from_nanos(11), MonoInstant::from_nanos(12))
                .unwrap(),
        ];
        assert_eq!(
            future_interval.validate_at(now),
            Err(ActionHistoryError::FutureInterval)
        );

        let mut invalid_interval = history(4);
        invalid_interval.last_recorded_at = Some(now);
        invalid_interval.active_intervals = vec![PublishedInterval {
            start: now,
            end: now,
        }];
        assert_eq!(
            invalid_interval.validate_at(now),
            Err(ActionHistoryError::InvalidInterval)
        );

        let noncanonical_cases = [
            vec![
                PublishedInterval::new(MonoInstant::from_nanos(1), MonoInstant::from_nanos(3))
                    .unwrap(),
                PublishedInterval::new(MonoInstant::from_nanos(3), MonoInstant::from_nanos(5))
                    .unwrap(),
            ],
            vec![
                PublishedInterval::new(MonoInstant::from_nanos(1), MonoInstant::from_nanos(4))
                    .unwrap(),
                PublishedInterval::new(MonoInstant::from_nanos(3), MonoInstant::from_nanos(5))
                    .unwrap(),
            ],
            vec![
                PublishedInterval::new(MonoInstant::from_nanos(4), MonoInstant::from_nanos(5))
                    .unwrap(),
                PublishedInterval::new(MonoInstant::from_nanos(1), MonoInstant::from_nanos(2))
                    .unwrap(),
            ],
        ];
        for intervals in noncanonical_cases {
            let mut malformed = history(4);
            malformed.last_recorded_at = Some(MonoInstant::from_nanos(5));
            malformed.active_intervals = intervals;
            assert_eq!(
                malformed.validate_at(now),
                Err(ActionHistoryError::NonCanonicalHistory)
            );
        }

        let mut missing_high_water = history(4);
        missing_high_water.active_intervals = vec![
            PublishedInterval::new(MonoInstant::from_nanos(1), MonoInstant::from_nanos(2)).unwrap(),
        ];
        assert_eq!(
            missing_high_water.validate_at(now),
            Err(ActionHistoryError::InconsistentRecordHighWater)
        );

        let mut lagging_high_water = history(4);
        lagging_high_water.last_recorded_at = Some(MonoInstant::from_nanos(1));
        lagging_high_water.active_intervals = vec![
            PublishedInterval::new(MonoInstant::from_nanos(2), MonoInstant::from_nanos(3)).unwrap(),
        ];
        assert_eq!(
            lagging_high_water.validate_at(now),
            Err(ActionHistoryError::InconsistentRecordHighWater)
        );

        let mut over_capacity = history(1);
        over_capacity.last_recorded_at = Some(MonoInstant::from_nanos(4));
        over_capacity.active_intervals = vec![
            PublishedInterval::new(MonoInstant::from_nanos(1), MonoInstant::from_nanos(2)).unwrap(),
            PublishedInterval::new(MonoInstant::from_nanos(3), MonoInstant::from_nanos(4)).unwrap(),
        ];
        assert_eq!(
            over_capacity.validate_at(now),
            Err(ActionHistoryError::CapacityExceeded)
        );
    }

    #[test]
    fn hold_bypasses_corrupt_motion_history_but_velocity_returns_typed_error() {
        let now = 1_000_000_000;
        let state = state(now, 10, [0, 0, 0], [10, 10, 10]);
        let lease = lease();
        let validated = ValidatedNativePolicy::new(policy()).unwrap();
        let mut malformed = history(16);
        malformed.last_recorded_at = Some(MonoInstant::from_nanos(now + 1));
        let hold = RequestedActionV1::Hold {
            requested_validity_ms: NonZeroU32::new(100).unwrap(),
        };

        let hold_decision = try_decide_validated(&PolicyInput {
            now: MonoInstant::from_nanos(now),
            lease: &lease,
            state: &state,
            action: &hold,
            history: &malformed,
            policy: &validated,
        })
        .unwrap();
        assert!(hold_decision.is_allow(), "{:?}", hold_decision.reasons);

        let mismatched = BoundedActionHistory::new(16, duration_ms(9_999)).unwrap();
        let hold_with_mismatched_window = try_decide_validated(&PolicyInput {
            now: MonoInstant::from_nanos(now),
            lease: &lease,
            state: &state,
            action: &hold,
            history: &mismatched,
            policy: &validated,
        })
        .unwrap();
        assert!(
            hold_with_mismatched_window.is_allow(),
            "{:?}",
            hold_with_mismatched_window.reasons
        );

        let velocity = vel(100, 0, 0, 100);
        let error = try_decide_validated(&PolicyInput {
            now: MonoInstant::from_nanos(now),
            lease: &lease,
            state: &state,
            action: &velocity,
            history: &malformed,
            policy: &validated,
        })
        .unwrap_err();
        assert_eq!(
            error,
            PolicyEvaluationError::ActionHistory(ActionHistoryError::FutureRecord)
        );
        assert_eq!(error.detail_reason_code(), "ACTION_HISTORY_FUTURE_RECORD");

        let lossy = decide_validated(&PolicyInput {
            now: MonoInstant::from_nanos(now),
            lease: &lease,
            state: &state,
            action: &velocity,
            history: &malformed,
            policy: &validated,
        });
        assert!(lossy.has_reason(R::DenyPolicyDiagnostic));
    }

    #[test]
    fn public_history_errors_have_stable_codes_and_standard_sources() {
        fn assert_standard_error<T: std::error::Error + Send + Sync + 'static>() {}
        assert_standard_error::<ActionHistoryError>();
        assert_standard_error::<PolicyEvaluationError>();

        let cases = [
            (
                ActionHistoryError::InvalidCapacity,
                "ACTION_HISTORY_INVALID_CAPACITY",
            ),
            (
                ActionHistoryError::CapacityExceeded,
                "ACTION_HISTORY_CAPACITY_EXCEEDED",
            ),
            (
                ActionHistoryError::InvalidRetentionWindow,
                "ACTION_HISTORY_INVALID_RETENTION_WINDOW",
            ),
            (
                ActionHistoryError::RetentionWindowMismatch,
                "ACTION_HISTORY_RETENTION_WINDOW_MISMATCH",
            ),
            (
                ActionHistoryError::InvalidInterval,
                "ACTION_HISTORY_INVALID_INTERVAL",
            ),
            (
                ActionHistoryError::FutureInterval,
                "ACTION_HISTORY_FUTURE_INTERVAL",
            ),
            (
                ActionHistoryError::NonCanonicalHistory,
                "ACTION_HISTORY_NON_CANONICAL_HISTORY",
            ),
            (
                ActionHistoryError::InconsistentSlewReference,
                "ACTION_HISTORY_INCONSISTENT_SLEW_REFERENCE",
            ),
            (
                ActionHistoryError::FutureSlewReference,
                "ACTION_HISTORY_FUTURE_SLEW_REFERENCE",
            ),
            (
                ActionHistoryError::FutureRecord,
                "ACTION_HISTORY_FUTURE_RECORD",
            ),
            (
                ActionHistoryError::InconsistentRecordHighWater,
                "ACTION_HISTORY_INCONSISTENT_RECORD_HIGH_WATER",
            ),
            (
                ActionHistoryError::ArithmeticOverflow,
                "ACTION_HISTORY_ARITHMETIC_OVERFLOW",
            ),
        ];
        for (error, expected) in cases {
            assert_eq!(error.reason_code(), expected);
            assert_eq!(error.to_string(), expected);
        }

        let source = ActionHistoryError::RetentionWindowMismatch;
        let error = PolicyEvaluationError::ActionHistory(source);
        assert_eq!(
            source.to_string(),
            "ACTION_HISTORY_RETENTION_WINDOW_MISMATCH"
        );
        assert_eq!(error.to_string(), "POLICY_EVALUATION_ACTION_HISTORY");
        assert_eq!(
            std::error::Error::source(&error).map(ToString::to_string),
            Some(source.to_string())
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]

        #[test]
        fn exact_duty_reason_matches_widened_reference(
            historical_ns in 0_u64..=6_000_000_000,
            candidate_ms in 100_u32..=500,
        ) {
            let now = 7_000_000_000;
            let state = state(now, 10, [0, 0, 0], [10, 10, 10]);
            let action = vel(100, 0, 0, candidate_ms);
            let mut hist = history(16);
            if historical_ns != 0 {
                hist.record_velocity(
                    [100, 0, 0],
                    MonoInstant::from_nanos(0),
                    MonoInstant::from_nanos(historical_ns),
                )
                .unwrap();
            }

            let decision = try_decide_with_history(&action, &state, &hist, now).unwrap();
            let expected_over = u128::from(historical_ns)
                + u128::from(candidate_ms) * 1_000_000
                > 6_000_000_000;
            prop_assert_eq!(decision.has_reason(R::DenyDutyLimit), expected_over);
        }

        #[test]
        fn bounded_compression_and_eviction_never_undercount_reference_union(
            pieces in prop::collection::vec(
                (1_u64..=2_000_000_000, 1_u64..=2_000_000_000),
                3..=12,
            ),
        ) {
            let mut hist = history(2);
            let mut cursor = 0_u64;
            let mut source_intervals = Vec::with_capacity(pieces.len());
            for (gap, length) in pieces {
                cursor = cursor.checked_add(gap).unwrap();
                let start = cursor;
                cursor = cursor.checked_add(length).unwrap();
                let end = cursor;
                source_intervals.push((start, end));
                hist.record_velocity(
                    [100, 0, 0],
                    MonoInstant::from_nanos(start),
                    MonoInstant::from_nanos(end),
                )
                .unwrap();
            }
            let now = cursor.checked_add(1).unwrap();
            let window_start = now.saturating_sub(duration_ms(10_000).as_nanos());
            let exact_ns = source_intervals
                .iter()
                .map(|&(start, end)| {
                    end.min(now).saturating_sub(start.max(window_start))
                })
                .sum::<u64>();
            let retained_ns = hist
                .active_duration_in_window(
                    MonoInstant::from_nanos(now),
                    duration_ms(10_000),
                )
                .unwrap()
                .as_nanos();
            prop_assert!(
                retained_ns >= exact_ns,
                "retained={retained_ns}, reference={exact_ns}"
            );
        }
    }
}
