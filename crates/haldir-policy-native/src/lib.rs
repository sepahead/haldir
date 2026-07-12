//! `haldir-policy-native` — the smallest trustworthy mission policy for `Hold`
//! and local-NED velocity, using fixed-point checked arithmetic.
//!
//! The [`decide`] function is pure: no I/O, no floats, no unbounded allocation.
//! An out-of-range value can never wrap into an accepted boundary value, a
//! monotonic-clock regression denies (never "fresh"), the prospective geofence
//! over-approximates the reachable set, and the effective validity is the minimum
//! of the full contributing set minus a publication safety margin.
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

pub use decide::decide;
pub use input::{BoundedActionHistory, PolicyInput, PublishedInterval};
pub use output::{PolicyDecision, PolicyOutcome};
pub use policy::{GeofenceBoxV1, NativePolicySnapshot, PhaseRuleV1};

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
    use haldir_core::time::MonoInstant;

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

    fn decide_vel(action: &RequestedActionV1, st: &TrustedStateSnapshotV1) -> PolicyDecision {
        let ls = lease();
        let pl = policy();
        let hist = BoundedActionHistory::new(16);
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
        let hist = BoundedActionHistory::new(16);
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
}
