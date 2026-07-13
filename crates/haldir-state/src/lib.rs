//! `haldir-state` — bounded, verified state machines for sessions, controller
//! replay, Gate-output streams, mission leases, anti-rollback, process lifecycle,
//! and the authorization-revision TOCTOU guard.
//!
//! The `model` tests encode the specification's safety invariants (Phase 6 /
//! punch-list) as executable checks. A TLA+ model of the same invariants is
//! authored under `formal/`; the model checker (TLC) is not run in this
//! environment (see `docs/LIMITATIONS.md`), so these executable model tests are
//! the CI-enforced encoding of those properties.
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

pub mod anti_rollback;
pub mod challenge;
pub mod clock;
pub mod durable;
pub mod fault;
pub mod gate_process;
pub mod mission;
pub mod output_stream;
pub mod replay;
pub mod revision;
pub mod session;

/// Crate version string.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub use anti_rollback::{AntiRollbackError, AntiRollbackStore, BootContext};
pub use challenge::ChallengeTable;
pub use clock::{SystemMonotonicClock, TestClock};
pub use durable::{
    BootedDurableAntiRollbackStore, DurableAntiRollbackError, DurableAntiRollbackStore,
};
pub use fault::FaultLatch;
pub use gate_process::{GateProcessMachine, InvalidTransition};
pub use mission::{
    LeaseAcceptContext, LeaseAcceptError, LeaseTermStore, LeaseTermStoreError, accept_lease,
};
pub use output_stream::{GateOutputStreamState, OutputStreamError};
pub use replay::{ControllerReplayState, ReplayClass};
pub use revision::RevisionCounter;
pub use session::{SessionBindOutcome, SessionState};

#[cfg(test)]
mod model {
    //! Executable encoding of the specification's safety invariants.
    use super::*;
    use core::num::{NonZeroU32, NonZeroU64};
    use haldir_contracts::action::{ActionClassV1, CoordinateFrameV1};
    use haldir_contracts::digest::{DigestDomain, DigestV1};
    use haldir_contracts::ids::*;
    use haldir_contracts::lease::MissionLeaseV1;
    use haldir_contracts::limits::MissionLeaseLimitsV1;
    use haldir_contracts::scalar::{
        AsciiId, BoundedAscii, BoundedSet, BoundedVec, CanonicalUuidV4String,
    };
    use haldir_contracts::session::NcpSessionIdentityV1;
    use haldir_core::snapshot::AdmittedControllerSnapshot;
    use haldir_core::time::MonoInstant;
    use proptest::prelude::*;

    fn dig(s: u8) -> DigestV1 {
        DigestV1::compute(DigestDomain::Payload, &[s])
    }
    fn sess(g: u8) -> NcpSessionIdentityV1 {
        NcpSessionIdentityV1 {
            session_id: AsciiId::new("sess-1").unwrap(),
            generation: CanonicalUuidV4String::from_random_bytes([g; 16]),
        }
    }
    fn out_epoch(n: u8) -> GateOutputEpoch {
        GateOutputEpoch::new(CanonicalUuidV4String::from_random_bytes([n; 16]))
    }
    fn controller() -> AdmittedControllerSnapshot {
        AdmittedControllerSnapshot {
            controller_id: ControllerId::new("survey-v1").unwrap(),
            bundle_digest: dig(4),
            backend_profile_digest: dig(5),
            admission_id: AdmissionId::new([4; 16]),
            admission_digest: dig(3),
        }
    }
    fn lease(boot: u8, g: u8, epoch: u8, term: u64) -> MissionLeaseV1 {
        MissionLeaseV1 {
            schema_major: 1,
            schema_minor: 0,
            issuer_id: AsciiId::new("mission-authority").unwrap(),
            issuer_key_id: KeyId::new(vec![1, 2, 3]).unwrap(),
            lease_id: MissionLeaseId::new([2; 16]),
            lease_term: NonZeroU64::new(term).unwrap(),
            gate_id: GateId::new("gate-1").unwrap(),
            gate_boot_id: GateBootId::new([boot; 16]),
            challenge_nonce: ChallengeNonce::new([7; 32]),
            realm: AsciiId::new("range-a").unwrap(),
            vehicle_id: VehicleId::new("uav-1").unwrap(),
            mission_id: MissionId::new("inspect-1").unwrap(),
            mission_phase: AsciiId::new("INSPECTION").unwrap(),
            ncp_session: sess(g),
            gate_output_epoch: out_epoch(epoch),
            controller_id: ControllerId::new("survey-v1").unwrap(),
            controller_intent_key: BoundedAscii::new("veh/uav-1/haldir/intent/survey-v1").unwrap(),
            controller_intent_signing_key_id: KeyId::new(vec![8, 8]).unwrap(),
            admission_id: AdmissionId::new([4; 16]),
            admission_digest: dig(3),
            controller_bundle_digest: dig(4),
            backend_profile_digest: dig(5),
            policy_snapshot_digest: dig(1),
            allowed_actions: BoundedSet::from_iter_checked([
                ActionClassV1::Hold,
                ActionClassV1::VelocityLocalNed,
            ])
            .unwrap(),
            allowed_frames: BoundedSet::from_iter_checked([CoordinateFrameV1::LocalNed]).unwrap(),
            allowed_source_keys: BoundedVec::from_vec(vec![
                BoundedAscii::new("veh/uav-1/state/pose").unwrap(),
            ])
            .unwrap(),
            limits: MissionLeaseLimitsV1 {
                max_output_validity_ms: NonZeroU32::new(500).unwrap(),
                max_linear_speed_mm_s: NonZeroU32::new(3000).unwrap(),
                max_linear_accel_mm_s2: NonZeroU32::new(2000).unwrap(),
                max_linear_slew_mm_s2: NonZeroU32::new(1500).unwrap(),
                max_source_age_ms: NonZeroU32::new(200).unwrap(),
                max_state_age_ms: NonZeroU32::new(200).unwrap(),
                max_continuous_motion_ms: NonZeroU32::new(2000).unwrap(),
                minimum_hold_between_bursts_ms: 500,
            },
            max_active_duration_ms: NonZeroU32::new(60_000).unwrap(),
            max_intent_rate_millihz: NonZeroU32::new(50_000).unwrap(),
            max_total_intents: NonZeroU64::new(100_000).unwrap(),
            operator_context_digest: None,
        }
    }
    fn ctx(boot: u8, g: u8, epoch: u8) -> LeaseAcceptContext {
        LeaseAcceptContext {
            gate_id: GateId::new("gate-1").unwrap(),
            gate_boot_id: GateBootId::new([boot; 16]),
            realm: AsciiId::new("range-a").unwrap(),
            vehicle_id: VehicleId::new("uav-1").unwrap(),
            session: sess(g),
            gate_output_epoch: out_epoch(epoch),
            policy_snapshot_digest: dig(1),
            controller: controller(),
            local_cap_ms: 30_000,
        }
    }
    fn now() -> MonoInstant {
        MonoInstant::from_nanos(1_000_000_000)
    }
    fn table_with_nonce() -> ChallengeTable {
        let mut t = ChallengeTable::new(4);
        t.insert(
            ChallengeNonce::new([7; 32]),
            MonoInstant::from_nanos(u64::MAX),
            now(),
        );
        t
    }

    #[test]
    fn canonical_term_scope_has_stable_versioned_length_framing() {
        let issuer = AsciiId::new("mission-authority").unwrap();
        let vehicle = VehicleId::new("uav-1").unwrap();
        let scope = mission::canonical_term_scope(&issuer, &vehicle);

        let mut expected = b"haldir.state.lease-term-scope.v1\0".to_vec();
        expected.extend_from_slice(&[
            0x82, // two-element array
            0x71, // 17-byte text string
        ]);
        expected.extend_from_slice(b"mission-authority");
        expected.push(0x65); // five-byte text string
        expected.extend_from_slice(b"uav-1");

        assert_eq!(scope, expected);
    }

    #[test]
    fn canonical_term_scope_separates_a_legacy_delimiter_collision() {
        let left_issuer = AsciiId::new("mission:authority").unwrap();
        let left_vehicle = VehicleId::new("uav").unwrap();
        let right_issuer = AsciiId::new("mission").unwrap();
        let right_vehicle = VehicleId::new("authority:uav").unwrap();

        assert_ne!(
            mission::canonical_term_scope(&left_issuer, &left_vehicle),
            mission::canonical_term_scope(&right_issuer, &right_vehicle)
        );
    }

    proptest! {
        #[test]
        fn canonical_term_scope_is_injective_for_distinct_bounded_pairs(
            issuer_a in "[A-Za-z0-9._:-]{1,16}",
            vehicle_a in "[A-Za-z0-9._:-]{1,16}",
            issuer_b in "[A-Za-z0-9._:-]{1,16}",
            vehicle_b in "[A-Za-z0-9._:-]{1,16}",
        ) {
            prop_assume!(issuer_a != issuer_b || vehicle_a != vehicle_b);
            let issuer_a = AsciiId::new(&issuer_a).unwrap();
            let vehicle_a = VehicleId::new(&vehicle_a).unwrap();
            let issuer_b = AsciiId::new(&issuer_b).unwrap();
            let vehicle_b = VehicleId::new(&vehicle_b).unwrap();

            prop_assert_ne!(
                mission::canonical_term_scope(&issuer_a, &vehicle_a),
                mission::canonical_term_scope(&issuer_b, &vehicle_b)
            );
        }
    }

    #[test]
    fn lease_accepts_and_anchors_deadline() {
        let mut ch = table_with_nonce();
        let mut ar = AntiRollbackStore::new_empty();
        let snap =
            accept_lease(&lease(1, 1, 1, 10), &ctx(1, 1, 1), &mut ch, &mut ar, now()).unwrap();
        assert_eq!(snap.lease_term, 10);
        assert_eq!(snap.remaining_ms(now()), 30_000);
        assert!(!ch.is_pending(&ChallengeNonce::new([7; 32]), now()));
    }

    #[test]
    fn restart_invalidates_lease_via_new_boot_id() {
        let mut ch = table_with_nonce();
        let mut ar = AntiRollbackStore::new_empty();
        let err = accept_lease(
            &lease(0xAA, 1, 1, 10),
            &ctx(0xBB, 1, 1),
            &mut ch,
            &mut ar,
            now(),
        )
        .unwrap_err();
        assert_eq!(err, LeaseAcceptError::GateBootMismatch);
    }

    #[test]
    fn stale_session_generation_is_scope_mismatch() {
        let mut ch = table_with_nonce();
        let mut ar = AntiRollbackStore::new_empty();
        let err =
            accept_lease(&lease(1, 2, 1, 10), &ctx(1, 1, 1), &mut ch, &mut ar, now()).unwrap_err();
        assert_eq!(err, LeaseAcceptError::ScopeMismatch);
    }

    #[test]
    fn lease_term_rollback_rejected_after_high_water_advanced() {
        let mut ar = AntiRollbackStore::new_empty();
        let mut ch = table_with_nonce();
        accept_lease(&lease(1, 1, 1, 10), &ctx(1, 1, 1), &mut ch, &mut ar, now()).unwrap();
        let mut ch2 = table_with_nonce();
        let err =
            accept_lease(&lease(1, 1, 1, 10), &ctx(1, 1, 1), &mut ch2, &mut ar, now()).unwrap_err();
        assert_eq!(err, LeaseAcceptError::TermRollback);
    }

    #[test]
    fn formerly_colliding_issuer_vehicle_pairs_have_independent_terms() {
        let mut anti_rollback = AntiRollbackStore::new_empty();

        let mut left = lease(1, 1, 1, 10);
        left.issuer_id = AsciiId::new("mission:authority").unwrap();
        left.vehicle_id = VehicleId::new("uav").unwrap();
        let mut left_ctx = ctx(1, 1, 1);
        left_ctx.vehicle_id = left.vehicle_id.clone();
        accept_lease(
            &left,
            &left_ctx,
            &mut table_with_nonce(),
            &mut anti_rollback,
            now(),
        )
        .unwrap();

        let mut right = lease(1, 1, 1, 10);
        right.issuer_id = AsciiId::new("mission").unwrap();
        right.vehicle_id = VehicleId::new("authority:uav").unwrap();
        let mut right_ctx = ctx(1, 1, 1);
        right_ctx.vehicle_id = right.vehicle_id.clone();
        accept_lease(
            &right,
            &right_ctx,
            &mut table_with_nonce(),
            &mut anti_rollback,
            now(),
        )
        .unwrap();
    }

    #[test]
    fn legacy_scope_high_water_remains_a_conservative_upgrade_floor() {
        let mut anti_rollback = AntiRollbackStore::new_empty();
        anti_rollback
            .accept_term(b"lease:mission-authority:uav-1", 10)
            .unwrap();

        let mut challenges = table_with_nonce();
        let err = accept_lease(
            &lease(1, 1, 1, 10),
            &ctx(1, 1, 1),
            &mut challenges,
            &mut anti_rollback,
            now(),
        )
        .unwrap_err();
        assert_eq!(err, LeaseAcceptError::TermRollback);
        assert!(challenges.is_pending(&ChallengeNonce::new([7; 32]), now()));

        accept_lease(
            &lease(1, 1, 1, 11),
            &ctx(1, 1, 1),
            &mut challenges,
            &mut anti_rollback,
            now(),
        )
        .unwrap();
        let canonical = mission::canonical_term_scope(
            &AsciiId::new("mission-authority").unwrap(),
            &VehicleId::new("uav-1").unwrap(),
        );
        assert_eq!(anti_rollback.highest_term(&canonical), 11);
    }

    #[test]
    fn realm_gate_boot_session_and_key_rotation_do_not_reset_term_high_water() {
        let mut anti_rollback = AntiRollbackStore::new_empty();
        accept_lease(
            &lease(1, 1, 1, 10),
            &ctx(1, 1, 1),
            &mut table_with_nonce(),
            &mut anti_rollback,
            now(),
        )
        .unwrap();

        let mut rotated = lease(2, 2, 2, 10);
        rotated.issuer_key_id = KeyId::new(vec![9, 9]).unwrap();
        rotated.gate_id = GateId::new("gate-2").unwrap();
        rotated.realm = AsciiId::new("range-b").unwrap();
        let mut rotated_ctx = ctx(2, 2, 2);
        rotated_ctx.gate_id = rotated.gate_id.clone();
        rotated_ctx.realm = rotated.realm.clone();

        let err = accept_lease(
            &rotated,
            &rotated_ctx,
            &mut table_with_nonce(),
            &mut anti_rollback,
            now(),
        )
        .unwrap_err();
        assert_eq!(err, LeaseAcceptError::TermRollback);
    }

    struct UnavailableTermStore;

    impl LeaseTermStore for UnavailableTermStore {
        fn highest_term(&self, _scope: &[u8]) -> u64 {
            0
        }

        fn commit_term(&mut self, _scope: &[u8], _term: u64) -> Result<(), LeaseTermStoreError> {
            Err(LeaseTermStoreError::Unavailable)
        }
    }

    #[test]
    fn durable_term_failure_keeps_challenge_pending_and_grants_no_lease() {
        let nonce = ChallengeNonce::new([7; 32]);
        let mut challenges = table_with_nonce();
        let mut store = UnavailableTermStore;

        let result = accept_lease(
            &lease(1, 1, 1, 10),
            &ctx(1, 1, 1),
            &mut challenges,
            &mut store,
            now(),
        );

        assert_eq!(result.unwrap_err(), LeaseAcceptError::TermStoreUnavailable);
        assert!(challenges.is_pending(&nonce, now()));
    }

    #[test]
    fn deny_consumes_replay_but_produces_no_output() {
        let mut replay = ControllerReplayState::new(8);
        let output = GateOutputStreamState::new(out_epoch(1), 8);
        let ep = IntentEpoch::new([6; 16]);
        replay.commit_consume(ep, 1).unwrap();
        assert_eq!(output.peek_next_seq(), 1, "no output allocated on deny");
        assert_eq!(replay.consumed_count(), 1);
        assert!(replay.commit_consume(ep, 1).is_err());
        assert_eq!(output.peek_next_seq(), 1);
    }

    #[test]
    fn allow_allocates_exactly_one_increasing_output() {
        let mut output = GateOutputStreamState::new(out_epoch(1), 8);
        let a = output.allocate().unwrap();
        let b = output.allocate().unwrap();
        assert!(a.get() < b.get());
        assert_ne!(a.get(), b.get());
    }

    #[test]
    fn authorization_revision_bump_defeats_toctou() {
        let mut rev = RevisionCounter::new();
        let captured = rev.get();
        rev.bump();
        assert_ne!(rev.get(), captured);
    }

    #[test]
    fn session_rebind_reports_generation_change() {
        let mut s = SessionState::new();
        assert_eq!(s.bind(sess(1)), SessionBindOutcome::NewBinding);
        assert_eq!(s.bind(sess(1)), SessionBindOutcome::Unchanged);
        assert_eq!(s.bind(sess(2)), SessionBindOutcome::GenerationChanged);
        assert!(!s.matches(&sess(1)));
    }
}
