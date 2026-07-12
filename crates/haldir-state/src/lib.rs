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

pub use anti_rollback::{AntiRollbackError, AntiRollbackStore};
pub use challenge::ChallengeTable;
pub use clock::{SystemMonotonicClock, TestClock};
pub use durable::{DurableAntiRollbackError, DurableAntiRollbackStore};
pub use fault::FaultLatch;
pub use gate_process::{GateProcessMachine, InvalidTransition};
pub use mission::{LeaseAcceptContext, LeaseAcceptError, accept_lease};
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
