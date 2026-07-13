//! `haldir-gate` — composition of the pure Haldir subsystems into one one-vehicle
//! authorization runtime with explicit side-effect boundaries.
//!
//! The end-to-end path is: trusted state + signed controller intent -> the
//! 13-stage [`actor::VehicleActor::decide_intent`] pipeline -> opaque prepared
//! output -> explicit modeled publication call -> deterministic reference plant ->
//! staged evidence. This is the P0
//! `assurance-reference-v1` profile: in-process, deterministic, no live transport,
//! no neural runtime, no physical hardware (see `docs/LIMITATIONS.md`).
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

pub mod actor;
pub mod startup;

/// Crate version string.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub use actor::{
    DecisionRecord, GateConfig, GateConfigError, GateError, GateStartupError, PreparedPublication,
    PublicationError, PublicationState, PublishCalledPublication, VehicleActor,
};
pub use startup::{
    DurableGateStartupError, EntropyError, EntropySource, GateConfigTemplate, JournalBindingError,
    JournalBoundRunningGate, LocalStartupConfig, OsEntropy, PublicationJournalConfigError,
    PublicationJournalStartupConfig, RunningGate, StartupProfile, StartupReport,
    StartupStateConfig, StateOpenMode, start_local, start_with_backends,
};

#[cfg(test)]
mod e2e {
    use super::*;
    #[cfg(feature = "live-zenoh")]
    use crate::startup::publication_coordinator::StrictPublisherCallError;
    use crate::startup::publication_coordinator::{
        CallTransition, DecideError, DecisionTransition, DecisionUnavailable,
        DurableCalledPublication, DurablePreparedPublication, JournaledReturnedError,
        JournaledReturnedOk, OutputCapacityPermit, OutputCapacityPool, PublicationCoordinator,
        PublishOnceError, ReadyDecision,
    };
    use core::num::{NonZeroU32, NonZeroU64, NonZeroUsize};
    use haldir_admission::{AdmissionLevelV1, AdmissionRecordV1, AdmissionSnapshot};
    use haldir_contracts::action::{ActionClassV1, CoordinateFrameV1, RequestedActionV1};
    use haldir_contracts::cbor::Limits;
    use haldir_contracts::digest::{DigestDomain, DigestV1};
    use haldir_contracts::ids::*;
    use haldir_contracts::intent::HaldirIntentV1;
    use haldir_contracts::lease::MissionLeaseV1;
    use haldir_contracts::limits::MissionLeaseLimitsV1;
    use haldir_contracts::receipt::DecisionReceiptV1;
    use haldir_contracts::receipt::{DecisionOutcomeV1, DecisionReasonCodeV1, PublishStageV1};
    use haldir_contracts::scalar::{
        AsciiId, BoundedAscii, BoundedSet, BoundedVec, CanonicalUuidV4String,
    };
    use haldir_contracts::session::{HaldirIntentPositionV1, NcpSessionIdentityV1, NcpSourceRefV1};
    use haldir_contracts::status::{
        AclExclusiveEvidenceV1, GateProcessStateV1, NcpLeaseEvidenceV1,
        PlantPublicationAuthorityStateV1,
    };
    use haldir_core::snapshot::{
        KinematicStateFixedV1, StateUncertaintyFixedV1, TrustedStateSnapshotV1,
        VerifiedSourceStateV1,
    };
    use haldir_core::time::{MonoInstant, MonotonicClock};
    use haldir_crypto::{
        ExpectedContext, KeyClass, KeyRecord, KeyRole, RevocationSnapshot, SigningKey, TrustStore,
        sign_message, verify_and_decode,
    };
    use haldir_durable::{
        Anchor, AnchorProtection, DurableError, GenerationAnchor, SnapshotBinding, SnapshotStorage,
        StorageMacKey, StoreId,
    };
    use haldir_evidence::gate_journal::RecoveredGateJournal;
    use haldir_evidence::journal::JournalBounds;
    use haldir_evidence::manager::{JournalLimits, JournalOpenOptions, RecoveryCaptureLimits};
    use haldir_evidence::publication::PublicationTraceState;
    use haldir_policy_native::{GeofenceBoxV1, NativePolicySnapshot, PhaseRuleV1};
    use haldir_reference_plant::{PlantConfig, PlantEventKind, ReferencePlant};
    use haldir_state::{BootedDurableAntiRollbackStore, DurableAntiRollbackStore};
    use std::collections::BTreeMap;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll, Waker};

    const INTENT_KEY: &str = "veh/uav-1/haldir/intent/survey-v1";

    fn poll_once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
        let mut context = Context::from_waker(Waker::noop());
        future.poll(&mut context)
    }

    #[derive(Debug, PartialEq, Eq)]
    struct TestPublishError;

    struct TestPublisher {
        drops: Arc<AtomicUsize>,
    }

    impl Drop for TestPublisher {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct PendingPublish {
        polls: Arc<AtomicUsize>,
    }

    impl Future for PendingPublish {
        type Output = Result<(), TestPublishError>;

        fn poll(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Self::Output> {
            self.get_mut().polls.fetch_add(1, Ordering::SeqCst);
            Poll::Pending
        }
    }

    fn kid(seed: u8) -> KeyId {
        KeyId::new(vec![seed, 0xAB, seed]).unwrap()
    }
    fn uuid(s: u8) -> CanonicalUuidV4String {
        CanonicalUuidV4String::from_random_bytes([s; 16])
    }
    fn sess() -> NcpSessionIdentityV1 {
        NcpSessionIdentityV1 {
            session_id: AsciiId::new("sess-1").unwrap(),
            generation: uuid(1),
        }
    }
    fn source() -> NcpSourceRefV1 {
        NcpSourceRefV1 {
            source_key: BoundedAscii::new("veh/uav-1/state/pose").unwrap(),
            stream_epoch: uuid(2),
            stream_seq: SourceSeq::new(NonZeroU64::new(7).unwrap()),
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

    struct Fixture {
        actor: VehicleActor,
        ctrl_sk: SigningKey,
        now: MonoInstant,
        admission_digest: DigestV1,
    }

    fn admission_record() -> AdmissionRecordV1 {
        AdmissionRecordV1 {
            schema_major: 1,
            schema_minor: 0,
            issuer_id: AsciiId::new("admission-authority").unwrap(),
            admission_id: AdmissionId::new([4; 16]),
            controller_id: ControllerId::new("survey-v1").unwrap(),
            admission_profile_id: AsciiId::new("fixed-weight-lif-control-v1").unwrap(),
            level: AdmissionLevelV1::A2ReferenceConformance,
            controller_bundle_digest: DigestV1::compute(DigestDomain::Bundle, b"bundle"),
            backend_profile_digest: DigestV1::compute(DigestDomain::BackendProfile, b"nest-3.9"),
            codec_digest: DigestV1::compute(DigestDomain::Payload, b"codec"),
            validity_term: NonZeroU64::new(1).unwrap(),
            conformance_run_digest: None,
        }
    }

    fn build_lease(admission_digest: DigestV1, rec: &AdmissionRecordV1) -> MissionLeaseV1 {
        MissionLeaseV1 {
            schema_major: 1,
            schema_minor: 0,
            issuer_id: AsciiId::new("mission-authority").unwrap(),
            issuer_key_id: kid(2),
            lease_id: MissionLeaseId::new([2; 16]),
            lease_term: NonZeroU64::new(10).unwrap(),
            gate_id: GateId::new("gate-1").unwrap(),
            gate_boot_id: GateBootId::new([9; 16]),
            challenge_nonce: ChallengeNonce::new([7; 32]),
            realm: AsciiId::new("range-a").unwrap(),
            vehicle_id: VehicleId::new("uav-1").unwrap(),
            mission_id: MissionId::new("inspect-1").unwrap(),
            mission_phase: AsciiId::new("INSPECTION").unwrap(),
            ncp_session: sess(),
            gate_output_epoch: GateOutputEpoch::new(uuid(5)),
            controller_id: ControllerId::new("survey-v1").unwrap(),
            controller_intent_key: BoundedAscii::new(INTENT_KEY).unwrap(),
            controller_intent_signing_key_id: kid(1),
            admission_id: AdmissionId::new([4; 16]),
            admission_digest,
            controller_bundle_digest: rec.controller_bundle_digest,
            backend_profile_digest: rec.backend_profile_digest,
            policy_snapshot_digest: DigestV1::compute(DigestDomain::PolicySnapshot, b"policy"),
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
                max_linear_slew_mm_s2: NonZeroU32::new(100_000).unwrap(),
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

    fn trusted_state(now: MonoInstant) -> TrustedStateSnapshotV1 {
        TrustedStateSnapshotV1 {
            vehicle_id: VehicleId::new("uav-1").unwrap(),
            session: sess(),
            captured_mono: now,
            primary_source: VerifiedSourceStateV1 {
                source: source(),
                session: sess(),
                frame_id: BoundedAscii::new("map").unwrap(),
                publisher_t_ns: 111,
                receive_mono: now,
                valid: true,
            },
            kinematic: KinematicStateFixedV1 {
                position_mm: [0, 0, 0],
                velocity_mm_s: [0, 0, 0],
            },
            uncertainty: StateUncertaintyFixedV1 {
                position_mm: [10, 10, 10],
                velocity_mm_s: [0, 0, 0],
            },
            mission_phase: AsciiId::new("INSPECTION").unwrap(),
            plant_mode: AsciiId::new("NOMINAL").unwrap(),
        }
    }

    fn build_intent(
        admission_digest: DigestV1,
        rec: &AdmissionRecordV1,
        seq: u64,
        action: RequestedActionV1,
    ) -> HaldirIntentV1 {
        HaldirIntentV1 {
            schema_major: 1,
            schema_minor: 0,
            controller_id: ControllerId::new("survey-v1").unwrap(),
            controller_instance_id: ControllerInstanceId::new([1; 16]),
            controller_signing_key_id: kid(1),
            actual_intent_key: BoundedAscii::new(INTENT_KEY).unwrap(),
            gate_id: GateId::new("gate-1").unwrap(),
            gate_boot_id: GateBootId::new([9; 16]),
            realm: AsciiId::new("range-a").unwrap(),
            vehicle_id: VehicleId::new("uav-1").unwrap(),
            mission_id: MissionId::new("inspect-1").unwrap(),
            ncp_session: sess(),
            mission_lease_id: MissionLeaseId::new([2; 16]),
            mission_lease_term: NonZeroU64::new(10).unwrap(),
            admission_id: AdmissionId::new([4; 16]),
            admission_digest,
            controller_bundle_digest: rec.controller_bundle_digest,
            backend_profile_digest: rec.backend_profile_digest,
            intent_position: HaldirIntentPositionV1 {
                epoch: IntentEpoch::new([6; 16]),
                seq: IntentSeq::new(NonZeroU64::new(seq).unwrap()),
            },
            controller_t_ns: 1,
            primary_source: source(),
            input_watermarks: BoundedVec::new(),
            action,
            controller_context_digest: None,
        }
    }

    fn acl_publication() -> PlantPublicationAuthorityStateV1 {
        PlantPublicationAuthorityStateV1::AclExclusiveV1(AclExclusiveEvidenceV1 {
            gate_transport_principal: PrincipalId::new("gate.range-a").unwrap(),
            final_route_digest: DigestV1::compute(DigestDomain::Payload, b"route"),
            certificate_fingerprint: DigestV1::compute(DigestDomain::Payload, b"cert"),
            acl_policy_digest: DigestV1::compute(DigestDomain::Payload, b"acl"),
            verified_at_mono_ns: 900,
        })
    }

    fn setup() -> Fixture {
        setup_with_publication(acl_publication())
    }

    #[cfg(feature = "real-ncp")]
    fn setup_with_adapter(ncp_adapter: haldir_ncp08::SelectedNcpCommandAdapter) -> Fixture {
        let ctrl_sk = SigningKey::from_seed([1; 32]);
        let mission_sk = SigningKey::from_seed([2; 32]);
        let gate_sk = SigningKey::from_seed([3; 32]);
        let now = MonoInstant::from_nanos(1_000_000_000);
        let (mut cfg, rec, admission_digest) =
            gate_config(acl_publication(), &ctrl_sk, &mission_sk, gate_sk);
        cfg.ncp_adapter = ncp_adapter;
        activate_fixture(cfg, rec, admission_digest, ctrl_sk, mission_sk, now)
    }

    fn gate_config(
        publication: PlantPublicationAuthorityStateV1,
        ctrl_sk: &SigningKey,
        mission_sk: &SigningKey,
        gate_sk: SigningKey,
    ) -> (GateConfig, AdmissionRecordV1, DigestV1) {
        let mut trust = TrustStore::new();
        trust
            .insert(KeyRecord {
                kid: kid(1),
                role: KeyRole::ControllerIntent,
                verifying_key: ctrl_sk.verifying_key(),
                subject: Some("survey-v1".to_owned()),
                class: KeyClass::Assurance,
            })
            .unwrap();
        trust
            .insert(KeyRecord {
                kid: kid(2),
                role: KeyRole::MissionAuthority,
                verifying_key: mission_sk.verifying_key(),
                subject: Some("mission-authority".to_owned()),
                class: KeyClass::Assurance,
            })
            .unwrap();
        // The Gate application key that signs decision receipts (H-B02). Enrolled
        // to the Gate's own id so a receipt verifier can bind signer→gate (H-H03).
        trust
            .insert(KeyRecord {
                kid: kid(3),
                role: KeyRole::GateApplication,
                verifying_key: gate_sk.verifying_key(),
                subject: Some("gate-1".to_owned()),
                class: KeyClass::Assurance,
            })
            .unwrap();

        let rec = admission_record();
        let admission_digest = rec.admission_digest();
        let mut admission = AdmissionSnapshot::new();
        admission.insert(rec.clone());

        let policy_snapshot_digest = DigestV1::compute(DigestDomain::PolicySnapshot, b"policy");
        let cfg = GateConfig {
            gate_id: GateId::new("gate-1").unwrap(),
            gate_boot_id: GateBootId::new([9; 16]),
            realm: AsciiId::new("range-a").unwrap(),
            vehicle_id: VehicleId::new("uav-1").unwrap(),
            trust,
            revocations: RevocationSnapshot::new(),
            admission,
            policy: policy(),
            policy_snapshot_digest,
            session: sess(),
            ncp_adapter: haldir_ncp08::SelectedNcpCommandAdapter::modeled_p0(),
            publication,
            output_epoch: GateOutputEpoch::new(uuid(5)),
            local_cap_ms: 30_000,
            gate_signer: gate_sk,
            gate_signer_kid: kid(3),
        };
        (cfg, rec, admission_digest)
    }

    fn valid_config(publication: PlantPublicationAuthorityStateV1) -> GateConfig {
        let ctrl_sk = SigningKey::from_seed([1; 32]);
        let mission_sk = SigningKey::from_seed([2; 32]);
        let gate_sk = SigningKey::from_seed([3; 32]);
        gate_config(publication, &ctrl_sk, &mission_sk, gate_sk).0
    }

    #[derive(Clone, Default)]
    struct GateMemoryStorage {
        bytes: Arc<Mutex<Option<Vec<u8>>>>,
        fail_replace: Arc<AtomicBool>,
    }

    impl SnapshotStorage for GateMemoryStorage {
        fn load(&self) -> Result<Option<Vec<u8>>, DurableError> {
            Ok(self.bytes.lock().unwrap().clone())
        }

        fn replace(&mut self, bytes: &[u8]) -> Result<(), DurableError> {
            if self.fail_replace.load(Ordering::SeqCst) {
                return Err(DurableError::Storage);
            }
            *self.bytes.lock().unwrap() = Some(bytes.to_vec());
            Ok(())
        }
    }

    #[derive(Clone, Default)]
    struct GateMemoryAnchor(Arc<Mutex<BTreeMap<StoreId, Anchor>>>);

    impl GenerationAnchor for GateMemoryAnchor {
        fn protection(&self) -> AnchorProtection {
            AnchorProtection::EphemeralTest
        }

        fn read(&self, store_id: StoreId) -> Result<Option<Anchor>, DurableError> {
            Ok(self.0.lock().unwrap().get(&store_id).copied())
        }

        fn compare_and_set(
            &mut self,
            store_id: StoreId,
            expected: Option<Anchor>,
            next: Anchor,
        ) -> Result<(), DurableError> {
            if self.0.lock().unwrap().get(&store_id).copied() != expected {
                return Err(DurableError::AnchorConflict);
            }
            self.0.lock().unwrap().insert(store_id, next);
            Ok(())
        }
    }

    fn fresh_booted_store(
        storage: GateMemoryStorage,
    ) -> BootedDurableAntiRollbackStore<GateMemoryStorage, GateMemoryAnchor> {
        let gate_id = GateId::new("gate-1").unwrap();
        let store = DurableAntiRollbackStore::provision_new(
            storage,
            GateMemoryAnchor::default(),
            StorageMacKey::new([7; 32]),
            SnapshotBinding::new(StoreId::new([1; 16]), gate_id.as_str().as_bytes()),
            4096,
        )
        .unwrap();
        store.begin_boot(&gate_id, [3; 32]).unwrap().0
    }

    fn gate_only_trust(
        signing_seed: u8,
        role: KeyRole,
        subject: Option<&str>,
        class: KeyClass,
    ) -> TrustStore {
        let mut trust = TrustStore::new();
        trust
            .insert(KeyRecord {
                kid: kid(3),
                role,
                verifying_key: SigningKey::from_seed([signing_seed; 32]).verifying_key(),
                subject: subject.map(str::to_owned),
                class,
            })
            .unwrap();
        trust
    }

    fn ncp_publication(
        session: NcpSessionIdentityV1,
        output_epoch: GateOutputEpoch,
    ) -> PlantPublicationAuthorityStateV1 {
        PlantPublicationAuthorityStateV1::NcpLeaseV1(NcpLeaseEvidenceV1 {
            gate_transport_principal: PrincipalId::new("gate.range-a").unwrap(),
            final_route_digest: DigestV1::compute(DigestDomain::Payload, b"route"),
            session,
            authority_term: NonZeroU64::new(1).unwrap(),
            lease_id: AuthorityLeaseId::new([8; 16]),
            authorized_output_epoch: output_epoch,
            expires_mono_ns: Some(u64::MAX),
        })
    }

    #[test]
    fn gate_config_accepts_consistent_assurance_configuration() {
        let cfg = valid_config(acl_publication());

        assert_eq!(cfg.validate(), Ok(()));
    }

    #[test]
    fn vehicle_actor_remains_send_for_threaded_runtimes() {
        fn assert_send<T: Send>() {}

        assert_send::<VehicleActor>();
    }

    #[test]
    fn vehicle_actor_new_rejects_zero_local_cap() {
        let mut cfg = valid_config(acl_publication());
        cfg.local_cap_ms = 0;

        let result = VehicleActor::new(cfg);

        assert!(matches!(
            result,
            Err(GateStartupError::Config(GateConfigError::LocalCapZero))
        ));
    }

    #[test]
    fn recovered_actor_requires_exact_committed_boot_context() {
        let cfg = valid_config(acl_publication());
        let store = fresh_booted_store(GateMemoryStorage::default());
        assert_ne!(cfg.gate_boot_id, store.boot_context().gate_boot_id);

        let result = VehicleActor::new_recovered(cfg, store);

        assert!(matches!(result, Err(GateStartupError::BootContextMismatch)));
    }

    #[test]
    fn recovered_actor_rejects_booted_store_for_another_gate() {
        let mut cfg = valid_config(acl_publication());
        cfg.gate_id = GateId::new("gate-2").unwrap();
        let store = fresh_booted_store(GateMemoryStorage::default());

        let result = VehicleActor::new_recovered(cfg, store);

        assert!(matches!(result, Err(GateStartupError::StoreGateMismatch)));
    }

    #[test]
    fn recovered_actor_faults_when_term_commit_is_unavailable() {
        let ctrl_sk = SigningKey::from_seed([1; 32]);
        let mission_sk = SigningKey::from_seed([2; 32]);
        let gate_sk = SigningKey::from_seed([3; 32]);
        let (mut cfg, rec, admission_digest) =
            gate_config(acl_publication(), &ctrl_sk, &mission_sk, gate_sk);
        let storage = GateMemoryStorage::default();
        let store = fresh_booted_store(storage.clone());
        let gate_boot_id = store.boot_context().gate_boot_id;
        cfg.gate_boot_id = gate_boot_id;
        storage.fail_replace.store(true, Ordering::SeqCst);
        let mut actor = VehicleActor::new_recovered(cfg, store).unwrap();
        let now = MonoInstant::from_nanos(1_000_000_000);
        assert!(actor.register_challenge(
            ChallengeNonce::new([7; 32]),
            MonoInstant::from_nanos(u64::MAX),
            now,
        ));
        let mut lease = build_lease(admission_digest, &rec);
        lease.gate_boot_id = gate_boot_id;
        let lease_env = sign_message(&lease, MissionLeaseV1::KIND, 1, &kid(2), &mission_sk);

        let result = actor.accept_lease_env(&lease_env, now);

        assert_eq!(result, Err(GateError::Faulted));
        assert_eq!(actor.process_state(), GateProcessStateV1::FaultLatched);
        assert_eq!(
            actor.accept_lease_env(&lease_env, now),
            Err(GateError::Faulted)
        );
    }

    #[test]
    fn gate_config_rejects_unknown_gate_signer_kid() {
        let mut cfg = valid_config(acl_publication());
        cfg.trust = TrustStore::new();

        assert_eq!(cfg.validate(), Err(GateConfigError::GateSignerKidUnknown));
    }

    #[test]
    fn gate_config_rejects_revoked_gate_signer_kid() {
        let mut cfg = valid_config(acl_publication());
        cfg.revocations.revoke_key(&kid(3), 1);

        assert_eq!(cfg.validate(), Err(GateConfigError::GateSignerKidRevoked));
    }

    #[test]
    fn gate_config_rejects_wrong_gate_signer_role() {
        let mut cfg = valid_config(acl_publication());
        cfg.trust = gate_only_trust(
            3,
            KeyRole::ControllerIntent,
            Some("gate-1"),
            KeyClass::Assurance,
        );

        assert_eq!(cfg.validate(), Err(GateConfigError::GateSignerRoleMismatch));
    }

    #[test]
    fn gate_config_rejects_development_gate_signer() {
        let mut cfg = valid_config(acl_publication());
        cfg.trust = gate_only_trust(
            3,
            KeyRole::GateApplication,
            Some("gate-1"),
            KeyClass::Development,
        );

        assert_eq!(cfg.validate(), Err(GateConfigError::GateSignerNotAssurance));
    }

    #[test]
    fn gate_config_rejects_gate_signer_for_another_subject() {
        let mut cfg = valid_config(acl_publication());
        cfg.trust = gate_only_trust(
            3,
            KeyRole::GateApplication,
            Some("gate-2"),
            KeyClass::Assurance,
        );

        assert_eq!(
            cfg.validate(),
            Err(GateConfigError::GateSignerSubjectMismatch)
        );
    }

    #[test]
    fn gate_config_rejects_gate_signer_public_key_mismatch() {
        let mut cfg = valid_config(acl_publication());
        cfg.trust = gate_only_trust(
            4,
            KeyRole::GateApplication,
            Some("gate-1"),
            KeyClass::Assurance,
        );

        assert_eq!(
            cfg.validate(),
            Err(GateConfigError::GateSignerPublicKeyMismatch)
        );
    }

    #[test]
    fn gate_config_rejects_publication_for_another_session() {
        let mut other_session = sess();
        other_session.generation = uuid(9);
        let publication = ncp_publication(other_session, GateOutputEpoch::new(uuid(5)));
        let cfg = valid_config(publication);

        assert_eq!(
            cfg.validate(),
            Err(GateConfigError::PublicationSessionMismatch)
        );
    }

    #[test]
    fn gate_config_rejects_publication_for_another_output_epoch() {
        let publication = ncp_publication(sess(), GateOutputEpoch::new(uuid(9)));
        let cfg = valid_config(publication);

        assert_eq!(
            cfg.validate(),
            Err(GateConfigError::PublicationOutputEpochMismatch)
        );
    }

    fn setup_with_publication(publication: PlantPublicationAuthorityStateV1) -> Fixture {
        let ctrl_sk = SigningKey::from_seed([1; 32]);
        let mission_sk = SigningKey::from_seed([2; 32]);
        let gate_sk = SigningKey::from_seed([3; 32]);
        let now = MonoInstant::from_nanos(1_000_000_000);
        let (cfg, rec, admission_digest) = gate_config(publication, &ctrl_sk, &mission_sk, gate_sk);
        activate_fixture(cfg, rec, admission_digest, ctrl_sk, mission_sk, now)
    }

    fn activate_fixture(
        cfg: GateConfig,
        rec: AdmissionRecordV1,
        admission_digest: DigestV1,
        ctrl_sk: SigningKey,
        mission_sk: SigningKey,
        now: MonoInstant,
    ) -> Fixture {
        let mut actor = VehicleActor::new(cfg).expect("valid Gate configuration");
        actor.register_challenge(
            ChallengeNonce::new([7; 32]),
            MonoInstant::from_nanos(u64::MAX),
            now,
        );

        let lease_env = sign_message(
            &build_lease(admission_digest, &rec),
            MissionLeaseV1::KIND,
            1,
            &kid(2),
            &mission_sk,
        );
        actor
            .accept_lease_env(&lease_env, now)
            .expect("lease accepted");
        // Capture the initial snapshot 1 ms before decision time so a later re-set
        // at `now` strictly advances the anti-rollback capture clock (H-B05).
        let mut initial = trusted_state(now);
        initial.captured_mono = MonoInstant::from_nanos(now.as_nanos() - 1_000_000);
        actor.set_trusted_state(initial).unwrap();

        Fixture {
            actor,
            ctrl_sk,
            now,
            admission_digest,
        }
    }

    fn sign_intent(sk: &SigningKey, intent: &HaldirIntentV1) -> Vec<u8> {
        sign_message(intent, HaldirIntentV1::KIND, 1, &kid(1), sk)
    }

    fn velocity(seq: u64, n: i32) -> RequestedActionV1 {
        let _ = seq;
        RequestedActionV1::VelocityLocalNed {
            north_mm_s: n,
            east_mm_s: 0,
            down_mm_s: 0,
            requested_validity_ms: NonZeroU32::new(300).unwrap(),
        }
    }

    static COORDINATOR_DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct CoordinatorTestDirectory(std::path::PathBuf);

    impl CoordinatorTestDirectory {
        fn new() -> Self {
            let sequence = COORDINATOR_DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "haldir-publication-coordinator-test-{}-{sequence}",
                std::process::id()
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for CoordinatorTestDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    struct SharedClockState {
        nanoseconds: AtomicU64,
        scripted_samples: Mutex<std::collections::VecDeque<u64>>,
    }

    #[derive(Clone)]
    struct SharedClock(Arc<SharedClockState>);

    impl SharedClock {
        fn new(start: MonoInstant) -> Self {
            Self(Arc::new(SharedClockState {
                nanoseconds: AtomicU64::new(start.as_nanos()),
                scripted_samples: Mutex::new(std::collections::VecDeque::new()),
            }))
        }

        fn advance_ms(&self, milliseconds: u64) {
            self.0
                .nanoseconds
                .fetch_add(milliseconds.saturating_mul(1_000_000), Ordering::SeqCst);
        }

        fn set_ns(&self, nanoseconds: u64) {
            self.0.nanoseconds.store(nanoseconds, Ordering::SeqCst);
        }

        fn script_samples(&self, samples: impl IntoIterator<Item = MonoInstant>) {
            let mut scripted = self.0.scripted_samples.lock().unwrap();
            scripted.extend(samples.into_iter().map(MonoInstant::as_nanos));
        }
    }

    impl MonotonicClock for SharedClock {
        fn now(&self) -> MonoInstant {
            let scripted = self.0.scripted_samples.lock().unwrap().pop_front();
            if let Some(nanoseconds) = scripted {
                self.0.nanoseconds.store(nanoseconds, Ordering::SeqCst);
                MonoInstant::from_nanos(nanoseconds)
            } else {
                MonoInstant::from_nanos(self.0.nanoseconds.load(Ordering::SeqCst))
            }
        }
    }

    struct CoordinatorFixture {
        coordinator: PublicationCoordinator<SharedClock>,
        clock: SharedClock,
        output_pool: OutputCapacityPool,
        ctrl_sk: SigningKey,
        admission_digest: DigestV1,
        _directory: CoordinatorTestDirectory,
    }

    fn coordinator_journal_limits() -> JournalLimits {
        let segment_bounds = JournalBounds::new(128 * 1024, 8, 32 * 1024).unwrap();
        JournalLimits::new(segment_bounds, 32, 4 * 1024 * 1024).unwrap()
    }

    const fn coordinator_capture_limits(max_records: u64) -> RecoveryCaptureLimits {
        RecoveryCaptureLimits::new(max_records, 4 * 1024 * 1024)
    }

    fn coordinator_fixture(max_recovery_records: u64) -> CoordinatorFixture {
        coordinator_fixture_with_counter(max_recovery_records, None)
    }

    fn coordinator_fixture_with_counter(
        max_recovery_records: u64,
        next_decision: Option<u64>,
    ) -> CoordinatorFixture {
        let mut fixture = setup();
        if let Some(next_decision) = next_decision {
            fixture.actor.force_next_decision_for_test(next_decision);
        }
        let directory = CoordinatorTestDirectory::new();
        let journal_directory = directory.0.join("journal");
        let lock = std::fs::File::create(directory.0.join("instance.lock")).unwrap();
        let limits = coordinator_journal_limits();
        let capture_limits = coordinator_capture_limits(max_recovery_records);
        let max_traces = NonZeroUsize::new(
            usize::try_from(max_recovery_records)
                .unwrap_or(usize::MAX)
                .max(1),
        )
        .unwrap();
        let options = JournalOpenOptions::new(
            fixture.actor.gate_id().clone(),
            fixture.actor.gate_boot_id(),
            fixture.now.as_nanos(),
            limits,
        );
        let journal = {
            let signer = fixture.actor.journal_signer();
            let verifier = fixture
                .actor
                .journal_verifier(NonZeroUsize::new(32 * 1024).unwrap());
            RecoveredGateJournal::provision_new(
                journal_directory,
                options,
                &signer,
                capture_limits,
                verifier,
                max_traces,
            )
            .unwrap()
        };
        let bound = RunningGate::bind_publication_journal_for_test(
            fixture.actor,
            journal,
            0,
            GateOutputEpoch::new(uuid(5)),
            lock,
        )
        .unwrap();
        let clock = SharedClock::new(fixture.now);
        let coordinator = PublicationCoordinator::new(bound, clock.clone()).unwrap();
        let output_pool = OutputCapacityPool::new(NonZeroUsize::new(1).unwrap());
        CoordinatorFixture {
            coordinator,
            clock,
            output_pool,
            ctrl_sk: fixture.ctrl_sk,
            admission_digest: fixture.admission_digest,
            _directory: directory,
        }
    }

    fn signed_coordinator_intent(fixture: &CoordinatorFixture, sequence: u64) -> Vec<u8> {
        let record = admission_record();
        let intent = build_intent(
            fixture.admission_digest,
            &record,
            sequence,
            velocity(sequence, 400),
        );
        sign_intent(&fixture.ctrl_sk, &intent)
    }

    fn output_permit(fixture: &CoordinatorFixture) -> OutputCapacityPermit {
        fixture.output_pool.try_reserve().unwrap()
    }

    struct RestartedCoordinatorFixture {
        bound: JournalBoundRunningGate,
        clock: SharedClock,
        effective_validity_ms: u32,
        prior_decision_boot: GateBootId,
        prior_decision_id: DecisionId,
        _directory: CoordinatorTestDirectory,
    }

    fn reopen_publication_directory(
        directory: CoordinatorTestDirectory,
        effective_validity_ms: u32,
        prior_decision_boot: GateBootId,
        prior_decision_id: DecisionId,
        expected_state: PublicationTraceState,
        expected_unknown_events: usize,
    ) -> RestartedCoordinatorFixture {
        let ctrl_sk = SigningKey::from_seed([1; 32]);
        let mission_sk = SigningKey::from_seed([2; 32]);
        let gate_sk = SigningKey::from_seed([3; 32]);
        let (mut config, _, _) = gate_config(acl_publication(), &ctrl_sk, &mission_sk, gate_sk);
        config.gate_boot_id = GateBootId::new([10; 16]);
        config.output_epoch = GateOutputEpoch::new(uuid(6));
        let actor = VehicleActor::new(config).unwrap();
        let restart_at = MonoInstant::from_nanos(2_000_000_000);
        let options = JournalOpenOptions::new(
            actor.gate_id().clone(),
            actor.gate_boot_id(),
            restart_at.as_nanos(),
            coordinator_journal_limits(),
        );
        let (journal, recovery_unknown_events) = {
            let signer = actor.journal_signer();
            let verifier = actor.journal_verifier(NonZeroUsize::new(32 * 1024).unwrap());
            RecoveredGateJournal::open_existing_with_recovery_unknowns(
                directory.0.join("journal"),
                options,
                &signer,
                Some(&signer),
                coordinator_capture_limits(64),
                verifier,
                NonZeroUsize::new(64).unwrap(),
            )
            .unwrap()
        };
        assert_eq!(recovery_unknown_events, expected_unknown_events);
        let lock = std::fs::File::create(directory.0.join("restart.lock")).unwrap();
        let bound = RunningGate::bind_publication_journal_for_test(
            actor,
            journal,
            recovery_unknown_events,
            GateOutputEpoch::new(uuid(6)),
            lock,
        )
        .unwrap();
        assert_eq!(
            bound
                .recovered_publication()
                .state(prior_decision_boot, prior_decision_id),
            Some(expected_state)
        );
        RestartedCoordinatorFixture {
            bound,
            clock: SharedClock::new(restart_at),
            effective_validity_ms,
            prior_decision_boot,
            prior_decision_id,
            _directory: directory,
        }
    }

    fn restarted_bound_after_dropped_call() -> RestartedCoordinatorFixture {
        let fixture = coordinator_fixture(64);
        let envelope = signed_coordinator_intent(&fixture, 1);
        let permit = output_permit(&fixture);
        let prepared = match fixture.coordinator.decide(permit, &envelope, INTENT_KEY) {
            Ok(DecisionTransition::Prepared(prepared)) => prepared,
            _ => panic!("expected prepared output"),
        };
        let prior_decision_boot = prepared.decision().receipt.gate_boot_id;
        let prior_decision_id = prepared.decision().receipt.decision_id;
        let effective_validity_ms = prepared.decision().receipt.effective_validity_ms.unwrap();
        let called = match prepared.enter_called_boundary().unwrap() {
            CallTransition::Called(called) => called,
            CallTransition::Rejected { .. } => panic!("fresh call must pass"),
        };
        assert_eq!(
            called.publication_trace_state(),
            Some(PublicationTraceState::PublishCalled)
        );
        drop(called);
        assert_eq!(fixture.output_pool.available(), 1);
        reopen_publication_directory(
            fixture._directory,
            effective_validity_ms,
            prior_decision_boot,
            prior_decision_id,
            PublicationTraceState::UnknownAfterPublish,
            1,
        )
    }

    #[test]
    fn restart_requires_external_clearance_after_current_policy_diagnostic() {
        let fixture = restarted_bound_after_dropped_call();
        let start_ns = fixture.clock.now().as_nanos();
        let diagnostic_offset_ms = fixture
            .effective_validity_ms
            .max(fixture.bound.actor().duty_history_window_ms());
        let coordinator =
            PublicationCoordinator::new(fixture.bound, fixture.clock.clone()).unwrap();
        let current_policy_diagnostic_not_before =
            MonoInstant::from_nanos(start_ns + u64::from(diagnostic_offset_ms) * 1_000_000);
        assert_eq!(
            coordinator.restart_clearance_diagnostic_not_before(),
            Some(current_policy_diagnostic_not_before)
        );
        assert_eq!(
            coordinator
                .publication_trace_state(fixture.prior_decision_boot, fixture.prior_decision_id),
            Some(PublicationTraceState::UnknownAfterPublish)
        );

        let output_pool = OutputCapacityPool::new(NonZeroUsize::new(1).unwrap());
        let permit = output_pool.try_reserve().unwrap();
        let error = match coordinator.decide(permit, b"ignored", INTENT_KEY) {
            Err(error) => error,
            Ok(_) => panic!("replacement decision escaped unresolved restart clearance"),
        };
        let (coordinator, permit, reason) = error.into_unavailable().unwrap();
        assert_eq!(
            reason,
            DecisionUnavailable::RestartClearanceRequired {
                observed_at: MonoInstant::from_nanos(start_ns),
                current_policy_diagnostic_not_before,
            }
        );
        assert_eq!(coordinator.actor().evidence().len(), 0);
        assert_eq!(output_pool.available(), 0);
        drop(permit);
        assert_eq!(output_pool.available(), 1);

        let after_diagnostic = MonoInstant::from_nanos(
            current_policy_diagnostic_not_before
                .as_nanos()
                .checked_add(1)
                .unwrap(),
        );
        fixture.clock.set_ns(after_diagnostic.as_nanos());
        let permit = output_pool.try_reserve().unwrap();
        let error = match coordinator.decide(permit, b"ignored", INTENT_KEY) {
            Err(error) => error,
            Ok(_) => panic!("time alone incorrectly cleared transport/history recovery"),
        };
        let (coordinator, permit, reason) = error.into_unavailable().unwrap();
        assert_eq!(
            reason,
            DecisionUnavailable::RestartClearanceRequired {
                observed_at: after_diagnostic,
                current_policy_diagnostic_not_before,
            }
        );
        assert_eq!(coordinator.actor().evidence().len(), 0);
        drop(permit);
        assert_eq!(output_pool.available(), 1);
    }

    #[test]
    fn restart_diagnostic_horizon_overflow_consumes_the_bound_runtime() {
        let fixture = restarted_bound_after_dropped_call();
        fixture.clock.set_ns(u64::MAX);
        assert!(matches!(
            PublicationCoordinator::new(fixture.bound, fixture.clock),
            Err(crate::startup::publication_coordinator::CoordinatorFatal::RestartDiagnosticHorizonOverflow)
        ));
    }

    #[test]
    fn publisher_ok_is_journaled_before_the_publisher_and_runtime_return() {
        let fixture = coordinator_fixture(64);
        let envelope = signed_coordinator_intent(&fixture, 1);
        let output_pool = fixture.output_pool.clone();
        let permit = output_permit(&fixture);
        let prepared = match fixture.coordinator.decide(permit, &envelope, INTENT_KEY) {
            Ok(DecisionTransition::Prepared(prepared)) => prepared,
            Ok(DecisionTransition::NoPublication(_)) => panic!("expected prepared output"),
            Err(_) => panic!("decision must be journaled"),
        };
        let decision_id = prepared.decision().receipt.decision_id;
        let decision_boot = prepared.decision().receipt.gate_boot_id;
        let effective_validity_ms = prepared.decision().receipt.effective_validity_ms.unwrap();
        assert_eq!(
            prepared.publication_trace_state(),
            Some(PublicationTraceState::Prepared)
        );

        let called = match prepared.enter_called_boundary().unwrap() {
            CallTransition::Called(called) => called,
            CallTransition::Rejected { .. } => panic!("fresh call must pass"),
        };
        let expected_frame_digest = called.decision().receipt.output_frame_digest.unwrap();
        assert_eq!(
            called.publication_trace_state(),
            Some(PublicationTraceState::PublishCalled)
        );

        let calls = Arc::new(AtomicUsize::new(0));
        let drops = Arc::new(AtomicUsize::new(0));
        let publisher = TestPublisher {
            drops: Arc::clone(&drops),
        };
        let observed_calls = Arc::clone(&calls);
        let mut publish = Box::pin(
            called.publish_once_with_test_future(publisher, move |frame| {
                observed_calls.fetch_add(1, Ordering::SeqCst);
                assert!(!frame.bytes().is_empty());
                assert_eq!(frame.digest(), expected_frame_digest);
                std::future::ready(Ok::<(), TestPublishError>(()))
            }),
        );
        let (returned, publisher) = match poll_once(publish.as_mut()) {
            Poll::Ready(Ok(success)) => success,
            Poll::Ready(Err(_)) => panic!("local publisher Ok must reach terminal success"),
            Poll::Pending => panic!("ready publisher result did not complete"),
        };
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        drop(publish);
        drop(publisher);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        let (coordinator, decision, terminal_digest, permit) = returned.into_parts();
        assert_eq!(decision.receipt.decision_id, decision_id);
        assert_ne!(
            terminal_digest,
            DigestV1::compute(DigestDomain::RawEnvelope, b"")
        );
        assert_eq!(output_pool.available(), 0);
        drop(permit);
        assert_eq!(output_pool.available(), 1);
        assert_eq!(
            coordinator.publication_trace_state(decision_boot, decision_id),
            Some(PublicationTraceState::PublishReturnedOk)
        );
        assert_eq!(
            coordinator.actor().publication_state(),
            PublicationState::Idle
        );
        drop(coordinator);
        let restarted = reopen_publication_directory(
            fixture._directory,
            effective_validity_ms,
            decision_boot,
            decision_id,
            PublicationTraceState::PublishReturnedOk,
            0,
        );
        assert_eq!(
            restarted
                .bound
                .recovered_publication()
                .state(decision_boot, decision_id),
            Some(PublicationTraceState::PublishReturnedOk)
        );
    }

    #[test]
    fn publisher_error_is_journaled_and_the_publisher_is_not_returned() {
        let fixture = coordinator_fixture(64);
        let envelope = signed_coordinator_intent(&fixture, 1);
        let output_pool = fixture.output_pool.clone();
        let permit = output_permit(&fixture);
        let prepared = match fixture.coordinator.decide(permit, &envelope, INTENT_KEY) {
            Ok(DecisionTransition::Prepared(prepared)) => prepared,
            _ => panic!("expected prepared output"),
        };
        let decision_boot = prepared.decision().receipt.gate_boot_id;
        let decision_id = prepared.decision().receipt.decision_id;
        let effective_validity_ms = prepared.decision().receipt.effective_validity_ms.unwrap();
        let called = match prepared.enter_called_boundary().unwrap() {
            CallTransition::Called(called) => called,
            CallTransition::Rejected { .. } => panic!("fresh call must pass"),
        };
        let expected_frame_digest = called.decision().receipt.output_frame_digest.unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let drops = Arc::new(AtomicUsize::new(0));
        let publisher = TestPublisher {
            drops: Arc::clone(&drops),
        };
        let observed_calls = Arc::clone(&calls);
        let mut publish = Box::pin(
            called.publish_once_with_test_future(publisher, move |frame| {
                observed_calls.fetch_add(1, Ordering::SeqCst);
                assert_eq!(frame.digest(), expected_frame_digest);
                std::future::ready(Err::<(), TestPublishError>(TestPublishError))
            }),
        );
        let returned = match poll_once(publish.as_mut()) {
            Poll::Ready(Err(PublishOnceError::PublisherReturned { source, journaled })) => {
                assert_eq!(source, TestPublishError);
                *journaled
            }
            Poll::Ready(Err(PublishOnceError::TerminalRecordFailed { .. })) => {
                panic!("terminal error record unexpectedly failed")
            }
            Poll::Ready(Ok(_)) => panic!("publisher error became success"),
            Poll::Pending => panic!("ready publisher error did not complete"),
        };
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        drop(publish);
        let (decision, terminal_digest, permit) = returned.into_parts();
        assert_eq!(decision.outcome, DecisionOutcomeV1::Allow);
        assert_ne!(
            terminal_digest,
            DigestV1::compute(DigestDomain::RawEnvelope, b"")
        );
        assert_eq!(output_pool.available(), 0);
        drop(permit);
        assert_eq!(output_pool.available(), 1);
        let restarted = reopen_publication_directory(
            fixture._directory,
            effective_validity_ms,
            decision_boot,
            decision_id,
            PublicationTraceState::PublishReturnedError,
            0,
        );
        assert_eq!(
            restarted
                .bound
                .recovered_publication()
                .state(decision_boot, decision_id),
            Some(PublicationTraceState::PublishReturnedError)
        );
    }

    #[cfg(feature = "live-zenoh")]
    #[test]
    fn wrong_publisher_route_is_terminally_rejected_before_invocation() {
        let fixture = coordinator_fixture(64);
        let envelope = signed_coordinator_intent(&fixture, 1);
        let output_pool = fixture.output_pool.clone();
        let permit = output_permit(&fixture);
        let prepared = match fixture.coordinator.decide(permit, &envelope, INTENT_KEY) {
            Ok(DecisionTransition::Prepared(prepared)) => prepared,
            _ => panic!("expected prepared output"),
        };
        let decision_boot = prepared.decision().receipt.gate_boot_id;
        let decision_id = prepared.decision().receipt.decision_id;
        let effective_validity_ms = prepared.decision().receipt.effective_validity_ms.unwrap();
        let called = match prepared.enter_called_boundary().unwrap() {
            CallTransition::Called(called) => called,
            CallTransition::Rejected { .. } => panic!("fresh call must pass"),
        };
        let expected_keys = haldir_transport_zenoh::HaldirKeys::try_new("range-a", "sess-1")
            .expect("fixture route must be valid");
        assert_eq!(
            called.expected_final_command_route(),
            expected_keys.final_command()
        );
        let wrong_keys = haldir_transport_zenoh::HaldirKeys::try_new("range-b", "sess-1")
            .expect("mismatched test route must be valid");

        let calls = Arc::new(AtomicUsize::new(0));
        let drops = Arc::new(AtomicUsize::new(0));
        let publisher = TestPublisher {
            drops: Arc::clone(&drops),
        };
        let observed_calls = Arc::clone(&calls);
        let mut publish = Box::pin(called.publish_once_with_test_route(
            publisher,
            wrong_keys.final_command(),
            move |_frame| {
                observed_calls.fetch_add(1, Ordering::SeqCst);
                std::future::ready(Ok::<(), haldir_transport_zenoh::SecureZenohError>(()))
            },
        ));
        let returned = match poll_once(publish.as_mut()) {
            Poll::Ready(Err(PublishOnceError::PublisherReturned { source, journaled })) => {
                assert_eq!(source, StrictPublisherCallError::PublisherRouteMismatch);
                *journaled
            }
            Poll::Ready(Err(PublishOnceError::TerminalRecordFailed { .. })) => {
                panic!("route-mismatch terminal record unexpectedly failed")
            }
            Poll::Ready(Ok(_)) => panic!("wrong route became publisher success"),
            Poll::Pending => panic!("route rejection unexpectedly waited on publisher"),
        };
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_eq!(output_pool.available(), 0);
        drop(publish);
        let (_, _, permit) = returned.into_parts();
        drop(permit);
        assert_eq!(output_pool.available(), 1);
        let restarted = reopen_publication_directory(
            fixture._directory,
            effective_validity_ms,
            decision_boot,
            decision_id,
            PublicationTraceState::PublishReturnedError,
            0,
        );
        assert_eq!(
            restarted
                .bound
                .recovered_publication()
                .state(decision_boot, decision_id),
            Some(PublicationTraceState::PublishReturnedError)
        );
    }

    #[test]
    fn cancelling_pending_publish_recovers_called_as_unknown() {
        let fixture = coordinator_fixture(64);
        let envelope = signed_coordinator_intent(&fixture, 1);
        let output_pool = fixture.output_pool.clone();
        let permit = output_permit(&fixture);
        let prepared = match fixture.coordinator.decide(permit, &envelope, INTENT_KEY) {
            Ok(DecisionTransition::Prepared(prepared)) => prepared,
            _ => panic!("expected prepared output"),
        };
        let decision_boot = prepared.decision().receipt.gate_boot_id;
        let decision_id = prepared.decision().receipt.decision_id;
        let effective_validity_ms = prepared.decision().receipt.effective_validity_ms.unwrap();
        let expected_frame_digest = prepared.decision().receipt.output_frame_digest.unwrap();
        let called = match prepared.enter_called_boundary().unwrap() {
            CallTransition::Called(called) => called,
            CallTransition::Rejected { .. } => panic!("fresh call must pass"),
        };
        assert_eq!(
            called.publication_trace_state(),
            Some(PublicationTraceState::PublishCalled)
        );

        let calls = Arc::new(AtomicUsize::new(0));
        let polls = Arc::new(AtomicUsize::new(0));
        let drops = Arc::new(AtomicUsize::new(0));
        let publisher = TestPublisher {
            drops: Arc::clone(&drops),
        };
        let observed_calls = Arc::clone(&calls);
        let observed_polls = Arc::clone(&polls);
        let mut publish = Box::pin(
            called.publish_once_with_test_future(publisher, move |frame| {
                observed_calls.fetch_add(1, Ordering::SeqCst);
                assert_eq!(frame.digest(), expected_frame_digest);
                PendingPublish {
                    polls: observed_polls,
                }
            }),
        );
        assert!(poll_once(publish.as_mut()).is_pending());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(polls.load(Ordering::SeqCst), 1);
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        assert_eq!(output_pool.available(), 0);

        drop(publish);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_eq!(output_pool.available(), 1);
        let restarted = reopen_publication_directory(
            fixture._directory,
            effective_validity_ms,
            decision_boot,
            decision_id,
            PublicationTraceState::UnknownAfterPublish,
            1,
        );
        assert_eq!(
            restarted
                .bound
                .recovered_publication()
                .state(decision_boot, decision_id),
            Some(PublicationTraceState::UnknownAfterPublish)
        );
    }

    #[test]
    fn prepared_cancel_releases_capacity_without_claiming_a_call() {
        let fixture = coordinator_fixture(4);
        let envelope = signed_coordinator_intent(&fixture, 1);
        let second_envelope = signed_coordinator_intent(&fixture, 2);
        let output_pool = fixture.output_pool.clone();
        let permit = output_permit(&fixture);
        let prepared = match fixture.coordinator.decide(permit, &envelope, INTENT_KEY) {
            Ok(DecisionTransition::Prepared(prepared)) => prepared,
            _ => panic!("expected prepared output"),
        };
        let decision_id = prepared.decision().receipt.decision_id;
        let decision_boot = prepared.decision().receipt.gate_boot_id;
        let ready = prepared.cancel().unwrap();
        let (coordinator, _, permit) = ready.into_parts();
        assert_eq!(output_pool.available(), 0);
        drop(permit);
        assert_eq!(output_pool.available(), 1);
        assert_eq!(
            coordinator.publication_trace_state(decision_boot, decision_id),
            Some(PublicationTraceState::Prepared)
        );
        assert_eq!(
            coordinator.actor().publication_state(),
            PublicationState::Idle
        );
        let second_permit = output_pool.try_reserve().unwrap();
        let second = match coordinator.decide(second_permit, &second_envelope, "wrong/actual/key") {
            Ok(DecisionTransition::NoPublication(ready)) => ready,
            _ => panic!("cancelled reservation capacity was not released"),
        };
        let (_, second_decision, second_permit) = second.into_parts();
        assert_eq!(second_decision.outcome, DecisionOutcomeV1::Deny);
        assert_eq!(output_pool.available(), 0);
        drop(second_permit);
        assert_eq!(output_pool.available(), 1);
    }

    #[test]
    fn expired_pre_call_validation_exposes_no_frame_and_returns_ready() {
        let fixture = coordinator_fixture(64);
        let envelope = signed_coordinator_intent(&fixture, 1);
        let output_pool = fixture.output_pool.clone();
        let permit = output_permit(&fixture);
        let prepared = match fixture.coordinator.decide(permit, &envelope, INTENT_KEY) {
            Ok(DecisionTransition::Prepared(prepared)) => prepared,
            _ => panic!("expected prepared output"),
        };
        fixture.clock.advance_ms(21);
        let (ready, reason) = match prepared.enter_called_boundary().unwrap() {
            CallTransition::Rejected { ready, reason } => (ready, reason),
            CallTransition::Called(_) => panic!("deadline-expired bytes became accessible"),
        };
        assert_eq!(reason, PublicationError::DeadlineElapsed);
        let decision_id = ready.decision().receipt.decision_id;
        let decision_boot = ready.decision().receipt.gate_boot_id;
        let (coordinator, _, permit) = ready.into_parts();
        assert_eq!(output_pool.available(), 0);
        drop(permit);
        assert_eq!(output_pool.available(), 1);
        assert_eq!(
            coordinator.publication_trace_state(decision_boot, decision_id),
            Some(PublicationTraceState::Prepared)
        );
        assert_eq!(
            coordinator.actor().publication_state(),
            PublicationState::Idle
        );
    }

    #[test]
    fn post_sync_deadline_failure_recovers_durable_called_as_unknown() {
        let fixture = coordinator_fixture(64);
        let envelope = signed_coordinator_intent(&fixture, 1);
        let output_pool = fixture.output_pool.clone();
        let permit = output_permit(&fixture);
        let prepared = match fixture.coordinator.decide(permit, &envelope, INTENT_KEY) {
            Ok(DecisionTransition::Prepared(prepared)) => prepared,
            _ => panic!("expected prepared output"),
        };
        let decision_boot = prepared.decision().receipt.gate_boot_id;
        let decision_id = prepared.decision().receipt.decision_id;
        let effective_validity_ms = prepared.decision().receipt.effective_validity_ms.unwrap();
        let validation_at = fixture.clock.now();
        let exposure_at = validation_at.checked_add_ms(21).unwrap();
        fixture.clock.script_samples([validation_at, exposure_at]);

        assert!(matches!(
            prepared.enter_called_boundary(),
            Err(
                crate::startup::publication_coordinator::CoordinatorFatal::Publication(
                    PublicationError::DeadlineElapsed
                )
            )
        ));
        assert_eq!(output_pool.available(), 1);

        let restarted = reopen_publication_directory(
            fixture._directory,
            effective_validity_ms,
            decision_boot,
            decision_id,
            PublicationTraceState::UnknownAfterPublish,
            1,
        );
        assert_eq!(
            restarted
                .bound
                .recovered_publication()
                .state(decision_boot, decision_id),
            Some(PublicationTraceState::UnknownAfterPublish)
        );
    }

    #[test]
    fn three_record_capacity_is_reserved_before_actor_mutation() {
        let fixture = coordinator_fixture(2);
        let envelope = signed_coordinator_intent(&fixture, 1);
        let output_pool = fixture.output_pool.clone();
        let permit = output_permit(&fixture);
        let error = match fixture.coordinator.decide(permit, &envelope, INTENT_KEY) {
            Err(error) => error,
            Ok(_) => panic!("two records cannot cover the three-stage lifecycle"),
        };
        let (coordinator, permit, reason) = error.into_unavailable().unwrap();
        assert!(matches!(reason, DecisionUnavailable::JournalCapacity(_)));
        assert_eq!(output_pool.available(), 0);
        drop(permit);
        assert_eq!(output_pool.available(), 1);
        assert_eq!(coordinator.actor().evidence().len(), 0);
        assert_eq!(
            coordinator.actor().publication_state(),
            PublicationState::Idle
        );
    }

    #[test]
    fn cached_terminal_decision_is_not_appended_as_a_duplicate_record() {
        let fixture = coordinator_fixture_with_counter(3, Some(u64::MAX));
        let envelope = signed_coordinator_intent(&fixture, 1);
        let output_pool = fixture.output_pool.clone();
        let permit = output_permit(&fixture);
        let first = match fixture.coordinator.decide(permit, &envelope, INTENT_KEY) {
            Ok(DecisionTransition::NoPublication(ready)) => ready,
            _ => panic!("counter exhaustion must journal one terminal error"),
        };
        let (coordinator, first_decision, first_permit) = first.into_parts();
        assert_eq!(first_decision.outcome, DecisionOutcomeV1::Error);
        assert_eq!(output_pool.available(), 0);
        drop(first_permit);
        assert_eq!(output_pool.available(), 1);
        assert_eq!(coordinator.actor().evidence().len(), 1);

        let second_permit = output_pool.try_reserve().unwrap();
        let second = match coordinator.decide(second_permit, &envelope, INTENT_KEY) {
            Ok(DecisionTransition::NoPublication(ready)) => ready,
            _ => panic!("cached terminal receipt must return without a duplicate append"),
        };
        let (coordinator, second_decision, second_permit) = second.into_parts();
        assert_eq!(
            second_decision.signed_receipt,
            first_decision.signed_receipt
        );
        assert_eq!(output_pool.available(), 0);
        drop(second_permit);
        assert_eq!(output_pool.available(), 1);
        assert_eq!(coordinator.actor().evidence().len(), 1);
    }

    #[test]
    fn output_capacity_pool_enforces_its_exact_bound_and_drop_release() {
        let pool = OutputCapacityPool::new(NonZeroUsize::new(2).unwrap());
        let first = pool.try_reserve().unwrap();
        let second = pool.try_reserve().unwrap();
        assert_eq!(pool.available(), 0);
        assert!(pool.try_reserve().is_none());

        drop(first);
        assert_eq!(pool.available(), 1);
        let replacement = pool.try_reserve().unwrap();
        assert_eq!(pool.available(), 0);

        drop(second);
        drop(replacement);
        assert_eq!(pool.available(), 2);
    }

    #[test]
    fn coordinator_clock_regression_is_fatal_and_releases_output_capacity() {
        let fixture = coordinator_fixture(64);
        let initial_ns = fixture.clock.now().as_nanos();
        fixture.clock.set_ns(initial_ns - 1);
        let permit = output_permit(&fixture);

        assert!(matches!(
            fixture.coordinator.decide(permit, b"ignored", INTENT_KEY),
            Err(crate::startup::publication_coordinator::DecideError::Fatal(
                crate::startup::publication_coordinator::CoordinatorFatal::ClockRegression
            ))
        ));
        assert_eq!(fixture.output_pool.available(), 1);
    }

    #[test]
    fn local_sync_coordinator_typestates_remain_send() {
        fn assert_send<T: Send>() {}
        assert_send::<PublicationCoordinator<SharedClock>>();
        assert_send::<DurablePreparedPublication<SharedClock>>();
        assert_send::<DurableCalledPublication<SharedClock>>();
        assert_send::<ReadyDecision<SharedClock>>();
        assert_send::<JournaledReturnedOk<SharedClock>>();
        assert_send::<JournaledReturnedError>();
        assert_send::<PublishOnceError<TestPublishError>>();
        assert_send::<DecisionTransition<SharedClock>>();
        assert_send::<CallTransition<SharedClock>>();
        assert_send::<DecideError<SharedClock>>();
        assert_send::<OutputCapacityPermit>();
        assert_send::<OutputCapacityPool>();
    }

    #[cfg(feature = "live-zenoh")]
    #[test]
    fn concrete_strict_publish_future_is_send() {
        fn assert_send<T: Send>(_: T) {}
        fn check(
            called: DurableCalledPublication<SharedClock>,
            publisher: haldir_transport_zenoh::FinalCommandPublisher,
        ) {
            assert_send(called.publish_once(publisher));
        }

        assert_send::<
            fn(
                DurableCalledPublication<SharedClock>,
                haldir_transport_zenoh::FinalCommandPublisher,
            ),
        >(check);
    }

    #[cfg(feature = "real-ncp")]
    #[test]
    fn explicitly_selected_exact_adapter_reaches_the_called_boundary_as_ncp_json() {
        let mut fixture =
            setup_with_adapter(haldir_ncp08::SelectedNcpCommandAdapter::exact_ncp_v0_8_json());
        assert_eq!(
            fixture.actor.ncp_command_wire_profile(),
            haldir_ncp08::NcpCommandWireProfile::ExactNcpV0_8Json
        );

        let record = admission_record();
        let intent = build_intent(fixture.admission_digest, &record, 1, velocity(1, 400));
        let envelope = sign_intent(&fixture.ctrl_sk, &intent);
        let decision = fixture
            .actor
            .decide_intent(&envelope, INTENT_KEY, fixture.now);
        assert_eq!(decision.outcome, DecisionOutcomeV1::Allow);
        let receipt_digest = decision.receipt.output_frame_digest.unwrap();
        let prepared = decision.into_prepared_publication().unwrap();
        let called = fixture
            .actor
            .mark_publish_called(prepared, fixture.now)
            .unwrap();

        assert_eq!(called.frame().digest(), receipt_digest);
        let exact_json = std::str::from_utf8(called.frame().bytes()).unwrap();
        assert!(exact_json.starts_with('{'));
        assert!(exact_json.contains("\"kind\":\"command_frame\""));
        fixture
            .actor
            .mark_publish_returned_ok(called, fixture.now)
            .unwrap();
    }

    #[test]
    fn end_to_end_allow_drives_reference_plant() {
        let mut f = setup();
        let rec = admission_record();
        // 400 mm/s converges in 5 ticks (80 mm/s/tick) — well within the ~180 ms
        // effective validity window (9 ticks).
        let intent = build_intent(f.admission_digest, &rec, 1, velocity(1, 400));
        let env = sign_intent(&f.ctrl_sk, &intent);
        let out = f.actor.decide_intent(&env, INTENT_KEY, f.now);
        assert_eq!(
            out.outcome,
            DecisionOutcomeV1::Allow,
            "reasons: {:?}",
            out.receipt.reason_codes.as_slice()
        );
        let prepared = out
            .into_prepared_publication()
            .expect("prepared publication");
        let called = f
            .actor
            .mark_publish_called(prepared, f.now)
            .expect("reference publication called");
        let cmd = called.reference_plant_command().clone();

        let mut plant = ReferencePlant::new(PlantConfig::default());
        plant.ingest(cmd).expect("plant accepts Gate command");
        f.actor
            .mark_publish_returned_ok(called, f.now)
            .expect("reference publication returned ok");
        plant.run(15);
        assert!(
            plant
                .events()
                .iter()
                .any(|e| e.kind == PlantEventKind::Applied)
        );
        assert!(
            plant
                .events()
                .iter()
                .any(|e| e.kind == PlantEventKind::ResponseObserved)
        );
    }

    #[test]
    fn preparation_does_not_seed_published_slew_history() {
        let mut f = setup();
        let rec = admission_record();
        let first = sign_intent(
            &f.ctrl_sk,
            &build_intent(f.admission_digest, &rec, 1, velocity(1, 400)),
        );
        let first = f.actor.decide_intent(&first, INTENT_KEY, f.now);
        let prepared = first
            .into_prepared_publication()
            .expect("first output prepared");
        let debug = format!("{prepared:?}");
        assert!(!debug.contains("frame"));
        assert!(!debug.contains("plant_command"));
        f.actor
            .cancel_prepared_publication(prepared)
            .expect("unexposed preparation cancels");

        // At the same instant, a prior published velocity would permit zero slew.
        // The larger command remains eligible because cancellation never exposed
        // bytes and therefore must not seed published-command history.
        let second = sign_intent(
            &f.ctrl_sk,
            &build_intent(f.admission_digest, &rec, 2, velocity(2, 800)),
        );
        let second = f.actor.decide_intent(&second, INTENT_KEY, f.now);
        assert_eq!(second.outcome, DecisionOutcomeV1::Allow);
        let prepared = second
            .into_prepared_publication()
            .expect("second output prepared");
        f.actor
            .cancel_prepared_publication(prepared)
            .expect("cleanup preparation");
    }

    #[test]
    fn successful_publication_seeds_slew_history_exactly_once() {
        let mut f = setup();
        let rec = admission_record();
        let first = sign_intent(
            &f.ctrl_sk,
            &build_intent(f.admission_digest, &rec, 1, velocity(1, 400)),
        );
        let first = f.actor.decide_intent(&first, INTENT_KEY, f.now);
        let prepared = first
            .into_prepared_publication()
            .expect("first output prepared");
        let called = f
            .actor
            .mark_publish_called(prepared, f.now)
            .expect("publication called");
        let mut plant = ReferencePlant::new(PlantConfig::default());
        plant
            .ingest(called.reference_plant_command().clone())
            .expect("reference receiver accepted");
        f.actor
            .mark_publish_returned_ok(called, f.now)
            .expect("publication returned ok");
        assert_eq!(f.actor.publication_state(), PublicationState::Idle);

        let second = sign_intent(
            &f.ctrl_sk,
            &build_intent(f.admission_digest, &rec, 2, velocity(2, 800)),
        );
        let second = f.actor.decide_intent(&second, INTENT_KEY, f.now);
        assert_eq!(second.outcome, DecisionOutcomeV1::Deny);
        assert!(
            second
                .receipt
                .reason_codes
                .as_slice()
                .contains(&DecisionReasonCodeV1::DenySlew)
        );
        assert!(!second.has_prepared_publication());
    }

    #[test]
    fn second_prepare_is_overload_until_the_single_slot_is_resolved() {
        let mut f = setup();
        let rec = admission_record();
        let first = sign_intent(
            &f.ctrl_sk,
            &build_intent(f.admission_digest, &rec, 1, velocity(1, 400)),
        );
        let first = f.actor.decide_intent(&first, INTENT_KEY, f.now);
        let prepared = first
            .into_prepared_publication()
            .expect("first output prepared");
        assert!(matches!(
            f.actor.publication_state(),
            PublicationState::Prepared { .. }
        ));

        let second = sign_intent(
            &f.ctrl_sk,
            &build_intent(f.admission_digest, &rec, 2, velocity(2, 400)),
        );
        let second = f.actor.decide_intent(&second, INTENT_KEY, f.now);
        assert_eq!(second.outcome, DecisionOutcomeV1::Deny);
        assert!(
            second
                .receipt
                .reason_codes
                .as_slice()
                .contains(&DecisionReasonCodeV1::DenyOverload)
        );
        f.actor
            .cancel_prepared_publication(prepared)
            .expect("first slot still owns cancellation");
    }

    #[test]
    fn publication_tokens_are_bound_to_their_originating_actor() {
        let rec = admission_record();
        let mut first = setup();
        let mut second = setup();

        let first_env = sign_intent(
            &first.ctrl_sk,
            &build_intent(first.admission_digest, &rec, 1, velocity(1, 400)),
        );
        let first_prepared = first
            .actor
            .decide_intent(&first_env, INTENT_KEY, first.now)
            .into_prepared_publication()
            .expect("first actor prepared output");
        let second_env = sign_intent(
            &second.ctrl_sk,
            &build_intent(second.admission_digest, &rec, 1, velocity(1, 800)),
        );
        let second_prepared = second
            .actor
            .decide_intent(&second_env, INTENT_KEY, second.now)
            .into_prepared_publication()
            .expect("second actor prepared output");

        // Both actors intentionally share the fixture boot id and per-actor
        // decision counter, so DecisionId alone would collide here.
        assert_eq!(first_prepared.decision_id(), second_prepared.decision_id());
        assert!(matches!(
            second.actor.mark_publish_called(first_prepared, second.now),
            Err(PublicationError::StateMismatch)
        ));
        assert!(matches!(
            second.actor.publication_state(),
            PublicationState::Prepared { .. }
        ));
        second
            .actor
            .cancel_prepared_publication(second_prepared)
            .expect("originating actor still resolves its own slot");
    }

    #[test]
    fn validated_publish_call_keeps_the_slot_prepared_and_frame_opaque() {
        let mut f = setup();
        let rec = admission_record();
        let env = sign_intent(
            &f.ctrl_sk,
            &build_intent(f.admission_digest, &rec, 1, velocity(1, 400)),
        );
        let prepared = f
            .actor
            .decide_intent(&env, INTENT_KEY, f.now)
            .into_prepared_publication()
            .expect("output prepared");
        let decision_id = prepared.decision_id();

        let validated = f
            .actor
            .validate_publish_call(prepared, f.now)
            .expect("initial publication checks pass");

        assert_eq!(validated.decision_id(), decision_id);
        assert_eq!(
            f.actor.publication_state(),
            PublicationState::Prepared { decision_id }
        );
        let debug = format!("{validated:?}");
        assert!(!debug.contains("frame"));
        assert!(!debug.contains("plant_command"));

        let called = f
            .actor
            .commit_publish_call(validated, f.now)
            .expect("durable-call confirmation reveals output");
        f.actor
            .mark_publish_returned_ok(called, f.now)
            .expect("test publication resolves");
    }

    #[test]
    fn validated_publish_call_is_rejected_by_the_wrong_actor() {
        let rec = admission_record();
        let mut first = setup();
        let mut second = setup();
        let first_env = sign_intent(
            &first.ctrl_sk,
            &build_intent(first.admission_digest, &rec, 1, velocity(1, 400)),
        );
        let first_prepared = first
            .actor
            .decide_intent(&first_env, INTENT_KEY, first.now)
            .into_prepared_publication()
            .expect("first actor prepared output");
        let validated = first
            .actor
            .validate_publish_call(first_prepared, first.now)
            .expect("first actor validates its token");
        let second_env = sign_intent(
            &second.ctrl_sk,
            &build_intent(second.admission_digest, &rec, 1, velocity(1, 800)),
        );
        let second_prepared = second
            .actor
            .decide_intent(&second_env, INTENT_KEY, second.now)
            .into_prepared_publication()
            .expect("second actor prepared output");

        let result = second.actor.commit_publish_call(validated, second.now);

        assert!(matches!(result, Err(PublicationError::StateMismatch)));
        assert!(matches!(
            second.actor.publication_state(),
            PublicationState::Prepared { .. }
        ));
        second
            .actor
            .cancel_prepared_publication(second_prepared)
            .expect("second actor still owns its slot");
    }

    #[test]
    fn validated_publish_call_is_rejected_when_the_actor_slot_changed() {
        let mut f = setup();
        let rec = admission_record();
        let env = sign_intent(
            &f.ctrl_sk,
            &build_intent(f.admission_digest, &rec, 1, velocity(1, 400)),
        );
        let prepared = f
            .actor
            .decide_intent(&env, INTENT_KEY, f.now)
            .into_prepared_publication()
            .expect("output prepared");
        let validated = f
            .actor
            .validate_publish_call(prepared, f.now)
            .expect("initial publication checks pass");
        f.actor
            .force_publication_state_for_test(PublicationState::Idle);

        let result = f.actor.commit_publish_call(validated, f.now);

        assert!(matches!(result, Err(PublicationError::StateMismatch)));
        assert!(matches!(
            f.actor.publication_state(),
            PublicationState::PublishCalled { .. }
        ));
        assert_eq!(f.actor.process_state(), GateProcessStateV1::FaultLatched);
    }

    #[test]
    fn post_sync_deadline_failure_faults_and_retains_called_state() {
        let mut f = setup();
        let rec = admission_record();
        let env = sign_intent(
            &f.ctrl_sk,
            &build_intent(f.admission_digest, &rec, 1, velocity(1, 400)),
        );
        let prepared = f
            .actor
            .decide_intent(&env, INTENT_KEY, f.now)
            .into_prepared_publication()
            .expect("output prepared");
        let decision_id = prepared.decision_id();
        let validated = f
            .actor
            .validate_publish_call(prepared, f.now)
            .expect("initial publication checks pass");
        let exposure_at = MonoInstant::from_nanos(
            f.now
                .as_nanos()
                .checked_add(20_000_001)
                .expect("fixture deadline is representable"),
        );

        let result = f.actor.commit_publish_call(validated, exposure_at);

        assert!(matches!(result, Err(PublicationError::DeadlineElapsed)));
        assert_eq!(
            f.actor.publication_state(),
            PublicationState::PublishCalled { decision_id }
        );
        assert_eq!(f.actor.process_state(), GateProcessStateV1::FaultLatched);
    }

    #[test]
    fn post_sync_causal_change_faults_and_retains_called_state() {
        let mut f = setup();
        let rec = admission_record();
        let env = sign_intent(
            &f.ctrl_sk,
            &build_intent(f.admission_digest, &rec, 1, velocity(1, 400)),
        );
        let prepared = f
            .actor
            .decide_intent(&env, INTENT_KEY, f.now)
            .into_prepared_publication()
            .expect("output prepared");
        let decision_id = prepared.decision_id();
        let validated = f
            .actor
            .validate_publish_call(prepared, f.now)
            .expect("initial publication checks pass");
        let exposure_at = f
            .now
            .checked_add_ms(1)
            .expect("fixture time is representable");
        f.actor
            .set_trusted_state(trusted_state(exposure_at))
            .expect("causal state advances during fsync");

        let result = f.actor.commit_publish_call(validated, exposure_at);

        assert!(matches!(result, Err(PublicationError::CausalStateChanged)));
        assert_eq!(
            f.actor.publication_state(),
            PublicationState::PublishCalled { decision_id }
        );
        assert_eq!(f.actor.process_state(), GateProcessStateV1::FaultLatched);
    }

    #[test]
    fn post_sync_revision_change_faults_and_retains_called_state() {
        let mut f = setup();
        let rec = admission_record();
        let env = sign_intent(
            &f.ctrl_sk,
            &build_intent(f.admission_digest, &rec, 1, velocity(1, 400)),
        );
        let prepared = f
            .actor
            .decide_intent(&env, INTENT_KEY, f.now)
            .into_prepared_publication()
            .expect("output prepared");
        let decision_id = prepared.decision_id();
        let validated = f
            .actor
            .validate_publish_call(prepared, f.now)
            .expect("initial publication checks pass");
        f.actor.revoke_active_lease();

        let result = f.actor.commit_publish_call(validated, f.now);

        assert!(matches!(
            result,
            Err(PublicationError::AuthorizationChanged)
        ));
        assert_eq!(
            f.actor.publication_state(),
            PublicationState::PublishCalled { decision_id }
        );
        assert_eq!(f.actor.process_state(), GateProcessStateV1::FaultLatched);
    }

    #[test]
    fn post_sync_monotonic_regression_faults_and_retains_called_state() {
        let mut f = setup();
        let rec = admission_record();
        let env = sign_intent(
            &f.ctrl_sk,
            &build_intent(f.admission_digest, &rec, 1, velocity(1, 400)),
        );
        let prepared = f
            .actor
            .decide_intent(&env, INTENT_KEY, f.now)
            .into_prepared_publication()
            .expect("output prepared");
        let decision_id = prepared.decision_id();
        let validated = f
            .actor
            .validate_publish_call(prepared, f.now)
            .expect("initial publication checks pass");
        let regressed = MonoInstant::from_nanos(
            f.now
                .as_nanos()
                .checked_sub(1)
                .expect("fixture time is nonzero"),
        );

        let result = f.actor.commit_publish_call(validated, regressed);

        assert!(matches!(result, Err(PublicationError::Faulted)));
        assert_eq!(
            f.actor.publication_state(),
            PublicationState::PublishCalled { decision_id }
        );
        assert_eq!(f.actor.process_state(), GateProcessStateV1::FaultLatched);
    }

    #[test]
    fn post_sync_publication_authority_loss_faults_and_retains_called_state() {
        let mut f = setup();
        let rec = admission_record();
        let env = sign_intent(
            &f.ctrl_sk,
            &build_intent(f.admission_digest, &rec, 1, velocity(1, 400)),
        );
        let prepared = f
            .actor
            .decide_intent(&env, INTENT_KEY, f.now)
            .into_prepared_publication()
            .expect("output prepared");
        let decision_id = prepared.decision_id();
        let validated = f
            .actor
            .validate_publish_call(prepared, f.now)
            .expect("initial publication checks pass");
        f.actor
            .force_publication_authority_for_test(ncp_publication(
                sess(),
                GateOutputEpoch::new(uuid(5)),
            ));

        let result = f.actor.commit_publish_call(validated, f.now);

        assert!(matches!(
            result,
            Err(PublicationError::PublicationAuthorityLost)
        ));
        assert_eq!(
            f.actor.publication_state(),
            PublicationState::PublishCalled { decision_id }
        );
        assert_eq!(f.actor.process_state(), GateProcessStateV1::FaultLatched);
    }

    #[test]
    fn unresolved_publication_blocks_lease_replacement() {
        let mut f = setup();
        let rec = admission_record();
        let env = sign_intent(
            &f.ctrl_sk,
            &build_intent(f.admission_digest, &rec, 1, velocity(1, 400)),
        );
        let prepared = f
            .actor
            .decide_intent(&env, INTENT_KEY, f.now)
            .into_prepared_publication()
            .expect("output prepared");
        assert_eq!(
            f.actor.accept_lease_env(&[], f.now),
            Err(GateError::PublicationPending)
        );

        let called = f
            .actor
            .mark_publish_called(prepared, f.now)
            .expect("publication called");
        assert_eq!(
            f.actor.accept_lease_env(&[], f.now),
            Err(GateError::PublicationPending)
        );
        f.actor
            .mark_publish_returned_ok(called, f.now)
            .expect("publication resolved");
        assert_ne!(
            f.actor.accept_lease_env(&[], f.now),
            Err(GateError::PublicationPending)
        );
    }

    #[test]
    fn changed_authority_or_causal_state_cannot_expose_prepared_bytes() {
        let rec = admission_record();

        let mut revoked = setup();
        let env = sign_intent(
            &revoked.ctrl_sk,
            &build_intent(revoked.admission_digest, &rec, 1, velocity(1, 400)),
        );
        let prepared = revoked
            .actor
            .decide_intent(&env, INTENT_KEY, revoked.now)
            .into_prepared_publication()
            .expect("output prepared");
        revoked.actor.revoke_active_lease();
        assert!(matches!(
            revoked.actor.mark_publish_called(prepared, revoked.now),
            Err(PublicationError::AuthorizationChanged)
        ));
        assert_eq!(revoked.actor.publication_state(), PublicationState::Idle);

        let mut changed_state = setup();
        let env = sign_intent(
            &changed_state.ctrl_sk,
            &build_intent(changed_state.admission_digest, &rec, 1, velocity(1, 400)),
        );
        let prepared = changed_state
            .actor
            .decide_intent(&env, INTENT_KEY, changed_state.now)
            .into_prepared_publication()
            .expect("output prepared");
        changed_state
            .actor
            .set_trusted_state(trusted_state(changed_state.now))
            .expect("newer causal state");
        assert!(matches!(
            changed_state
                .actor
                .mark_publish_called(prepared, changed_state.now),
            Err(PublicationError::CausalStateChanged)
        ));
        assert_eq!(
            changed_state.actor.publication_state(),
            PublicationState::Idle
        );
    }

    #[test]
    fn delayed_call_is_rejected_and_reported_failure_blocks_replacement_output() {
        let mut boundary = setup();
        let rec = admission_record();
        let env = sign_intent(
            &boundary.ctrl_sk,
            &build_intent(boundary.admission_digest, &rec, 1, velocity(1, 400)),
        );
        let prepared = boundary
            .actor
            .decide_intent(&env, INTENT_KEY, boundary.now)
            .into_prepared_publication()
            .expect("output prepared");
        let exact_deadline = boundary
            .now
            .checked_add_ms(20)
            .expect("fixture time is representable");
        let called = boundary
            .actor
            .mark_publish_called(prepared, exact_deadline)
            .expect("safety-margin boundary is inclusive");
        boundary
            .actor
            .mark_publish_returned_ok(called, exact_deadline)
            .expect("boundary publication resolved");

        let mut delayed = setup();
        let env = sign_intent(
            &delayed.ctrl_sk,
            &build_intent(delayed.admission_digest, &rec, 1, velocity(1, 400)),
        );
        let prepared = delayed
            .actor
            .decide_intent(&env, INTENT_KEY, delayed.now)
            .into_prepared_publication()
            .expect("output prepared");
        let too_late = MonoInstant::from_nanos(
            delayed
                .now
                .as_nanos()
                .checked_add(20_000_001)
                .expect("fixture time is representable"),
        );
        assert!(matches!(
            delayed.actor.mark_publish_called(prepared, too_late),
            Err(PublicationError::DeadlineElapsed)
        ));
        assert_eq!(delayed.actor.publication_state(), PublicationState::Idle);
        let next = sign_intent(
            &delayed.ctrl_sk,
            &build_intent(delayed.admission_digest, &rec, 2, velocity(2, 400)),
        );
        let next = delayed.actor.decide_intent(&next, INTENT_KEY, too_late);
        assert_eq!(next.outcome, DecisionOutcomeV1::Allow);
        assert_eq!(
            next.receipt
                .gate_output_stream
                .as_ref()
                .expect("next output stream")
                .seq
                .get(),
            2,
            "expired prepared output sequence is never reused"
        );
        delayed
            .actor
            .cancel_prepared_publication(
                next.into_prepared_publication()
                    .expect("next output prepared"),
            )
            .expect("next output cleanup");

        let mut failed = setup();
        let env = sign_intent(
            &failed.ctrl_sk,
            &build_intent(failed.admission_digest, &rec, 1, velocity(1, 400)),
        );
        let prepared = failed
            .actor
            .decide_intent(&env, INTENT_KEY, failed.now)
            .into_prepared_publication()
            .expect("output prepared");
        let called = failed
            .actor
            .mark_publish_called(prepared, failed.now)
            .expect("publication called");
        assert!(!called.frame().bytes().is_empty());
        let decision_id = called.decision_id();
        failed
            .actor
            .mark_publish_returned_error(called)
            .expect("ambiguous return fault-latches");
        assert_eq!(
            failed.actor.publication_state(),
            PublicationState::PublishCalled { decision_id }
        );
        assert_eq!(
            failed.actor.process_state(),
            GateProcessStateV1::FaultLatched
        );

        let next = sign_intent(
            &failed.ctrl_sk,
            &build_intent(failed.admission_digest, &rec, 2, velocity(2, 400)),
        );
        let next = failed.actor.decide_intent(&next, INTENT_KEY, failed.now);
        assert_eq!(next.outcome, DecisionOutcomeV1::Error);
        assert!(!next.has_prepared_publication());
    }

    #[test]
    fn tampered_intent_denies_and_produces_no_command() {
        let mut f = setup();
        let rec = admission_record();
        let intent = build_intent(f.admission_digest, &rec, 1, velocity(1, 800));
        let mut env = sign_intent(&f.ctrl_sk, &intent);
        let mid = env.len() / 2;
        env[mid] ^= 0x01;
        let out = f.actor.decide_intent(&env, INTENT_KEY, f.now);
        assert_eq!(out.outcome, DecisionOutcomeV1::Deny);
        assert!(
            !out.has_prepared_publication(),
            "deny must produce no output"
        );
    }

    #[test]
    fn wrong_actual_key_denies() {
        let mut f = setup();
        let rec = admission_record();
        let intent = build_intent(f.admission_digest, &rec, 1, velocity(1, 800));
        let env = sign_intent(&f.ctrl_sk, &intent);
        let out = f
            .actor
            .decide_intent(&env, "veh/uav-1/haldir/intent/OTHER", f.now);
        assert_eq!(out.outcome, DecisionOutcomeV1::Deny);
        assert!(!out.has_prepared_publication());
    }

    #[test]
    fn replayed_intent_denies_second_time() {
        let mut f = setup();
        let rec = admission_record();
        let intent = build_intent(f.admission_digest, &rec, 1, velocity(1, 800));
        let env = sign_intent(&f.ctrl_sk, &intent);
        assert_eq!(
            f.actor.decide_intent(&env, INTENT_KEY, f.now).outcome,
            DecisionOutcomeV1::Allow
        );
        // identical intent (same seq) is a replay -> deny, no output
        let out = f.actor.decide_intent(&env, INTENT_KEY, f.now);
        assert_eq!(out.outcome, DecisionOutcomeV1::Deny);
        assert!(!out.has_prepared_publication());
    }

    #[test]
    fn stale_session_intent_denies() {
        let mut f = setup();
        let rec = admission_record();
        let mut intent = build_intent(f.admission_digest, &rec, 1, velocity(1, 800));
        intent.ncp_session = NcpSessionIdentityV1 {
            session_id: AsciiId::new("sess-1").unwrap(),
            generation: uuid(9), // wrong generation
        };
        let env = sign_intent(&f.ctrl_sk, &intent);
        let out = f.actor.decide_intent(&env, INTENT_KEY, f.now);
        assert_eq!(out.outcome, DecisionOutcomeV1::Deny);
        assert!(!out.has_prepared_publication());
    }

    #[test]
    fn excessive_velocity_denies_on_policy() {
        let mut f = setup();
        let rec = admission_record();
        let intent = build_intent(f.admission_digest, &rec, 1, velocity(1, 9000)); // > 3000 cap
        let env = sign_intent(&f.ctrl_sk, &intent);
        let out = f.actor.decide_intent(&env, INTENT_KEY, f.now);
        assert_eq!(out.outcome, DecisionOutcomeV1::Deny);
        assert!(!out.has_prepared_publication());
    }

    #[test]
    fn spoofed_controller_id_denies() {
        // BUG-4: the intent's self-declared controller_id must equal the admitted
        // controller, even for an otherwise-valid signed intent.
        let mut f = setup();
        let rec = admission_record();
        let mut intent = build_intent(f.admission_digest, &rec, 1, velocity(1, 400));
        intent.controller_id = ControllerId::new("someone-else").unwrap();
        let env = sign_intent(&f.ctrl_sk, &intent);
        let out = f.actor.decide_intent(&env, INTENT_KEY, f.now);
        assert_eq!(out.outcome, DecisionOutcomeV1::Deny);
        assert!(!out.has_prepared_publication());
    }

    #[test]
    fn clock_regression_latches_and_errors() {
        // BUG-2 / H-H10: a backward `now` is an internal fault, not a policy
        // refusal. It latches the fault and yields ERROR (never extending a live
        // lease's deadline) with no output — distinct from an authorization DENY.
        let mut f = setup();
        let rec = admission_record();
        let env1 = sign_intent(
            &f.ctrl_sk,
            &build_intent(f.admission_digest, &rec, 1, velocity(1, 400)),
        );
        assert_eq!(
            f.actor.decide_intent(&env1, INTENT_KEY, f.now).outcome,
            DecisionOutcomeV1::Allow
        );
        let earlier = MonoInstant::from_nanos(500_000_000);
        let env2 = sign_intent(
            &f.ctrl_sk,
            &build_intent(f.admission_digest, &rec, 2, velocity(2, 400)),
        );
        let out = f.actor.decide_intent(&env2, INTENT_KEY, earlier);
        assert_eq!(out.outcome, DecisionOutcomeV1::Error);
        assert!(!out.has_prepared_publication());
        assert!(
            out.receipt
                .reason_codes
                .as_slice()
                .contains(&DecisionReasonCodeV1::ErrorInternalFault)
        );
        assert_eq!(
            f.actor.process_state(),
            haldir_contracts::status::GateProcessStateV1::FaultLatched
        );
        // the fault is latched: a subsequent well-formed intent still errors
        let env3 = sign_intent(
            &f.ctrl_sk,
            &build_intent(f.admission_digest, &rec, 3, velocity(3, 400)),
        );
        assert_eq!(
            f.actor.decide_intent(&env3, INTENT_KEY, f.now).outcome,
            DecisionOutcomeV1::Error
        );
    }

    #[test]
    fn revoke_active_lease_then_intent_denies() {
        // B1 invalidation: revoking the lease bumps the revision and denies later intents.
        let mut f = setup();
        let rec = admission_record();
        let env = sign_intent(
            &f.ctrl_sk,
            &build_intent(f.admission_digest, &rec, 1, velocity(1, 400)),
        );
        assert_eq!(
            f.actor.decide_intent(&env, INTENT_KEY, f.now).outcome,
            DecisionOutcomeV1::Allow
        );
        f.actor.revoke_active_lease();
        let env2 = sign_intent(
            &f.ctrl_sk,
            &build_intent(f.admission_digest, &rec, 2, velocity(2, 400)),
        );
        let out = f.actor.decide_intent(&env2, INTENT_KEY, f.now);
        assert_eq!(out.outcome, DecisionOutcomeV1::Deny);
        assert!(!out.has_prepared_publication());
    }

    #[test]
    fn mission_phase_mismatch_denies() {
        // H-P04: the lease authorizes exactly one mission phase (INSPECTION). If
        // the Gate-owned trusted state reports a different phase, the lease
        // confers no authority — denied before the per-action policy even runs.
        let mut f = setup();
        let rec = admission_record();
        let mut st = trusted_state(f.now);
        st.mission_phase = AsciiId::new("TRANSIT").unwrap();
        f.actor.set_trusted_state(st).unwrap();
        let env = sign_intent(
            &f.ctrl_sk,
            &build_intent(f.admission_digest, &rec, 1, velocity(1, 400)),
        );
        let out = f.actor.decide_intent(&env, INTENT_KEY, f.now);
        assert_eq!(out.outcome, DecisionOutcomeV1::Deny);
        assert!(
            out.receipt
                .reason_codes
                .as_slice()
                .contains(&DecisionReasonCodeV1::DenyScopeMismatch)
        );
        assert!(!out.has_prepared_publication());
    }

    #[test]
    fn decision_id_exhaustion_latches_error() {
        // H-H06: the decision-id counter is checked; exhaustion latches a fault and
        // yields ERROR (no wrap, no output), rather than silently reusing an id.
        let mut f = setup();
        f.actor.force_next_decision_for_test(u64::MAX);
        let rec = admission_record();
        let env = sign_intent(
            &f.ctrl_sk,
            &build_intent(f.admission_digest, &rec, 1, velocity(1, 400)),
        );
        let out = f.actor.decide_intent(&env, INTENT_KEY, f.now);
        assert_eq!(out.outcome, DecisionOutcomeV1::Error);
        assert!(
            out.receipt
                .reason_codes
                .as_slice()
                .contains(&DecisionReasonCodeV1::ErrorInternalFault)
        );
        assert!(!out.has_prepared_publication());

        // The reserved terminal receipt is replayed byte-for-byte after
        // exhaustion. It is one decision, not a stream of new decisions that
        // reuse an exhausted identifier.
        let retained = f.actor.evidence().len();
        let again = f.actor.decide_intent(&env, INTENT_KEY, f.now);
        assert_eq!(again.receipt.decision_id, out.receipt.decision_id);
        assert_eq!(again.signed_receipt, out.signed_receipt);
        assert_eq!(f.actor.evidence().len(), retained);
        assert_eq!(
            f.actor.process_state(),
            haldir_contracts::status::GateProcessStateV1::FaultLatched
        );
    }

    #[test]
    fn future_ncp_lease_does_not_authorize_acl_only_adapter() {
        let publication = PlantPublicationAuthorityStateV1::NcpLeaseV1(NcpLeaseEvidenceV1 {
            gate_transport_principal: PrincipalId::new("gate.range-a").unwrap(),
            final_route_digest: DigestV1::compute(DigestDomain::Payload, b"route"),
            session: sess(),
            authority_term: NonZeroU64::new(1).unwrap(),
            lease_id: AuthorityLeaseId::new([8; 16]),
            authorized_output_epoch: GateOutputEpoch::new(uuid(5)),
            expires_mono_ns: Some(u64::MAX),
        });
        let mut f = setup_with_publication(publication);
        let rec = admission_record();
        let env = sign_intent(
            &f.ctrl_sk,
            &build_intent(f.admission_digest, &rec, 1, velocity(1, 400)),
        );

        let out = f.actor.decide_intent(&env, INTENT_KEY, f.now);

        assert_eq!(out.outcome, DecisionOutcomeV1::Deny);
        assert!(
            out.receipt
                .reason_codes
                .as_slice()
                .contains(&DecisionReasonCodeV1::DenyNoPublicationAuthority)
        );
        assert!(!out.has_prepared_publication());
    }

    #[test]
    fn set_trusted_state_rejects_bad_ingress() {
        // H-B05: ingress is validated, not blindly accepted. Wrong vehicle, wrong
        // session, an invalid source frame, and a non-advancing capture are each
        // rejected with a stable reason code.
        let mut f = setup();

        let mut wrong_vehicle = trusted_state(f.now);
        wrong_vehicle.vehicle_id = VehicleId::new("uav-2").unwrap();
        assert_eq!(
            f.actor.set_trusted_state(wrong_vehicle),
            Err(DecisionReasonCodeV1::DenyStateProducer)
        );

        let mut wrong_session = trusted_state(f.now);
        wrong_session.session.session_id = AsciiId::new("sess-9").unwrap();
        assert_eq!(
            f.actor.set_trusted_state(wrong_session),
            Err(DecisionReasonCodeV1::DenyStateStale)
        );

        let mut invalid = trusted_state(f.now);
        invalid.primary_source.valid = false;
        assert_eq!(
            f.actor.set_trusted_state(invalid),
            Err(DecisionReasonCodeV1::DenyStateStale)
        );

        // Anti-rollback: a capture older than the currently held snapshot (set at
        // now - 1 ms by the fixture) is rejected.
        let mut rolled_back = trusted_state(f.now);
        rolled_back.captured_mono = MonoInstant::from_nanos(f.now.as_nanos() - 2_000_000);
        assert_eq!(
            f.actor.set_trusted_state(rolled_back),
            Err(DecisionReasonCodeV1::DenyStateStale)
        );
    }

    #[test]
    fn decision_receipt_is_signed_and_verifies_to_gate_identity() {
        // H-B02/H-H03: every decision emits a COSE_Sign1 receipt signed by the
        // Gate application key and bound to the Gate's own subject. Verify it
        // independently against a trust store holding only that key.
        let mut f = setup();
        let rec = admission_record();
        let env = sign_intent(
            &f.ctrl_sk,
            &build_intent(f.admission_digest, &rec, 1, velocity(1, 400)),
        );
        let out = f.actor.decide_intent(&env, INTENT_KEY, f.now);
        assert_eq!(out.outcome, DecisionOutcomeV1::Allow);
        assert!(!out.signed_receipt.is_empty());

        let gate_vk = SigningKey::from_seed([3; 32]).verifying_key();
        let mut trust = TrustStore::new();
        trust
            .insert(KeyRecord {
                kid: kid(3),
                role: KeyRole::GateApplication,
                verifying_key: gate_vk,
                subject: Some("gate-1".to_owned()),
                class: KeyClass::Assurance,
            })
            .unwrap();
        let ctx = ExpectedContext {
            kind: DecisionReceiptV1::KIND,
            schema_major: 1,
            required_role: KeyRole::GateApplication,
            assurance_profile: true,
        };
        let (decoded, signer_kid, subject): (DecisionReceiptV1, _, _) = verify_and_decode(
            &out.signed_receipt,
            &ctx,
            &trust,
            &RevocationSnapshot::new(),
            Limits::DEFAULT,
        )
        .expect("gate receipt verifies");
        assert_eq!(signer_kid, kid(3));
        assert_eq!(subject, Some("gate-1".to_owned()));
        assert_eq!(decoded.decision, DecisionOutcomeV1::Allow);
        assert_eq!(decoded.decision_id, out.receipt.decision_id);
        // Honesty (CL-ALLOW-HONEST-01): the ALLOW receipt claims only that output
        // was prepared, never that it was published downstream.
        assert!(
            decoded
                .reason_codes
                .as_slice()
                .contains(&DecisionReasonCodeV1::AllowPrepared)
        );
        assert!(
            !decoded
                .reason_codes
                .as_slice()
                .contains(&DecisionReasonCodeV1::AllowPublished)
        );
        assert_eq!(decoded.publish_stage, PublishStageV1::OutputPrepared);
        // The exact signed bytes must re-encode from the in-memory receipt.
        assert_eq!(decoded.reason_codes, out.receipt.reason_codes);
    }

    #[test]
    fn decisions_are_journaled_to_the_evidence_chain() {
        // Every decision — ALLOW or DENY — appends its signed receipt to the
        // digest-chained spool, which advances and stays verifiable.
        let mut f = setup();
        let rec = admission_record();
        assert_eq!(f.actor.evidence().len(), 0);

        let e1 = sign_intent(
            &f.ctrl_sk,
            &build_intent(f.admission_digest, &rec, 1, velocity(1, 400)),
        );
        assert_eq!(
            f.actor.decide_intent(&e1, INTENT_KEY, f.now).outcome,
            DecisionOutcomeV1::Allow
        );
        assert_eq!(f.actor.evidence().len(), 1);
        let head1 = f.actor.evidence().chain_head();
        assert!(head1.is_some());

        // An over-range velocity denies but is still journaled.
        let e2 = sign_intent(
            &f.ctrl_sk,
            &build_intent(f.admission_digest, &rec, 2, velocity(2, 999_999)),
        );
        let out2 = f.actor.decide_intent(&e2, INTENT_KEY, f.now);
        assert_eq!(out2.outcome, DecisionOutcomeV1::Deny);
        assert_eq!(f.actor.evidence().len(), 2);
        // The chain advanced (new head) and the whole chain still verifies.
        assert_ne!(f.actor.evidence().chain_head(), head1);
        assert!(f.actor.evidence().verify_chain());
    }
}
