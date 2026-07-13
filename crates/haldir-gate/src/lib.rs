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
    DurableGateStartupError, EntropyError, EntropySource, GateConfigTemplate, LocalStartupConfig,
    OsEntropy, RunningGate, StartupProfile, StartupReport, StartupStateConfig, StateOpenMode,
    start_local, start_with_backends,
};

#[cfg(test)]
mod e2e {
    use super::*;
    use core::num::{NonZeroU32, NonZeroU64};
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
    use haldir_core::time::MonoInstant;
    use haldir_crypto::{
        ExpectedContext, KeyClass, KeyRecord, KeyRole, RevocationSnapshot, SigningKey, TrustStore,
        sign_message, verify_and_decode,
    };
    use haldir_durable::{
        Anchor, AnchorProtection, DurableError, GenerationAnchor, SnapshotBinding, SnapshotStorage,
        StorageMacKey, StoreId,
    };
    use haldir_policy_native::{GeofenceBoxV1, NativePolicySnapshot, PhaseRuleV1};
    use haldir_reference_plant::{PlantConfig, PlantEventKind, ReferencePlant};
    use haldir_state::{BootedDurableAntiRollbackStore, DurableAntiRollbackStore};
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    const INTENT_KEY: &str = "veh/uav-1/haldir/intent/survey-v1";

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
