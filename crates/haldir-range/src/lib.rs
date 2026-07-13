//! `haldir-range` — a deterministic, in-process adversarial range and acceptance
//! campaign for the P0 `assurance-reference-v1` profile.
//!
//! Each scenario asserts the specification's central mediation property: an
//! unauthorized or malformed intent produces NO accepted plant application, while
//! a valid intent drives the deterministic reference plant. This is an in-process
//! campaign; live-transport bypass, wrong-route DDS/MAVROS, and second-backend
//! substitution attacks require live transport or a second backend and are OUT of
//! P0 scope (see `docs/LIMITATIONS.md`).
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

/// Crate version string.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

// The adversarial harness and campaign are test-support: they build fixtures with
// `unwrap`/indexing that are appropriate in tests but not in production code, so
// the entire module is gated to `#[cfg(test)]`.
#[cfg(test)]
mod range {
    use core::num::{NonZeroU32, NonZeroU64};
    use haldir_admission::{AdmissionLevelV1, AdmissionRecordV1, AdmissionSnapshot};
    use haldir_contracts::action::{ActionClassV1, CoordinateFrameV1, RequestedActionV1};
    use haldir_contracts::digest::{DigestDomain, DigestV1};
    use haldir_contracts::ids::{
        AdmissionId, ChallengeNonce, ControllerId, ControllerInstanceId, GateBootId, GateId,
        GateOutputEpoch, IntentEpoch, IntentSeq, KeyId, MissionId, MissionLeaseId, PrincipalId,
        SourceSeq, VehicleId,
    };
    use haldir_contracts::intent::HaldirIntentV1;
    use haldir_contracts::lease::MissionLeaseV1;
    use haldir_contracts::limits::MissionLeaseLimitsV1;
    use haldir_contracts::scalar::{
        AsciiId, BoundedAscii, BoundedSet, BoundedVec, CanonicalUuidV4String,
    };
    use haldir_contracts::session::{HaldirIntentPositionV1, NcpSessionIdentityV1, NcpSourceRefV1};
    use haldir_contracts::status::{AclExclusiveEvidenceV1, PlantPublicationAuthorityStateV1};
    use haldir_core::snapshot::{
        KinematicStateFixedV1, StateUncertaintyFixedV1, TrustedStateSnapshotV1,
        VerifiedSourceStateV1,
    };
    use haldir_core::time::MonoInstant;
    use haldir_crypto::{
        KeyClass, KeyRecord, KeyRole, RevocationSnapshot, SigningKey, TrustStore, sign_message,
    };
    use haldir_gate::{DecisionRecord, GateConfig, VehicleActor};
    use haldir_ncp08::SelectedNcpCommandAdapter;
    use haldir_policy_native::{GeofenceBoxV1, NativePolicySnapshot, PhaseRuleV1};
    use haldir_reference_plant::{PlantConfig, ReferencePlant};

    const INTENT_KEY: &str = "veh/uav-1/haldir/intent/survey-v1";

    fn kid(seed: u8) -> KeyId {
        KeyId::new(vec![seed, 0xAB, seed]).unwrap()
    }
    fn uuid(s: u8) -> CanonicalUuidV4String {
        CanonicalUuidV4String::from_random_bytes([s; 16])
    }
    fn sess(g: u8) -> NcpSessionIdentityV1 {
        NcpSessionIdentityV1 {
            session_id: AsciiId::new("sess-1").unwrap(),
            generation: uuid(g),
        }
    }
    fn source() -> NcpSourceRefV1 {
        NcpSourceRefV1 {
            source_key: BoundedAscii::new("veh/uav-1/state/pose").unwrap(),
            stream_epoch: uuid(2),
            stream_seq: SourceSeq::new(NonZeroU64::new(7).unwrap()),
        }
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

    /// A reusable, deterministic P0 scenario: an ACTIVE actor plus signing material.
    pub struct RangeScenario {
        /// The vehicle actor under test.
        pub actor: VehicleActor,
        /// The admitted controller signing key.
        pub ctrl_sk: SigningKey,
        /// A second, untrusted signing key (stolen-key / wrong-key attacks).
        pub other_sk: SigningKey,
        /// The decision-time monotonic instant.
        pub now: MonoInstant,
        admission_digest: DigestV1,
        rec: AdmissionRecordV1,
    }

    impl RangeScenario {
        /// Build a fully-provisioned, ACTIVE scenario.
        #[must_use]
        pub fn new() -> Self {
            let ctrl_sk = SigningKey::from_seed([1; 32]);
            let mission_sk = SigningKey::from_seed([2; 32]);
            let other_sk = SigningKey::from_seed([3; 32]);
            let gate_sk = SigningKey::from_seed([4; 32]);
            let now = MonoInstant::from_nanos(1_000_000_000);

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
            // Gate application key that signs decision receipts (H-B02), enrolled
            // to the Gate id so a verifier binds signer→gate (H-H03).
            trust
                .insert(KeyRecord {
                    kid: kid(4),
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
                session: sess(1),
                ncp_adapter: SelectedNcpCommandAdapter::modeled_p0(),
                publication: PlantPublicationAuthorityStateV1::AclExclusiveV1(
                    AclExclusiveEvidenceV1 {
                        gate_transport_principal: PrincipalId::new("gate.range-a").unwrap(),
                        final_route_digest: DigestV1::compute(DigestDomain::Payload, b"route"),
                        certificate_fingerprint: DigestV1::compute(DigestDomain::Payload, b"cert"),
                        acl_policy_digest: DigestV1::compute(DigestDomain::Payload, b"acl"),
                        verified_at_mono_ns: 900,
                    },
                ),
                output_epoch: GateOutputEpoch::new(uuid(5)),
                local_cap_ms: 30_000,
                gate_signer: gate_sk,
                gate_signer_kid: kid(4),
            };
            let mut actor = VehicleActor::new(cfg).expect("range fixture has valid Gate config");
            actor.register_challenge(
                ChallengeNonce::new([7; 32]),
                MonoInstant::from_nanos(u64::MAX),
                now,
            );

            let lease_env = sign_message(
                &Self::lease(admission_digest, &rec),
                MissionLeaseV1::KIND,
                1,
                &kid(2),
                &mission_sk,
            );
            actor
                .accept_lease_env(&lease_env, now)
                .expect("lease accepted");
            // Capture the initial snapshot 1 ms before decision time so a later
            // re-set at `now` strictly advances the anti-rollback capture clock.
            let initial_capture = MonoInstant::from_nanos(now.as_nanos() - 1_000_000);
            actor
                .set_trusted_state(Self::trusted_state(initial_capture))
                .unwrap();

            Self {
                actor,
                ctrl_sk,
                other_sk,
                now,
                admission_digest,
                rec,
            }
        }

        fn lease(admission_digest: DigestV1, rec: &AdmissionRecordV1) -> MissionLeaseV1 {
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
                ncp_session: sess(1),
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
                allowed_frames: BoundedSet::from_iter_checked([CoordinateFrameV1::LocalNed])
                    .unwrap(),
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
                session: sess(1),
                captured_mono: now,
                primary_source: VerifiedSourceStateV1 {
                    source: source(),
                    session: sess(1),
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

        /// A base valid intent for the current lease.
        #[must_use]
        pub fn intent(&self, seq: u64, action: RequestedActionV1) -> HaldirIntentV1 {
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
                ncp_session: sess(1),
                mission_lease_id: MissionLeaseId::new([2; 16]),
                mission_lease_term: NonZeroU64::new(10).unwrap(),
                admission_id: AdmissionId::new([4; 16]),
                admission_digest: self.admission_digest,
                controller_bundle_digest: self.rec.controller_bundle_digest,
                backend_profile_digest: self.rec.backend_profile_digest,
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

        /// Sign an intent with the admitted controller key.
        #[must_use]
        pub fn sign(&self, intent: &HaldirIntentV1) -> Vec<u8> {
            sign_message(intent, HaldirIntentV1::KIND, 1, &kid(1), &self.ctrl_sk)
        }

        /// Sign an intent with an untrusted key (stolen-key attack).
        #[must_use]
        pub fn sign_untrusted(&self, intent: &HaldirIntentV1) -> Vec<u8> {
            // Uses the controller kid but the wrong secret key: signature must fail.
            sign_message(intent, HaldirIntentV1::KIND, 1, &kid(1), &self.other_sk)
        }

        /// Run the decision pipeline.
        pub fn decide(&mut self, env: &[u8], key: &str) -> DecisionRecord {
            self.actor.decide_intent(env, key, self.now)
        }
    }

    impl Default for RangeScenario {
        fn default() -> Self {
            Self::new()
        }
    }

    /// A convenience velocity action.
    #[must_use]
    pub fn velocity(n: i32) -> RequestedActionV1 {
        RequestedActionV1::VelocityLocalNed {
            north_mm_s: n,
            east_mm_s: 0,
            down_mm_s: 0,
            requested_validity_ms: NonZeroU32::new(300).unwrap(),
        }
    }

    /// Explicitly cross the modeled publication boundary, ingest the Gate-authored
    /// command into a fresh reference plant, resolve local success, and run it.
    #[must_use]
    pub fn drive_plant(
        actor: &mut VehicleActor,
        record: DecisionRecord,
        published_at: MonoInstant,
        ticks: u64,
    ) -> Option<ReferencePlant> {
        let prepared = record.into_prepared_publication()?;
        let called = actor.mark_publish_called(prepared, published_at).ok()?;
        let cmd = called.reference_plant_command().clone();
        let mut plant = ReferencePlant::new(PlantConfig::default());
        if plant.ingest(cmd).is_err() {
            let _ = actor.mark_publish_returned_error(called);
            return None;
        }
        actor.mark_publish_returned_ok(called, published_at).ok()?;
        plant.run(ticks);
        Some(plant)
    }

    #[cfg(test)]
    mod campaign {
        use super::*;
        use haldir_contracts::receipt::DecisionOutcomeV1;
        use haldir_reference_plant::PlantEventKind;

        /// Assert a decision denied and produced no plant application capability.
        fn assert_denied(rec: &DecisionRecord) {
            assert_eq!(rec.outcome, DecisionOutcomeV1::Deny);
            assert!(
                !rec.has_prepared_publication(),
                "deny must produce no publication capability"
            );
        }

        #[test]
        fn allow_baseline_drives_plant_and_reaches_safe_region() {
            let mut s = RangeScenario::new();
            let env = s.sign(&s.intent(1, velocity(400)));
            let rec = s.decide(&env, INTENT_KEY);
            assert_eq!(rec.outcome, DecisionOutcomeV1::Allow);
            let published_at = s.now;
            let mut plant = drive_plant(&mut s.actor, rec, published_at, 15).expect("plant driven");
            assert!(
                plant
                    .events()
                    .iter()
                    .any(|e| e.kind == PlantEventKind::ResponseObserved)
            );
            // after command expiry the plant reaches its declared hold region
            plant.run(30);
            assert!(plant.safe_region_reached());
        }

        #[test]
        fn wrong_route() {
            let mut s = RangeScenario::new();
            let env = s.sign(&s.intent(1, velocity(400)));
            assert_denied(&s.decide(&env, "veh/uav-1/haldir/intent/OTHER"));
        }

        #[test]
        fn forged_signature() {
            let mut s = RangeScenario::new();
            let mut env = s.sign(&s.intent(1, velocity(400)));
            let m = env.len() / 2;
            env[m] ^= 0x01;
            assert_denied(&s.decide(&env, INTENT_KEY));
        }

        #[test]
        fn stolen_transport_wrong_app_key() {
            let mut s = RangeScenario::new();
            let env = s.sign_untrusted(&s.intent(1, velocity(400)));
            assert_denied(&s.decide(&env, INTENT_KEY));
        }

        #[test]
        fn session_generation_replay() {
            let mut s = RangeScenario::new();
            let mut intent = s.intent(1, velocity(400));
            intent.ncp_session = sess(9);
            let env = s.sign(&intent);
            assert_denied(&s.decide(&env, INTENT_KEY));
        }

        #[test]
        fn intent_replay() {
            let mut s = RangeScenario::new();
            let env = s.sign(&s.intent(1, velocity(400)));
            assert_eq!(s.decide(&env, INTENT_KEY).outcome, DecisionOutcomeV1::Allow);
            assert_denied(&s.decide(&env, INTENT_KEY));
        }

        #[test]
        fn stale_intent_sequence() {
            let mut s = RangeScenario::new();
            // first intent must be sequence one, then a gap is allowed
            let env1 = s.sign(&s.intent(1, velocity(400)));
            let first = s.decide(&env1, INTENT_KEY);
            assert_eq!(first.outcome, DecisionOutcomeV1::Allow);
            s.actor
                .cancel_prepared_publication(
                    first
                        .into_prepared_publication()
                        .expect("first output prepared"),
                )
                .expect("first output cancelled before the next decision");
            let env3 = s.sign(&s.intent(3, velocity(400)));
            let third = s.decide(&env3, INTENT_KEY);
            assert_eq!(third.outcome, DecisionOutcomeV1::Allow);
            s.actor
                .cancel_prepared_publication(
                    third
                        .into_prepared_publication()
                        .expect("third output prepared"),
                )
                .expect("third output cancelled before the stale decision");
            // a now-lower sequence (2 <= last_seq 3) is stale
            let env2 = s.sign(&s.intent(2, velocity(400)));
            assert_denied(&s.decide(&env2, INTENT_KEY));
        }

        #[test]
        fn wrong_gate_boot() {
            let mut s = RangeScenario::new();
            let mut intent = s.intent(1, velocity(400));
            intent.gate_boot_id = GateBootId::new([0xEE; 16]);
            let env = s.sign(&intent);
            assert_denied(&s.decide(&env, INTENT_KEY));
        }

        #[test]
        fn bundle_substitution() {
            let mut s = RangeScenario::new();
            let mut intent = s.intent(1, velocity(400));
            intent.controller_bundle_digest = DigestV1::compute(DigestDomain::Bundle, b"OTHER");
            let env = s.sign(&intent);
            assert_denied(&s.decide(&env, INTENT_KEY));
        }

        #[test]
        fn backend_profile_substitution() {
            let mut s = RangeScenario::new();
            let mut intent = s.intent(1, velocity(400));
            intent.backend_profile_digest =
                DigestV1::compute(DigestDomain::BackendProfile, b"OTHER");
            let env = s.sign(&intent);
            assert_denied(&s.decide(&env, INTENT_KEY));
        }

        #[test]
        fn source_spoof_wrong_source() {
            let mut s = RangeScenario::new();
            let mut intent = s.intent(1, velocity(400));
            intent.primary_source = NcpSourceRefV1 {
                source_key: BoundedAscii::new("veh/uav-1/state/pose").unwrap(),
                stream_epoch: uuid(2),
                stream_seq: SourceSeq::new(NonZeroU64::new(999).unwrap()), // not in cache
            };
            let env = s.sign(&intent);
            assert_denied(&s.decide(&env, INTENT_KEY));
        }

        #[test]
        fn excessive_component_denied() {
            let mut s = RangeScenario::new();
            let env = s.sign(&s.intent(1, velocity(9000)));
            assert_denied(&s.decide(&env, INTENT_KEY));
        }

        #[test]
        fn excessive_norm_denied() {
            let mut s = RangeScenario::new();
            let action = RequestedActionV1::VelocityLocalNed {
                north_mm_s: 2000,
                east_mm_s: 2000,
                down_mm_s: 2000, // each < 3000 but norm ~3464 > 3000
                requested_validity_ms: NonZeroU32::new(300).unwrap(),
            };
            let env = s.sign(&s.intent(1, action));
            assert_denied(&s.decide(&env, INTENT_KEY));
        }

        #[test]
        fn geofence_violation_denied() {
            let mut s = RangeScenario::new();
            // move the trusted state near the +X boundary
            let now = s.now;
            let mut st = RangeScenario::trusted_state(now);
            st.kinematic.position_mm = [99_000, 0, 0];
            s.actor.set_trusted_state(st).unwrap();
            let env = s.sign(&s.intent(1, velocity(3000)));
            assert_denied(&s.decide(&env, INTENT_KEY));
        }

        #[test]
        fn stale_state_denied() {
            let mut s = RangeScenario::new();
            // A snapshot that passes ingress (capture advances) but whose source
            // frame is far in the past relative to `now`: policy denies on source
            // freshness. (An older *capture* is now rejected at ingress by the
            // anti-rollback check — see stale_state_rollback_rejected.)
            let mut st = RangeScenario::trusted_state(s.now);
            st.primary_source.receive_mono = MonoInstant::from_nanos(1);
            s.actor.set_trusted_state(st).unwrap();
            let env = s.sign(&s.intent(1, velocity(400)));
            assert_denied(&s.decide(&env, INTENT_KEY));
        }

        #[test]
        fn stale_state_rollback_rejected() {
            // Anti-rollback (H-B05): after a snapshot at `now`, a producer cannot
            // regress to an older-but-still-fresh capture to revive a stale truth.
            let mut s = RangeScenario::new();
            let fresh = RangeScenario::trusted_state(s.now);
            s.actor.set_trusted_state(fresh).unwrap();
            let older =
                RangeScenario::trusted_state(MonoInstant::from_nanos(s.now.as_nanos() - 500_000));
            assert!(s.actor.set_trusted_state(older).is_err());
        }

        #[test]
        fn oversize_intent_denied() {
            let mut s = RangeScenario::new();
            let big = vec![0u8; 32 * 1024]; // over the 16 KiB ingress limit
            assert_denied(&s.decide(&big, INTENT_KEY));
        }

        #[test]
        fn hold_is_allowed() {
            let mut s = RangeScenario::new();
            let action = RequestedActionV1::Hold {
                requested_validity_ms: NonZeroU32::new(300).unwrap(),
            };
            let env = s.sign(&s.intent(1, action));
            assert_eq!(s.decide(&env, INTENT_KEY).outcome, DecisionOutcomeV1::Allow);
        }
    }
}
