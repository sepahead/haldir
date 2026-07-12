//! The per-vehicle decision actor and the 13-stage intent pipeline.
//!
//! All mutable authorization state for one vehicle is owned here. A single
//! `authorization_revision` is captured at the start of a decision and re-checked
//! immediately before output-sequence allocation (spec B1). Every DENY produces
//! no output and (from the replay-commit point on) consumes the intent sequence.

use haldir_admission::{AdmissionClaim, AdmissionSnapshot};
use haldir_contracts::cbor::Limits;
use haldir_contracts::digest::{DigestDomain, DigestV1};
use haldir_contracts::ids::{DecisionId, GateBootId, GateId, GateOutputEpoch, VehicleId};
use haldir_contracts::intent::HaldirIntentV1;
use haldir_contracts::lease::MissionLeaseV1;
use haldir_contracts::receipt::{
    DecisionOutcomeV1, DecisionReasonCodeV1 as R, DecisionReceiptV1, PublishStageV1,
    TransformationRelationV1,
};
use haldir_contracts::scalar::{AsciiId, BoundedVec};
use haldir_contracts::session::{
    HaldirIntentPositionV1, NcpSessionIdentityV1, NcpSourceRefV1, NcpStreamPositionV1,
};
use haldir_contracts::status::{GateProcessStateV1, PlantPublicationAuthorityStateV1};
use haldir_core::snapshot::ActiveMissionLeaseSnapshot;
use haldir_core::snapshot::{AdmittedControllerSnapshot, TrustedStateSnapshotV1};
use haldir_core::time::MonoInstant;
use haldir_crypto::{
    CryptoError, ExpectedContext, KeyRole, RevocationSnapshot, TrustStore, verify_and_decode,
};
use haldir_ncp08::{
    AclOnlyAdapter, ExactNcpCommandFrame, GateCommandBuildInputV1, NcpCommandAdapter,
};
use haldir_policy_native::{BoundedActionHistory, NativePolicySnapshot, PolicyInput, decide};
use haldir_reference_plant::{PlantAction, PlantCommand};
use haldir_state::{
    AntiRollbackStore, ChallengeTable, ControllerReplayState, GateOutputStreamState,
    GateProcessMachine, LeaseAcceptContext, RevisionCounter, accept_lease,
};

const MAX_RETIRED: usize = 16;
const INTENT_SIZE_LIMIT: usize = 16 * 1024;

/// A gate-level error for authority-establishment operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateError {
    /// A crypto/verification failure.
    Crypto(&'static str),
    /// An admission-verification failure.
    Admission(&'static str),
    /// A lease-acceptance failure.
    Lease(&'static str),
    /// The gate is fault-latched.
    Faulted,
}

/// The result of processing one intent.
#[derive(Debug, Clone)]
pub struct DecisionRecord {
    /// The signed-shape decision receipt.
    pub receipt: DecisionReceiptV1,
    /// The decision outcome.
    pub outcome: DecisionOutcomeV1,
    /// The prepared exact NCP frame (only on ALLOW).
    pub frame: Option<ExactNcpCommandFrame>,
    /// The plant command derived from the frame (only on ALLOW).
    pub plant_command: Option<PlantCommand>,
}

impl DecisionRecord {
    /// Whether the decision allowed and produced output.
    #[must_use]
    pub fn allowed(&self) -> bool {
        self.outcome == DecisionOutcomeV1::Allow && self.plant_command.is_some()
    }
}

/// Static + provisioned configuration for one vehicle actor.
pub struct GateConfig {
    /// Gate id.
    pub gate_id: GateId,
    /// Gate boot id (fresh per process).
    pub gate_boot_id: GateBootId,
    /// Realm.
    pub realm: AsciiId<64>,
    /// Vehicle id.
    pub vehicle_id: VehicleId,
    /// Application-signature trust store.
    pub trust: TrustStore,
    /// Revocation snapshot.
    pub revocations: RevocationSnapshot,
    /// Admission snapshot.
    pub admission: AdmissionSnapshot,
    /// Native policy snapshot.
    pub policy: NativePolicySnapshot,
    /// Policy snapshot digest.
    pub policy_snapshot_digest: DigestV1,
    /// Current NCP session.
    pub session: NcpSessionIdentityV1,
    /// Plant-publication authority state.
    pub publication: PlantPublicationAuthorityStateV1,
    /// Gate output epoch.
    pub output_epoch: GateOutputEpoch,
    /// Local cap on lease active duration (ms).
    pub local_cap_ms: u32,
}

/// The per-vehicle decision actor.
pub struct VehicleActor {
    gate_id: GateId,
    gate_boot_id: GateBootId,
    realm: AsciiId<64>,
    vehicle_id: VehicleId,
    adapter: AclOnlyAdapter,
    trust: TrustStore,
    revocations: RevocationSnapshot,
    admission: AdmissionSnapshot,
    policy: NativePolicySnapshot,
    policy_snapshot_digest: DigestV1,
    session: NcpSessionIdentityV1,
    publication: PlantPublicationAuthorityStateV1,
    output_epoch: GateOutputEpoch,
    output_stream: GateOutputStreamState,
    challenges: ChallengeTable,
    anti_rollback: AntiRollbackStore,
    lease: Option<ActiveMissionLeaseSnapshot>,
    replay: ControllerReplayState,
    history: BoundedActionHistory,
    trusted_state: Option<TrustedStateSnapshotV1>,
    fault: haldir_state::FaultLatch,
    revision: RevisionCounter,
    process: GateProcessMachine,
    next_decision: u64,
    local_cap_ms: u32,
    last_seen_mono: Option<MonoInstant>,
}

struct ReceiptDraft {
    decision_id: DecisionId,
    gate_id: GateId,
    gate_boot_id: GateBootId,
    vehicle_id: VehicleId,
    session: NcpSessionIdentityV1,
    received_key_digest: DigestV1,
    raw_envelope_digest: DigestV1,
    policy_snapshot_digest: DigestV1,
    received_mono_ns: u64,
    payload_digest: Option<DigestV1>,
    semantic_intent_digest: Option<DigestV1>,
    controller_id: Option<haldir_contracts::ids::ControllerId>,
    controller_intent_position: Option<HaldirIntentPositionV1>,
    mission_id: Option<haldir_contracts::ids::MissionId>,
    mission_lease_id: Option<haldir_contracts::ids::MissionLeaseId>,
    admission_digest: Option<DigestV1>,
    source: Option<NcpSourceRefV1>,
    state_snapshot_digest: Option<DigestV1>,
}

impl ReceiptDraft {
    fn base(&self) -> DecisionReceiptV1 {
        DecisionReceiptV1 {
            decision_id: self.decision_id,
            gate_id: self.gate_id.clone(),
            gate_boot_id: self.gate_boot_id,
            vehicle_id: self.vehicle_id.clone(),
            mission_id: self.mission_id.clone(),
            ncp_session: self.session.clone(),
            received_key_digest: self.received_key_digest,
            raw_envelope_digest: self.raw_envelope_digest,
            payload_digest: self.payload_digest,
            semantic_intent_digest: self.semantic_intent_digest,
            controller_id: self.controller_id.clone(),
            controller_intent_position: self.controller_intent_position.clone(),
            mission_lease_id: self.mission_lease_id,
            admission_digest: self.admission_digest,
            source: self.source.clone(),
            state_snapshot_digest: self.state_snapshot_digest,
            policy_snapshot_digest: self.policy_snapshot_digest,
            decision: DecisionOutcomeV1::Deny,
            reason_codes: BoundedVec::new(),
            effective_validity_ms: None,
            gate_output_stream: None,
            output_frame_digest: None,
            transformation_relation: None,
            received_mono_ns: self.received_mono_ns,
            decided_mono_ns: self.received_mono_ns,
            publish_stage: PublishStageV1::DecidedDeny,
        }
    }
}

impl VehicleActor {
    /// Construct a session-bound actor from configuration.
    #[must_use]
    pub fn new(cfg: GateConfig) -> Self {
        let mut anti_rollback = AntiRollbackStore::new_empty();
        let _ = anti_rollback.advance_boot();
        let mut process = GateProcessMachine::new();
        let _ = process.transition(GateProcessStateV1::Recovering);
        let _ = process.transition(GateProcessStateV1::ReadyNoSession);
        let _ = process.transition(GateProcessStateV1::SessionBound);
        Self {
            gate_id: cfg.gate_id,
            gate_boot_id: cfg.gate_boot_id,
            realm: cfg.realm,
            vehicle_id: cfg.vehicle_id,
            adapter: AclOnlyAdapter::new(),
            trust: cfg.trust,
            revocations: cfg.revocations,
            admission: cfg.admission,
            policy: cfg.policy,
            policy_snapshot_digest: cfg.policy_snapshot_digest,
            session: cfg.session,
            publication: cfg.publication,
            output_epoch: cfg.output_epoch,
            output_stream: GateOutputStreamState::new(cfg.output_epoch, MAX_RETIRED),
            challenges: ChallengeTable::new(4),
            anti_rollback,
            lease: None,
            replay: ControllerReplayState::new(MAX_RETIRED),
            history: BoundedActionHistory::new(64),
            trusted_state: None,
            fault: haldir_state::FaultLatch::new(),
            revision: RevisionCounter::new(),
            process,
            next_decision: 0,
            local_cap_ms: cfg.local_cap_ms,
            last_seen_mono: None,
        }
    }

    /// Detect a monotonic-clock regression (spec T5/B13, punch-list BUG-2). A
    /// backward `now` while ACTIVE latches a fault and denies rather than extending
    /// a live lease's deadline; on success the last-seen instant is advanced.
    fn mono_ok(&mut self, now: MonoInstant) -> bool {
        if let Some(last) = self.last_seen_mono
            && now < last
        {
            self.fault.latch("MONOTONIC_REGRESSION");
            self.revision.bump();
            return false;
        }
        self.last_seen_mono = Some(now);
        true
    }

    /// Revoke the active mission lease (an authorization invalidation): clears the
    /// lease, retires the controller replay epoch, and bumps the authorization
    /// revision. After this, decisions DENY with `DENY_LEASE_ABSENT` until a fresh
    /// lease is accepted.
    pub fn revoke_active_lease(&mut self) {
        self.lease = None;
        let _ = self.replay.retire_active();
        self.revision.bump();
        let _ = self.process.transition(GateProcessStateV1::SessionBound);
    }

    /// The current process state.
    #[must_use]
    pub fn process_state(&self) -> GateProcessStateV1 {
        self.process.state()
    }

    /// Register a pending challenge nonce (issued out of band by the orchestrator).
    pub fn register_challenge(
        &mut self,
        nonce: haldir_contracts::ids::ChallengeNonce,
        expires_at: MonoInstant,
    ) -> bool {
        self.challenges.insert(nonce, expires_at)
    }

    /// Set the current trusted-state snapshot (produced by the trusted-state task).
    pub fn set_trusted_state(&mut self, state: TrustedStateSnapshotV1) {
        self.trusted_state = Some(state);
    }

    /// Accept a signed mission lease and become ACTIVE.
    ///
    /// # Errors
    /// Returns a [`GateError`] if signature, admission, or acceptance fails.
    pub fn accept_lease_env(&mut self, env: &[u8], now: MonoInstant) -> Result<(), GateError> {
        if self.fault.is_latched() {
            return Err(GateError::Faulted);
        }
        if !self.mono_ok(now) {
            return Err(GateError::Faulted);
        }
        let ctx = ExpectedContext {
            kind: MissionLeaseV1::KIND,
            schema_major: 1,
            required_role: KeyRole::MissionAuthority,
            assurance_profile: true,
        };
        let (lease, _kid, _sub): (MissionLeaseV1, _, _) =
            verify_and_decode(env, &ctx, &self.trust, &self.revocations, Limits::LARGE)
                .map_err(|e: CryptoError| GateError::Crypto(e.reason_code()))?;

        let claim = AdmissionClaim {
            admission_id: &lease.admission_id,
            admission_digest: &lease.admission_digest,
            controller_id: &lease.controller_id,
            controller_bundle_digest: &lease.controller_bundle_digest,
            backend_profile_digest: &lease.backend_profile_digest,
        };
        self.admission
            .verify_admission(&claim, true)
            .map_err(|e| GateError::Admission(e.reason_code().code()))?;
        let rel = self
            .admission
            .resolve(&lease.admission_id)
            .ok_or(GateError::Admission("DENY_ADMISSION_MISMATCH"))?;
        let controller = AdmittedControllerSnapshot {
            controller_id: rel.record.controller_id.clone(),
            bundle_digest: rel.record.controller_bundle_digest,
            backend_profile_digest: rel.record.backend_profile_digest,
            admission_id: rel.record.admission_id,
            admission_digest: rel.digest,
        };
        let lctx = LeaseAcceptContext {
            gate_id: self.gate_id.clone(),
            gate_boot_id: self.gate_boot_id,
            realm: self.realm.clone(),
            vehicle_id: self.vehicle_id.clone(),
            session: self.session.clone(),
            gate_output_epoch: self.output_epoch,
            policy_snapshot_digest: self.policy_snapshot_digest,
            controller,
            local_cap_ms: self.local_cap_ms,
        };
        let snap = accept_lease(
            &lease,
            &lctx,
            &mut self.challenges,
            &mut self.anti_rollback,
            now,
        )
        .map_err(|e| GateError::Lease(e.reason_code().code()))?;
        self.lease = Some(snap);
        self.replay = ControllerReplayState::new(MAX_RETIRED);
        self.revision.bump();
        let _ = self.process.transition(GateProcessStateV1::Active);
        Ok(())
    }

    fn make_decision_id(&mut self) -> DecisionId {
        self.next_decision = self.next_decision.saturating_add(1);
        let mut b = [0u8; 16];
        b[..8].copy_from_slice(&self.next_decision.to_be_bytes());
        DecisionId::new(b)
    }

    fn deny(&self, draft: &ReceiptDraft, reason: R, now: MonoInstant) -> DecisionRecord {
        let mut receipt = draft.base();
        receipt.decision = DecisionOutcomeV1::Deny;
        receipt.reason_codes = BoundedVec::from_vec(vec![reason]).unwrap_or_default();
        receipt.decided_mono_ns = now.as_nanos();
        DecisionRecord {
            receipt,
            outcome: DecisionOutcomeV1::Deny,
            frame: None,
            plant_command: None,
        }
    }

    /// The full 13-stage intent decision pipeline.
    #[allow(clippy::too_many_lines)]
    pub fn decide_intent(
        &mut self,
        env: &[u8],
        actual_key: &str,
        now: MonoInstant,
    ) -> DecisionRecord {
        let decision_id = self.make_decision_id();
        let mut draft = ReceiptDraft {
            decision_id,
            gate_id: self.gate_id.clone(),
            gate_boot_id: self.gate_boot_id,
            vehicle_id: self.vehicle_id.clone(),
            session: self.session.clone(),
            received_key_digest: DigestV1::compute(DigestDomain::Payload, actual_key.as_bytes()),
            raw_envelope_digest: DigestV1::compute(DigestDomain::RawEnvelope, env),
            policy_snapshot_digest: self.policy_snapshot_digest,
            received_mono_ns: now.as_nanos(),
            payload_digest: None,
            semantic_intent_digest: None,
            controller_id: None,
            controller_intent_position: None,
            mission_id: None,
            mission_lease_id: None,
            admission_digest: None,
            source: None,
            state_snapshot_digest: None,
        };

        // Stage 0 — fault / monotonic clock / active / ingress admission
        if self.fault.is_latched() {
            return self.deny(&draft, R::ErrorInternalFault, now);
        }
        if !self.mono_ok(now) {
            return self.deny(&draft, R::ErrorInternalFault, now);
        }
        if !self.process.is_active() {
            return self.deny(&draft, R::DenyLeaseAbsent, now);
        }
        if env.len() > INTENT_SIZE_LIMIT {
            return self.deny(&draft, R::DenyOversize, now);
        }

        // Stage 1-2 — structural decode + cryptographic verification
        let ctx = ExpectedContext {
            kind: HaldirIntentV1::KIND,
            schema_major: 1,
            required_role: KeyRole::ControllerIntent,
            assurance_profile: true,
        };
        let (intent, signer_kid, _sub): (HaldirIntentV1, _, _) =
            match verify_and_decode(env, &ctx, &self.trust, &self.revocations, Limits::DEFAULT) {
                Ok(v) => v,
                Err(e) => return self.deny(&draft, crypto_reason(&e), now),
            };
        draft.payload_digest = Some(DigestV1::of_value(DigestDomain::Payload, &intent));
        draft.semantic_intent_digest =
            Some(DigestV1::of_value(DigestDomain::SemanticIntent, &intent));
        draft.controller_id = Some(intent.controller_id.clone());
        draft.controller_intent_position = Some(intent.intent_position.clone());
        draft.mission_id = Some(intent.mission_id.clone());
        draft.mission_lease_id = Some(intent.mission_lease_id);
        draft.admission_digest = Some(intent.admission_digest);
        draft.source = Some(intent.primary_source.clone());

        // Stage 4 — capture the authorization revision (TOCTOU baseline, B1)
        let captured_rev = self.revision.get();

        let Some(lease) = self.lease.clone() else {
            return self.deny(&draft, R::DenyLeaseAbsent, now);
        };

        // Stage 3 — identity / routing binding
        if actual_key != intent.actual_intent_key.as_str()
            || actual_key != lease.controller_intent_key
        {
            return self.deny(&draft, R::DenyWrongActualKey, now);
        }
        if signer_kid != lease.controller_intent_signing_key_id {
            return self.deny(&draft, R::DenyWrongRole, now);
        }

        // Stage 5 — scope checks
        if intent.gate_id != self.gate_id || intent.gate_boot_id != self.gate_boot_id {
            return self.deny(&draft, R::DenyGateBootMismatch, now);
        }
        if intent.realm != self.realm || intent.vehicle_id != self.vehicle_id {
            return self.deny(&draft, R::DenyScopeMismatch, now);
        }
        if intent.ncp_session != self.session {
            return self.deny(&draft, R::DenySessionStale, now);
        }
        if intent.mission_id != lease.mission_id
            || intent.mission_lease_id != lease.lease_id
            || intent.mission_lease_term.get() != lease.lease_term
        {
            return self.deny(&draft, R::DenyScopeMismatch, now);
        }
        if intent.admission_id != lease.controller.admission_id
            || intent.admission_digest != lease.controller.admission_digest
            || intent.controller_bundle_digest != lease.controller.bundle_digest
            || intent.backend_profile_digest != lease.controller.backend_profile_digest
        {
            return self.deny(&draft, R::DenyAdmissionMismatch, now);
        }
        // Bind the intent's self-declared controller identity to the admitted
        // controller and the verified signer (punch-list BUG-4): these are
        // equality-checked consistency claims, not trusted evidence content.
        if intent.controller_id != lease.controller.controller_id
            || intent.controller_signing_key_id != signer_kid
        {
            return self.deny(&draft, R::DenyScopeMismatch, now);
        }
        if lease.remaining_ms(now) == 0 {
            return self.deny(&draft, R::DenyLeaseExpired, now);
        }

        // Stage 6 — controller replay (two-phase): classify (no consume) then commit
        let cls = self.replay.classify(
            intent.intent_position.epoch,
            intent.intent_position.seq.get(),
        );
        if !cls.is_fresh() {
            return self.deny(&draft, replay_reason(cls), now);
        }
        let _ = self.replay.commit_consume(
            intent.intent_position.epoch,
            intent.intent_position.seq.get(),
        );

        // Stage 7 — source / state correlation
        let Some(state) = self.trusted_state.clone() else {
            return self.deny(&draft, R::DenyStateUnavailable, now);
        };
        if state.session != self.session {
            return self.deny(&draft, R::DenyStateStale, now);
        }
        if intent.primary_source != state.primary_source.source {
            return self.deny(&draft, R::DenySourceUnknown, now);
        }
        draft.state_snapshot_digest = Some(state.canonical_digest());

        // Stage 8-11 — deterministic native policy + effective validity
        let decision = decide(&PolicyInput {
            now,
            lease: &lease,
            state: &state,
            action: &intent.action,
            history: &self.history,
            policy: &self.policy,
        });
        let effective_validity_ms = match decision.effective_validity_ms() {
            Some(v) => v,
            None => {
                let reason = decision
                    .reasons
                    .first()
                    .copied()
                    .unwrap_or(R::DenyPolicyDiagnostic);
                return self.deny(&draft, reason, now);
            }
        };

        // Stage 12 — output allocation, after a TOCTOU re-check (B1)
        if self.revision.get() != captured_rev {
            return self.deny(&draft, R::ErrorInternalFault, now);
        }
        if !self.publication.authorizes_publication() {
            return self.deny(&draft, R::DenyNoPublicationAuthority, now);
        }
        let out_seq = match self.output_stream.allocate() {
            Ok(s) => s,
            Err(_) => return self.deny(&draft, R::DenyOverload, now),
        };
        let build_input = GateCommandBuildInputV1 {
            decision_id,
            session: self.session.clone(),
            stream: NcpStreamPositionV1 {
                epoch: self.output_stream.current_epoch(),
                seq: out_seq,
            },
            source: state.primary_source.source.clone(),
            source_t_ns: state.primary_source.publisher_t_ns,
            gate_t_ns: now.as_nanos(),
            action: intent.action,
            effective_validity_ms,
        };
        let frame = match self.adapter.build_command(&build_input) {
            Ok(f) => f,
            Err(_) => {
                self.fault.latch("NCP_BUILD_FAILED");
                self.revision.bump();
                return self.deny(&draft, R::ErrorInternalFault, now);
            }
        };
        if self
            .adapter
            .validate_exact_command(&frame, &build_input)
            .is_err()
        {
            self.fault.latch("NCP_VALIDATE_FAILED");
            self.revision.bump();
            return self.deny(&draft, R::ErrorInternalFault, now);
        }

        // Stage 13 — prepare plant command, update history (H7), emit ALLOW receipt
        let plant_action = if frame.is_hold() {
            PlantAction::Hold
        } else {
            PlantAction::Velocity(frame.decoded_velocity_mm_s())
        };
        let plant_command = PlantCommand {
            decision_id,
            session: self.session.clone(),
            output_epoch: build_input.stream.epoch,
            output_seq: out_seq,
            source: state.primary_source.source.clone(),
            action: plant_action,
            validity_ms: effective_validity_ms,
            output_frame_digest: frame.digest,
        };
        let window_start = MonoInstant::from_nanos(
            now.as_nanos()
                .saturating_sub(u64::from(self.policy.duty_window_ms) * 1_000_000),
        );
        let end = now
            .checked_add_ms(u64::from(effective_validity_ms))
            .unwrap_or(now);
        match plant_action {
            PlantAction::Hold => self.history.record_hold(),
            PlantAction::Velocity(v) => self.history.record_velocity(v, now, end, window_start),
        }

        let mut receipt = draft.base();
        receipt.decision = DecisionOutcomeV1::Allow;
        receipt.reason_codes = BoundedVec::from_vec(vec![R::AllowPublished]).unwrap_or_default();
        receipt.effective_validity_ms = Some(effective_validity_ms);
        receipt.gate_output_stream = Some(build_input.stream.clone());
        receipt.output_frame_digest = Some(frame.digest);
        receipt.transformation_relation = Some(if frame.is_hold() {
            TransformationRelationV1::Identity
        } else {
            TransformationRelationV1::FixedPointToNcpFloatV1
        });
        receipt.decided_mono_ns = now.as_nanos();
        // Gate signs only what it observed: it prepared the exact output bytes.
        receipt.publish_stage = PublishStageV1::OutputPrepared;

        DecisionRecord {
            receipt,
            outcome: DecisionOutcomeV1::Allow,
            frame: Some(frame),
            plant_command: Some(plant_command),
        }
    }
}

fn crypto_reason(e: &CryptoError) -> R {
    match e.reason_code() {
        "DENY_WRONG_ROLE" => R::DenyWrongRole,
        "DENY_KEY_REVOKED" => R::DenyKeyRevoked,
        "DENY_MALFORMED" => R::DenyMalformed,
        "DENY_NONCANONICAL" => R::DenyNonCanonical,
        _ => R::DenySignatureInvalid,
    }
}

fn replay_reason(cls: haldir_state::ReplayClass) -> R {
    match cls {
        haldir_state::ReplayClass::RetiredEpoch => R::DenyRetiredEpoch,
        _ => R::DenyIntentReplay,
    }
}
