//! The per-vehicle decision actor and the 13-stage intent pipeline.
//!
//! All mutable authorization state for one vehicle is owned here. A single
//! `authorization_revision` is captured at the start of a decision and re-checked
//! immediately before output-sequence allocation (spec B1). Every DENY produces
//! no output and (from the replay-commit point on) consumes the intent sequence.

use haldir_admission::{AdmissionClaim, AdmissionSnapshot};
use haldir_contracts::cbor::Limits;
use haldir_contracts::digest::{DigestDomain, DigestV1};
use haldir_contracts::ids::KeyId;
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
    CryptoError, ExpectedContext, KeyRole, RevocationSnapshot, SigningKey, TrustStore,
    sign_message, verify_and_decode,
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
    /// The decision receipt (the value form; canonically re-encodable).
    pub receipt: DecisionReceiptV1,
    /// The exact COSE_Sign1 bytes of the receipt, signed by the Gate application
    /// key (H-B02). Verify these, not the in-memory struct.
    pub signed_receipt: Vec<u8>,
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
    /// The Gate application signing key (signs decision receipts, H-B02).
    pub gate_signer: SigningKey,
    /// The Gate application signing key id.
    pub gate_signer_kid: KeyId,
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
    gate_signer: SigningKey,
    gate_signer_kid: KeyId,
    lease_usage: Option<LeaseUsage>,
}

/// Per-lease usage enforcement: total-intent counter and a fixed-point token
/// bucket (H-B07 / runbook Phase 3F). Tokens are micro-intents; the bucket
/// replenishes from monotonic time only (never on a regression).
struct LeaseUsage {
    accepted_intents: u64,
    max_total: u64,
    rate_millihz: u32,
    tokens_micro: u64,
    capacity_micro: u64,
    last_refill: MonoInstant,
}

const TOKEN_SCALE: u64 = 1_000_000;

impl LeaseUsage {
    fn new(max_total: u64, rate_millihz: u32, now: MonoInstant) -> Self {
        // Burst capacity = one second of authorized intents (>= 1 intent).
        let per_second = u64::from(rate_millihz) / 1000;
        let capacity_micro = per_second.max(1).saturating_mul(TOKEN_SCALE);
        Self {
            accepted_intents: 0,
            max_total,
            rate_millihz,
            tokens_micro: capacity_micro,
            capacity_micro,
            last_refill: now,
        }
    }

    /// Consume one intent's quota (total + rate). Called once a correctly-signed,
    /// correctly-scoped intent is accepted for evaluation.
    fn try_consume(&mut self, now: MonoInstant) -> Result<(), R> {
        if self.accepted_intents >= self.max_total {
            return Err(R::DenyTotalIntents);
        }
        // Replenish from elapsed monotonic time (no replenishment on regression).
        if let Some(d) = now.checked_duration_since(self.last_refill) {
            // micro-intents added = rate_millihz * elapsed_ns / 1_000_000
            let refill = u128::from(self.rate_millihz) * u128::from(d.as_nanos()) / 1_000_000;
            let refill = u64::try_from(refill).unwrap_or(u64::MAX);
            self.tokens_micro = self
                .tokens_micro
                .saturating_add(refill)
                .min(self.capacity_micro);
            self.last_refill = now;
        }
        if self.tokens_micro < TOKEN_SCALE {
            return Err(R::DenyRateLimit);
        }
        self.tokens_micro -= TOKEN_SCALE;
        self.accepted_intents = self.accepted_intents.saturating_add(1);
        Ok(())
    }
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
        let mut fault = haldir_state::FaultLatch::new();
        // These startup transitions must succeed; an impossible transition is an
        // invariant violation, so latch fail-closed rather than ignore it (H-H07).
        for to in [
            GateProcessStateV1::Recovering,
            GateProcessStateV1::ReadyNoSession,
            GateProcessStateV1::SessionBound,
        ] {
            if process.transition(to).is_err() {
                fault.latch("STARTUP_TRANSITION");
            }
        }
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
            fault,
            revision: RevisionCounter::new(),
            process,
            next_decision: 0,
            local_cap_ms: cfg.local_cap_ms,
            last_seen_mono: None,
            gate_signer: cfg.gate_signer,
            gate_signer_kid: cfg.gate_signer_kid,
            lease_usage: None,
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
        self.lease_usage = None;
        // A tombstone-full replay retirement is an invariant/resource failure (H-H07).
        if self.replay.retire_active().is_err() {
            self.fault.latch("REPLAY_TOMBSTONE_FULL");
        }
        self.revision.bump();
        if self
            .process
            .transition(GateProcessStateV1::SessionBound)
            .is_err()
        {
            self.fault.latch("REVOKE_TRANSITION");
        }
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

    /// Validate and set the current trusted-state snapshot (H-B05). Rejects a
    /// snapshot that is not for this vehicle/session, whose causal source is not in
    /// this session, or that is flagged invalid — a blind setter would let whichever
    /// task can call it author the causal truth Gate relies on. Full signed
    /// state-producer contracts are a later profile (see `docs/LIMITATIONS.md`).
    ///
    /// # Errors
    /// Returns a stable reason code on any ingress-validation failure.
    pub fn set_trusted_state(&mut self, state: TrustedStateSnapshotV1) -> Result<(), R> {
        if state.vehicle_id != self.vehicle_id {
            return Err(R::DenyStateProducer);
        }
        if state.session != self.session || state.primary_source.session != self.session {
            return Err(R::DenyStateStale);
        }
        if !state.primary_source.valid {
            return Err(R::DenyStateStale);
        }
        self.trusted_state = Some(state);
        Ok(())
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
        let (lease, kid, sub): (MissionLeaseV1, _, _) =
            verify_and_decode(env, &ctx, &self.trust, &self.revocations, Limits::LARGE)
                .map_err(|e: CryptoError| GateError::Crypto(e.reason_code()))?;

        // Bind the mission-authority signer identity to the lease issuer fields
        // (H-H01): the verified KID must be the lease's issuer key, and the verified
        // subject must be the lease issuer id.
        if kid != lease.issuer_key_id {
            return Err(GateError::Crypto("DENY_WRONG_ROLE"));
        }
        if sub.as_deref() != Some(lease.issuer_id.as_str()) {
            return Err(GateError::Crypto("DENY_WRONG_ROLE"));
        }

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
        let usage = LeaseUsage::new(snap.max_total_intents, snap.max_intent_rate_millihz, now);
        self.lease = Some(snap);
        self.lease_usage = Some(usage);
        self.replay = ControllerReplayState::new(MAX_RETIRED);
        self.revision.bump();
        if self.process.transition(GateProcessStateV1::Active).is_err() {
            self.fault.latch("ACTIVATE_TRANSITION");
            return Err(GateError::Faulted);
        }
        Ok(())
    }

    fn make_decision_id(&mut self) -> DecisionId {
        // Checked counter (H-H06): exhaustion latches a fault (caught at Stage 0).
        // The 128-bit id is a boot-unique prefix concatenated with the counter.
        match self.next_decision.checked_add(1) {
            Some(n) => self.next_decision = n,
            None => self.fault.latch("DECISION_ID_EXHAUSTED"),
        }
        let mut b = [0u8; 16];
        let (lo, hi) = b.split_at_mut(8);
        lo.copy_from_slice(self.gate_boot_id.as_bytes().get(..8).unwrap_or(&[0u8; 8]));
        hi.copy_from_slice(&self.next_decision.to_be_bytes());
        DecisionId::new(b)
    }

    fn sign_receipt(&self, receipt: &DecisionReceiptV1) -> Vec<u8> {
        sign_message(
            receipt,
            DecisionReceiptV1::KIND,
            1,
            &self.gate_signer_kid,
            &self.gate_signer,
        )
    }

    /// Build and sign a no-output response. Internal faults produce ERROR; policy /
    /// authorization refusals produce DENY (H-H10). Both prohibit output.
    fn respond(&self, draft: &ReceiptDraft, reason: R, now: MonoInstant) -> DecisionRecord {
        let is_err = reason.is_error();
        let mut receipt = draft.base();
        receipt.decision = if is_err {
            DecisionOutcomeV1::Error
        } else {
            DecisionOutcomeV1::Deny
        };
        receipt.reason_codes = BoundedVec::from_vec(vec![reason]).unwrap_or_default();
        receipt.decided_mono_ns = now.as_nanos();
        receipt.publish_stage = if is_err {
            PublishStageV1::DecidedError
        } else {
            PublishStageV1::DecidedDeny
        };
        let signed = self.sign_receipt(&receipt);
        DecisionRecord {
            receipt,
            signed_receipt: signed,
            outcome: if is_err {
                DecisionOutcomeV1::Error
            } else {
                DecisionOutcomeV1::Deny
            },
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
            return self.respond(&draft, R::ErrorInternalFault, now);
        }
        if !self.mono_ok(now) {
            return self.respond(&draft, R::ErrorInternalFault, now);
        }
        if !self.process.is_active() {
            return self.respond(&draft, R::DenyLeaseAbsent, now);
        }
        if env.len() > INTENT_SIZE_LIMIT {
            return self.respond(&draft, R::DenyOversize, now);
        }

        // Stage 1-2 — structural decode + cryptographic verification
        let ctx = ExpectedContext {
            kind: HaldirIntentV1::KIND,
            schema_major: 1,
            required_role: KeyRole::ControllerIntent,
            assurance_profile: true,
        };
        let (intent, signer_kid, signer_subject): (HaldirIntentV1, _, _) =
            match verify_and_decode(env, &ctx, &self.trust, &self.revocations, Limits::DEFAULT) {
                Ok(v) => v,
                Err(e) => return self.respond(&draft, crypto_reason(&e), now),
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
            return self.respond(&draft, R::DenyLeaseAbsent, now);
        };

        // Stage 3 — identity / routing binding
        if actual_key != intent.actual_intent_key.as_str()
            || actual_key != lease.controller_intent_key
        {
            return self.respond(&draft, R::DenyWrongActualKey, now);
        }
        if signer_kid != lease.controller_intent_signing_key_id {
            return self.respond(&draft, R::DenyWrongRole, now);
        }

        // Stage 5 — scope checks
        if intent.gate_id != self.gate_id || intent.gate_boot_id != self.gate_boot_id {
            return self.respond(&draft, R::DenyGateBootMismatch, now);
        }
        if intent.realm != self.realm || intent.vehicle_id != self.vehicle_id {
            return self.respond(&draft, R::DenyScopeMismatch, now);
        }
        if intent.ncp_session != self.session {
            return self.respond(&draft, R::DenySessionStale, now);
        }
        if intent.mission_id != lease.mission_id
            || intent.mission_lease_id != lease.lease_id
            || intent.mission_lease_term.get() != lease.lease_term
        {
            return self.respond(&draft, R::DenyScopeMismatch, now);
        }
        if intent.admission_id != lease.controller.admission_id
            || intent.admission_digest != lease.controller.admission_digest
            || intent.controller_bundle_digest != lease.controller.bundle_digest
            || intent.backend_profile_digest != lease.controller.backend_profile_digest
        {
            return self.respond(&draft, R::DenyAdmissionMismatch, now);
        }
        // Bind the intent's self-declared controller identity to the admitted
        // controller, the verified signer key, and the signer's registered
        // trust-store subject (H-H02 / punch-list BUG-4): the key that produced
        // this signature must itself be enrolled to this controller, not merely
        // hold the ControllerIntent role. A key with no bound subject fails
        // closed (`None != Some(..)`). These are equality-checked consistency
        // claims, not trusted evidence content.
        if intent.controller_id != lease.controller.controller_id
            || intent.controller_signing_key_id != signer_kid
            || signer_subject.as_deref() != Some(intent.controller_id.as_str())
        {
            return self.respond(&draft, R::DenyScopeMismatch, now);
        }
        if lease.remaining_ms(now) == 0 {
            return self.respond(&draft, R::DenyLeaseExpired, now);
        }

        // Stage 6 — controller replay (two-phase): classify (no consume) then commit
        let cls = self.replay.classify(
            intent.intent_position.epoch,
            intent.intent_position.seq.get(),
        );
        if !cls.is_fresh() {
            return self.respond(&draft, replay_reason(cls), now);
        }
        let _ = self.replay.commit_consume(
            intent.intent_position.epoch,
            intent.intent_position.seq.get(),
        );

        // Stage 6b — lease usage: total-intent ceiling + fixed-point rate bucket
        // (H-B07). Charged only for fresh, correctly-scoped intents that have
        // just consumed their replay position; a rate/total refusal is a DENY
        // that still spends the sequence (no output, no retry of this position).
        let usage_result = match self.lease_usage.as_mut() {
            Some(usage) => usage.try_consume(now),
            None => Err(R::ErrorInternalFault),
        };
        if let Err(reason) = usage_result {
            return self.respond(&draft, reason, now);
        }

        // Stage 7 — source / state correlation
        let Some(state) = self.trusted_state.clone() else {
            return self.respond(&draft, R::DenyStateUnavailable, now);
        };
        if state.session != self.session {
            return self.respond(&draft, R::DenyStateStale, now);
        }
        if intent.primary_source != state.primary_source.source {
            return self.respond(&draft, R::DenySourceUnknown, now);
        }
        draft.state_snapshot_digest = Some(state.canonical_digest());
        // Mission-phase intersection (H-P04): the lease authorizes exactly one
        // mission phase; the Gate-owned trusted state names the phase the vehicle
        // is actually in. A lease issued for a different phase confers no
        // authority here, regardless of the per-action policy phase rules.
        if state.mission_phase != lease.mission_phase {
            return self.respond(&draft, R::DenyScopeMismatch, now);
        }

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
                return self.respond(&draft, reason, now);
            }
        };

        // Stage 12 — output allocation, after a TOCTOU re-check (B1)
        if self.revision.get() != captured_rev {
            return self.respond(&draft, R::ErrorInternalFault, now);
        }
        if !self.publication.authorizes_publication() {
            return self.respond(&draft, R::DenyNoPublicationAuthority, now);
        }
        let out_seq = match self.output_stream.allocate() {
            Ok(s) => s,
            Err(_) => return self.respond(&draft, R::DenyOverload, now),
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
                return self.respond(&draft, R::ErrorInternalFault, now);
            }
        };
        if self
            .adapter
            .validate_exact_command(&frame, &build_input)
            .is_err()
        {
            self.fault.latch("NCP_VALIDATE_FAILED");
            self.revision.bump();
            return self.respond(&draft, R::ErrorInternalFault, now);
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
        // AllowPrepared, not AllowPublished: the Gate authorized and prepared the
        // exact output frame, but publication to NCP happens downstream — the
        // Gate does not claim delivery it did not observe (H-H10 honesty).
        receipt.reason_codes = BoundedVec::from_vec(vec![R::AllowPrepared]).unwrap_or_default();
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

        let signed = self.sign_receipt(&receipt);
        DecisionRecord {
            receipt,
            signed_receipt: signed,
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

#[cfg(test)]
mod lease_usage_tests {
    //! Fixed-point token-bucket + total-intent accounting (H-B07). The bucket is
    //! deterministic and depends only on monotonic time deltas.
    use super::{LeaseUsage, R};
    use haldir_core::time::MonoInstant;

    #[test]
    fn burst_capacity_then_rate_limits_at_same_instant() {
        // rate 2000 milli-Hz = 2 intents/s => burst capacity of exactly 2 tokens.
        let t0 = MonoInstant::from_nanos(1_000);
        let mut u = LeaseUsage::new(100, 2_000, t0);
        assert_eq!(u.try_consume(t0), Ok(()));
        assert_eq!(u.try_consume(t0), Ok(()));
        // Same instant, bucket empty (no time has elapsed to refill).
        assert_eq!(u.try_consume(t0), Err(R::DenyRateLimit));
    }

    #[test]
    fn refills_from_elapsed_monotonic_time() {
        let t0 = MonoInstant::from_nanos(1_000);
        let mut u = LeaseUsage::new(100, 2_000, t0);
        assert_eq!(u.try_consume(t0), Ok(()));
        assert_eq!(u.try_consume(t0), Ok(()));
        assert_eq!(u.try_consume(t0), Err(R::DenyRateLimit));
        // One second later: 2/s * 1 s = 2 tokens refilled (capped at capacity).
        let t1 = MonoInstant::from_nanos(1_000 + 1_000_000_000);
        assert_eq!(u.try_consume(t1), Ok(()));
        assert_eq!(u.try_consume(t1), Ok(()));
        assert_eq!(u.try_consume(t1), Err(R::DenyRateLimit));
    }

    #[test]
    fn total_intent_ceiling_is_checked_before_rate() {
        // Large rate so the bucket never limits; total cap of 2 dominates.
        let t0 = MonoInstant::from_nanos(0);
        let mut u = LeaseUsage::new(2, 1_000_000, t0);
        assert_eq!(u.try_consume(t0), Ok(()));
        assert_eq!(u.try_consume(t0), Ok(()));
        assert_eq!(u.try_consume(t0), Err(R::DenyTotalIntents));
    }

    #[test]
    fn no_refill_on_clock_regression() {
        // rate 1000 milli-Hz = 1 intent/s => capacity 1 token.
        let t0 = MonoInstant::from_nanos(1_000_000_000);
        let mut u = LeaseUsage::new(100, 1_000, t0);
        assert_eq!(u.try_consume(t0), Ok(())); // bucket now empty
        // A backward instant must not credit the bucket, and must not move the
        // refill anchor forward (fail-closed; the gate also latches a fault).
        let earlier = MonoInstant::from_nanos(0);
        assert_eq!(u.try_consume(earlier), Err(R::DenyRateLimit));
        // Real forward progress still refills relative to the original anchor.
        let later = MonoInstant::from_nanos(1_000_000_000 + 1_000_000_000);
        assert_eq!(u.try_consume(later), Ok(()));
    }
}
