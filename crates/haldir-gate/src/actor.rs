//! The per-vehicle decision actor and the 13-stage intent pipeline.
//!
//! All mutable authorization state for one vehicle is owned here. A single
//! `authorization_revision` is captured at the start of a decision and re-checked
//! immediately before output-sequence allocation (spec B1). Every DENY produces
//! no output and (from the replay-commit point on) consumes the intent sequence.

use haldir_admission::{AdmissionClaim, AdmissionSnapshot};
use haldir_contracts::cbor::{CanonicalMessage, Limits};
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
    CryptoError, ExpectedContext, KeyClass, KeyRole, RevocationSnapshot, SigningKey, TrustStore,
    sign_message, verify_and_decode,
};
use haldir_durable::{GenerationAnchor, SnapshotStorage};
use haldir_evidence::EvidenceSpool;
use haldir_ncp08::{
    AclOnlyAdapter, ExactNcpCommandFrame, GateCommandBuildInputV1, NcpCommandAdapter,
};
use haldir_policy_native::{BoundedActionHistory, NativePolicySnapshot, PolicyInput, decide};
use haldir_reference_plant::{PlantAction, PlantCommand};
use haldir_state::{
    AntiRollbackError, AntiRollbackStore, BootedDurableAntiRollbackStore, ChallengeTable,
    ControllerReplayState, GateOutputStreamState, GateProcessMachine, LeaseAcceptContext,
    LeaseAcceptError, LeaseTermStore, RevisionCounter, accept_lease,
};
use std::sync::Arc;

const MAX_RETIRED: usize = 16;
const INTENT_SIZE_LIMIT: usize = 16 * 1024;

fn checked_publication_horizon(
    called_at: MonoInstant,
    effective_validity_ms: u32,
) -> Result<MonoInstant, PublicationError> {
    called_at
        .checked_add_ms(u64::from(effective_validity_ms))
        .ok_or(PublicationError::ArithmeticOverflow)
}

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
    /// A prepared/called publication must be resolved before authority changes.
    PublicationPending,
}

/// A cross-field configuration validation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateConfigError {
    /// The local lease-duration cap is zero, so no lease can become useful.
    LocalCapZero,
    /// The configured Gate signing key id is absent from the trust store.
    GateSignerKidUnknown,
    /// The configured Gate signing key id is revoked.
    GateSignerKidRevoked,
    /// The trusted record is not authorized for Gate application signatures.
    GateSignerRoleMismatch,
    /// The trusted record is not provisioned for the assurance profile.
    GateSignerNotAssurance,
    /// The trusted record's subject is not the configured Gate id.
    GateSignerSubjectMismatch,
    /// The trusted public key does not belong to the configured private key.
    GateSignerPublicKeyMismatch,
    /// A future NCP authority lease names a different NCP session.
    PublicationSessionMismatch,
    /// A future NCP authority lease authorizes a different output epoch.
    PublicationOutputEpochMismatch,
}

/// A failure to construct a session-bound vehicle actor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateStartupError {
    /// Static configuration validation failed.
    Config(GateConfigError),
    /// The anti-rollback boot namespace could not advance.
    AntiRollback(AntiRollbackError),
    /// The booted durable store belongs to another Gate.
    StoreGateMismatch,
    /// The configured boot ID did not match the freshly committed boot context.
    BootContextMismatch,
    /// The explicit startup state-machine progression was rejected.
    ProcessTransition {
        /// State before the attempted transition.
        from: GateProcessStateV1,
        /// Requested startup state.
        to: GateProcessStateV1,
    },
}

impl From<GateConfigError> for GateStartupError {
    fn from(error: GateConfigError) -> Self {
        Self::Config(error)
    }
}

/// The actor's single-slot publication state.
///
/// A prepared output is not a publication capability until the actor transitions
/// it to [`PublicationState::PublishCalled`]. Keeping exactly one slot prevents
/// out-of-order publication of independently prepared output sequence numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicationState {
    /// No output is awaiting publication resolution.
    Idle,
    /// Exact output bytes were prepared but are not externally accessible.
    Prepared {
        /// Decision that owns the slot.
        decision_id: DecisionId,
    },
    /// The cooperative caller reported crossing the modeled side-effect boundary.
    PublishCalled {
        /// Decision that owns the slot.
        decision_id: DecisionId,
    },
}

/// A rejected publication-state transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicationError {
    /// The token does not own the actor's current publication slot.
    StateMismatch,
    /// Authority changed after the output was prepared.
    AuthorizationChanged,
    /// The trusted causal state changed after the output was prepared.
    CausalStateChanged,
    /// The bounded publication-call deadline elapsed before the side effect.
    DeadlineElapsed,
    /// A publication horizon could not be represented exactly.
    ArithmeticOverflow,
    /// Plant-publication authority is no longer present.
    PublicationAuthorityLost,
    /// The actor is fault-latched or detected a monotonic-clock regression.
    Faulted,
}

/// Opaque, non-cloneable proof that exact output was prepared.
///
/// This type intentionally exposes no frame or plant-command accessor. The only
/// route to those values is [`VehicleActor::mark_publish_called`], which consumes
/// this token and revalidates the actor-owned safety context when issuing the
/// first-access capability. The cooperative caller must invoke the side effect
/// immediately and must not copy/resubmit exposed bytes.
#[must_use = "dropping a prepared publication leaves the actor slot occupied"]
pub struct PreparedPublication {
    owner: Arc<()>,
    decision_id: DecisionId,
    captured_revision: u64,
    state_snapshot_digest: DigestV1,
    latest_call_at: MonoInstant,
    frame: ExactNcpCommandFrame,
    plant_command: PlantCommand,
    plant_action: PlantAction,
    effective_validity_ms: u32,
}

impl core::fmt::Debug for PreparedPublication {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("PreparedPublication")
            .field("decision_id", &self.decision_id)
            .field("latest_call_at", &self.latest_call_at)
            .finish_non_exhaustive()
    }
}

impl PreparedPublication {
    /// Decision that owns this prepared output.
    #[must_use]
    pub const fn decision_id(&self) -> DecisionId {
        self.decision_id
    }
}

/// Opaque, non-cloneable proof that the publication side effect may be invoked.
///
/// The exact frame is accessible only in this state. After the transport call,
/// the token must be consumed by `mark_publish_returned_ok` or
/// `mark_publish_returned_error`. The resolver token cannot be cloned, but the
/// cooperative caller/publisher remains trusted not to copy and resubmit exposed
/// bytes; closing that service boundary is a later slice.
#[derive(Debug)]
#[must_use = "a called publication must be resolved as returned-ok or error/timeout"]
pub struct PublishCalledPublication {
    owner: Arc<()>,
    decision_id: DecisionId,
    frame: ExactNcpCommandFrame,
    plant_command: PlantCommand,
    plant_action: PlantAction,
    called_at: MonoInstant,
    active_until: MonoInstant,
}

impl PublishCalledPublication {
    /// Decision that owns this called publication.
    #[must_use]
    pub const fn decision_id(&self) -> DecisionId {
        self.decision_id
    }

    /// Borrow the exact immutable frame after the side-effect boundary is crossed.
    #[must_use]
    pub const fn frame(&self) -> &ExactNcpCommandFrame {
        &self.frame
    }

    /// Borrow the deterministic reference-plant command for simulated receivers.
    #[must_use]
    pub const fn reference_plant_command(&self) -> &PlantCommand {
        &self.plant_command
    }
}

/// The result of processing one intent.
#[derive(Debug)]
#[must_use = "a decision may contain a prepared publication that must be resolved"]
pub struct DecisionRecord {
    /// The decision receipt (the value form; canonically re-encodable).
    pub receipt: DecisionReceiptV1,
    /// The exact COSE_Sign1 bytes of the receipt, signed by the Gate application
    /// key (H-B02). Verify these, not the in-memory struct.
    pub signed_receipt: Vec<u8>,
    /// The decision outcome.
    pub outcome: DecisionOutcomeV1,
    prepared_publication: Option<PreparedPublication>,
}

impl DecisionRecord {
    /// Whether the decision allowed and prepared an opaque publication token.
    #[must_use]
    pub fn has_prepared_publication(&self) -> bool {
        self.outcome == DecisionOutcomeV1::Allow && self.prepared_publication.is_some()
    }

    /// Consume the decision and take its opaque prepared-publication token.
    #[must_use]
    pub fn into_prepared_publication(mut self) -> Option<PreparedPublication> {
        self.prepared_publication.take()
    }
}

#[derive(Debug, Clone)]
struct TerminalDecisionRecord {
    receipt: DecisionReceiptV1,
    signed_receipt: Vec<u8>,
    outcome: DecisionOutcomeV1,
}

impl TerminalDecisionRecord {
    fn from_record(record: &DecisionRecord) -> Self {
        debug_assert!(!record.has_prepared_publication());
        Self {
            receipt: record.receipt.clone(),
            signed_receipt: record.signed_receipt.clone(),
            outcome: record.outcome,
        }
    }

    fn to_record(&self) -> DecisionRecord {
        DecisionRecord {
            receipt: self.receipt.clone(),
            signed_receipt: self.signed_receipt.clone(),
            outcome: self.outcome,
            prepared_publication: None,
        }
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

impl GateConfig {
    /// Validate static invariants that span provisioned configuration fields.
    ///
    /// # Errors
    /// Returns [`GateConfigError`] when the local lease cap is unusable, the
    /// Gate receipt signer is not bound to its trusted identity and key, or a
    /// future NCP publication lease is scoped to another session or output epoch.
    pub fn validate(&self) -> Result<(), GateConfigError> {
        validate_static_config(
            &self.gate_id,
            &self.trust,
            &self.revocations,
            self.local_cap_ms,
            &self.gate_signer,
            &self.gate_signer_kid,
        )?;

        if let PlantPublicationAuthorityStateV1::NcpLeaseV1(lease) = &self.publication {
            if lease.session != self.session {
                return Err(GateConfigError::PublicationSessionMismatch);
            }
            if lease.authorized_output_epoch != self.output_epoch {
                return Err(GateConfigError::PublicationOutputEpochMismatch);
            }
        }

        Ok(())
    }
}

pub(crate) fn validate_static_config(
    gate_id: &GateId,
    trust: &TrustStore,
    revocations: &RevocationSnapshot,
    local_cap_ms: u32,
    gate_signer: &SigningKey,
    gate_signer_kid: &KeyId,
) -> Result<(), GateConfigError> {
    if local_cap_ms == 0 {
        return Err(GateConfigError::LocalCapZero);
    }

    let signer_record = trust
        .resolve(gate_signer_kid)
        .ok_or(GateConfigError::GateSignerKidUnknown)?;
    if revocations.is_key_revoked(gate_signer_kid) {
        return Err(GateConfigError::GateSignerKidRevoked);
    }
    if signer_record.role != KeyRole::GateApplication {
        return Err(GateConfigError::GateSignerRoleMismatch);
    }
    if signer_record.class != KeyClass::Assurance {
        return Err(GateConfigError::GateSignerNotAssurance);
    }
    if signer_record.subject.as_deref() != Some(gate_id.as_str()) {
        return Err(GateConfigError::GateSignerSubjectMismatch);
    }
    if signer_record.verifying_key.to_bytes() != gate_signer.verifying_key().to_bytes() {
        return Err(GateConfigError::GateSignerPublicKeyMismatch);
    }

    Ok(())
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
    anti_rollback: Box<dyn LeaseTermStore>,
    lease: Option<ActiveMissionLeaseSnapshot>,
    replay: ControllerReplayState,
    history: BoundedActionHistory,
    trusted_state: Option<TrustedStateSnapshotV1>,
    fault: haldir_state::FaultLatch,
    revision: RevisionCounter,
    process: GateProcessMachine,
    next_decision: u64,
    terminal_decision: Option<TerminalDecisionRecord>,
    publication_state: PublicationState,
    publication_owner: Arc<()>,
    local_cap_ms: u32,
    last_seen_mono: Option<MonoInstant>,
    gate_signer: GateApplicationSigner,
    lease_usage: Option<LeaseUsage>,
    evidence: EvidenceSpool,
}

/// Single owner of the Gate application private key after configuration has
/// been validated. Future journal coordination can use short-lived borrows of
/// this capability without creating a second private-key owner.
struct GateApplicationSigner {
    kid: KeyId,
    key: SigningKey,
}

impl GateApplicationSigner {
    fn sign_receipt(&self, receipt: &DecisionReceiptV1) -> Vec<u8> {
        sign_message(
            receipt,
            DecisionReceiptV1::KIND,
            DecisionReceiptV1::SCHEMA_MAJOR,
            &self.kid,
            &self.key,
        )
    }
}

/// Bound on retained decision-receipt evidence records (in-process P0 spool).
const MAX_EVIDENCE_RECORDS: usize = 4096;
/// Bound on retained evidence bytes.
const MAX_EVIDENCE_BYTES: usize = 8 * 1024 * 1024;

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
    /// Validate configuration and construct a session-bound actor.
    ///
    /// # Errors
    /// Returns [`GateStartupError`] if configuration validation, anti-rollback
    /// initialization, or an explicit startup state transition fails.
    pub fn new(cfg: GateConfig) -> Result<Self, GateStartupError> {
        cfg.validate()?;

        let mut anti_rollback = AntiRollbackStore::new_empty();
        anti_rollback
            .advance_boot()
            .map_err(GateStartupError::AntiRollback)?;
        Self::from_validated_config(cfg, Box::new(anti_rollback))
    }

    /// Construct an actor from a store whose new boot incarnation was already
    /// durably committed by startup orchestration.
    ///
    /// The configured Gate and boot ID must match the authenticated binding and
    /// fresh context carried by the non-cloneable store state returned by
    /// `begin_boot`. This method never creates or advances durable state itself.
    ///
    /// # Errors
    /// Returns [`GateStartupError`] if the store belongs to another Gate,
    /// configuration validation fails, the boot context differs, or a startup
    /// transition is rejected.
    pub fn new_recovered<S, A>(
        cfg: GateConfig,
        term_store: BootedDurableAntiRollbackStore<S, A>,
    ) -> Result<Self, GateStartupError>
    where
        S: SnapshotStorage + Send + 'static,
        A: GenerationAnchor + Send + 'static,
    {
        if !term_store.is_bound_to_gate(&cfg.gate_id) {
            return Err(GateStartupError::StoreGateMismatch);
        }
        cfg.validate()?;
        if cfg.gate_boot_id != term_store.boot_context().gate_boot_id {
            return Err(GateStartupError::BootContextMismatch);
        }

        Self::from_validated_config(cfg, Box::new(term_store))
    }

    fn from_validated_config(
        cfg: GateConfig,
        anti_rollback: Box<dyn LeaseTermStore>,
    ) -> Result<Self, GateStartupError> {
        let mut process = GateProcessMachine::new();
        let fault = haldir_state::FaultLatch::new();
        for to in [
            GateProcessStateV1::Recovering,
            GateProcessStateV1::ReadyNoSession,
            GateProcessStateV1::SessionBound,
        ] {
            let from = process.state();
            process
                .transition(to)
                .map_err(|_| GateStartupError::ProcessTransition { from, to })?;
        }
        Ok(Self {
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
            terminal_decision: None,
            publication_state: PublicationState::Idle,
            publication_owner: Arc::new(()),
            local_cap_ms: cfg.local_cap_ms,
            last_seen_mono: None,
            gate_signer: GateApplicationSigner {
                kid: cfg.gate_signer_kid,
                key: cfg.gate_signer,
            },
            lease_usage: None,
            evidence: EvidenceSpool::new(MAX_EVIDENCE_RECORDS, MAX_EVIDENCE_BYTES),
        })
    }

    /// The digest-chained decision-receipt evidence spool (read-only). The chain
    /// head commits every appended signed receipt in order; `verify_chain`
    /// detects a truncated tail or a mutated completed record. The spool is
    /// in-process and lossy on overflow — a durable, crash-surviving journal is
    /// out of P0 (see `CL-DURABLE-01`).
    #[must_use]
    pub fn evidence(&self) -> &EvidenceSpool {
        &self.evidence
    }

    /// Current single-slot publication state.
    #[must_use]
    pub const fn publication_state(&self) -> PublicationState {
        self.publication_state
    }

    /// Cancel an output that was prepared but whose bytes were never exposed.
    ///
    /// Cancellation consumes the non-cloneable token, returns the slot to idle,
    /// and does not update published-command history.
    ///
    /// # Errors
    /// Returns [`PublicationError::StateMismatch`] if the token does not own the
    /// current prepared slot.
    pub fn cancel_prepared_publication(
        &mut self,
        prepared: PreparedPublication,
    ) -> Result<(), PublicationError> {
        if !Arc::ptr_eq(&self.publication_owner, &prepared.owner)
            || self.publication_state
                != (PublicationState::Prepared {
                    decision_id: prepared.decision_id,
                })
        {
            return Err(PublicationError::StateMismatch);
        }
        self.publication_state = PublicationState::Idle;
        Ok(())
    }

    /// Report crossing the in-memory reference publication-call boundary.
    ///
    /// This consumes the only prepared token and rechecks monotonic time, process
    /// state, authorization revision, ACL publication authority, causal-state
    /// digest, publication deadline, lease horizon, and checked horizon arithmetic.
    /// Exact frame bytes become accessible only in the returned token. The caller is
    /// part of the P0 trusted computing base and must invoke once without an
    /// intervening actor mutation. This method is not durable publication evidence;
    /// crash-surviving stage journaling belongs to the later service slice.
    ///
    /// # Errors
    /// Returns a [`PublicationError`] without exposing the frame if the token is
    /// stale, the actor context changed, the safety-margin deadline elapsed, or
    /// the full active horizon cannot be represented exactly.
    pub fn mark_publish_called(
        &mut self,
        prepared: PreparedPublication,
        called_at: MonoInstant,
    ) -> Result<PublishCalledPublication, PublicationError> {
        let expected_state = PublicationState::Prepared {
            decision_id: prepared.decision_id,
        };
        if !Arc::ptr_eq(&self.publication_owner, &prepared.owner)
            || self.publication_state != expected_state
        {
            return Err(PublicationError::StateMismatch);
        }

        let reject = |actor: &mut Self, error| {
            actor.publication_state = PublicationState::Idle;
            Err(error)
        };

        if self.fault.is_latched() || !self.mono_ok(called_at) {
            return reject(self, PublicationError::Faulted);
        }
        if self.revision.get() != prepared.captured_revision {
            return reject(self, PublicationError::AuthorizationChanged);
        }
        if !self.process.is_active() {
            return reject(self, PublicationError::AuthorizationChanged);
        }
        if !self.publication.authorizes_acl_only_publication() {
            return reject(self, PublicationError::PublicationAuthorityLost);
        }
        let Some(state) = &self.trusted_state else {
            return reject(self, PublicationError::CausalStateChanged);
        };
        if state.canonical_digest() != prepared.state_snapshot_digest {
            return reject(self, PublicationError::CausalStateChanged);
        }
        if called_at > prepared.latest_call_at {
            return reject(self, PublicationError::DeadlineElapsed);
        }
        let Some(lease) = &self.lease else {
            return reject(self, PublicationError::AuthorizationChanged);
        };
        if lease.remaining_ms(called_at) < u64::from(prepared.effective_validity_ms) {
            return reject(self, PublicationError::DeadlineElapsed);
        }
        let active_until =
            match checked_publication_horizon(called_at, prepared.effective_validity_ms) {
                Ok(end) => end,
                Err(error) => return reject(self, error),
            };

        self.publication_state = PublicationState::PublishCalled {
            decision_id: prepared.decision_id,
        };
        Ok(PublishCalledPublication {
            owner: prepared.owner,
            decision_id: prepared.decision_id,
            frame: prepared.frame,
            plant_command: prepared.plant_command,
            plant_action: prepared.plant_action,
            called_at,
            active_until,
        })
    }

    /// Resolve a called reference publication as locally successful.
    ///
    /// Published-command slew/duty history is committed exactly once here, using
    /// the call instant rather than the later return instant. The consumed token
    /// and actor slot prevent duplicate accounting.
    ///
    /// # Errors
    /// Returns [`PublicationError::StateMismatch`] for a token that does not own
    /// the called slot, or [`PublicationError::Faulted`] if `returned_at` regresses
    /// the actor's monotonic clock. A reported success is still conservatively
    /// charged before a regression fault is latched.
    pub fn mark_publish_returned_ok(
        &mut self,
        called: PublishCalledPublication,
        returned_at: MonoInstant,
    ) -> Result<(), PublicationError> {
        if !Arc::ptr_eq(&self.publication_owner, &called.owner)
            || self.publication_state
                != (PublicationState::PublishCalled {
                    decision_id: called.decision_id,
                })
        {
            return Err(PublicationError::StateMismatch);
        }

        let window_start = MonoInstant::from_nanos(
            called
                .called_at
                .as_nanos()
                .saturating_sub(u64::from(self.policy.duty_window_ms).saturating_mul(1_000_000)),
        );
        match called.plant_action {
            PlantAction::Hold => self.history.record_hold(called.called_at),
            PlantAction::Velocity(velocity) => self.history.record_velocity(
                velocity,
                called.called_at,
                called.active_until,
                window_start,
            ),
        }
        self.publication_state = PublicationState::Idle;

        if !self.mono_ok(returned_at) {
            return Err(PublicationError::Faulted);
        }
        Ok(())
    }

    /// Resolve a called reference publication as error/timeout.
    ///
    /// Once exact bytes were exposed the outcome is ambiguous: the actor faults
    /// and deliberately retains `PublishCalled`, so it cannot issue replacement
    /// output in the same process. The cooperative publisher remains responsible
    /// for not resubmitting copied bytes.
    ///
    /// # Errors
    /// Returns [`PublicationError::StateMismatch`] if the token does not own the
    /// current called slot.
    pub fn mark_publish_returned_error(
        &mut self,
        called: PublishCalledPublication,
    ) -> Result<(), PublicationError> {
        if !Arc::ptr_eq(&self.publication_owner, &called.owner)
            || self.publication_state
                != (PublicationState::PublishCalled {
                    decision_id: called.decision_id,
                })
        {
            return Err(PublicationError::StateMismatch);
        }
        self.latch_fault("PUBLISH_RETURNED_ERROR_OR_TIMEOUT");
        Ok(())
    }

    /// Latch both representations of a terminal process fault and invalidate any
    /// in-flight authorization snapshot. Keeping this transition in one helper
    /// prevents the public process state from disagreeing with the enforcement
    /// latch.
    fn latch_fault(&mut self, reason: &'static str) {
        if !self.fault.is_latched() {
            let _ = self.revision.bump();
        }
        self.fault.latch(reason);
        self.process.latch_fault();
    }

    /// Detect a monotonic-clock regression (spec T5/B13, punch-list BUG-2). A
    /// backward `now` while ACTIVE latches a fault and errors rather than extending
    /// a live lease's deadline; on success the last-seen instant is advanced.
    fn mono_ok(&mut self, now: MonoInstant) -> bool {
        if let Some(last) = self.last_seen_mono
            && now < last
        {
            self.latch_fault("MONOTONIC_REGRESSION");
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
        // The revoked mission's last-published velocity must not seed the next
        // lease's slew reference (its authority has ended).
        self.history.clear_slew_reference();
        // A tombstone-full replay retirement is an invariant/resource failure (H-H07).
        if self.replay.retire_active().is_err() {
            self.latch_fault("REPLAY_TOMBSTONE_FULL");
        }
        if self.revision.bump().is_none() {
            self.latch_fault("AUTHORIZATION_REVISION_EXHAUSTED");
            return;
        }
        if self
            .process
            .transition(GateProcessStateV1::SessionBound)
            .is_err()
        {
            self.latch_fault("REVOKE_TRANSITION");
        }
    }

    /// The current process state.
    #[must_use]
    pub fn process_state(&self) -> GateProcessStateV1 {
        self.process.state()
    }

    /// Test-only: preset the decision-id counter so the exhaustion/latch path
    /// (H-H06) is reachable without issuing `u64::MAX` real decisions.
    #[cfg(test)]
    pub(crate) fn force_next_decision_for_test(&mut self, v: u64) {
        self.next_decision = v;
    }

    /// Register a pending challenge nonce (issued out of band by the orchestrator).
    pub fn register_challenge(
        &mut self,
        nonce: haldir_contracts::ids::ChallengeNonce,
        expires_at: MonoInstant,
        now: MonoInstant,
    ) -> bool {
        self.challenges.insert(nonce, expires_at, now)
    }

    /// Validate and set the current trusted-state snapshot (H-B05). Rejects a
    /// snapshot that is not for this vehicle/session, whose causal source is not in
    /// this session, that is flagged invalid, or whose capture time does not
    /// strictly advance the currently held snapshot — a blind setter would let
    /// whichever task can call it author the causal truth Gate relies on, and
    /// without the monotonicity check a producer could roll the vehicle back to an
    /// older-but-still-fresh favourable snapshot and flip a geofence/phase DENY to
    /// ALLOW. Full signed state-producer contracts are a later profile (see
    /// `docs/LIMITATIONS.md`).
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
        // Anti-rollback: capture time must strictly advance. Two different truths
        // cannot share one capture instant, and a non-advancing snapshot carries
        // no new causal information — reject it rather than regress.
        if let Some(prev) = &self.trusted_state
            && state.captured_mono <= prev.captured_mono
        {
            return Err(R::DenyStateStale);
        }
        self.trusted_state = Some(state);
        Ok(())
    }

    /// Accept a signed mission lease and become ACTIVE.
    ///
    /// # Errors
    /// Returns a [`GateError`] if a publication slot is unresolved or signature,
    /// admission, or acceptance fails.
    pub fn accept_lease_env(&mut self, env: &[u8], now: MonoInstant) -> Result<(), GateError> {
        if self.fault.is_latched() {
            return Err(GateError::Faulted);
        }
        if self.publication_state != PublicationState::Idle {
            return Err(GateError::PublicationPending);
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
            self.anti_rollback.as_mut(),
            now,
        );
        let snap = match snap {
            Ok(snapshot) => snapshot,
            Err(LeaseAcceptError::TermStoreUnavailable) => {
                self.latch_fault("LEASE_TERM_STORE_UNAVAILABLE");
                return Err(GateError::Faulted);
            }
            Err(error) => return Err(GateError::Lease(error.reason_code().code())),
        };
        let usage = LeaseUsage::new(snap.max_total_intents, snap.max_intent_rate_millihz, now);
        self.lease = Some(snap);
        self.lease_usage = Some(usage);
        self.replay = ControllerReplayState::new(MAX_RETIRED);
        // Do not inherit a prior mission's slew reference into this lease.
        self.history.clear_slew_reference();
        if self.revision.bump().is_none() {
            self.latch_fault("AUTHORIZATION_REVISION_EXHAUSTED");
            return Err(GateError::Faulted);
        }
        if self.process.transition(GateProcessStateV1::Active).is_err() {
            self.latch_fault("ACTIVATE_TRANSITION");
            return Err(GateError::Faulted);
        }
        Ok(())
    }

    fn make_decision_id(&mut self) -> DecisionId {
        // Checked counter (H-H06): exhaustion latches a fault (caught at Stage 0).
        // Counter zero is reserved for the terminal exhaustion decision.
        match self.next_decision.checked_add(1) {
            Some(n) => self.next_decision = n,
            None => {
                // Counter zero is reserved for the one terminal exhaustion
                // receipt. Subsequent calls return that exact cached decision,
                // rather than presenting repeated ids as distinct decisions.
                self.latch_fault("DECISION_ID_EXHAUSTED");
                self.next_decision = 0;
            }
        }
        derive_decision_id(&self.gate_boot_id, self.next_decision)
    }

    fn sign_receipt(&self, receipt: &DecisionReceiptV1) -> Vec<u8> {
        self.gate_signer.sign_receipt(receipt)
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
            prepared_publication: None,
        }
    }

    /// Process one intent and append its signed receipt to the digest-chained
    /// evidence spool. Journaling never changes the decision: an ALLOW is already
    /// committed to the returned frame, and a full spool drops only the export
    /// copy (a spool outage can never turn a DENY into an ALLOW).
    #[must_use = "a decision may contain a prepared publication that must be resolved"]
    pub fn decide_intent(
        &mut self,
        env: &[u8],
        actual_key: &str,
        now: MonoInstant,
    ) -> DecisionRecord {
        if let Some(record) = &self.terminal_decision {
            return record.to_record();
        }
        let record = self.decide_intent_inner(env, actual_key, now);
        let _ = self.evidence.append(&record.signed_receipt);
        if self.fault.reason() == Some("DECISION_ID_EXHAUSTED") {
            self.terminal_decision = Some(TerminalDecisionRecord::from_record(&record));
        }
        record
    }

    /// The full 13-stage intent decision pipeline.
    #[allow(clippy::too_many_lines)]
    fn decide_intent_inner(
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
        if !self.publication.authorizes_acl_only_publication() {
            return self.respond(&draft, R::DenyNoPublicationAuthority, now);
        }
        if self.publication_state != PublicationState::Idle {
            return self.respond(&draft, R::DenyOverload, now);
        }
        let Some(latest_call_at) =
            now.checked_add_ms(u64::from(self.policy.publication_safety_margin_ms))
        else {
            return self.respond(&draft, R::DenyArithmeticOverflow, now);
        };
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
            frame_id: state.primary_source.frame_id.clone(),
            source_t_ns: state.primary_source.publisher_t_ns,
            gate_t_ns: now.as_nanos(),
            action: intent.action,
            effective_validity_ms,
        };
        let frame = match self.adapter.build_command(&build_input) {
            Ok(f) => f,
            Err(_) => {
                self.latch_fault("NCP_BUILD_FAILED");
                return self.respond(&draft, R::ErrorInternalFault, now);
            }
        };
        if self
            .adapter
            .validate_exact_command(&frame, &build_input)
            .is_err()
        {
            self.latch_fault("NCP_VALIDATE_FAILED");
            return self.respond(&draft, R::ErrorInternalFault, now);
        }

        // Stage 13 — prepare an opaque publication token and emit ALLOW receipt.
        // Published-command history is intentionally untouched until the caller
        // reports a successful return from the modeled publication side effect.
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
            output_frame_digest: frame.digest(),
        };
        let mut receipt = draft.base();
        receipt.decision = DecisionOutcomeV1::Allow;
        // AllowPrepared, not AllowPublished: the Gate authorized and prepared the
        // exact output frame, but publication to NCP happens downstream — the
        // Gate does not claim delivery it did not observe (H-H10 honesty).
        receipt.reason_codes = BoundedVec::from_vec(vec![R::AllowPrepared]).unwrap_or_default();
        receipt.effective_validity_ms = Some(effective_validity_ms);
        receipt.gate_output_stream = Some(build_input.stream.clone());
        receipt.output_frame_digest = Some(frame.digest());
        receipt.transformation_relation = Some(if frame.is_hold() {
            TransformationRelationV1::Identity
        } else {
            TransformationRelationV1::FixedPointToNcpFloatV1
        });
        receipt.decided_mono_ns = now.as_nanos();
        // Gate signs only what it observed: it prepared the exact output bytes.
        receipt.publish_stage = PublishStageV1::OutputPrepared;

        let signed = self.sign_receipt(&receipt);
        self.publication_state = PublicationState::Prepared { decision_id };
        DecisionRecord {
            receipt,
            signed_receipt: signed,
            outcome: DecisionOutcomeV1::Allow,
            prepared_publication: Some(PreparedPublication {
                owner: Arc::clone(&self.publication_owner),
                decision_id,
                captured_revision: captured_rev,
                state_snapshot_digest: state.canonical_digest(),
                latest_call_at,
                frame,
                plant_command,
                plant_action,
                effective_validity_ms,
            }),
        }
    }
}

fn derive_decision_id(gate_boot_id: &GateBootId, counter: u64) -> DecisionId {
    // Commit the full 128-bit boot id rather than truncating it. The resulting
    // 128-bit identifier is a domain-separated digest of (boot id || counter),
    // so two adversarially chosen boot ids with the same first half do not share
    // a decision-id namespace.
    let mut input = [0u8; 24];
    let (boot, count) = input.split_at_mut(16);
    boot.copy_from_slice(gate_boot_id.as_bytes());
    count.copy_from_slice(&counter.to_be_bytes());
    let digest = DigestV1::compute(DigestDomain::DecisionId, &input);
    let (truncated, _) = digest.value.split_at(16);
    let mut id = [0u8; 16];
    id.copy_from_slice(truncated);
    DecisionId::new(id)
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
mod decision_id_tests {
    use super::derive_decision_id;
    use haldir_contracts::ids::GateBootId;

    #[test]
    fn full_boot_id_and_counter_define_the_namespace() {
        let mut second_boot = [1u8; 16];
        second_boot[15] = 2;
        let first = GateBootId::new([1u8; 16]);
        let second = GateBootId::new(second_boot);

        assert_ne!(
            derive_decision_id(&first, 1),
            derive_decision_id(&second, 1)
        );
        assert_ne!(derive_decision_id(&first, 0), derive_decision_id(&first, 1));
    }
}

#[cfg(test)]
mod publication_horizon_tests {
    use super::{PublicationError, checked_publication_horizon};
    use haldir_core::time::MonoInstant;

    #[test]
    fn horizon_overflow_fails_instead_of_collapsing_to_zero_duty() {
        let called_at = MonoInstant::from_nanos(u64::MAX - 500_000);
        assert_eq!(
            checked_publication_horizon(called_at, 1),
            Err(PublicationError::ArithmeticOverflow)
        );
    }

    #[test]
    fn representable_horizon_is_exact() {
        let called_at = MonoInstant::from_nanos(7);
        assert_eq!(
            checked_publication_horizon(called_at, 2),
            Ok(MonoInstant::from_nanos(2_000_007))
        );
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
