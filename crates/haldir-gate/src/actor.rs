//! The per-vehicle decision actor and the 13-stage intent pipeline.
//!
//! All mutable authorization state for one vehicle is owned here. A single
//! `authorization_revision` is captured at the start of a decision and re-checked
//! immediately before output-sequence allocation (spec B1). Every DENY produces
//! no output and (from the replay-commit point on) consumes the intent sequence.

use haldir_admission::{AdmissionClaim, AdmissionSnapshot};
use haldir_contracts::cbor::Limits;
use haldir_contracts::challenge::GateChallengeV1;
use haldir_contracts::digest::{DigestDomain, DigestV1};
use haldir_contracts::ids::KeyId;
use haldir_contracts::ids::{
    ChallengeNonce, ChallengeSeq, DecisionId, GateBootId, GateId, GateOutputEpoch, OutputSeq,
    VehicleId,
};
use haldir_contracts::intent::HaldirIntentV1;
use haldir_contracts::lease::MissionLeaseV1;
use haldir_contracts::limits::ContractVersion;
use haldir_contracts::publication::PublicationStageEventV1;
use haldir_contracts::receipt::{
    DecisionOutcomeV1, DecisionReasonCodeV1 as R, DecisionReceiptV1, PublishStageV1,
};
use haldir_contracts::scalar::{AsciiId, BoundedSet, BoundedVec};
use haldir_contracts::session::{
    HaldirIntentPositionV1, NcpSessionIdentityV1, NcpSourceRefV1, NcpStreamPositionV1,
};
use haldir_contracts::status::{GateProcessStateV1, PlantPublicationAuthorityStateV1};
use haldir_core::snapshot::ActiveMissionLeaseSnapshot;
use haldir_core::snapshot::{AdmittedControllerSnapshot, TrustedStateSnapshotV1};
use haldir_core::time::{MonoDuration, MonoInstant};
use haldir_crypto::{
    CryptoError, ExpectedContext, KeyClass, KeyRole, RevocationSnapshot, SigningKey, TrustStore,
    sign_typed_message, verify_and_decode,
};
use haldir_durable::{GenerationAnchor, SnapshotStorage};
use haldir_evidence::{EvidenceSpool, gate_journal::GateJournalVerifier, manager::JournalSigner};
use haldir_ncp08::{
    ExactNcpCommandFrame, GateCommandBuildInputV1, NcpCommandAdapter, NcpCommandWireProfile,
    PlantAction, PlantCommand, SelectedNcpCommandAdapter,
};
use haldir_ncp08::{NCP_JSON_SAFE_INTEGER_MAX, NCP_V0_8_0};
use haldir_policy_native::{
    ActionHistoryError, BoundedActionHistory, MAX_RETAINED_ACTIVE_INTERVALS, NativePolicyError,
    NativePolicySnapshot, PolicyInput, ValidatedNativePolicy, try_decide_validated,
};
use haldir_state::{
    AntiRollbackError, AntiRollbackStore, BootedDurableAntiRollbackStore, ChallengeTable,
    ControllerReplayState, DeploymentBootedDurableAntiRollbackStore, GateOutputStreamState,
    GateProcessMachine, LeaseAcceptContext, LeaseAcceptError, LeaseTermStore, OutputStreamError,
    RevisionCounter, SourceReplayClass, SourceStreamReplayState, accept_lease,
};
use std::num::{NonZeroU32, NonZeroU64, NonZeroUsize};
use std::sync::Arc;

const MAX_RETIRED: usize = 16;
const MAX_STATE_SOURCE_STREAMS: usize = 64;
const MAX_PENDING_CHALLENGES: usize = 4;
const MAX_RETAINED_CHALLENGES: usize = 256;
/// Fixed local monotonic lifetime of a Gate-issued challenge.
pub const GATE_CHALLENGE_TTL_MS: u32 = 30_000;
/// Maximum exact candidate intent-envelope bytes accepted by the actor boundary.
pub const MAX_INTENT_ENVELOPE_BYTES: usize = Limits::DEFAULT.max_total_bytes;
/// Maximum observed intent-route bytes accepted by the actor boundary.
pub const MAX_INTENT_ROUTE_BYTES: usize = 256;

/// A borrowed intent candidate whose hashing and verification work is bounded.
///
/// Construction proves only byte-length bounds. It does not authenticate
/// transport provenance, route ownership, envelope structure, or signature;
/// [`VehicleActor::decide_bounded_intent`] performs the authorization pipeline.
/// Private fields prevent a downstream caller from bypassing the O(1) ingress
/// checks before the actor hashes the exact route and envelope into its receipt.
#[must_use = "pass the bounded candidate to VehicleActor::decide_bounded_intent"]
pub struct BoundedIntentCandidate<'candidate> {
    envelope: &'candidate [u8],
    actual_key: &'candidate str,
}

/// Failure to construct a bounded actor input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum IntentCandidateError {
    /// The raw candidate envelope exceeds the fixed intent profile bound.
    EnvelopeTooLarge {
        /// Inclusive maximum accepted length.
        maximum_bytes: usize,
        /// Supplied exact length.
        actual_bytes: usize,
    },
    /// The observed route exceeds the fixed Haldir route bound.
    ActualKeyTooLong {
        /// Inclusive maximum accepted length.
        maximum_bytes: usize,
        /// Supplied exact length.
        actual_bytes: usize,
    },
}

impl IntentCandidateError {
    /// Stable machine-readable failure class.
    #[must_use]
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::EnvelopeTooLarge { .. } => "GATE_INTENT_CANDIDATE_ENVELOPE_TOO_LARGE",
            Self::ActualKeyTooLong { .. } => "GATE_INTENT_CANDIDATE_ACTUAL_KEY_TOO_LONG",
        }
    }
}

impl std::fmt::Display for IntentCandidateError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for IntentCandidateError {}

impl<'candidate> BoundedIntentCandidate<'candidate> {
    /// Check the two O(1) byte-length bounds before any actor mutation or hashing.
    ///
    /// # Errors
    /// Returns [`IntentCandidateError`] when either input exceeds its fixed
    /// profile maximum. Envelope length takes precedence when both are invalid.
    pub const fn new(
        envelope: &'candidate [u8],
        actual_key: &'candidate str,
    ) -> Result<Self, IntentCandidateError> {
        if envelope.len() > MAX_INTENT_ENVELOPE_BYTES {
            return Err(IntentCandidateError::EnvelopeTooLarge {
                maximum_bytes: MAX_INTENT_ENVELOPE_BYTES,
                actual_bytes: envelope.len(),
            });
        }
        if actual_key.len() > MAX_INTENT_ROUTE_BYTES {
            return Err(IntentCandidateError::ActualKeyTooLong {
                maximum_bytes: MAX_INTENT_ROUTE_BYTES,
                actual_bytes: actual_key.len(),
            });
        }
        Ok(Self {
            envelope,
            actual_key,
        })
    }

    /// Exact bounded envelope bytes.
    #[must_use]
    pub const fn envelope(&self) -> &'candidate [u8] {
        self.envelope
    }

    /// Exact bounded observed route.
    #[must_use]
    pub const fn actual_key(&self) -> &'candidate str {
        self.actual_key
    }
}

#[cfg(test)]
mod bounded_intent_candidate_tests {
    use super::{
        BoundedIntentCandidate, IntentCandidateError, MAX_INTENT_ENVELOPE_BYTES,
        MAX_INTENT_ROUTE_BYTES,
    };

    #[test]
    fn exact_actor_input_bounds_are_admitted_and_one_byte_over_is_rejected() {
        let exact_envelope = vec![0_u8; MAX_INTENT_ENVELOPE_BYTES];
        let exact_key = "k".repeat(MAX_INTENT_ROUTE_BYTES);
        let candidate = BoundedIntentCandidate::new(&exact_envelope, &exact_key).unwrap();
        assert_eq!(candidate.envelope().len(), MAX_INTENT_ENVELOPE_BYTES);
        assert_eq!(candidate.actual_key().len(), MAX_INTENT_ROUTE_BYTES);

        let oversized_envelope = vec![0_u8; MAX_INTENT_ENVELOPE_BYTES + 1];
        assert!(matches!(
            BoundedIntentCandidate::new(&oversized_envelope, &exact_key),
            Err(IntentCandidateError::EnvelopeTooLarge {
                maximum_bytes: MAX_INTENT_ENVELOPE_BYTES,
                actual_bytes,
            }) if actual_bytes == MAX_INTENT_ENVELOPE_BYTES + 1
        ));

        let oversized_key = "k".repeat(MAX_INTENT_ROUTE_BYTES + 1);
        assert!(matches!(
            BoundedIntentCandidate::new(&exact_envelope, &oversized_key),
            Err(IntentCandidateError::ActualKeyTooLong {
                maximum_bytes: MAX_INTENT_ROUTE_BYTES,
                actual_bytes,
            }) if actual_bytes == MAX_INTENT_ROUTE_BYTES + 1
        ));
    }

    #[test]
    fn envelope_limit_has_stable_precedence_and_errors_are_non_leaking() {
        let oversized_envelope = vec![0_u8; MAX_INTENT_ENVELOPE_BYTES + 1];
        let oversized_key = "k".repeat(MAX_INTENT_ROUTE_BYTES + 1);
        let error = BoundedIntentCandidate::new(&oversized_envelope, &oversized_key)
            .err()
            .unwrap();
        assert!(matches!(
            error,
            IntentCandidateError::EnvelopeTooLarge { .. }
        ));
        assert_eq!(
            error.reason_code(),
            "GATE_INTENT_CANDIDATE_ENVELOPE_TOO_LARGE"
        );
        assert_eq!(error.to_string(), error.reason_code());
    }
}

fn checked_publication_horizon(
    called_at: MonoInstant,
    effective_validity_ms: u32,
) -> Result<MonoInstant, PublicationError> {
    called_at
        .checked_add_ms(u64::from(effective_validity_ms))
        .ok_or(PublicationError::ArithmeticOverflow)
}

fn source_replay_reason(class: SourceReplayClass) -> R {
    match class {
        SourceReplayClass::ReplayStale | SourceReplayClass::RetiredEpoch => R::DenySourceStale,
        SourceReplayClass::CapacityExhausted => R::ErrorNamespaceExhausted,
        SourceReplayClass::FreshSource
        | SourceReplayClass::FreshContinue
        | SourceReplayClass::FreshEpoch => R::ErrorInternalFault,
    }
}

/// A gate-level error for authority-establishment operations.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
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
    /// Lease acceptance is only valid from the session-bound state.
    NotSessionBound,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LeaseEnvelopeValidationError<E> {
    Gate(GateError),
    ValidatorRejected(E),
}

impl<E> From<GateError> for LeaseEnvelopeValidationError<E> {
    fn from(error: GateError) -> Self {
        Self::Gate(error)
    }
}

/// A cross-field configuration validation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum GateConfigError {
    /// The local lease-duration cap cannot cover policy margin plus minimum validity.
    LocalCapTooShort,
    /// The executable native policy snapshot is semantically invalid.
    InvalidPolicy(NativePolicyError),
    /// The policy's bounded duty-history state cannot be constructed exactly.
    ActionHistory(ActionHistoryError),
    /// The supplied policy identity is not the canonical executable policy digest.
    PolicyDigestMismatch,
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
    /// The configured publication-authority profile is not executable by this Gate.
    UnsupportedPublicationAuthorityProfile,
}

impl GateConfigError {
    /// Stable machine-readable failure class.
    #[must_use]
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::LocalCapTooShort => "GATE_CONFIG_LOCAL_CAP_TOO_SHORT",
            Self::InvalidPolicy(_) => "GATE_CONFIG_INVALID_POLICY",
            Self::ActionHistory(_) => "GATE_CONFIG_ACTION_HISTORY",
            Self::PolicyDigestMismatch => "GATE_CONFIG_POLICY_DIGEST_MISMATCH",
            Self::GateSignerKidUnknown => "GATE_CONFIG_SIGNER_KID_UNKNOWN",
            Self::GateSignerKidRevoked => "GATE_CONFIG_SIGNER_KID_REVOKED",
            Self::GateSignerRoleMismatch => "GATE_CONFIG_SIGNER_ROLE_MISMATCH",
            Self::GateSignerNotAssurance => "GATE_CONFIG_SIGNER_NOT_ASSURANCE",
            Self::GateSignerSubjectMismatch => "GATE_CONFIG_SIGNER_SUBJECT_MISMATCH",
            Self::GateSignerPublicKeyMismatch => "GATE_CONFIG_SIGNER_PUBLIC_KEY_MISMATCH",
            Self::UnsupportedPublicationAuthorityProfile => {
                "GATE_CONFIG_UNSUPPORTED_PUBLICATION_AUTHORITY_PROFILE"
            }
        }
    }
}

impl std::fmt::Display for GateConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for GateConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidPolicy(error) => Some(error),
            Self::ActionHistory(error) => Some(error),
            _ => None,
        }
    }
}

/// A failure to construct a session-bound vehicle actor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
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

impl GateStartupError {
    /// Stable machine-readable failure class.
    #[must_use]
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::Config(_) => "GATE_STARTUP_CONFIG",
            Self::AntiRollback(_) => "GATE_STARTUP_ANTI_ROLLBACK",
            Self::StoreGateMismatch => "GATE_STARTUP_STORE_GATE_MISMATCH",
            Self::BootContextMismatch => "GATE_STARTUP_BOOT_CONTEXT_MISMATCH",
            Self::ProcessTransition { .. } => "GATE_STARTUP_PROCESS_TRANSITION",
        }
    }
}

impl std::fmt::Display for GateStartupError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for GateStartupError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Config(error) => Some(error),
            Self::AntiRollback(error) => Some(error),
            _ => None,
        }
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
    /// The actor entered its pre-side-effect Called write-ahead boundary.
    PublishCalled {
        /// Decision that owns the slot.
        decision_id: DecisionId,
    },
}

/// A rejected publication-state transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
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
    /// The publisher returned success, but exact history commit failed.
    ///
    /// The command may already be active at the plant. It must never be retried
    /// or resubmitted; the actor remains fault-latched with its called slot held.
    PublishedHistoryCommitFailed(ActionHistoryError),
    /// Plant-publication authority is no longer present.
    PublicationAuthorityLost,
    /// The actor is fault-latched or detected a monotonic-clock regression.
    Faulted,
}

impl PublicationError {
    /// Stable machine-readable failure class.
    #[must_use]
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::StateMismatch => "PUBLICATION_STATE_MISMATCH",
            Self::AuthorizationChanged => "PUBLICATION_AUTHORIZATION_CHANGED",
            Self::CausalStateChanged => "PUBLICATION_CAUSAL_STATE_CHANGED",
            Self::DeadlineElapsed => "PUBLICATION_DEADLINE_ELAPSED",
            Self::ArithmeticOverflow => "PUBLICATION_ARITHMETIC_OVERFLOW",
            Self::PublishedHistoryCommitFailed(_) => "PUBLICATION_PUBLISHED_HISTORY_COMMIT_FAILED",
            Self::PublicationAuthorityLost => "PUBLICATION_AUTHORITY_LOST",
            Self::Faulted => "PUBLICATION_FAULTED",
        }
    }
}

impl std::fmt::Display for PublicationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for PublicationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::PublishedHistoryCommitFailed(error) => Some(error),
            _ => None,
        }
    }
}

/// Opaque, non-cloneable proof that exact output was prepared.
///
/// This type intentionally exposes no frame or plant-command accessor. The only
/// public route to those values is [`VehicleActor::mark_publish_called`], which
/// consumes this token and revalidates the actor-owned safety context when issuing
/// the first-access capability. The private lifecycle coordinator instead uses the
/// split validation/commit seam. The cooperative caller must invoke the side effect
/// immediately and must not copy/resubmit exposed bytes.
#[must_use = "dropping a prepared publication leaves the actor slot occupied"]
pub struct PreparedPublication {
    owner: Arc<()>,
    decision_id: DecisionId,
    captured_revision: u64,
    state_snapshot_digest: DigestV1,
    latest_call_at: MonoInstant,
    plant_command: PlantCommand,
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

    /// Whether one receipt binds the complete opaque publication payload.
    ///
    /// The coordinator performs this check before deriving any later publication
    /// event. Keeping it on the opaque token lets that boundary verify the signed
    /// evidence against the exact frame without exposing the frame itself.
    pub(crate) fn receipt_binding_matches(&self, receipt: &DecisionReceiptV1) -> bool {
        let exact_frame = self.plant_command.exact_frame();
        let stream_matches = receipt.gate_output_stream.as_ref().is_some_and(|stream| {
            stream.epoch == self.plant_command.output_epoch()
                && stream.seq == self.plant_command.output_seq()
        });

        exact_frame.is_self_consistent()
            && receipt.decision_id == self.decision_id
            && &receipt.ncp_session == self.plant_command.session()
            && receipt.source.as_ref() == Some(self.plant_command.source())
            && receipt.state_snapshot_digest == Some(self.state_snapshot_digest)
            && receipt.effective_validity_ms == Some(self.effective_validity_ms)
            && self.effective_validity_ms == self.plant_command.validity_ms()
            && stream_matches
            && receipt.output_frame_digest == Some(self.plant_command.output_frame_digest())
            && receipt.transformation_relation == Some(exact_frame.transformation())
    }
}

/// Opaque, non-cloneable proof that a prepared publication passed the initial
/// call-boundary checks without exposing its frame.
///
/// The journal coordinator owns this token while it locally appends and
/// `sync_data`-confirms the `PublishCalled` write-ahead event. Only the
/// crate-private commit step can consume it and reveal the existing public
/// called-publication capability.
#[derive(Debug)]
#[must_use = "a validated publication call must be committed or retained"]
pub(crate) struct ValidatedPublicationCall {
    prepared: PreparedPublication,
}

impl ValidatedPublicationCall {
    pub(crate) const fn decision_id(&self) -> DecisionId {
        self.prepared.decision_id
    }
}

/// Opaque, non-cloneable proof that the actor entered its pre-side-effect Called state.
///
/// The exact frame is accessible only in this state. A synchronous reference
/// receiver may consume the token through `mark_publish_returned_ok`; a live
/// transport whose local call merely returned `Ok` must instead use the internal
/// unobserved-application transition and stop. The resolver token cannot be
/// cloned, but the cooperative caller/publisher remains trusted not to copy and
/// resubmit exposed bytes; closing that service boundary is a later slice.
#[derive(Debug)]
#[must_use = "a called publication must be resolved by its profile-specific terminal transition"]
pub struct PublishCalledPublication {
    owner: Arc<()>,
    decision_id: DecisionId,
    plant_command: PlantCommand,
    called_at: MonoInstant,
    active_until: MonoInstant,
}

impl PublishCalledPublication {
    /// Decision that owns this called publication.
    #[must_use]
    pub const fn decision_id(&self) -> DecisionId {
        self.decision_id
    }

    /// Borrow the exact immutable frame after the actor's Called boundary is crossed.
    #[must_use]
    pub const fn frame(&self) -> &ExactNcpCommandFrame {
        self.plant_command.exact_frame()
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

    /// Move the opaque prepared token out while retaining the journal receipt.
    pub(crate) fn take_prepared_publication(&mut self) -> Option<PreparedPublication> {
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
    /// Expected canonical digest of the executable native policy snapshot.
    pub policy_snapshot_digest: DigestV1,
    /// Current NCP session.
    pub session: NcpSessionIdentityV1,
    /// Closed selection of modeled or exact pinned NCP command construction.
    /// This core accepts either profile; selection alone makes no live-service claim.
    pub ncp_adapter: SelectedNcpCommandAdapter,
    /// Plant-publication authority state.
    pub publication: PlantPublicationAuthorityStateV1,
    /// Gate output epoch.
    pub output_epoch: GateOutputEpoch,
    /// Local cap on lease active duration (ms).
    pub local_cap_ms: NonZeroU32,
    /// The Gate application signing key (signs decision receipts, H-B02).
    pub gate_signer: SigningKey,
    /// The Gate application signing key id.
    pub gate_signer_kid: KeyId,
}

impl GateConfig {
    /// Validate static invariants that span provisioned configuration fields.
    ///
    /// # Errors
    /// Returns [`GateConfigError`] when the local lease cap or native policy is
    /// unusable, the policy digest does not identify the executable parameters,
    /// the Gate receipt signer is not bound to its trusted identity and key, or
    /// the publication-authority profile is not implemented by this Gate.
    pub fn validate(&self) -> Result<(), GateConfigError> {
        validate_static_config(
            PolicyBindingValidation {
                policy: &self.policy,
                expected_digest: &self.policy_snapshot_digest,
                local_cap_ms: self.local_cap_ms,
            },
            GateSignerValidation {
                gate_id: &self.gate_id,
                trust: &self.trust,
                revocations: &self.revocations,
                signing_key: &self.gate_signer,
                signing_kid: &self.gate_signer_kid,
            },
        )?;

        if matches!(
            self.publication,
            PlantPublicationAuthorityStateV1::NcpLeaseV1(_)
        ) {
            return Err(GateConfigError::UnsupportedPublicationAuthorityProfile);
        }

        Ok(())
    }
}

pub(crate) struct PolicyBindingValidation<'a> {
    pub(crate) policy: &'a NativePolicySnapshot,
    pub(crate) expected_digest: &'a DigestV1,
    pub(crate) local_cap_ms: NonZeroU32,
}

pub(crate) struct GateSignerValidation<'a> {
    pub(crate) gate_id: &'a GateId,
    pub(crate) trust: &'a TrustStore,
    pub(crate) revocations: &'a RevocationSnapshot,
    pub(crate) signing_key: &'a SigningKey,
    pub(crate) signing_kid: &'a KeyId,
}

pub(crate) fn validate_static_config(
    policy_binding: PolicyBindingValidation<'_>,
    signer: GateSignerValidation<'_>,
) -> Result<(), GateConfigError> {
    let required_local_cap = policy_binding
        .policy
        .publication_safety_margin_ms
        .checked_add(policy_binding.policy.min_useful_validity_ms)
        .ok_or(GateConfigError::LocalCapTooShort)?;
    if policy_binding.local_cap_ms.get() < required_local_cap {
        return Err(GateConfigError::LocalCapTooShort);
    }
    policy_binding
        .policy
        .validate_for_evaluation()
        .map_err(GateConfigError::InvalidPolicy)?;
    let computed_policy_digest = policy_binding
        .policy
        .canonical_digest()
        .map_err(GateConfigError::InvalidPolicy)?;
    if &computed_policy_digest != policy_binding.expected_digest {
        return Err(GateConfigError::PolicyDigestMismatch);
    }

    let signer_record = signer
        .trust
        .resolve(signer.signing_kid)
        .ok_or(GateConfigError::GateSignerKidUnknown)?;
    if signer.revocations.is_key_revoked(signer.signing_kid) {
        return Err(GateConfigError::GateSignerKidRevoked);
    }
    if signer_record.role != KeyRole::GateApplication {
        return Err(GateConfigError::GateSignerRoleMismatch);
    }
    if signer_record.class != KeyClass::Assurance {
        return Err(GateConfigError::GateSignerNotAssurance);
    }
    if signer_record.subject.as_str() != signer.gate_id.as_str() {
        return Err(GateConfigError::GateSignerSubjectMismatch);
    }
    if signer_record.verifying_key.to_bytes() != signer.signing_key.verifying_key().to_bytes() {
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
    adapter: SelectedNcpCommandAdapter,
    trust: TrustStore,
    revocations: RevocationSnapshot,
    admission: AdmissionSnapshot,
    policy: ValidatedNativePolicy,
    session: NcpSessionIdentityV1,
    publication: PlantPublicationAuthorityStateV1,
    output_epoch: GateOutputEpoch,
    output_stream: GateOutputStreamState,
    challenges: ChallengeTable,
    next_challenge_seq: Option<NonZeroU64>,
    anti_rollback: Box<dyn LeaseTermStore>,
    lease: Option<ActiveMissionLeaseSnapshot>,
    replay: ControllerReplayState,
    history: BoundedActionHistory,
    source_replay: SourceStreamReplayState,
    trusted_state: Option<TrustedStateSnapshotV1>,
    fault: haldir_state::FaultLatch,
    revision: RevisionCounter,
    process: GateProcessMachine,
    next_decision: u64,
    decision_namespace_exhausted: bool,
    terminal_decision: Option<TerminalDecisionRecord>,
    publication_state: PublicationState,
    publication_owner: Arc<()>,
    local_cap_ms: NonZeroU32,
    last_seen_mono: Option<MonoInstant>,
    gate_signer: GateApplicationSigner,
    lease_usage: Option<LeaseUsage>,
    evidence: EvidenceSpool,
    #[cfg(test)]
    force_replay_commit_conflict: bool,
    #[cfg(test)]
    force_source_replay_commit_conflict: bool,
    #[cfg(test)]
    force_authorization_revision_change_before_recheck: bool,
    #[cfg(test)]
    force_output_stream_exhaustion: bool,
}

/// Single owner of the Gate application private key after configuration has
/// been validated. Internal journal coordination uses short-lived borrows of
/// this capability without creating a second private-key owner.
struct GateApplicationSigner {
    kid: KeyId,
    key: SigningKey,
}

impl GateApplicationSigner {
    fn sign_receipt(&self, receipt: &DecisionReceiptV1) -> Vec<u8> {
        sign_typed_message(receipt, &self.kid, &self.key)
    }

    fn sign_publication_stage(&self, event: &PublicationStageEventV1) -> Vec<u8> {
        sign_typed_message(event, &self.kid, &self.key)
    }

    fn sign_challenge(&self, challenge: &GateChallengeV1) -> Vec<u8> {
        sign_typed_message(challenge, &self.kid, &self.key)
    }

    const fn journal_signer(&self) -> JournalSigner<'_> {
        JournalSigner::new(&self.kid, &self.key)
    }
}

/// One Gate-authored challenge payload and its exact COSE signature envelope.
///
/// The local monotonic expiry remains in the issuing actor's bounded challenge
/// table and is intentionally absent from the externally signed contract.
#[must_use = "deliver the signed challenge to the lease authority before it expires"]
pub struct SignedGateChallenge {
    challenge: GateChallengeV1,
    signed_envelope: Vec<u8>,
}

impl SignedGateChallenge {
    /// Exact canonical challenge payload signed by Gate.
    #[must_use]
    pub const fn challenge(&self) -> &GateChallengeV1 {
        &self.challenge
    }

    /// Exact COSE envelope for independent Gate-signature verification.
    #[must_use]
    pub fn signed_envelope(&self) -> &[u8] {
        &self.signed_envelope
    }

    #[cfg(feature = "live-zenoh")]
    pub(crate) fn into_parts(self) -> (GateChallengeV1, Vec<u8>) {
        (self.challenge, self.signed_envelope)
    }
}

/// Failure to issue and locally register a signed Gate challenge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum GateChallengeIssueError {
    /// The per-actor nonzero challenge sequence is exhausted.
    SequenceExhausted,
    /// The fixed local challenge lifetime overflowed monotonic time.
    DeadlineOverflow,
    /// The operating-system CSPRNG failed to fill a fresh nonce.
    EntropyUnavailable,
    /// The fixed supported-contract set could not be constructed.
    ContractConstruction,
    /// Actor fault, time, duplicate, or bounded-table checks rejected registration.
    RegistrationRejected,
}

impl GateChallengeIssueError {
    /// Stable machine-readable failure class.
    #[must_use]
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::SequenceExhausted => "GATE_CHALLENGE_SEQUENCE_EXHAUSTED",
            Self::DeadlineOverflow => "GATE_CHALLENGE_DEADLINE_OVERFLOW",
            Self::EntropyUnavailable => "GATE_CHALLENGE_ENTROPY_UNAVAILABLE",
            Self::ContractConstruction => "GATE_CHALLENGE_CONTRACT_CONSTRUCTION",
            Self::RegistrationRejected => "GATE_CHALLENGE_REGISTRATION_REJECTED",
        }
    }
}

impl std::fmt::Display for GateChallengeIssueError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for GateChallengeIssueError {}

/// Bound on retained decision-receipt evidence records (in-process P0 spool).
const MAX_EVIDENCE_RECORDS: usize = 4096;
/// Bound on retained evidence bytes.
const MAX_EVIDENCE_BYTES: usize = 8 * 1024 * 1024;

/// Per-lease usage enforcement: total-intent counter and a fixed-point token
/// bucket (H-B07 / runbook Phase 3F). Tokens are micro-intents; the bucket
/// replenishes from monotonic time only (never on a regression).
struct LeaseUsage {
    charged_intents: u64,
    max_total: u64,
    rate_millihz: u32,
    tokens_micro: u64,
    capacity_micro: u64,
    refill_remainder: u64,
    last_refill: MonoInstant,
}

const TOKEN_SCALE: u64 = 1_000_000;
const REFILL_DENOMINATOR: u128 = 1_000_000;

impl LeaseUsage {
    fn new(max_total: u64, rate_millihz: u32, now: MonoInstant) -> Self {
        // Burst capacity = one second of authorized intents (>= 1 intent).
        let per_second = u64::from(rate_millihz) / 1000;
        // `rate_millihz` is u32, so this product is below 2^64.
        let capacity_micro = per_second.max(1) * TOKEN_SCALE;
        Self {
            charged_intents: 0,
            max_total,
            rate_millihz,
            tokens_micro: capacity_micro,
            capacity_micro,
            refill_remainder: 0,
            last_refill: now,
        }
    }

    /// Consume one intent's quota (total + rate). Called once a correctly-signed,
    /// correctly-scoped intent is accepted for evaluation.
    fn try_consume(&mut self, now: MonoInstant) -> Result<(), R> {
        if self.charged_intents >= self.max_total {
            return Err(R::DenyTotalIntents);
        }
        let next_charged = self
            .charged_intents
            .checked_add(1)
            .ok_or(R::DenyTotalIntents)?;
        // Replenish from elapsed monotonic time (no replenishment on regression).
        if let Some(d) = now.checked_duration_since(self.last_refill) {
            // micro-intents added = rate_millihz * elapsed_ns / 1_000_000.
            // Carry the exact fixed-point remainder across denied calls; moving
            // `last_refill` while discarding it would let a high-frequency caller
            // prevent the bucket from ever replenishing.
            let scaled = u128::from(self.rate_millihz) * u128::from(d.as_nanos())
                + u128::from(self.refill_remainder);
            let refill = scaled / REFILL_DENOMINATOR;
            let available = self.capacity_micro - self.tokens_micro;
            if refill >= u128::from(available) {
                self.tokens_micro = self.capacity_micro;
                // Time accrued beyond a full bucket does not create hidden burst
                // credit after the next consumption.
                self.refill_remainder = 0;
            } else {
                // This conversion is exact because `refill < available <= u64::MAX`.
                let refill = u64::try_from(refill).map_err(|_| R::DenyRateLimit)?;
                let refill_remainder =
                    u64::try_from(scaled % REFILL_DENOMINATOR).map_err(|_| R::DenyRateLimit)?;
                let tokens_micro = self
                    .tokens_micro
                    .checked_add(refill)
                    .ok_or(R::DenyRateLimit)?;
                self.tokens_micro = tokens_micro;
                self.refill_remainder = refill_remainder;
            }
            self.last_refill = now;
        }
        // Every fresh, authenticated, correctly scoped position that reaches
        // this stage consumes one unit of the lease's finite total—even when
        // the rate bucket refuses it. Otherwise an authorized flood could spend
        // unbounded replay positions and verification work while never reaching
        // `max_total_intents`.
        self.charged_intents = next_charged;
        if self.tokens_micro < TOKEN_SCALE {
            return Err(R::DenyRateLimit);
        }
        self.tokens_micro -= TOKEN_SCALE;
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
    /// Process one length-bounded candidate intent.
    ///
    /// The candidate type ensures the actor never hashes or verifies an
    /// attacker-sized route or envelope. An ingress that cannot construct the
    /// candidate must drop/reject it outside the decision pipeline; because the
    /// exact bytes were not admitted, no `DecisionReceiptV1` is minted for that
    /// ingress rejection.
    #[must_use = "a decision may contain a prepared publication that must be resolved"]
    pub fn decide_bounded_intent(
        &mut self,
        candidate: BoundedIntentCandidate<'_>,
        now: MonoInstant,
    ) -> DecisionRecord {
        self.decide_intent(candidate.envelope, candidate.actual_key, now)
    }

    /// Selected command-wire construction profile for this runtime.
    #[must_use]
    pub const fn ncp_command_wire_profile(&self) -> NcpCommandWireProfile {
        self.adapter.wire_profile()
    }

    /// Validate configuration and construct a session-bound actor with an
    /// **ephemeral, process-local** anti-rollback store.
    ///
    /// This constructor is suitable for tests and development-only embeddings.
    /// It cannot preserve the lease-term high-water mark across a crash or
    /// restart. A deployment that requires crash-surviving anti-rollback must
    /// durably begin a boot and call [`Self::new_recovered`] instead.
    ///
    /// # Errors
    /// Returns [`GateStartupError`] if configuration validation, anti-rollback
    /// initialization, or an explicit startup state transition fails.
    pub fn new_ephemeral(cfg: GateConfig) -> Result<Self, GateStartupError> {
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

    /// Construct an actor from a store whose deployment package and fresh boot
    /// were committed atomically by startup orchestration.
    ///
    /// The configured Gate and boot ID must match the authenticated store and
    /// the non-cloneable context returned by `begin_deployment_boot`. Package
    /// signature, artifact, and runtime-profile validation remain the startup
    /// orchestrator's responsibility; this boundary preserves the already
    /// committed package ratchet while installing the store as the lease-term
    /// authority.
    ///
    /// # Errors
    /// Returns [`GateStartupError`] if the store belongs to another Gate,
    /// configuration validation fails, the boot context differs, or a startup
    /// transition is rejected.
    pub fn new_deployment_recovered<S, A>(
        cfg: GateConfig,
        term_store: DeploymentBootedDurableAntiRollbackStore<S, A>,
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
        let policy =
            ValidatedNativePolicy::new(cfg.policy).map_err(GateConfigError::InvalidPolicy)?;
        if policy.canonical_digest() != cfg.policy_snapshot_digest {
            return Err(GateConfigError::PolicyDigestMismatch.into());
        }
        let duty_window =
            MonoDuration::checked_from_millis(u64::from(policy.snapshot().duty_window_ms)).ok_or(
                GateConfigError::ActionHistory(ActionHistoryError::ArithmeticOverflow),
            )?;
        let history = BoundedActionHistory::new(MAX_RETAINED_ACTIVE_INTERVALS, duty_window)
            .map_err(GateConfigError::ActionHistory)?;

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
        let challenges = ChallengeTable::for_session_with_limits(
            cfg.session.clone(),
            MAX_PENDING_CHALLENGES,
            MAX_RETAINED_CHALLENGES,
        );
        Ok(Self {
            gate_id: cfg.gate_id,
            gate_boot_id: cfg.gate_boot_id,
            realm: cfg.realm,
            vehicle_id: cfg.vehicle_id,
            adapter: cfg.ncp_adapter,
            trust: cfg.trust,
            revocations: cfg.revocations,
            admission: cfg.admission,
            policy,
            session: cfg.session,
            publication: cfg.publication,
            output_epoch: cfg.output_epoch,
            output_stream: GateOutputStreamState::new(cfg.output_epoch, MAX_RETIRED),
            challenges,
            next_challenge_seq: Some(NonZeroU64::MIN),
            anti_rollback,
            lease: None,
            replay: ControllerReplayState::new(MAX_RETIRED),
            history,
            source_replay: SourceStreamReplayState::new(MAX_STATE_SOURCE_STREAMS),
            trusted_state: None,
            fault,
            revision: RevisionCounter::new(),
            process,
            next_decision: 0,
            decision_namespace_exhausted: false,
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
            #[cfg(test)]
            force_replay_commit_conflict: false,
            #[cfg(test)]
            force_source_replay_commit_conflict: false,
            #[cfg(test)]
            force_authorization_revision_change_before_recheck: false,
            #[cfg(test)]
            force_output_stream_exhaustion: false,
        })
    }

    /// The digest-chained decision-receipt evidence spool (read-only). The chain
    /// head commits every appended signed receipt in order; `verify_chain`
    /// detects mutated retained records or mismatched local link metadata. Tail
    /// truncation requires an externally protected count/head checkpoint. The spool is
    /// in-process and lossy on overflow. The composed lifecycle coordinator can
    /// additionally make a selected durable journal part of its decision and
    /// publication ordering, but this direct actor accessor does not by itself
    /// provide crash durability (see `CL-DURABLE-01`).
    #[must_use]
    pub fn evidence(&self) -> &EvidenceSpool {
        &self.evidence
    }

    pub(crate) const fn gate_id(&self) -> &GateId {
        &self.gate_id
    }

    pub(crate) const fn gate_boot_id(&self) -> GateBootId {
        self.gate_boot_id
    }

    #[cfg(feature = "live-zenoh")]
    pub(crate) const fn realm(&self) -> &AsciiId<64> {
        &self.realm
    }

    #[cfg(feature = "live-zenoh")]
    pub(crate) const fn ncp_session(&self) -> &NcpSessionIdentityV1 {
        &self.session
    }

    pub(crate) const fn gate_signer_kid(&self) -> &KeyId {
        &self.gate_signer.kid
    }

    pub(crate) fn gate_signer_public_key(&self) -> [u8; 32] {
        self.gate_signer.key.verifying_key().to_bytes()
    }

    pub(crate) const fn journal_signer(&self) -> JournalSigner<'_> {
        self.gate_signer.journal_signer()
    }

    /// Current policy's rolling non-hold duty window. This does not recover the
    /// prior boot's policy or history.
    pub(crate) const fn duty_history_window_ms(&self) -> u32 {
        self.policy.snapshot().duty_window_ms
    }

    pub(crate) fn sign_publication_stage(&self, event: &PublicationStageEventV1) -> Vec<u8> {
        self.gate_signer.sign_publication_stage(event)
    }

    /// Exact cached terminal counter-exhaustion decision, if the actor can no
    /// longer mint decisions. Reading it performs no actor or evidence mutation.
    pub(crate) fn cached_terminal_decision(&self) -> Option<DecisionRecord> {
        self.terminal_decision
            .as_ref()
            .map(TerminalDecisionRecord::to_record)
    }

    pub(crate) fn journal_verifier(&self, max_envelope_bytes: NonZeroUsize) -> GateJournalVerifier {
        GateJournalVerifier::new(
            self.gate_id.clone(),
            self.vehicle_id.clone(),
            self.trust.clone(),
            self.revocations.clone(),
            max_envelope_bytes,
        )
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

    /// Enter the actor's in-memory Called write-ahead boundary before transport.
    ///
    /// This consumes the only prepared token and rechecks monotonic time, process
    /// state, authorization revision, ACL publication authority, causal-state
    /// digest, publication deadline, lease horizon, and checked horizon arithmetic.
    /// Exact frame bytes become accessible only in the returned token. The caller is
    /// part of the P0 trusted computing base and must invoke once without an
    /// intervening actor mutation. This public shortcut is not durable publication
    /// evidence; the crate-private startup coordinator uses the split validation/
    /// commit seam to order its local journal boundary before exposure.
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
        let validated = self.validate_publish_call(prepared, called_at)?;
        self.commit_publish_call(validated, called_at)
    }

    /// Validate a prepared call without exposing bytes or advancing its slot.
    pub(crate) fn validate_publish_call(
        &mut self,
        prepared: PreparedPublication,
        validation_at: MonoInstant,
    ) -> Result<ValidatedPublicationCall, PublicationError> {
        let expected_state = PublicationState::Prepared {
            decision_id: prepared.decision_id,
        };
        if !Arc::ptr_eq(&self.publication_owner, &prepared.owner)
            || self.publication_state != expected_state
        {
            return Err(PublicationError::StateMismatch);
        }

        if let Err(error) = self.recheck_publication_context(&prepared, validation_at) {
            self.publication_state = PublicationState::Idle;
            return Err(error);
        }

        Ok(ValidatedPublicationCall { prepared })
    }

    /// Commit a locally sync-confirmed write-ahead call boundary and reveal the frame.
    ///
    /// The state advances before the post-sync checks. If sync delay made the
    /// prepared authority stale, the recorded `PublishCalled` boundary remains
    /// represented conservatively and the actor fault-latches without exposing
    /// bytes.
    pub(crate) fn commit_publish_call(
        &mut self,
        validated: ValidatedPublicationCall,
        exposure_at: MonoInstant,
    ) -> Result<PublishCalledPublication, PublicationError> {
        let decision_id = validated.decision_id();
        let prepared = validated.prepared;
        let expected_state = PublicationState::Prepared { decision_id };
        if !Arc::ptr_eq(&self.publication_owner, &prepared.owner) {
            return Err(PublicationError::StateMismatch);
        }
        if self.publication_state != expected_state {
            self.publication_state = PublicationState::PublishCalled { decision_id };
            self.latch_fault("POST_SYNC_PUBLICATION_STATE_MISMATCH");
            return Err(PublicationError::StateMismatch);
        }

        self.publication_state = PublicationState::PublishCalled { decision_id };
        let active_until = match self.recheck_publication_context(&prepared, exposure_at) {
            Ok(active_until) => active_until,
            Err(error) => {
                self.latch_fault("POST_SYNC_PUBLICATION_REVALIDATION_FAILED");
                return Err(error);
            }
        };

        Ok(PublishCalledPublication {
            owner: prepared.owner,
            decision_id,
            plant_command: prepared.plant_command,
            called_at: exposure_at,
            active_until,
        })
    }

    fn recheck_publication_context(
        &mut self,
        prepared: &PreparedPublication,
        observed_at: MonoInstant,
    ) -> Result<MonoInstant, PublicationError> {
        if self.fault.is_latched() || !self.mono_ok(observed_at) {
            return Err(PublicationError::Faulted);
        }
        if self.expire_active_lease_if_needed(observed_at) {
            return if self.fault.is_latched() {
                Err(PublicationError::Faulted)
            } else {
                Err(PublicationError::DeadlineElapsed)
            };
        }
        if self.revision.get() != prepared.captured_revision {
            return Err(PublicationError::AuthorizationChanged);
        }
        if !self.process.is_active() {
            return Err(PublicationError::AuthorizationChanged);
        }
        if !self.publication.authorizes_acl_only_publication() {
            return Err(PublicationError::PublicationAuthorityLost);
        }
        let Some(state) = &self.trusted_state else {
            return Err(PublicationError::CausalStateChanged);
        };
        if state.canonical_digest() != prepared.state_snapshot_digest {
            return Err(PublicationError::CausalStateChanged);
        }
        if observed_at > prepared.latest_call_at {
            return Err(PublicationError::DeadlineElapsed);
        }
        let Some(lease) = &self.lease else {
            return Err(PublicationError::AuthorizationChanged);
        };
        if lease.remaining_ms(observed_at) < u64::from(prepared.effective_validity_ms) {
            return Err(PublicationError::DeadlineElapsed);
        }
        checked_publication_horizon(observed_at, prepared.effective_validity_ms)
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
    /// the actor's monotonic clock. Returns
    /// [`PublicationError::PublishedHistoryCommitFailed`] if a command that the
    /// publisher already reported successful cannot be committed to exact
    /// history; the actor fault-latches and retains the called slot, and callers
    /// must not retry or resubmit the command. A reported success is still
    /// conservatively charged before a return-time regression fault is latched.
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

        let expected_window =
            MonoDuration::checked_from_millis(u64::from(self.policy.snapshot().duty_window_ms))
                .ok_or(ActionHistoryError::ArithmeticOverflow);
        let history_result = expected_window.and_then(|expected_window| {
            self.history
                .validate_for_policy(called.called_at, expected_window)?;
            match called.plant_command.action() {
                PlantAction::Hold => self
                    .history
                    .record_hold(called.called_at, called.active_until),
                PlantAction::Velocity(velocity) => {
                    self.history
                        .record_velocity(velocity, called.called_at, called.active_until)
                }
            }
        });
        if let Err(error) = history_result {
            self.latch_fault(error.reason_code());
            return Err(PublicationError::PublishedHistoryCommitFailed(error));
        }
        self.publication_state = PublicationState::Idle;

        if !self.mono_ok(returned_at) {
            return Err(PublicationError::Faulted);
        }
        self.expire_active_lease_if_needed(returned_at);
        if self.fault.is_latched() {
            return Err(PublicationError::Faulted);
        }
        Ok(())
    }

    /// Record a live publisher's local `Ok` without pretending the plant arrival
    /// time or application interval is known.
    ///
    /// NCP v0.8 starts `ttl_ms` from the receiver's local arrival time. A local
    /// Zenoh return supplies neither that time nor a bounded in-transit lifetime,
    /// so charging `[called_at, called_at + ttl)` would end the possible plant
    /// interval too early. This transition therefore commits no action history,
    /// retains the called slot, and fault-latches the actor. The surrounding live
    /// service must be consumed and restart recovery must require authenticated
    /// external clearance.
    ///
    /// # Errors
    /// Returns [`PublicationError::StateMismatch`] if the token does not own the
    /// called slot, or [`PublicationError::Faulted`] if `returned_at` regresses the
    /// actor's monotonic clock. Either failure leaves the actor unusable.
    #[cfg(feature = "live-zenoh")]
    pub(crate) fn mark_live_publish_returned_ok_unobserved(
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
            self.latch_fault("LIVE_PUBLISH_RETURNED_OK_STATE_MISMATCH");
            return Err(PublicationError::StateMismatch);
        }
        if !self.mono_ok(returned_at) {
            return Err(PublicationError::Faulted);
        }
        self.latch_fault("LIVE_PUBLISH_APPLICATION_UNOBSERVED");
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

    /// Materialize the time-driven end of an active lease after the caller has
    /// accepted `now` through [`Self::mono_ok`]. The exact expiry instant ends
    /// authority; the final fractional millisecond before it does not.
    fn expire_active_lease_if_needed(&mut self, now: MonoInstant) -> bool {
        if !self.process.is_active()
            || !self
                .lease
                .as_ref()
                .is_some_and(|lease| lease.is_expired_at(now))
        {
            return false;
        }
        self.retire_active_lease("LEASE_EXPIRY_TRANSITION");
        true
    }

    fn retire_active_lease(&mut self, transition_fault: &'static str) {
        self.lease = None;
        self.lease_usage = None;
        // A completed mission must not seed the next lease's slew reference.
        self.history.clear_slew_reference();
        // A tombstone-full replay retirement is an invariant/resource failure (H-H07).
        if self.replay.retire_active().is_err() {
            self.latch_fault("REPLAY_TOMBSTONE_FULL");
            return;
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
            self.latch_fault(transition_fault);
        }
    }

    /// Revoke the active mission lease (an authorization invalidation): clears the
    /// lease, retires the controller replay epoch, and bumps the authorization
    /// revision. After this, decisions DENY with `DENY_LEASE_ABSENT` until a fresh
    /// lease is accepted. Repeating the call after authority is already absent is
    /// an idempotent no-op; it cannot turn a harmless duplicate control-plane
    /// notification into a process fault.
    pub fn revoke_active_lease(&mut self) {
        if self.fault.is_latched() || !self.process.is_active() {
            return;
        }
        if self.lease.is_none() {
            self.latch_fault("ACTIVE_LEASE_MISSING");
            return;
        }
        self.retire_active_lease("REVOKE_TRANSITION");
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

    #[cfg(test)]
    pub(crate) fn force_publication_state_for_test(&mut self, state: PublicationState) {
        self.publication_state = state;
    }

    #[cfg(test)]
    pub(crate) fn force_publication_authority_for_test(
        &mut self,
        publication: PlantPublicationAuthorityStateV1,
    ) {
        self.publication = publication;
    }

    #[cfg(test)]
    pub(crate) fn force_history_for_test(&mut self, history: BoundedActionHistory) {
        self.history = history;
    }

    #[cfg(test)]
    pub(crate) fn force_replay_commit_conflict_for_test(&mut self) {
        self.force_replay_commit_conflict = true;
    }

    #[cfg(test)]
    pub(crate) fn force_source_replay_commit_conflict_for_test(&mut self) {
        self.force_source_replay_commit_conflict = true;
    }

    #[cfg(test)]
    pub(crate) fn force_output_stream_exhaustion_for_test(&mut self) {
        self.force_output_stream_exhaustion = true;
    }

    fn allocate_output_sequence(&mut self) -> Result<OutputSeq, OutputStreamError> {
        #[cfg(test)]
        if core::mem::take(&mut self.force_output_stream_exhaustion) {
            return Err(OutputStreamError::Exhausted);
        }
        let next = self
            .output_stream
            .peek_next_seq()
            .ok_or(OutputStreamError::Exhausted)?;
        if !output_sequence_is_wire_representable(next) {
            return Err(OutputStreamError::Exhausted);
        }
        self.output_stream.allocate()
    }

    #[cfg(test)]
    pub(crate) fn force_missing_lease_usage_for_test(&mut self) {
        self.lease_usage = None;
    }

    #[cfg(test)]
    pub(crate) fn force_authorization_revision_change_before_recheck_for_test(&mut self) {
        self.force_authorization_revision_change_before_recheck = true;
    }

    #[cfg(test)]
    pub(crate) fn force_authorization_revision_exhaustion_for_test(&mut self) {
        self.revision = RevisionCounter::from_nonzero(std::num::NonZeroU64::MAX);
    }

    fn apply_authorization_revision_test_hook(&mut self) {
        #[cfg(test)]
        if core::mem::take(&mut self.force_authorization_revision_change_before_recheck) {
            let bumped = self.revision.bump();
            debug_assert!(bumped.is_some());
        }
    }

    fn commit_replay_position(
        &mut self,
        position: &HaldirIntentPositionV1,
    ) -> Result<(), haldir_state::ReplayClass> {
        #[cfg(test)]
        if core::mem::take(&mut self.force_replay_commit_conflict) {
            let seeded = self
                .replay
                .commit_consume(position.epoch, position.seq.get());
            debug_assert!(seeded.is_ok());
        }
        self.replay
            .commit_consume(position.epoch, position.seq.get())
    }

    fn commit_source_replay_position(
        &mut self,
        source: &NcpSourceRefV1,
    ) -> Result<(), SourceReplayClass> {
        #[cfg(test)]
        if core::mem::take(&mut self.force_source_replay_commit_conflict) {
            let seeded = self.source_replay.commit(source);
            debug_assert!(seeded.is_ok());
        }
        self.source_replay.commit(source)
    }

    #[cfg(test)]
    pub(crate) const fn history_for_test(&self) -> &BoundedActionHistory {
        &self.history
    }

    #[cfg(test)]
    pub(crate) fn intent_epoch_is_retired_for_test(
        &self,
        epoch: haldir_contracts::ids::IntentEpoch,
    ) -> bool {
        self.replay.is_retired(epoch)
    }

    #[cfg(test)]
    pub(crate) const fn fault_reason_for_test(&self) -> Option<&'static str> {
        self.fault.reason()
    }

    /// Issue a fresh OS-random, Gate-signed challenge under the fixed local TTL.
    ///
    /// This lower actor API supports reference embeddings without exposing raw
    /// nonce registration. The declared-live service uses startup-provisioned
    /// entropy so failure occurs before its durable boot boundary.
    ///
    /// ```compile_fail
    /// use haldir_contracts::ids::ChallengeNonce;
    /// use haldir_core::time::MonoInstant;
    /// use haldir_gate::VehicleActor;
    ///
    /// fn caller_cannot_register_a_nonce(actor: &mut VehicleActor, now: MonoInstant) {
    ///     actor.register_challenge(ChallengeNonce::new([7; 32]), now, now);
    /// }
    /// ```
    ///
    /// # Errors
    /// Returns when the challenge sequence or local deadline is exhausted, OS
    /// entropy is unavailable, contract construction fails, or actor state
    /// rejects registration.
    pub fn issue_challenge(
        &mut self,
        now: MonoInstant,
    ) -> Result<SignedGateChallenge, GateChallengeIssueError> {
        let expires_at = now
            .checked_add_ms(u64::from(GATE_CHALLENGE_TTL_MS))
            .ok_or(GateChallengeIssueError::DeadlineOverflow)?;
        let mut nonce = [0_u8; 32];
        getrandom::getrandom(&mut nonce)
            .map_err(|_| GateChallengeIssueError::EntropyUnavailable)?;
        self.issue_challenge_with_nonce(ChallengeNonce::new(nonce), expires_at, now)
    }

    /// Construct, sign, and register the sole initial declared-live challenge.
    #[cfg(feature = "live-zenoh")]
    pub(crate) fn issue_live_activation_challenge(
        &mut self,
        nonce: ChallengeNonce,
        expires_at: MonoInstant,
        now: MonoInstant,
    ) -> Result<SignedGateChallenge, GateChallengeIssueError> {
        self.issue_challenge_with_nonce(nonce, expires_at, now)
    }

    fn issue_challenge_with_nonce(
        &mut self,
        nonce: ChallengeNonce,
        expires_at: MonoInstant,
        now: MonoInstant,
    ) -> Result<SignedGateChallenge, GateChallengeIssueError> {
        let challenge_seq = self
            .next_challenge_seq
            .ok_or(GateChallengeIssueError::SequenceExhausted)?;
        let accepted_contract_versions =
            BoundedSet::from_iter_checked([ContractVersion { major: 1, minor: 0 }])
                .map_err(|_| GateChallengeIssueError::ContractConstruction)?;
        let challenge = GateChallengeV1 {
            schema_major: 1,
            schema_minor: 0,
            gate_id: self.gate_id.clone(),
            gate_boot_id: self.gate_boot_id,
            challenge_nonce: nonce,
            challenge_seq: ChallengeSeq::new(challenge_seq),
            realm: self.realm.clone(),
            vehicle_id: self.vehicle_id.clone(),
            ncp_session: self.session.clone(),
            gate_output_epoch: self.output_epoch,
            gate_key_id: self.gate_signer.kid.clone(),
            policy_snapshot_digest: self.policy.canonical_digest(),
            accepted_contract_versions,
            ncp_compatibility_id: NCP_V0_8_0.compatibility_id(),
        };
        let signed_envelope = self.gate_signer.sign_challenge(&challenge);
        if !self.register_challenge(nonce, expires_at, now) {
            return Err(GateChallengeIssueError::RegistrationRejected);
        }
        self.next_challenge_seq = challenge_seq.get().checked_add(1).and_then(NonZeroU64::new);
        Ok(SignedGateChallenge {
            challenge,
            signed_envelope,
        })
    }

    /// Register a pending challenge nonce issued by a trusted embedding.
    ///
    /// The declared-live service does not expose this lower-level path: it
    /// generates, signs, and registers its challenge through a private
    /// feature-gated issuer.
    pub(crate) fn register_challenge(
        &mut self,
        nonce: haldir_contracts::ids::ChallengeNonce,
        expires_at: MonoInstant,
        now: MonoInstant,
    ) -> bool {
        if self.fault.is_latched() || !self.mono_ok(now) {
            return false;
        }
        self.expire_active_lease_if_needed(now);
        if self.fault.is_latched() {
            return false;
        }
        self.challenges.insert(nonce, expires_at, now)
    }

    /// Validate and set the current trusted-state snapshot (H-B05). Rejects a
    /// snapshot that is not for this vehicle/session, whose causal source is not in
    /// this session, that is flagged invalid, or whose capture time does not
    /// strictly advance the currently held snapshot, or whose source position
    /// replays/regresses a boot-local source stream. `observed_at` is sampled by
    /// the Gate clock and bounds both receive and capture time — a blind setter would let
    /// whichever task can call it author the causal truth Gate relies on, and
    /// without the monotonicity check a producer could roll the vehicle back to an
    /// older-but-still-fresh favourable snapshot and flip a geofence/phase DENY to
    /// ALLOW. Full signed state-producer contracts are a later profile (see
    /// `docs/LIMITATIONS.md`).
    ///
    /// # Errors
    /// Returns a stable reason code on any ingress-validation failure.
    pub fn set_trusted_state(
        &mut self,
        state: TrustedStateSnapshotV1,
        observed_at: MonoInstant,
    ) -> Result<(), R> {
        if !self.mono_ok(observed_at) {
            return Err(R::ErrorStateTransition);
        }
        self.expire_active_lease_if_needed(observed_at);
        if self.fault.is_latched() {
            return Err(R::ErrorStateTransition);
        }
        self.validate_trusted_state(&state, observed_at)?;
        if let Err(class) = self.commit_source_replay_position(&state.primary_source.source) {
            if class == SourceReplayClass::CapacityExhausted {
                return Err(R::ErrorNamespaceExhausted);
            }
            // Validation classified this exact position as fresh under the same
            // exclusive actor owner. A different commit result is an internal
            // state-machine disagreement, not a recoverable producer replay.
            self.latch_fault("SOURCE_REPLAY_CLASSIFY_COMMIT_INVARIANT");
            return Err(R::ErrorInternalFault);
        }
        self.trusted_state = Some(state);
        Ok(())
    }

    pub(crate) fn validate_trusted_state(
        &self,
        state: &TrustedStateSnapshotV1,
        observed_at: MonoInstant,
    ) -> Result<(), R> {
        if self.fault.is_latched()
            || !matches!(
                self.process.state(),
                GateProcessStateV1::SessionBound | GateProcessStateV1::Active
            )
        {
            return Err(R::ErrorStateTransition);
        }
        if state.vehicle_id != self.vehicle_id {
            return Err(R::DenyStateProducer);
        }
        if state.session != self.session || state.primary_source.session != self.session {
            return Err(R::DenyStateStale);
        }
        if self.lease.as_ref().is_some_and(|lease| {
            !lease.permits_source_key(state.primary_source.source.source_key.as_str())
        }) {
            return Err(R::DenySourceUnknown);
        }
        if !state.primary_source.valid {
            return Err(R::DenyStateStale);
        }
        if state.primary_source.source.stream_seq.get() > NCP_JSON_SAFE_INTEGER_MAX {
            return Err(R::DenySourceUnrepresentable);
        }
        if state.primary_source.receive_mono > state.captured_mono
            || state.captured_mono > observed_at
        {
            return Err(R::DenyStateStale);
        }
        if state.uncertainty.position_mm.iter().any(|&value| value < 0)
            || state
                .uncertainty
                .velocity_mm_s
                .iter()
                .any(|&value| value < 0)
        {
            return Err(R::DenyUncertainty);
        }
        // Anti-rollback: capture time must strictly advance. Two different truths
        // cannot share one capture instant, and a non-advancing snapshot carries
        // no new causal information — reject it rather than regress.
        if let Some(prev) = &self.trusted_state
            && state.captured_mono <= prev.captured_mono
        {
            return Err(R::DenyStateStale);
        }
        let source_class = self.source_replay.classify(&state.primary_source.source);
        if !source_class.is_fresh() {
            return Err(source_replay_reason(source_class));
        }
        Ok(())
    }

    #[cfg(feature = "live-zenoh")]
    pub(crate) fn active_intent_binding(
        &self,
    ) -> Option<(&haldir_contracts::ids::ControllerId, &str)> {
        if !self.process.is_active() {
            return None;
        }
        let lease = self.lease.as_ref()?;
        Some((&lease.controller_id, lease.controller_intent_key.as_str()))
    }

    fn validate_controller_signer_binding(&self, lease: &MissionLeaseV1) -> Result<(), GateError> {
        let record = self
            .trust
            .resolve(&lease.controller_intent_signing_key_id)
            .ok_or_else(|| GateError::Crypto(CryptoError::KidUnknown.reason_code()))?;
        if record.role != KeyRole::ControllerIntent {
            return Err(GateError::Crypto(CryptoError::WrongRole.reason_code()));
        }
        if record.class != KeyClass::Assurance {
            return Err(GateError::Crypto(
                CryptoError::DevelopmentKeyInAssurance.reason_code(),
            ));
        }
        if self
            .revocations
            .is_key_revoked(&lease.controller_intent_signing_key_id)
        {
            return Err(GateError::Crypto(CryptoError::KeyRevoked.reason_code()));
        }
        if record.subject.as_str() != lease.controller_id.as_str() {
            return Err(GateError::Crypto(CryptoError::WrongRole.reason_code()));
        }
        Ok(())
    }

    /// Accept a signed mission lease and become ACTIVE.
    ///
    /// # Errors
    /// Returns a [`GateError`] if the lifecycle is not session-bound, a
    /// publication slot is unresolved, or signature, admission, or acceptance
    /// validation fails. The lease-nominated controller key must already resolve
    /// to an unrevoked assurance-class `ControllerIntent` record whose subject
    /// matches the admitted controller; that preflight precedes durable term and
    /// one-shot challenge mutation.
    pub fn accept_lease_env(&mut self, env: &[u8], now: MonoInstant) -> Result<(), GateError> {
        match self
            .accept_lease_env_with_validator(env, now, |_| Ok::<(), core::convert::Infallible>(()))
        {
            Ok(()) => Ok(()),
            Err(LeaseEnvelopeValidationError::Gate(error)) => Err(error),
            Err(LeaseEnvelopeValidationError::ValidatorRejected(infallible)) => match infallible {},
        }
    }

    pub(crate) fn accept_lease_env_with_validator<E, F>(
        &mut self,
        env: &[u8],
        now: MonoInstant,
        validate: F,
    ) -> Result<(), LeaseEnvelopeValidationError<E>>
    where
        F: FnOnce(&MissionLeaseV1) -> Result<(), E>,
    {
        if self.fault.is_latched() {
            return Err(GateError::Faulted.into());
        }
        if self.publication_state != PublicationState::Idle {
            return Err(GateError::PublicationPending.into());
        }
        // Reject an ordinary replacement while ACTIVE before observing the
        // candidate call's clock value. Besides preserving a true no-op, this
        // prevents an invalid lifecycle call from advancing the monotonic
        // high-water or turning a later valid observation into a false clock
        // regression. The one exception is an exactly expired active lease:
        // materialize that time-driven transition below so a previously issued,
        // still-pending challenge can establish its successor.
        if self.process.state() != GateProcessStateV1::SessionBound
            && !(self.process.is_active()
                && self
                    .lease
                    .as_ref()
                    .is_some_and(|lease| lease.is_expired_at(now)))
        {
            return Err(GateError::NotSessionBound.into());
        }
        if !self.mono_ok(now) {
            return Err(GateError::Faulted.into());
        }
        self.expire_active_lease_if_needed(now);
        if self.fault.is_latched() {
            return Err(GateError::Faulted.into());
        }
        if self.process.state() != GateProcessStateV1::SessionBound {
            return Err(GateError::NotSessionBound.into());
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
            return Err(GateError::Crypto("DENY_WRONG_ROLE").into());
        }
        if sub.as_str() != lease.issuer_id.as_str() {
            return Err(GateError::Crypto("DENY_WRONG_ROLE").into());
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
        // The mission authority may select only an immediately usable,
        // assurance-class controller signing identity. Rejecting this before
        // `accept_lease` prevents a false-success activation from spending the
        // durable term and one-shot challenge for a key that could never
        // authenticate an intent under this runtime snapshot.
        self.validate_controller_signer_binding(&lease)?;
        let lctx = LeaseAcceptContext {
            gate_id: self.gate_id.clone(),
            gate_boot_id: self.gate_boot_id,
            realm: self.realm.clone(),
            vehicle_id: self.vehicle_id.clone(),
            session: self.session.clone(),
            gate_output_epoch: self.output_epoch,
            policy_snapshot_digest: self.policy.canonical_digest(),
            controller,
            local_cap_ms: self.local_cap_ms,
        };
        // Every fallible local activation prerequisite must be checked before
        // the durable term high-water or one-shot challenge is consumed. The
        // actor is single-owned, so a successful preflight guarantees the later
        // bump cannot race another mutation.
        if self.revision.is_exhausted() {
            self.latch_fault("AUTHORIZATION_REVISION_EXHAUSTED");
            return Err(GateError::Faulted.into());
        }
        validate(&lease).map_err(LeaseEnvelopeValidationError::ValidatorRejected)?;
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
                return Err(GateError::Faulted.into());
            }
            Err(LeaseAcceptError::DeadlineOverflow) => {
                self.latch_fault("LEASE_DEADLINE_OVERFLOW");
                return Err(GateError::Faulted.into());
            }
            Err(LeaseAcceptError::ChallengeCommitInvariant) => {
                self.latch_fault("LEASE_CHALLENGE_COMMIT_INVARIANT");
                return Err(GateError::Faulted.into());
            }
            Err(error) => return Err(GateError::Lease(error.reason_code().code()).into()),
        };
        let usage = LeaseUsage::new(
            snap.max_total_intents.get(),
            snap.max_intent_rate_millihz.get(),
            now,
        );
        self.lease = Some(snap);
        self.lease_usage = Some(usage);
        self.replay = ControllerReplayState::new(MAX_RETIRED);
        // Do not inherit a prior mission's slew reference into this lease.
        self.history.clear_slew_reference();
        if self.revision.bump().is_none() {
            self.latch_fault("AUTHORIZATION_REVISION_EXHAUSTED");
            return Err(GateError::Faulted.into());
        }
        if self.process.transition(GateProcessStateV1::Active).is_err() {
            self.latch_fault("ACTIVATE_TRANSITION");
            return Err(GateError::Faulted.into());
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
                // Track exhaustion independently from the first-fault latch:
                // another fault may already own that latch reason, but it must
                // not suppress terminal receipt caching and reopen counter zero.
                self.decision_namespace_exhausted = true;
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
        receipt.reason_codes = BoundedVec::singleton(reason);
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

    /// Build and sign one policy denial without discarding independently true
    /// reasons. The evaluator and receipt schema share the hard bound of 32;
    /// malformed evaluator output is an actor invariant failure, not a partial
    /// receipt that happens to retain the first reason.
    fn respond_policy_denial(
        &self,
        draft: &ReceiptDraft,
        reasons: Vec<R>,
        now: MonoInstant,
    ) -> Option<DecisionRecord> {
        if reasons.is_empty()
            || reasons.len() > 32
            || reasons.iter().any(|reason| !reason.is_deny())
            || reasons
                .iter()
                .enumerate()
                .any(|(index, reason)| reasons.iter().take(index).any(|prior| prior == reason))
        {
            return None;
        }
        let reason_codes = BoundedVec::from_vec(reasons).ok()?;
        let mut receipt = draft.base();
        receipt.decision = DecisionOutcomeV1::Deny;
        receipt.reason_codes = reason_codes;
        receipt.decided_mono_ns = now.as_nanos();
        receipt.publish_stage = PublishStageV1::DecidedDeny;
        let signed_receipt = self.sign_receipt(&receipt);
        Some(DecisionRecord {
            receipt,
            signed_receipt,
            outcome: DecisionOutcomeV1::Deny,
            prepared_publication: None,
        })
    }

    /// Process one already length-bounded crate-internal intent and append its signed receipt to the digest-chained
    /// evidence spool. Journaling never changes the decision: an ALLOW is already
    /// committed to the returned frame, and a full spool drops only the export
    /// copy (a spool outage can never turn a DENY into an ALLOW).
    #[must_use = "a decision may contain a prepared publication that must be resolved"]
    pub(crate) fn decide_intent(
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
        if self.decision_namespace_exhausted {
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
            received_key_digest: DigestV1::compute(
                DigestDomain::TransportKey,
                actual_key.as_bytes(),
            ),
            raw_envelope_digest: DigestV1::compute(DigestDomain::RawEnvelope, env),
            policy_snapshot_digest: self.policy.canonical_digest(),
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
        if self.expire_active_lease_if_needed(now) {
            return if self.fault.is_latched() {
                self.respond(&draft, R::ErrorInternalFault, now)
            } else {
                self.respond(&draft, R::DenyLeaseExpired, now)
            };
        }
        if !self.process.is_active() {
            return self.respond(&draft, R::DenyLeaseAbsent, now);
        }
        if env.len() > MAX_INTENT_ENVELOPE_BYTES || actual_key.len() > MAX_INTENT_ROUTE_BYTES {
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
        draft.semantic_intent_digest = Some(intent.semantic_digest());
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
            || actual_key != lease.controller_intent_key.as_str()
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
            || intent.mission_lease_term != lease.lease_term
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
        // hold the ControllerIntent role. Every trust record has a mandatory,
        // bounded subject, and that subject must exact-match here. These are
        // equality-checked consistency claims, not trusted evidence content.
        if intent.controller_id != lease.controller.controller_id
            || intent.controller_signing_key_id != signer_kid
            || signer_subject.as_str() != intent.controller_id.as_str()
        {
            return self.respond(&draft, R::DenyScopeMismatch, now);
        }
        // Stage 6 — controller replay (two-phase): classify (no consume) then commit
        let cls = self.replay.classify(
            intent.intent_position.epoch,
            intent.intent_position.seq.get(),
        );
        if !cls.is_fresh() {
            return self.respond(&draft, replay_reason(cls), now);
        }
        if self
            .commit_replay_position(&intent.intent_position)
            .is_err()
        {
            self.latch_fault("REPLAY_CLASSIFY_COMMIT_INVARIANT");
            return self.respond(&draft, R::ErrorInternalFault, now);
        }

        // Stage 6b — lease usage: total-intent ceiling + fixed-point rate bucket
        // (H-B07). Charged only for fresh, correctly-scoped intents that have
        // just consumed their replay position; a rate/total refusal is a DENY
        // that still spends the sequence (no output, no retry of this position).
        let usage_result = match self.lease_usage.as_mut() {
            Some(usage) => usage.try_consume(now),
            None => {
                // ACTIVE with no usage state cannot be produced by the public
                // transition API. Treat it as a terminal actor invariant breach,
                // not as a recoverable refusal for this one intent.
                self.latch_fault("ACTIVE_LEASE_USAGE_INVARIANT");
                return self.respond(&draft, R::ErrorInternalFault, now);
            }
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
        let decision = match try_decide_validated(&PolicyInput {
            now,
            lease: &lease,
            state: &state,
            action: &intent.action,
            history: &self.history,
            policy: &self.policy,
        }) {
            Ok(decision) => decision,
            Err(error) => {
                self.latch_fault(error.detail_reason_code());
                return self.respond(&draft, R::ErrorInternalFault, now);
            }
        };
        let effective_validity_ms = match decision.effective_validity_ms() {
            Some(v) => v,
            None => {
                let Some(record) = self.respond_policy_denial(&draft, decision.reasons, now) else {
                    self.latch_fault("POLICY_DENIAL_REASONS_INVARIANT");
                    return self.respond(&draft, R::ErrorInternalFault, now);
                };
                return record;
            }
        };

        // Stage 12 — output allocation, after a TOCTOU re-check (B1)
        self.apply_authorization_revision_test_hook();
        if self.revision.get() != captured_rev {
            // `decide_intent` owns `&mut self`, so an in-decision revision change
            // is impossible under the current public API. If a future embedding
            // or refactor violates that assumption, fail-stop instead of allowing
            // the next intent to proceed from a potentially inconsistent actor.
            self.latch_fault("AUTHORIZATION_REVISION_CHANGED_DURING_DECISION");
            return self.respond(&draft, R::ErrorInternalFault, now);
        }
        if !self.publication.authorizes_acl_only_publication() {
            return self.respond(&draft, R::DenyNoPublicationAuthority, now);
        }
        if self.publication_state != PublicationState::Idle {
            return self.respond(&draft, R::DenyOverload, now);
        }
        let Some(latest_call_at) = now.checked_add_ms(u64::from(
            self.policy.snapshot().publication_safety_margin_ms,
        )) else {
            return self.respond(&draft, R::DenyArithmeticOverflow, now);
        };
        let allocation = self.allocate_output_sequence();
        let out_seq = match allocation {
            Ok(s) => s,
            Err(_) => {
                // Unlike a busy publication slot, sequence exhaustion cannot
                // recover within this output epoch. Continuing to report an
                // active actor would misclassify a permanent namespace failure
                // as transient load and spend later intent positions uselessly.
                self.latch_fault("OUTPUT_STREAM_EXHAUSTED");
                return self.respond(&draft, R::ErrorNamespaceExhausted, now);
            }
        };
        let build_input = GateCommandBuildInputV1 {
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
        let plant_command = match PlantCommand::from_exact_frame(decision_id, frame) {
            Ok(command) => command,
            Err(_) => {
                self.latch_fault("REFERENCE_PLANT_COMMAND_BUILD_FAILED");
                return self.respond(&draft, R::ErrorInternalFault, now);
            }
        };
        let output_frame_digest = plant_command.output_frame_digest();
        let mut receipt = draft.base();
        receipt.decision = DecisionOutcomeV1::Allow;
        // AllowPrepared, not AllowPublished: the Gate authorized and prepared the
        // exact output frame, but publication to NCP happens downstream — the
        // Gate does not claim delivery it did not observe (H-H10 honesty).
        receipt.reason_codes = BoundedVec::singleton(R::AllowPrepared);
        receipt.effective_validity_ms = Some(effective_validity_ms);
        receipt.gate_output_stream = Some(build_input.stream.clone());
        receipt.output_frame_digest = Some(output_frame_digest);
        receipt.transformation_relation = Some(plant_command.exact_frame().transformation());
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
                plant_command,
                effective_validity_ms,
            }),
        }
    }
}

fn output_sequence_is_wire_representable(sequence: OutputSeq) -> bool {
    sequence.get() <= NCP_JSON_SAFE_INTEGER_MAX
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

#[cfg(test)]
mod output_sequence_wire_bound_tests {
    use super::output_sequence_is_wire_representable;
    use core::num::NonZeroU64;
    use haldir_contracts::ids::OutputSeq;
    use haldir_ncp08::NCP_JSON_SAFE_INTEGER_MAX;

    #[test]
    fn implemented_wire_namespace_ends_at_the_json_safe_integer_limit() {
        let at_limit = NonZeroU64::new(NCP_JSON_SAFE_INTEGER_MAX)
            .map(OutputSeq::new)
            .expect("the fixed positive limit constructs");
        let over_limit = NonZeroU64::new(NCP_JSON_SAFE_INTEGER_MAX + 1)
            .map(OutputSeq::new)
            .expect("the fixed positive successor constructs");

        assert!(output_sequence_is_wire_representable(at_limit));
        assert!(!output_sequence_is_wire_representable(over_limit));
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
    fn rate_denials_still_consume_the_finite_total_intent_budget() {
        let t0 = MonoInstant::from_nanos(0);
        let mut usage = LeaseUsage::new(3, 1_000, t0);

        assert_eq!(usage.try_consume(t0), Ok(()));
        assert_eq!(usage.try_consume(t0), Err(R::DenyRateLimit));
        assert_eq!(usage.try_consume(t0), Err(R::DenyRateLimit));
        assert_eq!(usage.try_consume(t0), Err(R::DenyTotalIntents));
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

    #[test]
    fn denied_sub_quantum_calls_preserve_fractional_refill_credit() {
        let t0 = MonoInstant::from_nanos(0);
        let mut usage = LeaseUsage::new(100, 500_000, t0);
        usage.tokens_micro = 0;

        assert_eq!(
            usage.try_consume(MonoInstant::from_nanos(1)),
            Err(R::DenyRateLimit)
        );
        assert_eq!(usage.tokens_micro, 0);
        assert_eq!(usage.refill_remainder, 500_000);

        assert_eq!(
            usage.try_consume(MonoInstant::from_nanos(2)),
            Err(R::DenyRateLimit)
        );
        assert_eq!(usage.tokens_micro, 1);
        assert_eq!(usage.refill_remainder, 0);
    }
}
