//! Gate-specific semantic verification and fresh publication-state replay.
//!
//! [`GateJournalVerifier`] is deliberately stateless: the directory manager may
//! call it before append capacity or commit is known. Startup replay separately
//! walks a successfully returned [`JournalRecovery`]
//! once, reverifies each envelope, and returns fresh read-only recovered state
//! only after the complete pass succeeds.

use crate::journal::SegmentIdentity;
use crate::manager::{
    EvidenceJournalManager, EvidenceRecordDigest, JournalManagerError, JournalOpenOptions,
    JournalRecovery, JournalRecoveryReport, JournalReservation, JournalSigner,
    JournalVerificationError, JournalVerifier, RecoveryCaptureDimension, RecoveryCaptureLimits,
    RecoveryPrecommitPlan,
};
use crate::publication::{PublicationReductionError, PublicationStageReducer};
use core::num::{NonZeroU32, NonZeroU64, NonZeroUsize};
use haldir_contracts::cbor::{CanonicalMessage, Limits, from_canonical_bytes};
use haldir_contracts::digest::{DigestDomain, DigestV1};
use haldir_contracts::ids::{DecisionId, GateBootId, GateId};
use haldir_contracts::publication::PublicationStageEventV1;
use haldir_contracts::receipt::{
    DecisionOutcomeV1, DecisionReasonCodeV1, DecisionReceiptV1, PublishStageV1,
};
use haldir_crypto::{
    ExpectedContext, KeyClass, KeyRole, RevocationSnapshot, TrustStore, VerifyingKey,
    content_type_for, sign_message, verify_sign1_dispatched,
};
use std::collections::BTreeSet;
use std::path::PathBuf;

/// Gate-journal semantic verification failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum GateJournalVerificationError {
    /// The record exceeded the configured complete-envelope byte bound.
    EnvelopeTooLarge,
    /// A segment claimed another Gate.
    SegmentGateMismatch,
    /// The segment footer key was absent, revoked, wrong-role/class/subject, or
    /// did not exactly match the header bytes.
    SegmentSignerUntrusted,
    /// The protected content type, signature, or canonical typed payload failed.
    InvalidEnvelope,
    /// A signed receipt contradicted the current Gate outcome/reason/stage/output
    /// profile or regressed its local decision time.
    ReceiptSemanticInvalid,
    /// The record and footer used different Gate application key IDs.
    RecordSignerMismatch,
    /// The record signer subject was absent or did not name the configured Gate.
    RecordSubjectMismatch,
    /// The typed record claimed another Gate.
    RecordGateMismatch,
    /// The typed record's producing Gate boot did not match its segment boot.
    RecordBootMismatch,
}

/// Publication recovery failure. No partially reduced state is returned.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PublicationRecoveryError {
    /// A segment or record failed Gate-journal verification.
    Verification(GateJournalVerificationError),
    /// A Gate boot ID reappeared after a different boot's segment run.
    BootResurrection,
    /// Segment creation time regressed within one Gate boot.
    SegmentTimeRegression,
    /// Ordered record time regressed within one Gate boot, including across
    /// non-publication decision receipts.
    RecordTimeRegression,
    /// A decision receipt key appeared more than once in retained order.
    DuplicateDecisionReceipt,
    /// The linked publication trace was malformed, out of order, or over bound.
    Reduction(PublicationReductionError),
}

/// Fused Gate-journal open or semantic replay failure.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum GateJournalOpenError {
    /// The reducer bound cannot retain every record admitted by capture.
    TraceCapacityTooSmall,
    /// Directory discovery, recovery, signer, bounds, or storage failed.
    Journal(JournalManagerError),
    /// The complete history failed semantic replay before prior-tail closure and
    /// current-segment creation. Pending-artifact removal or insufficient-tail
    /// truncation may already have occurred as reported.
    Replay {
        /// Exact semantic rejection.
        error: PublicationRecoveryError,
        /// Observations available at the precommit boundary.
        recovery: JournalRecoveryReport,
    },
}

/// Transactional live/recovery append failure.
///
/// A single-record operation installs no candidate reducer state until its
/// append returns confirmed success. Consuming batch operations never return a
/// partially updated aggregate after failure; callers must recover before
/// making another decision.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum GateJournalMutationError {
    /// Logical journal bounds, storage, signer, duplicate, or commit ambiguity.
    Journal(JournalManagerError),
    /// The typed record batch would make ordered replay fail.
    Semantic(PublicationRecoveryError),
}

impl From<JournalManagerError> for GateJournalMutationError {
    fn from(error: JournalManagerError) -> Self {
        Self::Journal(error)
    }
}

impl From<PublicationRecoveryError> for GateJournalMutationError {
    fn from(error: PublicationRecoveryError) -> Self {
        Self::Semantic(error)
    }
}

impl From<JournalManagerError> for GateJournalOpenError {
    fn from(error: JournalManagerError) -> Self {
        Self::Journal(error)
    }
}

impl From<GateJournalVerificationError> for PublicationRecoveryError {
    fn from(error: GateJournalVerificationError) -> Self {
        Self::Verification(error)
    }
}

impl From<PublicationReductionError> for PublicationRecoveryError {
    fn from(error: PublicationReductionError) -> Self {
        Self::Reduction(error)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GateRecordKind {
    DecisionReceipt,
    PublicationStage,
}

enum VerifiedGateValue {
    DecisionReceipt(Box<DecisionReceiptV1>),
    PublicationStage(Box<PublicationStageEventV1>),
}

/// Borrowed view of a sealed, verified Gate journal record.
#[non_exhaustive]
pub enum VerifiedGateRecordRef<'a> {
    /// One canonical Gate-signed decision receipt.
    DecisionReceipt(&'a DecisionReceiptV1),
    /// One canonical Gate-signed publication-stage event.
    PublicationStage(&'a PublicationStageEventV1),
}

/// Sealed typed record produced only by [`GateJournalVerifier::verify_record`].
///
/// The exact envelope digest and trust-bound claimed segment fields are retained
/// without exposing a public constructor. Direct verification does not prove that
/// the supplied segment identity belongs to a footer-verified journal chain;
/// [`GateJournalVerifier::rebuild_publication_state`] obtains that stronger
/// provenance only from a manager-produced recovery snapshot.
pub struct VerifiedGateRecord {
    value: VerifiedGateValue,
    envelope_digest: DigestV1,
    segment_sequence: NonZeroU64,
    segment_gate_boot_id: GateBootId,
}

/// Opaque read-only publication state rebuilt from one complete recovery
/// snapshot. The underlying reducer is intentionally not exposed: future live
/// mutation must require a separately verified, locally sync-confirmed record path.
pub struct RecoveredPublicationState {
    reducer: PublicationStageReducer,
    replayed_segments: usize,
    replayed_records: u64,
    recovered_boots: BTreeSet<GateBootId>,
    last_recovered_segment_sequence: Option<NonZeroU64>,
    decision_receipts: BTreeSet<(GateBootId, DecisionId)>,
    current_boot_record_high_water: Option<u64>,
}

/// One manager fused with the fresh publication state rebuilt from its exact
/// successful recovery snapshot under the same verifier configuration.
///
/// The manager and reducer cannot be extracted separately. This prevents a
/// caller from pairing manager A with state rebuilt from manager B or appending
/// between replay and a later runtime binding.
pub struct RecoveredGateJournal {
    manager: EvidenceJournalManager<GateJournalVerifier>,
    verifier: GateJournalVerifier,
    publication: RecoveredPublicationState,
    recovery: JournalRecoveryReport,
    capture_limits: RecoveryCaptureLimits,
    captured_records: u64,
    captured_record_bytes: u64,
    reserved_capture_records: u64,
    reserved_capture_bytes: u64,
}

/// Move-only Gate-journal reservation coupled to future recovery-capture
/// capacity and the underlying manager's conservative logical storage quota.
#[must_use = "dropping a live reservation intentionally strands its quota until journal recovery"]
pub struct GateJournalReservation {
    manager: JournalReservation,
    remaining_records: u64,
    bytes_per_record: u64,
    remaining_bytes: u64,
}

struct PreparedGateJournalMutation {
    reducer: PublicationStageReducer,
    decision_receipts: BTreeSet<(GateBootId, DecisionId)>,
    current_boot_record_high_water: Option<u64>,
    captured_records: u64,
    captured_record_bytes: u64,
}

impl RecoveredGateJournal {
    /// Provision a fresh journal, capture its empty history, and fuse one replay
    /// result with the retained manager.
    ///
    /// # Errors
    /// Returns before directory access when the reducer bound is smaller than
    /// the capture record bound, or on journal provisioning/capture and semantic
    /// replay failures.
    pub fn provision_new(
        directory: impl Into<PathBuf>,
        options: JournalOpenOptions,
        signer: &JournalSigner<'_>,
        capture_limits: RecoveryCaptureLimits,
        verifier: GateJournalVerifier,
        max_traces: NonZeroUsize,
    ) -> Result<Self, GateJournalOpenError> {
        preflight_trace_bound(capture_limits, max_traces)?;
        let mut publication = None;
        let mut capture_usage = None;
        let mut replay_failure = None;
        let mut replay_report = None;
        let mut precommit = |recovery: &JournalRecovery| match verifier
            .rebuild_publication_state_ref(recovery, max_traces.get())
        {
            Ok(state) => {
                publication = Some(state);
                capture_usage =
                    Some((recovery.report().recovered_records, recovery.record_bytes()));
                Ok(RecoveryPrecommitPlan::empty())
            }
            Err(error) => {
                replay_report = Some(recovery.report());
                replay_failure = Some(error);
                Err(JournalManagerError::RecoveryConsumerRejected)
            }
        };
        let (manager, recovery) =
            match EvidenceJournalManager::provision_new_with_recovery_precommit(
                directory,
                options,
                signer,
                capture_limits,
                verifier.clone(),
                &mut precommit,
            ) {
                Ok(result) => result,
                Err(JournalManagerError::RecoveryConsumerRejected) => {
                    return Err(replay_open_error(replay_failure, replay_report));
                }
                Err(error) => return Err(error.into()),
            };
        let publication = publication.ok_or(GateJournalOpenError::Journal(
            JournalManagerError::RecoveryConsumerRejected,
        ))?;
        let (captured_records, captured_record_bytes) = capture_usage.ok_or(
            GateJournalOpenError::Journal(JournalManagerError::RecoveryCaptureAllocation),
        )?;
        Ok(Self {
            manager,
            verifier,
            publication,
            recovery,
            capture_limits,
            captured_records,
            captured_record_bytes,
            reserved_capture_records: 0,
            reserved_capture_bytes: 0,
        })
    }

    /// Open/recover an existing journal and fuse the exact ordered replay result
    /// with the manager that produced it.
    ///
    /// # Errors
    /// Returns before directory access when the reducer bound is smaller than
    /// the capture record bound, or on journal open/recovery/capture and semantic
    /// replay failures.
    pub fn open_existing(
        directory: impl Into<PathBuf>,
        options: JournalOpenOptions,
        signer: &JournalSigner<'_>,
        recovered_tail_signer: Option<&JournalSigner<'_>>,
        capture_limits: RecoveryCaptureLimits,
        verifier: GateJournalVerifier,
        max_traces: NonZeroUsize,
    ) -> Result<Self, GateJournalOpenError> {
        preflight_trace_bound(capture_limits, max_traces)?;
        let mut publication = None;
        let mut capture_usage = None;
        let mut replay_failure = None;
        let mut replay_report = None;
        let mut precommit = |recovery: &JournalRecovery| match verifier
            .rebuild_publication_state_ref(recovery, max_traces.get())
        {
            Ok(state) => {
                publication = Some(state);
                capture_usage =
                    Some((recovery.report().recovered_records, recovery.record_bytes()));
                Ok(RecoveryPrecommitPlan::empty())
            }
            Err(error) => {
                replay_report = Some(recovery.report());
                replay_failure = Some(error);
                Err(JournalManagerError::RecoveryConsumerRejected)
            }
        };
        let (manager, recovery) =
            match EvidenceJournalManager::open_existing_with_recovery_precommit(
                directory,
                options,
                signer,
                recovered_tail_signer,
                capture_limits,
                verifier.clone(),
                &mut precommit,
            ) {
                Ok(result) => result,
                Err(JournalManagerError::RecoveryConsumerRejected) => {
                    return Err(replay_open_error(replay_failure, replay_report));
                }
                Err(error) => return Err(error.into()),
            };
        let publication = publication.ok_or(GateJournalOpenError::Journal(
            JournalManagerError::RecoveryConsumerRejected,
        ))?;
        let (captured_records, captured_record_bytes) = capture_usage.ok_or(
            GateJournalOpenError::Journal(JournalManagerError::RecoveryCaptureAllocation),
        )?;
        Ok(Self {
            manager,
            verifier,
            publication,
            recovery,
            capture_limits,
            captured_records,
            captured_record_bytes,
            reserved_capture_records: 0,
            reserved_capture_bytes: 0,
        })
    }

    /// Open/replay an existing journal and append every required current-boot
    /// `UnknownAfterPublish` record inside the same recovery transaction.
    ///
    /// The complete signed batch is capture- and semantic-preflighted, and its
    /// conservative logical quota is checked before the old active tail is closed
    /// or the current segment is published. The manager then issues the reservation
    /// before the first append. The returned aggregate has already reduced every
    /// confirmed startup record; no live mutation boundary is exposed between
    /// replay and ambiguity closure.
    ///
    /// # Errors
    /// Returns on the errors documented by [`Self::open_existing`], recovery
    /// event planning/verification, future capture exhaustion, conservative
    /// logical reservation failure, or an append ambiguity.
    pub fn open_existing_with_recovery_unknowns(
        directory: impl Into<PathBuf>,
        options: JournalOpenOptions,
        signer: &JournalSigner<'_>,
        recovered_tail_signer: Option<&JournalSigner<'_>>,
        capture_limits: RecoveryCaptureLimits,
        verifier: GateJournalVerifier,
        max_traces: NonZeroUsize,
    ) -> Result<(Self, usize), GateJournalOpenError> {
        preflight_trace_bound(capture_limits, max_traces)?;
        let recovery_boot_id = options.gate_boot_id();
        let observed_mono_ns = options.created_mono_ns();
        let prospective_identity = SegmentIdentity {
            gate_id: verifier.gate_id().clone(),
            gate_boot_id: recovery_boot_id,
            segment_sequence: NonZeroU64::new(1).ok_or(GateJournalOpenError::Journal(
                JournalManagerError::SequenceExhausted,
            ))?,
            previous_completed_digest: [0; 32],
            created_mono_ns: observed_mono_ns,
            signer_kid: signer.kid().clone(),
            signer_public_key: signer.key().verifying_key().to_bytes(),
        };
        let mut publication = None;
        let mut capture_usage = None;
        let mut appended_unknowns = 0usize;
        let mut replay_failure = None;
        let mut replay_report = None;
        let mut precommit = |recovery: &JournalRecovery| {
            let mut state = match verifier.rebuild_publication_state_ref(recovery, max_traces.get())
            {
                Ok(state) => state,
                Err(error) => {
                    replay_report = Some(recovery.report());
                    replay_failure = Some(error);
                    return Err(JournalManagerError::RecoveryConsumerRejected);
                }
            };
            if state.contains_recovered_boot(recovery_boot_id) {
                replay_report = Some(recovery.report());
                replay_failure = Some(PublicationRecoveryError::Reduction(
                    PublicationReductionError::RecoveryBootAlreadyObserved,
                ));
                return Err(JournalManagerError::RecoveryConsumerRejected);
            }
            let events = match state
                .reducer
                .unknown_after_publish_events(recovery_boot_id, observed_mono_ns)
            {
                Ok(events) => events,
                Err(error) => {
                    replay_report = Some(recovery.report());
                    replay_failure = Some(PublicationRecoveryError::Reduction(error));
                    return Err(JournalManagerError::RecoveryConsumerRejected);
                }
            };
            let envelopes = events
                .iter()
                .map(|event| {
                    sign_message(
                        event,
                        PublicationStageEventV1::KIND,
                        PublicationStageEventV1::SCHEMA_MAJOR,
                        signer.kid(),
                        signer.key(),
                    )
                })
                .collect::<Vec<_>>();
            let required_records = recovery
                .report()
                .recovered_records
                .saturating_add(u64::try_from(envelopes.len()).unwrap_or(u64::MAX));
            if required_records > capture_limits.max_records() {
                return Err(JournalManagerError::RecoveryCaptureLimitExceeded {
                    dimension: RecoveryCaptureDimension::RecordCount,
                    maximum: capture_limits.max_records(),
                    required: required_records,
                });
            }
            let appended_bytes = envelopes.iter().fold(0u64, |bytes, envelope| {
                bytes.saturating_add(u64::try_from(envelope.len()).unwrap_or(u64::MAX))
            });
            let required_bytes = recovery.record_bytes().saturating_add(appended_bytes);
            if required_bytes > capture_limits.max_total_record_bytes() {
                return Err(JournalManagerError::RecoveryCaptureLimitExceeded {
                    dimension: RecoveryCaptureDimension::RecordBytes,
                    maximum: capture_limits.max_total_record_bytes(),
                    required: required_bytes,
                });
            }

            let mut candidate = state.reducer.clone();
            for (event, envelope) in events.iter().zip(&envelopes) {
                let verified = match verifier.verify_record(&prospective_identity, envelope) {
                    Ok(verified) => verified,
                    Err(error) => {
                        replay_report = Some(recovery.report());
                        replay_failure = Some(PublicationRecoveryError::Verification(error));
                        return Err(JournalManagerError::RecoveryConsumerRejected);
                    }
                };
                if !matches!(
                    verified.value(),
                    VerifiedGateRecordRef::PublicationStage(decoded) if decoded == event
                ) {
                    replay_report = Some(recovery.report());
                    replay_failure = Some(PublicationRecoveryError::Verification(
                        GateJournalVerificationError::InvalidEnvelope,
                    ));
                    return Err(JournalManagerError::RecoveryConsumerRejected);
                }
                if let Err(error) = candidate.apply_event(event, envelope) {
                    replay_report = Some(recovery.report());
                    replay_failure = Some(PublicationRecoveryError::Reduction(error));
                    return Err(JournalManagerError::RecoveryConsumerRejected);
                }
            }
            state.reducer = candidate;
            if !envelopes.is_empty() {
                state.current_boot_record_high_water = Some(observed_mono_ns);
            }
            appended_unknowns = envelopes.len();
            capture_usage = Some((required_records, required_bytes));
            publication = Some(state);
            Ok(RecoveryPrecommitPlan::with_records(envelopes))
        };
        let (manager, recovery) =
            match EvidenceJournalManager::open_existing_with_recovery_precommit(
                directory,
                options,
                signer,
                recovered_tail_signer,
                capture_limits,
                verifier.clone(),
                &mut precommit,
            ) {
                Ok(result) => result,
                Err(JournalManagerError::RecoveryConsumerRejected) => {
                    return Err(replay_open_error(replay_failure, replay_report));
                }
                Err(error) => return Err(error.into()),
            };
        let publication = publication.ok_or(GateJournalOpenError::Journal(
            JournalManagerError::RecoveryConsumerRejected,
        ))?;
        let (captured_records, captured_record_bytes) = capture_usage.ok_or(
            GateJournalOpenError::Journal(JournalManagerError::RecoveryCaptureAllocation),
        )?;
        Ok((
            Self {
                manager,
                verifier,
                publication,
                recovery,
                capture_limits,
                captured_records,
                captured_record_bytes,
                reserved_capture_records: 0,
                reserved_capture_bytes: 0,
            },
            appended_unknowns,
        ))
    }

    /// Manager-created and trust-resolved current active identity. The open tail
    /// is not footer-authenticated evidence yet. This is observation data, not a
    /// standalone boot authority; a runtime must consume this aggregate and
    /// compare it with its non-forgeable committed startup state.
    #[must_use]
    pub fn active_identity(&self) -> Option<&SegmentIdentity> {
        self.manager.active_identity()
    }

    /// Read-only publication state rebuilt from this manager's exact history.
    #[must_use]
    pub const fn publication(&self) -> &RecoveredPublicationState {
        &self.publication
    }

    /// Material recovery actions and current-tail status when fused open
    /// completed. Later explicit mutation does not rewrite this open report.
    #[must_use]
    pub const fn recovery_report(&self) -> JournalRecoveryReport {
        self.recovery
    }

    /// Reserve conservative manager storage and future recovery-capture capacity
    /// for `record_count` maximum-sized envelopes.
    ///
    /// # Errors
    /// Returns before changing reservation state when count/byte capture bounds,
    /// segment/byte quota, or the checked segment sequence cannot retain the
    /// requested units.
    pub fn reserve_append_capacity(
        &mut self,
        record_count: usize,
    ) -> Result<GateJournalReservation, GateJournalMutationError> {
        let additional_records = u64::try_from(record_count).unwrap_or(u64::MAX);
        let reserved_capture_records = self
            .reserved_capture_records
            .saturating_add(additional_records);
        let required_records = self
            .captured_records
            .saturating_add(reserved_capture_records);
        if required_records > self.capture_limits.max_records() {
            return Err(JournalManagerError::RecoveryCaptureLimitExceeded {
                dimension: RecoveryCaptureDimension::RecordCount,
                maximum: self.capture_limits.max_records(),
                required: required_records,
            }
            .into());
        }
        let bytes_per_record = u64::try_from(self.manager.max_record_bytes()).unwrap_or(u64::MAX);
        let additional_bytes = bytes_per_record.saturating_mul(additional_records);
        let reserved_capture_bytes = self.reserved_capture_bytes.saturating_add(additional_bytes);
        let required_bytes = self
            .captured_record_bytes
            .saturating_add(reserved_capture_bytes);
        if required_bytes > self.capture_limits.max_total_record_bytes() {
            return Err(JournalManagerError::RecoveryCaptureLimitExceeded {
                dimension: RecoveryCaptureDimension::RecordBytes,
                maximum: self.capture_limits.max_total_record_bytes(),
                required: required_bytes,
            }
            .into());
        }

        let manager = self.manager.reserve_append_capacity(record_count)?;
        self.reserved_capture_records = reserved_capture_records;
        self.reserved_capture_bytes = reserved_capture_bytes;
        Ok(GateJournalReservation {
            manager,
            remaining_records: additional_records,
            bytes_per_record,
            remaining_bytes: additional_bytes,
        })
    }

    /// Release unused reservation units before any corresponding recorded
    /// publication-call boundary has been locally sync-confirmed.
    ///
    /// # Errors
    /// Returns on a foreign/corrupt reservation or unusable manager. No capture
    /// accounting is released unless the manager accepts the token.
    pub fn release_reservation(
        &mut self,
        reservation: &mut GateJournalReservation,
    ) -> Result<(), GateJournalMutationError> {
        if !self.manager.owns_reservation(&reservation.manager) {
            return Err(JournalManagerError::ReservationMismatch.into());
        }
        let reserved_capture_records = self
            .reserved_capture_records
            .checked_sub(reservation.remaining_records)
            .ok_or(JournalManagerError::Poisoned)?;
        let reserved_capture_bytes = self
            .reserved_capture_bytes
            .checked_sub(reservation.remaining_bytes)
            .ok_or(JournalManagerError::Poisoned)?;
        self.manager.release_reservation(&mut reservation.manager)?;
        self.reserved_capture_records = reserved_capture_records;
        self.reserved_capture_bytes = reserved_capture_bytes;
        reservation.remaining_records = 0;
        reservation.remaining_bytes = 0;
        Ok(())
    }

    /// Verify and semantic-preview one closed-vocabulary Gate envelope, append
    /// it against a retained reservation, and install the candidate publication
    /// state only after the local append and `sync_data` are confirmed.
    ///
    /// # Errors
    /// Returns without reducer mutation on trust/schema/order/capture or manager
    /// failure. A commit ambiguity poisons the underlying manager; the caller
    /// must discard this fused object and recover before retrying.
    pub fn append_reserved_verified(
        &mut self,
        reservation: &mut GateJournalReservation,
        envelope: &[u8],
        rotation_created_mono_ns: u64,
        signer: &JournalSigner<'_>,
    ) -> Result<(), GateJournalMutationError> {
        if !self.manager.owns_reservation(&reservation.manager) {
            return Err(JournalManagerError::ReservationMismatch.into());
        }
        let active_created_mono_ns = self
            .manager
            .active_identity()
            .ok_or(JournalManagerError::Quiesced)?
            .created_mono_ns;
        if rotation_created_mono_ns < active_created_mono_ns {
            return Err(PublicationRecoveryError::SegmentTimeRegression.into());
        }
        let prepared = self.preview_mutation(&[envelope])?;
        if prepared
            .current_boot_record_high_water
            .is_some_and(|record_time| rotation_created_mono_ns < record_time)
        {
            return Err(PublicationRecoveryError::SegmentTimeRegression.into());
        }
        if reservation.remaining_records == 0 {
            return Err(JournalManagerError::ReservationExhausted.into());
        }
        let remaining_records = reservation
            .remaining_records
            .checked_sub(1)
            .ok_or(JournalManagerError::ReservationExhausted)?;
        let remaining_bytes = reservation
            .remaining_bytes
            .checked_sub(reservation.bytes_per_record)
            .ok_or(JournalManagerError::Poisoned)?;
        let reserved_capture_records = self
            .reserved_capture_records
            .checked_sub(1)
            .ok_or(JournalManagerError::Poisoned)?;
        let reserved_capture_bytes = self
            .reserved_capture_bytes
            .checked_sub(reservation.bytes_per_record)
            .ok_or(JournalManagerError::Poisoned)?;
        self.manager.append_reserved(
            &mut reservation.manager,
            envelope,
            rotation_created_mono_ns,
            signer,
        )?;
        self.reserved_capture_records = reserved_capture_records;
        self.reserved_capture_bytes = reserved_capture_bytes;
        reservation.remaining_records = remaining_records;
        reservation.remaining_bytes = remaining_bytes;
        self.publication.reducer = prepared.reducer;
        self.publication.decision_receipts = prepared.decision_receipts;
        self.publication.current_boot_record_high_water = prepared.current_boot_record_high_water;
        self.captured_records = prepared.captured_records;
        self.captured_record_bytes = prepared.captured_record_bytes;
        Ok(())
    }

    /// Consume this fused journal while locally sync-closing every recovered dangling
    /// publication call under the manager-created current segment boot.
    ///
    /// The complete deterministic batch is signed, statelessly verified,
    /// semantic-previewed on a cloned reducer, checked against future recovery
    /// capture bounds, and logically reserved before its first append. Each append
    /// is semantic-previewed before it is attempted. A confirmed append advances
    /// the internal candidate; any later failure consumes the whole aggregate, so
    /// partial batch state cannot escape and a fresh open/replay is required before
    /// retry decisions are made.
    ///
    /// This lower-level API derives the producer boot from the active segment and
    /// rejects it if that boot already appears anywhere in recovered journal
    /// provenance, including empty or non-publication segments. The caller must
    /// establish durable Gate-startup authority at a higher layer.
    ///
    /// `UnknownAfterPublish` means the prior process crossed its recorded
    /// write-ahead boundary but left no terminal local-return record. It does not
    /// claim that transport was invoked or that any receiver accepted the bytes.
    ///
    /// # Errors
    /// Returns on stale/same-boot recovery context, semantic/capture failure,
    /// logical capacity exhaustion, signer drift, storage failure, or an
    /// append-commit ambiguity.
    pub fn append_recovery_unknowns(
        mut self,
        observed_mono_ns: u64,
        signer: &JournalSigner<'_>,
    ) -> Result<(Self, usize), GateJournalMutationError> {
        let recovery_boot_id = self
            .manager
            .active_identity()
            .ok_or(JournalManagerError::Quiesced)?
            .gate_boot_id;
        if self.publication.contains_recovered_boot(recovery_boot_id) {
            return Err(PublicationRecoveryError::Reduction(
                PublicationReductionError::RecoveryBootAlreadyObserved,
            )
            .into());
        }
        let events = self
            .publication
            .reducer
            .unknown_after_publish_events(recovery_boot_id, observed_mono_ns)
            .map_err(PublicationRecoveryError::Reduction)?;
        if events.is_empty() {
            return Ok((self, 0));
        }

        let envelopes = events
            .iter()
            .map(|event| {
                sign_message(
                    event,
                    PublicationStageEventV1::KIND,
                    PublicationStageEventV1::SCHEMA_MAJOR,
                    signer.kid(),
                    signer.key(),
                )
            })
            .collect::<Vec<_>>();
        let envelope_refs = envelopes.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let _ = self.preview_mutation(&envelope_refs)?;
        let mut reservation = self.reserve_append_capacity(envelopes.len())?;
        for envelope in &envelopes {
            self.append_reserved_verified(&mut reservation, envelope, observed_mono_ns, signer)?;
        }
        Ok((self, events.len()))
    }

    fn preview_mutation(
        &self,
        envelopes: &[&[u8]],
    ) -> Result<PreparedGateJournalMutation, GateJournalMutationError> {
        let identity = self
            .manager
            .active_identity()
            .ok_or(JournalManagerError::Quiesced)?;
        let mut reducer = self.publication.reducer.clone();
        let mut decision_receipts = self.publication.decision_receipts.clone();
        let mut current_boot_record_high_water = self.publication.current_boot_record_high_water;
        let mut new_digests = BTreeSet::new();
        let mut record_bytes = 0u64;

        for &envelope in envelopes {
            let digest = EvidenceRecordDigest::compute(envelope);
            if self.manager.contains_record(digest)? || !new_digests.insert(digest) {
                return Err(JournalManagerError::DuplicateRecord.into());
            }
            record_bytes = record_bytes
                .checked_add(u64::try_from(envelope.len()).unwrap_or(u64::MAX))
                .ok_or(JournalManagerError::RecoveryCaptureLimitExceeded {
                    dimension: RecoveryCaptureDimension::RecordBytes,
                    maximum: self.capture_limits.max_total_record_bytes(),
                    required: u64::MAX,
                })?;
            let verified = self
                .verifier
                .verify_record(identity, envelope)
                .map_err(PublicationRecoveryError::Verification)?;
            let record_mono_ns = match verified.value() {
                VerifiedGateRecordRef::DecisionReceipt(receipt) => receipt.decided_mono_ns,
                VerifiedGateRecordRef::PublicationStage(event) => event.observed_mono_ns,
            };
            if current_boot_record_high_water.is_some_and(|previous| record_mono_ns < previous) {
                return Err(PublicationRecoveryError::RecordTimeRegression.into());
            }
            match verified.value() {
                VerifiedGateRecordRef::DecisionReceipt(receipt) => {
                    if !decision_receipts.insert((receipt.gate_boot_id, receipt.decision_id)) {
                        return Err(PublicationRecoveryError::DuplicateDecisionReceipt.into());
                    }
                    if receipt.decision == DecisionOutcomeV1::Allow {
                        reducer
                            .register_prepared(receipt, envelope)
                            .map_err(PublicationRecoveryError::Reduction)?;
                    }
                }
                VerifiedGateRecordRef::PublicationStage(event) => {
                    reducer
                        .apply_event(event, envelope)
                        .map_err(PublicationRecoveryError::Reduction)?;
                }
            }
            current_boot_record_high_water = Some(record_mono_ns);
        }

        let additional_records = u64::try_from(envelopes.len()).unwrap_or(u64::MAX);
        let captured_records = self
            .captured_records
            .checked_add(additional_records)
            .ok_or(JournalManagerError::RecoveryCaptureLimitExceeded {
                dimension: RecoveryCaptureDimension::RecordCount,
                maximum: self.capture_limits.max_records(),
                required: u64::MAX,
            })?;
        if captured_records > self.capture_limits.max_records() {
            return Err(JournalManagerError::RecoveryCaptureLimitExceeded {
                dimension: RecoveryCaptureDimension::RecordCount,
                maximum: self.capture_limits.max_records(),
                required: captured_records,
            }
            .into());
        }
        let captured_record_bytes = self.captured_record_bytes.checked_add(record_bytes).ok_or(
            JournalManagerError::RecoveryCaptureLimitExceeded {
                dimension: RecoveryCaptureDimension::RecordBytes,
                maximum: self.capture_limits.max_total_record_bytes(),
                required: u64::MAX,
            },
        )?;
        if captured_record_bytes > self.capture_limits.max_total_record_bytes() {
            return Err(JournalManagerError::RecoveryCaptureLimitExceeded {
                dimension: RecoveryCaptureDimension::RecordBytes,
                maximum: self.capture_limits.max_total_record_bytes(),
                required: captured_record_bytes,
            }
            .into());
        }
        Ok(PreparedGateJournalMutation {
            reducer,
            decision_receipts,
            current_boot_record_high_water,
            captured_records,
            captured_record_bytes,
        })
    }
}

fn preflight_trace_bound(
    capture_limits: RecoveryCaptureLimits,
    max_traces: NonZeroUsize,
) -> Result<(), GateJournalOpenError> {
    let max_traces = u64::try_from(max_traces.get()).unwrap_or(u64::MAX);
    if max_traces < capture_limits.max_records() {
        Err(GateJournalOpenError::TraceCapacityTooSmall)
    } else {
        Ok(())
    }
}

fn replay_open_error(
    error: Option<PublicationRecoveryError>,
    recovery: Option<JournalRecoveryReport>,
) -> GateJournalOpenError {
    match (error, recovery) {
        (Some(error), Some(recovery)) => GateJournalOpenError::Replay { error, recovery },
        _ => GateJournalOpenError::Journal(JournalManagerError::RecoveryConsumerRejected),
    }
}

impl RecoveredPublicationState {
    /// Reduced trace state for one decision key.
    #[must_use]
    pub fn state(
        &self,
        decision_gate_boot_id: GateBootId,
        decision_id: DecisionId,
    ) -> Option<crate::publication::PublicationTraceState> {
        self.reducer.state(decision_gate_boot_id, decision_id)
    }

    /// Largest effective-validity duration among recovered traces that crossed
    /// the recorded `PublishCalled` write-ahead boundary.
    ///
    /// This conservatively includes local returned-ok/error and recovery-unknown
    /// terminals because none proves receiver inactivity. Prepared-only traces are
    /// excluded. The value is a duration bound, not a remaining-lifetime or
    /// restart-readiness proof; a caller must establish an appropriate trusted
    /// time anchor and any receiver/plant-specific safety horizon separately.
    #[must_use]
    pub fn maximum_potentially_active_validity_ms(&self) -> Option<NonZeroU32> {
        self.reducer.maximum_potentially_active_validity_ms()
    }

    /// Number of authenticated recovered segments included in the rebuild.
    #[must_use]
    pub const fn replayed_segments(&self) -> usize {
        self.replayed_segments
    }

    /// Number of verifier-accepted records included in the rebuild pass,
    /// including valid DENY/ERROR receipts skipped by publication state.
    #[must_use]
    pub const fn replayed_records(&self) -> u64 {
        self.replayed_records
    }

    /// Whether any authenticated recovered segment used this Gate boot ID.
    ///
    /// This is a provenance query, not authority to select a current boot.
    #[must_use]
    pub fn contains_recovered_boot(&self, gate_boot_id: GateBootId) -> bool {
        self.recovered_boots.contains(&gate_boot_id)
    }

    /// Tail sequence included in the recovered snapshot, absent for a freshly
    /// provisioned empty journal.
    #[must_use]
    pub const fn last_recovered_segment_sequence(&self) -> Option<NonZeroU64> {
        self.last_recovered_segment_sequence
    }
}

impl VerifiedGateRecord {
    /// Borrow the verified typed value.
    #[must_use]
    pub const fn value(&self) -> VerifiedGateRecordRef<'_> {
        match &self.value {
            VerifiedGateValue::DecisionReceipt(receipt) => {
                VerifiedGateRecordRef::DecisionReceipt(receipt)
            }
            VerifiedGateValue::PublicationStage(event) => {
                VerifiedGateRecordRef::PublicationStage(event)
            }
        }
    }

    /// Domain-separated digest of the exact verified COSE envelope.
    #[must_use]
    pub const fn envelope_digest(&self) -> DigestV1 {
        self.envelope_digest
    }

    /// Trust-bound claimed containing segment sequence.
    #[must_use]
    pub const fn segment_sequence(&self) -> NonZeroU64 {
        self.segment_sequence
    }

    /// Trust-bound claimed containing segment's Gate boot.
    #[must_use]
    pub const fn segment_gate_boot_id(&self) -> GateBootId {
        self.segment_gate_boot_id
    }
}

/// Immutable assurance-profile verifier for the closed Gate publication journal.
///
/// Both segment footers and record envelopes must use the same unrevoked
/// assurance-class `GateApplication` key bound to the configured Gate subject.
/// The closed record vocabulary is `DecisionReceiptV1` plus
/// `PublicationStageEventV1`; other content types fail closed.
#[derive(Clone)]
pub struct GateJournalVerifier {
    gate_id: GateId,
    trust: TrustStore,
    revocations: RevocationSnapshot,
    max_envelope_bytes: NonZeroUsize,
    receipt_content_type: String,
    publication_content_type: String,
}

impl GateJournalVerifier {
    /// Bind an immutable trust/revocation snapshot and complete-envelope bound to
    /// one Gate.
    #[must_use]
    pub fn new(
        gate_id: GateId,
        trust: TrustStore,
        revocations: RevocationSnapshot,
        max_envelope_bytes: NonZeroUsize,
    ) -> Self {
        Self {
            gate_id,
            trust,
            revocations,
            max_envelope_bytes,
            receipt_content_type: content_type_for(DecisionReceiptV1::KIND),
            publication_content_type: content_type_for(PublicationStageEventV1::KIND),
        }
    }

    /// Configured Gate identity.
    #[must_use]
    pub const fn gate_id(&self) -> &GateId {
        &self.gate_id
    }

    /// Verify an authenticated segment identity against the pinned Gate trust
    /// and revocation snapshot.
    ///
    /// # Errors
    /// Returns on Gate, KID, key bytes, role, class, subject, or revocation drift.
    pub fn verify_segment_identity(
        &self,
        identity: &SegmentIdentity,
    ) -> Result<VerifyingKey, GateJournalVerificationError> {
        if identity.gate_id != self.gate_id {
            return Err(GateJournalVerificationError::SegmentGateMismatch);
        }
        let record = self
            .trust
            .resolve(&identity.signer_kid)
            .ok_or(GateJournalVerificationError::SegmentSignerUntrusted)?;
        if record.role != KeyRole::GateApplication
            || record.class != KeyClass::Assurance
            || record.subject.as_deref() != Some(self.gate_id.as_str())
            || record.verifying_key.to_bytes() != identity.signer_public_key
            || self.revocations.is_key_revoked(&identity.signer_kid)
        {
            return Err(GateJournalVerificationError::SegmentSignerUntrusted);
        }
        VerifyingKey::from_bytes(record.verifying_key.to_bytes())
            .map_err(|_| GateJournalVerificationError::SegmentSignerUntrusted)
    }

    /// Verify and canonically decode one record under a supplied, trust-bound
    /// segment identity. This method alone does not prove journal membership,
    /// footer validity, or chain order.
    ///
    /// Dispatch exact-matches the protected content type against a two-entry
    /// closed vocabulary before one role/revocation/signature verification. The
    /// payload never selects its own type.
    ///
    /// # Errors
    /// Returns on envelope bounds, segment trust, signature/type/canonical
    /// failure, signer drift, or Gate/boot substitution.
    pub fn verify_record(
        &self,
        identity: &SegmentIdentity,
        envelope: &[u8],
    ) -> Result<VerifiedGateRecord, GateJournalVerificationError> {
        if envelope.len() > self.max_envelope_bytes.get() {
            return Err(GateJournalVerificationError::EnvelopeTooLarge);
        }
        self.verify_segment_identity(identity)?;
        let (verified, kind) = verify_sign1_dispatched(
            envelope,
            &self.trust,
            &self.revocations,
            |protected_content_type| {
                if protected_content_type == self.receipt_content_type {
                    Some((
                        ExpectedContext {
                            kind: DecisionReceiptV1::KIND,
                            schema_major: 1,
                            required_role: KeyRole::GateApplication,
                            assurance_profile: true,
                        },
                        GateRecordKind::DecisionReceipt,
                    ))
                } else if protected_content_type == self.publication_content_type {
                    Some((
                        ExpectedContext {
                            kind: PublicationStageEventV1::KIND,
                            schema_major: 1,
                            required_role: KeyRole::GateApplication,
                            assurance_profile: true,
                        },
                        GateRecordKind::PublicationStage,
                    ))
                } else {
                    None
                }
            },
        )
        .map_err(|_| GateJournalVerificationError::InvalidEnvelope)?;
        if verified.signer_kid != identity.signer_kid {
            return Err(GateJournalVerificationError::RecordSignerMismatch);
        }
        if verified.signer_subject.as_deref() != Some(self.gate_id.as_str()) {
            return Err(GateJournalVerificationError::RecordSubjectMismatch);
        }

        let value = match kind {
            GateRecordKind::DecisionReceipt => {
                let receipt =
                    from_canonical_bytes::<DecisionReceiptV1>(verified.payload, Limits::DEFAULT)
                        .map_err(|_| GateJournalVerificationError::InvalidEnvelope)?;
                if receipt.gate_id != self.gate_id {
                    return Err(GateJournalVerificationError::RecordGateMismatch);
                }
                if receipt.gate_boot_id != identity.gate_boot_id {
                    return Err(GateJournalVerificationError::RecordBootMismatch);
                }
                validate_receipt_profile(&receipt)?;
                VerifiedGateValue::DecisionReceipt(Box::new(receipt))
            }
            GateRecordKind::PublicationStage => {
                let event = from_canonical_bytes::<PublicationStageEventV1>(
                    verified.payload,
                    Limits::DEFAULT,
                )
                .map_err(|_| GateJournalVerificationError::InvalidEnvelope)?;
                if event.gate_id != self.gate_id {
                    return Err(GateJournalVerificationError::RecordGateMismatch);
                }
                if event.producer_gate_boot_id != identity.gate_boot_id {
                    return Err(GateJournalVerificationError::RecordBootMismatch);
                }
                VerifiedGateValue::PublicationStage(Box::new(event))
            }
        };
        Ok(VerifiedGateRecord {
            value,
            envelope_digest: DigestV1::compute(DigestDomain::RawEnvelope, envelope),
            segment_sequence: identity.segment_sequence,
            segment_gate_boot_id: identity.gate_boot_id,
        })
    }

    /// Reverify a successful ordered recovery snapshot and build fresh
    /// publication state exactly once.
    ///
    /// Non-publication decision receipts are retained by the journal but skipped
    /// here. Any receipt claiming `OutputPrepared`/`AllowPrepared` is passed to the
    /// strict publication reducer, so contradictory prepared shapes fail closed.
    /// Segment boot runs must be contiguous; `A -> B -> A` is rejected.
    ///
    /// # Errors
    /// Returns on segment/record verification, boot resurrection or same-boot
    /// segment-time regression, malformed trace order/links, or reducer capacity.
    pub fn rebuild_publication_state(
        &self,
        recovery: JournalRecovery,
        max_traces: usize,
    ) -> Result<RecoveredPublicationState, PublicationRecoveryError> {
        self.rebuild_publication_state_ref(&recovery, max_traces)
    }

    fn rebuild_publication_state_ref(
        &self,
        recovery: &JournalRecovery,
        max_traces: usize,
    ) -> Result<RecoveredPublicationState, PublicationRecoveryError> {
        let replayed_segments = recovery.segments().len();
        let replayed_records = recovery.report().recovered_records;
        let last_recovered_segment_sequence = recovery
            .segments()
            .last()
            .map(|segment| segment.identity().segment_sequence);
        let mut reducer = PublicationStageReducer::new(max_traces)?;
        let mut seen_boots = BTreeSet::new();
        let mut active_boot: Option<GateBootId> = None;
        let mut last_segment_created = 0u64;
        let mut last_record_mono_ns: Option<u64> = None;
        let mut decision_receipts = BTreeSet::<(GateBootId, DecisionId)>::new();

        for segment in recovery.segments() {
            let identity = segment.identity();
            self.verify_segment_identity(identity)?;
            match active_boot {
                Some(boot_id) if boot_id == identity.gate_boot_id => {
                    if identity.created_mono_ns < last_segment_created
                        || last_record_mono_ns
                            .is_some_and(|last_record| identity.created_mono_ns < last_record)
                    {
                        return Err(PublicationRecoveryError::SegmentTimeRegression);
                    }
                }
                Some(_) | None => {
                    if !seen_boots.insert(identity.gate_boot_id) {
                        return Err(PublicationRecoveryError::BootResurrection);
                    }
                    last_record_mono_ns = None;
                }
            }
            active_boot = Some(identity.gate_boot_id);
            last_segment_created = identity.created_mono_ns;

            for envelope in segment.records() {
                let verified = self.verify_record(identity, envelope)?;
                let record_mono_ns = match verified.value() {
                    VerifiedGateRecordRef::DecisionReceipt(receipt) => receipt.decided_mono_ns,
                    VerifiedGateRecordRef::PublicationStage(event) => event.observed_mono_ns,
                };
                if last_record_mono_ns.is_some_and(|previous| record_mono_ns < previous) {
                    return Err(PublicationRecoveryError::RecordTimeRegression);
                }
                last_record_mono_ns = Some(record_mono_ns);
                match verified.value() {
                    VerifiedGateRecordRef::DecisionReceipt(receipt) => {
                        if !decision_receipts.insert((receipt.gate_boot_id, receipt.decision_id)) {
                            return Err(PublicationRecoveryError::DuplicateDecisionReceipt);
                        }
                        if receipt.decision == DecisionOutcomeV1::Allow {
                            reducer.register_prepared(receipt, envelope)?;
                        }
                    }
                    VerifiedGateRecordRef::PublicationStage(event) => {
                        reducer.apply_event(event, envelope)?;
                    }
                }
            }
        }
        Ok(RecoveredPublicationState {
            reducer,
            replayed_segments,
            replayed_records,
            recovered_boots: seen_boots,
            last_recovered_segment_sequence,
            decision_receipts,
            current_boot_record_high_water: None,
        })
    }
}

fn validate_receipt_profile(
    receipt: &DecisionReceiptV1,
) -> Result<(), GateJournalVerificationError> {
    if receipt.received_mono_ns > receipt.decided_mono_ns
        || receipt.reason_codes.as_slice().len() != 1
    {
        return Err(GateJournalVerificationError::ReceiptSemanticInvalid);
    }
    let reason = receipt
        .reason_codes
        .as_slice()
        .first()
        .copied()
        .ok_or(GateJournalVerificationError::ReceiptSemanticInvalid)?;
    let no_output = receipt.effective_validity_ms.is_none()
        && receipt.gate_output_stream.is_none()
        && receipt.output_frame_digest.is_none()
        && receipt.transformation_relation.is_none();
    let valid = match receipt.decision {
        DecisionOutcomeV1::Allow => {
            receipt.publish_stage == PublishStageV1::OutputPrepared
                && reason == DecisionReasonCodeV1::AllowPrepared
                && receipt.effective_validity_ms.is_some_and(|value| value > 0)
                && receipt.gate_output_stream.is_some()
                && receipt.output_frame_digest.is_some()
                && receipt.transformation_relation.is_some()
        }
        DecisionOutcomeV1::Deny => {
            receipt.publish_stage == PublishStageV1::DecidedDeny
                && reason.is_hard_deny()
                && !reason.is_error()
                && no_output
        }
        DecisionOutcomeV1::Error => {
            receipt.publish_stage == PublishStageV1::DecidedError && reason.is_error() && no_output
        }
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(GateJournalVerificationError::ReceiptSemanticInvalid)
    }
}

impl JournalVerifier for GateJournalVerifier {
    fn resolve_signer(
        &self,
        identity: &SegmentIdentity,
    ) -> Result<VerifyingKey, JournalVerificationError> {
        self.verify_segment_identity(identity)
            .map_err(|_| JournalVerificationError::UnknownSigner)
    }

    fn validate_record(
        &self,
        identity: &SegmentIdentity,
        record: &[u8],
    ) -> Result<(), JournalVerificationError> {
        self.verify_record(identity, record)
            .map(|_| ())
            .map_err(|_| JournalVerificationError::InvalidRecord)
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::journal::{JournalBounds, JournalError};
    use crate::manager::{
        EvidenceJournalManager, JournalLimits, JournalManagerError, JournalOpenOptions,
        JournalSigner, RecoveryCaptureLimits,
    };
    use crate::publication::PublicationTraceState;
    use core::num::{NonZeroU32, NonZeroU64};
    use haldir_contracts::digest::{DigestDomain, DigestV1};
    use haldir_contracts::ids::{DecisionId, GateOutputEpoch, KeyId, OutputSeq, VehicleId};
    use haldir_contracts::receipt::TransformationRelationV1;
    use haldir_contracts::scalar::{AsciiId, BoundedVec, CanonicalUuidV4String};
    use haldir_contracts::session::{NcpSessionIdentityV1, NcpStreamPositionV1};
    use haldir_crypto::{KeyRecord, SigningKey, sign_message};
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::LazyLock;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "haldir-gate-journal-test-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn journal(&self) -> PathBuf {
            self.0.join("journal")
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn gate() -> GateId {
        GateId::new("gate-1").unwrap()
    }

    fn kid(seed: u8) -> KeyId {
        KeyId::new(vec![seed, 0xaa, seed]).unwrap()
    }

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_seed([seed; 32])
    }

    static TEST_SIGNER: LazyLock<(KeyId, SigningKey)> = LazyLock::new(|| (kid(3), key(3)));

    fn journal_signer() -> JournalSigner<'static> {
        JournalSigner::new(&TEST_SIGNER.0, &TEST_SIGNER.1)
    }

    fn trust_with_gate_keys(seeds: &[u8]) -> TrustStore {
        let mut trust = TrustStore::new();
        for seed in seeds {
            trust
                .insert(KeyRecord {
                    kid: kid(*seed),
                    role: KeyRole::GateApplication,
                    verifying_key: key(*seed).verifying_key(),
                    subject: Some(gate().as_str().to_owned()),
                    class: KeyClass::Assurance,
                })
                .unwrap();
        }
        trust
    }

    fn verifier() -> GateJournalVerifier {
        GateJournalVerifier::new(
            gate(),
            trust_with_gate_keys(&[3]),
            RevocationSnapshot::new(),
            NonZeroUsize::new(32 * 1024).unwrap(),
        )
    }

    fn limits(max_records: u64) -> JournalLimits {
        JournalLimits::new(
            JournalBounds::new(128 * 1024, max_records, 32 * 1024).unwrap(),
            16,
            2 * 1024 * 1024,
        )
        .unwrap()
    }

    fn options(boot: u8, created_mono_ns: u64, limits: JournalLimits) -> JournalOpenOptions {
        JournalOpenOptions::new(gate(), GateBootId::new([boot; 16]), created_mono_ns, limits)
    }

    fn session() -> NcpSessionIdentityV1 {
        NcpSessionIdentityV1 {
            session_id: AsciiId::new("sess-1").unwrap(),
            generation: CanonicalUuidV4String::from_random_bytes([4; 16]),
        }
    }

    fn output() -> NcpStreamPositionV1 {
        NcpStreamPositionV1 {
            epoch: GateOutputEpoch::new(CanonicalUuidV4String::from_random_bytes([5; 16])),
            seq: OutputSeq::new(NonZeroU64::new(1).unwrap()),
        }
    }

    fn deny_receipt(decision: u8, boot: u8, decided_mono_ns: u64) -> DecisionReceiptV1 {
        DecisionReceiptV1 {
            decision_id: DecisionId::new([decision; 16]),
            gate_id: gate(),
            gate_boot_id: GateBootId::new([boot; 16]),
            vehicle_id: VehicleId::new("uav-1").unwrap(),
            mission_id: None,
            ncp_session: session(),
            received_key_digest: DigestV1::compute(DigestDomain::Payload, b"key"),
            raw_envelope_digest: DigestV1::compute(DigestDomain::RawEnvelope, b"intent"),
            payload_digest: None,
            semantic_intent_digest: None,
            controller_id: None,
            controller_intent_position: None,
            mission_lease_id: None,
            admission_digest: None,
            source: None,
            state_snapshot_digest: None,
            policy_snapshot_digest: DigestV1::compute(DigestDomain::PolicySnapshot, b"policy"),
            decision: DecisionOutcomeV1::Deny,
            reason_codes: BoundedVec::from_vec(vec![DecisionReasonCodeV1::DenyMalformed]).unwrap(),
            effective_validity_ms: None,
            gate_output_stream: None,
            output_frame_digest: None,
            transformation_relation: None,
            received_mono_ns: decided_mono_ns.saturating_sub(1),
            decided_mono_ns,
            publish_stage: PublishStageV1::DecidedDeny,
        }
    }

    fn prepared_receipt(decision: u8, boot: u8, decided_mono_ns: u64) -> DecisionReceiptV1 {
        let mut receipt = deny_receipt(decision, boot, decided_mono_ns);
        receipt.decision = DecisionOutcomeV1::Allow;
        receipt.reason_codes =
            BoundedVec::from_vec(vec![DecisionReasonCodeV1::AllowPrepared]).unwrap();
        receipt.effective_validity_ms = Some(10);
        receipt.gate_output_stream = Some(output());
        receipt.output_frame_digest = Some(DigestV1::compute(DigestDomain::OutputFrame, b"frame"));
        receipt.transformation_relation = Some(TransformationRelationV1::FixedPointToNcpFloatV1);
        receipt.publish_stage = PublishStageV1::OutputPrepared;
        receipt
    }

    fn stage_event(
        receipt: &DecisionReceiptV1,
        producer_boot: u8,
        stage: PublishStageV1,
        prepared_digest: DigestV1,
        predecessor: DigestV1,
        observed_mono_ns: u64,
    ) -> PublicationStageEventV1 {
        PublicationStageEventV1 {
            schema_major: 1,
            schema_minor: 0,
            decision_id: receipt.decision_id,
            gate_id: receipt.gate_id.clone(),
            decision_gate_boot_id: receipt.gate_boot_id,
            producer_gate_boot_id: GateBootId::new([producer_boot; 16]),
            vehicle_id: receipt.vehicle_id.clone(),
            ncp_session: receipt.ncp_session.clone(),
            gate_output_stream: receipt.gate_output_stream.clone().unwrap(),
            output_frame_digest: receipt.output_frame_digest.unwrap(),
            effective_validity_ms: NonZeroU32::new(receipt.effective_validity_ms.unwrap()).unwrap(),
            prepared_receipt_envelope_digest: prepared_digest,
            predecessor_envelope_digest: predecessor,
            stage,
            observed_mono_ns,
        }
    }

    fn sign_receipt(receipt: &DecisionReceiptV1, seed: u8) -> Vec<u8> {
        sign_message(receipt, DecisionReceiptV1::KIND, 1, &kid(seed), &key(seed))
    }

    fn sign_stage(event: &PublicationStageEventV1, seed: u8) -> Vec<u8> {
        sign_message(
            event,
            PublicationStageEventV1::KIND,
            1,
            &kid(seed),
            &key(seed),
        )
    }

    fn open_capture(
        path: &Path,
        boot: u8,
        created: u64,
        journal_limits: JournalLimits,
    ) -> (EvidenceJournalManager<GateJournalVerifier>, JournalRecovery) {
        EvidenceJournalManager::open_existing_with_recovered_records(
            path,
            options(boot, created, journal_limits),
            &journal_signer(),
            Some(&journal_signer()),
            RecoveryCaptureLimits::new(128, 512 * 1024),
            verifier(),
        )
        .unwrap()
    }

    #[test]
    fn mixed_receipts_and_linear_trace_rebuild_fresh_state() {
        let directory = TestDirectory::new();
        let journal = directory.journal();
        let journal_limits = limits(16);
        let (mut manager, _) = EvidenceJournalManager::provision_new(
            &journal,
            options(1, 10, journal_limits),
            &journal_signer(),
            verifier(),
        )
        .unwrap();

        let deny = sign_receipt(&deny_receipt(9, 1, 11), 3);
        let prepared = prepared_receipt(1, 1, 12);
        let prepared_env = sign_receipt(&prepared, 3);
        let prepared_digest = DigestV1::compute(DigestDomain::RawEnvelope, &prepared_env);
        let called = stage_event(
            &prepared,
            1,
            PublishStageV1::PublishCalled,
            prepared_digest,
            prepared_digest,
            13,
        );
        let called_env = sign_stage(&called, 3);
        let returned = stage_event(
            &prepared,
            1,
            PublishStageV1::PublishReturnedOk,
            prepared_digest,
            DigestV1::compute(DigestDomain::RawEnvelope, &called_env),
            14,
        );
        let returned_env = sign_stage(&returned, 3);
        for envelope in [&deny, &prepared_env, &called_env, &returned_env] {
            manager.append(envelope, 10, &journal_signer()).unwrap();
        }
        drop(manager);

        let (reopened, recovery) = open_capture(&journal, 2, 1, journal_limits);
        let reducer = verifier().rebuild_publication_state(recovery, 4).unwrap();
        assert_eq!(
            reducer.state(GateBootId::new([1; 16]), prepared.decision_id),
            Some(PublicationTraceState::PublishReturnedOk)
        );
        assert_eq!(
            reducer.state(GateBootId::new([1; 16]), DecisionId::new([9; 16])),
            None
        );
        assert_eq!(reducer.replayed_segments(), 1);
        assert_eq!(reducer.replayed_records(), 4);
        assert_eq!(
            reducer.maximum_potentially_active_validity_ms(),
            NonZeroU32::new(10)
        );
        assert!(reducer.contains_recovered_boot(GateBootId::new([1; 16])));
        assert_eq!(
            reducer
                .last_recovered_segment_sequence()
                .map(NonZeroU64::get),
            Some(1)
        );
        assert_eq!(reopened.active_sequence().map(NonZeroU64::get), Some(2));
    }

    #[test]
    fn later_boot_unknown_replays_only_after_linked_called_tail() {
        let directory = TestDirectory::new();
        let journal = directory.journal();
        let journal_limits = limits(16);
        let prepared = prepared_receipt(1, 1, 11);
        let prepared_env = sign_receipt(&prepared, 3);
        let prepared_digest = DigestV1::compute(DigestDomain::RawEnvelope, &prepared_env);
        let called = stage_event(
            &prepared,
            1,
            PublishStageV1::PublishCalled,
            prepared_digest,
            prepared_digest,
            12,
        );
        let called_env = sign_stage(&called, 3);

        let (mut first, _) = EvidenceJournalManager::provision_new(
            &journal,
            options(1, 10, journal_limits),
            &journal_signer(),
            verifier(),
        )
        .unwrap();
        first.append(&prepared_env, 10, &journal_signer()).unwrap();
        first.append(&called_env, 10, &journal_signer()).unwrap();
        drop(first.finish(&journal_signer()).unwrap());

        let (mut second, _) = EvidenceJournalManager::open_existing(
            &journal,
            options(2, 1, journal_limits),
            &journal_signer(),
            None,
            verifier(),
        )
        .unwrap();
        let unknown = stage_event(
            &prepared,
            2,
            PublishStageV1::UnknownAfterPublish,
            prepared_digest,
            DigestV1::compute(DigestDomain::RawEnvelope, &called_env),
            2,
        );
        second
            .append(&sign_stage(&unknown, 3), 1, &journal_signer())
            .unwrap();
        drop(second.finish(&journal_signer()).unwrap());

        let (_, recovery) = open_capture(&journal, 3, 1, journal_limits);
        let reducer = verifier().rebuild_publication_state(recovery, 4).unwrap();
        assert_eq!(
            reducer.state(GateBootId::new([1; 16]), prepared.decision_id),
            Some(PublicationTraceState::UnknownAfterPublish)
        );
    }

    #[test]
    fn record_dispatch_signer_gate_boot_bounds_and_receipt_profile_fail_closed() {
        let trust = trust_with_gate_keys(&[3, 4]);
        let verifier = GateJournalVerifier::new(
            gate(),
            trust,
            RevocationSnapshot::new(),
            NonZeroUsize::new(32 * 1024).unwrap(),
        );
        let identity = SegmentIdentity {
            gate_id: gate(),
            gate_boot_id: GateBootId::new([1; 16]),
            segment_sequence: NonZeroU64::new(1).unwrap(),
            previous_completed_digest: [0; 32],
            created_mono_ns: 10,
            signer_kid: kid(3),
            signer_public_key: key(3).verifying_key().to_bytes(),
        };
        let prepared = prepared_receipt(1, 1, 11);
        assert_eq!(
            verifier
                .verify_record(&identity, &sign_receipt(&prepared, 4))
                .err(),
            Some(GateJournalVerificationError::RecordSignerMismatch)
        );

        let mut wrong_gate = prepared.clone();
        wrong_gate.gate_id = GateId::new("gate-2").unwrap();
        assert_eq!(
            verifier
                .verify_record(&identity, &sign_receipt(&wrong_gate, 3))
                .err(),
            Some(GateJournalVerificationError::RecordGateMismatch)
        );
        let mut wrong_boot = prepared.clone();
        wrong_boot.gate_boot_id = GateBootId::new([2; 16]);
        assert_eq!(
            verifier
                .verify_record(&identity, &sign_receipt(&wrong_boot, 3))
                .err(),
            Some(GateJournalVerificationError::RecordBootMismatch)
        );
        let unknown_kind = sign_message(&prepared, "haldir.unknown", 1, &kid(3), &key(3));
        assert_eq!(
            verifier.verify_record(&identity, &unknown_kind).err(),
            Some(GateJournalVerificationError::InvalidEnvelope)
        );
        let cross_kind = sign_message(
            &prepared,
            PublicationStageEventV1::KIND,
            1,
            &kid(3),
            &key(3),
        );
        assert_eq!(
            verifier.verify_record(&identity, &cross_kind).err(),
            Some(GateJournalVerificationError::InvalidEnvelope)
        );

        let prepared_env = sign_receipt(&prepared, 3);
        let prepared_digest = DigestV1::compute(DigestDomain::RawEnvelope, &prepared_env);
        let wrong_producer = stage_event(
            &prepared,
            2,
            PublishStageV1::UnknownAfterPublish,
            prepared_digest,
            prepared_digest,
            12,
        );
        assert_eq!(
            verifier
                .verify_record(&identity, &sign_stage(&wrong_producer, 3))
                .err(),
            Some(GateJournalVerificationError::RecordBootMismatch)
        );

        let bounded = GateJournalVerifier::new(
            gate(),
            trust_with_gate_keys(&[3]),
            RevocationSnapshot::new(),
            NonZeroUsize::new(sign_receipt(&prepared, 3).len() - 1).unwrap(),
        );
        assert_eq!(
            bounded
                .verify_record(&identity, &sign_receipt(&prepared, 3))
                .err(),
            Some(GateJournalVerificationError::EnvelopeTooLarge)
        );

        let mut malformed_receipts = Vec::new();
        let mut malformed = prepared.clone();
        malformed.effective_validity_ms = None;
        malformed_receipts.push(malformed);
        let mut malformed = prepared.clone();
        malformed.received_mono_ns = malformed.decided_mono_ns + 1;
        malformed_receipts.push(malformed);
        let mut malformed = prepared.clone();
        malformed.reason_codes = BoundedVec::new();
        malformed_receipts.push(malformed);
        let mut malformed = prepared.clone();
        malformed.reason_codes = BoundedVec::from_vec(vec![
            DecisionReasonCodeV1::AllowPrepared,
            DecisionReasonCodeV1::AllowPolicy,
        ])
        .unwrap();
        malformed_receipts.push(malformed);
        let mut malformed = prepared.clone();
        malformed.publish_stage = PublishStageV1::DecidedAllow;
        malformed_receipts.push(malformed);
        let mut malformed = prepared.clone();
        malformed.gate_output_stream = None;
        malformed_receipts.push(malformed);
        let mut malformed = prepared.clone();
        malformed.output_frame_digest = None;
        malformed_receipts.push(malformed);
        let mut malformed = prepared;
        malformed.transformation_relation = None;
        malformed_receipts.push(malformed);
        let mut malformed = deny_receipt(2, 1, 12);
        malformed.reason_codes =
            BoundedVec::from_vec(vec![DecisionReasonCodeV1::ErrorInternalFault]).unwrap();
        malformed_receipts.push(malformed);
        let mut malformed = deny_receipt(3, 1, 12);
        malformed.effective_validity_ms = Some(1);
        malformed_receipts.push(malformed);
        let mut malformed = deny_receipt(4, 1, 12);
        malformed.decision = DecisionOutcomeV1::Error;
        malformed.publish_stage = PublishStageV1::DecidedError;
        malformed_receipts.push(malformed);
        let mut malformed = deny_receipt(5, 1, 12);
        malformed.decision = DecisionOutcomeV1::Error;
        malformed.reason_codes =
            BoundedVec::from_vec(vec![DecisionReasonCodeV1::ErrorInternalFault]).unwrap();
        malformed_receipts.push(malformed);

        for malformed in malformed_receipts {
            assert_eq!(
                verifier
                    .verify_record(&identity, &sign_receipt(&malformed, 3))
                    .err(),
                Some(GateJournalVerificationError::ReceiptSemanticInvalid)
            );
        }
    }

    #[test]
    fn replay_rejects_boot_resurrection_across_empty_segments() {
        let directory = TestDirectory::new();
        let journal = directory.journal();
        let journal_limits = limits(4);
        let (first, _) = EvidenceJournalManager::provision_new(
            &journal,
            options(1, 10, journal_limits),
            &journal_signer(),
            verifier(),
        )
        .unwrap();
        drop(first.finish(&journal_signer()).unwrap());
        let (second, _) = EvidenceJournalManager::open_existing(
            &journal,
            options(2, 1, journal_limits),
            &journal_signer(),
            None,
            verifier(),
        )
        .unwrap();
        drop(second.finish(&journal_signer()).unwrap());
        let (third, _) = EvidenceJournalManager::open_existing(
            &journal,
            options(1, 20, journal_limits),
            &journal_signer(),
            None,
            verifier(),
        )
        .unwrap();
        drop(third.finish(&journal_signer()).unwrap());

        let (_, recovery) = open_capture(&journal, 3, 1, journal_limits);
        assert!(matches!(
            verifier().rebuild_publication_state(recovery, 1),
            Err(PublicationRecoveryError::BootResurrection)
        ));
    }

    #[test]
    fn late_reducer_failure_and_duplicate_receipt_return_no_state() {
        let trace_directory = TestDirectory::new();
        let trace_journal = trace_directory.journal();
        let journal_limits = limits(8);
        let prepared = prepared_receipt(1, 1, 11);
        let prepared_env = sign_receipt(&prepared, 3);
        let wrong_digest = DigestV1::compute(DigestDomain::RawEnvelope, b"wrong-prepared");
        let bad_called = stage_event(
            &prepared,
            1,
            PublishStageV1::PublishCalled,
            wrong_digest,
            wrong_digest,
            12,
        );
        let (mut manager, _) = EvidenceJournalManager::provision_new(
            &trace_journal,
            options(1, 10, journal_limits),
            &journal_signer(),
            verifier(),
        )
        .unwrap();
        manager
            .append(&prepared_env, 10, &journal_signer())
            .unwrap();
        manager
            .append(&sign_stage(&bad_called, 3), 10, &journal_signer())
            .unwrap();
        drop(manager.finish(&journal_signer()).unwrap());
        let (_, recovery) = open_capture(&trace_journal, 2, 1, journal_limits);
        assert!(matches!(
            verifier().rebuild_publication_state(recovery, 4),
            Err(PublicationRecoveryError::Reduction(
                PublicationReductionError::IdentityMismatch
            ))
        ));

        let duplicate_directory = TestDirectory::new();
        let duplicate_journal = duplicate_directory.journal();
        let mut first = deny_receipt(7, 1, 11);
        let mut second = first.clone();
        first.raw_envelope_digest = DigestV1::compute(DigestDomain::RawEnvelope, b"intent-1");
        second.raw_envelope_digest = DigestV1::compute(DigestDomain::RawEnvelope, b"intent-2");
        second.decided_mono_ns = 12;
        let (mut manager, _) = EvidenceJournalManager::provision_new(
            &duplicate_journal,
            options(1, 10, journal_limits),
            &journal_signer(),
            verifier(),
        )
        .unwrap();
        manager
            .append(&sign_receipt(&first, 3), 10, &journal_signer())
            .unwrap();
        manager
            .append(&sign_receipt(&second, 3), 10, &journal_signer())
            .unwrap();
        drop(manager.finish(&journal_signer()).unwrap());
        let (_, recovery) = open_capture(&duplicate_journal, 2, 1, journal_limits);
        assert!(matches!(
            verifier().rebuild_publication_state(recovery, 4),
            Err(PublicationRecoveryError::DuplicateDecisionReceipt)
        ));
    }

    #[test]
    fn fused_replay_failure_does_not_close_tail_or_burn_current_segment() {
        let directory = TestDirectory::new();
        let journal = directory.journal();
        let journal_limits = limits(16);
        let prepared = prepared_receipt(1, 1, 11);
        let prepared_env = sign_receipt(&prepared, 3);
        let wrong_digest = DigestV1::compute(DigestDomain::RawEnvelope, b"wrong-prepared");
        let bad_called = stage_event(
            &prepared,
            1,
            PublishStageV1::PublishCalled,
            wrong_digest,
            wrong_digest,
            12,
        );
        let (mut manager, _) = EvidenceJournalManager::provision_new(
            &journal,
            options(1, 10, journal_limits),
            &journal_signer(),
            verifier(),
        )
        .unwrap();
        manager
            .append(&prepared_env, 10, &journal_signer())
            .unwrap();
        manager
            .append(&sign_stage(&bad_called, 3), 10, &journal_signer())
            .unwrap();
        drop(manager);
        let first_path = journal.join("segment-00000000000000000001");
        let second_path = journal.join("segment-00000000000000000002");
        let bytes_before = fs::metadata(&first_path).unwrap().len();

        for _ in 0..2 {
            let error = RecoveredGateJournal::open_existing(
                &journal,
                options(2, 1, journal_limits),
                &journal_signer(),
                Some(&journal_signer()),
                RecoveryCaptureLimits::new(8, 64 * 1024),
                verifier(),
                NonZeroUsize::new(8).unwrap(),
            )
            .err()
            .unwrap();
            assert!(matches!(
                error,
                GateJournalOpenError::Replay {
                    error: PublicationRecoveryError::Reduction(
                        PublicationReductionError::IdentityMismatch
                    ),
                    recovery: JournalRecoveryReport {
                        closed_active_tail: false,
                        active_sequence: None,
                        ..
                    }
                }
            ));
            assert_eq!(fs::metadata(&first_path).unwrap().len(), bytes_before);
            assert!(!second_path.exists());
        }
    }

    #[test]
    fn fused_trace_capacity_is_checked_before_directory_access() {
        let directory = TestDirectory::new();
        let journal = directory.0.join("absent-journal");

        assert!(matches!(
            RecoveredGateJournal::provision_new(
                &journal,
                options(1, 10, limits(16)),
                &journal_signer(),
                RecoveryCaptureLimits::new(8, 64 * 1024),
                verifier(),
                NonZeroUsize::new(7).unwrap(),
            ),
            Err(GateJournalOpenError::TraceCapacityTooSmall)
        ));
        assert!(!journal.exists());
    }

    #[test]
    fn foreign_gate_reservation_release_preserves_the_issuer_token() {
        let first_directory = TestDirectory::new();
        let second_directory = TestDirectory::new();
        let mut first = RecoveredGateJournal::provision_new(
            first_directory.journal(),
            options(1, 10, limits(16)),
            &journal_signer(),
            RecoveryCaptureLimits::new(8, 64 * 1024),
            verifier(),
            NonZeroUsize::new(8).unwrap(),
        )
        .unwrap();
        let mut second = RecoveredGateJournal::provision_new(
            second_directory.journal(),
            options(1, 10, limits(16)),
            &journal_signer(),
            RecoveryCaptureLimits::new(8, 64 * 1024),
            verifier(),
            NonZeroUsize::new(8).unwrap(),
        )
        .unwrap();
        let mut reservation = first.reserve_append_capacity(1).unwrap();

        assert_eq!(
            second.release_reservation(&mut reservation),
            Err(GateJournalMutationError::Journal(
                JournalManagerError::ReservationMismatch
            ))
        );
        first.release_reservation(&mut reservation).unwrap();
    }

    #[test]
    fn reserved_append_rejects_segment_creation_time_regression_without_consumption() {
        let directory = TestDirectory::new();
        let journal_path = directory.journal();
        let mut journal = RecoveredGateJournal::provision_new(
            &journal_path,
            options(1, 100, limits(1)),
            &journal_signer(),
            RecoveryCaptureLimits::new(8, 64 * 1024),
            verifier(),
            NonZeroUsize::new(8).unwrap(),
        )
        .unwrap();
        let envelope = sign_receipt(&deny_receipt(1, 1, 100), 3);
        let mut reservation = journal.reserve_append_capacity(1).unwrap();
        let active_path = journal_path.join("segment-00000000000000000001");
        let bytes_before = fs::metadata(&active_path).unwrap().len();

        assert_eq!(
            journal.append_reserved_verified(&mut reservation, &envelope, 99, &journal_signer(),),
            Err(GateJournalMutationError::Semantic(
                PublicationRecoveryError::SegmentTimeRegression
            ))
        );
        assert_eq!(fs::metadata(&active_path).unwrap().len(), bytes_before);
        journal
            .append_reserved_verified(&mut reservation, &envelope, 100, &journal_signer())
            .unwrap();
    }

    #[test]
    fn exhausted_gate_reservation_reports_exhaustion_without_mutation() {
        let directory = TestDirectory::new();
        let journal_path = directory.journal();
        let mut journal = RecoveredGateJournal::provision_new(
            &journal_path,
            options(1, 10, limits(16)),
            &journal_signer(),
            RecoveryCaptureLimits::new(8, 64 * 1024),
            verifier(),
            NonZeroUsize::new(8).unwrap(),
        )
        .unwrap();
        let first = sign_receipt(&deny_receipt(1, 1, 10), 3);
        let second = sign_receipt(&deny_receipt(2, 1, 11), 3);
        let mut reservation = journal.reserve_append_capacity(1).unwrap();
        journal
            .append_reserved_verified(&mut reservation, &first, 10, &journal_signer())
            .unwrap();
        let active_path = journal_path.join("segment-00000000000000000001");
        let bytes_before = fs::metadata(&active_path).unwrap().len();

        assert_eq!(
            journal.append_reserved_verified(&mut reservation, &second, 11, &journal_signer()),
            Err(GateJournalMutationError::Journal(
                JournalManagerError::ReservationExhausted
            ))
        );
        assert_eq!(fs::metadata(&active_path).unwrap().len(), bytes_before);
    }

    #[test]
    fn fused_recovery_appends_one_current_boot_unknown_then_replays_terminal() {
        let directory = TestDirectory::new();
        let journal = directory.journal();
        let journal_limits = limits(16);
        let prepared = prepared_receipt(1, 1, 11);
        let prepared_env = sign_receipt(&prepared, 3);
        let prepared_digest = DigestV1::compute(DigestDomain::RawEnvelope, &prepared_env);
        let called = stage_event(
            &prepared,
            1,
            PublishStageV1::PublishCalled,
            prepared_digest,
            prepared_digest,
            12,
        );
        let called_env = sign_stage(&called, 3);
        let (mut first, _) = EvidenceJournalManager::provision_new(
            &journal,
            options(1, 10, journal_limits),
            &journal_signer(),
            verifier(),
        )
        .unwrap();
        first.append(&prepared_env, 11, &journal_signer()).unwrap();
        first.append(&called_env, 12, &journal_signer()).unwrap();
        drop(first);

        let recovered = RecoveredGateJournal::open_existing(
            &journal,
            options(2, 20, journal_limits),
            &journal_signer(),
            Some(&journal_signer()),
            RecoveryCaptureLimits::new(8, 64 * 1024),
            verifier(),
            NonZeroUsize::new(8).unwrap(),
        )
        .unwrap();
        let (recovered, appended) = recovered
            .append_recovery_unknowns(20, &journal_signer())
            .unwrap();
        assert_eq!(appended, 1);
        assert_eq!(
            recovered
                .publication()
                .state(GateBootId::new([1; 16]), prepared.decision_id),
            Some(PublicationTraceState::UnknownAfterPublish)
        );
        assert_eq!(
            recovered
                .publication()
                .maximum_potentially_active_validity_ms(),
            NonZeroU32::new(10)
        );
        drop(recovered);

        let reopened = RecoveredGateJournal::open_existing(
            &journal,
            options(3, 30, journal_limits),
            &journal_signer(),
            Some(&journal_signer()),
            RecoveryCaptureLimits::new(8, 64 * 1024),
            verifier(),
            NonZeroUsize::new(8).unwrap(),
        )
        .unwrap();
        assert_eq!(
            reopened
                .publication()
                .state(GateBootId::new([1; 16]), prepared.decision_id),
            Some(PublicationTraceState::UnknownAfterPublish)
        );
        let (_, appended) = reopened
            .append_recovery_unknowns(30, &journal_signer())
            .unwrap();
        assert_eq!(appended, 0);
    }

    #[test]
    fn raw_recovery_unknown_rejects_current_boot_seen_in_empty_recovered_segment() {
        let directory = TestDirectory::new();
        let journal = directory.journal();
        let journal_limits = limits(16);
        let prepared = prepared_receipt(1, 1, 11);
        let prepared_env = sign_receipt(&prepared, 3);
        let prepared_digest = DigestV1::compute(DigestDomain::RawEnvelope, &prepared_env);
        let called = stage_event(
            &prepared,
            1,
            PublishStageV1::PublishCalled,
            prepared_digest,
            prepared_digest,
            12,
        );
        let (mut first, _) = EvidenceJournalManager::provision_new(
            &journal,
            options(1, 10, journal_limits),
            &journal_signer(),
            verifier(),
        )
        .unwrap();
        first.append(&prepared_env, 11, &journal_signer()).unwrap();
        first
            .append(&sign_stage(&called, 3), 12, &journal_signer())
            .unwrap();
        drop(first);

        let (empty_second, _) = EvidenceJournalManager::open_existing(
            &journal,
            options(2, 20, journal_limits),
            &journal_signer(),
            Some(&journal_signer()),
            verifier(),
        )
        .unwrap();
        drop(empty_second);
        let recovered = RecoveredGateJournal::open_existing(
            &journal,
            options(2, 30, journal_limits),
            &journal_signer(),
            Some(&journal_signer()),
            RecoveryCaptureLimits::new(8, 64 * 1024),
            verifier(),
            NonZeroUsize::new(8).unwrap(),
        )
        .unwrap();
        let current_path = journal.join("segment-00000000000000000003");
        let bytes_before = fs::metadata(&current_path).unwrap().len();

        assert!(matches!(
            recovered.append_recovery_unknowns(30, &journal_signer()),
            Err(GateJournalMutationError::Semantic(
                PublicationRecoveryError::Reduction(
                    PublicationReductionError::RecoveryBootAlreadyObserved
                )
            ))
        ));
        assert_eq!(fs::metadata(current_path).unwrap().len(), bytes_before);
    }

    #[test]
    fn precommit_closes_multiple_dangling_calls_and_reports_rotated_tail() {
        let directory = TestDirectory::new();
        let journal = directory.journal();
        let one_record_limits = limits(1);
        let first = prepared_receipt(1, 1, 11);
        let second = prepared_receipt(2, 1, 13);
        let first_envelope = sign_receipt(&first, 3);
        let second_envelope = sign_receipt(&second, 3);
        let first_digest = DigestV1::compute(DigestDomain::RawEnvelope, &first_envelope);
        let second_digest = DigestV1::compute(DigestDomain::RawEnvelope, &second_envelope);
        let first_called = sign_stage(
            &stage_event(
                &first,
                1,
                PublishStageV1::PublishCalled,
                first_digest,
                first_digest,
                12,
            ),
            3,
        );
        let second_called = sign_stage(
            &stage_event(
                &second,
                1,
                PublishStageV1::PublishCalled,
                second_digest,
                second_digest,
                14,
            ),
            3,
        );
        let (mut manager, _) = EvidenceJournalManager::provision_new(
            &journal,
            options(1, 10, one_record_limits),
            &journal_signer(),
            verifier(),
        )
        .unwrap();
        for (record, created) in [
            (&first_envelope, 11),
            (&first_called, 12),
            (&second_envelope, 13),
            (&second_called, 14),
        ] {
            manager.append(record, created, &journal_signer()).unwrap();
        }
        drop(manager);

        let (recovered, appended) = RecoveredGateJournal::open_existing_with_recovery_unknowns(
            &journal,
            options(2, 20, one_record_limits),
            &journal_signer(),
            Some(&journal_signer()),
            RecoveryCaptureLimits::new(8, 128 * 1024),
            verifier(),
            NonZeroUsize::new(8).unwrap(),
        )
        .unwrap();

        assert_eq!(appended, 2);
        assert_eq!(
            recovered
                .publication()
                .state(first.gate_boot_id, first.decision_id),
            Some(PublicationTraceState::UnknownAfterPublish)
        );
        assert_eq!(
            recovered
                .publication()
                .state(second.gate_boot_id, second.decision_id),
            Some(PublicationTraceState::UnknownAfterPublish)
        );
        assert_eq!(
            recovered
                .recovery_report()
                .active_sequence
                .map(NonZeroU64::get),
            Some(6)
        );
        assert_eq!(recovered.recovery_report().completed_segments, 5);
    }

    #[test]
    fn recovery_unknown_respects_next_open_capture_budget_before_append() {
        let directory = TestDirectory::new();
        let journal = directory.journal();
        let journal_limits = limits(16);
        let prepared = prepared_receipt(1, 1, 11);
        let prepared_env = sign_receipt(&prepared, 3);
        let prepared_digest = DigestV1::compute(DigestDomain::RawEnvelope, &prepared_env);
        let called = stage_event(
            &prepared,
            1,
            PublishStageV1::PublishCalled,
            prepared_digest,
            prepared_digest,
            12,
        );
        let (mut first, _) = EvidenceJournalManager::provision_new(
            &journal,
            options(1, 10, journal_limits),
            &journal_signer(),
            verifier(),
        )
        .unwrap();
        first.append(&prepared_env, 11, &journal_signer()).unwrap();
        first
            .append(&sign_stage(&called, 3), 12, &journal_signer())
            .unwrap();
        drop(first);

        let recovered = RecoveredGateJournal::open_existing(
            &journal,
            options(2, 20, journal_limits),
            &journal_signer(),
            Some(&journal_signer()),
            RecoveryCaptureLimits::new(2, 64 * 1024),
            verifier(),
            NonZeroUsize::new(2).unwrap(),
        )
        .unwrap();
        let current_path = journal.join("segment-00000000000000000002");
        let before = fs::metadata(&current_path).unwrap().len();
        assert!(matches!(
            recovered.append_recovery_unknowns(20, &journal_signer()),
            Err(GateJournalMutationError::Journal(
                JournalManagerError::RecoveryCaptureLimitExceeded {
                    dimension: RecoveryCaptureDimension::RecordCount,
                    maximum: 2,
                    required: 3,
                }
            ))
        ));
        assert_eq!(fs::metadata(current_path).unwrap().len(), before);
    }

    #[test]
    fn precommit_unknown_capacity_failure_never_closes_tail_or_burns_successor() {
        let directory = TestDirectory::new();
        let journal = directory.journal();
        let constrained_limits = JournalLimits::new(
            JournalBounds::new(128 * 1024, 16, 32 * 1024).unwrap(),
            2,
            2 * 1024 * 1024,
        )
        .unwrap();
        let prepared = prepared_receipt(1, 1, 11);
        let prepared_env = sign_receipt(&prepared, 3);
        let prepared_digest = DigestV1::compute(DigestDomain::RawEnvelope, &prepared_env);
        let called = stage_event(
            &prepared,
            1,
            PublishStageV1::PublishCalled,
            prepared_digest,
            prepared_digest,
            12,
        );
        let (mut first, _) = EvidenceJournalManager::provision_new(
            &journal,
            options(1, 10, constrained_limits),
            &journal_signer(),
            verifier(),
        )
        .unwrap();
        first.append(&prepared_env, 11, &journal_signer()).unwrap();
        first
            .append(&sign_stage(&called, 3), 12, &journal_signer())
            .unwrap();
        drop(first);
        let first_path = journal.join("segment-00000000000000000001");
        let second_path = journal.join("segment-00000000000000000002");
        let bytes_before = fs::metadata(&first_path).unwrap().len();

        for _ in 0..2 {
            assert!(matches!(
                RecoveredGateJournal::open_existing_with_recovery_unknowns(
                    &journal,
                    options(2, 20, constrained_limits),
                    &journal_signer(),
                    Some(&journal_signer()),
                    RecoveryCaptureLimits::new(8, 64 * 1024),
                    verifier(),
                    NonZeroUsize::new(8).unwrap(),
                ),
                Err(GateJournalOpenError::Journal(
                    JournalManagerError::ReservationUnavailable
                ))
            ));
            assert_eq!(fs::metadata(&first_path).unwrap().len(), bytes_before);
            assert!(!second_path.exists());
        }
    }

    #[cfg(target_pointer_width = "64")]
    #[test]
    fn precommit_rejects_unframeable_configured_maximum_before_tail_close() {
        let directory = TestDirectory::new();
        let journal = directory.journal();
        let seed_limits = limits(16);
        let prepared = prepared_receipt(1, 1, 11);
        let prepared_env = sign_receipt(&prepared, 3);
        let prepared_digest = DigestV1::compute(DigestDomain::RawEnvelope, &prepared_env);
        let called = stage_event(
            &prepared,
            1,
            PublishStageV1::PublishCalled,
            prepared_digest,
            prepared_digest,
            12,
        );
        let (mut first, _) = EvidenceJournalManager::provision_new(
            &journal,
            options(1, 10, seed_limits),
            &journal_signer(),
            verifier(),
        )
        .unwrap();
        first.append(&prepared_env, 11, &journal_signer()).unwrap();
        first
            .append(&sign_stage(&called, 3), 12, &journal_signer())
            .unwrap();
        drop(first);
        let unframeable = usize::try_from(u64::from(u32::MAX) + 1).unwrap();
        let invalid_limits = JournalLimits::new(
            JournalBounds::new(unframeable + 1024, 16, unframeable).unwrap(),
            16,
            u64::MAX,
        )
        .unwrap();
        let first_path = journal.join("segment-00000000000000000001");
        let second_path = journal.join("segment-00000000000000000002");
        let bytes_before = fs::metadata(&first_path).unwrap().len();

        assert!(matches!(
            RecoveredGateJournal::open_existing_with_recovery_unknowns(
                &journal,
                options(2, 20, invalid_limits),
                &journal_signer(),
                Some(&journal_signer()),
                RecoveryCaptureLimits::new(8, 64 * 1024),
                verifier(),
                NonZeroUsize::new(8).unwrap(),
            ),
            Err(GateJournalOpenError::Journal(JournalManagerError::Journal(
                JournalError::RecordTooLarge
            )))
        ));
        assert_eq!(fs::metadata(first_path).unwrap().len(), bytes_before);
        assert!(!second_path.exists());
    }

    #[test]
    fn precommit_rejects_recovered_current_boot_before_unknown_or_tail_close() {
        let directory = TestDirectory::new();
        let journal = directory.journal();
        let journal_limits = limits(16);
        let prepared = prepared_receipt(1, 1, 11);
        let prepared_env = sign_receipt(&prepared, 3);
        let prepared_digest = DigestV1::compute(DigestDomain::RawEnvelope, &prepared_env);
        let called = stage_event(
            &prepared,
            1,
            PublishStageV1::PublishCalled,
            prepared_digest,
            prepared_digest,
            12,
        );
        let (mut first, _) = EvidenceJournalManager::provision_new(
            &journal,
            options(1, 10, journal_limits),
            &journal_signer(),
            verifier(),
        )
        .unwrap();
        first.append(&prepared_env, 11, &journal_signer()).unwrap();
        first
            .append(&sign_stage(&called, 3), 12, &journal_signer())
            .unwrap();
        drop(first);
        let (second, _) = EvidenceJournalManager::open_existing(
            &journal,
            options(2, 20, journal_limits),
            &journal_signer(),
            Some(&journal_signer()),
            verifier(),
        )
        .unwrap();
        drop(second);
        let second_path = journal.join("segment-00000000000000000002");
        let third_path = journal.join("segment-00000000000000000003");
        let bytes_before = fs::metadata(&second_path).unwrap().len();

        assert!(matches!(
            RecoveredGateJournal::open_existing_with_recovery_unknowns(
                &journal,
                options(2, 30, journal_limits),
                &journal_signer(),
                Some(&journal_signer()),
                RecoveryCaptureLimits::new(8, 64 * 1024),
                verifier(),
                NonZeroUsize::new(8).unwrap(),
            ),
            Err(GateJournalOpenError::Replay {
                error: PublicationRecoveryError::Reduction(
                    PublicationReductionError::RecoveryBootAlreadyObserved
                ),
                recovery: JournalRecoveryReport {
                    closed_active_tail: false,
                    active_sequence: None,
                    ..
                }
            })
        ));
        assert_eq!(fs::metadata(second_path).unwrap().len(), bytes_before);
        assert!(!third_path.exists());
    }

    #[test]
    fn replay_rejects_same_boot_segment_and_record_time_regression() {
        let segment_directory = TestDirectory::new();
        let segment_journal = segment_directory.journal();
        let one_record_limits = limits(1);
        let (mut first, _) = EvidenceJournalManager::provision_new(
            &segment_journal,
            options(1, 10, one_record_limits),
            &journal_signer(),
            verifier(),
        )
        .unwrap();
        first
            .append(
                &sign_receipt(&deny_receipt(1, 1, 11), 3),
                10,
                &journal_signer(),
            )
            .unwrap();
        first
            .append(
                &sign_receipt(&deny_receipt(2, 1, 12), 3),
                10,
                &journal_signer(),
            )
            .unwrap();
        drop(first.finish(&journal_signer()).unwrap());
        let (_, recovery) = open_capture(&segment_journal, 2, 1, one_record_limits);
        assert!(matches!(
            verifier().rebuild_publication_state(recovery, 1),
            Err(PublicationRecoveryError::SegmentTimeRegression)
        ));

        let valid_directory = TestDirectory::new();
        let valid_journal = valid_directory.journal();
        let (mut valid, _) = EvidenceJournalManager::provision_new(
            &valid_journal,
            options(1, 10, one_record_limits),
            &journal_signer(),
            verifier(),
        )
        .unwrap();
        valid
            .append(
                &sign_receipt(&deny_receipt(1, 1, 11), 3),
                10,
                &journal_signer(),
            )
            .unwrap();
        // The pending record was observed at 12 before rotation created its
        // containing successor at 13; this is valid. The successor still follows
        // the prior segment's record at 11.
        valid
            .append(
                &sign_receipt(&deny_receipt(2, 1, 12), 3),
                13,
                &journal_signer(),
            )
            .unwrap();
        drop(valid.finish(&journal_signer()).unwrap());
        let (_, recovery) = open_capture(&valid_journal, 2, 1, one_record_limits);
        let state = verifier().rebuild_publication_state(recovery, 1).unwrap();
        assert_eq!(state.replayed_segments(), 2);
        assert_eq!(state.replayed_records(), 2);

        let record_directory = TestDirectory::new();
        let record_journal = record_directory.journal();
        let journal_limits = limits(4);
        let (mut manager, _) = EvidenceJournalManager::provision_new(
            &record_journal,
            options(1, 1, journal_limits),
            &journal_signer(),
            verifier(),
        )
        .unwrap();
        manager
            .append(
                &sign_receipt(&deny_receipt(1, 1, 10), 3),
                1,
                &journal_signer(),
            )
            .unwrap();
        manager
            .append(
                &sign_receipt(&deny_receipt(2, 1, 9), 3),
                1,
                &journal_signer(),
            )
            .unwrap();
        drop(manager.finish(&journal_signer()).unwrap());
        let (_, recovery) = open_capture(&record_journal, 2, 1, journal_limits);
        assert!(matches!(
            verifier().rebuild_publication_state(recovery, 1),
            Err(PublicationRecoveryError::RecordTimeRegression)
        ));
    }

    #[test]
    fn wrong_segment_role_revocation_and_append_validation_are_coarsened() {
        let mut wrong_role = TrustStore::new();
        wrong_role
            .insert(KeyRecord {
                kid: kid(3),
                role: KeyRole::ControllerIntent,
                verifying_key: key(3).verifying_key(),
                subject: Some(gate().as_str().to_owned()),
                class: KeyClass::Assurance,
            })
            .unwrap();
        let identity = SegmentIdentity {
            gate_id: gate(),
            gate_boot_id: GateBootId::new([1; 16]),
            segment_sequence: NonZeroU64::new(1).unwrap(),
            previous_completed_digest: [0; 32],
            created_mono_ns: 1,
            signer_kid: kid(3),
            signer_public_key: key(3).verifying_key().to_bytes(),
        };
        let wrong_role_verifier = GateJournalVerifier::new(
            gate(),
            wrong_role,
            RevocationSnapshot::new(),
            NonZeroUsize::new(4096).unwrap(),
        );
        assert_eq!(
            wrong_role_verifier.verify_segment_identity(&identity).err(),
            Some(GateJournalVerificationError::SegmentSignerUntrusted)
        );

        for (subject, class) in [
            (None, KeyClass::Assurance),
            (Some("gate-2"), KeyClass::Assurance),
            (Some("gate-1"), KeyClass::Development),
        ] {
            let mut trust = TrustStore::new();
            trust
                .insert(KeyRecord {
                    kid: kid(3),
                    role: KeyRole::GateApplication,
                    verifying_key: key(3).verifying_key(),
                    subject: subject.map(str::to_owned),
                    class,
                })
                .unwrap();
            let verifier = GateJournalVerifier::new(
                gate(),
                trust,
                RevocationSnapshot::new(),
                NonZeroUsize::new(4096).unwrap(),
            );
            assert_eq!(
                verifier.verify_segment_identity(&identity).err(),
                Some(GateJournalVerificationError::SegmentSignerUntrusted)
            );
        }

        let mut wrong_public_key = identity.clone();
        wrong_public_key.signer_public_key = key(4).verifying_key().to_bytes();
        assert_eq!(
            verifier().verify_segment_identity(&wrong_public_key).err(),
            Some(GateJournalVerificationError::SegmentSignerUntrusted)
        );
        let mut wrong_gate = identity.clone();
        wrong_gate.gate_id = GateId::new("gate-2").unwrap();
        assert_eq!(
            verifier().verify_segment_identity(&wrong_gate).err(),
            Some(GateJournalVerificationError::SegmentGateMismatch)
        );

        let mut revocations = RevocationSnapshot::new();
        revocations.revoke_key(&kid(3), 1);
        let revoked = GateJournalVerifier::new(
            gate(),
            trust_with_gate_keys(&[3]),
            revocations,
            NonZeroUsize::new(4096).unwrap(),
        );
        assert!(matches!(
            revoked.resolve_signer(&identity),
            Err(JournalVerificationError::UnknownSigner)
        ));
        assert_eq!(
            verifier().validate_record(&identity, b"not-cose"),
            Err(JournalVerificationError::InvalidRecord)
        );
        assert!(matches!(
            EvidenceJournalManager::provision_new(
                TestDirectory::new().journal(),
                options(1, 1, limits(4)),
                &journal_signer(),
                revoked,
            ),
            Err(JournalManagerError::Verification(
                JournalVerificationError::UnknownSigner
            ))
        ));
    }
}
