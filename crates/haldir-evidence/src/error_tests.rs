use crate::gate_journal::{
    GateJournalMutationError, GateJournalOpenError, GateJournalVerificationError,
    PublicationRecoveryError,
};
use crate::journal::JournalError;
use crate::manager::{
    EvidenceRecordDigest, JournalManagerError, JournalRecoveryReport, JournalVerificationError,
    RecoveryCaptureDimension,
};
use crate::publication::PublicationReductionError;
use haldir_contracts::error::DecodeError;
use std::error::Error;

macro_rules! assert_error_codes {
    ($($error:expr => $expected:literal),+ $(,)?) => {
        $(
            {
                let error = $error;
                let as_std_error: &(dyn Error + 'static) = &error;
                assert_eq!(error.reason_code(), $expected);
                assert_eq!(as_std_error.to_string(), $expected);
            }
        )+
    };
}

fn recovery_report() -> JournalRecoveryReport {
    JournalRecoveryReport {
        discovered_segments: 0,
        completed_segments: 0,
        recovered_records: 0,
        truncated_tail_bytes: 0,
        closed_active_tail: false,
        discarded_pending_creation: false,
        active_sequence: None,
        total_bytes: 0,
        quiesced: false,
    }
}

fn typed_source<'a, E>(error: &'a (dyn Error + 'static), expected_display: &str) -> &'a E
where
    E: Error + 'static,
{
    let source = error
        .source()
        .expect("wrapped error must expose its source");
    assert_eq!(source.to_string(), expected_display);
    source
        .downcast_ref::<E>()
        .expect("source must retain its concrete error type")
}

fn assert_thread_safe_error<E: Error + Send + Sync + 'static>() {}

#[test]
fn every_public_error_is_thread_safe_and_static() {
    assert_thread_safe_error::<JournalError>();
    assert_thread_safe_error::<JournalVerificationError>();
    assert_thread_safe_error::<JournalManagerError>();
    assert_thread_safe_error::<GateJournalVerificationError>();
    assert_thread_safe_error::<PublicationRecoveryError>();
    assert_thread_safe_error::<GateJournalOpenError>();
    assert_thread_safe_error::<GateJournalMutationError>();
    assert_thread_safe_error::<PublicationReductionError>();
}

#[test]
fn journal_error_codes_are_stable() {
    assert_error_codes! {
        JournalError::Missing => "EVIDENCE_JOURNAL_MISSING",
        JournalError::AlreadyExists => "EVIDENCE_JOURNAL_ALREADY_EXISTS",
        JournalError::Unsupported => "EVIDENCE_JOURNAL_UNSUPPORTED",
        JournalError::Storage => "EVIDENCE_JOURNAL_STORAGE_FAILED",
        JournalError::Bounds => "EVIDENCE_JOURNAL_BOUNDS",
        JournalError::RecordTooLarge => "EVIDENCE_JOURNAL_RECORD_TOO_LARGE",
        JournalError::RecordCannotFitSegment => "EVIDENCE_JOURNAL_RECORD_CANNOT_FIT_SEGMENT",
        JournalError::RotationRequired => "EVIDENCE_JOURNAL_ROTATION_REQUIRED",
        JournalError::ChainMismatch => "EVIDENCE_JOURNAL_CHAIN_MISMATCH",
        JournalError::SignerMismatch => "EVIDENCE_JOURNAL_SIGNER_MISMATCH",
        JournalError::CommitAmbiguous => "EVIDENCE_JOURNAL_COMMIT_AMBIGUOUS",
        JournalError::CorruptHeader => "EVIDENCE_JOURNAL_CORRUPT_HEADER",
        JournalError::CorruptRecord => "EVIDENCE_JOURNAL_CORRUPT_RECORD",
        JournalError::CorruptFooter => "EVIDENCE_JOURNAL_CORRUPT_FOOTER",
        JournalError::IdentityMismatch => "EVIDENCE_JOURNAL_IDENTITY_MISMATCH",
        JournalError::SignatureInvalid => "EVIDENCE_JOURNAL_SIGNATURE_INVALID",
        JournalError::Poisoned => "EVIDENCE_JOURNAL_POISONED",
    }
}

#[test]
fn journal_verification_error_codes_are_stable() {
    assert_error_codes! {
        JournalVerificationError::UnknownSigner =>
            "EVIDENCE_JOURNAL_VERIFICATION_UNKNOWN_SIGNER",
        JournalVerificationError::InvalidRecord =>
            "EVIDENCE_JOURNAL_VERIFICATION_INVALID_RECORD",
    }
}

#[test]
fn journal_manager_error_codes_are_stable() {
    assert_error_codes! {
        JournalManagerError::Journal(JournalError::Storage) =>
            "EVIDENCE_JOURNAL_MANAGER_JOURNAL",
        JournalManagerError::Verification(JournalVerificationError::InvalidRecord) =>
            "EVIDENCE_JOURNAL_MANAGER_VERIFICATION",
        JournalManagerError::LockHeld => "EVIDENCE_JOURNAL_MANAGER_LOCK_HELD",
        JournalManagerError::Missing => "EVIDENCE_JOURNAL_MANAGER_MISSING",
        JournalManagerError::AlreadyProvisioned =>
            "EVIDENCE_JOURNAL_MANAGER_ALREADY_PROVISIONED",
        JournalManagerError::IncompleteProvisioning =>
            "EVIDENCE_JOURNAL_MANAGER_INCOMPLETE_PROVISIONING",
        JournalManagerError::Storage => "EVIDENCE_JOURNAL_MANAGER_STORAGE_FAILED",
        JournalManagerError::UnexpectedEntry => "EVIDENCE_JOURNAL_MANAGER_UNEXPECTED_ENTRY",
        JournalManagerError::DuplicateSequence =>
            "EVIDENCE_JOURNAL_MANAGER_DUPLICATE_SEQUENCE",
        JournalManagerError::SequenceGap => "EVIDENCE_JOURNAL_MANAGER_SEQUENCE_GAP",
        JournalManagerError::Rewind => "EVIDENCE_JOURNAL_MANAGER_REWIND",
        JournalManagerError::Fork => "EVIDENCE_JOURNAL_MANAGER_FORK",
        JournalManagerError::MultipleActive => "EVIDENCE_JOURNAL_MANAGER_MULTIPLE_ACTIVE",
        JournalManagerError::GateMismatch => "EVIDENCE_JOURNAL_MANAGER_GATE_MISMATCH",
        JournalManagerError::TailSignerUnavailable =>
            "EVIDENCE_JOURNAL_MANAGER_TAIL_SIGNER_UNAVAILABLE",
        JournalManagerError::Quiesced => "EVIDENCE_JOURNAL_MANAGER_QUIESCED",
        JournalManagerError::ReservationUnavailable =>
            "EVIDENCE_JOURNAL_MANAGER_RESERVATION_UNAVAILABLE",
        JournalManagerError::ReservationMismatch =>
            "EVIDENCE_JOURNAL_MANAGER_RESERVATION_MISMATCH",
        JournalManagerError::ReservationExhausted =>
            "EVIDENCE_JOURNAL_MANAGER_RESERVATION_EXHAUSTED",
        JournalManagerError::Poisoned => "EVIDENCE_JOURNAL_MANAGER_POISONED",
        JournalManagerError::DuplicateRecord => "EVIDENCE_JOURNAL_MANAGER_DUPLICATE_RECORD",
        JournalManagerError::AppendCommitAmbiguous {
            record_digest: EvidenceRecordDigest::compute(b"record"),
        } => "EVIDENCE_JOURNAL_MANAGER_APPEND_COMMIT_AMBIGUOUS",
        JournalManagerError::SequenceExhausted =>
            "EVIDENCE_JOURNAL_MANAGER_SEQUENCE_EXHAUSTED",
        JournalManagerError::RecoveryCaptureLimitExceeded {
            dimension: RecoveryCaptureDimension::RecordBytes,
            maximum: 1,
            required: 2,
        } => "EVIDENCE_JOURNAL_MANAGER_RECOVERY_CAPTURE_LIMIT_EXCEEDED",
        JournalManagerError::RecoveryCaptureAllocation =>
            "EVIDENCE_JOURNAL_MANAGER_RECOVERY_CAPTURE_ALLOCATION",
        JournalManagerError::RecoveryConsumerRejected =>
            "EVIDENCE_JOURNAL_MANAGER_RECOVERY_CONSUMER_REJECTED",
    }
}

#[test]
fn gate_journal_verification_error_codes_are_stable() {
    assert_error_codes! {
        GateJournalVerificationError::EnvelopeTooLarge =>
            "EVIDENCE_GATE_JOURNAL_ENVELOPE_TOO_LARGE",
        GateJournalVerificationError::SegmentGateMismatch =>
            "EVIDENCE_GATE_JOURNAL_SEGMENT_GATE_MISMATCH",
        GateJournalVerificationError::SegmentSignerUntrusted =>
            "EVIDENCE_GATE_JOURNAL_SEGMENT_SIGNER_UNTRUSTED",
        GateJournalVerificationError::InvalidEnvelope =>
            "EVIDENCE_GATE_JOURNAL_INVALID_ENVELOPE",
        GateJournalVerificationError::ReceiptSemanticInvalid =>
            "EVIDENCE_GATE_JOURNAL_RECEIPT_SEMANTIC_INVALID",
        GateJournalVerificationError::RecordSignerMismatch =>
            "EVIDENCE_GATE_JOURNAL_RECORD_SIGNER_MISMATCH",
        GateJournalVerificationError::RecordSubjectMismatch =>
            "EVIDENCE_GATE_JOURNAL_RECORD_SUBJECT_MISMATCH",
        GateJournalVerificationError::RecordGateMismatch =>
            "EVIDENCE_GATE_JOURNAL_RECORD_GATE_MISMATCH",
        GateJournalVerificationError::RecordBootMismatch =>
            "EVIDENCE_GATE_JOURNAL_RECORD_BOOT_MISMATCH",
    }
}

#[test]
fn publication_recovery_error_codes_are_stable() {
    assert_error_codes! {
        PublicationRecoveryError::Verification(
            GateJournalVerificationError::InvalidEnvelope,
        ) => "EVIDENCE_PUBLICATION_RECOVERY_VERIFICATION",
        PublicationRecoveryError::BootResurrection =>
            "EVIDENCE_PUBLICATION_RECOVERY_BOOT_RESURRECTION",
        PublicationRecoveryError::SegmentTimeRegression =>
            "EVIDENCE_PUBLICATION_RECOVERY_SEGMENT_TIME_REGRESSION",
        PublicationRecoveryError::RecordTimeRegression =>
            "EVIDENCE_PUBLICATION_RECOVERY_RECORD_TIME_REGRESSION",
        PublicationRecoveryError::DuplicateDecisionReceipt =>
            "EVIDENCE_PUBLICATION_RECOVERY_DUPLICATE_DECISION_RECEIPT",
        PublicationRecoveryError::Reduction(PublicationReductionError::TimeRegression) =>
            "EVIDENCE_PUBLICATION_RECOVERY_REDUCTION",
    }
}

#[test]
fn gate_journal_open_error_codes_are_stable() {
    assert_error_codes! {
        GateJournalOpenError::TraceCapacityTooSmall =>
            "EVIDENCE_GATE_JOURNAL_OPEN_TRACE_CAPACITY_TOO_SMALL",
        GateJournalOpenError::Journal(JournalManagerError::Missing) =>
            "EVIDENCE_GATE_JOURNAL_OPEN_JOURNAL",
        GateJournalOpenError::Replay {
            error: PublicationRecoveryError::BootResurrection,
            recovery: recovery_report(),
        } => "EVIDENCE_GATE_JOURNAL_OPEN_REPLAY",
    }
}

#[test]
fn gate_journal_mutation_error_codes_are_stable() {
    assert_error_codes! {
        GateJournalMutationError::Journal(JournalManagerError::Poisoned) =>
            "EVIDENCE_GATE_JOURNAL_MUTATION_JOURNAL",
        GateJournalMutationError::Semantic(PublicationRecoveryError::RecordTimeRegression) =>
            "EVIDENCE_GATE_JOURNAL_MUTATION_SEMANTIC",
    }
}

#[test]
fn publication_reduction_error_codes_are_stable() {
    assert_error_codes! {
        PublicationReductionError::InvalidPreparedReceipt =>
            "EVIDENCE_PUBLICATION_REDUCTION_INVALID_PREPARED_RECEIPT",
        PublicationReductionError::CapacityExceeded =>
            "EVIDENCE_PUBLICATION_REDUCTION_CAPACITY_EXCEEDED",
        PublicationReductionError::DuplicateDecision =>
            "EVIDENCE_PUBLICATION_REDUCTION_DUPLICATE_DECISION",
        PublicationReductionError::MissingPreparedDecision =>
            "EVIDENCE_PUBLICATION_REDUCTION_MISSING_PREPARED_DECISION",
        PublicationReductionError::IdentityMismatch =>
            "EVIDENCE_PUBLICATION_REDUCTION_IDENTITY_MISMATCH",
        PublicationReductionError::GateScopeMismatch =>
            "EVIDENCE_PUBLICATION_REDUCTION_GATE_SCOPE_MISMATCH",
        PublicationReductionError::InvalidEvent(DecodeError::TrailingBytes) =>
            "EVIDENCE_PUBLICATION_REDUCTION_INVALID_EVENT",
        PublicationReductionError::InvalidTransition =>
            "EVIDENCE_PUBLICATION_REDUCTION_INVALID_TRANSITION",
        PublicationReductionError::PredecessorMismatch =>
            "EVIDENCE_PUBLICATION_REDUCTION_PREDECESSOR_MISMATCH",
        PublicationReductionError::TimeRegression =>
            "EVIDENCE_PUBLICATION_REDUCTION_TIME_REGRESSION",
        PublicationReductionError::RecoveryBootAlreadyObserved =>
            "EVIDENCE_PUBLICATION_REDUCTION_RECOVERY_BOOT_ALREADY_OBSERVED",
    }
}

#[test]
fn journal_mutation_source_chain_preserves_concrete_types() {
    let error =
        GateJournalMutationError::Journal(JournalManagerError::Journal(JournalError::Storage));
    let root: &(dyn Error + 'static) = &error;
    let manager = typed_source::<JournalManagerError>(root, "EVIDENCE_JOURNAL_MANAGER_JOURNAL");
    let journal = typed_source::<JournalError>(manager, "EVIDENCE_JOURNAL_STORAGE_FAILED");

    assert!(journal.source().is_none());
}

#[test]
fn semantic_mutation_source_chain_preserves_concrete_types() {
    let error = GateJournalMutationError::Semantic(PublicationRecoveryError::Reduction(
        PublicationReductionError::InvalidEvent(DecodeError::TrailingBytes),
    ));
    let root: &(dyn Error + 'static) = &error;
    let recovery =
        typed_source::<PublicationRecoveryError>(root, "EVIDENCE_PUBLICATION_RECOVERY_REDUCTION");
    let reduction = typed_source::<PublicationReductionError>(
        recovery,
        "EVIDENCE_PUBLICATION_REDUCTION_INVALID_EVENT",
    );
    let decode = typed_source::<DecodeError>(reduction, "DECODE_TRAILING_BYTES");

    assert!(decode.source().is_none());
}

#[test]
fn replay_source_chain_preserves_verification_type() {
    let error = GateJournalOpenError::Replay {
        error: PublicationRecoveryError::Verification(
            GateJournalVerificationError::RecordGateMismatch,
        ),
        recovery: recovery_report(),
    };
    let root: &(dyn Error + 'static) = &error;
    let recovery = typed_source::<PublicationRecoveryError>(
        root,
        "EVIDENCE_PUBLICATION_RECOVERY_VERIFICATION",
    );
    let verification = typed_source::<GateJournalVerificationError>(
        recovery,
        "EVIDENCE_GATE_JOURNAL_RECORD_GATE_MISMATCH",
    );

    assert!(verification.source().is_none());
}

#[test]
fn open_source_chain_preserves_consumer_verification_type() {
    let error = GateJournalOpenError::Journal(JournalManagerError::Verification(
        JournalVerificationError::UnknownSigner,
    ));
    let root: &(dyn Error + 'static) = &error;
    let manager =
        typed_source::<JournalManagerError>(root, "EVIDENCE_JOURNAL_MANAGER_VERIFICATION");
    let verification = typed_source::<JournalVerificationError>(
        manager,
        "EVIDENCE_JOURNAL_VERIFICATION_UNKNOWN_SIGNER",
    );

    assert!(verification.source().is_none());
}
