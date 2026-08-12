//! Admission verification errors mapped to stable decision reason codes.

use core::fmt;

use haldir_contracts::receipt::DecisionReasonCodeV1;

/// A failure to add a record to an admission snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AdmissionSnapshotError {
    /// The candidate record failed its supported record validation.
    InvalidRecord,
    /// A different record already uses the same admission id.
    ConflictingAdmissionId,
    /// The fixed active-record bound is already exhausted.
    RecordCapacityExceeded,
    /// A new revocation did not carry an epoch above the current high-water.
    RevocationEpochNotAdvanced,
    /// The fixed revoked-id bound is already exhausted.
    RevocationCapacityExceeded,
}

impl AdmissionSnapshotError {
    /// Stable non-record-leaking machine reason code.
    #[must_use]
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::InvalidRecord => "ADMISSION_SNAPSHOT_INVALID_RECORD",
            Self::ConflictingAdmissionId => "ADMISSION_SNAPSHOT_CONFLICTING_ADMISSION_ID",
            Self::RecordCapacityExceeded => "ADMISSION_SNAPSHOT_RECORD_CAPACITY_EXCEEDED",
            Self::RevocationEpochNotAdvanced => "ADMISSION_SNAPSHOT_REVOCATION_EPOCH_NOT_ADVANCED",
            Self::RevocationCapacityExceeded => "ADMISSION_SNAPSHOT_REVOCATION_CAPACITY_EXCEEDED",
        }
    }
}

impl fmt::Display for AdmissionSnapshotError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for AdmissionSnapshotError {}

/// A failure to verify a claimed admission against the snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AdmissionError {
    /// No admission with the claimed id is present.
    Unknown,
    /// The admission id is revoked.
    Revoked,
    /// The record's computed digest did not match the claimed `admission_digest`.
    DigestMismatch,
    /// The bundle digest did not match the admitted bundle.
    BundleMismatch,
    /// The backend profile digest did not match the admitted backend.
    BackendMismatch,
    /// The controller id did not match the admitted controller.
    ControllerMismatch,
    /// The level is not a semantic admission where one was required.
    NotSemantic,
}

impl AdmissionError {
    /// The stable decision reason code this error maps to.
    #[must_use]
    pub const fn reason_code(self) -> DecisionReasonCodeV1 {
        match self {
            Self::Revoked => DecisionReasonCodeV1::DenyAdmissionRevoked,
            Self::Unknown
            | Self::DigestMismatch
            | Self::BundleMismatch
            | Self::ControllerMismatch
            | Self::NotSemantic => DecisionReasonCodeV1::DenyAdmissionMismatch,
            Self::BackendMismatch => DecisionReasonCodeV1::DenyBackendMismatch,
        }
    }
}
