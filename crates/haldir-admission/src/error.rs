//! Admission verification errors mapped to stable decision reason codes.

use haldir_contracts::receipt::DecisionReasonCodeV1;

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
