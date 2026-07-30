//! Durable-state error classes.

use core::fmt;

/// A durable snapshot or anchor failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DurableError {
    /// The snapshot envelope is malformed or internally inconsistent.
    Corrupt,
    /// Authentication failed or the snapshot was bound to another store/Gate.
    AuthenticationFailed,
    /// No snapshot exists and explicit provisioning was not requested.
    Missing,
    /// Provisioning was requested for non-empty storage or an existing anchor.
    AlreadyProvisioned,
    /// Snapshot storage exists but the required generation anchor is absent.
    AnchorMissing,
    /// The snapshot is older than the generation anchor.
    Rewind,
    /// Snapshot and anchor claim the same generation with different digests, or
    /// a next-generation snapshot does not link to the anchored predecessor.
    Fork,
    /// The snapshot jumped over one or more anchored generations.
    GenerationGap,
    /// The checked generation namespace is exhausted.
    Exhausted,
    /// The storage backend failed its atomic replacement contract.
    Storage,
    /// The selected backend is unavailable on this platform.
    Unsupported,
    /// The generation-anchor backend was unavailable.
    AnchorUnavailable,
    /// The anchor request or persisted value named another logical store.
    AnchorBindingMismatch,
    /// The generation-anchor compare-and-set observed unexpected state.
    AnchorConflict,
    /// A snapshot replacement may have changed bytes, but the installed
    /// snapshot/anchor outcome is uncertain. Controlled reopen/recovery is
    /// required before another commit.
    CommitUncertain,
}

impl DurableError {
    /// Stable machine reason string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Corrupt => "DURABLE_CORRUPT",
            Self::AuthenticationFailed => "DURABLE_AUTHENTICATION_FAILED",
            Self::Missing => "DURABLE_MISSING",
            Self::AlreadyProvisioned => "DURABLE_ALREADY_PROVISIONED",
            Self::AnchorMissing => "DURABLE_ANCHOR_MISSING",
            Self::Rewind => "DURABLE_REWIND",
            Self::Fork => "DURABLE_FORK",
            Self::GenerationGap => "DURABLE_GENERATION_GAP",
            Self::Exhausted => "DURABLE_EXHAUSTED",
            Self::Storage => "DURABLE_STORAGE_FAILED",
            Self::Unsupported => "DURABLE_UNSUPPORTED",
            Self::AnchorUnavailable => "DURABLE_ANCHOR_UNAVAILABLE",
            Self::AnchorBindingMismatch => "DURABLE_ANCHOR_BINDING_MISMATCH",
            Self::AnchorConflict => "DURABLE_ANCHOR_CONFLICT",
            Self::CommitUncertain => "DURABLE_COMMIT_UNCERTAIN",
        }
    }
}

impl fmt::Display for DurableError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::error::Error for DurableError {}

#[cfg(test)]
mod tests {
    use super::DurableError;

    fn assert_thread_safe_error<E: std::error::Error + Send + Sync + 'static>() {}

    #[test]
    fn error_is_thread_safe_and_static() {
        assert_thread_safe_error::<DurableError>();
    }

    #[test]
    fn every_error_has_a_stable_display_code_and_no_source() {
        let cases = [
            (DurableError::Corrupt, "DURABLE_CORRUPT"),
            (
                DurableError::AuthenticationFailed,
                "DURABLE_AUTHENTICATION_FAILED",
            ),
            (DurableError::Missing, "DURABLE_MISSING"),
            (
                DurableError::AlreadyProvisioned,
                "DURABLE_ALREADY_PROVISIONED",
            ),
            (DurableError::AnchorMissing, "DURABLE_ANCHOR_MISSING"),
            (DurableError::Rewind, "DURABLE_REWIND"),
            (DurableError::Fork, "DURABLE_FORK"),
            (DurableError::GenerationGap, "DURABLE_GENERATION_GAP"),
            (DurableError::Exhausted, "DURABLE_EXHAUSTED"),
            (DurableError::Storage, "DURABLE_STORAGE_FAILED"),
            (DurableError::Unsupported, "DURABLE_UNSUPPORTED"),
            (
                DurableError::AnchorUnavailable,
                "DURABLE_ANCHOR_UNAVAILABLE",
            ),
            (
                DurableError::AnchorBindingMismatch,
                "DURABLE_ANCHOR_BINDING_MISMATCH",
            ),
            (DurableError::AnchorConflict, "DURABLE_ANCHOR_CONFLICT"),
            (DurableError::CommitUncertain, "DURABLE_COMMIT_UNCERTAIN"),
        ];

        for (error, expected) in cases {
            let as_std_error: &(dyn std::error::Error + 'static) = &error;
            assert_eq!(error.as_str(), expected);
            assert_eq!(error.to_string(), expected);
            assert!(as_std_error.source().is_none());
        }
    }
}
