//! Durable-state error classes.

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
    /// Snapshot storage exists but the required external anchor is absent.
    AnchorMissing,
    /// The snapshot is older than the external anchor.
    Rewind,
    /// Snapshot and anchor claim the same generation with different digests, or
    /// a next-generation snapshot does not link to the anchored predecessor.
    Fork,
    /// The snapshot jumped over one or more externally anchored generations.
    GenerationGap,
    /// The checked generation namespace is exhausted.
    Exhausted,
    /// The storage backend failed its atomic replacement contract.
    Storage,
    /// The external anchor backend was unavailable.
    AnchorUnavailable,
    /// The external anchor compare-and-set observed unexpected state.
    AnchorConflict,
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
            Self::AnchorUnavailable => "DURABLE_ANCHOR_UNAVAILABLE",
            Self::AnchorConflict => "DURABLE_ANCHOR_CONFLICT",
        }
    }
}
