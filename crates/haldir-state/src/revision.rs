//! Authorization revision counter (spec/punch-list B1).
//!
//! Every invalidation of authority state (session-generation change, lease
//! expiry/revocation/invalidation, publication-authority loss, fault latch)
//! bumps this counter. A decision captures the revision at snapshot time and
//! re-checks it immediately before output-sequence allocation; a change means an
//! invalidation raced the decision and no output may be produced (TOCTOU guard).

/// A monotonic authorization revision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RevisionCounter(u64);

impl RevisionCounter {
    /// A new counter starting at one.
    #[must_use]
    pub const fn new() -> Self {
        Self(1)
    }

    /// The current value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Bump the counter, returning the new value.
    pub fn bump(&mut self) -> u64 {
        self.0 = self.0.saturating_add(1);
        self.0
    }
}

impl Default for RevisionCounter {
    fn default() -> Self {
        Self::new()
    }
}
