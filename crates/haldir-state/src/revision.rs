//! Authorization revision counter (spec/punch-list B1).
//!
//! Every invalidation of authority state (session-generation change, lease
//! expiry/revocation/invalidation, publication-authority loss, fault latch)
//! bumps this counter. A decision captures the revision at snapshot time and
//! re-checks it immediately before output-sequence allocation; a change means an
//! invalidation raced the decision and no output may be produced (TOCTOU guard).

use core::num::NonZeroU64;

/// A monotonic authorization revision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RevisionCounter(u64);

impl RevisionCounter {
    /// A new counter starting at one.
    #[must_use]
    pub const fn new() -> Self {
        Self(1)
    }

    /// Reconstruct a previously retained nonzero revision value.
    #[must_use]
    pub const fn from_nonzero(value: NonZeroU64) -> Self {
        Self(value.get())
    }

    /// The current value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Whether no distinct successor revision can be represented.
    #[must_use]
    pub const fn is_exhausted(self) -> bool {
        self.0 == u64::MAX
    }

    /// Bump the counter, returning the new value, or `None` at exhaustion.
    ///
    /// Exhaustion never aliases two authorization revisions. Callers must fail
    /// closed instead of continuing with the unchanged maximum value.
    pub fn bump(&mut self) -> Option<u64> {
        let next = self.0.checked_add(1)?;
        self.0 = next;
        Some(next)
    }
}

impl Default for RevisionCounter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use core::num::NonZeroU64;

    use super::RevisionCounter;

    #[test]
    fn exhaustion_never_reuses_the_maximum_revision() {
        let mut revision = RevisionCounter::from_nonzero(NonZeroU64::MAX);
        assert!(revision.is_exhausted());
        assert_eq!(revision.bump(), None);
        assert_eq!(revision.get(), u64::MAX);
    }

    #[test]
    fn ordinary_revisions_report_remaining_successor_capacity() {
        let mut revision = RevisionCounter::new();
        assert!(!revision.is_exhausted());
        assert_eq!(revision.bump(), Some(2));
        assert!(!revision.is_exhausted());
    }
}
