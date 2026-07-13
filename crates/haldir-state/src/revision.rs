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
    use super::RevisionCounter;

    #[test]
    fn exhaustion_never_reuses_the_maximum_revision() {
        let mut revision = RevisionCounter(u64::MAX);
        assert_eq!(revision.bump(), None);
        assert_eq!(revision.get(), u64::MAX);
    }
}
