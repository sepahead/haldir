//! `haldir-evidence` — a bounded, append-only, digest-chained evidence spool.
//!
//! Records are stored with a running digest chain so a truncated tail or a
//! corrupted completed record is detectable. The spool is bounded in both record
//! count and total bytes; when full it drops only export copies and counts the
//! loss (the safety-first profile) — a spool outage can never turn a DENY into an
//! ALLOW (spec F2/B14). The local spool is not a lossy transport plane, so
//! command authorization never blocks on a remote collector.
#![forbid(unsafe_code)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::float_cmp
    )
)]

use haldir_contracts::digest::{DigestDomain, DigestV1};

pub mod gate_journal;
pub mod journal;
pub mod manager;
pub mod publication;

/// Crate version string.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The outcome of appending a record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppendOutcome {
    /// The record was appended.
    Appended,
    /// The spool is full; the record (an export copy) was dropped and counted.
    DroppedSpoolFull,
}

/// A bounded, digest-chained evidence spool.
#[derive(Debug, Clone)]
pub struct EvidenceSpool {
    records: Vec<Vec<u8>>,
    chain: Vec<DigestV1>,
    max_records: usize,
    max_bytes: usize,
    total_bytes: usize,
    dropped: u64,
}

impl EvidenceSpool {
    /// A new bounded spool.
    #[must_use]
    pub fn new(max_records: usize, max_bytes: usize) -> Self {
        Self {
            records: Vec::new(),
            chain: Vec::new(),
            max_records,
            max_bytes,
            total_bytes: 0,
            dropped: 0,
        }
    }

    fn link(prev: Option<&DigestV1>, record: &[u8]) -> DigestV1 {
        let mut buf = Vec::with_capacity(32 + record.len());
        if let Some(p) = prev {
            buf.extend_from_slice(&p.value);
        }
        buf.extend_from_slice(record);
        DigestV1::compute(DigestDomain::Payload, &buf)
    }

    /// Append a (typically signed) evidence record. Bounded; drops on overflow.
    pub fn append(&mut self, record: &[u8]) -> AppendOutcome {
        if self.records.len() >= self.max_records
            || self.total_bytes.saturating_add(record.len()) > self.max_bytes
        {
            self.dropped = self.dropped.saturating_add(1);
            return AppendOutcome::DroppedSpoolFull;
        }
        let d = Self::link(self.chain.last(), record);
        self.records.push(record.to_vec());
        self.chain.push(d);
        self.total_bytes = self.total_bytes.saturating_add(record.len());
        AppendOutcome::Appended
    }

    /// Number of retained records.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether the spool is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// The number of dropped export copies (loss summary).
    #[must_use]
    pub const fn dropped(&self) -> u64 {
        self.dropped
    }

    /// The current chain head digest.
    #[must_use]
    pub fn chain_head(&self) -> Option<DigestV1> {
        self.chain.last().copied()
    }

    /// Recompute the chain and confirm every record links correctly (detects
    /// tampering with a completed record or a broken tail).
    #[must_use]
    pub fn verify_chain(&self) -> bool {
        let mut prev: Option<DigestV1> = None;
        for (rec, expected) in self.records.iter().zip(self.chain.iter()) {
            let d = Self::link(prev.as_ref(), rec);
            if &d != expected {
                return false;
            }
            prev = Some(d);
        }
        prev.as_ref() == self.chain.last()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn appends_and_verifies_chain() {
        let mut s = EvidenceSpool::new(8, 4096);
        assert_eq!(s.append(b"a"), AppendOutcome::Appended);
        assert_eq!(s.append(b"bb"), AppendOutcome::Appended);
        assert_eq!(s.append(b"ccc"), AppendOutcome::Appended);
        assert_eq!(s.len(), 3);
        assert!(s.verify_chain());
        assert!(s.chain_head().is_some());
    }

    #[test]
    fn tampering_breaks_the_chain() {
        let mut s = EvidenceSpool::new(8, 4096);
        s.append(b"one");
        s.append(b"two");
        s.records[0] = b"XXX".to_vec();
        assert!(!s.verify_chain());
    }

    #[test]
    fn full_spool_drops_and_counts() {
        let mut s = EvidenceSpool::new(2, 4096);
        assert_eq!(s.append(b"a"), AppendOutcome::Appended);
        assert_eq!(s.append(b"b"), AppendOutcome::Appended);
        assert_eq!(s.append(b"c"), AppendOutcome::DroppedSpoolFull);
        assert_eq!(s.dropped(), 1);
        assert_eq!(s.len(), 2);
    }

    #[test]
    fn byte_bound_is_enforced() {
        let mut s = EvidenceSpool::new(100, 4);
        assert_eq!(s.append(b"aa"), AppendOutcome::Appended);
        assert_eq!(s.append(b"bb"), AppendOutcome::Appended);
        assert_eq!(s.append(b"c"), AppendOutcome::DroppedSpoolFull);
    }
}
