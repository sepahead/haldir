//! `haldir-evidence` — a bounded, append-only, digest-chained evidence spool.
//!
//! Records are stored with a running digest chain so corrupted retained records
//! or link metadata are detectable. Coordinated prefix truncation is detectable
//! only when a caller retains an external `(record_count, chain_head)` checkpoint.
//! The spool is bounded in both record
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

use haldir_contracts::digest::{DigestAlgorithmV1, DigestV1};
use sha2::{Digest, Sha256};

const SPOOL_LINK_DOMAIN: &[u8] = b"haldir.evidence.spool-link.v1\0";

pub mod gate_journal;
pub mod journal;
pub mod manager;
pub mod publication;

#[cfg(test)]
mod error_tests;

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
        let mut hasher = Sha256::new();
        hasher.update(SPOOL_LINK_DOMAIN);
        match prev {
            Some(predecessor) => {
                hasher.update([1]);
                hasher.update(predecessor.value);
            }
            None => hasher.update([0]),
        }
        hasher.update(
            u64::try_from(record.len())
                .unwrap_or(u64::MAX)
                .to_be_bytes(),
        );
        hasher.update(record);
        DigestV1 {
            algorithm: DigestAlgorithmV1::Sha256,
            value: hasher.finalize().into(),
        }
    }

    /// Append a (typically signed) evidence record. Bounded; drops on overflow.
    pub fn append(&mut self, record: &[u8]) -> AppendOutcome {
        let Some(next_total_bytes) = self.total_bytes.checked_add(record.len()) else {
            self.dropped = self.dropped.saturating_add(1);
            return AppendOutcome::DroppedSpoolFull;
        };
        if self.records.len() >= self.max_records || next_total_bytes > self.max_bytes {
            self.dropped = self.dropped.saturating_add(1);
            return AppendOutcome::DroppedSpoolFull;
        }

        // Complete every fallible allocation before changing the retained
        // record/chain state. Allocation pressure is an export loss, not a
        // process abort or a partially appended spool entry.
        if self.records.try_reserve(1).is_err() || self.chain.try_reserve(1).is_err() {
            self.dropped = self.dropped.saturating_add(1);
            return AppendOutcome::DroppedSpoolFull;
        }
        let mut retained_record = Vec::new();
        if retained_record.try_reserve_exact(record.len()).is_err() {
            self.dropped = self.dropped.saturating_add(1);
            return AppendOutcome::DroppedSpoolFull;
        }
        retained_record.extend_from_slice(record);

        let d = Self::link(self.chain.last(), record);
        self.records.push(retained_record);
        self.chain.push(d);
        self.total_bytes = next_total_bytes;
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

    /// Retained records in their exact append order.
    ///
    /// The iterator lends immutable byte slices and cannot modify, remove, or
    /// reorder spool state. Callers that export these records should checkpoint
    /// [`Self::len`] and [`Self::chain_head`] alongside the exported batch when
    /// they need to detect later prefix truncation.
    pub fn records(&self) -> impl ExactSizeIterator<Item = &[u8]> + '_ {
        self.records.iter().map(Vec::as_slice)
    }

    /// Total bytes currently retained across all records.
    #[must_use]
    pub const fn retained_bytes(&self) -> usize {
        self.total_bytes
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

    /// Recompute the locally retained chain and confirm every record has exactly
    /// one matching link.
    ///
    /// This detects a mutated retained record or mismatched local metadata. It
    /// cannot detect coordinated truncation of both vectors to an earlier valid
    /// prefix; use [`Self::verify_chain_against`] with an externally retained
    /// checkpoint for that property.
    #[must_use]
    pub fn verify_chain(&self) -> bool {
        if self.records.len() != self.chain.len() {
            return false;
        }
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

    /// Verify local chain integrity against an externally retained checkpoint.
    ///
    /// A trusted checkpoint binds both count and head; either a missing suffix or
    /// an appended/replaced suffix then fails verification. The checkpoint itself
    /// must be protected outside this in-process spool.
    #[must_use]
    pub fn verify_chain_against(
        &self,
        expected_records: usize,
        expected_head: Option<DigestV1>,
    ) -> bool {
        self.records.len() == expected_records
            && self.chain_head() == expected_head
            && self.verify_chain()
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
        assert_eq!(s.retained_bytes(), 6);
        assert_eq!(
            s.records().collect::<Vec<_>>(),
            [b"a".as_slice(), b"bb".as_slice(), b"ccc".as_slice()]
        );
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
    fn missing_link_metadata_breaks_local_verification() {
        let mut s = EvidenceSpool::new(8, 4096);
        s.append(b"one");
        s.append(b"two");
        s.chain.pop();

        assert!(!s.verify_chain());
    }

    #[test]
    fn link_framing_distinguishes_one_record_from_a_two_record_chain() {
        let first = EvidenceSpool::link(None, b"first");
        let mut formerly_ambiguous_record = first.value.to_vec();
        formerly_ambiguous_record.extend_from_slice(b"second");

        assert_ne!(
            EvidenceSpool::link(None, &formerly_ambiguous_record),
            EvidenceSpool::link(Some(&first), b"second")
        );
    }

    #[test]
    fn external_checkpoint_detects_coordinated_prefix_truncation() {
        let mut s = EvidenceSpool::new(8, 4096);
        s.append(b"one");
        s.append(b"two");
        let expected_records = s.len();
        let expected_head = s.chain_head();

        s.records.pop();
        s.chain.pop();
        s.total_bytes -= b"two".len();

        assert!(s.verify_chain(), "the retained prefix is internally valid");
        assert!(!s.verify_chain_against(expected_records, expected_head));
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
