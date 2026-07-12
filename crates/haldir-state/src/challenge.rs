//! Bounded pending-challenge table (spec §GateChallengeV1 processing rules).
//!
//! A nonce is accepted for a lease only while it remains pending, unexpired, and
//! unused. A consumed or expired nonce is never reactivated.

use haldir_contracts::ids::ChallengeNonce;
use haldir_core::time::MonoInstant;

struct Pending {
    nonce: ChallengeNonce,
    expires_at: MonoInstant,
}

/// A bounded table of pending Gate challenges for one vehicle.
#[derive(Default)]
pub struct ChallengeTable {
    pending: Vec<Pending>,
    max: usize,
}

impl ChallengeTable {
    /// A new table permitting `max` concurrent pending challenges.
    #[must_use]
    pub fn new(max: usize) -> Self {
        Self {
            pending: Vec::new(),
            max,
        }
    }

    /// Register a fresh pending challenge at trusted monotonic time `now`.
    /// Returns false if the proposed challenge is already expired, the nonce is
    /// already pending, or the table is full after expired entries are reclaimed.
    pub fn insert(
        &mut self,
        nonce: ChallengeNonce,
        expires_at: MonoInstant,
        now: MonoInstant,
    ) -> bool {
        self.pending.retain(|p| now <= p.expires_at);
        if expires_at < now {
            return false;
        }
        if self.pending.iter().any(|p| p.nonce == nonce) || self.pending.len() >= self.max {
            return false;
        }
        self.pending.push(Pending { nonce, expires_at });
        true
    }

    /// Consume a nonce if it is pending and unexpired.
    ///
    /// All expired entries are reclaimed before lookup. A successful lookup
    /// removes the entry, making one-time consumption structural rather than a
    /// retained flag and immediately releasing its bounded-table slot.
    pub fn consume(&mut self, nonce: &ChallengeNonce, now: MonoInstant) -> bool {
        self.pending.retain(|p| now <= p.expires_at);
        let Some(index) = self.pending.iter().position(|p| &p.nonce == nonce) else {
            return false;
        };
        self.pending.remove(index);
        true
    }

    /// Whether a nonce is currently pending and unexpired.
    #[must_use]
    pub fn is_pending(&self, nonce: &ChallengeNonce, now: MonoInstant) -> bool {
        self.pending
            .iter()
            .any(|p| &p.nonce == nonce && now <= p.expires_at)
    }

    /// Drop all pending challenges (e.g. on session generation change).
    pub fn clear(&mut self) {
        self.pending.clear();
    }

    /// The number of retained challenge entries.
    ///
    /// Expired entries are removed on the next time-aware [`Self::insert`] or
    /// [`Self::consume`] operation; consumed entries are removed immediately.
    #[must_use]
    pub fn len(&self) -> usize {
        self.pending.len()
    }

    /// Whether the table has no retained challenge entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nonce(seed: u8) -> ChallengeNonce {
        ChallengeNonce::new([seed; 32])
    }

    fn at(ns: u64) -> MonoInstant {
        MonoInstant::from_nanos(ns)
    }

    #[test]
    fn duplicate_nonce_is_rejected_without_replacing_original() {
        let mut table = ChallengeTable::new(2);
        let n = nonce(1);

        assert!(table.insert(n, at(10), at(0)));
        assert!(!table.insert(n, at(20), at(0)));
        assert_eq!(table.len(), 1);
        assert!(table.consume(&n, at(10)));
        assert!(!table.consume(&n, at(10)));
    }

    #[test]
    fn consumed_entry_is_removed_and_capacity_is_reusable() {
        let mut table = ChallengeTable::new(1);
        let first = nonce(1);
        let second = nonce(2);

        assert!(table.insert(first, at(10), at(0)));
        assert!(!table.insert(second, at(10), at(0)), "live table is full");
        assert!(table.consume(&first, at(5)));
        assert!(table.is_empty());
        assert!(table.insert(second, at(20), at(5)));
        assert!(table.is_pending(&second, at(20)));
    }

    #[test]
    fn challenge_is_valid_at_exact_expiry_boundary() {
        let mut table = ChallengeTable::new(1);
        let n = nonce(1);

        assert!(table.insert(n, at(10), at(10)));
        assert!(table.consume(&n, at(10)));
        assert!(table.is_empty());
    }

    #[test]
    fn expired_entries_are_reclaimed_even_when_requested_nonce_is_unknown() {
        let mut table = ChallengeTable::new(2);
        let first = nonce(1);
        let second = nonce(2);
        let replacement = nonce(3);

        assert!(table.insert(first, at(10), at(0)));
        assert!(table.insert(second, at(20), at(0)));
        assert!(!table.consume(&nonce(99), at(15)));
        assert_eq!(table.len(), 1, "only the unexpired entry remains");
        assert!(table.insert(replacement, at(30), at(15)));
        assert_eq!(table.len(), 2);
        assert!(!table.is_pending(&first, at(15)));
        assert!(table.is_pending(&second, at(15)));
        assert!(table.is_pending(&replacement, at(15)));
    }

    #[test]
    fn expired_requested_nonce_is_rejected_and_all_expired_slots_are_reclaimed() {
        let mut table = ChallengeTable::new(2);
        let first = nonce(1);
        let second = nonce(2);

        assert!(table.insert(first, at(10), at(0)));
        assert!(table.insert(second, at(10), at(0)));
        assert!(!table.consume(&first, at(11)));
        assert!(table.is_empty());
        assert!(table.insert(nonce(3), at(20), at(11)));
        assert!(table.insert(nonce(4), at(20), at(11)));
    }

    #[test]
    fn zero_capacity_table_rejects_every_insert() {
        let mut table = ChallengeTable::new(0);

        assert!(!table.insert(nonce(1), at(10), at(0)));
        assert!(table.is_empty());
    }

    #[test]
    fn registration_reclaims_expired_entries_before_capacity_check() {
        let mut table = ChallengeTable::new(2);
        assert!(table.insert(nonce(1), at(10), at(0)));
        assert!(table.insert(nonce(2), at(20), at(0)));

        assert!(table.insert(nonce(3), at(30), at(15)));

        assert_eq!(table.len(), 2);
        assert!(!table.is_pending(&nonce(1), at(15)));
        assert!(table.is_pending(&nonce(2), at(15)));
        assert!(table.is_pending(&nonce(3), at(15)));
    }

    #[test]
    fn registration_rejects_expired_challenge_after_sweeping_old_entries() {
        let mut table = ChallengeTable::new(1);
        assert!(table.insert(nonce(1), at(10), at(0)));

        assert!(!table.insert(nonce(2), at(19), at(20)));

        assert!(table.is_empty());
        assert!(table.insert(nonce(3), at(20), at(20)));
    }

    #[test]
    fn clear_releases_all_capacity() {
        let mut table = ChallengeTable::new(2);
        assert!(table.insert(nonce(1), at(10), at(0)));
        assert!(table.insert(nonce(2), at(10), at(0)));

        table.clear();

        assert!(table.is_empty());
        assert!(table.insert(nonce(3), at(20), at(0)));
        assert!(table.insert(nonce(4), at(20), at(0)));
    }
}
