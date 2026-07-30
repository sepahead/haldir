//! Bounded, optionally session-bound challenge table (spec §GateChallengeV1
//! processing rules).
//!
//! A nonce is accepted for a lease only while it remains pending, unexpired, and
//! unused. Consumed and expired nonces remain as bounded tombstones, so they
//! cannot be reactivated during the table's lifetime.

use haldir_contracts::ids::ChallengeNonce;
use haldir_contracts::session::NcpSessionIdentityV1;
use haldir_core::time::MonoInstant;

const DEFAULT_RETAINED_PER_PENDING: usize = 64;

#[derive(Clone, Copy, PartialEq, Eq)]
enum ChallengeState {
    Pending,
    Retired,
}

struct Entry {
    nonce: ChallengeNonce,
    expires_at: MonoInstant,
    state: ChallengeState,
}

/// A bounded table of Gate challenges for one vehicle.
///
/// [`Self::for_session`] creates the immutable session binding required for
/// mission-lease acceptance. [`Self::new`] remains available for standalone
/// nonce tracking, but an unbound table cannot authorize a lease.
///
/// Retired entries are retained until the table is dropped. This makes nonce
/// one-shot use structural while bounding memory; registration fails closed if
/// the retained-entry limit is exhausted.
#[derive(Default)]
pub struct ChallengeTable {
    session: Option<NcpSessionIdentityV1>,
    entries: Vec<Entry>,
    max_pending: usize,
    max_retained: usize,
}

impl ChallengeTable {
    /// A new unbound table permitting `max` concurrent pending challenges.
    ///
    /// The retained-entry limit is `max * 64`, saturating at [`usize::MAX`].
    /// Use [`Self::for_session`] for a table passed to mission-lease acceptance.
    #[must_use]
    pub fn new(max: usize) -> Self {
        Self {
            session: None,
            entries: Vec::new(),
            max_pending: max,
            max_retained: default_retained_limit(max),
        }
    }

    /// A new table bound immutably to one exact session identity.
    ///
    /// The retained-entry limit is `max_pending * 64`, saturating at
    /// [`usize::MAX`]. A session change requires retiring the owner and
    /// constructing a new table; this type deliberately exposes no rebind path.
    #[must_use]
    pub fn for_session(session: NcpSessionIdentityV1, max_pending: usize) -> Self {
        Self::for_session_with_limits(session, max_pending, default_retained_limit(max_pending))
    }

    /// A new session-bound table with independent pending and retained bounds.
    ///
    /// If `max_retained` is smaller than `max_pending`, the retained bound is the
    /// effective registration limit.
    #[must_use]
    pub fn for_session_with_limits(
        session: NcpSessionIdentityV1,
        max_pending: usize,
        max_retained: usize,
    ) -> Self {
        Self {
            session: Some(session),
            entries: Vec::new(),
            max_pending,
            max_retained,
        }
    }

    /// Register a fresh pending challenge at trusted monotonic time `now`.
    /// Returns false if the proposed challenge is already expired, the nonce is
    /// already known, the pending bound is full, or the retained bound is
    /// exhausted.
    pub fn insert(
        &mut self,
        nonce: ChallengeNonce,
        expires_at: MonoInstant,
        now: MonoInstant,
    ) -> bool {
        self.retire_expired(now);
        if expires_at < now {
            return false;
        }
        if self.entries.iter().any(|entry| entry.nonce == nonce)
            || self.len() >= self.max_pending
            || self.entries.len() >= self.max_retained
        {
            return false;
        }
        self.entries.push(Entry {
            nonce,
            expires_at,
            state: ChallengeState::Pending,
        });
        true
    }

    /// Consume a nonce if it is pending and unexpired.
    ///
    /// Expired entries are retired before lookup. Successful consumption also
    /// retires the entry, immediately releasing pending capacity while retaining
    /// a bounded tombstone.
    pub fn consume(&mut self, nonce: &ChallengeNonce, now: MonoInstant) -> bool {
        self.retire_expired(now);
        let Some(entry) = self
            .entries
            .iter_mut()
            .find(|entry| entry.state == ChallengeState::Pending && &entry.nonce == nonce)
        else {
            return false;
        };
        entry.state = ChallengeState::Retired;
        true
    }

    /// Whether a nonce is currently pending and unexpired.
    #[must_use]
    pub fn is_pending(&self, nonce: &ChallengeNonce, now: MonoInstant) -> bool {
        self.entries.iter().any(|entry| {
            entry.state == ChallengeState::Pending
                && &entry.nonce == nonce
                && now <= entry.expires_at
        })
    }

    /// Retire all pending challenges without releasing their tombstones.
    ///
    /// The immutable session binding is preserved. Session-generation changes
    /// require replacing the owning actor and table rather than clearing and
    /// rebinding this table.
    pub fn clear(&mut self) {
        for entry in &mut self.entries {
            entry.state = ChallengeState::Retired;
        }
    }

    /// The exact session identity bound to this table, if any.
    #[must_use]
    pub const fn session(&self) -> Option<&NcpSessionIdentityV1> {
        self.session.as_ref()
    }

    /// The number of entries currently marked pending.
    ///
    /// Expired entries are retired on the next time-aware [`Self::insert`] or
    /// [`Self::consume`] operation.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries
            .iter()
            .filter(|entry| entry.state == ChallengeState::Pending)
            .count()
    }

    /// The number of retained entries, including retired tombstones.
    #[must_use]
    pub fn retained_len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the table has no pending challenge entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn retire_expired(&mut self, now: MonoInstant) {
        for entry in &mut self.entries {
            if entry.state == ChallengeState::Pending && entry.expires_at < now {
                entry.state = ChallengeState::Retired;
            }
        }
    }
}

const fn default_retained_limit(max_pending: usize) -> usize {
    max_pending.saturating_mul(DEFAULT_RETAINED_PER_PENDING)
}

#[cfg(test)]
mod tests {
    use haldir_contracts::scalar::{AsciiId, CanonicalUuidV4String};

    use super::*;

    fn nonce(seed: u8) -> ChallengeNonce {
        ChallengeNonce::new([seed; 32])
    }

    fn session(generation: u8) -> NcpSessionIdentityV1 {
        NcpSessionIdentityV1 {
            session_id: AsciiId::new("session-1").unwrap(),
            generation: CanonicalUuidV4String::from_random_bytes([generation; 16]),
        }
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
        assert!(!table.insert(n, at(20), at(10)));
    }

    #[test]
    fn consumed_entry_releases_pending_capacity_but_remains_tombstoned() {
        let mut table = ChallengeTable::new(1);
        let first = nonce(1);
        let second = nonce(2);

        assert!(table.insert(first, at(10), at(0)));
        assert!(!table.insert(second, at(10), at(0)), "live table is full");
        assert!(table.consume(&first, at(5)));
        assert!(table.is_empty());
        assert!(table.insert(second, at(20), at(5)));
        assert!(table.is_pending(&second, at(20)));
        assert!(!table.insert(first, at(20), at(5)));
        assert_eq!(table.retained_len(), 2);
    }

    #[test]
    fn challenge_is_valid_at_exact_expiry_boundary() {
        let mut table = ChallengeTable::new(1);
        let n = nonce(1);

        assert!(table.insert(n, at(10), at(10)));
        assert!(table.consume(&n, at(10)));
        assert!(table.is_empty());
        assert_eq!(table.retained_len(), 1);
    }

    #[test]
    fn expired_entries_release_pending_capacity_but_remain_tombstoned() {
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
        assert!(!table.insert(first, at(30), at(15)));
        assert_eq!(table.retained_len(), 3);
    }

    #[test]
    fn expired_requested_nonce_is_rejected_and_pending_slots_are_reclaimed() {
        let mut table = ChallengeTable::new(2);
        let first = nonce(1);
        let second = nonce(2);

        assert!(table.insert(first, at(10), at(0)));
        assert!(table.insert(second, at(10), at(0)));
        assert!(!table.consume(&first, at(11)));
        assert!(table.is_empty());
        assert!(!table.insert(first, at(20), at(11)));
        assert!(!table.insert(second, at(20), at(11)));
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
        assert!(!table.insert(nonce(1), at(30), at(15)));
    }

    #[test]
    fn registration_rejects_expired_challenge_after_retiring_old_entries() {
        let mut table = ChallengeTable::new(1);
        assert!(table.insert(nonce(1), at(10), at(0)));

        assert!(!table.insert(nonce(2), at(19), at(20)));

        assert!(table.is_empty());
        assert!(table.insert(nonce(3), at(20), at(20)));
        assert!(!table.insert(nonce(1), at(30), at(20)));
    }

    #[test]
    fn clear_releases_pending_capacity_without_reactivating_retired_nonces() {
        let mut table = ChallengeTable::new(2);
        assert!(table.insert(nonce(1), at(10), at(0)));
        assert!(table.insert(nonce(2), at(10), at(0)));

        table.clear();

        assert!(table.is_empty());
        assert!(table.insert(nonce(3), at(20), at(0)));
        assert!(table.insert(nonce(4), at(20), at(0)));
        assert!(!table.insert(nonce(1), at(20), at(0)));
        assert_eq!(table.retained_len(), 4);
    }

    #[test]
    fn retained_capacity_exhaustion_fails_closed() {
        let mut table = ChallengeTable::for_session_with_limits(session(1), 1, 1);
        let first = nonce(1);

        assert!(table.insert(first, at(10), at(0)));
        assert!(table.consume(&first, at(5)));
        assert!(!table.insert(nonce(2), at(20), at(5)));
        assert_eq!(table.retained_len(), 1);
    }

    #[test]
    fn session_binding_is_immutable_for_table_lifetime() {
        let bound = session(1);
        let mut table = ChallengeTable::for_session(bound.clone(), 2);
        let retired = nonce(1);
        assert!(table.insert(retired, at(10), at(0)));
        assert!(table.consume(&retired, at(5)));

        table.clear();

        assert_eq!(table.session(), Some(&bound));
        assert!(!table.insert(retired, at(20), at(5)));
        assert_eq!(table.retained_len(), 1);
    }

    #[test]
    fn compatibility_constructor_creates_unbound_table() {
        let table = ChallengeTable::new(2);

        assert_eq!(table.session(), None);
    }
}
