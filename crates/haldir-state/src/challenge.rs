//! Bounded pending-challenge table (spec §GateChallengeV1 processing rules).
//!
//! A nonce is accepted for a lease only while it remains pending, unexpired, and
//! unused. A consumed or expired nonce is never reactivated.

use haldir_contracts::ids::ChallengeNonce;
use haldir_core::time::MonoInstant;

struct Pending {
    nonce: ChallengeNonce,
    expires_at: MonoInstant,
    consumed: bool,
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

    /// Register a fresh pending challenge. Returns false if the table is full.
    pub fn insert(&mut self, nonce: ChallengeNonce, expires_at: MonoInstant) -> bool {
        if self.pending.len() >= self.max {
            return false;
        }
        self.pending.push(Pending {
            nonce,
            expires_at,
            consumed: false,
        });
        true
    }

    /// Consume a nonce if it is pending, unexpired, and unused. Marks it consumed.
    pub fn consume(&mut self, nonce: &ChallengeNonce, now: MonoInstant) -> bool {
        for p in &mut self.pending {
            if &p.nonce == nonce && !p.consumed && now <= p.expires_at {
                p.consumed = true;
                return true;
            }
        }
        false
    }

    /// Whether a nonce is currently pending, unexpired, and unused.
    #[must_use]
    pub fn is_pending(&self, nonce: &ChallengeNonce, now: MonoInstant) -> bool {
        self.pending
            .iter()
            .any(|p| &p.nonce == nonce && !p.consumed && now <= p.expires_at)
    }

    /// Drop all pending challenges (e.g. on session generation change).
    pub fn clear(&mut self) {
        self.pending.clear();
    }

    /// The number of tracked challenges.
    #[must_use]
    pub fn len(&self) -> usize {
        self.pending.len()
    }

    /// Whether the table is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }
}
