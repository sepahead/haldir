//! Controller-intent replay state (spec §Controller intent replay state, B3).
//!
//! Two-phase: [`ControllerReplayState::classify`] is side-effect free (used for
//! the cheap checks 1–13, which must NOT advance replay state);
//! [`ControllerReplayState::commit_consume`] advances `last_seq` and is called
//! once authority/scope checks pass — a correctly-signed, correctly-scoped fresh
//! intent consumes its sequence even if mission policy later denies it. A retired
//! epoch always rejects; tombstone overflow quiesces rather than evicting.

use haldir_contracts::ids::IntentEpoch;
use std::collections::BTreeSet;

/// The classification of an intent position against replay state (no mutation).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayClass {
    /// First intent of a fresh epoch at sequence one.
    FreshFirst,
    /// Same active epoch, sequence strictly greater than the last.
    FreshContinue,
    /// Same active epoch, sequence not greater than the last (replay/stale).
    ReplayStale,
    /// Epoch is in the retired tombstone set.
    RetiredEpoch,
    /// A different, non-retired epoch while one is active (MVP: needs a fresh lease).
    EpochTransitionForbidden,
    /// First intent but not at sequence one.
    BadInitialSequence,
    /// The tombstone set is full; the lease must quiesce (never evict-and-reopen).
    TombstoneFull,
}

impl ReplayClass {
    /// Whether this class is a fresh, consumable intent.
    #[must_use]
    pub const fn is_fresh(self) -> bool {
        matches!(self, Self::FreshFirst | Self::FreshContinue)
    }
}

/// Per-active-lease controller replay state.
#[derive(Debug, Clone)]
pub struct ControllerReplayState {
    active_epoch: Option<IntentEpoch>,
    last_seq: u64,
    retired: BTreeSet<[u8; 16]>,
    max_retired: usize,
    consumed_count: u64,
}

impl ControllerReplayState {
    /// A fresh replay state with a bounded tombstone set.
    #[must_use]
    pub fn new(max_retired: usize) -> Self {
        Self {
            active_epoch: None,
            last_seq: 0,
            retired: BTreeSet::new(),
            max_retired,
            consumed_count: 0,
        }
    }

    /// The number of consumed intents.
    #[must_use]
    pub const fn consumed_count(&self) -> u64 {
        self.consumed_count
    }

    /// Classify `(epoch, seq)` without mutating state.
    #[must_use]
    pub fn classify(&self, epoch: IntentEpoch, seq: u64) -> ReplayClass {
        if self.retired.contains(epoch.as_bytes()) {
            return ReplayClass::RetiredEpoch;
        }
        match self.active_epoch {
            Some(active) if active == epoch => {
                if seq > self.last_seq {
                    ReplayClass::FreshContinue
                } else {
                    ReplayClass::ReplayStale
                }
            }
            Some(_) => ReplayClass::EpochTransitionForbidden,
            None => {
                if seq == 1 {
                    ReplayClass::FreshFirst
                } else {
                    ReplayClass::BadInitialSequence
                }
            }
        }
    }

    /// Commit a fresh intent, advancing `last_seq` and activating the epoch.
    /// Consumes the sequence regardless of the later policy outcome.
    ///
    /// # Errors
    /// Returns the non-fresh [`ReplayClass`] if `(epoch, seq)` is not fresh.
    pub fn commit_consume(&mut self, epoch: IntentEpoch, seq: u64) -> Result<(), ReplayClass> {
        match self.classify(epoch, seq) {
            ReplayClass::FreshFirst | ReplayClass::FreshContinue => {
                self.active_epoch = Some(epoch);
                self.last_seq = seq;
                self.consumed_count = self.consumed_count.saturating_add(1);
                Ok(())
            }
            other => Err(other),
        }
    }

    /// Retire the active epoch (on lease end, controller restart, or handoff).
    /// A retired epoch can never become active again under this lease.
    ///
    /// # Errors
    /// Returns [`ReplayClass::TombstoneFull`] if the tombstone set is full; the
    /// caller must require a fresh lease rather than evicting an old epoch.
    pub fn retire_active(&mut self) -> Result<(), ReplayClass> {
        if let Some(active) = self.active_epoch {
            if self.retired.len() >= self.max_retired {
                return Err(ReplayClass::TombstoneFull);
            }
            self.retired.insert(*active.as_bytes());
            self.active_epoch = None;
            self.last_seq = 0;
        }
        Ok(())
    }

    /// Whether an epoch has been retired.
    #[must_use]
    pub fn is_retired(&self, epoch: IntentEpoch) -> bool {
        self.retired.contains(epoch.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ep(n: u8) -> IntentEpoch {
        IntentEpoch::new([n; 16])
    }

    #[test]
    fn first_must_be_seq_one_then_monotone() {
        let mut r = ControllerReplayState::new(4);
        assert_eq!(r.classify(ep(1), 2), ReplayClass::BadInitialSequence);
        assert_eq!(r.classify(ep(1), 1), ReplayClass::FreshFirst);
        r.commit_consume(ep(1), 1).unwrap();
        assert_eq!(r.classify(ep(1), 1), ReplayClass::ReplayStale);
        assert_eq!(r.classify(ep(1), 2), ReplayClass::FreshContinue);
        r.commit_consume(ep(1), 2).unwrap();
        // gap is allowed
        assert_eq!(r.classify(ep(1), 10), ReplayClass::FreshContinue);
    }

    #[test]
    fn replay_does_not_consume_or_advance() {
        let mut r = ControllerReplayState::new(4);
        r.commit_consume(ep(1), 1).unwrap();
        let before = r.consumed_count();
        assert!(r.commit_consume(ep(1), 1).is_err()); // replay
        assert_eq!(r.consumed_count(), before, "replay must not consume");
    }

    #[test]
    fn retired_epoch_never_reactivates() {
        let mut r = ControllerReplayState::new(4);
        r.commit_consume(ep(1), 1).unwrap();
        r.retire_active().unwrap();
        // Even a huge sequence cannot revive a retired epoch.
        assert_eq!(r.classify(ep(1), u64::MAX), ReplayClass::RetiredEpoch);
        assert!(r.commit_consume(ep(1), 5).is_err());
    }

    #[test]
    fn different_epoch_forbidden_in_mvp() {
        let mut r = ControllerReplayState::new(4);
        r.commit_consume(ep(1), 1).unwrap();
        assert_eq!(r.classify(ep(2), 1), ReplayClass::EpochTransitionForbidden);
    }

    #[test]
    fn tombstone_full_quiesces_not_evicts() {
        let mut r = ControllerReplayState::new(1);
        r.commit_consume(ep(1), 1).unwrap();
        r.retire_active().unwrap();
        r.commit_consume(ep(2), 1).unwrap();
        // second retire would overflow the 1-slot tombstone set
        assert_eq!(r.retire_active(), Err(ReplayClass::TombstoneFull));
        // ep(1) is still retired (not evicted)
        assert!(r.is_retired(ep(1)));
    }
}
