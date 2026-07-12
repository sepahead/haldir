//! Gate-output stream state (spec S3/S4).
//!
//! Within one Gate output epoch, every new logical output gets a strictly
//! increasing sequence starting at one. An allocated sequence is NEVER reused: a
//! publish failure creates a gap (safer than reuse). A Gate restart or authority
//! transition rotates to a fresh epoch and restarts the sequence at one.

use haldir_contracts::ids::{GateOutputEpoch, OutputSeq};
use std::num::NonZeroU64;

/// An output-stream allocation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputStreamError {
    /// The sequence space is exhausted (would overflow `u64`).
    Exhausted,
}

/// Gate-owned output stream position allocator.
#[derive(Debug, Clone)]
pub struct GateOutputStreamState {
    epoch: GateOutputEpoch,
    next_seq: u64,
    retired_epochs: Vec<GateOutputEpoch>,
    max_retired: usize,
}

impl GateOutputStreamState {
    /// A new stream for `epoch`, first sequence one.
    #[must_use]
    pub fn new(epoch: GateOutputEpoch, max_retired: usize) -> Self {
        Self {
            epoch,
            next_seq: 1,
            retired_epochs: Vec::new(),
            max_retired,
        }
    }

    /// The current output epoch.
    #[must_use]
    pub fn current_epoch(&self) -> GateOutputEpoch {
        self.epoch
    }

    /// The next sequence that would be allocated (for status/tests).
    #[must_use]
    pub const fn peek_next_seq(&self) -> u64 {
        self.next_seq
    }

    /// Allocate the next output sequence. Never reuses a prior value.
    ///
    /// # Errors
    /// Returns [`OutputStreamError::Exhausted`] if the sequence space is full.
    pub fn allocate(&mut self) -> Result<OutputSeq, OutputStreamError> {
        let seq = NonZeroU64::new(self.next_seq).ok_or(OutputStreamError::Exhausted)?;
        self.next_seq = self
            .next_seq
            .checked_add(1)
            .ok_or(OutputStreamError::Exhausted)?;
        Ok(OutputSeq::new(seq))
    }

    /// Rotate to a fresh epoch (restart / authority transition), retiring the old
    /// one and restarting the sequence at one. A retired epoch is never revived.
    ///
    /// # Errors
    /// Returns [`OutputStreamError::Exhausted`] if the retired-epoch set is full.
    pub fn rotate_epoch(&mut self, new_epoch: GateOutputEpoch) -> Result<(), OutputStreamError> {
        if self.retired_epochs.len() >= self.max_retired {
            return Err(OutputStreamError::Exhausted);
        }
        self.retired_epochs.push(self.epoch);
        self.epoch = new_epoch;
        self.next_seq = 1;
        Ok(())
    }

    /// Whether an epoch has been retired.
    #[must_use]
    pub fn is_retired(&self, epoch: &GateOutputEpoch) -> bool {
        self.retired_epochs.contains(epoch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use haldir_contracts::scalar::CanonicalUuidV4String;

    fn epoch(n: u8) -> GateOutputEpoch {
        GateOutputEpoch::new(CanonicalUuidV4String::from_random_bytes([n; 16]))
    }

    #[test]
    fn allocates_strictly_increasing_from_one_and_never_reuses() {
        let mut s = GateOutputStreamState::new(epoch(1), 8);
        let a = s.allocate().unwrap();
        let b = s.allocate().unwrap();
        let c = s.allocate().unwrap();
        assert_eq!(a.get(), 1);
        assert_eq!(b.get(), 2);
        assert_eq!(c.get(), 3);
        assert!(a.get() < b.get() && b.get() < c.get());
    }

    #[test]
    fn rotate_retires_old_epoch_and_restarts_sequence() {
        let mut s = GateOutputStreamState::new(epoch(1), 8);
        let _ = s.allocate().unwrap();
        let _ = s.allocate().unwrap();
        let old = s.current_epoch();
        s.rotate_epoch(epoch(2)).unwrap();
        assert!(s.is_retired(&old));
        assert_eq!(s.allocate().unwrap().get(), 1, "sequence restarts at one");
        assert_ne!(s.current_epoch(), old);
    }
}
