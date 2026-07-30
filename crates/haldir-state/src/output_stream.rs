//! Gate-output stream state (spec S3/S4).
//!
//! Within one Gate output epoch, every new logical output gets a strictly
//! increasing sequence starting at one. An allocated sequence is NEVER reused: a
//! publish failure creates a gap (safer than reuse). A Gate restart or authority
//! transition rotates to a fresh epoch and restarts the sequence at one.

use haldir_contracts::ids::{GateOutputEpoch, OutputSeq};
use std::num::NonZeroU64;

/// An output-stream allocation or epoch-rotation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum OutputStreamError {
    /// The sequence space or bounded retired-epoch capacity is exhausted.
    Exhausted,
    /// The requested epoch is already the active epoch.
    EpochAlreadyActive,
    /// The requested epoch has been retired and cannot be reactivated.
    RetiredEpoch,
}

impl OutputStreamError {
    /// Stable machine-readable failure class.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Exhausted => "OUTPUT_STREAM_EXHAUSTED",
            Self::EpochAlreadyActive => "OUTPUT_STREAM_EPOCH_ALREADY_ACTIVE",
            Self::RetiredEpoch => "OUTPUT_STREAM_RETIRED_EPOCH",
        }
    }
}

impl std::fmt::Display for OutputStreamError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::error::Error for OutputStreamError {}

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
    /// Returns [`OutputStreamError::EpochAlreadyActive`] if `new_epoch` is
    /// already active, [`OutputStreamError::RetiredEpoch`] if it was previously
    /// retired, or [`OutputStreamError::Exhausted`] if the retired-epoch set is
    /// full.
    pub fn rotate_epoch(&mut self, new_epoch: GateOutputEpoch) -> Result<(), OutputStreamError> {
        if new_epoch == self.epoch {
            return Err(OutputStreamError::EpochAlreadyActive);
        }
        if self.retired_epochs.contains(&new_epoch) {
            return Err(OutputStreamError::RetiredEpoch);
        }
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

    fn assert_state_unchanged(state: &GateOutputStreamState, before: &GateOutputStreamState) {
        assert_eq!(
            (
                state.epoch,
                state.next_seq,
                state.retired_epochs.as_slice(),
                state.max_retired,
            ),
            (
                before.epoch,
                before.next_seq,
                before.retired_epochs.as_slice(),
                before.max_retired,
            )
        );
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

    #[test]
    fn rotate_rejects_active_epoch_without_mutating_stream_position() {
        let active = epoch(1);
        let mut s = GateOutputStreamState::new(active, 8);
        let _ = s.allocate().unwrap();
        let before = s.clone();

        assert_eq!(
            s.rotate_epoch(active),
            Err(OutputStreamError::EpochAlreadyActive)
        );
        assert_state_unchanged(&s, &before);
    }

    #[test]
    fn rotate_rejects_retired_epoch_without_reactivating_or_reusing_position() {
        let retired = epoch(1);
        let active = epoch(2);
        let mut s = GateOutputStreamState::new(retired, 1);
        s.rotate_epoch(active).unwrap();
        let _ = s.allocate().unwrap();
        let before = s.clone();

        assert_eq!(
            s.rotate_epoch(retired),
            Err(OutputStreamError::RetiredEpoch)
        );
        assert_state_unchanged(&s, &before);
        assert_eq!(s.allocate().unwrap().get(), 2);
    }

    #[test]
    fn output_stream_errors_have_stable_codes_and_standard_error_display() {
        for (error, expected) in [
            (OutputStreamError::Exhausted, "OUTPUT_STREAM_EXHAUSTED"),
            (
                OutputStreamError::EpochAlreadyActive,
                "OUTPUT_STREAM_EPOCH_ALREADY_ACTIVE",
            ),
            (
                OutputStreamError::RetiredEpoch,
                "OUTPUT_STREAM_RETIRED_EPOCH",
            ),
        ] {
            assert_eq!(error.as_str(), expected);
            assert_eq!(error.to_string(), expected);
            let _: &dyn std::error::Error = &error;
        }
    }
}
