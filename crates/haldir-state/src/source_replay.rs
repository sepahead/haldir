//! Bounded replay state for trusted upstream source streams.
//!
//! Source epochs are opaque identities, not timestamps. For each source key we
//! therefore retain one active epoch plus non-evicting tombstones for every
//! epoch observed earlier in this Gate boot. Sequence numbers must strictly
//! advance within the active epoch. A new source key or epoch may attach at any
//! nonzero sequence because Gate can join an already-running upstream stream.

use haldir_contracts::scalar::{BoundedAscii, CanonicalUuidV4String};
use haldir_contracts::session::NcpSourceRefV1;

/// Classification of one trusted source position against the boot-local cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceReplayClass {
    /// First observed epoch for this source key.
    FreshSource,
    /// Strictly advancing sequence in the active epoch.
    FreshContinue,
    /// First position in a new epoch; the prior active epoch will be retired.
    FreshEpoch,
    /// Sequence did not strictly advance in the active epoch.
    ReplayStale,
    /// The position names an epoch already retired in this Gate boot.
    RetiredEpoch,
    /// Retaining another source epoch would exceed the non-evicting logical or
    /// backing-allocation bound.
    CapacityExhausted,
}

impl SourceReplayClass {
    /// Whether this class can be committed without weakening replay protection.
    #[must_use]
    pub const fn is_fresh(self) -> bool {
        matches!(
            self,
            Self::FreshSource | Self::FreshContinue | Self::FreshEpoch
        )
    }
}

#[derive(Debug, Clone)]
struct SourceEpochWatermark {
    source_key: String,
    epoch: CanonicalUuidV4String,
    last_seq: u64,
    active: bool,
}

/// Boot-local, bounded source-stream replay state.
///
/// Entries and retired epochs are never evicted: when the bound is exhausted,
/// an unseen source epoch is rejected rather than reopening a replay window.
#[derive(Debug, Clone)]
pub struct SourceStreamReplayState {
    streams: Vec<SourceEpochWatermark>,
    max_streams: usize,
}

impl SourceStreamReplayState {
    /// Construct empty replay state with a hard retained-stream bound.
    #[must_use]
    pub const fn new(max_streams: usize) -> Self {
        Self {
            streams: Vec::new(),
            max_streams,
        }
    }

    /// Classify a source position without mutating replay state.
    #[must_use]
    pub fn classify(&self, source: &NcpSourceRefV1) -> SourceReplayClass {
        let source_key = source.source_key.as_str();
        if let Some(stream) = self.streams.iter().find(|stream| {
            stream.source_key.as_str() == source_key && stream.epoch == source.stream_epoch
        }) {
            if !stream.active {
                return SourceReplayClass::RetiredEpoch;
            }
            return if source.stream_seq.get() > stream.last_seq {
                SourceReplayClass::FreshContinue
            } else {
                SourceReplayClass::ReplayStale
            };
        }

        if self.streams.len() >= self.max_streams {
            return SourceReplayClass::CapacityExhausted;
        }
        if self
            .streams
            .iter()
            .any(|stream| stream.active && stream.source_key.as_str() == source_key)
        {
            SourceReplayClass::FreshEpoch
        } else {
            SourceReplayClass::FreshSource
        }
    }

    /// Commit one fresh source position transactionally.
    ///
    /// # Errors
    /// Returns the exact non-fresh classification without changing any entry.
    pub fn commit(&mut self, source: &NcpSourceRefV1) -> Result<(), SourceReplayClass> {
        let class = self.classify(source);
        match class {
            SourceReplayClass::FreshContinue => {
                let Some(stream) = self.streams.iter_mut().find(|stream| {
                    stream.active
                        && stream.source_key.as_str() == source.source_key.as_str()
                        && stream.epoch == source.stream_epoch
                }) else {
                    return Err(SourceReplayClass::ReplayStale);
                };
                stream.last_seq = source.stream_seq.get();
            }
            SourceReplayClass::FreshEpoch => {
                // Reserve and construct the new owned entry before retiring the
                // current epoch. A fallible backing allocation must not reopen
                // the source key by leaving it without an active watermark.
                self.streams
                    .try_reserve(1)
                    .map_err(|_| SourceReplayClass::CapacityExhausted)?;
                let next = SourceEpochWatermark {
                    source_key: try_copy_source_key(&source.source_key)?,
                    epoch: source.stream_epoch,
                    last_seq: source.stream_seq.get(),
                    active: true,
                };
                let Some(active) = self.streams.iter_mut().find(|stream| {
                    stream.active && stream.source_key.as_str() == source.source_key.as_str()
                }) else {
                    return Err(SourceReplayClass::ReplayStale);
                };
                active.active = false;
                self.streams.push(next);
            }
            SourceReplayClass::FreshSource => {
                self.streams
                    .try_reserve(1)
                    .map_err(|_| SourceReplayClass::CapacityExhausted)?;
                let next = SourceEpochWatermark {
                    source_key: try_copy_source_key(&source.source_key)?,
                    epoch: source.stream_epoch,
                    last_seq: source.stream_seq.get(),
                    active: true,
                };
                self.streams.push(next);
            }
            non_fresh => return Err(non_fresh),
        }
        Ok(())
    }

    /// Number of retained active and retired source epochs.
    #[must_use]
    pub const fn retained_streams(&self) -> usize {
        self.streams.len()
    }
}

fn try_copy_source_key(source_key: &BoundedAscii<256>) -> Result<String, SourceReplayClass> {
    let mut retained = String::new();
    retained
        .try_reserve_exact(source_key.as_str().len())
        .map_err(|_| SourceReplayClass::CapacityExhausted)?;
    retained.push_str(source_key.as_str());
    Ok(retained)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::num::NonZeroU64;
    use haldir_contracts::ids::SourceSeq;

    fn source(key: &str, epoch: u8, seq: u64) -> NcpSourceRefV1 {
        NcpSourceRefV1 {
            source_key: BoundedAscii::new(key).unwrap(),
            stream_epoch: CanonicalUuidV4String::from_random_bytes([epoch; 16]),
            stream_seq: SourceSeq::new(NonZeroU64::new(seq).unwrap()),
        }
    }

    #[test]
    fn active_epoch_strictly_advances_and_gaps_are_allowed() {
        let mut replay = SourceStreamReplayState::new(4);
        let first = source("pose", 1, 7);
        assert_eq!(replay.classify(&first), SourceReplayClass::FreshSource);
        replay.commit(&first).unwrap();
        assert_eq!(replay.classify(&first), SourceReplayClass::ReplayStale);
        replay.commit(&source("pose", 1, 99)).unwrap();
        assert_eq!(
            replay.classify(&source("pose", 1, 8)),
            SourceReplayClass::ReplayStale
        );
    }

    #[test]
    fn epoch_transition_retires_without_ordering_opaque_epoch_ids() {
        let mut replay = SourceStreamReplayState::new(4);
        replay.commit(&source("pose", 9, 42)).unwrap();
        replay.commit(&source("pose", 2, 3)).unwrap();
        assert_eq!(
            replay.classify(&source("pose", 9, u64::MAX)),
            SourceReplayClass::RetiredEpoch
        );
    }

    #[test]
    fn source_keys_advance_independently() {
        let mut replay = SourceStreamReplayState::new(4);
        replay.commit(&source("pose-a", 1, 7)).unwrap();
        replay.commit(&source("pose-b", 1, 2)).unwrap();
        replay.commit(&source("pose-a", 1, 8)).unwrap();
        assert_eq!(replay.retained_streams(), 2);
    }

    #[test]
    fn full_cache_never_evicts_a_replay_tombstone() {
        let mut replay = SourceStreamReplayState::new(2);
        let retired = source("pose", 1, 7);
        replay.commit(&retired).unwrap();
        replay.commit(&source("pose", 2, 1)).unwrap();
        assert_eq!(
            replay.classify(&source("other", 3, 1)),
            SourceReplayClass::CapacityExhausted
        );
        assert_eq!(replay.classify(&retired), SourceReplayClass::RetiredEpoch);
    }
}
