//! Reference-plant command, action, and staged-evidence types.

use haldir_contracts::digest::DigestV1;
use haldir_contracts::ids::{DecisionId, GateOutputEpoch, OutputSeq};
use haldir_contracts::session::{NcpSessionIdentityV1, NcpSourceRefV1};

/// Complete provenance attached atomically to every command-related plant event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlantCommandCorrelation {
    /// Decision id (correlation only; caller-supplied and absent from the NCP output frame).
    pub decision_id: DecisionId,
    /// Session carried by the exact output frame.
    pub session: NcpSessionIdentityV1,
    /// Gate output epoch carried by the exact output frame.
    pub output_epoch: GateOutputEpoch,
    /// Gate output sequence carried by the exact output frame.
    pub output_seq: OutputSeq,
    /// Exact-object causal-source correlation. The exact NCP v0.8 JSON bytes
    /// carry epoch/sequence but have no field for `source_key`.
    pub source: NcpSourceRefV1,
    /// Digest of the exact output-frame bytes.
    pub output_frame_digest: DigestV1,
}

/// Why a command was rejected by the receiver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RejectReason {
    /// The exact frame no longer matched its immutable bytes/digest projection.
    InvalidOutputFrame,
    /// The session pair did not match the plant's current session.
    WrongSession,
    /// The output epoch is retired.
    RetiredEpoch,
    /// A different output epoch was presented before the current stream's
    /// command horizon expired.
    PriorStreamLive,
    /// The sequence was a duplicate or lower than the highest accepted.
    DuplicateOrStale,
    /// The current output position was replayed with different exact-object
    /// provenance or bytes. The caller-supplied decision id is correlation-only
    /// and does not turn otherwise identical exact bytes into a conflict. In the
    /// real NCP v0.8 profile, `source_key` is object correlation rather than a
    /// field carried by the serialized JSON frame.
    ConflictingReplay,
}

impl RejectReason {
    /// Stable machine-readable rejection class.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidOutputFrame => "PLANT_REJECT_INVALID_OUTPUT_FRAME",
            Self::WrongSession => "PLANT_REJECT_WRONG_SESSION",
            Self::RetiredEpoch => "PLANT_REJECT_RETIRED_EPOCH",
            Self::PriorStreamLive => "PLANT_REJECT_PRIOR_STREAM_LIVE",
            Self::DuplicateOrStale => "PLANT_REJECT_DUPLICATE_OR_STALE",
            Self::ConflictingReplay => "PLANT_REJECT_CONFLICTING_REPLAY",
        }
    }
}

impl std::fmt::Display for RejectReason {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::error::Error for RejectReason {}

/// A kinematic snapshot recorded in evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KinematicSnapshot {
    /// Position (mm).
    pub position_mm: [i64; 3],
    /// Velocity (mm/s).
    pub velocity_mm_s: [i32; 3],
}

/// A staged plant-evidence event kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlantEventKind {
    /// A command arrived at the receiver.
    Received,
    /// The command passed receiver validation.
    Validated,
    /// The command was accepted into the action buffer, atomically superseding
    /// any previously active command.
    Accepted,
    /// The command was rejected (with reason).
    Rejected(RejectReason),
    /// The command was first selected for an eligible simulation tick.
    Selected,
    /// The command was first applied to the simulated plant.
    Applied,
    /// The active command expired.
    Expired,
    /// A plant-owned safe action began.
    SafeActionStarted,
    /// The plant reached its declared safe (hold) region.
    SafeRegionReached,
    /// A measured plant response consistent with an applied command was observed.
    ResponseObserved,
}

/// A staged plant-evidence event (deterministic, correlated).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlantEvent {
    /// Simulation tick.
    pub tick: u64,
    /// The event kind.
    pub kind: PlantEventKind,
    /// Complete exact-frame correlation for a command-related event.
    ///
    /// Plant-owned safe-action events carry the expired command that caused the
    /// transition. That is causal correlation, not a claim that Gate authored
    /// or selected the safe action.
    pub command: Option<PlantCommandCorrelation>,
    /// The plant state at the event.
    pub state: KinematicSnapshot,
}

impl PlantEvent {
    /// Correlated Gate decision id, if this event concerns a command.
    #[must_use]
    pub fn decision_id(&self) -> Option<DecisionId> {
        self.command.as_ref().map(|command| command.decision_id)
    }

    /// Correlated Gate output sequence, if this event concerns a command.
    #[must_use]
    pub fn output_seq(&self) -> Option<u64> {
        self.command
            .as_ref()
            .map(|command| command.output_seq.get())
    }
}
