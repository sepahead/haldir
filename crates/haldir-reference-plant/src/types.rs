//! Reference-plant command, action, and staged-evidence types.

use haldir_contracts::digest::DigestV1;
use haldir_contracts::ids::{DecisionId, GateOutputEpoch, OutputSeq};
use haldir_contracts::session::{NcpSessionIdentityV1, NcpSourceRefV1};

/// A plant-facing action (fixed-point).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlantAction {
    /// Hold at zero velocity.
    Hold,
    /// Local-NED velocity setpoint (mm/s).
    Velocity([i32; 3]),
}

impl PlantAction {
    /// The commanded velocity vector (`Hold` is zero).
    #[must_use]
    pub const fn velocity(self) -> [i32; 3] {
        match self {
            Self::Hold => [0, 0, 0],
            Self::Velocity(v) => v,
        }
    }
}

/// A Gate-authored plant command. This is the ONLY input that can change the
/// plant's commanded velocity; there is no other ingress (spec A1/B15).
#[derive(Debug, Clone)]
pub struct PlantCommand {
    /// The originating Gate decision id (correlation only, non-authoritative).
    pub decision_id: DecisionId,
    /// The session the command was published under.
    pub session: NcpSessionIdentityV1,
    /// The Gate output stream epoch.
    pub output_epoch: GateOutputEpoch,
    /// The Gate output stream sequence.
    pub output_seq: OutputSeq,
    /// The causal source reference.
    pub source: NcpSourceRefV1,
    /// The requested action.
    pub action: PlantAction,
    /// Command validity window (ms).
    pub validity_ms: u32,
    /// The exact output frame digest.
    pub output_frame_digest: DigestV1,
}

/// Why a command was rejected by the receiver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectReason {
    /// The session pair did not match the plant's current session.
    WrongSession,
    /// The output epoch is retired.
    RetiredEpoch,
    /// The sequence was a duplicate or lower than the highest accepted.
    DuplicateOrStale,
    /// The validity was zero.
    ZeroValidity,
}

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
    /// The command was accepted into the action buffer.
    Accepted,
    /// The command was rejected (with reason).
    Rejected(RejectReason),
    /// The command was selected as the active command for a tick.
    Selected,
    /// The command was applied to the plant this tick.
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlantEvent {
    /// Simulation tick.
    pub tick: u64,
    /// The event kind.
    pub kind: PlantEventKind,
    /// Correlated Gate decision id, if applicable.
    pub decision_id: Option<DecisionId>,
    /// Correlated output sequence, if applicable.
    pub output_seq: Option<u64>,
    /// The plant state at the event.
    pub state: KinematicSnapshot,
}
