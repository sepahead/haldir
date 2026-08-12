//! Validated exact-command capability shared by Gate and command consumers.
//!
//! This type belongs at the NCP boundary rather than in the reference plant:
//! Gate uses it in every publication profile, while the plant is only one
//! simulation consumer. Construction derives every authoritative field from one
//! self-consistent [`ExactNcpCommandFrame`]. The decision id remains explicitly
//! correlation-only because NCP v0.8 does not carry it on the wire.

use core::num::NonZeroU32;

use haldir_contracts::digest::DigestV1;
use haldir_contracts::ids::{DecisionId, GateOutputEpoch, OutputSeq};
use haldir_contracts::session::{NcpSessionIdentityV1, NcpSourceRefV1};

use crate::ExactNcpCommandFrame;

/// Fixed-point action derived from a validated exact NCP command frame.
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
            Self::Velocity(velocity) => velocity,
        }
    }
}

/// A validated exact NCP command plus Gate-local decision correlation.
///
/// All authoritative command fields are read from `exact_frame`; the decision
/// id is correlation-only and is not carried by the NCP command frame.
/// Construction proves exact-frame self-consistency, not that a Gate authored
/// the frame or that the caller is authorized to publish it.
#[derive(Debug, PartialEq)]
pub struct PlantCommand {
    decision_id: DecisionId,
    exact_frame: ExactNcpCommandFrame,
    action: PlantAction,
    validity_ms: NonZeroU32,
}

impl PlantCommand {
    /// Bind a correlation-only decision id to one self-consistent exact frame.
    ///
    /// # Errors
    /// Returns [`PlantCommandError::InvalidExactFrame`] if the frame's semantic
    /// projection for its wire profile, bytes, digest, or transformation relation
    /// disagree.
    pub fn from_exact_frame(
        decision_id: DecisionId,
        exact_frame: ExactNcpCommandFrame,
    ) -> Result<Self, PlantCommandError> {
        if !exact_frame.is_self_consistent() {
            return Err(PlantCommandError::InvalidExactFrame);
        }
        let action = if exact_frame.is_hold() {
            PlantAction::Hold
        } else {
            PlantAction::Velocity(
                exact_frame
                    .decoded_velocity_mm_s()
                    .map_err(|_| PlantCommandError::InvalidExactFrame)?,
            )
        };
        let validity_ms = NonZeroU32::new(exact_frame.validity_ms())
            .ok_or(PlantCommandError::InvalidExactFrame)?;
        Ok(Self {
            decision_id,
            exact_frame,
            action,
            validity_ms,
        })
    }

    /// Correlation-only decision id supplied by the Gate.
    #[must_use]
    pub const fn decision_id(&self) -> DecisionId {
        self.decision_id
    }

    /// Exact immutable NCP command frame.
    #[must_use]
    pub const fn exact_frame(&self) -> &ExactNcpCommandFrame {
        &self.exact_frame
    }

    /// Session carried by the exact frame.
    #[must_use]
    pub const fn session(&self) -> &NcpSessionIdentityV1 {
        self.exact_frame.session()
    }

    /// Gate output epoch carried by the exact frame.
    #[must_use]
    pub const fn output_epoch(&self) -> GateOutputEpoch {
        self.exact_frame.stream().epoch
    }

    /// Gate output sequence carried by the exact frame.
    #[must_use]
    pub const fn output_seq(&self) -> OutputSeq {
        self.exact_frame.stream().seq
    }

    /// Causal source carried by the exact frame.
    #[must_use]
    pub const fn source(&self) -> &NcpSourceRefV1 {
        self.exact_frame.source()
    }

    /// Fixed-point action carried by the exact frame.
    #[must_use]
    pub const fn action(&self) -> PlantAction {
        self.action
    }

    /// Command validity carried by the exact frame (ms).
    #[must_use]
    pub const fn validity_ms(&self) -> u32 {
        self.validity_ms.get()
    }

    /// Digest of the exact output-frame bytes.
    #[must_use]
    pub const fn output_frame_digest(&self) -> DigestV1 {
        self.exact_frame.digest()
    }
}

/// A structurally inconsistent exact frame cannot become a command capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PlantCommandError {
    /// Semantic fields, bytes, digest, or transformation relation disagreed.
    InvalidExactFrame,
}

impl PlantCommandError {
    /// Stable machine-readable failure class.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidExactFrame => "PLANT_COMMAND_INVALID_EXACT_FRAME",
        }
    }
}

impl core::fmt::Display for PlantCommandError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::error::Error for PlantCommandError {}

#[cfg(test)]
mod tests {
    use super::*;
    use core::num::{NonZeroU32, NonZeroU64};
    use haldir_contracts::action::RequestedActionV1;
    use haldir_contracts::ids::{GateOutputEpoch, OutputSeq, SourceSeq};
    use haldir_contracts::scalar::{AsciiId, BoundedAscii, CanonicalUuidV4String};
    use haldir_contracts::session::NcpStreamPositionV1;

    use crate::{AclOnlyAdapter, GateCommandBuildInputV1, NcpCommandAdapter};

    fn input(action: RequestedActionV1) -> GateCommandBuildInputV1 {
        GateCommandBuildInputV1 {
            session: NcpSessionIdentityV1 {
                session_id: AsciiId::new("sess-1").unwrap(),
                generation: CanonicalUuidV4String::from_random_bytes([1; 16]),
            },
            stream: NcpStreamPositionV1 {
                epoch: GateOutputEpoch::new(CanonicalUuidV4String::from_random_bytes([2; 16])),
                seq: OutputSeq::new(NonZeroU64::new(3).unwrap()),
            },
            source: NcpSourceRefV1 {
                source_key: BoundedAscii::new("veh/uav-1/state/pose").unwrap(),
                stream_epoch: CanonicalUuidV4String::from_random_bytes([4; 16]),
                stream_seq: SourceSeq::new(NonZeroU64::new(5).unwrap()),
            },
            frame_id: BoundedAscii::new("map").unwrap(),
            source_t_ns: 6,
            gate_t_ns: 7,
            action,
            effective_validity_ms: 200,
        }
    }

    #[test]
    fn command_derives_every_authoritative_field_from_the_exact_frame() {
        let action = RequestedActionV1::VelocityLocalNed {
            north_mm_s: 100,
            east_mm_s: -200,
            down_mm_s: 300,
            requested_validity_ms: NonZeroU32::new(200).unwrap(),
        };
        let frame = AclOnlyAdapter::new().build_command(&input(action)).unwrap();
        let command = PlantCommand::from_exact_frame(DecisionId::new([8; 16]), frame).unwrap();

        assert_eq!(command.decision_id(), DecisionId::new([8; 16]));
        assert_eq!(command.action(), PlantAction::Velocity([100, -200, 300]));
        assert_eq!(command.validity_ms(), 200);
        assert_eq!(command.session().session_id.as_str(), "sess-1");
        assert_eq!(command.output_seq().get(), 3);
        assert_eq!(command.source().stream_seq.get(), 5);
        assert_eq!(
            command.output_frame_digest(),
            command.exact_frame().digest()
        );
    }

    #[test]
    fn command_rejects_an_exact_frame_whose_retained_bytes_changed() {
        let action = RequestedActionV1::Hold {
            requested_validity_ms: NonZeroU32::new(200).unwrap(),
        };
        let mut frame = AclOnlyAdapter::new().build_command(&input(action)).unwrap();
        frame.bytes[0] ^= 1;

        assert_eq!(
            PlantCommand::from_exact_frame(DecisionId::new([8; 16]), frame),
            Err(PlantCommandError::InvalidExactFrame)
        );
    }
}
