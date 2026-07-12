//! Exact NCP v0.8.0 JSON adapter, compiled only for the `real-ncp` profile.
//!
//! The dependency is pinned by immutable commit. Construction is followed by the
//! upstream typed validator, compact JSON serialization, and upstream validated
//! decode before any bytes are returned to Gate.

use crate::adapter::{
    ExactNcpCommandFrame, GateCommandBuildInputV1, NcpCommandAdapter, NcpCommandFrameV1,
    build_semantic_frame,
};
use crate::compatibility::{NCP_V0_8_0, NcpCompatibilityRecordV1};
use crate::error::NcpAdapterError;
use ncp_core::{ChannelValue, CommandFrame, Map, Mode, SessionRef, StreamPosition, WireFrame};
use std::time::Duration;

const VELOCITY_SETPOINT_CHANNEL: &str = "velocity_setpoint";
const VELOCITY_SETPOINT_UNIT: &str = "m/s";

/// Exact adapter backed by `ncp-core` v0.8.0 at the pinned release commit.
#[derive(Debug, Clone)]
pub struct RealNcp08Adapter {
    compat: NcpCompatibilityRecordV1,
}

impl RealNcp08Adapter {
    /// Create the exact pinned adapter.
    #[must_use]
    pub fn new() -> Self {
        Self { compat: NCP_V0_8_0 }
    }

    fn to_ncp_frame(semantic: &NcpCommandFrameV1) -> Result<CommandFrame, NcpAdapterError> {
        let stream_seq = i64::try_from(semantic.stream.seq.get())
            .map_err(|_| NcpAdapterError::ConversionOutOfRange)?;
        let source_seq = i64::try_from(semantic.source.stream_seq.get())
            .map_err(|_| NcpAdapterError::ConversionOutOfRange)?;
        let mut channels = Map::new();
        channels.insert(
            VELOCITY_SETPOINT_CHANNEL.to_owned(),
            ChannelValue::vec3(
                semantic.velocity_m_s[0],
                semantic.velocity_m_s[1],
                semantic.velocity_m_s[2],
                Some(VELOCITY_SETPOINT_UNIT),
            ),
        );
        let frame = CommandFrame {
            t: Duration::from_nanos(semantic.t_ns).as_secs_f64(),
            frame_id: semantic.frame_id.as_str().to_owned(),
            mode: if semantic.is_hold {
                Mode::Hold
            } else {
                Mode::Active
            },
            ttl_ms: f64::from(semantic.validity_ms),
            channels,
            horizon: Vec::new(),
            horizon_dt_ms: None,
            stream: StreamPosition {
                epoch: semantic.stream.epoch.uuid().render(),
                seq: stream_seq,
            },
            source: Some(StreamPosition {
                epoch: semantic.source.stream_epoch.render(),
                seq: source_seq,
            }),
            source_t: Duration::from_nanos(semantic.source_t_ns).as_secs_f64(),
            session: SessionRef {
                generation: semantic.session.generation.render(),
            },
            session_id: semantic.session.session_id.as_str().to_owned(),
            ..CommandFrame::default()
        };
        WireFrame::validate_wire(&frame).map_err(|_| NcpAdapterError::UpstreamValidationFailed)?;
        Self::validate_profile_shape(&frame)?;
        Ok(frame)
    }

    fn validate_profile_shape(frame: &CommandFrame) -> Result<(), NcpAdapterError> {
        if frame.channels.len() != 1 {
            return Err(NcpAdapterError::UpstreamValidationFailed);
        }
        let Some(velocity) = frame.channels.get(VELOCITY_SETPOINT_CHANNEL) else {
            return Err(NcpAdapterError::UpstreamValidationFailed);
        };
        if velocity.data.len() != 3
            || velocity.data.iter().any(|value| !value.is_finite())
            || velocity.unit.as_deref() != Some(VELOCITY_SETPOINT_UNIT)
            || !frame.horizon.is_empty()
            || frame.horizon_dt_ms.is_some()
        {
            return Err(NcpAdapterError::UpstreamValidationFailed);
        }
        Ok(())
    }

    fn validated_bytes(frame: &CommandFrame) -> Result<Vec<u8>, NcpAdapterError> {
        WireFrame::validate_wire(frame).map_err(|_| NcpAdapterError::UpstreamValidationFailed)?;
        Self::validate_profile_shape(frame)?;
        let bytes = serde_json::to_vec(frame).map_err(|_| NcpAdapterError::SerializationFailed)?;
        let decoded = ncp_core::decode_validated::<CommandFrame>(&bytes)
            .map_err(|_| NcpAdapterError::UpstreamValidationFailed)?;
        Self::validate_profile_shape(&decoded)?;
        if &decoded != frame {
            return Err(NcpAdapterError::ValidatorMismatch);
        }
        Ok(bytes)
    }
}

impl Default for RealNcp08Adapter {
    fn default() -> Self {
        Self::new()
    }
}

impl NcpCommandAdapter for RealNcp08Adapter {
    fn compatibility(&self) -> &NcpCompatibilityRecordV1 {
        &self.compat
    }

    fn build_command(
        &self,
        input: &GateCommandBuildInputV1,
    ) -> Result<ExactNcpCommandFrame, NcpAdapterError> {
        let (semantic, transformation) = build_semantic_frame(input)?;
        let ncp = Self::to_ncp_frame(&semantic)?;
        let bytes = Self::validated_bytes(&ncp)?;
        Ok(ExactNcpCommandFrame::from_parts(
            semantic,
            bytes,
            transformation,
        ))
    }

    fn validate_exact_command(
        &self,
        frame: &ExactNcpCommandFrame,
        expected: &GateCommandBuildInputV1,
    ) -> Result<(), NcpAdapterError> {
        let rebuilt = self.build_command(expected)?;
        if &rebuilt != frame {
            return Err(NcpAdapterError::ValidatorMismatch);
        }
        let decoded = ncp_core::decode_validated::<CommandFrame>(frame.bytes())
            .map_err(|_| NcpAdapterError::ValidatorMismatch)?;
        Self::validate_profile_shape(&decoded).map_err(|_| NcpAdapterError::ValidatorMismatch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::num::{NonZeroU32, NonZeroU64};
    use haldir_contracts::action::RequestedActionV1;
    use haldir_contracts::digest::{DigestDomain, DigestV1};
    use haldir_contracts::ids::{DecisionId, GateOutputEpoch, OutputSeq, SourceSeq};
    use haldir_contracts::receipt::TransformationRelationV1;
    use haldir_contracts::scalar::{AsciiId, BoundedAscii, CanonicalUuidV4String};
    use haldir_contracts::session::{NcpSessionIdentityV1, NcpSourceRefV1, NcpStreamPositionV1};

    fn uuid(text: &str) -> CanonicalUuidV4String {
        CanonicalUuidV4String::parse(text).unwrap()
    }

    fn input(seq: u64, action: RequestedActionV1) -> GateCommandBuildInputV1 {
        GateCommandBuildInputV1 {
            decision_id: DecisionId::new([1; 16]),
            session: NcpSessionIdentityV1 {
                session_id: AsciiId::new("sess-1").unwrap(),
                generation: uuid("293279f3-d459-4bfd-aeeb-604799e96925"),
            },
            stream: NcpStreamPositionV1 {
                epoch: GateOutputEpoch::new(uuid("3ef6f0ad-8ee6-4c6a-9e3f-86dc9ce849a1")),
                seq: OutputSeq::new(NonZeroU64::new(seq).unwrap()),
            },
            source: NcpSourceRefV1 {
                source_key: BoundedAscii::new("veh/uav-1/state/pose").unwrap(),
                stream_epoch: uuid("7d61c9ba-4e1d-4aab-8ae6-08e05206aa67"),
                stream_seq: SourceSeq::new(NonZeroU64::new(7).unwrap()),
            },
            frame_id: BoundedAscii::new("map").unwrap(),
            source_t_ns: 1_000_000_000,
            gate_t_ns: 2_000_000_000,
            action,
            effective_validity_ms: 200,
        }
    }

    fn velocity() -> RequestedActionV1 {
        RequestedActionV1::VelocityLocalNed {
            north_mm_s: 100,
            east_mm_s: -200,
            down_mm_s: 300,
            requested_validity_ms: NonZeroU32::new(200).unwrap(),
        }
    }

    #[test]
    fn frozen_upstream_command_vector_decodes_with_the_pinned_crate() {
        let bytes = include_bytes!("../tests/data/ncp-v0.8.0/command_frame.json");
        let decoded = ncp_core::decode_validated::<CommandFrame>(bytes).unwrap();
        assert_eq!(decoded.ncp_version, "0.8");
        assert_eq!(decoded.kind, "command_frame");
        assert_eq!(decoded.mode, Mode::Active);
        assert_eq!(decoded.stream.seq, 7);
        assert_eq!(
            decoded.channels[VELOCITY_SETPOINT_CHANNEL].unit.as_deref(),
            Some("m/s")
        );
        let reencoded = serde_json::to_vec(&decoded).unwrap();
        assert_eq!(
            ncp_core::decode_validated::<CommandFrame>(&reencoded).unwrap(),
            decoded
        );
    }

    #[test]
    fn active_output_is_valid_exact_ncp_and_matches_an_independent_reference() {
        let adapter = RealNcp08Adapter::new();
        let input = input(7, velocity());
        let exact = adapter.build_command(&input).unwrap();
        adapter.validate_exact_command(&exact, &input).unwrap();
        let decoded = ncp_core::decode_validated::<CommandFrame>(exact.bytes()).unwrap();

        let mut channels = Map::new();
        channels.insert(
            VELOCITY_SETPOINT_CHANNEL.to_owned(),
            ChannelValue::vec3(0.1, -0.2, 0.3, Some(VELOCITY_SETPOINT_UNIT)),
        );
        let expected = CommandFrame {
            t: 2.0,
            frame_id: "map".to_owned(),
            mode: Mode::Active,
            ttl_ms: 200.0,
            channels,
            horizon: Vec::new(),
            horizon_dt_ms: None,
            stream: StreamPosition {
                epoch: "3ef6f0ad-8ee6-4c6a-9e3f-86dc9ce849a1".to_owned(),
                seq: 7,
            },
            source: Some(StreamPosition {
                epoch: "7d61c9ba-4e1d-4aab-8ae6-08e05206aa67".to_owned(),
                seq: 7,
            }),
            source_t: 1.0,
            session: SessionRef {
                generation: "293279f3-d459-4bfd-aeeb-604799e96925".to_owned(),
            },
            session_id: "sess-1".to_owned(),
            ..CommandFrame::default()
        };
        assert_eq!(decoded, expected);
        assert_eq!(exact.bytes(), serde_json::to_vec(&expected).unwrap());
        assert_eq!(
            exact.transformation(),
            TransformationRelationV1::FixedPointToNcpFloatV1
        );
    }

    #[test]
    fn hold_is_a_valid_zero_velocity_command_that_supersedes_active() {
        let adapter = RealNcp08Adapter::new();
        let input = input(
            8,
            RequestedActionV1::Hold {
                requested_validity_ms: NonZeroU32::new(200).unwrap(),
            },
        );
        let exact = adapter.build_command(&input).unwrap();
        let decoded = ncp_core::decode_validated::<CommandFrame>(exact.bytes()).unwrap();
        assert_eq!(decoded.mode, Mode::Hold);
        assert_eq!(decoded.stream.seq, 8);
        assert_eq!(decoded.frame_id, "map");
        assert_eq!(decoded.channels[VELOCITY_SETPOINT_CHANNEL].data, [0.0; 3]);
        assert_eq!(exact.transformation(), TransformationRelationV1::Identity);
    }

    #[test]
    fn json_safe_bound_and_active_ttl_are_enforced_by_the_real_path() {
        let adapter = RealNcp08Adapter::new();
        let mut at_limit = input(crate::NCP_JSON_SAFE_INTEGER_MAX, velocity());
        assert!(adapter.build_command(&at_limit).is_ok());
        at_limit.stream.seq =
            OutputSeq::new(NonZeroU64::new(crate::NCP_JSON_SAFE_INTEGER_MAX + 1).unwrap());
        assert_eq!(
            adapter.build_command(&at_limit),
            Err(NcpAdapterError::ConversionOutOfRange)
        );

        let mut source_over_limit = input(1, velocity());
        source_over_limit.source.stream_seq =
            SourceSeq::new(NonZeroU64::new(crate::NCP_JSON_SAFE_INTEGER_MAX + 1).unwrap());
        assert_eq!(
            adapter.build_command(&source_over_limit),
            Err(NcpAdapterError::ConversionOutOfRange)
        );

        let mut zero_ttl = input(1, velocity());
        zero_ttl.effective_validity_ms = 0;
        assert_eq!(
            adapter.build_command(&zero_ttl),
            Err(NcpAdapterError::UpstreamValidationFailed)
        );
    }

    #[test]
    fn byte_digest_and_transformation_tampering_are_rejected() {
        let adapter = RealNcp08Adapter::new();
        let input = input(7, velocity());

        let mut bytes = adapter.build_command(&input).unwrap();
        bytes.bytes.push(b' ');
        assert_eq!(
            adapter.validate_exact_command(&bytes, &input),
            Err(NcpAdapterError::ValidatorMismatch)
        );

        let mut digest = adapter.build_command(&input).unwrap();
        digest.digest = DigestV1::compute(DigestDomain::OutputFrame, b"tampered");
        assert_eq!(
            adapter.validate_exact_command(&digest, &input),
            Err(NcpAdapterError::ValidatorMismatch)
        );

        let mut relation = adapter.build_command(&input).unwrap();
        relation.transformation = TransformationRelationV1::Identity;
        assert_eq!(
            adapter.validate_exact_command(&relation, &input),
            Err(NcpAdapterError::ValidatorMismatch)
        );

        let mut semantic = adapter.build_command(&input).unwrap();
        semantic.frame.frame_id = BoundedAscii::new("odom").unwrap();
        assert_eq!(
            adapter.validate_exact_command(&semantic, &input),
            Err(NcpAdapterError::ValidatorMismatch)
        );
    }

    #[test]
    fn nanosecond_time_projection_is_finite_and_has_a_declared_precision_limit() {
        for ns in [0, 1, 1_000_000_001, u64::MAX] {
            let seconds = Duration::from_nanos(ns).as_secs_f64();
            assert!(seconds.is_finite());
            let reconstructed = Duration::from_secs_f64(seconds).as_nanos();
            assert!(reconstructed.abs_diff(u128::from(ns)) <= 2_048);
        }
    }
}
