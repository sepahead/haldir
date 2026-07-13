//! Gate-owned NCP `v0.8.0` command construction (modeled P0 semantic layer).
//!
//! Every publisher-owned field of the emitted frame comes from Gate state, never
//! from controller-authored bytes (spec mapping table / B4): the session, stream
//! epoch/seq, `t`, and source are taken from the [`GateCommandBuildInputV1`] the
//! Gate assembled after ALLOW. Plant authority (`authority.term`/`lease_id`) is
//! ABSENT under `PRE_AUTHORITY_ACL_ONLY` (H8) — it is not a field here.
//!
//! This models the wire semantics without depending on the real `ncp-core`/Zenoh
//! stack (P0 profile); the compatibility record pins the exact upstream release.

use crate::compatibility::{NCP_V0_8_0, NcpCompatibilityRecordV1};
use crate::conversion::{mm_s_to_ncp_m_s, ncp_m_s_to_mm_s};
use crate::error::NcpAdapterError;
use haldir_contracts::action::RequestedActionV1;
use haldir_contracts::digest::{DigestDomain, DigestV1};
use haldir_contracts::ids::DecisionId;
use haldir_contracts::receipt::TransformationRelationV1;
use haldir_contracts::scalar::BoundedAscii;
use haldir_contracts::session::{NcpSessionIdentityV1, NcpSourceRefV1, NcpStreamPositionV1};

/// Largest integer that NCP v0.8.0 can carry losslessly through its JSON wire.
pub const NCP_JSON_SAFE_INTEGER_MAX: u64 = 9_007_199_254_740_991;

/// The fully-approved input the Gate hands the adapter after a decision ALLOW.
#[derive(Debug, Clone)]
pub struct GateCommandBuildInputV1 {
    /// The Gate decision id (correlation only).
    pub decision_id: DecisionId,
    /// Current session pair (Gate state).
    pub session: NcpSessionIdentityV1,
    /// Gate output stream position (Gate state).
    pub stream: NcpStreamPositionV1,
    /// Verified causal source (Gate trusted-state cache).
    pub source: NcpSourceRefV1,
    /// Validated coordinate-frame identifier from the trusted source frame.
    pub frame_id: BoundedAscii<128>,
    /// Trusted source time (from the trusted frame).
    pub source_t_ns: u64,
    /// Gate-local monotonic creation time `t`.
    pub gate_t_ns: u64,
    /// The approved semantic action.
    pub action: RequestedActionV1,
    /// The computed effective output validity (ms).
    pub effective_validity_ms: u32,
}

/// A modeled NCP `v0.8.0` command frame (Gate-owned publisher fields).
#[derive(Debug, Clone, PartialEq)]
pub struct NcpCommandFrameV1 {
    /// Session pair.
    pub session: NcpSessionIdentityV1,
    /// Gate output stream position.
    pub stream: NcpStreamPositionV1,
    /// Causal source.
    pub source: NcpSourceRefV1,
    /// Coordinate frame copied from the trusted source frame.
    pub frame_id: BoundedAscii<128>,
    /// Gate creation time `t`.
    pub t_ns: u64,
    /// Source time.
    pub source_t_ns: u64,
    /// Whether this is a hold command.
    pub is_hold: bool,
    /// Wire velocity components (m/s).
    pub velocity_m_s: [f64; 3],
    /// Command validity (ms).
    pub validity_ms: u32,
}

fn put_str(b: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    b.extend_from_slice(&len.to_be_bytes());
    b.extend_from_slice(bytes);
}

impl NcpCommandFrameV1 {
    /// A deterministic wire serialization (fixed field order, big-endian, floats
    /// as IEEE-754 bit patterns). No `authority`/`publisher_id` fields exist.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn wire_bytes(&self) -> Vec<u8> {
        let mut b = Vec::new();
        put_str(&mut b, self.session.session_id.as_str());
        b.extend_from_slice(self.session.generation.as_bytes());
        b.extend_from_slice(self.stream.epoch.uuid().as_bytes());
        b.extend_from_slice(&self.stream.seq.get().to_be_bytes());
        put_str(&mut b, self.source.source_key.as_str());
        b.extend_from_slice(self.source.stream_epoch.as_bytes());
        b.extend_from_slice(&self.source.stream_seq.get().to_be_bytes());
        put_str(&mut b, self.frame_id.as_str());
        b.extend_from_slice(&self.t_ns.to_be_bytes());
        b.extend_from_slice(&self.source_t_ns.to_be_bytes());
        b.push(u8::from(self.is_hold));
        for v in self.velocity_m_s {
            b.extend_from_slice(&v.to_bits().to_be_bytes());
        }
        b.extend_from_slice(&self.validity_ms.to_be_bytes());
        b
    }
}

/// An immutable prepared output: the frame, its exact bytes, digest, and the
/// declared transformation relation.
#[derive(Debug, Clone, PartialEq)]
pub struct ExactNcpCommandFrame {
    pub(crate) frame: NcpCommandFrameV1,
    pub(crate) bytes: Vec<u8>,
    pub(crate) digest: DigestV1,
    pub(crate) transformation: TransformationRelationV1,
}

impl ExactNcpCommandFrame {
    pub(crate) fn from_parts(
        frame: NcpCommandFrameV1,
        bytes: Vec<u8>,
        transformation: TransformationRelationV1,
    ) -> Self {
        let digest = DigestV1::compute(DigestDomain::OutputFrame, &bytes);
        Self {
            frame,
            bytes,
            digest,
            transformation,
        }
    }

    /// Borrow the exact serialized bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Session id carried by the immutable semantic frame.
    ///
    /// Transport publishers use this to prevent placing valid bytes for one
    /// session on another session's command route.
    #[must_use]
    pub fn session_id(&self) -> &str {
        self.frame.session.session_id.as_str()
    }

    /// Digest of the exact serialized bytes.
    #[must_use]
    pub const fn digest(&self) -> DigestV1 {
        self.digest
    }

    /// The declared semantic-to-wire transformation.
    #[must_use]
    pub const fn transformation(&self) -> TransformationRelationV1 {
        self.transformation
    }

    /// Whether the frame is a hold.
    #[must_use]
    pub fn is_hold(&self) -> bool {
        self.frame.is_hold
    }

    /// The decoded fixed-point velocity components (mm/s), recovered from the wire.
    #[must_use]
    pub fn decoded_velocity_mm_s(&self) -> [i32; 3] {
        [
            ncp_m_s_to_mm_s(self.frame.velocity_m_s[0]),
            ncp_m_s_to_mm_s(self.frame.velocity_m_s[1]),
            ncp_m_s_to_mm_s(self.frame.velocity_m_s[2]),
        ]
    }

    fn is_self_consistent(&self) -> bool {
        let expected_transformation = if self.frame.is_hold {
            TransformationRelationV1::Identity
        } else {
            TransformationRelationV1::FixedPointToNcpFloatV1
        };
        let hold_is_zero = !self.frame.is_hold
            || self
                .frame
                .velocity_m_s
                .iter()
                .all(|value| value.to_bits() == 0.0f64.to_bits());
        let serialized = self.frame.wire_bytes();

        self.transformation == expected_transformation
            && hold_is_zero
            && serialized == self.bytes
            && DigestV1::compute(DigestDomain::OutputFrame, &self.bytes) == self.digest
    }
}

pub(crate) fn build_semantic_frame(
    input: &GateCommandBuildInputV1,
) -> Result<(NcpCommandFrameV1, TransformationRelationV1), NcpAdapterError> {
    if input.stream.seq.get() > NCP_JSON_SAFE_INTEGER_MAX
        || input.source.stream_seq.get() > NCP_JSON_SAFE_INTEGER_MAX
    {
        return Err(NcpAdapterError::ConversionOutOfRange);
    }

    let (is_hold, vel_mm, transformation) = match input.action {
        RequestedActionV1::Hold { .. } => (true, [0i32; 3], TransformationRelationV1::Identity),
        RequestedActionV1::VelocityLocalNed {
            north_mm_s,
            east_mm_s,
            down_mm_s,
            ..
        } => (
            false,
            [north_mm_s, east_mm_s, down_mm_s],
            TransformationRelationV1::FixedPointToNcpFloatV1,
        ),
    };
    let velocity_m_s = [
        mm_s_to_ncp_m_s(vel_mm[0]),
        mm_s_to_ncp_m_s(vel_mm[1]),
        mm_s_to_ncp_m_s(vel_mm[2]),
    ];
    Ok((
        NcpCommandFrameV1 {
            session: input.session.clone(),
            stream: NcpStreamPositionV1 {
                epoch: input.stream.epoch,
                seq: input.stream.seq,
            },
            source: input.source.clone(),
            frame_id: input.frame_id.clone(),
            t_ns: input.gate_t_ns,
            source_t_ns: input.source_t_ns,
            is_hold,
            velocity_m_s,
            validity_ms: input.effective_validity_ms,
        },
        transformation,
    ))
}

/// The Gate-owned NCP command adapter.
pub trait NcpCommandAdapter {
    /// The pinned compatibility record.
    fn compatibility(&self) -> &NcpCompatibilityRecordV1;

    /// Build the exact command frame from an approved Gate input.
    ///
    /// # Errors
    /// Returns [`NcpAdapterError`] if the input cannot be converted within bounds.
    fn build_command(
        &self,
        input: &GateCommandBuildInputV1,
    ) -> Result<ExactNcpCommandFrame, NcpAdapterError>;

    /// Validate that an exact frame matches what would be built from `expected`
    /// (byte-exact), guarding against post-build mutation.
    ///
    /// # Errors
    /// Returns [`NcpAdapterError::ValidatorMismatch`] on any drift.
    fn validate_exact_command(
        &self,
        frame: &ExactNcpCommandFrame,
        expected: &GateCommandBuildInputV1,
    ) -> Result<(), NcpAdapterError>;
}

/// The `PRE_AUTHORITY_ACL_ONLY` adapter for NCP `v0.8.0` increment 1.
#[derive(Debug, Clone)]
pub struct AclOnlyAdapter {
    compat: NcpCompatibilityRecordV1,
}

impl AclOnlyAdapter {
    /// A new adapter pinned to NCP `v0.8.0`.
    #[must_use]
    pub fn new() -> Self {
        Self { compat: NCP_V0_8_0 }
    }
}

impl Default for AclOnlyAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl NcpCommandAdapter for AclOnlyAdapter {
    fn compatibility(&self) -> &NcpCompatibilityRecordV1 {
        &self.compat
    }

    fn build_command(
        &self,
        input: &GateCommandBuildInputV1,
    ) -> Result<ExactNcpCommandFrame, NcpAdapterError> {
        let (frame, transformation) = build_semantic_frame(input)?;
        let bytes = frame.wire_bytes();
        Ok(ExactNcpCommandFrame::from_parts(
            frame,
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
        if !frame.is_self_consistent() || &rebuilt != frame {
            return Err(NcpAdapterError::ValidatorMismatch);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::num::{NonZeroU32, NonZeroU64};
    use haldir_contracts::ids::{DecisionId, GateOutputEpoch, OutputSeq, SourceSeq};
    use haldir_contracts::scalar::{AsciiId, BoundedAscii, CanonicalUuidV4String};

    fn input(action: RequestedActionV1) -> GateCommandBuildInputV1 {
        GateCommandBuildInputV1 {
            decision_id: DecisionId::new([1; 16]),
            session: NcpSessionIdentityV1 {
                session_id: AsciiId::new("sess-1").unwrap(),
                generation: CanonicalUuidV4String::from_random_bytes([1; 16]),
            },
            stream: NcpStreamPositionV1 {
                epoch: GateOutputEpoch::new(CanonicalUuidV4String::from_random_bytes([5; 16])),
                seq: OutputSeq::new(NonZeroU64::new(1).unwrap()),
            },
            source: NcpSourceRefV1 {
                source_key: BoundedAscii::new("veh/uav-1/state/pose").unwrap(),
                stream_epoch: CanonicalUuidV4String::from_random_bytes([2; 16]),
                stream_seq: SourceSeq::new(NonZeroU64::new(7).unwrap()),
            },
            frame_id: BoundedAscii::new("map").unwrap(),
            source_t_ns: 111,
            gate_t_ns: 222,
            action,
            effective_validity_ms: 300,
        }
    }

    fn hold_input() -> GateCommandBuildInputV1 {
        input(RequestedActionV1::Hold {
            requested_validity_ms: NonZeroU32::new(300).unwrap(),
        })
    }

    #[test]
    fn validator_rejects_internal_frame_tampering() {
        let adapter = AclOnlyAdapter::new();
        let input = hold_input();
        let mut exact = adapter.build_command(&input).unwrap();
        exact.frame.is_hold = false;

        assert_eq!(
            adapter.validate_exact_command(&exact, &input),
            Err(NcpAdapterError::ValidatorMismatch)
        );
    }

    #[test]
    fn validator_rejects_internal_bytes_tampering() {
        let adapter = AclOnlyAdapter::new();
        let input = hold_input();
        let mut exact = adapter.build_command(&input).unwrap();
        exact.bytes.push(0xff);

        assert_eq!(
            adapter.validate_exact_command(&exact, &input),
            Err(NcpAdapterError::ValidatorMismatch)
        );
    }

    #[test]
    fn validator_rejects_internal_digest_tampering() {
        let adapter = AclOnlyAdapter::new();
        let input = hold_input();
        let mut exact = adapter.build_command(&input).unwrap();
        exact.digest = DigestV1::compute(DigestDomain::OutputFrame, b"tampered");

        assert_eq!(
            adapter.validate_exact_command(&exact, &input),
            Err(NcpAdapterError::ValidatorMismatch)
        );
    }

    #[test]
    fn validator_rejects_internal_transformation_tampering() {
        let adapter = AclOnlyAdapter::new();
        let input = hold_input();
        let mut exact = adapter.build_command(&input).unwrap();
        exact.transformation = TransformationRelationV1::FixedPointToNcpFloatV1;

        assert_eq!(
            adapter.validate_exact_command(&exact, &input),
            Err(NcpAdapterError::ValidatorMismatch)
        );
    }
}
