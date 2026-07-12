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
use haldir_contracts::session::{NcpSessionIdentityV1, NcpSourceRefV1, NcpStreamPositionV1};

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
#[derive(Debug, Clone)]
pub struct NcpCommandFrameV1 {
    /// Session pair.
    pub session: NcpSessionIdentityV1,
    /// Gate output stream position.
    pub stream: NcpStreamPositionV1,
    /// Causal source.
    pub source: NcpSourceRefV1,
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
#[derive(Debug, Clone)]
pub struct ExactNcpCommandFrame {
    /// The frame.
    pub frame: NcpCommandFrameV1,
    /// Exact serialized bytes.
    pub bytes: Vec<u8>,
    /// Digest of the exact bytes.
    pub digest: DigestV1,
    /// The declared conversion relation.
    pub transformation: TransformationRelationV1,
}

impl ExactNcpCommandFrame {
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
        let frame = NcpCommandFrameV1 {
            session: input.session.clone(),
            stream: NcpStreamPositionV1 {
                epoch: input.stream.epoch,
                seq: input.stream.seq,
            },
            source: input.source.clone(),
            t_ns: input.gate_t_ns,
            source_t_ns: input.source_t_ns,
            is_hold,
            velocity_m_s,
            validity_ms: input.effective_validity_ms,
        };
        let bytes = frame.wire_bytes();
        let digest = DigestV1::compute(DigestDomain::OutputFrame, &bytes);
        Ok(ExactNcpCommandFrame {
            frame,
            bytes,
            digest,
            transformation,
        })
    }

    fn validate_exact_command(
        &self,
        frame: &ExactNcpCommandFrame,
        expected: &GateCommandBuildInputV1,
    ) -> Result<(), NcpAdapterError> {
        let rebuilt = self.build_command(expected)?;
        if rebuilt.bytes != frame.bytes || rebuilt.digest != frame.digest {
            return Err(NcpAdapterError::ValidatorMismatch);
        }
        Ok(())
    }
}
