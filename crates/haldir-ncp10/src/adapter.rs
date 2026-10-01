//! Gate-owned NCP `1.0.0-rc.1` command construction (modeled semantic layer).
//!
//! Every publisher-owned field of the emitted frame comes from Gate state, never
//! from controller-authored bytes (spec mapping table / B4): the session, stream
//! epoch/seq, `t`, the source stream position, and the authority lease are taken
//! from the [`GateCommandBuildInputV1`] the Gate assembled after ALLOW. The Haldir
//! `source_key` is carried by the immutable exact-frame correlation object; the
//! exact NCP 1.0 JSON profile has no corresponding wire field.
//!
//! NCP 1.0 requires an authority lease on every Active command and validates one
//! carried on HOLD; Haldir carries Gate's lease on both, so a HOLD is attributable
//! to the authority holder. The lease comes from [`crate::lease`]. The adapter
//! refuses a lease for another session or output epoch, an empty or over-long
//! UTC interval, or a lease without a Gate-local deadline.
//!
//! This models the wire semantics without depending on the real `ncp-core`/Zenoh
//! stack; the compatibility record pins the exact upstream candidate.

use crate::compatibility::{NCP_V1_0_0_RC1, NcpCompatibilityRecordV1};
use crate::conversion::{mm_s_to_ncp_m_s, ncp_m_s_to_mm_s};
use crate::error::NcpAdapterError;
use haldir_contracts::action::RequestedActionV1;
use haldir_contracts::digest::{DigestDomain, DigestV1};
use haldir_contracts::receipt::TransformationRelationV1;
use haldir_contracts::scalar::BoundedAscii;
use haldir_contracts::session::{NcpSessionIdentityV1, NcpSourceRefV1, NcpStreamPositionV1};
use haldir_contracts::status::NcpLeaseEvidenceV1;

/// Largest integer that NCP 1.0 can carry losslessly through its JSON wire.
pub const NCP_JSON_SAFE_INTEGER_MAX: u64 = 9_007_199_254_740_991;

/// Longest UTC authority interval NCP 1.0 accepts (`MAX_AUTHORITY_LEASE_MS`).
pub const NCP_MAX_AUTHORITY_LEASE_MS: u64 = 60_000;

/// NCP 1.0's bound on commander–body clock disagreement
/// (`MAX_CLOCK_UNCERTAINTY_MS`).
pub const NCP_MAX_CLOCK_UNCERTAINTY_MS: u64 = 5_000;

/// The fully-approved input the Gate hands the adapter after a decision ALLOW.
#[derive(Debug, Clone)]
pub struct GateCommandBuildInputV1 {
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
    ///
    /// This must not exceed the validity requested by [`Self::action`]. The
    /// adapter checks that cross-field invariant before constructing any wire
    /// representation.
    pub effective_validity_ms: u32,
    /// Gate's live NCP authority lease for this session and output epoch.
    pub lease: NcpLeaseEvidenceV1,
}

/// Closed encoding used by one immutable exact command frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NcpCommandWireProfile {
    /// Dependency-light deterministic semantic bytes used by the model.
    ModeledP0,
    /// Upstream-validated compact NCP 1.0 JSON.
    ExactNcpV1_0Json,
}

/// A modeled NCP 1.0 command frame (Gate-owned publisher fields).
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
    /// Gate creation time `t` in the internal nanosecond domain.
    ///
    /// Modeled-P0 bytes carry this integer exactly. Exact NCP 1.0 JSON carries
    /// its deterministic binary64-seconds projection, which is not injective
    /// over the full `u64` nanosecond domain.
    pub t_ns: u64,
    /// Source time in the internal nanosecond domain, with the same profile-
    /// specific projection semantics as [`Self::t_ns`].
    pub source_t_ns: u64,
    /// Whether this is a hold command.
    pub is_hold: bool,
    /// Wire velocity components (m/s).
    pub velocity_m_s: [f64; 3],
    /// Command validity (ms).
    pub validity_ms: u32,
    /// The authority lease carried by the frame.
    pub authority: NcpLeaseEvidenceV1,
}

fn put_str(b: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    b.extend_from_slice(&len.to_be_bytes());
    b.extend_from_slice(bytes);
}

impl NcpCommandFrameV1 {
    /// A deterministic wire serialization (fixed field order, big-endian, floats
    /// as IEEE-754 bit patterns), ending with every authority-lease field.
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
        let lease = &self.authority;
        put_str(&mut b, lease.gate_transport_principal.as_str());
        put_str(&mut b, lease.issuer_principal.as_str());
        put_str(&mut b, lease.holder_entity.as_str());
        b.extend_from_slice(lease.session.generation.as_bytes());
        b.extend_from_slice(&lease.authority_term.get().to_be_bytes());
        b.extend_from_slice(lease.lease_id.as_bytes());
        b.extend_from_slice(&lease.issued_at_utc_ms.to_be_bytes());
        b.extend_from_slice(&lease.expires_at_utc_ms.to_be_bytes());
        b
    }
}

/// An immutable prepared output: Gate-owned semantics, exact profile bytes,
/// their digest, and the declared action transformation.
///
/// “Exact” qualifies the serialized bytes. The exact NCP 1.0 JSON profile has
/// no `source_key` field and projects integer nanosecond times to binary64
/// seconds, so those semantic values are not all injectively committed by the
/// byte digest. The profile observability methods and compatibility document
/// make those projection limits explicit.
#[derive(Debug, PartialEq)]
pub struct ExactNcpCommandFrame {
    pub(crate) frame: NcpCommandFrameV1,
    pub(crate) bytes: Vec<u8>,
    pub(crate) digest: DigestV1,
    pub(crate) transformation: TransformationRelationV1,
    wire_profile: NcpCommandWireProfile,
}

impl ExactNcpCommandFrame {
    fn from_parts(
        frame: NcpCommandFrameV1,
        bytes: Vec<u8>,
        transformation: TransformationRelationV1,
        wire_profile: NcpCommandWireProfile,
    ) -> Self {
        let digest = DigestV1::compute(DigestDomain::OutputFrame, &bytes);
        Self {
            frame,
            bytes,
            digest,
            transformation,
            wire_profile,
        }
    }

    pub(crate) fn from_modeled_parts(
        frame: NcpCommandFrameV1,
        bytes: Vec<u8>,
        transformation: TransformationRelationV1,
    ) -> Self {
        Self::from_parts(
            frame,
            bytes,
            transformation,
            NcpCommandWireProfile::ModeledP0,
        )
    }

    #[cfg(feature = "real-ncp")]
    pub(crate) fn from_exact_json_parts(
        frame: NcpCommandFrameV1,
        bytes: Vec<u8>,
        transformation: TransformationRelationV1,
    ) -> Self {
        Self::from_parts(
            frame,
            bytes,
            transformation,
            NcpCommandWireProfile::ExactNcpV1_0Json,
        )
    }

    /// Borrow the exact serialized bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Encoding against which the semantic frame and exact bytes are checked.
    #[must_use]
    pub const fn wire_profile(&self) -> NcpCommandWireProfile {
        self.wire_profile
    }

    /// Whether the Haldir `source_key` itself is present in the serialized bytes.
    ///
    /// Both profiles bind the source stream epoch and sequence. NCP 1.0 JSON has
    /// no `source_key` field, so the key remains exact-object/event correlation in
    /// that profile and is not committed by [`Self::digest`].
    #[must_use]
    pub const fn source_key_is_wire_bound(&self) -> bool {
        matches!(self.wire_profile, NcpCommandWireProfile::ModeledP0)
    }

    /// Session pair carried by the exact frame.
    #[must_use]
    pub const fn session(&self) -> &NcpSessionIdentityV1 {
        &self.frame.session
    }

    /// Gate output position carried by the exact frame.
    #[must_use]
    pub const fn stream(&self) -> &NcpStreamPositionV1 {
        &self.frame.stream
    }

    /// Causal source carried by the exact frame.
    #[must_use]
    pub const fn source(&self) -> &NcpSourceRefV1 {
        &self.frame.source
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
    ///
    /// # Errors
    /// Returns [`NcpAdapterError::ConversionOutOfRange`] if an internal value
    /// is not in Haldir's exact fixed-point-to-wire image.
    pub fn decoded_velocity_mm_s(&self) -> Result<[i32; 3], NcpAdapterError> {
        Ok([
            ncp_m_s_to_mm_s(self.frame.velocity_m_s[0])?,
            ncp_m_s_to_mm_s(self.frame.velocity_m_s[1])?,
            ncp_m_s_to_mm_s(self.frame.velocity_m_s[2])?,
        ])
    }

    /// Command validity carried by the exact frame.
    #[must_use]
    pub const fn validity_ms(&self) -> u32 {
        self.frame.validity_ms
    }

    /// The NCP authority lease carried by the exact frame.
    #[must_use]
    pub const fn authority(&self) -> &haldir_contracts::status::NcpLeaseEvidenceV1 {
        &self.frame.authority
    }

    /// Whether the semantic frame, exact bytes, digest, and transformation still
    /// form the single immutable output built by the adapter.
    ///
    /// This checks the selected profile's deterministic projection. It does not
    /// make a non-injective profile encoding injective: two distinct internal
    /// nanosecond values can legitimately rebuild the same NCP 1.0 JSON bytes.
    #[must_use]
    pub fn is_self_consistent(&self) -> bool {
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
        let bytes_match_semantics = match self.wire_profile {
            NcpCommandWireProfile::ModeledP0 => self.frame.wire_bytes() == self.bytes,
            NcpCommandWireProfile::ExactNcpV1_0Json => {
                #[cfg(feature = "real-ncp")]
                {
                    crate::real::exact_bytes_match_semantic(&self.frame, &self.bytes)
                }
                #[cfg(not(feature = "real-ncp"))]
                {
                    false
                }
            }
        };

        self.transformation == expected_transformation
            && self.frame.authority.session == self.frame.session
            && hold_is_zero
            && self.frame.validity_ms != 0
            && self.decoded_velocity_mm_s().is_ok()
            && bytes_match_semantics
            && DigestV1::compute(DigestDomain::OutputFrame, &self.bytes) == self.digest
    }
}

pub(crate) fn build_semantic_frame(
    input: &GateCommandBuildInputV1,
) -> Result<(NcpCommandFrameV1, TransformationRelationV1), NcpAdapterError> {
    if input.effective_validity_ms == 0
        || input.effective_validity_ms > input.action.requested_validity_ms().get()
    {
        return Err(NcpAdapterError::InvalidEffectiveValidity);
    }
    if input.stream.seq.get() > NCP_JSON_SAFE_INTEGER_MAX
        || input.source.stream_seq.get() > NCP_JSON_SAFE_INTEGER_MAX
    {
        return Err(NcpAdapterError::ConversionOutOfRange);
    }
    validate_lease(input)?;

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
            authority: input.lease.clone(),
        },
        transformation,
    ))
}

/// Check the lease against the NCP 1.0 authority rules that Gate can verify
/// locally. The body remains the enforcer of term order and holder identity.
fn validate_lease(input: &GateCommandBuildInputV1) -> Result<(), NcpAdapterError> {
    let lease = &input.lease;
    if lease.session != input.session
        || lease.authorized_output_epoch != input.stream.epoch
        || lease.expires_mono_ns.is_none()
    {
        return Err(NcpAdapterError::InvalidAuthority);
    }
    if lease.authority_term.get() > NCP_JSON_SAFE_INTEGER_MAX
        || lease.issued_at_utc_ms > NCP_JSON_SAFE_INTEGER_MAX
        || lease.expires_at_utc_ms > NCP_JSON_SAFE_INTEGER_MAX
    {
        return Err(NcpAdapterError::ConversionOutOfRange);
    }
    let interval = lease
        .expires_at_utc_ms
        .checked_sub(lease.issued_at_utc_ms)
        .ok_or(NcpAdapterError::InvalidAuthority)?;
    if interval == 0 || interval > NCP_MAX_AUTHORITY_LEASE_MS {
        return Err(NcpAdapterError::InvalidAuthority);
    }
    Ok(())
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

/// The modeled `NCP_1_0_COMMANDER_LEASE` adapter for NCP `1.0.0-rc.1` increment 1.
#[derive(Debug, Clone)]
pub struct ModeledNcp10Adapter {
    compat: NcpCompatibilityRecordV1,
}

impl ModeledNcp10Adapter {
    /// A new adapter pinned to NCP `1.0.0-rc.1`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            compat: NCP_V1_0_0_RC1,
        }
    }
}

impl Default for ModeledNcp10Adapter {
    fn default() -> Self {
        Self::new()
    }
}

impl NcpCommandAdapter for ModeledNcp10Adapter {
    fn compatibility(&self) -> &NcpCompatibilityRecordV1 {
        &self.compat
    }

    fn build_command(
        &self,
        input: &GateCommandBuildInputV1,
    ) -> Result<ExactNcpCommandFrame, NcpAdapterError> {
        let (frame, transformation) = build_semantic_frame(input)?;
        let bytes = frame.wire_bytes();
        Ok(ExactNcpCommandFrame::from_modeled_parts(
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
    use crate::test_support::lease_for;
    use core::num::{NonZeroU32, NonZeroU64};
    use haldir_contracts::ids::{GateId, GateOutputEpoch, OutputSeq, SourceSeq};
    use haldir_contracts::scalar::{AsciiId, BoundedAscii, CanonicalUuidV4String};

    fn input(action: RequestedActionV1) -> GateCommandBuildInputV1 {
        let session = NcpSessionIdentityV1 {
            session_id: AsciiId::new("sess-1").unwrap(),
            generation: CanonicalUuidV4String::from_random_bytes([1; 16]),
        };
        let epoch = GateOutputEpoch::new(CanonicalUuidV4String::from_random_bytes([5; 16]));
        GateCommandBuildInputV1 {
            lease: lease_for(&session, epoch),
            session,
            stream: NcpStreamPositionV1 {
                epoch,
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
    fn lease_for_another_session_is_refused() {
        let adapter = ModeledNcp10Adapter::new();
        let mut input = hold_input();
        input.lease.session.generation = CanonicalUuidV4String::from_random_bytes([9; 16]);
        assert_eq!(
            adapter.build_command(&input),
            Err(NcpAdapterError::InvalidAuthority)
        );
    }

    #[test]
    fn lease_without_a_gate_local_deadline_is_refused() {
        let adapter = ModeledNcp10Adapter::new();
        let mut input = hold_input();
        input.lease.expires_mono_ns = None;
        assert_eq!(
            adapter.build_command(&input),
            Err(NcpAdapterError::InvalidAuthority)
        );
    }

    #[test]
    fn empty_inverted_or_over_long_lease_intervals_are_refused() {
        let adapter = ModeledNcp10Adapter::new();
        for (issued, expires) in [
            (1_700_000_000_000, 1_700_000_000_000),
            (1_700_000_000_001, 1_700_000_000_000),
            (
                1_700_000_000_000,
                1_700_000_000_000 + NCP_MAX_AUTHORITY_LEASE_MS + 1,
            ),
        ] {
            let mut input = hold_input();
            input.lease.issued_at_utc_ms = issued;
            input.lease.expires_at_utc_ms = expires;
            assert_eq!(
                adapter.build_command(&input),
                Err(NcpAdapterError::InvalidAuthority)
            );
        }
        let mut longest = hold_input();
        longest.lease.expires_at_utc_ms =
            longest.lease.issued_at_utc_ms + NCP_MAX_AUTHORITY_LEASE_MS;
        assert!(adapter.build_command(&longest).is_ok());
    }

    #[test]
    fn lease_values_beyond_the_json_safe_range_are_refused() {
        let adapter = ModeledNcp10Adapter::new();
        let mut input = hold_input();
        input.lease.authority_term = NonZeroU64::new(NCP_JSON_SAFE_INTEGER_MAX + 1).unwrap();
        assert_eq!(
            adapter.build_command(&input),
            Err(NcpAdapterError::ConversionOutOfRange)
        );
    }

    #[test]
    fn every_lease_field_changes_the_modeled_bytes() {
        let adapter = ModeledNcp10Adapter::new();
        let base = adapter.build_command(&hold_input()).unwrap();
        let mut variants = Vec::new();
        let mut term = hold_input();
        term.lease.authority_term = NonZeroU64::new(2).unwrap();
        variants.push(term);
        let mut id = hold_input();
        id.lease.lease_id = CanonicalUuidV4String::from_random_bytes([7; 16]);
        variants.push(id);
        let mut entity = hold_input();
        entity.lease.holder_entity = GateId::new("gate-b").unwrap();
        variants.push(entity);
        let mut expiry = hold_input();
        expiry.lease.expires_at_utc_ms -= 1;
        variants.push(expiry);
        for variant in variants {
            let frame = adapter.build_command(&variant).unwrap();
            assert_ne!(frame.bytes(), base.bytes());
            assert_ne!(frame.digest(), base.digest());
        }
    }

    #[test]
    fn validator_rejects_internal_frame_tampering() {
        let adapter = ModeledNcp10Adapter::new();
        let input = hold_input();
        let mut exact = adapter.build_command(&input).unwrap();
        exact.frame.is_hold = false;

        assert!(!exact.is_self_consistent());
        assert_eq!(
            adapter.validate_exact_command(&exact, &input),
            Err(NcpAdapterError::ValidatorMismatch)
        );
    }

    #[test]
    fn validator_rejects_internal_bytes_tampering() {
        let adapter = ModeledNcp10Adapter::new();
        let input = hold_input();
        let mut exact = adapter.build_command(&input).unwrap();
        exact.bytes.push(0xff);

        assert!(!exact.is_self_consistent());
        assert_eq!(
            adapter.validate_exact_command(&exact, &input),
            Err(NcpAdapterError::ValidatorMismatch)
        );
    }

    #[test]
    fn validator_rejects_internal_digest_tampering() {
        let adapter = ModeledNcp10Adapter::new();
        let input = hold_input();
        let mut exact = adapter.build_command(&input).unwrap();
        exact.digest = DigestV1::compute(DigestDomain::OutputFrame, b"tampered");

        assert!(!exact.is_self_consistent());
        assert_eq!(
            adapter.validate_exact_command(&exact, &input),
            Err(NcpAdapterError::ValidatorMismatch)
        );
    }

    #[test]
    fn validator_rejects_internal_transformation_tampering() {
        let adapter = ModeledNcp10Adapter::new();
        let input = hold_input();
        let mut exact = adapter.build_command(&input).unwrap();
        exact.transformation = TransformationRelationV1::FixedPointToNcpFloatV1;

        assert!(!exact.is_self_consistent());
        assert_eq!(
            adapter.validate_exact_command(&exact, &input),
            Err(NcpAdapterError::ValidatorMismatch)
        );
    }

    #[test]
    fn effective_validity_cannot_exceed_the_signed_request() {
        let adapter = ModeledNcp10Adapter::new();
        let mut input = hold_input();
        input.effective_validity_ms = 301;

        assert_eq!(
            adapter.build_command(&input),
            Err(NcpAdapterError::InvalidEffectiveValidity)
        );
    }

    #[test]
    fn effective_validity_must_be_nonzero() {
        let adapter = ModeledNcp10Adapter::new();
        let mut input = hold_input();
        input.effective_validity_ms = 0;

        assert_eq!(
            adapter.build_command(&input),
            Err(NcpAdapterError::InvalidEffectiveValidity)
        );
    }

    #[test]
    fn self_consistency_rejects_zero_validity_even_if_all_bytes_are_rebuilt() {
        let adapter = ModeledNcp10Adapter::new();
        let input = hold_input();
        let mut exact = adapter.build_command(&input).unwrap();
        exact.frame.validity_ms = 0;
        exact.bytes = exact.frame.wire_bytes();
        exact.digest = DigestV1::compute(DigestDomain::OutputFrame, &exact.bytes);

        assert!(!exact.is_self_consistent());
    }
}
