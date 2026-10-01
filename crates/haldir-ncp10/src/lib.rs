//! `haldir-ncp10` — Haldir's NCP `1.0.0-rc.1` command adapter.
//!
//! This is the ONLY crate aware of NCP wire semantics (spec §Isolation rule).
//! The default build is a dependency-light semantic model of the wire. The
//! off-by-default `real-ncp` feature adds an exact adapter built and validated by
//! the upstream `ncp-core` crate at an immutable commit, checked against NCP's
//! frozen 1.0 conformance corpus. Every publisher-owned field comes from Gate
//! state, including the NCP authority lease that [`lease`] issues.
#![forbid(unsafe_code)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::float_cmp
    )
)]

pub mod adapter;
pub mod command;
pub mod compatibility;
pub mod conversion;
pub mod error;
pub mod lease;
#[cfg(feature = "real-ncp")]
pub mod real;
pub mod selection;
#[cfg(test)]
mod test_support;

/// Crate version string.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub use adapter::{
    ExactNcpCommandFrame, GateCommandBuildInputV1, ModeledNcp10Adapter, NCP_JSON_SAFE_INTEGER_MAX,
    NCP_MAX_AUTHORITY_LEASE_MS, NCP_MAX_CLOCK_UNCERTAINTY_MS, NcpCommandAdapter, NcpCommandFrameV1,
    NcpCommandWireProfile,
};
pub use command::{PlantAction, PlantCommand, PlantCommandError};
pub use compatibility::{
    NCP_COMPATIBILITY_ARTIFACT_MAX_BYTES, NCP_V1_0_0_RC1, NcpCompatibilityArtifactV1,
    NcpCompatibilityError, NcpCompatibilityRecordV1, ValidatedNcpCompatibilityArtifact,
    pinned_ncp_compatibility_artifact_bytes, validate_ncp_compatibility_artifact,
};
pub use conversion::{mm_s_to_ncp_m_s, ncp_m_s_to_mm_s};
pub use error::NcpAdapterError;
pub use lease::{NcpCommanderLease, NcpLeaseInterval};
#[cfg(feature = "real-ncp")]
pub use real::RealNcp10Adapter;
pub use selection::SelectedNcpCommandAdapter;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::lease_for;
    use core::num::{NonZeroU32, NonZeroU64};
    use haldir_contracts::action::RequestedActionV1;
    use haldir_contracts::ids::{GateOutputEpoch, OutputSeq, SourceSeq};
    use haldir_contracts::scalar::{AsciiId, BoundedAscii, CanonicalUuidV4String};
    use haldir_contracts::session::{NcpSessionIdentityV1, NcpSourceRefV1, NcpStreamPositionV1};

    fn session() -> NcpSessionIdentityV1 {
        NcpSessionIdentityV1 {
            session_id: AsciiId::new("sess-1").unwrap(),
            generation: CanonicalUuidV4String::from_random_bytes([1; 16]),
        }
    }

    fn epoch() -> GateOutputEpoch {
        GateOutputEpoch::new(CanonicalUuidV4String::from_random_bytes([5; 16]))
    }

    fn input(seq: u64, action: RequestedActionV1) -> GateCommandBuildInputV1 {
        GateCommandBuildInputV1 {
            session: session(),
            stream: NcpStreamPositionV1 {
                epoch: epoch(),
                seq: OutputSeq::new(NonZeroU64::new(seq).unwrap()),
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
            lease: lease_for(&session(), epoch()),
        }
    }

    #[test]
    fn compatibility_is_pinned_to_ncp_1_0_0_rc1() {
        let a = ModeledNcp10Adapter::new();
        assert_eq!(a.compatibility().ncp_tag, "1.0.0-rc.1");
        assert_eq!(a.compatibility().wire_version, "1.0");
        assert_eq!(
            a.compatibility().ncp_commit,
            "2819dae3b6338bb1df6d105ebb5b7433936a993d"
        );
        assert_eq!(
            a.compatibility().capability_profile,
            "NCP_1_0_COMMANDER_LEASE"
        );
    }

    #[test]
    fn build_is_deterministic_and_validates() {
        let a = ModeledNcp10Adapter::new();
        let inp = input(
            1,
            RequestedActionV1::VelocityLocalNed {
                north_mm_s: 500,
                east_mm_s: -250,
                down_mm_s: 0,
                requested_validity_ms: NonZeroU32::new(300).unwrap(),
            },
        );
        let f1 = a.build_command(&inp).unwrap();
        let f2 = a.build_command(&inp).unwrap();
        assert_eq!(f1.bytes(), f2.bytes(), "build is deterministic");
        assert_eq!(f1.digest(), f2.digest());
        assert_eq!(f1.wire_profile(), NcpCommandWireProfile::ModeledP0);
        assert!(f1.source_key_is_wire_bound());
        assert!(f1.is_self_consistent());
        assert!(a.validate_exact_command(&f1, &inp).is_ok());
        // decoded velocity round-trips the fixed-point exactly (H17)
        assert_eq!(f1.decoded_velocity_mm_s().unwrap(), [500, -250, 0]);
        assert_eq!(
            f1.transformation(),
            haldir_contracts::receipt::TransformationRelationV1::FixedPointToNcpFloatV1
        );
    }

    #[test]
    fn hold_uses_identity_transformation() {
        let a = ModeledNcp10Adapter::new();
        let inp = input(
            1,
            RequestedActionV1::Hold {
                requested_validity_ms: NonZeroU32::new(300).unwrap(),
            },
        );
        let f = a.build_command(&inp).unwrap();
        assert!(f.is_hold());
        assert_eq!(
            f.transformation(),
            haldir_contracts::receipt::TransformationRelationV1::Identity
        );
    }

    #[test]
    fn different_stream_seq_yields_different_bytes() {
        let a = ModeledNcp10Adapter::new();
        let hold = RequestedActionV1::Hold {
            requested_validity_ms: NonZeroU32::new(300).unwrap(),
        };
        let f1 = a.build_command(&input(1, hold)).unwrap();
        let f2 = a.build_command(&input(2, hold)).unwrap();
        assert_ne!(
            f1.bytes(),
            f2.bytes(),
            "a new logical command is a new sequence"
        );
    }

    #[test]
    fn json_safe_sequence_boundaries_are_enforced() {
        let a = ModeledNcp10Adapter::new();
        let hold = RequestedActionV1::Hold {
            requested_validity_ms: NonZeroU32::new(300).unwrap(),
        };
        let at_limit = input(NCP_JSON_SAFE_INTEGER_MAX, hold);
        assert!(a.build_command(&at_limit).is_ok());

        let over_limit = input(NCP_JSON_SAFE_INTEGER_MAX + 1, hold);
        assert_eq!(
            a.build_command(&over_limit).unwrap_err(),
            NcpAdapterError::ConversionOutOfRange
        );

        let mut source_at_limit = input(1, hold);
        source_at_limit.source.stream_seq =
            SourceSeq::new(NonZeroU64::new(NCP_JSON_SAFE_INTEGER_MAX).unwrap());
        assert!(a.build_command(&source_at_limit).is_ok());

        source_at_limit.source.stream_seq =
            SourceSeq::new(NonZeroU64::new(NCP_JSON_SAFE_INTEGER_MAX + 1).unwrap());
        assert_eq!(
            a.build_command(&source_at_limit).unwrap_err(),
            NcpAdapterError::ConversionOutOfRange
        );
    }
}
