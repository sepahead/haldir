//! `haldir-ncp08` — the immutable-tag-pinned NCP `v0.8.0` command adapter.
//!
//! This is the ONLY crate aware of NCP wire semantics (spec §Isolation rule).
//! For the P0 `PRE_AUTHORITY_ACL_ONLY` profile it models the wire without the real
//! `ncp-core`/Zenoh dependency; the compatibility record pins the exact upstream
//! release so a future adapter can swap in the real dependency behind a
//! semantic-diff + corpus-replay gate. Every publisher-owned field of the emitted
//! frame comes from Gate state; plant authority/publisher-id fields do not exist
//! under increment 1 and are NOT fabricated (see `docs/LIMITATIONS.md`).
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
pub mod compatibility;
pub mod conversion;
pub mod error;

/// Crate version string.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub use adapter::{
    AclOnlyAdapter, ExactNcpCommandFrame, GateCommandBuildInputV1, NCP_JSON_SAFE_INTEGER_MAX,
    NcpCommandAdapter, NcpCommandFrameV1,
};
pub use compatibility::{NCP_V0_8_0, NcpCompatibilityRecordV1};
pub use conversion::{mm_s_to_ncp_m_s, ncp_m_s_to_mm_s};
pub use error::NcpAdapterError;

#[cfg(test)]
mod tests {
    use super::*;
    use core::num::{NonZeroU32, NonZeroU64};
    use haldir_contracts::action::RequestedActionV1;
    use haldir_contracts::ids::{DecisionId, GateOutputEpoch, OutputSeq, SourceSeq};
    use haldir_contracts::scalar::{AsciiId, BoundedAscii, CanonicalUuidV4String};
    use haldir_contracts::session::{NcpSessionIdentityV1, NcpSourceRefV1, NcpStreamPositionV1};

    fn input(seq: u64, action: RequestedActionV1) -> GateCommandBuildInputV1 {
        GateCommandBuildInputV1 {
            decision_id: DecisionId::new([1; 16]),
            session: NcpSessionIdentityV1 {
                session_id: AsciiId::new("sess-1").unwrap(),
                generation: CanonicalUuidV4String::from_random_bytes([1; 16]),
            },
            stream: NcpStreamPositionV1 {
                epoch: GateOutputEpoch::new(CanonicalUuidV4String::from_random_bytes([5; 16])),
                seq: OutputSeq::new(NonZeroU64::new(seq).unwrap()),
            },
            source: NcpSourceRefV1 {
                source_key: BoundedAscii::new("veh/uav-1/state/pose").unwrap(),
                stream_epoch: CanonicalUuidV4String::from_random_bytes([2; 16]),
                stream_seq: SourceSeq::new(NonZeroU64::new(7).unwrap()),
            },
            source_t_ns: 111,
            gate_t_ns: 222,
            action,
            effective_validity_ms: 300,
        }
    }

    #[test]
    fn compatibility_is_pinned_to_v0_8_0() {
        let a = AclOnlyAdapter::new();
        assert_eq!(a.compatibility().ncp_tag, "v0.8.0");
        assert_eq!(
            a.compatibility().ncp_commit,
            "2f5bd586d4bb20c90362bb6f5698b7f64057ba4e"
        );
        assert_eq!(
            a.compatibility().capability_profile,
            "PRE_AUTHORITY_ACL_ONLY"
        );
    }

    #[test]
    fn build_is_deterministic_and_validates() {
        let a = AclOnlyAdapter::new();
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
        assert!(a.validate_exact_command(&f1, &inp).is_ok());
        // decoded velocity round-trips the fixed-point exactly (H17)
        assert_eq!(f1.decoded_velocity_mm_s(), [500, -250, 0]);
        assert_eq!(
            f1.transformation(),
            haldir_contracts::receipt::TransformationRelationV1::FixedPointToNcpFloatV1
        );
    }

    #[test]
    fn hold_uses_identity_transformation() {
        let a = AclOnlyAdapter::new();
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
        let a = AclOnlyAdapter::new();
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
        let a = AclOnlyAdapter::new();
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
