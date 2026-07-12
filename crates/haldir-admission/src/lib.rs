//! `haldir-admission` — deterministic controller/backend admission records,
//! cumulative admission levels, and an immutable admission snapshot.
//!
//! No neural runtime is executed here or in the Gate: the Gate loads only
//! verified signed admission snapshots and checks exact digest equality
//! (spec Phase 4). Backend behavioural conformance (running NEST/Norse/Rockpool)
//! is performed by offline tools outside this crate and is **not** part of the P0
//! deliverable (see `docs/LIMITATIONS.md`).
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

pub mod error;
pub mod manifest;
pub mod record;
pub mod snapshot;
pub mod types;

/// Crate version string.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub use error::AdmissionError;
pub use manifest::ControllerBundleManifestV1;
pub use record::AdmissionRecordV1;
pub use snapshot::{AdmissionClaim, AdmissionRelation, AdmissionSnapshot};
pub use types::{AdmissionLevelV1, ArtifactRefV1};

#[cfg(test)]
mod tests {
    use super::*;
    use core::num::NonZeroU64;
    use haldir_contracts::digest::{DigestDomain, DigestV1};
    use haldir_contracts::ids::{AdmissionId, ControllerId};
    use haldir_contracts::scalar::{AsciiId, BoundedVec};

    fn art(seed: u8) -> ArtifactRefV1 {
        ArtifactRefV1 {
            digest: DigestV1::compute(DigestDomain::Bundle, &[seed]),
            size_bytes: u64::from(seed) * 100,
            media_type: AsciiId::new("application.octet-stream").unwrap(),
        }
    }

    fn manifest() -> ControllerBundleManifestV1 {
        ControllerBundleManifestV1 {
            schema_major: 1,
            schema_minor: 0,
            controller_id: ControllerId::new("survey-v1").unwrap(),
            bundle_id: [1; 16],
            admission_profile_id: AsciiId::new("fixed-weight-lif-control-v1").unwrap(),
            logical_graph: art(1),
            topology: art(2),
            parameter_tensors: BoundedVec::from_vec(vec![art(3), art(4)]).unwrap(),
            codec: art(5),
            time_contract: art(6),
            reset_contract: art(7),
            conformance_vectors: art(8),
            build_provenance: art(9),
            opaque_dependencies: BoundedVec::new(),
        }
    }

    fn record_for(bundle_digest: DigestV1, level: AdmissionLevelV1) -> AdmissionRecordV1 {
        AdmissionRecordV1 {
            schema_major: 1,
            schema_minor: 0,
            issuer_id: AsciiId::new("admission-authority").unwrap(),
            admission_id: AdmissionId::new([4; 16]),
            controller_id: ControllerId::new("survey-v1").unwrap(),
            admission_profile_id: AsciiId::new("fixed-weight-lif-control-v1").unwrap(),
            level,
            controller_bundle_digest: bundle_digest,
            backend_profile_digest: DigestV1::compute(DigestDomain::BackendProfile, b"nest-3.9"),
            codec_digest: DigestV1::compute(DigestDomain::Payload, b"codec"),
            validity_term: NonZeroU64::new(1).unwrap(),
            conformance_run_digest: Some(DigestV1::compute(DigestDomain::Payload, b"conf")),
        }
    }

    fn bundle_digest(m: &ControllerBundleManifestV1) -> DigestV1 {
        DigestV1::of_value(DigestDomain::Bundle, m)
    }

    #[test]
    fn manifest_is_profile_complete_without_opaque_deps() {
        assert!(manifest().is_profile_complete());
    }

    #[test]
    fn mutating_any_manifest_field_changes_the_digest() {
        let base = bundle_digest(&manifest());

        let mut m = manifest();
        m.bundle_id = [2; 16];
        assert_ne!(bundle_digest(&m), base, "bundle_id mutation undetected");

        let mut m = manifest();
        m.parameter_tensors = BoundedVec::from_vec(vec![art(3), art(99)]).unwrap();
        assert_ne!(bundle_digest(&m), base, "tensor mutation undetected");

        let mut m = manifest();
        m.reset_contract = art(77);
        assert_ne!(
            bundle_digest(&m),
            base,
            "reset-contract mutation undetected"
        );

        let mut m = manifest();
        m.codec = art(66);
        assert_ne!(bundle_digest(&m), base, "codec mutation undetected");
    }

    #[test]
    fn admission_verifies_matching_claim() {
        let bd = bundle_digest(&manifest());
        let rec = record_for(bd, AdmissionLevelV1::A2ReferenceConformance);
        let admission_digest = rec.admission_digest();
        let backend = rec.backend_profile_digest;
        let mut snap = AdmissionSnapshot::new();
        snap.insert(rec);
        let cid = ControllerId::new("survey-v1").unwrap();
        let aid = AdmissionId::new([4; 16]);
        let claim = AdmissionClaim {
            admission_id: &aid,
            admission_digest: &admission_digest,
            controller_id: &cid,
            controller_bundle_digest: &bd,
            backend_profile_digest: &backend,
        };
        assert_eq!(
            snap.verify_admission(&claim, true).unwrap(),
            AdmissionLevelV1::A2ReferenceConformance
        );
    }

    #[test]
    fn substituted_bundle_is_rejected() {
        // A mutated (redeployed) bundle produces a different digest than the one
        // the admission authority approved -> deny.
        let admitted = bundle_digest(&manifest());
        let rec = record_for(admitted, AdmissionLevelV1::A2ReferenceConformance);
        let admission_digest = rec.admission_digest();
        let backend = rec.backend_profile_digest;
        let mut snap = AdmissionSnapshot::new();
        snap.insert(rec);

        let mut mutated = manifest();
        mutated.parameter_tensors = BoundedVec::from_vec(vec![art(3), art(200)]).unwrap();
        let deployed = bundle_digest(&mutated);

        let cid = ControllerId::new("survey-v1").unwrap();
        let aid = AdmissionId::new([4; 16]);
        let claim = AdmissionClaim {
            admission_id: &aid,
            admission_digest: &admission_digest,
            controller_id: &cid,
            controller_bundle_digest: &deployed,
            backend_profile_digest: &backend,
        };
        assert_eq!(
            snap.verify_admission(&claim, true).err(),
            Some(AdmissionError::BundleMismatch)
        );
    }

    #[test]
    fn unknown_revoked_digest_mismatch_and_opaque() {
        let bd = bundle_digest(&manifest());
        let rec = record_for(bd, AdmissionLevelV1::OpaqueController);
        let good_digest = rec.admission_digest();
        let backend = rec.backend_profile_digest;
        let mut snap = AdmissionSnapshot::new();
        snap.insert(rec);
        let cid = ControllerId::new("survey-v1").unwrap();
        let aid = AdmissionId::new([4; 16]);
        let other = AdmissionId::new([9; 16]);
        let wrong_digest = DigestV1::compute(DigestDomain::Admission, b"nope");

        // unknown id
        let claim = AdmissionClaim {
            admission_id: &other,
            admission_digest: &good_digest,
            controller_id: &cid,
            controller_bundle_digest: &bd,
            backend_profile_digest: &backend,
        };
        assert_eq!(
            snap.verify_admission(&claim, true).err(),
            Some(AdmissionError::Unknown)
        );

        // digest mismatch
        let claim = AdmissionClaim {
            admission_id: &aid,
            admission_digest: &wrong_digest,
            controller_id: &cid,
            controller_bundle_digest: &bd,
            backend_profile_digest: &backend,
        };
        assert_eq!(
            snap.verify_admission(&claim, false).err(),
            Some(AdmissionError::DigestMismatch)
        );

        // opaque rejected when semantic required, level returned when not
        let claim = AdmissionClaim {
            admission_id: &aid,
            admission_digest: &good_digest,
            controller_id: &cid,
            controller_bundle_digest: &bd,
            backend_profile_digest: &backend,
        };
        assert_eq!(
            snap.verify_admission(&claim, true).err(),
            Some(AdmissionError::NotSemantic)
        );
        assert_eq!(
            snap.verify_admission(&claim, false).unwrap(),
            AdmissionLevelV1::OpaqueController
        );

        // revoked
        snap.revoke(&aid, 1);
        assert_eq!(
            snap.verify_admission(&claim, false).err(),
            Some(AdmissionError::Revoked)
        );
    }
}
