//! `haldir-admission` — deterministic controller/backend admission records,
//! cumulative admission levels, and an immutable admission snapshot.
//!
//! No neural runtime is executed here or in the Gate. This crate validates the
//! supported record schema and checks exact admission bindings, but it does not
//! verify record signatures, authenticate a snapshot loader, establish snapshot
//! freshness, or earn an admission level. A deployment must supply those
//! properties before inserting records. Backend behavioural conformance
//! (running NEST/Norse/Rockpool) is outside this crate and is **not** part of the
//! P0 deliverable (see `docs/LIMITATIONS.md`).
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

pub use error::{AdmissionError, AdmissionSnapshotError};
pub use manifest::ControllerBundleManifestV1;
pub use record::AdmissionRecordV1;
pub use snapshot::{
    ADMISSION_SNAPSHOT_DIGEST_SCHEMA_V1, AdmissionClaim, AdmissionRelation, AdmissionSnapshot,
    MAX_ADMISSION_RECORDS, MAX_REVOKED_ADMISSIONS,
};
pub use types::{AdmissionLevelV1, ArtifactRefV1};

#[cfg(test)]
mod tests {
    use super::*;
    use core::num::NonZeroU64;
    use haldir_contracts::cbor::{Limits, from_canonical_bytes, to_canonical_bytes};
    use haldir_contracts::digest::{DigestDomain, DigestV1};
    use haldir_contracts::error::DecodeError;
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

    fn semantic_record() -> AdmissionRecordV1 {
        record_for(
            bundle_digest(&manifest()),
            AdmissionLevelV1::A2ReferenceConformance,
        )
    }

    fn conflicting_record(record: &AdmissionRecordV1) -> AdmissionRecordV1 {
        let mut conflicting = record.clone();
        conflicting.backend_profile_digest =
            DigestV1::compute(DigestDomain::BackendProfile, b"norse-2.0");
        conflicting
    }

    fn admission_id(index: u64) -> AdmissionId {
        let mut bytes = [0_u8; 16];
        bytes[8..].copy_from_slice(&index.to_be_bytes());
        AdmissionId::new(bytes)
    }

    #[test]
    fn manifest_is_profile_complete_without_opaque_deps() {
        assert!(manifest().is_profile_complete());
    }

    #[test]
    fn manifest_rejects_nonzero_schema_minor() {
        let mut manifest = manifest();
        manifest.schema_minor = 1;
        let bytes = to_canonical_bytes(&manifest);

        assert_eq!(
            from_canonical_bytes::<ControllerBundleManifestV1>(&bytes, Limits::LARGE),
            Err(DecodeError::UnsupportedVersion)
        );
    }

    #[test]
    fn admission_record_rejects_nonzero_schema_minor() {
        let mut record = semantic_record();
        record.schema_minor = 1;
        let bytes = to_canonical_bytes(&record);

        assert_eq!(
            from_canonical_bytes::<AdmissionRecordV1>(&bytes, Limits::LARGE),
            Err(DecodeError::UnsupportedVersion)
        );
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
        snap.try_insert(rec).unwrap();
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
        snap.try_insert(rec).unwrap();

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
        snap.try_insert(rec).unwrap();
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
        snap.revoke(&other, 1).unwrap();
        assert_eq!(
            snap.verify_admission(&claim, true).err(),
            Some(AdmissionError::Revoked),
            "a retained revocation must not depend on an active record"
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
        snap.revoke(&aid, 2).unwrap();
        assert_eq!(
            snap.verify_admission(&claim, false).err(),
            Some(AdmissionError::Revoked)
        );
    }

    #[test]
    fn try_insert_is_idempotent_for_exact_duplicate() {
        let record = semantic_record();
        let admission_id = record.admission_id;
        let expected_digest = record.admission_digest();
        let mut snapshot = AdmissionSnapshot::new();

        snapshot.try_insert(record.clone()).unwrap();
        snapshot.try_insert(record.clone()).unwrap();

        let relation = snapshot.resolve(&admission_id).unwrap();
        assert_eq!(
            (&relation.record, relation.digest),
            (&record, expected_digest)
        );
    }

    #[test]
    fn try_insert_rejects_invalid_record_without_mutating_snapshot() {
        let mut snapshot = AdmissionSnapshot::new();
        let valid = semantic_record();
        snapshot.try_insert(valid.clone()).unwrap();
        let before = snapshot.resolve(&valid.admission_id).unwrap().digest;

        let mut invalid = valid.clone();
        invalid.schema_minor = 1;
        assert_eq!(
            snapshot.try_insert(invalid),
            Err(AdmissionSnapshotError::InvalidRecord)
        );
        assert_eq!(
            snapshot.resolve(&valid.admission_id).unwrap().digest,
            before
        );

        let mut invalid_new_id = valid;
        invalid_new_id.admission_id = admission_id(99);
        invalid_new_id.schema_major = 2;
        assert_eq!(
            snapshot.try_insert(invalid_new_id.clone()),
            Err(AdmissionSnapshotError::InvalidRecord)
        );
        assert!(snapshot.resolve(&invalid_new_id.admission_id).is_none());

        let mut unevidenced = semantic_record();
        unevidenced.admission_id = admission_id(100);
        unevidenced.conformance_run_digest = None;
        assert_eq!(
            snapshot.try_insert(unevidenced.clone()),
            Err(AdmissionSnapshotError::InvalidRecord)
        );
        assert!(snapshot.resolve(&unevidenced.admission_id).is_none());
    }

    #[test]
    fn try_insert_rejects_conflicting_same_id() {
        let record = semantic_record();
        let conflict = conflicting_record(&record);
        let mut snapshot = AdmissionSnapshot::new();
        snapshot.try_insert(record).unwrap();

        assert_eq!(
            snapshot.try_insert(conflict),
            Err(AdmissionSnapshotError::ConflictingAdmissionId)
        );
    }

    #[test]
    fn try_insert_conflict_preserves_original_record_and_digest() {
        let record = semantic_record();
        let admission_id = record.admission_id;
        let expected_digest = record.admission_digest();
        let conflict = conflicting_record(&record);
        let mut snapshot = AdmissionSnapshot::new();
        snapshot.try_insert(record.clone()).unwrap();

        assert_eq!(
            snapshot.try_insert(conflict),
            Err(AdmissionSnapshotError::ConflictingAdmissionId)
        );
        let relation = snapshot.resolve(&admission_id).unwrap();
        assert_eq!(
            (&relation.record, relation.digest),
            (&record, expected_digest),
            "conflict must leave the original record and digest unchanged"
        );
    }

    #[test]
    fn admission_snapshot_error_reason_code_and_display_are_stable() {
        for (error, code) in [
            (
                AdmissionSnapshotError::InvalidRecord,
                "ADMISSION_SNAPSHOT_INVALID_RECORD",
            ),
            (
                AdmissionSnapshotError::ConflictingAdmissionId,
                "ADMISSION_SNAPSHOT_CONFLICTING_ADMISSION_ID",
            ),
            (
                AdmissionSnapshotError::RecordCapacityExceeded,
                "ADMISSION_SNAPSHOT_RECORD_CAPACITY_EXCEEDED",
            ),
            (
                AdmissionSnapshotError::RevocationEpochNotAdvanced,
                "ADMISSION_SNAPSHOT_REVOCATION_EPOCH_NOT_ADVANCED",
            ),
            (
                AdmissionSnapshotError::RevocationCapacityExceeded,
                "ADMISSION_SNAPSHOT_REVOCATION_CAPACITY_EXCEEDED",
            ),
        ] {
            assert_eq!(error.reason_code(), code);
            assert_eq!(error.to_string(), code);
        }
    }

    #[test]
    fn admission_record_capacity_is_exact_and_failure_is_atomic() {
        let template = semantic_record();
        let mut snapshot = AdmissionSnapshot::new();
        for index in 1..=u64::try_from(MAX_ADMISSION_RECORDS).unwrap() {
            let mut record = template.clone();
            record.admission_id = admission_id(index);
            snapshot.try_insert(record).unwrap();
        }

        let mut rejected = template.clone();
        rejected.admission_id = admission_id(u64::try_from(MAX_ADMISSION_RECORDS + 1).unwrap());
        assert_eq!(
            snapshot.try_insert(rejected.clone()),
            Err(AdmissionSnapshotError::RecordCapacityExceeded)
        );
        assert!(snapshot.resolve(&rejected.admission_id).is_none());

        let existing_id = admission_id(1);
        let existing = snapshot.resolve(&existing_id).unwrap().record.clone();
        snapshot.try_insert(existing).unwrap();
        let conflict = conflicting_record(&snapshot.resolve(&existing_id).unwrap().record);
        assert_eq!(
            snapshot.try_insert(conflict),
            Err(AdmissionSnapshotError::ConflictingAdmissionId)
        );
    }

    #[test]
    fn admission_revocations_are_bounded_strictly_versioned_and_atomic() {
        let first = admission_id(1);
        let second = admission_id(2);
        let mut snapshot = AdmissionSnapshot::new();
        snapshot.revoke(&first, 1).unwrap();
        assert_eq!(
            snapshot.revoke(&second, 1),
            Err(AdmissionSnapshotError::RevocationEpochNotAdvanced)
        );
        assert_eq!(snapshot.revocation_epoch(), 1);
        snapshot.revoke(&first, 0).unwrap();
        assert_eq!(snapshot.revocation_epoch(), 1);
        snapshot.revoke(&first, 3).unwrap();
        assert_eq!(snapshot.revocation_epoch(), 3);
        assert_eq!(
            snapshot.revoke(&second, 2),
            Err(AdmissionSnapshotError::RevocationEpochNotAdvanced)
        );
        snapshot.revoke(&second, 4).unwrap();
        assert_eq!(snapshot.revocation_epoch(), 4);

        let mut full = AdmissionSnapshot::new();
        for epoch in 1..=u64::try_from(MAX_REVOKED_ADMISSIONS).unwrap() {
            full.revoke(&admission_id(epoch), epoch).unwrap();
        }
        let rejected = admission_id(u64::try_from(MAX_REVOKED_ADMISSIONS + 1).unwrap());
        assert_eq!(
            full.revoke(
                &rejected,
                u64::try_from(MAX_REVOKED_ADMISSIONS + 1).unwrap()
            ),
            Err(AdmissionSnapshotError::RevocationCapacityExceeded)
        );
        assert_eq!(
            full.revocation_epoch(),
            u64::try_from(MAX_REVOKED_ADMISSIONS).unwrap()
        );
    }

    #[test]
    fn admission_snapshot_error_is_standard_thread_safe_and_static() {
        fn assert_error_contract<E: std::error::Error + Send + Sync + 'static>() {}

        assert_error_contract::<AdmissionSnapshotError>();
    }
}
