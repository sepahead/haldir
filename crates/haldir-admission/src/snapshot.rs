//! In-memory admission snapshot consumed immutably by the decision pipeline.
//!
//! The snapshot answers, without importing Engram or any neural runtime, whether
//! an exact controller/backend relation is admitted, revoked, opaque, or outside
//! profile. This crate does not implement an authenticated or atomic external
//! snapshot loader; callers build the bounded index before handing it to Gate.

use crate::error::{AdmissionError, AdmissionSnapshotError};
use crate::record::AdmissionRecordV1;
use crate::types::AdmissionLevelV1;
use haldir_contracts::Validate;
use haldir_contracts::cbor::{CanonicalValue, CborWriter};
use haldir_contracts::digest::{DigestDomain, DigestV1};
use haldir_contracts::ids::{AdmissionId, ControllerId};
use std::collections::{BTreeMap, BTreeSet};

/// Frozen canonical preimage schema for [`AdmissionSnapshot::canonical_digest`].
pub const ADMISSION_SNAPSHOT_DIGEST_SCHEMA_V1: u64 = 1;

/// Maximum number of active records admitted into one snapshot.
pub const MAX_ADMISSION_RECORDS: usize = 256;

/// Maximum number of distinct revoked admission ids retained in one snapshot.
pub const MAX_REVOKED_ADMISSIONS: usize = 4_096;

/// A caller-supplied, schema-validated admission record plus its computed digest.
#[derive(Debug, Clone)]
pub struct AdmissionRelation {
    /// The record payload. Signature/provenance verification is external.
    pub record: AdmissionRecordV1,
    /// The record's domain-separated digest.
    pub digest: DigestV1,
}

/// The identifiers a lease or intent claims about its admission, checked for
/// equality against the snapshot.
#[derive(Debug, Clone)]
pub struct AdmissionClaim<'a> {
    /// Claimed admission id.
    pub admission_id: &'a AdmissionId,
    /// Claimed admission-record digest.
    pub admission_digest: &'a DigestV1,
    /// Claimed controller id.
    pub controller_id: &'a ControllerId,
    /// Claimed controller bundle digest.
    pub controller_bundle_digest: &'a DigestV1,
    /// Claimed backend execution-profile digest.
    pub backend_profile_digest: &'a DigestV1,
}

/// An immutable index of active admissions, keyed by admission id.
///
/// Record insertion is deliberately fallible; there is no error-discarding
/// compatibility method:
///
/// ```compile_fail
/// use haldir_admission::{AdmissionRecordV1, AdmissionSnapshot};
///
/// fn silently_insert(snapshot: &mut AdmissionSnapshot, record: AdmissionRecordV1) {
///     snapshot.insert(record);
/// }
/// ```
#[derive(Debug, Clone, Default)]
pub struct AdmissionSnapshot {
    records: BTreeMap<[u8; 16], AdmissionRelation>,
    revoked: BTreeSet<[u8; 16]>,
    /// Highest revocation epoch reflected by this snapshot.
    revocation_epoch: u64,
}

impl AdmissionSnapshot {
    /// An empty snapshot.
    #[must_use]
    pub fn new() -> Self {
        Self {
            records: BTreeMap::new(),
            revoked: BTreeSet::new(),
            revocation_epoch: 0,
        }
    }

    /// Validate and insert an admission record, computing and storing its digest.
    ///
    /// An exact duplicate is idempotent. A different record with the same
    /// admission id is rejected instead of silently replacing the established
    /// authority binding.
    ///
    /// # Errors
    /// Returns [`AdmissionSnapshotError::InvalidRecord`] when the candidate is
    /// not a supported valid record,
    /// [`AdmissionSnapshotError::ConflictingAdmissionId`] when an existing id is
    /// bound to a different record, or
    /// [`AdmissionSnapshotError::RecordCapacityExceeded`] when
    /// [`MAX_ADMISSION_RECORDS`] distinct records are already present.
    pub fn try_insert(&mut self, record: AdmissionRecordV1) -> Result<(), AdmissionSnapshotError> {
        record
            .validate()
            .map_err(|_| AdmissionSnapshotError::InvalidRecord)?;
        let id = *record.admission_id.as_bytes();
        if let Some(existing) = self.records.get(&id) {
            return if existing.record == record {
                Ok(())
            } else {
                Err(AdmissionSnapshotError::ConflictingAdmissionId)
            };
        }

        if self.records.len() >= MAX_ADMISSION_RECORDS {
            return Err(AdmissionSnapshotError::RecordCapacityExceeded);
        }
        let digest = record.admission_digest();
        self.records
            .insert(id, AdmissionRelation { record, digest });
        Ok(())
    }

    /// Mark a new admission id revoked at a strictly advancing epoch.
    ///
    /// Repeating an already revoked id at or below the current high-water is an
    /// idempotent no-op. Repeating it at a higher epoch advances the high-water
    /// without growing the retained set. Every error leaves the snapshot
    /// unchanged.
    ///
    /// # Errors
    /// Returns [`AdmissionSnapshotError::RevocationEpochNotAdvanced`] when a
    /// new id is paired with an epoch at or below the current high-water, or
    /// [`AdmissionSnapshotError::RevocationCapacityExceeded`] after
    /// [`MAX_REVOKED_ADMISSIONS`] distinct ids have been retained.
    pub fn revoke(
        &mut self,
        admission_id: &AdmissionId,
        epoch: u64,
    ) -> Result<(), AdmissionSnapshotError> {
        if self.revoked.contains(admission_id.as_bytes()) {
            self.revocation_epoch = self.revocation_epoch.max(epoch);
            return Ok(());
        }
        if epoch <= self.revocation_epoch {
            return Err(AdmissionSnapshotError::RevocationEpochNotAdvanced);
        }
        if self.revoked.len() >= MAX_REVOKED_ADMISSIONS {
            return Err(AdmissionSnapshotError::RevocationCapacityExceeded);
        }
        self.revoked.insert(*admission_id.as_bytes());
        self.revocation_epoch = epoch;
        Ok(())
    }

    /// Highest revocation epoch reflected by this snapshot.
    ///
    /// The epoch is mutated only through [`Self::revoke`], which preserves its
    /// monotonic high-water invariant.
    #[must_use]
    pub const fn revocation_epoch(&self) -> u64 {
        self.revocation_epoch
    }

    /// Canonical semantic identity of every active admission, every revoked
    /// admission id, and the revocation high-water in this snapshot.
    ///
    /// Digest schema v1 emits active records and revoked ids in their canonical
    /// `AdmissionId` order. The cached per-record digest is derived from each
    /// record and is intentionally not encoded twice.
    #[must_use]
    pub fn canonical_digest(&self) -> DigestV1 {
        let mut writer = CborWriter::new();
        writer.map_header(4);
        writer.uint(1);
        writer.uint(ADMISSION_SNAPSHOT_DIGEST_SCHEMA_V1);
        writer.uint(2);
        writer.uint(self.revocation_epoch);
        writer.uint(3);
        writer.array_header(u64::try_from(self.records.len()).unwrap_or(u64::MAX));
        for relation in self.records.values() {
            relation.record.encode(&mut writer);
        }
        writer.uint(4);
        writer.array_header(u64::try_from(self.revoked.len()).unwrap_or(u64::MAX));
        for admission_id in &self.revoked {
            writer.bytes(admission_id);
        }
        DigestV1::compute(DigestDomain::AdmissionSnapshot, writer.as_bytes())
    }

    /// Resolve an admission relation by id.
    #[must_use]
    pub fn resolve(&self, admission_id: &AdmissionId) -> Option<&AdmissionRelation> {
        self.records.get(admission_id.as_bytes())
    }

    /// Verify a claimed admission for exact equality of all bindings.
    ///
    /// When `require_semantic` is true, a non-semantic (opaque / provenance-only)
    /// level fails with [`AdmissionError::NotSemantic`].
    ///
    /// # Errors
    /// Returns an [`AdmissionError`] on any mismatch or revocation.
    pub fn verify_admission(
        &self,
        claim: &AdmissionClaim<'_>,
        require_semantic: bool,
    ) -> Result<AdmissionLevelV1, AdmissionError> {
        if self.revoked.contains(claim.admission_id.as_bytes()) {
            return Err(AdmissionError::Revoked);
        }
        let rel = self
            .resolve(claim.admission_id)
            .ok_or(AdmissionError::Unknown)?;
        if &rel.digest != claim.admission_digest {
            return Err(AdmissionError::DigestMismatch);
        }
        if &rel.record.controller_id != claim.controller_id {
            return Err(AdmissionError::ControllerMismatch);
        }
        if &rel.record.controller_bundle_digest != claim.controller_bundle_digest {
            return Err(AdmissionError::BundleMismatch);
        }
        if &rel.record.backend_profile_digest != claim.backend_profile_digest {
            return Err(AdmissionError::BackendMismatch);
        }
        if require_semantic && !rel.record.level.is_semantic() {
            return Err(AdmissionError::NotSemantic);
        }
        Ok(rel.record.level)
    }
}

#[cfg(test)]
mod tests {
    use core::num::NonZeroU64;

    use haldir_contracts::digest::{DigestDomain, DigestV1};
    use haldir_contracts::ids::{AdmissionId, ControllerId};
    use haldir_contracts::scalar::AsciiId;

    use crate::{AdmissionLevelV1, AdmissionRecordV1, AdmissionSnapshot};

    fn digest(label: &[u8]) -> DigestV1 {
        DigestV1::compute(DigestDomain::Payload, label)
    }

    fn record(id: u8) -> AdmissionRecordV1 {
        AdmissionRecordV1 {
            schema_major: 1,
            schema_minor: 0,
            issuer_id: AsciiId::new("admission-authority").unwrap(),
            admission_id: AdmissionId::new([id; 16]),
            controller_id: ControllerId::new(&format!("controller-{id}")).unwrap(),
            admission_profile_id: AsciiId::new("profile-a").unwrap(),
            level: AdmissionLevelV1::A3ActionRelation,
            controller_bundle_digest: digest(&[id, 1]),
            backend_profile_digest: digest(&[id, 2]),
            codec_digest: digest(&[id, 3]),
            validity_term: NonZeroU64::new(1).unwrap(),
            conformance_run_digest: Some(digest(&[id, 4])),
        }
    }

    #[test]
    fn admission_snapshot_digest_is_insertion_order_independent() {
        let mut first = AdmissionSnapshot::new();
        first.try_insert(record(2)).unwrap();
        first.try_insert(record(1)).unwrap();
        let mut second = AdmissionSnapshot::new();
        second.try_insert(record(1)).unwrap();
        second.try_insert(record(2)).unwrap();

        assert_eq!(
            first.canonical_digest().value,
            [
                53, 126, 157, 145, 168, 36, 244, 87, 8, 173, 250, 52, 212, 230, 158, 115, 80, 37,
                156, 37, 8, 162, 3, 149, 181, 214, 222, 207, 203, 164, 53, 18,
            ]
        );
        assert_eq!(first.canonical_digest(), second.canonical_digest());
    }

    #[test]
    fn admission_snapshot_digest_commits_revocation_set_and_epoch() {
        let admission_id = AdmissionId::new([1; 16]);
        let mut first = AdmissionSnapshot::new();
        first.try_insert(record(1)).unwrap();
        first.revoke(&admission_id, 1).unwrap();
        let mut advanced = first.clone();
        advanced.revoke(&admission_id, 2).unwrap();

        assert_ne!(first.canonical_digest(), advanced.canonical_digest());
    }
}
