//! Immutable admission snapshot loaded atomically by the decision pipeline.
//!
//! The snapshot answers, without importing Engram or any neural runtime, whether
//! an exact controller/backend relation is admitted, revoked, opaque, or outside
//! profile (spec Phase 4 exit gate).

use crate::error::{AdmissionError, AdmissionSnapshotError};
use crate::record::AdmissionRecordV1;
use crate::types::AdmissionLevelV1;
use haldir_contracts::digest::DigestV1;
use haldir_contracts::ids::{AdmissionId, ControllerId};
use std::collections::{BTreeMap, BTreeSet};

/// A verified admission record plus its computed digest.
#[derive(Debug, Clone)]
pub struct AdmissionRelation {
    /// The signed record.
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
#[derive(Debug, Clone, Default)]
pub struct AdmissionSnapshot {
    records: BTreeMap<[u8; 16], AdmissionRelation>,
    revoked: BTreeSet<[u8; 16]>,
    /// Highest revocation epoch reflected by this snapshot.
    pub revocation_epoch: u64,
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

    /// Insert a verified admission record without replacing an existing id.
    ///
    /// This method retains its original `()` return type for source
    /// compatibility. Conflicting records are left unapplied; callers that
    /// need to distinguish conflicts must use [`Self::try_insert`].
    pub fn insert(&mut self, record: AdmissionRecordV1) {
        let _ = self.try_insert(record);
    }

    /// Insert a verified admission record, computing and storing its digest.
    ///
    /// An exact duplicate is idempotent. A different record with the same
    /// admission id is rejected instead of silently replacing the established
    /// authority binding.
    ///
    /// # Errors
    /// Returns [`AdmissionSnapshotError::ConflictingAdmissionId`] when an
    /// existing id is bound to a different record.
    pub fn try_insert(&mut self, record: AdmissionRecordV1) -> Result<(), AdmissionSnapshotError> {
        let id = *record.admission_id.as_bytes();
        if let Some(existing) = self.records.get(&id) {
            return if existing.record == record {
                Ok(())
            } else {
                Err(AdmissionSnapshotError::ConflictingAdmissionId)
            };
        }

        let digest = record.admission_digest();
        self.records
            .insert(id, AdmissionRelation { record, digest });
        Ok(())
    }

    /// Mark an admission id revoked and advance the revocation epoch monotonically.
    pub fn revoke(&mut self, admission_id: &AdmissionId, epoch: u64) {
        self.revoked.insert(*admission_id.as_bytes());
        if epoch > self.revocation_epoch {
            self.revocation_epoch = epoch;
        }
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
        let rel = self
            .resolve(claim.admission_id)
            .ok_or(AdmissionError::Unknown)?;
        if self.revoked.contains(claim.admission_id.as_bytes()) {
            return Err(AdmissionError::Revoked);
        }
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
