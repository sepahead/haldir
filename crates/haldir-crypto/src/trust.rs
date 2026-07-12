//! Prevalidated trust index and revocation snapshot.
//!
//! The verifier resolves a `kid` to exactly one key record — it never builds a
//! certificate chain per message and never "tries every trusted key" until one
//! verifies (punch-list B7). Iteration order is deterministic (`BTreeMap`, H4).

use crate::key::VerifyingKey;
use crate::role::{KeyClass, KeyRole};
use haldir_contracts::ids::KeyId;
use std::collections::{BTreeMap, BTreeSet};

/// A trust-store insertion error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustStoreError {
    /// A different key record already exists for this `kid` (silent replacement
    /// would turn load order into authority — H-H03).
    ConflictingKid,
}

/// One trusted application key record.
#[derive(Debug, Clone)]
pub struct KeyRecord {
    /// The COSE key identifier.
    pub kid: KeyId,
    /// The role this key is authorized for.
    pub role: KeyRole,
    /// The verifying key.
    pub verifying_key: VerifyingKey,
    /// The subject identity (controller/gate/service id), where applicable.
    pub subject: Option<String>,
    /// Assurance vs development provisioning class.
    pub class: KeyClass,
}

/// A prevalidated, immutable trust index keyed by `kid` bytes.
#[derive(Debug, Clone, Default)]
pub struct TrustStore {
    keys: BTreeMap<Vec<u8>, KeyRecord>,
}

impl TrustStore {
    /// An empty trust store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            keys: BTreeMap::new(),
        }
    }

    /// Insert a key record, REJECTING a conflicting record for an existing `kid`
    /// (H-H03). An exact idempotent re-insert of an identical record is allowed.
    ///
    /// # Errors
    /// Returns [`TrustStoreError::ConflictingKid`] if a different record already
    /// exists for this `kid`.
    pub fn insert(&mut self, record: KeyRecord) -> Result<(), TrustStoreError> {
        let key = record.kid.as_bytes().to_vec();
        if let Some(existing) = self.keys.get(&key)
            && !records_equal(existing, &record)
        {
            return Err(TrustStoreError::ConflictingKid);
        }
        self.keys.insert(key, record);
        Ok(())
    }

    /// Resolve exactly one key record by `kid` (no fallback search).
    #[must_use]
    pub fn resolve(&self, kid: &KeyId) -> Option<&KeyRecord> {
        self.keys.get(kid.as_bytes())
    }

    /// Number of trusted keys.
    #[must_use]
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether the store is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

fn records_equal(a: &KeyRecord, b: &KeyRecord) -> bool {
    a.kid == b.kid
        && a.role == b.role
        && a.class == b.class
        && a.subject == b.subject
        && a.verifying_key.to_bytes() == b.verifying_key.to_bytes()
}

/// A revocation snapshot: which key ids are revoked, with a monotonic epoch.
#[derive(Debug, Clone, Default)]
pub struct RevocationSnapshot {
    revoked_kids: BTreeSet<Vec<u8>>,
    /// The highest revocation epoch this snapshot reflects.
    pub epoch: u64,
}

impl RevocationSnapshot {
    /// An empty snapshot at epoch 0.
    #[must_use]
    pub fn new() -> Self {
        Self {
            revoked_kids: BTreeSet::new(),
            epoch: 0,
        }
    }

    /// Mark a key id revoked and advance the epoch monotonically.
    pub fn revoke_key(&mut self, kid: &KeyId, epoch: u64) {
        self.revoked_kids.insert(kid.as_bytes().to_vec());
        if epoch > self.epoch {
            self.epoch = epoch;
        }
    }

    /// Whether a key id is revoked.
    #[must_use]
    pub fn is_key_revoked(&self, kid: &KeyId) -> bool {
        self.revoked_kids.contains(kid.as_bytes())
    }
}
