//! Prevalidated trust index and revocation snapshot.
//!
//! The verifier resolves a `kid` to exactly one key record — it never builds a
//! certificate chain per message and never "tries every trusted key" until one
//! verifies (punch-list B7). Iteration order is deterministic (`BTreeMap`, H4).

use crate::key::VerifyingKey;
use crate::role::{KeyClass, KeyRole};
use core::fmt;
use haldir_contracts::cbor::{CanonicalValue, CborWriter};
use haldir_contracts::digest::{DigestDomain, DigestV1};
use haldir_contracts::ids::KeyId;
use haldir_contracts::scalar::AsciiId;
use std::collections::{BTreeMap, BTreeSet};

/// Frozen canonical preimage schema for [`TrustStore::canonical_digest`].
pub const TRUST_STORE_DIGEST_SCHEMA_V1: u64 = 1;

/// Frozen canonical preimage schema for [`RevocationSnapshot::canonical_digest`].
pub const REVOCATION_SNAPSHOT_DIGEST_SCHEMA_V1: u64 = 1;

/// Maximum number of distinct application keys admitted into one trust store.
pub const MAX_TRUSTED_KEYS: usize = 128;

/// Maximum number of distinct revoked key identifiers retained in one snapshot.
pub const MAX_REVOKED_KEYS: usize = 4_096;

/// Bounded canonical identity assigned to one trusted application-key record.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeySubject(AsciiId<64>);

impl KeySubject {
    /// Maximum encoded subject length in ASCII bytes.
    pub const MAX_BYTES: usize = 64;

    /// Construct a signing subject from its canonical identifier.
    ///
    /// # Errors
    /// Returns a contract error for an empty, overlength, or noncanonical
    /// identifier.
    pub fn new(value: &str) -> Result<Self, haldir_contracts::error::DecodeError> {
        Ok(Self(AsciiId::new(value)?))
    }

    /// Borrow the canonical subject text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// A trust-store insertion error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TrustStoreError {
    /// This `kid` is already bound to a non-identical record.
    ///
    /// This error takes precedence when the supplied `kid` already exists,
    /// even if another record also owns the supplied public-key bytes. Silent
    /// replacement would turn load order into authority (H-H03).
    ConflictingKid,
    /// Another `kid` already owns this exact Ed25519 public-key encoding.
    ///
    /// The alias is rejected regardless of its proposed role, subject, or key
    /// class, preventing ordinary provisioning errors from crossing authority
    /// or revocation boundaries.
    ConflictingKeyMaterial,
    /// A `DEVELOPMENT_ONLY` role was mislabeled as assurance-class authority.
    InvalidDevelopmentClassification,
    /// The fixed trust-store key bound is already exhausted.
    CapacityExceeded,
}

impl TrustStoreError {
    /// Stable, non-record-leaking machine reason code.
    #[must_use]
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::ConflictingKid => "TRUST_STORE_CONFLICTING_KID",
            Self::ConflictingKeyMaterial => "TRUST_STORE_PUBLIC_KEY_ALREADY_ENROLLED",
            Self::InvalidDevelopmentClassification => {
                "TRUST_STORE_INVALID_DEVELOPMENT_CLASSIFICATION"
            }
            Self::CapacityExceeded => "TRUST_STORE_CAPACITY_EXCEEDED",
        }
    }
}

impl fmt::Display for TrustStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for TrustStoreError {}

/// A cross-store authority-namespace disjointness error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TrustStoreDisjointnessError {
    /// The stores contain the same key identifier, regardless of record equality.
    OverlappingKid,
    /// The stores contain the same public-key material under distinct identifiers.
    OverlappingKeyMaterial,
}

impl TrustStoreDisjointnessError {
    /// Stable, non-record-leaking machine reason code.
    #[must_use]
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::OverlappingKid => "TRUST_STORES_OVERLAPPING_KID",
            Self::OverlappingKeyMaterial => "TRUST_STORES_OVERLAPPING_KEY_MATERIAL",
        }
    }
}

impl fmt::Display for TrustStoreDisjointnessError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for TrustStoreDisjointnessError {}

/// One trusted application key record.
#[derive(Debug, Clone)]
pub struct KeyRecord {
    /// The COSE key identifier.
    pub kid: KeyId,
    /// The role this key is authorized for.
    pub role: KeyRole,
    /// The verifying key.
    pub verifying_key: VerifyingKey,
    /// The bounded subject identity (controller, Gate, service, or authority id).
    pub subject: KeySubject,
    /// Assurance vs development provisioning class.
    pub class: KeyClass,
}

/// A prevalidated trust index with a one-to-one `kid`/public-key binding.
///
/// [`VerifyingKey`] admits only canonical, non-identity,
/// prime-subgroup encodings, so byte equality is point equality for every key
/// this store can contain. The reverse byte index therefore also excludes
/// torsion-related aliases of one authority scalar.
#[derive(Debug, Clone, Default)]
pub struct TrustStore {
    keys: BTreeMap<Vec<u8>, KeyRecord>,
    public_key_owners: BTreeMap<[u8; 32], Vec<u8>>,
}

impl TrustStore {
    /// An empty trust store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            keys: BTreeMap::new(),
            public_key_owners: BTreeMap::new(),
        }
    }

    /// Insert a key record, rejecting both a conflicting record for an existing
    /// `kid` and an alias that enrolls the same public-key bytes under a new
    /// `kid` (H-H03). An exact whole-record re-insert is an idempotent no-op.
    /// Every error leaves both indexes unchanged.
    ///
    /// # Errors
    /// Returns [`TrustStoreError::ConflictingKid`] if a different record already
    /// exists for this `kid`, [`TrustStoreError::ConflictingKeyMaterial`] if
    /// another `kid` already owns the supplied public-key bytes,
    /// [`TrustStoreError::InvalidDevelopmentClassification`] when a
    /// `DEVELOPMENT_ONLY` role is labeled as assurance-class authority, or
    /// [`TrustStoreError::CapacityExceeded`] when [`MAX_TRUSTED_KEYS`] distinct
    /// records are already present. Existing-record conflicts are reported
    /// before capacity exhaustion.
    pub fn insert(&mut self, record: KeyRecord) -> Result<(), TrustStoreError> {
        let key = record.kid.as_bytes().to_vec();
        if let Some(existing) = self.keys.get(&key) {
            return if records_equal(existing, &record) {
                Ok(())
            } else {
                Err(TrustStoreError::ConflictingKid)
            };
        }
        if record.role == KeyRole::DevelopmentOnly && record.class != KeyClass::Development {
            return Err(TrustStoreError::InvalidDevelopmentClassification);
        }
        let public_key = record.verifying_key.to_bytes();
        if self.public_key_owners.contains_key(&public_key) {
            return Err(TrustStoreError::ConflictingKeyMaterial);
        }
        if self.keys.len() >= MAX_TRUSTED_KEYS {
            return Err(TrustStoreError::CapacityExceeded);
        }
        self.public_key_owners.insert(public_key, key.clone());
        self.keys.insert(key, record);
        Ok(())
    }

    /// Validate that another trust store occupies a disjoint authority
    /// namespace without changing either store.
    ///
    /// Both key identifiers and public-key material must be distinct. This is
    /// intentionally stronger than accepting an identical record in both
    /// stores: lifecycle-separated stores may carry independently governed
    /// revocation snapshots, so overlap would make revocation inheritance
    /// ambiguous and could resurrect a key revoked in the earlier namespace.
    /// This check deliberately does not impose the capacity of one store on
    /// the conceptual union of two independently bounded stores.
    ///
    /// Conflict precedence is deterministic: every `kid` conflict is checked
    /// before public-key aliases, independent of insertion or argument order.
    ///
    /// # Errors
    /// Returns [`TrustStoreDisjointnessError::OverlappingKid`] when the stores
    /// share any `kid`, or
    /// [`TrustStoreDisjointnessError::OverlappingKeyMaterial`] when they share
    /// public-key bytes under otherwise distinct identifiers.
    pub fn validate_disjoint_bindings(
        &self,
        other: &Self,
    ) -> Result<(), TrustStoreDisjointnessError> {
        for kid in other.keys.keys() {
            if self.keys.contains_key(kid) {
                return Err(TrustStoreDisjointnessError::OverlappingKid);
            }
        }

        for (public_key, kid) in &other.public_key_owners {
            if self
                .public_key_owners
                .get(public_key)
                .is_some_and(|existing_kid| existing_kid != kid)
            {
                return Err(TrustStoreDisjointnessError::OverlappingKeyMaterial);
            }
        }

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

    /// Canonical semantic identity of every trusted key record in this store.
    ///
    /// Digest schema v1 encodes the schema number followed by records in
    /// canonical `kid` order. Each record commits its `kid`, role, canonical
    /// public-key bytes, subject, and assurance class. The private reverse index
    /// is derived state and is intentionally excluded.
    #[must_use]
    pub fn canonical_digest(&self) -> DigestV1 {
        let mut writer = CborWriter::new();
        writer.map_header(2);
        writer.uint(1);
        writer.uint(TRUST_STORE_DIGEST_SCHEMA_V1);
        writer.uint(2);
        writer.array_header(u64::try_from(self.keys.len()).unwrap_or(u64::MAX));
        for record in self.keys.values() {
            writer.map_header(5);
            writer.uint(1);
            record.kid.encode(&mut writer);
            writer.uint(2);
            writer.text(record.role.as_str());
            writer.uint(3);
            writer.bytes(&record.verifying_key.to_bytes());
            writer.uint(4);
            writer.text(record.subject.as_str());
            writer.uint(5);
            writer.text(match record.class {
                KeyClass::Assurance => "ASSURANCE",
                KeyClass::Development => "DEVELOPMENT",
            });
        }
        DigestV1::compute(DigestDomain::TrustStoreSnapshot, writer.as_bytes())
    }
}

/// A revocation-snapshot update error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RevocationError {
    /// A new revocation did not carry an epoch above the current high-water.
    EpochNotAdvanced,
    /// The fixed revoked-key bound is already exhausted.
    CapacityExceeded,
}

impl RevocationError {
    /// Stable, non-record-leaking machine reason code.
    #[must_use]
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::EpochNotAdvanced => "REVOCATION_EPOCH_NOT_ADVANCED",
            Self::CapacityExceeded => "REVOCATION_CAPACITY_EXCEEDED",
        }
    }
}

impl fmt::Display for RevocationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for RevocationError {}

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
    epoch: u64,
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

    /// Mark a new key id revoked at a strictly advancing epoch.
    ///
    /// Repeating an already revoked key at or below the current high-water is an
    /// idempotent no-op. Repeating it at a higher epoch advances the high-water
    /// without growing the retained set. Thus [`Self::epoch`] always reports the
    /// highest accepted issuer epoch, including a newer record whose subject was
    /// already revoked. Every error leaves the snapshot unchanged.
    ///
    /// # Errors
    /// Returns [`RevocationError::EpochNotAdvanced`] when a new key is paired
    /// with an epoch at or below the current high-water, or
    /// [`RevocationError::CapacityExceeded`] after [`MAX_REVOKED_KEYS`]
    /// distinct keys have been retained.
    pub fn revoke_key(&mut self, kid: &KeyId, epoch: u64) -> Result<(), RevocationError> {
        if self.revoked_kids.contains(kid.as_bytes()) {
            self.epoch = self.epoch.max(epoch);
            return Ok(());
        }
        if epoch <= self.epoch {
            return Err(RevocationError::EpochNotAdvanced);
        }
        if self.revoked_kids.len() >= MAX_REVOKED_KEYS {
            return Err(RevocationError::CapacityExceeded);
        }
        self.revoked_kids.insert(kid.as_bytes().to_vec());
        self.epoch = epoch;
        Ok(())
    }

    /// Highest revocation epoch reflected by this snapshot.
    ///
    /// The epoch is mutated only through [`Self::revoke_key`], which preserves
    /// its monotonic high-water invariant.
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Whether a key id is revoked.
    #[must_use]
    pub fn is_key_revoked(&self, kid: &KeyId) -> bool {
        self.revoked_kids.contains(kid.as_bytes())
    }

    /// Canonical semantic identity of the revocation high-water and every
    /// revoked key identifier in this snapshot.
    #[must_use]
    pub fn canonical_digest(&self) -> DigestV1 {
        let mut writer = CborWriter::new();
        writer.map_header(3);
        writer.uint(1);
        writer.uint(REVOCATION_SNAPSHOT_DIGEST_SCHEMA_V1);
        writer.uint(2);
        writer.uint(self.epoch);
        writer.uint(3);
        writer.array_header(u64::try_from(self.revoked_kids.len()).unwrap_or(u64::MAX));
        for kid in &self.revoked_kids {
            writer.bytes(kid);
        }
        DigestV1::compute(DigestDomain::RevocationSnapshot, writer.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::{KeyRecord, KeySubject, RevocationSnapshot, TrustStore};
    use haldir_contracts::error::DecodeError;
    use haldir_contracts::ids::KeyId;

    use crate::{KeyClass, KeyRole, SigningKey};

    fn record(seed: u8, kid: u8, class: KeyClass) -> KeyRecord {
        let signer = SigningKey::from_seed([seed; 32]).expect("nonzero test seed");
        KeyRecord {
            kid: KeyId::new(vec![kid]).unwrap(),
            role: KeyRole::ControllerIntent,
            verifying_key: signer.verifying_key(),
            subject: KeySubject::new(&format!("controller-{kid}")).unwrap(),
            class,
        }
    }

    #[test]
    fn key_subject_accepts_canonical_identifiers_at_the_exact_bound() {
        let subject = "a".repeat(KeySubject::MAX_BYTES);
        let parsed = KeySubject::new(&subject).unwrap();

        assert_eq!(parsed.as_str(), subject);
    }

    #[test]
    fn key_subject_rejects_empty_overlength_or_noncanonical_identifiers() {
        let overlength = "a".repeat(KeySubject::MAX_BYTES + 1);

        for candidate in [
            "",
            "controller one",
            "controller/one",
            "contrôller",
            &overlength,
        ] {
            assert_eq!(
                KeySubject::new(candidate),
                Err(DecodeError::InvalidIdentifier),
                "unexpectedly accepted {candidate:?}"
            );
        }
    }

    #[test]
    fn trust_store_digest_is_insertion_order_independent() {
        let mut first = TrustStore::new();
        first.insert(record(1, 2, KeyClass::Assurance)).unwrap();
        first.insert(record(2, 1, KeyClass::Development)).unwrap();
        let mut second = TrustStore::new();
        second.insert(record(2, 1, KeyClass::Development)).unwrap();
        second.insert(record(1, 2, KeyClass::Assurance)).unwrap();

        assert_eq!(
            first.canonical_digest().value,
            [
                49, 163, 149, 232, 172, 53, 243, 166, 254, 39, 230, 252, 48, 202, 206, 73, 62, 66,
                12, 7, 155, 219, 106, 36, 194, 221, 8, 128, 64, 53, 139, 205,
            ]
        );
        assert_eq!(first.canonical_digest(), second.canonical_digest());
    }

    #[test]
    fn trust_store_digest_commits_authority_class() {
        let mut assurance = TrustStore::new();
        assurance.insert(record(3, 3, KeyClass::Assurance)).unwrap();
        let mut development = TrustStore::new();
        development
            .insert(record(3, 3, KeyClass::Development))
            .unwrap();

        assert_ne!(assurance.canonical_digest(), development.canonical_digest());
    }

    #[test]
    fn revocation_digest_commits_set_and_epoch_without_insertion_order() {
        let first_kid = KeyId::new(vec![1]).unwrap();
        let second_kid = KeyId::new(vec![2]).unwrap();
        let mut first = RevocationSnapshot::new();
        first.revoke_key(&first_kid, 1).unwrap();
        first.revoke_key(&second_kid, 2).unwrap();
        let mut second = RevocationSnapshot::new();
        second.revoke_key(&second_kid, 1).unwrap();
        second.revoke_key(&first_kid, 2).unwrap();
        assert_eq!(
            first.canonical_digest().value,
            [
                232, 110, 18, 185, 174, 109, 118, 39, 103, 105, 171, 83, 121, 211, 67, 93, 84, 85,
                125, 38, 160, 63, 139, 255, 199, 245, 42, 182, 160, 237, 253, 39,
            ]
        );
        assert_eq!(first.canonical_digest(), second.canonical_digest());

        second.revoke_key(&first_kid, 3).unwrap();
        assert_ne!(first.canonical_digest(), second.canonical_digest());
    }
}
