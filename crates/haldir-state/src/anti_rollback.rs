//! Anti-rollback high-water store (spec §anti-rollback, B11/B12/H12).
//!
//! Holds the highest accepted terms and revocation epochs plus a monotonic boot
//! counter, the last derived Gate boot ID, and the store-global deployment-package
//! revision/digest ratchet — never an active lease.
//! `accept_term`/`accept_revocation_epoch` reject values that rewind their stored
//! high-water. Boot candidates bind the checked next counter to a Gate ID and
//! caller-supplied entropy, and reject a derived boot-ID repeat.
//!
//! This type supplies copy-on-write semantic candidates. [`crate::durable`] owns
//! the commit-before-exposure ordering and authenticated persistence.

use haldir_contracts::cbor::{CanonicalValue, CborReader, CborWriter, Limits};
use haldir_contracts::deployment::{DeploymentPayloadDigestV1, DeploymentRevision};
use haldir_contracts::ids::{GateBootId, GateId};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

const BOOT_ID_DOMAIN: &[u8] = b"haldir.state.gate-boot-id.v1\0";
const STORE_FORMAT_VERSION: u64 = 3;
const LEGACY_V2_FORMAT_VERSION: u64 = 2;
const STORE_LIMITS: Limits = Limits::LARGE;

const PACKAGE_STATE_PRISTINE_UNBOUND: u64 = 0;
const PACKAGE_STATE_BOUND: u64 = 1;
const PACKAGE_STATE_MIGRATION_REQUIRED: u64 = 2;

/// A caller-supplied deployment revision and payload-digest pair bound to this
/// Gate's durable anti-rollback state.
///
/// This state-layer type commits the pair but does not verify package provenance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeploymentPackageBinding {
    revision: DeploymentRevision,
    payload_digest: DeploymentPayloadDigestV1,
}

impl DeploymentPackageBinding {
    /// Construct a binding from caller-supplied neutral ratchet values.
    #[must_use]
    pub const fn new(
        revision: DeploymentRevision,
        payload_digest: DeploymentPayloadDigestV1,
    ) -> Self {
        Self {
            revision,
            payload_digest,
        }
    }

    /// The monotonically compared deployment-package revision.
    #[must_use]
    pub const fn revision(&self) -> DeploymentRevision {
        self.revision
    }

    /// The committed deployment-package-domain payload digest.
    #[must_use]
    pub const fn payload_digest(&self) -> DeploymentPayloadDigestV1 {
        self.payload_digest
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum DeploymentPackageRatchet {
    PristineUnbound,
    Bound(DeploymentPackageBinding),
    MigrationRequired,
}

/// An anti-rollback failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AntiRollbackError {
    /// A term/epoch/boot value did not strictly advance (a rollback attempt).
    Rollback,
    /// A checked monotonic namespace reached its terminal value.
    Exhausted,
    /// A newly derived Gate boot ID matched the previously committed boot ID.
    BootIdRepeat,
    /// Legacy or already-used unbound state needs an explicit migration.
    MigrationRequired,
    /// A deployment package revision was below the committed revision.
    PackageRollback,
    /// One revision named a different package payload digest.
    PackageEquivocation,
    /// A package-bound store requires a deployment-package boot path.
    PackageBindingRequired,
    /// An update would exceed the durable store's collection or byte bounds.
    CapacityExceeded,
    /// The persisted store could not be parsed (corruption).
    Corrupt,
}

impl AntiRollbackError {
    /// Stable reason string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Rollback => "ANTI_ROLLBACK_REWIND",
            Self::Exhausted => "ANTI_ROLLBACK_EXHAUSTED",
            Self::BootIdRepeat => "ANTI_ROLLBACK_BOOT_ID_REPEAT",
            Self::MigrationRequired => "ANTI_ROLLBACK_MIGRATION_REQUIRED",
            Self::PackageRollback => "ANTI_ROLLBACK_PACKAGE_ROLLBACK",
            Self::PackageEquivocation => "ANTI_ROLLBACK_PACKAGE_EQUIVOCATION",
            Self::PackageBindingRequired => "ANTI_ROLLBACK_PACKAGE_BINDING_REQUIRED",
            Self::CapacityExceeded => "ANTI_ROLLBACK_CAPACITY_EXCEEDED",
            Self::Corrupt => "ANTI_ROLLBACK_CORRUPT",
        }
    }
}

impl std::fmt::Display for AntiRollbackError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::error::Error for AntiRollbackError {}

/// A Gate process incarnation that is safe to expose after durable commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootContext {
    /// The derived identifier for this Gate process incarnation.
    pub gate_boot_id: GateBootId,
    /// The checked monotonic counter committed with [`Self::gate_boot_id`].
    pub boot_counter: u64,
}

/// Highest-water anti-rollback state.
///
/// Equality compares the semantic ratchets and deliberately ignores the
/// private durable encoding. Consequently, a decoded legacy value can compare
/// equal to an equivalent current-format value while [`Self::to_bytes`]
/// preserves different representations until the next successful mutation.
#[derive(Debug, Clone)]
pub struct AntiRollbackStore {
    boot_counter: u64,
    last_gate_boot_id: Option<GateBootId>,
    terms: BTreeMap<Vec<u8>, u64>,
    revocation_epochs: BTreeMap<Vec<u8>, u64>,
    deployment_package: DeploymentPackageRatchet,
    encoding: StoreFormat,
}

impl PartialEq for AntiRollbackStore {
    fn eq(&self, other: &Self) -> bool {
        self.boot_counter == other.boot_counter
            && self.last_gate_boot_id == other.last_gate_boot_id
            && self.terms == other.terms
            && self.revocation_epochs == other.revocation_epochs
            && self.deployment_package == other.deployment_package
    }
}

impl Eq for AntiRollbackStore {}

impl Default for AntiRollbackStore {
    fn default() -> Self {
        Self {
            boot_counter: 0,
            last_gate_boot_id: None,
            terms: BTreeMap::new(),
            revocation_epochs: BTreeMap::new(),
            deployment_package: DeploymentPackageRatchet::PristineUnbound,
            encoding: StoreFormat::CurrentV3,
        }
    }
}

impl AntiRollbackStore {
    /// A fresh store (only for genuine first provisioning, never on corruption).
    #[must_use]
    pub fn new_empty() -> Self {
        Self::default()
    }

    /// Advance only the P0 in-memory boot counter with checked exhaustion.
    ///
    /// Durable callers must use [`Self::candidate_for_boot`] so the counter is
    /// cryptographically bound to a Gate ID and caller-supplied entropy.
    ///
    /// # Errors
    /// Returns [`AntiRollbackError::PackageBindingRequired`] once a deployment
    /// package has been bound, [`AntiRollbackError::Exhausted`] instead of
    /// reusing `u64::MAX`, or [`AntiRollbackError::CapacityExceeded`] if the
    /// advanced state would not fit its durable representation.
    pub fn advance_boot(&mut self) -> Result<u64, AntiRollbackError> {
        self.require_plain_boot_path()?;
        let next = self
            .boot_counter
            .checked_add(1)
            .ok_or(AntiRollbackError::Exhausted)?;
        let mut candidate = self.clone();
        candidate.boot_counter = next;
        candidate.mark_unbound_state_used();
        candidate.encoding = StoreFormat::CurrentV3;
        candidate.ensure_encodable()?;
        *self = candidate;
        Ok(next)
    }

    /// Prepare an advanced boot state without mutating the live store.
    ///
    /// The caller can serialize and durably commit the candidate, then replace
    /// the live state only after durable commit succeeds.
    ///
    /// # Errors
    /// Returns [`AntiRollbackError::PackageBindingRequired`] once a deployment
    /// package has been bound or [`AntiRollbackError::Exhausted`] at the
    /// counter limit. Returns [`AntiRollbackError::CapacityExceeded`] if the
    /// advanced state would not fit its durable representation.
    pub fn candidate_with_advanced_boot(&self) -> Result<(Self, u64), AntiRollbackError> {
        let mut candidate = self.clone();
        let counter = candidate.advance_boot()?;
        Ok((candidate, counter))
    }

    /// Prepare a boot-ID-bound next incarnation without mutating the live store.
    ///
    /// `entropy` must be 256 bits obtained by the caller from its configured
    /// cryptographic entropy source. This semantic layer performs no OS access.
    ///
    /// # Errors
    /// Returns [`AntiRollbackError::PackageBindingRequired`] once a deployment
    /// package has been bound, [`AntiRollbackError::Exhausted`] at the counter
    /// limit, or [`AntiRollbackError::BootIdRepeat`] if the derived ID matches
    /// the last committed Gate boot ID. Returns
    /// [`AntiRollbackError::CapacityExceeded`] if the candidate would not fit
    /// its durable representation.
    pub fn candidate_for_boot(
        &self,
        gate_id: &GateId,
        entropy: [u8; 32],
    ) -> Result<(Self, BootContext), AntiRollbackError> {
        self.require_plain_boot_path()?;
        let counter = self
            .boot_counter
            .checked_add(1)
            .ok_or(AntiRollbackError::Exhausted)?;
        let gate_boot_id = derive_gate_boot_id(gate_id, counter, &entropy);
        if self.last_gate_boot_id == Some(gate_boot_id) {
            return Err(AntiRollbackError::BootIdRepeat);
        }

        let mut candidate = self.clone();
        candidate.boot_counter = counter;
        candidate.last_gate_boot_id = Some(gate_boot_id);
        candidate.mark_unbound_state_used();
        candidate.encoding = StoreFormat::CurrentV3;
        candidate.ensure_encodable()?;
        Ok((
            candidate,
            BootContext {
                gate_boot_id,
                boot_counter: counter,
            },
        ))
    }

    /// Prepare a package-bound next Gate incarnation without mutating live state.
    ///
    /// The initial binding is allowed only on a genuinely pristine v3 store.
    /// A bound store accepts higher revisions and treats an identical
    /// revision/digest pair as an idempotent package selection while still
    /// advancing the boot incarnation. This state layer does not verify the
    /// provenance of the caller-supplied pair.
    ///
    /// # Errors
    /// Returns [`AntiRollbackError::MigrationRequired`] for legacy or previously
    /// used unbound state, [`AntiRollbackError::PackageRollback`] for a lower
    /// revision, [`AntiRollbackError::PackageEquivocation`] when the committed
    /// revision names a different digest, or the ordinary checked boot errors,
    /// including [`AntiRollbackError::CapacityExceeded`].
    pub fn candidate_for_deployment_boot(
        &self,
        gate_id: &GateId,
        entropy: [u8; 32],
        revision: DeploymentRevision,
        payload_digest: DeploymentPayloadDigestV1,
    ) -> Result<(Self, BootContext), AntiRollbackError> {
        let next_binding = DeploymentPackageBinding::new(revision, payload_digest);
        match &self.deployment_package {
            DeploymentPackageRatchet::PristineUnbound => {
                if !self.has_pristine_semantic_state() {
                    return Err(AntiRollbackError::MigrationRequired);
                }
            }
            DeploymentPackageRatchet::MigrationRequired => {
                return Err(AntiRollbackError::MigrationRequired);
            }
            DeploymentPackageRatchet::Bound(current) => {
                if revision < current.revision() {
                    return Err(AntiRollbackError::PackageRollback);
                }
                if revision == current.revision() && payload_digest != current.payload_digest() {
                    return Err(AntiRollbackError::PackageEquivocation);
                }
            }
        }

        let counter = self
            .boot_counter
            .checked_add(1)
            .ok_or(AntiRollbackError::Exhausted)?;
        let gate_boot_id = derive_gate_boot_id(gate_id, counter, &entropy);
        if self.last_gate_boot_id == Some(gate_boot_id) {
            return Err(AntiRollbackError::BootIdRepeat);
        }

        let mut candidate = self.clone();
        candidate.boot_counter = counter;
        candidate.last_gate_boot_id = Some(gate_boot_id);
        candidate.deployment_package = DeploymentPackageRatchet::Bound(next_binding);
        candidate.encoding = StoreFormat::CurrentV3;
        candidate.ensure_encodable()?;
        Ok((
            candidate,
            BootContext {
                gate_boot_id,
                boot_counter: counter,
            },
        ))
    }

    /// The current boot counter.
    #[must_use]
    pub const fn boot_counter(&self) -> u64 {
        self.boot_counter
    }

    /// The most recently committed Gate boot ID, if a bound boot has begun.
    #[must_use]
    pub const fn last_gate_boot_id(&self) -> Option<GateBootId> {
        self.last_gate_boot_id
    }

    /// The currently committed deployment-package binding, if package-bound.
    #[must_use]
    pub const fn deployment_package_binding(&self) -> Option<&DeploymentPackageBinding> {
        match &self.deployment_package {
            DeploymentPackageRatchet::Bound(binding) => Some(binding),
            DeploymentPackageRatchet::PristineUnbound
            | DeploymentPackageRatchet::MigrationRequired => None,
        }
    }

    /// Whether this store requires an explicit migration before package binding.
    #[must_use]
    pub const fn deployment_package_migration_required(&self) -> bool {
        matches!(
            &self.deployment_package,
            DeploymentPackageRatchet::MigrationRequired
        )
    }

    /// The highest accepted term for a scope.
    #[must_use]
    pub fn highest_term(&self, scope: &[u8]) -> u64 {
        self.terms.get(scope).copied().unwrap_or(0)
    }

    /// Durably accept a term, requiring it to strictly exceed the stored high-water.
    ///
    /// # Errors
    /// Returns [`AntiRollbackError::Rollback`] if `term` is not greater than the
    /// stored high-water, or [`AntiRollbackError::CapacityExceeded`] if the
    /// update would make the durable representation exceed its fixed bounds.
    pub fn accept_term(&mut self, scope: &[u8], term: u64) -> Result<(), AntiRollbackError> {
        let candidate = self.candidate_with_term(scope, term)?;
        *self = candidate;
        Ok(())
    }

    /// Prepare a term update without mutating the live store.
    ///
    /// # Errors
    /// Returns [`AntiRollbackError::Rollback`] when the term does not advance,
    /// or [`AntiRollbackError::CapacityExceeded`] when the candidate would not
    /// fit the durable representation.
    pub fn candidate_with_term(&self, scope: &[u8], term: u64) -> Result<Self, AntiRollbackError> {
        validate_scope(scope)?;
        let hw = self.highest_term(scope);
        if term <= hw {
            return Err(AntiRollbackError::Rollback);
        }
        let mut candidate = self.clone();
        candidate.terms.insert(scope.to_vec(), term);
        candidate.mark_unbound_state_used();
        candidate.encoding = StoreFormat::CurrentV3;
        candidate.ensure_encodable()?;
        Ok(candidate)
    }

    /// The highest accepted revocation epoch for a scope.
    #[must_use]
    pub fn revocation_epoch(&self, scope: &[u8]) -> u64 {
        self.revocation_epochs.get(scope).copied().unwrap_or(0)
    }

    /// Durably accept a revocation epoch (monotonic non-decreasing).
    ///
    /// # Errors
    /// Returns [`AntiRollbackError::Rollback`] if `epoch` is below the stored
    /// value, or [`AntiRollbackError::CapacityExceeded`] if the update would
    /// make the durable representation exceed its fixed bounds.
    pub fn accept_revocation_epoch(
        &mut self,
        scope: &[u8],
        epoch: u64,
    ) -> Result<(), AntiRollbackError> {
        let candidate = self.candidate_with_revocation_epoch(scope, epoch)?;
        *self = candidate;
        Ok(())
    }

    /// Prepare a revocation-epoch update without mutating the live store.
    ///
    /// # Errors
    /// Returns [`AntiRollbackError::Rollback`] when the epoch rewinds, or
    /// [`AntiRollbackError::CapacityExceeded`] when the candidate would not fit
    /// the durable representation.
    pub fn candidate_with_revocation_epoch(
        &self,
        scope: &[u8],
        epoch: u64,
    ) -> Result<Self, AntiRollbackError> {
        validate_scope(scope)?;
        let cur = self.revocation_epoch(scope);
        if epoch < cur {
            return Err(AntiRollbackError::Rollback);
        }
        let mut candidate = self.clone();
        candidate.revocation_epochs.insert(scope.to_vec(), epoch);
        candidate.mark_unbound_state_used();
        candidate.encoding = StoreFormat::CurrentV3;
        candidate.ensure_encodable()?;
        Ok(candidate)
    }

    /// Serialize to the store's durable byte representation.
    ///
    /// The representation is canonical and deterministic. A decoded legacy store
    /// retains its byte-exact legacy representation until a semantic mutation can
    /// be represented in the bounded current format. Legacy encoding still implies
    /// migration-required state and can never make the store eligible for package
    /// binding.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        match self.encoding {
            StoreFormat::LegacyV1 => self.to_legacy_v1_bytes(),
            StoreFormat::LegacyV2 => self.to_legacy_v2_bytes(),
            StoreFormat::CurrentV3 => self.to_current_v3_bytes(),
        }
    }

    fn to_current_v3_bytes(&self) -> Vec<u8> {
        let mut w = CborWriter::new();
        w.array_header(6);
        w.uint(STORE_FORMAT_VERSION);
        w.uint(self.boot_counter);
        match self.last_gate_boot_id {
            Some(gate_boot_id) => w.bytes(gate_boot_id.as_bytes()),
            None => w.bytes(&[]),
        }
        encode_map(&mut w, &self.terms);
        encode_map(&mut w, &self.revocation_epochs);
        encode_deployment_package_ratchet(&mut w, &self.deployment_package);
        w.into_bytes()
    }

    /// Parse current v3 or valid canonical legacy v1/v2 durable bytes.
    ///
    /// Legacy semantic state is preserved but marked migration-required. It
    /// cannot be implicitly package-bound, and every later v3 rewrite preserves
    /// that marker.
    ///
    /// # Errors
    /// Returns [`AntiRollbackError::Corrupt`] on any structural, canonical, or
    /// v3 state-invariant failure.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, AntiRollbackError> {
        if bytes.len() > STORE_LIMITS.max_total_bytes {
            return Err(AntiRollbackError::Corrupt);
        }
        let mut r = CborReader::new(bytes, STORE_LIMITS);
        let n = r.read_array_len().map_err(|_| AntiRollbackError::Corrupt)?;
        let format = match n {
            4 => StoreFormat::LegacyV1,
            5 => {
                if r.read_uint().map_err(|_| AntiRollbackError::Corrupt)?
                    != LEGACY_V2_FORMAT_VERSION
                {
                    return Err(AntiRollbackError::Corrupt);
                }
                StoreFormat::LegacyV2
            }
            6 => {
                if r.read_uint().map_err(|_| AntiRollbackError::Corrupt)? != STORE_FORMAT_VERSION {
                    return Err(AntiRollbackError::Corrupt);
                }
                StoreFormat::CurrentV3
            }
            _ => return Err(AntiRollbackError::Corrupt),
        };
        let boot_counter = r.read_uint().map_err(|_| AntiRollbackError::Corrupt)?;
        let last_gate_boot_id = match r.read_bytes().map_err(|_| AntiRollbackError::Corrupt)? {
            [] => None,
            bytes => Some(GateBootId::new(
                bytes.try_into().map_err(|_| AntiRollbackError::Corrupt)?,
            )),
        };
        let terms = decode_map(&mut r)?;
        let revocation_epochs = decode_map(&mut r)?;
        let deployment_package = match format {
            StoreFormat::LegacyV1 | StoreFormat::LegacyV2 => {
                DeploymentPackageRatchet::MigrationRequired
            }
            StoreFormat::CurrentV3 => decode_deployment_package_ratchet(&mut r)?,
        };
        r.end_container();
        r.finish().map_err(|_| AntiRollbackError::Corrupt)?;
        let store = Self {
            boot_counter,
            last_gate_boot_id,
            terms,
            revocation_epochs,
            deployment_package,
            encoding: format,
        };
        if store.boot_counter == 0 && store.last_gate_boot_id.is_some() {
            return Err(AntiRollbackError::Corrupt);
        }
        if matches!(
            &store.deployment_package,
            DeploymentPackageRatchet::PristineUnbound
        ) && !store.has_pristine_semantic_state()
        {
            return Err(AntiRollbackError::Corrupt);
        }
        if matches!(
            &store.deployment_package,
            DeploymentPackageRatchet::Bound(_)
        ) && (store.boot_counter == 0 || store.last_gate_boot_id.is_none())
        {
            return Err(AntiRollbackError::Corrupt);
        }
        store
            .ensure_encodable()
            .map_err(|_| AntiRollbackError::Corrupt)?;
        let canonical = store.to_bytes();
        if canonical != bytes {
            return Err(AntiRollbackError::Corrupt);
        }
        Ok(store)
    }

    fn to_legacy_v1_bytes(&self) -> Vec<u8> {
        let mut w = CborWriter::new();
        w.array_header(4);
        w.uint(self.boot_counter);
        match self.last_gate_boot_id {
            Some(gate_boot_id) => w.bytes(gate_boot_id.as_bytes()),
            None => w.bytes(&[]),
        }
        encode_map(&mut w, &self.terms);
        encode_map(&mut w, &self.revocation_epochs);
        w.into_bytes()
    }

    fn to_legacy_v2_bytes(&self) -> Vec<u8> {
        let mut w = CborWriter::new();
        w.array_header(5);
        w.uint(LEGACY_V2_FORMAT_VERSION);
        w.uint(self.boot_counter);
        match self.last_gate_boot_id {
            Some(gate_boot_id) => w.bytes(gate_boot_id.as_bytes()),
            None => w.bytes(&[]),
        }
        encode_map(&mut w, &self.terms);
        encode_map(&mut w, &self.revocation_epochs);
        w.into_bytes()
    }

    fn require_plain_boot_path(&self) -> Result<(), AntiRollbackError> {
        if matches!(&self.deployment_package, DeploymentPackageRatchet::Bound(_)) {
            Err(AntiRollbackError::PackageBindingRequired)
        } else {
            Ok(())
        }
    }

    fn mark_unbound_state_used(&mut self) {
        if matches!(
            &self.deployment_package,
            DeploymentPackageRatchet::PristineUnbound
        ) {
            self.deployment_package = DeploymentPackageRatchet::MigrationRequired;
        }
    }

    fn has_pristine_semantic_state(&self) -> bool {
        self.boot_counter == 0
            && self.last_gate_boot_id.is_none()
            && self.terms.is_empty()
            && self.revocation_epochs.is_empty()
    }

    fn ensure_encodable(&self) -> Result<(), AntiRollbackError> {
        validate_map(&self.terms)?;
        validate_map(&self.revocation_epochs)?;
        if self.to_bytes().len() > STORE_LIMITS.max_total_bytes {
            return Err(AntiRollbackError::CapacityExceeded);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StoreFormat {
    LegacyV1,
    LegacyV2,
    CurrentV3,
}

fn encode_deployment_package_ratchet(w: &mut CborWriter, state: &DeploymentPackageRatchet) {
    match state {
        DeploymentPackageRatchet::PristineUnbound => {
            w.array_header(1);
            w.uint(PACKAGE_STATE_PRISTINE_UNBOUND);
        }
        DeploymentPackageRatchet::Bound(binding) => {
            w.array_header(3);
            w.uint(PACKAGE_STATE_BOUND);
            binding.revision().encode(w);
            binding.payload_digest().encode(w);
        }
        DeploymentPackageRatchet::MigrationRequired => {
            w.array_header(1);
            w.uint(PACKAGE_STATE_MIGRATION_REQUIRED);
        }
    }
}

fn decode_deployment_package_ratchet(
    r: &mut CborReader<'_>,
) -> Result<DeploymentPackageRatchet, AntiRollbackError> {
    let n = r.read_array_len().map_err(|_| AntiRollbackError::Corrupt)?;
    let tag = r.read_uint().map_err(|_| AntiRollbackError::Corrupt)?;
    let state = match (tag, n) {
        (PACKAGE_STATE_PRISTINE_UNBOUND, 1) => DeploymentPackageRatchet::PristineUnbound,
        (PACKAGE_STATE_BOUND, 3) => {
            let revision = DeploymentRevision::decode(r).map_err(|_| AntiRollbackError::Corrupt)?;
            let payload_digest =
                DeploymentPayloadDigestV1::decode(r).map_err(|_| AntiRollbackError::Corrupt)?;
            DeploymentPackageRatchet::Bound(DeploymentPackageBinding::new(revision, payload_digest))
        }
        (PACKAGE_STATE_MIGRATION_REQUIRED, 1) => DeploymentPackageRatchet::MigrationRequired,
        _ => return Err(AntiRollbackError::Corrupt),
    };
    r.end_container();
    Ok(state)
}

fn derive_gate_boot_id(gate_id: &GateId, counter: u64, entropy: &[u8; 32]) -> GateBootId {
    let mut hasher = Sha256::new();
    hasher.update(BOOT_ID_DOMAIN);
    hasher.update(gate_id.as_str().as_bytes());
    hasher.update(counter.to_be_bytes());
    hasher.update(entropy);
    let digest: [u8; 32] = hasher.finalize().into();
    let mut boot_id = [0; 16];
    let (boot_id_bytes, _) = digest.split_at(boot_id.len());
    boot_id.copy_from_slice(boot_id_bytes);
    GateBootId::new(boot_id)
}

fn encode_map(w: &mut CborWriter, m: &BTreeMap<Vec<u8>, u64>) {
    w.array_header(m.len() as u64);
    for (k, v) in m {
        w.array_header(2);
        w.bytes(k);
        w.uint(*v);
    }
}

fn validate_scope(scope: &[u8]) -> Result<(), AntiRollbackError> {
    let len = u64::try_from(scope.len()).map_err(|_| AntiRollbackError::CapacityExceeded)?;
    if len > STORE_LIMITS.max_bytes_len {
        return Err(AntiRollbackError::CapacityExceeded);
    }
    Ok(())
}

fn validate_map(map: &BTreeMap<Vec<u8>, u64>) -> Result<(), AntiRollbackError> {
    let len = u64::try_from(map.len()).map_err(|_| AntiRollbackError::CapacityExceeded)?;
    if len > STORE_LIMITS.max_array_len {
        return Err(AntiRollbackError::CapacityExceeded);
    }
    for scope in map.keys() {
        validate_scope(scope)?;
    }
    Ok(())
}

fn decode_map(r: &mut CborReader<'_>) -> Result<BTreeMap<Vec<u8>, u64>, AntiRollbackError> {
    let n = r.read_array_len().map_err(|_| AntiRollbackError::Corrupt)?;
    let mut m = BTreeMap::new();
    for _ in 0..n {
        let pair = r.read_array_len().map_err(|_| AntiRollbackError::Corrupt)?;
        if pair != 2 {
            return Err(AntiRollbackError::Corrupt);
        }
        let k = r
            .read_bytes()
            .map_err(|_| AntiRollbackError::Corrupt)?
            .to_vec();
        let v = r.read_uint().map_err(|_| AntiRollbackError::Corrupt)?;
        r.end_container();
        if m.insert(k, v).is_some() {
            return Err(AntiRollbackError::Corrupt);
        }
    }
    r.end_container();
    Ok(m)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::num::NonZeroU64;
    use proptest::prelude::*;

    fn gate_id() -> GateId {
        GateId::new("gate-1").unwrap()
    }

    fn revision(value: u64) -> DeploymentRevision {
        DeploymentRevision::new(NonZeroU64::new(value).unwrap())
    }

    fn package_digest(value: u8) -> DeploymentPayloadDigestV1 {
        DeploymentPayloadDigestV1::compute(&[value])
    }

    fn legacy_bytes_at_total_limit(format: StoreFormat) -> Vec<u8> {
        let final_scope_len = match format {
            StoreFormat::LegacyV1 => 16_359,
            StoreFormat::LegacyV2 => 16_358,
            StoreFormat::CurrentV3 => unreachable!("fixture requires a legacy format"),
        };
        let scope_lengths = [16_384, 16_384, 16_384, final_scope_len];
        let mut writer = CborWriter::new();
        match format {
            StoreFormat::LegacyV1 => writer.array_header(4),
            StoreFormat::LegacyV2 => {
                writer.array_header(5);
                writer.uint(LEGACY_V2_FORMAT_VERSION);
            }
            StoreFormat::CurrentV3 => unreachable!("fixture requires a legacy format"),
        }
        writer.uint(0);
        writer.bytes(&[]);
        writer.array_header(4);
        for (marker, scope_len) in scope_lengths.into_iter().enumerate() {
            writer.array_header(2);
            writer.bytes(&vec![u8::try_from(marker).unwrap(); scope_len]);
            writer.uint(1);
        }
        writer.array_header(0);

        let bytes = writer.into_bytes();
        assert_eq!(bytes.len(), STORE_LIMITS.max_total_bytes);
        bytes
    }

    #[test]
    fn term_must_strictly_advance() {
        let mut s = AntiRollbackStore::new_empty();
        s.accept_term(b"lease", 5).unwrap();
        assert_eq!(s.accept_term(b"lease", 5), Err(AntiRollbackError::Rollback));
        assert_eq!(s.accept_term(b"lease", 4), Err(AntiRollbackError::Rollback));
        s.accept_term(b"lease", 6).unwrap();
        assert_eq!(s.highest_term(b"lease"), 6);
    }

    #[test]
    fn boot_counter_strictly_increases_across_reload() {
        let mut s = AntiRollbackStore::new_empty();
        let b1 = s.advance_boot().unwrap();
        let bytes = s.to_bytes();
        let mut s2 = AntiRollbackStore::from_bytes(&bytes).unwrap();
        let b2 = s2.advance_boot().unwrap();
        assert!(b2 > b1, "boot counter must advance across a reload");
    }

    #[test]
    fn roundtrip_preserves_high_waters() {
        let mut s = AntiRollbackStore::new_empty();
        let (boot_candidate, context) = s.candidate_for_boot(&gate_id(), [7; 32]).unwrap();
        s = boot_candidate;
        s.accept_term(b"lease", 9).unwrap();
        s.accept_revocation_epoch(b"admission", 3).unwrap();
        let bytes = s.to_bytes();
        let s2 = AntiRollbackStore::from_bytes(&bytes).unwrap();
        assert_eq!(s2.highest_term(b"lease"), 9);
        assert_eq!(s2.revocation_epoch(b"admission"), 3);
        assert_eq!(s2.boot_counter(), s.boot_counter());
        assert_eq!(s2.last_gate_boot_id(), Some(context.gate_boot_id));
    }

    #[test]
    fn corrupt_store_is_rejected_not_zeroed() {
        let mut s = AntiRollbackStore::new_empty();
        s.accept_term(b"lease", 42).unwrap();
        let mut bytes = s.to_bytes();
        bytes.truncate(bytes.len() / 2); // corrupt the tail
        assert_eq!(
            AntiRollbackStore::from_bytes(&bytes).err(),
            Some(AntiRollbackError::Corrupt),
            "corruption must be a fault, never a zero-init reset"
        );
    }

    #[test]
    fn boot_counter_exhaustion_is_terminal_not_reused() {
        let bytes = AntiRollbackStore {
            boot_counter: u64::MAX,
            deployment_package: DeploymentPackageRatchet::MigrationRequired,
            ..AntiRollbackStore::new_empty()
        }
        .to_bytes();
        let mut exhausted = AntiRollbackStore::from_bytes(&bytes).unwrap();
        assert_eq!(exhausted.advance_boot(), Err(AntiRollbackError::Exhausted));
        assert_eq!(exhausted.boot_counter(), u64::MAX);
    }

    #[test]
    fn candidates_do_not_mutate_live_state_before_commit() {
        let mut live = AntiRollbackStore::new_empty();
        live.accept_term(b"lease", 5).unwrap();
        let before = live.clone();

        let term_candidate = live.candidate_with_term(b"lease", 6).unwrap();
        assert_eq!(live, before);
        assert_eq!(term_candidate.highest_term(b"lease"), 6);

        let (boot_candidate, counter) = live.candidate_with_advanced_boot().unwrap();
        assert_eq!(live, before);
        assert_eq!(counter, 1);
        assert_eq!(boot_candidate.boot_counter(), 1);

        assert_eq!(
            live.candidate_with_term(b"lease", 5),
            Err(AntiRollbackError::Rollback)
        );
        assert_eq!(live, before);
    }

    #[test]
    fn map_entry_limit_is_enforced_before_mutation() {
        for update_terms in [true, false] {
            let mut store = AntiRollbackStore::new_empty();
            for index in 0..STORE_LIMITS.max_array_len {
                let scope = format!("scope-{index:03}");
                if update_terms {
                    store.accept_term(scope.as_bytes(), 1).unwrap();
                } else {
                    store.accept_revocation_epoch(scope.as_bytes(), 1).unwrap();
                }
            }

            let before = store.clone();
            let result = if update_terms {
                store.accept_term(b"one-scope-too-many", 1)
            } else {
                store.accept_revocation_epoch(b"one-scope-too-many", 1)
            };

            assert_eq!(result, Err(AntiRollbackError::CapacityExceeded));
            assert_eq!(store, before);
            assert_eq!(
                AntiRollbackStore::from_bytes(&store.to_bytes()).unwrap(),
                store
            );
        }
    }

    #[test]
    fn scope_byte_limit_accepts_boundary_and_rejects_excess_atomically() {
        let mut store = AntiRollbackStore::new_empty();
        let boundary = vec![7; usize::try_from(STORE_LIMITS.max_bytes_len).unwrap()];
        store.accept_term(&boundary, 1).unwrap();
        assert_eq!(
            AntiRollbackStore::from_bytes(&store.to_bytes()).unwrap(),
            store
        );

        let before = store.clone();
        let excess = vec![8; boundary.len() + 1];
        assert_eq!(
            store.accept_revocation_epoch(&excess, 1),
            Err(AntiRollbackError::CapacityExceeded)
        );
        assert_eq!(store, before);
    }

    #[test]
    fn aggregate_byte_limit_is_enforced_before_mutation() {
        let scope_len = usize::try_from(STORE_LIMITS.max_bytes_len).unwrap();
        let mut store = AntiRollbackStore::new_empty();
        for marker in 0..3 {
            store.accept_term(&vec![marker; scope_len], 1).unwrap();
        }
        assert!(store.to_bytes().len() <= STORE_LIMITS.max_total_bytes);
        let before = store.clone();

        assert_eq!(
            store.accept_term(&vec![3; scope_len], 1),
            Err(AntiRollbackError::CapacityExceeded)
        );
        assert_eq!(store, before);
        assert_eq!(
            AntiRollbackStore::from_bytes(&store.to_bytes()).unwrap(),
            store
        );
    }

    #[test]
    fn decoder_rejects_input_above_the_total_byte_limit() {
        let oversized = vec![0; STORE_LIMITS.max_total_bytes + 1];
        assert_eq!(
            AntiRollbackStore::from_bytes(&oversized),
            Err(AntiRollbackError::Corrupt)
        );
    }

    fn assert_boundary_legacy_roundtrip(format: StoreFormat) {
        let bytes = legacy_bytes_at_total_limit(format);
        let store = AntiRollbackStore::from_bytes(&bytes).unwrap();

        assert!(store.deployment_package_migration_required());
        assert_eq!(store.to_bytes(), bytes);
        assert_eq!(
            AntiRollbackStore::from_bytes(&store.to_bytes()).unwrap(),
            store
        );
    }

    #[test]
    fn legacy_v1_at_total_limit_opens_and_reserializes_byte_identically() {
        assert_boundary_legacy_roundtrip(StoreFormat::LegacyV1);
    }

    #[test]
    fn legacy_v2_at_total_limit_opens_and_reserializes_byte_identically() {
        assert_boundary_legacy_roundtrip(StoreFormat::LegacyV2);
    }

    #[test]
    fn boundary_legacy_mutation_failure_preserves_state_and_encoding() {
        let first_scope = vec![0; usize::try_from(STORE_LIMITS.max_bytes_len).unwrap()];
        for format in [StoreFormat::LegacyV1, StoreFormat::LegacyV2] {
            let bytes = legacy_bytes_at_total_limit(format);
            let mut store = AntiRollbackStore::from_bytes(&bytes).unwrap();
            let before = store.clone();

            assert_eq!(
                store.accept_term(&first_scope, 2),
                Err(AntiRollbackError::CapacityExceeded)
            );
            assert_eq!(store, before);
            assert_eq!(store.to_bytes(), bytes);
            assert_eq!(
                AntiRollbackStore::from_bytes(&store.to_bytes()).unwrap(),
                store
            );
        }
    }

    proptest! {
        #[test]
        fn every_accepted_public_update_remains_roundtrippable(
            updates in prop::collection::vec(
                (
                    any::<bool>(),
                    prop::collection::vec(any::<u8>(), 0..64),
                    any::<u16>(),
                ),
                0..128,
            )
        ) {
            let mut store = AntiRollbackStore::new_empty();

            for (is_term, scope, value) in updates {
                let before = store.clone();
                let result = if is_term {
                    store.accept_term(&scope, u64::from(value))
                } else {
                    store.accept_revocation_epoch(&scope, u64::from(value))
                };
                if result.is_err() {
                    prop_assert_eq!(&store, &before);
                }

                let bytes = store.to_bytes();
                prop_assert!(bytes.len() <= STORE_LIMITS.max_total_bytes);
                prop_assert_eq!(
                    AntiRollbackStore::from_bytes(&bytes).unwrap(),
                    store.clone()
                );
            }
        }
    }

    #[test]
    fn noncanonical_or_duplicate_maps_are_corrupt() {
        let mut w = CborWriter::new();
        w.array_header(4);
        w.uint(0);
        w.bytes(&[]);
        w.array_header(2);
        for value in [1, 2] {
            w.array_header(2);
            w.bytes(b"same");
            w.uint(value);
        }
        w.array_header(0);
        assert_eq!(
            AntiRollbackStore::from_bytes(&w.into_bytes()),
            Err(AntiRollbackError::Corrupt)
        );
    }

    #[test]
    fn boot_derivation_is_deterministic_and_domain_bound() {
        let store = AntiRollbackStore::new_empty();
        let (candidate, context) = store.candidate_for_boot(&gate_id(), [7; 32]).unwrap();
        let (_, repeated_derivation) = store.candidate_for_boot(&gate_id(), [7; 32]).unwrap();

        assert_eq!(context, repeated_derivation);
        assert_eq!(context.boot_counter, 1);
        assert_eq!(
            context.gate_boot_id,
            GateBootId::new([
                0x53, 0x37, 0x21, 0xc0, 0xb3, 0xa3, 0xa7, 0x46, 0x1d, 0xc7, 0xd0, 0xe6, 0x6f, 0xd1,
                0x96, 0x52,
            ])
        );
        assert_eq!(candidate.last_gate_boot_id(), Some(context.gate_boot_id));
    }

    #[test]
    fn derived_boot_id_repeat_is_rejected_without_mutation() {
        let entropy = [9; 32];
        let repeated_id = derive_gate_boot_id(&gate_id(), 8, &entropy);
        let live = AntiRollbackStore {
            boot_counter: 7,
            last_gate_boot_id: Some(repeated_id),
            ..AntiRollbackStore::new_empty()
        };
        let before = live.clone();

        assert_eq!(
            live.candidate_for_boot(&gate_id(), entropy),
            Err(AntiRollbackError::BootIdRepeat)
        );
        assert_eq!(live, before);
    }

    #[test]
    fn plain_boot_candidate_rejects_counter_exhaustion_without_mutation() {
        let live = AntiRollbackStore {
            boot_counter: u64::MAX,
            ..AntiRollbackStore::new_empty()
        };
        let before = live.clone();

        assert_eq!(
            live.candidate_for_boot(&gate_id(), [1; 32]),
            Err(AntiRollbackError::Exhausted)
        );
        assert_eq!(live, before);
    }

    #[test]
    fn deployment_boot_candidate_rejects_counter_exhaustion_without_mutation() {
        let live = AntiRollbackStore {
            boot_counter: u64::MAX,
            last_gate_boot_id: Some(GateBootId::new([4; 16])),
            deployment_package: DeploymentPackageRatchet::Bound(DeploymentPackageBinding::new(
                revision(2),
                package_digest(3),
            )),
            ..AntiRollbackStore::new_empty()
        };
        let before = live.clone();

        assert_eq!(
            live.candidate_for_deployment_boot(
                &gate_id(),
                [1; 32],
                revision(2),
                package_digest(3),
            ),
            Err(AntiRollbackError::Exhausted)
        );
        assert_eq!(live, before);
    }

    #[test]
    fn legacy_store_without_last_boot_id_is_rejected() {
        let mut legacy = CborWriter::new();
        legacy.array_header(3);
        legacy.uint(0);
        legacy.array_header(0);
        legacy.array_header(0);

        assert_eq!(
            AntiRollbackStore::from_bytes(&legacy.into_bytes()),
            Err(AntiRollbackError::Corrupt)
        );
    }

    #[test]
    fn legacy_v1_store_is_preserved_with_a_migration_required_marker() {
        let mut legacy = AntiRollbackStore::new_empty();
        legacy
            .accept_term(b"lease:mission-authority:uav-1", 10)
            .unwrap();
        let legacy_bytes = legacy.to_legacy_v1_bytes();
        let migrated = AntiRollbackStore::from_bytes(&legacy_bytes).unwrap();
        assert_eq!(migrated.highest_term(b"lease:mission-authority:uav-1"), 10);
        assert!(migrated.deployment_package_migration_required());
        assert_eq!(migrated.to_bytes(), legacy_bytes);
        assert_eq!(
            migrated.candidate_for_deployment_boot(
                &gate_id(),
                [1; 32],
                revision(1),
                package_digest(1),
            ),
            Err(AntiRollbackError::MigrationRequired)
        );

        let mut rewritten = migrated;
        rewritten.accept_term(b"canonical-scope", 11).unwrap();
        let rewritten_bytes = rewritten.to_bytes();

        let mut old_reader = CborReader::new(&rewritten_bytes, Limits::LARGE);
        assert_eq!(old_reader.read_array_len().unwrap(), 6);
        assert_ne!(rewritten_bytes, rewritten.to_legacy_v1_bytes());
        let reopened = AntiRollbackStore::from_bytes(&rewritten_bytes).unwrap();
        assert_eq!(reopened.highest_term(b"canonical-scope"), 11);
        assert!(reopened.deployment_package_migration_required());
    }

    #[test]
    fn legacy_v2_store_is_preserved_with_a_migration_required_marker() {
        let mut legacy = AntiRollbackStore::new_empty();
        legacy.accept_revocation_epoch(b"authority", 7).unwrap();
        let legacy_bytes = legacy.to_legacy_v2_bytes();
        let mut migrated = AntiRollbackStore::from_bytes(&legacy_bytes).unwrap();

        assert_eq!(migrated.to_bytes(), legacy_bytes);
        assert_eq!(migrated.revocation_epoch(b"authority"), 7);
        assert!(migrated.deployment_package_migration_required());

        migrated.accept_revocation_epoch(b"authority", 8).unwrap();
        let rewritten_bytes = migrated.to_bytes();
        let mut reader = CborReader::new(&rewritten_bytes, Limits::LARGE);
        assert_eq!(reader.read_array_len().unwrap(), 6);
        let reopened = AntiRollbackStore::from_bytes(&rewritten_bytes).unwrap();
        assert_eq!(reopened.revocation_epoch(b"authority"), 8);
        assert!(reopened.deployment_package_migration_required());
    }

    #[test]
    fn equality_is_semantic_across_legacy_and_current_encodings() {
        for format in [StoreFormat::LegacyV1, StoreFormat::LegacyV2] {
            let mut source = AntiRollbackStore::new_empty();
            source.accept_term(b"lease-scope", 7).unwrap();
            let legacy_bytes = match format {
                StoreFormat::LegacyV1 => source.to_legacy_v1_bytes(),
                StoreFormat::LegacyV2 => source.to_legacy_v2_bytes(),
                StoreFormat::CurrentV3 => unreachable!("fixture requires a legacy format"),
            };
            let mut legacy = AntiRollbackStore::from_bytes(&legacy_bytes).unwrap();
            let mut current = legacy.clone();
            current.encoding = StoreFormat::CurrentV3;

            assert_eq!(legacy, current);
            assert_ne!(legacy.to_bytes(), current.to_bytes());

            legacy.accept_revocation_epoch(b"authority", 11).unwrap();
            current.accept_revocation_epoch(b"authority", 11).unwrap();

            assert_eq!(legacy, current);
            assert_eq!(legacy.to_bytes(), current.to_bytes());
            assert_eq!(
                AntiRollbackStore::from_bytes(&legacy.to_bytes()).unwrap(),
                legacy
            );
        }
    }

    #[test]
    fn malformed_legacy_v2_is_corrupt_instead_of_migration_required() {
        let mut malformed = CborWriter::new();
        malformed.array_header(5);
        malformed.uint(LEGACY_V2_FORMAT_VERSION);
        malformed.uint(0);
        malformed.bytes(&[]);
        malformed.array_header(1);
        malformed.array_header(1);
        malformed.bytes(b"missing-value");
        malformed.array_header(0);

        assert_eq!(
            AntiRollbackStore::from_bytes(&malformed.into_bytes()),
            Err(AntiRollbackError::Corrupt)
        );
    }

    #[test]
    fn zero_boot_counter_with_a_boot_id_is_corrupt_in_every_v3_state() {
        for deployment_package in [
            DeploymentPackageRatchet::MigrationRequired,
            DeploymentPackageRatchet::Bound(DeploymentPackageBinding::new(
                revision(1),
                package_digest(1),
            )),
        ] {
            let invalid = AntiRollbackStore {
                last_gate_boot_id: Some(GateBootId::new([7; 16])),
                deployment_package,
                ..AntiRollbackStore::new_empty()
            };
            assert_eq!(
                AntiRollbackStore::from_bytes(&invalid.to_bytes()),
                Err(AntiRollbackError::Corrupt)
            );
        }
    }

    #[test]
    fn initial_deployment_boot_atomically_binds_a_pristine_store() {
        let live = AntiRollbackStore::new_empty();
        let before = live.clone();

        let (candidate, context) = live
            .candidate_for_deployment_boot(&gate_id(), [2; 32], revision(4), package_digest(8))
            .unwrap();

        assert_eq!(live, before);
        assert_eq!(context.boot_counter, 1);
        assert_eq!(candidate.boot_counter(), 1);
        assert_eq!(
            candidate.deployment_package_binding(),
            Some(&DeploymentPackageBinding::new(
                revision(4),
                package_digest(8)
            ))
        );
    }

    #[test]
    fn same_revision_and_digest_is_idempotent_but_advances_boot() {
        let (bound, first) = AntiRollbackStore::new_empty()
            .candidate_for_deployment_boot(&gate_id(), [2; 32], revision(4), package_digest(8))
            .unwrap();

        let (rebooted, second) = bound
            .candidate_for_deployment_boot(&gate_id(), [3; 32], revision(4), package_digest(8))
            .unwrap();

        assert_eq!(second.boot_counter, first.boot_counter + 1);
        assert_eq!(
            rebooted.deployment_package_binding(),
            bound.deployment_package_binding()
        );
    }

    #[test]
    fn lower_deployment_revision_is_rejected_without_mutation() {
        let (bound, _) = AntiRollbackStore::new_empty()
            .candidate_for_deployment_boot(&gate_id(), [2; 32], revision(4), package_digest(8))
            .unwrap();
        let before = bound.clone();

        assert_eq!(
            bound.candidate_for_deployment_boot(
                &gate_id(),
                [3; 32],
                revision(3),
                package_digest(8),
            ),
            Err(AntiRollbackError::PackageRollback)
        );
        assert_eq!(bound, before);
    }

    #[test]
    fn same_revision_with_a_different_digest_is_equivocation() {
        let (bound, _) = AntiRollbackStore::new_empty()
            .candidate_for_deployment_boot(&gate_id(), [2; 32], revision(4), package_digest(8))
            .unwrap();

        assert_eq!(
            bound.candidate_for_deployment_boot(
                &gate_id(),
                [3; 32],
                revision(4),
                package_digest(9),
            ),
            Err(AntiRollbackError::PackageEquivocation)
        );
    }

    #[test]
    fn higher_deployment_revision_rebinds_digest_and_advances_boot() {
        let (bound, first) = AntiRollbackStore::new_empty()
            .candidate_for_deployment_boot(&gate_id(), [2; 32], revision(4), package_digest(8))
            .unwrap();

        let (advanced, second) = bound
            .candidate_for_deployment_boot(&gate_id(), [3; 32], revision(5), package_digest(9))
            .unwrap();

        assert_eq!(second.boot_counter, first.boot_counter + 1);
        assert_eq!(
            advanced.deployment_package_binding(),
            Some(&DeploymentPackageBinding::new(
                revision(5),
                package_digest(9)
            ))
        );
    }

    #[test]
    fn plain_boot_and_advance_are_rejected_after_package_binding() {
        let (bound, _) = AntiRollbackStore::new_empty()
            .candidate_for_deployment_boot(&gate_id(), [2; 32], revision(4), package_digest(8))
            .unwrap();
        let mut direct = bound.clone();

        assert_eq!(
            bound.candidate_for_boot(&gate_id(), [3; 32]),
            Err(AntiRollbackError::PackageBindingRequired)
        );
        assert_eq!(
            direct.advance_boot(),
            Err(AntiRollbackError::PackageBindingRequired)
        );
    }

    #[test]
    fn plain_use_of_a_fresh_store_permanently_requires_migration_for_package_binding() {
        let (used, _) = AntiRollbackStore::new_empty()
            .candidate_for_boot(&gate_id(), [3; 32])
            .unwrap();
        let reopened = AntiRollbackStore::from_bytes(&used.to_bytes()).unwrap();

        assert!(reopened.deployment_package_migration_required());
        assert_eq!(
            reopened.candidate_for_deployment_boot(
                &gate_id(),
                [4; 32],
                revision(1),
                package_digest(1),
            ),
            Err(AntiRollbackError::MigrationRequired)
        );
    }

    #[test]
    fn term_use_of_a_fresh_store_permanently_requires_migration_for_package_binding() {
        let mut used = AntiRollbackStore::new_empty();
        used.accept_term(b"lease", 1).unwrap();

        assert!(used.deployment_package_migration_required());
        assert_eq!(
            used.candidate_for_deployment_boot(
                &gate_id(),
                [4; 32],
                revision(1),
                package_digest(1),
            ),
            Err(AntiRollbackError::MigrationRequired)
        );
    }

    #[test]
    fn revocation_use_of_a_fresh_store_permanently_requires_migration_for_package_binding() {
        let mut used = AntiRollbackStore::new_empty();
        used.accept_revocation_epoch(b"authority", 1).unwrap();

        assert!(used.deployment_package_migration_required());
        assert_eq!(
            used.candidate_for_deployment_boot(
                &gate_id(),
                [4; 32],
                revision(1),
                package_digest(1),
            ),
            Err(AntiRollbackError::MigrationRequired)
        );
    }

    #[test]
    fn package_bound_term_and_revocation_updates_preserve_binding() {
        let (mut bound, _) = AntiRollbackStore::new_empty()
            .candidate_for_deployment_boot(&gate_id(), [4; 32], revision(2), package_digest(3))
            .unwrap();
        let expected = bound.deployment_package_binding().cloned();

        bound.accept_term(b"lease", 1).unwrap();
        bound.accept_revocation_epoch(b"authority", 1).unwrap();

        assert_eq!(bound.deployment_package_binding().cloned(), expected);
    }

    #[test]
    fn inconsistent_pristine_state_cannot_be_implicitly_package_bound() {
        let inconsistent = AntiRollbackStore {
            boot_counter: 1,
            ..AntiRollbackStore::new_empty()
        };

        assert_eq!(
            inconsistent.candidate_for_deployment_boot(
                &gate_id(),
                [4; 32],
                revision(1),
                package_digest(1),
            ),
            Err(AntiRollbackError::MigrationRequired)
        );
    }

    #[test]
    fn package_binding_roundtrip_preserves_revision_digest_and_boot() {
        let (bound, context) = AntiRollbackStore::new_empty()
            .candidate_for_deployment_boot(&gate_id(), [5; 32], revision(11), package_digest(7))
            .unwrap();

        let reopened = AntiRollbackStore::from_bytes(&bound.to_bytes()).unwrap();

        assert_eq!(reopened.boot_counter(), context.boot_counter);
        assert_eq!(
            reopened.deployment_package_binding(),
            bound.deployment_package_binding()
        );
    }

    #[test]
    fn v3_bound_state_without_a_committed_boot_is_corrupt() {
        let impossible = AntiRollbackStore {
            deployment_package: DeploymentPackageRatchet::Bound(DeploymentPackageBinding::new(
                revision(1),
                package_digest(1),
            )),
            ..AntiRollbackStore::new_empty()
        };

        assert_eq!(
            AntiRollbackStore::from_bytes(&impossible.to_bytes()),
            Err(AntiRollbackError::Corrupt)
        );
    }

    #[test]
    fn deployment_ratchet_errors_have_stable_reason_strings() {
        for (error, reason) in [
            (AntiRollbackError::Rollback, "ANTI_ROLLBACK_REWIND"),
            (AntiRollbackError::Exhausted, "ANTI_ROLLBACK_EXHAUSTED"),
            (
                AntiRollbackError::BootIdRepeat,
                "ANTI_ROLLBACK_BOOT_ID_REPEAT",
            ),
            (
                AntiRollbackError::MigrationRequired,
                "ANTI_ROLLBACK_MIGRATION_REQUIRED",
            ),
            (
                AntiRollbackError::PackageRollback,
                "ANTI_ROLLBACK_PACKAGE_ROLLBACK",
            ),
            (
                AntiRollbackError::PackageEquivocation,
                "ANTI_ROLLBACK_PACKAGE_EQUIVOCATION",
            ),
            (
                AntiRollbackError::PackageBindingRequired,
                "ANTI_ROLLBACK_PACKAGE_BINDING_REQUIRED",
            ),
            (
                AntiRollbackError::CapacityExceeded,
                "ANTI_ROLLBACK_CAPACITY_EXCEEDED",
            ),
            (AntiRollbackError::Corrupt, "ANTI_ROLLBACK_CORRUPT"),
        ] {
            assert_eq!(error.as_str(), reason);
            assert_eq!(error.to_string(), reason);
        }
    }
}
