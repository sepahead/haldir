//! Durable boot, package, lease-term, and revocation anti-rollback state composed
//! over `haldir-durable` primitives.

use crate::mission::{LeaseTermStore, LeaseTermStoreError};
use crate::{AntiRollbackError, AntiRollbackStore, BootContext, DeploymentPackageBinding};
use haldir_contracts::deployment::{DeploymentPayloadDigestV1, DeploymentRevision};
use haldir_contracts::ids::{GateBootId, GateId};
use haldir_durable::{
    AnchorProtection, AuthenticatedSnapshotStore, CommitReceipt, DurableError, GenerationAnchor,
    RecoveryStatus, SnapshotBinding, SnapshotStorage, StorageMacKey,
};

/// A semantic or durable-storage failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DurableAntiRollbackError {
    /// The semantic high-water update was invalid.
    State(AntiRollbackError),
    /// The authenticated snapshot or external anchor failed.
    Durable(DurableError),
    /// Boot advancement named a Gate other than the store's provisioned binding.
    GateBindingMismatch,
}

impl From<AntiRollbackError> for DurableAntiRollbackError {
    fn from(error: AntiRollbackError) -> Self {
        Self::State(error)
    }
}

impl From<DurableError> for DurableAntiRollbackError {
    fn from(error: DurableError) -> Self {
        Self::Durable(error)
    }
}

/// Anti-rollback semantics whose live state changes only after snapshot commit.
pub struct DurableAntiRollbackStore<S, A> {
    state: AntiRollbackStore,
    snapshots: AuthenticatedSnapshotStore<S, A>,
}

/// A durable anti-rollback store that committed a fresh boot in this process.
///
/// This type is created only by [`DurableAntiRollbackStore::begin_boot`], is not
/// cloneable, and is consumed by recovered Gate construction. A reopened store
/// cannot regain this state without committing another boot first.
pub struct BootedDurableAntiRollbackStore<S, A> {
    store: DurableAntiRollbackStore<S, A>,
    context: BootContext,
}

/// A durable anti-rollback store that atomically committed caller-supplied
/// deployment ratchet values and a fresh boot in this process.
///
/// This non-cloneable capability is created only by
/// [`DurableAntiRollbackStore::begin_deployment_boot`]. A reopened store cannot
/// regain it without committing another package-bound boot first.
pub struct DeploymentBootedDurableAntiRollbackStore<S, A> {
    store: DurableAntiRollbackStore<S, A>,
    context: BootContext,
    binding: DeploymentPackageBinding,
}

impl<S: SnapshotStorage, A: GenerationAnchor> DurableAntiRollbackStore<S, A> {
    /// Explicitly provision a fresh empty anti-rollback store.
    ///
    /// # Errors
    /// Returns on pre-existing state, storage, authentication, or anchor failure.
    pub fn provision_new(
        storage: S,
        anchor: A,
        key: StorageMacKey,
        binding: SnapshotBinding,
        max_payload_bytes: usize,
    ) -> Result<Self, DurableAntiRollbackError> {
        let state = AntiRollbackStore::new_empty();
        let snapshots = AuthenticatedSnapshotStore::provision_new(
            storage,
            anchor,
            key,
            binding,
            max_payload_bytes,
            &state.to_bytes(),
        )?;
        Ok(Self { state, snapshots })
    }

    /// Open existing authenticated state; missing/corrupt/rewound state never
    /// becomes an implicit empty store.
    ///
    /// # Errors
    /// Returns on durable reconciliation or semantic payload corruption.
    pub fn open_existing(
        storage: S,
        anchor: A,
        key: StorageMacKey,
        binding: SnapshotBinding,
        max_payload_bytes: usize,
    ) -> Result<(Self, RecoveryStatus), DurableAntiRollbackError> {
        let (snapshots, recovery) = AuthenticatedSnapshotStore::open_existing(
            storage,
            anchor,
            key,
            binding,
            max_payload_bytes,
        )?;
        let state = AntiRollbackStore::from_bytes(snapshots.current().payload())?;
        Ok((Self { state, snapshots }, recovery))
    }

    /// Current monotonic boot counter.
    #[must_use]
    pub const fn boot_counter(&self) -> u64 {
        self.state.boot_counter()
    }

    /// The most recently committed Gate boot ID, if a bound boot has begun.
    #[must_use]
    pub const fn last_gate_boot_id(&self) -> Option<GateBootId> {
        self.state.last_gate_boot_id()
    }

    /// The currently committed deployment-package binding, if package-bound.
    #[must_use]
    pub const fn deployment_package_binding(&self) -> Option<&DeploymentPackageBinding> {
        self.state.deployment_package_binding()
    }

    /// Whether explicit migration is required before package binding.
    #[must_use]
    pub const fn deployment_package_migration_required(&self) -> bool {
        self.state.deployment_package_migration_required()
    }

    /// Protection class declared by the configured generation anchor.
    #[must_use]
    pub fn anchor_protection(&self) -> AnchorProtection {
        self.snapshots.anchor_protection()
    }

    /// Whether the authenticated snapshot store is provisioned for `gate_id`.
    #[must_use]
    pub fn is_bound_to_gate(&self, gate_id: &GateId) -> bool {
        self.snapshots
            .binding()
            .matches_gate_id(gate_id.as_str().as_bytes())
    }

    /// Highest accepted lease term for `scope`.
    #[must_use]
    pub fn highest_term(&self, scope: &[u8]) -> u64 {
        self.state.highest_term(scope)
    }

    /// Highest accepted revocation epoch for `scope`.
    #[must_use]
    pub fn revocation_epoch(&self, scope: &[u8]) -> u64 {
        self.state.revocation_epoch(scope)
    }

    /// Derive and commit the next Gate boot incarnation before exposing it.
    ///
    /// `entropy` must come from the caller's configured cryptographic entropy
    /// source. This semantic durability layer performs no OS random generation.
    ///
    /// # Errors
    /// Returns when `gate_id` differs from the authenticated store binding, on
    /// counter exhaustion, a derived boot-ID repeat, or durable commit failure.
    /// The booted capability is returned only after commit succeeds.
    pub fn begin_boot(
        mut self,
        gate_id: &GateId,
        entropy: [u8; 32],
    ) -> Result<(BootedDurableAntiRollbackStore<S, A>, CommitReceipt), DurableAntiRollbackError>
    {
        if !self.is_bound_to_gate(gate_id) {
            return Err(DurableAntiRollbackError::GateBindingMismatch);
        }
        let (candidate, context) = self.state.candidate_for_boot(gate_id, entropy)?;
        let receipt = self.snapshots.commit(&candidate.to_bytes())?;
        self.state = candidate;
        Ok((
            BootedDurableAntiRollbackStore {
                store: self,
                context,
            },
            receipt,
        ))
    }

    /// Atomically commit caller-supplied deployment ratchet values and a fresh Gate boot.
    ///
    /// `entropy` must come from the caller's configured cryptographic entropy
    /// source. The initial package can bind only a pristine v3 store. Later
    /// calls may retain an identical revision/digest pair or advance revision.
    /// This state layer does not verify package provenance.
    ///
    /// # Errors
    /// Returns when `gate_id` differs from the authenticated store binding, the
    /// package ratchet rejects migration, rollback, or equivocation, the boot
    /// namespace rejects its candidate, or durable commit fails. The package-
    /// booted capability is returned only after the atomic candidate commits.
    pub fn begin_deployment_boot(
        mut self,
        gate_id: &GateId,
        entropy: [u8; 32],
        revision: DeploymentRevision,
        payload_digest: DeploymentPayloadDigestV1,
    ) -> Result<
        (
            DeploymentBootedDurableAntiRollbackStore<S, A>,
            CommitReceipt,
        ),
        DurableAntiRollbackError,
    > {
        if !self.is_bound_to_gate(gate_id) {
            return Err(DurableAntiRollbackError::GateBindingMismatch);
        }
        let (candidate, context) =
            self.state
                .candidate_for_deployment_boot(gate_id, entropy, revision, payload_digest)?;
        let binding = candidate
            .deployment_package_binding()
            .cloned()
            .ok_or(AntiRollbackError::Corrupt)?;
        let receipt = self.snapshots.commit(&candidate.to_bytes())?;
        self.state = candidate;
        Ok((
            DeploymentBootedDurableAntiRollbackStore {
                store: self,
                context,
                binding,
            },
            receipt,
        ))
    }

    /// Commit a strictly advancing lease term before updating live state.
    ///
    /// # Errors
    /// Returns on rollback or durable commit failure.
    pub fn accept_term(
        &mut self,
        scope: &[u8],
        term: u64,
    ) -> Result<CommitReceipt, DurableAntiRollbackError> {
        let candidate = self.state.candidate_with_term(scope, term)?;
        let receipt = self.snapshots.commit(&candidate.to_bytes())?;
        self.state = candidate;
        Ok(receipt)
    }

    /// Commit a non-rewinding revocation epoch before updating live state.
    ///
    /// # Errors
    /// Returns on rollback or durable commit failure.
    pub fn accept_revocation_epoch(
        &mut self,
        scope: &[u8],
        epoch: u64,
    ) -> Result<CommitReceipt, DurableAntiRollbackError> {
        let candidate = self.state.candidate_with_revocation_epoch(scope, epoch)?;
        let receipt = self.snapshots.commit(&candidate.to_bytes())?;
        self.state = candidate;
        Ok(receipt)
    }

    /// Return owned backends for shutdown/recovery orchestration.
    #[must_use]
    pub fn into_parts(self) -> (S, A) {
        self.snapshots.into_parts()
    }
}

impl<S: SnapshotStorage, A: GenerationAnchor> BootedDurableAntiRollbackStore<S, A> {
    /// The fresh boot context committed immediately before this value was created.
    #[must_use]
    pub const fn boot_context(&self) -> BootContext {
        self.context
    }

    /// Whether this booted capability belongs to `gate_id`.
    #[must_use]
    pub fn is_bound_to_gate(&self, gate_id: &GateId) -> bool {
        self.store.is_bound_to_gate(gate_id)
    }

    /// Protection class declared by the configured generation anchor.
    #[must_use]
    pub fn anchor_protection(&self) -> AnchorProtection {
        self.store.anchor_protection()
    }

    /// Highest accepted lease term for `scope`.
    #[must_use]
    pub fn highest_term(&self, scope: &[u8]) -> u64 {
        self.store.highest_term(scope)
    }

    /// Commit a non-rewinding revocation epoch before updating live state.
    ///
    /// # Errors
    /// Returns on rollback or durable commit failure.
    pub fn accept_revocation_epoch(
        &mut self,
        scope: &[u8],
        epoch: u64,
    ) -> Result<CommitReceipt, DurableAntiRollbackError> {
        self.store.accept_revocation_epoch(scope, epoch)
    }

    /// Return owned backends for shutdown/recovery orchestration.
    #[must_use]
    pub fn into_parts(self) -> (S, A) {
        self.store.into_parts()
    }
}

impl<S: SnapshotStorage, A: GenerationAnchor> DeploymentBootedDurableAntiRollbackStore<S, A> {
    /// The fresh boot context committed atomically with the package binding.
    #[must_use]
    pub const fn boot_context(&self) -> BootContext {
        self.context
    }

    /// The deployment ratchet binding committed atomically with this boot.
    #[must_use]
    pub const fn deployment_package_binding(&self) -> &DeploymentPackageBinding {
        &self.binding
    }

    /// Whether this package-booted capability belongs to `gate_id`.
    #[must_use]
    pub fn is_bound_to_gate(&self, gate_id: &GateId) -> bool {
        self.store.is_bound_to_gate(gate_id)
    }

    /// Protection class declared by the configured generation anchor.
    #[must_use]
    pub fn anchor_protection(&self) -> AnchorProtection {
        self.store.anchor_protection()
    }

    /// Highest accepted lease term for `scope`.
    #[must_use]
    pub fn highest_term(&self, scope: &[u8]) -> u64 {
        self.store.highest_term(scope)
    }

    /// Commit a non-rewinding revocation epoch before updating live state.
    ///
    /// # Errors
    /// Returns on rollback or durable commit failure.
    pub fn accept_revocation_epoch(
        &mut self,
        scope: &[u8],
        epoch: u64,
    ) -> Result<CommitReceipt, DurableAntiRollbackError> {
        self.store.accept_revocation_epoch(scope, epoch)
    }

    /// Return owned backends for shutdown/recovery orchestration.
    #[must_use]
    pub fn into_parts(self) -> (S, A) {
        self.store.into_parts()
    }
}

impl<S: SnapshotStorage + Send, A: GenerationAnchor + Send> LeaseTermStore
    for BootedDurableAntiRollbackStore<S, A>
{
    fn highest_term(&self, scope: &[u8]) -> u64 {
        Self::highest_term(self, scope)
    }

    fn commit_term(&mut self, scope: &[u8], term: u64) -> Result<(), LeaseTermStoreError> {
        self.store
            .accept_term(scope, term)
            .map(|_| ())
            .map_err(|error| {
                if error == DurableAntiRollbackError::State(AntiRollbackError::Rollback) {
                    LeaseTermStoreError::Rollback
                } else {
                    LeaseTermStoreError::Unavailable
                }
            })
    }
}

impl<S: SnapshotStorage + Send, A: GenerationAnchor + Send> LeaseTermStore
    for DeploymentBootedDurableAntiRollbackStore<S, A>
{
    fn highest_term(&self, scope: &[u8]) -> u64 {
        Self::highest_term(self, scope)
    }

    fn commit_term(&mut self, scope: &[u8], term: u64) -> Result<(), LeaseTermStoreError> {
        self.store
            .accept_term(scope, term)
            .map(|_| ())
            .map_err(|error| {
                if error == DurableAntiRollbackError::State(AntiRollbackError::Rollback) {
                    LeaseTermStoreError::Rollback
                } else {
                    LeaseTermStoreError::Unavailable
                }
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::num::NonZeroU64;
    use haldir_durable::{Anchor, StoreId};
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct FailureFlag(Arc<AtomicBool>);

    impl FailureFlag {
        fn get(&self) -> bool {
            self.0.load(Ordering::SeqCst)
        }

        fn set(&self, value: bool) {
            self.0.store(value, Ordering::SeqCst);
        }
    }

    #[derive(Clone, Default)]
    struct MemoryStorage {
        bytes: Arc<Mutex<Option<Vec<u8>>>>,
        fail_replace: FailureFlag,
    }

    impl SnapshotStorage for MemoryStorage {
        fn load(&self) -> Result<Option<Vec<u8>>, DurableError> {
            Ok(self.bytes.lock().unwrap().clone())
        }

        fn replace(&mut self, bytes: &[u8]) -> Result<(), DurableError> {
            if self.fail_replace.get() {
                return Err(DurableError::Storage);
            }
            *self.bytes.lock().unwrap() = Some(bytes.to_vec());
            Ok(())
        }
    }

    #[derive(Clone, Default)]
    struct MemoryAnchor {
        heads: Arc<Mutex<BTreeMap<StoreId, Anchor>>>,
        fail_compare_set: FailureFlag,
    }

    impl GenerationAnchor for MemoryAnchor {
        fn protection(&self) -> AnchorProtection {
            AnchorProtection::EphemeralTest
        }

        fn read(&self, store_id: StoreId) -> Result<Option<Anchor>, DurableError> {
            Ok(self.heads.lock().unwrap().get(&store_id).copied())
        }

        fn compare_and_set(
            &mut self,
            store_id: StoreId,
            expected: Option<Anchor>,
            next: Anchor,
        ) -> Result<(), DurableError> {
            if self.fail_compare_set.get() {
                return Err(DurableError::AnchorUnavailable);
            }
            let mut heads = self.heads.lock().unwrap();
            if heads.get(&store_id).copied() != expected {
                return Err(DurableError::AnchorConflict);
            }
            heads.insert(store_id, next);
            Ok(())
        }
    }

    fn binding() -> SnapshotBinding {
        SnapshotBinding::new(StoreId::new([1; 16]), b"gate-1")
    }

    fn key() -> StorageMacKey {
        StorageMacKey::new([7; 32])
    }

    fn gate_id() -> GateId {
        GateId::new("gate-1").unwrap()
    }

    fn revision(value: u64) -> DeploymentRevision {
        DeploymentRevision::new(NonZeroU64::new(value).unwrap())
    }

    fn package_digest(value: u8) -> DeploymentPayloadDigestV1 {
        DeploymentPayloadDigestV1::compute(&[value])
    }

    fn provision(
        storage: MemoryStorage,
        anchor: MemoryAnchor,
    ) -> DurableAntiRollbackStore<MemoryStorage, MemoryAnchor> {
        DurableAntiRollbackStore::provision_new(storage, anchor, key(), binding(), 4096).unwrap()
    }

    #[test]
    fn term_and_boot_survive_reopen_and_rewind_is_rejected() {
        let storage = MemoryStorage::default();
        let anchor = MemoryAnchor::default();
        let mut store = provision(storage.clone(), anchor.clone());
        assert_eq!(store.anchor_protection(), AnchorProtection::EphemeralTest);
        store.accept_term(b"lease", 4).unwrap();
        let (booted, _) = store.begin_boot(&gate_id(), [1; 32]).unwrap();
        assert_eq!(booted.anchor_protection(), AnchorProtection::EphemeralTest);
        let boot = booted.boot_context();
        assert_eq!(boot.boot_counter, 1);
        drop(booted);

        let (mut reopened, recovery) =
            DurableAntiRollbackStore::open_existing(storage, anchor, key(), binding(), 4096)
                .unwrap();
        assert_eq!(recovery, RecoveryStatus::Clean);
        assert_eq!(reopened.highest_term(b"lease"), 4);
        assert_eq!(reopened.boot_counter(), 1);
        assert_eq!(reopened.last_gate_boot_id(), Some(boot.gate_boot_id));
        assert_eq!(
            reopened.accept_term(b"lease", 4),
            Err(DurableAntiRollbackError::State(AntiRollbackError::Rollback))
        );
    }

    #[test]
    fn storage_failure_never_mutates_live_high_water() {
        let storage = MemoryStorage::default();
        let anchor = MemoryAnchor::default();
        let mut store = provision(storage.clone(), anchor);
        storage.fail_replace.set(true);
        assert_eq!(
            store.accept_term(b"lease", 5),
            Err(DurableAntiRollbackError::Durable(DurableError::Storage))
        );
        assert_eq!(store.highest_term(b"lease"), 0);
    }

    #[test]
    fn anchor_failure_spends_candidate_only_during_recovery() {
        let storage = MemoryStorage::default();
        let anchor = MemoryAnchor::default();
        let mut store = provision(storage.clone(), anchor.clone());
        anchor.fail_compare_set.set(true);
        assert_eq!(
            store.accept_term(b"lease", 5),
            Err(DurableAntiRollbackError::Durable(
                DurableError::AnchorUnavailable
            ))
        );
        assert_eq!(store.highest_term(b"lease"), 0);
        anchor.fail_compare_set.set(false);
        drop(store);

        let (recovered, status) =
            DurableAntiRollbackStore::open_existing(storage, anchor, key(), binding(), 4096)
                .unwrap();
        assert_eq!(status, RecoveryStatus::CompletedPendingAnchor);
        assert_eq!(recovered.highest_term(b"lease"), 5);
    }

    #[test]
    fn begin_boot_commit_failure_does_not_mutate_live_state() {
        let storage = MemoryStorage::default();
        let anchor = MemoryAnchor::default();
        let store = provision(storage.clone(), anchor.clone());
        storage.fail_replace.set(true);

        assert!(matches!(
            store.begin_boot(&gate_id(), [3; 32]),
            Err(DurableAntiRollbackError::Durable(DurableError::Storage))
        ));
        storage.fail_replace.set(false);
        let (reopened, status) =
            DurableAntiRollbackStore::open_existing(storage, anchor, key(), binding(), 4096)
                .unwrap();
        assert_eq!(status, RecoveryStatus::Clean);
        assert_eq!(reopened.boot_counter(), 0);
        assert_eq!(reopened.last_gate_boot_id(), None);
    }

    #[test]
    fn begin_boot_rejects_a_gate_outside_the_authenticated_binding() {
        let storage = MemoryStorage::default();
        let anchor = MemoryAnchor::default();
        let store = provision(storage.clone(), anchor.clone());
        let other_gate = GateId::new("gate-2").unwrap();

        assert!(matches!(
            store.begin_boot(&other_gate, [3; 32]),
            Err(DurableAntiRollbackError::GateBindingMismatch)
        ));
        let (reopened, status) =
            DurableAntiRollbackStore::open_existing(storage, anchor, key(), binding(), 4096)
                .unwrap();
        assert_eq!(status, RecoveryStatus::Clean);
        assert_eq!(reopened.boot_counter(), 0);
        assert_eq!(reopened.last_gate_boot_id(), None);
    }

    #[test]
    fn begin_boot_reopen_advances_counter_and_retains_last_boot_id() {
        let storage = MemoryStorage::default();
        let anchor = MemoryAnchor::default();
        let store = provision(storage.clone(), anchor.clone());
        let (first_booted, _) = store.begin_boot(&gate_id(), [1; 32]).unwrap();
        let first = first_booted.boot_context();
        drop(first_booted);

        let (reopened, recovery) = DurableAntiRollbackStore::open_existing(
            storage.clone(),
            anchor.clone(),
            key(),
            binding(),
            4096,
        )
        .unwrap();
        assert_eq!(recovery, RecoveryStatus::Clean);
        let (second_booted, _) = reopened.begin_boot(&gate_id(), [2; 32]).unwrap();
        let second = second_booted.boot_context();
        assert!(second.boot_counter > first.boot_counter);
        assert_ne!(second.gate_boot_id, first.gate_boot_id);
        drop(second_booted);

        let (reopened_again, _) =
            DurableAntiRollbackStore::open_existing(storage, anchor, key(), binding(), 4096)
                .unwrap();
        assert_eq!(reopened_again.boot_counter(), second.boot_counter);
        assert_eq!(
            reopened_again.last_gate_boot_id(),
            Some(second.gate_boot_id)
        );
        assert!(reopened_again.is_bound_to_gate(&gate_id()));
        assert!(!reopened_again.is_bound_to_gate(&GateId::new("gate-2").unwrap()));
    }

    #[test]
    fn deployment_boot_returns_capability_only_after_atomic_commit() {
        let storage = MemoryStorage::default();
        let anchor = MemoryAnchor::default();
        let store = provision(storage.clone(), anchor.clone());

        let (mut booted, _) = store
            .begin_deployment_boot(&gate_id(), [4; 32], revision(7), package_digest(8))
            .unwrap();

        assert_eq!(booted.boot_context().boot_counter, 1);
        assert_eq!(
            booted.deployment_package_binding(),
            &DeploymentPackageBinding::new(revision(7), package_digest(8))
        );
        assert_eq!(booted.anchor_protection(), AnchorProtection::EphemeralTest);
        assert!(booted.is_bound_to_gate(&gate_id()));
        LeaseTermStore::commit_term(&mut booted, b"lease", 3).unwrap();
        assert_eq!(LeaseTermStore::highest_term(&booted, b"lease"), 3);
        booted.accept_revocation_epoch(b"authority", 2).unwrap();
        let (_storage, _anchor) = booted.into_parts();
    }

    #[test]
    fn deployment_binding_and_boot_survive_reopen() {
        let storage = MemoryStorage::default();
        let anchor = MemoryAnchor::default();
        let store = provision(storage.clone(), anchor.clone());
        let (booted, _) = store
            .begin_deployment_boot(&gate_id(), [4; 32], revision(7), package_digest(8))
            .unwrap();
        let boot = booted.boot_context();
        drop(booted);

        let (reopened, recovery) =
            DurableAntiRollbackStore::open_existing(storage, anchor, key(), binding(), 4096)
                .unwrap();

        assert_eq!(recovery, RecoveryStatus::Clean);
        assert_eq!(reopened.boot_counter(), boot.boot_counter);
        assert_eq!(reopened.last_gate_boot_id(), Some(boot.gate_boot_id));
        assert_eq!(
            reopened.deployment_package_binding(),
            Some(&DeploymentPackageBinding::new(
                revision(7),
                package_digest(8)
            ))
        );
        assert!(!reopened.deployment_package_migration_required());
    }

    #[test]
    fn same_package_reopen_advances_boot_idempotently() {
        let storage = MemoryStorage::default();
        let anchor = MemoryAnchor::default();
        let store = provision(storage.clone(), anchor.clone());
        let (first_booted, _) = store
            .begin_deployment_boot(&gate_id(), [4; 32], revision(7), package_digest(8))
            .unwrap();
        let first = first_booted.boot_context();
        drop(first_booted);
        let (reopened, _) = DurableAntiRollbackStore::open_existing(
            storage.clone(),
            anchor.clone(),
            key(),
            binding(),
            4096,
        )
        .unwrap();

        let (second_booted, _) = reopened
            .begin_deployment_boot(&gate_id(), [5; 32], revision(7), package_digest(8))
            .unwrap();
        let second = second_booted.boot_context();
        drop(second_booted);

        assert_eq!(second.boot_counter, first.boot_counter + 1);
        assert_ne!(second.gate_boot_id, first.gate_boot_id);
        let (reopened_again, _) =
            DurableAntiRollbackStore::open_existing(storage, anchor, key(), binding(), 4096)
                .unwrap();
        assert_eq!(reopened_again.boot_counter(), second.boot_counter);
        assert_eq!(
            reopened_again.deployment_package_binding(),
            Some(&DeploymentPackageBinding::new(
                revision(7),
                package_digest(8)
            ))
        );
    }

    #[test]
    fn deployment_rollback_rejection_preserves_committed_binding() {
        let storage = MemoryStorage::default();
        let anchor = MemoryAnchor::default();
        let store = provision(storage.clone(), anchor.clone());
        let (booted, _) = store
            .begin_deployment_boot(&gate_id(), [4; 32], revision(7), package_digest(8))
            .unwrap();
        drop(booted);
        let (reopened, _) = DurableAntiRollbackStore::open_existing(
            storage.clone(),
            anchor.clone(),
            key(),
            binding(),
            4096,
        )
        .unwrap();

        assert!(matches!(
            reopened.begin_deployment_boot(&gate_id(), [5; 32], revision(6), package_digest(8),),
            Err(DurableAntiRollbackError::State(
                AntiRollbackError::PackageRollback
            ))
        ));
        let (reopened_again, _) =
            DurableAntiRollbackStore::open_existing(storage, anchor, key(), binding(), 4096)
                .unwrap();
        assert_eq!(
            reopened_again.deployment_package_binding(),
            Some(&DeploymentPackageBinding::new(
                revision(7),
                package_digest(8)
            ))
        );
    }

    #[test]
    fn deployment_equivocation_rejection_preserves_committed_binding() {
        let storage = MemoryStorage::default();
        let anchor = MemoryAnchor::default();
        let store = provision(storage.clone(), anchor.clone());
        let (booted, _) = store
            .begin_deployment_boot(&gate_id(), [4; 32], revision(7), package_digest(8))
            .unwrap();
        drop(booted);
        let (reopened, _) = DurableAntiRollbackStore::open_existing(
            storage.clone(),
            anchor.clone(),
            key(),
            binding(),
            4096,
        )
        .unwrap();

        assert!(matches!(
            reopened.begin_deployment_boot(&gate_id(), [5; 32], revision(7), package_digest(9),),
            Err(DurableAntiRollbackError::State(
                AntiRollbackError::PackageEquivocation
            ))
        ));
        let (reopened_again, _) =
            DurableAntiRollbackStore::open_existing(storage, anchor, key(), binding(), 4096)
                .unwrap();
        assert_eq!(reopened_again.boot_counter(), 1);
        assert_eq!(
            reopened_again.deployment_package_binding(),
            Some(&DeploymentPackageBinding::new(
                revision(7),
                package_digest(8)
            ))
        );
    }

    #[test]
    fn higher_deployment_revision_commits_binding_and_boot_together() {
        let storage = MemoryStorage::default();
        let anchor = MemoryAnchor::default();
        let store = provision(storage.clone(), anchor.clone());
        let (booted, _) = store
            .begin_deployment_boot(&gate_id(), [4; 32], revision(7), package_digest(8))
            .unwrap();
        drop(booted);
        let (reopened, _) = DurableAntiRollbackStore::open_existing(
            storage.clone(),
            anchor.clone(),
            key(),
            binding(),
            4096,
        )
        .unwrap();
        let (advanced, _) = reopened
            .begin_deployment_boot(&gate_id(), [5; 32], revision(8), package_digest(9))
            .unwrap();
        let advanced_boot = advanced.boot_context();
        drop(advanced);

        let (reopened_again, _) =
            DurableAntiRollbackStore::open_existing(storage, anchor, key(), binding(), 4096)
                .unwrap();

        assert_eq!(reopened_again.boot_counter(), advanced_boot.boot_counter);
        assert_eq!(
            reopened_again.deployment_package_binding(),
            Some(&DeploymentPackageBinding::new(
                revision(8),
                package_digest(9)
            ))
        );
    }

    #[test]
    fn deployment_boot_storage_failure_commits_neither_binding_nor_boot() {
        let storage = MemoryStorage::default();
        let anchor = MemoryAnchor::default();
        let store = provision(storage.clone(), anchor.clone());
        storage.fail_replace.set(true);

        assert!(matches!(
            store.begin_deployment_boot(&gate_id(), [4; 32], revision(7), package_digest(8),),
            Err(DurableAntiRollbackError::Durable(DurableError::Storage))
        ));
        storage.fail_replace.set(false);
        let (reopened, recovery) =
            DurableAntiRollbackStore::open_existing(storage, anchor, key(), binding(), 4096)
                .unwrap();
        assert_eq!(recovery, RecoveryStatus::Clean);
        assert_eq!(reopened.boot_counter(), 0);
        assert_eq!(reopened.deployment_package_binding(), None);
        assert!(!reopened.deployment_package_migration_required());
    }

    #[test]
    fn deployment_boot_anchor_failure_is_recovered_as_one_candidate() {
        let storage = MemoryStorage::default();
        let anchor = MemoryAnchor::default();
        let store = provision(storage.clone(), anchor.clone());
        anchor.fail_compare_set.set(true);

        assert!(matches!(
            store.begin_deployment_boot(&gate_id(), [4; 32], revision(7), package_digest(8),),
            Err(DurableAntiRollbackError::Durable(
                DurableError::AnchorUnavailable
            ))
        ));
        anchor.fail_compare_set.set(false);
        let (recovered, recovery) =
            DurableAntiRollbackStore::open_existing(storage, anchor, key(), binding(), 4096)
                .unwrap();

        assert_eq!(recovery, RecoveryStatus::CompletedPendingAnchor);
        assert_eq!(recovered.boot_counter(), 1);
        assert_eq!(
            recovered.deployment_package_binding(),
            Some(&DeploymentPackageBinding::new(
                revision(7),
                package_digest(8)
            ))
        );
    }

    #[test]
    fn plain_boot_after_package_binding_requires_package_context() {
        let storage = MemoryStorage::default();
        let anchor = MemoryAnchor::default();
        let store = provision(storage.clone(), anchor.clone());
        let (booted, _) = store
            .begin_deployment_boot(&gate_id(), [4; 32], revision(7), package_digest(8))
            .unwrap();
        drop(booted);
        let (reopened, _) =
            DurableAntiRollbackStore::open_existing(storage, anchor, key(), binding(), 4096)
                .unwrap();

        assert!(matches!(
            reopened.begin_boot(&gate_id(), [5; 32]),
            Err(DurableAntiRollbackError::State(
                AntiRollbackError::PackageBindingRequired
            ))
        ));
    }

    #[test]
    fn plain_boot_on_fresh_v3_store_preserves_dev_flow_but_blocks_auto_binding() {
        let storage = MemoryStorage::default();
        let anchor = MemoryAnchor::default();
        let store = provision(storage.clone(), anchor.clone());
        let (booted, _) = store.begin_boot(&gate_id(), [4; 32]).unwrap();
        drop(booted);
        let (reopened, _) = DurableAntiRollbackStore::open_existing(
            storage.clone(),
            anchor.clone(),
            key(),
            binding(),
            4096,
        )
        .unwrap();

        assert!(reopened.deployment_package_migration_required());
        assert!(matches!(
            reopened.begin_deployment_boot(&gate_id(), [5; 32], revision(1), package_digest(1),),
            Err(DurableAntiRollbackError::State(
                AntiRollbackError::MigrationRequired
            ))
        ));
        let (reopened_again, _) =
            DurableAntiRollbackStore::open_existing(storage, anchor, key(), binding(), 4096)
                .unwrap();
        let (second_dev_boot, _) = reopened_again.begin_boot(&gate_id(), [6; 32]).unwrap();
        assert_eq!(second_dev_boot.boot_context().boot_counter, 2);
    }

    #[test]
    fn deployment_boot_rejects_a_gate_outside_authenticated_binding() {
        let storage = MemoryStorage::default();
        let anchor = MemoryAnchor::default();
        let store = provision(storage.clone(), anchor.clone());
        let other_gate = GateId::new("gate-2").unwrap();

        assert!(matches!(
            store.begin_deployment_boot(&other_gate, [4; 32], revision(7), package_digest(8),),
            Err(DurableAntiRollbackError::GateBindingMismatch)
        ));
        let (reopened, _) =
            DurableAntiRollbackStore::open_existing(storage, anchor, key(), binding(), 4096)
                .unwrap();
        assert_eq!(reopened.boot_counter(), 0);
        assert_eq!(reopened.deployment_package_binding(), None);
    }
}
