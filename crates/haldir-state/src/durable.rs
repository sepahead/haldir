//! Durable anti-rollback state composed over `haldir-durable` primitives.

use crate::mission::{LeaseTermStore, LeaseTermStoreError};
use crate::{AntiRollbackError, AntiRollbackStore, BootContext};
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

#[cfg(test)]
mod tests {
    use super::*;
    use haldir_durable::{Anchor, StoreId};
    use std::cell::{Cell, RefCell};
    use std::collections::BTreeMap;
    use std::rc::Rc;

    #[derive(Clone, Default)]
    struct MemoryStorage {
        bytes: Rc<RefCell<Option<Vec<u8>>>>,
        fail_replace: Rc<Cell<bool>>,
    }

    impl SnapshotStorage for MemoryStorage {
        fn load(&self) -> Result<Option<Vec<u8>>, DurableError> {
            Ok(self.bytes.borrow().clone())
        }

        fn replace(&mut self, bytes: &[u8]) -> Result<(), DurableError> {
            if self.fail_replace.get() {
                return Err(DurableError::Storage);
            }
            *self.bytes.borrow_mut() = Some(bytes.to_vec());
            Ok(())
        }
    }

    #[derive(Clone, Default)]
    struct MemoryAnchor {
        heads: Rc<RefCell<BTreeMap<StoreId, Anchor>>>,
        fail_compare_set: Rc<Cell<bool>>,
    }

    impl GenerationAnchor for MemoryAnchor {
        fn protection(&self) -> AnchorProtection {
            AnchorProtection::EphemeralTest
        }

        fn read(&self, store_id: StoreId) -> Result<Option<Anchor>, DurableError> {
            Ok(self.heads.borrow().get(&store_id).copied())
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
            if self.heads.borrow().get(&store_id).copied() != expected {
                return Err(DurableError::AnchorConflict);
            }
            self.heads.borrow_mut().insert(store_id, next);
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
}
