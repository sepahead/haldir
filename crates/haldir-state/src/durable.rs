//! Durable anti-rollback state composed over `haldir-durable` primitives.

use crate::{AntiRollbackError, AntiRollbackStore, BootContext};
use haldir_contracts::ids::{GateBootId, GateId};
use haldir_durable::{
    AuthenticatedSnapshotStore, CommitReceipt, DurableError, GenerationAnchor, RecoveryStatus,
    SnapshotBinding, SnapshotStorage, StorageMacKey,
};

/// A semantic or durable-storage failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DurableAntiRollbackError {
    /// The semantic high-water update was invalid.
    State(AntiRollbackError),
    /// The authenticated snapshot or external anchor failed.
    Durable(DurableError),
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
    /// Returns on counter exhaustion, a derived boot-ID repeat, or durable commit
    /// failure. The live state is replaced only after commit succeeds.
    pub fn begin_boot(
        &mut self,
        gate_id: &GateId,
        entropy: [u8; 32],
    ) -> Result<(BootContext, CommitReceipt), DurableAntiRollbackError> {
        let (candidate, context) = self.state.candidate_for_boot(gate_id, entropy)?;
        let receipt = self.snapshots.commit(&candidate.to_bytes())?;
        self.state = candidate;
        Ok((context, receipt))
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
        store.accept_term(b"lease", 4).unwrap();
        let (boot, _) = store.begin_boot(&gate_id(), [1; 32]).unwrap();
        assert_eq!(boot.boot_counter, 1);
        drop(store);

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
        let mut store = provision(storage.clone(), anchor);
        storage.fail_replace.set(true);

        assert_eq!(
            store.begin_boot(&gate_id(), [3; 32]),
            Err(DurableAntiRollbackError::Durable(DurableError::Storage))
        );
        assert_eq!(store.boot_counter(), 0);
        assert_eq!(store.last_gate_boot_id(), None);
    }

    #[test]
    fn begin_boot_reopen_advances_counter_and_retains_last_boot_id() {
        let storage = MemoryStorage::default();
        let anchor = MemoryAnchor::default();
        let mut store = provision(storage.clone(), anchor.clone());
        let (first, _) = store.begin_boot(&gate_id(), [1; 32]).unwrap();
        drop(store);

        let (mut reopened, recovery) = DurableAntiRollbackStore::open_existing(
            storage.clone(),
            anchor.clone(),
            key(),
            binding(),
            4096,
        )
        .unwrap();
        assert_eq!(recovery, RecoveryStatus::Clean);
        let (second, _) = reopened.begin_boot(&gate_id(), [2; 32]).unwrap();
        assert!(second.boot_counter > first.boot_counter);
        assert_ne!(second.gate_boot_id, first.gate_boot_id);
        drop(reopened);

        let (reopened_again, _) =
            DurableAntiRollbackStore::open_existing(storage, anchor, key(), binding(), 4096)
                .unwrap();
        assert_eq!(reopened_again.boot_counter(), second.boot_counter);
        assert_eq!(
            reopened_again.last_gate_boot_id(),
            Some(second.gate_boot_id)
        );
    }
}
