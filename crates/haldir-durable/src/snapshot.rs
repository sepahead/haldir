//! Authenticated snapshot envelopes and external-anchor reconciliation.
//!
//! This module deliberately abstracts atomic storage and the generation anchor.
//! A backend must not claim durability until it proves its replace/sync contract;
//! an anchor in the same rewritable failure domain cannot prove anti-rewind.

use crate::error::DurableError;
use crate::mac::StorageMacKey;
use sha2::{Digest, Sha256};

const MAGIC: &[u8; 8] = b"HLDRDUR1";
const FORMAT_VERSION: u16 = 1;
const HEADER_LEN: usize = 134;
const TAG_LEN: usize = 32;
const ZERO_DIGEST: [u8; 32] = [0; 32];
const SNAPSHOT_DIGEST_DOMAIN: &[u8] = b"haldir.durable.snapshot-digest.v1\0";

/// Stable identifier for one logical durable store.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StoreId([u8; 16]);

impl StoreId {
    /// Construct from a provisioned 128-bit identifier.
    #[must_use]
    pub const fn new(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }
}

/// Store and Gate binding committed by every snapshot envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotBinding {
    store_id: StoreId,
    gate_id_digest: [u8; 32],
}

impl SnapshotBinding {
    /// Bind a store to a Gate identifier without storing the identifier itself.
    #[must_use]
    pub fn new(store_id: StoreId, gate_id: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"haldir.durable.gate-id.v1\0");
        hasher.update(gate_id);
        Self {
            store_id,
            gate_id_digest: hasher.finalize().into(),
        }
    }

    /// The logical store id.
    #[must_use]
    pub const fn store_id(self) -> StoreId {
        self.store_id
    }
}

/// Externally anchored snapshot head.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Anchor {
    /// Monotonic snapshot generation.
    pub generation: u64,
    /// Digest of the complete authenticated snapshot envelope.
    pub snapshot_digest: [u8; 32],
}

/// Backend contract for the authenticated snapshot bytes.
pub trait SnapshotStorage {
    /// Load the current complete envelope, or `None` when unprovisioned.
    fn load(&self) -> Result<Option<Vec<u8>>, DurableError>;

    /// Atomically replace the committed envelope under an exclusive-writer lock.
    ///
    /// A real backend must make this old-or-new across its declared crash model
    /// and complete required file/directory syncs before returning success.
    fn replace(&mut self, bytes: &[u8]) -> Result<(), DurableError>;
}

/// Monotonic anchor outside the snapshot storage's rewritable failure domain.
pub trait GenerationAnchor {
    /// Read the externally witnessed head for `store_id`.
    fn read(&self, store_id: StoreId) -> Result<Option<Anchor>, DurableError>;

    /// Compare-and-set the head. A mismatch must return
    /// [`DurableError::AnchorConflict`].
    fn compare_and_set(
        &mut self,
        store_id: StoreId,
        expected: Option<Anchor>,
        next: Anchor,
    ) -> Result<(), DurableError>;
}

/// Result of opening an existing store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryStatus {
    /// Snapshot and external anchor already agreed.
    Clean,
    /// A crash left a valid next snapshot installed; opening completed the
    /// pending external-anchor advance.
    CompletedPendingAnchor,
}

/// Authenticated snapshot content returned to its semantic owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedSnapshot {
    generation: u64,
    previous_snapshot_digest: [u8; 32],
    snapshot_digest: [u8; 32],
    payload: Vec<u8>,
}

impl LoadedSnapshot {
    /// Monotonic generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Digest externally anchored for this envelope.
    #[must_use]
    pub const fn snapshot_digest(&self) -> [u8; 32] {
        self.snapshot_digest
    }

    /// Authenticated semantic payload bytes.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

/// Successful durable snapshot commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommitReceipt {
    /// Committed generation.
    pub generation: u64,
    /// Externally anchored envelope digest.
    pub snapshot_digest: [u8; 32],
}

/// An opened authenticated store.
pub struct AuthenticatedSnapshotStore<S, A> {
    storage: S,
    anchor: A,
    key: StorageMacKey,
    binding: SnapshotBinding,
    max_payload_bytes: usize,
    current: LoadedSnapshot,
}

impl<S: SnapshotStorage, A: GenerationAnchor> AuthenticatedSnapshotStore<S, A> {
    /// Explicitly provision a new store. Missing state is never implicitly
    /// treated as a fresh store by [`Self::open_existing`].
    ///
    /// # Errors
    /// Returns [`DurableError::AlreadyProvisioned`] if either backend is nonempty,
    /// or a backend/authentication error if the initial commit fails.
    pub fn provision_new(
        mut storage: S,
        mut anchor: A,
        key: StorageMacKey,
        binding: SnapshotBinding,
        max_payload_bytes: usize,
        payload: &[u8],
    ) -> Result<Self, DurableError> {
        if storage.load()?.is_some() || anchor.read(binding.store_id)?.is_some() {
            return Err(DurableError::AlreadyProvisioned);
        }
        let bytes = seal(&key, binding, 1, ZERO_DIGEST, payload, max_payload_bytes)?;
        let loaded = open_envelope(&key, binding, &bytes, max_payload_bytes)?;
        let head = Anchor {
            generation: loaded.generation,
            snapshot_digest: loaded.snapshot_digest,
        };
        storage.replace(&bytes)?;
        anchor.compare_and_set(binding.store_id, None, head)?;
        Ok(Self {
            storage,
            anchor,
            key,
            binding,
            max_payload_bytes,
            current: loaded,
        })
    }

    /// Open and reconcile an existing authenticated snapshot.
    ///
    /// # Errors
    /// Missing/corrupt/authentication/rewind/fork/gap states fail closed. Only a
    /// valid exactly-next snapshot may complete a pending anchor advance.
    pub fn open_existing(
        storage: S,
        mut anchor: A,
        key: StorageMacKey,
        binding: SnapshotBinding,
        max_payload_bytes: usize,
    ) -> Result<(Self, RecoveryStatus), DurableError> {
        let bytes = storage.load()?.ok_or(DurableError::Missing)?;
        let loaded = open_envelope(&key, binding, &bytes, max_payload_bytes)?;
        let snapshot_head = Anchor {
            generation: loaded.generation,
            snapshot_digest: loaded.snapshot_digest,
        };
        let anchored = anchor
            .read(binding.store_id)?
            .ok_or(DurableError::AnchorMissing)?;

        let status = if anchored == snapshot_head {
            RecoveryStatus::Clean
        } else if loaded.generation < anchored.generation {
            return Err(DurableError::Rewind);
        } else if loaded.generation == anchored.generation {
            return Err(DurableError::Fork);
        } else {
            let expected_generation = anchored
                .generation
                .checked_add(1)
                .ok_or(DurableError::Exhausted)?;
            if loaded.generation > expected_generation {
                return Err(DurableError::GenerationGap);
            }
            if loaded.previous_snapshot_digest != anchored.snapshot_digest {
                return Err(DurableError::Fork);
            }
            anchor.compare_and_set(binding.store_id, Some(anchored), snapshot_head)?;
            RecoveryStatus::CompletedPendingAnchor
        };

        Ok((
            Self {
                storage,
                anchor,
                key,
                binding,
                max_payload_bytes,
                current: loaded,
            },
            status,
        ))
    }

    /// The currently committed authenticated state.
    #[must_use]
    pub const fn current(&self) -> &LoadedSnapshot {
        &self.current
    }

    /// Install the next authenticated snapshot, then advance the external anchor.
    /// The returned receipt is the commit boundary; callers must not expose the
    /// candidate semantic authority before this succeeds.
    ///
    /// # Errors
    /// Returns on generation exhaustion, storage failure, or anchor failure.
    pub fn commit(&mut self, payload: &[u8]) -> Result<CommitReceipt, DurableError> {
        let generation = self
            .current
            .generation
            .checked_add(1)
            .ok_or(DurableError::Exhausted)?;
        let bytes = seal(
            &self.key,
            self.binding,
            generation,
            self.current.snapshot_digest,
            payload,
            self.max_payload_bytes,
        )?;
        let next = open_envelope(&self.key, self.binding, &bytes, self.max_payload_bytes)?;
        let previous_head = Anchor {
            generation: self.current.generation,
            snapshot_digest: self.current.snapshot_digest,
        };
        let next_head = Anchor {
            generation: next.generation,
            snapshot_digest: next.snapshot_digest,
        };
        self.storage.replace(&bytes)?;
        self.anchor
            .compare_and_set(self.binding.store_id, Some(previous_head), next_head)?;
        self.current = next;
        Ok(CommitReceipt {
            generation,
            snapshot_digest: next_head.snapshot_digest,
        })
    }

    /// Return owned backends for controlled recovery/testing.
    #[must_use]
    pub fn into_parts(self) -> (S, A) {
        (self.storage, self.anchor)
    }
}

fn seal(
    key: &StorageMacKey,
    binding: SnapshotBinding,
    generation: u64,
    previous_snapshot_digest: [u8; 32],
    payload: &[u8],
    max_payload_bytes: usize,
) -> Result<Vec<u8>, DurableError> {
    if payload.len() > max_payload_bytes {
        return Err(DurableError::Storage);
    }
    let payload_len = u32::try_from(payload.len()).map_err(|_| DurableError::Storage)?;
    let payload_digest: [u8; 32] = Sha256::digest(payload).into();
    let mut bytes = Vec::with_capacity(HEADER_LEN + payload.len() + TAG_LEN);
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
    bytes.extend_from_slice(&binding.store_id.0);
    bytes.extend_from_slice(&binding.gate_id_digest);
    bytes.extend_from_slice(&generation.to_be_bytes());
    bytes.extend_from_slice(&previous_snapshot_digest);
    bytes.extend_from_slice(&payload_len.to_be_bytes());
    bytes.extend_from_slice(&payload_digest);
    bytes.extend_from_slice(payload);
    let tag = key.tag(&bytes)?;
    bytes.extend_from_slice(&tag);
    Ok(bytes)
}

fn open_envelope(
    key: &StorageMacKey,
    binding: SnapshotBinding,
    bytes: &[u8],
    max_payload_bytes: usize,
) -> Result<LoadedSnapshot, DurableError> {
    if bytes.len() < HEADER_LEN + TAG_LEN {
        return Err(DurableError::Corrupt);
    }
    let mut cursor = Cursor::new(bytes);
    if cursor.take(8)? != MAGIC || cursor.u16()? != FORMAT_VERSION {
        return Err(DurableError::Corrupt);
    }
    if cursor.array::<16>()? != binding.store_id.0
        || cursor.array::<32>()? != binding.gate_id_digest
    {
        return Err(DurableError::AuthenticationFailed);
    }
    let generation = cursor.u64()?;
    if generation == 0 {
        return Err(DurableError::Corrupt);
    }
    let previous_snapshot_digest = cursor.array::<32>()?;
    let payload_len = usize::try_from(cursor.u32()?).map_err(|_| DurableError::Corrupt)?;
    if payload_len > max_payload_bytes {
        return Err(DurableError::Corrupt);
    }
    let expected_payload_digest = cursor.array::<32>()?;
    if cursor.position != HEADER_LEN {
        return Err(DurableError::Corrupt);
    }
    let expected_total = HEADER_LEN
        .checked_add(payload_len)
        .and_then(|value| value.checked_add(TAG_LEN))
        .ok_or(DurableError::Corrupt)?;
    if bytes.len() != expected_total {
        return Err(DurableError::Corrupt);
    }
    let payload = cursor.take(payload_len)?.to_vec();
    let tag = cursor.take(TAG_LEN)?;
    let authenticated = bytes
        .get(..HEADER_LEN + payload_len)
        .ok_or(DurableError::Corrupt)?;
    key.verify(authenticated, tag)?;
    if <[u8; 32]>::from(Sha256::digest(&payload)) != expected_payload_digest {
        return Err(DurableError::Corrupt);
    }
    let mut hasher = Sha256::new();
    hasher.update(SNAPSHOT_DIGEST_DOMAIN);
    hasher.update(bytes);
    Ok(LoadedSnapshot {
        generation,
        previous_snapshot_digest,
        snapshot_digest: hasher.finalize().into(),
        payload,
    })
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], DurableError> {
        let end = self
            .position
            .checked_add(len)
            .ok_or(DurableError::Corrupt)?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(DurableError::Corrupt)?;
        self.position = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], DurableError> {
        self.take(N)?.try_into().map_err(|_| DurableError::Corrupt)
    }

    fn u16(&mut self) -> Result<u16, DurableError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, DurableError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, DurableError> {
        Ok(u64::from_be_bytes(self.array()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::rc::Rc;

    #[derive(Clone, Default)]
    struct MemoryStorage(Rc<RefCell<Option<Vec<u8>>>>);

    impl SnapshotStorage for MemoryStorage {
        fn load(&self) -> Result<Option<Vec<u8>>, DurableError> {
            Ok(self.0.borrow().clone())
        }

        fn replace(&mut self, bytes: &[u8]) -> Result<(), DurableError> {
            *self.0.borrow_mut() = Some(bytes.to_vec());
            Ok(())
        }
    }

    #[derive(Clone, Default)]
    struct MemoryAnchor(Rc<RefCell<BTreeMap<StoreId, Anchor>>>);

    impl GenerationAnchor for MemoryAnchor {
        fn read(&self, store_id: StoreId) -> Result<Option<Anchor>, DurableError> {
            Ok(self.0.borrow().get(&store_id).copied())
        }

        fn compare_and_set(
            &mut self,
            store_id: StoreId,
            expected: Option<Anchor>,
            next: Anchor,
        ) -> Result<(), DurableError> {
            if self.0.borrow().get(&store_id).copied() != expected {
                return Err(DurableError::AnchorConflict);
            }
            self.0.borrow_mut().insert(store_id, next);
            Ok(())
        }
    }

    fn binding(seed: u8) -> SnapshotBinding {
        SnapshotBinding::new(StoreId::new([seed; 16]), b"gate-1")
    }

    fn key(seed: u8) -> StorageMacKey {
        StorageMacKey::new([seed; 32])
    }

    fn provision(
        storage: MemoryStorage,
        anchor: MemoryAnchor,
    ) -> AuthenticatedSnapshotStore<MemoryStorage, MemoryAnchor> {
        AuthenticatedSnapshotStore::provision_new(storage, anchor, key(7), binding(1), 1024, b"one")
            .unwrap()
    }

    #[test]
    fn missing_is_not_implicit_provisioning() {
        assert!(matches!(
            AuthenticatedSnapshotStore::open_existing(
                MemoryStorage::default(),
                MemoryAnchor::default(),
                key(7),
                binding(1),
                1024,
            ),
            Err(DurableError::Missing)
        ));
    }

    #[test]
    fn missing_anchor_is_not_recreated_from_rewritable_storage() {
        let storage = MemoryStorage::default();
        let anchor = MemoryAnchor::default();
        drop(provision(storage.clone(), anchor.clone()));
        anchor.0.borrow_mut().clear();

        assert!(matches!(
            AuthenticatedSnapshotStore::open_existing(storage, anchor, key(7), binding(1), 1024,),
            Err(DurableError::AnchorMissing)
        ));
    }

    #[test]
    fn provisioning_never_overwrites_existing_state() {
        let storage = MemoryStorage::default();
        let anchor = MemoryAnchor::default();
        drop(provision(storage.clone(), anchor.clone()));

        assert!(matches!(
            AuthenticatedSnapshotStore::provision_new(
                storage,
                anchor,
                key(7),
                binding(1),
                1024,
                b"replacement",
            ),
            Err(DurableError::AlreadyProvisioned)
        ));
    }

    #[test]
    fn provision_commit_and_clean_reopen() {
        let storage = MemoryStorage::default();
        let anchor = MemoryAnchor::default();
        let mut store = provision(storage.clone(), anchor.clone());
        let receipt = store.commit(b"two").unwrap();
        assert_eq!(receipt.generation, 2);
        assert_eq!(store.current().payload(), b"two");
        drop(store);

        let (reopened, status) =
            AuthenticatedSnapshotStore::open_existing(storage, anchor, key(7), binding(1), 1024)
                .unwrap();
        assert_eq!(status, RecoveryStatus::Clean);
        assert_eq!(reopened.current().generation(), 2);
        assert_eq!(reopened.current().payload(), b"two");
    }

    #[test]
    fn wrong_key_binding_and_bit_flip_fail_authentication() {
        let storage = MemoryStorage::default();
        let anchor = MemoryAnchor::default();
        drop(provision(storage.clone(), anchor.clone()));

        assert!(matches!(
            AuthenticatedSnapshotStore::open_existing(
                storage.clone(),
                anchor.clone(),
                key(8),
                binding(1),
                1024,
            ),
            Err(DurableError::AuthenticationFailed)
        ));
        assert!(matches!(
            AuthenticatedSnapshotStore::open_existing(
                storage.clone(),
                anchor.clone(),
                key(7),
                binding(2),
                1024,
            ),
            Err(DurableError::AuthenticationFailed)
        ));

        let mut bytes = storage.load().unwrap().unwrap();
        let index = HEADER_LEN + 1;
        let byte = bytes.get_mut(index).unwrap();
        *byte ^= 1;
        *storage.0.borrow_mut() = Some(bytes);
        assert!(matches!(
            AuthenticatedSnapshotStore::open_existing(storage, anchor, key(7), binding(1), 1024,),
            Err(DurableError::AuthenticationFailed)
        ));
    }

    #[test]
    fn valid_next_snapshot_completes_pending_anchor_advance() {
        let storage = MemoryStorage::default();
        let anchor = MemoryAnchor::default();
        let store = provision(storage.clone(), anchor.clone());
        let current = store.current().clone();
        drop(store);
        let next_bytes = seal(
            &key(7),
            binding(1),
            2,
            current.snapshot_digest(),
            b"pending",
            1024,
        )
        .unwrap();
        *storage.0.borrow_mut() = Some(next_bytes);

        let (recovered, status) =
            AuthenticatedSnapshotStore::open_existing(storage, anchor, key(7), binding(1), 1024)
                .unwrap();
        assert_eq!(status, RecoveryStatus::CompletedPendingAnchor);
        assert_eq!(recovered.current().payload(), b"pending");
    }

    #[test]
    fn authentic_snapshot_rewind_and_same_generation_fork_are_detected() {
        let storage = MemoryStorage::default();
        let anchor = MemoryAnchor::default();
        let mut store = provision(storage.clone(), anchor.clone());
        let old = storage.load().unwrap().unwrap();
        store.commit(b"two").unwrap();
        let anchored = anchor.read(binding(1).store_id()).unwrap().unwrap();

        *storage.0.borrow_mut() = Some(old);
        assert!(matches!(
            AuthenticatedSnapshotStore::open_existing(
                storage.clone(),
                anchor.clone(),
                key(7),
                binding(1),
                1024,
            ),
            Err(DurableError::Rewind)
        ));

        let fork = seal(
            &key(7),
            binding(1),
            anchored.generation,
            [9; 32],
            b"fork",
            1024,
        )
        .unwrap();
        *storage.0.borrow_mut() = Some(fork);
        assert!(matches!(
            AuthenticatedSnapshotStore::open_existing(storage, anchor, key(7), binding(1), 1024,),
            Err(DurableError::Fork)
        ));
    }

    #[test]
    fn generation_gap_is_rejected() {
        let storage = MemoryStorage::default();
        let anchor = MemoryAnchor::default();
        let store = provision(storage.clone(), anchor.clone());
        let current = store.current().clone();
        drop(store);
        let gap = seal(
            &key(7),
            binding(1),
            3,
            current.snapshot_digest(),
            b"gap",
            1024,
        )
        .unwrap();
        *storage.0.borrow_mut() = Some(gap);
        assert!(matches!(
            AuthenticatedSnapshotStore::open_existing(storage, anchor, key(7), binding(1), 1024,),
            Err(DurableError::GenerationGap)
        ));
    }
}
