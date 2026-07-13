//! Development-only local generation anchor for process-crash reconciliation.
//!
//! [`LocalFileGenerationAnchor`] stores one checksummed anchor in an
//! [`crate::AtomicFileSnapshot`]. It is useful for exercising old-or-new local
//! recovery across ordinary Unix process crashes after provisioning has completed,
//! but it remains rewritable and normally shares the snapshot host's filesystem
//! failure domain. An attacker
//! able to restore both files can rewind both consistently. It therefore reports
//! [`AnchorProtection::LocalRewritable`] and must never satisfy a deployment
//! requirement for an externally administered non-rewindable anchor.
//!
//! The implementation assumes one exclusive writer. Its read-then-replace CAS is
//! not a cross-process locking primitive. A crash or error during the initial
//! two-backend provisioning transaction can leave one side present; that state
//! fails closed and requires explicit operator repair rather than reconstruction
//! from the other rewritable file.

use std::path::PathBuf;

use sha2::{Digest, Sha256};

use crate::{
    Anchor, AnchorProtection, AtomicFileSnapshot, DurableError, GenerationAnchor, SnapshotStorage,
    StoreId,
};

const MAGIC: &[u8; 8] = b"HLDRANC1";
const FORMAT_VERSION: u16 = 1;
const CHECKSUM_DOMAIN: &[u8] = b"haldir.durable.local-anchor-checksum.v1\0";
const PREFIX_LEN: usize = 8 + 2 + 16 + 8 + 32;
const FORMAT_LEN: usize = PREFIX_LEN + 32;

/// A single-store local file anchor for development and crash-recovery tests.
pub struct LocalFileGenerationAnchor {
    store_id: StoreId,
    storage: AtomicFileSnapshot,
}

impl LocalFileGenerationAnchor {
    /// Bind `path` permanently to one logical store identifier.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>, store_id: StoreId) -> Self {
        Self {
            store_id,
            storage: AtomicFileSnapshot::new(path, FORMAT_LEN),
        }
    }

    /// Logical store accepted by this anchor instance.
    #[must_use]
    pub const fn store_id(&self) -> StoreId {
        self.store_id
    }

    fn ensure_store(&self, store_id: StoreId) -> Result<(), DurableError> {
        if store_id == self.store_id {
            Ok(())
        } else {
            Err(DurableError::AnchorBindingMismatch)
        }
    }

    fn read_bound(&self) -> Result<Option<Anchor>, DurableError> {
        self.storage
            .load()?
            .map(|bytes| decode(self.store_id, &bytes))
            .transpose()
    }
}

impl GenerationAnchor for LocalFileGenerationAnchor {
    fn protection(&self) -> AnchorProtection {
        AnchorProtection::LocalRewritable
    }

    fn read(&self, store_id: StoreId) -> Result<Option<Anchor>, DurableError> {
        self.ensure_store(store_id)?;
        self.read_bound()
    }

    fn compare_and_set(
        &mut self,
        store_id: StoreId,
        expected: Option<Anchor>,
        next: Anchor,
    ) -> Result<(), DurableError> {
        self.ensure_store(store_id)?;
        let current = self.read_bound()?;
        if current != expected {
            return Err(DurableError::AnchorConflict);
        }

        let expected_generation = match expected {
            None => 1,
            Some(previous) => previous
                .generation
                .checked_add(1)
                .ok_or(DurableError::Exhausted)?,
        };
        if next.generation != expected_generation {
            return Err(DurableError::AnchorConflict);
        }

        self.storage.replace(&encode(store_id, next)?)
    }
}

fn encode(store_id: StoreId, anchor: Anchor) -> Result<[u8; FORMAT_LEN], DurableError> {
    let mut bytes = [0u8; FORMAT_LEN];
    let mut position = 0usize;
    copy_field(&mut bytes, &mut position, MAGIC)?;
    copy_field(&mut bytes, &mut position, &FORMAT_VERSION.to_be_bytes())?;
    copy_field(&mut bytes, &mut position, store_id.as_bytes())?;
    copy_field(&mut bytes, &mut position, &anchor.generation.to_be_bytes())?;
    copy_field(&mut bytes, &mut position, &anchor.snapshot_digest)?;
    if position != PREFIX_LEN {
        return Err(DurableError::Corrupt);
    }

    let checksum = checksum(&bytes[..PREFIX_LEN]);
    bytes[PREFIX_LEN..].copy_from_slice(&checksum);
    Ok(bytes)
}

fn decode(expected_store_id: StoreId, bytes: &[u8]) -> Result<Anchor, DurableError> {
    if bytes.len() != FORMAT_LEN {
        return Err(DurableError::Corrupt);
    }
    let prefix = bytes.get(..PREFIX_LEN).ok_or(DurableError::Corrupt)?;
    let stored_checksum = bytes.get(PREFIX_LEN..).ok_or(DurableError::Corrupt)?;
    if checksum(prefix).as_slice() != stored_checksum {
        return Err(DurableError::Corrupt);
    }

    let mut cursor = Cursor::new(prefix);
    if cursor.take(8)? != MAGIC || cursor.u16()? != FORMAT_VERSION {
        return Err(DurableError::Corrupt);
    }
    let persisted_store_id = StoreId::new(cursor.array()?);
    if persisted_store_id != expected_store_id {
        return Err(DurableError::AnchorBindingMismatch);
    }
    let generation = cursor.u64()?;
    if generation == 0 {
        return Err(DurableError::Corrupt);
    }
    let snapshot_digest = cursor.array()?;
    if cursor.position != PREFIX_LEN {
        return Err(DurableError::Corrupt);
    }
    Ok(Anchor {
        generation,
        snapshot_digest,
    })
}

fn checksum(prefix: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(CHECKSUM_DOMAIN);
    hasher.update(prefix);
    hasher.finalize().into()
}

fn copy_field<const N: usize>(
    output: &mut [u8; N],
    position: &mut usize,
    field: &[u8],
) -> Result<(), DurableError> {
    let end = position
        .checked_add(field.len())
        .ok_or(DurableError::Corrupt)?;
    let destination = output
        .get_mut(*position..end)
        .ok_or(DurableError::Corrupt)?;
    destination.copy_from_slice(field);
    *position = end;
    Ok(())
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], DurableError> {
        let end = self
            .position
            .checked_add(length)
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

    fn u64(&mut self) -> Result<u64, DurableError> {
        Ok(u64::from_be_bytes(self.array()?))
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;
    use crate::{AuthenticatedSnapshotStore, RecoveryStatus, SnapshotBinding, StorageMacKey};

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "haldir-local-anchor-test-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn store(seed: u8) -> StoreId {
        StoreId::new([seed; 16])
    }

    fn anchor(generation: u64, seed: u8) -> Anchor {
        Anchor {
            generation,
            snapshot_digest: [seed; 32],
        }
    }

    #[test]
    fn missing_file_is_an_unprovisioned_anchor() {
        let directory = TestDirectory::new();
        let local = LocalFileGenerationAnchor::new(directory.0.join("anchor"), store(1));

        assert_eq!(local.read(store(1)).unwrap(), None);
        assert_eq!(local.protection(), AnchorProtection::LocalRewritable);
    }

    #[test]
    fn compare_and_set_persists_exactly_next_generations() {
        let directory = TestDirectory::new();
        let path = directory.0.join("anchor");
        let mut local = LocalFileGenerationAnchor::new(&path, store(1));
        local.compare_and_set(store(1), None, anchor(1, 1)).unwrap();
        local
            .compare_and_set(store(1), Some(anchor(1, 1)), anchor(2, 2))
            .unwrap();

        let reopened = LocalFileGenerationAnchor::new(path, store(1));

        assert_eq!(reopened.read(store(1)).unwrap(), Some(anchor(2, 2)));
    }

    #[test]
    fn compare_and_set_conflict_or_gap_preserves_current_head() {
        let directory = TestDirectory::new();
        let path = directory.0.join("anchor");
        let mut local = LocalFileGenerationAnchor::new(&path, store(1));
        local.compare_and_set(store(1), None, anchor(1, 1)).unwrap();

        assert_eq!(
            local.compare_and_set(store(1), None, anchor(1, 9)),
            Err(DurableError::AnchorConflict)
        );
        assert_eq!(
            local.compare_and_set(store(1), Some(anchor(1, 1)), anchor(3, 3)),
            Err(DurableError::AnchorConflict)
        );
        assert_eq!(local.read(store(1)).unwrap(), Some(anchor(1, 1)));
    }

    #[test]
    fn wrong_requested_or_persisted_store_is_rejected() {
        let directory = TestDirectory::new();
        let path = directory.0.join("anchor");
        let mut first = LocalFileGenerationAnchor::new(&path, store(1));
        first.compare_and_set(store(1), None, anchor(1, 1)).unwrap();

        assert_eq!(
            first.read(store(2)),
            Err(DurableError::AnchorBindingMismatch)
        );
        let rebound = LocalFileGenerationAnchor::new(path, store(2));
        assert_eq!(
            rebound.read(store(2)),
            Err(DurableError::AnchorBindingMismatch)
        );
    }

    #[test]
    fn checksum_tampering_is_corruption_not_missing_state() {
        let directory = TestDirectory::new();
        let path = directory.0.join("anchor");
        let mut local = LocalFileGenerationAnchor::new(&path, store(1));
        local.compare_and_set(store(1), None, anchor(1, 1)).unwrap();
        let mut bytes = fs::read(&path).unwrap();
        bytes[30] ^= 1;
        fs::write(&path, bytes).unwrap();

        assert_eq!(local.read(store(1)), Err(DurableError::Corrupt));
    }

    #[test]
    fn truncated_or_oversized_state_is_never_treated_as_missing() {
        let directory = TestDirectory::new();
        let truncated_path = directory.0.join("truncated");
        fs::write(&truncated_path, [0u8; 8]).unwrap();
        let truncated = LocalFileGenerationAnchor::new(truncated_path, store(1));
        assert_eq!(truncated.read(store(1)), Err(DurableError::Corrupt));

        let oversized_path = directory.0.join("oversized");
        fs::write(&oversized_path, [0u8; FORMAT_LEN + 1]).unwrap();
        let oversized = LocalFileGenerationAnchor::new(oversized_path, store(1));
        assert_eq!(oversized.read(store(1)), Err(DurableError::Storage));
    }

    #[test]
    fn local_anchor_reconciles_an_authenticated_file_snapshot() {
        let directory = TestDirectory::new();
        let snapshot_path = directory.0.join("snapshot");
        let anchor_path = directory.0.join("anchor");
        let store_id = store(1);
        let binding = SnapshotBinding::new(store_id, b"gate-1");
        let mut snapshots = AuthenticatedSnapshotStore::provision_new(
            AtomicFileSnapshot::new(&snapshot_path, 4096),
            LocalFileGenerationAnchor::new(&anchor_path, store_id),
            StorageMacKey::new([7; 32]),
            binding,
            1024,
            b"one",
        )
        .unwrap();
        assert_eq!(
            snapshots.anchor_protection(),
            AnchorProtection::LocalRewritable
        );
        snapshots.commit(b"two").unwrap();
        drop(snapshots);

        let (reopened, recovery) = AuthenticatedSnapshotStore::open_existing(
            AtomicFileSnapshot::new(snapshot_path, 4096),
            LocalFileGenerationAnchor::new(anchor_path, store_id),
            StorageMacKey::new([7; 32]),
            binding,
            1024,
        )
        .unwrap();

        assert_eq!(recovery, RecoveryStatus::Clean);
        assert_eq!(reopened.current().payload(), b"two");
    }
}
