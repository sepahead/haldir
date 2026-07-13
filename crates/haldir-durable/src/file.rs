//! Process-crash-scoped atomic snapshot storage for Unix filesystems.

use std::path::PathBuf;

#[cfg(unix)]
use std::ffi::OsString;
#[cfg(unix)]
use std::fs::{self, File, OpenOptions};
#[cfg(unix)]
use std::io::{ErrorKind, Read, Write};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
#[cfg(unix)]
use std::path::Path;
#[cfg(unix)]
use std::sync::atomic::{AtomicU64, Ordering};

use crate::{DurableError, SnapshotStorage};

#[cfg(unix)]
const TEMP_CREATE_ATTEMPTS: usize = 128;

#[cfg(unix)]
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// A bounded snapshot file replaced through a same-directory temporary file.
///
/// On Unix, [`SnapshotStorage::replace`] writes and syncs a new file, renames it
/// over the destination, and syncs the parent directory. This provides an
/// old-or-new replacement boundary for process crashes when the destination is
/// on a local filesystem with ordinary POSIX rename semantics.
///
/// This type does not lock writers, prevent an external rollback, or promise
/// power-loss durability. Callers must provide exclusive-writer coordination
/// and an [`crate::AnchorProtection::ExternalNonRewindable`] generation anchor
/// when protection from local rewind is required.
#[derive(Debug, Clone)]
pub struct AtomicFileSnapshot {
    path: PathBuf,
    max_snapshot_bytes: usize,
}

impl AtomicFileSnapshot {
    /// Target `path` and the largest snapshot accepted by `load` or `replace`.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>, max_snapshot_bytes: usize) -> Self {
        Self {
            path: path.into(),
            max_snapshot_bytes,
        }
    }

    #[cfg(unix)]
    fn parent(&self) -> &Path {
        self.path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."))
    }

    #[cfg(unix)]
    fn open_parent(&self) -> Result<File, DurableError> {
        let parent = self.parent();
        let path_metadata = fs::symlink_metadata(parent).map_err(|_| DurableError::Storage)?;
        if !path_metadata.file_type().is_dir() {
            return Err(DurableError::Storage);
        }

        let directory = File::open(parent).map_err(|_| DurableError::Storage)?;
        let opened_metadata = directory.metadata().map_err(|_| DurableError::Storage)?;
        if path_metadata.dev() != opened_metadata.dev()
            || path_metadata.ino() != opened_metadata.ino()
        {
            return Err(DurableError::Storage);
        }
        Ok(directory)
    }

    #[cfg(unix)]
    fn temp_path(&self) -> Result<PathBuf, DurableError> {
        let target_name = self.path.file_name().ok_or(DurableError::Storage)?;
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let mut temp_name = OsString::from(".");
        temp_name.push(target_name);
        temp_name.push(format!(".tmp.{}.{sequence}", std::process::id()));
        Ok(self.parent().join(temp_name))
    }

    #[cfg(unix)]
    fn create_temp(&self) -> Result<(File, TempCleanup), DurableError> {
        for _ in 0..TEMP_CREATE_ATTEMPTS {
            let path = self.temp_path()?;
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
            {
                Ok(file) => return Ok((file, TempCleanup::new(path))),
                Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
                Err(_) => return Err(DurableError::Storage),
            }
        }
        Err(DurableError::Storage)
    }

    #[cfg(unix)]
    fn load_unix(&self) -> Result<Option<Vec<u8>>, DurableError> {
        let path_metadata = match fs::symlink_metadata(&self.path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(DurableError::Storage),
        };
        if !path_metadata.file_type().is_file() {
            return Err(DurableError::Storage);
        }

        let file = OpenOptions::new()
            .read(true)
            .open(&self.path)
            .map_err(|_| DurableError::Storage)?;
        let opened_metadata = file.metadata().map_err(|_| DurableError::Storage)?;
        if path_metadata.dev() != opened_metadata.dev()
            || path_metadata.ino() != opened_metadata.ino()
        {
            return Err(DurableError::Storage);
        }

        let max_bytes = u64::try_from(self.max_snapshot_bytes).unwrap_or(u64::MAX);
        if opened_metadata.len() > max_bytes {
            return Err(DurableError::Storage);
        }
        let mut bytes = Vec::new();
        file.take(max_bytes.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|_| DurableError::Storage)?;
        if bytes.len() > self.max_snapshot_bytes {
            return Err(DurableError::Storage);
        }
        Ok(Some(bytes))
    }

    #[cfg(unix)]
    fn replace_unix(&self, bytes: &[u8]) -> Result<(), DurableError> {
        if bytes.len() > self.max_snapshot_bytes {
            return Err(DurableError::Storage);
        }

        let parent = self.open_parent()?;
        let (mut temp_file, mut cleanup) = self.create_temp()?;
        temp_file
            .write_all(bytes)
            .map_err(|_| DurableError::Storage)?;
        temp_file.sync_all().map_err(|_| DurableError::Storage)?;
        drop(temp_file);

        fs::rename(cleanup.path(), &self.path).map_err(|_| DurableError::Storage)?;
        cleanup.disarm();
        parent.sync_all().map_err(|_| DurableError::Storage)
    }
}

impl SnapshotStorage for AtomicFileSnapshot {
    fn load(&self) -> Result<Option<Vec<u8>>, DurableError> {
        #[cfg(unix)]
        {
            self.load_unix()
        }
        #[cfg(not(unix))]
        {
            let _ = (&self.path, self.max_snapshot_bytes);
            Err(DurableError::Unsupported)
        }
    }

    fn replace(&mut self, bytes: &[u8]) -> Result<(), DurableError> {
        #[cfg(unix)]
        {
            self.replace_unix(bytes)
        }
        #[cfg(not(unix))]
        {
            let _ = (&self.path, self.max_snapshot_bytes, bytes);
            Err(DurableError::Unsupported)
        }
    }
}

#[cfg(unix)]
struct TempCleanup {
    path: PathBuf,
    armed: bool,
}

#[cfg(unix)]
impl TempCleanup {
    fn new(path: PathBuf) -> Self {
        Self { path, armed: true }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

#[cfg(unix)]
impl Drop for TempCleanup {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static TEST_DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let sequence = TEST_DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "haldir-durable-file-test-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn load_returns_none_when_snapshot_is_missing() {
        let directory = TestDirectory::new();
        let storage = AtomicFileSnapshot::new(directory.path().join("snapshot"), 16);

        assert_eq!(storage.load().unwrap(), None);
    }

    #[test]
    fn replace_provisions_a_snapshot_that_load_returns() {
        let directory = TestDirectory::new();
        let mut storage = AtomicFileSnapshot::new(directory.path().join("snapshot"), 16);

        storage.replace(b"first").unwrap();

        assert_eq!(storage.load().unwrap(), Some(b"first".to_vec()));
    }

    #[test]
    fn replace_atomically_changes_the_visible_snapshot() {
        let directory = TestDirectory::new();
        let mut storage = AtomicFileSnapshot::new(directory.path().join("snapshot"), 16);
        storage.replace(b"first").unwrap();

        storage.replace(b"second").unwrap();

        assert_eq!(storage.load().unwrap(), Some(b"second".to_vec()));
    }

    #[test]
    fn load_rejects_a_file_larger_than_the_bound() {
        let directory = TestDirectory::new();
        let path = directory.path().join("snapshot");
        fs::write(&path, b"12345").unwrap();
        let storage = AtomicFileSnapshot::new(path, 4);

        assert_eq!(storage.load().unwrap_err(), DurableError::Storage);
    }

    #[test]
    fn oversized_replace_preserves_the_committed_snapshot() {
        let directory = TestDirectory::new();
        let mut storage = AtomicFileSnapshot::new(directory.path().join("snapshot"), 4);
        storage.replace(b"old").unwrap();

        let error = storage.replace(b"12345").unwrap_err();

        assert!(error == DurableError::Storage && storage.load().unwrap() == Some(b"old".to_vec()));
    }

    #[test]
    fn failed_rename_removes_the_temporary_file() {
        let directory = TestDirectory::new();
        let destination = directory.path().join("snapshot");
        fs::create_dir(&destination).unwrap();
        let mut storage = AtomicFileSnapshot::new(destination, 16);

        let error = storage.replace(b"bytes").unwrap_err();
        let entries = fs::read_dir(directory.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();

        assert!(error == DurableError::Storage && entries == [OsString::from("snapshot")]);
    }

    #[test]
    fn load_rejects_a_symbolic_link() {
        use std::os::unix::fs::symlink;

        let directory = TestDirectory::new();
        let target = directory.path().join("target");
        let link = directory.path().join("snapshot");
        fs::write(&target, b"target").unwrap();
        symlink(&target, &link).unwrap();
        let storage = AtomicFileSnapshot::new(link, 16);

        assert_eq!(storage.load().unwrap_err(), DurableError::Storage);
    }
}
