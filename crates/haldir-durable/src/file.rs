//! Process-crash-scoped atomic snapshot storage for Unix filesystems.

use std::path::PathBuf;

#[cfg(unix)]
use rustix::fs::{AtFlags, Mode, OFlags, open, openat, renameat, unlinkat};
#[cfg(unix)]
use rustix::io::Errno;
#[cfg(unix)]
use std::ffi::OsString;
#[cfg(unix)]
use std::fs::{self, File};
#[cfg(unix)]
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
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
/// Each operation first verifies and opens the parent directory, then performs
/// every leaf open/create/rename/unlink relative to that retained descriptor.
/// Replacing the parent pathname during that operation therefore cannot redirect
/// its leaf I/O. This type does not lock writers, prevent an external rollback,
/// defend against ancestor replacement before an operation or between
/// operations, or promise power-loss durability. Callers must provide
/// exclusive-writer coordination, trusted ancestry, and an
/// [`crate::AnchorProtection::ExternalNonRewindable`] generation anchor when
/// protection from local rewind is required.
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

        let directory = File::from(
            open(
                parent,
                OFlags::RDONLY
                    | OFlags::DIRECTORY
                    | OFlags::CLOEXEC
                    | OFlags::NOFOLLOW
                    | OFlags::NONBLOCK
                    | OFlags::NOCTTY,
                Mode::empty(),
            )
            .map_err(|_| DurableError::Storage)?,
        );
        let opened_metadata = directory.metadata().map_err(|_| DurableError::Storage)?;
        if path_metadata.dev() != opened_metadata.dev()
            || path_metadata.ino() != opened_metadata.ino()
        {
            return Err(DurableError::Storage);
        }
        Ok(directory)
    }

    #[cfg(unix)]
    fn target_name(&self) -> Result<&std::ffi::OsStr, DurableError> {
        self.path.file_name().ok_or(DurableError::Storage)
    }

    #[cfg(unix)]
    fn temp_name(&self) -> Result<OsString, DurableError> {
        let target_name = self.path.file_name().ok_or(DurableError::Storage)?;
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let mut temp_name = OsString::from(".");
        temp_name.push(target_name);
        temp_name.push(format!(".tmp.{}.{sequence}", std::process::id()));
        Ok(temp_name)
    }

    #[cfg(unix)]
    fn create_temp<'parent>(
        &self,
        parent: &'parent File,
    ) -> Result<(File, TempCleanup<'parent>), DurableError> {
        for _ in 0..TEMP_CREATE_ATTEMPTS {
            let name = self.temp_name()?;
            match openat(
                parent,
                &name,
                OFlags::WRONLY
                    | OFlags::CREATE
                    | OFlags::EXCL
                    | OFlags::CLOEXEC
                    | OFlags::NOFOLLOW
                    | OFlags::NONBLOCK
                    | OFlags::NOCTTY,
                Mode::RUSR | Mode::WUSR,
            ) {
                Ok(descriptor) => {
                    return Ok((File::from(descriptor), TempCleanup::new(parent, name)));
                }
                Err(Errno::EXIST) => {}
                Err(_) => return Err(DurableError::Storage),
            }
        }
        Err(DurableError::Storage)
    }

    #[cfg(unix)]
    fn load_from_parent(&self, parent: &File) -> Result<Option<Vec<u8>>, DurableError> {
        let file = match openat(
            parent,
            self.target_name()?,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY,
            Mode::empty(),
        ) {
            Ok(descriptor) => File::from(descriptor),
            Err(Errno::NOENT) => return Ok(None),
            Err(_) => return Err(DurableError::Storage),
        };
        let opened_metadata = file.metadata().map_err(|_| DurableError::Storage)?;
        if !opened_metadata.file_type().is_file() {
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
    fn load_unix(&self) -> Result<Option<Vec<u8>>, DurableError> {
        let parent = self.open_parent()?;
        self.load_from_parent(&parent)
    }

    #[cfg(unix)]
    fn replace_in_parent(&self, parent: &File, bytes: &[u8]) -> Result<(), DurableError> {
        if bytes.len() > self.max_snapshot_bytes {
            return Err(DurableError::Storage);
        }

        let (mut temp_file, mut cleanup) = self.create_temp(parent)?;
        temp_file
            .write_all(bytes)
            .map_err(|_| DurableError::Storage)?;
        temp_file.sync_all().map_err(|_| DurableError::Storage)?;
        drop(temp_file);

        renameat(parent, cleanup.name(), parent, self.target_name()?)
            .map_err(|_| DurableError::Storage)?;
        cleanup.disarm();
        parent.sync_all().map_err(|_| DurableError::Storage)
    }

    #[cfg(unix)]
    fn replace_unix(&self, bytes: &[u8]) -> Result<(), DurableError> {
        let parent = self.open_parent()?;
        self.replace_in_parent(&parent, bytes)
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
struct TempCleanup<'parent> {
    parent: &'parent File,
    name: OsString,
    armed: bool,
}

#[cfg(unix)]
impl<'parent> TempCleanup<'parent> {
    fn new(parent: &'parent File, name: OsString) -> Self {
        Self {
            parent,
            name,
            armed: true,
        }
    }

    fn name(&self) -> &std::ffi::OsStr {
        &self.name
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

#[cfg(unix)]
impl Drop for TempCleanup<'_> {
    fn drop(&mut self) {
        if self.armed {
            let _ = unlinkat(self.parent, &self.name, AtFlags::empty());
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
    fn leaf_io_stays_bound_to_the_verified_parent_descriptor() {
        let directory = TestDirectory::new();
        let trusted_path = directory.path().join("trusted");
        let relocated_path = directory.path().join("relocated");
        fs::create_dir(&trusted_path).unwrap();
        let storage = AtomicFileSnapshot::new(trusted_path.join("snapshot"), 16);
        let verified_parent = storage.open_parent().unwrap();

        fs::rename(&trusted_path, &relocated_path).unwrap();
        fs::create_dir(&trusted_path).unwrap();
        storage
            .replace_in_parent(&verified_parent, b"bound")
            .unwrap();

        assert_eq!(
            storage.load_from_parent(&verified_parent).unwrap(),
            Some(b"bound".to_vec())
        );
        assert_eq!(fs::read(relocated_path.join("snapshot")).unwrap(), b"bound");
        assert!(!trusted_path.join("snapshot").exists());
        assert_eq!(storage.load().unwrap(), None);
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

    #[test]
    fn load_rejects_a_fifo_without_waiting_for_a_writer() {
        use std::sync::mpsc;
        use std::thread;
        use std::time::Duration;

        let directory = TestDirectory::new();
        let path = directory.path().join("snapshot");
        assert!(
            std::process::Command::new("mkfifo")
                .arg(&path)
                .status()
                .unwrap()
                .success()
        );
        let storage = AtomicFileSnapshot::new(path, 16);
        let (sender, receiver) = mpsc::channel();
        let worker = thread::spawn(move || sender.send(storage.load()).unwrap());

        let result = receiver
            .recv_timeout(Duration::from_secs(2))
            .expect("FIFO snapshot open exceeded the nonblocking deadline");
        worker.join().unwrap();

        assert_eq!(result.unwrap_err(), DurableError::Storage);
    }
}
