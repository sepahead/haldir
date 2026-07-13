//! Bounded artifact capture relative to a caller-supplied directory capability.

use std::fmt;
use std::fs::File;

#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::collections::BTreeSet;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::io::{ErrorKind, Read};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::os::unix::fs::MetadataExt;

#[cfg(any(target_os = "linux", target_os = "macos"))]
use rustix::fs::{Mode, OFlags, openat};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use rustix::io::fcntl_dupfd_cloexec;

#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::artifact::DeploymentArtifactInput;
use crate::artifact::{ArtifactLimits, DeploymentArtifactSet, ResolvedDeploymentPackage};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::contract::DeploymentArtifactRefV1;
use crate::contract::{DeploymentArtifactIdV1, DeploymentPackageV1};
use crate::error::DeploymentError;
use crate::verify::VerifiedDeploymentPackage;

/// An owned, path-free capability for one flat artifact directory.
///
/// On Linux and macOS, [`Self::from_directory`] duplicates a caller-supplied open
/// directory descriptor with close-on-exec enabled. The caller remains
/// responsible for how that descriptor was selected and protected. No root
/// pathname is retained or exposed.
///
/// This source does not establish directory ownership, permissions, writer
/// exclusion, filesystem trust, credential custody, or Gate startup use.
pub struct ArtifactDirectory {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    directory: File,
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    root_device: u64,
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    _unsupported: (),
}

impl fmt::Debug for ArtifactDirectory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ArtifactDirectory")
            .finish_non_exhaustive()
    }
}

impl ArtifactDirectory {
    /// Consume an already-open directory into a path-free source capability.
    ///
    /// The descriptor's provenance is deliberately external to this API. On
    /// Linux and macOS it is duplicated before use; on other platforms this source is
    /// unsupported.
    ///
    /// # Errors
    /// Returns [`DeploymentError::ArtifactSourceRootInvalid`] if the supported
    /// descriptor cannot be duplicated or does not name a directory, and
    /// [`DeploymentError::ArtifactSourceUnsupported`] on other platforms.
    pub fn from_directory(directory: File) -> Result<Self, DeploymentError> {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            let duplicated = fcntl_dupfd_cloexec(&directory, 0)
                .map_err(|_| DeploymentError::ArtifactSourceRootInvalid)?;
            drop(directory);
            let directory = File::from(duplicated);
            let metadata = directory
                .metadata()
                .map_err(|_| DeploymentError::ArtifactSourceRootInvalid)?;
            if !metadata.file_type().is_dir() {
                return Err(DeploymentError::ArtifactSourceRootInvalid);
            }
            Ok(Self {
                directory,
                root_device: metadata.dev(),
            })
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            drop(directory);
            Err(DeploymentError::ArtifactSourceUnsupported)
        }
    }

    fn load(
        self,
        verified: &VerifiedDeploymentPackage,
        limits: ArtifactLimits,
    ) -> Result<DeploymentArtifactSet, DeploymentError> {
        verified.preflight_artifact_limits(limits)?;
        preflight_source_names_and_sizes(verified.package())?;

        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            self.load_unix(verified.package())
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let _ = self;
            Err(DeploymentError::ArtifactSourceUnsupported)
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn load_unix(
        self,
        package: &DeploymentPackageV1,
    ) -> Result<DeploymentArtifactSet, DeploymentError> {
        self.load_unix_with_observer(package, |_| {})
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn load_unix_with_observer<F>(
        self,
        package: &DeploymentPackageV1,
        mut after_initial_metadata: F,
    ) -> Result<DeploymentArtifactSet, DeploymentError>
    where
        F: FnMut(DeploymentArtifactIdV1),
    {
        let mut identities = BTreeSet::new();
        let mut inputs = Vec::with_capacity(package.artifacts.len());
        for artifact in package.artifacts.as_slice() {
            inputs.push(self.load_one(artifact, &mut identities, || {
                after_initial_metadata(artifact.role);
            })?);
        }
        DeploymentArtifactSet::from_inputs(inputs)
    }

    #[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
    pub(crate) fn load_with_after_initial_metadata<F>(
        self,
        verified: &VerifiedDeploymentPackage,
        limits: ArtifactLimits,
        after_initial_metadata: F,
    ) -> Result<DeploymentArtifactSet, DeploymentError>
    where
        F: FnMut(DeploymentArtifactIdV1),
    {
        verified.preflight_artifact_limits(limits)?;
        preflight_source_names_and_sizes(verified.package())?;
        self.load_unix_with_observer(verified.package(), after_initial_metadata)
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn load_one<F>(
        &self,
        artifact: &DeploymentArtifactRefV1,
        identities: &mut BTreeSet<FileIdentity>,
        after_initial_metadata: F,
    ) -> Result<DeploymentArtifactInput, DeploymentError>
    where
        F: FnOnce(),
    {
        let role = artifact.role;
        let descriptor = openat(
            &self.directory,
            artifact.logical_id.as_str(),
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY,
            Mode::empty(),
        )
        .map_err(|_| DeploymentError::ArtifactSourceEntryUnavailable(role))?;
        let mut file = File::from(descriptor);

        let before = file
            .metadata()
            .map_err(|_| DeploymentError::ArtifactSourceEntryRejected(role))?;
        let identity = FileIdentity::from_metadata(&before);
        if !before.file_type().is_file()
            || before.nlink() != 1
            || before.dev() != self.root_device
            || !identities.insert(identity)
        {
            return Err(DeploymentError::ArtifactSourceEntryRejected(role));
        }
        if before.len() != artifact.size_bytes.get() {
            return Err(DeploymentError::ArtifactSourceSizeMismatch(role));
        }
        after_initial_metadata();

        let expected_len = source_buffer_len(role, artifact.size_bytes.get())?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(expected_len)
            .map_err(|_| DeploymentError::ArtifactSourceAllocationFailed(role))?;
        bytes.resize(expected_len, 0);
        if let Err(error) = file.read_exact(&mut bytes) {
            return if error.kind() == ErrorKind::UnexpectedEof {
                Err(DeploymentError::ArtifactSourceSizeMismatch(role))
            } else {
                Err(DeploymentError::ArtifactSourceReadFailed(role))
            };
        }
        if read_one_more(&mut file, role)? {
            return Err(DeploymentError::ArtifactSourceSizeMismatch(role));
        }

        let after = file
            .metadata()
            .map_err(|_| DeploymentError::ArtifactSourceChanged(role))?;
        if !after.file_type().is_file()
            || after.nlink() != 1
            || after.dev() != self.root_device
            || FileIdentity::from_metadata(&after) != identity
            || after.len() != artifact.size_bytes.get()
        {
            return Err(DeploymentError::ArtifactSourceChanged(role));
        }

        Ok(DeploymentArtifactInput::new(
            role,
            artifact.logical_id.clone(),
            bytes,
        ))
    }
}

impl VerifiedDeploymentPackage {
    /// Consume this verified package and capture every signed artifact from one
    /// already-open flat directory before exact digest resolution.
    ///
    /// Signed per-artifact and total sizes, flat signed logical identifiers,
    /// and sentinel-read arithmetic are preflighted before any artifact entry
    /// is opened. On Linux and macOS each entry is opened exactly once relative to the
    /// retained directory descriptor without following a final symlink. File
    /// type, link count, device, identity, and exact size are checked on that
    /// same descriptor before and after a bounded read. The captured owned
    /// bytes then pass through [`Self::resolve_artifacts`].
    ///
    /// A nonregular entry can be opened before its descriptor type is rejected;
    /// device open itself may block or cause device-specific effects despite the
    /// nonblocking/no-controlling-terminal flags. Limits are caller-supplied
    /// byte bounds, not a global implementation cap or a wall-clock I/O bound.
    /// This method does not prove root provenance, ownership or mode policy, an
    /// atomic filesystem snapshot, semantic artifact validity, credential
    /// protection, running-binary correspondence, or Gate startup selection.
    ///
    /// # Errors
    /// Returns a stable, path-free [`DeploymentError`] for limits, source-name,
    /// open, topology, size, allocation, read, mutation, or digest failure.
    pub fn resolve_artifacts_from_directory(
        self,
        source: ArtifactDirectory,
        limits: ArtifactLimits,
    ) -> Result<ResolvedDeploymentPackage, DeploymentError> {
        let inputs = source.load(&self, limits)?;
        self.resolve_artifacts(inputs, limits)
    }
}

fn preflight_source_names_and_sizes(package: &DeploymentPackageV1) -> Result<(), DeploymentError> {
    for artifact in package.artifacts.as_slice() {
        let name = artifact.logical_id.as_str();
        if matches!(name, "." | "..") || name.contains('/') || name.contains('\0') {
            return Err(DeploymentError::ArtifactSourceNameInvalid(artifact.role));
        }
        let _ = source_buffer_len(artifact.role, artifact.size_bytes.get())?;
    }
    Ok(())
}

fn source_buffer_len(
    role: DeploymentArtifactIdV1,
    expected: u64,
) -> Result<usize, DeploymentError> {
    let _ = expected
        .checked_add(1)
        .ok_or(DeploymentError::ArtifactSourceSizeUnsupported(role))?;
    usize::try_from(expected).map_err(|_| DeploymentError::ArtifactSourceSizeUnsupported(role))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl FileIdentity {
    fn from_metadata(metadata: &std::fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn read_one_more(file: &mut File, role: DeploymentArtifactIdV1) -> Result<bool, DeploymentError> {
    let mut sentinel = [0u8; 1];
    loop {
        match file.read(&mut sentinel) {
            Ok(0) => return Ok(false),
            Ok(_) => return Ok(true),
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(_) => return Err(DeploymentError::ArtifactSourceReadFailed(role)),
        }
    }
}
