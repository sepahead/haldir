//! Stable deployment verification and artifact-resolution errors.

use core::fmt;

use haldir_contracts::error::DecodeError;
use haldir_crypto::CryptoError;
use haldir_ncp08::NcpCompatibilityError;

use crate::contract::{AuthoritySnapshotKindV1, DeploymentArtifactIdV1};

/// A fail-closed deployment-package verification or resolution failure.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DeploymentError {
    /// COSE structure, trust, role, revocation, or signature verification failed.
    Crypto(CryptoError),
    /// The signed payload was not the strict supported canonical contract.
    Decode(DecodeError),
    /// The trusted signer subject did not equal the signed authority identifier.
    AuthoritySubjectMismatch,
    /// The signed authority differed from the separately expected authority.
    AuthorityMismatch,
    /// The package named a Gate other than the externally expected Gate.
    GateMismatch,
    /// The package named a realm other than the externally expected realm.
    RealmMismatch,
    /// The package named a vehicle other than the externally expected vehicle.
    VehicleMismatch,
    /// The package class differed from the externally required class.
    ProfileMismatch,
    /// The package runtime differed from the externally required runtime.
    RuntimeProfileMismatch,
    /// The package NCP wire profile differed from the externally required profile.
    NcpWireProfileMismatch,
    /// Artifact limits were zero or internally inconsistent.
    ArtifactLimitsInvalid,
    /// A signed artifact size exceeded the external per-artifact bound.
    ArtifactDeclaredTooLarge(DeploymentArtifactIdV1),
    /// The checked sum of signed artifact sizes exceeded the external total bound.
    ArtifactTotalTooLarge,
    /// More than one input was supplied for one closed artifact role.
    ArtifactDuplicateInput(DeploymentArtifactIdV1),
    /// No owned input bytes were supplied for a required artifact role.
    ArtifactMissing(DeploymentArtifactIdV1),
    /// Supplied input named a different logical artifact identifier.
    ArtifactLogicalIdMismatch(DeploymentArtifactIdV1),
    /// Owned bytes did not have the exact signed length.
    ArtifactLengthMismatch(DeploymentArtifactIdV1),
    /// Owned bytes did not have the exact signed domain-separated digest.
    ArtifactDigestMismatch(DeploymentArtifactIdV1),
    /// The exact signed NCP-compatibility role did not match this compiled adapter.
    NcpCompatibility(NcpCompatibilityError),
    /// The strict Gate-configuration artifact disagreed with its containing package.
    GateConfigurationPackageMismatch,
    /// A signed snapshot approval declared another authority domain.
    AuthorityApprovalKindMismatch(AuthoritySnapshotKindV1),
    /// A signed snapshot approval's trusted signer subject did not equal its issuer.
    AuthorityApprovalSubjectMismatch(AuthoritySnapshotKindV1),
    /// A snapshot approval issuer differed from separately configured policy.
    AuthorityApprovalPolicyMismatch(AuthoritySnapshotKindV1),
    /// A snapshot approval was issued for another deployment or Gate context.
    AuthorityApprovalPackageMismatch(AuthoritySnapshotKindV1),
    /// A snapshot approval did not authorize the digest used by Gate configuration.
    AuthorityApprovalDigestMismatch(AuthoritySnapshotKindV1),
    /// The local artifact source is unavailable on this platform.
    ArtifactSourceUnsupported,
    /// The caller-supplied source capability was not an open directory.
    ArtifactSourceRootInvalid,
    /// A signed logical identifier was not a safe flat source filename.
    ArtifactSourceNameInvalid(DeploymentArtifactIdV1),
    /// A required source entry could not be opened through the directory capability.
    ArtifactSourceEntryUnavailable(DeploymentArtifactIdV1),
    /// An opened source entry had rejected filesystem topology or file type.
    ArtifactSourceEntryRejected(DeploymentArtifactIdV1),
    /// A signed source size could not support a bounded sentinel read.
    ArtifactSourceSizeUnsupported(DeploymentArtifactIdV1),
    /// An opened source entry did not have the exact signed size.
    ArtifactSourceSizeMismatch(DeploymentArtifactIdV1),
    /// An opened source entry changed during capture.
    ArtifactSourceChanged(DeploymentArtifactIdV1),
    /// A bounded source buffer could not be allocated.
    ArtifactSourceAllocationFailed(DeploymentArtifactIdV1),
    /// Reading an opened source entry failed.
    ArtifactSourceReadFailed(DeploymentArtifactIdV1),
}

impl DeploymentError {
    /// Stable non-path-leaking machine reason class.
    #[must_use]
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::Crypto(error) => error.reason_code(),
            Self::Decode(error) => error.reason_code(),
            Self::AuthoritySubjectMismatch => "DEPLOYMENT_AUTHORITY_SUBJECT_MISMATCH",
            Self::AuthorityMismatch => "DEPLOYMENT_AUTHORITY_MISMATCH",
            Self::GateMismatch => "DEPLOYMENT_GATE_MISMATCH",
            Self::RealmMismatch => "DEPLOYMENT_REALM_MISMATCH",
            Self::VehicleMismatch => "DEPLOYMENT_VEHICLE_MISMATCH",
            Self::ProfileMismatch => "DEPLOYMENT_PROFILE_MISMATCH",
            Self::RuntimeProfileMismatch => "DEPLOYMENT_RUNTIME_PROFILE_MISMATCH",
            Self::NcpWireProfileMismatch => "DEPLOYMENT_NCP_WIRE_PROFILE_MISMATCH",
            Self::ArtifactLimitsInvalid => "DEPLOYMENT_ARTIFACT_LIMITS_INVALID",
            Self::ArtifactDeclaredTooLarge(_) => "DEPLOYMENT_ARTIFACT_DECLARED_TOO_LARGE",
            Self::ArtifactTotalTooLarge => "DEPLOYMENT_ARTIFACT_TOTAL_TOO_LARGE",
            Self::ArtifactDuplicateInput(_) => "DEPLOYMENT_ARTIFACT_DUPLICATE_INPUT",
            Self::ArtifactMissing(_) => "DEPLOYMENT_ARTIFACT_MISSING",
            Self::ArtifactLogicalIdMismatch(_) => "DEPLOYMENT_ARTIFACT_ID_MISMATCH",
            Self::ArtifactLengthMismatch(_) => "DEPLOYMENT_ARTIFACT_LENGTH_MISMATCH",
            Self::ArtifactDigestMismatch(_) => "DEPLOYMENT_ARTIFACT_DIGEST_MISMATCH",
            Self::NcpCompatibility(error) => error.reason_code(),
            Self::GateConfigurationPackageMismatch => {
                "DEPLOYMENT_GATE_CONFIGURATION_PACKAGE_MISMATCH"
            }
            Self::AuthorityApprovalKindMismatch(_) => "DEPLOYMENT_AUTHORITY_APPROVAL_KIND_MISMATCH",
            Self::AuthorityApprovalSubjectMismatch(_) => {
                "DEPLOYMENT_AUTHORITY_APPROVAL_SUBJECT_MISMATCH"
            }
            Self::AuthorityApprovalPolicyMismatch(_) => {
                "DEPLOYMENT_AUTHORITY_APPROVAL_POLICY_MISMATCH"
            }
            Self::AuthorityApprovalPackageMismatch(_) => {
                "DEPLOYMENT_AUTHORITY_APPROVAL_PACKAGE_MISMATCH"
            }
            Self::AuthorityApprovalDigestMismatch(_) => {
                "DEPLOYMENT_AUTHORITY_APPROVAL_DIGEST_MISMATCH"
            }
            Self::ArtifactSourceUnsupported => "DEPLOYMENT_ARTIFACT_SOURCE_UNSUPPORTED",
            Self::ArtifactSourceRootInvalid => "DEPLOYMENT_ARTIFACT_SOURCE_ROOT_INVALID",
            Self::ArtifactSourceNameInvalid(_) => "DEPLOYMENT_ARTIFACT_SOURCE_NAME_INVALID",
            Self::ArtifactSourceEntryUnavailable(_) => {
                "DEPLOYMENT_ARTIFACT_SOURCE_ENTRY_UNAVAILABLE"
            }
            Self::ArtifactSourceEntryRejected(_) => "DEPLOYMENT_ARTIFACT_SOURCE_ENTRY_REJECTED",
            Self::ArtifactSourceSizeUnsupported(_) => "DEPLOYMENT_ARTIFACT_SOURCE_SIZE_UNSUPPORTED",
            Self::ArtifactSourceSizeMismatch(_) => "DEPLOYMENT_ARTIFACT_SOURCE_SIZE_MISMATCH",
            Self::ArtifactSourceChanged(_) => "DEPLOYMENT_ARTIFACT_SOURCE_CHANGED",
            Self::ArtifactSourceAllocationFailed(_) => {
                "DEPLOYMENT_ARTIFACT_SOURCE_ALLOCATION_FAILED"
            }
            Self::ArtifactSourceReadFailed(_) => "DEPLOYMENT_ARTIFACT_SOURCE_READ_FAILED",
        }
    }
}

impl From<CryptoError> for DeploymentError {
    fn from(error: CryptoError) -> Self {
        Self::Crypto(error)
    }
}

impl From<DecodeError> for DeploymentError {
    fn from(error: DecodeError) -> Self {
        Self::Decode(error)
    }
}

impl From<NcpCompatibilityError> for DeploymentError {
    fn from(error: NcpCompatibilityError) -> Self {
        Self::NcpCompatibility(error)
    }
}

impl fmt::Display for DeploymentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for DeploymentError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Crypto(error) => Some(error),
            Self::Decode(error) => Some(error),
            Self::NcpCompatibility(error) => Some(error),
            _ => None,
        }
    }
}
