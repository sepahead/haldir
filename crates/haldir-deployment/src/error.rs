//! Stable deployment verification and artifact-resolution errors.

use core::fmt;

use haldir_contracts::error::DecodeError;
use haldir_crypto::CryptoError;

use crate::contract::DeploymentArtifactIdV1;

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

impl fmt::Display for DeploymentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for DeploymentError {}
