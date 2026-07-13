//! Exact owned-byte artifact resolution with no verifier-to-consumer reopen.

use std::collections::BTreeMap;
use std::fmt;

use haldir_contracts::digest::{DigestDomain, DigestV1};
use haldir_contracts::scalar::AsciiId;

use crate::contract::DeploymentArtifactIdV1;
use crate::error::DeploymentError;
use crate::verify::VerifiedDeploymentPackage;

/// Externally imposed artifact byte bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArtifactLimits {
    max_artifact_bytes: usize,
    max_total_bytes: usize,
}

impl ArtifactLimits {
    /// Construct nonzero, internally consistent limits.
    ///
    /// # Errors
    /// Returns [`DeploymentError::ArtifactLimitsInvalid`] for zero bounds or
    /// when one artifact could exceed the total bound.
    pub fn new(max_artifact_bytes: usize, max_total_bytes: usize) -> Result<Self, DeploymentError> {
        if max_artifact_bytes == 0 || max_total_bytes == 0 || max_artifact_bytes > max_total_bytes {
            return Err(DeploymentError::ArtifactLimitsInvalid);
        }
        Ok(Self {
            max_artifact_bytes,
            max_total_bytes,
        })
    }
}

/// Owned bytes supplied once for one closed signed artifact role.
pub struct DeploymentArtifactInput {
    role: DeploymentArtifactIdV1,
    logical_id: AsciiId<64>,
    bytes: Vec<u8>,
}

impl fmt::Debug for DeploymentArtifactInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeploymentArtifactInput")
            .field("role", &self.role)
            .field("logical_id", &self.logical_id)
            .field("byte_len", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

impl DeploymentArtifactInput {
    /// Consume caller-owned bytes into an artifact input.
    #[must_use]
    pub fn new(role: DeploymentArtifactIdV1, logical_id: AsciiId<64>, bytes: Vec<u8>) -> Self {
        Self {
            role,
            logical_id,
            bytes,
        }
    }
}

/// A duplicate-checked collection of owned artifact inputs.
#[derive(Default)]
pub struct DeploymentArtifactSet {
    inputs: BTreeMap<DeploymentArtifactIdV1, DeploymentArtifactInput>,
}

impl fmt::Debug for DeploymentArtifactSet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeploymentArtifactSet")
            .field("artifact_count", &self.inputs.len())
            .field("roles", &self.inputs.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl DeploymentArtifactSet {
    /// Consume inputs, rejecting more than one for the same closed role.
    ///
    /// # Errors
    /// Returns [`DeploymentError::ArtifactDuplicateInput`] on duplicate roles.
    pub fn from_inputs(
        inputs: impl IntoIterator<Item = DeploymentArtifactInput>,
    ) -> Result<Self, DeploymentError> {
        let mut by_role = BTreeMap::new();
        for input in inputs {
            let role = input.role;
            if by_role.insert(role, input).is_some() {
                return Err(DeploymentError::ArtifactDuplicateInput(role));
            }
        }
        Ok(Self { inputs: by_role })
    }
}

struct ResolvedArtifact {
    logical_id: AsciiId<64>,
    bytes: Vec<u8>,
}

/// A verified package retaining every exact verified artifact byte string.
///
/// “Resolved” proves byte identity only. It does not parse configuration, open
/// credentials, identify the running executable, or start a Gate.
pub struct ResolvedDeploymentPackage {
    verified: VerifiedDeploymentPackage,
    artifacts: BTreeMap<DeploymentArtifactIdV1, ResolvedArtifact>,
}

impl fmt::Debug for ResolvedDeploymentPackage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResolvedDeploymentPackage")
            .field("verified", &self.verified)
            .field("artifact_count", &self.artifacts.len())
            .field("roles", &self.artifacts.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl ResolvedDeploymentPackage {
    /// The signature- and policy-verified package stage.
    #[must_use]
    pub const fn verified(&self) -> &VerifiedDeploymentPackage {
        &self.verified
    }

    /// Retained exact bytes for a required role.
    #[must_use]
    pub fn artifact(&self, role: DeploymentArtifactIdV1) -> Option<&[u8]> {
        self.artifacts
            .get(&role)
            .map(|artifact| artifact.bytes.as_slice())
    }

    /// Signed logical identifier associated with retained bytes for a role.
    #[must_use]
    pub fn artifact_logical_id(&self, role: DeploymentArtifactIdV1) -> Option<&str> {
        self.artifacts
            .get(&role)
            .map(|artifact| artifact.logical_id.as_str())
    }
}

impl VerifiedDeploymentPackage {
    pub(crate) fn preflight_artifact_limits(
        &self,
        limits: ArtifactLimits,
    ) -> Result<(), DeploymentError> {
        let max_artifact = u64::try_from(limits.max_artifact_bytes).unwrap_or(u64::MAX);
        let max_total = u64::try_from(limits.max_total_bytes).unwrap_or(u64::MAX);
        let mut declared_total = 0u64;
        for artifact in self.package().artifacts.as_slice() {
            if artifact.size_bytes.get() > max_artifact {
                return Err(DeploymentError::ArtifactDeclaredTooLarge(artifact.role));
            }
            declared_total = declared_total
                .checked_add(artifact.size_bytes.get())
                .ok_or(DeploymentError::ArtifactTotalTooLarge)?;
            if declared_total > max_total {
                return Err(DeploymentError::ArtifactTotalTooLarge);
            }
        }
        Ok(())
    }

    /// Consume exact owned inputs and retain only a fully verified artifact set.
    ///
    /// Signed sizes are preflighted against `limits` before any supplied bytes
    /// are inspected. Successful resolution retains the same owned byte buffers;
    /// consumers borrow them without a path or reopen operation.
    ///
    /// # Errors
    /// Returns a stable [`DeploymentError`] for bounds, missing/duplicate input,
    /// logical identity, exact length, or digest mismatch.
    pub fn resolve_artifacts(
        self,
        mut inputs: DeploymentArtifactSet,
        limits: ArtifactLimits,
    ) -> Result<ResolvedDeploymentPackage, DeploymentError> {
        self.preflight_artifact_limits(limits)?;

        let mut resolved = BTreeMap::new();
        for artifact in self.package().artifacts.as_slice() {
            let input = inputs
                .inputs
                .remove(&artifact.role)
                .ok_or(DeploymentError::ArtifactMissing(artifact.role))?;
            if input.logical_id != artifact.logical_id {
                return Err(DeploymentError::ArtifactLogicalIdMismatch(artifact.role));
            }
            let actual_len = u64::try_from(input.bytes.len()).unwrap_or(u64::MAX);
            if actual_len != artifact.size_bytes.get() {
                return Err(DeploymentError::ArtifactLengthMismatch(artifact.role));
            }
            let actual_digest = DigestV1::compute(DigestDomain::DeploymentArtifact, &input.bytes);
            if actual_digest != artifact.digest {
                return Err(DeploymentError::ArtifactDigestMismatch(artifact.role));
            }
            resolved.insert(
                artifact.role,
                ResolvedArtifact {
                    logical_id: input.logical_id,
                    bytes: input.bytes,
                },
            );
        }
        if let Some(role) = inputs.inputs.keys().next().copied() {
            return Err(DeploymentError::ArtifactDuplicateInput(role));
        }

        Ok(ResolvedDeploymentPackage {
            verified: self,
            artifacts: resolved,
        })
    }
}
