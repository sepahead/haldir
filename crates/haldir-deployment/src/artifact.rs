//! Exact owned-byte artifact resolution with no verifier-to-consumer reopen.

use std::collections::BTreeMap;
use std::fmt;

use haldir_contracts::cbor::{Limits, from_canonical_bytes};
use haldir_contracts::digest::{DigestDomain, DigestV1};
use haldir_contracts::ids::KeyId;
use haldir_contracts::scalar::AsciiId;
use haldir_crypto::{
    ExpectedContext, KeyRole, KeySubject, TrustStore, TrustStoreDisjointnessError,
    verify_and_decode,
};
use haldir_ncp08::{ValidatedNcpCompatibilityArtifact, validate_ncp_compatibility_artifact};

use crate::contract::{
    AuthoritySnapshotApprovalV1, AuthoritySnapshotKindV1, DeploymentArtifactIdV1,
    DeploymentClassV1, GateConfigurationArtifactV1,
};
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

/// A resolved package whose signed NCP-compatibility role exact-matched this build.
///
/// This capability proves the composition of package signature/policy, exact
/// signed-role byte resolution, and the compiled adapter's closed compatibility
/// validator. It does not validate the other artifact semantics, identify the
/// running executable, or authorize Gate startup.
pub struct NcpValidatedDeploymentPackage {
    resolved: ResolvedDeploymentPackage,
    compatibility: ValidatedNcpCompatibilityArtifact,
}

/// A resolved package whose NCP and strict Gate-configuration roles were both
/// validated and cross-bound to the signed package contract.
///
/// This stage proves configuration artifact syntax and package consistency. A
/// consuming Gate must still derive every configuration identity from its live
/// objects and exact-match those values before any startup effect.
pub struct GateConfigurationValidatedDeploymentPackage {
    ncp_validated: NcpValidatedDeploymentPackage,
    gate_configuration: GateConfigurationArtifactV1,
}

/// Separately configured subjects permitted to approve runtime authority
/// snapshots for one deployment.
///
/// This policy is not package data. Passing it separately prevents the
/// deployment signer from selecting its own trust, admission, revocation, or
/// policy authority identity. Verification requires four distinct key roles;
/// [`haldir_crypto::TrustStore`] also forbids one public key from occupying
/// multiple roles inside the retained bootstrap snapshot. Package-bound Gate
/// startup extends that same identity invariant across bootstrap and runtime
/// trust snapshots. Subject labels are allowed to coincide, so this type does
/// not prove organizational, operator, or administrative independence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityApprovalPolicy {
    trust_authority_id: AsciiId<64>,
    admission_authority_id: AsciiId<64>,
    revocation_authority_id: AsciiId<64>,
    policy_authority_id: AsciiId<64>,
}

impl AuthorityApprovalPolicy {
    /// Construct exact expected subjects for all four authority domains.
    #[must_use]
    pub const fn new(
        trust_authority_id: AsciiId<64>,
        admission_authority_id: AsciiId<64>,
        revocation_authority_id: AsciiId<64>,
        policy_authority_id: AsciiId<64>,
    ) -> Self {
        Self {
            trust_authority_id,
            admission_authority_id,
            revocation_authority_id,
            policy_authority_id,
        }
    }

    const fn expected_issuer(&self, kind: AuthoritySnapshotKindV1) -> &AsciiId<64> {
        match kind {
            AuthoritySnapshotKindV1::Trust => &self.trust_authority_id,
            AuthoritySnapshotKindV1::Admission => &self.admission_authority_id,
            AuthoritySnapshotKindV1::Revocation => &self.revocation_authority_id,
            AuthoritySnapshotKindV1::Policy => &self.policy_authority_id,
        }
    }
}

/// One separately verified, role-bound authority-snapshot approval retained
/// through deployment startup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAuthoritySnapshotApproval {
    approval: AuthoritySnapshotApprovalV1,
    signer_kid: KeyId,
    signer_subject: KeySubject,
}

impl VerifiedAuthoritySnapshotApproval {
    /// Canonical approval payload verified from the exact package artifact.
    #[must_use]
    pub const fn approval(&self) -> &AuthoritySnapshotApprovalV1 {
        &self.approval
    }

    /// Trusted key identifier that signed the approval.
    #[must_use]
    pub const fn signer_kid(&self) -> &KeyId {
        &self.signer_kid
    }

    /// Trusted signer subject exact-matched to the external approval policy.
    #[must_use]
    pub fn signer_subject(&self) -> &str {
        self.signer_subject.as_str()
    }
}

/// A package whose four authorization-relevant runtime snapshot identities
/// were separately verified under distinct key roles and cross-bound to this
/// exact deployment, while retaining the bootstrap trust needed to reject
/// incompatible runtime key bindings without exposing that root.
pub struct AuthorityValidatedDeploymentPackage {
    gate_configuration_validated: GateConfigurationValidatedDeploymentPackage,
    approvals: BTreeMap<AuthoritySnapshotKindV1, VerifiedAuthoritySnapshotApproval>,
}

impl fmt::Debug for NcpValidatedDeploymentPackage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NcpValidatedDeploymentPackage")
            .field("resolved", &self.resolved)
            .field("compatibility", &self.compatibility)
            .finish_non_exhaustive()
    }
}

impl NcpValidatedDeploymentPackage {
    /// Exact package and owned artifact bytes underlying this validation stage.
    #[must_use]
    pub const fn resolved(&self) -> &ResolvedDeploymentPackage {
        &self.resolved
    }

    /// Private-field proof that the signed NCP role matched every compiled pin.
    #[must_use]
    pub const fn ncp_compatibility(&self) -> &ValidatedNcpCompatibilityArtifact {
        &self.compatibility
    }

    /// Consume this stage and strictly decode/cross-bind the exact signed
    /// `GATE_CONFIGURATION` artifact.
    ///
    /// # Errors
    /// Returns [`DeploymentError::ArtifactMissing`] only for an internally
    /// incomplete resolved stage, [`DeploymentError::Decode`] for a malformed
    /// or unsupported configuration contract, or
    /// [`DeploymentError::GateConfigurationPackageMismatch`] when redundant
    /// deployment identities disagree.
    pub fn validate_gate_configuration(
        self,
    ) -> Result<GateConfigurationValidatedDeploymentPackage, DeploymentError> {
        let bytes = self
            .resolved
            .artifact(DeploymentArtifactIdV1::GateConfiguration)
            .ok_or(DeploymentError::ArtifactMissing(
                DeploymentArtifactIdV1::GateConfiguration,
            ))?;
        let gate_configuration =
            from_canonical_bytes::<GateConfigurationArtifactV1>(bytes, Limits::DEFAULT)?;
        let package = self.resolved.verified().package();
        if gate_configuration.gate_id != package.gate_id
            || gate_configuration.realm != package.realm
            || gate_configuration.vehicle_id != package.vehicle_id
            || gate_configuration.profile_class != package.profile_class
            || gate_configuration.runtime_profile != package.runtime_profile
            || gate_configuration.ncp_wire_profile != package.ncp_wire_profile
            || gate_configuration.state_store_id != package.state_store_id
            || gate_configuration.journal_id != package.journal_id
        {
            return Err(DeploymentError::GateConfigurationPackageMismatch);
        }
        Ok(GateConfigurationValidatedDeploymentPackage {
            ncp_validated: self,
            gate_configuration,
        })
    }
}

impl fmt::Debug for GateConfigurationValidatedDeploymentPackage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GateConfigurationValidatedDeploymentPackage")
            .field("ncp_validated", &self.ncp_validated)
            .field("gate_configuration", &self.gate_configuration)
            .finish_non_exhaustive()
    }
}

impl GateConfigurationValidatedDeploymentPackage {
    /// Exact package, owned artifact bytes, and NCP compatibility proof.
    #[must_use]
    pub const fn ncp_validated(&self) -> &NcpValidatedDeploymentPackage {
        &self.ncp_validated
    }

    /// Strict signed Gate configuration cross-bound to the package contract.
    #[must_use]
    pub const fn gate_configuration(&self) -> &GateConfigurationArtifactV1 {
        &self.gate_configuration
    }

    /// Exact package and owned artifact bytes underlying both validation stages.
    #[must_use]
    pub const fn resolved(&self) -> &ResolvedDeploymentPackage {
        self.ncp_validated.resolved()
    }

    /// Private-field proof that the signed NCP role matched every compiled pin.
    #[must_use]
    pub const fn ncp_compatibility(&self) -> &ValidatedNcpCompatibilityArtifact {
        self.ncp_validated.ncp_compatibility()
    }

    /// Consume this stage and verify all four role-separated runtime-snapshot
    /// approval envelopes from the exact package-retained artifacts.
    ///
    /// Verification selects each required cryptographic role from the package's
    /// closed artifact role, not from the signed payload. Each payload is then
    /// exact-matched to its trusted signer subject, the issuer policy and
    /// bootstrap trust/revocation snapshots retained from initial package
    /// verification, package deployment id/revision, Gate/realm/vehicle, and
    /// the corresponding strict Gate-configuration snapshot digest. No caller
    /// can substitute a second trust root at this later stage.
    ///
    /// # Errors
    /// Returns a stable [`DeploymentError`] for a missing artifact, COSE/trust/
    /// revocation failure, canonical payload failure, or any cross-binding
    /// mismatch.
    pub fn validate_authority_approvals(
        self,
    ) -> Result<AuthorityValidatedDeploymentPackage, DeploymentError> {
        const APPROVALS: [(DeploymentArtifactIdV1, AuthoritySnapshotKindV1, KeyRole); 4] = [
            (
                DeploymentArtifactIdV1::TrustManifest,
                AuthoritySnapshotKindV1::Trust,
                KeyRole::TrustAuthority,
            ),
            (
                DeploymentArtifactIdV1::AdmissionSnapshot,
                AuthoritySnapshotKindV1::Admission,
                KeyRole::AdmissionAuthority,
            ),
            (
                DeploymentArtifactIdV1::RevocationSnapshot,
                AuthoritySnapshotKindV1::Revocation,
                KeyRole::RevocationAuthority,
            ),
            (
                DeploymentArtifactIdV1::PolicySnapshot,
                AuthoritySnapshotKindV1::Policy,
                KeyRole::PolicyAuthority,
            ),
        ];

        let verified_package = self.resolved().verified();
        let package = verified_package.package();
        let policy = verified_package.authority_approval_policy();
        let bootstrap_trust = verified_package.bootstrap_trust();
        let bootstrap_revocations = verified_package.bootstrap_revocations();
        let assurance_profile = package.profile_class != DeploymentClassV1::Development;
        let mut approvals = BTreeMap::new();
        for (artifact_role, snapshot_kind, required_role) in APPROVALS {
            let envelope = self
                .resolved()
                .artifact(artifact_role)
                .ok_or(DeploymentError::ArtifactMissing(artifact_role))?;
            let context = ExpectedContext {
                kind: AuthoritySnapshotApprovalV1::KIND,
                schema_major: 1,
                required_role,
                assurance_profile,
            };
            let (approval, signer_kid, signer_subject) =
                verify_and_decode::<AuthoritySnapshotApprovalV1>(
                    envelope,
                    &context,
                    bootstrap_trust,
                    bootstrap_revocations,
                    Limits::LARGE,
                )?;

            if approval.snapshot_kind != snapshot_kind {
                return Err(DeploymentError::AuthorityApprovalKindMismatch(
                    snapshot_kind,
                ));
            }
            if signer_subject.as_str() != approval.issuer_id.as_str() {
                return Err(DeploymentError::AuthorityApprovalSubjectMismatch(
                    snapshot_kind,
                ));
            }
            if &approval.issuer_id != policy.expected_issuer(snapshot_kind) {
                return Err(DeploymentError::AuthorityApprovalPolicyMismatch(
                    snapshot_kind,
                ));
            }
            if approval.deployment_id != package.deployment_id
                || approval.deployment_revision != package.deployment_revision
                || approval.gate_id != package.gate_id
                || approval.realm != package.realm
                || approval.vehicle_id != package.vehicle_id
            {
                return Err(DeploymentError::AuthorityApprovalPackageMismatch(
                    snapshot_kind,
                ));
            }
            let expected_digest = match snapshot_kind {
                AuthoritySnapshotKindV1::Trust => self.gate_configuration.trust_snapshot_digest,
                AuthoritySnapshotKindV1::Admission => {
                    self.gate_configuration.admission_snapshot_digest
                }
                AuthoritySnapshotKindV1::Revocation => {
                    self.gate_configuration.revocation_snapshot_digest
                }
                AuthoritySnapshotKindV1::Policy => self.gate_configuration.policy_snapshot_digest,
            };
            if approval.snapshot_digest != expected_digest {
                return Err(DeploymentError::AuthorityApprovalDigestMismatch(
                    snapshot_kind,
                ));
            }
            approvals.insert(
                snapshot_kind,
                VerifiedAuthoritySnapshotApproval {
                    approval,
                    signer_kid,
                    signer_subject,
                },
            );
        }

        Ok(AuthorityValidatedDeploymentPackage {
            gate_configuration_validated: self,
            approvals,
        })
    }
}

impl fmt::Debug for AuthorityValidatedDeploymentPackage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorityValidatedDeploymentPackage")
            .field(
                "gate_configuration_validated",
                &self.gate_configuration_validated,
            )
            .field("approvals", &self.approvals)
            .finish_non_exhaustive()
    }
}

impl AuthorityValidatedDeploymentPackage {
    /// Underlying NCP and Gate-configuration validation stage.
    #[must_use]
    pub const fn gate_configuration_validated(
        &self,
    ) -> &GateConfigurationValidatedDeploymentPackage {
        &self.gate_configuration_validated
    }

    /// Strict Gate configuration authorized by this package.
    #[must_use]
    pub const fn gate_configuration(&self) -> &GateConfigurationArtifactV1 {
        self.gate_configuration_validated.gate_configuration()
    }

    /// Exact package and owned artifacts underlying every validation stage.
    #[must_use]
    pub const fn resolved(&self) -> &ResolvedDeploymentPackage {
        self.gate_configuration_validated.resolved()
    }

    /// Validate the signed runtime trust snapshot against the retained
    /// bootstrap authority namespace.
    ///
    /// The two stores must be disjoint by both key identifier and public key.
    /// Even exact-record overlap is rejected because the lifecycle-separated
    /// stores carry independently governed revocation snapshots; permitting
    /// overlap would make revocation inheritance ambiguous. Neither trust store
    /// is exposed or mutated.
    ///
    /// # Errors
    /// Returns the deterministic [`TrustStoreDisjointnessError`] reported by
    /// [`TrustStore::validate_disjoint_bindings`].
    pub fn validate_runtime_trust_bindings(
        &self,
        runtime_trust: &TrustStore,
    ) -> Result<(), TrustStoreDisjointnessError> {
        self.resolved()
            .verified()
            .bootstrap_trust()
            .validate_disjoint_bindings(runtime_trust)
    }

    /// One separately verified, role-bound approval by authority domain.
    #[must_use]
    pub fn approval(
        &self,
        kind: AuthoritySnapshotKindV1,
    ) -> Option<&VerifiedAuthoritySnapshotApproval> {
        self.approvals.get(&kind)
    }
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

    /// Consume this resolved package and validate its exact signed
    /// `NCP_COMPATIBILITY` artifact against the compiled adapter baseline.
    ///
    /// # Errors
    /// Returns [`DeploymentError::ArtifactMissing`] only for an internally
    /// incomplete resolved stage, or [`DeploymentError::NcpCompatibility`] for
    /// bounded canonical decoding or exact-pin mismatch.
    pub fn validate_ncp_compatibility(
        self,
    ) -> Result<NcpValidatedDeploymentPackage, DeploymentError> {
        let bytes = self
            .artifact(DeploymentArtifactIdV1::NcpCompatibility)
            .ok_or(DeploymentError::ArtifactMissing(
                DeploymentArtifactIdV1::NcpCompatibility,
            ))?;
        let compatibility = validate_ncp_compatibility_artifact(bytes)?;
        Ok(NcpValidatedDeploymentPackage {
            resolved: self,
            compatibility,
        })
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
