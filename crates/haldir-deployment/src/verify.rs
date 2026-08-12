//! COSE verification against external bootstrap policy and trust.

use haldir_contracts::cbor::{Limits, from_canonical_bytes};
use haldir_contracts::deployment::DeploymentPayloadDigestV1;
use haldir_contracts::digest::{DigestDomain, DigestV1};
use haldir_contracts::ids::{GateId, KeyId, VehicleId};
use haldir_contracts::scalar::AsciiId;
use haldir_crypto::{
    ExpectedContext, KeyRole, KeySubject, RevocationSnapshot, TrustStore, verify_sign1,
};

use crate::AuthorityApprovalPolicy;
use crate::contract::{
    DeploymentClassV1, DeploymentNcpWireProfileV1, DeploymentPackageV1, DeploymentRuntimeProfileV1,
};
use crate::error::DeploymentError;

/// Externally selected deployment and target identities.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeploymentIdentityExpectation {
    expected_deployment_authority_id: AsciiId<64>,
    expected_gate_id: GateId,
    expected_realm: AsciiId<64>,
    expected_vehicle_id: VehicleId,
}

impl DeploymentIdentityExpectation {
    /// Construct the exact authority and target identities accepted at bootstrap.
    #[must_use]
    pub const fn new(
        expected_deployment_authority_id: AsciiId<64>,
        expected_gate_id: GateId,
        expected_realm: AsciiId<64>,
        expected_vehicle_id: VehicleId,
    ) -> Self {
        Self {
            expected_deployment_authority_id,
            expected_gate_id,
            expected_realm,
            expected_vehicle_id,
        }
    }
}

/// Externally required assurance, runtime, and NCP-wire profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeploymentProfileRequirement {
    required_profile_class: DeploymentClassV1,
    required_runtime_profile: DeploymentRuntimeProfileV1,
    required_ncp_wire_profile: DeploymentNcpWireProfileV1,
}

impl DeploymentProfileRequirement {
    /// Construct the exact closed execution profile accepted at bootstrap.
    #[must_use]
    pub const fn new(
        required_profile_class: DeploymentClassV1,
        required_runtime_profile: DeploymentRuntimeProfileV1,
        required_ncp_wire_profile: DeploymentNcpWireProfileV1,
    ) -> Self {
        Self {
            required_profile_class,
            required_runtime_profile,
            required_ncp_wire_profile,
        }
    }
}

/// Bootstrap expectations supplied separately from the signed package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeploymentAcceptancePolicy {
    identity: DeploymentIdentityExpectation,
    profile: DeploymentProfileRequirement,
    authority_approval_policy: AuthorityApprovalPolicy,
}

impl DeploymentAcceptancePolicy {
    /// Compose separately selected identity, execution, and authority expectations.
    #[must_use]
    pub const fn new(
        identity: DeploymentIdentityExpectation,
        profile: DeploymentProfileRequirement,
        authority_approval_policy: AuthorityApprovalPolicy,
    ) -> Self {
        Self {
            identity,
            profile,
            authority_approval_policy,
        }
    }

    fn assurance_profile(&self) -> bool {
        self.profile.required_profile_class != DeploymentClassV1::Development
    }
}

/// A strictly decoded package whose signature and external bindings were verified.
///
/// Fields are private so unsigned package values cannot be mistaken for this stage.
pub struct VerifiedDeploymentPackage {
    package: DeploymentPackageV1,
    signer_kid: KeyId,
    signer_subject: KeySubject,
    payload_digest: DeploymentPayloadDigestV1,
    envelope_digest: DigestV1,
    canonical_payload: Box<[u8]>,
    authority_approval_policy: AuthorityApprovalPolicy,
    bootstrap_trust: TrustStore,
    bootstrap_revocations: RevocationSnapshot,
}

impl core::fmt::Debug for VerifiedDeploymentPackage {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("VerifiedDeploymentPackage")
            .field("package", &self.package)
            .field("signer_kid", &self.signer_kid)
            .field("signer_subject", &self.signer_subject)
            .field("payload_digest", &self.payload_digest)
            .field("envelope_digest", &self.envelope_digest)
            .field("canonical_payload_len", &self.canonical_payload.len())
            .finish_non_exhaustive()
    }
}

impl VerifiedDeploymentPackage {
    /// The verified package contract.
    #[must_use]
    pub const fn package(&self) -> &DeploymentPackageV1 {
        &self.package
    }

    /// Trusted deployment-authority key identifier that signed this envelope.
    #[must_use]
    pub const fn signer_kid(&self) -> &KeyId {
        &self.signer_kid
    }

    /// Trusted signer subject matched to `deployment_authority_id`.
    #[must_use]
    pub fn signer_subject(&self) -> &str {
        self.signer_subject.as_str()
    }

    /// Ratchet digest of the exact canonical payload, excluding the COSE envelope.
    #[must_use]
    pub const fn payload_digest(&self) -> DeploymentPayloadDigestV1 {
        self.payload_digest
    }

    /// Audit digest of the exact received COSE envelope.
    #[must_use]
    pub const fn envelope_digest(&self) -> DigestV1 {
        self.envelope_digest
    }

    /// Exact verified canonical package payload bytes.
    #[must_use]
    pub fn canonical_payload(&self) -> &[u8] {
        &self.canonical_payload
    }

    /// Separately configured authority subjects retained from the same package
    /// acceptance policy used for signature/profile verification.
    #[must_use]
    pub const fn authority_approval_policy(&self) -> &AuthorityApprovalPolicy {
        &self.authority_approval_policy
    }

    /// Bootstrap trust retained from package verification for subsequent
    /// authority-approval verification.
    ///
    /// Keeping this snapshot inside the typestate prevents a caller from
    /// substituting a different trust root between package verification and
    /// approval verification.
    #[must_use]
    pub(crate) const fn bootstrap_trust(&self) -> &TrustStore {
        &self.bootstrap_trust
    }

    /// Bootstrap revocation state retained from package verification.
    #[must_use]
    pub(crate) const fn bootstrap_revocations(&self) -> &RevocationSnapshot {
        &self.bootstrap_revocations
    }
}

/// Verify one package envelope against separately supplied bootstrap policy and trust.
///
/// This function performs no entropy, durable-state, secret, artifact-path, or
/// network access. Artifact bytes remain unresolved in the returned stage. The
/// bounded public-key trust and revocation snapshots are cloned into that stage
/// so later role-separated authority approvals cannot be checked under a
/// caller-substituted second root.
///
/// # Errors
/// Returns a stable [`DeploymentError`] on any signature, canonical schema,
/// signer-subject, or external-policy mismatch.
pub fn verify_deployment_package(
    envelope: &[u8],
    policy: &DeploymentAcceptancePolicy,
    bootstrap_trust: &TrustStore,
    bootstrap_revocations: &RevocationSnapshot,
) -> Result<VerifiedDeploymentPackage, DeploymentError> {
    let context = ExpectedContext {
        kind: DeploymentPackageV1::KIND,
        schema_major: 1,
        required_role: KeyRole::DeploymentAuthority,
        assurance_profile: policy.assurance_profile(),
    };
    let verified = verify_sign1(envelope, &context, bootstrap_trust, bootstrap_revocations)?;
    let package = from_canonical_bytes::<DeploymentPackageV1>(verified.payload, Limits::LARGE)?;

    if package.gate_id != policy.identity.expected_gate_id {
        return Err(DeploymentError::GateMismatch);
    }
    if package.realm != policy.identity.expected_realm {
        return Err(DeploymentError::RealmMismatch);
    }
    if package.vehicle_id != policy.identity.expected_vehicle_id {
        return Err(DeploymentError::VehicleMismatch);
    }
    if package.profile_class != policy.profile.required_profile_class {
        return Err(DeploymentError::ProfileMismatch);
    }
    if package.runtime_profile != policy.profile.required_runtime_profile {
        return Err(DeploymentError::RuntimeProfileMismatch);
    }
    if package.ncp_wire_profile != policy.profile.required_ncp_wire_profile {
        return Err(DeploymentError::NcpWireProfileMismatch);
    }
    let signer_subject = verified.signer_subject;
    if signer_subject.as_str() != package.deployment_authority_id.as_str() {
        return Err(DeploymentError::AuthoritySubjectMismatch);
    }
    if package.deployment_authority_id != policy.identity.expected_deployment_authority_id {
        return Err(DeploymentError::AuthorityMismatch);
    }

    Ok(VerifiedDeploymentPackage {
        package,
        signer_kid: verified.signer_kid,
        signer_subject,
        payload_digest: DeploymentPayloadDigestV1::compute(verified.payload),
        envelope_digest: DigestV1::compute(DigestDomain::RawEnvelope, envelope),
        canonical_payload: verified.payload.to_vec().into_boxed_slice(),
        authority_approval_policy: policy.authority_approval_policy.clone(),
        bootstrap_trust: bootstrap_trust.clone(),
        bootstrap_revocations: bootstrap_revocations.clone(),
    })
}
