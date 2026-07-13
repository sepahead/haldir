//! COSE verification against external bootstrap policy and trust.

use haldir_contracts::cbor::{Limits, from_canonical_bytes};
use haldir_contracts::deployment::DeploymentPayloadDigestV1;
use haldir_contracts::digest::{DigestDomain, DigestV1};
use haldir_contracts::ids::{GateId, KeyId, VehicleId};
use haldir_contracts::scalar::AsciiId;
use haldir_crypto::{ExpectedContext, KeyRole, RevocationSnapshot, TrustStore, verify_sign1};

use crate::contract::{
    DeploymentClassV1, DeploymentNcpWireProfileV1, DeploymentPackageV1, DeploymentRuntimeProfileV1,
};
use crate::error::DeploymentError;

/// Bootstrap expectations supplied separately from the signed package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeploymentAcceptancePolicy {
    expected_deployment_authority_id: AsciiId<64>,
    expected_gate_id: GateId,
    expected_realm: AsciiId<64>,
    expected_vehicle_id: VehicleId,
    required_profile_class: DeploymentClassV1,
    required_runtime_profile: DeploymentRuntimeProfileV1,
    required_ncp_wire_profile: DeploymentNcpWireProfileV1,
}

impl DeploymentAcceptancePolicy {
    /// Create separately selected exact package expectations.
    #[must_use]
    pub const fn new(
        expected_deployment_authority_id: AsciiId<64>,
        expected_gate_id: GateId,
        expected_realm: AsciiId<64>,
        expected_vehicle_id: VehicleId,
        required_profile_class: DeploymentClassV1,
        required_runtime_profile: DeploymentRuntimeProfileV1,
        required_ncp_wire_profile: DeploymentNcpWireProfileV1,
    ) -> Self {
        Self {
            expected_deployment_authority_id,
            expected_gate_id,
            expected_realm,
            expected_vehicle_id,
            required_profile_class,
            required_runtime_profile,
            required_ncp_wire_profile,
        }
    }

    fn assurance_profile(&self) -> bool {
        self.required_profile_class != DeploymentClassV1::Development
    }
}

/// A strictly decoded package whose signature and external bindings were verified.
///
/// Fields are private so unsigned package values cannot be mistaken for this stage.
pub struct VerifiedDeploymentPackage {
    package: DeploymentPackageV1,
    signer_kid: KeyId,
    signer_subject: String,
    payload_digest: DeploymentPayloadDigestV1,
    envelope_digest: DigestV1,
    canonical_payload: Box<[u8]>,
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
        &self.signer_subject
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
}

/// Verify one package envelope against separately supplied bootstrap policy and trust.
///
/// This function performs no entropy, durable-state, secret, artifact-path, or
/// network access. Artifact bytes remain unresolved in the returned stage.
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

    if package.gate_id != policy.expected_gate_id {
        return Err(DeploymentError::GateMismatch);
    }
    if package.realm != policy.expected_realm {
        return Err(DeploymentError::RealmMismatch);
    }
    if package.vehicle_id != policy.expected_vehicle_id {
        return Err(DeploymentError::VehicleMismatch);
    }
    if package.profile_class != policy.required_profile_class {
        return Err(DeploymentError::ProfileMismatch);
    }
    if package.runtime_profile != policy.required_runtime_profile {
        return Err(DeploymentError::RuntimeProfileMismatch);
    }
    if package.ncp_wire_profile != policy.required_ncp_wire_profile {
        return Err(DeploymentError::NcpWireProfileMismatch);
    }
    let signer_subject = verified
        .signer_subject
        .ok_or(DeploymentError::AuthoritySubjectMismatch)?;
    if signer_subject != package.deployment_authority_id.as_str() {
        return Err(DeploymentError::AuthoritySubjectMismatch);
    }
    if package.deployment_authority_id != policy.expected_deployment_authority_id {
        return Err(DeploymentError::AuthorityMismatch);
    }

    Ok(VerifiedDeploymentPackage {
        package,
        signer_kid: verified.signer_kid,
        signer_subject,
        payload_digest: DeploymentPayloadDigestV1::compute(verified.payload),
        envelope_digest: DigestV1::compute(DigestDomain::RawEnvelope, envelope),
        canonical_payload: verified.payload.to_vec().into_boxed_slice(),
    })
}
