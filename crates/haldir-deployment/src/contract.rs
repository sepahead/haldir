//! Strict canonical deployment-package contract.

use std::collections::BTreeSet;

use core::num::NonZeroU64;

use haldir_contracts::deployment::DeploymentRevision;
use haldir_contracts::digest::DigestV1;
use haldir_contracts::error::DecodeError;
use haldir_contracts::ids::{GateId, VehicleId};
use haldir_contracts::scalar::{AsciiId, BoundedVec};

/// Number of artifact roles required by deployment-package schema v1.0.
pub const REQUIRED_ARTIFACT_COUNT: usize = 13;

haldir_contracts::tagged_enum! {
    /// Package assurance class exact-matchable against separately passed policy.
    pub enum DeploymentClassV1 {
        Development = 0 => "DEVELOPMENT",
        ExperimentalCanary = 1 => "EXPERIMENTAL_CANARY",
        AssuranceSimulation = 2 => "ASSURANCE_SIMULATION",
    }
}

haldir_contracts::tagged_enum! {
    /// Closed runtime integration selected by a deployment package.
    pub enum DeploymentRuntimeProfileV1 {
        InProcessReference = 0 => "IN_PROCESS_REFERENCE",
        DeclaredLiveZenoh = 1 => "DECLARED_LIVE_ZENOH",
    }
}

haldir_contracts::tagged_enum! {
    /// Closed NCP command-wire selection bound by a deployment package.
    pub enum DeploymentNcpWireProfileV1 {
        ModeledP0 = 0 => "MODELED_P0",
        ExactNcpV0_8Json = 1 => "EXACT_NCP_V0_8_JSON",
    }
}

haldir_contracts::tagged_enum! {
    /// Closed required artifact roles. Unknown roles fail strict decoding.
    pub enum DeploymentArtifactIdV1 {
        GateExecutable = 1 => "GATE_EXECUTABLE",
        GateConfiguration = 2 => "GATE_CONFIGURATION",
        TrustManifest = 3 => "TRUST_MANIFEST",
        AdmissionSnapshot = 4 => "ADMISSION_SNAPSHOT",
        RevocationSnapshot = 5 => "REVOCATION_SNAPSHOT",
        PolicySnapshot = 6 => "POLICY_SNAPSHOT",
        NcpCompatibility = 7 => "NCP_COMPATIBILITY",
        SecureTransportProfile = 8 => "SECURE_TRANSPORT_PROFILE",
        EvidenceProfile = 9 => "EVIDENCE_PROFILE",
        ProcessHardeningProfile = 10 => "PROCESS_HARDENING_PROFILE",
        RouterIdentity = 11 => "ROUTER_IDENTITY",
        CredentialIdentity = 12 => "CREDENTIAL_IDENTITY",
        SourceLedger = 13 => "SOURCE_LEDGER",
    }
}

impl DeploymentArtifactIdV1 {
    /// Every required v1.0 role in canonical wire-tag order.
    pub const ALL: [Self; REQUIRED_ARTIFACT_COUNT] = [
        Self::GateExecutable,
        Self::GateConfiguration,
        Self::TrustManifest,
        Self::AdmissionSnapshot,
        Self::RevocationSnapshot,
        Self::PolicySnapshot,
        Self::NcpCompatibility,
        Self::SecureTransportProfile,
        Self::EvidenceProfile,
        Self::ProcessHardeningProfile,
        Self::RouterIdentity,
        Self::CredentialIdentity,
        Self::SourceLedger,
    ];
}

haldir_contracts::canonical_struct! {
    /// Exact immutable bytes required for one closed deployment artifact role.
    pub struct DeploymentArtifactRefV1 {
        req 1 role: DeploymentArtifactIdV1,
        req 2 logical_id: AsciiId<64>,
        req 3 digest: DigestV1,
        req 4 size_bytes: NonZeroU64,
    }
}

haldir_contracts::canonical_struct! {
    /// Signed schema v1.0 package binding deployment identities and artifact bytes.
    pub struct DeploymentPackageV1 kind "haldir.deployment_package" {
        req 2 schema_major: u16,
        req 3 schema_minor: u16,
        req 4 deployment_authority_id: AsciiId<64>,
        req 5 deployment_id: AsciiId<64>,
        req 6 deployment_revision: DeploymentRevision,
        req 7 profile_class: DeploymentClassV1,
        req 8 gate_id: GateId,
        req 9 realm: AsciiId<64>,
        req 10 vehicle_id: VehicleId,
        req 11 runtime_profile: DeploymentRuntimeProfileV1,
        req 12 ncp_wire_profile: DeploymentNcpWireProfileV1,
        req 13 state_store_id: [u8; 16],
        req 14 journal_id: [u8; 16],
        req 15 artifacts: BoundedVec<DeploymentArtifactRefV1, REQUIRED_ARTIFACT_COUNT>,
    }
}

impl haldir_contracts::cbor::Validate for DeploymentPackageV1 {
    fn validate(&self) -> Result<(), DecodeError> {
        if self.schema_major != 1 || self.schema_minor != 0 {
            return Err(DecodeError::UnsupportedVersion);
        }
        if self.state_store_id == [0; 16]
            || self.journal_id == [0; 16]
            || self.state_store_id == self.journal_id
        {
            return Err(DecodeError::SemanticInvalid {
                code: "DEPLOYMENT_DURABLE_ID_INVALID",
            });
        }
        if self.runtime_profile == DeploymentRuntimeProfileV1::DeclaredLiveZenoh
            && self.ncp_wire_profile != DeploymentNcpWireProfileV1::ExactNcpV0_8Json
        {
            return Err(DecodeError::SemanticInvalid {
                code: "DEPLOYMENT_LIVE_NCP_PROFILE_INVALID",
            });
        }
        if self.artifacts.len() != REQUIRED_ARTIFACT_COUNT {
            return Err(DecodeError::SemanticInvalid {
                code: "DEPLOYMENT_ARTIFACT_SET_INCOMPLETE",
            });
        }

        let mut logical_ids = BTreeSet::new();
        let mut total_size = 0u64;
        for (artifact, required_role) in self
            .artifacts
            .as_slice()
            .iter()
            .zip(DeploymentArtifactIdV1::ALL)
        {
            if artifact.role != required_role {
                return Err(DecodeError::SemanticInvalid {
                    code: "DEPLOYMENT_ARTIFACT_SET_NONCANONICAL",
                });
            }
            if !logical_ids.insert(artifact.logical_id.as_str()) {
                return Err(DecodeError::SemanticInvalid {
                    code: "DEPLOYMENT_ARTIFACT_LOGICAL_ID_DUPLICATE",
                });
            }
            total_size = total_size.checked_add(artifact.size_bytes.get()).ok_or(
                DecodeError::SemanticInvalid {
                    code: "DEPLOYMENT_ARTIFACT_SIZE_OVERFLOW",
                },
            )?;
        }
        Ok(())
    }
}
