use core::num::{NonZeroU32, NonZeroU64};

#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::fs::{self, File};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::path::{Path, PathBuf};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::sync::atomic::{AtomicU64, Ordering};

use haldir_contracts::cbor::{Limits, from_canonical_bytes, to_canonical_bytes};
use haldir_contracts::deployment::DeploymentRevision;
use haldir_contracts::digest::{DigestDomain, DigestV1};
use haldir_contracts::ids::{GateId, JournalId, KeyId, PrincipalId, VehicleId};
use haldir_contracts::scalar::{AsciiId, BoundedVec, CanonicalUuidV4String};
use haldir_contracts::session::NcpSessionIdentityV1;
use haldir_crypto::{
    KeyClass, KeyRecord, KeyRole, KeySubject, RevocationSnapshot, SigningKey, TrustStore,
    content_type_for, external_aad_for, sign_message,
};
use proptest::prelude::*;

use super::*;
use crate::contract::{
    AclPublicationBindingV1, AuthoritySnapshotApprovalV1, AuthoritySnapshotKindV1,
    DeploymentArtifactIdV1, DeploymentArtifactRefV1, DeploymentClassV1, DeploymentNcpWireProfileV1,
    DeploymentPackageV1, DeploymentRuntimeProfileV1, GateConfigurationArtifactV1,
};

fn gate_configuration() -> GateConfigurationArtifactV1 {
    let signer = SigningKey::from_seed([44; 32]).expect("nonzero test seed");
    GateConfigurationArtifactV1 {
        schema_major: 1,
        schema_minor: 0,
        gate_id: GateId::new("gate-1").unwrap(),
        realm: AsciiId::new("range-a").unwrap(),
        vehicle_id: VehicleId::new("uav-1").unwrap(),
        profile_class: DeploymentClassV1::AssuranceSimulation,
        runtime_profile: DeploymentRuntimeProfileV1::DeclaredLiveZenoh,
        ncp_wire_profile: DeploymentNcpWireProfileV1::ExactNcpV0_8Json,
        state_store_id: [1; 16],
        journal_id: JournalId::new([2; 16]).unwrap(),
        trust_snapshot_digest: DigestV1::compute(DigestDomain::TrustStoreSnapshot, b"trust"),
        revocation_snapshot_digest: DigestV1::compute(
            DigestDomain::RevocationSnapshot,
            b"revocations",
        ),
        admission_snapshot_digest: DigestV1::compute(DigestDomain::AdmissionSnapshot, b"admission"),
        policy_snapshot_digest: DigestV1::compute(DigestDomain::PolicySnapshot, b"policy"),
        session: NcpSessionIdentityV1 {
            session_id: AsciiId::new("session-1").unwrap(),
            generation: CanonicalUuidV4String::from_random_bytes([1; 16]),
        },
        publication: AclPublicationBindingV1 {
            gate_transport_principal: PrincipalId::new("gate-transport").unwrap(),
            final_route_digest: DigestV1::compute(DigestDomain::TransportKey, b"final-route"),
            certificate_fingerprint: DigestV1::compute(DigestDomain::Payload, b"certificate"),
            acl_policy_digest: DigestV1::compute(DigestDomain::Payload, b"acl"),
        },
        local_cap_ms: NonZeroU32::new(1_000).unwrap(),
        gate_signer_kid: KeyId::new(vec![44, 0xa5]).unwrap(),
        gate_signer_public_key: signer.verifying_key().to_bytes(),
    }
}

fn artifact_bytes(role: DeploymentArtifactIdV1) -> Vec<u8> {
    match role {
        DeploymentArtifactIdV1::GateConfiguration => to_canonical_bytes(&gate_configuration()),
        DeploymentArtifactIdV1::NcpCompatibility => {
            haldir_ncp08::pinned_ncp_compatibility_artifact_bytes().unwrap()
        }
        DeploymentArtifactIdV1::TrustManifest
        | DeploymentArtifactIdV1::AdmissionSnapshot
        | DeploymentArtifactIdV1::RevocationSnapshot
        | DeploymentArtifactIdV1::PolicySnapshot => signed_authority_approval(role),
        _ => vec![u8::try_from(role.tag()).unwrap(); usize::try_from(role.tag()).unwrap() + 1],
    }
}

fn authority_spec(
    role: DeploymentArtifactIdV1,
) -> (AuthoritySnapshotKindV1, KeyRole, u8, &'static str, DigestV1) {
    let configuration = gate_configuration();
    match role {
        DeploymentArtifactIdV1::TrustManifest => (
            AuthoritySnapshotKindV1::Trust,
            KeyRole::TrustAuthority,
            51,
            "trust-authority-a",
            configuration.trust_snapshot_digest,
        ),
        DeploymentArtifactIdV1::AdmissionSnapshot => (
            AuthoritySnapshotKindV1::Admission,
            KeyRole::AdmissionAuthority,
            52,
            "admission-authority-a",
            configuration.admission_snapshot_digest,
        ),
        DeploymentArtifactIdV1::RevocationSnapshot => (
            AuthoritySnapshotKindV1::Revocation,
            KeyRole::RevocationAuthority,
            53,
            "revocation-authority-a",
            configuration.revocation_snapshot_digest,
        ),
        DeploymentArtifactIdV1::PolicySnapshot => (
            AuthoritySnapshotKindV1::Policy,
            KeyRole::PolicyAuthority,
            54,
            "policy-authority-a",
            configuration.policy_snapshot_digest,
        ),
        _ => panic!("artifact role is not an authority approval"),
    }
}

fn authority_approval(role: DeploymentArtifactIdV1) -> AuthoritySnapshotApprovalV1 {
    let (snapshot_kind, _, _, issuer_id, snapshot_digest) = authority_spec(role);
    AuthoritySnapshotApprovalV1 {
        schema_major: 1,
        schema_minor: 0,
        snapshot_kind,
        issuer_id: AsciiId::new(issuer_id).unwrap(),
        deployment_id: AsciiId::new("deployment-a").unwrap(),
        deployment_revision: DeploymentRevision::new(NonZeroU64::new(7).unwrap()),
        gate_id: GateId::new("gate-1").unwrap(),
        realm: AsciiId::new("range-a").unwrap(),
        vehicle_id: VehicleId::new("uav-1").unwrap(),
        snapshot_digest,
    }
}

fn signed_authority_approval(role: DeploymentArtifactIdV1) -> Vec<u8> {
    let (_, _, seed, _, _) = authority_spec(role);
    let signer = SigningKey::from_seed([seed; 32]).expect("nonzero test seed");
    sign_message(
        &authority_approval(role),
        AuthoritySnapshotApprovalV1::KIND,
        1,
        &key_id(seed),
        &signer,
    )
}

fn authority_policy() -> AuthorityApprovalPolicy {
    AuthorityApprovalPolicy::new(
        AsciiId::new("trust-authority-a").unwrap(),
        AsciiId::new("admission-authority-a").unwrap(),
        AsciiId::new("revocation-authority-a").unwrap(),
        AsciiId::new("policy-authority-a").unwrap(),
    )
}

fn insert_authority_trust(trust: &mut TrustStore, class: KeyClass) {
    for role in [
        DeploymentArtifactIdV1::TrustManifest,
        DeploymentArtifactIdV1::AdmissionSnapshot,
        DeploymentArtifactIdV1::RevocationSnapshot,
        DeploymentArtifactIdV1::PolicySnapshot,
    ] {
        let (_, key_role, seed, subject, _) = authority_spec(role);
        let signer = SigningKey::from_seed([seed; 32]).expect("nonzero test seed");
        trust
            .insert(trust_record(
                &key_id(seed),
                &signer,
                key_role,
                class,
                subject,
            ))
            .unwrap();
    }
}

fn artifact_logical_id(role: DeploymentArtifactIdV1) -> AsciiId<64> {
    AsciiId::new(&format!("artifact-{}", role.tag())).unwrap()
}

fn artifact_ref(role: DeploymentArtifactIdV1) -> DeploymentArtifactRefV1 {
    let bytes = artifact_bytes(role);
    DeploymentArtifactRefV1 {
        role,
        logical_id: artifact_logical_id(role),
        digest: DigestV1::compute(DigestDomain::DeploymentArtifact, &bytes),
        size_bytes: NonZeroU64::new(u64::try_from(bytes.len()).unwrap()).unwrap(),
    }
}

fn package() -> DeploymentPackageV1 {
    DeploymentPackageV1 {
        schema_major: 1,
        schema_minor: 0,
        deployment_authority_id: AsciiId::new("deployment-authority-a").unwrap(),
        deployment_id: AsciiId::new("deployment-a").unwrap(),
        deployment_revision: DeploymentRevision::new(NonZeroU64::new(7).unwrap()),
        profile_class: DeploymentClassV1::AssuranceSimulation,
        gate_id: GateId::new("gate-1").unwrap(),
        realm: AsciiId::new("range-a").unwrap(),
        vehicle_id: VehicleId::new("uav-1").unwrap(),
        runtime_profile: DeploymentRuntimeProfileV1::DeclaredLiveZenoh,
        ncp_wire_profile: DeploymentNcpWireProfileV1::ExactNcpV0_8Json,
        state_store_id: [1; 16],
        journal_id: JournalId::new([2; 16]).unwrap(),
        artifacts: BoundedVec::from_vec(
            DeploymentArtifactIdV1::ALL
                .into_iter()
                .map(artifact_ref)
                .collect(),
        )
        .unwrap(),
    }
}

fn policy() -> DeploymentAcceptancePolicy {
    DeploymentAcceptancePolicy::new(
        DeploymentIdentityExpectation::new(
            AsciiId::new("deployment-authority-a").unwrap(),
            GateId::new("gate-1").unwrap(),
            AsciiId::new("range-a").unwrap(),
            VehicleId::new("uav-1").unwrap(),
        ),
        DeploymentProfileRequirement::new(
            DeploymentClassV1::AssuranceSimulation,
            DeploymentRuntimeProfileV1::DeclaredLiveZenoh,
            DeploymentNcpWireProfileV1::ExactNcpV0_8Json,
        ),
        authority_policy(),
    )
}

fn key_id(seed: u8) -> KeyId {
    KeyId::new(vec![seed, 0xa5]).unwrap()
}

fn trust_record(
    key_id: &KeyId,
    signer: &SigningKey,
    role: KeyRole,
    class: KeyClass,
    subject: &str,
) -> KeyRecord {
    KeyRecord {
        kid: key_id.clone(),
        role,
        verifying_key: signer.verifying_key(),
        subject: KeySubject::new(subject).unwrap(),
        class,
    }
}

fn signed_with(
    package: &DeploymentPackageV1,
    seed: u8,
    role: KeyRole,
    class: KeyClass,
    subject: &str,
) -> (Vec<u8>, TrustStore, KeyId) {
    let signer = SigningKey::from_seed([seed; 32]).expect("nonzero test seed");
    let key_id = key_id(seed);
    let mut trust = TrustStore::new();
    trust
        .insert(trust_record(&key_id, &signer, role, class, subject))
        .unwrap();
    let envelope = sign_message(package, DeploymentPackageV1::KIND, 1, &key_id, &signer);
    (envelope, trust, key_id)
}

fn signed_with_authority_trust(
    package: &DeploymentPackageV1,
    seed: u8,
    role: KeyRole,
    class: KeyClass,
    subject: &str,
    authority_class: KeyClass,
) -> (Vec<u8>, TrustStore, KeyId) {
    let (envelope, mut trust, key_id) = signed_with(package, seed, role, class, subject);
    insert_authority_trust(&mut trust, authority_class);
    (envelope, trust, key_id)
}

fn verified() -> VerifiedDeploymentPackage {
    verified_with_authority_class(KeyClass::Assurance)
}

fn verified_with_authority_class(authority_class: KeyClass) -> VerifiedDeploymentPackage {
    let (envelope, trust, _) = signed_with_authority_trust(
        &package(),
        1,
        KeyRole::DeploymentAuthority,
        KeyClass::Assurance,
        "deployment-authority-a",
        authority_class,
    );
    verify_deployment_package(&envelope, &policy(), &trust, &RevocationSnapshot::new()).unwrap()
}

fn ncp_validated_with_gate_configuration(
    configuration: &GateConfigurationArtifactV1,
) -> NcpValidatedDeploymentPackage {
    let configuration_bytes = to_canonical_bytes(configuration);
    let mut configured_package = package();
    let mut references = configured_package.artifacts.as_slice().to_vec();
    let reference = references
        .iter_mut()
        .find(|reference| reference.role == DeploymentArtifactIdV1::GateConfiguration)
        .unwrap();
    reference.digest = DigestV1::compute(DigestDomain::DeploymentArtifact, &configuration_bytes);
    reference.size_bytes =
        NonZeroU64::new(u64::try_from(configuration_bytes.len()).unwrap()).unwrap();
    configured_package.artifacts = BoundedVec::from_vec(references).unwrap();

    let (envelope, trust, _) = signed_with(
        &configured_package,
        92,
        KeyRole::DeploymentAuthority,
        KeyClass::Assurance,
        "deployment-authority-a",
    );
    let verified =
        verify_deployment_package(&envelope, &policy(), &trust, &RevocationSnapshot::new())
            .unwrap();
    let inputs =
        DeploymentArtifactSet::from_inputs(configured_package.artifacts.as_slice().iter().map(
            |artifact| {
                let bytes = if artifact.role == DeploymentArtifactIdV1::GateConfiguration {
                    configuration_bytes.clone()
                } else {
                    artifact_bytes(artifact.role)
                };
                DeploymentArtifactInput::new(artifact.role, artifact.logical_id.clone(), bytes)
            },
        ))
        .unwrap();
    verified
        .resolve_artifacts(inputs, ArtifactLimits::new(4096, 16 * 1024).unwrap())
        .unwrap()
        .validate_ncp_compatibility()
        .unwrap()
}

fn gate_configuration_validated_with_artifact(
    role: DeploymentArtifactIdV1,
    bytes: Vec<u8>,
) -> GateConfigurationValidatedDeploymentPackage {
    let mut configured_package = package();
    let mut references = configured_package.artifacts.as_slice().to_vec();
    let reference = references
        .iter_mut()
        .find(|reference| reference.role == role)
        .unwrap();
    reference.digest = DigestV1::compute(DigestDomain::DeploymentArtifact, &bytes);
    reference.size_bytes = NonZeroU64::new(u64::try_from(bytes.len()).unwrap()).unwrap();
    configured_package.artifacts = BoundedVec::from_vec(references).unwrap();

    let (envelope, trust, _) = signed_with_authority_trust(
        &configured_package,
        93,
        KeyRole::DeploymentAuthority,
        KeyClass::Assurance,
        "deployment-authority-a",
        KeyClass::Assurance,
    );
    let verified =
        verify_deployment_package(&envelope, &policy(), &trust, &RevocationSnapshot::new())
            .unwrap();
    let inputs =
        DeploymentArtifactSet::from_inputs(configured_package.artifacts.as_slice().iter().map(
            |artifact| {
                DeploymentArtifactInput::new(
                    artifact.role,
                    artifact.logical_id.clone(),
                    if artifact.role == role {
                        bytes.clone()
                    } else {
                        artifact_bytes(artifact.role)
                    },
                )
            },
        ))
        .unwrap();
    verified
        .resolve_artifacts(inputs, ArtifactLimits::new(4096, 16 * 1024).unwrap())
        .unwrap()
        .validate_ncp_compatibility()
        .unwrap()
        .validate_gate_configuration()
        .unwrap()
}

fn artifact_inputs(package: &DeploymentPackageV1) -> DeploymentArtifactSet {
    DeploymentArtifactSet::from_inputs(package.artifacts.as_slice().iter().map(|artifact| {
        DeploymentArtifactInput::new(
            artifact.role,
            artifact.logical_id.clone(),
            artifact_bytes(artifact.role),
        )
    }))
    .unwrap()
}

#[test]
fn signed_ncp_role_composes_into_a_compiled_compatibility_proof() {
    let resolved = verified()
        .resolve_artifacts(
            artifact_inputs(&package()),
            ArtifactLimits::new(1024, 4096).unwrap(),
        )
        .unwrap();
    let validated = resolved.validate_ncp_compatibility().unwrap();

    assert_eq!(
        validated.ncp_compatibility().compatibility_id(),
        haldir_ncp08::NCP_V0_8_0.compatibility_id()
    );
    assert_eq!(
        validated
            .resolved()
            .artifact(DeploymentArtifactIdV1::NcpCompatibility),
        Some(
            haldir_ncp08::pinned_ncp_compatibility_artifact_bytes()
                .unwrap()
                .as_slice()
        )
    );

    let configured = validated.validate_gate_configuration().unwrap();
    assert_eq!(configured.gate_configuration(), &gate_configuration());
}

#[test]
fn independently_signed_snapshot_approvals_compose_into_startup_authority() {
    let configured = verified()
        .resolve_artifacts(
            artifact_inputs(&package()),
            ArtifactLimits::new(4096, 16 * 1024).unwrap(),
        )
        .unwrap()
        .validate_ncp_compatibility()
        .unwrap()
        .validate_gate_configuration()
        .unwrap();

    let validated = configured.validate_authority_approvals().unwrap();

    for kind in [
        AuthoritySnapshotKindV1::Trust,
        AuthoritySnapshotKindV1::Admission,
        AuthoritySnapshotKindV1::Revocation,
        AuthoritySnapshotKindV1::Policy,
    ] {
        let approval = validated.approval(kind).unwrap();
        assert_eq!(approval.approval().snapshot_kind, kind);
        assert_eq!(
            approval.signer_subject(),
            approval.approval().issuer_id.as_str()
        );
    }
}

#[test]
fn snapshot_approval_cannot_authorize_a_different_runtime_digest() {
    let role = DeploymentArtifactIdV1::PolicySnapshot;
    let mut approval = authority_approval(role);
    approval.snapshot_digest = DigestV1::compute(DigestDomain::PolicySnapshot, b"other-policy");
    let (_, _, seed, _, _) = authority_spec(role);
    let signer = SigningKey::from_seed([seed; 32]).expect("nonzero test seed");
    let bytes = sign_message(
        &approval,
        AuthoritySnapshotApprovalV1::KIND,
        1,
        &key_id(seed),
        &signer,
    );
    let configured = gate_configuration_validated_with_artifact(role, bytes);

    assert_eq!(
        configured.validate_authority_approvals().unwrap_err(),
        DeploymentError::AuthorityApprovalDigestMismatch(AuthoritySnapshotKindV1::Policy)
    );
}

#[test]
fn snapshot_approval_cannot_be_replayed_into_another_package_revision() {
    let role = DeploymentArtifactIdV1::TrustManifest;
    let mut approval = authority_approval(role);
    approval.deployment_revision = DeploymentRevision::new(NonZeroU64::new(6).unwrap());
    let (_, _, seed, _, _) = authority_spec(role);
    let signer = SigningKey::from_seed([seed; 32]).expect("nonzero test seed");
    let bytes = sign_message(
        &approval,
        AuthoritySnapshotApprovalV1::KIND,
        1,
        &key_id(seed),
        &signer,
    );
    let configured = gate_configuration_validated_with_artifact(role, bytes);

    assert_eq!(
        configured.validate_authority_approvals().unwrap_err(),
        DeploymentError::AuthorityApprovalPackageMismatch(AuthoritySnapshotKindV1::Trust)
    );
}

#[test]
fn separately_expected_snapshot_authorities_cannot_be_selected_by_the_package() {
    let different_policy = AuthorityApprovalPolicy::new(
        AsciiId::new("different-trust-authority").unwrap(),
        AsciiId::new("admission-authority-a").unwrap(),
        AsciiId::new("revocation-authority-a").unwrap(),
        AsciiId::new("policy-authority-a").unwrap(),
    );

    let mut differently_bound_package = package();
    differently_bound_package.deployment_authority_id =
        AsciiId::new("deployment-authority-a").unwrap();
    let (envelope, trust, _) = signed_with_authority_trust(
        &differently_bound_package,
        94,
        KeyRole::DeploymentAuthority,
        KeyClass::Assurance,
        "deployment-authority-a",
        KeyClass::Assurance,
    );
    let acceptance = DeploymentAcceptancePolicy::new(
        DeploymentIdentityExpectation::new(
            AsciiId::new("deployment-authority-a").unwrap(),
            GateId::new("gate-1").unwrap(),
            AsciiId::new("range-a").unwrap(),
            VehicleId::new("uav-1").unwrap(),
        ),
        DeploymentProfileRequirement::new(
            DeploymentClassV1::AssuranceSimulation,
            DeploymentRuntimeProfileV1::DeclaredLiveZenoh,
            DeploymentNcpWireProfileV1::ExactNcpV0_8Json,
        ),
        different_policy,
    );
    let configured =
        verify_deployment_package(&envelope, &acceptance, &trust, &RevocationSnapshot::new())
            .unwrap()
            .resolve_artifacts(
                artifact_inputs(&differently_bound_package),
                ArtifactLimits::new(4096, 16 * 1024).unwrap(),
            )
            .unwrap()
            .validate_ncp_compatibility()
            .unwrap()
            .validate_gate_configuration()
            .unwrap();

    assert_eq!(
        configured.validate_authority_approvals().unwrap_err(),
        DeploymentError::AuthorityApprovalPolicyMismatch(AuthoritySnapshotKindV1::Trust)
    );
}

#[test]
fn assurance_snapshot_approval_rejects_development_keys() {
    let configured = verified_with_authority_class(KeyClass::Development)
        .resolve_artifacts(
            artifact_inputs(&package()),
            ArtifactLimits::new(4096, 16 * 1024).unwrap(),
        )
        .unwrap()
        .validate_ncp_compatibility()
        .unwrap()
        .validate_gate_configuration()
        .unwrap();

    assert_eq!(
        configured.validate_authority_approvals().unwrap_err(),
        DeploymentError::Crypto(haldir_crypto::CryptoError::DevelopmentKeyInAssurance)
    );
}

#[test]
fn approval_verification_cannot_introduce_a_second_trust_root() {
    let (envelope, trust, _) = signed_with(
        &package(),
        95,
        KeyRole::DeploymentAuthority,
        KeyClass::Assurance,
        "deployment-authority-a",
    );
    let configured =
        verify_deployment_package(&envelope, &policy(), &trust, &RevocationSnapshot::new())
            .unwrap()
            .resolve_artifacts(
                artifact_inputs(&package()),
                ArtifactLimits::new(4096, 16 * 1024).unwrap(),
            )
            .unwrap()
            .validate_ncp_compatibility()
            .unwrap()
            .validate_gate_configuration()
            .unwrap();

    assert_eq!(
        configured.validate_authority_approvals().unwrap_err(),
        DeploymentError::Crypto(haldir_crypto::CryptoError::KidUnknown)
    );
}

#[test]
fn approval_verification_uses_the_revocations_retained_at_package_verification() {
    let (envelope, trust, _) = signed_with_authority_trust(
        &package(),
        96,
        KeyRole::DeploymentAuthority,
        KeyClass::Assurance,
        "deployment-authority-a",
        KeyClass::Assurance,
    );
    let mut bootstrap_revocations = RevocationSnapshot::new();
    bootstrap_revocations.revoke_key(&key_id(51), 1).unwrap();

    let configured =
        verify_deployment_package(&envelope, &policy(), &trust, &bootstrap_revocations)
            .unwrap()
            .resolve_artifacts(
                artifact_inputs(&package()),
                ArtifactLimits::new(4096, 16 * 1024).unwrap(),
            )
            .unwrap()
            .validate_ncp_compatibility()
            .unwrap()
            .validate_gate_configuration()
            .unwrap();

    assert_eq!(
        configured.validate_authority_approvals().unwrap_err(),
        DeploymentError::Crypto(haldir_crypto::CryptoError::KeyRevoked)
    );
}

#[test]
fn signed_gate_configuration_cross_binds_redundant_package_identity() {
    let mut configuration = gate_configuration();
    configuration.gate_id = GateId::new("gate-2").unwrap();
    let ncp_validated = ncp_validated_with_gate_configuration(&configuration);
    let error = ncp_validated.validate_gate_configuration().unwrap_err();

    assert_eq!(error, DeploymentError::GateConfigurationPackageMismatch);
    assert_eq!(
        error.reason_code(),
        "DEPLOYMENT_GATE_CONFIGURATION_PACKAGE_MISMATCH"
    );
    assert_eq!(
        error.to_string(),
        "DEPLOYMENT_GATE_CONFIGURATION_PACKAGE_MISMATCH"
    );
}

#[test]
fn gate_configuration_artifact_digest_vector_is_stable() {
    assert_eq!(
        DigestV1::compute(
            DigestDomain::DeploymentArtifact,
            &to_canonical_bytes(&gate_configuration())
        )
        .value,
        [
            186, 174, 62, 97, 240, 245, 36, 153, 73, 76, 94, 171, 6, 208, 114, 70, 96, 189, 173,
            131, 16, 99, 57, 179, 82, 225, 207, 75, 117, 84, 6, 78,
        ]
    );
}

#[test]
fn gate_configuration_artifact_rejects_an_invalid_signer_point() {
    let mut configuration = gate_configuration();
    configuration.gate_signer_public_key = [0; 32];

    assert_eq!(
        from_canonical_bytes::<GateConfigurationArtifactV1>(
            &to_canonical_bytes(&configuration),
            Limits::DEFAULT,
        ),
        Err(haldir_contracts::DecodeError::SemanticInvalid {
            code: "GATE_CONFIGURATION_SIGNER_KEY_INVALID",
        })
    );
}

#[test]
fn gate_configuration_artifact_rejects_an_inexact_live_wire_profile() {
    let mut configuration = gate_configuration();
    configuration.ncp_wire_profile = DeploymentNcpWireProfileV1::ModeledP0;

    assert_eq!(
        from_canonical_bytes::<GateConfigurationArtifactV1>(
            &to_canonical_bytes(&configuration),
            Limits::DEFAULT,
        ),
        Err(haldir_contracts::DecodeError::SemanticInvalid {
            code: "GATE_CONFIGURATION_LIVE_NCP_PROFILE_INVALID",
        })
    );
}

#[test]
fn gate_configuration_artifact_rejects_aliased_durable_identities() {
    let mut configuration = gate_configuration();
    configuration.state_store_id = *configuration.journal_id.as_bytes();

    assert_eq!(
        from_canonical_bytes::<GateConfigurationArtifactV1>(
            &to_canonical_bytes(&configuration),
            Limits::DEFAULT,
        ),
        Err(haldir_contracts::DecodeError::SemanticInvalid {
            code: "GATE_CONFIGURATION_DURABLE_ID_INVALID",
        })
    );
}

#[test]
fn signed_gate_configuration_rejects_unsupported_schema_before_runtime_use() {
    let mut configuration = gate_configuration();
    configuration.schema_minor = 1;
    let ncp_validated = ncp_validated_with_gate_configuration(&configuration);

    assert_eq!(
        ncp_validated.validate_gate_configuration().unwrap_err(),
        DeploymentError::Decode(haldir_contracts::DecodeError::UnsupportedVersion)
    );
}

#[test]
fn signed_but_incompatible_ncp_role_fails_the_consuming_typestate() {
    let mut incompatible = haldir_ncp08::NcpCompatibilityArtifactV1::pinned().unwrap();
    incompatible.ncp_tag = AsciiId::new("v0.8.1").unwrap();
    let incompatible_bytes = to_canonical_bytes(&incompatible);
    let mut incompatible_package = package();
    let mut refs = incompatible_package.artifacts.as_slice().to_vec();
    let reference = refs
        .iter_mut()
        .find(|reference| reference.role == DeploymentArtifactIdV1::NcpCompatibility)
        .unwrap();
    reference.digest = DigestV1::compute(DigestDomain::DeploymentArtifact, &incompatible_bytes);
    reference.size_bytes =
        NonZeroU64::new(u64::try_from(incompatible_bytes.len()).unwrap()).unwrap();
    incompatible_package.artifacts = BoundedVec::from_vec(refs).unwrap();

    let (envelope, trust, _) = signed_with(
        &incompatible_package,
        91,
        KeyRole::DeploymentAuthority,
        KeyClass::Assurance,
        "deployment-authority-a",
    );
    let verified =
        verify_deployment_package(&envelope, &policy(), &trust, &RevocationSnapshot::new())
            .unwrap();
    let inputs =
        DeploymentArtifactSet::from_inputs(incompatible_package.artifacts.as_slice().iter().map(
            |artifact| {
                let bytes = if artifact.role == DeploymentArtifactIdV1::NcpCompatibility {
                    incompatible_bytes.clone()
                } else {
                    artifact_bytes(artifact.role)
                };
                DeploymentArtifactInput::new(artifact.role, artifact.logical_id.clone(), bytes)
            },
        ))
        .unwrap();
    let resolved = verified
        .resolve_artifacts(inputs, ArtifactLimits::new(1024, 4096).unwrap())
        .unwrap();

    let error = resolved.validate_ncp_compatibility().unwrap_err();
    assert!(matches!(
        error,
        DeploymentError::NcpCompatibility(haldir_ncp08::NcpCompatibilityError::PinMismatch)
    ));
    assert!(std::error::Error::source(&error).is_some());
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
static TEST_DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[cfg(any(target_os = "linux", target_os = "macos"))]
struct TestArtifactDirectory(PathBuf);

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl TestArtifactDirectory {
    fn new() -> Self {
        let sequence = TEST_DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "haldir-deployment-source-test-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl Drop for TestArtifactDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn write_artifact_files(root: &Path, package: &DeploymentPackageV1) {
    for artifact in package.artifacts.as_slice() {
        fs::write(
            root.join(artifact.logical_id.as_str()),
            artifact_bytes(artifact.role),
        )
        .unwrap();
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn artifact_path(
    root: &Path,
    package: &DeploymentPackageV1,
    role: DeploymentArtifactIdV1,
) -> PathBuf {
    let logical_id = package
        .artifacts
        .as_slice()
        .iter()
        .find(|artifact| artifact.role == role)
        .unwrap()
        .logical_id
        .as_str();
    root.join(logical_id)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn artifact_source(root: &Path) -> ArtifactDirectory {
    ArtifactDirectory::from_directory(File::open(root).unwrap()).unwrap()
}

#[test]
fn package_roundtrips_and_required_artifacts_are_exact() {
    let package = package();
    let bytes = to_canonical_bytes(&package);
    let decoded = from_canonical_bytes::<DeploymentPackageV1>(&bytes, Limits::LARGE).unwrap();

    assert_eq!(decoded, package);
    assert_eq!(
        decoded
            .artifacts
            .as_slice()
            .iter()
            .map(|artifact| artifact.role)
            .collect::<Vec<_>>(),
        DeploymentArtifactIdV1::ALL
    );
}

#[test]
fn contract_rejects_missing_duplicate_or_misordered_artifacts() {
    let mut missing = package();
    missing.artifacts = BoundedVec::from_vec(missing.artifacts.as_slice()[..12].to_vec()).unwrap();
    assert!(
        from_canonical_bytes::<DeploymentPackageV1>(&to_canonical_bytes(&missing), Limits::LARGE)
            .is_err()
    );

    let mut duplicate_id = package();
    duplicate_id.artifacts = BoundedVec::from_vec({
        let mut refs = duplicate_id.artifacts.as_slice().to_vec();
        refs[1].logical_id = refs[0].logical_id.clone();
        refs
    })
    .unwrap();
    assert!(
        from_canonical_bytes::<DeploymentPackageV1>(
            &to_canonical_bytes(&duplicate_id),
            Limits::LARGE
        )
        .is_err()
    );

    let mut misordered = package();
    misordered.artifacts = BoundedVec::from_vec({
        let mut refs = misordered.artifacts.as_slice().to_vec();
        refs.swap(0, 1);
        refs
    })
    .unwrap();
    assert!(
        from_canonical_bytes::<DeploymentPackageV1>(
            &to_canonical_bytes(&misordered),
            Limits::LARGE
        )
        .is_err()
    );
}

#[test]
fn contract_rejects_versions_durable_ids_and_inexact_live_ncp() {
    let mut bad_version = package();
    bad_version.schema_minor = 1;
    assert!(
        from_canonical_bytes::<DeploymentPackageV1>(
            &to_canonical_bytes(&bad_version),
            Limits::LARGE
        )
        .is_err()
    );

    let mut alias = package();
    alias.journal_id = haldir_contracts::ids::JournalId::new(alias.state_store_id).unwrap();
    assert!(
        from_canonical_bytes::<DeploymentPackageV1>(&to_canonical_bytes(&alias), Limits::LARGE)
            .is_err()
    );

    let mut zero_store_id = package();
    zero_store_id.state_store_id = [0; 16];
    assert!(
        from_canonical_bytes::<DeploymentPackageV1>(
            &to_canonical_bytes(&zero_store_id),
            Limits::LARGE
        )
        .is_err()
    );

    assert_eq!(
        haldir_contracts::ids::JournalId::new([0; 16]),
        Err(haldir_contracts::DecodeError::ZeroForNonZero)
    );

    let mut inexact = package();
    inexact.ncp_wire_profile = DeploymentNcpWireProfileV1::ModeledP0;
    assert!(
        from_canonical_bytes::<DeploymentPackageV1>(&to_canonical_bytes(&inexact), Limits::LARGE)
            .is_err()
    );

    let mut overflowing = package();
    overflowing.artifacts = BoundedVec::from_vec({
        let mut refs = overflowing.artifacts.as_slice().to_vec();
        refs[0].size_bytes = NonZeroU64::new(u64::MAX).unwrap();
        refs[1].size_bytes = NonZeroU64::new(u64::MAX).unwrap();
        refs
    })
    .unwrap();
    assert!(
        from_canonical_bytes::<DeploymentPackageV1>(
            &to_canonical_bytes(&overflowing),
            Limits::LARGE
        )
        .is_err()
    );
}

#[test]
fn verification_binds_external_policy_and_authority_subject() {
    let (envelope, trust, expected_kid) = signed_with(
        &package(),
        1,
        KeyRole::DeploymentAuthority,
        KeyClass::Assurance,
        "deployment-authority-a",
    );
    let verified =
        verify_deployment_package(&envelope, &policy(), &trust, &RevocationSnapshot::new())
            .unwrap();

    assert_eq!(verified.signer_kid(), &expected_kid);
    assert_eq!(verified.signer_subject(), "deployment-authority-a");
    assert_eq!(verified.package(), &package());
    assert_eq!(verified.canonical_payload(), to_canonical_bytes(&package()));
}

#[test]
fn separately_expected_authority_rejects_another_trusted_deployment_authority() {
    let mut second_authority_package = package();
    second_authority_package.deployment_authority_id =
        AsciiId::new("deployment-authority-b").unwrap();
    let (envelope, mut trust, _) = signed_with(
        &second_authority_package,
        9,
        KeyRole::DeploymentAuthority,
        KeyClass::Assurance,
        "deployment-authority-b",
    );
    let expected_signer = SigningKey::from_seed([10; 32]).expect("nonzero test seed");
    let expected_kid = key_id(10);
    trust
        .insert(trust_record(
            &expected_kid,
            &expected_signer,
            KeyRole::DeploymentAuthority,
            KeyClass::Assurance,
            "deployment-authority-a",
        ))
        .unwrap();

    assert_eq!(
        verify_deployment_package(&envelope, &policy(), &trust, &RevocationSnapshot::new())
            .unwrap_err(),
        DeploymentError::AuthorityMismatch
    );
}

#[test]
fn wrong_role_subject_revocation_and_assurance_class_fail_closed() {
    let package = package();
    let cases = [
        (
            KeyRole::MissionAuthority,
            KeyClass::Assurance,
            "deployment-authority-a",
        ),
        (
            KeyRole::DeploymentAuthority,
            KeyClass::Assurance,
            "different-authority",
        ),
        (
            KeyRole::DeploymentAuthority,
            KeyClass::Development,
            "deployment-authority-a",
        ),
    ];
    for (role, class, subject) in cases {
        let (envelope, trust, _) = signed_with(&package, 2, role, class, subject);
        assert!(
            verify_deployment_package(&envelope, &policy(), &trust, &RevocationSnapshot::new())
                .is_err()
        );
    }

    let (envelope, trust, kid) = signed_with(
        &package,
        3,
        KeyRole::DeploymentAuthority,
        KeyClass::Assurance,
        "deployment-authority-a",
    );
    let mut revoked = RevocationSnapshot::new();
    revoked.revoke_key(&kid, 1).unwrap();
    assert!(verify_deployment_package(&envelope, &policy(), &trust, &revoked).is_err());

    assert!(
        verify_deployment_package(
            &envelope,
            &policy(),
            &TrustStore::new(),
            &RevocationSnapshot::new()
        )
        .is_err()
    );
}

#[test]
fn valid_signature_over_an_unknown_payload_field_is_rejected() {
    let signer = SigningKey::from_seed([31; 32]).expect("nonzero test seed");
    let key_id = key_id(31);
    let mut trust = TrustStore::new();
    trust
        .insert(trust_record(
            &key_id,
            &signer,
            KeyRole::DeploymentAuthority,
            KeyClass::Assurance,
            "deployment-authority-a",
        ))
        .unwrap();
    let mut payload = to_canonical_bytes(&package());
    assert_eq!(payload[0], 0xaf, "schema v1.0 currently has 15 map pairs");
    payload[0] = 0xb0;
    payload.extend_from_slice(&[0x10, 0x00]);
    let envelope = haldir_crypto::cose::sign_sign1(
        &payload,
        &key_id,
        &content_type_for(DeploymentPackageV1::KIND),
        &external_aad_for(DeploymentPackageV1::KIND, 1),
        &signer,
    );

    assert!(matches!(
        verify_deployment_package(&envelope, &policy(), &trust, &RevocationSnapshot::new()),
        Err(DeploymentError::Decode(
            haldir_contracts::DecodeError::UnknownField { key: 16 }
        ))
    ));
}

#[test]
fn package_mismatch_cannot_override_separately_passed_profile_policy() {
    let (envelope, trust, _) = signed_with(
        &package(),
        4,
        KeyRole::DeploymentAuthority,
        KeyClass::Assurance,
        "deployment-authority-a",
    );
    let development_policy = DeploymentAcceptancePolicy::new(
        DeploymentIdentityExpectation::new(
            AsciiId::new("deployment-authority-a").unwrap(),
            GateId::new("gate-1").unwrap(),
            AsciiId::new("range-a").unwrap(),
            VehicleId::new("uav-1").unwrap(),
        ),
        DeploymentProfileRequirement::new(
            DeploymentClassV1::Development,
            DeploymentRuntimeProfileV1::InProcessReference,
            DeploymentNcpWireProfileV1::ModeledP0,
        ),
        authority_policy(),
    );
    assert_eq!(
        verify_deployment_package(
            &envelope,
            &development_policy,
            &trust,
            &RevocationSnapshot::new()
        )
        .unwrap_err(),
        DeploymentError::ProfileMismatch
    );
}

#[test]
fn gate_realm_vehicle_runtime_and_wire_mismatches_are_distinct() {
    let (envelope, trust, _) = signed_with(
        &package(),
        5,
        KeyRole::DeploymentAuthority,
        KeyClass::Assurance,
        "deployment-authority-a",
    );
    let identity = |gate: &str, realm: &str, vehicle: &str| {
        DeploymentIdentityExpectation::new(
            AsciiId::new("deployment-authority-a").unwrap(),
            GateId::new(gate).unwrap(),
            AsciiId::new(realm).unwrap(),
            VehicleId::new(vehicle).unwrap(),
        )
    };
    let profile = |runtime, wire| {
        DeploymentProfileRequirement::new(DeploymentClassV1::AssuranceSimulation, runtime, wire)
    };
    let policies = [
        (
            DeploymentAcceptancePolicy::new(
                identity("gate-2", "range-a", "uav-1"),
                profile(
                    DeploymentRuntimeProfileV1::DeclaredLiveZenoh,
                    DeploymentNcpWireProfileV1::ExactNcpV0_8Json,
                ),
                authority_policy(),
            ),
            DeploymentError::GateMismatch,
        ),
        (
            DeploymentAcceptancePolicy::new(
                identity("gate-1", "range-b", "uav-1"),
                profile(
                    DeploymentRuntimeProfileV1::DeclaredLiveZenoh,
                    DeploymentNcpWireProfileV1::ExactNcpV0_8Json,
                ),
                authority_policy(),
            ),
            DeploymentError::RealmMismatch,
        ),
        (
            DeploymentAcceptancePolicy::new(
                identity("gate-1", "range-a", "uav-2"),
                profile(
                    DeploymentRuntimeProfileV1::DeclaredLiveZenoh,
                    DeploymentNcpWireProfileV1::ExactNcpV0_8Json,
                ),
                authority_policy(),
            ),
            DeploymentError::VehicleMismatch,
        ),
        (
            DeploymentAcceptancePolicy::new(
                identity("gate-1", "range-a", "uav-1"),
                profile(
                    DeploymentRuntimeProfileV1::InProcessReference,
                    DeploymentNcpWireProfileV1::ExactNcpV0_8Json,
                ),
                authority_policy(),
            ),
            DeploymentError::RuntimeProfileMismatch,
        ),
        (
            DeploymentAcceptancePolicy::new(
                identity("gate-1", "range-a", "uav-1"),
                profile(
                    DeploymentRuntimeProfileV1::DeclaredLiveZenoh,
                    DeploymentNcpWireProfileV1::ModeledP0,
                ),
                authority_policy(),
            ),
            DeploymentError::NcpWireProfileMismatch,
        ),
    ];
    for (policy, expected) in policies {
        assert_eq!(
            verify_deployment_package(&envelope, &policy, &trust, &RevocationSnapshot::new())
                .unwrap_err(),
            expected
        );
    }
}

#[test]
fn payload_digest_is_signature_rotation_invariant_but_envelope_digest_is_not() {
    let package = package();
    let (first_envelope, first_trust, _) = signed_with(
        &package,
        6,
        KeyRole::DeploymentAuthority,
        KeyClass::Assurance,
        "deployment-authority-a",
    );
    let (second_envelope, second_trust, _) = signed_with(
        &package,
        7,
        KeyRole::DeploymentAuthority,
        KeyClass::Assurance,
        "deployment-authority-a",
    );
    let first = verify_deployment_package(
        &first_envelope,
        &policy(),
        &first_trust,
        &RevocationSnapshot::new(),
    )
    .unwrap();
    let second = verify_deployment_package(
        &second_envelope,
        &policy(),
        &second_trust,
        &RevocationSnapshot::new(),
    )
    .unwrap();

    assert_eq!(first.payload_digest(), second.payload_digest());
    assert_ne!(first.envelope_digest(), second.envelope_digest());
}

#[test]
fn tampering_fails_signature_verification() {
    let (mut envelope, trust, _) = signed_with(
        &package(),
        8,
        KeyRole::DeploymentAuthority,
        KeyClass::Assurance,
        "deployment-authority-a",
    );
    let last = envelope.len() - 1;
    envelope[last] ^= 1;

    assert!(
        verify_deployment_package(&envelope, &policy(), &trust, &RevocationSnapshot::new())
            .is_err()
    );
}

#[test]
fn artifact_resolution_retains_exact_owned_bytes() {
    let verified = verified();
    let inputs = artifact_inputs(verified.package());
    let resolved = verified
        .resolve_artifacts(inputs, ArtifactLimits::new(1024, 4096).unwrap())
        .unwrap();

    for role in DeploymentArtifactIdV1::ALL {
        assert_eq!(
            resolved.artifact(role),
            Some(artifact_bytes(role).as_slice())
        );
        assert_eq!(
            resolved.artifact_logical_id(role),
            Some(artifact_logical_id(role).as_str())
        );
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn directory_source_loads_every_signed_leaf_and_resolves_exact_bytes() {
    let directory = TestArtifactDirectory::new();
    let verified = verified();
    write_artifact_files(directory.path(), verified.package());
    let source = artifact_source(directory.path());

    let resolved = verified
        .resolve_artifacts_from_directory(source, ArtifactLimits::new(1024, 4096).unwrap())
        .unwrap();

    for role in DeploymentArtifactIdV1::ALL {
        assert_eq!(
            resolved.artifact(role),
            Some(artifact_bytes(role).as_slice())
        );
        assert_eq!(
            resolved.artifact_logical_id(role),
            Some(artifact_logical_id(role).as_str())
        );
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn directory_source_capability_stays_bound_after_root_path_replacement() {
    let outer = TestArtifactDirectory::new();
    let original = outer.path().join("original");
    let moved = outer.path().join("moved");
    fs::create_dir(&original).unwrap();
    let verified = verified();
    write_artifact_files(&original, verified.package());
    let source = artifact_source(&original);

    fs::rename(&original, &moved).unwrap();
    fs::create_dir(&original).unwrap();

    let resolved = verified
        .resolve_artifacts_from_directory(source, ArtifactLimits::new(1024, 4096).unwrap())
        .unwrap();
    assert_eq!(
        resolved.artifact(DeploymentArtifactIdV1::GateExecutable),
        Some(artifact_bytes(DeploymentArtifactIdV1::GateExecutable).as_slice())
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn directory_source_reads_opened_leaf_after_its_name_is_replaced() {
    let directory = TestArtifactDirectory::new();
    let verified = verified();
    write_artifact_files(directory.path(), verified.package());
    let role = DeploymentArtifactIdV1::GateExecutable;
    let leaf = artifact_path(directory.path(), verified.package(), role);
    let renamed_leaf = directory.path().join("renamed-open-leaf");
    let limits = ArtifactLimits::new(1024, 4096).unwrap();

    let inputs = artifact_source(directory.path())
        .load_with_after_initial_metadata(&verified, limits, |opened_role| {
            if opened_role == role {
                fs::rename(&leaf, &renamed_leaf).unwrap();
                fs::write(&leaf, [0xa5u8, 0x5a]).unwrap();
            }
        })
        .unwrap();
    let resolved = verified.resolve_artifacts(inputs, limits).unwrap();

    assert_eq!(
        resolved.artifact(role),
        Some(artifact_bytes(role).as_slice())
    );
    assert_eq!(fs::read(leaf).unwrap(), [0xa5, 0x5a]);
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn directory_source_detects_growth_shrink_and_post_open_linking() {
    let role = DeploymentArtifactIdV1::GateExecutable;
    let limits = ArtifactLimits::new(1024, 4096).unwrap();

    let growth_directory = TestArtifactDirectory::new();
    let verified_growth = verified();
    write_artifact_files(growth_directory.path(), verified_growth.package());
    let growth_leaf = artifact_path(growth_directory.path(), verified_growth.package(), role);
    assert!(matches!(
        artifact_source(growth_directory.path()).load_with_after_initial_metadata(
            &verified_growth,
            limits,
            |opened_role| {
                if opened_role == role {
                    fs::write(&growth_leaf, [1u8, 1, 1]).unwrap();
                }
            }
        ),
        Err(DeploymentError::ArtifactSourceSizeMismatch(
            DeploymentArtifactIdV1::GateExecutable
        ))
    ));

    let shrink_directory = TestArtifactDirectory::new();
    let verified_shrink = verified();
    write_artifact_files(shrink_directory.path(), verified_shrink.package());
    let shrink_leaf = artifact_path(shrink_directory.path(), verified_shrink.package(), role);
    assert!(matches!(
        artifact_source(shrink_directory.path()).load_with_after_initial_metadata(
            &verified_shrink,
            limits,
            |opened_role| {
                if opened_role == role {
                    fs::write(&shrink_leaf, [1u8]).unwrap();
                }
            }
        ),
        Err(DeploymentError::ArtifactSourceSizeMismatch(
            DeploymentArtifactIdV1::GateExecutable
        ))
    ));

    let link_directory = TestArtifactDirectory::new();
    let verified_link = verified();
    write_artifact_files(link_directory.path(), verified_link.package());
    let link_leaf = artifact_path(link_directory.path(), verified_link.package(), role);
    let alias = link_directory.path().join("post-open-alias");
    assert!(matches!(
        artifact_source(link_directory.path()).load_with_after_initial_metadata(
            &verified_link,
            limits,
            |opened_role| {
                if opened_role == role {
                    fs::hard_link(&link_leaf, &alias).unwrap();
                }
            }
        ),
        Err(DeploymentError::ArtifactSourceChanged(
            DeploymentArtifactIdV1::GateExecutable
        ))
    ));
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn directory_source_same_size_post_open_mutation_reaches_digest_rejection() {
    let directory = TestArtifactDirectory::new();
    let verified = verified();
    write_artifact_files(directory.path(), verified.package());
    let role = DeploymentArtifactIdV1::GateExecutable;
    let leaf = artifact_path(directory.path(), verified.package(), role);
    let limits = ArtifactLimits::new(1024, 4096).unwrap();

    let inputs = artifact_source(directory.path())
        .load_with_after_initial_metadata(&verified, limits, |opened_role| {
            if opened_role == role {
                fs::write(&leaf, [0xa5u8, 0x5a]).unwrap();
            }
        })
        .unwrap();

    assert!(matches!(
        verified.resolve_artifacts(inputs, limits),
        Err(DeploymentError::ArtifactDigestMismatch(
            DeploymentArtifactIdV1::GateExecutable
        ))
    ));
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn directory_source_rejects_a_second_role_resolving_to_the_same_inode() {
    let first_role = DeploymentArtifactIdV1::GateExecutable;
    let second_role = DeploymentArtifactIdV1::GateConfiguration;
    let mut same_bytes_package = package();
    same_bytes_package.artifacts = BoundedVec::from_vec({
        let mut refs = same_bytes_package.artifacts.as_slice().to_vec();
        refs[1].digest = refs[0].digest;
        refs[1].size_bytes = refs[0].size_bytes;
        refs
    })
    .unwrap();
    let (envelope, trust, _) = signed_with(
        &same_bytes_package,
        34,
        KeyRole::DeploymentAuthority,
        KeyClass::Assurance,
        "deployment-authority-a",
    );
    let verified_same =
        verify_deployment_package(&envelope, &policy(), &trust, &RevocationSnapshot::new())
            .unwrap();
    let directory = TestArtifactDirectory::new();
    write_artifact_files(directory.path(), verified_same.package());
    let first_leaf = artifact_path(directory.path(), verified_same.package(), first_role);
    let second_leaf = artifact_path(directory.path(), verified_same.package(), second_role);
    fs::write(&second_leaf, artifact_bytes(first_role)).unwrap();

    assert!(matches!(
        artifact_source(directory.path()).load_with_after_initial_metadata(
            &verified_same,
            ArtifactLimits::new(1024, 4096).unwrap(),
            |opened_role| {
                if opened_role == first_role {
                    fs::rename(&first_leaf, &second_leaf).unwrap();
                }
            }
        ),
        Err(DeploymentError::ArtifactSourceEntryRejected(
            DeploymentArtifactIdV1::GateConfiguration
        ))
    ));
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn directory_source_rejects_missing_symlink_and_hardlink_entries() {
    use std::os::unix::fs::symlink;

    let role = DeploymentArtifactIdV1::GateExecutable;

    let missing_directory = TestArtifactDirectory::new();
    let verified_missing = verified();
    write_artifact_files(missing_directory.path(), verified_missing.package());
    fs::remove_file(artifact_path(
        missing_directory.path(),
        verified_missing.package(),
        role,
    ))
    .unwrap();
    assert!(matches!(
        verified_missing.resolve_artifacts_from_directory(
            artifact_source(missing_directory.path()),
            ArtifactLimits::new(1024, 4096).unwrap()
        ),
        Err(DeploymentError::ArtifactSourceEntryUnavailable(
            DeploymentArtifactIdV1::GateExecutable
        ))
    ));

    let symlink_directory = TestArtifactDirectory::new();
    let verified_symlink = verified();
    write_artifact_files(symlink_directory.path(), verified_symlink.package());
    let symlink_path = artifact_path(symlink_directory.path(), verified_symlink.package(), role);
    fs::remove_file(&symlink_path).unwrap();
    symlink(
        artifact_path(
            symlink_directory.path(),
            verified_symlink.package(),
            DeploymentArtifactIdV1::GateConfiguration,
        ),
        &symlink_path,
    )
    .unwrap();
    assert!(matches!(
        verified_symlink.resolve_artifacts_from_directory(
            artifact_source(symlink_directory.path()),
            ArtifactLimits::new(1024, 4096).unwrap()
        ),
        Err(DeploymentError::ArtifactSourceEntryUnavailable(
            DeploymentArtifactIdV1::GateExecutable
        ))
    ));

    let hardlink_directory = TestArtifactDirectory::new();
    let verified_hardlink = verified();
    write_artifact_files(hardlink_directory.path(), verified_hardlink.package());
    let hardlink_path = artifact_path(hardlink_directory.path(), verified_hardlink.package(), role);
    fs::remove_file(&hardlink_path).unwrap();
    fs::hard_link(
        artifact_path(
            hardlink_directory.path(),
            verified_hardlink.package(),
            DeploymentArtifactIdV1::GateConfiguration,
        ),
        &hardlink_path,
    )
    .unwrap();
    assert!(matches!(
        verified_hardlink.resolve_artifacts_from_directory(
            artifact_source(hardlink_directory.path()),
            ArtifactLimits::new(1024, 4096).unwrap()
        ),
        Err(DeploymentError::ArtifactSourceEntryRejected(
            DeploymentArtifactIdV1::GateExecutable
        ))
    ));

    let outer = TestArtifactDirectory::new();
    let external_root = outer.path().join("root");
    fs::create_dir(&external_root).unwrap();
    let verified_external = verified();
    write_artifact_files(&external_root, verified_external.package());
    let external_path = outer.path().join("external-artifact");
    fs::write(&external_path, artifact_bytes(role)).unwrap();
    let external_link = artifact_path(&external_root, verified_external.package(), role);
    fs::remove_file(&external_link).unwrap();
    fs::hard_link(&external_path, &external_link).unwrap();
    assert!(matches!(
        verified_external.resolve_artifacts_from_directory(
            artifact_source(&external_root),
            ArtifactLimits::new(1024, 4096).unwrap()
        ),
        Err(DeploymentError::ArtifactSourceEntryRejected(
            DeploymentArtifactIdV1::GateExecutable
        ))
    ));
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn directory_source_rejects_directory_and_socket_entries() {
    use std::os::unix::net::UnixListener;

    let role = DeploymentArtifactIdV1::GateExecutable;

    let nested_directory = TestArtifactDirectory::new();
    let verified_directory = verified();
    write_artifact_files(nested_directory.path(), verified_directory.package());
    let nested_path = artifact_path(nested_directory.path(), verified_directory.package(), role);
    fs::remove_file(&nested_path).unwrap();
    fs::create_dir(&nested_path).unwrap();
    assert!(matches!(
        verified_directory.resolve_artifacts_from_directory(
            artifact_source(nested_directory.path()),
            ArtifactLimits::new(1024, 4096).unwrap()
        ),
        Err(DeploymentError::ArtifactSourceEntryRejected(
            DeploymentArtifactIdV1::GateExecutable
        ))
    ));

    let socket_directory = TestArtifactDirectory::new();
    let verified_socket = verified();
    write_artifact_files(socket_directory.path(), verified_socket.package());
    let socket_path = artifact_path(socket_directory.path(), verified_socket.package(), role);
    fs::remove_file(&socket_path).unwrap();
    let _listener = UnixListener::bind(&socket_path).unwrap();
    assert!(matches!(
        verified_socket.resolve_artifacts_from_directory(
            artifact_source(socket_directory.path()),
            ArtifactLimits::new(1024, 4096).unwrap()
        ),
        Err(DeploymentError::ArtifactSourceEntryUnavailable(
            DeploymentArtifactIdV1::GateExecutable
        )) | Err(DeploymentError::ArtifactSourceEntryRejected(
            DeploymentArtifactIdV1::GateExecutable
        ))
    ));
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn directory_source_rejects_fifo_without_blocking_for_a_writer() {
    use std::process::Command;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    let directory = TestArtifactDirectory::new();
    let verified = verified();
    write_artifact_files(directory.path(), verified.package());
    let role = DeploymentArtifactIdV1::GateExecutable;
    let path = artifact_path(directory.path(), verified.package(), role);
    fs::remove_file(&path).unwrap();
    let root = File::open(directory.path()).unwrap();
    assert!(
        Command::new("mkfifo")
            .arg(&path)
            .status()
            .unwrap()
            .success()
    );

    let (sender, receiver) = mpsc::channel();
    let worker = thread::spawn(move || {
        let result = verified.resolve_artifacts_from_directory(
            ArtifactDirectory::from_directory(root).unwrap(),
            ArtifactLimits::new(1024, 4096).unwrap(),
        );
        sender.send(result).unwrap();
    });
    let result = receiver
        .recv_timeout(Duration::from_secs(2))
        .expect("FIFO source open exceeded the nonblocking test deadline");
    worker.join().unwrap();

    assert!(matches!(
        result,
        Err(DeploymentError::ArtifactSourceEntryRejected(
            DeploymentArtifactIdV1::GateExecutable
        ))
    ));
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn directory_source_opens_then_rejects_a_device_entry() {
    let mut device_package = package();
    device_package.artifacts = BoundedVec::from_vec({
        let mut refs = device_package.artifacts.as_slice().to_vec();
        refs[0].logical_id = AsciiId::new("null").unwrap();
        refs
    })
    .unwrap();
    let (envelope, trust, _) = signed_with(
        &device_package,
        33,
        KeyRole::DeploymentAuthority,
        KeyClass::Assurance,
        "deployment-authority-a",
    );
    let verified_device =
        verify_deployment_package(&envelope, &policy(), &trust, &RevocationSnapshot::new())
            .unwrap();
    let source = ArtifactDirectory::from_directory(File::open("/dev").unwrap()).unwrap();

    assert!(matches!(
        verified_device
            .resolve_artifacts_from_directory(source, ArtifactLimits::new(1024, 4096).unwrap()),
        Err(DeploymentError::ArtifactSourceEntryRejected(
            DeploymentArtifactIdV1::GateExecutable
        ))
    ));
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn directory_source_rejects_short_long_and_wrong_digest_bytes() {
    let role = DeploymentArtifactIdV1::GateExecutable;

    let short_directory = TestArtifactDirectory::new();
    let verified_short = verified();
    write_artifact_files(short_directory.path(), verified_short.package());
    fs::write(
        artifact_path(short_directory.path(), verified_short.package(), role),
        [1u8],
    )
    .unwrap();
    assert!(matches!(
        verified_short.resolve_artifacts_from_directory(
            artifact_source(short_directory.path()),
            ArtifactLimits::new(1024, 4096).unwrap()
        ),
        Err(DeploymentError::ArtifactSourceSizeMismatch(
            DeploymentArtifactIdV1::GateExecutable
        ))
    ));

    let long_directory = TestArtifactDirectory::new();
    let verified_long = verified();
    write_artifact_files(long_directory.path(), verified_long.package());
    fs::write(
        artifact_path(long_directory.path(), verified_long.package(), role),
        [1u8, 1, 1],
    )
    .unwrap();
    assert!(matches!(
        verified_long.resolve_artifacts_from_directory(
            artifact_source(long_directory.path()),
            ArtifactLimits::new(1024, 4096).unwrap()
        ),
        Err(DeploymentError::ArtifactSourceSizeMismatch(
            DeploymentArtifactIdV1::GateExecutable
        ))
    ));

    let digest_directory = TestArtifactDirectory::new();
    let verified_digest = verified();
    write_artifact_files(digest_directory.path(), verified_digest.package());
    fs::write(
        artifact_path(digest_directory.path(), verified_digest.package(), role),
        [0xa5u8, 0x5a],
    )
    .unwrap();
    assert!(matches!(
        verified_digest.resolve_artifacts_from_directory(
            artifact_source(digest_directory.path()),
            ArtifactLimits::new(1024, 4096).unwrap()
        ),
        Err(DeploymentError::ArtifactDigestMismatch(
            DeploymentArtifactIdV1::GateExecutable
        ))
    ));
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn directory_source_preflights_limits_and_flat_signed_names_before_entry_open() {
    let empty_directory = TestArtifactDirectory::new();
    assert!(matches!(
        verified().resolve_artifacts_from_directory(
            artifact_source(empty_directory.path()),
            ArtifactLimits::new(1, 4096).unwrap()
        ),
        Err(DeploymentError::ArtifactDeclaredTooLarge(_))
    ));
    let maximum_declared_artifact = package()
        .artifacts
        .as_slice()
        .iter()
        .map(|artifact| usize::try_from(artifact.size_bytes.get()).unwrap())
        .max()
        .unwrap();
    assert_eq!(
        verified()
            .resolve_artifacts_from_directory(
                artifact_source(empty_directory.path()),
                ArtifactLimits::new(maximum_declared_artifact, maximum_declared_artifact).unwrap(),
            )
            .unwrap_err(),
        DeploymentError::ArtifactTotalTooLarge
    );

    for (seed, invalid_name) in [(31, "."), (32, "..")] {
        let mut invalid_package = package();
        invalid_package.artifacts = BoundedVec::from_vec({
            let mut refs = invalid_package.artifacts.as_slice().to_vec();
            refs.last_mut().unwrap().logical_id = AsciiId::new(invalid_name).unwrap();
            refs
        })
        .unwrap();
        let (envelope, trust, _) = signed_with(
            &invalid_package,
            seed,
            KeyRole::DeploymentAuthority,
            KeyClass::Assurance,
            "deployment-authority-a",
        );
        let verified_invalid =
            verify_deployment_package(&envelope, &policy(), &trust, &RevocationSnapshot::new())
                .unwrap();
        assert!(matches!(
            verified_invalid.resolve_artifacts_from_directory(
                artifact_source(empty_directory.path()),
                ArtifactLimits::new(1024, 4096).unwrap()
            ),
            Err(DeploymentError::ArtifactSourceNameInvalid(
                DeploymentArtifactIdV1::SourceLedger
            ))
        ));
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn directory_source_rejects_nondirectory_root_and_redacts_capability() {
    let directory = TestArtifactDirectory::new();
    let secret_path = directory.path().join("SECRET_ROOT_PATH");
    fs::write(&secret_path, b"not a directory").unwrap();
    assert_eq!(
        ArtifactDirectory::from_directory(File::open(&secret_path).unwrap()).unwrap_err(),
        DeploymentError::ArtifactSourceRootInvalid
    );

    let source = artifact_source(directory.path());
    let debug = format!("{source:?}");
    assert!(!debug.contains(directory.path().to_string_lossy().as_ref()));
    assert!(!debug.contains("SECRET_ROOT_PATH"));

    let error = verified()
        .resolve_artifacts_from_directory(source, ArtifactLimits::new(1024, 4096).unwrap())
        .unwrap_err();
    assert!(!format!("{error:?}").contains(directory.path().to_string_lossy().as_ref()));
    assert!(!error.to_string().contains("SECRET_ROOT_PATH"));
}

#[test]
fn artifact_input_duplicate_missing_and_logical_id_mismatch_fail() {
    let role = DeploymentArtifactIdV1::GateExecutable;
    let duplicate = DeploymentArtifactSet::from_inputs([
        DeploymentArtifactInput::new(role, artifact_logical_id(role), artifact_bytes(role)),
        DeploymentArtifactInput::new(role, artifact_logical_id(role), artifact_bytes(role)),
    ]);
    assert!(matches!(
        duplicate,
        Err(DeploymentError::ArtifactDuplicateInput(
            DeploymentArtifactIdV1::GateExecutable
        ))
    ));

    let missing = DeploymentArtifactSet::from_inputs(
        DeploymentArtifactIdV1::ALL
            .into_iter()
            .filter(|candidate| *candidate != role)
            .map(|candidate| {
                DeploymentArtifactInput::new(
                    candidate,
                    artifact_logical_id(candidate),
                    artifact_bytes(candidate),
                )
            }),
    )
    .unwrap();
    assert!(matches!(
        verified().resolve_artifacts(missing, ArtifactLimits::new(1024, 4096).unwrap()),
        Err(DeploymentError::ArtifactMissing(
            DeploymentArtifactIdV1::GateExecutable
        ))
    ));

    let mismatched = DeploymentArtifactSet::from_inputs(
        DeploymentArtifactIdV1::ALL.into_iter().map(|candidate| {
            DeploymentArtifactInput::new(
                candidate,
                if candidate == role {
                    AsciiId::new("wrong-logical-id").unwrap()
                } else {
                    artifact_logical_id(candidate)
                },
                artifact_bytes(candidate),
            )
        }),
    )
    .unwrap();
    assert!(matches!(
        verified().resolve_artifacts(mismatched, ArtifactLimits::new(1024, 4096).unwrap()),
        Err(DeploymentError::ArtifactLogicalIdMismatch(
            DeploymentArtifactIdV1::GateExecutable
        ))
    ));
}

#[test]
fn artifact_length_digest_and_bounds_fail_before_resolution() {
    let role = DeploymentArtifactIdV1::GateExecutable;
    let short = DeploymentArtifactSet::from_inputs(DeploymentArtifactIdV1::ALL.into_iter().map(
        |candidate| {
            let mut bytes = artifact_bytes(candidate);
            if candidate == role {
                bytes.pop();
            }
            DeploymentArtifactInput::new(candidate, artifact_logical_id(candidate), bytes)
        },
    ))
    .unwrap();
    assert!(matches!(
        verified().resolve_artifacts(short, ArtifactLimits::new(1024, 4096).unwrap()),
        Err(DeploymentError::ArtifactLengthMismatch(
            DeploymentArtifactIdV1::GateExecutable
        ))
    ));

    let wrong_digest = DeploymentArtifactSet::from_inputs(
        DeploymentArtifactIdV1::ALL.into_iter().map(|candidate| {
            let mut bytes = artifact_bytes(candidate);
            if candidate == role {
                bytes[0] ^= 1;
            }
            DeploymentArtifactInput::new(candidate, artifact_logical_id(candidate), bytes)
        }),
    )
    .unwrap();
    assert!(matches!(
        verified().resolve_artifacts(wrong_digest, ArtifactLimits::new(1024, 4096).unwrap()),
        Err(DeploymentError::ArtifactDigestMismatch(
            DeploymentArtifactIdV1::GateExecutable
        ))
    ));

    let inputs = artifact_inputs(verified().package());
    assert!(matches!(
        verified().resolve_artifacts(inputs, ArtifactLimits::new(5, 4096).unwrap()),
        Err(DeploymentError::ArtifactDeclaredTooLarge(_))
    ));

    let maximum_declared_artifact = package()
        .artifacts
        .as_slice()
        .iter()
        .map(|artifact| usize::try_from(artifact.size_bytes.get()).unwrap())
        .max()
        .unwrap();
    let inputs = artifact_inputs(verified().package());
    assert_eq!(
        verified()
            .resolve_artifacts(
                inputs,
                ArtifactLimits::new(maximum_declared_artifact, maximum_declared_artifact).unwrap(),
            )
            .unwrap_err(),
        DeploymentError::ArtifactTotalTooLarge
    );

    assert!(matches!(
        verified().resolve_artifacts(
            DeploymentArtifactSet::default(),
            ArtifactLimits::new(5, 4096).unwrap()
        ),
        Err(DeploymentError::ArtifactDeclaredTooLarge(_))
    ));

    let mut cross_domain_package = package();
    cross_domain_package.artifacts = BoundedVec::from_vec({
        let mut refs = cross_domain_package.artifacts.as_slice().to_vec();
        refs[0].digest = DigestV1::compute(
            DigestDomain::RawEnvelope,
            &artifact_bytes(DeploymentArtifactIdV1::GateExecutable),
        );
        refs
    })
    .unwrap();
    let (envelope, trust, _) = signed_with(
        &cross_domain_package,
        11,
        KeyRole::DeploymentAuthority,
        KeyClass::Assurance,
        "deployment-authority-a",
    );
    let verified_cross_domain =
        verify_deployment_package(&envelope, &policy(), &trust, &RevocationSnapshot::new())
            .unwrap();
    assert!(matches!(
        verified_cross_domain.resolve_artifacts(
            artifact_inputs(&cross_domain_package),
            ArtifactLimits::new(1024, 4096).unwrap()
        ),
        Err(DeploymentError::ArtifactDigestMismatch(
            DeploymentArtifactIdV1::GateExecutable
        ))
    ));
}

#[test]
fn artifact_debug_output_redacts_owned_bytes() {
    const SECRET: &[u8] = b"ULTRA_SECRET_ARTIFACT_BYTES";
    let leaked_byte_debug = format!("{SECRET:?}");
    let role = DeploymentArtifactIdV1::GateExecutable;
    let input = DeploymentArtifactInput::new(role, artifact_logical_id(role), SECRET.to_vec());
    assert!(!format!("{input:?}").contains(&leaked_byte_debug));

    let mut secret_package = package();
    secret_package.artifacts = BoundedVec::from_vec({
        let mut refs = secret_package.artifacts.as_slice().to_vec();
        refs[0].digest = DigestV1::compute(DigestDomain::DeploymentArtifact, SECRET);
        refs[0].size_bytes = NonZeroU64::new(u64::try_from(SECRET.len()).unwrap()).unwrap();
        refs
    })
    .unwrap();
    let inputs = DeploymentArtifactSet::from_inputs(DeploymentArtifactIdV1::ALL.into_iter().map(
        |candidate| {
            DeploymentArtifactInput::new(
                candidate,
                artifact_logical_id(candidate),
                if candidate == role {
                    SECRET.to_vec()
                } else {
                    artifact_bytes(candidate)
                },
            )
        },
    ))
    .unwrap();
    assert!(!format!("{inputs:?}").contains(&leaked_byte_debug));

    let (envelope, trust, _) = signed_with(
        &secret_package,
        12,
        KeyRole::DeploymentAuthority,
        KeyClass::Assurance,
        "deployment-authority-a",
    );
    let resolved =
        verify_deployment_package(&envelope, &policy(), &trust, &RevocationSnapshot::new())
            .unwrap()
            .resolve_artifacts(inputs, ArtifactLimits::new(1024, 4096).unwrap())
            .unwrap();
    assert!(!format!("{resolved:?}").contains(&leaked_byte_debug));
}

#[test]
fn artifact_limit_constructor_rejects_zero_or_inverted_bounds() {
    assert_eq!(
        ArtifactLimits::new(0, 1),
        Err(DeploymentError::ArtifactLimitsInvalid)
    );
    assert_eq!(
        ArtifactLimits::new(2, 1),
        Err(DeploymentError::ArtifactLimitsInvalid)
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    #[test]
    fn deployment_decoder_never_panics_on_arbitrary_bytes(
        bytes in proptest::collection::vec(any::<u8>(), 0..2048)
    ) {
        let _ = from_canonical_bytes::<DeploymentPackageV1>(&bytes, Limits::LARGE);
    }

    #[test]
    fn one_bit_package_mutations_never_panic(offset in 0usize..4096, bit in 0u8..8) {
        let mut bytes = to_canonical_bytes(&package());
        if offset < bytes.len() {
            bytes[offset] ^= 1u8 << (bit % 8);
            let _ = from_canonical_bytes::<DeploymentPackageV1>(&bytes, Limits::LARGE);
        }
    }
}
