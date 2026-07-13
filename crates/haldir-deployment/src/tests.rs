use core::num::NonZeroU64;

use haldir_contracts::cbor::{Limits, from_canonical_bytes, to_canonical_bytes};
use haldir_contracts::deployment::DeploymentRevision;
use haldir_contracts::digest::{DigestDomain, DigestV1};
use haldir_contracts::ids::{GateId, KeyId, VehicleId};
use haldir_contracts::scalar::{AsciiId, BoundedVec};
use haldir_crypto::{
    KeyClass, KeyRecord, KeyRole, RevocationSnapshot, SigningKey, TrustStore, content_type_for,
    external_aad_for, sign_message,
};
use proptest::prelude::*;

use super::*;
use crate::contract::{
    DeploymentArtifactIdV1, DeploymentArtifactRefV1, DeploymentClassV1, DeploymentNcpWireProfileV1,
    DeploymentPackageV1, DeploymentRuntimeProfileV1,
};

fn artifact_bytes(role: DeploymentArtifactIdV1) -> Vec<u8> {
    vec![u8::try_from(role.tag()).unwrap(); usize::try_from(role.tag()).unwrap() + 1]
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
        journal_id: [2; 16],
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
        AsciiId::new("deployment-authority-a").unwrap(),
        GateId::new("gate-1").unwrap(),
        AsciiId::new("range-a").unwrap(),
        VehicleId::new("uav-1").unwrap(),
        DeploymentClassV1::AssuranceSimulation,
        DeploymentRuntimeProfileV1::DeclaredLiveZenoh,
        DeploymentNcpWireProfileV1::ExactNcpV0_8Json,
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
    subject: Option<&str>,
) -> KeyRecord {
    KeyRecord {
        kid: key_id.clone(),
        role,
        verifying_key: signer.verifying_key(),
        subject: subject.map(str::to_owned),
        class,
    }
}

fn signed_with(
    package: &DeploymentPackageV1,
    seed: u8,
    role: KeyRole,
    class: KeyClass,
    subject: Option<&str>,
) -> (Vec<u8>, TrustStore, KeyId) {
    let signer = SigningKey::from_seed([seed; 32]);
    let key_id = key_id(seed);
    let mut trust = TrustStore::new();
    trust
        .insert(trust_record(&key_id, &signer, role, class, subject))
        .unwrap();
    let envelope = sign_message(package, DeploymentPackageV1::KIND, 1, &key_id, &signer);
    (envelope, trust, key_id)
}

fn verified() -> VerifiedDeploymentPackage {
    let (envelope, trust, _) = signed_with(
        &package(),
        1,
        KeyRole::DeploymentAuthority,
        KeyClass::Assurance,
        Some("deployment-authority-a"),
    );
    verify_deployment_package(&envelope, &policy(), &trust, &RevocationSnapshot::new()).unwrap()
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
    alias.journal_id = alias.state_store_id;
    assert!(
        from_canonical_bytes::<DeploymentPackageV1>(&to_canonical_bytes(&alias), Limits::LARGE)
            .is_err()
    );

    for (state_store_id, journal_id) in [([0; 16], [2; 16]), ([1; 16], [0; 16])] {
        let mut zero_id = package();
        zero_id.state_store_id = state_store_id;
        zero_id.journal_id = journal_id;
        assert!(
            from_canonical_bytes::<DeploymentPackageV1>(
                &to_canonical_bytes(&zero_id),
                Limits::LARGE
            )
            .is_err()
        );
    }

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
        Some("deployment-authority-a"),
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
        Some("deployment-authority-b"),
    );
    let expected_signer = SigningKey::from_seed([10; 32]);
    let expected_kid = key_id(10);
    trust
        .insert(trust_record(
            &expected_kid,
            &expected_signer,
            KeyRole::DeploymentAuthority,
            KeyClass::Assurance,
            Some("deployment-authority-a"),
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
            Some("deployment-authority-a"),
        ),
        (
            KeyRole::DeploymentAuthority,
            KeyClass::Assurance,
            Some("different-authority"),
        ),
        (
            KeyRole::DeploymentAuthority,
            KeyClass::Development,
            Some("deployment-authority-a"),
        ),
        (KeyRole::DeploymentAuthority, KeyClass::Assurance, None),
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
        Some("deployment-authority-a"),
    );
    let mut revoked = RevocationSnapshot::new();
    revoked.revoke_key(&kid, 1);
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
    let signer = SigningKey::from_seed([31; 32]);
    let key_id = key_id(31);
    let mut trust = TrustStore::new();
    trust
        .insert(trust_record(
            &key_id,
            &signer,
            KeyRole::DeploymentAuthority,
            KeyClass::Assurance,
            Some("deployment-authority-a"),
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
        Some("deployment-authority-a"),
    );
    let development_policy = DeploymentAcceptancePolicy::new(
        AsciiId::new("deployment-authority-a").unwrap(),
        GateId::new("gate-1").unwrap(),
        AsciiId::new("range-a").unwrap(),
        VehicleId::new("uav-1").unwrap(),
        DeploymentClassV1::Development,
        DeploymentRuntimeProfileV1::InProcessReference,
        DeploymentNcpWireProfileV1::ModeledP0,
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
        Some("deployment-authority-a"),
    );
    let policies = [
        (
            DeploymentAcceptancePolicy::new(
                AsciiId::new("deployment-authority-a").unwrap(),
                GateId::new("gate-2").unwrap(),
                AsciiId::new("range-a").unwrap(),
                VehicleId::new("uav-1").unwrap(),
                DeploymentClassV1::AssuranceSimulation,
                DeploymentRuntimeProfileV1::DeclaredLiveZenoh,
                DeploymentNcpWireProfileV1::ExactNcpV0_8Json,
            ),
            DeploymentError::GateMismatch,
        ),
        (
            DeploymentAcceptancePolicy::new(
                AsciiId::new("deployment-authority-a").unwrap(),
                GateId::new("gate-1").unwrap(),
                AsciiId::new("range-b").unwrap(),
                VehicleId::new("uav-1").unwrap(),
                DeploymentClassV1::AssuranceSimulation,
                DeploymentRuntimeProfileV1::DeclaredLiveZenoh,
                DeploymentNcpWireProfileV1::ExactNcpV0_8Json,
            ),
            DeploymentError::RealmMismatch,
        ),
        (
            DeploymentAcceptancePolicy::new(
                AsciiId::new("deployment-authority-a").unwrap(),
                GateId::new("gate-1").unwrap(),
                AsciiId::new("range-a").unwrap(),
                VehicleId::new("uav-2").unwrap(),
                DeploymentClassV1::AssuranceSimulation,
                DeploymentRuntimeProfileV1::DeclaredLiveZenoh,
                DeploymentNcpWireProfileV1::ExactNcpV0_8Json,
            ),
            DeploymentError::VehicleMismatch,
        ),
        (
            DeploymentAcceptancePolicy::new(
                AsciiId::new("deployment-authority-a").unwrap(),
                GateId::new("gate-1").unwrap(),
                AsciiId::new("range-a").unwrap(),
                VehicleId::new("uav-1").unwrap(),
                DeploymentClassV1::AssuranceSimulation,
                DeploymentRuntimeProfileV1::InProcessReference,
                DeploymentNcpWireProfileV1::ExactNcpV0_8Json,
            ),
            DeploymentError::RuntimeProfileMismatch,
        ),
        (
            DeploymentAcceptancePolicy::new(
                AsciiId::new("deployment-authority-a").unwrap(),
                GateId::new("gate-1").unwrap(),
                AsciiId::new("range-a").unwrap(),
                VehicleId::new("uav-1").unwrap(),
                DeploymentClassV1::AssuranceSimulation,
                DeploymentRuntimeProfileV1::DeclaredLiveZenoh,
                DeploymentNcpWireProfileV1::ModeledP0,
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
        Some("deployment-authority-a"),
    );
    let (second_envelope, second_trust, _) = signed_with(
        &package,
        7,
        KeyRole::DeploymentAuthority,
        KeyClass::Assurance,
        Some("deployment-authority-a"),
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
        Some("deployment-authority-a"),
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

    let inputs = artifact_inputs(verified().package());
    assert_eq!(
        verified()
            .resolve_artifacts(inputs, ArtifactLimits::new(14, 20).unwrap())
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
        Some("deployment-authority-a"),
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
        Some("deployment-authority-a"),
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
