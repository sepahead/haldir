//! `haldir-crypto` — COSE_Sign1 / Ed25519 application-signature profile, closed
//! key roles, a prevalidated trust index, and revocation snapshots.
//!
//! This crate separates the application signature from any transport (mTLS)
//! identity, binds every message to an explicit role and dispatch context, and
//! never performs a fallback key search or message-supplied algorithm dispatch.
#![forbid(unsafe_code)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::float_cmp,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss
    )
)]

pub mod cose;
pub mod error;
pub mod key;
pub mod role;
pub mod trust;

/// Crate version string.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub use cose::{
    ExpectedContext, VerifiedCose, content_type_for, external_aad_for, verify_sign1,
    verify_sign1_dispatched,
};
pub use error::CryptoError;
pub use key::{Signature, SigningKey, VerifyingKey};
pub use role::{KeyClass, KeyRole};
pub use trust::{
    KeyRecord, KeySubject, MAX_REVOKED_KEYS, MAX_TRUSTED_KEYS,
    REVOCATION_SNAPSHOT_DIGEST_SCHEMA_V1, RevocationError, RevocationSnapshot,
    TRUST_STORE_DIGEST_SCHEMA_V1, TrustStore, TrustStoreDisjointnessError, TrustStoreError,
};

use haldir_contracts::cbor::{
    CanonicalMessage, CanonicalValue, Limits, Validate, from_canonical_bytes, to_canonical_bytes,
};
use haldir_contracts::ids::KeyId;

/// Canonically encode and COSE-sign a Haldir message under `kid`, binding the
/// message kind and major version into the content-type and external AAD.
///
/// This byte-level primitive deliberately does not call [`Validate`]. That
/// permits signing negative conformance vectors and preserves the distinction
/// between construction and verification. Acceptance paths must pair signature
/// verification with a validating canonical decoder; [`verify_and_decode`]
/// provides that combined boundary.
#[must_use]
pub fn sign_message<T: CanonicalValue>(
    msg: &T,
    kind: &str,
    schema_major: u16,
    kid: &KeyId,
    sk: &SigningKey,
) -> Vec<u8> {
    let payload = to_canonical_bytes(msg);
    let content_type = content_type_for(kind);
    let aad = external_aad_for(kind, schema_major);
    cose::sign_sign1(&payload, kid, &content_type, &aad, sk)
}

/// Canonically encode and COSE-sign a typed Haldir message under its own fixed
/// kind and major-version context.
///
/// Prefer this entry point in runtime code. Unlike [`sign_message`], it cannot
/// accidentally sign one message type under another type's protected content
/// type or external AAD. The lower-level function remains available for
/// negative conformance vectors that intentionally construct such mismatches.
#[must_use]
pub fn sign_typed_message<T: CanonicalMessage>(msg: &T, kid: &KeyId, sk: &SigningKey) -> Vec<u8> {
    sign_message(msg, T::KIND, T::SCHEMA_MAJOR, kid, sk)
}

/// Verify a signed envelope and then canonically decode the payload.
///
/// The signature is checked over the exact received payload bytes; the payload
/// is then decoded with canonical re-encoding equality, so a validly-signed but
/// non-canonical payload is rejected.
///
/// # Errors
/// Returns a [`CryptoError`] on any verification or canonical-decode failure.
pub fn verify_and_decode<T: CanonicalMessage + Validate>(
    env: &[u8],
    ctx: &ExpectedContext,
    trust: &TrustStore,
    revocations: &RevocationSnapshot,
    limits: Limits,
) -> Result<(T, KeyId, KeySubject), CryptoError> {
    if ctx.kind != T::KIND || ctx.schema_major != T::SCHEMA_MAJOR {
        return Err(CryptoError::ContentTypeMismatch);
    }
    let verified = verify_sign1(env, ctx, trust, revocations)?;
    let msg = from_canonical_bytes::<T>(verified.payload, limits)?;
    Ok((msg, verified.signer_kid, verified.signer_subject))
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::num::{NonZeroU32, NonZeroU64};
    use haldir_contracts::action::RequestedActionV1;
    use haldir_contracts::digest::{DigestDomain, DigestV1};
    use haldir_contracts::error::DecodeError;
    use haldir_contracts::ids::{
        AdmissionId, ControllerId, ControllerInstanceId, DecisionId, GateBootId, GateId,
        GateOutputEpoch, IntentEpoch, IntentSeq, MissionId, MissionLeaseId, OutputSeq, SourceSeq,
        VehicleId,
    };
    use haldir_contracts::intent::HaldirIntentV1;
    use haldir_contracts::receipt::{
        DecisionOutcomeV1, DecisionReasonCodeV1, DecisionReceiptV1, PublishStageV1,
        TransformationRelationV1,
    };
    use haldir_contracts::scalar::{AsciiId, BoundedAscii, BoundedVec, CanonicalUuidV4String};
    use haldir_contracts::session::{
        HaldirIntentPositionV1, NcpSessionIdentityV1, NcpSourceRefV1, NcpStreamPositionV1,
    };

    const KIND: &str = "haldir.intent";
    const MAJOR: u16 = 1;

    fn kid(seed: u8) -> KeyId {
        KeyId::new(vec![seed, 0xAA, seed]).unwrap()
    }

    fn signer(seed: u8) -> SigningKey {
        SigningKey::from_seed([seed; 32]).expect("nonzero test seed")
    }

    fn dig(s: u8) -> DigestV1 {
        DigestV1::compute(DigestDomain::Payload, &[s])
    }

    fn record(k: &KeyId, sk: &SigningKey, role: KeyRole, class: KeyClass) -> KeyRecord {
        KeyRecord {
            kid: k.clone(),
            role,
            verifying_key: sk.verifying_key(),
            subject: KeySubject::new("survey-v1").unwrap(),
            class,
        }
    }

    fn assert_key_record_eq(actual: &KeyRecord, expected: &KeyRecord) {
        assert_eq!(actual.kid, expected.kid);
        assert_eq!(actual.role, expected.role);
        assert_eq!(
            actual.verifying_key.to_bytes(),
            expected.verifying_key.to_bytes()
        );
        assert_eq!(actual.subject, expected.subject);
        assert_eq!(actual.class, expected.class);
    }

    fn intent() -> HaldirIntentV1 {
        HaldirIntentV1 {
            schema_major: 1,
            schema_minor: 0,
            controller_id: ControllerId::new("survey-v1").unwrap(),
            controller_instance_id: ControllerInstanceId::new([1; 16]),
            controller_signing_key_id: kid(1),
            actual_intent_key: BoundedAscii::new("veh/uav-1/haldir/intent/survey-v1").unwrap(),
            gate_id: GateId::new("gate-1").unwrap(),
            gate_boot_id: GateBootId::new([9; 16]),
            realm: AsciiId::new("range-a").unwrap(),
            vehicle_id: VehicleId::new("uav-1").unwrap(),
            mission_id: MissionId::new("inspect-1").unwrap(),
            ncp_session: NcpSessionIdentityV1 {
                session_id: AsciiId::new("sess-1").unwrap(),
                generation: CanonicalUuidV4String::from_random_bytes([1; 16]),
            },
            mission_lease_id: MissionLeaseId::new([2; 16]),
            mission_lease_term: NonZeroU64::new(100).unwrap(),
            admission_id: AdmissionId::new([4; 16]),
            admission_digest: dig(3),
            controller_bundle_digest: dig(4),
            backend_profile_digest: dig(5),
            intent_position: HaldirIntentPositionV1 {
                epoch: IntentEpoch::new([6; 16]),
                seq: IntentSeq::new(NonZeroU64::new(1).unwrap()),
            },
            controller_t_ns: 1,
            primary_source: NcpSourceRefV1 {
                source_key: BoundedAscii::new("veh/uav-1/state/pose").unwrap(),
                stream_epoch: CanonicalUuidV4String::from_random_bytes([2; 16]),
                stream_seq: SourceSeq::new(NonZeroU64::new(7).unwrap()),
            },
            input_watermarks: BoundedVec::new(),
            action: RequestedActionV1::Hold {
                requested_validity_ms: NonZeroU32::new(300).unwrap(),
            },
            controller_context_digest: None,
        }
    }

    fn receipt() -> DecisionReceiptV1 {
        let intent = intent();
        DecisionReceiptV1 {
            decision_id: DecisionId::new([3; 16]),
            gate_id: GateId::new("gate-1").unwrap(),
            gate_boot_id: GateBootId::new([9; 16]),
            vehicle_id: VehicleId::new("uav-1").unwrap(),
            mission_id: Some(intent.mission_id.clone()),
            ncp_session: NcpSessionIdentityV1 {
                session_id: AsciiId::new("sess-1").unwrap(),
                generation: CanonicalUuidV4String::from_random_bytes([1; 16]),
            },
            received_key_digest: DigestV1::compute(
                DigestDomain::TransportKey,
                intent.actual_intent_key.as_str().as_bytes(),
            ),
            raw_envelope_digest: DigestV1::compute(DigestDomain::RawEnvelope, b"intent"),
            payload_digest: Some(DigestV1::of_value(DigestDomain::Payload, &intent)),
            semantic_intent_digest: Some(intent.semantic_digest()),
            controller_id: Some(intent.controller_id.clone()),
            controller_intent_position: Some(intent.intent_position.clone()),
            mission_lease_id: Some(intent.mission_lease_id),
            admission_digest: Some(intent.admission_digest),
            source: Some(intent.primary_source.clone()),
            state_snapshot_digest: Some(DigestV1::compute(DigestDomain::StateSnapshot, b"state")),
            policy_snapshot_digest: DigestV1::compute(DigestDomain::PolicySnapshot, b"policy"),
            decision: DecisionOutcomeV1::Allow,
            reason_codes: BoundedVec::from_vec(vec![DecisionReasonCodeV1::AllowPrepared]).unwrap(),
            effective_validity_ms: Some(10),
            gate_output_stream: Some(NcpStreamPositionV1 {
                epoch: GateOutputEpoch::new(CanonicalUuidV4String::from_random_bytes([2; 16])),
                seq: OutputSeq::new(NonZeroU64::new(1).unwrap()),
            }),
            output_frame_digest: Some(DigestV1::compute(DigestDomain::OutputFrame, b"frame")),
            transformation_relation: Some(TransformationRelationV1::FixedPointToNcpFloatV1),
            received_mono_ns: 10,
            decided_mono_ns: 11,
            publish_stage: PublishStageV1::OutputPrepared,
        }
    }

    fn ctx() -> ExpectedContext<'static> {
        ExpectedContext {
            kind: KIND,
            schema_major: MAJOR,
            required_role: KeyRole::ControllerIntent,
            assurance_profile: true,
        }
    }

    fn receipt_ctx() -> ExpectedContext<'static> {
        ExpectedContext {
            kind: DecisionReceiptV1::KIND,
            schema_major: DecisionReceiptV1::SCHEMA_MAJOR,
            required_role: KeyRole::GateApplication,
            assurance_profile: true,
        }
    }

    fn trust_with(k: &KeyId, sk: &SigningKey, role: KeyRole, class: KeyClass) -> TrustStore {
        let mut t = TrustStore::new();
        t.insert(record(k, sk, role, class)).unwrap();
        t
    }

    fn verify_receipt(
        receipt: &DecisionReceiptV1,
    ) -> Result<(DecisionReceiptV1, KeyId, KeySubject), CryptoError> {
        let k = kid(7);
        let sk = signer(7);
        let trust = trust_with(&k, &sk, KeyRole::GateApplication, KeyClass::Assurance);
        let envelope = sign_message(
            receipt,
            DecisionReceiptV1::KIND,
            DecisionReceiptV1::SCHEMA_MAJOR,
            &k,
            &sk,
        );
        verify_and_decode(
            &envelope,
            &receipt_ctx(),
            &trust,
            &RevocationSnapshot::new(),
            Limits::DEFAULT,
        )
    }

    fn assert_receipt_semantic_rejected(receipt: &DecisionReceiptV1) {
        assert_eq!(
            verify_receipt(receipt).err(),
            Some(CryptoError::Payload(DecodeError::SemanticInvalid {
                code: DecisionReceiptV1::SEMANTIC_ERROR_CODE,
            }))
        );
    }

    #[test]
    fn happy_path_verifies_and_decodes() {
        let k = kid(1);
        let sk = signer(1);
        let trust = trust_with(&k, &sk, KeyRole::ControllerIntent, KeyClass::Assurance);
        let env = sign_typed_message(&intent(), &k, &sk);
        assert_eq!(env, sign_message(&intent(), KIND, MAJOR, &k, &sk));
        let (decoded, signer_kid, subject): (HaldirIntentV1, _, _) = verify_and_decode(
            &env,
            &ctx(),
            &trust,
            &RevocationSnapshot::new(),
            Limits::LARGE,
        )
        .unwrap();
        assert_eq!(decoded, intent());
        assert_eq!(signer_kid, k);
        assert_eq!(subject, KeySubject::new("survey-v1").unwrap());
    }

    #[test]
    fn signed_prepared_receipt_verifies_and_decodes() {
        let original = receipt();
        let (decoded, _, _) = verify_receipt(&original).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn signed_deny_and_error_receipts_verify_and_decode() {
        for (decision, reason, stage) in [
            (
                DecisionOutcomeV1::Deny,
                DecisionReasonCodeV1::DenyMalformed,
                PublishStageV1::DecidedDeny,
            ),
            (
                DecisionOutcomeV1::Error,
                DecisionReasonCodeV1::ErrorInternalFault,
                PublishStageV1::DecidedError,
            ),
        ] {
            let mut original = receipt();
            original.decision = decision;
            original.reason_codes = BoundedVec::from_vec(vec![reason]).unwrap();
            original.effective_validity_ms = None;
            original.gate_output_stream = None;
            original.output_frame_digest = None;
            original.transformation_relation = None;
            original.publish_stage = stage;

            let (decoded, _, _) = verify_receipt(&original).unwrap();
            assert_eq!(decoded, original);
        }
    }

    #[test]
    fn signed_receipt_rejects_later_publication_reason() {
        let mut invalid = receipt();
        invalid.reason_codes =
            BoundedVec::from_vec(vec![DecisionReasonCodeV1::AllowPublished]).unwrap();
        assert_receipt_semantic_rejected(&invalid);
    }

    #[test]
    fn signed_receipt_rejects_later_publication_stage() {
        let mut invalid = receipt();
        invalid.publish_stage = PublishStageV1::PublishReturnedOk;
        assert_receipt_semantic_rejected(&invalid);
    }

    #[test]
    fn signed_receipt_rejects_outcome_reason_mismatch() {
        let mut invalid = receipt();
        invalid.decision = DecisionOutcomeV1::Deny;
        invalid.publish_stage = PublishStageV1::DecidedDeny;
        invalid.effective_validity_ms = None;
        invalid.gate_output_stream = None;
        invalid.output_frame_digest = None;
        invalid.transformation_relation = None;
        assert_receipt_semantic_rejected(&invalid);
    }

    #[test]
    fn signed_receipt_rejects_incomplete_output_binding() {
        let mut invalid = receipt();
        invalid.output_frame_digest = None;
        assert_receipt_semantic_rejected(&invalid);
    }

    #[test]
    fn signed_receipt_rejects_multiple_allow_reasons() {
        let mut invalid = receipt();
        invalid.reason_codes = BoundedVec::from_vec(vec![
            DecisionReasonCodeV1::AllowPrepared,
            DecisionReasonCodeV1::AllowPolicy,
        ])
        .unwrap();
        assert_receipt_semantic_rejected(&invalid);
    }

    #[test]
    fn signed_receipt_rejects_time_regression() {
        let mut invalid = receipt();
        invalid.received_mono_ns = invalid.decided_mono_ns + 1;
        assert_receipt_semantic_rejected(&invalid);
    }

    #[test]
    fn tampered_payload_fails() {
        let k = kid(1);
        let sk = signer(1);
        let trust = trust_with(&k, &sk, KeyRole::ControllerIntent, KeyClass::Assurance);
        let mut env = sign_message(&intent(), KIND, MAJOR, &k, &sk);
        // Flip a byte somewhere in the middle (payload region).
        let mid = env.len() / 2;
        env[mid] ^= 0x01;
        let res: Result<(HaldirIntentV1, _, _), _> = verify_and_decode(
            &env,
            &ctx(),
            &trust,
            &RevocationSnapshot::new(),
            Limits::LARGE,
        );
        assert!(res.is_err(), "tampered envelope must not verify");
    }

    #[test]
    fn wrong_role_key_rejected() {
        let k = kid(1);
        let sk = signer(1);
        // Same key material but registered under the wrong role.
        let trust = trust_with(&k, &sk, KeyRole::MissionAuthority, KeyClass::Assurance);
        let env = sign_message(&intent(), KIND, MAJOR, &k, &sk);
        let res: Result<(HaldirIntentV1, _, _), _> = verify_and_decode(
            &env,
            &ctx(),
            &trust,
            &RevocationSnapshot::new(),
            Limits::LARGE,
        );
        assert_eq!(res.err(), Some(CryptoError::WrongRole));
    }

    #[test]
    fn no_fallback_key_search_kid_resolves_one() {
        // The kid in the envelope points at key 1, but the store only trusts key 2
        // (a different key) under the SAME kid -> signature must fail; the verifier
        // must not "find" the real signing key.
        let real = kid(1);
        let sk_real = signer(1);
        let sk_other = signer(2);
        // Register kid(1) but with key 2's public material.
        let trust = trust_with(
            &real,
            &sk_other,
            KeyRole::ControllerIntent,
            KeyClass::Assurance,
        );
        let env = sign_message(&intent(), KIND, MAJOR, &real, &sk_real);
        let res: Result<(HaldirIntentV1, _, _), _> = verify_and_decode(
            &env,
            &ctx(),
            &trust,
            &RevocationSnapshot::new(),
            Limits::LARGE,
        );
        assert_eq!(res.err(), Some(CryptoError::SignatureInvalid));
    }

    #[test]
    fn unknown_kid_rejected() {
        let k = kid(1);
        let sk = signer(1);
        let trust = TrustStore::new(); // empty
        let env = sign_message(&intent(), KIND, MAJOR, &k, &sk);
        let res: Result<(HaldirIntentV1, _, _), _> = verify_and_decode(
            &env,
            &ctx(),
            &trust,
            &RevocationSnapshot::new(),
            Limits::LARGE,
        );
        assert_eq!(res.err(), Some(CryptoError::KidUnknown));
    }

    #[test]
    fn revoked_key_rejected() {
        let k = kid(1);
        let sk = signer(1);
        let trust = trust_with(&k, &sk, KeyRole::ControllerIntent, KeyClass::Assurance);
        let mut rev = RevocationSnapshot::new();
        rev.revoke_key(&k, 1).unwrap();
        let env = sign_message(&intent(), KIND, MAJOR, &k, &sk);
        let res: Result<(HaldirIntentV1, _, _), _> =
            verify_and_decode(&env, &ctx(), &trust, &rev, Limits::LARGE);
        assert_eq!(res.err(), Some(CryptoError::KeyRevoked));
    }

    #[test]
    fn development_key_rejected_under_assurance() {
        let k = kid(1);
        let sk = signer(1);
        let trust = trust_with(&k, &sk, KeyRole::ControllerIntent, KeyClass::Development);
        let env = sign_message(&intent(), KIND, MAJOR, &k, &sk);
        let res: Result<(HaldirIntentV1, _, _), _> = verify_and_decode(
            &env,
            &ctx(),
            &trust,
            &RevocationSnapshot::new(),
            Limits::LARGE,
        );
        assert_eq!(res.err(), Some(CryptoError::DevelopmentKeyInAssurance));
    }

    #[test]
    fn wrong_kind_context_rejected() {
        // Signed as an intent, but the verifier dispatches with a lease context:
        // content-type/AAD disagree -> reject (H9).
        let k = kid(1);
        let sk = signer(1);
        let trust = trust_with(&k, &sk, KeyRole::ControllerIntent, KeyClass::Assurance);
        let env = sign_message(&intent(), KIND, MAJOR, &k, &sk);
        let bad_ctx = ExpectedContext {
            kind: "haldir.mission_lease",
            schema_major: 1,
            required_role: KeyRole::ControllerIntent,
            assurance_profile: true,
        };
        let res: Result<(HaldirIntentV1, _, _), _> = verify_and_decode(
            &env,
            &bad_ctx,
            &trust,
            &RevocationSnapshot::new(),
            Limits::LARGE,
        );
        assert_eq!(res.err(), Some(CryptoError::ContentTypeMismatch));
    }

    #[test]
    fn typed_decode_rejects_a_matching_envelope_context_for_another_kind() {
        let k = kid(1);
        let sk = signer(1);
        let trust = trust_with(&k, &sk, KeyRole::ControllerIntent, KeyClass::Assurance);
        let wrong_kind = "haldir.mission_lease";
        let env = sign_message(&intent(), wrong_kind, 1, &k, &sk);
        let ctx = ExpectedContext {
            kind: wrong_kind,
            schema_major: 1,
            required_role: KeyRole::ControllerIntent,
            assurance_profile: true,
        };
        let res: Result<(HaldirIntentV1, _, _), _> = verify_and_decode(
            &env,
            &ctx,
            &trust,
            &RevocationSnapshot::new(),
            Limits::LARGE,
        );
        assert_eq!(res.err(), Some(CryptoError::ContentTypeMismatch));
    }

    #[test]
    fn typed_decode_rejects_a_matching_envelope_context_for_another_major() {
        let k = kid(1);
        let sk = signer(1);
        let trust = trust_with(&k, &sk, KeyRole::ControllerIntent, KeyClass::Assurance);
        let env = sign_message(&intent(), HaldirIntentV1::KIND, 2, &k, &sk);
        let ctx = ExpectedContext {
            kind: HaldirIntentV1::KIND,
            schema_major: 2,
            required_role: KeyRole::ControllerIntent,
            assurance_profile: true,
        };
        let res: Result<(HaldirIntentV1, _, _), _> = verify_and_decode(
            &env,
            &ctx,
            &trust,
            &RevocationSnapshot::new(),
            Limits::LARGE,
        );
        assert_eq!(res.err(), Some(CryptoError::ContentTypeMismatch));
    }

    #[test]
    fn protected_type_dispatch_selects_one_exact_context() {
        let k = kid(1);
        let sk = signer(1);
        let trust = trust_with(&k, &sk, KeyRole::ControllerIntent, KeyClass::Assurance);
        let revocations = RevocationSnapshot::new();
        let env = sign_message(&intent(), KIND, 1, &k, &sk);
        let expected_content_type = content_type_for(KIND);

        let (verified, tag) =
            verify_sign1_dispatched(&env, &trust, &revocations, |protected_content_type| {
                (protected_content_type == expected_content_type).then(|| (ctx(), 7u8))
            })
            .unwrap();
        assert_eq!(tag, 7);
        assert!(!verified.payload.is_empty());

        assert_eq!(
            verify_sign1_dispatched(&env, &trust, &revocations, |_| {
                None::<(ExpectedContext<'static>, u8)>
            })
            .err(),
            Some(CryptoError::ContentTypeMismatch)
        );
        let wrong_context = ExpectedContext {
            kind: "haldir.mission_lease",
            schema_major: 1,
            required_role: KeyRole::ControllerIntent,
            assurance_profile: true,
        };
        assert_eq!(
            verify_sign1_dispatched(&env, &trust, &revocations, |_| {
                Some((wrong_context, 9u8))
            })
            .err(),
            Some(CryptoError::ContentTypeMismatch)
        );
    }

    #[test]
    fn duplicate_conflicting_kid_rejected() {
        let k = kid(1);
        let sk1 = signer(1);
        let sk2 = signer(2);
        let mut t = TrustStore::new();
        let original = record(&k, &sk1, KeyRole::ControllerIntent, KeyClass::Assurance);
        t.insert(original.clone()).unwrap();
        // same kid, different key material -> conflict
        assert_eq!(
            t.insert(record(
                &k,
                &sk2,
                KeyRole::ControllerIntent,
                KeyClass::Assurance
            )),
            Err(TrustStoreError::ConflictingKid)
        );
        // same kid, different role -> conflict
        assert_eq!(
            t.insert(record(
                &k,
                &sk1,
                KeyRole::MissionAuthority,
                KeyClass::Assurance
            )),
            Err(TrustStoreError::ConflictingKid)
        );
        // exact idempotent re-insert -> ok
        assert!(
            t.insert(record(
                &k,
                &sk1,
                KeyRole::ControllerIntent,
                KeyClass::Assurance
            ))
            .is_ok()
        );
        assert_eq!(t.len(), 1);
        assert_key_record_eq(t.resolve(&k).unwrap(), &original);
    }

    #[test]
    fn development_only_role_cannot_be_mislabeled_as_assurance() {
        let key_id = kid(1);
        let signing_key = signer(1);
        let mut trust = TrustStore::new();

        assert_eq!(
            trust.insert(record(
                &key_id,
                &signing_key,
                KeyRole::DevelopmentOnly,
                KeyClass::Assurance,
            )),
            Err(TrustStoreError::InvalidDevelopmentClassification)
        );
        assert!(trust.is_empty());

        trust
            .insert(record(
                &key_id,
                &signing_key,
                KeyRole::DevelopmentOnly,
                KeyClass::Development,
            ))
            .unwrap();
        assert_eq!(trust.len(), 1);
    }

    #[test]
    fn duplicate_public_key_under_distinct_kid_is_rejected() {
        let first_kid = kid(1);
        let alias_kid = kid(2);
        let shared_key = signer(1);
        let mut trust = TrustStore::new();
        let original = record(
            &first_kid,
            &shared_key,
            KeyRole::ControllerIntent,
            KeyClass::Assurance,
        );
        trust.insert(original.clone()).unwrap();

        assert_eq!(
            trust.insert(record(
                &alias_kid,
                &shared_key,
                KeyRole::ControllerIntent,
                KeyClass::Assurance,
            )),
            Err(TrustStoreError::ConflictingKeyMaterial)
        );
        assert_eq!(trust.len(), 1, "rejected alias must not mutate trust");
        assert!(trust.resolve(&alias_kid).is_none());
        assert_key_record_eq(trust.resolve(&first_kid).unwrap(), &original);

        // Rejection must not reserve the proposed kid in the primary index.
        let replacement = record(
            &alias_kid,
            &signer(2),
            KeyRole::ControllerIntent,
            KeyClass::Assurance,
        );
        trust.insert(replacement.clone()).unwrap();
        assert_key_record_eq(trust.resolve(&alias_kid).unwrap(), &replacement);
    }

    #[test]
    fn duplicate_public_key_across_roles_is_rejected() {
        let controller_kid = kid(1);
        let mission_kid = kid(2);
        let shared_key = signer(1);
        let controller = record(
            &controller_kid,
            &shared_key,
            KeyRole::ControllerIntent,
            KeyClass::Assurance,
        );
        let mission_alias = record(
            &mission_kid,
            &shared_key,
            KeyRole::MissionAuthority,
            KeyClass::Assurance,
        );
        let mut trust = TrustStore::new();
        trust.insert(controller.clone()).unwrap();

        assert_eq!(
            trust.insert(mission_alias),
            Err(TrustStoreError::ConflictingKeyMaterial)
        );
        assert_eq!(trust.len(), 1);
        assert_key_record_eq(trust.resolve(&controller_kid).unwrap(), &controller);
        assert!(trust.resolve(&mission_kid).is_none());
    }

    #[test]
    fn duplicate_public_key_across_subjects_is_rejected() {
        let first_kid = kid(1);
        let alias_kid = kid(2);
        let shared_key = signer(1);
        let mut original = record(
            &first_kid,
            &shared_key,
            KeyRole::ControllerIntent,
            KeyClass::Assurance,
        );
        original.subject = KeySubject::new("controller-a").unwrap();
        let mut subject_alias = record(
            &alias_kid,
            &shared_key,
            KeyRole::ControllerIntent,
            KeyClass::Assurance,
        );
        subject_alias.subject = KeySubject::new("controller-b").unwrap();
        let mut trust = TrustStore::new();
        trust.insert(original.clone()).unwrap();

        assert_eq!(
            trust.insert(subject_alias),
            Err(TrustStoreError::ConflictingKeyMaterial)
        );
        assert_eq!(trust.len(), 1);
        assert_key_record_eq(trust.resolve(&first_kid).unwrap(), &original);
        assert!(trust.resolve(&alias_kid).is_none());
    }

    #[test]
    fn duplicate_public_key_across_key_classes_is_rejected() {
        let assurance_kid = kid(1);
        let development_kid = kid(2);
        let shared_key = signer(1);
        let assurance = record(
            &assurance_kid,
            &shared_key,
            KeyRole::ControllerIntent,
            KeyClass::Assurance,
        );
        let development_alias = record(
            &development_kid,
            &shared_key,
            KeyRole::ControllerIntent,
            KeyClass::Development,
        );
        let mut trust = TrustStore::new();
        trust.insert(assurance.clone()).unwrap();

        assert_eq!(
            trust.insert(development_alias),
            Err(TrustStoreError::ConflictingKeyMaterial)
        );
        assert_eq!(trust.len(), 1);
        assert_key_record_eq(trust.resolve(&assurance_kid).unwrap(), &assurance);
        assert!(trust.resolve(&development_kid).is_none());
    }

    #[test]
    fn duplicate_public_key_rejection_is_insertion_order_independent() {
        for first_is_controller in [true, false] {
            let controller_kid = kid(1);
            let mission_kid = kid(2);
            let shared_key = signer(1);
            let mut controller = record(
                &controller_kid,
                &shared_key,
                KeyRole::ControllerIntent,
                KeyClass::Assurance,
            );
            controller.subject = KeySubject::new("controller-a").unwrap();
            let mut mission = record(
                &mission_kid,
                &shared_key,
                KeyRole::MissionAuthority,
                KeyClass::Assurance,
            );
            mission.subject = KeySubject::new("mission-authority-a").unwrap();
            let (accepted, rejected) = if first_is_controller {
                (controller, mission)
            } else {
                (mission, controller)
            };
            let accepted_kid = accepted.kid.clone();
            let rejected_kid = rejected.kid.clone();
            let mut trust = TrustStore::new();

            trust.insert(accepted.clone()).unwrap();
            assert_eq!(
                trust.insert(rejected),
                Err(TrustStoreError::ConflictingKeyMaterial)
            );
            assert_eq!(trust.len(), 1);
            assert_key_record_eq(trust.resolve(&accepted_kid).unwrap(), &accepted);
            assert!(trust.resolve(&rejected_kid).is_none());
        }
    }

    #[test]
    fn conflicting_kid_rejection_does_not_reserve_rejected_public_key() {
        let occupied_kid = kid(1);
        let second_kid = kid(2);
        let original_key = signer(1);
        let rejected_key = signer(2);
        let original = record(
            &occupied_kid,
            &original_key,
            KeyRole::ControllerIntent,
            KeyClass::Assurance,
        );
        let mut trust = TrustStore::new();
        trust.insert(original.clone()).unwrap();

        assert_eq!(
            trust.insert(record(
                &occupied_kid,
                &rejected_key,
                KeyRole::ControllerIntent,
                KeyClass::Assurance,
            )),
            Err(TrustStoreError::ConflictingKid)
        );

        // The failed same-kid attempt must not poison the reverse key index.
        let second = record(
            &second_kid,
            &rejected_key,
            KeyRole::ControllerIntent,
            KeyClass::Assurance,
        );
        trust.insert(second.clone()).unwrap();
        assert_eq!(trust.len(), 2);
        assert_key_record_eq(trust.resolve(&occupied_kid).unwrap(), &original);
        assert_key_record_eq(trust.resolve(&second_kid).unwrap(), &second);
    }

    #[test]
    fn conflicting_kid_error_precedes_public_key_alias_error() {
        let first_kid = kid(1);
        let second_kid = kid(2);
        let first_key = signer(1);
        let second_key = signer(2);
        let first = record(
            &first_kid,
            &first_key,
            KeyRole::ControllerIntent,
            KeyClass::Assurance,
        );
        let second = record(
            &second_kid,
            &second_key,
            KeyRole::MissionAuthority,
            KeyClass::Assurance,
        );
        let mut trust = TrustStore::new();
        trust.insert(first.clone()).unwrap();
        trust.insert(second.clone()).unwrap();

        // This conflicts with `first` by kid and aliases `second` by key bytes.
        assert_eq!(
            trust.insert(record(
                &first_kid,
                &second_key,
                KeyRole::MissionAuthority,
                KeyClass::Assurance,
            )),
            Err(TrustStoreError::ConflictingKid)
        );
        assert_eq!(trust.len(), 2);
        assert_key_record_eq(trust.resolve(&first_kid).unwrap(), &first);
        assert_key_record_eq(trust.resolve(&second_kid).unwrap(), &second);
    }

    #[test]
    fn trust_store_disjointness_enforces_lifecycle_key_separation() {
        let first_kid = kid(1);
        let second_kid = kid(2);
        let third_kid = kid(3);
        let first_key = signer(1);
        let second_key = signer(2);
        let third_key = signer(3);
        let first_record = record(
            &first_kid,
            &first_key,
            KeyRole::DeploymentAuthority,
            KeyClass::Assurance,
        );

        let mut bootstrap = TrustStore::new();
        bootstrap.insert(first_record.clone()).unwrap();

        let mut exact_overlap = TrustStore::new();
        exact_overlap.insert(first_record).unwrap();
        assert_eq!(
            bootstrap.validate_disjoint_bindings(&exact_overlap),
            Err(TrustStoreDisjointnessError::OverlappingKid)
        );
        assert_eq!(
            exact_overlap.validate_disjoint_bindings(&bootstrap),
            Err(TrustStoreDisjointnessError::OverlappingKid)
        );

        let mut disjoint = TrustStore::new();
        disjoint
            .insert(record(
                &second_kid,
                &second_key,
                KeyRole::ControllerIntent,
                KeyClass::Assurance,
            ))
            .unwrap();
        assert_eq!(bootstrap.validate_disjoint_bindings(&disjoint), Ok(()));
        assert_eq!(disjoint.validate_disjoint_bindings(&bootstrap), Ok(()));

        let mut conflicting_kid = TrustStore::new();
        conflicting_kid
            .insert(record(
                &first_kid,
                &third_key,
                KeyRole::ControllerIntent,
                KeyClass::Assurance,
            ))
            .unwrap();
        assert_eq!(
            bootstrap.validate_disjoint_bindings(&conflicting_kid),
            Err(TrustStoreDisjointnessError::OverlappingKid)
        );
        assert_eq!(
            conflicting_kid.validate_disjoint_bindings(&bootstrap),
            Err(TrustStoreDisjointnessError::OverlappingKid)
        );

        let mut aliased_key = TrustStore::new();
        aliased_key
            .insert(record(
                &third_kid,
                &first_key,
                KeyRole::MissionAuthority,
                KeyClass::Development,
            ))
            .unwrap();
        assert_eq!(
            bootstrap.validate_disjoint_bindings(&aliased_key),
            Err(TrustStoreDisjointnessError::OverlappingKeyMaterial)
        );
        assert_eq!(
            aliased_key.validate_disjoint_bindings(&bootstrap),
            Err(TrustStoreDisjointnessError::OverlappingKeyMaterial)
        );
    }

    #[test]
    fn cross_snapshot_kid_conflict_precedes_cross_snapshot_key_alias() {
        let first_kid = kid(1);
        let second_kid = kid(2);
        let first_key = signer(1);
        let second_key = signer(2);
        let mut first = TrustStore::new();
        first
            .insert(record(
                &first_kid,
                &first_key,
                KeyRole::ControllerIntent,
                KeyClass::Assurance,
            ))
            .unwrap();
        first
            .insert(record(
                &second_kid,
                &second_key,
                KeyRole::MissionAuthority,
                KeyClass::Assurance,
            ))
            .unwrap();

        let mut second = TrustStore::new();
        second
            .insert(record(
                &first_kid,
                &second_key,
                KeyRole::PolicyAuthority,
                KeyClass::Development,
            ))
            .unwrap();

        assert_eq!(
            first.validate_disjoint_bindings(&second),
            Err(TrustStoreDisjointnessError::OverlappingKid)
        );
        assert_eq!(
            second.validate_disjoint_bindings(&first),
            Err(TrustStoreDisjointnessError::OverlappingKid)
        );
    }

    #[test]
    fn trust_store_disjointness_errors_have_stable_non_record_leaking_semantics() {
        for (error, expected) in [
            (
                TrustStoreDisjointnessError::OverlappingKid,
                "TRUST_STORES_OVERLAPPING_KID",
            ),
            (
                TrustStoreDisjointnessError::OverlappingKeyMaterial,
                "TRUST_STORES_OVERLAPPING_KEY_MATERIAL",
            ),
        ] {
            assert_eq!(error.reason_code(), expected);
            assert_eq!(error.to_string(), expected);
            assert!(std::error::Error::source(&error).is_none());
        }
    }

    #[test]
    fn trust_store_errors_have_stable_non_record_leaking_semantics() {
        let cases = [
            (
                TrustStoreError::ConflictingKid,
                "TRUST_STORE_CONFLICTING_KID",
            ),
            (
                TrustStoreError::ConflictingKeyMaterial,
                "TRUST_STORE_PUBLIC_KEY_ALREADY_ENROLLED",
            ),
            (
                TrustStoreError::InvalidDevelopmentClassification,
                "TRUST_STORE_INVALID_DEVELOPMENT_CLASSIFICATION",
            ),
            (
                TrustStoreError::CapacityExceeded,
                "TRUST_STORE_CAPACITY_EXCEEDED",
            ),
        ];

        for (error, expected) in cases {
            assert_eq!(error.reason_code(), expected);
            assert_eq!(error.to_string(), expected);
            assert!(std::error::Error::source(&error).is_none());
        }
    }

    #[test]
    fn trust_store_capacity_is_exact_and_failure_is_atomic() {
        let mut trust = TrustStore::new();
        for seed in 1..=u8::try_from(MAX_TRUSTED_KEYS).unwrap() {
            let key_id = kid(seed);
            trust
                .insert(record(
                    &key_id,
                    &signer(seed),
                    KeyRole::ControllerIntent,
                    KeyClass::Assurance,
                ))
                .unwrap();
        }
        assert_eq!(trust.len(), MAX_TRUSTED_KEYS);

        let rejected_kid = kid(u8::try_from(MAX_TRUSTED_KEYS + 1).unwrap());
        assert_eq!(
            trust.insert(record(
                &rejected_kid,
                &signer(u8::try_from(MAX_TRUSTED_KEYS + 1).unwrap()),
                KeyRole::ControllerIntent,
                KeyClass::Assurance,
            )),
            Err(TrustStoreError::CapacityExceeded)
        );
        assert_eq!(trust.len(), MAX_TRUSTED_KEYS);
        assert!(trust.resolve(&rejected_kid).is_none());

        let existing_kid = kid(1);
        assert_eq!(
            trust.insert(record(
                &existing_kid,
                &signer(2),
                KeyRole::ControllerIntent,
                KeyClass::Assurance,
            )),
            Err(TrustStoreError::ConflictingKid)
        );
        assert_eq!(
            trust.insert(record(
                &rejected_kid,
                &signer(1),
                KeyRole::ControllerIntent,
                KeyClass::Assurance,
            )),
            Err(TrustStoreError::ConflictingKeyMaterial)
        );
    }

    #[test]
    fn revocation_updates_are_bounded_strictly_versioned_and_atomic() {
        let first = kid(1);
        let second = kid(2);
        let mut revocations = RevocationSnapshot::new();
        revocations.revoke_key(&first, 1).unwrap();

        assert_eq!(
            revocations.revoke_key(&second, 1),
            Err(RevocationError::EpochNotAdvanced)
        );
        assert_eq!(revocations.epoch(), 1);
        assert!(!revocations.is_key_revoked(&second));
        revocations.revoke_key(&first, 0).unwrap();
        assert_eq!(revocations.epoch(), 1);
        revocations.revoke_key(&first, 3).unwrap();
        assert_eq!(revocations.epoch(), 3);
        assert_eq!(
            revocations.revoke_key(&second, 2),
            Err(RevocationError::EpochNotAdvanced)
        );
        revocations.revoke_key(&second, 4).unwrap();
        assert_eq!(revocations.epoch(), 4);

        let mut full = RevocationSnapshot::new();
        for epoch in 1..=u64::try_from(MAX_REVOKED_KEYS).unwrap() {
            let key_id = KeyId::new(epoch.to_be_bytes().to_vec()).unwrap();
            full.revoke_key(&key_id, epoch).unwrap();
        }
        let rejected = KeyId::new(
            u64::try_from(MAX_REVOKED_KEYS + 1)
                .unwrap()
                .to_be_bytes()
                .to_vec(),
        )
        .unwrap();
        assert_eq!(
            full.revoke_key(&rejected, u64::try_from(MAX_REVOKED_KEYS + 1).unwrap()),
            Err(RevocationError::CapacityExceeded)
        );
        assert_eq!(full.epoch(), u64::try_from(MAX_REVOKED_KEYS).unwrap());
        assert!(!full.is_key_revoked(&rejected));

        for (error, code) in [
            (
                RevocationError::EpochNotAdvanced,
                "REVOCATION_EPOCH_NOT_ADVANCED",
            ),
            (
                RevocationError::CapacityExceeded,
                "REVOCATION_CAPACITY_EXCEEDED",
            ),
        ] {
            assert_eq!(error.reason_code(), code);
            assert_eq!(error.to_string(), code);
        }
    }

    #[test]
    fn wrong_major_version_type_context_and_cose_aad_are_rejected() {
        let k = kid(1);
        let sk = signer(1);
        let trust = trust_with(&k, &sk, KeyRole::ControllerIntent, KeyClass::Assurance);
        let env = sign_message(&intent(), KIND, MAJOR, &k, &sk);
        let bad_ctx = ExpectedContext {
            kind: KIND,
            schema_major: 2,
            required_role: KeyRole::ControllerIntent,
            assurance_profile: true,
        };
        // The low-level COSE path proves the `{kind}.v{major}` external-AAD
        // separation even without typed decoding.
        assert_eq!(
            verify_sign1(&env, &bad_ctx, &trust, &RevocationSnapshot::new()).err(),
            Some(CryptoError::SignatureInvalid)
        );
        // The higher-level Rust V1 type rejects a V2 context before verification.
        let res: Result<(HaldirIntentV1, _, _), _> = verify_and_decode(
            &env,
            &bad_ctx,
            &trust,
            &RevocationSnapshot::new(),
            Limits::LARGE,
        );
        assert_eq!(res.err(), Some(CryptoError::ContentTypeMismatch));
    }
}
