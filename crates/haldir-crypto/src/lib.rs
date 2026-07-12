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

pub use cose::{ExpectedContext, VerifiedCose, content_type_for, external_aad_for, verify_sign1};
pub use error::CryptoError;
pub use key::{Signature, SigningKey, VerifyingKey};
pub use role::{KeyClass, KeyRole};
pub use trust::{KeyRecord, RevocationSnapshot, TrustStore, TrustStoreError};

use haldir_contracts::cbor::{
    CanonicalValue, Limits, Validate, from_canonical_bytes, to_canonical_bytes,
};
use haldir_contracts::ids::KeyId;

/// Canonically encode and COSE-sign a Haldir message under `kid`, binding the
/// message kind and major version into the content-type and external AAD.
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

/// Verify a signed envelope and then canonically decode the payload.
///
/// The signature is checked over the exact received payload bytes; the payload
/// is then decoded with canonical re-encoding equality, so a validly-signed but
/// non-canonical payload is rejected.
///
/// # Errors
/// Returns a [`CryptoError`] on any verification or canonical-decode failure.
pub fn verify_and_decode<T: CanonicalValue + Validate>(
    env: &[u8],
    ctx: &ExpectedContext,
    trust: &TrustStore,
    revocations: &RevocationSnapshot,
    limits: Limits,
) -> Result<(T, KeyId, Option<String>), CryptoError> {
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
    use haldir_contracts::ids::{
        AdmissionId, ControllerId, ControllerInstanceId, GateBootId, GateId, IntentEpoch,
        IntentSeq, MissionId, MissionLeaseId, SourceSeq, VehicleId,
    };
    use haldir_contracts::intent::HaldirIntentV1;
    use haldir_contracts::scalar::{AsciiId, BoundedAscii, BoundedVec, CanonicalUuidV4String};
    use haldir_contracts::session::{HaldirIntentPositionV1, NcpSessionIdentityV1, NcpSourceRefV1};

    const KIND: &str = "haldir.intent";
    const MAJOR: u16 = 1;

    fn kid(seed: u8) -> KeyId {
        KeyId::new(vec![seed, 0xAA, seed]).unwrap()
    }

    fn signer(seed: u8) -> SigningKey {
        SigningKey::from_seed([seed; 32])
    }

    fn dig(s: u8) -> DigestV1 {
        DigestV1::compute(DigestDomain::Payload, &[s])
    }

    fn record(k: &KeyId, sk: &SigningKey, role: KeyRole, class: KeyClass) -> KeyRecord {
        KeyRecord {
            kid: k.clone(),
            role,
            verifying_key: sk.verifying_key(),
            subject: Some("survey-v1".to_owned()),
            class,
        }
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

    fn ctx() -> ExpectedContext<'static> {
        ExpectedContext {
            kind: KIND,
            schema_major: MAJOR,
            required_role: KeyRole::ControllerIntent,
            assurance_profile: true,
        }
    }

    fn trust_with(k: &KeyId, sk: &SigningKey, role: KeyRole, class: KeyClass) -> TrustStore {
        let mut t = TrustStore::new();
        t.insert(record(k, sk, role, class)).unwrap();
        t
    }

    #[test]
    fn happy_path_verifies_and_decodes() {
        let k = kid(1);
        let sk = signer(1);
        let trust = trust_with(&k, &sk, KeyRole::ControllerIntent, KeyClass::Assurance);
        let env = sign_message(&intent(), KIND, MAJOR, &k, &sk);
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
        assert_eq!(subject, Some("survey-v1".to_owned()));
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
        rev.revoke_key(&k, 1);
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
    fn duplicate_conflicting_kid_rejected() {
        let k = kid(1);
        let sk1 = signer(1);
        let sk2 = signer(2);
        let mut t = TrustStore::new();
        t.insert(record(
            &k,
            &sk1,
            KeyRole::ControllerIntent,
            KeyClass::Assurance,
        ))
        .unwrap();
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
    }

    #[test]
    fn wrong_major_version_aad_rejected() {
        // AAD encodes the major version; verifying at a different major fails.
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
        let res: Result<(HaldirIntentV1, _, _), _> = verify_and_decode(
            &env,
            &bad_ctx,
            &trust,
            &RevocationSnapshot::new(),
            Limits::LARGE,
        );
        assert_eq!(res.err(), Some(CryptoError::SignatureInvalid));
    }
}
