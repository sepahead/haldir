//! `AuthorityRevocationV1` — one signed revocation form for mission leases,
//! admissions, controller signing keys, and policy packages.

use crate::digest::DigestV1;
use crate::ids::{KeyId, VehicleId};
use crate::scalar::AsciiId;
use core::num::NonZeroU64;

tagged_enum! {
    /// The subject class a revocation applies to.
    pub enum RevocationSubjectV1 {
        MissionLease = 1 => "MISSION_LEASE",
        Admission = 2 => "ADMISSION",
        ControllerKey = 3 => "CONTROLLER_KEY",
        PolicyPackage = 4 => "POLICY_PACKAGE",
    }
}

canonical_struct! {
    /// A signed revocation. Carries an issuer-monotonic `revocation_epoch` and
    /// either a specific object digest or a `revoke_terms_at_or_below` cutoff.
    pub struct AuthorityRevocationV1 kind "haldir.authority_revocation" {
        req 2 schema_major: u16,
        req 3 schema_minor: u16,
        req 4 issuer_id: AsciiId<64>,
        req 5 issuer_key_id: KeyId,
        req 6 subject_type: RevocationSubjectV1,
        req 7 revocation_epoch: NonZeroU64,
        req 8 realm: AsciiId<64>,
        req 9 vehicle_id: VehicleId,
        opt 10 subject_object_digest: DigestV1,
        opt 11 revoke_terms_at_or_below: NonZeroU64,
    }
}

impl crate::cbor::Validate for AuthorityRevocationV1 {
    fn validate(&self) -> Result<(), crate::error::DecodeError> {
        if self.schema_major != 1 {
            return Err(crate::error::DecodeError::UnsupportedVersion);
        }
        // A revocation must name at least one of: a specific object, or a cutoff.
        if self.subject_object_digest.is_none() && self.revoke_terms_at_or_below.is_none() {
            return Err(crate::error::DecodeError::SemanticInvalid {
                code: "REVOCATION_NO_SUBJECT",
            });
        }
        Ok(())
    }
}
