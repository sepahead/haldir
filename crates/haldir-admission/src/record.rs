//! `AdmissionRecordV1` — the exact backend-specific relation the admission
//! authority approves. Signed (COSE) by the admission authority; this crate
//! operates on records whose signature the deployment loader already verified.

use crate::types::AdmissionLevelV1;
use core::num::NonZeroU64;
use haldir_contracts::digest::DigestV1;
use haldir_contracts::ids::{AdmissionId, ControllerId};
use haldir_contracts::scalar::AsciiId;

haldir_contracts::canonical_struct! {
    /// A signed admission record binding a logical bundle, admission profile,
    /// backend execution profile, codec, and evidence level.
    pub struct AdmissionRecordV1 kind "haldir.admission_record" {
        req 2 schema_major: u16,
        req 3 schema_minor: u16,
        req 4 issuer_id: AsciiId<64>,
        req 5 admission_id: AdmissionId,
        req 6 controller_id: ControllerId,
        req 7 admission_profile_id: AsciiId<64>,
        req 8 level: AdmissionLevelV1,
        req 9 controller_bundle_digest: DigestV1,
        req 10 backend_profile_digest: DigestV1,
        req 11 codec_digest: DigestV1,
        req 12 validity_term: NonZeroU64,
        opt 13 conformance_run_digest: DigestV1,
    }
}

impl AdmissionRecordV1 {
    /// The domain-separated digest of this record (the value carried as
    /// `admission_digest` in leases and intents).
    #[must_use]
    pub fn admission_digest(&self) -> DigestV1 {
        DigestV1::of_value(haldir_contracts::digest::DigestDomain::Admission, self)
    }
}

impl haldir_contracts::cbor::Validate for AdmissionRecordV1 {
    fn validate(&self) -> Result<(), haldir_contracts::error::DecodeError> {
        if self.schema_major != 1 {
            return Err(haldir_contracts::error::DecodeError::UnsupportedVersion);
        }
        // A semantic admission requires that the level actually be semantic.
        Ok(())
    }
}
