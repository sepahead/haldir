//! `HaldirIntentV1` — a signed request for a semantic action. It is NOT an NCP
//! frame: it carries no final NCP stream sequence, publisher timestamp, plant
//! authority, or serialized final frame.
//!
//! Every scope/source/session field on the intent is a **consistency claim**
//! checked against independently retained Gate authority and state (punch-list
//! B4). After authorization, Gate derives a new command from the checked action,
//! trusted source correlation, and its own output stream; it never forwards a
//! controller-supplied final frame.

use crate::action::RequestedActionV1;
use crate::digest::{DigestDomain, DigestV1};
use crate::ids::{
    AdmissionId, ControllerId, ControllerInstanceId, GateBootId, GateId, KeyId, MissionId,
    MissionLeaseId, VehicleId,
};
use crate::scalar::{AsciiId, BoundedAscii, BoundedVec};
use crate::session::{HaldirIntentPositionV1, NcpSessionIdentityV1, NcpSourceRefV1};
use core::num::NonZeroU64;

canonical_struct! {
    /// A signed schema v1.0 controller intent (spec §HaldirIntentV1).
    pub struct HaldirIntentV1 kind "haldir.intent" {
        req 2 schema_major: u16,
        req 3 schema_minor: u16,
        req 4 controller_id: ControllerId,
        req 5 controller_instance_id: ControllerInstanceId,
        req 6 controller_signing_key_id: KeyId,
        req 7 actual_intent_key: BoundedAscii<256>,
        req 8 gate_id: GateId,
        req 9 gate_boot_id: GateBootId,
        req 10 realm: AsciiId<64>,
        req 11 vehicle_id: VehicleId,
        req 12 mission_id: MissionId,
        req 13 ncp_session: NcpSessionIdentityV1,
        req 14 mission_lease_id: MissionLeaseId,
        req 15 mission_lease_term: NonZeroU64,
        req 16 admission_id: AdmissionId,
        req 17 admission_digest: DigestV1,
        req 18 controller_bundle_digest: DigestV1,
        req 19 backend_profile_digest: DigestV1,
        req 20 intent_position: HaldirIntentPositionV1,
        req 21 controller_t_ns: u64,
        req 22 primary_source: NcpSourceRefV1,
        req 23 input_watermarks: BoundedVec<NcpSourceRefV1, 8>,
        req 24 action: RequestedActionV1,
        opt 25 controller_context_digest: DigestV1,
    }
}

// This is deliberately a distinct canonical object, not a second digest of the
// full signed payload. It contains every signed intent field that Gate uses to
// bind or decide the requested action. Controller-process provenance and
// diagnostics remain committed by the payload digest but cannot perturb the
// semantic identity of an otherwise identical request.
canonical_struct! {
    struct SemanticIntentV1 {
        req 1 controller_id: ControllerId,
        req 2 controller_signing_key_id: KeyId,
        req 3 actual_intent_key: BoundedAscii<256>,
        req 4 gate_id: GateId,
        req 5 gate_boot_id: GateBootId,
        req 6 realm: AsciiId<64>,
        req 7 vehicle_id: VehicleId,
        req 8 mission_id: MissionId,
        req 9 ncp_session: NcpSessionIdentityV1,
        req 10 mission_lease_id: MissionLeaseId,
        req 11 mission_lease_term: NonZeroU64,
        req 12 admission_id: AdmissionId,
        req 13 admission_digest: DigestV1,
        req 14 controller_bundle_digest: DigestV1,
        req 15 backend_profile_digest: DigestV1,
        req 16 intent_position: HaldirIntentPositionV1,
        req 17 primary_source: NcpSourceRefV1,
        req 18 action: RequestedActionV1,
    }
}

impl HaldirIntentV1 {
    /// Digest the canonical action plus every signed field Gate uses to bind or
    /// decide it.
    ///
    /// The projection intentionally excludes schema framing, the unsupported
    /// (therefore empty) `input_watermarks`, and controller-local observational
    /// provenance: `controller_instance_id`, `controller_t_ns`, and
    /// `controller_context_digest`. Those fields remain authenticated and are
    /// committed by the exact canonical payload digest.
    #[must_use]
    pub fn semantic_digest(&self) -> DigestV1 {
        let semantic = SemanticIntentV1 {
            controller_id: self.controller_id.clone(),
            controller_signing_key_id: self.controller_signing_key_id.clone(),
            actual_intent_key: self.actual_intent_key.clone(),
            gate_id: self.gate_id.clone(),
            gate_boot_id: self.gate_boot_id,
            realm: self.realm.clone(),
            vehicle_id: self.vehicle_id.clone(),
            mission_id: self.mission_id.clone(),
            ncp_session: self.ncp_session.clone(),
            mission_lease_id: self.mission_lease_id,
            mission_lease_term: self.mission_lease_term,
            admission_id: self.admission_id,
            admission_digest: self.admission_digest,
            controller_bundle_digest: self.controller_bundle_digest,
            backend_profile_digest: self.backend_profile_digest,
            intent_position: self.intent_position.clone(),
            primary_source: self.primary_source.clone(),
            action: self.action,
        };
        DigestV1::of_value(DigestDomain::SemanticIntent, &semantic)
    }
}

impl crate::cbor::Validate for HaldirIntentV1 {
    fn validate(&self) -> Result<(), crate::error::DecodeError> {
        if self.schema_major != 1 || self.schema_minor != 0 {
            return Err(crate::error::DecodeError::UnsupportedVersion);
        }
        // The v1 Gate has an exact authority rule only for `primary_source`.
        // Accepting additional signed watermarks without defining how each is
        // authenticated, freshness-checked, and bound into policy would make
        // them misleading non-authoritative metadata. A later schema may add
        // those semantics; v1 fails closed instead of silently ignoring them.
        if !self.input_watermarks.is_empty() {
            return Err(crate::error::DecodeError::SemanticInvalid {
                code: "INTENT_INPUT_WATERMARKS_UNSUPPORTED",
            });
        }
        Ok(())
    }
}
