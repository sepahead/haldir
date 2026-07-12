//! `HaldirIntentV1` — a signed request for a semantic action. It is NOT an NCP
//! frame: it carries no final NCP stream sequence, publisher timestamp, plant
//! authority, or serialized final frame.
//!
//! Every scope/source/session field on the intent is a **consistency claim**
//! checked for equality against Gate's own snapshot (punch-list B4); no field is
//! copied into the emitted command.

use crate::action::RequestedActionV1;
use crate::digest::DigestV1;
use crate::ids::{
    AdmissionId, ControllerId, ControllerInstanceId, GateBootId, GateId, KeyId, MissionId,
    MissionLeaseId, VehicleId,
};
use crate::scalar::{AsciiId, BoundedAscii, BoundedVec};
use crate::session::{HaldirIntentPositionV1, NcpSessionIdentityV1, NcpSourceRefV1};
use core::num::NonZeroU64;

canonical_struct! {
    /// A signed controller intent (spec §HaldirIntentV1).
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

impl crate::cbor::Validate for HaldirIntentV1 {
    fn validate(&self) -> Result<(), crate::error::DecodeError> {
        if self.schema_major != 1 {
            return Err(crate::error::DecodeError::UnsupportedVersion);
        }
        Ok(())
    }
}
