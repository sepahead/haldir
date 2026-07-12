//! `MissionLeaseV1` — grants a named controller deployment permission to request
//! a bounded class of semantic actions through one Gate boot and one NCP session.
//! It is not a plant command and grants no final-key publication rights.

use crate::action::{ActionClassV1, CoordinateFrameV1};
use crate::digest::DigestV1;
use crate::ids::{
    AdmissionId, ChallengeNonce, ControllerId, GateBootId, GateId, GateOutputEpoch, KeyId,
    MissionId, MissionLeaseId, VehicleId,
};
use crate::limits::MissionLeaseLimitsV1;
use crate::scalar::{AsciiId, BoundedAscii, BoundedSet, BoundedVec};
use crate::session::NcpSessionIdentityV1;
use core::num::{NonZeroU32, NonZeroU64};

canonical_struct! {
    /// A signed mission-intent lease (spec §MissionLeaseV1).
    pub struct MissionLeaseV1 kind "haldir.mission_lease" {
        req 2 schema_major: u16,
        req 3 schema_minor: u16,
        req 4 issuer_id: AsciiId<64>,
        req 5 issuer_key_id: KeyId,
        req 6 lease_id: MissionLeaseId,
        req 7 lease_term: NonZeroU64,
        req 8 gate_id: GateId,
        req 9 gate_boot_id: GateBootId,
        req 10 challenge_nonce: ChallengeNonce,
        req 11 realm: AsciiId<64>,
        req 12 vehicle_id: VehicleId,
        req 13 mission_id: MissionId,
        req 14 mission_phase: AsciiId<64>,
        req 15 ncp_session: NcpSessionIdentityV1,
        req 16 gate_output_epoch: GateOutputEpoch,
        req 17 controller_id: ControllerId,
        req 18 controller_intent_key: BoundedAscii<256>,
        req 19 controller_intent_signing_key_id: KeyId,
        req 20 admission_id: AdmissionId,
        req 21 admission_digest: DigestV1,
        req 22 controller_bundle_digest: DigestV1,
        req 23 backend_profile_digest: DigestV1,
        req 24 policy_snapshot_digest: DigestV1,
        req 25 allowed_actions: BoundedSet<ActionClassV1, 16>,
        req 26 allowed_frames: BoundedSet<CoordinateFrameV1, 8>,
        req 27 allowed_source_keys: BoundedVec<BoundedAscii<256>, 8>,
        req 28 limits: MissionLeaseLimitsV1,
        req 29 max_active_duration_ms: NonZeroU32,
        req 30 max_intent_rate_millihz: NonZeroU32,
        req 31 max_total_intents: NonZeroU64,
        opt 32 operator_context_digest: DigestV1,
    }
}

impl crate::cbor::Validate for MissionLeaseV1 {
    fn validate(&self) -> Result<(), crate::error::DecodeError> {
        if self.schema_major != 1 {
            return Err(crate::error::DecodeError::UnsupportedVersion);
        }
        if self.allowed_actions.is_empty() {
            return Err(crate::error::DecodeError::SemanticInvalid {
                code: "LEASE_EMPTY_ACTION_SET",
            });
        }
        if self.allowed_frames.is_empty() {
            return Err(crate::error::DecodeError::SemanticInvalid {
                code: "LEASE_EMPTY_FRAME_SET",
            });
        }
        if self.allowed_source_keys.is_empty() {
            return Err(crate::error::DecodeError::SemanticInvalid {
                code: "LEASE_EMPTY_SOURCE_KEYS",
            });
        }
        Ok(())
    }
}
