//! `GateChallengeV1` — proves liveness of one Gate process incarnation and gives
//! external authorities a one-time value to bind into a lease.

use crate::digest::DigestV1;
use crate::ids::{
    ChallengeNonce, ChallengeSeq, GateBootId, GateId, GateOutputEpoch, KeyId, VehicleId,
};
use crate::limits::ContractVersion;
use crate::scalar::{AsciiId, BoundedVec};
use crate::session::NcpSessionIdentityV1;

canonical_struct! {
    /// A signed Gate challenge. Its local validity deadline is intentionally not an
    /// externally authoritative timestamp; Gate stores the nonce in a bounded
    /// pending-challenge table with a local monotonic expiry (spec §GateChallengeV1).
    pub struct GateChallengeV1 kind "haldir.gate_challenge" {
        req 2 schema_major: u16,
        req 3 schema_minor: u16,
        req 4 gate_id: GateId,
        req 5 gate_boot_id: GateBootId,
        req 6 challenge_nonce: ChallengeNonce,
        req 7 challenge_seq: ChallengeSeq,
        req 8 realm: AsciiId<64>,
        req 9 vehicle_id: VehicleId,
        req 10 ncp_session: NcpSessionIdentityV1,
        req 11 gate_output_epoch: GateOutputEpoch,
        req 12 gate_key_id: KeyId,
        req 13 policy_snapshot_digest: DigestV1,
        req 14 accepted_contract_versions: BoundedVec<ContractVersion, 8>,
        req 15 ncp_compatibility_id: DigestV1,
    }
}

impl crate::cbor::Validate for GateChallengeV1 {
    fn validate(&self) -> Result<(), crate::error::DecodeError> {
        if self.schema_major != 1 {
            return Err(crate::error::DecodeError::UnsupportedVersion);
        }
        if self.accepted_contract_versions.is_empty() {
            return Err(crate::error::DecodeError::SemanticInvalid {
                code: "CHALLENGE_NO_CONTRACT_VERSIONS",
            });
        }
        Ok(())
    }
}
