//! `GateStatusV1`, process/readiness state, and the plant-publication authority
//! state.
//!
//! `PlantPublicationAuthorityStateV1` keeps `AclExclusiveV1` and `NcpLeaseV1` as
//! DISTINCT variants — never one ambiguous `has_authority` boolean (punch-list
//! H8). Under `PRE_AUTHORITY_ACL_ONLY` the future wire `authority.term`/`lease_id`
//! are simply absent.

use crate::cbor::{CanonicalValue, CborReader, CborWriter};
use crate::digest::DigestV1;
use crate::error::DecodeError;
use crate::ids::{
    AdmissionId, AuthorityLeaseId, DecisionId, GateBootId, GateId, GateOutputEpoch, MissionLeaseId,
    PrincipalId, VehicleId,
};
use crate::session::NcpSessionIdentityV1;
use core::num::NonZeroU64;

tagged_enum! {
    /// Gate process lifecycle state.
    pub enum GateProcessStateV1 {
        Booting = 1 => "BOOTING",
        Recovering = 2 => "RECOVERING",
        ReadyNoSession = 3 => "READY_NO_SESSION",
        SessionBound = 4 => "SESSION_BOUND",
        Active = 5 => "ACTIVE",
        Quiescing = 6 => "QUIESCING",
        FaultLatched = 7 => "FAULT_LATCHED",
    }
}

tagged_enum! {
    /// Whether every mandatory trusted-state source is fresh and ready.
    pub enum StateReadinessV1 {
        NotReady = 1 => "NOT_READY",
        Ready = 2 => "READY",
    }
}

tagged_enum! {
    /// Evidence-spool health.
    pub enum EvidenceHealthV1 {
        Nominal = 1 => "NOMINAL",
        Degraded = 2 => "DEGRADED",
        SpoolFull = 3 => "SPOOL_FULL",
    }
}

tagged_enum! {
    /// Why the plant-publication authority is unavailable.
    pub enum PlantPublicationUnavailableReasonV1 {
        NoMtls = 1 => "NO_MTLS",
        AclNotProvisioned = 2 => "ACL_NOT_PROVISIONED",
        SessionUnknown = 3 => "SESSION_UNKNOWN",
        PriorStreamLive = 4 => "PRIOR_STREAM_LIVE",
        Faulted = 5 => "FAULTED",
    }
}

canonical_struct! {
    /// The evidence that one authenticated Gate principal is the sole permitted
    /// publisher of the final route in the current `PRE_AUTHORITY_ACL_ONLY` profile.
    /// This is deployment evidence, NOT a plant-issued NCP lease.
    pub struct AclExclusiveEvidenceV1 {
        req 1 gate_transport_principal: PrincipalId,
        req 2 final_route_digest: DigestV1,
        req 3 certificate_fingerprint: DigestV1,
        req 4 acl_policy_digest: DigestV1,
        req 5 verified_at_mono_ns: u64,
    }
}

canonical_struct! {
    /// A future NCP plant-authority lease held by Gate. Unavailable until a reviewed
    /// upstream NCP release defines it; never serialized as an ACL evidence record.
    pub struct NcpLeaseEvidenceV1 {
        req 1 gate_transport_principal: PrincipalId,
        req 2 final_route_digest: DigestV1,
        req 3 session: NcpSessionIdentityV1,
        req 4 authority_term: NonZeroU64,
        req 5 lease_id: AuthorityLeaseId,
        req 6 authorized_output_epoch: GateOutputEpoch,
        opt 7 expires_mono_ns: u64,
    }
}

/// The plant-publication authority state, with distinct variants per compatibility
/// profile (H8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlantPublicationAuthorityStateV1 {
    /// No exclusive publication capability is currently established.
    Unavailable {
        /// Why publication is unavailable.
        reason: PlantPublicationUnavailableReasonV1,
    },
    /// Current profile: one authenticated Gate principal alone may publish the route.
    AclExclusiveV1(AclExclusiveEvidenceV1),
    /// Future profile: a plant-issued NCP authority lease (not used under P0).
    NcpLeaseV1(NcpLeaseEvidenceV1),
}

impl PlantPublicationAuthorityStateV1 {
    /// The compatibility profile string this state represents.
    #[must_use]
    pub const fn compatibility(&self) -> &'static str {
        match self {
            Self::Unavailable { .. } => "UNAVAILABLE",
            Self::AclExclusiveV1(_) => "PRE_AUTHORITY_ACL_ONLY",
            Self::NcpLeaseV1(_) => "NCP_PLANT_AUTHORITY",
        }
    }

    /// Whether this state currently authorizes publication.
    #[must_use]
    pub const fn authorizes_publication(&self) -> bool {
        !matches!(self, Self::Unavailable { .. })
    }
}

impl CanonicalValue for PlantPublicationAuthorityStateV1 {
    fn encode(&self, w: &mut CborWriter) {
        w.map_header(1);
        match self {
            Self::Unavailable { reason } => {
                w.uint(1);
                w.map_header(1);
                w.uint(1);
                reason.encode(w);
            }
            Self::AclExclusiveV1(e) => {
                w.uint(2);
                e.encode(w);
            }
            Self::NcpLeaseV1(e) => {
                w.uint(3);
                e.encode(w);
            }
        }
    }

    fn decode(r: &mut CborReader<'_>) -> Result<Self, DecodeError> {
        let n = r.read_map_len()?;
        if n != 1 {
            r.end_container();
            return Err(DecodeError::BadEnumTag);
        }
        let tag = r.read_map_key()?;
        let out = match tag {
            1 => {
                let bn = r.read_map_len()?;
                if bn != 1 {
                    r.end_container();
                    return Err(DecodeError::BadEnumTag);
                }
                let k = r.read_map_key()?;
                if k != 1 {
                    return Err(DecodeError::UnknownField { key: k });
                }
                let reason = PlantPublicationUnavailableReasonV1::decode(r)?;
                r.end_container();
                Self::Unavailable { reason }
            }
            2 => Self::AclExclusiveV1(AclExclusiveEvidenceV1::decode(r)?),
            3 => Self::NcpLeaseV1(NcpLeaseEvidenceV1::decode(r)?),
            _ => return Err(DecodeError::BadEnumTag),
        };
        r.end_container();
        Ok(out)
    }
}

canonical_struct! {
    /// A signed, read-only Gate status object. Contains no keys, certificates, raw
    /// payloads, or administrative tokens.
    pub struct GateStatusV1 kind "haldir.gate_status" {
        req 2 gate_id: GateId,
        req 3 gate_boot_id: GateBootId,
        req 4 vehicle_id: VehicleId,
        req 5 status_seq: NonZeroU64,
        req 6 process_state: GateProcessStateV1,
        opt 7 ncp_session: NcpSessionIdentityV1,
        opt 8 output_epoch: GateOutputEpoch,
        opt 9 mission_lease_id: MissionLeaseId,
        opt 10 admission_id: AdmissionId,
        req 11 policy_snapshot_digest: DigestV1,
        req 12 state_readiness: StateReadinessV1,
        req 13 plant_publication_state: PlantPublicationAuthorityStateV1,
        req 14 evidence_health: EvidenceHealthV1,
        opt 15 last_decision_id: DecisionId,
        req 16 emitted_mono_ns: u64,
    }
}

impl crate::cbor::Validate for GateStatusV1 {}
