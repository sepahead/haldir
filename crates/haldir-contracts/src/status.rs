//! `GateStatusV1`, process/readiness state, and the plant-publication authority
//! state.
//!
//! `PlantPublicationAuthorityStateV1` keeps `AclExclusiveV1` and `NcpLeaseV1` as
//! DISTINCT variants — never one ambiguous `has_authority` boolean (punch-list
//! H8). Exclusive-route ACL evidence and an NCP authority lease answer different
//! questions; NCP 1.0 publication needs both.

use crate::cbor::{CanonicalValue, CborReader, CborWriter};
use crate::digest::DigestV1;
use crate::error::DecodeError;
use crate::ids::{
    AdmissionId, DecisionId, GateBootId, GateId, GateOutputEpoch, MissionLeaseId, PrincipalId,
    VehicleId,
};
use crate::scalar::CanonicalUuidV4String;
use crate::session::NcpSessionIdentityV1;
use core::num::NonZeroU64;

const NANOS_PER_MS: u64 = 1_000_000;

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
    /// publisher of the final route: deployment evidence, not an NCP authority lease.
    /// Under NCP 1.0, Gate publishes only with both.
    /// `final_route_digest` uses `DigestDomain::TransportKey` over the exact
    /// final route's UTF-8 bytes.
    pub struct AclExclusiveEvidenceV1 {
        req 1 gate_transport_principal: PrincipalId,
        req 2 final_route_digest: DigestV1,
        req 3 certificate_fingerprint: DigestV1,
        req 4 acl_policy_digest: DigestV1,
        req 5 verified_at_mono_ns: u64,
    }
}

canonical_struct! {
    /// An NCP 1.0 authority lease that Gate holds for one plant session
    /// incarnation. Under NCP `1.0.0-rc.1` Gate issues the lease to itself
    /// (`issuer_principal == gate_transport_principal`) and the body's authority
    /// machine enforces it; under NCP ADR-006 the body issues it. The UTC bounds
    /// travel on the wire as audit metadata; the Gate-local `expires_mono_ns`
    /// alone ends publication. `final_route_digest` uses
    /// `DigestDomain::TransportKey` over the exact final route's UTF-8 bytes.
    pub struct NcpLeaseEvidenceV1 {
        req 1 gate_transport_principal: PrincipalId,
        req 2 final_route_digest: DigestV1,
        req 3 session: NcpSessionIdentityV1,
        req 4 authority_term: NonZeroU64,
        req 5 lease_id: CanonicalUuidV4String,
        req 6 authorized_output_epoch: GateOutputEpoch,
        opt 7 expires_mono_ns: u64,
        req 8 issuer_principal: PrincipalId,
        req 9 holder_entity: GateId,
        req 10 issued_at_utc_ms: u64,
        req 11 expires_at_utc_ms: u64,
    }
}

impl NcpLeaseEvidenceV1 {
    /// Whether the lease stays live for `duration_ms` from Gate-local monotonic
    /// time `start_mono_ns`. A lease without a Gate-local deadline covers nothing.
    #[must_use]
    pub fn covers(&self, start_mono_ns: u64, duration_ms: u32) -> bool {
        let end = start_mono_ns.checked_add(u64::from(duration_ms) * NANOS_PER_MS);
        match (self.expires_mono_ns, end) {
            (Some(deadline), Some(end)) => start_mono_ns < deadline && end <= deadline,
            _ => false,
        }
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
    /// Deployment evidence that one authenticated Gate principal alone may
    /// publish the route.
    AclExclusiveV1(AclExclusiveEvidenceV1),
    /// A live NCP 1.0 authority lease held by Gate.
    NcpLeaseV1(NcpLeaseEvidenceV1),
}

impl PlantPublicationAuthorityStateV1 {
    /// The compatibility profile string this state represents.
    #[must_use]
    pub const fn compatibility(&self) -> &'static str {
        match self {
            Self::Unavailable { .. } => "UNAVAILABLE",
            Self::AclExclusiveV1(_) => "PRE_AUTHORITY_ACL_ONLY",
            Self::NcpLeaseV1(_) => "NCP_1_0_COMMANDER_LEASE",
        }
    }

    /// Whether this state proves that Gate alone may publish on its final route.
    ///
    /// Only exclusive-route ACL evidence does. Lease evidence alone never does:
    /// under NCP 1.0 Gate needs a live authority lease in addition to this
    /// evidence, never instead of it.
    #[must_use]
    pub const fn proves_exclusive_route(&self) -> bool {
        matches!(self, Self::AclExclusiveV1(_))
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
    ///
    /// `process_state`, `state_readiness`, and `plant_publication_state` are
    /// independent axes. In particular, `Active` means that a mission lease is
    /// active; it does not conceal a later loss of fresh state or publication
    /// authority. Such degraded combinations are valid status reports, while the
    /// command path still requires every axis to authorize each output.
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

impl GateStatusV1 {
    const fn semantic_error(code: &'static str) -> DecodeError {
        DecodeError::SemanticInvalid { code }
    }

    fn validate_publication_context(&self) -> Result<(), DecodeError> {
        match &self.plant_publication_state {
            PlantPublicationAuthorityStateV1::Unavailable { .. } => Ok(()),
            PlantPublicationAuthorityStateV1::AclExclusiveV1(evidence) => {
                if evidence.verified_at_mono_ns > self.emitted_mono_ns {
                    return Err(Self::semantic_error(
                        "STATUS_PUBLICATION_OBSERVED_IN_FUTURE",
                    ));
                }
                Ok(())
            }
            PlantPublicationAuthorityStateV1::NcpLeaseV1(evidence) => {
                if self.ncp_session.as_ref() != Some(&evidence.session)
                    || self.output_epoch != Some(evidence.authorized_output_epoch)
                {
                    return Err(Self::semantic_error(
                        "STATUS_NCP_PUBLICATION_CONTEXT_MISMATCH",
                    ));
                }
                if evidence
                    .expires_mono_ns
                    .is_some_and(|expires| expires <= self.emitted_mono_ns)
                {
                    return Err(Self::semantic_error("STATUS_NCP_PUBLICATION_EXPIRED"));
                }
                Ok(())
            }
        }
    }
}

impl crate::cbor::Validate for GateStatusV1 {
    fn validate(&self) -> Result<(), DecodeError> {
        if self.output_epoch.is_some() && self.ncp_session.is_none() {
            return Err(Self::semantic_error("STATUS_OUTPUT_WITHOUT_SESSION"));
        }
        if self.mission_lease_id.is_some() != self.admission_id.is_some() {
            return Err(Self::semantic_error(
                "STATUS_LEASE_ADMISSION_PAIR_INCOMPLETE",
            ));
        }
        if self.mission_lease_id.is_some()
            && (self.ncp_session.is_none() || self.output_epoch.is_none())
        {
            return Err(Self::semantic_error("STATUS_LEASE_WITHOUT_OUTPUT_CONTEXT"));
        }
        if !matches!(
            &self.plant_publication_state,
            PlantPublicationAuthorityStateV1::Unavailable { .. }
        ) && (self.ncp_session.is_none() || self.output_epoch.is_none())
        {
            return Err(Self::semantic_error(
                "STATUS_PUBLICATION_WITHOUT_OUTPUT_CONTEXT",
            ));
        }

        match self.process_state {
            GateProcessStateV1::Booting | GateProcessStateV1::ReadyNoSession => {
                if self.ncp_session.is_some()
                    || self.output_epoch.is_some()
                    || self.mission_lease_id.is_some()
                    || self.admission_id.is_some()
                    || self.state_readiness != StateReadinessV1::NotReady
                {
                    return Err(Self::semantic_error("STATUS_PRE_SESSION_CONTEXT_PRESENT"));
                }
            }
            GateProcessStateV1::Recovering => {}
            GateProcessStateV1::SessionBound => {
                if self.ncp_session.is_none()
                    || self.mission_lease_id.is_some()
                    || self.admission_id.is_some()
                {
                    return Err(Self::semantic_error("STATUS_SESSION_BOUND_CONTEXT_INVALID"));
                }
            }
            GateProcessStateV1::Active => {
                if self.ncp_session.is_none()
                    || self.output_epoch.is_none()
                    || self.mission_lease_id.is_none()
                    || self.admission_id.is_none()
                {
                    return Err(Self::semantic_error("STATUS_ACTIVE_CONTEXT_INCOMPLETE"));
                }
            }
            GateProcessStateV1::Quiescing | GateProcessStateV1::FaultLatched => {}
        }

        self.validate_publication_context()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor::{Limits, from_canonical_bytes, to_canonical_bytes};
    use crate::digest::DigestDomain;
    use crate::scalar::{AsciiId, CanonicalUuidV4String};
    use core::num::NonZeroU64;

    fn digest(label: &[u8]) -> DigestV1 {
        DigestV1::compute(DigestDomain::Payload, label)
    }

    fn session() -> NcpSessionIdentityV1 {
        NcpSessionIdentityV1 {
            session_id: AsciiId::new("session-1").unwrap(),
            generation: CanonicalUuidV4String::from_random_bytes([1; 16]),
        }
    }

    fn active_status() -> GateStatusV1 {
        GateStatusV1 {
            gate_id: GateId::new("gate-1").unwrap(),
            gate_boot_id: GateBootId::new([2; 16]),
            vehicle_id: VehicleId::new("vehicle-1").unwrap(),
            status_seq: NonZeroU64::new(1).unwrap(),
            process_state: GateProcessStateV1::Active,
            ncp_session: Some(session()),
            output_epoch: Some(GateOutputEpoch::new(
                CanonicalUuidV4String::from_random_bytes([3; 16]),
            )),
            mission_lease_id: Some(MissionLeaseId::new([4; 16])),
            admission_id: Some(AdmissionId::new([5; 16])),
            policy_snapshot_digest: digest(b"policy"),
            state_readiness: StateReadinessV1::Ready,
            plant_publication_state: PlantPublicationAuthorityStateV1::AclExclusiveV1(
                AclExclusiveEvidenceV1 {
                    gate_transport_principal: PrincipalId::new("gate.transport").unwrap(),
                    final_route_digest: digest(b"route"),
                    certificate_fingerprint: digest(b"certificate"),
                    acl_policy_digest: digest(b"acl"),
                    verified_at_mono_ns: 99,
                },
            ),
            evidence_health: EvidenceHealthV1::Nominal,
            last_decision_id: Some(DecisionId::new([6; 16])),
            emitted_mono_ns: 100,
        }
    }

    fn decode(status: &GateStatusV1) -> Result<GateStatusV1, DecodeError> {
        from_canonical_bytes(&to_canonical_bytes(status), Limits::DEFAULT)
    }

    #[test]
    fn active_status_requires_complete_authorization_context() {
        let mut status = active_status();
        status.mission_lease_id = None;
        status.admission_id = None;

        assert_eq!(
            decode(&status),
            Err(DecodeError::SemanticInvalid {
                code: "STATUS_ACTIVE_CONTEXT_INCOMPLETE"
            })
        );
    }

    #[test]
    fn active_status_reports_state_not_ready_without_hiding_the_active_lease() {
        let mut status = active_status();
        status.state_readiness = StateReadinessV1::NotReady;

        assert_eq!(decode(&status), Ok(status));
    }

    #[test]
    fn active_status_reports_unavailable_publication_without_hiding_the_active_lease() {
        let mut status = active_status();
        status.plant_publication_state = PlantPublicationAuthorityStateV1::Unavailable {
            reason: PlantPublicationUnavailableReasonV1::Faulted,
        };

        assert_eq!(decode(&status), Ok(status));
    }

    #[test]
    fn pre_session_status_rejects_retained_session_context() {
        let mut status = active_status();
        status.process_state = GateProcessStateV1::ReadyNoSession;
        status.mission_lease_id = None;
        status.admission_id = None;
        status.state_readiness = StateReadinessV1::NotReady;

        assert_eq!(
            decode(&status),
            Err(DecodeError::SemanticInvalid {
                code: "STATUS_PRE_SESSION_CONTEXT_PRESENT"
            })
        );
    }

    #[test]
    fn session_bound_status_rejects_active_lease_context() {
        let mut status = active_status();
        status.process_state = GateProcessStateV1::SessionBound;

        assert_eq!(
            decode(&status),
            Err(DecodeError::SemanticInvalid {
                code: "STATUS_SESSION_BOUND_CONTEXT_INVALID"
            })
        );
    }

    #[test]
    fn recovering_status_can_report_partially_recovered_session_context() {
        let mut status = active_status();
        status.process_state = GateProcessStateV1::Recovering;
        status.output_epoch = None;
        status.mission_lease_id = None;
        status.admission_id = None;
        status.state_readiness = StateReadinessV1::NotReady;
        status.plant_publication_state = PlantPublicationAuthorityStateV1::Unavailable {
            reason: PlantPublicationUnavailableReasonV1::SessionUnknown,
        };

        assert_eq!(decode(&status), Ok(status));
    }

    #[test]
    fn session_bound_status_does_not_require_an_output_epoch_yet() {
        let mut status = active_status();
        status.process_state = GateProcessStateV1::SessionBound;
        status.output_epoch = None;
        status.mission_lease_id = None;
        status.admission_id = None;
        status.state_readiness = StateReadinessV1::NotReady;
        status.plant_publication_state = PlantPublicationAuthorityStateV1::Unavailable {
            reason: PlantPublicationUnavailableReasonV1::PriorStreamLive,
        };

        assert_eq!(decode(&status), Ok(status));
    }

    #[test]
    fn status_rejects_future_acl_observation() {
        let mut status = active_status();
        let PlantPublicationAuthorityStateV1::AclExclusiveV1(evidence) =
            &mut status.plant_publication_state
        else {
            unreachable!("fixture uses ACL publication authority")
        };
        evidence.verified_at_mono_ns = 101;

        assert_eq!(
            decode(&status),
            Err(DecodeError::SemanticInvalid {
                code: "STATUS_PUBLICATION_OBSERVED_IN_FUTURE"
            })
        );
    }

    #[test]
    fn status_rejects_ncp_authority_for_a_different_session() {
        let mut status = active_status();
        let output_epoch = status.output_epoch.unwrap();
        status.plant_publication_state =
            PlantPublicationAuthorityStateV1::NcpLeaseV1(NcpLeaseEvidenceV1 {
                gate_transport_principal: PrincipalId::new("gate.transport").unwrap(),
                final_route_digest: digest(b"route"),
                session: NcpSessionIdentityV1 {
                    session_id: AsciiId::new("different-session").unwrap(),
                    generation: CanonicalUuidV4String::from_random_bytes([7; 16]),
                },
                authority_term: NonZeroU64::new(1).unwrap(),
                lease_id: CanonicalUuidV4String::from_random_bytes([8; 16]),
                authorized_output_epoch: output_epoch,
                expires_mono_ns: Some(101),
                issuer_principal: PrincipalId::new("gate.transport").unwrap(),
                holder_entity: GateId::new("gate-a").unwrap(),
                issued_at_utc_ms: 1_700_000_000_000,
                expires_at_utc_ms: 1_700_000_030_000,
            });

        assert_eq!(
            decode(&status),
            Err(DecodeError::SemanticInvalid {
                code: "STATUS_NCP_PUBLICATION_CONTEXT_MISMATCH"
            })
        );
    }

    #[test]
    fn valid_active_status_roundtrips() {
        assert_eq!(decode(&active_status()), Ok(active_status()));
    }

    fn live_lease(status: &GateStatusV1) -> NcpLeaseEvidenceV1 {
        NcpLeaseEvidenceV1 {
            gate_transport_principal: PrincipalId::new("gate.transport").unwrap(),
            final_route_digest: digest(b"route"),
            session: status.ncp_session.clone().unwrap(),
            authority_term: NonZeroU64::new(1).unwrap(),
            lease_id: CanonicalUuidV4String::from_random_bytes([8; 16]),
            authorized_output_epoch: status.output_epoch.unwrap(),
            expires_mono_ns: Some(101),
            issuer_principal: PrincipalId::new("gate.transport").unwrap(),
            holder_entity: GateId::new("gate-a").unwrap(),
            issued_at_utc_ms: 1_700_000_000_000,
            expires_at_utc_ms: 1_700_000_030_000,
        }
    }

    #[test]
    fn ncp_lease_alone_never_proves_an_exclusive_route() {
        let status = active_status();
        let lease = PlantPublicationAuthorityStateV1::NcpLeaseV1(live_lease(&status));
        assert!(!lease.proves_exclusive_route());
    }

    #[test]
    fn ncp_lease_covers_only_windows_that_end_by_its_deadline() {
        let lease = live_lease(&active_status()); // deadline 101 ns
        assert!(lease.covers(0, 0));
        assert!(lease.covers(100, 0));
        assert!(!lease.covers(101, 0), "the deadline instant is not live");
        let ms_lease = NcpLeaseEvidenceV1 {
            expires_mono_ns: Some(3 * NANOS_PER_MS),
            ..lease.clone()
        };
        assert!(ms_lease.covers(NANOS_PER_MS, 2));
        assert!(!ms_lease.covers(NANOS_PER_MS + 1, 2));
        let far = NcpLeaseEvidenceV1 {
            expires_mono_ns: Some(u64::MAX),
            ..lease.clone()
        };
        assert!(
            !far.covers(u64::MAX - 1, 1),
            "an unrepresentable end covers nothing"
        );
        let no_deadline = NcpLeaseEvidenceV1 {
            expires_mono_ns: None,
            ..lease
        };
        assert!(!no_deadline.covers(0, 0));
    }
}
