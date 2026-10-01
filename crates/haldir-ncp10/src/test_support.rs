//! Fixtures shared by this crate's unit tests.

use core::num::NonZeroU64;

use haldir_contracts::digest::{DigestDomain, DigestV1};
use haldir_contracts::ids::{GateId, GateOutputEpoch, PrincipalId};
use haldir_contracts::scalar::CanonicalUuidV4String;
use haldir_contracts::session::NcpSessionIdentityV1;
use haldir_contracts::status::NcpLeaseEvidenceV1;

/// A live Gate lease on `session` for output epoch `epoch`.
pub(crate) fn lease_for(
    session: &NcpSessionIdentityV1,
    epoch: GateOutputEpoch,
) -> NcpLeaseEvidenceV1 {
    NcpLeaseEvidenceV1 {
        gate_transport_principal: PrincipalId::new("gate.transport").unwrap(),
        final_route_digest: DigestV1::compute(DigestDomain::TransportKey, b"ncp/v1/sess-1/command"),
        session: session.clone(),
        authority_term: NonZeroU64::new(1).unwrap(),
        lease_id: CanonicalUuidV4String::from_random_bytes([6; 16]),
        authorized_output_epoch: epoch,
        expires_mono_ns: Some(1_000_000_000),
        issuer_principal: PrincipalId::new("gate.transport").unwrap(),
        holder_entity: GateId::new("gate-a").unwrap(),
        issued_at_utc_ms: 1_700_000_000_000,
        expires_at_utc_ms: 1_700_000_030_000,
    }
}
