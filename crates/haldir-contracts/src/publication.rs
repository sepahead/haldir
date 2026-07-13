//! Gate-signed publication-stage evidence after an `OutputPrepared` decision.
//!
//! A decision receipt is immutable and stops at `OutputPrepared`. Later Gate
//! observations are separate signed envelopes linked to the exact predecessor
//! envelope digest. `UnknownAfterPublish` may be emitted by a distinct recovery
//! boot, so the decision boot and event-producing boot are carried separately.
//! Boot IDs are random and have no intrinsic order; verified startup/journal
//! context must authenticate that the claimed producer is the current later boot.
//! `PublishCalled` is a durable write-ahead ambiguity boundary after which bytes
//! may be exposed; it is not proof that transport began or delivered anything.

use crate::digest::DigestV1;
use crate::error::DecodeError;
use crate::ids::{DecisionId, GateBootId, GateId, VehicleId};
use crate::receipt::PublishStageV1;
use crate::session::{NcpSessionIdentityV1, NcpStreamPositionV1};
use core::num::NonZeroU32;

canonical_struct! {
    /// One append-only Gate publication-stage observation.
    ///
    /// The first `PublishCalled` event links to the exact signed decision receipt.
    /// A returned/unknown terminal event links to the exact signed
    /// `PublishCalled` envelope. Consumers must verify the COSE signature and
    /// reduce these links per `decision_id`; field repetition alone is not trust.
    pub struct PublicationStageEventV1 kind "haldir.publication_stage" {
        req 2 schema_major: u16,
        req 3 schema_minor: u16,
        req 4 decision_id: DecisionId,
        req 5 gate_id: GateId,
        req 6 decision_gate_boot_id: GateBootId,
        req 7 producer_gate_boot_id: GateBootId,
        req 8 vehicle_id: VehicleId,
        req 9 ncp_session: NcpSessionIdentityV1,
        req 10 gate_output_stream: NcpStreamPositionV1,
        req 11 output_frame_digest: DigestV1,
        req 12 effective_validity_ms: NonZeroU32,
        req 13 prepared_receipt_envelope_digest: DigestV1,
        req 14 predecessor_envelope_digest: DigestV1,
        req 15 stage: PublishStageV1,
        req 16 observed_mono_ns: u64,
    }
}

impl crate::cbor::Validate for PublicationStageEventV1 {
    fn validate(&self) -> Result<(), DecodeError> {
        if self.schema_major != 1 || self.schema_minor != 0 {
            return Err(DecodeError::UnsupportedVersion);
        }
        match self.stage {
            PublishStageV1::PublishCalled
            | PublishStageV1::PublishReturnedOk
            | PublishStageV1::PublishReturnedError => {
                if self.producer_gate_boot_id != self.decision_gate_boot_id {
                    return Err(DecodeError::SemanticInvalid {
                        code: "PUBLICATION_STAGE_CROSS_BOOT",
                    });
                }
            }
            PublishStageV1::UnknownAfterPublish => {
                if self.producer_gate_boot_id == self.decision_gate_boot_id {
                    return Err(DecodeError::SemanticInvalid {
                        code: "UNKNOWN_REQUIRES_RECOVERY_BOOT",
                    });
                }
            }
            _ => {
                return Err(DecodeError::SemanticInvalid {
                    code: "INVALID_GATE_PUBLICATION_STAGE",
                });
            }
        }
        if self.stage == PublishStageV1::PublishCalled
            && self.predecessor_envelope_digest != self.prepared_receipt_envelope_digest
        {
            return Err(DecodeError::SemanticInvalid {
                code: "CALLED_MUST_LINK_PREPARED_RECEIPT",
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::PublicationStageEventV1;
    use crate::cbor::{Limits, from_canonical_bytes, to_canonical_bytes};
    use crate::digest::{DigestDomain, DigestV1};
    use crate::error::DecodeError;
    use crate::ids::{DecisionId, GateBootId, GateId, GateOutputEpoch, OutputSeq, VehicleId};
    use crate::receipt::PublishStageV1;
    use crate::scalar::{AsciiId, CanonicalUuidV4String};
    use crate::session::{NcpSessionIdentityV1, NcpStreamPositionV1};
    use core::num::{NonZeroU32, NonZeroU64};

    fn event(stage: PublishStageV1) -> PublicationStageEventV1 {
        PublicationStageEventV1 {
            schema_major: 1,
            schema_minor: 0,
            decision_id: DecisionId::new([1; 16]),
            gate_id: GateId::new("gate-1").unwrap(),
            decision_gate_boot_id: GateBootId::new([2; 16]),
            producer_gate_boot_id: GateBootId::new([2; 16]),
            vehicle_id: VehicleId::new("uav-1").unwrap(),
            ncp_session: NcpSessionIdentityV1 {
                session_id: AsciiId::new("sess-1").unwrap(),
                generation: CanonicalUuidV4String::from_random_bytes([3; 16]),
            },
            gate_output_stream: NcpStreamPositionV1 {
                epoch: GateOutputEpoch::new(CanonicalUuidV4String::from_random_bytes([4; 16])),
                seq: OutputSeq::new(NonZeroU64::new(1).unwrap()),
            },
            output_frame_digest: DigestV1::compute(DigestDomain::OutputFrame, b"frame"),
            effective_validity_ms: NonZeroU32::new(10).unwrap(),
            prepared_receipt_envelope_digest: DigestV1::compute(
                DigestDomain::RawEnvelope,
                b"predecessor",
            ),
            predecessor_envelope_digest: DigestV1::compute(
                DigestDomain::RawEnvelope,
                b"predecessor",
            ),
            stage,
            observed_mono_ns: 42,
        }
    }

    #[test]
    fn called_event_round_trips_canonically() {
        let original = event(PublishStageV1::PublishCalled);
        let bytes = to_canonical_bytes(&original);
        let decoded = from_canonical_bytes::<PublicationStageEventV1>(&bytes, Limits::DEFAULT)
            .expect("valid publication stage");
        assert_eq!(decoded, original);
        assert_eq!(to_canonical_bytes(&decoded), bytes);
    }

    #[test]
    fn called_event_golden_hex_is_stable() {
        let bytes = to_canonical_bytes(&event(PublishStageV1::PublishCalled));
        let hex = bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert_eq!(
            hex,
            "b001781868616c6469722e7075626c69636174696f6e5f7374616765020103000450010101010101010101010101010101010566676174652d3106500202020202020202020202020202020207500202020202020202020202020202020208657561762d3109a20166736573732d3102782430333033303330332d303330332d343330332d383330332d3033303330333033303330330aa201782430343034303430342d303430342d343430342d383430342d30343034303430343034303402010ba201010258206b998891e198869296970540d5dcd904ffa388555eb4d4993dd19023c46fe1bc0c0a0da20101025820d8f5f7ad333546ccc4ee4515c6c1ba04f02747e654f7540a7c25bd31f164da880ea20101025820d8f5f7ad333546ccc4ee4515c6c1ba04f02747e654f7540a7c25bd31f164da880f0410182a"
        );
    }

    #[test]
    fn decision_receipt_and_downstream_producer_stages_are_rejected() {
        for stage in [
            PublishStageV1::DecidedDeny,
            PublishStageV1::DecidedAllow,
            PublishStageV1::DecidedError,
            PublishStageV1::OutputReserved,
            PublishStageV1::OutputPrepared,
            PublishStageV1::CrebainReceived,
            PublishStageV1::CrebainAccepted,
            PublishStageV1::CrebainRejected,
            PublishStageV1::AdapterApplied,
            PublishStageV1::AdapterFailed,
            PublishStageV1::PlantObserved,
            PublishStageV1::Expired,
        ] {
            let bytes = to_canonical_bytes(&event(stage));
            assert!(matches!(
                from_canonical_bytes::<PublicationStageEventV1>(&bytes, Limits::DEFAULT),
                Err(DecodeError::SemanticInvalid {
                    code: "INVALID_GATE_PUBLICATION_STAGE"
                })
            ));
        }
    }

    #[test]
    fn ordinary_events_cannot_claim_another_producer_boot() {
        let mut called = event(PublishStageV1::PublishCalled);
        called.producer_gate_boot_id = GateBootId::new([9; 16]);
        let bytes = to_canonical_bytes(&called);
        assert!(matches!(
            from_canonical_bytes::<PublicationStageEventV1>(&bytes, Limits::DEFAULT),
            Err(DecodeError::SemanticInvalid {
                code: "PUBLICATION_STAGE_CROSS_BOOT"
            })
        ));
    }

    #[test]
    fn called_event_must_link_the_exact_prepared_receipt() {
        let mut called = event(PublishStageV1::PublishCalled);
        called.predecessor_envelope_digest =
            DigestV1::compute(DigestDomain::RawEnvelope, b"different");
        let bytes = to_canonical_bytes(&called);
        assert!(matches!(
            from_canonical_bytes::<PublicationStageEventV1>(&bytes, Limits::DEFAULT),
            Err(DecodeError::SemanticInvalid {
                code: "CALLED_MUST_LINK_PREPARED_RECEIPT"
            })
        ));
    }

    #[test]
    fn unknown_tail_requires_a_distinct_recovery_boot() {
        let same_boot = event(PublishStageV1::UnknownAfterPublish);
        let bytes = to_canonical_bytes(&same_boot);
        assert!(matches!(
            from_canonical_bytes::<PublicationStageEventV1>(&bytes, Limits::DEFAULT),
            Err(DecodeError::SemanticInvalid {
                code: "UNKNOWN_REQUIRES_RECOVERY_BOOT"
            })
        ));

        let mut recovered = same_boot;
        recovered.producer_gate_boot_id = GateBootId::new([8; 16]);
        let bytes = to_canonical_bytes(&recovered);
        let decoded = from_canonical_bytes::<PublicationStageEventV1>(&bytes, Limits::DEFAULT)
            .expect("recovery boot may mark unknown");
        assert_eq!(decoded, recovered);
    }
}
