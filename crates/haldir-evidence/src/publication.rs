//! Pure reduction of already-verified Gate publication evidence.
//!
//! This module does not verify COSE signatures or prove that `envelope_bytes`
//! encode the supplied value. A journal verifier must establish exact envelope/value
//! correspondence and bind a `GateApplication` signer subject to the value's
//! `gate_id`, then replay records in retained journal order through this
//! retained-state-bounded reducer. The verifier must also enforce the envelope
//! byte-size/work limit before the reducer hashes those bytes.

use core::num::NonZeroU32;
use haldir_contracts::Validate;
use haldir_contracts::digest::{DigestDomain, DigestV1};
use haldir_contracts::error::DecodeError;
use haldir_contracts::ids::{DecisionId, GateBootId, GateId, VehicleId};
use haldir_contracts::publication::PublicationStageEventV1;
use haldir_contracts::receipt::{
    DecisionOutcomeV1, DecisionReasonCodeV1, DecisionReceiptV1, PublishStageV1,
};
use haldir_contracts::session::{NcpSessionIdentityV1, NcpStreamPositionV1};
use std::collections::BTreeMap;

/// Reduced state of one Gate publication trace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicationTraceState {
    /// The signed decision prepared bytes but did not expose them.
    Prepared,
    /// The Gate durably entered the write-ahead boundary after which bytes may be
    /// exposed; transport invocation and delivery remain unknown.
    PublishCalled,
    /// The cooperative publisher reported a local successful return.
    PublishReturnedOk,
    /// The cooperative publisher reported an error/timeout.
    PublishReturnedError,
    /// A distinct claimed recovery boot marked a dangling called tail unknown.
    UnknownAfterPublish,
}

/// A deterministic publication-evidence reduction failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicationReductionError {
    /// The receipt lacked the publication-relevant `AllowPrepared` tuple.
    InvalidPreparedReceipt,
    /// The bounded per-decision table has no free slot.
    CapacityExceeded,
    /// This decision already has a registered prepared receipt.
    DuplicateDecision,
    /// A stage event had no registered prepared decision.
    MissingPreparedDecision,
    /// A repeated decision/session/output/frame binding changed.
    IdentityMismatch,
    /// A prepared receipt belonged to a different Gate than the first retained
    /// receipt in this reducer.
    GateScopeMismatch,
    /// Contract-level validation rejected the stage event.
    InvalidEvent(DecodeError),
    /// The requested stage is not a legal successor of the reduced state.
    InvalidTransition,
    /// The event did not link to the exact expected predecessor envelope.
    PredecessorMismatch,
    /// Ordered replay observed producer-local monotonic time regress within one
    /// Gate boot, including across different decision traces.
    TimeRegression,
    /// The claimed recovery boot already appeared in the reduced publication
    /// evidence and therefore is not fresh within this replay.
    RecoveryBootAlreadyObserved,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PublicationBinding {
    gate_id: GateId,
    vehicle_id: VehicleId,
    ncp_session: NcpSessionIdentityV1,
    gate_output_stream: NcpStreamPositionV1,
    output_frame_digest: DigestV1,
    effective_validity_ms: NonZeroU32,
    prepared_receipt_envelope_digest: DigestV1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PublicationTrace {
    binding: PublicationBinding,
    state: PublicationTraceState,
    last_envelope_digest: DigestV1,
}

/// Bounded, deterministic reducer for Gate publication-stage envelopes.
///
/// `max_traces` limits all retained decisions over the replay lifetime, not only
/// currently nonterminal decisions. Terminal traces are deliberately not evicted,
/// so callers must size the bound for every retained prepared receipt.
pub struct PublicationStageReducer {
    gate_id: Option<GateId>,
    traces: BTreeMap<(GateBootId, DecisionId), PublicationTrace>,
    boot_high_water: BTreeMap<GateBootId, u64>,
    max_traces: usize,
}

impl PublicationStageReducer {
    /// Create an empty reducer with an explicit nonzero decision bound.
    ///
    /// # Errors
    /// Returns [`PublicationReductionError::CapacityExceeded`] for a zero bound.
    pub fn new(max_traces: usize) -> Result<Self, PublicationReductionError> {
        if max_traces == 0 {
            return Err(PublicationReductionError::CapacityExceeded);
        }
        Ok(Self {
            gate_id: None,
            traces: BTreeMap::new(),
            boot_high_water: BTreeMap::new(),
            max_traces,
        })
    }

    /// Register one already-signature-verified prepared decision receipt.
    ///
    /// `envelope_bytes` must be the exact COSE envelope from which `receipt` was
    /// independently verified. The reducer hashes it but cannot establish that
    /// correspondence itself.
    ///
    /// # Errors
    /// Returns on a non-prepared/non-ALLOW receipt, a contradictory reason set,
    /// incomplete output binding, invalid receipt time ordering, boot-local time
    /// regression in ordered replay, duplicate decision key, or exhausted bounded
    /// capacity.
    pub fn register_prepared(
        &mut self,
        receipt: &DecisionReceiptV1,
        envelope_bytes: &[u8],
    ) -> Result<(), PublicationReductionError> {
        if receipt.decision != DecisionOutcomeV1::Allow
            || receipt.publish_stage != PublishStageV1::OutputPrepared
            || receipt.reason_codes.as_slice() != [DecisionReasonCodeV1::AllowPrepared]
            || receipt.transformation_relation.is_none()
            || receipt.received_mono_ns > receipt.decided_mono_ns
        {
            return Err(PublicationReductionError::InvalidPreparedReceipt);
        }
        let gate_output_stream = receipt
            .gate_output_stream
            .clone()
            .ok_or(PublicationReductionError::InvalidPreparedReceipt)?;
        let output_frame_digest = receipt
            .output_frame_digest
            .ok_or(PublicationReductionError::InvalidPreparedReceipt)?;
        let effective_validity_ms = receipt
            .effective_validity_ms
            .and_then(NonZeroU32::new)
            .ok_or(PublicationReductionError::InvalidPreparedReceipt)?;
        if self
            .gate_id
            .as_ref()
            .is_some_and(|gate_id| gate_id != &receipt.gate_id)
        {
            return Err(PublicationReductionError::GateScopeMismatch);
        }
        let key = (receipt.gate_boot_id, receipt.decision_id);
        if self.traces.contains_key(&key) {
            return Err(PublicationReductionError::DuplicateDecision);
        }
        if self.traces.len() >= self.max_traces {
            return Err(PublicationReductionError::CapacityExceeded);
        }
        if self
            .boot_high_water
            .get(&receipt.gate_boot_id)
            .is_some_and(|high_water| receipt.decided_mono_ns < *high_water)
        {
            return Err(PublicationReductionError::TimeRegression);
        }
        let prepared_receipt_envelope_digest =
            DigestV1::compute(DigestDomain::RawEnvelope, envelope_bytes);
        if self.gate_id.is_none() {
            self.gate_id = Some(receipt.gate_id.clone());
        }
        self.traces.insert(
            key,
            PublicationTrace {
                binding: PublicationBinding {
                    gate_id: receipt.gate_id.clone(),
                    vehicle_id: receipt.vehicle_id.clone(),
                    ncp_session: receipt.ncp_session.clone(),
                    gate_output_stream,
                    output_frame_digest,
                    effective_validity_ms,
                    prepared_receipt_envelope_digest,
                },
                state: PublicationTraceState::Prepared,
                last_envelope_digest: prepared_receipt_envelope_digest,
            },
        );
        self.boot_high_water
            .insert(receipt.gate_boot_id, receipt.decided_mono_ns);
        Ok(())
    }

    /// Apply one already-signature-verified publication-stage event.
    ///
    /// `envelope_bytes` must be the exact COSE envelope verified as `event`.
    /// Generic replay does not authenticate recovery-boot freshness: one recovery
    /// boot may legitimately close multiple tails. That provenance must come from
    /// verified ordered startup/journal context; the planning helper below only
    /// rejects IDs already seen when the batch is constructed.
    ///
    /// # Errors
    /// Returns on contract invalidity, missing/mutated identity, a broken exact
    /// predecessor link, time regression, or any duplicate/skipped/terminal
    /// transition.
    pub fn apply_event(
        &mut self,
        event: &PublicationStageEventV1,
        envelope_bytes: &[u8],
    ) -> Result<(), PublicationReductionError> {
        event
            .validate()
            .map_err(PublicationReductionError::InvalidEvent)?;
        let key = (event.decision_gate_boot_id, event.decision_id);
        let trace = self
            .traces
            .get_mut(&key)
            .ok_or(PublicationReductionError::MissingPreparedDecision)?;
        if event.gate_id != trace.binding.gate_id
            || event.vehicle_id != trace.binding.vehicle_id
            || event.ncp_session != trace.binding.ncp_session
            || event.gate_output_stream != trace.binding.gate_output_stream
            || event.output_frame_digest != trace.binding.output_frame_digest
            || event.effective_validity_ms != trace.binding.effective_validity_ms
            || event.prepared_receipt_envelope_digest
                != trace.binding.prepared_receipt_envelope_digest
        {
            return Err(PublicationReductionError::IdentityMismatch);
        }
        if event.predecessor_envelope_digest != trace.last_envelope_digest {
            return Err(PublicationReductionError::PredecessorMismatch);
        }
        if self
            .boot_high_water
            .get(&event.producer_gate_boot_id)
            .is_some_and(|high_water| event.observed_mono_ns < *high_water)
        {
            return Err(PublicationReductionError::TimeRegression);
        }

        let next = match (trace.state, event.stage) {
            (PublicationTraceState::Prepared, PublishStageV1::PublishCalled) => {
                PublicationTraceState::PublishCalled
            }
            (PublicationTraceState::PublishCalled, PublishStageV1::PublishReturnedOk) => {
                PublicationTraceState::PublishReturnedOk
            }
            (PublicationTraceState::PublishCalled, PublishStageV1::PublishReturnedError) => {
                PublicationTraceState::PublishReturnedError
            }
            (PublicationTraceState::PublishCalled, PublishStageV1::UnknownAfterPublish) => {
                PublicationTraceState::UnknownAfterPublish
            }
            _ => return Err(PublicationReductionError::InvalidTransition),
        };
        trace.state = next;
        trace.last_envelope_digest = DigestV1::compute(DigestDomain::RawEnvelope, envelope_bytes);
        self.boot_high_water
            .insert(event.producer_gate_boot_id, event.observed_mono_ns);
        Ok(())
    }

    /// Current reduced state for a decision key.
    #[must_use]
    pub fn state(
        &self,
        decision_gate_boot_id: GateBootId,
        decision_id: DecisionId,
    ) -> Option<PublicationTraceState> {
        self.traces
            .get(&(decision_gate_boot_id, decision_id))
            .map(|trace| trace.state)
    }

    /// Build conservative recovery events for every distinct-boot dangling call.
    ///
    /// This does not mutate the reducer. Each returned payload must be signed,
    /// durably appended, and then fed back through [`Self::apply_event`]. Prepared
    /// tails are intentionally absent because their bytes were never exposed.
    ///
    /// The caller must independently establish that `recovery_boot_id` is the
    /// authenticated current boot in ordered startup evidence. This primitive can
    /// prove only that the ID has not appeared in the publication evidence reduced
    /// so far; random boot IDs have no intrinsic ordering.
    ///
    /// # Errors
    /// Returns if the claimed recovery boot already occurred anywhere in the
    /// reduced publication evidence.
    pub fn unknown_after_publish_events(
        &self,
        recovery_boot_id: GateBootId,
        observed_mono_ns: u64,
    ) -> Result<Vec<PublicationStageEventV1>, PublicationReductionError> {
        if self.boot_high_water.contains_key(&recovery_boot_id) {
            return Err(PublicationReductionError::RecoveryBootAlreadyObserved);
        }
        let mut events = Vec::new();
        for ((decision_boot_id, decision_id), trace) in &self.traces {
            if trace.state != PublicationTraceState::PublishCalled {
                continue;
            }
            events.push(PublicationStageEventV1 {
                schema_major: 1,
                schema_minor: 0,
                decision_id: *decision_id,
                gate_id: trace.binding.gate_id.clone(),
                decision_gate_boot_id: *decision_boot_id,
                producer_gate_boot_id: recovery_boot_id,
                vehicle_id: trace.binding.vehicle_id.clone(),
                ncp_session: trace.binding.ncp_session.clone(),
                gate_output_stream: trace.binding.gate_output_stream.clone(),
                output_frame_digest: trace.binding.output_frame_digest,
                effective_validity_ms: trace.binding.effective_validity_ms,
                prepared_receipt_envelope_digest: trace.binding.prepared_receipt_envelope_digest,
                predecessor_envelope_digest: trace.last_envelope_digest,
                stage: PublishStageV1::UnknownAfterPublish,
                observed_mono_ns,
            });
        }
        Ok(events)
    }
}

#[cfg(test)]
mod tests {
    use super::{PublicationReductionError, PublicationStageReducer, PublicationTraceState};
    use core::num::{NonZeroU32, NonZeroU64};
    use haldir_contracts::digest::{DigestDomain, DigestV1};
    use haldir_contracts::ids::{
        DecisionId, GateBootId, GateId, GateOutputEpoch, OutputSeq, VehicleId,
    };
    use haldir_contracts::publication::PublicationStageEventV1;
    use haldir_contracts::receipt::{
        DecisionOutcomeV1, DecisionReasonCodeV1, DecisionReceiptV1, PublishStageV1,
        TransformationRelationV1,
    };
    use haldir_contracts::scalar::{AsciiId, BoundedVec, CanonicalUuidV4String};
    use haldir_contracts::session::{NcpSessionIdentityV1, NcpStreamPositionV1};

    const PREPARED_ENVELOPE: &[u8] = b"signed-prepared";
    const CALLED_ENVELOPE: &[u8] = b"signed-called";

    fn session() -> NcpSessionIdentityV1 {
        NcpSessionIdentityV1 {
            session_id: AsciiId::new("sess-1").unwrap(),
            generation: CanonicalUuidV4String::from_random_bytes([3; 16]),
        }
    }

    fn output() -> NcpStreamPositionV1 {
        NcpStreamPositionV1 {
            epoch: GateOutputEpoch::new(CanonicalUuidV4String::from_random_bytes([4; 16])),
            seq: OutputSeq::new(NonZeroU64::new(1).unwrap()),
        }
    }

    fn receipt() -> DecisionReceiptV1 {
        DecisionReceiptV1 {
            decision_id: DecisionId::new([1; 16]),
            gate_id: GateId::new("gate-1").unwrap(),
            gate_boot_id: GateBootId::new([2; 16]),
            vehicle_id: VehicleId::new("uav-1").unwrap(),
            mission_id: None,
            ncp_session: session(),
            received_key_digest: DigestV1::compute(DigestDomain::Payload, b"key"),
            raw_envelope_digest: DigestV1::compute(DigestDomain::RawEnvelope, b"intent"),
            payload_digest: None,
            semantic_intent_digest: None,
            controller_id: None,
            controller_intent_position: None,
            mission_lease_id: None,
            admission_digest: None,
            source: None,
            state_snapshot_digest: None,
            policy_snapshot_digest: DigestV1::compute(DigestDomain::PolicySnapshot, b"policy"),
            decision: DecisionOutcomeV1::Allow,
            reason_codes: BoundedVec::from_vec(vec![DecisionReasonCodeV1::AllowPrepared]).unwrap(),
            effective_validity_ms: Some(10),
            gate_output_stream: Some(output()),
            output_frame_digest: Some(DigestV1::compute(DigestDomain::OutputFrame, b"frame")),
            transformation_relation: Some(TransformationRelationV1::FixedPointToNcpFloatV1),
            received_mono_ns: 90,
            decided_mono_ns: 100,
            publish_stage: PublishStageV1::OutputPrepared,
        }
    }

    fn event(stage: PublishStageV1, predecessor: DigestV1) -> PublicationStageEventV1 {
        let prepared_digest = DigestV1::compute(DigestDomain::RawEnvelope, PREPARED_ENVELOPE);
        PublicationStageEventV1 {
            schema_major: 1,
            schema_minor: 0,
            decision_id: DecisionId::new([1; 16]),
            gate_id: GateId::new("gate-1").unwrap(),
            decision_gate_boot_id: GateBootId::new([2; 16]),
            producer_gate_boot_id: GateBootId::new([2; 16]),
            vehicle_id: VehicleId::new("uav-1").unwrap(),
            ncp_session: session(),
            gate_output_stream: output(),
            output_frame_digest: DigestV1::compute(DigestDomain::OutputFrame, b"frame"),
            effective_validity_ms: NonZeroU32::new(10).unwrap(),
            prepared_receipt_envelope_digest: prepared_digest,
            predecessor_envelope_digest: predecessor,
            stage,
            observed_mono_ns: 110,
        }
    }

    #[test]
    fn exact_linear_trace_reduces_and_terminal_is_final() {
        let mut reducer = PublicationStageReducer::new(4).unwrap();
        reducer
            .register_prepared(&receipt(), PREPARED_ENVELOPE)
            .unwrap();
        let prepared_digest = DigestV1::compute(DigestDomain::RawEnvelope, PREPARED_ENVELOPE);
        reducer
            .apply_event(
                &event(PublishStageV1::PublishCalled, prepared_digest),
                CALLED_ENVELOPE,
            )
            .unwrap();
        let called_digest = DigestV1::compute(DigestDomain::RawEnvelope, CALLED_ENVELOPE);
        reducer
            .apply_event(
                &event(PublishStageV1::PublishReturnedOk, called_digest),
                b"signed-ok",
            )
            .unwrap();
        assert_eq!(
            reducer.state(GateBootId::new([2; 16]), DecisionId::new([1; 16])),
            Some(PublicationTraceState::PublishReturnedOk)
        );
        assert_eq!(
            reducer.apply_event(
                &event(
                    PublishStageV1::PublishReturnedError,
                    DigestV1::compute(DigestDomain::RawEnvelope, b"signed-ok"),
                ),
                b"signed-conflict",
            ),
            Err(PublicationReductionError::InvalidTransition)
        );
    }

    #[test]
    fn every_terminal_state_rejects_an_exactly_linked_successor() {
        for terminal in [
            PublishStageV1::PublishReturnedOk,
            PublishStageV1::PublishReturnedError,
        ] {
            let mut reducer = PublicationStageReducer::new(4).unwrap();
            reducer
                .register_prepared(&receipt(), PREPARED_ENVELOPE)
                .unwrap();
            let prepared_digest = DigestV1::compute(DigestDomain::RawEnvelope, PREPARED_ENVELOPE);
            reducer
                .apply_event(
                    &event(PublishStageV1::PublishCalled, prepared_digest),
                    CALLED_ENVELOPE,
                )
                .unwrap();
            reducer
                .apply_event(
                    &event(
                        terminal,
                        DigestV1::compute(DigestDomain::RawEnvelope, CALLED_ENVELOPE),
                    ),
                    b"signed-terminal",
                )
                .unwrap();
            assert_eq!(
                reducer.apply_event(
                    &event(
                        PublishStageV1::PublishReturnedError,
                        DigestV1::compute(DigestDomain::RawEnvelope, b"signed-terminal"),
                    ),
                    b"signed-successor",
                ),
                Err(PublicationReductionError::InvalidTransition)
            );
        }

        let mut reducer = PublicationStageReducer::new(4).unwrap();
        reducer
            .register_prepared(&receipt(), PREPARED_ENVELOPE)
            .unwrap();
        let prepared_digest = DigestV1::compute(DigestDomain::RawEnvelope, PREPARED_ENVELOPE);
        reducer
            .apply_event(
                &event(PublishStageV1::PublishCalled, prepared_digest),
                CALLED_ENVELOPE,
            )
            .unwrap();
        let unknown = reducer
            .unknown_after_publish_events(GateBootId::new([9; 16]), 1)
            .unwrap()
            .pop()
            .unwrap();
        reducer
            .apply_event(&unknown, b"signed-unknown-terminal")
            .unwrap();
        assert_eq!(
            reducer.apply_event(
                &event(
                    PublishStageV1::PublishReturnedError,
                    DigestV1::compute(DigestDomain::RawEnvelope, b"signed-unknown-terminal"),
                ),
                b"signed-successor",
            ),
            Err(PublicationReductionError::InvalidTransition)
        );
    }

    #[test]
    fn gaps_field_drift_and_time_regression_fail_closed() {
        let mut reducer = PublicationStageReducer::new(4).unwrap();
        reducer
            .register_prepared(&receipt(), PREPARED_ENVELOPE)
            .unwrap();
        let prepared_digest = DigestV1::compute(DigestDomain::RawEnvelope, PREPARED_ENVELOPE);

        let direct_terminal = event(PublishStageV1::PublishReturnedOk, prepared_digest);
        assert_eq!(
            reducer.apply_event(&direct_terminal, b"terminal"),
            Err(PublicationReductionError::InvalidTransition)
        );

        let mut drift = event(PublishStageV1::PublishCalled, prepared_digest);
        drift.vehicle_id = VehicleId::new("uav-2").unwrap();
        assert_eq!(
            reducer.apply_event(&drift, CALLED_ENVELOPE),
            Err(PublicationReductionError::IdentityMismatch)
        );

        let mut regressed = event(PublishStageV1::PublishCalled, prepared_digest);
        regressed.observed_mono_ns = 99;
        assert_eq!(
            reducer.apply_event(&regressed, CALLED_ENVELOPE),
            Err(PublicationReductionError::TimeRegression)
        );

        let mut wrong_link = event(
            PublishStageV1::PublishCalled,
            DigestV1::compute(DigestDomain::RawEnvelope, b"not-the-receipt"),
        );
        // Keep contract validation focused on the reducer's exact predecessor
        // check by changing both called-link fields together.
        wrong_link.prepared_receipt_envelope_digest = wrong_link.predecessor_envelope_digest;
        assert_eq!(
            reducer.apply_event(&wrong_link, CALLED_ENVELOPE),
            Err(PublicationReductionError::IdentityMismatch)
        );

        reducer
            .apply_event(
                &event(PublishStageV1::PublishCalled, prepared_digest),
                CALLED_ENVELOPE,
            )
            .unwrap();
        assert_eq!(
            reducer.apply_event(
                &event(
                    PublishStageV1::PublishReturnedOk,
                    DigestV1::compute(DigestDomain::RawEnvelope, b"wrong-called"),
                ),
                b"terminal",
            ),
            Err(PublicationReductionError::PredecessorMismatch)
        );
    }

    #[test]
    fn dangling_prior_call_builds_one_linked_unknown_without_mutation() {
        let mut reducer = PublicationStageReducer::new(4).unwrap();
        reducer
            .register_prepared(&receipt(), PREPARED_ENVELOPE)
            .unwrap();
        let prepared_digest = DigestV1::compute(DigestDomain::RawEnvelope, PREPARED_ENVELOPE);
        reducer
            .apply_event(
                &event(PublishStageV1::PublishCalled, prepared_digest),
                CALLED_ENVELOPE,
            )
            .unwrap();

        let unknown = reducer
            .unknown_after_publish_events(GateBootId::new([9; 16]), 7)
            .unwrap();
        assert_eq!(unknown.len(), 1);
        assert_eq!(unknown[0].stage, PublishStageV1::UnknownAfterPublish);
        assert_eq!(unknown[0].producer_gate_boot_id, GateBootId::new([9; 16]));
        assert_eq!(
            unknown[0].predecessor_envelope_digest,
            DigestV1::compute(DigestDomain::RawEnvelope, CALLED_ENVELOPE)
        );
        assert_eq!(
            reducer.state(GateBootId::new([2; 16]), DecisionId::new([1; 16])),
            Some(PublicationTraceState::PublishCalled)
        );

        reducer.apply_event(&unknown[0], b"signed-unknown").unwrap();
        assert_eq!(
            reducer.state(GateBootId::new([2; 16]), DecisionId::new([1; 16])),
            Some(PublicationTraceState::UnknownAfterPublish)
        );
    }

    #[test]
    fn prepared_only_tail_needs_no_unknown_and_bounds_are_enforced() {
        assert!(matches!(
            PublicationStageReducer::new(0),
            Err(PublicationReductionError::CapacityExceeded)
        ));
        let mut reducer = PublicationStageReducer::new(1).unwrap();
        reducer
            .register_prepared(&receipt(), PREPARED_ENVELOPE)
            .unwrap();
        assert!(
            reducer
                .unknown_after_publish_events(GateBootId::new([9; 16]), 0)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            reducer.unknown_after_publish_events(GateBootId::new([2; 16]), 0),
            Err(PublicationReductionError::RecoveryBootAlreadyObserved)
        );
        assert_eq!(
            reducer.register_prepared(&receipt(), PREPARED_ENVELOPE),
            Err(PublicationReductionError::DuplicateDecision)
        );

        let mut another = receipt();
        another.decision_id = DecisionId::new([7; 16]);
        assert_eq!(
            reducer.register_prepared(&another, b"another-prepared"),
            Err(PublicationReductionError::CapacityExceeded)
        );

        let mut other_gate = receipt();
        other_gate.decision_id = DecisionId::new([8; 16]);
        other_gate.gate_id = GateId::new("gate-2").unwrap();
        assert_eq!(
            reducer.register_prepared(&other_gate, b"other-gate-prepared"),
            Err(PublicationReductionError::GateScopeMismatch)
        );
    }

    #[test]
    fn malformed_prepared_receipts_and_return_time_regression_are_rejected() {
        let mut reducer = PublicationStageReducer::new(4).unwrap();
        let mut malformed = receipt();
        malformed.publish_stage = PublishStageV1::PublishReturnedOk;
        assert_eq!(
            reducer.register_prepared(&malformed, PREPARED_ENVELOPE),
            Err(PublicationReductionError::InvalidPreparedReceipt)
        );
        malformed = receipt();
        malformed.effective_validity_ms = None;
        assert_eq!(
            reducer.register_prepared(&malformed, PREPARED_ENVELOPE),
            Err(PublicationReductionError::InvalidPreparedReceipt)
        );
        malformed = receipt();
        malformed.reason_codes = BoundedVec::from_vec(vec![
            DecisionReasonCodeV1::AllowPrepared,
            DecisionReasonCodeV1::DenyCommandRange,
        ])
        .unwrap();
        assert_eq!(
            reducer.register_prepared(&malformed, PREPARED_ENVELOPE),
            Err(PublicationReductionError::InvalidPreparedReceipt)
        );
        malformed = receipt();
        malformed.transformation_relation = None;
        assert_eq!(
            reducer.register_prepared(&malformed, PREPARED_ENVELOPE),
            Err(PublicationReductionError::InvalidPreparedReceipt)
        );
        malformed = receipt();
        malformed.received_mono_ns = 101;
        assert_eq!(
            reducer.register_prepared(&malformed, PREPARED_ENVELOPE),
            Err(PublicationReductionError::InvalidPreparedReceipt)
        );

        reducer
            .register_prepared(&receipt(), PREPARED_ENVELOPE)
            .unwrap();
        let prepared_digest = DigestV1::compute(DigestDomain::RawEnvelope, PREPARED_ENVELOPE);
        reducer
            .apply_event(
                &event(PublishStageV1::PublishCalled, prepared_digest),
                CALLED_ENVELOPE,
            )
            .unwrap();
        let called_digest = DigestV1::compute(DigestDomain::RawEnvelope, CALLED_ENVELOPE);
        let mut returned = event(PublishStageV1::PublishReturnedError, called_digest);
        returned.observed_mono_ns = 109;
        assert_eq!(
            reducer.apply_event(&returned, b"signed-error"),
            Err(PublicationReductionError::TimeRegression)
        );
        returned.observed_mono_ns = 110;
        reducer.apply_event(&returned, b"signed-error").unwrap();
        assert_eq!(
            reducer.state(GateBootId::new([2; 16]), DecisionId::new([1; 16])),
            Some(PublicationTraceState::PublishReturnedError)
        );
    }

    #[test]
    fn ordered_replay_enforces_time_across_decisions_in_one_boot() {
        let mut reducer = PublicationStageReducer::new(4).unwrap();
        reducer
            .register_prepared(&receipt(), PREPARED_ENVELOPE)
            .unwrap();

        let mut second_receipt = receipt();
        second_receipt.decision_id = DecisionId::new([7; 16]);
        second_receipt.received_mono_ns = 100;
        second_receipt.decided_mono_ns = 101;
        reducer
            .register_prepared(&second_receipt, b"signed-prepared-2")
            .unwrap();

        let mut first_called = event(
            PublishStageV1::PublishCalled,
            DigestV1::compute(DigestDomain::RawEnvelope, PREPARED_ENVELOPE),
        );
        first_called.observed_mono_ns = 200;
        reducer.apply_event(&first_called, CALLED_ENVELOPE).unwrap();

        let second_prepared_digest =
            DigestV1::compute(DigestDomain::RawEnvelope, b"signed-prepared-2");
        let mut second_called = event(PublishStageV1::PublishCalled, second_prepared_digest);
        second_called.decision_id = DecisionId::new([7; 16]);
        second_called.prepared_receipt_envelope_digest = second_prepared_digest;
        second_called.observed_mono_ns = 199;
        assert_eq!(
            reducer.apply_event(&second_called, b"signed-called-2"),
            Err(PublicationReductionError::TimeRegression)
        );

        let mut regressed_receipt = receipt();
        regressed_receipt.decision_id = DecisionId::new([8; 16]);
        regressed_receipt.received_mono_ns = 149;
        regressed_receipt.decided_mono_ns = 150;
        assert_eq!(
            reducer.register_prepared(&regressed_receipt, b"signed-prepared-3"),
            Err(PublicationReductionError::TimeRegression)
        );
    }
}
