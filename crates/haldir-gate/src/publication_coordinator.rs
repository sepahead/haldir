//! Internal locally synced publication lifecycle coordination.
//!
//! The state types consume one another so no usable bound runtime can escape an
//! ambiguous journal append, a post-sync validation failure, or a dropped
//! called typestate. The called state owns the exact output bytes, and only a
//! startup-capability-marked live Called type lends them to the concrete strict
//! publisher. "Durable" state
//! names below mean a local append whose `sync_data` returned successfully; they do
//! not claim power-loss survival, delivery, acceptance, or application.

use core::num::{NonZeroU32, NonZeroUsize};

use haldir_contracts::digest::{DigestDomain, DigestV1};
#[cfg(feature = "live-zenoh")]
use haldir_contracts::ids::{ChallengeNonce, ControllerId};
use haldir_contracts::ids::{DecisionId, GateBootId, GateId, VehicleId};
use haldir_contracts::publication::PublicationStageEventV1;
#[cfg(feature = "live-zenoh")]
use haldir_contracts::receipt::DecisionReasonCodeV1;
use haldir_contracts::receipt::{DecisionOutcomeV1, PublishStageV1};
use haldir_contracts::session::{NcpSessionIdentityV1, NcpStreamPositionV1};
#[cfg(feature = "live-zenoh")]
use haldir_core::snapshot::TrustedStateSnapshotV1;
use haldir_core::time::{MonoInstant, MonotonicClock};
use haldir_evidence::gate_journal::{
    GateJournalMutationError, GateJournalReservation, RecoveredGateJournal,
};
#[cfg(test)]
use haldir_evidence::journal::JournalError;
#[cfg(test)]
use haldir_evidence::manager::{EvidenceRecordDigest, JournalManagerError};
use haldir_evidence::publication::PublicationTraceState;
#[cfg(any(test, feature = "live-zenoh"))]
use haldir_ncp08::ExactNcpCommandFrame;
#[cfg(feature = "live-zenoh")]
use haldir_ncp08::NcpCommandWireProfile;
#[cfg(feature = "live-zenoh")]
use haldir_transport_zenoh::{FinalCommandPublisher, HaldirKeyError, HaldirKeys, SecureZenohError};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::actor::{
    DecisionRecord, PreparedPublication, PublicationError, PublishCalledPublication,
    ValidatedPublicationCall, VehicleActor,
};
#[cfg(feature = "live-zenoh")]
use crate::actor::{GateError, LeaseEnvelopeValidationError};
use crate::startup::JournalBoundRunningGate;
#[cfg(feature = "live-zenoh")]
use crate::startup::{GateRuntimeProfile, ValidatedDeclaredLiveZenohStartup};

const LIFECYCLE_RECORD_RESERVATION: usize = 3;

struct OutputCapacityState {
    available: AtomicUsize,
    capacity: usize,
}

/// Bounded-pool handle that mints move-only slot permits. The public service holds
/// one production handle; tests may clone it to observe permit release across
/// consuming lifecycle transitions.
#[cfg_attr(test, derive(Clone))]
pub(crate) struct OutputCapacityPool {
    state: Arc<OutputCapacityState>,
}

impl OutputCapacityPool {
    pub(crate) fn new(capacity: NonZeroUsize) -> Self {
        Self {
            state: Arc::new(OutputCapacityState {
                available: AtomicUsize::new(capacity.get()),
                capacity: capacity.get(),
            }),
        }
    }

    pub(crate) fn try_reserve(&self) -> Option<OutputCapacityPermit> {
        self.state
            .available
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |available| {
                available.checked_sub(1)
            })
            .ok()
            .map(|_| OutputCapacityPermit {
                state: Arc::clone(&self.state),
            })
    }

    #[cfg(test)]
    pub(crate) fn available(&self) -> usize {
        self.state.available.load(Ordering::Acquire)
    }
}

/// One reserved output slot. It cannot be cloned or constructed independently
/// of its bounded pool; dropping it returns the slot.
#[must_use = "dropping the permit releases its reserved output slot"]
pub(crate) struct OutputCapacityPermit {
    state: Arc<OutputCapacityState>,
}

impl Drop for OutputCapacityPermit {
    fn drop(&mut self) {
        let mut current = self.state.available.load(Ordering::Acquire);
        while current < self.state.capacity {
            match self.state.available.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return,
                Err(observed) => current = observed,
            }
        }
    }
}

/// A failure after which the owned bound runtime is deliberately unavailable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CoordinatorFatal {
    Journal(GateJournalMutationError),
    Publication(PublicationError),
    InvalidPreparedReceipt,
    ClockRegression,
    RestartDiagnosticHorizonOverflow,
    #[cfg(feature = "live-zenoh")]
    RuntimeProfileMismatch {
        required: GateRuntimeProfile,
        actual: GateRuntimeProfile,
    },
    #[cfg(feature = "live-zenoh")]
    NcpWireProfileMismatch {
        required: NcpCommandWireProfile,
        actual: NcpCommandWireProfile,
    },
    #[cfg(feature = "live-zenoh")]
    DeclaredLiveStartupCapabilityUnavailable,
    #[cfg(feature = "live-zenoh")]
    InvalidFinalCommandRoute(HaldirKeyError),
}

/// Marker for the in-process reference lifecycle. Its private field prevents
/// sibling modules from manufacturing coordinator profile states.
pub(crate) struct InProcessReferencePublication {
    _private: (),
}

/// Capability marker minted only after a bound durable startup is rechecked as
/// the declared-live, exact-NCP profile.
#[cfg(feature = "live-zenoh")]
pub(crate) struct DeclaredLiveZenohPublication {
    _startup: ValidatedDeclaredLiveZenohStartup,
}

/// Exact intent subscription identity minted only from an accepted live lease.
#[cfg(feature = "live-zenoh")]
pub(crate) struct ActiveIntentBinding {
    controller_id: ControllerId,
    intent_route: String,
}

#[cfg(feature = "live-zenoh")]
impl ActiveIntentBinding {
    pub(crate) const fn controller_id(&self) -> &ControllerId {
        &self.controller_id
    }

    pub(crate) fn intent_route(&self) -> &str {
        &self.intent_route
    }
}

/// Fail-stop outcome while priming a declared-live coordinator with local control inputs.
#[cfg(feature = "live-zenoh")]
pub(crate) enum LiveIntentActivationFailure {
    Fatal(CoordinatorFatal),
    TrustedState(DecisionReasonCodeV1),
    ChallengeRejected,
    IntentRouteMismatch,
    Lease(GateError),
    ActiveBindingUnavailable,
}

/// A pre-decision refusal that returns the coordinator without actor, journal,
/// decision, or output-sequence mutation. Its clock high-water may advance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DecisionUnavailable {
    RestartClearanceRequired {
        observed_at: MonoInstant,
        /// Construction-time diagnostic based on recovered validity and the new
        /// actor's current duty policy. It is never sufficient for clearance.
        current_policy_diagnostic_not_before: MonoInstant,
    },
    JournalCapacity(GateJournalMutationError),
}

/// A pre-decision refusal retains both the runtime and the caller's capacity
/// permit because no actor, journal, decision, or output-sequence mutation occurred.
/// The coordinator's sampled clock high-water is retained.
pub(crate) enum DecideError<C, P = InProcessReferencePublication> {
    Unavailable {
        coordinator: PublicationCoordinator<C, P>,
        output_permit: OutputCapacityPermit,
        reason: DecisionUnavailable,
    },
    Fatal(CoordinatorFatal),
}

impl<C, P> DecideError<C, P> {
    pub(crate) fn into_unavailable(
        self,
    ) -> Result<
        (
            PublicationCoordinator<C, P>,
            OutputCapacityPermit,
            DecisionUnavailable,
        ),
        CoordinatorFatal,
    > {
        match self {
            Self::Unavailable {
                coordinator,
                output_permit,
                reason,
            } => Ok((coordinator, output_permit, reason)),
            Self::Fatal(error) => Err(error),
        }
    }
}

struct CoordinatorCore<C, P> {
    bound: JournalBoundRunningGate,
    clock: C,
    profile: P,
    last_observed: MonoInstant,
    restart_clearance_diagnostic_not_before: Option<MonoInstant>,
    #[cfg(feature = "live-zenoh")]
    haldir_keys: HaldirKeys,
}

impl<C: MonotonicClock, P> CoordinatorCore<C, P> {
    fn sample_now(&mut self) -> Result<MonoInstant, CoordinatorFatal> {
        let observed = self.clock.now();
        if observed < self.last_observed {
            return Err(CoordinatorFatal::ClockRegression);
        }
        self.last_observed = observed;
        Ok(observed)
    }
}

/// Ready state. It owns the fused actor, journal, process lock, and clock.
#[must_use = "dropping the coordinator stops the bound Gate runtime"]
pub(crate) struct PublicationCoordinator<C, P = InProcessReferencePublication> {
    core: Box<CoordinatorCore<C, P>>,
}

/// A completed or cancelled decision that returns a ready coordinator and the
/// still-reserved output-capacity permit for explicit reuse or release.
pub(crate) struct ReadyDecision<C, P = InProcessReferencePublication> {
    coordinator: PublicationCoordinator<C, P>,
    decision: DecisionRecord,
    output_permit: OutputCapacityPermit,
}

impl<C, P> ReadyDecision<C, P> {
    pub(crate) fn decision(&self) -> &DecisionRecord {
        &self.decision
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        PublicationCoordinator<C, P>,
        DecisionRecord,
        OutputCapacityPermit,
    ) {
        (self.coordinator, self.decision, self.output_permit)
    }
}

/// Result of locally sync-confirming one new decision receipt.
pub(crate) enum DecisionTransition<C, P = InProcessReferencePublication> {
    NoPublication(Box<ReadyDecision<C, P>>),
    Prepared(Box<DurablePreparedPublication<C, P>>),
}

/// A prepared output whose exact receipt append is locally sync-confirmed but
/// whose bytes remain inaccessible. The retained permit and two journal units
/// cover call + return.
#[must_use = "a locally synced prepared publication must be cancelled or advanced"]
pub(crate) struct DurablePreparedPublication<C, P = InProcessReferencePublication> {
    core: Box<CoordinatorCore<C, P>>,
    decision: DecisionRecord,
    prepared: Box<PreparedPublication>,
    reservation: GateJournalReservation,
    binding: PublicationBinding,
    output_permit: OutputCapacityPermit,
}

/// Result of attempting the pre-exposure Called boundary.
pub(crate) enum CallTransition<C, P = InProcessReferencePublication> {
    Called(Box<DurableCalledPublication<C, P>>),
    Rejected {
        ready: Box<ReadyDecision<C, P>>,
        reason: PublicationError,
    },
}

/// Test-only terminal append outcomes injected at the coordinator boundary.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TestTerminalAppendFault {
    /// Return a definite storage failure before terminal bytes reach the journal.
    BeforeAppend,
    /// Return ambiguity after the real terminal append and local sync succeed.
    AfterSyncAmbiguous,
}

/// A locally sync-confirmed Called output. Production code can lend its bytes only
/// to the feature-gated concrete publisher binding. Dropping it drops the whole
/// bound runtime; it cannot return to Ready silently.
#[must_use = "dropping a called publication abandons the bound runtime for restart recovery"]
pub(crate) struct DurableCalledPublication<C, P = InProcessReferencePublication> {
    core: Box<CoordinatorCore<C, P>>,
    decision: DecisionRecord,
    called: Box<PublishCalledPublication>,
    reservation: GateJournalReservation,
    binding: PublicationBinding,
    called_envelope_digest: DigestV1,
    output_permit: OutputCapacityPermit,
    #[cfg(test)]
    terminal_append_fault: Option<TestTerminalAppendFault>,
}

/// A locally sync-confirmed successful local publisher return.
pub(crate) struct JournaledReturnedOk<C, P = InProcessReferencePublication> {
    coordinator: PublicationCoordinator<C, P>,
    decision: DecisionRecord,
    terminal_envelope_digest: DigestV1,
    output_permit: OutputCapacityPermit,
}

impl<C, P> JournaledReturnedOk<C, P> {
    pub(crate) fn into_parts(
        self,
    ) -> (
        PublicationCoordinator<C, P>,
        DecisionRecord,
        DigestV1,
        OutputCapacityPermit,
    ) {
        (
            self.coordinator,
            self.decision,
            self.terminal_envelope_digest,
            self.output_permit,
        )
    }
}

/// A locally sync-confirmed publisher error return. This includes both definite
/// pre-transport validation rejection and delivery-ambiguous local transport error.
/// No ready coordinator is returned because replacement output is forbidden this boot.
pub(crate) struct JournaledReturnedError {
    decision: DecisionRecord,
    terminal_envelope_digest: DigestV1,
    output_permit: OutputCapacityPermit,
}

impl JournaledReturnedError {
    pub(crate) fn into_parts(self) -> (DecisionRecord, DigestV1, OutputCapacityPermit) {
        (
            self.decision,
            self.terminal_envelope_digest,
            self.output_permit,
        )
    }
}

/// Failure of the consuming one-call publisher binding.
///
/// The publisher capability is deliberately absent from both variants. A local
/// publisher error has a terminal record when possible; if the terminal journal/
/// actor boundary fails, the original publisher result remains available for diagnosis.
#[cfg(any(test, feature = "live-zenoh"))]
pub(crate) enum PublishOnceError<E> {
    PublisherReturned {
        source: E,
        journaled: Box<JournaledReturnedError>,
    },
    TerminalBoundaryFailed {
        publisher_error: Option<E>,
        source: CoordinatorFatal,
    },
}

/// Gate-side validation or concrete strict-publisher failure.
#[cfg(feature = "live-zenoh")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StrictPublisherCallError {
    PublisherRouteMismatch,
    Publisher(SecureZenohError),
}

#[derive(Clone)]
struct PublicationBinding {
    decision_id: DecisionId,
    gate_id: GateId,
    decision_gate_boot_id: GateBootId,
    vehicle_id: VehicleId,
    ncp_session: NcpSessionIdentityV1,
    gate_output_stream: NcpStreamPositionV1,
    output_frame_digest: DigestV1,
    effective_validity_ms: NonZeroU32,
    prepared_receipt_envelope_digest: DigestV1,
}

impl PublicationBinding {
    fn from_decision(
        decision: &DecisionRecord,
        prepared: &PreparedPublication,
    ) -> Result<Self, CoordinatorFatal> {
        let receipt = &decision.receipt;
        if decision.outcome != DecisionOutcomeV1::Allow
            || receipt.decision != DecisionOutcomeV1::Allow
            || receipt.publish_stage != PublishStageV1::OutputPrepared
            || prepared.decision_id() != receipt.decision_id
        {
            return Err(CoordinatorFatal::InvalidPreparedReceipt);
        }
        let gate_output_stream = receipt
            .gate_output_stream
            .clone()
            .ok_or(CoordinatorFatal::InvalidPreparedReceipt)?;
        let output_frame_digest = receipt
            .output_frame_digest
            .ok_or(CoordinatorFatal::InvalidPreparedReceipt)?;
        let effective_validity_ms = receipt
            .effective_validity_ms
            .and_then(NonZeroU32::new)
            .ok_or(CoordinatorFatal::InvalidPreparedReceipt)?;
        Ok(Self {
            decision_id: receipt.decision_id,
            gate_id: receipt.gate_id.clone(),
            decision_gate_boot_id: receipt.gate_boot_id,
            vehicle_id: receipt.vehicle_id.clone(),
            ncp_session: receipt.ncp_session.clone(),
            gate_output_stream,
            output_frame_digest,
            effective_validity_ms,
            prepared_receipt_envelope_digest: DigestV1::compute(
                DigestDomain::RawEnvelope,
                &decision.signed_receipt,
            ),
        })
    }

    fn event(
        &self,
        stage: PublishStageV1,
        predecessor_envelope_digest: DigestV1,
        observed_at: MonoInstant,
    ) -> PublicationStageEventV1 {
        PublicationStageEventV1 {
            schema_major: 1,
            schema_minor: 0,
            decision_id: self.decision_id,
            gate_id: self.gate_id.clone(),
            decision_gate_boot_id: self.decision_gate_boot_id,
            producer_gate_boot_id: self.decision_gate_boot_id,
            vehicle_id: self.vehicle_id.clone(),
            ncp_session: self.ncp_session.clone(),
            gate_output_stream: self.gate_output_stream.clone(),
            output_frame_digest: self.output_frame_digest,
            effective_validity_ms: self.effective_validity_ms,
            prepared_receipt_envelope_digest: self.prepared_receipt_envelope_digest,
            predecessor_envelope_digest,
            stage,
            observed_mono_ns: observed_at.as_nanos(),
        }
    }
}

impl<C: MonotonicClock> PublicationCoordinator<C, InProcessReferencePublication> {
    /// Construct the reference lifecycle only for tests. Production coordinator
    /// construction must select a checked concrete integration profile.
    #[cfg(test)]
    pub(crate) fn new_reference_for_test(
        bound: JournalBoundRunningGate,
        clock: C,
    ) -> Result<Self, CoordinatorFatal> {
        Self::new_with_profile(bound, clock, InProcessReferencePublication { _private: () })
    }
}

#[cfg(feature = "live-zenoh")]
impl<C: MonotonicClock> PublicationCoordinator<C, DeclaredLiveZenohPublication> {
    /// Consume a durable journal-bound runtime and mint the sole concrete-live
    /// coordinator profile after rechecking its retained startup declaration and
    /// exact NCP wire selection. Checks precede route derivation and clock access.
    pub(crate) fn new_declared_live(
        mut bound: JournalBoundRunningGate,
        clock: C,
    ) -> Result<Self, CoordinatorFatal> {
        let required_runtime = GateRuntimeProfile::DeclaredLiveZenoh;
        let actual_runtime = bound.report().runtime_profile;
        if actual_runtime != required_runtime {
            return Err(CoordinatorFatal::RuntimeProfileMismatch {
                required: required_runtime,
                actual: actual_runtime,
            });
        }

        let required_wire = NcpCommandWireProfile::ExactNcpV0_8Json;
        let actual_wire = bound.actor().ncp_command_wire_profile();
        if actual_wire != required_wire {
            return Err(CoordinatorFatal::NcpWireProfileMismatch {
                required: required_wire,
                actual: actual_wire,
            });
        }

        let startup = bound
            .take_declared_live_zenoh_capability()
            .ok_or(CoordinatorFatal::DeclaredLiveStartupCapabilityUnavailable)?;

        Self::new_with_profile(
            bound,
            clock,
            DeclaredLiveZenohPublication { _startup: startup },
        )
    }

    pub(crate) fn publisher_route_matches(&self, publisher_route: &str) -> bool {
        publisher_route == self.core.haldir_keys.final_command()
    }

    pub(crate) const fn haldir_keys(&self) -> &HaldirKeys {
        &self.core.haldir_keys
    }

    /// Prime the otherwise inactive startup actor with one caller-supplied state,
    /// challenge, and signed lease while keeping the coordinator capability sealed.
    /// The canonical intent route is checked after signature/admission validation
    /// but before lease-term commit, challenge consumption, or activation.
    pub(crate) fn activate_live_intent(
        mut self,
        trusted_state: TrustedStateSnapshotV1,
        challenge_nonce: ChallengeNonce,
        lease_envelope: &[u8],
    ) -> Result<(Self, ActiveIntentBinding), LiveIntentActivationFailure> {
        let now = self
            .core
            .sample_now()
            .map_err(LiveIntentActivationFailure::Fatal)?;

        let actor = &mut self.core.bound.gate.actor;
        actor
            .validate_trusted_state(&trusted_state)
            .map_err(LiveIntentActivationFailure::TrustedState)?;
        // Static activation verifies and consumes the supplied lease at this same
        // sampled instant, so no caller-selected challenge lifetime is needed.
        if !actor.register_challenge(challenge_nonce, now, now) {
            return Err(LiveIntentActivationFailure::ChallengeRejected);
        }

        let keys = &self.core.haldir_keys;
        actor
            .accept_lease_env_with_validator(lease_envelope, now, |lease| {
                let expected = keys.intent(lease.controller_id.as_str()).map_err(|_| ())?;
                if lease.controller_intent_key.as_str() != expected {
                    return Err(());
                }
                Ok(())
            })
            .map_err(|error| match error {
                LeaseEnvelopeValidationError::Gate(error) => {
                    LiveIntentActivationFailure::Lease(error)
                }
                LeaseEnvelopeValidationError::ValidatorRejected(()) => {
                    LiveIntentActivationFailure::IntentRouteMismatch
                }
            })?;

        // The same exclusive actor was prevalidated immediately above. A failure
        // here is still fail-stop because lease authority has already committed.
        actor
            .set_trusted_state(trusted_state)
            .map_err(LiveIntentActivationFailure::TrustedState)?;
        let intent_binding = actor
            .active_intent_binding()
            .map(|(controller_id, intent_route)| ActiveIntentBinding {
                controller_id: controller_id.clone(),
                intent_route: intent_route.to_owned(),
            })
            .ok_or(LiveIntentActivationFailure::ActiveBindingUnavailable)?;
        Ok((self, intent_binding))
    }
}

impl<C: MonotonicClock, P> PublicationCoordinator<C, P> {
    fn new_with_profile(
        bound: JournalBoundRunningGate,
        clock: C,
        profile: P,
    ) -> Result<Self, CoordinatorFatal> {
        let startup_now = clock.now();
        #[cfg(feature = "live-zenoh")]
        let haldir_keys = HaldirKeys::try_new(
            bound.actor().realm().as_str(),
            bound.actor().ncp_session().session_id.as_str(),
        )
        .map_err(CoordinatorFatal::InvalidFinalCommandRoute)?;
        // This cannot reconstruct the old boot's policy window. It is exposed only
        // as a current-policy diagnostic while the actual restart block remains
        // indefinite and requires a future authenticated external clearance.
        let restart_clearance_diagnostic_not_before = bound
            .recovered_publication()
            .maximum_potentially_active_validity_ms()
            .map(|validity| {
                let diagnostic_offset_ms =
                    validity.get().max(bound.actor().duty_history_window_ms());
                startup_now
                    .checked_add_ms(u64::from(diagnostic_offset_ms))
                    .ok_or(CoordinatorFatal::RestartDiagnosticHorizonOverflow)
            })
            .transpose()?;
        Ok(Self {
            core: Box::new(CoordinatorCore {
                bound,
                clock,
                profile,
                last_observed: startup_now,
                restart_clearance_diagnostic_not_before,
                #[cfg(feature = "live-zenoh")]
                haldir_keys,
            }),
        })
    }

    /// Current-policy diagnostic only; reaching it never clears restart refusal.
    pub(crate) const fn restart_clearance_diagnostic_not_before(&self) -> Option<MonoInstant> {
        self.core.restart_clearance_diagnostic_not_before
    }

    pub(crate) fn publication_trace_state(
        &self,
        decision_gate_boot_id: GateBootId,
        decision_id: DecisionId,
    ) -> Option<PublicationTraceState> {
        self.core
            .bound
            .recovered_publication()
            .state(decision_gate_boot_id, decision_id)
    }

    pub(crate) const fn actor(&self) -> &VehicleActor {
        self.core.bound.actor()
    }

    /// Reserve all journal stages and require an already-owned output-capacity
    /// permit before the actor can allocate a decision or output sequence.
    pub(crate) fn decide(
        mut self,
        output_permit: OutputCapacityPermit,
        envelope: &[u8],
        actual_key: &str,
    ) -> Result<DecisionTransition<C, P>, DecideError<C, P>> {
        let now = match self.core.sample_now() {
            Ok(now) => now,
            Err(reason) => return Err(DecideError::Fatal(reason)),
        };
        if let Some(current_policy_diagnostic_not_before) =
            self.core.restart_clearance_diagnostic_not_before
        {
            return Err(DecideError::Unavailable {
                coordinator: self,
                output_permit,
                reason: DecisionUnavailable::RestartClearanceRequired {
                    observed_at: now,
                    current_policy_diagnostic_not_before,
                },
            });
        }

        if let Some(decision) = self.core.bound.actor().cached_terminal_decision() {
            return Ok(DecisionTransition::NoPublication(Box::new(ReadyDecision {
                coordinator: self,
                decision,
                output_permit,
            })));
        }

        let mut reservation = {
            let (_, journal) = live_parts_mut(&mut self.core.bound);
            match journal.reserve_append_capacity(LIFECYCLE_RECORD_RESERVATION) {
                Ok(reservation) => reservation,
                Err(error) => {
                    return Err(DecideError::Unavailable {
                        coordinator: self,
                        output_permit,
                        reason: DecisionUnavailable::JournalCapacity(error),
                    });
                }
            }
        };
        let mut decision = {
            let (actor, _) = live_parts_mut(&mut self.core.bound);
            actor.decide_intent(envelope, actual_key, now)
        };

        append_verified(
            self.core.as_mut(),
            &mut reservation,
            &decision.signed_receipt,
            now,
        )
        .map_err(DecideError::Fatal)?;

        let Some(prepared) = decision.take_prepared_publication() else {
            release_reservation(self.core.as_mut(), &mut reservation)
                .map_err(DecideError::Fatal)?;
            return Ok(DecisionTransition::NoPublication(Box::new(ReadyDecision {
                coordinator: self,
                decision,
                output_permit,
            })));
        };
        let binding =
            PublicationBinding::from_decision(&decision, &prepared).map_err(DecideError::Fatal)?;
        Ok(DecisionTransition::Prepared(Box::new(
            DurablePreparedPublication {
                core: self.core,
                decision,
                prepared: Box::new(prepared),
                reservation,
                binding,
                output_permit,
            },
        )))
    }
}

impl<C: MonotonicClock, P> DurablePreparedPublication<C, P> {
    pub(crate) fn decision(&self) -> &DecisionRecord {
        &self.decision
    }

    pub(crate) fn publication_trace_state(&self) -> Option<PublicationTraceState> {
        self.core
            .bound
            .recovered_publication()
            .state(self.binding.decision_gate_boot_id, self.binding.decision_id)
    }

    pub(crate) fn cancel(self) -> Result<ReadyDecision<C, P>, CoordinatorFatal> {
        let Self {
            mut core,
            decision,
            prepared,
            mut reservation,
            binding: _,
            output_permit,
        } = self;
        release_reservation(core.as_mut(), &mut reservation)?;
        let (actor, _) = live_parts_mut(&mut core.bound);
        actor
            .cancel_prepared_publication(*prepared)
            .map_err(CoordinatorFatal::Publication)?;
        Ok(ReadyDecision {
            coordinator: PublicationCoordinator { core },
            decision,
            output_permit,
        })
    }

    pub(crate) fn enter_called_boundary(self) -> Result<CallTransition<C, P>, CoordinatorFatal> {
        let Self {
            mut core,
            decision,
            prepared,
            mut reservation,
            binding,
            output_permit,
        } = self;
        let validation_at = core.sample_now()?;
        let validated = {
            let (actor, _) = live_parts_mut(&mut core.bound);
            actor.validate_publish_call(*prepared, validation_at)
        };
        let validated = match validated {
            Ok(validated) => validated,
            Err(PublicationError::StateMismatch) => {
                return Err(CoordinatorFatal::Publication(
                    PublicationError::StateMismatch,
                ));
            }
            Err(reason) => {
                release_reservation(core.as_mut(), &mut reservation)?;
                return Ok(CallTransition::Rejected {
                    ready: Box::new(ReadyDecision {
                        coordinator: PublicationCoordinator { core },
                        decision,
                        output_permit,
                    }),
                    reason,
                });
            }
        };

        let called_event = binding.event(
            PublishStageV1::PublishCalled,
            binding.prepared_receipt_envelope_digest,
            validation_at,
        );
        let called_envelope_digest = sign_and_append_stage(
            core.as_mut(),
            &mut reservation,
            &called_event,
            validation_at,
        )?;

        let exposure_at = core.sample_now()?;
        let called = commit_called(core.as_mut(), validated, exposure_at)?;
        Ok(CallTransition::Called(Box::new(DurableCalledPublication {
            core,
            decision,
            called: Box::new(called),
            reservation,
            binding,
            called_envelope_digest,
            output_permit,
            #[cfg(test)]
            terminal_append_fault: None,
        })))
    }
}

impl<C: MonotonicClock, P> DurableCalledPublication<C, P> {
    #[cfg(test)]
    const fn frame_for_test(&self) -> &ExactNcpCommandFrame {
        self.called.frame()
    }

    pub(crate) fn decision(&self) -> &DecisionRecord {
        &self.decision
    }

    pub(crate) fn publication_trace_state(&self) -> Option<PublicationTraceState> {
        self.core
            .bound
            .recovered_publication()
            .state(self.binding.decision_gate_boot_id, self.binding.decision_id)
    }

    /// Select one terminal append fault for a consuming coordinator test.
    #[cfg(test)]
    pub(crate) fn with_test_terminal_append_fault(
        mut self,
        fault: TestTerminalAppendFault,
    ) -> Self {
        self.terminal_append_fault = Some(fault);
        self
    }

    #[cfg(feature = "live-zenoh")]
    fn publisher_route_matches(&self, publisher_route: &str) -> bool {
        publisher_route == self.core.haldir_keys.final_command()
    }

    #[cfg(all(test, feature = "live-zenoh"))]
    pub(crate) fn expected_final_command_route(&self) -> &str {
        self.core.haldir_keys.final_command()
    }

    /// Exercise route rejection without constructing a live Zenoh session.
    #[cfg(all(test, feature = "live-zenoh"))]
    pub(crate) async fn publish_once_with_test_route<Publisher, F, Fut>(
        self,
        publisher: Publisher,
        publisher_route: &str,
        invoke: F,
    ) -> Result<(JournaledReturnedOk<C, P>, Publisher), PublishOnceError<StrictPublisherCallError>>
    where
        F: FnOnce(&ExactNcpCommandFrame) -> Fut,
        Fut: core::future::Future<Output = Result<(), SecureZenohError>>,
    {
        if !self.publisher_route_matches(publisher_route) {
            return self.finish_publish_once(
                publisher,
                Err(StrictPublisherCallError::PublisherRouteMismatch),
            );
        }
        let publisher_result = invoke(self.frame_for_test())
            .await
            .map_err(StrictPublisherCallError::Publisher);
        self.finish_publish_once(publisher, publisher_result)
    }

    /// Exercise the same ownership and terminal-ordering path without a live session.
    #[cfg(test)]
    pub(crate) async fn publish_once_with_test_future<Publisher, E, F, Fut>(
        self,
        publisher: Publisher,
        invoke: F,
    ) -> Result<(JournaledReturnedOk<C, P>, Publisher), PublishOnceError<E>>
    where
        F: FnOnce(&ExactNcpCommandFrame) -> Fut,
        Fut: core::future::Future<Output = Result<(), E>>,
    {
        let publisher_result = invoke(self.frame_for_test()).await;
        self.finish_publish_once(publisher, publisher_result)
    }

    #[cfg(any(test, feature = "live-zenoh"))]
    fn finish_publish_once<Publisher, E>(
        self,
        publisher: Publisher,
        publisher_result: Result<(), E>,
    ) -> Result<(JournaledReturnedOk<C, P>, Publisher), PublishOnceError<E>> {
        match publisher_result {
            Ok(()) => match self.record_returned_ok() {
                Ok(journaled) => Ok((journaled, publisher)),
                Err(source) => {
                    drop(publisher);
                    Err(PublishOnceError::TerminalBoundaryFailed {
                        publisher_error: None,
                        source,
                    })
                }
            },
            Err(error) => match self.record_returned_error() {
                Ok(journaled) => {
                    drop(publisher);
                    Err(PublishOnceError::PublisherReturned {
                        source: error,
                        journaled: Box::new(journaled),
                    })
                }
                Err(source) => {
                    drop(publisher);
                    Err(PublishOnceError::TerminalBoundaryFailed {
                        publisher_error: Some(error),
                        source,
                    })
                }
            },
        }
    }

    #[cfg(any(test, feature = "live-zenoh"))]
    fn record_returned_ok(self) -> Result<JournaledReturnedOk<C, P>, CoordinatorFatal> {
        let Self {
            mut core,
            decision,
            called,
            mut reservation,
            binding,
            called_envelope_digest,
            output_permit,
            #[cfg(test)]
            terminal_append_fault,
        } = self;
        let returned_at = core.sample_now()?;
        let event = binding.event(
            PublishStageV1::PublishReturnedOk,
            called_envelope_digest,
            returned_at,
        );
        let terminal_envelope_digest = sign_and_append_terminal_stage(
            core.as_mut(),
            &mut reservation,
            &event,
            returned_at,
            #[cfg(test)]
            terminal_append_fault,
        )?;
        let (actor, _) = live_parts_mut(&mut core.bound);
        actor
            .mark_publish_returned_ok(*called, returned_at)
            .map_err(CoordinatorFatal::Publication)?;
        Ok(JournaledReturnedOk {
            coordinator: PublicationCoordinator { core },
            decision,
            terminal_envelope_digest,
            output_permit,
        })
    }

    #[cfg(any(test, feature = "live-zenoh"))]
    fn record_returned_error(self) -> Result<JournaledReturnedError, CoordinatorFatal> {
        let Self {
            mut core,
            decision,
            called,
            mut reservation,
            binding,
            called_envelope_digest,
            output_permit,
            #[cfg(test)]
            terminal_append_fault,
        } = self;
        let returned_at = core.sample_now()?;
        let event = binding.event(
            PublishStageV1::PublishReturnedError,
            called_envelope_digest,
            returned_at,
        );
        let terminal_envelope_digest = sign_and_append_terminal_stage(
            core.as_mut(),
            &mut reservation,
            &event,
            returned_at,
            #[cfg(test)]
            terminal_append_fault,
        )?;
        let (actor, _) = live_parts_mut(&mut core.bound);
        actor
            .mark_publish_returned_error(*called)
            .map_err(CoordinatorFatal::Publication)?;
        Ok(JournaledReturnedError {
            decision,
            terminal_envelope_digest,
            output_permit,
        })
    }
}

#[cfg(feature = "live-zenoh")]
impl<C: MonotonicClock> DurableCalledPublication<C, DeclaredLiveZenohPublication> {
    const fn frame(&self) -> &ExactNcpCommandFrame {
        self.called.frame()
    }

    /// Invoke a route-matched concrete strict publisher once for a Called state
    /// descended from this runtime's checked declared-live startup capability.
    ///
    /// A publisher bound to another exact realm/session route is rejected and
    /// terminally recorded before frame access or invocation. A matched publisher
    /// is returned for a later distinct output only after its local call returned
    /// `Ok` and the linked terminal record was sync-confirmed. A publisher error
    /// or terminal-boundary failure drops the publisher capability.
    /// Cancellation while awaiting drops this Called state without inventing a
    /// returned-error record; restart recovery must classify the synced Called tail.
    /// Local `Ok` is not delivery, receiver acceptance, application, or an ACK.
    pub(crate) async fn publish_once(
        self,
        publisher: FinalCommandPublisher,
    ) -> Result<
        (
            JournaledReturnedOk<C, DeclaredLiveZenohPublication>,
            FinalCommandPublisher,
        ),
        PublishOnceError<StrictPublisherCallError>,
    > {
        if !self.publisher_route_matches(publisher.route()) {
            return self.finish_publish_once(
                publisher,
                Err(StrictPublisherCallError::PublisherRouteMismatch),
            );
        }
        let publisher_result = publisher
            .publish(self.frame())
            .await
            .map_err(StrictPublisherCallError::Publisher);
        self.finish_publish_once(publisher, publisher_result)
    }
}

fn release_reservation<C, P>(
    core: &mut CoordinatorCore<C, P>,
    reservation: &mut GateJournalReservation,
) -> Result<(), CoordinatorFatal> {
    let (_, journal) = live_parts_mut(&mut core.bound);
    journal
        .release_reservation(reservation)
        .map_err(CoordinatorFatal::Journal)
}

fn append_verified<C, P>(
    core: &mut CoordinatorCore<C, P>,
    reservation: &mut GateJournalReservation,
    envelope: &[u8],
    observed_at: MonoInstant,
) -> Result<(), CoordinatorFatal> {
    let (actor, journal) = live_parts_mut(&mut core.bound);
    let signer = actor.journal_signer();
    journal
        .append_reserved_verified(reservation, envelope, observed_at.as_nanos(), &signer)
        .map_err(CoordinatorFatal::Journal)
}

fn sign_and_append_stage<C, P>(
    core: &mut CoordinatorCore<C, P>,
    reservation: &mut GateJournalReservation,
    event: &PublicationStageEventV1,
    observed_at: MonoInstant,
) -> Result<DigestV1, CoordinatorFatal> {
    let envelope = {
        let (actor, _) = live_parts_mut(&mut core.bound);
        actor.sign_publication_stage(event)
    };
    append_verified(core, reservation, &envelope, observed_at)?;
    Ok(DigestV1::compute(DigestDomain::RawEnvelope, &envelope))
}

fn sign_and_append_terminal_stage<C, P>(
    core: &mut CoordinatorCore<C, P>,
    reservation: &mut GateJournalReservation,
    event: &PublicationStageEventV1,
    observed_at: MonoInstant,
    #[cfg(test)] fault: Option<TestTerminalAppendFault>,
) -> Result<DigestV1, CoordinatorFatal> {
    let envelope = {
        let (actor, _) = live_parts_mut(&mut core.bound);
        actor.sign_publication_stage(event)
    };
    #[cfg(test)]
    if fault == Some(TestTerminalAppendFault::BeforeAppend) {
        return Err(CoordinatorFatal::Journal(
            GateJournalMutationError::Journal(JournalManagerError::Journal(JournalError::Storage)),
        ));
    }
    append_verified(core, reservation, &envelope, observed_at)?;
    #[cfg(test)]
    if fault == Some(TestTerminalAppendFault::AfterSyncAmbiguous) {
        return Err(CoordinatorFatal::Journal(
            GateJournalMutationError::Journal(JournalManagerError::AppendCommitAmbiguous {
                record_digest: EvidenceRecordDigest::compute(&envelope),
            }),
        ));
    }
    Ok(DigestV1::compute(DigestDomain::RawEnvelope, &envelope))
}

fn commit_called<C, P>(
    core: &mut CoordinatorCore<C, P>,
    validated: ValidatedPublicationCall,
    exposure_at: MonoInstant,
) -> Result<PublishCalledPublication, CoordinatorFatal> {
    let (actor, _) = live_parts_mut(&mut core.bound);
    actor
        .commit_publish_call(validated, exposure_at)
        .map_err(CoordinatorFatal::Publication)
}

fn live_parts_mut(
    bound: &mut JournalBoundRunningGate,
) -> (&mut VehicleActor, &mut RecoveredGateJournal) {
    (&mut bound.gate.actor, &mut bound.journal)
}
