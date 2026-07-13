//! Internal locally synced publication lifecycle coordination.
//!
//! The state types consume one another so no usable bound runtime can escape an
//! ambiguous journal append, a post-sync validation failure, or a dropped
//! called typestate. The called state owns the exact output bytes, and the optional
//! live binding lends them only to the concrete strict publisher. "Durable" state
//! names below mean a local append whose `sync_data` returned successfully; they do
//! not claim power-loss survival, delivery, acceptance, or application.

use core::num::{NonZeroU32, NonZeroUsize};

use haldir_contracts::digest::{DigestDomain, DigestV1};
use haldir_contracts::ids::{DecisionId, GateBootId, GateId, VehicleId};
use haldir_contracts::publication::PublicationStageEventV1;
use haldir_contracts::receipt::{DecisionOutcomeV1, PublishStageV1};
use haldir_contracts::session::{NcpSessionIdentityV1, NcpStreamPositionV1};
use haldir_core::time::{MonoInstant, MonotonicClock};
use haldir_evidence::gate_journal::{
    GateJournalMutationError, GateJournalReservation, RecoveredGateJournal,
};
use haldir_evidence::publication::PublicationTraceState;
use haldir_ncp08::ExactNcpCommandFrame;
#[cfg(feature = "live-zenoh")]
use haldir_transport_zenoh::{FinalCommandPublisher, HaldirKeyError, HaldirKeys, SecureZenohError};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::actor::{
    DecisionRecord, PreparedPublication, PublicationError, PublishCalledPublication,
    ValidatedPublicationCall, VehicleActor,
};
use crate::startup::JournalBoundRunningGate;

const LIFECYCLE_RECORD_RESERVATION: usize = 3;

struct OutputCapacityState {
    available: AtomicUsize,
    capacity: usize,
}

/// Cloneable bounded-pool handle that mints move-only slot permits for a possible
/// future publisher worker. The coordinator does not authenticate one canonical pool.
#[derive(Clone)]
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
    InvalidFinalCommandRoute(HaldirKeyError),
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
pub(crate) enum DecideError<C> {
    Unavailable {
        coordinator: PublicationCoordinator<C>,
        output_permit: OutputCapacityPermit,
        reason: DecisionUnavailable,
    },
    Fatal(CoordinatorFatal),
}

impl<C> DecideError<C> {
    pub(crate) fn into_unavailable(
        self,
    ) -> Result<
        (
            PublicationCoordinator<C>,
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

struct CoordinatorCore<C> {
    bound: JournalBoundRunningGate,
    clock: C,
    last_observed: MonoInstant,
    restart_clearance_diagnostic_not_before: Option<MonoInstant>,
    #[cfg(feature = "live-zenoh")]
    expected_final_command_route: String,
}

impl<C: MonotonicClock> CoordinatorCore<C> {
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
pub(crate) struct PublicationCoordinator<C> {
    core: Box<CoordinatorCore<C>>,
}

/// A completed or cancelled decision that returns a ready coordinator and the
/// still-reserved output-capacity permit for explicit reuse or release.
pub(crate) struct ReadyDecision<C> {
    coordinator: PublicationCoordinator<C>,
    decision: DecisionRecord,
    output_permit: OutputCapacityPermit,
}

impl<C> ReadyDecision<C> {
    pub(crate) fn decision(&self) -> &DecisionRecord {
        &self.decision
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        PublicationCoordinator<C>,
        DecisionRecord,
        OutputCapacityPermit,
    ) {
        (self.coordinator, self.decision, self.output_permit)
    }
}

/// Result of locally sync-confirming one new decision receipt.
pub(crate) enum DecisionTransition<C> {
    NoPublication(Box<ReadyDecision<C>>),
    Prepared(Box<DurablePreparedPublication<C>>),
}

/// A prepared output whose exact receipt append is locally sync-confirmed but
/// whose bytes remain inaccessible. The retained permit and two journal units
/// cover call + return.
#[must_use = "a locally synced prepared publication must be cancelled or advanced"]
pub(crate) struct DurablePreparedPublication<C> {
    core: Box<CoordinatorCore<C>>,
    decision: DecisionRecord,
    prepared: Box<PreparedPublication>,
    reservation: GateJournalReservation,
    binding: PublicationBinding,
    output_permit: OutputCapacityPermit,
}

/// Result of attempting the pre-exposure Called boundary.
pub(crate) enum CallTransition<C> {
    Called(Box<DurableCalledPublication<C>>),
    Rejected {
        ready: Box<ReadyDecision<C>>,
        reason: PublicationError,
    },
}

/// A locally sync-confirmed Called output. Production code can lend its bytes only
/// to the feature-gated concrete publisher binding. Dropping it drops the whole
/// bound runtime; it cannot return to Ready silently.
#[must_use = "dropping a called publication abandons the bound runtime for restart recovery"]
pub(crate) struct DurableCalledPublication<C> {
    core: Box<CoordinatorCore<C>>,
    decision: DecisionRecord,
    called: Box<PublishCalledPublication>,
    reservation: GateJournalReservation,
    binding: PublicationBinding,
    called_envelope_digest: DigestV1,
    output_permit: OutputCapacityPermit,
}

/// A locally sync-confirmed successful local publisher return.
pub(crate) struct JournaledReturnedOk<C> {
    coordinator: PublicationCoordinator<C>,
    decision: DecisionRecord,
    terminal_envelope_digest: DigestV1,
    output_permit: OutputCapacityPermit,
}

impl<C> JournaledReturnedOk<C> {
    pub(crate) fn into_parts(
        self,
    ) -> (
        PublicationCoordinator<C>,
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
/// publisher error has a terminal record when possible; if terminal recording
/// itself fails, the original publisher result remains available for diagnosis.
#[cfg(any(test, feature = "live-zenoh"))]
pub(crate) enum PublishOnceError<E> {
    PublisherReturned {
        source: E,
        journaled: Box<JournaledReturnedError>,
    },
    TerminalRecordFailed {
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

impl<C: MonotonicClock> PublicationCoordinator<C> {
    pub(crate) fn new(bound: JournalBoundRunningGate, clock: C) -> Result<Self, CoordinatorFatal> {
        let startup_now = clock.now();
        #[cfg(feature = "live-zenoh")]
        let expected_final_command_route = HaldirKeys::try_new(
            bound.actor().realm().as_str(),
            bound.actor().ncp_session().session_id.as_str(),
        )
        .map_err(CoordinatorFatal::InvalidFinalCommandRoute)?
        .final_command()
        .to_owned();
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
                last_observed: startup_now,
                restart_clearance_diagnostic_not_before,
                #[cfg(feature = "live-zenoh")]
                expected_final_command_route,
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
    ) -> Result<DecisionTransition<C>, DecideError<C>> {
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

impl<C: MonotonicClock> DurablePreparedPublication<C> {
    pub(crate) fn decision(&self) -> &DecisionRecord {
        &self.decision
    }

    pub(crate) fn publication_trace_state(&self) -> Option<PublicationTraceState> {
        self.core
            .bound
            .recovered_publication()
            .state(self.binding.decision_gate_boot_id, self.binding.decision_id)
    }

    pub(crate) fn cancel(self) -> Result<ReadyDecision<C>, CoordinatorFatal> {
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

    pub(crate) fn enter_called_boundary(self) -> Result<CallTransition<C>, CoordinatorFatal> {
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
        })))
    }
}

impl<C: MonotonicClock> DurableCalledPublication<C> {
    const fn frame(&self) -> &ExactNcpCommandFrame {
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

    /// Invoke a route-matched concrete strict publisher once for this consumed Called state.
    ///
    /// A publisher bound to another exact realm/session route is rejected and
    /// terminally recorded before frame access or invocation. A matched publisher
    /// is returned for a later distinct output only after its local call returned
    /// `Ok` and the linked terminal record was sync-confirmed. A publisher error
    /// or terminal-record failure drops the publisher capability.
    /// Cancellation while awaiting drops this Called state without inventing a
    /// returned-error record; restart recovery must classify the synced Called tail.
    /// Local `Ok` is not delivery, receiver acceptance, application, or an ACK.
    #[cfg(feature = "live-zenoh")]
    pub(crate) async fn publish_once(
        self,
        publisher: FinalCommandPublisher,
    ) -> Result<
        (JournaledReturnedOk<C>, FinalCommandPublisher),
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

    #[cfg(feature = "live-zenoh")]
    fn publisher_route_matches(&self, publisher_route: &str) -> bool {
        publisher_route == self.core.expected_final_command_route
    }

    #[cfg(all(test, feature = "live-zenoh"))]
    pub(crate) fn expected_final_command_route(&self) -> &str {
        &self.core.expected_final_command_route
    }

    /// Exercise route rejection without constructing a live Zenoh session.
    #[cfg(all(test, feature = "live-zenoh"))]
    pub(crate) async fn publish_once_with_test_route<P, F, Fut>(
        self,
        publisher: P,
        publisher_route: &str,
        invoke: F,
    ) -> Result<(JournaledReturnedOk<C>, P), PublishOnceError<StrictPublisherCallError>>
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
        let publisher_result = invoke(self.frame())
            .await
            .map_err(StrictPublisherCallError::Publisher);
        self.finish_publish_once(publisher, publisher_result)
    }

    /// Exercise the same ownership and terminal-ordering path without a live session.
    #[cfg(test)]
    pub(crate) async fn publish_once_with_test_future<P, E, F, Fut>(
        self,
        publisher: P,
        invoke: F,
    ) -> Result<(JournaledReturnedOk<C>, P), PublishOnceError<E>>
    where
        F: FnOnce(&ExactNcpCommandFrame) -> Fut,
        Fut: core::future::Future<Output = Result<(), E>>,
    {
        let publisher_result = invoke(self.frame()).await;
        self.finish_publish_once(publisher, publisher_result)
    }

    #[cfg(any(test, feature = "live-zenoh"))]
    fn finish_publish_once<P, E>(
        self,
        publisher: P,
        publisher_result: Result<(), E>,
    ) -> Result<(JournaledReturnedOk<C>, P), PublishOnceError<E>> {
        match publisher_result {
            Ok(()) => match self.record_returned_ok() {
                Ok(journaled) => Ok((journaled, publisher)),
                Err(source) => {
                    drop(publisher);
                    Err(PublishOnceError::TerminalRecordFailed {
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
                    Err(PublishOnceError::TerminalRecordFailed {
                        publisher_error: Some(error),
                        source,
                    })
                }
            },
        }
    }

    #[cfg(any(test, feature = "live-zenoh"))]
    fn record_returned_ok(self) -> Result<JournaledReturnedOk<C>, CoordinatorFatal> {
        let Self {
            mut core,
            decision,
            called,
            mut reservation,
            binding,
            called_envelope_digest,
            output_permit,
        } = self;
        let returned_at = core.sample_now()?;
        let event = binding.event(
            PublishStageV1::PublishReturnedOk,
            called_envelope_digest,
            returned_at,
        );
        let terminal_envelope_digest =
            sign_and_append_stage(core.as_mut(), &mut reservation, &event, returned_at)?;
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
        } = self;
        let returned_at = core.sample_now()?;
        let event = binding.event(
            PublishStageV1::PublishReturnedError,
            called_envelope_digest,
            returned_at,
        );
        let terminal_envelope_digest =
            sign_and_append_stage(core.as_mut(), &mut reservation, &event, returned_at)?;
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

fn release_reservation<C>(
    core: &mut CoordinatorCore<C>,
    reservation: &mut GateJournalReservation,
) -> Result<(), CoordinatorFatal> {
    let (_, journal) = live_parts_mut(&mut core.bound);
    journal
        .release_reservation(reservation)
        .map_err(CoordinatorFatal::Journal)
}

fn append_verified<C>(
    core: &mut CoordinatorCore<C>,
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

fn sign_and_append_stage<C>(
    core: &mut CoordinatorCore<C>,
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

fn commit_called<C>(
    core: &mut CoordinatorCore<C>,
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
