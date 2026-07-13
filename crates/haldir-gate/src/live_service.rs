//! Single-owner declared-live Gate publication service.
//!
//! This module closes the public service-local ownership boundary around the
//! startup-marked coordinator, one concrete strict publisher, and one output
//! capacity slot. It deliberately does not open a session, own intent ingress,
//! spawn a worker, or provide supervision and reconnect policy.

use core::fmt;
use core::num::NonZeroUsize;

use haldir_contracts::digest::DigestV1;
use haldir_core::time::{MonoInstant, MonotonicClock};
use haldir_evidence::gate_journal::GateJournalMutationError;
use haldir_ncp08::NcpCommandWireProfile;
use haldir_transport_zenoh::{
    FinalCommandPublisher, HARD_MAX_INTENT_BYTES, HaldirKeyError, IntentIngressEvent,
    MAX_HALDIR_ROUTE_BYTES, SecureZenohError,
};

use crate::actor::{DecisionRecord, PublicationError};
use crate::startup::publication_coordinator::{
    CallTransition, CoordinatorFatal, DecisionTransition, DecisionUnavailable,
    DeclaredLiveZenohPublication, DurableCalledPublication, OutputCapacityPool,
    PublicationCoordinator, PublishOnceError, StrictPublisherCallError,
};
use crate::startup::{GateRuntimeProfile, JournalBoundRunningGate};

/// Failure while binding one startup-marked runtime to one owned service publisher handle.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum LiveServiceStartError {
    /// The startup-marked coordinator could not be constructed.
    Coordinator(LiveServiceFatal),
    /// The supplied concrete publisher advertises another realm/session route.
    PublisherRouteMismatch,
}

impl fmt::Display for LiveServiceStartError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Coordinator(error) => {
                write!(formatter, "live coordinator binding failed: {error}")
            }
            Self::PublisherRouteMismatch => formatter.write_str(
                "the concrete publisher route does not match the startup-bound Gate runtime",
            ),
        }
    }
}

impl std::error::Error for LiveServiceStartError {}

/// A refusal before actor, journal, decision, or output-sequence mutation.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum LiveDecisionUnavailable {
    /// The raw candidate intent envelope exceeded the service hard bound.
    IntentEnvelopeTooLarge {
        /// Service profile maximum.
        maximum_bytes: usize,
        /// Supplied event length.
        actual_bytes: usize,
    },
    /// The event's actual-key field exceeded the maximum exact Haldir route length.
    ActualKeyTooLong {
        /// Service profile maximum.
        maximum_bytes: usize,
        /// Supplied route length.
        actual_bytes: usize,
    },
    /// The service's sole output slot was unavailable before clock or actor access.
    OutputCapacityUnavailable,
    /// Recovered Called-or-later history still requires authenticated clearance.
    RestartClearanceRequired {
        /// Monotonic observation recorded for this refusal.
        observed_at: MonoInstant,
        /// Current-policy diagnostic only; reaching it never grants clearance.
        current_policy_diagnostic_not_before: MonoInstant,
    },
    /// The journal could not reserve the complete decision/call/return lifecycle.
    JournalCapacity(GateJournalMutationError),
}

impl From<DecisionUnavailable> for LiveDecisionUnavailable {
    fn from(reason: DecisionUnavailable) -> Self {
        match reason {
            DecisionUnavailable::RestartClearanceRequired {
                observed_at,
                current_policy_diagnostic_not_before,
            } => Self::RestartClearanceRequired {
                observed_at,
                current_policy_diagnostic_not_before,
            },
            DecisionUnavailable::JournalCapacity(error) => Self::JournalCapacity(error),
        }
    }
}

/// A terminal coordinator failure that destroys the service-local capabilities.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum LiveServiceFatal {
    /// Journal mutation or commit classification failed.
    Journal(GateJournalMutationError),
    /// Actor publication state could not safely advance.
    Publication(PublicationError),
    /// The prepared receipt did not bind the required output fields.
    InvalidPreparedReceipt,
    /// The injected monotonic clock regressed.
    ClockRegression,
    /// The conservative restart diagnostic horizon overflowed.
    RestartDiagnosticHorizonOverflow,
    /// The retained startup declaration was not the required live profile.
    RuntimeProfileMismatch {
        /// Required service profile.
        required: GateRuntimeProfile,
        /// Retained startup profile.
        actual: GateRuntimeProfile,
    },
    /// The actor did not retain the required exact NCP wire selection.
    NcpWireProfileMismatch {
        /// Required exact wire profile.
        required: NcpCommandWireProfile,
        /// Actor-selected wire profile.
        actual: NcpCommandWireProfile,
    },
    /// The private startup capability was absent or already consumed.
    DeclaredLiveStartupCapabilityUnavailable,
    /// The final-command route could not be derived from retained runtime identity.
    InvalidFinalCommandRoute(HaldirKeyError),
}

impl From<CoordinatorFatal> for LiveServiceFatal {
    fn from(error: CoordinatorFatal) -> Self {
        match error {
            CoordinatorFatal::Journal(error) => Self::Journal(error),
            CoordinatorFatal::Publication(error) => Self::Publication(error),
            CoordinatorFatal::InvalidPreparedReceipt => Self::InvalidPreparedReceipt,
            CoordinatorFatal::ClockRegression => Self::ClockRegression,
            CoordinatorFatal::RestartDiagnosticHorizonOverflow => {
                Self::RestartDiagnosticHorizonOverflow
            }
            CoordinatorFatal::RuntimeProfileMismatch { required, actual } => {
                Self::RuntimeProfileMismatch { required, actual }
            }
            CoordinatorFatal::NcpWireProfileMismatch { required, actual } => {
                Self::NcpWireProfileMismatch { required, actual }
            }
            CoordinatorFatal::DeclaredLiveStartupCapabilityUnavailable => {
                Self::DeclaredLiveStartupCapabilityUnavailable
            }
            CoordinatorFatal::InvalidFinalCommandRoute(error) => {
                Self::InvalidFinalCommandRoute(error)
            }
        }
    }
}

impl fmt::Display for LiveServiceFatal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Journal(_) => "journal mutation failed",
            Self::Publication(_) => "publication state transition failed",
            Self::InvalidPreparedReceipt => "prepared receipt binding is invalid",
            Self::ClockRegression => "monotonic clock regressed",
            Self::RestartDiagnosticHorizonOverflow => "restart diagnostic horizon overflowed",
            Self::RuntimeProfileMismatch { .. } => "runtime profile mismatch",
            Self::NcpWireProfileMismatch { .. } => "NCP wire profile mismatch",
            Self::DeclaredLiveStartupCapabilityUnavailable => {
                "declared-live startup capability is unavailable"
            }
            Self::InvalidFinalCommandRoute(_) => "final-command route is invalid",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for LiveServiceFatal {}

/// Concrete strict-publisher failure observed after locally journaling Called.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LivePublisherError {
    /// The publisher route did not match the service-bound runtime.
    PublisherRouteMismatch,
    /// The local strict transport call rejected or returned an error.
    Transport(SecureZenohError),
}

impl From<StrictPublisherCallError> for LivePublisherError {
    fn from(error: StrictPublisherCallError) -> Self {
        match error {
            StrictPublisherCallError::PublisherRouteMismatch => Self::PublisherRouteMismatch,
            StrictPublisherCallError::Publisher(error) => Self::Transport(error),
        }
    }
}

impl fmt::Display for LivePublisherError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PublisherRouteMismatch => formatter.write_str("publisher route mismatch"),
            Self::Transport(error) => write!(formatter, "strict publisher failed: {error}"),
        }
    }
}

impl std::error::Error for LivePublisherError {}

/// Safe continuing outcome for one consumed ingress event.
#[derive(Debug)]
#[non_exhaustive]
pub enum LiveServiceOutcome {
    /// A DENY, ERROR, or cached terminal decision produced no output.
    NoPublication(Box<DecisionRecord>),
    /// Post-decision validation rejected the prepared output before Called.
    RejectedBeforeCall {
        /// Signed decision whose prepared output was rejected.
        decision: Box<DecisionRecord>,
        /// Exact actor-side rejection.
        reason: PublicationError,
    },
    /// The local strict publisher returned `Ok` and the linked terminal record was confirmed.
    PublishReturnedOk {
        /// Signed ALLOW decision for the published frame.
        decision: Box<DecisionRecord>,
        /// Digest of the locally confirmed `PUBLISH_RETURNED_OK` envelope.
        terminal_envelope_digest: DigestV1,
    },
}

/// Terminal service outcome. No coordinator, publisher, or output capability is returned.
#[derive(Debug)]
#[non_exhaustive]
pub enum LiveServiceStop {
    /// A coordinator transition failed and requires restart/recovery.
    Fatal(LiveServiceFatal),
    /// A route, preflight, or transport error was linked to a confirmed terminal record.
    PublisherReturned {
        /// Concrete route or transport failure.
        error: LivePublisherError,
        /// Decision whose publication attempt terminated.
        decision: Box<DecisionRecord>,
        /// Digest of the locally confirmed `PUBLISH_RETURNED_ERROR` envelope.
        terminal_envelope_digest: DigestV1,
    },
    /// Terminal recording or the immediately linked actor transition failed or became ambiguous.
    TerminalBoundaryFailed {
        /// Original route, preflight, or publisher error, if one was observed.
        publisher_error: Option<LivePublisherError>,
        /// Journal/actor failure at the terminal boundary.
        source: LiveServiceFatal,
    },
}

/// Result of presenting one raw intent event to the service hard-boundary.
#[must_use = "the returned service is required to process another event through this service instance"]
pub enum LiveServiceTransition<C> {
    /// The service may process another event only through the returned owner.
    Continue {
        /// Same single-owner service after a safe continuation path.
        service: DeclaredLiveGateService<C>,
        /// Decision/publication outcome.
        outcome: LiveServiceOutcome,
    },
    /// No actor/journal/sequence mutation occurred, so the exact event is returned for policy.
    Unavailable {
        /// Same single-owner service.
        service: DeclaredLiveGateService<C>,
        /// Unconsumed ingress event.
        event: IntentIngressEvent,
        /// Input-bound, capacity, or restart refusal.
        reason: LiveDecisionUnavailable,
    },
    /// The service is deliberately unavailable until restart/recovery.
    Stopped(LiveServiceStop),
}

struct LiveServiceCore<C, P> {
    coordinator: PublicationCoordinator<C, DeclaredLiveZenohPublication>,
    publisher: P,
    output_pool: OutputCapacityPool,
}

/// Single-owner process-local kernel for one declared-live Gate runtime.
///
/// The service is not cloneable and exposes no coordinator, publisher, frame,
/// pool, permit, or decomposition accessor. Calling [`Self::process_one`] consumes
/// it; only safe continuation paths return another service value. This is not a
/// session owner, ingress loop, spawned worker, supervisor, or delivery proof. Its
/// publisher retains a shared Zenoh session handle that this service neither opens
/// nor exclusively owns; other holders can create publishers or close that session.
#[must_use = "dropping the service stops the bound Gate runtime and drops its owned publisher handle"]
pub struct DeclaredLiveGateService<C> {
    core: LiveServiceCore<C, FinalCommandPublisher>,
}

impl<C: MonotonicClock> DeclaredLiveGateService<C> {
    /// Bind a startup-marked live runtime to exactly one route-matched publisher
    /// and an internally created one-slot output-capacity pool.
    ///
    /// # Errors
    /// Returns when the live coordinator capability/profile checks fail or the
    /// publisher advertises another exact realm/session route. Failure consumes
    /// and drops every supplied owned value/handle.
    ///
    /// Route equality does not authenticate the session's credential identity or
    /// establish exclusive credential/session custody.
    pub fn bind(
        bound: JournalBoundRunningGate,
        clock: C,
        publisher: FinalCommandPublisher,
    ) -> Result<Self, LiveServiceStartError> {
        let publisher_route = publisher.route().to_owned();
        bind_core(bound, clock, publisher, &publisher_route).map(|core| Self { core })
    }

    /// Consume one caller-supplied raw intent event through service hard bounds, decision,
    /// Called, and at most one concrete strict publisher invocation.
    ///
    /// Dropping the returned future before its first poll drops the service without
    /// creating Called. Cancellation after Called drops all service capabilities;
    /// restart recovery must classify the locally confirmed Called tail. Local
    /// publisher `Ok` is not delivery, receiver acceptance, application, or an ACK.
    pub async fn process_one(self, event: IntentIngressEvent) -> LiveServiceTransition<C> {
        match prepare_one(self.core, event) {
            PreparedServiceStep::Continue { core, outcome } => LiveServiceTransition::Continue {
                service: Self { core },
                outcome,
            },
            PreparedServiceStep::Unavailable {
                core,
                event,
                reason,
            } => LiveServiceTransition::Unavailable {
                service: Self { core },
                event,
                reason,
            },
            PreparedServiceStep::Stopped(error) => {
                LiveServiceTransition::Stopped(LiveServiceStop::Fatal(error))
            }
            PreparedServiceStep::Called {
                called,
                publisher,
                output_pool,
            } => match called.publish_once(publisher).await {
                Ok((journaled, publisher)) => {
                    let (coordinator, decision, terminal_envelope_digest, output_permit) =
                        journaled.into_parts();
                    drop(output_permit);
                    LiveServiceTransition::Continue {
                        service: Self {
                            core: LiveServiceCore {
                                coordinator,
                                publisher,
                                output_pool,
                            },
                        },
                        outcome: LiveServiceOutcome::PublishReturnedOk {
                            decision: Box::new(decision),
                            terminal_envelope_digest,
                        },
                    }
                }
                Err(PublishOnceError::PublisherReturned { source, journaled }) => {
                    let (decision, terminal_envelope_digest, output_permit) =
                        journaled.into_parts();
                    drop(output_permit);
                    LiveServiceTransition::Stopped(LiveServiceStop::PublisherReturned {
                        error: source.into(),
                        decision: Box::new(decision),
                        terminal_envelope_digest,
                    })
                }
                Err(PublishOnceError::TerminalBoundaryFailed {
                    publisher_error,
                    source,
                }) => LiveServiceTransition::Stopped(LiveServiceStop::TerminalBoundaryFailed {
                    publisher_error: publisher_error.map(Into::into),
                    source: source.into(),
                }),
            },
        }
    }
}

fn bind_core<C: MonotonicClock, P>(
    bound: JournalBoundRunningGate,
    clock: C,
    publisher: P,
    publisher_route: &str,
) -> Result<LiveServiceCore<C, P>, LiveServiceStartError> {
    let coordinator = PublicationCoordinator::new_declared_live(bound, clock)
        .map_err(|error| LiveServiceStartError::Coordinator(error.into()))?;
    if !coordinator.publisher_route_matches(publisher_route) {
        return Err(LiveServiceStartError::PublisherRouteMismatch);
    }
    Ok(LiveServiceCore {
        coordinator,
        publisher,
        output_pool: OutputCapacityPool::new(NonZeroUsize::MIN),
    })
}

enum PreparedServiceStep<C, P> {
    Continue {
        core: LiveServiceCore<C, P>,
        outcome: LiveServiceOutcome,
    },
    Unavailable {
        core: LiveServiceCore<C, P>,
        event: IntentIngressEvent,
        reason: LiveDecisionUnavailable,
    },
    Called {
        called: Box<DurableCalledPublication<C, DeclaredLiveZenohPublication>>,
        publisher: P,
        output_pool: OutputCapacityPool,
    },
    Stopped(LiveServiceFatal),
}

fn prepare_one<C: MonotonicClock, P>(
    core: LiveServiceCore<C, P>,
    event: IntentIngressEvent,
) -> PreparedServiceStep<C, P> {
    let LiveServiceCore {
        coordinator,
        publisher,
        output_pool,
    } = core;
    if event.bytes.len() > HARD_MAX_INTENT_BYTES {
        let actual_bytes = event.bytes.len();
        return PreparedServiceStep::Unavailable {
            core: LiveServiceCore {
                coordinator,
                publisher,
                output_pool,
            },
            event,
            reason: LiveDecisionUnavailable::IntentEnvelopeTooLarge {
                maximum_bytes: HARD_MAX_INTENT_BYTES,
                actual_bytes,
            },
        };
    }
    if event.actual_key.len() > MAX_HALDIR_ROUTE_BYTES {
        let actual_bytes = event.actual_key.len();
        return PreparedServiceStep::Unavailable {
            core: LiveServiceCore {
                coordinator,
                publisher,
                output_pool,
            },
            event,
            reason: LiveDecisionUnavailable::ActualKeyTooLong {
                maximum_bytes: MAX_HALDIR_ROUTE_BYTES,
                actual_bytes,
            },
        };
    }
    let Some(output_permit) = output_pool.try_reserve() else {
        return PreparedServiceStep::Unavailable {
            core: LiveServiceCore {
                coordinator,
                publisher,
                output_pool,
            },
            event,
            reason: LiveDecisionUnavailable::OutputCapacityUnavailable,
        };
    };

    let decision = match coordinator.decide(output_permit, &event.bytes, &event.actual_key) {
        Ok(decision) => decision,
        Err(error) => match error.into_unavailable() {
            Ok((coordinator, output_permit, reason)) => {
                drop(output_permit);
                return PreparedServiceStep::Unavailable {
                    core: LiveServiceCore {
                        coordinator,
                        publisher,
                        output_pool,
                    },
                    event,
                    reason: reason.into(),
                };
            }
            Err(error) => return PreparedServiceStep::Stopped(error.into()),
        },
    };

    match decision {
        DecisionTransition::NoPublication(ready) => {
            let (coordinator, decision, output_permit) = ready.into_parts();
            drop(output_permit);
            PreparedServiceStep::Continue {
                core: LiveServiceCore {
                    coordinator,
                    publisher,
                    output_pool,
                },
                outcome: LiveServiceOutcome::NoPublication(Box::new(decision)),
            }
        }
        DecisionTransition::Prepared(prepared) => match prepared.enter_called_boundary() {
            Ok(CallTransition::Called(called)) => PreparedServiceStep::Called {
                called,
                publisher,
                output_pool,
            },
            Ok(CallTransition::Rejected { ready, reason }) => {
                let (coordinator, decision, output_permit) = ready.into_parts();
                drop(output_permit);
                PreparedServiceStep::Continue {
                    core: LiveServiceCore {
                        coordinator,
                        publisher,
                        output_pool,
                    },
                    outcome: LiveServiceOutcome::RejectedBeforeCall {
                        decision: Box::new(decision),
                        reason,
                    },
                }
            }
            Err(error) => PreparedServiceStep::Stopped(error.into()),
        },
    }
}

#[cfg(test)]
pub(crate) struct TestDeclaredLiveGateService<C, P> {
    core: LiveServiceCore<C, P>,
}

#[cfg(test)]
#[allow(
    dead_code,
    reason = "the test service mirrors production endpoints whose fault matrix is covered below the facade"
)]
pub(crate) enum TestLiveServiceTransition<C, P, E> {
    Continue {
        service: TestDeclaredLiveGateService<C, P>,
        outcome: LiveServiceOutcome,
    },
    Unavailable {
        service: TestDeclaredLiveGateService<C, P>,
        event: IntentIngressEvent,
        reason: LiveDecisionUnavailable,
    },
    Fatal(LiveServiceFatal),
    PublisherReturned {
        error: E,
        decision: Box<DecisionRecord>,
        terminal_envelope_digest: DigestV1,
    },
    TerminalBoundaryFailed {
        publisher_error: Option<E>,
        source: LiveServiceFatal,
    },
}

#[cfg(test)]
impl<C: MonotonicClock, P> TestDeclaredLiveGateService<C, P> {
    pub(crate) fn new(
        coordinator: PublicationCoordinator<C, DeclaredLiveZenohPublication>,
        publisher: P,
    ) -> Self {
        Self {
            core: LiveServiceCore {
                coordinator,
                publisher,
                output_pool: OutputCapacityPool::new(NonZeroUsize::MIN),
            },
        }
    }

    pub(crate) fn bind(
        bound: JournalBoundRunningGate,
        clock: C,
        publisher: P,
        publisher_route: &str,
    ) -> Result<Self, LiveServiceStartError> {
        bind_core(bound, clock, publisher, publisher_route).map(|core| Self { core })
    }

    pub(crate) fn available_output_slots(&self) -> usize {
        self.core.output_pool.available()
    }

    pub(crate) fn output_pool_observer(&self) -> OutputCapacityPool {
        self.core.output_pool.clone()
    }

    pub(crate) fn reserve_output_slot_for_test(
        &self,
    ) -> Option<crate::startup::publication_coordinator::OutputCapacityPermit> {
        self.core.output_pool.try_reserve()
    }

    pub(crate) async fn process_one_with_test_future<E, F, Fut>(
        self,
        event: IntentIngressEvent,
        invoke: F,
    ) -> TestLiveServiceTransition<C, P, E>
    where
        F: FnOnce(&haldir_ncp08::ExactNcpCommandFrame) -> Fut,
        Fut: core::future::Future<Output = Result<(), E>>,
    {
        self.process_one_with_test_fault(event, None, invoke).await
    }

    pub(crate) async fn process_one_with_test_fault<E, F, Fut>(
        self,
        event: IntentIngressEvent,
        terminal_append_fault: Option<
            crate::startup::publication_coordinator::TestTerminalAppendFault,
        >,
        invoke: F,
    ) -> TestLiveServiceTransition<C, P, E>
    where
        F: FnOnce(&haldir_ncp08::ExactNcpCommandFrame) -> Fut,
        Fut: core::future::Future<Output = Result<(), E>>,
    {
        match prepare_one(self.core, event) {
            PreparedServiceStep::Continue { core, outcome } => {
                TestLiveServiceTransition::Continue {
                    service: Self { core },
                    outcome,
                }
            }
            PreparedServiceStep::Unavailable {
                core,
                event,
                reason,
            } => TestLiveServiceTransition::Unavailable {
                service: Self { core },
                event,
                reason,
            },
            PreparedServiceStep::Stopped(error) => TestLiveServiceTransition::Fatal(error),
            PreparedServiceStep::Called {
                called,
                publisher,
                output_pool,
            } => {
                let called = match terminal_append_fault {
                    Some(fault) => Box::new((*called).with_test_terminal_append_fault(fault)),
                    None => called,
                };
                match called
                    .publish_once_with_test_future(publisher, invoke)
                    .await
                {
                    Ok((journaled, publisher)) => {
                        let (coordinator, decision, terminal_envelope_digest, output_permit) =
                            journaled.into_parts();
                        drop(output_permit);
                        TestLiveServiceTransition::Continue {
                            service: Self {
                                core: LiveServiceCore {
                                    coordinator,
                                    publisher,
                                    output_pool,
                                },
                            },
                            outcome: LiveServiceOutcome::PublishReturnedOk {
                                decision: Box::new(decision),
                                terminal_envelope_digest,
                            },
                        }
                    }
                    Err(PublishOnceError::PublisherReturned { source, journaled }) => {
                        let (decision, terminal_envelope_digest, output_permit) =
                            journaled.into_parts();
                        drop(output_permit);
                        TestLiveServiceTransition::PublisherReturned {
                            error: source,
                            decision: Box::new(decision),
                            terminal_envelope_digest,
                        }
                    }
                    Err(PublishOnceError::TerminalBoundaryFailed {
                        publisher_error,
                        source,
                    }) => TestLiveServiceTransition::TerminalBoundaryFailed {
                        publisher_error,
                        source: source.into(),
                    },
                }
            }
        }
    }
}
