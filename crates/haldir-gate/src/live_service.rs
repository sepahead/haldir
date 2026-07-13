//! Single-owner declared-live Gate publication service.
//!
//! This module closes the public service-local ownership boundary around the
//! startup-marked coordinator, one locally primed canonical intent binding, one
//! concrete strict publisher, and one output-capacity slot. Activation performs
//! no network activity. The outer Zenoh aggregate can additionally retain one
//! caller-opened session wrapper and an internally declared ingress, plus a
//! cloneable stop-only request handle observed by its consuming shutdown-aware
//! method at an idle boundary.
//! This module deliberately does not load credentials, spawn a worker, or provide
//! timeout, signal, supervision, and reconnect policy.

use core::fmt;
use core::future::{Future, poll_fn};
use core::num::NonZeroUsize;
use core::task::Poll;

use haldir_contracts::cbor::Limits;
use haldir_contracts::digest::DigestV1;
use haldir_contracts::ids::{ChallengeNonce, ControllerId};
use haldir_contracts::receipt::DecisionReasonCodeV1;
use haldir_core::snapshot::TrustedStateSnapshotV1;
use haldir_core::time::{MonoInstant, MonotonicClock};
use haldir_evidence::gate_journal::GateJournalMutationError;
use haldir_ncp08::NcpCommandWireProfile;
use haldir_transport_zenoh::{
    FinalCommandPublisher, HARD_MAX_INTENT_BYTES, HaldirKeyError, HaldirKeys, IngressCounters,
    IngressCountersSnapshot, IngressLimits, IntentIngress, IntentIngressEvent,
    MAX_HALDIR_ROUTE_BYTES, SecureZenohError, SecureZenohSession,
};
use tokio::sync::watch;

use crate::actor::{DecisionRecord, GateError, PublicationError};
use crate::startup::publication_coordinator::{
    ActiveIntentBinding, CallTransition, CoordinatorFatal, DecisionTransition, DecisionUnavailable,
    DeclaredLiveZenohPublication, DurableCalledPublication, LiveIntentActivationFailure,
    OutputCapacityPool, PublicationCoordinator, PublishOnceError, StrictPublisherCallError,
};
use crate::startup::{GateRuntimeProfile, JournalBoundRunningGate};

/// Failure while validating one startup-marked runtime as a declared-live kernel.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum LiveKernelStartError {
    /// The startup-marked coordinator could not be constructed.
    Coordinator(LiveServiceFatal),
}

impl fmt::Display for LiveKernelStartError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Coordinator(error) => {
                write!(formatter, "declared-live kernel startup failed: {error}")
            }
        }
    }
}

impl std::error::Error for LiveKernelStartError {}

/// Failure while consuming a route-bound Gate into one publisher-owning service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LiveServiceBindError {
    /// The supplied concrete publisher advertises another realm/session route.
    PublisherRouteMismatch,
}

impl fmt::Display for LiveServiceBindError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PublisherRouteMismatch => formatter.write_str(
                "the concrete publisher route does not match the startup-bound Gate runtime",
            ),
        }
    }
}

impl std::error::Error for LiveServiceBindError {}

/// Primary failure while binding the route capability to one owned Zenoh I/O aggregate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LiveZenohServiceBindFailure {
    /// Re-deriving the accepted controller's exact intent route failed.
    IntentRoute(HaldirKeyError),
    /// The re-derived route differed from the accepted lease binding.
    IntentRouteMismatch,
    /// The internally derived final-command publisher did not match the runtime.
    Publisher(LiveServiceBindError),
    /// Declaring the exact bounded intent ingress failed.
    Ingress(SecureZenohError),
}

impl fmt::Display for LiveZenohServiceBindFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IntentRoute(error) => {
                write!(formatter, "intent-route derivation failed: {error}")
            }
            Self::IntentRouteMismatch => {
                formatter.write_str("accepted intent route failed its binding cross-check")
            }
            Self::Publisher(error) => write!(formatter, "publisher binding failed: {error}"),
            Self::Ingress(error) => write!(formatter, "intent-ingress declaration failed: {error}"),
        }
    }
}

impl std::error::Error for LiveZenohServiceBindFailure {}

/// Fail-stop Zenoh I/O binding error, including attempted session-close status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LiveZenohServiceBindError {
    failure: LiveZenohServiceBindFailure,
    session_close_error: Option<SecureZenohError>,
}

impl LiveZenohServiceBindError {
    /// Primary binding failure.
    #[must_use]
    pub const fn failure(&self) -> LiveZenohServiceBindFailure {
        self.failure
    }

    /// Explicit close failure after the primary binding failure, if any.
    #[must_use]
    pub const fn session_close_error(&self) -> Option<SecureZenohError> {
        self.session_close_error
    }
}

impl fmt::Display for LiveZenohServiceBindError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "Zenoh Gate service binding failed: {}",
            self.failure
        )?;
        if let Some(error) = self.session_close_error {
            write!(formatter, "; explicit session cleanup also failed: {error}")?;
        }
        Ok(())
    }
}

impl std::error::Error for LiveZenohServiceBindError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.failure)
    }
}

/// Hard maximum for one caller-supplied signed mission-lease envelope during
/// declared-live local activation.
pub const MAX_LIVE_LEASE_ENVELOPE_BYTES: usize = Limits::LARGE.max_total_bytes;

/// Invalid bounded input for one local declared-live activation attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LiveIntentActivationInputError {
    /// The signed lease envelope exceeded the large-contract decoder profile.
    LeaseEnvelopeTooLarge {
        /// Activation profile maximum.
        maximum_bytes: usize,
        /// Supplied envelope length.
        actual_bytes: usize,
    },
}

impl fmt::Display for LiveIntentActivationInputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LeaseEnvelopeTooLarge {
                maximum_bytes,
                actual_bytes,
            } => write!(
                formatter,
                "lease envelope is {actual_bytes} bytes; maximum is {maximum_bytes}"
            ),
        }
    }
}

impl std::error::Error for LiveIntentActivationInputError {}

/// Bounded caller-supplied inputs for one static local activation attempt.
///
/// This is not an authenticated control-plane message. The trusted-state value,
/// challenge nonce, and lease delivery are supplied by the embedding caller.
/// Construction proves only the lease-envelope size bound.
pub struct LiveIntentActivationInput {
    trusted_state: TrustedStateSnapshotV1,
    challenge_nonce: ChallengeNonce,
    signed_lease_envelope: Vec<u8>,
}

impl LiveIntentActivationInput {
    /// Construct one bounded static activation input.
    ///
    /// # Errors
    /// Returns when the signed lease envelope exceeds the 64-KiB large-contract
    /// decoder profile. State, challenge, signature, authority, and route checks
    /// occur only when a declared-live kernel consumes this value.
    pub fn new(
        trusted_state: TrustedStateSnapshotV1,
        challenge_nonce: ChallengeNonce,
        signed_lease_envelope: Vec<u8>,
    ) -> Result<Self, LiveIntentActivationInputError> {
        if signed_lease_envelope.len() > MAX_LIVE_LEASE_ENVELOPE_BYTES {
            return Err(LiveIntentActivationInputError::LeaseEnvelopeTooLarge {
                maximum_bytes: MAX_LIVE_LEASE_ENVELOPE_BYTES,
                actual_bytes: signed_lease_envelope.len(),
            });
        }
        Ok(Self {
            trusted_state,
            challenge_nonce,
            signed_lease_envelope,
        })
    }
}

/// Fail-stop declared-live activation failure. No kernel/runtime owner is returned.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum LiveIntentActivationError {
    /// The activation clock failed after kernel startup.
    Coordinator(LiveServiceFatal),
    /// The caller-supplied initial trusted-state snapshot was rejected.
    TrustedState(DecisionReasonCodeV1),
    /// The nonce was duplicate, expired, or outside the bounded challenge table.
    ChallengeRejected,
    /// The signed lease selected a route other than the canonical realm/session/controller route.
    IntentRouteMismatch,
    /// Signed lease verification, admission, scope, challenge, or term acceptance failed.
    Lease(GateError),
    /// Lease activation completed without a retained active controller binding.
    ActiveBindingUnavailable,
}

impl fmt::Display for LiveIntentActivationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Coordinator(_) => "declared-live coordinator activation failed",
            Self::TrustedState(_) => "initial trusted state was rejected",
            Self::ChallengeRejected => "challenge registration was rejected",
            Self::IntentRouteMismatch => "lease intent route is not canonical for this runtime",
            Self::Lease(_) => "signed mission lease was rejected",
            Self::ActiveBindingUnavailable => "active intent binding is unavailable",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for LiveIntentActivationError {}

impl From<LiveIntentActivationFailure> for LiveIntentActivationError {
    fn from(error: LiveIntentActivationFailure) -> Self {
        match error {
            LiveIntentActivationFailure::Fatal(error) => Self::Coordinator(error.into()),
            LiveIntentActivationFailure::TrustedState(reason) => Self::TrustedState(reason),
            LiveIntentActivationFailure::ChallengeRejected => Self::ChallengeRejected,
            LiveIntentActivationFailure::IntentRouteMismatch => Self::IntentRouteMismatch,
            LiveIntentActivationFailure::Lease(error) => Self::Lease(error),
            LiveIntentActivationFailure::ActiveBindingUnavailable => Self::ActiveBindingUnavailable,
        }
    }
}

/// Validated declared-live kernel before caller-supplied local authority priming.
///
/// It is non-cloneable, contains the sole startup capability descendant, and has
/// no actor/coordinator decomposition API. It performs no network activity.
///
/// ```compile_fail
/// fn requires_clone<T: Clone>() {}
/// requires_clone::<haldir_gate::DeclaredLiveGateKernel<()>>();
/// ```
#[must_use = "dropping the kernel stops the bound Gate runtime"]
pub struct DeclaredLiveGateKernel<C> {
    coordinator: PublicationCoordinator<C, DeclaredLiveZenohPublication>,
}

impl<C: MonotonicClock> DeclaredLiveGateKernel<C> {
    /// Consume a journal-bound runtime and validate its declared-live startup capability.
    ///
    /// # Errors
    /// Returns on profile, exact-wire, startup-capability, route, clock, or restart
    /// diagnostic failure. Failure consumes the bound runtime.
    pub fn start(bound: JournalBoundRunningGate, clock: C) -> Result<Self, LiveKernelStartError> {
        let coordinator = PublicationCoordinator::new_declared_live(bound, clock)
            .map_err(|error| LiveKernelStartError::Coordinator(error.into()))?;
        Ok(Self { coordinator })
    }

    /// Consume this kernel and one bounded static activation input.
    ///
    /// The signed lease's verified/admission-bound controller ID is used to
    /// derive the canonical exact intent route. Route equality is checked before
    /// lease-term commit, challenge consumption, revision change, or activation.
    /// Any failure is fail-stop and returns no kernel owner.
    ///
    /// This does not authenticate how the caller obtained the state, nonce, or
    /// lease and does not implement ongoing lease/state/revocation ingress.
    ///
    /// # Errors
    /// Returns on clock, state, challenge, lease, or exact-route validation failure.
    pub fn activate(
        self,
        activation: LiveIntentActivationInput,
    ) -> Result<LiveIntentRouteBoundGate<C>, LiveIntentActivationError> {
        let LiveIntentActivationInput {
            trusted_state,
            challenge_nonce,
            signed_lease_envelope,
        } = activation;
        let (coordinator, intent_binding) = self
            .coordinator
            .activate_live_intent(trusted_state, challenge_nonce, &signed_lease_envelope)
            .map_err(LiveIntentActivationError::from)?;
        Ok(LiveIntentRouteBoundGate {
            coordinator,
            intent_binding,
        })
    }
}

/// Non-cloneable live Gate capability with initial trusted state and one
/// canonical, accepted-lease-derived controller intent route.
///
/// This wrapper retains the sealed coordinator and accepted canonical binding.
/// Its route and controller accessors are read-only observability; authority
/// remains in the consuming wrapper. No session or ingress exists yet.
///
/// ```compile_fail
/// fn requires_clone<T: Clone>() {}
/// requires_clone::<haldir_gate::LiveIntentRouteBoundGate<()>>();
/// ```
#[must_use = "dropping the route-bound Gate stops the bound runtime and invalidates its route capability"]
pub struct LiveIntentRouteBoundGate<C> {
    coordinator: PublicationCoordinator<C, DeclaredLiveZenohPublication>,
    intent_binding: ActiveIntentBinding,
}

impl<C> LiveIntentRouteBoundGate<C> {
    /// Verified and admission-bound controller selected by the accepted lease.
    #[must_use]
    pub const fn controller_id(&self) -> &ControllerId {
        self.intent_binding.controller_id()
    }

    /// Canonical exact intent route retained from the accepted lease.
    #[must_use]
    pub fn intent_route(&self) -> &str {
        self.intent_binding.intent_route()
    }
}

#[cfg(test)]
impl<C: MonotonicClock> LiveIntentRouteBoundGate<C> {
    pub(crate) const fn actor(&self) -> &crate::actor::VehicleActor {
        self.coordinator.actor()
    }
}

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
/// it; only safe continuation paths return another service value. Construction
/// additionally requires a [`LiveIntentRouteBoundGate`] whose initial state and
/// signed lease selected the canonical controller intent route. This is not a session
/// owner, ingress loop, spawned worker, supervisor, ongoing control plane, or
/// delivery proof. Its publisher retains a shared Zenoh session handle that this
/// service neither opens nor exclusively owns; other holders can create publishers
/// or close that session.
///
/// ```compile_fail
/// fn requires_clone<T: Clone>() {}
/// requires_clone::<haldir_gate::DeclaredLiveGateService<()>>();
/// ```
#[must_use = "dropping the service stops the bound Gate runtime and drops its owned publisher handle"]
pub struct DeclaredLiveGateService<C> {
    core: LiveServiceCore<C, FinalCommandPublisher>,
    intent_binding: ActiveIntentBinding,
}

impl<C: MonotonicClock> DeclaredLiveGateService<C> {
    /// Bind one locally activated live runtime to exactly one route-matched
    /// publisher and an internally created one-slot output-capacity pool.
    ///
    /// # Errors
    /// Returns when the publisher advertises another exact realm/session route.
    /// Failure consumes and drops the route-bound runtime, accepted intent-route
    /// capability, and publisher.
    ///
    /// Route equality does not authenticate the session's credential identity or
    /// establish exclusive credential/session custody.
    pub fn bind(
        route_bound: LiveIntentRouteBoundGate<C>,
        publisher: FinalCommandPublisher,
    ) -> Result<Self, LiveServiceBindError> {
        let LiveIntentRouteBoundGate {
            coordinator,
            intent_binding,
        } = route_bound;
        let publisher_route = publisher.route().to_owned();
        bind_publisher_core(coordinator, publisher, &publisher_route).map(|core| Self {
            core,
            intent_binding,
        })
    }

    /// Verified and admission-bound controller selected by the accepted lease.
    #[must_use]
    pub const fn controller_id(&self) -> &ControllerId {
        self.intent_binding.controller_id()
    }

    /// Canonical exact intent route retained from the accepted lease.
    #[must_use]
    pub fn intent_route(&self) -> &str {
        self.intent_binding.intent_route()
    }

    /// Consume one caller-supplied raw intent event through service hard bounds, decision,
    /// Called, and at most one concrete strict publisher invocation.
    ///
    /// Dropping the returned future before its first poll drops the service without
    /// creating Called. Cancellation after Called drops all service capabilities;
    /// restart recovery must classify the locally confirmed Called tail. Local
    /// publisher `Ok` is not delivery, receiver acceptance, application, or an ACK.
    pub async fn process_one(self, event: IntentIngressEvent) -> LiveServiceTransition<C> {
        let Self {
            core,
            intent_binding,
        } = self;
        match prepare_one(core, event) {
            PreparedServiceStep::Continue { core, outcome } => LiveServiceTransition::Continue {
                service: Self {
                    core,
                    intent_binding,
                },
                outcome,
            },
            PreparedServiceStep::Unavailable {
                core,
                event,
                reason,
            } => LiveServiceTransition::Unavailable {
                service: Self {
                    core,
                    intent_binding,
                },
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
                            intent_binding,
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

/// Cloneable local request handle for a safe-boundary Gate aggregate shutdown.
///
/// A request is persistent and monotonic. It can wake
/// [`DeclaredLiveGateZenohService::process_next_or_shutdown`] while that method is
/// waiting for ingress, but it never cancels an event already handed to the Gate
/// decision/publication lifecycle. The aggregate remains the sole explicit close
/// handle. The request is cooperative and irreversible, so production wiring must
/// restrict clones and exclusively drive the aggregate through the shutdown-aware
/// processing method.
#[derive(Clone)]
pub struct LiveZenohShutdownHandle {
    requested: watch::Sender<bool>,
}

impl LiveZenohShutdownHandle {
    /// Persistently request shutdown at the next safe receive boundary.
    ///
    /// Returns `false` only after the aggregate-side receiver has already been
    /// dropped. `true` means the local latch accepted the request, not that an
    /// aggregate owner will be returned or cleanup will run; either can still be
    /// concurrently dropped. Repeated requests while the receiver exists remain
    /// successful.
    #[must_use]
    pub fn request_shutdown(&self) -> bool {
        self.requested.send(true).is_ok()
    }

    /// Whether shutdown has already been requested through any cloned handle.
    #[must_use]
    pub fn is_shutdown_requested(&self) -> bool {
        *self.requested.borrow()
    }
}

impl fmt::Debug for LiveZenohShutdownHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LiveZenohShutdownHandle")
            .field("requested", &self.is_shutdown_requested())
            .finish()
    }
}

/// Terminal result of the owned Zenoh receive/process path.
#[derive(Debug)]
#[non_exhaustive]
pub enum LiveZenohServiceStop {
    /// The owned bounded ingress receiver closed; no service owner is returned.
    IngressClosed,
    /// The owned ingress/service topology produced an otherwise unreachable refusal.
    OwnedIoInvariant(LiveDecisionUnavailable),
    /// The inner decision/publication service stopped fail-closed.
    Gate(LiveServiceStop),
}

/// Result of receiving and processing one event through the owned Zenoh ingress.
#[must_use = "the returned Zenoh service is required to receive another event through this owner"]
pub enum LiveZenohServiceTransition<C> {
    /// A persistent local shutdown request won at a safe receive boundary.
    ShutdownRequested {
        /// Same aggregate owner, ready for explicit [`DeclaredLiveGateZenohService::shutdown`].
        service: DeclaredLiveGateZenohService<C>,
    },
    /// The aggregate may receive another event only through the returned owner.
    Continue {
        /// Same single-owner aggregate after a safe continuation path.
        service: DeclaredLiveGateZenohService<C>,
        /// Decision/publication outcome.
        outcome: LiveServiceOutcome,
    },
    /// A journal-capacity or restart-clearance refusal retained the exact event privately.
    Unavailable {
        /// Same single-owner aggregate with one private pending event.
        service: DeclaredLiveGateZenohService<C>,
        /// Ownership-preserving journal-capacity or restart-clearance refusal.
        reason: LiveDecisionUnavailable,
    },
    /// The aggregate is deliberately unavailable until restart/recovery.
    Stopped(LiveZenohServiceStop),
}

/// Local successful-return report for explicit Zenoh Gate aggregate shutdown.
///
/// This reports local undeclare/drain and session-close returns, not confirmed
/// router-remote cleanup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LiveZenohShutdownReport {
    discarded_events: usize,
    ingress_counters: IngressCountersSnapshot,
}

impl LiveZenohShutdownReport {
    /// Number of privately pending and queued events discarded during shutdown.
    #[must_use]
    pub const fn discarded_events(&self) -> usize {
        self.discarded_events
    }

    /// Final bounded-label ingress counter snapshot after successful undeclaration.
    #[must_use]
    pub const fn ingress_counters(&self) -> IngressCountersSnapshot {
        self.ingress_counters
    }
}

/// Failure during explicit `undeclare-and-drain` then session-close shutdown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LiveZenohShutdownError {
    /// Ingress undeclare/quiescence cleanup failed; session close still returned `Ok`.
    Ingress(SecureZenohError),
    /// Ingress undeclare/quiescence cleanup succeeded, but session close failed.
    Session(SecureZenohError),
    /// Both ingress undeclare/quiescence cleanup and the subsequent session close failed.
    IngressAndSession {
        /// Ingress undeclare/quiescence cleanup failure.
        ingress: SecureZenohError,
        /// Session cleanup failure.
        session: SecureZenohError,
    },
}

impl fmt::Display for LiveZenohShutdownError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ingress(error) => write!(formatter, "intent-ingress shutdown failed: {error}"),
            Self::Session(error) => write!(formatter, "Zenoh session shutdown failed: {error}"),
            Self::IngressAndSession { ingress, session } => write!(
                formatter,
                "intent-ingress shutdown failed: {ingress}; Zenoh session shutdown also failed: {session}"
            ),
        }
    }
}

impl std::error::Error for LiveZenohShutdownError {}

/// Single-owner Gate I/O aggregate over one supplied Zenoh session lineage.
///
/// Binding consumes an accepted-lease-derived route capability, constructs the
/// strict publisher and exact bounded ingress internally from the same supplied
/// session wrapper, and retains all of them behind the consuming
/// [`Self::process_next`] and [`Self::process_next_or_shutdown`] methods. No public
/// method accepts or returns a raw [`IntentIngressEvent`]. An ownership-preserving
/// journal-capacity or restart-clearance refusal is retained privately and retried
/// byte-for-byte before receiving a newer event. Input/key/output-capacity refusals
/// are unreachable through this owned topology and stop as an invariant violation.
///
/// The move-only wrapper is the aggregate's sole close handle, but the transport
/// crate's public borrowing constructors can have minted other typed handles
/// before binding. This therefore establishes same-session lineage and local
/// ownership, not exclusive credential/session/handle custody, peer identity,
/// delivery, acceptance, application, supervision, or complete mediation.
///
/// ```compile_fail
/// fn requires_clone<T: Clone>() {}
/// requires_clone::<haldir_gate::DeclaredLiveGateZenohService<()>>();
/// ```
#[must_use = "dropping the aggregate stops the bound Gate runtime and drops its Zenoh handles"]
pub struct DeclaredLiveGateZenohService<C> {
    service: DeclaredLiveGateService<C>,
    ingress: IntentIngress,
    session: SecureZenohSession,
    pending_event: Option<IntentIngressEvent>,
    shutdown_sender: watch::Sender<bool>,
    shutdown_receiver: watch::Receiver<bool>,
}

struct PreparedLiveZenohBinding<C> {
    route_bound: LiveIntentRouteBoundGate<C>,
    keys: HaldirKeys,
    controller_id: ControllerId,
}

fn prepare_live_zenoh_binding<C: MonotonicClock>(
    route_bound: LiveIntentRouteBoundGate<C>,
) -> Result<PreparedLiveZenohBinding<C>, LiveZenohServiceBindFailure> {
    let keys = route_bound.coordinator.haldir_keys().clone();
    let controller_id = route_bound.intent_binding.controller_id().clone();
    let expected_intent_route = keys
        .intent(controller_id.as_str())
        .map_err(LiveZenohServiceBindFailure::IntentRoute)?;
    if expected_intent_route != route_bound.intent_binding.intent_route() {
        return Err(LiveZenohServiceBindFailure::IntentRouteMismatch);
    }
    Ok(PreparedLiveZenohBinding {
        route_bound,
        keys,
        controller_id,
    })
}

impl<C: MonotonicClock> DeclaredLiveGateZenohService<C> {
    /// Consume one route-bound Gate and caller-opened session, then internally
    /// construct the matched publisher and exact accepted-controller-route ingress.
    ///
    /// The canonical intent route is re-derived and cross-checked before any
    /// subscriber declaration. The publisher is locally bound before declaring
    /// ingress, leaving no fallible local binding step after subscription succeeds.
    /// Every failure returns no Gate, session, publisher, or ingress owner and
    /// attempts an explicit session close. Cancellation is fail-stop but cannot
    /// confirm remote declaration cleanup.
    ///
    /// # Errors
    /// Returns on intent-route derivation/cross-check, publisher binding, or
    /// ingress declaration. Any subsequent explicit session-close failure is
    /// recorded alongside that primary failure.
    pub async fn bind(
        route_bound: LiveIntentRouteBoundGate<C>,
        session: SecureZenohSession,
        limits: IngressLimits,
    ) -> Result<Self, LiveZenohServiceBindError> {
        let PreparedLiveZenohBinding {
            route_bound,
            keys,
            controller_id,
        } = match prepare_live_zenoh_binding(route_bound) {
            Ok(binding) => binding,
            Err(failure) => {
                return Err(close_failed_zenoh_binding(session, failure).await);
            }
        };

        let publisher = FinalCommandPublisher::new(&session, &keys);
        let service = match DeclaredLiveGateService::bind(route_bound, publisher) {
            Ok(service) => service,
            Err(error) => {
                return Err(close_failed_zenoh_binding(
                    session,
                    LiveZenohServiceBindFailure::Publisher(error),
                )
                .await);
            }
        };
        let ingress =
            match IntentIngress::declare(&session, &keys, controller_id.as_str(), limits).await {
                Ok(ingress) => ingress,
                Err(error) => {
                    drop(service);
                    return Err(close_failed_zenoh_binding(
                        session,
                        LiveZenohServiceBindFailure::Ingress(error),
                    )
                    .await);
                }
            };
        let (shutdown_sender, shutdown_receiver) = watch::channel(false);

        Ok(Self {
            service,
            session,
            ingress,
            pending_event: None,
            shutdown_sender,
            shutdown_receiver,
        })
    }

    /// Verified controller selected by the accepted lease.
    #[must_use]
    pub const fn controller_id(&self) -> &ControllerId {
        self.service.controller_id()
    }

    /// Canonical exact route declared by the owned intent ingress.
    #[must_use]
    pub fn intent_route(&self) -> &str {
        self.service.intent_route()
    }

    /// Operational Zenoh identifier; never an authorization principal.
    #[must_use]
    pub fn zid(&self) -> String {
        self.session.zid()
    }

    /// Shared bounded-label ingress counters.
    #[must_use]
    pub fn ingress_counters(&self) -> IngressCounters {
        self.ingress.counters()
    }

    /// Obtain a cloneable local handle that can request safe-boundary shutdown.
    ///
    /// Only [`Self::process_next_or_shutdown`] observes this request. The handle
    /// cannot close transport resources or extract the aggregate owner. Each clone
    /// is an irreversible cooperative stop capability and should remain restricted
    /// to the runner's shutdown path.
    #[must_use]
    pub fn shutdown_handle(&self) -> LiveZenohShutdownHandle {
        LiveZenohShutdownHandle {
            requested: self.shutdown_sender.clone(),
        }
    }

    /// Receive internally and consume one event through the Gate hard boundary.
    ///
    /// A private pending event always precedes a newer receive. Cancellation while
    /// awaiting ingress or publication drops every aggregate-local capability; if
    /// Called was already confirmed, restart recovery classifies that ambiguity.
    /// This legacy method does not observe [`Self::shutdown_handle`] requests; a
    /// shutdown-capable runner must exclusively use [`Self::process_next_or_shutdown`].
    pub async fn process_next(mut self) -> LiveZenohServiceTransition<C> {
        let event = match self.pending_event.take() {
            Some(event) => event,
            None => match self.ingress.recv().await {
                Some(event) => event,
                None => {
                    return LiveZenohServiceTransition::Stopped(
                        LiveZenohServiceStop::IngressClosed,
                    );
                }
            },
        };
        self.process_owned_event(event).await
    }

    /// Wait for one owned-ingress event or return the aggregate at a safe local
    /// shutdown boundary.
    ///
    /// A prior request wins before a privately retained retry or a newer receive.
    /// While idle, a later request wakes the receive and returns
    /// [`LiveZenohServiceTransition::ShutdownRequested`] with the same owner. Once
    /// an event is selected, the Gate decision/publication lifecycle runs to its
    /// ordinary transition without request-driven cancellation; a request arriving then remains
    /// latched for the next returned owner. This avoids inventing a publisher
    /// result, but does not provide a timeout for a stalled in-flight transport
    /// call. Cancelling this consuming future still drops the aggregate; callers
    /// must signal through [`Self::shutdown_handle`] and await the transition to
    /// preserve the owner for explicit shutdown. The race prioritizes an already
    /// observable request, but request and receive selection are not one atomic
    /// wall-clock action: if a concurrent event is selected first, that event runs
    /// to its ordinary transition and the request remains latched for the next
    /// returned owner.
    pub async fn process_next_or_shutdown(mut self) -> LiveZenohServiceTransition<C> {
        if *self.shutdown_receiver.borrow() {
            return LiveZenohServiceTransition::ShutdownRequested { service: self };
        }

        let event = match self.pending_event.take() {
            Some(event) => event,
            None => {
                let shutdown_receiver = &mut self.shutdown_receiver;
                let ingress = &mut self.ingress;
                match race_shutdown(shutdown_receiver, ingress.recv()).await {
                    ShutdownRace::Requested => {
                        return LiveZenohServiceTransition::ShutdownRequested { service: self };
                    }
                    ShutdownRace::Completed(Some(event)) => event,
                    ShutdownRace::Completed(None) => {
                        return LiveZenohServiceTransition::Stopped(
                            LiveZenohServiceStop::IngressClosed,
                        );
                    }
                }
            }
        };
        self.process_owned_event(event).await
    }

    async fn process_owned_event(self, event: IntentIngressEvent) -> LiveZenohServiceTransition<C> {
        let Self {
            service,
            session,
            ingress,
            pending_event,
            shutdown_sender,
            shutdown_receiver,
        } = self;
        debug_assert!(pending_event.is_none());
        drop(pending_event);

        match service.process_one(event).await {
            LiveServiceTransition::Continue { service, outcome } => {
                LiveZenohServiceTransition::Continue {
                    service: Self {
                        service,
                        session,
                        ingress,
                        pending_event: None,
                        shutdown_sender,
                        shutdown_receiver,
                    },
                    outcome,
                }
            }
            LiveServiceTransition::Unavailable {
                service,
                event,
                reason,
            } => {
                if unavailable_is_owned_io_invariant(&reason) {
                    drop((service, event, ingress, session));
                    LiveZenohServiceTransition::Stopped(LiveZenohServiceStop::OwnedIoInvariant(
                        reason,
                    ))
                } else {
                    LiveZenohServiceTransition::Unavailable {
                        service: Self {
                            service,
                            session,
                            ingress,
                            pending_event: Some(event),
                            shutdown_sender,
                            shutdown_receiver,
                        },
                        reason,
                    }
                }
            }
            LiveServiceTransition::Stopped(stop) => {
                drop(ingress);
                drop(session);
                LiveZenohServiceTransition::Stopped(LiveZenohServiceStop::Gate(stop))
            }
        }
    }

    /// Explicitly undeclare/drain ingress, drop the publisher-owning Gate service,
    /// and then close the retained session. Cleanup continues after undeclare error.
    /// This is local transport cleanup, not durable-journal footer finalization or
    /// confirmed remote session retirement. Because dropping the service releases
    /// its retained instance lock before session close completes, a runnable package
    /// must retain its own outer instance lock through final teardown.
    ///
    /// # Errors
    /// Returns either or both explicit transport cleanup failures. Cancellation
    /// drops remaining handles but does not confirm remote cleanup.
    pub async fn shutdown(self) -> Result<LiveZenohShutdownReport, LiveZenohShutdownError> {
        let Self {
            service,
            session,
            ingress,
            pending_event,
            shutdown_sender,
            shutdown_receiver,
        } = self;
        drop((shutdown_receiver, shutdown_sender));
        let pending_count = usize::from(pending_event.is_some());
        let ingress_result = ingress.undeclare_and_drain().await;
        drop(pending_event);
        drop(service);
        let session_result = session.close().await;
        finish_zenoh_shutdown(
            ingress_result.map(|(events, counters)| (events.len(), counters)),
            session_result,
            pending_count,
        )
    }
}

enum ShutdownRace<T> {
    Requested,
    Completed(T),
}

async fn race_shutdown<F, T>(
    shutdown_receiver: &mut watch::Receiver<bool>,
    operation: F,
) -> ShutdownRace<T>
where
    F: Future<Output = T>,
{
    if *shutdown_receiver.borrow() {
        return ShutdownRace::Requested;
    }
    let mut shutdown = core::pin::pin!(shutdown_receiver.changed());
    let mut operation = core::pin::pin!(operation);
    poll_fn(|context| {
        if shutdown.as_mut().poll(context).is_ready() {
            return Poll::Ready(ShutdownRace::Requested);
        }
        operation
            .as_mut()
            .poll(context)
            .map(ShutdownRace::Completed)
    })
    .await
}

async fn close_failed_zenoh_binding(
    session: SecureZenohSession,
    failure: LiveZenohServiceBindFailure,
) -> LiveZenohServiceBindError {
    LiveZenohServiceBindError {
        failure,
        session_close_error: session.close().await.err(),
    }
}

pub(crate) fn finish_zenoh_shutdown(
    ingress_result: Result<(usize, IngressCountersSnapshot), SecureZenohError>,
    session_result: Result<(), SecureZenohError>,
    pending_count: usize,
) -> Result<LiveZenohShutdownReport, LiveZenohShutdownError> {
    match (ingress_result, session_result) {
        (Ok((drained_count, ingress_counters)), Ok(())) => Ok(LiveZenohShutdownReport {
            discarded_events: drained_count.saturating_add(pending_count),
            ingress_counters,
        }),
        (Err(ingress), Ok(())) => Err(LiveZenohShutdownError::Ingress(ingress)),
        (Ok(_), Err(session)) => Err(LiveZenohShutdownError::Session(session)),
        (Err(ingress), Err(session)) => {
            Err(LiveZenohShutdownError::IngressAndSession { ingress, session })
        }
    }
}

pub(crate) const fn unavailable_is_owned_io_invariant(reason: &LiveDecisionUnavailable) -> bool {
    matches!(
        reason,
        LiveDecisionUnavailable::IntentEnvelopeTooLarge { .. }
            | LiveDecisionUnavailable::ActualKeyTooLong { .. }
            | LiveDecisionUnavailable::OutputCapacityUnavailable
    )
}

fn bind_publisher_core<C: MonotonicClock, P>(
    coordinator: PublicationCoordinator<C, DeclaredLiveZenohPublication>,
    publisher: P,
    publisher_route: &str,
) -> Result<LiveServiceCore<C, P>, LiveServiceBindError> {
    if !coordinator.publisher_route_matches(publisher_route) {
        return Err(LiveServiceBindError::PublisherRouteMismatch);
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

    pub(crate) fn bind_route_bound(
        route_bound: LiveIntentRouteBoundGate<C>,
        publisher: P,
        publisher_route: &str,
    ) -> Result<Self, LiveServiceBindError> {
        let LiveIntentRouteBoundGate {
            coordinator,
            intent_binding: _,
        } = route_bound;
        bind_publisher_core(coordinator, publisher, publisher_route).map(|core| Self { core })
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

/// Fake-only facade for testing aggregate orchestration without a Zenoh router.
#[cfg(test)]
pub(crate) struct TestDeclaredLiveGateZenohService<C, P, S, I> {
    service: TestDeclaredLiveGateService<C, P>,
    ingress: I,
    session: S,
    pending_event: Option<IntentIngressEvent>,
    shutdown_sender: watch::Sender<bool>,
    shutdown_receiver: watch::Receiver<bool>,
    controller_id: ControllerId,
    intent_route: String,
}

#[cfg(test)]
#[allow(
    dead_code,
    reason = "the fake aggregate mirrors all production terminal variants; lower lifecycle tests cover the unselected branches"
)]
pub(crate) enum TestLiveZenohServiceTransition<C, P, S, I, E> {
    Continue {
        service: TestDeclaredLiveGateZenohService<C, P, S, I>,
        outcome: LiveServiceOutcome,
    },
    Unavailable {
        service: TestDeclaredLiveGateZenohService<C, P, S, I>,
        reason: LiveDecisionUnavailable,
    },
    ShutdownRequested {
        service: TestDeclaredLiveGateZenohService<C, P, S, I>,
    },
    IngressClosed,
    OwnedIoInvariant(LiveDecisionUnavailable),
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
impl<C: MonotonicClock, P, S, I> TestDeclaredLiveGateZenohService<C, P, S, I> {
    pub(crate) async fn bind_with_test_factory<F, Fut>(
        route_bound: LiveIntentRouteBoundGate<C>,
        session: S,
        limits: IngressLimits,
        factory: F,
    ) -> Result<Self, LiveZenohServiceBindFailure>
    where
        F: FnOnce(S, HaldirKeys, ControllerId, IngressLimits) -> Fut,
        Fut: core::future::Future<Output = Result<(S, P, I, String), SecureZenohError>>,
    {
        let PreparedLiveZenohBinding {
            route_bound,
            keys,
            controller_id,
        } = prepare_live_zenoh_binding(route_bound)?;
        let intent_route = keys
            .intent(controller_id.as_str())
            .map_err(LiveZenohServiceBindFailure::IntentRoute)?;
        let (session, publisher, ingress, publisher_route) =
            factory(session, keys, controller_id.clone(), limits)
                .await
                .map_err(LiveZenohServiceBindFailure::Ingress)?;
        let service =
            TestDeclaredLiveGateService::bind_route_bound(route_bound, publisher, &publisher_route)
                .map_err(LiveZenohServiceBindFailure::Publisher)?;
        let (shutdown_sender, shutdown_receiver) = watch::channel(false);
        Ok(Self {
            service,
            session,
            ingress,
            pending_event: None,
            shutdown_sender,
            shutdown_receiver,
            controller_id,
            intent_route,
        })
    }

    pub(crate) const fn controller_id(&self) -> &ControllerId {
        &self.controller_id
    }

    pub(crate) fn intent_route(&self) -> &str {
        &self.intent_route
    }

    pub(crate) const fn session(&self) -> &S {
        &self.session
    }

    pub(crate) const fn ingress(&self) -> &I {
        &self.ingress
    }

    pub(crate) const fn has_pending_event(&self) -> bool {
        self.pending_event.is_some()
    }

    pub(crate) fn shutdown_handle(&self) -> LiveZenohShutdownHandle {
        LiveZenohShutdownHandle {
            requested: self.shutdown_sender.clone(),
        }
    }

    pub(crate) async fn process_next_with_test_future<E, F, Fut>(
        mut self,
        invoke: F,
    ) -> TestLiveZenohServiceTransition<C, P, S, I, E>
    where
        I: Iterator<Item = IntentIngressEvent>,
        F: FnOnce(&haldir_ncp08::ExactNcpCommandFrame) -> Fut,
        Fut: core::future::Future<Output = Result<(), E>>,
    {
        let event = match self.pending_event.take() {
            Some(event) => event,
            None => match self.ingress.next() {
                Some(event) => event,
                None => return TestLiveZenohServiceTransition::IngressClosed,
            },
        };
        self.process_owned_event_with_test_future(event, invoke)
            .await
    }

    pub(crate) async fn process_next_or_shutdown_with_test_future<E, F, Fut>(
        mut self,
        invoke: F,
    ) -> TestLiveZenohServiceTransition<C, P, S, I, E>
    where
        I: Iterator<Item = IntentIngressEvent>,
        F: FnOnce(&haldir_ncp08::ExactNcpCommandFrame) -> Fut,
        Fut: core::future::Future<Output = Result<(), E>>,
    {
        if *self.shutdown_receiver.borrow() {
            return TestLiveZenohServiceTransition::ShutdownRequested { service: self };
        }
        let event = match self.pending_event.take() {
            Some(event) => event,
            None => {
                let shutdown_receiver = &mut self.shutdown_receiver;
                let ingress = &mut self.ingress;
                let next = poll_fn(|_| Poll::Ready(ingress.next()));
                match race_shutdown(shutdown_receiver, next).await {
                    ShutdownRace::Requested => {
                        return TestLiveZenohServiceTransition::ShutdownRequested { service: self };
                    }
                    ShutdownRace::Completed(Some(event)) => event,
                    ShutdownRace::Completed(None) => {
                        return TestLiveZenohServiceTransition::IngressClosed;
                    }
                }
            }
        };
        self.process_owned_event_with_test_future(event, invoke)
            .await
    }

    async fn process_owned_event_with_test_future<E, F, Fut>(
        self,
        event: IntentIngressEvent,
        invoke: F,
    ) -> TestLiveZenohServiceTransition<C, P, S, I, E>
    where
        F: FnOnce(&haldir_ncp08::ExactNcpCommandFrame) -> Fut,
        Fut: core::future::Future<Output = Result<(), E>>,
    {
        let Self {
            service,
            session,
            ingress,
            pending_event,
            shutdown_sender,
            shutdown_receiver,
            controller_id,
            intent_route,
        } = self;
        debug_assert!(pending_event.is_none());
        drop(pending_event);
        match service.process_one_with_test_future(event, invoke).await {
            TestLiveServiceTransition::Continue { service, outcome } => {
                TestLiveZenohServiceTransition::Continue {
                    service: Self {
                        service,
                        session,
                        ingress,
                        pending_event: None,
                        shutdown_sender,
                        shutdown_receiver,
                        controller_id,
                        intent_route,
                    },
                    outcome,
                }
            }
            TestLiveServiceTransition::Unavailable {
                service,
                event,
                reason,
            } => {
                if unavailable_is_owned_io_invariant(&reason) {
                    drop((service, event, ingress, session));
                    TestLiveZenohServiceTransition::OwnedIoInvariant(reason)
                } else {
                    TestLiveZenohServiceTransition::Unavailable {
                        service: Self {
                            service,
                            session,
                            ingress,
                            pending_event: Some(event),
                            shutdown_sender,
                            shutdown_receiver,
                            controller_id,
                            intent_route,
                        },
                        reason,
                    }
                }
            }
            TestLiveServiceTransition::Fatal(error) => TestLiveZenohServiceTransition::Fatal(error),
            TestLiveServiceTransition::PublisherReturned {
                error,
                decision,
                terminal_envelope_digest,
            } => TestLiveZenohServiceTransition::PublisherReturned {
                error,
                decision,
                terminal_envelope_digest,
            },
            TestLiveServiceTransition::TerminalBoundaryFailed {
                publisher_error,
                source,
            } => TestLiveZenohServiceTransition::TerminalBoundaryFailed {
                publisher_error,
                source,
            },
        }
    }

    pub(crate) async fn shutdown_with_test_futures<UF, UFut, CF, CFut>(
        self,
        undeclare: UF,
        close: CF,
    ) -> Result<LiveZenohShutdownReport, LiveZenohShutdownError>
    where
        UF: FnOnce(I) -> UFut,
        UFut: core::future::Future<
                Output = Result<(usize, IngressCountersSnapshot), SecureZenohError>,
            >,
        CF: FnOnce(S) -> CFut,
        CFut: core::future::Future<Output = Result<(), SecureZenohError>>,
    {
        let Self {
            service,
            session,
            ingress,
            pending_event,
            shutdown_sender,
            shutdown_receiver,
            controller_id: _,
            intent_route: _,
        } = self;
        drop((shutdown_receiver, shutdown_sender));
        let pending_count = usize::from(pending_event.is_some());
        let ingress_result = undeclare(ingress).await;
        drop(pending_event);
        drop(service);
        let session_result = close(session).await;
        finish_zenoh_shutdown(ingress_result, session_result, pending_count)
    }
}

#[cfg(test)]
mod shutdown_race_tests {
    use super::{ShutdownRace, race_shutdown};
    use core::future::{Future, pending};
    use core::sync::atomic::{AtomicUsize, Ordering};
    use core::task::{Context, Poll, Waker};
    use std::sync::Arc;
    use std::task::Wake;

    struct WakeCounter(AtomicUsize);

    impl Wake for WakeCounter {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn later_shutdown_request_wakes_a_pending_idle_operation() {
        let (sender, mut receiver) = tokio::sync::watch::channel(false);
        let mut race = Box::pin(race_shutdown(&mut receiver, pending::<()>()));
        let wakes = Arc::new(WakeCounter(AtomicUsize::new(0)));
        let waker = Waker::from(Arc::clone(&wakes));
        let mut context = Context::from_waker(&waker);

        assert!(matches!(race.as_mut().poll(&mut context), Poll::Pending));
        assert!(sender.send(true).is_ok());
        assert!(wakes.0.load(Ordering::SeqCst) > 0);
        assert!(matches!(
            race.as_mut().poll(&mut context),
            Poll::Ready(ShutdownRace::Requested)
        ));
    }
}
