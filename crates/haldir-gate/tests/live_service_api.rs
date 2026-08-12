//! Compile-time API checks for the move-only declared-live service surface.

#![cfg(feature = "live-zenoh")]

use haldir_contracts::challenge::GateChallengeV1;
use haldir_contracts::ids::ControllerId;
use haldir_core::snapshot::TrustedStateSnapshotV1;
use haldir_core::{MonoInstant, MonotonicClock};
use haldir_gate::{
    DeclaredLiveGateKernel, DeclaredLiveGateZenohService, IssuedLiveGateChallenge,
    JournalBoundRunningGate, LiveIntentActivationError, LiveIntentActivationInput,
    LiveIntentActivationInputError, LiveIntentRouteBoundGate, LiveKernelStartError,
    LiveServiceBindError, LiveServiceFatal, LiveZenohActivityTransition, LiveZenohServiceBindError,
    LiveZenohServiceBindFailure, LiveZenohServiceStop, LiveZenohServiceTransition,
    LiveZenohShutdownError, LiveZenohShutdownHandle, LiveZenohShutdownReport,
    LiveZenohStateUpdateTransition,
};
use haldir_transport_zenoh::{IngressLimits, SecureZenohSession};

#[derive(Clone, Copy)]
struct ExternalClock;

impl MonotonicClock for ExternalClock {
    fn now(&self) -> MonoInstant {
        MonoInstant::from_nanos(0)
    }
}

#[test]
fn public_live_zenoh_aggregate_surface_is_root_exported_consuming_and_send() {
    fn assert_type_clone<T: Clone>() {}
    fn assert_type_send<T: Send>() {}
    fn assert_type_sync<T: Sync>() {}
    type Start = fn(
        JournalBoundRunningGate,
        ExternalClock,
    ) -> Result<DeclaredLiveGateKernel<ExternalClock>, LiveKernelStartError>;
    type NewActivationInput =
        fn(
            TrustedStateSnapshotV1,
            Vec<u8>,
        ) -> Result<LiveIntentActivationInput, LiveIntentActivationInputError>;
    type IssueChallenge = fn(
        DeclaredLiveGateKernel<ExternalClock>,
    )
        -> Result<IssuedLiveGateChallenge<ExternalClock>, LiveServiceFatal>;
    type Activate =
        fn(
            IssuedLiveGateChallenge<ExternalClock>,
            LiveIntentActivationInput,
        ) -> Result<LiveIntentRouteBoundGate<ExternalClock>, LiveIntentActivationError>;
    type ChallengeAccessor =
        for<'a> fn(&'a IssuedLiveGateChallenge<ExternalClock>) -> &'a GateChallengeV1;
    type ChallengeEnvelopeAccessor =
        for<'a> fn(&'a IssuedLiveGateChallenge<ExternalClock>) -> &'a [u8];
    type ControllerAccessor =
        for<'a> fn(&'a LiveIntentRouteBoundGate<ExternalClock>) -> &'a ControllerId;
    type RouteAccessor = for<'a> fn(&'a LiveIntentRouteBoundGate<ExternalClock>) -> &'a str;
    type ShutdownHandleAccessor =
        for<'a> fn(&'a DeclaredLiveGateZenohService<ExternalClock>) -> LiveZenohShutdownHandle;
    type ShutdownRequest = for<'a> fn(&'a LiveZenohShutdownHandle) -> bool;
    type UpdateZenohState = fn(
        DeclaredLiveGateZenohService<ExternalClock>,
        TrustedStateSnapshotV1,
    ) -> LiveZenohStateUpdateTransition<ExternalClock>;

    let _: Start = DeclaredLiveGateKernel::<ExternalClock>::start;
    let _: NewActivationInput = LiveIntentActivationInput::new;
    let _: IssueChallenge = DeclaredLiveGateKernel::<ExternalClock>::issue_activation_challenge;
    let _: Activate = IssuedLiveGateChallenge::<ExternalClock>::activate;
    let _: ChallengeAccessor = IssuedLiveGateChallenge::<ExternalClock>::challenge;
    let _: ChallengeEnvelopeAccessor =
        IssuedLiveGateChallenge::<ExternalClock>::signed_challenge_envelope;
    let _: ControllerAccessor = LiveIntentRouteBoundGate::<ExternalClock>::controller_id;
    let _: RouteAccessor = LiveIntentRouteBoundGate::<ExternalClock>::intent_route;
    let _: ShutdownHandleAccessor = DeclaredLiveGateZenohService::<ExternalClock>::shutdown_handle;
    let _: ShutdownRequest = LiveZenohShutdownHandle::request_shutdown;
    let _: ShutdownRequest = LiveZenohShutdownHandle::is_shutdown_requested;
    let _: UpdateZenohState = DeclaredLiveGateZenohService::<ExternalClock>::update_trusted_state;

    async fn wait_for_live_input(
        service: DeclaredLiveGateZenohService<ExternalClock>,
        state: TrustedStateSnapshotV1,
    ) -> LiveZenohActivityTransition<ExternalClock> {
        service
            .process_next_or_state_or_shutdown(core::future::ready(state))
            .await
    }
    let _ = wait_for_live_input;

    fn check_zenoh_bind(
        route_bound: LiveIntentRouteBoundGate<ExternalClock>,
        session: SecureZenohSession,
        limits: IngressLimits,
    ) {
        assert_send(DeclaredLiveGateZenohService::bind(
            route_bound,
            session,
            limits,
        ));
    }
    fn check_zenoh_process(service: DeclaredLiveGateZenohService<ExternalClock>) {
        assert_send(service.process_next());
    }
    fn check_zenoh_process_or_shutdown(service: DeclaredLiveGateZenohService<ExternalClock>) {
        assert_send(service.process_next_or_shutdown());
    }
    fn check_zenoh_shutdown(service: DeclaredLiveGateZenohService<ExternalClock>) {
        assert_send(service.shutdown());
    }
    fn assert_send<T: Send>(_: T) {}

    let _: fn(LiveIntentRouteBoundGate<ExternalClock>, SecureZenohSession, IngressLimits) =
        check_zenoh_bind;
    let _: fn(DeclaredLiveGateZenohService<ExternalClock>) = check_zenoh_process;
    let _: fn(DeclaredLiveGateZenohService<ExternalClock>) = check_zenoh_process_or_shutdown;
    let _: fn(DeclaredLiveGateZenohService<ExternalClock>) = check_zenoh_shutdown;

    assert_type_send::<DeclaredLiveGateKernel<ExternalClock>>();
    assert_type_send::<IssuedLiveGateChallenge<ExternalClock>>();
    assert_type_send::<LiveIntentActivationInput>();
    assert_type_send::<LiveIntentActivationInputError>();
    assert_type_send::<LiveIntentActivationError>();
    assert_type_send::<LiveIntentRouteBoundGate<ExternalClock>>();
    assert_type_send::<LiveKernelStartError>();
    assert_type_send::<LiveServiceBindError>();
    assert_type_send::<LiveZenohServiceBindFailure>();
    assert_type_send::<LiveZenohServiceBindError>();
    assert_type_send::<DeclaredLiveGateZenohService<ExternalClock>>();
    assert_type_send::<LiveZenohServiceStop>();
    assert_type_send::<LiveZenohServiceTransition<ExternalClock>>();
    assert_type_send::<LiveZenohStateUpdateTransition<ExternalClock>>();
    assert_type_send::<LiveZenohActivityTransition<ExternalClock>>();
    assert_type_send::<LiveZenohShutdownError>();
    assert_type_clone::<LiveZenohShutdownHandle>();
    assert_type_send::<LiveZenohShutdownHandle>();
    assert_type_sync::<LiveZenohShutdownHandle>();
    assert_type_send::<LiveZenohShutdownReport>();
    assert_type_send::<
        fn(LiveIntentRouteBoundGate<ExternalClock>, SecureZenohSession, IngressLimits),
    >();
    assert_type_send::<fn(DeclaredLiveGateZenohService<ExternalClock>)>();
}
