#![cfg(feature = "live-zenoh")]

use haldir_contracts::ids::{ChallengeNonce, ControllerId};
use haldir_core::snapshot::TrustedStateSnapshotV1;
use haldir_core::{MonoInstant, MonotonicClock};
use haldir_gate::{
    DeclaredLiveGateKernel, DeclaredLiveGateService, JournalBoundRunningGate,
    LiveIntentActivationError, LiveIntentActivationInput, LiveIntentActivationInputError,
    LiveIntentRouteBoundGate, LiveKernelStartError, LiveServiceBindError, LiveServiceTransition,
};
use haldir_transport_zenoh::FinalCommandPublisher;

#[derive(Clone, Copy)]
struct ExternalClock;

impl MonotonicClock for ExternalClock {
    fn now(&self) -> MonoInstant {
        MonoInstant::from_nanos(0)
    }
}

#[test]
fn public_live_service_surface_is_root_exported_consuming_and_send() {
    fn assert_send<T: Send>() {}
    type Start = fn(
        JournalBoundRunningGate,
        ExternalClock,
    ) -> Result<DeclaredLiveGateKernel<ExternalClock>, LiveKernelStartError>;
    type NewActivationInput =
        fn(
            TrustedStateSnapshotV1,
            ChallengeNonce,
            Vec<u8>,
        ) -> Result<LiveIntentActivationInput, LiveIntentActivationInputError>;
    type Activate =
        fn(
            DeclaredLiveGateKernel<ExternalClock>,
            LiveIntentActivationInput,
        ) -> Result<LiveIntentRouteBoundGate<ExternalClock>, LiveIntentActivationError>;
    type Bind = fn(
        LiveIntentRouteBoundGate<ExternalClock>,
        FinalCommandPublisher,
    ) -> Result<DeclaredLiveGateService<ExternalClock>, LiveServiceBindError>;
    type ControllerAccessor =
        for<'a> fn(&'a LiveIntentRouteBoundGate<ExternalClock>) -> &'a ControllerId;
    type RouteAccessor = for<'a> fn(&'a LiveIntentRouteBoundGate<ExternalClock>) -> &'a str;

    let _: Start = DeclaredLiveGateKernel::<ExternalClock>::start;
    let _: NewActivationInput = LiveIntentActivationInput::new;
    let _: Activate = DeclaredLiveGateKernel::<ExternalClock>::activate;
    let _: Bind = DeclaredLiveGateService::<ExternalClock>::bind;
    let _: ControllerAccessor = LiveIntentRouteBoundGate::<ExternalClock>::controller_id;
    let _: RouteAccessor = LiveIntentRouteBoundGate::<ExternalClock>::intent_route;
    assert_send::<DeclaredLiveGateKernel<ExternalClock>>();
    assert_send::<LiveIntentActivationInput>();
    assert_send::<LiveIntentActivationInputError>();
    assert_send::<LiveIntentActivationError>();
    assert_send::<LiveIntentRouteBoundGate<ExternalClock>>();
    assert_send::<LiveKernelStartError>();
    assert_send::<LiveServiceBindError>();
    assert_send::<DeclaredLiveGateService<ExternalClock>>();
    assert_send::<LiveServiceTransition<ExternalClock>>();
}
