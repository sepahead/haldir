#![cfg(feature = "live-zenoh")]

use haldir_core::{MonoInstant, MonotonicClock};
use haldir_gate::{
    DeclaredLiveGateService, JournalBoundRunningGate, LiveServiceStartError, LiveServiceTransition,
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
    type Bind = fn(
        JournalBoundRunningGate,
        ExternalClock,
        FinalCommandPublisher,
    ) -> Result<DeclaredLiveGateService<ExternalClock>, LiveServiceStartError>;

    let _: Bind = DeclaredLiveGateService::<ExternalClock>::bind;
    assert_send::<DeclaredLiveGateService<ExternalClock>>();
    assert_send::<LiveServiceTransition<ExternalClock>>();
}
