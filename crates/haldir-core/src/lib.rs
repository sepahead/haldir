//! `haldir-core` — shared, NCP-independent decision-input snapshots and monotonic
//! time types used by the state, policy, and gate crates.
#![forbid(unsafe_code)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::float_cmp
    )
)]

pub mod snapshot;
pub mod time;

/// Crate version string.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub use snapshot::{
    ActiveMissionLeaseSnapshot, AdmittedControllerSnapshot, KinematicStateFixedV1,
    StateUncertaintyFixedV1, TrustedStateSnapshotV1, VerifiedSourceStateV1,
};
pub use time::{MonoDuration, MonoInstant, MonotonicClock};
