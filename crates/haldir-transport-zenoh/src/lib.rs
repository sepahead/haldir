//! Exact route construction and an optional, typed secure-Zenoh boundary.
//!
//! [`HaldirKeys`] is always available and delegates the standard NCP command and
//! sensor routes to the exact pinned `ncp-core` key builder. The off-by-default
//! `live-zenoh` feature adds a strict mTLS client, bounded intent ingress, and an
//! exact final-command publisher. A received Zenoh sample contains its actual key
//! and payload, but not the peer certificate common name; this crate therefore
//! never presents a transport principal as sample metadata.
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

mod keys;
#[cfg(feature = "live-zenoh")]
mod live;

pub use keys::{HaldirKeyError, HaldirKeys, MAX_HALDIR_ROUTE_BYTES};
#[cfg(feature = "live-zenoh")]
pub use live::{
    FinalCommandPublisher, HARD_MAX_INTENT_BYTES, IngressCounters, IngressCountersSnapshot,
    IngressLimits, IntentIngress, IntentIngressEvent, SecureClientConfig, SecureZenohError,
    SecureZenohSession,
};

/// Crate version string.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
