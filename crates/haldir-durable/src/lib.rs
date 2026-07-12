//! Authenticated durable-state primitives for Haldir.
//!
//! This crate provides an HMAC-authenticated snapshot envelope, an atomic-storage
//! contract, and reconciliation against a monotonic anchor outside the snapshot
//! failure domain. It intentionally contains no filesystem backend yet and makes
//! no crash- or power-durability claim by itself.
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

pub mod error;
mod mac;
pub mod snapshot;

pub use error::DurableError;
pub use mac::StorageMacKey;
pub use snapshot::{
    Anchor, AuthenticatedSnapshotStore, CommitReceipt, GenerationAnchor, LoadedSnapshot,
    RecoveryStatus, SnapshotBinding, SnapshotStorage, StoreId,
};

/// Crate version string.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
