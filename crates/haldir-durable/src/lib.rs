//! Authenticated durable-state primitives for Haldir.
//!
//! This crate provides an HMAC-authenticated snapshot envelope, an atomic-storage
//! contract, a Unix process-crash-scoped file backend, and reconciliation
//! against a monotonic anchor outside the snapshot failure domain. It makes no
//! power-loss-durability claim by itself.
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
mod file;
mod local_anchor;
mod mac;
pub mod snapshot;

pub use error::DurableError;
pub use file::AtomicFileSnapshot;
pub use local_anchor::LocalFileGenerationAnchor;
pub use mac::StorageMacKey;
pub use snapshot::{
    Anchor, AnchorProtection, AuthenticatedSnapshotStore, CommitReceipt, GenerationAnchor,
    LoadedSnapshot, RecoveryStatus, SnapshotBinding, SnapshotStorage, StoreId,
};

/// Crate version string.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
