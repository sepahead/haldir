//! haldir-gate — composition of the pure Haldir subsystems into one one-vehicle
//! authorization runtime with explicit side-effect boundaries. See `docs/`.
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

/// Crate version string.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
