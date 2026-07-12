//! haldir-contracts — Haldir Gate crate. See the normative specification in `docs/`.
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
