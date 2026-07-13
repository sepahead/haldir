//! Strict deployment-package verification and exact artifact-byte resolution.
//!
//! This crate verifies a signed canonical package against bootstrap trust and
//! expectations supplied separately by the caller. It then consumes and
//! retains exact artifact bytes while exposing no artifact path or reopen API.
//! On Linux and macOS, an optional source captures signed flat leaves relative to a
//! caller-supplied open directory capability. It does not authenticate that
//! root, load secrets, parse artifacts into runtime configuration, prove the
//! running binary, start a Gate, or establish a control plane.
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

mod artifact;
pub mod contract;
pub mod error;
mod source;
mod verify;

pub use artifact::{
    ArtifactLimits, DeploymentArtifactInput, DeploymentArtifactSet, ResolvedDeploymentPackage,
};
pub use error::DeploymentError;
pub use source::ArtifactDirectory;
pub use verify::{
    DeploymentAcceptancePolicy, VerifiedDeploymentPackage, verify_deployment_package,
};

/// Crate version string.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests;
