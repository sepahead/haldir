//! Strict deployment-package verification and exact artifact-byte resolution.
//!
//! This crate verifies a signed canonical package against bootstrap trust and
//! expectations supplied separately by the caller. It then consumes and
//! retains exact artifact bytes while exposing no artifact path or reopen API.
//! On Linux and macOS, an optional source captures signed flat leaves relative to a
//! caller-supplied open directory capability. It does not authenticate that
//! root, load secrets, construct runtime objects from the retained snapshots, prove the
//! running binary, start a Gate, or establish a control plane. Consuming
//! typestates compose the exact signed `NCP_COMPATIBILITY` role with the compiled
//! adapter validator, then strictly decode and package-cross-bind the signed
//! `GATE_CONFIGURATION` role. A final consuming stage verifies independently
//! role-signed, revision-scoped approvals for the exact runtime trust,
//! admission, revocation, and policy snapshot identities. That stage also
//! retains an encapsulated check that the later runtime trust store cannot
//! rebind a bootstrap key identifier or public key to different authority
//! semantics. The other seven artifact roles remain byte-verified only.
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
    ArtifactLimits, AuthorityApprovalPolicy, AuthorityValidatedDeploymentPackage,
    DeploymentArtifactInput, DeploymentArtifactSet, GateConfigurationValidatedDeploymentPackage,
    NcpValidatedDeploymentPackage, ResolvedDeploymentPackage, VerifiedAuthoritySnapshotApproval,
};
pub use error::DeploymentError;
pub use source::ArtifactDirectory;
pub use verify::{
    DeploymentAcceptancePolicy, DeploymentIdentityExpectation, DeploymentProfileRequirement,
    VerifiedDeploymentPackage, verify_deployment_package,
};

/// Crate version string.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests;
