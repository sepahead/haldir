//! Immutable NCP `v0.8.0` compatibility identity.
//!
//! A version string such as `0.8` is insufficient; the compatibility record binds
//! the immutable tag, exact commit, contract hash, proto digest, capability
//! profile, and Haldir adapter revision (spec §Compatibility identifier).

use haldir_contracts::digest::{DigestDomain, DigestV1};

/// The pinned NCP `v0.8.0` compatibility record for this adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NcpCompatibilityRecordV1 {
    /// Immutable release tag.
    pub ncp_tag: &'static str,
    /// Exact 40-hex commit.
    pub ncp_commit: &'static str,
    /// Wire version.
    pub wire_version: &'static str,
    /// Contract hash from the release.
    pub contract_hash: &'static str,
    /// Measured `proto/ncp.proto` SHA-256.
    pub proto_sha256: &'static str,
    /// The active capability profile.
    pub capability_profile: &'static str,
    /// The Haldir adapter version.
    pub haldir_adapter_version: &'static str,
}

/// The pinned constants (specification NCP baseline; `docs/NCP-COMPATIBILITY.md`).
pub const NCP_V0_8_0: NcpCompatibilityRecordV1 = NcpCompatibilityRecordV1 {
    ncp_tag: "v0.8.0",
    ncp_commit: "2f5bd586d4bb20c90362bb6f5698b7f64057ba4e",
    wire_version: "0.8",
    contract_hash: "d1b50a2d8a265276",
    proto_sha256: "6f13b12cff76e12fef384f691d11e2944db1f676568c3e780d3f975689131227",
    capability_profile: "PRE_AUTHORITY_ACL_ONLY",
    haldir_adapter_version: env!("CARGO_PKG_VERSION"),
};

impl NcpCompatibilityRecordV1 {
    /// A stable digest over the compatibility fields.
    #[must_use]
    pub fn compatibility_id(&self) -> DigestV1 {
        let joined = [
            self.ncp_tag,
            self.ncp_commit,
            self.wire_version,
            self.contract_hash,
            self.proto_sha256,
            self.capability_profile,
            self.haldir_adapter_version,
        ]
        .join("\u{1f}");
        DigestV1::compute(DigestDomain::Payload, joined.as_bytes())
    }
}
