//! `ControllerBundleManifestV1` — the content-addressed, reconstructable
//! description of a controller within one declared admission profile.

use crate::types::ArtifactRefV1;
use haldir_contracts::ids::ControllerId;
use haldir_contracts::scalar::{AsciiId, BoundedVec};

haldir_contracts::canonical_struct! {
    /// A profile-complete controller bundle manifest (spec §ControllerBundleManifestV1).
    /// It is profile-complete only when `opaque_dependencies` is empty.
    pub struct ControllerBundleManifestV1 kind "haldir.controller_bundle" {
        req 2 schema_major: u16,
        req 3 schema_minor: u16,
        req 4 controller_id: ControllerId,
        req 5 bundle_id: [u8; 16],
        req 6 admission_profile_id: AsciiId<64>,
        req 7 logical_graph: ArtifactRefV1,
        req 8 topology: ArtifactRefV1,
        req 9 parameter_tensors: BoundedVec<ArtifactRefV1, 64>,
        req 10 codec: ArtifactRefV1,
        req 11 time_contract: ArtifactRefV1,
        req 12 reset_contract: ArtifactRefV1,
        req 13 conformance_vectors: ArtifactRefV1,
        req 14 build_provenance: ArtifactRefV1,
        req 15 opaque_dependencies: BoundedVec<ArtifactRefV1, 16>,
    }
}

impl ControllerBundleManifestV1 {
    /// Whether the manifest can be reconstructed with no opaque code dependency.
    #[must_use]
    pub fn is_profile_complete(&self) -> bool {
        self.opaque_dependencies.is_empty()
    }
}

impl haldir_contracts::cbor::Validate for ControllerBundleManifestV1 {
    fn validate(&self) -> Result<(), haldir_contracts::error::DecodeError> {
        if self.schema_major != 1 {
            return Err(haldir_contracts::error::DecodeError::UnsupportedVersion);
        }
        Ok(())
    }
}
