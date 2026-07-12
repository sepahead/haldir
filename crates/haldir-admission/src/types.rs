//! Admission value types: artifact references and the cumulative admission level.

use haldir_contracts::digest::DigestV1;
use haldir_contracts::scalar::AsciiId;

haldir_contracts::tagged_enum! {
    /// Cumulative admission levels. A higher label without the required lower
    /// evidence is invalid. `OpaqueController` is never a semantic admission.
    pub enum AdmissionLevelV1 {
        A0ProvenanceOnly = 0 => "A0_PROVENANCE_ONLY",
        A1SemanticReconstruction = 1 => "A1_SEMANTIC_RECONSTRUCTION",
        A2ReferenceConformance = 2 => "A2_REFERENCE_CONFORMANCE",
        A3ActionRelation = 3 => "A3_ACTION_RELATION",
        A4TrajectorySafetyRelation = 4 => "A4_TRAJECTORY_SAFETY_RELATION",
        A5HardwareConstrainedSimulation = 5 => "A5_HARDWARE_CONSTRAINED_SIMULATION",
        A6PhysicalHardwareAttested = 6 => "A6_PHYSICAL_HARDWARE_ATTESTED",
        OpaqueController = 99 => "OPAQUE_CONTROLLER",
    }
}

impl AdmissionLevelV1 {
    /// Whether this level constitutes a semantic bundle admission (A1..=A6).
    #[must_use]
    pub const fn is_semantic(self) -> bool {
        matches!(
            self,
            Self::A1SemanticReconstruction
                | Self::A2ReferenceConformance
                | Self::A3ActionRelation
                | Self::A4TrajectorySafetyRelation
                | Self::A5HardwareConstrainedSimulation
                | Self::A6PhysicalHardwareAttested
        )
    }
}

haldir_contracts::canonical_struct! {
    /// A content-addressed reference to an immutable artifact.
    pub struct ArtifactRefV1 {
        req 1 digest: DigestV1,
        req 2 size_bytes: u64,
        req 3 media_type: AsciiId<64>,
    }
}
