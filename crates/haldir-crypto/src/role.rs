//! Closed key-role and key-class enums.
//!
//! No key may sign more than one authority domain by default: an evidence key
//! cannot mint a mission lease, a controller key cannot sign an admission, and
//! the Gate output key cannot sign controller bundles.

/// The closed set of application key roles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum KeyRole {
    /// Gate decision/output evidence signing.
    GateApplication,
    /// Controller intent signing.
    ControllerIntent,
    /// Mission-lease and mission-revocation signing.
    MissionAuthority,
    /// Admission-record and admission-revocation signing.
    AdmissionAuthority,
    /// Policy-package signing.
    PolicyAuthority,
    /// Revocation signing (when separated from the issuing authority).
    RevocationAuthority,
    /// Crebain accepted/applied evidence signing.
    CrebainEvidence,
    /// Deployment-package signing.
    DeploymentAuthority,
    /// A development-only key. Never valid under an assurance profile.
    DevelopmentOnly,
}

impl KeyRole {
    /// Stable machine string for the role.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GateApplication => "GATE_APPLICATION",
            Self::ControllerIntent => "CONTROLLER_INTENT",
            Self::MissionAuthority => "MISSION_AUTHORITY",
            Self::AdmissionAuthority => "ADMISSION_AUTHORITY",
            Self::PolicyAuthority => "POLICY_AUTHORITY",
            Self::RevocationAuthority => "REVOCATION_AUTHORITY",
            Self::CrebainEvidence => "CREBAIN_EVIDENCE",
            Self::DeploymentAuthority => "DEPLOYMENT_AUTHORITY",
            Self::DevelopmentOnly => "DEVELOPMENT_ONLY",
        }
    }
}

/// Whether a key is provisioned for assurance use or is development-only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyClass {
    /// Usable in an assurance deployment.
    Assurance,
    /// Development/test only; rejected under an assurance profile.
    Development,
}
