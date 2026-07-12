//! Typed cryptographic errors with stable reason classes.

use core::fmt;
use haldir_contracts::error::DecodeError;

/// A COSE/verification failure with a stable machine reason class.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CryptoError {
    /// The COSE_Sign1 envelope was structurally malformed.
    Malformed,
    /// The protected header algorithm was absent or not EdDSA.
    UnsupportedAlgorithm,
    /// A security-relevant header appeared in the unprotected bucket.
    UnprotectedSecurityHeader,
    /// The protected `content_type` did not match the dispatch context.
    ContentTypeMismatch,
    /// The `kid` did not resolve to exactly one trusted key.
    KidUnknown,
    /// A public key was structurally invalid.
    BadKey,
    /// The resolved key's role did not match the required role.
    WrongRole,
    /// The resolved key is revoked.
    KeyRevoked,
    /// A development-class key was presented under an assurance profile.
    DevelopmentKeyInAssurance,
    /// The Ed25519 signature did not verify over the exact bytes.
    SignatureInvalid,
    /// The payload failed canonical decode/validation after a valid signature.
    Payload(DecodeError),
}

impl CryptoError {
    /// Stable machine reason code for logs and receipts.
    #[must_use]
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::Malformed => "DENY_MALFORMED",
            Self::UnsupportedAlgorithm => "DENY_SIGNATURE_INVALID",
            Self::UnprotectedSecurityHeader => "DENY_MALFORMED",
            Self::ContentTypeMismatch => "DENY_MALFORMED",
            Self::KidUnknown => "DENY_SIGNATURE_INVALID",
            Self::BadKey => "DENY_SIGNATURE_INVALID",
            Self::WrongRole => "DENY_WRONG_ROLE",
            Self::KeyRevoked => "DENY_KEY_REVOKED",
            Self::DevelopmentKeyInAssurance => "DENY_WRONG_ROLE",
            Self::SignatureInvalid => "DENY_SIGNATURE_INVALID",
            Self::Payload(_) => "DENY_NONCANONICAL",
        }
    }
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.reason_code())
    }
}

impl std::error::Error for CryptoError {}

impl From<DecodeError> for CryptoError {
    fn from(e: DecodeError) -> Self {
        Self::Payload(e)
    }
}
