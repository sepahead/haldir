//! NCP adapter errors.

/// A command-adapter failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NcpAdapterError {
    /// A converted value fell outside the representable/allowed range.
    ConversionOutOfRange,
    /// The exact upstream NCP validator rejected the constructed frame.
    UpstreamValidationFailed,
    /// The exact upstream NCP frame could not be serialized.
    SerializationFailed,
    /// The exact bytes did not match the validator's rebuild.
    ValidatorMismatch,
}

impl NcpAdapterError {
    /// Stable reason string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ConversionOutOfRange => "NCP_CONVERSION_OUT_OF_RANGE",
            Self::UpstreamValidationFailed => "NCP_UPSTREAM_VALIDATION_FAILED",
            Self::SerializationFailed => "NCP_SERIALIZATION_FAILED",
            Self::ValidatorMismatch => "NCP_VALIDATOR_MISMATCH",
        }
    }
}
