//! NCP adapter errors.

/// A command-adapter failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NcpAdapterError {
    /// The output lifetime was zero or exceeded the lifetime authorized by the action.
    InvalidEffectiveValidity,
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
            Self::InvalidEffectiveValidity => "NCP_INVALID_EFFECTIVE_VALIDITY",
            Self::ConversionOutOfRange => "NCP_CONVERSION_OUT_OF_RANGE",
            Self::UpstreamValidationFailed => "NCP_UPSTREAM_VALIDATION_FAILED",
            Self::SerializationFailed => "NCP_SERIALIZATION_FAILED",
            Self::ValidatorMismatch => "NCP_VALIDATOR_MISMATCH",
        }
    }
}

impl std::fmt::Display for NcpAdapterError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::error::Error for NcpAdapterError {}
