//! NCP adapter errors.

/// A command-adapter failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NcpAdapterError {
    /// A converted value fell outside the representable/allowed range.
    ConversionOutOfRange,
    /// The exact bytes did not match the validator's rebuild.
    ValidatorMismatch,
}

impl NcpAdapterError {
    /// Stable reason string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ConversionOutOfRange => "NCP_CONVERSION_OUT_OF_RANGE",
            Self::ValidatorMismatch => "NCP_VALIDATOR_MISMATCH",
        }
    }
}
