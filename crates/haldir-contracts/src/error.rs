//! Stable, typed decode/validation errors.
//!
//! Every variant maps to a stable machine reason code via [`DecodeError::reason_code`].
//! Human-readable strings are never used as a security decision input; the reason
//! code is the stable class.

use core::fmt;

/// A canonical-decode or semantic-validation failure with a stable reason class.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DecodeError {
    /// Input ended before a complete item was read.
    UnexpectedEof,
    /// An indefinite-length item was present (forbidden by the Haldir profile).
    IndefiniteLength,
    /// An integer or length was not encoded in the shortest possible form.
    NonShortestInt,
    /// Additional-info values 28/29/30 are reserved and forbidden.
    ReservedAdditionalInfo,
    /// A CBOR float was present in a signed contract (forbidden).
    FloatNotAllowed,
    /// A simple value other than the permitted `true`/`false` was present.
    BadSimpleValue,
    /// A CBOR tag was present where none is permitted.
    TagNotAllowed,
    /// The major type did not match what the schema required at this position.
    UnexpectedMajorType {
        /// Major type the schema expected.
        expected: u8,
        /// Major type actually found.
        found: u8,
    },
    /// Nesting depth exceeded the configured maximum.
    DepthExceeded,
    /// A map contained more key/value pairs than the configured maximum.
    MapPairsExceeded,
    /// An array contained more elements than the configured maximum.
    ArrayLenExceeded,
    /// A byte string was longer than the configured maximum.
    ByteLenExceeded,
    /// A text string was longer than the configured maximum.
    TextLenExceeded,
    /// A text string was not valid UTF-8.
    InvalidUtf8,
    /// An identifier contained non-ASCII, control, whitespace, or forbidden bytes.
    InvalidIdentifier,
    /// A map key was not an unsigned integer.
    MapKeyNotUnsigned,
    /// Map keys were duplicated or not in strictly ascending canonical order.
    NonCanonicalMapOrder,
    /// A field key not defined by the schema (major version) was present.
    UnknownField {
        /// The offending key.
        key: u64,
    },
    /// A required field was absent.
    MissingField {
        /// The required key.
        key: u64,
    },
    /// A field key appeared more than once.
    DuplicateField {
        /// The offending key.
        key: u64,
    },
    /// Bytes remained after the single top-level item was decoded.
    TrailingBytes,
    /// An integer did not fit the target fixed-width type.
    IntOutOfRange,
    /// A zero value was supplied for a `NonZero` field.
    ZeroForNonZero,
    /// An enum discriminant/tag was not recognized.
    BadEnumTag,
    /// A fixed-length byte field had the wrong length.
    BadLength {
        /// Expected length in bytes.
        expected: usize,
        /// Actual length in bytes.
        found: usize,
    },
    /// The embedded `message_kind` did not match the expected contract kind.
    WrongMessageKind,
    /// The schema major version is not supported by this build.
    UnsupportedVersion,
    /// A canonicalized UUIDv4 string was malformed.
    BadUuid,
    /// A collection exceeded a schema-declared bound (distinct from parser limits).
    BoundExceeded,
    /// A cross-field semantic invariant failed during construction.
    SemanticInvalid {
        /// Stable machine class of the semantic failure.
        code: &'static str,
    },
}

impl DecodeError {
    /// Stable machine-readable class for logs, receipts, and vectors.
    #[must_use]
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::UnexpectedEof => "DECODE_EOF",
            Self::IndefiniteLength => "DECODE_INDEFINITE_LENGTH",
            Self::NonShortestInt => "DECODE_NON_SHORTEST_INT",
            Self::ReservedAdditionalInfo => "DECODE_RESERVED_AI",
            Self::FloatNotAllowed => "DECODE_FLOAT_FORBIDDEN",
            Self::BadSimpleValue => "DECODE_BAD_SIMPLE",
            Self::TagNotAllowed => "DECODE_TAG_FORBIDDEN",
            Self::UnexpectedMajorType { .. } => "DECODE_UNEXPECTED_MAJOR",
            Self::DepthExceeded => "DECODE_DEPTH_EXCEEDED",
            Self::MapPairsExceeded => "DECODE_MAP_PAIRS_EXCEEDED",
            Self::ArrayLenExceeded => "DECODE_ARRAY_LEN_EXCEEDED",
            Self::ByteLenExceeded => "DECODE_BYTE_LEN_EXCEEDED",
            Self::TextLenExceeded => "DECODE_TEXT_LEN_EXCEEDED",
            Self::InvalidUtf8 => "DECODE_INVALID_UTF8",
            Self::InvalidIdentifier => "DECODE_INVALID_IDENTIFIER",
            Self::MapKeyNotUnsigned => "DECODE_MAP_KEY_NOT_UNSIGNED",
            Self::NonCanonicalMapOrder => "DECODE_NON_CANONICAL_MAP_ORDER",
            Self::UnknownField { .. } => "DECODE_UNKNOWN_FIELD",
            Self::MissingField { .. } => "DECODE_MISSING_FIELD",
            Self::DuplicateField { .. } => "DECODE_DUPLICATE_FIELD",
            Self::TrailingBytes => "DECODE_TRAILING_BYTES",
            Self::IntOutOfRange => "DECODE_INT_OUT_OF_RANGE",
            Self::ZeroForNonZero => "DECODE_ZERO_FOR_NONZERO",
            Self::BadEnumTag => "DECODE_BAD_ENUM_TAG",
            Self::BadLength { .. } => "DECODE_BAD_LENGTH",
            Self::WrongMessageKind => "DECODE_WRONG_MESSAGE_KIND",
            Self::UnsupportedVersion => "DECODE_UNSUPPORTED_VERSION",
            Self::BadUuid => "DECODE_BAD_UUID",
            Self::BoundExceeded => "DECODE_BOUND_EXCEEDED",
            Self::SemanticInvalid { code } => code,
        }
    }
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.reason_code())
    }
}

impl std::error::Error for DecodeError {}
