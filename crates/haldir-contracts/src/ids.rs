//! Identity newtypes.
//!
//! These types make accidental namespace mixing a compile error (spec invariant
//! S2). In particular the controller-intent and Gate-output stream namespaces use
//! **distinct** epoch and sequence types with no `From`/`Into` between them
//! (punch-list B5), so an intent sequence can never be assigned into an output
//! sequence.

use crate::cbor::{CanonicalValue, CborReader, CborWriter};
use crate::error::DecodeError;
use crate::scalar::{AsciiId, CanonicalUuidV4String};
use core::num::NonZeroU64;

/// Fixed-length opaque byte identifier newtype with a canonical byte-string encoding.
macro_rules! byte_id {
    ($(#[$m:meta])* $name:ident, $n:literal) => {
        $(#[$m])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name([u8; $n]);
        impl $name {
            /// Wrap raw bytes.
            #[must_use]
            pub const fn new(b: [u8; $n]) -> Self { Self(b) }
            /// Borrow the raw bytes.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; $n] { &self.0 }
        }
        impl CanonicalValue for $name {
            fn encode(&self, w: &mut CborWriter) { w.bytes(&self.0); }
            fn decode(r: &mut CborReader<'_>) -> Result<Self, DecodeError> {
                let b = r.read_bytes()?;
                let arr: [u8; $n] = b.try_into().map_err(|_| DecodeError::BadLength { expected: $n, found: b.len() })?;
                Ok(Self(arr))
            }
        }
    };
}

/// ASCII-identifier newtype (`AsciiId<N>` wrapper) with delegated encoding.
macro_rules! ascii_id {
    ($(#[$m:meta])* $name:ident, $n:literal) => {
        $(#[$m])*
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(AsciiId<$n>);
        impl $name {
            /// Construct from text, validating charset and length.
            ///
            /// # Errors
            /// Returns [`DecodeError::InvalidIdentifier`] on invalid input.
            pub fn new(s: &str) -> Result<Self, DecodeError> { Ok(Self(AsciiId::new(s)?)) }
            /// Borrow the identifier text.
            #[must_use]
            pub fn as_str(&self) -> &str { self.0.as_str() }
        }
        impl CanonicalValue for $name {
            fn encode(&self, w: &mut CborWriter) { self.0.encode(w); }
            fn decode(r: &mut CborReader<'_>) -> Result<Self, DecodeError> { Ok(Self(AsciiId::decode(r)?)) }
        }
    };
}

/// Distinct `NonZeroU64` sequence newtype (no cross-conversion between namespaces).
macro_rules! nonzero_seq {
    ($(#[$m:meta])* $name:ident) => {
        $(#[$m])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(NonZeroU64);
        impl $name {
            /// Wrap a nonzero value.
            #[must_use]
            pub const fn new(v: NonZeroU64) -> Self { Self(v) }
            /// The underlying value.
            #[must_use]
            pub const fn get(self) -> u64 { self.0.get() }
        }
        impl CanonicalValue for $name {
            fn encode(&self, w: &mut CborWriter) { self.0.encode(w); }
            fn decode(r: &mut CborReader<'_>) -> Result<Self, DecodeError> { Ok(Self(NonZeroU64::decode(r)?)) }
        }
    };
}

byte_id!(
    /// A Gate process-incarnation identifier, regenerated on every boot.
    GateBootId, 16);
byte_id!(
    /// A challenge nonce.
    ChallengeNonce, 32);
byte_id!(
    /// A mission-lease identifier.
    MissionLeaseId, 16);
byte_id!(
    /// An admission-record identifier.
    AdmissionId, 16);
byte_id!(
    /// A decision identifier.
    DecisionId, 16);
byte_id!(
    /// A controller-intent stream epoch (controller namespace).
    IntentEpoch, 16);
byte_id!(
    /// A controller process-instance identifier.
    ControllerInstanceId, 16);
byte_id!(
    /// A future NCP plant-authority lease identifier (unused under PRE_AUTHORITY).
    AuthorityLeaseId, 16);

ascii_id!(
    /// A controller deployment identifier.
    ControllerId, 64);
ascii_id!(
    /// A vehicle identifier.
    VehicleId, 64);
ascii_id!(
    /// A mission identifier.
    MissionId, 64);
ascii_id!(
    /// A Gate identifier.
    GateId, 64);
ascii_id!(
    /// A transport-principal identifier (certificate subject).
    PrincipalId, 128);

nonzero_seq!(
    /// A controller-intent sequence (controller namespace; never assignable to `OutputSeq`).
    IntentSeq);
nonzero_seq!(
    /// A Gate-output stream sequence (Gate namespace; never assignable to `IntentSeq`).
    OutputSeq);
nonzero_seq!(
    /// An NCP source sequence (correlation namespace; S7 — not delivery order).
    SourceSeq);
nonzero_seq!(
    /// A challenge sequence.
    ChallengeSeq);

/// The Gate-output stream epoch, wrapping a canonical UUIDv4 string. Distinct from
/// [`IntentEpoch`] (controller namespace) — the two never interconvert (B5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GateOutputEpoch(CanonicalUuidV4String);

impl GateOutputEpoch {
    /// Wrap a canonical UUIDv4.
    #[must_use]
    pub const fn new(u: CanonicalUuidV4String) -> Self {
        Self(u)
    }
    /// Borrow the underlying UUID.
    #[must_use]
    pub const fn uuid(&self) -> &CanonicalUuidV4String {
        &self.0
    }
}

impl CanonicalValue for GateOutputEpoch {
    fn encode(&self, w: &mut CborWriter) {
        self.0.encode(w);
    }
    fn decode(r: &mut CborReader<'_>) -> Result<Self, DecodeError> {
        Ok(Self(CanonicalUuidV4String::decode(r)?))
    }
}

/// A bounded application-signing key identifier (COSE `kid`), 1..=64 bytes.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyId(Vec<u8>);

impl KeyId {
    /// Maximum key-id length in bytes.
    pub const MAX: usize = 64;

    /// Construct, rejecting empty or overlength.
    ///
    /// # Errors
    /// Returns [`DecodeError::BoundExceeded`] when empty or longer than [`Self::MAX`].
    pub fn new(bytes: Vec<u8>) -> Result<Self, DecodeError> {
        if bytes.is_empty() || bytes.len() > Self::MAX {
            return Err(DecodeError::BoundExceeded);
        }
        Ok(Self(bytes))
    }

    /// Borrow the key-id bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl CanonicalValue for KeyId {
    fn encode(&self, w: &mut CborWriter) {
        w.bytes(&self.0);
    }
    fn decode(r: &mut CborReader<'_>) -> Result<Self, DecodeError> {
        Self::new(r.read_bytes()?.to_vec())
    }
}
