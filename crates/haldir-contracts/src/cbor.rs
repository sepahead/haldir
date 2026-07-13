//! Strict, bounded, deterministic CBOR codec for the Haldir application profile.
//!
//! This is a hand-written codec — not a general CBOR library — because the
//! specification requires enforcing rules that generic decoders do not:
//! definite lengths only, shortest integer/length encodings, strictly ascending
//! unsigned map keys with no duplicates, no floats in signed contracts, no tags,
//! bounded depth/collection/byte sizes, and exactly one top-level item with no
//! trailing bytes. Optional fields are represented by *absence* of the map key,
//! never by an encoded `null`.
//!
//! Struct fields are keyed by ascending unsigned integers. Key `1` is reserved
//! for the `message_kind` domain string. See [`crate::canonical_struct`].

use crate::error::DecodeError;

/// Decode limits. The command hot path chooses per-message-kind limits; these
/// defaults are conservative (see the specification's parser-limits table).
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum container nesting depth.
    pub max_depth: usize,
    /// Maximum key/value pairs in any one map.
    pub max_map_pairs: u64,
    /// Maximum elements in any one array.
    pub max_array_len: u64,
    /// Maximum length of any one byte string.
    pub max_bytes_len: u64,
    /// Maximum length of any one text string.
    pub max_text_len: u64,
    /// Maximum total encoded size accepted for a single top-level item.
    pub max_total_bytes: usize,
}

impl Limits {
    /// Conservative default limits (16 KiB envelope class).
    pub const DEFAULT: Self = Self {
        max_depth: 8,
        max_map_pairs: 64,
        max_array_len: 256,
        max_bytes_len: 4096,
        max_text_len: 1024,
        max_total_bytes: 16 * 1024,
    };

    /// Larger limits for lease/admission/deployment envelopes (64 KiB class).
    pub const LARGE: Self = Self {
        max_total_bytes: 64 * 1024,
        max_bytes_len: 16 * 1024,
        ..Self::DEFAULT
    };
}

impl Default for Limits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// A value that has exactly one canonical CBOR byte representation.
pub trait CanonicalValue: Sized {
    /// Append the canonical encoding of `self` to `w`.
    fn encode(&self, w: &mut CborWriter);
    /// Decode one value from `r`, enforcing the strict Haldir profile.
    fn decode(r: &mut CborReader<'_>) -> Result<Self, DecodeError>;
}

/// A top-level canonical message with a fixed embedded kind domain.
pub trait CanonicalMessage: CanonicalValue {
    /// Exact `message_kind` value encoded at map key `1`.
    const KIND: &'static str;
    /// Major schema version represented by this Rust message type.
    const SCHEMA_MAJOR: u16;
}

/// Optional semantic validation applied after structural decode.
pub trait Validate {
    /// Return a stable error if a cross-field or version invariant is violated.
    ///
    /// # Errors
    /// Returns [`DecodeError`] when a semantic invariant fails.
    fn validate(&self) -> Result<(), DecodeError> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Writer
// ---------------------------------------------------------------------------

/// Canonical CBOR byte sink.
#[derive(Debug, Default)]
pub struct CborWriter {
    buf: Vec<u8>,
}

impl CborWriter {
    /// A new empty writer.
    #[must_use]
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// Consume the writer, returning the encoded bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    /// Borrow the encoded bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }

    // Truncations below are provably safe: each branch is guarded by the range
    // test immediately preceding the cast.
    #[allow(clippy::cast_possible_truncation)]
    fn head(&mut self, major: u8, val: u64) {
        let mb = major << 5;
        if val < 24 {
            self.buf.push(mb | (val as u8));
        } else if val <= u64::from(u8::MAX) {
            self.buf.push(mb | 24);
            self.buf.push(val as u8);
        } else if val <= u64::from(u16::MAX) {
            self.buf.push(mb | 25);
            self.buf.extend_from_slice(&(val as u16).to_be_bytes());
        } else if val <= u64::from(u32::MAX) {
            self.buf.push(mb | 26);
            self.buf.extend_from_slice(&(val as u32).to_be_bytes());
        } else {
            self.buf.push(mb | 27);
            self.buf.extend_from_slice(&val.to_be_bytes());
        }
    }

    /// Write an unsigned integer (major 0).
    pub fn uint(&mut self, v: u64) {
        self.head(0, v);
    }

    // The `as u64` on a proven-nonnegative i128 cannot truncate.
    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
    /// Write a signed integer (major 0 or 1).
    pub fn int(&mut self, v: i64) {
        if v >= 0 {
            self.head(0, v as u64);
        } else {
            // -1 - v, computed in i128 so i64::MIN does not overflow.
            let n = (-1i128 - i128::from(v)) as u64;
            self.head(1, n);
        }
    }

    /// Write a byte string (major 2).
    pub fn bytes(&mut self, b: &[u8]) {
        self.head(2, b.len() as u64);
        self.buf.extend_from_slice(b);
    }

    /// Write a text string (major 3).
    pub fn text(&mut self, s: &str) {
        self.head(3, s.len() as u64);
        self.buf.extend_from_slice(s.as_bytes());
    }

    /// Write a boolean (major 7, simple 20/21).
    pub fn bool(&mut self, b: bool) {
        self.buf.push(if b { 0xf5 } else { 0xf4 });
    }

    /// Write a definite-length array header (major 4).
    pub fn array_header(&mut self, n: u64) {
        self.head(4, n);
    }

    /// Write a definite-length map header (major 5).
    pub fn map_header(&mut self, n: u64) {
        self.head(5, n);
    }
}

// ---------------------------------------------------------------------------
// Reader
// ---------------------------------------------------------------------------

/// Strict bounded CBOR reader over a borrowed buffer.
#[derive(Debug)]
pub struct CborReader<'a> {
    data: &'a [u8],
    pos: usize,
    depth: usize,
    limits: Limits,
}

impl<'a> CborReader<'a> {
    /// A reader over `data` with the given `limits`.
    #[must_use]
    pub fn new(data: &'a [u8], limits: Limits) -> Self {
        Self {
            data,
            pos: 0,
            depth: 0,
            limits,
        }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        let end = self.pos.checked_add(n).ok_or(DecodeError::UnexpectedEof)?;
        let slice = self
            .data
            .get(self.pos..end)
            .ok_or(DecodeError::UnexpectedEof)?;
        self.pos = end;
        Ok(slice)
    }

    fn take_byte(&mut self) -> Result<u8, DecodeError> {
        let b = self
            .data
            .get(self.pos)
            .copied()
            .ok_or(DecodeError::UnexpectedEof)?;
        self.pos = self.pos.checked_add(1).ok_or(DecodeError::UnexpectedEof)?;
        Ok(b)
    }

    fn read_argument(&mut self, ai: u8) -> Result<u64, DecodeError> {
        match ai {
            0..=23 => Ok(u64::from(ai)),
            24 => {
                let x = u64::from(self.take_byte()?);
                if x < 24 {
                    return Err(DecodeError::NonShortestInt);
                }
                Ok(x)
            }
            25 => {
                let bytes = self.take(2)?;
                let arr: [u8; 2] = bytes.try_into().map_err(|_| DecodeError::UnexpectedEof)?;
                let x = u16::from_be_bytes(arr);
                if x <= u16::from(u8::MAX) {
                    return Err(DecodeError::NonShortestInt);
                }
                Ok(u64::from(x))
            }
            26 => {
                let bytes = self.take(4)?;
                let arr: [u8; 4] = bytes.try_into().map_err(|_| DecodeError::UnexpectedEof)?;
                let x = u32::from_be_bytes(arr);
                if x <= u32::from(u16::MAX) {
                    return Err(DecodeError::NonShortestInt);
                }
                Ok(u64::from(x))
            }
            27 => {
                let bytes = self.take(8)?;
                let arr: [u8; 8] = bytes.try_into().map_err(|_| DecodeError::UnexpectedEof)?;
                let x = u64::from_be_bytes(arr);
                if x <= u64::from(u32::MAX) {
                    return Err(DecodeError::NonShortestInt);
                }
                Ok(x)
            }
            28..=30 => Err(DecodeError::ReservedAdditionalInfo),
            _ => Err(DecodeError::IndefiniteLength), // ai == 31
        }
    }

    /// Read a head for the exact `expect_major`, returning its argument value.
    fn read_head(&mut self, expect_major: u8) -> Result<u64, DecodeError> {
        let b = self.take_byte()?;
        let major = b >> 5;
        let ai = b & 0x1f;
        if major == 7 {
            return Err(match ai {
                25..=27 => DecodeError::FloatNotAllowed,
                28..=30 => DecodeError::ReservedAdditionalInfo,
                31 => DecodeError::IndefiniteLength,
                _ => DecodeError::BadSimpleValue,
            });
        }
        if major == 6 {
            return Err(DecodeError::TagNotAllowed);
        }
        if major != expect_major {
            return Err(DecodeError::UnexpectedMajorType {
                expected: expect_major,
                found: major,
            });
        }
        self.read_argument(ai)
    }

    fn enter(&mut self) -> Result<(), DecodeError> {
        self.depth = self
            .depth
            .checked_add(1)
            .ok_or(DecodeError::DepthExceeded)?;
        if self.depth > self.limits.max_depth {
            return Err(DecodeError::DepthExceeded);
        }
        Ok(())
    }

    /// Signal the end of a container previously opened by `read_map_len`/`read_array_len`.
    pub fn end_container(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }

    /// Read an unsigned integer (major 0).
    ///
    /// # Errors
    /// Returns [`DecodeError`] on non-unsigned, non-shortest, or truncated input.
    pub fn read_uint(&mut self) -> Result<u64, DecodeError> {
        self.read_head(0)
    }

    /// Read a signed integer (major 0 or 1) into an `i128` intermediate.
    ///
    /// # Errors
    /// Returns [`DecodeError`] on non-integer, non-shortest, or truncated input.
    pub fn read_int(&mut self) -> Result<i128, DecodeError> {
        let b = self.take_byte()?;
        let major = b >> 5;
        let ai = b & 0x1f;
        if major == 7 {
            return Err(match ai {
                25..=27 => DecodeError::FloatNotAllowed,
                28..=30 => DecodeError::ReservedAdditionalInfo,
                31 => DecodeError::IndefiniteLength,
                _ => DecodeError::BadSimpleValue,
            });
        }
        if major == 6 {
            return Err(DecodeError::TagNotAllowed);
        }
        let v = self.read_argument(ai)?;
        match major {
            0 => Ok(i128::from(v)),
            1 => Ok(-1i128 - i128::from(v)),
            _ => Err(DecodeError::UnexpectedMajorType {
                expected: 0,
                found: major,
            }),
        }
    }

    /// Read a byte string (major 2).
    ///
    /// # Errors
    /// Returns [`DecodeError`] on wrong type, overlength, or truncation.
    pub fn read_bytes(&mut self) -> Result<&'a [u8], DecodeError> {
        let len = self.read_head(2)?;
        if len > self.limits.max_bytes_len {
            return Err(DecodeError::ByteLenExceeded);
        }
        let n = usize::try_from(len).map_err(|_| DecodeError::ByteLenExceeded)?;
        self.take(n)
    }

    /// Read a text string (major 3), validated as UTF-8.
    ///
    /// # Errors
    /// Returns [`DecodeError`] on wrong type, overlength, non-UTF-8, or truncation.
    pub fn read_text(&mut self) -> Result<&'a str, DecodeError> {
        let len = self.read_head(3)?;
        if len > self.limits.max_text_len {
            return Err(DecodeError::TextLenExceeded);
        }
        let n = usize::try_from(len).map_err(|_| DecodeError::TextLenExceeded)?;
        let bytes = self.take(n)?;
        core::str::from_utf8(bytes).map_err(|_| DecodeError::InvalidUtf8)
    }

    /// Read a boolean (major 7, simple 20/21 only).
    ///
    /// # Errors
    /// Returns [`DecodeError`] on any other value.
    pub fn read_bool(&mut self) -> Result<bool, DecodeError> {
        let b = self.take_byte()?;
        match b {
            0xf4 => Ok(false),
            0xf5 => Ok(true),
            _ => {
                if b >> 5 == 7 {
                    Err(DecodeError::BadSimpleValue)
                } else {
                    Err(DecodeError::UnexpectedMajorType {
                        expected: 7,
                        found: b >> 5,
                    })
                }
            }
        }
    }

    /// Read a definite-length map header and enter one nesting level.
    ///
    /// # Errors
    /// Returns [`DecodeError`] on wrong type, too many pairs, or depth exceeded.
    pub fn read_map_len(&mut self) -> Result<u64, DecodeError> {
        let n = self.read_head(5)?;
        if n > self.limits.max_map_pairs {
            return Err(DecodeError::MapPairsExceeded);
        }
        self.enter()?;
        Ok(n)
    }

    /// Read a definite-length array header and enter one nesting level.
    ///
    /// # Errors
    /// Returns [`DecodeError`] on wrong type, too many elements, or depth exceeded.
    pub fn read_array_len(&mut self) -> Result<u64, DecodeError> {
        let n = self.read_head(4)?;
        if n > self.limits.max_array_len {
            return Err(DecodeError::ArrayLenExceeded);
        }
        self.enter()?;
        Ok(n)
    }

    /// Read an unsigned map key (major 0 only).
    ///
    /// # Errors
    /// Returns [`DecodeError::MapKeyNotUnsigned`] for any non-unsigned key.
    pub fn read_map_key(&mut self) -> Result<u64, DecodeError> {
        let b = self.take_byte()?;
        let major = b >> 5;
        let ai = b & 0x1f;
        if major != 0 {
            return Err(DecodeError::MapKeyNotUnsigned);
        }
        self.read_argument(ai)
    }

    /// Assert the input is fully consumed (no trailing bytes).
    ///
    /// # Errors
    /// Returns [`DecodeError::TrailingBytes`] if bytes remain.
    pub fn finish(&self) -> Result<(), DecodeError> {
        if self.pos == self.data.len() {
            Ok(())
        } else {
            Err(DecodeError::TrailingBytes)
        }
    }
}

// ---------------------------------------------------------------------------
// Primitive CanonicalValue impls
// ---------------------------------------------------------------------------

impl CanonicalValue for u64 {
    fn encode(&self, w: &mut CborWriter) {
        w.uint(*self);
    }
    fn decode(r: &mut CborReader<'_>) -> Result<Self, DecodeError> {
        r.read_uint()
    }
}

impl CanonicalValue for u32 {
    fn encode(&self, w: &mut CborWriter) {
        w.uint(u64::from(*self));
    }
    fn decode(r: &mut CborReader<'_>) -> Result<Self, DecodeError> {
        Self::try_from(r.read_uint()?).map_err(|_| DecodeError::IntOutOfRange)
    }
}

impl CanonicalValue for u16 {
    fn encode(&self, w: &mut CborWriter) {
        w.uint(u64::from(*self));
    }
    fn decode(r: &mut CborReader<'_>) -> Result<Self, DecodeError> {
        Self::try_from(r.read_uint()?).map_err(|_| DecodeError::IntOutOfRange)
    }
}

impl CanonicalValue for u8 {
    fn encode(&self, w: &mut CborWriter) {
        w.uint(u64::from(*self));
    }
    fn decode(r: &mut CborReader<'_>) -> Result<Self, DecodeError> {
        Self::try_from(r.read_uint()?).map_err(|_| DecodeError::IntOutOfRange)
    }
}

impl CanonicalValue for i32 {
    fn encode(&self, w: &mut CborWriter) {
        w.int(i64::from(*self));
    }
    fn decode(r: &mut CborReader<'_>) -> Result<Self, DecodeError> {
        Self::try_from(r.read_int()?).map_err(|_| DecodeError::IntOutOfRange)
    }
}

impl CanonicalValue for i64 {
    fn encode(&self, w: &mut CborWriter) {
        w.int(*self);
    }
    fn decode(r: &mut CborReader<'_>) -> Result<Self, DecodeError> {
        Self::try_from(r.read_int()?).map_err(|_| DecodeError::IntOutOfRange)
    }
}

impl CanonicalValue for bool {
    fn encode(&self, w: &mut CborWriter) {
        w.bool(*self);
    }
    fn decode(r: &mut CborReader<'_>) -> Result<Self, DecodeError> {
        r.read_bool()
    }
}

impl CanonicalValue for core::num::NonZeroU32 {
    fn encode(&self, w: &mut CborWriter) {
        w.uint(u64::from(self.get()));
    }
    fn decode(r: &mut CborReader<'_>) -> Result<Self, DecodeError> {
        let v = u32::try_from(r.read_uint()?).map_err(|_| DecodeError::IntOutOfRange)?;
        Self::new(v).ok_or(DecodeError::ZeroForNonZero)
    }
}

impl CanonicalValue for core::num::NonZeroU64 {
    fn encode(&self, w: &mut CborWriter) {
        w.uint(self.get());
    }
    fn decode(r: &mut CborReader<'_>) -> Result<Self, DecodeError> {
        Self::new(r.read_uint()?).ok_or(DecodeError::ZeroForNonZero)
    }
}

impl<const N: usize> CanonicalValue for [u8; N] {
    fn encode(&self, w: &mut CborWriter) {
        w.bytes(self);
    }
    fn decode(r: &mut CborReader<'_>) -> Result<Self, DecodeError> {
        let bytes = r.read_bytes()?;
        Self::try_from(bytes).map_err(|_| DecodeError::BadLength {
            expected: N,
            found: bytes.len(),
        })
    }
}

// ---------------------------------------------------------------------------
// Top-level envelope helpers
// ---------------------------------------------------------------------------

/// Encode a value to its canonical bytes.
#[must_use]
pub fn to_canonical_bytes<T: CanonicalValue>(v: &T) -> Vec<u8> {
    let mut w = CborWriter::new();
    v.encode(&mut w);
    w.into_bytes()
}

/// Decode a single top-level value, enforcing limits, no trailing bytes,
/// semantic validation, and byte-exact canonical re-encoding equality.
///
/// # Errors
/// Returns [`DecodeError`] if the bytes are oversize, non-canonical, structurally
/// invalid, semantically invalid, or do not round-trip to identical bytes.
pub fn from_canonical_bytes<T: CanonicalValue + Validate>(
    bytes: &[u8],
    limits: Limits,
) -> Result<T, DecodeError> {
    if bytes.len() > limits.max_total_bytes {
        return Err(DecodeError::ByteLenExceeded);
    }
    let mut r = CborReader::new(bytes, limits);
    let value = T::decode(&mut r)?;
    r.finish()?;
    value.validate()?;
    let re = to_canonical_bytes(&value);
    if re != bytes {
        return Err(DecodeError::SemanticInvalid {
            code: "DECODE_NON_CANONICAL_REENCODE",
        });
    }
    Ok(value)
}
