//! Bounded scalar types: ASCII identifiers, routing strings, fixed-point units,
//! canonical UUIDv4 strings, and bounded collections.
//!
//! Constructors reject empty, overlength, whitespace/control, and non-ASCII input.
//! Each type has exactly one canonical CBOR encoding.

use crate::cbor::{CanonicalValue, CborReader, CborWriter, to_canonical_bytes};
use crate::error::DecodeError;

/// A bounded ASCII security identifier: non-empty, `<= N` bytes, drawn from
/// `[A-Za-z0-9._:-]`. Whitespace, control bytes, and non-ASCII are rejected.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct AsciiId<const N: usize>(String);

impl<const N: usize> AsciiId<N> {
    /// Construct, validating length and character set.
    ///
    /// # Errors
    /// Returns [`DecodeError::InvalidIdentifier`] on empty, overlength, or a byte
    /// outside `[A-Za-z0-9._:-]`.
    pub fn new(s: &str) -> Result<Self, DecodeError> {
        if s.is_empty() || s.len() > N {
            return Err(DecodeError::InvalidIdentifier);
        }
        if !s.bytes().all(Self::allowed) {
            return Err(DecodeError::InvalidIdentifier);
        }
        Ok(Self(s.to_owned()))
    }

    const fn allowed(b: u8) -> bool {
        b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b':')
    }

    /// Borrow the identifier text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<const N: usize> CanonicalValue for AsciiId<N> {
    fn encode(&self, w: &mut CborWriter) {
        w.text(&self.0);
    }
    fn decode(r: &mut CborReader<'_>) -> Result<Self, DecodeError> {
        Self::new(r.read_text()?)
    }
}

/// A bounded printable-ASCII string (graphic bytes `0x21..=0x7E`), used for
/// routing keys where `/`, `*`-free concrete paths appear. Non-empty, `<= N`.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct BoundedAscii<const N: usize>(String);

impl<const N: usize> BoundedAscii<N> {
    /// Construct, validating length and printable-ASCII character set.
    ///
    /// # Errors
    /// Returns [`DecodeError::InvalidIdentifier`] on empty, overlength, or a
    /// non-graphic-ASCII byte.
    pub fn new(s: &str) -> Result<Self, DecodeError> {
        if s.is_empty() || s.len() > N {
            return Err(DecodeError::InvalidIdentifier);
        }
        if !s.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
            return Err(DecodeError::InvalidIdentifier);
        }
        Ok(Self(s.to_owned()))
    }

    /// Borrow the string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<const N: usize> CanonicalValue for BoundedAscii<N> {
    fn encode(&self, w: &mut CborWriter) {
        w.text(&self.0);
    }
    fn decode(r: &mut CborReader<'_>) -> Result<Self, DecodeError> {
        Self::new(r.read_text()?)
    }
}

// ---------------------------------------------------------------------------
// Fixed-point unit newtypes (no floats anywhere in signed contracts)
// ---------------------------------------------------------------------------

macro_rules! int_unit {
    ($(#[$m:meta])* $name:ident, $inner:ty) => {
        $(#[$m])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(pub $inner);
        impl $name {
            /// The underlying integer value.
            #[must_use]
            pub const fn get(self) -> $inner {
                self.0
            }
        }
        impl CanonicalValue for $name {
            fn encode(&self, w: &mut CborWriter) {
                <$inner as CanonicalValue>::encode(&self.0, w);
            }
            fn decode(r: &mut CborReader<'_>) -> Result<Self, DecodeError> {
                Ok(Self(<$inner as CanonicalValue>::decode(r)?))
            }
        }
    };
}

int_unit!(
    /// Linear velocity component, millimetres per second.
    MillimetresPerSecond, i32);
int_unit!(
    /// Linear acceleration/slew, millimetres per second squared.
    MillimetresPerSecondSquared, i32);
int_unit!(
    /// A duration in milliseconds.
    Milliseconds, u32);
int_unit!(
    /// A local monotonic instant/duration in nanoseconds.
    MonotonicNanoseconds, u64);

// ---------------------------------------------------------------------------
// Canonical UUIDv4 string
// ---------------------------------------------------------------------------

/// A UUID rendered in canonical lowercase hyphenated form with version 4 and an
/// RFC 4122 variant. Encoded as a text string; there is one canonical rendering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CanonicalUuidV4String([u8; 16]);

impl CanonicalUuidV4String {
    /// Build a v4 UUID from 16 random bytes, forcing the version and variant bits.
    #[must_use]
    pub fn from_random_bytes(mut b: [u8; 16]) -> Self {
        if let Some(x) = b.get_mut(6) {
            *x = (*x & 0x0f) | 0x40; // version 4
        }
        if let Some(x) = b.get_mut(8) {
            *x = (*x & 0x3f) | 0x80; // variant 10xx
        }
        Self(b)
    }

    /// The 16 raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    fn hex_val(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            _ => None,
        }
    }

    /// Parse a canonical lowercase v4 UUID string.
    ///
    /// # Errors
    /// Returns [`DecodeError::BadUuid`] on any format, version, or variant error.
    pub fn parse(s: &str) -> Result<Self, DecodeError> {
        let bytes = s.as_bytes();
        if bytes.len() != 36 {
            return Err(DecodeError::BadUuid);
        }
        let mut out = [0u8; 16];
        let mut oi = 0usize;
        let mut i = 0usize;
        while i < 36 {
            if matches!(i, 8 | 13 | 18 | 23) {
                if bytes.get(i) != Some(&b'-') {
                    return Err(DecodeError::BadUuid);
                }
                i += 1;
                continue;
            }
            let hi = Self::hex_val(*bytes.get(i).ok_or(DecodeError::BadUuid)?)
                .ok_or(DecodeError::BadUuid)?;
            let lo = Self::hex_val(*bytes.get(i + 1).ok_or(DecodeError::BadUuid)?)
                .ok_or(DecodeError::BadUuid)?;
            *out.get_mut(oi).ok_or(DecodeError::BadUuid)? = (hi << 4) | lo;
            oi += 1;
            i += 2;
        }
        // version 4, variant 10xx
        if out.get(6).map(|b| b & 0xf0) != Some(0x40) {
            return Err(DecodeError::BadUuid);
        }
        if out.get(8).map(|b| b & 0xc0) != Some(0x80) {
            return Err(DecodeError::BadUuid);
        }
        Ok(Self(out))
    }

    /// Render the canonical lowercase hyphenated string.
    #[must_use]
    pub fn render(&self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut s = String::with_capacity(36);
        for (idx, byte) in self.0.iter().enumerate() {
            if matches!(idx, 4 | 6 | 8 | 10) {
                s.push('-');
            }
            let hi = HEX.get(usize::from(byte >> 4)).copied().unwrap_or(b'0');
            let lo = HEX.get(usize::from(byte & 0x0f)).copied().unwrap_or(b'0');
            s.push(char::from(hi));
            s.push(char::from(lo));
        }
        s
    }
}

impl CanonicalValue for CanonicalUuidV4String {
    fn encode(&self, w: &mut CborWriter) {
        w.text(&self.render());
    }
    fn decode(r: &mut CborReader<'_>) -> Result<Self, DecodeError> {
        Self::parse(r.read_text()?)
    }
}

// ---------------------------------------------------------------------------
// Bounded collections
// ---------------------------------------------------------------------------

/// A `Vec<T>` bounded to at most `N` elements. Encoded as a definite-length array.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BoundedVec<T, const N: usize>(Vec<T>);

impl<T, const N: usize> BoundedVec<T, N> {
    /// An empty bounded vector.
    #[must_use]
    pub const fn new() -> Self {
        Self(Vec::new())
    }

    /// Wrap a vector, rejecting more than `N` elements.
    ///
    /// # Errors
    /// Returns [`DecodeError::BoundExceeded`] if `v.len() > N`.
    pub fn from_vec(v: Vec<T>) -> Result<Self, DecodeError> {
        if v.len() > N {
            return Err(DecodeError::BoundExceeded);
        }
        Ok(Self(v))
    }

    /// Borrow the elements.
    #[must_use]
    pub fn as_slice(&self) -> &[T] {
        &self.0
    }

    /// Number of elements.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the collection is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl<T, const N: usize> Default for BoundedVec<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: CanonicalValue, const N: usize> CanonicalValue for BoundedVec<T, N> {
    fn encode(&self, w: &mut CborWriter) {
        w.array_header(self.0.len() as u64);
        for item in &self.0 {
            item.encode(w);
        }
    }
    fn decode(r: &mut CborReader<'_>) -> Result<Self, DecodeError> {
        let n = r.read_array_len()?;
        let n_usize = usize::try_from(n).map_err(|_| DecodeError::BoundExceeded)?;
        if n_usize > N {
            return Err(DecodeError::BoundExceeded);
        }
        let mut v = Vec::with_capacity(n_usize);
        for _ in 0..n_usize {
            v.push(T::decode(r)?);
        }
        r.end_container();
        Ok(Self(v))
    }
}

/// A canonical set: at most `N` elements, encoded as a definite-length array in
/// strictly ascending canonical-byte order with no duplicates.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BoundedSet<T, const N: usize>(Vec<T>);

impl<T: CanonicalValue, const N: usize> BoundedSet<T, N> {
    /// An empty set.
    #[must_use]
    pub const fn new() -> Self {
        Self(Vec::new())
    }

    /// Build a canonical set from any iterator, sorting by canonical bytes and
    /// removing duplicates.
    ///
    /// # Errors
    /// Returns [`DecodeError::BoundExceeded`] if the deduplicated set exceeds `N`.
    pub fn from_iter_checked<I: IntoIterator<Item = T>>(items: I) -> Result<Self, DecodeError> {
        let mut v: Vec<T> = items.into_iter().collect();
        v.sort_by_key(to_canonical_bytes);
        v.dedup_by(|a, b| to_canonical_bytes(a) == to_canonical_bytes(b));
        if v.len() > N {
            return Err(DecodeError::BoundExceeded);
        }
        Ok(Self(v))
    }

    /// Borrow the (sorted, unique) elements.
    #[must_use]
    pub fn as_slice(&self) -> &[T] {
        &self.0
    }

    /// Number of elements.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the set is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Whether `item` is present (by canonical bytes).
    #[must_use]
    pub fn contains(&self, item: &T) -> bool {
        let target = to_canonical_bytes(item);
        self.0.iter().any(|e| to_canonical_bytes(e) == target)
    }
}

impl<T: CanonicalValue, const N: usize> Default for BoundedSet<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: CanonicalValue, const N: usize> CanonicalValue for BoundedSet<T, N> {
    fn encode(&self, w: &mut CborWriter) {
        w.array_header(self.0.len() as u64);
        for item in &self.0 {
            item.encode(w);
        }
    }
    fn decode(r: &mut CborReader<'_>) -> Result<Self, DecodeError> {
        let n = r.read_array_len()?;
        let n_usize = usize::try_from(n).map_err(|_| DecodeError::BoundExceeded)?;
        if n_usize > N {
            return Err(DecodeError::BoundExceeded);
        }
        let mut v: Vec<T> = Vec::with_capacity(n_usize);
        let mut prev: Option<Vec<u8>> = None;
        for _ in 0..n_usize {
            let item = T::decode(r)?;
            let bytes = to_canonical_bytes(&item);
            if let Some(p) = &prev
                && &bytes <= p
            {
                return Err(DecodeError::SemanticInvalid {
                    code: "DECODE_SET_UNSORTED_OR_DUP",
                });
            }
            prev = Some(bytes);
            v.push(item);
        }
        r.end_container();
        Ok(Self(v))
    }
}
