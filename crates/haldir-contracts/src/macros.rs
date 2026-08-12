//! Declarative macros that generate canonical CBOR `struct` encoders/decoders.
//!
//! Two forms:
//! * `canonical_struct! { pub struct T kind "haldir.x" { req 2 a: A, opt 3 b: B } }`
//!   — a top-level signed message; map key `1` carries the `message_kind` domain
//!   string and is verified on decode.
//! * `canonical_struct! { pub struct T { req 1 a: A, opt 2 b: B } }`
//!   — a nested value with no `message_kind`; fields may start at key `1`.
//!
//! Field keys MUST be declared in strictly ascending order (key `1` reserved for
//! `message_kind` in the first form). The macro enforces this at compile time.
//! Emission follows declaration order, which is therefore canonical ascending
//! order. Optional fields are omitted when `None`.

/// Field storage type: `T` for `req`, `Option<T>` for `opt`.
#[macro_export]
#[doc(hidden)]
macro_rules! __hc_field_ty {
    (req $ty:ty) => { $ty };
    (opt $ty:ty) => { ::core::option::Option<$ty> };
}

/// The decoded "raw" type (always `T`).
#[macro_export]
#[doc(hidden)]
macro_rules! __hc_raw_ty {
    (req $ty:ty) => {
        $ty
    };
    (opt $ty:ty) => {
        $ty
    };
}

/// Increment the map-entry count for a present field.
#[macro_export]
#[doc(hidden)]
macro_rules! __hc_count {
    ($c:ident $self:ident req $f:ident) => {
        $c += 1;
    };
    ($c:ident $self:ident opt $f:ident) => {
        if $self.$f.is_some() {
            $c += 1;
        }
    };
}

/// Encode one field entry (`key`, then value) when present.
#[macro_export]
#[doc(hidden)]
macro_rules! __hc_encode {
    ($w:ident $self:ident req $key:literal $f:ident) => {
        $w.uint($key);
        $crate::cbor::CanonicalValue::encode(&$self.$f, $w);
    };
    ($w:ident $self:ident opt $key:literal $f:ident) => {
        if let ::core::option::Option::Some(v) = &$self.$f {
            $w.uint($key);
            $crate::cbor::CanonicalValue::encode(v, $w);
        }
    };
}

/// Build the final field value, requiring presence for `req`.
#[macro_export]
#[doc(hidden)]
macro_rules! __hc_build {
    (req $key:literal $f:ident) => {
        $f.ok_or($crate::error::DecodeError::MissingField { key: $key })?
    };
    (opt $key:literal $f:ident) => {
        $f
    };
}

/// Generate a `u64`-tagged fieldless enum with a stable string `code()`, a wire
/// `tag()`, and a canonical encoding. Used for reason codes, stages, and other
/// closed discriminant enums. Numeric tags and machine codes are compile-time
/// unique.
#[macro_export]
macro_rules! tagged_enum {
    (
        $(#[$m:meta])*
        $vis:vis enum $name:ident {
            $( $variant:ident = $tag:literal => $code:literal ),+ $(,)?
        }
    ) => {
        // Every index is guarded by the adjacent loop bound. Const iteration is
        // intentionally written without runtime Option handling so a malformed
        // schema fails during compilation.
        #[allow(clippy::indexing_slicing)]
        const _: () = {
            const fn same_bytes(left: &str, right: &str) -> bool {
                let left = left.as_bytes();
                let right = right.as_bytes();
                if left.len() != right.len() {
                    return false;
                }
                let mut index = 0;
                while index < left.len() {
                    if left[index] != right[index] {
                        return false;
                    }
                    index += 1;
                }
                true
            }

            let tags: &[u64] = &[$( $tag ),+];
            let codes: &[&str] = &[$( $code ),+];
            let mut left = 0;
            while left < tags.len() {
                let mut right = left + 1;
                while right < tags.len() {
                    assert!(
                        tags[left] != tags[right],
                        "tagged_enum numeric tags must be unique"
                    );
                    assert!(
                        !same_bytes(codes[left], codes[right]),
                        "tagged_enum machine codes must be unique"
                    );
                    right += 1;
                }
                left += 1;
            }
        };

        $(#[$m])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[non_exhaustive]
        $vis enum $name {
            $( #[doc = $code] $variant ),+
        }
        impl $name {
            /// Stable machine-readable code string.
            #[must_use]
            pub const fn code(self) -> &'static str {
                match self { $( Self::$variant => $code ),+ }
            }
            /// Numeric wire tag.
            #[must_use]
            pub const fn tag(self) -> u64 {
                match self { $( Self::$variant => $tag ),+ }
            }
        }
        impl $crate::cbor::CanonicalValue for $name {
            fn encode(&self, w: &mut $crate::cbor::CborWriter) {
                w.uint(self.tag());
            }
            fn decode(r: &mut $crate::cbor::CborReader<'_>)
                -> ::core::result::Result<Self, $crate::error::DecodeError>
            {
                match r.read_uint()? {
                    $( $tag => ::core::result::Result::Ok(Self::$variant), )+
                    _ => ::core::result::Result::Err($crate::error::DecodeError::BadEnumTag),
                }
            }
        }
    };
}

/// Generate a canonical CBOR struct with or without a `message_kind` domain.
#[macro_export]
macro_rules! canonical_struct {
    // ---- form with message_kind ----
    (
        $(#[$smeta:meta])*
        $vis:vis struct $name:ident kind $kind:literal {
            $( $mode:ident $key:literal $field:ident : $ty:ty ),+ $(,)?
        }
    ) => {
        // Every index is guarded by the adjacent loop bound. Const iteration is
        // intentionally written without runtime Option handling so a malformed
        // schema fails during compilation.
        #[allow(clippy::indexing_slicing)]
        const _: () = {
            let keys: &[u64] = &[1, $( $key ),+];
            let mut index = 1;
            while index < keys.len() {
                assert!(
                    keys[index] > keys[index - 1],
                    "canonical_struct field keys must be strictly ascending and greater than reserved message-kind key 1"
                );
                index += 1;
            }
        };

        $(#[$smeta])*
        #[derive(Debug, Clone, PartialEq, Eq)]
        $vis struct $name {
            $(
                #[doc = concat!(
                    "Canonical `", stringify!($field), "` field at map key `",
                    stringify!($key), "`."
                )]
                pub $field : $crate::__hc_field_ty!($mode $ty),
            )+
        }

        impl $name {
            /// The `message_kind` domain string embedded at map key `1`.
            pub const KIND: &'static str = $kind;
        }

        impl $crate::cbor::CanonicalMessage for $name {
            const KIND: &'static str = $kind;
            const SCHEMA_MAJOR: u16 = 1;
        }

        impl $crate::cbor::CanonicalValue for $name {
            fn encode(&self, w: &mut $crate::cbor::CborWriter) {
                let mut count: u64 = 1;
                $( $crate::__hc_count!(count self $mode $field); )+
                w.map_header(count);
                w.uint(1);
                w.text(Self::KIND);
                $( $crate::__hc_encode!(w self $mode $key $field); )+
            }
            fn decode(r: &mut $crate::cbor::CborReader<'_>)
                -> ::core::result::Result<Self, $crate::error::DecodeError>
            {
                let n = r.read_map_len()?;
                let mut kind_seen = false;
                $( let mut $field : ::core::option::Option<$crate::__hc_raw_ty!($mode $ty)>
                    = ::core::option::Option::None; )+
                let mut last: ::core::option::Option<u64> = ::core::option::Option::None;
                for _ in 0..n {
                    let k = r.read_map_key()?;
                    if let ::core::option::Option::Some(p) = last {
                        if k <= p {
                            return ::core::result::Result::Err(
                                $crate::error::DecodeError::NonCanonicalMapOrder);
                        }
                    }
                    last = ::core::option::Option::Some(k);
                    match k {
                        1 => {
                            let s = r.read_text()?;
                            if s != Self::KIND {
                                return ::core::result::Result::Err(
                                    $crate::error::DecodeError::WrongMessageKind);
                            }
                            kind_seen = true;
                        }
                        $( $key => {
                            if $field.is_some() {
                                return ::core::result::Result::Err(
                                    $crate::error::DecodeError::DuplicateField { key: k });
                            }
                            $field = ::core::option::Option::Some(
                                <$crate::__hc_raw_ty!($mode $ty) as $crate::cbor::CanonicalValue>::decode(r)?);
                        } )+
                        other => return ::core::result::Result::Err(
                            $crate::error::DecodeError::UnknownField { key: other }),
                    }
                }
                r.end_container();
                if !kind_seen {
                    return ::core::result::Result::Err(
                        $crate::error::DecodeError::MissingField { key: 1 });
                }
                ::core::result::Result::Ok(Self {
                    $( $field : $crate::__hc_build!($mode $key $field), )+
                })
            }
        }
    };

    // ---- form without message_kind (nested value) ----
    (
        $(#[$smeta:meta])*
        $vis:vis struct $name:ident {
            $( $mode:ident $key:literal $field:ident : $ty:ty ),+ $(,)?
        }
    ) => {
        // Every index is guarded by the adjacent loop bound. Const iteration is
        // intentionally written without runtime Option handling so a malformed
        // schema fails during compilation.
        #[allow(clippy::indexing_slicing)]
        const _: () = {
            let keys: &[u64] = &[0, $( $key ),+];
            let mut index = 1;
            while index < keys.len() {
                assert!(
                    keys[index] > keys[index - 1],
                    "canonical_struct field keys must be nonzero and strictly ascending"
                );
                index += 1;
            }
        };

        $(#[$smeta])*
        #[derive(Debug, Clone, PartialEq, Eq)]
        $vis struct $name {
            $(
                #[doc = concat!(
                    "Canonical `", stringify!($field), "` field at map key `",
                    stringify!($key), "`."
                )]
                pub $field : $crate::__hc_field_ty!($mode $ty),
            )+
        }

        impl $crate::cbor::CanonicalValue for $name {
            fn encode(&self, w: &mut $crate::cbor::CborWriter) {
                let mut count: u64 = 0;
                $( $crate::__hc_count!(count self $mode $field); )+
                w.map_header(count);
                $( $crate::__hc_encode!(w self $mode $key $field); )+
            }
            fn decode(r: &mut $crate::cbor::CborReader<'_>)
                -> ::core::result::Result<Self, $crate::error::DecodeError>
            {
                let n = r.read_map_len()?;
                $( let mut $field : ::core::option::Option<$crate::__hc_raw_ty!($mode $ty)>
                    = ::core::option::Option::None; )+
                let mut last: ::core::option::Option<u64> = ::core::option::Option::None;
                for _ in 0..n {
                    let k = r.read_map_key()?;
                    if let ::core::option::Option::Some(p) = last {
                        if k <= p {
                            return ::core::result::Result::Err(
                                $crate::error::DecodeError::NonCanonicalMapOrder);
                        }
                    }
                    last = ::core::option::Option::Some(k);
                    match k {
                        $( $key => {
                            if $field.is_some() {
                                return ::core::result::Result::Err(
                                    $crate::error::DecodeError::DuplicateField { key: k });
                            }
                            $field = ::core::option::Option::Some(
                                <$crate::__hc_raw_ty!($mode $ty) as $crate::cbor::CanonicalValue>::decode(r)?);
                        } )+
                        other => return ::core::result::Result::Err(
                            $crate::error::DecodeError::UnknownField { key: other }),
                    }
                }
                r.end_container();
                ::core::result::Result::Ok(Self {
                    $( $field : $crate::__hc_build!($mode $key $field), )+
                })
            }
        }
    };
}
