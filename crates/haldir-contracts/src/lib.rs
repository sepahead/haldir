//! `haldir-contracts` — stable, NCP-independent Haldir wire contracts and a
//! strict, bounded, deterministic CBOR codec.
//!
//! This crate defines the semantic authority/intent/evidence types Haldir signs
//! and validates. It deliberately does **not** depend on any NCP-generated type
//! (punch-list H15): `NcpSessionIdentityV1` and `NcpSourceRefV1` are Haldir's own
//! stable types; the `haldir-ncp08` adapter converts them to the wire.
//!
//! Every accepted contract has exactly one canonical byte encoding. See
//! [`cbor`] for the deterministic profile and [`canonical_struct`] for the
//! struct-generating macro.
#![forbid(unsafe_code)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::float_cmp,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss
    )
)]

#[macro_use]
mod macros;

pub mod action;
pub mod cbor;
pub mod challenge;
pub mod deployment;
pub mod digest;
pub mod error;
pub mod ids;
pub mod intent;
pub mod lease;
pub mod limits;
pub mod publication;
pub mod receipt;
pub mod revocation;
pub mod scalar;
pub mod session;
pub mod status;

/// Crate version string.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub use cbor::{
    CanonicalValue, CborReader, CborWriter, Limits, Validate, from_canonical_bytes,
    to_canonical_bytes,
};
pub use error::DecodeError;

#[cfg(test)]
mod tests_contracts;

#[cfg(test)]
mod fuzz_smoke {
    //! The hostile parser must never panic, overflow, or over-allocate on arbitrary
    //! bytes (spec Phase D "fuzz targets before network ingress" / punch-list H11).
    //! Decoding must always return `Ok`/`Err`, never unwind.
    use super::*;
    use crate::challenge::GateChallengeV1;
    use crate::intent::HaldirIntentV1;
    use crate::lease::MissionLeaseV1;
    use crate::publication::PublicationStageEventV1;
    use crate::receipt::DecisionReceiptV1;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(4000))]

        #[test]
        fn decoder_never_panics_on_arbitrary_bytes(bytes in proptest::collection::vec(any::<u8>(), 0..2048)) {
            // Each of these returns a Result; the test passes iff none unwinds.
            let _ = from_canonical_bytes::<HaldirIntentV1>(&bytes, Limits::DEFAULT);
            let _ = from_canonical_bytes::<MissionLeaseV1>(&bytes, Limits::LARGE);
            let _ = from_canonical_bytes::<GateChallengeV1>(&bytes, Limits::LARGE);
            let _ = from_canonical_bytes::<DecisionReceiptV1>(&bytes, Limits::LARGE);
            let _ = from_canonical_bytes::<PublicationStageEventV1>(&bytes, Limits::LARGE);
        }

        #[test]
        fn one_bit_flips_of_a_valid_intent_never_panic(i in 0usize..4096, bit in 0u8..8) {
            // Mutate a valid encoding and re-decode: must be Ok(different)/Err, never panic.
            let base = to_canonical_bytes(&crate::tests_contracts::intent());
            if i < base.len() {
                let mut m = base.clone();
                m[i] ^= 1u8 << (bit % 8);
                let _ = from_canonical_bytes::<HaldirIntentV1>(&m, Limits::LARGE);
            }
        }
    }
}

#[cfg(test)]
mod codec_tests {
    use super::*;
    use crate::action::RequestedActionV1;
    use crate::cbor::{CanonicalValue, CborReader, Limits};
    use crate::scalar::CanonicalUuidV4String;
    use crate::session::NcpSessionIdentityV1;
    use core::num::NonZeroU32;

    fn roundtrip<T: CanonicalValue + PartialEq + core::fmt::Debug>(v: &T) -> Vec<u8> {
        let bytes = to_canonical_bytes(v);
        let mut r = CborReader::new(&bytes, Limits::DEFAULT);
        let back = T::decode(&mut r).expect("decode");
        r.finish().expect("no trailing");
        assert_eq!(&back, v, "roundtrip mismatch");
        assert_eq!(to_canonical_bytes(&back), bytes);
        bytes
    }

    #[test]
    fn uuid_roundtrip_and_v4_bits() {
        let u = CanonicalUuidV4String::from_random_bytes([0xABu8; 16]);
        let s = u.render();
        assert_eq!(s.len(), 36);
        assert_eq!(s.as_bytes()[14], b'4');
        assert!(matches!(s.as_bytes()[19], b'8' | b'9' | b'a' | b'b'));
        let back = CanonicalUuidV4String::parse(&s).expect("parse");
        assert_eq!(back, u);
    }

    #[test]
    fn session_roundtrip() {
        let v = NcpSessionIdentityV1 {
            session_id: crate::scalar::AsciiId::new("sess-1").unwrap(),
            generation: CanonicalUuidV4String::from_random_bytes([7u8; 16]),
        };
        roundtrip(&v);
    }

    #[test]
    fn action_hold_and_velocity_roundtrip() {
        roundtrip(&RequestedActionV1::Hold {
            requested_validity_ms: NonZeroU32::new(500).unwrap(),
        });
        roundtrip(&RequestedActionV1::VelocityLocalNed {
            north_mm_s: -1234,
            east_mm_s: 0,
            down_mm_s: 987,
            requested_validity_ms: NonZeroU32::new(200).unwrap(),
        });
    }

    #[test]
    fn rejects_trailing_bytes() {
        let mut bytes = to_canonical_bytes(&RequestedActionV1::Hold {
            requested_validity_ms: NonZeroU32::new(1).unwrap(),
        });
        bytes.push(0x00);
        let mut r = CborReader::new(&bytes, Limits::DEFAULT);
        let _ = RequestedActionV1::decode(&mut r).expect("decode");
        assert_eq!(r.finish(), Err(DecodeError::TrailingBytes));
    }

    #[test]
    fn rejects_non_shortest_int() {
        let bytes = [0x18u8, 0x05];
        let mut r = CborReader::new(&bytes, Limits::DEFAULT);
        assert_eq!(r.read_uint(), Err(DecodeError::NonShortestInt));
    }

    #[test]
    fn rejects_indefinite_length() {
        let bytes = [0x9fu8];
        let mut r = CborReader::new(&bytes, Limits::DEFAULT);
        assert_eq!(r.read_array_len(), Err(DecodeError::IndefiniteLength));
    }

    #[test]
    fn rejects_float() {
        let bytes = [0xfau8, 0, 0, 0, 0];
        let mut r = CborReader::new(&bytes, Limits::DEFAULT);
        assert_eq!(r.read_int(), Err(DecodeError::FloatNotAllowed));
    }

    #[test]
    fn rejects_tag() {
        let bytes = [0xc0u8, 0x00];
        let mut r = CborReader::new(&bytes, Limits::DEFAULT);
        assert_eq!(r.read_uint(), Err(DecodeError::TagNotAllowed));
    }
}
