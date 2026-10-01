//! Fixed-point (mm/s) to NCP-wire (m/s float) conversion.
//!
//! Labeled `FIXED_POINT_TO_NCP_FLOAT_V1`, never `IDENTITY`, because a decimal
//! division is involved (spec P6/H17). The conversion is finite, monotone, and
//! bounds-preserving; the property tests below *sample* the `i32` domain, and the
//! round-trip is exact analytically (`i32` is representable exactly in `f64` and
//! the division error is well under 0.5 mm/s). A full-domain exhaustive sweep is
//! available as an `#[ignore]`d test (`round_trip_exact_full_domain`).
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::float_arithmetic
)]

use crate::error::NcpAdapterError;

/// Convert a millimetre-per-second fixed-point component to an NCP metre-per-second
/// wire value.
#[must_use]
pub fn mm_s_to_ncp_m_s(mm_s: i32) -> f64 {
    // i32 is represented exactly in f64; division by 1000 rounds to nearest f64.
    f64::from(mm_s) / 1000.0
}

/// Recover one fixed-point value from the exact image of
/// [`mm_s_to_ncp_m_s`].
///
/// # Errors
/// Returns [`NcpAdapterError::ConversionOutOfRange`] for a non-finite value,
/// a value outside the `i32` millimetre-per-second domain, or a finite value
/// that is not the exact binary64 projection of an integer mm/s component.
pub fn ncp_m_s_to_mm_s(m_s: f64) -> Result<i32, NcpAdapterError> {
    if !m_s.is_finite() {
        return Err(NcpAdapterError::ConversionOutOfRange);
    }
    let scaled = (m_s * 1000.0).round();
    if scaled > f64::from(i32::MAX) || scaled < f64::from(i32::MIN) {
        return Err(NcpAdapterError::ConversionOutOfRange);
    }
    let fixed = scaled as i32;
    if mm_s_to_ncp_m_s(fixed).to_bits() != m_s.to_bits() {
        return Err(NcpAdapterError::ConversionOutOfRange);
    }
    Ok(fixed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn conversion_is_finite_and_bounded(x in any::<i32>()) {
            let y = mm_s_to_ncp_m_s(x);
            prop_assert!(y.is_finite());
            prop_assert!(y.abs() <= f64::from(i32::MAX) / 1000.0 + 1.0);
        }

        #[test]
        fn conversion_is_monotone(a in any::<i32>(), b in any::<i32>()) {
            if a <= b {
                prop_assert!(mm_s_to_ncp_m_s(a) <= mm_s_to_ncp_m_s(b));
            }
        }

        #[test]
        fn round_trip_is_exact(x in any::<i32>()) {
            prop_assert_eq!(ncp_m_s_to_mm_s(mm_s_to_ncp_m_s(x)), Ok(x));
        }
    }

    #[test]
    #[ignore = "exhaustive full-i32 domain sweep (~4.3e9 iterations); run with --ignored"]
    fn round_trip_exact_full_domain() {
        let mut x = i32::MIN;
        loop {
            assert_eq!(ncp_m_s_to_mm_s(mm_s_to_ncp_m_s(x)), Ok(x));
            if x == i32::MAX {
                break;
            }
            x += 1;
        }
    }

    #[test]
    fn zero_and_signs() {
        assert!((mm_s_to_ncp_m_s(0) - 0.0).abs() < f64::EPSILON);
        assert!(mm_s_to_ncp_m_s(-1000) < 0.0);
        assert!(mm_s_to_ncp_m_s(1000) > 0.0);
        assert_eq!(ncp_m_s_to_mm_s(1.0), Ok(1000));
    }

    #[test]
    fn reverse_conversion_rejects_non_finite_out_of_range_and_non_image_values() {
        for value in [
            f64::NAN,
            f64::INFINITY,
            f64::NEG_INFINITY,
            (f64::from(i32::MAX) + 1.0) / 1000.0,
            (f64::from(i32::MIN) - 1.0) / 1000.0,
            0.000_4,
            -0.0,
        ] {
            assert_eq!(
                ncp_m_s_to_mm_s(value),
                Err(NcpAdapterError::ConversionOutOfRange)
            );
        }
    }
}
