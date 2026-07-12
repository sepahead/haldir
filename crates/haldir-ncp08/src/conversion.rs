//! Fixed-point (mm/s) to NCP-wire (m/s float) conversion.
//!
//! Labeled `FIXED_POINT_TO_NCP_FLOAT_V1`, never `IDENTITY`, because a decimal
//! division is involved (spec P6/H17). The conversion is proven finite, monotone,
//! bounds-preserving, and exactly recoverable by round-to-nearest over the full
//! `i32` domain by the property tests below.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::float_arithmetic
)]

/// Convert a millimetre-per-second fixed-point component to an NCP metre-per-second
/// wire value.
#[must_use]
pub fn mm_s_to_ncp_m_s(mm_s: i32) -> f64 {
    // i32 is represented exactly in f64; division by 1000 rounds to nearest f64.
    f64::from(mm_s) / 1000.0
}

/// Recover the fixed-point value from a wire value by round-to-nearest. For values
/// produced by [`mm_s_to_ncp_m_s`] over the `i32` domain this is exact.
#[must_use]
pub fn ncp_m_s_to_mm_s(m_s: f64) -> i32 {
    let scaled = (m_s * 1000.0).round();
    if scaled >= f64::from(i32::MAX) {
        i32::MAX
    } else if scaled <= f64::from(i32::MIN) {
        i32::MIN
    } else {
        scaled as i32
    }
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
            prop_assert_eq!(ncp_m_s_to_mm_s(mm_s_to_ncp_m_s(x)), x);
        }
    }

    #[test]
    fn zero_and_signs() {
        assert!((mm_s_to_ncp_m_s(0) - 0.0).abs() < f64::EPSILON);
        assert!(mm_s_to_ncp_m_s(-1000) < 0.0);
        assert!(mm_s_to_ncp_m_s(1000) > 0.0);
        assert_eq!(ncp_m_s_to_mm_s(1.0), 1000);
    }
}
