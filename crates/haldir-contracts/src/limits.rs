//! Nested limit/version value types shared by several contracts.

use crate::ids::OutputSeq;
use core::num::{NonZeroU32, NonZeroU64};

canonical_struct! {
    /// A supported Haldir contract schema version.
    pub struct ContractVersion {
        req 1 major: u16,
        req 2 minor: u16,
    }
}

canonical_struct! {
    /// The numeric limits carried by a mission lease. A lease may be stricter than
    /// the policy package but never looser; effective bounds are the intersection
    /// of lease, policy, admission, NCP, and plant limits.
    pub struct MissionLeaseLimitsV1 {
        req 1 max_output_validity_ms: NonZeroU32,
        req 2 max_linear_speed_mm_s: NonZeroU32,
        req 3 max_linear_accel_mm_s2: NonZeroU32,
        req 4 max_linear_slew_mm_s2: NonZeroU32,
        req 5 max_source_age_ms: NonZeroU32,
        req 6 max_state_age_ms: NonZeroU32,
        req 7 max_continuous_motion_ms: NonZeroU32,
        req 8 minimum_hold_between_bursts_ms: u32,
    }
}

// A convenience re-export so downstream code that constructs an initial output
// stream can name a starting sequence without importing `core::num` directly.
/// The first valid output sequence (`1`).
#[must_use]
pub fn first_output_seq() -> OutputSeq {
    OutputSeq::new(NonZeroU64::MIN)
}
