//! Monotonic time types and an injectable clock.
//!
//! The only time suitable for hot-path validity is Gate's local monotonic clock
//! (spec T1). Wall-clock and controller timestamps are diagnostic only.

/// A monotonic instant, nanoseconds from an arbitrary per-boot origin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MonoInstant(u64);

/// A monotonic duration in nanoseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MonoDuration(u64);

impl MonoInstant {
    /// Construct from a nanosecond count.
    #[must_use]
    pub const fn from_nanos(n: u64) -> Self {
        Self(n)
    }

    /// The nanosecond count.
    #[must_use]
    pub const fn as_nanos(self) -> u64 {
        self.0
    }

    /// `self + ms` milliseconds, or `None` on overflow.
    #[must_use]
    pub fn checked_add_ms(self, ms: u64) -> Option<Self> {
        let add_ns = ms.checked_mul(1_000_000)?;
        self.0.checked_add(add_ns).map(Self)
    }

    /// `self - earlier` as a duration, or `None` if `self < earlier` (a monotonic
    /// clock regression — the caller must treat this as a fault, never as fresh).
    #[must_use]
    pub fn checked_duration_since(self, earlier: Self) -> Option<MonoDuration> {
        self.0.checked_sub(earlier.0).map(MonoDuration)
    }
}

impl MonoDuration {
    /// Construct from milliseconds.
    #[must_use]
    pub const fn from_millis(ms: u64) -> Self {
        Self(ms.saturating_mul(1_000_000))
    }

    /// The whole milliseconds in this duration (truncating).
    #[must_use]
    pub const fn as_millis(self) -> u64 {
        self.0 / 1_000_000
    }

    /// The nanoseconds in this duration.
    #[must_use]
    pub const fn as_nanos(self) -> u64 {
        self.0
    }
}

/// An injectable monotonic clock. Tests use a deterministic clock.
pub trait MonotonicClock {
    /// The current monotonic instant. MUST be nondecreasing within one boot.
    fn now(&self) -> MonoInstant;
}
