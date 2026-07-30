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

/// A standard duration is too large for Haldir's nanosecond counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct MonoDurationOverflow;

impl MonoDurationOverflow {
    /// Stable machine-readable failure class.
    #[must_use]
    pub const fn reason_code(self) -> &'static str {
        "MONO_DURATION_OVERFLOW"
    }
}

impl std::fmt::Display for MonoDurationOverflow {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for MonoDurationOverflow {}

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
        let duration = MonoDuration::checked_from_millis(ms)?;
        self.checked_add_duration(duration)
    }

    /// `self + duration`, or `None` on overflow.
    #[must_use]
    pub const fn checked_add_duration(self, duration: MonoDuration) -> Option<Self> {
        match self.0.checked_add(duration.0) {
            Some(nanos) => Some(Self(nanos)),
            None => None,
        }
    }

    /// `self - earlier` as a duration, or `None` if `self < earlier` (a monotonic
    /// clock regression — the caller must treat this as a fault, never as fresh).
    #[must_use]
    pub fn checked_duration_since(self, earlier: Self) -> Option<MonoDuration> {
        self.0.checked_sub(earlier.0).map(MonoDuration)
    }
}

impl TryFrom<std::time::Duration> for MonoDuration {
    type Error = MonoDurationOverflow;

    fn try_from(duration: std::time::Duration) -> Result<Self, Self::Error> {
        u64::try_from(duration.as_nanos())
            .map(Self)
            .map_err(|_| MonoDurationOverflow)
    }
}

impl From<MonoDuration> for std::time::Duration {
    fn from(duration: MonoDuration) -> Self {
        Self::from_nanos(duration.0)
    }
}

impl MonoDuration {
    /// Construct from an exact nanosecond count.
    #[must_use]
    pub const fn from_nanos(ns: u64) -> Self {
        Self(ns)
    }

    /// Construct from milliseconds, or return `None` if the nanosecond value
    /// cannot be represented.
    #[must_use]
    pub const fn checked_from_millis(ms: u64) -> Option<Self> {
        match ms.checked_mul(1_000_000) {
            Some(ns) => Some(Self(ns)),
            None => None,
        }
    }

    /// Construct from milliseconds, saturating explicitly at the largest
    /// representable monotonic duration.
    #[must_use]
    pub const fn saturating_from_millis(ms: u64) -> Self {
        Self(ms.saturating_mul(1_000_000))
    }

    /// Construct from milliseconds, saturating at the largest representable
    /// duration.
    ///
    /// New authorization code should choose
    /// [`MonoDuration::checked_from_millis`] or
    /// [`MonoDuration::saturating_from_millis`] explicitly.
    #[must_use]
    #[deprecated(
        since = "0.1.0-experimental",
        note = "use checked_from_millis or saturating_from_millis explicitly"
    )]
    pub const fn from_millis(ms: u64) -> Self {
        Self::saturating_from_millis(ms)
    }

    /// The whole milliseconds in this duration (truncating).
    #[must_use]
    pub const fn as_millis(self) -> u64 {
        self.0 / 1_000_000
    }

    /// Milliseconds in this duration, rounded up.
    #[must_use]
    pub const fn as_millis_ceil(self) -> u64 {
        self.0.div_ceil(1_000_000)
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

#[cfg(test)]
mod tests {
    use super::{MonoDuration, MonoDurationOverflow, MonoInstant};

    #[test]
    fn exact_nanosecond_duration_preserves_fractional_milliseconds() {
        let duration = MonoDuration::from_nanos(2_000_001);
        assert_eq!(duration.as_nanos(), 2_000_001);
        assert_eq!(duration.as_millis(), 2);
        assert_eq!(duration.as_millis_ceil(), 3);
    }

    #[test]
    fn checked_and_saturating_millisecond_construction_are_explicit() {
        let largest_exact_ms = u64::MAX / 1_000_000;
        assert_eq!(
            MonoDuration::checked_from_millis(largest_exact_ms).map(MonoDuration::as_nanos),
            Some(largest_exact_ms * 1_000_000)
        );
        assert_eq!(
            MonoDuration::checked_from_millis(largest_exact_ms + 1),
            None
        );
        assert_eq!(
            MonoDuration::saturating_from_millis(u64::MAX).as_nanos(),
            u64::MAX
        );
    }

    #[test]
    fn ceiling_conversion_handles_the_largest_duration_without_overflow() {
        assert_eq!(
            MonoDuration::from_nanos(u64::MAX).as_millis_ceil(),
            u64::MAX / 1_000_000 + 1
        );
    }

    #[test]
    fn millisecond_boundaries_floor_and_ceil_without_loss() {
        let cases = [
            (0, 0, 0),
            (1, 0, 1),
            (999_999, 0, 1),
            (1_000_000, 1, 1),
            (1_000_001, 1, 2),
            (u64::MAX, u64::MAX / 1_000_000, u64::MAX / 1_000_000 + 1),
        ];
        for (nanoseconds, floor, ceiling) in cases {
            let duration = MonoDuration::from_nanos(nanoseconds);
            assert_eq!(duration.as_millis(), floor);
            assert_eq!(duration.as_millis_ceil(), ceiling);
        }
    }

    #[test]
    fn exact_duration_addition_checks_instant_overflow() {
        assert_eq!(
            MonoInstant::from_nanos(7)
                .checked_add_duration(MonoDuration::from_nanos(11))
                .map(MonoInstant::as_nanos),
            Some(18)
        );
        assert_eq!(
            MonoInstant::from_nanos(u64::MAX).checked_add_duration(MonoDuration::from_nanos(1)),
            None
        );
    }

    #[test]
    fn standard_duration_conversion_is_exact_and_checked() {
        fn assert_standard_error<T: std::error::Error + Send + Sync + 'static>() {}
        assert_standard_error::<MonoDurationOverflow>();

        let standard = std::time::Duration::new(4, 123);
        let monotonic = MonoDuration::try_from(standard).unwrap();
        assert_eq!(monotonic.as_nanos(), 4_000_000_123);
        assert_eq!(std::time::Duration::from(monotonic), standard);

        let too_large = std::time::Duration::from_secs(u64::MAX);
        assert_eq!(MonoDuration::try_from(too_large), Err(MonoDurationOverflow));
        assert_eq!(MonoDurationOverflow.to_string(), "MONO_DURATION_OVERFLOW");
    }
}
