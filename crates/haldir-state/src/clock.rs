//! Monotonic clock implementations.

use core::sync::atomic::{AtomicU64, Ordering};
use haldir_core::time::{MonoInstant, MonotonicClock};
use std::time::Instant;

/// A real monotonic clock anchored at construction.
#[derive(Debug)]
pub struct SystemMonotonicClock {
    origin: Instant,
}

impl SystemMonotonicClock {
    /// A clock whose zero is now.
    #[must_use]
    pub fn new() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl Default for SystemMonotonicClock {
    fn default() -> Self {
        Self::new()
    }
}

impl MonotonicClock for SystemMonotonicClock {
    fn now(&self) -> MonoInstant {
        // `Instant` is monotonic; nanos since origin fit u64 for ~584 years.
        let ns = u64::try_from(self.origin.elapsed().as_nanos()).unwrap_or(u64::MAX);
        MonoInstant::from_nanos(ns)
    }
}

/// A deterministic test clock. It can be advanced or, for fault tests, moved
/// backward (which the Gate must treat as a fault, never as fresh).
#[derive(Debug)]
pub struct TestClock {
    ns: AtomicU64,
}

impl TestClock {
    /// A test clock starting at `start_ns`.
    #[must_use]
    pub fn new(start_ns: u64) -> Self {
        Self {
            ns: AtomicU64::new(start_ns),
        }
    }

    /// Advance by `ms` milliseconds.
    pub fn advance_ms(&self, ms: u64) {
        let delta_ns = ms.saturating_mul(1_000_000);
        // `AtomicU64::fetch_add` wraps at the namespace boundary. A test clock
        // advertised as monotonic must instead remain pinned at the last
        // representable instant; otherwise an overflow can accidentally model a
        // clock regression unrelated to the behavior under test.
        let _ = self
            .ns
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
                Some(current.saturating_add(delta_ns))
            });
    }

    /// Set the absolute nanosecond value (may move backward for fault testing).
    pub fn set_ns(&self, ns: u64) {
        self.ns.store(ns, Ordering::SeqCst);
    }
}

impl MonotonicClock for TestClock {
    fn now(&self) -> MonoInstant {
        MonoInstant::from_nanos(self.ns.load(Ordering::SeqCst))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clock_advance_saturates_instead_of_wrapping() {
        let clock = TestClock::new(u64::MAX - 500_000);

        clock.advance_ms(1);
        assert_eq!(clock.now().as_nanos(), u64::MAX);

        clock.advance_ms(u64::MAX);
        assert_eq!(clock.now().as_nanos(), u64::MAX);
    }
}
