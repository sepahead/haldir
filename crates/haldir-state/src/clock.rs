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
        self.ns
            .fetch_add(ms.saturating_mul(1_000_000), Ordering::SeqCst);
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
