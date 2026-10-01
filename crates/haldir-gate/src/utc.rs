//! The wall clock behind the UTC bounds of Gate's NCP commander lease.
//!
//! UTC never decides expiry inside Gate; the monotonic deadline does. The body
//! derives its deadline from the lease's UTC interval, so Gate acquires no new
//! term while it cannot read UTC.

use std::time::{SystemTime, UNIX_EPOCH};

/// A source of the current UTC time.
pub trait UtcClock: Send {
    /// Milliseconds since the Unix epoch, or `None` when unavailable.
    fn now_utc_ms(&self) -> Option<u64>;
}

/// The operating-system wall clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemUtcClock;

impl UtcClock for SystemUtcClock {
    fn now_utc_ms(&self) -> Option<u64> {
        let since_epoch = SystemTime::now().duration_since(UNIX_EPOCH).ok()?;
        u64::try_from(since_epoch.as_millis()).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_system_clock_reads_a_plausible_utc_time() {
        let first = SystemUtcClock.now_utc_ms().unwrap();
        assert!(first > 1_700_000_000_000, "after November 2023");
        assert!(SystemUtcClock.now_utc_ms().unwrap() >= first);
    }
}
