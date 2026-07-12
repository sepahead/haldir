//! Policy input and bounded action history.

use crate::policy::NativePolicySnapshot;
use haldir_contracts::action::RequestedActionV1;
use haldir_core::snapshot::{ActiveMissionLeaseSnapshot, TrustedStateSnapshotV1};
use haldir_core::time::MonoInstant;

/// A published-command interval used for duty accounting.
#[derive(Debug, Clone, Copy)]
pub struct PublishedInterval {
    /// Interval start (publish time).
    pub start: MonoInstant,
    /// Interval end (start + effective validity).
    pub end: MonoInstant,
}

/// Bounded history the policy consults for slew and duty. The gate updates it
/// only at output allocation (H7): the slew reference is the last **published**
/// command, never the last requested/denied one.
#[derive(Debug, Clone, Default)]
pub struct BoundedActionHistory {
    /// The last published velocity command (slew reference), if any.
    pub last_published_velocity_mm_s: Option<[i32; 3]>,
    /// Recent published non-hold intervals (bounded ring).
    pub active_intervals: Vec<PublishedInterval>,
    /// Maximum retained intervals.
    pub max_intervals: usize,
}

impl BoundedActionHistory {
    /// A fresh bounded history.
    #[must_use]
    pub fn new(max_intervals: usize) -> Self {
        Self {
            last_published_velocity_mm_s: None,
            active_intervals: Vec::new(),
            max_intervals,
        }
    }

    /// Record a published non-hold command interval and set the slew reference.
    /// Evicts intervals fully before `window_start` and the oldest if over bound.
    pub fn record_velocity(
        &mut self,
        velocity_mm_s: [i32; 3],
        start: MonoInstant,
        end: MonoInstant,
        window_start: MonoInstant,
    ) {
        self.last_published_velocity_mm_s = Some(velocity_mm_s);
        self.active_intervals.retain(|i| i.end > window_start);
        self.active_intervals.push(PublishedInterval { start, end });
        while self.active_intervals.len() > self.max_intervals {
            self.active_intervals.remove(0);
        }
    }

    /// Record a published hold (clears the velocity slew reference).
    pub fn record_hold(&mut self) {
        self.last_published_velocity_mm_s = None;
    }

    /// Milliseconds of non-hold activity overlapping `[window_start, now]`.
    #[must_use]
    pub fn active_ms_in_window(&self, window_start: MonoInstant, now: MonoInstant) -> u64 {
        let mut total: u64 = 0;
        for i in &self.active_intervals {
            let lo = i.start.max(window_start);
            let hi = i.end.min(now);
            if let Some(d) = hi.checked_duration_since(lo) {
                total = total.saturating_add(d.as_millis());
            }
        }
        total
    }
}

/// The fully-typed policy input assembled by the gate.
#[derive(Debug, Clone)]
pub struct PolicyInput<'a> {
    /// Current monotonic time.
    pub now: MonoInstant,
    /// The active mission lease snapshot.
    pub lease: &'a ActiveMissionLeaseSnapshot,
    /// The trusted state snapshot.
    pub state: &'a TrustedStateSnapshotV1,
    /// The requested action.
    pub action: &'a RequestedActionV1,
    /// Bounded action history.
    pub history: &'a BoundedActionHistory,
    /// Compiled native policy parameters.
    pub policy: &'a NativePolicySnapshot,
}
