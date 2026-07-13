//! Policy input and bounded action history.

use crate::policy::NativePolicySnapshot;
use haldir_contracts::action::RequestedActionV1;
use haldir_core::snapshot::{ActiveMissionLeaseSnapshot, TrustedStateSnapshotV1};
use haldir_core::time::{MonoDuration, MonoInstant};

/// A published-command interval used for duty accounting.
#[derive(Debug, Clone, Copy)]
pub struct PublishedInterval {
    /// Interval start (publish time).
    pub start: MonoInstant,
    /// Interval end (start + effective validity).
    pub end: MonoInstant,
}

/// Bounded history the policy consults for slew and duty. The gate updates it
/// only after the caller reports modeled publication returned-ok (H7): the slew
/// reference is the last **published** command, never the last
/// requested/denied/prepared one.
///
/// `active_intervals` is kept as a sorted set of **disjoint** intervals — the
/// union of the possibly-active published non-hold horizons (H-P02/H-P03).
/// Storing the union (rather than one entry per command) both removes the
/// double-counting a naive sum would incur and keeps a high-rate command stream
/// bounded, since back-to-back commands collapse into a single interval.
#[derive(Debug, Clone, Default)]
pub struct BoundedActionHistory {
    /// The last published velocity command (slew reference), if any.
    pub last_published_velocity_mm_s: Option<[i32; 3]>,
    /// Monotonic publish time of the slew reference. The admissible velocity
    /// change is bounded by the ACTUAL elapsed time since this instant, not a
    /// static nominal period (H-P01).
    pub last_published_at: Option<MonoInstant>,
    /// Disjoint, sorted, unioned published non-hold intervals.
    pub active_intervals: Vec<PublishedInterval>,
    /// Maximum retained disjoint intervals.
    pub max_intervals: usize,
}

impl BoundedActionHistory {
    /// A fresh bounded history.
    #[must_use]
    pub fn new(max_intervals: usize) -> Self {
        Self {
            last_published_velocity_mm_s: None,
            last_published_at: None,
            active_intervals: Vec::new(),
            max_intervals,
        }
    }

    /// Record a published non-hold command interval and set the slew reference.
    /// Evicts intervals fully before `window_start`, unions the new interval into
    /// the disjoint set, and — if that would exceed the retained bound — merges the
    /// closest pair rather than dropping one (fail-closed: dropping would
    /// under-count duty and defeat the limit, H-B04).
    pub fn record_velocity(
        &mut self,
        velocity_mm_s: [i32; 3],
        start: MonoInstant,
        end: MonoInstant,
        window_start: MonoInstant,
    ) {
        self.last_published_velocity_mm_s = Some(velocity_mm_s);
        self.last_published_at = Some(start);
        self.insert_active_interval(start, end, window_start);
    }

    /// Record a published hold. The vehicle is commanded to stop, so the slew
    /// reference becomes zero velocity: a subsequent velocity command must ramp up
    /// from rest within the slew limit, never unconstrained (a prior `None`
    /// reference silently skipped the slew check). A hold contributes no non-hold
    /// duty, so no active interval is added.
    pub fn record_hold(&mut self, at: MonoInstant) {
        self.last_published_velocity_mm_s = Some([0, 0, 0]);
        self.last_published_at = Some(at);
    }

    /// Clear the slew reference at an authority boundary (lease accept / revoke).
    /// A new lease must not inherit the previous mission's last-published velocity
    /// as a slew reference — that mission's authority has ended and the vehicle's
    /// true velocity is no longer known to the Gate. The first velocity command of
    /// the new lease is then bounded by the absolute component/norm/speed caps
    /// (its slew reference is established by that first published command). The
    /// duty window is left intact: it is time-based and reflects real motion that
    /// does not vanish at a lease boundary.
    pub fn clear_slew_reference(&mut self) {
        self.last_published_velocity_mm_s = None;
        self.last_published_at = None;
    }

    /// Actual elapsed milliseconds since the slew reference was published, floored
    /// (a shorter interval permits a smaller change — conservative), zero on a
    /// clock regression or when there is no reference, and capped at
    /// `nominal_update_ms` so a stale reference cannot grant an unbounded step
    /// (H-P01). Below the cap the bound tracks real elapsed time, closing the
    /// hole where bursts faster than nominal were granted a full nominal step.
    #[must_use]
    pub fn slew_elapsed_ms(&self, now: MonoInstant, nominal_update_ms: u32) -> u64 {
        let actual = self
            .last_published_at
            .and_then(|t| now.checked_duration_since(t))
            .map_or(0, MonoDuration::as_millis);
        actual.min(u64::from(nominal_update_ms))
    }

    /// Milliseconds of non-hold activity overlapping `[window_start, now]`. Because
    /// `active_intervals` is a disjoint union, this sum never double-counts.
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

    /// Union `[start, end]` into the disjoint interval set after evicting anything
    /// entirely before `window_start`, then enforce the retained bound.
    fn insert_active_interval(
        &mut self,
        start: MonoInstant,
        end: MonoInstant,
        window_start: MonoInstant,
    ) {
        self.active_intervals.retain(|i| i.end > window_start);
        let mut merged = PublishedInterval { start, end };
        let mut disjoint: Vec<PublishedInterval> = Vec::new();
        for iv in self.active_intervals.drain(..) {
            // Overlapping or touching intervals fold into `merged`; the rest stay.
            if iv.end < merged.start || iv.start > merged.end {
                disjoint.push(iv);
            } else {
                merged.start = merged.start.min(iv.start);
                merged.end = merged.end.max(iv.end);
            }
        }
        disjoint.push(merged);
        disjoint.sort_by_key(|i| i.start.as_nanos());
        self.active_intervals = disjoint;
        // Fail-closed bounding: never silently drop an active interval. Merging the
        // smallest-gap pair over-approximates duty (it counts the gap as active),
        // which can only deny more, never allow more (H-B04).
        while self.active_intervals.len() > self.max_intervals.max(1) {
            self.merge_closest_pair();
        }
    }

    /// Merge the adjacent pair (sorted by start) separated by the smallest gap.
    fn merge_closest_pair(&mut self) {
        let best = self
            .active_intervals
            .windows(2)
            .enumerate()
            .min_by_key(|&(_, w)| match w {
                [a, b] => b.start.as_nanos().saturating_sub(a.end.as_nanos()),
                _ => u64::MAX,
            })
            .map(|(i, _)| i);
        let Some(best) = best else {
            return;
        };
        let b = self.active_intervals.remove(best + 1);
        if let Some(a) = self.active_intervals.get_mut(best) {
            a.start = a.start.min(b.start);
            a.end = a.end.max(b.end);
        }
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
