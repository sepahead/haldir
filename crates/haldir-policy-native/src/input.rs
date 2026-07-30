//! Policy input and bounded action history.

use crate::policy::{NativePolicySnapshot, ValidatedNativePolicy};
use haldir_contracts::action::RequestedActionV1;
use haldir_core::snapshot::{ActiveMissionLeaseSnapshot, TrustedStateSnapshotV1};
use haldir_core::time::{MonoDuration, MonoInstant};

/// Maximum retained disjoint duty intervals supported by the native policy.
///
/// The integrated Gate uses this exact bound. Smaller bounds are permitted and
/// become conservatively restrictive through closest-gap compression.
pub const MAX_RETAINED_ACTIVE_INTERVALS: usize = 64;

/// A retained action-history validation or arithmetic failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ActionHistoryError {
    /// The retained interval capacity is zero or exceeds the hard policy bound.
    InvalidCapacity,
    /// More intervals are present than the configured retained capacity.
    CapacityExceeded,
    /// The history's configured retention window is zero.
    InvalidRetentionWindow,
    /// An expected policy window differs from the history's owned window.
    RetentionWindowMismatch,
    /// An interval is empty or has an end before its start.
    InvalidInterval,
    /// A published interval starts after the evaluation instant.
    FutureInterval,
    /// Intervals are unsorted, overlap, or touch instead of forming a canonical union.
    NonCanonicalHistory,
    /// The slew-reference value and timestamp are not both present or both absent.
    InconsistentSlewReference,
    /// The retained slew reference was published after the evaluation instant.
    FutureSlewReference,
    /// A publication was recorded after the evaluation or next-record instant.
    FutureRecord,
    /// Retained intervals are not covered by the publication high-water mark.
    InconsistentRecordHighWater,
    /// Exact duration accumulation exceeded its representation.
    ArithmeticOverflow,
}

impl ActionHistoryError {
    /// Stable machine-readable failure class.
    #[must_use]
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::InvalidCapacity => "ACTION_HISTORY_INVALID_CAPACITY",
            Self::CapacityExceeded => "ACTION_HISTORY_CAPACITY_EXCEEDED",
            Self::InvalidRetentionWindow => "ACTION_HISTORY_INVALID_RETENTION_WINDOW",
            Self::RetentionWindowMismatch => "ACTION_HISTORY_RETENTION_WINDOW_MISMATCH",
            Self::InvalidInterval => "ACTION_HISTORY_INVALID_INTERVAL",
            Self::FutureInterval => "ACTION_HISTORY_FUTURE_INTERVAL",
            Self::NonCanonicalHistory => "ACTION_HISTORY_NON_CANONICAL_HISTORY",
            Self::InconsistentSlewReference => "ACTION_HISTORY_INCONSISTENT_SLEW_REFERENCE",
            Self::FutureSlewReference => "ACTION_HISTORY_FUTURE_SLEW_REFERENCE",
            Self::FutureRecord => "ACTION_HISTORY_FUTURE_RECORD",
            Self::InconsistentRecordHighWater => "ACTION_HISTORY_INCONSISTENT_RECORD_HIGH_WATER",
            Self::ArithmeticOverflow => "ACTION_HISTORY_ARITHMETIC_OVERFLOW",
        }
    }
}

impl std::fmt::Display for ActionHistoryError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for ActionHistoryError {}

/// A half-open published-command interval used for duty accounting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublishedInterval {
    /// Interval start (publish time).
    pub(crate) start: MonoInstant,
    /// Exclusive interval end (start + effective validity).
    pub(crate) end: MonoInstant,
}

impl PublishedInterval {
    /// Construct a non-empty half-open interval.
    ///
    /// # Errors
    /// Returns [`ActionHistoryError::InvalidInterval`] unless `start < end`.
    pub(crate) fn new(start: MonoInstant, end: MonoInstant) -> Result<Self, ActionHistoryError> {
        if start >= end {
            return Err(ActionHistoryError::InvalidInterval);
        }
        Ok(Self { start, end })
    }

    /// Inclusive start of the published horizon.
    #[must_use]
    pub const fn start(self) -> MonoInstant {
        self.start
    }

    /// Exclusive end of the published horizon.
    #[must_use]
    pub const fn end(self) -> MonoInstant {
        self.end
    }
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundedActionHistory {
    /// The last published velocity command (slew reference), if any.
    pub(crate) last_published_velocity_mm_s: Option<[i32; 3]>,
    /// Monotonic publish time of the slew reference. The admissible velocity
    /// change is bounded by the ACTUAL elapsed time since this instant, not a
    /// static nominal period (H-P01).
    pub(crate) last_published_at: Option<MonoInstant>,
    /// Monotonic high-water mark for every recorded publication. Unlike the slew
    /// reference, this survives authority-boundary resets.
    pub(crate) last_recorded_at: Option<MonoInstant>,
    /// Disjoint, sorted, unioned published non-hold intervals.
    pub(crate) active_intervals: Vec<PublishedInterval>,
    /// Maximum retained disjoint intervals.
    pub(crate) max_intervals: usize,
    /// Exact owned rolling-window duration.
    pub(crate) retention_window: MonoDuration,
}

impl BoundedActionHistory {
    /// Construct a fresh history with an exact nonzero retention window.
    ///
    /// # Errors
    /// Returns [`ActionHistoryError::InvalidCapacity`] when `max_intervals` is
    /// zero or exceeds [`MAX_RETAINED_ACTIVE_INTERVALS`], or
    /// [`ActionHistoryError::InvalidRetentionWindow`] for a zero window.
    pub fn new(
        max_intervals: usize,
        retention_window: MonoDuration,
    ) -> Result<Self, ActionHistoryError> {
        if !(1..=MAX_RETAINED_ACTIVE_INTERVALS).contains(&max_intervals) {
            return Err(ActionHistoryError::InvalidCapacity);
        }
        if retention_window.as_nanos() == 0 {
            return Err(ActionHistoryError::InvalidRetentionWindow);
        }
        Ok(Self {
            last_published_velocity_mm_s: None,
            last_published_at: None,
            last_recorded_at: None,
            active_intervals: Vec::new(),
            max_intervals,
            retention_window,
        })
    }

    /// The last published velocity command, if the history has a slew reference.
    #[must_use]
    pub const fn last_published_velocity_mm_s(&self) -> Option<[i32; 3]> {
        self.last_published_velocity_mm_s
    }

    /// Monotonic publish instant of the slew reference.
    #[must_use]
    pub const fn last_published_at(&self) -> Option<MonoInstant> {
        self.last_published_at
    }

    /// Monotonic high-water mark for recorded publications.
    #[must_use]
    pub const fn last_recorded_at(&self) -> Option<MonoInstant> {
        self.last_recorded_at
    }

    /// Canonical retained duty intervals.
    #[must_use]
    pub fn active_intervals(&self) -> &[PublishedInterval] {
        &self.active_intervals
    }

    /// Maximum number of retained disjoint intervals.
    #[must_use]
    pub const fn max_intervals(&self) -> usize {
        self.max_intervals
    }

    /// Exact rolling duty window owned by this history.
    #[must_use]
    pub const fn retention_window(&self) -> MonoDuration {
        self.retention_window
    }

    /// Record a published non-hold command interval and set the slew reference.
    /// The eviction cutoff is derived internally from the owned retention window;
    /// callers cannot supply a cutoff that discards live history. Validation is
    /// transactional: every error leaves the history unchanged.
    ///
    /// # Errors
    /// Returns an [`ActionHistoryError`] for a malformed existing history, a
    /// monotonic regression, or a non-positive new interval.
    pub fn record_velocity(
        &mut self,
        velocity_mm_s: [i32; 3],
        start: MonoInstant,
        end: MonoInstant,
    ) -> Result<(), ActionHistoryError> {
        self.validate_at(start)?;
        let interval = PublishedInterval::new(start, end)?;
        let window_start = self.window_start(start);

        self.insert_active_interval(interval, window_start);
        self.last_published_velocity_mm_s = Some(velocity_mm_s);
        self.last_published_at = Some(start);
        self.last_recorded_at = Some(start);
        Ok(())
    }

    /// Record a published hold. The vehicle is commanded to stop, so the slew
    /// reference becomes zero velocity: a subsequent velocity command must ramp up
    /// from rest within the slew limit, never unconstrained (a prior `None`
    /// reference silently skipped the slew check). A hold contributes no non-hold
    /// duty, so no active interval is added.
    ///
    /// # Errors
    /// Returns an [`ActionHistoryError`] if retained history is malformed or
    /// `at` regresses behind its publication high-water. The history is unchanged
    /// on failure.
    pub fn record_hold(&mut self, at: MonoInstant) -> Result<(), ActionHistoryError> {
        self.validate_at(at)?;
        self.last_published_velocity_mm_s = Some([0, 0, 0]);
        self.last_published_at = Some(at);
        self.last_recorded_at = Some(at);
        Ok(())
    }

    /// Clear the slew reference at an authority boundary (lease accept / revoke).
    /// A new lease must not inherit the previous mission's last-published velocity
    /// as a slew reference — that mission's authority has ended and the vehicle's
    /// true velocity is no longer known to the Gate. The first velocity command of
    /// the new lease is then bounded by the absolute component/norm/speed caps
    /// (its slew reference is established by that first published command). The
    /// duty window is left intact: it reflects conservatively charged,
    /// locally-reported published-command horizons, which do not vanish at a
    /// lease boundary. It does not claim downstream acceptance or application.
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

    /// Validate the complete canonical history at `now`.
    ///
    /// An interval end after `now` is valid: a previously published command may
    /// still be active and is clipped by accounting. Its start may not be in the
    /// future.
    ///
    /// # Errors
    /// Returns the first invariant failure without mutating history.
    pub fn validate_at(&self, now: MonoInstant) -> Result<(), ActionHistoryError> {
        if !(1..=MAX_RETAINED_ACTIVE_INTERVALS).contains(&self.max_intervals) {
            return Err(ActionHistoryError::InvalidCapacity);
        }
        if self.active_intervals.len() > self.max_intervals {
            return Err(ActionHistoryError::CapacityExceeded);
        }
        if self.retention_window.as_nanos() == 0 {
            return Err(ActionHistoryError::InvalidRetentionWindow);
        }
        if self.last_recorded_at.is_some_and(|at| at > now) {
            return Err(ActionHistoryError::FutureRecord);
        }
        match (self.last_published_velocity_mm_s, self.last_published_at) {
            (Some(_), Some(at)) if at > now => {
                return Err(ActionHistoryError::FutureSlewReference);
            }
            (Some(_), Some(at)) if self.last_recorded_at == Some(at) => {}
            (None, None) => {}
            _ => return Err(ActionHistoryError::InconsistentSlewReference),
        }
        if !self.active_intervals.is_empty() && self.last_recorded_at.is_none() {
            return Err(ActionHistoryError::InconsistentRecordHighWater);
        }

        let mut previous_end = None;
        for interval in &self.active_intervals {
            if interval.start >= interval.end {
                return Err(ActionHistoryError::InvalidInterval);
            }
            if interval.start > now {
                return Err(ActionHistoryError::FutureInterval);
            }
            if self
                .last_recorded_at
                .is_some_and(|last_recorded| interval.start > last_recorded)
            {
                return Err(ActionHistoryError::InconsistentRecordHighWater);
            }
            if previous_end.is_some_and(|end| end >= interval.start) {
                return Err(ActionHistoryError::NonCanonicalHistory);
            }
            previous_end = Some(interval.end);
        }
        Ok(())
    }

    /// Validate structural invariants and the immutable policy-window binding.
    ///
    /// # Errors
    /// Returns an [`ActionHistoryError`] when history is malformed or
    /// `expected_retention_window` differs from the window owned at construction.
    pub fn validate_for_policy(
        &self,
        now: MonoInstant,
        expected_retention_window: MonoDuration,
    ) -> Result<(), ActionHistoryError> {
        self.validate_at(now)?;
        if expected_retention_window != self.retention_window {
            return Err(ActionHistoryError::RetentionWindowMismatch);
        }
        Ok(())
    }

    /// Exact non-hold duration overlapping the owned half-open window ending at
    /// `now`.
    ///
    /// `expected_retention_window` must equal the window bound at construction. This
    /// cross-check prevents evaluating retained state under a different policy.
    ///
    /// # Errors
    /// Returns an [`ActionHistoryError`] for malformed history, a mismatched
    /// window, or arithmetic overflow.
    pub fn active_duration_in_window(
        &self,
        now: MonoInstant,
        expected_retention_window: MonoDuration,
    ) -> Result<MonoDuration, ActionHistoryError> {
        self.validate_for_policy(now, expected_retention_window)?;

        let window_start = self.window_start(now);
        let mut total_ns = 0_u128;
        for interval in &self.active_intervals {
            let lo = interval.start.max(window_start);
            let hi = interval.end.min(now);
            if hi > lo {
                let overlap = hi
                    .checked_duration_since(lo)
                    .ok_or(ActionHistoryError::ArithmeticOverflow)?;
                total_ns = total_ns
                    .checked_add(u128::from(overlap.as_nanos()))
                    .ok_or(ActionHistoryError::ArithmeticOverflow)?;
            }
        }
        let total_ns =
            u64::try_from(total_ns).map_err(|_| ActionHistoryError::ArithmeticOverflow)?;
        Ok(MonoDuration::from_nanos(total_ns))
    }

    fn window_start(&self, now: MonoInstant) -> MonoInstant {
        MonoInstant::from_nanos(
            now.as_nanos()
                .saturating_sub(self.retention_window.as_nanos()),
        )
    }

    /// Union one validated interval into the disjoint set after evicting anything
    /// entirely before `window_start`, then enforce the retained bound.
    fn insert_active_interval(&mut self, interval: PublishedInterval, window_start: MonoInstant) {
        self.active_intervals.retain(|i| i.end > window_start);
        let mut merged = interval;
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
        while self.active_intervals.len() > self.max_intervals {
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

/// The fully-typed policy input assembled by the caller.
///
/// `P` is either the default raw [`NativePolicySnapshot`] used by the fail-closed
/// public evaluator or [`ValidatedNativePolicy`] retained by an integrated Gate.
#[derive(Debug, Clone)]
pub struct PolicyInput<'a, P: ?Sized = NativePolicySnapshot> {
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
    /// Raw or previously validated native policy parameters.
    pub policy: &'a P,
}

/// Policy input backed by a retained, previously validated policy.
pub type ValidatedPolicyInput<'a> = PolicyInput<'a, ValidatedNativePolicy>;
