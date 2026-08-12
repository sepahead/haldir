//! `haldir-reference-plant` — a deterministic kinematic point-mass plant that
//! separates command receipt, acceptance, selection, application, expiry,
//! plant-owned safe action, and measured response into distinct evidence stages.
//!
//! It has exactly one command ingress ([`ReferencePlant::ingest`]); nothing else
//! changes the commanded velocity (spec A1/B15). Given a seed schedule the plant
//! produces byte-identical evidence. The safe-action profile is
//! `reference-kinematic-hold-v1`: bounded deceleration to a declared hold region.
//! Construction and every runtime transition are checked. Configuration,
//! top-level evidence/tombstone retention, time, or fixed-point range exhaustion
//! returns a typed error instead of silently saturating or committing a partial
//! transition. Ordinary Rust allocation failure inside cloned correlation strings
//! retains the platform's normal abort behavior and is not converted to a typed
//! error.
//! This is a simulation-only model — never physical actuation (see LIMITATIONS).
#![forbid(unsafe_code)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::float_cmp,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss
    )
)]

pub mod types;

pub use types::{
    KinematicSnapshot, PlantCommandCorrelation, PlantEvent, PlantEventKind, RejectReason,
};
// Compatibility re-exports: the validated command capability is owned by the
// NCP boundary; this simulation crate only consumes it.
pub use haldir_ncp08::{PlantAction, PlantCommand, PlantCommandError};

use core::borrow::Borrow;
use haldir_contracts::ids::GateOutputEpoch;
use haldir_contracts::session::NcpSessionIdentityV1;
use types::PlantEventKind as K;

/// Crate version string.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The name of the reference safe-action profile.
pub const SAFE_ACTION_PROFILE: &str = "reference-kinematic-hold-v1";

/// Hard upper bound on retained in-process plant evidence.
pub const HARD_MAX_EVENTS: usize = 100_000;

/// Hard upper bound on retired Gate-output epoch tombstones.
///
/// This matches the P0 Gate actor's bounded output-stream/replay profile; either
/// limit must be changed only as a coordinated protocol-capacity review.
pub const HARD_MAX_RETIRED_EPOCHS: usize = 16;

/// Deterministic plant configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlantConfig {
    /// Fixed simulation tick period (ms).
    pub tick_ms: u32,
    /// Euclidean-magnitude normal acceleration limit (mm/s^2).
    pub max_accel_mm_s2: i32,
    /// Euclidean-magnitude safe-action deceleration limit (mm/s^2).
    pub safe_decel_mm_s2: i32,
    /// Speed below which the plant is considered in the hold region (mm/s).
    pub hold_epsilon_mm_s: i32,
    /// Maximum retained evidence events.
    pub max_events: usize,
    /// Maximum retained Gate-output epoch tombstones.
    pub max_retired_epochs: usize,
}

impl Default for PlantConfig {
    fn default() -> Self {
        Self {
            tick_ms: 20,
            max_accel_mm_s2: 4000,
            safe_decel_mm_s2: 6000,
            hold_epsilon_mm_s: 10,
            max_events: HARD_MAX_EVENTS,
            max_retired_epochs: HARD_MAX_RETIRED_EPOCHS,
        }
    }
}

impl PlantConfig {
    /// Validate the complete deterministic simulation configuration.
    ///
    /// # Errors
    /// Returns a classified [`PlantConfigError`] for zero/negative kinematic
    /// limits or a retention bound outside the crate's hard resource limits.
    pub fn validate(self) -> Result<(), PlantConfigError> {
        if self.tick_ms == 0 {
            return Err(PlantConfigError::ZeroTickPeriod);
        }
        if self.max_accel_mm_s2 <= 0 {
            return Err(PlantConfigError::NonPositiveMaxAcceleration {
                configured: self.max_accel_mm_s2,
            });
        }
        if self.safe_decel_mm_s2 <= 0 {
            return Err(PlantConfigError::NonPositiveSafeDeceleration {
                configured: self.safe_decel_mm_s2,
            });
        }
        if i64::from(self.max_accel_mm_s2) * i64::from(self.tick_ms) < 1000 {
            return Err(PlantConfigError::ZeroNormalVelocityDelta);
        }
        if i64::from(self.safe_decel_mm_s2) * i64::from(self.tick_ms) < 1000 {
            return Err(PlantConfigError::ZeroSafeVelocityDelta);
        }
        if self.hold_epsilon_mm_s < 0 {
            return Err(PlantConfigError::NegativeHoldEpsilon {
                configured: self.hold_epsilon_mm_s,
            });
        }
        if self.max_events == 0 {
            return Err(PlantConfigError::ZeroEventCapacity);
        }
        if self.max_events > HARD_MAX_EVENTS {
            return Err(PlantConfigError::EventCapacityTooLarge {
                configured: self.max_events,
                maximum: HARD_MAX_EVENTS,
            });
        }
        if self.max_retired_epochs > HARD_MAX_RETIRED_EPOCHS {
            return Err(PlantConfigError::RetiredEpochCapacityTooLarge {
                configured: self.max_retired_epochs,
                maximum: HARD_MAX_RETIRED_EPOCHS,
            });
        }
        Ok(())
    }
}

/// Invalid reference-plant configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PlantConfigError {
    /// The fixed simulation tick period is zero.
    ZeroTickPeriod,
    /// The normal acceleration limit is zero or negative.
    NonPositiveMaxAcceleration {
        /// Rejected configured limit.
        configured: i32,
    },
    /// The safe-action deceleration limit is zero or negative.
    NonPositiveSafeDeceleration {
        /// Rejected configured limit.
        configured: i32,
    },
    /// Fixed-point normal acceleration rounds to zero velocity change per tick.
    ZeroNormalVelocityDelta,
    /// Fixed-point safe deceleration rounds to zero velocity change per tick.
    ZeroSafeVelocityDelta,
    /// The hold-region speed tolerance is negative.
    NegativeHoldEpsilon {
        /// Rejected configured tolerance.
        configured: i32,
    },
    /// No plant evidence event can be retained.
    ZeroEventCapacity,
    /// The configured evidence bound exceeds [`HARD_MAX_EVENTS`].
    EventCapacityTooLarge {
        /// Rejected configured bound.
        configured: usize,
        /// Inclusive crate hard maximum.
        maximum: usize,
    },
    /// The configured tombstone bound exceeds [`HARD_MAX_RETIRED_EPOCHS`].
    RetiredEpochCapacityTooLarge {
        /// Rejected configured bound.
        configured: usize,
        /// Inclusive crate hard maximum.
        maximum: usize,
    },
}

impl PlantConfigError {
    /// Stable machine-readable failure class.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ZeroTickPeriod => "PLANT_CONFIG_ZERO_TICK_PERIOD",
            Self::NonPositiveMaxAcceleration { .. } => "PLANT_CONFIG_NON_POSITIVE_MAX_ACCELERATION",
            Self::NonPositiveSafeDeceleration { .. } => {
                "PLANT_CONFIG_NON_POSITIVE_SAFE_DECELERATION"
            }
            Self::ZeroNormalVelocityDelta => "PLANT_CONFIG_ZERO_NORMAL_VELOCITY_DELTA",
            Self::ZeroSafeVelocityDelta => "PLANT_CONFIG_ZERO_SAFE_VELOCITY_DELTA",
            Self::NegativeHoldEpsilon { .. } => "PLANT_CONFIG_NEGATIVE_HOLD_EPSILON",
            Self::ZeroEventCapacity => "PLANT_CONFIG_ZERO_EVENT_CAPACITY",
            Self::EventCapacityTooLarge { .. } => "PLANT_CONFIG_EVENT_CAPACITY_TOO_LARGE",
            Self::RetiredEpochCapacityTooLarge { .. } => {
                "PLANT_CONFIG_RETIRED_EPOCH_CAPACITY_TOO_LARGE"
            }
        }
    }
}

impl std::fmt::Display for PlantConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::error::Error for PlantConfigError {}

/// A checked reference-plant runtime transition failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PlantRuntimeError {
    /// The monotonic simulation tick or a command expiry cannot be represented.
    TimeExhausted,
    /// A position update cannot be represented exactly.
    PositionOverflow,
    /// An intermediate fixed-point kinematic calculation cannot be represented.
    KinematicArithmeticOverflow,
    /// Private fixed-point kinematic state or a derived acceleration step violated
    /// an invariant that every public transition is required to preserve.
    KinematicInvariantViolation,
    /// The configured logical evidence-event capacity is exhausted.
    EvidenceCapacityExhausted {
        /// Inclusive configured event limit.
        maximum: usize,
    },
    /// Memory for an otherwise in-bounds evidence append could not be reserved.
    EvidenceAllocationFailed,
    /// A new epoch would require one more tombstone than configured.
    RetiredEpochCapacityExhausted {
        /// Inclusive configured tombstone limit.
        maximum: usize,
    },
    /// Memory for an otherwise in-bounds epoch tombstone could not be reserved.
    RetiredEpochAllocationFailed,
}

impl PlantRuntimeError {
    /// Stable machine-readable failure class.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TimeExhausted => "PLANT_RUNTIME_TIME_EXHAUSTED",
            Self::PositionOverflow => "PLANT_RUNTIME_POSITION_OVERFLOW",
            Self::KinematicArithmeticOverflow => "PLANT_RUNTIME_KINEMATIC_ARITHMETIC_OVERFLOW",
            Self::KinematicInvariantViolation => "PLANT_RUNTIME_KINEMATIC_INVARIANT_VIOLATION",
            Self::EvidenceCapacityExhausted { .. } => "PLANT_RUNTIME_EVIDENCE_CAPACITY_EXHAUSTED",
            Self::EvidenceAllocationFailed => "PLANT_RUNTIME_EVIDENCE_ALLOCATION_FAILED",
            Self::RetiredEpochCapacityExhausted { .. } => {
                "PLANT_RUNTIME_RETIRED_EPOCH_CAPACITY_EXHAUSTED"
            }
            Self::RetiredEpochAllocationFailed => "PLANT_RUNTIME_RETIRED_EPOCH_ALLOCATION_FAILED",
        }
    }
}

impl std::fmt::Display for PlantRuntimeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::error::Error for PlantRuntimeError {}

/// A command-ingress failure, separated into receiver rejection and local fault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PlantIngestError {
    /// The command failed a receiver validation rule. Its rejection is evidenced.
    Rejected(RejectReason),
    /// The local model could not commit the command. No state or evidence changed.
    Runtime(PlantRuntimeError),
}

impl PlantIngestError {
    /// Stable machine-readable failure class.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Rejected(reason) => reason.as_str(),
            Self::Runtime(error) => error.as_str(),
        }
    }
}

impl From<RejectReason> for PlantIngestError {
    fn from(reason: RejectReason) -> Self {
        Self::Rejected(reason)
    }
}

impl From<PlantRuntimeError> for PlantIngestError {
    fn from(error: PlantRuntimeError) -> Self {
        Self::Runtime(error)
    }
}

impl std::fmt::Display for PlantIngestError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::error::Error for PlantIngestError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Rejected(reason) => Some(reason),
            Self::Runtime(error) => Some(error),
        }
    }
}

#[cfg_attr(test, derive(Debug, Clone, PartialEq, Eq))]
struct Active {
    correlation: PlantCommandCorrelation,
    expiry_tick: u64,
    velocity: [i32; 3],
    applied_recorded: bool,
    response_recorded: bool,
}

/// The deterministic reference plant.
#[cfg_attr(test, derive(Debug, Clone, PartialEq, Eq))]
pub struct ReferencePlant {
    cfg: PlantConfig,
    session: NcpSessionIdentityV1,
    tick: u64,
    pos: [i64; 3],
    /// Signed thousandths of a millimetre retained across integration ticks.
    ///
    /// A per-tick integer division would otherwise discard low-speed motion on
    /// every tick (for example, 10 mm/s at 50 Hz would remain at zero forever).
    /// Keeping the remainder makes the fixed-point integration exact over time
    /// while the public snapshot stays in whole millimetres.
    position_sub_mm_remainder: [i64; 3],
    vel: [i32; 3],
    current: Option<Active>,
    last_accepted: Option<PlantCommandCorrelation>,
    retired: Vec<GateOutputEpoch>,
    in_safe_action: bool,
    /// Exact expired command whose timeout caused the current plant-owned safe action.
    safe_action_cause: Option<PlantCommandCorrelation>,
    safe_reached: bool,
    events: Vec<PlantEvent>,
}

impl ReferencePlant {
    /// Construct a checked plant at rest at the origin, bound to one independently
    /// selected NCP session before any command is observed.
    ///
    /// # Errors
    /// Returns [`PlantConfigError`] before constructing any state when `cfg`
    /// violates a kinematic or resource invariant.
    pub fn new(cfg: PlantConfig, session: NcpSessionIdentityV1) -> Result<Self, PlantConfigError> {
        cfg.validate()?;
        Ok(Self {
            cfg,
            session,
            tick: 0,
            pos: [0; 3],
            position_sub_mm_remainder: [0; 3],
            vel: [0; 3],
            current: None,
            last_accepted: None,
            retired: Vec::new(),
            in_safe_action: false,
            safe_action_cause: None,
            safe_reached: false,
            events: Vec::new(),
        })
    }

    /// The current tick.
    #[must_use]
    pub const fn tick(&self) -> u64 {
        self.tick
    }

    /// The exact receiver session selected before command ingress.
    #[must_use]
    pub const fn session(&self) -> &NcpSessionIdentityV1 {
        &self.session
    }

    /// The current kinematic snapshot.
    #[must_use]
    pub fn snapshot(&self) -> KinematicSnapshot {
        KinematicSnapshot {
            position_mm: self.pos,
            velocity_mm_s: self.vel,
        }
    }

    /// All recorded evidence events.
    #[must_use]
    pub fn events(&self) -> &[PlantEvent] {
        &self.events
    }

    /// Whether the plant is in the declared hold region.
    #[must_use]
    pub fn in_hold_region(&self) -> bool {
        speed_within(self.vel, self.cfg.hold_epsilon_mm_s)
    }

    fn ensure_event_capacity(&mut self, additional: usize) -> Result<(), PlantRuntimeError> {
        let required = self.events.len().checked_add(additional).ok_or(
            PlantRuntimeError::EvidenceCapacityExhausted {
                maximum: self.cfg.max_events,
            },
        )?;
        if required > self.cfg.max_events {
            return Err(PlantRuntimeError::EvidenceCapacityExhausted {
                maximum: self.cfg.max_events,
            });
        }
        self.events
            .try_reserve(additional)
            .map_err(|_| PlantRuntimeError::EvidenceAllocationFailed)
    }

    fn ensure_retired_epoch_capacity(&mut self) -> Result<(), PlantRuntimeError> {
        if self.retired.len() >= self.cfg.max_retired_epochs {
            return Err(PlantRuntimeError::RetiredEpochCapacityExhausted {
                maximum: self.cfg.max_retired_epochs,
            });
        }
        self.retired
            .try_reserve(1)
            .map_err(|_| PlantRuntimeError::RetiredEpochAllocationFailed)
    }

    fn push_preflighted(
        &mut self,
        kind: PlantEventKind,
        command: Option<&PlantCommandCorrelation>,
    ) {
        self.events.push(PlantEvent {
            tick: self.tick,
            kind,
            command: command.cloned(),
            state: self.snapshot(),
        });
    }

    fn reject(
        &mut self,
        command: &PlantCommandCorrelation,
        reason: RejectReason,
    ) -> Result<(), PlantIngestError> {
        self.ensure_event_capacity(2)?;
        self.push_preflighted(K::Received, Some(command));
        self.push_preflighted(K::Rejected(reason), Some(command));
        Err(reason.into())
    }

    /// Submit a self-consistent command candidate to the receiver (the only command ingress).
    /// A receiver rejection records `Received` + `Rejected` but never refreshes
    /// the active command's expiry (spec S6). A local runtime failure is fully
    /// transactional: it changes neither receiver state nor evidence. Successful
    /// acceptance atomically replaces any prior active command; the ordered
    /// `Accepted(new)` event is the model's supersession record.
    ///
    /// # Errors
    /// Returns [`PlantIngestError::Rejected`] when a command fails receiver
    /// validation, or [`PlantIngestError::Runtime`] when bounded evidence,
    /// tombstone, top-level retention allocation, or time arithmetic prevents an
    /// atomic commit.
    pub fn ingest(&mut self, candidate: impl Borrow<PlantCommand>) -> Result<(), PlantIngestError> {
        let cmd = candidate.borrow();
        let correlation = PlantCommandCorrelation {
            decision_id: cmd.decision_id(),
            session: cmd.session().clone(),
            output_epoch: cmd.output_epoch(),
            output_seq: cmd.output_seq(),
            source: cmd.source().clone(),
            output_frame_digest: cmd.output_frame_digest(),
        };
        if !cmd.exact_frame().is_self_consistent() {
            return self.reject(&correlation, RejectReason::InvalidOutputFrame);
        }
        if *cmd.session() != self.session {
            return self.reject(&correlation, RejectReason::WrongSession);
        }
        if self.retired.contains(&cmd.output_epoch()) {
            return self.reject(&correlation, RejectReason::RetiredEpoch);
        }
        let is_new_epoch = self
            .last_accepted
            .as_ref()
            .is_none_or(|last| last.output_epoch != cmd.output_epoch());
        // NCP v0.8 constrained single-publisher transition rule: a foreign
        // epoch cannot replace a live stream. The expiry horizon is half-open;
        // equality is the first instant at which the prior stream is no longer
        // live and a validated new epoch may re-anchor sequence accounting.
        if is_new_epoch
            && self.last_accepted.is_some()
            && self
                .current
                .as_ref()
                .is_some_and(|active| self.tick < active.expiry_tick)
        {
            return self.reject(&correlation, RejectReason::PriorStreamLive);
        }
        let baseline = if is_new_epoch {
            0
        } else {
            self.last_accepted
                .as_ref()
                .map_or(0, |last| last.output_seq.get())
        };
        if cmd.output_seq().get() <= baseline {
            let reason = if cmd.output_seq().get() == baseline
                && self
                    .last_accepted
                    .as_ref()
                    .is_some_and(|last| !same_exact_output(last, &correlation))
            {
                RejectReason::ConflictingReplay
            } else {
                RejectReason::DuplicateOrStale
            };
            return self.reject(&correlation, reason);
        }

        let velocity = cmd.action().velocity();
        let retired_epoch = self
            .last_accepted
            .as_ref()
            .map(|last| last.output_epoch)
            .filter(|active| *active != correlation.output_epoch);
        // Only complete ticks wholly covered by the validity window may apply
        // authority. Rounding up would extend a sub-tick command to a full tick.
        let ticks = u64::from(cmd.validity_ms() / self.cfg.tick_ms);
        let expiry_tick = self
            .tick
            .checked_add(ticks)
            .ok_or(PlantRuntimeError::TimeExhausted)?;

        self.ensure_event_capacity(3)?;
        if retired_epoch.is_some() {
            self.ensure_retired_epoch_capacity()?;
        }

        if let Some(retired_epoch) = retired_epoch {
            self.retired.push(retired_epoch);
        }
        self.current = Some(Active {
            correlation: correlation.clone(),
            expiry_tick,
            velocity,
            applied_recorded: false,
            response_recorded: false,
        });
        self.in_safe_action = false;
        self.safe_action_cause = None;
        self.safe_reached = false;
        self.last_accepted = Some(correlation.clone());

        self.push_preflighted(K::Received, Some(&correlation));
        self.push_preflighted(K::Validated, Some(&correlation));
        self.push_preflighted(K::Accepted, Some(&correlation));
        Ok(())
    }

    /// Advance the simulation by one checked, atomic tick.
    ///
    /// # Errors
    /// Returns [`PlantRuntimeError`] without changing state or evidence if time,
    /// fixed-point position, or a bounded evidence append cannot be represented.
    pub fn step(&mut self) -> Result<(), PlantRuntimeError> {
        let next_tick = self
            .tick
            .checked_add(1)
            .ok_or(PlantRuntimeError::TimeExhausted)?;
        let dt = i64::from(self.cfg.tick_ms);

        let mut target = [0i32; 3];
        let mut selected: Option<PlantCommandCorrelation> = None;
        let mut just_applied = false;
        let mut expired: Option<PlantCommandCorrelation> = None;

        if let Some(active) = self.current.as_ref() {
            if next_tick <= active.expiry_tick {
                target = active.velocity;
                selected = Some(active.correlation.clone());
                if !active.applied_recorded {
                    just_applied = true;
                }
            } else {
                expired = Some(active.correlation.clone());
            }
        }
        let mut next_in_safe_action = self.in_safe_action;
        let mut next_safe_action_cause = self.safe_action_cause.clone();
        let mut next_safe_reached = self.safe_reached;
        let mut start_safe = false;
        if expired.is_some() && !next_in_safe_action {
            next_in_safe_action = true;
            next_safe_action_cause = expired.clone();
            next_safe_reached = false;
            start_safe = true;
        }

        let accel = if next_in_safe_action {
            self.cfg.safe_decel_mm_s2
        } else {
            self.cfg.max_accel_mm_s2
        };
        let dv_max = i64::from(accel)
            .checked_mul(dt)
            .ok_or(PlantRuntimeError::KinematicArithmeticOverflow)?
            / 1000;
        let dv_max =
            u64::try_from(dv_max).map_err(|_| PlantRuntimeError::KinematicArithmeticOverflow)?;
        if dv_max == 0 {
            return Err(PlantRuntimeError::KinematicArithmeticOverflow);
        }
        let new_vel = approach_vector(self.vel, target, dv_max)?;
        let mut new_pos = self.pos;
        let mut new_position_sub_mm_remainder = self.position_sub_mm_remainder;
        for (((np, remainder), &position), &velocity) in new_pos
            .iter_mut()
            .zip(new_position_sub_mm_remainder.iter_mut())
            .zip(self.pos.iter())
            .zip(new_vel.iter())
        {
            (*np, *remainder) = integrate_position_component(position, *remainder, velocity, dt)?;
        }

        let response_observed = selected.is_some()
            && self
                .current
                .as_ref()
                .is_some_and(|active| !active.response_recorded)
            && vectors_within(new_vel, target, self.cfg.hold_epsilon_mm_s);
        let safe_region_reached = next_in_safe_action
            && !next_safe_reached
            && speed_within(new_vel, self.cfg.hold_epsilon_mm_s);
        let event_count = usize::from(expired.is_some())
            + usize::from(start_safe)
            + 2 * usize::from(just_applied)
            + usize::from(response_observed)
            + usize::from(safe_region_reached);
        self.ensure_event_capacity(event_count)?;

        self.tick = next_tick;
        self.vel = new_vel;
        self.pos = new_pos;
        self.position_sub_mm_remainder = new_position_sub_mm_remainder;
        self.in_safe_action = next_in_safe_action;
        self.safe_action_cause = next_safe_action_cause;
        if expired.is_some() {
            self.current = None;
        } else if let Some(active) = self.current.as_mut() {
            if just_applied {
                active.applied_recorded = true;
            }
            if response_observed {
                active.response_recorded = true;
            }
        }
        if safe_region_reached {
            next_safe_reached = true;
        }
        self.safe_reached = next_safe_reached;

        if let Some(command) = expired.as_ref() {
            self.push_preflighted(K::Expired, Some(command));
        }
        if start_safe {
            let cause = self.safe_action_cause.clone();
            self.push_preflighted(K::SafeActionStarted, cause.as_ref());
        }
        if just_applied && let Some(command) = selected.as_ref() {
            self.push_preflighted(K::Selected, Some(command));
            self.push_preflighted(K::Applied, Some(command));
        }
        if response_observed && let Some(command) = selected.as_ref() {
            self.push_preflighted(K::ResponseObserved, Some(command));
        }
        if safe_region_reached {
            let cause = self.safe_action_cause.clone();
            self.push_preflighted(K::SafeRegionReached, cause.as_ref());
        }
        Ok(())
    }

    /// Run up to `n` checked ticks, stopping at the first failed transition.
    ///
    /// # Errors
    /// Returns the first [`PlantRuntimeError`] produced by [`Self::step`].
    pub fn run(&mut self, n: u64) -> Result<(), PlantRuntimeError> {
        for _ in 0..n {
            self.step()?;
        }
        Ok(())
    }

    /// Whether the plant reached its declared safe region during safe action.
    #[must_use]
    pub const fn safe_region_reached(&self) -> bool {
        self.safe_reached
    }
}

fn same_exact_output(left: &PlantCommandCorrelation, right: &PlantCommandCorrelation) -> bool {
    left.session == right.session
        && left.output_epoch == right.output_epoch
        && left.output_seq == right.output_seq
        && left.source == right.source
        && left.output_frame_digest == right.output_frame_digest
}

fn integrate_position_component(
    position_mm: i64,
    sub_mm_remainder: i64,
    velocity_mm_s: i32,
    tick_ms: i64,
) -> Result<(i64, i64), PlantRuntimeError> {
    if sub_mm_remainder.unsigned_abs() >= 1000 {
        return Err(PlantRuntimeError::KinematicInvariantViolation);
    }
    let scaled_displacement = i64::from(velocity_mm_s)
        .checked_mul(tick_ms)
        .and_then(|value| value.checked_add(sub_mm_remainder))
        .ok_or(PlantRuntimeError::KinematicArithmeticOverflow)?;
    let whole_mm = scaled_displacement / 1000;
    let next_remainder = scaled_displacement % 1000;
    let next_position = position_mm
        .checked_add(whole_mm)
        .ok_or(PlantRuntimeError::PositionOverflow)?;

    // The pair is a signed fixed-point value. `i64::MAX + positive fraction`
    // and `i64::MIN - negative fraction` are already outside its declared
    // position domain even when the whole-millimetre field itself did not wrap.
    if (next_position == i64::MAX && next_remainder > 0)
        || (next_position == i64::MIN && next_remainder < 0)
    {
        return Err(PlantRuntimeError::PositionOverflow);
    }
    Ok((next_position, next_remainder))
}

fn approach_vector(
    current: [i32; 3],
    target: [i32; 3],
    delta_limit: u64,
) -> Result<[i32; 3], PlantRuntimeError> {
    let mut desired = [0i128; 3];
    for ((delta, &target_component), &current_component) in
        desired.iter_mut().zip(target.iter()).zip(current.iter())
    {
        *delta = i128::from(target_component) - i128::from(current_component);
    }
    let desired_norm_squared = squared_norm(desired)?;
    let limit = u128::from(delta_limit);
    let limit_squared = limit
        .checked_mul(limit)
        .ok_or(PlantRuntimeError::KinematicArithmeticOverflow)?;
    if desired_norm_squared <= limit_squared {
        return Ok(target);
    }

    let denominator = ceil_sqrt(desired_norm_squared)?;
    let mut step = [0i128; 3];
    for (step_component, &desired_component) in step.iter_mut().zip(desired.iter()) {
        let magnitude = desired_component
            .unsigned_abs()
            .checked_mul(limit)
            .ok_or(PlantRuntimeError::KinematicArithmeticOverflow)?
            / denominator;
        let signed_magnitude = i128::try_from(magnitude)
            .map_err(|_| PlantRuntimeError::KinematicArithmeticOverflow)?;
        *step_component = signed_magnitude * desired_component.signum();
    }

    // Truncating a very small diagonal step can round every component to zero.
    // Advance the largest remaining component by one unit; `delta_limit >= 1`
    // is a validated configuration invariant, so the vector cap still holds.
    if step.iter().all(|component| *component == 0)
        && let Some((step_component, desired_component)) = step
            .iter_mut()
            .zip(desired.iter())
            .max_by_key(|(_, component)| component.unsigned_abs())
    {
        *step_component = desired_component.signum();
    }

    if squared_norm(step)? > limit_squared {
        return Err(PlantRuntimeError::KinematicInvariantViolation);
    }
    let mut next = [0i32; 3];
    for ((next_component, &current_component), &step_component) in
        next.iter_mut().zip(current.iter()).zip(step.iter())
    {
        *next_component = i32::try_from(i128::from(current_component) + step_component)
            .map_err(|_| PlantRuntimeError::KinematicArithmeticOverflow)?;
    }
    Ok(next)
}

fn squared_norm(vector: [i128; 3]) -> Result<u128, PlantRuntimeError> {
    vector.iter().try_fold(0u128, |sum, component| {
        let magnitude = component.unsigned_abs();
        let square = magnitude
            .checked_mul(magnitude)
            .ok_or(PlantRuntimeError::KinematicArithmeticOverflow)?;
        sum.checked_add(square)
            .ok_or(PlantRuntimeError::KinematicArithmeticOverflow)
    })
}

fn ceil_sqrt(value: u128) -> Result<u128, PlantRuntimeError> {
    if value < 2 {
        return Ok(value);
    }
    let mut low = 1u128;
    let mut high = value.min(u128::from(u64::MAX));
    let mut floor = 1u128;
    while low <= high {
        let midpoint = low + (high - low) / 2;
        if midpoint <= value / midpoint {
            floor = midpoint;
            low = midpoint
                .checked_add(1)
                .ok_or(PlantRuntimeError::KinematicArithmeticOverflow)?;
        } else {
            high = midpoint - 1;
        }
    }
    let square = floor
        .checked_mul(floor)
        .ok_or(PlantRuntimeError::KinematicArithmeticOverflow)?;
    if square == value {
        Ok(floor)
    } else {
        floor
            .checked_add(1)
            .ok_or(PlantRuntimeError::KinematicArithmeticOverflow)
    }
}

fn speed_within(v: [i32; 3], eps: i32) -> bool {
    let sq: i128 = v.iter().map(|&c| i128::from(c) * i128::from(c)).sum();
    let e = i128::from(eps.max(0));
    sq <= e * e
}

fn vectors_within(a: [i32; 3], b: [i32; 3], eps: i32) -> bool {
    let sq: i128 = a
        .iter()
        .zip(b.iter())
        .map(|(&left, &right)| {
            let delta = i128::from(left) - i128::from(right);
            delta * delta
        })
        .sum();
    let epsilon = i128::from(eps);
    sq <= epsilon * epsilon
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::num::{NonZeroU32, NonZeroU64};
    use haldir_contracts::action::RequestedActionV1;
    use haldir_contracts::digest::{DigestDomain, DigestV1};
    use haldir_contracts::ids::{DecisionId, GateOutputEpoch, OutputSeq, SourceSeq};
    use haldir_contracts::scalar::{AsciiId, BoundedAscii, CanonicalUuidV4String};
    use haldir_contracts::session::{NcpSessionIdentityV1, NcpSourceRefV1, NcpStreamPositionV1};
    use haldir_ncp08::{AclOnlyAdapter, GateCommandBuildInputV1, NcpCommandAdapter};

    fn sess(g: u8) -> NcpSessionIdentityV1 {
        NcpSessionIdentityV1 {
            session_id: AsciiId::new("sess-1").unwrap(),
            generation: CanonicalUuidV4String::from_random_bytes([g; 16]),
        }
    }
    fn epoch(n: u8) -> GateOutputEpoch {
        GateOutputEpoch::new(CanonicalUuidV4String::from_random_bytes([n; 16]))
    }
    fn source() -> NcpSourceRefV1 {
        source_with(1)
    }
    fn source_with(n: u8) -> NcpSourceRefV1 {
        NcpSourceRefV1 {
            source_key: BoundedAscii::new(if n == 1 {
                "veh/uav-1/state/pose"
            } else {
                "veh/uav-1/state/alternate"
            })
            .unwrap(),
            stream_epoch: CanonicalUuidV4String::from_random_bytes([n; 16]),
            stream_seq: SourceSeq::new(NonZeroU64::new(u64::from(n)).unwrap()),
        }
    }
    fn cmd(g: u8, ep: u8, seq: u64, action: PlantAction, validity_ms: u32) -> PlantCommand {
        cmd_with_source(g, ep, seq, action, validity_ms, source(), seq)
    }
    fn cmd_with_source(
        g: u8,
        ep: u8,
        seq: u64,
        action: PlantAction,
        validity_ms: u32,
        source: NcpSourceRefV1,
        gate_t_ns: u64,
    ) -> PlantCommand {
        cmd_with_source_and_decision(CommandFixture {
            g,
            ep,
            seq,
            action,
            validity_ms,
            source,
            gate_t_ns,
            decision_id: DecisionId::new([seq as u8; 16]),
        })
    }

    struct CommandFixture {
        g: u8,
        ep: u8,
        seq: u64,
        action: PlantAction,
        validity_ms: u32,
        source: NcpSourceRefV1,
        gate_t_ns: u64,
        decision_id: DecisionId,
    }

    fn cmd_with_source_and_decision(fixture: CommandFixture) -> PlantCommand {
        let CommandFixture {
            g,
            ep,
            seq,
            action,
            validity_ms,
            source,
            gate_t_ns,
            decision_id,
        } = fixture;
        let requested_validity_ms = NonZeroU32::new(validity_ms.max(1)).unwrap();
        let action = match action {
            PlantAction::Hold => RequestedActionV1::Hold {
                requested_validity_ms,
            },
            PlantAction::Velocity([north_mm_s, east_mm_s, down_mm_s]) => {
                RequestedActionV1::VelocityLocalNed {
                    north_mm_s,
                    east_mm_s,
                    down_mm_s,
                    requested_validity_ms,
                }
            }
        };
        let input = GateCommandBuildInputV1 {
            session: sess(g),
            stream: NcpStreamPositionV1 {
                epoch: epoch(ep),
                seq: OutputSeq::new(NonZeroU64::new(seq).unwrap()),
            },
            source,
            frame_id: BoundedAscii::new("NED").unwrap(),
            source_t_ns: 1,
            gate_t_ns,
            action,
            effective_validity_ms: validity_ms,
        };
        let frame = AclOnlyAdapter::new().build_command(&input).unwrap();
        PlantCommand::from_exact_frame(decision_id, frame).unwrap()
    }
    fn correlation(command: &PlantCommand) -> PlantCommandCorrelation {
        PlantCommandCorrelation {
            decision_id: command.decision_id(),
            session: command.session().clone(),
            output_epoch: command.output_epoch(),
            output_seq: command.output_seq(),
            source: command.source().clone(),
            output_frame_digest: command.output_frame_digest(),
        }
    }
    fn has(p: &ReferencePlant, k: PlantEventKind) -> bool {
        p.events().iter().any(|e| e.kind == k)
    }

    #[test]
    fn checked_construction_accepts_exact_lower_and_upper_boundaries() {
        let lower = PlantConfig {
            tick_ms: 1,
            max_accel_mm_s2: 1000,
            safe_decel_mm_s2: 1000,
            hold_epsilon_mm_s: 0,
            max_events: 1,
            max_retired_epochs: 0,
        };
        assert!(ReferencePlant::new(lower, sess(1)).is_ok());

        let upper = PlantConfig {
            max_events: HARD_MAX_EVENTS,
            max_retired_epochs: HARD_MAX_RETIRED_EPOCHS,
            ..PlantConfig::default()
        };
        assert!(ReferencePlant::new(upper, sess(1)).is_ok());
    }

    #[test]
    fn checked_construction_rejects_zero_tick_period() {
        let config = PlantConfig {
            tick_ms: 0,
            ..PlantConfig::default()
        };
        assert_eq!(
            ReferencePlant::new(config, sess(1)).unwrap_err(),
            PlantConfigError::ZeroTickPeriod
        );
    }

    #[test]
    fn checked_construction_rejects_non_positive_normal_acceleration() {
        for configured in [-1, 0] {
            let config = PlantConfig {
                max_accel_mm_s2: configured,
                ..PlantConfig::default()
            };
            assert_eq!(
                ReferencePlant::new(config, sess(1)).unwrap_err(),
                PlantConfigError::NonPositiveMaxAcceleration { configured }
            );
        }
    }

    #[test]
    fn checked_construction_rejects_non_positive_safe_deceleration() {
        for configured in [-1, 0] {
            let config = PlantConfig {
                safe_decel_mm_s2: configured,
                ..PlantConfig::default()
            };
            assert_eq!(
                ReferencePlant::new(config, sess(1)).unwrap_err(),
                PlantConfigError::NonPositiveSafeDeceleration { configured }
            );
        }
    }

    #[test]
    fn checked_construction_rejects_zero_fixed_point_velocity_delta() {
        let normal = PlantConfig {
            tick_ms: 1,
            max_accel_mm_s2: 999,
            safe_decel_mm_s2: 1000,
            ..PlantConfig::default()
        };
        assert_eq!(
            ReferencePlant::new(normal, sess(1)).unwrap_err(),
            PlantConfigError::ZeroNormalVelocityDelta
        );

        let safe = PlantConfig {
            tick_ms: 1,
            max_accel_mm_s2: 1000,
            safe_decel_mm_s2: 999,
            ..PlantConfig::default()
        };
        assert_eq!(
            ReferencePlant::new(safe, sess(1)).unwrap_err(),
            PlantConfigError::ZeroSafeVelocityDelta
        );
    }

    #[test]
    fn checked_construction_rejects_negative_hold_epsilon() {
        let config = PlantConfig {
            hold_epsilon_mm_s: -1,
            ..PlantConfig::default()
        };
        assert_eq!(
            ReferencePlant::new(config, sess(1)).unwrap_err(),
            PlantConfigError::NegativeHoldEpsilon { configured: -1 }
        );
    }

    #[test]
    fn checked_construction_rejects_event_capacity_outside_hard_bounds() {
        let zero = PlantConfig {
            max_events: 0,
            ..PlantConfig::default()
        };
        assert_eq!(
            ReferencePlant::new(zero, sess(1)).unwrap_err(),
            PlantConfigError::ZeroEventCapacity
        );

        let too_large = PlantConfig {
            max_events: HARD_MAX_EVENTS + 1,
            ..PlantConfig::default()
        };
        assert_eq!(
            ReferencePlant::new(too_large, sess(1)).unwrap_err(),
            PlantConfigError::EventCapacityTooLarge {
                configured: HARD_MAX_EVENTS + 1,
                maximum: HARD_MAX_EVENTS,
            }
        );
    }

    #[test]
    fn checked_construction_rejects_tombstone_capacity_above_hard_bound() {
        let config = PlantConfig {
            max_retired_epochs: HARD_MAX_RETIRED_EPOCHS + 1,
            ..PlantConfig::default()
        };
        assert_eq!(
            ReferencePlant::new(config, sess(1)).unwrap_err(),
            PlantConfigError::RetiredEpochCapacityTooLarge {
                configured: HARD_MAX_RETIRED_EPOCHS + 1,
                maximum: HARD_MAX_RETIRED_EPOCHS,
            }
        );
    }

    #[test]
    fn accepts_command_and_converges_then_holds_on_expiry() {
        // dv_max = 4000 mm/s^2 * 20 ms / 1000 = 80 mm/s per tick; 800 mm/s target
        // converges in 10 ticks, well within a 600 ms (30-tick) validity window.
        let mut p = ReferencePlant::new(PlantConfig::default(), sess(1)).unwrap();
        let command = cmd(1, 1, 1, PlantAction::Velocity([800, 0, 0]), 600);
        let expected_correlation = correlation(&command);
        p.ingest(command).unwrap();
        p.run(15).unwrap();
        assert!(has(&p, PlantEventKind::Accepted));
        assert!(has(&p, PlantEventKind::Applied));
        assert!(has(&p, PlantEventKind::ResponseObserved), "should converge");
        // now let the command expire and the plant reach the hold region
        p.run(30).unwrap();
        assert!(has(&p, PlantEventKind::Expired));
        assert!(has(&p, PlantEventKind::SafeActionStarted));
        assert!(p.safe_region_reached());
        assert!(p.in_hold_region());
        for kind in [
            PlantEventKind::Expired,
            PlantEventKind::SafeActionStarted,
            PlantEventKind::SafeRegionReached,
        ] {
            let event = p
                .events()
                .iter()
                .find(|event| event.kind == kind)
                .expect("expected correlated expiry/safe-action event");
            assert_eq!(event.command.as_ref(), Some(&expected_correlation));
        }
    }

    #[test]
    fn duplicate_command_does_not_refresh_expiry() {
        let mut p = ReferencePlant::new(PlantConfig::default(), sess(1)).unwrap();
        let command = cmd(1, 1, 1, PlantAction::Velocity([1000, 0, 0]), 200);
        let duplicate = cmd(1, 1, 1, PlantAction::Velocity([1000, 0, 0]), 200);
        let expected_correlation = correlation(&command);
        p.ingest(command).unwrap();
        let authority_before = (p.last_accepted.clone(), p.current.clone());
        assert_eq!(
            p.ingest(duplicate),
            Err(PlantIngestError::Rejected(RejectReason::DuplicateOrStale))
        );
        assert_eq!(
            (p.last_accepted.clone(), p.current.clone()),
            authority_before
        );
        assert_eq!(
            p.events().last().and_then(|event| event.command.as_ref()),
            Some(&expected_correlation)
        );
    }

    #[test]
    fn correlation_only_decision_change_does_not_turn_an_exact_replay_into_a_conflict() {
        let mut plant = ReferencePlant::new(PlantConfig::default(), sess(1)).unwrap();
        let accepted = cmd(1, 1, 1, PlantAction::Hold, 200);
        let replay = cmd_with_source_and_decision(CommandFixture {
            g: 1,
            ep: 1,
            seq: 1,
            action: PlantAction::Hold,
            validity_ms: 200,
            source: source(),
            gate_t_ns: 1,
            decision_id: DecisionId::new([0xa5; 16]),
        });
        let replay_correlation = correlation(&replay);
        assert_ne!(accepted.decision_id(), replay.decision_id());
        plant.ingest(accepted).unwrap();
        let authority_before = (plant.last_accepted.clone(), plant.current.clone());

        assert_eq!(
            plant.ingest(replay),
            Err(PlantIngestError::Rejected(RejectReason::DuplicateOrStale))
        );
        assert_eq!(
            (plant.last_accepted.clone(), plant.current.clone()),
            authority_before
        );
        assert_eq!(
            plant
                .events()
                .last()
                .and_then(|event| event.command.as_ref()),
            Some(&replay_correlation)
        );
    }

    #[test]
    fn command_events_retain_the_exact_source_and_output_frame_digest() {
        let mut plant = ReferencePlant::new(PlantConfig::default(), sess(1)).unwrap();
        let command = cmd(1, 1, 1, PlantAction::Velocity([80, 0, 0]), 200);
        let expected = correlation(&command);
        assert_eq!(
            expected.output_frame_digest,
            DigestV1::compute(DigestDomain::OutputFrame, command.exact_frame().bytes())
        );

        plant.ingest(command).unwrap();
        plant.run(11).unwrap();

        for kind in [
            PlantEventKind::Received,
            PlantEventKind::Validated,
            PlantEventKind::Accepted,
            PlantEventKind::Selected,
            PlantEventKind::Applied,
            PlantEventKind::ResponseObserved,
            PlantEventKind::Expired,
        ] {
            let event = plant
                .events()
                .iter()
                .find(|event| event.kind == kind)
                .expect("command lifecycle event");
            assert_eq!(event.command.as_ref(), Some(&expected));
            assert_eq!(event.decision_id(), Some(expected.decision_id));
            assert_eq!(event.output_seq(), Some(expected.output_seq.get()));
        }
    }

    #[test]
    fn same_output_position_with_a_different_source_is_a_conflicting_replay() {
        let mut plant = ReferencePlant::new(PlantConfig::default(), sess(1)).unwrap();
        let accepted = cmd_with_source(1, 1, 1, PlantAction::Hold, 200, source_with(1), 1);
        let conflicting = cmd_with_source(1, 1, 1, PlantAction::Hold, 200, source_with(2), 1);
        let conflicting_correlation = correlation(&conflicting);
        plant.ingest(accepted).unwrap();
        let authority_before = (plant.last_accepted.clone(), plant.current.clone());

        assert_eq!(
            plant.ingest(conflicting),
            Err(PlantIngestError::Rejected(RejectReason::ConflictingReplay))
        );
        assert_eq!(
            (plant.last_accepted.clone(), plant.current.clone()),
            authority_before
        );
        assert_eq!(
            plant
                .events()
                .last()
                .and_then(|event| event.command.as_ref()),
            Some(&conflicting_correlation)
        );
    }

    #[test]
    fn same_output_position_with_different_exact_bytes_is_a_conflicting_replay() {
        let mut plant = ReferencePlant::new(PlantConfig::default(), sess(1)).unwrap();
        let accepted = cmd_with_source(1, 1, 1, PlantAction::Hold, 200, source_with(1), 1);
        let conflicting = cmd_with_source(1, 1, 1, PlantAction::Hold, 200, source_with(1), 2);
        assert_ne!(
            accepted.output_frame_digest(),
            conflicting.output_frame_digest()
        );
        plant.ingest(accepted).unwrap();
        let authority_before = (plant.last_accepted.clone(), plant.current.clone());

        assert_eq!(
            plant.ingest(conflicting),
            Err(PlantIngestError::Rejected(RejectReason::ConflictingReplay))
        );
        assert_eq!(
            (plant.last_accepted.clone(), plant.current.clone()),
            authority_before
        );
    }

    #[test]
    fn rejected_command_does_not_wedge_the_stream() {
        // Regression for BUG-3: a rejected command (new epoch + wrong session) must
        // NOT retire the live epoch or reset the sequence high-water.
        let mut p = ReferencePlant::new(PlantConfig::default(), sess(1)).unwrap();
        p.ingest(cmd(1, 1, 5, PlantAction::Hold, 200)).unwrap();
        assert_eq!(
            p.ingest(cmd(2, 2, 1, PlantAction::Hold, 200)),
            Err(PlantIngestError::Rejected(RejectReason::WrongSession))
        );
        // epoch 1 is still live: a legitimate next command is accepted.
        assert!(p.ingest(cmd(1, 1, 6, PlantAction::Hold, 200)).is_ok());
    }

    #[test]
    fn receiver_session_is_configured_before_the_first_command() {
        let mut p = ReferencePlant::new(PlantConfig::default(), sess(1)).unwrap();
        assert_eq!(
            p.ingest(cmd(2, 1, 1, PlantAction::Hold, 200)),
            Err(PlantIngestError::Rejected(RejectReason::WrongSession))
        );
        assert_eq!(p.session(), &sess(1));
        assert!(p.last_accepted.is_none());
        assert!(p.current.is_none());

        p.ingest(cmd(1, 1, 1, PlantAction::Hold, 200))
            .expect("a rejected first frame cannot rebind the receiver session");
    }

    #[test]
    fn retired_epoch_rejected() {
        let mut p = ReferencePlant::new(PlantConfig::default(), sess(1)).unwrap();
        p.ingest(cmd(1, 1, 1, PlantAction::Hold, 200)).unwrap();
        p.run(10).unwrap();
        p.ingest(cmd(1, 2, 1, PlantAction::Hold, 200)).unwrap();
        assert_eq!(
            p.ingest(cmd(1, 1, 9, PlantAction::Hold, 200)),
            Err(PlantIngestError::Rejected(RejectReason::RetiredEpoch))
        );
    }

    #[test]
    fn foreign_epoch_is_rejected_while_prior_stream_is_live_then_allowed_at_expiry() {
        let mut plant = ReferencePlant::new(PlantConfig::default(), sess(1)).unwrap();
        plant
            .ingest(cmd(1, 1, 7, PlantAction::Velocity([1000, 0, 0]), 40))
            .unwrap();
        plant.step().unwrap();
        let authority_before = (plant.last_accepted.clone(), plant.current.clone());

        assert_eq!(
            plant.ingest(cmd(1, 2, 99, PlantAction::Hold, 200)),
            Err(PlantIngestError::Rejected(RejectReason::PriorStreamLive))
        );
        assert_eq!(
            (plant.last_accepted.clone(), plant.current.clone()),
            authority_before,
            "a foreign live epoch must not replace or refresh current authority"
        );

        plant.step().unwrap();
        assert_eq!(plant.tick(), 2, "the old horizon ends at this boundary");
        plant
            .ingest(cmd(1, 2, 99, PlantAction::Hold, 200))
            .expect("the same new epoch is eligible at exact prior expiry");
        assert_eq!(plant.last_accepted.as_ref().unwrap().output_epoch, epoch(2));
        assert!(plant.retired.contains(&epoch(1)));
    }

    #[test]
    fn no_command_no_motion_single_ingress() {
        let mut p = ReferencePlant::new(PlantConfig::default(), sess(1)).unwrap();
        p.run(50).unwrap();
        assert_eq!(p.snapshot().velocity_mm_s, [0, 0, 0]);
        assert_eq!(p.snapshot().position_mm, [0, 0, 0]);
        assert!(!has(&p, PlantEventKind::Applied));
    }

    #[test]
    fn evidence_is_deterministic() {
        let build = || {
            let mut p = ReferencePlant::new(PlantConfig::default(), sess(1)).unwrap();
            p.ingest(cmd(1, 1, 1, PlantAction::Velocity([1500, -500, 0]), 200))
                .unwrap();
            p.run(30).unwrap();
            p.events().to_vec()
        };
        assert_eq!(build(), build(), "same schedule => byte-identical evidence");
    }

    #[test]
    fn accepted_ingest_is_transactional_when_evidence_capacity_is_insufficient() {
        let config = PlantConfig {
            max_events: 2,
            ..PlantConfig::default()
        };
        let mut plant = ReferencePlant::new(config, sess(1)).unwrap();
        let before = plant.clone();

        assert_eq!(
            plant.ingest(cmd(1, 1, 1, PlantAction::Hold, 200)),
            Err(PlantIngestError::Runtime(
                PlantRuntimeError::EvidenceCapacityExhausted { maximum: 2 }
            ))
        );
        assert_eq!(plant, before);
    }

    #[test]
    fn rejected_ingest_is_transactional_when_rejection_cannot_be_evidenced() {
        let config = PlantConfig {
            max_events: 1,
            ..PlantConfig::default()
        };
        let mut plant = ReferencePlant::new(config, sess(1)).unwrap();
        let before = plant.clone();

        assert_eq!(
            plant.ingest(cmd(2, 1, 1, PlantAction::Hold, 200)),
            Err(PlantIngestError::Runtime(
                PlantRuntimeError::EvidenceCapacityExhausted { maximum: 1 }
            ))
        );
        assert_eq!(plant, before);
    }

    #[test]
    fn semantic_rejection_records_exact_evidence_without_authority_mutation() {
        let mut plant = ReferencePlant::new(PlantConfig::default(), sess(1)).unwrap();
        plant.ingest(cmd(1, 1, 5, PlantAction::Hold, 200)).unwrap();
        let authority_before = (
            plant.last_accepted.clone(),
            plant.retired.clone(),
            plant.current.clone(),
        );
        let rejected = cmd(2, 2, 1, PlantAction::Hold, 200);
        let rejected_correlation = correlation(&rejected);

        assert_eq!(
            plant.ingest(rejected),
            Err(PlantIngestError::Rejected(RejectReason::WrongSession))
        );
        assert_eq!(
            (
                plant.last_accepted.clone(),
                plant.retired.clone(),
                plant.current.clone(),
            ),
            authority_before
        );
        assert_eq!(
            &plant.events()[plant.events().len() - 2..],
            &[
                PlantEvent {
                    tick: 0,
                    kind: PlantEventKind::Received,
                    command: Some(rejected_correlation.clone()),
                    state: KinematicSnapshot {
                        position_mm: [0; 3],
                        velocity_mm_s: [0; 3],
                    },
                },
                PlantEvent {
                    tick: 0,
                    kind: PlantEventKind::Rejected(RejectReason::WrongSession),
                    command: Some(rejected_correlation),
                    state: KinematicSnapshot {
                        position_mm: [0; 3],
                        velocity_mm_s: [0; 3],
                    },
                },
            ]
        );
    }

    #[test]
    fn step_is_transactional_when_evidence_capacity_is_exhausted() {
        let config = PlantConfig {
            max_events: 3,
            ..PlantConfig::default()
        };
        let mut plant = ReferencePlant::new(config, sess(1)).unwrap();
        plant.ingest(cmd(1, 1, 1, PlantAction::Hold, 200)).unwrap();
        let before = plant.clone();

        assert_eq!(
            plant.step(),
            Err(PlantRuntimeError::EvidenceCapacityExhausted { maximum: 3 })
        );
        assert_eq!(plant, before);
    }

    #[test]
    fn retired_epoch_capacity_exhaustion_quiesces_rotation_transactionally() {
        let config = PlantConfig {
            max_retired_epochs: 1,
            ..PlantConfig::default()
        };
        let mut plant = ReferencePlant::new(config, sess(1)).unwrap();
        plant.ingest(cmd(1, 1, 5, PlantAction::Hold, 200)).unwrap();
        plant.run(10).unwrap();
        plant.ingest(cmd(1, 2, 1, PlantAction::Hold, 200)).unwrap();
        plant.run(10).unwrap();
        let before = plant.clone();

        assert_eq!(
            plant.ingest(cmd(1, 3, 1, PlantAction::Hold, 200)),
            Err(PlantIngestError::Runtime(
                PlantRuntimeError::RetiredEpochCapacityExhausted { maximum: 1 }
            ))
        );
        assert_eq!(plant, before);
    }

    #[test]
    fn zero_retired_epoch_capacity_allows_initial_epoch_but_no_rotation() {
        let config = PlantConfig {
            max_retired_epochs: 0,
            ..PlantConfig::default()
        };
        let mut plant = ReferencePlant::new(config, sess(1)).unwrap();
        plant.ingest(cmd(1, 1, 5, PlantAction::Hold, 200)).unwrap();
        plant.run(10).unwrap();
        let before = plant.clone();

        assert_eq!(
            plant.ingest(cmd(1, 2, 1, PlantAction::Hold, 200)),
            Err(PlantIngestError::Runtime(
                PlantRuntimeError::RetiredEpochCapacityExhausted { maximum: 0 }
            ))
        );
        assert_eq!(plant, before);
    }

    #[test]
    fn expiry_overflow_rejects_ingest_transactionally() {
        let mut plant = ReferencePlant::new(PlantConfig::default(), sess(1)).unwrap();
        plant.tick = u64::MAX - 1;
        let before = plant.clone();

        assert_eq!(
            plant.ingest(cmd(1, 1, 1, PlantAction::Hold, 40)),
            Err(PlantIngestError::Runtime(PlantRuntimeError::TimeExhausted))
        );
        assert_eq!(plant, before);
    }

    #[test]
    fn exact_last_tick_is_representable_then_time_exhaustion_is_transactional() {
        let mut plant = ReferencePlant::new(PlantConfig::default(), sess(1)).unwrap();
        plant.tick = u64::MAX - 1;
        plant.ingest(cmd(1, 1, 1, PlantAction::Hold, 20)).unwrap();
        plant.step().unwrap();
        assert_eq!(plant.tick(), u64::MAX);
        let before = plant.clone();

        assert_eq!(plant.step(), Err(PlantRuntimeError::TimeExhausted));
        assert_eq!(plant, before);
    }

    #[test]
    fn validity_uses_only_complete_ticks_without_extending_authority() {
        for (validity_ms, applies_on_first_tick) in
            [(1, false), (19, false), (20, true), (21, true)]
        {
            let mut plant = ReferencePlant::new(PlantConfig::default(), sess(1)).unwrap();
            plant
                .ingest(cmd(1, 1, 1, PlantAction::Hold, validity_ms))
                .unwrap();

            plant.step().unwrap();
            assert_eq!(
                has(&plant, PlantEventKind::Applied),
                applies_on_first_tick,
                "validity_ms={validity_ms}"
            );

            plant.step().unwrap();
            assert!(
                has(&plant, PlantEventKind::Expired),
                "validity_ms={validity_ms}"
            );
        }
    }

    #[test]
    fn normal_acceleration_is_bounded_by_vector_magnitude() {
        let mut plant = ReferencePlant::new(PlantConfig::default(), sess(1)).unwrap();
        plant
            .ingest(cmd(1, 1, 1, PlantAction::Velocity([1000, 1000, 1000]), 200))
            .unwrap();

        plant.step().unwrap();

        let velocity = plant.snapshot().velocity_mm_s;
        let velocity = velocity.map(i128::from);
        assert!(squared_norm(velocity).unwrap() <= 80u128 * 80);
        assert!(velocity.iter().filter(|component| **component != 0).count() > 1);
    }

    #[test]
    fn sub_millimetre_motion_accumulates_without_per_tick_truncation() {
        let config = PlantConfig {
            tick_ms: 20,
            max_accel_mm_s2: 1000,
            safe_decel_mm_s2: 1000,
            ..PlantConfig::default()
        };
        let mut positive = ReferencePlant::new(config, sess(1)).unwrap();
        positive
            .ingest(cmd(1, 1, 1, PlantAction::Velocity([10, 0, 0]), 200))
            .unwrap();

        positive.run(4).unwrap();
        assert_eq!(positive.snapshot().position_mm[0], 0);
        assert_eq!(positive.position_sub_mm_remainder[0], 800);
        positive.step().unwrap();
        assert_eq!(positive.snapshot().position_mm[0], 1);
        assert_eq!(positive.position_sub_mm_remainder[0], 0);

        let mut negative = ReferencePlant::new(config, sess(1)).unwrap();
        negative
            .ingest(cmd(1, 1, 1, PlantAction::Velocity([-10, 0, 0]), 200))
            .unwrap();
        negative.run(5).unwrap();
        assert_eq!(negative.snapshot().position_mm[0], -1);
        assert_eq!(negative.position_sub_mm_remainder[0], 0);
    }

    #[test]
    fn safe_deceleration_is_bounded_by_vector_magnitude() {
        let mut plant = ReferencePlant::new(PlantConfig::default(), sess(1)).unwrap();
        plant.vel = [1000, 1000, 1000];
        plant.in_safe_action = true;
        let before = plant.vel;

        plant.step().unwrap();

        let mut delta = [0i128; 3];
        for ((component, &old), &new) in delta.iter_mut().zip(before.iter()).zip(plant.vel.iter()) {
            *component = i128::from(new) - i128::from(old);
        }
        assert!(squared_norm(delta).unwrap() <= 120u128 * 120);
    }

    #[test]
    fn vector_approach_is_deterministic_bounded_and_progresses_at_integer_limits() {
        for (current, target, limit) in [
            ([0, 0, 0], [1, 1, 1], 1),
            ([0, 0, 0], [i32::MAX, i32::MAX, i32::MAX], 80),
            ([i32::MAX, i32::MIN, 0], [i32::MIN, i32::MAX, i32::MIN], 120),
        ] {
            let next = approach_vector(current, target, limit).unwrap();
            assert_eq!(next, approach_vector(current, target, limit).unwrap());
            assert_ne!(next, current);
            let mut delta = [0i128; 3];
            for ((component, &old), &new) in delta.iter_mut().zip(current.iter()).zip(next.iter()) {
                *component = i128::from(new) - i128::from(old);
            }
            assert!(squared_norm(delta).unwrap() <= u128::from(limit).pow(2));
        }
    }

    #[test]
    fn positive_position_boundary_is_exact_then_overflow_is_transactional() {
        let mut plant = ReferencePlant::new(PlantConfig::default(), sess(1)).unwrap();
        plant
            .ingest(cmd(1, 1, 1, PlantAction::Velocity([1000, 0, 0]), 200))
            .unwrap();
        plant.pos[0] = i64::MAX - 20;
        plant.vel[0] = 1000;
        plant.step().unwrap();
        assert_eq!(plant.snapshot().position_mm[0], i64::MAX);
        let before = plant.clone();

        assert_eq!(plant.step(), Err(PlantRuntimeError::PositionOverflow));
        assert_eq!(plant, before);
    }

    #[test]
    fn negative_position_boundary_is_exact_then_overflow_is_transactional() {
        let mut plant = ReferencePlant::new(PlantConfig::default(), sess(1)).unwrap();
        plant
            .ingest(cmd(1, 1, 1, PlantAction::Velocity([-1000, 0, 0]), 200))
            .unwrap();
        plant.pos[0] = i64::MIN + 20;
        plant.vel[0] = -1000;
        plant.step().unwrap();
        assert_eq!(plant.snapshot().position_mm[0], i64::MIN);
        let before = plant.clone();

        assert_eq!(plant.step(), Err(PlantRuntimeError::PositionOverflow));
        assert_eq!(plant, before);
    }

    #[test]
    fn fractional_position_boundary_overflow_is_rejected_transactionally() {
        let mut plant = ReferencePlant::new(PlantConfig::default(), sess(1)).unwrap();
        plant
            .ingest(cmd(1, 1, 1, PlantAction::Velocity([10, 0, 0]), 200))
            .unwrap();
        plant.pos[0] = i64::MAX;
        plant.position_sub_mm_remainder[0] = 900;
        plant.vel[0] = 10;
        let before = plant.clone();

        assert_eq!(plant.step(), Err(PlantRuntimeError::PositionOverflow));
        assert_eq!(plant, before);
    }

    #[test]
    fn malformed_private_fractional_state_fails_transactionally_in_release_logic() {
        let mut plant = ReferencePlant::new(PlantConfig::default(), sess(1)).unwrap();
        plant.position_sub_mm_remainder[0] = 1000;
        let before = plant.clone();

        assert_eq!(
            plant.step(),
            Err(PlantRuntimeError::KinematicInvariantViolation)
        );
        assert_eq!(plant, before);
    }

    #[test]
    fn vector_distance_uses_full_width_without_saturating_subtraction() {
        assert!(!vectors_within(
            [i32::MAX, 0, 0],
            [i32::MIN, 0, 0],
            i32::MAX
        ));
        assert!(vectors_within([i32::MAX, 0, 0], [0, 0, 0], i32::MAX));
    }

    #[test]
    fn public_errors_have_stable_codes_display_and_standard_sources() {
        fn assert_standard_error<T: std::error::Error + Send + Sync + 'static>() {}

        for (error, expected) in [
            (
                PlantConfigError::ZeroTickPeriod,
                "PLANT_CONFIG_ZERO_TICK_PERIOD",
            ),
            (
                PlantConfigError::NonPositiveMaxAcceleration { configured: 0 },
                "PLANT_CONFIG_NON_POSITIVE_MAX_ACCELERATION",
            ),
            (
                PlantConfigError::NonPositiveSafeDeceleration { configured: 0 },
                "PLANT_CONFIG_NON_POSITIVE_SAFE_DECELERATION",
            ),
            (
                PlantConfigError::ZeroNormalVelocityDelta,
                "PLANT_CONFIG_ZERO_NORMAL_VELOCITY_DELTA",
            ),
            (
                PlantConfigError::ZeroSafeVelocityDelta,
                "PLANT_CONFIG_ZERO_SAFE_VELOCITY_DELTA",
            ),
            (
                PlantConfigError::NegativeHoldEpsilon { configured: -1 },
                "PLANT_CONFIG_NEGATIVE_HOLD_EPSILON",
            ),
            (
                PlantConfigError::ZeroEventCapacity,
                "PLANT_CONFIG_ZERO_EVENT_CAPACITY",
            ),
            (
                PlantConfigError::EventCapacityTooLarge {
                    configured: 2,
                    maximum: 1,
                },
                "PLANT_CONFIG_EVENT_CAPACITY_TOO_LARGE",
            ),
            (
                PlantConfigError::RetiredEpochCapacityTooLarge {
                    configured: 2,
                    maximum: 1,
                },
                "PLANT_CONFIG_RETIRED_EPOCH_CAPACITY_TOO_LARGE",
            ),
        ] {
            assert_eq!(error.as_str(), expected);
            assert_eq!(error.to_string(), expected);
        }
        assert_standard_error::<PlantConfigError>();

        for (error, expected) in [
            (
                PlantRuntimeError::TimeExhausted,
                "PLANT_RUNTIME_TIME_EXHAUSTED",
            ),
            (
                PlantRuntimeError::PositionOverflow,
                "PLANT_RUNTIME_POSITION_OVERFLOW",
            ),
            (
                PlantRuntimeError::KinematicArithmeticOverflow,
                "PLANT_RUNTIME_KINEMATIC_ARITHMETIC_OVERFLOW",
            ),
            (
                PlantRuntimeError::KinematicInvariantViolation,
                "PLANT_RUNTIME_KINEMATIC_INVARIANT_VIOLATION",
            ),
            (
                PlantRuntimeError::EvidenceCapacityExhausted { maximum: 1 },
                "PLANT_RUNTIME_EVIDENCE_CAPACITY_EXHAUSTED",
            ),
            (
                PlantRuntimeError::EvidenceAllocationFailed,
                "PLANT_RUNTIME_EVIDENCE_ALLOCATION_FAILED",
            ),
            (
                PlantRuntimeError::RetiredEpochCapacityExhausted { maximum: 1 },
                "PLANT_RUNTIME_RETIRED_EPOCH_CAPACITY_EXHAUSTED",
            ),
            (
                PlantRuntimeError::RetiredEpochAllocationFailed,
                "PLANT_RUNTIME_RETIRED_EPOCH_ALLOCATION_FAILED",
            ),
        ] {
            assert_eq!(error.as_str(), expected);
            assert_eq!(error.to_string(), expected);
        }
        assert_standard_error::<PlantRuntimeError>();

        for (error, expected) in [
            (
                RejectReason::InvalidOutputFrame,
                "PLANT_REJECT_INVALID_OUTPUT_FRAME",
            ),
            (RejectReason::WrongSession, "PLANT_REJECT_WRONG_SESSION"),
            (RejectReason::RetiredEpoch, "PLANT_REJECT_RETIRED_EPOCH"),
            (
                RejectReason::PriorStreamLive,
                "PLANT_REJECT_PRIOR_STREAM_LIVE",
            ),
            (
                RejectReason::DuplicateOrStale,
                "PLANT_REJECT_DUPLICATE_OR_STALE",
            ),
            (
                RejectReason::ConflictingReplay,
                "PLANT_REJECT_CONFLICTING_REPLAY",
            ),
        ] {
            assert_eq!(error.as_str(), expected);
            assert_eq!(error.to_string(), expected);
        }
        assert_standard_error::<RejectReason>();

        let command_error = PlantCommandError::InvalidExactFrame;
        assert_eq!(command_error.as_str(), "PLANT_COMMAND_INVALID_EXACT_FRAME");
        assert_eq!(command_error.to_string(), command_error.as_str());
        assert_standard_error::<PlantCommandError>();

        let runtime = PlantRuntimeError::TimeExhausted;
        let ingest = PlantIngestError::Runtime(runtime);
        assert_eq!(ingest.as_str(), runtime.as_str());
        assert_eq!(ingest.to_string(), runtime.as_str());
        assert_eq!(
            std::error::Error::source(&ingest).map(ToString::to_string),
            Some(runtime.to_string())
        );
        let rejection = RejectReason::RetiredEpoch;
        let ingest = PlantIngestError::Rejected(rejection);
        assert_eq!(ingest.as_str(), rejection.as_str());
        assert_eq!(
            std::error::Error::source(&ingest).map(ToString::to_string),
            Some(rejection.to_string())
        );
        assert_standard_error::<PlantIngestError>();
    }
}
