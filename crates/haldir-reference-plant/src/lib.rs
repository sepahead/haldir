//! `haldir-reference-plant` — a deterministic kinematic point-mass plant that
//! separates command receipt, acceptance, selection, application, expiry,
//! plant-owned safe action, and measured response into distinct evidence stages.
//!
//! It has exactly one command ingress ([`ReferencePlant::ingest`]); nothing else
//! changes the commanded velocity (spec A1/B15). Given a seed schedule the plant
//! produces byte-identical evidence. The safe-action profile is
//! `reference-kinematic-hold-v1`: bounded deceleration to a declared hold region.
//! Construction and every runtime transition are checked. Configuration,
//! evidence, retired-epoch, time, or fixed-point range exhaustion returns a typed
//! error instead of silently saturating or committing a partial transition.
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
    KinematicSnapshot, PlantAction, PlantCommand, PlantEvent, PlantEventKind, RejectReason,
};

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
    /// Normal acceleration limit (mm/s^2).
    pub max_accel_mm_s2: i32,
    /// Safe-action deceleration limit (mm/s^2).
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
    decision_id: [u8; 16],
    output_seq: u64,
    expiry_tick: u64,
    velocity: [i32; 3],
    applied_recorded: bool,
    response_recorded: bool,
}

/// The deterministic reference plant.
#[cfg_attr(test, derive(Debug, Clone, PartialEq, Eq))]
pub struct ReferencePlant {
    cfg: PlantConfig,
    tick: u64,
    pos: [i64; 3],
    vel: [i32; 3],
    current: Option<Active>,
    session: Option<NcpSessionIdentityV1>,
    epoch: Option<GateOutputEpoch>,
    retired: Vec<GateOutputEpoch>,
    last_seq: u64,
    in_safe_action: bool,
    safe_reached: bool,
    events: Vec<PlantEvent>,
}

impl ReferencePlant {
    /// Construct a checked plant at rest at the origin.
    ///
    /// # Errors
    /// Returns [`PlantConfigError`] before constructing any state when `cfg`
    /// violates a kinematic or resource invariant.
    pub fn new(cfg: PlantConfig) -> Result<Self, PlantConfigError> {
        cfg.validate()?;
        Ok(Self {
            cfg,
            tick: 0,
            pos: [0; 3],
            vel: [0; 3],
            current: None,
            session: None,
            epoch: None,
            retired: Vec::new(),
            last_seq: 0,
            in_safe_action: false,
            safe_reached: false,
            events: Vec::new(),
        })
    }

    /// The current tick.
    #[must_use]
    pub const fn tick(&self) -> u64 {
        self.tick
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
        decision_id: Option<[u8; 16]>,
        output_seq: Option<u64>,
    ) {
        self.events.push(PlantEvent {
            tick: self.tick,
            kind,
            decision_id: decision_id.map(haldir_contracts::ids::DecisionId::new),
            output_seq,
            state: self.snapshot(),
        });
    }

    fn reject(&mut self, cmd: &PlantCommand, reason: RejectReason) -> Result<(), PlantIngestError> {
        self.ensure_event_capacity(2)?;
        self.push_preflighted(
            K::Received,
            Some(*cmd.decision_id.as_bytes()),
            Some(cmd.output_seq.get()),
        );
        self.push_preflighted(K::Rejected(reason), None, None);
        Err(reason.into())
    }

    /// Submit a Gate-authored command to the receiver (the only command ingress).
    /// A receiver rejection records `Received` + `Rejected` but never refreshes
    /// the active command's expiry (spec S6). A local runtime failure is fully
    /// transactional: it changes neither receiver state nor evidence.
    ///
    /// # Errors
    /// Returns [`PlantIngestError::Rejected`] when a command fails receiver
    /// validation, or [`PlantIngestError::Runtime`] when bounded evidence,
    /// tombstone, allocation, or time arithmetic prevents an atomic commit.
    pub fn ingest(&mut self, cmd: PlantCommand) -> Result<(), PlantIngestError> {
        if cmd.validity_ms == 0 {
            return self.reject(&cmd, RejectReason::ZeroValidity);
        }
        if let Some(cur) = &self.session
            && *cur != cmd.session
        {
            return self.reject(&cmd, RejectReason::WrongSession);
        }
        if self.retired.contains(&cmd.output_epoch) {
            return self.reject(&cmd, RejectReason::RetiredEpoch);
        }
        let is_new_epoch = self.epoch.as_ref().is_none_or(|e| *e != cmd.output_epoch);
        let baseline = if is_new_epoch { 0 } else { self.last_seq };
        if cmd.output_seq.get() <= baseline {
            return self.reject(&cmd, RejectReason::DuplicateOrStale);
        }

        let decision_bytes = *cmd.decision_id.as_bytes();
        let seq = cmd.output_seq.get();
        let epoch = cmd.output_epoch;
        let velocity = cmd.action.velocity();
        let retired_epoch = self.epoch.filter(|active| *active != epoch);
        let ticks = u64::from(cmd.validity_ms.div_ceil(self.cfg.tick_ms));
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
        self.epoch = Some(epoch);
        if self.session.is_none() {
            self.session = Some(cmd.session);
        }
        self.last_seq = seq;
        self.current = Some(Active {
            decision_id: decision_bytes,
            output_seq: seq,
            expiry_tick,
            velocity,
            applied_recorded: false,
            response_recorded: false,
        });
        self.in_safe_action = false;
        self.safe_reached = false;

        self.push_preflighted(K::Received, Some(decision_bytes), Some(seq));
        self.push_preflighted(K::Validated, Some(decision_bytes), Some(seq));
        self.push_preflighted(K::Accepted, Some(decision_bytes), Some(seq));
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
        let mut selected: Option<([u8; 16], u64)> = None;
        let mut just_applied = false;
        let mut expired: Option<([u8; 16], u64)> = None;

        if let Some(active) = self.current.as_ref() {
            if next_tick <= active.expiry_tick {
                target = active.velocity;
                selected = Some((active.decision_id, active.output_seq));
                if !active.applied_recorded {
                    just_applied = true;
                }
            } else {
                expired = Some((active.decision_id, active.output_seq));
            }
        }
        let mut next_in_safe_action = self.in_safe_action;
        let mut next_safe_reached = self.safe_reached;
        let mut start_safe = false;
        if expired.is_some() && !next_in_safe_action {
            next_in_safe_action = true;
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
        let mut new_vel = [0i32; 3];
        for ((nv, &cur), &tgt) in new_vel.iter_mut().zip(self.vel.iter()).zip(target.iter()) {
            *nv = approach(cur, tgt, dv_max)?;
        }
        let mut new_pos = self.pos;
        for (np, &v) in new_pos.iter_mut().zip(new_vel.iter()) {
            let delta = i64::from(v)
                .checked_mul(dt)
                .ok_or(PlantRuntimeError::KinematicArithmeticOverflow)?
                / 1000;
            *np = np
                .checked_add(delta)
                .ok_or(PlantRuntimeError::PositionOverflow)?;
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
        self.in_safe_action = next_in_safe_action;
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

        if let Some((did, seq)) = expired {
            self.push_preflighted(K::Expired, Some(did), Some(seq));
        }
        if start_safe {
            self.push_preflighted(K::SafeActionStarted, None, None);
        }
        if just_applied && let Some((did, seq)) = selected {
            self.push_preflighted(K::Selected, Some(did), Some(seq));
            self.push_preflighted(K::Applied, Some(did), Some(seq));
        }
        if response_observed && let Some((did, seq)) = selected {
            self.push_preflighted(K::ResponseObserved, Some(did), Some(seq));
        }
        if safe_region_reached {
            self.push_preflighted(K::SafeRegionReached, None, None);
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

fn approach(current: i32, target: i32, dv_max: u64) -> Result<i32, PlantRuntimeError> {
    let cur = i128::from(current);
    let tgt = i128::from(target);
    let delta = i128::from(dv_max);
    let next = if tgt > cur {
        (cur + delta).min(tgt)
    } else if tgt < cur {
        (cur - delta).max(tgt)
    } else {
        cur
    };
    i32::try_from(next.clamp(i128::from(i32::MIN), i128::from(i32::MAX)))
        .map_err(|_| PlantRuntimeError::KinematicArithmeticOverflow)
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
    use core::num::NonZeroU64;
    use haldir_contracts::digest::{DigestDomain, DigestV1};
    use haldir_contracts::ids::{DecisionId, GateOutputEpoch, OutputSeq, SourceSeq};
    use haldir_contracts::scalar::{AsciiId, BoundedAscii, CanonicalUuidV4String};
    use haldir_contracts::session::{NcpSessionIdentityV1, NcpSourceRefV1};

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
        NcpSourceRefV1 {
            source_key: BoundedAscii::new("veh/uav-1/state/pose").unwrap(),
            stream_epoch: CanonicalUuidV4String::from_random_bytes([2; 16]),
            stream_seq: SourceSeq::new(NonZeroU64::new(1).unwrap()),
        }
    }
    fn cmd(g: u8, ep: u8, seq: u64, action: PlantAction, validity_ms: u32) -> PlantCommand {
        PlantCommand {
            decision_id: DecisionId::new([seq as u8; 16]),
            session: sess(g),
            output_epoch: epoch(ep),
            output_seq: OutputSeq::new(NonZeroU64::new(seq).unwrap()),
            source: source(),
            action,
            validity_ms,
            output_frame_digest: DigestV1::compute(DigestDomain::OutputFrame, &[seq as u8]),
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
        assert!(ReferencePlant::new(lower).is_ok());

        let upper = PlantConfig {
            max_events: HARD_MAX_EVENTS,
            max_retired_epochs: HARD_MAX_RETIRED_EPOCHS,
            ..PlantConfig::default()
        };
        assert!(ReferencePlant::new(upper).is_ok());
    }

    #[test]
    fn checked_construction_rejects_zero_tick_period() {
        let config = PlantConfig {
            tick_ms: 0,
            ..PlantConfig::default()
        };
        assert_eq!(
            ReferencePlant::new(config).unwrap_err(),
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
                ReferencePlant::new(config).unwrap_err(),
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
                ReferencePlant::new(config).unwrap_err(),
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
            ReferencePlant::new(normal).unwrap_err(),
            PlantConfigError::ZeroNormalVelocityDelta
        );

        let safe = PlantConfig {
            tick_ms: 1,
            max_accel_mm_s2: 1000,
            safe_decel_mm_s2: 999,
            ..PlantConfig::default()
        };
        assert_eq!(
            ReferencePlant::new(safe).unwrap_err(),
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
            ReferencePlant::new(config).unwrap_err(),
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
            ReferencePlant::new(zero).unwrap_err(),
            PlantConfigError::ZeroEventCapacity
        );

        let too_large = PlantConfig {
            max_events: HARD_MAX_EVENTS + 1,
            ..PlantConfig::default()
        };
        assert_eq!(
            ReferencePlant::new(too_large).unwrap_err(),
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
            ReferencePlant::new(config).unwrap_err(),
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
        let mut p = ReferencePlant::new(PlantConfig::default()).unwrap();
        p.ingest(cmd(1, 1, 1, PlantAction::Velocity([800, 0, 0]), 600))
            .unwrap();
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
    }

    #[test]
    fn duplicate_command_does_not_refresh_expiry() {
        let mut p = ReferencePlant::new(PlantConfig::default()).unwrap();
        p.ingest(cmd(1, 1, 1, PlantAction::Velocity([1000, 0, 0]), 200))
            .unwrap();
        assert_eq!(
            p.ingest(cmd(1, 1, 1, PlantAction::Velocity([1000, 0, 0]), 5000)),
            Err(PlantIngestError::Rejected(RejectReason::DuplicateOrStale))
        );
    }

    #[test]
    fn rejected_command_does_not_wedge_the_stream() {
        // Regression for BUG-3: a rejected command (new epoch + zero validity) must
        // NOT retire the live epoch or reset the sequence high-water.
        let mut p = ReferencePlant::new(PlantConfig::default()).unwrap();
        p.ingest(cmd(1, 1, 5, PlantAction::Hold, 200)).unwrap();
        assert_eq!(
            p.ingest(cmd(1, 2, 1, PlantAction::Hold, 0)),
            Err(PlantIngestError::Rejected(RejectReason::ZeroValidity))
        );
        // epoch 1 is still live: a legitimate next command is accepted.
        assert!(p.ingest(cmd(1, 1, 6, PlantAction::Hold, 200)).is_ok());
    }

    #[test]
    fn wrong_session_rejected() {
        let mut p = ReferencePlant::new(PlantConfig::default()).unwrap();
        p.ingest(cmd(1, 1, 1, PlantAction::Hold, 200)).unwrap();
        assert_eq!(
            p.ingest(cmd(2, 1, 2, PlantAction::Hold, 200)),
            Err(PlantIngestError::Rejected(RejectReason::WrongSession))
        );
    }

    #[test]
    fn retired_epoch_rejected() {
        let mut p = ReferencePlant::new(PlantConfig::default()).unwrap();
        p.ingest(cmd(1, 1, 1, PlantAction::Hold, 200)).unwrap();
        p.ingest(cmd(1, 2, 1, PlantAction::Hold, 200)).unwrap();
        assert_eq!(
            p.ingest(cmd(1, 1, 9, PlantAction::Hold, 200)),
            Err(PlantIngestError::Rejected(RejectReason::RetiredEpoch))
        );
    }

    #[test]
    fn no_command_no_motion_single_ingress() {
        let mut p = ReferencePlant::new(PlantConfig::default()).unwrap();
        p.run(50).unwrap();
        assert_eq!(p.snapshot().velocity_mm_s, [0, 0, 0]);
        assert_eq!(p.snapshot().position_mm, [0, 0, 0]);
        assert!(!has(&p, PlantEventKind::Applied));
    }

    #[test]
    fn evidence_is_deterministic() {
        let build = || {
            let mut p = ReferencePlant::new(PlantConfig::default()).unwrap();
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
        let mut plant = ReferencePlant::new(config).unwrap();
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
        let mut plant = ReferencePlant::new(config).unwrap();
        let before = plant.clone();

        assert_eq!(
            plant.ingest(cmd(1, 1, 1, PlantAction::Hold, 0)),
            Err(PlantIngestError::Runtime(
                PlantRuntimeError::EvidenceCapacityExhausted { maximum: 1 }
            ))
        );
        assert_eq!(plant, before);
    }

    #[test]
    fn semantic_rejection_records_exact_evidence_without_authority_mutation() {
        let mut plant = ReferencePlant::new(PlantConfig::default()).unwrap();
        plant.ingest(cmd(1, 1, 5, PlantAction::Hold, 200)).unwrap();
        let authority_before = (
            plant.session.clone(),
            plant.epoch,
            plant.retired.clone(),
            plant.last_seq,
            plant.current.clone(),
        );

        assert_eq!(
            plant.ingest(cmd(1, 2, 1, PlantAction::Hold, 0)),
            Err(PlantIngestError::Rejected(RejectReason::ZeroValidity))
        );
        assert_eq!(
            (
                plant.session.clone(),
                plant.epoch,
                plant.retired.clone(),
                plant.last_seq,
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
                    decision_id: Some(DecisionId::new([1; 16])),
                    output_seq: Some(1),
                    state: KinematicSnapshot {
                        position_mm: [0; 3],
                        velocity_mm_s: [0; 3],
                    },
                },
                PlantEvent {
                    tick: 0,
                    kind: PlantEventKind::Rejected(RejectReason::ZeroValidity),
                    decision_id: None,
                    output_seq: None,
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
        let mut plant = ReferencePlant::new(config).unwrap();
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
        let mut plant = ReferencePlant::new(config).unwrap();
        plant.ingest(cmd(1, 1, 5, PlantAction::Hold, 200)).unwrap();
        plant.ingest(cmd(1, 2, 1, PlantAction::Hold, 200)).unwrap();
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
        let mut plant = ReferencePlant::new(config).unwrap();
        plant.ingest(cmd(1, 1, 5, PlantAction::Hold, 200)).unwrap();
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
        let mut plant = ReferencePlant::new(PlantConfig::default()).unwrap();
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
        let mut plant = ReferencePlant::new(PlantConfig::default()).unwrap();
        plant.tick = u64::MAX - 1;
        plant.ingest(cmd(1, 1, 1, PlantAction::Hold, 20)).unwrap();
        plant.step().unwrap();
        assert_eq!(plant.tick(), u64::MAX);
        let before = plant.clone();

        assert_eq!(plant.step(), Err(PlantRuntimeError::TimeExhausted));
        assert_eq!(plant, before);
    }

    #[test]
    fn positive_position_boundary_is_exact_then_overflow_is_transactional() {
        let mut plant = ReferencePlant::new(PlantConfig::default()).unwrap();
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
        let mut plant = ReferencePlant::new(PlantConfig::default()).unwrap();
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
            (RejectReason::WrongSession, "PLANT_REJECT_WRONG_SESSION"),
            (RejectReason::RetiredEpoch, "PLANT_REJECT_RETIRED_EPOCH"),
            (
                RejectReason::DuplicateOrStale,
                "PLANT_REJECT_DUPLICATE_OR_STALE",
            ),
            (RejectReason::ZeroValidity, "PLANT_REJECT_ZERO_VALIDITY"),
        ] {
            assert_eq!(error.as_str(), expected);
            assert_eq!(error.to_string(), expected);
        }
        assert_standard_error::<RejectReason>();

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
