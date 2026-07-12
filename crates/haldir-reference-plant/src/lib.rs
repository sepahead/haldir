//! `haldir-reference-plant` — a deterministic kinematic point-mass plant that
//! separates command receipt, acceptance, selection, application, expiry,
//! plant-owned safe action, and measured response into distinct evidence stages.
//!
//! It has exactly one command ingress ([`ReferencePlant::ingest`]); nothing else
//! changes the commanded velocity (spec A1/B15). Given a seed schedule the plant
//! produces byte-identical evidence. The safe-action profile is
//! `reference-kinematic-hold-v1`: bounded deceleration to a declared hold region.
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

/// Deterministic plant configuration.
#[derive(Debug, Clone, Copy)]
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
}

impl Default for PlantConfig {
    fn default() -> Self {
        Self {
            tick_ms: 20,
            max_accel_mm_s2: 4000,
            safe_decel_mm_s2: 6000,
            hold_epsilon_mm_s: 10,
            max_events: 100_000,
        }
    }
}

struct Active {
    cmd: PlantCommand,
    expiry_tick: u64,
    velocity: [i32; 3],
    applied_recorded: bool,
    response_recorded: bool,
}

/// The deterministic reference plant.
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
    /// A new plant at rest at the origin.
    #[must_use]
    pub fn new(cfg: PlantConfig) -> Self {
        Self {
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
        }
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

    fn push(
        &mut self,
        kind: PlantEventKind,
        decision_id: Option<[u8; 16]>,
        output_seq: Option<u64>,
    ) {
        if self.events.len() >= self.cfg.max_events {
            return;
        }
        self.events.push(PlantEvent {
            tick: self.tick,
            kind,
            decision_id: decision_id.map(haldir_contracts::ids::DecisionId::new),
            output_seq,
            state: self.snapshot(),
        });
    }

    /// Submit a Gate-authored command to the receiver (the only command ingress).
    /// A rejection never refreshes the active command's expiry (spec S6).
    ///
    /// # Errors
    /// Returns a [`RejectReason`] when the command fails receiver validation.
    pub fn ingest(&mut self, cmd: PlantCommand) -> Result<(), RejectReason> {
        self.push(
            K::Received,
            Some(*cmd.decision_id.as_bytes()),
            Some(cmd.output_seq.get()),
        );

        if let Some(cur) = &self.session
            && *cur != cmd.session
        {
            self.push(K::Rejected(RejectReason::WrongSession), None, None);
            return Err(RejectReason::WrongSession);
        }
        if self.retired.contains(&cmd.output_epoch) {
            self.push(K::Rejected(RejectReason::RetiredEpoch), None, None);
            return Err(RejectReason::RetiredEpoch);
        }
        match &self.epoch {
            None => {
                self.epoch = Some(cmd.output_epoch);
                self.last_seq = 0;
            }
            Some(e) if *e != cmd.output_epoch => {
                self.retired.push(*e);
                self.epoch = Some(cmd.output_epoch);
                self.last_seq = 0;
            }
            Some(_) => {}
        }
        if cmd.output_seq.get() <= self.last_seq {
            self.push(K::Rejected(RejectReason::DuplicateOrStale), None, None);
            return Err(RejectReason::DuplicateOrStale);
        }
        if cmd.validity_ms == 0 {
            self.push(K::Rejected(RejectReason::ZeroValidity), None, None);
            return Err(RejectReason::ZeroValidity);
        }

        self.push(
            K::Validated,
            Some(*cmd.decision_id.as_bytes()),
            Some(cmd.output_seq.get()),
        );
        self.push(
            K::Accepted,
            Some(*cmd.decision_id.as_bytes()),
            Some(cmd.output_seq.get()),
        );

        if self.session.is_none() {
            self.session = Some(cmd.session.clone());
        }
        self.last_seq = cmd.output_seq.get();
        let ticks = u64::from(cmd.validity_ms.div_ceil(self.cfg.tick_ms.max(1)));
        let velocity = cmd.action.velocity();
        self.current = Some(Active {
            cmd,
            expiry_tick: self.tick.saturating_add(ticks),
            velocity,
            applied_recorded: false,
            response_recorded: false,
        });
        self.in_safe_action = false;
        self.safe_reached = false;
        Ok(())
    }

    /// Advance the simulation by one tick.
    pub fn step(&mut self) {
        self.tick = self.tick.saturating_add(1);
        let dt = i64::from(self.cfg.tick_ms);

        let mut target = [0i32; 3];
        let mut selected: Option<([u8; 16], u64)> = None;
        let mut just_applied = false;
        let mut expired: Option<([u8; 16], u64)> = None;

        if let Some(active) = self.current.as_mut() {
            if self.tick <= active.expiry_tick {
                target = active.velocity;
                selected = Some((
                    *active.cmd.decision_id.as_bytes(),
                    active.cmd.output_seq.get(),
                ));
                if !active.applied_recorded {
                    active.applied_recorded = true;
                    just_applied = true;
                }
            } else {
                expired = Some((
                    *active.cmd.decision_id.as_bytes(),
                    active.cmd.output_seq.get(),
                ));
            }
        }
        let mut start_safe = false;
        if expired.is_some() {
            self.current = None;
            if !self.in_safe_action {
                self.in_safe_action = true;
                self.safe_reached = false;
                start_safe = true;
            }
        }

        // physics: accel-limited approach to target, then integrate position
        let accel = if self.in_safe_action {
            self.cfg.safe_decel_mm_s2
        } else {
            self.cfg.max_accel_mm_s2
        };
        let dv_max = i64::from(accel) * dt / 1000;
        let mut new_vel = [0i32; 3];
        for ((nv, &cur), &tgt) in new_vel.iter_mut().zip(self.vel.iter()).zip(target.iter()) {
            *nv = approach(cur, tgt, dv_max);
        }
        let mut new_pos = self.pos;
        for (np, &v) in new_pos.iter_mut().zip(new_vel.iter()) {
            let delta = i64::from(v) * dt / 1000;
            *np = np.saturating_add(delta);
        }
        self.vel = new_vel;
        self.pos = new_pos;

        // events (recorded against post-physics state)
        if let Some((did, seq)) = expired {
            self.push(K::Expired, Some(did), Some(seq));
        }
        if start_safe {
            self.push(K::SafeActionStarted, None, None);
        }
        if just_applied && let Some((did, seq)) = selected {
            self.push(K::Selected, Some(did), Some(seq));
            self.push(K::Applied, Some(did), Some(seq));
        }
        // measured response consistent with the applied command
        if let Some((did, seq)) = selected {
            let reached = vectors_within(self.vel, target, self.cfg.hold_epsilon_mm_s);
            if reached
                && let Some(active) = self.current.as_mut()
                && !active.response_recorded
            {
                active.response_recorded = true;
                self.push(K::ResponseObserved, Some(did), Some(seq));
            }
        }
        // safe-region detection
        if self.in_safe_action && !self.safe_reached && self.in_hold_region() {
            self.safe_reached = true;
            self.push(K::SafeRegionReached, None, None);
        }
    }

    /// Run `n` ticks.
    pub fn run(&mut self, n: u64) {
        for _ in 0..n {
            self.step();
        }
    }

    /// Whether the plant reached its declared safe region during safe action.
    #[must_use]
    pub const fn safe_region_reached(&self) -> bool {
        self.safe_reached
    }
}

fn approach(current: i32, target: i32, dv_max: i64) -> i32 {
    let cur = i64::from(current);
    let tgt = i64::from(target);
    let next = if tgt > cur {
        (cur + dv_max).min(tgt)
    } else if tgt < cur {
        (cur - dv_max).max(tgt)
    } else {
        cur
    };
    i32::try_from(next.clamp(i64::from(i32::MIN), i64::from(i32::MAX))).unwrap_or(0)
}

fn speed_within(v: [i32; 3], eps: i32) -> bool {
    let sq: i128 = v.iter().map(|&c| i128::from(c) * i128::from(c)).sum();
    let e = i128::from(eps.max(0));
    sq <= e * e
}

fn vectors_within(a: [i32; 3], b: [i32; 3], eps: i32) -> bool {
    let d = [
        a[0].saturating_sub(b[0]),
        a[1].saturating_sub(b[1]),
        a[2].saturating_sub(b[2]),
    ];
    speed_within(d, eps)
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
    fn accepts_command_and_converges_then_holds_on_expiry() {
        // dv_max = 4000 mm/s^2 * 20 ms / 1000 = 80 mm/s per tick; 800 mm/s target
        // converges in 10 ticks, well within a 600 ms (30-tick) validity window.
        let mut p = ReferencePlant::new(PlantConfig::default());
        p.ingest(cmd(1, 1, 1, PlantAction::Velocity([800, 0, 0]), 600))
            .unwrap();
        p.run(15);
        assert!(has(&p, PlantEventKind::Accepted));
        assert!(has(&p, PlantEventKind::Applied));
        assert!(has(&p, PlantEventKind::ResponseObserved), "should converge");
        // now let the command expire and the plant reach the hold region
        p.run(30);
        assert!(has(&p, PlantEventKind::Expired));
        assert!(has(&p, PlantEventKind::SafeActionStarted));
        assert!(p.safe_region_reached());
        assert!(p.in_hold_region());
    }

    #[test]
    fn duplicate_command_does_not_refresh_expiry() {
        let mut p = ReferencePlant::new(PlantConfig::default());
        p.ingest(cmd(1, 1, 1, PlantAction::Velocity([1000, 0, 0]), 200))
            .unwrap();
        assert_eq!(
            p.ingest(cmd(1, 1, 1, PlantAction::Velocity([1000, 0, 0]), 5000)),
            Err(RejectReason::DuplicateOrStale)
        );
    }

    #[test]
    fn wrong_session_rejected() {
        let mut p = ReferencePlant::new(PlantConfig::default());
        p.ingest(cmd(1, 1, 1, PlantAction::Hold, 200)).unwrap();
        assert_eq!(
            p.ingest(cmd(2, 1, 2, PlantAction::Hold, 200)),
            Err(RejectReason::WrongSession)
        );
    }

    #[test]
    fn retired_epoch_rejected() {
        let mut p = ReferencePlant::new(PlantConfig::default());
        p.ingest(cmd(1, 1, 1, PlantAction::Hold, 200)).unwrap();
        p.ingest(cmd(1, 2, 1, PlantAction::Hold, 200)).unwrap();
        assert_eq!(
            p.ingest(cmd(1, 1, 9, PlantAction::Hold, 200)),
            Err(RejectReason::RetiredEpoch)
        );
    }

    #[test]
    fn no_command_no_motion_single_ingress() {
        let mut p = ReferencePlant::new(PlantConfig::default());
        p.run(50);
        assert_eq!(p.snapshot().velocity_mm_s, [0, 0, 0]);
        assert_eq!(p.snapshot().position_mm, [0, 0, 0]);
        assert!(!has(&p, PlantEventKind::Applied));
    }

    #[test]
    fn evidence_is_deterministic() {
        let build = || {
            let mut p = ReferencePlant::new(PlantConfig::default());
            p.ingest(cmd(1, 1, 1, PlantAction::Velocity([1500, -500, 0]), 200))
                .unwrap();
            p.run(30);
            p.events().to_vec()
        };
        assert_eq!(build(), build(), "same schedule => byte-identical evidence");
    }
}
