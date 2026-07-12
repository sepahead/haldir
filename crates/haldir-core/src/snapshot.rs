//! Immutable decision-input snapshots shared by the state, policy, and gate crates.
//!
//! These are internal types, not wire contracts. The controller may name a source
//! position, but never supplies the state *values* used for policy (spec
//! §TrustedStateSnapshotV1).

use crate::time::MonoInstant;
use haldir_contracts::action::{ActionClassV1, CoordinateFrameV1};
use haldir_contracts::cbor::CborWriter;
use haldir_contracts::digest::{DigestDomain, DigestV1};
use haldir_contracts::ids::{
    AdmissionId, ControllerId, GateBootId, GateOutputEpoch, KeyId, MissionId, MissionLeaseId,
    VehicleId,
};
use haldir_contracts::limits::MissionLeaseLimitsV1;
use haldir_contracts::scalar::AsciiId;
use haldir_contracts::session::{NcpSessionIdentityV1, NcpSourceRefV1};

/// Fixed-point kinematic state (integer millimetres / mm-per-second).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KinematicStateFixedV1 {
    /// Position in the local navigation frame, millimetres.
    pub position_mm: [i64; 3],
    /// Velocity in the local navigation frame, mm/s.
    pub velocity_mm_s: [i32; 3],
}

/// Nonnegative uncertainty bounds in matching units.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StateUncertaintyFixedV1 {
    /// Position uncertainty bound, millimetres (per axis, nonnegative).
    pub position_mm: [i64; 3],
    /// Velocity uncertainty bound, mm/s (per axis, nonnegative).
    pub velocity_mm_s: [i32; 3],
}

/// A verified upstream source frame, correlated to Gate's trusted-state cache.
#[derive(Debug, Clone)]
pub struct VerifiedSourceStateV1 {
    /// The source reference (key, epoch, seq).
    pub source: NcpSourceRefV1,
    /// The session the source frame was observed under.
    pub session: NcpSessionIdentityV1,
    /// Source publisher time (diagnostic only).
    pub publisher_t_ns: u64,
    /// Gate receive monotonic time (authoritative freshness basis).
    pub receive_mono: MonoInstant,
    /// Whether the NCP validity result was OK.
    pub valid: bool,
}

/// A trusted-state snapshot: the internal canonical decision input for one vehicle.
#[derive(Debug, Clone)]
pub struct TrustedStateSnapshotV1 {
    /// Vehicle identifier.
    pub vehicle_id: VehicleId,
    /// Current session pair.
    pub session: NcpSessionIdentityV1,
    /// Snapshot capture time.
    pub captured_mono: MonoInstant,
    /// Primary source frame.
    pub primary_source: VerifiedSourceStateV1,
    /// Kinematic state used by policy.
    pub kinematic: KinematicStateFixedV1,
    /// State uncertainty.
    pub uncertainty: StateUncertaintyFixedV1,
    /// Gate-owned mission phase.
    pub mission_phase: AsciiId<64>,
    /// Plant mode.
    pub plant_mode: AsciiId<64>,
}

impl TrustedStateSnapshotV1 {
    /// A reproducible domain-separated digest of the policy-relevant fields
    /// (deterministic: fixed field order, no floats, no hash-map iteration).
    #[must_use]
    pub fn canonical_digest(&self) -> DigestV1 {
        let mut w = CborWriter::new();
        w.array_header(9);
        haldir_contracts::cbor::CanonicalValue::encode(&self.vehicle_id, &mut w);
        haldir_contracts::cbor::CanonicalValue::encode(&self.session, &mut w);
        w.uint(self.captured_mono.as_nanos());
        haldir_contracts::cbor::CanonicalValue::encode(&self.primary_source.source, &mut w);
        w.array_header(3);
        for v in self.kinematic.position_mm {
            w.int(v);
        }
        w.array_header(3);
        for v in self.kinematic.velocity_mm_s {
            w.int(i64::from(v));
        }
        w.array_header(3);
        for v in self.uncertainty.position_mm {
            w.int(v);
        }
        w.array_header(3);
        for v in self.uncertainty.velocity_mm_s {
            w.int(i64::from(v));
        }
        haldir_contracts::cbor::CanonicalValue::encode(&self.mission_phase, &mut w);
        DigestV1::compute(DigestDomain::StateSnapshot, w.as_bytes())
    }
}

/// The admitted controller identity a decision runs against.
#[derive(Debug, Clone)]
pub struct AdmittedControllerSnapshot {
    /// Controller identifier.
    pub controller_id: ControllerId,
    /// Admitted controller bundle digest.
    pub bundle_digest: DigestV1,
    /// Admitted backend profile digest.
    pub backend_profile_digest: DigestV1,
    /// Admission id.
    pub admission_id: AdmissionId,
    /// Admission record digest.
    pub admission_digest: DigestV1,
}

/// An accepted, active mission lease with its monotonic-anchored deadline. The
/// policy uses `limits`, `allowed_*`, `mission_phase`, and `expires_at_mono`.
#[derive(Debug, Clone)]
pub struct ActiveMissionLeaseSnapshot {
    /// Lease id.
    pub lease_id: MissionLeaseId,
    /// Lease term (monotonic anti-rollback value).
    pub lease_term: u64,
    /// Controller identifier.
    pub controller_id: ControllerId,
    /// Mission identifier.
    pub mission_id: MissionId,
    /// Mission phase the lease was issued for.
    pub mission_phase: AsciiId<64>,
    /// Vehicle identifier.
    pub vehicle_id: VehicleId,
    /// The Gate boot the lease binds.
    pub gate_boot_id: GateBootId,
    /// Session pair.
    pub session: NcpSessionIdentityV1,
    /// Gate output epoch.
    pub gate_output_epoch: GateOutputEpoch,
    /// Admitted controller identity.
    pub controller: AdmittedControllerSnapshot,
    /// Concrete controller intent route.
    pub controller_intent_key: String,
    /// The controller intent signing key id the intent must be signed under.
    pub controller_intent_signing_key_id: KeyId,
    /// Policy snapshot digest bound into the lease.
    pub policy_snapshot_digest: DigestV1,
    /// Allowed action classes.
    pub allowed_actions: Vec<ActionClassV1>,
    /// Allowed coordinate frames.
    pub allowed_frames: Vec<CoordinateFrameV1>,
    /// Allowed source keys.
    pub allowed_source_keys: Vec<String>,
    /// Numeric lease limits.
    pub limits: MissionLeaseLimitsV1,
    /// Monotonic acceptance time.
    pub accepted_at_mono: MonoInstant,
    /// Monotonic expiry (min of requested duration and local cap).
    pub expires_at_mono: MonoInstant,
}

impl ActiveMissionLeaseSnapshot {
    /// Whether the action class is permitted by the lease allowlist.
    #[must_use]
    pub fn permits_action(&self, class: ActionClassV1) -> bool {
        self.allowed_actions.contains(&class)
    }

    /// Whether the coordinate frame is permitted.
    #[must_use]
    pub fn permits_frame(&self, frame: CoordinateFrameV1) -> bool {
        self.allowed_frames.contains(&frame)
    }

    /// Whether the source key is permitted.
    #[must_use]
    pub fn permits_source_key(&self, key: &str) -> bool {
        self.allowed_source_keys.iter().any(|k| k == key)
    }

    /// Remaining lease time at `now`, or zero if expired/regressed.
    #[must_use]
    pub fn remaining_ms(&self, now: MonoInstant) -> u64 {
        self.expires_at_mono
            .checked_duration_since(now)
            .map_or(0, |d| d.as_millis())
    }
}
