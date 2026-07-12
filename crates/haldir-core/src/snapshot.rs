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
use haldir_contracts::scalar::{AsciiId, BoundedAscii};
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
    /// Validated coordinate-frame identifier from the source NCP frame.
    pub frame_id: BoundedAscii<128>,
    /// Source publisher time, carried as causal provenance but never used for freshness.
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
        use haldir_contracts::cbor::CanonicalValue;
        let mut w = CborWriter::new();
        // Commit EVERY field any decision or adapter function can read (H-B06);
        // the `digest_coverage` test module below enforces this by asserting that
        // a change to any single field changes the digest.
        w.array_header(15);
        self.vehicle_id.encode(&mut w);
        self.session.encode(&mut w);
        w.uint(self.captured_mono.as_nanos());
        self.primary_source.source.encode(&mut w);
        self.primary_source.session.encode(&mut w);
        self.primary_source.frame_id.encode(&mut w);
        w.uint(self.primary_source.publisher_t_ns);
        w.uint(self.primary_source.receive_mono.as_nanos());
        w.bool(self.primary_source.valid);
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
        self.mission_phase.encode(&mut w);
        self.plant_mode.encode(&mut w);
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
    /// Maximum intent rate (milli-Hz) the lease authorizes (H-B07).
    pub max_intent_rate_millihz: u32,
    /// Maximum total intents the lease authorizes (H-B07).
    pub max_total_intents: u64,
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

#[cfg(test)]
mod digest_coverage {
    //! H-B06: the canonical state digest must commit every policy-relevant field.
    //! We prove it by showing that changing any single field changes the digest —
    //! an uncommitted field would let two policy-distinct states share a digest.
    use super::{
        KinematicStateFixedV1, StateUncertaintyFixedV1, TrustedStateSnapshotV1,
        VerifiedSourceStateV1,
    };
    use crate::time::MonoInstant;
    use core::num::NonZeroU64;
    use haldir_contracts::digest::DigestV1;
    use haldir_contracts::ids::{SourceSeq, VehicleId};
    use haldir_contracts::scalar::{AsciiId, BoundedAscii, CanonicalUuidV4String};
    use haldir_contracts::session::{NcpSessionIdentityV1, NcpSourceRefV1};

    fn uuid(s: u8) -> CanonicalUuidV4String {
        CanonicalUuidV4String::from_random_bytes([s; 16])
    }

    fn base() -> TrustedStateSnapshotV1 {
        TrustedStateSnapshotV1 {
            vehicle_id: VehicleId::new("uav-1").unwrap(),
            session: NcpSessionIdentityV1 {
                session_id: AsciiId::new("sess-1").unwrap(),
                generation: uuid(1),
            },
            captured_mono: MonoInstant::from_nanos(1_000),
            primary_source: VerifiedSourceStateV1 {
                source: NcpSourceRefV1 {
                    source_key: BoundedAscii::new("veh/uav-1/state/pose").unwrap(),
                    stream_epoch: uuid(2),
                    stream_seq: SourceSeq::new(NonZeroU64::new(7).unwrap()),
                },
                session: NcpSessionIdentityV1 {
                    session_id: AsciiId::new("sess-1").unwrap(),
                    generation: uuid(1),
                },
                frame_id: BoundedAscii::new("map").unwrap(),
                publisher_t_ns: 111,
                receive_mono: MonoInstant::from_nanos(1_000),
                valid: true,
            },
            kinematic: KinematicStateFixedV1 {
                position_mm: [0, 0, 0],
                velocity_mm_s: [0, 0, 0],
            },
            uncertainty: StateUncertaintyFixedV1 {
                position_mm: [10, 10, 10],
                velocity_mm_s: [0, 0, 0],
            },
            mission_phase: AsciiId::new("INSPECTION").unwrap(),
            plant_mode: AsciiId::new("NOMINAL").unwrap(),
        }
    }

    fn mutated(f: impl FnOnce(&mut TrustedStateSnapshotV1)) -> DigestV1 {
        let mut s = base();
        f(&mut s);
        s.canonical_digest()
    }

    #[test]
    fn digest_is_deterministic() {
        assert_eq!(base().canonical_digest(), base().canonical_digest());
    }

    #[test]
    fn every_policy_relevant_field_is_committed() {
        let d0 = base().canonical_digest();
        assert_ne!(
            d0,
            mutated(|s| s.vehicle_id = VehicleId::new("uav-2").unwrap())
        );
        assert_ne!(
            d0,
            mutated(|s| s.session.session_id = AsciiId::new("sess-2").unwrap())
        );
        assert_ne!(d0, mutated(|s| s.session.generation = uuid(9)));
        assert_ne!(
            d0,
            mutated(|s| s.captured_mono = MonoInstant::from_nanos(2_000))
        );
        assert_ne!(
            d0,
            mutated(|s| s.primary_source.source.stream_seq =
                SourceSeq::new(NonZeroU64::new(9).unwrap()))
        );
        assert_ne!(
            d0,
            mutated(|s| s.primary_source.source.stream_epoch = uuid(8))
        );
        assert_ne!(
            d0,
            mutated(|s| s.primary_source.source.source_key =
                BoundedAscii::new("veh/uav-1/state/other").unwrap())
        );
        assert_ne!(
            d0,
            mutated(|s| s.primary_source.session.session_id = AsciiId::new("sess-3").unwrap())
        );
        assert_ne!(
            d0,
            mutated(|s| s.primary_source.frame_id = BoundedAscii::new("odom").unwrap())
        );
        assert_ne!(d0, mutated(|s| s.primary_source.publisher_t_ns = 424_242));
        assert_ne!(
            d0,
            mutated(|s| s.primary_source.receive_mono = MonoInstant::from_nanos(9_999))
        );
        assert_ne!(d0, mutated(|s| s.primary_source.valid = false));
        assert_ne!(d0, mutated(|s| s.kinematic.position_mm[1] = 12_345));
        assert_ne!(d0, mutated(|s| s.kinematic.velocity_mm_s[2] = 55));
        assert_ne!(d0, mutated(|s| s.uncertainty.position_mm[0] = 999));
        assert_ne!(d0, mutated(|s| s.uncertainty.velocity_mm_s[0] = 7));
        assert_ne!(
            d0,
            mutated(|s| s.mission_phase = AsciiId::new("TRANSIT").unwrap())
        );
        assert_ne!(
            d0,
            mutated(|s| s.plant_mode = AsciiId::new("DEGRADED").unwrap())
        );
    }
}
