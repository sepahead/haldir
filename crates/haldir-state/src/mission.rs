//! Mission-lease acceptance (spec §Lease acceptance algorithm, H12).
//!
//! Operates on a lease whose COSE signature and issuer role the gate already
//! verified. Enforces exact scope binding, challenge consumption, term
//! anti-rollback (durably advanced before the lease is exposed active), and a
//! monotonic-anchored deadline.

use crate::anti_rollback::AntiRollbackStore;
use crate::challenge::ChallengeTable;
use haldir_contracts::digest::DigestV1;
use haldir_contracts::ids::{GateBootId, GateId, GateOutputEpoch, VehicleId};
use haldir_contracts::lease::MissionLeaseV1;
use haldir_contracts::receipt::DecisionReasonCodeV1;
use haldir_contracts::scalar::AsciiId;
use haldir_contracts::session::NcpSessionIdentityV1;
use haldir_core::snapshot::{ActiveMissionLeaseSnapshot, AdmittedControllerSnapshot};
use haldir_core::time::MonoInstant;

/// A mission-lease acceptance failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LeaseAcceptError {
    /// Gate id or boot id did not match the current Gate incarnation.
    GateBootMismatch,
    /// Realm/vehicle/session/output-epoch scope mismatch.
    ScopeMismatch,
    /// The policy snapshot digest did not match the loaded policy.
    PolicyMismatch,
    /// The admission bindings did not match the resolved admission.
    AdmissionMismatch,
    /// The referenced challenge was absent, expired, or already used.
    ChallengeInvalid,
    /// The lease term did not strictly advance the anti-rollback high-water.
    TermRollback,
}

impl LeaseAcceptError {
    /// The stable decision reason code.
    #[must_use]
    pub const fn reason_code(self) -> DecisionReasonCodeV1 {
        match self {
            Self::GateBootMismatch => DecisionReasonCodeV1::DenyGateBootMismatch,
            Self::ScopeMismatch => DecisionReasonCodeV1::DenyScopeMismatch,
            Self::PolicyMismatch => DecisionReasonCodeV1::DenyPolicyDiagnostic,
            Self::AdmissionMismatch => DecisionReasonCodeV1::DenyAdmissionMismatch,
            Self::ChallengeInvalid | Self::TermRollback => DecisionReasonCodeV1::DenyLeaseAbsent,
        }
    }
}

/// The current Gate context a lease must bind to.
#[derive(Debug, Clone)]
pub struct LeaseAcceptContext {
    /// Current Gate id.
    pub gate_id: GateId,
    /// Current Gate boot id.
    pub gate_boot_id: GateBootId,
    /// Current realm.
    pub realm: AsciiId<64>,
    /// Current vehicle id.
    pub vehicle_id: VehicleId,
    /// Current session pair.
    pub session: NcpSessionIdentityV1,
    /// Current Gate output epoch.
    pub gate_output_epoch: GateOutputEpoch,
    /// Loaded policy snapshot digest.
    pub policy_snapshot_digest: DigestV1,
    /// The admitted controller resolved by the admission snapshot.
    pub controller: AdmittedControllerSnapshot,
    /// The local cap on active duration (ms).
    pub local_cap_ms: u32,
}

fn term_scope(lease: &MissionLeaseV1) -> Vec<u8> {
    let mut s = Vec::new();
    s.extend_from_slice(b"lease:");
    s.extend_from_slice(lease.issuer_id.as_str().as_bytes());
    s.push(b':');
    s.extend_from_slice(lease.vehicle_id.as_str().as_bytes());
    s
}

/// Accept a verified mission lease into an active snapshot.
///
/// # Errors
/// Returns a [`LeaseAcceptError`] on any scope, admission, challenge, or
/// anti-rollback failure; on error no challenge is consumed and no term is
/// committed unless explicitly noted.
pub fn accept_lease(
    lease: &MissionLeaseV1,
    ctx: &LeaseAcceptContext,
    challenges: &mut ChallengeTable,
    anti_rollback: &mut AntiRollbackStore,
    now: MonoInstant,
) -> Result<ActiveMissionLeaseSnapshot, LeaseAcceptError> {
    // 1. Gate incarnation binding.
    if lease.gate_id != ctx.gate_id || lease.gate_boot_id != ctx.gate_boot_id {
        return Err(LeaseAcceptError::GateBootMismatch);
    }
    // 2. Scope binding.
    if lease.realm != ctx.realm
        || lease.vehicle_id != ctx.vehicle_id
        || lease.ncp_session != ctx.session
        || lease.gate_output_epoch != ctx.gate_output_epoch
    {
        return Err(LeaseAcceptError::ScopeMismatch);
    }
    // 3. Policy binding.
    if lease.policy_snapshot_digest != ctx.policy_snapshot_digest {
        return Err(LeaseAcceptError::PolicyMismatch);
    }
    // 4. Admission binding (exact equality against the resolved admission).
    if lease.controller_id != ctx.controller.controller_id
        || lease.admission_id != ctx.controller.admission_id
        || lease.admission_digest != ctx.controller.admission_digest
        || lease.controller_bundle_digest != ctx.controller.bundle_digest
        || lease.backend_profile_digest != ctx.controller.backend_profile_digest
    {
        return Err(LeaseAcceptError::AdmissionMismatch);
    }
    // 5. Term anti-rollback check (peek before any commit).
    let scope = term_scope(lease);
    if lease.lease_term.get() <= anti_rollback.highest_term(&scope) {
        return Err(LeaseAcceptError::TermRollback);
    }
    // 6. Consume the challenge (only after all non-challenge checks pass).
    if !challenges.consume(&lease.challenge_nonce, now) {
        return Err(LeaseAcceptError::ChallengeInvalid);
    }
    // 7. Durably advance the accepted-term high-water BEFORE exposing active (H12).
    anti_rollback
        .accept_term(&scope, lease.lease_term.get())
        .map_err(|_| LeaseAcceptError::TermRollback)?;
    // 8. Anchor the deadline to local monotonic time.
    let cap_ms = u64::from(lease.max_active_duration_ms.get()).min(u64::from(ctx.local_cap_ms));
    let expires_at = now.checked_add_ms(cap_ms).unwrap_or(now);

    Ok(ActiveMissionLeaseSnapshot {
        lease_id: lease.lease_id,
        lease_term: lease.lease_term.get(),
        controller_id: lease.controller_id.clone(),
        mission_id: lease.mission_id.clone(),
        mission_phase: lease.mission_phase.clone(),
        vehicle_id: lease.vehicle_id.clone(),
        gate_boot_id: lease.gate_boot_id,
        session: lease.ncp_session.clone(),
        gate_output_epoch: lease.gate_output_epoch,
        controller: ctx.controller.clone(),
        controller_intent_key: lease.controller_intent_key.as_str().to_owned(),
        policy_snapshot_digest: lease.policy_snapshot_digest,
        allowed_actions: lease.allowed_actions.as_slice().to_vec(),
        allowed_frames: lease.allowed_frames.as_slice().to_vec(),
        allowed_source_keys: lease
            .allowed_source_keys
            .as_slice()
            .iter()
            .map(|k| k.as_str().to_owned())
            .collect(),
        limits: lease.limits.clone(),
        accepted_at_mono: now,
        expires_at_mono: expires_at,
    })
}
