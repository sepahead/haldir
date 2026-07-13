//! Mission-lease acceptance (spec §Lease acceptance algorithm, H12).
//!
//! Operates on a lease whose COSE signature and issuer role the gate already
//! verified. Enforces exact scope binding, challenge consumption, term
//! anti-rollback (durably advanced before the lease is exposed active), and a
//! monotonic-anchored deadline.

use crate::anti_rollback::AntiRollbackStore;
use crate::challenge::ChallengeTable;
use haldir_contracts::cbor::{CanonicalValue, CborWriter};
use haldir_contracts::digest::DigestV1;
use haldir_contracts::ids::{GateBootId, GateId, GateOutputEpoch, VehicleId};
use haldir_contracts::lease::MissionLeaseV1;
use haldir_contracts::receipt::DecisionReasonCodeV1;
use haldir_contracts::scalar::AsciiId;
use haldir_contracts::session::NcpSessionIdentityV1;
use haldir_core::snapshot::{ActiveMissionLeaseSnapshot, AdmittedControllerSnapshot};
use haldir_core::time::MonoInstant;

const LEASE_TERM_SCOPE_DOMAIN: &[u8] = b"haldir.state.lease-term-scope.v1\0";

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
    /// The term store could not durably commit an otherwise valid lease.
    TermStoreUnavailable,
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
            Self::TermStoreUnavailable => DecisionReasonCodeV1::ErrorInternalFault,
        }
    }
}

/// A lease-term high-water commit failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseTermStoreError {
    /// The term did not strictly advance.
    Rollback,
    /// The durable store or external anchor was unavailable.
    Unavailable,
}

/// Minimal anti-rollback interface required by mission-lease acceptance.
pub trait LeaseTermStore: Send {
    /// Highest committed term for `scope`.
    fn highest_term(&self, scope: &[u8]) -> u64;

    /// Commit a strictly advancing term before authority becomes active.
    fn commit_term(&mut self, scope: &[u8], term: u64) -> Result<(), LeaseTermStoreError>;
}

impl LeaseTermStore for AntiRollbackStore {
    fn highest_term(&self, scope: &[u8]) -> u64 {
        Self::highest_term(self, scope)
    }

    fn commit_term(&mut self, scope: &[u8], term: u64) -> Result<(), LeaseTermStoreError> {
        self.accept_term(scope, term)
            .map_err(|_| LeaseTermStoreError::Rollback)
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

/// Build the persistent lease-term namespace for a logical issuer and vehicle.
///
/// The versioned domain is followed by a canonical CBOR array. CBOR's canonical
/// text lengths make the two fields unambiguous even though `AsciiId` permits
/// `:`. The issuer signing-key id is deliberately absent so key rotation cannot
/// reset the high-water. Realm, Gate incarnation, and NCP session/output epochs
/// are also absent: they are acceptance bindings, not rollback namespaces. A
/// different logical issuer id does select a different namespace; this state
/// layer does not authorize or transfer issuer identity. A
/// durable store is separately bound to one provisioned Gate ID; moving a
/// vehicle to another store does not transfer high-water state automatically.
pub(crate) fn canonical_term_scope(issuer_id: &AsciiId<64>, vehicle_id: &VehicleId) -> Vec<u8> {
    let mut encoded = CborWriter::new();
    encoded.array_header(2);
    issuer_id.encode(&mut encoded);
    vehicle_id.encode(&mut encoded);

    let mut scope = Vec::with_capacity(LEASE_TERM_SCOPE_DOMAIN.len() + encoded.as_bytes().len());
    scope.extend_from_slice(LEASE_TERM_SCOPE_DOMAIN);
    scope.extend_from_slice(encoded.as_bytes());
    scope
}

fn legacy_term_scope(lease: &MissionLeaseV1) -> Vec<u8> {
    let mut scope = Vec::new();
    scope.extend_from_slice(b"lease:");
    scope.extend_from_slice(lease.issuer_id.as_str().as_bytes());
    scope.push(b':');
    scope.extend_from_slice(lease.vehicle_id.as_str().as_bytes());
    scope
}

/// Accept a verified mission lease into an active snapshot.
///
/// # Errors
/// Returns a [`LeaseAcceptError`] on any scope, admission, challenge, or
/// anti-rollback failure. A durable commit failure consumes no challenge and does
/// not update the live term; recovery may conservatively complete a candidate that
/// reached snapshot storage before its external-anchor update failed. If challenge
/// consumption unexpectedly fails after a successful commit, the term remains
/// conservatively spent and no lease becomes active.
pub fn accept_lease(
    lease: &MissionLeaseV1,
    ctx: &LeaseAcceptContext,
    challenges: &mut ChallengeTable,
    anti_rollback: &mut dyn LeaseTermStore,
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
    let scope = canonical_term_scope(&lease.issuer_id, &lease.vehicle_id);
    // Compatibility read: older snapshots keyed terms with an ambiguous
    // colon-delimited encoding. Taking the maximum prevents an upgrade from
    // resetting a pre-existing high-water. New commits use only the canonical
    // namespace, so formerly colliding logical scopes diverge safely after the
    // shared legacy floor.
    let legacy_scope = legacy_term_scope(lease);
    let highest_term = anti_rollback
        .highest_term(&scope)
        .max(anti_rollback.highest_term(&legacy_scope));
    if lease.lease_term.get() <= highest_term {
        return Err(LeaseAcceptError::TermRollback);
    }
    // 6. Verify the challenge without consuming it. The per-vehicle actor lock
    //    prevents a concurrent consume between this check and step 8.
    if !challenges.is_pending(&lease.challenge_nonce, now) {
        return Err(LeaseAcceptError::ChallengeInvalid);
    }
    // 7. Commit the accepted-term high-water BEFORE consuming the one-shot
    //    challenge or exposing the lease. A failure leaves the challenge usable;
    //    a crash after a successful commit conservatively spends the term.
    anti_rollback
        .commit_term(&scope, lease.lease_term.get())
        .map_err(|error| match error {
            LeaseTermStoreError::Rollback => LeaseAcceptError::TermRollback,
            LeaseTermStoreError::Unavailable => LeaseAcceptError::TermStoreUnavailable,
        })?;
    // 8. Consume the challenge after durable commit. Unexpected failure is safe:
    //    the term remains spent but no lease becomes active.
    if !challenges.consume(&lease.challenge_nonce, now) {
        return Err(LeaseAcceptError::ChallengeInvalid);
    }
    // 9. Anchor the deadline to local monotonic time.
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
        controller_intent_signing_key_id: lease.controller_intent_signing_key_id.clone(),
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
        max_intent_rate_millihz: lease.max_intent_rate_millihz.get(),
        max_total_intents: lease.max_total_intents.get(),
        accepted_at_mono: now,
        expires_at_mono: expires_at,
    })
}
