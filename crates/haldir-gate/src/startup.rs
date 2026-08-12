//! Durable Gate startup orchestration.
//!
//! Startup validates the static actor configuration and deployment profile,
//! obtains the runtime identifiers' entropy (plus the initial live challenge
//! nonce when live support is compiled), acquires a retained instance lock,
//! explicitly provisions or opens durable state, and commits a new boot before
//! constructing [`VehicleActor`].

use core::num::{NonZeroU32, NonZeroU64, NonZeroUsize};
#[cfg(not(unix))]
use std::fs::OpenOptions;
use std::fs::{self, File, TryLockError};
use std::path::{Path, PathBuf};

#[cfg(unix)]
use rustix::fs::{Mode, OFlags, open};
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, MetadataExt};

use haldir_admission::AdmissionSnapshot;
use haldir_contracts::deployment::{DeploymentPayloadDigestV1, DeploymentRevision};
#[cfg(feature = "live-zenoh")]
use haldir_contracts::digest::DigestDomain;
use haldir_contracts::digest::DigestV1;
#[cfg(feature = "live-zenoh")]
use haldir_contracts::ids::ChallengeNonce;
use haldir_contracts::ids::{GateBootId, GateId, GateOutputEpoch, JournalId, KeyId, VehicleId};
use haldir_contracts::scalar::{AsciiId, CanonicalUuidV4String};
use haldir_contracts::session::NcpSessionIdentityV1;
use haldir_contracts::status::PlantPublicationAuthorityStateV1;
use haldir_crypto::{RevocationSnapshot, SigningKey, TrustStore, TrustStoreDisjointnessError};
use haldir_deployment::AuthorityValidatedDeploymentPackage;
use haldir_deployment::contract::{
    DeploymentClassV1, DeploymentNcpWireProfileV1, DeploymentRuntimeProfileV1,
};
use haldir_durable::{
    AnchorProtection, AtomicFileSnapshot, CommitReceipt, GenerationAnchor,
    LocalFileGenerationAnchor, RecoveryStatus, SnapshotBinding, SnapshotStorage, StorageMacKey,
    StoreId,
};
use haldir_evidence::gate_journal::{
    GateJournalOpenError, RecoveredGateJournal, RecoveredPublicationState,
};
use haldir_evidence::journal::SegmentIdentity;
use haldir_evidence::manager::{
    JournalLimits, JournalOpenOptions, JournalRecoveryReport, JournalSigner, RecoveryCaptureLimits,
};
use haldir_ncp08::{NcpCommandWireProfile, SelectedNcpCommandAdapter};
use haldir_policy_native::NativePolicySnapshot;
use haldir_state::{DurableAntiRollbackError, DurableAntiRollbackStore};
#[cfg(feature = "live-zenoh")]
use haldir_transport_zenoh::HaldirKeys;

use crate::actor::{
    GateConfig, GateConfigError, GateSignerValidation, GateStartupError, PolicyBindingValidation,
    VehicleActor, validate_static_config,
};

#[path = "publication_coordinator.rs"]
#[allow(
    dead_code,
    reason = "internal lifecycle typestates are reached only through feature-gated service and test facades"
)]
pub(crate) mod publication_coordinator;

#[cfg(feature = "live-zenoh")]
#[path = "live_service.rs"]
mod live_service;

#[cfg(feature = "live-zenoh")]
pub use live_service::{
    DeclaredLiveGateKernel, DeclaredLiveGateZenohService, IssuedLiveGateChallenge,
    LIVE_ACTIVATION_CHALLENGE_TTL_MS, LiveDecisionUnavailable, LiveIntentActivationError,
    LiveIntentActivationInput, LiveIntentActivationInputError, LiveIntentRouteBoundGate,
    LiveKernelStartError, LivePublisherError, LiveServiceBindError, LiveServiceFatal,
    LiveServiceOutcome, LiveServiceStop, LiveZenohActivityTransition, LiveZenohServiceBindError,
    LiveZenohServiceBindFailure, LiveZenohServiceStop, LiveZenohServiceTransition,
    LiveZenohShutdownError, LiveZenohShutdownHandle, LiveZenohShutdownReport,
    LiveZenohStateUpdateTransition, MAX_LIVE_LEASE_ENVELOPE_BYTES,
};

#[cfg(all(test, feature = "live-zenoh"))]
pub(crate) use live_service::{
    DeclaredLiveGateService, LiveServiceTransition, TestDeclaredLiveGateService,
    TestDeclaredLiveGateZenohService, TestLiveServiceTransition, TestLiveStateUpdateTransition,
    TestLiveZenohServiceTransition, finish_zenoh_shutdown, unavailable_is_owned_io_invariant,
};

const BOOT_ENTROPY_BYTES: usize = 32;
const OUTPUT_EPOCH_ENTROPY_BYTES: usize = 16;
#[cfg(feature = "live-zenoh")]
const ACTIVATION_CHALLENGE_ENTROPY_BYTES: usize = 32;
#[cfg(not(feature = "live-zenoh"))]
const ENTROPY_BYTES: usize = BOOT_ENTROPY_BYTES + OUTPUT_EPOCH_ENTROPY_BYTES;
#[cfg(feature = "live-zenoh")]
const ENTROPY_BYTES: usize =
    BOOT_ENTROPY_BYTES + OUTPUT_EPOCH_ENTROPY_BYTES + ACTIVATION_CHALLENGE_ENTROPY_BYTES;
const LOCAL_SNAPSHOT_OVERHEAD_ALLOWANCE: usize = 1024;
const LOCAL_SNAPSHOT_FILE: &str = "anti-rollback.snapshot";
const LOCAL_ANCHOR_FILE: &str = "generation.anchor";
const LOCAL_LOCK_FILE: &str = ".haldir-gate.lock";

/// Caller-declared runtime integration profile for one Gate startup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateRuntimeProfile {
    /// Deterministic in-process reference integration.
    InProcessReference,
    /// Live Zenoh integration declared by the caller.
    ///
    /// Startup retains this declaration for observability. It does not by
    /// itself prove that a live session, service, or publisher was established.
    DeclaredLiveZenoh,
}

/// Static Gate configuration. Runtime boot and output identifiers are supplied
/// only after durable startup has passed its commit boundary.
pub struct GateConfigTemplate {
    /// Gate id.
    pub gate_id: GateId,
    /// Realm.
    pub realm: AsciiId<64>,
    /// Vehicle id.
    pub vehicle_id: VehicleId,
    /// Application-signature trust store.
    pub trust: TrustStore,
    /// Revocation snapshot.
    pub revocations: RevocationSnapshot,
    /// Admission snapshot.
    pub admission: AdmissionSnapshot,
    /// Native policy snapshot.
    pub policy: NativePolicySnapshot,
    /// Expected canonical digest of the executable native policy snapshot.
    pub policy_snapshot_digest: DigestV1,
    /// Current NCP session.
    pub session: NcpSessionIdentityV1,
    /// Caller-declared runtime integration profile.
    pub runtime_profile: GateRuntimeProfile,
    /// Closed selection of modeled or exact pinned NCP command construction.
    pub ncp_adapter: SelectedNcpCommandAdapter,
    /// Current ACL-only plant-publication authority evidence.
    pub publication: PlantPublicationAuthorityStateV1,
    /// Local cap on lease active duration (ms).
    pub local_cap_ms: NonZeroU32,
    /// Gate application signing key.
    pub gate_signer: SigningKey,
    /// Gate application signing key id.
    pub gate_signer_kid: KeyId,
}

impl GateConfigTemplate {
    /// Validate every static invariant without opening or changing durable state.
    ///
    /// # Errors
    /// Returns when signer/cap/policy validation fails, the configured policy
    /// digest does not identify its executable parameters, publication authority
    /// is not the current `PRE_AUTHORITY_ACL_ONLY` profile, the declared runtime
    /// profile requires a different NCP wire profile, or required live support
    /// was not compiled.
    pub fn validate(&self) -> Result<(), DurableGateStartupError> {
        validate_static_config(
            PolicyBindingValidation {
                policy: &self.policy,
                expected_digest: &self.policy_snapshot_digest,
                local_cap_ms: self.local_cap_ms,
            },
            GateSignerValidation {
                gate_id: &self.gate_id,
                trust: &self.trust,
                revocations: &self.revocations,
                signing_key: &self.gate_signer,
                signing_kid: &self.gate_signer_kid,
            },
        )
        .map_err(DurableGateStartupError::Config)?;
        if !matches!(
            self.publication,
            PlantPublicationAuthorityStateV1::AclExclusiveV1(_)
        ) {
            return Err(DurableGateStartupError::UnsupportedPublicationProfile);
        }
        self.validate_runtime_profile()
    }

    fn validate_runtime_profile(&self) -> Result<(), DurableGateStartupError> {
        match self.runtime_profile {
            GateRuntimeProfile::InProcessReference => Ok(()),
            GateRuntimeProfile::DeclaredLiveZenoh => {
                let required = NcpCommandWireProfile::ExactNcpV0_8Json;
                let actual = self.ncp_adapter.wire_profile();
                if actual != required {
                    return Err(DurableGateStartupError::NcpWireProfileMismatch {
                        runtime_profile: self.runtime_profile,
                        required,
                        actual,
                    });
                }

                #[cfg(feature = "live-zenoh")]
                {
                    let keys =
                        HaldirKeys::try_new(self.realm.as_str(), self.session.session_id.as_str())
                            .map_err(|_| DurableGateStartupError::PublicationRouteBinding)?;
                    let evidence = match &self.publication {
                        PlantPublicationAuthorityStateV1::AclExclusiveV1(evidence) => evidence,
                        _ => return Err(DurableGateStartupError::UnsupportedPublicationProfile),
                    };
                    let expected = DigestV1::compute(
                        DigestDomain::TransportKey,
                        keys.final_command().as_bytes(),
                    );
                    if evidence.final_route_digest != expected {
                        return Err(DurableGateStartupError::PublicationRouteBinding);
                    }
                    Ok(())
                }
                #[cfg(not(feature = "live-zenoh"))]
                {
                    Err(DurableGateStartupError::LiveZenohSupportNotCompiled)
                }
            }
        }
    }

    fn into_runtime(self, boot_id: GateBootId, output_epoch: GateOutputEpoch) -> GateConfig {
        GateConfig {
            gate_id: self.gate_id,
            gate_boot_id: boot_id,
            realm: self.realm,
            vehicle_id: self.vehicle_id,
            trust: self.trust,
            revocations: self.revocations,
            admission: self.admission,
            policy: self.policy,
            policy_snapshot_digest: self.policy_snapshot_digest,
            session: self.session,
            ncp_adapter: self.ncp_adapter,
            publication: self.publication,
            output_epoch,
            local_cap_ms: self.local_cap_ms,
            gate_signer: self.gate_signer,
            gate_signer_kid: self.gate_signer_kid,
        }
    }
}

/// Whether startup must provision empty backends or open existing state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateOpenMode {
    /// Require both backends to be empty and explicitly create generation one.
    ProvisionNew,
    /// Require existing authenticated state; missing state fails closed.
    OpenExisting,
}

/// Required generation-anchor assurance class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartupProfile {
    /// Development startup with a locally durable, rewritable anchor.
    DevelopmentLocal,
    /// Package-bound assurance startup with a supplied anchor that declares
    /// external non-rewindable protection. This profile check does not attest
    /// the implementation or its administrative failure domain.
    AssuranceExternal,
}

impl StartupProfile {
    const fn accepts(self, protection: AnchorProtection) -> bool {
        matches!(
            (self, protection),
            (Self::DevelopmentLocal, AnchorProtection::LocalRewritable)
                | (
                    Self::AssuranceExternal,
                    AnchorProtection::ExternalNonRewindable
                )
        )
    }
}

/// Generic durable startup settings.
pub struct StartupStateConfig {
    /// Explicit state-open mode.
    pub open_mode: StateOpenMode,
    /// Required anchor protection profile.
    pub profile: StartupProfile,
    /// Path of the process-instance lock retained by [`RunningGate`].
    pub instance_lock_path: PathBuf,
    /// Authenticated store/Gate binding.
    pub binding: SnapshotBinding,
    /// Maximum semantic durable payload bytes.
    pub max_payload_bytes: usize,
}

/// Development local-file startup settings.
pub struct LocalStartupConfig {
    /// Dedicated directory containing the fixed snapshot, anchor, and lock names.
    pub state_directory: PathBuf,
    /// Logical durable-store identifier.
    pub store_id: StoreId,
    /// Explicit state-open mode.
    pub open_mode: StateOpenMode,
    /// Required startup profile. Local files satisfy only [`StartupProfile::DevelopmentLocal`].
    pub profile: StartupProfile,
    /// Maximum semantic durable payload bytes.
    pub max_payload_bytes: usize,
}

/// Entropy provider used before any durable backend is opened or provisioned.
pub trait EntropySource {
    /// Fill `destination` completely with cryptographic entropy.
    ///
    /// # Errors
    /// Returns when no trustworthy entropy is available. Implementations must
    /// not report success after a short fill.
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropyError>;
}

/// Opaque entropy failure; no backend-specific detail or partial bytes escape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntropyError;

/// Operating-system cryptographic entropy source.
#[derive(Debug, Default, Clone, Copy)]
pub struct OsEntropy;

impl EntropySource for OsEntropy {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
        getrandom::getrandom(destination).map_err(|_| EntropyError)
    }
}

/// Observable result of a successful durable startup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StartupReport {
    /// Caller-declared runtime integration profile retained for observability.
    pub runtime_profile: GateRuntimeProfile,
    /// Whether generation one was explicitly provisioned by this call.
    pub provisioned: bool,
    /// Existing-state reconciliation result, absent only for provisioning.
    pub recovery: Option<RecoveryStatus>,
    /// Receipt for the freshly committed boot generation.
    pub boot_commit: CommitReceipt,
    /// Protection class declared by the selected generation anchor.
    pub anchor_protection: AnchorProtection,
    /// Startup assurance profile enforced before backend access.
    pub startup_profile: StartupProfile,
    /// Signed package revision atomically committed with this boot, when bound.
    pub deployment_revision: Option<DeploymentRevision>,
    /// Exact verified canonical package-payload digest committed with this boot.
    pub deployment_payload_digest: Option<DeploymentPayloadDigestV1>,
    /// Fresh committed Gate boot identifier.
    pub gate_boot_id: GateBootId,
    /// Fresh process-local output stream epoch.
    pub output_epoch: GateOutputEpoch,
}

/// A started actor paired with the exclusive instance lock protecting its
/// durable backends. Dropping this value releases the lock.
pub struct RunningGate {
    actor: VehicleActor,
    report: StartupReport,
    deployment_package: Option<AuthorityValidatedDeploymentPackage>,
    #[cfg(feature = "live-zenoh")]
    declared_live_zenoh: Option<ValidatedDeclaredLiveZenohStartup>,
    _instance_lock: InstanceLock,
}

/// Exclusive process-instance lock with deterministic release on ownership
/// teardown. Closing the file is an OS-level fallback; the explicit unlock
/// avoids relying on drop timing when a replacement Gate starts immediately.
struct InstanceLock(File);

impl Drop for InstanceLock {
    fn drop(&mut self) {
        let _unlock_result = self.0.unlock();
    }
}

/// Non-cloneable process-local proof that this exact [`RunningGate`] descended
/// from a successfully validated declared-live startup. The public report is
/// observability data; concrete coordinator authority consumes this private value.
#[cfg(feature = "live-zenoh")]
pub(super) struct ValidatedDeclaredLiveZenohStartup {
    activation_challenge_nonce: ChallengeNonce,
}

#[cfg(feature = "live-zenoh")]
impl ValidatedDeclaredLiveZenohStartup {
    pub(super) const fn activation_challenge_nonce(&self) -> ChallengeNonce {
        self.activation_challenge_nonce
    }
}

/// A durable-started Gate fused with the exact journal manager and publication
/// replay produced during the same bounded open operation.
///
/// Restart Unknown emission is completed before construction. Public mutable actor
/// and journal access remains withheld; only the private child lifecycle mechanism
/// can consume both together.
pub struct JournalBoundRunningGate {
    journal: RecoveredGateJournal,
    gate: RunningGate,
    recovery_unknown_events: usize,
}

/// Explicit logical journal identity plus non-authority bounds and paths for one
/// Gate publication-journal startup. Gate ID, boot ID, signer, trust, and
/// revocations are always derived from the consuming [`RunningGate`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicationJournalStartupConfig {
    directory: PathBuf,
    journal_id: JournalId,
    created_mono_ns: u64,
    limits: JournalLimits,
    capture_limits: RecoveryCaptureLimits,
    max_envelope_bytes: NonZeroUsize,
    max_traces: NonZeroUsize,
}

/// Invalid publication-journal startup bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PublicationJournalConfigError {
    /// The reducer cannot retain every record admitted by recovery capture.
    TraceCapacityTooSmall,
}

impl PublicationJournalConfigError {
    /// Stable machine-readable failure class.
    #[must_use]
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::TraceCapacityTooSmall => "PUBLICATION_JOURNAL_TRACE_CAPACITY_TOO_SMALL",
        }
    }
}

impl std::fmt::Display for PublicationJournalConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for PublicationJournalConfigError {}

impl PublicationJournalStartupConfig {
    /// Construct the logical journal selection, path, and bounded replay profile.
    ///
    /// # Errors
    /// Returns when the reducer bound is smaller than the capture record bound.
    pub fn new(
        directory: impl Into<PathBuf>,
        journal_id: JournalId,
        created_mono_ns: u64,
        limits: JournalLimits,
        capture_limits: RecoveryCaptureLimits,
        max_envelope_bytes: NonZeroUsize,
        max_traces: NonZeroUsize,
    ) -> Result<Self, PublicationJournalConfigError> {
        let max_traces_u64 = u64::try_from(max_traces.get()).unwrap_or(u64::MAX);
        if max_traces_u64 < capture_limits.max_records() {
            return Err(PublicationJournalConfigError::TraceCapacityTooSmall);
        }
        Ok(Self {
            directory: directory.into(),
            journal_id,
            created_mono_ns,
            limits,
            capture_limits,
            max_envelope_bytes,
            max_traces,
        })
    }
}

/// Gate/journal construction or committed-current-boot binding failure.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum JournalBindingError {
    /// Fused directory open, bounded capture, or semantic replay failed.
    Journal(GateJournalOpenError),
    /// Logical bounds left no usable current active segment.
    NoActiveSegment,
    /// The current segment belongs to another Gate.
    GateMismatch,
    /// The configured or recovered journal differs from the signed deployment.
    JournalIdMismatch,
    /// The current segment does not name this actual committed Gate boot.
    BootMismatch,
    /// The current segment does not use the actor's validated signer identity.
    SignerMismatch,
    /// This fresh committed boot already appeared in recovered history.
    CurrentBootAlreadyRecovered,
    /// The current segment does not immediately follow the recovered tail.
    SequenceMismatch,
    /// A restarted durable Gate attempted to fork a fresh journal directory.
    JournalProvisionRequiresFreshGateState,
    /// A freshly provisioned durable Gate attempted to adopt existing history.
    JournalOpenRequiresExistingGateState,
}

impl JournalBindingError {
    /// Stable machine-readable failure class.
    #[must_use]
    pub const fn reason_code(&self) -> &'static str {
        match self {
            Self::Journal(_) => "GATE_JOURNAL_BINDING_JOURNAL",
            Self::NoActiveSegment => "GATE_JOURNAL_BINDING_NO_ACTIVE_SEGMENT",
            Self::GateMismatch => "GATE_JOURNAL_BINDING_GATE_MISMATCH",
            Self::JournalIdMismatch => "GATE_JOURNAL_BINDING_JOURNAL_ID_MISMATCH",
            Self::BootMismatch => "GATE_JOURNAL_BINDING_BOOT_MISMATCH",
            Self::SignerMismatch => "GATE_JOURNAL_BINDING_SIGNER_MISMATCH",
            Self::CurrentBootAlreadyRecovered => {
                "GATE_JOURNAL_BINDING_CURRENT_BOOT_ALREADY_RECOVERED"
            }
            Self::SequenceMismatch => "GATE_JOURNAL_BINDING_SEQUENCE_MISMATCH",
            Self::JournalProvisionRequiresFreshGateState => {
                "GATE_JOURNAL_BINDING_PROVISION_REQUIRES_FRESH_GATE_STATE"
            }
            Self::JournalOpenRequiresExistingGateState => {
                "GATE_JOURNAL_BINDING_OPEN_REQUIRES_EXISTING_GATE_STATE"
            }
        }
    }
}

impl std::fmt::Display for JournalBindingError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for JournalBindingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Journal(error) => Some(error),
            _ => None,
        }
    }
}

impl From<GateJournalOpenError> for JournalBindingError {
    fn from(error: GateJournalOpenError) -> Self {
        Self::Journal(error)
    }
}

impl RunningGate {
    /// Construct an already-activated journal fixture. Under `live-zenoh`, a
    /// declared/exact fixture deliberately mints the private startup capability;
    /// this bypass exists only in test builds and is not a production constructor.
    #[cfg(test)]
    pub(crate) fn bind_publication_journal_for_test(
        actor: VehicleActor,
        journal: RecoveredGateJournal,
        recovery_unknown_events: usize,
        output_epoch: GateOutputEpoch,
        runtime_profile: GateRuntimeProfile,
        instance_lock: File,
    ) -> Result<JournalBoundRunningGate, JournalBindingError> {
        let gate_boot_id = actor.gate_boot_id();
        #[cfg(feature = "live-zenoh")]
        let declared_live_zenoh = match runtime_profile {
            GateRuntimeProfile::InProcessReference => None,
            GateRuntimeProfile::DeclaredLiveZenoh
                if actor.ncp_command_wire_profile() == NcpCommandWireProfile::ExactNcpV0_8Json =>
            {
                Some(ValidatedDeclaredLiveZenohStartup {
                    activation_challenge_nonce: ChallengeNonce::new([7; 32]),
                })
            }
            GateRuntimeProfile::DeclaredLiveZenoh => None,
        };
        Self {
            actor,
            report: StartupReport {
                runtime_profile,
                provisioned: true,
                recovery: None,
                boot_commit: CommitReceipt {
                    generation: 1,
                    snapshot_digest: [0; 32],
                },
                anchor_protection: AnchorProtection::EphemeralTest,
                startup_profile: StartupProfile::DevelopmentLocal,
                deployment_revision: None,
                deployment_payload_digest: None,
                gate_boot_id,
                output_epoch,
            },
            deployment_package: None,
            #[cfg(feature = "live-zenoh")]
            declared_live_zenoh,
            _instance_lock: InstanceLock(instance_lock),
        }
        .bind_publication_journal_with_recovery_count(journal, recovery_unknown_events)
    }

    /// Started vehicle actor.
    #[must_use]
    pub const fn actor(&self) -> &VehicleActor {
        &self.actor
    }

    /// Durable startup report.
    #[must_use]
    pub const fn report(&self) -> StartupReport {
        self.report
    }

    /// Signed, exact-role-resolved, NCP- and Gate-configuration-validated
    /// package retained by a deployment-bound startup, if this is that stronger
    /// startup class.
    #[must_use]
    pub const fn deployment_package(&self) -> Option<&AuthorityValidatedDeploymentPackage> {
        self.deployment_package.as_ref()
    }

    /// Provision and bind a fresh selected Gate publication journal using this
    /// runtime's committed boot and sole validated application signer.
    ///
    /// # Errors
    /// Returns on journal provisioning/replay failure or any mismatch with the
    /// non-forgeable running Gate state.
    pub fn provision_publication_journal(
        self,
        config: PublicationJournalStartupConfig,
    ) -> Result<JournalBoundRunningGate, JournalBindingError> {
        if !self.report.provisioned {
            return Err(JournalBindingError::JournalProvisionRequiresFreshGateState);
        }
        self.validate_journal_id(config.journal_id)?;
        let PublicationJournalStartupConfig {
            directory,
            journal_id,
            created_mono_ns,
            limits,
            capture_limits,
            max_envelope_bytes,
            max_traces,
        } = config;
        let options = JournalOpenOptions::new(
            self.actor.gate_id().clone(),
            journal_id,
            self.actor.gate_boot_id(),
            created_mono_ns,
            limits,
        );
        let journal = {
            let signer = self.actor.journal_signer();
            let verifier = self.actor.journal_verifier(max_envelope_bytes);
            RecoveredGateJournal::provision_new(
                directory,
                options,
                &signer,
                capture_limits,
                verifier,
                max_traces,
            )?
        };
        self.bind_publication_journal(journal)
    }

    /// Recover and bind an existing selected Gate publication journal using
    /// this runtime's committed boot and sole validated application signer.
    ///
    /// When `recovered_tail_signer` is absent, the current Gate signer is tried
    /// for the prior open tail. Key rotation may instead supply the exact old
    /// signer as a short-lived borrow.
    ///
    /// # Errors
    /// Returns on journal recovery/replay failure or any mismatch with the
    /// non-forgeable running Gate state.
    pub fn open_publication_journal(
        self,
        config: PublicationJournalStartupConfig,
        recovered_tail_signer: Option<&JournalSigner<'_>>,
    ) -> Result<JournalBoundRunningGate, JournalBindingError> {
        if self.report.provisioned {
            return Err(JournalBindingError::JournalOpenRequiresExistingGateState);
        }
        self.validate_journal_id(config.journal_id)?;
        let PublicationJournalStartupConfig {
            directory,
            journal_id,
            created_mono_ns,
            limits,
            capture_limits,
            max_envelope_bytes,
            max_traces,
        } = config;
        let options = JournalOpenOptions::new(
            self.actor.gate_id().clone(),
            journal_id,
            self.actor.gate_boot_id(),
            created_mono_ns,
            limits,
        );
        let (journal, recovery_unknown_events) = {
            let signer = self.actor.journal_signer();
            let tail_signer = recovered_tail_signer.or(Some(&signer));
            let verifier = self.actor.journal_verifier(max_envelope_bytes);
            RecoveredGateJournal::open_existing_with_recovery_unknowns(
                directory,
                options,
                &signer,
                tail_signer,
                capture_limits,
                verifier,
                max_traces,
            )?
        };
        self.bind_publication_journal_with_recovery_count(journal, recovery_unknown_events)
    }

    fn bind_publication_journal(
        self,
        journal: RecoveredGateJournal,
    ) -> Result<JournalBoundRunningGate, JournalBindingError> {
        self.bind_publication_journal_with_recovery_count(journal, 0)
    }

    fn bind_publication_journal_with_recovery_count(
        self,
        journal: RecoveredGateJournal,
        recovery_unknown_events: usize,
    ) -> Result<JournalBoundRunningGate, JournalBindingError> {
        let active = journal
            .active_identity()
            .ok_or(JournalBindingError::NoActiveSegment)?;
        if active.gate_id != *self.actor.gate_id() {
            return Err(JournalBindingError::GateMismatch);
        }
        self.validate_journal_id(active.journal_id)?;
        if active.gate_boot_id != self.actor.gate_boot_id() {
            return Err(JournalBindingError::BootMismatch);
        }
        if active.signer_kid != *self.actor.gate_signer_kid()
            || active.signer_public_key != self.actor.gate_signer_public_key()
        {
            return Err(JournalBindingError::SignerMismatch);
        }
        if journal
            .publication()
            .contains_recovered_boot(self.actor.gate_boot_id())
        {
            return Err(JournalBindingError::CurrentBootAlreadyRecovered);
        }
        let expected_sequence = match journal.publication().last_recovered_segment_sequence() {
            Some(previous) => previous
                .get()
                .checked_add(1)
                .and_then(NonZeroU64::new)
                .ok_or(JournalBindingError::SequenceMismatch)?,
            None => NonZeroU64::new(1).ok_or(JournalBindingError::SequenceMismatch)?,
        };
        let maximum_startup_rotations = recovery_unknown_events.saturating_sub(1);
        let maximum_sequence = expected_sequence
            .get()
            .checked_add(u64::try_from(maximum_startup_rotations).unwrap_or(u64::MAX))
            .ok_or(JournalBindingError::SequenceMismatch)?;
        if active.segment_sequence.get() < expected_sequence.get()
            || active.segment_sequence.get() > maximum_sequence
        {
            return Err(JournalBindingError::SequenceMismatch);
        }
        Ok(JournalBoundRunningGate {
            journal,
            gate: self,
            recovery_unknown_events,
        })
    }

    fn validate_journal_id(&self, selected: JournalId) -> Result<(), JournalBindingError> {
        if self
            .deployment_package
            .as_ref()
            .is_some_and(|package| package.resolved().verified().package().journal_id != selected)
        {
            return Err(JournalBindingError::JournalIdMismatch);
        }
        Ok(())
    }
}

impl JournalBoundRunningGate {
    /// Durable startup report. This remains observability data, not authority.
    #[must_use]
    pub const fn report(&self) -> StartupReport {
        self.gate.report
    }

    /// Deployment package retained through journal binding, when startup was
    /// package-bound.
    #[must_use]
    pub const fn deployment_package(&self) -> Option<&AuthorityValidatedDeploymentPackage> {
        self.gate.deployment_package.as_ref()
    }

    /// Read-only started actor retained behind the journal binding.
    #[must_use]
    pub const fn actor(&self) -> &VehicleActor {
        &self.gate.actor
    }

    /// Manager-created and trust-resolved current segment identity. The open
    /// tail is not footer-authenticated evidence yet.
    #[must_use]
    pub fn active_journal_identity(&self) -> Option<&SegmentIdentity> {
        self.journal.active_identity()
    }

    /// Read-only publication state rebuilt before current authority exposure and
    /// then updated only by the private consuming lifecycle mechanism.
    #[must_use]
    pub const fn recovered_publication(&self) -> &RecoveredPublicationState {
        self.journal.publication()
    }

    /// Material journal recovery actions and current-tail status at completion
    /// of the fused startup transaction.
    #[must_use]
    pub const fn journal_recovery_report(&self) -> JournalRecoveryReport {
        self.journal.recovery_report()
    }

    /// Number of dangling prior-boot calls locally sync-closed as
    /// `UnknownAfterPublish` before this runtime became observable.
    #[must_use]
    pub const fn recovery_unknown_events(&self) -> usize {
        self.recovery_unknown_events
    }

    /// Consume the private successful-startup proof exactly once. Absence is a
    /// hard coordinator binding failure, never reconstructed from report fields.
    #[cfg(feature = "live-zenoh")]
    pub(super) fn take_declared_live_zenoh_capability(
        &mut self,
    ) -> Option<ValidatedDeclaredLiveZenohStartup> {
        self.gate.declared_live_zenoh.take()
    }
}

/// Mismatch between one NCP/configuration-validated signed package and the
/// runtime objects it is being asked to authorize.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DeploymentGateBindingError {
    /// The package and template name different Gates.
    GateMismatch,
    /// The package and template name different realms.
    RealmMismatch,
    /// The package and template name different vehicles.
    VehicleMismatch,
    /// The package runtime selection differs from the template selection.
    RuntimeProfileMismatch,
    /// The package NCP wire selection differs from the compiled adapter selection.
    NcpWireProfileMismatch,
    /// The package state-store identifier differs from the selected durable store.
    StateStoreMismatch,
    /// Package assurance class and startup anchor profile are incompatible.
    AssuranceProfileMismatch,
    /// The live trust store differs from the signed Gate configuration.
    TrustSnapshotMismatch,
    /// Bootstrap and runtime trust reuse a key identifier or public key under
    /// incompatible authority semantics.
    BootstrapRuntimeTrustConflict(TrustStoreDisjointnessError),
    /// The live key-revocation snapshot differs from the signed Gate configuration.
    RevocationSnapshotMismatch,
    /// The live admission snapshot differs from the signed Gate configuration.
    AdmissionSnapshotMismatch,
    /// The validated executable policy differs from the signed Gate configuration.
    PolicySnapshotMismatch,
    /// The live NCP session differs from the signed Gate configuration.
    SessionMismatch,
    /// Publication-authority evidence differs from the signed Gate configuration.
    PublicationMismatch,
    /// The local lease-duration cap differs from the signed Gate configuration.
    LocalCapMismatch,
    /// The Gate application signer id differs from the signed Gate configuration.
    GateSignerKidMismatch,
    /// The Gate application public key differs from the signed Gate configuration.
    GateSignerPublicKeyMismatch,
}

impl DeploymentGateBindingError {
    /// Stable machine-readable failure class.
    #[must_use]
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::GateMismatch => "DEPLOYMENT_GATE_BINDING_GATE_MISMATCH",
            Self::RealmMismatch => "DEPLOYMENT_GATE_BINDING_REALM_MISMATCH",
            Self::VehicleMismatch => "DEPLOYMENT_GATE_BINDING_VEHICLE_MISMATCH",
            Self::RuntimeProfileMismatch => "DEPLOYMENT_GATE_BINDING_RUNTIME_PROFILE_MISMATCH",
            Self::NcpWireProfileMismatch => "DEPLOYMENT_GATE_BINDING_NCP_WIRE_PROFILE_MISMATCH",
            Self::StateStoreMismatch => "DEPLOYMENT_GATE_BINDING_STATE_STORE_MISMATCH",
            Self::AssuranceProfileMismatch => "DEPLOYMENT_GATE_BINDING_ASSURANCE_PROFILE_MISMATCH",
            Self::TrustSnapshotMismatch => "DEPLOYMENT_GATE_BINDING_TRUST_SNAPSHOT_MISMATCH",
            Self::BootstrapRuntimeTrustConflict(_) => {
                "DEPLOYMENT_GATE_BINDING_BOOTSTRAP_RUNTIME_TRUST_CONFLICT"
            }
            Self::RevocationSnapshotMismatch => {
                "DEPLOYMENT_GATE_BINDING_REVOCATION_SNAPSHOT_MISMATCH"
            }
            Self::AdmissionSnapshotMismatch => {
                "DEPLOYMENT_GATE_BINDING_ADMISSION_SNAPSHOT_MISMATCH"
            }
            Self::PolicySnapshotMismatch => "DEPLOYMENT_GATE_BINDING_POLICY_SNAPSHOT_MISMATCH",
            Self::SessionMismatch => "DEPLOYMENT_GATE_BINDING_SESSION_MISMATCH",
            Self::PublicationMismatch => "DEPLOYMENT_GATE_BINDING_PUBLICATION_MISMATCH",
            Self::LocalCapMismatch => "DEPLOYMENT_GATE_BINDING_LOCAL_CAP_MISMATCH",
            Self::GateSignerKidMismatch => "DEPLOYMENT_GATE_BINDING_SIGNER_KID_MISMATCH",
            Self::GateSignerPublicKeyMismatch => {
                "DEPLOYMENT_GATE_BINDING_SIGNER_PUBLIC_KEY_MISMATCH"
            }
        }
    }
}

impl std::fmt::Display for DeploymentGateBindingError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for DeploymentGateBindingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::BootstrapRuntimeTrustConflict(error) => Some(error),
            _ => None,
        }
    }
}

/// Durable startup orchestration failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DurableGateStartupError {
    /// Static actor configuration failed validation.
    Config(GateConfigError),
    /// Publication authority is not the current ACL-only profile.
    UnsupportedPublicationProfile,
    /// A declared runtime profile requires a different NCP wire profile.
    NcpWireProfileMismatch {
        /// Runtime profile declared by the caller.
        runtime_profile: GateRuntimeProfile,
        /// Wire profile required by that runtime declaration.
        required: NcpCommandWireProfile,
        /// Wire profile selected by the configured adapter.
        actual: NcpCommandWireProfile,
    },
    /// Live Zenoh was declared but this build omits live-Zenoh support.
    LiveZenohSupportNotCompiled,
    /// ACL evidence does not bind the exact final route derived for this realm/session.
    PublicationRouteBinding,
    /// Snapshot binding does not name the configured Gate.
    StoreGateMismatch,
    /// A zero or overflowing durable-size bound was supplied.
    InvalidSizeLimit,
    /// The selected anchor does not meet the requested startup profile.
    AnchorProtectionMismatch {
        /// Required startup profile.
        required: StartupProfile,
        /// Protection declared by the supplied anchor.
        actual: AnchorProtection,
    },
    /// Assurance startup was attempted through the cooperative unbound API.
    DeploymentPackageRequired,
    /// A validated package did not bind the supplied runtime objects exactly.
    DeploymentBinding(DeploymentGateBindingError),
    /// Cryptographic entropy was unavailable before backend access.
    EntropyUnavailable,
    /// The configured instance-lock path is invalid or inaccessible.
    LockUnavailable,
    /// Another process or actor currently owns the instance lock.
    LockHeld,
    /// The dedicated local state directory is invalid or inaccessible.
    StateDirectoryUnavailable,
    /// Durable provision/open/boot advancement failed.
    Durable(DurableAntiRollbackError),
    /// Recovered actor construction failed after boot commit.
    Actor(GateStartupError),
}

impl DurableGateStartupError {
    /// Stable machine-readable failure class.
    #[must_use]
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::Config(_) => "DURABLE_GATE_STARTUP_CONFIG",
            Self::UnsupportedPublicationProfile => {
                "DURABLE_GATE_STARTUP_UNSUPPORTED_PUBLICATION_PROFILE"
            }
            Self::NcpWireProfileMismatch { .. } => "DURABLE_GATE_STARTUP_NCP_WIRE_PROFILE_MISMATCH",
            Self::LiveZenohSupportNotCompiled => "DURABLE_GATE_STARTUP_LIVE_ZENOH_NOT_COMPILED",
            Self::PublicationRouteBinding => "DURABLE_GATE_STARTUP_PUBLICATION_ROUTE_BINDING",
            Self::StoreGateMismatch => "DURABLE_GATE_STARTUP_STORE_GATE_MISMATCH",
            Self::InvalidSizeLimit => "DURABLE_GATE_STARTUP_INVALID_SIZE_LIMIT",
            Self::AnchorProtectionMismatch { .. } => {
                "DURABLE_GATE_STARTUP_ANCHOR_PROTECTION_MISMATCH"
            }
            Self::DeploymentPackageRequired => "DURABLE_GATE_STARTUP_DEPLOYMENT_PACKAGE_REQUIRED",
            Self::DeploymentBinding(error) => error.reason_code(),
            Self::EntropyUnavailable => "DURABLE_GATE_STARTUP_ENTROPY_UNAVAILABLE",
            Self::LockUnavailable => "DURABLE_GATE_STARTUP_LOCK_UNAVAILABLE",
            Self::LockHeld => "DURABLE_GATE_STARTUP_LOCK_HELD",
            Self::StateDirectoryUnavailable => "DURABLE_GATE_STARTUP_STATE_DIRECTORY_UNAVAILABLE",
            Self::Durable(_) => "DURABLE_GATE_STARTUP_DURABLE_STATE",
            Self::Actor(_) => "DURABLE_GATE_STARTUP_ACTOR",
        }
    }
}

impl std::fmt::Display for DurableGateStartupError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for DurableGateStartupError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Config(error) => Some(error),
            Self::Actor(error) => Some(error),
            Self::DeploymentBinding(error) => Some(error),
            Self::Durable(error) => Some(error),
            _ => None,
        }
    }
}

impl From<DurableAntiRollbackError> for DurableGateStartupError {
    fn from(error: DurableAntiRollbackError) -> Self {
        Self::Durable(error)
    }
}

impl From<GateStartupError> for DurableGateStartupError {
    fn from(error: GateStartupError) -> Self {
        Self::Actor(error)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeploymentStartupMode {
    Unbound,
    PackageBound,
}

/// Validate, lock, explicitly open/provision arbitrary durable backends, commit
/// a fresh boot, and construct the actor.
///
/// # Errors
/// Returns before backend access for invalid configuration, profile mismatch, or
/// entropy failure. Missing state under [`StateOpenMode::OpenExisting`] is never
/// provisioned. Backend, lock, boot-commit, and actor-construction errors fail closed.
/// The lock path must be distinct from every backend path, and all backend writers
/// must cooperate on that same lock. [`StartupProfile::AssuranceExternal`] is
/// rejected here; use [`start_deployment_with_backends`] so assurance startup
/// cannot omit the signed package and package-bound boot ratchet.
pub fn start_with_backends<S, A, E>(
    template: GateConfigTemplate,
    state: StartupStateConfig,
    storage: S,
    anchor: A,
    key: StorageMacKey,
    entropy: &mut E,
) -> Result<RunningGate, DurableGateStartupError>
where
    S: SnapshotStorage + Send + 'static,
    A: GenerationAnchor + Send + 'static,
    E: EntropySource + ?Sized,
{
    let prepared = prepare(
        &template,
        &state,
        &anchor,
        entropy,
        DeploymentStartupMode::Unbound,
    )?;
    start_prepared(template, state, storage, anchor, key, prepared)
}

/// Start a Gate whose signed package, exact NCP compatibility and Gate
/// configuration roles, package ratchet, runtime selections, and durable boot
/// are one consuming chain.
///
/// The supplied package must already have passed signature/policy verification,
/// exact artifact-byte resolution, signed-role NCP compatibility validation,
/// strict Gate-configuration decoding/cross-binding, and four separately
/// role-bound, public-key-distinct authority-approval checks rooted in the same retained bootstrap trust and
/// revocation snapshots that verified the package. This function
/// additionally exact-matches its Gate, realm, vehicle, runtime, NCP wire,
/// state-store, assurance, trust, revocation, admission, policy, session,
/// publication, local-cap, and application-signer selections to the concrete
/// startup objects and rejects incompatible bootstrap/runtime `kid` or public-key
/// bindings before entropy, lock, storage, or anchor mutation. It then
/// commits the verified package revision and canonical payload digest atomically
/// with the fresh boot and retains the package through the running lifecycle.
///
/// The trust/admission/revocation/policy roles carry revision-scoped approvals
/// of runtime snapshot digests; the corresponding runtime objects are supplied
/// separately and exact-matched here. The other seven artifact roles remain
/// byte-verified, not semantically loaded by this function. A later journal
/// bind exact-matches the signed
/// journal ID to the authenticated format-v2 segment chain, but this boundary
/// does not prove a mandatory journal, its path, the running executable,
/// credential custody, or transport setup.
///
/// # Errors
/// Returns before entropy or backend access on any package/runtime mismatch.
/// Other failures have the same fail-closed semantics as
/// [`start_with_backends`].
pub fn start_deployment_with_backends<S, A, E>(
    package: AuthorityValidatedDeploymentPackage,
    template: GateConfigTemplate,
    state: StartupStateConfig,
    storage: S,
    anchor: A,
    key: StorageMacKey,
    entropy: &mut E,
) -> Result<RunningGate, DurableGateStartupError>
where
    S: SnapshotStorage + Send + 'static,
    A: GenerationAnchor + Send + 'static,
    E: EntropySource + ?Sized,
{
    template.validate()?;
    validate_deployment_binding(&package, &template, &state)?;
    let prepared = prepare_validated_template(
        &template,
        &state,
        &anchor,
        entropy,
        DeploymentStartupMode::PackageBound,
    )?;
    start_prepared_deployment(package, template, state, storage, anchor, key, prepared)
}

/// Start with the fixed-name Unix local snapshot and rewritable local anchor.
///
/// The dedicated directory is created only for explicit provisioning, and only
/// after configuration, profile, and entropy checks succeed. This convenience is
/// development-only: assurance startup rejects its `LocalRewritable` anchor.
///
/// # Errors
/// Returns on validation, entropy, directory, lock, durable, or actor failures.
pub fn start_local<E: EntropySource + ?Sized>(
    template: GateConfigTemplate,
    local: LocalStartupConfig,
    key: StorageMacKey,
    entropy: &mut E,
) -> Result<RunningGate, DurableGateStartupError> {
    template.validate()?;
    let snapshot_path = local.state_directory.join(LOCAL_SNAPSHOT_FILE);
    let anchor_path = local.state_directory.join(LOCAL_ANCHOR_FILE);
    let lock_path = local.state_directory.join(LOCAL_LOCK_FILE);
    let max_snapshot_bytes = local
        .max_payload_bytes
        .checked_add(LOCAL_SNAPSHOT_OVERHEAD_ALLOWANCE)
        .ok_or(DurableGateStartupError::InvalidSizeLimit)?;
    let storage = AtomicFileSnapshot::new(snapshot_path, max_snapshot_bytes);
    let anchor = LocalFileGenerationAnchor::new(anchor_path, local.store_id);
    let state = StartupStateConfig {
        open_mode: local.open_mode,
        profile: local.profile,
        instance_lock_path: lock_path,
        binding: SnapshotBinding::new(local.store_id, template.gate_id.as_str().as_bytes()),
        max_payload_bytes: local.max_payload_bytes,
    };

    let prepared = prepare_validated_template(
        &template,
        &state,
        &anchor,
        entropy,
        DeploymentStartupMode::Unbound,
    )?;
    #[cfg(not(unix))]
    {
        let _ = (template, state, storage, anchor, key, prepared);
        return Err(DurableGateStartupError::Durable(
            DurableAntiRollbackError::Durable(haldir_durable::DurableError::Unsupported),
        ));
    }
    #[cfg(unix)]
    prepare_local_directory(&local.state_directory, local.open_mode)?;
    #[cfg(unix)]
    start_prepared(template, state, storage, anchor, key, prepared)
}

fn validate_deployment_binding(
    package: &AuthorityValidatedDeploymentPackage,
    template: &GateConfigTemplate,
    state: &StartupStateConfig,
) -> Result<(), DurableGateStartupError> {
    let signed = package.resolved().verified().package();
    if signed.gate_id != template.gate_id {
        return Err(DurableGateStartupError::DeploymentBinding(
            DeploymentGateBindingError::GateMismatch,
        ));
    }
    if signed.realm != template.realm {
        return Err(DurableGateStartupError::DeploymentBinding(
            DeploymentGateBindingError::RealmMismatch,
        ));
    }
    if signed.vehicle_id != template.vehicle_id {
        return Err(DurableGateStartupError::DeploymentBinding(
            DeploymentGateBindingError::VehicleMismatch,
        ));
    }

    let runtime_matches = matches!(
        (signed.runtime_profile, template.runtime_profile),
        (
            DeploymentRuntimeProfileV1::InProcessReference,
            GateRuntimeProfile::InProcessReference
        ) | (
            DeploymentRuntimeProfileV1::DeclaredLiveZenoh,
            GateRuntimeProfile::DeclaredLiveZenoh
        )
    );
    if !runtime_matches {
        return Err(DurableGateStartupError::DeploymentBinding(
            DeploymentGateBindingError::RuntimeProfileMismatch,
        ));
    }

    let wire_matches = matches!(
        (signed.ncp_wire_profile, template.ncp_adapter.wire_profile()),
        (
            DeploymentNcpWireProfileV1::ModeledP0,
            NcpCommandWireProfile::ModeledP0
        ) | (
            DeploymentNcpWireProfileV1::ExactNcpV0_8Json,
            NcpCommandWireProfile::ExactNcpV0_8Json
        )
    );
    if !wire_matches {
        return Err(DurableGateStartupError::DeploymentBinding(
            DeploymentGateBindingError::NcpWireProfileMismatch,
        ));
    }

    if &signed.state_store_id != state.binding.store_id().as_bytes() {
        return Err(DurableGateStartupError::DeploymentBinding(
            DeploymentGateBindingError::StateStoreMismatch,
        ));
    }

    let assurance_matches = matches!(
        (signed.profile_class, state.profile),
        (
            DeploymentClassV1::Development,
            StartupProfile::DevelopmentLocal
        ) | (
            DeploymentClassV1::ExperimentalCanary | DeploymentClassV1::AssuranceSimulation,
            StartupProfile::AssuranceExternal
        )
    );
    if !assurance_matches {
        return Err(DurableGateStartupError::DeploymentBinding(
            DeploymentGateBindingError::AssuranceProfileMismatch,
        ));
    }

    let configuration = package.gate_configuration();
    if configuration.gate_signer_kid != template.gate_signer_kid {
        return Err(DurableGateStartupError::DeploymentBinding(
            DeploymentGateBindingError::GateSignerKidMismatch,
        ));
    }
    if configuration.gate_signer_public_key != template.gate_signer.verifying_key().to_bytes() {
        return Err(DurableGateStartupError::DeploymentBinding(
            DeploymentGateBindingError::GateSignerPublicKeyMismatch,
        ));
    }
    if configuration.trust_snapshot_digest != template.trust.canonical_digest() {
        return Err(DurableGateStartupError::DeploymentBinding(
            DeploymentGateBindingError::TrustSnapshotMismatch,
        ));
    }
    package
        .validate_runtime_trust_bindings(&template.trust)
        .map_err(|error| {
            DurableGateStartupError::DeploymentBinding(
                DeploymentGateBindingError::BootstrapRuntimeTrustConflict(error),
            )
        })?;
    if configuration.revocation_snapshot_digest != template.revocations.canonical_digest() {
        return Err(DurableGateStartupError::DeploymentBinding(
            DeploymentGateBindingError::RevocationSnapshotMismatch,
        ));
    }
    if configuration.admission_snapshot_digest != template.admission.canonical_digest() {
        return Err(DurableGateStartupError::DeploymentBinding(
            DeploymentGateBindingError::AdmissionSnapshotMismatch,
        ));
    }
    if configuration.policy_snapshot_digest != template.policy_snapshot_digest {
        return Err(DurableGateStartupError::DeploymentBinding(
            DeploymentGateBindingError::PolicySnapshotMismatch,
        ));
    }
    if configuration.session != template.session {
        return Err(DurableGateStartupError::DeploymentBinding(
            DeploymentGateBindingError::SessionMismatch,
        ));
    }
    let PlantPublicationAuthorityStateV1::AclExclusiveV1(publication) = &template.publication
    else {
        return Err(DurableGateStartupError::DeploymentBinding(
            DeploymentGateBindingError::PublicationMismatch,
        ));
    };
    if configuration.publication.gate_transport_principal != publication.gate_transport_principal
        || configuration.publication.final_route_digest != publication.final_route_digest
        || configuration.publication.certificate_fingerprint != publication.certificate_fingerprint
        || configuration.publication.acl_policy_digest != publication.acl_policy_digest
    {
        return Err(DurableGateStartupError::DeploymentBinding(
            DeploymentGateBindingError::PublicationMismatch,
        ));
    }
    if configuration.local_cap_ms != template.local_cap_ms {
        return Err(DurableGateStartupError::DeploymentBinding(
            DeploymentGateBindingError::LocalCapMismatch,
        ));
    }
    Ok(())
}

struct PreparedStartup {
    boot_entropy: [u8; BOOT_ENTROPY_BYTES],
    output_epoch: GateOutputEpoch,
    #[cfg(feature = "live-zenoh")]
    activation_challenge_nonce: ChallengeNonce,
    anchor_protection: AnchorProtection,
}

fn prepare<A: GenerationAnchor, E: EntropySource + ?Sized>(
    template: &GateConfigTemplate,
    state: &StartupStateConfig,
    anchor: &A,
    entropy: &mut E,
    deployment_mode: DeploymentStartupMode,
) -> Result<PreparedStartup, DurableGateStartupError> {
    template.validate()?;
    prepare_validated_template(template, state, anchor, entropy, deployment_mode)
}

fn prepare_validated_template<A: GenerationAnchor, E: EntropySource + ?Sized>(
    template: &GateConfigTemplate,
    state: &StartupStateConfig,
    anchor: &A,
    entropy: &mut E,
    deployment_mode: DeploymentStartupMode,
) -> Result<PreparedStartup, DurableGateStartupError> {
    if !state
        .binding
        .matches_gate_id(template.gate_id.as_str().as_bytes())
    {
        return Err(DurableGateStartupError::StoreGateMismatch);
    }
    if state.max_payload_bytes == 0 {
        return Err(DurableGateStartupError::InvalidSizeLimit);
    }
    if state.instance_lock_path.file_name().is_none() {
        return Err(DurableGateStartupError::LockUnavailable);
    }

    let anchor_protection = anchor.protection();
    if !state.profile.accepts(anchor_protection) {
        return Err(DurableGateStartupError::AnchorProtectionMismatch {
            required: state.profile,
            actual: anchor_protection,
        });
    }
    if state.profile == StartupProfile::AssuranceExternal
        && deployment_mode == DeploymentStartupMode::Unbound
    {
        return Err(DurableGateStartupError::DeploymentPackageRequired);
    }

    let mut bytes = [0u8; ENTROPY_BYTES];
    entropy
        .fill_bytes(&mut bytes)
        .map_err(|_| DurableGateStartupError::EntropyUnavailable)?;
    let boot_entropy = bytes
        .get(..BOOT_ENTROPY_BYTES)
        .and_then(|value| value.try_into().ok())
        .ok_or(DurableGateStartupError::EntropyUnavailable)?;
    let output_entropy_end = BOOT_ENTROPY_BYTES + OUTPUT_EPOCH_ENTROPY_BYTES;
    let output_random = bytes
        .get(BOOT_ENTROPY_BYTES..output_entropy_end)
        .and_then(|value| value.try_into().ok())
        .ok_or(DurableGateStartupError::EntropyUnavailable)?;
    #[cfg(feature = "live-zenoh")]
    let activation_challenge_random = bytes
        .get(output_entropy_end..)
        .and_then(|value| value.try_into().ok())
        .ok_or(DurableGateStartupError::EntropyUnavailable)?;
    let output_epoch =
        GateOutputEpoch::new(CanonicalUuidV4String::from_random_bytes(output_random));

    Ok(PreparedStartup {
        boot_entropy,
        output_epoch,
        #[cfg(feature = "live-zenoh")]
        activation_challenge_nonce: ChallengeNonce::new(activation_challenge_random),
        anchor_protection,
    })
}

fn start_prepared<S, A>(
    template: GateConfigTemplate,
    state: StartupStateConfig,
    storage: S,
    anchor: A,
    key: StorageMacKey,
    prepared: PreparedStartup,
) -> Result<RunningGate, DurableGateStartupError>
where
    S: SnapshotStorage + Send + 'static,
    A: GenerationAnchor + Send + 'static,
{
    let startup_profile = state.profile;
    let instance_lock = acquire_instance_lock(&state.instance_lock_path)?;
    let (store, recovery, provisioned) = match state.open_mode {
        StateOpenMode::ProvisionNew => (
            DurableAntiRollbackStore::provision_new(
                storage,
                anchor,
                key,
                state.binding,
                state.max_payload_bytes,
            )?,
            None,
            true,
        ),
        StateOpenMode::OpenExisting => {
            let (store, recovery) = DurableAntiRollbackStore::open_existing(
                storage,
                anchor,
                key,
                state.binding,
                state.max_payload_bytes,
            )?;
            (store, Some(recovery), false)
        }
    };

    let (booted, boot_commit) = store.begin_boot(&template.gate_id, prepared.boot_entropy)?;
    let gate_boot_id = booted.boot_context().gate_boot_id;
    let runtime_profile = template.runtime_profile;
    let config = template.into_runtime(gate_boot_id, prepared.output_epoch);
    let actor = VehicleActor::new_recovered(config, booted)?;
    #[cfg(feature = "live-zenoh")]
    let declared_live_zenoh = match runtime_profile {
        GateRuntimeProfile::InProcessReference => None,
        GateRuntimeProfile::DeclaredLiveZenoh => Some(ValidatedDeclaredLiveZenohStartup {
            activation_challenge_nonce: prepared.activation_challenge_nonce,
        }),
    };
    let report = StartupReport {
        runtime_profile,
        provisioned,
        recovery,
        boot_commit,
        anchor_protection: prepared.anchor_protection,
        startup_profile,
        deployment_revision: None,
        deployment_payload_digest: None,
        gate_boot_id,
        output_epoch: prepared.output_epoch,
    };

    Ok(RunningGate {
        actor,
        report,
        deployment_package: None,
        #[cfg(feature = "live-zenoh")]
        declared_live_zenoh,
        _instance_lock: instance_lock,
    })
}

fn start_prepared_deployment<S, A>(
    package: AuthorityValidatedDeploymentPackage,
    template: GateConfigTemplate,
    state: StartupStateConfig,
    storage: S,
    anchor: A,
    key: StorageMacKey,
    prepared: PreparedStartup,
) -> Result<RunningGate, DurableGateStartupError>
where
    S: SnapshotStorage + Send + 'static,
    A: GenerationAnchor + Send + 'static,
{
    let startup_profile = state.profile;
    let package_contract = package.resolved().verified().package();
    let deployment_revision = package_contract.deployment_revision;
    let deployment_payload_digest = package.resolved().verified().payload_digest();
    let instance_lock = acquire_instance_lock(&state.instance_lock_path)?;
    let (store, recovery, provisioned) = match state.open_mode {
        StateOpenMode::ProvisionNew => (
            DurableAntiRollbackStore::provision_new(
                storage,
                anchor,
                key,
                state.binding,
                state.max_payload_bytes,
            )?,
            None,
            true,
        ),
        StateOpenMode::OpenExisting => {
            let (store, recovery) = DurableAntiRollbackStore::open_existing(
                storage,
                anchor,
                key,
                state.binding,
                state.max_payload_bytes,
            )?;
            (store, Some(recovery), false)
        }
    };

    let (booted, boot_commit) = store.begin_deployment_boot(
        &template.gate_id,
        prepared.boot_entropy,
        deployment_revision,
        deployment_payload_digest,
    )?;
    let gate_boot_id = booted.boot_context().gate_boot_id;
    let runtime_profile = template.runtime_profile;
    let config = template.into_runtime(gate_boot_id, prepared.output_epoch);
    let actor = VehicleActor::new_deployment_recovered(config, booted)?;
    #[cfg(feature = "live-zenoh")]
    let declared_live_zenoh = match runtime_profile {
        GateRuntimeProfile::InProcessReference => None,
        GateRuntimeProfile::DeclaredLiveZenoh => Some(ValidatedDeclaredLiveZenohStartup {
            activation_challenge_nonce: prepared.activation_challenge_nonce,
        }),
    };
    let report = StartupReport {
        runtime_profile,
        provisioned,
        recovery,
        boot_commit,
        anchor_protection: prepared.anchor_protection,
        startup_profile,
        deployment_revision: Some(deployment_revision),
        deployment_payload_digest: Some(deployment_payload_digest),
        gate_boot_id,
        output_epoch: prepared.output_epoch,
    };

    Ok(RunningGate {
        actor,
        report,
        deployment_package: Some(package),
        #[cfg(feature = "live-zenoh")]
        declared_live_zenoh,
        _instance_lock: instance_lock,
    })
}

fn acquire_instance_lock(path: &Path) -> Result<InstanceLock, DurableGateStartupError> {
    if let Ok(metadata) = fs::symlink_metadata(path)
        && !metadata.file_type().is_file()
    {
        return Err(DurableGateStartupError::LockUnavailable);
    }

    #[cfg(unix)]
    let file = File::from(
        open(
            path,
            OFlags::RDWR
                | OFlags::CREATE
                | OFlags::CLOEXEC
                | OFlags::NOFOLLOW
                | OFlags::NONBLOCK
                | OFlags::NOCTTY,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|_| DurableGateStartupError::LockUnavailable)?,
    );
    #[cfg(not(unix))]
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(path)
        .map_err(|_| DurableGateStartupError::LockUnavailable)?;
    let path_metadata =
        fs::symlink_metadata(path).map_err(|_| DurableGateStartupError::LockUnavailable)?;
    if !path_metadata.file_type().is_file() {
        return Err(DurableGateStartupError::LockUnavailable);
    }
    #[cfg(unix)]
    {
        let opened_metadata = file
            .metadata()
            .map_err(|_| DurableGateStartupError::LockUnavailable)?;
        if path_metadata.dev() != opened_metadata.dev()
            || path_metadata.ino() != opened_metadata.ino()
        {
            return Err(DurableGateStartupError::LockUnavailable);
        }
    }

    match file.try_lock() {
        Ok(()) => Ok(InstanceLock(file)),
        Err(TryLockError::WouldBlock) => Err(DurableGateStartupError::LockHeld),
        Err(TryLockError::Error(_)) => Err(DurableGateStartupError::LockUnavailable),
    }
}

#[cfg(unix)]
fn prepare_local_directory(
    directory: &Path,
    mode: StateOpenMode,
) -> Result<(), DurableGateStartupError> {
    match fs::symlink_metadata(directory) {
        Ok(metadata) if metadata.file_type().is_dir() => Ok(()),
        Ok(_) => Err(DurableGateStartupError::StateDirectoryUnavailable),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => match mode {
            StateOpenMode::OpenExisting => Err(DurableGateStartupError::Durable(
                DurableAntiRollbackError::Durable(haldir_durable::DurableError::Missing),
            )),
            StateOpenMode::ProvisionNew => {
                let mut builder = fs::DirBuilder::new();
                #[cfg(unix)]
                builder.mode(0o700);
                builder
                    .create(directory)
                    .map_err(|_| DurableGateStartupError::StateDirectoryUnavailable)
            }
        },
        Err(_) => Err(DurableGateStartupError::StateDirectoryUnavailable),
    }
}

#[cfg(test)]
mod tests {
    use core::num::{NonZeroU32, NonZeroU64};
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use haldir_contracts::cbor::{CanonicalMessage, to_canonical_bytes};
    use haldir_contracts::deployment::DeploymentRevision;
    use haldir_contracts::digest::DigestDomain;
    use haldir_contracts::ids::{
        AdmissionId, ControllerId, DecisionId, GateOutputEpoch, IntentEpoch, IntentSeq, KeyId,
        MissionId, MissionLeaseId, OutputSeq, PrincipalId, SourceSeq,
    };
    use haldir_contracts::publication::PublicationStageEventV1;
    use haldir_contracts::receipt::{
        DecisionOutcomeV1, DecisionReasonCodeV1, DecisionReceiptV1, PublishStageV1,
        TransformationRelationV1,
    };
    use haldir_contracts::scalar::{BoundedAscii, BoundedVec};
    use haldir_contracts::session::{HaldirIntentPositionV1, NcpSourceRefV1, NcpStreamPositionV1};
    use haldir_contracts::status::{AclExclusiveEvidenceV1, PlantPublicationUnavailableReasonV1};
    use haldir_crypto::{KeyClass, KeyRecord, KeyRole, KeySubject, sign_message};
    use haldir_deployment::contract::{
        AclPublicationBindingV1, AuthoritySnapshotApprovalV1, AuthoritySnapshotKindV1,
        DeploymentArtifactIdV1, DeploymentArtifactRefV1, DeploymentPackageV1,
        GateConfigurationArtifactV1,
    };
    use haldir_deployment::{
        ArtifactLimits, AuthorityApprovalPolicy, AuthorityValidatedDeploymentPackage,
        DeploymentAcceptancePolicy, DeploymentArtifactInput, DeploymentArtifactSet,
        DeploymentIdentityExpectation, DeploymentProfileRequirement, verify_deployment_package,
    };
    use haldir_durable::{Anchor, DurableError};
    use haldir_evidence::journal::JournalBounds;
    use haldir_evidence::manager::{EvidenceJournalManager, JournalManagerError};
    use haldir_evidence::publication::PublicationTraceState;
    use haldir_policy_native::GeofenceBoxV1;

    use super::*;

    static TEST_DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let sequence = TEST_DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "haldir-gate-startup-test-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn absent_child(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[derive(Clone, Default)]
    struct MemoryStorage(Arc<Mutex<Option<Vec<u8>>>>);

    impl SnapshotStorage for MemoryStorage {
        fn load(&self) -> Result<Option<Vec<u8>>, DurableError> {
            Ok(self.0.lock().unwrap().clone())
        }

        fn replace(&mut self, bytes: &[u8]) -> Result<(), DurableError> {
            *self.0.lock().unwrap() = Some(bytes.to_vec());
            Ok(())
        }
    }

    #[derive(Clone, Default)]
    struct MemoryAnchor {
        head: Arc<Mutex<Option<Anchor>>>,
        fail_compare_set: Arc<AtomicBool>,
    }

    impl GenerationAnchor for MemoryAnchor {
        fn protection(&self) -> AnchorProtection {
            AnchorProtection::LocalRewritable
        }

        fn read(&self, _store_id: StoreId) -> Result<Option<Anchor>, DurableError> {
            Ok(*self.head.lock().unwrap())
        }

        fn compare_and_set(
            &mut self,
            _store_id: StoreId,
            expected: Option<Anchor>,
            next: Anchor,
        ) -> Result<(), DurableError> {
            if self.fail_compare_set.load(Ordering::Relaxed) {
                return Err(DurableError::AnchorUnavailable);
            }
            let mut head = self.head.lock().unwrap();
            if *head != expected {
                return Err(DurableError::AnchorConflict);
            }
            *head = Some(next);
            Ok(())
        }
    }

    #[derive(Clone, Default)]
    struct ExternalMemoryAnchor(MemoryAnchor);

    impl GenerationAnchor for ExternalMemoryAnchor {
        fn protection(&self) -> AnchorProtection {
            AnchorProtection::ExternalNonRewindable
        }

        fn read(&self, store_id: StoreId) -> Result<Option<Anchor>, DurableError> {
            self.0.read(store_id)
        }

        fn compare_and_set(
            &mut self,
            store_id: StoreId,
            expected: Option<Anchor>,
            next: Anchor,
        ) -> Result<(), DurableError> {
            self.0.compare_and_set(store_id, expected, next)
        }
    }

    #[derive(Clone)]
    struct CountingStorage(Arc<AtomicUsize>);

    impl SnapshotStorage for CountingStorage {
        fn load(&self) -> Result<Option<Vec<u8>>, DurableError> {
            self.0.fetch_add(1, Ordering::Relaxed);
            Ok(None)
        }

        fn replace(&mut self, _bytes: &[u8]) -> Result<(), DurableError> {
            self.0.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    #[derive(Clone)]
    struct CountingAnchor(Arc<AtomicUsize>);

    impl GenerationAnchor for CountingAnchor {
        fn protection(&self) -> AnchorProtection {
            self.0.fetch_add(1, Ordering::Relaxed);
            AnchorProtection::LocalRewritable
        }

        fn read(&self, _store_id: StoreId) -> Result<Option<Anchor>, DurableError> {
            self.0.fetch_add(1, Ordering::Relaxed);
            Ok(None)
        }

        fn compare_and_set(
            &mut self,
            _store_id: StoreId,
            _expected: Option<Anchor>,
            _next: Anchor,
        ) -> Result<(), DurableError> {
            self.0.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    struct DeterministicEntropy {
        seed: u8,
        calls: usize,
    }

    impl DeterministicEntropy {
        const fn new(seed: u8) -> Self {
            Self { seed, calls: 0 }
        }
    }

    impl EntropySource for DeterministicEntropy {
        fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
            self.calls += 1;
            for (offset, byte) in destination.iter_mut().enumerate() {
                let offset = u8::try_from(offset).map_err(|_| EntropyError)?;
                *byte = self.seed.wrapping_add(offset);
            }
            Ok(())
        }
    }

    struct FailingEntropy;

    impl EntropySource for FailingEntropy {
        fn fill_bytes(&mut self, _destination: &mut [u8]) -> Result<(), EntropyError> {
            Err(EntropyError)
        }
    }

    #[cfg(feature = "live-zenoh")]
    #[derive(Clone, Copy)]
    struct FixedCoordinatorClock;

    #[cfg(feature = "live-zenoh")]
    impl haldir_core::time::MonotonicClock for FixedCoordinatorClock {
        fn now(&self) -> haldir_core::time::MonoInstant {
            haldir_core::time::MonoInstant::from_nanos(1_000_000_000)
        }
    }

    #[cfg(feature = "live-zenoh")]
    #[derive(Clone, Copy)]
    struct RejectClockSampling;

    #[cfg(feature = "live-zenoh")]
    impl haldir_core::time::MonotonicClock for RejectClockSampling {
        fn now(&self) -> haldir_core::time::MonoInstant {
            panic!("a rejected live capability bind must not sample its clock")
        }
    }

    fn digest(bytes: &[u8]) -> DigestV1 {
        DigestV1::compute(DigestDomain::Payload, bytes)
    }

    fn template() -> GateConfigTemplate {
        let gate_id = GateId::new("gate-1").unwrap();
        let gate_signer_kid = KeyId::new(vec![3]).unwrap();
        let gate_signer = SigningKey::from_seed([3; 32]).expect("nonzero test seed");
        let mut trust = TrustStore::new();
        trust
            .insert(KeyRecord {
                kid: gate_signer_kid.clone(),
                role: KeyRole::GateApplication,
                verifying_key: gate_signer.verifying_key(),
                subject: KeySubject::new(gate_id.as_str()).unwrap(),
                class: KeyClass::Assurance,
            })
            .unwrap();
        let policy = NativePolicySnapshot {
            max_component_mm_s: 1,
            max_speed_mm_s: 1,
            max_output_validity_ms: 1,
            min_useful_validity_ms: 1,
            publication_safety_margin_ms: 0,
            source_freshness_cap_ms: 1,
            state_freshness_cap_ms: 1,
            ncp_validity_cap_ms: 1,
            plant_validity_cap_ms: 1,
            nominal_update_ms: 1,
            tracking_error_mm: 0,
            uncertainty_margin_mm: 0,
            max_position_uncertainty_mm: 1,
            geofence: GeofenceBoxV1 {
                min_mm: [-1; 3],
                max_mm: [1; 3],
            },
            duty_window_ms: 1,
            max_active_ms_in_window: 1,
            motion_envelope_v2: Some(haldir_policy_native::LocallyAdmittedMotionEnvelopeV2 {
                local_ned_frame_id: BoundedAscii::new("map").unwrap(),
                max_linear_accel_mm_s2: 1,
                max_linear_slew_mm_s2: 1,
                max_continuous_motion_ms: 1,
                minimum_hold_between_bursts_ms: 0,
                plant_mode_rules: Vec::new(),
            }),
            phase_rules: Vec::new(),
        };
        let policy_snapshot_digest = policy.canonical_digest().unwrap();

        GateConfigTemplate {
            gate_id,
            realm: AsciiId::new("range-a").unwrap(),
            vehicle_id: VehicleId::new("uav-1").unwrap(),
            trust,
            revocations: RevocationSnapshot::new(),
            admission: AdmissionSnapshot::new(),
            policy,
            policy_snapshot_digest,
            session: NcpSessionIdentityV1 {
                session_id: AsciiId::new("session-1").unwrap(),
                generation: CanonicalUuidV4String::from_random_bytes([1; 16]),
            },
            runtime_profile: GateRuntimeProfile::InProcessReference,
            ncp_adapter: SelectedNcpCommandAdapter::modeled_p0(),
            publication: PlantPublicationAuthorityStateV1::AclExclusiveV1(AclExclusiveEvidenceV1 {
                gate_transport_principal: PrincipalId::new("gate-transport").unwrap(),
                final_route_digest: DigestV1::compute(
                    DigestDomain::TransportKey,
                    b"range-a/session/session-1/command",
                ),
                certificate_fingerprint: digest(b"certificate"),
                acl_policy_digest: digest(b"acl"),
                verified_at_mono_ns: 1,
            }),
            local_cap_ms: NonZeroU32::new(1_000).unwrap(),
            gate_signer,
            gate_signer_kid,
        }
    }

    fn state(directory: &TestDirectory, mode: StateOpenMode) -> StartupStateConfig {
        StartupStateConfig {
            open_mode: mode,
            profile: StartupProfile::DevelopmentLocal,
            instance_lock_path: directory.0.join("gate.lock"),
            binding: SnapshotBinding::new(StoreId::new([1; 16]), b"gate-1"),
            max_payload_bytes: 4096,
        }
    }

    fn key() -> StorageMacKey {
        StorageMacKey::new([7; 32]).expect("nonzero test storage key")
    }

    fn deployment_authority_spec(
        role: DeploymentArtifactIdV1,
        gate_configuration: &GateConfigurationArtifactV1,
    ) -> (AuthoritySnapshotKindV1, KeyRole, u8, &'static str, DigestV1) {
        match role {
            DeploymentArtifactIdV1::TrustManifest => (
                AuthoritySnapshotKindV1::Trust,
                KeyRole::TrustAuthority,
                51,
                "trust-authority-a",
                gate_configuration.trust_snapshot_digest,
            ),
            DeploymentArtifactIdV1::AdmissionSnapshot => (
                AuthoritySnapshotKindV1::Admission,
                KeyRole::AdmissionAuthority,
                52,
                "admission-authority-a",
                gate_configuration.admission_snapshot_digest,
            ),
            DeploymentArtifactIdV1::RevocationSnapshot => (
                AuthoritySnapshotKindV1::Revocation,
                KeyRole::RevocationAuthority,
                53,
                "revocation-authority-a",
                gate_configuration.revocation_snapshot_digest,
            ),
            DeploymentArtifactIdV1::PolicySnapshot => (
                AuthoritySnapshotKindV1::Policy,
                KeyRole::PolicyAuthority,
                54,
                "policy-authority-a",
                gate_configuration.policy_snapshot_digest,
            ),
            _ => panic!("artifact role is not an authority approval"),
        }
    }

    fn deployment_artifact_bytes(
        role: DeploymentArtifactIdV1,
        gate_configuration: &GateConfigurationArtifactV1,
        gate_configuration_bytes: &[u8],
        deployment_id: &str,
    ) -> Vec<u8> {
        match role {
            DeploymentArtifactIdV1::GateConfiguration => gate_configuration_bytes.to_vec(),
            DeploymentArtifactIdV1::NcpCompatibility => {
                haldir_ncp08::pinned_ncp_compatibility_artifact_bytes().unwrap()
            }
            DeploymentArtifactIdV1::TrustManifest
            | DeploymentArtifactIdV1::AdmissionSnapshot
            | DeploymentArtifactIdV1::RevocationSnapshot
            | DeploymentArtifactIdV1::PolicySnapshot => {
                let (snapshot_kind, _, seed, issuer_id, snapshot_digest) =
                    deployment_authority_spec(role, gate_configuration);
                let approval = AuthoritySnapshotApprovalV1 {
                    schema_major: 1,
                    schema_minor: 0,
                    snapshot_kind,
                    issuer_id: AsciiId::new(issuer_id).unwrap(),
                    deployment_id: AsciiId::new(deployment_id).unwrap(),
                    deployment_revision: DeploymentRevision::new(NonZeroU64::new(7).unwrap()),
                    gate_id: gate_configuration.gate_id.clone(),
                    realm: gate_configuration.realm.clone(),
                    vehicle_id: gate_configuration.vehicle_id.clone(),
                    snapshot_digest,
                };
                let signer = SigningKey::from_seed([seed; 32]).expect("nonzero test seed");
                sign_message(
                    &approval,
                    AuthoritySnapshotApprovalV1::KIND,
                    1,
                    &KeyId::new(vec![seed, 0xa5]).unwrap(),
                    &signer,
                )
            }
            _ => vec![u8::try_from(role.tag()).unwrap(); usize::try_from(role.tag()).unwrap() + 1],
        }
    }

    fn deployment_artifact_logical_id(role: DeploymentArtifactIdV1) -> AsciiId<64> {
        AsciiId::new(&format!("artifact-{}", role.tag())).unwrap()
    }

    fn validated_deployment_package(
        configured: &GateConfigTemplate,
        profile_class: DeploymentClassV1,
        state_store_id: [u8; 16],
    ) -> AuthorityValidatedDeploymentPackage {
        validated_deployment_package_named(
            configured,
            profile_class,
            state_store_id,
            "deployment-a",
        )
    }

    fn validated_deployment_package_named(
        configured: &GateConfigTemplate,
        profile_class: DeploymentClassV1,
        state_store_id: [u8; 16],
        deployment_id: &str,
    ) -> AuthorityValidatedDeploymentPackage {
        let runtime_profile = match configured.runtime_profile {
            GateRuntimeProfile::InProcessReference => {
                DeploymentRuntimeProfileV1::InProcessReference
            }
            GateRuntimeProfile::DeclaredLiveZenoh => DeploymentRuntimeProfileV1::DeclaredLiveZenoh,
        };
        let ncp_wire_profile = match configured.ncp_adapter.wire_profile() {
            NcpCommandWireProfile::ModeledP0 => DeploymentNcpWireProfileV1::ModeledP0,
            NcpCommandWireProfile::ExactNcpV0_8Json => DeploymentNcpWireProfileV1::ExactNcpV0_8Json,
            _ => panic!("test helper does not support an unknown NCP wire profile"),
        };
        let journal_id = JournalId::new([2; 16]).unwrap();
        let PlantPublicationAuthorityStateV1::AclExclusiveV1(publication) = &configured.publication
        else {
            panic!("test helper requires ACL-only publication evidence")
        };
        let gate_configuration = GateConfigurationArtifactV1 {
            schema_major: 1,
            schema_minor: 0,
            gate_id: configured.gate_id.clone(),
            realm: configured.realm.clone(),
            vehicle_id: configured.vehicle_id.clone(),
            profile_class,
            runtime_profile,
            ncp_wire_profile,
            state_store_id,
            journal_id,
            trust_snapshot_digest: configured.trust.canonical_digest(),
            revocation_snapshot_digest: configured.revocations.canonical_digest(),
            admission_snapshot_digest: configured.admission.canonical_digest(),
            policy_snapshot_digest: configured.policy_snapshot_digest,
            session: configured.session.clone(),
            publication: AclPublicationBindingV1 {
                gate_transport_principal: publication.gate_transport_principal.clone(),
                final_route_digest: publication.final_route_digest,
                certificate_fingerprint: publication.certificate_fingerprint,
                acl_policy_digest: publication.acl_policy_digest,
            },
            local_cap_ms: configured.local_cap_ms,
            gate_signer_kid: configured.gate_signer_kid.clone(),
            gate_signer_public_key: configured.gate_signer.verifying_key().to_bytes(),
        };
        let gate_configuration_bytes = to_canonical_bytes(&gate_configuration);
        let artifacts = DeploymentArtifactIdV1::ALL
            .into_iter()
            .map(|role| {
                let bytes = deployment_artifact_bytes(
                    role,
                    &gate_configuration,
                    &gate_configuration_bytes,
                    deployment_id,
                );
                DeploymentArtifactRefV1 {
                    role,
                    logical_id: deployment_artifact_logical_id(role),
                    digest: DigestV1::compute(DigestDomain::DeploymentArtifact, &bytes),
                    size_bytes: NonZeroU64::new(u64::try_from(bytes.len()).unwrap()).unwrap(),
                }
            })
            .collect();
        let package = DeploymentPackageV1 {
            schema_major: 1,
            schema_minor: 0,
            deployment_authority_id: AsciiId::new("deployment-authority-a").unwrap(),
            deployment_id: AsciiId::new(deployment_id).unwrap(),
            deployment_revision: DeploymentRevision::new(NonZeroU64::new(7).unwrap()),
            profile_class,
            gate_id: configured.gate_id.clone(),
            realm: configured.realm.clone(),
            vehicle_id: configured.vehicle_id.clone(),
            runtime_profile,
            ncp_wire_profile,
            state_store_id,
            journal_id,
            artifacts: BoundedVec::from_vec(artifacts).unwrap(),
        };
        let signer = SigningKey::from_seed([9; 32]).expect("nonzero test seed");
        let signer_kid = KeyId::new(vec![9, 0xa5]).unwrap();
        let mut trust = TrustStore::new();
        trust
            .insert(KeyRecord {
                kid: signer_kid.clone(),
                role: KeyRole::DeploymentAuthority,
                verifying_key: signer.verifying_key(),
                subject: KeySubject::new("deployment-authority-a").unwrap(),
                class: if profile_class == DeploymentClassV1::Development {
                    KeyClass::Development
                } else {
                    KeyClass::Assurance
                },
            })
            .unwrap();
        for role in [
            DeploymentArtifactIdV1::TrustManifest,
            DeploymentArtifactIdV1::AdmissionSnapshot,
            DeploymentArtifactIdV1::RevocationSnapshot,
            DeploymentArtifactIdV1::PolicySnapshot,
        ] {
            let (_, key_role, seed, subject, _) =
                deployment_authority_spec(role, &gate_configuration);
            let authority_signer = SigningKey::from_seed([seed; 32]).expect("nonzero test seed");
            trust
                .insert(KeyRecord {
                    kid: KeyId::new(vec![seed, 0xa5]).unwrap(),
                    role: key_role,
                    verifying_key: authority_signer.verifying_key(),
                    subject: KeySubject::new(subject).unwrap(),
                    class: if profile_class == DeploymentClassV1::Development {
                        KeyClass::Development
                    } else {
                        KeyClass::Assurance
                    },
                })
                .unwrap();
        }
        let envelope = sign_message(
            &package,
            DeploymentPackageV1::KIND,
            DeploymentPackageV1::SCHEMA_MAJOR,
            &signer_kid,
            &signer,
        );
        let policy = DeploymentAcceptancePolicy::new(
            DeploymentIdentityExpectation::new(
                AsciiId::new("deployment-authority-a").unwrap(),
                configured.gate_id.clone(),
                configured.realm.clone(),
                configured.vehicle_id.clone(),
            ),
            DeploymentProfileRequirement::new(profile_class, runtime_profile, ncp_wire_profile),
            AuthorityApprovalPolicy::new(
                AsciiId::new("trust-authority-a").unwrap(),
                AsciiId::new("admission-authority-a").unwrap(),
                AsciiId::new("revocation-authority-a").unwrap(),
                AsciiId::new("policy-authority-a").unwrap(),
            ),
        );
        let verified =
            verify_deployment_package(&envelope, &policy, &trust, &RevocationSnapshot::new())
                .unwrap();
        let inputs = DeploymentArtifactSet::from_inputs(
            DeploymentArtifactIdV1::ALL.into_iter().map(|role| {
                DeploymentArtifactInput::new(
                    role,
                    deployment_artifact_logical_id(role),
                    deployment_artifact_bytes(
                        role,
                        &gate_configuration,
                        &gate_configuration_bytes,
                        deployment_id,
                    ),
                )
            }),
        )
        .unwrap();
        let gate_configuration_validated = verified
            .resolve_artifacts(inputs, ArtifactLimits::new(4096, 32 * 1024).unwrap())
            .unwrap()
            .validate_ncp_compatibility()
            .unwrap()
            .validate_gate_configuration()
            .unwrap();
        gate_configuration_validated
            .validate_authority_approvals()
            .unwrap()
    }

    fn deployment_fixture() -> (AuthorityValidatedDeploymentPackage, GateConfigTemplate) {
        let configured = template();
        let package =
            validated_deployment_package(&configured, DeploymentClassV1::Development, [1; 16]);
        (package, configured)
    }

    fn assert_configuration_binding_rejected_before_effects(
        package: AuthorityValidatedDeploymentPackage,
        configured: GateConfigTemplate,
        expected: DeploymentGateBindingError,
    ) {
        let directory = TestDirectory::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let mut entropy = DeterministicEntropy::new(1);
        let result = start_deployment_with_backends(
            package,
            configured,
            state(&directory, StateOpenMode::ProvisionNew),
            CountingStorage(calls.clone()),
            CountingAnchor(calls.clone()),
            key(),
            &mut entropy,
        );

        match result {
            Err(DurableGateStartupError::DeploymentBinding(actual)) => {
                assert_eq!(actual, expected);
            }
            Ok(_) => panic!("mismatched signed Gate configuration authorized startup"),
            Err(other) => panic!("unexpected startup failure: {other}"),
        }
        assert_eq!(entropy.calls, 0);
        assert_eq!(calls.load(Ordering::Relaxed), 0);
        assert!(!directory.absent_child("gate.lock").exists());
    }

    fn journal_limits() -> JournalLimits {
        JournalLimits::new(JournalBounds::new(4096, 4, 2048).unwrap(), 8, 64 * 1024).unwrap()
    }

    const fn capture_limits() -> RecoveryCaptureLimits {
        RecoveryCaptureLimits::new(32, 64 * 1024)
    }

    fn journal_config(
        directory: impl Into<PathBuf>,
        created_mono_ns: u64,
        limits: JournalLimits,
    ) -> PublicationJournalStartupConfig {
        journal_config_with_id(
            directory,
            JournalId::new([2; 16]).unwrap(),
            created_mono_ns,
            limits,
        )
    }

    fn journal_config_with_id(
        directory: impl Into<PathBuf>,
        journal_id: JournalId,
        created_mono_ns: u64,
        limits: JournalLimits,
    ) -> PublicationJournalStartupConfig {
        PublicationJournalStartupConfig::new(
            directory,
            journal_id,
            created_mono_ns,
            limits,
            capture_limits(),
            NonZeroUsize::new(32 * 1024).unwrap(),
            NonZeroUsize::new(32).unwrap(),
        )
        .unwrap()
    }

    fn prepared_receipt(gate_boot_id: GateBootId) -> DecisionReceiptV1 {
        DecisionReceiptV1 {
            decision_id: DecisionId::new([0x44; 16]),
            gate_id: GateId::new("gate-1").unwrap(),
            gate_boot_id,
            vehicle_id: VehicleId::new("uav-1").unwrap(),
            mission_id: Some(MissionId::new("mission-1").unwrap()),
            ncp_session: NcpSessionIdentityV1 {
                session_id: AsciiId::new("session-1").unwrap(),
                generation: CanonicalUuidV4String::from_random_bytes([1; 16]),
            },
            received_key_digest: DigestV1::compute(DigestDomain::TransportKey, b"key"),
            raw_envelope_digest: DigestV1::compute(DigestDomain::RawEnvelope, b"intent"),
            payload_digest: Some(DigestV1::compute(DigestDomain::Payload, b"intent-payload")),
            semantic_intent_digest: Some(DigestV1::compute(
                DigestDomain::SemanticIntent,
                b"intent-semantics",
            )),
            controller_id: Some(ControllerId::new("controller-1").unwrap()),
            controller_intent_position: Some(HaldirIntentPositionV1 {
                epoch: IntentEpoch::new([6; 16]),
                seq: IntentSeq::new(NonZeroU64::new(1).unwrap()),
            }),
            mission_lease_id: Some(MissionLeaseId::new([7; 16])),
            admission_digest: Some(DigestV1::compute(DigestDomain::Admission, b"admission")),
            source: Some(NcpSourceRefV1 {
                source_key: BoundedAscii::new("range-a/session/session-1/sensor/pose").unwrap(),
                stream_epoch: CanonicalUuidV4String::from_random_bytes([8; 16]),
                stream_seq: SourceSeq::new(NonZeroU64::new(1).unwrap()),
            }),
            state_snapshot_digest: Some(DigestV1::compute(DigestDomain::StateSnapshot, b"state")),
            policy_snapshot_digest: DigestV1::compute(DigestDomain::PolicySnapshot, b"policy"),
            decision: DecisionOutcomeV1::Allow,
            reason_codes: BoundedVec::from_vec(vec![DecisionReasonCodeV1::AllowPrepared]).unwrap(),
            effective_validity_ms: Some(10),
            gate_output_stream: Some(NcpStreamPositionV1 {
                epoch: GateOutputEpoch::new(CanonicalUuidV4String::from_random_bytes([5; 16])),
                seq: OutputSeq::new(NonZeroU64::new(1).unwrap()),
            }),
            output_frame_digest: Some(DigestV1::compute(DigestDomain::OutputFrame, b"frame")),
            transformation_relation: Some(TransformationRelationV1::FixedPointToNcpFloatV1),
            received_mono_ns: 10,
            decided_mono_ns: 11,
            publish_stage: PublishStageV1::OutputPrepared,
        }
    }

    fn called_event(
        receipt: &DecisionReceiptV1,
        prepared_envelope: &[u8],
    ) -> PublicationStageEventV1 {
        let prepared_digest = DigestV1::compute(DigestDomain::RawEnvelope, prepared_envelope);
        PublicationStageEventV1 {
            schema_major: PublicationStageEventV1::SCHEMA_MAJOR,
            schema_minor: 0,
            decision_id: receipt.decision_id,
            gate_id: receipt.gate_id.clone(),
            decision_gate_boot_id: receipt.gate_boot_id,
            producer_gate_boot_id: receipt.gate_boot_id,
            vehicle_id: receipt.vehicle_id.clone(),
            ncp_session: receipt.ncp_session.clone(),
            gate_output_stream: receipt.gate_output_stream.clone().unwrap(),
            output_frame_digest: receipt.output_frame_digest.unwrap(),
            effective_validity_ms: NonZeroU32::new(receipt.effective_validity_ms.unwrap()).unwrap(),
            prepared_receipt_envelope_digest: prepared_digest,
            predecessor_envelope_digest: prepared_digest,
            stage: PublishStageV1::PublishCalled,
            observed_mono_ns: 12,
        }
    }

    #[test]
    fn open_existing_never_provisions_missing_state() {
        let directory = TestDirectory::new();
        let storage = MemoryStorage::default();
        let anchor = MemoryAnchor::default();
        let mut entropy = DeterministicEntropy::new(1);

        let result = start_with_backends(
            template(),
            state(&directory, StateOpenMode::OpenExisting),
            storage.clone(),
            anchor.clone(),
            key(),
            &mut entropy,
        );

        assert!(matches!(
            result,
            Err(DurableGateStartupError::Durable(
                DurableAntiRollbackError::Durable(DurableError::Missing)
            ))
        ));
        assert!(storage.0.lock().unwrap().is_none());
        assert!(anchor.head.lock().unwrap().is_none());
        assert_eq!(entropy.calls, 1);
    }

    #[test]
    fn declared_live_modeled_adapter_is_rejected_before_entropy_lock_or_backend_access() {
        let directory = TestDirectory::new();
        let backend_calls = Arc::new(AtomicUsize::new(0));
        let storage = CountingStorage(Arc::clone(&backend_calls));
        let anchor = CountingAnchor(Arc::clone(&backend_calls));
        let mut configured = template();
        configured.runtime_profile = GateRuntimeProfile::DeclaredLiveZenoh;
        let mut entropy = DeterministicEntropy::new(1);

        let result = start_with_backends(
            configured,
            state(&directory, StateOpenMode::ProvisionNew),
            storage,
            anchor,
            key(),
            &mut entropy,
        );

        assert!(matches!(
            result,
            Err(DurableGateStartupError::NcpWireProfileMismatch {
                runtime_profile: GateRuntimeProfile::DeclaredLiveZenoh,
                required: NcpCommandWireProfile::ExactNcpV0_8Json,
                actual: NcpCommandWireProfile::ModeledP0,
            })
        ));
        assert_eq!(entropy.calls, 0);
        assert_eq!(backend_calls.load(Ordering::Relaxed), 0);
        assert!(!directory.0.join("gate.lock").exists());
    }

    #[cfg(all(feature = "real-ncp", not(feature = "live-zenoh")))]
    #[test]
    fn declared_live_exact_adapter_rejects_when_live_support_is_not_compiled() {
        let directory = TestDirectory::new();
        let backend_calls = Arc::new(AtomicUsize::new(0));
        let storage = CountingStorage(Arc::clone(&backend_calls));
        let anchor = CountingAnchor(Arc::clone(&backend_calls));
        let mut configured = template();
        configured.runtime_profile = GateRuntimeProfile::DeclaredLiveZenoh;
        configured.ncp_adapter = SelectedNcpCommandAdapter::exact_ncp_v0_8_json();
        let mut entropy = DeterministicEntropy::new(1);

        let result = start_with_backends(
            configured,
            state(&directory, StateOpenMode::ProvisionNew),
            storage,
            anchor,
            key(),
            &mut entropy,
        );

        assert!(matches!(
            result,
            Err(DurableGateStartupError::LiveZenohSupportNotCompiled)
        ));
        assert_eq!(entropy.calls, 0);
        assert_eq!(backend_calls.load(Ordering::Relaxed), 0);
        assert!(!directory.0.join("gate.lock").exists());
    }

    #[cfg(feature = "live-zenoh")]
    #[test]
    fn declared_live_acl_evidence_must_bind_the_derived_final_route_before_side_effects() {
        let directory = TestDirectory::new();
        let backend_calls = Arc::new(AtomicUsize::new(0));
        let storage = CountingStorage(Arc::clone(&backend_calls));
        let anchor = CountingAnchor(Arc::clone(&backend_calls));
        let mut configured = template();
        configured.runtime_profile = GateRuntimeProfile::DeclaredLiveZenoh;
        configured.ncp_adapter = SelectedNcpCommandAdapter::exact_ncp_v0_8_json();
        let PlantPublicationAuthorityStateV1::AclExclusiveV1(evidence) =
            &mut configured.publication
        else {
            panic!("template must carry ACL evidence");
        };
        evidence.final_route_digest =
            DigestV1::compute(DigestDomain::TransportKey, b"range-a/session/other/command");
        let mut entropy = DeterministicEntropy::new(1);

        let result = start_with_backends(
            configured,
            state(&directory, StateOpenMode::ProvisionNew),
            storage,
            anchor,
            key(),
            &mut entropy,
        );

        assert!(matches!(
            result,
            Err(DurableGateStartupError::PublicationRouteBinding)
        ));
        assert_eq!(entropy.calls, 0);
        assert_eq!(backend_calls.load(Ordering::Relaxed), 0);
        assert!(!directory.0.join("gate.lock").exists());
    }

    #[cfg(feature = "live-zenoh")]
    #[test]
    fn declared_live_exact_startup_capability_constructs_the_live_coordinator() {
        let directory = TestDirectory::new();
        let mut configured = template();
        configured.runtime_profile = GateRuntimeProfile::DeclaredLiveZenoh;
        configured.ncp_adapter = SelectedNcpCommandAdapter::exact_ncp_v0_8_json();
        let mut entropy = DeterministicEntropy::new(1);

        let running = start_with_backends(
            configured,
            state(&directory, StateOpenMode::ProvisionNew),
            MemoryStorage::default(),
            MemoryAnchor::default(),
            key(),
            &mut entropy,
        )
        .unwrap();

        assert_eq!(
            running.actor().ncp_command_wire_profile(),
            NcpCommandWireProfile::ExactNcpV0_8Json
        );
        assert_eq!(
            running.report().runtime_profile,
            GateRuntimeProfile::DeclaredLiveZenoh
        );
        assert!(running.declared_live_zenoh.is_some());

        let bound = running
            .provision_publication_journal(journal_config(
                directory.0.join("journal"),
                10,
                journal_limits(),
            ))
            .unwrap();
        let coordinator = publication_coordinator::PublicationCoordinator::<
            _,
            publication_coordinator::DeclaredLiveZenohPublication,
        >::new_declared_live(bound, FixedCoordinatorClock)
        .unwrap();
        let (coordinator, issued) = coordinator
            .issue_live_activation_challenge(super::live_service::LIVE_ACTIVATION_CHALLENGE_TTL_MS)
            .unwrap();
        let expected_challenge_nonce = ChallengeNonce::new(core::array::from_fn(|index| {
            let offset =
                u8::try_from(BOOT_ENTROPY_BYTES + OUTPUT_EPOCH_ENTROPY_BYTES + index).unwrap();
            1_u8.wrapping_add(offset)
        }));
        assert_eq!(
            coordinator.actor().ncp_command_wire_profile(),
            NcpCommandWireProfile::ExactNcpV0_8Json
        );
        assert_eq!(issued.challenge().challenge_nonce, expected_challenge_nonce);
        assert_eq!(entropy.calls, 1);
    }

    #[cfg(feature = "live-zenoh")]
    #[test]
    fn exact_reference_startup_cannot_construct_the_live_coordinator() {
        let directory = TestDirectory::new();
        let mut configured = template();
        configured.ncp_adapter = SelectedNcpCommandAdapter::exact_ncp_v0_8_json();
        let running = start_with_backends(
            configured,
            state(&directory, StateOpenMode::ProvisionNew),
            MemoryStorage::default(),
            MemoryAnchor::default(),
            key(),
            &mut DeterministicEntropy::new(1),
        )
        .unwrap();
        assert!(running.declared_live_zenoh.is_none());
        let bound = running
            .provision_publication_journal(journal_config(
                directory.0.join("journal"),
                10,
                journal_limits(),
            ))
            .unwrap();

        let error = match publication_coordinator::PublicationCoordinator::<
            _,
            publication_coordinator::DeclaredLiveZenohPublication,
        >::new_declared_live(bound, RejectClockSampling)
        {
            Err(error) => error,
            Ok(_) => panic!("an exact reference startup minted a live coordinator"),
        };
        assert_eq!(
            error,
            publication_coordinator::CoordinatorFatal::RuntimeProfileMismatch {
                required: GateRuntimeProfile::DeclaredLiveZenoh,
                actual: GateRuntimeProfile::InProcessReference,
            }
        );
    }

    #[cfg(feature = "live-zenoh")]
    #[test]
    fn copied_report_value_cannot_manufacture_the_live_startup_capability() {
        let directory = TestDirectory::new();
        let mut configured = template();
        configured.ncp_adapter = SelectedNcpCommandAdapter::exact_ncp_v0_8_json();
        let mut running = start_with_backends(
            configured,
            state(&directory, StateOpenMode::ProvisionNew),
            MemoryStorage::default(),
            MemoryAnchor::default(),
            key(),
            &mut DeterministicEntropy::new(1),
        )
        .unwrap();
        assert!(running.declared_live_zenoh.is_none());
        running.report.runtime_profile = GateRuntimeProfile::DeclaredLiveZenoh;
        let bound = running
            .provision_publication_journal(journal_config(
                directory.0.join("journal"),
                10,
                journal_limits(),
            ))
            .unwrap();

        let error = match publication_coordinator::PublicationCoordinator::<
            _,
            publication_coordinator::DeclaredLiveZenohPublication,
        >::new_declared_live(bound, RejectClockSampling)
        {
            Err(error) => error,
            Ok(_) => panic!("forged observability data minted a live coordinator"),
        };
        assert_eq!(
            error,
            publication_coordinator::CoordinatorFatal::DeclaredLiveStartupCapabilityUnavailable
        );
    }

    #[cfg(feature = "live-zenoh")]
    #[test]
    fn forged_declared_report_with_modeled_actor_fails_the_wire_cross_check() {
        let directory = TestDirectory::new();
        let mut running = start_with_backends(
            template(),
            state(&directory, StateOpenMode::ProvisionNew),
            MemoryStorage::default(),
            MemoryAnchor::default(),
            key(),
            &mut DeterministicEntropy::new(1),
        )
        .unwrap();
        assert!(running.declared_live_zenoh.is_none());
        running.report.runtime_profile = GateRuntimeProfile::DeclaredLiveZenoh;
        let bound = running
            .provision_publication_journal(journal_config(
                directory.0.join("journal"),
                10,
                journal_limits(),
            ))
            .unwrap();

        let error = match publication_coordinator::PublicationCoordinator::<
            _,
            publication_coordinator::DeclaredLiveZenohPublication,
        >::new_declared_live(bound, RejectClockSampling)
        {
            Err(error) => error,
            Ok(_) => panic!("a modeled actor minted a live coordinator"),
        };
        assert_eq!(
            error,
            publication_coordinator::CoordinatorFatal::NcpWireProfileMismatch {
                required: NcpCommandWireProfile::ExactNcpV0_8Json,
                actual: NcpCommandWireProfile::ModeledP0,
            }
        );
    }

    #[cfg(feature = "real-ncp")]
    #[test]
    fn explicit_exact_adapter_selection_survives_durable_startup() {
        let directory = TestDirectory::new();
        let mut configured = template();
        configured.ncp_adapter = SelectedNcpCommandAdapter::exact_ncp_v0_8_json();
        let mut entropy = DeterministicEntropy::new(1);

        let running = start_with_backends(
            configured,
            state(&directory, StateOpenMode::ProvisionNew),
            MemoryStorage::default(),
            MemoryAnchor::default(),
            key(),
            &mut entropy,
        )
        .unwrap();

        assert_eq!(
            running.actor().ncp_command_wire_profile(),
            NcpCommandWireProfile::ExactNcpV0_8Json
        );
        assert_eq!(
            running.report().runtime_profile,
            GateRuntimeProfile::InProcessReference
        );
    }

    #[test]
    fn explicit_provision_then_open_advances_boot_and_output_namespaces() {
        let directory = TestDirectory::new();
        let storage = MemoryStorage::default();
        let anchor = MemoryAnchor::default();
        let mut first_entropy = DeterministicEntropy::new(1);
        let first = start_with_backends(
            template(),
            state(&directory, StateOpenMode::ProvisionNew),
            storage.clone(),
            anchor.clone(),
            key(),
            &mut first_entropy,
        )
        .unwrap();
        let first_report = first.report();
        assert!(first_report.provisioned);
        assert_eq!(first_report.recovery, None);
        assert_eq!(first_report.boot_commit.generation, 2);
        assert_eq!(
            first_report.runtime_profile,
            GateRuntimeProfile::InProcessReference
        );
        assert_eq!(
            first.actor().ncp_command_wire_profile(),
            NcpCommandWireProfile::ModeledP0
        );
        drop(first);

        let mut second_entropy = DeterministicEntropy::new(91);
        let second = start_with_backends(
            template(),
            state(&directory, StateOpenMode::OpenExisting),
            storage,
            anchor,
            key(),
            &mut second_entropy,
        )
        .unwrap();
        let second_report = second.report();

        assert!(!second_report.provisioned);
        assert_eq!(second_report.recovery, Some(RecoveryStatus::Clean));
        assert_eq!(second_report.boot_commit.generation, 3);
        assert_ne!(first_report.gate_boot_id, second_report.gate_boot_id);
        assert_ne!(first_report.output_epoch, second_report.output_epoch);
    }

    #[test]
    fn publication_journal_config_rejects_trace_underprovisioning() {
        let directory = TestDirectory::new();

        assert_eq!(
            PublicationJournalStartupConfig::new(
                directory.0.join("journal"),
                JournalId::new([2; 16]).unwrap(),
                10,
                journal_limits(),
                RecoveryCaptureLimits::new(8, 64 * 1024),
                NonZeroUsize::new(32 * 1024).unwrap(),
                NonZeroUsize::new(7).unwrap(),
            ),
            Err(PublicationJournalConfigError::TraceCapacityTooSmall)
        );
    }

    #[cfg(unix)]
    #[test]
    fn running_gate_provisions_and_retains_exact_current_journal_binding() {
        let directory = TestDirectory::new();
        let storage = MemoryStorage::default();
        let anchor = MemoryAnchor::default();
        let running = start_with_backends(
            template(),
            state(&directory, StateOpenMode::ProvisionNew),
            storage,
            anchor,
            key(),
            &mut DeterministicEntropy::new(1),
        )
        .unwrap();
        let committed_boot = running.report().gate_boot_id;

        let bound = running
            .provision_publication_journal(journal_config(
                directory.0.join("journal"),
                10,
                journal_limits(),
            ))
            .unwrap();
        let active = bound.active_journal_identity().unwrap();

        assert_eq!(active.gate_id, *bound.actor().gate_id());
        assert_eq!(active.gate_boot_id, committed_boot);
        assert_eq!(active.segment_sequence.get(), 1);
        assert_eq!(bound.recovered_publication().replayed_segments(), 0);
        assert_eq!(
            bound
                .journal_recovery_report()
                .active_sequence
                .map(NonZeroU64::get),
            Some(1)
        );
        assert!(
            !bound
                .recovered_publication()
                .contains_recovered_boot(committed_boot)
        );
    }

    #[cfg(unix)]
    #[test]
    fn restart_fuses_prior_empty_tail_and_fresh_committed_boot() {
        let directory = TestDirectory::new();
        let storage = MemoryStorage::default();
        let anchor = MemoryAnchor::default();
        let first = start_with_backends(
            template(),
            state(&directory, StateOpenMode::ProvisionNew),
            storage.clone(),
            anchor.clone(),
            key(),
            &mut DeterministicEntropy::new(1),
        )
        .unwrap();
        let first_boot = first.report().gate_boot_id;
        let first = first
            .provision_publication_journal(journal_config(
                directory.0.join("journal"),
                10,
                journal_limits(),
            ))
            .unwrap();
        drop(first);

        let second = start_with_backends(
            template(),
            state(&directory, StateOpenMode::OpenExisting),
            storage,
            anchor,
            key(),
            &mut DeterministicEntropy::new(91),
        )
        .unwrap();
        let second_boot = second.report().gate_boot_id;
        let second = second
            .open_publication_journal(
                journal_config(directory.0.join("journal"), 20, journal_limits()),
                None,
            )
            .unwrap();

        assert_eq!(
            second
                .active_journal_identity()
                .unwrap()
                .segment_sequence
                .get(),
            2
        );
        assert_eq!(
            second.active_journal_identity().unwrap().gate_boot_id,
            second_boot
        );
        assert!(
            second
                .recovered_publication()
                .contains_recovered_boot(first_boot)
        );
        assert!(
            !second
                .recovered_publication()
                .contains_recovered_boot(second_boot)
        );
        assert!(second.journal_recovery_report().closed_active_tail);
        assert_eq!(second.journal_recovery_report().discovered_segments, 1);
        assert_eq!(second.recovery_unknown_events(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn restart_closes_dangling_called_under_actual_committed_boot_before_exposure() {
        let directory = TestDirectory::new();
        let storage = MemoryStorage::default();
        let anchor = MemoryAnchor::default();
        let first = start_with_backends(
            template(),
            state(&directory, StateOpenMode::ProvisionNew),
            storage.clone(),
            anchor.clone(),
            key(),
            &mut DeterministicEntropy::new(1),
        )
        .unwrap();
        let first_boot = first.report().gate_boot_id;
        let receipt = prepared_receipt(first_boot);
        let signing_kid = KeyId::new(vec![3]).unwrap();
        let signing_key = SigningKey::from_seed([3; 32]).expect("nonzero test seed");
        let receipt_envelope = sign_message(
            &receipt,
            DecisionReceiptV1::KIND,
            DecisionReceiptV1::SCHEMA_MAJOR,
            &signing_kid,
            &signing_key,
        );
        let called = called_event(&receipt, &receipt_envelope);
        let called_envelope = sign_message(
            &called,
            PublicationStageEventV1::KIND,
            PublicationStageEventV1::SCHEMA_MAJOR,
            &signing_kid,
            &signing_key,
        );
        let journal_path = directory.0.join("journal");
        let (mut journal, _) = {
            let signer = first.actor.journal_signer();
            EvidenceJournalManager::provision_new(
                &journal_path,
                JournalOpenOptions::new(
                    first.actor.gate_id().clone(),
                    JournalId::new([2; 16]).unwrap(),
                    first_boot,
                    10,
                    journal_limits(),
                ),
                &signer,
                first
                    .actor
                    .journal_verifier(NonZeroUsize::new(32 * 1024).unwrap()),
            )
            .unwrap()
        };
        {
            let signer = first.actor.journal_signer();
            journal.append(&receipt_envelope, 11, &signer).unwrap();
            journal.append(&called_envelope, 12, &signer).unwrap();
        }
        drop(journal);
        drop(first);

        let second = start_with_backends(
            template(),
            state(&directory, StateOpenMode::OpenExisting),
            storage,
            anchor,
            key(),
            &mut DeterministicEntropy::new(91),
        )
        .unwrap();
        let second_boot = second.report().gate_boot_id;
        let bound = second
            .open_publication_journal(journal_config(&journal_path, 20, journal_limits()), None)
            .unwrap();

        assert_eq!(bound.recovery_unknown_events(), 1);
        assert_eq!(
            bound
                .recovered_publication()
                .state(first_boot, receipt.decision_id),
            Some(PublicationTraceState::UnknownAfterPublish)
        );
        assert_eq!(
            bound.active_journal_identity().unwrap().gate_boot_id,
            second_boot
        );
    }

    #[cfg(unix)]
    #[test]
    fn quiesced_journal_cannot_expose_a_bound_running_gate() {
        let directory = TestDirectory::new();
        let running = start_with_backends(
            template(),
            state(&directory, StateOpenMode::ProvisionNew),
            MemoryStorage::default(),
            MemoryAnchor::default(),
            key(),
            &mut DeterministicEntropy::new(1),
        )
        .unwrap();
        let unusable_limits =
            JournalLimits::new(JournalBounds::new(4096, 4, 2048).unwrap(), 1, 1).unwrap();

        let journal = directory.0.join("journal");
        assert!(matches!(
            running.provision_publication_journal(journal_config(&journal, 10, unusable_limits)),
            Err(JournalBindingError::Journal(GateJournalOpenError::Journal(
                JournalManagerError::Quiesced
            )))
        ));
        assert!(!journal.exists());
    }

    #[cfg(unix)]
    #[test]
    fn caller_selected_journal_boot_cannot_bind_to_running_authority() {
        let directory = TestDirectory::new();
        let running = start_with_backends(
            template(),
            state(&directory, StateOpenMode::ProvisionNew),
            MemoryStorage::default(),
            MemoryAnchor::default(),
            key(),
            &mut DeterministicEntropy::new(1),
        )
        .unwrap();
        let forged_options = JournalOpenOptions::new(
            running.actor.gate_id().clone(),
            JournalId::new([2; 16]).unwrap(),
            GateBootId::new([0xee; 16]),
            10,
            journal_limits(),
        );
        let forged = {
            let signer = running.actor.journal_signer();
            RecoveredGateJournal::provision_new(
                directory.0.join("journal"),
                forged_options,
                &signer,
                capture_limits(),
                running
                    .actor
                    .journal_verifier(NonZeroUsize::new(32 * 1024).unwrap()),
                NonZeroUsize::new(32).unwrap(),
            )
            .unwrap()
        };

        assert!(matches!(
            running.bind_publication_journal(forged),
            Err(JournalBindingError::BootMismatch)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn current_committed_boot_cannot_reappear_in_recovered_history() {
        let directory = TestDirectory::new();
        let journal_path = directory.0.join("journal");
        let running = start_with_backends(
            template(),
            state(&directory, StateOpenMode::ProvisionNew),
            MemoryStorage::default(),
            MemoryAnchor::default(),
            key(),
            &mut DeterministicEntropy::new(1),
        )
        .unwrap();
        let current_options = || {
            JournalOpenOptions::new(
                running.actor.gate_id().clone(),
                JournalId::new([2; 16]).unwrap(),
                running.actor.gate_boot_id(),
                10,
                journal_limits(),
            )
        };
        let prior_same_boot = {
            let signer = running.actor.journal_signer();
            RecoveredGateJournal::provision_new(
                &journal_path,
                current_options(),
                &signer,
                capture_limits(),
                running
                    .actor
                    .journal_verifier(NonZeroUsize::new(32 * 1024).unwrap()),
                NonZeroUsize::new(32).unwrap(),
            )
            .unwrap()
        };
        drop(prior_same_boot);
        let reopened_same_boot = {
            let signer = running.actor.journal_signer();
            RecoveredGateJournal::open_existing(
                &journal_path,
                current_options(),
                &signer,
                Some(&signer),
                capture_limits(),
                running
                    .actor
                    .journal_verifier(NonZeroUsize::new(32 * 1024).unwrap()),
                NonZeroUsize::new(32).unwrap(),
            )
            .unwrap()
        };

        assert!(matches!(
            running.bind_publication_journal(reopened_same_boot),
            Err(JournalBindingError::CurrentBootAlreadyRecovered)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn restarted_gate_cannot_silently_fork_a_fresh_journal() {
        let directory = TestDirectory::new();
        let storage = MemoryStorage::default();
        let anchor = MemoryAnchor::default();
        let first = start_with_backends(
            template(),
            state(&directory, StateOpenMode::ProvisionNew),
            storage.clone(),
            anchor.clone(),
            key(),
            &mut DeterministicEntropy::new(1),
        )
        .unwrap();
        drop(first);
        let restarted = start_with_backends(
            template(),
            state(&directory, StateOpenMode::OpenExisting),
            storage,
            anchor,
            key(),
            &mut DeterministicEntropy::new(91),
        )
        .unwrap();
        let fork = directory.0.join("forked-journal");

        assert!(matches!(
            restarted.provision_publication_journal(journal_config(&fork, 10, journal_limits(),)),
            Err(JournalBindingError::JournalProvisionRequiresFreshGateState)
        ));
        assert!(!fork.exists());
    }

    #[test]
    fn invalid_static_config_precedes_live_profile_entropy_and_durable_generation() {
        let directory = TestDirectory::new();
        let storage = MemoryStorage::default();
        let anchor = MemoryAnchor::default();
        let mut invalid = template();
        invalid.policy.max_speed_mm_s = 0;
        invalid.runtime_profile = GateRuntimeProfile::DeclaredLiveZenoh;
        let mut entropy = DeterministicEntropy::new(1);

        let result = start_with_backends(
            invalid,
            state(&directory, StateOpenMode::ProvisionNew),
            storage.clone(),
            anchor.clone(),
            key(),
            &mut entropy,
        );

        assert!(matches!(
            result,
            Err(DurableGateStartupError::Config(
                GateConfigError::InvalidPolicy(
                    haldir_policy_native::NativePolicyError::NonPositiveVelocityBound
                )
            ))
        ));
        assert_eq!(entropy.calls, 0);
        assert!(storage.0.lock().unwrap().is_none());
        assert!(anchor.head.lock().unwrap().is_none());
    }

    #[test]
    fn non_acl_publication_profile_precedes_live_profile_and_entropy() {
        let directory = TestDirectory::new();
        let storage = MemoryStorage::default();
        let anchor = MemoryAnchor::default();
        let mut invalid = template();
        invalid.publication = PlantPublicationAuthorityStateV1::Unavailable {
            reason: PlantPublicationUnavailableReasonV1::AclNotProvisioned,
        };
        invalid.runtime_profile = GateRuntimeProfile::DeclaredLiveZenoh;
        let mut entropy = DeterministicEntropy::new(1);

        let result = start_with_backends(
            invalid,
            state(&directory, StateOpenMode::ProvisionNew),
            storage.clone(),
            anchor.clone(),
            key(),
            &mut entropy,
        );

        assert!(matches!(
            result,
            Err(DurableGateStartupError::UnsupportedPublicationProfile)
        ));
        assert_eq!(entropy.calls, 0);
        assert!(storage.0.lock().unwrap().is_none());
        assert!(anchor.head.lock().unwrap().is_none());
    }

    #[test]
    fn assurance_profile_rejects_local_anchor_before_entropy() {
        let directory = TestDirectory::new();
        let storage = MemoryStorage::default();
        let anchor = MemoryAnchor::default();
        let mut state = state(&directory, StateOpenMode::ProvisionNew);
        state.profile = StartupProfile::AssuranceExternal;
        let mut entropy = DeterministicEntropy::new(1);

        let result = start_with_backends(
            template(),
            state,
            storage.clone(),
            anchor.clone(),
            key(),
            &mut entropy,
        );

        assert!(matches!(
            result,
            Err(DurableGateStartupError::AnchorProtectionMismatch {
                required: StartupProfile::AssuranceExternal,
                actual: AnchorProtection::LocalRewritable,
            })
        ));
        assert_eq!(entropy.calls, 0);
        assert!(storage.0.lock().unwrap().is_none());
        assert!(anchor.head.lock().unwrap().is_none());
    }

    #[test]
    fn assurance_startup_requires_a_validated_deployment_package_before_entropy_or_storage() {
        let directory = TestDirectory::new();
        let storage = MemoryStorage::default();
        let anchor = ExternalMemoryAnchor::default();
        let mut startup_state = state(&directory, StateOpenMode::ProvisionNew);
        startup_state.profile = StartupProfile::AssuranceExternal;
        let mut entropy = DeterministicEntropy::new(1);

        let result = start_with_backends(
            template(),
            startup_state,
            storage.clone(),
            anchor.clone(),
            key(),
            &mut entropy,
        );

        assert!(matches!(
            result,
            Err(DurableGateStartupError::DeploymentPackageRequired)
        ));
        assert_eq!(entropy.calls, 0);
        assert!(storage.0.lock().unwrap().is_none());
        assert!(anchor.0.head.lock().unwrap().is_none());
    }

    #[test]
    fn deployment_startup_commits_and_retains_the_exact_verified_package_binding() {
        let directory = TestDirectory::new();
        let configured = template();
        let package =
            validated_deployment_package(&configured, DeploymentClassV1::Development, [1; 16]);
        let expected_digest = package.resolved().verified().payload_digest();
        let mut entropy = DeterministicEntropy::new(1);

        let running = start_deployment_with_backends(
            package,
            configured,
            state(&directory, StateOpenMode::ProvisionNew),
            MemoryStorage::default(),
            MemoryAnchor::default(),
            key(),
            &mut entropy,
        )
        .unwrap();

        assert_eq!(entropy.calls, 1);
        assert_eq!(
            running.report().startup_profile,
            StartupProfile::DevelopmentLocal
        );
        assert_eq!(
            running
                .report()
                .deployment_revision
                .map(DeploymentRevision::get),
            Some(7)
        );
        assert_eq!(
            running.report().deployment_payload_digest,
            Some(expected_digest)
        );
        assert_eq!(
            running
                .deployment_package()
                .unwrap()
                .resolved()
                .verified()
                .package()
                .deployment_id
                .as_str(),
            "deployment-a"
        );
    }

    #[cfg(unix)]
    #[test]
    fn deployment_package_proof_is_retained_through_journal_binding() {
        let directory = TestDirectory::new();
        let configured = template();
        let package =
            validated_deployment_package(&configured, DeploymentClassV1::Development, [1; 16]);
        let running = start_deployment_with_backends(
            package,
            configured,
            state(&directory, StateOpenMode::ProvisionNew),
            MemoryStorage::default(),
            MemoryAnchor::default(),
            key(),
            &mut DeterministicEntropy::new(1),
        )
        .unwrap();

        let bound = running
            .provision_publication_journal(journal_config(
                directory.0.join("journal"),
                10,
                journal_limits(),
            ))
            .unwrap();

        assert_eq!(
            bound
                .deployment_package()
                .unwrap()
                .resolved()
                .verified()
                .package()
                .deployment_revision
                .get(),
            7
        );
        assert_eq!(
            bound.active_journal_identity().unwrap().journal_id,
            JournalId::new([2; 16]).unwrap()
        );
    }

    #[test]
    fn deployment_journal_mismatch_is_rejected_before_directory_access() {
        let directory = TestDirectory::new();
        let configured = template();
        let package =
            validated_deployment_package(&configured, DeploymentClassV1::Development, [1; 16]);
        let running = start_deployment_with_backends(
            package,
            configured,
            state(&directory, StateOpenMode::ProvisionNew),
            MemoryStorage::default(),
            MemoryAnchor::default(),
            key(),
            &mut DeterministicEntropy::new(1),
        )
        .unwrap();
        let journal_path = directory.absent_child("wrong-deployment-journal");

        let result = running.provision_publication_journal(journal_config_with_id(
            &journal_path,
            JournalId::new([3; 16]).unwrap(),
            10,
            journal_limits(),
        ));

        assert!(matches!(
            result,
            Err(JournalBindingError::JournalIdMismatch)
        ));
        assert!(!journal_path.exists());
    }

    #[test]
    fn assurance_package_selects_only_an_external_anchor_profile() {
        let directory = TestDirectory::new();
        let configured = template();
        let package = validated_deployment_package(
            &configured,
            DeploymentClassV1::AssuranceSimulation,
            [1; 16],
        );
        let mut startup_state = state(&directory, StateOpenMode::ProvisionNew);
        startup_state.profile = StartupProfile::AssuranceExternal;

        let running = start_deployment_with_backends(
            package,
            configured,
            startup_state,
            MemoryStorage::default(),
            ExternalMemoryAnchor::default(),
            key(),
            &mut DeterministicEntropy::new(1),
        )
        .unwrap();

        assert_eq!(
            running.report().startup_profile,
            StartupProfile::AssuranceExternal
        );
        assert_eq!(
            running.report().anchor_protection,
            AnchorProtection::ExternalNonRewindable
        );
        assert!(running.deployment_package().is_some());
    }

    #[test]
    fn deployment_state_store_mismatch_precedes_anchor_entropy_lock_and_storage() {
        let directory = TestDirectory::new();
        let configured = template();
        let package =
            validated_deployment_package(&configured, DeploymentClassV1::Development, [9; 16]);
        let calls = Arc::new(AtomicUsize::new(0));
        let mut entropy = DeterministicEntropy::new(1);

        let result = start_deployment_with_backends(
            package,
            configured,
            state(&directory, StateOpenMode::ProvisionNew),
            CountingStorage(calls.clone()),
            CountingAnchor(calls.clone()),
            key(),
            &mut entropy,
        );

        assert!(matches!(
            result,
            Err(DurableGateStartupError::DeploymentBinding(
                DeploymentGateBindingError::StateStoreMismatch
            ))
        ));
        assert_eq!(entropy.calls, 0);
        assert_eq!(calls.load(Ordering::Relaxed), 0);
        assert!(!directory.absent_child("gate.lock").exists());
    }

    #[test]
    fn deployment_trust_snapshot_mismatch_precedes_every_startup_effect() {
        let (package, mut configured) = deployment_fixture();
        let extra_signer = SigningKey::from_seed([41; 32]).expect("nonzero test seed");
        configured
            .trust
            .insert(KeyRecord {
                kid: KeyId::new(vec![41]).unwrap(),
                role: KeyRole::ControllerIntent,
                verifying_key: extra_signer.verifying_key(),
                subject: KeySubject::new("controller-extra").unwrap(),
                class: KeyClass::Assurance,
            })
            .unwrap();

        assert_configuration_binding_rejected_before_effects(
            package,
            configured,
            DeploymentGateBindingError::TrustSnapshotMismatch,
        );
    }

    #[test]
    fn deployment_rejects_bootstrap_key_reenrolled_under_runtime_authority() {
        let mut configured = template();
        let deployment_signer = SigningKey::from_seed([9; 32]).expect("nonzero test seed");
        configured
            .trust
            .insert(KeyRecord {
                kid: KeyId::new(vec![90]).unwrap(),
                role: KeyRole::ControllerIntent,
                verifying_key: deployment_signer.verifying_key(),
                subject: KeySubject::new("controller-alias").unwrap(),
                class: KeyClass::Development,
            })
            .unwrap();
        let package =
            validated_deployment_package(&configured, DeploymentClassV1::Development, [1; 16]);

        assert_configuration_binding_rejected_before_effects(
            package,
            configured,
            DeploymentGateBindingError::BootstrapRuntimeTrustConflict(
                TrustStoreDisjointnessError::OverlappingKeyMaterial,
            ),
        );
    }

    #[test]
    fn deployment_rejects_bootstrap_kid_rebound_in_runtime_trust() {
        let mut configured = template();
        let runtime_signer = SigningKey::from_seed([90; 32]).expect("nonzero test seed");
        configured
            .trust
            .insert(KeyRecord {
                kid: KeyId::new(vec![9, 0xa5]).unwrap(),
                role: KeyRole::ControllerIntent,
                verifying_key: runtime_signer.verifying_key(),
                subject: KeySubject::new("controller-rebound-kid").unwrap(),
                class: KeyClass::Development,
            })
            .unwrap();
        let package =
            validated_deployment_package(&configured, DeploymentClassV1::Development, [1; 16]);

        assert_configuration_binding_rejected_before_effects(
            package,
            configured,
            DeploymentGateBindingError::BootstrapRuntimeTrustConflict(
                TrustStoreDisjointnessError::OverlappingKid,
            ),
        );
    }

    #[test]
    fn deployment_rejects_exact_bootstrap_record_in_runtime_trust() {
        let mut configured = template();
        let deployment_signer = SigningKey::from_seed([9; 32]).expect("nonzero test seed");
        configured
            .trust
            .insert(KeyRecord {
                kid: KeyId::new(vec![9, 0xa5]).unwrap(),
                role: KeyRole::DeploymentAuthority,
                verifying_key: deployment_signer.verifying_key(),
                subject: KeySubject::new("deployment-authority-a").unwrap(),
                class: KeyClass::Development,
            })
            .unwrap();
        let package =
            validated_deployment_package(&configured, DeploymentClassV1::Development, [1; 16]);

        assert_configuration_binding_rejected_before_effects(
            package,
            configured,
            DeploymentGateBindingError::BootstrapRuntimeTrustConflict(
                TrustStoreDisjointnessError::OverlappingKid,
            ),
        );
    }

    #[test]
    fn deployment_revocation_snapshot_mismatch_precedes_every_startup_effect() {
        let (package, mut configured) = deployment_fixture();
        configured
            .revocations
            .revoke_key(&KeyId::new(vec![42]).unwrap(), 1)
            .unwrap();

        assert_configuration_binding_rejected_before_effects(
            package,
            configured,
            DeploymentGateBindingError::RevocationSnapshotMismatch,
        );
    }

    #[test]
    fn deployment_admission_snapshot_mismatch_precedes_every_startup_effect() {
        let (package, mut configured) = deployment_fixture();
        configured
            .admission
            .revoke(&AdmissionId::new([43; 16]), 1)
            .unwrap();

        assert_configuration_binding_rejected_before_effects(
            package,
            configured,
            DeploymentGateBindingError::AdmissionSnapshotMismatch,
        );
    }

    #[test]
    fn deployment_policy_snapshot_mismatch_precedes_every_startup_effect() {
        let (package, mut configured) = deployment_fixture();
        configured.policy.max_speed_mm_s = 2;
        configured.policy_snapshot_digest = configured.policy.canonical_digest().unwrap();

        assert_configuration_binding_rejected_before_effects(
            package,
            configured,
            DeploymentGateBindingError::PolicySnapshotMismatch,
        );
    }

    #[test]
    fn deployment_session_mismatch_precedes_every_startup_effect() {
        let (package, mut configured) = deployment_fixture();
        configured.session.generation = CanonicalUuidV4String::from_random_bytes([44; 16]);

        assert_configuration_binding_rejected_before_effects(
            package,
            configured,
            DeploymentGateBindingError::SessionMismatch,
        );
    }

    #[test]
    fn deployment_publication_mismatch_precedes_every_startup_effect() {
        let (package, mut configured) = deployment_fixture();
        let PlantPublicationAuthorityStateV1::AclExclusiveV1(evidence) =
            &mut configured.publication
        else {
            panic!("fixture publication profile changed")
        };
        evidence.acl_policy_digest = digest(b"different-acl-policy");

        assert_configuration_binding_rejected_before_effects(
            package,
            configured,
            DeploymentGateBindingError::PublicationMismatch,
        );
    }

    #[test]
    fn deployment_publication_observation_time_is_not_static_authority() {
        let directory = TestDirectory::new();
        let (package, mut configured) = deployment_fixture();
        let PlantPublicationAuthorityStateV1::AclExclusiveV1(evidence) =
            &mut configured.publication
        else {
            panic!("fixture publication profile changed")
        };
        evidence.verified_at_mono_ns = 999;

        let running = start_deployment_with_backends(
            package,
            configured,
            state(&directory, StateOpenMode::ProvisionNew),
            MemoryStorage::default(),
            MemoryAnchor::default(),
            key(),
            &mut DeterministicEntropy::new(1),
        )
        .unwrap();

        assert_eq!(
            running
                .report()
                .deployment_revision
                .map(DeploymentRevision::get),
            Some(7)
        );
    }

    #[test]
    fn deployment_local_cap_mismatch_precedes_every_startup_effect() {
        let (package, mut configured) = deployment_fixture();
        configured.local_cap_ms = NonZeroU32::new(999).unwrap();

        assert_configuration_binding_rejected_before_effects(
            package,
            configured,
            DeploymentGateBindingError::LocalCapMismatch,
        );
    }

    #[test]
    fn deployment_signer_kid_mismatch_precedes_every_startup_effect() {
        let (package, mut configured) = deployment_fixture();
        let replacement = SigningKey::from_seed([45; 32]).expect("nonzero test seed");
        let replacement_kid = KeyId::new(vec![45]).unwrap();
        let mut trust = TrustStore::new();
        trust
            .insert(KeyRecord {
                kid: replacement_kid.clone(),
                role: KeyRole::GateApplication,
                verifying_key: replacement.verifying_key(),
                subject: KeySubject::new(configured.gate_id.as_str()).unwrap(),
                class: KeyClass::Assurance,
            })
            .unwrap();
        configured.trust = trust;
        configured.gate_signer = replacement;
        configured.gate_signer_kid = replacement_kid;

        assert_configuration_binding_rejected_before_effects(
            package,
            configured,
            DeploymentGateBindingError::GateSignerKidMismatch,
        );
    }

    #[test]
    fn deployment_signer_public_key_mismatch_precedes_every_startup_effect() {
        let (package, mut configured) = deployment_fixture();
        let replacement = SigningKey::from_seed([46; 32]).expect("nonzero test seed");
        let mut trust = TrustStore::new();
        trust
            .insert(KeyRecord {
                kid: configured.gate_signer_kid.clone(),
                role: KeyRole::GateApplication,
                verifying_key: replacement.verifying_key(),
                subject: KeySubject::new(configured.gate_id.as_str()).unwrap(),
                class: KeyClass::Assurance,
            })
            .unwrap();
        configured.trust = trust;
        configured.gate_signer = replacement;

        assert_configuration_binding_rejected_before_effects(
            package,
            configured,
            DeploymentGateBindingError::GateSignerPublicKeyMismatch,
        );
    }

    #[test]
    fn deployment_startup_rejects_same_revision_package_equivocation_on_reopen() {
        let directory = TestDirectory::new();
        let storage = MemoryStorage::default();
        let anchor = MemoryAnchor::default();
        let first_config = template();
        let first_package = validated_deployment_package_named(
            &first_config,
            DeploymentClassV1::Development,
            [1; 16],
            "deployment-a",
        );
        let first = start_deployment_with_backends(
            first_package,
            first_config,
            state(&directory, StateOpenMode::ProvisionNew),
            storage.clone(),
            anchor.clone(),
            key(),
            &mut DeterministicEntropy::new(1),
        )
        .unwrap();
        drop(first);

        let conflicting_config = template();
        let conflicting_package = validated_deployment_package_named(
            &conflicting_config,
            DeploymentClassV1::Development,
            [1; 16],
            "deployment-b",
        );
        let result = start_deployment_with_backends(
            conflicting_package,
            conflicting_config,
            state(&directory, StateOpenMode::OpenExisting),
            storage,
            anchor,
            key(),
            &mut DeterministicEntropy::new(91),
        );

        assert!(matches!(
            result,
            Err(DurableGateStartupError::Durable(
                DurableAntiRollbackError::State(
                    haldir_state::AntiRollbackError::PackageEquivocation
                )
            ))
        ));
    }

    #[test]
    fn deployment_and_durable_startup_errors_preserve_nested_sources() {
        fn assert_standard_error<E: std::error::Error + Send + Sync + 'static>() {}
        assert_standard_error::<DeploymentGateBindingError>();
        assert_standard_error::<DurableGateStartupError>();
        assert_standard_error::<JournalBindingError>();
        assert_standard_error::<PublicationJournalConfigError>();

        let binding = DurableGateStartupError::DeploymentBinding(
            DeploymentGateBindingError::StateStoreMismatch,
        );
        let durable = DurableGateStartupError::Durable(DurableAntiRollbackError::State(
            haldir_state::AntiRollbackError::PackageEquivocation,
        ));
        let trust_binding = DurableGateStartupError::DeploymentBinding(
            DeploymentGateBindingError::BootstrapRuntimeTrustConflict(
                TrustStoreDisjointnessError::OverlappingKeyMaterial,
            ),
        );

        assert_eq!(
            binding.to_string(),
            "DEPLOYMENT_GATE_BINDING_STATE_STORE_MISMATCH"
        );
        assert_eq!(durable.to_string(), "DURABLE_GATE_STARTUP_DURABLE_STATE");
        assert!(std::error::Error::source(&binding).is_some());
        assert!(std::error::Error::source(&durable).is_some());
        let binding_source = std::error::Error::source(&trust_binding).unwrap();
        assert_eq!(
            binding_source.to_string(),
            "DEPLOYMENT_GATE_BINDING_BOOTSTRAP_RUNTIME_TRUST_CONFLICT"
        );
        assert_eq!(
            binding_source.source().unwrap().to_string(),
            "TRUST_STORES_OVERLAPPING_KEY_MATERIAL"
        );
    }

    #[test]
    fn deployment_configuration_binding_errors_have_stable_reason_codes() {
        for (error, expected) in [
            (
                DeploymentGateBindingError::TrustSnapshotMismatch,
                "DEPLOYMENT_GATE_BINDING_TRUST_SNAPSHOT_MISMATCH",
            ),
            (
                DeploymentGateBindingError::BootstrapRuntimeTrustConflict(
                    TrustStoreDisjointnessError::OverlappingKeyMaterial,
                ),
                "DEPLOYMENT_GATE_BINDING_BOOTSTRAP_RUNTIME_TRUST_CONFLICT",
            ),
            (
                DeploymentGateBindingError::RevocationSnapshotMismatch,
                "DEPLOYMENT_GATE_BINDING_REVOCATION_SNAPSHOT_MISMATCH",
            ),
            (
                DeploymentGateBindingError::AdmissionSnapshotMismatch,
                "DEPLOYMENT_GATE_BINDING_ADMISSION_SNAPSHOT_MISMATCH",
            ),
            (
                DeploymentGateBindingError::PolicySnapshotMismatch,
                "DEPLOYMENT_GATE_BINDING_POLICY_SNAPSHOT_MISMATCH",
            ),
            (
                DeploymentGateBindingError::SessionMismatch,
                "DEPLOYMENT_GATE_BINDING_SESSION_MISMATCH",
            ),
            (
                DeploymentGateBindingError::PublicationMismatch,
                "DEPLOYMENT_GATE_BINDING_PUBLICATION_MISMATCH",
            ),
            (
                DeploymentGateBindingError::LocalCapMismatch,
                "DEPLOYMENT_GATE_BINDING_LOCAL_CAP_MISMATCH",
            ),
            (
                DeploymentGateBindingError::GateSignerKidMismatch,
                "DEPLOYMENT_GATE_BINDING_SIGNER_KID_MISMATCH",
            ),
            (
                DeploymentGateBindingError::GateSignerPublicKeyMismatch,
                "DEPLOYMENT_GATE_BINDING_SIGNER_PUBLIC_KEY_MISMATCH",
            ),
        ] {
            assert_eq!(error.reason_code(), expected);
            assert_eq!(error.to_string(), expected);
        }
    }

    #[test]
    fn retained_instance_lock_excludes_a_second_startup() {
        let directory = TestDirectory::new();
        let storage = MemoryStorage::default();
        let anchor = MemoryAnchor::default();
        let first = start_with_backends(
            template(),
            state(&directory, StateOpenMode::ProvisionNew),
            storage.clone(),
            anchor.clone(),
            key(),
            &mut DeterministicEntropy::new(1),
        )
        .unwrap();

        let second = start_with_backends(
            template(),
            state(&directory, StateOpenMode::OpenExisting),
            storage.clone(),
            anchor.clone(),
            key(),
            &mut DeterministicEntropy::new(2),
        );
        assert!(matches!(second, Err(DurableGateStartupError::LockHeld)));
        drop(first);

        let third = start_with_backends(
            template(),
            state(&directory, StateOpenMode::OpenExisting),
            storage,
            anchor,
            key(),
            &mut DeterministicEntropy::new(3),
        )
        .unwrap();
        assert_eq!(third.report().boot_commit.generation, 3);
    }

    #[test]
    fn instance_lock_rejects_a_fifo_without_waiting_for_a_writer() {
        use std::sync::mpsc;
        use std::thread;
        use std::time::Duration;

        let directory = TestDirectory::new();
        let path = directory.absent_child("instance.lock");
        assert!(
            std::process::Command::new("mkfifo")
                .arg(&path)
                .status()
                .unwrap()
                .success()
        );
        let (sender, receiver) = mpsc::channel();
        let worker = thread::spawn(move || sender.send(acquire_instance_lock(&path)).unwrap());

        let result = receiver
            .recv_timeout(Duration::from_secs(2))
            .expect("FIFO instance-lock open exceeded the nonblocking deadline");
        worker.join().unwrap();

        assert!(matches!(
            result,
            Err(DurableGateStartupError::LockUnavailable)
        ));
    }

    #[test]
    fn pending_boot_anchor_is_reconciled_and_reported_on_next_startup() {
        let directory = TestDirectory::new();
        let storage = MemoryStorage::default();
        let anchor = MemoryAnchor::default();
        let first = start_with_backends(
            template(),
            state(&directory, StateOpenMode::ProvisionNew),
            storage.clone(),
            anchor.clone(),
            key(),
            &mut DeterministicEntropy::new(1),
        )
        .unwrap();
        drop(first);

        anchor.fail_compare_set.store(true, Ordering::Relaxed);
        let failed = start_with_backends(
            template(),
            state(&directory, StateOpenMode::OpenExisting),
            storage.clone(),
            anchor.clone(),
            key(),
            &mut DeterministicEntropy::new(2),
        );
        assert!(matches!(
            failed,
            Err(DurableGateStartupError::Durable(
                DurableAntiRollbackError::Durable(DurableError::AnchorUnavailable)
            ))
        ));

        anchor.fail_compare_set.store(false, Ordering::Relaxed);
        let recovered = start_with_backends(
            template(),
            state(&directory, StateOpenMode::OpenExisting),
            storage,
            anchor,
            key(),
            &mut DeterministicEntropy::new(3),
        )
        .unwrap();
        assert_eq!(
            recovered.report().recovery,
            Some(RecoveryStatus::CompletedPendingAnchor)
        );
        assert_eq!(recovered.report().boot_commit.generation, 4);
    }

    #[test]
    fn entropy_failure_creates_no_local_state_directory_or_files() {
        let parent = TestDirectory::new();
        let state_directory = parent.absent_child("not-created");
        let result = start_local(
            template(),
            LocalStartupConfig {
                state_directory: state_directory.clone(),
                store_id: StoreId::new([1; 16]),
                open_mode: StateOpenMode::ProvisionNew,
                profile: StartupProfile::DevelopmentLocal,
                max_payload_bytes: 4096,
            },
            key(),
            &mut FailingEntropy,
        );

        assert!(matches!(
            result,
            Err(DurableGateStartupError::EntropyUnavailable)
        ));
        assert!(!state_directory.exists());
    }

    #[test]
    fn declared_live_modeled_adapter_creates_no_local_state_directory_or_files() {
        let parent = TestDirectory::new();
        let state_directory = parent.absent_child("not-created-for-profile-mismatch");
        let mut configured = template();
        configured.runtime_profile = GateRuntimeProfile::DeclaredLiveZenoh;
        let mut entropy = DeterministicEntropy::new(1);

        let result = start_local(
            configured,
            LocalStartupConfig {
                state_directory: state_directory.clone(),
                store_id: StoreId::new([1; 16]),
                open_mode: StateOpenMode::ProvisionNew,
                profile: StartupProfile::DevelopmentLocal,
                max_payload_bytes: 4096,
            },
            key(),
            &mut entropy,
        );

        assert!(matches!(
            result,
            Err(DurableGateStartupError::NcpWireProfileMismatch {
                runtime_profile: GateRuntimeProfile::DeclaredLiveZenoh,
                required: NcpCommandWireProfile::ExactNcpV0_8Json,
                actual: NcpCommandWireProfile::ModeledP0,
            })
        ));
        assert_eq!(entropy.calls, 0);
        assert!(!state_directory.exists());
    }

    #[cfg(all(feature = "real-ncp", not(feature = "live-zenoh")))]
    #[test]
    fn declared_live_exact_adapter_without_live_support_creates_no_local_state_directory() {
        let parent = TestDirectory::new();
        let state_directory = parent.absent_child("not-created-without-live-support");
        let mut configured = template();
        configured.runtime_profile = GateRuntimeProfile::DeclaredLiveZenoh;
        configured.ncp_adapter = SelectedNcpCommandAdapter::exact_ncp_v0_8_json();
        let mut entropy = DeterministicEntropy::new(1);

        let result = start_local(
            configured,
            LocalStartupConfig {
                state_directory: state_directory.clone(),
                store_id: StoreId::new([1; 16]),
                open_mode: StateOpenMode::ProvisionNew,
                profile: StartupProfile::DevelopmentLocal,
                max_payload_bytes: 4096,
            },
            key(),
            &mut entropy,
        );

        assert!(matches!(
            result,
            Err(DurableGateStartupError::LiveZenohSupportNotCompiled)
        ));
        assert_eq!(entropy.calls, 0);
        assert!(!state_directory.exists());
    }

    #[test]
    fn running_gate_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<RunningGate>();
        assert_send::<JournalBoundRunningGate>();
    }

    #[cfg(unix)]
    #[test]
    fn local_file_convenience_requires_explicit_provision_then_opens() {
        let parent = TestDirectory::new();
        let state_directory = parent.absent_child("state");
        let config = |mode| LocalStartupConfig {
            state_directory: state_directory.clone(),
            store_id: StoreId::new([1; 16]),
            open_mode: mode,
            profile: StartupProfile::DevelopmentLocal,
            max_payload_bytes: 4096,
        };

        let missing = start_local(
            template(),
            config(StateOpenMode::OpenExisting),
            key(),
            &mut DeterministicEntropy::new(1),
        );
        assert!(matches!(
            missing,
            Err(DurableGateStartupError::Durable(
                DurableAntiRollbackError::Durable(DurableError::Missing)
            ))
        ));
        assert!(!state_directory.exists());

        let first = start_local(
            template(),
            config(StateOpenMode::ProvisionNew),
            key(),
            &mut DeterministicEntropy::new(2),
        )
        .unwrap();
        assert!(state_directory.join(LOCAL_SNAPSHOT_FILE).is_file());
        assert!(state_directory.join(LOCAL_ANCHOR_FILE).is_file());
        drop(first);

        let second = start_local(
            template(),
            config(StateOpenMode::OpenExisting),
            key(),
            &mut DeterministicEntropy::new(3),
        )
        .unwrap();
        assert_eq!(second.report().recovery, Some(RecoveryStatus::Clean));
    }
}
