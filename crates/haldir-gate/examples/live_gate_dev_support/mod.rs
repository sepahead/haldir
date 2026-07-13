//! Shared implementation for the development-only live Gate smoke examples.
//!
//! Every key below is a public, deterministic fixture value. Nothing in this
//! module is a credential-loading, deployment-package, or production runtime
//! design. The networked target opens only an existing disposable fixture and
//! retains a separate outer lock until the concrete Zenoh session has closed.

#![allow(
    dead_code,
    reason = "this module is compiled separately into two complementary example targets"
)]

use core::fmt;
use core::num::{NonZeroU32, NonZeroU64, NonZeroUsize};
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions, TryLockError};
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};

use haldir_admission::{AdmissionLevelV1, AdmissionRecordV1, AdmissionSnapshot};
use haldir_contracts::action::{ActionClassV1, CoordinateFrameV1};
use haldir_contracts::cbor::CanonicalMessage;
use haldir_contracts::digest::{DigestDomain, DigestV1};
use haldir_contracts::ids::{
    AdmissionId, ChallengeNonce, ControllerId, GateId, KeyId, MissionId, MissionLeaseId,
    PrincipalId, SourceSeq, VehicleId,
};
use haldir_contracts::lease::MissionLeaseV1;
use haldir_contracts::limits::MissionLeaseLimitsV1;
use haldir_contracts::scalar::{
    AsciiId, BoundedAscii, BoundedSet, BoundedVec, CanonicalUuidV4String,
};
use haldir_contracts::session::{NcpSessionIdentityV1, NcpSourceRefV1};
use haldir_contracts::status::{AclExclusiveEvidenceV1, PlantPublicationAuthorityStateV1};
use haldir_core::snapshot::{
    KinematicStateFixedV1, StateUncertaintyFixedV1, TrustedStateSnapshotV1, VerifiedSourceStateV1,
};
use haldir_core::time::{MonoInstant, MonotonicClock};
use haldir_crypto::{
    KeyClass, KeyRecord, KeyRole, RevocationSnapshot, SigningKey, TrustStore, sign_message,
};
use haldir_durable::{AnchorProtection, RecoveryStatus, StorageMacKey, StoreId};
use haldir_evidence::journal::JournalBounds;
use haldir_evidence::manager::{JournalLimits, JournalRecoveryReport, RecoveryCaptureLimits};
use haldir_gate::{
    DeclaredLiveGateKernel, DeclaredLiveGateZenohService, GateConfigTemplate, GateRuntimeProfile,
    LiveIntentActivationInput, LiveZenohShutdownError, LocalStartupConfig, OsEntropy,
    PublicationJournalStartupConfig, StartupProfile, StartupReport, StateOpenMode, start_local,
};
use haldir_ncp08::SelectedNcpCommandAdapter;
use haldir_policy_native::{GeofenceBoxV1, NativePolicySnapshot, PhaseRuleV1};
use haldir_transport_zenoh::{
    HARD_MAX_INTENT_BYTES, HaldirKeys, IngressCountersSnapshot, IngressLimits, SecureClientConfig,
    SecureZenohSession,
};
use serde_json::{Value, json};

const FIXTURE_GATE_ID: &str = "gate-live-dev-smoke";
const FIXTURE_REALM: &str = "haldir-ncp";
const FIXTURE_VEHICLE_ID: &str = "uav-1";
const FIXTURE_SESSION_ID: &str = "uav-1";
const FIXTURE_CONTROLLER_ID: &str = "controller-a";
const FIXTURE_MISSION_ID: &str = "development-smoke";
const FIXTURE_PHASE: &str = "INSPECTION";
const FIXTURE_SOURCE_ROUTE: &str = "haldir-ncp/session/uav-1/sensor/pose";
const OUTER_LOCK_NAME: &str = ".haldir-live-gate-smoke.lock";
const STATE_DIRECTORY_NAME: &str = "state";
const JOURNAL_DIRECTORY_NAME: &str = "publication-journal";
const STATE_SNAPSHOT_NAME: &str = "anti-rollback.snapshot";
const STATE_ANCHOR_NAME: &str = "generation.anchor";
const STATE_LOCK_NAME: &str = ".haldir-gate.lock";
const JOURNAL_LOCK_NAME: &str = ".haldir-evidence.lock";
const JOURNAL_SEGMENT_PREFIX: &str = "segment-";
const JOURNAL_PENDING_PREFIX: &str = ".haldir-evidence.pending-";
const JOURNAL_SEGMENT_DIGITS: usize = 20;
const MAX_JOURNAL_SEGMENTS: usize = 32;
const MAX_STATE_PAYLOAD_BYTES: usize = 4096;
const RESULT_SCHEMA_VERSION: u64 = 1;
const GATE_SIGNING_SEED: [u8; 32] = [0x33; 32];
const MISSION_SIGNING_SEED: [u8; 32] = [0x22; 32];
const CONTROLLER_SIGNING_SEED: [u8; 32] = [0x11; 32];
const STORAGE_MAC_BYTES: [u8; 32] = [0x44; 32];
const STORE_ID_BYTES: [u8; 16] = [0x55; 16];

/// Bounded stage-classified failure that never includes paths or secret material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SmokeError {
    stage: &'static str,
    durable_effects_may_have_committed: bool,
    cleanup_classification: &'static str,
}

impl SmokeError {
    const fn before_durable(stage: &'static str) -> Self {
        Self {
            stage,
            durable_effects_may_have_committed: false,
            cleanup_classification: "not-applicable",
        }
    }

    const fn after_durable(stage: &'static str) -> Self {
        Self {
            stage,
            durable_effects_may_have_committed: true,
            cleanup_classification: "not-applicable",
        }
    }

    const fn after_durable_with_cleanup(
        stage: &'static str,
        cleanup_classification: &'static str,
    ) -> Self {
        Self {
            stage,
            durable_effects_may_have_committed: true,
            cleanup_classification,
        }
    }

    /// Classify failure to construct the target-owned development executor.
    pub const fn runtime_creation() -> Self {
        Self::before_durable("runtime-create")
    }

    /// Stable failure stage without backend or path detail.
    pub const fn stage(self) -> &'static str {
        self.stage
    }

    /// Whether startup or recovery may already have changed the disposable fixture.
    pub const fn durable_effects_may_have_committed(self) -> bool {
        self.durable_effects_may_have_committed
    }

    /// Bounded local cleanup observation associated with the failed stage.
    pub const fn cleanup_classification(self) -> &'static str {
        self.cleanup_classification
    }
}

impl fmt::Display for SmokeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "development live smoke failed at {}", self.stage)
    }
}

impl std::error::Error for SmokeError {}

/// Construct the one-worker multi-thread executor required by Zenoh's runtime.
pub fn development_runtime() -> Result<tokio::runtime::Runtime, SmokeError> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_time()
        .build()
        .map_err(|_| SmokeError::runtime_creation())
}

type SmokeResult<T> = Result<T, SmokeError>;

/// Exact arguments for the offline disposable-fixture provisioner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvisionArgs {
    root: PathBuf,
    result: PathBuf,
}

/// Exact arguments for the OpenExisting-only networked bind/shutdown target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindArgs {
    root: PathBuf,
    zenoh_config: PathBuf,
    result: PathBuf,
}

/// Parse `program fixture-root result-json` without option or environment fallback.
pub fn parse_provision_args<I>(arguments: I) -> SmokeResult<ProvisionArgs>
where
    I: IntoIterator<Item = OsString>,
{
    let mut arguments = arguments.into_iter();
    let _program = arguments.next();
    let root = arguments
        .next()
        .map(PathBuf::from)
        .ok_or_else(|| SmokeError::before_durable("arguments"))?;
    let result = arguments
        .next()
        .map(PathBuf::from)
        .ok_or_else(|| SmokeError::before_durable("arguments"))?;
    if arguments.next().is_some() {
        return Err(SmokeError::before_durable("arguments"));
    }
    Ok(ProvisionArgs { root, result })
}

/// Parse `program fixture-root strict-client-config result-json` exactly.
pub fn parse_bind_args<I>(arguments: I) -> SmokeResult<BindArgs>
where
    I: IntoIterator<Item = OsString>,
{
    let mut arguments = arguments.into_iter();
    let _program = arguments.next();
    let root = arguments
        .next()
        .map(PathBuf::from)
        .ok_or_else(|| SmokeError::before_durable("arguments"))?;
    let zenoh_config = arguments
        .next()
        .map(PathBuf::from)
        .ok_or_else(|| SmokeError::before_durable("arguments"))?;
    let result = arguments
        .next()
        .map(PathBuf::from)
        .ok_or_else(|| SmokeError::before_durable("arguments"))?;
    if arguments.next().is_some() {
        return Err(SmokeError::before_durable("arguments"));
    }
    Ok(BindArgs {
        root,
        zenoh_config,
        result,
    })
}

#[derive(Debug, Clone)]
struct FixturePaths {
    root: PathBuf,
    state: PathBuf,
    journal: PathBuf,
    outer_lock: PathBuf,
}

impl FixturePaths {
    fn new(root: PathBuf) -> Self {
        Self {
            state: root.join(STATE_DIRECTORY_NAME),
            journal: root.join(JOURNAL_DIRECTORY_NAME),
            outer_lock: root.join(OUTER_LOCK_NAME),
            root,
        }
    }
}

/// A per-process monotonic clock with a wall-derived development-only origin.
///
/// `Instant` supplies monotonic movement within the target. The wall-derived base
/// merely makes immediate disposable-fixture reopenings comparable to prior journal
/// segment times; it is not an assurance clock or non-rewindable time source.
#[derive(Clone)]
struct DevelopmentClock {
    origin: Instant,
    base_nanoseconds: u64,
}

impl DevelopmentClock {
    fn new() -> SmokeResult<Self> {
        let elapsed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| SmokeError::before_durable("clock"))?;
        let base_nanoseconds =
            u64::try_from(elapsed.as_nanos()).map_err(|_| SmokeError::before_durable("clock"))?;
        Ok(Self {
            origin: Instant::now(),
            base_nanoseconds,
        })
    }
}

impl MonotonicClock for DevelopmentClock {
    fn now(&self) -> MonoInstant {
        let elapsed = u64::try_from(self.origin.elapsed().as_nanos()).unwrap_or(u64::MAX);
        MonoInstant::from_nanos(self.base_nanoseconds.saturating_add(elapsed))
    }
}

struct OuterLock {
    _file: File,
}

fn result_temporary_path(path: &Path) -> SmokeResult<PathBuf> {
    let name = path
        .file_name()
        .ok_or_else(|| SmokeError::before_durable("result-preflight"))?;
    let mut temporary_name = name.to_os_string();
    temporary_name.push(format!(".tmp-{}", std::process::id()));
    Ok(path.with_file_name(temporary_name))
}

fn preflight_result_path(path: &Path, fixture_root: &Path) -> SmokeResult<()> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        _ => return Err(SmokeError::before_durable("result-preflight")),
    }
    let temporary = result_temporary_path(path)?;
    match fs::symlink_metadata(&temporary) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        _ => return Err(SmokeError::before_durable("result-preflight")),
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let parent_metadata =
        fs::symlink_metadata(parent).map_err(|_| SmokeError::before_durable("result-preflight"))?;
    if !parent_metadata.file_type().is_dir() {
        return Err(SmokeError::before_durable("result-preflight"));
    }
    let canonical_parent =
        fs::canonicalize(parent).map_err(|_| SmokeError::before_durable("result-preflight"))?;
    let canonical_root = fs::canonicalize(fixture_root)
        .map_err(|_| SmokeError::before_durable("result-preflight"))?;
    if canonical_parent.starts_with(canonical_root) {
        return Err(SmokeError::before_durable("result-alias"));
    }
    Ok(())
}

#[cfg(unix)]
fn require_restricted_directory(path: &Path) -> SmokeResult<()> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| SmokeError::before_durable("fixture-preflight"))?;
    if !metadata.file_type().is_dir() || metadata.permissions().mode() & 0o077 != 0 {
        return Err(SmokeError::before_durable("fixture-preflight"));
    }
    Ok(())
}

#[cfg(not(unix))]
fn require_restricted_directory(_path: &Path) -> SmokeResult<()> {
    Err(SmokeError::before_durable("unsupported-platform"))
}

fn require_regular_file(path: &Path, stage: &'static str) -> SmokeResult<()> {
    let metadata = fs::symlink_metadata(path).map_err(|_| SmokeError::before_durable(stage))?;
    if !metadata.file_type().is_file() {
        return Err(SmokeError::before_durable(stage));
    }
    Ok(())
}

#[cfg(unix)]
fn require_restricted_regular_file(path: &Path, stage: &'static str) -> SmokeResult<()> {
    let metadata = fs::symlink_metadata(path).map_err(|_| SmokeError::before_durable(stage))?;
    if !metadata.file_type().is_file() || metadata.permissions().mode() & 0o077 != 0 {
        return Err(SmokeError::before_durable(stage));
    }
    Ok(())
}

#[cfg(not(unix))]
fn require_restricted_regular_file(_path: &Path, stage: &'static str) -> SmokeResult<()> {
    Err(SmokeError::before_durable(stage))
}

#[cfg(unix)]
fn prepare_fresh_root(paths: &FixturePaths) -> SmokeResult<()> {
    match fs::symlink_metadata(&paths.root) {
        Ok(_) => require_restricted_directory(&paths.root)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut builder = fs::DirBuilder::new();
            builder.mode(0o700);
            builder
                .create(&paths.root)
                .map_err(|_| SmokeError::before_durable("fixture-root-create"))?;
        }
        Err(_) => return Err(SmokeError::before_durable("fixture-root-create")),
    }
    for path in [&paths.state, &paths.journal] {
        if fs::symlink_metadata(path).is_ok() {
            return Err(SmokeError::before_durable("fixture-not-fresh"));
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn prepare_fresh_root(_paths: &FixturePaths) -> SmokeResult<()> {
    Err(SmokeError::before_durable("unsupported-platform"))
}

fn require_existing_fixture(paths: &FixturePaths) -> SmokeResult<()> {
    require_restricted_directory(&paths.root)?;
    require_restricted_directory(&paths.state)?;
    require_restricted_directory(&paths.journal)?;
    for path in [
        paths.state.join(STATE_SNAPSHOT_NAME),
        paths.state.join(STATE_ANCHOR_NAME),
        paths.state.join(STATE_LOCK_NAME),
    ] {
        require_restricted_regular_file(&path, "state-preflight")?;
    }
    require_restricted_regular_file(&paths.journal.join(JOURNAL_LOCK_NAME), "journal-preflight")?;
    let mut segment_found = false;
    let mut segment_count = 0_usize;
    let mut pending_found = false;
    let mut entries = 0_usize;
    for entry in
        fs::read_dir(&paths.journal).map_err(|_| SmokeError::before_durable("journal-preflight"))?
    {
        let entry = entry.map_err(|_| SmokeError::before_durable("journal-preflight"))?;
        entries = entries
            .checked_add(1)
            .ok_or_else(|| SmokeError::before_durable("journal-preflight"))?;
        if entries > MAX_JOURNAL_SEGMENTS + 2 {
            return Err(SmokeError::before_durable("journal-preflight"));
        }
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            return Err(SmokeError::before_durable("journal-preflight"));
        };
        if name == JOURNAL_LOCK_NAME {
            continue;
        }
        let valid_segment_name = |candidate: &str| {
            candidate
                .strip_prefix(JOURNAL_SEGMENT_PREFIX)
                .is_some_and(|suffix| {
                    suffix.len() == JOURNAL_SEGMENT_DIGITS
                        && suffix.bytes().all(|byte| byte.is_ascii_digit())
                })
        };
        if valid_segment_name(name) {
            require_restricted_regular_file(&entry.path(), "journal-preflight")?;
            segment_count = segment_count
                .checked_add(1)
                .ok_or_else(|| SmokeError::before_durable("journal-preflight"))?;
            if segment_count > MAX_JOURNAL_SEGMENTS {
                return Err(SmokeError::before_durable("journal-preflight"));
            }
            segment_found = true;
            continue;
        }
        if let Some(candidate) = name.strip_prefix(JOURNAL_PENDING_PREFIX)
            && !pending_found
            && valid_segment_name(candidate)
        {
            require_restricted_regular_file(&entry.path(), "journal-preflight")?;
            pending_found = true;
            continue;
        }
        return Err(SmokeError::before_durable("journal-preflight"));
    }
    if !segment_found {
        return Err(SmokeError::before_durable("journal-preflight"));
    }
    require_restricted_regular_file(&paths.outer_lock, "outer-lock-preflight")
}

#[cfg(unix)]
fn restrict_directory_after_provision(path: &Path) -> SmokeResult<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|_| SmokeError::after_durable("fixture-permissions"))?;
    require_restricted_directory(path).map_err(|_| SmokeError::after_durable("fixture-permissions"))
}

#[cfg(not(unix))]
fn restrict_directory_after_provision(_path: &Path) -> SmokeResult<()> {
    Err(SmokeError::after_durable("unsupported-platform"))
}

#[cfg(unix)]
fn acquire_outer_lock(path: &Path, create: bool) -> SmokeResult<OuterLock> {
    if let Ok(metadata) = fs::symlink_metadata(path)
        && !metadata.file_type().is_file()
    {
        return Err(SmokeError::before_durable("outer-lock"));
    }
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(create).mode(0o600);
    let file = options
        .open(path)
        .map_err(|_| SmokeError::before_durable("outer-lock"))?;
    let path_metadata =
        fs::symlink_metadata(path).map_err(|_| SmokeError::before_durable("outer-lock"))?;
    let opened_metadata = file
        .metadata()
        .map_err(|_| SmokeError::before_durable("outer-lock"))?;
    if !path_metadata.file_type().is_file()
        || path_metadata.dev() != opened_metadata.dev()
        || path_metadata.ino() != opened_metadata.ino()
        || opened_metadata.permissions().mode() & 0o077 != 0
    {
        return Err(SmokeError::before_durable("outer-lock"));
    }
    match file.try_lock() {
        Ok(()) => Ok(OuterLock { _file: file }),
        Err(TryLockError::WouldBlock) => Err(SmokeError::before_durable("outer-lock-held")),
        Err(TryLockError::Error(_)) => Err(SmokeError::before_durable("outer-lock")),
    }
}

#[cfg(not(unix))]
fn acquire_outer_lock(_path: &Path, _create: bool) -> SmokeResult<OuterLock> {
    Err(SmokeError::before_durable("unsupported-platform"))
}

fn fixture_key_id(seed: u8) -> SmokeResult<KeyId> {
    KeyId::new(vec![seed, 0xAB, seed]).map_err(|_| SmokeError::before_durable("fixture-invariant"))
}

fn fixture_session() -> SmokeResult<NcpSessionIdentityV1> {
    Ok(NcpSessionIdentityV1 {
        session_id: AsciiId::new(FIXTURE_SESSION_ID)
            .map_err(|_| SmokeError::before_durable("fixture-invariant"))?,
        generation: CanonicalUuidV4String::from_random_bytes([0x66; 16]),
    })
}

fn fixture_policy() -> NativePolicySnapshot {
    NativePolicySnapshot {
        max_component_mm_s: 3000,
        max_speed_mm_s: 3000,
        max_output_validity_ms: 500,
        min_useful_validity_ms: 50,
        publication_safety_margin_ms: 20,
        source_freshness_cap_ms: 200,
        state_freshness_cap_ms: 200,
        ncp_validity_cap_ms: 1000,
        plant_validity_cap_ms: 1000,
        nominal_update_ms: 20,
        tracking_error_mm: 50,
        uncertainty_margin_mm: 50,
        max_position_uncertainty_mm: 500,
        geofence: GeofenceBoxV1 {
            min_mm: [-100_000, -100_000, -100_000],
            max_mm: [100_000, 100_000, 100_000],
        },
        duty_window_ms: 10_000,
        max_active_ms_in_window: 6000,
        phase_rules: vec![PhaseRuleV1 {
            phase: FIXTURE_PHASE.to_owned(),
            allowed: vec![ActionClassV1::Hold, ActionClassV1::VelocityLocalNed],
        }],
    }
}

fn fixture_admission() -> SmokeResult<AdmissionRecordV1> {
    Ok(AdmissionRecordV1 {
        schema_major: 1,
        schema_minor: 0,
        issuer_id: AsciiId::new("development-admission-authority")
            .map_err(|_| SmokeError::before_durable("fixture-invariant"))?,
        admission_id: AdmissionId::new([0x77; 16]),
        controller_id: ControllerId::new(FIXTURE_CONTROLLER_ID)
            .map_err(|_| SmokeError::before_durable("fixture-invariant"))?,
        admission_profile_id: AsciiId::new("development-live-bind-smoke-v1")
            .map_err(|_| SmokeError::before_durable("fixture-invariant"))?,
        level: AdmissionLevelV1::A2ReferenceConformance,
        controller_bundle_digest: DigestV1::compute(
            DigestDomain::Bundle,
            b"development-live-bind-smoke-bundle",
        ),
        backend_profile_digest: DigestV1::compute(
            DigestDomain::BackendProfile,
            b"development-live-bind-smoke-backend",
        ),
        codec_digest: DigestV1::compute(
            DigestDomain::Payload,
            b"development-live-bind-smoke-codec",
        ),
        validity_term: NonZeroU64::new(1)
            .ok_or_else(|| SmokeError::before_durable("fixture-invariant"))?,
        conformance_run_digest: None,
    })
}

fn fixture_template() -> SmokeResult<GateConfigTemplate> {
    let gate_signer = SigningKey::from_seed(GATE_SIGNING_SEED);
    let mission_signer = SigningKey::from_seed(MISSION_SIGNING_SEED);
    let controller_signer = SigningKey::from_seed(CONTROLLER_SIGNING_SEED);
    let gate_id = GateId::new(FIXTURE_GATE_ID)
        .map_err(|_| SmokeError::before_durable("fixture-invariant"))?;
    let mut trust = TrustStore::new();
    for record in [
        KeyRecord {
            kid: fixture_key_id(1)?,
            role: KeyRole::ControllerIntent,
            verifying_key: controller_signer.verifying_key(),
            subject: Some(FIXTURE_CONTROLLER_ID.to_owned()),
            class: KeyClass::Assurance,
        },
        KeyRecord {
            kid: fixture_key_id(2)?,
            role: KeyRole::MissionAuthority,
            verifying_key: mission_signer.verifying_key(),
            subject: Some("development-mission-authority".to_owned()),
            class: KeyClass::Assurance,
        },
        KeyRecord {
            kid: fixture_key_id(3)?,
            role: KeyRole::GateApplication,
            verifying_key: gate_signer.verifying_key(),
            subject: Some(FIXTURE_GATE_ID.to_owned()),
            class: KeyClass::Assurance,
        },
    ] {
        trust
            .insert(record)
            .map_err(|_| SmokeError::before_durable("fixture-invariant"))?;
    }
    let admission_record = fixture_admission()?;
    let mut admission = AdmissionSnapshot::new();
    admission.insert(admission_record);
    Ok(GateConfigTemplate {
        gate_id,
        realm: AsciiId::new(FIXTURE_REALM)
            .map_err(|_| SmokeError::before_durable("fixture-invariant"))?,
        vehicle_id: VehicleId::new(FIXTURE_VEHICLE_ID)
            .map_err(|_| SmokeError::before_durable("fixture-invariant"))?,
        trust,
        revocations: RevocationSnapshot::new(),
        admission,
        policy: fixture_policy(),
        policy_snapshot_digest: fixture_policy_digest(),
        session: fixture_session()?,
        runtime_profile: GateRuntimeProfile::DeclaredLiveZenoh,
        ncp_adapter: SelectedNcpCommandAdapter::exact_ncp_v0_8_json(),
        publication: PlantPublicationAuthorityStateV1::AclExclusiveV1(AclExclusiveEvidenceV1 {
            gate_transport_principal: PrincipalId::new("haldir-gate.secure-reference-v1")
                .map_err(|_| SmokeError::before_durable("fixture-invariant"))?,
            final_route_digest: DigestV1::compute(
                DigestDomain::Payload,
                b"haldir-ncp/session/uav-1/command",
            ),
            certificate_fingerprint: DigestV1::compute(
                DigestDomain::Payload,
                b"development-ephemeral-certificate-placeholder",
            ),
            acl_policy_digest: DigestV1::compute(
                DigestDomain::Payload,
                b"haldir-secure-reference-v1",
            ),
            verified_at_mono_ns: 1,
        }),
        local_cap_ms: 30_000,
        gate_signer,
        gate_signer_kid: fixture_key_id(3)?,
    })
}

fn fixture_policy_digest() -> DigestV1 {
    DigestV1::compute(
        DigestDomain::PolicySnapshot,
        b"development-live-bind-smoke-policy",
    )
}

fn local_startup(paths: &FixturePaths, open_mode: StateOpenMode) -> LocalStartupConfig {
    LocalStartupConfig {
        state_directory: paths.state.clone(),
        store_id: StoreId::new(STORE_ID_BYTES),
        open_mode,
        profile: StartupProfile::DevelopmentLocal,
        max_payload_bytes: MAX_STATE_PAYLOAD_BYTES,
    }
}

fn publication_journal_config(
    paths: &FixturePaths,
    created_mono_ns: u64,
) -> SmokeResult<PublicationJournalStartupConfig> {
    let bounds = JournalBounds::new(128 * 1024, 8, 32 * 1024)
        .map_err(|_| SmokeError::before_durable("fixture-invariant"))?;
    let limits = JournalLimits::new(bounds, MAX_JOURNAL_SEGMENTS, 4 * 1024 * 1024)
        .map_err(|_| SmokeError::before_durable("fixture-invariant"))?;
    PublicationJournalStartupConfig::new(
        paths.journal.clone(),
        created_mono_ns,
        limits,
        RecoveryCaptureLimits::new(64, 4 * 1024 * 1024),
        NonZeroUsize::new(32 * 1024)
            .ok_or_else(|| SmokeError::before_durable("fixture-invariant"))?,
        NonZeroUsize::new(64).ok_or_else(|| SmokeError::before_durable("fixture-invariant"))?,
    )
    .map_err(|_| SmokeError::before_durable("fixture-invariant"))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ActivationSummary {
    controller_id: String,
    intent_route: String,
    lease_term: u64,
    gate_boot_id: [u8; 16],
    gate_output_epoch: [u8; 16],
}

fn build_activation(
    report: StartupReport,
    now: MonoInstant,
    entropy: &mut OsEntropy,
) -> SmokeResult<(LiveIntentActivationInput, ActivationSummary)> {
    use haldir_gate::EntropySource as _;

    let mut random = [0_u8; 48];
    entropy
        .fill_bytes(&mut random)
        .map_err(|_| SmokeError::after_durable("activation-entropy"))?;
    let challenge_bytes: [u8; 32] = random
        .get(..32)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| SmokeError::after_durable("fixture-invariant"))?;
    let lease_id_bytes: [u8; 16] = random
        .get(32..)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| SmokeError::after_durable("fixture-invariant"))?;
    let challenge = ChallengeNonce::new(challenge_bytes);
    let admission =
        fixture_admission().map_err(|_| SmokeError::after_durable("fixture-invariant"))?;
    let admission_digest = admission.admission_digest();
    let keys = HaldirKeys::try_new(FIXTURE_REALM, FIXTURE_SESSION_ID)
        .map_err(|_| SmokeError::after_durable("fixture-invariant"))?;
    let intent_route = keys
        .intent(FIXTURE_CONTROLLER_ID)
        .map_err(|_| SmokeError::after_durable("fixture-invariant"))?;
    let lease_term = NonZeroU64::new(report.boot_commit.generation)
        .ok_or_else(|| SmokeError::after_durable("lease-term"))?;
    let session = fixture_session().map_err(|_| SmokeError::after_durable("fixture-invariant"))?;
    let lease = MissionLeaseV1 {
        schema_major: 1,
        schema_minor: 0,
        issuer_id: AsciiId::new("development-mission-authority")
            .map_err(|_| SmokeError::after_durable("fixture-invariant"))?,
        issuer_key_id: fixture_key_id(2)
            .map_err(|_| SmokeError::after_durable("fixture-invariant"))?,
        lease_id: MissionLeaseId::new(lease_id_bytes),
        lease_term,
        gate_id: GateId::new(FIXTURE_GATE_ID)
            .map_err(|_| SmokeError::after_durable("fixture-invariant"))?,
        gate_boot_id: report.gate_boot_id,
        challenge_nonce: challenge,
        realm: AsciiId::new(FIXTURE_REALM)
            .map_err(|_| SmokeError::after_durable("fixture-invariant"))?,
        vehicle_id: VehicleId::new(FIXTURE_VEHICLE_ID)
            .map_err(|_| SmokeError::after_durable("fixture-invariant"))?,
        mission_id: MissionId::new(FIXTURE_MISSION_ID)
            .map_err(|_| SmokeError::after_durable("fixture-invariant"))?,
        mission_phase: AsciiId::new(FIXTURE_PHASE)
            .map_err(|_| SmokeError::after_durable("fixture-invariant"))?,
        ncp_session: session.clone(),
        gate_output_epoch: report.output_epoch,
        controller_id: ControllerId::new(FIXTURE_CONTROLLER_ID)
            .map_err(|_| SmokeError::after_durable("fixture-invariant"))?,
        controller_intent_key: BoundedAscii::new(&intent_route)
            .map_err(|_| SmokeError::after_durable("fixture-invariant"))?,
        controller_intent_signing_key_id: fixture_key_id(1)
            .map_err(|_| SmokeError::after_durable("fixture-invariant"))?,
        admission_id: admission.admission_id,
        admission_digest,
        controller_bundle_digest: admission.controller_bundle_digest,
        backend_profile_digest: admission.backend_profile_digest,
        policy_snapshot_digest: fixture_policy_digest(),
        allowed_actions: BoundedSet::from_iter_checked([
            ActionClassV1::Hold,
            ActionClassV1::VelocityLocalNed,
        ])
        .map_err(|_| SmokeError::after_durable("fixture-invariant"))?,
        allowed_frames: BoundedSet::from_iter_checked([CoordinateFrameV1::LocalNed])
            .map_err(|_| SmokeError::after_durable("fixture-invariant"))?,
        allowed_source_keys: BoundedVec::from_vec(vec![
            BoundedAscii::new(FIXTURE_SOURCE_ROUTE)
                .map_err(|_| SmokeError::after_durable("fixture-invariant"))?,
        ])
        .map_err(|_| SmokeError::after_durable("fixture-invariant"))?,
        limits: MissionLeaseLimitsV1 {
            max_output_validity_ms: nonzero_u32(500)?,
            max_linear_speed_mm_s: nonzero_u32(3000)?,
            max_linear_accel_mm_s2: nonzero_u32(2000)?,
            max_linear_slew_mm_s2: nonzero_u32(100_000)?,
            max_source_age_ms: nonzero_u32(200)?,
            max_state_age_ms: nonzero_u32(200)?,
            max_continuous_motion_ms: nonzero_u32(2000)?,
            minimum_hold_between_bursts_ms: 500,
        },
        max_active_duration_ms: nonzero_u32(30_000)?,
        max_intent_rate_millihz: nonzero_u32(50_000)?,
        max_total_intents: NonZeroU64::new(100_000)
            .ok_or_else(|| SmokeError::after_durable("fixture-invariant"))?,
        operator_context_digest: None,
    };
    let source = NcpSourceRefV1 {
        source_key: BoundedAscii::new(FIXTURE_SOURCE_ROUTE)
            .map_err(|_| SmokeError::after_durable("fixture-invariant"))?,
        stream_epoch: CanonicalUuidV4String::from_random_bytes([0x88; 16]),
        stream_seq: SourceSeq::new(
            NonZeroU64::new(1).ok_or_else(|| SmokeError::after_durable("fixture-invariant"))?,
        ),
    };
    let state = TrustedStateSnapshotV1 {
        vehicle_id: VehicleId::new(FIXTURE_VEHICLE_ID)
            .map_err(|_| SmokeError::after_durable("fixture-invariant"))?,
        session: session.clone(),
        captured_mono: now,
        primary_source: VerifiedSourceStateV1 {
            source,
            session,
            frame_id: BoundedAscii::new("map")
                .map_err(|_| SmokeError::after_durable("fixture-invariant"))?,
            publisher_t_ns: 0,
            receive_mono: now,
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
        mission_phase: AsciiId::new(FIXTURE_PHASE)
            .map_err(|_| SmokeError::after_durable("fixture-invariant"))?,
        plant_mode: AsciiId::new("NOMINAL")
            .map_err(|_| SmokeError::after_durable("fixture-invariant"))?,
    };
    let mission_signer = SigningKey::from_seed(MISSION_SIGNING_SEED);
    let mission_kid =
        fixture_key_id(2).map_err(|_| SmokeError::after_durable("fixture-invariant"))?;
    let signed_lease = sign_message(
        &lease,
        MissionLeaseV1::KIND,
        MissionLeaseV1::SCHEMA_MAJOR,
        &mission_kid,
        &mission_signer,
    );
    let activation = LiveIntentActivationInput::new(state, challenge, signed_lease)
        .map_err(|_| SmokeError::after_durable("activation-input"))?;
    let summary = ActivationSummary {
        controller_id: FIXTURE_CONTROLLER_ID.to_owned(),
        intent_route,
        lease_term: lease_term.get(),
        gate_boot_id: *report.gate_boot_id.as_bytes(),
        gate_output_epoch: *report.output_epoch.uuid().as_bytes(),
    };
    Ok((activation, summary))
}

fn nonzero_u32(value: u32) -> SmokeResult<NonZeroU32> {
    NonZeroU32::new(value).ok_or_else(|| SmokeError::after_durable("fixture-invariant"))
}

fn recovery_label(recovery: Option<RecoveryStatus>) -> &'static str {
    match recovery {
        None => "provisioned",
        Some(RecoveryStatus::Clean) => "clean",
        Some(RecoveryStatus::CompletedPendingAnchor) => "completed-pending-anchor",
    }
}

fn journal_json(report: JournalRecoveryReport, unknown_events: usize) -> Value {
    json!({
        "active_sequence": report.active_sequence.map(NonZeroU64::get),
        "closed_active_tail": report.closed_active_tail,
        "completed_segments": report.completed_segments,
        "discarded_pending_creation": report.discarded_pending_creation,
        "discovered_segments": report.discovered_segments,
        "quiesced": report.quiesced,
        "recovered_records": report.recovered_records,
        "recovery_unknown_events": unknown_events,
        "total_bytes": report.total_bytes,
        "truncated_tail_bytes": report.truncated_tail_bytes,
    })
}

fn counters_json(counters: IngressCountersSnapshot) -> Value {
    json!({
        "accepted": counters.accepted,
        "non_put_dropped": counters.non_put_dropped,
        "oversize_dropped": counters.oversize_dropped,
        "queue_full_dropped": counters.queue_full_dropped,
        "receiver_closed_dropped": counters.receiver_closed_dropped,
        "unexpected_key_dropped": counters.unexpected_key_dropped,
    })
}

fn record_bind_failure(path: &Path, error: SmokeError) -> SmokeError {
    let result = json!({
        "development_only": true,
        "failure": {
            "cleanup_classification": error.cleanup_classification,
            "durable_effects_may_have_committed": error.durable_effects_may_have_committed,
            "stage": error.stage
        },
        "mode": "development-live-bind-smoke-v1",
        "negative_evidence": {
            "commands_published_by_target": 0,
            "intents_processed_by_target": 0,
            "production_ready": false,
            "remote_session_retirement_evidence": false
        },
        "production_claim": false,
        "provisioned": false,
        "schema_version": RESULT_SCHEMA_VERSION,
        "status": "fail"
    });
    let _ = write_result(path, &result, error.durable_effects_may_have_committed);
    error
}

#[cfg(unix)]
fn write_result(path: &Path, value: &Value, durable: bool) -> SmokeResult<()> {
    fn error(durable: bool) -> SmokeError {
        if durable {
            SmokeError::after_durable("result-write")
        } else {
            SmokeError::before_durable("result-write")
        }
    }

    let temporary = result_temporary_path(path).map_err(|_| error(durable))?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut file = options.open(&temporary).map_err(|_| error(durable))?;
    use std::io::Write as _;
    let write = serde_json::to_writer_pretty(&mut file, value)
        .and_then(|()| file.write_all(b"\n").map_err(serde_json::Error::io))
        .and_then(|()| file.sync_all().map_err(serde_json::Error::io));
    drop(file);
    if write.is_err() {
        let _ = fs::remove_file(&temporary);
        return Err(error(durable));
    }
    if fs::hard_link(&temporary, path).is_err() {
        let _ = fs::remove_file(&temporary);
        return Err(error(durable));
    }
    if fs::remove_file(&temporary).is_err() {
        return Err(error(durable));
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| error(durable))
}

#[cfg(not(unix))]
fn write_result(_path: &Path, _value: &Value, _durable: bool) -> SmokeResult<()> {
    Err(SmokeError::before_durable("unsupported-platform"))
}

/// Provision a new disposable state+journal fixture without opening a network session.
pub fn provision_fixture(args: ProvisionArgs) -> SmokeResult<()> {
    let template = fixture_template()?;
    template
        .validate()
        .map_err(|_| SmokeError::before_durable("static-config"))?;
    let paths = FixturePaths::new(args.root);
    prepare_fresh_root(&paths)?;
    preflight_result_path(&args.result, &paths.root)?;
    let outer_lock = acquire_outer_lock(&paths.outer_lock, true)?;
    prepare_fresh_root(&paths)?;
    let clock = DevelopmentClock::new()?;
    let mut entropy = OsEntropy;
    let running = start_local(
        template,
        local_startup(&paths, StateOpenMode::ProvisionNew),
        StorageMacKey::new(STORAGE_MAC_BYTES),
        &mut entropy,
    )
    .map_err(|_| SmokeError::after_durable("state-provision"))?;
    let report = running.report();
    let journal_config = publication_journal_config(&paths, clock.now().as_nanos())
        .map_err(|_| SmokeError::after_durable("journal-config"))?;
    let bound = running
        .provision_publication_journal(journal_config)
        .map_err(|_| SmokeError::after_durable("journal-provision"))?;
    restrict_directory_after_provision(&paths.journal)?;
    let journal = bound.journal_recovery_report();
    let unknown_events = bound.recovery_unknown_events();
    let result = json!({
        "anchor_protection": "local-rewritable",
        "development_only": true,
        "journal": journal_json(journal, unknown_events),
        "mode": "development-live-fixture-provision-v1",
        "ncp_wire_profile": "exact-ncp-v0.8-json",
        "production_claim": false,
        "provisioned": true,
        "runtime_profile": "declared-live-zenoh",
        "schema_version": RESULT_SCHEMA_VERSION,
        "stages": [
            "static-config-validated",
            "outer-lock-acquired",
            "state-provisioned",
            "journal-provisioned"
        ],
        "startup_generation": report.boot_commit.generation,
        "status": "pass"
    });
    write_result(&args.result, &result, true)?;
    drop(bound);
    drop(outer_lock);
    Ok(())
}

/// Open the existing disposable fixture, bind the concrete aggregate, and shut it down.
pub async fn bind_and_shutdown(args: BindArgs) -> SmokeResult<()> {
    let template = fixture_template()?;
    template
        .validate()
        .map_err(|_| SmokeError::before_durable("static-config"))?;
    let paths = FixturePaths::new(args.root);
    require_existing_fixture(&paths)?;
    preflight_result_path(&args.result, &paths.root)?;
    let outer_lock = acquire_outer_lock(&paths.outer_lock, false)?;
    require_existing_fixture(&paths).map_err(|error| record_bind_failure(&args.result, error))?;
    require_regular_file(&args.zenoh_config, "zenoh-config-preflight")
        .map_err(|error| record_bind_failure(&args.result, error))?;
    let zenoh_config = SecureClientConfig::from_file(&args.zenoh_config)
        .map_err(|_| SmokeError::before_durable("zenoh-config"))
        .map_err(|error| record_bind_failure(&args.result, error))?;
    let clock =
        DevelopmentClock::new().map_err(|error| record_bind_failure(&args.result, error))?;
    let mut entropy = OsEntropy;
    let running = start_local(
        template,
        local_startup(&paths, StateOpenMode::OpenExisting),
        StorageMacKey::new(STORAGE_MAC_BYTES),
        &mut entropy,
    )
    .map_err(|_| SmokeError::after_durable("state-open"))
    .map_err(|error| record_bind_failure(&args.result, error))?;
    let report = running.report();
    let journal_config = publication_journal_config(&paths, clock.now().as_nanos())
        .map_err(|_| SmokeError::after_durable("journal-config"))
        .map_err(|error| record_bind_failure(&args.result, error))?;
    let bound = running
        .open_publication_journal(journal_config, None)
        .map_err(|_| SmokeError::after_durable("journal-open"))
        .map_err(|error| record_bind_failure(&args.result, error))?;
    let journal = bound.journal_recovery_report();
    let unknown_events = bound.recovery_unknown_events();
    let (activation, activation_summary) = build_activation(report, clock.now(), &mut entropy)
        .map_err(|error| record_bind_failure(&args.result, error))?;
    let kernel = DeclaredLiveGateKernel::start(bound, clock)
        .map_err(|_| SmokeError::after_durable("kernel-start"))
        .map_err(|error| record_bind_failure(&args.result, error))?;
    let route_bound = kernel
        .activate(activation)
        .map_err(|_| SmokeError::after_durable("local-activation"))
        .map_err(|error| record_bind_failure(&args.result, error))?;
    if route_bound.controller_id().as_str() != activation_summary.controller_id
        || route_bound.intent_route() != activation_summary.intent_route
    {
        return Err(record_bind_failure(
            &args.result,
            SmokeError::after_durable("route-cross-check"),
        ));
    }
    let limits = IngressLimits::new(HARD_MAX_INTENT_BYTES, 8)
        .map_err(|_| SmokeError::after_durable("ingress-limits"))
        .map_err(|error| record_bind_failure(&args.result, error))?;
    let session = SecureZenohSession::open(zenoh_config)
        .await
        .map_err(|_| {
            SmokeError::after_durable_with_cleanup(
                "session-open",
                "session-open-failed-no-session-owner",
            )
        })
        .map_err(|error| record_bind_failure(&args.result, error))?;
    let service = DeclaredLiveGateZenohService::bind(route_bound, session, limits)
        .await
        .map_err(|error| {
            let cleanup = if error.session_close_error().is_some() {
                "aggregate-bind-failed-session-close-failed"
            } else {
                "aggregate-bind-failed-session-close-ok"
            };
            SmokeError::after_durable_with_cleanup("aggregate-bind", cleanup)
        })
        .map_err(|error| record_bind_failure(&args.result, error))?;
    let zid = service.zid();
    let shutdown = service
        .shutdown()
        .await
        .map_err(|error| {
            let cleanup = match error {
                LiveZenohShutdownError::Ingress(_) => {
                    "aggregate-shutdown-ingress-failed-session-close-ok"
                }
                LiveZenohShutdownError::Session(_) => {
                    "aggregate-shutdown-ingress-ok-session-close-failed"
                }
                LiveZenohShutdownError::IngressAndSession { .. } => {
                    "aggregate-shutdown-ingress-and-session-close-failed"
                }
                _ => "aggregate-shutdown-unclassified-cleanup-failure",
            };
            SmokeError::after_durable_with_cleanup("aggregate-shutdown", cleanup)
        })
        .map_err(|error| record_bind_failure(&args.result, error))?;
    let result = json!({
        "anchor_protection": match report.anchor_protection {
            AnchorProtection::LocalRewritable => "local-rewritable",
            AnchorProtection::EphemeralTest => "unexpected-ephemeral-test",
            AnchorProtection::ExternalNonRewindable => "unexpected-external-nonrewindable",
        },
        "bind_returned_ok": true,
        "controller_id": activation_summary.controller_id,
        "development_only": true,
        "discarded_events": shutdown.discarded_events(),
        "gate_boot_id": activation_summary.gate_boot_id,
        "gate_output_epoch": activation_summary.gate_output_epoch,
        "ingress_counters": counters_json(shutdown.ingress_counters()),
        "intent_route": activation_summary.intent_route,
        "journal": journal_json(journal, unknown_events),
        "lease_term": activation_summary.lease_term,
        "local_returns": {
            "aggregate_bind": true,
            "aggregate_shutdown": true,
            "session_open": true
        },
        "mode": "development-live-bind-smoke-v1",
        "ncp_wire_profile": "exact-ncp-v0.8-json",
        "negative_evidence": {
            "acl_exclusivity_evidence": false,
            "authenticated_control_ingress": false,
            "commands_published_by_target": 0,
            "complete_mediation_evidence": false,
            "credential_custody_evidence": false,
            "intents_processed_by_target": 0,
            "journal_finalization_evidence": false,
            "production_ready": false,
            "remote_session_retirement_evidence": false,
            "zid_is_authenticated_principal": false
        },
        "production_claim": false,
        "provisioned": false,
        "runtime_profile": "declared-live-zenoh",
        "schema_version": RESULT_SCHEMA_VERSION,
        "shutdown_returned_ok": true,
        "stages": [
            "static-config-validated",
            "outer-lock-acquired",
            "zenoh-config-validated",
            "state-opened",
            "journal-opened",
            "local-activation-accepted",
            "session-opened",
            "aggregate-bound",
            "aggregate-shutdown"
        ],
        "startup_generation": report.boot_commit.generation,
        "startup_recovery": recovery_label(report.recovery),
        "status": "pass",
        "zid": {
            "authenticated_principal": false,
            "operational_identifier": zid
        }
    });
    write_result(&args.result, &result, true)?;
    drop(outer_lock);
    Ok(())
}
