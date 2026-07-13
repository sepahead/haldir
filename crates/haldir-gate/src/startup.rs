//! Durable Gate startup orchestration.
//!
//! Startup validates the static actor configuration and deployment profile,
//! obtains both runtime identifiers' entropy, acquires a retained instance lock,
//! explicitly provisions or opens durable state, and commits a new boot before
//! constructing [`VehicleActor`].

use std::fs::{self, File, OpenOptions, TryLockError};
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};

use haldir_admission::AdmissionSnapshot;
use haldir_contracts::digest::DigestV1;
use haldir_contracts::ids::{GateBootId, GateId, GateOutputEpoch, KeyId, VehicleId};
use haldir_contracts::scalar::{AsciiId, CanonicalUuidV4String};
use haldir_contracts::session::NcpSessionIdentityV1;
use haldir_contracts::status::PlantPublicationAuthorityStateV1;
use haldir_crypto::{RevocationSnapshot, SigningKey, TrustStore};
use haldir_durable::{
    AnchorProtection, AtomicFileSnapshot, CommitReceipt, GenerationAnchor,
    LocalFileGenerationAnchor, RecoveryStatus, SnapshotBinding, SnapshotStorage, StorageMacKey,
    StoreId,
};
use haldir_policy_native::NativePolicySnapshot;
use haldir_state::{DurableAntiRollbackError, DurableAntiRollbackStore};

use crate::actor::{
    GateConfig, GateConfigError, GateStartupError, VehicleActor, validate_static_config,
};

const ENTROPY_BYTES: usize = 48;
const BOOT_ENTROPY_BYTES: usize = 32;
const LOCAL_SNAPSHOT_OVERHEAD_ALLOWANCE: usize = 1024;
const LOCAL_SNAPSHOT_FILE: &str = "anti-rollback.snapshot";
const LOCAL_ANCHOR_FILE: &str = "generation.anchor";
const LOCAL_LOCK_FILE: &str = ".haldir-gate.lock";

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
    /// Policy snapshot digest.
    pub policy_snapshot_digest: DigestV1,
    /// Current NCP session.
    pub session: NcpSessionIdentityV1,
    /// Current ACL-only plant-publication authority evidence.
    pub publication: PlantPublicationAuthorityStateV1,
    /// Local cap on lease active duration (ms).
    pub local_cap_ms: u32,
    /// Gate application signing key.
    pub gate_signer: SigningKey,
    /// Gate application signing key id.
    pub gate_signer_kid: KeyId,
}

impl GateConfigTemplate {
    /// Validate every static invariant without opening or changing durable state.
    ///
    /// # Errors
    /// Returns when signer/cap validation fails or publication authority is not
    /// the current `PRE_AUTHORITY_ACL_ONLY` profile.
    pub fn validate(&self) -> Result<(), DurableGateStartupError> {
        validate_static_config(
            &self.gate_id,
            &self.trust,
            &self.revocations,
            self.local_cap_ms,
            &self.gate_signer,
            &self.gate_signer_kid,
        )
        .map_err(DurableGateStartupError::Config)?;
        if !matches!(
            self.publication,
            PlantPublicationAuthorityStateV1::AclExclusiveV1(_)
        ) {
            return Err(DurableGateStartupError::UnsupportedPublicationProfile);
        }
        Ok(())
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
    /// Assurance startup with an independently administered non-rewindable anchor.
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
    /// Whether generation one was explicitly provisioned by this call.
    pub provisioned: bool,
    /// Existing-state reconciliation result, absent only for provisioning.
    pub recovery: Option<RecoveryStatus>,
    /// Receipt for the freshly committed boot generation.
    pub boot_commit: CommitReceipt,
    /// Protection class declared by the selected generation anchor.
    pub anchor_protection: AnchorProtection,
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
    _instance_lock: File,
}

impl RunningGate {
    /// Started vehicle actor.
    #[must_use]
    pub const fn actor(&self) -> &VehicleActor {
        &self.actor
    }

    /// Started vehicle actor for serialized event processing.
    #[must_use]
    pub const fn actor_mut(&mut self) -> &mut VehicleActor {
        &mut self.actor
    }

    /// Durable startup report.
    #[must_use]
    pub const fn report(&self) -> StartupReport {
        self.report
    }
}

/// Durable startup orchestration failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DurableGateStartupError {
    /// Static actor configuration failed validation.
    Config(GateConfigError),
    /// Publication authority is not the current ACL-only profile.
    UnsupportedPublicationProfile,
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

/// Validate, lock, explicitly open/provision arbitrary durable backends, commit
/// a fresh boot, and construct the actor.
///
/// # Errors
/// Returns before backend access for invalid configuration, profile mismatch, or
/// entropy failure. Missing state under [`StateOpenMode::OpenExisting`] is never
/// provisioned. Backend, lock, boot-commit, and actor-construction errors fail closed.
/// The lock path must be distinct from every backend path, and all backend writers
/// must cooperate on that same lock.
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
    let prepared = prepare(&template, &state, &anchor, entropy)?;
    start_prepared(template, state, storage, anchor, key, prepared)
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

    let prepared = prepare(&template, &state, &anchor, entropy)?;
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

struct PreparedStartup {
    boot_entropy: [u8; BOOT_ENTROPY_BYTES],
    output_epoch: GateOutputEpoch,
    anchor_protection: AnchorProtection,
}

fn prepare<A: GenerationAnchor, E: EntropySource + ?Sized>(
    template: &GateConfigTemplate,
    state: &StartupStateConfig,
    anchor: &A,
    entropy: &mut E,
) -> Result<PreparedStartup, DurableGateStartupError> {
    template.validate()?;
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

    let mut bytes = [0u8; ENTROPY_BYTES];
    entropy
        .fill_bytes(&mut bytes)
        .map_err(|_| DurableGateStartupError::EntropyUnavailable)?;
    let boot_entropy = bytes
        .get(..BOOT_ENTROPY_BYTES)
        .and_then(|value| value.try_into().ok())
        .ok_or(DurableGateStartupError::EntropyUnavailable)?;
    let output_random = bytes
        .get(BOOT_ENTROPY_BYTES..)
        .and_then(|value| value.try_into().ok())
        .ok_or(DurableGateStartupError::EntropyUnavailable)?;
    let output_epoch =
        GateOutputEpoch::new(CanonicalUuidV4String::from_random_bytes(output_random));

    Ok(PreparedStartup {
        boot_entropy,
        output_epoch,
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
    let config = template.into_runtime(gate_boot_id, prepared.output_epoch);
    let actor = VehicleActor::new_recovered(config, booted)?;
    let report = StartupReport {
        provisioned,
        recovery,
        boot_commit,
        anchor_protection: prepared.anchor_protection,
        gate_boot_id,
        output_epoch: prepared.output_epoch,
    };

    Ok(RunningGate {
        actor,
        report,
        _instance_lock: instance_lock,
    })
}

fn acquire_instance_lock(path: &Path) -> Result<File, DurableGateStartupError> {
    if let Ok(metadata) = fs::symlink_metadata(path)
        && !metadata.file_type().is_file()
    {
        return Err(DurableGateStartupError::LockUnavailable);
    }

    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    options.mode(0o600);
    let file = options
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
        Ok(()) => Ok(file),
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
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};

    use haldir_contracts::digest::DigestDomain;
    use haldir_contracts::ids::PrincipalId;
    use haldir_contracts::status::{AclExclusiveEvidenceV1, PlantPublicationUnavailableReasonV1};
    use haldir_crypto::{KeyClass, KeyRecord, KeyRole};
    use haldir_durable::{Anchor, DurableError};
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

    fn digest(bytes: &[u8]) -> DigestV1 {
        DigestV1::compute(DigestDomain::Payload, bytes)
    }

    fn template() -> GateConfigTemplate {
        let gate_id = GateId::new("gate-1").unwrap();
        let gate_signer_kid = KeyId::new(vec![3]).unwrap();
        let gate_signer = SigningKey::from_seed([3; 32]);
        let mut trust = TrustStore::new();
        trust
            .insert(KeyRecord {
                kid: gate_signer_kid.clone(),
                role: KeyRole::GateApplication,
                verifying_key: gate_signer.verifying_key(),
                subject: Some(gate_id.as_str().to_owned()),
                class: KeyClass::Assurance,
            })
            .unwrap();

        GateConfigTemplate {
            gate_id,
            realm: AsciiId::new("range-a").unwrap(),
            vehicle_id: VehicleId::new("uav-1").unwrap(),
            trust,
            revocations: RevocationSnapshot::new(),
            admission: AdmissionSnapshot::new(),
            policy: NativePolicySnapshot {
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
                phase_rules: Vec::new(),
            },
            policy_snapshot_digest: digest(b"policy"),
            session: NcpSessionIdentityV1 {
                session_id: AsciiId::new("session-1").unwrap(),
                generation: CanonicalUuidV4String::from_random_bytes([1; 16]),
            },
            publication: PlantPublicationAuthorityStateV1::AclExclusiveV1(AclExclusiveEvidenceV1 {
                gate_transport_principal: PrincipalId::new("gate-transport").unwrap(),
                final_route_digest: digest(b"route"),
                certificate_fingerprint: digest(b"certificate"),
                acl_policy_digest: digest(b"acl"),
                verified_at_mono_ns: 1,
            }),
            local_cap_ms: 1_000,
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
        StorageMacKey::new([7; 32])
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
    fn invalid_static_config_precedes_entropy_and_durable_generation() {
        let directory = TestDirectory::new();
        let storage = MemoryStorage::default();
        let anchor = MemoryAnchor::default();
        let mut invalid = template();
        invalid.local_cap_ms = 0;
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
                GateConfigError::LocalCapZero
            ))
        ));
        assert_eq!(entropy.calls, 0);
        assert!(storage.0.lock().unwrap().is_none());
        assert!(anchor.head.lock().unwrap().is_none());
    }

    #[test]
    fn non_acl_publication_profile_is_rejected_before_entropy() {
        let directory = TestDirectory::new();
        let storage = MemoryStorage::default();
        let anchor = MemoryAnchor::default();
        let mut invalid = template();
        invalid.publication = PlantPublicationAuthorityStateV1::Unavailable {
            reason: PlantPublicationUnavailableReasonV1::AclNotProvisioned,
        };
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
    fn running_gate_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<RunningGate>();
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
