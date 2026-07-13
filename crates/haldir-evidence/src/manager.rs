//! Bounded single-writer directory orchestration for evidence segments.
//!
//! The manager owns the directory lock, verifies the complete on-disk chain,
//! closes a recovered prior-boot tail, and rotates segments without retrying a
//! record after an ambiguous commit. It retains only the configured signer's
//! public identity and borrows the private key for operations that may commit a
//! footer. It inherits the segment primitive's narrow
//! Unix process-crash scope; it does not claim power-loss durability or an
//! external non-rewindable witness.

use core::num::NonZeroU64;
use haldir_contracts::ids::{GateBootId, GateId, KeyId};
use haldir_crypto::{SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions, TryLockError};
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use crate::journal::{
    ActiveEvidenceSegment, CompletedSegment, JournalBounds, JournalError, OpenRecoveryStatus,
    PENDING_CREATION_PREFIX, RecoveredEvidenceSegment, SegmentIdentity,
};

const LOCK_FILE_NAME: &str = ".haldir-evidence.lock";
const SEGMENT_PREFIX: &str = "segment-";
const SEGMENT_DIGITS: usize = 20;
const RECORD_DIGEST_DOMAIN: &[u8] = b"haldir.evidence.record-digest.v1\0";

/// Stable digest of one exact opaque evidence envelope.
///
/// The manager rejects the same bytes twice across the complete retained
/// journal. After an ambiguous append or process crash, callers can recompute
/// this value and query the recovered manager before deciding whether to retry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EvidenceRecordDigest([u8; 32]);

impl EvidenceRecordDigest {
    /// Domain-separated digest of the exact record bytes.
    #[must_use]
    pub fn compute(record: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(RECORD_DIGEST_DOMAIN);
        hasher.update(
            u64::try_from(record.len())
                .unwrap_or(u64::MAX)
                .to_be_bytes(),
        );
        hasher.update(record);
        Self(hasher.finalize().into())
    }

    /// Digest bytes for persistence or comparison by an orchestrator.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Verification failure reported by a journal consumer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum JournalVerificationError {
    /// The header signer was not trusted for this segment identity.
    UnknownSigner,
    /// An opaque record failed the consumer's canonical/signature validation.
    InvalidRecord,
}

/// Dimension that rejected an opt-in recovery capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RecoveryCaptureDimension {
    /// Number of complete opaque records.
    RecordCount,
    /// Sum of exact opaque record-envelope bytes, excluding journal framing.
    RecordBytes,
}

/// Resolves segment signing keys and validates every opaque record.
pub trait JournalVerifier {
    /// Resolve the header identity to its trusted verifying key.
    fn resolve_signer(
        &self,
        identity: &SegmentIdentity,
    ) -> Result<VerifyingKey, JournalVerificationError>;

    /// Validate one recovered or newly submitted opaque record candidate.
    ///
    /// Implementations must be deterministic and side-effect-free. This method
    /// also runs before append capacity and commit are known, so success is not a
    /// durable-append callback and must never advance a reducer.
    fn validate_record(
        &self,
        identity: &SegmentIdentity,
        record: &[u8],
    ) -> Result<(), JournalVerificationError>;
}

/// Directory-manager failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum JournalManagerError {
    /// A segment primitive operation failed.
    Journal(JournalError),
    /// Consumer key or record validation failed.
    Verification(JournalVerificationError),
    /// Another manager retains the directory's exclusive lock.
    LockHeld,
    /// Existing journal state was required but absent.
    Missing,
    /// Provisioning was requested for a directory that already held state.
    AlreadyProvisioned,
    /// Initial segment publication was interrupted and requires operator repair.
    IncompleteProvisioning,
    /// The directory path or an I/O operation failed.
    Storage,
    /// A directory entry was not the lock file or a canonical segment filename.
    UnexpectedEntry,
    /// Two headers claimed the same segment sequence.
    DuplicateSequence,
    /// A sequence advanced beyond the next required value.
    SequenceGap,
    /// A sequence or previous digest rewound to older completed state.
    Rewind,
    /// The previous digest did not name the immediately preceding segment.
    Fork,
    /// More than one open segment, or an open segment before the tail, was found.
    MultipleActive,
    /// A segment claimed another Gate identity.
    GateMismatch,
    /// An open recovered tail had no supplied matching historical signer.
    TailSignerUnavailable,
    /// The configured global journal limit has quiesced further appends.
    Quiesced,
    /// The requested reservation or ordinary append would consume logical
    /// capacity retained for another reservation.
    ReservationUnavailable,
    /// A reservation token belongs to another manager instance.
    ReservationMismatch,
    /// A reservation token has no remaining record units.
    ReservationExhausted,
    /// A commit-ambiguous operation requires full recovery before reuse.
    Poisoned,
    /// The exact record bytes already exist in the retained journal.
    DuplicateRecord,
    /// An append-related write may or may not have committed these exact bytes.
    /// Reopen and query [`EvidenceJournalManager::contains_record`] before retrying.
    AppendCommitAmbiguous {
        /// Digest of the exact attempted record bytes.
        record_digest: EvidenceRecordDigest,
    },
    /// The checked segment-sequence namespace is exhausted.
    SequenceExhausted,
    /// Opt-in recovered-record capture exceeded an explicit bound.
    RecoveryCaptureLimitExceeded {
        /// Rejected capture dimension.
        dimension: RecoveryCaptureDimension,
        /// Configured inclusive maximum.
        maximum: u64,
        /// Required value, saturating at `u64::MAX` on arithmetic overflow.
        required: u64,
    },
    /// Bounded snapshot storage could not be reserved before closing a recovered
    /// active tail.
    RecoveryCaptureAllocation,
    /// An in-process recovery consumer rejected the complete ordered snapshot
    /// before prior-tail closure and current-segment creation.
    RecoveryConsumerRejected,
}

impl From<JournalError> for JournalManagerError {
    fn from(error: JournalError) -> Self {
        Self::Journal(error)
    }
}

impl From<JournalVerificationError> for JournalManagerError {
    fn from(error: JournalVerificationError) -> Self {
        Self::Verification(error)
    }
}

/// Whole-journal limits. Completed segments are never deleted automatically.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JournalLimits {
    segment: JournalBounds,
    max_segments: usize,
    max_total_bytes: u64,
}

impl JournalLimits {
    /// Construct nonzero global limits around one segment profile.
    ///
    /// # Errors
    /// Returns [`JournalManagerError::Quiesced`] for unusable limits.
    pub fn new(
        segment: JournalBounds,
        max_segments: usize,
        max_total_bytes: u64,
    ) -> Result<Self, JournalManagerError> {
        if max_segments == 0 || max_total_bytes == 0 {
            return Err(JournalManagerError::Quiesced);
        }
        Ok(Self {
            segment,
            max_segments,
            max_total_bytes,
        })
    }

    /// Per-segment bounds.
    #[must_use]
    pub const fn segment(self) -> JournalBounds {
        self.segment
    }
}

/// Borrowed Gate application signer for one journal operation.
///
/// The manager retains only the public signer identity. Keeping the private key
/// behind this short-lived, non-cloneable borrow lets one runtime component own
/// the key while the journal uses it only at footer commit boundaries.
pub struct JournalSigner<'key> {
    kid: &'key KeyId,
    key: &'key SigningKey,
}

/// Move-only logical capacity for future maximum-sized record appends.
///
/// A token is bound to the manager that issued it. It does not reserve or
/// preallocate filesystem space, and a write may still fail or become
/// commit-ambiguous.
#[must_use = "dropping a live reservation intentionally strands its quota until manager recovery"]
pub struct JournalReservation {
    owner: Arc<ReservationOwner>,
    remaining_records: usize,
    bytes_per_record: u64,
    remaining_bytes: u64,
}

/// Identity, time, and bounds for opening the journal for one Gate boot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalOpenOptions {
    gate_id: GateId,
    gate_boot_id: GateBootId,
    created_mono_ns: u64,
    limits: JournalLimits,
}

impl JournalOpenOptions {
    /// Describe the current boot and the complete directory limits.
    #[must_use]
    pub const fn new(
        gate_id: GateId,
        gate_boot_id: GateBootId,
        created_mono_ns: u64,
        limits: JournalLimits,
    ) -> Self {
        Self {
            gate_id,
            gate_boot_id,
            created_mono_ns,
            limits,
        }
    }

    /// Current boot selected by the higher-level fused adapter.
    #[must_use]
    pub(crate) const fn gate_boot_id(&self) -> GateBootId {
        self.gate_boot_id
    }

    /// Monotonic creation/observation time for the planned current segment.
    #[must_use]
    pub(crate) const fn created_mono_ns(&self) -> u64 {
        self.created_mono_ns
    }
}

impl<'key> JournalSigner<'key> {
    /// Borrow a key identifier and its private signing key.
    #[must_use]
    pub const fn new(kid: &'key KeyId, key: &'key SigningKey) -> Self {
        Self { kid, key }
    }

    #[must_use]
    pub(crate) const fn kid(&self) -> &KeyId {
        self.kid
    }

    #[must_use]
    pub(crate) const fn key(&self) -> &SigningKey {
        self.key
    }
}

/// Deterministic result of opening and reconciling a journal directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JournalRecoveryReport {
    /// Segment files discovered before recovery created the current tail.
    pub discovered_segments: usize,
    /// Completed segments after any recovered tail was closed.
    pub completed_segments: usize,
    /// Complete records validated while recovering existing segments.
    pub recovered_records: u64,
    /// Bytes removed from an insufficient final frame/footer tail.
    pub truncated_tail_bytes: u64,
    /// Whether recovery closed an open prior tail before starting this boot.
    pub closed_active_tail: bool,
    /// Whether recovery discarded one unpublished atomic-creation artifact.
    pub discarded_pending_creation: bool,
    /// New active sequence, absent when global limits caused quiescence.
    pub active_sequence: Option<NonZeroU64>,
    /// Actual segment bytes after recovery and current-tail creation.
    pub total_bytes: u64,
    /// Whether global limits prevent further mutation.
    pub quiesced: bool,
}

/// Explicit memory bounds for an opt-in recovered-record snapshot.
///
/// `max_total_record_bytes` counts the aggregate exact opaque record-envelope
/// bytes, excluding journal framing and per-segment identities. A zero record cap
/// permits only empty segments; a zero byte cap may still capture zero-length
/// records within the record-count cap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryCaptureLimits {
    max_records: u64,
    max_total_record_bytes: u64,
}

impl RecoveryCaptureLimits {
    /// Construct exact count and aggregate opaque-record byte caps.
    #[must_use]
    pub const fn new(max_records: u64, max_total_record_bytes: u64) -> Self {
        Self {
            max_records,
            max_total_record_bytes,
        }
    }

    /// Maximum complete records admitted into one recovery snapshot.
    #[must_use]
    pub const fn max_records(self) -> u64 {
        self.max_records
    }

    /// Maximum aggregate exact opaque record bytes admitted into one recovery
    /// snapshot.
    #[must_use]
    pub const fn max_total_record_bytes(self) -> u64 {
        self.max_total_record_bytes
    }
}

/// One authenticated journal segment and its verifier-accepted opaque records.
///
/// Fields are private and no byte-revealing `Debug` or accidental `Clone` is
/// provided. Empty recovered segments are retained to preserve exact ordering and
/// identity context.
pub struct RecoveredJournalSegment {
    identity: SegmentIdentity,
    records: Vec<Vec<u8>>,
}

impl RecoveredJournalSegment {
    /// Authenticated segment identity in recovered journal order.
    #[must_use]
    pub const fn identity(&self) -> &SegmentIdentity {
        &self.identity
    }

    /// Verifier-accepted opaque records in append order.
    pub fn records(&self) -> impl ExactSizeIterator<Item = &[u8]> + '_ {
        self.records.iter().map(Vec::as_slice)
    }

    /// Number of records in this segment.
    #[must_use]
    pub fn record_count(&self) -> usize {
        self.records.len()
    }
}

/// Complete opt-in snapshot returned only after journal open/recovery succeeds.
///
/// The snapshot proves authenticated segment order and candidate-verifier
/// acceptance of opaque bytes. It does not by itself prove COSE semantics or make
/// a stateful verifier safe.
pub struct JournalRecovery {
    report: JournalRecoveryReport,
    segments: Vec<RecoveredJournalSegment>,
    record_bytes: u64,
}

/// Internal records accepted by a fused semantic recovery consumer for append
/// under the newly created current-boot segment before open returns.
pub(crate) struct RecoveryPrecommitPlan {
    records: Vec<Vec<u8>>,
}

impl RecoveryPrecommitPlan {
    /// Accept recovery without current-boot startup records.
    #[must_use]
    pub(crate) const fn empty() -> Self {
        Self {
            records: Vec::new(),
        }
    }

    /// Append this complete bounded record batch before returning the manager.
    #[must_use]
    pub(crate) const fn with_records(records: Vec<Vec<u8>>) -> Self {
        Self { records }
    }
}

impl JournalRecovery {
    /// Ordinary recovery metadata for the same successful open.
    #[must_use]
    pub const fn report(&self) -> JournalRecoveryReport {
        self.report
    }

    /// Recovered segments in canonical sequence order, excluding the newly
    /// created current-boot tail.
    #[must_use]
    pub fn segments(&self) -> &[RecoveredJournalSegment] {
        &self.segments
    }

    /// Flatten recovered records in exact segment then append order while
    /// preserving each record's authenticated segment identity.
    pub fn records(&self) -> impl Iterator<Item = (&SegmentIdentity, &[u8])> {
        self.segments.iter().flat_map(|segment| {
            segment
                .records
                .iter()
                .map(move |record| (&segment.identity, record.as_slice()))
        })
    }

    /// Captured exact opaque record-envelope bytes, excluding journal framing.
    #[must_use]
    pub const fn record_bytes(&self) -> u64 {
        self.record_bytes
    }
}

/// Single-writer bounded evidence journal.
pub struct EvidenceJournalManager<V> {
    directory: PathBuf,
    _lock_file: File,
    verifier: V,
    signer_kid: KeyId,
    signer_public_key: [u8; 32],
    gate_id: GateId,
    gate_boot_id: GateBootId,
    limits: JournalLimits,
    active: Option<ActiveEvidenceSegment>,
    last_completed: Option<CompletedSegment>,
    segment_count: usize,
    total_bytes: u64,
    record_digests: BTreeSet<EvidenceRecordDigest>,
    reservation_owner: Arc<ReservationOwner>,
    reserved_segment_slots: usize,
    reserved_bytes: u64,
    poisoned: bool,
    quiesced: bool,
}

struct ReservationOwner;

#[derive(Clone, Copy)]
struct AppendCapacity {
    reserved_segment_slots_after_append: usize,
    reserved_bytes_after_append: u64,
    consumes_reservation: bool,
}

impl AppendCapacity {
    const fn ordinary(reserved_segment_slots: usize, reserved_bytes: u64) -> Self {
        Self {
            reserved_segment_slots_after_append: reserved_segment_slots,
            reserved_bytes_after_append: reserved_bytes,
            consumes_reservation: false,
        }
    }
}

struct PreparedReservationConsumption {
    capacity: AppendCapacity,
    token_remaining_records: usize,
    token_remaining_bytes: u64,
}

impl<V: JournalVerifier> EvidenceJournalManager<V> {
    /// Explicitly provision an empty dedicated directory and create genesis.
    ///
    /// Existing segment, lock, or interrupted-publication state is never
    /// overwritten or adopted as a fresh journal.
    ///
    /// # Errors
    /// Returns [`JournalManagerError::AlreadyProvisioned`] for any existing
    /// journal state, or another validation/storage error.
    pub fn provision_new(
        directory: impl Into<PathBuf>,
        options: JournalOpenOptions,
        signer: &JournalSigner<'_>,
        verifier: V,
    ) -> Result<(Self, JournalRecoveryReport), JournalManagerError> {
        let (manager, report, _) = Self::open_inner(
            directory.into(),
            options,
            signer,
            None,
            OpenBehavior::new(OpenMode::ProvisionNew, None, None),
            verifier,
        )?;
        Ok((manager, report))
    }

    /// Explicitly provision a journal and opt in to bounded recovered-record
    /// capture. A fresh journal returns an empty snapshot; this symmetric entry
    /// point lets callers use one startup flow for provision and reopen.
    ///
    /// # Errors
    /// Returns the errors documented by [`Self::provision_new`] plus
    /// recovery capture limit/allocation failures.
    pub fn provision_new_with_recovered_records(
        directory: impl Into<PathBuf>,
        options: JournalOpenOptions,
        signer: &JournalSigner<'_>,
        capture_limits: RecoveryCaptureLimits,
        verifier: V,
    ) -> Result<(Self, JournalRecovery), JournalManagerError> {
        let (manager, _, recovery) = Self::open_inner(
            directory.into(),
            options,
            signer,
            None,
            OpenBehavior::new(OpenMode::ProvisionNew, Some(capture_limits), None),
            verifier,
        )?;
        Ok((
            manager,
            recovery.ok_or(JournalManagerError::RecoveryCaptureAllocation)?,
        ))
    }

    /// Open, verify, and recover an existing dedicated journal directory.
    ///
    /// Any recovered open tail is validated and footer-completed only with the
    /// separately supplied historical signer when its KID and public key match
    /// exactly. An unpublished atomic-creation artifact may be discarded; the
    /// manager never deletes completed segments or repairs gaps/forks.
    ///
    /// # Errors
    /// Returns on lock contention, unexpected entries, chain/identity failure,
    /// invalid records/signers, storage failure, or ambiguous tail completion.
    pub fn open_existing(
        directory: impl Into<PathBuf>,
        options: JournalOpenOptions,
        signer: &JournalSigner<'_>,
        recovered_tail_signer: Option<&JournalSigner<'_>>,
        verifier: V,
    ) -> Result<(Self, JournalRecoveryReport), JournalManagerError> {
        let (manager, report, _) = Self::open_inner(
            directory.into(),
            options,
            signer,
            recovered_tail_signer,
            OpenBehavior::new(OpenMode::OpenExisting, None, None),
            verifier,
        )?;
        Ok((manager, report))
    }

    /// Open and recover an existing journal while returning a bounded snapshot
    /// of every verifier-accepted opaque record in authenticated journal order.
    ///
    /// The snapshot is returned only after the entire chain verifies, any old
    /// active tail closes, and current-tail creation or quiescence succeeds. A
    /// capture-limit failure returns no partial snapshot, though ordinary recovery
    /// may already have removed an insufficient tail or pending creation artifact.
    ///
    /// # Errors
    /// Returns the errors documented by [`Self::open_existing`] plus
    /// recovery capture limit/allocation failures.
    pub fn open_existing_with_recovered_records(
        directory: impl Into<PathBuf>,
        options: JournalOpenOptions,
        signer: &JournalSigner<'_>,
        recovered_tail_signer: Option<&JournalSigner<'_>>,
        capture_limits: RecoveryCaptureLimits,
        verifier: V,
    ) -> Result<(Self, JournalRecovery), JournalManagerError> {
        let (manager, _, recovery) = Self::open_inner(
            directory.into(),
            options,
            signer,
            recovered_tail_signer,
            OpenBehavior::new(OpenMode::OpenExisting, Some(capture_limits), None),
            verifier,
        )?;
        Ok((
            manager,
            recovery.ok_or(JournalManagerError::RecoveryCaptureAllocation)?,
        ))
    }

    /// Provision a fresh journal only after an in-process consumer accepts the
    /// complete empty ordered snapshot. Used by fused semantic adapters so a
    /// rejection cannot publish a current segment.
    pub(crate) fn provision_new_with_recovery_precommit(
        directory: impl Into<PathBuf>,
        options: JournalOpenOptions,
        signer: &JournalSigner<'_>,
        capture_limits: RecoveryCaptureLimits,
        verifier: V,
        precommit: &mut dyn FnMut(
            &JournalRecovery,
        ) -> Result<RecoveryPrecommitPlan, JournalManagerError>,
    ) -> Result<(Self, JournalRecoveryReport), JournalManagerError> {
        let (manager, report, _) = Self::open_inner(
            directory.into(),
            options,
            signer,
            None,
            OpenBehavior::new(
                OpenMode::ProvisionNew,
                Some(capture_limits),
                Some(precommit),
            ),
            verifier,
        )?;
        Ok((manager, report))
    }

    /// Recover an existing journal only after an in-process consumer accepts
    /// the complete ordered snapshot. Prior-tail closure and current-segment
    /// creation occur after the callback succeeds.
    pub(crate) fn open_existing_with_recovery_precommit(
        directory: impl Into<PathBuf>,
        options: JournalOpenOptions,
        signer: &JournalSigner<'_>,
        recovered_tail_signer: Option<&JournalSigner<'_>>,
        capture_limits: RecoveryCaptureLimits,
        verifier: V,
        precommit: &mut dyn FnMut(
            &JournalRecovery,
        ) -> Result<RecoveryPrecommitPlan, JournalManagerError>,
    ) -> Result<(Self, JournalRecoveryReport), JournalManagerError> {
        let (manager, report, _) = Self::open_inner(
            directory.into(),
            options,
            signer,
            recovered_tail_signer,
            OpenBehavior::new(
                OpenMode::OpenExisting,
                Some(capture_limits),
                Some(precommit),
            ),
            verifier,
        )?;
        Ok((manager, report))
    }

    fn open_inner(
        directory: PathBuf,
        options: JournalOpenOptions,
        signer: &JournalSigner<'_>,
        recovered_tail_signer: Option<&JournalSigner<'_>>,
        behavior: OpenBehavior<'_>,
        verifier: V,
    ) -> Result<(Self, JournalRecoveryReport, Option<JournalRecovery>), JournalManagerError> {
        let OpenBehavior {
            mode,
            capture_limits,
            mut recovery_precommit,
        } = behavior;
        let JournalOpenOptions {
            gate_id,
            gate_boot_id,
            created_mono_ns,
            limits,
        } = options;
        if mode == OpenMode::ProvisionNew {
            let identity = SegmentIdentity {
                gate_id: gate_id.clone(),
                gate_boot_id,
                segment_sequence: NonZeroU64::new(1)
                    .ok_or(JournalManagerError::SequenceExhausted)?,
                previous_completed_digest: [0; 32],
                created_mono_ns,
                signer_kid: signer.kid.clone(),
                signer_public_key: signer.key.verifying_key().to_bytes(),
            };
            ensure_matching_signer(&verifier, &identity, signer)?;
            let minimum = ActiveEvidenceSegment::minimum_complete_bytes(&identity)?;
            if minimum > limits.segment.max_segment_bytes() {
                return Err(JournalManagerError::Journal(JournalError::Bounds));
            }
            if !fits_total(0, minimum, 0, limits.max_total_bytes) {
                return Err(JournalManagerError::Quiesced);
            }
        }
        let directory = prepare_directory(directory, mode)?;
        let lock_file = lock_directory(&directory, mode)?;
        let (entries, pending_creation) = discover_segments(&directory, limits.max_segments)?;
        match mode {
            OpenMode::ProvisionNew if !entries.is_empty() || pending_creation.is_some() => {
                return Err(JournalManagerError::AlreadyProvisioned);
            }
            OpenMode::OpenExisting if entries.is_empty() && pending_creation.is_some() => {
                return Err(JournalManagerError::IncompleteProvisioning);
            }
            OpenMode::OpenExisting if entries.is_empty() => {
                return Err(JournalManagerError::Missing);
            }
            _ => {}
        }
        let discarded_pending_creation = if let Some(path) = pending_creation {
            fs::remove_file(path).map_err(|_| JournalManagerError::Storage)?;
            sync_directory(&directory)?;
            true
        } else {
            false
        };
        let discovered_segments = entries.len();
        let mut seen_sequences = BTreeSet::new();
        let mut completed_digests = BTreeSet::new();
        let mut expected_sequence = 1u64;
        let mut completed_segments = 0usize;
        let mut recovered_records = 0u64;
        let mut truncated_tail_bytes = 0u64;
        let mut total_bytes = 0u64;
        let mut last_completed: Option<CompletedSegment> = None;
        let mut recovered_active: Option<(ActiveEvidenceSegment, OpenRecoveryStatus)> = None;
        let mut record_digests = BTreeSet::new();
        let mut capture = capture_limits.map(RecoveryCapture::new);

        for (index, entry) in entries.iter().enumerate() {
            let identity = ActiveEvidenceSegment::inspect_identity(&entry.path, limits.segment)?;
            if identity.gate_id != gate_id {
                return Err(JournalManagerError::GateMismatch);
            }
            let header_sequence = identity.segment_sequence.get();
            if !seen_sequences.insert(header_sequence) {
                return Err(JournalManagerError::DuplicateSequence);
            }
            classify_sequence(entry.sequence, expected_sequence)?;
            classify_sequence(header_sequence, expected_sequence)?;
            if entry.sequence != header_sequence {
                return Err(if header_sequence < entry.sequence {
                    JournalManagerError::Rewind
                } else {
                    JournalManagerError::SequenceGap
                });
            }

            match &last_completed {
                None if identity.previous_completed_digest != [0; 32] => {
                    return Err(JournalManagerError::Fork);
                }
                Some(previous)
                    if identity.previous_completed_digest != previous.segment_digest() =>
                {
                    if completed_digests.contains(&identity.previous_completed_digest) {
                        return Err(JournalManagerError::Rewind);
                    }
                    return Err(JournalManagerError::Fork);
                }
                _ => {}
            }

            let verifying_key = verifier.resolve_signer(&identity)?;
            if verifying_key.to_bytes() != identity.signer_public_key {
                return Err(JournalManagerError::Verification(
                    JournalVerificationError::UnknownSigner,
                ));
            }
            let recovered = ActiveEvidenceSegment::recover(
                &entry.path,
                &identity,
                limits.segment,
                &verifying_key,
            )?;
            match recovered {
                RecoveredEvidenceSegment::Completed(mut completed) => {
                    validate_records(
                        &verifier,
                        completed.identity(),
                        completed.records(),
                        &mut record_digests,
                    )?;
                    recovered_records = recovered_records
                        .checked_add(completed.record_count())
                        .ok_or(JournalManagerError::Quiesced)?;
                    total_bytes = total_bytes
                        .checked_add(completed.segment_bytes())
                        .ok_or(JournalManagerError::Quiesced)?;
                    completed_digests.insert(completed.segment_digest());
                    completed_segments = completed_segments
                        .checked_add(1)
                        .ok_or(JournalManagerError::Quiesced)?;
                    if let Some(capture) = capture.as_mut() {
                        capture
                            .push_segment(completed.identity().clone(), completed.take_records())?;
                    }
                    last_completed = Some(completed);
                }
                RecoveredEvidenceSegment::Active { segment, status } => {
                    if index + 1 != entries.len() || recovered_active.is_some() {
                        return Err(JournalManagerError::MultipleActive);
                    }
                    validate_records(
                        &verifier,
                        segment.identity(),
                        segment.records(),
                        &mut record_digests,
                    )?;
                    recovered_records = recovered_records
                        .checked_add(segment.record_count())
                        .ok_or(JournalManagerError::Quiesced)?;
                    total_bytes = total_bytes
                        .checked_add(
                            u64::try_from(segment.segment_bytes())
                                .map_err(|_| JournalManagerError::Quiesced)?,
                        )
                        .ok_or(JournalManagerError::Quiesced)?;
                    if let OpenRecoveryStatus::TruncatedTail { removed_bytes } = status {
                        truncated_tail_bytes = removed_bytes;
                    }
                    recovered_active = Some((segment, status));
                }
            }
            expected_sequence = expected_sequence
                .checked_add(1)
                .ok_or(JournalManagerError::SequenceExhausted)?;
        }

        if let Some((active, _)) = recovered_active.as_mut()
            && let Some(capture) = capture.as_mut()
        {
            let identity = active.identity().clone();
            let prepared = capture.prepare_segment(active.records())?;
            let records = active.take_records();
            capture.commit_segment(identity, records, prepared);
        }

        let mut precommitted_recovery = None;
        let mut precommit_records = Vec::new();
        if let Some(precommit) = recovery_precommit.as_mut() {
            let preview_report = JournalRecoveryReport {
                discovered_segments,
                completed_segments,
                recovered_records,
                truncated_tail_bytes,
                closed_active_tail: false,
                discarded_pending_creation,
                active_sequence: None,
                total_bytes,
                quiesced: false,
            };
            let recovery = capture
                .take()
                .ok_or(JournalManagerError::RecoveryCaptureAllocation)?
                .finish(preview_report);
            let plan = precommit(&recovery)?;
            preflight_recovery_records(
                &limits,
                discovered_segments,
                total_bytes,
                recovered_active.is_some(),
                expected_sequence,
                &record_digests,
                &plan.records,
            )?;
            precommit_records = plan.records;
            precommitted_recovery = Some(recovery);
        }

        let mut closed_active_tail = false;
        if let Some((active, _)) = recovered_active {
            let tail_signer =
                recovered_tail_signer.ok_or(JournalManagerError::TailSignerUnavailable)?;
            ensure_matching_signer(&verifier, active.identity(), tail_signer)?;
            let active_bytes =
                u64::try_from(active.segment_bytes()).map_err(|_| JournalManagerError::Quiesced)?;
            let closed = active
                .close(tail_signer.kid, tail_signer.key)
                .map_err(map_commit_error)?;
            total_bytes = total_bytes
                .checked_sub(active_bytes)
                .and_then(|bytes| bytes.checked_add(closed.segment_bytes()))
                .ok_or(JournalManagerError::Quiesced)?;
            last_completed = Some(closed);
            closed_active_tail = true;
        }

        let mut manager = Self {
            directory,
            _lock_file: lock_file,
            verifier,
            signer_kid: signer.kid.clone(),
            signer_public_key: signer.key.verifying_key().to_bytes(),
            gate_id,
            gate_boot_id,
            limits,
            active: None,
            last_completed,
            segment_count: discovered_segments,
            total_bytes,
            record_digests,
            reservation_owner: Arc::new(ReservationOwner),
            reserved_segment_slots: 0,
            reserved_bytes: 0,
            poisoned: false,
            quiesced: false,
        };
        manager.start_next_segment(created_mono_ns, None, AppendCapacity::ordinary(0, 0))?;
        if !precommit_records.is_empty() {
            let mut reservation = manager.reserve_append_capacity(precommit_records.len())?;
            for record in &precommit_records {
                manager.append_reserved(&mut reservation, record, created_mono_ns, signer)?;
            }
        }
        let active_sequence = manager
            .active
            .as_ref()
            .map(|segment| segment.identity().segment_sequence);
        let completed_segments = manager
            .segment_count
            .saturating_sub(usize::from(manager.active.is_some()));
        let report = JournalRecoveryReport {
            discovered_segments,
            completed_segments,
            recovered_records,
            truncated_tail_bytes,
            closed_active_tail,
            discarded_pending_creation,
            active_sequence,
            total_bytes: manager.total_bytes,
            quiesced: manager.quiesced,
        };
        let recovery = if let Some(mut recovery) = precommitted_recovery {
            recovery.report = report;
            Some(recovery)
        } else {
            capture.map(|capture| capture.finish(report))
        };
        Ok((manager, report, recovery))
    }

    /// Reserve conservative logical capacity for future maximum-sized records.
    ///
    /// Each unit retains one dedicated future segment slot and the complete
    /// bytes for that segment's header, maximum-sized record frame, and footer.
    /// The reservation is logical only: it does not allocate filesystem blocks
    /// or make a durability claim.
    ///
    /// # Errors
    /// Returns on poison/quiescence, unusable maximum-record bounds, sequence
    /// exhaustion, or insufficient unreserved global byte/segment capacity.
    pub fn reserve_append_capacity(
        &mut self,
        record_count: usize,
    ) -> Result<JournalReservation, JournalManagerError> {
        if self.poisoned {
            return Err(JournalManagerError::Poisoned);
        }
        if self.quiesced {
            return Err(JournalManagerError::Quiesced);
        }
        if record_count == 0 {
            return Err(JournalManagerError::ReservationExhausted);
        }
        let active = self.active.as_ref().ok_or(JournalManagerError::Quiesced)?;
        let bounds = self.limits.segment;
        let maximum_record_bytes = self.max_record_bytes();
        if u32::try_from(maximum_record_bytes).is_err() {
            return Err(JournalManagerError::Journal(JournalError::RecordTooLarge));
        }
        let maximum_frame_bytes = ActiveEvidenceSegment::framed_record_bytes(maximum_record_bytes)?;
        let bytes_per_record = ActiveEvidenceSegment::maximum_header_bytes()
            .checked_add(ActiveEvidenceSegment::footer_bytes())
            .and_then(|bytes| bytes.checked_add(maximum_frame_bytes))
            .ok_or(JournalManagerError::ReservationUnavailable)?;
        if bytes_per_record > bounds.max_segment_bytes() {
            return Err(JournalManagerError::Journal(
                JournalError::RecordCannotFitSegment,
            ));
        }

        let requested_segment_slots = record_count;
        let reserved_segment_slots = self
            .reserved_segment_slots
            .checked_add(requested_segment_slots)
            .ok_or(JournalManagerError::ReservationUnavailable)?;
        let projected_segment_count = self
            .segment_count
            .checked_add(reserved_segment_slots)
            .ok_or(JournalManagerError::ReservationUnavailable)?;
        if projected_segment_count > self.limits.max_segments {
            return Err(JournalManagerError::ReservationUnavailable);
        }
        let reserved_sequence_span = u64::try_from(reserved_segment_slots)
            .map_err(|_| JournalManagerError::SequenceExhausted)?;
        let _ = active
            .identity()
            .segment_sequence
            .get()
            .checked_add(reserved_sequence_span)
            .ok_or(JournalManagerError::SequenceExhausted)?;

        let bytes_per_record = u64::try_from(bytes_per_record)
            .map_err(|_| JournalManagerError::ReservationUnavailable)?;
        let requested_records = u64::try_from(requested_segment_slots)
            .map_err(|_| JournalManagerError::ReservationUnavailable)?;
        let requested_bytes = bytes_per_record
            .checked_mul(requested_records)
            .ok_or(JournalManagerError::ReservationUnavailable)?;
        let reserved_bytes = self
            .reserved_bytes
            .checked_add(requested_bytes)
            .ok_or(JournalManagerError::ReservationUnavailable)?;
        if !fits_total_with_logical_reservation(
            self.total_bytes,
            0,
            ActiveEvidenceSegment::footer_bytes(),
            reserved_bytes,
            self.limits.max_total_bytes,
        ) {
            return Err(JournalManagerError::ReservationUnavailable);
        }

        self.reserved_segment_slots = reserved_segment_slots;
        self.reserved_bytes = reserved_bytes;
        Ok(JournalReservation {
            owner: Arc::clone(&self.reservation_owner),
            remaining_records: requested_segment_slots,
            bytes_per_record,
            remaining_bytes: requested_bytes,
        })
    }

    /// Release every unused unit in a reservation after publication is
    /// cancelled before the corresponding durable call evidence.
    ///
    /// # Errors
    /// Returns on poison/quiescence, a token from another manager, or an
    /// inconsistent internal reservation state. No capacity is released on
    /// error.
    pub fn release_reservation(
        &mut self,
        reservation: &mut JournalReservation,
    ) -> Result<(), JournalManagerError> {
        if self.poisoned {
            return Err(JournalManagerError::Poisoned);
        }
        if self.quiesced {
            return Err(JournalManagerError::Quiesced);
        }
        if !Arc::ptr_eq(&self.reservation_owner, &reservation.owner) {
            return Err(JournalManagerError::ReservationMismatch);
        }
        let Ok(remaining_records) = u64::try_from(reservation.remaining_records) else {
            self.poisoned = true;
            return Err(JournalManagerError::Poisoned);
        };
        let Some(expected_remaining_bytes) =
            reservation.bytes_per_record.checked_mul(remaining_records)
        else {
            self.poisoned = true;
            return Err(JournalManagerError::Poisoned);
        };
        let Some(reserved_segment_slots) = self
            .reserved_segment_slots
            .checked_sub(reservation.remaining_records)
        else {
            self.poisoned = true;
            return Err(JournalManagerError::Poisoned);
        };
        let Some(reserved_bytes) = self.reserved_bytes.checked_sub(reservation.remaining_bytes)
        else {
            self.poisoned = true;
            return Err(JournalManagerError::Poisoned);
        };
        if expected_remaining_bytes != reservation.remaining_bytes {
            self.poisoned = true;
            return Err(JournalManagerError::Poisoned);
        }
        self.reserved_segment_slots = reserved_segment_slots;
        self.reserved_bytes = reserved_bytes;
        reservation.remaining_records = 0;
        reservation.remaining_bytes = 0;
        Ok(())
    }

    /// Whether an opaque reservation was issued by this exact manager instance.
    #[must_use]
    pub(crate) fn owns_reservation(&self, reservation: &JournalReservation) -> bool {
        Arc::ptr_eq(&self.reservation_owner, &reservation.owner)
    }

    /// Append one record against a manager-owned reservation.
    ///
    /// One reservation unit is consumed only after the append is durably
    /// confirmed by the segment primitive. Every error retains the unit; an
    /// ambiguous append poisons the manager and requires recovery.
    ///
    /// # Errors
    /// Returns the errors documented by [`Self::append`], plus reservation
    /// mismatch or exhaustion.
    pub fn append_reserved(
        &mut self,
        reservation: &mut JournalReservation,
        record: &[u8],
        rotation_created_mono_ns: u64,
        signer: &JournalSigner<'_>,
    ) -> Result<(), JournalManagerError> {
        let prepared = self.prepare_reservation_consumption(reservation)?;
        self.append_inner(record, rotation_created_mono_ns, signer, prepared.capacity)?;
        self.reserved_segment_slots = prepared.capacity.reserved_segment_slots_after_append;
        self.reserved_bytes = prepared.capacity.reserved_bytes_after_append;
        reservation.remaining_records = prepared.token_remaining_records;
        reservation.remaining_bytes = prepared.token_remaining_bytes;
        Ok(())
    }

    /// Append exactly once, rotating first only after the segment reports that a
    /// fresh segment can accommodate the record.
    ///
    /// Candidate validation may succeed even when this method later returns a
    /// capacity or commit-ambiguity error. Stateful consumers may reduce the new
    /// record only after `Ok(())`; after ambiguity they must discard this manager,
    /// reopen, and rebuild fresh reducer state exactly once from the successfully
    /// returned recovery snapshot.
    ///
    /// # Errors
    /// Returns on validation, permanent record bounds, global-cap quiescence, or
    /// a commit-ambiguous operation. A commit ambiguity permanently poisons this
    /// manager instance.
    pub fn append(
        &mut self,
        record: &[u8],
        rotation_created_mono_ns: u64,
        signer: &JournalSigner<'_>,
    ) -> Result<(), JournalManagerError> {
        let capacity = AppendCapacity::ordinary(self.reserved_segment_slots, self.reserved_bytes);
        self.append_inner(record, rotation_created_mono_ns, signer, capacity)
    }

    fn append_inner(
        &mut self,
        record: &[u8],
        rotation_created_mono_ns: u64,
        signer: &JournalSigner<'_>,
        capacity: AppendCapacity,
    ) -> Result<(), JournalManagerError> {
        if self.poisoned {
            return Err(JournalManagerError::Poisoned);
        }
        if self.quiesced {
            return Err(JournalManagerError::Quiesced);
        }
        let active_identity = self
            .active
            .as_ref()
            .ok_or(JournalManagerError::Quiesced)?
            .identity();
        ensure_matching_signer(&self.verifier, active_identity, signer)?;
        let record_digest = EvidenceRecordDigest::compute(record);
        if self.record_digests.contains(&record_digest) {
            return Err(JournalManagerError::DuplicateRecord);
        }
        let classification = {
            let active = self.active.as_ref().ok_or(JournalManagerError::Quiesced)?;
            self.verifier.validate_record(active.identity(), record)?;
            active.preflight_append(record.len())
        };
        match classification {
            Ok(frame_bytes) => {
                if !fits_total_with_logical_reservation(
                    self.total_bytes,
                    frame_bytes,
                    ActiveEvidenceSegment::footer_bytes(),
                    capacity.reserved_bytes_after_append,
                    self.limits.max_total_bytes,
                ) {
                    if capacity.consumes_reservation {
                        self.poisoned = true;
                        return Err(JournalManagerError::Poisoned);
                    }
                    if self.has_reservations() {
                        return Err(JournalManagerError::ReservationUnavailable);
                    }
                    self.quiesce(signer)?;
                    return Err(JournalManagerError::Quiesced);
                }
                let confirmed_total_bytes = self
                    .total_bytes
                    .checked_add(
                        u64::try_from(frame_bytes).map_err(|_| JournalManagerError::Quiesced)?,
                    )
                    .ok_or(JournalManagerError::Quiesced)?;
                let active = self.active.as_mut().ok_or(JournalManagerError::Quiesced)?;
                match active.append(record) {
                    Ok(()) => {
                        self.total_bytes = confirmed_total_bytes;
                        self.record_digests.insert(record_digest);
                        Ok(())
                    }
                    Err(JournalError::CommitAmbiguous) => {
                        self.poisoned = true;
                        Err(JournalManagerError::AppendCommitAmbiguous { record_digest })
                    }
                    Err(JournalError::Poisoned) => {
                        self.poisoned = true;
                        Err(JournalManagerError::Poisoned)
                    }
                    Err(error) => Err(error.into()),
                }
            }
            Err(JournalError::RotationRequired) => {
                let frame_bytes = ActiveEvidenceSegment::framed_record_bytes(record.len())?;
                if !self.rotation_fits_logical_capacity(frame_bytes, capacity)? {
                    if capacity.consumes_reservation {
                        self.poisoned = true;
                        return Err(JournalManagerError::Poisoned);
                    }
                    if self.has_reservations() {
                        return Err(JournalManagerError::ReservationUnavailable);
                    }
                }
                self.rotate_and_append(
                    record,
                    record_digest,
                    rotation_created_mono_ns,
                    frame_bytes,
                    signer,
                    capacity,
                )
            }
            Err(JournalError::CommitAmbiguous | JournalError::Poisoned) => {
                self.poisoned = true;
                Err(JournalManagerError::Poisoned)
            }
            Err(error) => Err(error.into()),
        }
    }

    fn prepare_reservation_consumption(
        &mut self,
        reservation: &JournalReservation,
    ) -> Result<PreparedReservationConsumption, JournalManagerError> {
        if self.poisoned {
            return Err(JournalManagerError::Poisoned);
        }
        if self.quiesced {
            return Err(JournalManagerError::Quiesced);
        }
        if !Arc::ptr_eq(&self.reservation_owner, &reservation.owner) {
            return Err(JournalManagerError::ReservationMismatch);
        }
        let Some(token_remaining_records) = reservation.remaining_records.checked_sub(1) else {
            return Err(JournalManagerError::ReservationExhausted);
        };
        let Some(token_remaining_bytes) = reservation
            .remaining_bytes
            .checked_sub(reservation.bytes_per_record)
        else {
            self.poisoned = true;
            return Err(JournalManagerError::Poisoned);
        };
        let Some(reserved_segment_slots_after_append) = self.reserved_segment_slots.checked_sub(1)
        else {
            self.poisoned = true;
            return Err(JournalManagerError::Poisoned);
        };
        let Some(reserved_bytes_after_append) = self
            .reserved_bytes
            .checked_sub(reservation.bytes_per_record)
        else {
            self.poisoned = true;
            return Err(JournalManagerError::Poisoned);
        };
        let Ok(remaining_records) = u64::try_from(reservation.remaining_records) else {
            self.poisoned = true;
            return Err(JournalManagerError::Poisoned);
        };
        let Some(expected_token_bytes) =
            reservation.bytes_per_record.checked_mul(remaining_records)
        else {
            self.poisoned = true;
            return Err(JournalManagerError::Poisoned);
        };
        if expected_token_bytes != reservation.remaining_bytes {
            self.poisoned = true;
            return Err(JournalManagerError::Poisoned);
        }
        Ok(PreparedReservationConsumption {
            capacity: AppendCapacity {
                reserved_segment_slots_after_append,
                reserved_bytes_after_append,
                consumes_reservation: true,
            },
            token_remaining_records,
            token_remaining_bytes,
        })
    }

    const fn has_reservations(&self) -> bool {
        self.reserved_segment_slots != 0 || self.reserved_bytes != 0
    }

    fn rotation_fits_logical_capacity(
        &self,
        frame_bytes: usize,
        capacity: AppendCapacity,
    ) -> Result<bool, JournalManagerError> {
        let active = self.active.as_ref().ok_or(JournalManagerError::Quiesced)?;
        let next_sequence = active
            .identity()
            .segment_sequence
            .get()
            .checked_add(1)
            .ok_or(JournalManagerError::SequenceExhausted)?;
        let reserved_sequence_span = u64::try_from(capacity.reserved_segment_slots_after_append)
            .map_err(|_| JournalManagerError::SequenceExhausted)?;
        let _ = next_sequence
            .checked_add(reserved_sequence_span)
            .ok_or(JournalManagerError::SequenceExhausted)?;
        let projected_segments = self
            .segment_count
            .checked_add(1)
            .and_then(|count| count.checked_add(capacity.reserved_segment_slots_after_append));
        let added_bytes = ActiveEvidenceSegment::footer_bytes()
            .checked_add(ActiveEvidenceSegment::minimum_complete_bytes(
                active.identity(),
            )?)
            .and_then(|bytes| bytes.checked_add(frame_bytes));
        Ok(
            projected_segments.is_some_and(|count| count <= self.limits.max_segments)
                && added_bytes.is_some_and(|bytes| {
                    fits_total_with_logical_reservation(
                        self.total_bytes,
                        bytes,
                        0,
                        capacity.reserved_bytes_after_append,
                        self.limits.max_total_bytes,
                    )
                }),
        )
    }

    /// Preflight one uninterrupted batch against the configured logical journal
    /// bounds without issuing I/O or changing manager state.
    ///
    /// The simulation includes record framing, every required footer/header,
    /// per-segment record and byte bounds, the segment-count namespace, and the
    /// whole-journal byte cap. An exclusive higher-level owner can keep this
    /// capacity available by permitting no intervening append before it submits
    /// the batch. This is not a filesystem-space reservation: a later write can
    /// still fail or become commit-ambiguous.
    ///
    /// # Errors
    /// Returns the same permanent record-bound, checked sequence, poison, or
    /// logical-capacity errors that an append in the simulated batch would reach.
    pub fn preflight_append_batch(
        &self,
        record_lengths: &[usize],
    ) -> Result<(), JournalManagerError> {
        if self.poisoned {
            return Err(JournalManagerError::Poisoned);
        }
        if self.quiesced {
            return Err(JournalManagerError::Quiesced);
        }
        if record_lengths.is_empty() {
            return Ok(());
        }

        let active = self.active.as_ref().ok_or(JournalManagerError::Quiesced)?;
        let bounds = self.limits.segment;
        let footer_bytes = ActiveEvidenceSegment::footer_bytes();
        let minimum_segment_bytes =
            ActiveEvidenceSegment::minimum_complete_bytes(active.identity())?;
        let header_bytes = minimum_segment_bytes
            .checked_sub(footer_bytes)
            .ok_or(JournalManagerError::Journal(JournalError::Bounds))?;
        let mut sequence = active.identity().segment_sequence.get();
        let mut segment_count = self.segment_count;
        let mut segment_bytes = active.segment_bytes();
        let mut record_count = active.record_count();
        let mut total_bytes = self.total_bytes;

        for &record_len in record_lengths {
            if record_len > bounds.max_record_bytes() || u32::try_from(record_len).is_err() {
                return Err(JournalManagerError::Journal(JournalError::RecordTooLarge));
            }
            let frame_bytes = ActiveEvidenceSegment::framed_record_bytes(record_len)?;
            if minimum_segment_bytes
                .checked_add(frame_bytes)
                .is_none_or(|required| required > bounds.max_segment_bytes())
            {
                return Err(JournalManagerError::Journal(
                    JournalError::RecordCannotFitSegment,
                ));
            }

            let fits_current = record_count < bounds.max_records()
                && segment_bytes
                    .checked_add(frame_bytes)
                    .and_then(|bytes| bytes.checked_add(footer_bytes))
                    .is_some_and(|complete| complete <= bounds.max_segment_bytes());
            if !fits_current {
                sequence = sequence
                    .checked_add(1)
                    .ok_or(JournalManagerError::SequenceExhausted)?;
                let _ = NonZeroU64::new(sequence).ok_or(JournalManagerError::SequenceExhausted)?;
                let reserved_sequence_span = u64::try_from(self.reserved_segment_slots)
                    .map_err(|_| JournalManagerError::SequenceExhausted)?;
                let _ = sequence
                    .checked_add(reserved_sequence_span)
                    .ok_or(JournalManagerError::SequenceExhausted)?;
                let projected_segment_count = segment_count
                    .checked_add(1)
                    .and_then(|count| count.checked_add(self.reserved_segment_slots));
                if projected_segment_count.is_none_or(|count| count > self.limits.max_segments) {
                    return Err(if self.has_reservations() {
                        JournalManagerError::ReservationUnavailable
                    } else {
                        JournalManagerError::Quiesced
                    });
                }
                total_bytes = total_bytes
                    .checked_add(
                        u64::try_from(footer_bytes).map_err(|_| JournalManagerError::Quiesced)?,
                    )
                    .and_then(|bytes| {
                        u64::try_from(header_bytes)
                            .ok()
                            .and_then(|header| bytes.checked_add(header))
                    })
                    .ok_or(JournalManagerError::Quiesced)?;
                segment_count = segment_count
                    .checked_add(1)
                    .ok_or(JournalManagerError::Quiesced)?;
                segment_bytes = header_bytes;
                record_count = 0;
            }

            if !fits_total_with_logical_reservation(
                total_bytes,
                frame_bytes,
                footer_bytes,
                self.reserved_bytes,
                self.limits.max_total_bytes,
            ) {
                return Err(if self.has_reservations() {
                    JournalManagerError::ReservationUnavailable
                } else {
                    JournalManagerError::Quiesced
                });
            }
            total_bytes = total_bytes
                .checked_add(u64::try_from(frame_bytes).map_err(|_| JournalManagerError::Quiesced)?)
                .ok_or(JournalManagerError::Quiesced)?;
            segment_bytes = segment_bytes
                .checked_add(frame_bytes)
                .ok_or(JournalManagerError::Quiesced)?;
            record_count = record_count
                .checked_add(1)
                .ok_or(JournalManagerError::Quiesced)?;
        }
        Ok(())
    }

    /// Whether global capacity has quiesced further appends.
    #[must_use]
    pub const fn is_quiesced(&self) -> bool {
        self.quiesced
    }

    /// Current active sequence, absent after quiescence or ambiguous commit.
    #[must_use]
    pub fn active_sequence(&self) -> Option<NonZeroU64> {
        if self.poisoned || self.quiesced {
            return None;
        }
        self.active
            .as_ref()
            .map(|segment| segment.identity().segment_sequence)
    }

    /// Current manager-created, verifier-resolved active identity for a fused
    /// in-crate adapter. It is not footer-authenticated until completion.
    pub(crate) fn active_identity(&self) -> Option<&SegmentIdentity> {
        if self.poisoned || self.quiesced {
            return None;
        }
        self.active.as_ref().map(ActiveEvidenceSegment::identity)
    }

    #[must_use]
    pub(crate) const fn max_record_bytes(&self) -> usize {
        self.limits.segment.max_record_bytes()
    }

    /// Whether recovery or this confirmed manager instance contains the exact
    /// record bytes. A poisoned instance cannot answer; reopen it first.
    ///
    /// # Errors
    /// Returns [`JournalManagerError::Poisoned`] while an I/O outcome is unknown.
    pub fn contains_record(
        &self,
        digest: EvidenceRecordDigest,
    ) -> Result<bool, JournalManagerError> {
        if self.poisoned {
            Err(JournalManagerError::Poisoned)
        } else {
            Ok(self.record_digests.contains(&digest))
        }
    }

    /// Gracefully footer-complete the active tail.
    ///
    /// This consumes the manager on success or error. A rejected signer issues
    /// no journal I/O, but the caller must reopen to regain a manager handle.
    ///
    /// # Errors
    /// Returns on a poisoned manager, signer mismatch, or footer commit failure.
    pub fn finish(
        mut self,
        signer: &JournalSigner<'_>,
    ) -> Result<Option<CompletedSegment>, JournalManagerError> {
        if self.poisoned {
            return Err(JournalManagerError::Poisoned);
        }
        let Some(active_identity) = self.active.as_ref().map(ActiveEvidenceSegment::identity)
        else {
            return Ok(None);
        };
        ensure_matching_signer(&self.verifier, active_identity, signer)?;
        let Some(active) = self.active.take() else {
            return Ok(None);
        };
        active
            .close(signer.kid, signer.key)
            .map(Some)
            .map_err(map_commit_error)
    }

    fn rotate_and_append(
        &mut self,
        record: &[u8],
        record_digest: EvidenceRecordDigest,
        created_mono_ns: u64,
        frame_bytes: usize,
        signer: &JournalSigner<'_>,
        capacity: AppendCapacity,
    ) -> Result<(), JournalManagerError> {
        let active = self.active.take().ok_or(JournalManagerError::Quiesced)?;
        let active_bytes =
            u64::try_from(active.segment_bytes()).map_err(|_| JournalManagerError::Quiesced)?;
        let completed = match active.close(signer.kid, signer.key) {
            Ok(completed) => completed,
            Err(JournalError::CommitAmbiguous) => {
                self.poisoned = true;
                return Err(JournalManagerError::AppendCommitAmbiguous { record_digest });
            }
            Err(error) => {
                self.poisoned = true;
                return Err(error.into());
            }
        };
        let Some(total_bytes) = self
            .total_bytes
            .checked_sub(active_bytes)
            .and_then(|bytes| bytes.checked_add(completed.segment_bytes()))
        else {
            self.poisoned = true;
            return Err(JournalManagerError::Poisoned);
        };
        self.total_bytes = total_bytes;
        self.last_completed = Some(completed);

        if let Err(error) = self.start_next_segment(created_mono_ns, Some(frame_bytes), capacity) {
            self.poisoned = true;
            return Err(if error == JournalManagerError::Poisoned {
                JournalManagerError::AppendCommitAmbiguous { record_digest }
            } else {
                error
            });
        }
        if self.quiesced {
            return Err(JournalManagerError::Quiesced);
        }
        let validation = {
            let active = self.active.as_ref().ok_or(JournalManagerError::Quiesced)?;
            self.verifier.validate_record(active.identity(), record)
        };
        if let Err(error) = validation {
            self.poisoned = true;
            return Err(error.into());
        }
        let Some(confirmed_total_bytes) =
            self.total_bytes
                .checked_add(u64::try_from(frame_bytes).map_err(|_| {
                    self.poisoned = true;
                    JournalManagerError::Poisoned
                })?)
        else {
            self.poisoned = true;
            return Err(JournalManagerError::Poisoned);
        };
        let Some(active) = self.active.as_mut() else {
            self.poisoned = true;
            return Err(JournalManagerError::Poisoned);
        };
        match active.append(record) {
            Ok(()) => {
                self.total_bytes = confirmed_total_bytes;
                self.record_digests.insert(record_digest);
                Ok(())
            }
            Err(JournalError::CommitAmbiguous) => {
                self.poisoned = true;
                Err(JournalManagerError::AppendCommitAmbiguous { record_digest })
            }
            Err(error) => {
                self.poisoned = true;
                Err(error.into())
            }
        }
    }

    fn start_next_segment(
        &mut self,
        created_mono_ns: u64,
        pending_frame_bytes: Option<usize>,
        capacity: AppendCapacity,
    ) -> Result<(), JournalManagerError> {
        let sequence = match &self.last_completed {
            Some(previous) => previous
                .identity()
                .segment_sequence
                .get()
                .checked_add(1)
                .and_then(NonZeroU64::new)
                .ok_or(JournalManagerError::SequenceExhausted)?,
            None => NonZeroU64::new(1).ok_or(JournalManagerError::SequenceExhausted)?,
        };
        let previous_completed_digest = self
            .last_completed
            .as_ref()
            .map_or([0; 32], CompletedSegment::segment_digest);
        let identity = SegmentIdentity {
            gate_id: self.gate_id.clone(),
            gate_boot_id: self.gate_boot_id,
            segment_sequence: sequence,
            previous_completed_digest,
            created_mono_ns,
            signer_kid: self.signer_kid.clone(),
            signer_public_key: self.signer_public_key,
        };
        let resolved = self.verifier.resolve_signer(&identity)?;
        if resolved.to_bytes() != self.signer_public_key {
            return Err(JournalManagerError::Verification(
                JournalVerificationError::UnknownSigner,
            ));
        }
        let minimum = ActiveEvidenceSegment::minimum_complete_bytes(&identity)?;
        let required = minimum
            .checked_add(pending_frame_bytes.unwrap_or(0))
            .ok_or(JournalManagerError::Quiesced)?;
        let projected_segment_count = self
            .segment_count
            .checked_add(1)
            .and_then(|count| count.checked_add(capacity.reserved_segment_slots_after_append));
        let has_capacity = projected_segment_count
            .is_some_and(|count| count <= self.limits.max_segments)
            && fits_total_with_logical_reservation(
                self.total_bytes,
                required,
                0,
                capacity.reserved_bytes_after_append,
                self.limits.max_total_bytes,
            );
        if !has_capacity {
            if capacity.consumes_reservation || self.has_reservations() {
                self.poisoned = true;
                return Err(JournalManagerError::Poisoned);
            }
            self.quiesced = true;
            return Ok(());
        }

        let path = self.directory.join(segment_file_name(sequence));
        let segment = match &self.last_completed {
            Some(previous) => {
                ActiveEvidenceSegment::create_next(path, identity, self.limits.segment, previous)
            }
            None => ActiveEvidenceSegment::create_new(path, identity, self.limits.segment),
        };
        let segment = match segment {
            Ok(segment) => segment,
            Err(
                JournalError::Storage | JournalError::AlreadyExists | JournalError::CommitAmbiguous,
            ) => {
                self.poisoned = true;
                return Err(JournalManagerError::Poisoned);
            }
            Err(error) => return Err(error.into()),
        };
        self.total_bytes = self
            .total_bytes
            .checked_add(
                u64::try_from(segment.segment_bytes())
                    .map_err(|_| JournalManagerError::Quiesced)?,
            )
            .ok_or(JournalManagerError::Quiesced)?;
        self.segment_count = self
            .segment_count
            .checked_add(1)
            .ok_or(JournalManagerError::Quiesced)?;
        self.active = Some(segment);
        Ok(())
    }

    fn quiesce(&mut self, signer: &JournalSigner<'_>) -> Result<(), JournalManagerError> {
        let Some(active) = self.active.take() else {
            self.quiesced = true;
            return Ok(());
        };
        let active_bytes =
            u64::try_from(active.segment_bytes()).map_err(|_| JournalManagerError::Quiesced)?;
        match active.close(signer.kid, signer.key) {
            Ok(completed) => {
                self.total_bytes = self
                    .total_bytes
                    .checked_sub(active_bytes)
                    .and_then(|bytes| bytes.checked_add(completed.segment_bytes()))
                    .ok_or(JournalManagerError::Quiesced)?;
                self.last_completed = Some(completed);
                self.quiesced = true;
                Ok(())
            }
            Err(JournalError::CommitAmbiguous) => {
                self.poisoned = true;
                Err(JournalManagerError::Poisoned)
            }
            Err(error) => Err(error.into()),
        }
    }
}

struct SegmentEntry {
    sequence: u64,
    path: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OpenMode {
    ProvisionNew,
    OpenExisting,
}

type RecoveryPrecommit<'callback> = Option<
    &'callback mut dyn FnMut(
        &JournalRecovery,
    ) -> Result<RecoveryPrecommitPlan, JournalManagerError>,
>;

struct OpenBehavior<'callback> {
    mode: OpenMode,
    capture_limits: Option<RecoveryCaptureLimits>,
    recovery_precommit: RecoveryPrecommit<'callback>,
}

impl<'callback> OpenBehavior<'callback> {
    const fn new(
        mode: OpenMode,
        capture_limits: Option<RecoveryCaptureLimits>,
        recovery_precommit: RecoveryPrecommit<'callback>,
    ) -> Self {
        Self {
            mode,
            capture_limits,
            recovery_precommit,
        }
    }
}

struct RecoveryCapture {
    limits: RecoveryCaptureLimits,
    record_count: u64,
    record_bytes: u64,
    segments: Vec<RecoveredJournalSegment>,
}

#[derive(Clone, Copy)]
struct PreparedCaptureSegment {
    record_count: u64,
    record_bytes: u64,
}

impl RecoveryCapture {
    const fn new(limits: RecoveryCaptureLimits) -> Self {
        Self {
            limits,
            record_count: 0,
            record_bytes: 0,
            segments: Vec::new(),
        }
    }

    fn push_segment(
        &mut self,
        identity: SegmentIdentity,
        records: Vec<Vec<u8>>,
    ) -> Result<(), JournalManagerError> {
        let prepared = self.prepare_segment(&records)?;
        self.commit_segment(identity, records, prepared);
        Ok(())
    }

    fn prepare_segment(
        &mut self,
        records: &[Vec<u8>],
    ) -> Result<PreparedCaptureSegment, JournalManagerError> {
        let segment_records = u64::try_from(records.len())
            .map_err(|_| self.limit_error(RecoveryCaptureDimension::RecordCount, u64::MAX))?;
        let segment_record_bytes = records.iter().try_fold(0u64, |total, record| {
            let bytes = u64::try_from(record.len())
                .map_err(|_| self.limit_error(RecoveryCaptureDimension::RecordBytes, u64::MAX))?;
            total
                .checked_add(bytes)
                .ok_or_else(|| self.limit_error(RecoveryCaptureDimension::RecordBytes, u64::MAX))
        })?;
        let record_count = self
            .record_count
            .checked_add(segment_records)
            .ok_or_else(|| self.limit_error(RecoveryCaptureDimension::RecordCount, u64::MAX))?;
        if record_count > self.limits.max_records {
            return Err(self.limit_error(RecoveryCaptureDimension::RecordCount, record_count));
        }
        let record_bytes = self
            .record_bytes
            .checked_add(segment_record_bytes)
            .ok_or_else(|| self.limit_error(RecoveryCaptureDimension::RecordBytes, u64::MAX))?;
        if record_bytes > self.limits.max_total_record_bytes {
            return Err(self.limit_error(RecoveryCaptureDimension::RecordBytes, record_bytes));
        }
        self.segments
            .try_reserve(1)
            .map_err(|_| JournalManagerError::RecoveryCaptureAllocation)?;
        Ok(PreparedCaptureSegment {
            record_count,
            record_bytes,
        })
    }

    fn commit_segment(
        &mut self,
        identity: SegmentIdentity,
        records: Vec<Vec<u8>>,
        prepared: PreparedCaptureSegment,
    ) {
        self.segments
            .push(RecoveredJournalSegment { identity, records });
        self.record_count = prepared.record_count;
        self.record_bytes = prepared.record_bytes;
    }

    const fn limit_error(
        &self,
        dimension: RecoveryCaptureDimension,
        required: u64,
    ) -> JournalManagerError {
        let maximum = match dimension {
            RecoveryCaptureDimension::RecordCount => self.limits.max_records,
            RecoveryCaptureDimension::RecordBytes => self.limits.max_total_record_bytes,
        };
        JournalManagerError::RecoveryCaptureLimitExceeded {
            dimension,
            maximum,
            required,
        }
    }

    fn finish(self, report: JournalRecoveryReport) -> JournalRecovery {
        debug_assert_eq!(self.record_count, report.recovered_records);
        JournalRecovery {
            report,
            segments: self.segments,
            record_bytes: self.record_bytes,
        }
    }
}

fn prepare_directory(path: PathBuf, mode: OpenMode) -> Result<PathBuf, JournalManagerError> {
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_dir() => Ok(path),
        Ok(_) => Err(JournalManagerError::Storage),
        Err(error)
            if error.kind() == std::io::ErrorKind::NotFound && mode == OpenMode::ProvisionNew =>
        {
            fs::create_dir(&path).map_err(|_| JournalManagerError::Storage)?;
            Ok(path)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Err(JournalManagerError::Missing)
        }
        Err(_) => Err(JournalManagerError::Storage),
    }
}

fn lock_directory(directory: &Path, mode: OpenMode) -> Result<File, JournalManagerError> {
    let path = directory.join(LOCK_FILE_NAME);
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    if mode == OpenMode::ProvisionNew {
        options.create_new(true);
    }
    #[cfg(unix)]
    options.mode(0o600);
    let file = match options.open(&path) {
        Ok(file) => file,
        Err(error)
            if error.kind() == std::io::ErrorKind::AlreadyExists
                && mode == OpenMode::ProvisionNew =>
        {
            return Err(JournalManagerError::AlreadyProvisioned);
        }
        Err(error)
            if error.kind() == std::io::ErrorKind::NotFound && mode == OpenMode::OpenExisting =>
        {
            return Err(JournalManagerError::Missing);
        }
        Err(_) => return Err(JournalManagerError::Storage),
    };
    let path_metadata = fs::symlink_metadata(&path).map_err(|_| JournalManagerError::Storage)?;
    let opened_metadata = file.metadata().map_err(|_| JournalManagerError::Storage)?;
    if !path_metadata.file_type().is_file() || !opened_metadata.file_type().is_file() {
        return Err(JournalManagerError::Storage);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if path_metadata.dev() != opened_metadata.dev()
            || path_metadata.ino() != opened_metadata.ino()
        {
            return Err(JournalManagerError::Storage);
        }
    }
    match file.try_lock() {
        Ok(()) => {
            if mode == OpenMode::ProvisionNew {
                file.sync_all().map_err(|_| JournalManagerError::Storage)?;
                sync_directory(directory)?;
            }
            Ok(file)
        }
        Err(TryLockError::WouldBlock) => Err(JournalManagerError::LockHeld),
        Err(TryLockError::Error(_)) => Err(JournalManagerError::Storage),
    }
}

fn discover_segments(
    directory: &Path,
    max_segments: usize,
) -> Result<(Vec<SegmentEntry>, Option<PathBuf>), JournalManagerError> {
    let mut entries = Vec::new();
    let mut pending_path = None;
    for entry in fs::read_dir(directory).map_err(|_| JournalManagerError::Storage)? {
        let entry = entry.map_err(|_| JournalManagerError::Storage)?;
        let name = entry.file_name();
        if name == OsStr::new(LOCK_FILE_NAME) {
            continue;
        }
        let file_type = entry
            .file_type()
            .map_err(|_| JournalManagerError::Storage)?;
        if !file_type.is_file() {
            return Err(JournalManagerError::UnexpectedEntry);
        }
        if let Some(remainder) = name
            .to_str()
            .and_then(|name| name.strip_prefix(PENDING_CREATION_PREFIX))
        {
            if pending_path.is_some() || parse_segment_file_name(OsStr::new(remainder)).is_err() {
                return Err(JournalManagerError::UnexpectedEntry);
            }
            pending_path = Some(entry.path());
            continue;
        }
        let sequence = parse_segment_file_name(&name)?;
        if entries.len() >= max_segments {
            return Err(JournalManagerError::Quiesced);
        }
        entries.push(SegmentEntry {
            sequence,
            path: entry.path(),
        });
    }
    entries.sort_by_key(|entry| entry.sequence);
    Ok((entries, pending_path))
}

fn sync_directory(directory: &Path) -> Result<(), JournalManagerError> {
    #[cfg(unix)]
    {
        File::open(directory)
            .and_then(|file| file.sync_all())
            .map_err(|_| JournalManagerError::Storage)
    }
    #[cfg(not(unix))]
    {
        let _ = directory;
        Err(JournalManagerError::Journal(JournalError::Unsupported))
    }
}

fn parse_segment_file_name(name: &OsStr) -> Result<u64, JournalManagerError> {
    let text = name.to_str().ok_or(JournalManagerError::UnexpectedEntry)?;
    let digits = text
        .strip_prefix(SEGMENT_PREFIX)
        .ok_or(JournalManagerError::UnexpectedEntry)?;
    if digits.len() != SEGMENT_DIGITS || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(JournalManagerError::UnexpectedEntry);
    }
    let sequence = digits
        .parse::<u64>()
        .map_err(|_| JournalManagerError::UnexpectedEntry)?;
    if sequence == 0
        || segment_file_name(NonZeroU64::new(sequence).ok_or(JournalManagerError::UnexpectedEntry)?)
            != text
    {
        return Err(JournalManagerError::UnexpectedEntry);
    }
    Ok(sequence)
}

fn segment_file_name(sequence: NonZeroU64) -> String {
    format!("{SEGMENT_PREFIX}{:0SEGMENT_DIGITS$}", sequence.get())
}

fn classify_sequence(actual: u64, expected: u64) -> Result<(), JournalManagerError> {
    if actual < expected {
        Err(JournalManagerError::Rewind)
    } else if actual > expected {
        Err(JournalManagerError::SequenceGap)
    } else {
        Ok(())
    }
}

fn validate_records<V: JournalVerifier>(
    verifier: &V,
    identity: &SegmentIdentity,
    records: &[Vec<u8>],
    record_digests: &mut BTreeSet<EvidenceRecordDigest>,
) -> Result<(), JournalManagerError> {
    for record in records {
        verifier.validate_record(identity, record)?;
        if !record_digests.insert(EvidenceRecordDigest::compute(record)) {
            return Err(JournalManagerError::DuplicateRecord);
        }
    }
    Ok(())
}

fn ensure_matching_signer<V: JournalVerifier>(
    verifier: &V,
    identity: &SegmentIdentity,
    signer: &JournalSigner<'_>,
) -> Result<(), JournalManagerError> {
    let resolved = verifier.resolve_signer(identity)?;
    let supplied = signer.key.verifying_key().to_bytes();
    if &identity.signer_kid != signer.kid
        || identity.signer_public_key != supplied
        || resolved.to_bytes() != supplied
    {
        return Err(JournalManagerError::Verification(
            JournalVerificationError::UnknownSigner,
        ));
    }
    Ok(())
}

fn fits_total(current: u64, add: usize, reserve: usize, maximum: u64) -> bool {
    fits_total_with_logical_reservation(current, add, reserve, 0, maximum)
}

fn preflight_recovery_records(
    limits: &JournalLimits,
    discovered_segments: usize,
    total_bytes: u64,
    closes_active_tail: bool,
    current_sequence: u64,
    recovered_record_digests: &BTreeSet<EvidenceRecordDigest>,
    records: &[Vec<u8>],
) -> Result<(), JournalManagerError> {
    if records.is_empty() {
        return Ok(());
    }
    let bounds = limits.segment;
    if u32::try_from(bounds.max_record_bytes()).is_err() {
        return Err(JournalManagerError::Journal(JournalError::RecordTooLarge));
    }
    let mut planned_digests = BTreeSet::new();
    for record in records {
        if record.len() > bounds.max_record_bytes() || u32::try_from(record.len()).is_err() {
            return Err(JournalManagerError::Journal(JournalError::RecordTooLarge));
        }
        let digest = EvidenceRecordDigest::compute(record);
        if recovered_record_digests.contains(&digest) || !planned_digests.insert(digest) {
            return Err(JournalManagerError::DuplicateRecord);
        }
    }

    let maximum_frame_bytes =
        ActiveEvidenceSegment::framed_record_bytes(bounds.max_record_bytes())?;
    let maximum_complete_record_segment = ActiveEvidenceSegment::maximum_header_bytes()
        .checked_add(ActiveEvidenceSegment::footer_bytes())
        .and_then(|bytes| bytes.checked_add(maximum_frame_bytes))
        .ok_or(JournalManagerError::ReservationUnavailable)?;
    if maximum_complete_record_segment > bounds.max_segment_bytes() {
        return Err(JournalManagerError::Journal(
            JournalError::RecordCannotFitSegment,
        ));
    }

    let record_count = records.len();
    let projected_segment_count = discovered_segments
        .checked_add(1)
        .and_then(|count| count.checked_add(record_count))
        .ok_or(JournalManagerError::ReservationUnavailable)?;
    if projected_segment_count > limits.max_segments {
        return Err(JournalManagerError::ReservationUnavailable);
    }
    let reserved_sequence_span =
        u64::try_from(record_count).map_err(|_| JournalManagerError::SequenceExhausted)?;
    let _ = NonZeroU64::new(current_sequence)
        .and_then(|sequence| sequence.get().checked_add(reserved_sequence_span))
        .ok_or(JournalManagerError::SequenceExhausted)?;

    let old_footer_bytes = if closes_active_tail {
        u64::try_from(ActiveEvidenceSegment::footer_bytes())
            .map_err(|_| JournalManagerError::ReservationUnavailable)?
    } else {
        0
    };
    let current_header_bytes = u64::try_from(ActiveEvidenceSegment::maximum_header_bytes())
        .map_err(|_| JournalManagerError::ReservationUnavailable)?;
    let current_footer_bytes = u64::try_from(ActiveEvidenceSegment::footer_bytes())
        .map_err(|_| JournalManagerError::ReservationUnavailable)?;
    let reserved_unit_bytes = u64::try_from(maximum_complete_record_segment)
        .map_err(|_| JournalManagerError::ReservationUnavailable)?;
    let reserved_records_bytes = reserved_unit_bytes
        .checked_mul(
            u64::try_from(record_count).map_err(|_| JournalManagerError::ReservationUnavailable)?,
        )
        .ok_or(JournalManagerError::ReservationUnavailable)?;
    let projected_total = total_bytes
        .checked_add(old_footer_bytes)
        .and_then(|bytes| bytes.checked_add(current_header_bytes))
        .and_then(|bytes| bytes.checked_add(current_footer_bytes))
        .and_then(|bytes| bytes.checked_add(reserved_records_bytes))
        .ok_or(JournalManagerError::ReservationUnavailable)?;
    if projected_total > limits.max_total_bytes {
        return Err(JournalManagerError::ReservationUnavailable);
    }
    Ok(())
}

fn fits_total_with_logical_reservation(
    current: u64,
    add: usize,
    footer_reserve: usize,
    logical_reservation: u64,
    maximum: u64,
) -> bool {
    let Ok(add) = u64::try_from(add) else {
        return false;
    };
    let Ok(footer_reserve) = u64::try_from(footer_reserve) else {
        return false;
    };
    current
        .checked_add(add)
        .and_then(|bytes| bytes.checked_add(footer_reserve))
        .and_then(|bytes| bytes.checked_add(logical_reservation))
        .is_some_and(|bytes| bytes <= maximum)
}

fn map_commit_error(error: JournalError) -> JournalManagerError {
    if error == JournalError::CommitAmbiguous {
        JournalManagerError::Poisoned
    } else {
        JournalManagerError::Journal(error)
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, LazyLock};

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "haldir-evidence-manager-test-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn journal(&self) -> PathBuf {
            self.0.join("journal")
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    struct TestVerifier {
        signer: VerifyingKey,
        kid: KeyId,
        reject: Option<Vec<u8>>,
    }

    impl JournalVerifier for TestVerifier {
        fn resolve_signer(
            &self,
            identity: &SegmentIdentity,
        ) -> Result<VerifyingKey, JournalVerificationError> {
            if identity.signer_kid != self.kid
                || identity.signer_public_key != self.signer.to_bytes()
            {
                return Err(JournalVerificationError::UnknownSigner);
            }
            VerifyingKey::from_bytes(self.signer.to_bytes())
                .map_err(|_| JournalVerificationError::UnknownSigner)
        }

        fn validate_record(
            &self,
            _identity: &SegmentIdentity,
            record: &[u8],
        ) -> Result<(), JournalVerificationError> {
            if self.reject.as_deref() == Some(record) {
                return Err(JournalVerificationError::InvalidRecord);
            }
            Ok(())
        }
    }

    struct RotatingVerifier {
        signers: Vec<(KeyId, VerifyingKey)>,
    }

    struct CountingVerifier {
        validated: Arc<AtomicU64>,
    }

    impl JournalVerifier for CountingVerifier {
        fn resolve_signer(
            &self,
            identity: &SegmentIdentity,
        ) -> Result<VerifyingKey, JournalVerificationError> {
            verifier().resolve_signer(identity)
        }

        fn validate_record(
            &self,
            _identity: &SegmentIdentity,
            _record: &[u8],
        ) -> Result<(), JournalVerificationError> {
            self.validated.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    impl JournalVerifier for RotatingVerifier {
        fn resolve_signer(
            &self,
            identity: &SegmentIdentity,
        ) -> Result<VerifyingKey, JournalVerificationError> {
            self.signers
                .iter()
                .find(|(kid, key)| {
                    kid == &identity.signer_kid && key.to_bytes() == identity.signer_public_key
                })
                .and_then(|(_, key)| VerifyingKey::from_bytes(key.to_bytes()).ok())
                .ok_or(JournalVerificationError::UnknownSigner)
        }

        fn validate_record(
            &self,
            _identity: &SegmentIdentity,
            _record: &[u8],
        ) -> Result<(), JournalVerificationError> {
            Ok(())
        }
    }

    fn kid() -> KeyId {
        KeyId::new(vec![3, 0xab, 3]).unwrap()
    }

    static TEST_SIGNER: LazyLock<(KeyId, SigningKey)> = LazyLock::new(|| {
        (
            KeyId::new(vec![3, 0xab, 3]).unwrap(),
            SigningKey::from_seed([3; 32]),
        )
    });

    fn signer() -> JournalSigner<'static> {
        JournalSigner::new(&TEST_SIGNER.0, &TEST_SIGNER.1)
    }

    fn verifier() -> TestVerifier {
        TestVerifier {
            signer: SigningKey::from_seed([3; 32]).verifying_key(),
            kid: kid(),
            reject: None,
        }
    }

    fn gate() -> GateId {
        GateId::new("gate-1").unwrap()
    }

    fn limits(max_records: u64, max_segments: usize) -> JournalLimits {
        JournalLimits::new(
            JournalBounds::new(4096, max_records, 1024).unwrap(),
            max_segments,
            64 * 1024,
        )
        .unwrap()
    }

    fn reservation_limits(
        max_records: u64,
        max_segments: usize,
        max_record_bytes: usize,
        max_total_bytes: u64,
    ) -> JournalLimits {
        let maximum_single_record_segment = ActiveEvidenceSegment::maximum_header_bytes()
            + ActiveEvidenceSegment::footer_bytes()
            + ActiveEvidenceSegment::framed_record_bytes(max_record_bytes).unwrap();
        JournalLimits::new(
            JournalBounds::new(maximum_single_record_segment, max_records, max_record_bytes)
                .unwrap(),
            max_segments,
            max_total_bytes,
        )
        .unwrap()
    }

    fn exact_reservation_total_bytes(max_record_bytes: usize, record_count: usize) -> u64 {
        let key = SigningKey::from_seed([3; 32]);
        let current_header =
            ActiveEvidenceSegment::minimum_complete_bytes(&identity(1, [0; 32], 1, &key)).unwrap()
                - ActiveEvidenceSegment::footer_bytes();
        let reserved_unit = ActiveEvidenceSegment::maximum_header_bytes()
            + ActiveEvidenceSegment::footer_bytes()
            + ActiveEvidenceSegment::framed_record_bytes(max_record_bytes).unwrap();
        u64::try_from(
            current_header + ActiveEvidenceSegment::footer_bytes() + reserved_unit * record_count,
        )
        .unwrap()
    }

    fn options(boot: u8, limits: JournalLimits) -> JournalOpenOptions {
        JournalOpenOptions::new(gate(), GateBootId::new([boot; 16]), u64::from(boot), limits)
    }

    fn open(
        directory: &Path,
        boot: u8,
        limits: JournalLimits,
    ) -> Result<(EvidenceJournalManager<TestVerifier>, JournalRecoveryReport), JournalManagerError>
    {
        let recovered_tail_signer = signer();
        if directory.exists() {
            EvidenceJournalManager::open_existing(
                directory,
                options(boot, limits),
                &signer(),
                Some(&recovered_tail_signer),
                verifier(),
            )
        } else {
            EvidenceJournalManager::provision_new(
                directory,
                options(boot, limits),
                &signer(),
                verifier(),
            )
        }
    }

    fn open_with_recovered_records(
        directory: &Path,
        boot: u8,
        limits: JournalLimits,
        capture_limits: RecoveryCaptureLimits,
    ) -> Result<(EvidenceJournalManager<TestVerifier>, JournalRecovery), JournalManagerError> {
        let recovered_tail_signer = signer();
        if directory.exists() {
            EvidenceJournalManager::open_existing_with_recovered_records(
                directory,
                options(boot, limits),
                &signer(),
                Some(&recovered_tail_signer),
                capture_limits,
                verifier(),
            )
        } else {
            EvidenceJournalManager::provision_new_with_recovered_records(
                directory,
                options(boot, limits),
                &signer(),
                capture_limits,
                verifier(),
            )
        }
    }

    fn seed_lock(directory: &Path) {
        fs::write(directory.join(LOCK_FILE_NAME), []).unwrap();
    }

    #[test]
    fn open_existing_never_creates_missing_or_empty_state() {
        let directory = TestDirectory::new();
        let missing = directory.journal();
        let result = EvidenceJournalManager::open_existing(
            &missing,
            options(1, limits(4, 4)),
            &signer(),
            None,
            verifier(),
        );
        assert!(matches!(result, Err(JournalManagerError::Missing)));
        assert!(!missing.exists());

        fs::create_dir(&missing).unwrap();
        let empty = EvidenceJournalManager::open_existing(
            &missing,
            options(1, limits(4, 4)),
            &signer(),
            None,
            verifier(),
        );
        assert!(matches!(empty, Err(JournalManagerError::Missing)));
        assert!(fs::read_dir(&missing).unwrap().next().is_none());
    }

    #[test]
    fn unusable_genesis_capacity_is_rejected_before_directory_creation() {
        let directory = TestDirectory::new();
        let journal = directory.journal();
        let tiny_limits =
            JournalLimits::new(JournalBounds::new(4096, 4, 1024).unwrap(), 1, 1).unwrap();

        assert!(matches!(
            EvidenceJournalManager::provision_new(
                &journal,
                options(1, tiny_limits),
                &signer(),
                verifier(),
            ),
            Err(JournalManagerError::Quiesced)
        ));
        assert!(!journal.exists());
    }

    #[test]
    fn provision_new_is_explicit_and_never_overwrites_interrupted_genesis() {
        let directory = TestDirectory::new();
        let journal = directory.journal();
        let (manager, report) = EvidenceJournalManager::provision_new(
            &journal,
            options(1, limits(4, 4)),
            &signer(),
            verifier(),
        )
        .unwrap();
        assert_eq!(report.discovered_segments, 0);
        drop(manager);
        assert!(matches!(
            EvidenceJournalManager::provision_new(
                &journal,
                options(1, limits(4, 4)),
                &signer(),
                verifier(),
            ),
            Err(JournalManagerError::AlreadyProvisioned)
        ));

        let interrupted = directory.0.join("interrupted");
        fs::create_dir(&interrupted).unwrap();
        seed_lock(&interrupted);
        let final_name = segment_file_name(NonZeroU64::new(1).unwrap());
        let pending = interrupted.join(format!("{PENDING_CREATION_PREFIX}{final_name}"));
        fs::write(&pending, b"partial genesis").unwrap();
        assert!(matches!(
            EvidenceJournalManager::open_existing(
                &interrupted,
                options(1, limits(4, 4)),
                &signer(),
                None,
                verifier(),
            ),
            Err(JournalManagerError::IncompleteProvisioning)
        ));
        assert!(pending.exists());
    }

    #[test]
    fn retained_file_lock_excludes_a_second_manager() {
        let directory = TestDirectory::new();
        let (first, _) = open(&directory.journal(), 1, limits(4, 4)).unwrap();

        let second = open(&directory.journal(), 2, limits(4, 4));

        assert!(matches!(second, Err(JournalManagerError::LockHeld)));
        drop(first);
    }

    #[test]
    fn wrong_borrowed_signer_is_rejected_before_nonrotating_append() {
        let directory = TestDirectory::new();
        let (mut manager, _) = open(&directory.journal(), 1, limits(4, 4)).unwrap();
        let wrong_kid = kid();
        let wrong_key = SigningKey::from_seed([4; 32]);
        let wrong_signer = JournalSigner::new(&wrong_kid, &wrong_key);
        let record = b"not-written";

        assert_eq!(
            manager.append(record, 1, &wrong_signer),
            Err(JournalManagerError::Verification(
                JournalVerificationError::UnknownSigner
            ))
        );
        assert_eq!(
            manager.contains_record(EvidenceRecordDigest::compute(record)),
            Ok(false)
        );
        let other_kid = KeyId::new(vec![9, 0xab, 9]).unwrap();
        let wrong_kid_signer = JournalSigner::new(&other_kid, &TEST_SIGNER.1);
        assert_eq!(
            manager.append(record, 1, &wrong_kid_signer),
            Err(JournalManagerError::Verification(
                JournalVerificationError::UnknownSigner
            ))
        );
        assert_eq!(
            manager.contains_record(EvidenceRecordDigest::compute(record)),
            Ok(false)
        );
        manager.append(record, 1, &signer()).unwrap();
    }

    #[test]
    fn wrong_borrowed_signer_cannot_trigger_rotation() {
        let directory = TestDirectory::new();
        let (mut manager, _) = open(&directory.journal(), 1, limits(1, 3)).unwrap();
        manager.append(b"one", 1, &signer()).unwrap();
        let wrong_key = SigningKey::from_seed([4; 32]);
        let expected_kid = kid();
        let wrong_signer = JournalSigner::new(&expected_kid, &wrong_key);

        assert_eq!(
            manager.append(b"two", 2, &wrong_signer),
            Err(JournalManagerError::Verification(
                JournalVerificationError::UnknownSigner
            ))
        );
        assert_eq!(manager.active_sequence().map(NonZeroU64::get), Some(1));
        assert!(!manager.is_quiesced());
        manager.append(b"two", 2, &signer()).unwrap();
        assert_eq!(manager.active_sequence().map(NonZeroU64::get), Some(2));
    }

    #[test]
    fn batch_preflight_reserves_logical_rotation_capacity_without_mutation() {
        let directory = TestDirectory::new();
        let (mut manager, _) = open(&directory.journal(), 1, limits(1, 2)).unwrap();

        manager.preflight_append_batch(&[3, 3]).unwrap();
        assert_eq!(
            manager.preflight_append_batch(&[3, 3, 3]),
            Err(JournalManagerError::Quiesced)
        );
        assert_eq!(manager.active_sequence().map(NonZeroU64::get), Some(1));
        assert!(!manager.is_quiesced());

        manager.append(b"one", 1, &signer()).unwrap();
        manager.append(b"two", 2, &signer()).unwrap();
        assert_eq!(manager.active_sequence().map(NonZeroU64::get), Some(2));
        assert!(!manager.is_quiesced());
    }

    #[test]
    fn batch_preflight_rejects_permanent_record_bounds_without_quiescing() {
        let directory = TestDirectory::new();
        let (mut manager, _) = open(&directory.journal(), 1, limits(4, 2)).unwrap();

        assert_eq!(
            manager.preflight_append_batch(&[1025]),
            Err(JournalManagerError::Journal(JournalError::RecordTooLarge))
        );
        assert!(!manager.is_quiesced());
        manager.append(b"fits", 1, &signer()).unwrap();
    }

    #[test]
    fn reservation_accepts_the_exact_maximum_header_frame_and_footer_bound() {
        let directory = TestDirectory::new();
        let maximum_record_bytes = 8;
        let maximum = exact_reservation_total_bytes(maximum_record_bytes, 1);
        let configured = reservation_limits(4, 2, maximum_record_bytes, maximum);
        let (mut manager, _) = open(&directory.journal(), 1, configured).unwrap();

        let reservation = manager.reserve_append_capacity(1);

        assert!(reservation.is_ok(), "exact logical bound was rejected");
    }

    #[test]
    fn reservation_rejects_one_byte_below_the_maximum_header_bound() {
        let directory = TestDirectory::new();
        let maximum_record_bytes = 8;
        let maximum = exact_reservation_total_bytes(maximum_record_bytes, 1) - 1;
        let configured = reservation_limits(4, 2, maximum_record_bytes, maximum);
        let (mut manager, _) = open(&directory.journal(), 1, configured).unwrap();

        assert!(matches!(
            manager.reserve_append_capacity(1),
            Err(JournalManagerError::ReservationUnavailable)
        ));
    }

    #[test]
    fn ordinary_append_cannot_consume_reserved_byte_capacity() {
        let directory = TestDirectory::new();
        let maximum_record_bytes = 8;
        let maximum = exact_reservation_total_bytes(maximum_record_bytes, 1);
        let configured = reservation_limits(4, 2, maximum_record_bytes, maximum);
        let (mut manager, _) = open(&directory.journal(), 1, configured).unwrap();
        let mut reservation = manager.reserve_append_capacity(1).unwrap();

        assert_eq!(
            manager.append(b"x", 1, &signer()),
            Err(JournalManagerError::ReservationUnavailable)
        );
        manager
            .append_reserved(&mut reservation, b"x", 1, &signer())
            .unwrap();
        assert_eq!(
            manager.append_reserved(&mut reservation, b"y", 1, &signer()),
            Err(JournalManagerError::ReservationExhausted)
        );
    }

    #[test]
    fn releasing_a_cancelled_reservation_restores_ordinary_capacity() {
        let directory = TestDirectory::new();
        let maximum_record_bytes = 8;
        let maximum = exact_reservation_total_bytes(maximum_record_bytes, 1);
        let configured = reservation_limits(4, 2, maximum_record_bytes, maximum);
        let (mut manager, _) = open(&directory.journal(), 1, configured).unwrap();
        let mut reservation = manager.reserve_append_capacity(1).unwrap();

        manager.release_reservation(&mut reservation).unwrap();

        manager.append(b"x", 1, &signer()).unwrap();
    }

    #[test]
    fn reservation_from_another_manager_is_rejected_without_consumption() {
        let first_directory = TestDirectory::new();
        let second_directory = TestDirectory::new();
        let (mut first, _) = open(&first_directory.journal(), 1, limits(4, 3)).unwrap();
        let (mut second, _) = open(&second_directory.journal(), 1, limits(4, 3)).unwrap();
        let mut reservation = first.reserve_append_capacity(1).unwrap();

        assert_eq!(
            second.append_reserved(&mut reservation, b"record", 1, &signer()),
            Err(JournalManagerError::ReservationMismatch)
        );
        first
            .append_reserved(&mut reservation, b"record", 1, &signer())
            .unwrap();
    }

    #[test]
    fn foreign_release_rejection_preserves_the_issuing_manager_token() {
        let first_directory = TestDirectory::new();
        let second_directory = TestDirectory::new();
        let (mut first, _) = open(&first_directory.journal(), 1, limits(4, 3)).unwrap();
        let (mut second, _) = open(&second_directory.journal(), 1, limits(4, 3)).unwrap();
        let mut reservation = first.reserve_append_capacity(1).unwrap();

        assert_eq!(
            second.release_reservation(&mut reservation),
            Err(JournalManagerError::ReservationMismatch)
        );
        first.release_reservation(&mut reservation).unwrap();
        first.append(b"record", 1, &signer()).unwrap();
    }

    #[test]
    fn failed_reserved_append_does_not_consume_a_unit() {
        let directory = TestDirectory::new();
        let (mut manager, _) = open(&directory.journal(), 1, limits(4, 2)).unwrap();
        let mut reservation = manager.reserve_append_capacity(1).unwrap();
        let wrong_key = SigningKey::from_seed([4; 32]);
        let expected_kid = kid();
        let wrong_signer = JournalSigner::new(&expected_kid, &wrong_key);

        assert_eq!(
            manager.append_reserved(&mut reservation, b"record", 1, &wrong_signer),
            Err(JournalManagerError::Verification(
                JournalVerificationError::UnknownSigner
            ))
        );
        manager
            .append_reserved(&mut reservation, b"record", 1, &signer())
            .unwrap();
    }

    #[test]
    fn reserved_append_can_consume_its_dedicated_rotation_slot() {
        let directory = TestDirectory::new();
        let (mut manager, _) = open(&directory.journal(), 1, limits(1, 2)).unwrap();
        manager.append(b"seed", 1, &signer()).unwrap();
        let mut reservation = manager.reserve_append_capacity(1).unwrap();

        assert_eq!(
            manager.append(b"ordinary", 2, &signer()),
            Err(JournalManagerError::ReservationUnavailable)
        );
        assert_eq!(manager.active_sequence().map(NonZeroU64::get), Some(1));
        manager
            .append_reserved(&mut reservation, b"reserved", 2, &signer())
            .unwrap();
        assert_eq!(manager.active_sequence().map(NonZeroU64::get), Some(2));
    }

    #[test]
    fn wrong_finish_signer_writes_nothing_and_recovery_can_close_tail() {
        let directory = TestDirectory::new();
        let journal = directory.journal();
        let (mut manager, _) = open(&journal, 1, limits(4, 4)).unwrap();
        manager.append(b"one", 1, &signer()).unwrap();
        let path = journal.join(segment_file_name(NonZeroU64::new(1).unwrap()));
        let bytes_before = fs::metadata(&path).unwrap().len();
        let wrong_key = SigningKey::from_seed([4; 32]);
        let expected_kid = kid();
        let wrong_signer = JournalSigner::new(&expected_kid, &wrong_key);

        assert!(matches!(
            manager.finish(&wrong_signer),
            Err(JournalManagerError::Verification(
                JournalVerificationError::UnknownSigner
            ))
        ));
        assert_eq!(fs::metadata(&path).unwrap().len(), bytes_before);

        let (_, report) = open(&journal, 2, limits(4, 4)).unwrap();
        assert!(report.closed_active_tail);
        assert_eq!(report.recovered_records, 1);
    }

    #[test]
    fn contiguous_recovery_closes_old_boot_tail_and_starts_new_boot() {
        let directory = TestDirectory::new();
        let (mut first, _) = open(&directory.journal(), 1, limits(4, 4)).unwrap();
        first.append(b"one", 1, &signer()).unwrap();
        drop(first);

        let (second, report) = open(&directory.journal(), 2, limits(4, 4)).unwrap();

        assert!(report.closed_active_tail);
        assert_eq!(report.completed_segments, 1);
        assert_eq!(report.recovered_records, 1);
        assert_eq!(second.active_sequence().map(NonZeroU64::get), Some(2));
    }

    #[test]
    fn captured_recovery_preserves_exact_segment_and_record_order() {
        let directory = TestDirectory::new();
        let journal = directory.journal();
        let journal_limits = limits(2, 6);
        let capture_limits = RecoveryCaptureLimits::new(8, 64);

        let (first, initial) =
            open_with_recovered_records(&journal, 1, journal_limits, capture_limits).unwrap();
        assert_eq!(initial.report().discovered_segments, 0);
        assert!(initial.segments().is_empty());
        assert_eq!(initial.records().count(), 0);
        assert_eq!(initial.record_bytes(), 0);
        drop(first.finish(&signer()).unwrap());

        let (mut second, _) = open(&journal, 2, journal_limits).unwrap();
        second.append(b"z-first", 2, &signer()).unwrap();
        second.append(b"a-second", 2, &signer()).unwrap();
        second.append(b"m-third", 2, &signer()).unwrap();
        drop(second);

        let (third, recovered) =
            open_with_recovered_records(&journal, 3, journal_limits, capture_limits).unwrap();
        assert_eq!(recovered.report().discovered_segments, 3);
        assert_eq!(recovered.report().recovered_records, 3);
        assert_eq!(
            recovered.report().active_sequence.map(NonZeroU64::get),
            Some(4)
        );
        assert_eq!(recovered.record_bytes(), 22);
        assert_eq!(
            recovered
                .segments()
                .iter()
                .map(|segment| segment.identity().segment_sequence.get())
                .collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
        assert_eq!(recovered.segments()[0].record_count(), 0);
        assert_eq!(
            recovered
                .records()
                .map(|(identity, record)| { (identity.segment_sequence.get(), record.to_vec()) })
                .collect::<Vec<_>>(),
            vec![
                (2, b"z-first".to_vec()),
                (2, b"a-second".to_vec()),
                (3, b"m-third".to_vec()),
            ]
        );
        assert_eq!(third.active_sequence().map(NonZeroU64::get), Some(4));
    }

    #[test]
    fn recovered_record_capture_fails_closed_at_exact_count_and_byte_bounds() {
        let directory = TestDirectory::new();
        let journal = directory.journal();
        let journal_limits = limits(4, 4);
        let (mut first, _) = open(&journal, 1, journal_limits).unwrap();
        first.append(b"one", 1, &signer()).unwrap();
        first.append(b"two", 1, &signer()).unwrap();
        drop(first);
        let active_path = journal.join(segment_file_name(NonZeroU64::new(1).unwrap()));
        let active_before = fs::read(&active_path).unwrap();

        assert!(matches!(
            open_with_recovered_records(
                &journal,
                2,
                journal_limits,
                RecoveryCaptureLimits::new(1, 64),
            ),
            Err(JournalManagerError::RecoveryCaptureLimitExceeded {
                dimension: RecoveryCaptureDimension::RecordCount,
                maximum: 1,
                required: 2,
            })
        ));
        assert_eq!(fs::read(&active_path).unwrap(), active_before);
        assert!(matches!(
            open_with_recovered_records(
                &journal,
                2,
                journal_limits,
                RecoveryCaptureLimits::new(2, 5),
            ),
            Err(JournalManagerError::RecoveryCaptureLimitExceeded {
                dimension: RecoveryCaptureDimension::RecordBytes,
                maximum: 5,
                required: 6,
            })
        ));
        assert_eq!(fs::read(&active_path).unwrap(), active_before);
        assert!(
            !journal
                .join(segment_file_name(NonZeroU64::new(2).unwrap()))
                .exists()
        );

        let (second, recovered) = open_with_recovered_records(
            &journal,
            2,
            journal_limits,
            RecoveryCaptureLimits::new(2, 6),
        )
        .unwrap();
        assert!(recovered.report().closed_active_tail);
        assert_eq!(recovered.report().recovered_records, 2);
        assert_eq!(recovered.record_bytes(), 6);
        assert_eq!(
            recovered
                .records()
                .map(|(_, record)| record.to_vec())
                .collect::<Vec<_>>(),
            vec![b"one".to_vec(), b"two".to_vec()]
        );
        assert_eq!(second.active_sequence().map(NonZeroU64::get), Some(2));
    }

    #[test]
    fn later_record_verification_failure_returns_no_recovery_snapshot() {
        let directory = TestDirectory::new();
        let journal = directory.journal();
        let journal_limits = limits(1, 4);
        let (mut first, _) = open(&journal, 1, journal_limits).unwrap();
        first.append(b"good", 1, &signer()).unwrap();
        first.append(b"bad", 1, &signer()).unwrap();
        drop(first.finish(&signer()).unwrap());

        let mut rejecting = verifier();
        rejecting.reject = Some(b"bad".to_vec());
        let result = EvidenceJournalManager::open_existing_with_recovered_records(
            &journal,
            options(2, journal_limits),
            &signer(),
            None,
            RecoveryCaptureLimits::new(2, 7),
            rejecting,
        );
        assert!(matches!(
            result,
            Err(JournalManagerError::Verification(
                JournalVerificationError::InvalidRecord
            ))
        ));
        assert!(
            !journal
                .join(segment_file_name(NonZeroU64::new(3).unwrap()))
                .exists()
        );
    }

    #[test]
    fn captured_recovery_excludes_a_structurally_matching_partial_tail() {
        let directory = TestDirectory::new();
        let journal = directory.journal();
        let journal_limits = limits(4, 4);
        let (mut first, _) = open(&journal, 1, journal_limits).unwrap();
        first.append(b"complete", 1, &signer()).unwrap();
        drop(first);

        let active_path = journal.join(segment_file_name(NonZeroU64::new(1).unwrap()));
        OpenOptions::new()
            .append(true)
            .open(&active_path)
            .unwrap()
            .write_all(b"EVR1")
            .unwrap();

        let (second, recovered) = open_with_recovered_records(
            &journal,
            2,
            journal_limits,
            RecoveryCaptureLimits::new(1, 8),
        )
        .unwrap();
        assert_eq!(recovered.report().truncated_tail_bytes, 4);
        assert_eq!(recovered.report().discovered_segments, 1);
        assert_eq!(recovered.segments().len(), 1);
        assert_eq!(
            recovered
                .records()
                .map(|(_, record)| record.to_vec())
                .collect::<Vec<_>>(),
            vec![b"complete".to_vec()]
        );
        assert_eq!(second.active_sequence().map(NonZeroU64::get), Some(2));
    }

    #[test]
    fn candidate_validation_never_implies_ambiguous_append_recovery_state() {
        let directory = TestDirectory::new();
        let journal = directory.journal();
        let journal_limits = limits(1, 4);
        let validated = Arc::new(AtomicU64::new(0));
        let (mut first, _) = EvidenceJournalManager::provision_new(
            &journal,
            options(1, journal_limits),
            &signer(),
            CountingVerifier {
                validated: Arc::clone(&validated),
            },
        )
        .unwrap();
        first.append(b"prepared", 1, &signer()).unwrap();
        crate::journal::inject_create_publication_commit_ambiguous_once();
        assert_eq!(
            first.append(b"called", 1, &signer()),
            Err(JournalManagerError::AppendCommitAmbiguous {
                record_digest: EvidenceRecordDigest::compute(b"called"),
            })
        );
        assert_eq!(validated.load(Ordering::Relaxed), 2);
        drop(first);

        let (second, recovered) = open_with_recovered_records(
            &journal,
            2,
            journal_limits,
            RecoveryCaptureLimits::new(1, 8),
        )
        .unwrap();
        assert!(recovered.report().discarded_pending_creation);
        assert_eq!(
            recovered
                .segments()
                .iter()
                .map(RecoveredJournalSegment::record_count)
                .collect::<Vec<_>>(),
            vec![1, 0]
        );
        assert_eq!(
            recovered
                .records()
                .map(|(_, record)| record.to_vec())
                .collect::<Vec<_>>(),
            vec![b"prepared".to_vec()]
        );
        assert_eq!(second.active_sequence().map(NonZeroU64::get), Some(3));
    }

    #[test]
    fn sequence_gap_is_rejected() {
        let directory = TestDirectory::new();
        let journal = directory.journal();
        fs::create_dir(&journal).unwrap();
        seed_lock(&journal);
        let key = SigningKey::from_seed([3; 32]);
        let identity = identity(1, [0; 32], 1, &key);
        ActiveEvidenceSegment::create_new(
            journal.join(segment_file_name(NonZeroU64::new(2).unwrap())),
            identity,
            limits(4, 4).segment,
        )
        .unwrap();

        assert!(matches!(
            open(&journal, 2, limits(4, 4)),
            Err(JournalManagerError::SequenceGap)
        ));
    }

    #[test]
    fn previous_digest_fork_is_rejected() {
        let directory = TestDirectory::new();
        let journal = directory.journal();
        let alternate = directory.0.join("alternate");
        fs::create_dir(&journal).unwrap();
        fs::create_dir(&alternate).unwrap();
        seed_lock(&journal);
        let key = SigningKey::from_seed([3; 32]);
        let first = ActiveEvidenceSegment::create_new(
            journal.join(segment_file_name(NonZeroU64::new(1).unwrap())),
            identity(1, [0; 32], 1, &key),
            limits(4, 4).segment,
        )
        .unwrap()
        .close(&kid(), &key)
        .unwrap();
        let alternate_first = ActiveEvidenceSegment::create_new(
            alternate.join("first"),
            identity(1, [0; 32], 1, &key),
            limits(4, 4).segment,
        )
        .unwrap();
        let mut alternate_first = alternate_first;
        alternate_first.append(b"different").unwrap();
        let alternate_first = alternate_first.close(&kid(), &key).unwrap();
        let second_identity = identity(2, alternate_first.segment_digest(), 1, &key);
        ActiveEvidenceSegment::create_next(
            journal.join(segment_file_name(NonZeroU64::new(2).unwrap())),
            second_identity,
            limits(4, 4).segment,
            &alternate_first,
        )
        .unwrap();
        drop(first);

        assert!(matches!(
            open(&journal, 2, limits(4, 4)),
            Err(JournalManagerError::Fork)
        ));
    }

    #[test]
    fn unexpected_directory_entry_is_rejected() {
        let directory = TestDirectory::new();
        let journal = directory.journal();
        fs::create_dir(&journal).unwrap();
        seed_lock(&journal);
        fs::write(journal.join("unexpected"), b"x").unwrap();

        assert!(matches!(
            open(&journal, 1, limits(4, 4)),
            Err(JournalManagerError::UnexpectedEntry)
        ));
    }

    #[test]
    fn global_segment_cap_quiesces_without_deleting() {
        let directory = TestDirectory::new();
        let journal = directory.journal();
        let (mut manager, _) = open(&journal, 1, limits(1, 1)).unwrap();
        manager.append(b"one", 1, &signer()).unwrap();

        assert_eq!(
            manager.append(b"two", 2, &signer()),
            Err(JournalManagerError::Quiesced)
        );
        assert!(manager.is_quiesced());
        assert_eq!(manager.active_sequence(), None);
        assert!(
            journal
                .join(segment_file_name(NonZeroU64::new(1).unwrap()))
                .is_file()
        );
        assert!(
            !journal
                .join(segment_file_name(NonZeroU64::new(2).unwrap()))
                .exists()
        );
    }

    #[test]
    fn global_byte_cap_footer_completes_then_quiesces_without_deleting() {
        let directory = TestDirectory::new();
        let journal = directory.journal();
        let key = SigningKey::from_seed([3; 32]);
        let bounds = JournalBounds::new(4096, 4, 1024).unwrap();
        let maximum = ActiveEvidenceSegment::minimum_complete_bytes(&identity(1, [0; 32], 1, &key))
            .unwrap()
            .checked_add(ActiveEvidenceSegment::framed_record_bytes(b"one".len()).unwrap())
            .unwrap();
        let limits = JournalLimits::new(bounds, 4, u64::try_from(maximum).unwrap()).unwrap();
        let (mut manager, _) = open(&journal, 1, limits).unwrap();
        manager.append(b"one", 1, &signer()).unwrap();
        let wrong_key = SigningKey::from_seed([4; 32]);
        let expected_kid = kid();
        let wrong_signer = JournalSigner::new(&expected_kid, &wrong_key);

        assert_eq!(
            manager.append(b"two", 2, &wrong_signer),
            Err(JournalManagerError::Verification(
                JournalVerificationError::UnknownSigner
            ))
        );
        assert!(!manager.is_quiesced());
        assert_eq!(manager.active_sequence().map(NonZeroU64::get), Some(1));

        assert_eq!(
            manager.append(b"two", 2, &signer()),
            Err(JournalManagerError::Quiesced)
        );
        assert!(manager.is_quiesced());
        let path = journal.join(segment_file_name(NonZeroU64::new(1).unwrap()));
        let identity = ActiveEvidenceSegment::inspect_identity(&path, bounds).unwrap();
        let recovered =
            ActiveEvidenceSegment::recover(path, &identity, bounds, &key.verifying_key()).unwrap();
        let RecoveredEvidenceSegment::Completed(completed) = recovered else {
            panic!("quiescence must complete the retained tail");
        };
        assert_eq!(completed.records(), &[b"one".to_vec()]);
    }

    #[test]
    fn permanent_record_error_is_classified_before_global_capacity() {
        let directory = TestDirectory::new();
        let key = SigningKey::from_seed([3; 32]);
        let bounds = JournalBounds::new(4096, 4, 3).unwrap();
        let maximum = ActiveEvidenceSegment::minimum_complete_bytes(&identity(1, [0; 32], 1, &key))
            .unwrap()
            .checked_add(ActiveEvidenceSegment::framed_record_bytes(b"one".len()).unwrap())
            .unwrap();
        let limits = JournalLimits::new(bounds, 4, u64::try_from(maximum).unwrap()).unwrap();
        let (mut manager, _) = open(&directory.journal(), 1, limits).unwrap();

        assert_eq!(
            manager.append(b"four", 1, &signer()),
            Err(JournalManagerError::Journal(JournalError::RecordTooLarge))
        );
        manager.append(b"one", 2, &signer()).unwrap();
        assert!(!manager.is_quiesced());
        assert_eq!(manager.active_sequence().map(NonZeroU64::get), Some(1));
    }

    #[cfg(unix)]
    #[test]
    fn ambiguous_successor_publication_permanently_poisoned_manager_cannot_mutate() {
        let directory = TestDirectory::new();
        let journal = directory.journal();
        let (mut manager, _) = open(&journal, 1, limits(1, 3)).unwrap();
        manager.append(b"one", 1, &signer()).unwrap();
        crate::journal::inject_create_publication_commit_ambiguous_once();

        assert_eq!(
            manager.append(b"two", 2, &signer()),
            Err(JournalManagerError::AppendCommitAmbiguous {
                record_digest: EvidenceRecordDigest::compute(b"two"),
            })
        );
        assert_eq!(manager.active_sequence(), None);

        let successor_name = segment_file_name(NonZeroU64::new(2).unwrap());
        let successor = journal.join(&successor_name);
        let pending = journal.join(format!("{PENDING_CREATION_PREFIX}{successor_name}"));
        let bytes_before_rejected_append =
            (fs::read(&successor).unwrap(), fs::read(&pending).unwrap());

        assert_eq!(
            manager.append(b"three", 3, &signer()),
            Err(JournalManagerError::Poisoned)
        );
        assert_eq!(
            (fs::read(successor).unwrap(), fs::read(pending).unwrap()),
            bytes_before_rejected_append
        );
    }

    #[test]
    fn rotation_appends_the_pending_record_exactly_once() {
        let directory = TestDirectory::new();
        let journal = directory.journal();
        let (mut manager, _) = open(&journal, 1, limits(1, 3)).unwrap();
        manager.append(b"one", 1, &signer()).unwrap();
        manager.append(b"two", 2, &signer()).unwrap();
        manager.finish(&signer()).unwrap();

        let mut occurrences = 0usize;
        for sequence in 1..=2 {
            let path = journal.join(segment_file_name(NonZeroU64::new(sequence).unwrap()));
            let identity =
                ActiveEvidenceSegment::inspect_identity(&path, limits(1, 3).segment).unwrap();
            let recovered = ActiveEvidenceSegment::recover(
                path,
                &identity,
                limits(1, 3).segment,
                &SigningKey::from_seed([3; 32]).verifying_key(),
            )
            .unwrap();
            let RecoveredEvidenceSegment::Completed(completed) = recovered else {
                panic!("finished segments must be completed");
            };
            occurrences += completed
                .records()
                .iter()
                .filter(|record| record.as_slice() == b"two")
                .count();
        }
        assert_eq!(occurrences, 1);
    }

    #[test]
    fn exact_record_digest_prevents_duplicate_retry_across_recovery() {
        let directory = TestDirectory::new();
        let journal = directory.journal();
        let digest = EvidenceRecordDigest::compute(b"one");
        let (mut first, _) = open(&journal, 1, limits(4, 4)).unwrap();
        first.append(b"one", 1, &signer()).unwrap();
        assert_eq!(first.contains_record(digest), Ok(true));
        assert_eq!(
            first.append(b"one", 1, &signer()),
            Err(JournalManagerError::DuplicateRecord)
        );
        drop(first);

        let (mut recovered, _) = open(&journal, 2, limits(4, 4)).unwrap();
        assert_eq!(recovered.contains_record(digest), Ok(true));
        assert_eq!(
            recovered.append(b"one", 2, &signer()),
            Err(JournalManagerError::DuplicateRecord)
        );
    }

    #[test]
    fn invalid_record_and_signer_are_rejected() {
        let directory = TestDirectory::new();
        let mut rejecting = verifier();
        rejecting.reject = Some(b"bad".to_vec());
        let (mut manager, _) = EvidenceJournalManager::provision_new(
            directory.journal(),
            options(1, limits(4, 4)),
            &signer(),
            rejecting,
        )
        .unwrap();
        assert_eq!(
            manager.append(b"bad", 1, &signer()),
            Err(JournalManagerError::Verification(
                JournalVerificationError::InvalidRecord
            ))
        );
        drop(manager);

        let wrong = TestVerifier {
            signer: SigningKey::from_seed([4; 32]).verifying_key(),
            kid: kid(),
            reject: None,
        };
        let recovered_tail_signer = signer();
        assert!(matches!(
            EvidenceJournalManager::open_existing(
                directory.journal(),
                options(2, limits(4, 4)),
                &signer(),
                Some(&recovered_tail_signer),
                wrong,
            ),
            Err(JournalManagerError::Verification(
                JournalVerificationError::UnknownSigner
            ))
        ));
    }

    #[test]
    fn old_tail_requires_its_signer_before_current_key_rotation() {
        let directory = TestDirectory::new();
        let journal = directory.journal();
        let old_kid = KeyId::new(vec![3, 0xa1, 1]).unwrap();
        let old_key = SigningKey::from_seed([0xa1; 32]);
        let new_kid = KeyId::new(vec![3, 0xb2, 1]).unwrap();
        let new_key = SigningKey::from_seed([0xb2; 32]);
        let verifier = || RotatingVerifier {
            signers: vec![
                (old_kid.clone(), old_key.verifying_key()),
                (new_kid.clone(), new_key.verifying_key()),
            ],
        };
        let old_signer = JournalSigner::new(&old_kid, &old_key);
        let new_signer = JournalSigner::new(&new_kid, &new_key);
        let (mut first, _) = EvidenceJournalManager::provision_new(
            &journal,
            options(1, limits(4, 4)),
            &old_signer,
            verifier(),
        )
        .unwrap();
        first.append(b"old", 1, &old_signer).unwrap();
        drop(first);

        let unavailable = EvidenceJournalManager::open_existing(
            &journal,
            options(2, limits(4, 4)),
            &new_signer,
            None,
            verifier(),
        );
        assert!(matches!(
            unavailable,
            Err(JournalManagerError::TailSignerUnavailable)
        ));
        assert!(
            !journal
                .join(segment_file_name(NonZeroU64::new(2).unwrap()))
                .exists()
        );

        let (second, report) = EvidenceJournalManager::open_existing(
            &journal,
            options(2, limits(4, 4)),
            &new_signer,
            Some(&old_signer),
            verifier(),
        )
        .unwrap();
        assert!(report.closed_active_tail);
        assert_eq!(second.active_sequence().map(NonZeroU64::get), Some(2));
    }

    #[test]
    fn interrupted_unpublished_successor_is_discarded_during_recovery() {
        let directory = TestDirectory::new();
        let journal = directory.journal();
        let (first, _) = open(&journal, 1, limits(4, 4)).unwrap();
        drop(first);
        let final_name = segment_file_name(NonZeroU64::new(2).unwrap());
        let pending = journal.join(format!("{PENDING_CREATION_PREFIX}{final_name}"));
        fs::write(&pending, b"partial header").unwrap();

        let (manager, report) = open(&journal, 2, limits(4, 4)).unwrap();

        assert!(report.discarded_pending_creation);
        assert!(!pending.exists());
        assert_eq!(manager.active_sequence().map(NonZeroU64::get), Some(2));
    }

    fn identity(
        sequence: u64,
        previous: [u8; 32],
        boot: u8,
        signer: &SigningKey,
    ) -> SegmentIdentity {
        SegmentIdentity {
            gate_id: gate(),
            gate_boot_id: GateBootId::new([boot; 16]),
            segment_sequence: NonZeroU64::new(sequence).unwrap(),
            previous_completed_digest: previous,
            created_mono_ns: u64::from(boot),
            signer_kid: kid(),
            signer_public_key: signer.verifying_key().to_bytes(),
        }
    }
}
