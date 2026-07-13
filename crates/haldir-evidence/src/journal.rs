//! Bounded, signed evidence-segment files with strict crash-tail recovery.
//!
//! This module implements the local segment format required by the P1 journal
//! design. Each append is framed and CRC32C protected, segment constructors
//! enforce previous-content-digest continuity, completed segments are Ed25519
//! signed, and recovery truncates only an
//! insufficient final frame/footer tail. A complete frame with a bad checksum,
//! a malformed header, or a completed footer with a bad digest/signature fails
//! closed.
//!
//! The implementation supplies a Unix process-crash primitive. It does not by
//! itself prove power-loss durability, collector delivery, external availability,
//! or Gate crash semantics; Gate selection and child-process fault injection are
//! separate integration gates. It assumes one exclusive writer and a trusted
//! local parent directory; path-based safe standard-library APIs cannot close
//! ancestor-directory replacement races.

use core::num::NonZeroU64;
use haldir_contracts::ids::{GateBootId, GateId, KeyId};
use haldir_crypto::{SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

#[cfg(all(test, unix))]
use std::cell::Cell;
#[cfg(unix)]
use std::fs::{self, File, OpenOptions};
#[cfg(unix)]
use std::io::{ErrorKind, Read, Write};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
#[cfg(unix)]
use std::path::Path;

const SEGMENT_MAGIC: &[u8; 8] = b"HLDRJNL1";
const RECORD_MAGIC: &[u8; 4] = b"EVR1";
const FOOTER_MAGIC: &[u8; 8] = b"HLDRFTR1";
const FORMAT_VERSION: u16 = 1;
const RECORD_PREFIX_LEN: usize = 10;
const RECORD_SUFFIX_LEN: usize = 4;
const FOOTER_LEN: usize = 8 + 2 + 8 + 32 + 32 + 64 + 4;
const RECORD_FIXED_PREFIX: &[u8; 6] = b"EVR1\0\x01";
const FOOTER_FIXED_PREFIX: &[u8; 10] = b"HLDRFTR1\0\x01";
const RECORD_CHAIN_DOMAIN: &[u8] = b"haldir.evidence.record-chain.v1\0";
const SEGMENT_DIGEST_DOMAIN: &[u8] = b"haldir.evidence.segment-digest.v1\0";
const FOOTER_SIGNATURE_DOMAIN: &[u8] = b"haldir.evidence.segment-footer-signature.v1\0";
pub(crate) const PENDING_CREATION_PREFIX: &str = ".haldir-evidence.pending-";

#[cfg(all(test, unix))]
std::thread_local! {
    static CREATE_PUBLICATION_COMMIT_AMBIGUOUS: Cell<bool> = const { Cell::new(false) };
}

#[cfg(all(test, unix))]
pub(crate) fn inject_create_publication_commit_ambiguous_once() {
    CREATE_PUBLICATION_COMMIT_AMBIGUOUS.with(|fault| fault.set(true));
}

#[cfg(all(test, unix))]
fn take_create_publication_commit_ambiguous() -> bool {
    CREATE_PUBLICATION_COMMIT_AMBIGUOUS.with(|fault| fault.replace(false))
}

/// Evidence-journal format, bound, integrity, or storage failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum JournalError {
    /// The journal file is absent.
    Missing,
    /// Creation was requested for an existing path.
    AlreadyExists,
    /// The selected filesystem implementation is unavailable.
    Unsupported,
    /// A filesystem operation failed.
    Storage,
    /// Configured or encoded sizes exceed a declared bound.
    Bounds,
    /// One record can never fit the configured record-size bound.
    RecordTooLarge,
    /// The record-size bound permits it, but no empty segment can fit it.
    RecordCannotFitSegment,
    /// The current segment must be footer-completed before this record can fit.
    RotationRequired,
    /// Genesis or next-segment sequence/previous-digest continuity was invalid.
    ChainMismatch,
    /// The supplied signing/verifying key did not match the bound signer identity.
    SignerMismatch,
    /// A write was issued but its durable completion is unknown; recover before retry.
    CommitAmbiguous,
    /// The segment header is malformed or has a bad checksum.
    CorruptHeader,
    /// A complete record is malformed or has a bad checksum.
    CorruptRecord,
    /// A completed footer is malformed, inconsistent, or has a bad checksum.
    CorruptFooter,
    /// The recovered segment identity differs from the expected identity.
    IdentityMismatch,
    /// The completed segment signature did not verify.
    SignatureInvalid,
    /// A previous append failed; recovery is required before another mutation.
    Poisoned,
}

/// Hard limits for one evidence segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JournalBounds {
    max_segment_bytes: usize,
    max_records: u64,
    max_record_bytes: usize,
}

impl JournalBounds {
    /// Construct nonzero bounds with enough space for a header and footer.
    ///
    /// # Errors
    /// Returns [`JournalError::Bounds`] for an unusable configuration.
    pub fn new(
        max_segment_bytes: usize,
        max_records: u64,
        max_record_bytes: usize,
    ) -> Result<Self, JournalError> {
        if max_segment_bytes == 0 || max_records == 0 || max_record_bytes == 0 {
            return Err(JournalError::Bounds);
        }
        Ok(Self {
            max_segment_bytes,
            max_records,
            max_record_bytes,
        })
    }

    /// Maximum complete segment size.
    #[must_use]
    pub const fn max_segment_bytes(self) -> usize {
        self.max_segment_bytes
    }
}

/// Identity and chain binding stored in a segment header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SegmentIdentity {
    /// Gate that authored the segment.
    pub gate_id: GateId,
    /// Gate process incarnation that opened the segment.
    pub gate_boot_id: GateBootId,
    /// Strictly positive sequence within this journal chain.
    pub segment_sequence: NonZeroU64,
    /// Digest of the previous completed segment, or zero for the first segment.
    pub previous_completed_digest: [u8; 32],
    /// Local monotonic creation time recorded as evidence.
    pub created_mono_ns: u64,
    /// Gate application signing key identifier used for the footer.
    pub signer_kid: KeyId,
    /// Trusted Gate application public key expected to sign the footer.
    pub signer_public_key: [u8; 32],
}

/// Recovery result for an open (not footer-completed) segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenRecoveryStatus {
    /// The file ended exactly after the last complete record.
    Clean,
    /// An insufficient final frame/footer tail was removed.
    TruncatedTail {
        /// Number of bytes removed from the incomplete tail.
        removed_bytes: u64,
    },
}

/// Verified metadata for a completed signed segment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompletedSegment {
    /// Header identity.
    identity: SegmentIdentity,
    /// Number of complete records.
    record_count: u64,
    /// Digest of the final record-chain link, or zero for an empty segment.
    final_record_digest: [u8; 32],
    /// Digest used to chain the next segment.
    segment_digest: [u8; 32],
    /// Complete on-disk length including footer.
    segment_bytes: u64,
    /// Complete opaque record bytes. Canonical/signature validation is the
    /// producer/consumer's responsibility.
    records: Vec<Vec<u8>>,
}

impl CompletedSegment {
    /// Authenticated segment header identity.
    #[must_use]
    pub const fn identity(&self) -> &SegmentIdentity {
        &self.identity
    }

    /// Number of complete records.
    #[must_use]
    pub const fn record_count(&self) -> u64 {
        self.record_count
    }

    /// Final record-chain digest.
    #[must_use]
    pub const fn final_record_digest(&self) -> [u8; 32] {
        self.final_record_digest
    }

    /// Signed segment-content digest used by a successor header.
    #[must_use]
    pub const fn segment_digest(&self) -> [u8; 32] {
        self.segment_digest
    }

    /// Complete on-disk byte length.
    #[must_use]
    pub const fn segment_bytes(&self) -> u64 {
        self.segment_bytes
    }

    /// Complete opaque record bytes in append order.
    #[must_use]
    pub fn records(&self) -> &[Vec<u8>] {
        &self.records
    }

    /// Move recovered opaque record bytes to a higher-level recovery snapshot.
    ///
    /// Segment identity, counts, and signed digests remain available for journal
    /// chaining; the directory manager does not need to retain a second copy.
    pub(crate) fn take_records(&mut self) -> Vec<Vec<u8>> {
        core::mem::take(&mut self.records)
    }
}

/// Result of recovering a segment path.
pub enum RecoveredEvidenceSegment {
    /// An open segment that may continue accepting records.
    Active {
        /// Recovered append handle.
        segment: ActiveEvidenceSegment,
        /// Whether an incomplete tail was truncated.
        status: OpenRecoveryStatus,
    },
    /// A footer-completed, digest-checked, signature-verified segment.
    Completed(CompletedSegment),
}

/// Append handle for one bounded evidence segment.
pub struct ActiveEvidenceSegment {
    path: PathBuf,
    identity: SegmentIdentity,
    bounds: JournalBounds,
    #[cfg(unix)]
    file: File,
    content_hasher: Sha256,
    record_count: u64,
    final_record_digest: [u8; 32],
    records: Vec<Vec<u8>>,
    segment_bytes: usize,
    poisoned: bool,
}

struct RecoveredContent<'a> {
    bytes: &'a [u8],
    record_count: u64,
    final_record_digest: [u8; 32],
    records: Vec<Vec<u8>>,
}

impl ActiveEvidenceSegment {
    /// Minimum complete on-disk size for a segment with this identity.
    ///
    /// This is useful to reserve footer capacity before a directory manager
    /// creates the segment.
    pub(crate) fn minimum_complete_bytes(
        identity: &SegmentIdentity,
    ) -> Result<usize, JournalError> {
        encode_header(identity)?
            .len()
            .checked_add(FOOTER_LEN)
            .ok_or(JournalError::Bounds)
    }

    /// Encoded on-disk size of one record frame.
    pub(crate) fn framed_record_bytes(record_len: usize) -> Result<usize, JournalError> {
        RECORD_PREFIX_LEN
            .checked_add(record_len)
            .and_then(|size| size.checked_add(RECORD_SUFFIX_LEN))
            .ok_or(JournalError::Bounds)
    }

    /// Encoded signed-footer size.
    pub(crate) const fn footer_bytes() -> usize {
        FOOTER_LEN
    }

    /// Classify an append without issuing I/O and return its encoded frame size.
    pub(crate) fn preflight_append(&self, record_len: usize) -> Result<usize, JournalError> {
        if self.poisoned {
            return Err(JournalError::Poisoned);
        }
        if record_len > self.bounds.max_record_bytes {
            return Err(JournalError::RecordTooLarge);
        }
        let _ = u32::try_from(record_len).map_err(|_| JournalError::RecordTooLarge)?;
        let frame_len = Self::framed_record_bytes(record_len)?;
        let fresh_segment_bytes = encode_header(&self.identity)?
            .len()
            .checked_add(frame_len)
            .and_then(|bytes| bytes.checked_add(FOOTER_LEN))
            .ok_or(JournalError::Bounds)?;
        if fresh_segment_bytes > self.bounds.max_segment_bytes {
            return Err(JournalError::RecordCannotFitSegment);
        }
        if self.record_count >= self.bounds.max_records
            || self
                .segment_bytes
                .checked_add(frame_len)
                .and_then(|bytes| bytes.checked_add(FOOTER_LEN))
                .is_none_or(|complete| complete > self.bounds.max_segment_bytes)
        {
            return Err(JournalError::RotationRequired);
        }
        Ok(frame_len)
    }

    /// Create a new segment, write its checksummed header, and sync the file and
    /// containing directory before returning.
    ///
    /// # Errors
    /// Returns on an existing path, unusable bounds/identity, unsupported
    /// platform, or storage failure. [`JournalError::CommitAmbiguous`] means the
    /// final path may have been published; recover the directory before making
    /// another creation attempt.
    pub fn create_new(
        path: impl Into<PathBuf>,
        identity: SegmentIdentity,
        bounds: JournalBounds,
    ) -> Result<Self, JournalError> {
        if identity.segment_sequence.get() != 1 || identity.previous_completed_digest != [0; 32] {
            return Err(JournalError::ChainMismatch);
        }
        Self::create_validated(path.into(), identity, bounds)
    }

    /// Create the checked successor to `previous` at a new path.
    ///
    /// The Gate identity must remain stable, the sequence must be exactly one
    /// greater, and the previous-digest field must equal the verified prior
    /// segment-content digest. Gate boot and signing key rotation remain explicit
    /// in the supplied identity.
    ///
    /// # Errors
    /// Returns [`JournalError::ChainMismatch`] for a fork, gap, rewind, or Gate
    /// substitution, plus the errors documented by [`Self::create_new`].
    pub fn create_next(
        path: impl Into<PathBuf>,
        identity: SegmentIdentity,
        bounds: JournalBounds,
        previous: &CompletedSegment,
    ) -> Result<Self, JournalError> {
        let expected_sequence = previous
            .identity
            .segment_sequence
            .get()
            .checked_add(1)
            .ok_or(JournalError::ChainMismatch)?;
        if identity.gate_id != previous.identity.gate_id
            || identity.segment_sequence.get() != expected_sequence
            || identity.previous_completed_digest != previous.segment_digest
        {
            return Err(JournalError::ChainMismatch);
        }
        Self::create_validated(path.into(), identity, bounds)
    }

    fn create_validated(
        path: PathBuf,
        identity: SegmentIdentity,
        bounds: JournalBounds,
    ) -> Result<Self, JournalError> {
        let header = encode_header(&identity)?;
        if header
            .len()
            .checked_add(FOOTER_LEN)
            .is_none_or(|minimum| minimum > bounds.max_segment_bytes)
        {
            return Err(JournalError::Bounds);
        }

        #[cfg(unix)]
        {
            let parent = checked_parent(&path)?;
            let pending_path = pending_creation_path(&path)?;
            let mut file = match OpenOptions::new()
                .read(true)
                .append(true)
                .create_new(true)
                .mode(0o600)
                .open(&pending_path)
            {
                Ok(file) => file,
                Err(error) if error.kind() == ErrorKind::AlreadyExists => {
                    return Err(JournalError::AlreadyExists);
                }
                Err(_) => return Err(JournalError::Storage),
            };
            if file.write_all(&header).is_err() || file.sync_all().is_err() {
                remove_unpublished(&pending_path, &parent)?;
                return Err(JournalError::Storage);
            }
            if let Err(error) = fs::hard_link(&pending_path, &path) {
                remove_unpublished(&pending_path, &parent)?;
                return Err(if error.kind() == ErrorKind::AlreadyExists {
                    JournalError::AlreadyExists
                } else {
                    JournalError::Storage
                });
            }
            #[cfg(test)]
            if take_create_publication_commit_ambiguous() {
                return Err(JournalError::CommitAmbiguous);
            }
            if parent.sync_all().is_err() {
                return Err(JournalError::CommitAmbiguous);
            }
            if fs::remove_file(&pending_path).is_err() || parent.sync_all().is_err() {
                return Err(JournalError::CommitAmbiguous);
            }
            Ok(Self::from_parts(
                path,
                identity,
                bounds,
                file,
                RecoveredContent {
                    bytes: &header,
                    record_count: 0,
                    final_record_digest: [0; 32],
                    records: Vec::new(),
                },
            ))
        }
        #[cfg(not(unix))]
        {
            let _ = (path, identity, bounds, header);
            Err(JournalError::Unsupported)
        }
    }

    #[cfg(unix)]
    fn from_parts(
        path: PathBuf,
        identity: SegmentIdentity,
        bounds: JournalBounds,
        file: File,
        recovered: RecoveredContent<'_>,
    ) -> Self {
        let mut content_hasher = Sha256::new();
        content_hasher.update(SEGMENT_DIGEST_DOMAIN);
        content_hasher.update(recovered.bytes);
        Self {
            path,
            identity,
            bounds,
            file,
            content_hasher,
            record_count: recovered.record_count,
            final_record_digest: recovered.final_record_digest,
            records: recovered.records,
            segment_bytes: recovered.bytes.len(),
            poisoned: false,
        }
    }

    /// Read and checksum-validate the persisted header identity under the
    /// segment-size bound. This is a discovery step, not authentication: callers
    /// must resolve `signer_kid` to the expected Gate role/subject/public key and
    /// validate journal-chain policy before calling [`Self::recover`].
    ///
    /// # Errors
    /// Returns on missing/unsupported storage, an oversized file, or a malformed
    /// header.
    pub fn inspect_identity(
        path: impl Into<PathBuf>,
        bounds: JournalBounds,
    ) -> Result<SegmentIdentity, JournalError> {
        let path = path.into();
        #[cfg(unix)]
        {
            let mut file = checked_open_existing(&path, bounds.max_segment_bytes, false)?;
            let mut bytes = Vec::new();
            (&mut file)
                .take(
                    u64::try_from(bounds.max_segment_bytes)
                        .unwrap_or(u64::MAX)
                        .saturating_add(1),
                )
                .read_to_end(&mut bytes)
                .map_err(|_| JournalError::Storage)?;
            if bytes.len() > bounds.max_segment_bytes {
                return Err(JournalError::Bounds);
            }
            decode_header(&bytes).map(|(identity, _)| identity)
        }
        #[cfg(not(unix))]
        {
            let _ = (path, bounds);
            Err(JournalError::Unsupported)
        }
    }

    /// Recover an existing segment. Only an insufficient final record/footer
    /// tail may be truncated; every complete integrity failure is rejected.
    /// Completed segments are returned only after footer signature verification.
    /// The caller must resolve the inspected signer KID through its trust store;
    /// this method additionally requires that key's bytes to match the header.
    ///
    /// # Errors
    /// Returns on missing/unsupported storage, identity mismatch, a complete
    /// corrupt frame/footer, bad signature, or any declared bound violation.
    pub fn recover(
        path: impl Into<PathBuf>,
        expected: &SegmentIdentity,
        bounds: JournalBounds,
        verifying_key: &VerifyingKey,
    ) -> Result<RecoveredEvidenceSegment, JournalError> {
        let path = path.into();
        #[cfg(unix)]
        {
            let mut file = checked_open_existing(&path, bounds.max_segment_bytes, true)?;
            let mut bytes = Vec::new();
            (&mut file)
                .take(
                    u64::try_from(bounds.max_segment_bytes)
                        .unwrap_or(u64::MAX)
                        .saturating_add(1),
                )
                .read_to_end(&mut bytes)
                .map_err(|_| JournalError::Storage)?;
            if bytes.len() > bounds.max_segment_bytes {
                return Err(JournalError::Bounds);
            }
            let (identity, header_len) = decode_header(&bytes)?;
            if &identity != expected {
                return Err(JournalError::IdentityMismatch);
            }
            if verifying_key.to_bytes() != identity.signer_public_key {
                return Err(JournalError::SignerMismatch);
            }
            if header_len
                .checked_add(FOOTER_LEN)
                .is_none_or(|minimum| minimum > bounds.max_segment_bytes)
            {
                return Err(JournalError::Bounds);
            }

            let ScanResult {
                content_end,
                record_count,
                final_record_digest,
                records,
                terminal,
            } = scan_content(&bytes, header_len, bounds)?;
            match terminal {
                ScanTerminal::Completed(footer) => {
                    verify_footer(
                        &bytes,
                        content_end,
                        record_count,
                        &final_record_digest,
                        &footer,
                        verifying_key,
                    )?;
                    Ok(RecoveredEvidenceSegment::Completed(CompletedSegment {
                        identity,
                        record_count,
                        final_record_digest,
                        segment_digest: footer.segment_digest,
                        segment_bytes: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
                        records,
                    }))
                }
                ScanTerminal::Open { tail_start } => {
                    let removed = bytes.len().saturating_sub(tail_start);
                    if removed > 0 {
                        file.set_len(u64::try_from(tail_start).map_err(|_| JournalError::Bounds)?)
                            .map_err(|_| JournalError::Storage)?;
                        file.sync_all().map_err(|_| JournalError::Storage)?;
                    }
                    let content = bytes.get(..tail_start).ok_or(JournalError::CorruptRecord)?;
                    let segment = Self::from_parts(
                        path,
                        identity,
                        bounds,
                        file,
                        RecoveredContent {
                            bytes: content,
                            record_count,
                            final_record_digest,
                            records,
                        },
                    );
                    let status = if removed == 0 {
                        OpenRecoveryStatus::Clean
                    } else {
                        OpenRecoveryStatus::TruncatedTail {
                            removed_bytes: u64::try_from(removed).unwrap_or(u64::MAX),
                        }
                    };
                    Ok(RecoveredEvidenceSegment::Active { segment, status })
                }
            }
        }
        #[cfg(not(unix))]
        {
            let _ = (path, expected, bounds, verifying_key);
            Err(JournalError::Unsupported)
        }
    }

    /// Append and `sync_data` one already signed/canonical evidence envelope.
    /// The journal treats bytes as opaque; semantic envelope validation belongs
    /// to the producer before this call.
    ///
    /// # Errors
    /// Returns [`JournalError::RecordTooLarge`] or
    /// [`JournalError::RecordCannotFitSegment`] for a permanently invalid record,
    /// and [`JournalError::RotationRequired`] only when rotation can make room.
    /// [`JournalError::CommitAmbiguous`] poisons this handle and requires recovery
    /// before the caller decides whether a retry is a duplicate.
    pub fn append(&mut self, record: &[u8]) -> Result<(), JournalError> {
        let frame_len = self.preflight_append(record.len())?;
        let frame = encode_record(record)?;
        debug_assert_eq!(frame.len(), frame_len);

        #[cfg(unix)]
        {
            self.poisoned = true;
            self.file
                .write_all(&frame)
                .map_err(|_| JournalError::CommitAmbiguous)?;
            self.file
                .sync_data()
                .map_err(|_| JournalError::CommitAmbiguous)?;
            self.content_hasher.update(&frame);
            self.final_record_digest = record_link(&self.final_record_digest, record);
            self.records.push(record.to_vec());
            self.record_count = self
                .record_count
                .checked_add(1)
                .ok_or(JournalError::Bounds)?;
            self.segment_bytes = self
                .segment_bytes
                .checked_add(frame.len())
                .ok_or(JournalError::Bounds)?;
            self.poisoned = false;
            Ok(())
        }
        #[cfg(not(unix))]
        {
            let _ = frame;
            Err(JournalError::Unsupported)
        }
    }

    /// Footer-complete and `sync_all` this segment. The signature covers the
    /// complete header/record digest plus footer count/chain metadata.
    ///
    /// # Errors
    /// Returns on a signer mismatch, poisoned handle, bound exhaustion,
    /// unsupported platform, or storage failure. `CommitAmbiguous` means the
    /// consumed path must be recovered before any new segment is created.
    pub fn close(
        mut self,
        signer_kid: &KeyId,
        signer: &SigningKey,
    ) -> Result<CompletedSegment, JournalError> {
        if self.poisoned {
            return Err(JournalError::Poisoned);
        }
        if signer_kid != &self.identity.signer_kid
            || signer.verifying_key().to_bytes() != self.identity.signer_public_key
        {
            return Err(JournalError::SignerMismatch);
        }
        let segment_digest = finish_segment_digest(
            &self.content_hasher,
            self.record_count,
            &self.final_record_digest,
        );
        let footer = encode_footer(
            self.record_count,
            self.final_record_digest,
            segment_digest,
            signer,
        );
        if self
            .segment_bytes
            .checked_add(footer.len())
            .is_none_or(|complete| complete > self.bounds.max_segment_bytes)
        {
            return Err(JournalError::Bounds);
        }

        #[cfg(unix)]
        {
            self.poisoned = true;
            self.file
                .write_all(&footer)
                .map_err(|_| JournalError::CommitAmbiguous)?;
            self.file
                .sync_all()
                .map_err(|_| JournalError::CommitAmbiguous)?;
            let segment_bytes = self
                .segment_bytes
                .checked_add(footer.len())
                .ok_or(JournalError::Bounds)?;
            Ok(CompletedSegment {
                identity: self.identity,
                record_count: self.record_count,
                final_record_digest: self.final_record_digest,
                segment_digest,
                segment_bytes: u64::try_from(segment_bytes).unwrap_or(u64::MAX),
                records: self.records,
            })
        }
        #[cfg(not(unix))]
        {
            let _ = (footer, signer);
            Err(JournalError::Unsupported)
        }
    }

    /// Segment path.
    #[must_use]
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    /// Header identity bound to this active segment.
    #[must_use]
    pub const fn identity(&self) -> &SegmentIdentity {
        &self.identity
    }

    /// Current on-disk bytes, excluding the reserved footer.
    #[must_use]
    pub const fn segment_bytes(&self) -> usize {
        self.segment_bytes
    }

    /// Number of durably appended complete records.
    #[must_use]
    pub const fn record_count(&self) -> u64 {
        self.record_count
    }

    /// Complete records currently retained by this bounded segment.
    #[must_use]
    pub fn records(&self) -> &[Vec<u8>] {
        &self.records
    }

    /// Move recovered record bytes into a higher-level bounded snapshot before
    /// footer completion. Cryptographic chain/count state is retained.
    pub(crate) fn take_records(&mut self) -> Vec<Vec<u8>> {
        core::mem::take(&mut self.records)
    }
}

fn encode_header(identity: &SegmentIdentity) -> Result<Vec<u8>, JournalError> {
    let gate = identity.gate_id.as_str().as_bytes();
    let kid = identity.signer_kid.as_bytes();
    let header_len = 8usize
        .checked_add(2)
        .and_then(|n| n.checked_add(2))
        .and_then(|n| n.checked_add(2 + gate.len()))
        .and_then(|n| n.checked_add(16 + 8 + 32 + 8))
        .and_then(|n| n.checked_add(2 + kid.len()))
        .and_then(|n| n.checked_add(32))
        .and_then(|n| n.checked_add(4))
        .ok_or(JournalError::Bounds)?;
    let header_len_u16 = u16::try_from(header_len).map_err(|_| JournalError::Bounds)?;
    let gate_len = u16::try_from(gate.len()).map_err(|_| JournalError::Bounds)?;
    let kid_len = u16::try_from(kid.len()).map_err(|_| JournalError::Bounds)?;
    let mut out = Vec::with_capacity(header_len);
    out.extend_from_slice(SEGMENT_MAGIC);
    out.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
    out.extend_from_slice(&header_len_u16.to_be_bytes());
    out.extend_from_slice(&gate_len.to_be_bytes());
    out.extend_from_slice(gate);
    out.extend_from_slice(identity.gate_boot_id.as_bytes());
    out.extend_from_slice(&identity.segment_sequence.get().to_be_bytes());
    out.extend_from_slice(&identity.previous_completed_digest);
    out.extend_from_slice(&identity.created_mono_ns.to_be_bytes());
    out.extend_from_slice(&kid_len.to_be_bytes());
    out.extend_from_slice(kid);
    out.extend_from_slice(&identity.signer_public_key);
    let crc = crc32c(&out);
    out.extend_from_slice(&crc.to_be_bytes());
    Ok(out)
}

fn decode_header(bytes: &[u8]) -> Result<(SegmentIdentity, usize), JournalError> {
    let mut cursor = ByteCursor::new(bytes);
    if cursor.take(8)? != SEGMENT_MAGIC || cursor.u16()? != FORMAT_VERSION {
        return Err(JournalError::CorruptHeader);
    }
    let header_len = usize::from(cursor.u16()?);
    if header_len > bytes.len() || header_len < 86 {
        return Err(JournalError::CorruptHeader);
    }
    let gate_len = usize::from(cursor.u16()?);
    let gate_bytes = cursor.take(gate_len)?;
    let gate_text = core::str::from_utf8(gate_bytes).map_err(|_| JournalError::CorruptHeader)?;
    let gate_id = GateId::new(gate_text).map_err(|_| JournalError::CorruptHeader)?;
    let gate_boot_id = GateBootId::new(cursor.array()?);
    let segment_sequence = NonZeroU64::new(cursor.u64()?).ok_or(JournalError::CorruptHeader)?;
    let previous_completed_digest = cursor.array()?;
    let created_mono_ns = cursor.u64()?;
    let kid_len = usize::from(cursor.u16()?);
    let signer_kid =
        KeyId::new(cursor.take(kid_len)?.to_vec()).map_err(|_| JournalError::CorruptHeader)?;
    let signer_public_key = cursor.array()?;
    let crc_offset = header_len
        .checked_sub(4)
        .ok_or(JournalError::CorruptHeader)?;
    if cursor.position() != crc_offset {
        return Err(JournalError::CorruptHeader);
    }
    let stored_crc = cursor.u32()?;
    if cursor.position() != header_len
        || crc32c(bytes.get(..crc_offset).ok_or(JournalError::CorruptHeader)?) != stored_crc
    {
        return Err(JournalError::CorruptHeader);
    }
    Ok((
        SegmentIdentity {
            gate_id,
            gate_boot_id,
            segment_sequence,
            previous_completed_digest,
            created_mono_ns,
            signer_kid,
            signer_public_key,
        },
        header_len,
    ))
}

fn encode_record(record: &[u8]) -> Result<Vec<u8>, JournalError> {
    let len = u32::try_from(record.len()).map_err(|_| JournalError::Bounds)?;
    let capacity = RECORD_PREFIX_LEN
        .checked_add(record.len())
        .and_then(|n| n.checked_add(RECORD_SUFFIX_LEN))
        .ok_or(JournalError::Bounds)?;
    let mut frame = Vec::with_capacity(capacity);
    frame.extend_from_slice(RECORD_MAGIC);
    frame.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(record);
    let crc = crc32c(&frame);
    frame.extend_from_slice(&crc.to_be_bytes());
    Ok(frame)
}

fn record_link(previous: &[u8; 32], record: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(RECORD_CHAIN_DOMAIN);
    hasher.update(previous);
    hasher.update(
        u64::try_from(record.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    hasher.update(record);
    hasher.finalize().into()
}

fn finish_segment_digest(
    content_hasher: &Sha256,
    record_count: u64,
    final_record_digest: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = content_hasher.clone();
    hasher.update(record_count.to_be_bytes());
    hasher.update(final_record_digest);
    hasher.finalize().into()
}

fn signature_input(segment_digest: &[u8; 32]) -> Vec<u8> {
    let mut input = Vec::with_capacity(FOOTER_SIGNATURE_DOMAIN.len() + 32);
    input.extend_from_slice(FOOTER_SIGNATURE_DOMAIN);
    input.extend_from_slice(segment_digest);
    input
}

fn encode_footer(
    record_count: u64,
    final_record_digest: [u8; 32],
    segment_digest: [u8; 32],
    signer: &SigningKey,
) -> Vec<u8> {
    let signature = signer.sign(&signature_input(&segment_digest));
    let mut footer = Vec::with_capacity(FOOTER_LEN);
    footer.extend_from_slice(FOOTER_MAGIC);
    footer.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
    footer.extend_from_slice(&record_count.to_be_bytes());
    footer.extend_from_slice(&final_record_digest);
    footer.extend_from_slice(&segment_digest);
    footer.extend_from_slice(&signature.to_bytes());
    let crc = crc32c(&footer);
    footer.extend_from_slice(&crc.to_be_bytes());
    footer
}

struct ScanResult {
    content_end: usize,
    record_count: u64,
    final_record_digest: [u8; 32],
    records: Vec<Vec<u8>>,
    terminal: ScanTerminal,
}

enum ScanTerminal {
    Open { tail_start: usize },
    Completed(DecodedFooter),
}

struct DecodedFooter {
    record_count: u64,
    final_record_digest: [u8; 32],
    segment_digest: [u8; 32],
    signature: haldir_crypto::Signature,
}

fn scan_content(
    bytes: &[u8],
    header_len: usize,
    bounds: JournalBounds,
) -> Result<ScanResult, JournalError> {
    let mut position = header_len;
    let mut record_count = 0u64;
    let mut final_record_digest = [0; 32];
    let mut records = Vec::new();
    loop {
        let remaining = bytes.get(position..).ok_or(JournalError::CorruptRecord)?;
        if remaining.is_empty() {
            return Ok(ScanResult {
                content_end: position,
                record_count,
                final_record_digest,
                records,
                terminal: ScanTerminal::Open {
                    tail_start: position,
                },
            });
        }
        let footer_candidate = remaining.starts_with(FOOTER_MAGIC)
            || (remaining.len() < FOOTER_MAGIC.len() && FOOTER_FIXED_PREFIX.starts_with(remaining));
        if footer_candidate {
            if !matches_partial_frame(remaining, FOOTER_FIXED_PREFIX) {
                return Err(JournalError::CorruptFooter);
            }
            if remaining.len() < FOOTER_LEN {
                return Ok(ScanResult {
                    content_end: position,
                    record_count,
                    final_record_digest,
                    records,
                    terminal: ScanTerminal::Open {
                        tail_start: position,
                    },
                });
            }
            if remaining.len() != FOOTER_LEN {
                return Err(JournalError::CorruptFooter);
            }
            let footer = decode_footer(remaining)?;
            return Ok(ScanResult {
                content_end: position,
                record_count,
                final_record_digest,
                records,
                terminal: ScanTerminal::Completed(footer),
            });
        }
        if remaining.len() < RECORD_PREFIX_LEN {
            if !matches_partial_frame(remaining, RECORD_FIXED_PREFIX) {
                return Err(JournalError::CorruptRecord);
            }
            return Ok(ScanResult {
                content_end: position,
                record_count,
                final_record_digest,
                records,
                terminal: ScanTerminal::Open {
                    tail_start: position,
                },
            });
        }
        let mut cursor = ByteCursor::new(remaining);
        if cursor.take(4)? != RECORD_MAGIC || cursor.u16()? != FORMAT_VERSION {
            return Err(JournalError::CorruptRecord);
        }
        let record_len = usize::try_from(cursor.u32()?).map_err(|_| JournalError::Bounds)?;
        if record_len > bounds.max_record_bytes || record_count >= bounds.max_records {
            return Err(JournalError::Bounds);
        }
        let frame_len = RECORD_PREFIX_LEN
            .checked_add(record_len)
            .and_then(|n| n.checked_add(RECORD_SUFFIX_LEN))
            .ok_or(JournalError::Bounds)?;
        if remaining.len() < frame_len {
            return Ok(ScanResult {
                content_end: position,
                record_count,
                final_record_digest,
                records,
                terminal: ScanTerminal::Open {
                    tail_start: position,
                },
            });
        }
        let record = cursor.take(record_len)?;
        let stored_crc = cursor.u32()?;
        let crc_end = frame_len
            .checked_sub(RECORD_SUFFIX_LEN)
            .ok_or(JournalError::CorruptRecord)?;
        if crc32c(
            remaining
                .get(..crc_end)
                .ok_or(JournalError::CorruptRecord)?,
        ) != stored_crc
        {
            return Err(JournalError::CorruptRecord);
        }
        final_record_digest = record_link(&final_record_digest, record);
        records.push(record.to_vec());
        record_count = record_count.checked_add(1).ok_or(JournalError::Bounds)?;
        position = position
            .checked_add(frame_len)
            .ok_or(JournalError::Bounds)?;
    }
}

fn decode_footer(bytes: &[u8]) -> Result<DecodedFooter, JournalError> {
    if bytes.len() != FOOTER_LEN {
        return Err(JournalError::CorruptFooter);
    }
    let mut cursor = ByteCursor::new(bytes);
    if cursor.take(8)? != FOOTER_MAGIC || cursor.u16()? != FORMAT_VERSION {
        return Err(JournalError::CorruptFooter);
    }
    let record_count = cursor.u64()?;
    let final_record_digest = cursor.array()?;
    let segment_digest = cursor.array()?;
    let signature = haldir_crypto::Signature::from_bytes(cursor.array()?);
    let stored_crc = cursor.u32()?;
    let crc_end = FOOTER_LEN
        .checked_sub(4)
        .ok_or(JournalError::CorruptFooter)?;
    if cursor.position() != FOOTER_LEN
        || crc32c(bytes.get(..crc_end).ok_or(JournalError::CorruptFooter)?) != stored_crc
    {
        return Err(JournalError::CorruptFooter);
    }
    Ok(DecodedFooter {
        record_count,
        final_record_digest,
        segment_digest,
        signature,
    })
}

fn verify_footer(
    bytes: &[u8],
    content_end: usize,
    record_count: u64,
    final_record_digest: &[u8; 32],
    footer: &DecodedFooter,
    verifying_key: &VerifyingKey,
) -> Result<(), JournalError> {
    if footer.record_count != record_count || footer.final_record_digest != *final_record_digest {
        return Err(JournalError::CorruptFooter);
    }
    let content = bytes
        .get(..content_end)
        .ok_or(JournalError::CorruptFooter)?;
    let mut hasher = Sha256::new();
    hasher.update(SEGMENT_DIGEST_DOMAIN);
    hasher.update(content);
    let expected_digest = finish_segment_digest(&hasher, record_count, final_record_digest);
    if footer.segment_digest != expected_digest {
        return Err(JournalError::CorruptFooter);
    }
    if !verifying_key.verify(&signature_input(&footer.segment_digest), &footer.signature) {
        return Err(JournalError::SignatureInvalid);
    }
    Ok(())
}

fn matches_partial_frame(candidate: &[u8], fixed_prefix: &[u8]) -> bool {
    if candidate.len() < fixed_prefix.len() {
        fixed_prefix.starts_with(candidate)
    } else {
        candidate.starts_with(fixed_prefix)
    }
}

/// CRC32C (Castagnoli), reflected polynomial `0x82f63b78`.
fn crc32c(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = 0u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0x82f6_3b78 & mask);
        }
    }
    !crc
}

struct ByteCursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> ByteCursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    const fn position(&self) -> usize {
        self.position
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], JournalError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(JournalError::Bounds)?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(JournalError::CorruptHeader)?;
        self.position = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], JournalError> {
        self.take(N)?
            .try_into()
            .map_err(|_| JournalError::CorruptHeader)
    }

    fn u16(&mut self) -> Result<u16, JournalError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, JournalError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, JournalError> {
        Ok(u64::from_be_bytes(self.array()?))
    }
}

#[cfg(unix)]
fn parent(path: &Path) -> &Path {
    path.parent()
        .filter(|candidate| !candidate.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

#[cfg(unix)]
fn checked_parent(path: &Path) -> Result<File, JournalError> {
    let parent_path = parent(path);
    let path_metadata = fs::symlink_metadata(parent_path).map_err(|_| JournalError::Storage)?;
    if !path_metadata.file_type().is_dir() {
        return Err(JournalError::Storage);
    }
    let directory = File::open(parent_path).map_err(|_| JournalError::Storage)?;
    let opened_metadata = directory.metadata().map_err(|_| JournalError::Storage)?;
    if path_metadata.dev() != opened_metadata.dev() || path_metadata.ino() != opened_metadata.ino()
    {
        return Err(JournalError::Storage);
    }
    Ok(directory)
}

#[cfg(unix)]
fn pending_creation_path(path: &Path) -> Result<PathBuf, JournalError> {
    let file_name = path.file_name().ok_or(JournalError::Storage)?;
    let mut pending_name = std::ffi::OsString::from(PENDING_CREATION_PREFIX);
    pending_name.push(file_name);
    Ok(parent(path).join(pending_name))
}

#[cfg(unix)]
fn remove_unpublished(path: &Path, parent: &File) -> Result<(), JournalError> {
    match fs::remove_file(path) {
        Ok(()) => parent.sync_all().map_err(|_| JournalError::CommitAmbiguous),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(_) => Err(JournalError::CommitAmbiguous),
    }
}

#[cfg(unix)]
fn checked_open_existing(
    path: &Path,
    max_bytes: usize,
    append: bool,
) -> Result<File, JournalError> {
    let path_metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => return Err(JournalError::Missing),
        Err(_) => return Err(JournalError::Storage),
    };
    if !path_metadata.file_type().is_file() {
        return Err(JournalError::Storage);
    }
    let file = OpenOptions::new()
        .read(true)
        .append(append)
        .open(path)
        .map_err(|_| JournalError::Storage)?;
    let opened_metadata = file.metadata().map_err(|_| JournalError::Storage)?;
    if path_metadata.dev() != opened_metadata.dev() || path_metadata.ino() != opened_metadata.ino()
    {
        return Err(JournalError::Storage);
    }
    if opened_metadata.len() > u64::try_from(max_bytes).unwrap_or(u64::MAX) {
        return Err(JournalError::Bounds);
    }
    Ok(file)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "haldir-evidence-journal-test-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn identity() -> SegmentIdentity {
        let signer = SigningKey::from_seed([3; 32]);
        SegmentIdentity {
            gate_id: GateId::new("gate-1").unwrap(),
            gate_boot_id: GateBootId::new([9; 16]),
            segment_sequence: NonZeroU64::new(1).unwrap(),
            previous_completed_digest: [0; 32],
            created_mono_ns: 123,
            signer_kid: signer_kid(),
            signer_public_key: signer.verifying_key().to_bytes(),
        }
    }

    fn signer_kid() -> KeyId {
        KeyId::new(vec![3, 0xab, 3]).unwrap()
    }

    fn bounds() -> JournalBounds {
        JournalBounds::new(16 * 1024, 16, 4096).unwrap()
    }

    #[test]
    fn crc32c_matches_the_standard_check_vector() {
        assert_eq!(crc32c(b"123456789"), 0xe306_9283);
    }

    #[test]
    fn append_close_and_verified_recovery_round_trip() {
        let directory = TestDirectory::new();
        let path = directory.0.join("segment");
        let signer = SigningKey::from_seed([3; 32]);
        let mut segment = ActiveEvidenceSegment::create_new(&path, identity(), bounds()).unwrap();
        segment.append(b"signed-one").unwrap();
        segment.append(b"signed-two").unwrap();
        let closed = segment.close(&signer_kid(), &signer).unwrap();
        assert_eq!(closed.record_count, 2);
        assert_eq!(
            closed.records.as_slice(),
            &[b"signed-one".to_vec(), b"signed-two".to_vec()]
        );

        let recovered =
            ActiveEvidenceSegment::recover(&path, &identity(), bounds(), &signer.verifying_key())
                .unwrap();
        let RecoveredEvidenceSegment::Completed(verified) = recovered else {
            panic!("completed segment must remain completed");
        };
        assert_eq!(verified, closed);
    }

    #[test]
    fn recovery_truncates_only_an_insufficient_final_record() {
        let directory = TestDirectory::new();
        let path = directory.0.join("segment");
        let signer = SigningKey::from_seed([3; 32]);
        let mut segment = ActiveEvidenceSegment::create_new(&path, identity(), bounds()).unwrap();
        segment.append(b"one").unwrap();
        drop(segment);
        let before_tail = fs::metadata(&path).unwrap().len();
        let full_frame = encode_record(b"incomplete").unwrap();
        let partial = full_frame.get(..12).unwrap();
        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(partial)
            .unwrap();

        let recovered =
            ActiveEvidenceSegment::recover(&path, &identity(), bounds(), &signer.verifying_key())
                .unwrap();
        let RecoveredEvidenceSegment::Active {
            mut segment,
            status,
        } = recovered
        else {
            panic!("incomplete segment must reopen active");
        };
        assert_eq!(
            status,
            OpenRecoveryStatus::TruncatedTail { removed_bytes: 12 }
        );
        assert_eq!(fs::metadata(&path).unwrap().len(), before_tail);
        assert_eq!(segment.records(), &[b"one".to_vec()]);
        segment.append(b"two").unwrap();
        assert_eq!(
            segment.close(&signer_kid(), &signer).unwrap().record_count,
            2
        );
    }

    #[test]
    fn complete_record_corruption_is_never_truncated_as_a_tail() {
        let directory = TestDirectory::new();
        let path = directory.0.join("segment");
        let signer = SigningKey::from_seed([3; 32]);
        let mut segment = ActiveEvidenceSegment::create_new(&path, identity(), bounds()).unwrap();
        segment.append(b"one").unwrap();
        segment.close(&signer_kid(), &signer).unwrap();
        let mut bytes = fs::read(&path).unwrap();
        let (_, header_len) = decode_header(&bytes).unwrap();
        let record_offset = header_len + RECORD_PREFIX_LEN;
        bytes[record_offset] ^= 1;
        fs::write(&path, bytes).unwrap();

        assert!(matches!(
            ActiveEvidenceSegment::recover(&path, &identity(), bounds(), &signer.verifying_key(),),
            Err(JournalError::CorruptRecord)
        ));
    }

    #[test]
    fn completed_footer_requires_the_expected_signing_key() {
        let directory = TestDirectory::new();
        let path = directory.0.join("segment");
        let signer = SigningKey::from_seed([3; 32]);
        let wrong = SigningKey::from_seed([4; 32]);
        ActiveEvidenceSegment::create_new(&path, identity(), bounds())
            .unwrap()
            .close(&signer_kid(), &signer)
            .unwrap();

        assert!(matches!(
            ActiveEvidenceSegment::recover(&path, &identity(), bounds(), &wrong.verifying_key(),),
            Err(JournalError::SignerMismatch)
        ));
    }

    #[test]
    fn incomplete_footer_is_removed_and_can_be_recreated() {
        let directory = TestDirectory::new();
        let path = directory.0.join("segment");
        let signer = SigningKey::from_seed([3; 32]);
        ActiveEvidenceSegment::create_new(&path, identity(), bounds())
            .unwrap()
            .close(&signer_kid(), &signer)
            .unwrap();
        let complete_len = fs::metadata(&path).unwrap().len();
        let truncated_len = complete_len - 10;
        OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(truncated_len)
            .unwrap();

        let recovered =
            ActiveEvidenceSegment::recover(&path, &identity(), bounds(), &signer.verifying_key())
                .unwrap();
        let RecoveredEvidenceSegment::Active { segment, status } = recovered else {
            panic!("incomplete footer must reopen active");
        };
        assert_eq!(
            status,
            OpenRecoveryStatus::TruncatedTail {
                removed_bytes: u64::try_from(FOOTER_LEN - 10).unwrap()
            }
        );
        assert_eq!(
            segment.close(&signer_kid(), &signer).unwrap().segment_bytes,
            complete_len
        );
    }

    #[test]
    fn completed_footer_digest_tampering_is_rejected_even_with_a_fresh_crc() {
        let directory = TestDirectory::new();
        let path = directory.0.join("segment");
        let signer = SigningKey::from_seed([3; 32]);
        ActiveEvidenceSegment::create_new(&path, identity(), bounds())
            .unwrap()
            .close(&signer_kid(), &signer)
            .unwrap();
        let mut bytes = fs::read(&path).unwrap();
        let footer_start = bytes.len() - FOOTER_LEN;
        let digest_offset = footer_start + 8 + 2 + 8 + 32;
        bytes[digest_offset] ^= 1;
        let crc_offset = bytes.len() - 4;
        let crc = crc32c(bytes.get(footer_start..crc_offset).unwrap());
        bytes[crc_offset..].copy_from_slice(&crc.to_be_bytes());
        fs::write(&path, bytes).unwrap();

        assert!(matches!(
            ActiveEvidenceSegment::recover(&path, &identity(), bounds(), &signer.verifying_key(),),
            Err(JournalError::CorruptFooter)
        ));
    }

    #[test]
    fn completed_footer_signature_tampering_is_rejected_with_a_fresh_crc() {
        let directory = TestDirectory::new();
        let path = directory.0.join("segment");
        let signer = SigningKey::from_seed([3; 32]);
        ActiveEvidenceSegment::create_new(&path, identity(), bounds())
            .unwrap()
            .close(&signer_kid(), &signer)
            .unwrap();
        let mut bytes = fs::read(&path).unwrap();
        let footer_start = bytes.len() - FOOTER_LEN;
        let signature_offset = footer_start + 8 + 2 + 8 + 32 + 32;
        bytes[signature_offset] ^= 1;
        let crc_offset = bytes.len() - 4;
        let crc = crc32c(bytes.get(footer_start..crc_offset).unwrap());
        bytes[crc_offset..].copy_from_slice(&crc.to_be_bytes());
        fs::write(&path, bytes).unwrap();

        assert!(matches!(
            ActiveEvidenceSegment::recover(&path, &identity(), bounds(), &signer.verifying_key(),),
            Err(JournalError::SignatureInvalid)
        ));
    }

    #[test]
    fn header_tampering_is_rejected() {
        let directory = TestDirectory::new();
        let path = directory.0.join("segment");
        let signer = SigningKey::from_seed([3; 32]);
        drop(ActiveEvidenceSegment::create_new(&path, identity(), bounds()).unwrap());
        let mut bytes = fs::read(&path).unwrap();
        bytes[20] ^= 1;
        fs::write(&path, bytes).unwrap();

        assert!(matches!(
            ActiveEvidenceSegment::recover(&path, &identity(), bounds(), &signer.verifying_key(),),
            Err(JournalError::CorruptHeader)
        ));
    }

    #[test]
    fn recovery_rejects_identity_substitution() {
        let directory = TestDirectory::new();
        let path = directory.0.join("segment");
        let signer = SigningKey::from_seed([3; 32]);
        ActiveEvidenceSegment::create_new(&path, identity(), bounds()).unwrap();
        let mut other = identity();
        other.gate_boot_id = GateBootId::new([8; 16]);

        assert!(matches!(
            ActiveEvidenceSegment::recover(&path, &other, bounds(), &signer.verifying_key(),),
            Err(JournalError::IdentityMismatch)
        ));
    }

    #[test]
    fn inspect_then_recover_supports_trust_resolution() {
        let directory = TestDirectory::new();
        let path = directory.0.join("segment");
        let signer = SigningKey::from_seed([3; 32]);
        ActiveEvidenceSegment::create_new(&path, identity(), bounds()).unwrap();

        let inspected = ActiveEvidenceSegment::inspect_identity(&path, bounds()).unwrap();

        assert_eq!(inspected, identity());
        assert_eq!(inspected.signer_kid, signer_kid());
        assert_eq!(
            inspected.signer_public_key,
            signer.verifying_key().to_bytes()
        );
    }

    #[test]
    fn genesis_and_successor_constructors_reject_forks_and_gaps() {
        let directory = TestDirectory::new();
        let first_path = directory.0.join("segment-1");
        let second_path = directory.0.join("segment-2");
        let signer = SigningKey::from_seed([3; 32]);
        let first = ActiveEvidenceSegment::create_new(&first_path, identity(), bounds())
            .unwrap()
            .close(&signer_kid(), &signer)
            .unwrap();
        let mut second_identity = identity();
        second_identity.segment_sequence = NonZeroU64::new(2).unwrap();
        second_identity.previous_completed_digest = first.segment_digest;
        let second = ActiveEvidenceSegment::create_next(
            &second_path,
            second_identity.clone(),
            bounds(),
            &first,
        )
        .unwrap();
        drop(second);

        let mut gap = second_identity;
        gap.segment_sequence = NonZeroU64::new(3).unwrap();
        assert!(matches!(
            ActiveEvidenceSegment::create_next(directory.0.join("gap"), gap, bounds(), &first,),
            Err(JournalError::ChainMismatch)
        ));
        let mut false_genesis = identity();
        false_genesis.segment_sequence = NonZeroU64::new(2).unwrap();
        assert!(matches!(
            ActiveEvidenceSegment::create_new(
                directory.0.join("false-genesis"),
                false_genesis,
                bounds(),
            ),
            Err(JournalError::ChainMismatch)
        ));
    }

    #[test]
    fn close_rejects_a_kid_or_key_outside_the_header_binding() {
        let directory = TestDirectory::new();
        let signer = SigningKey::from_seed([3; 32]);
        let wrong_signer = SigningKey::from_seed([4; 32]);
        let wrong_kid = KeyId::new(vec![4]).unwrap();

        assert!(matches!(
            ActiveEvidenceSegment::create_new(directory.0.join("wrong-kid"), identity(), bounds(),)
                .unwrap()
                .close(&wrong_kid, &signer),
            Err(JournalError::SignerMismatch)
        ));
        assert!(matches!(
            ActiveEvidenceSegment::create_new(directory.0.join("wrong-key"), identity(), bounds(),)
                .unwrap()
                .close(&signer_kid(), &wrong_signer),
            Err(JournalError::SignerMismatch)
        ));
    }

    #[test]
    fn short_garbage_and_wrong_partial_versions_are_corruption_not_crash_tails() {
        let directory = TestDirectory::new();
        let signer = SigningKey::from_seed([3; 32]);
        for (name, tail, expected_error) in [
            ("garbage", vec![0x99; 5], JournalError::CorruptRecord),
            (
                "record-version",
                [RECORD_MAGIC.as_slice(), &[0, 2]].concat(),
                JournalError::CorruptRecord,
            ),
            (
                "footer-version",
                [FOOTER_MAGIC.as_slice(), &[0, 2]].concat(),
                JournalError::CorruptFooter,
            ),
        ] {
            let path = directory.0.join(name);
            drop(ActiveEvidenceSegment::create_new(&path, identity(), bounds()).unwrap());
            OpenOptions::new()
                .append(true)
                .open(&path)
                .unwrap()
                .write_all(&tail)
                .unwrap();

            let error = match ActiveEvidenceSegment::recover(
                &path,
                &identity(),
                bounds(),
                &signer.verifying_key(),
            ) {
                Ok(_) => panic!("corrupt short tail must not recover"),
                Err(error) => error,
            };
            assert_eq!(error, expected_error);
        }
    }

    #[test]
    fn bounds_reserve_space_for_the_signed_footer() {
        let directory = TestDirectory::new();
        let path = directory.0.join("segment");
        let mut segment = ActiveEvidenceSegment::create_new(
            &path,
            identity(),
            JournalBounds::new(300, 2, 256).unwrap(),
        )
        .unwrap();

        assert_eq!(
            segment.append(&[1; 128]),
            Err(JournalError::RecordCannotFitSegment)
        );
    }

    #[test]
    fn append_distinguishes_permanent_oversize_from_rotation() {
        let directory = TestDirectory::new();
        let path = directory.0.join("segment");
        let mut segment = ActiveEvidenceSegment::create_new(
            &path,
            identity(),
            JournalBounds::new(4096, 1, 4).unwrap(),
        )
        .unwrap();

        assert_eq!(segment.append(b"12345"), Err(JournalError::RecordTooLarge));
        segment.append(b"1234").unwrap();
        assert_eq!(segment.append(b"x"), Err(JournalError::RotationRequired));
    }

    #[test]
    fn symlink_is_rejected() {
        use std::os::unix::fs::symlink;

        let directory = TestDirectory::new();
        let target = directory.0.join("target");
        let link = directory.0.join("segment");
        fs::write(&target, b"bytes").unwrap();
        symlink(target, &link).unwrap();
        let signer = SigningKey::from_seed([3; 32]);

        assert!(matches!(
            ActiveEvidenceSegment::recover(link, &identity(), bounds(), &signer.verifying_key(),),
            Err(JournalError::Storage)
        ));
    }
}
