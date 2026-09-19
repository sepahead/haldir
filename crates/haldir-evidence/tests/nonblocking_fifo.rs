//! FIFO rejection controls in a process separate from journal recovery tests.
//!
//! Subprocess fixture creation can inherit active file-lock references.
//! Keep it outside the unit-test executable that owns regular journal locks.
#![cfg(unix)]
#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use haldir_contracts::ids::{GateBootId, GateId, JournalId, KeyId};
use haldir_crypto::{SigningKey, VerifyingKey};
use haldir_evidence::journal::{
    ActiveEvidenceSegment, JournalBounds, JournalError, SegmentIdentity,
};
use haldir_evidence::manager::{
    EvidenceJournalManager, JournalLimits, JournalManagerError, JournalOpenOptions, JournalSigner,
    JournalVerificationError, JournalVerifier,
};
use std::fs;
use std::os::unix::fs::FileTypeExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "haldir-evidence-fifo-test-{}-{sequence}",
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

struct RejectRecords;

impl JournalVerifier for RejectRecords {
    fn resolve_signer(
        &self,
        _identity: &SegmentIdentity,
    ) -> Result<VerifyingKey, JournalVerificationError> {
        Err(JournalVerificationError::UnknownSigner)
    }

    fn validate_record(
        &self,
        _identity: &SegmentIdentity,
        _record: &[u8],
    ) -> Result<(), JournalVerificationError> {
        Err(JournalVerificationError::InvalidRecord)
    }
}

#[test]
fn existing_lock_rejects_a_fifo_without_waiting_for_a_writer() {
    let directory = TestDirectory::new();
    let journal = directory.0.join("journal");
    fs::create_dir(&journal).unwrap();
    let lock = journal.join(".haldir-evidence.lock");
    assert!(
        std::process::Command::new("mkfifo")
            .arg(&lock)
            .status()
            .unwrap()
            .success()
    );
    assert!(fs::symlink_metadata(&lock).unwrap().file_type().is_fifo());
    let (sender, receiver) = mpsc::channel();
    let worker = thread::spawn(move || {
        let key = SigningKey::from_seed([3; 32]).expect("nonzero test seed");
        let kid = KeyId::new(vec![3, 0xab, 3]).unwrap();
        let limits =
            JournalLimits::new(JournalBounds::new(4096, 4, 1024).unwrap(), 4, 64 * 1024).unwrap();
        let options = JournalOpenOptions::new(
            GateId::new("gate-1").unwrap(),
            JournalId::new([7; 16]).unwrap(),
            GateBootId::new([1; 16]),
            1,
            limits,
        );
        let result = EvidenceJournalManager::open_existing(
            journal,
            options,
            &JournalSigner::new(&kid, &key),
            None,
            RejectRecords,
        )
        .map(|(manager, _)| drop(manager));
        sender.send(result).unwrap();
    });

    let result = receiver
        .recv_timeout(Duration::from_secs(2))
        .expect("FIFO journal-lock open exceeded the nonblocking deadline");
    worker.join().unwrap();

    assert_eq!(result, Err(JournalManagerError::Storage));
}

#[test]
fn inspection_rejects_a_fifo_without_waiting_for_a_writer() {
    let directory = TestDirectory::new();
    let path = directory.0.join("segment");
    assert!(
        std::process::Command::new("mkfifo")
            .arg(&path)
            .status()
            .unwrap()
            .success()
    );
    assert!(fs::symlink_metadata(&path).unwrap().file_type().is_fifo());
    let (sender, receiver) = mpsc::channel();
    let worker = thread::spawn(move || {
        sender
            .send(ActiveEvidenceSegment::inspect_identity(
                path,
                JournalBounds::new(4096, 4, 1024).unwrap(),
            ))
            .unwrap();
    });

    let result = receiver
        .recv_timeout(Duration::from_secs(2))
        .expect("FIFO segment open exceeded the nonblocking deadline");
    worker.join().unwrap();

    assert_eq!(result.unwrap_err(), JournalError::Storage);
}
