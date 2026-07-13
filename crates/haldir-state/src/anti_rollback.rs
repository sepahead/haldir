//! Anti-rollback high-water store (spec §anti-rollback, B11/B12/H12).
//!
//! Holds the highest accepted terms and revocation epochs plus a monotonic boot
//! counter and the last derived Gate boot ID — never an active lease.
//! `accept_term`/`accept_revocation_epoch` reject values that rewind their stored
//! high-water. Boot candidates bind the checked next counter to a Gate ID and
//! caller-supplied entropy, and reject a derived boot-ID repeat.
//!
//! This type supplies copy-on-write semantic candidates. [`crate::durable`] owns
//! the commit-before-exposure ordering and authenticated persistence.

use haldir_contracts::cbor::{CborReader, CborWriter, Limits};
use haldir_contracts::ids::{GateBootId, GateId};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

const BOOT_ID_DOMAIN: &[u8] = b"haldir.state.gate-boot-id.v1\0";
const STORE_FORMAT_VERSION: u64 = 2;

/// An anti-rollback failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AntiRollbackError {
    /// A term/epoch/boot value did not strictly advance (a rollback attempt).
    Rollback,
    /// A checked monotonic namespace reached its terminal value.
    Exhausted,
    /// A newly derived Gate boot ID matched the previously committed boot ID.
    BootIdRepeat,
    /// The persisted store could not be parsed (corruption).
    Corrupt,
}

impl AntiRollbackError {
    /// Stable reason string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Rollback => "ANTI_ROLLBACK_REWIND",
            Self::Exhausted => "ANTI_ROLLBACK_EXHAUSTED",
            Self::BootIdRepeat => "ANTI_ROLLBACK_BOOT_ID_REPEAT",
            Self::Corrupt => "ANTI_ROLLBACK_CORRUPT",
        }
    }
}

/// A Gate process incarnation that is safe to expose after durable commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootContext {
    /// The derived identifier for this Gate process incarnation.
    pub gate_boot_id: GateBootId,
    /// The checked monotonic counter committed with [`Self::gate_boot_id`].
    pub boot_counter: u64,
}

/// Highest-water anti-rollback state.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AntiRollbackStore {
    boot_counter: u64,
    last_gate_boot_id: Option<GateBootId>,
    terms: BTreeMap<Vec<u8>, u64>,
    revocation_epochs: BTreeMap<Vec<u8>, u64>,
}

impl AntiRollbackStore {
    /// A fresh store (only for genuine first provisioning, never on corruption).
    #[must_use]
    pub fn new_empty() -> Self {
        Self::default()
    }

    /// Advance only the P0 in-memory boot counter with checked exhaustion.
    ///
    /// Durable callers must use [`Self::candidate_for_boot`] so the counter is
    /// cryptographically bound to a Gate ID and caller-supplied entropy.
    ///
    /// # Errors
    /// Returns [`AntiRollbackError::Exhausted`] instead of reusing `u64::MAX`.
    pub fn advance_boot(&mut self) -> Result<u64, AntiRollbackError> {
        let next = self
            .boot_counter
            .checked_add(1)
            .ok_or(AntiRollbackError::Exhausted)?;
        self.boot_counter = next;
        Ok(next)
    }

    /// Prepare an advanced boot state without mutating the live store.
    ///
    /// The caller can serialize and durably commit the candidate, then replace
    /// the live state only after durable commit succeeds.
    ///
    /// # Errors
    /// Returns [`AntiRollbackError::Exhausted`] at the counter limit.
    pub fn candidate_with_advanced_boot(&self) -> Result<(Self, u64), AntiRollbackError> {
        let mut candidate = self.clone();
        let counter = candidate.advance_boot()?;
        Ok((candidate, counter))
    }

    /// Prepare a boot-ID-bound next incarnation without mutating the live store.
    ///
    /// `entropy` must be 256 bits obtained by the caller from its configured
    /// cryptographic entropy source. This semantic layer performs no OS access.
    ///
    /// # Errors
    /// Returns [`AntiRollbackError::Exhausted`] at the counter limit or
    /// [`AntiRollbackError::BootIdRepeat`] if the derived ID matches the last
    /// committed Gate boot ID.
    pub fn candidate_for_boot(
        &self,
        gate_id: &GateId,
        entropy: [u8; 32],
    ) -> Result<(Self, BootContext), AntiRollbackError> {
        let counter = self
            .boot_counter
            .checked_add(1)
            .ok_or(AntiRollbackError::Exhausted)?;
        let gate_boot_id = derive_gate_boot_id(gate_id, counter, &entropy);
        if self.last_gate_boot_id == Some(gate_boot_id) {
            return Err(AntiRollbackError::BootIdRepeat);
        }

        let mut candidate = self.clone();
        candidate.boot_counter = counter;
        candidate.last_gate_boot_id = Some(gate_boot_id);
        Ok((
            candidate,
            BootContext {
                gate_boot_id,
                boot_counter: counter,
            },
        ))
    }

    /// The current boot counter.
    #[must_use]
    pub const fn boot_counter(&self) -> u64 {
        self.boot_counter
    }

    /// The most recently committed Gate boot ID, if a bound boot has begun.
    #[must_use]
    pub const fn last_gate_boot_id(&self) -> Option<GateBootId> {
        self.last_gate_boot_id
    }

    /// The highest accepted term for a scope.
    #[must_use]
    pub fn highest_term(&self, scope: &[u8]) -> u64 {
        self.terms.get(scope).copied().unwrap_or(0)
    }

    /// Durably accept a term, requiring it to strictly exceed the stored high-water.
    ///
    /// # Errors
    /// Returns [`AntiRollbackError::Rollback`] if `term` is not greater than the
    /// stored high-water.
    pub fn accept_term(&mut self, scope: &[u8], term: u64) -> Result<(), AntiRollbackError> {
        let hw = self.highest_term(scope);
        if term <= hw {
            return Err(AntiRollbackError::Rollback);
        }
        self.terms.insert(scope.to_vec(), term);
        Ok(())
    }

    /// Prepare a term update without mutating the live store.
    ///
    /// # Errors
    /// Returns [`AntiRollbackError::Rollback`] when the term does not advance.
    pub fn candidate_with_term(&self, scope: &[u8], term: u64) -> Result<Self, AntiRollbackError> {
        let mut candidate = self.clone();
        candidate.accept_term(scope, term)?;
        Ok(candidate)
    }

    /// The highest accepted revocation epoch for a scope.
    #[must_use]
    pub fn revocation_epoch(&self, scope: &[u8]) -> u64 {
        self.revocation_epochs.get(scope).copied().unwrap_or(0)
    }

    /// Durably accept a revocation epoch (monotonic non-decreasing).
    ///
    /// # Errors
    /// Returns [`AntiRollbackError::Rollback`] if `epoch` is below the stored value.
    pub fn accept_revocation_epoch(
        &mut self,
        scope: &[u8],
        epoch: u64,
    ) -> Result<(), AntiRollbackError> {
        let cur = self.revocation_epoch(scope);
        if epoch < cur {
            return Err(AntiRollbackError::Rollback);
        }
        self.revocation_epochs.insert(scope.to_vec(), epoch);
        Ok(())
    }

    /// Prepare a revocation-epoch update without mutating the live store.
    ///
    /// # Errors
    /// Returns [`AntiRollbackError::Rollback`] when the epoch rewinds.
    pub fn candidate_with_revocation_epoch(
        &self,
        scope: &[u8],
        epoch: u64,
    ) -> Result<Self, AntiRollbackError> {
        let mut candidate = self.clone();
        candidate.accept_revocation_epoch(scope, epoch)?;
        Ok(candidate)
    }

    /// Serialize to the current durable byte representation (canonical,
    /// deterministic, and rejected by pre-v2 readers after the next write).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = CborWriter::new();
        w.array_header(5);
        w.uint(STORE_FORMAT_VERSION);
        w.uint(self.boot_counter);
        match self.last_gate_boot_id {
            Some(gate_boot_id) => w.bytes(gate_boot_id.as_bytes()),
            None => w.bytes(&[]),
        }
        encode_map(&mut w, &self.terms);
        encode_map(&mut w, &self.revocation_epochs);
        w.into_bytes()
    }

    /// Parse current v2 or legacy v1 durable bytes. The next serialization always
    /// writes v2 so restoring a pre-v2 binary fails closed rather than reusing a
    /// high-water advanced only in the collision-free namespace.
    ///
    /// # Errors
    /// Returns [`AntiRollbackError::Corrupt`] on any structural failure.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, AntiRollbackError> {
        let mut r = CborReader::new(bytes, Limits::LARGE);
        let n = r.read_array_len().map_err(|_| AntiRollbackError::Corrupt)?;
        let legacy_v1 = match n {
            4 => true,
            5 => {
                if r.read_uint().map_err(|_| AntiRollbackError::Corrupt)? != STORE_FORMAT_VERSION {
                    return Err(AntiRollbackError::Corrupt);
                }
                false
            }
            _ => return Err(AntiRollbackError::Corrupt),
        };
        let boot_counter = r.read_uint().map_err(|_| AntiRollbackError::Corrupt)?;
        let last_gate_boot_id = match r.read_bytes().map_err(|_| AntiRollbackError::Corrupt)? {
            [] => None,
            bytes => Some(GateBootId::new(
                bytes.try_into().map_err(|_| AntiRollbackError::Corrupt)?,
            )),
        };
        let terms = decode_map(&mut r)?;
        let revocation_epochs = decode_map(&mut r)?;
        r.end_container();
        r.finish().map_err(|_| AntiRollbackError::Corrupt)?;
        let store = Self {
            boot_counter,
            last_gate_boot_id,
            terms,
            revocation_epochs,
        };
        let canonical = if legacy_v1 {
            store.to_legacy_v1_bytes()
        } else {
            store.to_bytes()
        };
        if canonical != bytes {
            return Err(AntiRollbackError::Corrupt);
        }
        Ok(store)
    }

    fn to_legacy_v1_bytes(&self) -> Vec<u8> {
        let mut w = CborWriter::new();
        w.array_header(4);
        w.uint(self.boot_counter);
        match self.last_gate_boot_id {
            Some(gate_boot_id) => w.bytes(gate_boot_id.as_bytes()),
            None => w.bytes(&[]),
        }
        encode_map(&mut w, &self.terms);
        encode_map(&mut w, &self.revocation_epochs);
        w.into_bytes()
    }
}

fn derive_gate_boot_id(gate_id: &GateId, counter: u64, entropy: &[u8; 32]) -> GateBootId {
    let mut hasher = Sha256::new();
    hasher.update(BOOT_ID_DOMAIN);
    hasher.update(gate_id.as_str().as_bytes());
    hasher.update(counter.to_be_bytes());
    hasher.update(entropy);
    let digest: [u8; 32] = hasher.finalize().into();
    let mut boot_id = [0; 16];
    let (boot_id_bytes, _) = digest.split_at(boot_id.len());
    boot_id.copy_from_slice(boot_id_bytes);
    GateBootId::new(boot_id)
}

fn encode_map(w: &mut CborWriter, m: &BTreeMap<Vec<u8>, u64>) {
    w.array_header(m.len() as u64);
    for (k, v) in m {
        w.array_header(2);
        w.bytes(k);
        w.uint(*v);
    }
}

fn decode_map(r: &mut CborReader<'_>) -> Result<BTreeMap<Vec<u8>, u64>, AntiRollbackError> {
    let n = r.read_array_len().map_err(|_| AntiRollbackError::Corrupt)?;
    let mut m = BTreeMap::new();
    for _ in 0..n {
        let pair = r.read_array_len().map_err(|_| AntiRollbackError::Corrupt)?;
        if pair != 2 {
            return Err(AntiRollbackError::Corrupt);
        }
        let k = r
            .read_bytes()
            .map_err(|_| AntiRollbackError::Corrupt)?
            .to_vec();
        let v = r.read_uint().map_err(|_| AntiRollbackError::Corrupt)?;
        r.end_container();
        if m.insert(k, v).is_some() {
            return Err(AntiRollbackError::Corrupt);
        }
    }
    r.end_container();
    Ok(m)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gate_id() -> GateId {
        GateId::new("gate-1").unwrap()
    }

    #[test]
    fn term_must_strictly_advance() {
        let mut s = AntiRollbackStore::new_empty();
        s.accept_term(b"lease", 5).unwrap();
        assert_eq!(s.accept_term(b"lease", 5), Err(AntiRollbackError::Rollback));
        assert_eq!(s.accept_term(b"lease", 4), Err(AntiRollbackError::Rollback));
        s.accept_term(b"lease", 6).unwrap();
        assert_eq!(s.highest_term(b"lease"), 6);
    }

    #[test]
    fn boot_counter_strictly_increases_across_reload() {
        let mut s = AntiRollbackStore::new_empty();
        let b1 = s.advance_boot().unwrap();
        let bytes = s.to_bytes();
        let mut s2 = AntiRollbackStore::from_bytes(&bytes).unwrap();
        let b2 = s2.advance_boot().unwrap();
        assert!(b2 > b1, "boot counter must advance across a reload");
    }

    #[test]
    fn roundtrip_preserves_high_waters() {
        let mut s = AntiRollbackStore::new_empty();
        let (boot_candidate, context) = s.candidate_for_boot(&gate_id(), [7; 32]).unwrap();
        s = boot_candidate;
        s.accept_term(b"lease", 9).unwrap();
        s.accept_revocation_epoch(b"admission", 3).unwrap();
        let bytes = s.to_bytes();
        let s2 = AntiRollbackStore::from_bytes(&bytes).unwrap();
        assert_eq!(s2.highest_term(b"lease"), 9);
        assert_eq!(s2.revocation_epoch(b"admission"), 3);
        assert_eq!(s2.boot_counter(), s.boot_counter());
        assert_eq!(s2.last_gate_boot_id(), Some(context.gate_boot_id));
    }

    #[test]
    fn corrupt_store_is_rejected_not_zeroed() {
        let mut s = AntiRollbackStore::new_empty();
        s.accept_term(b"lease", 42).unwrap();
        let mut bytes = s.to_bytes();
        bytes.truncate(bytes.len() / 2); // corrupt the tail
        assert_eq!(
            AntiRollbackStore::from_bytes(&bytes).err(),
            Some(AntiRollbackError::Corrupt),
            "corruption must be a fault, never a zero-init reset"
        );
    }

    #[test]
    fn boot_counter_exhaustion_is_terminal_not_reused() {
        let bytes = AntiRollbackStore {
            boot_counter: u64::MAX,
            ..AntiRollbackStore::new_empty()
        }
        .to_bytes();
        let mut exhausted = AntiRollbackStore::from_bytes(&bytes).unwrap();
        assert_eq!(exhausted.advance_boot(), Err(AntiRollbackError::Exhausted));
        assert_eq!(exhausted.boot_counter(), u64::MAX);
    }

    #[test]
    fn candidates_do_not_mutate_live_state_before_commit() {
        let mut live = AntiRollbackStore::new_empty();
        live.accept_term(b"lease", 5).unwrap();
        let before = live.clone();

        let term_candidate = live.candidate_with_term(b"lease", 6).unwrap();
        assert_eq!(live, before);
        assert_eq!(term_candidate.highest_term(b"lease"), 6);

        let (boot_candidate, counter) = live.candidate_with_advanced_boot().unwrap();
        assert_eq!(live, before);
        assert_eq!(counter, 1);
        assert_eq!(boot_candidate.boot_counter(), 1);

        assert_eq!(
            live.candidate_with_term(b"lease", 5),
            Err(AntiRollbackError::Rollback)
        );
        assert_eq!(live, before);
    }

    #[test]
    fn noncanonical_or_duplicate_maps_are_corrupt() {
        let mut w = CborWriter::new();
        w.array_header(4);
        w.uint(0);
        w.bytes(&[]);
        w.array_header(2);
        for value in [1, 2] {
            w.array_header(2);
            w.bytes(b"same");
            w.uint(value);
        }
        w.array_header(0);
        assert_eq!(
            AntiRollbackStore::from_bytes(&w.into_bytes()),
            Err(AntiRollbackError::Corrupt)
        );
    }

    #[test]
    fn boot_derivation_is_deterministic_and_domain_bound() {
        let store = AntiRollbackStore::new_empty();
        let (candidate, context) = store.candidate_for_boot(&gate_id(), [7; 32]).unwrap();
        let (_, repeated_derivation) = store.candidate_for_boot(&gate_id(), [7; 32]).unwrap();

        assert_eq!(context, repeated_derivation);
        assert_eq!(context.boot_counter, 1);
        assert_eq!(
            context.gate_boot_id,
            GateBootId::new([
                0x53, 0x37, 0x21, 0xc0, 0xb3, 0xa3, 0xa7, 0x46, 0x1d, 0xc7, 0xd0, 0xe6, 0x6f, 0xd1,
                0x96, 0x52,
            ])
        );
        assert_eq!(candidate.last_gate_boot_id(), Some(context.gate_boot_id));
    }

    #[test]
    fn derived_boot_id_repeat_is_rejected_without_mutation() {
        let entropy = [9; 32];
        let repeated_id = derive_gate_boot_id(&gate_id(), 8, &entropy);
        let live = AntiRollbackStore {
            boot_counter: 7,
            last_gate_boot_id: Some(repeated_id),
            ..AntiRollbackStore::new_empty()
        };
        let before = live.clone();

        assert_eq!(
            live.candidate_for_boot(&gate_id(), entropy),
            Err(AntiRollbackError::BootIdRepeat)
        );
        assert_eq!(live, before);
    }

    #[test]
    fn bound_boot_candidate_rejects_counter_exhaustion_without_mutation() {
        let live = AntiRollbackStore {
            boot_counter: u64::MAX,
            ..AntiRollbackStore::new_empty()
        };
        let before = live.clone();

        assert_eq!(
            live.candidate_for_boot(&gate_id(), [1; 32]),
            Err(AntiRollbackError::Exhausted)
        );
        assert_eq!(live, before);
    }

    #[test]
    fn legacy_store_without_last_boot_id_is_rejected() {
        let mut legacy = CborWriter::new();
        legacy.array_header(3);
        legacy.uint(0);
        legacy.array_header(0);
        legacy.array_header(0);

        assert_eq!(
            AntiRollbackStore::from_bytes(&legacy.into_bytes()),
            Err(AntiRollbackError::Corrupt)
        );
    }

    #[test]
    fn legacy_v1_store_is_readable_but_every_new_write_blocks_binary_downgrade() {
        let mut legacy = AntiRollbackStore::new_empty();
        legacy
            .accept_term(b"lease:mission-authority:uav-1", 10)
            .unwrap();
        let legacy_bytes = legacy.to_legacy_v1_bytes();
        let migrated = AntiRollbackStore::from_bytes(&legacy_bytes).unwrap();
        assert_eq!(migrated.highest_term(b"lease:mission-authority:uav-1"), 10);

        let mut rewritten = migrated;
        rewritten.accept_term(b"canonical-scope", 11).unwrap();
        let rewritten_bytes = rewritten.to_bytes();

        let mut old_reader = CborReader::new(&rewritten_bytes, Limits::LARGE);
        assert_eq!(old_reader.read_array_len().unwrap(), 5);
        assert_ne!(rewritten_bytes, rewritten.to_legacy_v1_bytes());
        assert_eq!(
            AntiRollbackStore::from_bytes(&rewritten_bytes)
                .unwrap()
                .highest_term(b"canonical-scope"),
            11
        );
    }
}
