//! Anti-rollback high-water store (spec §anti-rollback, B11/B12/H12).
//!
//! Holds the highest accepted terms and revocation epochs plus a monotonic boot
//! counter — never an active lease. `accept_term`/`accept_revocation_epoch` reject
//! any value that does not strictly advance the stored high-water, and the
//! high-water is advanced BEFORE a lease is exposed active (H12, in-process order).
//!
//! **In P0 this store is in-memory.** The `to_bytes`/`from_bytes` format exists for
//! a future durable backing, and `from_bytes` detects *structural* corruption; but
//! the P0 Gate does not persist, load, MAC, or fsync the store, and does not yet
//! derive/compare `gate_boot_id` against the boot counter. Durable persistence
//! (atomic temp→fsync→rename, a separate-key MAC to detect a semantic rewind to a
//! lower high-water, and a boot-id-repeat latch) is therefore OUT of P0 scope; see
//! `docs/LIMITATIONS.md`. Consequently the cross-restart rollback protection B11/B12
//! describe is **not** established by this deliverable.

use haldir_contracts::cbor::{CborReader, CborWriter, Limits};
use std::collections::BTreeMap;

/// An anti-rollback failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AntiRollbackError {
    /// A term/epoch/boot value did not strictly advance (a rollback attempt).
    Rollback,
    /// A checked monotonic namespace reached its terminal value.
    Exhausted,
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
            Self::Corrupt => "ANTI_ROLLBACK_CORRUPT",
        }
    }
}

/// Highest-water anti-rollback state.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AntiRollbackStore {
    boot_counter: u64,
    terms: BTreeMap<Vec<u8>, u64>,
    revocation_epochs: BTreeMap<Vec<u8>, u64>,
}

impl AntiRollbackStore {
    /// A fresh store (only for genuine first provisioning, never on corruption).
    #[must_use]
    pub fn new_empty() -> Self {
        Self::default()
    }

    /// Advance the boot counter with checked exhaustion.
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

    /// The current boot counter.
    #[must_use]
    pub const fn boot_counter(&self) -> u64 {
        self.boot_counter
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

    /// Serialize to a durable byte representation (canonical, deterministic).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = CborWriter::new();
        w.array_header(3);
        w.uint(self.boot_counter);
        encode_map(&mut w, &self.terms);
        encode_map(&mut w, &self.revocation_epochs);
        w.into_bytes()
    }

    /// Parse from durable bytes. A parse failure is corruption (latch a fault).
    ///
    /// # Errors
    /// Returns [`AntiRollbackError::Corrupt`] on any structural failure.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, AntiRollbackError> {
        let mut r = CborReader::new(bytes, Limits::LARGE);
        let n = r.read_array_len().map_err(|_| AntiRollbackError::Corrupt)?;
        if n != 3 {
            return Err(AntiRollbackError::Corrupt);
        }
        let boot_counter = r.read_uint().map_err(|_| AntiRollbackError::Corrupt)?;
        let terms = decode_map(&mut r)?;
        let revocation_epochs = decode_map(&mut r)?;
        r.end_container();
        r.finish().map_err(|_| AntiRollbackError::Corrupt)?;
        let store = Self {
            boot_counter,
            terms,
            revocation_epochs,
        };
        if store.to_bytes() != bytes {
            return Err(AntiRollbackError::Corrupt);
        }
        Ok(store)
    }
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
        let _ = s.advance_boot().unwrap();
        s.accept_term(b"lease", 9).unwrap();
        s.accept_revocation_epoch(b"admission", 3).unwrap();
        let bytes = s.to_bytes();
        let s2 = AntiRollbackStore::from_bytes(&bytes).unwrap();
        assert_eq!(s2.highest_term(b"lease"), 9);
        assert_eq!(s2.revocation_epoch(b"admission"), 3);
        assert_eq!(s2.boot_counter(), s.boot_counter());
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
        let mut w = CborWriter::new();
        w.array_header(3);
        w.uint(u64::MAX);
        w.array_header(0);
        w.array_header(0);
        let bytes = w.into_bytes();
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
        w.array_header(3);
        w.uint(0);
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
}
