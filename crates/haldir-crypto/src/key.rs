//! Ed25519 key wrappers with deterministic signing (RFC 8032).
//!
//! Application signing keys are separate from any transport (mTLS) key even when
//! they share an operational owner. Secret seed material is held in a zeroizing
//! buffer.

use crate::error::CryptoError;
use ed25519_compact as ed;
use zeroize::Zeroizing;

/// An Ed25519 public (verifying) key.
#[derive(Debug, Clone)]
pub struct VerifyingKey(ed::PublicKey);

impl VerifyingKey {
    /// Construct from raw 32-byte public key material.
    ///
    /// # Errors
    /// Returns [`CryptoError::BadKey`] if the bytes are not a valid public key.
    pub fn from_bytes(b: [u8; 32]) -> Result<Self, CryptoError> {
        ed::PublicKey::from_slice(&b)
            .map(Self)
            .map_err(|_| CryptoError::BadKey)
    }

    /// The 32-byte public key.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 32] {
        *self.0
    }

    /// Verify `signature` over the exact `message` bytes.
    #[must_use]
    pub fn verify(&self, message: &[u8], signature: &Signature) -> bool {
        match ed::Signature::from_slice(&signature.0) {
            Ok(s) => self.0.verify(message, &s).is_ok(),
            Err(_) => false,
        }
    }
}

/// An Ed25519 signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signature([u8; 64]);

impl Signature {
    /// Wrap raw 64 signature bytes.
    #[must_use]
    pub const fn from_bytes(b: [u8; 64]) -> Self {
        Self(b)
    }

    /// The 64 signature bytes.
    #[must_use]
    pub const fn to_bytes(&self) -> [u8; 64] {
        self.0
    }
}

/// An Ed25519 signing key backed by a zeroizing 32-byte seed.
pub struct SigningKey {
    seed: Zeroizing<[u8; 32]>,
}

impl SigningKey {
    /// Construct from a nonzero 32-byte seed.
    ///
    /// The all-zero value is not a valid seed in the selected Ed25519
    /// implementation. Rejecting it here makes that dependency precondition an
    /// invariant of `SigningKey`, so the otherwise infallible signing methods
    /// cannot reach the dependency's panic path.
    ///
    /// # Errors
    /// Returns [`CryptoError::BadKey`] when `seed` is all zeroes.
    pub fn from_seed(seed: [u8; 32]) -> Result<Self, CryptoError> {
        if seed.iter().all(|byte| *byte == 0) {
            return Err(CryptoError::BadKey);
        }
        Ok(Self {
            seed: Zeroizing::new(seed),
        })
    }

    fn keypair(&self) -> ed::KeyPair {
        ed::KeyPair::from_seed(ed::Seed::new(*self.seed))
    }

    /// The corresponding verifying key.
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey(self.keypair().pk)
    }

    /// Deterministically sign `message`.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> Signature {
        let sig = self.keypair().sk.sign(message, None);
        Signature(*sig)
    }
}

impl core::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Never print secret material.
        f.write_str("SigningKey(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_seed_rejects_all_zero_seed_without_panicking() {
        assert!(matches!(
            SigningKey::from_seed([0; 32]),
            Err(CryptoError::BadKey)
        ));
    }

    #[test]
    fn nonzero_seed_supports_signing_and_verification() {
        let key = SigningKey::from_seed([1; 32]).expect("nonzero test seed");
        let message = b"haldir-signing-key-invariant";
        let signature = key.sign(message);

        assert!(key.verifying_key().verify(message, &signature));
    }
}
