//! Ed25519 key wrappers with deterministic signing (RFC 8032).
//!
//! Application signing keys are separate from any transport (mTLS) key even when
//! they share an operational owner. The provider retains the seed inside its
//! secret-key representation for the key's lifetime. Haldir explicitly wipes
//! that retained buffer on drop, after which the provider's own `Drop` wipes it
//! again. This is defense in depth, not a claim that compiler/provider
//! temporaries, process memory, swap, or crash dumps are comprehensively erased.

use crate::error::CryptoError;
use curve25519_dalek::{edwards::CompressedEdwardsY, traits::IsIdentity};
use ed25519_compact as ed;
use zeroize::Zeroize;

/// An Ed25519 public (verifying) key.
#[derive(Debug, Clone)]
pub struct VerifyingKey(ed::PublicKey);

impl VerifyingKey {
    /// Construct from raw 32-byte public key material.
    ///
    /// # Errors
    /// Returns [`CryptoError::BadKey`] unless the bytes are the unique canonical
    /// encoding of a non-identity point in the prime-order subgroup and the
    /// selected signature provider also accepts them. The subgroup check rejects
    /// pure-torsion and mixed-torsion aliases before they can cross key-role or
    /// revocation boundaries.
    pub fn from_bytes(b: [u8; 32]) -> Result<Self, CryptoError> {
        let compressed = CompressedEdwardsY(b);
        let point = compressed.decompress().ok_or(CryptoError::BadKey)?;
        if point.compress().to_bytes() != b || point.is_identity() || !point.is_torsion_free() {
            return Err(CryptoError::BadKey);
        }
        let key = ed::PublicKey::from_slice(&b).map_err(|_| CryptoError::BadKey)?;
        // `PublicKey::from_slice` checks length only. Incremental verifier
        // construction performs the provider's actual public-key checks before
        // it accepts message bytes. A canonical-zero scalar in this deliberately
        // non-verifying probe keeps signature validity irrelevant.
        let probe = ed::Signature::new([0; 64]);
        key.verify_incremental(&probe)
            .map_err(|_| CryptoError::BadKey)?;
        Ok(Self(key))
    }

    /// The 32-byte public key.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 32] {
        *self.0
    }

    /// Verify `signature` over the exact `message` bytes.
    #[must_use]
    pub fn verify(&self, message: &[u8], signature: &Signature) -> bool {
        if !signature.has_strict_r_encoding() {
            return false;
        }
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

    /// Require the signature's encoded nonce point to be canonical and in the
    /// prime-order subgroup before using the provider's cofactored verifier.
    /// With the same invariant on the public key, a small-order verification
    /// difference can only be the identity, giving Haldir one accepted point
    /// encoding for each signature equation.
    fn has_strict_r_encoding(&self) -> bool {
        let Some(encoded_r) = self.0.get(..32) else {
            return false;
        };
        let mut bytes = [0_u8; 32];
        bytes.copy_from_slice(encoded_r);
        let compressed = CompressedEdwardsY(bytes);
        compressed.decompress().is_some_and(|point| {
            point.compress().to_bytes() == bytes && !point.is_identity() && point.is_torsion_free()
        })
    }
}

/// An Ed25519 signing key with an explicitly drop-zeroized provider secret.
pub struct SigningKey {
    keypair: ed::KeyPair,
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
    pub fn from_seed(mut seed: [u8; 32]) -> Result<Self, CryptoError> {
        if seed.iter().all(|byte| *byte == 0) {
            return Err(CryptoError::BadKey);
        }
        let mut provider_seed = ed::Seed::new(seed);
        // This does not affect the caller's by-value source buffer, but it does
        // minimize the lifetime of Haldir's own argument copy.
        seed.zeroize();
        let keypair = ed::KeyPair::from_seed(provider_seed);
        provider_seed.wipe_mut();
        Ok(Self { keypair })
    }

    fn wipe_secret(&mut self) {
        self.keypair.sk[..].zeroize();
    }

    /// The corresponding verifying key.
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey(self.keypair.pk)
    }

    /// Deterministically sign `message`.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> Signature {
        let sig = self.keypair.sk.sign(message, None);
        Signature(*sig)
    }
}

impl Drop for SigningKey {
    fn drop(&mut self) {
        // Wipe through Haldir's reviewed dependency before the provider's
        // SecretKey::drop performs a second volatile wipe of the same buffer.
        self.wipe_secret();
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
    fn verifying_key_rejects_provider_weak_encodings_at_construction() {
        assert!(matches!(
            VerifyingKey::from_bytes([0; 32]),
            Err(CryptoError::BadKey)
        ));

        let mut identity = [0; 32];
        identity[0] = 1;
        assert!(matches!(
            VerifyingKey::from_bytes(identity),
            Err(CryptoError::BadKey)
        ));

        // Canonical order-two point (y = -1). The pinned signature provider's
        // incremental constructor accepts this point, so Haldir's independent
        // prime-subgroup validation is security-significant.
        let mut order_two = [0xff; 32];
        order_two[0] = 0xec;
        order_two[31] = 0x7f;
        assert!(matches!(
            VerifyingKey::from_bytes(order_two),
            Err(CryptoError::BadKey)
        ));

        // Non-canonical encoding of the identity (y = p + 1).
        let mut noncanonical_identity = [0xff; 32];
        noncanonical_identity[0] = 0xee;
        noncanonical_identity[31] = 0x7f;
        assert!(matches!(
            VerifyingKey::from_bytes(noncanonical_identity),
            Err(CryptoError::BadKey)
        ));
    }

    #[test]
    fn verifying_key_rejects_a_prime_component_with_added_torsion() {
        use curve25519_dalek::constants::{ED25519_BASEPOINT_POINT, EIGHT_TORSION};

        let mixed = (ED25519_BASEPOINT_POINT + EIGHT_TORSION[1])
            .compress()
            .to_bytes();
        assert!(matches!(
            VerifyingKey::from_bytes(mixed),
            Err(CryptoError::BadKey)
        ));
    }

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

        assert!(signature.has_strict_r_encoding());
        assert!(key.verifying_key().verify(message, &signature));
    }

    #[test]
    fn signature_rejects_noncanonical_or_torsion_nonce_points_before_verification() {
        let key = SigningKey::from_seed([2; 32]).expect("nonzero test seed");
        let message = b"haldir-strict-signature-point";
        let valid = key.sign(message).to_bytes();

        let mut noncanonical = valid;
        noncanonical[..32].copy_from_slice(&[
            0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x7f,
        ]);
        let noncanonical = Signature::from_bytes(noncanonical);
        assert!(!noncanonical.has_strict_r_encoding());
        assert!(!key.verifying_key().verify(message, &noncanonical));

        let mut torsion = valid;
        torsion[..32].copy_from_slice(
            &curve25519_dalek::constants::EIGHT_TORSION[1]
                .compress()
                .to_bytes(),
        );
        let torsion = Signature::from_bytes(torsion);
        assert!(!torsion.has_strict_r_encoding());
        assert!(!key.verifying_key().verify(message, &torsion));

        // The identity is torsion-free in the group-theoretic sense but has
        // order one, not the required prime order. Reject it explicitly rather
        // than relying on the provider's cofactored verification equation.
        let mut identity = valid;
        identity[..32].fill(0);
        identity[0] = 1;
        let identity = Signature::from_bytes(identity);
        assert!(!identity.has_strict_r_encoding());
        assert!(!key.verifying_key().verify(message, &identity));
    }

    #[test]
    fn explicit_secret_wipe_clears_the_retained_provider_buffer() {
        let mut key = SigningKey::from_seed([7; 32]).expect("nonzero test seed");
        assert!(key.keypair.sk.iter().any(|byte| *byte != 0));

        key.wipe_secret();

        assert!(key.keypair.sk.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn signing_key_debug_is_redacted() {
        let key = SigningKey::from_seed([9; 32]).expect("nonzero test seed");
        assert_eq!(format!("{key:?}"), "SigningKey(<redacted>)");
    }
}
