//! Storage MAC key and HMAC-SHA256 helpers.

use crate::error::DurableError;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

type HmacSha256 = Hmac<Sha256>;

fn compute_tag(key: &[u8], bytes: &[u8]) -> Result<[u8; 32], DurableError> {
    let mut mac =
        HmacSha256::new_from_slice(key).map_err(|_| DurableError::AuthenticationFailed)?;
    mac.update(bytes);
    Ok(mac.finalize().into_bytes().into())
}

/// Separately provisioned storage-authentication key.
///
/// This key must not be derived from, or stored beside, the rewritable snapshot.
pub struct StorageMacKey(Zeroizing<[u8; 32]>);

impl StorageMacKey {
    /// Construct from an independently provisioned, nonzero 256-bit key.
    ///
    /// Rejecting the all-zero sentinel catches an otherwise catastrophic
    /// provisioning error. It does not measure entropy or prove protected key
    /// generation/custody. The retained key is wiped on drop; transient caller,
    /// compiler, process, swap, and crash-dump copies remain outside that claim.
    ///
    /// # Errors
    /// Returns [`DurableError::InvalidKey`] for the all-zero value.
    pub fn new(mut bytes: [u8; 32]) -> Result<Self, DurableError> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(DurableError::InvalidKey);
        }
        let retained = Zeroizing::new(bytes);
        bytes.zeroize();
        Ok(Self(retained))
    }

    pub(crate) fn tag(&self, bytes: &[u8]) -> Result<[u8; 32], DurableError> {
        compute_tag(self.0.as_ref(), bytes)
    }

    pub(crate) fn verify(&self, bytes: &[u8], tag: &[u8]) -> Result<(), DurableError> {
        let mut mac = HmacSha256::new_from_slice(self.0.as_ref())
            .map_err(|_| DurableError::AuthenticationFailed)?;
        mac.update(bytes);
        mac.verify_slice(tag)
            .map_err(|_| DurableError::AuthenticationFailed)
    }
}

impl core::fmt::Debug for StorageMacKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("StorageMacKey(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc_4231_hmac_sha256_case_one() {
        let tag = compute_tag(&[0x0b; 20], b"Hi There").unwrap();
        assert_eq!(
            tag,
            [
                0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b,
                0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c,
                0x2e, 0x32, 0xcf, 0xf7,
            ]
        );
    }

    #[test]
    fn storage_key_rejects_all_zero_provisioning_value() {
        assert!(matches!(
            StorageMacKey::new([0; 32]),
            Err(DurableError::InvalidKey)
        ));
    }

    #[test]
    fn storage_key_debug_never_exposes_key_material() {
        let key = StorageMacKey::new([7; 32]).expect("nonzero test key");

        assert_eq!(format!("{key:?}"), "StorageMacKey(<redacted>)");
    }
}
