//! Neutral deployment-package ratchet values shared by verification and state.
//!
//! The signed package schema and its loader live outside this module. These
//! narrow values let durable state bind a nonzero revision to a package-domain
//! digest without depending on a verifier crate. The values themselves carry no
//! verification or canonical-decoding provenance.

use core::num::NonZeroU64;

use crate::cbor::{CanonicalValue, CborReader, CborWriter, Validate};
use crate::digest::{DigestDomain, DigestV1};
use crate::error::DecodeError;

/// A nonzero, monotonically compared deployment-package revision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DeploymentRevision(NonZeroU64);

impl DeploymentRevision {
    /// Construct from a nonzero revision.
    #[must_use]
    pub const fn new(revision: NonZeroU64) -> Self {
        Self(revision)
    }

    /// The numeric revision.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

impl CanonicalValue for DeploymentRevision {
    fn encode(&self, writer: &mut CborWriter) {
        self.0.encode(writer);
    }

    fn decode(reader: &mut CborReader<'_>) -> Result<Self, DecodeError> {
        Ok(Self(NonZeroU64::decode(reader)?))
    }
}

impl Validate for DeploymentRevision {}

/// Domain-separated digest wrapper for deployment-package payload bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DeploymentPayloadDigestV1(DigestV1);

impl DeploymentPayloadDigestV1 {
    /// Hash caller-supplied bytes in the deployment-package domain.
    ///
    /// This neutral constructor does not prove that the bytes were verified or
    /// canonically decoded; the deployment verifier supplies that provenance at
    /// its own higher-level typestate boundary.
    #[must_use]
    pub fn compute(canonical_payload: &[u8]) -> Self {
        Self(DigestV1::compute(
            DigestDomain::DeploymentPackage,
            canonical_payload,
        ))
    }

    /// Borrow the typed digest value.
    #[must_use]
    pub const fn as_digest(&self) -> &DigestV1 {
        &self.0
    }
}

impl CanonicalValue for DeploymentPayloadDigestV1 {
    fn encode(&self, writer: &mut CborWriter) {
        self.0.encode(writer);
    }

    fn decode(reader: &mut CborReader<'_>) -> Result<Self, DecodeError> {
        Ok(Self(DigestV1::decode(reader)?))
    }
}

impl Validate for DeploymentPayloadDigestV1 {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor::{Limits, from_canonical_bytes, to_canonical_bytes};

    #[test]
    fn revision_and_payload_digest_roundtrip_canonically() {
        let revision = DeploymentRevision::new(NonZeroU64::new(7).unwrap());
        let digest = DeploymentPayloadDigestV1::compute(b"canonical-package");

        let revision_bytes = to_canonical_bytes(&revision);
        let digest_bytes = to_canonical_bytes(&digest);

        assert_eq!(
            from_canonical_bytes::<DeploymentRevision>(&revision_bytes, Limits::DEFAULT).unwrap(),
            revision
        );
        assert_eq!(
            from_canonical_bytes::<DeploymentPayloadDigestV1>(&digest_bytes, Limits::DEFAULT)
                .unwrap(),
            digest
        );
    }

    #[test]
    fn payload_digest_has_a_distinct_domain() {
        let bytes = b"same-bytes";
        assert_ne!(
            *DeploymentPayloadDigestV1::compute(bytes).as_digest(),
            DigestV1::compute(DigestDomain::Payload, bytes)
        );
    }
}
