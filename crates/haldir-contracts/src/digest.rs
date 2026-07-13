//! Typed digests with explicit algorithm and domain separation.
//!
//! Digests are typed values, not bare hex strings. Distinct digest *domains*
//! (`raw_envelope`, `payload`, `semantic_intent`, `state_snapshot`, ...) are
//! domain-separated by a per-kind prefix so two different objects cannot collide
//! into one digest value (punch-list H10).

use crate::cbor::{CanonicalValue, CborReader, CborWriter};
use crate::error::DecodeError;
use sha2::{Digest, Sha256};

/// Supported digest algorithms. Only SHA-256 is enabled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum DigestAlgorithmV1 {
    /// SHA-256 (RFC 6234).
    Sha256,
}

impl DigestAlgorithmV1 {
    const TAG_SHA256: u64 = 1;
}

impl CanonicalValue for DigestAlgorithmV1 {
    fn encode(&self, w: &mut CborWriter) {
        match self {
            Self::Sha256 => w.uint(Self::TAG_SHA256),
        }
    }
    fn decode(r: &mut CborReader<'_>) -> Result<Self, DecodeError> {
        match r.read_uint()? {
            Self::TAG_SHA256 => Ok(Self::Sha256),
            _ => Err(DecodeError::BadEnumTag),
        }
    }
}

/// A typed 256-bit digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DigestV1 {
    /// Digest algorithm.
    pub algorithm: DigestAlgorithmV1,
    /// Digest value.
    pub value: [u8; 32],
}

/// Domains for hashing distinct object classes. The domain byte-string is mixed
/// into the hash input so digests of different domains never collide.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DigestDomain {
    /// Exact received COSE envelope bytes.
    RawEnvelope,
    /// Exact canonical payload bytes.
    Payload,
    /// Canonical typed action and its policy-relevant bindings.
    SemanticIntent,
    /// Exact Gate-created NCP serialization.
    OutputFrame,
    /// Canonical state values used for a decision.
    StateSnapshot,
    /// Exact approved policy package.
    PolicySnapshot,
    /// A controller bundle.
    Bundle,
    /// A backend execution profile.
    BackendProfile,
    /// An admission record.
    Admission,
    /// Exact bytes of an artifact referenced by a deployment package.
    DeploymentArtifact,
    /// Exact canonical payload bytes of a deployment package.
    DeploymentPackage,
    /// A Gate decision identifier derived from a full boot id and counter.
    DecisionId,
}

impl DigestDomain {
    /// The domain-separation prefix mixed into the hash input.
    #[must_use]
    pub const fn prefix(self) -> &'static [u8] {
        match self {
            Self::RawEnvelope => b"haldir.digest.raw_envelope.v1",
            Self::Payload => b"haldir.digest.payload.v1",
            Self::SemanticIntent => b"haldir.digest.semantic_intent.v1",
            Self::OutputFrame => b"haldir.digest.output_frame.v1",
            Self::StateSnapshot => b"haldir.digest.state_snapshot.v1",
            Self::PolicySnapshot => b"haldir.digest.policy_snapshot.v1",
            Self::Bundle => b"haldir.digest.bundle.v1",
            Self::BackendProfile => b"haldir.digest.backend_profile.v1",
            Self::Admission => b"haldir.digest.admission.v1",
            Self::DeploymentArtifact => b"haldir.digest.deployment_artifact.v1",
            Self::DeploymentPackage => b"haldir.digest.deployment_package.v1",
            Self::DecisionId => b"haldir.digest.decision_id.v1",
        }
    }
}

impl DigestV1 {
    /// Compute a domain-separated SHA-256 digest of `data`.
    ///
    /// The hash input is `len(prefix) || prefix || data` so that neither the
    /// prefix nor the data boundary can be shifted to forge a cross-domain match.
    #[must_use]
    pub fn compute(domain: DigestDomain, data: &[u8]) -> Self {
        let prefix = domain.prefix();
        let mut h = Sha256::new();
        h.update((prefix.len() as u64).to_be_bytes());
        h.update(prefix);
        h.update(data);
        Self {
            algorithm: DigestAlgorithmV1::Sha256,
            value: h.finalize().into(),
        }
    }

    /// Convenience: digest the canonical bytes of a [`CanonicalValue`] in a domain.
    #[must_use]
    pub fn of_value<T: CanonicalValue>(domain: DigestDomain, value: &T) -> Self {
        Self::compute(domain, &crate::cbor::to_canonical_bytes(value))
    }
}

impl CanonicalValue for DigestV1 {
    fn encode(&self, w: &mut CborWriter) {
        // map { 1: algorithm, 2: value }
        w.map_header(2);
        w.uint(1);
        self.algorithm.encode(w);
        w.uint(2);
        w.bytes(&self.value);
    }
    fn decode(r: &mut CborReader<'_>) -> Result<Self, DecodeError> {
        let n = r.read_map_len()?;
        let mut algorithm: Option<DigestAlgorithmV1> = None;
        let mut value: Option<[u8; 32]> = None;
        let mut last: Option<u64> = None;
        for _ in 0..n {
            let k = r.read_map_key()?;
            if let Some(p) = last
                && k <= p
            {
                return Err(DecodeError::NonCanonicalMapOrder);
            }
            last = Some(k);
            match k {
                1 => algorithm = Some(DigestAlgorithmV1::decode(r)?),
                2 => value = Some(<[u8; 32]>::decode(r)?),
                other => return Err(DecodeError::UnknownField { key: other }),
            }
        }
        r.end_container();
        Ok(Self {
            algorithm: algorithm.ok_or(DecodeError::MissingField { key: 1 })?,
            value: value.ok_or(DecodeError::MissingField { key: 2 })?,
        })
    }
}
