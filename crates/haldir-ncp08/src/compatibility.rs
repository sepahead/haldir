//! Immutable NCP `v0.8.0` compatibility identity and artifact validation.
//!
//! A version string such as `0.8` is insufficient. The compiled compatibility
//! record binds the reviewed command-path subset: release tag and exact commit,
//! contract and proto identities, the frozen command schema/vector digests, the
//! enabled increment, capability profile, and Haldir adapter version. A strict
//! canonical artifact decoder exact-matches every one of those pins before
//! returning a validation proof.
//!
//! This remains narrower than the full compatibility identity required by the
//! project specification: aggregate schema/conformance-set identities and
//! reproducible adapter source/build provenance are not yet present.

use core::fmt;

use haldir_contracts::cbor::{
    CborWriter, Limits, Validate, from_canonical_bytes, to_canonical_bytes,
};
use haldir_contracts::digest::{DigestDomain, DigestV1};
use haldir_contracts::error::DecodeError;
use haldir_contracts::scalar::AsciiId;

/// Maximum encoded size accepted for one NCP compatibility artifact.
pub const NCP_COMPATIBILITY_ARTIFACT_MAX_BYTES: usize = 512;

const NCP_COMPATIBILITY_ARTIFACT_LIMITS: Limits = Limits {
    max_depth: 1,
    max_map_pairs: 16,
    max_array_len: 0,
    max_bytes_len: 32,
    max_text_len: 64,
    max_total_bytes: NCP_COMPATIBILITY_ARTIFACT_MAX_BYTES,
};

/// The pinned NCP `v0.8.0` compatibility record for this adapter.
///
/// The schema/vector fields identify Haldir's frozen command-frame subset, not
/// aggregate identities for every file in the upstream schema/conformance sets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NcpCompatibilityRecordV1 {
    /// Reviewed release tag; the exact commit is the immutable identity.
    pub ncp_tag: &'static str,
    /// Exact 40-hex commit.
    pub ncp_commit: &'static str,
    /// Wire version.
    pub wire_version: &'static str,
    /// Contract hash from the release.
    pub contract_hash: &'static str,
    /// Measured `proto/ncp.proto` SHA-256.
    pub proto_sha256: &'static str,
    /// SHA-256 of the frozen command-frame schema used by Haldir.
    pub command_schema_sha256: &'static str,
    /// SHA-256 of the frozen command-frame conformance vector used by Haldir.
    pub command_vector_sha256: &'static str,
    /// Closed NCP capability increment enabled by this adapter.
    pub enabled_increment: u16,
    /// The active capability profile.
    pub capability_profile: &'static str,
    /// The Haldir adapter version.
    pub haldir_adapter_version: &'static str,
}

/// The pinned constants (specification NCP baseline; `docs/NCP-COMPATIBILITY.md`).
pub const NCP_V0_8_0: NcpCompatibilityRecordV1 = NcpCompatibilityRecordV1 {
    ncp_tag: "v0.8.0",
    ncp_commit: "2f5bd586d4bb20c90362bb6f5698b7f64057ba4e",
    wire_version: "0.8",
    contract_hash: "d1b50a2d8a265276",
    proto_sha256: "6f13b12cff76e12fef384f691d11e2944db1f676568c3e780d3f975689131227",
    command_schema_sha256: "abd9743323e4f6eabdbc27888704462b1b1fd128777422b35146605709a01344",
    command_vector_sha256: "3e3d73235fe2dd4288158c29f9cd2f3f17034f7a58d803682f45c145a9733f2e",
    enabled_increment: 1,
    capability_profile: "PRE_AUTHORITY_ACL_ONLY",
    haldir_adapter_version: env!("CARGO_PKG_VERSION"),
};

impl NcpCompatibilityRecordV1 {
    /// A stable digest over an unambiguous canonical array containing every
    /// compiled compatibility field. A future identity schema must use a new
    /// domain label rather than silently reusing the `.v1` label below.
    #[must_use]
    pub fn compatibility_id(&self) -> DigestV1 {
        let mut material = CborWriter::new();
        material.array_header(11);
        material.text("haldir.ncp_compatibility_id.v1");
        material.text(self.ncp_tag);
        material.text(self.ncp_commit);
        material.text(self.wire_version);
        material.text(self.contract_hash);
        material.text(self.proto_sha256);
        material.text(self.command_schema_sha256);
        material.text(self.command_vector_sha256);
        material.uint(u64::from(self.enabled_increment));
        material.text(self.capability_profile);
        material.text(self.haldir_adapter_version);
        DigestV1::compute(DigestDomain::Payload, material.as_bytes())
    }
}

haldir_contracts::canonical_struct! {
    /// Canonical syntax for the ordinary `NCP_COMPATIBILITY` deployment artifact.
    ///
    /// Constructing or decoding this value does not prove pin agreement. Use
    /// [`validate_ncp_compatibility_artifact`] to obtain the validation proof.
    pub struct NcpCompatibilityArtifactV1 kind "haldir.ncp_compatibility" {
        req 2 schema_major: u16,
        req 3 schema_minor: u16,
        req 4 ncp_tag: AsciiId<16>,
        req 5 ncp_commit: AsciiId<40>,
        req 6 wire_version: AsciiId<16>,
        req 7 contract_hash: AsciiId<32>,
        req 8 proto_sha256: [u8; 32],
        req 9 command_schema_sha256: [u8; 32],
        req 10 command_vector_sha256: [u8; 32],
        req 11 enabled_increment: u16,
        req 12 capability_profile: AsciiId<64>,
        req 13 haldir_adapter_version: AsciiId<64>,
    }
}

impl Validate for NcpCompatibilityArtifactV1 {
    fn validate(&self) -> Result<(), DecodeError> {
        if self.schema_major != 1 || self.schema_minor != 0 {
            return Err(DecodeError::UnsupportedVersion);
        }
        Ok(())
    }
}

impl NcpCompatibilityArtifactV1 {
    /// Build the canonical artifact value for this compiled adapter baseline.
    ///
    /// # Errors
    /// Returns [`NcpCompatibilityError::CompiledPinInvalid`] if a source pin is
    /// malformed. The repository pin verifier also checks these constants.
    pub fn pinned() -> Result<Self, NcpCompatibilityError> {
        Ok(Self {
            schema_major: 1,
            schema_minor: 0,
            ncp_tag: pinned_ascii(NCP_V0_8_0.ncp_tag)?,
            ncp_commit: pinned_ascii(NCP_V0_8_0.ncp_commit)?,
            wire_version: pinned_ascii(NCP_V0_8_0.wire_version)?,
            contract_hash: pinned_ascii(NCP_V0_8_0.contract_hash)?,
            proto_sha256: decode_sha256(NCP_V0_8_0.proto_sha256)
                .ok_or(NcpCompatibilityError::CompiledPinInvalid)?,
            command_schema_sha256: decode_sha256(NCP_V0_8_0.command_schema_sha256)
                .ok_or(NcpCompatibilityError::CompiledPinInvalid)?,
            command_vector_sha256: decode_sha256(NCP_V0_8_0.command_vector_sha256)
                .ok_or(NcpCompatibilityError::CompiledPinInvalid)?,
            enabled_increment: NCP_V0_8_0.enabled_increment,
            capability_profile: pinned_ascii(NCP_V0_8_0.capability_profile)?,
            haldir_adapter_version: pinned_ascii(NCP_V0_8_0.haldir_adapter_version)?,
        })
    }
}

/// A canonical compatibility artifact that exact-matched every compiled pin.
///
/// Fields are private so ordinary structural decoding cannot be confused with
/// agreement to this build's reviewed baseline.
///
/// ```compile_fail
/// use haldir_ncp08::ValidatedNcpCompatibilityArtifact;
///
/// let _forged = ValidatedNcpCompatibilityArtifact {
///     artifact: todo!(),
///     compatibility_id: todo!(),
/// };
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedNcpCompatibilityArtifact {
    artifact: NcpCompatibilityArtifactV1,
    compatibility_id: DigestV1,
}

impl ValidatedNcpCompatibilityArtifact {
    /// The canonical, exact-pin-matched artifact value.
    #[must_use]
    pub const fn artifact(&self) -> &NcpCompatibilityArtifactV1 {
        &self.artifact
    }

    /// Identity derived from every compiled compatibility field.
    #[must_use]
    pub const fn compatibility_id(&self) -> DigestV1 {
        self.compatibility_id
    }
}

/// Strict compatibility-artifact decoding or exact-pin validation failure.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum NcpCompatibilityError {
    /// Canonical syntax, resource limits, or schema validation failed.
    Decode(DecodeError),
    /// One of the adapter's compiled source pins was internally malformed.
    CompiledPinInvalid,
    /// The canonical artifact did not exact-match the compiled baseline.
    PinMismatch,
}

impl NcpCompatibilityError {
    /// Stable machine-readable reason class.
    #[must_use]
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::Decode(error) => error.reason_code(),
            Self::CompiledPinInvalid => "NCP_COMPATIBILITY_COMPILED_PIN_INVALID",
            Self::PinMismatch => "NCP_COMPATIBILITY_PIN_MISMATCH",
        }
    }
}

impl From<DecodeError> for NcpCompatibilityError {
    fn from(error: DecodeError) -> Self {
        Self::Decode(error)
    }
}

impl fmt::Display for NcpCompatibilityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for NcpCompatibilityError {}

/// Emit the exact canonical artifact bytes for this compiled adapter baseline.
///
/// # Errors
/// Returns [`NcpCompatibilityError::CompiledPinInvalid`] if a source pin is
/// malformed.
pub fn pinned_ncp_compatibility_artifact_bytes() -> Result<Vec<u8>, NcpCompatibilityError> {
    Ok(to_canonical_bytes(&NcpCompatibilityArtifactV1::pinned()?))
}

/// Strictly decode and exact-match one NCP compatibility artifact.
///
/// This validates only the supplied bytes. It does not prove that they occupied
/// the signed `NCP_COMPATIBILITY` deployment role, authenticate an artifact root,
/// identify the running binary, or select Gate startup.
///
/// # Errors
/// Returns [`NcpCompatibilityError`] for a bounded canonical decode failure, an
/// invalid compiled pin, or any exact baseline mismatch.
pub fn validate_ncp_compatibility_artifact(
    bytes: &[u8],
) -> Result<ValidatedNcpCompatibilityArtifact, NcpCompatibilityError> {
    let artifact = from_canonical_bytes::<NcpCompatibilityArtifactV1>(
        bytes,
        NCP_COMPATIBILITY_ARTIFACT_LIMITS,
    )?;
    if artifact != NcpCompatibilityArtifactV1::pinned()? {
        return Err(NcpCompatibilityError::PinMismatch);
    }
    Ok(ValidatedNcpCompatibilityArtifact {
        artifact,
        compatibility_id: NCP_V0_8_0.compatibility_id(),
    })
}

fn pinned_ascii<const N: usize>(value: &str) -> Result<AsciiId<N>, NcpCompatibilityError> {
    AsciiId::new(value).map_err(|_| NcpCompatibilityError::CompiledPinInvalid)
}

fn decode_sha256(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 {
        return None;
    }
    let mut decoded = [0u8; 32];
    for (slot, pair) in decoded.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        let [high, low]: [u8; 2] = pair.try_into().ok()?;
        *slot = (hex_nibble(high)? << 4) | hex_nibble(low)?;
    }
    Some(decoded)
}

const fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use core::fmt::Write;

    use proptest::prelude::*;

    fn hex(bytes: &[u8]) -> String {
        let mut encoded = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            write!(&mut encoded, "{byte:02x}").unwrap();
        }
        encoded
    }

    #[test]
    fn pinned_artifact_roundtrips_and_returns_a_validation_proof() {
        let expected = NcpCompatibilityArtifactV1::pinned().unwrap();
        let bytes = pinned_ncp_compatibility_artifact_bytes().unwrap();
        assert!(bytes.len() <= NCP_COMPATIBILITY_ARTIFACT_MAX_BYTES);

        let validated = validate_ncp_compatibility_artifact(&bytes).unwrap();
        assert_eq!(validated.artifact(), &expected);
        assert_eq!(validated.compatibility_id(), NCP_V0_8_0.compatibility_id());
        assert_eq!(to_canonical_bytes(validated.artifact()), bytes);
    }

    #[test]
    fn canonical_artifact_and_compatibility_id_have_golden_vectors() {
        let bytes = pinned_ncp_compatibility_artifact_bytes().unwrap();
        assert_eq!(
            hex(&bytes),
            concat!(
                "ad01781868616c6469722e6e63705f636f6d7061746962696c6974790201030004667630",
                "2e382e30057828326635626435383664346262323063393033363262623666353639386237",
                "663634303537626134650663302e380770643162353061326438613236353237360858206f",
                "13b12cff76e12fef384f691d11e2944db1f676568c3e780d3f975689131227095820abd9",
                "743323e4f6eabdbc27888704462b1b1fd128777422b35146605709a013440a58203e3d73",
                "235fe2dd4288158c29f9cd2f3f17034f7a58d803682f45c145a9733f2e0b010c765052",
                "455f415554484f524954595f41434c5f4f4e4c590d72302e312e302d6578706572696d",
                "656e74616c"
            )
        );
        assert_eq!(
            hex(&NCP_V0_8_0.compatibility_id().value),
            "7598422f3c123c52dcd79b97ee77f92d1467116edf7bb0e9f403bc9953f5300e"
        );
    }

    #[test]
    fn every_compiled_pin_participates_in_artifact_acceptance() {
        let expected = NcpCompatibilityArtifactV1::pinned().unwrap();
        let mut substitutions = Vec::new();

        let mut artifact = expected.clone();
        artifact.ncp_tag = AsciiId::new("v0.8.1").unwrap();
        substitutions.push(artifact);

        let mut artifact = expected.clone();
        artifact.ncp_commit = AsciiId::new("3f5bd586d4bb20c90362bb6f5698b7f64057ba4e").unwrap();
        substitutions.push(artifact);

        let mut artifact = expected.clone();
        artifact.wire_version = AsciiId::new("0.9").unwrap();
        substitutions.push(artifact);

        let mut artifact = expected.clone();
        artifact.contract_hash = AsciiId::new("e1b50a2d8a265276").unwrap();
        substitutions.push(artifact);

        let mut artifact = expected.clone();
        artifact.proto_sha256[0] ^= 1;
        substitutions.push(artifact);

        let mut artifact = expected.clone();
        artifact.command_schema_sha256[0] ^= 1;
        substitutions.push(artifact);

        let mut artifact = expected.clone();
        artifact.command_vector_sha256[0] ^= 1;
        substitutions.push(artifact);

        let mut artifact = expected.clone();
        artifact.enabled_increment = 2;
        substitutions.push(artifact);

        let mut artifact = expected.clone();
        artifact.capability_profile = AsciiId::new("AUTHORITY_INCREMENT_2").unwrap();
        substitutions.push(artifact);

        let mut artifact = expected;
        artifact.haldir_adapter_version = AsciiId::new("0.1.1-experimental").unwrap();
        substitutions.push(artifact);

        for substitution in substitutions {
            assert_eq!(
                validate_ncp_compatibility_artifact(&to_canonical_bytes(&substitution)),
                Err(NcpCompatibilityError::PinMismatch)
            );
        }
    }

    #[test]
    fn schema_version_must_be_exactly_v1_0() {
        let mut artifact = NcpCompatibilityArtifactV1::pinned().unwrap();
        artifact.schema_major = 2;
        assert_eq!(
            validate_ncp_compatibility_artifact(&to_canonical_bytes(&artifact)),
            Err(NcpCompatibilityError::Decode(
                DecodeError::UnsupportedVersion
            ))
        );

        let mut artifact = NcpCompatibilityArtifactV1::pinned().unwrap();
        artifact.schema_minor = 1;
        assert_eq!(
            validate_ncp_compatibility_artifact(&to_canonical_bytes(&artifact)),
            Err(NcpCompatibilityError::Decode(
                DecodeError::UnsupportedVersion
            ))
        );
    }

    #[test]
    fn parser_rejects_wrong_kind_missing_unknown_duplicate_and_reordered_fields() {
        let canonical = pinned_ncp_compatibility_artifact_bytes().unwrap();

        let mut wrong_kind = canonical.clone();
        let kind_offset = wrong_kind
            .windows(NcpCompatibilityArtifactV1::KIND.len())
            .position(|window| window == NcpCompatibilityArtifactV1::KIND.as_bytes())
            .unwrap();
        wrong_kind[kind_offset] = b'H';
        assert_eq!(
            validate_ncp_compatibility_artifact(&wrong_kind),
            Err(NcpCompatibilityError::Decode(DecodeError::WrongMessageKind))
        );

        let mut unknown = canonical.clone();
        assert_eq!(unknown[0], 0xad);
        unknown[0] = 0xae;
        unknown.extend_from_slice(&[0x0e, 0x00]);
        assert_eq!(
            validate_ncp_compatibility_artifact(&unknown),
            Err(NcpCompatibilityError::Decode(DecodeError::UnknownField {
                key: 14
            }))
        );

        let mut missing = canonical.clone();
        let adapter_version_offset = missing
            .windows(NCP_V0_8_0.haldir_adapter_version.len())
            .position(|window| window == NCP_V0_8_0.haldir_adapter_version.as_bytes())
            .unwrap();
        missing.truncate(adapter_version_offset - 2);
        missing[0] = 0xac;
        assert_eq!(
            validate_ncp_compatibility_artifact(&missing),
            Err(NcpCompatibilityError::Decode(DecodeError::MissingField {
                key: 13
            }))
        );

        let mut duplicate = canonical.clone();
        duplicate[0] = 0xae;
        duplicate.extend_from_slice(&[0x0d, 0x61, b'x']);
        assert_eq!(
            validate_ncp_compatibility_artifact(&duplicate),
            Err(NcpCompatibilityError::Decode(
                DecodeError::NonCanonicalMapOrder
            ))
        );

        let mut reordered = canonical;
        reordered[0] = 0xae;
        reordered.extend_from_slice(&[0x0c, 0x61, b'x']);
        assert_eq!(
            validate_ncp_compatibility_artifact(&reordered),
            Err(NcpCompatibilityError::Decode(
                DecodeError::NonCanonicalMapOrder
            ))
        );
    }

    #[test]
    fn parser_rejects_nonshortest_indefinite_trailing_and_resource_excess() {
        let canonical = pinned_ncp_compatibility_artifact_bytes().unwrap();

        let mut nonshortest = vec![0xb8, 0x0d];
        nonshortest.extend_from_slice(&canonical[1..]);
        assert_eq!(
            validate_ncp_compatibility_artifact(&nonshortest),
            Err(NcpCompatibilityError::Decode(DecodeError::NonShortestInt))
        );

        let mut indefinite = canonical.clone();
        indefinite[0] = 0xbf;
        assert_eq!(
            validate_ncp_compatibility_artifact(&indefinite),
            Err(NcpCompatibilityError::Decode(DecodeError::IndefiniteLength))
        );

        let mut trailing = canonical.clone();
        trailing.push(0);
        assert_eq!(
            validate_ncp_compatibility_artifact(&trailing),
            Err(NcpCompatibilityError::Decode(DecodeError::TrailingBytes))
        );

        let oversize = vec![0; NCP_COMPATIBILITY_ARTIFACT_MAX_BYTES + 1];
        assert_eq!(
            validate_ncp_compatibility_artifact(&oversize),
            Err(NcpCompatibilityError::Decode(DecodeError::ByteLenExceeded))
        );

        let mut too_many_pairs = canonical.clone();
        too_many_pairs[0] = 0xb1;
        assert_eq!(
            validate_ncp_compatibility_artifact(&too_many_pairs),
            Err(NcpCompatibilityError::Decode(DecodeError::MapPairsExceeded))
        );

        let mut oversized_text = CborWriter::new();
        oversized_text.map_header(1);
        oversized_text.uint(1);
        oversized_text.text(&"x".repeat(65));
        assert_eq!(
            validate_ncp_compatibility_artifact(&oversized_text.into_bytes()),
            Err(NcpCompatibilityError::Decode(DecodeError::TextLenExceeded))
        );
    }

    #[test]
    fn parser_rejects_digest_integer_and_cbor_type_boundaries() {
        let expected = NcpCompatibilityArtifactV1::pinned().unwrap();
        let canonical = pinned_ncp_compatibility_artifact_bytes().unwrap();

        let proto_offset = canonical
            .windows(expected.proto_sha256.len())
            .position(|window| window == expected.proto_sha256)
            .unwrap();
        assert_eq!(&canonical[proto_offset - 2..proto_offset], &[0x58, 0x20]);
        let mut oversized_digest = canonical.clone();
        oversized_digest[proto_offset - 1] = 0x21;
        oversized_digest.insert(proto_offset + expected.proto_sha256.len(), 0);
        assert_eq!(
            validate_ncp_compatibility_artifact(&oversized_digest),
            Err(NcpCompatibilityError::Decode(DecodeError::ByteLenExceeded))
        );

        let vector_offset = canonical
            .windows(expected.command_vector_sha256.len())
            .position(|window| window == expected.command_vector_sha256)
            .unwrap();
        let increment_key_offset = vector_offset + expected.command_vector_sha256.len();
        assert_eq!(
            &canonical[increment_key_offset..increment_key_offset + 2],
            &[0x0b, 0x01]
        );
        let mut oversized_increment = canonical.clone();
        oversized_increment.splice(
            increment_key_offset + 1..increment_key_offset + 2,
            [0x1a, 0x00, 0x01, 0x00, 0x00],
        );
        assert_eq!(
            validate_ncp_compatibility_artifact(&oversized_increment),
            Err(NcpCompatibilityError::Decode(DecodeError::IntOutOfRange))
        );

        let mut wrong_root_type = canonical.clone();
        wrong_root_type[0] = 0x8d;
        assert_eq!(
            validate_ncp_compatibility_artifact(&wrong_root_type),
            Err(NcpCompatibilityError::Decode(
                DecodeError::UnexpectedMajorType {
                    expected: 5,
                    found: 4,
                }
            ))
        );

        let mut tagged = canonical.clone();
        tagged[0] = 0xc0;
        assert_eq!(
            validate_ncp_compatibility_artifact(&tagged),
            Err(NcpCompatibilityError::Decode(DecodeError::TagNotAllowed))
        );

        let mut floating = canonical.clone();
        floating[0] = 0xf9;
        assert_eq!(
            validate_ncp_compatibility_artifact(&floating),
            Err(NcpCompatibilityError::Decode(DecodeError::FloatNotAllowed))
        );

        let mut non_unsigned_key = canonical;
        non_unsigned_key[1] = 0x61;
        assert_eq!(
            validate_ncp_compatibility_artifact(&non_unsigned_key),
            Err(NcpCompatibilityError::Decode(
                DecodeError::MapKeyNotUnsigned
            ))
        );
    }

    #[test]
    fn compatibility_id_binds_every_compiled_field() {
        let baseline = NCP_V0_8_0;
        let substitutions = [
            NcpCompatibilityRecordV1 {
                ncp_tag: "v0.8.1",
                ..baseline
            },
            NcpCompatibilityRecordV1 {
                ncp_commit: "3f5bd586d4bb20c90362bb6f5698b7f64057ba4e",
                ..baseline
            },
            NcpCompatibilityRecordV1 {
                wire_version: "0.9",
                ..baseline
            },
            NcpCompatibilityRecordV1 {
                contract_hash: "e1b50a2d8a265276",
                ..baseline
            },
            NcpCompatibilityRecordV1 {
                proto_sha256: "7f13b12cff76e12fef384f691d11e2944db1f676568c3e780d3f975689131227",
                ..baseline
            },
            NcpCompatibilityRecordV1 {
                command_schema_sha256: "bbd9743323e4f6eabdbc27888704462b1b1fd128777422b35146605709a01344",
                ..baseline
            },
            NcpCompatibilityRecordV1 {
                command_vector_sha256: "4e3d73235fe2dd4288158c29f9cd2f3f17034f7a58d803682f45c145a9733f2e",
                ..baseline
            },
            NcpCompatibilityRecordV1 {
                enabled_increment: 2,
                ..baseline
            },
            NcpCompatibilityRecordV1 {
                capability_profile: "AUTHORITY_INCREMENT_2",
                ..baseline
            },
            NcpCompatibilityRecordV1 {
                haldir_adapter_version: "0.1.1-experimental",
                ..baseline
            },
        ];
        for substitution in substitutions {
            assert_ne!(substitution.compatibility_id(), baseline.compatibility_id());
        }
    }

    #[test]
    fn every_error_class_displays_its_stable_reason_code() {
        let cases = [
            (
                NcpCompatibilityError::Decode(DecodeError::UnexpectedEof),
                "DECODE_EOF",
            ),
            (
                NcpCompatibilityError::CompiledPinInvalid,
                "NCP_COMPATIBILITY_COMPILED_PIN_INVALID",
            ),
            (
                NcpCompatibilityError::PinMismatch,
                "NCP_COMPATIBILITY_PIN_MISMATCH",
            ),
        ];
        for (error, expected) in cases {
            assert_eq!(error.reason_code(), expected);
            assert_eq!(error.to_string(), expected);
        }
    }

    proptest! {
        #[test]
        fn arbitrary_artifact_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..1024)) {
            let _ = validate_ncp_compatibility_artifact(&bytes);
        }
    }
}
