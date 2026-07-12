//! Embedded-payload `COSE_Sign1` over Ed25519, Haldir profile.
//!
//! Binding rules (punch-list B7/H9):
//! * `alg`, `kid`, and `content_type` are in the **protected** header; the
//!   unprotected bucket MUST be empty.
//! * `alg` MUST be EdDSA (`-8`); no message-supplied algorithm dispatch.
//! * `kid` resolves to exactly one trusted key — no fallback key search.
//! * the external AAD and the expected `content_type` are reconstructed from the
//!   verifier's dispatch context (kind + major version), never from the payload's
//!   self-declared kind, and the AAD encodes the major version.
//! * the signature is verified over the exact received payload bytes; canonical
//!   re-encoding equality is enforced afterwards by the payload decoder.

use crate::error::CryptoError;
use crate::key::{Signature, SigningKey};
use crate::role::{KeyClass, KeyRole};
use crate::trust::{RevocationSnapshot, TrustStore};
use haldir_contracts::cbor::{CborReader, CborWriter, Limits};
use haldir_contracts::ids::KeyId;

const ALG_EDDSA: i128 = -8;
const HDR_ALG: u64 = 1;
const HDR_CONTENT_TYPE: u64 = 3;
const HDR_KID: u64 = 4;

/// The content-type string for a message kind, e.g. `application/haldir-intent+cbor`.
#[must_use]
pub fn content_type_for(kind: &str) -> String {
    format!("application/{}+cbor", kind.replace('.', "-"))
}

/// The external AAD for a message kind at a major version, e.g. `haldir.intent.v1`.
#[must_use]
pub fn external_aad_for(kind: &str, schema_major: u16) -> Vec<u8> {
    format!("{kind}.v{schema_major}").into_bytes()
}

/// The verifier's dispatch context. Content-type and AAD are derived from these
/// fields, never from the payload.
#[derive(Debug, Clone, Copy)]
pub struct ExpectedContext<'a> {
    /// Expected message kind (must equal the target type's `KIND`).
    pub kind: &'a str,
    /// Expected schema major version.
    pub schema_major: u16,
    /// The role the signing key must hold.
    pub required_role: KeyRole,
    /// Whether an assurance profile is in force (rejects development keys).
    pub assurance_profile: bool,
}

impl ExpectedContext<'_> {
    /// The content-type this context expects.
    #[must_use]
    pub fn content_type(&self) -> String {
        content_type_for(self.kind)
    }

    /// The external AAD this context expects.
    #[must_use]
    pub fn external_aad(&self) -> Vec<u8> {
        external_aad_for(self.kind, self.schema_major)
    }
}

/// The result of a successful verification: the exact payload bytes and signer id.
#[derive(Debug)]
pub struct VerifiedCose<'a> {
    /// Exact received payload bytes (still to be canonically decoded).
    pub payload: &'a [u8],
    /// The resolved signer key id.
    pub signer_kid: KeyId,
    /// The resolved signer role.
    pub signer_role: KeyRole,
    /// The resolved signer subject, where present.
    pub signer_subject: Option<String>,
}

fn encode_protected(content_type: &str, kid: &KeyId) -> Vec<u8> {
    let mut w = CborWriter::new();
    w.map_header(3);
    w.uint(HDR_ALG);
    w.int(-8);
    w.uint(HDR_CONTENT_TYPE);
    w.text(content_type);
    w.uint(HDR_KID);
    w.bytes(kid.as_bytes());
    w.into_bytes()
}

fn sig_structure(protected: &[u8], external_aad: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut w = CborWriter::new();
    w.array_header(4);
    w.text("Signature1");
    w.bytes(protected);
    w.bytes(external_aad);
    w.bytes(payload);
    w.into_bytes()
}

/// Sign `payload` as a `COSE_Sign1`, binding `content_type` and `external_aad`.
#[must_use]
pub fn sign_sign1(
    payload: &[u8],
    kid: &KeyId,
    content_type: &str,
    external_aad: &[u8],
    sk: &SigningKey,
) -> Vec<u8> {
    let protected = encode_protected(content_type, kid);
    let ss = sig_structure(&protected, external_aad, payload);
    let sig = sk.sign(&ss);
    let mut w = CborWriter::new();
    w.array_header(4);
    w.bytes(&protected);
    w.map_header(0);
    w.bytes(payload);
    w.bytes(&sig.to_bytes());
    w.into_bytes()
}

struct ParsedSign1<'a> {
    protected: &'a [u8],
    payload: &'a [u8],
    signature: [u8; 64],
}

fn parse_sign1(env: &[u8]) -> Result<ParsedSign1<'_>, CryptoError> {
    let mut r = CborReader::new(env, Limits::LARGE);
    let n = r.read_array_len().map_err(|_| CryptoError::Malformed)?;
    if n != 4 {
        return Err(CryptoError::Malformed);
    }
    let protected = r.read_bytes().map_err(|_| CryptoError::Malformed)?;
    let un = r.read_map_len().map_err(|_| CryptoError::Malformed)?;
    if un != 0 {
        return Err(CryptoError::UnprotectedSecurityHeader);
    }
    r.end_container();
    let payload = r.read_bytes().map_err(|_| CryptoError::Malformed)?;
    let sig_bytes = r.read_bytes().map_err(|_| CryptoError::Malformed)?;
    r.end_container();
    r.finish().map_err(|_| CryptoError::Malformed)?;
    let signature: [u8; 64] = sig_bytes.try_into().map_err(|_| CryptoError::Malformed)?;
    Ok(ParsedSign1 {
        protected,
        payload,
        signature,
    })
}

fn parse_protected(bytes: &[u8]) -> Result<(String, KeyId), CryptoError> {
    let mut r = CborReader::new(bytes, Limits::DEFAULT);
    let n = r.read_map_len().map_err(|_| CryptoError::Malformed)?;
    let mut alg: Option<i128> = None;
    let mut content_type: Option<String> = None;
    let mut kid: Option<KeyId> = None;
    let mut last: Option<u64> = None;
    for _ in 0..n {
        let k = r.read_map_key().map_err(|_| CryptoError::Malformed)?;
        if let Some(p) = last
            && k <= p
        {
            return Err(CryptoError::Malformed);
        }
        last = Some(k);
        match k {
            HDR_ALG => alg = Some(r.read_int().map_err(|_| CryptoError::Malformed)?),
            HDR_CONTENT_TYPE => {
                content_type = Some(
                    r.read_text()
                        .map_err(|_| CryptoError::Malformed)?
                        .to_owned(),
                );
            }
            HDR_KID => {
                let b = r.read_bytes().map_err(|_| CryptoError::Malformed)?;
                kid = Some(KeyId::new(b.to_vec()).map_err(|_| CryptoError::Malformed)?);
            }
            _ => return Err(CryptoError::Malformed),
        }
    }
    r.end_container();
    r.finish().map_err(|_| CryptoError::Malformed)?;
    if alg.ok_or(CryptoError::UnsupportedAlgorithm)? != ALG_EDDSA {
        return Err(CryptoError::UnsupportedAlgorithm);
    }
    Ok((
        content_type.ok_or(CryptoError::Malformed)?,
        kid.ok_or(CryptoError::Malformed)?,
    ))
}

/// Verify a `COSE_Sign1` envelope against the dispatch context, trust store, and
/// revocation snapshot. Returns the exact payload bytes on success.
///
/// # Errors
/// Returns a [`CryptoError`] with a stable reason class on any structural,
/// binding, role, revocation, or signature failure.
pub fn verify_sign1<'a>(
    env: &'a [u8],
    ctx: &ExpectedContext,
    trust: &TrustStore,
    revocations: &RevocationSnapshot,
) -> Result<VerifiedCose<'a>, CryptoError> {
    let parsed = parse_sign1(env)?;
    let (content_type, kid) = parse_protected(parsed.protected)?;
    if content_type != ctx.content_type() {
        return Err(CryptoError::ContentTypeMismatch);
    }
    let rec = trust.resolve(&kid).ok_or(CryptoError::KidUnknown)?;
    if rec.role != ctx.required_role {
        return Err(CryptoError::WrongRole);
    }
    if ctx.assurance_profile && rec.class == KeyClass::Development {
        return Err(CryptoError::DevelopmentKeyInAssurance);
    }
    if revocations.is_key_revoked(&kid) {
        return Err(CryptoError::KeyRevoked);
    }
    let aad = ctx.external_aad();
    let ss = sig_structure(parsed.protected, &aad, parsed.payload);
    let sig = Signature::from_bytes(parsed.signature);
    if !rec.verifying_key.verify(&ss, &sig) {
        return Err(CryptoError::SignatureInvalid);
    }
    Ok(VerifiedCose {
        payload: parsed.payload,
        signer_kid: kid,
        signer_role: rec.role,
        signer_subject: rec.subject.clone(),
    })
}
