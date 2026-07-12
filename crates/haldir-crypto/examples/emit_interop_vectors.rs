//! Emit `COSE_Sign1` interop vectors for the independent verifier.
//!
//! Each vector is a deterministic canonical-CBOR payload (crafted to exercise
//! every wire major type and integer width Haldir uses) signed with a fixed seed
//! key, so `tools/interop/verify_cose.py` can independently decode and verify it.
//! Regenerate with:
//!
//! ```text
//! cargo run -p haldir-crypto --example emit_interop_vectors > tools/interop/vectors.json
//! ```
//!
//! The output is deterministic; a diff means the wire format changed.
#![allow(clippy::expect_used)] // a developer-run vector emitter, not shipped code

use haldir_contracts::cbor::CborWriter;
use haldir_contracts::ids::KeyId;
use haldir_crypto::cose::sign_sign1;
use haldir_crypto::{SigningKey, content_type_for, external_aad_for};

struct Vector {
    name: &'static str,
    kind: &'static str,
    major: u16,
    payload: Vec<u8>,
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn vectors() -> Vec<Vector> {
    // (1) scalars: uint, negative int, byte string, and a UTF-8 text string.
    let mut w = CborWriter::new();
    w.map_header(4);
    w.uint(1);
    w.uint(42);
    w.uint(2);
    w.int(-7);
    w.uint(3);
    w.bytes(&[0xDE, 0xAD, 0xBE, 0xEF]);
    w.uint(4);
    w.text("haldir");
    let scalars = w.into_bytes();

    // (2) nesting: an array holding an array and a map with a byte-string value.
    let mut w = CborWriter::new();
    w.array_header(3);
    w.uint(1);
    w.array_header(2);
    w.uint(2);
    w.uint(3);
    w.map_header(1);
    w.uint(9);
    w.bytes(&[1, 2, 3]);
    let nested = w.into_bytes();

    // (3) integer widths: 1-, 2-, 4-, and 8-byte unsigned heads (shortest-form).
    let mut w = CborWriter::new();
    w.map_header(4);
    w.uint(1);
    w.uint(23);
    w.uint(2);
    w.uint(300);
    w.uint(3);
    w.uint(1_000_000);
    w.uint(4);
    w.uint(4_294_967_296);
    let wide_ints = w.into_bytes();

    // (4) booleans and an empty container (major-7 simples + zero-length array).
    let mut w = CborWriter::new();
    w.array_header(3);
    w.bool(true);
    w.bool(false);
    w.array_header(0);
    let bools = w.into_bytes();

    vec![
        Vector {
            name: "scalars",
            kind: "haldir.interop.scalars",
            major: 1,
            payload: scalars,
        },
        Vector {
            name: "nested",
            kind: "haldir.interop.nested",
            major: 1,
            payload: nested,
        },
        Vector {
            name: "wide-ints",
            kind: "haldir.interop.wideints",
            major: 1,
            payload: wide_ints,
        },
        Vector {
            name: "bools",
            kind: "haldir.interop.bools",
            major: 1,
            payload: bools,
        },
    ]
}

fn main() {
    // A fixed seed makes the whole document reproducible byte-for-byte.
    let sk = SigningKey::from_seed([7u8; 32]);
    let pk_hex = hex(&sk.verifying_key().to_bytes());
    let kid = KeyId::new(vec![0x01, 0x02, 0x03]).expect("kid");

    let mut items: Vec<String> = Vec::new();
    for v in vectors() {
        let content_type = content_type_for(v.kind);
        let aad = external_aad_for(v.kind, v.major);
        let cose = sign_sign1(&v.payload, &kid, &content_type, &aad, &sk);
        items.push(format!(
            concat!(
                "    {{\n",
                "      \"name\": \"{name}\",\n",
                "      \"kind\": \"{kind}\",\n",
                "      \"schema_major\": {major},\n",
                "      \"content_type\": \"{ct}\",\n",
                "      \"public_key_hex\": \"{pk}\",\n",
                "      \"payload_hex\": \"{payload}\",\n",
                "      \"cose_hex\": \"{cose}\"\n",
                "    }}"
            ),
            name = v.name,
            kind = v.kind,
            major = v.major,
            ct = content_type,
            pk = pk_hex,
            payload = hex(&v.payload),
            cose = hex(&cose),
        ));
    }

    println!(
        concat!(
            "{{\n",
            "  \"profile\": \"assurance-reference-v1\",\n",
            "  \"note\": \"COSE_Sign1/Ed25519 over deterministic CBOR; ",
            "regenerate with cargo run -p haldir-crypto --example emit_interop_vectors\",\n",
            "  \"vectors\": [\n{items}\n  ]\n",
            "}}"
        ),
        items = items.join(",\n"),
    );
}
