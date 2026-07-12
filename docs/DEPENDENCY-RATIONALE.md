# Dependency rationale

The command hot path is Rust, bounded, local, and independent of neural runtimes,
web UIs, databases, and dynamic-plugin loaders. Every external dependency is
pinned in `Cargo.lock` and justified here. All are available offline in the
reviewed cache; a dependency change on the hot path is a security-relevant review,
not a routine bump.

| Crate | Version | Why | Where |
| --- | --- | --- | --- |
| `ed25519-compact` | 2.2 | Small, self-contained, deterministic Ed25519 (RFC 8032) with minimal transitive deps; no `getrandom`-in-verify surprises. Used for the application-signature profile. | `haldir-crypto` |
| `sha2` | 0.10 | Vetted SHA-256 (RFC 6234) for domain-separated digests. | `haldir-contracts` (digests) |
| `zeroize` | 1 | Zeroize the signing-key seed buffer. | `haldir-crypto` |
| `subtle` | 2 | Constant-time primitives (available for comparison paths). | `haldir-contracts` |
| `getrandom` | 0.2 | OS CSPRNG for boot ids / nonces / epochs (used by the runtime, not the pure policy). | `haldir-crypto`, `haldir-state` |
| `proptest` | 1 | Property tests (dev-dependency only). | several crates |
| `ncp-core` | 0.8.0 at `2f5bd586…` | Normative upstream NCP wire types and validation for the off-by-default exact conformance adapter. The immutable git source is checked against `tools/pins.toml` and `.ncp-consumer`. | `haldir-ncp08` `real-ncp` feature only |
| `serde_json` | 1.0 (locked) | Serialize and decode the upstream NCP JSON frame in the exact conformance adapter; never used in signed Haldir contracts or policy. | `haldir-ncp08` `real-ncp` feature only |

The transitive `unicode-ident` build dependency uses the OSI-approved
`Unicode-3.0` data license in addition to MIT/Apache-2.0; `deny.toml` admits that
license explicitly. Git sources remain denied by default, with only the exact NCP
repository allowed and `rev` required; `tools/verify-pins.py` separately enforces
the full immutable commit in both manifest and lockfile.

## Deliberately absent

- **No general CBOR library on the trusted path.** The canonical codec is
  hand-written (`haldir-contracts/src/cbor.rs`) because the profile enforces rules
  generic decoders do not (shortest ints, ascending integer keys, no floats/tags/
  indefinite, one top-level item, re-encode equality).
- **No `serde`/`serde_json` in signed Haldir contracts or policy**, no `HashMap`
  where iteration feeds a digest or decision. `serde_json` exists only in the
  opt-in exact NCP boundary.
- **No async runtime, Zenoh, Python/PyO3, or neural runtime** in the pure core.
  The NCP crate exists only behind the `real-ncp` adapter feature.
- **No floating point in signed authority/policy/replay/action contracts.** Floats
  appear only at the modeled/exact NCP wire boundary, with an error-bounded
  conversion.
