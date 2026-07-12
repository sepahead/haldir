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

## Deliberately absent

- **No general CBOR library on the trusted path.** The canonical codec is
  hand-written (`haldir-contracts/src/cbor.rs`) because the profile enforces rules
  generic decoders do not (shortest ints, ascending integer keys, no floats/tags/
  indefinite, one top-level item, re-encode equality).
- **No `serde`/`serde_json` on the trusted path**, no `HashMap` where iteration
  feeds a digest or decision (deterministic `BTreeMap`/sorted vectors only).
- **No async runtime, no Zenoh, no NCP crate, no Python/PyO3, no neural runtime**
  in the pure core. These belong to future profiles (P1+) behind versioned seams.
- **No floating point in signed authority/policy/replay/action contracts.** Floats
  appear only in the modeled NCP wire value inside `haldir-ncp08`, with an
  error-bounded conversion.
