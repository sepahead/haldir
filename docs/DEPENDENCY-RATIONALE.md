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
| `ncp-core` | 0.8.0 at `2f5bd586…` | Normative upstream NCP key construction is always used by `haldir-transport-zenoh`; normative wire types/validation are also used by the off-by-default exact conformance adapter. Gate's `real-ncp` feature explicitly forwards that capability; Cargo feature unification may also compile the exact constructor but cannot change Gate's stored closed selection. The immutable git source is checked against `tools/pins.toml` and `.ncp-consumer`. | `haldir-transport-zenoh`; `haldir-ncp08` / `haldir-gate` `real-ncp` features |
| `serde_json` | 1.0 (locked) | Serialize/decode the upstream NCP JSON frame in the exact conformance adapter, inspect effective Zenoh configuration values in the off-by-default live boundary, and emit bounded result files from the explicitly development-only Gate smoke examples; never used in signed Haldir contracts or policy. | `haldir-ncp08` `real-ncp`; `haldir-transport-zenoh` `live-zenoh`; `haldir-gate` `live-gate-dev-smoke` |
| `hmac` | 0.12.1 | RustCrypto HMAC with constant-time `verify_slice`, paired with the existing SHA-256 0.10 stack for separately keyed authenticated durable snapshots. Version 0.13 targets the newer digest/SHA-2 generation, so 0.12.1 avoids duplicating the cryptographic hash stack. | `haldir-durable` |
| `tokio` | 1 (locked) | Bounded MPSC handoff from Zenoh's callback into the future single-owner Gate runtime. The workspace dependency has default features disabled and enables `sync`; the separate `live-gate-dev-smoke` feature adds only `rt` so its one-shot example can drive bind/shutdown. | `haldir-transport-zenoh` `live-zenoh`; forwarded by `haldir-gate` `live-zenoh`; `haldir-gate` `live-gate-dev-smoke` |
| `zenoh` | exactly 1.9.0 | Pinned NCP-v0.8 transport baseline for the off-by-default strict mTLS client, exact-route subscriber, and typed final-command publisher. Default features are disabled and `transport_tls` is the sole admitted transport feature; plaintext, discovery, listeners, shared memory, compression, and generic publication are excluded by configuration/API/profile checks. Gate's identically named feature consumes only the typed publisher/result boundary. | `haldir-transport-zenoh` `live-zenoh`; forwarded by `haldir-gate` `live-zenoh` |

The transitive `unicode-ident` build dependency uses the OSI-approved
`Unicode-3.0` data license in addition to MIT/Apache-2.0; `deny.toml` admits that
license explicitly. Git sources remain denied by default, with only the exact NCP
repository allowed and `rev` required; `tools/verify-pins.py` separately enforces
the full immutable commit in both manifest and lockfile.

The Zenoh 1.9 TLS graph adds reviewed BSD-2-Clause, ISC, Zlib, MPL-2.0, and
CDLA-Permissive-2.0 licenses; `deny.toml` remains default-deny and admits exactly
the current reviewed lockfile set. It also names three exact transitive RustSec
exceptions forced by Zenoh 1.9.0: `RUSTSEC-2026-0041` is in LZ4 block
decompression compiled only by the disabled `transport_compression` feature,
while `RUSTSEC-2024-0436` (`paste`) and `RUSTSEC-2025-0134`
(`rustls-pemfile`) are maintenance notices rather than reported vulnerabilities.
The exceptions must be removed when the pinned Zenoh baseline permits fixed
transitives; `cargo deny --all-features check` still rejects every new advisory.
`tools/verify-pins.py` also inspects the resolved all-feature Cargo graph so a
second dependency cannot silently feature-unify Zenoh compression or another
transport back on while the LZ4 exception exists.

Zenoh 1.9's TLS client unconditionally combines public WebPKI roots with the
configured custom CA; it has no exclusive-custom-root setting. The reference
profile therefore uses a reserved `.invalid` router hostname and never claims
exclusive server trust from the stock library. A production assurance profile
needs a patched/upgraded Zenoh or a client API that accepts a pinned Rustls
verifier. Zenoh 1.9 also carries its plugin trait and `libloading` even with
default features disabled. Haldir's strict client rejects plugins/plugin loading,
and the pinned router launch re-disables the daemon's forced loader after config
load, but the transitive code remains in the binary graph until Zenoh provides a
plugin-free client feature.

## Deliberately absent

- **No general CBOR library on the trusted path.** The canonical codec is
  hand-written (`haldir-contracts/src/cbor.rs`) because the profile enforces rules
  generic decoders do not (shortest ints, ascending integer keys, no floats/tags/
  indefinite, one top-level item, re-encode equality).
- **No `serde`/`serde_json` in signed Haldir contracts or policy**, no `HashMap`
  where iteration feeds a digest or decision. `serde_json` exists only in the
  opt-in exact NCP/live-configuration boundaries and the development smoke's
  bounded result reporting.
- **No async runtime, Zenoh, Python/PyO3, or neural runtime in the default pure core.**
  Tokio/Zenoh implementation remains in `haldir-transport-zenoh`'s off-by-default
  `live-zenoh` feature. Gate's off-by-default feature forwards it and contains the
  startup-capability-marked consuming concrete publisher/result binding plus a single-owner
  async service façade; the library adds no Gate-owned async runtime, channel, timer, or worker.
  The stricter development smoke feature owns a current-thread executor only long enough to open,
  bind, and explicitly shut down without processing an event. The always-on
  transport route builder uses only pinned `ncp-core`; Gate policy/state/contracts remain
  independent of both.
- **No floating point in signed authority/policy/replay/action contracts.** Floats
  appear only at the modeled/exact NCP wire boundary, with an error-bounded
  conversion.
