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
exceptions forced by Zenoh 1.9.0.

Zenoh 1.9.0 unconditionally depends on affected `lz4_flex` 0.10.0, so
`RUSTSEC-2026-0041` and the corresponding GitHub alert are valid and must remain
open. The default Haldir graph does not include Zenoh. The all-feature live
client graph compiles `lz4_flex`, but compiles out Zenoh's sole affected
block-decompression call site because `transport_compression` is absent.
`tools/verify-pins.py` inspects the resolved all-feature graph and rejects any
compression feature or non-TLS Zenoh transport, preventing another dependency
from silently making that network-fed path reachable. Enabling compression is
forbidden until a reviewed Zenoh baseline selects a fixed LZ4 implementation.
The exception is a temporary, scoped risk acceptance, not a false positive.

The pinned stock router image is a separate boundary: upstream `zenohd` defaults
include `transport_compression`, and no image build-feature attestation proves
that the pinned image excludes it. Treat its affected decoder as likely compiled
in but dormant. The retained effective configuration disables unicast and
multicast compression, making the path unreachable under that exact profile,
but configuration is not source-level remediation. A future trust-root
replacement must explicitly render and verify both flags as false instead of
relying on Zenoh 1.9 defaults.

`RUSTSEC-2024-0436` (`paste`) and `RUSTSEC-2025-0134` (`rustls-pemfile`) are
maintenance notices rather than reported vulnerabilities. The exceptions must
be removed when the pinned Zenoh baseline permits fixed transitives;
`cargo deny --all-features check` still rejects every new advisory.

## Supply-chain tooling boundary

`tools/pins.toml` records exact archive and executable sizes and SHA-256
identities for cargo-deny 0.20.2 on the admitted x86_64 Linux and arm64 macOS
hosts. It also binds one freshness-checked RustSec advisory-database snapshot by
upstream commit, Git tree, archive identity, reconstructed repository identity,
and bounded member inventory.
`tools/pinned_cargo_deny.py` accepts only separately fetched matching inputs. It
uses bounded decompression, validates the complete reviewed member set and entry
types, never extracts archive paths, writes into new destinations without
overwrite, reconstructs and verifies the exact RustSec Git repository, and
re-verifies the cargo-deny executable before an exact version check.
Its adversarial suite is executed by `tools/verify-pins.py`, so the protected
source-pin step covers both acquisition parsers and installers on every hosted
run.

Protected CI now downloads those bounded assets, verifies their exact sizes and
digests, installs them directly without the retired cargo-deny Docker Action,
and primes the locked Cargo inputs while network access is still available. The
authoritative audit then revalidates the executable, RustSec commit/tree, and
toolchain; drops privileges and ambient capabilities; enters a Linux network
namespace; and runs the exact cargo-deny binary with `--frozen --all-features`.
That final execution is frozen and network-isolated. Asset acquisition still
depends on upstream availability and the hosted runner's network path, so this
does not claim an availability-independent bootstrap, reproducible release, SBOM,
or end-to-end release provenance.

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

## Automated update proposals

`.github/dependabot.yml` keeps Dependabot security-update pull requests enabled
while disabling routine Cargo version-update pull requests. GitHub Actions
version updates are grouped into at most one monthly proposal after a 14-day
cooldown. This is discovery automation only: a bot pull request has no merge,
release, deployment, or audit authority. There is no auto-approval or auto-merge
path, no Dependabot registry credential, and no reason to expose an Actions
secret to dependency-update code.

GitHub runs the update-generation jobs on Actions runners even when repository
or organization Actions policy would otherwise disable them. That
GitHub-managed exception creates proposals only; it grants no merge, release,
deployment, or audit authority.

Do not merge a Dependabot commit directly. When the accepted paths are not
epoch-18 protected, reproduce the reviewed diff in a single-parent maintainer
commit signed by the allowed release principal; the audit chain rejects a
post-activation commit with another identity or signature. A proposal touching a
protected path instead requires an intentional signed gate and trust-root
replacement.

Cargo proposals are lockfile-only and may include transitive crates. A maintainer
must review the upstream source, changelog, resolved graph, licenses, and
advisories, then require every protected check. Manifest constraints and exact
NCP, Zenoh, rustix, Rust toolchain, downloaded-tool, RustSec, TLA+/Java, GitHub
CLI, container-image, and policy pins remain coordinated manual changes.

`Cargo.lock` legitimately contains parallel incompatible `getrandom` 0.2, 0.3,
and 0.4 lines. A hosted Cargo updater reproducibly tried to replace the 0.2 line
with the already-present 0.4 line, produced no lockfile change, and failed the
whole update job. Incompatible-line migrations require a reviewed manifest
change or an update to the parent crate that owns the requirement. Routine
Cargo version proposals stay disabled; maintainers can still perform deliberate
signed lockfile updates, and Dependabot security updates remain enabled.

Actions proposals must retain a full 40-hex commit SHA and its same-line release
comment. Reviewers must authenticate the upstream repository, tag, and commit,
then deliberately update the exact pin constants, tests, and protected job
hashes. The workflows and their pin-verification boundary are epoch-18 protected,
so an accepted Actions update cannot land as an ordinary successor: it requires
the intentional signed recovery process and a new gate/trust root. A proposal
that initially fails `tools/verify-ci-pins.py` is a review prompt, not permission
to relax that verifier. Pull-request workflows must keep read-only permissions
and `persist-credentials: false`; OIDC attesters remain limited to pushes on
`main`, and dependency code must never be moved to `pull_request_target`.

Dependabot alerts do not cover vulnerable Actions pinned by SHA. A grouped,
monthly update proposal and independent upstream-advisory monitoring are
therefore complementary; neither proves that a proposed commit is safe. The
one-open-PR limit applies only to version updates, so it does not delay
security-update pull requests.

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
