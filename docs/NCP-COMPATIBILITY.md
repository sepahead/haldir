# NCP compatibility

Haldir's stable contracts contain semantic Haldir fields, not NCP-generated
structs. Only `haldir-ncp08` is aware of NCP wire semantics.

## Current provider boundary (checked 2026-08-10)

NCP repository `main` at
`1ffd3bf9a6c52d0279eb31a56e0664e4eec24d68` is the unreleased and
release-blocked `1.0.0-rc.1` candidate. Its wire is `1.0`, and its compact
`CONTRACT_HASH` is `163acc57d8a62b66`. Haldir's supported immutable baseline
remains the annotated `v0.8.0` tag, which uses a different wire. This document
calls it a tag/baseline rather than GitHub's “latest release”: the Releases API
currently identifies `v0.5.1`, while the newer protocol baselines are immutable
annotated tags.

Haldir remains on the exact immutable v0.8 baseline below. Native Haldir 1.0 migration
and independent qualification are **NOT RUN** and are not dependency-ready in the
NCP ecosystem task ledger. This provider-status note changes no dependency, runtime
behavior, task status, phase status, or claim evidence.

## Pinned baseline (exact commit)

| Field | Value |
| --- | --- |
| `ncp_tag` | `v0.8.0` |
| `ncp_commit` | `2f5bd586d4bb20c90362bb6f5698b7f64057ba4e` |
| `wire_version` | `0.8` |
| `contract_hash` | `d1b50a2d8a265276` |
| `proto_sha256` | `6f13b12cff76e12fef384f691d11e2944db1f676568c3e780d3f975689131227` (measured locally 2026-07-12) |
| `command_schema_sha256` | `abd9743323e4f6eabdbc27888704462b1b1fd128777422b35146605709a01344` |
| `command_vector_sha256` | `3e3d73235fe2dd4288158c29f9cd2f3f17034f7a58d803682f45c145a9733f2e` |
| `enabled_increment` | `1` |
| `capability_profile` | `PRE_AUTHORITY_ACL_ONLY` |
| `haldir_adapter_version` | compiled `haldir-ncp08` package version |

The pinned values through `capability_profile` are duplicated in
`crates/haldir-ncp08/src/compatibility.rs` (`NCP_V0_8_0`) and `tools/pins.toml`.
`haldir_adapter_version` instead derives from the compiled Cargo package version.
`tools/verify-pins.py` enforces both the duplicated values and that derivation.

The two command digests deliberately name Haldir's frozen command-frame schema/vector subset. They
are not aggregate identities for every file in NCP's schema and conformance sets. The normative
full-set manifest digests and reproducible Haldir adapter source/build identity remain open.

## Canonical compatibility artifact

`NcpCompatibilityArtifactV1` is the strict canonical CBOR syntax for the ordinary
`NCP_COMPATIBILITY` deployment artifact. It has fixed kind `haldir.ncp_compatibility`, exact schema
`1.0`, required fields for every pin above, raw 32-byte SHA-256 values, and a 512-byte whole-item
limit. The shared canonical decoder rejects unknown/missing/duplicate/reordered fields,
non-shortest or indefinite encodings, trailing bytes, and parser-limit excess. Structural decode is
not acceptance: `validate_ncp_compatibility_artifact` exact-matches every decoded field to the
compiled baseline before returning a private-field `ValidatedNcpCompatibilityArtifact` proof.
Golden vectors, one-field substitutions, hostile shapes, arbitrary bytes, and default/exact-adapter
identity agreement are tested (`CL-NCP-COMPATIBILITY-01`).

The standalone function validates whichever bytes its caller supplies. For deployment-package use,
`ResolvedDeploymentPackage::validate_ncp_compatibility` consumes the resolved package, selects the
exact signed `NcpCompatibility` role retained by that package, runs this validator, and returns the
private-field `NcpValidatedDeploymentPackage` composition proof. That stage therefore binds package
signature and acceptance policy, exact signed-role bytes, and every compiled compatibility pin. It
does not identify the running executable or source tree or validate the other signed artifact roles.
The next consuming deployment stage strictly validates the signed Gate configuration; a third
verifies four separately role-bound, public-key-distinct revision-scoped runtime-snapshot approvals under the same bootstrap
trust/revocation snapshots retained when the package was accepted. Package-bound Gate startup then
exact-matches its top-level and live authorization identities and commits the package revision/digest
with the boot. That still does not make the other seven artifact roles, the running executable, or
external acquisition trustworthy.

## Default P0 model, exact conformance adapter, and route boundary

The default `AclOnlyAdapter` models the NCP v0.8.0 command semantics without an
upstream or Zenoh dependency, keeping the pure P0 core dependency-light. The
off-by-default `real-ncp` feature adds `RealNcp08Adapter`, compiled from
`ncp-core` v0.8.0 at the exact commit above. It constructs the upstream
`CommandFrame`, runs `WireFrame::validate_wire`, serializes the exact compact
JSON bytes, and validates those bytes again with
`decode_validated::<CommandFrame>` before exposing them.

The frozen upstream command vector and schema live under
`crates/haldir-ncp08/tests/data/ncp-v0.8.0`; their SHA-256 values are recorded in
`tools/pins.toml` and checked by `tools/verify-pins.py`. Differential tests cover
Active/HOLD mapping, exact session/stream/source identity, JSON-safe sequence
boundaries, Crebain's `velocity_setpoint` vec3/`m/s` profile, and byte/digest/
transformation tampering. The stable `HaldirIntentV1` contracts do not depend on
the upstream type.

`frame_id` is copied from the independently validated trusted source state only
after native policy requires exact equality with the frame identifier committed
by the lease-bound schema-v2 policy digest. It is also part of the trusted-state
digest and is never hardcoded: NCP's safety governor requires the sensor and
command coordinate frames to agree, while Haldir must additionally prove that
the shared label is the configured local-NED interpretation. NCP has no field
for Haldir's trusted `source_key`, so that key remains evidence/cache metadata
while `source.{epoch,seq}` is carried on the NCP frame. Nanosecond Gate/source
times are projected to NCP binary64 seconds; at the full `u64` nanosecond range
the tested round-trip error bound is 2,048 ns, so this mapping is not byte
identity.

`haldir-transport-zenoh` always delegates standard command and named-sensor route
construction to this exact pinned `ncp-core`; its Haldir intent/evidence extensions
are bounded, fallible, and wildcard-free. The off-by-default `live-zenoh` feature
pins Zenoh exactly 1.9.0 with default features disabled and only `transport_tls`.
Its publisher accepts only `ExactNcpCommandFrame` and is permanently bound to the
standard base command route. The deterministic secure-reference package separately
pins the router image digest and a direction-specific default-deny ACL. The only ACL
wildcard is the reviewed pinned-NCP `{realm}/rpc/*` propagation declaration for
`declare_queryable`; query and reply grants remain the four exact NCP RPC routes, and
no Haldir extension route is widened.

`SelectedNcpCommandAdapter` is a closed forwarding adapter with no caller-defined
implementation seam or default constructor. `GateConfigTemplate` and `GateConfig` require an
explicit selection value: current P0 fixtures choose deterministic modeled bytes, while the
Gate `real-ncp` forwarding feature explicitly enables upstream-validated exact JSON. Cargo
feature unification can also compile that exact constructor, but never changes the stored
selection. Tests exercise both forwarding paths and carry an exact-selected actor output
through the Called boundary with its receipt digest intact. The strict
`FinalCommandPublisher` deliberately rejects modeled non-JSON bytes and accepts only
upstream-validated NCP JSON whose payload and retained exact-frame semantics match the
publisher's complete `(session_id, session.generation)` binding.

Template startup separately requires an explicit `GateRuntimeProfile`; it is not inferred
from the selected adapter or compiled Cargo features. `InProcessReference` preserves the P0
model and exact-conformance paths. `DeclaredLiveZenoh` requires both
`ExactNcpV0_8Json` and the compiled `live-zenoh` feature. In particular, compiling only
`real-ncp` makes the exact constructor available but cannot satisfy the declared-live feature
requirement by itself. A mismatch is rejected before startup-owned backend-trait calls,
entropy, locks, or local-directory access, and a successful `StartupReport` retains the
declaration for process-local observation. Only a successful validated declared-live startup
also retains a distinct private, move-only capability; it is not reconstructed from the
copyable report.

Gate's off-by-default `live-zenoh` feature now provides a crate-private consuming binding
from one durable coordinator Called state to one awaited invocation of the concrete
`FinalCommandPublisher`, plus public no-network activation and single-owner service typestates.
The live coordinator
constructor consumes the private startup capability and cross-checks the retained declaration
and exact actor wire profile before clock sampling. The resulting marker is carried through
every runtime-returning coordinator state; error and fatal paths destroy it. The concrete
publisher method exists only on the
marked live Called type. Exact
`InProcessReference`, forged-report, and modeled-actor paths cannot construct it.
Coordinator construction derives the exact pinned command route
from its actor realm/session; a publisher for any other route is terminally rejected before
frame access or invocation. Every invoked matched publisher consumes both itself and the
runtime. A local publisher `Ok` is linked to terminal journal success but stops as
application-unobserved: NCP v0.8 starts `ttl_ms` at plant-local arrival, and this path has no
enforced in-transit age bound or authenticated application acknowledgement. Gate therefore
commits no guessed live action interval and returns no capability that could publish again.
A publisher error is journaled conservatively when terminal append and sync succeed and also
returns no capability. Terminal-boundary failure returns an immediate diagnostic and no
capabilities.
Dropping the future while it is pending
leaves locally sync-confirmed Called, which the tested restart path closes as
`UnknownAfterPublish`. Tests exercise the
result and fault ordering through test-only seams. Dropping the consuming future before its
first poll invokes no test publisher code but is already after locally sync-confirmed Called;
dropping it after a `Pending` poll models an external timeout, and an unwind from a test
publisher-future panic has the same restart classification. None invents ReturnedError; only
an explicit local publisher error or definite Gate rejection can record that stage.
Synthetic terminal-record faults cover definite failure before append and an
`AppendCommitAmbiguous` result injected
after the real terminal append and sync, with reopen respectively producing Unknown or the
exact terminal state. These tests do not open a live Zenoh session, execute the concrete
method, enforce a real deadline, or inject an OS-I/O fault.

The public off-by-default `DeclaredLiveGateKernel` first consumes the marked coordinator to issue
one Gate-signed, startup-entropy-derived challenge with a fixed local monotonic lifetime. Only the
resulting move-only issued-challenge state can consume one bounded caller-supplied initial trusted
state and matching signed lease. It derives the intent route from the verified, admission-bound controller and requires the signed route to equal the
canonical realm/session/controller route before challenge consumption, durable term commit,
revision change, or activation. Failure returns no owner. A crate-private lower service then consumes
only that move-only route-bound result and one internally constructed route-matched publisher,
creating one private capacity slot. For each internally supplied raw event, it enforces the hard
envelope and actual-key-field bounds before capacity,
clock, or actor access. The key value is caller-supplied at this boundary and is not transport
provenance. The service privately owns one capacity slot and returns the sole service owner
only before publication or after an ordinary no-publication outcome; fatal, cancellation, publisher-error, and
terminal-boundary-failure paths return no service/publisher capability. A local publisher
`Ok` is also terminally surfaced as application-unobserved rather than safe continuation.
Marked-live service
tests use a fake publisher seam; the
production concrete aggregate signature compiles but is not invoked. The lower raw-event service
is not exposed by `haldir-gate`; the activation inputs are locally
caller-supplied rather than authenticated control/state ingress. A consuming local state-update
transition exists and validates Gate time plus bounded source replay, but it does not authenticate
the producer or provide a transport; no lease/revocation refresh loop exists. A separate
`DeclaredLiveGateZenohService` consumes the route capability, one supplied
session wrapper, and bounded limits; it derives the matched publisher and exact accepted-controller-
route ingress internally from that same session lineage, then exposes only consuming receive/process/
shutdown paths. A cloneable local handle can latch a request that lets the shutdown-aware method
return the owner before retry/new receive or wake an idle receive, but never request-cancels a
selected event and supplies no in-flight timeout or signal supervision. The request is cooperative:
legacy `process_next` ignores it, successful latching is not a cleanup acknowledgment, and a runner
must restrict clones and exclusively use the shutdown-aware method. Offline fake tests prove the composition and ownership ordering, not concrete
Zenoh invocation. The feature-gated development examples now hard-select `DeclaredLiveZenoh` and
exact v0.8 for a separately provisioned disposable fixture; the networked target opens an external
strict-client configuration, constructs the aggregate, and immediately shuts it down without
processing. The retained development campaign proves those concrete local calls and returns for
one fresh disposable fixture with zero intents processed and zero commands published
(`CL-LIVE-GATE-DEV-BIND-01`). No authenticated production package protects the
session/credentials, authenticates ongoing controls, or makes the selection mandatory.
The separate deployment verifier authenticates a closed runtime/NCP-wire selection plus exact
compatibility-artifact bytes. `haldir-ncp08` separately exact-validates the implemented frozen
command-subset record when explicitly passed bytes (`CL-NCP-COMPATIBILITY-01`). The state primitive
separately ratchets caller-supplied neutral values, but no type-enforced path connects the signed
artifact role, semantic proof, ratchet, or Gate startup (`CL-DEPLOYMENT-PRIMITIVE-01`). The actual template runtime-profile
value therefore remains a cooperative caller declaration; public `GateConfig` and direct
`VehicleActor` construction bypass template startup and remain outside this capability chain. Production declared-live
startup with injected in-memory backends is tested through marked coordinator construction.
Separately, a test-minted marked capability wraps an initially inactive actor and
the actual journal manager, then exercises bounded local activation, canonical intent-route
binding, fake-publisher service binding, and fake session/ingress aggregate orchestration.
Called/result fault tests still use test-only publisher seams. Neither test path opens a Zenoh
session or invokes the concrete publisher, or establishes credential/handle exclusivity.
The retained synthetic campaign proves the exact final-command/controller-intent ACL subset
using valid pinned-NCP JSON and remote callbacks (`CL-LIVE-TRANSPORT-01`), but not the service
binding or application. The separately retained local Zenoh success does not prove delivery or
application (`CL-LIVE-GATE-DEV-BIND-01`).

## Deferred upstream capabilities (increment 1)

Per the release, NCP v0.8.0 defers: plant-issued command authority, transport-bound
`publisher_id`, and applied-command/stop acknowledgements. Haldir does **not**
fabricate these as private extension fields. The wire `authority.term`/`lease_id`
are ABSENT in `NcpCommandFrameV1`; `PlantPublicationAuthorityStateV1` keeps
`AclExclusiveV1` and the future `NcpLeaseV1` as distinct variants. The current
Gate configuration rejects `NcpLeaseV1` at construction: retaining the contract
shape for a future wire profile must not admit an unimplemented authority mode
into an ACL-only actor and defer failure until command time.

## Documentation-drift ledger (to record upstream, not to copy)

The specification records that at review time some NCP prose lagged the tag
(README quick-start built the deleted top-level `seq`; a `proto/ncp.proto` comment
still said `"0.7"`; the wire-0.8 design record called the line untagged;
`NEURO_CYBERNETIC_PROTOCOL.md` retained wire-0.7 sequence prose). Two stale time
comments are especially hazardous: the protocol overview and the pre-0.8
`CommandFrame` rustdoc say command `t` echoes the driving sensor. The tagged
v0.8.0 changelog and frozen wire-0.8 identity design instead define `t` as this
command publisher's local monotonic creation time and carry the driving sensor's
time separately in `source_t`; Haldir follows that release definition by mapping
Gate time to `t` and trusted-source time to `source_t`. Haldir implements
stream/source/session/time/restart semantics from the tagged proto/schemas/
changelog/conformance corpus and the typed-identity design record, never from
stale prose. Upstream issues/PRs are the owner's to file.
