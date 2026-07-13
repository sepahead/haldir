# NCP compatibility

Haldir's stable contracts contain semantic Haldir fields, not NCP-generated
structs. Only `haldir-ncp08` is aware of NCP wire semantics.

## Pinned baseline (immutable)

| Field | Value |
| --- | --- |
| `ncp_tag` | `v0.8.0` |
| `ncp_commit` | `2f5bd586d4bb20c90362bb6f5698b7f64057ba4e` |
| `wire_version` | `0.8` |
| `contract_hash` | `d1b50a2d8a265276` |
| `proto_sha256` | `6f13b12cff76e12fef384f691d11e2944db1f676568c3e780d3f975689131227` (measured locally 2026-07-12) |
| `capability_profile` | `PRE_AUTHORITY_ACL_ONLY` |

These are encoded in `crates/haldir-ncp08/src/compatibility.rs` (`NCP_V0_8_0`) and
`tools/pins.toml`, and enforced by `tools/verify-pins.py`.

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

`frame_id` is copied from the independently validated trusted source state. It is
part of the trusted-state digest and is never hardcoded: NCP's safety governor
requires the sensor and command coordinate frames to agree. NCP has no field for
Haldir's trusted `source_key`, so that key remains evidence/cache metadata while
`source.{epoch,seq}` is carried on the NCP frame. Nanosecond Gate/source times are
projected to NCP binary64 seconds; at the full `u64` nanosecond range the tested
round-trip error bound is 2,048 ns, so this mapping is not byte identity.

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
`FinalCommandPublisher` still deliberately rejects modeled non-JSON bytes and accepts only
upstream-validated NCP JSON.

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
frame access or invocation. A matched publisher capability is returned only after local
publisher `Ok` and linked terminal journal success; a publisher error is journaled
conservatively when terminal append and sync succeed and does not return the capability.
Terminal-boundary failure instead returns an immediate diagnostic and no capabilities.
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

The public off-by-default `DeclaredLiveGateKernel` first consumes the marked coordinator plus one
bounded caller-supplied initial trusted state, challenge, and signed lease. It derives the intent
route from the verified, admission-bound controller and requires the signed route to equal the
canonical realm/session/controller route before challenge consumption, durable term commit,
revision change, or activation. Failure returns no owner. `DeclaredLiveGateService` then consumes
only that move-only route-bound result and one preconstructed route-matched publisher, creating
one private capacity slot. For each raw, publicly constructible
`IntentIngressEvent`, it enforces the hard envelope and actual-key-field bounds before capacity,
clock, or actor access. The key value is caller-supplied at this boundary and is not transport
provenance. The service privately owns one capacity slot and returns the sole service owner
only on safe continuation; fatal, cancellation, publisher-error, and
terminal-boundary-failure paths return no service/publisher capability. Marked-live service
tests use a fake publisher seam; the
production concrete signature compiles but is not invoked. The activation inputs are locally
caller-supplied rather than authenticated control/state ingress, and no refresh/revocation loop
exists. A separate `DeclaredLiveGateZenohService` consumes the route capability, one supplied
session wrapper, and bounded limits; it derives the matched publisher and exact accepted-controller-
route ingress internally from that same session lineage, then exposes only consuming receive/process/
shutdown paths. A cloneable local handle can latch a request that lets the shutdown-aware method
return the owner before retry/new receive or wake an idle receive, but never request-cancels a
selected event and supplies no in-flight timeout or signal supervision. The request is cooperative:
legacy `process_next` ignores it, successful latching is not a cleanup acknowledgment, and a runner
must restrict clones and exclusively use the shutdown-aware method. Offline fake tests prove the composition and ownership ordering, not concrete
Zenoh invocation. No runnable Gate binary/service package selects `DeclaredLiveZenoh`, constructs
the concrete aggregate, or opens/authenticates its session or credentials.
The runtime-profile value is a cooperative caller declaration, not authenticated package data
or a durable anti-downgrade state; public `GateConfig` and direct `VehicleActor` construction
bypasses template startup and remains outside this capability chain. Production declared-live
startup with injected in-memory backends is tested through marked coordinator construction.
Separately, a test-minted marked capability wraps an initially inactive actor and
the actual journal manager, then exercises bounded local activation, canonical intent-route
binding, fake-publisher service binding, and fake session/ingress aggregate orchestration.
Called/result fault tests still use test-only publisher seams. Neither test path opens a Zenoh
session or invokes the concrete publisher, or establishes credential/handle exclusivity.
The retained synthetic campaign proves the exact final-command/controller-intent ACL subset
using valid pinned-NCP JSON and remote callbacks (`CL-LIVE-TRANSPORT-01`), but not the service
binding or application. Even a local Zenoh success would not prove delivery or application.

## Deferred upstream capabilities (increment 1)

Per the release, NCP v0.8.0 defers: plant-issued command authority, transport-bound
`publisher_id`, and applied-command/stop acknowledgements. Haldir does **not**
fabricate these as private extension fields. The wire `authority.term`/`lease_id`
are ABSENT in `NcpCommandFrameV1`; `PlantPublicationAuthorityStateV1` keeps
`AclExclusiveV1` and the future `NcpLeaseV1` as distinct variants.

## Documentation-drift ledger (to record upstream, not to copy)

The specification records that at review time some NCP prose lagged the tag
(README quick-start built the deleted top-level `seq`; a `proto/ncp.proto` comment
still said `"0.7"`; the wire-0.8 design record called the line untagged;
`NEURO_CYBERNETIC_PROTOCOL.md` retained wire-0.7 sequence prose). Haldir implements
stream/source/session/time/restart semantics from the tagged proto/schemas/
changelog/conformance corpus and the typed-identity design record, never from
stale prose. Upstream issues/PRs are the owner's to file.
