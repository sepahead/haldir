# NCP compatibility

Haldir's stable contracts contain semantic Haldir fields, not NCP-generated
structs. Only `haldir-ncp10` is aware of NCP wire semantics.

## Current provider boundary (checked 2026-10-01)

Haldir speaks NCP 1.0 natively. It pins the `1.0.0-rc.1` candidate at commit
`2819dae3b6338bb1df6d105ebb5b7433936a993d`: wire `1.0`, compact `CONTRACT_HASH`
`163acc57d8a62b66`. The candidate is untagged upstream, so the commit is its
identity. NCP cuts the `v1.0.0` tag after its technical release gates pass, and
Haldir moves to that tag when it exists.

The previous immutable baseline, NCP `v0.8.0`, is retired. Haldir neither builds
nor accepts wire-0.8 frames, and a deployment package that selects the exact
v0.8 wire no longer decodes. Independent qualification of the 1.0 adapter
remains **NOT RUN**.

## Candidate local NCP boundary

The candidate `ncp.local-lockstep.v1` experiment uses a direct command path.
Haldir is absent from that path.
Haldir has no qualified adapter for this candidate profile.
This status does not change the pinned wire-1.0 baseline below.

The experiment supervisor must reject a requested Haldir gate before preparing any endpoint.
It must report the selected gated profile as unsupported.
It must not substitute direct execution after that rejection.
This requirement is a release acceptance condition, not evidence of a Haldir runtime implementation.

### Native policy seam

The pure prepared-policy API is `haldir_policy_native::try_decide_validated`.
Its input is `ValidatedPolicyInput`, and its result is `Result<PolicyDecision, PolicyEvaluationError>`.
The input joins these independently supplied values:

- current monotonic time
- active mission lease
- trusted state snapshot
- requested action
- bounded action history
- validated native policy

A successful policy call alone does not execute the Gate actor or publish a command.
`VehicleActor::decide_bounded_intent` consumes the actor's bounded intent input and applies its own state checks.
Publication then requires the existing prepared-publication and publication-result transitions.
The [architecture](ARCHITECTURE.md) defines those separate boundaries.

The current action contract supports `Hold` and `VelocityLocalNed`.
Velocity components use integer millimeters per second in the local north-east-down frame.
The earlier fixed-role CREBAIN reference experiment uses acceleration commands.
Acceleration cannot be copied into a velocity field.
A future adapter requires an explicit action mapping and independently tested policy and execution semantics.

The current modular [CREBAIN sensor application](https://github.com/sepahead/crebain/tree/main/integrations/ncp-force-ground-sensors) is a separate interface.
Its body target uses roll, pitch, and heading in radians, plus altitude in meters.
Those fields cannot be copied into Haldir's local-NED velocity command.
Haldir has no qualified gate for that application.
The [NCP modular guide](https://github.com/sepahead/NCP/blob/main/local/modular/STATUS.md) records its separate current scope.

### Advisory evidence and identity

Galadriel evidence remains record-only in this candidate experiment.
No Galadriel verdict grants, restores, or widens Haldir authority.
An unavailable, insufficient, or nominal assessment does not become a Haldir policy decision.
A future policy effect requires an independently admitted contract and supporting evidence.

Local NCP digests bind the supplied bytes and labels.
They are not Haldir signatures or proof of an authenticated controller.
The experiment must not label an unsigned local request as a signed Haldir intent.
Existing Haldir signature, lease, policy, replay, and publication requirements remain separate.

No candidate local gate execution, publication, or receiver application is claimed here.
The [claim ledger](CLAIM-LEDGER.md) remains the authority for Haldir's tested scope.

## Pinned baseline (exact commit)

| Field | Value |
| --- | --- |
| `ncp_tag` | `1.0.0-rc.1` (untagged candidate; the commit is its identity) |
| `ncp_commit` | `2819dae3b6338bb1df6d105ebb5b7433936a993d` |
| `wire_version` | `1.0` |
| `contract_hash` | `163acc57d8a62b66` |
| `proto_sha256` | `9c127c8e795105da73dddfe47b671bf1f4ee895958ea5f35eda8b37cc503d510` (measured locally 2026-10-01) |
| `command_schema_sha256` | `3203e44dc071433c333340201250b345afb0c78cf74e9a01b023d6624f6b6092` |
| `command_vector_sha256` | `7f6aad14820f52330fa9517ec322644a090225dfd3c0cd99e15961bb0d3efd33` |
| `enabled_increment` | `1` |
| `capability_profile` | `NCP_1_0_COMMANDER_LEASE` |
| `haldir_adapter_version` | compiled `haldir-ncp10` package version |

The pinned values through `capability_profile` are duplicated in
`crates/haldir-ncp10/src/compatibility.rs` (`NCP_V1_0_0_RC1`) and `tools/pins.toml`.
`haldir_adapter_version` instead derives from the compiled Cargo package version.
`tools/verify-pins.py` enforces both the duplicated values and that derivation.
NCP's own consumer guard reads the same revision from `.ncp-consumer`.

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

## Commander lease

NCP 1.0 rejects an Active command without an authority lease. Under
`1.0.0-rc.1` the commander issues its own lease and the body's authority machine
enforces it; NCP ADR-006 later moves issuance to the body. Haldir's Gate issues
its lease to the transport principal and final route named by its
deployment-bound exclusive-route ACL evidence, so NCP authority never reaches
beyond that grant. Gate carries the lease on every command, HOLD included: NCP
requires it on Active and validates it on HOLD, and it makes a HOLD attributable
to the authority holder.

The body returns no authority feedback under rc.1, so the lease needs none. A
lease never changes. Once two thirds of its interval has elapsed, the next
command carries a newer term with a fresh lease id and interval. NCP accepts a
newer term as a transfer from the holder while the old lease is live, and as a
fresh acquisition once it has lapsed. Gate never renews in place: NCP refuses to
renew a lapsed lease, and a lost renewal could leave Gate holding a lease that
the body had let lapse. Lost commands therefore never cost authority.

A term must exceed every term the body has seen in the session, including the
terms of earlier Gate boots. Terms come from Gate's durable boot counter,
`term = boot_counter · 2^24 + n`, where `n ≥ 1` counts acquisitions in this
boot. No term repeats and none needs a durable write; a boot counter beyond the
JSON-safe term space fails startup. The interval is 15–60 s (default 30 s).
Its final third, in which Gate rotates, spans NCP's 5 s bound on commander–body
clock disagreement. Configuration rejects a policy NCP validity cap above that
margin, and both the decision and the publication recheck require the lease to
cover the command's whole validity.

Gate acquires a term only with UTC, for the lease's audit bounds, and entropy,
for its id. Without them a held lease stays in use until its monotonic deadline
and decisions then deny publication. UTC never decides expiry inside Gate. NCP's
own `AuthorityMachine`, run in process as the body, accepts the first term, a
rotation while the old term is live, re-acquisition after a lapse, and a later
boot's first term, and it refuses a restart that reused its boot counter
(`CL-NCP-LEASE-01`).

## Default P0 model, exact conformance adapter, and route boundary

The default `ModeledNcp10Adapter` models the NCP 1.0 command semantics, lease
included, without an upstream or Zenoh dependency, keeping the pure P0 core
dependency-light. The off-by-default `real-ncp` feature adds `RealNcp10Adapter`,
compiled from `ncp-core` `1.0.0-rc.1` at the exact commit above. It constructs the upstream
`CommandFrame`, runs `WireFrame::validate_wire`, serializes the exact compact
JSON bytes, and validates those bytes again with
`decode_validated::<CommandFrame>` before exposing them.

The frozen upstream command vector and schema live under
`crates/haldir-ncp10/tests/data/ncp-v1.0.0-rc.1`; their SHA-256 values are
recorded in `tools/pins.toml` and checked by `tools/verify-pins.py`. The exact
adapter rebuilds that conformance vector, compared after upstream validated
decoding. Differential tests cover
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
`ExactNcpV1_0Json` and the compiled `live-zenoh` feature. In particular, compiling only
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
application-unobserved: NCP 1.0 starts `ttl_ms` at plant-local arrival, and this path has no
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
exact NCP 1.0 for a separately provisioned disposable fixture; the networked target opens an
external strict-client configuration, constructs the aggregate, and immediately shuts it down
without processing. The retained development campaign proves those concrete local calls and returns for
one fresh disposable fixture with zero intents processed and zero commands published
(`CL-LIVE-GATE-DEV-BIND-01`). No authenticated production package protects the
session/credentials, authenticates ongoing controls, or makes the selection mandatory.
The separate deployment verifier authenticates a closed runtime/NCP-wire selection plus exact
compatibility-artifact bytes. `haldir-ncp10` separately exact-validates the implemented frozen
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
using valid pinned-NCP JSON and remote callbacks (`CL-LIVE-TRANSPORT-01`). It was recorded
with NCP v0.8 frames; router ACLs do not depend on the frame version. It does not prove the
service binding or application. The separately retained local Zenoh success does not prove
delivery or application (`CL-LIVE-GATE-DEV-BIND-01`).

## Upstream authority capabilities

NCP `1.0.0-rc.1` provides commander-issued authority leases, which Haldir
carries as described above. Explicit stream declaration and retirement
(ADR-005), which a restarted Gate needs before a 1.0 body accepts its fresh
output epoch, is not yet implemented by Haldir (see `LIMITATIONS.md`).
Body-issued authority (ADR-006), journaled command dispositions (ADR-007), a
transport-bound publisher identity that `ncp-zenoh` exposes to receivers, and
applied-command or stop acknowledgements are not yet delivered upstream. Haldir
does **not** fabricate them as private extension fields.
`PlantPublicationAuthorityStateV1` keeps `AclExclusiveV1` and `NcpLeaseV1` as
distinct variants. Configuration supplies only the exclusive-route ACL evidence;
Gate issues its lease at runtime, so a configured `NcpLeaseV1` is rejected at
construction.

## Documentation-drift ledger (to record upstream, not to copy)

These notes record the NCP v0.8 review. The specification records that at review
time some NCP prose lagged the tag (README quick-start built the deleted
top-level `seq`; a `proto/ncp.proto` comment
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
