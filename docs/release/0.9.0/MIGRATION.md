# Haldir 0.9 migration record

This record satisfies the per-requirement migration-note obligation for the
0.9 qualification program. An entry saying “none” means that the task changes
qualification artifacts or semantics documentation only; it does not hide an
unreviewed wire, API, data, deployment, or consumer conversion.

| Requirement | Change class | Wire/API/data impact | Required consumer or operator action | Automated conversion |
| --- | --- | --- | --- | --- |
| `HALDIR-0.9-T000` | release qualification provenance | None. The immutable audit cut and retained baseline add release-only files. | Preserve the exact source/dependency/NCP/deployment/evidence identities when reproducing the cut. | Not applicable; verification is provided by `verify-audit-inputs.py`. |
| `HALDIR-0.9-T001` | normative semantic clarification | No Rust API or wire change. The operational term “plant command” includes unauthorized final-route bypass frames; decisions remain `ALLOW`/`DENY`/`ERROR`, while `HOLD` is an action. | Documentation or consumers that called `HOLD` a denial/ESTOP must update terminology; no byte conversion can safely guess the intended semantic correction. | None; the authority-model verifier detects contradictory vocabulary and profile grants. |
| `HALDIR-0.9-T002` | evolved protection inventory; qualification reopened | The model update itself changes no Rust API, wire format, or stored-data schema. It now accounts for the post-qualification source APIs and deployment-package schema documented below; the prior closure does not verify the evolved bytes. | Continue to apply default deny, keep credentials with their named custodians, use Gate-origin monotonic time for freshness, and treat controller/source timestamps as provenance. Do not report T002 as verified until a new signed exact-commit closure is recorded. | None; the protection-model verifier checks the current inventory, while the evidence verifier preserves the old record only as historical evidence. |

## Post-qualification experimental API changes

The workspace crates remain unpublished and explicitly experimental. Ordinary
hardening after the qualification tasks can therefore tighten source APIs, but
the required migration remains recorded rather than hidden.

### Declared-live activation now requires a Gate-issued signed challenge

The caller-selectable activation nonce was removed from
`LiveIntentActivationInput::new`. Replace
`LiveIntentActivationInput::new(state, nonce, signed_lease)` with
`LiveIntentActivationInput::new(state, signed_lease)`, and replace direct
`DeclaredLiveGateKernel::activate(...)` calls with the explicit linear
handshake:

```rust,ignore
let issued = kernel.issue_activation_challenge()?;
publish_to_the_mission_authority(issued.signed_challenge_envelope())?;
let signed_lease = receive_lease_bound_to(issued.challenge().challenge_nonce)?;
let activation = LiveIntentActivationInput::new(initial_state, signed_lease)?;
let route_bound = issued.activate(activation)?;
```

`DeclaredLiveGateKernel` deliberately has no activation method. Only the new
move-only `IssuedLiveGateChallenge` state can accept a lease, so successful
Gate-signed challenge construction and local registration are compile-time
prerequisites. The challenge nonce comes from startup's cryptographic-entropy
fill (`OsEntropy` uses the operating-system CSPRNG), not from the activation
caller. Its deadline is local Gate monotonic state and is not added to the
contract; `LIVE_ACTIVATION_CHALLENGE_TTL_MS` is currently 30 seconds. The signed
`GateChallengeV1` and `MissionLeaseV1` schemas and their canonical encodings are
unchanged, but integrations must now deliver the exact signed challenge to the
mission authority and return a lease that binds its nonce.

Custom `EntropySource` implementations must continue to fill the entire slice
provided by startup and must accept 48 bytes for non-live builds or 80 bytes when
the `live-zenoh` feature is compiled. Declared-live
startup now draws an additional 32 bytes in the same fill for its initial
challenge nonce. This is an unpublished Rust source/protocol-sequencing change;
there is no automatic conversion for a caller-authored nonce because retaining
that authority would defeat the safety boundary.

The lower `VehicleActor::register_challenge` method is no longer public. A
reference embedding that intentionally drives the actor directly must call
`VehicleActor::issue_challenge(now)?`, independently verify or deliver the
returned `SignedGateChallenge::signed_envelope()`, and bind
`SignedGateChallenge::challenge().challenge_nonce` into the authority-signed
lease. That API obtains its nonce directly from the OS CSPRNG, enforces the same
fixed local TTL, and allocates a monotonic nonzero challenge sequence. Raw nonce
insertion remains crate-private for the sealed startup/live composition and
white-box tests only.

### Preflight the lease-nominated controller signing key

`VehicleActor::accept_lease_env` and declared-live activation now reject a
lease unless `controller_intent_signing_key_id` already resolves in the runtime
trust snapshot to an unrevoked, assurance-class `ControllerIntent` record whose
subject exactly matches the lease/admission controller. This validation happens
before the durable lease-term high-water, one-shot challenge, authorization
revision, replay state, or process state changes. Previously such an unusable
lease could report successful activation and spend term/nonce authority even
though no controller intent could ever pass the later signature binding.

Provision the controller key before issuing the lease and keep its key id,
role, class, subject, and revocation state consistent with the admission-bound
controller. Existing wire schemas and persisted formats do not change; this is
a stricter authority-establishment behavior.

### Revocation snapshot epochs are read-only

`haldir_crypto::RevocationSnapshot::epoch` and
`haldir_admission::AdmissionSnapshot::revocation_epoch` are no longer public
fields. Read them through `epoch()` and `revocation_epoch()` respectively, and
advance them only with `revoke_key(...)` / `revoke(...)`. `revoke_key` now
returns `Result<(), RevocationError>`: a new revoked key must carry an epoch
strictly above the current high-water, a repeated revocation at or below that
high-water is idempotent, and a repeated revocation at a higher issuer epoch
advances the high-water without growing the set. The snapshot rejects growth
beyond `MAX_REVOKED_KEYS` without mutation.
Propagate or explicitly handle `EpochNotAdvanced` and `CapacityExceeded`. This
prevents callers from bypassing the snapshot's monotonic high-water invariant
or constructing an unbounded revocation index. This is a Rust source-level
change only; it does not alter a wire or persisted-data schema.

### Signing-key subjects are mandatory and bounded

`haldir_crypto::KeyRecord::subject` changed from `Option<String>` to the
mandatory `KeySubject` type. Construct it with `KeySubject::new(...)` and handle
`DecodeError::InvalidIdentifier`; accepted subjects are 1 through 64 ASCII bytes
from the same `[A-Za-z0-9._:-]` alphabet used by contract identifiers.
`VerifiedCose::signer_subject` and the third element returned by
`verify_and_decode` are consequently `KeySubject`, not optional strings.
Provisioning code must assign every trusted key an explicit subject and compare
it through `as_str()`. Missing or unbounded signer identity is no longer
representable after successful trust resolution.

`TrustStoreError` is now non-exhaustive; downstream matches require a wildcard.
The store also rejects byte-identical public-key material under a second key id,
regardless of proposed role, subject, or assurance class, while allowing exact
whole-record reinsertion. A distinct insertion after `MAX_TRUSTED_KEYS` records
now returns `TrustStoreError::CapacityExceeded`; existing-key conflict and alias
diagnostics retain precedence and every error is non-mutating. These are
unpublished Rust source-level hardenings. They do not change COSE, public-key,
signature, or persisted-data bytes.

`KeyRole::DevelopmentOnly` records must now also carry
`KeyClass::Development`; labeling that role as assurance authority returns
`TrustStoreError::InvalidDevelopmentClassification`. Assurance verification
independently rejects either a development class or the development-only role.
Correct inconsistent bootstrap trust configuration instead of relying on the
previously contradictory role/class pair.

### Bounded-set constructors bound input work

`BoundedSet::<T, N>::from_iter_checked` now consumes at most `N + 1` items and
returns `DecodeError::BoundExceeded` when the iterator supplies more than `N`,
even if the excess items are duplicates. Previously only the deduplicated output
cardinality was checked, so an unbounded duplicate iterator could create
unbounded work while producing a small set. Pass a pre-bounded iterator or
collection whose input length is at most `N`. Canonical set wire encoding and
decoding are unchanged.

`MissionLeaseV1::allowed_source_keys` is now a
`BoundedSet<BoundedAscii<256>, 8>` rather than a `BoundedVec`. Construct it with
`BoundedSet::from_iter_checked(...)`. Source authorization is a set operation;
the canonical contract now rejects duplicate or non-canonically ordered source
keys instead of giving permutation-distinct bytes to equivalent authority. The
CBOR field remains a definite array with the same element encoding, so already
sorted, unique leases retain their bytes. Existing signed leases whose source
keys are duplicated or out of canonical order must be reissued; they cannot be
safely rewritten without the mission authority's signature.

`GateChallengeV1::accepted_contract_versions` is likewise now a
`BoundedSet<ContractVersion, 8>`. Supported-version membership is unordered;
sorted unique inputs retain the same array bytes, while duplicate or permuted
encodings are rejected instead of producing multiple signed identities for one
capability set.

### Cumulative admission levels require their available evidence binding

`AdmissionRecordV1::validate` now rejects A2 through A6 records whose
`conformance_run_digest` is absent. Those levels are cumulative and all include
the A2 reference-conformance claim; an evidence-free record must use A0, A1, or
`OPAQUE_CONTROLLER`, or be reissued by the admission authority with the exact
conformance-run digest. Existing valid records that already carry the digest
retain their bytes. Admission revocation tombstones also now return `Revoked`
before active-record lookup, so a loader may omit an inactive record without
weakening the retained revocation result; authorization remains fail-closed in
either case.

### Remove the non-enforcing session-rebind scaffold

`haldir_state::SessionState` and `SessionBindOutcome` were removed. The unused
scaffold installed a new session binding before merely telling its caller that
dependent lease, replay, challenge, output, and publication authority needed
invalidation; its type could not enforce that cascade. Current Gate actors bind
one immutable `NcpSessionIdentityV1` and a session-generation change requires
retiring the actor and constructing a freshly booted replacement. Integrations
must use that lifecycle rather than attempting an in-place `SessionState::bind`.
This is an unpublished Rust source-level removal with no wire or persisted-data
conversion.

### Fallible construction, lease deadlines, and motion-policy schema v2

- `SigningKey::from_seed([u8; 32])` now returns
  `Result<SigningKey, CryptoError>`. Propagate or map the error in runtime code;
  tests with a fixed nonzero seed may use an explicit expectation. The all-zero
  seed is rejected because the underlying provider does not accept it. This is a
  source-level error-model change; public-key and signature wire formats are
  unchanged.
- `VerifyingKey::from_bytes([u8; 32])` now performs the pinned provider's
  verification-time checks plus independent canonical, non-identity,
  prime-subgroup validation during provisioning instead of accepting every
  length-correct encoding. Callers already handle `Result`; malformed,
  non-canonical, pure-torsion, and mixed-torsion encodings that previously
  survived construction now return `CryptoError::BadKey`. Existing keys emitted
  by ordinary Ed25519 key generation remain valid. Public-key bytes and
  signature wire formats are unchanged.
- Signature verification now rejects a noncanonical or torsion-bearing encoded
  nonce point before invoking the pinned provider. Signatures produced by
  ordinary Ed25519 signers remain valid; previously accepted weak encodings may
  now return signature verification failure. The 64-byte wire shape is unchanged.
- `StorageMacKey::new([u8; 32])` now returns
  `Result<StorageMacKey, DurableError>` and rejects the all-zero provisioning
  sentinel as `DurableError::InvalidKey`. Propagate this error in runtime key
  loading; fixed nonzero test keys may use an explicit expectation. This catches
  one catastrophic provisioning error but does not measure entropy or prove key
  generation, confidentiality, rotation, or custody. Snapshot bytes are unchanged.
- `AdmissionSnapshot::insert(record) -> ()` was removed. Use
  `AdmissionSnapshot::try_insert(record)?` and handle
  `AdmissionSnapshotError::InvalidRecord` when the candidate fails the
  supported admission-record validation, as well as a
  conflicting record for an existing admission id, instead of relying on an
  error-discarding convenience path. Validation precedes every lookup or
  mutation; an exact valid duplicate remains idempotent. The same call also
  returns `AdmissionSnapshotError::RecordCapacityExceeded` after
  `MAX_ADMISSION_RECORDS` distinct records. `AdmissionSnapshot::revoke` now
  returns `Result<(), AdmissionSnapshotError>`: new revoked ids require a
  strictly advancing epoch, exact repeats remain idempotent, and
  `MAX_REVOKED_ADMISSIONS` bounds retained revocations. Propagate or explicitly
  handle both revocation error variants. A repeat at or below the current
  high-water remains idempotent; a repeat presented with a higher issuer epoch
  advances the high-water without growing the set. Capacity and epoch failures
  are non-mutating.
- `GateConfig.local_cap_ms`, `GateConfigTemplate.local_cap_ms`, and
  `LeaseAcceptContext.local_cap_ms` changed from `u32` to `NonZeroU32`.
  Construct the cap explicitly; the retired `GateConfigError::LocalCapZero`
  cannot occur once invalid zero is unrepresentable. Handle the new non-exhaustive
  `LeaseAcceptError::InvalidLease`, `LeaseAcceptError::DeadlineOverflow`, and
  `LeaseAcceptError::ChallengeCommitInvariant` variants.
  Direct `accept_lease` callers must now supply a supported, semantically valid
  `MissionLeaseV1`; invalid leases and monotonic deadlines that cannot be
  represented fail before lease-term or challenge state is spent. A challenge
  that was pending immediately before the durable term commit but cannot be
  consumed afterward is now an internal-fault invariant breach rather than an
  ordinary lease denial; the term remains conservatively spent and no lease is
  activated. Gate latches this condition fail-stop. There is no wire or
  persisted-data schema change.
- `ActiveMissionLeaseSnapshot` now preserves the validated contract types for
  authority-bearing fields instead of widening them after acceptance:
  `lease_term` and both usage limits are `NonZeroU64`/`NonZeroU32`, the intent
  route is `BoundedAscii<256>`, and action/frame/source allowlists retain their
  original `BoundedSet` types. Direct snapshot fixtures must construct those
  values explicitly and use `.get()`/`.as_str()` when a primitive view is
  required. This is a source-level change only; lease wire bytes are unchanged.
- `RevisionCounter::from_nonzero(NonZeroU64)` and `is_exhausted()` are additive
  APIs for restoring and preflighting the authorization revision. Gate now
  rejects an exhausted counter before invoking lease validation or mutating the
  durable lease-term/challenge state, so an unrepresentable successor can no
  longer burn otherwise valid authority before faulting. There is no wire or
  persisted-data schema change.
- `NativePolicySnapshot` now requires the source field
  `motion_envelope_v2: Option<LocallyAdmittedMotionEnvelopeV2>`. `None` preserves
  representability and the exact canonical identity of a legacy digest-schema-v1
  snapshot, but `ValidatedNativePolicy`, the expanded evaluator, and Gate reject
  it for execution. Set `Some(...)`, recompute the schema-v2 canonical policy
  digest, update every lease's `policy_snapshot_digest`, and reissue/reprovision
  artifacts that bind the old identity. `canonical_digest_v1` is preserved and
  rejects a v2 envelope rather than silently omitting executable fields.
- The v2 envelope supplies the exact trusted-state/NCP frame identifier in
  which local-NED values are interpreted, local acceleration/slew maxima, a
  continuous-motion maximum, a minimum Hold dwell, and
  `plant_mode_rules: Vec<PlantModeRuleV2>`. Populate an explicit rule for every
  plant mode in which Gate may emit an action; an unlisted mode denies all
  actions. Rules are action-specific, bounded, unique, and canonicalized in the
  schema-v2 digest. The frame identifier and mode rules are part of that digest;
  a request denies rather than copying an unmatched frame or treating an
  unknown mode as nominal. Effective maxima are the minimum of the signed lease
  and local envelope; effective dwell is their maximum. This is a locally
  admitted executable policy/plant envelope, not proof of authenticated
  policy-package provenance or an independently authenticated live plant
  capability. Because schema v2 was introduced in this release candidate,
  regenerate any pre-release v2 policy digest and every artifact or lease that
  binds it.
- Motion behavior is intentionally stricter. Acceleration is a vector-norm
  state-to-command mismatch against fresh measured velocity, with worst-case
  velocity uncertainty and the nominal control period. Slew remains a distinct
  vector-norm command-to-last-published-command check. Continuous motion persists
  across silence, command gaps, and lease boundaries. Only a returned-ok
  published Hold whose continuously covered horizon satisfies the stricter dwell
  and latest-call boundary can rearm a burst. Prospective duty now unions the
  candidate with retained future tails, so a shorter replacement candidate can
  no longer hide a longer previously published horizon.
- Raw `NativePolicySnapshot::phase_permits` is no longer public, and the new
  plant-mode predicate is crate-private. Those helpers are meaningful only
  after whole-policy duplicate and bound validation; use `try_decide`, or retain
  a `ValidatedNativePolicy` and call `try_decide_validated`, instead of making an
  authorization decision from an unvalidated rule vector.
- `DecisionReasonCodeV1` adds the append-only numeric tags
  `DenyAcceleration = 49`, `DenyContinuousMotion = 50`, and
  `DenyHoldDwell = 51`, `DenyPlantMode = 52`, and
  `DenySourceUnrepresentable = 53`. The last reason rejects a trusted-source
  stream position outside the implemented NCP JSON-safe integer namespace at
  state ingress, before it can become causal decision state. This extends the
  canonical receipt wire vocabulary:
  older closed-vocabulary decoders will reject receipts that use these tags and
  must be upgraded before interoperating. The enum is non-exhaustive; downstream
  Rust matches require a wildcard.
- Gate output allocation now treats the same NCP JSON-safe integer limit as the
  terminal output namespace boundary. The first position above that limit is
  rejected before allocation and reported as `ErrorNamespaceExhausted`, rather
  than being allocated and later misclassified as a generic adapter fault. No
  previously representable output position changes.
- Schema-v1 `HaldirIntentV1.input_watermarks` must now be empty. The field had
  no Gate authentication, freshness, or policy-intersection semantics and was
  previously ignored after signature verification. Controllers using auxiliary
  fusion watermarks must omit them until a later schema defines those semantics.
- `HaldirIntentV1::semantic_digest()` now defines the receipt's
  `semantic_intent_digest` as a separate canonical projection rather than a
  second domain-separated hash of the entire payload. It binds controller/key/
  route, Gate/boot/scope/session, lease/admission/bundle/backend, replay
  position, causal source, and action; it excludes schema framing, required-empty
  auxiliary watermarks, and controller-local instance/time/context provenance.
  `payload_digest` continues to bind every canonical payload field. Receipt
  layouts do not change, but digest values do: consumers must recompute through
  `HaldirIntentV1::semantic_digest()` and must not substitute a full-payload hash.
- `DecisionReceiptV1` deny/error validation now accepts a nonempty,
  duplicate-free vector when every reason matches the outcome class; an allow
  still requires exactly one `AllowPrepared`. Gate now signs all distinct
  bounded reasons returned by native policy evaluation rather than discarding
  every reason after the first. Verifiers that incorrectly assumed exactly one
  denial reason must iterate the vector.
- `DecisionReceiptV1` validation now rejects partial intent-derived evidence.
  Payload/semantic digests, controller/position, mission/lease, admission, and
  source are either all absent or all present; a state digest cannot appear
  without that group, and an `ALLOW` additionally requires the complete group
  plus state. Producers that constructed synthetic prepared receipts with only
  output fields must populate the actual decision bindings instead. The wire
  layout is unchanged; previously admitted impossible field combinations are
  now rejected.

There is no automatic conversion for policy identities or signed leases: the
v2 digest commits new executable semantics and must be intentionally
recomputed, approved, and rebound. The new reason tags require a decoder
upgrade, not byte rewriting.

### NCP command-build and wire-profile observability

- `GateCommandBuildInputV1::effective_validity_ms` is now checked before either
  wire profile is built. Zero, or a value greater than the signed action's
  `requested_validity_ms`, returns
  `NcpAdapterError::InvalidEffectiveValidity`. The modeled profile previously
  admitted both shapes and the exact profile rejected zero only as an incidental
  upstream validation failure. This is a stricter source-level error contract;
  no valid NCP bytes or stored data change.
- Remove `decision_id` from every `GateCommandBuildInputV1` initializer. It was
  correlation-only, was not read by command construction, and is absent from
  both modeled and exact command bytes. This is a Rust source change with no NCP
  wire or stored-data conversion.
- `ncp_m_s_to_mm_s(f64)` and
  `ExactNcpCommandFrame::decoded_velocity_mm_s()` now return `Result` instead of
  silently mapping non-finite values to zero or saturating out-of-range values.
  They accept only the exact binary64 image produced by
  `mm_s_to_ncp_m_s(i32)`; propagate
  `NcpAdapterError::ConversionOutOfRange`. Adapter-produced valid frames retain
  the same values and bytes. `PlantCommand::from_exact_frame` performs this
  check once and retains the validated fixed-point action and nonzero validity
  internally. The unreachable `RejectReason::ZeroValidity` variant was removed:
  zero validity is rejected before an `ExactNcpCommandFrame` or `PlantCommand`
  can be constructed.
- `ExactNcpCommandFrame::wire_profile()` and
  `ExactNcpCommandFrame::source_key_is_wire_bound()` are additive observability
  APIs. Exact NCP v0.8 JSON binds the source epoch and sequence but has no
  `source_key` field, so its output-frame digest does not bind `source_key`;
  modeled-P0 bytes do. Consumers must retain that profile distinction rather
  than projecting exact-v0.8 source-key provenance from the digest. No bytes
  changed: this pre-existing limitation is now explicit and profile-validated.
  Exact-v0.8 also projects Gate/source nanoseconds to binary64 seconds. That
  deterministic projection has a tested 2,048 ns full-domain round-trip bound
  but is non-injective, so consumers must not infer that its digest uniquely
  commits the original nanosecond integers; modeled-P0 bytes do commit them.
  `NcpCommandWireProfile` is non-exhaustive; downstream matches require a
  wildcard so later exact encodings can be added without another source break.

### Durable revocation high-water no-op semantics

`AntiRollbackStore::candidate_with_revocation_epoch` and
`accept_revocation_epoch` now treat an epoch equal to the current scope
high-water as an exact semantic no-op. In particular, presenting epoch zero for
a previously unseen scope no longer inserts a zero-valued entry, consumes bounded
scope capacity, or makes a pristine store ineligible for first deployment-package
binding. Callers that used equal-epoch calls as an implicit scope-registration
side effect must stop doing so; no canonical persisted bytes require conversion.
The durable wrappers now return `DurableRevocationUpdate` instead of an
unconditional `CommitReceipt`: match `Unchanged` for an accepted equal epoch and
`Committed(receipt)` for a newly written authenticated head. An `Unchanged`
result performs no snapshot or anchor write and does not advance the durable
generation.

### Trusted-state and live-service updates

- `SecureClientConfig::from_file` now accepts only a no-follow, nonblocking
  regular file on Linux/macOS, captures at most 256 KiB, and parses that captured
  JSON5 directly. It compares descriptor identity, ownership, mode, link count,
  size, modification time, and change time across the bounded read; symlinks,
  special files, concurrent metadata-visible rewrites, growth beyond the bound,
  non-UTF-8, and other targets return `SecureZenohError::ConfigLoad`. This also removes
  Zenoh's pre-validation external-plugin-config loading behavior. Integrations
  that relied on config symlinks or Zenoh plugin includes must supply one closed
  ordinary file instead; there is no wire or persisted-state conversion.
- `DigestDomain::TransportKey` now identifies exact concrete route/key bytes.
  Gate receipts use it for `received_key_digest`, and declared-live startup
  requires `AclExclusiveEvidenceV1.final_route_digest` to equal this-domain
  digest of the exact pinned-NCP final route derived from realm/session. Existing
  ACL evidence built with `DigestDomain::Payload` must be regenerated. Receipt
  layouts are unchanged, but `received_key_digest` values change.
- `FinalCommandPublisher::new(session, keys)` was replaced by fallible
  `FinalCommandPublisher::try_new(session, keys, expected_session)`. Supply the
  complete `NcpSessionIdentityV1` owned by the Gate. Construction rejects a route
  session-id mismatch, and publication rejects any mismatch in either session id
  or generation across the retained exact-frame semantics and decoded upstream
  JSON. This is a Rust source-level hardening; the NCP route and command bytes are
  unchanged. `FinalCommandPublisher::publish` now consumes `self`; construct a
  distinct publisher for each deliberate call. This makes one publisher handle
  single-use across both definite and ambiguous returns. It does not make the
  shared session or transport credential exclusive, so deployment-level custody
  remains mandatory.

- `VehicleActor::set_trusted_state` now requires a second `MonoInstant`
  argument sampled from the current Gate boot's monotonic clock. The setter
  rejects source receive or snapshot capture time later than that observation,
  and a clock regression fault-latches rather than accepting a future-dated
  freshness anchor.
- Accepted snapshots must strictly advance both global capture time and the
  primary source stream. A source key may first attach at any nonzero sequence;
  sequence then advances strictly in its active epoch. A new opaque epoch retires
  the old one permanently, and the bounded tombstone set is never evicted.
  Replay/retired positions return `DenySourceStale`; retained-stream exhaustion
  returns `ErrorNamespaceExhausted`.
- Exhausting the Gate output-sequence namespace now fault-latches the actor and
  returns `ErrorNamespaceExhausted`; it is no longer reported as the recoverable
  `DenyOverload` class. No wire shape changes, but operators must treat this
  reason as a terminal boot failure and replace the Gate incarnation.
- `max_total_intents` now counts every fresh authenticated, correctly scoped
  intent that reaches lease-usage accounting, including an intent refused by the
  rate bucket. Previously only rate-admitted intents consumed the total. Size
  lease totals for presented-intent volume and expect an authorized rate flood
  to exhaust its own lease rather than retain unlimited denied attempts.
- Under `live-zenoh`, the lower raw-event `DeclaredLiveGateService`,
  `LiveServiceTransition`, and `LiveStateUpdateTransition` are no longer public
  or root-reexported. Migrate external integrations to the consuming
  `DeclaredLiveGateZenohService` aggregate and match
  `LiveZenohServiceTransition`, `LiveZenohActivityTransition`, or
  `LiveZenohStateUpdateTransition`. The public aggregate derives its ingress and
  publisher internally from the same supplied session and accepts no raw event
  or publisher override. Retain the returned aggregate owner on safe
  continuation; a stopped transition returns no reusable runtime. Its state
  update still validates a caller-supplied internal snapshot and does not
  authenticate a producer or create a state transport. This is a Rust source API
  break only; no wire or persisted-data shape changed.
- `DeclaredLiveGateZenohService::process_next_or_state_or_shutdown` and
  `LiveZenohActivityTransition` are additive. The method polls a caller-owned
  cancellation-safe state-receive future beside the aggregate's intent ingress
  and shutdown latch, so state refresh is not blocked by a quiet intent route.
  The supplied future is dropped whenever another branch wins; cancellation of
  the consuming method still destroys the aggregate. A privately retained
  intent retry stays inside the aggregate until its own branch wins.

This is a source-level change to the unpublished actor API and a stricter local
state-ingress semantic. There is no wire or persisted-data conversion; source
replay state is rebuilt empty for each Gate boot.

### Exact reference-plant command provenance

- `ReferencePlant::new` now requires the independently selected
  `NcpSessionIdentityV1` as its second argument. Construct a new plant model for
  a session rollover. The receiver no longer trusts the first accepted command
  to choose its session; a wrong first frame is rejected without rebinding the
  model.
- `PlantCommand` can no longer be created with a struct literal or with
  independently supplied session, output position, source, action, validity,
  and digest fields. Build the exact frame with the selected NCP adapter, then
  call `PlantCommand::from_exact_frame(decision_id, exact_frame)` and handle
  `PlantCommandError`. Read the derived values through `decision_id`, `session`,
  `output_epoch`, `output_seq`, `source`, `action`, `validity_ms`,
  `output_frame_digest`, and `exact_frame`.
- `PlantEvent` is no longer `Copy`, and its former independent `decision_id` and
  `output_seq` fields are replaced by `command: Option<PlantCommandCorrelation>`.
  Command-related events carry the complete frame-derived session/output/source/
  digest tuple atomically. Use `PlantEvent::decision_id()` and
  `PlantEvent::output_seq()` for compatibility-style projections; treat the
  decision id as correlation-only because it is absent from the NCP frame bytes.
- Exhaustive matches on `RejectReason` must account for
  `InvalidOutputFrame`, `ConflictingReplay`, and `PriorStreamLive`, or use a
  wildcard as required by the enum's existing `non_exhaustive` contract.

This is a source-level change to unpublished experimental Rust APIs. Neither
`PlantCommand` nor `PlantEvent` is a canonical wire or persisted-data contract,
so there is no byte migration. `PlantAction`, `PlantCommand`, and
`PlantCommandError` are now defined by `haldir-ncp08`, which owns the validated
exact-command boundary. `haldir-reference-plant` re-exports those names for
source compatibility and consumes them through its sole ingress. Production
`haldir-gate` no longer depends on the simulation crate.

The reference model also tightens two simulation behaviors. A command now
applies only for complete fixed ticks covered by its validity, so a sub-tick
validity expires before the next integration step instead of being rounded up.
`max_accel_mm_s2` and `safe_decel_mm_s2` now bound the Euclidean magnitude of a
velocity-vector delta; multi-axis trajectories therefore no longer receive the
same configured limit independently on every axis. These are deterministic
model behavior changes, with no wire or persisted-data migration. A different
output epoch is now rejected with `PriorStreamLive` while the preceding command
horizon remains live and becomes eligible at its exact half-open expiry
boundary, matching the constrained NCP v0.8 single-publisher transition rule.
Position integration now also carries the signed sub-millimetre remainder
between ticks. Previously each tick discarded that remainder, so a legitimate
low-speed command could appear permanently stationary. Public snapshots remain
whole-millimetre values; only deterministic model trajectories change, and
overflow at a fractional `i64` boundary now fails transactionally.

### Exact action history

- Replace `BoundedActionHistory::new(capacity)` with
  `BoundedActionHistory::new(capacity, retention_window)` and handle its
  `Result`. Replace `BoundedActionHistory::default()` the same way; history no
  longer has a context-free default because its retention window is a required
  policy invariant.
- Do not construct or mutate history fields. Use the read-only accessors and the
  fallible `record_hold(start, end)`, `record_velocity`, `validate_for_policy`,
  `active_duration_in_window`, and `prospective_active_duration` methods.
  `record_hold` now requires the exact returned-ok published horizon;
  `record_velocity` no longer accepts a caller-selected eviction cutoff because
  history derives it from its owned window. This history transition applies to
  the synchronous in-process reference boundary, where application occurs in
  the same call. A declared-live local transport `Ok` no longer supplies a
  caller-derived interval.
- Replace removed whole-millisecond `active_ms_in_window` calls with exact
  `MonoDuration` accounting and handle `ActionHistoryError`.
- Integrated monitors should use `try_decide` or `try_decide_validated` and treat
  `PolicyEvaluationError` as an internal fault. The existing `decide` wrappers
  remain fail-closed but intentionally collapse internal errors to
  `DenyPolicyDiagnostic`.
- Use `MonoDuration::from_nanos`, `checked_from_millis`, or
  `saturating_from_millis` explicitly. The ambiguous saturating
  `from_millis` constructor is deprecated. Standard-library durations convert
  through checked `TryFrom<std::time::Duration>` and infallible conversion in
  the other direction.
- Public configuration, startup, evaluation, history, and publication errors
  added by this change are non-exhaustive. Downstream matches require a wildcard;
  use stable reason codes for diagnostics. Wrapper variants expose an
  `Error::source` when their nested error implements `Error`.
- History construction and a later record after spare-capacity-shrinking may
  return `ActionHistoryError::AllocationFailed`. The history reserves one
  bounded candidate slot before semantic mutation; returned-ok recording then
  performs the interval union and closest-gap compression in place.

No wire or stored-data conversion exists: action history remains actor-local and
is rebuilt through validated Gate construction.

### Treat live local transport success as application-unobserved

`LiveServiceOutcome::PublishReturnedOk` was removed. Once the declared-live
publisher is invoked, no result returns the public
`DeclaredLiveGateZenohService` aggregate or its publisher. A local transport `Ok` now
returns the terminal `LiveServiceStop::ApplicationUnobserved` (wrapped in
`LiveZenohServiceStop::Gate` at the owned Zenoh boundary) with the decision and
the synced `PUBLISH_RETURNED_OK` envelope digest.

Callers must stop the process-instance lifecycle and enter authenticated restart
clearance instead of treating local `Ok` as authority to publish again. NCP
v0.8 starts command `ttl_ms` from plant-local arrival, and the present transport
supplies neither that arrival time, an enforced in-transit lifetime, nor an
authenticated application acknowledgement. Consequently Gate commits no live
action-history interval derived from its local call time. The evidence schema is
unchanged: `PUBLISH_RETURNED_OK` still names the exact observed local return; it
does not mean delivery or application. This is an unpublished Rust API and
behavioral break with no NCP wire or persisted-journal conversion.

### Bound the public actor input before hashing

The raw three-argument `VehicleActor::decide_intent(envelope, actual_key, now)`
entry point is no longer public. Construct
`BoundedIntentCandidate::new(envelope, actual_key)?` and pass it to
`VehicleActor::decide_bounded_intent(candidate, now)`. Handle the non-exhaustive
`IntentCandidateError` using its stable `reason_code` or a wildcard match.

The candidate admits at most 16 KiB of exact envelope bytes and 256 bytes of
observed route. An over-limit value is now rejected in O(1) before exact-byte
hashing, signature work, decision-id allocation, actor mutation, or evidence
append; it therefore has no `DecisionRecord` or signed receipt. The live ingress
already used these ceilings, so this is a public source-level hardening change,
not a canonical wire or persisted-data migration.

### Make ephemeral actor construction explicit

`VehicleActor::new_ephemeral(config)` is now the explicit constructor for the
process-local anti-rollback path used by tests and development-only embeddings.
The ambiguous former `VehicleActor::new(config)` spelling is removed; migrate
callers to the explicit name. Integrations that require
crash-surviving lease-term anti-rollback must instead use staged durable startup,
which returns a `RunningGate` after committing a fresh boot and constructs the
actor through `new_recovered` or `new_deployment_recovered`. This is a Rust API
source break only; it changes no canonical bytes or persisted state.

### Reject the unimplemented NCP publication-authority profile at startup

Direct `GateConfig` construction now rejects
`PlantPublicationAuthorityStateV1::NcpLeaseV1` with
`GateConfigError::UnsupportedPublicationAuthorityProfile`. The contract keeps
that variant so a later reviewed NCP profile can version and migrate it, but the
current Gate implements only `PRE_AUTHORITY_ACL_ONLY`; it no longer accepts a
future authority shape and waits until a decision to deny publication. The
retired `PublicationSessionMismatch` and `PublicationOutputEpochMismatch`
Gate-configuration errors cannot occur in an implementation that rejects the
whole profile. Match the non-exhaustive error through its stable reason code or
a wildcard. Canonical contract bytes and persisted state are unchanged.

### Bind assurance startup to the verified deployment package

`start_with_backends` no longer accepts `StartupProfile::AssuranceExternal`
without a deployment package. It now returns
`DurableGateStartupError::DeploymentPackageRequired` after static/anchor-profile
validation but before entropy, lock, storage, or anchor mutation. Development-local
callers are unchanged.

Assurance callers must construct `AuthorityValidatedDeploymentPackage`
through the consuming chain
`verify_deployment_package` → `resolve_artifacts` (or
`resolve_artifacts_from_directory`) → `validate_ncp_compatibility` →
`validate_gate_configuration` → `validate_authority_approvals`, then call
`start_deployment_with_backends`. The
entry point exact-matches the signed Gate, realm, vehicle, runtime, NCP wire,
state-store, assurance, and configuration identities to the supplied runtime
objects before effects. It commits the verifier-derived
package revision and canonical payload digest atomically with the boot and retains
the package in `RunningGate`/`JournalBoundRunningGate`.

`Development` packages select only `DevelopmentLocal` startup;
`ExperimentalCanary` and `AssuranceSimulation` select only `AssuranceExternal`.
Handle the non-exhaustive `DeploymentGateBindingError` through its stable
`reason_code` or a wildcard match. `VehicleActor::new_deployment_recovered` is
the corresponding lower-level additive constructor for an already committed
package-bound store.

`StartupReport` adds `startup_profile`, `deployment_revision`, and
`deployment_payload_digest`. Downstream struct literals must initialize those
fields; ordinary callers should continue treating the report as returned
observability data. This is a Rust source/behavior change, not a new canonical
wire format. Existing durable stores previously used through the unbound boot
path still require the explicit v3 package-binding migration documented above.

### Bind signed Gate configuration and role-separated authority approvals

The package-consuming chain now has two mandatory semantic typestates after NCP validation:

`verify_deployment_package` → `resolve_artifacts` (or
`resolve_artifacts_from_directory`) → `validate_ncp_compatibility` →
`validate_gate_configuration` → `validate_authority_approvals`.

`start_deployment_with_backends` now accepts
`AuthorityValidatedDeploymentPackage`, not
`NcpValidatedDeploymentPackage`. The new stage strictly decodes the exact
package-resolved `GATE_CONFIGURATION` bytes as
`GateConfigurationArtifactV1`, validates schema v1.0 plus its signer,
publication, NCP-profile, and durable-identity invariants, and cross-binds its
redundant Gate/realm/vehicle/class/runtime/wire/state/journal fields to the
containing package. There is no public conversion that can mint the stronger
type without those checks.

`DeploymentAcceptancePolicy::new` now accepts three grouped values:
`DeploymentIdentityExpectation`, `DeploymentProfileRequirement`, and
`AuthorityApprovalPolicy`. This replaces the former positional constructor and
requires callers to select the expected trust, admission, revocation, and policy
authority subjects outside the signed package. `verify_deployment_package`
retains bounded clones of the exact bootstrap `TrustStore` and
`RevocationSnapshot`; `validate_authority_approvals` no longer accepts trust or
revocation arguments, preventing a second root from being introduced between
typestate stages.

The `TRUST_MANIFEST`, `ADMISSION_SNAPSHOT`, `REVOCATION_SNAPSHOT`, and
`POLICY_SNAPSHOT` role bytes must now be COSE envelopes containing
`AuthoritySnapshotApprovalV1`. Each approval uses its distinct required role
(`TRUST_AUTHORITY`, `ADMISSION_AUTHORITY`, `REVOCATION_AUTHORITY`, or
`POLICY_AUTHORITY`) and exact-matches the expected issuer, deployment
id/revision, Gate/realm/vehicle, authority kind, and corresponding configuration
digest. Existing placeholder or raw-snapshot bytes fail closed; issue a new
package revision with the four approval envelopes and ensure their public keys
are present and unrevoked in the original bootstrap trust snapshots.

The artifact commits semantic identities for the complete bounded trust store,
key-revocation snapshot, admission snapshot, executable policy, NCP session,
static ACL publication authority, nonzero local lease cap, and Gate application
signer id and public key. The ACL binding covers principal, final route,
certificate fingerprint, and policy digest; boot-local `verified_at_mono_ns` is
runtime observation metadata and is deliberately excluded. Package-bound startup derives every identity from the supplied
live objects and rejects any mismatch before entropy, lock, storage, or anchor
access. Handle the new non-exhaustive `DeploymentGateBindingError` variants by
stable `reason_code` or a wildcard match.

Package-bound startup now also calls
`AuthorityValidatedDeploymentPackage::validate_runtime_trust_bindings` after
the signed runtime trust digest matches. `TrustStore::validate_disjoint_bindings`
requires the bootstrap and runtime stores to be disjoint: any shared `kid`
returns `TrustStoreDisjointnessError::OverlappingKid`, and shared public-key
material under otherwise distinct identifiers returns
`TrustStoreDisjointnessError::OverlappingKeyMaterial`. Exact-record overlap is
intentionally rejected because the two stores have independently governed
revocation snapshots and therefore cannot safely share a key lifecycle. The
new disjointness error is non-exhaustive; downstream matches require a wildcard.
The startup error is
`DeploymentGateBindingError::BootstrapRuntimeTrustConflict`; it occurs before
entropy, lock, storage, or anchor access and retains the underlying trust error
as its source. Provision distinct key material per authority domain and issue a
new signed package/configuration snapshot if an earlier package relied on such
cross-store aliasing. This is a stricter behavioral and additive Rust-API change;
it changes no canonical wire or durable-state schema.

`TrustStore::canonical_digest`, `RevocationSnapshot::canonical_digest`, and
`AdmissionSnapshot::canonical_digest` use new frozen semantic digest schemas and
the new `TrustStoreSnapshot`, `RevocationSnapshot`, and `AdmissionSnapshot`
domains. They encode all authority-bearing fields in canonical map/set order;
their internal reverse indexes and cached record digests are derived and are not
encoded twice.

Existing packages whose `GATE_CONFIGURATION` role contained opaque placeholder
bytes no longer reach package-bound startup. Rebuild that role as the strict
canonical artifact, update its signed size and deployment-artifact digest, and
issue a new signed package revision. This is a Rust source and signed-artifact
behavior change; the outer `DeploymentPackageV1` wire schema and durable Gate
state format do not change. The four approval roles authenticate the semantic
identity of separately supplied runtime snapshots; they do not deserialize or
acquire those snapshots. The other seven named roles remain exact retained bytes
until their own semantic loaders are implemented, so this change does not claim
a complete production package loader.

### Reject semantically impossible Gate status combinations

Canonical decoding of `GateStatusV1` now validates cross-field lifecycle and
publication relationships. It rejects output without a session, incomplete
lease/admission pairs, active status without its lease/session/output context,
pre-session context in `BOOTING`/`READY_NO_SESSION`, session-bound active-lease
state, future-dated ACL evidence, and mismatched or expired NCP publication
evidence. `process_state`, `state_readiness`, and
`plant_publication_state` remain independent: an active lease can truthfully be
reported while state is temporarily not ready or publication authority is
unavailable, and either condition still prevents command authorization.
`RECOVERING` and terminal/transition states retain diagnostic partial state, and
`SESSION_BOUND` need not have allocated an output epoch yet. Producers must emit
a coherent status object; consumers should handle the stable
`DecodeError::SemanticInvalid` codes. Canonical field encoding is unchanged.

### Bind the signed journal identity in evidence format v2

`DeploymentPackageV1::journal_id` is now the distinct
`haldir_contracts::ids::JournalId` type rather than a raw `[u8; 16]`. Construct it
with `JournalId::new(bytes)?`; the all-zero sentinel is rejected with
`DecodeError::ZeroForNonZero`. Its canonical deployment-package encoding remains
the same 16-byte CBOR byte string, so valid signed package bytes do not change,
but downstream Rust struct literals and zero-ID error expectations do.

`JournalOpenOptions::new` and `PublicationJournalStartupConfig::new` now require
that typed journal ID. `SegmentIdentity` exposes the authenticated `journal_id`,
and package-bound `RunningGate` journal provision/open rejects a different ID
with `JournalBindingError::JournalIdMismatch` before directory access. Ordinary
development startup still selects an explicit ID; it does not acquire signed
deployment provenance merely by doing so. Handle the new non-exhaustive
`JournalManagerError::JournalMismatch` and Gate binding error through their
stable reason codes or wildcard matches.

The stored evidence format advances incompatibly from v1 to v2. Segment,
record, and footer magic/version domains are v2; every header includes the
16-byte journal ID; the maximum encoded header grows from 244 to 260 bytes; and
the segment/record/signature digest domains advance to v2. Current recovery
rejects v1 rather than adopting history that cannot prove a journal identity.
There is no in-place byte rewrite: changing a v1 header would invalidate the
footer digest and signature. Before deploying this build, finish and export any
required v1 evidence with the prior verifier, retain that immutable archive and
its external checkpoints, then explicitly provision a v2 journal under the
selected nonzero ID. Do not point `OpenExisting` at a v1 directory.

This closes package-to-local-chain identity substitution only. Journal binding
is still a later explicit step; the filesystem path is not in the signed package
or durable Gate ratchet; no authenticated runner makes the bind mandatory; and
no external witness, power-loss guarantee, or retention service follows.

### Remove the empty `haldir-testkit` scaffold

The unpublished `haldir-testkit` workspace crate and the unused
`haldir-range -> haldir-testkit` dependency are removed. The crate exposed only
its package version and contained no builders, fixtures, or consumers; retaining
it created a false architectural boundary and compiled unused dependencies.
Delete downstream references to that package. There is no replacement API and
no wire or persisted-data migration.

All `haldir-range` imports are confined to its `#[cfg(test)]` adversarial
campaign, so its Haldir crate edges are now dev-dependencies rather than normal
runtime dependencies. This changes only Cargo dependency classification; the
range tests and their APIs are unchanged.

### Exhaust the output sequence space exactly

`GateOutputStreamState::allocate` now returns `OutputSeq(u64::MAX)` once before
reporting `OutputStreamError::Exhausted`. The prior implementation rejected that
last representable value because it tried to construct the successor before
returning the current allocation. Exhaustion remains terminal for the active
epoch and a failed call does not mutate state.

`GateOutputStreamState::peek_next_seq` now returns `Option<OutputSeq>` rather
than `u64`: `Some(sequence)` identifies the next allocation and `None` identifies
exhaustion without inventing a sentinel. Replace numeric comparisons with the
typed option or map it through `OutputSeq::get`. This is an unpublished Rust API
correction; it does not change any canonical wire or persisted-data format.

### Align Cargo package identity with the qualification namespace

All workspace packages now report version `0.9.0` and the named author recorded
by this release program. This intentionally changes build metadata and the
compiled Haldir adapter-version field in the NCP compatibility artifact, so
consumers must regenerate and revalidate that artifact rather than accepting an
identity generated by `0.1.0-experimental`.

Registry publication remains disabled with `publish = false`, and this metadata
alignment grants no deployment, qualification, certification, or release
authority. The repository remains `EXPERIMENTAL` and the release remains
`NO_GO` until its separately documented evidence and deployment boundaries are
closed.

The release remains NO-GO. These entries do not promise compatibility for later
implementation tasks; each later requirement must add its own row before it can
close.
