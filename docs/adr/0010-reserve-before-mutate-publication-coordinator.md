# ADR-0010 — Reserve-before-mutate, single-slot publication coordination

Status: accepted

## Context

A Gate decision, the act of exposing exact command bytes, the local publisher
return, receiver acceptance, and physical application are not one atomic event.
A crash or cancellation can occur between any two locally observable stages. The
coordinator must also prevent independently prepared output positions from being
published out of order and must not begin an authority mutation that its bounded
local journal cannot represent.

The current profile has no distributed transaction with the receiver and no
authenticated application acknowledgement. The design therefore preserves exact
local facts and stops when the downstream result is ambiguous.

## Decision

Use one consuming, single-owner publication coordinator with these ordered rules:

1. Require one non-cloneable permit from the production capacity-one output pool.
2. Before allocating a new decision or output position, reserve three
   maximum-sized logical journal units: the signed decision receipt, the
   `PublishCalled` stage, and one local-return terminal stage.
3. Keep prepared exact bytes inside an opaque non-cloneable typestate. Cross-check
   the complete receipt/frame binding before it can seed a later stage.
4. Validate the call boundary, append and `sync_data`-confirm `PublishCalled`, then
   resample time and recheck actor-owned authority, causal state, slot, validity,
   and horizon before exposing that same immutable frame once.
5. Append and `sync_data`-confirm the exact locally observed return. In the
   declared-live profile, either local `Ok` or local error is terminal and returns
   no publisher or runtime authority.
6. On recovery, turn a dangling `PublishCalled` into a linked
   `UnknownAfterPublish` and refuse new decisions until a future authenticated
   external clearance mechanism resolves the ambiguity.

The precise reasons are causal ordering and representability. The permit prevents
two independently prepared sequence positions from racing to publication. Reserving
all three record units before decision mutation prevents predictable quota
exhaustion midway through the lifecycle. Syncing the Called record before byte
exposure leaves a recoverable pre-side-effect boundary. Consuming typestates make
unsafe continuation unavailable through the intended Rust API, while terminal
ambiguity prevents a retry that could duplicate an already active command.

The three-unit reservation is logical quota isolation, not filesystem block
preallocation. It cannot guarantee that a later write or sync succeeds.

## Alternatives considered and rejected or deferred

- **Reserve or allocate each journal record only when needed.** Rejected because a
  known capacity shortfall could occur after decision/output sequence mutation or
  after the lifecycle had become non-retryable. Up-front reservation moves that
  predictable refusal before mutation; storage faults remain possible and retain
  typed failure semantics.
- **A queue or several publication slots.** Rejected for the one-vehicle profile.
  Independently prepared positions could be exposed out of order or against stale
  causal state. Parallel publication is deferred until a protocol proves ordering,
  cancellation, state revision, and recovery semantics and measured need justifies
  the added state space.
- **A shared or cloneable actor/publication handle.** Rejected because multiple
  callers could race lifecycle transitions or retain a resubmission path. A
  cloneable shutdown request remains a separate one-way denial capability and does
  not own publication.
- **Expose bytes before the Called record is synced, or record Called after the
  publisher returns.** Rejected because a crash can then leave externally exposed
  bytes with no durable local pre-side-effect fact.
- **Treat publisher `Ok` as delivery/application and continue.** Rejected because
  the local return proves neither receiver arrival nor application and supplies no
  trustworthy active interval for subsequent duty accounting.
- **Automatically retry after a timeout, cancellation, panic, or ambiguous error.**
  Rejected because the first call may already have taken effect.
- **Block authorization on a remote evidence collector.** Rejected because remote
  evidence availability must not create command authority or an unbounded denial-
  of-service dependency. The mandatory boundary here is the bounded local journal;
  export remains separate.
- **A distributed transaction or authenticated receiver acknowledgement.** Deferred
  because the current receiver protocol supplies neither. A future protocol would
  be a new architecture and recovery claim, not an interpretation of local `Ok`.

## Assumptions and invariants

- One process cooperatively follows the consuming coordinator API for one vehicle.
- The actor, coordinator, journal manager, monotonic clock, and exact publisher
  identities were constructed through the documented local binding. Rust privacy
  and ownership do not provide process isolation or global credential custody.
- Local `sync_data` success is the implementation's observed persistence boundary.
  Filesystem, device, kernel, and power-loss behavior remain external to the narrow
  tests unless a separate campaign covers them.
- A second decision can use the capacity-one slot only when the owning production
  service/runtime is safely returned. Dropping a permit restores the pool's local
  accounting but cannot resurrect a consumed runtime.
- Unused logical journal capacity is explicitly released only on a safe
  pre-Called continuation. Dropping an unreleased reservation deliberately strands
  its quota until journal recovery.
- Any Called-or-later trace is non-retryable without authenticated external
  clearance. Elapsed time alone does not clear it.
- The publisher is cooperative not to copy or resubmit borrowed bytes through a
  lower API. Closing lower APIs and alternate actuator paths is a deployment task.

## Output and failure semantics

- A no-publication decision or safe pre-Called rejection returns the sole runtime
  owner and still-owned output permit after explicitly releasing the unused
  journal reservation. The permit can then be reused or dropped.
- A prepared decision may be explicitly cancelled before Called; its already
  journaled receipt remains evidence, while the exact frame is never exposed.
- After `PublishCalled` is synced, cancellation, task drop, panic, missing return,
  or an unconfirmed terminal append returns no usable runtime. Recovery records
  `UnknownAfterPublish` when no exact terminal record was durably recovered.
- A locally observed `Ok` is recorded as `PublishReturnedOk`; a locally observed
  error is recorded as `PublishReturnedError`. Neither outcome means non-delivery,
  receiver acceptance, application, or physical effect, and neither authorizes an
  automatic replacement.
- Journal-capacity refusal before mutation is typed unavailability. Journal,
  clock, binding, or actor failures at a terminal boundary are typed fatal results
  and consume the authority-bearing path where safe continuation cannot be proved.

## Consequences

- Publication throughput is deliberately serialized and bounded to one in-flight
  output for the current one-vehicle profile.
- Some local success and failure cases terminate the service even when a richer
  receiver protocol might eventually disambiguate them. This is restrictive by
  design.
- The journal distinguishes local stages without pretending they are receiver or
  plant observations.
- The protocol narrows misuse through the intended API but does not prevent a
  caller with lower public APIs or copied credentials from creating another path.

## Evidence and claim ceiling

`haldir-gate` tests reservation-before-mutation, capacity release, receipt/frame
cross-checks, call-boundary rechecks, single-slot ownership, local `Ok` and error,
pre-append failure, post-sync ambiguity, cold and pending future drop, panic unwind,
restart reduction, and no-retry terminal behavior. `haldir-evidence` tests linked
stage reduction, journal reservation, append ambiguity, and reopen behavior
(`CL-GATE-LIFECYCLE-01`, `CL-GATE-JOURNAL-BINDING-01`,
`CL-PUBLICATION-STATE-01`).

The evidence is local Rust, fake-publisher, and bounded journal evidence. It does
not establish a production runner, protected credential custody, process isolation,
real transport invocation, delivery, receiver application, remote cleanup,
filesystem or power-loss durability, disk-full behavior, crash supervision,
availability, proof that every actuator path traverses this coordinator, or
physical effect. The release threat model remains a draft checkpoint; this ADR
does not close it.
