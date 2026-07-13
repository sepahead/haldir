# Evidence semantics (P0)

## Staged, not a boolean "executed"

Publication is never atomic with a receipt, so evidence uses stages, not a false
`executed` flag. `PublishStageV1` (in `haldir-contracts`) defines the vocabulary,
including `UNKNOWN_AFTER_PUBLISH` for a crash between publish and acknowledgement.
The canonical linked stage payload and a retained-state-bounded pure reducer now exist
(`CL-PUBLICATION-EVIDENCE-PRIMITIVE-01`). The staged durable-startup path now replays
those records and emits a signed, linked successor-boot `UnknownAfterPublish` for every
recovered dangling `PublishCalled` before returning the bound runtime
(`CL-GATE-JOURNAL-BINDING-01`). A crate-private consuming coordinator now owns that
bound runtime and one monotonic clock through an exact receipt -> `PublishCalled` ->
local-return lifecycle (`CL-GATE-LIFECYCLE-01`). It reserves all three maximum-sized
journal units and requires a non-cloneable slot minted by a bounded permit pool before
the actor can allocate a decision/output sequence. Successful declared-live startup also
mints a separate move-only capability that the live coordinator consumes and carries through
each runtime-returning state; error and fatal paths destroy it. The concrete production
publisher path borrows the frame only from the resulting live Called type, after the linked
Called append was locally `sync_data`-confirmed and post-sync actor
checks pass. Before service binding, a public no-network kernel consumes one bounded
caller-supplied initial trusted state, challenge, and signed lease. It validates the canonical
intent route from the verified, admission-bound controller before lease-term/challenge commit and
returns a move-only route-bound capability. The service kernel consumes only that capability plus
one preconstructed route-matched concrete publisher and creates one internal capacity slot. Its
consuming one-event API returns the sole owner only on safe continuation paths. This is a
lower process-local ownership boundary. The outer `DeclaredLiveGateZenohService` instead consumes
the route capability, one caller-opened session wrapper, and bounded ingress limits; it internally
derives the publisher and exact accepted-controller-route ingress from the same session lineage and
exposes a consuming receive/process API. This remains static local priming and code-shape ownership,
not authenticated state/control provenance, a selected credential-opening package, publisher
worker, supervisor, or runnable transport pipeline (`CL-LIVE-INGRESS-BINDING-01`).

## Each producer signs only what it observed

- **Gate** (`DecisionReceiptV1`) records the decision it made and stops at
  `OUTPUT_PREPARED` — it prepared the exact output bytes. It does **not** assert
  `CREBAIN_ACCEPTED` / `ADAPTER_APPLIED` / `PLANT_OBSERVED`; those belong to the
  plant/Crebain producers. (See `actor.rs`: the ALLOW receipt's `publish_stage` is
  `OutputPrepared`.)
- **Plant** (`haldir-reference-plant`) records its own stages: `Received`,
  `Validated`, `Accepted`, `Rejected(reason)`, `Selected`, `Applied`, `Expired`,
  `SafeActionStarted`, `SafeRegionReached`, `ResponseObserved`. In P0 these are
  **simulation model values**, never physical actuation.

## Digest domains are separated

`DigestDomain` prefixes each hash input so `raw_envelope`, `payload`,
`semantic_intent`, `output_frame`, and `state_snapshot` digests cannot collide
across domains (`haldir-contracts/src/digest.rs`).

## The evidence spool

`haldir-evidence::EvidenceSpool` is a bounded, digest-chained append-only spool.
It detects a tampered completed record or a broken tail. When full it drops export
copies and counts the loss (safety-first profile): **an evidence outage can never
turn a DENY into an ALLOW** (F2/B14), and command authorization never blocks on a
remote collector. The spool is not a lossy transport plane.

The Unix directory manager can opt in to a separately count/byte-bounded snapshot
of verifier-accepted opaque records grouped by authenticated segment in exact journal
order. It returns that snapshot only after the complete open/recovery succeeds. The
manager requires candidate verifier implementations to be deterministic and
side-effect-free because calls can precede new append capacity and commit; semantic
reduction happens only after a confirmed append or over a successfully returned
recovery snapshot used to rebuild fresh state exactly once.
It can also issue opaque manager-affine logical reservations. Each conservative unit
protects a future segment slot and the maximum header, maximum record frame, and footer
from ordinary appends/rotations. This isolates configured quota only; it does not
preallocate filesystem blocks or guarantee that a later write/sync succeeds.

The assurance-only Gate adapter closes that semantic gap offline for the two-record
publication journal profile. It binds footer and record KIDs to the same unrevoked
Gate-application assurance key/subject, dispatches only protected receipt/stage
content types, enforces the current Gate receipt shape and segment Gate/producer boot,
and consumes one ordered recovery snapshot to build fresh publication state. Empty
segments participate in boot chronology; boot resurrection and same-boot segment or
record time regression fail closed. Standalone replay still does not authenticate the
newly created current tail as a durably committed Gate boot; that authority comes only
from the consuming Gate startup boundary below.

A staged Gate startup boundary now fuses directory open, bounded capture, and semantic
replay under one verifier snapshot and derives the recovery producer from the actual
`RunningGate`'s private Gate identity, committed boot, and validated signer. It plans
every dangling call's exact linked `UnknownAfterPublish`, verifies and semantic-previews
the signed batch, checks future capture bounds and conservative journal quota, then
closes the prior tail, creates the current segment, and appends the batch before returning
the bound runtime. Semantic/current-boot-freshness rejection never closes the old tail;
for a nonempty Unknown batch, capture/logical-capacity rejection also cannot close it or
burn a successor. An empty batch keeps ordinary recovery/quiescence semantics. Insufficient-tail
truncation or pending-artifact removal can occur earlier. Its action is reported on a
successful open or semantic-replay rejection; another later recovery failure can return
without an exact action report. The
manager and replay state cannot be extracted separately, and the bound aggregate
withholds public mutable actor/journal access. This prevents report/raw-ID authority
substitution. The internal consuming coordinator retains the whole aggregate across the
future in-crate caller's possession of the called typestate; any journal error, clock
regression, state mismatch, or post-sync ambiguity returns no usable runtime. It appends a
terminal local-return record before resolving actor history/state. With Gate's
off-by-default `live-zenoh` feature, the concrete method exists only on a Called state
descended from a live coordinator that consumed the private startup capability and
cross-checked the retained declared-live profile plus exact wire selection before clock
sampling. Exact reference, copied-report, and modeled-actor paths cannot create that type.
The concrete production publisher path borrows the frame only after the strict publisher's
exact route matches the route derived from the actor realm/session; mismatch is terminally
recorded before frame access or invocation. For a match, the frame is borrowed for one awaited
invocation. `returned_ok` means that publisher
returned local `Ok` and the terminal append synced; it is not delivery.
`returned_error` covers both definite strict-publisher preflight rejection and a
delivery-ambiguous local transport error, and yields neither a replacement runtime nor the
publisher capability. If the await is cancelled, no return result was observed, so the
already-synced Called tail remains for restart classification. The test-only future seam
exercises three such no-result paths: dropping the consuming future before its first poll
without invoking test publisher code, dropping it after `Pending` to model an external
timeout, and catching an unwind from a panic while polling the test publisher future. Each
drops the bound runtime, publisher, and permit and reopens as one linked Unknown; none is a
ReturnedError. An explicit local publisher error or definite Gate rejection can take that
terminal path.

The public `DeclaredLiveGateKernel` and `LiveIntentRouteBoundGate` narrow the production call
surface before publisher binding. The kernel consumes the startup-marked coordinator plus one bounded
caller-supplied initial state/challenge/signed-lease bundle. Signed lease verification and
admission binding precede canonical `realm/session/controller` intent-route equality, and that
route check precedes challenge consumption, durable term commit, revision change, and Active.
Failure returns no runtime owner. This does not authenticate how the caller obtained or delivered
the state, nonce, or lease and provides no ongoing control/state/revocation path.

`DeclaredLiveGateService::bind` then consumes only the route-bound capability and one
already-created concrete publisher, checks its exact final-command route, and creates a private
fixed one-slot pool. `process_one` consumes the service and one raw, publicly constructible
`IntentIngressEvent`; it rejects an oversized
envelope or actual-key field before capacity, clock, actor, journal, or publisher work, and
returns the exact event with the service. It otherwise returns the service only for a
no-publication decision, a pre-Called rejection, pre-mutation unavailability, or local
publisher `Ok` followed by a confirmed terminal append. Fatal coordinator errors, a publisher
error, a terminal-boundary failure, cancellation, or unwind return no service/publisher
capability. Cold-dropping this outer future before its first poll performs no decision and
creates no Called record; dropping after it reaches a pending publisher leaves Called for
restart classification. This service does not open or exclusively own the shared Zenoh
session and does not own ingress; its publisher retains a shared session handle, while a
caller-held session can still create other publishers or close the session. The service does
not authenticate package/control choice or stop lower-level public publisher/session APIs
elsewhere.

`DeclaredLiveGateZenohService::bind` is the narrower owned-I/O composition. It accepts no caller
controller, route, keys, publisher, or event; re-derives the retained accepted-controller route
before declaration; and builds both typed handles from one supplied session wrapper. Its
`process_next` receives only from its owned ingress and retains a journal-capacity or
restart-clearance event privately before newer receive; otherwise-unreachable input/key/output-
capacity refusals stop the aggregate as invariant violations. Explicit shutdown orders
undeclare/drain before dropping the lower service
and closing the wrapper. Public transport borrowing constructors may already have minted other
handles, however, and the lower raw-event service remains public. Fake-only tests establish this
orchestration without a broker; they do not establish concrete session/subscriber invocation,
credentials, transport principal, ACL delivery, remote cleanup, or complete mediation.

Test-only terminal-record fault injection also covers both observed publisher `Ok` and
`Err`. A definite failure before terminal bytes are appended consumes the runtime and
publisher, then reopen closes the remaining Called tail as Unknown. A synthetic
`AppendCommitAmbiguous` returned only after the real terminal append and sync also consumes
them, but reopen finds the exact ReturnedOk or ReturnedError record and emits no Unknown.
The original publisher error, when one existed, is retained only in the immediate diagnostic;
the recovered journal remains authoritative. Production declared-live startup with injected
backends is tested through marked coordinator construction. Separately, a test-minted marked
capability around an initially inactive actor and the actual journal manager exercises caller-
supplied local activation, canonical route validation, and the shared fake-publisher binding core;
lifecycle/result fault cases still use a test-only publisher. Fake session/ingress tests separately
exercise the outer aggregate's binding, journal-capacity retry, closure, and shutdown ownership. No live invocation
exercises the concrete method. No runnable Gate executable/service package selects the public
aggregate, authenticates or refreshes its state/lease controls, or opens its session/credentials.
Lower-level actor/frame and
publisher/session constructors still permit copying
or resubmission outside this coordinator binding.

On reopen, dangling Called tails become linked Unknown records. If replay contains any
Called/ReturnedOk/ReturnedError/Unknown trace, the coordinator refuses every new decision
until a future authenticated transport/session/plant/history clearance mechanism exists.
For diagnostics it computes a timestamp from coordinator construction plus the larger of
the maximum such trace validity and the new actor's current duty-history window. That value
is not authoritative for the prior boot's policy/history, reaching it does not clear the
refusal, and a common trustworthy clock origin across startup, journal events, and the
coordinator is not established. Prepared cancellation or pre-call rejection releases unused
journal reservation and returns the still-reserved permit but leaves the already-journaled
Prepared trace, so retained trace capacity is not reclaimed and no abandonment/loss-summary
event is emitted. Cold drop, pending timeout-as-drop, panic unwind, and the two synthetic
terminal-fault endpoints are covered only through test seams. Coordinator-level OS partial
write/`sync_data` failure, disk-full behavior, real append-commit ambiguity on either
recovery side,
panic-abort or service-supervisor behavior, child-process crash, live-session
cancellation/timeout/panic, queue-worker, and transport tests remain absent. Lower journal
layers test their own narrower append ambiguity and reopen behavior. This is not transport
invocation, delivery, receiver inactivity, or application evidence
(`CL-GATE-LIFECYCLE-01`).

## Honesty rules

- A publish/prepare stage is never automatically upgraded to `received` /
  `accepted` / `applied`.
- `applied` and `observed response` are reference-plant model values in P0.
- A signed receipt does not prove physical actuation.
- A durable restart represents a recovered dangling `PUBLISH_CALLED` as
  `UNKNOWN_AFTER_PUBLISH`, never as success, failure, or non-delivery. The current
  crate-private coordinator can create and recover that locally sync-confirmed
  sequence, and the public service kernel selects it in code; no runnable Gate executable/package makes
  the path mandatory or proves a real publisher call.
