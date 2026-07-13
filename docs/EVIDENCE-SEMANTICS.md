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
the actor can allocate a decision/output sequence. Only the called typestate exposes frame
bytes, after the linked Called append was locally `sync_data`-confirmed and post-sync actor
checks pass. This remains an internal tested mechanism, not a selected queue, service,
publisher worker, transport pipeline, or coordinator-bound singleton pool.

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
terminal local-return assertion before resolving actor history/state, but the current API
does not bind that assertion to an actual publisher invocation. `returned_ok` therefore
means only that a trusted future in-crate caller asserted local `Ok`; `returned_error`
remains delivery-ambiguous and yields no replacement runtime. Exposed frame bytes can still
be copied or resubmitted by that caller.

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
event is emitted. Coordinator-level OS append ambiguity, child-process crash, async
cancellation, panic, queue-worker, and transport tests remain absent; lower journal layers
test their own append ambiguity and reopen behavior. This is not transport invocation,
delivery, receiver inactivity, or application evidence (`CL-GATE-LIFECYCLE-01`).

## Honesty rules

- A publish/prepare stage is never automatically upgraded to `received` /
  `accepted` / `applied`.
- `applied` and `observed response` are reference-plant model values in P0.
- A signed receipt does not prove physical actuation.
- A durable restart represents a recovered dangling `PUBLISH_CALLED` as
  `UNKNOWN_AFTER_PUBLISH`, never as success, failure, or non-delivery. The current
  crate-private coordinator can create and recover that locally sync-confirmed
  sequence, but no runnable service yet makes the path mandatory or proves a real
  publisher call.
