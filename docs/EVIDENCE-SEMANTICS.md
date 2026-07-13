# Evidence semantics (P0)

## Staged, not a boolean "executed"

Publication is never atomic with a receipt, so evidence uses stages, not a false
`executed` flag. `PublishStageV1` (in `haldir-contracts`) defines the vocabulary,
including `UNKNOWN_AFTER_PUBLISH` for a crash between publish and acknowledgement.
The P0 actor does not yet durably append or recover publication-stage transitions,
so it cannot yet emit that crash-tail stage; the enum is the shared vocabulary for
the later durable reducer, not evidence that reducer already exists.

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

## Honesty rules

- A publish/prepare stage is never automatically upgraded to `received` /
  `accepted` / `applied`.
- `applied` and `observed response` are reference-plant model values in P0.
- A signed receipt does not prove physical actuation.
- A future durable reducer must represent ambiguous crash tails as
  `UNKNOWN_AFTER_PUBLISH`, not guess; the current in-memory actor fault-latches an
  explicitly reported error/timeout but cannot recover a process-crash tail.
