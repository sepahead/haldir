# Evidence semantics (P0)

## Staged, not a boolean "executed"

Publication is never atomic with a receipt, so evidence uses stages, not a false
`executed` flag. `PublishStageV1` (in `haldir-contracts`) defines the vocabulary,
including `UNKNOWN_AFTER_PUBLISH` for a crash between publish and acknowledgement.
The canonical linked stage payload and a retained-state-bounded pure reducer now exist
(`CL-PUBLICATION-EVIDENCE-PRIMITIVE-01`), but the P0 actor/manager/startup do not yet
sign, append, replay, or recover those transitions. The runtime therefore cannot yet
emit a crash-tail stage; the tested reducer is a prerequisite, not evidence of wiring.

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

The assurance-only Gate adapter closes that semantic gap offline for the two-record
publication journal profile. It binds footer and record KIDs to the same unrevoked
Gate-application assurance key/subject, dispatches only protected receipt/stage
content types, enforces the current Gate receipt shape and segment Gate/producer boot,
and consumes one ordered recovery snapshot to build fresh publication state. Empty
segments participate in boot chronology; boot resurrection and same-boot segment or
record time regression fail closed. This still does not authenticate the newly created
current tail as a durably committed Gate boot or append any recovery event.

## Honesty rules

- A publish/prepare stage is never automatically upgraded to `received` /
  `accepted` / `applied`.
- `applied` and `observed response` are reference-plant model values in P0.
- A signed receipt does not prove physical actuation.
- A future durable reducer must represent ambiguous crash tails as
  `UNKNOWN_AFTER_PUBLISH`, not guess; the current in-memory actor fault-latches an
  explicitly reported error/timeout but cannot recover a process-crash tail.
