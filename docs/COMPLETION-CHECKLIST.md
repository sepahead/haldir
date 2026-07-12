# Final completion checklist (P0)

The specification's Final Agent Completion Checklist, answered per item for the P0
`assurance-reference-v1` deliverable. **YES** = implemented + tested here;
**PARTIAL** = implemented within P0, full claim needs an out-of-scope campaign;
**NO (out of P0)** = deliberately deferred, mapped to `docs/LIMITATIONS.md`.
Every non-YES is a narrower experimental result, per the spec's down-label rule.

## Authority

- **YES** — Controller lacks every final plant-command credential. Controllers only
  produce `HaldirIntentV1`; the modeled final frame is Gate-authored (`actor.rs`).
- **YES** — Gate alone originates final NCP frames (`haldir-ncp08`, `actor.rs` Stage 12).
- **YES** — Mission lease, admission, policy, session, Gate output stream,
  controller intent stream, boot id, and ACL-exclusive publication are separate
  identities/types (`ids.rs` B5 newtypes; state machines).
- **YES** — Restart invalidates active controller delegation (fresh boot id; state
  `restart_invalidates_lease_via_new_boot_id`).
- **PARTIAL** — Revocation can preempt command traffic: the revocation snapshot and
  admission/lease term anti-rollback are implemented and tested; a *live* control-
  priority-under-flood test needs the transport runtime (out of P0).

## Protocol

- **YES** — All Haldir authority objects canonical + signed (contracts + crypto).
- **YES** — Parser/size limits before expensive work (ingress cap before verify).
- **PARTIAL** — Actual route + principal bound: the actual key and application
  signer are bound (`actor.rs` Stage 3); the *authenticated transport principal*
  binding needs live mTLS (out of P0).
- **PARTIAL** — NCP stream/source/session semantics: modeled exactly and pinned by
  digest; upstream frozen-corpus conformance is out of P0 (modeled adapter).
- **YES** — A retry is byte-identical and a new logical command is a new sequence
  (`output_stream`, `haldir-ncp08` tests).

## Policy

- **YES** — Policy is pure, fixed-point, deterministic, bounded, profile-specific.
- **YES** — Stale/missing state and arithmetic errors are deny paths.
- **YES** — Limits intersected, not overwritten (lease ∩ policy).
- **N/A** — Cedar is not enabled in P0 (native policy only).

## Plant

- **YES (P0/simulation)** — The reference plant is the sole actuator owner with one
  ingress; safe action is plant-owned, named (`reference-kinematic-hold-v1`), and
  measured in ticks. Received/accepted/selected/applied/observed are distinct.
- **NO (out of P0)** — Crebain `CommandPlant`, real MAVROS/ROS/browser path closure,
  and physical actuation. `applied`/`observed` are simulation model values.

## Neural / backend

- **NO (out of P0)** — NEST/Engram controller; controller-artifact clean-room
  reconstruction; backend behavioural evidence. Admission is digest-equality only;
  Lava is absent; NIR/XyloSim not attempted.

## Evidence and operations

- **YES** — Decisions reconstructable from bounded signed-shape events; digest
  domains separated; `UNKNOWN_AFTER_PUBLISH` for crash tails.
- **YES** — Evidence storage bounded; tamper/chain-break detected; full-spool drop
  never flips a decision.
- **NO (out of P0)** — Live mTLS/ACL delivery matrix; p99/p99.9 latency; long-run
  resource campaign.
- **PARTIAL** — Exact commits/lockfile pinned and `pins.toml`/`verify-pins.py`
  present; SBOM/provenance/reproducible-release is a release-phase task.
- **YES** — Every push was normal and non-forced.

## Verdict

A single non-YES blocks the corresponding *stronger* assurance claim, exactly as
the spec requires. The delivered result is the P0 pure reference-monitor core; the
profile and `docs/LIMITATIONS.md` state precisely what remains unproven.
