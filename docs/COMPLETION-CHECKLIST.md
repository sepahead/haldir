# Final completion checklist (P0)

The specification's Final Agent Completion Checklist, answered per item for the P0
`assurance-reference-v1` deliverable. **YES** = implemented + tested here;
**PARTIAL** = implemented within P0, full claim needs an out-of-scope campaign;
**NO (out of P0)** = deliberately deferred, mapped to `docs/LIMITATIONS.md`.
Every non-YES is a narrower experimental result, per the spec's down-label rule.

## Authority

- **PARTIAL** — In the modeled actor and retained synthetic ACL subset, controllers
  produce only `HaldirIntentV1` and configured controller principals cannot publish the
  final route; the final frame is Gate-authored. Runnable-service credential custody and
  complete-mediation/bypass evidence remain absent.
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
- **PARTIAL** — Actual route + principal bound: the actual key and application signer
  are bound in actor Stage 3, and the retained mTLS router campaign binds configured
  certificate principals to its tested route subset. No runnable Gate passes an
  authenticated transport identity into actor decisions.
- **PARTIAL** — NCP stream/source/session semantics: current P0 fixtures remain modeled,
  while a closed explicit exact-revision selection passes upstream validated JSON,
  frozen-corpus, differential, tamper, and actor-Called-boundary tests
  (`CL-NCP-REAL-01`). Requiring that selection and binding it to a publisher in a live
  Gate/Crebain deployment remain outstanding.
- **PARTIAL** — Exact prepared frames are immutable and every new logical command gets
  a new sequence (`output_stream`, `haldir-ncp08` tests). An internal consuming
  coordinator orders local receipt/Called/caller-asserted terminal evidence and blocks
  replacement after ambiguity, but no runnable worker binds one Called state to one
  transport call/result. The frame remains copyable and exactly-once submission is not
  enforced.

## Policy

- **YES** — Policy is pure, fixed-point, deterministic, bounded, profile-specific.
- **YES** — Inside policy/`decide_intent`, stale/missing state and arithmetic errors are
  no-output deny/error paths. Later publication-transition failures are separately
  classified and never rewrite the signed prepared receipt.
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

- **PARTIAL** — Decisions are reconstructable from bounded Gate-signed receipts and
  digest-separated domains. The internal coordinator locally append-and-`sync_data`-
  confirms publication stages, and startup reduces a recovered dangling Called trace to
  linked Unknown. Positive composition is test-only; mandatory service selection,
  Prepared abandonment/reclamation, coordinator fault injection, child-process crash,
  and power-loss behavior remain absent.
- **YES** — Evidence storage bounded; tamper/chain-break detected; full-spool drop
  never flips a decision.
- **PARTIAL** — The retained live mTLS/ACL campaign proves only the pinned synthetic
  command/intent subset (`CL-LIVE-TRANSPORT-01`). The remaining operation/route and
  certificate-lifecycle matrix, p99/p99.9 latency, and long-run resource campaign are
  still absent.
- **PARTIAL** — Exact commits/lockfile pinned and `pins.toml`/`verify-pins.py`
  present; SBOM/provenance/reproducible-release is a release-phase task.
- **YES** — Every push was normal and non-forced.

## Verdict

A single non-YES blocks the corresponding *stronger* assurance claim, exactly as
the spec requires. The delivered result is the P0 pure reference-monitor core; the
profile and `docs/LIMITATIONS.md` state precisely what remains unproven.

## Reproducing the P0-R exit gate

Run every offline acceptance check in one command:

```bash
bash tools/p0r-exit-gate.sh
```

It runs rustfmt, both feature-matrix Clippy gates (`-D warnings`), all-target /
all-feature tests and doc tests, warning-free docs, no-default and cold builds,
dependency policy, source/CI/formal/evidence/claim/generated-artifact verifiers,
diff hygiene, and the independent COSE/CBOR interop check (re-emit + diff +
verify). The pinned TLA+ model check runs in CI (`.github/workflows/formal.yml`,
`CL-FORMAL-01`) and can run locally when a JRE is available. Every claim these gates back is listed in
[`CLAIM-LEDGER.md`](CLAIM-LEDGER.md).
