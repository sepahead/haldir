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
- **PARTIAL** — A strict signed deployment-package contract, separately passed exact-policy verifier,
  exact owned-artifact resolver, bounded Linux/macOS source from a caller-supplied open directory, and
  atomic store-global package-plus-boot ratchet for one authenticated Gate binding are tested
  (`CL-DEPLOYMENT-PRIMITIVE-01`). No Gate startup consumes the resolved/package-booted stages,
  authenticates/protects artifact-root or credential acquisition, semantically uses the artifacts,
  or makes their selections mandatory
  (`CL-DEPLOYMENT-PACKAGE-01`).
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
  certificate principals to its tested route subset. The development bind target records Zenoh's
  operational ZID as non-authoritative and never processes an event; no Gate passes an
  authenticated transport identity into actor decisions.
- **PARTIAL** — NCP stream/source/session semantics: current P0 fixtures remain modeled,
  while a closed explicit exact-revision selection passes upstream validated JSON,
  frozen-corpus, differential, tamper, and actor-Called-boundary tests
  (`CL-NCP-REAL-01`). Template startup's explicit `DeclaredLiveZenoh` profile now requires
  that exact selection and the compiled `live-zenoh` feature before startup-owned backend
  calls, entropy, locks, or directories. Successful declared-live startup separately mints
  the private move-only capability required by the live coordinator; exact reference and
  forged-report paths cannot mint it. The declaration remains cooperative, process-local,
  and bypassed by direct actor construction. A public no-network kernel can consume the marked
  coordinator plus one bounded caller-supplied initial state/challenge/signed lease, and it
  validates the signed intent route against the canonical verified-controller route before the
  lease becomes active. The lower public service can consume only that route-bound result plus a
  preconstructed matched publisher. The outer aggregate instead consumes that result and one
  supplied session wrapper, internally deriving the publisher and exact ingress from the same
  lineage. Separate development examples explicitly provision then `OpenExisting`-open that path
  for immediate bind/shutdown only; they do not authenticate/refresh control inputs, protect
  credential custody, process an intent, or select a Crebain deployment. Retained evidence proves
  only the strict-session-open, aggregate-bind, and immediate aggregate-shutdown local returns
  with zero processing/publication (`CL-LIVE-GATE-DEV-BIND-01`).
- **PARTIAL** — Exact prepared frames are immutable and every new logical command gets
  a new sequence (`output_stream`, `haldir-ncp08` tests). An internal consuming
  coordinator orders local receipt/Called/terminal evidence and blocks replacement after
  ambiguity. Its off-by-default live typestate is reachable only through the startup-minted
  capability and is the only Called type exposing the concrete method. It rejects a concrete
  publisher whose exact route differs from the actor realm/session before frame access or
  invocation, then consumes a matched publisher around one awaited call and returns that
  capability only after local `Ok` plus terminal journal success. A public non-cloneable
  service kernel adds an internal capacity-one pool and returns itself only on safe
  continuation. An initially inactive marked actor is tested through local state/challenge/lease
  activation, canonical intent-route binding, and fake-publisher service binding. A separate
  fake session/ingress facade tests the outer aggregate's derivation, journal-capacity
  retention/retry, closure, drops, and shutdown ordering. Its local stop-only handle is tested
  before receive, before a retained retry, and during an in-flight publication; the latter reaches
  its ordinary transition before the latched request is returned, and the underlying race helper
  wakes a pending idle operation. Dropping a pending shutdown-aware future is separately tested to
  destroy the owners and make the handle reject another request. The latch remains cooperative:
  successful request acceptance is not cleanup acknowledgment, legacy `process_next` ignores it,
  and clones must be restricted. This does not establish an in-flight timeout, OS-signal runner,
  journal finalization, remote session retirement, or graceful production shutdown. Service result, cold/pending-drop, rejection, and terminal-fault
  tests still use a fake publisher rather than a live session. The development target binds and
  immediately shuts down without calling the processing/publisher path. No authenticated protected-
  credential package, control loop, or publisher worker selects it; lower APIs remain bypasses, the frame
  remains copyable there, and exactly-once submission is not enforced.

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
  linked Unknown. Its test-only matrix covers cold drop, pending timeout-as-drop, panic
  unwind, definite pre-terminal-append failure, and synthetic ambiguity after a real
  terminal append/sync. Production declared-live startup code with injected in-memory backends
  plus the actual journal manager is tested through live coordinator construction only.
  Separately, a test-minted marked capability around an initially inactive actor and the actual
  journal manager exercises bounded local activation, canonical route capability, and fake-
  publisher service binding; fake session/ingress tests exercise only aggregate orchestration,
  while decision/Called result and fault composition remains publisher-seam-only. The retained
  development smoke separately exercises concrete session open, aggregate bind, and immediate
  local shutdown, but no decision or publisher path (`CL-LIVE-GATE-DEV-BIND-01`). An
  executable authenticated service package, Prepared abandonment/reclamation, OS-level append/write/
  `sync_data` or disk-full fault injection, live-session faults, panic-abort/supervisor handling, child-process
  crash, and power-loss behavior remain absent.
- **YES** — Evidence storage bounded; tamper/chain-break detected; full-spool drop
  never flips a decision.
- **PARTIAL** — The retained live mTLS/ACL campaign proves only the pinned synthetic
  command/intent subset (`CL-LIVE-TRANSPORT-01`), while the separate retained development Gate
  campaign proves only immediate local bind/shutdown with zero processing/publication
  (`CL-LIVE-GATE-DEV-BIND-01`). The remaining operation/route and certificate-lifecycle matrix,
  p99/p99.9 latency, and long-run resource campaign are absent.
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
