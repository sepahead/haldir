# Claim ledger

Every load-bearing statement Haldir makes about itself has a claim id, a status,
and a pointer to the evidence that backs it — or an explicit note that it is
unproven, deferred, or out of scope. This ledger is the single place where claims
and evidence are reconciled; the drift guard `tools/verify-claims.py` treats any
doc line citing a `CL-` id as scoped, so overclaims must be entered here honestly
rather than asserted loosely elsewhere.

Scope: this repository implements the **P0 `assurance-reference-v1`** profile —
the repaired, in-process pure core. See `docs/ASSURANCE-PROFILES.md` for the
profile matrix and `docs/LIMITATIONS.md` for what P0 deliberately does not do.

## Status vocabulary

- **PROVEN** — backed by code plus an automated test or CI gate in this repo.
- **PARTIAL** — mechanism implemented; coverage or an external gate is still open.
- **PENDING** — implemented but its evidence gate has not yet run green in CI.
- **UNPROVEN** — asserted nowhere as an affirmative property; would require a
  capability (live transport, hardware, a neural backend) absent from P0.
- **OUT OF SCOPE** — intentionally deferred to a later profile (P1+); not a gap
  in P0.

## Proven in P0 (code + test/CI evidence)

| Claim | Statement | Status | Evidence |
| --- | --- | --- | --- |
| CL-CBOR-01 | Wire encoding is strict deterministic CBOR: integer keys, shortest ints, no floats/tags/indefinite, and every value re-encodes to identical bytes. | PROVEN | `haldir-contracts` cbor tests + hostile-parser fuzz-smoke property tests |
| CL-COSE-01 | Every signed message is `COSE_Sign1`/Ed25519 with a domain-separated AAD (`{kind}.v{major}`) and a per-kind content type. | PROVEN | `haldir-crypto` cose tests |
| CL-TRUST-01 | The trust store admits an idempotent identical key record but rejects a second, conflicting record for the same key id. | PROVEN | `haldir-crypto` `duplicate_conflicting_kid_rejected` |
| CL-CHALLENGE-01 | Gate challenges are bounded and one-shot: duplicate or already-expired registration is rejected, expired entries are reclaimed, and successful consumption structurally removes the nonce and releases capacity. | PROVEN | `haldir-state` `challenge::tests` (duplicate, expiry-boundary, capacity-reuse, replay, and zero-capacity cases) |
| CL-GATE-MEDIATION-01 | Within P0, no unauthorized, misscoped, replayed, or malformed intent produces an accepted plant command; only a fully valid intent drives the reference plant. This is the P0 conjunction over the declared in-process route, not complete mediation of a real vehicle. | PROVEN | `haldir-range` adversarial campaign |
| CL-RECEIPT-01 | Every decision emits a `COSE_Sign1` `DecisionReceiptV1` signed by the Gate application key; the receipt verifies independently and is bound to the Gate's enrolled subject (H-B02/H-H03). | PROVEN | `haldir-gate` `decision_receipt_is_signed_and_verifies_to_gate_identity` |
| CL-IDENTITY-01 | Signer identities are bound to their roles and subjects: mission-authority to the lease issuer (H-H01), the controller-intent signer's trust-store subject to the claimed controller id (H-H02), the Gate signer to the Gate id (H-H03). | PROVEN | `haldir-gate` `accept_lease_env`, `spoofed_controller_id_denies`, receipt test |
| CL-ALLOW-HONEST-01 | An ALLOW receipt is stamped `AllowPrepared` with stage `OutputPrepared`, never `AllowPublished`: the Gate authorized and prepared exact output bytes and does not claim a downstream delivery it did not observe. | PROVEN | `haldir-gate` `decision_receipt_is_signed_and_verifies_to_gate_identity` (asserts `AllowPrepared`/`OutputPrepared`, not `AllowPublished`) |
| CL-ERROR-01 | Internal faults (fault latch, monotonic-clock regression, TOCTOU revision change, NCP build/validate failure) yield an ERROR outcome with no output, distinct from an authorization DENY (H-H10). | PROVEN | `haldir-gate` `clock_regression_latches_and_errors` |
| CL-LEASE-USAGE-01 | The Gate enforces per-lease total-intent and fixed-point rate limits; refill is from monotonic time only and never credited across a clock regression (H-B07). | PROVEN | `haldir-gate` `lease_usage_tests` |
| CL-PHASE-01 | A lease authorizes exactly one mission phase; an intent evaluated against a Gate-owned trusted state in a different phase is denied before policy runs (H-P04). | PROVEN | `haldir-gate` `mission_phase_mismatch_denies` |
| CL-STATE-DIGEST-01 | The canonical trusted-state digest commits every policy-relevant field; changing any single field changes the digest (H-B06). | PROVEN | `haldir-core` `digest_coverage` |
| CL-STATE-INGRESS-01 | Trusted-state ingress is validated (vehicle, session, source session, validity flag) and anti-rollback: a snapshot for another vehicle/session, a stale source, or a capture time that does not strictly advance is rejected, not blindly accepted (H-B05). | PROVEN | `haldir-gate` `set_trusted_state_rejects_bad_ingress`; `haldir-range` `stale_state_rollback_rejected` |
| CL-SLEW-01 | The slew bound scales with the actual monotonic time elapsed since the last published command (floored, capped at the nominal update); command bursts faster than nominal are not granted a full nominal step (H-P01). | PROVEN | `haldir-policy-native` `slew_bound_tracks_actual_elapsed_time` |
| CL-DUTY-01 | Duty accounting unions overlapping possibly-active horizons rather than summing them, and at capacity merges the closest pair rather than dropping an interval, so it never under-counts (H-P02/H-P03/H-B04). | PROVEN | `haldir-policy-native` `duty_union_does_not_double_count_overlap`, `bounded_history_merges_instead_of_dropping` |
| CL-FIXEDPOINT-01 | The native policy uses only integer / fixed-point arithmetic with widened comparisons; no floating point participates in an authorization decision. | PROVEN | `haldir-policy-native` `decide.rs` + tests |
| CL-DECISION-ID-01 | Decision ids are the domain-separated 128-bit digest of the full Gate boot id and a checked counter; exhaustion latches a fault and emits one reserved terminal receipt which is then replayed byte-for-byte rather than minting distinct decisions with a reused id (H-H06). | PROVEN | `haldir-gate` `decision_id_tests`, `decision_id_exhaustion_latches_error` |
| CL-FAULT-STATE-01 | Every actor fault latch also moves the public process state to terminal `FAULT_LATCHED`; the enforcement latch and reported lifecycle cannot disagree. | PROVEN | `haldir-gate` `clock_regression_latches_and_errors`, `decision_id_exhaustion_latches_error` |
| CL-CONFIG-01 | In-process Gate construction is fallible and rejects a zero lease cap, an unknown/revoked/wrong-role/development/wrong-subject/wrong-public-key Gate receipt signer, or a future NCP publication lease bound to another session/output epoch. Startup state transitions and boot-counter failures are propagated, never ignored. This does not validate the absent live ACL/route package. | PROVEN | `haldir-gate` Gate configuration tests; `VehicleActor::new` |
| CL-DURABLE-PRIMITIVE-01 | The storage primitive authenticates store/Gate/generation/predecessor/payload with HMAC-SHA256, requires explicit provisioning, reconciles only an authenticated exactly-next snapshot with an external compare-and-set anchor, and rejects missing anchors, rewind, fork, gaps, wrong keys/bindings, tampering, and overwrite provisioning. The Unix file backend performs bounded same-directory create/write/file-sync/rename/directory-sync and rejects symlinks; the anti-rollback wrapper changes live state only after commit, derives boot IDs from Gate ID + checked counter + injected entropy, persists the last ID, and rejects repeats. `begin_boot` rejects a Gate outside the authenticated binding and returns a non-cloneable booted-store capability only after a fresh commit; recovered Gate construction consumes that capability and requires its boot ID to match configuration. A store-unavailable lease-term commit grants no authority and latches a fault. This proves unit-tested mechanisms and injection, not runnable-service selection, an external anchor deployment, child-process crash recovery, power-loss durability, or Windows support. | PROVEN | `haldir-durable` RFC 4231/envelope/recovery/file tests; `haldir-state` boot-vector/binding/repeat/failure-order/reopen tests; `haldir-gate` recovered-startup/failure-latch tests |
| CL-NCP-MODEL-01 | The P0 modeled NCP adapter rejects source/output sequences above NCP's JSON-safe integer maximum and its exact prepared frame cannot be externally mutated; internal frame/bytes/digest/transformation drift is rejected. This is model hardening, not real NCP interoperability. | PROVEN | `haldir-ncp08` sequence-boundary and four validator-tampering tests |
| CL-NCP-REAL-01 | With the off-by-default `real-ncp` feature, Haldir constructs an upstream NCP v0.8.0 `CommandFrame` from Gate-owned semantics, validates before and after exact JSON serialization, and passes frozen-corpus/differential/tamper tests at the immutable NCP commit. This proves the adapter path, not Gate selection, Zenoh delivery, ACL exclusivity, or plant application. | PROVEN | `haldir-ncp08::real` tests; frozen corpus hashes enforced by `tools/verify-pins.py`; exact git source in `Cargo.lock` |
| CL-EVIDENCE-01 | Every decision (ALLOW or DENY) appends its signed receipt to a bounded, digest-chained in-process spool that stays verifiable; a full spool drops only the export copy and can never change a decision. The chain is in-process — crash-durability is out of P0 (`CL-DURABLE-01`). | PROVEN | `haldir-gate` `decisions_are_journaled_to_the_evidence_chain`; `haldir-evidence` chain tests |
| CL-INTEROP-01 | The `COSE_Sign1`/Ed25519 envelope and deterministic-CBOR payload codec are decoded and verified by an independent, dependency-free second implementation over shared vectors, which also rejects tampering and mismatched kind/key. Vectors cover every wire major type and integer width; per-contract schema vectors are a future extension. | PROVEN | `tools/interop/verify_cose.py` over `tools/interop/vectors.json` (emitted by `haldir-crypto` `emit_interop_vectors`); CI `interop` job |
| CL-CI-01 | The Rust quality gate (build, clippy `-D warnings`, tests, docs, fmt) runs on a single pinned toolchain reproducibly (H-B01). | PROVEN | `.github/workflows/ci.yml` `build-test`; `rust-toolchain.toml` |
| CL-CI-02 | Every third-party GitHub Action and the exact TLA+ release asset are pinned immutably; automated drift checks reject mutable refs/URLs or a missing digest verification. | PROVEN | `tools/verify-ci-pins.py`; CI `supply-chain`; `.github/workflows/formal.yml`; `tools/pins.toml` |
| CL-FORMAL-01 | The bounded TLA+ authority model (`RetiredNeverActive`, `NoOutputReuse`, `LeaseBindsCurrentIncarnation`) model-checks with no error under the pinned TLA+ v1.7.4 jar. | PROVEN | `formal/HaldirAuthority.tla`; exact jar digest in `tools/pins.toml`; GitHub formal run `29211573130` on commit `6ca5958` |

## Unproven or out of scope in P0 (require a later profile)

| Claim | Statement | Status | Evidence |
| --- | --- | --- | --- |
| CL-DURABLE-01 | Anti-rollback high-water and evidence survive a crash via durable authenticated storage. | OUT OF SCOPE | Authenticated snapshot/anchor primitives, a Unix atomic-file mechanism, a commit-before-mutation boot/high-water wrapper, and checked Gate injection exist (`CL-DURABLE-PRIMITIVE-01`), but no runnable service provisions/selects a deployed external non-rewindable anchor and evidence remains in-memory — see `docs/LIMITATIONS.md` |
| CL-LIVE-TRANSPORT-01 | The Gate is the only writer on a live NCP command route (ACL-exclusive publisher). | UNPROVEN | modeled adapter only; no live transport in P0. The `PRE_AUTHORITY_ACL_ONLY` label is declared, not a proven live firewall |
| CL-BACKEND-01 | The admitted neural backend is equivalent to a reference. | OUT OF SCOPE | admission is digest-equality only; no neural runtime and no backend equivalence is claimed in P0 |
| CL-HARDWARE-01 | Behaviour is validated on flight hardware. | UNPROVEN | simulation-only reference plant; nothing here is hardware validated or airworthy |
| CL-TIMING-01 | The Gate meets a real-time deadline. | UNPROVEN | no performance campaign was run; P0 makes no timing claim and is not hard real-time |
| CL-PRODUCTION-01 | The system is production ready. | UNPROVEN | P0 is a research/reference core and is not production ready; it is not certified for any operational use |

## Maintenance

When you add a mechanism, add or update its `CL-` row here and cite the test or
CI gate that proves it. When you change wording in an authored doc that touches a
high-risk phrase, cite the relevant `CL-` id on that line so the drift guard can
see it is reconciled here. A claim with no evidence pointer must read PARTIAL,
PENDING, UNPROVEN, or OUT OF SCOPE — never PROVEN.
