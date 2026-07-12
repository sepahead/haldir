# Architecture decision records

Each ADR records one load-bearing design decision, the forces behind it, and the
consequences we accepted. They explain *why* the code is shaped the way it is; the
*what* lives in the code and the *claims* live in [`../CLAIM-LEDGER.md`](../CLAIM-LEDGER.md).

| ADR | Decision |
| --- | --- |
| [0001](0001-fail-closed-gate-originated-authority.md) | Fail-closed reference monitor; the Gate originates every final command |
| [0002](0002-deterministic-cbor-and-cose.md) | Strict deterministic CBOR + domain-separated COSE_Sign1/Ed25519 |
| [0003](0003-error-vs-deny-outcomes.md) | Separate ERROR (internal fault) from DENY (authorization refusal) |
| [0004](0004-fixed-point-token-bucket.md) | Fixed-point, monotonic-only token bucket for lease usage limits |
| [0005](0005-interval-union-duty.md) | Interval-union duty accounting with fail-closed bounded merge |
| [0006](0006-elapsed-time-slew.md) | Elapsed-time slew bound, capped at the nominal update period |
| [0007](0007-p0-scope-and-deferrals.md) | In-process P0 scope; durable storage and live transport deferred |

Format: Context → Decision → Consequences → Evidence. Supersede an ADR by adding a
new one that references it, never by silently editing the old decision.
