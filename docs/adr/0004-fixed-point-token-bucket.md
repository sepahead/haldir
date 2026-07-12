# ADR-0004 — Fixed-point, monotonic-only token bucket for lease usage limits

Status: accepted

## Context

A lease authorizes a bounded intent rate and a bounded total number of intents
(H-B07). A floating-point rate limiter would introduce non-determinism and
rounding drift into an authorization decision. A wall-clock limiter could be
rewound. A naive per-second counter cannot express sub-second bursts or refill.

## Decision

Enforce usage with a fixed-point token bucket denominated in micro-intents
(`TOKEN_SCALE = 1_000_000`). Burst capacity is one second of authorized intents
(at least one). Refill is computed only from positive elapsed **monotonic** time
(`rate_millihz * elapsed_ns / 1_000_000`), so a clock regression credits nothing.
The total-intent ceiling is checked before the rate bucket. Usage is charged once,
after an intent passes structural, cryptographic, scope, and replay checks — a
rate/total refusal is a DENY that still spends the replay sequence.

## Consequences

- Limits are deterministic and integer-exact; no float participates.
- A rewound clock cannot manufacture refill tokens.
- Charging after replay-commit means a rate-limited intent cannot be retried at
  the same position — consistent with "a real intent was received and refused".

## Evidence

`haldir-gate` `LeaseUsage`; `lease_usage_tests` (`CL-LEASE-USAGE-01`).
