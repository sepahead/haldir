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
Sub-token division remainder is carried exactly between calls. A caller therefore
cannot suppress legitimate refill by forcing repeated checks at intervals shorter
than one micro-intent, and elapsed credit beyond a full bucket is discarded rather
than becoming a hidden future burst.
The total-intent ceiling is checked before the rate bucket. Every fresh intent
that passes structural, cryptographic, scope, and replay checks is charged once
against the finite total before the rate result is returned. A rate/total refusal
is a DENY that still spends both the replay sequence and (when not already
exhausted) that presented intent's total-budget unit. This prevents an authorized
rate-denied flood from doing unbounded verification/replay work without ever
reaching `max_total_intents`.

## Consequences

- Limits are deterministic and integer-exact; no float participates.
- Adversarial sub-quantum call cadence cannot erase fractional refill credit.
- A rewound clock cannot manufacture refill tokens.
- Charging after replay-commit means a rate-limited intent cannot be retried at
  the same position — consistent with "a real intent was received and refused".
- Charging the total before the rate result makes the lease's total a bound on
  authenticated presented intents, not only on policy-evaluated successes.

## Evidence

`haldir-gate` `LeaseUsage`; `lease_usage_tests` (`CL-LEASE-USAGE-01`).
