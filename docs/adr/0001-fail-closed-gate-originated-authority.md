# ADR-0001 — Fail-closed reference monitor; the Gate originates every final command

Status: accepted

## Context

Haldir sits between an untrusted controller and the plant. A controller could try
to reach the plant directly, replay an old command, or coax the Gate into
forwarding controller-supplied bytes. A monitor that forwards or blesses external
bytes inherits whatever the attacker put in them.

## Decision

The Gate is a fail-closed reference monitor. It never forwards controller bytes.
On ALLOW it *originates* a fresh NCP command frame under its own stream position,
output epoch, and creation time, from validated fields only. Any missing
precondition, internal fault, or ambiguity detected before the publication-call
boundary denies (or errors) without exposing output. After exact bytes are exposed,
an ambiguous reported return fault-latches and blocks actor-issued replacement; the
future durable reducer must recover that tail as `UnknownAfterPublish`. The
authorization state for one vehicle is owned by a single actor; a revision counter
captured at decision start is re-checked immediately before output allocation so a
concurrent invalidation cannot slip a stale ALLOW through (TOCTOU close).

## Consequences

- The plant command is a function of Gate-validated state, not controller framing.
- Every not-ALLOW path must be explicitly enumerated; there is no default-allow.
- The cooperative publisher is part of the P0 trusted computing base after first
  byte access; the runnable service must own call discipline and durable stage updates.
- The Gate must hold the sole capability to publish the final command key; in P0
  this is modeled, not a live ACL (see ADR-0007 and `CL-LIVE-TRANSPORT-01`).

## Evidence

`haldir-gate` `actor.rs` 13-stage pipeline; `haldir-range` adversarial campaign
(`CL-GATE-MEDIATION-01`).
