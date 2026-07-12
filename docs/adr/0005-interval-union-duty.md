# ADR-0005 — Interval-union duty accounting with fail-closed bounded merge

Status: accepted

## Context

The duty limit caps aggregate non-hold command validity within a sliding window.
Published command horizons overlap (a new command is issued while the previous is
still valid). Two failure modes threaten the limit:

1. Summing per-command overlaps double-counts the shared time, over-charging duty
   and wrongly denying legitimate activity.
2. A fixed-size ring of intervals, under a high command rate, silently drops the
   oldest still-active interval — under-counting duty and *defeating* the limit.

Under-counting is a safety hole; over-counting is merely restrictive.

## Decision

Maintain the history as a sorted set of **disjoint** intervals — the union of the
possibly-active horizons. Inserting a command unions it with any interval it
overlaps or touches, so back-to-back commands collapse into one entry and the
count stays small regardless of command rate. If the disjoint set still exceeds
the retained bound, merge the pair separated by the smallest gap rather than
dropping one; this over-approximates duty (it counts the gap as active) and so can
only ever deny more, never allow more.

## Consequences

- Duty is exact when memory suffices and conservatively high under pressure, never
  under-counted. The limit cannot be defeated by flooding commands.
- The merge is O(n) per over-capacity insert; n is bounded by `max_intervals`.

## Evidence

`haldir-policy-native` `BoundedActionHistory`; `duty_union_does_not_double_count_overlap`,
`bounded_history_merges_instead_of_dropping` (`CL-DUTY-01`).
