# ADR-0009 — Checked policy arithmetic, conservative projection, and a complete bounded reason vector

Status: accepted

## Context

Haldir's native policy makes authorization decisions at exact numeric boundaries.
The decision must be reproducible from the signed inputs, must not gain authority
through overflow or rounding, and must explain every policy predicate that refused
an otherwise well-formed request. Three choices are therefore coupled:

1. the arithmetic representation used by policy and signed action contracts;
2. the software projection used for the prospective geofence; and
3. the shape and bound of a policy DENY's reason output.

These choices define software authorization semantics. They cannot establish the
truth of caller-supplied state or a physical vehicle's reachable set.

## Decision

### Checked fixed-point arithmetic

Use integer units in signed authority, policy, replay, state, and action objects:
millimetres, millimetres per second, millimetres per second squared,
milliseconds, and monotonic nanoseconds. Policy predicates use checked arithmetic
or a widened integer type before comparison. Division rounds in the conservative
direction selected by the predicate. Saturation is permitted only where the
specified one-way result cannot widen authority, such as subtracting a safety
margin from validity. An unrepresentable calculation never wraps or becomes an
ALLOW boundary value.

The precise reason is that the policy needs one canonical, bounded comparison for
each accepted input. Integer units avoid NaN, infinities, signed zero, multiple
representations of the same accepted contract value, and an implicit tolerance at
an authorization boundary. Widened comparisons also avoid square roots for vector
norms and retain exact sub-millisecond duty accounting.

### Conservative prospective geofence

For each axis, project an outward-rounded interval from the trusted snapshot's
capture time through the complete candidate horizon. The velocity interval contains
both the requested velocity and measured velocity plus or minus supplied velocity
uncertainty. Expand the projected position by supplied position uncertainty,
configured tracking error, and policy margin. Require the complete interval to lie
strictly inside the configured axis-aligned region; touching or crossing a boundary
denies.

The precise reason is that a current-position check, a decision-time-only
projection, or a requested-velocity-only projection can omit already elapsed state
age, measured motion, or an admitted uncertainty extreme. Outward rounding ensures
that discarded fractional millimetres cannot shrink the software envelope.

### Complete bounded denial reasons

Evaluate the fixed predicate order without stopping at the first ordinary policy
failure. Retain each distinct stable reason code, order hard denies before other
denials while preserving deterministic evaluation order within each class, and
return the complete current result in the signed schema's 32-slot bounded vector.

The precise reason is that first-failure output hides simultaneous independent
refusals and makes an operator or verifier infer which later predicates were never
reported. An unbounded vector would violate the fixed resource and signed-schema
contract. The current closed evaluator has fewer than 32 distinct reason codes
reachable in one decision, so 32 preserves its complete result while matching the
existing signed envelope and leaving bounded schema evolution room. The number 32
is a representation ceiling, not a claim about threat prevalence, policy quality,
or the number of physically independent hazards.

## Alternatives considered and rejected or deferred

- **Binary floating point in policy.** Rejected for this profile. It would require
  separate canonical special-value, rounding-order, conversion-error, and boundary-
  tolerance rules. This is not a general claim that floating point cannot be used
  safely; those additional rules and proofs do not exist for Haldir's signed policy.
- **Arbitrary-precision decimal or rational arithmetic.** Deferred. It can represent
  exact quantities but adds a new canonical representation and a separately bounded
  allocation/work contract without improving the current integer-unit predicates.
- **Unchecked, wrapping, or authority-increasing saturation.** Rejected because an
  out-of-range calculation could re-enter the accepted domain. Documented
  authority-reducing saturation remains admissible.
- **Current-position, requested-velocity-only, or decision-time-only geofencing.**
  Rejected because each can understate the declared software interval.
- **A stochastic trajectory or physical reachable-set calculation.** Deferred until
  independently authenticated and validated dynamics, localization, disturbance,
  actuator, braking, overshoot, and vehicle-geometry bounds exist. Naming an
  unevidenced dynamics model would overstate the present claim.
- **A norm ball instead of per-axis intervals.** Rejected for the current
  axis-aligned policy region because it changes the admitted envelope and still
  supplies no physical dynamics proof.
- **Return only the first denial.** Rejected because it discards known simultaneous
  policy evidence.
- **Return an unbounded list or bind the schema to today's exact reason count.** The
  former is rejected as an output-resource hazard. The latter is rejected because
  every new predicate would require an otherwise unnecessary wire-shape change; the
  fixed 32-slot ceiling remains bounded and already exceeds the current evaluator's
  complete result.

## Assumptions and invariants

- Signed numeric fields use their declared integer units and canonical encodings.
- The configured coordinate frame, axis-aligned region, margins, and policy limits
  have the intended mission meaning. Policy evaluation does not establish that fact.
- The trusted-state position, velocity, and uncertainty fields have already passed
  the local structural and freshness boundary. The current repository does not
  authenticate a live state producer or prove physical truth.
- The per-axis velocity interval is a conservative configured software input, not a
  claim that physical velocity remains inside it.
- The current evaluator's distinct reachable reason set fits in 32 slots. A future
  change must preserve that invariant or revise the schema and implementation; it
  must not silently describe a truncated vector as complete.
- Earlier duty and slew decisions remain governed by
  [ADR-0008](0008-exact-action-history-accounting.md) and
  [ADR-0006](0006-elapsed-time-slew.md).

## Output and failure semantics

- If every predicate succeeds, policy returns `Allow` with the checked effective
  validity. ALLOW carries no denial reasons.
- An ordinary boundary failure returns `Deny` with every distinct reason found by
  the current evaluator, subject to the invariant above.
- Invalid executable policy or malformed retained history required by a velocity
  decision is a typed evaluation error, not a controller policy denial. The
  integrated Gate reports ERROR, emits no command, and fault-latches where its
  lifecycle contract requires it.
- An overflow or unrepresentable projection fails closed at its owning predicate or
  typed invariant boundary. It never produces ALLOW. Hold deliberately remains
  independent of malformed motion-duty history so a stop command is not lost merely
  because motion accounting is broken.

## Consequences

- Policy decisions and reason order are deterministic over accepted inputs.
- Conservative rounding and interval construction can deny a request that a richer
  validated dynamics model might accept. That restrictive bias is intentional.
- Complete reason output improves auditability but is not causal diagnosis: several
  reasons can arise from one bad input, and one reason can have several causes.
- Integer units have finite range and resolution. Checked failure is part of the
  contract, not evidence that the represented physical state is accurate.

## Evidence and claim ceiling

`haldir-contracts` fixes the integer-unit and bounded-reason wire shapes.
`haldir-policy-native` tests component/norm boundaries, measured acceleration,
uncertainty, conservative age rounding, outward geofence projection, overflow,
effective validity, exact duty accounting, reason ordering, and Gate integration
(`CL-FIXEDPOINT-01`, `CL-DUTY-01`, `CL-SLEW-01`, `CL-ERROR-01`).

That evidence establishes deterministic local software-envelope evaluation for the
tested Rust composition. It does not establish authenticated state provenance,
calibrated margins, a physical reachable set, containment, stopping distance,
vehicle stability, real-time execution, deployment suitability, or physical safety.
