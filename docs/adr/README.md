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
| [0005](0005-interval-union-duty.md) | Interval-union duty accounting with fail-closed bounded merge (superseded by 0008) |
| [0006](0006-elapsed-time-slew.md) | Elapsed-time slew bound, capped at the nominal update period |
| [0007](0007-p0-scope-and-deferrals.md) | In-process P0 scope; durable storage and live transport deferred |
| [0008](0008-exact-action-history-accounting.md) | Exact, validated action-history accounting |
| [0009](0009-checked-policy-arithmetic-and-complete-reasons.md) | Checked fixed-point policy, conservative projection, and a complete bounded reason vector |
| [0010](0010-reserve-before-mutate-publication-coordinator.md) | Reserve-before-mutate, single-slot publication coordination |

For each new or superseding record, state: context; selected technique and precise
reason; alternatives and rejection/defer rationale; assumptions; output and failure
semantics; consequences; and evidence/claim ceiling. Supersede an ADR by adding a
new one that references it, never by silently editing the old decision.

## Twenty-lens decision review

The following lenses are a repeatable internal review method. They are not a
claim that 20 independent people reviewed a decision. The “council” is a set of
deliberately different professional perspectives applied to the same record. A
human owner remains responsible for acceptance.

| Lens | Question that must be answered | Failure disposition |
|---:|---|---|
| 1 | What exact problem and authority boundary does the decision address? | Reject a mechanism-first record. |
| 2 | Which input identities, provenance, units, and coordinate frames are trusted? | Block execution when a required identity is absent or ambiguous. |
| 3 | Which output can change authority, state, evidence, or plant-facing bytes? | Remove any undeclared influence edge. |
| 4 | Why is the selected technique suitable for this exact contract? | Keep the decision open until the fit is demonstrated. |
| 5 | Which alternatives were rejected or deferred, and on what evidence? | Do not treat an unexamined alternative as inferior. |
| 6 | Which numeric representation and rounding direction are constitutive? | Fail closed on overflow, ambiguity, or authority-increasing rounding. |
| 7 | Are boundary equalities, half-open intervals, and time origins explicit? | Reject unspecified edge behavior. |
| 8 | Is ordering deterministic across inputs, reasons, records, and serialization? | Reject nondeterministic authority or evidence bytes. |
| 9 | Which state transitions consume, return, or strand authority-bearing capability? | Make unsafe continuation unrepresentable or fatal. |
| 10 | Can concurrency reorder, duplicate, or replay an effect? | Serialize the path or prove the stronger concurrent protocol. |
| 11 | Are memory, record count, work, and queue capacity bounded before mutation? | Return typed unavailability before authority mutation. |
| 12 | Are DENY, ERROR, unavailable, ambiguous, and externally unconfirmed states distinct? | Preserve the most conservative typed outcome. |
| 13 | What can be retried, and what becomes non-retryable after possible exposure? | Do not retry across an ambiguous side-effect boundary. |
| 14 | What does local persistence prove, and what storage or power-loss behavior remains external? | Narrow the evidence claim to the observed boundary. |
| 15 | Can recovery reconstruct one deterministic safe state from every retained prefix? | Stop when a prefix has more than one authority interpretation. |
| 16 | Which lower APIs, credentials, transport paths, or operator actions can bypass the composition? | Record the bypass as an open deployment obligation. |
| 17 | Are evidence minimization, sensitive fields, retention, and access ownership explicit? | Remove unnecessary data or add a bounded privacy contract. |
| 18 | Do schemas, versions, domain separators, and downstream interpretations remain non-aliased? | Require an explicit versioned migration. |
| 19 | Do unit, property, hostile, recovery, mutation, and integration tests isolate the claimed predicate? | Strengthen the test before raising the claim. |
| 20 | Are the owner, evidence cut, acceptance state, claim ceiling, and reopen conditions recorded? | Keep the ADR proposed or supersede it. |

## Review council and selection rule

Apply the lenses from ten perspectives: authority and safety, protocol and
distributed systems, evidence and forensics, Rust ownership and API design,
numeric analysis, operations and recovery, security and bypass analysis,
privacy and minimization, interoperability, and human factors. Each perspective
must nominate its strongest design and its strongest objection.

The owner selects the best overall design by lexicographic rule, not by averaging
scores:

1. reject any option that can widen authority under an admitted failure;
2. among the survivors, prefer the option with explicit deterministic semantics;
3. then prefer the smallest state space and least ambient input;
4. then prefer the option with the strongest predicate-isolating evidence;
5. use performance or convenience only after the first four criteria tie.

This rule explains why restrictive designs such as checked integer policy,
reserve-before-mutate publication, one in-flight output, and terminal ambiguity
win the current profile. A future design can supersede them only with a stronger
record that preserves the authority boundary and closes the new state space.
