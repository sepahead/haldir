# Haldir 0.9 migration record

This record satisfies the per-requirement migration-note obligation for the
0.9 qualification program. An entry saying “none” means that the task changes
qualification artifacts or semantics documentation only; it does not hide an
unreviewed wire, API, data, deployment, or consumer conversion.

| Requirement | Change class | Wire/API/data impact | Required consumer or operator action | Automated conversion |
| --- | --- | --- | --- | --- |
| `HALDIR-0.9-T000` | release qualification provenance | None. The immutable audit cut and retained baseline add release-only files. | Preserve the exact source/dependency/NCP/deployment/evidence identities when reproducing the cut. | Not applicable; verification is provided by `verify-audit-inputs.py`. |
| `HALDIR-0.9-T001` | normative semantic clarification | No Rust API or wire change. The operational term “plant command” includes unauthorized final-route bypass frames; decisions remain `ALLOW`/`DENY`/`ERROR`, while `HOLD` is an action. | Documentation or consumers that called `HOLD` a denial/ESTOP must update terminology; no byte conversion can safely guess the intended semantic correction. | None; the authority-model verifier detects contradictory vocabulary and profile grants. |
| `HALDIR-0.9-T002` | closed protection inventory | No Rust API, wire, or stored-data change. Transport principals/CNs, role-to-object signature domains, logical subjects, clocks, and roots are explicitly non-interchangeable. | Operators and consumers must keep signing secrets and transport credentials with their named custodians, use Gate-origin monotonic time for freshness, treat controller/source timestamps as provenance, preserve default deny, and avoid inferring route grants or signed-object domains from role names. | None; the protection-model verifier checks the exact current profile, access tuples, custody, constraint bindings, and source contracts. |

## Post-qualification experimental API changes

The workspace crates remain unpublished and explicitly experimental. Ordinary
hardening after the qualification tasks can therefore tighten source APIs, but
the required migration remains recorded rather than hidden.

### Exact action history

- Replace `BoundedActionHistory::new(capacity)` with
  `BoundedActionHistory::new(capacity, retention_window)` and handle its
  `Result`. Replace `BoundedActionHistory::default()` the same way; history no
  longer has a context-free default because its retention window is a required
  policy invariant.
- Do not construct or mutate history fields. Use the read-only accessors and the
  fallible `record_hold`, `record_velocity`, `validate_for_policy`, and
  `active_duration_in_window` methods. `record_velocity` no longer accepts a
  caller-selected eviction cutoff; the history derives it from its owned window.
- Replace removed whole-millisecond `active_ms_in_window` calls with exact
  `MonoDuration` accounting and handle `ActionHistoryError`.
- Integrated monitors should use `try_decide` or `try_decide_validated` and treat
  `PolicyEvaluationError` as an internal fault. The existing `decide` wrappers
  remain fail-closed but intentionally collapse internal errors to
  `DenyPolicyDiagnostic`.
- Use `MonoDuration::from_nanos`, `checked_from_millis`, or
  `saturating_from_millis` explicitly. The ambiguous saturating
  `from_millis` constructor is deprecated. Standard-library durations convert
  through checked `TryFrom<std::time::Duration>` and infallible conversion in
  the other direction.
- Public configuration, startup, evaluation, history, and publication errors
  added by this change are non-exhaustive. Downstream matches require a wildcard;
  use stable reason codes for diagnostics. Wrapper variants expose an
  `Error::source` when their nested error implements `Error`.

No wire or stored-data conversion exists: action history remains actor-local and
is rebuilt through validated Gate construction.

The release remains NO-GO. These entries do not promise compatibility for later
implementation tasks; each later requirement must add its own row before it can
close.
