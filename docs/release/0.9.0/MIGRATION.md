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

The release remains NO-GO. These entries do not promise compatibility for later
implementation tasks; each later requirement must add its own row before it can
close.
