# Assurance profiles

Every demonstration and release names its assurance profile. This repository
implements **P0** only.

## Profile matrix

| Profile | Controller | Plant | NCP capability | Claim | Status here |
| --- | --- | --- | --- | --- | --- |
| **P0** | deterministic reference | deterministic reference plant | local semantic adapter model | contract/state/policy correctness in-process | **IMPLEMENTED + TESTED** |
| P1 | isolated NEST controller | deterministic plant | NCP v0.8.0, live mTLS/ACL exclusive Gate publisher | experimental complete-mediation slice; `PRE_AUTHORITY_ACL_ONLY` | out of scope |
| P2 | isolated NEST controller | Crebain + PX4-SITL | same | measured end-to-end simulated plant authorization | out of scope |
| P3 | NEST + independent admitted backend | deterministic plant + SITL | same Gate contract | backend-aware admission research result | out of scope |

## `assurance-reference-v1` (the P0 profile implemented here)

```text
Profile:            assurance-reference-v1
Vehicle/plant:      deterministic integer point-mass plant (simulation only)
Controller route:   controller -> HaldirIntentV1 (one signed intent key)
Final command route: Gate -> one modeled NCP command frame -> reference plant
Direct DDS/MAVROS routes: absent by construction (in-process; no transport)
NCP compatibility:  immutable v0.8.0 (modeled adapter, digest-pinned)
Gate writers:       one authenticated principal (modeled; live ACL UNPROVEN)
Controller writers: one application-signing key per intent key
Command family:     local-NED velocity + hold
State source:       one modeled trusted-state snapshot
Safe action:        plant-owned reference-kinematic-hold-v1 (simulation only)
Timing claim:       none (no performance campaign); not hard real-time
Backend claim:      none (no neural runtime; admission is digest-equality only)
Command-authority:  PRE_AUTHORITY_ACL_ONLY (declared label; live property UNPROVEN)
```

Do not write "Haldir mediates the vehicle." The proven statement is: within P0,
the Gate enforces the contract/state/policy conjunction over the declared,
in-process command route. Everything beyond that is out of scope (see
`docs/LIMITATIONS.md`).
