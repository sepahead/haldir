# Assurance profiles

Every demonstration and release names its assurance profile. This repository
implements and can compose **P0** only. It also contains individually tested
primitives needed by later profiles, but those primitives do not compose into a
P1/P2/P3 assurance profile and must not be cited as one.

## Profile matrix

| Profile | Controller | Plant | NCP capability | Claim | Status here |
| --- | --- | --- | --- | --- | --- |
| **P0** | deterministic reference | deterministic reference plant | local semantic adapter model | contract/state/policy correctness in-process | **IMPLEMENTED + TESTED** |
| P1 | isolated NEST controller | deterministic plant | NCP v0.8.0, live mTLS/ACL exclusive Gate publisher | experimental complete-mediation slice; `PRE_AUTHORITY_ACL_ONLY` | **NOT IMPLEMENTED**; partial transport/startup/evidence primitives only |
| P2 | isolated NEST controller | Crebain + PX4-SITL | same | measured end-to-end simulated plant authorization | **NOT IMPLEMENTED** |
| P3 | NEST + independent admitted backend | deterministic plant + SITL | same Gate contract | backend-aware admission research result | **NOT IMPLEMENTED** |

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

## Why the live library path is not P1

The off-by-default live code supplies strict route construction, bounded intent
ingress, exact NCP-v0.8 JSON validation, a move-only Gate lifecycle, signed
publication evidence, and a development-only bind/shutdown campaign. Those are
useful prerequisites, not an assurance profile. P1 still requires one private
authenticated runner that selects the signed package, authenticates ongoing
state and control producers, owns the sole protected final-route credential,
supervises timeouts and shutdown, and demonstrates that every alternate actuator
path is closed. Until those properties are composed and evidenced, the live
surface remains a library boundary and P1 remains **NOT IMPLEMENTED**
(`CL-DEPLOYMENT-PACKAGE-01`, `CL-LIVE-CONTROL-PLANE-01`,
`CL-PRODUCTION-01`).
