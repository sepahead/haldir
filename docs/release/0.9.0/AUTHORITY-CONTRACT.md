# Haldir 0.9 normative authority contract

## HALDIR-0.9-T001 — sole plant-command principal

> **Qualification status: IMPLEMENTED, REOPENED.** The NCP 1.0 amendment below
> changed this contract after the signed `395f78be…` T001 closure. That exact
> record remains historical evidence for its own commit; it does not verify these
> current bytes. T001 must receive a new signed exact-commit closure before its
> ledger status can return to `verified`.

The key words **SHALL**, **SHALL NOT**, **MUST**, and **MUST NOT** in this
document are normative. This contract applies to the Haldir 0.9 claimed
`NCP_1_0_COMMANDER_LEASE` secure-reference profile, which speaks NCP
`1.0.0-rc.1` (wire 1.0). Other deployment modes are defined separately by
HALDIR-0.9-T005 and do not inherit this authority claim.

### Definitions

- The **protected final route** is the `final_command` route named by the
  selected, verified deployment profile. In `haldir-secure-reference-v1` it is
  `haldir-ncp/session/uav-1/command`.
- A **plant command** is an exact command frame produced or handled with the
  intent that it be consumed from the protected final route to affect the plant.
  This definition does not assume authorization: a bypass frame intended for that
  route is an *unauthorized plant command* and therefore violates this contract.
  A local value, serialized byte string, test fixture, copied frame, or value for
  another route with no such intent is only *command-shaped data*.
- To **create** a plant command is to produce or cause production of that exact
  intended final-route frame. Authorized creation requires Haldir's decision,
  fresh-frame construction, and current route-bound publication capability.
  Creation does not claim delivery, plant acceptance, application, physical
  response, or safety.
- A **principal** is the authenticated runtime identity to which the deployment
  profile grants route capabilities. A key role, process name, library type, or
  advisory producer is not by itself a principal.

### Sole authority

For `haldir-secure-reference-v1`, the authenticated principal `gate`, with role
`gate` and certificate common name
`haldir-gate.secure-reference-v1`, **SHALL** be the sole Haldir principal
authorized to create plant commands. Its application signing key **SHALL** have
the closed `GATE_APPLICATION` key role. Neither identity element substitutes for
the other, and possession of either element alone **SHALL NOT** authorize a plant
command.

Controllers, mission authority, admission authority, lifecycle, observer, the
robot/Crebain consumer, deployment authority, policy authority, revocation
authority, evidence producers, Galadriel, and PID evidence **SHALL NOT** create,
publish, relay, or widen authority for a plant command in this profile. Crebain
is a downstream consumer/application boundary, not a Haldir authorization
principal. Controller bytes **SHALL NOT** be forwarded as final command bytes.

The Gate **SHALL** create a plant command only when all of the following are true:

1. the Gate process is active and not fault-latched;
2. the controller intent is bounded, canonical, authenticated, fresh, and bound
   to the actual controller route, session, mission lease, admission, and trusted
   state;
3. deterministic policy returns `ALLOW` with a useful effective validity;
4. authorization state is unchanged at the time-of-check/time-of-use recheck;
5. the current publication state is a validated, deployment-bound exclusive
   capability for this profile and final route;
6. the Gate holds a live NCP commander lease for the current session and output
   epoch, issued to that principal and route, that stays live for the whole
   effective validity of the command;
7. a new Gate-owned output position is allocated; and
8. the Gate builds and validates a fresh NCP frame from the approved semantic
   action, Gate/trusted-state fields, and that lease, then binds its exact bytes,
   digest, and final route into an opaque publication transition.

Failure of any conjunct **SHALL NOT** produce a plant command. No lower-level
adapter, transport handle, publisher, alternate route, cached frame, retry, or
fallback **SHALL** turn a failed or absent conjunct into authority.

### Decisions are not actions

The closed Haldir 0.9 decision outcomes are `ALLOW`, `DENY`, and `ERROR`. The
closed initial semantic plant actions are `HOLD` and `VELOCITY_LOCAL_NED`.
`HOLD` is an action, not a refusal outcome: `ALLOW(HOLD)` **SHALL** create a
bounded zero-velocity plant command. `DENY` and `ERROR` **SHALL NOT** create a
plant command. Haldir 0.9 does not define decision outcomes named `HOLD` or
`ESTOP`, and it does not claim a Haldir-originated ESTOP command.

### Claim boundary

The secure-reference ACL and retained synthetic live matrix show that only the
`gate` profile identity can deliver on the protected final route within that
bounded router experiment. They do not prove that the packaged runtime holds the
only usable credentials, that every lower-level construction/publication API is
sealed, or that every Crebain/ROS/MAVROS/firmware actuator path is closed.
In particular, current `AclExclusiveEvidenceV1` values and lower-level actor,
adapter, session, and publisher APIs are not yet a sealed route-capability proof.
Under NCP `1.0.0-rc.1` the Gate issues its own lease and the body's authority
machine enforces it; the lease gives each command a bounded, attributable
authority term, while body acceptance stays **NOT_CLAIMED**. The retained live
matrix was recorded with NCP v0.8 frames. Router ACLs do not depend on the frame
version, and a rerun with NCP 1.0 frames remains to be recorded.
The authority rule is frozen here, while enforcement hardening remains partial
until the later capability, API-surface, credential-custody, and bypass tasks
close. Accordingly, complete mediation, delivery, plant
acceptance/application, physical-system safety, and production deployment
security remain **NOT_CLAIMED** for Haldir 0.9 until their later requirements
have independent evidence.

### Amendment of 1 October 2026

The owner moved every sepahead project to NCP 1.0. This amendment replaces the
`PRE_AUTHORITY_ACL_ONLY` profile, in which exclusive-route ACL evidence alone was
the publication capability, with `NCP_1_0_COMMANDER_LEASE`, and adds conjunct 6.
It only narrows authority: the previous rule permitted every command that this
rule permits. The T001 verification record verifies the previous rule at its
recorded commit, not this amendment.

The machine-readable mirror and executable drift checks are
[`authority-model.json`](../../../release/0.9.0/authority-model.json) and
[`verify-authority-model.py`](../../../tools/release/verify-authority-model.py).
