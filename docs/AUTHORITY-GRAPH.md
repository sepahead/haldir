# Authority graph (P0)

The normative Haldir 0.9 definition of plant-command creation and the sole
authorized Haldir principal is
[`docs/release/0.9.0/AUTHORITY-CONTRACT.md`](release/0.9.0/AUTHORITY-CONTRACT.md).
This P0 graph is supporting design material and does not expand that contract's
claim boundary.

## Authorities as capabilities (distinct key roles)

`crates/haldir-crypto/src/role.rs` encodes the closed role set. No key signs more
than one authority domain: `CONTROLLER_INTENT`, `MISSION_AUTHORITY`,
`ADMISSION_AUTHORITY`, `POLICY_AUTHORITY`, `REVOCATION_AUTHORITY`,
`GATE_APPLICATION`, `CREBAIN_EVIDENCE`, `DEPLOYMENT_AUTHORITY`, `DEVELOPMENT_ONLY`.

`DEPLOYMENT_AUTHORITY` now has a strict standalone package-verification boundary
(`CL-DEPLOYMENT-PRIMITIVE-01`). A separately passed policy names the expected deployment authority,
Gate, realm, vehicle, class, runtime, and NCP-wire profile, and the verifier rejects any package
mismatch. The standalone API cannot establish where its caller obtained that policy; future Gate
glue must source it from bootstrap state rather than derive it from the package. This capability is
not yet an input to the Gate command conjunction below. Its optional Linux/macOS artifact source begins
from a caller-supplied open directory and proves bounded no-reopen byte capture, not authenticated
root or credential custody; no startup path consumes the resolved artifact typestate or
package-booted durable capability.

## Effective permission to create a plant command (conjunction)

Enforced in `crates/haldir-gate/src/actor.rs::decide_intent`, in order:

```text
process ACTIVE and not fault-latched
  AND intent within ingress size limit
  AND COSE(Ed25519) verifies over exact bytes AND canonical re-encode equal
  AND signer kid resolves to exactly one CONTROLLER_INTENT key, not revoked
  AND actual route == signed intent key == lease intent key
  AND signer kid == lease's controller_intent_signing_key_id
  AND gate id/boot, realm, vehicle, session pair, mission id, lease id/term match
  AND admission (id/digest/bundle/backend) matches the resolved admission
  AND lease remaining time > 0
  AND controller replay: fresh (classify), then commit-consume
  AND trusted state present, same session, primary source correlates to cache
  AND deterministic native policy ALLOW with effective validity >= min useful
  AND authorization_revision unchanged since snapshot (TOCTOU re-check)
  AND plant-publication authority authorizes publication
  AND Gate output sequence allocated (never reused)
  AND Gate-owned NCP frame built and byte-validated
= one Gate-authored plant command
```

No lower layer expands a higher layer's scope. A DENY at any point produces no
output; from the replay-commit point on, the intent sequence is consumed.

## Who may publish what (P0, modeled)

| Role | Produces | Never |
| --- | --- | --- |
| controller | one signed `HaldirIntentV1` on its intent key | any final command, other controller intents, leases/admissions |
| mission authority | signed `MissionLeaseV1` / revocations | final commands, controller intents |
| admission authority | signed `AdmissionRecordV1` / revocations | final commands, controller intents |
| Gate | the modeled final NCP command frame, decision receipts | leases/admissions/policy; another vehicle's command |
| plant (Crebain, future) | accepted/applied evidence | controller intents, Gate decision claims |

## Actuator-path disposition (P0)

The reference plant has **exactly one** command ingress
(`ReferencePlant::ingest`); nothing else changes commanded velocity (invariant
A1/B15). In P0 there is no live transport, so there are no DDS/MAVROS/UI/native
bypass routes to close — and correspondingly, **A1/A2 complete-mediation is not
claimed** (it requires the live transport + bypass-inventory campaign; see
`docs/THREAT-MODEL.md` and `docs/LIMITATIONS.md`). A real deployment MUST produce
the machine-readable actuator-path disposition table and a live bypass campaign
before any stronger mediation claim.
