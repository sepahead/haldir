# Authority graph (P0)

The normative Haldir 0.9 definition of plant-command creation and the sole
authorized Haldir principal is
[`docs/release/0.9.0/AUTHORITY-CONTRACT.md`](release/0.9.0/AUTHORITY-CONTRACT.md).
This P0 graph is supporting design material and does not expand that contract's
claim boundary.

## Authorities as capabilities (distinct key roles)

`crates/haldir-crypto/src/role.rs` encodes the closed role set. Each trust record
authorizes exactly one role and carries one mandatory canonical subject of at
most 64 ASCII bytes. Provisioning admits only the unique canonical encoding of
a non-identity Ed25519 point in the prime-order subgroup, then rejects reuse of
that public key under distinct key identifiers, including aliases that propose
the same role but another subject or assurance class. Deployments must provision
a distinct cryptographic key for each authority domain: `CONTROLLER_INTENT`, `MISSION_AUTHORITY`,
`TRUST_AUTHORITY`, `ADMISSION_AUTHORITY`, `POLICY_AUTHORITY`, `REVOCATION_AUTHORITY`,
`GATE_APPLICATION`, `CREBAIN_EVIDENCE`, `DEPLOYMENT_AUTHORITY`, `DEVELOPMENT_ONLY`.
Package-bound startup treats the retained bootstrap store and the approved
runtime store as lifecycle-separated authority namespaces: neither a `kid` nor
public-key material may occur in both. That comparison happens before entropy,
locks, storage, or anchor access. Rejecting even an identical record keeps the
two independently governed revocation snapshots from creating ambiguous key
lifecycle or reviving a key revoked at bootstrap.

A logical subject may legitimately rotate to a new key identifier and distinct
key material. The one-to-one invariant is between a key identifier and exact
accepted public key, not between a long-lived logical subject and one key forever.

`DEPLOYMENT_AUTHORITY` has a strict package-verification boundary
(`CL-DEPLOYMENT-PRIMITIVE-01`). A separately passed policy names the expected deployment authority,
Gate, realm, vehicle, class, runtime, and NCP-wire profile, and the verifier rejects any package
mismatch. The API cannot establish where its caller obtained that policy. Package-bound Gate startup
now consumes signed-role NCP and strict Gate-configuration proofs plus four separately verified,
role-separated, public-key-distinct revision-scoped runtime-snapshot approvals. The approval keys and revocations are retained from the
same bootstrap snapshots that verified the package, so no second trust root can be introduced
between typestate stages. This proves cryptographic role/key separation, not separate organizations,
operators, or administrative control. Startup derives and exact-matches the complete live authorization
configuration plus runtime/store selections before effects, commits its
verified revision/digest with the boot, and exact-matches the signed journal ID when the
authenticated format-v2 journal is bound; unbound assurance startup is rejected. That capability is
not yet a complete input to the command conjunction below because bootstrap/root provenance and
journal binding/path are not mandatory and the other seven artifact roles, running executable,
protected root, and credentials
are not bound. The
optional Linux/macOS artifact source begins from a caller-supplied open directory and proves bounded
no-reopen byte capture, not authenticated root or credential custody.

## Effective permission to create a plant command (conjunction)

Enforced in `crates/haldir-gate/src/actor.rs::decide_intent`, in order:

```text
process ACTIVE and not fault-latched
  AND intent within ingress size limit
  AND COSE(Ed25519) verifies over exact bytes AND canonical re-encode equal
  AND signer kid resolves to exactly one CONTROLLER_INTENT key, not revoked
  AND lease activation preflight already bound that kid/role/class/subject to
      the admitted controller before spending term or challenge
  AND actual route == signed intent key == lease intent key
  AND signer kid == lease's controller_intent_signing_key_id
  AND gate id/boot, realm, vehicle, session pair, mission id, lease id/term match
  AND admission (id/digest/bundle/backend) matches the resolved admission
  AND lease remaining time > 0
  AND controller replay: fresh (classify), then commit-consume
  AND trusted state present, same session, and still within its age bound
  AND that state was admitted through strict capture-time and source-position
      progression (prior source epochs retained as non-evicting tombstones)
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

## Actuator-path disposition

The modeled P0 reference plant has **exactly one** command ingress
(`ReferencePlant::ingest`); nothing else changes commanded velocity (invariant
A1/B15). The separate off-by-default Zenoh library path and retained ACL
experiment do not enumerate or close DDS, MAVROS, UI, firmware, native-client,
credential-reuse, or other physical actuator routes. Accordingly, **A1/A2
complete mediation is not claimed**. A real deployment MUST produce the
machine-readable actuator-path disposition table and a live bypass campaign
before any stronger mediation claim; see the normative
[threat model](release/0.9.0/THREAT-MODEL.md) and [limitations](LIMITATIONS.md).
