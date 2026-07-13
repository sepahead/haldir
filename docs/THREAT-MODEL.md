# Threat model (P0)

## Protected assets

Authority to affect the plant; integrity/freshness of final commands; session and
stream state; mission-lease scope/lifetime; controller admission/revocation state;
trusted source/state snapshots; Gate output/evidence signing keys; the
complete-mediation deployment configuration; policy-package integrity; availability
of safe expiry and plant-owned fallback; the evidence needed to reconstruct what
each component observed.

## Adversaries addressed by the P0 core (with the mediating control)

| Adversary | Mediating control in the code | Test |
| --- | --- | --- |
| Wrong authenticated role / wrong app key | closed key-role trust, exact `kid` resolve, no fallback search | `haldir-crypto`, `range::stolen_transport_wrong_app_key` |
| Compromised controller emitting well-formed signed intents | conjunctive authorization: scope + admission + lease + source + policy | `haldir-gate` e2e denies, `range::*` |
| Stale controller (old lease/session/source, retired epoch) | atomic session pair, boot binding, two-phase replay, source correlation | `range::session_generation_replay`, `intent_replay`, `stale_intent_sequence`, `stale_state` |
| Wrong admitted artifact | admission digest equality (bundle/backend/admission) | `range::bundle_substitution`, `backend_profile_substitution` |
| Wrong deployment bytes at the standalone verifier boundary | separately passed expected authority/scope/profile policy and bootstrap trust, strict signed package, exact owned role/ID/size/digest set | `haldir-deployment` signature/policy/artifact negatives |
| Package rollback/equivocation at the standalone state boundary | atomic store-global revision/payload-digest plus boot ratchet for the store's authenticated Gate binding | `haldir-state` deployment-ratchet negatives |
| Buggy controller (extreme/oscillatory) | fixed-point bounds, norm, slew, duty, geofence, uncertainty | `haldir-policy-native`, `range::excessive_*`, `geofence_violation` |
| Replay / duplicate | replay state (no liveness effect), output stream never reused | `haldir-state::replay`, `range::intent_replay` |
| Clock fault (regression) | monotonic-only freshness; regression denies, never "fresh" | `haldir-policy-native` freshness test |
| Anti-rollback (rewound/corrupt durable store) | corrupt/rewind → fault, never zero-init | `haldir-state::anti_rollback` |
| Resource exhaustion (oversize intent) | ingress size cap before signature verification | `range::oversize_intent_denied` |
| Gate internal fault | `FAULT_LATCHED` terminal; no output | `haldir-state::gate_process`, actor fault paths |

## Adversaries NOT solved by the P0 core (need controls out of scope)

- Root compromise of the Gate host / kernel / process memory / signing key.
- Mandatory use of the standalone deployment verifier/ratchet by Gate startup; secure artifact
  opening, bootstrap-policy provenance, protected credential custody, and
  running-binary/configuration correspondence.
- Compromise of both mission and admission authorities.
- Malicious plant/Crebain code that ignores validation, or malicious firmware.
- Physical sensor spoofing not caught by the state-estimation boundary.
- **Any bypass that requires live transport to demonstrate** — direct final-key
  publication, wrong-route DDS/MAVROS, observer/UI publish. These require the live
  secure-transport campaign (out of P0; see `docs/LIMITATIONS.md`), so **complete
  mediation is NOT claimed**.
- Backend substitution detected only by behaviour (no neural runtime here).
- Denial of service that prevents both Gate output and the plant's local safe
  mechanism.

## Trust assumptions (P0)

- Gate's host monotonic clock does not move backward during one boot; a detected
  violation denies/latches.
- Gate boot identity is fresh and unpredictable (modeled by the boot counter).
- Mission and admission trust roots are provisioned out of band and are not
  writable by controllers.
- Policy-critical state arrives already validated into the trusted-state snapshot
  (the trusted-state production path is modeled in P0).
- NCP compatibility is pinned to the exact immutable v0.8.0 revision.
- The first profile has one Gate writer and one active controller lease per vehicle.
