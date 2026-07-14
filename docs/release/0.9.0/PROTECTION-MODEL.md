# Haldir 0.9 protection model

## HALDIR-0.9-T002 — protected subjects, resources, actions, constraints, time and roots

The key words **SHALL**, **SHALL NOT**, **MUST**, and **MUST NOT** are
normative. This requirement refines the authority rule in
`HALDIR-0.9-T001`; it does not broaden that rule. It applies to the declared
`haldir-secure-reference-v1` / `PRE_AUTHORITY_ACL_ONLY` qualification scope.
The model is default-deny: an identity, resource, action, constraint, clock, or
root that is not explicitly listed **SHALL NOT** gain authority by analogy,
fallback, wildcard, naming similarity, or possession of command-shaped data.

### Identity namespaces and protected subjects

The following identity namespaces **SHALL** remain distinct:

1. a transport principal authenticated by mTLS and admitted by the router ACL;
2. that principal's configured certificate common name;
3. an application-signing `KeyRole`, exact `kid`, key class, public key, and
   verified signer subject;
4. a logical signed subject such as `GateId`, `ControllerId`, issuer,
   `GateBootId`, or deployment identity; and
5. a process, crate, service, operator, or component label.

No value in one namespace **SHALL** be treated as a value in another. In
particular, a role string is not an authenticated principal, a certificate is
not an application-signing key, and a process called `gate` is not thereby the
logical Gate. Authorized plant-command creation requires the T001 conjunction
of the verified Gate application identity and the current route-bound Gate
transport authority; neither possession alone is sufficient.

The closed transport-principal inventory is the eight principals in
`deploy/secure-reference-v1/profile.json`: `admission-authority`,
`controller-a`, `controller-b`, `gate`, `lifecycle`, `mission-authority`,
`observer`, and `robot-crebain`. Their exact role, certificate common name, and
publish/subscribe/query/serve grants are part of this requirement and **SHALL
NOT** be inferred from a role label.

The closed application-key-role inventory is `GATE_APPLICATION`,
`CONTROLLER_INTENT`, `MISSION_AUTHORITY`, `ADMISSION_AUTHORITY`,
`POLICY_AUTHORITY`, `REVOCATION_AUTHORITY`, `CREBAIN_EVIDENCE`,
`DEPLOYMENT_AUTHORITY`, and `DEVELOPMENT_ONLY`. `DEVELOPMENT_ONLY` **SHALL
NOT** grant assurance authority. A role absent from the transport profile may
still authenticate a separately loaded signed artifact, but it gains no route
grant from that fact.

The machine model also freezes each role's allowed key class, signed Rust type,
message kind, schema major, protected content type, external AAD, and signer
subject binding. `POLICY_AUTHORITY` and `CREBAIN_EVIDENCE` currently have no
implemented signed-object domain, so their role names grant no assurance
authority. `DEVELOPMENT_ONLY` accepts only the development key class, has no
signed-object domain, and is forbidden in an assurance profile. An object kind
or signature domain absent from this registry **SHALL NOT** be inferred from a
role comment or from successful generic `COSE_Sign1` verification.

The protected logical/component subjects are the Gate application signer, Gate
transport principal, secure transport router, controllers, mission authority, admission authority,
policy authority, revocation authority, deployment authority, trusted-state
producer, lifecycle service, plant/Crebain boundary, observer/auditor,
provisioning operator, and external generation-anchor service. Controllers may
request semantic actions only. Issuers may issue or revoke only their named
authority objects. The Gate application may verify, decide, allocate, construct,
and record. The Gate transport may publish only its exact profile grants. The
plant/Crebain boundary may produce state and application evidence and consume a
final command, but it is not Haldir authorization authority. Observers,
Galadriel, PID evidence, receipts, and other advisory producers **SHALL NOT**
grant or widen authority.

For every logical component, the exact transport-principal IDs, application
key roles, logical Rust subject types, and current binding status are frozen in
`subject_type_bindings`. The router is an explicit non-authorizing custodian:
it may enforce the exact ACL and route admitted frames, but it may not construct,
authorize, or originate a plant command. The `robot-crebain` transport principal
appears in both the trusted-state-producer and downstream-plant mappings; that
shared transport name does not merge those logical duties or create an
application-signing identity.

### Protected resources and custody

All 17 exact profile routes are protected resources. Their complete paths and
directional grants are frozen in the machine-readable model. The
`final_command` route, `haldir-ncp/session/uav-1/command`, is the primary
command-effect resource. Only the authenticated `gate` transport principal may
publish it; `observer` and `robot-crebain` may subscribe. Subscription is not
receipt, acceptance, application, or physical effect.

The non-route protected resources are:

- the Gate, controller, mission, admission, policy, revocation, deployment, and
  Crebain application-signing secrets, each scoped to its actual custodian;
- the Gate, controller, mission, admission, lifecycle, observer, Crebain, and
  router transport credentials/trust, each scoped to its actual custodian;
- bootstrap application trust and the independently owned revocation snapshot;
- the signed deployment package and its exact owned artifact bytes;
- admission, mission-lease, Gate-owned one-shot challenge, policy, and
  trusted-state snapshots as distinct resources;
- the inseparable NCP session pair and Gate boot identity;
- distinct controller-intent, source, and Gate-output stream positions;
- replay, usage, authorization-revision, publication-slot, and validity state;
- the fresh final frame and its exact route/bytes/digest binding;
- the Gate-custodied authenticated durable snapshot, the separately custodied
  generation-anchor head, and the storage MAC key;
- the signed evidence journal and publication trace; and
- the router profile/ACL and downstream plant/application boundary.

Every resource **SHALL** have one documented semantic owner and one current
runtime custodian, which may be the same subject. Integrity and freshness are
mandatory for authority inputs and outputs. Availability is fail-closed: loss
or exhaustion may deny service but **SHALL NOT** create authority.
Confidentiality is mandatory for private keys, credentials, storage MAC keys,
and administrative material; most signed messages and evidence are not secret.
No controller-declared scope, source, session, timestamp, digest, or identity
field is a root of trust. Such fields are authenticated consistency claims and
**SHALL** match Gate-selected or independently verified state before use.

Owner and custodian identifiers **SHALL** resolve to the closed logical-subject
inventory. A nonempty free-form label is insufficient. In particular, the
mission authority owns the mission lease but not the Gate challenge; the
revocation authority owns revocation state but not bootstrap trust; the Gate
holds the authenticated durable snapshot while the selected anchor holds only
its generation/digest head. The current external non-rewindable anchor remains
undeployed, so this custody definition does not claim that protected external
custody exists in the reference deployment.

### Protected actions

The closed transport verbs are `publish`, `subscribe`, `query`, and `serve`.
The protected authority operations are authenticate/connect, sign, verify,
issue, revoke, configure, provision, submit intent, observe, authorize,
allocate output, construct frame, validate frame, publish once, consume,
accept, apply, record evidence, recover, compare-and-set a generation, and
perform lifecycle RPC, enforce the ACL, and route transport. Issuance,
observation, serialization, receipt, routing, and
evidence recording **SHALL NOT** imply plant-command authority.

Component access rules are exact default-deny grants. Each grant denotes only
the Cartesian product of the resource IDs and operations inside that one grant;
separate grants **SHALL NOT** be merged. The verifier reduces all grants to a
frozen set of `(subject, resource, operation)` tuples. The transport principal
matrix remains the sole source for `publish`/`subscribe`/`query`/`serve`; the
component rules cannot manufacture a route grant. Only `gate_application` may
authorize or construct, only `gate_transport` may perform `publish_once` on the
final route, and router forwarding is not command origination.

The closed decision outcomes remain `ALLOW`, `DENY`, and `ERROR`. The closed
semantic plant actions remain `HOLD` and `VELOCITY_LOCAL_NED`.
`ALLOW(HOLD)` **SHALL** create a bounded zero-velocity command;
`DENY` and `ERROR` **SHALL NOT** create a new plant command. Haldir 0.9 does
not define or claim an ESTOP action or outcome.

### Authorization constraints

Every Gate-authored plant command **SHALL** satisfy all applicable constraints,
with no permissive fallback:

- exact `kid` lookup and exact role, class, subject, public-key, signature
  domain, canonical encoding, and revocation checks;
- exact equality of observed route, signed intent route, and leased route;
- exact Gate/boot, realm, vehicle, mission/phase, session pair, controller,
  lease/admission, bundle/backend, policy, source-key/frame, and output bindings;
- separate replay/order namespaces for controller intent, NCP source, Gate
  output, boot, session generation, lease term, revocation epoch, deployment
  revision, and authorization revision;
- bounded canonical decoding, ingress, queues, sets, histories, journals,
  rates, totals, validity, numeric actions, slew, duty, geofence, uncertainty,
  and checked arithmetic;
- active and non-faulted Gate state, present and strictly advancing trusted
  state, deterministic policy `ALLOW`, useful effective validity, unchanged
  authorization revision, current publication authority, fresh output
  allocation, exact frame validation, and one opaque publication transition.

“Applicable” is not open-ended: the machine model's
`final_command_transition.required_constraint_ids` contains the exact 26
identity, scope, ordering, bound, and state-transition constraints that must
hold before construction/publication. `failure:no_new_command` is the exact
failed-precondition rule, and `failure:no_retroactive_erasure` is the exact
post-exposure interpretation rule. Removing, replacing, duplicating, or adding
a constraint without a reviewed model revision **SHALL** fail verification.

Opaque epochs and boot identifiers **SHALL NOT** be numerically ordered or
compared across namespaces. A failed constraint **SHALL NOT** produce a new
Gate-authored command. A denial, error, expiry, revocation, or later evidence
event does not retroactively prove that a previously exposed command was never
delivered or applied; downstream validity and local safe behavior remain a
separate boundary.

### Time domains

Gate boot-local monotonic time is the sole hot-path authorization clock. It is
used for lease anchoring/expiry, trusted-state freshness from Gate receive and
capture instants, rate/duty/slew accounting, publication deadlines, and Gate
output time. It **SHALL NOT** be compared across Gate boots. Regression or
overflow **SHALL** fault or deny, never make data fresh.

The Gate-clock field array is explicitly a reviewed set of named examples,
classified by origin rather than by spelling: it includes `MonoInstant`,
`receive_mono`, `captured_mono`, `accepted_at_mono`, `expires_at_mono`,
publication observation/deadline/horizon instants, and derived `gate_t_ns`.
An unlisted integer timestamp **SHALL NOT** become authority merely because its
name resembles one of these fields. The controller and source provenance arrays
are exhaustive for their current fields; the evidence and UTC arrays are named
examples that remain non-authorizing.

`controller_t_ns` is controller-local provenance and diagnostics only.
Source `publisher_t_ns` / `source_t_ns` is causal provenance only. Neither
**SHALL** establish freshness, validity, lease life, ordering across producers,
or output time. Gate `receive_mono` and `captured_mono` are authoritative for
freshness because they are samples of the current Gate boot-local clock.

Publication/evidence `observed_mono_ns` is producer-boot-local ordering
evidence only after signer, boot, and retained journal/startup provenance are
authenticated. Wall-clock/UTC may describe certificates, releases, or audit
records but **SHALL NOT** authorize the command hot path. Session generations,
stream epochs, and boot IDs are opaque typed identities: equality is meaningful
only inside the exact namespace, and numeric ordering is forbidden. Lease
terms, revocation epochs, deployment revisions, and durable generations are a
separate logical-ratchet domain. They are comparable across restart only within
the exact typed subject/scope and against authenticated persisted high water;
they are not wall or monotonic clocks and **SHALL NOT** compare across scopes.
`authorization_revision` and the typed intent, output, source, and challenge
sequence counters form a third, boot-or-epoch-scoped logical-counter domain.
They may order events only inside the current Gate boot or matching typed stream
epoch and **SHALL NOT** be treated as durable or compared across a boot/epoch
change. In particular, a new-process authorization revision value is not a
durable anti-rollback ratchet.

### Trust roots and root status

The current implementation consumes caller-supplied prevalidated application
trust and revocation snapshots, exact external deployment-acceptance policy,
configured policy/admission/session/publication snapshots, the Gate monotonic
clock, and Gate-owned signing material. These are trusted inputs at their local
verification boundary; their protected acquisition, freshness, custody, and
deployment composition are not thereby proven.

The deployment verifier and owned-artifact resolver, mTLS/router/default-deny
profile, storage MAC, authenticated snapshot, generation-anchor interface, and
evidence journal are implemented primitives. Gate startup does not yet consume
the resolved deployment-package typestate. The retained ACL campaign uses an
ephemeral PKI and proves only its bounded experiment. The local file generation
anchor is rewritable and development-only. No deployed external non-rewindable
anchor, protected secret loader, exclusive custom-CA trust, authenticated
ongoing state/control provenance, global credential/handle exclusivity, or
plant/firmware trust proof exists.

The pinned NCP v0.8.0 commit, dependency lock, toolchain, router image, and
artifact digests are supply-chain integrity anchors, not runtime principals and
not native NCP 1.0 authority. Trust **SHALL NOT** be derived from controller
claims, process names, command shape, advisory evidence, a caller-constructible
`AclExclusiveEvidenceV1`, or successful serialization.

### Claim boundary

This requirement freezes a closed, executable protection inventory and its
default-deny relationships. The repository verifier checks that inventory
against the exact profile matrix and current Rust vocabularies and semantics.
It validates closed owner/custodian references, role/object/domain records,
logical identity mappings, exact resource and access-tuple fingerprints, the
complete final-command constraint list, immutable constraint/root semantics,
and the opaque-identity versus durable-ratchet split. These fingerprints are
review anchors inside the signed source commit, not evidence that current
runtime custody or complete mediation exists.
Implementation enforcement remains **PARTIAL**: protected credential custody,
mandatory deployment-package consumption, authenticated live state/control
ingress, sealed capabilities, globally unique publisher handles, external
anti-rewind protection, complete mediation, delivery, plant acceptance and
application, physical safety, and production deployment security remain
**NOT_CLAIMED**. Later tasks may close those gaps; this definition alone does
not.

The machine-readable mirror and executable drift checks are
[`protection-model.json`](../../../release/0.9.0/protection-model.json) and
[`verify-protection-model.py`](../../../tools/release/verify-protection-model.py).
