# Shortcomings and to-do

Status: 23 October 2026, epoch-21 transition.

This page lists what Haldir cannot yet do, and the work that closes each gap.
It is a short summary.
The [limitations](LIMITATIONS.md) and the [claim ledger](CLAIM-LEDGER.md) remain the normative records.
The [roadmap](ROADMAP-STATUS.md) gives the phase status, and the open issues track the gates.

## What works today

The offline P0 reference monitor is implemented and tested.
It rejects unauthorized, malformed, stale, replayed, mission-forbidden, and policy-invalid intents.
Each stage that the Gate observes produces separate evidence.
A development campaign opened one strict live Gate session and shut it down without processing.
A synthetic campaign checked the transport access rules for commands and intents.

## Shortcomings

| # | Shortcoming | Why it matters | Record |
| --- | --- | --- | --- |
| 1 | No end-to-end path. No controller sends signed intents, and no plant applies the commands. | Mediation is shown for the Gate against a simulation model, not for a vehicle. | Phases 12 and 13, [#5](https://github.com/sepahead/haldir/issues/5), [#6](https://github.com/sepahead/haldir/issues/6) |
| 2 | No observed application. NCP 1.0 starts `ttl_ms` when the plant receives a command. The transport does not report that time, and the plant does not acknowledge the command. | After a publication, the Gate cannot bound when the command took effect. It therefore cannot authorize a later command that depends on it. | Phase 22, `CL-GATE-LIFECYCLE-01` |
| 3 | No restart clearance. After a crash between a publication and its record, the Gate blocks new decisions. | No authenticated operation clears the block, and elapsed time does not clear it. Recovery needs an operator who cannot yet prove authority. | Phase 10, `CL-DURABLE-01`, [#3](https://github.com/sepahead/haldir/issues/3) |
| 4 | The geofence is a software calculation, not physical containment. | It does not include braking, overshoot, disturbances, actuator lag, or vehicle geometry. A pass does not show a safe flight. | `CL-HARDWARE-01` |
| 5 | Backend admission compares digests only. | A neural controller with an admitted digest can still behave differently from its reference. | Phase 18, `CL-BACKEND-01`, [#7](https://github.com/sepahead/haldir/issues/7) |
| 6 | No timing evidence. | The Gate is on every command path. Its latency, overload behavior, and endurance are unknown. It makes no real-time claim. | Phase 20, `CL-TIMING-01`, [#7](https://github.com/sepahead/haldir/issues/7) |
| 7 | No authenticated deployment shell. | Package-bound startup is not yet mandatory. Credentials and the artifact root are not opened by a protected runner. | Phases 5 and 10, `CL-DEPLOYMENT-PACKAGE-01`, `CL-LIVE-CONTROL-PLANE-01` |
| 8 | Transport proof is partial. | Certificate renewal, reconnect, the full route matrix, peer identity, and the bypass inventory are not tested. | Phase 11, `CL-LIVE-TRANSPORT-01` |
| 9 | The NCP pin is an untagged release candidate. | Haldir uses wire `1.0.0-rc.1`. The upstream authority increments that Haldir needs are not delivered. | Phase 22, [NCP compatibility](NCP-COMPATIBILITY.md) |
| 10 | No independent review and no release. | Automated review does not authenticate a reviewer. Release 0.9.0 is `NO_GO`, and no signed experimental release exists. | Phases 0 and 21, `CL-PRODUCTION-01`, [#8](https://github.com/sepahead/haldir/issues/8) |
| 11 | Each change is expensive. | Protected lineage paths, signed delivery, and seven required contexts slow every change. The CI workflows cannot run new checks until a lineage transition admits them. | [Contributing](../CONTRIBUTING.md) |

Shortcomings 1, 2, and 3 decide how far the design can be trusted.
Shortcoming 4 is a limit of any upstream gate.
The plant must still enforce its own physical limits, for example with the flight controller's geofence.

## Advisory snapshot cadence

The epoch-21 transition moved the pinned RustSec snapshot to `640bf5a9`, committed on 22 October 2026.
`tools/pinned_cargo_deny.py` rejects a snapshot that is 90 days old, so the next refresh is due before 20 January 2027, 10:49 UTC.
The snapshot identity is in four protected files: `tools/pins.toml`, `.github/workflows/ci.yml`, `tools/verify-ci-pins.py`, and `tools/test_pinned_cargo_deny.py`.
Each refresh therefore needs a lineage transition, which is shortcoming 11 at a fixed rhythm.

To-do: keep the snapshot identity in one unprotected data file that the protected tool validates (exact URL form, sizes, digests, tree, seed commit, freshness), and let the protected workflow read the values through that tool.
A refresh then becomes an ordinary signed successor, and the protected files no longer change with the snapshot.

## To-do

Do the work in this order.
Each step depends on the steps above it.

1. **Restart clearance** ([#3](https://github.com/sepahead/haldir/issues/3)).
   Design an authenticated clearance that covers transport and session retirement and the recovered policy history.
   Test it with crash, disk-full, and power-loss fault injection.
2. **Authenticated runner.**
   Make package-bound startup and journal binding mandatory on every boot.
   Open credentials and the artifact root through a protected path.
3. **Plant owner** ([#5](https://github.com/sepahead/haldir/issues/5)).
   Make Crebain the only owner of plant commands in PX4-SITL and Gazebo.
   Record the bypass inventory and the accepted and applied events.
4. **Observed application** (upstream NCP).
   Adopt command dispositions and apply and stop acknowledgements when NCP delivers them.
   Until then, keep each published command terminal and unobserved.
5. **Controller** ([#6](https://github.com/sepahead/haldir/issues/6)).
   Make Engram with NEST produce signed `HaldirIntentV1` intents under a Gate-issued lease.
6. **Evidence campaigns** ([#7](https://github.com/sepahead/haldir/issues/7)).
   Measure p99 and p99.9 latency, overload, soak, and recovery.
   Run backend reconstruction for NEST and one independent backend.
   Extend the transport campaign to certificate renewal, reconnect, and the full route matrix.
7. **Release** ([#8](https://github.com/sepahead/haldir/issues/8)).
   Produce a signed experimental release with an SBOM, provenance, and reproducible artifacts.
   Release only after each stronger claim has direct evidence.

Later work, not on the critical path:

- Galadriel PID advisory evidence (phase 16). The [contract](GALADRIEL-PID-ADVISORY-CONTRACT.md) fixes the boundary. No runtime exists.
- Trace exports and consumer replay (phase 17).

## Keep this page current

Update this page when a shortcoming closes or a new one is found.
Change the [limitations](LIMITATIONS.md) and the [claim ledger](CLAIM-LEDGER.md) first.
