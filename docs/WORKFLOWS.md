# Read a Haldir decision and its evidence

Haldir asks whether Gate may create one new command now.
It answers that question under a declared authority, policy, state, and transport profile.
It does not decide whether a vehicle is physically safe or whether a command actually took effect.

The [authority contract](release/0.9.0/AUTHORITY-CONTRACT.md) owns command creation.
The [evidence contract](EVIDENCE-SEMANTICS.md) owns publication and recovery.
This guide explains those existing rules without replacing them.

<picture>
  <source media="(max-width: 640px)" srcset="../assets/authorization-flow-mobile.svg">
  <img src="../assets/authorization-flow.svg" width="1200" alt="Independent authority and state constrain Gate. Only an allowed intent can produce a new command. Publication evidence is recorded before one call; plant application is a separate observation.">
</picture>

[Wide SVG](../assets/authorization-flow.svg) · [Mobile SVG](../assets/authorization-flow-mobile.svg) ·
[Direct vector](https://raw.githubusercontent.com/sepahead/haldir/main/assets/authorization-flow.svg)

The [standalone HTML view](authorization-flow.html) supports local script-free zoom.
The following text provides the complete reading alternative.

## Run the implemented reference

From the repository root:

```bash
python3 -I -B tools/doctor.py
cargo test --locked -p haldir-range
cargo run --locked -p haldir-gate -- --build-info
cargo run --locked -p haldir-ctl -- --help
```

The range uses the actual Gate and a deterministic reference plant in one process.
It exercises allowed, malformed, stale, replayed, and policy-invalid intents through the declared reference route.
Its plant observations are simulated values.
They are not CREBAIN, NEST, or physical-vehicle observations.

Both command-line tools are offline inspection tools.
`haldir-ctl verify-ncp-compatibility <FILE>` checks supplied bounded artifact bytes against compiled NCP pins.
It does not prove signed deployment-role origin, artifact-root trust, running-binary identity, or Gate startup selection.
The [NCP guide](NCP-COMPATIBILITY.md) defines that separate input contract.

## A conjunction of independent requirements

Let $I$ denote the exact signed intent bytes.
Let $A$ denote independently held authority, including the active lease and admitted policy.
Let $S$ denote the trusted state snapshot.
Let $t$ denote Gate's current boot-local monotonic time.

Let $V(I,A,S,t)$ mean that every required validation and scope check passes.
Let $P(I,A,S,t)$ be the pure policy result.
Let $R$ mean that the final authority, state, time, horizon, and publication checks pass.

A necessary condition for exposing the exact output to a publisher is:

$$
\operatorname{ExposeForPublish}
\;\Longrightarrow\;
V(I,A,S,t)\;\land\;[P(I,A,S,t)=\mathrm{ALLOW}]\;\land\;R.
$$

This implication states the final exposure boundary.
Private frame construction can occur earlier, after the intent receives an allowed decision.
The final recheck can still reject exposure of those already prepared bytes.
No single conjunct guarantees progress, delivery, or physical safety.
Resource or storage failure can still prevent progress.

The signature binds the observed bytes to an enrolled signer under the selected trust policy.
It cannot supply a missing lease, fresh state, or publication capability.
Gate constructs output from admitted semantic fields and its own trusted identities.
It does not relay a signed controller frame unchanged.

## Why a component limit is not a vector limit

The velocity action uses integer millimeters per second in a local north-east-down frame.
Write its components as $v=(v_N,v_E,v_D)$.
Let the per-component speed cap be $c=4000$ mm/s and the vector cap be $b=5000$ mm/s.

The vector-speed condition can compare squared integers:

$$
v_N^2+v_E^2+v_D^2\;\leq\;b^2.
$$

Both sides have units mm²/s².
The implementation uses checked or widened arithmetic rather than a floating-point square root.

| Candidate velocity, mm/s | Per-component cap | Squared magnitude, mm²/s² | Vector cap |
| --- | --- | --- | --- |
| $(3000,4000,0)$ | Passes | 25,000,000 | Passes at the boundary |
| $(4000,4000,0)$ | Passes | 32,000,000 | Fails against 25,000,000 |

These are constructed arithmetic examples, not recorded trajectories.
Passing the speed checks does not establish `ALLOW`.
Freshness, lease scope, acceleration, slew, duty, mode, geofence, and the other required checks still apply.

A prospective geofence projects a conservative software envelope from the supplied state and uncertainty.
It does not validate braking, actuator lag, disturbance rejection, or physical stopping distance.

## Why denial is not a stop command

`DENY` and `ERROR` produce no new Gate command.
They do not remove an older command already exposed to a publisher.

`HOLD` is an action that must itself receive `ALLOW`.
It constructs a bounded zero-velocity command under the selected frame and profile.
A plant may respond later, reject it, or never receive it.
The reference plant's `reference-kinematic-hold-v1` behavior is a simulation-only rule.

Do not translate a capacity error, missing state, or unknown publication into an automatic hold.
The closed decision contract contains no Haldir-originated emergency-stop outcome.

## The publication boundary

The journal-bound composition uses this order:

1. Reserve bounded logical evidence capacity.
2. Validate and decide on the bounded intent.
3. Keep any prepared exact frame private.
4. Cross-check and locally sync its signed decision receipt.
5. Locally sync the linked `PublishCalled` record.
6. Recheck authority, state, time, and remaining horizon.
7. Expose that exact frame for one publisher invocation.
8. Record only the terminal local return that was observed.

A logical reservation protects configured quota.
It cannot guarantee filesystem space, a future successful sync, or a hard execution deadline.

| Evidence stage | What it records | What remains unknown |
| --- | --- | --- |
| `OutputPrepared` | Gate prepared the exact output bytes | Whether a publisher received them |
| `PublishCalled` | The locally sync-confirmed boundary before possible invocation | Whether transport code began or any bytes arrived remotely |
| `PublishReturnedOk` | The local publisher returned `Ok` | Delivery, acceptance, application, and physical response |
| `PublishReturnedError` | An observed local error or definite preflight rejection under its exact transition | General transport non-delivery cannot be inferred |
| `UnknownAfterPublish` | Recovery found a dangling called boundary without a supported terminal result | Which downstream effects, if any, occurred |

A missing return is not an observed error.
A malformed or corrupt journal cannot become an empty history or a successful recovery.
The exact recovery validator owns which retained states are admissible.

In the declared-live path, every actual publisher invocation consumes the usable service and publisher.
Even local success is terminal and application-unobserved.
Wire-0.8 TTL begins at plant-local arrival, which Gate cannot reconstruct from its local return time.
It commits no guessed live action interval.

Recovered called-or-later history blocks new decisions.
There is no authenticated clearance API, and elapsed time cannot remove that block.
A future clearance contract must address transport, session, plant, and policy-history evidence.

## Keep each owner separate

| Owner | Responsibility | Boundary |
| --- | --- | --- |
| Controller | Propose a signed semantic intent | Does not author the final Gate command |
| Authority inputs | Grant lease, admission, policy, and revocation scope | Controller fields cannot create these roots |
| Trusted-state producer | Supply the state used by policy | Current local state API does not authenticate producer acquisition |
| Gate | Decide, construct, recheck, and record its observed stages | Does not claim downstream application |
| Transport | Perform its local publish operation | Local success does not prove delivery |
| Plant | Validate, select, apply, and observe its own response | P0 plant events are model values |
| External evidence consumer | Inspect retained observations | No authority follows from an attractive report |

Galadriel, PID, and Prisoma do not add an implemented Haldir authority path.
The candidate native local NCP experiment excludes Haldir gating before preparation.
CREBAIN and Engram remain external integration work for Haldir.
Their separate capabilities cannot close Haldir's missing authenticated runner, credential custody, or plant-side evidence.

The [claim ledger](CLAIM-LEDGER.md), [limitations](LIMITATIONS.md), and [current qualification program](../release/0.9.0/current-head/README.md) remain authoritative.
This guide changes no release or scientific disposition.
