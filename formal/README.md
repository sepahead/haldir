# Formal models

`HaldirAuthority.tla` is a **bounded, finite** TLA+ model of Gate authority /
session / stream / replay / restart safety (specification Phase 6).

## Model-checking status

The registered bounded model has retained historical green evidence under the
SHA-256-pinned TLA+ v1.7.4 jar. `docs/CLAIM-LEDGER.md` (`CL-FORMAL-01`) identifies
GitHub formal run `29211573130` at commit `6ca5958`. The retained epoch-16
recovery evidence additionally records successful main-push formal runs
`30519401534` at `c06465d5` and `30519979149` at `60f43a3a`, including their
canonical results and attestations. Each record proves only its named commit,
workflow, inputs, and finite model. It does not automatically validate a later
runner or workflow revision, and it does not prove a wired live service or
durable runtime.

The independent executable `model` tests in `crates/haldir-state/src/lib.rs` run
as part of the Rust test suite. They complement the TLA+ result; neither encoding
substitutes for exact-subject hosted evidence when hosted workflow bytes change.

The model is bounded (`GateRestart`/`SessionReopen`/`AllocateOutput` are disabled
at their `MaxBoot`/`MaxGen`/`MaxSeq` caps) so TLC terminates; a prior version grew
counters without bound and would not have.

Checked invariants (`Safety`): `TypeOK`, `RetiredNeverActive`, `NoOutputReuse`
(allocated positions are exactly `1..lastOutputSeq` — no gaps or reuse within an
epoch), and `LeaseBindsCurrentIncarnation`.

## Running locally

Use the repository runner rather than downloading or invoking a mutable TLA+
release manually. The online mode acquires the exact release asset declared in
`tools/pins.toml`, verifies its bound and SHA-256 digest, and populates the
ignored cache under `target/formal/`. The offline mode prohibits acquisition and
fails closed unless that verified cache is already present.

```bash
# Populate or reuse the verified cache, then run TLC.
just formal

# Require an already-populated verified cache; perform no download.
just formal-offline

# Run the hermetic formal-runner regression suite (no network or JRE required).
just formal-runner-test

# Equivalent direct commands when `just` is unavailable.
python3 -I -B tools/run_formal.py
python3 -I -B tools/run_formal.py --offline
python3 -I -B tools/test_run_formal.py
```

Both runner modes require an installed Eclipse Temurin 21.0.11+10 runtime whose
properties report vendor `Eclipse Adoptium`, runtime version
`21.0.11+10-LTS`, and specification version `21`. Hosted CI independently
acquires the schema-v3-pinned Linux x64 JRE archive
`OpenJDK21U-jre_x64_linux_hotspot_21.0.11_10.tar.gz`, then verifies its exact
52,099,793-byte size and SHA-256 digest before execution.

The hosted `java_archive_architecture = "x64"` and
`java_runtime_architecture = "amd64"` fields describe that archive and hosted
runtime; they do not require local evidence to run on x86-64. The local runner
separately admits Temurin's observed `aarch64`, `amd64`, and `x86_64` `os.arch`
values, so the same exact runtime is usable on Apple Silicon. Its observed
architecture, vendor, runtime and specification versions, properties-output
digest, and executable identity are measured in the
`HALDIR_FORMAL_RUNTIME_V2` runtime record. That record also binds the complete
hosted provenance field set through the recorded digest of `tools/pins.toml`.

The TLC log is written beneath `target/formal/`. A successful local run is
evidence for that local invocation only; it is not a GitHub-hosted result or
attestation. Conversely, historical hosted results do not prove the current
checkout until a hosted run binds that exact commit and workflow. The recipes
remain separate from `just ci` because Java availability and formal-tool caching
are distinct from the canonical platform-independent P0 gate.

The runner executes private verified snapshots of the model, configuration, and
jar; its canonical runtime record binds those inputs, the runner and pin files,
the measured Java identity, TLC exit status, exact success-marker count, and raw
log digest. Time and output bounds apply to TLC and its inherited process group.
Portable process-group cleanup cannot contain a deliberately hostile descendant
that creates a new session; the admitted TLC invocation is not expected to do so,
and this local runner is not an OS sandbox or deployment boundary.
