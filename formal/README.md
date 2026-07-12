# Formal models

`HaldirAuthority.tla` is a **bounded, finite** TLA+ model of Gate authority /
session / stream / replay / restart safety (specification Phase 6).

## Model-checking status

TLC runs in CI via [`.github/workflows/formal.yml`](../.github/workflows/formal.yml)
on a GitHub runner (a JRE is available there). It was **not** run in the delivery
shell (no local JRE), so until the first public green TLC run is recorded in
`docs/CLAIM-LEDGER.md` (`CL-FORMAL-01`), the authoritative, CI-enforced encoding of
the same invariants is the executable `model` test module in
`crates/haldir-state/src/lib.rs`, which runs on every build.

The model is bounded (`GateRestart`/`SessionReopen`/`AllocateOutput` are disabled
at their `MaxBoot`/`MaxGen`/`MaxSeq` caps) so TLC terminates; a prior version grew
counters without bound and would not have.

Checked invariants (`Safety`): `TypeOK`, `RetiredNeverActive`, `NoOutputReuse`
(allocated positions are exactly `1..lastOutputSeq` — no gaps or reuse within an
epoch), and `LeaseBindsCurrentIncarnation`.

## Running locally

```bash
# needs a JRE and tla2tools.jar
curl -sSL -o tla2tools.jar \
  https://github.com/tlaplus/tlaplus/releases/latest/download/tla2tools.jar
java -cp tla2tools.jar tlc2.TLC \
  -config formal/HaldirAuthority.cfg formal/HaldirAuthority.tla
```
