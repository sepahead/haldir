# Formal models

`HaldirAuthority.tla` is an abstract TLA+ model of Gate authority/session/stream/
replay/restart safety (specification Phase 6).

## Important honesty note

TLC (the TLA+ model checker) is **not installed in the delivery environment**, so
this model has **not** been model-checked here (see `docs/LIMITATIONS.md`). Do not
represent it as "model-checked".

The **CI-enforced** encoding of the same safety invariants is the executable
`model` test module in `crates/haldir-state/src/lib.rs`, which runs on every build:

- restart mints a fresh boot id and no pre-restart lease survives (`RetiredNeverActive`,
  `LeaseBindsCurrentIncarnation`);
- a session-generation change invalidates the active lease;
- a lower/equal lease term is rejected (anti-rollback);
- a denied intent consumes its replay sequence but allocates no output;
- output sequences are strictly increasing and never reused;
- a fault latch never self-clears.

## Running the model (when TLC is available)

```bash
# with the TLA+ tools (tla2tools.jar) on the classpath:
java -cp tla2tools.jar tlc2.TLC -config formal/HaldirAuthority.cfg formal/HaldirAuthority.tla
```
