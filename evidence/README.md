# Evidence

Machine-readable evidence is retained by digest. Large generated artifacts may
live in release storage rather than Git; manifests, scripts, schemas, checksums,
and stable artifact locations are committed.

For the P0 deliverable, the primary machine-checked evidence is the workspace test
suite itself (run `cargo test --workspace --locked`) together with the committed
golden vectors (`contracts/vectors/`, checked by `tools/verify-generated.py`) and
the source pins (`tools/pins.toml`, checked by `tools/verify-pins.py`).

`11-secure-zenoh-live/` retains the narrow receiver-observed synthetic command/intent ACL
campaign. No retained concrete Gate development bind/shutdown campaign is present yet; target
compilation and offline fixture tests are not live evidence. NEST, PX4-SITL, backend, and
performance evidence directories remain absent (see `docs/LIMITATIONS.md`).

- `source-review/` — source pins and baseline ledger.
- `11-secure-zenoh-live/` — pinned-router, ephemeral-PKI ACL subset evidence.

The absent Gate campaign has an explicit generate/check handoff. From a clean committed tree, use
one fresh disposable fixture/output name:

```bash
python3 tools/run-live-gate-dev-smoke.py \
  --output target/live-gate-dev-smoke/<unique-run>
python3 tools/verify-live-gate-dev-smoke.py \
  --evidence target/live-gate-dev-smoke/<unique-run>/evidence
```

The generator never promotes or independently verifies its output. A passing candidate becomes
retained evidence only through a separate reviewed copy to `evidence/12-live-gate-dev-smoke`, a
second verifier pass at that location, and an honest claim-ledger update.
