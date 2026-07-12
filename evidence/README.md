# Evidence

Machine-readable evidence is retained by digest. Large generated artifacts may
live in release storage rather than Git; manifests, scripts, schemas, checksums,
and stable artifact locations are committed.

For the P0 deliverable, the primary machine-checked evidence is the workspace test
suite itself (run `cargo test --workspace --locked`) together with the committed
golden vectors (`contracts/vectors/`, checked by `tools/verify-generated.py`) and
the source pins (`tools/pins.toml`, checked by `tools/verify-pins.py`).

Live-transport, NEST, PX4-SITL, backend, and performance evidence directories are
**not** present because those campaigns are out of P0 scope (see
`docs/LIMITATIONS.md`).

- `source-review/` — source pins and baseline ledger.
