# NCP compatibility

Haldir's stable contracts contain semantic Haldir fields, not NCP-generated
structs. Only `haldir-ncp08` is aware of NCP wire semantics.

## Pinned baseline (immutable)

| Field | Value |
| --- | --- |
| `ncp_tag` | `v0.8.0` |
| `ncp_commit` | `2f5bd586d4bb20c90362bb6f5698b7f64057ba4e` |
| `wire_version` | `0.8` |
| `contract_hash` | `d1b50a2d8a265276` |
| `proto_sha256` | `6f13b12cff76e12fef384f691d11e2944db1f676568c3e780d3f975689131227` (measured locally 2026-07-12) |
| `capability_profile` | `PRE_AUTHORITY_ACL_ONLY` |

These are encoded in `crates/haldir-ncp08/src/compatibility.rs` (`NCP_V0_8_0`) and
`tools/pins.toml`, and enforced by `tools/verify-pins.py`.

## P0 modeling note

For the P0 profile `haldir-ncp08` **models** the NCP v0.8.0 command-frame
semantics (typed stream/source/session, Gate-owned publisher fields, no
`authority`/`publisher_id` fields) without linking the real `ncp-core`/Zenoh
stack. This keeps the pure core buildable and testable offline. A future adapter
(`haldir-ncpXX`) swaps in the real dependency behind a semantic-diff +
corpus-replay gate; the stable `HaldirIntentV1` and Gate contracts do not change.
See `docs/LIMITATIONS.md`.

## Deferred upstream capabilities (increment 1)

Per the release, NCP v0.8.0 defers: plant-issued command authority, transport-bound
`publisher_id`, and applied-command/stop acknowledgements. Haldir does **not**
fabricate these as private extension fields. The wire `authority.term`/`lease_id`
are ABSENT in `NcpCommandFrameV1`; `PlantPublicationAuthorityStateV1` keeps
`AclExclusiveV1` and the future `NcpLeaseV1` as distinct variants.

## Documentation-drift ledger (to record upstream, not to copy)

The specification records that at review time some NCP prose lagged the tag
(README quick-start built the deleted top-level `seq`; a `proto/ncp.proto` comment
still said `"0.7"`; the wire-0.8 design record called the line untagged;
`NEURO_CYBERNETIC_PROTOCOL.md` retained wire-0.7 sequence prose). Haldir implements
stream/source/session/time/restart semantics from the tagged proto/schemas/
changelog/conformance corpus and the typed-identity design record, never from
stale prose. Upstream issues/PRs are the owner's to file.
