# Secure Zenoh reference configuration

This directory is the source for a deterministic **configuration-only** fixture. It is
not a runnable deployment, provisioned PKI, live-delivery result, complete-mediation
manifest, or production profile. It has two controller principals for ACL confinement
tests; the offline `assurance-reference-v1` P0 model described elsewhere has one modeled
controller and no network.

## Render and verify

Render only into a new or disposable trusted scratch/CI directory:

```bash
python3 tools/render-secure-zenoh.py --output /trusted/scratch/haldir-secure-reference-v1
python3 tools/verify-secure-zenoh.py --rendered /trusted/scratch/haldir-secure-reference-v1
```

The renderer checks paths and stale files but writes the bundle in place. It does not
fsync temporary files, atomically rename a complete directory, or defend the scan/write
interval against a hostile writer. Never use it to update a live or adversarial deployment
directory. Publish a separately verified bundle through the deployment system's own atomic,
authenticated rollout mechanism.

## Exact router launch contract

`router-launch.json` is the authoritative launch descriptor. Use its immutable image digest
and `argv` exactly. Mount the generated `router.json5` read-only at
`/etc/haldir-secure-reference-v1/router.json5`, which is the descriptor's `config_path`.
Do not add flags, plugins, environment-generated configuration, or further `--cfg` overrides.
The final arguments deliberately re-disable adminspace and plugin loading **after** the
official Zenoh daemon has loaded the file; omitting or reordering this launch contract can
reopen those surfaces.

Each process must load only its corresponding generated file under `clients/`. Do not merge
client files, enable discovery/listeners, or place controller and Gate behavior in one Zenoh
session. Generated paths under `/run/secrets/haldir-secure-reference-v1` are runtime mount
contracts; the generated files never contain secret bytes.

## PKI and secret mounts

Provisioning is deliberately external to this repository:

- The router certificate must chain to `ca.pem`, be valid for TLS server use, and contain
  the DNS SAN `router.haldir.invalid`. A matching common name alone is insufficient. Resolve
  that reserved hostname to the intended router only inside the controlled deployment.
- Every client certificate must chain to the same deployment CA, be valid for TLS client
  use, and have the exact common name bound to its principal in `profile.json`. The ACL maps
  those exact names; aliases and shared client certificates are forbidden.
- Give every process a separate read-only secret mount containing only `ca.pem`, its own
  certificate, and its own private key. Give the router only the router equivalents. Never
  mount all principal keys into one process or image. Private keys should be owned by the
  process identity and mode `0400`; CA and certificate files should be immutable/read-only.
- Validate certificate lifetimes, chain, SAN/EKU, ownership, and file modes before starting
  Zenoh. Never commit certificates, private keys, fingerprints from production credentials,
  or rendered host-specific secret material.

Stock Zenoh 1.9 combines its public WebPKI roots with the configured custom CA for client
server verification. The reserved `.invalid` name reduces public-issuance risk but does not
provide exclusive custom-CA trust. A production assurance deployment requires a patched or
upgraded transport with an exclusive/pinned verifier; this fixture makes no such claim.

## Evidence boundary

Static verification proves deterministic configuration shape and the fixed ACL grant set.
A successful or failed local Zenoh `put()` call proves neither remote delivery nor
non-delivery. A live claim requires separate mTLS sessions, receiver-observed unique payloads,
negative-route attempts, a post-attempt quarantine window, router/config digests, certificate
fingerprints without private keys, and a retained machine-verifiable campaign artifact.
