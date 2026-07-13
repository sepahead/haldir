# Live secure-Zenoh campaign harness

This directory contains the pinned container build for the receiver-observed ACL
campaign. The campaign is intentionally not part of the offline `just ci` gate: it
requires Docker, OpenSSL, ephemeral private keys, and live processes.

Run only from a clean committed Haldir tree:

```bash
python3 tools/run-live-secure-zenoh.py --output target/live-secure-zenoh/manual-run
python3 tools/verify-live-secure-zenoh.py \
  --evidence target/live-secure-zenoh/manual-run/evidence
```

The runner creates all private keys below the ignored `target/` tree, mounts them
read-only into disposable containers, and emits a sanitized candidate only when every
normal/handled-error cleanup succeeds. Never publish the raw run directory. `SIGKILL`,
host failure, or Docker-daemon failure can preempt cleanup; after abnormal termination,
operators must remove the named `haldir-probe-*`/`haldir-router-*` containers,
`haldir-live-*` network/image objects, and the entire raw run directory before retrying.
Review and commit only the independently verified `evidence/` candidate.
