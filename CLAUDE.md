# Haldir instructions

@AGENTS.md

Read [README.md](README.md) first. [AGENTS.md](AGENTS.md), imported above, is the canonical
maintainer contract and document router. [CONTRIBUTING.md](CONTRIBUTING.md) retains the protected
signed-lineage and delivery procedure.

- The owner authorizes delivery to `main`: an exact signed commit, all seven contexts green on that
  head, then a fast-forward push. Never use a GitHub merge button.
- Do not add AI attribution or co-author trailers to commits or pull requests.
- Preserve the P0 reference boundary and release `NO_GO`.
- Keep `ALLOW`, `DENY`, and `ERROR` distinct from `HOLD` and velocity actions.
- A publish return does not prove delivery, application, or physical effect.
- Retain `UnknownAfterPublish` and the unimplemented authenticated restart-clearance boundary.
- Native local NCP gating and Galadriel/PID authority effects remain unsupported.
- Report exact changed paths, gate results, retained failures, and remaining limits.
