#!/usr/bin/env bash
# P0-R exit gate — run every offline acceptance check for the repaired pure core
# in one place. Mirrors the CI jobs so a developer can reproduce the gate locally
# before pushing. Each check is reported; any failure makes the whole gate fail.
#
# Not covered here when a JRE is unavailable: the independently pinned TLA+
# model check (CL-FORMAL-01), which always runs in .github/workflows/formal.yml.
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 2

pass=0
fail=0
declare -a failed

run() {
  local name="$1"
  shift
  printf '\n=== %s ===\n' "$name"
  if "$@"; then
    printf '  PASS: %s\n' "$name"
    pass=$((pass + 1))
  else
    printf '  FAIL: %s\n' "$name"
    fail=$((fail + 1))
    failed+=("$name")
  fi
}

interop_gate() {
  local tmp
  tmp="$(mktemp)"
  cargo run -q -p haldir-crypto --example emit_interop_vectors >"$tmp" 2>/dev/null || return 1
  diff -u tools/interop/vectors.json "$tmp" || { rm -f "$tmp"; return 1; }
  rm -f "$tmp"
  python3 tools/interop/verify_cose.py tools/interop/vectors.json
}

clean_build_gate() {
  local tmp
  tmp="$(mktemp -d)" || return 1
  CARGO_TARGET_DIR="$tmp" cargo build --workspace --locked
  local status=$?
  rm -rf "$tmp"
  return "$status"
}

run "rustfmt"              cargo fmt --all --check
run "clippy (deny warns)" cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
run "tests"               cargo test --workspace --all-targets --all-features --locked
run "doc tests"           cargo test --workspace --doc --locked
run "docs (deny warns)"   env "RUSTDOCFLAGS=-D warnings" cargo doc --workspace --no-deps --all-features --locked
run "no-default build"    cargo build --workspace --no-default-features --locked
run "default clippy"      cargo clippy --workspace --locked -- -D warnings
run "clean build"         clean_build_gate
run "dependency policy"   cargo deny --all-features check
run "source pins"         python3 tools/verify-pins.py
run "CI/formal pins"       python3 tools/verify-ci-pins.py
run "release audit tests" python3 -m unittest tools/release/test_verify_audit_inputs.py
run "release audit cut"   python3 tools/release/verify-audit-inputs.py
run "current-head audit tests" python3 -m unittest tools/release/test_verify_current_audit.py
run "current-head audit cut" python3 tools/release/verify-current-audit.py
run "release authority tests" python3 -m unittest tools/release/test_verify_authority_model.py
run "release authority model" python3 tools/release/verify-authority-model.py
run "release evidence generator tests" python3 -m unittest tools/release/test_generate_task_evidence.py
run "generated task evidence" python3 tools/release/verify-task-evidence.py --all-present
run "release protection tests" python3 -m unittest tools/release/test_verify_protection_model.py
run "release protection model" python3 tools/release/verify-protection-model.py
run "evidence layout"     python3 tools/verify-evidence.py
run "offline Zenoh profile tests" python3 -m unittest tools/test_secure_zenoh.py tools/test_live_secure_zenoh.py
run "live Gate dev smoke tests" python3 -m unittest tools/test_live_gate_dev_smoke.py tools/test_live_gate_dev_smoke_verifier.py
run "offline Zenoh profile" python3 tools/verify-secure-zenoh.py
run "retained live Zenoh evidence" python3 tools/verify-live-secure-zenoh.py
run "retained live Gate dev smoke" python3 tools/verify-live-gate-dev-smoke.py
run "forbidden claims"    python3 tools/verify-claims.py
run "generated vectors"   python3 tools/verify-generated.py
run "interop (COSE/CBOR)" interop_gate
run "diff hygiene"        git diff --check

printf '\n============================================================\n'
printf 'P0-R exit gate: %d passed, %d failed\n' "$pass" "$fail"
if [ "$fail" -ne 0 ]; then
  printf 'failed: %s\n' "${failed[*]}"
  printf 'Note: the TLA+ check (CL-FORMAL-01) runs in CI, not here.\n'
  exit 1
fi
printf 'All offline P0-R gates passed. (TLA+ check runs in CI: CL-FORMAL-01.)\n'
