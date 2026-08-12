#!/bin/bash -p
# P0-R exit gate — run every local acceptance check for the repaired pure core
# in one place. It reproduces every platform-independent CI check that does not
# require the hosted pinned cargo-deny/RustSec environment. Each check is
# reported; any failure makes the whole gate fail.
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
  tmp="$(mktemp)" || return 1
  cargo run -q -p haldir-crypto --locked --example emit_interop_vectors >"$tmp" || {
    rm -f "$tmp"
    return 1
  }
  diff -u tools/interop/vectors.json "$tmp" || {
    rm -f "$tmp"
    return 1
  }
  rm -f "$tmp"
  python3 -I -B tools/interop/verify_cose.py tools/interop/vectors.json
}

clean_build_gate() {
  local tmp
  tmp="$(mktemp -d)" || return 1
  CARGO_TARGET_DIR="$tmp" cargo build --workspace --locked
  local status=$?
  rm -rf "$tmp"
  return "$status"
}

run "current-head audit gate" /usr/bin/env -u BASH_ENV -u ENV /bin/bash --noprofile --norc -p tools/release/current-audit-gate.sh
run "doctor tests"         python3 -I -B -W error tools/test_doctor.py
run "development prerequisites" python3 -I -B tools/doctor.py
run "rustfmt"              cargo fmt --all --check
run "clippy (deny warns)" cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
run "tests"               cargo test --workspace --all-targets --all-features --locked
run "doc tests"           cargo test --workspace --doc --all-features --locked
run "docs (deny warns)"   env "RUSTDOCFLAGS=-D warnings" cargo doc --workspace --no-deps --all-features --locked
run "no-default build"    cargo build --workspace --no-default-features --locked
run "default clippy"      cargo clippy --workspace --locked -- -D warnings
run "clean build"         clean_build_gate
run "local dependency policy" cargo deny --all-features check
run "source pins"         python3 -I -B tools/verify-pins.py
run "CI/formal pins"      python3 -I -B tools/verify-ci-pins.py
run "pinned cargo-deny tests" python3 -I -B -W error tools/test_pinned_cargo_deny.py
run "formal runner tests" python3 -I -B -W error tools/test_run_formal.py
run "release audit tests" python3 -I -B tools/release/test_verify_audit_inputs.py
run "release audit cut"   python3 -I -B tools/release/verify-audit-inputs.py
run "release authority tests" python3 -I -B tools/release/test_verify_authority_model.py
run "release authority model" python3 -I -B tools/release/verify-authority-model.py
run "release evidence generator tests" python3 -I -B tools/release/test_generate_task_evidence.py
run "generated task evidence" python3 -I -B tools/release/verify-task-evidence.py --all-present
run "release protection tests" python3 -I -B tools/release/test_verify_protection_model.py
run "release protection model" python3 -I -B tools/release/verify-protection-model.py
run "evidence layout"     python3 -I -B tools/verify-evidence.py
run "offline Zenoh profile tests" python3 -I -B tools/test_secure_zenoh.py
run "offline Zenoh live-evidence tests" python3 -I -B tools/test_live_secure_zenoh.py
run "live Gate dev smoke tests" python3 -I -B tools/test_live_gate_dev_smoke.py
run "live Gate dev verifier tests" python3 -I -B tools/test_live_gate_dev_smoke_verifier.py
run "offline Zenoh profile" python3 -I -B -c 'import runpy,sys;sys.path.append("tools");runpy.run_path("tools/verify-secure-zenoh.py",run_name="__main__")'
run "retained live Zenoh evidence" python3 -I -B tools/verify-live-secure-zenoh.py
run "retained live Gate dev smoke" python3 -I -B tools/verify-live-gate-dev-smoke.py
run "forbidden claims"    python3 -I -B tools/verify-claims.py
run "generated vectors"   python3 -I -B tools/verify-generated.py
run "interop (COSE/CBOR)" interop_gate
run "diff hygiene"        git diff --check

printf '\n============================================================\n'
printf 'P0-R exit gate: %d passed, %d failed\n' "$pass" "$fail"
if (( fail != 0 )); then
  printf 'failed: %s\n' "${failed[*]}"
  printf 'Note: the TLA+ check (CL-FORMAL-01) runs in CI, not here.\n'
  builtin exit 1
fi
printf 'All local P0-R gates passed. (TLA+ check runs in CI: CL-FORMAL-01.)\n'
