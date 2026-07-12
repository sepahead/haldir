#!/usr/bin/env bash
# P0-R exit gate — run every offline acceptance check for the repaired pure core
# in one place. Mirrors the CI jobs so a developer can reproduce the gate locally
# before pushing. Each check is reported; any failure makes the whole gate fail.
#
# Not covered here (requires a JRE / CI): the TLA+ model check (CL-FORMAL-01),
# which runs in .github/workflows/formal.yml.
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

run "rustfmt"              cargo fmt --all --check
run "clippy (deny warns)" cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
run "tests"               cargo test --workspace --locked
run "source pins"         python3 tools/verify-pins.py
run "evidence layout"     python3 tools/verify-evidence.py
run "forbidden claims"    python3 tools/verify-claims.py
run "generated vectors"   python3 tools/verify-generated.py
run "interop (COSE/CBOR)" interop_gate

printf '\n============================================================\n'
printf 'P0-R exit gate: %d passed, %d failed\n' "$pass" "$fail"
if [ "$fail" -ne 0 ]; then
  printf 'failed: %s\n' "${failed[*]}"
  printf 'Note: the TLA+ check (CL-FORMAL-01) runs in CI, not here.\n'
  exit 1
fi
printf 'All offline P0-R gates passed. (TLA+ check runs in CI: CL-FORMAL-01.)\n'
