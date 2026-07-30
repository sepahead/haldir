# Canonical local checks for Haldir. `just ci` runs the platform-independent
# P0 gate. Platform-specific checks remain hosted CI responsibilities; the
# Java-dependent TLA+ recipes are explicit and intentionally separate.
# If `just` is unavailable, run the underlying command directly.

set shell := ["/usr/bin/env", "-u", "BASH_ENV", "-u", "ENV", "/bin/bash", "--noprofile", "--norc", "-uc"]

default: ci

fmt:
    cargo fmt --all

fmt-check:
    cargo fmt --all -- --check

lint:
    cargo clippy --workspace --all-targets --all-features --locked -- -D warnings

test:
    cargo test --workspace --locked

test-all:
    cargo test --workspace --all-targets --all-features --locked

docs:
    RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features --locked

doc-test:
    cargo test --workspace --doc --locked

build-no-default:
    cargo build --workspace --no-default-features --locked

lint-default:
    cargo clippy --workspace --locked -- -D warnings

deny:
    cargo deny --all-features check

conformance:
    cargo test --workspace --locked -- vectors

model:
    cargo test -p haldir-state --locked -- model::

# Populate or reuse the verified formal-tool cache, then run the bounded model.
formal:
    python3 -I -B tools/run_formal.py

# Require the verified cache to be present and prohibit formal-tool acquisition.
formal-offline:
    python3 -I -B tools/run_formal.py --offline

# Hermetic adversarial tests for acquisition, caching, Java, and TLC handling.
formal-runner-test:
    python3 -I -B tools/test_run_formal.py

fuzz-smoke:
    cargo test --workspace --locked -- malformed

range-reference:
    cargo test -p haldir-range --locked

verify-generated:
    python3 tools/verify-generated.py

verify-evidence:
    python3 tools/verify-evidence.py

verify-pins:
    python3 tools/verify-pins.py

verify-ci-pins:
    python3 tools/verify-ci-pins.py

verify-claims:
    python3 tools/verify-claims.py

verify-release-audit:
    python3 -m unittest tools/release/test_verify_audit_inputs.py
    python3 tools/release/verify-audit-inputs.py

verify-current-audit:
    /usr/bin/env -u BASH_ENV -u ENV /bin/bash --noprofile --norc tools/release/current-audit-gate.sh

verify-release-authority:
    python3 -m unittest tools/release/test_verify_authority_model.py
    python3 tools/release/verify-authority-model.py

verify-release-protection:
    python3 -m unittest tools/release/test_generate_task_evidence.py
    python3 tools/release/verify-task-evidence.py --all-present
    python3 -m unittest tools/release/test_verify_protection_model.py
    python3 tools/release/verify-protection-model.py

interop:
    tmp="$(mktemp)"; trap 'rm -f "$tmp"' EXIT; cargo run -q -p haldir-crypto --example emit_interop_vectors >"$tmp"; diff -u tools/interop/vectors.json "$tmp"; python3 tools/interop/verify_cose.py tools/interop/vectors.json

diff-check:
    git diff --check

# Canonical offline P0 gate; excludes the Java-dependent formal recipes.
ci:
    /usr/bin/env -u BASH_ENV -u ENV /bin/bash --noprofile --norc tools/p0r-exit-gate.sh
