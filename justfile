# Canonical local checks for Haldir. `just ci` MUST be the same logical gate as PR CI.
# If `just` is not installed, run the underlying cargo/python commands directly
# (see .github/workflows/ci.yml, which does not depend on `just`).

set shell := ["bash", "-uc"]

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
    cargo deny check

conformance:
    cargo test --workspace --locked -- vectors

model:
    cargo test -p haldir-state --locked -- model::

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

verify-release-authority:
    python3 -m unittest tools/release/test_verify_authority_model.py
    python3 tools/release/verify-authority-model.py

interop:
    tmp="$(mktemp)"; trap 'rm -f "$tmp"' EXIT; cargo run -q -p haldir-crypto --example emit_interop_vectors >"$tmp"; diff -u tools/interop/vectors.json "$tmp"; python3 tools/interop/verify_cose.py tools/interop/vectors.json

diff-check:
    git diff --check

# Canonical offline gate. Platform-specific and TLA+ jobs still run in GitHub CI.
ci:
    bash tools/p0r-exit-gate.sh
