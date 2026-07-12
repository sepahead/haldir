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
    cargo doc --workspace --no-deps --all-features --locked

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

# Same logical gate as pull-request CI.
ci: fmt-check lint test-all docs deny verify-pins verify-generated
