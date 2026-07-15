#!/usr/bin/env bash
# Immutable entry point for the current-head qualification framework.
set -euo pipefail

builtin unset BASH_ENV ENV CDPATH GLOBIGNORE
builtin unalias -a 2>/dev/null || true
builtin unset -f python3 2>/dev/null || true
builtin hash -r
PYTHON3="$(builtin type -P python3)"
readonly PYTHON3

"$PYTHON3" -I tools/release/test_verify_current_audit.py
"$PYTHON3" -I tools/release/test_current_audit_resource_profile.py
"$PYTHON3" -I tools/release/verify-current-audit.py
