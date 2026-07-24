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
FR2_COMPAT_DIR=
cleanup_fr2_compat() {
  builtin trap - EXIT HUP INT TERM
  if [[ -n "$FR2_COMPAT_DIR" ]]; then
    /bin/rm -f -- \
      "$FR2_COMPAT_DIR/current-audit-gate.sh" \
      "$FR2_COMPAT_DIR/test_verify_current_audit_fr_0002.py" \
      "$FR2_COMPAT_DIR/verify-current-audit.py"
    /bin/rmdir -- "$FR2_COMPAT_DIR"
  fi
}
builtin trap cleanup_fr2_compat EXIT
builtin trap 'builtin exit 129' HUP
builtin trap 'builtin exit 130' INT
builtin trap 'builtin exit 143' TERM
FR2_COMPAT_DIR="$(/usr/bin/mktemp -d /tmp/haldir-fr2-gate.XXXXXX)"
readonly FR2_COMPAT_DIR
/bin/ln -s \
  "$PWD/tools/release/test_verify_current_audit_fr_0002.py" \
  "$FR2_COMPAT_DIR/test_verify_current_audit_fr_0002.py"
/bin/ln -s \
  "$PWD/tools/release/verify-current-audit.py" \
  "$FR2_COMPAT_DIR/verify-current-audit.py"
/usr/bin/env \
  -i \
  GIT_NO_REPLACE_OBJECTS=1 \
  PATH=/usr/bin:/bin \
  /usr/bin/git cat-file blob 5255d9b4ff685231cf86bd30368a71f26e2d69fa \
  > "$FR2_COMPAT_DIR/current-audit-gate.sh"
"$PYTHON3" -B -I -W error::ResourceWarning \
  "$FR2_COMPAT_DIR/test_verify_current_audit_fr_0002.py"
"$PYTHON3" -I -W error tools/release/test_verify_current_audit_fr_0003.py
"$PYTHON3" -I -W error tools/release/test_current_audit_resource_profile.py
"$PYTHON3" -I tools/release/verify-current-audit.py
