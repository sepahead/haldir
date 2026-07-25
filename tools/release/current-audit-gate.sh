#!/usr/bin/env bash
# Immutable entry point for the current-head qualification framework.
set -euo pipefail

builtin unset \
  BASH_ENV ENV CDPATH GLOBIGNORE \
  PYTHONHOME PYTHONPATH LD_PRELOAD DYLD_INSERT_LIBRARIES \
  GIT_DIR GIT_WORK_TREE GIT_COMMON_DIR GIT_OBJECT_DIRECTORY \
  GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_REPLACE_REF_BASE GIT_INDEX_FILE \
  GIT_CONFIG_GLOBAL GIT_CONFIG_SYSTEM GIT_CONFIG_COUNT GIT_EXEC_PATH \
  GIT_SSH GIT_SSH_COMMAND GIT_PROXY_COMMAND GIT_EXTERNAL_DIFF GIT_DIFF_OPTS
builtin unalias -a 2>/dev/null || true
builtin unset -f python3 2>/dev/null || true
builtin hash -r
PYTHON3="$(builtin type -P python3)"
readonly PYTHON3

"$PYTHON3" -B -I -W error tools/release/test_verify_current_audit.py
FR2_COMPAT_DIR=
FR3_COMPAT_DIR=
FR4_COMPAT_DIR=
cleanup_fr2_compat() {
  builtin trap - EXIT HUP INT TERM
  if [[ -n "$FR2_COMPAT_DIR" ]]; then
    /bin/rm -f -- \
      "$FR2_COMPAT_DIR/current-audit-gate.sh" \
      "$FR2_COMPAT_DIR/test_verify_current_audit_fr_0002.py" \
      "$FR2_COMPAT_DIR/verify-current-audit.py"
    /bin/rmdir -- "$FR2_COMPAT_DIR"
  fi
  if [[ -n "$FR3_COMPAT_DIR" ]]; then
    /bin/rm -f -- \
      "$FR3_COMPAT_DIR/current-audit-gate.sh" \
      "$FR3_COMPAT_DIR/current-audit-resource-profile.py" \
      "$FR3_COMPAT_DIR/test_current_audit_resource_profile.py" \
      "$FR3_COMPAT_DIR/test_verify_current_audit_fr_0003.py" \
      "$FR3_COMPAT_DIR/verify-current-audit.py"
    /bin/rmdir -- "$FR3_COMPAT_DIR"
  fi
  if [[ -n "$FR4_COMPAT_DIR" ]]; then
    /bin/rm -f -- \
      "$FR4_COMPAT_DIR/test_verify_current_audit_fr_0004.py" \
      "$FR4_COMPAT_DIR/verify-current-audit.py"
    /bin/rmdir -- "$FR4_COMPAT_DIR"
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
[[ "$(/usr/bin/env \
  -i \
  GIT_NO_REPLACE_OBJECTS=1 \
  PATH=/usr/bin:/bin \
  /usr/bin/git hash-object --no-filters -- \
  "$FR2_COMPAT_DIR/current-audit-gate.sh")" \
  == 5255d9b4ff685231cf86bd30368a71f26e2d69fa ]]
"$PYTHON3" -B -I -W error::ResourceWarning \
  "$FR2_COMPAT_DIR/test_verify_current_audit_fr_0002.py"
FR3_COMPAT_DIR="$(/usr/bin/mktemp -d /tmp/haldir-fr3-gate.XXXXXX)"
readonly FR3_COMPAT_DIR
/bin/ln -s \
  "$PWD/tools/release/test_verify_current_audit_fr_0003.py" \
  "$FR3_COMPAT_DIR/test_verify_current_audit_fr_0003.py"
/bin/ln -s \
  "$PWD/tools/release/current-audit-resource-profile.py" \
  "$FR3_COMPAT_DIR/current-audit-resource-profile.py"
/bin/ln -s \
  "$PWD/tools/release/test_current_audit_resource_profile.py" \
  "$FR3_COMPAT_DIR/test_current_audit_resource_profile.py"
/usr/bin/env \
  -i \
  GIT_NO_REPLACE_OBJECTS=1 \
  PATH=/usr/bin:/bin \
  /usr/bin/git cat-file blob f8651670f456f4e1a1c6add10aca2e7b245e62ff \
  > "$FR3_COMPAT_DIR/current-audit-gate.sh"
/usr/bin/env \
  -i \
  GIT_NO_REPLACE_OBJECTS=1 \
  PATH=/usr/bin:/bin \
  /usr/bin/git cat-file blob e053e120851d15502bb64a7b5e18db205244118a \
  > "$FR3_COMPAT_DIR/verify-current-audit.py"
[[ "$(/usr/bin/env \
  -i \
  GIT_NO_REPLACE_OBJECTS=1 \
  PATH=/usr/bin:/bin \
  /usr/bin/git hash-object --no-filters -- \
  "$FR3_COMPAT_DIR/current-audit-gate.sh")" \
  == f8651670f456f4e1a1c6add10aca2e7b245e62ff ]]
[[ "$(/usr/bin/env \
  -i \
  GIT_NO_REPLACE_OBJECTS=1 \
  PATH=/usr/bin:/bin \
  /usr/bin/git hash-object --no-filters -- \
  "$FR3_COMPAT_DIR/verify-current-audit.py")" \
  == e053e120851d15502bb64a7b5e18db205244118a ]]
"$PYTHON3" -B -I -W error \
  "$FR3_COMPAT_DIR/test_verify_current_audit_fr_0003.py"
"$PYTHON3" -B -I -W error tools/release/test_current_audit_resource_profile.py
FR4_COMPAT_DIR="$(/usr/bin/mktemp -d /tmp/haldir-fr4-gate.XXXXXX)"
readonly FR4_COMPAT_DIR
/bin/ln -s \
  "$PWD/tools/release/test_verify_current_audit_fr_0004.py" \
  "$FR4_COMPAT_DIR/test_verify_current_audit_fr_0004.py"
/usr/bin/env \
  -i \
  GIT_NO_REPLACE_OBJECTS=1 \
  PATH=/usr/bin:/bin \
  /usr/bin/git cat-file blob f1fcc6059289ddb738da2a932d3d6014f2f4e377 \
  > "$FR4_COMPAT_DIR/verify-current-audit.py"
[[ "$(/usr/bin/env \
  -i \
  GIT_NO_REPLACE_OBJECTS=1 \
  PATH=/usr/bin:/bin \
  /usr/bin/git hash-object --no-filters -- \
  "$FR4_COMPAT_DIR/verify-current-audit.py")" \
  == f1fcc6059289ddb738da2a932d3d6014f2f4e377 ]]
"$PYTHON3" -B -I -W error \
  "$FR4_COMPAT_DIR/test_verify_current_audit_fr_0004.py"
"$PYTHON3" -B -I -W error tools/release/test_verify_current_audit_fr_0005.py
"$PYTHON3" -B -I -W error tools/release/verify-current-audit.py
