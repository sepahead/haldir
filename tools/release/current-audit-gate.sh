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
FR5_COMPAT_DIR=
FR6_COMPAT_DIR=
FR7_COMPAT_DIR=
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
  if [[ -n "$FR5_COMPAT_DIR" ]]; then
    /bin/rm -f -- \
      "$FR5_COMPAT_DIR/test_verify_current_audit_fr_0005.py" \
      "$FR5_COMPAT_DIR/verify-current-audit.py"
    /bin/rmdir -- "$FR5_COMPAT_DIR"
  fi
  if [[ -n "$FR6_COMPAT_DIR" ]]; then
    if [[ -d "$FR6_COMPAT_DIR/tools/release" ]]; then
      /bin/rm -f -- \
        "$FR6_COMPAT_DIR/tools/release/current-audit-gate.sh" \
        "$FR6_COMPAT_DIR/tools/release/test_verify_current_audit_fr_0006.py" \
        "$FR6_COMPAT_DIR/tools/release/verify-current-audit.py"
      /bin/rmdir -- "$FR6_COMPAT_DIR/tools/release"
    fi
    if [[ -d "$FR6_COMPAT_DIR/tools" ]]; then
      /bin/rmdir -- "$FR6_COMPAT_DIR/tools"
    fi
    /bin/rmdir -- "$FR6_COMPAT_DIR"
  fi
  if [[ -n "$FR7_COMPAT_DIR" ]]; then
    case "$FR7_COMPAT_DIR" in
      /tmp/haldir-fr7-gate.??????) ;;
      *) builtin exit 1 ;;
    esac
    if [[ -d "$FR7_COMPAT_DIR" ]]; then
      /bin/chmod -R u+w "$FR7_COMPAT_DIR"
      /bin/rm -rf -- "$FR7_COMPAT_DIR"
    fi
    [[ ! -e "$FR7_COMPAT_DIR" ]]
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
FR5_COMPAT_DIR="$(/usr/bin/mktemp -d /tmp/haldir-fr5-gate.XXXXXX)"
readonly FR5_COMPAT_DIR
/bin/ln -s \
  "$PWD/tools/release/test_verify_current_audit_fr_0005.py" \
  "$FR5_COMPAT_DIR/test_verify_current_audit_fr_0005.py"
/usr/bin/env \
  -i \
  GIT_NO_REPLACE_OBJECTS=1 \
  PATH=/usr/bin:/bin \
  /usr/bin/git cat-file blob 98a71c9c83f9ff305a431b5a1ed473113b65b7a6 \
  > "$FR5_COMPAT_DIR/verify-current-audit.py"
[[ "$(/usr/bin/env \
  -i \
  GIT_NO_REPLACE_OBJECTS=1 \
  PATH=/usr/bin:/bin \
  /usr/bin/git hash-object --no-filters -- \
  "$FR5_COMPAT_DIR/verify-current-audit.py")" \
  == 98a71c9c83f9ff305a431b5a1ed473113b65b7a6 ]]
"$PYTHON3" -B -I -W error \
  "$FR5_COMPAT_DIR/test_verify_current_audit_fr_0005.py"
FR6_COMPAT_DIR="$(/usr/bin/mktemp -d /tmp/haldir-fr6-gate.XXXXXX)"
readonly FR6_COMPAT_DIR
/bin/mkdir -- "$FR6_COMPAT_DIR/tools"
/bin/mkdir -- "$FR6_COMPAT_DIR/tools/release"
/bin/ln -s \
  "$PWD/tools/release/test_verify_current_audit_fr_0006.py" \
  "$FR6_COMPAT_DIR/tools/release/test_verify_current_audit_fr_0006.py"
[[ "$(/usr/bin/env \
  -i \
  GIT_NO_REPLACE_OBJECTS=1 \
  PATH=/usr/bin:/bin \
  /usr/bin/git hash-object --no-filters -- \
  "$FR6_COMPAT_DIR/tools/release/test_verify_current_audit_fr_0006.py")" \
  == b9689ba7461cc16130efa9c128d41690635d2d3b ]]
/usr/bin/env \
  -i \
  GIT_NO_REPLACE_OBJECTS=1 \
  PATH=/usr/bin:/bin \
  /usr/bin/git cat-file blob 4c8dedc5ab1fa84299fc1bcc613c3900324d1d2e \
  > "$FR6_COMPAT_DIR/tools/release/verify-current-audit.py"
/usr/bin/env \
  -i \
  GIT_NO_REPLACE_OBJECTS=1 \
  PATH=/usr/bin:/bin \
  /usr/bin/git cat-file blob 6260a482a62c10cea8961ad0be136ac0b3023ba7 \
  > "$FR6_COMPAT_DIR/tools/release/current-audit-gate.sh"
[[ "$(/usr/bin/env \
  -i \
  GIT_NO_REPLACE_OBJECTS=1 \
  PATH=/usr/bin:/bin \
  /usr/bin/git hash-object --no-filters -- \
  "$FR6_COMPAT_DIR/tools/release/verify-current-audit.py")" \
  == 4c8dedc5ab1fa84299fc1bcc613c3900324d1d2e ]]
[[ "$(/usr/bin/env \
  -i \
  GIT_NO_REPLACE_OBJECTS=1 \
  PATH=/usr/bin:/bin \
  /usr/bin/git hash-object --no-filters -- \
  "$FR6_COMPAT_DIR/tools/release/current-audit-gate.sh")" \
  == 6260a482a62c10cea8961ad0be136ac0b3023ba7 ]]
(
  builtin cd -- "$FR6_COMPAT_DIR"
  "$PYTHON3" -B -I -W error \
    "$FR6_COMPAT_DIR/tools/release/test_verify_current_audit_fr_0006.py"
)
FR7_COMPAT_DIR="$(/usr/bin/mktemp -d /tmp/haldir-fr7-gate.XXXXXX)"
readonly FR7_COMPAT_DIR
/usr/bin/env \
  -i \
  GIT_CONFIG_GLOBAL=/dev/null \
  GIT_CONFIG_NOSYSTEM=1 \
  GIT_NO_REPLACE_OBJECTS=1 \
  PATH=/usr/bin:/bin \
  /usr/bin/git \
  -c core.hooksPath=/dev/null \
  clone \
  --no-local \
  --no-hardlinks \
  --no-checkout \
  --quiet \
  -- "$PWD" "$FR7_COMPAT_DIR/repo"
/usr/bin/env \
  -i \
  GIT_CONFIG_GLOBAL=/dev/null \
  GIT_CONFIG_NOSYSTEM=1 \
  GIT_NO_REPLACE_OBJECTS=1 \
  PATH=/usr/bin:/bin \
  /usr/bin/git \
  -c core.hooksPath=/dev/null \
  -C "$FR7_COMPAT_DIR/repo" \
  checkout --detach --quiet 0ec8c45d50e7e73fbc1994bda27ac7ad127a00a7
[[ "$(/usr/bin/env \
  -i \
  GIT_CONFIG_GLOBAL=/dev/null \
  GIT_CONFIG_NOSYSTEM=1 \
  GIT_NO_REPLACE_OBJECTS=1 \
  PATH=/usr/bin:/bin \
  /usr/bin/git -C "$FR7_COMPAT_DIR/repo" rev-parse HEAD)" \
  == 0ec8c45d50e7e73fbc1994bda27ac7ad127a00a7 ]]
[[ "$(/usr/bin/env \
  -i \
  GIT_CONFIG_GLOBAL=/dev/null \
  GIT_CONFIG_NOSYSTEM=1 \
  GIT_NO_REPLACE_OBJECTS=1 \
  PATH=/usr/bin:/bin \
  /usr/bin/git -C "$FR7_COMPAT_DIR/repo" rev-parse 'HEAD^{tree}')" \
  == 717284e47c7b457432ba3ef433ca19222ccd82ff ]]
[[ "$(/usr/bin/env \
  -i \
  GIT_CONFIG_GLOBAL=/dev/null \
  GIT_CONFIG_NOSYSTEM=1 \
  GIT_NO_REPLACE_OBJECTS=1 \
  PATH=/usr/bin:/bin \
  /usr/bin/git -C "$FR7_COMPAT_DIR/repo" hash-object --no-filters -- \
  "$FR7_COMPAT_DIR/repo/tools/release/verify-current-audit.py")" \
  == 2502af4b7d9466d86b22fa4f796b751588b7ffe2 ]]
[[ "$(/usr/bin/env \
  -i \
  GIT_CONFIG_GLOBAL=/dev/null \
  GIT_CONFIG_NOSYSTEM=1 \
  GIT_NO_REPLACE_OBJECTS=1 \
  PATH=/usr/bin:/bin \
  /usr/bin/git -C "$FR7_COMPAT_DIR/repo" hash-object --no-filters -- \
  "$FR7_COMPAT_DIR/repo/tools/release/test_verify_current_audit_fr_0007.py")" \
  == 511fda019f190a7da09641c8910c7e1f1b8f33c3 ]]
[[ "$(/usr/bin/env \
  -i \
  GIT_CONFIG_GLOBAL=/dev/null \
  GIT_CONFIG_NOSYSTEM=1 \
  GIT_NO_REPLACE_OBJECTS=1 \
  PATH=/usr/bin:/bin \
  /usr/bin/git -C "$FR7_COMPAT_DIR/repo" hash-object --no-filters -- \
  "$FR7_COMPAT_DIR/repo/tools/release/current-audit-gate.sh")" \
  == e78c6434438fd98c91710f0a91da0e06239ba3cf ]]
[[ "$(/usr/bin/env \
  -i \
  GIT_CONFIG_GLOBAL=/dev/null \
  GIT_CONFIG_NOSYSTEM=1 \
  GIT_NO_REPLACE_OBJECTS=1 \
  PATH=/usr/bin:/bin \
  /usr/bin/git -C "$FR7_COMPAT_DIR/repo" hash-object --no-filters -- \
  "$FR7_COMPAT_DIR/repo/release/0.9.0/current-head/closures/framework-recovery/FR-0007-plan.json")" \
  == 6ee2a3dac503c89455e947b675e0170970bfd879 ]]
(
  builtin cd -- "$FR7_COMPAT_DIR/repo"
  "$PYTHON3" -B -I -W error \
    tools/release/test_verify_current_audit_fr_0007.py
)
"$PYTHON3" -B -I -W error tools/release/test_verify_current_audit_fr_0008.py
"$PYTHON3" -B -I -W error tools/release/verify-current-audit.py
