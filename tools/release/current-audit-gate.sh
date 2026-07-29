#!/usr/bin/env bash
# Epoch-15 current-head gate. The signed FR-0010 through FR-0012 repair
# boundaries and the signed FR-0013 qualification boundary are frozen; none of
# their Python verifiers execute on successors.
set -euo pipefail
IFS=$'\n\t'
umask 077

builtin unset \
  BASH_ENV CDPATH DYLD_INSERT_LIBRARIES ENV GLOBIGNORE LD_PRELOAD \
  GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_CONFIG_COUNT GIT_CONFIG_GLOBAL \
  GIT_CONFIG_SYSTEM GIT_DIR GIT_EXEC_PATH GIT_INDEX_FILE \
  GIT_OBJECT_DIRECTORY GIT_REPLACE_REF_BASE GIT_WORK_TREE \
  PYTHONHOME PYTHONINSPECT PYTHONPATH PYTHONSTARTUP
builtin unalias -a 2>/dev/null || true
builtin unset -f python3 2>/dev/null || true
builtin hash -r
export GIT_CONFIG_GLOBAL=/dev/null
export GIT_CONFIG_NOSYSTEM=1
export GIT_NO_REPLACE_OBJECTS=1
export LC_ALL=C
export PYTHONDONTWRITEBYTECODE=1
export PYTHONHASHSEED=0

readonly GIT=/usr/bin/git
ROOT="$(
  "$GIT" -c core.hooksPath=/dev/null rev-parse --show-toplevel
)"
readonly ROOT
cd "$ROOT"

if [[ -n ${pythonLocation:-} ]]; then
  PYTHON_CANDIDATE="${pythonLocation}/bin/python3"
else
  PYTHON_CANDIDATE="$(builtin type -P python3)"
fi
readonly PYTHON_CANDIDATE
PYTHON3="$(/usr/bin/readlink -f "$PYTHON_CANDIDATE")"
readonly PYTHON3
[[ \
  -n "$PYTHON3" \
  && -f "$PYTHON3" \
  && -x "$PYTHON3" \
  && ! -L "$PYTHON3" \
  && "$PYTHON3" != "$ROOT/"* \
  && -z "$(/usr/bin/find "$PYTHON3" -prune -perm -022 -print)" \
]] || {
  builtin printf '%s\n' \
    'current-audit-gate: untrusted python3 executable' >&2
  exit 1
}
export PATH="${PYTHON3%/*}:/usr/bin:/bin"
"$PYTHON3" -I -B -S -c \
  'import sys; assert sys.implementation.name == "cpython"; assert sys.version_info[:3] == (3, 14, 6)'

"$PYTHON3" -I -B -W error \
  tools/release/test_verify_framework_recovery_fr_0014.py
"$PYTHON3" -I -B -W error tools/verify-ci-pins.py
"$PYTHON3" -I -B -W error \
  tools/release/verify-framework-recovery-fr-0014.py

parent_count="$("$GIT" show -s --format=%P HEAD | /usr/bin/wc -w)"
[[ "$parent_count" -eq 1 ]] || {
  printf '%s\n' 'current-audit-gate: HEAD must have exactly one parent' >&2
  exit 1
}
"$GIT" -c core.hooksPath=/dev/null diff --check HEAD^ HEAD

printf '%s\n' \
  'current-audit-gate: OK (epoch 15; signed linear scope; release NO_GO)'
