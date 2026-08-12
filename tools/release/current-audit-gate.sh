#!/bin/bash -p
# Compact epoch-19 signed-lineage and immutable-pin gate.
set -euo pipefail
IFS=$'\n\t'
umask 077

builtin unset \
  BASH_ENV CDPATH DYLD_INSERT_LIBRARIES ENV GLOBIGNORE LD_PRELOAD \
  GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_CONFIG_COUNT GIT_CONFIG_GLOBAL \
  GIT_CONFIG_SYSTEM GIT_DIR GIT_EXEC_PATH GIT_INDEX_FILE \
  GIT_OBJECT_DIRECTORY GIT_REPLACE_REF_BASE GIT_WORK_TREE \
  HALDIR_CARGO \
  PYTHONHOME PYTHONINSPECT PYTHONPATH PYTHONSTARTUP
builtin unalias -a 2>/dev/null || true
builtin unset -f cargo git python3 rustup 2>/dev/null || true
builtin hash -r

readonly GIT=/usr/bin/git
ROOT="$("$GIT" -c core.hooksPath=/dev/null rev-parse --show-toplevel)"
readonly ROOT
cd "$ROOT"

mode=full
if [[ "${1:-}" == --lineage-only ]]; then
  mode=lineage
  shift
fi
readonly mode
[[ "$#" -le 1 ]] || {
  builtin printf '%s\n' \
    'current-audit-gate: expected [--lineage-only] [commit]' >&2
  exit 1
}
requested_commit="${1:-HEAD}"
CANDIDATE="$(
  "$GIT" -c core.hooksPath=/dev/null rev-parse \
    --verify "${requested_commit}^{commit}"
)"
readonly CANDIDATE
[[ "$CANDIDATE" =~ ^[0-9a-f]{40}$ ]] || {
  builtin printf '%s\n' 'current-audit-gate: invalid candidate commit' >&2
  exit 1
}

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
  builtin printf '%s\n' 'current-audit-gate: untrusted python3 executable' >&2
  exit 1
}

export GIT_CONFIG_GLOBAL=/dev/null
export GIT_CONFIG_NOSYSTEM=1
export GIT_NO_REPLACE_OBJECTS=1
export LC_ALL=C
export PYTHONDONTWRITEBYTECODE=1
export PYTHONHASHSEED=0

if [[ "$mode" == full ]]; then
  RUSTUP_CANDIDATE="$(builtin type -P rustup)"
  readonly RUSTUP_CANDIDATE
  RUSTUP="$(/usr/bin/readlink -f "$RUSTUP_CANDIDATE")"
  readonly RUSTUP
  [[ \
    -n "$RUSTUP" \
    && -f "$RUSTUP" \
    && -x "$RUSTUP" \
    && ! -L "$RUSTUP" \
    && "$RUSTUP" != "$ROOT/"* \
    && -z "$(/usr/bin/find "$RUSTUP" -prune -perm -022 -print)" \
  ]] || {
    builtin printf '%s\n' 'current-audit-gate: untrusted rustup executable' >&2
    exit 1
  }
  CARGO_CANDIDATE="$("$RUSTUP" which --toolchain 1.96.0 cargo)"
  readonly CARGO_CANDIDATE
  HALDIR_CARGO="$(/usr/bin/readlink -f "$CARGO_CANDIDATE")"
  readonly HALDIR_CARGO
  [[ \
    -n "$HALDIR_CARGO" \
    && -f "$HALDIR_CARGO" \
    && -x "$HALDIR_CARGO" \
    && ! -L "$HALDIR_CARGO" \
    && "$HALDIR_CARGO" != "$ROOT/"* \
    && -z "$(/usr/bin/find "$HALDIR_CARGO" -prune -perm -022 -print)" \
  ]] || {
    builtin printf '%s\n' 'current-audit-gate: untrusted cargo executable' >&2
    exit 1
  }
  CARGO_VERSION="$("$HALDIR_CARGO" --version)"
  readonly CARGO_VERSION
  [[ "$CARGO_VERSION" =~ ^cargo\ 1\.96\.0\ \([0-9a-f]{7,40}\ 20[0-9]{2}-[0-9]{2}-[0-9]{2}\)$ ]] || {
    builtin printf '%s\n' 'current-audit-gate: cargo version differs from 1.96.0' >&2
    exit 1
  }
  export HALDIR_CARGO
  export PATH="${PYTHON3%/*}:${HALDIR_CARGO%/*}:/usr/bin:/bin"
  export RUSTUP_TOOLCHAIN=1.96.0
else
  export PATH="${PYTHON3%/*}:/usr/bin:/bin"
fi

"$PYTHON3" -I -B -S -c \
  'import sys; assert sys.implementation.name == "cpython"; assert sys.version_info >= (3, 11)'
if [[ "$mode" == full ]]; then
  "$PYTHON3" -I -B -W error tools/release/test_verify_current_lineage.py
  "$PYTHON3" -I -B -W error tools/verify-pins.py
  "$PYTHON3" -I -B -W error tools/verify-ci-pins.py
fi
"$PYTHON3" -I -B -W error tools/release/verify-current-lineage.py \
  --commit "$CANDIDATE"

parent_count="$(
  "$GIT" show -s --format=%P "$CANDIDATE" | /usr/bin/wc -w
)"
[[ "$parent_count" -eq 1 ]] || {
  builtin printf '%s\n' 'current-audit-gate: candidate must have one parent' >&2
  exit 1
}
"$GIT" -c core.hooksPath=/dev/null diff --check "${CANDIDATE}^" "$CANDIDATE"

builtin printf 'current-audit-gate: OK (%s; signed linear epoch 19; release NO_GO)\n' \
  "$mode"
