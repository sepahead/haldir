#!/usr/bin/env python3
"""Render the fixed single-session Zenoh 1.9 deployment bundle.

The generated files contain only prescribed runtime identity paths. Certificate
and private-key bytes must be provisioned separately at those paths.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from secure_zenoh import (
    DEFAULT_PROFILE,
    ProfileError,
    VerificationError,
    load_profile,
    render_bundle,
    verify_bundle,
    write_bundle,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", type=Path, default=DEFAULT_PROFILE)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        profile = load_profile(args.profile)
        files = render_bundle(profile)
        verify_bundle(profile, files)
        write_bundle(args.output, files)
        written = {
            str(path.relative_to(args.output)): path.read_bytes()
            for path in sorted(args.output.rglob("*"))
            if path.is_file()
        }
        verify_bundle(profile, written)
    except (ProfileError, VerificationError, OSError) as error:
        print(f"render-secure-zenoh: FAIL: {error}", file=sys.stderr)
        return 1
    print(
        f"render-secure-zenoh: OK ({len(files)} deterministic files; "
        "configuration only, no live router evidence)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
