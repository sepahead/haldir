#!/usr/bin/env python3
"""Statically verify the Haldir secure Zenoh source profile and rendered bundle.

With no --rendered directory, this verifies a fresh in-memory deterministic
render. It does not start a router and cannot prove live ACL delivery.
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
)


def _read_rendered(directory: Path) -> dict[str, bytes]:
    if not directory.is_dir():
        raise VerificationError(f"rendered path is not a directory: {directory}")
    return {
        str(path.relative_to(directory)): path.read_bytes()
        for path in sorted(directory.rglob("*"))
        if path.is_file()
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", type=Path, default=DEFAULT_PROFILE)
    parser.add_argument("--rendered", type=Path)
    args = parser.parse_args()
    try:
        profile = load_profile(args.profile)
        files = _read_rendered(args.rendered) if args.rendered else render_bundle(profile)
        verify_bundle(profile, files)
    except (ProfileError, VerificationError, OSError) as error:
        print(f"verify-secure-zenoh: FAIL: {error}", file=sys.stderr)
        return 1
    source = str(args.rendered) if args.rendered else "deterministic in-memory render"
    print(
        f"verify-secure-zenoh: OK ({source}; exact default-deny ACL and TLS shape; "
        "no live delivery claim)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
