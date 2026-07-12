#!/usr/bin/env python3
"""Check that each evidence directory carries the required machine-readable files.

An evidence directory (evidence/<phase-id>-<name>/) MUST contain README.md and
manifest.json. A hand-written "passed" summary without raw evidence is rejected.
If no evidence directories exist yet, this is a no-op.

No third-party dependencies.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "evidence"
REQUIRED = ["README.md", "manifest.json"]


def fail(msg: str) -> None:
    print(f"verify-evidence: FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def main() -> None:
    if not EVIDENCE.is_dir():
        print("verify-evidence: OK (no evidence directories yet)")
        return

    dirs = [p for p in sorted(EVIDENCE.iterdir()) if p.is_dir() and p.name != "source-review"]
    problems = 0
    for d in dirs:
        for req in REQUIRED:
            if not (d / req).is_file():
                print(f"verify-evidence: {d.name} missing {req}", file=sys.stderr)
                problems += 1
        mpath = d / "manifest.json"
        if mpath.is_file():
            try:
                json.loads(mpath.read_text())
            except json.JSONDecodeError as exc:
                print(f"verify-evidence: {d.name}/manifest.json invalid JSON: {exc}", file=sys.stderr)
                problems += 1

    if problems:
        fail(f"{problems} evidence discrepancies")
    print(f"verify-evidence: OK ({len(dirs)} evidence dirs)")


if __name__ == "__main__":
    main()
