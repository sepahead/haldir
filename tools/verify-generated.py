#!/usr/bin/env python3
"""Detect drift in committed generated artifacts (contract vectors).

Every file under contracts/vectors/ and contracts/malformed/ (except the manifest
itself) MUST have a matching SHA-256 entry in contracts/vectors/CHECKSUMS.sha256.
The generator that produces the vectors also rewrites that manifest, so a drifted
or hand-edited vector is caught here. If no vectors exist yet, this is a no-op.

No third-party dependencies.
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "contracts" / "vectors" / "CHECKSUMS.sha256"
SCAN_DIRS = [ROOT / "contracts" / "vectors", ROOT / "contracts" / "malformed"]


def fail(msg: str) -> None:
    print(f"verify-generated: FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def main() -> None:
    files: list[Path] = []
    for d in SCAN_DIRS:
        if d.is_dir():
            files += [p for p in sorted(d.rglob("*")) if p.is_file() and p != MANIFEST]

    if not files:
        print("verify-generated: OK (no vectors present yet)")
        return

    if not MANIFEST.is_file():
        fail("contracts/vectors/CHECKSUMS.sha256 missing but vectors exist")

    recorded: dict[str, str] = {}
    for line in MANIFEST.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        digest, _, rel = line.partition("  ")
        recorded[rel.strip()] = digest.strip()

    problems = 0
    for p in files:
        rel = str(p.relative_to(ROOT))
        actual = sha256(p)
        if rel not in recorded:
            print(f"verify-generated: unlisted vector {rel}", file=sys.stderr)
            problems += 1
        elif recorded[rel] != actual:
            print(f"verify-generated: drift in {rel}", file=sys.stderr)
            problems += 1
    listed = set(recorded)
    present = {str(p.relative_to(ROOT)) for p in files}
    for missing in sorted(listed - present):
        print(f"verify-generated: manifest lists missing file {missing}", file=sys.stderr)
        problems += 1

    if problems:
        fail(f"{problems} generated-file discrepancies")
    print(f"verify-generated: OK ({len(files)} vectors match manifest)")


if __name__ == "__main__":
    main()
