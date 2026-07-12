#!/usr/bin/env python3
"""Reject accidental overclaims in public-facing docs (runbook Phase 2 step 5).

A small set of high-risk phrases must never appear as an *affirmative* claim in
README/SECURITY or the docs tree. A line is allowed to contain such a phrase only
when it is clearly scoped/negated (e.g. "not ... complete mediation", "out of
scope", "unproven", "future") or references a claim id (`CL-...`). This is a drift
guard, not a substitute for review.

No third-party dependencies.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Phrases that stay false for the P0-R (repaired pure core) profile.
FORBIDDEN = [
    "production ready",
    "production-ready",
    "airworthy",
    "certified",
    "complete mediation",
    "live firewall",
    "inline firewall",
    "ncp interoperable",
    "ncp-interoperable",
    "neuromorphic equivalent",
    "backend equivalent",
    "hardware validated",
]

# If a line contains any of these, the forbidden phrase is treated as scoped/negated.
GUARDS = [
    "not ", "n't", "never", "no ", "cannot", "without", "unproven", "un-proven",
    "out of scope", "out-of-scope", "out of p0", "future", "deferred", "would ",
    "requires", "pending", "absent", "is not", "are not", "does not", "do not",
    "must ", "should ", "cl-", "not claimed", "not established", "limitations",
    "roadmap", "when ", "only after", "later",
]

# Scan only the AUTHORED claim surface, not imported reference material (the
# normative spec, the runbook, the project audit/discussion records analyse these
# phrases as requirements and must not be policed here).
AUTHORED_DOCS = [
    "README.md",
    "SECURITY.md",
    "docs/LIMITATIONS.md",
    "docs/COMPLETION-CHECKLIST.md",
    "docs/ASSURANCE-PROFILES.md",
    "docs/THREAT-MODEL.md",
    "docs/AUTHORITY-GRAPH.md",
    "docs/EVIDENCE-SEMANTICS.md",
    "docs/NCP-COMPATIBILITY.md",
    "docs/RESEARCH-PROTOCOL.md",
    "docs/DEPENDENCY-RATIONALE.md",
    "docs/CLAIM-LEDGER.md",
]
# Architecture decision records are authored claim surface too; scan them all.
FILES = [ROOT / p for p in AUTHORED_DOCS] + sorted((ROOT / "docs" / "adr").glob("*.md"))


def fail(msg: str) -> None:
    print(f"verify-claims: FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def main() -> None:
    problems = 0
    for path in FILES:
        if not path.is_file():
            continue
        def norm(s: str) -> str:
            # strip markdown emphasis so "**not**" matches the "not " guard
            return s.lower().replace("*", "").replace("`", "").replace("_", " ")

        lines = path.read_text().splitlines()
        for lineno, raw in enumerate(lines, start=1):
            low = norm(raw)
            # A guard on the current OR previous line scopes/negates the phrase
            # (handles sentence wrapping, e.g. "not\nproduction ready").
            prev = norm(lines[lineno - 2]) if lineno >= 2 else ""
            for phrase in FORBIDDEN:
                if phrase in low and not any(g in low or g in prev for g in GUARDS):
                    rel = path.relative_to(ROOT)
                    print(
                        f"verify-claims: {rel}:{lineno}: unscoped forbidden phrase "
                        f"{phrase!r}: {raw.strip()[:100]}",
                        file=sys.stderr,
                    )
                    problems += 1
    if problems:
        fail(f"{problems} unscoped overclaim(s); scope/negate them or cite a claim id")
    print(f"verify-claims: OK ({len(FILES)} files scanned)")


if __name__ == "__main__":
    # `re` imported for future structured checks; keep the dependency explicit.
    _ = re
    main()
