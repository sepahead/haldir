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

import sys
import xml.etree.ElementTree as ET
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
    "docs/ARCHITECTURE.md",
    "docs/LIMITATIONS.md",
    "docs/COMPLETION-CHECKLIST.md",
    "docs/ASSURANCE-PROFILES.md",
    "docs/THREAT-MODEL.md",
    "docs/release/0.9.0/THREAT-MODEL.md",
    "docs/AUTHORITY-GRAPH.md",
    "docs/GALADRIEL-PID-ADVISORY-CONTRACT.md",
    "docs/EVIDENCE-SEMANTICS.md",
    "docs/NCP-COMPATIBILITY.md",
    "docs/RESEARCH-PROTOCOL.md",
    "docs/DEPENDENCY-RATIONALE.md",
    "docs/CLAIM-LEDGER.md",
    "docs/ROADMAP-STATUS.md",
]
# Architecture decision records are authored claim surface too; scan them all.
FILES = [ROOT / p for p in AUTHORED_DOCS] + sorted((ROOT / "docs" / "adr").glob("*.md"))

BOUNDARY_PATHS = {
    "contract": "docs/GALADRIEL-PID-ADVISORY-CONTRACT.md",
    "authority": "docs/AUTHORITY-GRAPH.md",
    "specification": (
        "docs/HALDIR-NCP-V0.8.0-TRIPLE-CHECKED-AUDIT-AND-"
        "IMPLEMENTATION-SPECIFICATION-2026.md"
    ),
    "mirror": "docs/galadriels-mirror.md",
    "survey": "docs/pid-security-and-communication.md",
    "svg": "docs/assets/galadriel-pid-advisory-boundary.svg",
}

REQUIRED_SVG_NODES = {
    "scenario-state",
    "sensor-row",
    "target",
    "nis",
    "cusum",
    "signed-correlation",
    "ksg-mi",
    "co-information",
    "o-information",
    "categorical-mgw",
    "typed-evidence",
    "audit-reference",
    "trusted-state",
    "authority-inputs",
    "gate-decision",
    "plant-command",
}

REQUIRED_SOURCE_METHOD_EDGES = {
    ("sensor-row", "nis"),
    ("sensor-row", "cusum"),
    ("sensor-row", "signed-correlation"),
    ("sensor-row", "ksg-mi"),
    ("sensor-row", "co-information"),
    ("sensor-row", "o-information"),
    ("sensor-row", "categorical-mgw"),
    ("target", "categorical-mgw"),
}

FORBIDDEN_ADVISORY_TARGETS = {
    "trusted-state",
    "authority-inputs",
    "gate-decision",
    "plant-command",
}


def fail(msg: str) -> None:
    print(f"verify-claims: FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def compact(text: str) -> str:
    """Collapse prose layout while preserving case and mathematical spelling."""

    return " ".join(text.split())


def boundary_contract_problems(
    *,
    contract: str,
    authority: str,
    specification: str,
    mirror: str,
    survey: str,
    svg: str,
) -> list[str]:
    """Return semantic boundary drift without depending on repository globals."""

    problems: list[str] = []
    contract_compact = compact(contract)
    authority_compact = compact(authority)
    specification_compact = compact(specification)

    contract_requirements = {
        "authorization noninterference equation": (
            r"\operatorname{Authorize}(x,e) =\operatorname{Authorize}(x,e') "
            r"=\operatorname{Authorize}(x)."
        ),
        "plant-command noninterference equation": (
            r"\operatorname{PlantCommand}(x,e) "
            r"=\operatorname{PlantCommand}(x,e') "
            r"=\operatorname{PlantCommand}(x)."
        ),
        "trusted-state noninterference equation": (
            r"\operatorname{TrustedStateSnapshot}(x,e) "
            r"=\operatorname{TrustedStateSnapshot}(x,e') "
            r"=\operatorname{TrustedStateSnapshot}(x)."
        ),
        "audit-record variation equation": (
            r"\operatorname{AuditRecord}(x,e)\;\text{may differ from}\; "
            r"\operatorname{AuditRecord}(x,e')."
        ),
        "complete authority verb boundary": (
            "PID evidence cannot grant, widen, restore, refresh, revoke, "
            "restrict, deny, or exercise authority."
        ),
        "two-axis eligibility tag": "Eligibility = Applicable { contract_id } | Inapplicable { failed_contract }",
        "two-axis execution tag": "Execution = NotRequested { reason } | Requested {",
        "closed requested outcomes": (
            "outcome: Produced | Unavailable | ResourceRejected | Error"
        ),
        "impossible-state rejection": (
            "Inapplicable` pairs with `NotRequested` and `Requested` pairs with "
            "`Applicable`"
        ),
        "exact TargetFree join": "target-or-TargetFree, law, method, configuration",
        "no method or target fallback": "no other method or target may fill the slot as a fallback",
        "separately authorized record-only route": (
            "adapter, if ever built, must be separately authorized for one bounded "
            "audit route"
        ),
        "confidentiality and minimization boundary": (
            "omit raw sensor rows, media, location traces, free-text operator data, "
            "and stable person identifiers"
        ),
        "sociotechnical limitation": (
            "software-path noninterference claims, not sociotechnical noninterference"
        ),
    }
    for label, required in contract_requirements.items():
        if required not in contract_compact:
            problems.append(f"contract missing {label}")

    for method in (
        "Co-information invariant",
        "O-information invariant",
        "NIS diagnostic",
        "CUSUM diagnostic",
        "Signed-correlation diagnostic",
    ):
        if contract_compact.count(method) != 1:
            problems.append(
                f"contract must contain exactly one distinct method-table row for {method}"
            )

    authority_requirements = {
        "authorization equality": (
            "Authorize(x, e) = Authorize(x, e′) = Authorize(x)"
        ),
        "trusted-state equality": (
            "TrustedStateSnapshot(x, e) = TrustedStateSnapshot(x, e′) "
            "= TrustedStateSnapshot(x)"
        ),
        "plant-command equality": (
            "PlantCommand(x, e) = PlantCommand(x, e′) = PlantCommand(x)"
        ),
        "audit-record variation": (
            "AuditRecord(x, e) may differ from AuditRecord(x, e′)"
        ),
    }
    for label, required in authority_requirements.items():
        if required not in authority_compact:
            problems.append(f"authority graph missing {label}")

    specification_requirements = {
        "superseding amendment": "Later Galadriel/PID amendment",
        "retired policy-input proposal": (
            "`AdvisoryEvidenceRefV1` — retired policy-input proposal"
        ),
        "record-only phase": "Phase 16 — possible record-only Galadriel audit evidence",
        "impossible state rejection": "Reject `Inapplicable + Requested`",
        "trusted-state equality obligation": (
            "authorization, `TrustedStateSnapshotV1`, and plant-command bytes are identical"
        ),
    }
    for label, required in specification_requirements.items():
        if required not in specification_compact:
            problems.append(f"specification missing {label}")

    if "Superseded historical design" not in compact(mirror):
        problems.append("Galadriel's Mirror lacks its superseded-history banner")
    if "Superseded design survey" not in compact(survey):
        problems.append("PID design survey lacks its superseded-history banner")

    try:
        root = ET.fromstring(svg)
    except ET.ParseError as exc:
        problems.append(f"authority SVG is not well-formed XML: {exc}")
        return problems

    namespace = {"svg": "http://www.w3.org/2000/svg"}
    title = root.find("svg:title", namespace)
    description = root.find("svg:desc", namespace)
    if title is None or not " ".join(title.itertext()).strip():
        problems.append("authority SVG has no accessible title")
    if description is None or not " ".join(description.itertext()).strip():
        problems.append("authority SVG has no accessible description")

    nodes = {
        value
        for element in root.iter()
        if (value := element.attrib.get("data-node")) is not None
    }
    for node in sorted(REQUIRED_SVG_NODES - nodes):
        problems.append(f"authority SVG missing distinct node {node!r}")

    edges = {
        (source, target)
        for element in root.iter()
        if element.attrib.get("data-edge") is not None
        if (source := element.attrib.get("data-source")) is not None
        if (target := element.attrib.get("data-target")) is not None
    }
    for source, target in sorted(REQUIRED_SOURCE_METHOD_EDGES - edges):
        problems.append(
            f"authority SVG missing exact source/method edge {source!r}->{target!r}"
        )

    target_edges = {edge for edge in edges if edge[0] == "target"}
    if target_edges != {("target", "categorical-mgw")}:
        problems.append(
            "authority SVG target must join categorical MGW exactly once and no other method"
        )

    for source, target in sorted(edges):
        if source in {"typed-evidence", "audit-reference"} and target in FORBIDDEN_ADVISORY_TARGETS:
            problems.append(
                f"authority SVG contains forbidden advisory/control edge {source!r}->{target!r}"
            )

    forbidden_markers = {
        value
        for element in root.iter()
        if (value := element.attrib.get("data-forbidden-edge")) is not None
    }
    if "audit-reference->authority-inputs" not in forbidden_markers:
        problems.append("authority SVG lacks the explicit audit-to-authority stop marker")

    return problems


def load_boundary_documents(root: Path = ROOT) -> dict[str, str]:
    documents: dict[str, str] = {}
    for name, relative in BOUNDARY_PATHS.items():
        path = root / relative
        if not path.is_file():
            raise FileNotFoundError(relative)
        documents[name] = path.read_text(encoding="utf-8")
    return documents


def main() -> None:
    problems = 0
    for path in FILES:
        if not path.is_file():
            fail(f"declared authored claim surface is missing: {path.relative_to(ROOT)}")
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
    try:
        boundary_documents = load_boundary_documents()
    except FileNotFoundError as exc:
        fail(f"declared PID boundary artifact is missing: {exc}")
    for problem in boundary_contract_problems(**boundary_documents):
        print(f"verify-claims: {problem}", file=sys.stderr)
        problems += 1
    if problems:
        fail(f"{problems} authored-claim or PID-boundary problem(s)")
    print(
        "verify-claims: OK "
        f"({len(FILES)} authored files + {len(BOUNDARY_PATHS)} PID boundary artifacts)"
    )


if __name__ == "__main__":
    main()
