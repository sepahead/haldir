#!/usr/bin/env python3
"""Reject mutable CI Actions and formal-tool downloads.

All third-party GitHub Actions must use a full commit SHA. The TLA+ executable
asset must come from the exact release and match the digest recorded in
``tools/pins.toml``. No third-party dependencies are required.
"""
from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
FULL_SHA = re.compile(r"[0-9a-f]{40}")
USES = re.compile(r"^\s*(?:-\s*)?uses:\s*([^@\s]+)@([^\s#]+)", re.MULTILINE)


def fail(messages: list[str]) -> None:
    for message in messages:
        print(f"verify-ci-pins: FAIL: {message}", file=sys.stderr)
    sys.exit(1)


def main() -> None:
    problems: list[str] = []
    workflow_files = sorted(WORKFLOWS.glob("*.y*ml"))
    if not workflow_files:
        fail(["no workflow files found"])

    action_count = 0
    for path in workflow_files:
        text = path.read_text()
        for action, ref in USES.findall(text):
            if action.startswith("./"):
                continue
            action_count += 1
            if not FULL_SHA.fullmatch(ref):
                problems.append(
                    f"{path.relative_to(ROOT)} uses mutable action ref {action}@{ref}"
                )

    pins = tomllib.loads((ROOT / "tools" / "pins.toml").read_text())
    formal = pins.get("formal", {})
    version = formal.get("tla_tools_version", "")
    digest = formal.get("tla_tools_sha256", "")
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        problems.append(f"formal.tla_tools_version is not exact: {version!r}")
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        problems.append("formal.tla_tools_sha256 is not a 64-hex digest")

    formal_path = WORKFLOWS / "formal.yml"
    formal_text = formal_path.read_text() if formal_path.is_file() else ""
    expected_version = f'TLA_TOOLS_VERSION: "{version}"'
    expected_digest = f'TLA_TOOLS_SHA256: "{digest}"'
    if expected_version not in formal_text:
        problems.append("formal workflow version disagrees with tools/pins.toml")
    if expected_digest not in formal_text:
        problems.append("formal workflow digest disagrees with tools/pins.toml")
    if "releases/latest" in formal_text:
        problems.append("formal workflow uses a moving releases/latest URL")
    if "sha256sum --check --strict" not in formal_text:
        problems.append("formal workflow does not verify the TLA+ asset before execution")

    if problems:
        fail(problems)
    print(
        "verify-ci-pins: OK "
        f"({action_count} immutable Action uses; TLA+ v{version} digest pinned)"
    )


if __name__ == "__main__":
    main()
