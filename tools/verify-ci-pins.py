#!/usr/bin/env python3
"""Reject mutable CI Actions, container references, and formal-tool downloads.

All third-party GitHub Actions must use a full commit SHA. The TLA+ executable
asset must come from the exact release and match the digest recorded in
``tools/pins.toml``. No third-party dependencies are required.
"""
from __future__ import annotations

from collections import Counter
import hashlib
import re
import sys
import tomllib
from pathlib import Path
from typing import NamedTuple

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
FULL_SHA = re.compile(r"[0-9a-f]{40}")
ACTION = re.compile(
    r"(?P<action>[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+"
    r"(?:/[A-Za-z0-9_./-]+)?)@(?P<ref>[0-9a-f]{40})"
)
DOCKER = re.compile(
    r"docker://(?P<image>[A-Za-z0-9._:/-]+)"
    r"@sha256:(?P<digest>[0-9a-f]{64})"
)
LOCAL = re.compile(r"\./[A-Za-z0-9_./-]+")
USES_LINE = re.compile(
    r"^\s*(?:-\s*)?uses:\s*(?P<value>\S+?)\s*(?:#.*)?$"
)
ANY_USES_LINE = re.compile(
    r"^\s*(?:-\s*)?(?:uses|\"uses\"|'uses')\s*:",
    re.MULTILINE,
)
INLINE_USES_LINE = re.compile(
    r"^\s*-\s*\{.*(?:^|[\s,{])(?:uses|\"uses\"|'uses')\s*:"
)
REQUIRED_ACTION_PINS = {
    (
        "actions/attest",
        "f7c74d28b9d84cb8768d0b8ca14a4bac6ef463e6",
    ): 2,
    (
        "actions/download-artifact",
        "3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
    ): 2,
    (
        "actions/upload-artifact",
        "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
    ): 3,
}
MAX_WORKFLOW_BYTES = 1024 * 1024
GH_CLI_VERSION = "2.95.0"
GH_CLI_ARCHIVE_SHA256 = (
    "25d1e4729e8808c9ed3d613e96ebd3f3e44446f2d368c89d878a71a36ddb3d8c"
)
GH_CLI_ARCHIVE_BYTES = 14_642_738
GH_CLI_BINARY_SHA256 = (
    "62c11fbaa08835168c3d1acf8a645ac6268a13a5682c73581388c9df0c622617"
)
GH_CLI_BINARY_BYTES = 40_702_114
EXPECTED_RUNNERS = {
    "ci.yml": Counter({"ubuntu-24.04": 6, "macos-15": 1}),
    "formal.yml": Counter({"ubuntu-24.04": 2}),
}
OIDC_JOB_SHA256 = {
    "attest-ci-audit-result": (
        "f69344b3c3b1873a9710d78678e4c9858020c1cdb7999356321226b27734563f"
    ),
    "attest-formal-audit-result": (
        "2b4506613f00db866173814610c4bab2fd7ee005b29b4be3de41a6bb0c89d36f"
    ),
}
RUNS_ON_LINE = re.compile(r"^    runs-on:\s*(\S+)\s*$", re.MULTILINE)


class Use(NamedTuple):
    """One normalized workflow ``uses:`` declaration."""

    kind: str
    name: str
    pin: str
    line: int


def collect_uses(text: str, *, label: str) -> tuple[list[Use], list[str]]:
    """Parse every declaration and reject syntax that could evade pin checks."""

    uses: list[Use] = []
    problems: list[str] = []
    declaration_count = 0
    for line_number, line in enumerate(text.splitlines(), start=1):
        declaration = ANY_USES_LINE.match(line)
        inline = INLINE_USES_LINE.match(line)
        if declaration is None and inline is None:
            continue
        declaration_count += 1
        match = USES_LINE.fullmatch(line)
        if match is None:
            problems.append(
                f"{label}:{line_number} has an unparseable uses declaration"
            )
            continue
        value = match.group("value")
        action = ACTION.fullmatch(value)
        docker = DOCKER.fullmatch(value)
        if action is not None:
            uses.append(
                Use(
                    "action",
                    action.group("action"),
                    action.group("ref"),
                    line_number,
                )
            )
        elif docker is not None:
            uses.append(
                Use(
                    "docker",
                    docker.group("image"),
                    docker.group("digest"),
                    line_number,
                )
            )
        elif LOCAL.fullmatch(value) is not None:
            uses.append(Use("local", value, "", line_number))
        else:
            problems.append(
                f"{label}:{line_number} uses a mutable or invalid reference {value}"
            )
    if len(uses) + len(problems) != declaration_count:
        problems.append(f"{label} contains an unaccounted uses declaration")
    return uses, problems


def _job_block(text: str, job: str, *, label: str) -> str:
    lines = text.splitlines()
    marker = f"  {job}:"
    starts = [index for index, line in enumerate(lines) if line == marker]
    if len(starts) != 1:
        raise ValueError(f"{label} must contain exactly one {job!r} job")
    start = starts[0]
    end = len(lines)
    for index in range(start + 1, len(lines)):
        if re.fullmatch(r"  [A-Za-z0-9_-]+:", lines[index]):
            end = index
            break
    return "\n".join(lines[start:end]) + "\n"


def verify_oidc_job(
    text: str,
    *,
    label: str,
    job: str,
    expected_needs: tuple[str, ...],
) -> list[str]:
    """Enforce the isolated main-only OIDC job's source-free trust boundary."""

    try:
        block = _job_block(text, job, label=label)
    except ValueError as error:
        return [str(error)]
    problems: list[str] = []
    expected_digest = OIDC_JOB_SHA256.get(job)
    observed_digest = hashlib.sha256(block.encode("utf-8")).hexdigest()
    if expected_digest is None or observed_digest != expected_digest:
        problems.append(
            f"{label}:{job} exact reviewed job block digest mismatch"
        )
    required_fragments = (
        "github.repository == 'sepahead/haldir'",
        "github.event_name == 'push'",
        "github.ref == 'refs/heads/main'",
        "      artifact-metadata: write",
        "      attestations: write",
        "      id-token: write",
        "actions/download-artifact@"
        "3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
        "actions/attest@f7c74d28b9d84cb8768d0b8ca14a4bac6ef463e6",
        "          digest-mismatch: error",
    )
    for fragment in required_fragments:
        if block.count(fragment) != 1:
            problems.append(
                f"{label}:{job} requires exactly one {fragment!r}"
            )
    forbidden = (
        "actions/checkout@",
        "uses: ./",
        "uses: docker://",
        "      contents:",
        "pull_request",
    )
    for fragment in forbidden:
        if fragment in block:
            problems.append(f"{label}:{job} forbids {fragment!r}")
    uses, parse_problems = collect_uses(block, label=f"{label}:{job}")
    problems.extend(parse_problems)
    observed = [(use.kind, use.name) for use in uses]
    if observed != [
        ("action", "actions/download-artifact"),
        ("action", "actions/attest"),
    ]:
        problems.append(
            f"{label}:{job} may use only pinned download-artifact and attest"
        )
    rendered_needs = (
        f"    needs: {expected_needs[0]}\n"
        if len(expected_needs) == 1
        else "    needs:\n"
        + "".join(f"      - {dependency}\n" for dependency in expected_needs)
    )
    if block.count(rendered_needs) != 1:
        problems.append(
            f"{label}:{job} needs must be exactly {expected_needs!r}"
        )
    return problems


def _read_workflow(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{path.relative_to(ROOT)} is not a regular file")
    payload = path.read_bytes()
    if not 1 <= len(payload) <= MAX_WORKFLOW_BYTES or b"\0" in payload:
        raise ValueError(f"{path.relative_to(ROOT)} violates workflow size bounds")
    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError(
            f"{path.relative_to(ROOT)} is not valid UTF-8"
        ) from error


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
    docker_count = 0
    observed_actions: Counter[tuple[str, str]] = Counter()
    workflow_texts: dict[str, str] = {}
    for path in workflow_files:
        try:
            text = _read_workflow(path)
        except (OSError, ValueError) as error:
            problems.append(str(error))
            continue
        workflow_texts[path.name] = text
        uses, parse_problems = collect_uses(
            text, label=str(path.relative_to(ROOT))
        )
        problems.extend(parse_problems)
        for use in uses:
            if use.kind == "action":
                action_count += 1
                observed_actions[(use.name, use.pin)] += 1
            elif use.kind == "docker":
                docker_count += 1
    if "ci.yml" in workflow_texts:
        problems.extend(
            verify_oidc_job(
                workflow_texts["ci.yml"],
                label=".github/workflows/ci.yml",
                job="attest-ci-audit-result",
                expected_needs=(
                    "build-test",
                    "clean-build",
                    "feature-matrix",
                    "interop",
                    "macos-compile",
                    "supply-chain",
                ),
            )
        )
    if "formal.yml" in workflow_texts:
        problems.extend(
            verify_oidc_job(
                workflow_texts["formal.yml"],
                label=".github/workflows/formal.yml",
                job="attest-formal-audit-result",
                expected_needs=("tlc-model-check",),
            )
        )
    ci_text = workflow_texts.get("ci.yml", "")
    required_gh_fragments = {
        f"GH_CLI_VERSION: {GH_CLI_VERSION}": 1,
        f"GH_CLI_ARCHIVE_BYTES: {GH_CLI_ARCHIVE_BYTES}": 1,
        f"GH_CLI_ARCHIVE_SHA256: {GH_CLI_ARCHIVE_SHA256}": 1,
        f"GH_CLI_BINARY_BYTES: {GH_CLI_BINARY_BYTES}": 1,
        f"GH_CLI_BINARY_SHA256: {GH_CLI_BINARY_SHA256}": 1,
        (
            "https://github.com/cli/cli/releases/download/"
            "v${GH_CLI_VERSION}/gh_${GH_CLI_VERSION}_linux_amd64.tar.gz"
        ): 1,
        "/usr/bin/sha256sum --check --strict": 3,
        "--proto '=https'": 1,
        "--proto-redir '=https'": 1,
        "--tlsv1.2": 1,
        "--no-same-owner": 1,
        "--no-same-permissions": 1,
        '-- "gh_${GH_CLI_VERSION}_linux_amd64/bin/gh"': 1,
    }
    for exact, expected_count in required_gh_fragments.items():
        if ci_text.count(exact) != expected_count:
            problems.append(
                f"ci workflow must contain exact pinned gh material {exact!r}"
            )
    for workflow, expected_runners in EXPECTED_RUNNERS.items():
        observed_runners = Counter(
            RUNS_ON_LINE.findall(workflow_texts.get(workflow, ""))
        )
        if observed_runners != expected_runners:
            problems.append(
                f"{workflow} runner labels are {dict(observed_runners)!r}; "
                f"expected {dict(expected_runners)!r}"
            )
    for identity, expected_count in REQUIRED_ACTION_PINS.items():
        observed_count = observed_actions[identity]
        if observed_count != expected_count:
            problems.append(
                f"required action pin {identity[0]}@{identity[1]} occurs "
                f"{observed_count} times; expected {expected_count}"
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
        f"({action_count} immutable Action uses; {docker_count} immutable "
        f"container uses; TLA+ v{version} digest pinned)"
    )


if __name__ == "__main__":
    main()
