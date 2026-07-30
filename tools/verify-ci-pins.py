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
USES_LINE = re.compile(r"^\s*(?:-\s*)?uses:\s*(?P<value>\S+?)\s*(?:#.*)?$")
ANY_USES_LINE = re.compile(
    r"^\s*(?:-\s*)?(?:uses|\"uses\"|'uses')\s*:",
    re.MULTILINE,
)
INLINE_USES_LINE = re.compile(r"^\s*-\s*\{.*(?:^|[\s,{])(?:uses|\"uses\"|'uses')\s*:")
SIMPLE_MAPPING_LINE = re.compile(
    r"^(?P<indent> *)(?P<sequence>- )?"
    r"(?P<key>[A-Za-z0-9_.-]+):(?P<value>.*)$"
)
SIMPLE_SEQUENCE_LINE = re.compile(r"^ +- [A-Za-z0-9_.-]+(?: +#.*)?$")
BLOCK_SCALAR_VALUE = re.compile(r"^[>|](?:[+-](?:[1-9])?|[1-9](?:[+-])?)?\s*(?:#.*)?$")
GITHUB_EXPRESSION = re.compile(r"\$\{\{[^{}\r\n]*\}\}")
REQUIRED_ACTION_PINS = {
    (
        "actions/checkout",
        "9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0",
    ): 7,
    (
        "actions/cache",
        "55cc8345863c7cc4c66a329aec7e433d2d1c52a9",
    ): 1,
    (
        "actions/attest",
        "508db95dd578ae2727ebd6217d5ba78e4fbda05d",
    ): 2,
    (
        "actions/setup-python",
        "5fda3b95a4ea91299a34e894583c3862153e4b97",
    ): 1,
    (
        "actions/setup-java",
        "03ad4de0992f5dab5e18fcb136590ce7c4a0ac95",
    ): 1,
    (
        "actions/download-artifact",
        "3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
    ): 2,
    (
        "actions/upload-artifact",
        "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
    ): 3,
}
REQUIRED_ACTION_COMMENTS = {
    ("actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7.0.0"): 7,
    ("actions/cache@55cc8345863c7cc4c66a329aec7e433d2d1c52a9 # v6.1.0"): 1,
    ("actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97 # v7.0.0"): 1,
    ("actions/setup-java@03ad4de0992f5dab5e18fcb136590ce7c4a0ac95 # v5.6.0"): 1,
    ("actions/attest@508db95dd578ae2727ebd6217d5ba78e4fbda05d # v4.2.1"): 2,
    ("actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1"): 2,
    ("actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1"): 3,
}
MAX_WORKFLOW_BYTES = 1024 * 1024
GH_CLI_VERSION = "2.96.0"
GH_CLI_ARCHIVE_SHA256 = (
    "83d5c2ccad5498f58bf6368acb1ab32588cf43ab3a4b1c301bf36328b1c8bd60"
)
GH_CLI_ARCHIVE_BYTES = 14_652_560
GH_CLI_BINARY_SHA256 = (
    "56b8bbbb27b066ecb33dbef9a256dc9d1314adaeff0908a752feba6c34053b40"
)
GH_CLI_BINARY_BYTES = 40_722_594
EXPECTED_RUNNERS = {
    "ci.yml": Counter({"ubuntu-24.04": 6, "macos-15": 1}),
    "formal.yml": Counter({"ubuntu-24.04": 2}),
}
OIDC_JOB_SHA256 = {
    "attest-ci-audit-result": (
        "f9685078dba2d50ec8b0e91221e6e35b50556fa928fa220160357fc1766e497e"
    ),
    "attest-formal-audit-result": (
        "889a27a1a0ffa7907e99e521be3614d6c1b70f240969aba29ef1d907af7a1e48"
    ),
}
SUPPLY_CHAIN_JOB_SHA256 = (
    "383df1e48d29bf331c2ba3e874800686142fae0d57d8071c0c08fdf1057d611a"
)
RUNS_ON_LINE = re.compile(r"^    runs-on:\s*(\S+)\s*$", re.MULTILINE)


class Use(NamedTuple):
    """One normalized workflow ``uses:`` declaration."""

    kind: str
    name: str
    pin: str
    line: int


def validate_workflow_syntax(text: str, *, label: str) -> list[str]:
    """Restrict workflows to a uses-safe, line-oriented YAML subset.

    GitHub accepts YAML spellings such as escaped quoted keys, tags, explicit
    keys, aliases, and flow mappings. A raw ``uses:`` scanner cannot decode all
    of those safely without a complete YAML 1.2 implementation. Rejecting those
    unnecessary constructs makes every executable ``uses`` key lexically
    visible to ``collect_uses`` while preserving block scalar command bodies.
    """

    problems: list[str] = []
    block_header_indent: int | None = None
    block_content_indent: int | None = None
    for line_number, line in enumerate(text.splitlines(), start=1):
        indentation = len(line) - len(line.lstrip(" "))
        if block_header_indent is not None:
            if not line.strip():
                continue
            if block_content_indent is None:
                if line.lstrip(" ").startswith("#"):
                    continue
                if indentation > block_header_indent:
                    block_content_indent = indentation
                    continue
            elif indentation >= block_content_indent:
                continue
            block_header_indent = None
            block_content_indent = None
        if not line.strip() or line.lstrip(" ").startswith("#"):
            continue
        if "\t" in line:
            problems.append(
                f"{label}:{line_number} contains a tab outside a block scalar"
            )
            continue
        mapping = SIMPLE_MAPPING_LINE.fullmatch(line)
        if mapping is not None:
            if mapping.group("key") in {"container", "services"}:
                problems.append(
                    f"{label}:{line_number} uses a forbidden job container surface"
                )
                continue
            value = mapping.group("value").strip()
            if BLOCK_SCALAR_VALUE.fullmatch(value) is not None:
                block_header_indent = len(mapping.group("indent")) + (
                    2 if mapping.group("sequence") else 0
                )
                block_content_indent = None
                continue
            masked = GITHUB_EXPRESSION.sub("", value).replace("{0}", "")
            if (
                "{" in masked
                or "}" in masked
                or (("[" in masked or "]" in masked) and ":" in masked)
            ):
                problems.append(f"{label}:{line_number} uses a forbidden flow mapping")
            continue
        if SIMPLE_SEQUENCE_LINE.fullmatch(line) is not None:
            continue
        problems.append(f"{label}:{line_number} is outside the uses-safe YAML subset")
    return problems


def collect_uses(text: str, *, label: str) -> tuple[list[Use], list[str]]:
    """Parse every declaration and reject syntax that could evade pin checks."""

    uses: list[Use] = []
    problems = validate_workflow_syntax(text, label=label)
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
            problems.append(
                f"{label}:{line_number} uses a forbidden repository-local action"
            )
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
        problems.append(f"{label}:{job} exact reviewed job block digest mismatch")
    required_fragments = (
        "github.repository == 'sepahead/haldir'",
        "github.event_name == 'push'",
        "github.ref == 'refs/heads/main'",
        "      artifact-metadata: write",
        "      attestations: write",
        "      id-token: write",
        "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
        "actions/attest@508db95dd578ae2727ebd6217d5ba78e4fbda05d",
        "          digest-mismatch: error",
    )
    for fragment in required_fragments:
        if block.count(fragment) != 1:
            problems.append(f"{label}:{job} requires exactly one {fragment!r}")
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
        problems.append(f"{label}:{job} needs must be exactly {expected_needs!r}")
    return problems


def verify_supply_chain_job(text: str, *, label: str) -> list[str]:
    """Bind the complete reviewed supply-chain job, including command order."""

    try:
        block = _job_block(text, "supply-chain", label=label)
    except ValueError as error:
        return [str(error)]
    observed = hashlib.sha256(block.encode("utf-8")).hexdigest()
    if observed != SUPPLY_CHAIN_JOB_SHA256:
        return [f"{label}:supply-chain exact reviewed job block digest mismatch"]
    return []


def _read_workflow(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{path.relative_to(ROOT)} is not a regular file")
    payload = path.read_bytes()
    if not 1 <= len(payload) <= MAX_WORKFLOW_BYTES or b"\0" in payload:
        raise ValueError(f"{path.relative_to(ROOT)} violates workflow size bounds")
    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError(f"{path.relative_to(ROOT)} is not valid UTF-8") from error


def fail(messages: list[str]) -> None:
    for message in messages:
        print(f"verify-ci-pins: FAIL: {message}", file=sys.stderr)
    sys.exit(1)


def main() -> None:
    problems: list[str] = []
    workflow_files = sorted(WORKFLOWS.glob("*.y*ml"))
    if not workflow_files:
        fail(["no workflow files found"])
    observed_workflow_names = {path.name for path in workflow_files}
    if observed_workflow_names != {"ci.yml", "formal.yml"}:
        problems.append("workflow set differs from the reviewed ci.yml/formal.yml pair")

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
        uses, parse_problems = collect_uses(text, label=str(path.relative_to(ROOT)))
        problems.extend(parse_problems)
        for use in uses:
            if use.kind == "action":
                action_count += 1
                observed_actions[(use.name, use.pin)] += 1
            elif use.kind == "docker":
                docker_count += 1
    if "ci.yml" in workflow_texts:
        problems.extend(
            verify_supply_chain_job(
                workflow_texts["ci.yml"],
                label=".github/workflows/ci.yml",
            )
        )
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
        "/usr/bin/sha256sum --check --strict": 4,
        "--proto '=https'": 2,
        "--proto-redir '=https'": 2,
        "--tlsv1.2": 2,
        "--no-same-owner": 1,
        "--no-same-permissions": 1,
        '-- "gh_${GH_CLI_VERSION}_linux_amd64/bin/gh"': 1,
        "gh version ${GH_CLI_VERSION} (2026-07-02)": 1,
    }
    for exact, expected_count in required_gh_fragments.items():
        if ci_text.count(exact) != expected_count:
            problems.append(
                f"ci workflow must contain exact pinned gh material {exact!r}"
            )
    try:
        supply_chain_block = _job_block(
            ci_text,
            "supply-chain",
            label=".github/workflows/ci.yml",
        )
    except ValueError as error:
        problems.append(str(error))
        supply_chain_block = ""
    required_cargo_deny_fragments = {
        (
            "CARGO_DENY_URL: https://github.com/EmbarkStudios/cargo-deny/"
            "releases/download/0.20.2/"
            "cargo-deny-0.20.2-x86_64-unknown-linux-musl.tar.gz"
        ): 1,
        (
            "RUSTSEC_URL: https://codeload.github.com/RustSec/advisory-db/"
            "tar.gz/7c7ccac53056b87f69ac677f15ea2d9a98a6f8e2"
        ): 1,
        "python3 -I -B tools/pinned_cargo_deny.py install": 1,
        "python3 -I -B tools/pinned_cargo_deny.py seed-advisory-db": 1,
        "--target x86_64-unknown-linux-musl": 1,
        'cargo fetch --locked --manifest-path "$GITHUB_WORKSPACE/Cargo.toml"': 1,
        "/usr/bin/unshare --net --": 1,
        "/usr/bin/setpriv": 1,
        '--reuid="$RUNNER_UID"': 1,
        '--regid="$RUNNER_GID"': 1,
        "--clear-groups": 1,
        "--inh-caps=-all": 1,
        "--bounding-set=-all": 1,
        "--no-new-privs": 1,
        '--max-filesize "$MAX_BYTES"': 1,
        "${CARGO_DENY_URL}|${DENY_ARCHIVE}|4936832": 1,
        "${RUSTSEC_URL}|${RUSTSEC_ARCHIVE}|441027": 1,
        'PATH="$TOOLCHAIN_BIN:/usr/bin:/bin"': 1,
        "GIT_CONFIG_GLOBAL=/dev/null": 2,
        "GIT_CONFIG_NOSYSTEM=1": 2,
        "GIT_NO_REPLACE_OBJECTS=1": 2,
        "b329e25933d01c36dd7c47d84ea5716694f9b7caf53a5003d45674703a8ed54a": 1,
        "1ec5ce48144b04d9bf3e740b4dd3c2d61d8cc4ce": 1,
        "2d3ab21e05f8b06ad2e232f92894b5e247d817ce": 1,
        'CARGO_NET_OFFLINE: "true"': 1,
        "RUSTUP_TOOLCHAIN=1.96.0": 1,
        "      - name: Install pinned Rust toolchain\n"
        "        run: rustup toolchain install 1.96.0 --profile minimal\n"
        "      - name: Verify current-head 0.9 audit cut": 1,
        "      - name: Prime exact locked dependency inputs\n"
        "        shell: /bin/bash --noprofile --norc -euo pipefail {0}\n"
        "        run: cargo fetch --locked --manifest-path "
        '"$GITHUB_WORKSPACE/Cargo.toml"': 1,
        "--frozen": 1,
        "--all-features": 1,
        '--manifest-path "$GITHUB_WORKSPACE/Cargo.toml"': 2,
    }
    for exact, expected_count in required_cargo_deny_fragments.items():
        observed_count = supply_chain_block.count(exact)
        if observed_count != expected_count:
            problems.append(
                "supply-chain job must contain exact cargo-deny contract "
                f"{exact!r} {expected_count} time(s), observed {observed_count}"
            )
    if "EmbarkStudios/cargo-deny-action" in "\n".join(workflow_texts.values()):
        problems.append("the superseded cargo-deny Action must be absent")
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
    expected_actions = Counter(REQUIRED_ACTION_PINS)
    if observed_actions != expected_actions:
        problems.append(
            "complete Action pin multiset differs: "
            f"observed {dict(observed_actions)!r}; "
            f"expected {dict(expected_actions)!r}"
        )
    if action_count != sum(REQUIRED_ACTION_PINS.values()):
        problems.append("total immutable Action use count differs")
    if docker_count != 0:
        problems.append("workflow Docker uses are forbidden")
    all_workflows = "\n".join(workflow_texts.values())
    for fragment, expected_count in REQUIRED_ACTION_COMMENTS.items():
        observed_count = all_workflows.count(fragment)
        if observed_count != expected_count:
            problems.append(
                f"required action annotation {fragment!r} occurs "
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
        problems.append(
            "formal workflow does not verify the TLA+ asset before execution"
        )

    if problems:
        fail(problems)
    print(
        "verify-ci-pins: OK "
        f"({action_count} immutable Action uses; {docker_count} immutable "
        f"container uses; TLA+ v{version} digest pinned)"
    )


if __name__ == "__main__":
    main()
