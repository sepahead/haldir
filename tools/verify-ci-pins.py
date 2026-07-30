#!/usr/bin/env python3
"""Enforce the immutable CI execution and event-isolation contract.

All third-party GitHub Actions must use a full commit SHA. The TLA+ executable
asset and Java runtime must match the closed records in ``tools/pins.toml``.
Pull requests execute against GitHub's merge commit and retain every substantive
check, while history-bound result and attestation work remains trusted-event
only. The recovery-test dispatcher is an always-run step: it executes the
reviewed suites on pull requests, explicitly succeeds on trusted events, and
rejects every unknown event. No third-party dependencies are required.
"""

from __future__ import annotations

from collections import Counter
import hashlib
import re
import sys
import tomllib
from pathlib import Path
from typing import Any, NamedTuple

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
PYTHON_INTERPRETER_TOKEN = re.compile(
    r"(?:^|[ \t])"
    r"(?:/[A-Za-z0-9_.-]+)*/?"
    r"python(?:3(?:\.[0-9]+)?)?"
    r"(?=[ \t]|$)"
)
ISOLATED_REPOSITORY_PYTHON = re.compile(
    r"^python3 -I -B "
    r"tools/(?:[A-Za-z0-9_-]+/)*[A-Za-z0-9_-]+\.py"
    r"(?:[ \t]|$)"
)
ISOLATED_SECURE_ZENOH_COMMAND = (
    "python3 -I -B -c "
    '\'import runpy,sys;sys.path.append("tools");'
    'runpy.run_path("tools/verify-secure-zenoh.py",run_name="__main__")\''
)
RECOVERY_DISPATCH_STEP_NAME = (
    "Verify epoch-18 recovery primitives for current event"
)
RECOVERY_DISPATCH_STEP_STATUS = "completed"
RECOVERY_DISPATCH_STEP_CONCLUSION = "success"
RECOVERY_DISPATCH_STEP_CARDINALITY = 1
PR_RECOVERY_STEP_NAME = RECOVERY_DISPATCH_STEP_NAME
PR_RECOVERY_COMMANDS = (
    "python3 -I -B -W error tools/release/test_verify_framework_recovery_fr_0017.py",
    "python3 -I -B -W error tools/test_pinned_cargo_deny.py",
    "python3 -I -B -W error tools/test_run_formal.py",
)
RECOVERY_DISPATCH_SHELL = "/bin/bash --noprofile --norc -euo pipefail {0}"
RECOVERY_DISPATCH_PUSH_MESSAGE = (
    "current-audit gate verified epoch-18 recovery primitives for push"
)
RECOVERY_DISPATCH_WORKFLOW_DISPATCH_MESSAGE = (
    "current-audit gate verified epoch-18 recovery primitives for workflow_dispatch"
)
RECOVERY_DISPATCH_DIAGNOSTIC = "unsupported recovery verification event"
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
    ("actions/attest@508db95dd578ae2727ebd6217d5ba78e4fbda05d # v4.2.1"): 2,
    ("actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1"): 2,
    ("actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1"): 3,
}
MAX_WORKFLOW_BYTES = 1024 * 1024
MAX_PINS_BYTES = 64 * 1024
PIN_SCHEMA_VERSION = 3
GH_CLI_VERSION = "2.96.0"
GH_CLI_ARCHIVE_SHA256 = (
    "83d5c2ccad5498f58bf6368acb1ab32588cf43ab3a4b1c301bf36328b1c8bd60"
)
GH_CLI_ARCHIVE_BYTES = 14_652_560
GH_CLI_BINARY_SHA256 = (
    "56b8bbbb27b066ecb33dbef9a256dc9d1314adaeff0908a752feba6c34053b40"
)
GH_CLI_BINARY_BYTES = 40_722_594
GH_CLI_ENVIRONMENT_VARIABLE = "HALDIR_FR0017_GH"
MAX_FORMAL_ASSET_BYTES = 4_000_000
MAX_JAVA_ARCHIVE_BYTES = 64 * 1024 * 1024
EXACT_VERSION = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)")
FORMAL_PIN_KEYS = frozenset(
    {
        "tla_tools_version",
        "tla_tools_bytes",
        "tla_tools_sha256",
        "java_distribution",
        "java_release_tag",
        "java_archive_package",
        "java_archive_architecture",
        "java_archive_name",
        "java_archive_root",
        "java_archive_url",
        "java_archive_bytes",
        "java_archive_sha256",
        "java_runtime_vendor",
        "java_runtime_version",
        "java_specification_version",
        "java_runtime_architecture",
    }
)
EXACT_JAVA_PINS: dict[str, str | int] = {
    "java_distribution": "temurin",
    "java_release_tag": "jdk-21.0.11+10",
    "java_archive_package": "jre",
    "java_archive_architecture": "x64",
    "java_archive_name": ("OpenJDK21U-jre_x64_linux_hotspot_21.0.11_10.tar.gz"),
    "java_archive_root": "jdk-21.0.11+10-jre",
    "java_archive_url": (
        "https://github.com/adoptium/temurin21-binaries/releases/download/"
        "jdk-21.0.11%2B10/"
        "OpenJDK21U-jre_x64_linux_hotspot_21.0.11_10.tar.gz"
    ),
    "java_archive_bytes": 52_099_793,
    "java_archive_sha256": (
        "e5038aae3ca9ff670bc696496b0728dbd23d280026bad30291cb919221ecfdcb"
    ),
    "java_runtime_vendor": "Eclipse Adoptium",
    "java_runtime_version": "21.0.11+10-LTS",
    "java_specification_version": "21",
    "java_runtime_architecture": "amd64",
}
EXPECTED_RUNNERS = {
    "ci.yml": Counter({"ubuntu-24.04": 6, "macos-15": 1}),
    "formal.yml": Counter({"ubuntu-24.04": 2}),
}
EXPECTED_WORKFLOW_JOBS = {
    "ci.yml": frozenset(
        {
            "build-test",
            "clean-build",
            "feature-matrix",
            "interop",
            "macos-compile",
            "supply-chain",
            "attest-ci-audit-result",
        }
    ),
    "formal.yml": frozenset(
        {
            "tlc-model-check",
            "attest-formal-audit-result",
        }
    ),
}
REQUIRED_CHECK_JOBS = frozenset(
    {
        "build-test",
        "clean-build",
        "feature-matrix",
        "interop",
        "macos-compile",
        "supply-chain",
        "tlc-model-check",
    }
)
WORKFLOW_TOP_LEVEL_KEYS = frozenset(
    {
        "name",
        "on",
        "concurrency",
        "permissions",
        "jobs",
    }
)
TRUSTED_ONLY_STEPS = {
    "supply-chain": (
        "Install pinned GitHub CLI for offline attestation verification",
        "Preload isolated task-runner image",
        "Verify current-head 0.9 audit cut",
        "Emit canonical epoch-18 audit result",
        "Upload canonical epoch-18 audit result",
    ),
    "tlc-model-check": (
        "Emit canonical epoch-18 formal result",
        "Upload canonical epoch-18 formal result",
    ),
}
OIDC_JOB_SHA256 = {
    "attest-ci-audit-result": (
        "1a3d958f7b240460faaf87bddfe75c4aea3419a0335581fa50161c32b538cb9d"
    ),
    "attest-formal-audit-result": (
        "ae73c51f964662907303152e83bd7285b25c44b18dac384941bdc090afbe48f3"
    ),
}
REQUIRED_JOB_SHA256 = {
    "build-test": ("6a40a09f91b98ffeb6084dcabde5b21cfe6f8c1e72c781428c5ccdc8f045aa7c"),
    "clean-build": ("3258a0329e7b3c22053c227992b6c4f4dac4fcf7894603e956fb709a15e39177"),
    "feature-matrix": (
        "6c5fc8de278f88eb24a1ef949cc5fbe4a7c32d5799de00d21063842b1acdc891"
    ),
    "interop": ("1bcbe55e830d34d48df6e20fc2e971877094ee4234f22f470a45ee2039cd58d6"),
    "macos-compile": (
        "0eb0a0e75662827088aeb2f57a559e6ca56308a8d67b7ecdd598244b27e35291"
    ),
    "supply-chain": (
        "b17255230b39cfafa988e3ea1da58446938d401c911207d9362288d677f2be46"
    ),
    "tlc-model-check": (
        "48faf25d2df2b10c063e88f5c2ba08430dd34ea4e5d0e94f062369a805caa002"
    ),
}
SUPPLY_CHAIN_JOB_SHA256 = REQUIRED_JOB_SHA256["supply-chain"]
FORMAL_JOB_SHA256 = REQUIRED_JOB_SHA256["tlc-model-check"]
RUNS_ON_LINE = re.compile(r"^    runs-on:\s*(\S+)\s*$", re.MULTILINE)
REF_KEY_LINE = re.compile(r"^\s+ref:\s*", re.MULTILINE)


class Use(NamedTuple):
    """One normalized workflow ``uses:`` declaration."""

    kind: str
    name: str
    pin: str
    line: int


class FormalPins(NamedTuple):
    """The exact formal runtime and executable-asset pins."""

    tla_tools_version: str
    tla_tools_bytes: int
    tla_tools_sha256: str
    java_distribution: str
    java_release_tag: str
    java_archive_package: str
    java_archive_architecture: str
    java_archive_name: str
    java_archive_root: str
    java_archive_url: str
    java_archive_bytes: int
    java_archive_sha256: str
    java_runtime_vendor: str
    java_runtime_version: str
    java_specification_version: str
    java_runtime_architecture: str


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


def verify_python_isolation(text: str, *, label: str) -> list[str]:
    """Require isolated mode for every repository Python entrypoint.

    Without ``-I``, Python prepends the entrypoint directory to ``sys.path``.
    A pull request can then shadow standard-library imports with a sibling such
    as ``tools/hashlib.py`` and exit before an authoritative verifier runs.
    ``-B`` also prevents untrusted checkout paths from receiving bytecode.
    """

    problems: list[str] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        command = line.strip()
        if command.startswith("run: "):
            command = command.removeprefix("run: ")
        interpreters = tuple(PYTHON_INTERPRETER_TOKEN.finditer(command))
        if not interpreters:
            continue
        if (
            len(interpreters) != 1
            or interpreters[0].start() != 0
            or (
                ISOLATED_REPOSITORY_PYTHON.match(command) is None
                and command != ISOLATED_SECURE_ZENOH_COMMAND
                and command not in PR_RECOVERY_COMMANDS
            )
        ):
            problems.append(
                f"{label}:{line_number} Python repository entrypoints must use "
                "an exact reviewed 'python3 -I -B ...' isolated command"
            )
    return problems


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


def verify_required_job_blocks(text: str, *, label: str) -> list[str]:
    """Bind every required check name to its complete reviewed job block."""

    problems: list[str] = []
    observed_jobs = _workflow_job_names(text) & REQUIRED_CHECK_JOBS
    for job in sorted(observed_jobs):
        try:
            block = _job_block(text, job, label=label)
        except ValueError as error:
            problems.append(str(error))
            continue
        observed = hashlib.sha256(block.encode("utf-8")).hexdigest()
        expected = REQUIRED_JOB_SHA256.get(job)
        if expected is None or observed != expected:
            problems.append(f"{label}:{job} exact reviewed job block mismatch")
    return problems


def _step_block(job_block: str, step: str, *, label: str) -> str:
    """Return one uniquely named step from an already isolated job block."""

    lines = job_block.splitlines()
    marker = f"      - name: {step}"
    starts = [index for index, line in enumerate(lines) if line == marker]
    if len(starts) != 1:
        raise ValueError(f"{label} must contain exactly one {step!r} step")
    start = starts[0]
    end = len(lines)
    for index in range(start + 1, len(lines)):
        if lines[index].startswith("      - "):
            end = index
            break
    return "\n".join(lines[start:end]) + "\n"


def _workflow_job_names(text: str) -> frozenset[str]:
    """Return top-level job keys from the uses-safe workflow subset."""

    _prefix, separator, jobs = text.partition("\njobs:\n")
    if separator == "":
        return frozenset()
    return frozenset(re.findall(r"^  ([A-Za-z0-9_-]+):$", jobs, flags=re.MULTILINE))


def parse_formal_pins(pins: dict[str, Any]) -> FormalPins:
    """Parse the formal pin table with exact keys, types, and platform policy."""

    if (
        type(pins.get("schema_version")) is not int
        or pins["schema_version"] != PIN_SCHEMA_VERSION
    ):
        raise ValueError(f"tools/pins.toml schema_version must be {PIN_SCHEMA_VERSION}")
    value = pins.get("formal")
    if type(value) is not dict:
        raise ValueError("formal must be a table")
    observed = set(value)
    missing = sorted(FORMAL_PIN_KEYS - observed)
    unknown = sorted(observed - FORMAL_PIN_KEYS)
    if missing or unknown:
        raise ValueError(
            f"formal schema differs: missing={missing!r}, unknown={unknown!r}"
        )
    version = value["tla_tools_version"]
    asset_bytes = value["tla_tools_bytes"]
    digest = value["tla_tools_sha256"]
    if not isinstance(version, str) or EXACT_VERSION.fullmatch(version) is None:
        raise ValueError("formal.tla_tools_version must be an exact release")
    if type(asset_bytes) is not int or not 0 < asset_bytes <= MAX_FORMAL_ASSET_BYTES:
        raise ValueError("formal.tla_tools_bytes violates the hard bound")
    if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise ValueError("formal.tla_tools_sha256 is not exact")
    java_archive_bytes = value["java_archive_bytes"]
    if (
        type(java_archive_bytes) is not int
        or not 0 < java_archive_bytes <= MAX_JAVA_ARCHIVE_BYTES
    ):
        raise ValueError("formal.java_archive_bytes violates the hard bound")
    java_archive_sha256 = value["java_archive_sha256"]
    if (
        type(java_archive_sha256) is not str
        or re.fullmatch(r"[0-9a-f]{64}", java_archive_sha256) is None
    ):
        raise ValueError("formal.java_archive_sha256 is not exact")
    for field, expected in EXACT_JAVA_PINS.items():
        observed_value = value[field]
        if type(observed_value) is not type(expected):
            raise ValueError(f"formal.{field} must have type {type(expected).__name__}")
        if observed_value != expected:
            raise ValueError(
                f"formal.{field} differs from the reviewed Temurin identity"
            )
    return FormalPins(
        tla_tools_version=version,
        tla_tools_bytes=asset_bytes,
        tla_tools_sha256=digest,
        **{field: value[field] for field in EXACT_JAVA_PINS},
    )


def verify_workflow_envelope(
    text: str,
    *,
    label: str,
    workflow: str,
) -> list[str]:
    """Enforce triggers, non-coalescing main runs, and merge-ref checkout."""

    problems: list[str] = []
    expected_trigger = (
        'on:\n  push:\n    branches: ["**"]\n  pull_request:\n  workflow_dispatch:\n'
    )
    observed_top_level = Counter(
        match.group("key")
        for line in text.splitlines()
        if (match := SIMPLE_MAPPING_LINE.fullmatch(line)) is not None
        and match.group("indent") == ""
    )
    if set(observed_top_level) != WORKFLOW_TOP_LEVEL_KEYS or any(
        count != 1 for count in observed_top_level.values()
    ):
        problems.append(
            f"{label} top-level key multiset differs: {dict(observed_top_level)!r}"
        )
    if (
        len(re.findall(r"^name:", text, flags=re.MULTILINE)) != 1
        or len(
            re.findall(
                rf"^name: {re.escape(workflow)}$",
                text,
                flags=re.MULTILINE,
            )
        )
        != 1
    ):
        problems.append(f"{label} must contain exactly one {workflow!r} identity")
    for top_level_key in ("on", "concurrency", "jobs"):
        if (
            len(
                re.findall(
                    rf"^{re.escape(top_level_key)}:$",
                    text,
                    flags=re.MULTILINE,
                )
            )
            != 1
        ):
            problems.append(
                f"{label} must contain exactly one top-level {top_level_key!r} key"
            )
    if text.count(f"{expected_trigger}\nconcurrency:\n") != 1:
        problems.append(
            f"{label} must run on every branch push, pull request, and dispatch"
        )
    expected_concurrency = (
        "concurrency:\n"
        f"  group: {workflow}-"
        "${{ github.ref == 'refs/heads/main' && github.run_id || github.ref }}\n"
        "  cancel-in-progress: "
        "${{ github.ref != 'refs/heads/main' }}\n"
    )
    if text.count(f"{expected_concurrency}\npermissions:\n") != 1:
        problems.append(
            f"{label} must isolate every main run and cancel only non-main runs"
        )
    if len(re.findall(r"^permissions:", text, flags=re.MULTILINE)) != 1:
        problems.append(f"{label} must contain exactly one global permissions policy")
    global_permissions = re.search(
        r"^permissions:\n(?P<body>(?:  [^\n]+\n)+)",
        text,
        flags=re.MULTILINE,
    )
    if (
        global_permissions is None
        or global_permissions.group("body") != "  contents: read\n"
    ):
        problems.append(f"{label} global permissions must be contents: read only")
    observed_write_permissions = Counter(
        re.findall(
            r"^(?:  |      )([a-z-]+): write$",
            text,
            flags=re.MULTILINE,
        )
    )
    expected_write_permissions = Counter(
        {
            "artifact-metadata": 1,
            "attestations": 1,
            "id-token": 1,
        }
    )
    if observed_write_permissions != expected_write_permissions:
        problems.append(
            f"{label} write permissions escape its isolated attester: "
            f"{dict(observed_write_permissions)!r}"
        )
    if re.search(r"^\s*permissions:\s*write-all$", text, flags=re.MULTILINE):
        problems.append(f"{label} forbids write-all workflow permissions")
    observed_jobs = _workflow_job_names(text)
    expected_jobs = EXPECTED_WORKFLOW_JOBS.get(f"{workflow}.yml", frozenset())
    if observed_jobs != expected_jobs:
        problems.append(
            f"{label} job set is {sorted(observed_jobs)!r}; "
            f"expected {sorted(expected_jobs)!r}"
        )
    exact_permission_jobs = {
        "supply-chain",
        "tlc-model-check",
        "attest-ci-audit-result",
        "attest-formal-audit-result",
    }
    for job in sorted(observed_jobs - exact_permission_jobs):
        try:
            block = _job_block(text, job, label=label)
        except ValueError as error:
            problems.append(str(error))
            continue
        if re.search(r"^    permissions\s*:", block, flags=re.MULTILINE):
            problems.append(
                f"{label}:{job} must inherit the read-only global permissions; "
                "job-level permissions are forbidden"
            )
    if REF_KEY_LINE.search(text) is not None:
        problems.append(
            f"{label} must let checkout select the event revision; pull requests "
            "must test GitHub's merge commit"
        )
    forbidden_head_bypasses = (
        "github.event.pull_request.head.sha",
        "github.event.pull_request.head.ref",
        "github.head_ref",
    )
    for fragment in forbidden_head_bypasses:
        if fragment in text:
            problems.append(f"{label} forbids pull-request head bypass {fragment!r}")
    return problems


def verify_required_checks_run_on_pr(
    text: str,
    *,
    label: str,
) -> list[str]:
    """Reject event conditions on required checks outside reviewed core jobs."""

    problems: list[str] = []
    protected_core_jobs = {"supply-chain", "tlc-model-check"}
    for job in sorted(_workflow_job_names(text) & REQUIRED_CHECK_JOBS):
        if job in protected_core_jobs:
            continue
        try:
            block = _job_block(text, job, label=label)
        except ValueError as error:
            problems.append(str(error))
            continue
        conditional_fields = re.findall(
            r"^(?:    |        )if:\s*",
            block,
            flags=re.MULTILINE,
        )
        if conditional_fields:
            problems.append(
                f"{label}:{job} must run every required step on pull requests"
            )
    return problems


def verify_trusted_event_steps(
    text: str,
    *,
    label: str,
    job: str,
) -> list[str]:
    """Gate only history/result plumbing away from pull-request merge commits."""

    try:
        block = _job_block(text, job, label=label)
    except ValueError as error:
        return [str(error)]
    problems: list[str] = []
    expected_condition = "        if: github.event_name != 'pull_request'\n"
    expected_steps = TRUSTED_ONLY_STEPS[job]
    for step in expected_steps:
        try:
            step_block = _step_block(
                block,
                step,
                label=f"{label}:{job}",
            )
        except ValueError as error:
            problems.append(str(error))
            continue
        if step_block.count(expected_condition) != 1:
            problems.append(
                f"{label}:{job}:{step} must be skipped only for pull requests"
            )
        if not step_block.startswith(f"      - name: {step}\n{expected_condition}"):
            problems.append(
                f"{label}:{job}:{step} event condition must precede execution fields"
            )
    observed_conditions = block.count("if: github.event_name != 'pull_request'")
    if observed_conditions != len(expected_steps):
        problems.append(
            f"{label}:{job} contains {observed_conditions} pull-request exclusions; "
            f"expected {len(expected_steps)}"
        )
    return problems


def verify_pr_recovery_step(text: str, *, label: str) -> list[str]:
    """Bind the always-run, event-closed recovery-test dispatcher."""

    try:
        block = _job_block(text, "supply-chain", label=label)
        step = _step_block(
            block,
            PR_RECOVERY_STEP_NAME,
            label=f"{label}:supply-chain",
        )
    except ValueError as error:
        return [str(error)]
    expected = (
        f"      - name: {PR_RECOVERY_STEP_NAME}\n"
        f"        shell: {RECOVERY_DISPATCH_SHELL}\n"
        "        run: |\n"
        '          case "$GITHUB_EVENT_NAME" in\n'
        "            pull_request)\n"
        + "".join(f"              {command}\n" for command in PR_RECOVERY_COMMANDS)
        + "              ;;\n"
        "            push)\n"
        "              /usr/bin/printf '%s\\n' \\\n"
        f"                '{RECOVERY_DISPATCH_PUSH_MESSAGE}'\n"
        "              ;;\n"
        "            workflow_dispatch)\n"
        "              /usr/bin/printf '%s\\n' \\\n"
        f"                '{RECOVERY_DISPATCH_WORKFLOW_DISPATCH_MESSAGE}'\n"
        "              ;;\n"
        "            *)\n"
        f"              /usr/bin/printf '%s\\n' '{RECOVERY_DISPATCH_DIAGNOSTIC}' >&2\n"
        "              exit 1\n"
        "              ;;\n"
        "          esac\n"
    )
    problems: list[str] = []
    if step != expected:
        problems.append(
            f"{label}:supply-chain:{PR_RECOVERY_STEP_NAME} must contain only "
            "the exact always-run fail-closed event dispatcher"
        )
    event_name_env_key = re.compile(
        r"^\s+(?:GITHUB_EVENT_NAME|\"GITHUB_EVENT_NAME\"|'GITHUB_EVENT_NAME')\s*:",
        flags=re.MULTILINE,
    )
    if event_name_env_key.search(text) is not None:
        problems.append(
            f"{label}:GITHUB_EVENT_NAME must not be shadowed by workflow, job, "
            "or step env"
        )
    observed_step_conditions = step.count("        if:")
    if observed_step_conditions != 0:
        problems.append(
            f"{label}:supply-chain:{PR_RECOVERY_STEP_NAME} must always run; "
            f"observed {observed_step_conditions} step-level conditions"
        )
    return problems


def verify_formal_job(
    text: str,
    *,
    label: str,
    pins: FormalPins,
) -> list[str]:
    """Bind the formal job's exact runtime, download, and pipe semantics."""

    try:
        block = _job_block(text, "tlc-model-check", label=label)
    except ValueError as error:
        return [str(error)]
    problems: list[str] = []
    observed = hashlib.sha256(block.encode("utf-8")).hexdigest()
    if observed != FORMAL_JOB_SHA256:
        problems.append(f"{label}:tlc-model-check exact reviewed job block mismatch")
    expected_fragments = {
        f'TLA_TOOLS_VERSION: "{pins.tla_tools_version}"': 1,
        f"TLA_TOOLS_BYTES: {pins.tla_tools_bytes}": 1,
        f'TLA_TOOLS_SHA256: "{pins.tla_tools_sha256}"': 1,
        f"JAVA_DISTRIBUTION: {pins.java_distribution}": 1,
        f"JAVA_RELEASE_TAG: {pins.java_release_tag}": 1,
        f"JAVA_ARCHIVE_PACKAGE: {pins.java_archive_package}": 1,
        f"JAVA_ARCHIVE_ARCHITECTURE: {pins.java_archive_architecture}": 1,
        f"JAVA_ARCHIVE_NAME: {pins.java_archive_name}": 1,
        f"JAVA_ARCHIVE_ROOT: {pins.java_archive_root}": 1,
        f"JAVA_ARCHIVE_URL: {pins.java_archive_url}": 1,
        f"JAVA_ARCHIVE_BYTES: {pins.java_archive_bytes}": 1,
        f'JAVA_ARCHIVE_SHA256: "{pins.java_archive_sha256}"': 1,
        f"JAVA_RUNTIME_VENDOR: {pins.java_runtime_vendor}": 1,
        f"JAVA_RUNTIME_VERSION: {pins.java_runtime_version}": 1,
        (f'JAVA_SPECIFICATION_VERSION: "{pins.java_specification_version}"'): 1,
        f"JAVA_RUNTIME_ARCHITECTURE: {pins.java_runtime_architecture}": 1,
        "/usr/bin/curl": 2,
        "--disable": 2,
        "--proto '=https'": 2,
        "--proto-redir '=https'": 2,
        "--tlsv1.2": 2,
        "--retry-all-errors": 2,
        "--connect-timeout 30": 2,
        "--max-time 300": 2,
        "--max-redirs 5": 2,
        '--max-filesize "$JAVA_ARCHIVE_BYTES"': 1,
        '--max-filesize "$TLA_TOOLS_BYTES"': 1,
        '/usr/bin/test -f "$JAVA_ARCHIVE"': 1,
        '/usr/bin/test ! -L "$JAVA_ARCHIVE"': 1,
        '/usr/bin/stat --format=%s "$JAVA_ARCHIVE"': 1,
        '/usr/bin/stat --format=%s "$TLA_TOOLS_PATH"': 1,
        "| /usr/bin/sha256sum --check --strict": 3,
        "--quoting-style=escape": 2,
        "declare -A SEEN_MEMBERS=()": 1,
        '[[ "$COMPONENT" =~ ^[A-Za-z0-9._+@-]+$ ]]': 1,
        '[[ "$COMPONENT" != "." ]]': 1,
        '[[ "$COMPONENT" != ".." ]]': 1,
        "NOTICE|bin|conf|legal|lib|release) ;;": 1,
        '[[ -n "${SEEN_MEMBERS[$JAVA_ARCHIVE_ROOT]+present}" ]]': 1,
        "JAVA_REGULAR_FILE_COUNT=112": 1,
        "JAVA_DIRECTORY_COUNT=63": 1,
        "-) ((REGULAR_COUNT += 1)) ;;": 1,
        "d) ((DIRECTORY_COUNT += 1)) ;;": 1,
        "JAVA_LEGAL_LINK_COUNT=145": 1,
        "JAVA_LEGAL_LINKS_BYTES=13095": 1,
        (
            'JAVA_LEGAL_LINKS_SHA256="'
            "e623b66f52db07699c4723e448b1a34531097e6c38ee63630da3dcd81729d576"
            '"'
        ): 1,
        '[[ "$LINK_PATH" == "$JAVA_ARCHIVE_ROOT/legal/"* ]]': 1,
        '[[ "$LINK_MODULE" != "." ]]': 1,
        '[[ "$LINK_MODULE" != ".." ]]': 1,
        '[[ -z "$LINK_EXTRA" ]]': 1,
        '[[ "$LINK_TARGET" == "../java.base/$LINK_NAME" ]]': 1,
        '[[ "$LINK_MODULE" == jdk.localedata ]]': 1,
        '[[ "$LINK_TARGET" == ../java.base/cldr.md ]]': 1,
        '[[ "$LINK_COUNT" -eq "$JAVA_LEGAL_LINK_COUNT" ]]': 1,
        '[[ "$REGULAR_COUNT" -eq "$JAVA_REGULAR_FILE_COUNT" ]]': 1,
        '[[ "$DIRECTORY_COUNT" -eq "$JAVA_DIRECTORY_COUNT" ]]': 1,
        'LC_ALL=C /usr/bin/sort "$JAVA_LEGAL_LINKS"': 1,
        '[[ "$TYPE_COUNT" -eq "$MEMBER_COUNT" ]]': 1,
        "--strip-components=1": 1,
        '--exclude="${JAVA_ARCHIVE_ROOT}/legal"': 1,
        '--exclude="${JAVA_ARCHIVE_ROOT}/legal/*"': 1,
        "--no-same-owner": 1,
        "--no-same-permissions": 1,
        "--delay-directory-restore": 1,
        "/usr/bin/env -u GZIP -u TAR_OPTIONS LC_ALL=C /usr/bin/tar": 3,
        '/usr/bin/test ! -e "$JAVA_HOME/legal"': 1,
        '/usr/bin/test ! -L "$JAVA_HOME/legal"': 1,
        '/usr/bin/find "$JAVA_HOME" -xdev -type l -print -quit': 1,
        "! -type f ! -type d -print -quit": 1,
        "-perm /0111": 2,
        "-exec /usr/bin/chmod 0700 {} +": 2,
        "-exec /usr/bin/chmod 0600 {} +": 1,
        "      - name: Verify exact Temurin runtime identity\n": 1,
        "-u JAVA_TOOL_OPTIONS": 2,
        "-u _JAVA_OPTIONS": 2,
        "-u JDK_JAVA_OPTIONS": 2,
        "LC_ALL=C": 6,
        "count != 1 || matches != 1": 1,
        'assert_property java.vendor "$JAVA_RUNTIME_VENDOR"': 1,
        'assert_property java.runtime.version "$JAVA_RUNTIME_VERSION"': 1,
        ('assert_property java.specification.version "$JAVA_SPECIFICATION_VERSION"'): 1,
        'assert_property os.arch "$JAVA_RUNTIME_ARCHITECTURE"': 1,
        '"${JAVA_HOME}/bin/java" \\\n            -XX:+UseParallelGC': 1,
        "| /usr/bin/tee tlc.log": 1,
        "      - name: Upload TLC log\n        if: always()\n": 1,
        "framework_recovery_fr_0017_result.py": 1,
        "epoch-18-formal-result-attempt-": 3,
    }
    for fragment, expected_count in expected_fragments.items():
        observed_count = block.count(fragment)
        if observed_count != expected_count:
            problems.append(
                f"{label}:tlc-model-check requires {fragment!r} "
                f"{expected_count} time(s), observed {observed_count}"
            )
    try:
        model_step = _step_block(
            block,
            "Model-check HaldirAuthority",
            label=f"{label}:tlc-model-check",
        )
    except ValueError as error:
        problems.append(str(error))
    else:
        hardened_shell = (
            "        shell: /bin/bash --noprofile --norc -euo pipefail {0}\n"
        )
        if model_step.count(hardened_shell) != 1:
            problems.append(
                f"{label}:tlc-model-check must make TLC pipeline failures fatal"
            )
    if "releases/latest" in block:
        problems.append(f"{label}:tlc-model-check uses a moving releases/latest URL")
    if "actions/setup-java@" in block:
        problems.append(f"{label}:tlc-model-check must not use actions/setup-java")
    return problems


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
    problems: list[str] = []
    observed = hashlib.sha256(block.encode("utf-8")).hexdigest()
    if observed != SUPPLY_CHAIN_JOB_SHA256:
        problems.append(f"{label}:supply-chain exact reviewed job block mismatch")
    expected_fragments = {
        "framework_recovery_fr_0017_result.py": 1,
        "epoch-18-ci-result-attempt-": 3,
    }
    for fragment, expected_count in expected_fragments.items():
        observed_count = block.count(fragment)
        if observed_count != expected_count:
            problems.append(
                f"{label}:supply-chain requires {fragment!r} "
                f"{expected_count} time(s), observed {observed_count}"
            )
    return problems


def verify_gh_cli_material(text: str, *, label: str) -> list[str]:
    """Bind the pinned GitHub CLI and its epoch-18 consumer interface."""

    problems: list[str] = []
    required_fragments = {
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
        (
            f'printf \'{GH_CLI_ENVIRONMENT_VARIABLE}=%s\\n\' "$GH_BIN" >> "$GITHUB_ENV"'
        ): 1,
    }
    for fragment, expected_count in required_fragments.items():
        observed_count = text.count(fragment)
        if observed_count != expected_count:
            problems.append(
                f"{label} requires exact pinned gh material {fragment!r} "
                f"{expected_count} time(s), observed {observed_count}"
            )
    observed_interfaces = Counter(re.findall(r"\bHALDIR_FR[0-9]{4}_GH\b", text))
    expected_interfaces = Counter({GH_CLI_ENVIRONMENT_VARIABLE: 1})
    if observed_interfaces != expected_interfaces:
        problems.append(
            f"{label} GitHub CLI environment interface differs: "
            f"observed {dict(observed_interfaces)!r}; "
            f"expected {dict(expected_interfaces)!r}"
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
        raise ValueError(f"{path.relative_to(ROOT)} is not valid UTF-8") from error


def _read_pins() -> dict[str, Any]:
    path = ROOT / "tools" / "pins.toml"
    if path.is_symlink() or not path.is_file():
        raise ValueError("tools/pins.toml is not a regular file")
    payload = path.read_bytes()
    if not 1 <= len(payload) <= MAX_PINS_BYTES or b"\0" in payload:
        raise ValueError("tools/pins.toml violates pin-file size bounds")
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("tools/pins.toml is not valid UTF-8") from error
    try:
        pins = tomllib.loads(text)
    except tomllib.TOMLDecodeError as error:
        raise ValueError(f"tools/pins.toml is invalid TOML: {error}") from error
    if type(pins) is not dict:
        raise ValueError("tools/pins.toml must contain a table")
    return pins


def fail(messages: list[str]) -> None:
    for message in messages:
        print(f"verify-ci-pins: FAIL: {message}", file=sys.stderr)
    sys.exit(1)


def main() -> None:
    problems: list[str] = []
    try:
        pins = _read_pins()
    except (OSError, ValueError) as error:
        problems.append(str(error))
        pins = {}
    try:
        formal_pins = parse_formal_pins(pins)
    except ValueError as error:
        problems.append(str(error))
        formal_pins = None

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
        problems.extend(
            verify_workflow_envelope(
                text,
                label=str(path.relative_to(ROOT)),
                workflow=path.stem,
            )
        )
        problems.extend(
            verify_required_checks_run_on_pr(
                text,
                label=str(path.relative_to(ROOT)),
            )
        )
        problems.extend(
            verify_python_isolation(
                text,
                label=str(path.relative_to(ROOT)),
            )
        )
        problems.extend(
            verify_required_job_blocks(
                text,
                label=str(path.relative_to(ROOT)),
            )
        )
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
            verify_trusted_event_steps(
                workflow_texts["ci.yml"],
                label=".github/workflows/ci.yml",
                job="supply-chain",
            )
        )
        problems.extend(
            verify_pr_recovery_step(
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
        if formal_pins is not None:
            problems.extend(
                verify_formal_job(
                    workflow_texts["formal.yml"],
                    label=".github/workflows/formal.yml",
                    pins=formal_pins,
                )
            )
        problems.extend(
            verify_trusted_event_steps(
                workflow_texts["formal.yml"],
                label=".github/workflows/formal.yml",
                job="tlc-model-check",
            )
        )
        problems.extend(
            verify_oidc_job(
                workflow_texts["formal.yml"],
                label=".github/workflows/formal.yml",
                job="attest-formal-audit-result",
                expected_needs=("tlc-model-check",),
            )
        )
    observed_required_checks = frozenset().union(
        *(
            _workflow_job_names(text) & REQUIRED_CHECK_JOBS
            for text in workflow_texts.values()
        )
    )
    if observed_required_checks != REQUIRED_CHECK_JOBS:
        problems.append(
            "required check job set differs: "
            f"observed {sorted(observed_required_checks)!r}; "
            f"expected {sorted(REQUIRED_CHECK_JOBS)!r}"
        )
    ci_text = workflow_texts.get("ci.yml", "")
    problems.extend(
        verify_gh_cli_material(
            ci_text,
            label=".github/workflows/ci.yml",
        )
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
    if "actions/setup-java@" in all_workflows:
        problems.append(
            "actions/setup-java must be absent; Java is an exact archive pin"
        )
    for fragment, expected_count in REQUIRED_ACTION_COMMENTS.items():
        observed_count = all_workflows.count(fragment)
        if observed_count != expected_count:
            problems.append(
                f"required action annotation {fragment!r} occurs "
                f"{observed_count} times; expected {expected_count}"
            )

    if problems:
        fail(problems)
    assert formal_pins is not None
    print(
        "verify-ci-pins: OK "
        f"({action_count} immutable Action uses; {docker_count} immutable "
        "container uses; "
        f"TLA+ v{formal_pins.tla_tools_version}/{formal_pins.tla_tools_bytes} "
        f"bytes and Java {formal_pins.java_runtime_version} pinned)"
    )


if __name__ == "__main__":
    main()
