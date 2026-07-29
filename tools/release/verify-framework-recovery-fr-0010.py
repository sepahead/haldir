#!/usr/bin/env python3
"""Verify the isolated FR-0010 epoch-11 trust-root bridge.

The 47k-line epoch-10 verifier is frozen at the signed c5 boundary and is never
executed against later successors.  This bridge validates only the signed
FR-0010 R/Q/A transition, immutable epoch-11 trust-root files, and ordinary
signed linear milestones after activation.  Branch protection is an external
merge invariant; main-only OIDC evidence is captured separately after merge.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import os
import re
import selectors
import stat
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence


PARENT = "c5e986d7cb2a36c5a98b6bc494d9615e1f4d7fe7"
PARENT_TREE = "7161cdff92b5574f969a1af6de2ef68e715efac4"
RECOVERY_ID = "FR-0010"
REPAIR_SUBJECT = "release: establish epoch-11 audit trust root"
QUALIFICATION_SUBJECT = "release: qualify epoch-11 audit trust root"
ACTIVATION_SUBJECT = "release: activate epoch-11 audit trust root"
PLAN_NAMESPACE = "haldir-framework-recovery-fr-0010-plan-v1"
QUALIFICATION_NAMESPACE = "haldir-framework-recovery-fr-0010-qualification-v1"
ACTIVATION_NAMESPACE = "haldir-framework-recovery-fr-0010-activation-v1"
SIGNER_PRINCIPAL = "sepmhn@gmail.com"
SIGNER_FINGERPRINT = (
    "SHA256:3gaatfl4IVnuBX4D60Jxw9oVIrvEE1ZphK8IuEyrfPU"
)
AUTHOR_NAME = "Sepehr Mahmoudian"
AUTHOR_EMAIL = "sepmhn@gmail.com"
ALLOWED_SIGNERS_PATH = "release/0.9.0/allowed-signers"
PLAN_PATH = (
    "release/0.9.0/current-head/closures/framework-recovery/FR-0010-plan.json"
)
QUALIFICATION_PATH = (
    "release/0.9.0/current-head/closures/framework-recovery/"
    "FR-0010-qualification.json"
)
ACTIVATION_PATH = (
    "release/0.9.0/current-head/closures/framework-recovery/"
    "FR-0010-activation.json"
)
MODULE_PATH = "tools/release/framework_recovery_fr_0010.py"
CAPTURE_PATH = "tools/release/framework_recovery_fr_0010_capture.py"
RESULT_PATH = "tools/release/framework_recovery_fr_0010_result.py"
BRIDGE_PATH = "tools/release/verify-framework-recovery-fr-0010.py"
TEST_PATH = "tools/release/test_verify_framework_recovery_fr_0010.py"
TRUSTED_ROOT_PATH = "tools/release/sigstore-public-good-trusted-root.jsonl"
GATE_PATH = "tools/release/current-audit-gate.sh"
CORE_PATHS = (
    ".github/workflows/ci.yml",
    ".github/workflows/formal.yml",
    "tools/verify-ci-pins.py",
    GATE_PATH,
    MODULE_PATH,
    CAPTURE_PATH,
    RESULT_PATH,
    BRIDGE_PATH,
    TEST_PATH,
    TRUSTED_ROOT_PATH,
)
REPAIR_STATUSES = {
    ".github/workflows/ci.yml": "M",
    ".github/workflows/formal.yml": "M",
    PLAN_PATH: "A",
    "tools/verify-ci-pins.py": "M",
    GATE_PATH: "M",
    MODULE_PATH: "A",
    CAPTURE_PATH: "A",
    RESULT_PATH: "A",
    BRIDGE_PATH: "A",
    TEST_PATH: "A",
    TRUSTED_ROOT_PATH: "A",
}
REPAIR_MODES = {
    ".github/workflows/ci.yml": "100644",
    ".github/workflows/formal.yml": "100644",
    PLAN_PATH: "100644",
    "tools/verify-ci-pins.py": "100755",
    GATE_PATH: "100755",
    MODULE_PATH: "100644",
    CAPTURE_PATH: "100755",
    RESULT_PATH: "100755",
    BRIDGE_PATH: "100755",
    TEST_PATH: "100644",
    TRUSTED_ROOT_PATH: "100644",
}
EVIDENCE_ROOT = "release/0.9.0/current-head/evidence"
REVIEW_ROOT = "release/0.9.0/current-head/reviews"
C5_CI_PATHS = (
    f"{EVIDENCE_ROOT}/framework-recovery-fr-0010-c5-ci.json",
    f"{EVIDENCE_ROOT}/framework-recovery-fr-0010-c5-ci-logs.zip",
)
C5_FORMAL_PATHS = (
    f"{EVIDENCE_ROOT}/framework-recovery-fr-0010-c5-formal.json",
    f"{EVIDENCE_ROOT}/framework-recovery-fr-0010-c5-formal-logs.zip",
)
REPAIR_CI_PATHS = (
    f"{EVIDENCE_ROOT}/framework-recovery-fr-0010-r-ci-capture.json",
    f"{EVIDENCE_ROOT}/framework-recovery-fr-0010-r-ci-result.json",
    f"{EVIDENCE_ROOT}/framework-recovery-fr-0010-r-ci-attestation.json",
)
REPAIR_FORMAL_PATHS = (
    f"{EVIDENCE_ROOT}/framework-recovery-fr-0010-r-formal-capture.json",
    f"{EVIDENCE_ROOT}/framework-recovery-fr-0010-r-formal-result.json",
    f"{EVIDENCE_ROOT}/framework-recovery-fr-0010-r-formal-attestation.json",
)
LOCAL_PATH = f"{EVIDENCE_ROOT}/framework-recovery-fr-0010-r-local.json"
DESIGN_REVIEW_PATHS = (
    f"{REVIEW_ROOT}/framework-recovery-fr-0010-design-capture.json",
    f"{REVIEW_ROOT}/framework-recovery-fr-0010-design-response.json",
)
IMPLEMENTATION_REVIEW_PATHS = (
    f"{REVIEW_ROOT}/framework-recovery-fr-0010-implementation-capture.json",
    f"{REVIEW_ROOT}/framework-recovery-fr-0010-implementation-response.json",
)
QUALIFICATION_EVIDENCE_PATHS = (
    *C5_CI_PATHS,
    *C5_FORMAL_PATHS,
    *REPAIR_CI_PATHS,
    *REPAIR_FORMAL_PATHS,
    LOCAL_PATH,
    *DESIGN_REVIEW_PATHS,
    *IMPLEMENTATION_REVIEW_PATHS,
)
QUALIFICATION_STATUSES = {
    QUALIFICATION_PATH: "A",
    **{path: "A" for path in QUALIFICATION_EVIDENCE_PATHS},
}
QUALIFICATION_CI_PATHS = (
    f"{EVIDENCE_ROOT}/framework-recovery-fr-0010-q-ci-capture.json",
    f"{EVIDENCE_ROOT}/framework-recovery-fr-0010-q-ci-result.json",
    f"{EVIDENCE_ROOT}/framework-recovery-fr-0010-q-ci-attestation.json",
)
QUALIFICATION_FORMAL_PATHS = (
    f"{EVIDENCE_ROOT}/framework-recovery-fr-0010-q-formal-capture.json",
    f"{EVIDENCE_ROOT}/framework-recovery-fr-0010-q-formal-result.json",
    f"{EVIDENCE_ROOT}/framework-recovery-fr-0010-q-formal-attestation.json",
)
BRANCH_PROTECTION_PATH = (
    f"{EVIDENCE_ROOT}/framework-recovery-fr-0010-branch-protection.json"
)
ACTIVATION_EVIDENCE_PATHS = (
    *QUALIFICATION_CI_PATHS,
    *QUALIFICATION_FORMAL_PATHS,
    BRANCH_PROTECTION_PATH,
)
ACTIVATION_STATUSES = {
    ACTIVATION_PATH: "A",
    **{path: "A" for path in ACTIVATION_EVIDENCE_PATHS},
}
LEGACY_RECORDS = {
    "release/0.9.0/allowed-signers": {
        "git_mode": "100644",
        "git_object_id": "7e563049b65dc6761e76b7d0c96c1cc10bd5c0dc",
        "sha256": "88eddddf1b3a6d0176acf2ec88b1d3c120453e2658651c49b82d41057caa78ed",
        "bytes": 98,
    },
    "tools/release/verify-current-audit.py": {
        "git_mode": "100644",
        "git_object_id": "7d94097c9e2c96a1569efb8e521f05a8ed58516b",
        "sha256": "6bf4d745d3f4c90bdaa58ab4335cba9becbca26d7c3fa40ccd2fa0bda6fb6e41",
        "bytes": 1_842_863,
    },
    "tools/release/current-audit-gate.sh": {
        "git_mode": "100755",
        "git_object_id": "b5e331e611780b809a4c2e628bf8583d54195ef0",
        "sha256": "54462abbbfe0908fd16c521c86e4f3a775c658fc594199480b1d6cb0247c9399",
        "bytes": 14_314,
    },
    "release/0.9.0/current-head/requirements.json": {
        "git_mode": "100644",
        "git_object_id": "da3bf2edd60efb4071d3dbb63f39b9bdfcd1176e",
        "sha256": "0963891fbfb1a174972f22b2d6e253df8531506b92bb2fd3f46708f8fff782e7",
        "bytes": 189_708,
    },
}
PROTECTED_AFTER_ACTIVATION = frozenset(
    {
        *CORE_PATHS,
        PLAN_PATH,
        QUALIFICATION_PATH,
        ACTIVATION_PATH,
        *QUALIFICATION_EVIDENCE_PATHS,
        *ACTIVATION_EVIDENCE_PATHS,
        ALLOWED_SIGNERS_PATH,
        "tools/release/verify-current-audit.py",
        "tools/release/test_verify_current_audit_fr_0009.py",
    }
)
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
MAX_GIT_BYTES = 16 * 1024 * 1024
MAX_JSON_BYTES = 2 * 1024 * 1024
MAX_TRUSTED_ROOT_BYTES = 8 * 1024 * 1024
TRUSTED_ROOT_BYTES = 5_748
TRUSTED_ROOT_SHA256 = (
    "3c2cc7f357dc064ec527fdcd78da6e9245c21a381e1abaa0f2b62b186bcac1a1"
)
GH_CLI_VERSION = "2.95.0"
GH_CLI_LINUX_AMD64_ARCHIVE = (
    "https://github.com/cli/cli/releases/download/v2.95.0/"
    "gh_2.95.0_linux_amd64.tar.gz"
)
GH_CLI_LINUX_AMD64_ARCHIVE_SHA256 = (
    "25d1e4729e8808c9ed3d613e96ebd3f3e44446f2d368c89d878a71a36ddb3d8c"
)
GH_CLI_LINUX_AMD64_ARCHIVE_BYTES = 14_642_738
GH_CLI_LINUX_AMD64_BINARY_SHA256 = (
    "62c11fbaa08835168c3d1acf8a645ac6268a13a5682c73581388c9df0c622617"
)
GH_CLI_LINUX_AMD64_BINARY_BYTES = 40_702_114
MAX_SUCCESSOR_PATHS = 512
GITHUB_ACTIONS_APP_ID = 15_368
REQUIRED_PRE_ACCEPT_CHECKS = frozenset(
    {
        "build-test",
        "feature-matrix",
        "macos-compile",
        "clean-build",
        "supply-chain",
        "interop",
        "tlc-model-check",
    }
)
MAIN_RULESET_NAME = "haldir-main-writer-allowlist"
MAIN_RULESET_OWNER_ID = 10_104_569


class BridgeError(RuntimeError):
    """One fail-closed epoch-11 bridge error."""


def _fail(code: str) -> None:
    raise BridgeError(code)


def canonical_json_bytes(value: Any, *, pretty: bool = True) -> bytes:
    return (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            indent=2 if pretty else None,
            separators=None if pretty else (",", ":"),
            sort_keys=True,
        )
        + ("\n" if pretty else "")
    ).encode("utf-8")


def _git_environment() -> dict[str, str]:
    return {
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }


def _git(
    repo: Path,
    *arguments: str,
    input_bytes: bytes | None = None,
    limit: int = MAX_GIT_BYTES,
) -> bytes:
    completed = subprocess.run(
        ("/usr/bin/git", "-c", "core.hooksPath=/dev/null", *arguments),
        cwd=repo,
        env=_git_environment(),
        input=input_bytes,
        stdin=None if input_bytes is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=30,
    )
    if (
        completed.returncode != 0
        or len(completed.stdout) > limit
        or len(completed.stderr) > 256 * 1024
    ):
        _fail("FR0010_GIT:" + (arguments[0] if arguments else "missing"))
    return completed.stdout


def _metadata(repo: Path, commit: str) -> dict[str, str]:
    raw = _git(
        repo,
        "show",
        "-s",
        "--format=%H%x00%P%x00%T%x00%an%x00%ae%x00%cn%x00%ce%x00%s%x00%aI%x00%cI",
        commit,
        limit=64 * 1024,
    )
    fields = raw.rstrip(b"\n").split(b"\0")
    if len(fields) != 10:
        _fail("FR0010_COMMIT_METADATA")
    try:
        values = [field.decode("utf-8") for field in fields]
    except UnicodeDecodeError:
        _fail("FR0010_COMMIT_METADATA")
    keys = (
        "commit",
        "parents",
        "tree",
        "author_name",
        "author_email",
        "committer_name",
        "committer_email",
        "subject",
        "author_date",
        "committer_date",
    )
    result = dict(zip(keys, values, strict=True))
    if (
        HEX40.fullmatch(result["commit"]) is None
        or HEX40.fullmatch(result["tree"]) is None
        or len(result["parents"].split()) > 1
    ):
        _fail("FR0010_COMMIT_METADATA")
    return result


def _verify_commit_identity(
    repo: Path,
    commit: str,
    *,
    parent: str,
    subject: str | None,
) -> dict[str, str]:
    metadata = _metadata(repo, commit)
    if (
        metadata["parents"] != parent
        or (subject is not None and metadata["subject"] != subject)
        or metadata["author_name"] != AUTHOR_NAME
        or metadata["author_email"] != AUTHOR_EMAIL
        or metadata["committer_name"] != AUTHOR_NAME
        or metadata["committer_email"] != AUTHOR_EMAIL
        or metadata["author_date"] != metadata["committer_date"]
    ):
        _fail("FR0010_COMMIT_IDENTITY")
    completed = subprocess.run(
        _verify_commit_argv(repo, commit),
        cwd=repo,
        env=_git_environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=30,
    )
    expected = (
        f'Good "git" signature for {SIGNER_PRINCIPAL} with ED25519 key '
        f"{SIGNER_FINGERPRINT}\n"
    ).encode("ascii")
    if (
        completed.returncode != 0
        or completed.stdout != b""
        or completed.stderr != expected
    ):
        _fail("FR0010_COMMIT_SIGNATURE")
    return metadata


def _verify_commit_argv(repo: Path, commit: str) -> tuple[str, ...]:
    return (
        "/usr/bin/git",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        f"gpg.ssh.allowedSignersFile={repo / ALLOWED_SIGNERS_PATH}",
        "-c",
        f"gpg.ssh.revocationFile={os.devnull}",
        "-c",
        "gpg.ssh.program=/usr/bin/ssh-keygen",
        "-c",
        "gpg.format=ssh",
        "verify-commit",
        commit,
    )


def _changed_statuses(repo: Path, parent: str, commit: str) -> dict[str, str]:
    raw = _git(
        repo,
        "diff-tree",
        "--no-commit-id",
        "--no-renames",
        "--root",
        "-r",
        "--name-status",
        "-z",
        parent,
        commit,
    )
    parts = raw.split(b"\0")
    if parts[-1:] == [b""]:
        parts.pop()
    if len(parts) % 2:
        _fail("FR0010_DIFF_GRAMMAR")
    result: dict[str, str] = {}
    for index in range(0, len(parts), 2):
        try:
            status = parts[index].decode("ascii")
            path = parts[index + 1].decode("utf-8")
        except UnicodeDecodeError:
            _fail("FR0010_DIFF_GRAMMAR")
        if (
            status not in {"A", "M", "D"}
            or path in result
            or path.startswith("/")
            or "//" in path
            or any(part in {"", ".", ".."} for part in path.split("/"))
        ):
            _fail("FR0010_DIFF_GRAMMAR")
        result[path] = status
    return dict(sorted(result.items()))


def _tree_entry(repo: Path, commit: str, path: str) -> dict[str, str]:
    raw = _git(repo, "ls-tree", "-z", commit, "--", path, limit=64 * 1024)
    if raw.count(b"\0") != 1 or not raw.endswith(b"\0"):
        _fail("FR0010_TREE_ENTRY:" + path)
    try:
        header, observed = raw[:-1].split(b"\t", 1)
        mode, object_type, oid = header.decode("ascii").split(" ")
        decoded = observed.decode("utf-8")
    except (UnicodeDecodeError, ValueError):
        _fail("FR0010_TREE_ENTRY:" + path)
    if (
        decoded != path
        or mode not in {"100644", "100755"}
        or object_type != "blob"
        or HEX40.fullmatch(oid) is None
    ):
        _fail("FR0010_TREE_ENTRY:" + path)
    return {"mode": mode, "type": object_type, "oid": oid}


def _file(repo: Path, commit: str, path: str, limit: int = MAX_JSON_BYTES) -> bytes:
    entry = _tree_entry(repo, commit, path)
    return _git(repo, "cat-file", "blob", entry["oid"], limit=limit)


def file_record(repo: Path, commit: str, path: str) -> dict[str, Any]:
    entry = _tree_entry(repo, commit, path)
    payload = _file(repo, commit, path, MAX_GIT_BYTES)
    return {
        "path": path,
        "git_mode": entry["mode"],
        "git_object_type": "blob",
        "git_object_id": entry["oid"],
        "sha256": hashlib.sha256(payload).hexdigest(),
        "bytes": len(payload),
    }


def _read_json(repo: Path, commit: str, path: str) -> tuple[dict[str, Any], bytes]:
    payload = _file(repo, commit, path)
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError):
        _fail("FR0010_JSON:" + path)
    if not isinstance(value, dict) or payload != canonical_json_bytes(value):
        _fail("FR0010_JSON_CANONICAL:" + path)
    return value, payload


def _verify_detached(
    repo: Path,
    record: Any,
    payload: bytes,
    *,
    namespace: str,
) -> None:
    if (
        not isinstance(record, dict)
        or set(record)
        != {
            "format",
            "namespace",
            "principal",
            "key_fingerprint",
            "signature",
        }
        or record["format"] != "ssh"
        or record["namespace"] != namespace
        or record["principal"] != SIGNER_PRINCIPAL
        or record["key_fingerprint"] != SIGNER_FINGERPRINT
        or not isinstance(record["signature"], str)
        or len(record["signature"]) > 16 * 1024
    ):
        _fail("FR0010_DETACHED_SIGNATURE")
    with tempfile.TemporaryDirectory(prefix="haldir-fr0010-signature-") as name:
        root = Path(name)
        signature = root / "signature"
        signature.write_text(record["signature"], encoding="ascii")
        completed = subprocess.run(
            (
                "/usr/bin/ssh-keygen",
                "-Y",
                "verify",
                "-f",
                str(repo / ALLOWED_SIGNERS_PATH),
                "-I",
                SIGNER_PRINCIPAL,
                "-n",
                namespace,
                "-s",
                str(signature),
            ),
            cwd=repo,
            env=_git_environment(),
            input=payload,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=30,
        )
    expected = (
        f'Good "{namespace}" signature for {SIGNER_PRINCIPAL} with ED25519 key '
        f"{SIGNER_FINGERPRINT}\n"
    ).encode("ascii")
    if (
        completed.returncode != 0
        or completed.stdout != expected
        or completed.stderr != b""
    ):
        _fail("FR0010_DETACHED_SIGNATURE")


def _core_patch(repo: Path, repair_commit: str) -> bytes:
    return _git(
        repo,
        "-c",
        "diff.algorithm=myers",
        "-c",
        "core.attributesFile=/dev/null",
        "diff",
        "--no-ext-diff",
        "--no-textconv",
        "--text",
        "--no-renames",
        "--no-color",
        "--full-index",
        "--binary",
        f"{PARENT}..{repair_commit}",
        "--",
        *CORE_PATHS,
    )


def _core_diff(repo: Path, repair_commit: str) -> dict[str, Any]:
    patch = _core_patch(repo, repair_commit)
    return {
        "base": PARENT,
        "target": "SIGNED_COMMIT_CONTAINING_THIS_PLAN",
        "paths": list(CORE_PATHS),
        "patch_sha256": hashlib.sha256(patch).hexdigest(),
        "patch_bytes": len(patch),
        "patch_lines": len(patch.splitlines()),
    }


def expected_plan(repo: Path, repair_commit: str) -> dict[str, Any]:
    """Return the exact unsigned FR-0010 plan."""

    return {
        "schema_version": "1.0.0",
        "recovery_id": RECOVERY_ID,
        "release_target": "0.9.0",
        "protocol_parent": {"commit": PARENT, "tree": PARENT_TREE},
        "repair_identity": {
            "subject": REPAIR_SUBJECT,
            "commit": "SIGNED_COMMIT_CONTAINING_THIS_PLAN",
            "required_parent": PARENT,
        },
        "repair_scope": dict(sorted(REPAIR_STATUSES.items())),
        "core_records": [
            file_record(repo, repair_commit, path) for path in CORE_PATHS
        ],
        "core_diff": _core_diff(repo, repair_commit),
        "legacy_boundary": {
            "state": "HISTORICAL_SIGNED_C5_BOUNDARY",
            "fr_0009_state": "ABORTED_BEFORE_QUALIFICATION",
            "legacy_forward_engine_state": "RETIRED_ON_EPOCH_11_ACTIVATION",
            "legacy_verifier_executed_on_successors": False,
            "records": copy.deepcopy(LEGACY_RECORDS),
        },
        "defects": [
            {
                "id": "FR0010-D01",
                "summary": (
                    "FR-0009 filters a gh whole-job archive as though every "
                    "line carried synthetic job and step prefixes."
                ),
                "c5_ci_run_id": 30_301_664_607,
                "c5_formal_run_id": 30_301_664_692,
            },
            {
                "id": "FR0010-D02",
                "summary": (
                    "FR-0009 authenticates only asserted size and digest for "
                    "an absent, untracked automated-review capture tool."
                ),
                "missing_tool": "review_fr_0009_models.py",
            },
        ],
        "correction": {
            "normative_hosted_proof": (
                "CANONICAL_RESULT_ARTIFACT_PLUS_SUCCESSFUL_RUN_JOBS_PLUS_"
                "GITHUB_OIDC_ATTESTATION"
            ),
            "trusted_root_bootstrap": {
                "path": TRUSTED_ROOT_PATH,
                "bytes": TRUSTED_ROOT_BYTES,
                "sha256": TRUSTED_ROOT_SHA256,
                "source": (
                    "gh-2.95.0 TUF-authenticated Sigstore Public Good "
                    "trusted-root record fetched 2026-07-29"
                ),
                "fulcio_uri": "https://fulcio.sigstore.dev",
                "rekor_uris": [
                    "https://log2025-1.rekor.sigstore.dev",
                    "https://rekor.sigstore.dev",
                ],
                "evidence_selected_root_allowed": False,
            },
            "offline_verifier_tool": {
                "name": "gh",
                "version": GH_CLI_VERSION,
                "linux_amd64_archive": GH_CLI_LINUX_AMD64_ARCHIVE,
                "linux_amd64_archive_sha256": (
                    GH_CLI_LINUX_AMD64_ARCHIVE_SHA256
                ),
                "linux_amd64_archive_bytes": (
                    GH_CLI_LINUX_AMD64_ARCHIVE_BYTES
                ),
                "linux_amd64_binary_sha256": (
                    GH_CLI_LINUX_AMD64_BINARY_SHA256
                ),
                "linux_amd64_binary_bytes": GH_CLI_LINUX_AMD64_BINARY_BYTES,
                "install": "DIGEST_VERIFIED_ARCHIVE_NO_CURL_TO_SHELL",
                "upstream_provenance": {
                    "release_id": 341_013_769,
                    "release_commit": (
                        "70bb306bd25eb407f90eabefd98824aed62cf519"
                    ),
                    "checksum_asset": {
                        "id": 450_525_906,
                        "bytes": 1_950,
                        "sha256": (
                            "d919a580356eaafd06321b9b6039ba513b81e370f"
                            "3134747807ef0b1a101f9f6"
                        ),
                        "contains_archive_sha256": True,
                    },
                    "archive_asset": {
                        "id": 450_525_940,
                        "bytes": GH_CLI_LINUX_AMD64_ARCHIVE_BYTES,
                        "sha256": GH_CLI_LINUX_AMD64_ARCHIVE_SHA256,
                    },
                    "public_good_slsa_attestation": {
                        "workflow": "deployment.yml@trunk",
                        "run_id": 27_714_369_385,
                        "run_attempt": 1,
                        "signer_and_source_commit": (
                            "70bb306bd25eb407f90eabefd98824aed62cf519"
                        ),
                        "verified_timestamp": "2026-06-17T19:53:16Z",
                    },
                    "github_release_attestation": (
                        "BINDS_RELEASE_AND_CHECKSUM_ASSETS"
                    ),
                },
            },
            "hosted_runner_labels": {
                "linux": "ubuntu-24.04",
                "macos": "macos-15",
                "property": "VERSIONED_LABEL_NOT_IMMUTABLE_IMAGE",
                "retirement_or_upgrade": (
                    "REQUIRES_NEW_SIGNED_FRAMEWORK_RECOVERY_EPOCH"
                ),
            },
            "hosted_reruns": {
                "allowed_attempts": {"minimum": 1, "maximum": 8},
                "rerun_mode": "ALL_JOBS_FOR_EXACT_ATTEMPT",
                "artifact_filename_attempt_qualified": True,
                "cross_attempt_reuse": "REJECT",
            },
            "whole_job_logs": "C5_DEFECT_REPRODUCTION_ONLY",
            "review_capture": (
                "TRACKED_REQUEST_BUILDER_PLUS_LITERAL_COMMITTED_RESPONSE_JSON"
            ),
            "oidc_job_isolation": (
                "NO_CHECKOUT_NO_REPOSITORY_CODE_CANONICAL_MAIN_PUSH_ONLY"
            ),
        },
        "stage_contract": {
            "repair": {
                "subject": REPAIR_SUBJECT,
                "state_after": "PENDING_QUALIFICATION",
            },
            "qualification": {
                "subject": QUALIFICATION_SUBJECT,
                "namespace": QUALIFICATION_NAMESPACE,
                "data_only": True,
                "state_after": "QUALIFIED_PENDING_ACTIVATION",
                "statuses": dict(sorted(QUALIFICATION_STATUSES.items())),
            },
            "activation": {
                "subject": ACTIVATION_SUBJECT,
                "namespace": ACTIVATION_NAMESPACE,
                "data_only": True,
                "state_after": "ACTIVE",
                "statuses": dict(sorted(ACTIVATION_STATUSES.items())),
            },
            "ordinary_successor_before_activation": "REJECT",
        },
        "post_activation_contract": {
            "model": "SIGNED_LINEAR_SCOPED_MILESTONES",
            "threat_model": "TRUSTED_SOURCE_AUTHORITY_AND_OWNER_ACCOUNT",
            "writer_adversarial_immutability_claimed": False,
            "main_update_ruleset": {
                "name": MAIN_RULESET_NAME,
                "enforcement": "active",
                "sole_bypass_actor": {
                    "actor_type": "User",
                    "actor_id": MAIN_RULESET_OWNER_ID,
                    "bypass_mode": "always",
                },
                "scope": "refs/heads/main",
                "rule": {
                    "type": "update",
                    "update_allows_fetch_and_merge": False,
                },
                "layers_with_classic_branch_protection": True,
            },
            "bespoke_per_task_f_i_c_d_required": False,
            "requirements_json_remains_audit_backlog": True,
            "required_pre_accept_checks": [
                {"context": context, "app_id": GITHUB_ACTIONS_APP_ID}
                for context in sorted(REQUIRED_PRE_ACCEPT_CHECKS)
            ],
            "post_main_attestation_jobs": [
                "attest-ci-audit-result",
                "attest-formal-audit-result",
            ],
            "candidate_hosted_evidence_captured_once_at_final_qualification": True,
            "trust_root_paths_immutable": sorted(PROTECTED_AFTER_ACTIVATION),
        },
        "review_contract": {
            "responses_committed_verbatim": True,
            "response_max_bytes": 1_048_576,
            "provider_provenance_independently_attested": False,
            "review_authority_conferred": False,
        },
        "authority": _authority("PENDING_QUALIFICATION"),
        "limitations": [
            (
                "GitHub OIDC proves the isolated attestation workflow identity; "
                "the producer result remains a statement from repository code."
            ),
            (
                "Automated model responses are retained exactly but their "
                "provider provenance is not independently signed or attested."
            ),
            (
                "Committed branch-protection API evidence is a TLS-observed "
                "snapshot of mutable external state, not durable cryptographic "
                "proof; live protection must be rechecked operationally."
            ),
            (
                "Offline successor verification proves signature, ancestry, "
                "and protected-path scope, but cannot prove that mutable GitHub "
                "required checks were enforced for each successor."
            ),
            (
                "The main update ruleset excludes non-owner writers, apps, and "
                "deploy keys, but the owner/admin can mutate external settings; "
                "owner-account or GitHub control-plane compromise is outside "
                "this repository-local guarantee."
            ),
            (
                "Versioned GitHub-hosted runner labels reduce image drift but "
                "do not identify immutable VM images; label retirement is an "
                "availability risk, and an upgrade requires a new signed "
                "framework-recovery epoch."
            ),
            (
                "Upstream GitHub CLI provenance identifiers are signed-plan "
                "rationale rather than retained independent evidence; runtime "
                "enforcement uses the exact archive and binary digests."
            ),
            (
                "This bridge grants no release, deployment, publication, tag, "
                "archive, DOI, or GitHub Release authority."
            ),
        ],
    }


def _authority(state: str) -> dict[str, Any]:
    return {
        "state": state,
        "framework_epoch": 11,
        "overall_release_status": "NO_GO",
        "release_authorized": False,
        "deployment_authorized": False,
        "publication_authorized": False,
        "tag_authorized": False,
        "github_release_authorized": False,
        "doi_authorized": False,
        "archive_authorized": False,
    }


def _verify_legacy_boundary(repo: Path) -> None:
    if _metadata(repo, PARENT)["tree"] != PARENT_TREE:
        _fail("FR0010_PARENT_TREE")
    _verify_commit_identity(
        repo,
        PARENT,
        parent="1e937a4bf213a5605250cf4843f1dfd26ae0ae3b",
        subject="release: repair hosted log protocol binding",
    )
    for path, expected in LEGACY_RECORDS.items():
        observed = file_record(repo, PARENT, path)
        comparable = {
            key: observed[key]
            for key in ("git_mode", "git_object_id", "sha256", "bytes")
        }
        if comparable != expected:
            _fail("FR0010_LEGACY_RECORD:" + path)


def _verify_repair(repo: Path, commit: str) -> dict[str, Any]:
    _verify_commit_identity(
        repo, commit, parent=PARENT, subject=REPAIR_SUBJECT
    )
    if _changed_statuses(repo, PARENT, commit) != dict(
        sorted(REPAIR_STATUSES.items())
    ):
        _fail("FR0010_REPAIR_DIFF")
    for path, mode in REPAIR_MODES.items():
        if _tree_entry(repo, commit, path)["mode"] != mode:
            _fail("FR0010_REPAIR_MODE:" + path)
    value, payload = _read_json(repo, commit, PLAN_PATH)
    expected = expected_plan(repo, commit)
    unsigned = {
        key: copy.deepcopy(item)
        for key, item in value.items()
        if key != "detached_signature"
    }
    if (
        set(value) != {*expected, "detached_signature"}
        or unsigned != expected
    ):
        _fail("FR0010_PLAN_INVALID")
    _verify_detached(
        repo,
        value["detached_signature"],
        canonical_json_bytes(unsigned),
        namespace=PLAN_NAMESPACE,
    )
    return value


def _load_protocol_module(repo: Path, repair_commit: str):
    payload = _file(repo, repair_commit, MODULE_PATH, MAX_GIT_BYTES)
    current = (repo / MODULE_PATH).read_bytes()
    if current != payload:
        _fail("FR0010_MODULE_WORKTREE_DRIFT")
    specification = importlib.util.spec_from_file_location(
        "_haldir_fr0010_protocol", repo / MODULE_PATH
    )
    if specification is None or specification.loader is None:
        _fail("FR0010_MODULE_LOAD")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def _evidence_catalog(
    repo: Path, commit: str, paths: Sequence[str]
) -> list[dict[str, Any]]:
    return [file_record(repo, commit, path) for path in paths]


def _validate_c5_lane(
    repo: Path,
    containing_commit: str,
    *,
    workflow: str,
    paths: tuple[str, str],
    protocol: Any,
) -> dict[str, Any]:
    metadata, _payload = _read_json(repo, containing_commit, paths[0])
    archive = _file(repo, containing_commit, paths[1], 2 * 1024 * 1024)
    suite_counts = [163, 78, 94, 26, 30, 44, 56, 37, 55, 60]
    return protocol.validate_c5_hosted_capture(
        metadata,
        archive,
        workflow=workflow,
        subject_commit=PARENT,
        suite_counts=suite_counts if workflow == "ci" else None,
    )


def _parse_utc(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        _fail("FR0010_TIMESTAMP:" + label)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        _fail("FR0010_TIMESTAMP:" + label)
    if parsed.tzinfo != timezone.utc:
        _fail("FR0010_TIMESTAMP:" + label)
    return parsed


def _parse_git_time(value: Any, label: str) -> datetime:
    if not isinstance(value, str):
        _fail("FR0010_TIMESTAMP:" + label)
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        _fail("FR0010_TIMESTAMP:" + label)
    if parsed.tzinfo is None:
        _fail("FR0010_TIMESTAMP:" + label)
    return parsed.astimezone(timezone.utc)


def _trusted_gh() -> tuple[Path, str]:
    configured = os.environ.get("HALDIR_FR0010_GH")
    if configured is not None:
        runner_temp = os.environ.get("RUNNER_TEMP")
        if (
            not runner_temp
            or configured
            != str(
                Path(runner_temp)
                / "haldir-gh-2.95.0"
                / "gh_2.95.0_linux_amd64"
                / "bin"
                / "gh"
            )
        ):
            _fail("FR0010_GH_EXECUTABLE")
        candidates = (Path(configured),)
    else:
        candidates = (
            Path("/usr/bin/gh"),
            Path("/usr/local/bin/gh"),
            Path("/opt/homebrew/bin/gh"),
        )
    executable: Path | None = None
    for candidate in candidates:
        try:
            if configured is not None and candidate.is_symlink():
                continue
            resolved = candidate.resolve(strict=True)
            metadata = resolved.stat()
        except OSError:
            continue
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or not os.access(resolved, os.X_OK)
        ):
            continue
        if configured is not None:
            if (
                metadata.st_size != GH_CLI_LINUX_AMD64_BINARY_BYTES
                or _bounded_file_sha256(
                    resolved,
                    expected_bytes=GH_CLI_LINUX_AMD64_BINARY_BYTES,
                )
                != GH_CLI_LINUX_AMD64_BINARY_SHA256
            ):
                continue
        executable = resolved
        break
    if executable is None:
        _fail("FR0010_GH_EXECUTABLE")
    with tempfile.TemporaryDirectory(prefix="haldir-fr0010-gh-version-") as name:
        completed = subprocess.run(
            (str(executable), "--version"),
            env={
                "GH_CONFIG_DIR": name,
                "HOME": name,
                "LC_ALL": "C",
                "PATH": f"{executable.parent}:/usr/bin:/bin",
            },
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=10,
        )
    if (
        completed.returncode != 0
        or completed.stderr
        or len(completed.stdout) > 4096
    ):
        _fail("FR0010_GH_VERSION")
    try:
        output = completed.stdout.decode("ascii")
    except UnicodeDecodeError:
        _fail("FR0010_GH_VERSION")
    if not output.startswith(
        "gh version 2.95.0 (2026-06-17)\n"
    ):
        _fail("FR0010_GH_VERSION")
    return executable, output.rstrip("\n")


def _bounded_file_sha256(path: Path, *, expected_bytes: int) -> str:
    digest = hashlib.sha256()
    consumed = 0
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            consumed += len(chunk)
            if consumed > expected_bytes:
                _fail("FR0010_GH_EXECUTABLE")
            digest.update(chunk)
    if consumed != expected_bytes:
        _fail("FR0010_GH_EXECUTABLE")
    return digest.hexdigest()


def _write_private(path: Path, payload: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written < 1:
                _fail("FR0010_TEMP_WRITE")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _run_bounded(
    command: tuple[str, ...],
    *,
    cwd: Path,
    env: dict[str, str],
    timeout_seconds: float,
    output_limit: int,
) -> tuple[int, bytes, bytes]:
    process = subprocess.Popen(
        command,
        cwd=cwd,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if process.stdout is None or process.stderr is None:
        process.kill()
        _fail("FR0010_PROCESS_PIPE")
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    streams = {"stdout": bytearray(), "stderr": bytearray()}
    deadline = time.monotonic() + timeout_seconds
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                process.kill()
                process.wait(timeout=5)
                _fail("FR0010_GH_TIMEOUT")
            for key, _mask in selector.select(min(remaining, 0.25)):
                chunk = os.read(key.fileobj.fileno(), 64 * 1024)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                streams[key.data].extend(chunk)
                if sum(len(value) for value in streams.values()) > output_limit:
                    process.kill()
                    process.wait(timeout=5)
                    _fail("FR0010_GH_OUTPUT_BOUND")
        returncode = process.wait(timeout=max(0.1, deadline - time.monotonic()))
    finally:
        selector.close()
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
    return returncode, bytes(streams["stdout"]), bytes(streams["stderr"])


def _validate_trusted_root(payload: bytes) -> None:
    if (
        len(payload) != TRUSTED_ROOT_BYTES
        or hashlib.sha256(payload).hexdigest() != TRUSTED_ROOT_SHA256
        or b"\0" in payload
        or not payload.endswith(b"\n")
    ):
        _fail("FR0010_TRUSTED_ROOT_BOUND")
    lines = payload.splitlines()
    if len(lines) != 1:
        _fail("FR0010_TRUSTED_ROOT_BOUND")
    try:
        value = json.loads(lines[0])
    except (UnicodeDecodeError, json.JSONDecodeError):
        _fail("FR0010_TRUSTED_ROOT_JSONL")
    if (
        not isinstance(value, dict)
        or value.get("mediaType")
        != "application/vnd.dev.sigstore.trustedroot+json;version=0.1"
        or {
            item.get("uri")
            for item in value.get("certificateAuthorities", [])
            if isinstance(item, dict)
        }
        != {"https://fulcio.sigstore.dev"}
        or {
            item.get("baseUrl")
            for item in value.get("tlogs", [])
            if isinstance(item, dict)
        }
        != {
            "https://rekor.sigstore.dev",
            "https://log2025-1.rekor.sigstore.dev",
        }
    ):
        _fail("FR0010_TRUSTED_ROOT_IDENTITY")


def _verification_argv(
    *,
    executable: Path,
    result_path: Path,
    bundle_path: Path,
    trusted_root_path: Path,
    workflow: str,
    subject_commit: str,
) -> tuple[str, ...]:
    workflow_path = (
        ".github/workflows/ci.yml"
        if workflow == "ci"
        else ".github/workflows/formal.yml"
    )
    identity = (
        f"https://github.com/sepahead/haldir/{workflow_path}"
        "@refs/heads/main"
    )
    return (
        str(executable),
        "attestation",
        "verify",
        str(result_path),
        "--bundle",
        str(bundle_path),
        "--custom-trusted-root",
        str(trusted_root_path),
        "--repo",
        "sepahead/haldir",
        "--format",
        "json",
        "--cert-identity",
        identity,
        "--cert-oidc-issuer",
        "https://token.actions.githubusercontent.com",
        "--deny-self-hosted-runners",
        "--digest-alg",
        "sha256",
        "--predicate-type",
        "https://slsa.dev/provenance/v1",
        "--signer-digest",
        subject_commit,
        "--source-digest",
        subject_commit,
        "--source-ref",
        "refs/heads/main",
        "--hostname",
        "github.com",
    )


def _offline_verification_environment(
    *,
    executable: Path,
    root: Path,
    config_dir: Path,
) -> dict[str, str]:
    return {
        "ALL_PROXY": "http://127.0.0.1:1",
        "GH_CONFIG_DIR": str(config_dir),
        "GH_HOST": "github.com",
        "GH_TOKEN": "invalid-offline-token",
        "GITHUB_TOKEN": "invalid-offline-token",
        "HOME": str(root),
        "HTTPS_PROXY": "http://127.0.0.1:1",
        "HTTP_PROXY": "http://127.0.0.1:1",
        "LC_ALL": "C",
        "NO_PROXY": "",
        "PATH": f"{executable.parent}:/usr/bin:/bin",
        "TZ": "UTC",
    }


def _verify_attestation_offline(
    *,
    result_payload: bytes,
    bundle_payload: bytes,
    trusted_root_payload: bytes,
    workflow: str,
    subject_commit: str,
    attempt: int,
) -> tuple[Any, dict[str, Any]]:
    _validate_trusted_root(trusted_root_payload)
    executable, version = _trusted_gh()
    with tempfile.TemporaryDirectory(prefix="haldir-fr0010-attestation-") as name:
        root = Path(name)
        result_path = (
            root
            / f"epoch-11-{workflow}-result-attempt-{attempt}.json"
        )
        bundle_path = root / "attestation.jsonl"
        trusted_root_path = root / "trusted-root.jsonl"
        _write_private(result_path, result_payload)
        _write_private(bundle_path, bundle_payload)
        _write_private(trusted_root_path, trusted_root_payload)
        command = _verification_argv(
            executable=executable,
            result_path=result_path,
            bundle_path=bundle_path,
            trusted_root_path=trusted_root_path,
            workflow=workflow,
            subject_commit=subject_commit,
        )
        isolated = root / "gh-config"
        isolated.mkdir(mode=0o700)
        environment = _offline_verification_environment(
            executable=executable,
            root=root,
            config_dir=isolated,
        )
        returncode, stdout, stderr = _run_bounded(
            command,
            cwd=root,
            env=environment,
            timeout_seconds=30,
            output_limit=2 * 1024 * 1024,
        )
    if returncode != 0 or stderr:
        _fail("FR0010_ATTESTATION_CRYPTOGRAPHY")
    try:
        receipt = json.loads(stdout)
    except (UnicodeDecodeError, json.JSONDecodeError):
        _fail("FR0010_ATTESTATION_CRYPTOGRAPHY")
    return receipt, {
        "tool": "gh",
        "version": version,
        "network_mode": "OFFLINE_INVALID_PROXY_AND_TOKEN",
        "custom_trusted_root_sha256": hashlib.sha256(
            trusted_root_payload
        ).hexdigest(),
        "result": "PASS",
    }


def _hosted_commands(
    *,
    workflow: str,
    run_id: int,
    attempt: int,
    artifact_id: int,
) -> dict[str, str]:
    fields = (
        "attempt,conclusion,createdAt,databaseId,event,headBranch,headSha,jobs,"
        "number,status,updatedAt,url,workflowDatabaseId,workflowName"
    )
    attempt_fields = (
        "attempt,conclusion,createdAt,databaseId,event,headBranch,headSha,jobs,"
        "number,startedAt,status,updatedAt,url,workflowDatabaseId,workflowName"
    )
    artifact_name = f"epoch-11-{workflow}-result-attempt-{attempt}.json"
    return {
        "ordinary": (
            f"gh run view {run_id} --repo sepahead/haldir --json {fields}"
        ),
        "attempt": (
            f"gh run view {run_id} --repo sepahead/haldir --attempt {attempt} "
            f"--json {attempt_fields}"
        ),
        "artifact_list": (
            "gh api --method GET "
            f"repos/sepahead/haldir/actions/runs/{run_id}/artifacts"
            f"?name={artifact_name}&per_page=100"
        ),
        "artifact_get": (
            "gh api --method GET "
            f"repos/sepahead/haldir/actions/artifacts/{artifact_id}"
        ),
        "artifact_download": (
            "gh api --method GET "
            f"repos/sepahead/haldir/actions/artifacts/{artifact_id}/zip"
        ),
        "attestation_download": (
            f"gh attestation download {artifact_name} "
            "--repo sepahead/haldir --limit 1 "
            "--predicate-type https://slsa.dev/provenance/v1"
        ),
    }


def _validate_hosted_lane(
    repo: Path,
    containing_commit: str,
    *,
    repair_commit: str,
    workflow: str,
    subject_commit: str,
    paths: tuple[str, str, str],
    protocol: Any,
) -> dict[str, Any]:
    capture, _capture_payload = _read_json(repo, containing_commit, paths[0])
    result_payload = _file(repo, containing_commit, paths[1], 256 * 1024)
    bundle_payload = _file(repo, containing_commit, paths[2], 1024 * 1024)
    trusted_root_payload = _file(
        repo,
        repair_commit,
        TRUSTED_ROOT_PATH,
        MAX_TRUSTED_ROOT_BYTES,
    )
    required = {
        "schema_version",
        "protocol",
        "workflow",
        "subject_commit",
        "subject_tree",
        "expected_ref",
        "ordinary",
        "attempt_metadata",
        "artifact_listing",
        "artifact_by_id",
        "artifact",
        "artifact_download",
        "commands",
        "capture_tool",
        "result_record",
        "attestation_record",
        "trusted_root_record",
        "attestation_verification",
        "capture_verification",
        "captured_at_utc",
        "result",
    }
    if (
        not isinstance(capture, dict)
        or set(capture) != required
        or capture["schema_version"] != "1.0.0"
        or capture["protocol"] != "HALDIR_FR_0010_HOSTED_RESULT_CAPTURE_V1"
        or capture["workflow"] != workflow
        or capture["subject_commit"] != subject_commit
        or capture["subject_tree"] != _metadata(repo, subject_commit)["tree"]
        or capture["expected_ref"] != "refs/heads/main"
        or capture["result"] != "PASS"
        or capture["capture_tool"]
        != file_record(repo, repair_commit, CAPTURE_PATH)
    ):
        _fail("FR0010_HOSTED_CAPTURE_SCHEMA")
    if capture["result_record"] != file_record(repo, containing_commit, paths[1]):
        _fail("FR0010_HOSTED_RESULT_RECORD")
    if capture["attestation_record"] != file_record(
        repo, containing_commit, paths[2]
    ):
        _fail("FR0010_HOSTED_ATTESTATION_RECORD")
    if capture["trusted_root_record"] != file_record(
        repo, repair_commit, TRUSTED_ROOT_PATH
    ):
        _fail("FR0010_HOSTED_TRUSTED_ROOT_RECORD")
    _validate_trusted_root(trusted_root_payload)
    run = protocol.validate_epoch11_run_documents(
        capture["ordinary"],
        capture["attempt_metadata"],
        workflow=workflow,
        subject_commit=subject_commit,
        expected_ref="refs/heads/main",
    )
    listing = capture["artifact_listing"]
    if (
        not isinstance(listing, dict)
        or set(listing) != {"artifacts", "total_count"}
        or listing["total_count"] != 1
        or listing["artifacts"] != [capture["artifact"]]
        or capture["artifact_by_id"] != capture["artifact"]
    ):
        _fail("FR0010_ARTIFACT_UNIQUENESS")
    if capture["artifact_download"] != {
        "bytes": len(result_payload),
        "content_mode": "DIRECT_UNARCHIVED_FILE",
        "sha256": hashlib.sha256(result_payload).hexdigest(),
    }:
        _fail("FR0010_ARTIFACT_DOWNLOAD")
    if capture["commands"] != _hosted_commands(
        workflow=workflow,
        run_id=run["run_id"],
        attempt=run["attempt"],
        artifact_id=capture["artifact"].get("id", 0)
        if isinstance(capture["artifact"], dict)
        else 0,
    ):
        _fail("FR0010_HOSTED_COMMANDS")
    captured = _parse_utc(capture["captured_at_utc"], "hosted.captured")
    if (
        captured
        < max(
            _parse_utc(capture["ordinary"]["updatedAt"], "hosted.run.updated"),
            _parse_utc(
                capture["attempt_metadata"]["updatedAt"],
                "hosted.attempt.updated",
            ),
            _parse_utc(
                capture["artifact"]["updated_at"], "hosted.artifact.updated"
            ),
        )
        or captured
        > _parse_git_time(
            _metadata(repo, containing_commit)["committer_date"],
            "hosted.containing_commit",
        )
    ):
        _fail("FR0010_HOSTED_CHRONOLOGY")
    materials = [
        file_record(repo, subject_commit, path)
        for path in protocol.RESULT_CONTRACT[workflow]["material_paths"]
    ]
    protocol.validate_result_artifact(
        result_payload,
        workflow=workflow,
        subject_commit=subject_commit,
        subject_tree=capture["subject_tree"],
        run_id=run["run_id"],
        attempt=run["attempt"],
        run_number=run["run_number"],
        expected_ref="refs/heads/main",
        expected_materials=materials,
    )
    protocol.validate_artifact_metadata(
        capture["artifact"],
        workflow=workflow,
        run_id=run["run_id"],
        attempt=run["attempt"],
        subject_commit=subject_commit,
        result_payload=result_payload,
        producer_started=run["jobs"][
            protocol.RESULT_CONTRACT[workflow]["job"]
        ]["started"],
        producer_completed=run["jobs"][
            protocol.RESULT_CONTRACT[workflow]["job"]
        ]["completed"],
        attestation_started=run["jobs"][run["attestation_job"]]["started"],
    )
    captured_attestation = protocol.validate_attestation_evidence(
        bundle_payload,
        capture["attestation_verification"],
        workflow=workflow,
        result_payload=result_payload,
        subject_commit=subject_commit,
        expected_ref="refs/heads/main",
        run_id=run["run_id"],
        attempt=run["attempt"],
        attestation_started=run["jobs"][run["attestation_job"]]["started"],
        attestation_completed=run["jobs"][run["attestation_job"]]["completed"],
    )
    live_receipt, offline_verification = _verify_attestation_offline(
        result_payload=result_payload,
        bundle_payload=bundle_payload,
        trusted_root_payload=trusted_root_payload,
        workflow=workflow,
        subject_commit=subject_commit,
        attempt=run["attempt"],
    )
    attestation = protocol.validate_attestation_evidence(
        bundle_payload,
        live_receipt,
        workflow=workflow,
        result_payload=result_payload,
        subject_commit=subject_commit,
        expected_ref="refs/heads/main",
        run_id=run["run_id"],
        attempt=run["attempt"],
        attestation_started=run["jobs"][run["attestation_job"]]["started"],
        attestation_completed=run["jobs"][run["attestation_job"]]["completed"],
    )
    capture_verification = capture["capture_verification"]
    if (
        not isinstance(capture_verification, dict)
        or set(capture_verification)
        != {
            "custom_trusted_root_sha256",
            "network_mode",
            "result",
            "tool",
            "version",
        }
        or capture_verification["tool"] != "gh"
        or not isinstance(capture_verification["version"], str)
        or not capture_verification["version"].startswith(
            "gh version 2.95.0 (2026-06-17)\n"
        )
        or capture_verification["network_mode"]
        != "OFFLINE_INVALID_PROXY_AND_TOKEN"
        or capture_verification["custom_trusted_root_sha256"]
        != hashlib.sha256(trusted_root_payload).hexdigest()
        or capture_verification["result"] != "PASS"
        or captured_attestation != attestation
    ):
        _fail("FR0010_CAPTURE_OFFLINE_VERIFICATION")
    return {
        "workflow": workflow,
        "run_id": run["run_id"],
        "attempt": run["attempt"],
        "artifact_id": capture["artifact"]["id"],
        "result_sha256": hashlib.sha256(result_payload).hexdigest(),
        "attestation": attestation,
        "offline_verification": offline_verification,
    }


def _validate_review(
    repo: Path,
    containing_commit: str,
    *,
    repair_commit: str,
    paths: tuple[str, str],
    review_id: str,
    model: str,
    plan: dict[str, Any],
    protocol: Any,
) -> dict[str, Any]:
    capture, _capture_payload = _read_json(repo, containing_commit, paths[0])
    response = _file(repo, containing_commit, paths[1], 1024 * 1024)
    required_findings = [
        {
            "id": "F001",
            "summary": "Normative hosted proof is artifact and OIDC based.",
            "affected_paths": [
                MODULE_PATH,
                ".github/workflows/ci.yml",
                ".github/workflows/formal.yml",
            ],
        },
        {
            "id": "F002",
            "summary": "Legacy successor recursion is retired after activation.",
            "affected_paths": [BRIDGE_PATH, PLAN_PATH],
        },
        {
            "id": "F003",
            "summary": "Exact model response bytes are retained and reparsed.",
            "affected_paths": [CAPTURE_PATH, paths[1]],
        },
    ]
    manifest = protocol.review_subject_manifest(
        review_id=review_id,
        model=model,
        repair_commit=repair_commit,
        plan_sha256=file_record(repo, repair_commit, PLAN_PATH)["sha256"],
        patch_sha256=plan["core_diff"]["patch_sha256"],
        gate_sha256=file_record(repo, repair_commit, GATE_PATH)["sha256"],
        required_findings=required_findings,
    )
    plan_payload = _file(repo, repair_commit, PLAN_PATH)
    patch_payload = _core_patch(repo, repair_commit)
    gate_payload = _file(repo, repair_commit, GATE_PATH)
    request = protocol.build_review_request(
        manifest=manifest,
        plan_payload=plan_payload,
        patch_payload=patch_payload,
        gate_payload=gate_payload,
    )
    outcome = protocol.parse_review_response_bytes(
        response, manifest=manifest
    )
    expected_capture = {
        "schema_version": "1.0.0",
        "protocol": "HALDIR_FR_0010_REVIEW_CAPTURE_V1",
        "review_id": review_id,
        "model": model,
        "manifest": manifest,
        "request_sha256": hashlib.sha256(request).hexdigest(),
        "request_bytes": len(request),
        "response_record": file_record(repo, containing_commit, paths[1]),
        "parsed_outcome": outcome,
        "provider_provenance_independently_attested": False,
        "review_authority_conferred": False,
    }
    if capture != expected_capture:
        _fail("FR0010_REVIEW_CAPTURE:" + review_id)
    if outcome["verdict"] != "GO_FOR_FRAMEWORK_QUALIFICATION":
        _fail("FR0010_REVIEW_VETO:" + review_id)
    return outcome


def _verify_stage_signature(
    repo: Path,
    value: dict[str, Any],
    *,
    namespace: str,
) -> dict[str, Any]:
    unsigned = {
        key: copy.deepcopy(item)
        for key, item in value.items()
        if key != "detached_signature"
    }
    _verify_detached(
        repo,
        value.get("detached_signature"),
        canonical_json_bytes(unsigned),
        namespace=namespace,
    )
    return unsigned


def validate_main_writer_ruleset(
    ruleset_list: Any,
    ruleset_by_id: Any,
    effective_rules: Any,
) -> dict[str, Any]:
    """Validate the exact owner-only update layer over classic protection."""

    if (
        not isinstance(ruleset_list, list)
        or not isinstance(ruleset_by_id, dict)
        or not isinstance(effective_rules, list)
    ):
        _fail("FR0010_RULESET_SCHEMA")
    matches = [
        item
        for item in ruleset_list
        if isinstance(item, dict) and item.get("name") == MAIN_RULESET_NAME
    ]
    if len(matches) != 1:
        _fail("FR0010_RULESET_UNIQUENESS")
    summary = matches[0]
    ruleset_id = summary.get("id")
    if (
        type(ruleset_id) is not int
        or ruleset_id < 1
        or summary.get("target") != "branch"
        or summary.get("enforcement") != "active"
        or summary.get("source_type") != "Repository"
        or summary.get("source") != "sepahead/haldir"
        or ruleset_by_id.get("id") != ruleset_id
        or ruleset_by_id.get("name") != MAIN_RULESET_NAME
        or ruleset_by_id.get("target") != "branch"
        or ruleset_by_id.get("enforcement") != "active"
        or ruleset_by_id.get("source_type") != "Repository"
        or ruleset_by_id.get("source") != "sepahead/haldir"
    ):
        _fail("FR0010_RULESET_IDENTITY")
    if ruleset_by_id.get("bypass_actors") != [
        {
            "actor_id": MAIN_RULESET_OWNER_ID,
            "actor_type": "User",
            "bypass_mode": "always",
        }
    ]:
        _fail("FR0010_RULESET_BYPASS")
    if ruleset_by_id.get("conditions") != {
        "ref_name": {
            "exclude": [],
            "include": ["refs/heads/main"],
        }
    }:
        _fail("FR0010_RULESET_CONDITIONS")
    expected_rule = {
        "type": "update",
        "parameters": {"update_allows_fetch_and_merge": False},
    }
    if ruleset_by_id.get("rules") != [expected_rule]:
        _fail("FR0010_RULESET_RULES")
    if (
        len(effective_rules) != 1
        or not isinstance(effective_rules[0], dict)
        or effective_rules[0].get("type") != "update"
        or effective_rules[0].get("parameters")
        != {"update_allows_fetch_and_merge": False}
        or effective_rules[0].get("ruleset_id") != ruleset_id
        or effective_rules[0].get("ruleset_source_type") != "Repository"
        or effective_rules[0].get("ruleset_source") != "sepahead/haldir"
    ):
        _fail("FR0010_RULESET_EFFECTIVE")
    return {
        "id": ruleset_id,
        "name": MAIN_RULESET_NAME,
        "owner_user_id": MAIN_RULESET_OWNER_ID,
        "enforcement": "active",
        "effective_rule": expected_rule,
        "protects_against": [
            "NON_OWNER_REPOSITORY_WRITERS",
            "GITHUB_APPS",
            "DEPLOY_KEYS",
        ],
        "owner_account_compromise_protected": False,
        "mutable_external_admin_state": True,
    }


def _verify_branch_protection(
    repo: Path,
    containing_commit: str,
    qualification_commit: str,
) -> dict[str, Any]:
    value, _payload = _read_json(
        repo, containing_commit, BRANCH_PROTECTION_PATH
    )
    if (
        set(value)
        != {
            "authority",
            "branch",
            "capture",
            "effective_rules",
            "observed_commit",
            "protocol",
            "protection",
            "ref_after",
            "ref_before",
            "repository",
            "repository_id",
            "ruleset_by_id",
            "ruleset_list",
            "schema_version",
        }
        or value["schema_version"] != "1.0.0"
        or value["protocol"]
        != "HALDIR_FR_0010_BRANCH_PROTECTION_CAPTURE_V1"
        or value["repository"] != "sepahead/haldir"
        or value["repository_id"] != 1_292_802_592
        or value["branch"] != "main"
        or value["observed_commit"] != qualification_commit
        or value["authority"]
        != {
            "cryptographic_proof": False,
            "durable_external_state_proof": False,
            "release_authority": False,
            "transport_observation": "GITHUB_API_OVER_TLS",
        }
    ):
        _fail("FR0010_BRANCH_PROTECTION_SCHEMA")
    expected_ref = {
        "ref": "refs/heads/main",
        "node_id": value["ref_before"].get("node_id")
        if isinstance(value["ref_before"], dict)
        else None,
        "url": "https://api.github.com/repos/sepahead/haldir/git/refs/heads/main",
        "object": {
            "sha": qualification_commit,
            "type": "commit",
            "url": (
                "https://api.github.com/repos/sepahead/haldir/git/commits/"
                f"{qualification_commit}"
            ),
        },
    }
    if (
        not isinstance(value["ref_before"], dict)
        or set(value["ref_before"]) != {"node_id", "object", "ref", "url"}
        or not isinstance(value["ref_before"].get("node_id"), str)
        or not value["ref_before"]["node_id"]
        or value["ref_before"] != expected_ref
        or value["ref_after"] != expected_ref
    ):
        _fail("FR0010_BRANCH_PROTECTION_HEAD_STABILITY")
    protection = value["protection"]
    if not isinstance(protection, dict):
        _fail("FR0010_BRANCH_PROTECTION_SCHEMA")
    required_status = protection.get("required_status_checks")
    expected_checks = [
        {"app_id": GITHUB_ACTIONS_APP_ID, "context": context}
        for context in sorted(REQUIRED_PRE_ACCEPT_CHECKS)
    ]
    if (
        not isinstance(required_status, dict)
        or required_status.get("strict") is not True
        or sorted(
            required_status.get("checks", []),
            key=lambda item: (
                item.get("context", "") if isinstance(item, dict) else ""
            ),
        )
        != expected_checks
        or set(required_status.get("contexts", []))
        != REQUIRED_PRE_ACCEPT_CHECKS
        or protection.get("enforce_admins", {}).get("enabled") is not True
        or protection.get("required_linear_history", {}).get("enabled")
        is not True
        or protection.get("required_signatures", {}).get("enabled") is not True
        or protection.get("allow_force_pushes", {}).get("enabled") is not False
        or protection.get("allow_deletions", {}).get("enabled") is not False
    ):
        _fail("FR0010_BRANCH_PROTECTION_POLICY")
    ruleset = validate_main_writer_ruleset(
        value["ruleset_list"],
        value["ruleset_by_id"],
        value["effective_rules"],
    )
    capture = value["capture"]
    if (
        not isinstance(capture, dict)
        or set(capture)
        != {
            "captured_at_utc",
            "commit_after_command",
            "commit_before_command",
            "effective_rules_command",
            "protection_command",
            "result",
            "ruleset_get_command",
            "ruleset_list_command",
            "transport",
        }
        or capture["commit_before_command"]
        != "gh api --method GET repos/sepahead/haldir/git/ref/heads/main"
        or capture["commit_after_command"]
        != "gh api --method GET repos/sepahead/haldir/git/ref/heads/main"
        or capture["protection_command"]
        != "gh api --method GET repos/sepahead/haldir/branches/main/protection"
        or capture["ruleset_list_command"]
        != "gh api --method GET repos/sepahead/haldir/rulesets"
        or capture["ruleset_get_command"]
        != (
            "gh api --method GET repos/sepahead/haldir/rulesets/"
            f"{ruleset['id']}"
        )
        or capture["effective_rules_command"]
        != "gh api --method GET repos/sepahead/haldir/rules/branches/main"
        or capture["transport"] != "GITHUB_API_OVER_TLS"
        or capture["result"] != "PASS"
    ):
        _fail("FR0010_BRANCH_PROTECTION_CAPTURE")
    _parse_utc(capture["captured_at_utc"], "branch-protection.captured")
    result = copy.deepcopy(value)
    result["validated_ruleset_policy"] = ruleset
    return result


def _verify_qualification(
    repo: Path,
    repair_commit: str,
    commit: str,
    *,
    plan: dict[str, Any],
    protocol: Any,
) -> dict[str, Any]:
    _verify_commit_identity(
        repo,
        commit,
        parent=repair_commit,
        subject=QUALIFICATION_SUBJECT,
    )
    if _changed_statuses(repo, repair_commit, commit) != dict(
        sorted(QUALIFICATION_STATUSES.items())
    ):
        _fail("FR0010_QUALIFICATION_DIFF")
    for path in (*CORE_PATHS, PLAN_PATH):
        if _tree_entry(repo, commit, path) != _tree_entry(
            repo, repair_commit, path
        ):
            _fail("FR0010_QUALIFICATION_DRIFT:" + path)
    c5 = {
        "ci": _validate_c5_lane(
            repo,
            commit,
            workflow="ci",
            paths=C5_CI_PATHS,
            protocol=protocol,
        ),
        "formal": _validate_c5_lane(
            repo,
            commit,
            workflow="formal",
            paths=C5_FORMAL_PATHS,
            protocol=protocol,
        ),
    }
    hosted = {
        "repair_ci": _validate_hosted_lane(
            repo,
            commit,
            repair_commit=repair_commit,
            workflow="ci",
            subject_commit=repair_commit,
            paths=REPAIR_CI_PATHS,
            protocol=protocol,
        ),
        "repair_formal": _validate_hosted_lane(
            repo,
            commit,
            repair_commit=repair_commit,
            workflow="formal",
            subject_commit=repair_commit,
            paths=REPAIR_FORMAL_PATHS,
            protocol=protocol,
        ),
    }
    reviews = {
        "FR-0010-R01": _validate_review(
            repo,
            commit,
            repair_commit=repair_commit,
            paths=DESIGN_REVIEW_PATHS,
            review_id="FR-0010-R01",
            model="claude-fable-5",
            plan=plan,
            protocol=protocol,
        ),
        "FR-0010-R02": _validate_review(
            repo,
            commit,
            repair_commit=repair_commit,
            paths=IMPLEMENTATION_REVIEW_PATHS,
            review_id="FR-0010-R02",
            model="claude-opus-5",
            plan=plan,
            protocol=protocol,
        ),
    }
    local, _local_payload = _read_json(repo, commit, LOCAL_PATH)
    python_commands = (
        [
            "-I",
            "-B",
            "-W",
            "error",
            "tools/release/test_verify_framework_recovery_fr_0010.py",
        ],
        [
            "-I",
            "-B",
            "-W",
            "error",
            "tools/verify-ci-pins.py",
        ],
        [
            "-I",
            "-B",
            "-W",
            "error",
            "tools/release/verify-framework-recovery-fr-0010.py",
        ],
    )
    if (
        set(local)
        != {
            "authority",
            "capture_tool",
            "checks",
            "completed_at_utc",
            "protocol",
            "python",
            "result",
            "schema_version",
            "subject_commit",
            "subject_tree",
        }
        or local["schema_version"] != "1.0.0"
        or local["protocol"] != "HALDIR_FR_0010_LOCAL_VALIDATION_V1"
        or local["subject_commit"] != repair_commit
        or local["subject_tree"] != _metadata(repo, repair_commit)["tree"]
        or local["capture_tool"]
        != file_record(repo, repair_commit, CAPTURE_PATH)
        or local["python"]
        != {"implementation": "cpython", "version": "3.14.6"}
        or not isinstance(local["checks"], list)
        or len(local["checks"]) != 4
        or local["result"] != "PASS"
        or local["authority"] != _authority("PENDING_QUALIFICATION")
    ):
        _fail("FR0010_LOCAL_EVIDENCE")
    for index, check in enumerate(local["checks"]):
        if (
            not isinstance(check, dict)
            or set(check)
            != {
                "argv",
                "result",
                "returncode",
                "stderr_bytes",
                "stderr_sha256",
                "stdout_bytes",
                "stdout_sha256",
            }
            or check["returncode"] != 0
            or check["result"] != "PASS"
            or type(check["stdout_bytes"]) is not int
            or not 0 <= check["stdout_bytes"] <= 4 * 1024 * 1024
            or type(check["stderr_bytes"]) is not int
            or not 0 <= check["stderr_bytes"] <= 4 * 1024 * 1024
            or HEX64.fullmatch(str(check["stdout_sha256"])) is None
            or HEX64.fullmatch(str(check["stderr_sha256"])) is None
            or not isinstance(check["argv"], list)
        ):
            _fail("FR0010_LOCAL_CHECK")
        if index < 3:
            executable = check["argv"][0] if check["argv"] else None
            if (
                not isinstance(executable, str)
                or not Path(executable).is_absolute()
                or not Path(executable).name.startswith("python3")
                or check["argv"][1:] != python_commands[index]
            ):
                _fail("FR0010_LOCAL_COMMAND")
        elif check["argv"] != [
            "/usr/bin/git",
            "-c",
            "core.hooksPath=/dev/null",
            "diff",
            "--check",
            f"{PARENT}..{repair_commit}",
        ]:
            _fail("FR0010_LOCAL_COMMAND")
    completed = _parse_utc(local["completed_at_utc"], "local.completed")
    if completed > _parse_git_time(
        _metadata(repo, commit)["committer_date"], "local.containing_commit"
    ):
        _fail("FR0010_LOCAL_CHRONOLOGY")
    expected = {
        "schema_version": "1.0.0",
        "recovery_id": RECOVERY_ID,
        "stage": "QUALIFICATION",
        "state_before": "PENDING_QUALIFICATION",
        "state_after": "QUALIFIED_PENDING_ACTIVATION",
        "repair_commit": repair_commit,
        "plan_record": file_record(repo, repair_commit, PLAN_PATH),
        "evidence_catalog": _evidence_catalog(
            repo, commit, QUALIFICATION_EVIDENCE_PATHS
        ),
        "c5_defect_reproduction": c5,
        "hosted_evidence": hosted,
        "reviews": reviews,
        "authority": _authority("QUALIFIED_PENDING_ACTIVATION"),
        "limitations": plan["limitations"],
    }
    value, _payload = _read_json(repo, commit, QUALIFICATION_PATH)
    unsigned = _verify_stage_signature(
        repo, value, namespace=QUALIFICATION_NAMESPACE
    )
    if unsigned != expected:
        _fail("FR0010_QUALIFICATION_RECORD")
    return value


def _verify_activation(
    repo: Path,
    repair_commit: str,
    qualification_commit: str,
    commit: str,
    *,
    plan: dict[str, Any],
    protocol: Any,
) -> dict[str, Any]:
    _verify_commit_identity(
        repo,
        commit,
        parent=qualification_commit,
        subject=ACTIVATION_SUBJECT,
    )
    if _changed_statuses(repo, qualification_commit, commit) != dict(
        sorted(ACTIVATION_STATUSES.items())
    ):
        _fail("FR0010_ACTIVATION_DIFF")
    for path in (
        *CORE_PATHS,
        PLAN_PATH,
        QUALIFICATION_PATH,
        *QUALIFICATION_EVIDENCE_PATHS,
    ):
        if _tree_entry(repo, commit, path) != _tree_entry(
            repo, qualification_commit, path
        ):
            _fail("FR0010_ACTIVATION_DRIFT:" + path)
    hosted = {
        "qualification_ci": _validate_hosted_lane(
            repo,
            commit,
            repair_commit=repair_commit,
            workflow="ci",
            subject_commit=qualification_commit,
            paths=QUALIFICATION_CI_PATHS,
            protocol=protocol,
        ),
        "qualification_formal": _validate_hosted_lane(
            repo,
            commit,
            repair_commit=repair_commit,
            workflow="formal",
            subject_commit=qualification_commit,
            paths=QUALIFICATION_FORMAL_PATHS,
            protocol=protocol,
        ),
    }
    branch_protection = _verify_branch_protection(
        repo, commit, qualification_commit
    )
    expected = {
        "schema_version": "1.0.0",
        "recovery_id": RECOVERY_ID,
        "stage": "ACTIVATION",
        "state_before": "QUALIFIED_PENDING_ACTIVATION",
        "state_after": "ACTIVE",
        "repair_commit": repair_commit,
        "qualification_commit": qualification_commit,
        "plan_record": file_record(repo, repair_commit, PLAN_PATH),
        "qualification_record": file_record(
            repo, qualification_commit, QUALIFICATION_PATH
        ),
        "evidence_catalog": _evidence_catalog(
            repo, commit, ACTIVATION_EVIDENCE_PATHS
        ),
        "hosted_evidence": hosted,
        "branch_protection": branch_protection,
        "authority": _authority("ACTIVE"),
        "limitations": plan["limitations"],
    }
    value, _payload = _read_json(repo, commit, ACTIVATION_PATH)
    unsigned = _verify_stage_signature(repo, value, namespace=ACTIVATION_NAMESPACE)
    if unsigned != expected:
        _fail("FR0010_ACTIVATION_RECORD")
    return value


def _verify_successors(
    repo: Path,
    chain: list[str],
    *,
    activation_commit: str,
) -> None:
    previous = activation_commit
    for commit in chain[chain.index(activation_commit) + 1 :]:
        _verify_commit_identity(repo, commit, parent=previous, subject=None)
        statuses = _changed_statuses(repo, previous, commit)
        if (
            not statuses
            or len(statuses) > MAX_SUCCESSOR_PATHS
            or set(statuses) & PROTECTED_AFTER_ACTIVATION
        ):
            _fail("FR0010_SUCCESSOR_SCOPE")
        previous = commit


def _verify_worktree(repo: Path, commit: str, paths: Sequence[str]) -> None:
    for path in paths:
        target = repo / path
        try:
            metadata = target.lstat()
            payload = target.read_bytes()
        except OSError:
            _fail("FR0010_WORKTREE:" + path)
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or payload != _file(repo, commit, path, MAX_GIT_BYTES)
        ):
            _fail("FR0010_WORKTREE:" + path)


def verify(repo: Path) -> dict[str, Any]:
    """Verify the current first-parent epoch-11 state."""

    _verify_legacy_boundary(repo)
    head = _git(repo, "rev-parse", "--verify", "HEAD^{commit}").decode().strip()
    ancestor = subprocess.run(
        (
            "/usr/bin/git",
            "-c",
            "core.hooksPath=/dev/null",
            "merge-base",
            "--is-ancestor",
            PARENT,
            head,
        ),
        cwd=repo,
        env=_git_environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=30,
    )
    if (
        ancestor.returncode != 0
        or ancestor.stdout
        or ancestor.stderr
    ):
        _fail("FR0010_PARENT_ANCESTRY")
    chain = (
        _git(
            repo,
            "rev-list",
            "--first-parent",
            "--reverse",
            f"{PARENT}..{head}",
        )
        .decode("ascii")
        .splitlines()
    )
    if not chain:
        _fail("FR0010_REPAIR_MISSING")
    repair_commit = chain[0]
    plan = _verify_repair(repo, repair_commit)
    protocol = _load_protocol_module(repo, repair_commit)
    state = "PENDING_QUALIFICATION"
    qualification_commit: str | None = None
    activation_commit: str | None = None
    if len(chain) >= 2:
        qualification_commit = chain[1]
        _verify_qualification(
            repo,
            repair_commit,
            qualification_commit,
            plan=plan,
            protocol=protocol,
        )
        state = "QUALIFIED_PENDING_ACTIVATION"
    if len(chain) >= 3:
        activation_commit = chain[2]
        _verify_activation(
            repo,
            repair_commit,
            qualification_commit,
            activation_commit,
            plan=plan,
            protocol=protocol,
        )
        state = "ACTIVE"
        _verify_successors(
            repo, chain, activation_commit=activation_commit
        )
    if len(chain) > 1 and qualification_commit is None:
        _fail("FR0010_SUCCESSOR_BEFORE_QUALIFICATION")
    if len(chain) > 2 and activation_commit is None:
        _fail("FR0010_SUCCESSOR_BEFORE_ACTIVATION")
    worktree_paths: list[str] = [
        *CORE_PATHS,
        PLAN_PATH,
        ALLOWED_SIGNERS_PATH,
        "tools/release/verify-current-audit.py",
        "tools/release/test_verify_current_audit_fr_0009.py",
    ]
    if qualification_commit is not None:
        worktree_paths.extend((QUALIFICATION_PATH, *QUALIFICATION_EVIDENCE_PATHS))
    if activation_commit is not None:
        worktree_paths.extend((ACTIVATION_PATH, *ACTIVATION_EVIDENCE_PATHS))
    _verify_worktree(repo, head, sorted(set(worktree_paths)))
    return {
        "head": head,
        "repair_commit": repair_commit,
        "qualification_commit": qualification_commit,
        "activation_commit": activation_commit,
        "state": state,
        "authority": _authority(state),
    }


def _repo() -> Path:
    completed = subprocess.run(
        ("/usr/bin/git", "rev-parse", "--show-toplevel"),
        cwd=Path.cwd(),
        env=_git_environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=30,
    )
    if completed.returncode != 0:
        _fail("FR0010_REPOSITORY")
    try:
        return Path(completed.stdout.decode("utf-8").strip()).resolve(strict=True)
    except (OSError, UnicodeDecodeError):
        _fail("FR0010_REPOSITORY")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--print-expected-plan",
        metavar="REPAIR_COMMIT",
        help="print the unsigned canonical plan for a provisional repair commit",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        repo = _repo()
        if arguments.print_expected_plan:
            print(
                canonical_json_bytes(
                    expected_plan(repo, arguments.print_expected_plan)
                ).decode("utf-8"),
                end="",
            )
            return 0
        result = verify(repo)
    except (
        BridgeError,
        OSError,
        UnicodeDecodeError,
        subprocess.TimeoutExpired,
    ) as error:
        print(f"verify-framework-recovery-fr-0010: {error}", file=sys.stderr)
        return 1
    print(
        "verify-framework-recovery-fr-0010: OK "
        f"({result['state']}; epoch 11; release NO_GO)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
