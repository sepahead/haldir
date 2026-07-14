#!/usr/bin/env python3
"""Generate and verify exact-attempt release-task evidence.

Review prose lives in a signed, commit-sourced specification.  All other
fields are derived from two cryptographically verified Git commits, exact
GitHub Actions attempt metadata, and an online coverage-validated log archive.
The retained canonical payload contains each job's complete aggregate and
system logs; redundant per-step ZIP copies are validated but not retained.
Generated records are supplemental: historical closure artifacts are never
overwritten.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import secrets
import stat
import subprocess
import sys
import tempfile
import threading
import tomllib
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any, Callable


REPOSITORY = "sepahead/haldir"
AUTHOR = "Sepehr Mahmoudian <sepmhn@gmail.com>"
SIGNER_PRINCIPAL = "sepmhn@gmail.com"
SIGNER_FINGERPRINT = "SHA256:3gaatfl4IVnuBX4D60Jxw9oVIrvEE1ZphK8IuEyrfPU"
SIGNER_KEY_TYPE = "ED25519"
ALLOWED_SIGNERS = (
    b"sepmhn@gmail.com ssh-ed25519 "
    b"AAAAC3NzaC1lZDI1NTE5AAAAIDuKh9+1+qdjbO6MP/NHD/ai3JtumsKPiz2KBx3lQwLI\n"
)

GENERATOR_PATH = "tools/release/generate-task-evidence.py"
VERIFIER_PATH = "tools/release/verify-task-evidence.py"
ALLOWED_SIGNERS_PATH = "release/0.9.0/allowed-signers"
SPEC_DIRECTORY = "release/0.9.0/evidence-specs"
EVIDENCE_DIRECTORY = "release/0.9.0/evidence"

MAX_SPEC_BYTES = 128 * 1024
MAX_RECORD_BYTES = 512 * 1024
MAX_METADATA_BYTES = 2 * 1024 * 1024
MAX_ARCHIVE_BYTES = 4 * 1024 * 1024
MAX_LOG_BYTES = 8 * 1024 * 1024
MAX_GIT_BYTES = 4 * 1024 * 1024
MAX_STDERR_BYTES = 512 * 1024
MAX_ARCHIVE_ENTRIES = 1024
COMMAND_TIMEOUT_SECONDS = 300

HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
TASK_ID = re.compile(r"^T[0-9]{3}$")
SAFE_JOB_NAME = re.compile(r"^[A-Za-z0-9_.-]+$")

EXPECTED_SPEC_FIELDS = {
    "schema_version",
    "task_id",
    "requirement_id",
    "verification_scope",
    "review",
    "residual_risks",
    "implementation_artifacts",
    "github",
}
EXPECTED_SCOPE_FIELDS = {
    "positive",
    "negative",
    "boundary",
    "adversarial",
    "regression",
    "metamorphic",
}
EXPECTED_REVIEW_FIELDS = {
    "self_reviewed_by",
    "independent_reviewer",
    "independent_review_required_for_task",
    "independent_release_review_deferred_to",
}
EXPECTED_GITHUB_FIELDS = {"repository", "event", "branch", "ci", "formal"}
EXPECTED_WORKFLOW_FIELDS = {
    "workflow_name",
    "workflow_path",
    "workflow_id",
    "expected_jobs",
    "required_steps_by_job",
    "marker_job",
    "marker_step",
    "success_marker",
}
EXPECTED_RECORD_FIELDS = {
    "schema_version",
    "task_id",
    "requirement_id",
    "status",
    "generated_by",
    "evidence_tool",
    "implementation",
    "implementation_artifacts",
    "inputs",
    "github_ci",
    "github_formal",
    "verification_scope",
    "review",
    "residual_risks",
}
EXPECTED_RUN_FIELDS = {
    "run_id",
    "attempt",
    "repository",
    "url",
    "api_url",
    "workflow_name",
    "workflow_path",
    "workflow_id",
    "event",
    "head_branch",
    "head_sha",
    "status",
    "conclusion",
    "jobs",
    "log",
}
EXPECTED_LOG_FIELDS = {
    "path",
    "format",
    "compression",
    "gzip_timestamp",
    "compressed_sha256",
    "compressed_bytes",
    "uncompressed_sha256",
    "uncompressed_bytes",
    "uncompressed_lines",
    "logical_entries",
}


class EvidenceGenerationError(ValueError):
    """An input cannot produce valid deterministic release evidence."""


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _require_hex(value: Any, pattern: re.Pattern[str], label: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise EvidenceGenerationError(f"EVIDENCE_INVALID_HEX:{label}")
    return value


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceGenerationError(f"EVIDENCE_JSON_DUPLICATE_KEY:{key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise EvidenceGenerationError(f"EVIDENCE_JSON_NONFINITE:{value}")


def _load_json_bytes(payload: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            payload,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_json_constant,
        )
    except EvidenceGenerationError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise EvidenceGenerationError(f"EVIDENCE_JSON_INVALID:{label}") from error
    if not isinstance(value, dict):
        raise EvidenceGenerationError(f"EVIDENCE_JSON_NOT_OBJECT:{label}")
    return value


def _canonical_json_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False)
        + "\n"
    ).encode("utf-8")


def _read_bounded(path: Path, limit: int, label: str) -> bytes:
    try:
        with path.open("rb") as handle:
            payload = handle.read(limit + 1)
    except OSError as error:
        raise EvidenceGenerationError(f"EVIDENCE_READ_FAILED:{label}") from error
    if len(payload) > limit:
        raise EvidenceGenerationError(f"EVIDENCE_RESOURCE_BOUND:{label}")
    return payload


def _regular_repo_file(repo: Path, relative: str, *, must_exist: bool = True) -> Path:
    pure = PurePosixPath(relative)
    if (
        pure.is_absolute()
        or not pure.parts
        or any(part in {"", ".", ".."} for part in pure.parts)
        or "\\" in relative
    ):
        raise EvidenceGenerationError("EVIDENCE_PATH_INVALID")
    root = repo.resolve(strict=True)
    current = root
    for part in pure.parts:
        current = current / part
        if not current.exists() and not current.is_symlink():
            if must_exist and part == pure.parts[-1]:
                raise EvidenceGenerationError("EVIDENCE_PATH_MISSING")
            continue
        try:
            mode = current.lstat().st_mode
        except OSError as error:
            raise EvidenceGenerationError("EVIDENCE_PATH_STAT_FAILED") from error
        if stat.S_ISLNK(mode):
            raise EvidenceGenerationError("EVIDENCE_PATH_SYMLINK")
    if must_exist:
        try:
            mode = current.lstat().st_mode
        except OSError as error:
            raise EvidenceGenerationError("EVIDENCE_PATH_STAT_FAILED") from error
        if not stat.S_ISREG(mode):
            raise EvidenceGenerationError("EVIDENCE_PATH_NOT_REGULAR")
    if not current.resolve(strict=False).is_relative_to(root):
        raise EvidenceGenerationError("EVIDENCE_PATH_ESCAPE")
    return current


def _run_bounded(
    arguments: list[str],
    cwd: Path,
    stdout_limit: int,
    label: str,
    *,
    stderr_limit: int = MAX_STDERR_BYTES,
) -> tuple[bytes, bytes]:
    """Run a command while draining both pipes with hard in-memory bounds."""

    try:
        process = subprocess.Popen(
            arguments,
            cwd=cwd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as error:
        raise EvidenceGenerationError(f"EVIDENCE_COMMAND_FAILED:{label}") from error
    assert process.stdout is not None and process.stderr is not None
    output = bytearray()
    errors = bytearray()
    overflow: list[str] = []

    def drain(stream: Any, destination: bytearray, limit: int, stream_name: str) -> None:
        while True:
            chunk = stream.read(64 * 1024)
            if not chunk:
                return
            if len(destination) + len(chunk) > limit:
                overflow.append(stream_name)
                try:
                    process.kill()
                except OSError:
                    pass
                return
            destination.extend(chunk)

    threads = [
        threading.Thread(target=drain, args=(process.stdout, output, stdout_limit, "stdout")),
        threading.Thread(target=drain, args=(process.stderr, errors, stderr_limit, "stderr")),
    ]
    for thread in threads:
        thread.start()
    try:
        return_code = process.wait(timeout=COMMAND_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired as error:
        process.kill()
        process.wait()
        for thread in threads:
            thread.join()
        process.stdout.close()
        process.stderr.close()
        raise EvidenceGenerationError(f"EVIDENCE_COMMAND_TIMEOUT:{label}") from error
    for thread in threads:
        thread.join()
    process.stdout.close()
    process.stderr.close()
    if overflow:
        raise EvidenceGenerationError(f"EVIDENCE_RESOURCE_BOUND:{label}:{overflow[0]}")
    if return_code != 0:
        raise EvidenceGenerationError(f"EVIDENCE_COMMAND_FAILED:{label}")
    return bytes(output), bytes(errors)


def _git(repo: Path, *arguments: str, limit: int = MAX_GIT_BYTES) -> bytes:
    return _run_bounded(["git", *arguments], repo, limit, "git")[0]


def _git_blob_info(repo: Path, commit: str, path: str) -> tuple[str, str, bytes]:
    listing = _git(repo, "ls-tree", "-z", commit, "--", path)
    records = [record for record in listing.split(b"\0") if record]
    if len(records) != 1:
        raise EvidenceGenerationError(f"EVIDENCE_GIT_BLOB_MISSING:{path}")
    try:
        metadata, observed_path = records[0].split(b"\t", 1)
        mode, object_type, object_id = metadata.decode("ascii").split(" ")
        decoded_path = observed_path.decode("utf-8")
    except (ValueError, UnicodeDecodeError) as error:
        raise EvidenceGenerationError(f"EVIDENCE_GIT_BLOB_INVALID:{path}") from error
    if (
        decoded_path != path
        or object_type != "blob"
        or mode not in {"100644", "100755"}
        or HEX40.fullmatch(object_id) is None
    ):
        raise EvidenceGenerationError(f"EVIDENCE_GIT_BLOB_INVALID:{path}")
    return mode, object_id, _git(repo, "cat-file", "blob", object_id)


def _git_blob(repo: Path, commit: str, path: str) -> bytes:
    return _git_blob_info(repo, commit, path)[2]


def _commit_identity(repo: Path, commit: str) -> tuple[str, str, str]:
    _require_hex(commit, HEX40, "commit")
    tree = _git(repo, "rev-parse", f"{commit}^{{tree}}").decode("ascii").strip()
    _require_hex(tree, HEX40, "tree")
    identities = _git(
        repo,
        "show",
        "-s",
        "--format=%an <%ae>%n%cn <%ce>",
        commit,
    ).decode("utf-8").splitlines()
    if identities != [AUTHOR, AUTHOR]:
        raise EvidenceGenerationError("EVIDENCE_COMMIT_IDENTITY_INVALID")
    return tree, identities[0], identities[1]


def _verify_signed_commit(repo: Path, commit: str, allowed_signers: bytes) -> dict[str, str]:
    if allowed_signers != ALLOWED_SIGNERS:
        raise EvidenceGenerationError("EVIDENCE_ALLOWED_SIGNERS_INVALID")
    descriptor, path = tempfile.mkstemp(prefix="haldir-allowed-signers-")
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(allowed_signers)
            handle.flush()
            os.fsync(handle.fileno())
        stdout, stderr = _run_bounded(
            [
                "git",
                "-c",
                "gpg.format=ssh",
                "-c",
                f"gpg.ssh.allowedSignersFile={path}",
                "verify-commit",
                "--raw",
                commit,
            ],
            repo,
            64 * 1024,
            "verify_commit",
            stderr_limit=64 * 1024,
        )
    finally:
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
    verification = (stdout + stderr).decode("utf-8", "strict")
    expected = (
        f'Good "git" signature for {SIGNER_PRINCIPAL} with '
        f"{SIGNER_KEY_TYPE} key {SIGNER_FINGERPRINT}"
    )
    if expected not in verification:
        raise EvidenceGenerationError("EVIDENCE_COMMIT_SIGNER_INVALID")
    return {
        "format": "ssh",
        "principal": SIGNER_PRINCIPAL,
        "key_type": SIGNER_KEY_TYPE,
        "fingerprint": SIGNER_FINGERPRINT,
    }


def _commit_record(repo: Path, commit: str, allowed_signers: bytes) -> dict[str, Any]:
    tree, author, committer = _commit_identity(repo, commit)
    return {
        "commit": commit,
        "tree": tree,
        "author": author,
        "committer": committer,
        "signature": _verify_signed_commit(repo, commit, allowed_signers),
    }


def _require_ancestor(repo: Path, ancestor: str, descendant: str) -> None:
    try:
        _run_bounded(
            ["git", "merge-base", "--is-ancestor", ancestor, descendant],
            repo,
            1024,
            "commit_ancestry",
            stderr_limit=16 * 1024,
        )
    except EvidenceGenerationError as error:
        raise EvidenceGenerationError("EVIDENCE_TOOL_HISTORY_INVALID") from error


def _validate_nonempty_strings(value: Any, fields: set[str], label: str) -> None:
    if (
        not isinstance(value, dict)
        or set(value) != fields
        or any(
            not isinstance(item, str) or not item.strip()
            for item in value.values()
        )
    ):
        raise EvidenceGenerationError(f"EVIDENCE_SPEC_{label}_INVALID")


def load_spec_bytes(payload: bytes) -> dict[str, Any]:
    spec = _load_json_bytes(payload, "spec")
    if set(spec) != EXPECTED_SPEC_FIELDS:
        raise EvidenceGenerationError("EVIDENCE_SPEC_FIELDS_INVALID")
    task_id = spec.get("task_id")
    if (
        spec.get("schema_version") != "2.0.0"
        or not isinstance(task_id, str)
        or TASK_ID.fullmatch(task_id) is None
        or spec.get("requirement_id") != f"HALDIR-0.9-{task_id}"
    ):
        raise EvidenceGenerationError("EVIDENCE_SPEC_IDENTITY_INVALID")
    _validate_nonempty_strings(
        spec.get("verification_scope"), EXPECTED_SCOPE_FIELDS, "VERIFICATION_SCOPE"
    )
    _validate_nonempty_strings(spec.get("review"), EXPECTED_REVIEW_FIELDS, "REVIEW")
    risks = spec.get("residual_risks")
    if (
        not isinstance(risks, list)
        or not risks
        or len(set(risks)) != len(risks)
        or any(not isinstance(risk, str) or not risk.strip() for risk in risks)
    ):
        raise EvidenceGenerationError("EVIDENCE_SPEC_RESIDUAL_RISKS_INVALID")
    artifacts = spec.get("implementation_artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise EvidenceGenerationError("EVIDENCE_SPEC_ARTIFACTS_INVALID")
    artifact_paths: list[str] = []
    for artifact in artifacts:
        if (
            not isinstance(artifact, dict)
            or set(artifact) != {"path", "worktree_policy"}
            or not isinstance(artifact.get("path"), str)
            or artifact.get("worktree_policy") not in {"MUST_MATCH", "MAY_EVOLVE"}
        ):
            raise EvidenceGenerationError("EVIDENCE_SPEC_ARTIFACT_INVALID")
        path = artifact["path"]
        pure = PurePosixPath(path)
        if (
            pure.is_absolute()
            or not pure.parts
            or any(part in {"", ".", ".."} for part in pure.parts)
            or "\\" in path
        ):
            raise EvidenceGenerationError("EVIDENCE_SPEC_ARTIFACT_PATH_INVALID")
        artifact_paths.append(path)
    if artifact_paths != sorted(artifact_paths) or len(set(artifact_paths)) != len(artifact_paths):
        raise EvidenceGenerationError("EVIDENCE_SPEC_ARTIFACT_ORDER_INVALID")
    github = spec.get("github")
    if not isinstance(github, dict) or set(github) != EXPECTED_GITHUB_FIELDS:
        raise EvidenceGenerationError("EVIDENCE_SPEC_GITHUB_INVALID")
    if (
        github.get("repository") != REPOSITORY
        or github.get("event") != "push"
        or github.get("branch") != "main"
    ):
        raise EvidenceGenerationError("EVIDENCE_SPEC_GITHUB_SCOPE_INVALID")
    for kind, expected_name, expected_path in (
        ("ci", "ci", ".github/workflows/ci.yml"),
        ("formal", "formal", ".github/workflows/formal.yml"),
    ):
        workflow = github.get(kind)
        if not isinstance(workflow, dict) or set(workflow) != EXPECTED_WORKFLOW_FIELDS:
            raise EvidenceGenerationError("EVIDENCE_SPEC_WORKFLOW_FIELDS_INVALID")
        jobs = workflow.get("expected_jobs")
        required_steps = workflow.get("required_steps_by_job")
        if (
            workflow.get("workflow_name") != expected_name
            or workflow.get("workflow_path") != expected_path
            or isinstance(workflow.get("workflow_id"), bool)
            or not isinstance(workflow.get("workflow_id"), int)
            or workflow["workflow_id"] <= 0
            or not isinstance(jobs, list)
            or not jobs
            or jobs != sorted(jobs)
            or len(set(jobs)) != len(jobs)
            or any(
                not isinstance(job, str) or SAFE_JOB_NAME.fullmatch(job) is None
                for job in jobs
            )
            or not isinstance(required_steps, dict)
            or set(required_steps) != set(jobs or [])
            or any(
                not isinstance(steps, list)
                or not steps
                or steps != sorted(steps)
                or len(set(steps)) != len(steps)
                or any(not isinstance(step, str) or not step.strip() for step in steps)
                for steps in required_steps.values()
            )
            or workflow.get("marker_job") not in jobs
            or not isinstance(workflow.get("marker_step"), str)
            or not workflow["marker_step"].strip()
            or not isinstance(workflow.get("success_marker"), str)
            or not workflow["success_marker"].strip()
            or "\n" in workflow["success_marker"]
            or "\r" in workflow["success_marker"]
        ):
            raise EvidenceGenerationError("EVIDENCE_SPEC_WORKFLOW_INVALID")
    return spec


def load_spec(path: Path) -> dict[str, Any]:
    return load_spec_bytes(_read_bounded(path, MAX_SPEC_BYTES, "spec"))


def canonical_gzip(payload: bytes) -> bytes:
    """Return a cross-runtime canonical RFC 1952 member using stored blocks."""

    blocks = bytearray()
    if not payload:
        blocks.extend(b"\x01\x00\x00\xff\xff")
    else:
        offset = 0
        while offset < len(payload):
            chunk = payload[offset : offset + 65535]
            offset += len(chunk)
            blocks.append(1 if offset == len(payload) else 0)
            length = len(chunk)
            blocks.extend(length.to_bytes(2, "little"))
            blocks.extend((length ^ 0xFFFF).to_bytes(2, "little"))
            blocks.extend(chunk)
    header = b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff"
    trailer = (
        binascii.crc32(payload).to_bytes(4, "little")
        + (len(payload) & 0xFFFFFFFF).to_bytes(4, "little")
    )
    return header + bytes(blocks) + trailer


def decode_canonical_gzip(payload: bytes, limit: int = MAX_LOG_BYTES) -> bytes:
    if len(payload) < 23 or payload[:10] != b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff":
        raise EvidenceGenerationError("EVIDENCE_GZIP_HEADER_INVALID")
    cursor = 10
    output = bytearray()
    final = False
    while not final:
        if cursor + 5 > len(payload) - 8:
            raise EvidenceGenerationError("EVIDENCE_GZIP_TRUNCATED")
        header = payload[cursor]
        cursor += 1
        if header not in {0, 1}:
            raise EvidenceGenerationError("EVIDENCE_GZIP_DEFLATE_NONCANONICAL")
        final = header == 1
        length = int.from_bytes(payload[cursor : cursor + 2], "little")
        inverse = int.from_bytes(payload[cursor + 2 : cursor + 4], "little")
        cursor += 4
        if inverse != (length ^ 0xFFFF) or cursor + length > len(payload) - 8:
            raise EvidenceGenerationError("EVIDENCE_GZIP_BLOCK_INVALID")
        if len(output) + length > limit:
            raise EvidenceGenerationError("EVIDENCE_RESOURCE_BOUND:gzip")
        output.extend(payload[cursor : cursor + length])
        cursor += length
    if cursor + 8 != len(payload):
        raise EvidenceGenerationError("EVIDENCE_GZIP_TRAILING_DATA")
    expected_crc = int.from_bytes(payload[cursor : cursor + 4], "little")
    expected_size = int.from_bytes(payload[cursor + 4 :], "little")
    if (
        binascii.crc32(output) != expected_crc
        or (len(output) & 0xFFFFFFFF) != expected_size
        or canonical_gzip(bytes(output)) != payload
    ):
        raise EvidenceGenerationError("EVIDENCE_GZIP_INTEGRITY_INVALID")
    return bytes(output)


def _canonical_log_payload(entries: dict[str, bytes]) -> bytes:
    document = {
        "schema_version": "1.0.0",
        "entries": [
            {
                "path": name,
                "bytes": len(entries[name]),
                "sha256": _sha256(entries[name]),
                "content_base64": base64.b64encode(entries[name]).decode("ascii"),
            }
            for name in sorted(entries)
        ],
    }
    payload = _canonical_json_bytes(document)
    if len(payload) > MAX_LOG_BYTES:
        raise EvidenceGenerationError("EVIDENCE_RESOURCE_BOUND:canonical_log")
    return payload


def _read_log_zip_entries(archive: bytes) -> dict[str, bytes]:
    if len(archive) > MAX_ARCHIVE_BYTES:
        raise EvidenceGenerationError("EVIDENCE_RESOURCE_BOUND:github_log_zip")
    entries: dict[str, bytes] = {}
    try:
        with zipfile.ZipFile(__import__("io").BytesIO(archive), "r") as bundle:
            infos = bundle.infolist()
            if not infos or len(infos) > MAX_ARCHIVE_ENTRIES:
                raise EvidenceGenerationError("EVIDENCE_LOG_ARCHIVE_ENTRY_COUNT_INVALID")
            total = 0
            for info in infos:
                name = info.filename
                pure = PurePosixPath(name)
                mode = (info.external_attr >> 16) & 0xFFFF
                if (
                    info.is_dir()
                    or not name
                    or "\\" in name
                    or "\x00" in name
                    or pure.is_absolute()
                    or any(part in {"", ".", ".."} for part in pure.parts)
                    or name in entries
                    or info.flag_bits & 0x1
                    or info.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
                    or (mode and stat.S_ISLNK(mode))
                ):
                    raise EvidenceGenerationError("EVIDENCE_LOG_ARCHIVE_ENTRY_INVALID")
                total += info.file_size
                if total > MAX_LOG_BYTES:
                    raise EvidenceGenerationError("EVIDENCE_RESOURCE_BOUND:github_logs")
                data = bundle.read(info)
                if len(data) != info.file_size:
                    raise EvidenceGenerationError("EVIDENCE_LOG_ARCHIVE_SIZE_MISMATCH")
                entries[name] = data
    except EvidenceGenerationError:
        raise
    except (OSError, zipfile.BadZipFile, RuntimeError, NotImplementedError) as error:
        raise EvidenceGenerationError("EVIDENCE_LOG_ARCHIVE_INVALID") from error
    return entries


def _canonicalize_log_zip(archive: bytes) -> tuple[bytes, dict[str, bytes]]:
    """Test/helper representation of every source ZIP entry.

    Generation uses :func:`_read_log_zip_entries` directly so GitHub's optional
    redundant per-step copies cannot impose a layout-dependent JSON size bound.
    """

    entries = _read_log_zip_entries(archive)
    return _canonical_log_payload(entries), entries


def _parse_canonical_log(payload: bytes) -> dict[str, bytes]:
    document = _load_json_bytes(payload, "canonical_log")
    if set(document) != {"schema_version", "entries"} or document.get("schema_version") != "1.0.0":
        raise EvidenceGenerationError("EVIDENCE_CANONICAL_LOG_FIELDS_INVALID")
    values = document.get("entries")
    if not isinstance(values, list) or not values or len(values) > MAX_ARCHIVE_ENTRIES:
        raise EvidenceGenerationError("EVIDENCE_CANONICAL_LOG_ENTRIES_INVALID")
    entries: dict[str, bytes] = {}
    observed_order: list[str] = []
    total = 0
    for value in values:
        if not isinstance(value, dict) or set(value) != {
            "path", "bytes", "sha256", "content_base64"
        }:
            raise EvidenceGenerationError("EVIDENCE_CANONICAL_LOG_ENTRY_INVALID")
        name = value.get("path")
        if not isinstance(name, str) or name in entries:
            raise EvidenceGenerationError("EVIDENCE_CANONICAL_LOG_PATH_INVALID")
        try:
            data = base64.b64decode(value.get("content_base64"), validate=True)
        except (TypeError, ValueError, binascii.Error) as error:
            raise EvidenceGenerationError("EVIDENCE_CANONICAL_LOG_BASE64_INVALID") from error
        if (
            not isinstance(value.get("bytes"), int)
            or isinstance(value.get("bytes"), bool)
            or value["bytes"] != len(data)
            or _require_hex(value.get("sha256"), HEX64, "log_entry.sha256") != _sha256(data)
        ):
            raise EvidenceGenerationError("EVIDENCE_CANONICAL_LOG_DIGEST_INVALID")
        total += len(data)
        if total > MAX_LOG_BYTES:
            raise EvidenceGenerationError("EVIDENCE_RESOURCE_BOUND:canonical_entries")
        entries[name] = data
        observed_order.append(name)
    if observed_order != sorted(observed_order) or _canonical_json_bytes(document) != payload:
        raise EvidenceGenerationError("EVIDENCE_CANONICAL_LOG_NONCANONICAL")
    return entries


def _gh_api(path: str, repo: Path, limit: int, label: str) -> bytes:
    return _run_bounded(
        ["gh", "api", "--hostname", "github.com", path], repo, limit, label
    )[0]


def _gh_run(repo: Path, run_id: int, attempt: int) -> tuple[dict[str, Any], dict[str, Any], bytes]:
    base = f"repos/{REPOSITORY}/actions/runs/{run_id}/attempts/{attempt}"
    run = _load_json_bytes(_gh_api(base, repo, MAX_METADATA_BYTES, "github_run"), "github_run")
    jobs = _load_json_bytes(
        _gh_api(f"{base}/jobs?per_page=100", repo, MAX_METADATA_BYTES, "github_jobs"),
        "github_jobs",
    )
    archive = _gh_api(f"{base}/logs", repo, MAX_ARCHIVE_BYTES, "github_logs")
    return run, jobs, archive


def _normalize_jobs(jobs_metadata: dict[str, Any], expected_jobs: list[str]) -> list[dict[str, Any]]:
    jobs = jobs_metadata.get("jobs")
    total = jobs_metadata.get("total_count")
    if (
        not isinstance(jobs, list)
        or isinstance(total, bool)
        or not isinstance(total, int)
        or total != len(jobs)
        or total > 100
    ):
        raise EvidenceGenerationError("EVIDENCE_RUN_JOBS_INVALID")
    normalized: list[dict[str, Any]] = []
    for job in jobs:
        if not isinstance(job, dict):
            raise EvidenceGenerationError("EVIDENCE_RUN_JOB_INVALID")
        steps = job.get("steps")
        if not isinstance(steps, list) or not steps:
            raise EvidenceGenerationError("EVIDENCE_RUN_JOB_STEPS_INVALID")
        normalized_steps: list[dict[str, Any]] = []
        for step in steps:
            if (
                not isinstance(step, dict)
                or isinstance(step.get("number"), bool)
                or not isinstance(step.get("number"), int)
                or step["number"] <= 0
                or not isinstance(step.get("name"), str)
                or not step["name"].strip()
                or step.get("status") != "completed"
                or step.get("conclusion") != "success"
            ):
                raise EvidenceGenerationError("EVIDENCE_RUN_STEP_INVALID")
            normalized_steps.append(
                {
                    "number": step["number"],
                    "name": step["name"],
                    "status": "completed",
                    "conclusion": "success",
                }
            )
        if len({step["number"] for step in normalized_steps}) != len(normalized_steps):
            raise EvidenceGenerationError("EVIDENCE_RUN_STEP_DUPLICATE")
        if (
            isinstance(job.get("id"), bool)
            or not isinstance(job.get("id"), int)
            or job["id"] <= 0
            or not isinstance(job.get("name"), str)
            or job.get("status") != "completed"
            or job.get("conclusion") != "success"
        ):
            raise EvidenceGenerationError("EVIDENCE_RUN_JOB_INVALID")
        normalized.append(
            {
                "job_id": job["id"],
                "name": job["name"],
                "status": "completed",
                "conclusion": "success",
                "steps": sorted(normalized_steps, key=lambda step: step["number"]),
            }
        )
    normalized.sort(key=lambda job: job["name"])
    if [job["name"] for job in normalized] != expected_jobs:
        raise EvidenceGenerationError("EVIDENCE_RUN_JOB_SET_INVALID")
    if len({job["job_id"] for job in normalized}) != len(normalized):
        raise EvidenceGenerationError("EVIDENCE_RUN_JOB_DUPLICATE")
    return normalized


def _is_github_generated_step(name: str) -> bool:
    return (
        name in {"Set up job", "Complete job"}
        or name.startswith("Post ")
        or re.fullmatch(r"Run actions/checkout@[0-9a-f]{40}", name) is not None
        or re.fullmatch(r"Build [A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}", name)
        is not None
    )


def _validate_required_steps(jobs: list[dict[str, Any]], workflow: dict[str, Any]) -> None:
    required_by_job = workflow["required_steps_by_job"]
    for job in jobs:
        actual = [step["name"] for step in job["steps"]]
        if len(set(actual)) != len(actual):
            raise EvidenceGenerationError("EVIDENCE_RUN_STEP_NAME_DUPLICATE")
        required = required_by_job[job["name"]]
        non_generated = sorted(name for name in actual if not _is_github_generated_step(name))
        if non_generated != required:
            raise EvidenceGenerationError("EVIDENCE_RUN_REQUIRED_STEP_SET_INVALID")


def _validate_log_coverage(
    entries: dict[str, bytes], jobs: list[dict[str, Any]], workflow: dict[str, Any]
) -> None:
    covered: set[str] = set()
    aggregate_indices: set[int] = set()
    marker_entry: bytes | None = None
    for job in jobs:
        name = job["name"]
        pattern = re.compile(rf"^([0-9]+)_{re.escape(name)}\.txt$")
        combined = [path for path in entries if pattern.fullmatch(path) is not None]
        system = f"{name}/system.txt"
        if len(combined) != 1 or system not in entries:
            raise EvidenceGenerationError("EVIDENCE_LOG_JOB_COVERAGE_INVALID")
        match = pattern.fullmatch(combined[0])
        assert match is not None
        aggregate_index = int(match.group(1))
        if aggregate_index in aggregate_indices:
            raise EvidenceGenerationError("EVIDENCE_LOG_JOB_INDEX_DUPLICATE")
        aggregate_indices.add(aggregate_index)
        covered.update({combined[0], system})
        detailed = [
            path for path in entries if path.startswith(f"{name}/") and path != system
        ]
        if detailed:
            for step in job["steps"]:
                prefix = f"{name}/{step['number']}_"
                matches = [path for path in detailed if path.startswith(prefix)]
                if len(matches) != 1:
                    raise EvidenceGenerationError("EVIDENCE_LOG_STEP_COVERAGE_INVALID")
                covered.add(matches[0])
                if (
                    name == workflow["marker_job"]
                    and step["name"] == workflow["marker_step"]
                ):
                    marker_entry = entries[matches[0]]
            if not set(detailed).issubset(covered):
                raise EvidenceGenerationError("EVIDENCE_LOG_UNKNOWN_STEP_ENTRY")
        elif name == workflow["marker_job"]:
            # Older GitHub archives contain the complete aggregate job log plus
            # system log, but no duplicated per-step files.  Exact successful
            # step coverage remains bound by the attempt jobs API above.
            marker_entry = entries[combined[0]]
    if covered != set(entries):
        raise EvidenceGenerationError("EVIDENCE_LOG_UNKNOWN_ENTRY")
    if marker_entry is None or workflow["success_marker"].encode("utf-8") not in marker_entry:
        raise EvidenceGenerationError("EVIDENCE_RUN_LOG_MARKER_MISSING")


def _logical_job_logs(
    entries: dict[str, bytes], jobs: list[dict[str, Any]]
) -> dict[str, bytes]:
    """Normalize GitHub's changing redundant ZIP layouts to logical job logs."""

    logical: dict[str, bytes] = {}
    for job in jobs:
        name = job["name"]
        pattern = re.compile(rf"^[0-9]+_{re.escape(name)}\.txt$")
        combined = [path for path in entries if pattern.fullmatch(path) is not None]
        system = f"{name}/system.txt"
        if len(combined) != 1 or system not in entries:
            raise EvidenceGenerationError("EVIDENCE_LOG_JOB_COVERAGE_INVALID")
        logical[f"{name}/aggregate.log"] = entries[combined[0]]
        logical[f"{name}/system.log"] = entries[system]
    return logical


def _validate_logical_job_logs(
    entries: dict[str, bytes], jobs: list[dict[str, Any]], workflow: dict[str, Any]
) -> None:
    expected = {
        f"{job['name']}/{kind}.log"
        for job in jobs
        for kind in ("aggregate", "system")
    }
    if set(entries) != expected:
        raise EvidenceGenerationError("EVIDENCE_LOGICAL_JOB_LOG_SET_INVALID")
    marker = entries[f"{workflow['marker_job']}/aggregate.log"]
    if workflow["success_marker"].encode("utf-8") not in marker:
        raise EvidenceGenerationError("EVIDENCE_RUN_LOG_MARKER_MISSING")


def _normalize_run(
    run_metadata: dict[str, Any],
    jobs_metadata: dict[str, Any],
    archive: bytes,
    *,
    run_id: int,
    attempt: int,
    expected_commit: str,
    workflow: dict[str, Any],
    github_scope: dict[str, Any],
) -> tuple[dict[str, Any], bytes]:
    if (
        isinstance(run_id, bool)
        or not isinstance(run_id, int)
        or run_id <= 0
        or isinstance(attempt, bool)
        or not isinstance(attempt, int)
        or attempt <= 0
    ):
        raise EvidenceGenerationError("EVIDENCE_RUN_ID_INVALID")
    expected_url = f"https://github.com/{REPOSITORY}/actions/runs/{run_id}/attempts/{attempt}"
    actual_html = run_metadata.get("html_url")
    # GitHub omits /attempts/1 from the canonical first-attempt HTML URL.
    base_html = f"https://github.com/{REPOSITORY}/actions/runs/{run_id}"
    accepted_html = {expected_url, base_html}
    canonical_html = base_html if attempt == 1 else expected_url
    repository = run_metadata.get("repository")
    if (
        isinstance(run_metadata.get("id"), bool)
        or not isinstance(run_metadata.get("id"), int)
        or run_metadata.get("id") != run_id
        or isinstance(run_metadata.get("run_attempt"), bool)
        or not isinstance(run_metadata.get("run_attempt"), int)
        or run_metadata.get("run_attempt") != attempt
        or run_metadata.get("status") != "completed"
        or run_metadata.get("conclusion") != "success"
        or run_metadata.get("head_sha") != expected_commit
        or run_metadata.get("name") != workflow["workflow_name"]
        or run_metadata.get("path") != workflow["workflow_path"]
        or run_metadata.get("event") != github_scope["event"]
        or run_metadata.get("head_branch") != github_scope["branch"]
        or not isinstance(repository, dict)
        or repository.get("full_name") != REPOSITORY
        or actual_html not in accepted_html
        or run_metadata.get("url") != f"https://api.github.com/repos/{REPOSITORY}/actions/runs/{run_id}"
        or run_metadata.get("workflow_id") != workflow["workflow_id"]
    ):
        raise EvidenceGenerationError("EVIDENCE_RUN_METADATA_INVALID")
    jobs = _normalize_jobs(jobs_metadata, workflow["expected_jobs"])
    _validate_required_steps(jobs, workflow)
    entries = _read_log_zip_entries(archive)
    _validate_log_coverage(entries, jobs, workflow)
    logical_entries = _logical_job_logs(entries, jobs)
    _validate_logical_job_logs(logical_entries, jobs, workflow)
    log_payload = _canonical_log_payload(logical_entries)
    return (
        {
            "run_id": run_id,
            "attempt": attempt,
            "repository": REPOSITORY,
            "url": canonical_html,
            "api_url": run_metadata["url"],
            "workflow_name": workflow["workflow_name"],
            "workflow_path": workflow["workflow_path"],
            "workflow_id": workflow["workflow_id"],
            "event": github_scope["event"],
            "head_branch": github_scope["branch"],
            "head_sha": expected_commit,
            "status": "completed",
            "conclusion": "success",
            "jobs": jobs,
        },
        log_payload,
    )


def _source_inputs(repo: Path, commit: str) -> dict[str, Any]:
    audit = _load_json_bytes(
        _git_blob(repo, commit, "release/0.9.0/audit-inputs.json"), "audit_inputs"
    )
    toolchain = _git_blob(repo, commit, "rust-toolchain.toml")
    try:
        parsed_toolchain = tomllib.loads(toolchain.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise EvidenceGenerationError("EVIDENCE_TOOLCHAIN_TOML_INVALID") from error
    toolchain_table = parsed_toolchain.get("toolchain")
    channel = toolchain_table.get("channel") if isinstance(toolchain_table, dict) else None
    ncp = audit.get("ncp")
    if (
        not isinstance(channel, str)
        or not channel
        or not isinstance(ncp, dict)
        or ncp.get("tag") != "v0.8.0"
        or _require_hex(ncp.get("tag_object"), HEX40, "ncp.tag_object")
        != ncp.get("tag_object")
        or _require_hex(ncp.get("commit"), HEX40, "ncp.commit") != ncp.get("commit")
    ):
        raise EvidenceGenerationError("EVIDENCE_SOURCE_INPUT_INVALID")
    return {
        "cargo_lock_sha256": _sha256(_git_blob(repo, commit, "Cargo.lock")),
        "rust_toolchain_sha256": _sha256(toolchain),
        "rustc": channel,
        "ncp_tag": "v0.8.0",
        "ncp_tag_object": ncp["tag_object"],
        "ncp_commit": ncp["commit"],
    }


def _implementation_artifacts(
    repo: Path, commit: str, specifications: list[dict[str, str]]
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for specification in specifications:
        path = specification["path"]
        mode, blob, payload = _git_blob_info(repo, commit, path)
        records.append(
            {
                "path": path,
                "worktree_policy": specification["worktree_policy"],
                "git_mode": mode,
                "git_blob": blob,
                "sha256": _sha256(payload),
                "bytes": len(payload),
            }
        )
    return records


def _atomic_write(path: Path, payload: bytes) -> None:
    parent = path.parent
    parent.mkdir(parents=True, exist_ok=True)
    if parent.is_symlink() or not parent.is_dir():
        raise EvidenceGenerationError("EVIDENCE_OUTPUT_DIRECTORY_INVALID")
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    directory = os.open(parent, flags)
    temporary = f".{path.name}.{secrets.token_hex(12)}.tmp"
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
            dir_fd=directory,
        )
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
        except BaseException:
            try:
                os.unlink(temporary, dir_fd=directory)
            except FileNotFoundError:
                pass
            raise
        os.replace(temporary, path.name, src_dir_fd=directory, dst_dir_fd=directory)
        os.fsync(directory)
    finally:
        os.close(directory)


def _log_record(path: str, uncompressed: bytes, compressed: bytes, entries: int) -> dict[str, Any]:
    return {
        "path": path,
        "format": "github-actions-complete-logical-job-logs-v1",
        "compression": "canonical-gzip-stored-v1",
        "gzip_timestamp": 0,
        "compressed_sha256": _sha256(compressed),
        "compressed_bytes": len(compressed),
        "uncompressed_sha256": _sha256(uncompressed),
        "uncompressed_bytes": len(uncompressed),
        "uncompressed_lines": uncompressed.count(b"\n"),
        "logical_entries": entries,
    }


RunLoader = Callable[[Path, int, int], tuple[dict[str, Any], dict[str, Any], bytes]]


def generate(
    *,
    spec_path: Path,
    repo: Path,
    implementation_commit: str,
    tool_commit: str,
    ci_run_id: int,
    ci_attempt: int,
    formal_run_id: int,
    formal_attempt: int,
    run_loader: RunLoader = _gh_run,
) -> Path:
    """Generate one supplemental record and two canonical log members."""

    root = repo.resolve(strict=True)
    top = _git(root, "rev-parse", "--show-toplevel").decode("utf-8").strip()
    if Path(top).resolve(strict=True) != root:
        raise EvidenceGenerationError("EVIDENCE_REPOSITORY_ROOT_INVALID")
    _require_hex(implementation_commit, HEX40, "implementation_commit")
    _require_hex(tool_commit, HEX40, "tool_commit")

    expected_spec_rel = f"{SPEC_DIRECTORY}/{spec_path.stem}.json"
    worktree_spec = _regular_repo_file(root, expected_spec_rel)
    if spec_path.resolve(strict=True) != worktree_spec:
        raise EvidenceGenerationError("EVIDENCE_SPEC_PATH_INVALID")
    allowed_signers = _git_blob(root, tool_commit, ALLOWED_SIGNERS_PATH)
    tool = _commit_record(root, tool_commit, allowed_signers)
    spec_blob = _git_blob(root, tool_commit, expected_spec_rel)
    generator_blob = _git_blob(root, tool_commit, GENERATOR_PATH)
    verifier_blob = _git_blob(root, tool_commit, VERIFIER_PATH)
    if (
        _read_bounded(worktree_spec, MAX_SPEC_BYTES, "spec") != spec_blob
        or _read_bounded(_regular_repo_file(root, GENERATOR_PATH), MAX_RECORD_BYTES, "generator")
        != generator_blob
        or _read_bounded(_regular_repo_file(root, VERIFIER_PATH), MAX_RECORD_BYTES, "verifier")
        != verifier_blob
        or _read_bounded(
            _regular_repo_file(root, ALLOWED_SIGNERS_PATH), MAX_SPEC_BYTES, "allowed_signers"
        )
        != allowed_signers
    ):
        raise EvidenceGenerationError("EVIDENCE_TOOL_WORKTREE_DRIFT")
    spec = load_spec_bytes(spec_blob)
    expected_spec_rel = f"{SPEC_DIRECTORY}/{spec['task_id'].lower()}.json"
    if worktree_spec != _regular_repo_file(root, expected_spec_rel):
        raise EvidenceGenerationError("EVIDENCE_SPEC_ID_PATH_MISMATCH")
    implementation = _commit_record(root, implementation_commit, allowed_signers)
    _require_ancestor(root, implementation_commit, tool_commit)

    ci_metadata, ci_jobs, ci_archive = run_loader(root, ci_run_id, ci_attempt)
    formal_metadata, formal_jobs, formal_archive = run_loader(
        root, formal_run_id, formal_attempt
    )
    ci, ci_log = _normalize_run(
        ci_metadata,
        ci_jobs,
        ci_archive,
        run_id=ci_run_id,
        attempt=ci_attempt,
        expected_commit=implementation_commit,
        workflow=spec["github"]["ci"],
        github_scope=spec["github"],
    )
    formal, formal_log = _normalize_run(
        formal_metadata,
        formal_jobs,
        formal_archive,
        run_id=formal_run_id,
        attempt=formal_attempt,
        expected_commit=implementation_commit,
        workflow=spec["github"]["formal"],
        github_scope=spec["github"],
    )

    task = spec["task_id"].lower()
    ci_relative = (
        f"{EVIDENCE_DIRECTORY}/{task}-generated-ci-{implementation_commit}-"
        f"run{ci_run_id}-attempt{ci_attempt}.log.gz"
    )
    formal_relative = (
        f"{EVIDENCE_DIRECTORY}/{task}-generated-formal-{implementation_commit}-"
        f"run{formal_run_id}-attempt{formal_attempt}.log.gz"
    )
    ci_gzip = canonical_gzip(ci_log)
    formal_gzip = canonical_gzip(formal_log)
    _atomic_write(root / ci_relative, ci_gzip)
    _atomic_write(root / formal_relative, formal_gzip)
    ci["log"] = _log_record(ci_relative, ci_log, ci_gzip, len(_parse_canonical_log(ci_log)))
    formal["log"] = _log_record(
        formal_relative, formal_log, formal_gzip, len(_parse_canonical_log(formal_log))
    )

    tool.update(
        {
            "generator": {"path": GENERATOR_PATH, "sha256": _sha256(generator_blob)},
            "verifier": {"path": VERIFIER_PATH, "sha256": _sha256(verifier_blob)},
            "allowed_signers": {
                "path": ALLOWED_SIGNERS_PATH,
                "sha256": _sha256(allowed_signers),
            },
            "evidence_spec": {
                "path": expected_spec_rel,
                "sha256": _sha256(spec_blob),
            },
        }
    )
    record = {
        "schema_version": "2.0.0",
        "task_id": spec["task_id"],
        "requirement_id": spec["requirement_id"],
        "status": "verified",
        "generated_by": GENERATOR_PATH,
        "evidence_tool": tool,
        "implementation": implementation,
        "implementation_artifacts": _implementation_artifacts(
            root, implementation_commit, spec["implementation_artifacts"]
        ),
        "inputs": _source_inputs(root, implementation_commit),
        "github_ci": ci,
        "github_formal": formal,
        "verification_scope": spec["verification_scope"],
        "review": spec["review"],
        "residual_risks": spec["residual_risks"],
    }
    output = root / EVIDENCE_DIRECTORY / f"{task}-generated-verification.json"
    _atomic_write(output, _canonical_json_bytes(record))
    return output


def _validate_signature_record(value: Any) -> None:
    expected = {
        "format": "ssh",
        "principal": SIGNER_PRINCIPAL,
        "key_type": SIGNER_KEY_TYPE,
        "fingerprint": SIGNER_FINGERPRINT,
    }
    if value != expected:
        raise EvidenceGenerationError("EVIDENCE_SIGNATURE_RECORD_INVALID")


def _verify_commit_record(
    repo: Path, record: Any, allowed_signers: bytes, label: str
) -> str:
    if not isinstance(record, dict):
        raise EvidenceGenerationError(f"EVIDENCE_{label}_INVALID")
    base_fields = {"commit", "tree", "author", "committer", "signature"}
    if label == "TOOL":
        base_fields |= {"generator", "verifier", "allowed_signers", "evidence_spec"}
    if set(record) != base_fields:
        raise EvidenceGenerationError(f"EVIDENCE_{label}_FIELDS_INVALID")
    commit = _require_hex(record.get("commit"), HEX40, f"{label}.commit")
    expected = _commit_record(repo, commit, allowed_signers)
    for field in ("commit", "tree", "author", "committer"):
        if record.get(field) != expected[field]:
            raise EvidenceGenerationError(f"EVIDENCE_{label}_{field.upper()}_INVALID")
    _validate_signature_record(record.get("signature"))
    return commit


def _verify_log_record(
    repo: Path,
    record: Any,
    *,
    expected_path: str,
    jobs: list[dict[str, Any]],
    workflow: dict[str, Any],
) -> None:
    if not isinstance(record, dict) or set(record) != EXPECTED_LOG_FIELDS:
        raise EvidenceGenerationError("EVIDENCE_LOG_RECORD_FIELDS_INVALID")
    if (
        record.get("path") != expected_path
        or record.get("format") != "github-actions-complete-logical-job-logs-v1"
        or record.get("compression") != "canonical-gzip-stored-v1"
        or record.get("gzip_timestamp") != 0
    ):
        raise EvidenceGenerationError("EVIDENCE_LOG_RECORD_IDENTITY_INVALID")
    path = _regular_repo_file(repo, expected_path)
    compressed = _read_bounded(path, MAX_LOG_BYTES + 1024, "generated_log")
    if (
        record.get("compressed_bytes") != len(compressed)
        or _require_hex(record.get("compressed_sha256"), HEX64, "compressed_sha256")
        != _sha256(compressed)
    ):
        raise EvidenceGenerationError("EVIDENCE_LOG_COMPRESSED_DIGEST_INVALID")
    uncompressed = decode_canonical_gzip(compressed)
    if (
        record.get("uncompressed_bytes") != len(uncompressed)
        or record.get("uncompressed_lines") != uncompressed.count(b"\n")
        or _require_hex(record.get("uncompressed_sha256"), HEX64, "uncompressed_sha256")
        != _sha256(uncompressed)
    ):
        raise EvidenceGenerationError("EVIDENCE_LOG_UNCOMPRESSED_DIGEST_INVALID")
    entries = _parse_canonical_log(uncompressed)
    if record.get("logical_entries") != len(entries):
        raise EvidenceGenerationError("EVIDENCE_LOG_ENTRY_COUNT_INVALID")
    _validate_logical_job_logs(entries, jobs, workflow)


def _verify_run_record(
    repo: Path,
    record: Any,
    *,
    implementation_commit: str,
    workflow: dict[str, Any],
    github_scope: dict[str, Any],
    kind: str,
    task: str,
) -> None:
    if not isinstance(record, dict) or set(record) != EXPECTED_RUN_FIELDS:
        raise EvidenceGenerationError("EVIDENCE_RUN_RECORD_FIELDS_INVALID")
    run_id = record.get("run_id")
    attempt = record.get("attempt")
    if (
        isinstance(run_id, bool)
        or not isinstance(run_id, int)
        or run_id <= 0
        or isinstance(attempt, bool)
        or not isinstance(attempt, int)
        or attempt <= 0
    ):
        raise EvidenceGenerationError("EVIDENCE_RUN_RECORD_ID_INVALID")
    expected_base = f"https://github.com/{REPOSITORY}/actions/runs/{run_id}"
    valid_url = expected_base if attempt == 1 else f"{expected_base}/attempts/{attempt}"
    if (
        record.get("repository") != REPOSITORY
        or record.get("url") != valid_url
        or record.get("api_url")
        != f"https://api.github.com/repos/{REPOSITORY}/actions/runs/{run_id}"
        or record.get("workflow_name") != workflow["workflow_name"]
        or record.get("workflow_path") != workflow["workflow_path"]
        or record.get("workflow_id") != workflow["workflow_id"]
        or record.get("event") != github_scope["event"]
        or record.get("head_branch") != github_scope["branch"]
        or record.get("head_sha") != implementation_commit
        or record.get("status") != "completed"
        or record.get("conclusion") != "success"
    ):
        raise EvidenceGenerationError("EVIDENCE_RUN_RECORD_METADATA_INVALID")
    jobs = record.get("jobs")
    if not isinstance(jobs, list):
        raise EvidenceGenerationError("EVIDENCE_RUN_RECORD_JOBS_INVALID")
    # Revalidate the generated job schema without relying on remote metadata.
    names: list[str] = []
    job_ids: list[int] = []
    for job in jobs:
        if (
            not isinstance(job, dict)
            or set(job) != {"job_id", "name", "status", "conclusion", "steps"}
            or isinstance(job.get("job_id"), bool)
            or not isinstance(job.get("job_id"), int)
            or job["job_id"] <= 0
            or job.get("status") != "completed"
            or job.get("conclusion") != "success"
            or not isinstance(job.get("steps"), list)
            or not job["steps"]
        ):
            raise EvidenceGenerationError("EVIDENCE_RUN_RECORD_JOB_INVALID")
        names.append(job.get("name"))
        job_ids.append(job["job_id"])
        numbers: list[int] = []
        for step in job["steps"]:
            if (
                not isinstance(step, dict)
                or set(step) != {"number", "name", "status", "conclusion"}
                or isinstance(step.get("number"), bool)
                or not isinstance(step.get("number"), int)
                or step["number"] <= 0
                or not isinstance(step.get("name"), str)
                or not step["name"].strip()
                or step.get("status") != "completed"
                or step.get("conclusion") != "success"
            ):
                raise EvidenceGenerationError("EVIDENCE_RUN_RECORD_STEP_INVALID")
            numbers.append(step["number"])
        if numbers != sorted(numbers) or len(set(numbers)) != len(numbers):
            raise EvidenceGenerationError("EVIDENCE_RUN_RECORD_STEP_ORDER_INVALID")
    if (
        names != workflow["expected_jobs"]
        or len(set(job_ids)) != len(job_ids)
        or not any(
            job["name"] == workflow["marker_job"]
            and any(step["name"] == workflow["marker_step"] for step in job["steps"])
            for job in jobs
        )
    ):
        raise EvidenceGenerationError("EVIDENCE_RUN_RECORD_JOB_SET_INVALID")
    _validate_required_steps(jobs, workflow)
    expected_path = (
        f"{EVIDENCE_DIRECTORY}/{task}-generated-{kind}-{implementation_commit}-"
        f"run{run_id}-attempt{attempt}.log.gz"
    )
    _verify_log_record(
        repo,
        record.get("log"),
        expected_path=expected_path,
        jobs=jobs,
        workflow=workflow,
    )


def _verify_spec_derived_fields(record: dict[str, Any], spec: dict[str, Any]) -> None:
    for field in ("verification_scope", "review", "residual_risks"):
        if record.get(field) != spec[field]:
            raise EvidenceGenerationError("EVIDENCE_RECORD_SPEC_FIELD_MISMATCH")


def _verify_artifact_manifest(
    repo: Path,
    artifact_records: Any,
    implementation_commit: str,
    specifications: list[dict[str, str]],
) -> None:
    expected_artifacts = _implementation_artifacts(
        repo, implementation_commit, specifications
    )
    if artifact_records != expected_artifacts:
        raise EvidenceGenerationError("EVIDENCE_RECORD_IMPLEMENTATION_ARTIFACTS_INVALID")
    for artifact in expected_artifacts:
        if artifact["worktree_policy"] == "MUST_MATCH":
            current_path = _regular_repo_file(repo, artifact["path"])
            current = _read_bounded(
                current_path,
                MAX_GIT_BYTES,
                "implementation_artifact",
            )
            current_mode = "100755" if current_path.stat().st_mode & 0o111 else "100644"
            if (
                _sha256(current) != artifact["sha256"]
                or len(current) != artifact["bytes"]
                or current_mode != artifact["git_mode"]
            ):
                raise EvidenceGenerationError("EVIDENCE_RECORD_ARTIFACT_WORKTREE_DRIFT")


def _verify_record_identity(record: dict[str, Any], relative: str) -> str:
    if set(record) != EXPECTED_RECORD_FIELDS:
        raise EvidenceGenerationError("EVIDENCE_RECORD_FIELDS_INVALID")
    task_id = record.get("task_id")
    if (
        record.get("schema_version") != "2.0.0"
        or not isinstance(task_id, str)
        or TASK_ID.fullmatch(task_id) is None
        or record.get("requirement_id") != f"HALDIR-0.9-{task_id}"
        or record.get("status") != "verified"
        or record.get("generated_by") != GENERATOR_PATH
        or relative != f"{EVIDENCE_DIRECTORY}/{task_id.lower()}-generated-verification.json"
    ):
        raise EvidenceGenerationError("EVIDENCE_RECORD_IDENTITY_INVALID")
    return task_id


def verify_generated_record(repo: Path, record_path: Path) -> dict[str, Any]:
    """Offline verification of every byte and every locally derivable field."""

    root = repo.resolve(strict=True)
    relative = record_path.resolve(strict=True).relative_to(root).as_posix()
    record_file = _regular_repo_file(root, relative)
    payload = _read_bounded(record_file, MAX_RECORD_BYTES, "generated_record")
    record = _load_json_bytes(payload, "generated_record")
    if _canonical_json_bytes(record) != payload:
        raise EvidenceGenerationError("EVIDENCE_RECORD_NONCANONICAL")
    task_id = _verify_record_identity(record, relative)

    tool_record = record.get("evidence_tool")
    if not isinstance(tool_record, dict):
        raise EvidenceGenerationError("EVIDENCE_TOOL_INVALID")
    tool_commit = _require_hex(tool_record.get("commit"), HEX40, "tool.commit")
    allowed_signers = _git_blob(root, tool_commit, ALLOWED_SIGNERS_PATH)
    _verify_commit_record(root, tool_record, allowed_signers, "TOOL")
    expected_spec_path = f"{SPEC_DIRECTORY}/{task_id.lower()}.json"
    bound_blobs = {
        "generator": GENERATOR_PATH,
        "verifier": VERIFIER_PATH,
        "allowed_signers": ALLOWED_SIGNERS_PATH,
        "evidence_spec": expected_spec_path,
    }
    blobs: dict[str, bytes] = {}
    for field, path in bound_blobs.items():
        binding = tool_record.get(field)
        blob = _git_blob(root, tool_commit, path)
        if (
            not isinstance(binding, dict)
            or set(binding) != {"path", "sha256"}
            or binding.get("path") != path
            or _require_hex(binding.get("sha256"), HEX64, f"tool.{field}.sha256")
            != _sha256(blob)
        ):
            raise EvidenceGenerationError("EVIDENCE_TOOL_BLOB_BINDING_INVALID")
        blobs[field] = blob
    if blobs["allowed_signers"] != ALLOWED_SIGNERS:
        raise EvidenceGenerationError("EVIDENCE_ALLOWED_SIGNERS_INVALID")
    spec = load_spec_bytes(blobs["evidence_spec"])
    if spec["task_id"] != task_id:
        raise EvidenceGenerationError("EVIDENCE_RECORD_SPEC_MISMATCH")

    implementation_record = record.get("implementation")
    implementation_commit = _verify_commit_record(
        root, implementation_record, allowed_signers, "IMPLEMENTATION"
    )
    _require_ancestor(root, implementation_commit, tool_commit)
    if record.get("inputs") != _source_inputs(root, implementation_commit):
        raise EvidenceGenerationError("EVIDENCE_RECORD_SOURCE_INPUTS_INVALID")
    _verify_artifact_manifest(
        root,
        record.get("implementation_artifacts"),
        implementation_commit,
        spec["implementation_artifacts"],
    )
    _verify_spec_derived_fields(record, spec)
    _verify_run_record(
        root,
        record.get("github_ci"),
        implementation_commit=implementation_commit,
        workflow=spec["github"]["ci"],
        github_scope=spec["github"],
        kind="ci",
        task=task_id.lower(),
    )
    _verify_run_record(
        root,
        record.get("github_formal"),
        implementation_commit=implementation_commit,
        workflow=spec["github"]["formal"],
        github_scope=spec["github"],
        kind="formal",
        task=task_id.lower(),
    )
    return record


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", required=True, type=Path)
    parser.add_argument("--implementation-commit", required=True)
    parser.add_argument("--tool-commit", required=True)
    parser.add_argument("--ci-run-id", required=True, type=int)
    parser.add_argument("--ci-attempt", required=True, type=int)
    parser.add_argument("--formal-run-id", required=True, type=int)
    parser.add_argument("--formal-attempt", required=True, type=int)
    return parser


def main() -> int:
    arguments = _parser().parse_args()
    repo = Path(__file__).resolve().parents[2]
    try:
        output = generate(
            spec_path=arguments.spec,
            repo=repo,
            implementation_commit=arguments.implementation_commit,
            tool_commit=arguments.tool_commit,
            ci_run_id=arguments.ci_run_id,
            ci_attempt=arguments.ci_attempt,
            formal_run_id=arguments.formal_run_id,
            formal_attempt=arguments.formal_attempt,
        )
        verify_generated_record(repo, output)
    except (EvidenceGenerationError, UnicodeDecodeError, ValueError) as error:
        print(f"generate-task-evidence: FAIL: {error}", file=sys.stderr)
        return 1
    print(f"generate-task-evidence: OK: {output.relative_to(repo)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
