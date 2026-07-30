#!/usr/bin/env python3
"""Capture bounded FR-0017 evidence using exact GitHub identities.

This tool acquires bytes; it does not grant authority.  The central bridge
replays every parser and independently performs offline Sigstore verification
against the trust root frozen by the signed R commit.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from types import ModuleType
from typing import Any, Sequence


REPOSITORY = "sepahead/haldir"
HEX40 = re.compile(r"^[0-9a-f]{40}$")
MAX_JSON_BYTES = 2 * 1024 * 1024
MAX_BUNDLE_BYTES = 1024 * 1024
MAX_GH_STDERR = 64 * 1024
MAX_LOCAL_TOOL_BYTES = 256 * 1024 * 1024
BRIDGE_PATH = "tools/release/verify-framework-recovery-fr-0017.py"
PROTOCOL_PATH = "tools/release/framework_recovery_fr_0017.py"


class CaptureError(RuntimeError):
    """One fail-closed capture error."""


def _fail(code: str) -> None:
    raise CaptureError(code)


def _load_module(path: Path, name: str) -> ModuleType:
    specification = importlib.util.spec_from_file_location(name, path)
    if specification is None or specification.loader is None:
        _fail("FR0017_CAPTURE_MODULE")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def _git_environment() -> dict[str, str]:
    return {
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }


def _git(repo: Path, *arguments: str, limit: int = MAX_JSON_BYTES) -> bytes:
    completed = subprocess.run(
        ("/usr/bin/git", "-c", "core.hooksPath=/dev/null", *arguments),
        cwd=repo,
        env=_git_environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=30,
    )
    if completed.returncode != 0 or completed.stderr or len(completed.stdout) > limit:
        _fail("FR0017_CAPTURE_GIT:" + (arguments[0] if arguments else "missing"))
    return completed.stdout


def _repository() -> Path:
    raw = _git(Path.cwd(), "rev-parse", "--show-toplevel", limit=64 * 1024)
    try:
        return Path(raw.decode("utf-8").strip()).resolve(strict=True)
    except (OSError, UnicodeDecodeError):
        _fail("FR0017_CAPTURE_REPOSITORY")


def _require_clean_worktree(repo: Path, *, label: str) -> None:
    status = _git(
        repo,
        "status",
        "--porcelain=v1",
        "-z",
        "--untracked-files=all",
        limit=MAX_JSON_BYTES,
    )
    if status:
        _fail(label)


def _online_environment(executable: Path) -> dict[str, str]:
    environment = {
        "LC_ALL": "C",
        "PATH": f"{executable.parent}:/usr/bin:/bin",
    }
    for name in (
        "GH_CONFIG_DIR",
        "GH_ENTERPRISE_TOKEN",
        "GH_HOST",
        "GH_TOKEN",
        "GITHUB_ENTERPRISE_TOKEN",
        "GITHUB_TOKEN",
        "HOME",
        "HTTPS_PROXY",
        "HTTP_PROXY",
        "NO_PROXY",
        "SSL_CERT_FILE",
        "XDG_CONFIG_HOME",
    ):
        if name in os.environ:
            environment[name] = os.environ[name]
    return environment


def _gh(
    bridge: ModuleType,
    executable: Path,
    arguments: tuple[str, ...],
    *,
    cwd: Path,
    limit: int,
    timeout: float = 60,
) -> bytes:
    returncode, stdout, stderr = bridge._run_bounded(
        (str(executable), *arguments),
        cwd=cwd,
        env=_online_environment(executable),
        timeout_seconds=timeout,
        output_limit=limit + MAX_GH_STDERR,
    )
    if returncode != 0 or len(stdout) > limit or len(stderr) > MAX_GH_STDERR:
        _fail("FR0017_CAPTURE_GH:" + (arguments[0] if arguments else "missing"))
    return stdout


def _json_bytes(raw: bytes, label: str) -> dict[str, Any]:
    if not raw or len(raw) > MAX_JSON_BYTES or b"\0" in raw:
        _fail("FR0017_CAPTURE_JSON:" + label)
    try:
        value = json.loads(raw)
    except (RecursionError, UnicodeDecodeError, json.JSONDecodeError):
        _fail("FR0017_CAPTURE_JSON:" + label)
    if not isinstance(value, dict):
        _fail("FR0017_CAPTURE_JSON:" + label)
    return value


def _json_list(raw: bytes, label: str) -> list[Any]:
    if not raw or len(raw) > MAX_JSON_BYTES or b"\0" in raw:
        _fail("FR0017_CAPTURE_JSON:" + label)
    try:
        value = json.loads(raw)
    except (RecursionError, UnicodeDecodeError, json.JSONDecodeError):
        _fail("FR0017_CAPTURE_JSON:" + label)
    if not isinstance(value, list):
        _fail("FR0017_CAPTURE_JSON:" + label)
    return value


def _now() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def _write_exclusive(path: Path, payload: bytes, *, mode: int = 0o644) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        mode,
    )
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written < 1:
                _fail("FR0017_CAPTURE_WRITE")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _read_regular_bounded(path: Path, *, limit: int, label: str) -> bytes:
    """Read one regular file through a no-follow descriptor within a hard bound."""

    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        _fail(label)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or not 1 <= before.st_size <= limit:
            _fail(label)
        chunks: list[bytes] = []
        remaining = limit + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        after = os.fstat(descriptor)
        if (
            len(payload) != before.st_size
            or len(payload) > limit
            or (
                after.st_dev,
                after.st_ino,
                after.st_mode,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            )
            != (
                before.st_dev,
                before.st_ino,
                before.st_mode,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            )
        ):
            _fail(label)
        return payload
    finally:
        os.close(descriptor)


def _blob_record(path: str, payload: bytes, *, mode: str = "100644") -> dict[str, Any]:
    framed = b"blob " + str(len(payload)).encode("ascii") + b"\0" + payload
    return {
        "path": path,
        "git_mode": mode,
        "git_object_type": "blob",
        "git_object_id": hashlib.sha1(framed, usedforsecurity=False).hexdigest(),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "bytes": len(payload),
    }


def _commit_tree(repo: Path, commit: str) -> str:
    if HEX40.fullmatch(commit) is None:
        _fail("FR0017_CAPTURE_COMMIT")
    value = _git(repo, "rev-parse", "--verify", f"{commit}^{{tree}}").decode().strip()
    if HEX40.fullmatch(value) is None:
        _fail("FR0017_CAPTURE_COMMIT")
    return value


def _stage_paths(bridge: ModuleType, stage: str, workflow: str) -> tuple[str, str, str]:
    if stage == "repair":
        return (
            bridge.REPAIR_CI_PATHS if workflow == "ci" else bridge.REPAIR_FORMAL_PATHS
        )
    if stage == "qualification":
        return (
            bridge.QUALIFICATION_CI_PATHS
            if workflow == "ci"
            else bridge.QUALIFICATION_FORMAL_PATHS
        )
    _fail("FR0017_CAPTURE_STAGE")


def _run_fields(*, epoch18: bool, attempt: bool) -> str:
    fields = [
        "attempt",
        "conclusion",
        "createdAt",
        "databaseId",
        "event",
        "headBranch",
        "headSha",
        "jobs",
    ]
    if epoch18:
        fields.append("number")
    if attempt:
        fields.append("startedAt")
    fields.extend(("status", "updatedAt", "url"))
    if attempt or epoch18:
        fields.append("workflowDatabaseId")
    fields.append("workflowName")
    return ",".join(fields)


def _capture_hosted(
    repo: Path,
    bridge: ModuleType,
    protocol: ModuleType,
    arguments: argparse.Namespace,
) -> None:
    workflow = arguments.workflow
    expected_paths = _stage_paths(bridge, arguments.stage, workflow)
    output_paths = tuple(repo / path for path in expected_paths)
    if any(path.exists() or path.is_symlink() for path in output_paths):
        _fail("FR0017_CAPTURE_OUTPUT_EXISTS")
    if arguments.run_id < 1:
        _fail("FR0017_CAPTURE_RUN_ID")
    repair_commit = arguments.repair_commit
    subject_commit = arguments.subject_commit
    _commit_tree(repo, repair_commit)
    subject_tree = _commit_tree(repo, subject_commit)
    executable, _version = bridge._trusted_gh()
    ordinary_fields = _run_fields(epoch18=True, attempt=False)
    ordinary = _json_bytes(
        _gh(
            bridge,
            executable,
            (
                "run",
                "view",
                str(arguments.run_id),
                "--repo",
                REPOSITORY,
                "--json",
                ordinary_fields,
            ),
            cwd=repo,
            limit=MAX_JSON_BYTES,
        ),
        "ordinary",
    )
    attempt_number = ordinary.get("attempt")
    if (
        type(attempt_number) is not int
        or not 1 <= attempt_number <= protocol.MAX_EPOCH18_RUN_ATTEMPT
    ):
        _fail("FR0017_CAPTURE_ATTEMPT")
    attempt_fields = _run_fields(epoch18=True, attempt=True)
    attempt = _json_bytes(
        _gh(
            bridge,
            executable,
            (
                "run",
                "view",
                str(arguments.run_id),
                "--repo",
                REPOSITORY,
                "--attempt",
                str(attempt_number),
                "--json",
                attempt_fields,
            ),
            cwd=repo,
            limit=MAX_JSON_BYTES,
        ),
        "attempt",
    )
    run = protocol.validate_epoch18_run_documents(
        ordinary,
        attempt,
        workflow=workflow,
        subject_commit=subject_commit,
        expected_ref="refs/heads/main",
    )
    artifact_name = f"epoch-18-{workflow}-result-attempt-{attempt_number}.json"
    listing_endpoint = (
        f"repos/{REPOSITORY}/actions/runs/{arguments.run_id}/artifacts"
        f"?name={artifact_name}&per_page=100"
    )
    listing = _json_bytes(
        _gh(
            bridge,
            executable,
            ("api", "--method", "GET", listing_endpoint),
            cwd=repo,
            limit=MAX_JSON_BYTES,
        ),
        "artifact-list",
    )
    artifact = protocol.validate_artifact_listing(listing)
    artifact_id = artifact.get("id")
    if type(artifact_id) is not int or artifact_id < 1:
        _fail("FR0017_CAPTURE_ARTIFACT_ID")
    artifact_by_id = _json_bytes(
        _gh(
            bridge,
            executable,
            (
                "api",
                "--method",
                "GET",
                f"repos/{REPOSITORY}/actions/artifacts/{artifact_id}",
            ),
            cwd=repo,
            limit=MAX_JSON_BYTES,
        ),
        "artifact-id",
    )
    if artifact_by_id != artifact:
        _fail("FR0017_CAPTURE_ARTIFACT_IDENTITY")
    result_payload = _gh(
        bridge,
        executable,
        (
            "api",
            "--method",
            "GET",
            f"repos/{REPOSITORY}/actions/artifacts/{artifact_id}/zip",
        ),
        cwd=repo,
        limit=256 * 1024,
    )
    if not result_payload.endswith(b"\n"):
        _fail("FR0017_CAPTURE_DIRECT_ARTIFACT")
    materials = [
        bridge.file_record(repo, subject_commit, path)
        for path in protocol.RESULT_CONTRACT[workflow]["material_paths"]
    ]
    protocol.validate_result_artifact(
        result_payload,
        workflow=workflow,
        subject_commit=subject_commit,
        subject_tree=subject_tree,
        run_id=run["run_id"],
        attempt=run["attempt"],
        run_number=run["run_number"],
        expected_ref="refs/heads/main",
        expected_materials=materials,
    )
    protocol.validate_artifact_metadata(
        artifact,
        workflow=workflow,
        run_id=run["run_id"],
        attempt=run["attempt"],
        subject_commit=subject_commit,
        result_payload=result_payload,
        producer_started=run["jobs"][protocol.RESULT_CONTRACT[workflow]["job"]][
            "started"
        ],
        producer_completed=run["jobs"][protocol.RESULT_CONTRACT[workflow]["job"]][
            "completed"
        ],
        attestation_started=run["jobs"][run["attestation_job"]]["started"],
    )
    trusted_root_payload = (repo / bridge.TRUSTED_ROOT_PATH).read_bytes()
    bridge._validate_trusted_root(trusted_root_payload)
    with tempfile.TemporaryDirectory(prefix="haldir-fr0017-download-") as name:
        root = Path(name)
        result_file = root / artifact_name
        bridge._write_private(result_file, result_payload)
        _gh(
            bridge,
            executable,
            (
                "attestation",
                "download",
                artifact_name,
                "--repo",
                REPOSITORY,
                "--limit",
                "1",
                "--predicate-type",
                "https://slsa.dev/provenance/v1",
            ),
            cwd=root,
            limit=64 * 1024,
        )
        digest = hashlib.sha256(result_payload).hexdigest()
        candidates = (
            root / f"sha256:{digest}.jsonl",
            root / f"sha256-{digest}.jsonl",
        )
        bundles = [
            path for path in candidates if path.is_file() and not path.is_symlink()
        ]
        if len(bundles) != 1:
            _fail("FR0017_CAPTURE_ATTESTATION_FILE")
        bundle_payload = _read_regular_bounded(
            bundles[0],
            limit=MAX_BUNDLE_BYTES,
            label="FR0017_CAPTURE_ATTESTATION_BOUND",
        )
    receipt, verification = bridge._verify_attestation_offline(
        result_payload=result_payload,
        bundle_payload=bundle_payload,
        trusted_root_payload=trusted_root_payload,
        workflow=workflow,
        subject_commit=subject_commit,
        attempt=attempt_number,
    )
    protocol.validate_attestation_evidence(
        bundle_payload,
        receipt,
        workflow=workflow,
        result_payload=result_payload,
        subject_commit=subject_commit,
        expected_ref="refs/heads/main",
        run_id=run["run_id"],
        attempt=run["attempt"],
        attestation_started=run["jobs"][run["attestation_job"]]["started"],
        attestation_completed=run["jobs"][run["attestation_job"]]["completed"],
    )
    result_path, bundle_path = expected_paths[1], expected_paths[2]
    capture = {
        "schema_version": "1.0.0",
        "protocol": "HALDIR_FR_0017_HOSTED_RESULT_CAPTURE_V1",
        "workflow": workflow,
        "subject_commit": subject_commit,
        "subject_tree": subject_tree,
        "expected_ref": "refs/heads/main",
        "ordinary": ordinary,
        "attempt_metadata": attempt,
        "artifact_listing": listing,
        "artifact_by_id": artifact_by_id,
        "artifact": artifact,
        "artifact_download": {
            "bytes": len(result_payload),
            "content_mode": "DIRECT_UNARCHIVED_FILE",
            "sha256": hashlib.sha256(result_payload).hexdigest(),
        },
        "commands": bridge._hosted_commands(
            workflow=workflow,
            run_id=run["run_id"],
            attempt=run["attempt"],
            artifact_id=artifact_id,
        ),
        "capture_tool": bridge.file_record(repo, repair_commit, bridge.CAPTURE_PATH),
        "result_record": _blob_record(result_path, result_payload),
        "attestation_record": _blob_record(bundle_path, bundle_payload),
        "trusted_root_record": bridge.file_record(
            repo, repair_commit, bridge.TRUSTED_ROOT_PATH
        ),
        "attestation_verification": receipt,
        "capture_verification": verification,
        "captured_at_utc": _now(),
        "result": "PASS",
    }
    capture_payload = bridge.canonical_json_bytes(capture)
    _write_exclusive(output_paths[1], result_payload)
    _write_exclusive(output_paths[2], bundle_payload)
    _write_exclusive(output_paths[0], capture_payload)
    print(
        "framework-recovery-fr-0017-capture: OK "
        f"({arguments.stage}; {workflow}; run {run['run_id']}; "
        f"attempt {run['attempt']}; artifact {artifact_id})"
    )


def _normalize_repository_document(
    document: Any,
    bridge: ModuleType,
) -> dict[str, Any]:
    """Reduce one repository GET while proving non-fork ancestry keys are absent."""

    owner = document.get("owner") if isinstance(document, dict) else None
    if (
        not isinstance(document, dict)
        or not isinstance(owner, dict)
        or type(document.get("id")) is not int
        or type(owner.get("id")) is not int
        or document.get("fork") is not False
        or "parent" in document
        or "source" in document
    ):
        _fail("FR0017_CAPTURE_REPOSITORY_IDENTITY")
    identity = {
        "id": document["id"],
        "name": document.get("name"),
        "full_name": document.get("full_name"),
        "default_branch": document.get("default_branch"),
        "fork": document["fork"],
        "owner": {
            "id": owner["id"],
            "login": owner.get("login"),
            "type": owner.get("type"),
        },
        "has_parent": False,
        "has_source": False,
    }
    try:
        return bridge.validate_repository_identity(identity)
    except bridge.BridgeError:
        _fail("FR0017_CAPTURE_REPOSITORY_IDENTITY")


def _normalize_pull_request_document(
    document: Any,
    *,
    repair_commit: str,
    required_state: str,
) -> dict[str, Any]:
    if required_state not in {"open", "closed"}:
        _fail("FR0017_CAPTURE_PULL_REQUEST")
    head = document.get("head") if isinstance(document, dict) else None
    base = document.get("base") if isinstance(document, dict) else None
    head_repo = head.get("repo") if isinstance(head, dict) else None
    base_repo = base.get("repo") if isinstance(base, dict) else None
    if (
        not isinstance(document, dict)
        or type(document.get("number")) is not int
        or document["number"] < 1
        or type(document.get("id")) is not int
        or document["id"] < 1
        or not isinstance(document.get("node_id"), str)
        or not document["node_id"]
        or document.get("state") != required_state
        or type(document.get("draft")) is not bool
        or document["draft"] is not False
        or type(document.get("locked")) is not bool
        or document["locked"] is not False
        or type(document.get("merged")) is not bool
        or document["merged"] is not False
        or document.get("merged_at") is not None
        or (required_state == "open" and document.get("closed_at") is not None)
        or (
            required_state == "closed"
            and not isinstance(document.get("closed_at"), str)
        )
        or not isinstance(document.get("merge_commit_sha"), str)
        or HEX40.fullmatch(document["merge_commit_sha"]) is None
        or not isinstance(head, dict)
        or not isinstance(base, dict)
        or not isinstance(head_repo, dict)
        or not isinstance(base_repo, dict)
        or type(head_repo.get("id")) is not int
        or type(base_repo.get("id")) is not int
        or head_repo["id"] != 1_292_802_592
        or base_repo["id"] != 1_292_802_592
        or head.get("sha") != repair_commit
        or base.get("sha") != "7e5015092d5a4de3556b252e594c59c72636e7b9"
        or base.get("ref") != "main"
        or not isinstance(head.get("ref"), str)
        or re.fullmatch(r"[A-Za-z0-9._/-]+", head["ref"]) is None
        or len(head["ref"].encode("ascii")) > 255
        or head["ref"].startswith("/")
        or head["ref"].endswith("/")
        or ".." in head["ref"]
        or "//" in head["ref"]
        or head["ref"] == "main"
    ):
        _fail("FR0017_CAPTURE_PULL_REQUEST")
    number = document["number"]
    expected_api_url = f"https://api.github.com/repos/{REPOSITORY}/pulls/{number}"
    expected_html_url = f"https://github.com/{REPOSITORY}/pull/{number}"
    if (
        document.get("url") != expected_api_url
        or document.get("html_url") != expected_html_url
    ):
        _fail("FR0017_CAPTURE_PULL_REQUEST")
    return {
        "number": number,
        "database_id": document["id"],
        "node_id": document["node_id"],
        "api_url": expected_api_url,
        "html_url": expected_html_url,
        "state": required_state,
        "draft": False,
        "locked": False,
        "merged": False,
        "merge_commit_sha": document["merge_commit_sha"],
        "created_at": document.get("created_at"),
        "updated_at": document.get("updated_at"),
        "closed_at": document.get("closed_at"),
        "merged_at": None,
        "head": {
            "ref": head["ref"],
            "sha": repair_commit,
            "repository_id": head_repo["id"],
        },
        "base": {
            "ref": "main",
            "sha": base["sha"],
            "repository_id": base_repo["id"],
        },
    }


def _normalize_synthetic_merge(
    document: Any,
    *,
    merge_commit: str,
    repair_commit: str,
) -> dict[str, Any]:
    tree = document.get("tree") if isinstance(document, dict) else None
    parents = document.get("parents") if isinstance(document, dict) else None
    expected_parents = (
        "7e5015092d5a4de3556b252e594c59c72636e7b9",
        repair_commit,
    )
    if (
        not isinstance(document, dict)
        or document.get("sha") != merge_commit
        or not isinstance(tree, dict)
        or not isinstance(tree.get("sha"), str)
        or HEX40.fullmatch(tree["sha"]) is None
        or not isinstance(parents, list)
        or len(parents) != 2
    ):
        _fail("FR0017_CAPTURE_PULL_REQUEST_MERGE")
    normalized_parents = []
    for raw, expected_sha in zip(parents, expected_parents, strict=True):
        expected_url = (
            f"https://api.github.com/repos/{REPOSITORY}/git/commits/{expected_sha}"
        )
        if (
            not isinstance(raw, dict)
            or raw.get("sha") != expected_sha
            or raw.get("url") != expected_url
        ):
            _fail("FR0017_CAPTURE_PULL_REQUEST_MERGE")
        normalized_parents.append({"sha": expected_sha, "url": expected_url})
    api_url = f"https://api.github.com/repos/{REPOSITORY}/git/commits/{merge_commit}"
    if document.get("url") != api_url:
        _fail("FR0017_CAPTURE_PULL_REQUEST_MERGE")
    return {
        "sha": merge_commit,
        "tree": tree["sha"],
        "parents": normalized_parents,
        "api_url": api_url,
    }


def _normalize_run_pull_request_association(
    document: Any,
    *,
    run_id: int,
    number: int,
    database_id: int,
    head_ref: str,
    repair_commit: str,
) -> dict[str, Any]:
    repository = document.get("repository") if isinstance(document, dict) else None
    head_repository = (
        document.get("head_repository") if isinstance(document, dict) else None
    )
    pull_requests = (
        document.get("pull_requests") if isinstance(document, dict) else None
    )
    pull_request = (
        pull_requests[0]
        if isinstance(pull_requests, list) and len(pull_requests) == 1
        else None
    )
    head = pull_request.get("head") if isinstance(pull_request, dict) else None
    base = pull_request.get("base") if isinstance(pull_request, dict) else None
    head_repo = head.get("repo") if isinstance(head, dict) else None
    base_repo = base.get("repo") if isinstance(base, dict) else None
    run_api_url = f"https://api.github.com/repos/{REPOSITORY}/actions/runs/{run_id}"
    pull_api_url = f"https://api.github.com/repos/{REPOSITORY}/pulls/{number}"
    if (
        not isinstance(document, dict)
        or type(document.get("id")) is not int
        or document["id"] != run_id
        or document.get("url") != run_api_url
        or document.get("event") != "pull_request"
        or document.get("head_branch") != head_ref
        or document.get("head_sha") != repair_commit
        or not isinstance(repository, dict)
        or type(repository.get("id")) is not int
        or repository["id"] != 1_292_802_592
        or not isinstance(head_repository, dict)
        or type(head_repository.get("id")) is not int
        or head_repository["id"] != 1_292_802_592
        or not isinstance(pull_request, dict)
        or type(pull_request.get("id")) is not int
        or pull_request["id"] != database_id
        or type(pull_request.get("number")) is not int
        or pull_request["number"] != number
        or pull_request.get("url") != pull_api_url
        or not isinstance(head, dict)
        or not isinstance(base, dict)
        or head.get("ref") != head_ref
        or head.get("sha") != repair_commit
        or base.get("ref") != "main"
        or base.get("sha") != "7e5015092d5a4de3556b252e594c59c72636e7b9"
        or not isinstance(head_repo, dict)
        or not isinstance(base_repo, dict)
        or type(head_repo.get("id")) is not int
        or type(base_repo.get("id")) is not int
        or head_repo["id"] != 1_292_802_592
        or base_repo["id"] != 1_292_802_592
    ):
        _fail("FR0017_CAPTURE_PULL_REQUEST_RUN_ASSOCIATION")
    return {
        "run_id": run_id,
        "run_api_url": run_api_url,
        "pull_request": {
            "number": number,
            "database_id": database_id,
            "api_url": pull_api_url,
            "head": {
                "ref": head_ref,
                "sha": repair_commit,
                "repository_id": head_repo["id"],
            },
            "base": {
                "ref": "main",
                "sha": base["sha"],
                "repository_id": base_repo["id"],
            },
        },
    }


def _validate_open_pull_request_chronology(
    bridge: ModuleType,
    pull_request: dict[str, Any],
    validated_runs: dict[str, dict[str, Any]],
    captured_at_utc: Any,
) -> None:
    """Bind completed PR runs to the interval observed while the PR was open."""

    try:
        created = bridge._parse_utc(
            pull_request["created_at"],
            "pull_request.open_created",
        )
        updated = bridge._parse_utc(
            pull_request["updated_at"],
            "pull_request.open_updated",
        )
        captured = bridge._parse_utc(
            captured_at_utc,
            "pull_request.association_captured",
        )
    except (KeyError, bridge.BridgeError):
        _fail("FR0017_CAPTURE_PULL_REQUEST_SNAPSHOT_CHRONOLOGY")
    if not created <= updated <= captured:
        _fail("FR0017_CAPTURE_PULL_REQUEST_SNAPSHOT_CHRONOLOGY")
    for workflow in ("ci", "formal"):
        run = validated_runs.get(workflow)
        if (
            not isinstance(run, dict)
            or run.get("created") is None
            or run.get("updated") is None
            or run["created"] < created
            or run["updated"] > captured
        ):
            _fail("FR0017_CAPTURE_PULL_REQUEST_SNAPSHOT_CHRONOLOGY")


def _require_repair_head(
    repo: Path,
    bridge: ModuleType,
) -> str:
    repair_commit = (
        _git(
            repo,
            "rev-parse",
            "--verify",
            "HEAD^{commit}",
        )
        .decode()
        .strip()
    )
    try:
        verified = bridge.verify(repo)
    except bridge.BridgeError:
        _fail("FR0017_CAPTURE_PULL_REQUEST_HEAD")
    if (
        verified["head"] != repair_commit
        or verified["repair_commit"] != repair_commit
        or verified["state"] != "PENDING_QUALIFICATION"
    ):
        _fail("FR0017_CAPTURE_PULL_REQUEST_HEAD")
    return repair_commit


def _external_snapshot_path(repo: Path, candidate: Path) -> Path:
    if not candidate.is_absolute() or not candidate.name:
        _fail("FR0017_CAPTURE_PULL_REQUEST_SNAPSHOT_PATH")
    try:
        target = candidate.parent.resolve(strict=True) / candidate.name
    except OSError:
        _fail("FR0017_CAPTURE_PULL_REQUEST_SNAPSHOT_PATH")
    if target.is_relative_to(repo) or target.exists() or target.is_symlink():
        _fail("FR0017_CAPTURE_PULL_REQUEST_SNAPSHOT_PATH")
    return target


def _capture_open_pull_request(
    repo: Path,
    bridge: ModuleType,
    protocol: ModuleType,
    arguments: argparse.Namespace,
) -> None:
    output = _external_snapshot_path(repo, arguments.output)
    repair_commit = _require_repair_head(repo, bridge)
    if arguments.repair_commit != repair_commit:
        _fail("FR0017_CAPTURE_PULL_REQUEST_HEAD")
    executable, _version = bridge._trusted_gh()
    repository_document = _json_bytes(
        _gh(
            bridge,
            executable,
            ("api", "--method", "GET", f"repos/{REPOSITORY}"),
            cwd=repo,
            limit=MAX_JSON_BYTES,
        ),
        "repository",
    )
    repository_identity = _normalize_repository_document(
        repository_document,
        bridge,
    )
    pull_document = _json_bytes(
        _gh(
            bridge,
            executable,
            (
                "api",
                "--method",
                "GET",
                f"repos/{REPOSITORY}/pulls/{arguments.number}",
            ),
            cwd=repo,
            limit=MAX_JSON_BYTES,
        ),
        "pull-request",
    )
    pull_request = _normalize_pull_request_document(
        pull_document,
        repair_commit=repair_commit,
        required_state="open",
    )
    if pull_request["number"] != arguments.number:
        _fail("FR0017_CAPTURE_PULL_REQUEST")
    merge_commit = pull_request["merge_commit_sha"]
    merge_document = _json_bytes(
        _gh(
            bridge,
            executable,
            (
                "api",
                "--method",
                "GET",
                f"repos/{REPOSITORY}/git/commits/{merge_commit}",
            ),
            cwd=repo,
            limit=MAX_JSON_BYTES,
        ),
        "pull-request-merge",
    )
    synthetic_merge = _normalize_synthetic_merge(
        merge_document,
        merge_commit=merge_commit,
        repair_commit=repair_commit,
    )
    run_fields = _run_fields(epoch18=True, attempt=False)
    runs: dict[str, dict[str, Any]] = {}
    validated_runs: dict[str, dict[str, Any]] = {}
    run_pull_request_associations: dict[str, dict[str, Any]] = {}
    for workflow, run_id in (
        ("ci", arguments.ci_run_id),
        ("formal", arguments.formal_run_id),
    ):
        raw = _json_bytes(
            _gh(
                bridge,
                executable,
                (
                    "run",
                    "view",
                    str(run_id),
                    "--repo",
                    REPOSITORY,
                    "--json",
                    run_fields,
                ),
                cwd=repo,
                limit=MAX_JSON_BYTES,
            ),
            f"pull-request-{workflow}-run",
        )
        try:
            validated_runs[workflow] = protocol.validate_pull_request_run_document(
                raw,
                workflow=workflow,
                subject_commit=repair_commit,
                head_branch=pull_request["head"]["ref"],
            )
        except protocol.RecoveryProtocolError:
            _fail("FR0017_CAPTURE_PULL_REQUEST_RUN")
        runs[workflow] = raw
        association_document = _json_bytes(
            _gh(
                bridge,
                executable,
                (
                    "api",
                    "--method",
                    "GET",
                    f"repos/{REPOSITORY}/actions/runs/{run_id}",
                ),
                cwd=repo,
                limit=MAX_JSON_BYTES,
            ),
            f"pull-request-{workflow}-run-association",
        )
        run_pull_request_associations[workflow] = (
            _normalize_run_pull_request_association(
                association_document,
                run_id=run_id,
                number=pull_request["number"],
                database_id=pull_request["database_id"],
                head_ref=pull_request["head"]["ref"],
                repair_commit=repair_commit,
            )
        )
    captured_at_utc = _now()
    _validate_open_pull_request_chronology(
        bridge,
        pull_request,
        validated_runs,
        captured_at_utc,
    )
    snapshot = {
        "schema_version": "1.0.0",
        "protocol": "HALDIR_FR_0017_OPEN_PULL_REQUEST_SNAPSHOT_V1",
        "repository": repository_identity,
        "pull_request": pull_request,
        "synthetic_merge": synthetic_merge,
        "runs": runs,
        "run_pull_request_associations": run_pull_request_associations,
        "capture": {
            "commands": bridge._pull_request_open_capture_commands(
                number=arguments.number,
                merge_commit=merge_commit,
                ci_run_id=arguments.ci_run_id,
                formal_run_id=arguments.formal_run_id,
            ),
            "captured_at_utc": captured_at_utc,
            "transport": "GITHUB_API_OVER_TLS",
            "result": "PASS",
        },
        "authority": {
            "durable_external_state_proof": False,
            "release_authority": False,
            "transport_observation": "GITHUB_API_OVER_TLS",
        },
    }
    _write_exclusive(
        output,
        bridge.canonical_json_bytes(snapshot),
        mode=0o600,
    )
    print(
        "framework-recovery-fr-0017-capture: OK "
        f"(open PR {arguments.number} run associations; snapshot {output}; "
        "close unmerged before final capture; release NO_GO)"
    )


def _validate_open_pull_request_snapshot(
    repo: Path,
    bridge: ModuleType,
    protocol: ModuleType,
    arguments: argparse.Namespace,
) -> tuple[dict[str, Any], bytes]:
    snapshot_path = arguments.open_snapshot
    if not snapshot_path.is_absolute():
        _fail("FR0017_CAPTURE_PULL_REQUEST_SNAPSHOT_PATH")
    try:
        metadata = snapshot_path.lstat()
        resolved_snapshot = snapshot_path.resolve(strict=True)
    except OSError:
        _fail("FR0017_CAPTURE_PULL_REQUEST_SNAPSHOT_PATH")
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) & 0o077
        or metadata.st_uid != os.geteuid()
        or resolved_snapshot.is_relative_to(repo)
    ):
        _fail("FR0017_CAPTURE_PULL_REQUEST_SNAPSHOT_PATH")
    snapshot_payload = _read_regular_bounded(
        snapshot_path,
        limit=MAX_JSON_BYTES,
        label="FR0017_CAPTURE_PULL_REQUEST_SNAPSHOT",
    )
    snapshot = _json_bytes(
        snapshot_payload,
        "open-pull-request-snapshot",
    )
    expected_fields = {
        "authority",
        "capture",
        "protocol",
        "pull_request",
        "repository",
        "run_pull_request_associations",
        "runs",
        "schema_version",
        "synthetic_merge",
    }
    try:
        canonical_snapshot = bridge.canonical_json_bytes(snapshot)
    except (RecursionError, UnicodeEncodeError, ValueError):
        _fail("FR0017_CAPTURE_PULL_REQUEST_SNAPSHOT")
    if (
        snapshot_payload != canonical_snapshot
        or set(snapshot) != expected_fields
        or snapshot["schema_version"] != "1.0.0"
        or snapshot["protocol"] != "HALDIR_FR_0017_OPEN_PULL_REQUEST_SNAPSHOT_V1"
    ):
        _fail("FR0017_CAPTURE_PULL_REQUEST_SNAPSHOT")
    repository = snapshot["repository"]
    try:
        bridge.validate_repository_identity(repository)
    except bridge.BridgeError:
        _fail("FR0017_CAPTURE_PULL_REQUEST_SNAPSHOT")
    pull_request = snapshot["pull_request"]
    pull_fields = {
        "api_url",
        "base",
        "closed_at",
        "created_at",
        "database_id",
        "draft",
        "head",
        "html_url",
        "locked",
        "merge_commit_sha",
        "merged",
        "merged_at",
        "node_id",
        "number",
        "state",
        "updated_at",
    }
    head = pull_request.get("head") if isinstance(pull_request, dict) else None
    base = pull_request.get("base") if isinstance(pull_request, dict) else None
    ref_fields = {"ref", "repository_id", "sha"}
    if (
        not isinstance(pull_request, dict)
        or set(pull_request) != pull_fields
        or type(pull_request.get("number")) is not int
        or pull_request.get("number") != arguments.number
        or not 1 <= pull_request["number"] <= 2**63 - 1
        or type(pull_request.get("database_id")) is not int
        or not 1 <= pull_request["database_id"] <= 2**63 - 1
        or not isinstance(pull_request.get("node_id"), str)
        or not pull_request["node_id"]
        or len(pull_request["node_id"]) > 256
        or pull_request.get("api_url")
        != f"https://api.github.com/repos/{REPOSITORY}/pulls/{arguments.number}"
        or pull_request.get("html_url")
        != f"https://github.com/{REPOSITORY}/pull/{arguments.number}"
        or pull_request.get("state") != "open"
        or type(pull_request.get("draft")) is not bool
        or pull_request.get("draft") is not False
        or type(pull_request.get("locked")) is not bool
        or pull_request.get("locked") is not False
        or type(pull_request.get("merged")) is not bool
        or pull_request.get("merged") is not False
        or pull_request.get("closed_at") is not None
        or pull_request.get("merged_at") is not None
        or not isinstance(head, dict)
        or set(head) != ref_fields
        or not isinstance(base, dict)
        or set(base) != ref_fields
        or type(head.get("repository_id")) is not int
        or type(base.get("repository_id")) is not int
        or head["repository_id"] != 1_292_802_592
        or base
        != {
            "ref": "main",
            "sha": "7e5015092d5a4de3556b252e594c59c72636e7b9",
            "repository_id": 1_292_802_592,
        }
        or head.get("sha") != arguments.repair_commit
        or not isinstance(head.get("ref"), str)
        or re.fullmatch(r"[A-Za-z0-9._/-]+", head["ref"]) is None
        or len(head["ref"].encode("ascii")) > 255
        or head["ref"].startswith("/")
        or head["ref"].endswith("/")
        or ".." in head["ref"]
        or "//" in head["ref"]
        or head["ref"] == "main"
    ):
        _fail("FR0017_CAPTURE_PULL_REQUEST_SNAPSHOT")
    merge_commit = pull_request.get("merge_commit_sha")
    if not isinstance(merge_commit, str) or HEX40.fullmatch(merge_commit) is None:
        _fail("FR0017_CAPTURE_PULL_REQUEST_SNAPSHOT")
    synthetic_merge = snapshot["synthetic_merge"]
    expected_parent_urls = [
        (
            "https://api.github.com/repos/sepahead/haldir/git/commits/"
            "7e5015092d5a4de3556b252e594c59c72636e7b9"
        ),
        (
            "https://api.github.com/repos/sepahead/haldir/git/commits/"
            f"{arguments.repair_commit}"
        ),
    ]
    if (
        not isinstance(synthetic_merge, dict)
        or set(synthetic_merge) != {"api_url", "parents", "sha", "tree"}
        or synthetic_merge.get("sha") != merge_commit
        or synthetic_merge.get("api_url")
        != f"https://api.github.com/repos/{REPOSITORY}/git/commits/{merge_commit}"
        or not isinstance(synthetic_merge.get("tree"), str)
        or HEX40.fullmatch(synthetic_merge["tree"]) is None
        or synthetic_merge.get("parents")
        != [
            {
                "sha": "7e5015092d5a4de3556b252e594c59c72636e7b9",
                "url": expected_parent_urls[0],
            },
            {
                "sha": arguments.repair_commit,
                "url": expected_parent_urls[1],
            },
        ]
    ):
        _fail("FR0017_CAPTURE_PULL_REQUEST_SNAPSHOT")
    runs = snapshot["runs"]
    associations = snapshot["run_pull_request_associations"]
    if (
        not isinstance(runs, dict)
        or set(runs) != {"ci", "formal"}
        or not isinstance(associations, dict)
        or set(associations) != {"ci", "formal"}
    ):
        _fail("FR0017_CAPTURE_PULL_REQUEST_SNAPSHOT")
    validated_runs: dict[str, dict[str, Any]] = {}
    for workflow, run_id in (
        ("ci", arguments.ci_run_id),
        ("formal", arguments.formal_run_id),
    ):
        try:
            validated = protocol.validate_pull_request_run_document(
                runs[workflow],
                workflow=workflow,
                subject_commit=arguments.repair_commit,
                head_branch=pull_request["head"]["ref"],
            )
        except protocol.RecoveryProtocolError:
            _fail("FR0017_CAPTURE_PULL_REQUEST_SNAPSHOT")
        if validated["run_id"] != run_id:
            _fail("FR0017_CAPTURE_PULL_REQUEST_SNAPSHOT")
        validated_runs[workflow] = validated
        try:
            bridge._validate_run_pull_request_association(
                associations[workflow],
                run_id=run_id,
                number=arguments.number,
                database_id=pull_request["database_id"],
                head_ref=pull_request["head"]["ref"],
                repair_commit=arguments.repair_commit,
            )
        except bridge.BridgeError:
            _fail("FR0017_CAPTURE_PULL_REQUEST_SNAPSHOT")
    capture = snapshot["capture"]
    if (
        not isinstance(capture, dict)
        or set(capture) != {"captured_at_utc", "commands", "result", "transport"}
        or capture["commands"]
        != bridge._pull_request_open_capture_commands(
            number=arguments.number,
            merge_commit=merge_commit,
            ci_run_id=arguments.ci_run_id,
            formal_run_id=arguments.formal_run_id,
        )
        or capture["result"] != "PASS"
        or capture["transport"] != "GITHUB_API_OVER_TLS"
    ):
        _fail("FR0017_CAPTURE_PULL_REQUEST_SNAPSHOT")
    _validate_open_pull_request_chronology(
        bridge,
        pull_request,
        validated_runs,
        capture["captured_at_utc"],
    )
    expected_authority = {
        "durable_external_state_proof": False,
        "release_authority": False,
        "transport_observation": "GITHUB_API_OVER_TLS",
    }
    if snapshot["authority"] != expected_authority:
        _fail("FR0017_CAPTURE_PULL_REQUEST_SNAPSHOT")
    return snapshot, snapshot_payload


def _capture_pull_request(
    repo: Path,
    bridge: ModuleType,
    protocol: ModuleType,
    arguments: argparse.Namespace,
) -> None:
    output = repo / bridge.PULL_REQUEST_PATH
    if output.exists() or output.is_symlink():
        _fail("FR0017_CAPTURE_OUTPUT_EXISTS")
    repair_commit = _require_repair_head(repo, bridge)
    if arguments.repair_commit != repair_commit:
        _fail("FR0017_CAPTURE_PULL_REQUEST_HEAD")
    snapshot, _snapshot_payload = _validate_open_pull_request_snapshot(
        repo,
        bridge,
        protocol,
        arguments,
    )
    executable, _version = bridge._trusted_gh()
    repository_document = _json_bytes(
        _gh(
            bridge,
            executable,
            ("api", "--method", "GET", f"repos/{REPOSITORY}"),
            cwd=repo,
            limit=MAX_JSON_BYTES,
        ),
        "closed-repository",
    )
    repository_identity = _normalize_repository_document(
        repository_document,
        bridge,
    )
    pull_document = _json_bytes(
        _gh(
            bridge,
            executable,
            (
                "api",
                "--method",
                "GET",
                f"repos/{REPOSITORY}/pulls/{arguments.number}",
            ),
            cwd=repo,
            limit=MAX_JSON_BYTES,
        ),
        "closed-pull-request",
    )
    pull_request = _normalize_pull_request_document(
        pull_document,
        repair_commit=repair_commit,
        required_state="closed",
    )
    merge_commit = pull_request["merge_commit_sha"]
    merge_document = _json_bytes(
        _gh(
            bridge,
            executable,
            (
                "api",
                "--method",
                "GET",
                f"repos/{REPOSITORY}/git/commits/{merge_commit}",
            ),
            cwd=repo,
            limit=MAX_JSON_BYTES,
        ),
        "closed-pull-request-merge",
    )
    synthetic_merge = _normalize_synthetic_merge(
        merge_document,
        merge_commit=merge_commit,
        repair_commit=repair_commit,
    )
    open_pull_request = snapshot["pull_request"]
    stable_fields = set(pull_request) - {"closed_at", "state", "updated_at"}
    if (
        repository_identity != snapshot["repository"]
        or synthetic_merge != snapshot["synthetic_merge"]
        or any(
            pull_request[field] != open_pull_request[field] for field in stable_fields
        )
    ):
        _fail("FR0017_CAPTURE_PULL_REQUEST_PHASE_DRIFT")
    run_fields = _run_fields(epoch18=True, attempt=False)
    for workflow, run_id in (
        ("ci", arguments.ci_run_id),
        ("formal", arguments.formal_run_id),
    ):
        current = _json_bytes(
            _gh(
                bridge,
                executable,
                (
                    "run",
                    "view",
                    str(run_id),
                    "--repo",
                    REPOSITORY,
                    "--json",
                    run_fields,
                ),
                cwd=repo,
                limit=MAX_JSON_BYTES,
            ),
            f"closed-pull-request-{workflow}-run",
        )
        protocol.validate_pull_request_run_document(
            current,
            workflow=workflow,
            subject_commit=repair_commit,
            head_branch=pull_request["head"]["ref"],
        )
        if current != snapshot["runs"][workflow]:
            _fail("FR0017_CAPTURE_PULL_REQUEST_PHASE_DRIFT")
    value = {
        "schema_version": "1.0.0",
        "protocol": "HALDIR_FR_0017_PULL_REQUEST_QUALIFICATION_V1",
        "repository": repository_identity,
        "pull_request": pull_request,
        "synthetic_merge": synthetic_merge,
        "runs": snapshot["runs"],
        "run_pull_request_associations": {
            "captured_at_utc": snapshot["capture"]["captured_at_utc"],
            "observed_pull_request": open_pull_request,
            "ci": snapshot["run_pull_request_associations"]["ci"],
            "formal": snapshot["run_pull_request_associations"]["formal"],
        },
        "github_event_contract": dict(bridge.PULL_REQUEST_EVENT_CONTRACT),
        "capture": {
            "commands": bridge._pull_request_capture_commands(
                number=arguments.number,
                merge_commit=merge_commit,
                ci_run_id=arguments.ci_run_id,
                formal_run_id=arguments.formal_run_id,
            ),
            "captured_at_utc": _now(),
            "transport": "GITHUB_API_OVER_TLS",
            "result": "PASS",
        },
        "authority": {
            "durable_external_state_proof": False,
            "merge_commit_signature_claimed": False,
            "release_authority": False,
            "transport_observation": "GITHUB_API_OVER_TLS",
        },
    }
    _write_exclusive(output, bridge.canonical_json_bytes(value))
    print(
        "framework-recovery-fr-0017-capture: OK "
        f"(closed unmerged PR {arguments.number}; ci {arguments.ci_run_id}; "
        f"formal {arguments.formal_run_id}; release NO_GO)"
    )


def _http_no_content_status(raw: bytes, *, label: str) -> int:
    normalized = raw.replace(b"\r\n", b"\n")
    header, separator, body = normalized.partition(b"\n\n")
    first_line = header.split(b"\n", 1)[0]
    if (
        not separator
        or body not in {b"", b"\n"}
        or re.fullmatch(rb"HTTP/(?:1\.1|2(?:\.0)?) 204 No Content", first_line) is None
    ):
        _fail(label)
    return 204


def _capture_hosted_settings(
    repo: Path,
    bridge: ModuleType,
    arguments: argparse.Namespace,
) -> None:
    output = repo / bridge.HOSTED_SETTINGS_PATH
    if output.exists() or output.is_symlink():
        _fail("FR0017_CAPTURE_OUTPUT_EXISTS")
    qualification_commit = arguments.qualification_commit
    _commit_tree(repo, qualification_commit)
    executable, _version = bridge._trusted_gh()
    base = f"repos/{REPOSITORY}"

    def document(endpoint: str, label: str) -> dict[str, Any]:
        return _json_bytes(
            _gh(
                bridge,
                executable,
                ("api", "--method", "GET", endpoint),
                cwd=repo,
                limit=MAX_JSON_BYTES,
            ),
            label,
        )

    reference = document(f"{base}/git/ref/heads/main", "settings-main-ref")
    reference_object = reference.get("object")
    if (
        not isinstance(reference_object, dict)
        or reference_object.get("sha") != qualification_commit
    ):
        _fail("FR0017_CAPTURE_SETTINGS_HEAD")
    repository_document = document(base, "settings-repository")
    repository_identity = _normalize_repository_document(
        repository_document,
        bridge,
    )
    security_and_analysis = repository_document.get("security_and_analysis")
    private_reporting = document(
        f"{base}/private-vulnerability-reporting",
        "private-vulnerability-reporting",
    )
    dependabot_updates = document(
        f"{base}/automated-security-fixes",
        "dependabot-security-updates",
    )
    actions_permissions = document(
        f"{base}/actions/permissions",
        "actions-permissions",
    )
    selected_actions = document(
        f"{base}/actions/permissions/selected-actions",
        "selected-actions",
    )
    workflow_permissions = document(
        f"{base}/actions/permissions/workflow",
        "workflow-permissions",
    )
    fork_approval = document(
        f"{base}/actions/permissions/fork-pr-contributor-approval",
        "fork-pr-contributor-approval",
    )
    vulnerability_alerts_status = _http_no_content_status(
        _gh(
            bridge,
            executable,
            (
                "api",
                "--method",
                "GET",
                "--include",
                f"{base}/vulnerability-alerts",
            ),
            cwd=repo,
            limit=MAX_JSON_BYTES,
        ),
        label="FR0017_CAPTURE_VULNERABILITY_ALERTS",
    )
    settings = {
        "actions_permissions": actions_permissions,
        "dependabot_security_updates": dependabot_updates,
        "fork_pull_request_contributor_approval": fork_approval,
        "private_vulnerability_reporting": private_reporting,
        "repository_security_and_analysis": security_and_analysis,
        "selected_actions": selected_actions,
        "vulnerability_alerts": {
            "enabled": True,
            "http_status": vulnerability_alerts_status,
        },
        "workflow_permissions": workflow_permissions,
    }
    boolean_paths = (
        ("actions_permissions", "enabled"),
        ("actions_permissions", "sha_pinning_required"),
        ("dependabot_security_updates", "enabled"),
        ("dependabot_security_updates", "paused"),
        ("private_vulnerability_reporting", "enabled"),
        ("selected_actions", "github_owned_allowed"),
        ("selected_actions", "verified_allowed"),
        ("vulnerability_alerts", "enabled"),
        ("workflow_permissions", "can_approve_pull_request_reviews"),
    )
    if (
        any(
            not isinstance(settings.get(group), dict)
            or type(settings[group].get(field)) is not bool
            for group, field in boolean_paths
        )
        or type(settings["vulnerability_alerts"].get("http_status")) is not int
        or settings != bridge.HOSTED_SETTINGS_EXPECTED_POLICY
    ):
        _fail("FR0017_CAPTURE_HOSTED_SETTINGS_POLICY")
    reference_after = document(
        f"{base}/git/ref/heads/main",
        "settings-main-ref-after",
    )
    if reference_after != reference:
        _fail("FR0017_CAPTURE_SETTINGS_HEAD")
    value = {
        "schema_version": "1.0.0",
        "protocol": "HALDIR_FR_0017_HOSTED_SETTINGS_CAPTURE_V1",
        "repository": repository_identity,
        "observed_commit": qualification_commit,
        "ref_before": reference,
        "ref_after": reference_after,
        "settings": settings,
        "history_scope": dict(bridge.HOSTED_SETTINGS_HISTORY_SCOPE),
        "capture": {
            "commands": bridge._hosted_settings_capture_commands(),
            "captured_at_utc": _now(),
            "transport": "GITHUB_API_OVER_TLS",
            "result": "PASS",
        },
        "authority": {
            "cryptographic_proof": False,
            "durable_external_state_proof": False,
            "release_authority": False,
            "transport_observation": "GITHUB_API_OVER_TLS",
        },
    }
    _write_exclusive(output, bridge.canonical_json_bytes(value))
    print(
        "framework-recovery-fr-0017-capture: OK "
        "(hosted security/settings TLS observation; historical transition "
        "not claimed)"
    )


def _capture_branch_protection(
    repo: Path,
    bridge: ModuleType,
    arguments: argparse.Namespace,
) -> None:
    output = repo / bridge.BRANCH_PROTECTION_PATH
    if output.exists() or output.is_symlink():
        _fail("FR0017_CAPTURE_OUTPUT_EXISTS")
    executable, _version = bridge._trusted_gh()
    reference = _json_bytes(
        _gh(
            bridge,
            executable,
            (
                "api",
                "--method",
                "GET",
                f"repos/{REPOSITORY}/git/ref/heads/main",
            ),
            cwd=repo,
            limit=MAX_JSON_BYTES,
        ),
        "main-ref",
    )
    object_value = reference.get("object")
    observed = object_value.get("sha") if isinstance(object_value, dict) else None
    if observed != arguments.qualification_commit:
        _fail("FR0017_CAPTURE_PROTECTION_HEAD")
    repository_document = _json_bytes(
        _gh(
            bridge,
            executable,
            (
                "api",
                "--method",
                "GET",
                f"repos/{REPOSITORY}",
            ),
            cwd=repo,
            limit=MAX_JSON_BYTES,
        ),
        "repository",
    )
    repository_identity = _normalize_repository_document(
        repository_document,
        bridge,
    )
    protection = _json_bytes(
        _gh(
            bridge,
            executable,
            (
                "api",
                "--method",
                "GET",
                f"repos/{REPOSITORY}/branches/main/protection",
            ),
            cwd=repo,
            limit=MAX_JSON_BYTES,
        ),
        "protection",
    )
    ruleset_list = _json_list(
        _gh(
            bridge,
            executable,
            (
                "api",
                "--method",
                "GET",
                f"repos/{REPOSITORY}/rulesets",
            ),
            cwd=repo,
            limit=MAX_JSON_BYTES,
        ),
        "ruleset-list",
    )
    ruleset_matches = [
        item
        for item in ruleset_list
        if isinstance(item, dict)
        and item.get("name") == "haldir-main-writer-allowlist"
        and item.get("target") == "branch"
        and item.get("enforcement") == "active"
    ]
    if len(ruleset_matches) != 1:
        _fail("FR0017_CAPTURE_RULESET_UNIQUENESS")
    ruleset_id = ruleset_matches[0].get("id")
    if type(ruleset_id) is not int or ruleset_id < 1:
        _fail("FR0017_CAPTURE_RULESET_ID")
    ruleset_by_id = _json_bytes(
        _gh(
            bridge,
            executable,
            (
                "api",
                "--method",
                "GET",
                f"repos/{REPOSITORY}/rulesets/{ruleset_id}",
            ),
            cwd=repo,
            limit=MAX_JSON_BYTES,
        ),
        "ruleset-id",
    )
    effective_rules = _json_list(
        _gh(
            bridge,
            executable,
            (
                "api",
                "--method",
                "GET",
                f"repos/{REPOSITORY}/rules/branches/main",
            ),
            cwd=repo,
            limit=MAX_JSON_BYTES,
        ),
        "effective-rules",
    )
    ruleset_history = _json_list(
        _gh(
            bridge,
            executable,
            (
                "api",
                "--method",
                "GET",
                f"repos/{REPOSITORY}/rulesets/{ruleset_id}/history",
            ),
            cwd=repo,
            limit=MAX_JSON_BYTES,
        ),
        "ruleset-history",
    )
    if (
        len(ruleset_history) != 1
        or not isinstance(ruleset_history[0], dict)
        or type(ruleset_history[0].get("version_id")) is not int
        or ruleset_history[0]["version_id"] < 1
    ):
        _fail("FR0017_CAPTURE_RULESET_HISTORY")
    version_id = ruleset_history[0]["version_id"]
    ruleset_version = _json_bytes(
        _gh(
            bridge,
            executable,
            (
                "api",
                "--method",
                "GET",
                (f"repos/{REPOSITORY}/rulesets/{ruleset_id}/history/{version_id}"),
            ),
            cwd=repo,
            limit=MAX_JSON_BYTES,
        ),
        "ruleset-version",
    )
    try:
        bridge.validate_branch_protection_get(protection)
        bridge.validate_main_writer_ruleset(
            repository_identity,
            ruleset_list,
            ruleset_by_id,
            effective_rules,
            ruleset_history,
            ruleset_version,
        )
    except bridge.BridgeError:
        _fail("FR0017_CAPTURE_BRANCH_CONTROL_VALIDATION")
    reference_after = _json_bytes(
        _gh(
            bridge,
            executable,
            (
                "api",
                "--method",
                "GET",
                f"repos/{REPOSITORY}/git/ref/heads/main",
            ),
            cwd=repo,
            limit=MAX_JSON_BYTES,
        ),
        "main-ref-after",
    )
    object_after = reference_after.get("object")
    observed_after = object_after.get("sha") if isinstance(object_after, dict) else None
    if observed_after != arguments.qualification_commit:
        _fail("FR0017_CAPTURE_PROTECTION_HEAD")
    value = {
        "schema_version": "1.0.0",
        "protocol": "HALDIR_FR_0017_BRANCH_PROTECTION_CAPTURE_V1",
        "repository": repository_identity,
        "branch": "main",
        "observed_commit": observed,
        "ref_before": reference,
        "ref_after": reference_after,
        "protection": protection,
        "ruleset_list": ruleset_list,
        "ruleset_by_id": ruleset_by_id,
        "effective_rules": effective_rules,
        "ruleset_history": ruleset_history,
        "ruleset_version": ruleset_version,
        "capture": {
            "commit_before_command": (
                f"gh api --method GET repos/{REPOSITORY}/git/ref/heads/main"
            ),
            "commit_after_command": (
                f"gh api --method GET repos/{REPOSITORY}/git/ref/heads/main"
            ),
            "protection_command": (
                f"gh api --method GET repos/{REPOSITORY}/branches/main/protection"
            ),
            "repository_command": f"gh api --method GET repos/{REPOSITORY}",
            "ruleset_list_command": (
                f"gh api --method GET repos/{REPOSITORY}/rulesets"
            ),
            "ruleset_get_command": (
                f"gh api --method GET repos/{REPOSITORY}/rulesets/{ruleset_id}"
            ),
            "ruleset_history_command": (
                f"gh api --method GET repos/{REPOSITORY}/rulesets/{ruleset_id}/history"
            ),
            "ruleset_version_command": (
                f"gh api --method GET repos/{REPOSITORY}/rulesets/"
                f"{ruleset_id}/history/{version_id}"
            ),
            "effective_rules_command": (
                f"gh api --method GET repos/{REPOSITORY}/rules/branches/main"
            ),
            "captured_at_utc": _now(),
            "transport": "GITHUB_API_OVER_TLS",
            "result": "PASS",
        },
        "authority": {
            "cryptographic_proof": False,
            "durable_external_state_proof": False,
            "release_authority": False,
            "transport_observation": "GITHUB_API_OVER_TLS",
        },
    }
    _write_exclusive(output, bridge.canonical_json_bytes(value))
    print(
        "framework-recovery-fr-0017-capture: OK "
        "(branch protection TLS observation; non-cryptographic)"
    )


def _assemble_signed_record(
    repo: Path,
    bridge: ModuleType,
    arguments: argparse.Namespace,
) -> None:
    contracts = {
        "plan": (bridge.PLAN_PATH, bridge.PLAN_NAMESPACE),
        "qualification": (
            bridge.QUALIFICATION_PATH,
            bridge.QUALIFICATION_NAMESPACE,
        ),
        "activation": (
            bridge.ACTIVATION_PATH,
            bridge.ACTIVATION_NAMESPACE,
        ),
    }
    output_path, namespace = contracts[arguments.stage]
    output = repo / output_path
    if output.exists() or output.is_symlink():
        _fail("FR0017_CAPTURE_OUTPUT_EXISTS")
    unsigned = _read_regular_bounded(
        arguments.unsigned,
        limit=MAX_JSON_BYTES,
        label="FR0017_CAPTURE_UNSIGNED_RECORD",
    )
    signature_payload = _read_regular_bounded(
        arguments.signature,
        limit=16 * 1024,
        label="FR0017_CAPTURE_RECORD_SIGNATURE",
    )
    try:
        value = json.loads(unsigned)
        signature = signature_payload.decode("ascii")
        canonical = bridge.canonical_json_bytes(value)
    except (
        RecursionError,
        UnicodeDecodeError,
        UnicodeEncodeError,
        ValueError,
        json.JSONDecodeError,
    ):
        _fail("FR0017_CAPTURE_UNSIGNED_RECORD")
    expected = bridge.expected_record_for_provisional(
        repo,
        stage=arguments.stage,
        provisional_commit=arguments.provisional_commit,
    )
    if (
        not isinstance(value, dict)
        or "detached_signature" in value
        or canonical != unsigned
        or value != expected
    ):
        _fail("FR0017_CAPTURE_UNSIGNED_RECORD")
    detached_signature = {
        "format": "ssh",
        "namespace": namespace,
        "principal": bridge.SIGNER_PRINCIPAL,
        "key_fingerprint": bridge.SIGNER_FINGERPRINT,
        "signature": signature,
    }
    bridge._verify_detached(
        repo,
        detached_signature,
        unsigned,
        namespace=namespace,
    )
    signed = {**value, "detached_signature": detached_signature}
    _write_exclusive(output, bridge.canonical_json_bytes(signed))
    print(
        "framework-recovery-fr-0017-capture: OK "
        f"({arguments.stage} signed record assembled and verified)"
    )


def _validated_local_executable(
    repo: Path,
    candidate: Path,
    *,
    label: str,
) -> tuple[Path, bytes]:
    """Resolve, bound, and read one non-repository executable."""

    try:
        resolved = candidate.resolve(strict=True)
        metadata = resolved.stat(follow_symlinks=False)
    except OSError:
        _fail(label)
    if (
        resolved.is_relative_to(repo)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        or not os.access(resolved, os.X_OK)
    ):
        _fail(label)
    payload = _read_regular_bounded(
        resolved,
        limit=MAX_LOCAL_TOOL_BYTES,
        label=label,
    )
    return resolved, payload


def _resolve_local_cargo(
    repo: Path,
    bridge: ModuleType,
) -> tuple[Path, dict[str, Any]]:
    """Resolve the exact 1.96.0 Cargo binary used by local validation."""

    candidate = shutil.which("rustup")
    if candidate is None:
        _fail("FR0017_CAPTURE_LOCAL_RUSTUP")
    rustup, rustup_payload = _validated_local_executable(
        repo,
        Path(candidate),
        label="FR0017_CAPTURE_LOCAL_RUSTUP",
    )
    resolver_environment = {
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }
    for name in ("HOME", "RUSTUP_HOME"):
        value = os.environ.get(name)
        if value is not None:
            resolver_environment[name] = value
    resolver_argv = (
        str(rustup),
        "which",
        "--toolchain",
        "1.96.0",
        "cargo",
    )
    returncode, stdout, stderr = bridge._run_bounded(
        resolver_argv,
        cwd=repo,
        env=resolver_environment,
        timeout_seconds=30,
        output_limit=64 * 1024,
    )
    if returncode != 0 or stderr or stdout.count(b"\n") != 1:
        _fail("FR0017_CAPTURE_LOCAL_CARGO")
    try:
        cargo_candidate = Path(stdout.decode("utf-8").removesuffix("\n"))
    except UnicodeDecodeError:
        _fail("FR0017_CAPTURE_LOCAL_CARGO")
    if not cargo_candidate.is_absolute():
        _fail("FR0017_CAPTURE_LOCAL_CARGO")
    cargo, cargo_payload = _validated_local_executable(
        repo,
        cargo_candidate,
        label="FR0017_CAPTURE_LOCAL_CARGO",
    )
    cargo_environment = {
        "LC_ALL": "C",
        "PATH": f"{cargo.parent}:/usr/bin:/bin",
        "RUSTUP_TOOLCHAIN": "1.96.0",
    }
    returncode, version_stdout, version_stderr = bridge._run_bounded(
        (str(cargo), "--version"),
        cwd=repo,
        env=cargo_environment,
        timeout_seconds=30,
        output_limit=64 * 1024,
    )
    if (
        returncode != 0
        or version_stderr
        or re.fullmatch(rb"cargo 1\.96\.0 \([0-9a-f]+ [^)]+\)\n", version_stdout)
        is None
    ):
        _fail("FR0017_CAPTURE_LOCAL_CARGO")
    version = version_stdout.decode("ascii").removesuffix("\n")
    return cargo, {
        "toolchain": "1.96.0",
        "version": version,
        "executable": {
            "path": str(cargo),
            "bytes": len(cargo_payload),
            "sha256": hashlib.sha256(cargo_payload).hexdigest(),
        },
        "resolver": {
            "argv": list(resolver_argv),
            "executable": {
                "path": str(rustup),
                "bytes": len(rustup_payload),
                "sha256": hashlib.sha256(rustup_payload).hexdigest(),
            },
        },
    }


def _capture_local(
    repo: Path,
    bridge: ModuleType,
    arguments: argparse.Namespace,
) -> None:
    output = repo / bridge.LOCAL_PATH
    if output.exists() or output.is_symlink():
        _fail("FR0017_CAPTURE_OUTPUT_EXISTS")
    repair_commit = arguments.repair_commit
    if (
        _git(repo, "rev-parse", "--verify", "HEAD^{commit}").decode().strip()
        != repair_commit
    ):
        _fail("FR0017_CAPTURE_LOCAL_HEAD")
    _require_clean_worktree(
        repo,
        label="FR0017_CAPTURE_LOCAL_WORKTREE",
    )
    python = Path(sys.executable).resolve(strict=True)
    cargo, cargo_record = _resolve_local_cargo(repo, bridge)
    commands = (
        (
            str(python),
            "-I",
            "-B",
            "-W",
            "error",
            "tools/release/test_verify_framework_recovery_fr_0017.py",
        ),
        (
            str(python),
            "-I",
            "-B",
            "-W",
            "error",
            "tools/test_pinned_cargo_deny.py",
        ),
        (
            str(python),
            "-I",
            "-B",
            "-W",
            "error",
            "tools/test_run_formal.py",
        ),
        (
            str(python),
            "-I",
            "-B",
            "-W",
            "error",
            "tools/verify-pins.py",
        ),
        (
            str(python),
            "-I",
            "-B",
            "-W",
            "error",
            "tools/verify-ci-pins.py",
        ),
        (
            str(python),
            "-I",
            "-B",
            "-W",
            "error",
            "tools/release/verify-framework-recovery-fr-0017.py",
        ),
        (
            "/bin/bash",
            "-n",
            "tools/release/current-audit-gate.sh",
        ),
        (
            "/usr/bin/git",
            "-c",
            "core.hooksPath=/dev/null",
            "diff",
            "--check",
            f"{bridge.PARENT}..{repair_commit}",
        ),
    )
    environment = {
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "LC_ALL": "C",
        "PATH": f"{python.parent}:{cargo.parent}:/usr/bin:/bin",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONHASHSEED": "0",
        "RUSTUP_TOOLCHAIN": "1.96.0",
    }
    if "HALDIR_FR0017_GH" in os.environ:
        environment["HALDIR_FR0017_GH"] = os.environ["HALDIR_FR0017_GH"]
    if "RUNNER_TEMP" in os.environ:
        environment["RUNNER_TEMP"] = os.environ["RUNNER_TEMP"]
    checks = []
    for command in commands:
        returncode, stdout, stderr = bridge._run_bounded(
            command,
            cwd=repo,
            env=environment,
            timeout_seconds=180,
            output_limit=4 * 1024 * 1024,
        )
        if type(returncode) is not int or returncode != 0:
            _fail("FR0017_CAPTURE_LOCAL_COMMAND")
        checks.append(
            {
                "argv": list(command),
                "returncode": 0,
                "stdout_bytes": len(stdout),
                "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
                "stderr_bytes": len(stderr),
                "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
                "result": "PASS",
            }
        )
    value = {
        "schema_version": "1.0.0",
        "protocol": "HALDIR_FR_0017_LOCAL_VALIDATION_V1",
        "subject_commit": repair_commit,
        "subject_tree": _commit_tree(repo, repair_commit),
        "capture_tool": bridge.file_record(repo, repair_commit, bridge.CAPTURE_PATH),
        "python": {
            "implementation": sys.implementation.name,
            "version": (
                f"{sys.version_info.major}.{sys.version_info.minor}."
                f"{sys.version_info.micro}"
            ),
        },
        "cargo": cargo_record,
        "checks": checks,
        "completed_at_utc": _now(),
        "result": "PASS",
        "authority": bridge._authority("PENDING_QUALIFICATION"),
    }
    _write_exclusive(output, bridge.canonical_json_bytes(value))
    print("framework-recovery-fr-0017-capture: OK (local R validation; release NO_GO)")


def _verify_root(
    repo: Path,
    bridge: ModuleType,
) -> None:
    executable, version = bridge._trusted_gh()
    raw = _gh(
        bridge,
        executable,
        ("attestation", "trusted-root"),
        cwd=repo,
        limit=bridge.MAX_TRUSTED_ROOT_BYTES,
        timeout=120,
    )
    matches: list[bytes] = []
    for line in raw.splitlines(keepends=True):
        try:
            value = json.loads(line)
        except (UnicodeDecodeError, json.JSONDecodeError):
            _fail("FR0017_CAPTURE_TRUSTED_ROOT")
        tlogs = value.get("tlogs", []) if isinstance(value, dict) else []
        if {item.get("baseUrl") for item in tlogs if isinstance(item, dict)} == {
            "https://rekor.sigstore.dev",
            "https://log2025-1.rekor.sigstore.dev",
        }:
            matches.append(line)
    expected = (repo / bridge.TRUSTED_ROOT_PATH).read_bytes()
    if matches != [expected]:
        _fail("FR0017_CAPTURE_TRUSTED_ROOT_DRIFT")
    bridge._validate_trusted_root(expected)
    print(
        "framework-recovery-fr-0017-capture: OK "
        f"(TUF Public Good root matches R pin; {version.splitlines()[0]})"
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    hosted = subparsers.add_parser("hosted")
    hosted.add_argument("--stage", choices=("repair", "qualification"), required=True)
    hosted.add_argument("--workflow", choices=("ci", "formal"), required=True)
    hosted.add_argument("--run-id", type=int, required=True)
    hosted.add_argument("--repair-commit", required=True)
    hosted.add_argument("--subject-commit", required=True)
    pull_request_open = subparsers.add_parser("pull-request-open")
    pull_request_open.add_argument("--number", type=int, required=True)
    pull_request_open.add_argument("--repair-commit", required=True)
    pull_request_open.add_argument("--ci-run-id", type=int, required=True)
    pull_request_open.add_argument("--formal-run-id", type=int, required=True)
    pull_request_open.add_argument("--output", type=Path, required=True)
    pull_request = subparsers.add_parser("pull-request")
    pull_request.add_argument("--number", type=int, required=True)
    pull_request.add_argument("--repair-commit", required=True)
    pull_request.add_argument("--ci-run-id", type=int, required=True)
    pull_request.add_argument("--formal-run-id", type=int, required=True)
    pull_request.add_argument("--open-snapshot", type=Path, required=True)
    protection = subparsers.add_parser("branch-protection")
    protection.add_argument("--qualification-commit", required=True)
    settings = subparsers.add_parser("hosted-settings")
    settings.add_argument("--qualification-commit", required=True)
    record = subparsers.add_parser("signed-record")
    record.add_argument(
        "--stage",
        choices=("plan", "qualification", "activation"),
        required=True,
    )
    record.add_argument("--provisional-commit", required=True)
    record.add_argument("--unsigned", type=Path, required=True)
    record.add_argument("--signature", type=Path, required=True)
    local = subparsers.add_parser("local")
    local.add_argument("--repair-commit", required=True)
    subparsers.add_parser("verify-root")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        repo = _repository()
        bridge = _load_module(repo / BRIDGE_PATH, "_haldir_fr0017_capture_bridge")
        protocol = _load_module(repo / PROTOCOL_PATH, "_haldir_fr0017_capture_protocol")
        if arguments.command == "hosted":
            _capture_hosted(repo, bridge, protocol, arguments)
        elif arguments.command == "pull-request-open":
            _capture_open_pull_request(repo, bridge, protocol, arguments)
        elif arguments.command == "pull-request":
            _capture_pull_request(repo, bridge, protocol, arguments)
        elif arguments.command == "branch-protection":
            _capture_branch_protection(repo, bridge, arguments)
        elif arguments.command == "hosted-settings":
            _capture_hosted_settings(repo, bridge, arguments)
        elif arguments.command == "signed-record":
            _assemble_signed_record(repo, bridge, arguments)
        elif arguments.command == "local":
            _capture_local(repo, bridge, arguments)
        elif arguments.command == "verify-root":
            _verify_root(repo, bridge)
        else:
            _fail("FR0017_CAPTURE_COMMAND")
    except (
        CaptureError,
        OSError,
        RecursionError,
        UnicodeDecodeError,
        UnicodeEncodeError,
        ValueError,
        subprocess.TimeoutExpired,
    ) as error:
        print(f"framework-recovery-fr-0017-capture: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
