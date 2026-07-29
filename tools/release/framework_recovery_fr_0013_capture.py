#!/usr/bin/env python3
"""Capture bounded FR-0013 evidence using exact GitHub identities.

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
BRIDGE_PATH = "tools/release/verify-framework-recovery-fr-0013.py"
PROTOCOL_PATH = "tools/release/framework_recovery_fr_0013.py"


class CaptureError(RuntimeError):
    """One fail-closed capture error."""


def _fail(code: str) -> None:
    raise CaptureError(code)


def _load_module(path: Path, name: str) -> ModuleType:
    specification = importlib.util.spec_from_file_location(name, path)
    if specification is None or specification.loader is None:
        _fail("FR0013_CAPTURE_MODULE")
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
        _fail("FR0013_CAPTURE_GIT:" + (arguments[0] if arguments else "missing"))
    return completed.stdout


def _repository() -> Path:
    raw = _git(Path.cwd(), "rev-parse", "--show-toplevel", limit=64 * 1024)
    try:
        return Path(raw.decode("utf-8").strip()).resolve(strict=True)
    except (OSError, UnicodeDecodeError):
        _fail("FR0013_CAPTURE_REPOSITORY")


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
        _fail("FR0013_CAPTURE_GH:" + (arguments[0] if arguments else "missing"))
    return stdout


def _json_bytes(raw: bytes, label: str) -> dict[str, Any]:
    if not raw or len(raw) > MAX_JSON_BYTES or b"\0" in raw:
        _fail("FR0013_CAPTURE_JSON:" + label)
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        _fail("FR0013_CAPTURE_JSON:" + label)
    if not isinstance(value, dict):
        _fail("FR0013_CAPTURE_JSON:" + label)
    return value


def _json_list(raw: bytes, label: str) -> list[Any]:
    if not raw or len(raw) > MAX_JSON_BYTES or b"\0" in raw:
        _fail("FR0013_CAPTURE_JSON:" + label)
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        _fail("FR0013_CAPTURE_JSON:" + label)
    if not isinstance(value, list):
        _fail("FR0013_CAPTURE_JSON:" + label)
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
                _fail("FR0013_CAPTURE_WRITE")
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
        _fail("FR0013_CAPTURE_COMMIT")
    value = _git(repo, "rev-parse", "--verify", f"{commit}^{{tree}}").decode().strip()
    if HEX40.fullmatch(value) is None:
        _fail("FR0013_CAPTURE_COMMIT")
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
    _fail("FR0013_CAPTURE_STAGE")


def _run_fields(*, epoch14: bool, attempt: bool) -> str:
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
    if epoch14:
        fields.append("number")
    if attempt:
        fields.append("startedAt")
    fields.extend(("status", "updatedAt", "url"))
    if attempt or epoch14:
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
        _fail("FR0013_CAPTURE_OUTPUT_EXISTS")
    if arguments.run_id < 1:
        _fail("FR0013_CAPTURE_RUN_ID")
    repair_commit = arguments.repair_commit
    subject_commit = arguments.subject_commit
    _commit_tree(repo, repair_commit)
    subject_tree = _commit_tree(repo, subject_commit)
    executable, _version = bridge._trusted_gh()
    ordinary_fields = _run_fields(epoch14=True, attempt=False)
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
        or not 1 <= attempt_number <= protocol.MAX_EPOCH14_RUN_ATTEMPT
    ):
        _fail("FR0013_CAPTURE_ATTEMPT")
    attempt_fields = _run_fields(epoch14=True, attempt=True)
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
    run = protocol.validate_epoch14_run_documents(
        ordinary,
        attempt,
        workflow=workflow,
        subject_commit=subject_commit,
        expected_ref="refs/heads/main",
    )
    artifact_name = f"epoch-14-{workflow}-result-attempt-{attempt_number}.json"
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
        _fail("FR0013_CAPTURE_ARTIFACT_ID")
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
        _fail("FR0013_CAPTURE_ARTIFACT_IDENTITY")
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
        _fail("FR0013_CAPTURE_DIRECT_ARTIFACT")
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
    with tempfile.TemporaryDirectory(prefix="haldir-fr0013-download-") as name:
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
            _fail("FR0013_CAPTURE_ATTESTATION_FILE")
        bundle_payload = _read_regular_bounded(
            bundles[0],
            limit=MAX_BUNDLE_BYTES,
            label="FR0013_CAPTURE_ATTESTATION_BOUND",
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
        "protocol": "HALDIR_FR_0013_HOSTED_RESULT_CAPTURE_V1",
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
        "framework-recovery-fr-0013-capture: OK "
        f"({arguments.stage}; {workflow}; run {run['run_id']}; "
        f"attempt {run['attempt']}; artifact {artifact_id})"
    )


def _capture_branch_protection(
    repo: Path,
    bridge: ModuleType,
    arguments: argparse.Namespace,
) -> None:
    output = repo / bridge.BRANCH_PROTECTION_PATH
    if output.exists() or output.is_symlink():
        _fail("FR0013_CAPTURE_OUTPUT_EXISTS")
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
        _fail("FR0013_CAPTURE_PROTECTION_HEAD")
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
        _fail("FR0013_CAPTURE_RULESET_UNIQUENESS")
    ruleset_id = ruleset_matches[0].get("id")
    if type(ruleset_id) is not int or ruleset_id < 1:
        _fail("FR0013_CAPTURE_RULESET_ID")
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
        _fail("FR0013_CAPTURE_PROTECTION_HEAD")
    value = {
        "schema_version": "1.0.0",
        "protocol": "HALDIR_FR_0013_BRANCH_PROTECTION_CAPTURE_V1",
        "repository": REPOSITORY,
        "repository_id": 1_292_802_592,
        "branch": "main",
        "observed_commit": observed,
        "ref_before": reference,
        "ref_after": reference_after,
        "protection": protection,
        "ruleset_list": ruleset_list,
        "ruleset_by_id": ruleset_by_id,
        "effective_rules": effective_rules,
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
            "ruleset_list_command": (
                f"gh api --method GET repos/{REPOSITORY}/rulesets"
            ),
            "ruleset_get_command": (
                f"gh api --method GET repos/{REPOSITORY}/rulesets/{ruleset_id}"
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
        "framework-recovery-fr-0013-capture: OK "
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
        _fail("FR0013_CAPTURE_OUTPUT_EXISTS")
    unsigned = _read_regular_bounded(
        arguments.unsigned,
        limit=MAX_JSON_BYTES,
        label="FR0013_CAPTURE_UNSIGNED_RECORD",
    )
    signature_payload = _read_regular_bounded(
        arguments.signature,
        limit=16 * 1024,
        label="FR0013_CAPTURE_RECORD_SIGNATURE",
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
        _fail("FR0013_CAPTURE_UNSIGNED_RECORD")
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
        _fail("FR0013_CAPTURE_UNSIGNED_RECORD")
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
        "framework-recovery-fr-0013-capture: OK "
        f"({arguments.stage} signed record assembled and verified)"
    )


def _capture_local(
    repo: Path,
    bridge: ModuleType,
    arguments: argparse.Namespace,
) -> None:
    output = repo / bridge.LOCAL_PATH
    if output.exists() or output.is_symlink():
        _fail("FR0013_CAPTURE_OUTPUT_EXISTS")
    repair_commit = arguments.repair_commit
    if (
        _git(repo, "rev-parse", "--verify", "HEAD^{commit}").decode().strip()
        != repair_commit
    ):
        _fail("FR0013_CAPTURE_LOCAL_HEAD")
    python = Path(sys.executable).resolve(strict=True)
    commands = (
        (
            str(python),
            "-I",
            "-B",
            "-W",
            "error",
            "tools/release/test_verify_framework_recovery_fr_0013.py",
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
            "tools/release/verify-framework-recovery-fr-0013.py",
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
        "PATH": f"{python.parent}:/usr/bin:/bin",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONHASHSEED": "0",
    }
    if "HALDIR_FR0013_GH" in os.environ:
        environment["HALDIR_FR0013_GH"] = os.environ["HALDIR_FR0013_GH"]
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
            _fail("FR0013_CAPTURE_LOCAL_COMMAND")
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
        "protocol": "HALDIR_FR_0013_LOCAL_VALIDATION_V1",
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
        "checks": checks,
        "completed_at_utc": _now(),
        "result": "PASS",
        "authority": bridge._authority("PENDING_QUALIFICATION"),
    }
    _write_exclusive(output, bridge.canonical_json_bytes(value))
    print("framework-recovery-fr-0013-capture: OK (local R validation; release NO_GO)")


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
            _fail("FR0013_CAPTURE_TRUSTED_ROOT")
        tlogs = value.get("tlogs", []) if isinstance(value, dict) else []
        if {item.get("baseUrl") for item in tlogs if isinstance(item, dict)} == {
            "https://rekor.sigstore.dev",
            "https://log2025-1.rekor.sigstore.dev",
        }:
            matches.append(line)
    expected = (repo / bridge.TRUSTED_ROOT_PATH).read_bytes()
    if matches != [expected]:
        _fail("FR0013_CAPTURE_TRUSTED_ROOT_DRIFT")
    bridge._validate_trusted_root(expected)
    print(
        "framework-recovery-fr-0013-capture: OK "
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
    protection = subparsers.add_parser("branch-protection")
    protection.add_argument("--qualification-commit", required=True)
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
        bridge = _load_module(repo / BRIDGE_PATH, "_haldir_fr0013_capture_bridge")
        protocol = _load_module(repo / PROTOCOL_PATH, "_haldir_fr0013_capture_protocol")
        if arguments.command == "hosted":
            _capture_hosted(repo, bridge, protocol, arguments)
        elif arguments.command == "branch-protection":
            _capture_branch_protection(repo, bridge, arguments)
        elif arguments.command == "signed-record":
            _assemble_signed_record(repo, bridge, arguments)
        elif arguments.command == "local":
            _capture_local(repo, bridge, arguments)
        elif arguments.command == "verify-root":
            _verify_root(repo, bridge)
        else:
            _fail("FR0013_CAPTURE_COMMAND")
    except (
        CaptureError,
        OSError,
        UnicodeDecodeError,
        subprocess.TimeoutExpired,
    ) as error:
        print(f"framework-recovery-fr-0013-capture: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
