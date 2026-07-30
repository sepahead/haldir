#!/usr/bin/env python3
"""Pure validation primitives for the FR-0015 epoch-16 recovery.

The central audit verifier loads these exact bytes from the signed repair commit.
This module deliberately has no repository, network, subprocess, or filesystem
authority.  Machine-readable result artifacts and OIDC attestations are normative.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any


RESULT_PROTOCOL = "HALDIR_EPOCH_16_HOSTED_RESULT_V1"
REPOSITORY = "sepahead/haldir"
REPOSITORY_ID = 1_292_802_592
REPOSITORY_OWNER_ID = 10_104_569
MAX_MATERIAL_BYTES = 8 * 1024 * 1024
MAX_ATTESTATION_BUNDLE_BYTES = 1024 * 1024
TIMESTAMP_SKEW_SECONDS = 1
MAX_EPOCH16_RUN_ATTEMPT = 8
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
JOB_NAME = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
CI_JOB_NAMES = frozenset(
    {
        "build-test",
        "clean-build",
        "feature-matrix",
        "interop",
        "macos-compile",
        "supply-chain",
    }
)
FORMAL_JOB_NAMES = frozenset({"tlc-model-check"})
EPOCH16_CI_JOB_NAMES = CI_JOB_NAMES | frozenset({"attest-ci-audit-result"})
EPOCH16_FORMAL_JOB_NAMES = FORMAL_JOB_NAMES | frozenset({"attest-formal-audit-result"})
RESULT_CONTRACT = {
    "ci": {
        "workflow_path": ".github/workflows/ci.yml",
        "job": "supply-chain",
        "command": (
            "/usr/bin/env -u BASH_ENV -u ENV /bin/bash --noprofile "
            "--norc tools/release/current-audit-gate.sh"
        ),
        "material_paths": (
            "Cargo.lock",
            ".github/workflows/ci.yml",
            ".github/workflows/formal.yml",
            "deny.toml",
            "rust-toolchain.toml",
            "tools/pins.toml",
            "tools/pinned_cargo_deny.py",
            "tools/test_pinned_cargo_deny.py",
            "tools/verify-pins.py",
            "tools/verify-ci-pins.py",
            "tools/release/current-audit-gate.sh",
            "tools/release/framework_recovery_fr_0015.py",
            "tools/release/framework_recovery_fr_0015_result.py",
            "tools/release/test_verify_framework_recovery_fr_0015.py",
            "tools/release/verify-framework-recovery-fr-0015.py",
        ),
    },
    "formal": {
        "workflow_path": ".github/workflows/formal.yml",
        "job": "tlc-model-check",
        "command": (
            "java -XX:+UseParallelGC -cp tla2tools.jar tlc2.TLC "
            "-workers auto -config formal/HaldirAuthority.cfg "
            "formal/HaldirAuthority.tla"
        ),
        "material_paths": (
            ".github/workflows/formal.yml",
            "formal/HaldirAuthority.cfg",
            "formal/HaldirAuthority.tla",
            "tools/pins.toml",
            "tools/release/framework_recovery_fr_0015.py",
            "tools/release/framework_recovery_fr_0015_result.py",
            "tools/release/verify-framework-recovery-fr-0015.py",
        ),
    },
}
COMMON_RUN_FIELDS = frozenset(
    {
        "conclusion",
        "createdAt",
        "databaseId",
        "event",
        "headBranch",
        "headSha",
        "jobs",
        "status",
        "updatedAt",
        "url",
        "workflowName",
    }
)
ORDINARY_RUN_FIELDS = COMMON_RUN_FIELDS | {"attempt"}
ATTEMPT_RUN_FIELDS = COMMON_RUN_FIELDS | {
    "attempt",
    "startedAt",
    "workflowDatabaseId",
}
EPOCH16_ORDINARY_RUN_FIELDS = ORDINARY_RUN_FIELDS | {
    "number",
    "workflowDatabaseId",
}
EPOCH16_ATTEMPT_RUN_FIELDS = ATTEMPT_RUN_FIELDS | {"number"}
WORKFLOW_DATABASE_IDS = {"ci": 311_605_710, "formal": 311_703_244}
JOB_FIELDS = frozenset(
    {
        "completedAt",
        "conclusion",
        "databaseId",
        "name",
        "startedAt",
        "status",
        "steps",
        "url",
    }
)
STEP_FIELDS = frozenset(
    {
        "completedAt",
        "conclusion",
        "name",
        "number",
        "startedAt",
        "status",
    }
)


class RecoveryProtocolError(ValueError):
    """One fail-closed FR-0015 validation error."""


def _fail(code: str) -> None:
    raise RecoveryProtocolError(code)


def canonical_json_bytes(value: Any, *, pretty: bool = False) -> bytes:
    """Return the sole accepted UTF-8 JSON representation."""

    separators = (",", ": ") if pretty else (",", ":")
    indent = 2 if pretty else None
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            indent=indent,
            separators=separators,
        )
        + ("\n" if pretty else "")
    ).encode("utf-8")


def sha256(payload: bytes) -> str:
    """Return the lowercase SHA-256 digest of bytes."""

    if type(payload) is not bytes:
        _fail("FR0015_BYTES_REQUIRED")
    return hashlib.sha256(payload).hexdigest()


def _parse_utc(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        _fail("FR0015_TIMESTAMP:" + label)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        _fail("FR0015_TIMESTAMP:" + label)
    if parsed.tzinfo != timezone.utc:
        _fail("FR0015_TIMESTAMP:" + label)
    return parsed


def _require_dict(value: Any, fields: frozenset[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        _fail("FR0015_FIELDS:" + label)
    return value


def _bounded_int(value: Any, *, minimum: int, maximum: int, label: str) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        _fail("FR0015_INTEGER:" + label)
    return value


def _validate_step(
    value: Any,
    *,
    run_start: datetime,
    run_end: datetime,
    label: str,
) -> dict[str, Any]:
    step = _require_dict(value, STEP_FIELDS, label)
    number = _bounded_int(step["number"], minimum=1, maximum=10_000, label=label)
    if (
        not isinstance(step["name"], str)
        or not step["name"].strip()
        or len(step["name"].encode("utf-8")) > 1_024
        or step["status"] != "completed"
        or step["conclusion"] != "success"
    ):
        _fail("FR0015_STEP:" + label)
    started = _parse_utc(step["startedAt"], label + ".started")
    completed = _parse_utc(step["completedAt"], label + ".completed")
    tolerance = timedelta(seconds=TIMESTAMP_SKEW_SECONDS)
    if (
        started > completed
        or started < run_start - tolerance
        or completed > run_end + tolerance
    ):
        _fail("FR0015_STEP_TIME:" + label)
    return {
        "number": number,
        "name": step["name"],
        "started": started,
        "completed": completed,
    }


def _validate_jobs(
    jobs: Any,
    *,
    expected_names: frozenset[str],
    expected_run_id: int,
    run_start: datetime,
    run_end: datetime,
    label: str,
) -> dict[str, dict[str, Any]]:
    if not isinstance(jobs, list) or len(jobs) != len(expected_names):
        _fail("FR0015_JOBS:" + label)
    result: dict[str, dict[str, Any]] = {}
    job_ids: set[int] = set()
    for index, raw in enumerate(jobs):
        job = _require_dict(raw, JOB_FIELDS, f"{label}.{index}")
        name = job["name"]
        database_id = _bounded_int(
            job["databaseId"],
            minimum=1,
            maximum=2**63 - 1,
            label=f"{label}.{index}.database_id",
        )
        if (
            not isinstance(name, str)
            or JOB_NAME.fullmatch(name) is None
            or name in result
            or database_id in job_ids
            or job["status"] != "completed"
            or job["conclusion"] != "success"
            or job["url"]
            != f"https://github.com/sepahead/haldir/actions/runs/"
            f"{expected_run_id}"
            f"/job/{database_id}"
        ):
            _fail("FR0015_JOB:" + f"{label}.{index}")
        started = _parse_utc(job["startedAt"], f"{label}.{index}.started")
        completed = _parse_utc(job["completedAt"], f"{label}.{index}.completed")
        if started > completed or started < run_start or completed > run_end:
            _fail("FR0015_JOB_TIME:" + f"{label}.{index}")
        steps = [
            _validate_step(
                step,
                run_start=started,
                run_end=completed,
                label=f"{label}.{index}.step.{step_index}",
            )
            for step_index, step in enumerate(job["steps"])
        ]
        numbers = [step["number"] for step in steps]
        if not steps or len(numbers) != len(set(numbers)):
            _fail("FR0015_JOB_STEPS:" + f"{label}.{index}")
        result[name] = {
            "database_id": database_id,
            "started": started,
            "completed": completed,
            "steps": steps,
        }
        job_ids.add(database_id)
    if set(result) != expected_names:
        _fail("FR0015_JOB_SET:" + label)
    return result


def validate_epoch16_run_documents(
    ordinary: Any,
    attempt: Any,
    *,
    workflow: str,
    subject_commit: str,
    expected_ref: str,
) -> dict[str, Any]:
    """Validate a successful epoch-16 run, including its OIDC attestation job."""

    if (
        workflow not in {"ci", "formal"}
        or HEX40.fullmatch(subject_commit) is None
        or re.fullmatch(r"refs/heads/[A-Za-z0-9._/-]+", expected_ref) is None
        or ".." in expected_ref
        or "//" in expected_ref
    ):
        _fail("FR0015_EPOCH16_RUN_IDENTITY")
    ordinary = _require_dict(ordinary, EPOCH16_ORDINARY_RUN_FIELDS, "epoch16.ordinary")
    attempt = _require_dict(attempt, EPOCH16_ATTEMPT_RUN_FIELDS, "epoch16.attempt")
    run_id = _bounded_int(
        ordinary["databaseId"],
        minimum=1,
        maximum=2**63 - 1,
        label="epoch16.run_id",
    )
    attempt_number = _bounded_int(
        attempt["attempt"],
        minimum=1,
        maximum=MAX_EPOCH16_RUN_ATTEMPT,
        label="epoch16.attempt_number",
    )
    ordinary_attempt = _bounded_int(
        ordinary["attempt"],
        minimum=1,
        maximum=MAX_EPOCH16_RUN_ATTEMPT,
        label="epoch16.ordinary_attempt",
    )
    attempt_run_id = _bounded_int(
        attempt["databaseId"],
        minimum=1,
        maximum=2**63 - 1,
        label="epoch16.attempt_run_id",
    )
    expected_url = f"https://github.com/{REPOSITORY}/actions/runs/{run_id}"
    expected_branch = expected_ref.removeprefix("refs/heads/")
    run_number = _bounded_int(
        ordinary["number"],
        minimum=1,
        maximum=2**63 - 1,
        label="epoch16.run_number",
    )
    attempt_run_number = _bounded_int(
        attempt["number"],
        minimum=1,
        maximum=2**63 - 1,
        label="epoch16.attempt_run_number",
    )
    ordinary_workflow_id = _bounded_int(
        ordinary["workflowDatabaseId"],
        minimum=1,
        maximum=2**63 - 1,
        label="epoch16.ordinary_workflow_id",
    )
    attempt_workflow_id = _bounded_int(
        attempt["workflowDatabaseId"],
        minimum=1,
        maximum=2**63 - 1,
        label="epoch16.attempt_workflow_id",
    )
    common = {
        "conclusion": "success",
        "databaseId": run_id,
        "event": "push",
        "headBranch": expected_branch,
        "headSha": subject_commit,
        "status": "completed",
        "workflowName": workflow,
    }
    if (
        ordinary_attempt != attempt_number
        or attempt_run_id != run_id
        or ordinary["number"] != run_number
        or attempt_run_number != run_number
        or ordinary_workflow_id != WORKFLOW_DATABASE_IDS[workflow]
        or attempt_workflow_id != WORKFLOW_DATABASE_IDS[workflow]
        or ordinary["url"] != expected_url
        or attempt["url"] != f"{expected_url}/attempts/{attempt_number}"
        or any(ordinary[key] != value for key, value in common.items())
        or any(attempt[key] != value for key, value in common.items())
    ):
        _fail("FR0015_EPOCH16_RUN_METADATA")
    for key in COMMON_RUN_FIELDS - {"createdAt", "jobs", "updatedAt", "url"}:
        if ordinary[key] != attempt[key]:
            _fail("FR0015_EPOCH16_RUN_ATTEMPT_MISMATCH:" + key)
    created = _parse_utc(ordinary["createdAt"], "epoch16.ordinary.created")
    ordinary_updated = _parse_utc(ordinary["updatedAt"], "epoch16.ordinary.updated")
    attempt_created = _parse_utc(attempt["createdAt"], "epoch16.attempt.created")
    attempt_started = _parse_utc(attempt["startedAt"], "epoch16.attempt.started")
    attempt_updated = _parse_utc(attempt["updatedAt"], "epoch16.attempt.updated")
    if (
        created > ordinary_updated
        or attempt_created < created
        or attempt_started < created
        or attempt_created > ordinary_updated
        or attempt_started > ordinary_updated
        or attempt_created > attempt_updated
        or attempt_started > attempt_updated
        or ordinary_updated > attempt_updated
        or (attempt_number == 1 and created != attempt_created)
        or (
            attempt_number > 1
            and (created >= attempt_created or created >= attempt_started)
        )
    ):
        _fail("FR0015_EPOCH16_RUN_CHRONOLOGY")
    expected_jobs = (
        EPOCH16_CI_JOB_NAMES if workflow == "ci" else EPOCH16_FORMAL_JOB_NAMES
    )
    _validate_jobs(
        ordinary["jobs"],
        expected_names=expected_jobs,
        expected_run_id=run_id,
        run_start=created,
        run_end=ordinary_updated,
        label="epoch16.ordinary.jobs",
    )
    attempt_jobs = _validate_jobs(
        attempt["jobs"],
        expected_names=expected_jobs,
        expected_run_id=run_id,
        run_start=created,
        run_end=attempt_updated,
        label="epoch16.attempt.jobs",
    )
    if canonical_json_bytes(ordinary["jobs"]) != canonical_json_bytes(attempt["jobs"]):
        _fail("FR0015_EPOCH16_RUN_JOB_MISMATCH")
    producer_job = RESULT_CONTRACT[workflow]["job"]
    attestation_job = (
        "attest-ci-audit-result" if workflow == "ci" else "attest-formal-audit-result"
    )
    if (
        producer_job not in attempt_jobs
        or attestation_job not in attempt_jobs
        or attempt_jobs[producer_job]["started"] < attempt_started
        or attempt_jobs[attestation_job]["started"] < attempt_started
        or attempt_jobs[producer_job]["completed"] > attempt_updated
        or attempt_jobs[attestation_job]["completed"] > attempt_updated
    ):
        _fail("FR0015_EPOCH16_CURRENT_ATTEMPT_JOBS")
    return {
        "run_id": run_id,
        "attempt": attempt_number,
        "run_number": run_number,
        "created": created,
        "started": attempt_started,
        "updated": attempt_updated,
        "jobs": attempt_jobs,
        "attestation_job": attestation_job,
    }


def validate_artifact_listing(value: Any) -> dict[str, Any]:
    """Validate one exact, unique GitHub Actions artifact listing."""

    listing = _require_dict(
        value,
        frozenset({"artifacts", "total_count"}),
        "artifact_listing",
    )
    total_count = _bounded_int(
        listing["total_count"],
        minimum=1,
        maximum=1,
        label="artifact_listing.total_count",
    )
    artifacts = listing["artifacts"]
    if (
        total_count != 1
        or not isinstance(artifacts, list)
        or len(artifacts) != 1
        or not isinstance(artifacts[0], dict)
    ):
        _fail("FR0015_ARTIFACT_LISTING")
    return copy.deepcopy(artifacts[0])


def _validate_file_record(value: Any, *, expected_path: str) -> dict[str, Any]:
    record = _require_dict(
        value,
        frozenset(
            {
                "path",
                "git_mode",
                "git_object_type",
                "git_object_id",
                "sha256",
                "bytes",
            }
        ),
        "file_record." + expected_path,
    )
    if (
        record["path"] != expected_path
        or record["git_mode"] not in {"100644", "100755"}
        or record["git_object_type"] != "blob"
        or not isinstance(record["git_object_id"], str)
        or HEX40.fullmatch(record["git_object_id"]) is None
        or not isinstance(record["sha256"], str)
        or HEX64.fullmatch(record["sha256"]) is None
        or type(record["bytes"]) is not int
        or not 1 <= record["bytes"] <= MAX_MATERIAL_BYTES
    ):
        _fail("FR0015_FILE_RECORD:" + expected_path)
    return copy.deepcopy(record)


def validate_result_artifact(
    payload: bytes,
    *,
    workflow: str,
    subject_commit: str,
    subject_tree: str,
    run_id: int,
    attempt: int,
    run_number: int,
    expected_ref: str,
    expected_materials: list[dict[str, Any]],
) -> dict[str, Any]:
    """Validate one canonical machine-readable hosted result artifact."""

    if (
        type(payload) is not bytes
        or not 1 <= len(payload) <= 256 * 1024
        or b"\0" in payload
    ):
        _fail("FR0015_RESULT_BOUND")
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError):
        _fail("FR0015_RESULT_JSON")
    if (
        not isinstance(value, dict)
        or canonical_json_bytes(value, pretty=True) != payload
        or set(value)
        != {
            "schema_version",
            "protocol",
            "repository",
            "subject",
            "execution",
            "materials",
            "authority",
        }
        or value["schema_version"] != "1.0.0"
        or value["protocol"] != RESULT_PROTOCOL
    ):
        _fail("FR0015_RESULT_SCHEMA")
    contract = RESULT_CONTRACT.get(workflow)
    if (
        contract is None
        or HEX40.fullmatch(subject_commit) is None
        or HEX40.fullmatch(subject_tree) is None
        or type(run_id) is not int
        or run_id < 1
        or type(attempt) is not int
        or attempt < 1
        or type(run_number) is not int
        or run_number < 1
        or not isinstance(expected_ref, str)
        or re.fullmatch(r"refs/heads/[A-Za-z0-9._/-]+", expected_ref) is None
        or ".." in expected_ref
        or "//" in expected_ref
    ):
        _fail("FR0015_RESULT_IDENTITY")
    repository = _require_dict(
        value["repository"],
        frozenset({"name", "database_id", "owner_database_id"}),
        "result.repository",
    )
    if (
        type(repository["database_id"]) is not int
        or type(repository["owner_database_id"]) is not int
        or repository
        != {
            "name": REPOSITORY,
            "database_id": REPOSITORY_ID,
            "owner_database_id": REPOSITORY_OWNER_ID,
        }
    ):
        _fail("FR0015_RESULT_REPOSITORY")
    subject = _require_dict(
        value["subject"],
        frozenset({"commit", "tree", "ref", "event"}),
        "result.subject",
    )
    if (
        subject["commit"] != subject_commit
        or subject["tree"] != subject_tree
        or subject["ref"] != expected_ref
        or subject["event"] != "push"
    ):
        _fail("FR0015_RESULT_SUBJECT")
    execution = _require_dict(
        value["execution"],
        frozenset(
            {
                "workflow",
                "workflow_ref",
                "job",
                "run_id",
                "run_attempt",
                "run_number",
                "command",
                "result",
            }
        ),
        "result.execution",
    )
    if (
        execution["workflow"] != workflow
        or execution["workflow_ref"]
        != f"{REPOSITORY}/{contract['workflow_path']}@{expected_ref}"
        or execution["job"] != contract["job"]
        or type(execution["run_id"]) is not int
        or execution["run_id"] != run_id
        or type(execution["run_attempt"]) is not int
        or execution["run_attempt"] != attempt
        or type(execution["run_number"]) is not int
        or execution["run_number"] != run_number
        or execution["command"] != contract["command"]
        or execution["result"] != "PASS"
    ):
        _fail("FR0015_RESULT_EXECUTION")
    if not isinstance(expected_materials, list) or len(expected_materials) != len(
        contract["material_paths"]
    ):
        _fail("FR0015_RESULT_EXPECTED_MATERIALS")
    normalized_expected = [
        _validate_file_record(item, expected_path=path)
        for item, path in zip(
            expected_materials, contract["material_paths"], strict=True
        )
    ]
    materials = value["materials"]
    if not isinstance(materials, list) or len(materials) != len(normalized_expected):
        _fail("FR0015_RESULT_MATERIALS")
    normalized_observed = [
        _validate_file_record(item, expected_path=path)
        for item, path in zip(materials, contract["material_paths"], strict=True)
    ]
    if canonical_json_bytes(normalized_observed) != canonical_json_bytes(
        normalized_expected
    ):
        _fail("FR0015_RESULT_MATERIAL_DRIFT")
    expected_authority = {
        "provenance_only": True,
        "release_authority": False,
        "deployment_authority": False,
        "publication_authority": False,
        "tag_authority": False,
    }
    authority = _require_dict(
        value["authority"],
        frozenset(expected_authority),
        "result.authority",
    )
    if (
        any(type(authority[key]) is not bool for key in expected_authority)
        or authority != expected_authority
    ):
        _fail("FR0015_RESULT_AUTHORITY")
    return copy.deepcopy(value)


def validate_artifact_metadata(
    value: Any,
    *,
    workflow: str,
    run_id: int,
    attempt: int,
    subject_commit: str,
    result_payload: bytes,
    producer_started: datetime,
    producer_completed: datetime,
    attestation_started: datetime,
) -> dict[str, Any]:
    """Validate the REST identity for one unarchived immutable result artifact."""

    fields = frozenset(
        {
            "archive_download_url",
            "created_at",
            "digest",
            "expired",
            "expires_at",
            "id",
            "name",
            "node_id",
            "size_in_bytes",
            "updated_at",
            "url",
            "workflow_run",
        }
    )
    artifact = _require_dict(value, fields, "artifact")
    if workflow not in RESULT_CONTRACT:
        _fail("FR0015_ARTIFACT_WORKFLOW")
    artifact_id = _bounded_int(
        artifact["id"],
        minimum=1,
        maximum=2**63 - 1,
        label="artifact.id",
    )
    _bounded_int(
        run_id,
        minimum=1,
        maximum=2**63 - 1,
        label="artifact.run_id",
    )
    _bounded_int(
        attempt,
        minimum=1,
        maximum=MAX_EPOCH16_RUN_ATTEMPT,
        label="artifact.attempt",
    )
    artifact_name = f"epoch-16-{workflow}-result-attempt-{attempt}.json"
    digest = sha256(result_payload)
    if (
        artifact["name"] != artifact_name
        or type(artifact["size_in_bytes"]) is not int
        or artifact["size_in_bytes"] != len(result_payload)
        or artifact["digest"] != "sha256:" + digest
        or artifact["expired"] is not False
        or artifact["url"]
        != f"https://api.github.com/repos/{REPOSITORY}/actions/artifacts/{artifact_id}"
        or artifact["archive_download_url"] != artifact["url"] + "/zip"
        or not isinstance(artifact["node_id"], str)
        or not artifact["node_id"]
        or len(artifact["node_id"]) > 256
    ):
        _fail("FR0015_ARTIFACT_IDENTITY")
    created = _parse_utc(artifact["created_at"], "artifact.created")
    updated = _parse_utc(artifact["updated_at"], "artifact.updated")
    expires = _parse_utc(artifact["expires_at"], "artifact.expires")
    tolerance = timedelta(seconds=TIMESTAMP_SKEW_SECONDS)
    if (
        not created <= updated < expires
        or created < producer_started - tolerance
        or updated > producer_completed + tolerance
        or updated > attestation_started + tolerance
    ):
        _fail("FR0015_ARTIFACT_CHRONOLOGY")
    workflow_run = _require_dict(
        artifact["workflow_run"],
        frozenset(
            {
                "head_branch",
                "head_repository_id",
                "head_sha",
                "id",
                "repository_id",
            }
        ),
        "artifact.workflow_run",
    )
    if (
        type(workflow_run["head_repository_id"]) is not int
        or type(workflow_run["id"]) is not int
        or type(workflow_run["repository_id"]) is not int
        or workflow_run
        != {
            "head_branch": "main",
            "head_repository_id": REPOSITORY_ID,
            "head_sha": subject_commit,
            "id": run_id,
            "repository_id": REPOSITORY_ID,
        }
    ):
        _fail("FR0015_ARTIFACT_RUN_BINDING")
    return copy.deepcopy(artifact)


def _parse_attestation_bundle(payload: bytes) -> dict[str, Any]:
    if (
        type(payload) is not bytes
        or not 1 <= len(payload) <= MAX_ATTESTATION_BUNDLE_BYTES
        or b"\0" in payload
        or payload.count(b"\n") != 1
        or not payload.endswith(b"\n")
    ):
        _fail("FR0015_ATTESTATION_BUNDLE_BOUND")
    try:
        bundle = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError):
        _fail("FR0015_ATTESTATION_BUNDLE_JSON")
    if (
        not isinstance(bundle, dict)
        or set(bundle)
        != {
            "mediaType",
            "verificationMaterial",
            "dsseEnvelope",
        }
        or bundle["mediaType"] != "application/vnd.dev.sigstore.bundle.v0.3+json"
    ):
        _fail("FR0015_ATTESTATION_BUNDLE_SCHEMA")
    envelope = _require_dict(
        bundle["dsseEnvelope"],
        frozenset({"payload", "payloadType", "signatures"}),
        "attestation.envelope",
    )
    signatures = envelope["signatures"]
    if (
        envelope["payloadType"] != "application/vnd.in-toto+json"
        or not isinstance(signatures, list)
        or len(signatures) != 1
        or not isinstance(signatures[0], dict)
        or set(signatures[0]) != {"sig"}
        or not isinstance(signatures[0]["sig"], str)
        or not signatures[0]["sig"]
    ):
        _fail("FR0015_ATTESTATION_ENVELOPE")
    try:
        decoded = base64.b64decode(envelope["payload"], validate=True)
        statement = json.loads(decoded)
    except (
        TypeError,
        ValueError,
        UnicodeDecodeError,
        json.JSONDecodeError,
    ):
        _fail("FR0015_ATTESTATION_STATEMENT")
    if not isinstance(statement, dict):
        _fail("FR0015_ATTESTATION_STATEMENT")
    return {"bundle": bundle, "statement": statement}


def _expected_attestation_statement(
    *,
    workflow: str,
    result_digest: str,
    subject_commit: str,
    expected_ref: str,
    run_id: int,
    attempt: int,
) -> dict[str, Any]:
    contract = RESULT_CONTRACT[workflow]
    workflow_identity = (
        f"https://github.com/{REPOSITORY}/{contract['workflow_path']}@{expected_ref}"
    )
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [
            {
                "name": (f"epoch-16-{workflow}-result-attempt-{attempt}.json"),
                "digest": {"sha256": result_digest},
            }
        ],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": "https://actions.github.io/buildtypes/workflow/v1",
                "externalParameters": {
                    "workflow": {
                        "ref": expected_ref,
                        "repository": f"https://github.com/{REPOSITORY}",
                        "path": contract["workflow_path"],
                    }
                },
                "internalParameters": {
                    "github": {
                        "event_name": "push",
                        "repository_id": str(REPOSITORY_ID),
                        "repository_owner_id": str(REPOSITORY_OWNER_ID),
                        "runner_environment": "github-hosted",
                    }
                },
                "resolvedDependencies": [
                    {
                        "uri": (f"git+https://github.com/{REPOSITORY}@{expected_ref}"),
                        "digest": {"gitCommit": subject_commit},
                    }
                ],
            },
            "runDetails": {
                "builder": {"id": workflow_identity},
                "metadata": {
                    "invocationId": (
                        f"https://github.com/{REPOSITORY}/actions/runs/"
                        f"{run_id}/attempts/{attempt}"
                    )
                },
            },
        },
    }


def validate_attestation_evidence(
    bundle_payload: bytes,
    verification_receipt: Any,
    *,
    workflow: str,
    result_payload: bytes,
    subject_commit: str,
    expected_ref: str,
    run_id: int,
    attempt: int,
    attestation_started: datetime,
    attestation_completed: datetime,
) -> dict[str, Any]:
    """Validate exact downloaded bundle bytes and strict gh verification output."""

    if (
        workflow not in RESULT_CONTRACT
        or type(run_id) is not int
        or run_id < 1
        or type(attempt) is not int
        or not 1 <= attempt <= MAX_EPOCH16_RUN_ATTEMPT
    ):
        _fail("FR0015_ATTESTATION_IDENTITY")
    parsed = _parse_attestation_bundle(bundle_payload)
    expected_statement = _expected_attestation_statement(
        workflow=workflow,
        result_digest=sha256(result_payload),
        subject_commit=subject_commit,
        expected_ref=expected_ref,
        run_id=run_id,
        attempt=attempt,
    )
    if canonical_json_bytes(parsed["statement"]) != canonical_json_bytes(
        expected_statement
    ):
        _fail("FR0015_ATTESTATION_STATEMENT_MISMATCH")
    if (
        not isinstance(verification_receipt, list)
        or len(verification_receipt) != 1
        or not isinstance(verification_receipt[0], dict)
        or set(verification_receipt[0]) != {"attestation", "verificationResult"}
    ):
        _fail("FR0015_ATTESTATION_RECEIPT")
    item = verification_receipt[0]
    attestation = _require_dict(
        item["attestation"],
        frozenset({"bundle", "bundle_url", "initiator"}),
        "attestation.receipt.bundle",
    )
    if (
        canonical_json_bytes(attestation["bundle"])
        != canonical_json_bytes(parsed["bundle"])
        or attestation["bundle_url"] != ""
        or attestation["initiator"] != ""
    ):
        _fail("FR0015_ATTESTATION_RECEIPT_BUNDLE")
    result = item["verificationResult"]
    if (
        not isinstance(result, dict)
        or result.get("mediaType")
        != "application/vnd.dev.sigstore.verificationresult+json;version=0.1"
        or canonical_json_bytes(result.get("statement"))
        != canonical_json_bytes(expected_statement)
        or not isinstance(result.get("verifiedTimestamps"), list)
        or len(result["verifiedTimestamps"]) != 1
    ):
        _fail("FR0015_ATTESTATION_VERIFICATION_RESULT")
    timestamp = result["verifiedTimestamps"][0]
    if (
        not isinstance(timestamp, dict)
        or set(timestamp) != {"timestamp", "type", "uri"}
        or timestamp["type"] != "Tlog"
        or not isinstance(timestamp["uri"], str)
        or timestamp["uri"]
        not in {
            "https://rekor.sigstore.dev",
            "https://log2025-1.rekor.sigstore.dev",
        }
    ):
        _fail("FR0015_ATTESTATION_TRANSPARENCY_LOG")
    witnessed = _parse_utc(
        timestamp["timestamp"], "attestation.transparency_log.timestamp"
    )
    tolerance = timedelta(seconds=TIMESTAMP_SKEW_SECONDS)
    if (
        witnessed < attestation_started - tolerance
        or witnessed > attestation_completed + tolerance
    ):
        _fail("FR0015_ATTESTATION_TRANSPARENCY_LOG_TIME")
    signature = result.get("signature")
    certificate = signature.get("certificate") if isinstance(signature, dict) else None
    contract = RESULT_CONTRACT[workflow]
    workflow_identity = (
        f"https://github.com/{REPOSITORY}/{contract['workflow_path']}@{expected_ref}"
    )
    run_identity = (
        f"https://github.com/{REPOSITORY}/actions/runs/{run_id}/attempts/{attempt}"
    )
    expected_certificate = {
        "subjectAlternativeName": workflow_identity,
        "issuer": "https://token.actions.githubusercontent.com",
        "githubWorkflowTrigger": "push",
        "githubWorkflowSHA": subject_commit,
        "githubWorkflowName": workflow,
        "githubWorkflowRepository": REPOSITORY,
        "githubWorkflowRef": expected_ref,
        "buildSignerURI": workflow_identity,
        "buildSignerDigest": subject_commit,
        "runnerEnvironment": "github-hosted",
        "sourceRepositoryURI": f"https://github.com/{REPOSITORY}",
        "sourceRepositoryDigest": subject_commit,
        "sourceRepositoryRef": expected_ref,
        "sourceRepositoryIdentifier": str(REPOSITORY_ID),
        "sourceRepositoryOwnerURI": "https://github.com/sepahead",
        "sourceRepositoryOwnerIdentifier": str(REPOSITORY_OWNER_ID),
        "buildConfigURI": workflow_identity,
        "buildConfigDigest": subject_commit,
        "buildTrigger": "push",
        "runInvocationURI": run_identity,
        "sourceRepositoryVisibilityAtSigning": "public",
    }
    if not isinstance(certificate, dict) or any(
        certificate.get(key) != value for key, value in expected_certificate.items()
    ):
        _fail("FR0015_ATTESTATION_CERTIFICATE")
    return {
        "bundle_sha256": sha256(bundle_payload),
        "bundle_bytes": len(bundle_payload),
        "statement": copy.deepcopy(expected_statement),
        "certificate_policy": expected_certificate,
        "verified_timestamp_count": len(result["verifiedTimestamps"]),
        "transparency_log": copy.deepcopy(timestamp),
        "provider_provenance_independently_attested": True,
        "release_authority_conferred": False,
    }
