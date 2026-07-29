#!/usr/bin/env python3
"""Pure validation primitives for the FR-0011 epoch-12 recovery.

The central audit verifier loads these exact bytes from the signed repair commit.
This module deliberately has no repository, network, subprocess, or filesystem
authority.  Machine-readable result artifacts and OIDC attestations are normative.
Bounded GitHub whole-job archives are accepted only to reproduce the c5/FR-0010
defect; they are not an epoch-12 PASS oracle.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import io
import json
import re
import stat
import zipfile
from datetime import datetime, timedelta, timezone
from typing import Any


C5_ARCHIVE_PROTOCOL = "HALDIR_FR_0011_C5_WHOLE_JOB_ARCHIVE_V1"
RESULT_PROTOCOL = "HALDIR_EPOCH_12_HOSTED_RESULT_V1"
REVIEW_REQUEST_PROTOCOL = "HALDIR_FR_0011_REVIEW_REQUEST_V1"
REVIEW_RESPONSE_PROTOCOL = "HALDIR_FR_0011_REVIEW_RESPONSE_V1"
REPOSITORY = "sepahead/haldir"
REPOSITORY_ID = 1_292_802_592
REPOSITORY_OWNER_ID = 10_104_569
MAX_ARCHIVE_BYTES = 2 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 32
MAX_ARCHIVE_ENTRY_BYTES = 4 * 1024 * 1024
MAX_ARCHIVE_TOTAL_BYTES = 8 * 1024 * 1024
MAX_COMPRESSION_RATIO = 1_000
MAX_REVIEW_REQUEST_BYTES = 1024 * 1024
MAX_REVIEW_RESPONSE_BYTES = 1024 * 1024
MAX_PROVIDER_RESPONSE_BYTES = 2 * 1024 * 1024
TIMESTAMP_SKEW_SECONDS = 1
MAX_EPOCH12_RUN_ATTEMPT = 8
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
JOB_NAME = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
ARCHIVE_JOB = re.compile(
    r"^(?P<index>0|[1-9][0-9]*)_(?P<job>[a-z0-9][a-z0-9-]{0,62})\.txt$"
)
LOG_LINE = re.compile(
    rb"^(?P<timestamp>[0-9]{4}-[0-9]{2}-[0-9]{2}T"
    rb"[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z) "
    rb"(?P<body>[^\r\n]*)$"
)
RUN_MARKER = re.compile(
    rb"^Ran (?P<count>0|[1-9][0-9]*) tests? in [0-9]+(?:\.[0-9]+)?s$"
)
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
EPOCH12_CI_JOB_NAMES = CI_JOB_NAMES | frozenset({"attest-ci-audit-result"})
EPOCH12_FORMAL_JOB_NAMES = FORMAL_JOB_NAMES | frozenset({"attest-formal-audit-result"})
RESULT_CONTRACT = {
    "ci": {
        "workflow_path": ".github/workflows/ci.yml",
        "job": "supply-chain",
        "command": (
            "/usr/bin/env -u BASH_ENV -u ENV /bin/bash --noprofile "
            "--norc tools/release/current-audit-gate.sh"
        ),
        "material_paths": (
            ".github/workflows/ci.yml",
            "tools/release/current-audit-gate.sh",
            "tools/release/framework_recovery_fr_0011.py",
            "tools/release/framework_recovery_fr_0011_result.py",
            "tools/release/verify-framework-recovery-fr-0011.py",
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
            "tools/release/framework_recovery_fr_0011_result.py",
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
EPOCH12_ORDINARY_RUN_FIELDS = ORDINARY_RUN_FIELDS | {
    "number",
    "workflowDatabaseId",
}
EPOCH12_ATTEMPT_RUN_FIELDS = ATTEMPT_RUN_FIELDS | {"number"}
WORKFLOW_DATABASE_IDS = {"ci": 311_605_710, "formal": 311_703_244}
C5_RUN_IDS = {"ci": 30_301_664_607, "formal": 30_301_664_692}
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
FAILURE_TOKENS = (
    b"FAILED",
    b"ERROR",
    b"Traceback",
    b"ResourceWarning",
    b"##[error]",
    b"skipped=",
    b"expected failure",
    b"unexpected success",
)
REVIEW_FINDING_ID = re.compile(r"^(?:F|B)[0-9]{3}$")
REPOSITORY_PATH = re.compile(
    r"^(?!/)(?!.*(?:^|/)\.\.(?:/|$))(?!.*//)"
    r"[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*$"
)


class RecoveryProtocolError(ValueError):
    """One fail-closed FR-0011 validation error."""


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
        _fail("FR0011_BYTES_REQUIRED")
    return hashlib.sha256(payload).hexdigest()


def _parse_utc(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        _fail("FR0011_TIMESTAMP:" + label)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        _fail("FR0011_TIMESTAMP:" + label)
    if parsed.tzinfo != timezone.utc:
        _fail("FR0011_TIMESTAMP:" + label)
    return parsed


def _require_dict(value: Any, fields: frozenset[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        _fail("FR0011_FIELDS:" + label)
    return value


def _bounded_int(value: Any, *, minimum: int, maximum: int, label: str) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        _fail("FR0011_INTEGER:" + label)
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
        _fail("FR0011_STEP:" + label)
    started = _parse_utc(step["startedAt"], label + ".started")
    completed = _parse_utc(step["completedAt"], label + ".completed")
    tolerance = timedelta(seconds=TIMESTAMP_SKEW_SECONDS)
    if (
        started > completed
        or started < run_start - tolerance
        or completed > run_end + tolerance
    ):
        _fail("FR0011_STEP_TIME:" + label)
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
        _fail("FR0011_JOBS:" + label)
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
            _fail("FR0011_JOB:" + f"{label}.{index}")
        started = _parse_utc(job["startedAt"], f"{label}.{index}.started")
        completed = _parse_utc(job["completedAt"], f"{label}.{index}.completed")
        tolerance = timedelta(seconds=TIMESTAMP_SKEW_SECONDS)
        if (
            started > completed
            or started < run_start - tolerance
            or completed > run_end + tolerance
        ):
            _fail("FR0011_JOB_TIME:" + f"{label}.{index}")
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
            _fail("FR0011_JOB_STEPS:" + f"{label}.{index}")
        result[name] = {
            "database_id": database_id,
            "started": started,
            "completed": completed,
            "steps": steps,
        }
        job_ids.add(database_id)
    if set(result) != expected_names:
        _fail("FR0011_JOB_SET:" + label)
    return result


def raw_run_id_from_job_url(value: Any, *, label: str) -> int:
    """Extract the run identity from one canonical GitHub job URL."""

    if not isinstance(value, str):
        _fail("FR0011_JOB_URL:" + label)
    match = re.fullmatch(
        r"https://github\.com/sepahead/haldir/actions/runs/"
        r"(?P<run>[1-9][0-9]*)/job/[1-9][0-9]*",
        value,
    )
    if match is None:
        _fail("FR0011_JOB_URL:" + label)
    return int(match.group("run"))


def validate_c5_run_documents(
    ordinary: Any,
    attempt: Any,
    *,
    workflow: str,
    subject_commit: str,
) -> dict[str, Any]:
    """Validate exact c5 ordinary/attempt metadata for defect reproduction."""

    if workflow not in {"ci", "formal"} or HEX40.fullmatch(subject_commit) is None:
        _fail("FR0011_RUN_IDENTITY")
    ordinary = _require_dict(ordinary, ORDINARY_RUN_FIELDS, "ordinary")
    attempt = _require_dict(attempt, ATTEMPT_RUN_FIELDS, "attempt")
    run_id = _bounded_int(
        ordinary["databaseId"],
        minimum=1,
        maximum=2**63 - 1,
        label="run_id",
    )
    attempt_number = _bounded_int(
        attempt["attempt"],
        minimum=1,
        maximum=1_000,
        label="attempt",
    )
    expected_workflow_name = workflow
    expected_url = f"https://github.com/sepahead/haldir/actions/runs/{run_id}"
    common = {
        "conclusion": "success",
        "databaseId": run_id,
        "event": "push",
        "headSha": subject_commit,
        "status": "completed",
        "workflowName": expected_workflow_name,
    }
    if (
        run_id != C5_RUN_IDS[workflow]
        or attempt_number != 1
        or ordinary["attempt"] != attempt_number
        or attempt["databaseId"] != run_id
        or attempt["workflowDatabaseId"] != WORKFLOW_DATABASE_IDS[workflow]
        or ordinary["headBranch"] != "main"
        or attempt["headBranch"] != "main"
        or ordinary["url"] != expected_url
        or attempt["url"] != f"{expected_url}/attempts/{attempt_number}"
        or any(ordinary[key] != value for key, value in common.items())
        or any(attempt[key] != value for key, value in common.items())
    ):
        _fail("FR0011_RUN_METADATA")
    for key in COMMON_RUN_FIELDS - {"jobs", "updatedAt", "url"}:
        if ordinary[key] != attempt[key]:
            _fail("FR0011_RUN_ATTEMPT_MISMATCH:" + key)
    created = _parse_utc(ordinary["createdAt"], "ordinary.created")
    ordinary_updated = _parse_utc(ordinary["updatedAt"], "ordinary.updated")
    attempt_created = _parse_utc(attempt["createdAt"], "attempt.created")
    attempt_started = _parse_utc(attempt["startedAt"], "attempt.started")
    attempt_updated = _parse_utc(attempt["updatedAt"], "attempt.updated")
    if (
        created > attempt_started
        or attempt_created > attempt_started + timedelta(seconds=1)
        or attempt_started > ordinary_updated
        or ordinary_updated > attempt_updated
        or (attempt_number == 1 and created != attempt_created)
        or (attempt_number > 1 and created >= attempt_created)
    ):
        _fail("FR0011_RUN_CHRONOLOGY")
    _validate_jobs(
        ordinary["jobs"],
        expected_names=CI_JOB_NAMES if workflow == "ci" else FORMAL_JOB_NAMES,
        expected_run_id=run_id,
        run_start=created,
        run_end=ordinary_updated,
        label="ordinary.jobs",
    )
    attempt_jobs = _validate_jobs(
        attempt["jobs"],
        expected_names=CI_JOB_NAMES if workflow == "ci" else FORMAL_JOB_NAMES,
        expected_run_id=run_id,
        run_start=attempt_started,
        run_end=attempt_updated,
        label="attempt.jobs",
    )
    if canonical_json_bytes(ordinary["jobs"]) != canonical_json_bytes(attempt["jobs"]):
        _fail("FR0011_RUN_JOB_MISMATCH")
    return {
        "run_id": run_id,
        "attempt": attempt_number,
        "created": created,
        "started": attempt_started,
        "updated": attempt_updated,
        "jobs": attempt_jobs,
    }


def validate_epoch12_run_documents(
    ordinary: Any,
    attempt: Any,
    *,
    workflow: str,
    subject_commit: str,
    expected_ref: str,
) -> dict[str, Any]:
    """Validate a successful epoch-12 run, including its OIDC attestation job."""

    if (
        workflow not in {"ci", "formal"}
        or HEX40.fullmatch(subject_commit) is None
        or re.fullmatch(r"refs/heads/[A-Za-z0-9._/-]+", expected_ref) is None
        or ".." in expected_ref
        or "//" in expected_ref
    ):
        _fail("FR0011_EPOCH12_RUN_IDENTITY")
    ordinary = _require_dict(ordinary, EPOCH12_ORDINARY_RUN_FIELDS, "epoch12.ordinary")
    attempt = _require_dict(attempt, EPOCH12_ATTEMPT_RUN_FIELDS, "epoch12.attempt")
    run_id = _bounded_int(
        ordinary["databaseId"],
        minimum=1,
        maximum=2**63 - 1,
        label="epoch12.run_id",
    )
    attempt_number = _bounded_int(
        attempt["attempt"],
        minimum=1,
        maximum=MAX_EPOCH12_RUN_ATTEMPT,
        label="epoch12.attempt_number",
    )
    expected_url = f"https://github.com/{REPOSITORY}/actions/runs/{run_id}"
    expected_branch = expected_ref.removeprefix("refs/heads/")
    run_number = _bounded_int(
        ordinary["number"],
        minimum=1,
        maximum=2**63 - 1,
        label="epoch12.run_number",
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
        ordinary["attempt"] != attempt_number
        or attempt["databaseId"] != run_id
        or ordinary["number"] != run_number
        or attempt["number"] != run_number
        or ordinary["workflowDatabaseId"] != WORKFLOW_DATABASE_IDS[workflow]
        or attempt["workflowDatabaseId"] != WORKFLOW_DATABASE_IDS[workflow]
        or ordinary["url"] != expected_url
        or attempt["url"] != f"{expected_url}/attempts/{attempt_number}"
        or any(ordinary[key] != value for key, value in common.items())
        or any(attempt[key] != value for key, value in common.items())
    ):
        _fail("FR0011_EPOCH12_RUN_METADATA")
    for key in COMMON_RUN_FIELDS - {"createdAt", "jobs", "updatedAt", "url"}:
        if ordinary[key] != attempt[key]:
            _fail("FR0011_EPOCH12_RUN_ATTEMPT_MISMATCH:" + key)
    created = _parse_utc(ordinary["createdAt"], "epoch12.ordinary.created")
    ordinary_updated = _parse_utc(ordinary["updatedAt"], "epoch12.ordinary.updated")
    attempt_created = _parse_utc(attempt["createdAt"], "epoch12.attempt.created")
    attempt_started = _parse_utc(attempt["startedAt"], "epoch12.attempt.started")
    attempt_updated = _parse_utc(attempt["updatedAt"], "epoch12.attempt.updated")
    if (
        created > attempt_started
        or attempt_created > attempt_started + timedelta(seconds=1)
        or attempt_started > ordinary_updated
        or ordinary_updated > attempt_updated
        or (attempt_number == 1 and created != attempt_created)
        or (attempt_number > 1 and created >= attempt_created)
    ):
        _fail("FR0011_EPOCH12_RUN_CHRONOLOGY")
    expected_jobs = (
        EPOCH12_CI_JOB_NAMES if workflow == "ci" else EPOCH12_FORMAL_JOB_NAMES
    )
    _validate_jobs(
        ordinary["jobs"],
        expected_names=expected_jobs,
        expected_run_id=run_id,
        run_start=created,
        run_end=ordinary_updated,
        label="epoch12.ordinary.jobs",
    )
    attempt_jobs = _validate_jobs(
        attempt["jobs"],
        expected_names=expected_jobs,
        expected_run_id=run_id,
        run_start=attempt_started,
        run_end=attempt_updated,
        label="epoch12.attempt.jobs",
    )
    if canonical_json_bytes(ordinary["jobs"]) != canonical_json_bytes(attempt["jobs"]):
        _fail("FR0011_EPOCH12_RUN_JOB_MISMATCH")
    attestation_job = (
        "attest-ci-audit-result" if workflow == "ci" else "attest-formal-audit-result"
    )
    if attestation_job not in attempt_jobs:
        _fail("FR0011_EPOCH12_ATTESTATION_JOB")
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


def _zip_mode(info: zipfile.ZipInfo) -> int:
    return (info.external_attr >> 16) & 0xFFFF


def inspect_whole_job_archive(
    payload: bytes,
    *,
    expected_jobs: frozenset[str],
) -> dict[str, Any]:
    """Validate a bounded Actions whole-job ZIP and return authenticated entries."""

    if (
        type(payload) is not bytes
        or not 1 <= len(payload) <= MAX_ARCHIVE_BYTES
        or not payload.startswith(b"PK")
    ):
        _fail("FR0011_ARCHIVE_BOUND")
    try:
        archive = zipfile.ZipFile(io.BytesIO(payload), mode="r")
    except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile):
        _fail("FR0011_ARCHIVE_INVALID")
    with archive:
        infos = archive.infolist()
        names = [info.filename for info in infos]
        if (
            not 1 <= len(infos) <= MAX_ARCHIVE_ENTRIES
            or len(names) != len(set(names))
            or archive.comment
        ):
            _fail("FR0011_ARCHIVE_SHAPE")
        expected_names: set[str] = set()
        job_entries: dict[str, dict[str, Any]] = {}
        observed_indexes: set[int] = set()
        total = 0
        for info in infos:
            try:
                info.filename.encode("ascii")
            except UnicodeEncodeError:
                _fail("FR0011_ARCHIVE_NAME")
            if (
                info.flag_bits & 0x1
                or info.is_dir()
                or info.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
                or info.file_size < 0
                or info.file_size > MAX_ARCHIVE_ENTRY_BYTES
                or info.compress_size < 0
                or (
                    info.file_size > 0
                    and info.compress_size == 0
                    and info.compress_type != zipfile.ZIP_STORED
                )
                or (
                    info.compress_size > 0
                    and info.file_size > info.compress_size * MAX_COMPRESSION_RATIO
                )
            ):
                _fail("FR0011_ARCHIVE_ENTRY")
            mode = _zip_mode(info)
            if mode and stat.S_IFMT(mode) not in {0, stat.S_IFREG}:
                _fail("FR0011_ARCHIVE_ENTRY_TYPE")
            total += info.file_size
            if total > MAX_ARCHIVE_TOTAL_BYTES:
                _fail("FR0011_ARCHIVE_TOTAL")
            match = ARCHIVE_JOB.fullmatch(info.filename)
            if match is not None:
                job = match.group("job")
                index = int(match.group("index"))
                if job in job_entries or index in observed_indexes:
                    _fail("FR0011_ARCHIVE_JOB_DUPLICATE")
                job_entries[job] = {"info": info, "index": index}
                observed_indexes.add(index)
                expected_names.add(info.filename)
                continue
            system_match = re.fullmatch(
                r"(?P<job>[a-z0-9][a-z0-9-]{0,62})/system\.txt",
                info.filename,
            )
            if system_match is None:
                _fail("FR0011_ARCHIVE_NAME")
            expected_names.add(info.filename)
        if (
            set(job_entries) != expected_jobs
            or observed_indexes != set(range(len(expected_jobs)))
            or names != list(dict.fromkeys(names))
            or set(names) != expected_names
            or {name for name in names if name.endswith("/system.txt")}
            != {f"{job}/system.txt" for job in expected_jobs}
        ):
            _fail("FR0011_ARCHIVE_JOB_SET")
        records: list[dict[str, Any]] = []
        job_payloads: dict[str, bytes] = {}
        for name in sorted(names):
            info = archive.getinfo(name)
            try:
                with archive.open(info, mode="r") as source:
                    data = source.read(info.file_size + 1)
                    trailing = source.read(1)
            except (OSError, RuntimeError, zipfile.BadZipFile):
                _fail("FR0011_ARCHIVE_READ")
            if len(data) != info.file_size or trailing:
                _fail("FR0011_ARCHIVE_SIZE")
            records.append(
                {
                    "name": name,
                    "compressed_bytes": info.compress_size,
                    "uncompressed_bytes": len(data),
                    "crc32": f"{info.CRC:08x}",
                    "sha256": sha256(data),
                }
            )
            match = ARCHIVE_JOB.fullmatch(name)
            if match is not None:
                job_payloads[match.group("job")] = data
    return {
        "sha256": sha256(payload),
        "bytes": len(payload),
        "entries": records,
        "jobs": job_payloads,
    }


def _timestamped_lines(payload: bytes, *, label: str) -> list[tuple[datetime, bytes]]:
    if (
        type(payload) is not bytes
        or not payload
        or b"\0" in payload
        or b"\r" in payload
    ):
        _fail("FR0011_LOG_GRAMMAR:" + label)
    result: list[tuple[datetime, bytes]] = []
    for index, raw in enumerate(payload.splitlines()):
        if index == 0:
            raw = raw.removeprefix(b"\xef\xbb\xbf")
        match = LOG_LINE.fullmatch(raw)
        if match is None:
            _fail("FR0011_LOG_LINE:" + label)
        try:
            timestamp = _parse_utc(
                match.group("timestamp").decode("ascii"),
                f"{label}.{index}",
            )
        except UnicodeDecodeError:
            _fail("FR0011_LOG_TIMESTAMP:" + label)
        result.append((timestamp, match.group("body")))
    if any(result[index][0] > result[index + 1][0] for index in range(len(result) - 1)):
        _fail("FR0011_LOG_ORDER:" + label)
    return result


def _critical_step(
    jobs: dict[str, dict[str, Any]],
    *,
    job_name: str,
    step_name: str,
) -> dict[str, Any]:
    job = jobs.get(job_name)
    if job is None:
        _fail("FR0011_CRITICAL_JOB")
    matches = [step for step in job["steps"] if step["name"] == step_name]
    if len(matches) != 1:
        _fail("FR0011_CRITICAL_STEP")
    return matches[0]


def _command_group_lines(
    payload: bytes,
    *,
    started: datetime,
    completed: datetime,
    group_start: bytes,
    next_group_start: bytes,
    label: str,
) -> list[bytes]:
    """Return one exact command group bounded by API step time and next group."""

    tolerance = timedelta(seconds=TIMESTAMP_SKEW_SECONDS)
    lower = started - tolerance
    upper = completed + tolerance
    timestamped = _timestamped_lines(payload, label=label)
    start_indexes = [
        index
        for index, (_timestamp, body) in enumerate(timestamped)
        if body == group_start
    ]
    if len(start_indexes) != 1:
        _fail("FR0011_COMMAND_GROUP_START:" + label)
    start_index = start_indexes[0]
    following_groups = [
        (index, body)
        for index, (_timestamp, body) in enumerate(
            timestamped[start_index + 1 :],
            start=start_index + 1,
        )
        if body.startswith(b"##[group]Run ")
    ]
    if not following_groups or following_groups[0][1] != next_group_start:
        _fail("FR0011_COMMAND_GROUP_END:" + label)
    end_index = following_groups[0][0]
    start_time = timestamped[start_index][0]
    end_time = timestamped[end_index][0]
    if (
        start_time < lower
        or start_time > upper
        or end_time < lower
        or end_time > upper
        or start_time > end_time
    ):
        _fail("FR0011_COMMAND_GROUP_TIME:" + label)
    lines = [body for _timestamp, body in timestamped[start_index:end_index]]
    if not lines or lines[0] != group_start:
        _fail("FR0011_COMMAND_GROUP_EMPTY:" + label)
    return lines


def _ci_markers(lines: list[bytes]) -> list[tuple[str, int | None]]:
    markers: list[tuple[str, int | None]] = []
    for line in lines:
        match = RUN_MARKER.fullmatch(line)
        if match is not None:
            markers.append(("RUN", int(match.group("count"))))
        elif line == b"OK":
            markers.append(("OK", None))
        elif line == b"verify-current-audit: OK":
            markers.append(("VERIFIER_OK", None))
    return markers


def validate_c5_ci_archive(
    payload: bytes,
    *,
    jobs: dict[str, dict[str, Any]],
    suite_counts: list[int],
) -> dict[str, Any]:
    """Reproduce c5 CI markers inside the metadata-bound critical step."""

    if (
        not isinstance(suite_counts, list)
        or not 1 <= len(suite_counts) <= 32
        or any(
            type(count) is not int or not 1 <= count <= 100_000
            for count in suite_counts
        )
    ):
        _fail("FR0011_SUITE_COUNTS")
    inspected = inspect_whole_job_archive(payload, expected_jobs=CI_JOB_NAMES)
    step = _critical_step(
        jobs,
        job_name="supply-chain",
        step_name="Verify current-head 0.9 audit cut",
    )
    lines = _command_group_lines(
        inspected["jobs"]["supply-chain"],
        started=step["started"],
        completed=step["completed"],
        group_start=(
            b"##[group]Run /usr/bin/env -u BASH_ENV -u ENV /bin/bash "
            b"--noprofile --norc tools/release/current-audit-gate.sh"
        ),
        next_group_start=b"##[group]Run python3 tools/verify-pins.py",
        label="ci.supply_chain",
    )
    if any(token in line for token in FAILURE_TOKENS for line in lines):
        _fail("FR0011_CI_FAILURE_TOKEN")
    expected = [
        marker for count in suite_counts for marker in (("RUN", count), ("OK", None))
    ] + [("VERIFIER_OK", None)]
    if _ci_markers(lines) != expected:
        _fail("FR0011_CI_MARKERS")
    return {
        "archive_sha256": inspected["sha256"],
        "archive_bytes": inspected["bytes"],
        "entry_records": inspected["entries"],
        "critical_job_sha256": sha256(inspected["jobs"]["supply-chain"]),
        "critical_step": {
            "name": step["name"],
            "number": step["number"],
            "started_at_utc": step["started"].isoformat().replace("+00:00", "Z"),
            "completed_at_utc": step["completed"].isoformat().replace("+00:00", "Z"),
            "timestamp_skew_seconds": TIMESTAMP_SKEW_SECONDS,
        },
        "marker_sequence": [
            {"kind": kind, **({} if count is None else {"count": count})}
            for kind, count in expected
        ],
    }


def validate_c5_formal_archive(
    payload: bytes,
    *,
    jobs: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Reproduce c5 formal markers inside the exact model-check step."""

    inspected = inspect_whole_job_archive(payload, expected_jobs=FORMAL_JOB_NAMES)
    step = _critical_step(
        jobs,
        job_name="tlc-model-check",
        step_name="Model-check HaldirAuthority",
    )
    lines = _command_group_lines(
        inspected["jobs"]["tlc-model-check"],
        started=step["started"],
        completed=step["completed"],
        group_start=(
            b"##[group]Run java -XX:+UseParallelGC -cp tla2tools.jar tlc2.TLC \\"
        ),
        next_group_start=(
            b"##[group]Run actions/upload-artifact@"
            b"043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
        ),
        label="formal.tlc",
    )
    success = b"Model checking completed. No error has been found."
    if (
        any(token in line for token in FAILURE_TOKENS for line in lines)
        or lines.count(success) != 1
        or sum(line.startswith(b"Finished in") for line in lines) != 1
    ):
        _fail("FR0011_FORMAL_MARKERS")
    return {
        "archive_sha256": inspected["sha256"],
        "archive_bytes": inspected["bytes"],
        "entry_records": inspected["entries"],
        "critical_job_sha256": sha256(inspected["jobs"]["tlc-model-check"]),
        "critical_step": {
            "name": step["name"],
            "number": step["number"],
            "started_at_utc": step["started"].isoformat().replace("+00:00", "Z"),
            "completed_at_utc": step["completed"].isoformat().replace("+00:00", "Z"),
            "timestamp_skew_seconds": TIMESTAMP_SKEW_SECONDS,
        },
    }


def validate_c5_hosted_capture(
    metadata: Any,
    archive: bytes,
    *,
    workflow: str,
    subject_commit: str,
    suite_counts: list[int] | None = None,
) -> dict[str, Any]:
    """Validate one diagnostic c5 capture without treating logs as epoch-12 proof."""

    document = _require_dict(
        metadata,
        frozenset(
            {
                "schema_version",
                "protocol",
                "workflow",
                "subject_commit",
                "ordinary",
                "attempt_metadata",
                "archive",
                "capture",
                "result",
            }
        ),
        "hosted_capture",
    )
    if (
        document["schema_version"] != "1.0.0"
        or document["protocol"] != C5_ARCHIVE_PROTOCOL
        or document["workflow"] != workflow
        or document["subject_commit"] != subject_commit
        or document["result"] != "PASS"
    ):
        _fail("FR0011_HOSTED_IDENTITY")
    run = validate_c5_run_documents(
        document["ordinary"],
        document["attempt_metadata"],
        workflow=workflow,
        subject_commit=subject_commit,
    )
    expected_archive = (
        validate_c5_ci_archive(
            archive, jobs=run["jobs"], suite_counts=suite_counts or []
        )
        if workflow == "ci"
        else validate_c5_formal_archive(archive, jobs=run["jobs"])
    )
    if canonical_json_bytes(document["archive"]) != canonical_json_bytes(
        expected_archive
    ):
        _fail("FR0011_HOSTED_ARCHIVE_RECEIPT")
    capture = _require_dict(
        document["capture"],
        frozenset(
            {
                "tool",
                "metadata_command",
                "attempt_command",
                "archive_command",
                "started_at_utc",
                "completed_at_utc",
            }
        ),
        "capture",
    )
    tool = _require_dict(
        capture["tool"],
        frozenset(
            {
                "path",
                "sha256",
                "bytes",
                "git_mode",
                "git_object_type",
                "git_object_id",
            }
        ),
        "capture.tool",
    )
    if (
        tool["path"] != "tools/release/framework_recovery_fr_0011_capture.py"
        or HEX64.fullmatch(str(tool["sha256"])) is None
        or type(tool["bytes"]) is not int
        or tool["bytes"] < 1
        or tool["git_mode"] != "100755"
        or tool["git_object_type"] != "blob"
        or HEX40.fullmatch(str(tool["git_object_id"])) is None
    ):
        _fail("FR0011_CAPTURE_TOOL")
    run_id = run["run_id"]
    attempt_number = run["attempt"]
    fields = (
        "attempt,conclusion,createdAt,databaseId,event,headBranch,headSha,jobs,"
        "status,updatedAt,url,workflowName"
    )
    attempt_fields = (
        "attempt,conclusion,createdAt,databaseId,event,headBranch,headSha,jobs,"
        "startedAt,status,updatedAt,url,workflowDatabaseId,workflowName"
    )
    expected_commands = {
        "metadata_command": (
            f"gh run view {run_id} --repo sepahead/haldir --json {fields}"
        ),
        "attempt_command": (
            f"gh run view {run_id} --repo sepahead/haldir --attempt "
            f"{attempt_number} --json {attempt_fields}"
        ),
        "archive_command": (
            "gh api --method GET "
            f"repos/sepahead/haldir/actions/runs/{run_id}/attempts/"
            f"{attempt_number}/logs"
        ),
    }
    if any(capture[key] != value for key, value in expected_commands.items()):
        _fail("FR0011_CAPTURE_COMMAND")
    started = _parse_utc(capture["started_at_utc"], "capture.started")
    completed = _parse_utc(capture["completed_at_utc"], "capture.completed")
    if run["updated"] > started or started > completed:
        _fail("FR0011_CAPTURE_CHRONOLOGY")
    return {
        "run_id": run_id,
        "attempt": attempt_number,
        "workflow": workflow,
        "capture_completed": completed.isoformat().replace("+00:00", "Z"),
        "archive": expected_archive,
        "tool": copy.deepcopy(tool),
    }


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
        or HEX40.fullmatch(str(record["git_object_id"])) is None
        or HEX64.fullmatch(str(record["sha256"])) is None
        or type(record["bytes"]) is not int
        or not 1 <= record["bytes"] <= MAX_ARCHIVE_TOTAL_BYTES
    ):
        _fail("FR0011_FILE_RECORD:" + expected_path)
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
        _fail("FR0011_RESULT_BOUND")
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError):
        _fail("FR0011_RESULT_JSON")
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
        _fail("FR0011_RESULT_SCHEMA")
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
        _fail("FR0011_RESULT_IDENTITY")
    if value["repository"] != {
        "name": REPOSITORY,
        "database_id": REPOSITORY_ID,
        "owner_database_id": REPOSITORY_OWNER_ID,
    }:
        _fail("FR0011_RESULT_REPOSITORY")
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
        _fail("FR0011_RESULT_SUBJECT")
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
        or execution["run_id"] != run_id
        or execution["run_attempt"] != attempt
        or execution["run_number"] != run_number
        or execution["command"] != contract["command"]
        or execution["result"] != "PASS"
    ):
        _fail("FR0011_RESULT_EXECUTION")
    if not isinstance(expected_materials, list) or len(expected_materials) != len(
        contract["material_paths"]
    ):
        _fail("FR0011_RESULT_EXPECTED_MATERIALS")
    normalized_expected = [
        _validate_file_record(item, expected_path=path)
        for item, path in zip(
            expected_materials, contract["material_paths"], strict=True
        )
    ]
    materials = value["materials"]
    if not isinstance(materials, list) or len(materials) != len(normalized_expected):
        _fail("FR0011_RESULT_MATERIALS")
    normalized_observed = [
        _validate_file_record(item, expected_path=path)
        for item, path in zip(materials, contract["material_paths"], strict=True)
    ]
    if canonical_json_bytes(normalized_observed) != canonical_json_bytes(
        normalized_expected
    ):
        _fail("FR0011_RESULT_MATERIAL_DRIFT")
    if value["authority"] != {
        "provenance_only": True,
        "release_authority": False,
        "deployment_authority": False,
        "publication_authority": False,
        "tag_authority": False,
    }:
        _fail("FR0011_RESULT_AUTHORITY")
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
        _fail("FR0011_ARTIFACT_WORKFLOW")
    artifact_id = _bounded_int(
        artifact["id"],
        minimum=1,
        maximum=2**63 - 1,
        label="artifact.id",
    )
    _bounded_int(
        attempt,
        minimum=1,
        maximum=MAX_EPOCH12_RUN_ATTEMPT,
        label="artifact.attempt",
    )
    artifact_name = f"epoch-12-{workflow}-result-attempt-{attempt}.json"
    digest = sha256(result_payload)
    if (
        artifact["name"] != artifact_name
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
        _fail("FR0011_ARTIFACT_IDENTITY")
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
        _fail("FR0011_ARTIFACT_CHRONOLOGY")
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
    if workflow_run != {
        "head_branch": "main",
        "head_repository_id": REPOSITORY_ID,
        "head_sha": subject_commit,
        "id": run_id,
        "repository_id": REPOSITORY_ID,
    }:
        _fail("FR0011_ARTIFACT_RUN_BINDING")
    return copy.deepcopy(artifact)


def _parse_attestation_bundle(payload: bytes) -> dict[str, Any]:
    if (
        type(payload) is not bytes
        or not 1 <= len(payload) <= MAX_REVIEW_RESPONSE_BYTES
        or b"\0" in payload
        or payload.count(b"\n") != 1
        or not payload.endswith(b"\n")
    ):
        _fail("FR0011_ATTESTATION_BUNDLE_BOUND")
    try:
        bundle = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError):
        _fail("FR0011_ATTESTATION_BUNDLE_JSON")
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
        _fail("FR0011_ATTESTATION_BUNDLE_SCHEMA")
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
        _fail("FR0011_ATTESTATION_ENVELOPE")
    try:
        decoded = base64.b64decode(envelope["payload"], validate=True)
        statement = json.loads(decoded)
    except (
        TypeError,
        ValueError,
        UnicodeDecodeError,
        json.JSONDecodeError,
    ):
        _fail("FR0011_ATTESTATION_STATEMENT")
    if not isinstance(statement, dict):
        _fail("FR0011_ATTESTATION_STATEMENT")
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
                "name": (f"epoch-12-{workflow}-result-attempt-{attempt}.json"),
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
        or type(attempt) is not int
        or not 1 <= attempt <= MAX_EPOCH12_RUN_ATTEMPT
    ):
        _fail("FR0011_ATTESTATION_IDENTITY")
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
        _fail("FR0011_ATTESTATION_STATEMENT_MISMATCH")
    if (
        not isinstance(verification_receipt, list)
        or len(verification_receipt) != 1
        or not isinstance(verification_receipt[0], dict)
        or set(verification_receipt[0]) != {"attestation", "verificationResult"}
    ):
        _fail("FR0011_ATTESTATION_RECEIPT")
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
        _fail("FR0011_ATTESTATION_RECEIPT_BUNDLE")
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
        _fail("FR0011_ATTESTATION_VERIFICATION_RESULT")
    timestamp = result["verifiedTimestamps"][0]
    if (
        not isinstance(timestamp, dict)
        or set(timestamp) != {"timestamp", "type", "uri"}
        or timestamp["type"] != "Tlog"
        or not isinstance(timestamp["uri"], str)
        or timestamp["uri"].removeprefix("https://")
        not in {
            "rekor.sigstore.dev",
            "log2025-1.rekor.sigstore.dev",
        }
    ):
        _fail("FR0011_ATTESTATION_TRANSPARENCY_LOG")
    witnessed = _parse_utc(
        timestamp["timestamp"], "attestation.transparency_log.timestamp"
    )
    tolerance = timedelta(seconds=TIMESTAMP_SKEW_SECONDS)
    if (
        witnessed < attestation_started - tolerance
        or witnessed > attestation_completed + tolerance
    ):
        _fail("FR0011_ATTESTATION_TRANSPARENCY_LOG_TIME")
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
        _fail("FR0011_ATTESTATION_CERTIFICATE")
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


def review_subject_manifest(
    *,
    review_id: str,
    model: str,
    repair_commit: str,
    plan_sha256: str,
    patch_sha256: str,
    gate_sha256: str,
    required_findings: list[dict[str, Any]],
) -> dict[str, Any]:
    """Construct the exact compact review subject manifest."""

    if (
        review_id not in {"FR-0011-R01", "FR-0011-R02"}
        or model not in {"claude-fable-5", "claude-opus-5"}
        or HEX40.fullmatch(repair_commit) is None
        or any(
            HEX64.fullmatch(item) is None
            for item in (plan_sha256, patch_sha256, gate_sha256)
        )
        or not isinstance(required_findings, list)
        or not required_findings
    ):
        _fail("FR0011_REVIEW_SUBJECT")
    normalized_findings = _validate_required_finding_contract(required_findings)
    return {
        "schema_version": "1.0.0",
        "protocol": REVIEW_REQUEST_PROTOCOL,
        "review_id": review_id,
        "model": model,
        "repair_commit": repair_commit,
        "material_sha256": {
            "plan": plan_sha256,
            "core_patch": patch_sha256,
            "p0_gate": gate_sha256,
        },
        "required_findings": normalized_findings,
        "authority": {
            "human_review_performed": False,
            "external_independence": False,
            "release_authority": False,
        },
    }


def _review_finding_schema() -> dict[str, Any]:
    return {
        "additionalProperties": False,
        "properties": {
            "affected_paths": {
                "items": {"type": "string"},
                "type": "array",
            },
            "disposition": {"type": "string"},
            "id": {"type": "string"},
            "severity": {"const": "BLOCKING"},
            "status": {"enum": ["OPEN", "RESOLVED"]},
            "summary": {"type": "string"},
        },
        "required": [
            "affected_paths",
            "disposition",
            "id",
            "severity",
            "status",
            "summary",
        ],
        "type": "object",
    }


def review_output_schema(manifest: dict[str, Any]) -> dict[str, Any]:
    """Return the strict provider-side schema for one authenticated review."""

    _validate_required_finding_contract(manifest.get("required_findings"))
    model = manifest.get("model")
    review_id = manifest.get("review_id")
    if model not in {"claude-fable-5", "claude-opus-5"} or review_id not in {
        "FR-0011-R01",
        "FR-0011-R02",
    }:
        _fail("FR0011_REVIEW_SUBJECT")
    return {
        "additionalProperties": False,
        "properties": {
            "additional_findings": {
                "items": _review_finding_schema(),
                "type": "array",
            },
            "model": {"const": model},
            "protocol": {"const": REVIEW_RESPONSE_PROTOCOL},
            "required_findings": {
                "items": _review_finding_schema(),
                "type": "array",
            },
            "review_id": {"const": review_id},
            "verdict": {"enum": ["GO_FOR_FRAMEWORK_QUALIFICATION", "NO_GO"]},
        },
        "required": [
            "additional_findings",
            "model",
            "protocol",
            "required_findings",
            "review_id",
            "verdict",
        ],
        "type": "object",
    }


def build_review_request(
    *,
    manifest: dict[str, Any],
    plan_payload: bytes,
    patch_payload: bytes,
    gate_payload: bytes,
) -> bytes:
    """Build the exact provider request authenticated by qualification evidence."""

    for label, payload in (
        ("plan", plan_payload),
        ("patch", patch_payload),
        ("gate", gate_payload),
    ):
        if (
            type(payload) is not bytes
            or not payload
            or len(payload) > MAX_REVIEW_REQUEST_BYTES
            or b"\0" in payload
        ):
            _fail("FR0011_REVIEW_MATERIAL:" + label)
        try:
            payload.decode("utf-8")
        except UnicodeDecodeError:
            _fail("FR0011_REVIEW_MATERIAL:" + label)
    model = manifest.get("model")
    if model not in {"claude-fable-5", "claude-opus-5"}:
        _fail("FR0011_REVIEW_MODEL")
    instruction = (
        "Review only the authenticated FR-0011 repair material. Return only one "
        "UTF-8 JSON object with exactly these six top-level keys: "
        "additional_findings, model, protocol, required_findings, review_id, "
        "verdict. Set protocol to HALDIR_FR_0011_REVIEW_RESPONSE_V1; copy model "
        "and review_id exactly from the subject. Preserve every required finding "
        "ID, affected_paths value, and order. Use "
        "GO_FOR_FRAMEWORK_QUALIFICATION only when every blocking finding is "
        "resolved by the supplied bytes; otherwise use NO_GO and retain at "
        "least one OPEN finding. Serialize the response as recursively "
        "lexicographically sorted object keys with compact ',' and ':' "
        "separators, raw UTF-8 rather than ASCII escapes, and no BOM, code "
        "fence, leading or trailing whitespace, or final newline. Do not claim "
        "human review, external independence, or release authority."
    )
    content = (
        instruction
        + "\n\n-----BEGIN FR-0011 SUBJECT-----\n"
        + canonical_json_bytes(manifest).decode("utf-8")
        + "-----END FR-0011 SUBJECT-----\n"
        + "-----BEGIN FR-0011 PLAN-----\n"
        + plan_payload.decode("utf-8")
        + "-----END FR-0011 PLAN-----\n"
        + "-----BEGIN FR-0011 CORE PATCH-----\n"
        + patch_payload.decode("utf-8")
        + "-----END FR-0011 CORE PATCH-----\n"
        + "-----BEGIN PINNED P0 GATE-----\n"
        + gate_payload.decode("utf-8")
        + "-----END PINNED P0 GATE-----\n"
    )
    request = canonical_json_bytes(
        {
            "model": model,
            "max_tokens": 16_384,
            "output_config": {
                "effort": "max",
                "format": {
                    "schema": review_output_schema(manifest),
                    "type": "json_schema",
                },
            },
            "system": (
                "You are an internal automated security and release-protocol "
                "reviewer. Analyze only the supplied authenticated bytes."
            ),
            "messages": [{"role": "user", "content": content}],
        }
    )
    if len(request) > MAX_REVIEW_REQUEST_BYTES:
        _fail("FR0011_REVIEW_REQUEST_BOUND")
    return request


def _bounded_text(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        _fail("FR0011_REVIEW_TEXT:" + label)
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError:
        _fail("FR0011_REVIEW_TEXT:" + label)
    if len(encoded) > 4_096 or any(
        ord(character) < 0x20 and character not in "\t\n\r" for character in value
    ):
        _fail("FR0011_REVIEW_TEXT:" + label)
    return value


def _validate_paths(value: Any, *, label: str) -> list[str]:
    if (
        not isinstance(value, list)
        or not 1 <= len(value) <= 32
        or len(value) != len(set(value))
        or any(
            not isinstance(path, str) or REPOSITORY_PATH.fullmatch(path) is None
            for path in value
        )
    ):
        _fail("FR0011_REVIEW_PATHS:" + label)
    return list(value)


def _validate_required_finding_contract(value: Any) -> list[dict[str, Any]]:
    if (
        not isinstance(value, list)
        or not 1 <= len(value) <= 32
        or any(not isinstance(item, dict) for item in value)
    ):
        _fail("FR0011_REVIEW_FINDING_CONTRACT")
    result: list[dict[str, Any]] = []
    for index, item in enumerate(value):
        if set(item) != {"id", "summary", "affected_paths"}:
            _fail("FR0011_REVIEW_FINDING_CONTRACT")
        finding_id = item["id"]
        if (
            not isinstance(finding_id, str)
            or re.fullmatch(r"F[0-9]{3}", finding_id) is None
            or finding_id != f"F{index + 1:03d}"
        ):
            _fail("FR0011_REVIEW_FINDING_CONTRACT")
        result.append(
            {
                "id": finding_id,
                "summary": _bounded_text(
                    item["summary"], label=f"contract.{finding_id}.summary"
                ),
                "affected_paths": _validate_paths(
                    item["affected_paths"],
                    label=f"contract.{finding_id}.affected_paths",
                ),
            }
        )
    return result


def _validate_review_finding(
    value: Any,
    *,
    expected_id: str,
    additional: bool,
) -> dict[str, Any]:
    fields = {
        "id",
        "severity",
        "status",
        "summary",
        "affected_paths",
        "disposition",
    }
    if not isinstance(value, dict) or set(value) != fields:
        _fail("FR0011_REVIEW_FINDING:" + expected_id)
    finding_id = value["id"]
    if (
        finding_id != expected_id
        or REVIEW_FINDING_ID.fullmatch(str(finding_id)) is None
        or (additional and not finding_id.startswith("B"))
        or (not additional and not finding_id.startswith("F"))
        or value["severity"] != "BLOCKING"
        or value["status"] not in {"OPEN", "RESOLVED"}
    ):
        _fail("FR0011_REVIEW_FINDING:" + expected_id)
    return {
        "id": finding_id,
        "severity": "BLOCKING",
        "status": value["status"],
        "summary": _bounded_text(value["summary"], label=f"{finding_id}.summary"),
        "affected_paths": _validate_paths(
            value["affected_paths"], label=f"{finding_id}.affected_paths"
        ),
        "disposition": _bounded_text(
            value["disposition"], label=f"{finding_id}.disposition"
        ),
    }


def validate_review_response(
    manifest: dict[str, Any],
    response: Any,
) -> dict[str, Any]:
    """Validate the exact JSON model response against its signed subject."""

    if (
        not isinstance(manifest, dict)
        or manifest.get("protocol") != REVIEW_REQUEST_PROTOCOL
        or not isinstance(response, dict)
        or set(response)
        != {
            "protocol",
            "review_id",
            "model",
            "verdict",
            "required_findings",
            "additional_findings",
        }
        or response["protocol"] != REVIEW_RESPONSE_PROTOCOL
        or response["review_id"] != manifest.get("review_id")
        or response["model"] != manifest.get("model")
        or response["verdict"] not in {"GO_FOR_FRAMEWORK_QUALIFICATION", "NO_GO"}
    ):
        _fail("FR0011_REVIEW_RESPONSE")
    contract = _validate_required_finding_contract(manifest.get("required_findings"))
    required = response["required_findings"]
    additional = response["additional_findings"]
    if (
        not isinstance(required, list)
        or len(required) != len(contract)
        or not isinstance(additional, list)
        or len(additional) > 32
    ):
        _fail("FR0011_REVIEW_RESPONSE_FINDINGS")
    normalized_required = [
        _validate_review_finding(
            item,
            expected_id=contract[index]["id"],
            additional=False,
        )
        for index, item in enumerate(required)
    ]
    normalized_additional = [
        _validate_review_finding(
            item,
            expected_id=f"B{index + 1:03d}",
            additional=True,
        )
        for index, item in enumerate(additional)
    ]
    for expected, observed in zip(contract, normalized_required, strict=True):
        if observed["affected_paths"] != expected["affected_paths"]:
            _fail("FR0011_REVIEW_RESPONSE_PATHS:" + expected["id"])
    open_ids = [
        item["id"]
        for item in (*normalized_required, *normalized_additional)
        if item["status"] == "OPEN"
    ]
    if (response["verdict"] == "GO_FOR_FRAMEWORK_QUALIFICATION" and open_ids) or (
        response["verdict"] == "NO_GO" and not open_ids
    ):
        _fail("FR0011_REVIEW_RESPONSE_VERDICT")
    return {
        "review_id": response["review_id"],
        "model": response["model"],
        "verdict": response["verdict"],
        "required_findings": normalized_required,
        "additional_findings": normalized_additional,
        "open_blocker_ids": open_ids,
    }


def parse_review_response_bytes(
    raw: bytes,
    *,
    manifest: dict[str, Any],
) -> dict[str, Any]:
    """Parse findings directly from one exact committed provider response."""

    if type(raw) is not bytes or not 1 <= len(raw) <= MAX_REVIEW_RESPONSE_BYTES:
        _fail("FR0011_REVIEW_RESPONSE_BOUND")
    try:
        value = json.loads(raw)
        canonical = canonical_json_bytes(value)
    except (
        RecursionError,
        UnicodeDecodeError,
        UnicodeEncodeError,
        ValueError,
        json.JSONDecodeError,
    ):
        _fail("FR0011_REVIEW_RESPONSE_JSON")
    if not isinstance(value, dict) or canonical != raw:
        _fail("FR0011_REVIEW_RESPONSE_JSON")
    return validate_review_response(manifest, value)


def extract_provider_review_response_bytes(
    raw: bytes,
    *,
    manifest: dict[str, Any],
) -> bytes:
    """Extract and validate the literal final text from one Messages response.

    The provider envelope is retained separately by the capture tool. Refusals,
    truncation, model substitution, tool use, and multiple text blocks are hard
    failures; the returned text is never normalized.
    """

    if type(raw) is not bytes or not 1 <= len(raw) <= MAX_PROVIDER_RESPONSE_BYTES:
        _fail("FR0011_PROVIDER_RESPONSE_BOUND")

    def reject_duplicate_keys(
        pairs: list[tuple[str, Any]],
    ) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                _fail("FR0011_PROVIDER_RESPONSE_JSON")
            result[key] = item
        return result

    try:
        value = json.loads(
            raw,
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=lambda _constant: _fail("FR0011_PROVIDER_RESPONSE_JSON"),
        )
    except (RecursionError, UnicodeDecodeError, json.JSONDecodeError):
        _fail("FR0011_PROVIDER_RESPONSE_JSON")
    required_fields = {
        "content",
        "id",
        "model",
        "role",
        "stop_reason",
        "stop_sequence",
        "type",
        "usage",
    }
    usage = value.get("usage") if isinstance(value, dict) else None
    if (
        not isinstance(value, dict)
        or not required_fields <= set(value)
        or not isinstance(value.get("id"), str)
        or re.fullmatch(r"msg_[A-Za-z0-9_-]{1,252}", value["id"]) is None
        or value.get("type") != "message"
        or value.get("role") != "assistant"
        or value.get("model") != manifest.get("model")
        or value.get("stop_reason") != "end_turn"
        or value.get("stop_sequence") is not None
        or not isinstance(usage, dict)
        or type(usage.get("input_tokens")) is not int
        or usage["input_tokens"] < 0
        or type(usage.get("output_tokens")) is not int
        or usage["output_tokens"] < 0
    ):
        _fail("FR0011_PROVIDER_RESPONSE_IDENTITY")
    content = value.get("content")
    if not isinstance(content, list) or not 1 <= len(content) <= 8:
        _fail("FR0011_PROVIDER_RESPONSE_CONTENT")
    text: str | None = None
    for index, block in enumerate(content):
        if not isinstance(block, dict):
            _fail("FR0011_PROVIDER_RESPONSE_CONTENT")
        block_type = block.get("type")
        if block_type == "thinking":
            if (
                text is not None
                or set(block) != {"signature", "thinking", "type"}
                or not isinstance(block.get("signature"), str)
                or not isinstance(block.get("thinking"), str)
            ):
                _fail("FR0011_PROVIDER_RESPONSE_CONTENT")
        elif block_type == "redacted_thinking":
            if (
                text is not None
                or set(block) != {"data", "type"}
                or not isinstance(block.get("data"), str)
            ):
                _fail("FR0011_PROVIDER_RESPONSE_CONTENT")
        elif block_type == "text":
            if (
                text is not None
                or index != len(content) - 1
                or set(block) != {"text", "type"}
                or not isinstance(block.get("text"), str)
            ):
                _fail("FR0011_PROVIDER_RESPONSE_CONTENT")
            text = block["text"]
        else:
            _fail("FR0011_PROVIDER_RESPONSE_CONTENT")
    if text is None:
        _fail("FR0011_PROVIDER_RESPONSE_CONTENT")
    try:
        response = text.encode("utf-8")
    except UnicodeEncodeError:
        _fail("FR0011_PROVIDER_RESPONSE_CONTENT")
    parse_review_response_bytes(response, manifest=manifest)
    return response
