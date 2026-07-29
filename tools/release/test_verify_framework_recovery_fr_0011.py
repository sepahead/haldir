#!/usr/bin/env python3
"""Offline adversarial tests for the FR-0011 epoch-12 trust root."""

from __future__ import annotations

import base64
import copy
import hashlib
import importlib.util
import io
import json
import os
import stat
import subprocess
import tempfile
import unittest
import warnings
import zipfile
from collections import Counter
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from types import ModuleType
from typing import Iterator


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
    "tools/release/framework_recovery_fr_0011.py",
    "_haldir_fr0011_test_protocol",
)
RESULT = load_module(
    "tools/release/framework_recovery_fr_0011_result.py",
    "_haldir_fr0011_test_result",
)
BRIDGE = load_module(
    "tools/release/verify-framework-recovery-fr-0011.py",
    "_haldir_fr0011_test_bridge",
)
CAPTURE = load_module(
    "tools/release/framework_recovery_fr_0011_capture.py",
    "_haldir_fr0011_test_capture",
)
PINS = load_module("tools/verify-ci-pins.py", "_haldir_fr0011_test_pins")


def utc(hour: int, minute: int, second: int = 0) -> str:
    return f"2026-07-29T{hour:02d}:{minute:02d}:{second:02d}Z"


def job(name: str, database_id: int, start: int, end: int) -> dict:
    return {
        "completedAt": utc(12, end),
        "conclusion": "success",
        "databaseId": database_id,
        "name": name,
        "startedAt": utc(12, start),
        "status": "completed",
        "steps": [
            {
                "completedAt": utc(12, end),
                "conclusion": "success",
                "name": "complete",
                "number": 1,
                "startedAt": utc(12, start),
                "status": "completed",
            }
        ],
        "url": (
            f"https://github.com/sepahead/haldir/actions/runs/{RUN_ID}"
            f"/job/{database_id}"
        ),
    }


def run_documents(workflow: str = "ci") -> tuple[dict, dict]:
    if workflow == "ci":
        names = sorted(PROTOCOL.EPOCH12_CI_JOB_NAMES)
        producer = "supply-chain"
        attester = "attest-ci-audit-result"
    else:
        names = sorted(PROTOCOL.EPOCH12_FORMAL_JOB_NAMES)
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


def c5_run_documents(workflow: str = "formal") -> tuple[dict, dict]:
    run_id = PROTOCOL.C5_RUN_IDS[workflow]
    names = (
        sorted(PROTOCOL.CI_JOB_NAMES)
        if workflow == "ci"
        else sorted(PROTOCOL.FORMAL_JOB_NAMES)
    )
    jobs = []
    for index, name in enumerate(names, start=1):
        value = job(name, 60_000 + index, 1, 3)
        value["url"] = (
            f"https://github.com/sepahead/haldir/actions/runs/{run_id}"
            f"/job/{60_000 + index}"
        )
        jobs.append(value)
    common = {
        "attempt": 1,
        "conclusion": "success",
        "createdAt": utc(10, 0),
        "databaseId": run_id,
        "event": "push",
        "headBranch": "main",
        "headSha": BRIDGE.PARENT_PARENT,
        "jobs": jobs,
        "status": "completed",
        "updatedAt": utc(12, 10),
        "workflowName": workflow,
    }
    ordinary = {
        **common,
        "url": f"https://github.com/sepahead/haldir/actions/runs/{run_id}",
    }
    attempt = {
        **common,
        "startedAt": utc(10, 0),
        "url": (f"https://github.com/sepahead/haldir/actions/runs/{run_id}/attempts/1"),
        "workflowDatabaseId": PROTOCOL.WORKFLOW_DATABASE_IDS[workflow],
    }
    return ordinary, attempt


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
        "name": f"epoch-12-{workflow}-result-attempt-{attempt}.json",
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
                        "uri": "rekor.sigstore.dev",
                        "timestamp": utc(12, 7),
                    }
                ],
            },
        }
    ]
    return bundle_payload, receipt


def zip_bytes(entries: list[tuple[str, bytes, int | None]]) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, payload, mode in entries:
            info = zipfile.ZipInfo(name)
            info.compress_type = zipfile.ZIP_DEFLATED
            if mode is not None:
                info.create_system = 3
                info.external_attr = mode << 16
            archive.writestr(info, payload)
    return output.getvalue()


FORMAL_GROUP_START = (
    b"##[group]Run java -XX:+UseParallelGC -cp tla2tools.jar tlc2.TLC \\"
)
FORMAL_NEXT_GROUP = (
    b"##[group]Run actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
)
FORMAL_SUCCESS = b"Model checking completed. No error has been found."
FORMAL_ANSI_ECHO = (
    b'\x1b[36;1mgrep -c -- "Model checking completed. '
    b'No error has been found." formal.log\x1b[0m'
)
REVIEW_RESPONSE_FIELDS = (
    "additional_findings",
    "model",
    "protocol",
    "required_findings",
    "review_id",
    "verdict",
)


def formal_jobs() -> dict[str, dict]:
    return {
        "tlc-model-check": {
            "steps": [
                {
                    "completed": datetime(2026, 7, 29, 12, 3, tzinfo=timezone.utc),
                    "name": "Model-check HaldirAuthority",
                    "number": 4,
                    "started": datetime(2026, 7, 29, 12, 1, tzinfo=timezone.utc),
                }
            ]
        }
    }


def formal_archive(
    lines: list[bytes],
    *,
    group_start: bytes = FORMAL_GROUP_START,
    next_group: bytes = FORMAL_NEXT_GROUP,
    group_timestamp: str = utc(12, 1),
    next_timestamp: str = utc(12, 2),
) -> bytes:
    timestamped = [
        group_timestamp.encode("ascii") + b" " + group_start,
        *[
            utc(12, 1, index).encode("ascii") + b" " + line
            for index, line in enumerate(lines, start=1)
        ],
        next_timestamp.encode("ascii") + b" " + next_group,
    ]
    log = b"\n".join(timestamped) + b"\n"
    return zip_bytes(
        [
            (
                "0_tlc-model-check.txt",
                log,
                stat.S_IFREG | 0o644,
            ),
            (
                "tlc-model-check/system.txt",
                b"GitHub Actions hosted runner\n",
                stat.S_IFREG | 0o644,
            ),
        ]
    )


def review_material(
    review_id: str = "FR-0011-R01",
) -> tuple[dict, bytes, tuple[str, str, str]]:
    model, paths, findings = CAPTURE._review_contract(BRIDGE, review_id)
    plan = b'{"recovery_id":"FR-0011","epoch":12}\n'
    patch = b"diff --git a/a b/a\n--- a/a\n+++ b/a\n"
    gate = b"#!/bin/sh\nexec python3 verify-framework-recovery-fr-0011.py\n"
    manifest = PROTOCOL.review_subject_manifest(
        review_id=review_id,
        model=model,
        repair_commit=COMMIT,
        plan_sha256=hashlib.sha256(plan).hexdigest(),
        patch_sha256=hashlib.sha256(patch).hexdigest(),
        gate_sha256=hashlib.sha256(gate).hexdigest(),
        required_findings=findings,
    )
    request = PROTOCOL.build_review_request(
        manifest=manifest,
        plan_payload=plan,
        patch_payload=patch,
        gate_payload=gate,
    )
    return manifest, request, paths


def review_finding(
    contract: dict,
    *,
    status: str = "RESOLVED",
) -> dict:
    return {
        "affected_paths": list(contract["affected_paths"]),
        "disposition": "Verified against the authenticated epoch-12 bytes.",
        "id": contract["id"],
        "severity": "BLOCKING",
        "status": status,
        "summary": "Résolu: " + contract["summary"],
    }


def additional_finding(
    index: int,
    *,
    status: str = "RESOLVED",
) -> dict:
    return {
        "affected_paths": ["tools/release/framework_recovery_fr_0011.py"],
        "disposition": "Verified against the authenticated epoch-12 bytes.",
        "id": f"B{index:03d}",
        "severity": "BLOCKING",
        "status": status,
        "summary": f"Additional blocking finding {index}.",
    }


def review_response(
    manifest: dict,
    *,
    verdict: str = "GO_FOR_FRAMEWORK_QUALIFICATION",
    statuses: tuple[str, ...] | None = None,
    additional: list[dict] | None = None,
) -> dict:
    contracts = manifest["required_findings"]
    if statuses is None:
        statuses = ("RESOLVED",) * len(contracts)
    return {
        "additional_findings": (
            [] if additional is None else copy.deepcopy(additional)
        ),
        "model": manifest["model"],
        "protocol": PROTOCOL.REVIEW_RESPONSE_PROTOCOL,
        "required_findings": [
            review_finding(contract, status=status)
            for contract, status in zip(contracts, statuses, strict=True)
        ],
        "review_id": manifest["review_id"],
        "verdict": verdict,
    }


def provider_envelope(
    manifest: dict,
    response: bytes,
    *,
    content_prefix: list[dict] | None = None,
) -> dict:
    return {
        "content": [
            *([] if content_prefix is None else copy.deepcopy(content_prefix)),
            {"text": response.decode("utf-8"), "type": "text"},
        ],
        "id": "msg_fr0011_fixture",
        "model": manifest["model"],
        "role": "assistant",
        "stop_reason": "end_turn",
        "stop_sequence": None,
        "type": "message",
        "usage": {"input_tokens": 1024, "output_tokens": 512},
    }


def envelope_bytes(value: dict) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


@contextmanager
def changed_directory(path: Path) -> Iterator[None]:
    previous = Path.cwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(previous)


class RunDocumentTests(unittest.TestCase):
    def test_attempt_two_is_valid_and_fully_bound(self) -> None:
        ordinary, attempt = run_documents()
        result = PROTOCOL.validate_epoch12_run_documents(
            ordinary,
            attempt,
            workflow="ci",
            subject_commit=COMMIT,
            expected_ref="refs/heads/main",
        )
        self.assertEqual(result["attempt"], 2)
        self.assertEqual(result["run_id"], RUN_ID)
        self.assertEqual(set(result["jobs"]), PROTOCOL.EPOCH12_CI_JOB_NAMES)

    def test_cross_run_job_url_is_rejected(self) -> None:
        ordinary, attempt = run_documents()
        attempt["jobs"][0]["url"] = (
            "https://github.com/sepahead/haldir/actions/runs/999/job/50001"
        )
        ordinary["jobs"] = copy.deepcopy(attempt["jobs"])
        with self.assertRaisesRegex(ValueError, "FR0011_JOB"):
            PROTOCOL.validate_epoch12_run_documents(
                ordinary,
                attempt,
                workflow="ci",
                subject_commit=COMMIT,
                expected_ref="refs/heads/main",
            )

    def test_cross_attempt_documents_are_rejected(self) -> None:
        ordinary, attempt = run_documents()
        ordinary["attempt"] = 1
        with self.assertRaisesRegex(ValueError, "EPOCH12_RUN_METADATA"):
            PROTOCOL.validate_epoch12_run_documents(
                ordinary,
                attempt,
                workflow="ci",
                subject_commit=COMMIT,
                expected_ref="refs/heads/main",
            )

    def test_attempt_bound_is_fail_closed(self) -> None:
        ordinary, attempt = run_documents()
        ordinary["attempt"] = attempt["attempt"] = 9
        with self.assertRaisesRegex(ValueError, "epoch12.attempt_number"):
            PROTOCOL.validate_epoch12_run_documents(
                ordinary,
                attempt,
                workflow="ci",
                subject_commit=COMMIT,
                expected_ref="refs/heads/main",
            )


class C5RunDocumentTests(unittest.TestCase):
    def test_exact_historical_run_and_attempt_are_bound(self) -> None:
        for workflow, expected_run_id in PROTOCOL.C5_RUN_IDS.items():
            with self.subTest(workflow=workflow):
                ordinary, attempt = c5_run_documents(workflow)
                result = PROTOCOL.validate_c5_run_documents(
                    ordinary,
                    attempt,
                    workflow=workflow,
                    subject_commit=BRIDGE.PARENT_PARENT,
                )
                self.assertEqual(result["run_id"], expected_run_id)
                self.assertEqual(result["attempt"], 1)

    def test_substitute_run_or_rerun_is_rejected(self) -> None:
        ordinary, attempt = c5_run_documents()
        for label in ("run", "attempt"):
            with self.subTest(label=label):
                candidate_ordinary = copy.deepcopy(ordinary)
                candidate_attempt = copy.deepcopy(attempt)
                if label == "run":
                    candidate_ordinary["databaseId"] = 1
                else:
                    candidate_ordinary["attempt"] = 2
                    candidate_attempt["attempt"] = 2
                with self.assertRaisesRegex(ValueError, "FR0011_RUN_METADATA"):
                    PROTOCOL.validate_c5_run_documents(
                        candidate_ordinary,
                        candidate_attempt,
                        workflow="formal",
                        subject_commit=BRIDGE.PARENT_PARENT,
                    )


class ResultAndArtifactTests(unittest.TestCase):
    def test_attempt_two_result_and_artifact(self) -> None:
        payload, materials = result_payload()
        PROTOCOL.validate_result_artifact(
            payload,
            workflow="ci",
            subject_commit=COMMIT,
            subject_tree=TREE,
            run_id=RUN_ID,
            attempt=ATTEMPT,
            run_number=RUN_NUMBER,
            expected_ref="refs/heads/main",
            expected_materials=materials,
        )
        PROTOCOL.validate_artifact_metadata(
            artifact(payload),
            workflow="ci",
            run_id=RUN_ID,
            attempt=ATTEMPT,
            subject_commit=COMMIT,
            result_payload=payload,
            producer_started=datetime(2026, 7, 29, 12, 1, tzinfo=timezone.utc),
            producer_completed=datetime(2026, 7, 29, 12, 4, tzinfo=timezone.utc),
            attestation_started=datetime(2026, 7, 29, 12, 6, tzinfo=timezone.utc),
        )

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

    def test_witness_outside_attestation_job_is_rejected(self) -> None:
        payload, _materials = result_payload()
        bundle, receipt = attestation_fixture(payload)
        receipt[0]["verificationResult"]["verifiedTimestamps"][0]["timestamp"] = utc(
            12, 9
        )
        with self.assertRaisesRegex(ValueError, "TRANSPARENCY_LOG_TIME"):
            self.validate(bundle, receipt)


class TrustedRootAndCommandTests(unittest.TestCase):
    def test_real_openssh_detached_signature_is_accepted(self) -> None:
        payload = b"FR-0011 detached signature parser integration\n"
        namespace = "haldir-fr0011-openssh-integration"
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
        self.assertIn(BRIDGE.ALLOWED_SIGNERS_PATH, BRIDGE.LEGACY_RECORDS)
        self.assertIn(
            BRIDGE.ALLOWED_SIGNERS_PATH,
            BRIDGE.PROTECTED_AFTER_ACTIVATION,
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
                    with self.assertRaisesRegex(RuntimeError, "FR0011_WORKTREE"):
                        BRIDGE._verify_worktree(repo, commit, ["protected.txt"])


class RulesetTests(unittest.TestCase):
    def fixture(self) -> tuple[list, dict, list]:
        ruleset_id = 8181
        summary = {
            "id": ruleset_id,
            "name": BRIDGE.MAIN_RULESET_NAME,
            "target": "branch",
            "enforcement": "active",
            "source_type": "Repository",
            "source": "sepahead/haldir",
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
            "rules": [
                {
                    "type": "update",
                    "parameters": {"update_allows_fetch_and_merge": False},
                }
            ],
        }
        effective = [
            {
                "type": "update",
                "parameters": {"update_allows_fetch_and_merge": False},
                "ruleset_id": ruleset_id,
                "ruleset_source_type": "Repository",
                "ruleset_source": "sepahead/haldir",
            }
        ]
        return [summary], detail, effective

    def test_owner_only_main_ruleset(self) -> None:
        result = BRIDGE.validate_main_writer_ruleset(*self.fixture())
        self.assertEqual(result["owner_user_id"], 10_104_569)
        self.assertIn("GITHUB_APPS", result["protects_against"])

    def test_additional_bypass_actor_is_rejected(self) -> None:
        summary, detail, effective = self.fixture()
        detail["bypass_actors"].append(
            {"actor_id": 99, "actor_type": "User", "bypass_mode": "always"}
        )
        with self.assertRaisesRegex(RuntimeError, "RULESET_BYPASS"):
            BRIDGE.validate_main_writer_ruleset(summary, detail, effective)

    def test_fetch_and_merge_update_is_rejected(self) -> None:
        summary, detail, effective = self.fixture()
        detail["rules"][0]["parameters"]["update_allows_fetch_and_merge"] = True
        with self.assertRaisesRegex(RuntimeError, "RULESET_RULES"):
            BRIDGE.validate_main_writer_ruleset(summary, detail, effective)

    def test_non_main_condition_is_rejected(self) -> None:
        summary, detail, effective = self.fixture()
        detail["conditions"]["ref_name"]["include"] = ["~ALL"]
        with self.assertRaisesRegex(RuntimeError, "RULESET_CONDITIONS"):
            BRIDGE.validate_main_writer_ruleset(summary, detail, effective)


class ArchiveTests(unittest.TestCase):
    def test_minimal_archive_is_bounded(self) -> None:
        payload = zip_bytes(
            [
                ("0_a.txt", b"2026-07-29T12:00:00Z ok\n", stat.S_IFREG | 0o644),
                ("a/system.txt", b"runner\n", stat.S_IFREG | 0o644),
            ]
        )
        result = PROTOCOL.inspect_whole_job_archive(
            payload, expected_jobs=frozenset({"a"})
        )
        self.assertEqual(set(result["jobs"]), {"a"})

    def test_traversal_is_rejected(self) -> None:
        payload = zip_bytes(
            [
                ("0_a.txt", b"x", stat.S_IFREG | 0o644),
                ("a/system.txt", b"x", stat.S_IFREG | 0o644),
                ("../escape", b"x", stat.S_IFREG | 0o644),
            ]
        )
        with self.assertRaisesRegex(ValueError, "ARCHIVE_NAME"):
            PROTOCOL.inspect_whole_job_archive(payload, expected_jobs=frozenset({"a"}))

    def test_symlink_is_rejected(self) -> None:
        payload = zip_bytes(
            [
                ("0_a.txt", b"x", stat.S_IFLNK | 0o777),
                ("a/system.txt", b"x", stat.S_IFREG | 0o644),
            ]
        )
        with self.assertRaisesRegex(ValueError, "ENTRY_TYPE"):
            PROTOCOL.inspect_whole_job_archive(payload, expected_jobs=frozenset({"a"}))

    def test_duplicate_is_rejected(self) -> None:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            payload = zip_bytes(
                [
                    ("0_a.txt", b"x", stat.S_IFREG | 0o644),
                    ("0_a.txt", b"y", stat.S_IFREG | 0o644),
                    ("a/system.txt", b"x", stat.S_IFREG | 0o644),
                ]
            )
        with self.assertRaisesRegex(ValueError, "ARCHIVE_SHAPE"):
            PROTOCOL.inspect_whole_job_archive(payload, expected_jobs=frozenset({"a"}))

    def test_compression_bomb_ratio_is_rejected(self) -> None:
        payload = zip_bytes(
            [
                ("0_a.txt", b"\0" * (2 * 1024 * 1024), stat.S_IFREG | 0o644),
                ("a/system.txt", b"x", stat.S_IFREG | 0o644),
            ]
        )
        with self.assertRaisesRegex(ValueError, "ARCHIVE_ENTRY"):
            PROTOCOL.inspect_whole_job_archive(payload, expected_jobs=frozenset({"a"}))


class FormalC5ExactLineTests(unittest.TestCase):
    def validate(self, lines: list[bytes], **archive_options: object) -> dict:
        return PROTOCOL.validate_c5_formal_archive(
            formal_archive(lines, **archive_options),
            jobs=formal_jobs(),
        )

    def test_ansi_wrapped_echo_and_one_exact_success_line_pass(self) -> None:
        result = self.validate(
            [
                FORMAL_ANSI_ECHO,
                FORMAL_SUCCESS,
                b"Finished in 00s at (2026-07-29 12:01:03)",
            ]
        )
        self.assertEqual(
            result["critical_step"]["name"],
            "Model-check HaldirAuthority",
        )

    def test_echo_without_exact_success_line_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "FR0011_FORMAL_MARKERS"):
            self.validate(
                [
                    FORMAL_ANSI_ECHO,
                    b"Finished in 00s at (2026-07-29 12:01:02)",
                ]
            )

    def test_duplicate_exact_success_lines_are_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "FR0011_FORMAL_MARKERS"):
            self.validate(
                [
                    FORMAL_ANSI_ECHO,
                    FORMAL_SUCCESS,
                    FORMAL_SUCCESS,
                    b"Finished in 00s at (2026-07-29 12:01:04)",
                ]
            )

    def test_embedded_or_prefixed_success_is_rejected(self) -> None:
        for observed in (
            b"diagnostic: " + FORMAL_SUCCESS,
            b"prefix" + FORMAL_SUCCESS,
            FORMAL_SUCCESS + b" trailing text",
        ):
            with self.subTest(observed=observed):
                with self.assertRaisesRegex(ValueError, "FR0011_FORMAL_MARKERS"):
                    self.validate(
                        [
                            FORMAL_ANSI_ECHO,
                            observed,
                            b"Finished in 00s at (2026-07-29 12:01:03)",
                        ]
                    )

    def test_failure_tokens_remain_fail_closed(self) -> None:
        with self.assertRaisesRegex(ValueError, "FR0011_FORMAL_MARKERS"):
            self.validate(
                [
                    FORMAL_ANSI_ECHO,
                    FORMAL_SUCCESS,
                    b"##[error]TLC process reported a failure",
                    b"Finished in 00s at (2026-07-29 12:01:04)",
                ]
            )

    def test_command_group_boundary_remains_exact(self) -> None:
        with self.assertRaisesRegex(ValueError, "FR0011_COMMAND_GROUP_END"):
            self.validate(
                [
                    FORMAL_ANSI_ECHO,
                    FORMAL_SUCCESS,
                    b"Finished in 00s at (2026-07-29 12:01:03)",
                ],
                next_group=b"##[group]Run attacker/action@" + b"c" * 40,
            )

    def test_command_group_timestamp_remains_step_bound(self) -> None:
        with self.assertRaisesRegex(ValueError, "FR0011_COMMAND_GROUP_TIME"):
            self.validate(
                [
                    FORMAL_ANSI_ECHO,
                    FORMAL_SUCCESS,
                    b"Finished in 00s at (2026-07-29 12:01:03)",
                ],
                next_timestamp=utc(12, 4),
            )


class WorkflowAndPinTests(unittest.TestCase):
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
                f"epoch-12-{workflow}-result-attempt-${{{{ github.run_attempt }}}}.json",
                text,
            )
            self.assertNotIn(f"name: epoch-12-{workflow}-result-attempt", text)

    def test_github_cli_archive_is_immutable(self) -> None:
        ci = (ROOT / ".github/workflows/ci.yml").read_text()
        self.assertEqual(BRIDGE.GH_CLI_VERSION, "2.95.0")
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
        self.assertIn("verify-framework-recovery-fr-0011.py", text)


class ReviewRequestContractTests(unittest.TestCase):
    def test_both_requests_advertise_the_exact_six_field_contract(self) -> None:
        expected_instruction = (
            "exactly these six top-level keys: "
            "additional_findings, model, protocol, required_findings, "
            "review_id, verdict."
        )
        legacy_instruction = (
            "exactly review_id, verdict, required_findings, and additional_findings"
        )
        for review_id, expected_model in (
            ("FR-0011-R01", "claude-fable-5"),
            ("FR-0011-R02", "claude-opus-5"),
        ):
            with self.subTest(review_id=review_id):
                manifest, raw_request, _paths = review_material(review_id)
                request = json.loads(raw_request)
                content = request["messages"][0]["content"]
                self.assertEqual(
                    set(request),
                    {
                        "max_tokens",
                        "messages",
                        "model",
                        "output_config",
                        "system",
                    },
                )
                self.assertEqual(request["model"], expected_model)
                self.assertEqual(request["max_tokens"], 16_384)
                self.assertNotIn("thinking", request)
                self.assertEqual(request["output_config"]["effort"], "max")
                self.assertEqual(manifest["model"], expected_model)
                self.assertIn(expected_instruction, content)
                self.assertNotIn(legacy_instruction, content)
                self.assertNotIn("exactly four top-level", content)
                self.assertEqual(raw_request, PROTOCOL.canonical_json_bytes(request))

    def test_both_requests_include_the_strict_json_schema(self) -> None:
        for review_id in ("FR-0011-R01", "FR-0011-R02"):
            with self.subTest(review_id=review_id):
                manifest, raw_request, _paths = review_material(review_id)
                request = json.loads(raw_request)
                output_format = request["output_config"]["format"]
                self.assertEqual(set(output_format), {"schema", "type"})
                self.assertEqual(output_format["type"], "json_schema")
                schema = output_format["schema"]
                self.assertEqual(schema, PROTOCOL.review_output_schema(manifest))
                self.assertEqual(schema["type"], "object")
                self.assertIs(schema["additionalProperties"], False)
                self.assertEqual(schema["required"], list(REVIEW_RESPONSE_FIELDS))
                self.assertEqual(
                    set(schema["properties"]),
                    set(REVIEW_RESPONSE_FIELDS),
                )
                self.assertEqual(
                    schema["properties"]["protocol"],
                    {"const": PROTOCOL.REVIEW_RESPONSE_PROTOCOL},
                )
                self.assertEqual(
                    schema["properties"]["model"],
                    {"const": manifest["model"]},
                )
                self.assertEqual(
                    schema["properties"]["review_id"],
                    {"const": review_id},
                )
                for field in (
                    "additional_findings",
                    "required_findings",
                ):
                    finding_schema = schema["properties"][field]["items"]
                    self.assertEqual(finding_schema["type"], "object")
                    self.assertIs(finding_schema["additionalProperties"], False)


class ReviewResponseContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest, _request, _paths = review_material()
        self.response = review_response(self.manifest)
        self.literal = PROTOCOL.canonical_json_bytes(self.response)

    def parse(self, value: dict) -> dict:
        return PROTOCOL.parse_review_response_bytes(
            PROTOCOL.canonical_json_bytes(value),
            manifest=self.manifest,
        )

    def test_canonical_compact_sorted_six_field_go_passes(self) -> None:
        self.assertEqual(
            tuple(json.loads(self.literal).keys()),
            REVIEW_RESPONSE_FIELDS,
        )
        self.assertNotIn(b"\n", self.literal)
        self.assertNotIn(b'": ', self.literal)
        outcome = PROTOCOL.parse_review_response_bytes(
            self.literal,
            manifest=self.manifest,
        )
        self.assertEqual(outcome["verdict"], "GO_FOR_FRAMEWORK_QUALIFICATION")
        self.assertEqual(outcome["open_blocker_ids"], [])

    def test_each_missing_top_level_field_is_rejected(self) -> None:
        for field in REVIEW_RESPONSE_FIELDS:
            with self.subTest(field=field):
                value = copy.deepcopy(self.response)
                del value[field]
                with self.assertRaisesRegex(ValueError, "FR0011_REVIEW_RESPONSE"):
                    self.parse(value)

    def test_legacy_four_field_response_is_rejected(self) -> None:
        value = {
            field: copy.deepcopy(self.response[field])
            for field in (
                "additional_findings",
                "required_findings",
                "review_id",
                "verdict",
            )
        }
        with self.assertRaisesRegex(ValueError, "FR0011_REVIEW_RESPONSE"):
            self.parse(value)

    def test_wrong_protocol_and_model_are_rejected(self) -> None:
        mutations = {
            "protocol": "HALDIR_FR_0010_REVIEW_RESPONSE_V1",
            "model": "claude-opus-5",
        }
        for field, replacement in mutations.items():
            with self.subTest(field=field):
                value = copy.deepcopy(self.response)
                value[field] = replacement
                with self.assertRaisesRegex(ValueError, "FR0011_REVIEW_RESPONSE"):
                    self.parse(value)

    def test_noncanonical_or_decorated_bytes_are_rejected(self) -> None:
        unsorted_value = dict(reversed(list(self.response.items())))
        malformed = {
            "pretty": json.dumps(
                self.response,
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            ).encode("utf-8"),
            "unsorted": json.dumps(
                unsorted_value,
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8"),
            "newline": self.literal + b"\n",
            "bom": b"\xef\xbb\xbf" + self.literal,
            "leading_whitespace": b" " + self.literal,
            "trailing_whitespace": self.literal + b"\t",
            "fenced": b"```json\n" + self.literal + b"\n```",
        }
        self.assertNotEqual(malformed["unsorted"], self.literal)
        for label, raw in malformed.items():
            with self.subTest(label=label):
                with self.assertRaisesRegex(ValueError, "FR0011_REVIEW_RESPONSE_JSON"):
                    PROTOCOL.parse_review_response_bytes(
                        raw,
                        manifest=self.manifest,
                    )

    def test_required_finding_order_is_bound_to_the_manifest(self) -> None:
        value = copy.deepcopy(self.response)
        value["required_findings"][0], value["required_findings"][1] = (
            value["required_findings"][1],
            value["required_findings"][0],
        )
        with self.assertRaisesRegex(ValueError, "FR0011_REVIEW_FINDING"):
            self.parse(value)

    def test_required_finding_path_value_and_order_are_bound(self) -> None:
        original = self.response["required_findings"][0]["affected_paths"]
        self.assertGreater(len(original), 1)
        mutations = (
            list(reversed(original)),
            original[:-1],
            [*original[:-1], "attacker/replacement"],
        )
        for affected_paths in mutations:
            with self.subTest(affected_paths=affected_paths):
                value = copy.deepcopy(self.response)
                value["required_findings"][0]["affected_paths"] = affected_paths
                with self.assertRaisesRegex(ValueError, "FR0011_REVIEW_RESPONSE_PATHS"):
                    self.parse(value)

    def test_additional_finding_order_is_canonical(self) -> None:
        value = review_response(
            self.manifest,
            additional=[additional_finding(1), additional_finding(2)],
        )
        self.assertEqual(self.parse(value)["additional_findings"][1]["id"], "B002")
        value["additional_findings"].reverse()
        with self.assertRaisesRegex(ValueError, "FR0011_REVIEW_FINDING"):
            self.parse(value)

    def test_go_with_any_open_finding_is_rejected(self) -> None:
        statuses = ["RESOLVED"] * len(self.manifest["required_findings"])
        statuses[0] = "OPEN"
        value = review_response(
            self.manifest,
            statuses=tuple(statuses),
        )
        with self.assertRaisesRegex(ValueError, "FR0011_REVIEW_RESPONSE_VERDICT"):
            self.parse(value)

    def test_no_go_with_all_findings_closed_is_rejected(self) -> None:
        value = review_response(self.manifest, verdict="NO_GO")
        with self.assertRaisesRegex(ValueError, "FR0011_REVIEW_RESPONSE_VERDICT"):
            self.parse(value)

    def test_no_go_with_an_open_finding_passes(self) -> None:
        statuses = ["RESOLVED"] * len(self.manifest["required_findings"])
        statuses[-1] = "OPEN"
        value = review_response(
            self.manifest,
            verdict="NO_GO",
            statuses=tuple(statuses),
        )
        outcome = self.parse(value)
        self.assertEqual(outcome["verdict"], "NO_GO")
        self.assertEqual(outcome["open_blocker_ids"], ["F003"])


class ProviderMessagesEnvelopeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest, _request, _paths = review_material()
        self.literal = PROTOCOL.canonical_json_bytes(review_response(self.manifest))

    def extract(self, envelope: dict) -> bytes:
        return PROTOCOL.extract_provider_review_response_bytes(
            envelope_bytes(envelope),
            manifest=self.manifest,
        )

    def test_text_and_optional_thinking_envelopes_extract_exact_bytes(
        self,
    ) -> None:
        prefixes = {
            "text_only": [],
            "thinking": [
                {
                    "signature": "signed-thinking-fixture",
                    "thinking": "Internal analysis omitted.",
                    "type": "thinking",
                }
            ],
            "redacted_thinking": [
                {
                    "data": "opaque-redacted-thinking-fixture",
                    "type": "redacted_thinking",
                }
            ],
        }
        for label, prefix in prefixes.items():
            with self.subTest(label=label):
                self.assertEqual(
                    self.extract(
                        provider_envelope(
                            self.manifest,
                            self.literal,
                            content_prefix=prefix,
                        )
                    ),
                    self.literal,
                )

    def test_refusal_is_rejected(self) -> None:
        refusal_stop = provider_envelope(self.manifest, self.literal)
        refusal_stop["stop_reason"] = "refusal"
        refusal_block = provider_envelope(self.manifest, self.literal)
        refusal_block["content"] = [
            {"refusal": "I cannot perform this review.", "type": "refusal"}
        ]
        for label, envelope in (
            ("stop_reason", refusal_stop),
            ("content_block", refusal_block),
        ):
            with self.subTest(label=label):
                with self.assertRaisesRegex(ValueError, "FR0011_PROVIDER_RESPONSE"):
                    self.extract(envelope)

    def test_max_tokens_stop_is_rejected(self) -> None:
        envelope = provider_envelope(self.manifest, self.literal)
        envelope["stop_reason"] = "max_tokens"
        with self.assertRaisesRegex(ValueError, "FR0011_PROVIDER_RESPONSE_IDENTITY"):
            self.extract(envelope)

    def test_model_substitution_is_rejected(self) -> None:
        envelope = provider_envelope(self.manifest, self.literal)
        envelope["model"] = "claude-opus-5"
        with self.assertRaisesRegex(ValueError, "FR0011_PROVIDER_RESPONSE_IDENTITY"):
            self.extract(envelope)

    def test_required_provider_identity_fields_are_bound(self) -> None:
        for field in (
            "content",
            "id",
            "model",
            "role",
            "stop_reason",
            "stop_sequence",
            "type",
            "usage",
        ):
            with self.subTest(field=field):
                envelope = provider_envelope(self.manifest, self.literal)
                del envelope[field]
                with self.assertRaisesRegex(
                    ValueError, "FR0011_PROVIDER_RESPONSE_IDENTITY"
                ):
                    self.extract(envelope)

    def test_duplicate_provider_keys_are_rejected(self) -> None:
        raw = envelope_bytes(provider_envelope(self.manifest, self.literal))
        duplicate = (
            b'{"model":"' + self.manifest["model"].encode("ascii") + b'",' + raw[1:]
        )
        with self.assertRaisesRegex(ValueError, "FR0011_PROVIDER_RESPONSE_JSON"):
            PROTOCOL.extract_provider_review_response_bytes(
                duplicate,
                manifest=self.manifest,
            )

    def test_provider_usage_and_message_id_are_validated(self) -> None:
        mutations = {
            "id": ("id", "not-a-message-id"),
            "negative-input": (
                "usage",
                {"input_tokens": -1, "output_tokens": 1},
            ),
            "boolean-output": (
                "usage",
                {"input_tokens": 1, "output_tokens": True},
            ),
        }
        for label, (field, replacement) in mutations.items():
            with self.subTest(label=label):
                envelope = provider_envelope(self.manifest, self.literal)
                envelope[field] = replacement
                with self.assertRaisesRegex(
                    ValueError, "FR0011_PROVIDER_RESPONSE_IDENTITY"
                ):
                    self.extract(envelope)

    def test_multiple_text_blocks_are_rejected(self) -> None:
        envelope = provider_envelope(self.manifest, self.literal)
        envelope["content"].insert(
            0, {"text": self.literal.decode("utf-8"), "type": "text"}
        )
        with self.assertRaisesRegex(ValueError, "FR0011_PROVIDER_RESPONSE_CONTENT"):
            self.extract(envelope)

    def test_tool_use_is_rejected(self) -> None:
        envelope = provider_envelope(self.manifest, self.literal)
        envelope["content"].insert(
            0,
            {
                "id": "toolu_fr0011_fixture",
                "input": {},
                "name": "external_lookup",
                "type": "tool_use",
            },
        )
        with self.assertRaisesRegex(ValueError, "FR0011_PROVIDER_RESPONSE_CONTENT"):
            self.extract(envelope)

    def test_text_must_be_the_final_content_block(self) -> None:
        envelope = provider_envelope(self.manifest, self.literal)
        envelope["content"].append(
            {
                "signature": "signed-thinking-fixture",
                "thinking": "Late analysis.",
                "type": "thinking",
            }
        )
        with self.assertRaisesRegex(ValueError, "FR0011_PROVIDER_RESPONSE_CONTENT"):
            self.extract(envelope)

    def test_noncanonical_literal_inside_valid_envelope_is_rejected(
        self,
    ) -> None:
        envelope = provider_envelope(
            self.manifest,
            self.literal + b"\n",
        )
        with self.assertRaisesRegex(ValueError, "FR0011_REVIEW_RESPONSE_JSON"):
            self.extract(envelope)


class ReviewCapturePrimitiveTests(unittest.TestCase):
    def test_request_to_envelope_to_literal_to_records(self) -> None:
        manifest, raw_request, paths = review_material("FR-0011-R02")
        request = json.loads(raw_request)
        self.assertEqual(request["model"], "claude-opus-5")
        literal = PROTOCOL.canonical_json_bytes(review_response(manifest))
        provider_raw = envelope_bytes(
            provider_envelope(
                manifest,
                literal,
                content_prefix=[
                    {
                        "data": "opaque-redacted-thinking-fixture",
                        "type": "redacted_thinking",
                    }
                ],
            )
        )
        extracted = PROTOCOL.extract_provider_review_response_bytes(
            provider_raw,
            manifest=manifest,
        )
        self.assertEqual(extracted, literal)
        outcome = PROTOCOL.parse_review_response_bytes(
            extracted,
            manifest=manifest,
        )
        self.assertEqual(outcome["verdict"], "GO_FOR_FRAMEWORK_QUALIFICATION")
        self.assertEqual(len(paths), 3)
        provider_record = CAPTURE._blob_record(paths[1], provider_raw)
        response_record = CAPTURE._blob_record(paths[2], extracted)
        self.assertEqual(
            provider_record["sha256"],
            hashlib.sha256(provider_raw).hexdigest(),
        )
        self.assertEqual(
            response_record["sha256"],
            hashlib.sha256(literal).hexdigest(),
        )
        self.assertEqual(provider_record["bytes"], len(provider_raw))
        self.assertEqual(response_record["bytes"], len(literal))
        self.assertIn("-provider-response.json", provider_record["path"])
        self.assertTrue(response_record["path"].endswith("-response.json"))
        self.assertNotEqual(
            provider_record["git_object_id"],
            response_record["git_object_id"],
        )


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
    def test_blob_record_matches_git_object_format(self) -> None:
        value = CAPTURE._blob_record("evidence.json", b"{}\n")
        completed = subprocess.run(
            ["/usr/bin/git", "hash-object", "--stdin"],
            input=b"{}\n",
            stdout=subprocess.PIPE,
            check=True,
        )
        self.assertEqual(value["git_object_id"], completed.stdout.decode().strip())

    def test_epoch12_field_contracts(self) -> None:
        self.assertEqual(
            CAPTURE._run_fields(epoch12=True, attempt=False),
            (
                "attempt,conclusion,createdAt,databaseId,event,headBranch,"
                "headSha,jobs,number,status,updatedAt,url,workflowDatabaseId,"
                "workflowName"
            ),
        )
        self.assertIn(
            "startedAt",
            CAPTURE._run_fields(epoch12=True, attempt=True),
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
