#!/usr/bin/env python3
"""Frozen tests for the CH-T003 registered verifier."""

from __future__ import annotations

import gzip
import importlib.util
import io
import itertools
import random
import subprocess
import sys
import tempfile
import time
import unittest
import warnings
import zipfile
from copy import deepcopy
from pathlib import Path
from unittest import mock

_CLAIM_TIER_FIXTURE_CACHE = None
_PRIOR_SNAPSHOT_CACHE = None


def verifier():
    cached = sys.modules.get("_haldir_ch_t003_verifier")
    if cached is not None:
        return cached
    path = Path(__file__).with_name("verify.py")
    spec = importlib.util.spec_from_file_location("_haldir_ch_t003_verifier", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("verifier import failed")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class RegisteredVerifierTests(unittest.TestCase):
    def repo(self) -> Path:
        return Path(__file__).resolve().parents[5]

    def prior_snapshot(self, module):
        global _PRIOR_SNAPSHOT_CACHE
        if _PRIOR_SNAPSHOT_CACHE is None:
            _PRIOR_SNAPSHOT_CACHE = module.tree_snapshot(
                self.repo(), module.PRIOR_ACTIVATION
            )
        return _PRIOR_SNAPSHOT_CACHE

    def zip_payload(
        self,
        members: list[tuple[str | zipfile.ZipInfo, bytes]],
        compression: int,
    ) -> bytes:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", compression) as archive:
            for name, payload in members:
                archive.writestr(name, payload)
        return buffer.getvalue()

    def insert_before_zip_central_directory(self, payload, inserted):
        value = bytearray(payload)
        eocd = value.rfind(b"PK\x05\x06")
        central_offset = int.from_bytes(value[eocd + 16 : eocd + 20], "little")
        value[central_offset:central_offset] = inserted
        eocd += len(inserted)
        value[eocd + 16 : eocd + 20] = (central_offset + len(inserted)).to_bytes(
            4, "little"
        )
        return bytes(value)

    def zip_payload_with_data_descriptor(self):
        value = bytearray(
            self.zip_payload(
                [("member.txt", b"payload")],
                zipfile.ZIP_DEFLATED,
            )
        )
        local = value.find(b"PK\x03\x04")
        central = value.find(b"PK\x01\x02")
        crc_and_sizes = bytes(value[local + 14 : local + 26])
        value[local + 6 : local + 8] = (0x08).to_bytes(2, "little")
        value[local + 14 : local + 26] = b"\x00" * 12
        value[central + 8 : central + 10] = (0x08).to_bytes(2, "little")
        return self.insert_before_zip_central_directory(
            bytes(value),
            b"PK\x07\x08" + crc_and_sizes,
        )

    def current_state_fixture(self, module):
        implementation_ledger = (
            f"| {module.NARROWED_CLAIM} | Narrow statement. | PROVEN | Evidence. |\n"
            "| CL-OTHER-01 | Other statement. | UNPROVEN | Evidence. |\n"
        ).encode()
        current_ledger = implementation_ledger.replace(
            b"Other statement.",
            b"Later unrelated statement.",
        )
        implementation_entries = []
        current_entries = []
        for index, path in enumerate(module.IMPLEMENTATION_PLAN, 1):
            implementation_entry = {
                "path": path,
                "git_mode": "100644",
                "git_object_type": "blob",
                "git_object_id": f"{index:040x}",
            }
            implementation_entries.append(implementation_entry)
            current_entries.append(deepcopy(implementation_entry))
        ledger_index = next(
            index
            for index, item in enumerate(current_entries)
            if item["path"] == module.CLAIM_LEDGER_PATH
        )
        current_entries[ledger_index]["git_object_id"] = "f" * 40
        return {
            "implementation_entries": implementation_entries,
            "implementation_blobs": {
                module.CLAIM_LEDGER_PATH: implementation_ledger,
            },
            "current_entries": current_entries,
            "current_blobs": {
                module.CLAIM_LEDGER_PATH: current_ledger,
            },
        }

    def current_state_entry(self, fixture, commit, path):
        collection = (
            fixture["implementation_entries"]
            if commit == "1" * 40
            else fixture["current_entries"]
        )
        return deepcopy(next(item for item in collection if item["path"] == path))

    def current_state_file(self, fixture, commit, path, **_kwargs):
        self.assertEqual(path, "docs/CLAIM-LEDGER.md")
        collection = (
            fixture["implementation_blobs"]
            if commit == "1" * 40
            else fixture["current_blobs"]
        )
        return collection[path]

    def retained_command(self, module):
        stdout = "registered output\n"
        stderr = ""
        return {
            "id": "CH-T003-CMD-TEST",
            "phase": "REGISTERED_TESTS",
            "argv": ["/opt/homebrew/bin/python3.14", "-B", "test.py"],
            "cwd": ".",
            "exit_code": 0,
            "started_at_utc": "2026-07-23T00:00:01Z",
            "completed_at_utc": "2026-07-23T00:00:02Z",
            "stdout": stdout,
            "stdout_sha256": module.sha256(stdout.encode("utf-8")),
            "stderr": stderr,
            "stderr_sha256": module.sha256(stderr.encode("utf-8")),
        }

    def common_evidence(self, module):
        identifier = "CH-T003-E01"
        record = {
            key: None
            for key in (
                module.EVIDENCE_COMMON_FIELDS
                | module.EVIDENCE_SPECIFIC_FIELDS[identifier]
            )
        }
        record.update(
            {
                "schema_id": "haldir.ch-t003.file-review-traceability.v1",
                "evidence_id": identifier,
                "task_id": module.TASK_ID,
                "epoch": module.EPOCH,
                "freeze_commit": "f" * 40,
                "implementation_commit": "1" * 40,
                "started_at_utc": "2026-07-23T00:00:01Z",
                "completed_at_utc": "2026-07-23T00:00:02Z",
                "result": "PASS",
            }
        )
        return record

    def activation_command(self, module, identifier, phase, argv, stdout):
        stderr = ""
        return {
            "id": identifier,
            "phase": phase,
            "argv": argv,
            "cwd": ".",
            "exit_code": 0,
            "started_at_utc": "2026-07-23T00:00:04Z",
            "completed_at_utc": "2026-07-23T00:00:05Z",
            "stdout": stdout,
            "stdout_sha256": module.sha256(stdout.encode("utf-8")),
            "stderr": stderr,
            "stderr_sha256": module.sha256(stderr.encode("utf-8")),
        }

    def activation_log_payload(self, name):
        return f"{name}: completed successfully\n".encode("utf-8")

    def activation_log_captures(self, module):
        return [
            {
                "name": name,
                "retained_member": module.JOB_LOG_MEMBERS[name],
                "bytes": len(self.activation_log_payload(name)),
                "sha256": module.sha256(self.activation_log_payload(name)),
            }
            for name in module.ALL_HOSTED_JOB_NAMES
        ]

    def activation_archive(self, module, captures):
        if captures is None:
            captures = self.activation_log_captures(module)
        buffer = io.BytesIO()
        with zipfile.ZipFile(
            buffer,
            "w",
            compression=zipfile.ZIP_STORED,
            strict_timestamps=True,
        ) as archive:
            for capture in captures:
                info = zipfile.ZipInfo(
                    capture["retained_member"],
                    date_time=(1980, 1, 1, 0, 0, 0),
                )
                info.create_system = 3
                info.external_attr = 0o100644 << 16
                info.compress_type = zipfile.ZIP_STORED
                archive.writestr(
                    info,
                    self.activation_log_payload(capture["name"]),
                    compress_type=zipfile.ZIP_STORED,
                )
        return buffer.getvalue()

    def retained_capture(
        self,
        module,
        kind,
        source_url,
        payload,
        started_at_utc,
        completed_at_utc,
    ):
        stderr = ""
        api_path = source_url.removeprefix("https://api.github.com/")
        return {
            "bytes": len(payload),
            "capture_argv": [
                "/opt/homebrew/bin/gh",
                "api",
                "--hostname",
                "github.com",
                "--method",
                "GET",
                "-H",
                "Accept: application/vnd.github+json",
                "-H",
                "X-GitHub-Api-Version: 2022-11-28",
                api_path,
            ],
            "completed_at_utc": completed_at_utc,
            "content_base64": module.base64.b64encode(payload).decode("ascii"),
            "exit_code": 0,
            "kind": kind,
            "media_type": "application/vnd.github+json",
            "request_headers": [
                "Accept: application/vnd.github+json",
                "X-GitHub-Api-Version: 2022-11-28",
            ],
            "sha256": module.sha256(payload),
            "source_url": source_url,
            "started_at_utc": started_at_utc,
            "stderr": stderr,
            "stderr_sha256": module.sha256(stderr.encode("utf-8")),
            "tool_version": "gh version 2.76.2 (2026-07-01)",
        }

    def activation_a01(
        self, module, freeze_commit, implementation_commit, qualification_commit
    ):
        executable = "/opt/homebrew/bin/python3.14"
        phases = [
            "PRODUCT_TESTS",
            "PRODUCT_VERIFY",
            "REGISTERED_TESTS",
            "EXACT_IMPLEMENTATION_VERIFY",
        ]
        tails = {
            "PRODUCT_TESTS": ["-B", "-I", "-P", module.PRODUCT_TESTS_PATH],
            "PRODUCT_VERIFY": [
                "-B",
                "-I",
                "-P",
                module.PRODUCT_PATH,
                "verify",
                "--repo",
                ".",
                "--implementation-commit",
                implementation_commit,
            ],
            "REGISTERED_TESTS": ["-B", "-I", "-P", module.TESTS_PATH],
            "EXACT_IMPLEMENTATION_VERIFY": [
                "-B",
                "-I",
                "-P",
                module.VERIFIER_PATH,
                "--repo",
                ".",
                "--freeze-commit",
                freeze_commit,
                "--implementation-commit",
                implementation_commit,
                "--implementation-only",
            ],
        }
        outputs = {
            "PRODUCT_TESTS": "tests passed\n",
            "PRODUCT_VERIFY": module.canonical_json(
                {
                    "schema_id": "haldir.ch-t003.product-verification.v1",
                    "mode": "FROZEN_PRODUCT_CHECKS",
                    "result": "PASS",
                }
            ).decode("utf-8"),
            "REGISTERED_TESTS": "tests passed\n",
            "EXACT_IMPLEMENTATION_VERIFY": module.canonical_json(
                {
                    "task_id": module.TASK_ID,
                    "freeze_commit": freeze_commit,
                    "implementation_commit": implementation_commit,
                    "mode": "IMPLEMENTATION_ONLY",
                    "result": "PASS",
                }
            ).decode("utf-8"),
        }
        commands = [
            self.activation_command(
                module,
                f"CH-T003-A01-CMD{index:02d}",
                phase,
                [executable, *tails[phase]],
                outputs[phase],
            )
            for index, phase in enumerate(phases, 1)
        ]
        return {
            "checks": phases,
            "commands": commands,
            "completed_at_utc": "2026-07-23T00:00:05Z",
            "epoch": module.EPOCH,
            "evidence_id": "CH-T003-A01",
            "freeze_commit": freeze_commit,
            "implementation_commit": implementation_commit,
            "qualification_commit": qualification_commit,
            "result": "PASS",
            "schema_id": "haldir.ch-t003.subsystem-gate.v1",
            "started_at_utc": "2026-07-23T00:00:04Z",
            "task_id": module.TASK_ID,
        }

    def activation_a02(
        self, module, freeze_commit, implementation_commit, qualification_commit
    ):
        transcript = (
            "\n".join(
                [
                    *[f"  PASS: gate-{index:02d}" for index in range(1, 31)],
                    "P0-R exit gate: 30 passed, 0 failed",
                    (
                        "All offline P0-R gates passed. "
                        "(TLA+ check runs in CI: CL-FORMAL-01.)"
                    ),
                ]
            )
            + "\n"
        )
        command = self.activation_command(
            module,
            "CH-T003-A02-CMD01",
            "WAVE_GATE",
            [
                "/usr/bin/env",
                "-u",
                "BASH_ENV",
                "-u",
                "ENV",
                "CARGO_TERM_COLOR=never",
                "TERM=dumb",
                "/bin/bash",
                "--noprofile",
                "--norc",
                "tools/p0r-exit-gate.sh",
            ],
            transcript,
        )
        return {
            "command": command,
            "completed_at_utc": "2026-07-23T00:00:05Z",
            "epoch": module.EPOCH,
            "evidence_id": "CH-T003-A02",
            "freeze_commit": freeze_commit,
            "implementation_commit": implementation_commit,
            "qualification_commit": qualification_commit,
            "result": "PASS",
            "schema_id": "haldir.ch-t003.wave-gate.v2",
            "scope": {
                "execution_wave": 0,
                "gate_scope": "FULL_REPOSITORY_LOCKED_GATE_AT_CH_T003_CANDIDATE",
                "remaining_wave_tasks": [f"CH-T{index:03d}" for index in range(4, 13)],
                "wave_acceptance": "NOT_YET_ELIGIBLE",
            },
            "started_at_utc": "2026-07-23T00:00:04Z",
            "task_id": module.TASK_ID,
        }

    def activation_a03(
        self, module, freeze_commit, implementation_commit, qualification_commit
    ):
        workflows = []
        all_log_captures = []
        next_job_id = 100
        for ordinal, (workflow_path, job_names) in enumerate(
            module.HOSTED_WORKFLOW_SPECS
        ):
            run_id = 42 + ordinal
            run_attempt = 1
            api_root = (
                f"https://api.github.com/repos/sepahead/haldir/actions/runs/{run_id}"
            )
            run_url = f"https://github.com/sepahead/haldir/actions/runs/{run_id}"
            workflow_started = (
                "2026-07-23T00:00:04Z" if ordinal == 0 else "2026-07-23T00:00:06Z"
            )
            workflow_completed = (
                "2026-07-23T00:00:06Z" if ordinal == 0 else "2026-07-23T00:00:08Z"
            )
            capture_started = (
                "2026-07-23T00:00:04Z" if ordinal == 0 else "2026-07-23T00:00:06Z"
            )
            capture_completed = (
                "2026-07-23T00:00:05Z" if ordinal == 0 else "2026-07-23T00:00:07Z"
            )
            log_started = (
                "2026-07-23T00:00:05Z" if ordinal == 0 else "2026-07-23T00:00:07Z"
            )
            log_completed = (
                "2026-07-23T00:00:06Z" if ordinal == 0 else "2026-07-23T00:00:08Z"
            )
            jobs = []
            raw_jobs = []
            log_captures = []
            for name in job_names:
                job_id = next_job_id
                next_job_id += 1
                jobs.append(
                    {
                        "conclusion": "success",
                        "job_id": job_id,
                        "name": name,
                    }
                )
                raw_jobs.append(
                    {
                        "id": job_id,
                        "name": name,
                        "run_id": run_id,
                        "run_attempt": run_attempt,
                        "head_sha": qualification_commit,
                        "status": "completed",
                        "conclusion": "success",
                        "started_at": "2026-07-23T00:00:01Z",
                        "completed_at": "2026-07-23T00:00:02Z",
                    }
                )
                payload = self.activation_log_payload(name)
                api_path = f"repos/sepahead/haldir/actions/jobs/{job_id}/logs"
                capture = {
                    "bytes": len(payload),
                    "capture_argv": [
                        "/opt/homebrew/bin/gh",
                        "api",
                        "--hostname",
                        "github.com",
                        "--method",
                        "GET",
                        "-H",
                        "Accept: application/vnd.github+json",
                        "-H",
                        "X-GitHub-Api-Version: 2022-11-28",
                        api_path,
                    ],
                    "completed_at_utc": log_completed,
                    "exit_code": 0,
                    "job_id": job_id,
                    "kind": "JOB_LOG_TEXT",
                    "media_type": "text/plain",
                    "name": name,
                    "request_headers": [
                        "Accept: application/vnd.github+json",
                        "X-GitHub-Api-Version: 2022-11-28",
                    ],
                    "retained_member": module.JOB_LOG_MEMBERS[name],
                    "sha256": module.sha256(payload),
                    "source_url": f"https://api.github.com/{api_path}",
                    "started_at_utc": log_started,
                    "stderr": "",
                    "stderr_sha256": module.sha256(b""),
                    "tool_version": "gh version 2.76.2 (2026-07-01)",
                }
                log_captures.append(capture)
                all_log_captures.append(capture)
            run_document = {
                "id": run_id,
                "run_attempt": run_attempt,
                "url": api_root,
                "html_url": run_url,
                "path": workflow_path,
                "event": "push",
                "head_branch": "main",
                "head_sha": qualification_commit,
                "status": "completed",
                "conclusion": "success",
                "repository": {"full_name": "sepahead/haldir"},
                "created_at": "2026-07-23T00:00:01Z",
                "updated_at": "2026-07-23T00:00:03Z",
            }
            jobs_document = {
                "total_count": len(jobs),
                "jobs": raw_jobs,
            }
            jobs_source = f"{api_root}/attempts/{run_attempt}/jobs?per_page=100"
            workflows.append(
                {
                    "completed_at_utc": workflow_completed,
                    "conclusion": "success",
                    "head_sha": qualification_commit,
                    "job_log_captures": log_captures,
                    "jobs": jobs,
                    "retained_records": [
                        self.retained_capture(
                            module,
                            "RUN_API_JSON",
                            api_root,
                            module.canonical_json(run_document),
                            started_at_utc=capture_started,
                            completed_at_utc=capture_completed,
                        ),
                        self.retained_capture(
                            module,
                            "ATTEMPT_JOBS_API_JSON",
                            jobs_source,
                            module.canonical_json(jobs_document),
                            started_at_utc=capture_started,
                            completed_at_utc=capture_completed,
                        ),
                    ],
                    "run_attempt": run_attempt,
                    "run_id": run_id,
                    "run_url": run_url,
                    "started_at_utc": workflow_started,
                    "workflow_path": workflow_path,
                }
            )
        archive_payload = self.activation_archive(
            module,
            all_log_captures,
        )
        manifest = module.activation_log_manifest(
            archive_payload,
            all_log_captures,
        )
        return (
            {
                "combined_log_archive": {
                    "artifact_evidence_id": "CH-T003-A05",
                    "completed_at_utc": "2026-07-23T00:00:09Z",
                    "entry_manifest": manifest,
                    "file": module.prospective_file_record(
                        module.ACTIVATION_PATHS["CH-T003-A05"],
                        archive_payload,
                    ),
                    "format": "ZIP_STORED_FLAT_EXACT_JOB_LOGS_V1",
                    "started_at_utc": min(
                        item["started_at_utc"] for item in all_log_captures
                    ),
                },
                "completed_at_utc": "2026-07-23T00:00:09Z",
                "conclusion": "success",
                "epoch": module.EPOCH,
                "evidence_id": "CH-T003-A03",
                "freeze_commit": freeze_commit,
                "head_sha": qualification_commit,
                "implementation_commit": implementation_commit,
                "provider": "GITHUB_ACTIONS",
                "qualification_commit": qualification_commit,
                "result": "PASS",
                "schema_id": "haldir.ch-t003.full-locked-ci.v3",
                "started_at_utc": "2026-07-23T00:00:04Z",
                "task_id": module.TASK_ID,
                "workflows": workflows,
            },
            archive_payload,
        )

    def activation_state_fixture(self, module):
        freeze_commit = "f" * 40
        implementation_commit = "1" * 40
        qualification_commit = "c" * 40
        activation_commit = "d" * 40
        claim_id = module.NARROWED_CLAIM
        ledger_payload = (
            f"| {claim_id} | Narrow statement. | PROVEN | Bound support. |\n"
        ).encode("utf-8")
        prospective = module.prospective_file_record(
            module.CLAIM_LEDGER_PATH,
            ledger_payload,
            include_selected_lines=True,
        )
        implementation_entries = [
            {
                "path": prospective["path"],
                "git_mode": prospective["git_mode"],
                "git_object_type": prospective["git_object_type"],
                "git_object_id": prospective["git_object_id"],
            }
        ]
        implementation_blobs = {
            module.CLAIM_LEDGER_PATH: ledger_payload,
        }
        claim_record = module.exact_file_record(
            module.CLAIM_LEDGER_PATH,
            implementation_entries,
            implementation_blobs,
            include_selected_lines=True,
        )
        prior_requirements = {
            "schema_version": "1.0.0",
            "overall_status": "NO_GO",
            "tasks": [
                {
                    "id": f"CH-T{index:03d}",
                    "status": "OPEN",
                }
                for index in range(126)
            ],
        }
        prior_claims = {
            "schema_version": "1.0.0",
            "current_epochs": {"CH-T002": "E0002"},
            "public_surface_records": [],
            "tag_authorized": False,
            "github_release_authorized": False,
            "doi_authorized": False,
            "zenodo_authorized": False,
            "archive_authorized": False,
        }
        freeze = {
            "activation_evidence_requirements": [{"id": "CH-T003-A01"}],
        }
        qualification = {
            "freeze_commit": freeze_commit,
            "review_records": [{"id": "CH-T003-R01"}],
            "evidence_records": [{"id": "CH-T003-E01"}],
            "twenty_lens_reviews": {"L01": {"status": "RESOLVED"}},
            "limitations": ["No release authority is granted."],
        }
        outcome = {
            "claim_disposition": "ACTIVE_NARROWED_PENDING_ACTIVATION",
            "overall_status": "NO_GO",
            "active_claims": [claim_id],
            "release_qualified_claims": [],
            "removed_claims": [],
            "non_claimed_claims": [],
            "narrowed_claims": [claim_id],
            "public_surfaces": [module.CLAIM_LEDGER_PATH],
        }
        inventory = module.claim_inventory(ledger_payload)
        expected_requirements = deepcopy(prior_requirements)
        expected_requirements["tasks"][3].update(
            {
                "status": "VERIFIED",
                "claim_disposition": outcome["claim_disposition"],
                "assigned_reviewers": ["CH-T003-R01"],
                "implementation_commits": [
                    freeze_commit,
                    implementation_commit,
                ],
                "evidence": ["CH-T003-E01", "CH-T003-A01"],
                "closure_commit": qualification_commit,
                "twenty_lens_reviews": qualification["twenty_lens_reviews"],
            }
        )
        expected_requirements["overall_status"] = "NO_GO"
        expected_claims = deepcopy(prior_claims)
        expected_claims.update(
            {
                "verified_prefix": 4,
                "overall_status": "NO_GO",
                "claim_inventory": inventory,
                "asserted_claims": inventory,
                "active_claims": [claim_id],
                "release_qualified_claims": [],
                "removed_claims": [],
                "non_claimed_claims": [],
                "narrowed_claims": [claim_id],
                "residual_limitations": qualification["limitations"],
                "current_epochs": {
                    "CH-T002": "E0002",
                    module.TASK_ID: module.EPOCH,
                },
                "public_surface_records": [claim_record],
                "claim_ledger": claim_record,
                "tag_authorized": False,
                "github_release_authorized": False,
                "doi_authorized": False,
                "zenodo_authorized": False,
                "archive_authorized": False,
            }
        )
        return {
            "freeze_commit": freeze_commit,
            "implementation_commit": implementation_commit,
            "qualification_commit": qualification_commit,
            "activation_commit": activation_commit,
            "freeze": freeze,
            "qualification": qualification,
            "outcome": outcome,
            "qualification_entries": [],
            "qualification_blobs": {
                module.REQUIREMENTS_PATH: module.canonical_json(prior_requirements),
                module.CLAIMS_STATE_PATH: module.canonical_json(prior_claims),
            },
            "activation_entries": [],
            "activation_blobs": {
                module.REQUIREMENTS_PATH: module.canonical_json(expected_requirements),
                module.CLAIMS_STATE_PATH: module.canonical_json(expected_claims),
            },
            "implementation_entries": implementation_entries,
            "implementation_blobs": implementation_blobs,
            "expected_requirements": expected_requirements,
            "expected_claims": expected_claims,
            "ledger_payload": ledger_payload,
        }

    def assert_verify_error(self, module, expected, operation):
        with self.assertRaises(module.VerifyError) as observed:
            operation()
        self.assertEqual(str(observed.exception), expected)

    def product_identity(self, module, schema_id, **fields):
        return {
            "schema_version": "1.0.0",
            "schema_id": schema_id,
            "task_id": module.TASK_ID,
            "release_target": module.RELEASE_TARGET,
            "author": deepcopy(module.AUTHOR),
            "persistent_identifier": None,
            "result": "PASS",
            **fields,
        }

    def candidate_plan_fixture(self, module):
        cyclic_outputs = {
            module.CLAIM_TIER_PATH,
            module.REVIEW_OVERLAY_PATH,
            module.GITHUB_METADATA_PATH,
            module.LEDGER_COMPOSITION_PATH,
            module.PUBLIC_INVENTORY_PATH,
            module.CLAIM_LANGUAGE_PATH,
        }
        entries = []
        blobs = {}
        records = []
        for ordinal, (path, change) in enumerate(
            module.IMPLEMENTATION_PLAN.items(),
            1,
        ):
            if path in cyclic_outputs:
                records.append(
                    {
                        "path": path,
                        "change": change,
                        "binding_kind": "NO_INNER_DIGEST",
                        "sha256": None,
                        "bytes": None,
                    }
                )
                continue
            payload = f"candidate {ordinal}: {path}\n".encode()
            blobs[path] = payload
            entries.append(
                {
                    "path": path,
                    "git_mode": "100644",
                    "git_object_type": "blob",
                    "git_object_id": module.sha256(payload)[:40],
                }
            )
            records.append(
                {
                    "path": path,
                    "change": change,
                    "binding_kind": "EXACT_CANDIDATE_BYTES",
                    "sha256": module.sha256(payload),
                    "bytes": len(payload),
                }
            )
        section = {
            "records": records,
            "paths_sha256": module.sha256(
                module.canonical_json(list(module.IMPLEMENTATION_PLAN))
            ),
            "records_sha256": module.sha256(module.canonical_json(records)),
            "expected_implementation_regular_blobs": 434,
            "cycle_boundary": (
                "Generated products omit their own inner digest. "
                "The signed commit binds their exact bytes."
            ),
        }
        return section, entries, blobs

    def inventory_records_fixture(self, module):
        paths = [
            "release/0.9.0/allowed-signers",
            "tools/generated-surface.py",
            "crates/generated-surface/src/lib.rs",
            *[f"docs/generated-surface-{index:03d}.md" for index in range(423)],
        ]
        paths.sort(key=lambda item: item.encode("utf-8"))
        entries = []
        blobs = {}
        records = []
        for ordinal, path in enumerate(paths):
            payload = (
                b"ssh-ed25519 AAAA fixture\n"
                if path.endswith("allowed-signers")
                else (
                    b"pub struct GeneratedSurface;\n"
                    if path.endswith(".rs")
                    else f"surface {ordinal} CL-FIXTURE-{ordinal:03d}\n".encode()
                )
            )
            entry = {
                "path": path,
                "git_mode": "100644",
                "git_object_type": "blob",
                "git_object_id": module.sha256(payload + path.encode())[:40],
            }
            classification, disposition, reason = module.inventory_classification(path)
            entries.append(entry)
            blobs[path] = payload
            records.append(
                {
                    **entry,
                    "bytes": len(payload),
                    "sha256": module.sha256(payload),
                    "lines": (
                        len(payload.decode("utf-8").splitlines())
                        if module.content_kind(path, payload) == "UTF8"
                        else None
                    ),
                    "content_kind": module.content_kind(path, payload),
                    "classification": classification,
                    "disposition": disposition,
                    "classification_reason": reason,
                    "surface_types": module.inventory_surface_types(
                        path,
                        payload,
                        classification,
                    ),
                    "claim_ids": module.claim_ids(payload),
                }
            )
        return records, entries, blobs

    def claim_tier_fixture(self, module):
        global _CLAIM_TIER_FIXTURE_CACHE
        if _CLAIM_TIER_FIXTURE_CACHE is not None:
            return deepcopy(_CLAIM_TIER_FIXTURE_CACHE)
        freeze_commit = module.PRIOR_ACTIVATION
        freeze_tree = module.PRIOR_ACTIVATION_TREE
        _entries, blobs = self.prior_snapshot(module)
        freeze_payload = blobs[module.CLAIM_LEDGER_PATH]
        state_payload = blobs[module.CLAIMS_STATE_PATH]
        state = module.load_json(state_payload, canonical=False)
        before_rows = module.parse_claim_rows(freeze_payload)
        before_target = next(
            item for item in before_rows if item["id"] == module.NARROWED_CLAIM
        )
        narrowed_statement = (
            "Repository VERIFIED evidence primitives do not establish "
            "VALIDATED, DEPLOYMENT_QUALIFIED, or FIELD_VALIDATED status, "
            "a release-qualified artifact, transport delivery, or "
            "operational use."
        )
        candidate_payload = freeze_payload.replace(
            before_target["statement"].encode(),
            narrowed_statement.encode(),
            1,
        )
        after_rows = module.parse_claim_rows(candidate_payload)
        non_claimed = set(state["non_claimed_claims"])
        removed = set(state["removed_claims"])
        records = []
        for row in after_rows:
            claim_id = row["id"]
            claim_type = module.expected_claim_type(claim_id)
            disposition = (
                "NOT_CLAIMED"
                if claim_id in non_claimed
                else "REMOVED"
                if claim_id in removed
                else "ACTIVE"
            )
            narrowing = None
            if claim_id == module.NARROWED_CLAIM:
                disposition = "ACTIVE_NARROWED_PENDING_ACTIVATION"
                narrowing = {
                    "narrowed": True,
                    "markdown_status_preserved": "PROVEN",
                    "generated_tier_preserved": "VERIFIED",
                    "scope": (
                        "Repository evidence primitives are verified. "
                        "This does not qualify a release, deployment, DOI, "
                        "archive, or field result."
                    ),
                }
            tier = module.TIER_BY_STATUS[row["status"]]
            records.append(
                {
                    **row,
                    "lifecycle_disposition": disposition,
                    "evidence_tier": tier,
                    "claim_type": claim_type,
                    "minimum_evidence": module.MINIMUM_EVIDENCE_BY_CLAIM_TYPE[
                        claim_type
                    ],
                    "observed_evidence_classes": (
                        ["SIGNED_REPOSITORY_EVIDENCE"] if tier == "VERIFIED" else []
                    ),
                    "non_substitutes": module.NON_SUBSTITUTES_BY_CLAIM_TYPE[claim_type],
                    "linked_surfaces": [module.CLAIM_LEDGER_PATH],
                    "release_qualified": False,
                    "narrowing": narrowing,
                }
            )
        claim_ids = sorted(item["id"] for item in records)
        reverse = [
            {
                "surface": module.CLAIM_LEDGER_PATH,
                "claim_ids": claim_ids,
            }
        ]
        status_counts = {}
        for item in records:
            status = item["status"]
            status_counts[status] = status_counts.get(status, 0) + 1
        product = self.product_identity(
            module,
            "haldir.ch-t003.claim-tier-ledger.v1",
            source={
                "freeze_commit": freeze_commit,
                "freeze_tree": freeze_tree,
                "claim_ledger": {
                    "path": module.CLAIM_LEDGER_PATH,
                    "sha256": module.sha256(candidate_payload),
                    "bytes": len(candidate_payload),
                },
                "prior_active_claims": {
                    "path": module.CLAIMS_STATE_PATH,
                    "sha256": module.sha256(state_payload),
                    "bytes": len(state_payload),
                },
            },
            tier_vocabulary=list(module.TIER_VOCABULARY),
            policy={
                "status_and_tier_are_distinct": True,
                "conservative_mapping": {
                    "PROVEN": "VERIFIED",
                    "ALL_OTHER_MARKDOWN_STATUSES": "NOT_CLAIMED",
                },
                "no_tier_above_verified_assigned": True,
            },
            records=records,
            counts={
                "claims": 52,
                "by_status": dict(sorted(status_counts.items())),
                "by_tier": {"NOT_CLAIMED": 7, "VERIFIED": 45},
                "narrowed": 1,
                "release_qualified": 0,
            },
            bidirectional_links={
                "claim_to_surface_complete": True,
                "surface_to_claims": reverse,
                "surface_to_claims_sha256": module.sha256(
                    module.canonical_json(reverse)
                ),
            },
            records_sha256=module.sha256(module.canonical_json(records)),
            release_boundary={
                "overall_status": "NO_GO",
                "release_qualified_claims": [],
                "archive_authorized": False,
                "doi_authorized": False,
                "github_release_authorized": False,
                "tag_authorized": False,
                "zenodo_authorized": False,
            },
        )
        fixture = {
            "product": product,
            "freeze_commit": freeze_commit,
            "freeze_tree": freeze_tree,
            "freeze_payload": freeze_payload,
            "candidate_payload": candidate_payload,
            "state_payload": state_payload,
            "state": state,
        }
        _CLAIM_TIER_FIXTURE_CACHE = fixture
        return deepcopy(fixture)

    def validate_claim_tier_fixture(self, module, fixture):
        module.validate_claim_tier_product(
            fixture["product"],
            fixture["freeze_commit"],
            fixture["freeze_tree"],
            fixture["freeze_payload"],
            fixture["candidate_payload"],
            fixture["state_payload"],
            fixture["state"],
        )

    def github_metadata_fixture(self, module):
        freeze_commit = "f" * 40
        captures = []
        summaries = []
        normalized = {
            "repository": {
                "owner": "sepahead",
                "default_branch": "main",
                "private": False,
                "archived": False,
                "disabled": False,
                "description": "Verified repository evidence.",
            },
            "default_branch_head": freeze_commit,
            "publication": {
                "tag_count": 0,
                "release_count": 0,
                "tags": [],
                "releases": [],
            },
            "completeness": {
                "expected_endpoint_ids": [
                    item[0] for item in module.GITHUB_ENDPOINT_SPECS
                ],
                "captured_endpoint_ids": [
                    item[0] for item in module.GITHUB_ENDPOINT_SPECS
                ],
                "all_complete": True,
                "permission_denied": [],
            },
        }
        for identifier, endpoint, _paginated, statuses in module.GITHUB_ENDPOINT_SPECS:
            status = min(statuses)
            if status == 204:
                document = None
            elif identifier in {"hooks", "deploy_keys", "autolinks"}:
                document = [{"present": True}]
            elif identifier == "secrets":
                document = {"total_count": 0, "secrets": []}
            elif identifier == "variables":
                document = {"total_count": 0, "variables": []}
            else:
                document = {"fixture": identifier}
            body = b"" if document is None else module.canonical_json(document)
            disposition = {
                200: "OBSERVED",
                204: "ENABLED_OR_EMPTY_NO_CONTENT",
                404: "ABSENT_DISABLED_OR_NOT_CONFIGURED",
            }[status]
            captures.append(
                {
                    "id": f"{identifier}#page-0001",
                    "endpoint": endpoint,
                    "page": 1,
                    "method": "GET",
                    "accept": "application/vnd.github+json",
                    "api_version": "2022-11-28",
                    "http_status": status,
                    "etag": (
                        None
                        if identifier in module.SENSITIVE_RAW_BODY_ENDPOINTS
                        else '"fixture-etag"'
                    ),
                    "link": None,
                    "bytes": (
                        None
                        if identifier in module.SENSITIVE_RAW_BODY_ENDPOINTS
                        else len(body)
                    ),
                    "sha256": (
                        None
                        if identifier in module.SENSITIVE_RAW_BODY_ENDPOINTS
                        else module.sha256(body)
                    ),
                    "document_bytes": len(module.canonical_json(document)),
                    "document_sha256": module.sha256(module.canonical_json(document)),
                    "disposition": disposition,
                    "redaction": (
                        ["/0/*"]
                        if identifier in {"hooks", "deploy_keys", "autolinks"}
                        else []
                    ),
                    "document": document,
                }
            )
            summaries.append(
                {
                    "id": identifier,
                    "endpoint": endpoint,
                    "pages": 1,
                    "http_statuses": [status],
                    "disposition": disposition,
                    "complete": True,
                }
            )
            if identifier in {"hooks", "deploy_keys", "autolinks"}:
                normalized[identifier] = {"count": 1, "present": True}
        product = self.product_identity(
            module,
            "haldir.ch-t003.github-metadata.v1",
            captured_at_utc="2026-07-23T00:00:01Z",
            repository={
                "owner": "sepahead",
                "name": "haldir",
                "full_name": "sepahead/haldir",
                "default_branch": "main",
            },
            request_policy={
                "method": "GET",
                "accept": "application/vnd.github+json",
                "api_version": "2022-11-28",
                "authentication": "BEARER_TOKEN_USED_NOT_RETAINED",
                "pagination": "FOLLOW_REL_NEXT_TO_CLOSURE",
                "per_page": 100,
                "raw_body": (
                    "OMITTED_FOR_SENSITIVE_ENDPOINTS_OTHERWISE_DIGEST_AND_SIZE"
                ),
                "retained_document": ("CANONICAL_JSON_DIGEST_AND_SIZE"),
                "sensitive_values": "FIELD_LEVEL_REDACTION",
            },
            captures=captures,
            endpoint_summary=summaries,
            normalized=normalized,
            captures_sha256=module.sha256(module.canonical_json(captures)),
        )
        return {
            "product": product,
            "freeze_commit": freeze_commit,
            "freeze_time": module.parse_utc("2026-07-23T00:00:00Z"),
            "implementation_time": module.parse_utc("2026-07-23T00:00:02Z"),
        }

    def rust_api_fixture(self, module):
        feature_map = {
            package: ({"fixture"} if index < 5 else set())
            for index, package in enumerate(sorted(module.EXPECTED_LIBRARY_PACKAGES))
        }
        lines = [
            *[
                f"pub macro haldir_contracts::{name}!"
                for name in sorted(module.EXPECTED_EXPORTED_MACROS)
            ],
            "pub const haldir_contracts::HARD_MAX_INTENT_BYTES: usize",
        ]
        payload = ("\n".join(lines) + "\n").encode()
        compressed = gzip.compress(payload, mtime=0)
        document = {
            "sha256": module.sha256(payload),
            "bytes": len(payload),
            "lines": len(payload.splitlines()),
            "encoding": "gzip+base64",
            "encoded_bytes": len(compressed),
            "encoded_sha256": module.sha256(compressed),
            "listing_gzip_base64": module.base64.b64encode(compressed).decode("ascii"),
        }
        observations = []
        for package in sorted(module.EXPECTED_LIBRARY_PACKAGES):
            configurations = [
                ("DEFAULT", []),
                ("NO_DEFAULT", ["--no-default-features"]),
                *[
                    (
                        f"FEATURE:{feature}",
                        [
                            "--no-default-features",
                            "--features",
                            feature,
                        ],
                    )
                    for feature in sorted(feature_map[package])
                ],
                ("ALL_FEATURES", ["--all-features"]),
            ]
            for target in sorted(module.EXPECTED_RUST_TARGETS):
                for configuration, arguments in configurations:
                    observations.append(
                        {
                            "package": package,
                            "target": target,
                            "configuration": configuration,
                            "feature_arguments": arguments,
                            "rustdoc_json_format": 57,
                            "api_document_sha256": document["sha256"],
                            "api_lines": document["lines"],
                        }
                    )
        section = {
            "policy": {
                "toolchain": "1.96.0",
                "cargo_public_api": "0.52.0",
                "binary_sha256": (
                    "acdc7b1733d52476fc2ce456a2a0292b82c367566fe0d2ab15c12b99974c8d24"
                ),
                "environment": "RUSTC_BOOTSTRAP CARGO_NET_OFFLINE",
                "arguments": [
                    "--document-hidden-items",
                    "--locked",
                    "--offline",
                ],
            },
            "documents": [document],
            "observations": observations,
            "macro_invariant": {
                "package": "haldir-contracts",
                "expected": sorted(module.EXPECTED_EXPORTED_MACROS),
                "observed": sorted(module.EXPECTED_EXPORTED_MACROS),
                "result": "PASS",
            },
            "counts": {
                "documents": 1,
                "observations": len(observations),
            },
            "documents_sha256": module.sha256(module.canonical_json([document])),
            "observations_sha256": module.sha256(module.canonical_json(observations)),
        }
        return section, feature_map

    def reviewer_registry_fixture(self, module):
        records = []
        for index, (identifier, kind, _name) in enumerate(
            module.REVIEW_SPECS,
            1,
        ):
            algorithm = b"ssh-ed25519"
            key_bytes = bytes([index]) * 32
            wire = (
                len(algorithm).to_bytes(4, "big")
                + algorithm
                + len(key_bytes).to_bytes(4, "big")
                + key_bytes
            )
            public_key = "ssh-ed25519 " + module.base64.b64encode(wire).decode("ascii")
            reviewer = (
                {
                    "name": (
                        f"CH-T003 Independent Automated Reviewer Lane {index:02d}"
                    ),
                    "principal": (f"ch-t003-e0001-lane-{index:02d}@local.invalid"),
                    "classification": "INDEPENDENT_AUTOMATED",
                    "organization": ("Independent Automated Technical Review"),
                }
                if index < 4
                else {
                    "name": "CH-T003 Automated Lead Support",
                    "principal": ("ch-t003-e0001-automated-lead-support@local.invalid"),
                    "classification": "AUTOMATED_LEAD_SUPPORT",
                    "organization": "Automated Technical Review",
                }
            )
            records.append(
                {
                    "requirement_id": identifier,
                    "kind": kind,
                    "path": module.REVIEW_PATHS[identifier],
                    "reviewer": reviewer,
                    "public_key": public_key,
                    "key_fingerprint": module.public_key_fingerprint(public_key),
                    "trust_basis": ("SOURCE_SIGNER_ASSERTED_KEY_FROZEN_IN_SIGNED_F"),
                }
            )
        return {"reviewer_registry": records}

    def validate_activation_state_fixture(self, module, fixture):
        with (
            mock.patch.object(
                module,
                "git_file",
                return_value=fixture["ledger_payload"],
            ),
            mock.patch.object(
                module,
                "tree_snapshot",
                return_value=(
                    fixture["implementation_entries"],
                    fixture["implementation_blobs"],
                ),
            ),
        ):
            return module.validate_activation_state_transition(
                repo=Path("/bounded-fixture"),
                freeze_commit=fixture["freeze_commit"],
                implementation_commit=fixture["implementation_commit"],
                qualification_commit=fixture["qualification_commit"],
                activation_commit=fixture["activation_commit"],
                freeze=fixture["freeze"],
                qualification=fixture["qualification"],
                outcome=fixture["outcome"],
                qualification_entries=fixture["qualification_entries"],
                qualification_blobs=fixture["qualification_blobs"],
                activation_entries=fixture["activation_entries"],
                activation_blobs=fixture["activation_blobs"],
            )

    def test_n01_accepted(self):
        module = verifier()
        record = self.product_identity(
            module,
            "haldir.ch-t003.identity-fixture.v1",
        )
        observed = module.require_product_identity(
            record,
            "haldir.ch-t003.identity-fixture.v1",
            set(),
            "freeze_identity",
        )
        self.assertIs(observed, record)
        self.assertEqual(
            (
                observed["task_id"],
                observed["release_target"],
                observed["author"],
                observed["persistent_identifier"],
            ),
            (
                "CH-T003",
                "0.9.0",
                {
                    "name": "Sepehr Mahmoudian",
                    "email": "sepmhn@gmail.com",
                },
                None,
            ),
        )
        self.assertEqual(
            module.EXPECTED_SUBJECTS["F"],
            "release: freeze CH-T003 verification protocol",
        )

    def test_n01_rejected(self):
        module = verifier()
        record = self.product_identity(
            module,
            "haldir.ch-t003.identity-fixture.v1",
        )
        record["persistent_identifier"] = "doi:premature"
        self.assert_verify_error(
            module,
            "IDENTITY:freeze_identity",
            lambda: module.require_product_identity(
                record,
                "haldir.ch-t003.identity-fixture.v1",
                set(),
                "freeze_identity",
            ),
        )

    def test_n02_accepted(self):
        module = verifier()
        section, entries, blobs = self.candidate_plan_fixture(module)
        module.validate_candidate_plan(section, entries, blobs)
        self.assertEqual(
            [item["path"] for item in section["records"]],
            list(module.IMPLEMENTATION_PLAN),
        )
        self.assertEqual(
            section["paths_sha256"],
            module.sha256(module.canonical_json(list(module.IMPLEMENTATION_PLAN))),
        )

    def test_n02_rejected(self):
        module = verifier()
        section, entries, blobs = self.candidate_plan_fixture(module)
        section["records"][0], section["records"][1] = (
            section["records"][1],
            section["records"][0],
        )
        section["records_sha256"] = module.sha256(
            module.canonical_json(section["records"])
        )
        self.assert_verify_error(
            module,
            "CANDIDATE_PATHS",
            lambda: module.validate_candidate_plan(
                section,
                entries,
                blobs,
            ),
        )

    def test_n03_accepted(self):
        module = verifier()
        records, entries, blobs = self.inventory_records_fixture(module)
        module.validate_inventory_file_records(records, entries, blobs)
        self.assertEqual(len(records), 426)
        self.assertEqual(
            [item["path"] for item in records],
            sorted(blobs, key=lambda item: item.encode("utf-8")),
        )
        self.assertEqual(
            {item["disposition"] for item in records},
            {"SURFACE", "EXCLUDED"},
        )

    def test_n03_rejected(self):
        module = verifier()
        records, entries, blobs = self.inventory_records_fixture(module)
        records[0] = deepcopy(records[1])
        self.assert_verify_error(
            module,
            "PUBLIC_FILE_PARTITION",
            lambda: module.validate_inventory_file_records(
                records,
                entries,
                blobs,
            ),
        )

    def test_n04_accepted(self):
        module = verifier()
        records, entries, blobs = self.inventory_records_fixture(module)
        module.validate_inventory_file_records(records, entries, blobs)
        rust_record = next(item for item in records if item["path"].endswith(".rs"))
        self.assertEqual(rust_record["git_object_type"], "blob")
        self.assertEqual(
            rust_record["sha256"],
            module.sha256(blobs[rust_record["path"]]),
        )
        self.assertIn("RUST_API_SOURCE", rust_record["surface_types"])
        self.assertEqual(
            rust_record["claim_ids"],
            module.claim_ids(blobs[rust_record["path"]]),
        )

    def test_n04_rejected(self):
        module = verifier()
        records, entries, blobs = self.inventory_records_fixture(module)
        records[200]["git_object_id"] = "0" * 40
        self.assert_verify_error(
            module,
            "PUBLIC_FILE_IDENTITY",
            lambda: module.validate_inventory_file_records(
                records,
                entries,
                blobs,
            ),
        )

    def test_n05_accepted(self):
        module = verifier()
        section, feature_map = self.rust_api_fixture(module)
        module.validate_rust_api(section, feature_map)
        cells = {
            (
                item["package"],
                item["target"],
                item["configuration"],
            )
            for item in section["observations"]
        }
        self.assertEqual(len(cells), 100)
        self.assertEqual(
            {item["target"] for item in section["observations"]},
            module.EXPECTED_RUST_TARGETS,
        )
        self.assertTrue(
            any(
                item["configuration"].startswith("FEATURE:")
                for item in section["observations"]
            )
        )

    def test_n05_rejected(self):
        module = verifier()
        section, feature_map = self.rust_api_fixture(module)
        section["observations"][0]["target"] = "host-default"
        section["observations_sha256"] = module.sha256(
            module.canonical_json(section["observations"])
        )
        self.assert_verify_error(
            module,
            "RUST_API_OBSERVATION",
            lambda: module.validate_rust_api(section, feature_map),
        )

    def test_n06_accepted(self):
        module = verifier()
        payload = (
            b"| CL-ONE-01 | Exact statement. | PROVEN | Exact evidence. |\n"
            b"| CL-TWO-02 | Limited statement. | UNPROVEN | No evidence. |\n"
        )
        rows = module.parse_claim_rows(payload)
        self.assertEqual([item["id"] for item in rows], ["CL-ONE-01", "CL-TWO-02"])
        self.assertEqual(
            rows[0]["statement_sha256"],
            module.sha256(b"Exact statement."),
        )
        self.assertEqual(
            rows[0]["evidence_sha256"],
            module.sha256(b"Exact evidence."),
        )

    def test_n06_rejected(self):
        module = verifier()
        for payload, code in (
            (
                b"| CL-ONE-01 | Missing status. | Exact evidence. |\n",
                "CLAIM_ROW_FORMAT",
            ),
            (
                b"| CL-ONE-01 | One. | PROVEN | Evidence. |\n"
                b"| CL-ONE-01 | Duplicate. | PROVEN | Evidence. |\n",
                "CLAIM_ROW_INVALID",
            ),
        ):
            with self.subTest(code=code):
                self.assert_verify_error(
                    module,
                    code,
                    lambda payload=payload: module.parse_claim_rows(payload),
                )

    def test_n07_accepted(self):
        module = verifier()
        fixture = self.claim_tier_fixture(module)
        self.validate_claim_tier_fixture(module, fixture)
        self.assertEqual(
            fixture["product"]["tier_vocabulary"],
            [
                "IMPLEMENTED",
                "VERIFIED",
                "VALIDATED",
                "DEPLOYMENT_QUALIFIED",
                "FIELD_VALIDATED",
                "NOT_CLAIMED",
            ],
        )
        self.assertFalse(
            any(item["release_qualified"] for item in fixture["product"]["records"])
        )

    def test_n07_rejected(self):
        module = verifier()
        fixture = self.claim_tier_fixture(module)
        fixture["product"]["tier_vocabulary"].append("RELEASE_QUALIFIED")
        self.assert_verify_error(
            module,
            "CLAIM_TIER_VOCABULARY",
            lambda: self.validate_claim_tier_fixture(module, fixture),
        )

    def test_n08_accepted(self):
        module = verifier()
        fixture = self.claim_tier_fixture(module)
        self.validate_claim_tier_fixture(module, fixture)
        before = {
            item["id"]: item
            for item in module.parse_claim_rows(fixture["freeze_payload"])
        }
        after = {
            item["id"]: item
            for item in module.parse_claim_rows(fixture["candidate_payload"])
        }
        self.assertEqual(
            {claim_id for claim_id in before if before[claim_id] != after[claim_id]},
            {module.NARROWED_CLAIM},
        )
        self.assertEqual(
            module.claim_ledger_scaffold(fixture["freeze_payload"]),
            module.claim_ledger_scaffold(fixture["candidate_payload"]),
        )
        self.assertEqual(after[module.NARROWED_CLAIM]["status"], "PROVEN")

    def test_n08_rejected(self):
        module = verifier()
        fixture = self.claim_tier_fixture(module)
        other = next(
            item
            for item in module.parse_claim_rows(fixture["candidate_payload"])
            if item["id"] != module.NARROWED_CLAIM
        )
        fixture["candidate_payload"] = fixture["candidate_payload"].replace(
            other["statement"].encode(),
            (other["statement"] + " Mutated.").encode(),
            1,
        )
        source = fixture["product"]["source"]["claim_ledger"]
        source["sha256"] = module.sha256(fixture["candidate_payload"])
        source["bytes"] = len(fixture["candidate_payload"])
        self.assert_verify_error(
            module,
            "CLAIM_LEDGER_SEMANTIC_DELTA",
            lambda: self.validate_claim_tier_fixture(module, fixture),
        )

    def test_n09_accepted(self):
        module = verifier()
        fixtures = (
            (
                "HANDOFF_BASELINE_TRACKED_TEXT",
                "README.md",
                None,
                None,
            ),
            (
                "EXTENDED_ARCHIVE_MEMBER_UTF8",
                "evidence.zip",
                "report.txt",
                None,
            ),
            (
                "EXTENDED_CLI_RUNTIME_UTF8",
                None,
                None,
                "help:stdout",
            ),
            (
                "EXTENDED_PACKAGE_METADATA_UTF8",
                "Cargo.toml",
                None,
                None,
            ),
            (
                "EXTENDED_GITHUB_DESCRIPTION_UTF8",
                None,
                None,
                "https://github.com/sepahead/haldir",
            ),
        )
        for scope, path, member, endpoint in fixtures:
            with self.subTest(scope=scope):
                payload = (
                    f"Verified complete CL-SCOPE-{len(scope)} evidence."
                ).encode()
                hits = module.scan_claim_language_text(
                    payload,
                    module.EXTENDED_CLAIM_REGEX,
                    scope,
                    path,
                    member,
                    endpoint,
                )
                self.assertEqual(
                    {item["normalized_term"] for item in hits},
                    {"complete", "verified"},
                )
                self.assertTrue(
                    all(item["line_sha256"] == module.sha256(payload) for item in hits)
                )

    def test_n09_rejected(self):
        module = verifier()
        product = self.product_identity(
            module,
            "haldir.ch-t003.claim-language.v1",
            source={},
            policy={"baseline_pattern": "partial-pattern"},
            sources=[],
            hits=[],
            counts={},
            hits_sha256=module.sha256(module.canonical_json([])),
        )
        self.assert_verify_error(
            module,
            "CLAIM_LANGUAGE_POLICY",
            lambda: module.validate_claim_language_product(
                product,
                [],
                {},
                b"",
                {},
                {},
            ),
        )

    def test_n10_accepted(self):
        module = verifier()
        fixture = self.github_metadata_fixture(module)
        module.validate_github_metadata_v2(
            fixture["product"],
            fixture["freeze_commit"],
            fixture["freeze_time"],
            fixture["implementation_time"],
        )
        self.assertEqual(
            [item["id"] for item in fixture["product"]["endpoint_summary"]],
            [item[0] for item in module.GITHUB_ENDPOINT_SPECS],
        )
        sensitive = [
            item
            for item in fixture["product"]["captures"]
            if item["id"].split("#", 1)[0] in module.SENSITIVE_RAW_BODY_ENDPOINTS
        ]
        self.assertTrue(
            all(item["bytes"] is None and item["sha256"] is None for item in sensitive)
        )
        self.assertTrue(any(item["redaction"] for item in sensitive))

    def test_n10_rejected(self):
        module = verifier()
        fixture = self.github_metadata_fixture(module)
        capture = fixture["product"]["captures"][0]
        capture["document"] = {"fixture": "stale-body-substitution"}
        fixture["product"]["captures_sha256"] = module.sha256(
            module.canonical_json(fixture["product"]["captures"])
        )
        self.assert_verify_error(
            module,
            "GITHUB_CAPTURE_BODY",
            lambda: module.validate_github_metadata_v2(
                fixture["product"],
                fixture["freeze_commit"],
                fixture["freeze_time"],
                fixture["implementation_time"],
            ),
        )

    def test_github_variable_value_is_rejected(self):
        module = verifier()
        fixture = self.github_metadata_fixture(module)
        capture = next(
            item
            for item in fixture["product"]["captures"]
            if item["id"] == "variables#page-0001"
        )
        capture["document"] = {
            "total_count": 1,
            "variables": [{"name": "SAFE_NAME", "value": "must-not-survive"}],
        }
        retained = module.canonical_json(capture["document"])
        capture["document_bytes"] = len(retained)
        capture["document_sha256"] = module.sha256(retained)
        fixture["product"]["captures_sha256"] = module.sha256(
            module.canonical_json(fixture["product"]["captures"])
        )
        self.assert_verify_error(
            module,
            "GITHUB_VARIABLE_REDACTION",
            lambda: module.validate_github_metadata_v2(
                fixture["product"],
                fixture["freeze_commit"],
                fixture["freeze_time"],
                fixture["implementation_time"],
            ),
        )

    def test_n11_accepted(self):
        module = verifier()
        coverage = {
            "freeze_partition": {
                "count": 426,
                "commit": "f" * 40,
            },
            "candidate_partition": {
                "count": 9,
                "expected_implementation_count": 434,
            },
            "review_overlay": {
                "path": module.REVIEW_OVERLAY_PATH,
            },
            "sibling_products": {
                "count": 5,
            },
        }
        projection = module.composition_projection({"coverage": coverage})
        self.assertEqual(
            set(projection),
            {
                "source_file",
                "freeze_partition_sha256",
                "candidate_partition_sha256",
                "review_overlay_sha256",
                "sibling_products_sha256",
            },
        )
        self.assertEqual(projection["source_file"], module.LEDGER_COMPOSITION_PATH)
        self.assertEqual(coverage["freeze_partition"]["count"], 426)
        self.assertEqual(
            (
                module.PRIOR_FREEZE,
                module.PRIOR_IMPLEMENTATION,
                module.PRIOR_QUALIFICATION,
                module.PRIOR_ACTIVATION,
            ),
            tuple(
                dict.fromkeys(
                    (
                        module.PRIOR_FREEZE,
                        module.PRIOR_IMPLEMENTATION,
                        module.PRIOR_QUALIFICATION,
                        module.PRIOR_ACTIVATION,
                    )
                )
            ),
        )

    def test_n11_rejected(self):
        module = verifier()
        product = self.product_identity(
            module,
            "haldir.ch-t003.ledger-composition.v1",
            prior_lifecycle={
                "freeze_commit": module.PRIOR_FREEZE,
                "implementation_commit": module.PRIOR_IMPLEMENTATION,
                "qualification_commit": module.PRIOR_QUALIFICATION,
                "activation_commit": "0" * 40,
            },
            source={},
            artifacts=[],
            coverage={},
            review_boundary={},
            bidirectional_references={},
        )
        self.assert_verify_error(
            module,
            "COMPOSITION_PRIOR_LIFECYCLE",
            lambda: module.validate_ledger_composition_v2(
                product,
                Path("/bounded-fixture"),
                "f" * 40,
                [],
                {},
                "1" * 40,
                [],
                {},
            ),
        )

    def test_n12_accepted(self):
        module = verifier()
        value = {
            "finite": [0, 1, -(2**53)],
            "unicode": "na\u00efve-\u0394-\U0001f642",
            "nested": {"canonical": True},
        }
        payload = module.canonical_json(value)
        self.assertEqual(module.load_json(payload), value)
        self.assertTrue(payload.endswith(b"\n"))
        self.assertEqual(module.canonical_json(module.load_json(payload)), payload)

    def test_n12_rejected(self):
        module = verifier()
        for payload, code in (
            (b'{"a":1,"a":2}\n', "JSON_DUPLICATE_KEY:a"),
            (b'{"b":2,"a":1}\n', "JSON_NOT_CANONICAL"),
            (b'{"value":NaN}\n', "JSON_NONFINITE:NaN"),
        ):
            with self.subTest(code=code):
                self.assert_verify_error(
                    module,
                    code,
                    lambda payload=payload: module.load_json(payload),
                )

    def test_n13_accepted(self):
        module = verifier()
        section, entries, blobs = self.candidate_plan_fixture(module)
        module.validate_candidate_plan(section, entries, blobs)
        records, freeze_entries, freeze_blobs = self.inventory_records_fixture(module)
        module.validate_inventory_file_records(
            records,
            freeze_entries,
            freeze_blobs,
        )
        archive = self.zip_payload(
            [("bound/member.txt", b"exact bytes\n")],
            zipfile.ZIP_DEFLATED,
        )
        self.assertEqual(
            [item["member_path"] for item in module.inspect_archive("a.zip", archive)],
            ["bound/member.txt"],
        )
        self.assertEqual(
            len(
                module.parse_claim_rows(
                    b"| CL-BOUND-01 | Bound. | PROVEN | Evidence. |\n"
                )
            ),
            1,
        )

    def test_n13_rejected(self):
        module = verifier()
        section, entries, blobs = self.candidate_plan_fixture(module)
        section["records"].append(deepcopy(section["records"][0]))
        self.assert_verify_error(
            module,
            "CANDIDATE_PATHS",
            lambda: module.validate_candidate_plan(section, entries, blobs),
        )
        hostile_archive = self.zip_payload(
            [("../escape.txt", b"unsafe")],
            zipfile.ZIP_DEFLATED,
        )
        self.assert_verify_error(
            module,
            "ZIP_MEMBER_POLICY",
            lambda: module.inspect_archive("hostile.zip", hostile_archive),
        )
        self.assert_verify_error(
            module,
            "CLAIM_ROW_INVALID",
            lambda: module.parse_claim_rows(
                b"| CL-DUPLICATE-01 | One. | PROVEN | Evidence. |\n"
                b"| CL-DUPLICATE-01 | Two. | PROVEN | Evidence. |\n"
            ),
        )
        self.assert_verify_error(
            module,
            "DIGEST:stale_surface",
            lambda: module.digest_matches(
                "0" * 64,
                {"surface": "changed"},
                "stale_surface",
            ),
        )

    def test_n14_accepted(self):
        module = verifier()
        fixture = self.claim_tier_fixture(module)
        self.validate_claim_tier_fixture(module, fixture)
        ids = {
            item["id"] for item in module.parse_claim_rows(fixture["candidate_payload"])
        }
        active = set(fixture["state"]["active_claims"])
        non_claimed = set(fixture["state"]["non_claimed_claims"])
        removed = set(fixture["state"]["removed_claims"])
        self.assertEqual(ids, active | non_claimed | removed)
        self.assertFalse(active & non_claimed)
        self.assertEqual(
            sum(
                item["narrowing"] is not None for item in fixture["product"]["records"]
            ),
            1,
        )

    def test_n14_rejected(self):
        module = verifier()
        fixture = self.claim_tier_fixture(module)
        fixture["state"]["non_claimed_claims"].append(
            fixture["state"]["active_claims"][0]
        )
        self.assert_verify_error(
            module,
            "CLAIM_PARTITION",
            lambda: self.validate_claim_tier_fixture(module, fixture),
        )

    def test_n15_accepted(self):
        module = verifier()
        fixture = self.claim_tier_fixture(module)
        self.validate_claim_tier_fixture(module, fixture)
        by_type = {
            item["claim_type"]: tuple(item["minimum_evidence"])
            for item in fixture["product"]["records"]
        }
        self.assertEqual(
            set(by_type),
            {
                "EVIDENCE_OR_PUBLICATION",
                "INTERFACE_OR_INTEROPERABILITY",
                "FORMAL_OR_MODEL",
                "DEPLOYMENT_OR_RUNTIME",
                "IMPLEMENTATION",
            },
        )
        self.assertIn(
            "SECURITY_OR_AUTHORITY",
            module.MINIMUM_EVIDENCE_BY_CLAIM_TYPE,
        )
        self.assertTrue(
            all(
                item["observed_evidence_classes"]
                for item in fixture["product"]["records"]
                if item["evidence_tier"] == "VERIFIED"
            )
        )

    def test_n15_rejected(self):
        module = verifier()
        fixture = self.claim_tier_fixture(module)
        verified = next(
            item
            for item in fixture["product"]["records"]
            if item["evidence_tier"] == "VERIFIED"
        )
        verified["observed_evidence_classes"] = []
        fixture["product"]["records_sha256"] = module.sha256(
            module.canonical_json(fixture["product"]["records"])
        )
        self.assert_verify_error(
            module,
            "CLAIM_TIER_EVIDENCE",
            lambda: self.validate_claim_tier_fixture(module, fixture),
        )

    def test_n16_accepted(self):
        module = verifier()
        fixture = self.activation_state_fixture(module)
        _requirements, claims = self.validate_activation_state_fixture(
            module,
            fixture,
        )
        self.assertEqual(claims["overall_status"], "NO_GO")
        self.assertEqual(claims["release_qualified_claims"], [])
        self.assertFalse(
            any(
                claims[field]
                for field in (
                    "tag_authorized",
                    "github_release_authorized",
                    "doi_authorized",
                    "zenodo_authorized",
                    "archive_authorized",
                )
            )
        )

    def test_n16_rejected(self):
        module = verifier()
        fixture = self.activation_state_fixture(module)
        fixture["expected_claims"]["tag_authorized"] = True
        fixture["activation_blobs"][module.CLAIMS_STATE_PATH] = module.canonical_json(
            fixture["expected_claims"]
        )
        self.assert_verify_error(
            module,
            "ACTIVATION_CLAIMS_TRANSITION",
            lambda: self.validate_activation_state_fixture(module, fixture),
        )

    def test_n17_accepted(self):
        module = verifier()
        payload = self.zip_payload(
            [
                ("a.txt", b"bounded\n"),
                ("z.bin", b"\x00\x01"),
            ],
            compression=zipfile.ZIP_STORED,
        )
        members = module.inspect_archive("fixture.zip", payload)
        self.assertEqual(
            [item["member_path"] for item in members],
            ["a.txt", "z.bin"],
        )
        self.assertTrue(
            all(item["bytes"] <= module.MAX_ARCHIVE_MEMBER_BYTES for item in members)
        )

    def test_n17_rejected(self):
        module = verifier()
        payload = self.zip_payload(
            [("../escape.txt", b"unsafe")],
            zipfile.ZIP_DEFLATED,
        )
        self.assert_verify_error(
            module,
            "ZIP_MEMBER_POLICY",
            lambda: module.inspect_archive("fixture.zip", payload),
        )

    def test_n18_accepted(self):
        module = verifier()
        fixture = self.claim_tier_fixture(module)
        self.validate_claim_tier_fixture(module, fixture)
        records = fixture["product"]["records"]
        reverse = fixture["product"]["bidirectional_links"]["surface_to_claims"]
        self.assertEqual(
            reverse,
            [
                {
                    "surface": module.CLAIM_LEDGER_PATH,
                    "claim_ids": sorted(item["id"] for item in records),
                }
            ],
        )

    def test_n18_rejected(self):
        module = verifier()
        fixture = self.claim_tier_fixture(module)
        links = fixture["product"]["bidirectional_links"]
        links["surface_to_claims"][0]["claim_ids"].pop()
        links["surface_to_claims_sha256"] = module.sha256(
            module.canonical_json(links["surface_to_claims"])
        )
        self.assert_verify_error(
            module,
            "CLAIM_LINK_DANGLING",
            lambda: self.validate_claim_tier_fixture(module, fixture),
        )

    def test_n19_accepted(self):
        module = verifier()
        fixture = self.claim_tier_fixture(module)
        self.validate_claim_tier_fixture(module, fixture)
        target = next(
            item
            for item in fixture["product"]["records"]
            if item["id"] == module.NARROWED_CLAIM
        )
        self.assertEqual(
            target["statement"],
            (
                "Repository VERIFIED evidence primitives do not establish "
                "VALIDATED, DEPLOYMENT_QUALIFIED, or FIELD_VALIDATED status, "
                "a release-qualified artifact, transport delivery, or "
                "operational use."
            ),
        )
        self.assertEqual(
            target["lifecycle_disposition"],
            "ACTIVE_NARROWED_PENDING_ACTIVATION",
        )

    def test_n19_rejected(self):
        module = verifier()
        fixture = self.claim_tier_fixture(module)
        fixture["candidate_payload"] = fixture["candidate_payload"].replace(
            b"transport delivery",
            b"transport completion",
            1,
        )
        source = fixture["product"]["source"]["claim_ledger"]
        source["sha256"] = module.sha256(fixture["candidate_payload"])
        source["bytes"] = len(fixture["candidate_payload"])
        self.assert_verify_error(
            module,
            "CLAIM_NARROWING_LANGUAGE",
            lambda: self.validate_claim_tier_fixture(module, fixture),
        )

    def test_n20_accepted(self):
        module = verifier()
        freeze_commit = "f" * 40
        implementation_commit = "1" * 40
        metas = {
            freeze_commit: {
                "parents": module.PRIOR_ACTIVATION,
                "subject": module.EXPECTED_SUBJECTS["F"],
                "author_name": module.AUTHOR["name"],
                "author_email": module.AUTHOR["email"],
            },
            implementation_commit: {
                "parents": freeze_commit,
                "subject": module.EXPECTED_SUBJECTS["I"],
                "author_name": module.AUTHOR["name"],
                "author_email": module.AUTHOR["email"],
            },
        }
        freeze_diff = {
            module.REGISTRY_PATH: "M",
            module.FREEZE_PATH: "A",
            module.TESTS_PATH: "A",
            module.VERIFIER_PATH: "A",
        }
        with (
            mock.patch.object(
                module,
                "commit_meta",
                side_effect=lambda _repo, commit: metas[commit],
            ),
            mock.patch.object(
                module,
                "changed_statuses",
                side_effect=[freeze_diff, module.IMPLEMENTATION_PLAN],
            ),
            mock.patch.object(
                module,
                "tree_snapshot",
                return_value=(
                    [],
                    {module.FREEZE_PATH: b"{}\n"},
                ),
            ),
            mock.patch.object(module, "verify_signature") as signatures,
            mock.patch.object(module, "validate_freeze_contract"),
            mock.patch.object(module, "validate_products"),
        ):
            module.validate_implementation(
                Path("/bounded-fixture"),
                freeze_commit,
                implementation_commit,
            )
        self.assertEqual(signatures.call_count, 2)
        with mock.patch.object(
            module,
            "git_file",
            side_effect=[b"verifier", b"tests"],
        ):
            output = module.implementation_output_record(
                Path("/bounded-fixture"),
                freeze_commit,
                implementation_commit,
            )
        self.assertEqual(output["result"], "PASS")
        self.assertEqual(
            module.load_json(module.canonical_json(output)),
            output,
        )

        qualification_commit = "c" * 40
        activation_commit = "d" * 40
        lifecycle_metas = {
            freeze_commit: metas[freeze_commit],
            implementation_commit: metas[implementation_commit],
            qualification_commit: {
                "parents": implementation_commit,
                "subject": module.EXPECTED_SUBJECTS["C"],
                "author_name": module.AUTHOR["name"],
                "author_email": module.AUTHOR["email"],
            },
            activation_commit: {
                "parents": qualification_commit,
                "subject": module.EXPECTED_SUBJECTS["D"],
                "author_name": module.AUTHOR["name"],
                "author_email": module.AUTHOR["email"],
            },
        }
        expected_c_diff = dict(
            sorted(
                {
                    module.QUALIFICATION_PATH: "A",
                    **{path: "A" for path in module.EVIDENCE_PATHS.values()},
                    **{path: "A" for path in module.REVIEW_PATHS.values()},
                }.items()
            )
        )
        expected_d_diff = dict(
            sorted(
                {
                    module.ACTIVATION_PATH: "A",
                    module.RECEIPT_PATH: "A",
                    module.REQUIREMENTS_PATH: "M",
                    module.CLAIMS_STATE_PATH: "M",
                    **{path: "A" for path in module.ACTIVATION_PATHS.values()},
                }.items()
            )
        )
        qualification = {
            "selected_claim_outcome_id": module.OUTCOME_ID,
        }
        requirements = {
            "tasks": [
                None,
                None,
                None,
                {"id": module.TASK_ID, "status": "VERIFIED"},
            ],
            "overall_status": "NO_GO",
        }
        claims = {
            "verified_prefix": 4,
            "current_epochs": {module.TASK_ID: module.EPOCH},
            "overall_status": "NO_GO",
            "narrowed_claims": [module.NARROWED_CLAIM],
            "release_qualified_claims": [],
            "tag_authorized": False,
            "github_release_authorized": False,
            "doi_authorized": False,
            "zenodo_authorized": False,
            "archive_authorized": False,
        }
        with (
            mock.patch.object(module, "validate_implementation"),
            mock.patch.object(
                module,
                "commit_meta",
                side_effect=lambda _repo, commit: lifecycle_metas[commit],
            ),
            mock.patch.object(module, "is_ancestor", return_value=True),
            mock.patch.object(
                module,
                "changed_statuses",
                side_effect=[expected_c_diff, expected_d_diff],
            ),
            mock.patch.object(module, "verify_signature") as lifecycle_signatures,
            mock.patch.object(
                module,
                "validate_qualification_stage",
                return_value=qualification,
            ),
            mock.patch.object(module, "validate_activation_stage"),
            mock.patch.object(module, "validate_current_state") as current_state,
            mock.patch.object(
                module,
                "git_file",
                side_effect=[
                    module.canonical_json(requirements),
                    module.canonical_json(claims),
                ],
            ),
        ):
            observed = module.validate_lifecycle(
                Path("/bounded-fixture"),
                freeze_commit,
                implementation_commit,
                qualification_commit,
                activation_commit,
                activation_commit,
            )
        self.assertIs(observed, qualification)
        self.assertEqual(lifecycle_signatures.call_count, 2)
        current_state.assert_called_once_with(
            Path("/bounded-fixture"),
            implementation_commit,
            activation_commit,
        )
        with mock.patch.object(
            module,
            "git_file",
            side_effect=[b"verifier", b"tests"],
        ):
            lifecycle_output = module.output_record(
                Path("/bounded-fixture"),
                freeze_commit,
                implementation_commit,
                qualification_commit,
                activation_commit,
                activation_commit,
                qualification,
            )
        self.assertEqual(lifecycle_output["result"], "PASS")
        self.assertEqual(
            module.load_json(module.canonical_json(lifecycle_output)),
            lifecycle_output,
        )

    def test_n20_rejected(self):
        module = verifier()
        freeze_commit = "f" * 40
        implementation_commit = "1" * 40
        metas = {
            freeze_commit: {
                "parents": "0" * 40,
                "subject": module.EXPECTED_SUBJECTS["F"],
                "author_name": module.AUTHOR["name"],
                "author_email": module.AUTHOR["email"],
            },
            implementation_commit: {
                "parents": freeze_commit,
                "subject": module.EXPECTED_SUBJECTS["I"],
                "author_name": module.AUTHOR["name"],
                "author_email": module.AUTHOR["email"],
            },
        }
        with mock.patch.object(
            module,
            "commit_meta",
            side_effect=lambda _repo, commit: metas[commit],
        ):
            self.assert_verify_error(
                module,
                "IMPLEMENTATION_ADJACENCY",
                lambda: module.validate_implementation(
                    Path("/bounded-fixture"),
                    freeze_commit,
                    implementation_commit,
                ),
            )

        qualification_commit = "c" * 40
        activation_commit = "d" * 40
        lifecycle_metas = {
            freeze_commit: {
                **metas[freeze_commit],
                "parents": module.PRIOR_ACTIVATION,
            },
            implementation_commit: metas[implementation_commit],
            qualification_commit: {
                "parents": freeze_commit,
                "subject": module.EXPECTED_SUBJECTS["C"],
                "author_name": module.AUTHOR["name"],
                "author_email": module.AUTHOR["email"],
            },
            activation_commit: {
                "parents": qualification_commit,
                "subject": module.EXPECTED_SUBJECTS["D"],
                "author_name": module.AUTHOR["name"],
                "author_email": module.AUTHOR["email"],
            },
        }
        with (
            mock.patch.object(module, "validate_implementation"),
            mock.patch.object(
                module,
                "commit_meta",
                side_effect=lambda _repo, commit: lifecycle_metas[commit],
            ),
        ):
            self.assert_verify_error(
                module,
                "LIFECYCLE_ADJACENCY",
                lambda: module.validate_lifecycle(
                    Path("/bounded-fixture"),
                    freeze_commit,
                    implementation_commit,
                    qualification_commit,
                    activation_commit,
                    activation_commit,
                ),
            )

    def test_current_state_allows_unrelated_claim_evolution(self):
        module = verifier()
        fixture = self.current_state_fixture(module)
        with (
            mock.patch.object(
                module,
                "targeted_tree_entry",
                side_effect=lambda _repo, commit, path: self.current_state_entry(
                    fixture, commit, path
                ),
            ),
            mock.patch.object(
                module,
                "git_file",
                side_effect=lambda _repo, commit, path, **kwargs: (
                    self.current_state_file(fixture, commit, path, **kwargs)
                ),
            ),
        ):
            self.assertIsNone(
                module.validate_current_state(
                    Path("/bounded-fixture"),
                    "1" * 40,
                    "d" * 40,
                )
            )

    def test_current_state_rejects_immutable_surface_drift(self):
        module = verifier()
        fixture = self.current_state_fixture(module)
        immutable_path = next(
            path
            for path in module.IMPLEMENTATION_PLAN
            if path != module.CLAIM_LEDGER_PATH
        )
        current_entry = next(
            item
            for item in fixture["current_entries"]
            if item["path"] == immutable_path
        )
        current_entry["git_object_id"] = "e" * 40
        with (
            mock.patch.object(
                module,
                "targeted_tree_entry",
                side_effect=lambda _repo, commit, path: self.current_state_entry(
                    fixture, commit, path
                ),
            ),
            mock.patch.object(
                module,
                "git_file",
                side_effect=lambda _repo, commit, path, **kwargs: (
                    self.current_state_file(fixture, commit, path, **kwargs)
                ),
            ),
        ):
            self.assert_verify_error(
                module,
                "CURRENT_IMPLEMENTATION_SURFACE_DRIFT",
                lambda: module.validate_current_state(
                    Path("/bounded-fixture"),
                    "1" * 40,
                    "d" * 40,
                ),
            )

    def test_current_state_rejects_narrowed_claim_drift(self):
        module = verifier()
        fixture = self.current_state_fixture(module)
        fixture["current_blobs"][module.CLAIM_LEDGER_PATH] = fixture["current_blobs"][
            module.CLAIM_LEDGER_PATH
        ].replace(
            b"Narrow statement.",
            b"Broadened statement.",
        )
        with (
            mock.patch.object(
                module,
                "targeted_tree_entry",
                side_effect=lambda _repo, commit, path: self.current_state_entry(
                    fixture, commit, path
                ),
            ),
            mock.patch.object(
                module,
                "git_file",
                side_effect=lambda _repo, commit, path, **kwargs: (
                    self.current_state_file(fixture, commit, path, **kwargs)
                ),
            ),
        ):
            self.assert_verify_error(
                module,
                "CURRENT_NARROWED_CLAIM_DRIFT",
                lambda: module.validate_current_state(
                    Path("/bounded-fixture"),
                    "1" * 40,
                    "d" * 40,
                ),
            )

    def test_cf01_accepted(self):
        module = verifier()
        fixture = self.claim_tier_fixture(module)
        self.validate_claim_tier_fixture(module, fixture)
        target = next(
            item
            for item in module.parse_claim_rows(fixture["candidate_payload"])
            if item["id"] == module.NARROWED_CLAIM
        )
        self.assertIn("do not establish", target["statement"])

    def test_cf01_rejected(self):
        module = verifier()
        fixture = self.claim_tier_fixture(module)
        fixture["candidate_payload"] = fixture["candidate_payload"].replace(
            b"do not establish",
            b"establish",
            1,
        )
        source = fixture["product"]["source"]["claim_ledger"]
        source["sha256"] = module.sha256(fixture["candidate_payload"])
        source["bytes"] = len(fixture["candidate_payload"])
        self.assert_verify_error(
            module,
            "CLAIM_NARROWING_LANGUAGE",
            lambda: self.validate_claim_tier_fixture(module, fixture),
        )

    def test_cf02_accepted(self):
        module = verifier()
        freeze = self.reviewer_registry_fixture(module)
        observed = module.reviewer_registry(freeze)
        self.assertEqual(list(observed), [item[0] for item in module.REVIEW_SPECS])
        self.assertEqual(
            len({item["key_fingerprint"] for item in observed.values()}),
            len(module.REVIEW_SPECS),
        )

    def test_cf02_rejected(self):
        module = verifier()
        freeze = self.reviewer_registry_fixture(module)
        records = freeze["reviewer_registry"]
        records[0]["reviewer"] = deepcopy(records[1]["reviewer"])
        records[0]["public_key"] = records[1]["public_key"]
        records[0]["key_fingerprint"] = records[1]["key_fingerprint"]
        self.assert_verify_error(
            module,
            "REVIEWER_REGISTRY_BINDING",
            lambda: module.reviewer_registry(freeze),
        )

    def test_cf03_accepted(self):
        module = verifier()
        record = self.common_evidence(module)
        observed, started, completed = module.validate_common_evidence(
            record,
            identifier="CH-T003-E01",
            schema_id="haldir.ch-t003.file-review-traceability.v1",
            freeze_commit="f" * 40,
            implementation_commit="1" * 40,
            implementation_time=module.parse_utc("2026-07-23T00:00:00Z"),
            qualification_time=module.parse_utc("2026-07-23T00:00:03Z"),
        )
        self.assertIs(observed, record)
        self.assertLess(started, completed)

    def test_cf03_rejected(self):
        module = verifier()
        record = self.common_evidence(module)
        record["started_at_utc"] = "2026-07-22T23:59:59Z"
        self.assert_verify_error(
            module,
            "EVIDENCE_IDENTITY:CH-T003-E01",
            lambda: module.validate_common_evidence(
                record,
                identifier="CH-T003-E01",
                schema_id="haldir.ch-t003.file-review-traceability.v1",
                freeze_commit="f" * 40,
                implementation_commit="1" * 40,
                implementation_time=module.parse_utc("2026-07-23T00:00:00Z"),
                qualification_time=module.parse_utc("2026-07-23T00:00:03Z"),
            ),
        )

    def test_cf04_accepted(self):
        module = verifier()
        contract = {
            "version": "1.0.0",
            "contract": "haldir.ch-t003.public-surface-inventory.v1",
            "algorithm": "sha256",
        }
        digest = module.sha256(module.canonical_json(contract))
        self.assertIsNone(module.digest_matches(digest, contract, "contract_identity"))

    def test_cf04_rejected(self):
        module = verifier()
        contract = {
            "version": "1.0.0",
            "contract": "haldir.ch-t003.public-surface-inventory.v1",
            "algorithm": "sha256",
        }
        digest = module.sha256(module.canonical_json(contract))
        contract["contract"] = "haldir.ch-t003.wrong.v1"
        self.assert_verify_error(
            module,
            "DIGEST:contract_identity",
            lambda: module.digest_matches(
                digest,
                contract,
                "contract_identity",
            ),
        )

    def test_cf05_accepted(self):
        module = verifier()
        records, entries, blobs = self.inventory_records_fixture(module)
        module.validate_inventory_file_records(records, entries, blobs)
        self.assertEqual(len(entries), 426)

    def test_cf05_rejected(self):
        module = verifier()
        records, entries, blobs = self.inventory_records_fixture(module)
        self.assert_verify_error(
            module,
            "PUBLIC_FILE_COUNT",
            lambda: module.validate_inventory_file_records(
                records[:25],
                entries[:25],
                {item["path"]: blobs[item["path"]] for item in entries[:25]},
            ),
        )

    def test_cf06_accepted(self):
        module = verifier()
        command = self.retained_command(module)
        command["stdout"] = "x" * 65_536
        command["stdout_sha256"] = module.sha256(command["stdout"].encode())
        observed = module.validate_retained_command(
            command,
            window_start=module.parse_utc("2026-07-23T00:00:00Z"),
            window_end=module.parse_utc("2026-07-23T00:00:03Z"),
        )
        self.assertEqual(
            observed,
            (
                module.parse_utc("2026-07-23T00:00:01Z"),
                module.parse_utc("2026-07-23T00:00:02Z"),
            ),
        )
        command["stdout"] = "x" * 65_537
        command["stdout_sha256"] = module.sha256(command["stdout"].encode())
        observed = module.validate_retained_command(
            command,
            window_start=module.parse_utc("2026-07-23T00:00:00Z"),
            window_end=module.parse_utc("2026-07-23T00:00:03Z"),
            maximum_stream_bytes=4_194_304,
        )
        self.assertEqual(
            observed,
            (
                module.parse_utc("2026-07-23T00:00:01Z"),
                module.parse_utc("2026-07-23T00:00:02Z"),
            ),
        )

    def test_cf06_rejected(self):
        module = verifier()
        command = self.retained_command(module)
        command["stdout"] = "x" * 65_537
        command["stdout_sha256"] = module.sha256(command["stdout"].encode())
        self.assert_verify_error(
            module,
            "RETAINED_COMMAND",
            lambda: module.validate_retained_command(
                command,
                window_start=module.parse_utc("2026-07-23T00:00:00Z"),
                window_end=module.parse_utc("2026-07-23T00:00:03Z"),
            ),
        )

    def test_cf07_accepted(self):
        module = verifier()
        section, feature_map = self.rust_api_fixture(module)
        module.validate_rust_api(section, feature_map)
        expected_features = {
            (package, feature)
            for package, features in feature_map.items()
            for feature in features
        }
        observed_features = {
            (
                item["package"],
                item["configuration"].removeprefix("FEATURE:"),
            )
            for item in section["observations"]
            if item["configuration"].startswith("FEATURE:")
        }
        self.assertEqual(observed_features, expected_features)

    def test_cf07_rejected(self):
        module = verifier()
        section, feature_map = self.rust_api_fixture(module)
        observation = section["observations"][0]
        observation["configuration"] = "FEATURE:privileged"
        observation["feature_arguments"] = [
            "--no-default-features",
            "--features",
            "privileged",
        ]
        section["observations_sha256"] = module.sha256(
            module.canonical_json(section["observations"])
        )
        self.assert_verify_error(
            module,
            "RUST_API_OBSERVATION",
            lambda: module.validate_rust_api(section, feature_map),
        )

    def test_cf08_accepted(self):
        module = verifier()
        section, entries, blobs = self.candidate_plan_fixture(module)
        module.validate_candidate_plan(section, entries, blobs)
        self.assertTrue(
            all(
                item["binding_kind"] in {"NO_INNER_DIGEST", "EXACT_CANDIDATE_BYTES"}
                for item in section["records"]
            )
        )

    def test_cf08_rejected(self):
        module = verifier()
        section, entries, blobs = self.candidate_plan_fixture(module)
        exact = next(
            item
            for item in section["records"]
            if item["binding_kind"] == "EXACT_CANDIDATE_BYTES"
        )
        exact["binding_kind"] = "DEFAULT_BINDING"
        exact["sha256"] = None
        exact["bytes"] = None
        section["records_sha256"] = module.sha256(
            module.canonical_json(section["records"])
        )
        self.assert_verify_error(
            module,
            "CANDIDATE_IDENTITY",
            lambda: module.validate_candidate_plan(section, entries, blobs),
        )

    def test_cf09_accepted(self):
        module = verifier()
        fixture = self.activation_state_fixture(module)
        requirements, claims = self.validate_activation_state_fixture(
            module,
            fixture,
        )
        self.assertEqual(requirements["tasks"][3]["status"], "VERIFIED")
        self.assertIn(module.NARROWED_CLAIM, claims["active_claims"])
        self.assertEqual(
            claims["claim_ledger"]["sha256"],
            module.sha256(fixture["ledger_payload"]),
        )

    def test_cf09_rejected(self):
        module = verifier()
        fixture = self.activation_state_fixture(module)
        fixture["expected_claims"]["claim_ledger"]["sha256"] = "0" * 64
        fixture["activation_blobs"][module.CLAIMS_STATE_PATH] = module.canonical_json(
            fixture["expected_claims"]
        )
        self.assert_verify_error(
            module,
            "ACTIVATION_CLAIMS_TRANSITION",
            lambda: self.validate_activation_state_fixture(module, fixture),
        )

    def test_cf10_accepted(self):
        module = verifier()
        path = "docs/na\u00efve-\u0394.md"
        self.assertTrue(module.valid_path(path))
        self.assertEqual(
            module.inventory_classification(path),
            (
                "PUBLIC_DOCUMENTATION",
                "SURFACE",
                "HUMAN_OR_BRAND_DOCUMENTATION",
            ),
        )
        payload = b"Odd but valid: [] {} 0.\n"
        self.assertEqual(module.load_json(b'{"odd":[0,{},[]]}\n')["odd"][0], 0)
        self.assertEqual(module.content_kind(path, payload), "UTF8")

    def test_cf10_rejected(self):
        module = verifier()
        decomposed = "docs/nai\u0308ve.md"
        self.assertFalse(module.valid_path(decomposed))
        self.assertFalse(module.valid_path("docs/../odd.md"))
        self.assert_verify_error(
            module,
            "PROSPECTIVE_FILE_PATH",
            lambda: module.prospective_file_record(decomposed, b"odd\n"),
        )

    def test_technique_metamorphic_path_order(self):
        module = verifier()
        paths = ["README.md", "Cargo.toml", "docs/A.md"]
        self.assertEqual(sorted(paths), sorted(reversed(paths)))
        self.assertTrue(all(module.classify_path(path) is not None for path in paths))

    def test_technique_mutation_changes_digest(self):
        module = verifier()
        original = module.canonical_json({"records": [1, 2, 3]})
        mutated = module.canonical_json({"records": [1, 3, 2]})
        self.assertNotEqual(module.sha256(original), module.sha256(mutated))

    def test_technique_differential_claim_hash(self):
        module = verifier()
        row = module.parse_claim_rows(
            b"| CL-EXAMPLE-01 | Exact. | PROVEN | Evidence. |\n"
        )[0]
        self.assertEqual(row["statement_sha256"], module.sha256(b"Exact."))
        self.assertEqual(row["evidence_sha256"], module.sha256(b"Evidence."))

    def test_resource_exact_json_boundary(self):
        module = verifier()
        self.assertEqual(module.load_json(b"{}\n", maximum=3), {})
        with self.assertRaises(module.VerifyError):
            module.load_json(b"{}\n", maximum=2)

    def test_resource_path_boundary(self):
        module = verifier()
        accepted = "a" * module.MAX_PATH_BYTES
        rejected = "a" * (module.MAX_PATH_BYTES + 1)
        self.assertTrue(module.valid_path(accepted))
        self.assertFalse(module.valid_path(rejected))

    def test_resource_language_hit_boundary(self):
        module = verifier()
        self.assertGreater(module.MAX_LANGUAGE_HITS, 0)
        self.assertLess(module.MAX_LANGUAGE_HITS, 1_000_000)

    def test_exact_prior_tree_snapshot_fits_registered_budget(self):
        module = verifier()
        started = time.perf_counter()
        entries, blobs = self.prior_snapshot(module)
        elapsed = time.perf_counter() - started
        self.assertEqual(len(entries), 423)
        self.assertEqual(sum(map(len, blobs.values())), 14_527_449)
        self.assertLess(elapsed, 2.0)

    def test_exact_baseline_claim_language_is_preserved(self):
        module = verifier()
        entries, blobs = self.prior_snapshot(module)
        paths, hits, matching_lines = module.expected_baseline_language_hits(
            entries, blobs
        )
        self.assertEqual(len(paths), 49)
        self.assertEqual(len(hits), 1_379)
        self.assertEqual(matching_lines, 1_181)

    def test_exact_archive_inventory_is_complete(self):
        module = verifier()
        entries, blobs = self.prior_snapshot(module)
        containers, members = module.expected_archive_inventory(entries, blobs)
        self.assertEqual(len(containers), 34)
        self.assertEqual(
            {item["kind"] for item in containers},
            {"GZIP", "ZIP"},
        )
        self.assertEqual(len(members), 148)

    def test_archive_path_traversal_is_rejected(self):
        module = verifier()
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("../escape.txt", "unsafe")
        with self.assertRaises(module.VerifyError):
            module.inspect_archive("fixture.zip", buffer.getvalue())

    def test_archive_duplicate_member_is_rejected(self):
        module = verifier()
        buffer = io.BytesIO()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(buffer, "w", zipfile.ZIP_STORED) as archive:
                archive.writestr("same.txt", "one")
                archive.writestr("same.txt", "two")
        with self.assertRaises(module.VerifyError):
            module.inspect_archive("fixture.zip", buffer.getvalue())

    def test_concatenated_gzip_is_rejected(self):
        module = verifier()
        payload = gzip.compress(b"one") + gzip.compress(b"two")
        with self.assertRaises(module.VerifyError):
            module.inspect_archive("fixture.log.gz", payload)

    def test_unknown_extension_is_not_silently_classified(self):
        module = verifier()
        self.assertTrue(module.recognized_file_name("docs/README.md"))
        self.assertTrue(module.recognized_file_name("tools/image/Dockerfile"))
        self.assertFalse(module.recognized_file_name("surface.unknown"))

    def test_output_is_single_canonical_record(self):
        module = verifier()
        payload = module.canonical_json({"result": "PASS", "tests": 1})
        self.assertEqual(payload.count(b"\n"), 1)
        self.assertTrue(payload.endswith(b"\n"))

    def test_technique_deterministic_seeded_fuzz_json_roundtrip(self):
        module = verifier()
        generator = random.Random(0xC0FFEE)
        alphabet = "abcXYZ09-\u00e9\u0394\U0001f642"
        for _ in range(256):
            keys = {
                "".join(
                    generator.choice(alphabet) for _ in range(generator.randint(1, 12))
                )
                for _ in range(generator.randint(1, 8))
            }
            value = {
                key: [
                    generator.randint(-(2**53), 2**53),
                    bool(generator.getrandbits(1)),
                    "".join(
                        generator.choice(alphabet)
                        for _ in range(generator.randint(0, 24))
                    ),
                    None,
                ]
                for key in keys
            }
            payload = module.canonical_json(value)
            self.assertEqual(module.load_json(payload), value)
            self.assertEqual(module.canonical_json(module.load_json(payload)), payload)

    def test_technique_deterministic_seeded_fuzz_path_policy(self):
        module = verifier()
        generator = random.Random(0x5EED)
        alphabet = "abcdefghijklmnopqrstuvwxyz0123456789-_"
        for _ in range(256):
            components = [
                "".join(
                    generator.choice(alphabet) for _ in range(generator.randint(1, 24))
                )
                for _ in range(generator.randint(1, 6))
            ]
            path = "/".join(components)
            self.assertTrue(module.valid_path(path))
            self.assertFalse(module.valid_path(f"../{path}"))
            self.assertFalse(module.valid_path(f"{path}/../escape"))
            backslash_path = (
                path.replace("/", "\\", 1) if "/" in path else f"{path}\\escape"
            )
            self.assertFalse(module.valid_path(backslash_path))

    def test_technique_property_canonical_json_is_permutation_invariant(self):
        module = verifier()
        items = [("z", 1), ("\u00e9", 2), ("a", 3), ("\u0394", 4)]
        expected = module.canonical_json(dict(items))
        for permutation in itertools.permutations(items):
            self.assertEqual(module.canonical_json(dict(permutation)), expected)

    def test_technique_property_canonical_json_mutation_is_detectable(self):
        module = verifier()
        generator = random.Random(0xD16E57)
        for _ in range(128):
            values = [generator.randrange(0, 2**32) for _ in range(8)]
            original = module.canonical_json({"values": values})
            index = generator.randrange(len(values))
            mutated_values = list(values)
            mutated_values[index] ^= 1
            mutated = module.canonical_json({"values": mutated_values})
            self.assertNotEqual(original, mutated)
            self.assertNotEqual(module.sha256(original), module.sha256(mutated))

    def test_json_unicode_scalars_roundtrip(self):
        module = verifier()
        value = {
            "latin": "na\u00efve",
            "greek": "\u0394",
            "astral": "\U0001f642",
            "\U00010348": "Gothic letter",
        }
        payload = module.canonical_json(value)
        self.assertEqual(module.load_json(payload), value)
        self.assertIn("\U0001f642".encode("utf-8"), payload)

    def test_json_surrogate_scalar_is_rejected(self):
        module = verifier()
        for payload in (
            b'{"value":"\\ud800"}\n',
            b'{"value":"\\udfff"}\n',
            b'{"\\ud800":"value"}\n',
        ):
            with self.subTest(payload=payload):
                with self.assertRaises(module.VerifyError):
                    module.load_json(payload)

    def test_json_invalid_utf8_is_rejected(self):
        module = verifier()
        for payload in (
            b'{"value":"\x80"}\n',
            b'{"value":"\xc0\xaf"}\n',
            b"\xef\xbb\xbf{}\n",
        ):
            with self.subTest(payload=payload):
                with self.assertRaises(module.VerifyError):
                    module.load_json(payload)

    def test_json_nonfinite_values_are_rejected(self):
        module = verifier()
        for token in (b"NaN", b"Infinity", b"-Infinity"):
            with self.subTest(token=token):
                with self.assertRaises(module.VerifyError):
                    module.load_json(token + b"\n", canonical=False)
        for value in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    module.canonical_json({"value": value})

    def test_json_nested_duplicate_key_is_rejected(self):
        module = verifier()
        with self.assertRaises(module.VerifyError):
            module.load_json(b'{"outer":{"same":1,"same":2}}\n', canonical=False)

    def test_json_depth_boundary_is_exact(self):
        module = verifier()
        accepted: object = 0
        for _ in range(64):
            accepted = [accepted]
        self.assertEqual(module.load_json(module.canonical_json(accepted)), accepted)
        rejected = [accepted]
        with self.assertRaises(module.VerifyError):
            module.load_json(module.canonical_json(rejected))

    def test_json_byte_boundary_counts_utf8_bytes(self):
        module = verifier()
        payload = module.canonical_json({"value": "\U0001f642"})
        self.assertEqual(
            module.load_json(payload, maximum=len(payload)), {"value": "\U0001f642"}
        )
        with self.assertRaises(module.VerifyError):
            module.load_json(payload, maximum=len(payload) - 1)

    def test_json_canonical_form_rejects_trailing_or_leading_space(self):
        module = verifier()
        for payload in (b" {}\n", b"{} \n", b"{}\n\n", b"{ }\n"):
            with self.subTest(payload=payload):
                with self.assertRaises(module.VerifyError):
                    module.load_json(payload)

    def test_git_environment_is_closed(self):
        module = verifier()
        with (
            tempfile.TemporaryDirectory() as directory,
            mock.patch.dict(
                module.os.environ,
                {
                    "GIT_TRACE": "1",
                    "GIT_CONFIG_GLOBAL": "/unsafe",
                    "SENSITIVE_TOKEN": "not-retained",
                    "HOME": "/unsafe-home",
                },
                clear=True,
            ),
        ):
            environment = module.git_environment(Path(directory))
        self.assertEqual(environment["GIT_NO_LAZY_FETCH"], "1")
        self.assertEqual(environment["GIT_NO_REPLACE_OBJECTS"], "1")
        self.assertEqual(environment["GIT_OPTIONAL_LOCKS"], "0")
        self.assertEqual(environment["GIT_ALLOW_PROTOCOL"], "")
        self.assertEqual(environment["HOME"], "/nonexistent")
        self.assertNotIn("GIT_TRACE", environment)
        self.assertNotIn("SENSITIVE_TOKEN", environment)

    def test_structured_yaml_subset_accepts_workflow_shape(self):
        module = verifier()
        payload = (
            b"name: ci\n"
            b"on:\n"
            b"  push:\n"
            b'    branches: ["**"]\n'
            b"jobs:\n"
            b"  build:\n"
            b"    steps:\n"
            b"      - name: Run\n"
            b"        run: |\n"
            b"          echo completed\n"
        )
        self.assertIsNone(module.validate_yaml(payload, "workflow.yml"))

    def test_structured_yaml_subset_rejects_malformed_flow(self):
        module = verifier()
        for payload in (
            b"a: [unterminated\n",
            b"a: {key: 1, key: 2}\n",
        ):
            with self.subTest(payload=payload):
                with self.assertRaises(module.VerifyError):
                    module.validate_yaml(payload, "fixture.yml")

    def test_structured_yaml_subset_rejects_child_below_scalar(self):
        module = verifier()
        with self.assertRaises(module.VerifyError):
            module.validate_yaml(b"a: 1\n  b: 2\n", "fixture.yml")

    def test_structured_yaml_subset_rejects_plain_scalar_mapping_injection(self):
        module = verifier()
        with self.assertRaises(module.VerifyError):
            module.validate_yaml(b"a: foo: bar\n", "fixture.yml")

    def test_structured_yaml_subset_rejects_invalid_double_quote_escape(self):
        module = verifier()
        with self.assertRaises(module.VerifyError):
            module.validate_yaml(b'a: "\\q"\n', "fixture.yml")

    def test_structured_yaml_subset_rejects_lone_unicode_surrogate(self):
        module = verifier()
        with self.assertRaises(module.VerifyError):
            module.validate_yaml(b'a: "\\ud800"\n', "fixture.yml")

    def test_structured_yaml_subset_rejects_duplicate_after_inline_sequence_block(self):
        module = verifier()
        payload = (
            b"jobs:\n"
            b"  x:\n"
            b"    steps:\n"
            b"      - run: |\n"
            b"          echo ok\n"
            b"        run: duplicate\n"
        )
        with self.assertRaises(module.VerifyError):
            module.validate_yaml(payload, "fixture.yml")

    def test_structured_json5_rejects_duplicate_keys(self):
        module = verifier()
        with self.assertRaises(module.VerifyError):
            module.validate_structured_blob("fixture.json5", b'{"a":1,"a":2}\n')

    def test_archive_valid_gzip_has_exact_member_record(self):
        module = verifier()
        expanded = b"CL-EXAMPLE-01\nregistered gzip member\n"
        payload = gzip.compress(expanded, mtime=0)
        records = module.inspect_archive("fixture.log.gz", payload)
        self.assertEqual(
            records,
            [
                {
                    "container_path": "fixture.log.gz",
                    "member_path": "fixture.log",
                    "bytes": len(expanded),
                    "compressed_bytes": len(payload),
                    "crc32": None,
                    "sha256": module.sha256(expanded),
                    "content_kind": "UTF8",
                    "claim_ids": ["CL-EXAMPLE-01"],
                }
            ],
        )

    def test_archive_gzip_trailing_junk_is_rejected(self):
        module = verifier()
        payload = gzip.compress(b"member", mtime=0) + b"trailing-junk"
        with self.assertRaises(module.VerifyError):
            module.inspect_archive("fixture.txt.gz", payload)

    def test_archive_truncated_gzip_is_rejected(self):
        module = verifier()
        payload = gzip.compress(b"member", mtime=0)
        for removed_bytes in (1, 4, 8):
            with self.subTest(removed_bytes=removed_bytes):
                with self.assertRaises(module.VerifyError):
                    module.inspect_archive("fixture.txt.gz", payload[:-removed_bytes])

    def test_archive_gzip_optional_header_metadata_is_rejected(self):
        module = verifier()
        payload = bytearray(gzip.compress(b"payload", mtime=0))
        payload[3] = 0x08
        payload[10:10] = b"VALIDATED\x00"
        with self.assertRaises(module.VerifyError):
            module.inspect_archive("fixture.txt.gz", bytes(payload))

    def test_archive_gzip_nested_archive_magic_is_rejected(self):
        module = verifier()
        nested = self.zip_payload(
            [("member.txt", b"payload")],
            zipfile.ZIP_STORED,
        )
        with self.assertRaises(module.VerifyError):
            module.inspect_archive(
                "fixture.txt.gz",
                gzip.compress(nested, mtime=0),
            )

    def test_archive_gzip_decoder_does_not_call_unbounded_flush(self):
        module = verifier()
        inner = module.zlib.decompressobj(16 + module.zlib.MAX_WBITS)

        class BoundedInflater:
            def decompress(self, payload, maximum):
                return inner.decompress(payload, maximum)

            @property
            def eof(self):
                return inner.eof

            @property
            def unused_data(self):
                return inner.unused_data

            @property
            def unconsumed_tail(self):
                return inner.unconsumed_tail

            def flush(self):
                raise AssertionError("unbounded flush must not be called")

        payload = gzip.compress(b"payload", mtime=0)
        with mock.patch.object(
            module.zlib,
            "decompressobj",
            return_value=BoundedInflater(),
        ):
            records = module.inspect_archive("fixture.txt.gz", payload)
        self.assertEqual([item["bytes"] for item in records], [7])

    def test_archive_gzip_ratio_limit_is_enforced(self):
        module = verifier()
        payload = gzip.compress(b"A" * 200_000, compresslevel=9, mtime=0)
        self.assertGreater(200_000, len(payload) * module.MAX_ARCHIVE_RATIO)
        with self.assertRaises(module.VerifyError):
            module.inspect_archive("fixture.txt.gz", payload)

    def test_archive_valid_zip_is_sorted_and_bound(self):
        module = verifier()
        payload = self.zip_payload(
            [("z.txt", b"last"), ("a.txt", b"first")],
            compression=zipfile.ZIP_STORED,
        )
        records = module.inspect_archive("fixture.zip", payload)
        self.assertEqual([item["member_path"] for item in records], ["a.txt", "z.txt"])
        self.assertEqual([item["bytes"] for item in records], [5, 4])
        self.assertTrue(all(type(item["crc32"]) is int for item in records))

    def test_archive_signed_data_descriptor_is_accepted(self):
        module = verifier()
        records = module.inspect_archive(
            "fixture.zip",
            self.zip_payload_with_data_descriptor(),
        )
        self.assertEqual([item["member_path"] for item in records], ["member.txt"])
        self.assertEqual([item["bytes"] for item in records], [7])

    def test_archive_hidden_gap_before_central_directory_is_rejected(self):
        module = verifier()
        payload = self.insert_before_zip_central_directory(
            self.zip_payload(
                [("member.txt", b"payload")],
                zipfile.ZIP_DEFLATED,
            ),
            b"hidden-gap",
        )
        with self.assertRaises(module.VerifyError):
            module.inspect_archive("fixture.zip", payload)

    def test_archive_deflate_stream_tail_is_rejected(self):
        module = verifier()
        value = bytearray(
            self.zip_payload(
                [("member.txt", b"A")],
                zipfile.ZIP_DEFLATED,
            )
        )
        local = value.find(b"PK\x03\x04")
        compressed_size = int.from_bytes(value[local + 18 : local + 22], "little")
        compressor = module.zlib.compressobj(
            level=9,
            wbits=-module.zlib.MAX_WBITS,
        )
        tail = compressor.compress(b"B") + compressor.flush()
        value = bytearray(self.insert_before_zip_central_directory(bytes(value), tail))
        central = value.find(b"PK\x01\x02")
        value[local + 18 : local + 22] = (compressed_size + len(tail)).to_bytes(
            4, "little"
        )
        value[central + 20 : central + 24] = (compressed_size + len(tail)).to_bytes(
            4, "little"
        )
        with self.assertRaises(module.VerifyError):
            module.inspect_archive("fixture.zip", bytes(value))

    def test_archive_local_only_extra_field_is_rejected(self):
        module = verifier()
        value = bytearray(
            self.zip_payload(
                [("member.txt", b"payload")],
                zipfile.ZIP_DEFLATED,
            )
        )
        local = value.find(b"PK\x03\x04")
        eocd = value.rfind(b"PK\x05\x06")
        central_offset = int.from_bytes(value[eocd + 16 : eocd + 20], "little")
        name_length = int.from_bytes(value[local + 26 : local + 28], "little")
        data_start = local + 30 + name_length
        value[local + 28 : local + 30] = (4).to_bytes(2, "little")
        value[data_start:data_start] = b"\xfe\xca\x00\x00"
        eocd += 4
        value[eocd + 16 : eocd + 20] = (central_offset + 4).to_bytes(
            4,
            "little",
        )
        with self.assertRaises(module.VerifyError):
            module.inspect_archive("fixture.zip", bytes(value))

    def test_archive_local_header_metadata_mismatch_is_rejected(self):
        module = verifier()
        payload = self.zip_payload(
            [("member.txt", b"payload")],
            zipfile.ZIP_STORED,
        )
        local = payload.find(b"PK\x03\x04")
        for label, start, end in (
            ("version", 4, 6),
            ("time", 10, 12),
            ("date", 12, 14),
            ("crc", 14, 18),
            ("compressed_size", 18, 22),
            ("expanded_size", 22, 26),
        ):
            with self.subTest(field=label):
                value = bytearray(payload)
                value[local + start : local + end] = b"\xff" * (end - start)
                with self.assertRaises(module.VerifyError):
                    module.inspect_archive("fixture.zip", bytes(value))

    def test_archive_reserved_zip_flag_is_rejected(self):
        module = verifier()
        value = bytearray(
            self.zip_payload(
                [("member.txt", b"payload")],
                zipfile.ZIP_STORED,
            )
        )
        local = value.find(b"PK\x03\x04")
        central = value.find(b"PK\x01\x02")
        value[local + 6 : local + 8] = (0x10).to_bytes(2, "little")
        value[central + 8 : central + 10] = (0x10).to_bytes(2, "little")
        with self.assertRaises(module.VerifyError):
            module.inspect_archive("fixture.zip", bytes(value))

    def test_archive_uninventoried_zip_metadata_is_rejected(self):
        module = verifier()
        cases = {}
        target = io.BytesIO()
        with zipfile.ZipFile(target, "w", zipfile.ZIP_STORED) as archive:
            archive.comment = b"VALIDATED"
            archive.writestr("member.txt", b"payload")
        cases["archive_comment"] = target.getvalue()
        target = io.BytesIO()
        with zipfile.ZipFile(target, "w", zipfile.ZIP_STORED) as archive:
            info = zipfile.ZipInfo("member.txt")
            info.comment = b"DEPLOYMENT_QUALIFIED"
            archive.writestr(info, b"payload")
        cases["member_comment"] = target.getvalue()
        target = io.BytesIO()
        with zipfile.ZipFile(target, "w", zipfile.ZIP_STORED) as archive:
            info = zipfile.ZipInfo("member.txt")
            info.extra = b"\xfe\xca\x00\x00"
            archive.writestr(info, b"payload")
        cases["matching_extra"] = target.getvalue()
        for label, payload in cases.items():
            with self.subTest(metadata=label):
                with self.assertRaises(module.VerifyError):
                    module.inspect_archive("fixture.zip", payload)

    def test_archive_zip_leading_and_trailing_junk_are_rejected(self):
        module = verifier()
        payload = self.zip_payload(
            [("member.txt", b"member")],
            zipfile.ZIP_DEFLATED,
        )
        for hostile in (b"junk" + payload, payload + b"junk"):
            with self.subTest(
                position="leading" if hostile.startswith(b"junk") else "trailing"
            ):
                with self.assertRaises(module.VerifyError):
                    module.inspect_archive("fixture.zip", hostile)

    def test_archive_nested_container_is_rejected(self):
        module = verifier()
        for member in ("nested.zip", "nested.gz", "nested.tgz", "nested.tar"):
            with self.subTest(member=member):
                payload = self.zip_payload(
                    [(member, b"not-an-archive")],
                    zipfile.ZIP_DEFLATED,
                )
                with self.assertRaises(module.VerifyError):
                    module.inspect_archive("fixture.zip", payload)

    def test_archive_nested_container_magic_under_text_name_is_rejected(self):
        module = verifier()
        nested = gzip.compress(b"payload", mtime=0)
        payload = self.zip_payload(
            [("nested.txt", nested)],
            zipfile.ZIP_DEFLATED,
        )
        with self.assertRaises(module.VerifyError):
            module.inspect_archive("fixture.zip", payload)

    def test_archive_non_normalized_member_is_rejected(self):
        module = verifier()
        payload = self.zip_payload(
            [("nai\u0308ve.txt", b"member")],
            zipfile.ZIP_DEFLATED,
        )
        with self.assertRaises(module.VerifyError):
            module.inspect_archive("fixture.zip", payload)

    def test_archive_symlink_member_is_rejected(self):
        module = verifier()
        info = zipfile.ZipInfo("link")
        info.create_system = 3
        info.external_attr = 0o120777 << 16
        payload = self.zip_payload([(info, b"target")], zipfile.ZIP_STORED)
        with self.assertRaises(module.VerifyError):
            module.inspect_archive("fixture.zip", payload)

    def test_archive_directory_and_empty_zip_are_rejected(self):
        module = verifier()
        directory_payload = self.zip_payload(
            [("directory/", b"")],
            zipfile.ZIP_DEFLATED,
        )
        empty_buffer = io.BytesIO()
        with zipfile.ZipFile(empty_buffer, "w"):
            pass
        for payload in (directory_payload, empty_buffer.getvalue()):
            with self.subTest(bytes=len(payload)):
                with self.assertRaises(module.VerifyError):
                    module.inspect_archive("fixture.zip", payload)

    def test_archive_zip_ratio_limit_is_enforced(self):
        module = verifier()
        payload = self.zip_payload(
            [("member.txt", b"A" * 200_000)],
            zipfile.ZIP_DEFLATED,
        )
        with self.assertRaises(module.VerifyError):
            module.inspect_archive("fixture.zip", payload)

    def test_qualification_common_evidence_valid_fixture(self):
        module = verifier()
        record = self.common_evidence(module)
        observed, started, completed = module.validate_common_evidence(
            record,
            identifier="CH-T003-E01",
            schema_id="haldir.ch-t003.file-review-traceability.v1",
            freeze_commit="f" * 40,
            implementation_commit="1" * 40,
            implementation_time=module.parse_utc("2026-07-23T00:00:00Z"),
            qualification_time=module.parse_utc("2026-07-23T00:00:03Z"),
        )
        self.assertIs(observed, record)
        self.assertLess(started, completed)

    def test_qualification_common_evidence_mutations_are_rejected(self):
        module = verifier()
        mutations = {
            "extra_field": lambda item: item.update({"unexpected": True}),
            "wrong_schema": lambda item: item.update({"schema_id": "wrong"}),
            "wrong_identifier": lambda item: item.update(
                {"evidence_id": "CH-T003-E02"}
            ),
            "wrong_result": lambda item: item.update({"result": "FAIL"}),
            "before_implementation": lambda item: item.update(
                {"started_at_utc": "2026-07-22T23:59:59Z"}
            ),
            "after_qualification": lambda item: item.update(
                {"completed_at_utc": "2026-07-23T00:00:04Z"}
            ),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                record = self.common_evidence(module)
                mutate(record)
                with self.assertRaises(module.VerifyError):
                    module.validate_common_evidence(
                        record,
                        identifier="CH-T003-E01",
                        schema_id="haldir.ch-t003.file-review-traceability.v1",
                        freeze_commit="f" * 40,
                        implementation_commit="1" * 40,
                        implementation_time=module.parse_utc("2026-07-23T00:00:00Z"),
                        qualification_time=module.parse_utc("2026-07-23T00:00:03Z"),
                    )

    def test_qualification_retained_command_valid_fixture(self):
        module = verifier()
        record = self.retained_command(module)
        started, completed = module.validate_retained_command(
            record,
            window_start=module.parse_utc("2026-07-23T00:00:00Z"),
            window_end=module.parse_utc("2026-07-23T00:00:03Z"),
            expected_phase="REGISTERED_TESTS",
            expected_argv=record["argv"],
        )
        self.assertLess(started, completed)

    def test_qualification_retained_command_mutations_are_rejected(self):
        module = verifier()
        mutations = {
            "unknown_field": lambda item: item.update({"unknown": True}),
            "wrong_phase": lambda item: item.update({"phase": "WRONG"}),
            "wrong_cwd": lambda item: item.update({"cwd": "/tmp"}),
            "failed_exit": lambda item: item.update({"exit_code": 1}),
            "empty_output": lambda item: item.update(
                {
                    "stdout": "",
                    "stdout_sha256": module.sha256(b""),
                    "stderr": "",
                    "stderr_sha256": module.sha256(b""),
                }
            ),
            "bad_stdout_digest": lambda item: item.update({"stdout_sha256": "0" * 64}),
            "inverted_time": lambda item: item.update(
                {
                    "started_at_utc": "2026-07-23T00:00:02Z",
                    "completed_at_utc": "2026-07-23T00:00:01Z",
                }
            ),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                record = self.retained_command(module)
                mutate(record)
                with self.assertRaises(module.VerifyError):
                    module.validate_retained_command(
                        record,
                        window_start=module.parse_utc("2026-07-23T00:00:00Z"),
                        window_end=module.parse_utc("2026-07-23T00:00:03Z"),
                        expected_phase="REGISTERED_TESTS",
                    )

    def test_qualification_retained_command_stream_boundaries(self):
        module = verifier()
        window_start = module.parse_utc("2026-07-23T00:00:00Z")
        window_end = module.parse_utc("2026-07-23T00:00:03Z")

        def command_with_stdout(size):
            record = self.retained_command(module)
            record["stdout"] = "x" * size
            record["stdout_sha256"] = module.sha256(record["stdout"].encode())
            return record

        module.validate_retained_command(
            command_with_stdout(65_536),
            window_start=window_start,
            window_end=window_end,
        )
        self.assert_verify_error(
            module,
            "RETAINED_COMMAND",
            lambda: module.validate_retained_command(
                command_with_stdout(65_537),
                window_start=window_start,
                window_end=window_end,
            ),
        )
        module.validate_retained_command(
            command_with_stdout(4_194_304),
            window_start=window_start,
            window_end=window_end,
            maximum_stream_bytes=4_194_304,
        )
        self.assert_verify_error(
            module,
            "RETAINED_COMMAND",
            lambda: module.validate_retained_command(
                command_with_stdout(4_194_305),
                window_start=window_start,
                window_end=window_end,
                maximum_stream_bytes=4_194_304,
            ),
        )
        for invalid_bound in (0, 4_194_305, True):
            with self.subTest(invalid_bound=invalid_bound):
                self.assert_verify_error(
                    module,
                    "RETAINED_COMMAND_BOUND",
                    lambda invalid_bound=invalid_bound: (
                        module.validate_retained_command(
                            self.retained_command(module),
                            window_start=window_start,
                            window_end=window_end,
                            maximum_stream_bytes=invalid_bound,
                        )
                    ),
                )

    def test_qualification_review_attestation_excludes_signature(self):
        module = verifier()
        outer = {
            "id": "CH-T003-R01",
            "nested": {"values": [1, 2, 3]},
            "detached_signature": {"signature": "excluded"},
        }
        payload = module.review_attestation_payload(outer, "f" * 40, "1" * 40)
        document = module.load_json(payload)
        self.assertEqual(
            set(document),
            {
                "epoch",
                "freeze_commit",
                "implementation_commit",
                "purpose",
                "review_record",
                "schema_version",
                "task_id",
            },
        )
        self.assertNotIn("detached_signature", document["review_record"])
        outer["nested"]["values"].append(4)
        self.assertEqual(document["review_record"]["nested"]["values"], [1, 2, 3])

    def test_qualification_review_signature_valid_and_mutated(self):
        module = verifier()
        namespace = "haldir-independent-review-v2"
        payload = module.review_attestation_payload(
            {
                "id": "CH-T003-R01",
                "decision": "ACCEPT_TECHNICAL_TASK_QUALIFICATION",
                "detached_signature": None,
            },
            "f" * 40,
            "1" * 40,
        )
        with tempfile.TemporaryDirectory(
            prefix="haldir-ch-t003-test-signature-"
        ) as directory:
            root = Path(directory)
            key = root / "reviewer"
            keygen = subprocess.run(
                [
                    "/usr/bin/ssh-keygen",
                    "-q",
                    "-t",
                    "ed25519",
                    "-N",
                    "",
                    "-C",
                    "registered-test",
                    "-f",
                    str(key),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=30,
            )
            self.assertEqual(keygen.returncode, 0, keygen.stderr.decode())
            payload_path = root / "attestation.json"
            payload_path.write_bytes(payload)
            signing = subprocess.run(
                [
                    "/usr/bin/ssh-keygen",
                    "-Y",
                    "sign",
                    "-f",
                    str(key),
                    "-n",
                    namespace,
                    str(payload_path),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=30,
            )
            self.assertEqual(signing.returncode, 0, signing.stderr.decode())
            signature = (root / "attestation.json.sig").read_text(encoding="ascii")
            registry = {
                "reviewer": {
                    "principal": "ch-t003-test-reviewer",
                },
                "public_key": (root / "reviewer.pub")
                .read_text(encoding="ascii")
                .strip(),
            }
            module.verify_review_signature(registry, namespace, signature, payload)
            with self.assertRaises(module.VerifyError):
                module.verify_review_signature(
                    registry, namespace, signature, payload + b" "
                )
            with self.assertRaises(module.VerifyError):
                module.verify_review_signature(
                    registry, "wrong-namespace", signature, payload
                )

    def test_qualification_review_signature_armor_is_bounded(self):
        module = verifier()
        registry = {
            "reviewer": {"principal": "ch-t003-test-reviewer"},
            "public_key": "ssh-ed25519 AAAA",
        }
        for signature in (
            "",
            "not armor",
            "-----BEGIN SSH SIGNATURE-----\nmissing-end",
            "-----BEGIN SSH SIGNATURE-----\n"
            + ("A" * 8192)
            + "\n-----END SSH SIGNATURE-----\n",
        ):
            with self.subTest(length=len(signature)):
                with self.assertRaises(module.VerifyError):
                    module.verify_review_signature(
                        registry,
                        "haldir-independent-review-v2",
                        signature,
                        b"payload",
                    )

    def test_qualification_reviewer_registry_key_semantics(self):
        module = verifier()
        freeze = self.reviewer_registry_fixture(module)
        registry = module.reviewer_registry(freeze)
        for identifier, kind, _name in module.REVIEW_SPECS:
            item = registry[identifier]
            self.assertEqual(item["kind"], kind)
            self.assertEqual(item["path"], module.REVIEW_PATHS[identifier])
            self.assertEqual(
                item["key_fingerprint"],
                module.public_key_fingerprint(item["public_key"]),
            )
            self.assertNotEqual(
                item["reviewer"]["name"],
                module.AUTHOR["name"],
            )
            self.assertNotEqual(
                item["reviewer"]["principal"],
                module.AUTHOR["email"],
            )

        fingerprint_mismatch = self.reviewer_registry_fixture(module)
        fingerprint_mismatch["reviewer_registry"][0]["key_fingerprint"] = "SHA256:" + (
            "A" * 43
        )
        self.assert_verify_error(
            module,
            "REVIEWER_REGISTRY_BINDING",
            lambda: module.reviewer_registry(fingerprint_mismatch),
        )

        duplicate_key = self.reviewer_registry_fixture(module)
        duplicate_key["reviewer_registry"][1]["public_key"] = duplicate_key[
            "reviewer_registry"
        ][0]["public_key"]
        duplicate_key["reviewer_registry"][1]["key_fingerprint"] = duplicate_key[
            "reviewer_registry"
        ][0]["key_fingerprint"]
        self.assert_verify_error(
            module,
            "REVIEWER_REGISTRY_SEPARATION",
            lambda: module.reviewer_registry(duplicate_key),
        )

        wrong_contract = self.reviewer_registry_fixture(module)
        wrong_contract["reviewer_registry"][0]["kind"] = "LEAD_IMPLEMENTATION_REVIEW"
        wrong_contract["reviewer_registry"][0]["path"] = module.REVIEW_PATHS[
            "CH-T003-R04"
        ]
        self.assert_verify_error(
            module,
            "REVIEWER_REGISTRY_BINDING",
            lambda: module.reviewer_registry(wrong_contract),
        )

    def test_qualification_freeze_control_sets_valid_fixture(self):
        module = verifier()
        controls = [
            {
                "id": f"CH-T003-N{index:02d}",
                "statement": f"Control {index}.",
                "accepted_test_id": f"test_n{index:02d}_accepted",
                "rejected_test_id": f"test_n{index:02d}_rejected",
            }
            for index in range(1, 21)
        ]
        counterfactuals = [
            {
                "id": f"CH-T003-CF{index:02d}",
                "statement": f"Counterfactual {index}.",
                "accepted_test_id": f"test_cf{index:02d}_accepted",
                "rejected_test_id": f"test_cf{index:02d}_rejected",
            }
            for index in range(1, 11)
        ]
        requirements, counterfactual_ids, sorted_tests, ordered_tests = (
            module.freeze_control_sets(
                {
                    "normative_controls": controls,
                    "mandatory_counterfactuals": counterfactuals,
                }
            )
        )
        self.assertEqual(len(requirements), 20)
        self.assertEqual(len(counterfactual_ids), 10)
        self.assertEqual(len(sorted_tests), 60)
        self.assertEqual(set(sorted_tests), set(ordered_tests))

    def test_qualification_freeze_control_mutations_are_rejected(self):
        module = verifier()
        controls = [
            {
                "id": f"CH-T003-N{index:02d}",
                "statement": f"Control {index}.",
                "accepted_test_id": f"test_n{index:02d}_accepted",
                "rejected_test_id": f"test_n{index:02d}_rejected",
            }
            for index in range(1, 21)
        ]
        counterfactuals = [
            {
                "id": f"CH-T003-CF{index:02d}",
                "statement": f"Counterfactual {index}.",
                "accepted_test_id": f"test_cf{index:02d}_accepted",
                "rejected_test_id": f"test_cf{index:02d}_rejected",
            }
            for index in range(1, 11)
        ]
        hostile = deepcopy(controls)
        hostile[0]["accepted_test_id"] = hostile[1]["accepted_test_id"]
        with self.assertRaises(module.VerifyError):
            module.freeze_control_sets(
                {
                    "normative_controls": hostile,
                    "mandatory_counterfactuals": counterfactuals,
                }
            )
        hostile = deepcopy(counterfactuals)
        hostile[-1]["id"] = "CH-T003-CF99"
        with self.assertRaises(module.VerifyError):
            module.freeze_control_sets(
                {
                    "normative_controls": controls,
                    "mandatory_counterfactuals": hostile,
                }
            )

    def test_qualification_assignment_policy_is_deterministic(self):
        module = verifier()
        paths = [
            module.CLAIM_LEDGER_PATH,
            module.CLAIM_TIER_PATH,
            module.GITHUB_METADATA_PATH,
            ".github/workflows/ci.yml",
            "Cargo.toml",
            "crates/haldir-contracts/src/lib.rs",
            "README.md",
        ]
        first = {
            path: (
                module.assigned_review_lanes(path),
                module.assignment_evidence_ids(path),
            )
            for path in paths
        }
        second = {
            path: (
                module.assigned_review_lanes(path),
                module.assignment_evidence_ids(path),
            )
            for path in reversed(paths)
        }
        self.assertEqual(first, second)
        for primary, secondary in (
            module.assigned_review_lanes(path) for path in paths
        ):
            self.assertNotEqual(primary, secondary)
            self.assertIn(primary, {"CH-T003-R01", "CH-T003-R02", "CH-T003-R03"})
            self.assertIn(secondary, {"CH-T003-R01", "CH-T003-R02", "CH-T003-R03"})
        self.assertIn(
            "CH-T003-E12",
            module.assignment_evidence_ids(module.GITHUB_METADATA_PATH),
        )
        self.assertIn(
            "CH-T003-E13",
            module.assignment_evidence_ids("crates/haldir-contracts/src/lib.rs"),
        )

    def test_qualification_section_results_bind_content_digests(self):
        module = verifier()
        public = {
            "records": [
                {"path": "README.md", "surface_types": ["DOCUMENTATION"]},
                {
                    "path": "crates/a/src/lib.rs",
                    "surface_types": ["RUST_API_SOURCE"],
                },
                {
                    "path": "deploy/config.yml",
                    "surface_types": ["CONFIGURATION", "DEPLOYMENT"],
                },
                {
                    "path": "Cargo.toml",
                    "surface_types": ["BUILD"],
                },
            ],
            "cargo": {"public_api": {"observations": ["bound"]}},
            "cli": {"entries": []},
            "ipc": {"routes": []},
            "schemas": {"messages": []},
            "documentation": {"records": []},
            "archives": {"containers": []},
            "candidate_implementation": "1" * 40,
            "release_target": module.RELEASE_TARGET,
            "persistent_identifier": None,
        }
        original = module.evidence_section_results(public)
        self.assertEqual([item["id"] for item in original], list(module.SECTION_IDS))
        self.assertTrue(all(item["result"] == "PASS" for item in original))
        mutated = deepcopy(public)
        mutated["cargo"]["public_api"]["observations"].append("changed")
        changed = module.evidence_section_results(mutated)
        original_by_id = {item["id"]: item for item in original}
        changed_by_id = {item["id"]: item for item in changed}
        self.assertNotEqual(
            original_by_id["COMPILER_OUTPUT"]["digest"],
            changed_by_id["COMPILER_OUTPUT"]["digest"],
        )
        self.assertNotEqual(
            original_by_id["CARGO_PACKAGES_TARGETS_FEATURES"]["digest"],
            changed_by_id["CARGO_PACKAGES_TARGETS_FEATURES"]["digest"],
        )

    def test_activation_log_manifest_valid_fixture(self):
        module = verifier()
        captures = self.activation_log_captures(module)
        payload = self.activation_archive(module, captures)
        manifest = module.activation_log_manifest(payload, captures)
        self.assertEqual(len(manifest), len(module.ALL_HOSTED_JOB_NAMES))
        self.assertEqual(
            [item["name"] for item in manifest],
            [module.JOB_LOG_MEMBERS[name] for name in module.ALL_HOSTED_JOB_NAMES],
        )
        self.assertTrue(all(item["bytes"] > 0 for item in manifest))
        self.assertTrue(all(item["mode"] == 0o100644 for item in manifest))
        self.assertTrue(all(item["method"] == zipfile.ZIP_STORED for item in manifest))

    def test_activation_log_manifest_mutations_are_rejected(self):
        module = verifier()
        captures = self.activation_log_captures(module)
        payload = self.activation_archive(module, captures)
        self.assert_verify_error(
            module,
            "ACTIVATION_LOG_ARCHIVE_BOUND",
            lambda: module.activation_log_manifest(payload, captures[:-1]),
        )

        digest_mismatch = deepcopy(captures)
        digest_mismatch[0]["sha256"] = "0" * 64
        self.assert_verify_error(
            module,
            "ACTIVATION_LOG_ARCHIVE_CONTENT",
            lambda: module.activation_log_manifest(
                payload,
                digest_mismatch,
            ),
        )

        extra_capture = {
            "name": "extra",
            "retained_member": "extra.log",
            "bytes": len(self.activation_log_payload("extra")),
            "sha256": module.sha256(self.activation_log_payload("extra")),
        }
        extra_payload = self.activation_archive(
            module,
            [*captures, extra_capture],
        )
        self.assert_verify_error(
            module,
            "ACTIVATION_LOG_ARCHIVE_ENTRIES",
            lambda: module.activation_log_manifest(extra_payload, captures),
        )

        nested_captures = deepcopy(captures)
        nested_captures[0]["retained_member"] = (
            "nested/" + nested_captures[0]["retained_member"]
        )
        nested_payload = self.activation_archive(module, nested_captures)
        self.assert_verify_error(
            module,
            "ACTIVATION_LOG_ARCHIVE_ENTRIES",
            lambda: module.activation_log_manifest(nested_payload, captures),
        )

        compressed = io.BytesIO()
        with zipfile.ZipFile(
            compressed,
            "w",
            compression=zipfile.ZIP_DEFLATED,
        ) as archive:
            for capture in captures:
                info = zipfile.ZipInfo(
                    capture["retained_member"],
                    date_time=(1980, 1, 1, 0, 0, 0),
                )
                info.create_system = 3
                info.external_attr = 0o100644 << 16
                archive.writestr(
                    info,
                    self.activation_log_payload(capture["name"]),
                    compress_type=zipfile.ZIP_DEFLATED,
                )
        self.assert_verify_error(
            module,
            "ACTIVATION_LOG_ARCHIVE_ENTRY",
            lambda: module.activation_log_manifest(
                compressed.getvalue(),
                captures,
            ),
        )

    def test_activation_retained_capture_valid_fixture(self):
        module = verifier()
        payload = module.canonical_json({"result": "captured"})
        source = "https://api.github.com/repos/sepahead/haldir/actions/runs/42"
        capture = self.retained_capture(
            module,
            "RUN_API_JSON",
            source,
            payload,
            "2026-07-23T00:00:04Z",
            "2026-07-23T00:00:05Z",
        )
        observed, decoded = module.decode_retained_capture(
            capture,
            expected_kind="RUN_API_JSON",
            expected_source_url=source,
            qualification_time=module.parse_utc("2026-07-23T00:00:00Z"),
            activation_time=module.parse_utc("2026-07-23T00:00:10Z"),
        )
        self.assertIs(observed, capture)
        self.assertEqual(decoded, payload)

    def test_activation_retained_capture_mutations_are_rejected(self):
        module = verifier()
        payload = module.canonical_json({"result": "captured"})
        source = "https://api.github.com/repos/sepahead/haldir/actions/runs/42"
        mutations = {
            "unknown_field": lambda item: item.update({"unknown": True}),
            "wrong_kind": lambda item: item.update({"kind": "OTHER"}),
            "relative_executable": lambda item: item["capture_argv"].__setitem__(
                0, "gh"
            ),
            "wrong_digest": lambda item: item.update({"sha256": "0" * 64}),
            "invalid_base64": lambda item: item.update({"content_base64": "%%%"}),
            "credential_header": lambda item: item["request_headers"].append(
                "Authorization: token"
            ),
            "tool_version": lambda item: item.update(
                {"tool_version": "gh version unknown"}
            ),
            "late_capture": lambda item: item.update(
                {"completed_at_utc": "2026-07-23T00:00:11Z"}
            ),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                capture = self.retained_capture(
                    module,
                    "RUN_API_JSON",
                    source,
                    payload,
                    "2026-07-23T00:00:04Z",
                    "2026-07-23T00:00:05Z",
                )
                mutate(capture)
                with self.assertRaises(module.VerifyError):
                    module.decode_retained_capture(
                        capture,
                        expected_kind="RUN_API_JSON",
                        expected_source_url=source,
                        qualification_time=module.parse_utc("2026-07-23T00:00:00Z"),
                        activation_time=module.parse_utc("2026-07-23T00:00:10Z"),
                    )

    def test_activation_a01_valid_fixture(self):
        module = verifier()
        freeze_commit = "f" * 40
        implementation_commit = "1" * 40
        qualification_commit = "c" * 40
        record = self.activation_a01(
            module,
            freeze_commit,
            implementation_commit,
            qualification_commit,
        )
        started, completed = module.validate_activation_a01(
            record,
            freeze_commit=freeze_commit,
            implementation_commit=implementation_commit,
            qualification_commit=qualification_commit,
            qualification_time=module.parse_utc("2026-07-23T00:00:00Z"),
            activation_time=module.parse_utc("2026-07-23T00:00:10Z"),
        )
        self.assertLess(started, completed)

    def test_activation_a01_mutations_are_rejected(self):
        module = verifier()
        freeze_commit = "f" * 40
        implementation_commit = "1" * 40
        qualification_commit = "c" * 40

        wrong_mode = self.activation_a01(
            module,
            freeze_commit,
            implementation_commit,
            qualification_commit,
        )
        product_command = wrong_mode["commands"][1]
        document = module.load_json(product_command["stdout"].encode("utf-8"))
        document["mode"] = "UNBOUND"
        product_command["stdout"] = module.canonical_json(document).decode("utf-8")
        product_command["stdout_sha256"] = module.sha256(
            product_command["stdout"].encode("utf-8")
        )
        with self.assertRaises(module.VerifyError):
            module.validate_activation_a01(
                wrong_mode,
                freeze_commit=freeze_commit,
                implementation_commit=implementation_commit,
                qualification_commit=qualification_commit,
                qualification_time=module.parse_utc("2026-07-23T00:00:00Z"),
                activation_time=module.parse_utc("2026-07-23T00:00:10Z"),
            )

        wrong_order = self.activation_a01(
            module,
            freeze_commit,
            implementation_commit,
            qualification_commit,
        )
        wrong_order["commands"][0], wrong_order["commands"][1] = (
            wrong_order["commands"][1],
            wrong_order["commands"][0],
        )
        with self.assertRaises(module.VerifyError):
            module.validate_activation_a01(
                wrong_order,
                freeze_commit=freeze_commit,
                implementation_commit=implementation_commit,
                qualification_commit=qualification_commit,
                qualification_time=module.parse_utc("2026-07-23T00:00:00Z"),
                activation_time=module.parse_utc("2026-07-23T00:00:10Z"),
            )

    def test_activation_a02_valid_fixture(self):
        module = verifier()
        freeze_commit = "f" * 40
        implementation_commit = "1" * 40
        qualification_commit = "c" * 40
        record = self.activation_a02(
            module,
            freeze_commit,
            implementation_commit,
            qualification_commit,
        )
        started, completed = module.validate_activation_a02(
            record,
            freeze_commit=freeze_commit,
            implementation_commit=implementation_commit,
            qualification_commit=qualification_commit,
            qualification_time=module.parse_utc("2026-07-23T00:00:00Z"),
            activation_time=module.parse_utc("2026-07-23T00:00:10Z"),
        )
        self.assertLess(started, completed)

    def test_activation_a02_mutations_are_rejected(self):
        module = verifier()
        freeze_commit = "f" * 40
        implementation_commit = "1" * 40
        qualification_commit = "c" * 40
        mutations = {
            "eligible_too_soon": lambda item: item["scope"].update(
                {"wave_acceptance": "ELIGIBLE"}
            ),
            "missing_pass": lambda item: item["command"].update(
                {
                    "stdout": item["command"]["stdout"].replace(
                        "  PASS: gate-01\n", "", 1
                    )
                }
            ),
            "profile_injection": lambda item: item["command"]["argv"].__setitem__(
                -2, "/bin/bash"
            ),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                record = self.activation_a02(
                    module,
                    freeze_commit,
                    implementation_commit,
                    qualification_commit,
                )
                mutate(record)
                if label == "missing_pass":
                    record["command"]["stdout_sha256"] = module.sha256(
                        record["command"]["stdout"].encode("utf-8")
                    )
                with self.assertRaises(module.VerifyError):
                    module.validate_activation_a02(
                        record,
                        freeze_commit=freeze_commit,
                        implementation_commit=implementation_commit,
                        qualification_commit=qualification_commit,
                        qualification_time=module.parse_utc("2026-07-23T00:00:00Z"),
                        activation_time=module.parse_utc("2026-07-23T00:00:10Z"),
                    )

    def test_activation_a03_valid_fixture(self):
        module = verifier()
        freeze_commit = "f" * 40
        implementation_commit = "1" * 40
        qualification_commit = "c" * 40
        record, archive_payload = self.activation_a03(
            module,
            freeze_commit,
            implementation_commit,
            qualification_commit,
        )
        started, completed, manifest = module.validate_activation_a03(
            record,
            archive_payload=archive_payload,
            freeze_commit=freeze_commit,
            implementation_commit=implementation_commit,
            qualification_commit=qualification_commit,
            qualification_time=module.parse_utc("2026-07-23T00:00:00Z"),
            activation_time=module.parse_utc("2026-07-23T00:00:10Z"),
        )
        self.assertLess(started, completed)
        self.assertEqual(
            manifest,
            record["combined_log_archive"]["entry_manifest"],
        )
        self.assertEqual(
            [item["workflow_path"] for item in record["workflows"]],
            [
                ".github/workflows/ci.yml",
                ".github/workflows/formal.yml",
            ],
        )
        self.assertEqual(
            [
                job["name"]
                for workflow in record["workflows"]
                for job in workflow["jobs"]
            ],
            list(module.ALL_HOSTED_JOB_NAMES),
        )

    def test_activation_a03_mutations_are_rejected(self):
        module = verifier()
        freeze_commit = "f" * 40
        implementation_commit = "1" * 40
        qualification_commit = "c" * 40

        failed_projection, archive_payload = self.activation_a03(
            module,
            freeze_commit,
            implementation_commit,
            qualification_commit,
        )
        failed_projection["workflows"][0]["jobs"][0]["conclusion"] = "failure"
        self.assert_verify_error(
            module,
            "ACTIVATION_A03_JOB",
            lambda: module.validate_activation_a03(
                failed_projection,
                archive_payload=archive_payload,
                freeze_commit=freeze_commit,
                implementation_commit=implementation_commit,
                qualification_commit=qualification_commit,
                qualification_time=module.parse_utc("2026-07-23T00:00:00Z"),
                activation_time=module.parse_utc("2026-07-23T00:00:10Z"),
            ),
        )

        wrong_raw_head, archive_payload = self.activation_a03(
            module,
            freeze_commit,
            implementation_commit,
            qualification_commit,
        )
        capture = wrong_raw_head["workflows"][0]["retained_records"][0]
        raw = module.load_json(
            module.base64.b64decode(capture["content_base64"], validate=True),
            canonical=False,
        )
        raw["head_sha"] = "0" * 40
        payload = module.canonical_json(raw)
        wrong_raw_head["workflows"][0]["retained_records"][0] = self.retained_capture(
            module,
            "RUN_API_JSON",
            capture["source_url"],
            payload,
            started_at_utc=capture["started_at_utc"],
            completed_at_utc=capture["completed_at_utc"],
        )
        self.assert_verify_error(
            module,
            "ACTIVATION_A03_RAW_RUN",
            lambda: module.validate_activation_a03(
                wrong_raw_head,
                archive_payload=archive_payload,
                freeze_commit=freeze_commit,
                implementation_commit=implementation_commit,
                qualification_commit=qualification_commit,
                qualification_time=module.parse_utc("2026-07-23T00:00:00Z"),
                activation_time=module.parse_utc("2026-07-23T00:00:10Z"),
            ),
        )

        wrong_manifest, archive_payload = self.activation_a03(
            module,
            freeze_commit,
            implementation_commit,
            qualification_commit,
        )
        wrong_manifest["combined_log_archive"]["entry_manifest"][0]["sha256"] = "0" * 64
        self.assert_verify_error(
            module,
            "ACTIVATION_A03_COMBINED_LOG",
            lambda: module.validate_activation_a03(
                wrong_manifest,
                archive_payload=archive_payload,
                freeze_commit=freeze_commit,
                implementation_commit=implementation_commit,
                qualification_commit=qualification_commit,
                qualification_time=module.parse_utc("2026-07-23T00:00:00Z"),
                activation_time=module.parse_utc("2026-07-23T00:00:10Z"),
            ),
        )

        missing_formal, archive_payload = self.activation_a03(
            module,
            freeze_commit,
            implementation_commit,
            qualification_commit,
        )
        missing_formal["workflows"].pop()
        self.assert_verify_error(
            module,
            "ACTIVATION_A03_WORKFLOWS",
            lambda: module.validate_activation_a03(
                missing_formal,
                archive_payload=archive_payload,
                freeze_commit=freeze_commit,
                implementation_commit=implementation_commit,
                qualification_commit=qualification_commit,
                qualification_time=module.parse_utc("2026-07-23T00:00:00Z"),
                activation_time=module.parse_utc("2026-07-23T00:00:10Z"),
            ),
        )

        failed_formal, archive_payload = self.activation_a03(
            module,
            freeze_commit,
            implementation_commit,
            qualification_commit,
        )
        failed_formal["workflows"][1]["jobs"][0]["conclusion"] = "failure"
        self.assert_verify_error(
            module,
            "ACTIVATION_A03_JOB",
            lambda: module.validate_activation_a03(
                failed_formal,
                archive_payload=archive_payload,
                freeze_commit=freeze_commit,
                implementation_commit=implementation_commit,
                qualification_commit=qualification_commit,
                qualification_time=module.parse_utc("2026-07-23T00:00:00Z"),
                activation_time=module.parse_utc("2026-07-23T00:00:10Z"),
            ),
        )

        log_digest_mismatch, archive_payload = self.activation_a03(
            module,
            freeze_commit,
            implementation_commit,
            qualification_commit,
        )
        log_digest_mismatch["workflows"][1]["job_log_captures"][0]["sha256"] = "0" * 64
        self.assert_verify_error(
            module,
            "ACTIVATION_LOG_ARCHIVE_CONTENT",
            lambda: module.validate_activation_a03(
                log_digest_mismatch,
                archive_payload=archive_payload,
                freeze_commit=freeze_commit,
                implementation_commit=implementation_commit,
                qualification_commit=qualification_commit,
                qualification_time=module.parse_utc("2026-07-23T00:00:00Z"),
                activation_time=module.parse_utc("2026-07-23T00:00:10Z"),
            ),
        )

        member_mismatch, archive_payload = self.activation_a03(
            module,
            freeze_commit,
            implementation_commit,
            qualification_commit,
        )
        member_mismatch["workflows"][1]["job_log_captures"][0]["retained_member"] = (
            "wrong-formal.log"
        )
        self.assert_verify_error(
            module,
            "ACTIVATION_A03_JOB_LOG",
            lambda: module.validate_activation_a03(
                member_mismatch,
                archive_payload=archive_payload,
                freeze_commit=freeze_commit,
                implementation_commit=implementation_commit,
                qualification_commit=qualification_commit,
                qualification_time=module.parse_utc("2026-07-23T00:00:00Z"),
                activation_time=module.parse_utc("2026-07-23T00:00:10Z"),
            ),
        )

        metadata_mismatch, archive_payload = self.activation_a03(
            module,
            freeze_commit,
            implementation_commit,
            qualification_commit,
        )
        metadata_mismatch["combined_log_archive"]["format"] = "ZIP"
        self.assert_verify_error(
            module,
            "ACTIVATION_A03_COMBINED_LOG",
            lambda: module.validate_activation_a03(
                metadata_mismatch,
                archive_payload=archive_payload,
                freeze_commit=freeze_commit,
                implementation_commit=implementation_commit,
                qualification_commit=qualification_commit,
                qualification_time=module.parse_utc("2026-07-23T00:00:00Z"),
                activation_time=module.parse_utc("2026-07-23T00:00:10Z"),
            ),
        )

    def test_activation_a04_valid_and_mutated_fixture(self):
        module = verifier()
        freeze_commit = "f" * 40
        implementation_commit = "1" * 40
        qualification_commit = "c" * 40
        record = {
            "affected_downstreams": [],
            "completed_at_utc": "2026-07-23T00:00:05Z",
            "disposition": ("NO_RUNTIME_OR_EXTERNAL_DOWNSTREAM_CONFORMANCE_CHANGE"),
            "epoch": module.EPOCH,
            "evidence_id": "CH-T003-A04",
            "freeze_commit": freeze_commit,
            "implementation_commit": implementation_commit,
            "implementation_paths": sorted(module.IMPLEMENTATION_PLAN),
            "qualification_commit": qualification_commit,
            "rationale": (
                "The candidate changes inventory evidence and claim text only."
            ),
            "result": "PASS",
            "runtime_surface_changed": False,
            "schema_id": ("haldir.ch-t003.downstream-conformance-disposition.v1"),
            "started_at_utc": "2026-07-23T00:00:04Z",
            "task_id": module.TASK_ID,
        }
        started, completed = module.validate_activation_a04(
            record,
            freeze_commit=freeze_commit,
            implementation_commit=implementation_commit,
            qualification_commit=qualification_commit,
            qualification_time=module.parse_utc("2026-07-23T00:00:00Z"),
            activation_time=module.parse_utc("2026-07-23T00:00:10Z"),
        )
        self.assertLess(started, completed)
        for field, value in (
            ("runtime_surface_changed", True),
            ("affected_downstreams", ["ncp"]),
            ("implementation_paths", []),
            ("rationale", ""),
        ):
            with self.subTest(field=field):
                mutated = deepcopy(record)
                mutated[field] = value
                with self.assertRaises(module.VerifyError):
                    module.validate_activation_a04(
                        mutated,
                        freeze_commit=freeze_commit,
                        implementation_commit=implementation_commit,
                        qualification_commit=qualification_commit,
                        qualification_time=module.parse_utc("2026-07-23T00:00:00Z"),
                        activation_time=module.parse_utc("2026-07-23T00:00:10Z"),
                    )

    def test_activation_claim_inventory_binds_statement_and_support(self):
        module = verifier()
        payload = (
            b"| CL-ONE-01 | One statement. | PROVEN | One support. |\n"
            b"| CL-TWO-02 | Two statement. | UNPROVEN | No support. |\n"
        )
        inventory = module.claim_inventory(payload)
        self.assertEqual(
            inventory,
            [
                {
                    "id": "CL-ONE-01",
                    "status": "PROVEN",
                    "statement_sha256": module.sha256(b"One statement."),
                    "support_sha256": module.sha256(b"One support."),
                },
                {
                    "id": "CL-TWO-02",
                    "status": "UNPROVEN",
                    "statement_sha256": module.sha256(b"Two statement."),
                    "support_sha256": module.sha256(b"No support."),
                },
            ],
        )
        with self.assertRaises(module.VerifyError):
            module.claim_inventory(payload + payload.splitlines(keepends=True)[0])

    def test_activation_state_transition_valid_fixture(self):
        module = verifier()
        fixture = self.activation_state_fixture(module)
        with (
            mock.patch.object(
                module,
                "git_file",
                return_value=fixture["ledger_payload"],
            ),
            mock.patch.object(
                module,
                "tree_snapshot",
                return_value=(
                    fixture["implementation_entries"],
                    fixture["implementation_blobs"],
                ),
            ),
        ):
            requirements, claims = module.validate_activation_state_transition(
                repo=Path("/bounded-fixture"),
                freeze_commit=fixture["freeze_commit"],
                implementation_commit=fixture["implementation_commit"],
                qualification_commit=fixture["qualification_commit"],
                activation_commit=fixture["activation_commit"],
                freeze=fixture["freeze"],
                qualification=fixture["qualification"],
                outcome=fixture["outcome"],
                qualification_entries=fixture["qualification_entries"],
                qualification_blobs=fixture["qualification_blobs"],
                activation_entries=fixture["activation_entries"],
                activation_blobs=fixture["activation_blobs"],
            )
        self.assertEqual(requirements, fixture["expected_requirements"])
        self.assertEqual(claims, fixture["expected_claims"])
        self.assertFalse(
            any(
                claims[field]
                for field in (
                    "tag_authorized",
                    "github_release_authorized",
                    "doi_authorized",
                    "zenodo_authorized",
                    "archive_authorized",
                )
            )
        )

    def test_activation_state_transition_mutations_are_rejected(self):
        module = verifier()
        mutations = {
            "task_reopened": lambda fixture: fixture["expected_requirements"]["tasks"][
                3
            ].update({"status": "OPEN"}),
            "release_authorized": lambda fixture: fixture["expected_claims"].update(
                {"tag_authorized": True}
            ),
            "claim_removed": lambda fixture: fixture["expected_claims"].update(
                {"active_claims": []}
            ),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                fixture = self.activation_state_fixture(module)
                mutate(fixture)
                fixture["activation_blobs"] = {
                    module.REQUIREMENTS_PATH: module.canonical_json(
                        fixture["expected_requirements"]
                    ),
                    module.CLAIMS_STATE_PATH: module.canonical_json(
                        fixture["expected_claims"]
                    ),
                }
                with (
                    mock.patch.object(
                        module,
                        "git_file",
                        return_value=fixture["ledger_payload"],
                    ),
                    mock.patch.object(
                        module,
                        "tree_snapshot",
                        return_value=(
                            fixture["implementation_entries"],
                            fixture["implementation_blobs"],
                        ),
                    ),
                    self.assertRaises(module.VerifyError),
                ):
                    module.validate_activation_state_transition(
                        repo=Path("/bounded-fixture"),
                        freeze_commit=fixture["freeze_commit"],
                        implementation_commit=fixture["implementation_commit"],
                        qualification_commit=fixture["qualification_commit"],
                        activation_commit=fixture["activation_commit"],
                        freeze=fixture["freeze"],
                        qualification=fixture["qualification"],
                        outcome=fixture["outcome"],
                        qualification_entries=fixture["qualification_entries"],
                        qualification_blobs=fixture["qualification_blobs"],
                        activation_entries=fixture["activation_entries"],
                        activation_blobs=fixture["activation_blobs"],
                    )


if __name__ == "__main__":
    unittest.main()
