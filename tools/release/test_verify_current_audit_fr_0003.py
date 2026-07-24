#!/usr/bin/env python3
"""Test the FR-0003 hosted-time boundary repair."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import socket
import sys
import unittest
from ast import Call, Constant, FunctionDef, Name, parse, walk
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest import mock


PARENT_COMMIT = "0fc0516dc951f69fdafaaf31d9a72a0933515e93"
PARENT_TREE = "b5f8c0084b450392ba3fadb1da98b7cd05360210"


def _load_verify():
    """Load one isolated verifier module for a test."""

    module_path = Path(__file__).with_name("verify-current-audit.py")
    spec = importlib.util.spec_from_file_location(
        "verify_current_audit_fr_0003",
        module_path,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load the current-audit verifier")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_resource_profiler():
    """Load one isolated current-audit resource profiler module."""

    module_path = Path(__file__).with_name("current-audit-resource-profile.py")
    spec = importlib.util.spec_from_file_location(
        "current_audit_resource_profile_fr_0003",
        module_path,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load the current-audit resource profiler")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def utc(value: str) -> datetime:
    """Parse one canonical UTC test timestamp."""

    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def hosted_document() -> dict[str, Any]:
    """Return the exact GitHub boundary shape that stopped FR-0002."""

    return {
        "jobs": [
            {
                "completedAt": "2026-07-23T16:07:18Z",
                "conclusion": "success",
                "databaseId": 89_262_381_501,
                "name": "macos-compile",
                "startedAt": "2026-07-23T16:06:27Z",
                "status": "completed",
                "steps": [
                    {
                        "completedAt": "2026-07-23T16:06:27Z",
                        "conclusion": "success",
                        "name": "Set up job",
                        "number": 1,
                        "startedAt": "2026-07-23T16:06:26Z",
                        "status": "completed",
                    },
                    {
                        "completedAt": "2026-07-23T16:07:15Z",
                        "conclusion": "success",
                        "name": "Complete job",
                        "number": 9,
                        "startedAt": "2026-07-23T16:07:14Z",
                        "status": "completed",
                    },
                ],
                "url": (
                    "https://github.com/sepahead/haldir/actions/runs/"
                    "30023626301/job/89262381501"
                ),
            }
        ]
    }


def commit_file_record(
    _repo: Path,
    commit: str,
    path: str,
) -> dict[str, Any]:
    """Return one deterministic regular-file record for mocked commits."""

    payload = f"{commit}:{path}".encode("utf-8")
    return {
        "path": path,
        "mode": "100755" if path.endswith(".sh") else "100644",
        "type": "blob",
        "oid": hashlib.sha1(payload, usedforsecurity=False).hexdigest(),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "bytes": len(payload),
        "lines": 1,
    }


def framework_history_prefix() -> list[str]:
    """Return the exact prefix through the signed FR-0002 repair."""

    verify = _load_verify()
    chain = [f"{index + 1:040x}" for index in range(23)]
    chain[10] = "dde6512d615f54fac26b2728a05b9c53dca68666"
    chain[11] = verify.FRAMEWORK_RECOVERY_2_PRIOR_QUALIFICATION
    chain[12] = verify.FRAMEWORK_RECOVERY_2_PRIOR_ACTIVATION
    chain[21] = verify.FRAMEWORK_RECOVERY_2_PARENT
    chain[22] = verify.FRAMEWORK_RECOVERY_3_PARENT
    return chain


def parent_run_documents() -> tuple[dict[str, Any], dict[str, Any]]:
    """Return normalized parent-run documents with the exact boundary defect."""

    jobs = copy.deepcopy(hosted_document()["jobs"])
    ordinary = {
        "conclusion": "success",
        "createdAt": "2026-07-23T16:06:23Z",
        "databaseId": 30_023_626_301,
        "event": "push",
        "headBranch": "main",
        "headSha": PARENT_COMMIT,
        "jobs": jobs,
        "status": "completed",
        "updatedAt": "2026-07-23T16:12:30Z",
        "url": "https://github.com/sepahead/haldir/actions/runs/30023626301",
        "workflowName": "ci",
    }
    attempt = {
        "attempt": 1,
        "conclusion": "success",
        "createdAt": "2026-07-23T16:06:23Z",
        "databaseId": 30_023_626_301,
        "event": "push",
        "headBranch": "main",
        "headSha": PARENT_COMMIT,
        "jobs": copy.deepcopy(jobs),
        "startedAt": "2026-07-23T16:06:23Z",
        "status": "completed",
        "updatedAt": "2026-07-23T16:12:30Z",
        "url": "https://github.com/sepahead/haldir/actions/runs/30023626301",
        "workflowDatabaseId": 311_605_710,
        "workflowName": "ci",
    }
    return ordinary, attempt


class FrameworkRecovery3HostedTimeTests(unittest.TestCase):
    """Keep the GitHub job-boundary exception exact and narrow."""

    def verify(self, verifier, value: dict[str, Any]) -> list[dict[str, Any]]:
        """Run the epoch-4 nested-job policy."""

        return verifier._verify_nested_jobs(
            value,
            "framework_recovery_3.fixture",
            lower=utc("2026-07-23T16:06:23Z"),
            upper=utc("2026-07-23T16:12:30Z"),
            job_boundary_skew_seconds=(verifier.HOSTED_STEP_JOB_BOUNDARY_SKEW_SECONDS),
        )

    def assert_time_rejected(self, verifier, value: dict[str, Any]) -> None:
        """Require the stable production time error."""

        with self.assertRaisesRegex(
            verifier.CurrentAuditError,
            "CURRENT_AUDIT_HOSTED_(?:JOB|STEP)_TIME",
        ):
            self.verify(verifier, value)

    def test_exact_github_second_boundary_is_accepted(self) -> None:
        verify = _load_verify()
        self.assertEqual(
            self.verify(verify, hosted_document()),
            [
                {
                    "boundary": "STEP_STARTED_BEFORE_JOB",
                    "difference_seconds": 1,
                    "job_database_id": 89_262_381_501,
                    "job_name": "macos-compile",
                    "job_timestamp_utc": "2026-07-23T16:06:27Z",
                    "step_name": "Set up job",
                    "step_number": 1,
                    "step_timestamp_utc": "2026-07-23T16:06:26Z",
                }
            ],
        )

    def test_historical_default_remains_strict(self) -> None:
        verify = _load_verify()
        with self.assertRaisesRegex(
            verify.CurrentAuditError,
            "CURRENT_AUDIT_HOSTED_STEP_TIME",
        ):
            verify._verify_nested_jobs(
                hosted_document(),
                "framework_recovery_2.fixture",
                lower=utc("2026-07-23T16:06:23Z"),
                upper=utc("2026-07-23T16:12:30Z"),
            )

    def test_boundary_constant_is_exactly_one_second(self) -> None:
        verify = _load_verify()
        self.assertEqual(verify.HOSTED_STEP_JOB_BOUNDARY_SKEW_SECONDS, 1)
        self.assertIs(
            type(verify.HOSTED_STEP_JOB_BOUNDARY_SKEW_SECONDS),
            int,
        )

    def test_step_start_at_one_second_before_job_is_accepted(self) -> None:
        verify = _load_verify()
        value = hosted_document()
        value["jobs"][0]["steps"][0]["startedAt"] = "2026-07-23T16:06:26Z"
        self.assertEqual(len(self.verify(verify, value)), 1)

    def test_step_start_more_than_one_second_before_job_is_rejected(self) -> None:
        verify = _load_verify()
        value = hosted_document()
        value["jobs"][0]["steps"][0]["startedAt"] = "2026-07-23T16:06:25Z"
        self.assert_time_rejected(verify, value)

    def test_fractional_step_start_boundary_is_rejected(self) -> None:
        verify = _load_verify()
        for timestamp in (
            "2026-07-23T16:06:26.500Z",
            "2026-07-23T16:06:25.999Z",
        ):
            with self.subTest(timestamp=timestamp):
                value = hosted_document()
                value["jobs"][0]["steps"][0]["startedAt"] = timestamp
                self.assert_time_rejected(verify, value)

    def test_step_completion_at_one_second_after_job_is_accepted(self) -> None:
        verify = _load_verify()
        value = hosted_document()
        value["jobs"][0]["completedAt"] = "2026-07-23T16:07:14Z"
        anomalies = self.verify(verify, value)
        self.assertEqual(
            [item["boundary"] for item in anomalies],
            ["STEP_STARTED_BEFORE_JOB", "STEP_COMPLETED_AFTER_JOB"],
        )

    def test_step_completion_more_than_one_second_after_job_is_rejected(
        self,
    ) -> None:
        verify = _load_verify()
        value = hosted_document()
        value["jobs"][0]["completedAt"] = "2026-07-23T16:07:13Z"
        self.assert_time_rejected(verify, value)

    def test_fractional_step_completion_boundary_is_rejected(self) -> None:
        verify = _load_verify()
        for timestamp in (
            "2026-07-23T16:07:18.500Z",
            "2026-07-23T16:07:19.001Z",
        ):
            with self.subTest(timestamp=timestamp):
                value = hosted_document()
                value["jobs"][0]["steps"][1]["completedAt"] = timestamp
                self.assert_time_rejected(verify, value)

    def test_step_must_remain_inside_workflow_run(self) -> None:
        verify = _load_verify()
        value = hosted_document()
        value["jobs"][0]["startedAt"] = "2026-07-23T16:06:23Z"
        value["jobs"][0]["steps"][0]["startedAt"] = "2026-07-23T16:06:22Z"
        self.assert_time_rejected(verify, value)

    def test_reversed_step_interval_is_rejected(self) -> None:
        verify = _load_verify()
        value = hosted_document()
        value["jobs"][0]["steps"][0]["completedAt"] = "2026-07-23T16:06:25Z"
        self.assert_time_rejected(verify, value)

    def test_job_interval_must_remain_inside_workflow_run(self) -> None:
        verify = _load_verify()
        value = hosted_document()
        value["jobs"][0]["startedAt"] = "2026-07-23T16:06:22Z"
        self.assert_time_rejected(verify, value)

    def test_status_and_conclusion_checks_are_unchanged(self) -> None:
        verify = _load_verify()
        for field, invalid in (
            ("status", "in_progress"),
            ("conclusion", "failure"),
        ):
            value = hosted_document()
            value["jobs"][0]["steps"][0][field] = invalid
            with self.assertRaisesRegex(
                verify.CurrentAuditError,
                "CURRENT_AUDIT_HOSTED_STEP_FAILED",
            ):
                self.verify(verify, value)

    def test_skew_policy_rejects_other_values(self) -> None:
        verify = _load_verify()
        for invalid in (-1, 2, True, 1.0):
            with self.subTest(invalid=invalid):
                with self.assertRaisesRegex(
                    verify.CurrentAuditError,
                    "CURRENT_AUDIT_HOSTED_STEP_SKEW_POLICY",
                ):
                    verify._verify_nested_jobs(
                        hosted_document(),
                        "framework_recovery_3.fixture",
                        lower=utc("2026-07-23T16:06:23Z"),
                        upper=utc("2026-07-23T16:12:30Z"),
                        job_boundary_skew_seconds=invalid,
                    )

    def test_input_is_not_mutated(self) -> None:
        verify = _load_verify()
        value = hosted_document()
        before = copy.deepcopy(value)
        self.verify(verify, value)
        self.assertEqual(value, before)

    def test_anomaly_manifest_is_sorted_by_stable_identity(self) -> None:
        verify = _load_verify()
        first = hosted_document()["jobs"][0]
        second = copy.deepcopy(first)
        second["databaseId"] = 89_262_381_500
        second["name"] = "earlier-id"
        value = {"jobs": [first, second]}
        anomalies = self.verify(verify, value)
        self.assertEqual(
            [item["job_database_id"] for item in anomalies],
            [89_262_381_500, 89_262_381_501],
        )

    def test_explicit_zero_policy_matches_historical_default(self) -> None:
        verify = _load_verify()
        value = hosted_document()
        with self.assertRaisesRegex(
            verify.CurrentAuditError,
            "CURRENT_AUDIT_HOSTED_STEP_TIME",
        ):
            verify._verify_nested_jobs(
                value,
                "framework_recovery_3.zero",
                lower=utc("2026-07-23T16:06:23Z"),
                upper=utc("2026-07-23T16:12:30Z"),
                job_boundary_skew_seconds=0,
            )

    def test_clean_nested_times_return_an_empty_manifest(self) -> None:
        verify = _load_verify()
        value = hosted_document()
        value["jobs"][0]["steps"][0]["startedAt"] = value["jobs"][0]["startedAt"]
        self.assertEqual(self.verify(verify, value), [])

    def test_anomaly_manifest_has_only_exact_integer_seconds(self) -> None:
        verify = _load_verify()
        anomaly = self.verify(verify, hosted_document())[0]
        self.assertEqual(
            set(anomaly),
            {
                "boundary",
                "difference_seconds",
                "job_database_id",
                "job_name",
                "job_timestamp_utc",
                "step_name",
                "step_number",
                "step_timestamp_utc",
            },
        )
        self.assertIs(type(anomaly["difference_seconds"]), int)
        self.assertEqual(anomaly["difference_seconds"], 1)

    def test_same_step_anomalies_have_a_stable_boundary_order(self) -> None:
        verify = _load_verify()
        value = hosted_document()
        value["jobs"][0]["steps"][0]["completedAt"] = "2026-07-23T16:07:19Z"
        anomalies = self.verify(verify, value)
        self.assertEqual(
            [
                (
                    item["job_database_id"],
                    item["step_number"],
                    item["boundary"],
                )
                for item in anomalies
            ],
            [
                (
                    89_262_381_501,
                    1,
                    "STEP_COMPLETED_AFTER_JOB",
                ),
                (
                    89_262_381_501,
                    1,
                    "STEP_STARTED_BEFORE_JOB",
                ),
            ],
        )

    def test_duplicate_job_identity_is_rejected_under_epoch_4(self) -> None:
        verify = _load_verify()
        first = hosted_document()["jobs"][0]
        value = {"jobs": [first, copy.deepcopy(first)]}
        with self.assertRaisesRegex(
            verify.CurrentAuditError,
            "CURRENT_AUDIT_HOSTED_JOB_DUPLICATE",
        ):
            self.verify(verify, value)

    def test_duplicate_or_unsorted_step_identity_is_rejected(self) -> None:
        verify = _load_verify()
        for number in (1, 0):
            with self.subTest(number=number):
                value = hosted_document()
                duplicate = copy.deepcopy(value["jobs"][0]["steps"][0])
                duplicate["number"] = number
                value["jobs"][0]["steps"].append(duplicate)
                with self.assertRaisesRegex(
                    verify.CurrentAuditError,
                    "CURRENT_AUDIT_HOSTED_(?:STEP_DUPLICATE|STEP_FAILED)",
                ):
                    self.verify(verify, value)

    def test_one_second_policy_does_not_widen_run_bounds(self) -> None:
        verify = _load_verify()
        for field, timestamp in (
            ("startedAt", "2026-07-23T16:06:22Z"),
            ("completedAt", "2026-07-23T16:12:31Z"),
        ):
            with self.subTest(field=field):
                value = hosted_document()
                step = value["jobs"][0]["steps"][0]
                step[field] = timestamp
                with self.assertRaisesRegex(
                    verify.CurrentAuditError,
                    "CURRENT_AUDIT_HOSTED_STEP_TIME",
                ):
                    self.verify(verify, value)

    def test_one_second_policy_does_not_accept_reversed_job_time(self) -> None:
        verify = _load_verify()
        value = hosted_document()
        value["jobs"][0]["completedAt"] = "2026-07-23T16:06:26Z"
        with self.assertRaisesRegex(
            verify.CurrentAuditError,
            "CURRENT_AUDIT_HOSTED_JOB_TIME",
        ):
            self.verify(verify, value)

    def test_one_second_policy_does_not_accept_reversed_step_time(self) -> None:
        verify = _load_verify()
        value = hosted_document()
        value["jobs"][0]["steps"][1]["completedAt"] = "2026-07-23T16:07:13Z"
        with self.assertRaisesRegex(
            verify.CurrentAuditError,
            "CURRENT_AUDIT_HOSTED_STEP_TIME",
        ):
            self.verify(verify, value)

    def test_one_second_policy_rejects_missing_or_extra_job_fields(self) -> None:
        verify = _load_verify()
        for mutation in ("missing", "extra"):
            with self.subTest(mutation=mutation):
                value = hosted_document()
                if mutation == "missing":
                    del value["jobs"][0]["url"]
                else:
                    value["jobs"][0]["unexpected"] = None
                with self.assertRaisesRegex(
                    verify.CurrentAuditError,
                    "CURRENT_AUDIT_HOSTED_JOB_FAILED",
                ):
                    self.verify(verify, value)

    def test_one_second_policy_rejects_missing_or_extra_step_fields(self) -> None:
        verify = _load_verify()
        for mutation in ("missing", "extra"):
            with self.subTest(mutation=mutation):
                value = hosted_document()
                if mutation == "missing":
                    del value["jobs"][0]["steps"][0]["name"]
                else:
                    value["jobs"][0]["steps"][0]["unexpected"] = None
                with self.assertRaisesRegex(
                    verify.CurrentAuditError,
                    "CURRENT_AUDIT_HOSTED_STEP_FAILED",
                ):
                    self.verify(verify, value)

    def test_one_second_policy_rejects_noncanonical_timestamps(self) -> None:
        verify = _load_verify()
        for timestamp in (
            "2026-07-23T18:06:26+02:00",
            "2026-07-23 16:06:26Z",
        ):
            with self.subTest(timestamp=timestamp):
                value = hosted_document()
                value["jobs"][0]["steps"][0]["startedAt"] = timestamp
                with self.assertRaises(verify.CurrentAuditError):
                    self.verify(verify, value)

    def test_anomaly_manifest_does_not_depend_on_input_job_order(self) -> None:
        verify = _load_verify()
        first = hosted_document()["jobs"][0]
        second = copy.deepcopy(first)
        second["databaseId"] = 89_262_381_499
        second["name"] = "lowest-id"
        forward = self.verify(verify, {"jobs": [first, second]})
        reverse = self.verify(verify, {"jobs": [second, first]})
        self.assertEqual(forward, reverse)

    def test_policy_value_is_not_coerced_from_numeric_or_text_types(self) -> None:
        verify = _load_verify()
        for invalid in ("1", b"1", None, object()):
            with self.subTest(type=type(invalid).__name__):
                with self.assertRaisesRegex(
                    verify.CurrentAuditError,
                    "CURRENT_AUDIT_HOSTED_STEP_SKEW_POLICY",
                ):
                    verify._verify_nested_jobs(
                        hosted_document(),
                        "framework_recovery_3.fixture",
                        lower=utc("2026-07-23T16:06:23Z"),
                        upper=utc("2026-07-23T16:12:30Z"),
                        job_boundary_skew_seconds=invalid,
                    )


class FrameworkRecovery3ParentReproductionTests(unittest.TestCase):
    """Bind the exact parent defect without changing captured timestamps."""

    def test_framework_recovery_3_expected_parent_anomaly_is_exact(
        self,
    ) -> None:
        verify = _load_verify()
        self.assertEqual(
            verify._framework_recovery_3_expected_parent_anomaly(),
            {
                "attempt": 1,
                "boundary": "STEP_STARTED_BEFORE_JOB",
                "difference_seconds": 1,
                "job_database_id": 89_262_381_501,
                "job_name": "macos-compile",
                "job_timestamp_utc": "2026-07-23T16:06:27Z",
                "run_id": 30_023_626_301,
                "step_name": "Set up job",
                "step_number": 1,
                "step_timestamp_utc": "2026-07-23T16:06:26Z",
                "workflow": "ci",
            },
        )

    def test_framework_recovery_3_parent_metadata_reproduces_strict_failure(
        self,
    ) -> None:
        verify = _load_verify()
        ordinary, attempt = parent_run_documents()
        ordinary_payload = b"o" * 17_765
        attempt_payload = b"a" * 17_866

        def digest(payload: bytes) -> str:
            if payload is ordinary_payload:
                return (
                    "829b5e001c00ca7958758c6834f0293ab1811c058ff84cf50030208faf6587b7"
                )
            if payload is attempt_payload:
                return (
                    "c5e3f8743ed7122a964dfe61d450e3d3d34fb118b825cb1759d74b0bfdb8d2f0"
                )
            return hashlib.sha256(payload).hexdigest()

        def canonical(value: Any, *, pretty: bool = False) -> bytes:
            self.assertTrue(pretty)
            return ordinary_payload if value is ordinary else attempt_payload

        with (
            mock.patch.object(verify, "_sha256", side_effect=digest),
            mock.patch.object(
                verify,
                "_load_json_bytes",
                side_effect=(ordinary, attempt),
            ),
            mock.patch.object(
                verify,
                "_canonical_json_bytes",
                side_effect=canonical,
            ),
        ):
            anomaly = verify._framework_recovery_3_validate_parent_metadata(
                ordinary_payload,
                attempt_payload,
            )
        self.assertEqual(
            anomaly,
            verify._framework_recovery_3_expected_parent_anomaly(),
        )

    def test_framework_recovery_3_parent_metadata_bytes_are_pinned(
        self,
    ) -> None:
        verify = _load_verify()
        mutations = (
            (b"o" * 17_764, b"a" * 17_866),
            (b"o" * 17_765, b"a" * 17_865),
            (b"o" * 17_765, b"a" * 17_866),
        )
        for index, (ordinary, attempt) in enumerate(mutations):
            with (
                self.subTest(index=index),
                self.assertRaisesRegex(
                    verify.CurrentAuditError,
                    "CURRENT_AUDIT_FRAMEWORK_RECOVERY_3_PARENT_METADATA_BYTES",
                ),
            ):
                verify._framework_recovery_3_validate_parent_metadata(
                    ordinary,
                    attempt,
                )

    def test_framework_recovery_3_parent_metadata_must_be_canonical(
        self,
    ) -> None:
        verify = _load_verify()
        ordinary, attempt = parent_run_documents()
        ordinary_payload = b"o" * 17_765
        attempt_payload = b"a" * 17_866

        def digest(payload: bytes) -> str:
            return (
                "829b5e001c00ca7958758c6834f0293ab1811c058ff84cf50030208faf6587b7"
                if payload is ordinary_payload
                else (
                    "c5e3f8743ed7122a964dfe61d450e3d3d34fb118b825cb1759d74b0bfdb8d2f0"
                )
            )

        with (
            mock.patch.object(verify, "_sha256", side_effect=digest),
            mock.patch.object(
                verify,
                "_load_json_bytes",
                side_effect=(ordinary, attempt),
            ),
            mock.patch.object(
                verify,
                "_canonical_json_bytes",
                return_value=b"not-the-retained-payload",
            ),
            self.assertRaisesRegex(
                verify.CurrentAuditError,
                ("CURRENT_AUDIT_FRAMEWORK_RECOVERY_3_PARENT_METADATA_IDENTITY"),
            ),
        ):
            verify._framework_recovery_3_validate_parent_metadata(
                ordinary_payload,
                attempt_payload,
            )

    def test_framework_recovery_3_parent_metadata_identity_mutations_fail(
        self,
    ) -> None:
        verify = _load_verify()
        ordinary_payload = b"o" * 17_765
        attempt_payload = b"a" * 17_866
        mutations = (
            ("ordinary", "databaseId", 1),
            ("attempt", "attempt", 2),
            ("ordinary", "headSha", "0" * 40),
            ("attempt", "headBranch", "other"),
            ("ordinary", "event", "workflow_dispatch"),
            ("attempt", "conclusion", "failure"),
            ("ordinary", "workflowName", "formal"),
        )

        def digest(payload: bytes) -> str:
            return (
                "829b5e001c00ca7958758c6834f0293ab1811c058ff84cf50030208faf6587b7"
                if payload is ordinary_payload
                else (
                    "c5e3f8743ed7122a964dfe61d450e3d3d34fb118b825cb1759d74b0bfdb8d2f0"
                )
            )

        for document_name, field, value in mutations:
            ordinary, attempt = parent_run_documents()
            selected = ordinary if document_name == "ordinary" else attempt
            selected[field] = value

            def canonical(
                document: Any,
                *,
                pretty: bool = False,
            ) -> bytes:
                self.assertTrue(pretty)
                return ordinary_payload if document is ordinary else attempt_payload

            with (
                self.subTest(document=document_name, field=field),
                mock.patch.object(verify, "_sha256", side_effect=digest),
                mock.patch.object(
                    verify,
                    "_load_json_bytes",
                    side_effect=(ordinary, attempt),
                ),
                mock.patch.object(
                    verify,
                    "_canonical_json_bytes",
                    side_effect=canonical,
                ),
                self.assertRaisesRegex(
                    verify.CurrentAuditError,
                    ("CURRENT_AUDIT_FRAMEWORK_RECOVERY_3_PARENT_METADATA_IDENTITY"),
                ),
            ):
                verify._framework_recovery_3_validate_parent_metadata(
                    ordinary_payload,
                    attempt_payload,
                )

    def test_framework_recovery_3_parent_metadata_requires_exact_strict_error(
        self,
    ) -> None:
        verify = _load_verify()
        ordinary, attempt = parent_run_documents()
        ordinary_payload = b"o" * 17_765
        attempt_payload = b"a" * 17_866

        def digest(payload: bytes) -> str:
            return (
                "829b5e001c00ca7958758c6834f0293ab1811c058ff84cf50030208faf6587b7"
                if payload is ordinary_payload
                else (
                    "c5e3f8743ed7122a964dfe61d450e3d3d34fb118b825cb1759d74b0bfdb8d2f0"
                )
            )

        def canonical(
            document: Any,
            *,
            pretty: bool = False,
        ) -> bytes:
            self.assertTrue(pretty)
            return ordinary_payload if document is ordinary else attempt_payload

        for failure in (
            None,
            verify.CurrentAuditError("CURRENT_AUDIT_HOSTED_JOB_TIME:wrong"),
        ):
            side_effect = ([],) if failure is None else (failure,)
            expected_error = (
                "PARENT_STRICT_ACCEPTED" if failure is None else "PARENT_STRICT_ERROR"
            )
            with (
                self.subTest(expected_error=expected_error),
                mock.patch.object(verify, "_sha256", side_effect=digest),
                mock.patch.object(
                    verify,
                    "_load_json_bytes",
                    side_effect=(ordinary, attempt),
                ),
                mock.patch.object(
                    verify,
                    "_canonical_json_bytes",
                    side_effect=canonical,
                ),
                mock.patch.object(
                    verify,
                    "_verify_nested_jobs",
                    side_effect=side_effect,
                ),
                self.assertRaisesRegex(
                    verify.CurrentAuditError,
                    expected_error,
                ),
            ):
                verify._framework_recovery_3_validate_parent_metadata(
                    ordinary_payload,
                    attempt_payload,
                )

    def test_framework_recovery_3_parent_metadata_requires_matching_manifests(
        self,
    ) -> None:
        verify = _load_verify()
        ordinary, attempt = parent_run_documents()
        ordinary_payload = b"o" * 17_765
        attempt_payload = b"a" * 17_866
        raw_anomaly = {
            key: value
            for key, value in (
                verify._framework_recovery_3_expected_parent_anomaly().items()
            )
            if key not in {"attempt", "run_id", "workflow"}
        }

        def digest(payload: bytes) -> str:
            return (
                "829b5e001c00ca7958758c6834f0293ab1811c058ff84cf50030208faf6587b7"
                if payload is ordinary_payload
                else (
                    "c5e3f8743ed7122a964dfe61d450e3d3d34fb118b825cb1759d74b0bfdb8d2f0"
                )
            )

        def canonical(
            document: Any,
            *,
            pretty: bool = False,
        ) -> bytes:
            self.assertTrue(pretty)
            return ordinary_payload if document is ordinary else attempt_payload

        with (
            mock.patch.object(verify, "_sha256", side_effect=digest),
            mock.patch.object(
                verify,
                "_load_json_bytes",
                side_effect=(ordinary, attempt),
            ),
            mock.patch.object(
                verify,
                "_canonical_json_bytes",
                side_effect=canonical,
            ),
            mock.patch.object(
                verify,
                "_verify_nested_jobs",
                side_effect=(
                    verify.CurrentAuditError(
                        (
                            "CURRENT_AUDIT_HOSTED_STEP_TIME:"
                            "framework_recovery_3.parent_strict"
                        )
                    ),
                    [raw_anomaly],
                    [],
                ),
            ),
            self.assertRaisesRegex(
                verify.CurrentAuditError,
                "PARENT_ANOMALY_MISMATCH",
            ),
        ):
            verify._framework_recovery_3_validate_parent_metadata(
                ordinary_payload,
                attempt_payload,
            )

    def test_framework_recovery_3_parent_reproduction_log_is_exact(
        self,
    ) -> None:
        verify = _load_verify()
        payload = verify._framework_recovery_3_parent_reproduction_log()
        self.assertEqual(payload.count(b"FR-0003-PARENT-REPRODUCTION\n"), 1)
        self.assertEqual(
            payload.count((b"strict_policy_result=CURRENT_AUDIT_HOSTED_STEP_TIME\n")),
            1,
        )
        self.assertEqual(payload.count(b"raw_timestamps_changed=false\n"), 1)
        self.assertEqual(
            payload.count(b"result=PARENT_VERIFIER_DEFECT_REPRODUCED\n"),
            1,
        )
        self.assertNotIn(b"timestamp_rewrite", payload)

    def test_framework_recovery_3_parent_reproduction_record_is_bound(
        self,
    ) -> None:
        verify = _load_verify()
        repair_commit = "a" * 40
        qualification_commit = "b" * 40
        log = verify._framework_recovery_3_parent_reproduction_log()
        with (
            mock.patch.object(
                verify,
                "_git_file",
                return_value=b"compressed",
            ),
            mock.patch.object(
                verify,
                "_decompress_unbound_gzip",
                return_value=log,
            ),
            mock.patch.object(
                verify,
                "_commit_regular_file_record",
                side_effect=commit_file_record,
            ),
        ):
            record = verify._framework_recovery_3_expected_parent_reproduction(
                Path("."),
                repair_commit,
                qualification_commit,
                started_at_utc="2026-07-24T00:00:00Z",
                completed_at_utc="2026-07-24T00:00:01Z",
            )
        self.assertEqual(record["parent_commit"], PARENT_COMMIT)
        self.assertEqual(record["parent_tree"], PARENT_TREE)
        self.assertEqual(record["repair_commit"], repair_commit)
        self.assertEqual(
            record["strict_parent_error"],
            "CURRENT_AUDIT_HOSTED_STEP_TIME",
        )
        self.assertFalse(record["raw_timestamps_changed"])
        self.assertEqual(
            record["result"],
            "PARENT_VERIFIER_DEFECT_REPRODUCED",
        )
        self.assertEqual(
            record["raw_log"]["uncompressed"]["sha256"],
            hashlib.sha256(log).hexdigest(),
        )

    def test_framework_recovery_3_parent_reproduction_validator_is_exact(
        self,
    ) -> None:
        verify = _load_verify()
        repair_commit = "a" * 40
        qualification_commit = "b" * 40
        log = verify._framework_recovery_3_parent_reproduction_log()
        value = {
            "schema_version": "1.0.0",
            "evidence_id": "FR-0003-E01",
            "kind": "DETERMINISTIC_PARENT_DEFECT_REPRODUCTION",
            "parent_commit": PARENT_COMMIT,
            "parent_tree": PARENT_TREE,
            "repair_commit": repair_commit,
            "validator": (
                "tools/release/verify-current-audit.py::"
                "_framework_recovery_3_validate_parent_metadata"
            ),
            "strict_parent_error": "CURRENT_AUDIT_HOSTED_STEP_TIME",
            "anomaly": verify._framework_recovery_3_expected_parent_anomaly(),
            "raw_timestamps_changed": False,
            "raw_log": {
                "file": {"path": "reproduction.log.gz"},
                "uncompressed": {
                    "bytes": len(log),
                    "lines": len(log.splitlines()),
                    "sha256": hashlib.sha256(log).hexdigest(),
                },
            },
            "started_at_utc": "2026-07-24T00:00:01Z",
            "completed_at_utc": "2026-07-24T00:00:02Z",
            "result": "PARENT_VERIFIER_DEFECT_REPRODUCED",
        }
        evidence = {
            "files": [None, value["raw_log"]["file"]],
            "uncompressed": [None, value["raw_log"]["uncompressed"]],
        }

        def validate(candidate: dict[str, Any], observed_log: bytes) -> None:
            with (
                mock.patch.object(
                    verify,
                    "_commit_datetime",
                    side_effect=(
                        utc("2026-07-24T00:00:00Z"),
                        utc("2026-07-24T00:00:03Z"),
                    ),
                ),
                mock.patch.object(
                    verify,
                    "_framework_recovery_3_expected_parent_reproduction",
                    return_value=value,
                ),
                mock.patch.object(
                    verify,
                    "_git_file",
                    return_value=b"compressed",
                ),
                mock.patch.object(
                    verify,
                    "_decompress_unbound_gzip",
                    return_value=observed_log,
                ),
            ):
                verify._framework_recovery_3_validate_parent_reproduction(
                    Path("."),
                    repair_commit,
                    qualification_commit,
                    candidate,
                    evidence_record=evidence,
                )

        validate(value, log)
        mutations = []
        candidate = copy.deepcopy(value)
        candidate["raw_timestamps_changed"] = True
        mutations.append(candidate)
        candidate = copy.deepcopy(value)
        candidate["anomaly"]["difference_seconds"] = 2
        mutations.append(candidate)
        candidate = copy.deepcopy(value)
        candidate["unexpected"] = True
        mutations.append(candidate)
        for index, mutation in enumerate(mutations):
            with (
                self.subTest(index=index),
                self.assertRaises(verify.CurrentAuditError),
            ):
                validate(mutation, log)
        with self.assertRaisesRegex(
            verify.CurrentAuditError,
            "CURRENT_AUDIT_FRAMEWORK_RECOVERY_3_PARENT_REPRODUCTION_LOG",
        ):
            validate(value, log + b"changed\n")


class FrameworkRecovery3StaticContractTests(unittest.TestCase):
    """Freeze the candidate epoch, path scopes, and warning-strict gate."""

    def test_framework_recovery_3_identity_constants_are_exact(self) -> None:
        verify = _load_verify()
        self.assertEqual(
            verify.FRAMEWORK_RECOVERY_3_PARENT,
            "0fc0516dc951f69fdafaaf31d9a72a0933515e93",
        )
        self.assertEqual(
            verify.FRAMEWORK_RECOVERY_3_PARENT_TREE,
            "b5f8c0084b450392ba3fadb1da98b7cd05360210",
        )
        self.assertEqual(verify.FRAMEWORK_RECOVERY_3_ID, "FR-0003")
        self.assertEqual(
            verify.FRAMEWORK_RECOVERY_3_SUBJECT,
            "release: repair epoch-4 audit validation",
        )
        self.assertEqual(
            verify.FRAMEWORK_RECOVERY_3_QUALIFICATION_SUBJECT,
            "release: qualify epoch-4 audit validation",
        )
        self.assertEqual(
            verify.FRAMEWORK_RECOVERY_3_ACTIVATION_SUBJECT,
            "release: activate epoch-4 audit validation",
        )

    def test_framework_recovery_3_repair_scope_is_exact(self) -> None:
        verify = _load_verify()
        self.assertEqual(
            verify.FRAMEWORK_RECOVERY_3_CORE_PATHS,
            (
                "tools/release/verify-current-audit.py",
                "tools/release/test_verify_current_audit_fr_0003.py",
                "tools/release/current-audit-gate.sh",
                "tools/release/current-audit-resource-profile.py",
                "tools/release/test_current_audit_resource_profile.py",
            ),
        )
        self.assertEqual(
            verify.FRAMEWORK_RECOVERY_3_REPAIR_STATUSES,
            {
                (
                    "release/0.9.0/current-head/closures/"
                    "framework-recovery/FR-0003-plan.json"
                ): "A",
                "tools/release/current-audit-gate.sh": "M",
                "tools/release/current-audit-resource-profile.py": "M",
                "tools/release/test_current_audit_resource_profile.py": "M",
                "tools/release/test_verify_current_audit_fr_0003.py": "A",
                "tools/release/verify-current-audit.py": "M",
            },
        )

    def test_framework_recovery_3_evidence_layout_is_exact(self) -> None:
        verify = _load_verify()
        qualification_paths = [
            path
            for requirement in verify.FRAMEWORK_RECOVERY_3_QUALIFICATION_REQUIREMENTS
            for path in requirement["paths"]
        ]
        activation_paths = [
            path
            for requirement in verify.FRAMEWORK_RECOVERY_3_ACTIVATION_REQUIREMENTS
            for path in requirement["paths"]
        ]
        self.assertEqual(
            [
                item["id"]
                for item in verify.FRAMEWORK_RECOVERY_3_QUALIFICATION_REQUIREMENTS
            ],
            [
                "FR-0003-E01",
                "FR-0003-E02",
                "FR-0003-E03",
                "FR-0003-E04",
                "FR-0003-E05",
                "FR-0003-R01",
                "FR-0003-R02",
            ],
        )
        self.assertEqual(
            [
                item["id"]
                for item in verify.FRAMEWORK_RECOVERY_3_ACTIVATION_REQUIREMENTS
            ],
            ["FR-0003-A01", "FR-0003-A02"],
        )
        self.assertEqual(len(qualification_paths), 14)
        self.assertEqual(len(activation_paths), 6)
        self.assertEqual(len(set(qualification_paths)), 14)
        self.assertEqual(len(set(activation_paths)), 6)
        self.assertEqual(
            len(verify.FRAMEWORK_RECOVERY_3_QUALIFICATION_STATUSES),
            15,
        )
        self.assertEqual(
            len(verify.FRAMEWORK_RECOVERY_3_ACTIVATION_STATUSES),
            7,
        )
        self.assertFalse(set(qualification_paths) & set(activation_paths))
        self.assertFalse(
            any(
                len(item["paths"]) != len(item["max_bytes"]) or "path" in item
                for item in (
                    *verify.FRAMEWORK_RECOVERY_3_QUALIFICATION_REQUIREMENTS,
                    *verify.FRAMEWORK_RECOVERY_3_ACTIVATION_REQUIREMENTS,
                )
            )
        )

    def test_framework_recovery_3_evidence_paths_are_bounded_and_namespaced(
        self,
    ) -> None:
        verify = _load_verify()
        requirements = (
            *verify.FRAMEWORK_RECOVERY_3_QUALIFICATION_REQUIREMENTS,
            *verify.FRAMEWORK_RECOVERY_3_ACTIVATION_REQUIREMENTS,
        )
        paths = [path for requirement in requirements for path in requirement["paths"]]
        bounds = [
            bound for requirement in requirements for bound in requirement["max_bytes"]
        ]
        self.assertTrue(
            all(
                path.startswith(
                    ("release/0.9.0/current-head/evidence/framework-recovery-fr-0003-")
                )
                or path.startswith(
                    ("release/0.9.0/current-head/reviews/framework-recovery-fr-0003-")
                )
                for path in paths
            )
        )
        self.assertTrue(
            all(
                type(bound) is int and 0 < bound <= verify.MAX_LOG_BYTES
                for bound in bounds
            )
        )
        self.assertFalse(any("-metadata" in path for path in paths))

    def test_framework_recovery_3_prior_records_are_preserved(self) -> None:
        verify = _load_verify()
        preserved = set(verify.FRAMEWORK_RECOVERY_3_PRESERVED_PATHS)
        self.assertTrue(set(verify.FRAMEWORK_RECOVERY_2_PRESERVED_PATHS) <= preserved)
        self.assertIn(verify.FRAMEWORK_RECOVERY_2_PLAN_PATH, preserved)
        self.assertIn(verify.FRAMEWORK_RECOVERY_2_TEST_PATH, preserved)
        self.assertNotIn(
            verify.FRAMEWORK_RECOVERY_2_QUALIFICATION_PATH,
            preserved,
        )
        self.assertNotIn(
            verify.FRAMEWORK_RECOVERY_2_ACTIVATION_PATH,
            preserved,
        )

    def test_framework_recovery_3_gate_order_and_warning_policy_are_exact(
        self,
    ) -> None:
        verify = _load_verify()
        expected = verify._framework_recovery_3_expected_gate_payload()
        observed = Path(__file__).with_name("current-audit-gate.sh").read_bytes()
        self.assertEqual(observed, expected)
        lines = observed.decode("utf-8").splitlines()
        commands = [line for line in lines if line.startswith('"$PYTHON3"')]
        self.assertEqual(
            commands,
            [
                '"$PYTHON3" -I tools/release/test_verify_current_audit.py',
                ('"$PYTHON3" -B -I -W error::ResourceWarning \\'),
                (
                    '"$PYTHON3" -I -W error '
                    "tools/release/test_verify_current_audit_fr_0003.py"
                ),
                (
                    '"$PYTHON3" -I -W error '
                    "tools/release/test_current_audit_resource_profile.py"
                ),
                '"$PYTHON3" -I tools/release/verify-current-audit.py',
            ],
        )
        mktemp = 'FR2_COMPAT_DIR="$(/usr/bin/mktemp -d /tmp/haldir-fr2-gate.XXXXXX)"'
        self.assertIn(mktemp, lines)
        self.assertIn(
            "  /usr/bin/git cat-file blob 5255d9b4ff685231cf86bd30368a71f26e2d69fa \\",
            lines,
        )
        self.assertIn("  -i \\", lines)
        self.assertIn("  GIT_NO_REPLACE_OBJECTS=1 \\", lines)
        self.assertIn("  PATH=/usr/bin:/bin \\", lines)
        self.assertIn("  builtin trap - EXIT HUP INT TERM", lines)
        self.assertLess(
            lines.index("builtin trap cleanup_fr2_compat EXIT"),
            lines.index(mktemp),
        )
        self.assertLess(
            lines.index("builtin trap 'builtin exit 129' HUP"),
            lines.index(mktemp),
        )
        self.assertLess(
            lines.index("builtin trap 'builtin exit 130' INT"),
            lines.index(mktemp),
        )
        self.assertLess(
            lines.index("builtin trap 'builtin exit 143' TERM"),
            lines.index(mktemp),
        )
        self.assertIn(
            '  "$FR2_COMPAT_DIR/test_verify_current_audit_fr_0002.py"',
            lines,
        )
        root = Path(__file__).resolve().parents[2]
        self.assertEqual(
            verify._git_file(
                root,
                verify.FRAMEWORK_RECOVERY_3_PARENT,
                "tools/release/current-audit-gate.sh",
            ),
            verify._framework_recovery_2_expected_gate_payload(),
        )

    def test_framework_recovery_3_test_source_rejects_dynamic_bypasses(
        self,
    ) -> None:
        verify = _load_verify()
        source = Path(__file__).read_bytes()
        mutations = (
            source.replace(
                b'"""Test the FR-0003 hosted-time boundary repair."""',
                b'"""Different contract."""',
                1,
            ),
            source.replace(
                b'\nif __name__ == "__main__":\n    unittest.main()\n',
                b'\nif __name__ != "__main__":\n    unittest.main()\n',
                1,
            ),
            source
            + (
                b'\n@unittest.skip("bypass")\n'
                b"def test_framework_recovery_3_bypassed():\n"
                b"    raise AssertionError\n"
            ),
            source
            + (
                b"\ndef framework_recovery_3_override():\n"
                b'    setattr(unittest, "TestCase", object)\n'
            ),
        )
        self.assertTrue(all(mutation != source for mutation in mutations))
        for index, mutation in enumerate(mutations):
            with (
                self.subTest(index=index),
                self.assertRaises(verify.CurrentAuditError),
            ):
                verify._framework_recovery_3_validate_test_source(
                    mutation,
                    verify.FRAMEWORK_RECOVERY_3_TEST_PATH,
                )

    def test_framework_recovery_3_required_test_ids_match_discovery(
        self,
    ) -> None:
        verify = _load_verify()
        payload = Path(__file__).read_bytes()
        identifiers = verify._discover_unittest_test_ids(
            payload,
            verify.FRAMEWORK_RECOVERY_3_TEST_PATH,
            strict_runtime=True,
        )
        self.assertEqual(len(identifiers), len(set(identifiers)))
        self.assertEqual(
            set(identifiers),
            verify.FRAMEWORK_RECOVERY_3_REQUIRED_TEST_IDS,
        )

    def test_framework_recovery_3_test_contract_preserves_all_prior_suites(
        self,
    ) -> None:
        verify = _load_verify()
        repo = Path(__file__).resolve().parents[2]
        repair_commit = "a" * 40
        new_payload = Path(__file__).read_bytes()
        resource_payload = Path(__file__).with_name(
            "test_current_audit_resource_profile.py"
        ).read_bytes()
        original_git_file = verify._git_file
        identifiers = verify._discover_unittest_test_ids(
            new_payload,
            verify.FRAMEWORK_RECOVERY_3_TEST_PATH,
            strict_runtime=True,
        )

        def git_file(_repo: Path, commit: str, path: str) -> bytes:
            if commit == repair_commit:
                if path == verify.FRAMEWORK_RECOVERY_3_TEST_PATH:
                    return new_payload
                if path == verify.FRAMEWORK_RECOVERY_3_RESOURCE_TEST_PATH:
                    return resource_payload
                if path == "tools/release/current-audit-gate.sh":
                    return verify._framework_recovery_3_expected_gate_payload()
                return original_git_file(
                    repo,
                    verify.FRAMEWORK_RECOVERY_3_PARENT,
                    path,
                )
            return original_git_file(_repo, commit, path)

        with (
            mock.patch.object(verify, "_git_file", side_effect=git_file),
            mock.patch.object(
                verify,
                "_commit_regular_file_record",
                side_effect=commit_file_record,
            ),
            mock.patch.object(
                verify,
                "FRAMEWORK_RECOVERY_3_TEST_SHA256",
                hashlib.sha256(new_payload).hexdigest(),
            ),
            mock.patch.object(
                verify,
                "FRAMEWORK_RECOVERY_3_TEST_BYTES",
                len(new_payload),
            ),
            mock.patch.object(
                verify,
                "FRAMEWORK_RECOVERY_3_REQUIRED_TEST_IDS",
                set(identifiers),
            ),
            mock.patch.object(
                verify,
                "FRAMEWORK_RECOVERY_3_RESOURCE_TEST_SHA256",
                hashlib.sha256(resource_payload).hexdigest(),
            ),
            mock.patch.object(
                verify,
                "FRAMEWORK_RECOVERY_3_RESOURCE_TEST_BYTES",
                len(resource_payload),
            ),
        ):
            contract = verify._framework_recovery_3_test_contract(
                repo,
                repair_commit,
            )
        self.assertEqual(contract["legacy_count"], 163)
        self.assertEqual(contract["fr_0002_count"], 78)
        self.assertEqual(contract["fr_0003_count"], len(identifiers))
        self.assertEqual(contract["resource_count"], 26)
        self.assertTrue(contract["resource_test_modified_for_materialization_limits"])
        self.assertTrue(contract["prior_test_bytes_preserved"])

    def test_framework_recovery_3_test_contract_rejects_prior_test_drift(
        self,
    ) -> None:
        verify = _load_verify()
        repo = Path(__file__).resolve().parents[2]
        original_git_file = verify._git_file
        repair_commit = "a" * 40

        def git_file(_repo: Path, commit: str, path: str) -> bytes:
            payload = original_git_file(
                repo,
                verify.FRAMEWORK_RECOVERY_3_PARENT,
                path,
            )
            if (
                commit == repair_commit
                and path == verify.FRAMEWORK_RECOVERY_2_TEST_PATH
            ):
                return payload + b"\n"
            return payload

        with (
            mock.patch.object(verify, "_git_file", side_effect=git_file),
            self.assertRaisesRegex(
                verify.CurrentAuditError,
                "CURRENT_AUDIT_FRAMEWORK_RECOVERY_3_PRIOR_TEST_DRIFT",
            ),
        ):
            verify._framework_recovery_3_test_contract(repo, repair_commit)

        resource_payload = (
            repo / verify.FRAMEWORK_RECOVERY_3_RESOURCE_TEST_PATH
        ).read_bytes()

        def resource_drift(
            _repo: Path,
            commit: str,
            path: str,
        ) -> bytes:
            if (
                commit == repair_commit
                and path == verify.FRAMEWORK_RECOVERY_3_RESOURCE_TEST_PATH
            ):
                return resource_payload + b"\n"
            return original_git_file(
                repo,
                verify.FRAMEWORK_RECOVERY_3_PARENT,
                path,
            )

        with (
            mock.patch.object(verify, "_git_file", side_effect=resource_drift),
            self.assertRaisesRegex(
                verify.CurrentAuditError,
                "CURRENT_AUDIT_FRAMEWORK_RECOVERY_3_RESOURCE_TEST_BYTES_INVALID",
            ),
        ):
            verify._framework_recovery_3_test_contract(repo, repair_commit)

    def test_framework_recovery_3_code_diff_excludes_its_own_commit(
        self,
    ) -> None:
        verify = _load_verify()
        with mock.patch.object(
            verify,
            "_git",
            side_effect=(b"patch\n", b"M\0path\0", b"1\t0\tpath\0"),
        ) as git:
            value = verify._framework_recovery_3_code_diff(
                Path("."),
                "a" * 40,
            )
        self.assertEqual(git.call_count, 3)
        self.assertEqual(value["base"], verify.FRAMEWORK_RECOVERY_3_PARENT)
        self.assertEqual(
            value["target"],
            "SIGNED_COMMIT_CONTAINING_THIS_PLAN",
        )
        self.assertNotIn(
            "a" * 40,
            verify._canonical_json_bytes(value).decode("utf-8"),
        )
        self.assertEqual(
            value["paths"],
            list(verify.FRAMEWORK_RECOVERY_3_CORE_PATHS),
        )

    def test_framework_recovery_3_registered_container_materialization_selector_is_exact(
        self,
    ) -> None:
        verify = _load_verify()
        repo = Path(__file__).resolve().parents[2]
        registry = verify._load_json_bytes(
            (repo / verify.SUCCESSOR_REGISTRY_PATH).read_bytes(),
            "fr_0003.materialization.registry",
        )
        registration = next(
            item
            for item in registry["registrations"]
            if item["task_id"] == "CH-T001" and item["epoch"] == 2
        )
        exception = verify.FRAMEWORK_RECOVERY_REGISTERED_EXECUTION_EXCEPTION
        lifecycle = {
            "freeze_commit": exception["freeze_commit"],
            "implementation_commit": exception["implementation_commit"],
            "qualification_commit": exception["qualification_commit"],
            "activation_commit": exception["activation_commit"],
        }
        self.assertTrue(
            verify._registered_snapshot_materialization_applies(
                registration,
                **lifecycle,
            )
        )
        mutations: list[tuple[dict[str, Any], dict[str, str]]] = []

        def leaves(
            value: object,
            prefix: tuple[str, ...] = (),
        ):
            if isinstance(value, dict):
                for key in sorted(value):
                    yield from leaves(value[key], (*prefix, key))
            else:
                yield prefix

        for path in leaves(registration):
            candidate = copy.deepcopy(registration)
            target = candidate
            for component in path[:-1]:
                target = target[component]
            original = target[path[-1]]
            target[path[-1]] = (
                original + 1
                if type(original) is int
                else f"{original}-different"
            )
            mutations.append((candidate, lifecycle))
        for field in lifecycle:
            candidate_lifecycle = dict(lifecycle)
            candidate_lifecycle[field] = "0" * 40
            mutations.append((registration, candidate_lifecycle))
        for index, (candidate, candidate_lifecycle) in enumerate(mutations):
            with self.subTest(index=index):
                self.assertFalse(
                    verify._registered_snapshot_materialization_applies(
                        candidate,
                        **candidate_lifecycle,
                    )
                )

        module_tree = parse(
            Path(__file__).with_name("verify-current-audit.py").read_bytes()
        )
        runner = next(
            node
            for node in module_tree.body
            if isinstance(node, FunctionDef)
            and node.name == "_run_registered_verifier_v2"
        )
        calls = [node for node in walk(runner) if isinstance(node, Call)]
        selector_calls = [
            node
            for node in calls
            if isinstance(node.func, Name)
            and node.func.id == "_registered_snapshot_materialization_applies"
        ]
        container_calls = [
            node
            for node in calls
            if isinstance(node.func, Name)
            and node.func.id == "_run_registered_container"
        ]
        self.assertEqual(len(selector_calls), 1)
        self.assertEqual(len(container_calls), 2)
        labels = {
            next(
                keyword.value.value
                for keyword in call.keywords
                if keyword.arg == "label"
                and isinstance(keyword.value, Constant)
            ): call
            for call in container_calls
        }
        self.assertEqual(set(labels), {"TESTS", "VERIFIER"})
        self.assertLess(selector_calls[0].lineno, labels["TESTS"].lineno)
        image_calls = [
            node
            for node in calls
            if isinstance(node.func, Name)
            and node.func.id == "_registered_image_state"
        ]
        live_state_calls = [
            node
            for node in calls
            if isinstance(node.func, Name)
            and node.func.id == "_repository_execution_state"
        ]
        clone_calls = [
            node
            for node in calls
            if isinstance(node.func, Name)
            and node.func.id == "_git_command"
            and node.args
            and isinstance(node.args[0], Constant)
            and node.args[0].value == "clone"
        ]
        self.assertEqual(len(image_calls), 2)
        self.assertGreaterEqual(len(live_state_calls), 3)
        self.assertEqual(len(clone_calls), 1)
        self.assertLess(selector_calls[0].lineno, image_calls[0].lineno)
        self.assertLess(image_calls[0].lineno, live_state_calls[0].lineno)
        self.assertLess(live_state_calls[0].lineno, clone_calls[0].lineno)
        for call in container_calls:
            materialization = next(
                keyword.value
                for keyword in call.keywords
                if keyword.arg == "materialize_snapshot"
            )
            self.assertIsInstance(materialization, Name)
            self.assertEqual(materialization.id, "materialize_snapshot")
            setup = next(
                keyword.value
                for keyword in call.keywords
                if keyword.arg == "materialization_setup_seconds"
            )
            self.assertIsInstance(setup, verify.ast.IfExp)
            self.assertIsInstance(setup.test, Name)
            self.assertEqual(setup.test.id, "materialize_snapshot")
            self.assertIsInstance(setup.body, Name)
            self.assertEqual(
                setup.body.id,
                "FRAMEWORK_RECOVERY_3_MATERIALIZATION_SETUP_SECONDS",
            )
            self.assertIsInstance(setup.orelse, Constant)
            self.assertIsNone(setup.orelse.value)

    def test_framework_recovery_3_registered_container_materialization_receipt_is_exact(
        self,
    ) -> None:
        verify = _load_verify()
        plain = b"plain\n"
        executable = b"#!/bin/sh\nexit 0\n"
        snapshot = (
            ("directory", "", 0o755, 501, 20, 3, 0, 11, 12),
            ("directory", "bin", 0o755, 501, 20, 2, 0, 11, 12),
            (
                "file",
                "README.md",
                0o644,
                501,
                20,
                1,
                len(plain),
                11,
                12,
                hashlib.sha256(plain).hexdigest(),
            ),
            (
                "file",
                "bin/run",
                0o755,
                501,
                20,
                1,
                len(executable),
                11,
                12,
                hashlib.sha256(executable).hexdigest(),
            ),
        )
        aggregate = hashlib.sha256()
        rows = (
            (b"D", b"", 0, 0, b""),
            (b"D", b"bin", 0, 0, b""),
            (
                b"F",
                b"README.md",
                0,
                len(plain),
                hashlib.sha256(plain).digest(),
            ),
            (
                b"F",
                b"bin/run",
                1,
                len(executable),
                hashlib.sha256(executable).digest(),
            ),
        )
        for kind, relative, executable_bit, size, digest in sorted(rows):
            aggregate.update(kind)
            aggregate.update(len(relative).to_bytes(8, "big"))
            aggregate.update(relative)
            aggregate.update(bytes([executable_bit]))
            if kind == b"F":
                aggregate.update(size.to_bytes(8, "big"))
                aggregate.update(digest)
        expected = {
            "algorithm": "SHA256-FRAMED-PATH-EXECUTABLE-CONTENT-V1",
            "bytes": len(plain) + len(executable),
            "entries": 4,
            "files": 2,
            "kind": "HALDIR_REGISTERED_MATERIALIZED_SNAPSHOT",
            "schema_version": "1.0.0",
            "sha256": aggregate.hexdigest(),
        }
        self.assertEqual(
            verify._registered_snapshot_materialization_receipt(snapshot),
            expected,
        )
        self.assertEqual(
            verify._canonical_json_bytes(expected),
            (
                verify.json.dumps(
                    expected,
                    ensure_ascii=True,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode("ascii"),
        )

        def directory_record(relative: str) -> tuple[Any, ...]:
            return ("directory", relative, 0o755, 501, 20, 2, 0, 11, 12)

        def file_record(relative: str, size: int) -> tuple[Any, ...]:
            return (
                "file",
                relative,
                0o644,
                501,
                20,
                1,
                size,
                11,
                12,
                hashlib.sha256(relative.encode("utf-8")).hexdigest(),
            )

        depth_parts = [f"d{index}" for index in range(verify.MAX_JSON_DEPTH)]
        maximum_depth_snapshot = (
            directory_record(""),
            *(
                directory_record("/".join(depth_parts[:index]))
                for index in range(1, len(depth_parts) + 1)
            ),
            file_record("/".join((*depth_parts, "leaf")), 0),
        )
        maximum_depth_receipt = (
            verify._registered_snapshot_materialization_receipt(
                maximum_depth_snapshot
            )
        )
        self.assertEqual(maximum_depth_receipt["entries"], verify.MAX_JSON_DEPTH + 2)
        self.assertEqual(maximum_depth_receipt["files"], 1)

        file_limit = verify.MAX_REGISTERED_MATERIALIZED_FILE_BYTES
        total_limit = verify.MAX_REGISTERED_MATERIALIZED_TOTAL_BYTES
        file_exact_snapshot = (
            directory_record(""),
            file_record("a", file_limit),
        )
        self.assertEqual(
            verify._registered_snapshot_materialization_receipt(
                file_exact_snapshot
            )["bytes"],
            file_limit,
        )
        total_exact_snapshot = (
            directory_record(""),
            file_record("a", total_limit // 2),
            file_record("b", total_limit - total_limit // 2),
        )
        self.assertEqual(
            verify._registered_snapshot_materialization_receipt(
                total_exact_snapshot
            )["bytes"],
            total_limit,
        )
        too_deep_snapshot = maximum_depth_snapshot[:-1] + (
            directory_record("/".join((*depth_parts, "too-deep"))),
        )
        total_over_snapshot = total_exact_snapshot + (file_record("c", 1),)
        invalid_state = [
            list(snapshot),
            (),
            snapshot + (snapshot[-1],),
            snapshot[:1] + snapshot[2:],
            snapshot[:-1] + (snapshot[-1][:-1],),
            snapshot[:-1]
            + (
                (
                    *snapshot[-1][:5],
                    2,
                    *snapshot[-1][6:],
                ),
            ),
            (
                (snapshot[0][0], snapshot[0][1], 0o4755, *snapshot[0][3:]),
                *snapshot[1:],
            ),
            too_deep_snapshot,
        ]
        for index, candidate in enumerate(invalid_state):
            with (
                self.subTest(index=index),
                self.assertRaisesRegex(
                    verify.CurrentAuditError,
                    "CURRENT_AUDIT_REGISTERED_MATERIALIZATION_STATE",
                ),
            ):
                verify._registered_snapshot_materialization_receipt(candidate)
        file_over_snapshot = snapshot[:-1] + (
            (
                *snapshot[-1][:6],
                verify.MAX_REGISTERED_MATERIALIZED_FILE_BYTES + 1,
                *snapshot[-1][7:],
            ),
        )
        for candidate, error_code in (
            (
                file_over_snapshot,
                "CURRENT_AUDIT_REGISTERED_MATERIALIZATION_FILE_BOUND",
            ),
            (
                total_over_snapshot,
                "CURRENT_AUDIT_REGISTERED_MATERIALIZATION_TOTAL_BOUND",
            ),
        ):
            with self.assertRaisesRegex(
                verify.CurrentAuditError,
                error_code,
            ):
                verify._registered_snapshot_materialization_receipt(candidate)

        for special_kind in ("symlink", "fifo", "socket"):
            with (
                self.subTest(special_kind=special_kind),
                verify.tempfile.TemporaryDirectory(
                    prefix=f"fr-0003-{special_kind}-"
                ) as raw,
            ):
                special_root = Path(raw)
                special_path = special_root / "special"
                open_socket = None
                if special_kind == "symlink":
                    special_path.symlink_to("missing")
                elif special_kind == "fifo":
                    verify.os.mkfifo(special_path)
                else:
                    open_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    open_socket.bind(str(special_path))
                try:
                    with self.assertRaisesRegex(
                        verify.CurrentAuditError,
                        "CURRENT_AUDIT_FILESYSTEM_STATE_TYPE",
                    ):
                        verify._bounded_filesystem_state(
                            special_root,
                            f"fr_0003.{special_kind}",
                        )
                finally:
                    if open_socket is not None:
                        open_socket.close()

        with verify.tempfile.TemporaryDirectory(prefix="fr-0003-hardlink-") as raw:
            hardlink_root = Path(raw)
            original = hardlink_root / "original"
            linked = hardlink_root / "linked"
            original.write_bytes(b"same inode")
            verify.os.link(original, linked)
            hardlink_state = verify._bounded_filesystem_state(
                hardlink_root,
                "fr_0003.hardlink",
            )
            with self.assertRaisesRegex(
                verify.CurrentAuditError,
                "CURRENT_AUDIT_REGISTERED_MATERIALIZATION_STATE",
            ):
                verify._registered_snapshot_materialization_receipt(hardlink_state)
        with verify.tempfile.TemporaryDirectory(
            prefix="fr-0003-special-mode-"
        ) as raw:
            special_mode_root = Path(raw)
            special_mode_file = special_mode_root / "file"
            special_mode_file.write_bytes(b"mode")
            special_mode_root.chmod(0o7755)
            special_mode_file.chmod(0o6755)
            verify._make_snapshot_world_readable(special_mode_root)
            self.assertFalse(
                special_mode_root.stat().st_mode
                & (verify.stat.S_ISUID | verify.stat.S_ISGID | verify.stat.S_ISVTX)
            )
            self.assertFalse(
                special_mode_file.stat().st_mode
                & (verify.stat.S_ISUID | verify.stat.S_ISGID | verify.stat.S_ISVTX)
            )
            normalized_state = verify._bounded_filesystem_state(
                special_mode_root,
                "fr_0003.special_mode",
            )
            verify._registered_snapshot_materialization_receipt(
                normalized_state
            )

    def test_framework_recovery_3_registered_container_launcher_payload_is_fail_closed(
        self,
    ) -> None:
        verify = _load_verify()
        payload = verify._registered_snapshot_materialization_payload()
        tree = parse(payload)
        calls = [node for node in walk(tree) if isinstance(node, Call)]

        def attribute_calls(owner: str, attribute: str) -> list[Call]:
            return [
                node
                for node in calls
                if isinstance(node.func, verify.ast.Attribute)
                and isinstance(node.func.value, Name)
                and node.func.value.id == owner
                and node.func.attr == attribute
            ]

        self.assertEqual(len(attribute_calls("os", "execve")), 1)
        self.assertEqual(len(attribute_calls("os", "setgroups")), 1)
        self.assertEqual(len(attribute_calls("os", "setresgid")), 1)
        self.assertEqual(len(attribute_calls("os", "setresuid")), 1)
        self.assertEqual(len(attribute_calls("os", "_exit")), 1)
        self.assertEqual(len(attribute_calls("signal", "signal")), 1)
        self.assertEqual(len(attribute_calls("signal", "setitimer")), 2)
        self.assertFalse(attribute_calls("os", "system"))
        self.assertNotIn("subprocess", payload)
        self.assertNotIn("shell=True", payload)
        self.assertIn('"/staging/source"', payload)
        self.assertIn('"/repo"', payload)
        self.assertIn('"O_CLOEXEC", "O_DIRECTORY", "O_NOFOLLOW"', payload)
        self.assertGreaterEqual(payload.count("names(source_fd)"), 2)
        self.assertIn("NoNewPrivs", payload)
        self.assertIn('("CapAmb", "CapEff", "CapInh", "CapPrm")', payload)
        self.assertIn("time.monotonic() - started > setup_limit", payload)
        self.assertIn('TIMEOUT = "/usr/bin/timeout"', payload)
        assignments = {
            node.targets[0].id: node.value.value
            for node in tree.body
            if isinstance(node, verify.ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], Name)
            and isinstance(node.value, Constant)
        }
        self.assertEqual(
            {
                "MAX_DEPTH": verify.MAX_JSON_DEPTH,
                "MAX_FILE_BYTES": (
                    verify.MAX_REGISTERED_MATERIALIZED_FILE_BYTES
                ),
                "MAX_NODES": verify.MAX_JSON_NODES,
                "MAX_PATH_BYTES": 4096,
                "MAX_TOTAL_BYTES": (
                    verify.MAX_REGISTERED_MATERIALIZED_TOTAL_BYTES
                ),
            },
            {
                name: assignments[name]
                for name in (
                    "MAX_DEPTH",
                    "MAX_FILE_BYTES",
                    "MAX_NODES",
                    "MAX_PATH_BYTES",
                    "MAX_TOTAL_BYTES",
                )
            },
        )
        self.assertIn(
            'before.st_size > MAX_TOTAL_BYTES - state["bytes"]',
            payload,
        )
        self.assertLess(
            payload.index(
                'before.st_size > MAX_TOTAL_BYTES - state["bytes"]'
            ),
            payload.index("destination_file = os.open"),
        )
        self.assertEqual(payload.count("chunk = os.read"), 1)
        self.assertNotIn("chunks =", payload)
        self.assertNotIn(".append(chunk)", payload)
        main = next(
            node
            for node in tree.body
            if isinstance(node, FunctionDef) and node.name == "main"
        )
        main_calls = [node for node in walk(main) if isinstance(node, Call)]

        def named_main_call(name: str) -> Call:
            matches = [
                node
                for node in main_calls
                if isinstance(node.func, Name) and node.func.id == name
            ]
            self.assertEqual(len(matches), 1)
            return matches[0]

        copy_call = named_main_call("copy_tree")
        scan_call = named_main_call("scan_tree")
        identity_call = named_main_call("verify_dropped_identity")
        exec_call = next(
            node
            for node in main_calls
            if isinstance(node.func, verify.ast.Attribute)
            and isinstance(node.func.value, Name)
            and node.func.value.id == "os"
            and node.func.attr == "execve"
        )
        drop_calls = [
            node
            for node in main_calls
            if isinstance(node.func, verify.ast.Attribute)
            and isinstance(node.func.value, Name)
            and node.func.value.id == "os"
            and node.func.attr in {"setgroups", "setresgid", "setresuid"}
        ]
        self.assertEqual(len(drop_calls), 3)
        signal_call = attribute_calls("signal", "signal")[0]
        timer_calls = sorted(
            attribute_calls("signal", "setitimer"),
            key=lambda node: node.lineno,
        )
        self.assertLess(copy_call.lineno, scan_call.lineno)
        self.assertLess(signal_call.lineno, timer_calls[0].lineno)
        self.assertLess(timer_calls[0].lineno, copy_call.lineno)
        self.assertLess(scan_call.lineno, min(node.lineno for node in drop_calls))
        self.assertLess(max(node.lineno for node in drop_calls), identity_call.lineno)
        self.assertLess(identity_call.lineno, timer_calls[1].lineno)
        self.assertLess(timer_calls[1].lineno, exec_call.lineno)
        self.assertLess(identity_call.lineno, exec_call.lineno)
        self.assertIsInstance(timer_calls[0].args[1], Name)
        self.assertEqual(timer_calls[0].args[1].id, "setup_limit")
        self.assertIsInstance(timer_calls[1].args[1], Constant)
        self.assertEqual(timer_calls[1].args[1].value, 0)
        self.assertNotIn("min(command_limit", payload)
        self.assertIn('f"{command_limit:.6f}s"', payload)
        self.assertIn("0 < command_limit <= 120", payload)
        self.assertIn("0 < setup_limit <= 120", payload)
        for prohibited in ("fork", "forkpty", "posix_spawn", "posix_spawnp"):
            self.assertFalse(attribute_calls("os", prohibited))

        materialized_host_command = [
            verify.DOCKER_EXECUTABLE,
            "--host",
            "unix:///private/fixture.sock",
            "run",
            "--user",
            "0:0",
            "--mount",
            (
                "type=bind,src=/snapshot,dst=/staging/source,"
                "readonly,bind-propagation=rprivate"
            ),
            "--entrypoint",
            "/usr/local/bin/python3",
            "fixture-image",
        ]

        def run_bounded_configuration(
            command: list[str],
            timeout_seconds: int,
            ceiling: object | None,
        ) -> None:
            keywords: dict[str, Any] = {
                "cwd": Path.cwd(),
                "env": {},
                "timeout_seconds": timeout_seconds,
                "stdout_limit": 0,
                "stderr_limit": 0,
                "error_prefix": "FR_0003_BOUNDED_SEAM",
            }
            if ceiling is not None:
                keywords["_timeout_ceiling_seconds"] = ceiling
            verify._run_bounded(command, **keywords)

        near_misses: list[tuple[list[str], int, object | None]] = [
            (materialized_host_command, 181, None),
            (materialized_host_command, 1, True),
            (materialized_host_command, 1, 179),
            (materialized_host_command, 1, 254),
            (materialized_host_command, 1, 256),
            (materialized_host_command, 256, 255),
            ([verify.GIT_EXECUTABLE, "status"], 255, 255),
        ]
        for token in (
            "readonly,",
            "--user",
            "0:0",
            "--entrypoint",
            "/usr/local/bin/python3",
        ):
            candidate = list(materialized_host_command)
            if token == "readonly,":
                candidate = [
                    item.replace("readonly,", "")
                    for item in candidate
                ]
            else:
                candidate.remove(token)
            near_misses.append((candidate, 255, 255))
        wrong_operation = list(materialized_host_command)
        wrong_operation[3] = "create"
        near_misses.append((wrong_operation, 255, 255))
        for index, (command, timeout_seconds, ceiling) in enumerate(
            near_misses
        ):
            with (
                self.subTest(bounded_seam_mutation=index),
                mock.patch.object(verify.subprocess, "Popen") as popen,
                self.assertRaisesRegex(
                    verify.CurrentAuditError,
                    "FR_0003_BOUNDED_SEAM_CONFIG_INVALID",
                ),
            ):
                run_bounded_configuration(command, timeout_seconds, ceiling)
            popen.assert_not_called()
        with (
            mock.patch.object(
                verify.subprocess,
                "Popen",
                side_effect=RuntimeError("SPAWN_REACHED"),
            ) as popen,
            self.assertRaisesRegex(RuntimeError, "SPAWN_REACHED"),
        ):
            run_bounded_configuration(
                materialized_host_command,
                verify.FRAMEWORK_RECOVERY_3_MATERIALIZED_HOST_SECONDS,
                verify.FRAMEWORK_RECOVERY_3_MATERIALIZED_HOST_SECONDS,
            )
        popen.assert_called_once()

        with (
            mock.patch.object(
                verify,
                "_registered_snapshot_materialization_receipt",
                return_value={
                    "kind": "HALDIR_REGISTERED_MATERIALIZED_SNAPSHOT"
                },
            ),
            mock.patch.object(
                verify,
                "_registered_image_state",
                return_value={
                    "daemon_cpus": 1,
                    "daemon_memory_bytes": (
                        verify
                        .FRAMEWORK_RECOVERY_3_MATERIALIZATION_MIN_DAEMON_MEMORY_BYTES
                    ),
                },
            ),
            self.assertRaisesRegex(
                verify.CurrentAuditError,
                "MATERIALIZATION_CPU_CAPACITY",
            ),
        ):
            verify._run_registered_container(
                Path("/private/tmp/fr-0003-capacity"),
                Path("/private/tmp/fr-0003-capacity-snapshot"),
                command=["/repo/probe.py"],
                label="FR_0003_CAPACITY",
                execution_seconds=30,
                materialize_snapshot=True,
                expected_snapshot_files=(("fixture",),),
                materialization_setup_seconds=(
                    verify.FRAMEWORK_RECOVERY_3_MATERIALIZATION_SETUP_SECONDS
                ),
            )
        with (
            mock.patch.object(
                verify,
                "_registered_snapshot_materialization_receipt",
                return_value={
                    "kind": "HALDIR_REGISTERED_MATERIALIZED_SNAPSHOT"
                },
            ),
            mock.patch.object(
                verify,
                "_registered_image_state",
                return_value={
                    "daemon_cpus": 2,
                    "daemon_memory_bytes": (
                        verify
                        .FRAMEWORK_RECOVERY_3_MATERIALIZATION_MIN_DAEMON_MEMORY_BYTES
                        - 1
                    ),
                },
            ),
            self.assertRaisesRegex(
                verify.CurrentAuditError,
                "MATERIALIZATION_MEMORY_CAPACITY",
            ),
        ):
            verify._run_registered_container(
                Path("/private/tmp/fr-0003-memory-capacity"),
                Path("/private/tmp/fr-0003-memory-capacity-snapshot"),
                command=["/repo/probe.py"],
                label="FR_0003_MEMORY_CAPACITY",
                execution_seconds=30,
                materialize_snapshot=True,
                expected_snapshot_files=(("fixture",),),
                materialization_setup_seconds=(
                    verify.FRAMEWORK_RECOVERY_3_MATERIALIZATION_SETUP_SECONDS
                ),
            )

        with verify.tempfile.TemporaryDirectory(
            prefix="fr-0003-start-failure-"
        ) as raw:
            expected_snapshot = (("fixture",),)
            docker_state = {
                "daemon_cpus": 2,
                "daemon_memory_bytes": (
                    verify
                    .FRAMEWORK_RECOVERY_3_MATERIALIZATION_MIN_DAEMON_MEMORY_BYTES
                ),
                "endpoint": "unix:///private/fixture.sock",
            }
            start_stderr = b"bounded daemon refusal"
            empty_digest = hashlib.sha256(b"").hexdigest()
            stderr_digest = hashlib.sha256(start_stderr).hexdigest()
            expected_error = (
                "CURRENT_AUDIT_REGISTERED_FR_0003_START_"
                "CONTAINER_START_FAILED:"
                "EXIT=125:"
                "STDOUT_BYTES=0:"
                f"STDOUT_SHA256={empty_digest}:"
                f"STDERR_BYTES={len(start_stderr)}:"
                f"STDERR_SHA256={stderr_digest}"
            )
            with (
                mock.patch.object(
                    verify,
                    "_registered_snapshot_materialization_receipt",
                    return_value={
                        "kind": "HALDIR_REGISTERED_MATERIALIZED_SNAPSHOT"
                    },
                ),
                mock.patch.object(
                    verify,
                    "_registered_image_state",
                    return_value=docker_state,
                ),
                mock.patch.object(
                    verify,
                    "_bounded_filesystem_state",
                    return_value=expected_snapshot,
                ),
                mock.patch.object(
                    verify,
                    "_run_bounded",
                    side_effect=[
                        (125, b"", start_stderr),
                        (1, b"", b""),
                        (0, b"", b""),
                        (0, b"a" * 64 + b"\n", b""),
                        (0, b"", b""),
                        (0, b"", b""),
                    ],
                ) as bounded,
                mock.patch.object(
                    verify.time,
                    "monotonic",
                    side_effect=(0.0, 0.5, 3.0),
                ),
                mock.patch.object(verify.time, "sleep") as sleep,
                self.assertRaises(verify.CurrentAuditError) as caught,
            ):
                verify._run_registered_container(
                    Path(raw),
                    Path(raw) / "snapshot",
                    command=["/repo/probe.py"],
                    label="FR_0003_START",
                    execution_seconds=(
                        verify.FRAMEWORK_RECOVERY_REGISTERED_TEST_SECONDS
                    ),
                    materialize_snapshot=True,
                    expected_snapshot_files=expected_snapshot,
                    materialization_setup_seconds=(
                        verify.FRAMEWORK_RECOVERY_3_MATERIALIZATION_SETUP_SECONDS
                    ),
                )
            self.assertEqual(str(caught.exception), expected_error)
            self.assertEqual(bounded.call_count, 6)
            sleep.assert_called_once_with(0.02)
            self.assertEqual(
                bounded.call_args_list[0].kwargs["timeout_seconds"],
                verify.FRAMEWORK_RECOVERY_3_MATERIALIZED_HOST_SECONDS,
            )
            self.assertEqual(
                bounded.call_args_list[0].kwargs[
                    "_timeout_ceiling_seconds"
                ],
                verify.FRAMEWORK_RECOVERY_3_MATERIALIZED_HOST_SECONDS,
            )
            repeated_cleanup = bounded.call_args_list[4].args[0]
            self.assertIn("rm", repeated_cleanup)
            self.assertIn("--force", repeated_cleanup)
            for call_index in (2, 3, 5):
                inspection = bounded.call_args_list[call_index].args[0]
                self.assertEqual(
                    inspection[inspection.index("--filter") + 1][
                        :7
                    ],
                    "name=^/",
                )
            docker_command = bounded.call_args_list[0].args[0]
            self.assertEqual(
                docker_command[docker_command.index("--cpus") + 1],
                "2",
            )
            self.assertEqual(
                docker_command[docker_command.index("--memory") + 1],
                "1280m",
            )
            self.assertEqual(
                docker_command[docker_command.index("--memory-swap") + 1],
                "1280m",
            )
            self.assertIn(
                "/repo:rw,nosuid,nodev,size=671088640,mode=0700",
                docker_command,
            )
            self.assertIn(
                "/staging:rw,noexec,nosuid,nodev,size=1048576,mode=0700",
                docker_command,
            )
            self.assertIn(
                "/tmp:rw,noexec,nosuid,nodev,size=67108864,mode=1777",
                docker_command,
            )
            self.assertIn(
                "fsize=536870912:536870912",
                docker_command,
            )

    def test_framework_recovery_3_registered_container_materialization_preserves_direct_calls_and_outputs(
        self,
    ) -> None:
        verify = _load_verify()
        repo = Path(__file__).resolve().parents[2]
        with verify.tempfile.TemporaryDirectory(
            prefix="fr-0003-materialized-", dir=repo.parent
        ) as raw:
            root = Path(raw)
            snapshot = root / "snapshot"
            snapshot.mkdir(mode=0o700)
            probe = snapshot / "probe.py"
            probe.write_text(
                "from pathlib import Path\n"
                "import os\n"
                "status = {}\n"
                "for line in Path('/proc/self/status').read_text().splitlines():\n"
                "    key, separator, value = line.partition(':')\n"
                "    if separator:\n"
                "        status[key] = value.strip()\n"
                "assert Path.cwd() == Path('/repo')\n"
                "assert os.getresuid() == (65534, 65534, 65534)\n"
                "assert os.getresgid() == (65534, 65534, 65534)\n"
                "assert not os.getgroups()\n"
                "assert status['NoNewPrivs'] == '1'\n"
                "assert all(\n"
                "    int(status[name], 16) == 0\n"
                "    for name in ('CapAmb', 'CapEff', 'CapInh', 'CapPrm')\n"
                ")\n"
                "for operation in (\n"
                "    lambda: Path('/repo/new').write_text('x'),\n"
                "    lambda: Path('/repo/probe.py').write_text('x'),\n"
                "    lambda: Path('/repo/probe.py').chmod(0o600),\n"
                "    lambda: Path('/staging/source/probe.py').read_bytes(),\n"
                "):\n"
                "    try:\n"
                "        operation()\n"
                "    except OSError:\n"
                "        pass\n"
                "    else:\n"
                "        raise AssertionError('sealed snapshot was mutable')\n"
                "print('MATERIALIZED_IDENTITY_PASS')\n",
                encoding="utf-8",
            )
            runner = root / "registered-test-runner.py"
            runner.write_bytes(verify._registered_test_runner_payload())
            runner.chmod(0o444)
            verify._make_snapshot_world_readable(snapshot)
            before = verify._bounded_filesystem_state(
                snapshot,
                "fr_0003.materialized.before",
            )
            result = verify._run_registered_container(
                root,
                snapshot,
                command=["/repo/probe.py"],
                label="FR_0003_MATERIALIZED_IDENTITY",
                execution_seconds=30,
                materialize_snapshot=True,
                expected_snapshot_files=before,
                materialization_setup_seconds=(
                    verify.FRAMEWORK_RECOVERY_3_MATERIALIZATION_SETUP_SECONDS
                ),
            )
            self.assertEqual(
                result,
                (0, b"MATERIALIZED_IDENTITY_PASS\n", b""),
            )
            self.assertEqual(
                verify._bounded_filesystem_state(
                    snapshot,
                    "fr_0003.materialized.after",
                ),
                before,
            )
            timeout_result = verify._run_registered_container(
                root,
                snapshot,
                command=["-c", "import time; time.sleep(30)"],
                label="FR_0003_MATERIALIZED_TIMEOUT",
                execution_seconds=1,
                materialize_snapshot=True,
                expected_snapshot_files=before,
                materialization_setup_seconds=(
                    verify.FRAMEWORK_RECOVERY_3_MATERIALIZATION_SETUP_SECONDS
                ),
            )
            self.assertEqual(timeout_result, (137, b"", b""))

            stale_before = tuple(
                (*record[:-1], "0" * 64)
                if record[0] == "file" and record[1] == "probe.py"
                else record
                for record in before
            )
            self.assertNotEqual(stale_before, before)
            with mock.patch.object(
                verify,
                "_bounded_filesystem_state",
                return_value=stale_before,
            ):
                stale_result = verify._run_registered_container(
                    root,
                    snapshot,
                    command=["/repo/probe.py"],
                    label="FR_0003_MATERIALIZED_STALE_RECEIPT",
                    execution_seconds=30,
                    materialize_snapshot=True,
                    expected_snapshot_files=stale_before,
                    materialization_setup_seconds=(
                        verify.FRAMEWORK_RECOVERY_3_MATERIALIZATION_SETUP_SECONDS
                    ),
                )
            self.assertEqual(stale_result, (70, b"", b""))


class FrameworkRecovery3PlanAndSourceTests(unittest.TestCase):
    """Prove the new trust-root identity and retain every unrelated byte."""

    def test_framework_recovery_3_transition_retires_epoch_3_without_reuse(
        self,
    ) -> None:
        verify = _load_verify()
        self.assertEqual(
            verify._framework_recovery_3_transition_identity(),
            {
                "transition_kind": "NEW_SIGNED_TRUST_ROOT_REBASELINE",
                "prior_framework_accepts_transition": False,
                "ordinary_successor_transition": False,
                "fr_0002_mechanism_reused": False,
                "epoch_3_reused": False,
                "epoch_3_state": "ABORTED_BEFORE_QUALIFICATION",
                "epoch_4_candidate_created": True,
                "active_epoch_before_activation": 2,
            },
        )

    def test_framework_recovery_3_active_epoch_changes_only_at_activation(
        self,
    ) -> None:
        verify = _load_verify()
        pending = verify._framework_recovery_3_decision("PENDING_QUALIFICATION")
        qualified = verify._framework_recovery_3_decision(
            "QUALIFIED_PENDING_ACTIVATION"
        )
        active = verify._framework_recovery_3_decision("ACTIVE")
        self.assertEqual(pending["active_framework_epoch"], 2)
        self.assertEqual(qualified["active_framework_epoch"], 2)
        self.assertEqual(active["active_framework_epoch"], 4)
        self.assertEqual(
            {
                pending["framework_epoch"],
                qualified["framework_epoch"],
                active["framework_epoch"],
            },
            {4},
        )

    def test_framework_recovery_3_decision_grants_no_external_authority(
        self,
    ) -> None:
        verify = _load_verify()
        authority_fields = {
            "runtime_authority_changed",
            "release_authority_changed",
            "deployment_authorized",
            "publication_authorized",
            "tag_authorized",
            "github_release_authorized",
            "doi_authorized",
            "zenodo_authorized",
            "archive_authorized",
        }
        for state in (
            "PENDING_QUALIFICATION",
            "QUALIFIED_PENDING_ACTIVATION",
            "ACTIVE",
        ):
            with self.subTest(state=state):
                decision = verify._framework_recovery_3_decision(state)
                self.assertTrue(
                    all(decision[field] is False for field in authority_fields)
                )
                self.assertEqual(decision["overall_release_status"], "NO_GO")

    def test_framework_recovery_3_decision_rejects_unknown_state(self) -> None:
        verify = _load_verify()
        for state in ("", "QUALIFIED", 4, None, True):
            with (
                self.subTest(state=state),
                self.assertRaisesRegex(
                    verify.CurrentAuditError,
                    "CURRENT_AUDIT_FRAMEWORK_RECOVERY_3_STATE",
                ),
            ):
                verify._framework_recovery_3_decision(state)

    def test_framework_recovery_3_expected_plan_retires_fr_0002_exactly(
        self,
    ) -> None:
        verify = _load_verify()
        repair_commit = "a" * 40
        framework_commit = "b" * 40
        with (
            mock.patch.object(
                verify,
                "_commit_regular_file_record",
                side_effect=commit_file_record,
            ),
            mock.patch.object(
                verify,
                "_signed_commit_binding",
                return_value={"commit": verify.FRAMEWORK_RECOVERY_3_PARENT},
            ),
            mock.patch.object(
                verify,
                "_framework_recovery_3_code_diff",
                return_value={
                    "base": verify.FRAMEWORK_RECOVERY_3_PARENT,
                    "target": "SIGNED_COMMIT_CONTAINING_THIS_PLAN",
                },
            ),
            mock.patch.object(
                verify,
                "_framework_recovery_3_source_retention_manifest",
                return_value={"protected_residual": {"byte_exact": True}},
            ),
            mock.patch.object(
                verify,
                "_framework_recovery_3_test_contract",
                return_value={"fr_0003_count": 1},
            ),
        ):
            plan = verify._framework_recovery_3_expected_plan(
                Path("."),
                repair_commit,
                framework_commit,
            )
        self.assertEqual(
            plan["framework_epoch"],
            {"active": 2, "retired_candidate": 3, "next_candidate": 4},
        )
        self.assertEqual(
            plan["retired_recovery"],
            {
                "recovery_id": "FR-0002",
                "repair": {
                    "commit": verify.FRAMEWORK_RECOVERY_3_PARENT,
                },
                "plan_record": commit_file_record(
                    Path("."),
                    verify.FRAMEWORK_RECOVERY_3_PARENT,
                    verify.FRAMEWORK_RECOVERY_2_PLAN_PATH,
                ),
                "state_before": "PENDING_QUALIFICATION",
                "state_after": "ABORTED_BEFORE_QUALIFICATION",
                "reason": "VERIFIER_DEFECT",
                "qualification_commit": None,
                "activation_commit": None,
                "epoch_reusable": False,
            },
        )
        self.assertFalse(
            plan["assurance_boundary"]["fr_0002_qualification_reclassified_as_valid"]
        )
        self.assertFalse(plan["state"]["successor_transitions_allowed"])
        self.assertIsNone(plan["persistent_identifier"])
        self.assertNotIn("resource_profile_precondition", plan)
        materialization = plan["registered_snapshot_materialization"]
        self.assertEqual(
            plan["secondary_defect"]["evidence_boundary"],
            {
                "local_diagnostic_observation_retained": False,
                "comparative_performance_claim_is_qualification_evidence": (
                    False
                ),
                "attribution_status": "RISK_NOT_RETAINED_REPRODUCTION_FACT",
                "qualification_basis": (
                    "FAIL_CLOSED_IDENTITY_RESOURCE_AND_EXECUTION_CONTROLS"
                ),
            },
        )
        self.assertEqual(
            materialization["scope"],
            (
                "EXACT_CH-T001_EPOCH_2_REGISTRATION_RERUN_AT_"
                "CURRENT_AND_SUCCESSOR_HEADS"
            ),
        )
        self.assertEqual(
            materialization["exception_binding"],
            verify.FRAMEWORK_RECOVERY_REGISTERED_EXECUTION_EXCEPTION,
        )
        self.assertIsNot(
            materialization["exception_binding"],
            verify.FRAMEWORK_RECOVERY_REGISTERED_EXECUTION_EXCEPTION,
        )
        self.assertEqual(
            materialization["repository_view"],
            {
                "snapshot_commit": "FINAL_HEAD_UNDER_VERIFICATION",
                "complete_detached_snapshot": True,
                "forward_active_verifier_rerun": True,
                "aggregate_bytes_align_with_repository_hygiene": True,
                "nodes_align_with_repository_hygiene": True,
                "materialization_depth_is_additional_successor_constraint": (
                    True
                ),
            },
        )
        self.assertEqual(
            materialization["source_mount"],
            {
                "path": "/staging/source",
                "read_only": True,
                "bind_propagation": "rprivate",
                "hidden_after_identity_drop": True,
            },
        )
        self.assertEqual(
            materialization["execution_mount"]["storage"],
            "FRESH_CONTAINER_LOCAL_TMPFS",
        )
        self.assertEqual(
            materialization["bounds"],
            {
                "maximum_directory_depth": verify.MAX_JSON_DEPTH,
                "maximum_file_component_depth": verify.MAX_JSON_DEPTH + 1,
                "nodes": verify.MAX_JSON_NODES,
                "path_bytes": 4096,
                "file_bytes": verify.MAX_REGISTERED_MATERIALIZED_FILE_BYTES,
                "total_bytes": verify.MAX_REGISTERED_MATERIALIZED_TOTAL_BYTES,
                "container_fsize_bytes": (
                    verify.MAX_REGISTERED_MATERIALIZED_FILE_BYTES
                ),
                "streaming_copy_chunk_bytes": 1024 * 1024,
                "file_and_total_ceiling_equal": True,
                "equal_ceiling_reason": (
                    "A_SINGLE_GIT_PACK_MAY_SPAN_THE_COMPLETE_"
                    "REPOSITORY_HYGIENE_CEILING;_THE_FILE_CEILING_"
                    "IS_A_REDUNDANT_FAIL_CLOSED_CONTROL"
                ),
                "minimum_daemon_cpus": 2,
                "minimum_daemon_memory_bytes": (
                    verify
                    .FRAMEWORK_RECOVERY_3_MATERIALIZATION_MIN_DAEMON_MEMORY_BYTES
                ),
                "container_cpus": 2,
                "container_memory_bytes": (
                    verify
                    .FRAMEWORK_RECOVERY_3_MATERIALIZATION_MIN_DAEMON_MEMORY_BYTES
                ),
                "container_memory_swap_bytes": (
                    verify
                    .FRAMEWORK_RECOVERY_3_MATERIALIZATION_MIN_DAEMON_MEMORY_BYTES
                ),
                "container_swap_additional_bytes": 0,
                "execution_tmpfs_bytes": 640 * 1024 * 1024,
                "staging_tmpfs_bytes": 1024 * 1024,
                "temporary_tmpfs_bytes": 64 * 1024 * 1024,
                "materialization_setup_seconds": (
                    verify.FRAMEWORK_RECOVERY_3_MATERIALIZATION_SETUP_SECONDS
                ),
                "test_execution_seconds": (
                    verify.FRAMEWORK_RECOVERY_REGISTERED_TEST_SECONDS
                ),
                "test_container_seconds": (
                    verify.FRAMEWORK_RECOVERY_3_MATERIALIZATION_SETUP_SECONDS
                    + verify.FRAMEWORK_RECOVERY_REGISTERED_TEST_SECONDS
                ),
                "verifier_execution_seconds": (
                    verify.FRAMEWORK_RECOVERY_REGISTERED_VERIFIER_SECONDS
                ),
                "verifier_container_seconds": (
                    verify.FRAMEWORK_RECOVERY_3_MATERIALIZATION_SETUP_SECONDS
                    + verify.FRAMEWORK_RECOVERY_REGISTERED_VERIFIER_SECONDS
                ),
                "host_containment_grace_seconds": 15,
                "host_bounded_process_ceiling_seconds": (
                    verify.FRAMEWORK_RECOVERY_3_MATERIALIZED_HOST_SECONDS
                ),
            },
        )
        self.assertEqual(
            materialization["receipt"]["algorithm"],
            "SHA256-FRAMED-PATH-EXECUTABLE-CONTENT-V1",
        )
        self.assertEqual(
            materialization["receipt"]["required_equal_views"],
            [
                "HOST_SNAPSHOT",
                "CONTAINER_SOURCE_COPY",
                "SEALED_EXECUTION_TREE",
            ],
        )
        self.assertEqual(
            materialization["execution_policy"][
                "registered_tests_run_count"
            ],
            1,
        )
        self.assertEqual(
            materialization["execution_policy"]["setup_capabilities"],
            ["SETGID", "SETUID"],
        )
        self.assertTrue(
            materialization["execution_policy"][
                "container_root_filesystem_read_only"
            ]
        )
        self.assertEqual(
            materialization["execution_policy"]["container_network"],
            "NONE",
        )
        self.assertEqual(
            materialization["execution_policy"][
                "registered_verifier_run_count"
            ],
            1,
        )
        self.assertFalse(
            materialization["execution_policy"]["retry_allowed"]
        )
        self.assertFalse(
            materialization["execution_policy"]["cache_warmth_relied_on"]
        )
        self.assertEqual(
            materialization["execution_policy"]["final_uid"],
            65_534,
        )
        self.assertEqual(
            materialization["execution_policy"]["final_gid"],
            65_534,
        )
        self.assertEqual(
            {
                key: materialization["execution_policy"][key]
                for key in (
                    "setup_watchdog",
                    "setup_watchdog_armed_before_source_open",
                    "setup_monotonic_postcondition",
                    "setup_watchdog_cancelled_before_exec",
                    "registered_command_allowance_preserved",
                )
            },
            {
                "setup_watchdog": "SIGALRM_ITIMER_REAL",
                "setup_watchdog_armed_before_source_open": True,
                "setup_monotonic_postcondition": True,
                "setup_watchdog_cancelled_before_exec": True,
                "registered_command_allowance_preserved": True,
            },
        )
        self.assertEqual(
            materialization["copy_policy"],
            {
                "directory_fd_traversal": True,
                "nofollow_required": True,
                "regular_files_only": True,
                "symbolic_links_allowed": False,
                "hard_links_allowed": False,
                "special_files_allowed": False,
                "source_nonregular_types_remain_rejected": True,
                "clone_output_single_link_postcondition": True,
                "disposable_snapshot_special_bits_cleared": True,
                "aggregate_capacity_checked_before_destination_creation": True,
                "container_file_copy_streaming": True,
                "source_relisted_after_descendants": True,
                "destination_rescanned_after_sealing": True,
            },
        )

    def test_framework_recovery_3_added_plan_and_test_have_no_old_record(
        self,
    ) -> None:
        verify = _load_verify()
        with (
            mock.patch.object(
                verify,
                "_commit_regular_file_record",
                side_effect=commit_file_record,
            ),
            mock.patch.object(
                verify,
                "_signed_commit_binding",
                return_value={"commit": verify.FRAMEWORK_RECOVERY_3_PARENT},
            ),
            mock.patch.object(
                verify,
                "_framework_recovery_3_code_diff",
                return_value={"target": "SIGNED_COMMIT_CONTAINING_THIS_PLAN"},
            ),
            mock.patch.object(
                verify,
                "_framework_recovery_3_source_retention_manifest",
                return_value={"protected_residual": {"byte_exact": True}},
            ),
            mock.patch.object(
                verify,
                "_framework_recovery_3_test_contract",
                return_value={"fr_0003_count": 1},
            ),
        ):
            plan = verify._framework_recovery_3_expected_plan(
                Path("."),
                "a" * 40,
                "b" * 40,
            )
        records = {item["new"]["path"]: item for item in plan["changed_core_files"]}
        self.assertIsNone(records[verify.FRAMEWORK_RECOVERY_3_TEST_PATH]["old"])
        self.assertEqual(
            records[verify.FRAMEWORK_RECOVERY_3_TEST_PATH]["status"],
            "A",
        )
        self.assertIsNotNone(records["tools/release/verify-current-audit.py"]["old"])
        profiler_record = records["tools/release/current-audit-resource-profile.py"]
        self.assertEqual(profiler_record["status"], "M")
        self.assertIsNotNone(profiler_record["old"])
        self.assertIsNotNone(profiler_record["new"])

    def test_framework_recovery_3_stage_modes_reject_nonregular_or_wrong_mode(
        self,
    ) -> None:
        verify = _load_verify()
        expected = {"plain": "100644", "runner": "100755"}

        def valid_entry(_repo: Path, _commit: str, path: str) -> dict[str, str]:
            return {"mode": expected[path], "type": "blob", "oid": path}

        with mock.patch.object(
            verify,
            "_git_tree_entry",
            side_effect=valid_entry,
        ):
            verify._framework_recovery_3_verify_stage_modes(
                Path("."),
                "a" * 40,
                expected,
                label="fixture",
            )
        for path, entry in (
            ("plain", None),
            ("plain", {"mode": "100755", "type": "blob"}),
            ("plain", {"mode": "100644", "type": "tree"}),
            ("runner", {"mode": "120000", "type": "blob"}),
        ):
            with (
                self.subTest(path=path, entry=entry),
                mock.patch.object(
                    verify,
                    "_git_tree_entry",
                    side_effect=lambda _repo, _commit, candidate: (
                        entry
                        if candidate == path
                        else {
                            "mode": expected[candidate],
                            "type": "blob",
                        }
                    ),
                ),
                self.assertRaisesRegex(
                    verify.CurrentAuditError,
                    "CURRENT_AUDIT_FRAMEWORK_RECOVERY_3_MODE",
                ),
            ):
                verify._framework_recovery_3_verify_stage_modes(
                    Path("."),
                    "a" * 40,
                    expected,
                    label="fixture",
                )

    def test_framework_recovery_3_repair_validator_binds_signature_and_scope(
        self,
    ) -> None:
        verify = _load_verify()
        repair_commit = "a" * 40
        framework_commit = "b" * 40
        expected = {
            "schema_version": "1.0.0",
            "persistent_identifier": None,
        }
        plan = {
            **copy.deepcopy(expected),
            "created_at_utc": "2026-07-24T00:00:01Z",
            "detached_signature": {"signature": "fixture"},
        }
        metadata = {
            "parent": verify.FRAMEWORK_RECOVERY_3_PARENT,
            "subject": verify.FRAMEWORK_RECOVERY_3_SUBJECT,
            "author_name": "Sepehr Mahmoudian",
            "author_email": "sepmhn@gmail.com",
            "committer_name": "Sepehr Mahmoudian",
            "committer_email": "sepmhn@gmail.com",
        }
        signer = {
            "principal": "sepmhn@gmail.com",
            "public_key": "ssh-ed25519 fixture",
            "key_fingerprint": "SHA256:fixture",
        }
        with (
            mock.patch.object(
                verify,
                "_commit_metadata",
                return_value=metadata,
            ),
            mock.patch.object(
                verify,
                "_verify_named_commit_signature",
            ) as commit_signature,
            mock.patch.object(
                verify,
                "_changed_path_statuses",
                return_value=dict(
                    sorted(verify.FRAMEWORK_RECOVERY_3_REPAIR_STATUSES.items())
                ),
            ),
            mock.patch.object(
                verify,
                "_framework_recovery_3_verify_stage_modes",
            ),
            mock.patch.object(
                verify,
                "_git_tree_entry",
                return_value={"mode": "100644", "type": "blob", "oid": "same"},
            ),
            mock.patch.object(
                verify,
                "_read_commit_json",
                return_value=(
                    plan,
                    verify._canonical_json_bytes(plan, pretty=True),
                ),
            ),
            mock.patch.object(
                verify,
                "_framework_recovery_3_expected_plan",
                return_value=expected,
            ),
            mock.patch.object(
                verify,
                "_commit_datetime",
                side_effect=(
                    utc("2026-07-24T00:00:00Z"),
                    utc("2026-07-24T00:00:02Z"),
                ),
            ),
            mock.patch.object(
                verify,
                "_source_release_signer",
                return_value=signer,
            ),
            mock.patch.object(
                verify,
                "_verify_ssh_detached_attestation",
            ) as attestation,
        ):
            observed = verify._verify_framework_recovery_3_repair(
                Path("."),
                repair_commit,
                framework_commit=framework_commit,
            )
        self.assertEqual(observed, plan)
        commit_signature.assert_called_once_with(
            Path("."),
            repair_commit,
            "FRAMEWORK_RECOVERY_3",
        )
        self.assertEqual(
            attestation.call_args.kwargs["namespace"],
            "haldir-framework-recovery-fr-0003-plan-v1",
        )
        self.assertEqual(
            attestation.call_args.kwargs["expected_fingerprint"],
            signer["key_fingerprint"],
        )

    def test_framework_recovery_3_repair_identity_mutations_are_rejected(
        self,
    ) -> None:
        verify = _load_verify()
        base = {
            "parent": verify.FRAMEWORK_RECOVERY_3_PARENT,
            "subject": verify.FRAMEWORK_RECOVERY_3_SUBJECT,
            "author_name": "Sepehr Mahmoudian",
            "author_email": "sepmhn@gmail.com",
            "committer_name": "Sepehr Mahmoudian",
            "committer_email": "sepmhn@gmail.com",
        }
        mutations = (
            ("parent", "0" * 40),
            ("subject", "release: similar but unbound"),
            ("author_name", "Other"),
            ("author_email", "other@example.invalid"),
            ("committer_name", "Other"),
            ("committer_email", "other@example.invalid"),
        )
        for field, value in mutations:
            metadata = {**base, field: value}
            with (
                self.subTest(field=field),
                mock.patch.object(
                    verify,
                    "_commit_metadata",
                    return_value=metadata,
                ),
                self.assertRaisesRegex(
                    verify.CurrentAuditError,
                    "CURRENT_AUDIT_FRAMEWORK_RECOVERY_3_COMMIT_IDENTITY",
                ),
            ):
                verify._verify_framework_recovery_3_repair(
                    Path("."),
                    "a" * 40,
                    framework_commit="b" * 40,
                )

    def test_framework_recovery_3_repair_rejects_fr_0002_record_drift(
        self,
    ) -> None:
        verify = _load_verify()
        repair_commit = "a" * 40
        metadata = {
            "parent": verify.FRAMEWORK_RECOVERY_3_PARENT,
            "subject": verify.FRAMEWORK_RECOVERY_3_SUBJECT,
            "author_name": "Sepehr Mahmoudian",
            "author_email": "sepmhn@gmail.com",
            "committer_name": "Sepehr Mahmoudian",
            "committer_email": "sepmhn@gmail.com",
        }
        for changed_path in (
            verify.FRAMEWORK_RECOVERY_2_PLAN_PATH,
            verify.FRAMEWORK_RECOVERY_2_TEST_PATH,
        ):

            def tree_entry(
                _repo: Path,
                commit: str,
                path: str,
            ) -> dict[str, str]:
                return {
                    "mode": "100644",
                    "type": "blob",
                    "oid": (
                        "changed"
                        if commit == repair_commit and path == changed_path
                        else "preserved"
                    ),
                }

            with (
                self.subTest(path=changed_path),
                mock.patch.object(
                    verify,
                    "_commit_metadata",
                    return_value=metadata,
                ),
                mock.patch.object(
                    verify,
                    "_verify_named_commit_signature",
                ),
                mock.patch.object(
                    verify,
                    "_changed_path_statuses",
                    return_value=dict(
                        sorted(verify.FRAMEWORK_RECOVERY_3_REPAIR_STATUSES.items())
                    ),
                ),
                mock.patch.object(
                    verify,
                    "_framework_recovery_3_verify_stage_modes",
                ),
                mock.patch.object(
                    verify,
                    "_git_tree_entry",
                    side_effect=tree_entry,
                ),
                self.assertRaisesRegex(
                    verify.CurrentAuditError,
                    "CURRENT_AUDIT_FRAMEWORK_RECOVERY_3_STATE_DRIFT",
                ),
            ):
                verify._verify_framework_recovery_3_repair(
                    Path("."),
                    repair_commit,
                    framework_commit="b" * 40,
                )

    def test_framework_recovery_3_source_retention_preserves_bounded_runner(
        self,
    ) -> None:
        verify = _load_verify()
        repo = Path(__file__).resolve().parents[2]
        path = "tools/release/verify-current-audit.py"
        target = Path(__file__).with_name("verify-current-audit.py").read_bytes()
        original_git_file = verify._git_file

        def git_file(_repo: Path, commit: str, selected: str) -> bytes:
            if commit == "a" * 40 and selected == path:
                return target
            return original_git_file(_repo, commit, selected)

        with mock.patch.object(
            verify,
            "_git_file",
            side_effect=git_file,
        ):
            manifest = verify._framework_recovery_3_source_retention_manifest(
                repo,
                "a" * 40,
            )
        self.assertTrue(manifest["protected_residual"]["byte_exact"])
        self.assertEqual(
            manifest["protected_residual"]["parent"]["sha256"],
            manifest["protected_residual"]["target"]["sha256"],
        )
        self.assertEqual(
            set(manifest["bounded_runner_records"]),
            set(verify.FRAMEWORK_RECOVERY_3_BOUNDED_RUNNER_DEFINITIONS),
        )
        self.assertNotIn("_run_bounded", manifest["bounded_runner_records"])
        self.assertIn(
            "_stop_bounded_process",
            manifest["bounded_runner_records"],
        )
        self.assertIn(
            "_run_registered_container",
            manifest["allowed_changes"]["modified_definitions"],
        )
        self.assertIn(
            "_run_bounded",
            manifest["allowed_changes"]["modified_definitions"],
        )
        self.assertIn(
            "_run_registered_verifier_v2",
            manifest["allowed_changes"]["modified_definitions"],
        )
        self.assertIn(
            "_registered_image_state",
            manifest["allowed_changes"]["modified_definitions"],
        )
        self.assertEqual(
            {
                "_registered_snapshot_materialization_applies",
                "_registered_snapshot_materialization_payload",
                "_registered_snapshot_materialization_receipt",
            },
            {
                name
                for name in manifest["allowed_changes"]["new_definitions"]
                if "snapshot_materialization" in name
            },
        )
        self.assertNotIn(
            "_run_registered_container",
            manifest["bounded_runner_records"],
        )
        self.assertEqual(
            manifest["bounded_runner_recovery_seam"],
            {
                "definition": "_run_bounded",
                "default_timeout_ceiling_seconds": 180,
                "materialized_timeout_ceiling_seconds": (
                    verify.FRAMEWORK_RECOVERY_3_MATERIALIZED_HOST_SECONDS
                ),
                "ast_exact_outside_timeout_ceiling_seam": True,
                "parent_projection_sha256": (
                    manifest["bounded_runner_recovery_seam"][
                        "target_projection_sha256"
                    ]
                ),
                "target_projection_sha256": (
                    manifest["bounded_runner_recovery_seam"][
                        "parent_projection_sha256"
                    ]
                ),
            },
        )
        self.assertGreater(manifest["preserved_counts"]["definitions"], 200)

    def test_framework_recovery_3_local_resource_profile_is_fully_validated(
        self,
    ) -> None:
        profiler = _load_resource_profiler()
        verify = _load_verify()
        generated = datetime(2026, 7, 24, 12, 0, tzinfo=timezone.utc)
        profile = {
            "generated_at_utc": "2026-07-24T12:00:00Z",
            "overall_pass": True,
            "cases": [{} for _ in range(38)],
            "verifier": {
                "path": "tools/release/verify-current-audit.py",
            },
            "configuration": {
                "samples_per_case": 3,
                "limits_bytes": {
                    name: getattr(verify, name)
                    for name in profiler.LIMIT_NAMES
                },
                "json_structure_limits": {
                    name: getattr(verify, name)
                    for name in profiler.JSON_STRUCTURE_LIMIT_NAMES
                },
            },
        }

        def validate(candidate: dict[str, Any]) -> mock.Mock:
            loaded = mock.Mock()
            with (
                mock.patch.object(
                    verify,
                    "_git_file",
                    side_effect=(b"profiler", b"verifier"),
                ),
                mock.patch.object(
                    verify,
                    "_load_exact_module",
                    return_value=loaded,
                ),
            ):
                verify._framework_recovery_3_validate_local_resource_profile(
                    Path("."),
                    "a" * 40,
                    candidate,
                    generated_not_before=generated,
                    generated_not_after=generated,
                )
            return loaded

        loaded = validate(copy.deepcopy(profile))
        loaded.validate_profile.assert_called_once_with(
            profile,
            verifier_payload=b"verifier",
        )
        mutations = []
        for update in (
            {"overall_pass": False},
            {"cases": [{} for _ in range(37)]},
            {"generated_at_utc": "2026-07-24T11:59:59Z"},
        ):
            candidate = copy.deepcopy(profile)
            candidate.update(update)
            mutations.append(candidate)
        samples = copy.deepcopy(profile)
        samples["configuration"]["samples_per_case"] = 2
        mutations.append(samples)
        byte_limit = copy.deepcopy(profile)
        byte_limit["configuration"]["limits_bytes"][
            "MAX_REGISTERED_MATERIALIZED_TOTAL_BYTES"
        ] -= 1
        mutations.append(byte_limit)
        json_limit = copy.deepcopy(profile)
        json_limit["configuration"]["json_structure_limits"][
            "MAX_JSON_DEPTH"
        ] -= 1
        mutations.append(json_limit)
        verifier_path = copy.deepcopy(profile)
        verifier_path["verifier"]["path"] = "wrong.py"
        mutations.append(verifier_path)
        for index, candidate in enumerate(mutations):
            with (
                self.subTest(wrapper_mutation=index),
                self.assertRaisesRegex(
                    verify.CurrentAuditError,
                    "CURRENT_AUDIT_FRAMEWORK_RECOVERY_3_RESOURCE_PROFILE",
                ),
            ):
                validate(candidate)

        loaded = mock.Mock()
        loaded.validate_profile.side_effect = ValueError("rejected profile")
        with (
            mock.patch.object(
                verify,
                "_git_file",
                side_effect=(b"profiler", b"verifier"),
            ),
            mock.patch.object(
                verify,
                "_load_exact_module",
                return_value=loaded,
            ),
            self.assertRaisesRegex(
                verify.CurrentAuditError,
                "CURRENT_AUDIT_FRAMEWORK_RECOVERY_3_RESOURCE_PROFILE",
            ),
        ):
            verify._framework_recovery_3_validate_local_resource_profile(
                Path("."),
                "a" * 40,
                copy.deepcopy(profile),
                generated_not_before=generated,
                generated_not_after=generated,
            )

    def test_framework_recovery_3_source_retention_rejects_mutations(
        self,
    ) -> None:
        verify = _load_verify()
        repo = Path(__file__).resolve().parents[2]
        path = "tools/release/verify-current-audit.py"
        target = Path(__file__).with_name("verify-current-audit.py").read_bytes()
        original_git_file = verify._git_file
        mutations = (
            target.replace(
                b"def _sha256(payload: bytes) -> str:\n",
                b"def _sha256(payload: bytes) -> str:\n    # drift\n",
                1,
            ),
            target.replace(
                (
                    b"def _stop_bounded_process("
                    b"state: _BoundedProcessState) -> tuple[str, ...]:\n"
                ),
                (
                    b"# bounded-runner drift\n"
                    b"def _stop_bounded_process("
                    b"state: _BoundedProcessState) -> tuple[str, ...]:\n"
                ),
                1,
            ),
            target.replace(
                b'if os.name != "posix":\n',
                b'if os.name == "posix":\n',
                1,
            ),
            target.replace(
                (
                    b"        for attempt in range(8):\n"
                    b"            try:\n"
                    b"                events = selector.select"
                ),
                (
                    b"        for attempt in range(7):\n"
                    b"            try:\n"
                    b"                events = selector.select"
                ),
                1,
            ),
            target.replace(
                b"import selectors\n",
                b"import selectors\nimport socket\n",
                1,
            ),
            target.replace(
                b'FRAMEWORK_RECOVERY_2_ID = "FR-0002"\n',
                b'FRAMEWORK_RECOVERY_2_ID = "FR-0002-DRIFT"\n',
                1,
            ),
            target.replace(
                b"\ndef _framework_recovery_3_expected_gate_payload(",
                (
                    b"\ndef unauthorized_framework_recovery_3_helper():\n"
                    b"    return None\n\n"
                    b"def _framework_recovery_3_expected_gate_payload("
                ),
                1,
            ),
        )
        self.assertTrue(all(candidate != target for candidate in mutations))
        for index, mutation in enumerate(mutations):

            def git_file(_repo: Path, commit: str, selected: str) -> bytes:
                if commit == "a" * 40 and selected == path:
                    return mutation
                return original_git_file(_repo, commit, selected)

            with (
                self.subTest(index=index),
                mock.patch.object(
                    verify,
                    "_git_file",
                    side_effect=git_file,
                ),
                self.assertRaises(verify.CurrentAuditError),
            ):
                verify._framework_recovery_3_source_retention_manifest(
                    repo,
                    "a" * 40,
                )

    def test_framework_recovery_2_retention_projects_exact_fr_0003_delta(
        self,
    ) -> None:
        verify = _load_verify()
        repo = Path(__file__).resolve().parents[2]
        path = "tools/release/verify-current-audit.py"
        target = Path(__file__).with_name("verify-current-audit.py").read_bytes()
        original_git_file = verify._git_file
        baseline = verify._framework_recovery_2_source_retention_manifest(
            repo,
            verify.FRAMEWORK_RECOVERY_3_PARENT,
        )

        def git_file(_repo: Path, commit: str, selected: str) -> bytes:
            if commit == "a" * 40 and selected == path:
                return target
            return original_git_file(_repo, commit, selected)

        with mock.patch.object(
            verify,
            "_git_file",
            side_effect=git_file,
        ):
            projected = verify._framework_recovery_2_source_retention_manifest(
                repo,
                "a" * 40,
            )
        self.assertEqual(projected, baseline)
        self.assertTrue(projected["protected_residual"]["byte_exact"])
        self.assertEqual(
            projected["target"],
            baseline["target"],
        )

    def test_framework_recovery_2_compatibility_rejects_near_misses(
        self,
    ) -> None:
        verify = _load_verify()
        repo = Path(__file__).resolve().parents[2]
        path = "tools/release/verify-current-audit.py"
        parent = verify._git_file(
            repo,
            verify.FRAMEWORK_RECOVERY_3_PARENT,
            path,
        )
        target = Path(__file__).with_name("verify-current-audit.py").read_bytes()
        mutations = (
            target.replace(
                b"def _sha256(payload: bytes) -> str:\n",
                b"def _sha256(payload: bytes) -> str:\n    # drift\n",
                1,
            ),
            target.replace(
                b"def _run_bounded(\n",
                b"# bounded-runner gap drift\ndef _run_bounded(\n",
                1,
            ),
            target.replace(
                b'FRAMEWORK_RECOVERY_2_ID = "FR-0002"\n',
                b'FRAMEWORK_RECOVERY_2_ID = "FR-0002-DRIFT"\n',
                1,
            ),
            target.replace(
                b"import selectors\n",
                b"import selectors\nimport socket\n",
                1,
            ),
            target.replace(
                b"\ndef _framework_recovery_3_expected_gate_payload(",
                (
                    b"\ndef unauthorized_framework_recovery_3_helper():\n"
                    b"    return None\n\n"
                    b"def _framework_recovery_3_expected_gate_payload("
                ),
                1,
            ),
            target.replace(
                b"\ndef _framework_recovery_3_boundary_policy(",
                b"\ndef _framework_recovery_3_boundary_policy_drift(",
                1,
            ),
        )
        self.assertTrue(all(candidate != target for candidate in mutations))
        for index, mutation in enumerate(mutations):
            with (
                self.subTest(index=index),
                self.assertRaisesRegex(
                    verify.CurrentAuditError,
                    "CURRENT_AUDIT_FRAMEWORK_RECOVERY_2_SOURCE_COMPATIBILITY",
                ),
            ):
                verify._framework_recovery_3_validate_source_compatibility(
                    parent,
                    mutation,
                )

    def test_framework_recovery_2_compatibility_requires_frozen_anchor(
        self,
    ) -> None:
        verify = _load_verify()
        repo = Path(__file__).resolve().parents[2]
        path = "tools/release/verify-current-audit.py"
        target = Path(__file__).with_name("verify-current-audit.py").read_bytes()
        original_git_file = verify._git_file
        original_git_tree_entry = verify._git_tree_entry

        def git_file(_repo: Path, commit: str, selected: str) -> bytes:
            if commit == "a" * 40 and selected == path:
                return target
            return original_git_file(_repo, commit, selected)

        for entry in (
            None,
            {"mode": "100644", "type": "tree", "oid": "0" * 40},
        ):

            def git_tree_entry(
                _repo: Path,
                commit: str,
                selected: str,
            ) -> dict[str, str] | None:
                if commit == verify.FRAMEWORK_RECOVERY_3_PARENT and selected == path:
                    return entry
                return original_git_tree_entry(_repo, commit, selected)

            with (
                self.subTest(entry=entry),
                mock.patch.object(
                    verify,
                    "_git_file",
                    side_effect=git_file,
                ),
                mock.patch.object(
                    verify,
                    "_git_tree_entry",
                    side_effect=git_tree_entry,
                ),
                self.assertRaisesRegex(
                    verify.CurrentAuditError,
                    "CURRENT_AUDIT_FRAMEWORK_RECOVERY_2_SOURCE_COMPATIBILITY",
                ),
            ):
                verify._framework_recovery_2_source_retention_manifest(
                    repo,
                    "a" * 40,
                )


class FrameworkRecovery3EvidenceProtocolTests(unittest.TestCase):
    """Validate hosted identities, anomaly binding, and authority records."""

    def test_framework_recovery_3_boundary_policy_is_explicit(self) -> None:
        verify = _load_verify()
        self.assertEqual(
            verify._framework_recovery_3_boundary_policy(),
            {
                "historical_default_strict": True,
                "job_boundary_skew_seconds": 1,
                "raw_timestamps_changed": False,
                "step_interval_must_not_reverse": True,
                "step_must_remain_inside_workflow_run": True,
                "job_must_remain_inside_workflow_run": True,
                "ordinary_and_attempt_jobs_must_match": True,
            },
        )

    def test_framework_recovery_3_hosted_entry_uses_epoch_4_policy(
        self,
    ) -> None:
        verify = _load_verify()
        paths = ("ordinary.json", "attempt.json", "run.log.gz")
        subject_commit = "a" * 40
        containing_commit = "b" * 40
        anomaly = verify._framework_recovery_3_expected_parent_anomaly()
        operations = {
            "raw_log": {
                "completed_at_utc": "2026-07-24T00:00:02Z",
            }
        }
        base = {
            "capture_schema": verify.FRAMEWORK_RECOVERY_2_CAPTURE_SCHEMA,
            "workflow": "ci",
            "subject_commit": subject_commit,
            "files": [{"path": path} for path in paths],
            "log_integrity": {"sha256": "0" * 64},
            "capture_operations": operations,
        }
        observed = {
            **copy.deepcopy(base),
            "boundary_policy": verify._framework_recovery_3_boundary_policy(),
            "anomaly_manifest": [copy.deepcopy(anomaly)],
        }
        metadata = {
            "databaseId": anomaly["run_id"],
        }
        attempt = {
            "updatedAt": "2026-07-24T00:00:01Z",
        }
        with (
            mock.patch.object(
                verify,
                "_framework_recovery_2_hosted_entry",
                return_value=base,
            ),
            mock.patch.object(
                verify,
                "_git_file",
                side_effect=(b"metadata", b"attempt"),
            ),
            mock.patch.object(
                verify,
                "_load_json_bytes",
                side_effect=(metadata, attempt),
            ),
            mock.patch.object(
                verify,
                "_framework_recovery_2_verify_capture_operations",
                return_value=operations,
            ),
            mock.patch.object(
                verify,
                "_commit_datetime",
                return_value=utc("2026-07-24T00:00:03Z"),
            ),
            mock.patch.object(
                verify,
                "_verify_hosted_evidence_v2",
                return_value=[anomaly],
            ) as hosted_validator,
        ):
            result, captured = verify._framework_recovery_3_verify_hosted_entry(
                Path("."),
                containing_commit,
                observed,
                paths=paths,
                subject_commit=subject_commit,
                workflow="ci",
                lane="repair_ci",
            )
        self.assertEqual(result, observed)
        self.assertEqual(captured, utc("2026-07-24T00:00:02Z"))
        self.assertEqual(
            hosted_validator.call_args.kwargs["job_boundary_skew_seconds"],
            1,
        )

    def test_framework_recovery_3_hosted_entry_rejects_manifest_mutation(
        self,
    ) -> None:
        verify = _load_verify()
        paths = ("ordinary.json", "attempt.json", "run.log.gz")
        operations = {
            "raw_log": {
                "completed_at_utc": "2026-07-24T00:00:02Z",
            }
        }
        base = {
            "capture_schema": verify.FRAMEWORK_RECOVERY_2_CAPTURE_SCHEMA,
            "workflow": "formal",
            "subject_commit": "a" * 40,
            "files": [{"path": path} for path in paths],
            "log_integrity": {},
            "capture_operations": operations,
        }
        expected_anomaly = verify._framework_recovery_3_expected_parent_anomaly()
        observed = {
            **copy.deepcopy(base),
            "boundary_policy": verify._framework_recovery_3_boundary_policy(),
            "anomaly_manifest": [],
        }
        with (
            mock.patch.object(
                verify,
                "_framework_recovery_2_hosted_entry",
                return_value=base,
            ),
            mock.patch.object(
                verify,
                "_git_file",
                side_effect=(b"metadata", b"attempt"),
            ),
            mock.patch.object(
                verify,
                "_load_json_bytes",
                side_effect=(
                    {"databaseId": 1},
                    {"updatedAt": "2026-07-24T00:00:01Z"},
                ),
            ),
            mock.patch.object(
                verify,
                "_framework_recovery_2_verify_capture_operations",
                return_value=operations,
            ),
            mock.patch.object(
                verify,
                "_commit_datetime",
                return_value=utc("2026-07-24T00:00:03Z"),
            ),
            mock.patch.object(
                verify,
                "_verify_hosted_evidence_v2",
                return_value=[expected_anomaly],
            ),
            self.assertRaisesRegex(
                verify.CurrentAuditError,
                "CURRENT_AUDIT_FRAMEWORK_RECOVERY_3_HOSTED_ANOMALIES",
            ),
        ):
            verify._framework_recovery_3_verify_hosted_entry(
                Path("."),
                "b" * 40,
                observed,
                paths=paths,
                subject_commit="a" * 40,
                workflow="formal",
                lane="repair_formal",
            )

    def test_framework_recovery_3_run_attempt_namespace_includes_parent(
        self,
    ) -> None:
        verify = _load_verify()
        entries = [
            ("repair_ci", "a" * 40, {}),
            ("repair_formal", "b" * 40, {}),
            ("qualification_ci", "c" * 40, {}),
            ("qualification_formal", "d" * 40, {}),
        ]
        with mock.patch.object(
            verify,
            "_framework_recovery_3_run_attempt_identity",
            side_effect=((10, 1), (11, 1), (12, 1), (13, 1)),
        ):
            verify._framework_recovery_3_verify_run_attempt_uniqueness(
                Path("."),
                entries,
            )
        for identities in (
            ((30_023_626_301, 1), (11, 1), (12, 1), (13, 1)),
            ((10, 1), (11, 1), (10, 1), (13, 1)),
        ):
            with (
                self.subTest(identities=identities),
                mock.patch.object(
                    verify,
                    "_framework_recovery_3_run_attempt_identity",
                    side_effect=identities,
                ),
                self.assertRaisesRegex(
                    verify.CurrentAuditError,
                    ("CURRENT_AUDIT_FRAMEWORK_RECOVERY_3_RUN_ATTEMPT_REUSED"),
                ),
            ):
                verify._framework_recovery_3_verify_run_attempt_uniqueness(
                    Path("."),
                    entries,
                )

    def test_framework_recovery_3_ci_markers_are_exact_and_warning_strict(
        self,
    ) -> None:
        verify = _load_verify()
        contract = {
            "legacy_count": 163,
            "fr_0002_count": 78,
            "fr_0003_count": 58,
        }
        prefix = b"supply-chain\t2026-07-24T00:00:00Z "
        lines = []
        for count in (163, 78, 58, 26):
            lines.extend(
                (
                    prefix + f"Ran {count} tests in 1.000s".encode("ascii"),
                    prefix + b"OK",
                )
            )
        lines.append(prefix + b"verify-current-audit: OK")
        clean = b"\n".join(lines) + b"\n"
        entry = {"files": [{}, {}, {"path": "retained.log.gz"}]}

        def validate(payload: bytes) -> None:
            with (
                mock.patch.object(
                    verify,
                    "_git_file",
                    return_value=b"compressed",
                ),
                mock.patch.object(
                    verify,
                    "_decompress_unbound_gzip",
                    return_value=payload,
                ),
                mock.patch.object(
                    verify,
                    "_hosted_step_log_lines",
                    return_value=payload,
                ),
            ):
                verify._framework_recovery_3_verify_ci_markers(
                    Path("."),
                    "a" * 40,
                    entry,
                    test_contract=contract,
                    label="fixture",
                )

        validate(clean)
        mutations = (
            b"\n".join(lines[:-2]) + b"\n",
            clean + prefix + b"OK\n",
            clean + prefix + b"FAILED (failures=1)\n",
            clean.replace(b"Ran 58 tests", b"Ran 57 tests", 1),
        )
        for index, mutation in enumerate(mutations):
            with (
                self.subTest(index=index),
                self.assertRaisesRegex(
                    verify.CurrentAuditError,
                    "CURRENT_AUDIT_FRAMEWORK_RECOVERY_3_CI_LOG_MARKERS",
                ),
            ):
                validate(mutation)

    def test_framework_recovery_3_local_log_is_complete_and_ordered(
        self,
    ) -> None:
        verify = _load_verify()
        contract = {
            "legacy_count": 163,
            "fr_0002_count": 78,
            "fr_0003_count": 83,
        }
        resource_document = {"overall_pass": True}
        resource_body = verify._canonical_json_bytes(
            resource_document,
            pretty=True,
        )
        direct_lines = [
            b"=== CURRENT_AUDIT_GATE ===",
            b"$ tools/release/current-audit-gate.sh",
        ]
        for count in (163, 78, 83, 26):
            direct_lines.extend(
                (
                    f"Ran {count} tests in 1.000s".encode("ascii"),
                    b"OK",
                )
            )
        direct_lines.append(b"verify-current-audit: OK")
        p0_lines = [
            b"=== P0R_EXIT_GATE ===",
            b"$ tools/p0r-exit-gate.sh",
        ]
        for count in (163, 78, 83, 26, 26):
            p0_lines.append(f"Ran {count} tests in 1.000s".encode("ascii"))
        p0_lines.extend([b"OK"] * 10)
        p0_lines.extend(
            (
                b"verify-current-audit: OK",
                b"P0-R exit gate: 30 passed, 0 failed",
            )
        )
        resource_prefix = (
            b"=== RESOURCE_PROFILE ===\n"
            b"$ python3 -I tools/release/current-audit-resource-profile.py\n"
        )
        clean = (
            b"\n".join(direct_lines)
            + b"\n"
            + b"\n".join(p0_lines)
            + b"\n"
            + resource_prefix
            + resource_body
        )

        def validate(payload: bytes) -> None:
            with (
                mock.patch.object(
                    verify,
                    "_framework_recovery_3_validate_local_resource_profile",
                ),
            ):
                verify._framework_recovery_3_verify_local_log(
                    Path("."),
                    "a" * 40,
                    payload,
                    test_contract=contract,
                    resource_started_at_utc="2026-07-24T00:00:00Z",
                    resource_completed_at_utc="2026-07-24T00:00:01Z",
                )

        validate(clean)
        mutations = (
            clean.replace(b"Ran 83 tests", b"Ran 82 tests", 1),
            clean.replace(
                b"P0-R exit gate: 30 passed, 0 failed",
                b"P0-R exit gate: 29 passed, 1 failed",
                1,
            ),
            clean.replace(
                b"verify-current-audit: OK",
                b"ResourceWarning\nverify-current-audit: OK",
                1,
            ),
            clean.replace(
                b"=== P0R_EXIT_GATE ===",
                b"=== RESOURCE_PROFILE ===",
                1,
            ),
        )
        for index, mutation in enumerate(mutations):
            with (
                self.subTest(index=index),
                self.assertRaisesRegex(
                    verify.CurrentAuditError,
                    "CURRENT_AUDIT_FRAMEWORK_RECOVERY_3_LOCAL_LOG",
                ),
            ):
                validate(mutation)

    def test_framework_recovery_3_review_keys_are_purpose_separated(
        self,
    ) -> None:
        verify = _load_verify()
        source = {
            "public_key": "source-key",
            "key_fingerprint": "source-fingerprint",
        }
        reviews = [
            {
                "public_key": "review-key-1",
                "key_fingerprint": "review-fingerprint-1",
            },
            {
                "public_key": "review-key-2",
                "key_fingerprint": "review-fingerprint-2",
            },
        ]
        verify._framework_recovery_3_verify_review_key_separation(
            source,
            reviews,
        )
        mutations = (
            reviews[:1],
            [reviews[0], copy.deepcopy(reviews[0])],
            [
                reviews[0],
                {
                    "public_key": "source-key",
                    "key_fingerprint": "review-fingerprint-2",
                },
            ],
            [
                reviews[0],
                {
                    "public_key": "review-key-2",
                    "key_fingerprint": "source-fingerprint",
                },
            ],
        )
        for index, mutation in enumerate(mutations):
            with (
                self.subTest(index=index),
                self.assertRaisesRegex(
                    verify.CurrentAuditError,
                    "CURRENT_AUDIT_FRAMEWORK_RECOVERY_3_REVIEW_KEY_SEPARATION",
                ),
            ):
                verify._framework_recovery_3_verify_review_key_separation(
                    source,
                    mutation,
                )

    def test_framework_recovery_3_expected_qualification_keeps_fr_0002_invalid(
        self,
    ) -> None:
        verify = _load_verify()
        catalog = [
            {"id": "FR-0003-E01", "file": "reproduction"},
            {"id": "FR-0003-E02", "file": "metadata"},
        ]
        hosted = {"repair_ci": {}, "repair_formal": {}}
        plan = {
            "retired_recovery": {
                "recovery_id": "FR-0002",
                "state_after": "ABORTED_BEFORE_QUALIFICATION",
            },
            "source_retention": {"byte_exact": True},
            "test_contract": {"fr_0003_count": 58},
            "registered_snapshot_materialization": {
                "scope": "EXACT_CH-T001_EPOCH_2_REGISTRATION_ONLY"
            },
        }
        with (
            mock.patch.object(
                verify,
                "_signed_commit_binding",
                return_value={"commit": "a" * 40},
            ),
            mock.patch.object(
                verify,
                "_commit_regular_file_record",
                side_effect=commit_file_record,
            ),
            mock.patch.object(
                verify,
                "_framework_recovery_3_run_attempt_identity",
                side_effect=((10, 1), (11, 1)),
            ),
        ):
            qualification = verify._framework_recovery_3_expected_qualification(
                Path("."),
                "a" * 40,
                "b" * 40,
                plan=plan,
                evidence_catalog=catalog,
                hosted_evidence=hosted,
                review_records=[],
            )
        self.assertEqual(
            qualification["retired_recovery"]["state_after"],
            "ABORTED_BEFORE_QUALIFICATION",
        )
        self.assertFalse(
            qualification["assurance_boundary"][
                "fr_0002_qualification_reclassified_as_valid"
            ]
        )
        self.assertEqual(
            qualification["decision"]["active_framework_epoch"],
            2,
        )
        self.assertIsNone(qualification["persistent_identifier"])
        self.assertNotIn("resource_profile_precondition", qualification)
        self.assertEqual(
            qualification["registered_snapshot_materialization"],
            plan["registered_snapshot_materialization"],
        )
        self.assertIsNot(
            qualification["registered_snapshot_materialization"],
            plan["registered_snapshot_materialization"],
        )
        self.assertIn(
            "EPOCH_3_REMAINS_ABORTED_AND_CANNOT_BE_REUSED",
            qualification["limitations"],
        )

    def test_framework_recovery_3_expected_activation_changes_only_epoch(
        self,
    ) -> None:
        verify = _load_verify()
        qualification = {
            "evidence_catalog": [],
            "hosted_evidence": {
                "repair_ci": {},
                "repair_formal": {},
            },
            "review_records": [],
            "registered_snapshot_materialization": {
                "scope": "EXACT_CH-T001_EPOCH_2_REGISTRATION_ONLY"
            },
            "assurance_boundary": {
                "fr_0002_qualification_reclassified_as_valid": False,
            },
        }
        hosted = {"qualification_ci": {}, "qualification_formal": {}}
        with (
            mock.patch.object(
                verify,
                "_signed_commit_binding",
                return_value={"commit": "b" * 40},
            ),
            mock.patch.object(
                verify,
                "_commit_regular_file_record",
                side_effect=commit_file_record,
            ),
            mock.patch.object(
                verify,
                "_framework_recovery_3_run_attempt_identity",
                side_effect=((10, 1), (11, 1), (12, 1), (13, 1)),
            ),
        ):
            activation = verify._framework_recovery_3_expected_activation(
                Path("."),
                "a" * 40,
                "b" * 40,
                "c" * 40,
                qualification=qualification,
                evidence_catalog=[],
                hosted_evidence=hosted,
            )
        self.assertEqual(activation["decision"]["active_framework_epoch"], 4)
        self.assertFalse(activation["decision"]["runtime_authority_changed"])
        self.assertFalse(activation["decision"]["release_authority_changed"])
        self.assertIsNone(activation["persistent_identifier"])
        self.assertNotIn("resource_profile_precondition", activation)
        self.assertEqual(
            activation["registered_snapshot_materialization"],
            qualification["registered_snapshot_materialization"],
        )
        self.assertIsNot(
            activation["registered_snapshot_materialization"],
            qualification["registered_snapshot_materialization"],
        )
        self.assertEqual(
            activation["effective_on"],
            ("SIGNED_COMMIT_FIRST_CONTAINING_THIS_EXACT_ACTIVATION_RECORD"),
        )

    def test_framework_recovery_3_stage_commit_parent_subject_and_scope(
        self,
    ) -> None:
        verify = _load_verify()
        stages = (
            (
                verify._verify_framework_recovery_3_qualification,
                "b" * 40,
                "a" * 40,
                verify.FRAMEWORK_RECOVERY_3_QUALIFICATION_STATUSES,
                "FRAMEWORK_RECOVERY_3_QUALIFICATION",
                verify.FRAMEWORK_RECOVERY_3_QUALIFICATION_SUBJECT,
                {"plan": True},
            ),
            (
                verify._verify_framework_recovery_3_activation,
                "c" * 40,
                "b" * 40,
                verify.FRAMEWORK_RECOVERY_3_ACTIVATION_STATUSES,
                "FRAMEWORK_RECOVERY_3_ACTIVATION",
                verify.FRAMEWORK_RECOVERY_3_ACTIVATION_SUBJECT,
                {"qualification": True},
            ),
        )
        for (
            validator,
            commit,
            parent,
            statuses,
            label,
            subject,
            context,
        ) in stages:
            with (
                self.subTest(label=label),
                mock.patch.object(
                    verify,
                    "_verify_data_only_commit",
                    return_value={"subject": "wrong"},
                ) as data_only,
                self.assertRaises(verify.CurrentAuditError),
            ):
                if label.endswith("QUALIFICATION"):
                    validator(
                        Path("."),
                        parent,
                        commit,
                        plan=context,
                    )
                else:
                    validator(
                        Path("."),
                        "a" * 40,
                        parent,
                        commit,
                        qualification=context,
                    )
            self.assertEqual(data_only.call_args.kwargs["commit"], commit)
            self.assertEqual(data_only.call_args.kwargs["parent"], parent)
            self.assertEqual(
                data_only.call_args.kwargs["expected_statuses"],
                dict(sorted(statuses.items())),
            )
            self.assertEqual(data_only.call_args.kwargs["label"], label)
            self.assertNotEqual(data_only.return_value["subject"], subject)

    def test_framework_recovery_3_signature_namespaces_are_unique(
        self,
    ) -> None:
        verify = _load_verify()
        source = (
            Path(__file__)
            .with_name("verify-current-audit.py")
            .read_text(encoding="utf-8")
        )
        functions = {
            node.name: node
            for node in parse(source).body
            if isinstance(node, FunctionDef)
        }
        expected = {
            "_verify_framework_recovery_3_repair": (
                "haldir-framework-recovery-fr-0003-plan-v1"
            ),
            "_verify_framework_recovery_3_qualification": (
                "haldir-framework-recovery-fr-0003-qualification-v1"
            ),
            "_verify_framework_recovery_3_activation": (
                "haldir-framework-recovery-fr-0003-activation-v1"
            ),
            "_validate_framework_recovery_3_review": (
                "haldir-framework-recovery-fr-0003-local-integrity-v1"
            ),
        }
        observed = {}
        for name, namespace in expected.items():
            calls = [
                node
                for node in walk(functions[name])
                if (
                    isinstance(node, Call)
                    and isinstance(node.func, Name)
                    and node.func.id == "_verify_ssh_detached_attestation"
                )
            ]
            self.assertEqual(len(calls), 1)
            keyword = next(
                item for item in calls[0].keywords if item.arg == "namespace"
            )
            self.assertEqual(keyword.value.value, namespace)
            observed[name] = keyword.value.value
        self.assertEqual(len(set(observed.values())), len(observed))
        self.assertEqual(
            set(observed.values()),
            set(expected.values()),
        )
        self.assertEqual(verify.FRAMEWORK_RECOVERY_3_ID, "FR-0003")

    def test_framework_recovery_3_review_rejects_false_provenance(
        self,
    ) -> None:
        verify = _load_verify()
        contracts = verify._framework_recovery_3_review_contracts()
        covered_functions = {
            function
            for contract_mapping in contracts.values()
            for finding in contract_mapping.values()
            for function in finding["affected_functions"]
        }
        self.assertTrue(
            {
                "_registered_snapshot_materialization_applies",
                "_registered_snapshot_materialization_receipt",
                "_registered_snapshot_materialization_payload",
                "_registered_image_state",
                "_make_snapshot_world_readable",
                "_run_registered_container",
                "_run_registered_verifier_v2",
                "_framework_recovery_3_validate_local_resource_profile",
                "_load_verifier",
                "generate_profile",
                "_expected_case_specs",
                "_validate_fixture",
                "validate_profile",
            }.issubset(covered_functions)
        )
        self.assertIn(
            "MATERIALIZATION_AVAILABILITY_REQUIRES_TWO_DAEMON_CPUS",
            verify._framework_recovery_3_review_limitations(),
        )
        self.assertIn(
            "MATERIALIZATION_AVAILABILITY_REQUIRES_1280_MIB_DAEMON_MEMORY",
            verify._framework_recovery_3_review_limitations(),
        )
        self.assertIn(
            "BIND_MOUNT_COMPARATIVE_PERFORMANCE_IS_NOT_QUALIFICATION_EVIDENCE",
            verify._framework_recovery_3_review_limitations(),
        )
        self.assertIn(
            "MAXIMUM_MATERIALIZATION_BOUNDARY_AVAILABILITY_IS_NOT_UNIVERSAL",
            verify._framework_recovery_3_review_limitations(),
        )
        self.assertIn(
            (
                "MATERIALIZATION_ADDS_DIRECTORY_DEPTH_64_AND_"
                "FILE_DEPTH_65_CONSTRAINTS"
            ),
            verify._framework_recovery_3_review_limitations(),
        )
        self.assertIn(
            "MATERIALIZATION_RESOURCE_PROFILE_USES_METADATA_ONLY_RECEIPT_FIXTURES",
            verify._framework_recovery_3_review_limitations(),
        )
        self.assertIn(
            "HOST_SNAPSHOT_HASHING_READS_EACH_FILE_INTO_BOUNDED_MEMORY",
            verify._framework_recovery_3_review_limitations(),
        )
        review_id = "FR-0003-R01"
        kind = "INTERNAL_AUTOMATED_DESIGN_REVIEW"
        contract = contracts[review_id]
        required_ids = {
            test_id
            for mapping in contract.values()
            for test_id in mapping["resolving_test_ids"]
        }
        plan = {
            "code_diff": {"patch_sha256": "0" * 64},
            "source_retention": {"byte_exact": True},
            "transition_identity": (verify._framework_recovery_3_transition_identity()),
            "test_contract": {
                "required_regression_test_ids": sorted(required_ids),
            },
        }
        narratives = {
            finding_id: {
                "summary": f"{finding_id} summary",
                "disposition": f"{finding_id} disposition",
            }
            for finding_id in contract
        }
        unsigned = verify._framework_recovery_3_expected_review(
            review_id=review_id,
            kind=kind,
            repair_commit="a" * 40,
            plan=plan,
            narratives=narratives,
        )
        value = {
            **copy.deepcopy(unsigned),
            "detached_signature": {"signature": "fixture"},
        }
        with mock.patch.object(
            verify,
            "_verify_ssh_detached_attestation",
            return_value={
                "public_key": "review-key",
                "key_fingerprint": "review-fingerprint",
            },
        ):
            key = verify._validate_framework_recovery_3_review(
                Path("."),
                value,
                review_id=review_id,
                kind=kind,
                repair_commit="a" * 40,
                plan=plan,
            )
        self.assertEqual(key["public_key"], "review-key")
        mutations = (
            ("human_review_performed", True),
            ("named_human_review_performed", True),
            ("external_independence", True),
            ("release_authority", True),
            ("capture_key_role", "REVIEW_APPROVAL"),
        )
        for field, replacement in mutations:
            candidate = copy.deepcopy(value)
            candidate["reviewer"][field] = replacement
            with (
                self.subTest(field=field),
                self.assertRaisesRegex(
                    verify.CurrentAuditError,
                    "CURRENT_AUDIT_FRAMEWORK_RECOVERY_3_REVIEW_INVALID",
                ),
            ):
                verify._validate_framework_recovery_3_review(
                    Path("."),
                    candidate,
                    review_id=review_id,
                    kind=kind,
                    repair_commit="a" * 40,
                    plan=plan,
                )

    def test_framework_recovery_3_qualification_chronology_and_signature(
        self,
    ) -> None:
        verify = _load_verify()
        repair_commit = "a" * 40
        qualification_commit = "b" * 40
        hosted = {
            "repair_ci": {"lane": "repair_ci"},
            "repair_formal": {"lane": "repair_formal"},
        }
        expected = {
            "schema_version": "1.0.0",
            "hosted_evidence": hosted,
        }
        plan = {"test_contract": {"fr_0003_count": 77}}
        signer = {
            "principal": "sepmhn@gmail.com",
            "public_key": "ssh-ed25519 source",
            "key_fingerprint": "source-fingerprint",
        }
        review_keys = (
            {
                "public_key": "review-key-1",
                "key_fingerprint": "review-fingerprint-1",
            },
            {
                "public_key": "review-key-2",
                "key_fingerprint": "review-fingerprint-2",
            },
        )

        def run(created_at_utc: str):
            qualification = {
                **copy.deepcopy(expected),
                "created_at_utc": created_at_utc,
                "detached_signature": {"signature": "fixture"},
            }

            def catalog(
                _repo: Path,
                _commit: str,
                requirement: dict[str, Any],
                *,
                subject_commit: str,
                result: str,
            ) -> tuple[dict[str, Any], list[bytes]]:
                self.assertIn(
                    subject_commit,
                    {verify.FRAMEWORK_RECOVERY_3_PARENT, repair_commit},
                )
                self.assertIn(result, {"EXPECTED_DEFECT", "PASS"})
                count = len(requirement["paths"])
                return (
                    {
                        "id": requirement["id"],
                        "files": [{"path": path} for path in requirement["paths"]],
                        "uncompressed": [None] * count,
                    },
                    [b"{}"] * count,
                )

            documents = (
                {"completed_at_utc": "2026-07-24T00:00:01Z"},
                {"completed_at_utc": "2026-07-24T00:00:01Z"},
                {},
                {},
            )
            with (
                mock.patch.object(
                    verify,
                    "_verify_data_only_commit",
                    return_value={
                        "subject": (verify.FRAMEWORK_RECOVERY_3_QUALIFICATION_SUBJECT)
                    },
                ),
                mock.patch.object(
                    verify,
                    "_framework_recovery_3_verify_stage_modes",
                ),
                mock.patch.object(
                    verify,
                    "_read_commit_json",
                    return_value=(
                        qualification,
                        verify._canonical_json_bytes(
                            qualification,
                            pretty=True,
                        ),
                    ),
                ),
                mock.patch.object(
                    verify,
                    "_framework_recovery_2_catalog_record",
                    side_effect=catalog,
                ),
                mock.patch.object(
                    verify,
                    "_load_json_bytes",
                    side_effect=documents,
                ),
                mock.patch.object(
                    verify,
                    "_framework_recovery_3_validate_parent_reproduction",
                ),
                mock.patch.object(
                    verify,
                    "_framework_recovery_3_validate_parent_metadata",
                    return_value=(
                        verify._framework_recovery_3_expected_parent_anomaly()
                    ),
                ),
                mock.patch.object(
                    verify,
                    "_framework_recovery_3_verify_hosted_entry",
                    side_effect=(
                        (hosted["repair_ci"], utc("2026-07-24T00:00:01Z")),
                        (
                            hosted["repair_formal"],
                            utc("2026-07-24T00:00:01Z"),
                        ),
                    ),
                ),
                mock.patch.object(
                    verify,
                    "_framework_recovery_3_verify_ci_markers",
                ),
                mock.patch.object(
                    verify,
                    "_framework_recovery_3_verify_run_attempt_uniqueness",
                ),
                mock.patch.object(
                    verify,
                    "_framework_recovery_3_validate_local_document",
                ),
                mock.patch.object(
                    verify,
                    "_validate_framework_recovery_3_review",
                    side_effect=review_keys,
                ),
                mock.patch.object(
                    verify,
                    "_source_release_signer",
                    return_value=signer,
                ),
                mock.patch.object(
                    verify,
                    "_framework_recovery_3_expected_qualification",
                    return_value=expected,
                ),
                mock.patch.object(
                    verify,
                    "_commit_datetime",
                    side_effect=lambda _repo, commit: (
                        utc("2026-07-24T00:00:00Z")
                        if commit == repair_commit
                        else utc("2026-07-24T00:00:03Z")
                    ),
                ),
                mock.patch.object(
                    verify,
                    "_verify_ssh_detached_attestation",
                ) as attestation,
            ):
                result = verify._verify_framework_recovery_3_qualification(
                    Path("."),
                    repair_commit,
                    qualification_commit,
                    plan=plan,
                )
            return result, attestation

        result, attestation = run("2026-07-24T00:00:02Z")
        self.assertEqual(result["created_at_utc"], "2026-07-24T00:00:02Z")
        self.assertEqual(
            attestation.call_args.kwargs["namespace"],
            "haldir-framework-recovery-fr-0003-qualification-v1",
        )
        with self.assertRaisesRegex(
            verify.CurrentAuditError,
            "CURRENT_AUDIT_FRAMEWORK_RECOVERY_3_QUALIFICATION_CHRONOLOGY",
        ):
            run("2026-07-24T00:00:04Z")

    def test_framework_recovery_3_activation_chronology_and_signature(
        self,
    ) -> None:
        verify = _load_verify()
        repair_commit = "a" * 40
        qualification_commit = "b" * 40
        activation_commit = "c" * 40
        hosted = {
            "qualification_ci": {"lane": "qualification_ci"},
            "qualification_formal": {"lane": "qualification_formal"},
        }
        expected = {
            "schema_version": "1.0.0",
            "activation_hosted_evidence": hosted,
        }
        qualification = {
            "test_contract": {"fr_0003_count": 77},
            "hosted_evidence": {
                "repair_ci": {},
                "repair_formal": {},
            },
        }
        signer = {
            "principal": "sepmhn@gmail.com",
            "public_key": "ssh-ed25519 source",
            "key_fingerprint": "source-fingerprint",
        }

        def run(created_at_utc: str):
            activation = {
                **copy.deepcopy(expected),
                "created_at_utc": created_at_utc,
                "detached_signature": {"signature": "fixture"},
            }
            with (
                mock.patch.object(
                    verify,
                    "_verify_data_only_commit",
                    return_value={
                        "subject": (verify.FRAMEWORK_RECOVERY_3_ACTIVATION_SUBJECT)
                    },
                ),
                mock.patch.object(
                    verify,
                    "_framework_recovery_3_verify_stage_modes",
                ),
                mock.patch.object(
                    verify,
                    "_read_commit_json",
                    return_value=(
                        activation,
                        verify._canonical_json_bytes(
                            activation,
                            pretty=True,
                        ),
                    ),
                ),
                mock.patch.object(
                    verify,
                    "_framework_recovery_2_catalog_record",
                    side_effect=(
                        ({"id": "FR-0003-A01"}, [b"{}"]),
                        ({"id": "FR-0003-A02"}, [b"{}"]),
                    ),
                ),
                mock.patch.object(
                    verify,
                    "_framework_recovery_3_verify_hosted_entry",
                    side_effect=(
                        (
                            hosted["qualification_ci"],
                            utc("2026-07-24T00:00:01Z"),
                        ),
                        (
                            hosted["qualification_formal"],
                            utc("2026-07-24T00:00:01Z"),
                        ),
                    ),
                ),
                mock.patch.object(
                    verify,
                    "_framework_recovery_3_verify_ci_markers",
                ),
                mock.patch.object(
                    verify,
                    "_framework_recovery_3_verify_run_attempt_uniqueness",
                ),
                mock.patch.object(
                    verify,
                    "_framework_recovery_3_expected_activation",
                    return_value=expected,
                ),
                mock.patch.object(
                    verify,
                    "_commit_datetime",
                    side_effect=lambda _repo, commit: (
                        utc("2026-07-24T00:00:00Z")
                        if commit == qualification_commit
                        else utc("2026-07-24T00:00:03Z")
                    ),
                ),
                mock.patch.object(
                    verify,
                    "_source_release_signer",
                    return_value=signer,
                ),
                mock.patch.object(
                    verify,
                    "_verify_ssh_detached_attestation",
                ) as attestation,
            ):
                result = verify._verify_framework_recovery_3_activation(
                    Path("."),
                    repair_commit,
                    qualification_commit,
                    activation_commit,
                    qualification=qualification,
                )
            return result, attestation

        result, attestation = run("2026-07-24T00:00:02Z")
        self.assertEqual(result["created_at_utc"], "2026-07-24T00:00:02Z")
        self.assertEqual(
            attestation.call_args.kwargs["namespace"],
            "haldir-framework-recovery-fr-0003-activation-v1",
        )
        with self.assertRaisesRegex(
            verify.CurrentAuditError,
            "CURRENT_AUDIT_FRAMEWORK_RECOVERY_3_ACTIVATION_CHRONOLOGY",
        ):
            run("2026-07-24T00:00:04Z")


class FrameworkRecovery3HistoryAndWrapperTests(unittest.TestCase):
    """Require retirement, contiguous activation, and epoch-aware wrappers."""

    def test_framework_recovery_3_retires_fr_0002_without_qualification(
        self,
    ) -> None:
        verify = _load_verify()
        repair_commit = "a" * 40
        chain = [*framework_history_prefix(), repair_commit, "b" * 40, "c" * 40]
        metadata = {
            "parent": verify.FRAMEWORK_RECOVERY_3_PARENT,
            "subject": verify.FRAMEWORK_RECOVERY_3_SUBJECT,
        }
        with (
            mock.patch.object(
                verify,
                "_verify_framework_recovery_2_repair",
                return_value={"plan": "fr2"},
            ),
            mock.patch.object(
                verify,
                "_commit_metadata",
                return_value=metadata,
            ),
            mock.patch.object(
                verify,
                "_verify_framework_recovery_3_repair",
                return_value={"plan": "fr3"},
            ) as fr3_repair,
            mock.patch.object(
                verify,
                "_verify_framework_recovery_2_qualification",
                side_effect=AssertionError("FR-0002 was qualified"),
            ) as fr2_qualification,
            mock.patch.object(
                verify,
                "_verify_framework_recovery_2_activation",
                side_effect=AssertionError("FR-0002 was activated"),
            ) as fr2_activation,
        ):
            result = verify._verify_framework_recovery_2_history(
                Path("."),
                chain,
                framework_commit="d" * 40,
            )
        self.assertEqual(result["state"], "ABORTED_BEFORE_QUALIFICATION")
        self.assertEqual(result["retirement_commit"], repair_commit)
        self.assertIsNone(result["qualification_commit"])
        self.assertIsNone(result["activation_commit"])
        self.assertIsNone(result["qualification"])
        fr3_repair.assert_called_once()
        fr2_qualification.assert_not_called()
        fr2_activation.assert_not_called()

    def test_framework_recovery_3_retirement_requires_authenticated_r3_repair(
        self,
    ) -> None:
        verify = _load_verify()
        repair_commit = "a" * 40
        chain = [*framework_history_prefix(), repair_commit]
        metadata = {
            "parent": verify.FRAMEWORK_RECOVERY_3_PARENT,
            "subject": verify.FRAMEWORK_RECOVERY_3_SUBJECT,
        }
        with (
            mock.patch.object(
                verify,
                "_verify_framework_recovery_2_repair",
                return_value={"plan": "fr2"},
            ),
            mock.patch.object(
                verify,
                "_commit_metadata",
                return_value=metadata,
            ),
            mock.patch.object(
                verify,
                "_verify_framework_recovery_3_repair",
                side_effect=verify.CurrentAuditError("invalid signed R3"),
            ),
            mock.patch.object(
                verify,
                "_verify_framework_recovery_2_qualification",
            ) as fr2_qualification,
            self.assertRaisesRegex(
                verify.CurrentAuditError,
                "invalid signed R3",
            ),
        ):
            verify._verify_framework_recovery_2_history(
                Path("."),
                chain,
                framework_commit="d" * 40,
            )
        fr2_qualification.assert_not_called()

    def test_framework_recovery_3_history_states_are_contiguous(self) -> None:
        verify = _load_verify()
        repair_commit = "a" * 40
        qualification_commit = "b" * 40
        activation_commit = "c" * 40
        plan = {"plan": True}
        qualification = {"qualification": True}

        def qualify(
            _repo: Path,
            observed_repair: str,
            observed_qualification: str,
            *,
            plan: dict[str, Any],
        ) -> dict[str, Any]:
            self.assertEqual(observed_repair, repair_commit)
            self.assertEqual(observed_qualification, qualification_commit)
            self.assertEqual(plan, {"plan": True})
            return qualification

        def activate(
            _repo: Path,
            observed_repair: str,
            observed_qualification: str,
            observed_activation: str,
            *,
            qualification: dict[str, Any],
        ) -> dict[str, Any]:
            self.assertEqual(observed_repair, repair_commit)
            self.assertEqual(observed_qualification, qualification_commit)
            self.assertEqual(observed_activation, activation_commit)
            self.assertEqual(qualification, {"qualification": True})
            return {"activation": True}

        with (
            mock.patch.object(
                verify,
                "_verify_framework_recovery_3_repair",
                return_value=plan,
            ),
            mock.patch.object(
                verify,
                "_verify_framework_recovery_3_qualification",
                side_effect=qualify,
            ),
            mock.patch.object(
                verify,
                "_verify_framework_recovery_3_activation",
                side_effect=activate,
            ),
        ):
            pending = verify._verify_framework_recovery_3_history(
                Path("."),
                [*framework_history_prefix(), repair_commit],
                framework_commit="d" * 40,
            )
            qualified = verify._verify_framework_recovery_3_history(
                Path("."),
                [
                    *framework_history_prefix(),
                    repair_commit,
                    qualification_commit,
                ],
                framework_commit="d" * 40,
            )
            active = verify._verify_framework_recovery_3_history(
                Path("."),
                [
                    *framework_history_prefix(),
                    repair_commit,
                    qualification_commit,
                    activation_commit,
                    "e" * 40,
                ],
                framework_commit="d" * 40,
            )
        self.assertEqual(pending["state"], "PENDING_QUALIFICATION")
        self.assertEqual(pending["active_framework_epoch"], 2)
        self.assertFalse(pending["successor_transitions_allowed"])
        self.assertEqual(
            qualified["state"],
            "QUALIFIED_PENDING_ACTIVATION",
        )
        self.assertEqual(qualified["active_framework_epoch"], 2)
        self.assertFalse(qualified["successor_transitions_allowed"])
        self.assertEqual(active["state"], "ACTIVE")
        self.assertEqual(active["candidate_framework_epoch"], 4)
        self.assertEqual(active["active_framework_epoch"], 4)
        self.assertTrue(active["successor_transitions_allowed"])

    def test_framework_recovery_3_rejects_successor_before_activation(
        self,
    ) -> None:
        verify = _load_verify()
        repair_commit = "a" * 40
        qualification_commit = "b" * 40
        unrelated = "e" * 40

        def qualify(
            _repo: Path,
            _repair: str,
            candidate: str,
            *,
            plan: dict[str, Any],
        ) -> dict[str, Any]:
            self.assertEqual(plan, {"plan": True})
            if candidate != qualification_commit:
                raise verify.CurrentAuditError(
                    "CURRENT_AUDIT_FRAMEWORK_RECOVERY_3_SUCCESSOR_BEFORE_ACTIVATION"
                )
            return {"qualification": True}

        with (
            mock.patch.object(
                verify,
                "_verify_framework_recovery_3_repair",
                return_value={"plan": True},
            ),
            mock.patch.object(
                verify,
                "_verify_framework_recovery_3_qualification",
                side_effect=qualify,
            ),
            self.assertRaisesRegex(
                verify.CurrentAuditError,
                "CURRENT_AUDIT_FRAMEWORK_RECOVERY_3_SUCCESSOR_BEFORE_ACTIVATION",
            ),
        ):
            verify._verify_framework_recovery_3_history(
                Path("."),
                [
                    *framework_history_prefix(),
                    repair_commit,
                    unrelated,
                    qualification_commit,
                ],
                framework_commit="d" * 40,
            )

    def test_framework_recovery_3_history_requires_exact_parent_position(
        self,
    ) -> None:
        verify = _load_verify()
        chain = framework_history_prefix()
        mutations = (
            chain[1:],
            [*chain[:21], "f" * 40, *chain[22:], "a" * 40],
            [*chain[:22], "f" * 40, "a" * 40],
        )
        for index, mutation in enumerate(mutations):
            with (
                self.subTest(index=index),
                self.assertRaisesRegex(
                    verify.CurrentAuditError,
                    ("CURRENT_AUDIT_FRAMEWORK_RECOVERY_3_(?:PARENT_MISSING|POSITION)"),
                ),
            ):
                verify._verify_framework_recovery_3_history(
                    Path("."),
                    mutation,
                    framework_commit="d" * 40,
                )

    def test_framework_recovery_3_wrapper_selects_epochs_2_3_and_4(
        self,
    ) -> None:
        verify = _load_verify()
        repo = Path(__file__).resolve().parents[2]
        verify._verify_post_activation_gate_retention(
            repo,
            verify.FRAMEWORK_RECOVERY_2_PARENT,
            framework_epoch=2,
            compare_worktree=False,
        )
        verify._verify_post_activation_gate_retention(
            repo,
            verify.FRAMEWORK_RECOVERY_3_PARENT,
            framework_epoch=3,
            compare_worktree=False,
        )
        original_git_file = verify._git_file
        original_tree_entry = verify._git_tree_entry
        wrapper_path = "tools/release/current-audit-gate.sh"

        def git_file(_repo: Path, commit: str, path: str) -> bytes:
            if path == wrapper_path:
                return verify._framework_recovery_3_expected_gate_payload()
            return original_git_file(_repo, commit, path)

        def tree_entry(
            _repo: Path,
            commit: str,
            path: str,
        ) -> dict[str, Any] | None:
            if path == wrapper_path:
                return {
                    "mode": "100755",
                    "type": "blob",
                    "oid": "epoch-4-wrapper",
                }
            return original_tree_entry(_repo, commit, path)

        with (
            mock.patch.object(verify, "_git_file", side_effect=git_file),
            mock.patch.object(
                verify,
                "_git_tree_entry",
                side_effect=tree_entry,
            ),
        ):
            verify._verify_post_activation_gate_retention(
                repo,
                verify.FRAMEWORK_RECOVERY_3_PARENT,
                framework_epoch=4,
                compare_worktree=False,
            )
            verify._verify_post_activation_gate_retention(
                repo,
                verify.FRAMEWORK_RECOVERY_3_PARENT,
                compare_worktree=False,
            )
        self.assertEqual(
            verify._framework_recovery_3_expected_gate_payload(),
            Path(__file__).with_name("current-audit-gate.sh").read_bytes(),
        )

    def test_framework_recovery_3_wrapper_rejects_invalid_epoch_values(
        self,
    ) -> None:
        verify = _load_verify()
        for epoch in (0, 1, 5, True, 4.0, "4"):
            with (
                self.subTest(epoch=epoch),
                self.assertRaisesRegex(
                    verify.CurrentAuditError,
                    "CURRENT_AUDIT_POST_ACTIVATION_EPOCH_INVALID",
                ),
            ):
                verify._verify_post_activation_gate_retention(
                    Path("."),
                    "a" * 40,
                    framework_epoch=epoch,
                    compare_worktree=False,
                )

    def test_framework_recovery_3_historical_wrapper_ignores_worktree(
        self,
    ) -> None:
        verify = _load_verify()
        repo = Path(__file__).resolve().parents[2]
        with mock.patch.object(
            verify,
            "_read_repo_relative_bounded",
            side_effect=AssertionError("historical replay read worktree"),
        ) as reader:
            verify._verify_post_activation_gate_retention(
                repo,
                verify.FRAMEWORK_RECOVERY_3_PARENT,
                framework_epoch=3,
                compare_worktree=False,
            )
        reader.assert_not_called()

    def test_framework_recovery_3_forward_history_has_pre_activation_guard(
        self,
    ) -> None:
        source = (
            Path(__file__)
            .with_name("verify-current-audit.py")
            .read_text(encoding="utf-8")
        )
        tree = parse(source)
        function = next(
            node
            for node in tree.body
            if (
                isinstance(node, FunctionDef)
                and node.name == "_verify_forward_protocol_history"
            )
        )
        literals = {
            node.value
            for node in walk(function)
            if isinstance(node, Constant) and isinstance(node.value, str)
        }
        self.assertIn(
            "CURRENT_AUDIT_FRAMEWORK_RECOVERY_3_SUCCESSOR_BEFORE_ACTIVATION",
            literals,
        )


if __name__ == "__main__":
    unittest.main()
