#!/usr/bin/env python3
"""Test the FR-0005 hosted-attempt recovery."""

from __future__ import annotations

import ast
import copy
import hashlib
import importlib.util
import inspect
import subprocess
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock


PARENT_COMMIT = "4abfad7f2030257e7499d18f9502087b20dec04b"
PARENT_TREE = "cad764cec0c2e73e5d6ee68392aebcb94507f54d"
LIVE_CI_RUN = 30_113_826_853
LIVE_FORMAL_RUN = 30_113_827_036
REQUIRED_TEST_IDS = {
    "test_framework_recovery_5_activation_scope_is_exact",
    "test_framework_recovery_5_anomaly_manifest_binds_exact_attempt",
    "test_framework_recovery_5_attempt_created_at_is_bound",
    "test_framework_recovery_5_attempt_url_binds_exact_attempt",
    "test_framework_recovery_5_capture_commands_bind_exact_attempt",
    "test_framework_recovery_5_code_diff_excludes_plan",
    "test_framework_recovery_5_decision_is_fail_closed",
    "test_framework_recovery_5_defect_reproduction_is_exact",
    "test_framework_recovery_5_dynamic_attempt_accepts_positive_integer",
    "test_framework_recovery_5_dynamic_attempt_rejects_bool_zero_and_negative",
    "test_framework_recovery_5_epoch_5_is_not_reusable",
    "test_framework_recovery_5_evidence_signatures_and_chronology_are_bound",
    "test_framework_recovery_5_expected_gate_payload_is_exact",
    "test_framework_recovery_5_expected_plan_has_exact_fields",
    "test_framework_recovery_5_forward_replay_has_pre_activation_guard",
    "test_framework_recovery_5_history_requires_exact_position",
    "test_framework_recovery_5_hosted_entries_bind_subject_event_and_workflow",
    "test_framework_recovery_5_identity_constants_are_exact",
    "test_framework_recovery_5_input_is_not_mutated",
    "test_framework_recovery_5_legacy_attempt_default_remains_one",
    "test_framework_recovery_5_local_markers_reject_missing_suite",
    "test_framework_recovery_5_materialization_is_inherited",
    "test_framework_recovery_5_parent_bytes_are_pinned",
    "test_framework_recovery_5_parent_has_no_q_or_a",
    "test_framework_recovery_5_parent_rejects_rerun_attempt",
    "test_framework_recovery_5_preserves_prior_test_suites",
    "test_framework_recovery_5_qualification_scope_is_exact",
    "test_framework_recovery_5_rejects_cross_phase_run_attempt_reuse",
    "test_framework_recovery_5_repair_scope_is_exact",
    "test_framework_recovery_5_reserves_parent_run_attempts",
    "test_framework_recovery_5_resource_bounds_are_inherited",
    "test_framework_recovery_5_retires_fr_0004_without_qualification",
    "test_framework_recovery_5_review_contracts_cite_real_tests",
    "test_framework_recovery_5_review_keys_are_separate",
    "test_framework_recovery_5_run_attempt_identity_is_exact_tuple",
    "test_framework_recovery_5_same_run_different_attempt_is_distinct",
    "test_framework_recovery_5_source_retention_projects_all_recoveries",
    "test_framework_recovery_5_source_retention_rejects_parent_pin_drift",
    "test_framework_recovery_5_source_retention_rejects_unrelated_change",
    "test_framework_recovery_5_stage_modes_are_regular",
    "test_framework_recovery_5_successor_requires_activation",
    "test_framework_recovery_5_test_contract_is_warning_strict",
    "test_framework_recovery_5_transition_creates_epoch_6",
    "test_framework_recovery_5_wrapper_accepts_epochs_2_through_6",
}


def _load_verify():
    """Load one isolated verifier module for a test."""

    module_path = Path(__file__).with_name("verify-current-audit.py")
    spec = importlib.util.spec_from_file_location(
        "_fr_0005",
        module_path,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load the current-audit verifier")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _repo() -> Path:
    """Return the repository root."""

    return Path(__file__).resolve().parents[2]


def _git(*arguments: str) -> str:
    """Run one read-only Git query."""

    return (
        subprocess.run(
            ["/usr/bin/git", *arguments],
            cwd=_repo(),
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": "/dev/null",
                "GIT_NO_REPLACE_OBJECTS": "1",
                "LANG": "C",
                "LC_ALL": "C",
                "PATH": "/usr/bin:/bin",
            },
        )
        .stdout.decode("ascii")
        .strip()
    )


def _repair_commit() -> str:
    """Return the first child of the immutable FR-0005 parent."""

    commits = _git(
        "rev-list",
        "--first-parent",
        "--reverse",
        f"{PARENT_COMMIT}..HEAD",
    ).splitlines()
    if not commits:
        raise RuntimeError("FR-0005 repair commit is not present")
    return commits[0]


def _framework_commit(verify) -> str:
    """Return the original framework commit."""

    commits = _git(
        "rev-list",
        "--first-parent",
        "--reverse",
        f"{verify.IMPLEMENTATION_COMMIT}..{_repair_commit()}",
    ).splitlines()
    if not commits:
        raise RuntimeError("framework commit is not present")
    return commits[0]


def _repair_plan(verify) -> dict:
    """Read the canonical signed FR-0005 repair plan."""

    value, _payload = verify._read_commit_json(
        _repo(),
        _repair_commit(),
        verify.FRAMEWORK_RECOVERY_5_PLAN_PATH,
        "fr_0005.test.plan",
    )
    return value


def _function_source(verify, name: str) -> str:
    """Return one complete top-level function source segment."""

    source = Path(verify.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    matches = [
        node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == name
    ]
    if len(matches) != 1 or matches[0].end_lineno is None:
        raise RuntimeError(f"missing unique verifier definition: {name}")
    node = matches[0]
    return "\n".join(source.splitlines()[node.lineno - 1 : node.end_lineno])


def _utc(value: str) -> datetime:
    """Parse one fixed UTC test timestamp."""

    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def _hosted_fixture(verify, attempt_number: int) -> tuple[dict, dict, dict]:
    """Build one synthetic formal run with the live rerun boundary shape."""

    head = "a" * 40
    run_id = LIVE_CI_RUN
    ordinary_created = "2026-07-24T17:39:03Z"
    if attempt_number == 1:
        attempt_created = ordinary_created
        attempt_started = "2026-07-24T17:39:02Z"
        updated = "2026-07-24T17:40:00Z"
    else:
        attempt_created = "2026-07-24T19:01:34Z"
        attempt_started = "2026-07-24T19:01:33Z"
        updated = "2026-07-24T19:38:19Z"
    jobs = [
        {
            "databaseId": 91,
            "name": "tlc-model-check",
            "startedAt": attempt_started,
            "completedAt": updated,
            "conclusion": "success",
            "status": "completed",
            "url": (f"https://github.com/sepahead/haldir/actions/runs/{run_id}/job/91"),
            "steps": [
                {
                    "name": "Model-check HaldirAuthority",
                    "startedAt": attempt_started,
                    "completedAt": updated,
                    "conclusion": "success",
                    "status": "completed",
                    "number": 1,
                }
            ],
        }
    ]
    metadata = {
        "attempt": attempt_number,
        "conclusion": "success",
        "createdAt": ordinary_created,
        "databaseId": run_id,
        "event": "push",
        "headBranch": "main",
        "headSha": head,
        "jobs": copy.deepcopy(jobs),
        "status": "completed",
        "updatedAt": updated,
        "url": f"https://github.com/sepahead/haldir/actions/runs/{run_id}",
        "workflowName": "formal",
    }
    attempt = {
        **copy.deepcopy(metadata),
        "createdAt": attempt_created,
        "startedAt": attempt_started,
        "url": (
            "https://github.com/sepahead/haldir/actions/runs/"
            f"{run_id}/attempts/{attempt_number}"
        ),
        "workflowDatabaseId": verify.EXPECTED_IMPLEMENTATION_RUNS["formal"][
            "workflow_id"
        ],
    }
    paths = ("e/formal.json", "e/formal-attempt.json", "e/formal.log.gz")
    entry = {
        "files": [{"path": path} for path in paths],
        "log_integrity": {},
        "capture_operations": {},
    }
    return metadata, attempt, entry


def _verify_hosted_fixture(
    verify,
    metadata: dict,
    attempt: dict,
    entry: dict,
    *,
    expected_attempt: int,
    policy: str,
) -> list[dict]:
    """Run the shared hosted validator with all non-policy I/O isolated."""

    if policy not in {
        "fr_0005",
        "fr_0005_integrated",
        "legacy",
        "subject_late",
        "containing_early",
    }:
        raise RuntimeError("invalid hosted test policy")
    legacy = policy == "legacy"
    use_real_nested_jobs = policy == "fr_0005_integrated"
    subject_time = (
        "2026-07-24T17:39:04Z" if policy == "subject_late" else "2026-07-24T17:38:00Z"
    )
    containing_time = (
        "2026-07-24T19:38:18Z"
        if policy == "containing_early"
        else "2026-07-24T19:39:00Z"
    )

    payload_by_path = {
        entry["files"][0]["path"]: verify._canonical_json_bytes(metadata),
        entry["files"][1]["path"]: verify._canonical_json_bytes(attempt),
        entry["files"][2]["path"]: b"compressed",
    }

    def read_bound(_repo_path, _commit, record, _label, _limit):
        return payload_by_path[record["path"]]

    def commit_time(_repo_path, commit):
        return _utc(subject_time) if commit == "a" * 40 else _utc(containing_time)

    anomaly = {
        "code": "SYNTHETIC_JOB_BOUNDARY",
        "job_database_id": 91,
        "step_number": 1,
    }
    nested_jobs_patch = (
        mock.patch.object(
            verify,
            "_verify_nested_jobs",
            wraps=verify._verify_nested_jobs,
        )
        if use_real_nested_jobs
        else mock.patch.object(
            verify,
            "_verify_nested_jobs",
            return_value=[anomaly],
        )
    )
    with (
        mock.patch.object(verify, "_read_commit_file_bound", side_effect=read_bound),
        mock.patch.object(verify, "_commit_datetime", side_effect=commit_time),
        nested_jobs_patch,
        mock.patch.object(verify, "_require_gzip_record", return_value={}),
        mock.patch.object(
            verify, "_gzip_as_file_record", return_value=entry["files"][2]
        ),
        mock.patch.object(
            verify,
            "_decode_gzip_evidence",
            return_value=(
                b"a" * 40
                + b"\nModel checking completed. No error has been found.\n"
                + b"Finished in 1s\n"
            ),
        ),
        mock.patch.object(verify, "_verify_capture_operations"),
    ):
        arguments = {
            "expected_head": "a" * 40,
            "workflow": "formal",
            "label": "fr_0005.test.hosted",
        }
        if not legacy:
            arguments.update(
                {
                    "expected_attempt": expected_attempt,
                    "require_ordinary_attempt": True,
                }
            )
        return verify._verify_hosted_evidence_v2(
            Path("."), "b" * 40, entry, **arguments
        )


def _capture_operations(
    run_id: int,
    attempt_number: int,
    paths: tuple[str, str, str],
) -> dict:
    """Build normalized FR-0002 capture operations for one attempt."""

    json_fields = (
        "attempt,conclusion,createdAt,databaseId,event,headBranch,headSha,jobs,"
        "status,updatedAt,url,workflowName"
    )
    attempt_fields = (
        "attempt,conclusion,createdAt,databaseId,event,headBranch,headSha,jobs,"
        "startedAt,status,updatedAt,url,workflowDatabaseId,workflowName"
    )
    ordinary_raw = f"/private/tmp/{Path(paths[0]).name}.raw"
    ordinary_normalized = f"/private/tmp/{Path(paths[0]).name}.normalized"
    attempt_raw = f"/private/tmp/{Path(paths[1]).name}.raw"
    attempt_normalized = f"/private/tmp/{Path(paths[1]).name}.normalized"
    log_raw = f"/private/tmp/{Path(paths[2]).name}.raw"
    decompressed = f"/private/tmp/{Path(paths[2]).name}.decompressed"
    times = iter(
        (
            "2026-07-24T19:38:20Z",
            "2026-07-24T19:38:21Z",
            "2026-07-24T19:38:22Z",
            "2026-07-24T19:38:23Z",
            "2026-07-24T19:38:24Z",
            "2026-07-24T19:38:25Z",
        )
    )

    def common(started: str, completed: str) -> dict:
        return {
            "capture_exit_status": 0,
            "compare_exit_status": 0,
            "byte_equal": True,
            "started_at_utc": started,
            "completed_at_utc": completed,
        }

    ordinary_start, ordinary_end = next(times), next(times)
    attempt_start, attempt_end = next(times), next(times)
    log_start, log_end = next(times), next(times)
    return {
        "ordinary_metadata": {
            "raw_path": ordinary_raw,
            "normalized_path": ordinary_normalized,
            "retained_path": paths[0],
            "capture_command": (
                f"gh run view {run_id} --repo sepahead/haldir --json "
                f"{json_fields} > {ordinary_raw}"
            ),
            "normalize_command": (f"jq -S . {ordinary_raw} > {ordinary_normalized}"),
            "normalize_exit_status": 0,
            "compare_command": f"cmp {ordinary_normalized} {paths[0]}",
            **common(ordinary_start, ordinary_end),
        },
        "attempt_metadata": {
            "raw_path": attempt_raw,
            "normalized_path": attempt_normalized,
            "retained_path": paths[1],
            "capture_command": (
                f"gh run view {run_id} --repo sepahead/haldir --attempt "
                f"{attempt_number} --json {attempt_fields} > {attempt_raw}"
            ),
            "normalize_command": (f"jq -S . {attempt_raw} > {attempt_normalized}"),
            "normalize_exit_status": 0,
            "compare_command": f"cmp {attempt_normalized} {paths[1]}",
            **common(attempt_start, attempt_end),
        },
        "raw_log": {
            "raw_path": log_raw,
            "retained_path": paths[2],
            "decompressed_path": decompressed,
            "capture_command": (
                f"gh run view {run_id} --repo sepahead/haldir --attempt "
                f"{attempt_number} --log > {log_raw}"
            ),
            "compression_command": f"gzip -n -9 -c {log_raw} > {paths[2]}",
            "compression_exit_status": 0,
            "decompress_command": f"gzip -cd {paths[2]} > {decompressed}",
            "decompress_exit_status": 0,
            "compare_command": f"cmp {log_raw} {decompressed}",
            **common(log_start, log_end),
        },
    }


def _run_attempt_entry(verify, run_id: int, attempt_number) -> dict:
    """Build a retained run-attempt entry for the identity validator."""

    metadata = {"databaseId": run_id}
    attempt = {"attempt": attempt_number, "databaseId": run_id}
    return {
        "files": [
            {"path": "e/run.json", "payload": verify._canonical_json_bytes(metadata)},
            {
                "path": "e/run-attempt.json",
                "payload": verify._canonical_json_bytes(attempt),
            },
            {"path": "e/run.log.gz"},
        ]
    }


class FrameworkRecovery5Tests(unittest.TestCase):
    """Keep the epoch-6 hosted-attempt recovery exact."""

    def test_framework_recovery_5_identity_constants_are_exact(self) -> None:
        verify = _load_verify()
        self.assertEqual(verify.FRAMEWORK_RECOVERY_5_PARENT, PARENT_COMMIT)
        self.assertEqual(verify.FRAMEWORK_RECOVERY_5_PARENT_TREE, PARENT_TREE)
        self.assertEqual(verify.FRAMEWORK_RECOVERY_5_ID, "FR-0005")
        self.assertEqual(
            verify.FRAMEWORK_RECOVERY_5_SUBJECT,
            "release: repair hosted attempt validation",
        )
        self.assertEqual(
            verify.FRAMEWORK_RECOVERY_5_QUALIFICATION_SUBJECT,
            "release: qualify epoch-6 audit validation",
        )
        self.assertEqual(
            verify.FRAMEWORK_RECOVERY_5_ACTIVATION_SUBJECT,
            "release: activate epoch-6 audit validation",
        )

    def test_framework_recovery_5_parent_bytes_are_pinned(self) -> None:
        verify = _load_verify()
        verifier = verify._git_file(
            _repo(), PARENT_COMMIT, "tools/release/verify-current-audit.py"
        )
        prior_test = verify._git_file(
            _repo(), PARENT_COMMIT, "tools/release/test_verify_current_audit_fr_0004.py"
        )
        self.assertEqual(
            (len(verifier), hashlib.sha256(verifier).hexdigest()),
            (
                1_019_896,
                "5b430e13ea56154f7879952047b65d69d5d1608e5c1234f197a8d2b5008f4375",
            ),
        )
        self.assertEqual(
            (len(prior_test), hashlib.sha256(prior_test).hexdigest()),
            (
                38_855,
                "d33e0b30586a77717e282947a375253a816ce84b53620cba300f5d30657234f4",
            ),
        )
        self.assertEqual(verify.FRAMEWORK_RECOVERY_5_PARENT_VERIFIER_BYTES, 1_019_896)
        self.assertEqual(verify.FRAMEWORK_RECOVERY_5_PARENT_FR4_TEST_BYTES, 38_855)

    def test_framework_recovery_5_parent_has_no_q_or_a(self) -> None:
        verify = _load_verify()
        for path in (
            verify.FRAMEWORK_RECOVERY_4_QUALIFICATION_PATH,
            verify.FRAMEWORK_RECOVERY_4_ACTIVATION_PATH,
        ):
            with self.subTest(path=path):
                self.assertFalse(verify._git_path_exists(_repo(), PARENT_COMMIT, path))

    def test_framework_recovery_5_defect_reproduction_is_exact(self) -> None:
        verify = _load_verify()
        defect = verify._framework_recovery_5_parent_defect(_repo())
        parent_failure = (
            "CURRENT_AUDIT_HOSTED_IDENTITY_INVALID:framework_recovery_3.repair_ci"
        )
        self.assertEqual(defect["code"], "HOSTED_ATTEMPT_NUMBER_FIXED_TO_ONE")
        self.assertEqual(defect["severity"], "QUALIFICATION_BLOCKER")
        self.assertIsNone(defect["fr_0004_qualification_commit"])
        self.assertIsNone(defect["fr_0004_activation_commit"])
        self.assertTrue(defect["ci_attempt_1_cancelled"])
        self.assertTrue(defect["parent_verifier_rejects_every_attempt_greater_than_1"])
        self.assertEqual(defect["parent_attempt_2_failure_identifier"], parent_failure)
        self.assertEqual(
            defect["fr_0005_augmented_fixture_attempt_2_result"], "ACCEPTED"
        )
        reproduction_log = verify._framework_recovery_5_parent_reproduction_log(_repo())
        self.assertIn(
            f"parent_failure_identifier={parent_failure}\n".encode("ascii"),
            reproduction_log,
        )
        self.assertIn(
            b"fr_0005_augmented_fixture_attempt_2_result=ACCEPTED\n",
            reproduction_log,
        )
        source = _function_source(verify, "_framework_recovery_5_parent_defect")
        for token in (
            "_framework_recovery_2_verify_capture_operations",
            "_framework_recovery_3_verify_hosted_entry",
            "_verify_capture_operations",
            "_verify_hosted_evidence_v2",
            'fixture_label = "framework_recovery_3.repair_ci"',
            "--attempt 1",
            "/attempts/1",
            "augmented_result = current_validator_adapter(",
            "fixture_test_counts = _frozen_test_run_counts(",
            '"fr_0005_augmented_fixture_attempt_2_result": "ACCEPTED"',
        ):
            self.assertIn(token, source)
        self.assertLess(
            source.index("augmented_result = current_validator_adapter("),
            source.index('"fr_0005_augmented_fixture_attempt_2_result": "ACCEPTED"'),
        )
        with (
            mock.patch.object(
                verify, "_hosted_ci_job_names_are_complete", return_value=False
            ),
            self.assertRaisesRegex(
                verify.CurrentAuditError,
                "CURRENT_AUDIT_FRAMEWORK_RECOVERY_5_AUGMENTED_FIXTURE_EXECUTION",
            ),
        ):
            verify._framework_recovery_5_parent_defect(_repo())
        with (
            mock.patch.object(
                verify, "_frozen_test_run_counts", return_value=(164, 26)
            ),
            self.assertRaisesRegex(
                verify.CurrentAuditError,
                "CURRENT_AUDIT_FRAMEWORK_RECOVERY_5_AUGMENTED_FIXTURE_INVALID",
            ),
        ):
            verify._framework_recovery_5_parent_defect(_repo())
        command = verify._framework_recovery_5_parent_reproduction_command()
        self.assertEqual(
            command[-1],
            "FrameworkRecovery5Tests."
            "test_framework_recovery_5_parent_rejects_rerun_attempt",
        )

    def test_framework_recovery_5_parent_rejects_rerun_attempt(self) -> None:
        verify = _load_verify()
        parent_defect = verify._framework_recovery_5_parent_defect(_repo())
        self.assertEqual(
            parent_defect["parent_attempt_2_failure_identifier"],
            "CURRENT_AUDIT_HOSTED_IDENTITY_INVALID:framework_recovery_3.repair_ci",
        )
        metadata, attempt, entry = _hosted_fixture(verify, 2)
        with self.assertRaisesRegex(verify.CurrentAuditError, "HOSTED_IDENTITY"):
            _verify_hosted_fixture(
                verify,
                metadata,
                attempt,
                entry,
                expected_attempt=1,
                policy="fr_0005",
            )
        anomalies = _verify_hosted_fixture(
            verify,
            metadata,
            attempt,
            entry,
            expected_attempt=2,
            policy="fr_0005",
        )
        self.assertEqual({item["attempt"] for item in anomalies}, {2})

        repair_commit = "a" * 40
        qualification_commit = "b" * 40
        started = "2026-07-24T20:00:01Z"
        completed = "2026-07-24T20:00:02Z"
        semantic_log = verify._framework_recovery_5_parent_reproduction_log(_repo())
        complete_log = (
            b".\n" + b"-" * 70 + b"\nRan 1 test in 0.001s\n\nOK\n" + semantic_log
        )

        def file_record(_repo_path, _commit, path):
            return {"path": path}

        with (
            mock.patch.object(
                verify,
                "_framework_recovery_5_parent_defect",
                return_value=parent_defect,
            ),
            mock.patch.object(verify, "_git_file", return_value=b"compressed"),
            mock.patch.object(
                verify, "_decompress_unbound_gzip", return_value=complete_log
            ),
            mock.patch.object(
                verify, "_commit_regular_file_record", side_effect=file_record
            ),
        ):
            reproduction = verify._framework_recovery_5_expected_parent_reproduction(
                Path("."),
                repair_commit,
                qualification_commit,
                defect=parent_defect,
                command=list(
                    verify._framework_recovery_5_parent_reproduction_command()
                ),
                exit_status=0,
                started_at_utc=started,
                completed_at_utc=completed,
            )
        evidence_record = {
            "files": [{}, copy.deepcopy(reproduction["raw_log"]["file"])],
            "uncompressed": [
                {},
                copy.deepcopy(reproduction["raw_log"]["uncompressed"]),
            ],
        }

        def commit_time(_repo_path, commit):
            return (
                _utc("2026-07-24T20:00:00Z")
                if commit == repair_commit
                else _utc("2026-07-24T20:00:03Z")
            )

        with (
            mock.patch.object(
                verify,
                "_framework_recovery_5_parent_defect",
                return_value=parent_defect,
            ),
            mock.patch.object(verify, "_git_file", return_value=b"compressed"),
            mock.patch.object(
                verify, "_decompress_unbound_gzip", return_value=complete_log
            ),
            mock.patch.object(
                verify, "_commit_regular_file_record", side_effect=file_record
            ),
            mock.patch.object(verify, "_commit_datetime", side_effect=commit_time),
        ):
            verify._framework_recovery_5_validate_parent_reproduction(
                Path("."),
                repair_commit,
                qualification_commit,
                reproduction,
                evidence_record=evidence_record,
            )
        wrong_exit = copy.deepcopy(reproduction)
        wrong_exit["exit_status"] = 1
        wrong_test = copy.deepcopy(reproduction)
        wrong_test["test_id"] = "FrameworkRecovery5Tests.wrong"
        wrong_log = copy.deepcopy(reproduction)
        wrong_log["raw_log"]["uncompressed"]["sha256"] = "0" * 64
        for mutation, mutated in (
            ("exit_status", wrong_exit),
            ("test_id", wrong_test),
            ("raw_log", wrong_log),
        ):
            with (
                self.subTest(mutation=mutation),
                mock.patch.object(
                    verify,
                    "_framework_recovery_5_parent_defect",
                    return_value=parent_defect,
                ),
                mock.patch.object(verify, "_git_file", return_value=b"compressed"),
                mock.patch.object(
                    verify, "_decompress_unbound_gzip", return_value=complete_log
                ),
                mock.patch.object(
                    verify, "_commit_regular_file_record", side_effect=file_record
                ),
                mock.patch.object(verify, "_commit_datetime", side_effect=commit_time),
                self.assertRaises(verify.CurrentAuditError),
            ):
                verify._framework_recovery_5_validate_parent_reproduction(
                    Path("."),
                    repair_commit,
                    qualification_commit,
                    mutated,
                    evidence_record=evidence_record,
                )

    def test_framework_recovery_5_dynamic_attempt_accepts_positive_integer(
        self,
    ) -> None:
        verify = _load_verify()
        for attempt_number in (1, 2, 7):
            with self.subTest(attempt=attempt_number):
                metadata, attempt, entry = _hosted_fixture(verify, attempt_number)
                if attempt_number > 2:
                    attempt["createdAt"] = "2026-07-24T19:01:34Z"
                    attempt["startedAt"] = "2026-07-24T19:01:33Z"
                anomalies = _verify_hosted_fixture(
                    verify,
                    metadata,
                    attempt,
                    entry,
                    expected_attempt=attempt_number,
                    policy="fr_0005",
                )
                self.assertEqual(anomalies[0]["attempt"], attempt_number)
                with mock.patch.object(
                    verify,
                    "_read_commit_file_bound",
                    return_value=verify._canonical_json_bytes(
                        {"attempt": attempt_number}
                    ),
                ) as read_attempt:
                    self.assertEqual(
                        verify._framework_recovery_5_positive_attempt(
                            Path("."),
                            "b" * 40,
                            {"path": "e/attempt.json"},
                            label="fr_0005.test.positive",
                        ),
                        attempt_number,
                    )
                    read_attempt.assert_called_once_with(
                        Path("."),
                        "b" * 40,
                        {"path": "e/attempt.json"},
                        "fr_0005.test.positive.attempt",
                        65_536,
                    )
        for function_name in (
            "_framework_recovery_2_verify_capture_operations",
            "_framework_recovery_3_verify_hosted_entry",
            "_verify_capture_operations",
            "_verify_hosted_evidence_v2",
        ):
            parameters = inspect.signature(getattr(verify, function_name)).parameters
            self.assertEqual(parameters["expected_attempt"].default, 1)
            self.assertEqual(parameters["require_ordinary_attempt"].default, False)
        for lane, workflow, selected_attempt in (
            ("repair_ci", "ci", 2),
            ("repair_formal", "formal", 1),
        ):
            expected_result = ({"lane": lane}, _utc("2026-07-24T19:38:25Z"))
            with (
                self.subTest(lane=lane, attempt=selected_attempt),
                mock.patch.object(
                    verify,
                    "_framework_recovery_5_positive_attempt",
                    return_value=selected_attempt,
                ),
                mock.patch.object(
                    verify,
                    "_framework_recovery_3_verify_hosted_entry",
                    return_value=expected_result,
                ) as delegated,
            ):
                result = verify._framework_recovery_5_verify_hosted_entry(
                    Path("."),
                    "b" * 40,
                    {"files": [{}, {"path": "attempt.json"}, {}]},
                    paths=("ordinary.json", "attempt.json", "log.gz"),
                    subject_commit="a" * 40,
                    workflow=workflow,
                    lane=lane,
                )
            self.assertEqual(result, expected_result)
            self.assertEqual(
                delegated.call_args.kwargs["expected_attempt"], selected_attempt
            )
            self.assertIs(delegated.call_args.kwargs["require_ordinary_attempt"], True)

    def test_framework_recovery_5_dynamic_attempt_rejects_bool_zero_and_negative(
        self,
    ) -> None:
        verify = _load_verify()
        metadata, attempt, entry = _hosted_fixture(verify, 1)
        for invalid in (False, True, 0, -1, 1.0, "1"):
            with (
                self.subTest(attempt=invalid),
                self.assertRaisesRegex(verify.CurrentAuditError, "ATTEMPT"),
            ):
                _verify_hosted_fixture(
                    verify,
                    metadata,
                    attempt,
                    entry,
                    expected_attempt=invalid,
                    policy="fr_0005",
                )
            with (
                self.subTest(positive_attempt=invalid),
                mock.patch.object(
                    verify,
                    "_read_commit_file_bound",
                    return_value=verify._canonical_json_bytes({"attempt": invalid}),
                ),
                self.assertRaises(verify.CurrentAuditError),
            ):
                verify._framework_recovery_5_positive_attempt(
                    Path("."),
                    "b" * 40,
                    {"path": "e/attempt.json"},
                    label="fr_0005.test.invalid",
                )
        with (
            mock.patch.object(
                verify,
                "_read_commit_file_bound",
                return_value=verify._canonical_json_bytes(["attempt", 2]),
            ),
            self.assertRaisesRegex(verify.CurrentAuditError, "ATTEMPT_INVALID"),
        ):
            verify._framework_recovery_5_positive_attempt(
                Path("."),
                "b" * 40,
                {"path": "e/attempt.json"},
                label="fr_0005.test.non_object",
            )
        attempt_payload = verify._canonical_json_bytes({"attempt": 2})
        with (
            mock.patch.object(verify, "_git_file", return_value=attempt_payload),
            self.assertRaisesRegex(
                verify.CurrentAuditError, "EVIDENCE_DIGEST_MISMATCH"
            ),
        ):
            verify._framework_recovery_5_positive_attempt(
                Path("."),
                "b" * 40,
                {
                    "path": "e/attempt.json",
                    "bytes": len(attempt_payload),
                    "sha256": "0" * 64,
                },
                label="fr_0005.test.digest_mismatch",
            )
        paths = ("e/a.json", "e/b.json", "e/c.log.gz")
        operations = _capture_operations(91, 1, paths)
        for function in (
            verify._framework_recovery_2_verify_capture_operations,
            verify._verify_capture_operations,
        ):
            for invalid in (False, True, 0, -1):
                with (
                    self.subTest(function=function.__name__, attempt=invalid),
                    self.assertRaises(verify.CurrentAuditError),
                ):
                    function(
                        operations,
                        run_id=91,
                        workflow="formal",
                        paths=paths,
                        head="a" * 40,
                        label="fr_0005.test.invalid_attempt",
                        not_before=_utc("2026-07-24T19:38:19Z"),
                        retained_by=_utc("2026-07-24T19:38:26Z"),
                        expected_attempt=invalid,
                        require_ordinary_attempt=True,
                    )
        for invalid_policy in (0, 1, None, "true"):
            with (
                self.subTest(hosted_policy=invalid_policy),
                self.assertRaises(verify.CurrentAuditError),
            ):
                verify._verify_hosted_evidence_v2(
                    Path("."),
                    "b" * 40,
                    {},
                    expected_head="a" * 40,
                    workflow="formal",
                    label="fr_0005.test.invalid_policy",
                    require_ordinary_attempt=invalid_policy,
                )
            with (
                self.subTest(wrapper_policy=invalid_policy),
                self.assertRaises(verify.CurrentAuditError),
            ):
                verify._framework_recovery_3_verify_hosted_entry(
                    Path("."),
                    "b" * 40,
                    {},
                    paths=paths,
                    subject_commit="a" * 40,
                    workflow="formal",
                    lane="fr_0005.test.invalid_policy",
                    require_ordinary_attempt=invalid_policy,
                )
            for function in (
                verify._framework_recovery_2_verify_capture_operations,
                verify._verify_capture_operations,
            ):
                with (
                    self.subTest(function=function.__name__, policy=invalid_policy),
                    self.assertRaises(verify.CurrentAuditError),
                ):
                    function(
                        operations,
                        run_id=91,
                        workflow="formal",
                        paths=paths,
                        head="a" * 40,
                        label="fr_0005.test.invalid_policy",
                        not_before=_utc("2026-07-24T19:38:19Z"),
                        retained_by=_utc("2026-07-24T19:38:26Z"),
                        require_ordinary_attempt=invalid_policy,
                    )

        with self.assertRaisesRegex(verify.CurrentAuditError, "HOSTED_ATTEMPT_POLICY"):
            verify._verify_hosted_evidence_v2(
                Path("."),
                "b" * 40,
                {},
                expected_head="a" * 40,
                workflow="formal",
                label="fr_0005.test.unbound_attempt",
                expected_attempt=2,
            )
        with self.assertRaisesRegex(
            verify.CurrentAuditError, "FRAMEWORK_RECOVERY_3_HOSTED_ATTEMPT"
        ):
            verify._framework_recovery_3_verify_hosted_entry(
                Path("."),
                "b" * 40,
                {},
                paths=paths,
                subject_commit="a" * 40,
                workflow="formal",
                lane="fr_0005.test.unbound_attempt",
                expected_attempt=2,
            )
        for function in (
            verify._framework_recovery_2_verify_capture_operations,
            verify._verify_capture_operations,
        ):
            with (
                self.subTest(function=function.__name__, policy="unbound_attempt"),
                self.assertRaisesRegex(verify.CurrentAuditError, "ATTEMPT"),
            ):
                function(
                    operations,
                    run_id=91,
                    workflow="formal",
                    paths=paths,
                    head="a" * 40,
                    label="fr_0005.test.unbound_attempt",
                    not_before=_utc("2026-07-24T19:38:19Z"),
                    retained_by=_utc("2026-07-24T19:38:26Z"),
                    expected_attempt=2,
                )

    def test_framework_recovery_5_legacy_attempt_default_remains_one(self) -> None:
        verify = _load_verify()
        metadata, attempt, entry = _hosted_fixture(verify, 1)
        with self.assertRaisesRegex(verify.CurrentAuditError, "HOSTED_FIELDS"):
            _verify_hosted_fixture(
                verify,
                metadata,
                attempt,
                entry,
                expected_attempt=1,
                policy="legacy",
            )
        metadata.pop("attempt")
        attempt["startedAt"] = attempt["createdAt"]
        anomalies = _verify_hosted_fixture(
            verify,
            metadata,
            attempt,
            entry,
            expected_attempt=1,
            policy="legacy",
        )
        self.assertEqual(anomalies[0]["attempt"], 1)
        inverted_metadata, inverted_attempt, inverted_entry = _hosted_fixture(verify, 1)
        inverted_metadata.pop("attempt")
        with self.assertRaisesRegex(verify.CurrentAuditError, "ATTEMPT"):
            _verify_hosted_fixture(
                verify,
                inverted_metadata,
                inverted_attempt,
                inverted_entry,
                expected_attempt=1,
                policy="legacy",
            )
        paths = ("e/legacy.json", "e/legacy-attempt.json", "e/legacy.log.gz")
        legacy_operations = _capture_operations(91, 1, paths)
        legacy_operations["ordinary_metadata"]["capture_command"] = legacy_operations[
            "ordinary_metadata"
        ]["capture_command"].replace("--json attempt,", "--json ", 1)
        compatibility_operations = (
            verify._framework_recovery_2_verify_capture_operations(
                legacy_operations,
                run_id=91,
                workflow="formal",
                paths=paths,
                head="a" * 40,
                label="fr_0005.test.legacy_capture",
                not_before=_utc("2026-07-24T19:38:19Z"),
                retained_by=_utc("2026-07-24T19:38:26Z"),
            )
        )
        self.assertNotIn(
            "--json attempt,",
            compatibility_operations["ordinary_metadata"]["capture_command"],
        )
        verify._verify_capture_operations(
            compatibility_operations,
            run_id=91,
            workflow="formal",
            paths=paths,
            head="a" * 40,
            label="fr_0005.test.legacy_compatibility_capture",
            not_before=_utc("2026-07-24T19:38:19Z"),
            retained_by=_utc("2026-07-24T19:38:26Z"),
        )
        source = _function_source(verify, "_verify_hosted_evidence_v2")
        self.assertIn("require_ordinary_attempt: bool = False", source)
        self.assertIn("expected_attempt: int = 1", source)
        metadata2, attempt2, entry2 = _hosted_fixture(verify, 2)
        metadata2.pop("attempt")
        with self.assertRaisesRegex(verify.CurrentAuditError, "HOSTED_IDENTITY"):
            _verify_hosted_fixture(
                verify,
                metadata2,
                attempt2,
                entry2,
                expected_attempt=1,
                policy="legacy",
            )

    def test_framework_recovery_5_attempt_url_binds_exact_attempt(self) -> None:
        verify = _load_verify()
        for wrong_attempt in (1, 3):
            metadata, attempt, entry = _hosted_fixture(verify, 2)
            attempt["url"] = (
                "https://github.com/sepahead/haldir/actions/runs/"
                f"{LIVE_CI_RUN}/attempts/{wrong_attempt}"
            )
            with (
                self.subTest(url_attempt=wrong_attempt),
                self.assertRaisesRegex(verify.CurrentAuditError, "ATTEMPT_URL"),
            ):
                _verify_hosted_fixture(
                    verify,
                    metadata,
                    attempt,
                    entry,
                    expected_attempt=2,
                    policy="fr_0005",
                )

    def test_framework_recovery_5_attempt_created_at_is_bound(self) -> None:
        verify = _load_verify()
        for attempt_number in (1, 2):
            metadata, attempt, entry = _hosted_fixture(verify, attempt_number)
            _verify_hosted_fixture(
                verify,
                metadata,
                attempt,
                entry,
                expected_attempt=attempt_number,
                policy="fr_0005",
            )
        metadata, attempt, entry = _hosted_fixture(verify, 1)
        with self.subTest(boundary="attempt_1_one_second_start_skew"):
            _verify_hosted_fixture(
                verify,
                metadata,
                attempt,
                entry,
                expected_attempt=1,
                policy="fr_0005_integrated",
            )
        # The one-second start-skew policy also permits this narrow attempt-1
        # boundary: createdAt can be one second later than updatedAt.
        metadata, attempt, entry = _hosted_fixture(verify, 1)
        metadata["updatedAt"] = "2026-07-24T17:39:02Z"
        attempt["updatedAt"] = "2026-07-24T17:39:02Z"
        with self.subTest(boundary="attempt_1_created_after_updated_by_one_second"):
            _verify_hosted_fixture(
                verify,
                metadata,
                attempt,
                entry,
                expected_attempt=1,
                policy="fr_0005",
            )
        metadata, attempt, entry = _hosted_fixture(verify, 1)
        attempt["startedAt"] = "2026-07-24T17:39:01Z"
        metadata["updatedAt"] = "2026-07-24T17:39:01Z"
        attempt["updatedAt"] = "2026-07-24T17:39:01Z"
        with (
            self.subTest(boundary="attempt_1_created_after_updated_by_two_seconds"),
            self.assertRaisesRegex(verify.CurrentAuditError, "ATTEMPT"),
        ):
            _verify_hosted_fixture(
                verify,
                metadata,
                attempt,
                entry,
                expected_attempt=1,
                policy="fr_0005",
            )
        metadata, attempt, entry = _hosted_fixture(verify, 1)
        attempt["createdAt"] = "2026-07-24T17:39:04Z"
        with self.assertRaisesRegex(verify.CurrentAuditError, "ATTEMPT_MISMATCH"):
            _verify_hosted_fixture(
                verify,
                metadata,
                attempt,
                entry,
                expected_attempt=1,
                policy="fr_0005",
            )
        metadata, attempt, entry = _hosted_fixture(verify, 1)
        attempt["startedAt"] = "2026-07-24T17:39:01Z"
        with self.assertRaisesRegex(verify.CurrentAuditError, "ATTEMPT"):
            _verify_hosted_fixture(
                verify,
                metadata,
                attempt,
                entry,
                expected_attempt=1,
                policy="fr_0005_integrated",
            )
        metadata, attempt, entry = _hosted_fixture(verify, 2)
        metadata["updatedAt"] = "2026-07-24T19:38:18Z"
        attempt["updatedAt"] = "2026-07-24T19:38:19Z"
        _verify_hosted_fixture(
            verify,
            metadata,
            attempt,
            entry,
            expected_attempt=2,
            policy="fr_0005",
        )
        _verify_hosted_fixture(
            verify,
            metadata,
            attempt,
            entry,
            expected_attempt=2,
            policy="fr_0005_integrated",
        )
        mutations = (
            ("2026-07-24T17:39:03Z", "2026-07-24T17:39:02Z"),
            ("2026-07-24T19:01:35Z", "2026-07-24T19:01:33Z"),
            ("2026-07-24T17:39:02Z", "2026-07-24T19:01:33Z"),
            ("2026-07-24T19:38:20Z", "2026-07-24T19:01:33Z"),
        )
        for created_at, started_at in mutations:
            metadata, attempt, entry = _hosted_fixture(verify, 2)
            attempt["createdAt"] = created_at
            attempt["startedAt"] = started_at
            with (
                self.subTest(created=created_at, started=started_at),
                self.assertRaisesRegex(verify.CurrentAuditError, "ATTEMPT"),
            ):
                _verify_hosted_fixture(
                    verify,
                    metadata,
                    attempt,
                    entry,
                    expected_attempt=2,
                    policy="fr_0005",
                )
        metadata, attempt, entry = _hosted_fixture(verify, 2)
        metadata["createdAt"] = "2026-07-24T17:37:59Z"
        with self.assertRaisesRegex(verify.CurrentAuditError, "ATTEMPT"):
            _verify_hosted_fixture(
                verify,
                metadata,
                attempt,
                entry,
                expected_attempt=2,
                policy="fr_0005",
            )
        extra_mutations = (
            (
                "start_after_ordinary_update",
                "attempt",
                "startedAt",
                "2026-07-24T19:38:20Z",
            ),
            (
                "ordinary_update_after_attempt_update",
                "metadata",
                "updatedAt",
                "2026-07-24T19:38:20Z",
            ),
            (
                "attempt_created_after_attempt_update",
                "attempt",
                "createdAt",
                "2026-07-24T19:38:20Z",
            ),
        )
        for name, document, field, value in extra_mutations:
            metadata, attempt, entry = _hosted_fixture(verify, 2)
            {"metadata": metadata, "attempt": attempt}[document][field] = value
            with (
                self.subTest(boundary=name),
                self.assertRaisesRegex(verify.CurrentAuditError, "ATTEMPT"),
            ):
                _verify_hosted_fixture(
                    verify,
                    metadata,
                    attempt,
                    entry,
                    expected_attempt=2,
                    policy="fr_0005",
                )
        metadata, attempt, entry = _hosted_fixture(verify, 2)
        with self.assertRaisesRegex(verify.CurrentAuditError, "ATTEMPT"):
            _verify_hosted_fixture(
                verify,
                metadata,
                attempt,
                entry,
                expected_attempt=2,
                policy="subject_late",
            )
        metadata, attempt, entry = _hosted_fixture(verify, 2)
        with self.assertRaisesRegex(verify.CurrentAuditError, "ATTEMPT"):
            _verify_hosted_fixture(
                verify,
                metadata,
                attempt,
                entry,
                expected_attempt=2,
                policy="containing_early",
            )

    def test_framework_recovery_5_capture_commands_bind_exact_attempt(self) -> None:
        verify = _load_verify()
        paths = ("e/run.json", "e/run-attempt.json", "e/run.log.gz")
        operations = _capture_operations(LIVE_CI_RUN, 2, paths)
        result = verify._framework_recovery_2_verify_capture_operations(
            operations,
            run_id=LIVE_CI_RUN,
            workflow="formal",
            paths=paths,
            head="a" * 40,
            label="fr_0005.test.capture",
            not_before=_utc("2026-07-24T19:38:19Z"),
            retained_by=_utc("2026-07-24T19:38:26Z"),
            expected_attempt=2,
            require_ordinary_attempt=True,
        )
        self.assertIn("--attempt 2", result["attempt_metadata"]["capture_command"])
        verify._verify_capture_operations(
            result,
            run_id=LIVE_CI_RUN,
            workflow="formal",
            paths=paths,
            head="a" * 40,
            label="fr_0005.test.compatibility_capture",
            not_before=_utc("2026-07-24T19:38:19Z"),
            retained_by=_utc("2026-07-24T19:38:26Z"),
            expected_attempt=2,
            require_ordinary_attempt=True,
        )
        for lane in ("attempt_metadata", "raw_log"):
            mutated = copy.deepcopy(operations)
            mutated[lane]["capture_command"] = mutated[lane]["capture_command"].replace(
                "--attempt 2", "--attempt 1"
            )
            with (
                self.subTest(lane=lane),
                self.assertRaisesRegex(verify.CurrentAuditError, "CAPTURE_COMMAND"),
            ):
                verify._framework_recovery_2_verify_capture_operations(
                    mutated,
                    run_id=LIVE_CI_RUN,
                    workflow="formal",
                    paths=paths,
                    head="a" * 40,
                    label="fr_0005.test.capture",
                    not_before=_utc("2026-07-24T19:38:19Z"),
                    retained_by=_utc("2026-07-24T19:38:26Z"),
                    expected_attempt=2,
                    require_ordinary_attempt=True,
                )
            compatibility_mutated = copy.deepcopy(result)
            compatibility_mutated[lane]["capture_command"] = compatibility_mutated[
                lane
            ]["capture_command"].replace("--attempt 2", "--attempt 1")
            with (
                self.subTest(compatibility_lane=lane),
                self.assertRaisesRegex(verify.CurrentAuditError, "CAPTURE_COMMAND"),
            ):
                verify._verify_capture_operations(
                    compatibility_mutated,
                    run_id=LIVE_CI_RUN,
                    workflow="formal",
                    paths=paths,
                    head="a" * 40,
                    label="fr_0005.test.compatibility_capture",
                    not_before=_utc("2026-07-24T19:38:19Z"),
                    retained_by=_utc("2026-07-24T19:38:26Z"),
                    expected_attempt=2,
                    require_ordinary_attempt=True,
                )

    def test_framework_recovery_5_anomaly_manifest_binds_exact_attempt(self) -> None:
        verify = _load_verify()
        metadata, attempt, entry = _hosted_fixture(verify, 2)
        anomalies = _verify_hosted_fixture(
            verify,
            metadata,
            attempt,
            entry,
            expected_attempt=2,
            policy="fr_0005",
        )
        self.assertEqual(anomalies[0]["run_id"], LIVE_CI_RUN)
        self.assertEqual(anomalies[0]["attempt"], 2)
        source = _function_source(verify, "_framework_recovery_3_verify_hosted_entry")
        self.assertIn("expected_attempt=expected_attempt", source)
        self.assertIn("require_ordinary_attempt=require_ordinary_attempt", source)
        observed = {
            "capture_schema": verify.FRAMEWORK_RECOVERY_2_CAPTURE_SCHEMA,
            "workflow": "formal",
            "subject_commit": "a" * 40,
            "files": [{"path": "ordinary"}, {"path": "attempt"}, {"path": "log"}],
            "log_integrity": {},
            "capture_operations": {},
            "boundary_policy": verify._framework_recovery_3_boundary_policy(),
            "anomaly_manifest": [{"run_id": 91, "attempt": 1}],
        }
        base = {
            key: copy.deepcopy(value)
            for key, value in observed.items()
            if key not in {"boundary_policy", "anomaly_manifest"}
        }
        documents = {
            "ordinary": verify._canonical_json_bytes({"databaseId": 91}),
            "attempt": verify._canonical_json_bytes(
                {"attempt": 2, "updatedAt": "2026-07-24T19:38:19Z"}
            ),
        }
        with (
            mock.patch.object(
                verify, "_framework_recovery_2_hosted_entry", return_value=base
            ),
            mock.patch.object(
                verify,
                "_git_file",
                side_effect=lambda _repo_path, _commit, path: documents[path],
            ),
            mock.patch.object(
                verify,
                "_framework_recovery_2_verify_capture_operations",
                return_value={},
            ),
            mock.patch.object(
                verify,
                "_verify_hosted_evidence_v2",
                return_value=[{"run_id": 91, "attempt": 2}],
            ),
            mock.patch.object(
                verify,
                "_commit_datetime",
                return_value=_utc("2026-07-24T19:39:00Z"),
            ),
            self.assertRaisesRegex(verify.CurrentAuditError, "HOSTED_ANOMALIES"),
        ):
            verify._framework_recovery_3_verify_hosted_entry(
                Path("."),
                "b" * 40,
                observed,
                paths=("ordinary", "attempt", "log"),
                subject_commit="a" * 40,
                workflow="formal",
                lane="fr_0005_test",
                expected_attempt=2,
                require_ordinary_attempt=True,
            )

    def test_framework_recovery_5_hosted_entries_bind_subject_event_and_workflow(
        self,
    ) -> None:
        verify = _load_verify()
        mutations = (
            ("headSha", "c" * 40),
            ("event", "workflow_dispatch"),
            ("workflowName", "ci"),
            ("headBranch", "other"),
        )
        for field, value in mutations:
            metadata, attempt, entry = _hosted_fixture(verify, 2)
            metadata[field] = value
            attempt[field] = value
            with (
                self.subTest(field=field),
                self.assertRaisesRegex(verify.CurrentAuditError, "HOSTED_IDENTITY"),
            ):
                _verify_hosted_fixture(
                    verify,
                    metadata,
                    attempt,
                    entry,
                    expected_attempt=2,
                    policy="fr_0005",
                )
        for ordinary_attempt in (1, 3):
            metadata, attempt, entry = _hosted_fixture(verify, 2)
            metadata["attempt"] = ordinary_attempt
            with (
                self.subTest(ordinary_attempt=ordinary_attempt),
                self.assertRaisesRegex(verify.CurrentAuditError, "HOSTED_IDENTITY"),
            ):
                _verify_hosted_fixture(
                    verify,
                    metadata,
                    attempt,
                    entry,
                    expected_attempt=2,
                    policy="fr_0005",
                )
        metadata, attempt, entry = _hosted_fixture(verify, 1)
        metadata["attempt"] = True
        attempt["attempt"] = True
        with self.assertRaisesRegex(verify.CurrentAuditError, "HOSTED_IDENTITY"):
            _verify_hosted_fixture(
                verify,
                metadata,
                attempt,
                entry,
                expected_attempt=1,
                policy="fr_0005",
            )
        metadata, attempt, entry = _hosted_fixture(verify, 2)
        metadata.pop("attempt")
        with self.assertRaisesRegex(verify.CurrentAuditError, "HOSTED_FIELDS"):
            _verify_hosted_fixture(
                verify,
                metadata,
                attempt,
                entry,
                expected_attempt=2,
                policy="fr_0005",
            )
        metadata, attempt, entry = _hosted_fixture(verify, 2)
        attempt["workflowDatabaseId"] += 1
        with self.assertRaisesRegex(verify.CurrentAuditError, "HOSTED_IDENTITY"):
            _verify_hosted_fixture(
                verify,
                metadata,
                attempt,
                entry,
                expected_attempt=2,
                policy="fr_0005",
            )
        metadata, attempt, entry = _hosted_fixture(verify, 2)
        attempt["databaseId"] += 1
        with self.assertRaisesRegex(verify.CurrentAuditError, "ATTEMPT_MISMATCH"):
            _verify_hosted_fixture(
                verify,
                metadata,
                attempt,
                entry,
                expected_attempt=2,
                policy="fr_0005",
            )
        metadata, attempt, entry = _hosted_fixture(verify, 2)
        attempt["jobs"].append(copy.deepcopy(attempt["jobs"][0]))
        with self.assertRaisesRegex(verify.CurrentAuditError, "ATTEMPT_JOBS"):
            _verify_hosted_fixture(
                verify,
                metadata,
                attempt,
                entry,
                expected_attempt=2,
                policy="fr_0005",
            )
        metadata, attempt, entry = _hosted_fixture(verify, 2)
        metadata["jobs"][0]["steps"] = []
        attempt["jobs"][0]["steps"] = []
        with self.assertRaisesRegex(verify.CurrentAuditError, "CRITICAL_STEP"):
            _verify_hosted_fixture(
                verify,
                metadata,
                attempt,
                entry,
                expected_attempt=2,
                policy="fr_0005",
            )
        wrapper_source = _function_source(
            verify, "_framework_recovery_5_verify_hosted_entry"
        )
        for token in (
            "_framework_recovery_5_positive_attempt",
            "expected_attempt=expected_attempt",
            "require_ordinary_attempt=True",
        ):
            self.assertIn(token, wrapper_source)
        with self.assertRaisesRegex(verify.CurrentAuditError, "HOSTED_FILES"):
            verify._framework_recovery_5_verify_hosted_entry(
                Path("."),
                "b" * 40,
                {"files": [{}, {"path": "e/wrong-attempt.json"}, {}]},
                paths=("e/run.json", "e/run-attempt.json", "e/run.log.gz"),
                subject_commit="a" * 40,
                workflow="formal",
                lane="test",
            )

    def test_framework_recovery_5_input_is_not_mutated(self) -> None:
        verify = _load_verify()
        metadata, attempt, entry = _hosted_fixture(verify, 2)
        before = copy.deepcopy((metadata, attempt, entry))
        _verify_hosted_fixture(
            verify,
            metadata,
            attempt,
            entry,
            expected_attempt=2,
            policy="fr_0005",
        )
        self.assertEqual((metadata, attempt, entry), before)

    def test_framework_recovery_5_transition_creates_epoch_6(self) -> None:
        verify = _load_verify()
        transition = verify._framework_recovery_5_transition_identity()
        self.assertEqual(
            transition,
            {
                "transition_kind": "NEW_SIGNED_TRUST_ROOT_REBASELINE",
                "prior_framework_accepts_transition": False,
                "ordinary_successor_transition": False,
                "fr_0004_mechanism_reused": False,
                "epoch_5_reused": False,
                "epoch_5_state": "ABORTED_BEFORE_QUALIFICATION",
                "epoch_6_candidate_created": True,
                "active_epoch_before_activation": 2,
            },
        )

    def test_framework_recovery_5_epoch_5_is_not_reusable(self) -> None:
        verify = _load_verify()
        transition = verify._framework_recovery_5_transition_identity()
        self.assertFalse(transition["epoch_5_reused"])
        self.assertEqual(transition["epoch_5_state"], "ABORTED_BEFORE_QUALIFICATION")
        plan = _repair_plan(verify)
        self.assertFalse(plan["retired_recovery"]["epoch_reusable"])
        self.assertEqual(plan["framework_epoch"]["retired_candidate"], 5)

    def test_framework_recovery_5_decision_is_fail_closed(self) -> None:
        verify = _load_verify()
        for state, active_epoch, allowed in (
            ("PENDING_QUALIFICATION", 2, False),
            ("QUALIFIED_PENDING_ACTIVATION", 2, False),
            ("ACTIVE", 6, True),
        ):
            with self.subTest(state=state):
                decision = verify._framework_recovery_5_decision(state)
                self.assertEqual(decision["framework_epoch"], 6)
                self.assertEqual(decision["active_framework_epoch"], active_epoch)
                self.assertIs(decision["successor_transitions_allowed"], allowed)
                self.assertEqual(decision["overall_release_status"], "NO_GO")
                for field in (
                    "release_authority_changed",
                    "deployment_authorized",
                    "publication_authorized",
                    "tag_authorized",
                    "github_release_authorized",
                    "doi_authorized",
                    "zenodo_authorized",
                    "archive_authorized",
                ):
                    self.assertFalse(decision[field])
        with self.assertRaisesRegex(verify.CurrentAuditError, "DECISION_STATE"):
            verify._framework_recovery_5_decision("UNKNOWN")

    def test_framework_recovery_5_repair_scope_is_exact(self) -> None:
        verify = _load_verify()
        expected = {
            "release/0.9.0/current-head/closures/framework-recovery/FR-0005-plan.json": "A",
            "tools/release/current-audit-gate.sh": "M",
            "tools/release/test_verify_current_audit_fr_0005.py": "A",
            "tools/release/verify-current-audit.py": "M",
        }
        self.assertEqual(verify.FRAMEWORK_RECOVERY_5_REPAIR_STATUSES, expected)
        self.assertEqual(
            verify._changed_path_statuses(_repo(), PARENT_COMMIT, _repair_commit()),
            dict(sorted(expected.items())),
        )
        parent_metadata = {"tree": verify.FRAMEWORK_RECOVERY_5_PARENT_TREE}
        repair_metadata = {
            "parent": verify.FRAMEWORK_RECOVERY_5_PARENT,
            "subject": verify.FRAMEWORK_RECOVERY_5_SUBJECT,
            "author_name": "Sepehr Mahmoudian",
            "author_email": "sepmhn@gmail.com",
            "committer_name": "Sepehr Mahmoudian",
            "committer_email": "sepmhn@gmail.com",
        }
        for field, value in (
            ("parent", "0" * 40),
            ("subject", "release: wrong repair subject"),
        ):
            invalid_metadata = {**repair_metadata, field: value}
            with (
                self.subTest(identity_field=field),
                mock.patch.object(
                    verify,
                    "_commit_metadata",
                    side_effect=[parent_metadata, invalid_metadata],
                ),
                self.assertRaisesRegex(
                    verify.CurrentAuditError, "RECOVERY_5_COMMIT_IDENTITY"
                ),
            ):
                verify._verify_framework_recovery_5_repair(
                    Path("."), "a" * 40, framework_commit="b" * 40
                )
        extra = {**expected, "unexpected.txt": "A"}
        with (
            mock.patch.object(
                verify,
                "_commit_metadata",
                side_effect=[parent_metadata, repair_metadata],
            ),
            mock.patch.object(verify, "_verify_named_commit_signature"),
            mock.patch.object(
                verify,
                "_changed_path_statuses",
                return_value=dict(sorted(extra.items())),
            ),
            self.assertRaisesRegex(verify.CurrentAuditError, "RECOVERY_5_DIFF"),
        ):
            verify._verify_framework_recovery_5_repair(
                Path("."), "a" * 40, framework_commit="b" * 40
            )

    def test_framework_recovery_5_qualification_scope_is_exact(self) -> None:
        verify = _load_verify()
        statuses = verify.FRAMEWORK_RECOVERY_5_QUALIFICATION_STATUSES
        self.assertEqual(len(statuses), 13)
        self.assertEqual(set(statuses.values()), {"A"})
        self.assertEqual(
            {
                item["id"]
                for item in verify.FRAMEWORK_RECOVERY_5_QUALIFICATION_REQUIREMENTS
            },
            {
                "FR-0005-E01",
                "FR-0005-E02",
                "FR-0005-E03",
                "FR-0005-E04",
                "FR-0005-R01",
                "FR-0005-R02",
            },
        )
        source = _function_source(verify, "_verify_framework_recovery_5_qualification")
        self.assertIn("parent=repair_commit", source)
        self.assertIn("FRAMEWORK_RECOVERY_5_QUALIFICATION_SUBJECT", source)
        self.assertIn("expected_statuses=dict", source)
        data_only = mock.Mock(return_value={"subject": "wrong qualification"})
        with (
            mock.patch.object(verify, "_verify_data_only_commit", data_only),
            self.assertRaisesRegex(
                verify.CurrentAuditError, "RECOVERY_5_QUALIFICATION_IDENTITY"
            ),
        ):
            verify._verify_framework_recovery_5_qualification(
                Path("."), "a" * 40, "b" * 40, plan={}
            )
        data_only.assert_called_once_with(
            Path("."),
            commit="b" * 40,
            parent="a" * 40,
            expected_statuses=dict(sorted(statuses.items())),
            label="FRAMEWORK_RECOVERY_5_QUALIFICATION",
        )
        valid_metadata = {
            "parent": "a" * 40,
            "subject": "release: qualify epoch-6 audit validation",
            "author_name": "Sepehr Mahmoudian",
            "author_email": "sepmhn@gmail.com",
            "committer_name": "Sepehr Mahmoudian",
            "committer_email": "sepmhn@gmail.com",
        }
        with (
            mock.patch.object(
                verify,
                "_commit_metadata",
                return_value={**valid_metadata, "parent": "0" * 40},
            ),
            self.assertRaisesRegex(verify.CurrentAuditError, "COMMIT_IDENTITY_INVALID"),
        ):
            verify._verify_data_only_commit(
                Path("."),
                commit="b" * 40,
                parent="a" * 40,
                expected_statuses=statuses,
                label="FRAMEWORK_RECOVERY_5_QUALIFICATION",
            )
        with (
            mock.patch.object(verify, "_commit_metadata", return_value=valid_metadata),
            mock.patch.object(verify, "_verify_named_commit_signature"),
            mock.patch.object(
                verify,
                "_changed_path_statuses",
                return_value={**statuses, "unexpected.txt": "A"},
            ),
            self.assertRaisesRegex(verify.CurrentAuditError, "DATA_ONLY_DIFF_INVALID"),
        ):
            verify._verify_data_only_commit(
                Path("."),
                commit="b" * 40,
                parent="a" * 40,
                expected_statuses=statuses,
                label="FRAMEWORK_RECOVERY_5_QUALIFICATION",
            )

    def test_framework_recovery_5_activation_scope_is_exact(self) -> None:
        verify = _load_verify()
        statuses = verify.FRAMEWORK_RECOVERY_5_ACTIVATION_STATUSES
        self.assertEqual(len(statuses), 7)
        self.assertEqual(set(statuses.values()), {"A"})
        self.assertEqual(
            {
                item["id"]
                for item in verify.FRAMEWORK_RECOVERY_5_ACTIVATION_REQUIREMENTS
            },
            {"FR-0005-A01", "FR-0005-A02"},
        )
        source = _function_source(verify, "_verify_framework_recovery_5_activation")
        self.assertIn("parent=qualification_commit", source)
        self.assertIn("FRAMEWORK_RECOVERY_5_ACTIVATION_SUBJECT", source)
        self.assertIn("expected_statuses=dict", source)
        data_only = mock.Mock(return_value={"subject": "wrong activation"})
        with (
            mock.patch.object(verify, "_verify_data_only_commit", data_only),
            self.assertRaisesRegex(
                verify.CurrentAuditError, "RECOVERY_5_ACTIVATION_IDENTITY"
            ),
        ):
            verify._verify_framework_recovery_5_activation(
                Path("."),
                "a" * 40,
                "b" * 40,
                "c" * 40,
                qualification={},
            )
        data_only.assert_called_once_with(
            Path("."),
            commit="c" * 40,
            parent="b" * 40,
            expected_statuses=dict(sorted(statuses.items())),
            label="FRAMEWORK_RECOVERY_5_ACTIVATION",
        )
        valid_metadata = {
            "parent": "b" * 40,
            "subject": "release: activate epoch-6 audit validation",
            "author_name": "Sepehr Mahmoudian",
            "author_email": "sepmhn@gmail.com",
            "committer_name": "Sepehr Mahmoudian",
            "committer_email": "sepmhn@gmail.com",
        }
        with (
            mock.patch.object(
                verify,
                "_commit_metadata",
                return_value={**valid_metadata, "parent": "0" * 40},
            ),
            self.assertRaisesRegex(verify.CurrentAuditError, "COMMIT_IDENTITY_INVALID"),
        ):
            verify._verify_data_only_commit(
                Path("."),
                commit="c" * 40,
                parent="b" * 40,
                expected_statuses=statuses,
                label="FRAMEWORK_RECOVERY_5_ACTIVATION",
            )
        with (
            mock.patch.object(verify, "_commit_metadata", return_value=valid_metadata),
            mock.patch.object(verify, "_verify_named_commit_signature"),
            mock.patch.object(
                verify,
                "_changed_path_statuses",
                return_value={**statuses, "unexpected.txt": "A"},
            ),
            self.assertRaisesRegex(verify.CurrentAuditError, "DATA_ONLY_DIFF_INVALID"),
        ):
            verify._verify_data_only_commit(
                Path("."),
                commit="c" * 40,
                parent="b" * 40,
                expected_statuses=statuses,
                label="FRAMEWORK_RECOVERY_5_ACTIVATION",
            )

    def test_framework_recovery_5_stage_modes_are_regular(self) -> None:
        verify = _load_verify()
        with mock.patch.object(
            verify,
            "_git_tree_entry",
            return_value={"mode": "100644", "type": "blob"},
        ):
            verify._framework_recovery_5_verify_stage_modes(
                Path("."), "a" * 40, {"x": "100644"}, label="test"
            )
        for entry in (
            {"mode": "120000", "type": "blob"},
            {"mode": "100644", "type": "tree"},
            None,
        ):
            with (
                self.subTest(entry=entry),
                mock.patch.object(verify, "_git_tree_entry", return_value=entry),
                self.assertRaisesRegex(verify.CurrentAuditError, "MODE:test:x"),
            ):
                verify._framework_recovery_5_verify_stage_modes(
                    Path("."), "a" * 40, {"x": "100644"}, label="test"
                )
        stage_cases = (
            (
                verify._verify_framework_recovery_5_qualification,
                {
                    "repo": Path("."),
                    "repair_commit": "a" * 40,
                    "qualification_commit": "b" * 40,
                    "plan": {},
                },
                verify.FRAMEWORK_RECOVERY_5_QUALIFICATION_SUBJECT,
                {"mode": "120000", "type": "blob"},
                "MODE:qualification",
            ),
            (
                verify._verify_framework_recovery_5_activation,
                {
                    "repo": Path("."),
                    "repair_commit": "a" * 40,
                    "qualification_commit": "b" * 40,
                    "activation_commit": "c" * 40,
                    "qualification": {},
                },
                verify.FRAMEWORK_RECOVERY_5_ACTIVATION_SUBJECT,
                {"mode": "100755", "type": "blob"},
                "MODE:activation",
            ),
        )
        for function, arguments, subject, entry, error in stage_cases:
            with (
                self.subTest(stage=function.__name__, entry=entry),
                mock.patch.object(
                    verify,
                    "_verify_data_only_commit",
                    return_value={"subject": subject},
                ),
                mock.patch.object(verify, "_git_tree_entry", return_value=entry),
                self.assertRaisesRegex(verify.CurrentAuditError, error),
            ):
                function(**arguments)

    def test_framework_recovery_5_code_diff_excludes_plan(self) -> None:
        verify = _load_verify()
        diff = verify._framework_recovery_5_code_diff(_repo(), _repair_commit())
        self.assertEqual(
            diff["paths"],
            [
                "tools/release/verify-current-audit.py",
                "tools/release/test_verify_current_audit_fr_0005.py",
                "tools/release/current-audit-gate.sh",
            ],
        )
        self.assertNotIn(verify.FRAMEWORK_RECOVERY_5_PLAN_PATH, diff["paths"])
        self.assertGreater(diff["patch_bytes"], 0)

    def test_framework_recovery_5_expected_plan_has_exact_fields(self) -> None:
        verify = _load_verify()
        expected = verify._framework_recovery_5_expected_plan(
            _repo(), _repair_commit(), _framework_commit(verify)
        )
        expected_keys = {
            "schema_version",
            "recovery_id",
            "release_target",
            "author",
            "persistent_identifier",
            "framework_epoch",
            "parent_commit",
            "parent_tree",
            "prior_framework_commit",
            "repair_subject",
            "transition_identity",
            "retired_recovery",
            "defect",
            "correction",
            "hosted_attempt_policy",
            "boundary_policy",
            "registered_snapshot_materialization",
            "changed_core_files",
            "code_diff",
            "source_retention",
            "test_contract",
            "preserved_state_records",
            "qualification_path",
            "qualification_requirements",
            "activation_path",
            "activation_requirements",
            "state",
            "authority",
            "assurance_boundary",
        }
        self.assertEqual(set(expected), expected_keys)
        plan = _repair_plan(verify)
        self.assertEqual(
            set(plan), expected_keys | {"created_at_utc", "detached_signature"}
        )
        comparable = {
            key: value
            for key, value in plan.items()
            if key not in {"created_at_utc", "detached_signature"}
        }
        self.assertEqual(comparable, expected)
        self.assertIsNone(plan["persistent_identifier"])
        self.assertEqual(
            plan["hosted_attempt_policy"],
            verify._framework_recovery_5_hosted_attempt_policy(),
        )
        self.assertEqual(
            plan["correction"]["shared_function_keyword_parameters"],
            ["expected_attempt", "require_ordinary_attempt"],
        )
        self.assertTrue(
            plan["correction"]["ordinary_attempt_field_required_only_for_fr_0005"]
        )

    def test_framework_recovery_5_expected_gate_payload_is_exact(self) -> None:
        verify = _load_verify()
        prior = verify._framework_recovery_4_expected_gate_payload()
        direct_fr_0004 = (
            b'"$PYTHON3" -I -W error '
            b"tools/release/test_verify_current_audit_fr_0004.py\n"
        )
        pinned_fr_0004 = (
            b"/usr/bin/git cat-file blob "
            b"f1fcc6059289ddb738da2a932d3d6014f2f4e377 \\\n"
            b'  > "$FR4_COMPAT_DIR/verify-current-audit.py"\n'
            b'[[ "$(/usr/bin/env \\\n'
            b"  -i \\\n"
            b"  GIT_NO_REPLACE_OBJECTS=1 \\\n"
            b"  PATH=/usr/bin:/bin \\\n"
            b"  /usr/bin/git hash-object --no-filters -- \\\n"
            b'  "$FR4_COMPAT_DIR/verify-current-audit.py")" \\\n'
            b"  == f1fcc6059289ddb738da2a932d3d6014f2f4e377 ]]\n"
            b'"$PYTHON3" -B -I -W error \\\n'
            b'  "$FR4_COMPAT_DIR/test_verify_current_audit_fr_0004.py"\n'
        )
        self.assertEqual(prior.count(direct_fr_0004), 1)
        expected = verify._framework_recovery_5_expected_gate_payload()
        self.assertEqual(
            verify._git_file(
                _repo(), _repair_commit(), "tools/release/current-audit-gate.sh"
            ),
            expected,
        )
        parent_verifier = verify._git_tree_entry(
            _repo(), PARENT_COMMIT, "tools/release/verify-current-audit.py"
        )
        self.assertIsNotNone(parent_verifier)
        self.assertEqual(parent_verifier["mode"], "100644")
        self.assertEqual(parent_verifier["type"], "blob")
        self.assertEqual(
            parent_verifier["oid"], "f1fcc6059289ddb738da2a932d3d6014f2f4e377"
        )
        parent_payload = verify._git_file(
            _repo(), PARENT_COMMIT, "tools/release/verify-current-audit.py"
        )
        self.assertEqual(
            len(parent_payload), verify.FRAMEWORK_RECOVERY_5_PARENT_VERIFIER_BYTES
        )
        self.assertEqual(
            hashlib.sha256(parent_payload).hexdigest(),
            verify.FRAMEWORK_RECOVERY_5_PARENT_VERIFIER_SHA256,
        )
        self.assertNotIn(direct_fr_0004, expected)
        self.assertEqual(expected.count(b"\nFR4_COMPAT_DIR=\n"), 1)
        self.assertEqual(
            expected.count(b'\nFR4_COMPAT_DIR="$(/usr/bin/mktemp -d '),
            1,
        )
        self.assertEqual(
            expected.count(b"/tmp/haldir-fr4-gate.XXXXXX"),
            1,
        )
        self.assertEqual(expected.count(pinned_fr_0004), 1)
        self.assertEqual(
            expected.count(
                b'"$PWD/tools/release/test_verify_current_audit_fr_0004.py" \\\n'
                b'  "$FR4_COMPAT_DIR/test_verify_current_audit_fr_0004.py"\n'
            ),
            1,
        )
        self.assertEqual(
            expected.count(
                b'      "$FR4_COMPAT_DIR/test_verify_current_audit_fr_0004.py" \\\n'
                b'      "$FR4_COMPAT_DIR/verify-current-audit.py"\n'
            ),
            1,
        )
        self.assertEqual(expected.count(b"test_verify_current_audit_fr_0005.py"), 1)
        ordered_fragments = (
            b"builtin trap cleanup_fr2_compat EXIT\n",
            b"builtin trap 'builtin exit 129' HUP\n",
            b'FR4_COMPAT_DIR="$(/usr/bin/mktemp -d ',
            b'"$PWD/tools/release/test_verify_current_audit_fr_0004.py" \\\n',
            b"/usr/bin/git cat-file blob f1fcc6059289ddb738da2a932d3d6014f2f4e377",
            b'"$FR4_COMPAT_DIR/verify-current-audit.py")" \\\n'
            b"  == f1fcc6059289ddb738da2a932d3d6014f2f4e377 ]]\n",
            b'"$PYTHON3" -B -I -W error \\\n'
            b'  "$FR4_COMPAT_DIR/test_verify_current_audit_fr_0004.py"\n',
            b'"$PYTHON3" -B -I -W error '
            b"tools/release/test_verify_current_audit_fr_0005.py\n",
            b'"$PYTHON3" -B -I -W error tools/release/verify-current-audit.py\n',
        )
        positions = [expected.index(fragment) for fragment in ordered_fragments]
        self.assertEqual(positions, sorted(positions))
        original_git_file = verify._git_file
        gate_path = "tools/release/current-audit-gate.sh"
        mutations = (
            expected.replace(
                b'"$PYTHON3" -B -I -W error '
                b"tools/release/test_verify_current_audit_fr_0005.py\n",
                b'"$PYTHON3" -B -I '
                b"tools/release/test_verify_current_audit_fr_0005.py\n",
                1,
            ),
            expected.replace(
                b'"$PYTHON3" -B -I -W error '
                b"tools/release/test_verify_current_audit_fr_0005.py\n",
                b"",
                1,
            ),
            expected.replace(
                b"f1fcc6059289ddb738da2a932d3d6014f2f4e377",
                b"0" * 40,
                1,
            ),
            expected.replace(
                b'"$PYTHON3" -B -I -W error \\\n'
                b'  "$FR4_COMPAT_DIR/test_verify_current_audit_fr_0004.py"\n',
                b'"$PYTHON3" -I -W error \\\n'
                b'  "$FR4_COMPAT_DIR/test_verify_current_audit_fr_0004.py"\n',
                1,
            ),
            expected.replace(pinned_fr_0004, direct_fr_0004, 1),
        )
        for mutation in mutations:

            def git_file(repo, commit, path, *, _mutation=mutation):
                if path == gate_path:
                    return _mutation
                return original_git_file(repo, commit, path)

            with (
                self.subTest(gate_sha256=hashlib.sha256(mutation).hexdigest()),
                mock.patch.object(verify, "_git_file", side_effect=git_file),
                self.assertRaisesRegex(verify.CurrentAuditError, "GATE_WIRING"),
            ):
                verify._framework_recovery_5_test_contract(_repo(), _repair_commit())
        for invalid_prior in (
            prior.replace(direct_fr_0004, b"", 1),
            prior.replace(direct_fr_0004, direct_fr_0004 * 2, 1),
        ):
            with (
                mock.patch.object(
                    verify,
                    "_framework_recovery_4_expected_gate_payload",
                    return_value=invalid_prior,
                ),
                self.assertRaisesRegex(
                    verify.CurrentAuditError,
                    "FRAMEWORK_RECOVERY_5_PRIOR_GATE_INVALID",
                ),
            ):
                verify._framework_recovery_5_expected_gate_payload()
        original_tree_entry = verify._git_tree_entry
        for pinned_path in (
            "tools/release/verify-current-audit.py",
            verify.FRAMEWORK_RECOVERY_4_TEST_PATH,
        ):

            def tree_entry(repo, commit, path, *, _pinned_path=pinned_path):
                if commit == PARENT_COMMIT and path == _pinned_path:
                    return {"mode": "100644", "type": "blob", "oid": "0" * 40}
                return original_tree_entry(repo, commit, path)

            with (
                self.subTest(parent_pin=pinned_path),
                mock.patch.object(verify, "_git_tree_entry", side_effect=tree_entry),
                self.assertRaisesRegex(
                    verify.CurrentAuditError,
                    "FRAMEWORK_RECOVERY_5_GATE_COMPATIBILITY_PIN",
                ),
            ):
                verify._framework_recovery_5_test_contract(_repo(), _repair_commit())

    def test_framework_recovery_5_preserves_prior_test_suites(self) -> None:
        verify = _load_verify()
        repair = _repair_commit()
        paths = (
            "tools/release/test_verify_current_audit.py",
            verify.FRAMEWORK_RECOVERY_2_TEST_PATH,
            verify.FRAMEWORK_RECOVERY_3_TEST_PATH,
            verify.FRAMEWORK_RECOVERY_3_RESOURCE_TEST_PATH,
            verify.FRAMEWORK_RECOVERY_4_TEST_PATH,
        )
        for path in paths:
            with self.subTest(path=path):
                self.assertEqual(
                    verify._git_tree_entry(_repo(), PARENT_COMMIT, path),
                    verify._git_tree_entry(_repo(), repair, path),
                )
        self.assertEqual(
            verify._git_file(_repo(), repair, verify.FRAMEWORK_RECOVERY_4_TEST_PATH),
            verify._git_file(
                _repo(), PARENT_COMMIT, verify.FRAMEWORK_RECOVERY_4_TEST_PATH
            ),
        )

    def test_framework_recovery_5_test_contract_is_warning_strict(self) -> None:
        verify = _load_verify()
        contract = verify._framework_recovery_5_test_contract(_repo(), _repair_commit())
        self.assertEqual(contract["warning_policy"], "-W error")
        self.assertEqual(
            set(contract["required_regression_test_ids"]), REQUIRED_TEST_IDS
        )
        self.assertEqual(contract["fr_0005"]["count"], 44)
        counts = [
            contract[key]["count"]
            for key in (
                "legacy",
                "fr_0002",
                "fr_0003",
                "resource",
                "fr_0004",
                "fr_0005",
            )
        ]
        self.assertEqual(len(counts), len(set(counts)))
        self.assertEqual(
            contract["gate_record"]["path"],
            "tools/release/current-audit-gate.sh",
        )

    def test_framework_recovery_5_local_markers_reject_missing_suite(self) -> None:
        verify = _load_verify()
        counts = {
            "legacy": {"count": 163},
            "fr_0002": {"count": 78},
            "fr_0003": {"count": 94},
            "resource": {"count": 26},
            "fr_0004": {"count": 30},
            "fr_0005": {"count": 44},
        }

        def suite(count: int) -> bytes:
            return f"Ran {count} tests in 1.000s\nOK\n".encode("ascii")

        direct = b"".join(suite(count) for count in (163, 78, 94, 26, 30, 44))
        direct += b"verify-current-audit: OK\n"
        p0 = b"".join(suite(count) for count in (163, 78, 94, 26, 30, 44, 26))
        p0 += b"OK\n" * 5
        p0 += b"verify-current-audit: OK\nP0-R exit gate: 30 passed, 0 failed\n"
        payload = (
            b"=== CURRENT_AUDIT_GATE ===\n"
            b"$ tools/release/current-audit-gate.sh\n"
            + direct
            + b"=== P0R_EXIT_GATE ===\n$ tools/p0r-exit-gate.sh\n"
            + p0
            + b"=== RESOURCE_PROFILE ===\n"
            b"$ python3 -I tools/release/current-audit-resource-profile.py\n{}\n"
        )
        verify._framework_recovery_5_verify_local_markers(payload, test_contract=counts)
        missing = payload.replace(suite(44), b"", 1)
        with self.assertRaisesRegex(verify.CurrentAuditError, "LOCAL_LOG"):
            verify._framework_recovery_5_verify_local_markers(
                missing, test_contract=counts
            )
        duplicate_counts = copy.deepcopy(counts)
        duplicate_counts["fr_0005"]["count"] = counts["fr_0004"]["count"]
        with self.assertRaisesRegex(verify.CurrentAuditError, "CI_TEST_COUNT"):
            verify._framework_recovery_5_verify_ci_markers(
                Path("."),
                "a" * 40,
                {"files": []},
                test_contract=duplicate_counts,
                label="duplicate_count",
            )

        timestamps = (
            ("2026-07-24T19:38:20Z", "2026-07-24T19:38:21Z"),
            ("2026-07-24T19:38:21Z", "2026-07-24T19:38:22Z"),
            ("2026-07-24T19:38:22Z", "2026-07-24T19:38:23Z"),
        )
        command_ids = ("CURRENT_AUDIT_GATE", "P0R_EXIT_GATE", "RESOURCE_PROFILE")
        commands = [
            {
                "argv": list(argv),
                "completed_at_utc": completed,
                "exit_status": 0,
                "id": command_ids[index],
                "result": "PASS",
                "started_at_utc": started,
            }
            for index, (argv, (started, completed)) in enumerate(
                zip(verify._framework_recovery_5_local_commands(), timestamps)
            )
        ]
        commands[0]["exit_status"] = False
        local_document = {
            "schema_version": "1.0.0",
            "evidence_id": "FR-0005-E04",
            "kind": "REPAIR_LOCAL_VALIDATION",
            "subject_commit": "a" * 40,
            "subject_tree": "tree",
            "platform": {"architecture": "arm64", "operating_system": "macOS"},
            "tool_versions": {
                "cargo": "cargo",
                "docker": "docker",
                "git": "git",
                "python": "python",
                "rustc": "rustc",
            },
            "commands": commands,
            "raw_log": {},
            "started_at_utc": timestamps[0][0],
            "completed_at_utc": timestamps[-1][1],
            "overall_result": "PASS",
        }
        with (
            mock.patch.object(
                verify, "_commit_metadata", return_value={"tree": "tree"}
            ),
            self.assertRaisesRegex(verify.CurrentAuditError, "LOCAL_COMMANDS"),
        ):
            verify._framework_recovery_5_validate_local_document(
                Path("."),
                "b" * 40,
                "a" * 40,
                local_document,
                evidence_record={},
                test_contract=counts,
            )

        def hosted_line(message: bytes) -> bytes:
            return (
                b"supply-chain\tVerify current-head 0.9 audit cut\t"
                b"2026-07-24T19:38:19Z " + message + b"\n"
            )

        hosted_markers = b"".join(
            hosted_line(f"Ran {count} tests in 1.000s".encode("ascii"))
            + hosted_line(b"OK")
            for count in (163, 78, 94, 26, 30, 44)
        ) + hosted_line(b"verify-current-audit: OK")
        hosted_entry = {"files": [{}, {}, {"path": "ci.log.gz"}]}
        with (
            mock.patch.object(verify, "_git_file", return_value=b"compressed"),
            mock.patch.object(
                verify, "_decompress_unbound_gzip", return_value=hosted_markers
            ),
        ):
            verify._framework_recovery_5_verify_ci_markers(
                Path("."),
                "a" * 40,
                hosted_entry,
                test_contract=counts,
                label="test",
            )
            reversed_markers = b"".join(
                hosted_line(f"Ran {count} tests in 1.000s".encode("ascii"))
                + hosted_line(b"OK")
                for count in (44, 30, 26, 94, 78, 163)
            ) + hosted_line(b"verify-current-audit: OK")
            with (
                mock.patch.object(
                    verify,
                    "_decompress_unbound_gzip",
                    return_value=reversed_markers,
                ),
                self.assertRaisesRegex(verify.CurrentAuditError, "CI_LOG_MARKERS"),
            ):
                verify._framework_recovery_5_verify_ci_markers(
                    Path("."),
                    "a" * 40,
                    hosted_entry,
                    test_contract=counts,
                    label="test",
                )
            verifier_first = (
                hosted_line(b"verify-current-audit: OK")
                + hosted_markers[: -len(hosted_line(b"verify-current-audit: OK"))]
            )
            with (
                mock.patch.object(
                    verify,
                    "_decompress_unbound_gzip",
                    return_value=verifier_first,
                ),
                self.assertRaisesRegex(verify.CurrentAuditError, "CI_LOG_MARKERS"),
            ):
                verify._framework_recovery_5_verify_ci_markers(
                    Path("."),
                    "a" * 40,
                    hosted_entry,
                    test_contract=counts,
                    label="test",
                )

    def test_framework_recovery_5_materialization_is_inherited(self) -> None:
        verify = _load_verify()
        parent, _payload = verify._read_commit_json(
            _repo(),
            PARENT_COMMIT,
            verify.FRAMEWORK_RECOVERY_4_PLAN_PATH,
            "fr_0005.test.parent_plan",
        )
        for mutation in ("missing", "wrong_type", "wrong_value"):
            invalid = copy.deepcopy(parent)
            if mutation == "missing":
                invalid.pop("registered_snapshot_materialization")
            elif mutation == "wrong_type":
                invalid["registered_snapshot_materialization"] = []
            else:
                invalid["registered_snapshot_materialization"]["mode"] = "changed"
            with (
                self.subTest(mutation=mutation),
                mock.patch.object(
                    verify,
                    "_read_commit_json",
                    return_value=(
                        invalid,
                        verify._canonical_json_bytes(invalid, pretty=True),
                    ),
                ),
                self.assertRaisesRegex(
                    verify.CurrentAuditError,
                    "CURRENT_AUDIT_FRAMEWORK_RECOVERY_5_PARENT_MATERIALIZATION",
                ),
            ):
                verify._framework_recovery_5_expected_plan(
                    Path("."), "a" * 40, "b" * 40
                )
        plan = _repair_plan(verify)
        self.assertEqual(
            plan["registered_snapshot_materialization"],
            parent["registered_snapshot_materialization"],
        )

    def test_framework_recovery_5_resource_bounds_are_inherited(self) -> None:
        verify = _load_verify()
        materialization = _repair_plan(verify)["registered_snapshot_materialization"]
        bounds = materialization["bounds"]
        self.assertEqual(bounds["minimum_daemon_cpus"], 2)
        self.assertEqual(bounds["minimum_daemon_memory_bytes"], 1280 * 1024 * 1024)
        self.assertEqual(bounds["maximum_directory_depth"], 64)
        self.assertEqual(bounds["maximum_file_component_depth"], 65)
        self.assertEqual(
            materialization["execution_policy"]["failure_policy"], "FAIL_CLOSED"
        )

    def test_framework_recovery_5_run_attempt_identity_is_exact_tuple(self) -> None:
        verify = _load_verify()

        def identities(
            run_id: int, attempt_number
        ) -> tuple[tuple[int, int], tuple[int, int]]:
            entry = _run_attempt_entry(verify, run_id, attempt_number)
            payloads = {item["path"]: item["payload"] for item in entry["files"][:2]}
            public_entry = {
                "files": [
                    {key: value for key, value in item.items() if key != "payload"}
                    for item in entry["files"]
                ]
            }
            with mock.patch.object(
                verify,
                "_git_file",
                side_effect=lambda _repo_path, _commit, path: payloads[path],
            ):
                direct = verify._framework_recovery_2_run_attempt_identity(
                    Path("."), "a" * 40, public_entry, label="direct"
                )
                wrapped = verify._framework_recovery_5_run_attempt_identity(
                    Path("."), "a" * 40, public_entry, label="wrapped"
                )
            return direct, wrapped

        for attempt_number in (2, 7):
            expected = (500, attempt_number)
            self.assertEqual(identities(500, attempt_number), (expected, expected))
        for attempt_number in (False, True, 0, -1, "2"):
            with (
                self.subTest(attempt=attempt_number),
                self.assertRaisesRegex(verify.CurrentAuditError, "RUN_ATTEMPT"),
            ):
                identities(500, attempt_number)

    def test_framework_recovery_5_same_run_different_attempt_is_distinct(self) -> None:
        verify = _load_verify()
        self.assertNotEqual((500, 2), (500, 3))
        entries = [
            ("repair_ci", "a" * 40, {}),
            ("repair_formal", "b" * 40, {}),
        ]
        with mock.patch.object(
            verify,
            "_framework_recovery_5_run_attempt_identity",
            side_effect=((500, 2), (500, 3)),
        ):
            verify._framework_recovery_5_verify_run_attempt_uniqueness(
                Path("."), entries
            )
        with mock.patch.object(
            verify,
            "_framework_recovery_5_run_attempt_identity",
            side_effect=((500, 2), (501, 1)),
        ):
            verify._framework_recovery_5_verify_run_attempt_uniqueness(
                Path("."), entries
            )

    def test_framework_recovery_5_reserves_parent_run_attempts(self) -> None:
        verify = _load_verify()
        reserved = (
            (30_023_626_301, 1),
            (30_093_828_629, 1),
            (30_093_828_642, 1),
            (LIVE_CI_RUN, 1),
            (LIVE_CI_RUN, 2),
            (LIVE_FORMAL_RUN, 1),
        )
        entries = [("lane", "a" * 40, {})]
        for identity in reserved:
            with (
                self.subTest(identity=identity),
                mock.patch.object(
                    verify,
                    "_framework_recovery_5_run_attempt_identity",
                    return_value=identity,
                ),
                self.assertRaisesRegex(verify.CurrentAuditError, "RUN_ATTEMPT_REUSED"),
            ):
                verify._framework_recovery_5_verify_run_attempt_uniqueness(
                    Path("."), entries
                )

    def test_framework_recovery_5_rejects_cross_phase_run_attempt_reuse(self) -> None:
        verify = _load_verify()
        entries = [
            ("repair_ci", "a" * 40, {}),
            ("repair_formal", "b" * 40, {}),
            ("qualification_ci", "c" * 40, {}),
            ("qualification_formal", "d" * 40, {}),
        ]
        for identities in (
            ((500, 2), (500, 2), (502, 1), (503, 1)),
            ((500, 2), (501, 1), (500, 2), (503, 1)),
            ((500, 2), (501, 1), (502, 1), (501, 1)),
        ):
            with (
                self.subTest(identities=identities),
                mock.patch.object(
                    verify,
                    "_framework_recovery_5_run_attempt_identity",
                    side_effect=identities,
                ),
                self.assertRaisesRegex(verify.CurrentAuditError, "RUN_ATTEMPT_REUSED"),
            ):
                verify._framework_recovery_5_verify_run_attempt_uniqueness(
                    Path("."), entries
                )

        payloads: dict[str, bytes] = {}
        composed_entries = []
        for lane, commit in (("repair_ci", "a" * 40), ("qualification_ci", "b" * 40)):
            entry = _run_attempt_entry(verify, 600, 2)
            for index, item in enumerate(entry["files"]):
                path = f"e/{lane}-{index}"
                item["path"] = path
                payload = item.pop("payload", None)
                if payload is not None:
                    payloads[path] = payload
            composed_entries.append((lane, commit, entry))
        with (
            mock.patch.object(
                verify,
                "_git_file",
                side_effect=lambda _repo_path, _commit, path: payloads[path],
            ),
            self.assertRaisesRegex(verify.CurrentAuditError, "RUN_ATTEMPT_REUSED"),
        ):
            verify._framework_recovery_5_verify_run_attempt_uniqueness(
                Path("."), composed_entries
            )

    def test_framework_recovery_5_review_contracts_cite_real_tests(self) -> None:
        verify = _load_verify()
        contracts = verify._framework_recovery_5_review_contracts()
        self.assertEqual(set(contracts), {"FR-0005-R01", "FR-0005-R02"})
        allowed_evidence = {
            "FR-0005-E01",
            "FR-0005-E02",
            "FR-0005-E03",
            "FR-0005-E04",
        }
        cited_tests: set[str] = set()
        for review_id, findings in contracts.items():
            self.assertEqual(len(findings), 5, review_id)
            for finding_id, mapping in findings.items():
                self.assertRegex(finding_id, r"^F\d{3}$")
                self.assertTrue(set(mapping["resolving_test_ids"]) <= REQUIRED_TEST_IDS)
                self.assertTrue(
                    set(mapping["resolving_evidence_ids"]) <= allowed_evidence
                )
                cited_tests.update(mapping["resolving_test_ids"])
        self.assertTrue(cited_tests <= REQUIRED_TEST_IDS)
        self.assertTrue(
            {
                "test_framework_recovery_5_parent_rejects_rerun_attempt",
                "test_framework_recovery_5_capture_commands_bind_exact_attempt",
                "test_framework_recovery_5_retires_fr_0004_without_qualification",
                "test_framework_recovery_5_source_retention_rejects_unrelated_change",
                "test_framework_recovery_5_rejects_cross_phase_run_attempt_reuse",
                "test_framework_recovery_5_wrapper_accepts_epochs_2_through_6",
            }
            <= cited_tests
        )
        plan = _repair_plan(verify)
        narratives = {
            finding_id: {"summary": "Exact test finding.", "disposition": "Resolved."}
            for finding_id in contracts["FR-0005-R01"]
        }
        review = verify._framework_recovery_5_expected_review(
            review_id="FR-0005-R01",
            kind="INTERNAL_AUTOMATED_DESIGN_REVIEW",
            repair_commit=_repair_commit(),
            plan=plan,
            narratives=narratives,
        )
        self.assertFalse(review["reviewer"]["human_review_performed"])
        self.assertFalse(review["reviewer"]["external_independence"])
        self.assertFalse(review["reviewer"]["release_authority"])
        self.assertEqual(review["initial_verdict"], "NO_GO")
        self.assertEqual(review["final_verdict"], "GO_FOR_FRAMEWORK_QUALIFICATION")

    def test_framework_recovery_5_review_keys_are_separate(self) -> None:
        verify = _load_verify()
        source = {"public_key": "source", "key_fingerprint": "source-fp"}
        distinct = [
            {"public_key": "design", "key_fingerprint": "design-fp"},
            {"public_key": "implementation", "key_fingerprint": "implementation-fp"},
        ]
        verify._framework_recovery_5_verify_review_key_separation(source, distinct)
        for review_keys in (
            [distinct[0], distinct[0]],
            [source, distinct[1]],
            [distinct[0]],
        ):
            with (
                self.subTest(keys=review_keys),
                self.assertRaisesRegex(
                    verify.CurrentAuditError, "REVIEW_KEY_SEPARATION"
                ),
            ):
                verify._framework_recovery_5_verify_review_key_separation(
                    source, review_keys
                )

    def test_framework_recovery_5_evidence_signatures_and_chronology_are_bound(
        self,
    ) -> None:
        verify = _load_verify()
        qualification = _function_source(
            verify, "_verify_framework_recovery_5_qualification"
        )
        activation = _function_source(verify, "_verify_framework_recovery_5_activation")
        for source, namespace in (
            (qualification, "haldir-framework-recovery-fr-0005-qualification-v1"),
            (activation, "haldir-framework-recovery-fr-0005-activation-v1"),
        ):
            self.assertIn(namespace, source)
            self.assertIn("_verify_ssh_detached_attestation", source)
            self.assertIn("_commit_datetime", source)
            self.assertIn("hosted_capture_completed", source)
        self.assertIn(
            "_framework_recovery_5_validate_parent_reproduction", qualification
        )
        self.assertIn(
            "_framework_recovery_5_verify_review_key_separation", qualification
        )
        self.assertIn("_framework_recovery_5_verify_run_attempt_uniqueness", activation)

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
        qualification_record = {
            "test_contract": {},
            "hosted_evidence": {"repair_ci": {}, "repair_formal": {}},
        }
        signer = {
            "principal": "sepmhn@gmail.com",
            "public_key": "ssh-ed25519 source",
            "key_fingerprint": "source-fingerprint",
        }

        qualification_hosted = {
            "repair_ci": {"lane": "repair_ci"},
            "repair_formal": {"lane": "repair_formal"},
        }
        qualification_expected = {
            "schema_version": "1.0.0",
            "hosted_evidence": qualification_hosted,
            "hosted_run_attempts": [
                {"lane": "repair_ci", "run_id": LIVE_CI_RUN, "attempt": 2},
                {"lane": "repair_formal", "run_id": LIVE_FORMAL_RUN, "attempt": 1},
            ],
        }
        qualification_plan = {"test_contract": {}}
        qualification_documents = {
            "FR-0005-E01": {"completed_at_utc": "2026-07-24T00:00:01Z"},
            "FR-0005-E04": {"completed_at_utc": "2026-07-24T00:00:02Z"},
            "FR-0005-R01": {},
            "FR-0005-R02": {},
        }

        def execute_qualification(document, attestation):
            def catalog_record(_repo_path, _commit, requirement, **_kwargs):
                evidence_id = requirement["id"]
                retained = verify._canonical_json_bytes(
                    qualification_documents.get(evidence_id, {})
                )
                return (
                    {
                        "id": evidence_id,
                        "files": [{"path": requirement["paths"][0]}],
                    },
                    [retained],
                )

            with (
                mock.patch.object(
                    verify,
                    "_verify_data_only_commit",
                    return_value={
                        "subject": verify.FRAMEWORK_RECOVERY_5_QUALIFICATION_SUBJECT
                    },
                ),
                mock.patch.object(verify, "_framework_recovery_5_verify_stage_modes"),
                mock.patch.object(
                    verify, "_git_tree_entry", return_value={"oid": "same"}
                ),
                mock.patch.object(
                    verify,
                    "_read_commit_json",
                    return_value=(
                        document,
                        verify._canonical_json_bytes(document, pretty=True),
                    ),
                ),
                mock.patch.object(
                    verify,
                    "_framework_recovery_2_catalog_record",
                    side_effect=catalog_record,
                ),
                mock.patch.object(
                    verify, "_framework_recovery_5_validate_parent_reproduction"
                ),
                mock.patch.object(
                    verify, "_framework_recovery_5_validate_local_document"
                ),
                mock.patch.object(
                    verify,
                    "_framework_recovery_5_verify_hosted_entry",
                    side_effect=(
                        (
                            qualification_hosted["repair_ci"],
                            _utc("2026-07-24T00:00:01Z"),
                        ),
                        (
                            qualification_hosted["repair_formal"],
                            _utc("2026-07-24T00:00:02Z"),
                        ),
                    ),
                ),
                mock.patch.object(verify, "_framework_recovery_5_verify_ci_markers"),
                mock.patch.object(
                    verify, "_framework_recovery_5_verify_run_attempt_uniqueness"
                ),
                mock.patch.object(
                    verify,
                    "_framework_recovery_5_validate_review",
                    side_effect=(
                        {
                            "public_key": "ssh-ed25519 review-1",
                            "key_fingerprint": "review-fingerprint-1",
                        },
                        {
                            "public_key": "ssh-ed25519 review-2",
                            "key_fingerprint": "review-fingerprint-2",
                        },
                    ),
                ),
                mock.patch.object(
                    verify, "_framework_recovery_5_verify_review_key_separation"
                ),
                mock.patch.object(
                    verify,
                    "_framework_recovery_5_expected_qualification",
                    return_value=qualification_expected,
                ),
                mock.patch.object(
                    verify,
                    "_commit_datetime",
                    side_effect=lambda _repo_path, commit: (
                        _utc("2026-07-24T00:00:00Z")
                        if commit == repair_commit
                        else _utc("2026-07-24T00:00:05Z")
                    ),
                ),
                mock.patch.object(
                    verify, "_source_release_signer", return_value=signer
                ),
                mock.patch.object(
                    verify, "_verify_ssh_detached_attestation", attestation
                ),
            ):
                return verify._verify_framework_recovery_5_qualification(
                    Path("."),
                    repair_commit,
                    qualification_commit,
                    plan=qualification_plan,
                )

        qualification_document = {
            **copy.deepcopy(qualification_expected),
            "created_at_utc": "2026-07-24T00:00:03Z",
            "detached_signature": {"signature": "qualification-fixture"},
        }
        qualification_attestation = mock.Mock()
        self.assertEqual(
            execute_qualification(qualification_document, qualification_attestation),
            qualification_document,
        )
        qualification_unsigned = {
            key: copy.deepcopy(value)
            for key, value in qualification_document.items()
            if key != "detached_signature"
        }
        self.assertEqual(
            qualification_attestation.call_args.args[2],
            verify._canonical_json_bytes(qualification_unsigned),
        )
        self.assertEqual(
            qualification_attestation.call_args.args[1],
            qualification_document["detached_signature"],
        )
        self.assertEqual(
            qualification_attestation.call_args.kwargs,
            {
                "namespace": "haldir-framework-recovery-fr-0005-qualification-v1",
                "label": "framework_recovery_5.qualification",
                "expected_principal": signer["principal"],
                "expected_public_key": signer["public_key"],
                "expected_fingerprint": signer["key_fingerprint"],
            },
        )
        early_qualification = {
            **copy.deepcopy(qualification_document),
            "created_at_utc": "2026-07-24T00:00:01Z",
        }
        rejected_qualification_attestation = mock.Mock()
        with self.assertRaisesRegex(
            verify.CurrentAuditError,
            "CURRENT_AUDIT_FRAMEWORK_RECOVERY_5_QUALIFICATION_CHRONOLOGY",
        ):
            execute_qualification(
                early_qualification, rejected_qualification_attestation
            )
        rejected_qualification_attestation.assert_not_called()
        wrong_qualification_attempt = copy.deepcopy(qualification_document)
        wrong_qualification_attempt["hosted_run_attempts"][0]["attempt"] = 1
        rejected_attempt_attestation = mock.Mock()
        with self.assertRaisesRegex(
            verify.CurrentAuditError,
            "CURRENT_AUDIT_FRAMEWORK_RECOVERY_5_QUALIFICATION_INVALID",
        ):
            execute_qualification(
                wrong_qualification_attempt, rejected_attempt_attestation
            )
        rejected_attempt_attestation.assert_not_called()

        def execute(document, attestation):
            with (
                mock.patch.object(
                    verify,
                    "_verify_data_only_commit",
                    return_value={
                        "subject": verify.FRAMEWORK_RECOVERY_5_ACTIVATION_SUBJECT
                    },
                ),
                mock.patch.object(verify, "_framework_recovery_5_verify_stage_modes"),
                mock.patch.object(
                    verify, "_git_tree_entry", return_value={"oid": "same"}
                ),
                mock.patch.object(
                    verify,
                    "_read_commit_json",
                    return_value=(
                        document,
                        verify._canonical_json_bytes(document, pretty=True),
                    ),
                ),
                mock.patch.object(
                    verify,
                    "_framework_recovery_2_catalog_record",
                    side_effect=(
                        ({"id": "FR-0005-A01"}, [b"{}"]),
                        ({"id": "FR-0005-A02"}, [b"{}"]),
                    ),
                ),
                mock.patch.object(
                    verify,
                    "_framework_recovery_5_verify_hosted_entry",
                    side_effect=(
                        (hosted["qualification_ci"], _utc("2026-07-24T00:00:01Z")),
                        (
                            hosted["qualification_formal"],
                            _utc("2026-07-24T00:00:02Z"),
                        ),
                    ),
                ),
                mock.patch.object(verify, "_framework_recovery_5_verify_ci_markers"),
                mock.patch.object(
                    verify, "_framework_recovery_5_verify_run_attempt_uniqueness"
                ),
                mock.patch.object(
                    verify,
                    "_framework_recovery_5_expected_activation",
                    return_value=expected,
                ),
                mock.patch.object(
                    verify,
                    "_commit_datetime",
                    side_effect=lambda _repo_path, commit: (
                        _utc("2026-07-24T00:00:00Z")
                        if commit == qualification_commit
                        else _utc("2026-07-24T00:00:04Z")
                    ),
                ),
                mock.patch.object(
                    verify, "_source_release_signer", return_value=signer
                ),
                mock.patch.object(
                    verify, "_verify_ssh_detached_attestation", attestation
                ),
            ):
                return verify._verify_framework_recovery_5_activation(
                    Path("."),
                    repair_commit,
                    qualification_commit,
                    activation_commit,
                    qualification=qualification_record,
                )

        document = {
            **copy.deepcopy(expected),
            "created_at_utc": "2026-07-24T00:00:03Z",
            "detached_signature": {"signature": "fixture"},
        }
        attestation = mock.Mock()
        self.assertEqual(execute(document, attestation), document)
        unsigned = {
            key: copy.deepcopy(value)
            for key, value in document.items()
            if key != "detached_signature"
        }
        self.assertIn("created_at_utc", unsigned)
        self.assertNotIn("detached_signature", unsigned)
        self.assertEqual(
            attestation.call_args.args[2], verify._canonical_json_bytes(unsigned)
        )
        self.assertEqual(attestation.call_args.args[1], document["detached_signature"])
        self.assertEqual(
            attestation.call_args.kwargs,
            {
                "namespace": "haldir-framework-recovery-fr-0005-activation-v1",
                "label": "framework_recovery_5.activation",
                "expected_principal": signer["principal"],
                "expected_public_key": signer["public_key"],
                "expected_fingerprint": signer["key_fingerprint"],
            },
        )
        too_early = {
            **copy.deepcopy(document),
            "created_at_utc": "2026-07-24T00:00:01Z",
        }
        rejected_attestation = mock.Mock()
        with self.assertRaisesRegex(
            verify.CurrentAuditError,
            "CURRENT_AUDIT_FRAMEWORK_RECOVERY_5_ACTIVATION_CHRONOLOGY",
        ):
            execute(too_early, rejected_attestation)
        rejected_attestation.assert_not_called()

    def test_framework_recovery_5_history_requires_exact_position(self) -> None:
        verify = _load_verify()
        source = _function_source(verify, "_verify_framework_recovery_5_history")
        self.assertIn("parent_index != 24", source)
        self.assertIn("chain[parent_index - 1] != FRAMEWORK_RECOVERY_4_PARENT", source)
        chain = [f"{index + 1:040x}" for index in range(26)]
        chain[23] = verify.FRAMEWORK_RECOVERY_4_PARENT
        chain[24] = verify.FRAMEWORK_RECOVERY_5_PARENT
        chain[25] = "f" * 40
        with mock.patch.object(
            verify, "_verify_framework_recovery_5_repair", return_value={}
        ):
            result = verify._verify_framework_recovery_5_history(
                Path("."), chain, framework_commit="e" * 40
            )
        self.assertEqual(result["state"], "PENDING_QUALIFICATION")
        self.assertEqual(result["candidate_framework_epoch"], 6)
        self.assertEqual(result["active_framework_epoch"], 2)
        qualified = [*chain, "d" * 40]
        with (
            mock.patch.object(
                verify, "_verify_framework_recovery_5_repair", return_value={}
            ),
            mock.patch.object(
                verify,
                "_verify_framework_recovery_5_qualification",
                return_value={},
            ),
        ):
            qualified_result = verify._verify_framework_recovery_5_history(
                Path("."), qualified, framework_commit="e" * 40
            )
        self.assertEqual(qualified_result["state"], "QUALIFIED_PENDING_ACTIVATION")
        self.assertEqual(qualified_result["active_framework_epoch"], 2)
        self.assertFalse(qualified_result["successor_transitions_allowed"])
        activated = [*qualified, "c" * 40]
        with (
            mock.patch.object(
                verify, "_verify_framework_recovery_5_repair", return_value={}
            ),
            mock.patch.object(
                verify,
                "_verify_framework_recovery_5_qualification",
                return_value={},
            ),
            mock.patch.object(verify, "_verify_framework_recovery_5_activation"),
        ):
            active_result = verify._verify_framework_recovery_5_history(
                Path("."), activated, framework_commit="e" * 40
            )
        self.assertEqual(active_result["state"], "ACTIVE")
        self.assertEqual(active_result["active_framework_epoch"], 6)
        self.assertTrue(active_result["successor_transitions_allowed"])
        wrong = ["0" * 40, *chain]
        with self.assertRaisesRegex(verify.CurrentAuditError, "POSITION"):
            verify._verify_framework_recovery_5_history(
                Path("."), wrong, framework_commit="e" * 40
            )

    def test_framework_recovery_5_retires_fr_0004_without_qualification(self) -> None:
        verify = _load_verify()
        source = _function_source(verify, "_verify_framework_recovery_4_history")
        for token in (
            "FRAMEWORK_RECOVERY_5_SUBJECT",
            '"state": "ABORTED_BEFORE_QUALIFICATION"',
            "FRAMEWORK_RECOVERY_4_RETIREMENT_ABSORPTION",
        ):
            self.assertIn(token, source)
        chain = [f"{index + 1:040x}" for index in range(27)]
        chain[22] = verify.FRAMEWORK_RECOVERY_3_PARENT
        chain[23] = verify.FRAMEWORK_RECOVERY_4_PARENT
        chain[24] = verify.FRAMEWORK_RECOVERY_5_PARENT
        chain[25] = "e" * 40
        chain[26] = "f" * 40

        def metadata(_repo_path, commit):
            if commit == chain[25]:
                return {
                    "parent": verify.FRAMEWORK_RECOVERY_5_PARENT,
                    "subject": verify.FRAMEWORK_RECOVERY_5_SUBJECT,
                }
            return {
                "parent": chain[25],
                "subject": verify.FRAMEWORK_RECOVERY_4_QUALIFICATION_SUBJECT,
            }

        with (
            mock.patch.object(
                verify, "_verify_framework_recovery_4_repair", return_value={}
            ),
            mock.patch.object(
                verify, "_verify_framework_recovery_5_repair", return_value={}
            ),
            mock.patch.object(verify, "_commit_metadata", side_effect=metadata),
            mock.patch.object(verify, "_git_path_exists", return_value=False),
        ):
            retired = verify._verify_framework_recovery_4_history(
                Path("."), chain[:-1], framework_commit="d" * 40
            )
        self.assertEqual(retired["state"], "ABORTED_BEFORE_QUALIFICATION")
        self.assertEqual(retired["retirement_commit"], chain[25])
        self.assertIsNone(retired["qualification_commit"])
        self.assertIsNone(retired["activation_commit"])

        with (
            mock.patch.object(
                verify, "_verify_framework_recovery_4_repair", return_value={}
            ),
            mock.patch.object(
                verify, "_verify_framework_recovery_5_repair", return_value={}
            ),
            mock.patch.object(verify, "_commit_metadata", side_effect=metadata),
            mock.patch.object(verify, "_git_path_exists", return_value=False),
            self.assertRaisesRegex(verify.CurrentAuditError, "RETIREMENT_ABSORPTION"),
        ):
            verify._verify_framework_recovery_4_history(
                Path("."), chain, framework_commit="d" * 40
            )

    def test_framework_recovery_5_successor_requires_activation(self) -> None:
        verify = _load_verify()
        repair, qualification, activation, successor = (
            "a" * 40,
            "b" * 40,
            "c" * 40,
            "d" * 40,
        )
        chain = [repair, qualification]
        with self.assertRaisesRegex(
            verify.CurrentAuditError,
            "FRAMEWORK_RECOVERY_5_SUCCESSOR_BEFORE_ACTIVATION",
        ):
            verify._framework_recovery_5_verify_successor_guard(
                chain,
                1,
                repair_commit=repair,
                activation_commit=None,
                recovery_transition=None,
            )
        verify._framework_recovery_5_verify_successor_guard(
            chain,
            1,
            repair_commit=repair,
            activation_commit=None,
            recovery_transition={"stage": "QUALIFICATION"},
        )
        activated = [repair, activation, successor]
        verify._framework_recovery_5_verify_successor_guard(
            activated,
            2,
            repair_commit=repair,
            activation_commit=activation,
            recovery_transition=None,
        )
        fr4_source = _function_source(
            verify, "_framework_recovery_4_verify_successor_guard"
        )
        self.assertIn("terminal_commit", fr4_source)
        fr4_repair, fr5_repair, ordinary = "e" * 40, "f" * 40, "1" * 40
        retired_chain = [fr4_repair, fr5_repair, ordinary]
        verify._framework_recovery_4_verify_successor_guard(
            retired_chain,
            1,
            repair_commit=fr4_repair,
            activation_commit=fr5_repair,
            recovery_transition={"stage": "REPAIR"},
        )
        verify._framework_recovery_4_verify_successor_guard(
            retired_chain,
            2,
            repair_commit=fr4_repair,
            activation_commit=fr5_repair,
            recovery_transition=None,
        )

    def test_framework_recovery_5_forward_replay_has_pre_activation_guard(self) -> None:
        verify = _load_verify()
        source = _function_source(verify, "_verify_forward_protocol_history")
        for token in (
            "FRAMEWORK_RECOVERY_5_PLAN_PATH",
            "FRAMEWORK_RECOVERY_5_QUALIFICATION_STATUSES",
            "FRAMEWORK_RECOVERY_5_ACTIVATION_STATUSES",
            "recovery_5_repair_commit",
            "recovery_5_activation_commit",
            "_framework_recovery_5_verify_successor_guard",
            "framework_epoch =",
            "6",
        ):
            self.assertIn(token, source)

        history_chain = [f"{index + 1:040x}" for index in range(28)]
        history_chain[22] = verify.FRAMEWORK_RECOVERY_3_PARENT
        history_chain[23] = verify.FRAMEWORK_RECOVERY_4_PARENT
        history_chain[24] = verify.FRAMEWORK_RECOVERY_5_PARENT
        fr4_repair = history_chain[24]
        fr5_repair = history_chain[25]
        fr5_qualification = history_chain[26]
        fr5_activation = history_chain[27]

        def recovery_metadata(_repo_path, commit):
            if commit == fr5_repair:
                return {
                    "parent": fr4_repair,
                    "subject": verify.FRAMEWORK_RECOVERY_5_SUBJECT,
                }
            return {"parent": "0" * 40, "subject": "release: inert fixture"}

        with (
            mock.patch.object(
                verify, "_verify_framework_recovery_4_repair", return_value={}
            ),
            mock.patch.object(
                verify, "_verify_framework_recovery_5_repair", return_value={}
            ),
            mock.patch.object(
                verify, "_commit_metadata", side_effect=recovery_metadata
            ),
            mock.patch.object(verify, "_git_path_exists", return_value=False),
        ):
            retired_fr4 = verify._verify_framework_recovery_4_history(
                Path("."), history_chain, framework_commit="e" * 40
            )
        with mock.patch.object(
            verify, "_verify_framework_recovery_5_repair", return_value={}
        ):
            pending_fr5 = verify._verify_framework_recovery_5_history(
                Path("."), history_chain[:26], framework_commit="e" * 40
            )
        with (
            mock.patch.object(
                verify, "_verify_framework_recovery_5_repair", return_value={}
            ),
            mock.patch.object(
                verify,
                "_verify_framework_recovery_5_qualification",
                return_value={"qualified": True},
            ),
            mock.patch.object(verify, "_verify_framework_recovery_5_activation"),
        ):
            active_fr5 = verify._verify_framework_recovery_5_history(
                Path("."), history_chain, framework_commit="e" * 40
            )
        self.assertEqual(retired_fr4["state"], "ABORTED_BEFORE_QUALIFICATION")
        self.assertEqual(retired_fr4["retirement_commit"], fr5_repair)
        self.assertEqual(pending_fr5["state"], "PENDING_QUALIFICATION")
        self.assertEqual(active_fr5["state"], "ACTIVE")
        self.assertEqual(active_fr5["activation_commit"], fr5_activation)

        framework = "1" * 40
        qualification = "2" * 40
        activation = "3" * 40
        ordinary = "4" * 40
        claims = {"public_surface_records": []}
        ledger = {"tasks": [{"id": "CH-T000"}, {"id": "CH-T001"}]}
        registration = {"task_id": "CH-T001", "epoch": 1}

        def protocol_document(_payload, label):
            if "claims" in label:
                return copy.deepcopy(claims)
            if label == "protocol.registry":
                return {"registrations": [copy.deepcopy(registration)]}
            if "registry" in label:
                return {"registrations": []}
            if "revocation" in label:
                return {"records": []}
            return copy.deepcopy(ledger)

        base_recovery = {
            "repair_commit": "9" * 40,
            "qualification_commit": None,
            "activation_commit": None,
        }
        pre_activation_recovery = {
            **base_recovery,
            "subsequent_recoveries": [retired_fr4, pending_fr5],
        }
        pre_activation_chain = [
            framework,
            qualification,
            activation,
            fr4_repair,
            fr5_repair,
            ordinary,
        ]
        pre_activation_gate_epochs = []
        with (
            mock.patch.object(verify, "_git_file", return_value=b"{}"),
            mock.patch.object(
                verify, "_load_json_bytes", side_effect=protocol_document
            ),
            mock.patch.object(verify, "_verify_terminal_requirement_state"),
            mock.patch.object(
                verify, "_expected_initial_active_claims", return_value=claims
            ),
            mock.patch.object(
                verify, "_initial_claims_before_ch_t000", return_value=claims
            ),
            mock.patch.object(
                verify,
                "_expected_empty_successor_registry",
                return_value={"registrations": []},
            ),
            mock.patch.object(
                verify,
                "_expected_empty_revocation_ledger",
                return_value={"records": []},
            ),
            mock.patch.object(verify, "_verify_protocol_commit_identity"),
            mock.patch.object(
                verify,
                "_verify_post_activation_gate_retention",
                side_effect=lambda *_args, **kwargs: pre_activation_gate_epochs.append(
                    kwargs["framework_epoch"]
                ),
            ),
            mock.patch.object(verify, "_changed_path_statuses", return_value={}),
            mock.patch.object(verify, "_validate_protocol_changed_paths"),
            mock.patch.object(verify, "_verify_changed_hygiene", return_value=0),
            mock.patch.object(verify, "_verify_framework_recovery_transition"),
            self.assertRaisesRegex(
                verify.CurrentAuditError,
                "FRAMEWORK_RECOVERY_5_SUCCESSOR_BEFORE_ACTIVATION",
            ),
        ):
            verify._verify_forward_protocol_history(
                Path("."),
                pre_activation_chain,
                framework_commit=framework,
                qualification_commit=qualification,
                activation_commit=activation,
                recovery=pre_activation_recovery,
            )
        self.assertEqual(pre_activation_gate_epochs, [5, 6, 6])

        post_activation = "5" * 40
        task_paths = verify._task_epoch_paths("CH-T001", 1)
        post_activation_statuses = dict(
            sorted(
                {
                    verify.SUCCESSOR_REGISTRY_PATH: "M",
                    task_paths["verifier"]: "A",
                    task_paths["tests"]: "A",
                    task_paths["freeze"]: "A",
                }.items()
            )
        )
        active_recovery = {
            **base_recovery,
            "subsequent_recoveries": [retired_fr4, active_fr5],
        }
        active_chain = [
            framework,
            qualification,
            activation,
            fr4_repair,
            fr5_repair,
            fr5_qualification,
            fr5_activation,
            post_activation,
        ]
        active_gate_epochs = []

        def changed_statuses(_repo_path, _previous, commit):
            return post_activation_statuses if commit == post_activation else {}

        transition = mock.Mock()
        registered = mock.Mock(return_value=(registration, {"implementation_plan": {}}))
        with (
            mock.patch.object(verify, "_git_file", return_value=b"{}"),
            mock.patch.object(
                verify, "_load_json_bytes", side_effect=protocol_document
            ),
            mock.patch.object(verify, "_verify_terminal_requirement_state"),
            mock.patch.object(
                verify, "_expected_initial_active_claims", return_value=claims
            ),
            mock.patch.object(
                verify, "_initial_claims_before_ch_t000", return_value=claims
            ),
            mock.patch.object(
                verify,
                "_expected_empty_successor_registry",
                return_value={"registrations": []},
            ),
            mock.patch.object(
                verify,
                "_expected_empty_revocation_ledger",
                return_value={"records": []},
            ),
            mock.patch.object(verify, "_verify_protocol_commit_identity"),
            mock.patch.object(
                verify,
                "_verify_post_activation_gate_retention",
                side_effect=lambda *_args, **kwargs: active_gate_epochs.append(
                    kwargs["framework_epoch"]
                ),
            ),
            mock.patch.object(
                verify, "_changed_path_statuses", side_effect=changed_statuses
            ),
            mock.patch.object(verify, "_validate_protocol_changed_paths"),
            mock.patch.object(verify, "_verify_changed_hygiene", return_value=0),
            mock.patch.object(
                verify, "_verify_framework_recovery_transition", transition
            ),
            mock.patch.object(verify, "_commit_file_record", return_value={}),
            mock.patch.object(
                verify, "_validate_successor_registration_v2", registered
            ),
        ):
            self.assertIsNone(
                verify._verify_forward_protocol_history(
                    Path("."),
                    active_chain,
                    framework_commit=framework,
                    qualification_commit=qualification,
                    activation_commit=activation,
                    recovery=active_recovery,
                )
            )
        self.assertEqual(active_gate_epochs, [5, 6, 6, 6, 6])
        self.assertEqual(
            [call.kwargs["transition"]["stage"] for call in transition.call_args_list],
            ["REPAIR", "REPAIR", "QUALIFICATION", "ACTIVATION"],
        )
        registered.assert_called_once()

    def test_framework_recovery_5_source_retention_projects_all_recoveries(
        self,
    ) -> None:
        verify = _load_verify()
        repair = _repair_commit()
        manifest = verify._framework_recovery_5_source_retention_manifest(
            _repo(), repair
        )
        self.assertEqual(
            set(manifest["modified_definitions"]),
            verify.FRAMEWORK_RECOVERY_5_MODIFIED_DEFINITIONS,
        )
        self.assertEqual(
            set(manifest["new_definitions"]),
            verify.FRAMEWORK_RECOVERY_5_NEW_DEFINITIONS,
        )
        for projection in (
            verify._framework_recovery_4_source_retention_manifest,
            verify._framework_recovery_3_source_retention_manifest,
            verify._framework_recovery_2_source_retention_manifest,
        ):
            with self.subTest(projection=projection.__name__):
                projected = projection(_repo(), repair)
                if "protected_residual" in projected:
                    self.assertTrue(projected["protected_residual"]["byte_exact"])

    def test_framework_recovery_5_source_retention_rejects_parent_pin_drift(
        self,
    ) -> None:
        verify = _load_verify()
        parent = verify._git_file(
            _repo(), PARENT_COMMIT, "tools/release/verify-current-audit.py"
        )
        target = Path(verify.__file__).read_bytes()

        def function_interval(payload: bytes, name: str) -> bytes:
            tree = ast.parse(payload.decode("utf-8"))
            starts = [0]
            for line in payload.splitlines(keepends=True):
                starts.append(starts[-1] + len(line))
            nodes = [
                node
                for node in tree.body
                if isinstance(node, ast.FunctionDef) and node.name == name
            ]
            self.assertEqual(len(nodes), 1)
            node = nodes[0]
            self.assertIsNotNone(node.end_lineno)
            end = (
                starts[node.end_lineno]
                if node.end_lineno is not None and node.end_lineno < len(starts)
                else len(payload)
            )
            return payload[starts[node.lineno - 1] : end]

        protected_name = "_verify_framework_recovery_4_activation"
        parent_interval = function_interval(parent, protected_name)
        target_interval = function_interval(target, protected_name)
        self.assertEqual(parent_interval, target_interval)
        self.assertEqual(
            hashlib.sha256(target_interval).hexdigest(),
            "81f07dd42c7e8e28ef1b39cf2e28abf374de220ec0bc28d6e69162f63adc0bcb",
        )
        spoofed = target.replace(
            (b'FRAMEWORK_RECOVERY_5_PARENT = "' + PARENT_COMMIT.encode("ascii") + b'"'),
            b'FRAMEWORK_RECOVERY_5_PARENT = "' + b"0" * 40 + b'"',
            1,
        )
        self.assertNotEqual(spoofed, target)
        with self.assertRaisesRegex(verify.CurrentAuditError, "SOURCE_COMPATIBILITY"):
            verify._framework_recovery_5_validate_source_compatibility(parent, spoofed)
        fr4_parent = verify._git_file(
            _repo(),
            verify.FRAMEWORK_RECOVERY_4_PARENT,
            "tools/release/verify-current-audit.py",
        )
        for entry in (
            {"mode": "100755", "type": "blob", "oid": "a" * 40},
            {"mode": "100644", "type": "tree", "oid": "a" * 40},
        ):
            with (
                self.subTest(entry=entry),
                mock.patch.object(
                    verify,
                    "_git_file",
                    side_effect=lambda _repo_path, commit, _path: (
                        fr4_parent
                        if commit == verify.FRAMEWORK_RECOVERY_4_PARENT
                        else target
                    ),
                ),
                mock.patch.object(verify, "_git_tree_entry", return_value=entry),
                self.assertRaisesRegex(
                    verify.CurrentAuditError, "SOURCE_COMPATIBILITY"
                ),
            ):
                verify._framework_recovery_4_source_retention_manifest(
                    _repo(), "f" * 40
                )

    def test_framework_recovery_5_source_retention_rejects_unrelated_change(
        self,
    ) -> None:
        verify = _load_verify()
        parent = verify._git_file(
            _repo(), PARENT_COMMIT, "tools/release/verify-current-audit.py"
        )
        target = Path(verify.__file__).read_bytes()
        real_index_mutations = (
            (
                "unrelated_function",
                target.replace(
                    b"return hashlib.sha256(payload).hexdigest()",
                    b"return hashlib.sha256(payload + b'x').hexdigest()",
                    1,
                ),
            ),
            (
                "unrelated_assignment",
                target.replace(
                    b"MAX_JSON_BYTES = 256 * 1024",
                    b"MAX_JSON_BYTES = 1",
                    1,
                ),
            ),
            (
                "import",
                target.replace(b"import ast\n", b"import ast\nimport decimal\n", 1),
            ),
        )
        required_pin_literals = (
            PARENT_COMMIT.encode("ascii"),
            PARENT_TREE.encode("ascii"),
            b"5b430e13ea56154f7879952047b65d69d5d1608e5c1234f197a8d2b5008f4375",
            b"d33e0b30586a77717e282947a375253a816ce84b53620cba300f5d30657234f4",
        )
        for kind, source_mutation in real_index_mutations:
            self.assertNotEqual(source_mutation, target)
            self.assertTrue(
                all(pin in source_mutation for pin in required_pin_literals)
            )
            with (
                self.subTest(kind=kind),
                self.assertRaisesRegex(
                    verify.CurrentAuditError, "SOURCE_COMPATIBILITY"
                ),
            ):
                verify._framework_recovery_5_validate_source_compatibility(
                    parent, source_mutation
                )
        for protected_mutation in (
            target.replace(
                b"\ndef _verify_framework_recovery_history(",
                b"\n# unauthorized interstitial drift\n"
                b"def _verify_framework_recovery_history(",
                1,
            ),
            target.replace(
                b"\ndef _verify_framework_recovery_history(",
                b"\n\ndef _verify_framework_recovery_history(",
                1,
            ),
        ):
            self.assertNotEqual(protected_mutation, target)
            self.assertTrue(
                all(pin in protected_mutation for pin in required_pin_literals)
            )
            with (
                self.subTest(kind="protected_residual"),
                self.assertRaisesRegex(
                    verify.CurrentAuditError, "SOURCE_COMPATIBILITY"
                ),
            ):
                verify._framework_recovery_5_validate_source_compatibility(
                    parent, protected_mutation
                )

    def test_framework_recovery_5_wrapper_accepts_epochs_2_through_6(self) -> None:
        verify = _load_verify()
        chain = _git(
            "rev-list",
            "--first-parent",
            "--reverse",
            f"{verify.IMPLEMENTATION_COMMIT}..{_repair_commit()}",
        ).splitlines()
        commits = {2: chain[2], 3: chain[22], 4: chain[23], 5: chain[24], 6: chain[25]}
        for epoch, commit in commits.items():
            with self.subTest(epoch=epoch):
                verify._verify_post_activation_gate_retention(
                    _repo(), commit, framework_epoch=epoch, compare_worktree=False
                )
        with self.assertRaisesRegex(verify.CurrentAuditError, "WRAPPER_DRIFT"):
            verify._verify_post_activation_gate_retention(
                _repo(),
                _repair_commit(),
                framework_epoch=5,
                compare_worktree=False,
            )
        for invalid in (True, 1, 7):
            with (
                self.subTest(epoch=invalid),
                self.assertRaisesRegex(verify.CurrentAuditError, "EPOCH_INVALID"),
            ):
                verify._verify_post_activation_gate_retention(
                    _repo(),
                    _repair_commit(),
                    framework_epoch=invalid,
                    compare_worktree=False,
                )


if __name__ == "__main__":
    unittest.main()
