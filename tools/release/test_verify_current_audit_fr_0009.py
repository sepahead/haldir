"""Test the FR-0009 hosted-log protocol-binding recovery."""

from __future__ import annotations

import ast
import copy
import gzip
import hashlib
import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

PARENT_COMMIT = '1e937a4bf213a5605250cf4843f1dfd26ae0ae3b'
PARENT_TREE = 'e343ea41c29543f85db52314f89c7cbdcb813cc2'
PARENT_VERIFIER_OID = '57833cced2fdeb03dd8c56970a1df419499c69d5'
PARENT_VERIFIER_SHA256 = '9d56519d658931b60f87518191f6a0c8e86ff278c754ed735d094d788e12f10d'
PARENT_TEST_OID = '78e1391241c6f99de24980d9db965b2875b998c0'
PARENT_TEST_SHA256 = '3ab220fb0fde58ecaa0efd76900886bc2dd1435a11cd9617382b91075562f3b3'
PARENT_GATE_OID = '4fa7b36570188ab343db8c18d7d4e3895f53c59c'
PARENT_GATE_SHA256 = '92756273c4f48d9bbcdb9b52b1f16ff73e2bf39abaf4f8b4e073adafd9eeb362'
PARENT_P0_OID = '05927d4a6cf144ba09ac1a5ffd111cc508397c42'
PARENT_P0_SHA256 = '8238fd229ffd1e95da26787d793af73523f6980cd6430ec220bd4fa2632e5a64'
PARENT_PLAN_OID = '470947ef9ccb985735067e45f3ea9fc0e811bac3'
PARENT_PLAN_SHA256 = '9bc95771509ccf300dd6906b5abba95f8d34457280d18203090763b85ab592b8'
DEFECT_CODE = 'FR_0008_HOSTED_LOG_BINDING_UNSATISFIABLE'
REPAIR_SUBJECT = 'release: repair hosted log protocol binding'
SUITE_KEYS = (
    'legacy',
    'fr_0002',
    'fr_0003',
    'resource',
    'fr_0004',
    'fr_0005',
    'fr_0006',
    'fr_0007',
    'fr_0008',
    'fr_0009',
)
PARENT_SUITE_COUNTS = (
    163,
    78,
    94,
    26,
    30,
    44,
    56,
    37,
    55,
)
P0_EXTRA_UNITTEST_COUNTS = (
    6,
    10,
    23,
    26,
    22,
    24,
)
REQUIRED_TEST_IDS = {
    'test_framework_recovery_9_activation_scope_is_exact',
    'test_framework_recovery_9_ci_markers_accept_epoch_10_topology',
    'test_framework_recovery_9_ci_markers_reject_order_count_and_failure_mutations',
    'test_framework_recovery_9_code_diff_excludes_plan',
    'test_framework_recovery_9_decision_is_fail_closed',
    'test_framework_recovery_9_expected_gate_payload_is_exact',
    'test_framework_recovery_9_expected_plan_has_exact_contract',
    'test_framework_recovery_9_forward_replay_has_retirement_and_activation_guards',
    'test_framework_recovery_9_fr_0008_guard_accepts_only_fr_0009_retirement',
    'test_framework_recovery_9_framework_history_requires_fr_0008_retirement',
    'test_framework_recovery_9_gate_and_p0_topology_are_derived_from_pinned_sources',
    'test_framework_recovery_9_gate_and_p0_topology_reject_source_order_mutations',
    'test_framework_recovery_9_gate_runs_fr_0008_in_parent_snapshot',
    'test_framework_recovery_9_history_position_and_stages_are_exact',
    'test_framework_recovery_9_hosted_compatibility_projection_is_exact',
    'test_framework_recovery_9_hosted_entry_accepts_exact_subject_workflow_and_attempt',
    'test_framework_recovery_9_hosted_entry_rejects_path_subject_workflow_and_attempt_mutations',
    'test_framework_recovery_9_identity_constants_are_exact',
    'test_framework_recovery_9_local_document_accepts_exact_bound_fixture',
    'test_framework_recovery_9_local_document_rejects_command_time_and_binding_mutations',
    'test_framework_recovery_9_local_document_rejects_marker_resource_and_failure_mutations',
    'test_framework_recovery_9_local_markers_accept_epoch_10_topology',
    'test_framework_recovery_9_local_markers_reject_order_count_ok_and_failure_mutations',
    'test_framework_recovery_9_log_binding_rejects_payload_and_integrity_mutations',
    'test_framework_recovery_9_parent_bytes_are_pinned',
    'test_framework_recovery_9_parent_has_no_fr_0008_q_or_a',
    'test_framework_recovery_9_parent_hosted_log_binding_contradiction_is_reproduced',
    'test_framework_recovery_9_parent_reproduction_accepts_exact_bound_fixture',
    'test_framework_recovery_9_parent_reproduction_reexecutes_parent_defect',
    'test_framework_recovery_9_parent_reproduction_rejects_catalog_and_chronology_mutations',
    'test_framework_recovery_9_parent_reproduction_rejects_command_log_and_receipt_mutations',
    'test_framework_recovery_9_positive_composition_has_no_critical_mocks',
    'test_framework_recovery_9_preserves_all_prior_test_suites',
    'test_framework_recovery_9_protocol_binding_rejects_git_record_mutations',
    'test_framework_recovery_9_qualification_scope_is_exact',
    'test_framework_recovery_9_real_builder_and_validator_compose',
    'test_framework_recovery_9_repair_scope_is_exact',
    'test_framework_recovery_9_reproduction_raw_is_verbose_identity_bound_and_canonical_gzip',
    'test_framework_recovery_9_reproduction_raw_rejects_noncanonical_and_wrong_identity_mutations',
    'test_framework_recovery_9_retirement_absorbs_no_fr_0008_q_or_a',
    'test_framework_recovery_9_retires_fr_0008_without_qualification',
    'test_framework_recovery_9_review_eligibility_accepts_two_go_reviews',
    'test_framework_recovery_9_review_eligibility_rejects_no_go_open_or_blocking',
    'test_framework_recovery_9_review_keys_are_separate',
    'test_framework_recovery_9_review_validator_accepts_additional_findings',
    'test_framework_recovery_9_review_validator_accepts_truthful_go',
    'test_framework_recovery_9_review_validator_accepts_truthful_no_go',
    'test_framework_recovery_9_review_validator_rejects_malformed_and_duplicate_findings',
    'test_framework_recovery_9_review_validator_rejects_model_fallback_and_wrong_model',
    'test_framework_recovery_9_run_attempt_uniqueness_accepts_distinct_attempt',
    'test_framework_recovery_9_run_attempt_uniqueness_rejects_reserved_and_duplicate',
    'test_framework_recovery_9_signatures_and_chronology_are_bound',
    'test_framework_recovery_9_source_compatibility_rejects_drift',
    'test_framework_recovery_9_source_retention_is_exact',
    'test_framework_recovery_9_successor_requires_activation',
    'test_framework_recovery_9_test_source_ast_and_discovery_are_strict',
    'test_framework_recovery_9_transition_retires_epoch_9_and_creates_epoch_10',
    'test_framework_recovery_9_warning_policy_is_exact_per_suite',
    'test_framework_recovery_9_warning_policy_rejects_fr_0002_exception_misstatement',
    'test_framework_recovery_9_wrapper_accepts_epochs_2_through_10',
}
EXPECTED_MODIFIED_DEFINITIONS = {
    '_framework_recovery_2_source_retention_manifest',
    '_framework_recovery_3_source_retention_manifest',
    '_framework_recovery_3_verify_hosted_entry',
    '_framework_recovery_4_source_retention_manifest',
    '_framework_recovery_5_source_retention_manifest',
    '_framework_recovery_8_verify_successor_guard',
    '_verify_forward_protocol_history',
    '_verify_framework_history',
    '_verify_framework_recovery_8_history',
    '_verify_post_activation_gate_retention',
}
def _repo() -> Path:
    path = Path(__file__).resolve()
    for parent in path.parents:
        if (parent / ".git").exists():
            return parent
    raise RuntimeError("repository root not found")


def _git(
    repo: Path,
    *arguments: str,
    **options: object,
) -> bytes:
    input_value = options.pop("input_bytes", None)
    environment_value = options.pop("environment", None)
    if (
        options
        or input_value is not None
        and not isinstance(input_value, bytes)
        or environment_value is not None
        and not isinstance(environment_value, dict)
    ):
        raise RuntimeError("invalid Git helper options")
    input_bytes = input_value
    environment = environment_value
    env = {
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }
    if environment:
        env.update(environment)
    completed = subprocess.run(
        ("/usr/bin/git", "-c", "core.hooksPath=/dev/null", *arguments),
        cwd=repo,
        env=env,
        input=input_bytes,
        stdin=None if input_bytes is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=30,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            completed.stderr.decode("utf-8", errors="replace").strip()
        )
    return completed.stdout


def _load_verify(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load verifier")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _canonical_json(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")


def _canonical_gzip(payload: bytes) -> bytes:
    compressed = gzip.compress(payload, compresslevel=9, mtime=0)
    return compressed[:9] + b"\x03" + compressed[10:]


def _commit(
    repo: Path,
    tree: str,
    *,
    parent: str | None,
    subject: str,
    timestamp: str,
) -> str:
    arguments = ["commit-tree", tree]
    if parent is not None:
        arguments.extend(("-p", parent))
    environment = {
        "GIT_AUTHOR_NAME": "Fixture",
        "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
        "GIT_AUTHOR_DATE": timestamp,
        "GIT_COMMITTER_NAME": "Fixture",
        "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
        "GIT_COMMITTER_DATE": timestamp,
    }
    return (
        _git(
            repo,
            *arguments,
            input_bytes=(subject + "\n").encode("utf-8"),
            environment=environment,
        )
        .decode("ascii")
        .strip()
    )


def _parent_source(repo: Path, name: str) -> bytes:
    payload = _git(
        repo,
        "show",
        f"{PARENT_COMMIT}:tools/release/verify-current-audit.py",
    )
    tree = ast.parse(payload.decode("utf-8"))
    lines = payload.splitlines(keepends=True)
    matches = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == name
    ]
    if len(matches) != 1 or matches[0].end_lineno is None:
        raise RuntimeError(f"missing parent function: {name}")
    node = matches[0]
    return b"".join(lines[node.lineno - 1 : node.end_lineno])


def _function_source(path: Path, name: str) -> bytes:
    payload = path.read_bytes()
    tree = ast.parse(payload.decode("utf-8"))
    lines = payload.splitlines(keepends=True)
    matches = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == name
    ]
    if len(matches) != 1 or matches[0].end_lineno is None:
        raise RuntimeError(f"missing function: {name}")
    node = matches[0]
    return b"".join(lines[node.lineno - 1 : node.end_lineno])


def _hosted_fixture(module):
    temporary = tempfile.TemporaryDirectory(prefix="haldir-fr9-hosted-")
    repo = Path(temporary.name)
    _git(repo, "init", "--quiet")
    empty_tree = _git(repo, "mktree", input_bytes=b"").decode("ascii").strip()
    base = _commit(
        repo,
        empty_tree,
        parent=None,
        subject="fixture base",
        timestamp="2029-12-31T23:59:59+0000",
    )
    subject = _commit(
        repo,
        empty_tree,
        parent=base,
        subject="fixture subject",
        timestamp="2030-01-01T00:00:00+0000",
    )
    run_id = 90000000001
    created = "2030-01-01T00:00:01Z"
    started = "2030-01-01T00:00:02Z"
    updated = "2030-01-01T00:00:05Z"
    attempt_updated = "2030-01-01T00:00:06Z"
    step = {
        "completedAt": "2030-01-01T00:00:04Z",
        "conclusion": "success",
        "name": "Model-check HaldirAuthority",
        "number": 1,
        "startedAt": "2030-01-01T00:00:02Z",
        "status": "completed",
    }
    job = {
        "completedAt": "2030-01-01T00:00:04Z",
        "conclusion": "success",
        "databaseId": 90000000002,
        "name": "tlc-model-check",
        "startedAt": "2030-01-01T00:00:02Z",
        "status": "completed",
        "steps": [step],
        "url": "https://github.com/sepahead/haldir/actions/jobs/90000000002",
    }
    common = {
        "attempt": 1,
        "conclusion": "success",
        "createdAt": created,
        "databaseId": run_id,
        "event": "push",
        "headBranch": "main",
        "headSha": subject,
        "jobs": [job],
        "status": "completed",
        "updatedAt": updated,
        "url": f"https://github.com/sepahead/haldir/actions/runs/{run_id}",
        "workflowName": "formal",
    }
    metadata = copy.deepcopy(common)
    attempt = {
        **copy.deepcopy(common),
        "startedAt": started,
        "updatedAt": attempt_updated,
        "url": (
            f"https://github.com/sepahead/haldir/actions/runs/{run_id}/attempts/1"
        ),
        "workflowDatabaseId": 311703244,
    }
    paths = (
        "evidence/fr9-formal.json",
        "evidence/fr9-formal-attempt.json",
        "evidence/fr9-formal.log.gz",
    )
    log = (
        subject.encode("ascii")
        + b"\nModel checking completed. No error has been found.\n"
        + b"Finished in 1s\n"
    )
    payloads = {
        paths[0]: _canonical_json(metadata),
        paths[1]: _canonical_json(attempt),
        paths[2]: _canonical_gzip(log),
    }
    index = repo / "fixture.index"
    index_environment = {"GIT_INDEX_FILE": str(index)}
    _git(repo, "read-tree", "--empty", environment=index_environment)
    for path, payload in payloads.items():
        oid = (
            _git(repo, "hash-object", "-w", "--stdin", input_bytes=payload)
            .decode("ascii")
            .strip()
        )
        _git(
            repo,
            "update-index",
            "--add",
            "--cacheinfo",
            "100644",
            oid,
            path,
            environment=index_environment,
        )
    tree = (
        _git(repo, "write-tree", environment=index_environment)
        .decode("ascii")
        .strip()
    )
    containing = _commit(
        repo,
        tree,
        parent=subject,
        subject="fixture evidence",
        timestamp="2030-01-01T00:00:20+0000",
    )
    json_fields = (
        "attempt,conclusion,createdAt,databaseId,event,headBranch,headSha,jobs,"
        "status,updatedAt,url,workflowName"
    )
    attempt_fields = (
        "attempt,conclusion,createdAt,databaseId,event,headBranch,headSha,jobs,"
        "startedAt,status,updatedAt,url,workflowDatabaseId,workflowName"
    )
    ordinary_raw = "/private/tmp/fr9-formal.json.raw"
    ordinary_normalized = "/private/tmp/fr9-formal.json.normalized"
    attempt_raw = "/private/tmp/fr9-formal-attempt.json.raw"
    attempt_normalized = "/private/tmp/fr9-formal-attempt.json.normalized"
    log_raw = "/private/tmp/fr9-formal.log.gz.raw"
    log_decompressed = "/private/tmp/fr9-formal.log.gz.decompressed"
    operations = {
        "ordinary_metadata": {
            "raw_path": ordinary_raw,
            "normalized_path": ordinary_normalized,
            "retained_path": paths[0],
            "capture_command": (
                f"gh run view {run_id} --repo sepahead/haldir --json "
                f"{json_fields} > {ordinary_raw}"
            ),
            "capture_exit_status": 0,
            "normalize_command": (
                f"jq -S . {ordinary_raw} > {ordinary_normalized}"
            ),
            "normalize_exit_status": 0,
            "compare_command": f"cmp {ordinary_normalized} {paths[0]}",
            "compare_exit_status": 0,
            "byte_equal": True,
            "started_at_utc": "2030-01-01T00:00:07Z",
            "completed_at_utc": "2030-01-01T00:00:08Z",
        },
        "attempt_metadata": {
            "raw_path": attempt_raw,
            "normalized_path": attempt_normalized,
            "retained_path": paths[1],
            "capture_command": (
                f"gh run view {run_id} --repo sepahead/haldir --attempt 1 "
                f"--json {attempt_fields} > {attempt_raw}"
            ),
            "capture_exit_status": 0,
            "normalize_command": (
                f"jq -S . {attempt_raw} > {attempt_normalized}"
            ),
            "normalize_exit_status": 0,
            "compare_command": f"cmp {attempt_normalized} {paths[1]}",
            "compare_exit_status": 0,
            "byte_equal": True,
            "started_at_utc": "2030-01-01T00:00:09Z",
            "completed_at_utc": "2030-01-01T00:00:10Z",
        },
        "raw_log": {
            "raw_path": log_raw,
            "retained_path": paths[2],
            "decompressed_path": log_decompressed,
            "capture_command": (
                f"gh run view {run_id} --repo sepahead/haldir --attempt 1 "
                f"--log > {log_raw}"
            ),
            "capture_exit_status": 0,
            "compression_command": (
                f"gzip -n -9 -c {log_raw} > {paths[2]}"
            ),
            "compression_exit_status": 0,
            "decompress_command": (
                f"gzip -cd {paths[2]} > {log_decompressed}"
            ),
            "decompress_exit_status": 0,
            "compare_command": f"cmp {log_raw} {log_decompressed}",
            "compare_exit_status": 0,
            "byte_equal": True,
            "started_at_utc": "2030-01-01T00:00:11Z",
            "completed_at_utc": "2030-01-01T00:00:12Z",
        },
    }
    entry = module._framework_recovery_3_hosted_entry(
        repo,
        containing,
        paths=paths,
        subject_commit=subject,
        workflow="formal",
        capture_operations=operations,
        anomaly_manifest=[],
    )
    return {
        "temporary": temporary,
        "repo": repo,
        "subject": subject,
        "containing": containing,
        "paths": paths,
        "operations": operations,
        "entry": entry,
    }


def _compatibility_entry(module, fixture, *, projected: bool):
    paths = fixture["paths"]
    entry = fixture["entry"]
    attempt = json.loads(
        _git(
            fixture["repo"],
            "show",
            f"{fixture['containing']}:{paths[1]}",
        )
    )
    base = module._framework_recovery_2_hosted_entry(
        fixture["repo"],
        fixture["containing"],
        paths=paths,
        subject_commit=fixture["subject"],
        workflow="formal",
        capture_operations=entry["capture_operations"],
    )
    compatibility_operations = (
        module._framework_recovery_2_verify_capture_operations(
            entry["capture_operations"],
            run_id=attempt["databaseId"],
            workflow="formal",
            paths=paths,
            head=fixture["subject"],
            label="framework_recovery_3.fr_0009_fixture",
            not_before=module._parse_utc(
                attempt["updatedAt"],
                "framework_recovery_3.fr_0009_fixture.attempt.updated",
            ),
            retained_by=module._commit_datetime(
                fixture["repo"], fixture["containing"]
            ),
            expected_attempt=1,
            require_ordinary_attempt=True,
        )
    )
    base.pop("capture_schema")
    base["capture_operations"] = compatibility_operations
    if projected:
        base["files"] = [
            {
                key: value
                for key, value in record.items()
                if key not in {"git_mode", "git_object_type", "git_object_id"}
            }
            for record in base["files"]
        ]
    return base


def _call_wrapper(module, fixture, *entries):
    if len(entries) > 1:
        raise RuntimeError("too many hosted entries")
    entry = fixture["entry"] if not entries else entries[0]
    return module._framework_recovery_3_verify_hosted_entry(
        fixture["repo"],
        fixture["containing"],
        entry,
        paths=fixture["paths"],
        subject_commit=fixture["subject"],
        workflow="formal",
        lane="fr_0009_fixture",
        expected_attempt=1,
        require_ordinary_attempt=True,
    )


def _repair_plan(module, repo: Path):
    head = _git(repo, "rev-parse", "HEAD").decode("ascii").strip()
    suffix = _git(
        repo,
        "rev-list",
        "--first-parent",
        "--reverse",
        f"{PARENT_COMMIT}..{head}",
    ).decode("ascii").splitlines()
    if not suffix:
        raise RuntimeError("FR-0009 repair commit is absent")
    repair_commit = suffix[0]
    parent_plan = json.loads(
        _git(
            repo,
            "show",
            f"{PARENT_COMMIT}:release/0.9.0/current-head/closures/"
            "framework-recovery/FR-0008-plan.json",
        )
    )
    return module._verify_framework_recovery_9_repair(
        repo,
        repair_commit,
        framework_commit=parent_plan["prior_framework_commit"],
    )


def _repair_commit(repo: Path) -> str:
    head = _git(repo, "rev-parse", "HEAD").decode("ascii").strip()
    suffix = _git(
        repo,
        "rev-list",
        "--first-parent",
        "--reverse",
        f"{PARENT_COMMIT}..{head}",
    ).decode("ascii").splitlines()
    if not suffix:
        raise RuntimeError("FR-0009 repair commit is absent")
    return suffix[0]


def _verbose_reproduction_raw() -> bytes:
    method = (
        "test_framework_recovery_9_parent_hosted_log_binding_"
        "contradiction_is_reproduced"
    )
    return (
        f"{method} (__main__.FrameworkRecovery9Tests.{method}) ... ok\n\n"
        + "-" * 70
        + "\nRan 1 test in 0.123s\n\nOK\n"
    ).encode("ascii")


def _marker_log(module, repo: Path) -> bytes:
    contract = _repair_plan(module, repo)["test_contract"]
    counts = [contract[key]["count"] for key in SUITE_KEYS]
    extras = contract["p0_extra_unittest_counts"]
    direct = b"".join(
        f"Ran {count} tests in 0.001s\n\nOK\n".encode("ascii")
        for count in counts
    )
    p0 = b"".join(
        f"Ran {count} tests in 0.001s\n\nOK\n".encode("ascii")
        for count in [*counts, *extras]
    )
    return (
        b"=== CURRENT_AUDIT_GATE ===\n"
        b"$ tools/release/current-audit-gate.sh\n"
        + direct
        + b"verify-current-audit: OK\n"
        + b"=== P0R_EXIT_GATE ===\n"
        + b"$ tools/p0r-exit-gate.sh\n"
        + p0
        + b"verify-current-audit: OK\n"
        + b"P0-R exit gate: 30 passed, 0 failed\n"
        + b"=== RESOURCE_PROFILE ===\n"
        + b"$ python3 -I tools/release/current-audit-resource-profile.py\n"
    )


def _review_outcomes():
    return [
        {
            "review_id": "FR-0009-R01",
            "verdict": "GO_FOR_FRAMEWORK_QUALIFICATION",
            "open_blocker_ids": [],
            "capture_binding": {"raw_response_sha256": "1" * 64},
        },
        {
            "review_id": "FR-0009-R02",
            "verdict": "GO_FOR_FRAMEWORK_QUALIFICATION",
            "open_blocker_ids": [],
            "capture_binding": {"raw_response_sha256": "2" * 64},
        },
    ]


class FrameworkRecovery9Tests(unittest.TestCase):
    """Exercise the signed epoch-10 recovery contract."""

    def test_framework_recovery_9_activation_scope_is_exact(self) -> None:
        """Exercise framework_recovery_9_activation_scope_is_exact."""
        REPO = _repo()
        verify = _load_verify(REPO / "tools/release/verify-current-audit.py", f"_haldir_fr9_verify_{self._testMethodName}")
        expected = {
            verify.FRAMEWORK_RECOVERY_9_ACTIVATION_PATH,
            *[path for requirement in verify.FRAMEWORK_RECOVERY_9_ACTIVATION_REQUIREMENTS for path in requirement["paths"]],
        }
        self.assertEqual(set(verify.FRAMEWORK_RECOVERY_9_ACTIVATION_STATUSES), expected)
        self.assertEqual(len(expected), 7)

    def test_framework_recovery_9_ci_markers_accept_epoch_10_topology(self) -> None:
        """Exercise framework_recovery_9_ci_markers_accept_epoch_10_topology."""
        REPO = _repo()
        verify = _load_verify(REPO / "tools/release/verify-current-audit.py", f"_haldir_fr9_verify_{self._testMethodName}")
        plan = _repair_plan(verify, REPO)
        expected = verify._framework_recovery_9_expected_local_marker_counts(plan["test_contract"])
        self.assertEqual(expected["direct_suite_run_multiplicity"], [1] * 10)
        self.assertEqual(expected["direct_bare_ok"], 10)
        self.assertEqual(expected["p0_suite_run_multiplicity"], [1, 1, 1, 2, 1, 1, 1, 1, 1, 1])
        self.assertEqual(expected["p0_bare_ok"], 16)

    def test_framework_recovery_9_ci_markers_reject_order_count_and_failure_mutations(self) -> None:
        """Exercise framework_recovery_9_ci_markers_reject_order_count_and_failure_mutations."""
        REPO = _repo()
        verify = _load_verify(REPO / "tools/release/verify-current-audit.py", f"_haldir_fr9_verify_{self._testMethodName}")
        source = _function_source(REPO / "tools/release/verify-current-audit.py", "_framework_recovery_9_verify_ci_markers")
        self.assertIn(b"observed_markers != expected_markers", source)
        self.assertIn(b"FAILED", source)
        self.assertIn(b"VERIFIER_OK", source)
        self.assertIn(b"for count in counts", source)

    def test_framework_recovery_9_code_diff_excludes_plan(self) -> None:
        """Exercise framework_recovery_9_code_diff_excludes_plan."""
        REPO = _repo()
        verify = _load_verify(REPO / "tools/release/verify-current-audit.py", f"_haldir_fr9_verify_{self._testMethodName}")
        plan = _repair_plan(verify, REPO)
        self.assertEqual(plan["code_diff"]["paths"], [
            "tools/release/verify-current-audit.py",
            "tools/release/test_verify_current_audit_fr_0009.py",
            "tools/release/current-audit-gate.sh",
        ])
        self.assertNotIn(verify.FRAMEWORK_RECOVERY_9_PLAN_PATH, plan["code_diff"]["paths"])

    def test_framework_recovery_9_decision_is_fail_closed(self) -> None:
        """Exercise framework_recovery_9_decision_is_fail_closed."""
        REPO = _repo()
        verify = _load_verify(REPO / "tools/release/verify-current-audit.py", f"_haldir_fr9_verify_{self._testMethodName}")
        pending = verify._framework_recovery_9_decision("PENDING_QUALIFICATION")
        active = verify._framework_recovery_9_decision("ACTIVE")
        self.assertEqual(pending["active_framework_epoch"], 2)
        self.assertFalse(pending["successor_transitions_allowed"])
        self.assertEqual(active["active_framework_epoch"], 10)
        with self.assertRaises(verify.CurrentAuditError):
            verify._framework_recovery_9_decision("UNKNOWN")

    def test_framework_recovery_9_expected_gate_payload_is_exact(self) -> None:
        """Exercise framework_recovery_9_expected_gate_payload_is_exact."""
        REPO = _repo()
        verify = _load_verify(REPO / "tools/release/verify-current-audit.py", f"_haldir_fr9_verify_{self._testMethodName}")
        observed = (REPO / "tools/release/current-audit-gate.sh").read_bytes()
        self.assertEqual(verify._framework_recovery_9_expected_gate_payload(), observed)
        self.assertEqual(hashlib.sha256(observed).hexdigest(), verify.FRAMEWORK_RECOVERY_9_GATE_SHA256)

    def test_framework_recovery_9_expected_plan_has_exact_contract(self) -> None:
        """Exercise framework_recovery_9_expected_plan_has_exact_contract."""
        REPO = _repo()
        verify = _load_verify(REPO / "tools/release/verify-current-audit.py", f"_haldir_fr9_verify_{self._testMethodName}")
        plan = _repair_plan(verify, REPO)
        review = plan["review_contract"]
        self.assertEqual(review["capture_tool"], {
            "name": "review_fr_0009_models.py",
            "sha256": "5f6bee21255da227ad04e369f0e4b3f25e143867cf245d53678ddd60e0c61b71",
            "bytes": 66229,
            "capture_protocol": "HALDIR_FR_0009_AUTOMATED_REVIEW_CAPTURE_V1",
        })
        request = review["request_contract"]
        self.assertEqual(request["protocol"], "HALDIR_FR_0009_REVIEW_REQUEST_BODY_V1")
        self.assertEqual(request["provider_endpoint"], "https://api.anthropic.com/v1/messages")
        self.assertEqual(request["provider_version"], "2023-06-01")
        self.assertEqual(request["subject_encoding"], "ASCII_CANONICAL_JSON_INLINE_V1")
        self.assertEqual(
            request["review_material_order"],
            ["SIGNED_PLAN", "CORE_PATCH", "P0_GATE"],
        )
        self.assertEqual(request["request_max_bytes"], 1_048_576)
        self.assertEqual(request["raw_response_max_bytes"], 1_048_576)
        for key in (
            "plan_begin", "plan_end", "patch_begin", "patch_end",
            "p0_begin", "p0_end",
        ):
            self.assertTrue(request[key].startswith("-----"))
        for token in (
            "canonical subject manifest and exact review material",
            "affected_functions",
            "affected_paths",
            "resolving_test_ids",
            "resolving_evidence_ids",
        ):
            self.assertIn(token, request["user_instruction"])
        self.assertEqual(plan["retired_private_review_capture_binding"]["capture_tool"]["sha256"],
                         "d74d950de0d019446b4e43327a6530c1542a2b0ce161e5693a3f862f910ec8ed")

    def test_framework_recovery_9_forward_replay_has_retirement_and_activation_guards(self) -> None:
        """Exercise framework_recovery_9_forward_replay_has_retirement_and_activation_guards."""
        REPO = _repo()
        verify = _load_verify(REPO / "tools/release/verify-current-audit.py", f"_haldir_fr9_verify_{self._testMethodName}")
        source = _function_source(REPO / "tools/release/verify-current-audit.py", "_verify_forward_protocol_history")
        for token in (
            b"recovery_8_terminal_commit",
            b"recovery_9_repair_commit",
            b"recovery_9_activation_commit",
            b"_framework_recovery_9_verify_successor_guard",
            b'"recovery_id": FRAMEWORK_RECOVERY_9_ID',
        ):
            self.assertIn(token, source)

    def test_framework_recovery_9_fr_0008_guard_accepts_only_fr_0009_retirement(self) -> None:
        """Exercise framework_recovery_9_fr_0008_guard_accepts_only_fr_0009_retirement."""
        REPO = _repo()
        verify = _load_verify(REPO / "tools/release/verify-current-audit.py", f"_haldir_fr9_verify_{self._testMethodName}")
        chain = ["a" * 40, "b" * 40]
        transition = {"stage": "RETIREMENT", "recovery_id": "FR-0009", "retirement_commit": chain[1]}
        self.assertIsNone(verify._framework_recovery_8_verify_successor_guard(
            chain, 1, repair_commit=chain[0], activation_commit=chain[1], recovery_transition=transition,
        ))
        for mutation in (
            None,
            {**transition, "stage": "REPAIR"},
            {**transition, "recovery_id": "FR-0008"},
            {**transition, "retirement_commit": "c" * 40},
        ):
            with self.assertRaises(verify.CurrentAuditError):
                verify._framework_recovery_8_verify_successor_guard(
                    chain, 1, repair_commit=chain[0], activation_commit=chain[1], recovery_transition=mutation,
                )

    def test_framework_recovery_9_framework_history_requires_fr_0008_retirement(self) -> None:
        """Exercise framework_recovery_9_framework_history_requires_fr_0008_retirement."""
        REPO = _repo()
        verify = _load_verify(REPO / "tools/release/verify-current-audit.py", f"_haldir_fr9_verify_{self._testMethodName}")
        head = _git(REPO, "rev-parse", "HEAD").decode().strip()
        chain = _git(REPO, "rev-list", "--first-parent", "--reverse", f"{verify.IMPLEMENTATION_COMMIT}..{head}").decode().splitlines()
        parent_plan = json.loads(_git(REPO, "show", f"{PARENT_COMMIT}:release/0.9.0/current-head/closures/framework-recovery/FR-0008-plan.json"))
        result = verify._verify_framework_recovery_8_history(REPO, chain, framework_commit=parent_plan["prior_framework_commit"])
        repair_commit = chain[chain.index(PARENT_COMMIT) + 1]
        self.assertEqual(result["state"], "ABORTED_BEFORE_QUALIFICATION")
        self.assertEqual(result["retirement_commit"], repair_commit)

    def test_framework_recovery_9_gate_and_p0_topology_are_derived_from_pinned_sources(self) -> None:
        """Exercise framework_recovery_9_gate_and_p0_topology_are_derived_from_pinned_sources."""
        REPO = _repo()
        verify = _load_verify(REPO / "tools/release/verify-current-audit.py", f"_haldir_fr9_verify_{self._testMethodName}")
        contract = verify._framework_recovery_9_gate_and_p0_contract(REPO, _git(REPO, "rev-parse", "HEAD").decode().strip())
        self.assertEqual(contract["suite_order"], list(SUITE_KEYS))
        self.assertEqual(contract["suite_counts"], [163, 78, 94, 26, 30, 44, 56, 37, 55, 60])

    def test_framework_recovery_9_gate_and_p0_topology_reject_source_order_mutations(self) -> None:
        """Exercise framework_recovery_9_gate_and_p0_topology_reject_source_order_mutations."""
        REPO = _repo()
        verify = _load_verify(REPO / "tools/release/verify-current-audit.py", f"_haldir_fr9_verify_{self._testMethodName}")
        contract = verify._framework_recovery_9_gate_and_p0_contract(REPO, _repair_commit(REPO))
        mutated = copy.deepcopy(contract)
        mutated["suite_order"][0], mutated["suite_order"][1] = mutated["suite_order"][1], mutated["suite_order"][0]
        with self.assertRaises(verify.CurrentAuditError):
            verify._framework_recovery_9_verify_gate_and_p0_contract(mutated, contract)

    def test_framework_recovery_9_gate_runs_fr_0008_in_parent_snapshot(self) -> None:
        """Exercise framework_recovery_9_gate_runs_fr_0008_in_parent_snapshot."""
        REPO = _repo()
        verify = _load_verify(REPO / "tools/release/verify-current-audit.py", f"_haldir_fr9_verify_{self._testMethodName}")
        gate = (REPO / "tools/release/current-audit-gate.sh").read_bytes()
        self.assertIn(b"clone \\\n  --no-local \\\n  --no-hardlinks", gate)
        self.assertIn(f"checkout --detach --quiet {PARENT_COMMIT}".encode(), gate)
        for value in (PARENT_TREE, PARENT_VERIFIER_OID, PARENT_TEST_OID, PARENT_GATE_OID, PARENT_PLAN_OID, PARENT_P0_OID):
            self.assertEqual(gate.count(value.encode()), 1)

    def test_framework_recovery_9_history_position_and_stages_are_exact(self) -> None:
        """Exercise framework_recovery_9_history_position_and_stages_are_exact."""
        REPO = _repo()
        verify = _load_verify(REPO / "tools/release/verify-current-audit.py", f"_haldir_fr9_verify_{self._testMethodName}")
        source = _function_source(REPO / "tools/release/verify-current-audit.py", "_verify_framework_recovery_9_history")
        self.assertIn(b"parent_index != 28", source)
        self.assertIn(b"chain[parent_index - 1] != FRAMEWORK_RECOVERY_8_PARENT", source)
        self.assertIn(b'"candidate_framework_epoch": 10', source)
        self.assertIn(b'"active_framework_epoch": 10', source)

    def test_framework_recovery_9_hosted_compatibility_projection_is_exact(self) -> None:
        """Exercise framework_recovery_9_hosted_compatibility_projection_is_exact."""
        REPO = _repo()
        verify = _load_verify(REPO / "tools/release/verify-current-audit.py", f"_haldir_fr9_verify_{self._testMethodName}")
        fixture = _hosted_fixture(verify)
        with fixture["temporary"]:
            before = copy.deepcopy(fixture["entry"])
            observed, _completed = _call_wrapper(verify, fixture)
            self.assertEqual(observed, fixture["entry"])
            self.assertEqual(fixture["entry"], before)
            projected = _compatibility_entry(verify, fixture, projected=True)
            self.assertIn("lines", projected["files"][0])
            self.assertIn("lines", projected["files"][1])
            self.assertNotIn("lines", projected["files"][2])
            for record in projected["files"]:
                self.assertFalse({"git_mode", "git_object_type", "git_object_id"} & set(record))

    def test_framework_recovery_9_hosted_entry_accepts_exact_subject_workflow_and_attempt(self) -> None:
        """Exercise framework_recovery_9_hosted_entry_accepts_exact_subject_workflow_and_attempt."""
        REPO = _repo()
        verify = _load_verify(REPO / "tools/release/verify-current-audit.py", f"_haldir_fr9_verify_{self._testMethodName}")
        fixture = _hosted_fixture(verify)
        with fixture["temporary"]:
            observed, completed = _call_wrapper(verify, fixture)
            self.assertEqual(observed, fixture["entry"])
            self.assertEqual(completed.isoformat(), "2030-01-01T00:00:12+00:00")

    def test_framework_recovery_9_hosted_entry_rejects_path_subject_workflow_and_attempt_mutations(self) -> None:
        """Exercise framework_recovery_9_hosted_entry_rejects_path_subject_workflow_and_attempt_mutations."""
        REPO = _repo()
        verify = _load_verify(REPO / "tools/release/verify-current-audit.py", f"_haldir_fr9_verify_{self._testMethodName}")
        fixture = _hosted_fixture(verify)
        with fixture["temporary"]:
            mutations = []
            for field, value in (("subject_commit", "0" * 40), ("workflow", "ci")):
                item = copy.deepcopy(fixture["entry"])
                item[field] = value
                mutations.append(item)
            item = copy.deepcopy(fixture["entry"])
            item["files"][0]["path"] += ".wrong"
            mutations.append(item)
            item = copy.deepcopy(fixture["entry"])
            item["capture_operations"]["attempt_metadata"]["capture_command"] = item["capture_operations"]["attempt_metadata"]["capture_command"].replace("--attempt 1", "--attempt 2")
            mutations.append(item)
            for mutation in mutations:
                with self.assertRaises(verify.CurrentAuditError):
                    _call_wrapper(verify, fixture, mutation)

    def test_framework_recovery_9_identity_constants_are_exact(self) -> None:
        """Exercise framework_recovery_9_identity_constants_are_exact."""
        REPO = _repo()
        verify = _load_verify(REPO / "tools/release/verify-current-audit.py", f"_haldir_fr9_verify_{self._testMethodName}")
        self.assertEqual(verify.FRAMEWORK_RECOVERY_9_PARENT, PARENT_COMMIT)
        self.assertEqual(verify.FRAMEWORK_RECOVERY_9_PARENT_TREE, PARENT_TREE)
        self.assertEqual(verify.FRAMEWORK_RECOVERY_9_SUBJECT, REPAIR_SUBJECT)
        self.assertEqual(verify.FRAMEWORK_RECOVERY_9_REPAIR_STATUSES, {verify.FRAMEWORK_RECOVERY_9_PLAN_PATH: "A", verify.FRAMEWORK_RECOVERY_9_TEST_PATH: "A", "tools/release/current-audit-gate.sh": "M", "tools/release/verify-current-audit.py": "M"})

    def test_framework_recovery_9_local_document_accepts_exact_bound_fixture(self) -> None:
        """Exercise framework_recovery_9_local_document_accepts_exact_bound_fixture."""
        REPO = _repo()
        verify = _load_verify(REPO / "tools/release/verify-current-audit.py", f"_haldir_fr9_verify_{self._testMethodName}")
        payload = _marker_log(verify, REPO)
        plan = _repair_plan(verify, REPO)
        self.assertIsNone(verify._framework_recovery_9_verify_local_markers(
            payload, test_contract=plan["test_contract"],
        ))
        source = _function_source(REPO / "tools/release/verify-current-audit.py", "_framework_recovery_9_validate_local_document")
        self.assertIn(b"REPAIR_LOCAL_VALIDATION", source)

    def test_framework_recovery_9_local_document_rejects_command_time_and_binding_mutations(self) -> None:
        """Exercise framework_recovery_9_local_document_rejects_command_time_and_binding_mutations."""
        REPO = _repo()
        verify = _load_verify(REPO / "tools/release/verify-current-audit.py", f"_haldir_fr9_verify_{self._testMethodName}")
        source = _function_source(REPO / "tools/release/verify-current-audit.py", "_framework_recovery_9_validate_local_document")
        self.assertIn(b'record.get("argv") != list(argv)', source)
        self.assertIn(b"started > completed", source)
        self.assertIn(b"LOCAL_LOG_BINDING", source)

    def test_framework_recovery_9_local_document_rejects_marker_resource_and_failure_mutations(self) -> None:
        """Exercise framework_recovery_9_local_document_rejects_marker_resource_and_failure_mutations."""
        REPO = _repo()
        verify = _load_verify(REPO / "tools/release/verify-current-audit.py", f"_haldir_fr9_verify_{self._testMethodName}")
        payload = _marker_log(verify, REPO)
        contract = _repair_plan(verify, REPO)["test_contract"]
        for mutated in (
            payload.replace(b"verify-current-audit: OK", b"verify-current-audit: BAD", 1),
            payload + b"\nFAILED\n",
            payload.replace(b"=== RESOURCE_PROFILE ===", b"=== RESOURCE_PROFILE_BAD ==="),
        ):
            with self.assertRaises(verify.CurrentAuditError):
                verify._framework_recovery_9_verify_local_markers(mutated, test_contract=contract)

    def test_framework_recovery_9_local_markers_accept_epoch_10_topology(self) -> None:
        """Exercise framework_recovery_9_local_markers_accept_epoch_10_topology."""
        REPO = _repo()
        verify = _load_verify(REPO / "tools/release/verify-current-audit.py", f"_haldir_fr9_verify_{self._testMethodName}")
        payload = _marker_log(verify, REPO)
        contract = _repair_plan(verify, REPO)["test_contract"]
        self.assertIsNone(verify._framework_recovery_9_verify_local_markers(payload, test_contract=contract))

    def test_framework_recovery_9_local_markers_reject_order_count_ok_and_failure_mutations(self) -> None:
        """Exercise framework_recovery_9_local_markers_reject_order_count_ok_and_failure_mutations."""
        REPO = _repo()
        verify = _load_verify(REPO / "tools/release/verify-current-audit.py", f"_haldir_fr9_verify_{self._testMethodName}")
        payload = _marker_log(verify, REPO)
        contract = _repair_plan(verify, REPO)["test_contract"]
        mutations = (
            payload.replace(b"Ran 163 tests", b"Ran 162 tests", 1),
            payload.replace(b"\nOK\n", b"\nBAD\n", 1),
            payload.replace(b"=== CURRENT_AUDIT_GATE ===", b"=== P0R_EXIT_GATE ===", 1),
            payload + b"Traceback\n",
        )
        for mutated in mutations:
            with self.assertRaises(verify.CurrentAuditError):
                verify._framework_recovery_9_verify_local_markers(mutated, test_contract=contract)

    def test_framework_recovery_9_log_binding_rejects_payload_and_integrity_mutations(self) -> None:
        """Exercise framework_recovery_9_log_binding_rejects_payload_and_integrity_mutations."""
        REPO = _repo()
        verify = _load_verify(REPO / "tools/release/verify-current-audit.py", f"_haldir_fr9_verify_{self._testMethodName}")
        fixture = _hosted_fixture(verify)
        with fixture["temporary"]:
            for field, value in (
                ("path", fixture["entry"]["files"][2]["path"] + ".wrong"),
                ("bytes", 1),
                ("sha256", "0" * 64),
            ):
                mutated = copy.deepcopy(fixture["entry"])
                mutated["files"][2][field] = value
                with self.assertRaises(verify.CurrentAuditError):
                    _call_wrapper(verify, fixture, mutated)

    def test_framework_recovery_9_parent_bytes_are_pinned(self) -> None:
        """Exercise framework_recovery_9_parent_bytes_are_pinned."""
        REPO = _repo()
        verify = _load_verify(REPO / "tools/release/verify-current-audit.py", f"_haldir_fr9_verify_{self._testMethodName}")
        pins = (
            ("tools/release/verify-current-audit.py", PARENT_VERIFIER_SHA256, 1650717),
            ("tools/release/test_verify_current_audit_fr_0008.py", PARENT_TEST_SHA256, 95569),
            ("tools/release/current-audit-gate.sh", PARENT_GATE_SHA256, 11042),
            ("tools/p0r-exit-gate.sh", PARENT_P0_SHA256, 3977),
            ("release/0.9.0/current-head/closures/framework-recovery/FR-0008-plan.json", PARENT_PLAN_SHA256, 56905),
        )
        for path, digest, size in pins:
            payload = _git(REPO, "show", f"{PARENT_COMMIT}:{path}")
            self.assertEqual((hashlib.sha256(payload).hexdigest(), len(payload)), (digest, size))

    def test_framework_recovery_9_parent_has_no_fr_0008_q_or_a(self) -> None:
        """Exercise framework_recovery_9_parent_has_no_fr_0008_q_or_a."""
        REPO = _repo()
        verify = _load_verify(REPO / "tools/release/verify-current-audit.py", f"_haldir_fr9_verify_{self._testMethodName}")
        for path in (verify.FRAMEWORK_RECOVERY_8_QUALIFICATION_PATH, verify.FRAMEWORK_RECOVERY_8_ACTIVATION_PATH):
            completed = subprocess.run(
                ["/usr/bin/git", "cat-file", "-e", f"{PARENT_COMMIT}:{path}"],
                cwd=REPO, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
            )
            self.assertNotEqual(completed.returncode, 0)

    def test_framework_recovery_9_parent_hosted_log_binding_contradiction_is_reproduced(self) -> None:
        """Exercise framework_recovery_9_parent_hosted_log_binding_contradiction_is_reproduced."""
        REPO = _repo()
        verify = _load_verify(REPO / "tools/release/verify-current-audit.py", f"_haldir_fr9_verify_{self._testMethodName}")
        fixture = _hosted_fixture(verify)
        with fixture["temporary"]:
            parent_path = fixture["repo"] / "parent_verify.py"
            parent_path.write_bytes(_git(REPO, "show", f"{PARENT_COMMIT}:tools/release/verify-current-audit.py"))
            parent_path.chmod(0o600)
            parent = _load_verify(parent_path, "_haldir_fr9_parent_verify")
            with self.assertRaises(parent.CurrentAuditError) as captured:
                parent._framework_recovery_3_verify_hosted_entry(
                    fixture["repo"], fixture["containing"], fixture["entry"],
                    paths=fixture["paths"], subject_commit=fixture["subject"],
                    workflow="formal", lane="fr_0008_repair_ci",
                    expected_attempt=1, require_ordinary_attempt=True,
                )
            self.assertEqual(
                str(captured.exception),
                "CURRENT_AUDIT_HOSTED_LOG_BINDING:"
                "framework_recovery_3.fr_0008_repair_ci",
            )

    def test_framework_recovery_9_parent_reproduction_accepts_exact_bound_fixture(self) -> None:
        """Exercise framework_recovery_9_parent_reproduction_accepts_exact_bound_fixture."""
        REPO = _repo()
        verify = _load_verify(REPO / "tools/release/verify-current-audit.py", f"_haldir_fr9_verify_{self._testMethodName}")
        value = verify._framework_recovery_9_expected_parent_reproduction(
            REPO, _repair_commit(REPO), execution={}, raw_log={}, semantic_receipt={},
        )
        self.assertEqual(value["kind"], "PARENT_HOSTED_LOG_BINDING_CONTRADICTION_REPRODUCTION")
        self.assertEqual(value["subject_commit"], PARENT_COMMIT)
        self.assertFalse(value["defect"]["satisfiable"])

    def test_framework_recovery_9_parent_reproduction_reexecutes_parent_defect(self) -> None:
        """Exercise framework_recovery_9_parent_reproduction_reexecutes_parent_defect."""
        REPO = _repo()
        verify = _load_verify(REPO / "tools/release/verify-current-audit.py", f"_haldir_fr9_verify_{self._testMethodName}")
        defect = verify._framework_recovery_9_parent_contract_defects(REPO)
        self.assertEqual(verify._framework_recovery_9_rederive_parent_contract_defects(REPO, defect), defect)
        mutated = copy.deepcopy(defect)
        mutated["satisfiable"] = True
        with self.assertRaises(verify.CurrentAuditError):
            verify._framework_recovery_9_rederive_parent_contract_defects(REPO, mutated)

    def test_framework_recovery_9_parent_reproduction_rejects_catalog_and_chronology_mutations(self) -> None:
        """Exercise framework_recovery_9_parent_reproduction_rejects_catalog_and_chronology_mutations."""
        REPO = _repo()
        verify = _load_verify(REPO / "tools/release/verify-current-audit.py", f"_haldir_fr9_verify_{self._testMethodName}")
        source = _function_source(REPO / "tools/release/verify-current-audit.py", "_framework_recovery_9_validate_parent_reproduction")
        chronology = _function_source(REPO / "tools/release/verify-current-audit.py", "_framework_recovery_9_validate_parent_reproduction_chronology")
        self.assertIn(b"REPRODUCTION_CATALOG_BINDING", source)
        self.assertIn(b"<= started", chronology)
        self.assertIn(b"<= completed", chronology)

    def test_framework_recovery_9_parent_reproduction_rejects_command_log_and_receipt_mutations(self) -> None:
        """Exercise framework_recovery_9_parent_reproduction_rejects_command_log_and_receipt_mutations."""
        REPO = _repo()
        verify = _load_verify(REPO / "tools/release/verify-current-audit.py", f"_haldir_fr9_verify_{self._testMethodName}")
        source = _function_source(REPO / "tools/release/verify-current-audit.py", "_framework_recovery_9_validate_parent_reproduction")
        self.assertIn(b"FrameworkRecovery9Tests.", source)
        self.assertIn(b"ELAPSED_SECONDS_ONLY", source)
        self.assertIn(b"REPRODUCTION_RECEIPT", source)
        self.assertIn(b"HALDIR_FR_0009_HOSTED_LOG_PROTOCOL_BINDING_V1", source)

    def test_framework_recovery_9_positive_composition_has_no_critical_mocks(self) -> None:
        """Exercise framework_recovery_9_positive_composition_has_no_critical_mocks."""
        REPO = _repo()
        verify = _load_verify(REPO / "tools/release/verify-current-audit.py", f"_haldir_fr9_verify_{self._testMethodName}")
        fixture = _hosted_fixture(verify)
        with fixture["temporary"]:
            full_observed_before = copy.deepcopy(fixture["entry"])
            observed, _completed = _call_wrapper(verify, fixture)
            self.assertEqual(observed, fixture["entry"])
            self.assertEqual(fixture["entry"], full_observed_before)
            projected = _compatibility_entry(verify, fixture, projected=True)
            self.assertEqual(verify._verify_hosted_evidence_v2(
                fixture["repo"], fixture["containing"], projected,
                expected_head=fixture["subject"], workflow="formal",
                label="framework_recovery_3.fr_0009_fixture",
                job_boundary_skew_seconds=verify.HOSTED_STEP_JOB_BOUNDARY_SKEW_SECONDS,
                expected_attempt=1, require_ordinary_attempt=True,
            ), [])
        target_names = {
            "test_framework_recovery_9_hosted_compatibility_projection_is_exact",
            "test_framework_recovery_9_log_binding_rejects_payload_and_integrity_mutations",
            "test_framework_recovery_9_positive_composition_has_no_critical_mocks",
            "test_framework_recovery_9_protocol_binding_rejects_git_record_mutations",
            "test_framework_recovery_9_real_builder_and_validator_compose",
        }
        tree = ast.parse(
            (REPO / "tools/release/test_verify_current_audit_fr_0009.py").read_text(
                encoding="utf-8"
            )
        )
        target_methods = {
            node.name: node
            for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef) and node.name in target_names
        }
        self.assertEqual(set(target_methods), target_names)
        for name, method in target_methods.items():
            prohibited = []
            for node in ast.walk(method):
                if isinstance(node, ast.Attribute) and node.attr in {"mock", "patch"}:
                    prohibited.append(node)
                elif isinstance(node, ast.Call):
                    call_names = {
                        part.id
                        for part in ast.walk(node.func)
                        if isinstance(part, ast.Name)
                    }
                    call_attributes = {
                        part.attr
                        for part in ast.walk(node.func)
                        if isinstance(part, ast.Attribute)
                    }
                    if {"mock", "patch"} & (call_names | call_attributes):
                        prohibited.append(node)
            self.assertEqual(prohibited, [], name)

    def test_framework_recovery_9_preserves_all_prior_test_suites(self) -> None:
        """Exercise framework_recovery_9_preserves_all_prior_test_suites."""
        REPO = _repo()
        verify = _load_verify(REPO / "tools/release/verify-current-audit.py", f"_haldir_fr9_verify_{self._testMethodName}")
        contract = _repair_plan(verify, REPO)["test_contract"]
        self.assertEqual([contract[key]["count"] for key in SUITE_KEYS], [163, 78, 94, 26, 30, 44, 56, 37, 55, 60])
        self.assertTrue(contract["prior_test_bytes_preserved"])
        self.assertTrue(contract["p0_gate_bytes_preserved"])

    def test_framework_recovery_9_protocol_binding_rejects_git_record_mutations(self) -> None:
        """Exercise framework_recovery_9_protocol_binding_rejects_git_record_mutations."""
        REPO = _repo()
        verify = _load_verify(REPO / "tools/release/verify-current-audit.py", f"_haldir_fr9_verify_{self._testMethodName}")
        fixture = _hosted_fixture(verify)
        with fixture["temporary"]:
            for field, value in (
                ("git_mode", "100755"),
                ("git_object_type", "tree"),
                ("git_object_id", "0" * 40),
            ):
                mutated = copy.deepcopy(fixture["entry"])
                mutated["files"][2][field] = value
                with self.assertRaisesRegex(verify.CurrentAuditError, "CURRENT_AUDIT_FRAMEWORK_RECOVERY_3_HOSTED_BINDING"):
                    _call_wrapper(verify, fixture, mutated)

    def test_framework_recovery_9_qualification_scope_is_exact(self) -> None:
        """Exercise framework_recovery_9_qualification_scope_is_exact."""
        REPO = _repo()
        verify = _load_verify(REPO / "tools/release/verify-current-audit.py", f"_haldir_fr9_verify_{self._testMethodName}")
        expected = {
            verify.FRAMEWORK_RECOVERY_9_QUALIFICATION_PATH,
            *[path for requirement in verify.FRAMEWORK_RECOVERY_9_QUALIFICATION_REQUIREMENTS for path in requirement["paths"]],
        }
        self.assertEqual(set(verify.FRAMEWORK_RECOVERY_9_QUALIFICATION_STATUSES), expected)
        self.assertEqual(len(expected), 14)

    def test_framework_recovery_9_real_builder_and_validator_compose(self) -> None:
        """Exercise framework_recovery_9_real_builder_and_validator_compose."""
        REPO = _repo()
        verify = _load_verify(REPO / "tools/release/verify-current-audit.py", f"_haldir_fr9_verify_{self._testMethodName}")
        fixture = _hosted_fixture(verify)
        with fixture["temporary"]:
            observed, completed = _call_wrapper(verify, fixture)
            self.assertEqual(observed, fixture["entry"])
            self.assertEqual(completed.isoformat(), "2030-01-01T00:00:12+00:00")

    def test_framework_recovery_9_repair_scope_is_exact(self) -> None:
        """Exercise framework_recovery_9_repair_scope_is_exact."""
        REPO = _repo()
        verify = _load_verify(REPO / "tools/release/verify-current-audit.py", f"_haldir_fr9_verify_{self._testMethodName}")
        self.assertEqual(verify.FRAMEWORK_RECOVERY_9_REPAIR_STATUSES, {
            verify.FRAMEWORK_RECOVERY_9_PLAN_PATH: "A",
            verify.FRAMEWORK_RECOVERY_9_TEST_PATH: "A",
            "tools/release/current-audit-gate.sh": "M",
            "tools/release/verify-current-audit.py": "M",
        })

    def test_framework_recovery_9_reproduction_raw_is_verbose_identity_bound_and_canonical_gzip(self) -> None:
        """Exercise framework_recovery_9_reproduction_raw_is_verbose_identity_bound_and_canonical_gzip."""
        REPO = _repo()
        verify = _load_verify(REPO / "tools/release/verify-current-audit.py", f"_haldir_fr9_verify_{self._testMethodName}")
        raw = _verbose_reproduction_raw()
        compressed = _canonical_gzip(raw)
        self.assertEqual(compressed[:10], b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\x03")
        self.assertEqual(verify._framework_recovery_9_decode_reproduction_raw(compressed), raw)
        normalized = verify._framework_recovery_9_normalize_reproduction_raw(raw)
        self.assertIn(b"test_framework_recovery_9_parent_hosted_log_binding_contradiction_is_reproduced", normalized)
        self.assertIn(b"<ELAPSED>", normalized)

    def test_framework_recovery_9_reproduction_raw_rejects_noncanonical_and_wrong_identity_mutations(self) -> None:
        """Exercise framework_recovery_9_reproduction_raw_rejects_noncanonical_and_wrong_identity_mutations."""
        REPO = _repo()
        verify = _load_verify(REPO / "tools/release/verify-current-audit.py", f"_haldir_fr9_verify_{self._testMethodName}")
        raw = _verbose_reproduction_raw()
        compressed = _canonical_gzip(raw)
        mutations = (
            b"bad" + compressed,
            compressed + compressed,
            _canonical_gzip(raw.replace(b"hosted_log_binding", b"hosted_log_otherxx")),
        )
        for mutation in mutations:
            with self.assertRaises(verify.CurrentAuditError):
                decoded = verify._framework_recovery_9_decode_reproduction_raw(mutation)
                verify._framework_recovery_9_normalize_reproduction_raw(decoded)

    def test_framework_recovery_9_retirement_absorbs_no_fr_0008_q_or_a(self) -> None:
        """Exercise framework_recovery_9_retirement_absorbs_no_fr_0008_q_or_a."""
        REPO = _repo()
        verify = _load_verify(REPO / "tools/release/verify-current-audit.py", f"_haldir_fr9_verify_{self._testMethodName}")
        head = _git(REPO, "rev-parse", "HEAD").decode().strip()
        chain = _git(REPO, "rev-list", "--first-parent", "--reverse", f"{verify.IMPLEMENTATION_COMMIT}..{head}").decode().splitlines()
        parent_plan = json.loads(_git(REPO, "show", f"{PARENT_COMMIT}:release/0.9.0/current-head/closures/framework-recovery/FR-0008-plan.json"))
        result = verify._verify_framework_recovery_8_history(REPO, chain, framework_commit=parent_plan["prior_framework_commit"])
        self.assertEqual(result["state"], "ABORTED_BEFORE_QUALIFICATION")
        self.assertIsNone(result["qualification_commit"])
        self.assertIsNone(result["activation_commit"])

    def test_framework_recovery_9_retires_fr_0008_without_qualification(self) -> None:
        """Exercise framework_recovery_9_retires_fr_0008_without_qualification."""
        REPO = _repo()
        verify = _load_verify(REPO / "tools/release/verify-current-audit.py", f"_haldir_fr9_verify_{self._testMethodName}")
        transition = verify._framework_recovery_9_transition_identity()
        self.assertEqual(transition["epoch_9_state"], "ABORTED_BEFORE_QUALIFICATION")
        self.assertIs(transition["fr_0008_mechanism_reused"], False)

    def test_framework_recovery_9_review_eligibility_accepts_two_go_reviews(self) -> None:
        """Exercise framework_recovery_9_review_eligibility_accepts_two_go_reviews."""
        REPO = _repo()
        verify = _load_verify(REPO / "tools/release/verify-current-audit.py", f"_haldir_fr9_verify_{self._testMethodName}")
        outcomes = _review_outcomes()
        self.assertIsNone(verify._framework_recovery_9_require_reviews_go(outcomes))

    def test_framework_recovery_9_review_eligibility_rejects_no_go_open_or_blocking(self) -> None:
        """Exercise framework_recovery_9_review_eligibility_rejects_no_go_open_or_blocking."""
        REPO = _repo()
        verify = _load_verify(REPO / "tools/release/verify-current-audit.py", f"_haldir_fr9_verify_{self._testMethodName}")
        for mutation in (
            [{**_review_outcomes()[0], "verdict": "NO_GO"}, _review_outcomes()[1]],
            [{**_review_outcomes()[0], "open_blocker_ids": ["B001"]}, _review_outcomes()[1]],
            [_review_outcomes()[0]],
        ):
            with self.assertRaises(verify.CurrentAuditError):
                verify._framework_recovery_9_require_reviews_go(mutation)

    def test_framework_recovery_9_review_keys_are_separate(self) -> None:
        """Exercise framework_recovery_9_review_keys_are_separate."""
        REPO = _repo()
        verify = _load_verify(REPO / "tools/release/verify-current-audit.py", f"_haldir_fr9_verify_{self._testMethodName}")
        source = {"public_key": "source", "key_fingerprint": "source-fp"}
        keys = [
            {"public_key": "one", "key_fingerprint": "one-fp"},
            {"public_key": "two", "key_fingerprint": "two-fp"},
        ]
        self.assertIsNone(verify._framework_recovery_9_verify_review_key_separation(source, keys))
        with self.assertRaises(verify.CurrentAuditError):
            verify._framework_recovery_9_verify_review_key_separation(source, [keys[0], keys[0]])

    def test_framework_recovery_9_review_validator_accepts_additional_findings(self) -> None:
        """Exercise framework_recovery_9_review_validator_accepts_additional_findings."""
        REPO = _repo()
        verify = _load_verify(REPO / "tools/release/verify-current-audit.py", f"_haldir_fr9_verify_{self._testMethodName}")
        source = _function_source(REPO / "tools/release/verify-current-audit.py", "_framework_recovery_9_validate_review")
        self.assertIn(b"additional_findings", source)
        self.assertIn(b"B\\d{3}", source)
        self.assertIn(b'finding_id == "B000"', source)
        self.assertIn(b"additional_blocker_ids", source)

    def test_framework_recovery_9_review_validator_accepts_truthful_go(self) -> None:
        """Exercise framework_recovery_9_review_validator_accepts_truthful_go."""
        REPO = _repo()
        verify = _load_verify(REPO / "tools/release/verify-current-audit.py", f"_haldir_fr9_verify_{self._testMethodName}")
        plan = _repair_plan(verify, REPO)
        repair = _repair_commit(REPO)
        model = "claude-fable-5"
        manifest = verify._framework_recovery_9_review_subject_manifest(
            REPO, review_id="FR-0009-R01", repair_commit=repair, plan=plan, model=model,
        )
        compact = lambda value: (json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        request_contract = plan["review_contract"]["request_contract"]
        manifest_payload = compact(manifest)
        plan_text = verify._git_file(
            REPO, repair, verify.FRAMEWORK_RECOVERY_9_PLAN_PATH,
        ).decode("utf-8")
        common = (
            "-c", "diff.algorithm=myers", "-c", "core.attributesFile=/dev/null",
            "-c", "diff.relative=false", "-c", "diff.suppressBlankEmpty=false",
            "-c", "diff.compactionHeuristic=false", "diff", "--no-ext-diff",
            "--no-textconv", "--text", "--no-renames",
            "--no-color", "-O/dev/null", "--no-indent-heuristic", "--unified=3",
            "--inter-hunk-context=0",
        )
        patch_text = verify._git(
            REPO, *common, "--src-prefix=a/", "--dst-prefix=b/", "--binary",
            "--full-index", f"{verify.FRAMEWORK_RECOVERY_9_PARENT}..{repair}",
            "--", *verify.FRAMEWORK_RECOVERY_9_CORE_PATHS,
        ).decode("utf-8")
        p0_text = verify._git_file(
            REPO, repair, "tools/p0r-exit-gate.sh",
        ).decode("utf-8")
        user_content = (
            request_contract["user_instruction"] + "\n\n"
            + request_contract["subject_begin"] + "\n"
            + manifest_payload.decode("ascii")
            + request_contract["subject_end"] + "\n"
            + request_contract["plan_begin"] + "\n" + plan_text
            + request_contract["plan_end"] + "\n"
            + request_contract["patch_begin"] + "\n" + patch_text
            + request_contract["patch_end"] + "\n"
            + request_contract["p0_begin"] + "\n" + p0_text
            + request_contract["p0_end"] + "\n"
        )
        request_payload = compact({
            "model": model,
            "max_tokens": request_contract["max_tokens"],
            "thinking": request_contract["thinking"],
            "output_config": request_contract["output_config"],
            "system": request_contract["system"],
            "messages": [{"role": "user", "content": user_content}],
        })
        capture = {
            "protocol": "HALDIR_FR_0009_AUTOMATED_REVIEW_CAPTURE_V1",
            "subject_manifest_sha256": hashlib.sha256(manifest_payload).hexdigest(),
            "capture_tool_sha256": plan["review_contract"]["capture_tool"]["sha256"],
            "capture_tool_bytes": plan["review_contract"]["capture_tool"]["bytes"],
            "request_contract_sha256": hashlib.sha256(compact(request_contract)).hexdigest(),
            "request_payload_sha256": hashlib.sha256(request_payload).hexdigest(),
            "request_payload_bytes": len(request_payload),
            "raw_response_sha256": "1" * 64,
            "raw_response_bytes": 1,
            "attempt": 1,
            "stop_reason": "end_turn",
            "captured_at_utc": "2030-01-01T00:00:00Z",
            "raw_response_retention": "PRIVATE_UNTRACKED",
            "raw_response_committed": False,
        }
        self.assertEqual(verify._framework_recovery_9_validate_review_capture(
            REPO, capture, review_id="FR-0009-R01", repair_commit=repair, plan=plan, model=model,
        ), capture)
        review = verify._framework_recovery_9_expected_review(
            REPO, review_id="FR-0009-R01", kind="INTERNAL_AUTOMATED_DESIGN_REVIEW",
            repair_commit=repair, plan=plan, capture=capture,
            verdict="GO_FOR_FRAMEWORK_QUALIFICATION", required_findings=[], additional_findings=[],
        )
        self.assertEqual(review["verdict"], "GO_FOR_FRAMEWORK_QUALIFICATION")
        self.assertFalse(review["reviewer"]["fallback_used"])

    def test_framework_recovery_9_review_validator_accepts_truthful_no_go(self) -> None:
        """Exercise framework_recovery_9_review_validator_accepts_truthful_no_go."""
        REPO = _repo()
        verify = _load_verify(REPO / "tools/release/verify-current-audit.py", f"_haldir_fr9_verify_{self._testMethodName}")
        plan = _repair_plan(verify, REPO)
        review = verify._framework_recovery_9_expected_review(
            REPO, review_id="FR-0009-R02", kind="INTERNAL_AUTOMATED_IMPLEMENTATION_REVIEW",
            repair_commit=_repair_commit(REPO), plan=plan, capture={},
            verdict="NO_GO", required_findings=[], additional_findings=[],
        )
        self.assertEqual(review["verdict"], "NO_GO")
        self.assertEqual(review["reviewer"]["model_resolved"], "claude-opus-5")

    def test_framework_recovery_9_review_validator_rejects_malformed_and_duplicate_findings(self) -> None:
        """Exercise framework_recovery_9_review_validator_rejects_malformed_and_duplicate_findings."""
        REPO = _repo()
        verify = _load_verify(REPO / "tools/release/verify-current-audit.py", f"_haldir_fr9_verify_{self._testMethodName}")
        source = _function_source(REPO / "tools/release/verify-current-audit.py", "_framework_recovery_9_validate_review")
        self.assertIn(b"finding_id in observed_required_ids", source)
        self.assertIn(b"finding_id in additional_ids", source)
        self.assertIn(b"REVIEW_REQUIRED_FINDINGS", source)

    def test_framework_recovery_9_review_validator_rejects_model_fallback_and_wrong_model(self) -> None:
        """Exercise framework_recovery_9_review_validator_rejects_model_fallback_and_wrong_model."""
        REPO = _repo()
        verify = _load_verify(REPO / "tools/release/verify-current-audit.py", f"_haldir_fr9_verify_{self._testMethodName}")
        plan = _repair_plan(verify, REPO)
        repair = _repair_commit(REPO)
        model = "claude-fable-5"
        compact = lambda value: (json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        manifest = verify._framework_recovery_9_review_subject_manifest(
            REPO, review_id="FR-0009-R01", repair_commit=repair, plan=plan, model=model,
        )
        manifest_payload = compact(manifest)
        contract = plan["review_contract"]["request_contract"]
        plan_text = verify._git_file(
            REPO, repair, verify.FRAMEWORK_RECOVERY_9_PLAN_PATH,
        ).decode("utf-8")
        common = (
            "-c", "diff.algorithm=myers", "-c", "core.attributesFile=/dev/null",
            "-c", "diff.relative=false", "-c", "diff.suppressBlankEmpty=false",
            "-c", "diff.compactionHeuristic=false", "diff", "--no-ext-diff",
            "--no-textconv", "--text", "--no-renames",
            "--no-color", "-O/dev/null", "--no-indent-heuristic", "--unified=3",
            "--inter-hunk-context=0",
        )
        patch_text = verify._git(
            REPO, *common, "--src-prefix=a/", "--dst-prefix=b/", "--binary",
            "--full-index", f"{verify.FRAMEWORK_RECOVERY_9_PARENT}..{repair}",
            "--", *verify.FRAMEWORK_RECOVERY_9_CORE_PATHS,
        ).decode("utf-8")
        p0_text = verify._git_file(
            REPO, repair, "tools/p0r-exit-gate.sh",
        ).decode("utf-8")
        content = (
            contract["user_instruction"] + "\n\n"
            + contract["subject_begin"] + "\n"
            + manifest_payload.decode("ascii")
            + contract["subject_end"] + "\n"
            + contract["plan_begin"] + "\n" + plan_text
            + contract["plan_end"] + "\n"
            + contract["patch_begin"] + "\n" + patch_text
            + contract["patch_end"] + "\n"
            + contract["p0_begin"] + "\n" + p0_text
            + contract["p0_end"] + "\n"
        )
        request_payload = compact({
            "model": model, "max_tokens": contract["max_tokens"],
            "thinking": contract["thinking"], "output_config": contract["output_config"],
            "system": contract["system"], "messages": [{"role": "user", "content": content}],
        })
        valid = {
            "protocol": "HALDIR_FR_0009_AUTOMATED_REVIEW_CAPTURE_V1",
            "subject_manifest_sha256": hashlib.sha256(manifest_payload).hexdigest(),
            "capture_tool_sha256": plan["review_contract"]["capture_tool"]["sha256"],
            "capture_tool_bytes": plan["review_contract"]["capture_tool"]["bytes"],
            "request_contract_sha256": hashlib.sha256(compact(contract)).hexdigest(),
            "request_payload_sha256": hashlib.sha256(request_payload).hexdigest(),
            "request_payload_bytes": len(request_payload),
            "raw_response_sha256": "2" * 64, "raw_response_bytes": 2,
            "attempt": 1, "stop_reason": "end_turn", "captured_at_utc": "2030-01-01T00:00:00Z",
            "raw_response_retention": "PRIVATE_UNTRACKED", "raw_response_committed": False,
        }
        for field, replacement in (
            ("capture_tool_sha256", "0" * 64),
            ("capture_tool_bytes", 1),
            ("subject_manifest_sha256", "0" * 64),
            ("request_contract_sha256", "0" * 64),
            ("request_payload_sha256", "0" * 64),
            ("request_payload_bytes", 1),
        ):
            mutated = copy.deepcopy(valid)
            mutated[field] = replacement
            with self.assertRaises(verify.CurrentAuditError):
                verify._framework_recovery_9_validate_review_capture(
                    REPO, mutated, review_id="FR-0009-R01", repair_commit=repair, plan=plan, model=model,
                )
        for material_name in ("SIGNED_PLAN", "CORE_PATCH", "P0_GATE"):
            alternative = {
                "SIGNED_PLAN": plan_text,
                "CORE_PATCH": patch_text,
                "P0_GATE": p0_text,
            }
            alternative[material_name] += "substituted review material\n"
            alternative_content = (
                contract["user_instruction"] + "\n\n"
                + contract["subject_begin"] + "\n"
                + manifest_payload.decode("ascii")
                + contract["subject_end"] + "\n"
                + contract["plan_begin"] + "\n" + alternative["SIGNED_PLAN"]
                + contract["plan_end"] + "\n"
                + contract["patch_begin"] + "\n" + alternative["CORE_PATCH"]
                + contract["patch_end"] + "\n"
                + contract["p0_begin"] + "\n" + alternative["P0_GATE"]
                + contract["p0_end"] + "\n"
            )
            alternative_request = compact({
                "model": model, "max_tokens": contract["max_tokens"],
                "thinking": contract["thinking"],
                "output_config": contract["output_config"],
                "system": contract["system"],
                "messages": [{"role": "user", "content": alternative_content}],
            })
            mutated = copy.deepcopy(valid)
            mutated["request_payload_sha256"] = hashlib.sha256(
                alternative_request
            ).hexdigest()
            mutated["request_payload_bytes"] = len(alternative_request)
            with self.assertRaises(verify.CurrentAuditError):
                verify._framework_recovery_9_validate_review_capture(
                    REPO, mutated, review_id="FR-0009-R01", repair_commit=repair,
                    plan=plan, model=model,
                )
        source = _function_source(REPO / "tools/release/verify-current-audit.py", "_framework_recovery_9_validate_review")
        self.assertIn(b'"model_requested": model', source)
        self.assertIn(b'"model_resolved": model', source)
        self.assertIn(b'"fallback_used": False', source)
        self.assertIn(b"claude-fable-5", source)
        self.assertIn(b"claude-opus-5", source)

    def test_framework_recovery_9_run_attempt_uniqueness_accepts_distinct_attempt(self) -> None:
        """Exercise framework_recovery_9_run_attempt_uniqueness_accepts_distinct_attempt."""
        REPO = _repo()
        verify = _load_verify(REPO / "tools/release/verify-current-audit.py", f"_haldir_fr9_verify_{self._testMethodName}")
        fixture = _hosted_fixture(verify)
        with fixture["temporary"]:
            self.assertIsNone(verify._framework_recovery_9_verify_run_attempt_uniqueness(
                fixture["repo"], [("one", fixture["containing"], fixture["entry"])],
            ))

    def test_framework_recovery_9_run_attempt_uniqueness_rejects_reserved_and_duplicate(self) -> None:
        """Exercise framework_recovery_9_run_attempt_uniqueness_rejects_reserved_and_duplicate."""
        REPO = _repo()
        verify = _load_verify(REPO / "tools/release/verify-current-audit.py", f"_haldir_fr9_verify_{self._testMethodName}")
        fixture = _hosted_fixture(verify)
        with fixture["temporary"]:
            with self.assertRaises(verify.CurrentAuditError):
                verify._framework_recovery_9_verify_run_attempt_uniqueness(
                    fixture["repo"],
                    [
                        ("one", fixture["containing"], fixture["entry"]),
                        ("two", fixture["containing"], fixture["entry"]),
                    ],
                )
        self.assertIn((30214443045, 1), verify.FRAMEWORK_RECOVERY_9_RESERVED_RUN_ATTEMPTS)
        self.assertIn((30214443071, 1), verify.FRAMEWORK_RECOVERY_9_RESERVED_RUN_ATTEMPTS)

    def test_framework_recovery_9_signatures_and_chronology_are_bound(self) -> None:
        """Exercise framework_recovery_9_signatures_and_chronology_are_bound."""
        REPO = _repo()
        verify = _load_verify(REPO / "tools/release/verify-current-audit.py", f"_haldir_fr9_verify_{self._testMethodName}")
        plan = _repair_plan(verify, REPO)
        self.assertIn("detached_signature", plan)
        repair_source = _function_source(REPO / "tools/release/verify-current-audit.py", "_verify_framework_recovery_9_repair")
        reproduction_source = _function_source(REPO / "tools/release/verify-current-audit.py", "_framework_recovery_9_validate_parent_reproduction_chronology")
        self.assertIn(b"haldir-framework-recovery-fr-0009-plan-v1", repair_source)
        self.assertIn(b"_commit_datetime", reproduction_source)

    def test_framework_recovery_9_source_compatibility_rejects_drift(self) -> None:
        """Exercise framework_recovery_9_source_compatibility_rejects_drift."""
        REPO = _repo()
        verify = _load_verify(REPO / "tools/release/verify-current-audit.py", f"_haldir_fr9_verify_{self._testMethodName}")
        parent = _git(REPO, "show", f"{PARENT_COMMIT}:tools/release/verify-current-audit.py")
        target = (REPO / "tools/release/verify-current-audit.py").read_bytes()
        mutated = target.replace(b"def _verify_hosted_evidence_v2(", b"def _verify_hosted_evidence_v2_mutated(", 1)
        with self.assertRaises(verify.CurrentAuditError):
            verify._framework_recovery_9_validate_source_compatibility(parent, mutated)

    def test_framework_recovery_9_source_retention_is_exact(self) -> None:
        """Exercise framework_recovery_9_source_retention_is_exact."""
        REPO = _repo()
        verify = _load_verify(REPO / "tools/release/verify-current-audit.py", f"_haldir_fr9_verify_{self._testMethodName}")
        self.assertEqual(verify.FRAMEWORK_RECOVERY_9_MODIFIED_DEFINITIONS, EXPECTED_MODIFIED_DEFINITIONS)
        self.assertEqual(verify.FRAMEWORK_RECOVERY_9_MODIFIED_ASSIGNMENTS, {"FRAMEWORK_CORE_FROZEN_PATHS"})
        parent = _git(REPO, "show", f"{PARENT_COMMIT}:tools/release/verify-current-audit.py")
        target = (REPO / "tools/release/verify-current-audit.py").read_bytes()
        self.assertEqual(
            verify._framework_recovery_9_unwrap_source_layer(REPO, target),
            parent,
        )

    def test_framework_recovery_9_successor_requires_activation(self) -> None:
        """Exercise framework_recovery_9_successor_requires_activation."""
        REPO = _repo()
        verify = _load_verify(REPO / "tools/release/verify-current-audit.py", f"_haldir_fr9_verify_{self._testMethodName}")
        chain = ["a" * 40, "b" * 40]
        with self.assertRaises(verify.CurrentAuditError):
            verify._framework_recovery_9_verify_successor_guard(chain, 1, repair_commit=chain[0], activation_commit=None, recovery_transition=None)

    def test_framework_recovery_9_test_source_ast_and_discovery_are_strict(self) -> None:
        """Exercise framework_recovery_9_test_source_ast_and_discovery_are_strict."""
        REPO = _repo()
        verify = _load_verify(REPO / "tools/release/verify-current-audit.py", f"_haldir_fr9_verify_{self._testMethodName}")
        payload = (REPO / "tools/release/test_verify_current_audit_fr_0009.py").read_bytes()
        tree = verify._framework_recovery_9_validate_test_source(payload, verify.FRAMEWORK_RECOVERY_9_TEST_PATH)
        self.assertEqual(hashlib.sha256(ast.dump(tree, include_attributes=False).encode()).hexdigest(), verify.FRAMEWORK_RECOVERY_9_TEST_AST_SHA256)
        self.assertEqual(len(verify._discover_unittest_test_ids(payload, verify.FRAMEWORK_RECOVERY_9_TEST_PATH, strict_runtime=True)), 60)

    def test_framework_recovery_9_transition_retires_epoch_9_and_creates_epoch_10(self) -> None:
        """Exercise framework_recovery_9_transition_retires_epoch_9_and_creates_epoch_10."""
        REPO = _repo()
        verify = _load_verify(REPO / "tools/release/verify-current-audit.py", f"_haldir_fr9_verify_{self._testMethodName}")
        transition = verify._framework_recovery_9_transition_identity()
        self.assertIs(transition["epoch_10_candidate_created"], True)
        self.assertIs(transition["epoch_9_reused"], False)

    def test_framework_recovery_9_warning_policy_is_exact_per_suite(self) -> None:
        """Exercise framework_recovery_9_warning_policy_is_exact_per_suite."""
        REPO = _repo()
        verify = _load_verify(REPO / "tools/release/verify-current-audit.py", f"_haldir_fr9_verify_{self._testMethodName}")
        contract = verify._framework_recovery_9_gate_and_p0_contract(REPO, _repair_commit(REPO))
        expected = {key: (["-W", "error::ResourceWarning"] if key == "fr_0002" else ["-W", "error"]) for key in SUITE_KEYS}
        self.assertEqual(contract["warning_policy_by_suite"], expected)

    def test_framework_recovery_9_warning_policy_rejects_fr_0002_exception_misstatement(self) -> None:
        """Exercise framework_recovery_9_warning_policy_rejects_fr_0002_exception_misstatement."""
        REPO = _repo()
        verify = _load_verify(REPO / "tools/release/verify-current-audit.py", f"_haldir_fr9_verify_{self._testMethodName}")
        contract = verify._framework_recovery_9_gate_and_p0_contract(REPO, _repair_commit(REPO))
        mutated = copy.deepcopy(contract)
        mutated["warning_policy_by_suite"]["fr_0002"] = ["-W", "error"]
        with self.assertRaises(verify.CurrentAuditError):
            verify._framework_recovery_9_verify_gate_and_p0_contract(mutated, contract)

    def test_framework_recovery_9_wrapper_accepts_epochs_2_through_10(self) -> None:
        """Exercise framework_recovery_9_wrapper_accepts_epochs_2_through_10."""
        REPO = _repo()
        verify = _load_verify(REPO / "tools/release/verify-current-audit.py", f"_haldir_fr9_verify_{self._testMethodName}")
        repair = _repair_commit(REPO)
        self.assertIsNone(verify._verify_post_activation_gate_retention(
            REPO, repair, framework_epoch=10, compare_worktree=False,
        ))
        source = _function_source(REPO / "tools/release/verify-current-audit.py", "_verify_post_activation_gate_retention")
        for epoch in range(2, 11):
            self.assertIn(f"{epoch}:".encode(), source)


if __name__ == "__main__":
    unittest.main()
