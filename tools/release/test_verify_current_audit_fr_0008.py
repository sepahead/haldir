"""Test the FR-0008 review-veto and evidence-binding recovery."""

from __future__ import annotations

import ast
import copy
import gzip
import hashlib
import importlib.util
import inspect
import json
import os
import re
import subprocess
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock


PARENT_COMMIT = "0ec8c45d50e7e73fbc1994bda27ac7ad127a00a7"
PARENT_TREE = "717284e47c7b457432ba3ef433ca19222ccd82ff"
DEFECT_CODE = "FR_0007_REVIEW_VETO_AND_EVIDENCE_BINDING_INVALID"
REPAIR_SUBJECT = "release: repair review veto and evidence binding"
SUITE_KEYS = (
    "legacy",
    "fr_0002",
    "fr_0003",
    "resource",
    "fr_0004",
    "fr_0005",
    "fr_0006",
    "fr_0007",
    "fr_0008",
)
PARENT_SUITE_COUNTS = (163, 78, 94, 26, 30, 44, 56, 37)
P0_EXTRA_UNITTEST_COUNTS = (6, 10, 23, 26, 22, 24)
WARNING_POLICY_BY_SUITE = {
    "legacy": ["-W", "error"],
    "fr_0002": ["-W", "error::ResourceWarning"],
    "fr_0003": ["-W", "error"],
    "resource": ["-W", "error"],
    "fr_0004": ["-W", "error"],
    "fr_0005": ["-W", "error"],
    "fr_0006": ["-W", "error"],
    "fr_0007": ["-W", "error"],
    "fr_0008": ["-W", "error"],
}
P0_EXTRA_UNITTEST_COMMAND_COUNT = 6
REQUIRED_TEST_IDS = {
    "test_framework_recovery_8_activation_scope_is_exact",
    "test_framework_recovery_8_ci_markers_accept_epoch_9_topology",
    "test_framework_recovery_8_ci_markers_reject_order_count_and_failure_mutations",
    "test_framework_recovery_8_code_diff_excludes_plan",
    "test_framework_recovery_8_decision_is_fail_closed",
    "test_framework_recovery_8_expected_gate_payload_is_exact",
    "test_framework_recovery_8_expected_plan_has_exact_contract",
    "test_framework_recovery_8_forward_replay_has_retirement_and_activation_guards",
    "test_framework_recovery_8_fr_0007_guard_accepts_only_fr_0008_retirement",
    "test_framework_recovery_8_framework_history_requires_fr_0007_retirement",
    "test_framework_recovery_8_gate_and_p0_topology_are_derived_from_pinned_sources",
    "test_framework_recovery_8_gate_and_p0_topology_reject_source_order_mutations",
    "test_framework_recovery_8_gate_runs_fr_0007_in_parent_snapshot",
    "test_framework_recovery_8_history_position_and_stages_are_exact",
    "test_framework_recovery_8_hosted_entry_accepts_exact_subject_workflow_and_attempt",
    "test_framework_recovery_8_hosted_entry_rejects_path_subject_workflow_and_attempt_mutations",
    "test_framework_recovery_8_identity_constants_are_exact",
    "test_framework_recovery_8_local_document_accepts_exact_bound_fixture",
    "test_framework_recovery_8_local_document_rejects_command_time_and_binding_mutations",
    "test_framework_recovery_8_local_document_rejects_marker_resource_and_failure_mutations",
    "test_framework_recovery_8_local_markers_accept_epoch_9_topology",
    "test_framework_recovery_8_local_markers_reject_order_count_ok_and_failure_mutations",
    "test_framework_recovery_8_parent_bytes_are_pinned",
    "test_framework_recovery_8_parent_has_no_fr_0007_q_or_a",
    "test_framework_recovery_8_parent_reproduction_accepts_exact_bound_fixture",
    "test_framework_recovery_8_parent_reproduction_reexecutes_parent_defect",
    "test_framework_recovery_8_parent_reproduction_rejects_catalog_and_chronology_mutations",
    "test_framework_recovery_8_parent_reproduction_rejects_command_log_and_receipt_mutations",
    "test_framework_recovery_8_parent_review_veto_is_reproduced",
    "test_framework_recovery_8_preserves_all_prior_test_suites",
    "test_framework_recovery_8_qualification_scope_is_exact",
    "test_framework_recovery_8_repair_scope_is_exact",
    "test_framework_recovery_8_reproduction_raw_is_verbose_identity_bound_and_canonical_gzip",
    "test_framework_recovery_8_reproduction_raw_rejects_noncanonical_and_wrong_identity_mutations",
    "test_framework_recovery_8_retires_fr_0007_without_qualification",
    "test_framework_recovery_8_retirement_absorbs_no_fr_0007_q_or_a",
    "test_framework_recovery_8_review_eligibility_accepts_two_go_reviews",
    "test_framework_recovery_8_review_eligibility_rejects_no_go_open_or_blocking",
    "test_framework_recovery_8_review_keys_are_separate",
    "test_framework_recovery_8_review_validator_accepts_additional_findings",
    "test_framework_recovery_8_review_validator_accepts_truthful_go",
    "test_framework_recovery_8_review_validator_accepts_truthful_no_go",
    "test_framework_recovery_8_review_validator_rejects_malformed_and_duplicate_findings",
    "test_framework_recovery_8_review_validator_rejects_model_fallback_and_wrong_model",
    "test_framework_recovery_8_run_attempt_uniqueness_accepts_distinct_attempt",
    "test_framework_recovery_8_run_attempt_uniqueness_rejects_reserved_and_duplicate",
    "test_framework_recovery_8_signatures_and_chronology_are_bound",
    "test_framework_recovery_8_source_compatibility_rejects_drift",
    "test_framework_recovery_8_source_retention_is_exact",
    "test_framework_recovery_8_successor_requires_activation",
    "test_framework_recovery_8_test_source_ast_and_discovery_are_strict",
    "test_framework_recovery_8_transition_retires_epoch_8_and_creates_epoch_9",
    "test_framework_recovery_8_warning_policy_is_exact_per_suite",
    "test_framework_recovery_8_warning_policy_rejects_fr_0002_exception_misstatement",
    "test_framework_recovery_8_wrapper_accepts_epochs_2_through_9",
}


def _repo() -> Path:
    return Path(__file__).resolve().parents[2]


def _load_verify():
    path = _repo() / "tools/release/verify-current-audit.py"
    spec = importlib.util.spec_from_file_location("verify_current_audit_fr_0008", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load verifier")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _git(*arguments: str) -> bytes:
    return subprocess.run(
        ["/usr/bin/git", "-C", str(_repo()), *arguments],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout


def _synthetic_repair_commit() -> str:
    """Create an unreferenced commit object from the exact current core bytes."""

    with tempfile.TemporaryDirectory(prefix="haldir-fr8-test-index-") as directory:
        environment = dict(os.environ)
        environment.update(
            {
                "GIT_INDEX_FILE": str(Path(directory) / "index"),
                "GIT_AUTHOR_NAME": "Sepehr Mahmoudian",
                "GIT_AUTHOR_EMAIL": "sepmhn@gmail.com",
                "GIT_COMMITTER_NAME": "Sepehr Mahmoudian",
                "GIT_COMMITTER_EMAIL": "sepmhn@gmail.com",
                "GIT_AUTHOR_DATE": "2026-07-26T12:00:00Z",
                "GIT_COMMITTER_DATE": "2026-07-26T12:00:00Z",
            }
        )

        def run(*arguments: str, input_bytes: bytes | None = None) -> bytes:
            return subprocess.run(
                ["/usr/bin/git", "-C", str(_repo()), *arguments],
                input=input_bytes,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=environment,
            ).stdout

        run("read-tree", PARENT_COMMIT)
        for mode, path in (
            ("100644", "tools/release/verify-current-audit.py"),
            ("100644", "tools/release/test_verify_current_audit_fr_0008.py"),
            ("100755", "tools/release/current-audit-gate.sh"),
        ):
            oid = run("hash-object", "-w", "--", path).decode("ascii").strip()
            run("update-index", "--add", "--cacheinfo", mode, oid, path)
        tree = run("write-tree").decode("ascii").strip()
        return (
            run(
                "commit-tree",
                tree,
                "-p",
                PARENT_COMMIT,
                input_bytes=(REPAIR_SUBJECT + "\n").encode("utf-8"),
            )
            .decode("ascii")
            .strip()
        )


def _function_source(module: object, name: str) -> str:
    return inspect.getsource(getattr(module, name))


def _mutate_source_once(payload: bytes, old: bytes, new: bytes) -> bytes:
    if payload.count(old) != 1:
        raise AssertionError("mutation anchor is not unique")
    return payload.replace(old, new)


def _all_suite_counts() -> tuple[int, ...]:
    return (*PARENT_SUITE_COUNTS, len(REQUIRED_TEST_IDS))


def _marker_contract() -> dict[str, object]:
    return {
        **{
            key: {
                "count": count,
                "warning_policy": copy.deepcopy(WARNING_POLICY_BY_SUITE[key]),
            }
            for key, count in zip(SUITE_KEYS, _all_suite_counts(), strict=True)
        },
        "p0_extra_unittest_counts": list(P0_EXTRA_UNITTEST_COUNTS),
        "p0_extra_unittest_command_count": P0_EXTRA_UNITTEST_COMMAND_COUNT,
    }


def _marker_log(
    *,
    counts: tuple[int, ...] | None,
    direct_ok: int,
    p0_ok: int,
) -> bytes:
    observed = counts if counts is not None else _all_suite_counts()
    direct = (
        b"=== CURRENT_AUDIT_GATE ===\n"
        b"$ tools/release/current-audit-gate.sh\n"
        + b"".join(
            f"Ran {count} tests in 0.001s\nOK\n".encode("ascii") for count in observed
        )
        + b"verify-current-audit: OK\n"
    )
    if direct_ok != len(observed):
        direct = direct.replace(b"OK\n", b"", len(observed) - direct_ok)
        if direct_ok > len(observed):
            direct += b"OK\n" * (direct_ok - len(observed))
    p0_counts = (*observed, *P0_EXTRA_UNITTEST_COUNTS)
    p0 = (
        b"=== P0R_EXIT_GATE ===\n"
        b"$ tools/p0r-exit-gate.sh\n"
        + b"".join(
            f"Ran {count} tests in 0.001s\nOK\n".encode("ascii") for count in p0_counts
        )
        + b"verify-current-audit: OK\n"
        + b"P0-R exit gate: 30 passed, 0 failed\n"
    )
    if p0_ok != len(p0_counts):
        p0 = p0.replace(b"OK\n", b"", len(p0_counts) - p0_ok)
        if p0_ok > len(p0_counts):
            p0 += b"OK\n" * (p0_ok - len(p0_counts))
    return (
        direct
        + p0
        + b"=== RESOURCE_PROFILE ===\n"
        + b"$ python3 -I tools/release/current-audit-resource-profile.py\n"
    )


def _ci_marker_log() -> bytes:
    timestamp = b"supply-chain\t2026-07-26T12:00:00Z "
    return (
        b"".join(
            timestamp
            + f"Ran {count} tests in 0.001s\n".encode("ascii")
            + timestamp
            + b"OK\n"
            for count in _all_suite_counts()
        )
        + timestamp
        + b"verify-current-audit: OK\n"
    )


def _canonical_gzip(payload: bytes) -> bytes:
    compressed = gzip.compress(payload, compresslevel=9, mtime=0)
    return compressed[:9] + b"\x03" + compressed[10:]


def _file_record(path: str, payload: bytes) -> dict[str, object]:
    return {
        "path": path,
        "mode": "100644",
        "sha256": hashlib.sha256(payload).hexdigest(),
        "bytes": len(payload),
    }


def _uncompressed_record(payload: bytes) -> dict[str, object]:
    return {
        "sha256": hashlib.sha256(payload).hexdigest(),
        "bytes": len(payload),
        "lines": len(payload.splitlines()),
    }


def _review_plan() -> dict[str, object]:
    return {
        "code_diff": {"patch_sha256": "1" * 64},
        "source_retention": {"manifest_sha256": "2" * 64},
        "transition_identity": {
            "epoch_8_state": "ABORTED_BEFORE_QUALIFICATION",
            "epoch_9_candidate_created": True,
        },
        "defect": {"code": DEFECT_CODE},
        "correction": {"review_veto_is_representable": True},
        "test_contract": {
            "required_regression_test_ids": sorted(REQUIRED_TEST_IDS),
        },
        "review_contract": {
            "capture_tool": {
                "sha256": "4" * 64,
                "bytes": 16_601,
            },
            "required_review_ids": ["FR-0008-R01", "FR-0008-R02"],
            "raw_response_retention": "PRIVATE_UNTRACKED",
        },
    }


def _review_subject(
    review_id: str,
) -> dict[str, object]:
    plan_path = (
        "release/0.9.0/current-head/closures/framework-recovery/FR-0008-plan.json"
    )
    return {
        "parent_commit": PARENT_COMMIT,
        "parent_tree": PARENT_TREE,
        "repair_commit": "8" * 40,
        "repair_tree": "9" * 40,
        "plan_record": {
            "path": plan_path,
            "mode": "100644",
            "sha256": "7" * 64,
            "bytes": 65_536,
        },
        "code_diff": copy.deepcopy(_review_plan()["code_diff"]),
        "source_retention": copy.deepcopy(_review_plan()["source_retention"]),
        "transition_identity": copy.deepcopy(_review_plan()["transition_identity"]),
        "defect": copy.deepcopy(_review_plan()["defect"]),
        "correction": copy.deepcopy(_review_plan()["correction"]),
        "review_id": review_id,
    }


def _review_subject_manifest(
    verify: object,
    review_id: str,
    model: str,
) -> str:
    subject = copy.deepcopy(_review_subject(review_id))
    subject.pop("review_id")
    manifest = {
        "schema_version": "1.0.0",
        "review_id": review_id,
        "model": model,
        "subject": subject,
        "required_finding_contract": copy.deepcopy(
            verify._framework_recovery_8_review_contracts()[review_id]
        ),
    }
    return hashlib.sha256(verify._canonical_json_bytes(manifest)).hexdigest()


def _review_fixture(
    verify: object,
    review_id: str,
    *,
    verdict: str,
    status: str,
    additional_findings: list[dict[str, object]] | None,
) -> dict[str, object]:
    kind = (
        "INTERNAL_AUTOMATED_DESIGN_REVIEW"
        if review_id == "FR-0008-R01"
        else "INTERNAL_AUTOMATED_IMPLEMENTATION_REVIEW"
    )
    model = "claude-fable-5" if review_id == "FR-0008-R01" else "claude-opus-5"
    contract = verify._framework_recovery_8_review_contracts()[review_id]
    required_findings = []
    for finding_id, mapping in contract.items():
        required_findings.append(
            {
                "id": finding_id,
                "severity": "BLOCKING",
                "status": status,
                "summary": "A substantive independent review finding.",
                "affected_functions": copy.deepcopy(mapping["affected_functions"]),
                "resolving_test_ids": copy.deepcopy(mapping["resolving_test_ids"]),
                "resolving_evidence_ids": copy.deepcopy(
                    mapping["resolving_evidence_ids"]
                ),
                "disposition": (
                    "Resolved by the bound repair and evidence."
                    if status == "RESOLVED"
                    else "The finding remains open."
                ),
            }
        )
        if status == "OPEN":
            required_findings[-1]["resolving_test_ids"] = []
            required_findings[-1]["resolving_evidence_ids"] = []
    subject = _review_subject(review_id)
    subject.pop("review_id")
    return {
        "schema_version": "2.0.0",
        "review_id": review_id,
        "kind": kind,
        "subject": subject,
        "reviewer": {
            "provider": "Anthropic",
            "model_requested": model,
            "model_resolved": model,
            "fallback_used": False,
            "classification": "INTERNAL_AUTOMATED",
            "human_review_performed": False,
            "named_human_review_performed": False,
            "external_independence": False,
            "release_authority": False,
            "capture_key_role": "LOCAL_RECORD_INTEGRITY_ONLY",
        },
        "capture": {
            "protocol": "HALDIR_AUTOMATED_REVIEW_CAPTURE_V1",
            "subject_manifest_sha256": _review_subject_manifest(
                verify, review_id, model
            ),
            "capture_tool_sha256": "4" * 64,
            "request_payload_sha256": (
                "5" * 64 if review_id == "FR-0008-R01" else "8" * 64
            ),
            "request_payload_bytes": 8_192,
            "raw_response_sha256": (
                "6" * 64 if review_id == "FR-0008-R01" else "9" * 64
            ),
            "raw_response_bytes": 4096,
            "attempt": 1,
            "stop_reason": "end_turn",
            "captured_at_utc": "2026-07-26T12:00:00Z",
            "raw_response_retention": "PRIVATE_UNTRACKED",
            "raw_response_committed": False,
        },
        "verdict": verdict,
        "required_findings": required_findings,
        "additional_findings": copy.deepcopy(additional_findings or []),
        "limitations": verify._framework_recovery_8_review_limitations(),
        "integrity_scope": "LOCAL_RECORD_INTEGRITY_ONLY",
        "detached_signature": {},
    }


def _validate_review(verify: object, value: dict[str, object]) -> dict[str, object]:
    attestation = {
        "public_key": "ssh-ed25519 " + "A" * 68,
        "key_fingerprint": "SHA256:" + "a" * 43,
    }
    with (
        mock.patch.object(
            verify, "_verify_ssh_detached_attestation", return_value=attestation
        ),
        mock.patch.object(
            verify,
            "_commit_metadata",
            return_value={"tree": value["subject"]["repair_tree"]},
        ),
        mock.patch.object(
            verify,
            "_commit_regular_file_record",
            return_value=value["subject"]["plan_record"],
        ),
    ):
        return verify._framework_recovery_8_validate_review(
            _repo(),
            value,
            review_id=value["review_id"],
            kind=value["kind"],
            repair_commit="8" * 40,
            plan=_review_plan(),
        )


def _verbose_reproduction_raw() -> bytes:
    test_id = (
        "test_framework_recovery_8_parent_review_veto_is_reproduced "
        "(__main__.FrameworkRecovery8Tests."
        "test_framework_recovery_8_parent_review_veto_is_reproduced)"
    )
    return (
        f"{test_id} ... ok\n\n".encode("ascii")
        + b"-" * 70
        + b"\nRan 1 test in 0.001s\n\nOK\n"
    )


def _normalized_reproduction_raw() -> bytes:
    return _verbose_reproduction_raw().replace(b"0.001s", b"<ELAPSED>s")


def _prior_capture_binding() -> dict[str, object]:
    return {
        "capture_tool": {
            "sha256": (
                "0bd79ba49eecb9f2cfbc314101f16aeab5e72177a9291c3dcbd149a2eeafb1aa"
            ),
            "bytes": 16_601,
        },
        "review_packet": {
            "sha256": (
                "c13a24a62150bf273f4206630118a7ebdfbcfee8ca8b0611bef16fee60c546ea"
            ),
            "bytes": 283_347,
        },
        "responses": [
            {
                "review_id": "FR-0007-R01",
                "model": "claude-fable-5",
                "attempt": 1,
                "stop_reason": "end_turn",
                "sha256": (
                    "5ae126766b82898be6be237cfb7eb0e92d3c1fd872db0f39f7d76c30f5f746f3"
                ),
                "bytes": 148_810,
            },
            {
                "review_id": "FR-0007-R02",
                "model": "claude-opus-5",
                "attempt": 1,
                "stop_reason": "end_turn",
                "sha256": (
                    "38242c56a04b7d420f9f1a9b0b58cf35fffadd9ae099466a90b590dcb978e335"
                ),
                "bytes": 260_452,
            },
        ],
        "raw_response_retention": "PRIVATE_UNTRACKED",
        "assurance": "LOCAL_CAPTURE_SIGNER_ATTESTED_HASH_BINDING_ONLY",
    }


def _reproduction_fixture(verify: object) -> dict[str, object]:
    raw_path = (
        "release/0.9.0/current-head/evidence/"
        "framework-recovery-fr-0008-d-reproduction-raw.log.gz"
    )
    receipt_path = (
        "release/0.9.0/current-head/evidence/"
        "framework-recovery-fr-0008-d-reproduction-semantic-receipt.json"
    )
    record_path = (
        "release/0.9.0/current-head/evidence/"
        "framework-recovery-fr-0008-d-reproduction.json"
    )
    raw = _verbose_reproduction_raw()
    compressed = _canonical_gzip(raw)
    execution = {
        "argv": [
            "python3",
            "-B",
            "-I",
            "-W",
            "error",
            "tools/release/test_verify_current_audit_fr_0008.py",
            "-v",
            (
                "FrameworkRecovery8Tests."
                "test_framework_recovery_8_parent_review_veto_is_reproduced"
            ),
        ],
        "started_at_utc": "2026-07-26T12:00:00Z",
        "completed_at_utc": "2026-07-26T12:00:01Z",
        "exit_status": 0,
        "result": "PASS",
    }
    defect = verify._framework_recovery_8_parent_contract_defects(_repo())
    normalized = _normalized_reproduction_raw()
    prior_capture = _prior_capture_binding()
    receipt = {
        "schema_version": "1.0.0",
        "contract_id": "HALDIR_FR_0008_REVIEW_VETO_EVIDENCE_BINDING_V1",
        "subject_commit": PARENT_COMMIT,
        "subject_tree": PARENT_TREE,
        "command": copy.deepcopy(execution["argv"]),
        "exit_status": 0,
        "raw_log_sha256": hashlib.sha256(raw).hexdigest(),
        "raw_log_bytes": len(raw),
        "raw_log_lines": len(raw.splitlines()),
        "normalized_log_sha256": hashlib.sha256(normalized).hexdigest(),
        "normalized_log_bytes": len(normalized),
        "normalized_log_lines": len(normalized.splitlines()),
        "normalization": "ELAPSED_SECONDS_ONLY",
        "parent_defect_sha256": hashlib.sha256(
            verify._canonical_json_bytes(defect)
        ).hexdigest(),
        "prior_capture_binding_sha256": hashlib.sha256(
            verify._canonical_json_bytes(prior_capture)
        ).hexdigest(),
        "semantic_derivation": "QUALIFICATION_REEXECUTION_FROM_PINNED_PARENT_BYTES",
        "result": "DEFECT_REPRODUCED",
    }
    receipt_payload = verify._canonical_json_bytes(receipt, pretty=True)
    record_payload = b"{}\n"
    files = [
        _file_record(record_path, record_payload),
        _file_record(raw_path, compressed),
        _file_record(receipt_path, receipt_payload),
    ]
    evidence_record = {
        "id": "FR-0008-E01",
        "kind": "PARENT_REVIEW_AND_EVIDENCE_CONTRACT_REPRODUCTION",
        "files": files,
        "subject_commit": PARENT_COMMIT,
        "result": "EXPECTED_DEFECT",
        "uncompressed": [None, _uncompressed_record(raw), None],
    }
    value = verify._framework_recovery_8_expected_parent_reproduction(
        _repo(),
        "8" * 40,
        execution=execution,
        raw_log={
            "file": copy.deepcopy(files[1]),
            "uncompressed": copy.deepcopy(evidence_record["uncompressed"][1]),
        },
        semantic_receipt={"file": copy.deepcopy(files[2])},
    )
    return {
        "value": value,
        "evidence_record": evidence_record,
        "raw": raw,
        "compressed": compressed,
        "receipt": receipt,
        "receipt_payload": receipt_payload,
        "raw_path": raw_path,
        "receipt_path": receipt_path,
        "defect": defect,
        "normalized": normalized,
        "prior_capture": prior_capture,
    }


def _local_fixture(verify: object) -> dict[str, object]:
    log_path = (
        "release/0.9.0/current-head/evidence/framework-recovery-fr-0008-r-local.log.gz"
    )
    document_path = (
        "release/0.9.0/current-head/evidence/framework-recovery-fr-0008-r-local.json"
    )
    resource = {
        "schema_version": "1.0.0",
        "generated_at_utc": "2026-07-26T12:00:05Z",
        "subject_commit": "8" * 40,
        "result": "PASS",
    }
    resource_payload = verify._canonical_json_bytes(resource, pretty=True)
    log = _marker_log(counts=None, direct_ok=9, p0_ok=15) + resource_payload
    compressed = _canonical_gzip(log)
    files = [
        _file_record(document_path, b"{}\n"),
        _file_record(log_path, compressed),
    ]
    evidence_record = {
        "id": "FR-0008-E04",
        "kind": "REPAIR_LOCAL_VALIDATION",
        "files": files,
        "subject_commit": "8" * 40,
        "result": "PASS",
        "uncompressed": [None, _uncompressed_record(log)],
    }
    command_times = (
        ("2026-07-26T12:00:01Z", "2026-07-26T12:00:03Z"),
        ("2026-07-26T12:00:03Z", "2026-07-26T12:00:05Z"),
        ("2026-07-26T12:00:05Z", "2026-07-26T12:00:06Z"),
    )
    commands = []
    for index, (argv, times) in enumerate(
        zip(verify._framework_recovery_8_local_commands(), command_times, strict=True)
    ):
        commands.append(
            {
                "id": ("CURRENT_AUDIT_GATE", "P0R_EXIT_GATE", "RESOURCE_PROFILE")[
                    index
                ],
                "argv": list(argv),
                "started_at_utc": times[0],
                "completed_at_utc": times[1],
                "exit_status": 0,
                "result": "PASS",
            }
        )
    value = {
        "schema_version": "1.0.0",
        "evidence_id": "FR-0008-E04",
        "kind": "REPAIR_LOCAL_VALIDATION",
        "subject_commit": "8" * 40,
        "subject_tree": "b" * 40,
        "platform": {
            "architecture": "arm64",
            "operating_system": "macOS",
        },
        "tool_versions": {
            "cargo": "cargo 1.88.0",
            "docker": "Docker 28.0.0",
            "git": "git version 2.50.0",
            "python": "Python 3.13.5",
            "rustc": "rustc 1.88.0",
        },
        "commands": commands,
        "raw_log": {
            "file": copy.deepcopy(files[1]),
            "uncompressed": copy.deepcopy(evidence_record["uncompressed"][1]),
        },
        "started_at_utc": command_times[0][0],
        "completed_at_utc": command_times[-1][1],
        "overall_result": "PASS",
    }
    return {
        "value": value,
        "evidence_record": evidence_record,
        "log": log,
        "compressed": compressed,
        "resource": resource,
        "log_path": log_path,
    }


def _history_chain(stage: str) -> list[str]:
    chain = (
        _git(
            "rev-list",
            "--first-parent",
            "--reverse",
            "bfe0b136213a823913cee0f2f7e21e2992c6aced.." + PARENT_COMMIT,
        )
        .decode("ascii")
        .splitlines()
    )
    if stage in {"R", "Q", "A"}:
        chain.append("8" * 40)
    if stage in {"Q", "A"}:
        chain.append("9" * 40)
    if stage == "A":
        chain.append("a" * 40)
    return chain


class FrameworkRecovery8Tests(unittest.TestCase):
    def test_framework_recovery_8_identity_constants_are_exact(self) -> None:
        verify = _load_verify()
        self.assertEqual(verify.FRAMEWORK_RECOVERY_8_PARENT, PARENT_COMMIT)
        self.assertEqual(verify.FRAMEWORK_RECOVERY_8_PARENT_TREE, PARENT_TREE)
        self.assertEqual(verify.FRAMEWORK_RECOVERY_8_ID, "FR-0008")
        self.assertEqual(verify.FRAMEWORK_RECOVERY_8_DEFECT_CODE, DEFECT_CODE)
        self.assertEqual(verify.FRAMEWORK_RECOVERY_8_SUBJECT, REPAIR_SUBJECT)
        self.assertEqual(tuple(verify.FRAMEWORK_RECOVERY_8_SUITE_KEYS), SUITE_KEYS)
        self.assertEqual(verify.FRAMEWORK_RECOVERY_8_REQUIRED_TEST_COUNT, 55)
        self.assertEqual(
            verify.FRAMEWORK_RECOVERY_8_P0_EXTRA_UNITTEST_COMMAND_COUNT,
            P0_EXTRA_UNITTEST_COMMAND_COUNT,
        )

    def test_framework_recovery_8_parent_bytes_are_pinned(self) -> None:
        verify = _load_verify()
        pins = (
            (
                "tools/release/verify-current-audit.py",
                verify.FRAMEWORK_RECOVERY_8_PARENT_VERIFIER_BYTES,
                verify.FRAMEWORK_RECOVERY_8_PARENT_VERIFIER_SHA256,
                verify.FRAMEWORK_RECOVERY_8_PARENT_VERIFIER_OID,
            ),
            (
                "tools/release/test_verify_current_audit_fr_0007.py",
                verify.FRAMEWORK_RECOVERY_8_PARENT_FR7_TEST_BYTES,
                verify.FRAMEWORK_RECOVERY_8_PARENT_FR7_TEST_SHA256,
                verify.FRAMEWORK_RECOVERY_8_PARENT_FR7_TEST_OID,
            ),
            (
                "tools/release/current-audit-gate.sh",
                verify.FRAMEWORK_RECOVERY_8_PARENT_GATE_BYTES,
                verify.FRAMEWORK_RECOVERY_8_PARENT_GATE_SHA256,
                verify.FRAMEWORK_RECOVERY_8_PARENT_GATE_OID,
            ),
            (
                "tools/p0r-exit-gate.sh",
                verify.FRAMEWORK_RECOVERY_8_PARENT_P0_GATE_BYTES,
                verify.FRAMEWORK_RECOVERY_8_PARENT_P0_GATE_SHA256,
                verify.FRAMEWORK_RECOVERY_8_PARENT_P0_GATE_OID,
            ),
            (
                "release/0.9.0/current-head/closures/framework-recovery/"
                "FR-0007-plan.json",
                verify.FRAMEWORK_RECOVERY_8_PARENT_FR7_PLAN_BYTES,
                verify.FRAMEWORK_RECOVERY_8_PARENT_FR7_PLAN_SHA256,
                verify.FRAMEWORK_RECOVERY_8_PARENT_FR7_PLAN_OID,
            ),
        )
        for path, size, digest, oid in pins:
            with self.subTest(path=path):
                payload = _git("show", f"{PARENT_COMMIT}:{path}")
                entry = _git("ls-tree", PARENT_COMMIT, path).decode("ascii")
                self.assertEqual(len(payload), size)
                self.assertEqual(hashlib.sha256(payload).hexdigest(), digest)
                self.assertIn(f" blob {oid}\t", entry)

    def test_framework_recovery_8_parent_has_no_fr_0007_q_or_a(self) -> None:
        verify = _load_verify()
        self.assertFalse(
            verify._git_path_exists(
                _repo(), PARENT_COMMIT, verify.FRAMEWORK_RECOVERY_7_QUALIFICATION_PATH
            )
        )
        self.assertFalse(
            verify._git_path_exists(
                _repo(), PARENT_COMMIT, verify.FRAMEWORK_RECOVERY_7_ACTIVATION_PATH
            )
        )

    def test_framework_recovery_8_repair_scope_is_exact(self) -> None:
        verify = _load_verify()
        self.assertEqual(
            verify.FRAMEWORK_RECOVERY_8_REPAIR_STATUSES,
            {
                verify.FRAMEWORK_RECOVERY_8_PLAN_PATH: "A",
                verify.FRAMEWORK_RECOVERY_8_TEST_PATH: "A",
                "tools/release/current-audit-gate.sh": "M",
                "tools/release/verify-current-audit.py": "M",
            },
        )

    def test_framework_recovery_8_qualification_scope_is_exact(self) -> None:
        verify = _load_verify()
        self.assertEqual(len(verify.FRAMEWORK_RECOVERY_8_QUALIFICATION_STATUSES), 14)
        self.assertEqual(
            set(verify.FRAMEWORK_RECOVERY_8_QUALIFICATION_STATUSES.values()), {"A"}
        )

    def test_framework_recovery_8_activation_scope_is_exact(self) -> None:
        verify = _load_verify()
        self.assertEqual(len(verify.FRAMEWORK_RECOVERY_8_ACTIVATION_STATUSES), 7)
        self.assertEqual(
            set(verify.FRAMEWORK_RECOVERY_8_ACTIVATION_STATUSES.values()), {"A"}
        )

    def test_framework_recovery_8_expected_plan_has_exact_contract(self) -> None:
        verify = _load_verify()
        plan = verify._framework_recovery_8_expected_plan(
            _repo(), _synthetic_repair_commit(), "f" * 40
        )
        self.assertEqual(plan["defect"]["code"], DEFECT_CODE)
        self.assertEqual(plan["framework_epoch"]["retired_candidate"], 8)
        self.assertEqual(plan["framework_epoch"]["next_candidate"], 9)
        self.assertEqual(plan["state"]["candidate_epoch"], 9)
        self.assertEqual(
            plan["test_contract"]["required_regression_test_ids"],
            sorted(REQUIRED_TEST_IDS),
        )
        self.assertEqual(
            {key: plan["test_contract"][key]["warning_policy"] for key in SUITE_KEYS},
            WARNING_POLICY_BY_SUITE,
        )
        self.assertEqual(
            plan["test_contract"]["p0_extra_unittest_counts"],
            list(P0_EXTRA_UNITTEST_COUNTS),
        )
        serialized = verify._canonical_json_bytes(plan, pretty=True)
        self.assertNotIn(b'"repair_commit": "8888888888888888', serialized)
        self.assertNotIn(b'"repair_tree":', serialized)

    def test_framework_recovery_8_code_diff_excludes_plan(self) -> None:
        verify = _load_verify()
        self.assertNotIn(
            verify.FRAMEWORK_RECOVERY_8_PLAN_PATH,
            verify.FRAMEWORK_RECOVERY_8_CORE_PATHS,
        )
        self.assertEqual(
            set(verify.FRAMEWORK_RECOVERY_8_CORE_PATHS),
            {
                "tools/release/verify-current-audit.py",
                "tools/release/test_verify_current_audit_fr_0008.py",
                "tools/release/current-audit-gate.sh",
            },
        )

    def test_framework_recovery_8_source_retention_is_exact(self) -> None:
        verify = _load_verify()
        parent = _git("show", f"{PARENT_COMMIT}:tools/release/verify-current-audit.py")
        current = Path(verify.__file__).read_bytes()
        verify._framework_recovery_8_validate_source_compatibility(parent, current)
        self.assertEqual(
            verify._framework_recovery_8_unwrap_source_layer(_repo(), current), parent
        )
        self.assertIn(
            "_verify_framework_recovery_7_history",
            verify.FRAMEWORK_RECOVERY_8_MODIFIED_DEFINITIONS,
        )

    def test_framework_recovery_8_source_compatibility_rejects_drift(self) -> None:
        verify = _load_verify()
        parent = _git("show", f"{PARENT_COMMIT}:tools/release/verify-current-audit.py")
        current = Path(verify.__file__).read_bytes()
        mutation = _mutate_source_once(
            current,
            b"return hashlib.sha256(payload).hexdigest()",
            b"return hashlib.sha256(payload + b'x').hexdigest()",
        )
        with self.assertRaises(verify.CurrentAuditError):
            verify._framework_recovery_8_validate_source_compatibility(parent, mutation)

    def test_framework_recovery_8_test_source_ast_and_discovery_are_strict(
        self,
    ) -> None:
        verify = _load_verify()
        payload = Path(__file__).read_bytes()
        tree = verify._framework_recovery_8_validate_test_source(payload, __file__)
        ids = verify._discover_unittest_test_ids(payload, __file__, strict_runtime=True)
        self.assertEqual(set(ids), REQUIRED_TEST_IDS)
        self.assertEqual(len(ids), 55)
        self.assertEqual(
            hashlib.sha256(
                ast.dump(tree, include_attributes=False).encode("utf-8")
            ).hexdigest(),
            verify.FRAMEWORK_RECOVERY_8_TEST_AST_SHA256,
        )

    def test_framework_recovery_8_preserves_all_prior_test_suites(self) -> None:
        verify = _load_verify()
        prior = (
            "tools/release/test_verify_current_audit.py",
            verify.FRAMEWORK_RECOVERY_2_TEST_PATH,
            verify.FRAMEWORK_RECOVERY_3_TEST_PATH,
            verify.FRAMEWORK_RECOVERY_3_RESOURCE_TEST_PATH,
            verify.FRAMEWORK_RECOVERY_4_TEST_PATH,
            verify.FRAMEWORK_RECOVERY_5_TEST_PATH,
            verify.FRAMEWORK_RECOVERY_6_TEST_PATH,
            verify.FRAMEWORK_RECOVERY_7_TEST_PATH,
        )
        head = _git("rev-parse", "HEAD").decode("ascii").strip()
        for path in prior:
            with self.subTest(path=path):
                self.assertEqual(
                    verify._git_tree_entry(_repo(), PARENT_COMMIT, path),
                    verify._git_tree_entry(_repo(), head, path),
                )

    def test_framework_recovery_8_expected_gate_payload_is_exact(self) -> None:
        verify = _load_verify()
        payload = verify._framework_recovery_8_expected_gate_payload()
        self.assertEqual(
            payload,
            (_repo() / "tools/release/current-audit-gate.sh").read_bytes(),
        )
        self.assertIn(b'/bin/chmod -R u+w "$FR7_COMPAT_DIR"\n', payload)
        self.assertNotIn(
            b'/bin/chmod -R u+w -- "$FR7_COMPAT_DIR"\n',
            payload,
        )
        verify._framework_recovery_8_verify_gate_payload(payload)
        with self.assertRaisesRegex(
            verify.CurrentAuditError,
            "CURRENT_AUDIT_FRAMEWORK_RECOVERY_8_GATE_WIRING",
        ):
            verify._framework_recovery_8_verify_gate_payload(payload + b"\n")

    def test_framework_recovery_8_gate_runs_fr_0007_in_parent_snapshot(self) -> None:
        verify = _load_verify()
        gate = verify._framework_recovery_8_expected_gate_payload()
        self.assertEqual(gate.count(PARENT_COMMIT.encode("ascii")), 2)
        self.assertEqual(
            gate.count(b"tools/release/test_verify_current_audit_fr_0007.py"),
            2,
        )
        self.assertIn(b"  clone \\\n", gate)
        self.assertIn(b"  --no-local \\\n", gate)
        self.assertIn(b"  --no-hardlinks \\\n", gate)
        self.assertIn(b"  checkout --detach --quiet ", gate)
        self.assertNotIn(b'test_verify_current_audit_fr_0007.py" \\\n', gate)
        contract = verify._framework_recovery_8_gate_and_p0_contract(
            _repo(), _synthetic_repair_commit()
        )
        self.assertEqual(
            contract["fr_0007_parent_snapshot"],
            {
                "commit": PARENT_COMMIT,
                "tree": PARENT_TREE,
                "suite_count": 37,
                "isolated_clone": True,
            },
        )

    def test_framework_recovery_8_wrapper_accepts_epochs_2_through_9(self) -> None:
        verify = _load_verify()
        source = _function_source(verify, "_verify_post_activation_gate_retention")
        self.assertIn("framework_epoch not in {2, 3, 4, 5, 6, 7, 8, 9}", source)
        self.assertIn("9: _framework_recovery_8_expected_gate_payload()", source)

    def test_framework_recovery_8_transition_retires_epoch_8_and_creates_epoch_9(
        self,
    ) -> None:
        verify = _load_verify()
        transition = verify._framework_recovery_8_transition_identity()
        self.assertEqual(transition["epoch_8_state"], "ABORTED_BEFORE_QUALIFICATION")
        self.assertFalse(transition["epoch_8_reused"])
        self.assertFalse(transition["fr_0007_mechanism_reused"])
        self.assertTrue(transition["epoch_9_candidate_created"])
        self.assertEqual(transition["active_epoch_before_activation"], 2)

    def test_framework_recovery_8_decision_is_fail_closed(self) -> None:
        verify = _load_verify()
        for state, active, allowed in (
            ("PENDING_QUALIFICATION", 2, False),
            ("QUALIFIED_PENDING_ACTIVATION", 2, False),
            ("ACTIVE", 9, True),
        ):
            with self.subTest(state=state):
                decision = verify._framework_recovery_8_decision(state)
                self.assertEqual(decision["framework_epoch"], 9)
                self.assertEqual(decision["active_framework_epoch"], active)
                self.assertIs(decision["successor_transitions_allowed"], allowed)
                self.assertEqual(decision["overall_release_status"], "NO_GO")
        with self.assertRaises(verify.CurrentAuditError):
            verify._framework_recovery_8_decision("UNKNOWN")

    def test_framework_recovery_8_history_position_and_stages_are_exact(
        self,
    ) -> None:
        verify = _load_verify()
        with (
            mock.patch.object(
                verify, "_verify_framework_recovery_8_repair", return_value={}
            ),
            mock.patch.object(
                verify, "_verify_framework_recovery_8_qualification", return_value={}
            ),
            mock.patch.object(
                verify, "_verify_framework_recovery_8_activation", return_value={}
            ),
        ):
            states = [
                verify._verify_framework_recovery_8_history(
                    _repo(), _history_chain(stage), framework_commit="f" * 40
                )
                for stage in ("R", "Q", "A")
            ]
        self.assertEqual(
            [item["state"] for item in states],
            ["PENDING_QUALIFICATION", "QUALIFIED_PENDING_ACTIVATION", "ACTIVE"],
        )
        self.assertEqual([item["active_framework_epoch"] for item in states], [2, 2, 9])
        invalid = _history_chain("R")
        invalid.insert(-1, "c" * 40)
        with self.assertRaises(verify.CurrentAuditError):
            verify._verify_framework_recovery_8_history(
                _repo(), invalid, framework_commit="f" * 40
            )

    def test_framework_recovery_8_retires_fr_0007_without_qualification(
        self,
    ) -> None:
        verify = _load_verify()
        repair = {"parent": PARENT_COMMIT, "subject": REPAIR_SUBJECT}
        with (
            mock.patch.object(
                verify, "_verify_framework_recovery_7_repair", return_value={}
            ),
            mock.patch.object(
                verify, "_verify_framework_recovery_8_repair", return_value={}
            ),
            mock.patch.object(verify, "_commit_metadata", side_effect=[repair, repair]),
            mock.patch.object(verify, "_git_path_exists", return_value=False),
        ):
            result = verify._verify_framework_recovery_7_history(
                _repo(), _history_chain("R"), framework_commit="f" * 40
            )
        self.assertEqual(result["state"], "ABORTED_BEFORE_QUALIFICATION")
        self.assertEqual(result["retirement_commit"], "8" * 40)
        self.assertIsNone(result["qualification_commit"])
        self.assertIsNone(result["activation_commit"])

    def test_framework_recovery_8_retirement_absorbs_no_fr_0007_q_or_a(
        self,
    ) -> None:
        verify = _load_verify()
        retirement = {"parent": PARENT_COMMIT, "subject": REPAIR_SUBJECT}
        later = {
            "parent": "8" * 40,
            "subject": verify.FRAMEWORK_RECOVERY_7_QUALIFICATION_SUBJECT,
        }
        with (
            mock.patch.object(
                verify, "_verify_framework_recovery_7_repair", return_value={}
            ),
            mock.patch.object(
                verify, "_verify_framework_recovery_8_repair", return_value={}
            ),
            mock.patch.object(
                verify, "_commit_metadata", side_effect=[retirement, retirement, later]
            ),
            mock.patch.object(verify, "_git_path_exists", return_value=False),
            self.assertRaisesRegex(
                verify.CurrentAuditError,
                "CURRENT_AUDIT_FRAMEWORK_RECOVERY_7_RETIREMENT_ABSORPTION",
            ),
        ):
            verify._verify_framework_recovery_7_history(
                _repo(), _history_chain("Q"), framework_commit="f" * 40
            )

    def test_framework_recovery_8_fr_0007_guard_accepts_only_fr_0008_retirement(
        self,
    ) -> None:
        verify = _load_verify()
        chain = _history_chain("R")
        accepted = {
            "stage": "RETIREMENT",
            "recovery_id": "FR-0008",
            "retirement_commit": "8" * 40,
        }
        verify._framework_recovery_7_verify_successor_guard(
            chain,
            len(chain) - 1,
            repair_commit=PARENT_COMMIT,
            activation_commit="8" * 40,
            recovery_transition=accepted,
        )
        for mutation in (
            {**accepted, "stage": "QUALIFICATION"},
            {**accepted, "recovery_id": "FR-0009"},
            {**accepted, "retirement_commit": "d" * 40},
            None,
        ):
            with (
                self.subTest(mutation=mutation),
                self.assertRaises(verify.CurrentAuditError),
            ):
                verify._framework_recovery_7_verify_successor_guard(
                    chain,
                    len(chain) - 1,
                    repair_commit=PARENT_COMMIT,
                    activation_commit="8" * 40,
                    recovery_transition=mutation,
                )
        later_chain = [*chain, "c" * 40]
        verify._framework_recovery_7_verify_successor_guard(
            later_chain,
            len(later_chain) - 1,
            repair_commit=PARENT_COMMIT,
            activation_commit="8" * 40,
            recovery_transition=None,
        )

    def test_framework_recovery_8_successor_requires_activation(self) -> None:
        verify = _load_verify()
        chain = _history_chain("A") + ["c" * 40]
        with self.assertRaisesRegex(
            verify.CurrentAuditError,
            "CURRENT_AUDIT_FRAMEWORK_RECOVERY_8_SUCCESSOR_BEFORE_ACTIVATION",
        ):
            verify._framework_recovery_8_verify_successor_guard(
                chain,
                len(chain) - 1,
                repair_commit="8" * 40,
                activation_commit=None,
                recovery_transition=None,
            )
        verify._framework_recovery_8_verify_successor_guard(
            chain,
            len(chain) - 1,
            repair_commit="8" * 40,
            activation_commit="a" * 40,
            recovery_transition=None,
        )

    def test_framework_recovery_8_forward_replay_has_retirement_and_activation_guards(
        self,
    ) -> None:
        verify = _load_verify()
        source = _function_source(verify, "_verify_forward_protocol_history")
        self.assertIn("_framework_recovery_7_verify_successor_guard", source)
        self.assertIn("_framework_recovery_8_verify_successor_guard", source)
        self.assertIn("recovery_7_terminal_commit", source)
        self.assertIn('descriptor.get("retirement_commit")', source)
        self.assertIn("recovery_8_repair_commit", source)
        self.assertIn("recovery_8_activation_commit", source)

    def test_framework_recovery_8_framework_history_requires_fr_0007_retirement(
        self,
    ) -> None:
        verify = _load_verify()
        source = _function_source(verify, "_verify_framework_history")
        self.assertIn('recovery_7["state"] != "ABORTED_BEFORE_QUALIFICATION"', source)
        self.assertIn(
            'recovery_7["retirement_commit"] != recovery_8["repair_commit"]',
            source,
        )
        self.assertIn("CURRENT_AUDIT_FRAMEWORK_RECOVERY_8_RETIREMENT_INVALID", source)

    def test_framework_recovery_8_parent_review_veto_is_reproduced(self) -> None:
        verify = _load_verify()
        defect = verify._framework_recovery_8_parent_contract_defects(_repo())
        self.assertEqual(defect["code"], DEFECT_CODE)
        self.assertEqual(defect["severity"], "QUALIFICATION_BLOCKER")
        self.assertEqual(
            defect["review_contract"]["no_go_rejected"],
            "CURRENT_AUDIT_FRAMEWORK_RECOVERY_7_REVIEW_INVALID",
        )
        self.assertEqual(
            defect["review_contract"]["open_rejected"],
            "CURRENT_AUDIT_FRAMEWORK_RECOVERY_7_REVIEW_FINDINGS",
        )
        self.assertEqual(
            defect["review_contract"]["additional_findings_rejected"],
            "CURRENT_AUDIT_FRAMEWORK_RECOVERY_7_REVIEW_FIELDS",
        )
        self.assertFalse(defect["evidence_contract"]["raw_transcript_identity_bound"])
        self.assertFalse(
            defect["evidence_contract"]["qualification_rederives_parent_semantics"]
        )
        self.assertFalse(defect["warning_policy_contract"]["signed_scalar_is_complete"])
        self.assertEqual(
            verify._framework_recovery_8_prior_review_capture_binding(),
            _prior_capture_binding(),
        )

    def test_framework_recovery_8_review_validator_accepts_truthful_go(self) -> None:
        verify = _load_verify()
        value = _review_fixture(
            verify,
            "FR-0008-R01",
            verdict="GO_FOR_FRAMEWORK_QUALIFICATION",
            status="RESOLVED",
            additional_findings=None,
        )
        outcome = _validate_review(verify, value)
        self.assertEqual(outcome["verdict"], "GO_FOR_FRAMEWORK_QUALIFICATION")
        self.assertEqual(outcome["open_blocker_ids"], [])
        self.assertEqual(
            outcome["required_finding_ids"],
            [item["id"] for item in value["required_findings"]],
        )
        self.assertTrue(
            all(
                re.fullmatch(r"F\d{3}", item["id"]) is not None
                for item in value["required_findings"]
            )
        )
        self.assertEqual(outcome["additional_blocker_ids"], [])
        self.assertEqual(
            outcome["capture_binding"]["raw_response_sha256"],
            value["capture"]["raw_response_sha256"],
        )
        self.assertIn("public_key", outcome)
        self.assertIn("key_fingerprint", outcome)

    def test_framework_recovery_8_review_validator_accepts_truthful_no_go(
        self,
    ) -> None:
        verify = _load_verify()
        value = _review_fixture(
            verify,
            "FR-0008-R02",
            verdict="NO_GO",
            status="OPEN",
            additional_findings=None,
        )
        outcome = _validate_review(verify, value)
        self.assertEqual(outcome["verdict"], "NO_GO")
        self.assertEqual(
            outcome["open_blocker_ids"],
            [item["id"] for item in value["required_findings"]],
        )

    def test_framework_recovery_8_review_validator_accepts_additional_findings(
        self,
    ) -> None:
        verify = _load_verify()
        additional = [
            {
                "id": "B001",
                "severity": "BLOCKING",
                "status": "OPEN",
                "summary": "A newly discovered qualification blocker.",
                "affected_functions": [
                    "_framework_recovery_8_validate_parent_reproduction"
                ],
                "affected_paths": ["tools/release/verify-current-audit.py"],
                "resolving_test_ids": [],
                "resolving_evidence_ids": [],
                "disposition": "The finding remains open.",
            }
        ]
        value = _review_fixture(
            verify,
            "FR-0008-R02",
            verdict="NO_GO",
            status="RESOLVED",
            additional_findings=additional,
        )
        outcome = _validate_review(verify, value)
        self.assertEqual(outcome["verdict"], "NO_GO")
        self.assertEqual(outcome["open_blocker_ids"], ["B001"])
        self.assertEqual(outcome["additional_blocker_ids"], ["B001"])

    def test_framework_recovery_8_review_validator_rejects_model_fallback_and_wrong_model(
        self,
    ) -> None:
        verify = _load_verify()
        valid = _review_fixture(
            verify,
            "FR-0008-R01",
            verdict="GO_FOR_FRAMEWORK_QUALIFICATION",
            status="RESOLVED",
            additional_findings=None,
        )
        mutations = []
        wrong_model = copy.deepcopy(valid)
        wrong_model["reviewer"]["model_resolved"] = "claude-opus-5"
        mutations.append(wrong_model)
        fallback = copy.deepcopy(valid)
        fallback["reviewer"]["fallback_used"] = True
        mutations.append(fallback)
        wrong_stop = copy.deepcopy(valid)
        wrong_stop["capture"]["stop_reason"] = "max_tokens"
        mutations.append(wrong_stop)
        for field in (
            "subject_manifest_sha256",
            "capture_tool_sha256",
            "request_payload_sha256",
            "raw_response_sha256",
        ):
            wrong_hash = copy.deepcopy(valid)
            wrong_hash["capture"][field] = "0" * 64
            mutations.append(wrong_hash)
        raw_content = copy.deepcopy(valid)
        raw_content["capture"]["raw_response"] = "provider response body"
        mutations.append(raw_content)
        private_path = copy.deepcopy(valid)
        private_path["capture"]["raw_response_path"] = "/private/tmp/response.json"
        mutations.append(private_path)
        for mutation in mutations:
            with (
                self.subTest(
                    digest=hashlib.sha256(
                        json.dumps(mutation, sort_keys=True).encode()
                    ).hexdigest()
                ),
                self.assertRaises(verify.CurrentAuditError),
            ):
                _validate_review(verify, mutation)

    def test_framework_recovery_8_review_validator_rejects_malformed_and_duplicate_findings(
        self,
    ) -> None:
        verify = _load_verify()
        valid = _review_fixture(
            verify,
            "FR-0008-R02",
            verdict="GO_FOR_FRAMEWORK_QUALIFICATION",
            status="RESOLVED",
            additional_findings=None,
        )
        mutations = []
        duplicate_required = copy.deepcopy(valid)
        duplicate_required["required_findings"].append(
            copy.deepcopy(duplicate_required["required_findings"][0])
        )
        mutations.append(duplicate_required)
        missing_required = copy.deepcopy(valid)
        missing_required["required_findings"].pop()
        mutations.append(missing_required)
        malformed_id = copy.deepcopy(valid)
        malformed_id["required_findings"][0]["id"] = "NOT-A-FINDING"
        mutations.append(malformed_id)
        open_with_resolver = _review_fixture(
            verify,
            "FR-0008-R02",
            verdict="NO_GO",
            status="OPEN",
            additional_findings=None,
        )
        open_with_resolver["required_findings"][0]["resolving_test_ids"] = [
            "test_framework_recovery_8_review_validator_accepts_truthful_no_go"
        ]
        mutations.append(open_with_resolver)
        duplicate_additional = copy.deepcopy(valid)
        item = {
            "id": "B001",
            "severity": "BLOCKING",
            "status": "RESOLVED",
            "summary": "Additional finding.",
            "affected_functions": ["_framework_recovery_8_validate_review"],
            "affected_paths": ["tools/release/verify-current-audit.py"],
            "resolving_test_ids": [
                "test_framework_recovery_8_review_validator_accepts_truthful_go"
            ],
            "resolving_evidence_ids": ["FR-0008-R02"],
            "disposition": "Resolved.",
        }
        duplicate_additional["additional_findings"] = [item, copy.deepcopy(item)]
        mutations.append(duplicate_additional)
        unsorted_additional = copy.deepcopy(valid)
        later = copy.deepcopy(item)
        later["id"] = "B002"
        earlier = copy.deepcopy(item)
        unsorted_additional["additional_findings"] = [later, earlier]
        mutations.append(unsorted_additional)
        noncanonical_path = copy.deepcopy(valid)
        path_finding = copy.deepcopy(item)
        path_finding["affected_paths"] = ["../private-response.json"]
        noncanonical_path["additional_findings"] = [path_finding]
        mutations.append(noncanonical_path)
        go_with_open = _review_fixture(
            verify,
            "FR-0008-R02",
            verdict="GO_FOR_FRAMEWORK_QUALIFICATION",
            status="OPEN",
            additional_findings=None,
        )
        mutations.append(go_with_open)
        no_go_without_open = _review_fixture(
            verify,
            "FR-0008-R02",
            verdict="NO_GO",
            status="RESOLVED",
            additional_findings=None,
        )
        mutations.append(no_go_without_open)
        for mutation in mutations:
            with (
                self.subTest(
                    digest=hashlib.sha256(
                        json.dumps(mutation, sort_keys=True).encode()
                    ).hexdigest()
                ),
                self.assertRaises(verify.CurrentAuditError),
            ):
                _validate_review(verify, mutation)

    def test_framework_recovery_8_review_eligibility_accepts_two_go_reviews(
        self,
    ) -> None:
        verify = _load_verify()
        outcomes = [
            _validate_review(
                verify,
                _review_fixture(
                    verify,
                    review_id,
                    verdict="GO_FOR_FRAMEWORK_QUALIFICATION",
                    status="RESOLVED",
                    additional_findings=None,
                ),
            )
            for review_id in ("FR-0008-R01", "FR-0008-R02")
        ]
        self.assertIsNone(verify._framework_recovery_8_require_reviews_go(outcomes))

    def test_framework_recovery_8_review_eligibility_rejects_no_go_open_or_blocking(
        self,
    ) -> None:
        verify = _load_verify()
        go = {
            "review_id": "FR-0008-R01",
            "verdict": "GO_FOR_FRAMEWORK_QUALIFICATION",
            "open_blocker_ids": [],
            "required_finding_ids": ["F001"],
            "additional_blocker_ids": [],
            "capture_binding": {"raw_response_sha256": "1" * 64},
            "captured_at_utc": "2026-07-26T12:00:00Z",
            "public_key": "key-a",
            "key_fingerprint": "fingerprint-a",
        }
        other_go = {
            **go,
            "review_id": "FR-0008-R02",
            "public_key": "key-b",
            "key_fingerprint": "fingerprint-b",
        }
        no_go = {**other_go, "verdict": "NO_GO", "open_blocker_ids": ["F001"]}
        open_required = {**other_go, "open_blocker_ids": ["F001"]}
        additional_blocker = {
            **other_go,
            "open_blocker_ids": ["B001"],
            "additional_blocker_ids": ["B001"],
        }
        veto_cases = (
            [go, no_go],
            [go, open_required],
            [go, additional_blocker],
        )
        for outcomes in veto_cases:
            with (
                self.subTest(outcomes=outcomes),
                self.assertRaisesRegex(
                    verify.CurrentAuditError,
                    "CURRENT_AUDIT_FRAMEWORK_RECOVERY_8_REVIEW_VETO",
                ),
            ):
                verify._framework_recovery_8_require_reviews_go(outcomes)
        set_cases = (
            [go],
            [go, go],
            [go, other_go, copy.deepcopy(other_go)],
            [go, {**other_go, "review_id": "FR-0008-R03"}],
        )
        for outcomes in set_cases:
            with (
                self.subTest(outcomes=outcomes),
                self.assertRaisesRegex(
                    verify.CurrentAuditError,
                    "CURRENT_AUDIT_FRAMEWORK_RECOVERY_8_REVIEW_SET",
                ),
            ):
                verify._framework_recovery_8_require_reviews_go(outcomes)

    def test_framework_recovery_8_review_keys_are_separate(self) -> None:
        verify = _load_verify()
        source = {"public_key": "release-key", "key_fingerprint": "release-fp"}
        valid = [
            {"public_key": "review-a", "key_fingerprint": "review-fp-a"},
            {"public_key": "review-b", "key_fingerprint": "review-fp-b"},
        ]
        self.assertIsNone(
            verify._framework_recovery_8_verify_review_key_separation(source, valid)
        )
        mutations = (
            [valid[0], valid[0]],
            [valid[0], {**valid[1], "public_key": valid[0]["public_key"]}],
            [valid[0], {**valid[1], "key_fingerprint": valid[0]["key_fingerprint"]}],
            [{**valid[0], "public_key": source["public_key"]}, valid[1]],
            [{**valid[0], "key_fingerprint": source["key_fingerprint"]}, valid[1]],
            valid[:1],
        )
        for mutation in mutations:
            with (
                self.subTest(mutation=mutation),
                self.assertRaises(verify.CurrentAuditError),
            ):
                verify._framework_recovery_8_verify_review_key_separation(
                    source, mutation
                )
        signed_review = _review_fixture(
            verify,
            "FR-0008-R01",
            verdict="GO_FOR_FRAMEWORK_QUALIFICATION",
            status="RESOLVED",
            additional_findings=None,
        )
        with (
            mock.patch.object(
                verify,
                "_commit_metadata",
                return_value={"tree": signed_review["subject"]["repair_tree"]},
            ),
            mock.patch.object(
                verify,
                "_commit_regular_file_record",
                return_value=signed_review["subject"]["plan_record"],
            ),
            mock.patch.object(
                verify,
                "_verify_ssh_detached_attestation",
                side_effect=verify.CurrentAuditError("signature rejected"),
            ),
            self.assertRaisesRegex(verify.CurrentAuditError, "signature rejected"),
        ):
            verify._framework_recovery_8_validate_review(
                _repo(),
                signed_review,
                review_id="FR-0008-R01",
                kind="INTERNAL_AUTOMATED_DESIGN_REVIEW",
                repair_commit="8" * 40,
                plan=_review_plan(),
            )

    def test_framework_recovery_8_parent_reproduction_accepts_exact_bound_fixture(
        self,
    ) -> None:
        verify = _load_verify()
        fixture = _reproduction_fixture(verify)
        repair_time = datetime(2026, 7, 26, 11, 59, tzinfo=timezone.utc)
        qualification_time = datetime(2026, 7, 26, 12, 1, tzinfo=timezone.utc)

        def git_file(repo: Path, commit: str, path: str) -> bytes:
            if path == fixture["raw_path"]:
                return fixture["compressed"]
            if path == fixture["receipt_path"]:
                return fixture["receipt_payload"]
            raise AssertionError(path)

        with (
            mock.patch.object(verify, "_git_file", side_effect=git_file),
            mock.patch.object(
                verify,
                "_commit_datetime",
                side_effect=[repair_time, qualification_time],
            ),
            mock.patch.object(
                verify,
                "_framework_recovery_8_rederive_parent_contract_defects",
                return_value=fixture["defect"],
            ),
        ):
            self.assertIsNone(
                verify._framework_recovery_8_validate_parent_reproduction(
                    _repo(),
                    "8" * 40,
                    "9" * 40,
                    fixture["value"],
                    evidence_record=fixture["evidence_record"],
                )
            )

    def test_framework_recovery_8_parent_reproduction_rejects_command_log_and_receipt_mutations(
        self,
    ) -> None:
        verify = _load_verify()
        fixture = _reproduction_fixture(verify)
        values = []
        bad_command = copy.deepcopy(fixture["value"])
        bad_command["execution"]["argv"][-1] = "FrameworkRecovery8Tests.wrong"
        values.append((bad_command, fixture["compressed"], fixture["receipt_payload"]))
        wrong_raw = fixture["raw"].replace(
            b"parent_review_veto_is_reproduced",
            b"parent_reproduction_accepts_exact_bound_fixture",
        )
        values.append(
            (
                copy.deepcopy(fixture["value"]),
                _canonical_gzip(wrong_raw),
                fixture["receipt_payload"],
            )
        )
        for field, replacement in (
            ("result", "PASS"),
            ("normalization", "NONE"),
            ("normalized_log_sha256", "0" * 64),
            ("parent_defect_sha256", "0" * 64),
            ("prior_capture_binding_sha256", "0" * 64),
            ("raw_log_lines", 5),
        ):
            wrong_receipt = copy.deepcopy(fixture["receipt"])
            wrong_receipt[field] = replacement
            values.append(
                (
                    copy.deepcopy(fixture["value"]),
                    fixture["compressed"],
                    verify._canonical_json_bytes(wrong_receipt, pretty=True),
                )
            )
        boundary = datetime(2026, 7, 26, 12, 0, tzinfo=timezone.utc)
        for value, compressed, receipt in values:
            with (
                self.subTest(digest=hashlib.sha256(compressed + receipt).hexdigest()),
                mock.patch.object(
                    verify,
                    "_git_file",
                    side_effect=lambda repo, commit, path: (
                        compressed if path == fixture["raw_path"] else receipt
                    ),
                ),
                mock.patch.object(
                    verify, "_commit_datetime", side_effect=[boundary, boundary]
                ),
                mock.patch.object(
                    verify,
                    "_framework_recovery_8_rederive_parent_contract_defects",
                    return_value=fixture["defect"],
                ),
                self.assertRaises(verify.CurrentAuditError),
            ):
                verify._framework_recovery_8_validate_parent_reproduction(
                    _repo(),
                    "8" * 40,
                    "9" * 40,
                    value,
                    evidence_record=fixture["evidence_record"],
                )

    def test_framework_recovery_8_parent_reproduction_reexecutes_parent_defect(
        self,
    ) -> None:
        verify = _load_verify()
        fixture = _reproduction_fixture(verify)
        boundary = datetime(2026, 7, 26, 12, 0, tzinfo=timezone.utc)
        rederive = mock.Mock(return_value=fixture["defect"])
        with (
            mock.patch.object(
                verify,
                "_git_file",
                side_effect=lambda repo, commit, path: (
                    fixture["compressed"]
                    if path == fixture["raw_path"]
                    else fixture["receipt_payload"]
                ),
            ),
            mock.patch.object(
                verify,
                "_commit_datetime",
                side_effect=[
                    boundary,
                    datetime(2026, 7, 26, 12, 1, tzinfo=timezone.utc),
                ],
            ),
            mock.patch.object(
                verify,
                "_framework_recovery_8_rederive_parent_contract_defects",
                rederive,
            ),
        ):
            verify._framework_recovery_8_validate_parent_reproduction(
                _repo(),
                "8" * 40,
                "9" * 40,
                fixture["value"],
                evidence_record=fixture["evidence_record"],
            )
        rederive.assert_called_once_with(_repo(), fixture["defect"])

    def test_framework_recovery_8_parent_reproduction_rejects_catalog_and_chronology_mutations(
        self,
    ) -> None:
        verify = _load_verify()
        fixture = _reproduction_fixture(verify)
        catalog_mutations = []
        wrong_subject = copy.deepcopy(fixture["evidence_record"])
        wrong_subject["subject_commit"] = "d" * 40
        catalog_mutations.append(wrong_subject)
        wrong_path = copy.deepcopy(fixture["evidence_record"])
        wrong_path["files"][1]["path"] += ".wrong"
        catalog_mutations.append(wrong_path)
        wrong_uncompressed = copy.deepcopy(fixture["evidence_record"])
        wrong_uncompressed["uncompressed"][1]["sha256"] = "0" * 64
        catalog_mutations.append(wrong_uncompressed)
        boundary = datetime(2026, 7, 26, 12, 0, tzinfo=timezone.utc)
        for evidence_record in catalog_mutations:
            with (
                self.subTest(evidence_record=evidence_record),
                mock.patch.object(
                    verify,
                    "_git_file",
                    side_effect=lambda repo, commit, path: (
                        fixture["compressed"]
                        if path == fixture["raw_path"]
                        else fixture["receipt_payload"]
                    ),
                ),
                mock.patch.object(
                    verify, "_commit_datetime", side_effect=[boundary, boundary]
                ),
                mock.patch.object(
                    verify,
                    "_framework_recovery_8_rederive_parent_contract_defects",
                    return_value=fixture["defect"],
                ),
                self.assertRaises(verify.CurrentAuditError),
            ):
                verify._framework_recovery_8_validate_parent_reproduction(
                    _repo(),
                    "8" * 40,
                    "9" * 40,
                    fixture["value"],
                    evidence_record=evidence_record,
                )
        before_repair = copy.deepcopy(fixture["value"])
        before_repair["execution"]["started_at_utc"] = "2026-07-26T11:59:59Z"
        with (
            mock.patch.object(
                verify,
                "_git_file",
                side_effect=lambda repo, commit, path: (
                    fixture["compressed"]
                    if path == fixture["raw_path"]
                    else fixture["receipt_payload"]
                ),
            ),
            mock.patch.object(
                verify, "_commit_datetime", side_effect=[boundary, boundary]
            ),
            mock.patch.object(
                verify,
                "_framework_recovery_8_rederive_parent_contract_defects",
                return_value=fixture["defect"],
            ),
            self.assertRaisesRegex(
                verify.CurrentAuditError,
                "CURRENT_AUDIT_FRAMEWORK_RECOVERY_8_REPRODUCTION_CHRONOLOGY",
            ),
        ):
            verify._framework_recovery_8_validate_parent_reproduction(
                _repo(),
                "8" * 40,
                "9" * 40,
                before_repair,
                evidence_record=fixture["evidence_record"],
            )

    def test_framework_recovery_8_local_document_accepts_exact_bound_fixture(
        self,
    ) -> None:
        verify = _load_verify()
        fixture = _local_fixture(verify)
        before = datetime(2026, 7, 26, 12, 0, tzinfo=timezone.utc)
        after = datetime(2026, 7, 26, 12, 1, tzinfo=timezone.utc)
        with (
            mock.patch.object(
                verify, "_commit_metadata", return_value={"tree": "b" * 40}
            ),
            mock.patch.object(verify, "_commit_datetime", side_effect=[before, after]),
            mock.patch.object(verify, "_git_file", return_value=fixture["compressed"]),
            mock.patch.object(
                verify,
                "_framework_recovery_3_validate_local_resource_profile",
                return_value=None,
            ),
        ):
            self.assertIsNone(
                verify._framework_recovery_8_validate_local_document(
                    _repo(),
                    "9" * 40,
                    "8" * 40,
                    fixture["value"],
                    evidence_record=fixture["evidence_record"],
                    test_contract=_marker_contract(),
                )
            )

    def test_framework_recovery_8_local_document_rejects_command_time_and_binding_mutations(
        self,
    ) -> None:
        verify = _load_verify()
        fixture = _local_fixture(verify)
        mutations = []
        bad_command = copy.deepcopy(fixture["value"])
        bad_command["commands"][0]["argv"].append("--changed")
        mutations.append(bad_command)
        overlapping = copy.deepcopy(fixture["value"])
        overlapping["commands"][1]["started_at_utc"] = "2026-07-26T12:00:02Z"
        mutations.append(overlapping)
        wrong_tree = copy.deepcopy(fixture["value"])
        wrong_tree["subject_tree"] = "c" * 40
        mutations.append(wrong_tree)
        wrong_binding = copy.deepcopy(fixture["value"])
        wrong_binding["raw_log"]["file"]["sha256"] = "0" * 64
        mutations.append(wrong_binding)
        before = datetime(2026, 7, 26, 12, 0, tzinfo=timezone.utc)
        after = datetime(2026, 7, 26, 12, 1, tzinfo=timezone.utc)
        for value in mutations:
            with (
                self.subTest(
                    digest=hashlib.sha256(
                        json.dumps(value, sort_keys=True).encode()
                    ).hexdigest()
                ),
                mock.patch.object(
                    verify, "_commit_metadata", return_value={"tree": "b" * 40}
                ),
                mock.patch.object(
                    verify, "_commit_datetime", side_effect=[before, after]
                ),
                mock.patch.object(
                    verify, "_git_file", return_value=fixture["compressed"]
                ),
                mock.patch.object(
                    verify,
                    "_framework_recovery_3_validate_local_resource_profile",
                    return_value=None,
                ),
                self.assertRaises(verify.CurrentAuditError),
            ):
                verify._framework_recovery_8_validate_local_document(
                    _repo(),
                    "9" * 40,
                    "8" * 40,
                    value,
                    evidence_record=fixture["evidence_record"],
                    test_contract=_marker_contract(),
                )

    def test_framework_recovery_8_local_document_rejects_marker_resource_and_failure_mutations(
        self,
    ) -> None:
        verify = _load_verify()
        fixture = _local_fixture(verify)
        resource_payload = verify._canonical_json_bytes(
            fixture["resource"], pretty=True
        )
        bad_logs = (
            fixture["log"].replace(b"Ran 55 tests", b"Ran 54 tests", 1),
            fixture["log"].replace(resource_payload, b'{"result":"PASS"}\n'),
            fixture["log"] + b"\nFAILED (failures=1)\n",
            fixture["log"].replace(
                b"P0-R exit gate: 30 passed, 0 failed",
                b"P0-R exit gate: 29 passed, 1 failed",
            ),
        )
        before = datetime(2026, 7, 26, 12, 0, tzinfo=timezone.utc)
        after = datetime(2026, 7, 26, 12, 1, tzinfo=timezone.utc)
        for log in bad_logs:
            with (
                self.subTest(digest=hashlib.sha256(log).hexdigest()),
                mock.patch.object(
                    verify, "_commit_metadata", return_value={"tree": "b" * 40}
                ),
                mock.patch.object(
                    verify, "_commit_datetime", side_effect=[before, after]
                ),
                mock.patch.object(
                    verify, "_git_file", return_value=_canonical_gzip(log)
                ),
                mock.patch.object(
                    verify,
                    "_framework_recovery_3_validate_local_resource_profile",
                    return_value=None,
                ),
                self.assertRaises(verify.CurrentAuditError),
            ):
                verify._framework_recovery_8_validate_local_document(
                    _repo(),
                    "9" * 40,
                    "8" * 40,
                    fixture["value"],
                    evidence_record=fixture["evidence_record"],
                    test_contract=_marker_contract(),
                )

    def test_framework_recovery_8_hosted_entry_accepts_exact_subject_workflow_and_attempt(
        self,
    ) -> None:
        verify = _load_verify()
        paths = (
            "ci.json",
            "ci-attempt.json",
            "ci.log.gz",
        )
        observed = {
            "files": [
                {"path": paths[0]},
                {"path": paths[1]},
                {"path": paths[2]},
            ]
        }
        completed = datetime(2026, 7, 26, 12, 0, tzinfo=timezone.utc)
        with (
            mock.patch.object(
                verify, "_framework_recovery_8_positive_attempt", return_value=2
            ),
            mock.patch.object(
                verify,
                "_framework_recovery_3_verify_hosted_entry",
                return_value=(observed, completed),
            ) as delegated,
        ):
            result = verify._framework_recovery_8_verify_hosted_entry(
                _repo(),
                "9" * 40,
                observed,
                paths=paths,
                subject_commit="8" * 40,
                workflow="ci",
                lane="repair_ci",
            )
        self.assertEqual(result, (observed, completed))
        delegated.assert_called_once_with(
            _repo(),
            "9" * 40,
            observed,
            paths=paths,
            subject_commit="8" * 40,
            workflow="ci",
            lane="fr_0008_repair_ci",
            expected_attempt=2,
            require_ordinary_attempt=True,
        )

    def test_framework_recovery_8_hosted_entry_rejects_path_subject_workflow_and_attempt_mutations(
        self,
    ) -> None:
        verify = _load_verify()
        paths = ("ci.json", "ci-attempt.json", "ci.log.gz")
        observed = {
            "files": [
                {"path": paths[0]},
                {"path": paths[1]},
                {"path": paths[2]},
            ]
        }
        wrong_path = copy.deepcopy(observed)
        wrong_path["files"][1]["path"] = "wrong-attempt.json"
        with self.assertRaises(verify.CurrentAuditError):
            verify._framework_recovery_8_verify_hosted_entry(
                _repo(),
                "9" * 40,
                wrong_path,
                paths=paths,
                subject_commit="8" * 40,
                workflow="ci",
                lane="repair_ci",
            )
        with (
            mock.patch.object(
                verify, "_framework_recovery_8_positive_attempt", return_value=1
            ),
            mock.patch.object(
                verify,
                "_framework_recovery_3_verify_hosted_entry",
                side_effect=verify.CurrentAuditError("delegated binding rejected"),
            ),
        ):
            for subject, workflow in (("d" * 40, "ci"), ("8" * 40, "formal")):
                with (
                    self.subTest(subject=subject, workflow=workflow),
                    self.assertRaises(verify.CurrentAuditError),
                ):
                    verify._framework_recovery_8_verify_hosted_entry(
                        _repo(),
                        "9" * 40,
                        observed,
                        paths=paths,
                        subject_commit=subject,
                        workflow=workflow,
                        lane="repair_ci",
                    )
        with (
            mock.patch.object(
                verify,
                "_framework_recovery_8_positive_attempt",
                side_effect=verify.CurrentAuditError("attempt rejected"),
            ),
            self.assertRaises(verify.CurrentAuditError),
        ):
            verify._framework_recovery_8_verify_hosted_entry(
                _repo(),
                "9" * 40,
                observed,
                paths=paths,
                subject_commit="8" * 40,
                workflow="ci",
                lane="repair_ci",
            )

    def test_framework_recovery_8_run_attempt_uniqueness_rejects_reserved_and_duplicate(
        self,
    ) -> None:
        verify = _load_verify()
        entries = [
            ("repair_ci", "9" * 40, {"files": []}),
            ("repair_formal", "9" * 40, {"files": []}),
        ]
        reserved = next(iter(verify.FRAMEWORK_RECOVERY_8_RESERVED_RUN_ATTEMPTS))
        with (
            mock.patch.object(
                verify,
                "_framework_recovery_8_run_attempt_identity",
                side_effect=[reserved, (99_000_000_002, 1)],
            ),
            self.assertRaisesRegex(
                verify.CurrentAuditError,
                "CURRENT_AUDIT_FRAMEWORK_RECOVERY_8_RUN_ATTEMPT_REUSED",
            ),
        ):
            verify._framework_recovery_8_verify_run_attempt_uniqueness(_repo(), entries)
        duplicate = (99_000_000_003, 1)
        with (
            mock.patch.object(
                verify,
                "_framework_recovery_8_run_attempt_identity",
                side_effect=[duplicate, duplicate],
            ),
            self.assertRaisesRegex(
                verify.CurrentAuditError,
                "CURRENT_AUDIT_FRAMEWORK_RECOVERY_8_RUN_ATTEMPT_REUSED",
            ),
        ):
            verify._framework_recovery_8_verify_run_attempt_uniqueness(_repo(), entries)

    def test_framework_recovery_8_run_attempt_uniqueness_accepts_distinct_attempt(
        self,
    ) -> None:
        verify = _load_verify()
        entries = [
            ("repair_ci", "9" * 40, {"files": []}),
            ("repair_formal", "9" * 40, {"files": []}),
        ]
        with mock.patch.object(
            verify,
            "_framework_recovery_8_run_attempt_identity",
            side_effect=[(99_000_000_001, 1), (99_000_000_001, 2)],
        ):
            self.assertIsNone(
                verify._framework_recovery_8_verify_run_attempt_uniqueness(
                    _repo(), entries
                )
            )

    def test_framework_recovery_8_signatures_and_chronology_are_bound(self) -> None:
        verify = _load_verify()
        combined = "\n".join(
            _function_source(verify, name)
            for name in (
                "_verify_framework_recovery_8_repair",
                "_verify_framework_recovery_8_qualification",
                "_verify_framework_recovery_8_activation",
            )
        )
        for namespace in (
            "haldir-framework-recovery-fr-0008-plan-v1",
            "haldir-framework-recovery-fr-0008-qualification-v1",
            "haldir-framework-recovery-fr-0008-activation-v1",
        ):
            self.assertIn(namespace, combined)
        self.assertIn("_commit_datetime", combined)
        self.assertIn("_verify_named_commit_signature", combined)
        repair_time = datetime(2026, 7, 26, 12, 0, tzinfo=timezone.utc)
        qualification_time = datetime(2026, 7, 26, 12, 10, tzinfo=timezone.utc)
        boundary = {
            "started_at_utc": "2026-07-26T12:00:00Z",
            "completed_at_utc": "2026-07-26T12:10:00Z",
        }
        with mock.patch.object(
            verify,
            "_commit_datetime",
            side_effect=[repair_time, qualification_time],
        ):
            self.assertIsNone(
                verify._framework_recovery_8_validate_parent_reproduction_chronology(
                    _repo(), "8" * 40, "9" * 40, boundary
                )
            )
        boundary["started_at_utc"] = "2026-07-26T11:59:59Z"
        with (
            mock.patch.object(
                verify,
                "_commit_datetime",
                side_effect=[repair_time, qualification_time],
            ),
            self.assertRaises(verify.CurrentAuditError),
        ):
            verify._framework_recovery_8_validate_parent_reproduction_chronology(
                _repo(), "8" * 40, "9" * 40, boundary
            )

    def test_framework_recovery_8_gate_and_p0_topology_are_derived_from_pinned_sources(
        self,
    ) -> None:
        verify = _load_verify()
        contract = verify._framework_recovery_8_gate_and_p0_contract(
            _repo(), _synthetic_repair_commit()
        )
        self.assertEqual(contract["suite_order"], list(SUITE_KEYS))
        self.assertEqual(contract["suite_counts"], list(_all_suite_counts()))
        self.assertEqual(contract["warning_policy_by_suite"], WARNING_POLICY_BY_SUITE)
        self.assertEqual(
            contract["p0"]["extra_unittest_counts"],
            list(P0_EXTRA_UNITTEST_COUNTS),
        )
        self.assertEqual(
            contract["p0"]["extra_unittest_command_count"],
            P0_EXTRA_UNITTEST_COMMAND_COUNT,
        )
        self.assertTrue(contract["p0"]["current_audit_precedes_extra_unittests"])
        self.assertEqual(
            contract["sources"]["p0_gate_sha256"],
            verify.FRAMEWORK_RECOVERY_8_PARENT_P0_GATE_SHA256,
        )

    def test_framework_recovery_8_gate_and_p0_topology_reject_source_order_mutations(
        self,
    ) -> None:
        verify = _load_verify()
        gate = verify._framework_recovery_8_expected_gate_payload()
        p0 = _git("show", f"{PARENT_COMMIT}:tools/p0r-exit-gate.sh")
        gate_mutation = _mutate_source_once(
            gate,
            b"tools/release/test_verify_current_audit_fr_0008.py\n",
            b"tools/release/verify-current-audit.py\n",
        )
        first_extra = re.search(
            rb"^run [^\n]* python3 -m unittest [^\n]+$", p0, flags=re.MULTILINE
        )
        audit = re.search(
            rb"^run \"current-head audit gate\" [^\n]+$", p0, flags=re.MULTILINE
        )
        self.assertIsNotNone(first_extra)
        self.assertIsNotNone(audit)
        p0_mutation = (
            p0[: audit.start()]
            + first_extra.group(0)
            + b"\n"
            + p0[audit.end() + 1 : first_extra.start()]
            + audit.group(0)
            + p0[first_extra.end() :]
        )

        def mutated_git_file(repo: Path, commit: str, path: str) -> bytes:
            if path == "tools/release/current-audit-gate.sh":
                return gate_mutation
            if path == "tools/p0r-exit-gate.sh":
                return p0
            return _git("show", f"{commit}:{path}")

        with (
            mock.patch.object(verify, "_git_file", side_effect=mutated_git_file),
            self.assertRaises(verify.CurrentAuditError),
        ):
            verify._framework_recovery_8_gate_and_p0_contract(
                _repo(), _synthetic_repair_commit()
            )

        def mutated_p0_git_file(repo: Path, commit: str, path: str) -> bytes:
            if path == "tools/release/current-audit-gate.sh":
                return gate
            if path == "tools/p0r-exit-gate.sh":
                return p0_mutation
            return _git("show", f"{commit}:{path}")

        with (
            mock.patch.object(verify, "_git_file", side_effect=mutated_p0_git_file),
            self.assertRaises(verify.CurrentAuditError),
        ):
            verify._framework_recovery_8_gate_and_p0_contract(
                _repo(), _synthetic_repair_commit()
            )

    def test_framework_recovery_8_warning_policy_is_exact_per_suite(self) -> None:
        verify = _load_verify()
        contract = verify._framework_recovery_8_gate_and_p0_contract(
            _repo(), _synthetic_repair_commit()
        )
        self.assertEqual(contract["warning_policy_by_suite"], WARNING_POLICY_BY_SUITE)
        self.assertEqual(
            {tuple(value) for value in contract["warning_policy_by_suite"].values()},
            {("-W", "error"), ("-W", "error::ResourceWarning")},
        )

    def test_framework_recovery_8_warning_policy_rejects_fr_0002_exception_misstatement(
        self,
    ) -> None:
        verify = _load_verify()
        derived = verify._framework_recovery_8_gate_and_p0_contract(
            _repo(), _synthetic_repair_commit()
        )
        mutation = copy.deepcopy(derived)
        mutation["warning_policy_by_suite"]["fr_0002"] = ["-W", "error"]
        with self.assertRaisesRegex(
            verify.CurrentAuditError,
            "CURRENT_AUDIT_FRAMEWORK_RECOVERY_8_WARNING_POLICY",
        ):
            verify._framework_recovery_8_verify_gate_and_p0_contract(mutation, derived)

    def test_framework_recovery_8_reproduction_raw_is_verbose_identity_bound_and_canonical_gzip(
        self,
    ) -> None:
        verify = _load_verify()
        raw = _verbose_reproduction_raw()
        compressed = _canonical_gzip(raw)
        normalized = _normalized_reproduction_raw()
        identity = (
            b"FrameworkRecovery8Tests."
            b"test_framework_recovery_8_parent_review_veto_is_reproduced"
        )
        self.assertEqual(raw.count(identity), 1)
        self.assertRegex(raw, rb"^test_framework_recovery_8_.* \(__main__\.")
        self.assertRegex(raw, rb"\nRan 1 test in \d+(?:\.\d+)?s\n\nOK\n$")
        self.assertEqual(compressed[:3], b"\x1f\x8b\x08")
        self.assertEqual(compressed[3], 0)
        self.assertEqual(compressed[4:8], b"\0\0\0\0")
        self.assertEqual(compressed[8], 2)
        self.assertEqual(compressed[9], 3)
        self.assertEqual(gzip.decompress(compressed), raw)
        self.assertEqual(len(raw.splitlines()), 6)
        self.assertEqual(len(normalized.splitlines()), 6)
        self.assertEqual(
            verify._framework_recovery_8_decode_reproduction_raw(compressed), raw
        )
        self.assertEqual(
            verify._framework_recovery_8_normalize_reproduction_raw(raw),
            normalized,
        )

    def test_framework_recovery_8_reproduction_raw_rejects_noncanonical_and_wrong_identity_mutations(
        self,
    ) -> None:
        verify = _load_verify()
        fixture = _reproduction_fixture(verify)
        wrong_os = fixture["compressed"][:9] + b"\0" + fixture["compressed"][10:]
        multi_member = fixture["compressed"] + _canonical_gzip(b"extra")
        trailing = fixture["compressed"] + b"trailing"
        wrong_identity_raw = fixture["raw"].replace(
            b"parent_review_veto_is_reproduced",
            b"review_validator_accepts_truthful_go",
        )
        nonverbose_raw = b".\n" + b"-" * 70 + b"\nRan 1 test in 0.001s\n\nOK\n"
        appended_semantics = fixture["raw"] + b"semantic_result=DEFECT_REPRODUCED\n"
        wrong_count = fixture["raw"].replace(b"Ran 1 test", b"Ran 2 tests")
        failed = (
            fixture["raw"]
            .replace(b"... ok", b"... FAIL")
            .replace(b"\nOK\n", b"\nFAILED (failures=1)\n")
        )
        error = (
            fixture["raw"]
            .replace(b"... ok", b"... ERROR")
            .replace(b"\nOK\n", b"\nFAILED (errors=1)\n")
        )
        expansion = _canonical_gzip(
            b"x" * (verify.FRAMEWORK_RECOVERY_8_REPRODUCTION_RAW_MAX_BYTES + 1)
        )
        mutations = (
            wrong_os,
            multi_member,
            trailing,
            _canonical_gzip(wrong_identity_raw),
            _canonical_gzip(nonverbose_raw),
            _canonical_gzip(appended_semantics),
            _canonical_gzip(wrong_count),
            _canonical_gzip(failed),
            _canonical_gzip(error),
            expansion,
        )
        boundary = datetime(2026, 7, 26, 12, 0, tzinfo=timezone.utc)
        for compressed in mutations:
            with (
                self.subTest(digest=hashlib.sha256(compressed).hexdigest()),
                mock.patch.object(
                    verify,
                    "_git_file",
                    side_effect=lambda repo, commit, path: (
                        compressed
                        if path == fixture["raw_path"]
                        else fixture["receipt_payload"]
                    ),
                ),
                mock.patch.object(
                    verify, "_commit_datetime", side_effect=[boundary, boundary]
                ),
                mock.patch.object(
                    verify,
                    "_framework_recovery_8_rederive_parent_contract_defects",
                    return_value=fixture["defect"],
                ),
                self.assertRaises(verify.CurrentAuditError),
            ):
                verify._framework_recovery_8_validate_parent_reproduction(
                    _repo(),
                    "8" * 40,
                    "9" * 40,
                    fixture["value"],
                    evidence_record=fixture["evidence_record"],
                )

    def test_framework_recovery_8_local_markers_accept_epoch_9_topology(
        self,
    ) -> None:
        verify = _load_verify()
        self.assertIsNone(
            verify._framework_recovery_8_verify_local_markers(
                _marker_log(counts=None, direct_ok=9, p0_ok=15),
                test_contract=_marker_contract(),
            )
        )

    def test_framework_recovery_8_local_markers_reject_order_count_ok_and_failure_mutations(
        self,
    ) -> None:
        verify = _load_verify()
        valid = _marker_log(counts=None, direct_ok=9, p0_ok=15)
        fr8 = b"Ran 55 tests in 0.001s\nOK\n"
        mutations = (
            valid.replace(
                b"Ran 163 tests in 0.001s\nOK\nRan 78 tests in 0.001s\nOK\n",
                b"Ran 78 tests in 0.001s\nOK\nRan 163 tests in 0.001s\nOK\n",
                1,
            ),
            valid.replace(fr8, b"Ran 54 tests in 0.001s\nOK\n", 1),
            valid.replace(fr8, b"", 1),
            valid.replace(fr8, fr8 + fr8, 1),
            valid.replace(b"\nOK\n", b"\n", 1),
            valid + b"\nFAILED (failures=1)\n",
            valid + b"\nTraceback (most recent call last):\n",
            valid + b"\nResourceWarning: leaked process\n",
        )
        for mutation in mutations:
            with (
                self.subTest(digest=hashlib.sha256(mutation).hexdigest()),
                self.assertRaises(verify.CurrentAuditError),
            ):
                verify._framework_recovery_8_verify_local_markers(
                    mutation, test_contract=_marker_contract()
                )

    def test_framework_recovery_8_ci_markers_accept_epoch_9_topology(self) -> None:
        verify = _load_verify()
        entry = {
            "files": [
                {"path": "ci.json"},
                {"path": "ci-attempt.json"},
                {"path": "ci.log.gz"},
            ]
        }
        with (
            mock.patch.object(
                verify, "_git_file", return_value=_canonical_gzip(b"hosted")
            ),
            mock.patch.object(
                verify, "_hosted_step_log_lines", return_value=_ci_marker_log()
            ),
        ):
            self.assertIsNone(
                verify._framework_recovery_8_verify_ci_markers(
                    _repo(),
                    "9" * 40,
                    entry,
                    test_contract=_marker_contract(),
                    label="repair_ci",
                )
            )

    def test_framework_recovery_8_ci_markers_reject_order_count_and_failure_mutations(
        self,
    ) -> None:
        verify = _load_verify()
        entry = {
            "files": [
                {"path": "ci.json"},
                {"path": "ci-attempt.json"},
                {"path": "ci.log.gz"},
            ]
        }
        valid = _ci_marker_log()
        mutations = (
            valid.replace(
                b"Ran 163 tests in 0.001s",
                b"Ran 999 tests in 0.001s",
                1,
            ),
            valid.replace(
                b"Ran 163 tests in 0.001s\n"
                b"supply-chain\t2026-07-26T12:00:00Z OK\n"
                b"supply-chain\t2026-07-26T12:00:00Z "
                b"Ran 78 tests in 0.001s",
                b"Ran 78 tests in 0.001s\n"
                b"supply-chain\t2026-07-26T12:00:00Z OK\n"
                b"supply-chain\t2026-07-26T12:00:00Z "
                b"Ran 163 tests in 0.001s",
                1,
            ),
            valid.replace(
                b"\nsupply-chain\t2026-07-26T12:00:00Z OK\n", b"\n", 1
            ),
            valid + b"2026-07-26T12:00:00Z FAILED (failures=1)\n",
            valid + b"2026-07-26T12:00:00Z Traceback\n",
        )
        for marker_log in mutations:
            with (
                self.subTest(digest=hashlib.sha256(marker_log).hexdigest()),
                mock.patch.object(
                    verify, "_git_file", return_value=_canonical_gzip(b"hosted")
                ),
                mock.patch.object(
                    verify, "_hosted_step_log_lines", return_value=marker_log
                ),
                self.assertRaises(verify.CurrentAuditError),
            ):
                verify._framework_recovery_8_verify_ci_markers(
                    _repo(),
                    "9" * 40,
                    entry,
                    test_contract=_marker_contract(),
                    label="repair_ci",
                )


if __name__ == "__main__":
    unittest.main()
