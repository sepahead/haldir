#!/usr/bin/env python3
"""Test the FR-0006 reproduction-evidence provenance recovery."""

# ruff: noqa: F401

from __future__ import annotations

import ast
import copy
import hashlib
import importlib.util
import inspect
import re
import subprocess
import sys
import unittest
import zlib
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock


PARENT_COMMIT = "5c0131d8b6a1a64d9465a1eb5f7039dc72d8c41e"
PARENT_TREE = "eb20644bccf64c42998ab2c5e340165fb4886142"
DEFECT_CODE = "FR_0005_REPRODUCTION_CAPTURE_PROVENANCE_CONTRADICTION"
REPAIR_SUBJECT = "release: repair reproduction evidence provenance"
PROVENANCE_SCHEMA = "REPRODUCTION_CAPTURE_PROVENANCE_V2"
REQUIRED_TEST_IDS = {
    "test_framework_recovery_6_identity_constants_are_exact",
    "test_framework_recovery_6_parent_bytes_are_pinned",
    "test_framework_recovery_6_parent_has_no_q_or_a",
    "test_framework_recovery_6_defect_code_and_subject_are_exact",
    "test_framework_recovery_6_parent_capture_provenance_contradiction_is_reproduced",
    "test_framework_recovery_6_correction_policy_is_fail_closed",
    "test_framework_recovery_6_transition_creates_epoch_7",
    "test_framework_recovery_6_epoch_6_is_not_reusable",
    "test_framework_recovery_6_decision_is_fail_closed",
    "test_framework_recovery_6_expected_plan_has_exact_fields",
    "test_framework_recovery_6_code_diff_excludes_plan",
    "test_framework_recovery_6_repair_scope_is_exact",
    "test_framework_recovery_6_qualification_scope_is_exact",
    "test_framework_recovery_6_activation_scope_is_exact",
    "test_framework_recovery_6_stage_modes_are_regular",
    "test_framework_recovery_6_materialization_is_inherited",
    "test_framework_recovery_6_resource_bounds_are_inherited",
    "test_framework_recovery_6_raw_capture_command_is_exact",
    "test_framework_recovery_6_raw_capture_uses_one_merged_descriptor",
    "test_framework_recovery_6_parent_command_emits_no_semantic_receipt",
    "test_framework_recovery_6_raw_transcript_is_execution_output_only",
    "test_framework_recovery_6_raw_transcript_grammar_is_exact",
    "test_framework_recovery_6_raw_transcript_record_is_bound",
    "test_framework_recovery_6_raw_transcript_rejects_append_and_rewrite",
    "test_framework_recovery_6_normalization_replaces_exactly_one_elapsed_value",
    "test_framework_recovery_6_normalization_is_pure_and_input_is_unchanged",
    "test_framework_recovery_6_normalization_rejects_zero_or_multiple_matches",
    "test_framework_recovery_6_normalization_rejects_non_ascii_crlf_nul_and_trailing_bytes",
    "test_framework_recovery_6_normalized_transcript_digest_is_bound",
    "test_framework_recovery_6_semantic_receipt_has_exact_fields",
    "test_framework_recovery_6_semantic_receipt_binds_command_config_and_exit",
    "test_framework_recovery_6_semantic_receipt_binds_raw_and_normalized_digests",
    "test_framework_recovery_6_reproduction_chronology_is_bound",
    "test_framework_recovery_6_semantic_receipt_mutations_are_rejected",
    "test_framework_recovery_6_qualification_requires_provenance_v2",
    "test_framework_recovery_6_evidence_catalog_binds_raw_and_receipt",
    "test_framework_recovery_6_evidence_signatures_and_chronology_are_bound",
    "test_framework_recovery_6_review_contracts_cite_real_tests",
    "test_framework_recovery_6_review_keys_are_separate",
    "test_framework_recovery_6_expected_gate_payload_is_exact",
    "test_framework_recovery_6_gate_order_and_warning_policy_are_exact",
    "test_framework_recovery_6_gate_rejects_missing_duplicate_or_reordered_suites",
    "test_framework_recovery_6_gate_runs_fr_0005_compatibility_exactly_once",
    "test_framework_recovery_6_preserves_all_prior_test_suites",
    "test_framework_recovery_6_test_contract_requires_exact_discovery_count",
    "test_framework_recovery_6_local_markers_require_every_suite",
    "test_framework_recovery_6_wrapper_accepts_epochs_2_through_7",
    "test_framework_recovery_6_history_requires_exact_position",
    "test_framework_recovery_6_history_states_are_contiguous",
    "test_framework_recovery_6_retires_fr_0005_without_qualification",
    "test_framework_recovery_6_retirement_absorbs_no_fr_0005_q_or_a",
    "test_framework_recovery_6_successor_requires_activation",
    "test_framework_recovery_6_forward_replay_has_pre_activation_guard",
    "test_framework_recovery_6_framework_history_requires_exact_retirement_relationship",
    "test_framework_recovery_6_source_retention_projects_all_recoveries_and_rejects_drift",
    "test_framework_recovery_6_test_source_ast_and_discovery_are_strict",
}


def _load_verify():
    """Load one isolated verifier module for a test."""

    module_path = Path(__file__).with_name("verify-current-audit.py")
    spec = importlib.util.spec_from_file_location("_fr_0006", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load the current-audit verifier")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _repo() -> Path:
    """Return the repository root."""

    return Path(__file__).resolve().parents[2]


def _git(*arguments: str) -> str:
    """Run one read-only Git query in a scrubbed environment."""

    allowed = {
        "cat-file",
        "diff-tree",
        "log",
        "merge-base",
        "rev-list",
        "rev-parse",
        "show",
    }
    command = next((item for item in arguments if not item.startswith("-")), "")
    if command not in allowed:
        raise RuntimeError("Git query is not read-only")
    return (
        subprocess.run(
            ["/usr/bin/git", *arguments],
            cwd=_repo(),
            check=True,
            stdin=subprocess.DEVNULL,
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
    """Return the first first-parent child of the immutable FR-0006 parent."""

    commits = _git(
        "rev-list",
        "--first-parent",
        "--reverse",
        f"{PARENT_COMMIT}..HEAD",
    ).splitlines()
    if not commits:
        raise RuntimeError("FR-0006 repair commit is not present")
    return commits[0]


def _framework_commit(verify) -> str:
    """Return the first framework commit on the repair ancestry."""

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
    """Read the canonical signed FR-0006 repair plan from committed bytes."""

    value, payload = verify._read_commit_json(
        _repo(),
        _repair_commit(),
        verify.FRAMEWORK_RECOVERY_6_PLAN_PATH,
        "fr_0006.test.plan",
    )
    if not isinstance(value, dict) or payload != verify._canonical_json_bytes(
        value, pretty=True
    ):
        raise RuntimeError("FR-0006 repair plan is not canonical")
    return value


def _function_source(verify, name: str) -> str:
    """Return one complete top-level function source segment."""

    source = Path(verify.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    matches = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == name
    ]
    if len(matches) != 1 or matches[0].end_lineno is None:
        raise RuntimeError(f"missing unique verifier definition: {name}")
    node = matches[0]
    return "\n".join(source.splitlines()[node.lineno - 1 : node.end_lineno])


def _utc(value: str) -> datetime:
    """Parse one fixed UTC test timestamp."""

    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    )


def _file_record(path: str, payload: bytes) -> dict:
    """Return one exact in-memory regular-file record."""

    return {
        "path": path,
        "sha256": hashlib.sha256(payload).hexdigest(),
        "bytes": len(payload),
        "lines": len(payload.splitlines()),
    }


def _deterministic_gzip(payload: bytes) -> bytes:
    """Return one deterministic level-nine gzip member with Unix OS byte."""

    compressor = zlib.compressobj(9, zlib.DEFLATED, -zlib.MAX_WBITS)
    body = compressor.compress(payload) + compressor.flush()
    checksum = zlib.crc32(payload) & 0xFFFFFFFF
    return (
        b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\x03"
        + body
        + checksum.to_bytes(4, "little")
        + (len(payload) & 0xFFFFFFFF).to_bytes(4, "little")
    )


def _semantic_receipt(
    verify,
    repair_commit: str,
    raw_transcript: bytes,
    records: dict,
) -> dict:
    """Build the exact detached semantic-receipt fixture."""

    normalized = _normalize_transcript_oracle(raw_transcript)
    defect = {
        "code": DEFECT_CODE,
        "severity": "QUALIFICATION_BLOCKER",
        "fr_0005_repair_commit": PARENT_COMMIT,
        "fr_0005_state_before_retirement": "PENDING_QUALIFICATION",
        "claimed_capture": "MERGED_STDOUT_STDERR_RAW_BYTES",
        "frozen_command_emits_semantic_receipt": False,
        "selected_test_semantic_value_use": "IN_MEMORY_VALIDATOR_FIXTURE_ONLY",
        "parent_validator_requires_unittest_transcript": True,
        "parent_validator_requires_semantic_suffix": True,
        "parent_required_semantic_suffix": {
            "sha256": "75c3be766628c2406e29b0ef108c91ca61c6e9a2d56229890444800bd2c8b730",
            "bytes": 561,
            "lines": 10,
        },
        "raw_transcript_and_required_composite_are_distinct": True,
        "private_helper_append_would_falsify_capture": True,
        "fr_0005_reproduction_contract_satisfiable": False,
    }
    return {
        "schema_version": "1.0.0",
        "receipt_id": "FR-0006-E01-SR01",
        "kind": "DETACHED_SEMANTIC_RECEIPT",
        "contract_id": verify.FRAMEWORK_RECOVERY_6_REPRODUCTION_CONTRACT_ID,
        "producer": {
            "recovery_id": "FR-0006",
            "repair_commit": repair_commit,
            "verifier": {
                "path": "tools/release/verify-current-audit.py",
                "function": "_framework_recovery_6_expected_semantic_receipt",
                "file": records["repair_verifier"],
            },
        },
        "subject": {
            "recovery_id": "FR-0005",
            "repair_commit": PARENT_COMMIT,
            "repair_tree": PARENT_TREE,
            "plan": records["parent_plan"],
            "verifier": records["parent_verifier"],
            "test": records["parent_test"],
        },
        "observation_binding": {
            "command_argv_canonical_json_sha256": (
                verify.FRAMEWORK_RECOVERY_6_REPRODUCTION_COMMAND_SHA256
            ),
            "capture_configuration_canonical_json_sha256": (
                verify.FRAMEWORK_RECOVERY_6_REPRODUCTION_CAPTURE_CONFIGURATION_SHA256
            ),
            "exit_status": 0,
            "raw_transcript": {
                "sha256": hashlib.sha256(raw_transcript).hexdigest(),
                "bytes": len(raw_transcript),
                "lines": len(raw_transcript.splitlines()),
            },
            "normalized_transcript": {
                "sha256": hashlib.sha256(normalized).hexdigest(),
                "bytes": len(normalized),
                "lines": len(normalized.splitlines()),
            },
        },
        "contract_facts": defect,
        "result": "FR_0005_REPRODUCTION_CONTRACT_UNSATISFIABLE",
    }


def _raw_transcript(elapsed: bytes) -> bytes:
    """Build only the exact five-line unittest command transcript."""

    return b".\n" + b"-" * 70 + b"\nRan 1 test in " + elapsed + b"s\n\nOK\n"


def _normalize_transcript_oracle(payload: bytes) -> bytes:
    """Independently normalize one exact unittest elapsed field."""

    if type(payload) is not bytes or len(payload) > 16_384:
        raise ValueError("invalid raw transcript")
    pattern = (
        rb"\A\.\n-{70}\nRan 1 test in "
        rb"(?P<elapsed>(?:0|[1-9][0-9]*)\.[0-9]{3})s\n\nOK\n\Z"
    )
    match = re.fullmatch(pattern, payload)
    if match is None:
        raise ValueError("invalid raw transcript")
    whole, fractional = match.group("elapsed").split(b".", 1)
    if int(whole) * 1_000 + int(fractional) >= 300_000:
        raise ValueError("raw transcript duration exceeds the bound")
    return b".\n" + b"-" * 70 + b"\nRan 1 test in <ELAPSED>s\n\nOK\n"


def _provenance_v2_fixture(verify) -> dict:
    """Return a fresh, complete provenance-v2 fixture."""

    repair_commit = "6" * 40
    qualification_commit = "7" * 40
    raw = _raw_transcript(b"0.001")
    normalized = _normalize_transcript_oracle(raw)
    compressed = _deterministic_gzip(raw)
    records = {
        "repair_verifier": _file_record(
            "tools/release/verify-current-audit.py", b"repair verifier\n"
        ),
        "parent_plan": _file_record(
            verify.FRAMEWORK_RECOVERY_5_PLAN_PATH, b"parent plan\n"
        ),
        "parent_verifier": _file_record(
            "tools/release/verify-current-audit.py", b"parent verifier\n"
        ),
        "parent_test": _file_record(
            verify.FRAMEWORK_RECOVERY_5_TEST_PATH, b"parent test\n"
        ),
    }
    receipt = _semantic_receipt(verify, repair_commit, raw, records)
    receipt_payload = verify._canonical_json_bytes(receipt, pretty=True)
    paths = verify.FRAMEWORK_RECOVERY_6_REPRODUCTION_REQUIREMENT["paths"]
    raw_file = _file_record(paths[1], compressed)
    receipt_file = _file_record(paths[2], receipt_payload)
    raw_record = _file_record(paths[1], raw)
    raw_record.pop("path")
    normalized_record = _file_record("normalized", normalized)
    normalized_record.pop("path")
    reproduction = {
        "schema_version": "2.0.0",
        "evidence_id": "FR-0006-E01",
        "kind": verify.FRAMEWORK_RECOVERY_6_REPRODUCTION_REQUIREMENT["kind"],
        "contract_id": verify.FRAMEWORK_RECOVERY_6_REPRODUCTION_CONTRACT_ID,
        "producer": {"recovery_id": "FR-0006", "repair_commit": repair_commit},
        "subject": {
            "recovery_id": "FR-0005",
            "repair_commit": PARENT_COMMIT,
            "repair_tree": PARENT_TREE,
        },
        "test_id": (
            "FrameworkRecovery5Tests."
            "test_framework_recovery_5_parent_rejects_rerun_attempt"
        ),
        "command": {
            "argv": list(verify._framework_recovery_6_parent_reproduction_command()),
            "argv_canonical_json_sha256": (
                verify.FRAMEWORK_RECOVERY_6_REPRODUCTION_COMMAND_SHA256
            ),
        },
        "capture_configuration": {
            "configuration": verify._framework_recovery_6_capture_configuration(),
            "canonical_json_sha256": (
                verify.FRAMEWORK_RECOVERY_6_REPRODUCTION_CAPTURE_CONFIGURATION_SHA256
            ),
        },
        "execution": {
            "started_at_utc": "2026-07-25T00:00:01Z",
            "completed_at_utc": "2026-07-25T00:00:02Z",
            "exit_status": 0,
            "result": "PASS",
        },
        "raw_transcript": {
            "capture_kind": "MERGED_STDOUT_STDERR_RAW_BYTES",
            "compressed_file": raw_file,
            "uncompressed": raw_record,
        },
        "normalization": {
            "algorithm": "UNITTEST_ELAPSED_FIELD_REPLACEMENT_V1",
            "source": "RAW_TRANSCRIPT_ONLY",
            "retained_as_file": False,
            "placeholder": "<ELAPSED>",
            "normalized": normalized_record,
        },
        "semantic_receipt": {
            "detached": True,
            "concatenated_to_raw_transcript": False,
            "file": receipt_file,
        },
        "result": "FR_0005_REPRODUCTION_CONTRACT_UNSATISFIABLE",
    }
    reproduction_payload = verify._canonical_json_bytes(reproduction, pretty=True)
    reproduction_file = _file_record(paths[0], reproduction_payload)
    catalog = {
        "id": "FR-0006-E01",
        "kind": verify.FRAMEWORK_RECOVERY_6_REPRODUCTION_REQUIREMENT["kind"],
        "files": [reproduction_file, raw_file, receipt_file],
        "subject_commit": PARENT_COMMIT,
        "result": "EXPECTED_DEFECT",
        "uncompressed": [None, raw_record, None],
    }
    return copy.deepcopy(
        {
            "repair_commit": repair_commit,
            "qualification_commit": qualification_commit,
            "raw": raw,
            "normalized": normalized,
            "compressed": compressed,
            "records": records,
            "defect": copy.deepcopy(receipt["contract_facts"]),
            "receipt": receipt,
            "receipt_payload": receipt_payload,
            "reproduction": reproduction,
            "reproduction_payload": reproduction_payload,
            "catalog": catalog,
        }
    )


def _execute_provenance_validator(
    verify,
    fixture: dict,
    value: dict | None,
    evidence_record: dict | None,
) -> None:
    """Run the provenance validator with bounded committed reads isolated."""

    reproduction = copy.deepcopy(
        fixture["reproduction"] if value is None else value
    )
    catalog = copy.deepcopy(
        fixture["catalog"] if evidence_record is None else evidence_record
    )
    paths = verify.FRAMEWORK_RECOVERY_6_REPRODUCTION_REQUIREMENT["paths"]
    reproduction_payload = verify._canonical_json_bytes(reproduction, pretty=True)
    receipt_payload = verify._canonical_json_bytes(fixture["receipt"], pretty=True)
    reproduction_file = _file_record(paths[0], reproduction_payload)
    raw_file = _file_record(paths[1], fixture["compressed"])
    receipt_file = _file_record(paths[2], receipt_payload)
    catalog["files"] = [reproduction_file, raw_file, receipt_file]
    reproduction["raw_transcript"]["compressed_file"] = raw_file
    reproduction["semantic_receipt"]["file"] = receipt_file
    reproduction_payload = verify._canonical_json_bytes(reproduction, pretty=True)
    catalog["files"][0] = _file_record(paths[0], reproduction_payload)
    record_reads = [
        *copy.deepcopy(catalog["files"]),
        copy.deepcopy(raw_file),
        copy.deepcopy(receipt_file),
        copy.deepcopy(fixture["records"]["repair_verifier"]),
        copy.deepcopy(fixture["records"]["parent_plan"]),
        copy.deepcopy(fixture["records"]["parent_verifier"]),
        copy.deepcopy(fixture["records"]["parent_test"]),
    ]
    file_reads = [
        fixture["compressed"],
        reproduction_payload,
        fixture["compressed"],
        receipt_payload,
    ]
    with (
        mock.patch.object(
            verify, "_commit_regular_file_record", side_effect=record_reads
        ),
        mock.patch.object(verify, "_git_file", side_effect=file_reads),
        mock.patch.object(
            verify,
            "_framework_recovery_6_parent_evidence_contract_defect",
            return_value=copy.deepcopy(fixture["defect"]),
        ),
        mock.patch.object(
            verify,
            "_commit_datetime",
            side_effect=[
                _utc("2026-07-25T00:00:00Z"),
                _utc("2026-07-25T00:00:03Z"),
            ],
        ),
    ):
        verify._framework_recovery_6_validate_parent_reproduction(
            Path("."),
            fixture["repair_commit"],
            fixture["qualification_commit"],
            reproduction,
            evidence_record=catalog,
        )


def _history_chain(phase: str) -> list[str]:
    """Build one exact synthetic FR-0006 R, Q, or A chain."""

    if phase not in {"R", "Q", "A"}:
        raise ValueError("unknown FR-0006 phase")
    chain = [f"{index:040x}" for index in range(23)]
    chain.extend(
        [
            "555108666cb82e8a36dcd4b08b5b30c62367a6f4",
            "4abfad7f2030257e7499d18f9502087b20dec04b",
            PARENT_COMMIT,
            "6" * 40,
        ]
    )
    if phase in {"Q", "A"}:
        chain.append("7" * 40)
    if phase == "A":
        chain.append("8" * 40)
    return chain


def _protocol_fixture(verify) -> dict:
    """Build fresh forward-replay requirements and transition fixtures."""

    return copy.deepcopy(
        {
            "repair_commit": "6" * 40,
            "qualification_commit": "7" * 40,
            "activation_commit": "8" * 40,
            "ordinary_commit": "9" * 40,
            "requirements": [
                copy.deepcopy(item)
                for item in verify.FRAMEWORK_RECOVERY_6_QUALIFICATION_REQUIREMENTS
            ],
            "claims": {
                "candidate_framework_epoch": 7,
                "active_framework_epoch": 2,
                "successor_transitions_allowed": False,
            },
            "registry": {"framework_epoch": 7, "state": "ACTIVE"},
            "revocation": {
                "recovery_id": "FR-0005",
                "state": "ABORTED_BEFORE_QUALIFICATION",
                "qualification_commit": None,
                "activation_commit": None,
            },
        }
    )


def _mutate_source_once(payload: bytes, old: bytes, new: bytes) -> bytes:
    """Return one exact in-memory source mutation."""

    if payload.count(old) != 1:
        raise ValueError("source mutation needle is not unique")
    return payload.replace(old, new, 1)


class FrameworkRecovery6Tests(unittest.TestCase):
    """Keep the epoch-7 provenance recovery exact."""

    def test_framework_recovery_6_identity_constants_are_exact(self) -> None:
        verify = _load_verify()
        self.assertEqual(verify.FRAMEWORK_RECOVERY_6_PARENT, PARENT_COMMIT)
        self.assertEqual(verify.FRAMEWORK_RECOVERY_6_PARENT_TREE, PARENT_TREE)
        self.assertEqual(verify.FRAMEWORK_RECOVERY_6_ID, "FR-0006")
        self.assertEqual(verify.FRAMEWORK_RECOVERY_6_DEFECT_CODE, DEFECT_CODE)
        self.assertEqual(verify.FRAMEWORK_RECOVERY_6_SUBJECT, REPAIR_SUBJECT)
        self.assertEqual(verify.FRAMEWORK_RECOVERY_6_PROVENANCE_SCHEMA, PROVENANCE_SCHEMA)
        self.assertEqual(
            verify.FRAMEWORK_RECOVERY_6_QUALIFICATION_SUBJECT,
            "release: qualify epoch-7 audit validation",
        )
        self.assertEqual(
            verify.FRAMEWORK_RECOVERY_6_ACTIVATION_SUBJECT,
            "release: activate epoch-7 audit validation",
        )

    def test_framework_recovery_6_parent_bytes_are_pinned(self) -> None:
        verify = _load_verify()
        verifier = verify._git_file(
            _repo(), PARENT_COMMIT, "tools/release/verify-current-audit.py"
        )
        prior_test = verify._git_file(
            _repo(), PARENT_COMMIT, verify.FRAMEWORK_RECOVERY_5_TEST_PATH
        )
        parent_plan = verify._git_file(
            _repo(), PARENT_COMMIT, verify.FRAMEWORK_RECOVERY_5_PLAN_PATH
        )
        self.assertEqual(
            (len(verifier), hashlib.sha256(verifier).hexdigest()),
            (
                1_180_876,
                "9215a8dfa7434376ada64f0b1d299d2ac1e84885a3d2974b4beb48eccf6ee8ec",
            ),
        )
        self.assertEqual(
            (len(prior_test), hashlib.sha256(prior_test).hexdigest()),
            (
                142_730,
                "c02f1cbdb8e7edc96c70086e02528c1a6f96528c01905025082cdd5d926d70a0",
            ),
        )
        self.assertEqual(
            (len(parent_plan), hashlib.sha256(parent_plan).hexdigest()),
            (
                42_413,
                "993f9a4c588b4777d66d47eac7923f4ac8c171810bdf9f4080f4d2f8ef318392",
            ),
        )
        self.assertEqual(verify.FRAMEWORK_RECOVERY_6_PARENT_VERIFIER_BYTES, 1_180_876)
        self.assertEqual(verify.FRAMEWORK_RECOVERY_6_PARENT_FR5_TEST_BYTES, 142_730)
        self.assertEqual(verify.FRAMEWORK_RECOVERY_6_PARENT_FR5_PLAN_BYTES, 42_413)

    def test_framework_recovery_6_parent_has_no_q_or_a(self) -> None:
        verify = _load_verify()
        for path in (
            verify.FRAMEWORK_RECOVERY_5_QUALIFICATION_PATH,
            verify.FRAMEWORK_RECOVERY_5_ACTIVATION_PATH,
        ):
            with self.subTest(path=path):
                self.assertFalse(verify._git_path_exists(_repo(), PARENT_COMMIT, path))

    def test_framework_recovery_6_defect_code_and_subject_are_exact(self) -> None:
        verify = _load_verify()
        self.assertEqual(DEFECT_CODE, verify.FRAMEWORK_RECOVERY_6_DEFECT_CODE)
        self.assertEqual(REPAIR_SUBJECT, verify.FRAMEWORK_RECOVERY_6_SUBJECT)
        self.assertEqual(
            verify.FRAMEWORK_RECOVERY_6_REPRODUCTION_CONTRACT_ID,
            "HALDIR_FR_0006_REPRODUCTION_V2",
        )
        self.assertEqual(
            verify.FRAMEWORK_RECOVERY_6_REPRODUCTION_REQUIREMENT["kind"],
            "PARENT_EVIDENCE_CONTRACT_PROVENANCE_REPRODUCTION_V2",
        )

    def test_framework_recovery_6_parent_capture_provenance_contradiction_is_reproduced(
        self,
    ) -> None:
        verify = _load_verify()
        defect = verify._framework_recovery_6_parent_evidence_contract_defect(_repo())
        self.assertEqual(defect["code"], DEFECT_CODE)
        self.assertEqual(defect["severity"], "QUALIFICATION_BLOCKER")
        self.assertEqual(defect["fr_0005_repair_commit"], PARENT_COMMIT)
        self.assertEqual(
            defect["selected_test_semantic_value_use"],
            "IN_MEMORY_VALIDATOR_FIXTURE_ONLY",
        )
        self.assertFalse(defect["frozen_command_emits_semantic_receipt"])
        self.assertTrue(defect["parent_validator_requires_unittest_transcript"])
        self.assertTrue(defect["parent_validator_requires_semantic_suffix"])
        self.assertTrue(defect["raw_transcript_and_required_composite_are_distinct"])
        self.assertTrue(defect["private_helper_append_would_falsify_capture"])
        self.assertFalse(defect["fr_0005_reproduction_contract_satisfiable"])
        self.assertEqual(
            defect["parent_required_semantic_suffix"],
            {
                "sha256": "75c3be766628c2406e29b0ef108c91ca61c6e9a2d56229890444800bd2c8b730",
                "bytes": 561,
                "lines": 10,
            },
        )

    def test_framework_recovery_6_correction_policy_is_fail_closed(self) -> None:
        verify = _load_verify()
        authority = verify._framework_recovery_6_authority()
        self.assertTrue(all(value is False for key, value in authority.items() if key != "overall_release_status"))
        self.assertEqual(authority["overall_release_status"], "NO_GO")
        composite = _raw_transcript(b"0.001") + b"FR-0005-REPRO result=DEFECT_REPRODUCED\n"
        with self.assertRaisesRegex(
            verify.CurrentAuditError,
            "CURRENT_AUDIT_FRAMEWORK_RECOVERY_6_REPRODUCTION_RAW_COMPOSITE",
        ):
            verify._framework_recovery_6_normalize_reproduction_transcript(composite)

    def test_framework_recovery_6_transition_creates_epoch_7(self) -> None:
        verify = _load_verify()
        transition = verify._framework_recovery_6_transition_identity()
        self.assertEqual(
            transition,
            {
                "transition_kind": "NEW_SIGNED_TRUST_ROOT_REBASELINE",
                "prior_framework_accepts_transition": False,
                "ordinary_successor_transition": False,
                "fr_0005_mechanism_reused": False,
                "epoch_6_reused": False,
                "epoch_6_state": "ABORTED_BEFORE_QUALIFICATION",
                "epoch_7_candidate_created": True,
                "active_epoch_before_activation": 2,
            },
        )

    def test_framework_recovery_6_epoch_6_is_not_reusable(self) -> None:
        verify = _load_verify()
        transition = verify._framework_recovery_6_transition_identity()
        self.assertFalse(transition["epoch_6_reused"])
        self.assertFalse(transition["fr_0005_mechanism_reused"])
        self.assertEqual(transition["epoch_6_state"], "ABORTED_BEFORE_QUALIFICATION")
        self.assertEqual(verify._framework_recovery_6_decision("ACTIVE")["framework_epoch"], 7)

    def test_framework_recovery_6_decision_is_fail_closed(self) -> None:
        verify = _load_verify()
        for state, active, allowed in (
            ("PENDING_QUALIFICATION", 2, False),
            ("QUALIFIED_PENDING_ACTIVATION", 2, False),
            ("ACTIVE", 7, True),
        ):
            with self.subTest(state=state):
                decision = verify._framework_recovery_6_decision(state)
                self.assertEqual(decision["state"], state)
                self.assertEqual(decision["framework_epoch"], 7)
                self.assertEqual(decision["active_framework_epoch"], active)
                self.assertIs(decision["framework_activation_authorized"], allowed)
                self.assertIs(decision["successor_transitions_allowed"], allowed)
                self.assertEqual(decision["overall_release_status"], "NO_GO")
        with self.assertRaisesRegex(
            verify.CurrentAuditError,
            "CURRENT_AUDIT_FRAMEWORK_RECOVERY_6_DECISION_STATE",
        ):
            verify._framework_recovery_6_decision("UNKNOWN")

    def test_framework_recovery_6_expected_plan_has_exact_fields(self) -> None:
        verify = _load_verify()
        source = _function_source(verify, "_framework_recovery_6_expected_plan")
        required = {
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
        self.assertTrue(all(f'"{field}"' in source for field in required))
        self.assertIn('"next_candidate": 7', source)
        self.assertIn('"retired_candidate": 6', source)
        self.assertIn('"new_evidence_required": True', source)

    def test_framework_recovery_6_code_diff_excludes_plan(self) -> None:
        verify = _load_verify()
        with mock.patch.object(
            verify, "_git", side_effect=[b"patch\n", b"status\x00", b"numstat\x00"]
        ) as git:
            record = verify._framework_recovery_6_code_diff(Path("."), "6" * 40)
        self.assertEqual(record["paths"], list(verify.FRAMEWORK_RECOVERY_6_CORE_PATHS))
        self.assertNotIn(verify.FRAMEWORK_RECOVERY_6_PLAN_PATH, record["paths"])
        self.assertEqual(record["target"], "SIGNED_COMMIT_CONTAINING_THIS_PLAN")
        self.assertEqual(git.call_count, 3)
        self.assertEqual(record["patch_sha256"], hashlib.sha256(b"patch\n").hexdigest())

    def test_framework_recovery_6_repair_scope_is_exact(self) -> None:
        verify = _load_verify()
        self.assertEqual(
            verify.FRAMEWORK_RECOVERY_6_REPAIR_STATUSES,
            {
                verify.FRAMEWORK_RECOVERY_6_PLAN_PATH: "A",
                verify.FRAMEWORK_RECOVERY_6_TEST_PATH: "A",
                "tools/release/current-audit-gate.sh": "M",
                "tools/release/verify-current-audit.py": "M",
            },
        )
        self.assertEqual(len(verify.FRAMEWORK_RECOVERY_6_REPAIR_STATUSES), 4)
        repair_commit = _repair_commit()
        framework_commit = _framework_commit(verify)
        plan = _repair_plan(verify)
        authenticated = verify._verify_framework_recovery_6_repair(
            _repo(), repair_commit, framework_commit=framework_commit
        )
        self.assertEqual(authenticated, plan)
        self.assertEqual(plan["recovery_id"], "FR-0006")
        self.assertEqual(plan["parent_commit"], PARENT_COMMIT)
        self.assertEqual(plan["repair_subject"], REPAIR_SUBJECT)

    def test_framework_recovery_6_qualification_scope_is_exact(self) -> None:
        verify = _load_verify()
        requirements = verify.FRAMEWORK_RECOVERY_6_QUALIFICATION_REQUIREMENTS
        self.assertEqual(
            [item["id"] for item in requirements],
            [
                "FR-0006-E01",
                "FR-0006-E02",
                "FR-0006-E03",
                "FR-0006-E04",
                "FR-0006-R01",
                "FR-0006-R02",
            ],
        )
        self.assertEqual(requirements[0], verify.FRAMEWORK_RECOVERY_6_REPRODUCTION_REQUIREMENT)
        expected_paths = 1 + sum(len(item["paths"]) for item in requirements)
        self.assertEqual(len(verify.FRAMEWORK_RECOVERY_6_QUALIFICATION_STATUSES), expected_paths)
        self.assertTrue(all(value == "A" for value in verify.FRAMEWORK_RECOVERY_6_QUALIFICATION_STATUSES.values()))

    def test_framework_recovery_6_activation_scope_is_exact(self) -> None:
        verify = _load_verify()
        requirements = verify.FRAMEWORK_RECOVERY_6_ACTIVATION_REQUIREMENTS
        self.assertEqual([item["id"] for item in requirements], ["FR-0006-A01", "FR-0006-A02"])
        self.assertEqual(
            [item["kind"] for item in requirements],
            ["QUALIFICATION_HOSTED_CI", "QUALIFICATION_HOSTED_FORMAL"],
        )
        expected_paths = 1 + sum(len(item["paths"]) for item in requirements)
        self.assertEqual(len(verify.FRAMEWORK_RECOVERY_6_ACTIVATION_STATUSES), expected_paths)
        self.assertTrue(all(value == "A" for value in verify.FRAMEWORK_RECOVERY_6_ACTIVATION_STATUSES.values()))

    def test_framework_recovery_6_stage_modes_are_regular(self) -> None:
        verify = _load_verify()
        expected = {"a": "100644", "b": "100755"}
        good = [
            {"mode": "100644", "type": "blob", "oid": "a" * 40},
            {"mode": "100755", "type": "blob", "oid": "b" * 40},
        ]
        with mock.patch.object(verify, "_git_tree_entry", side_effect=good):
            verify._framework_recovery_6_verify_stage_modes(
                Path("."), "6" * 40, expected, label="test"
            )
        bad = [{"mode": "120000", "type": "blob", "oid": "a" * 40}]
        with (
            mock.patch.object(verify, "_git_tree_entry", side_effect=bad),
            self.assertRaisesRegex(
                verify.CurrentAuditError,
                "CURRENT_AUDIT_FRAMEWORK_RECOVERY_6_MODE:test:a",
            ),
        ):
            verify._framework_recovery_6_verify_stage_modes(
                Path("."), "6" * 40, {"a": "100644"}, label="test"
            )

    def test_framework_recovery_6_materialization_is_inherited(self) -> None:
        verify = _load_verify()
        source = _function_source(verify, "_framework_recovery_6_expected_plan")
        self.assertIn('parent_plan.get("registered_snapshot_materialization")', source)
        self.assertIn(
            '"518784a1aa8071fb9c08c41766b0c115ad0024f6fb5787ae013a2b15b4b5b4fe"',
            source,
        )
        self.assertIn('"registered_snapshot_materialization": copy.deepcopy(materialization)', source)

    def test_framework_recovery_6_resource_bounds_are_inherited(self) -> None:
        verify = _load_verify()
        reproduction = verify.FRAMEWORK_RECOVERY_6_REPRODUCTION_REQUIREMENT
        self.assertEqual(reproduction["max_bytes"], [65_536, 16_384, 65_536])
        self.assertEqual(verify.FRAMEWORK_RECOVERY_6_REPRODUCTION_RAW_MAX_BYTES, 16_384)
        for requirement in (
            *verify.FRAMEWORK_RECOVERY_6_QUALIFICATION_REQUIREMENTS,
            *verify.FRAMEWORK_RECOVERY_6_ACTIVATION_REQUIREMENTS,
        ):
            with self.subTest(requirement=requirement["id"]):
                self.assertEqual(len(requirement["paths"]), len(requirement["max_bytes"]))
                self.assertTrue(all(type(value) is int and value > 0 for value in requirement["max_bytes"]))
        with self.assertRaisesRegex(
            verify.CurrentAuditError,
            "CURRENT_AUDIT_FRAMEWORK_RECOVERY_6_REPRODUCTION_GZIP_BOUND",
        ):
            verify._framework_recovery_6_decode_raw_transcript(b"x" * 16_385)

    def test_framework_recovery_6_raw_capture_command_is_exact(self) -> None:
        verify = _load_verify()
        command = verify._framework_recovery_6_parent_reproduction_command()
        self.assertEqual(
            command,
            (
                "python3",
                "-I",
                "tools/release/test_verify_current_audit_fr_0005.py",
                (
                    "FrameworkRecovery5Tests."
                    "test_framework_recovery_5_parent_rejects_rerun_attempt"
                ),
            ),
        )
        self.assertEqual(
            hashlib.sha256(verify._canonical_json_bytes(list(command))).hexdigest(),
            "7bba97b8450de6e28889843a0ff6b6183eaa0cb706c6e9f95ca4770d8712022e",
        )

    def test_framework_recovery_6_raw_capture_uses_one_merged_descriptor(self) -> None:
        verify = _load_verify()
        configuration = verify._framework_recovery_6_capture_configuration()
        self.assertEqual(
            configuration,
            {
                "schema_version": "1.0.0",
                "runner": "BOUNDED_SUBPROCESS_SINGLE_PIPE_V1",
                "cwd": "REPOSITORY_ROOT",
                "stdin": "DEVNULL",
                "stdout": "PIPE",
                "stderr": "STDOUT",
                "merge_model": "SINGLE_OS_PIPE",
                "shell": False,
                "text": False,
                "encoding": None,
                "newline_translation": "NONE",
                "start_new_session": True,
                "close_fds": True,
                "timeout_seconds": 300,
                "max_merged_bytes": 16_384,
                "separate_stderr_bytes": 0,
                "postprocessing": "NONE",
                "receipt_concatenation": False,
            },
        )
        self.assertEqual(len(configuration), 18)
        self.assertEqual(
            hashlib.sha256(verify._canonical_json_bytes(configuration)).hexdigest(),
            "9ad534cbc9bda2f3b703582bd943b58b032b00383b50d3d7f4d12fd2819fec41",
        )

    def test_framework_recovery_6_parent_command_emits_no_semantic_receipt(
        self,
    ) -> None:
        verify = _load_verify()
        fixture = _provenance_v2_fixture(verify)
        facts = fixture["receipt"]["contract_facts"]
        self.assertFalse(facts["frozen_command_emits_semantic_receipt"])
        self.assertEqual(
            facts["selected_test_semantic_value_use"],
            "IN_MEMORY_VALIDATOR_FIXTURE_ONLY",
        )
        self.assertNotIn(b"FR-0005-REPRO", fixture["raw"])
        self.assertFalse(
            verify._framework_recovery_6_has_forbidden_reference(
                fixture["reproduction"], {"contract_facts"}
            )
        )

    def test_framework_recovery_6_raw_transcript_is_execution_output_only(
        self,
    ) -> None:
        verify = _load_verify()
        raw = _raw_transcript(b"0.001")
        self.assertEqual(raw.count(b"Ran 1 test"), 1)
        self.assertEqual(len(raw.splitlines()), 5)
        self.assertNotIn(b"FR-0005-REPRO", raw)
        self.assertNotIn(b"DETACHED_SEMANTIC_RECEIPT", raw)
        self.assertEqual(
            verify._framework_recovery_6_normalize_reproduction_transcript(raw),
            verify.FRAMEWORK_RECOVERY_6_REPRODUCTION_NORMALIZED_TRANSCRIPT,
        )

    def test_framework_recovery_6_raw_transcript_grammar_is_exact(self) -> None:
        verify = _load_verify()
        for elapsed in (b"0.000", b"0.001", b"1.234", b"299.999"):
            with self.subTest(elapsed=elapsed):
                self.assertEqual(
                    verify._framework_recovery_6_normalize_reproduction_transcript(
                        _raw_transcript(elapsed)
                    ),
                    verify.FRAMEWORK_RECOVERY_6_REPRODUCTION_NORMALIZED_TRANSCRIPT,
                )
        for elapsed in (b"00.001", b"01.000", b"1.23", b"1.2345", b"300.000"):
            with self.subTest(elapsed=elapsed):
                with self.assertRaises(verify.CurrentAuditError):
                    verify._framework_recovery_6_normalize_reproduction_transcript(
                        _raw_transcript(elapsed)
                    )

    def test_framework_recovery_6_raw_transcript_record_is_bound(self) -> None:
        verify = _load_verify()
        fixture = _provenance_v2_fixture(verify)
        _execute_provenance_validator(verify, fixture, None, None)
        self.assertTrue(
            fixture["compressed"].startswith(
                b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\x03"
            )
        )
        self.assertEqual(
            verify._framework_recovery_6_decode_raw_transcript(
                fixture["compressed"]
            ),
            fixture["raw"],
        )
        with self.assertRaisesRegex(
            verify.CurrentAuditError,
            "CURRENT_AUDIT_FRAMEWORK_RECOVERY_6_REPRODUCTION_GZIP_SINGLE_MEMBER",
        ):
            verify._framework_recovery_6_decode_raw_transcript(
                fixture["compressed"] + b"trailing"
            )
        raw_record = fixture["reproduction"]["raw_transcript"]["uncompressed"]
        self.assertEqual(
            raw_record,
            {
                "sha256": hashlib.sha256(fixture["raw"]).hexdigest(),
                "bytes": len(fixture["raw"]),
                "lines": 5,
            },
        )
        self.assertEqual(fixture["catalog"]["uncompressed"], [None, raw_record, None])

    def test_framework_recovery_6_raw_transcript_rejects_append_and_rewrite(
        self,
    ) -> None:
        verify = _load_verify()
        raw = _raw_transcript(b"0.001")
        mutations = (
            raw + b"receipt\n",
            b"prefix\n" + raw,
            raw.replace(b"OK\n", b"FAILED\n"),
            raw.replace(b"-" * 70, b"-" * 69),
            raw[:-1],
        )
        for payload in mutations:
            with self.subTest(payload=payload[:16]):
                with self.assertRaises(verify.CurrentAuditError):
                    verify._framework_recovery_6_normalize_reproduction_transcript(
                        payload
                    )

    def test_framework_recovery_6_normalization_replaces_exactly_one_elapsed_value(
        self,
    ) -> None:
        verify = _load_verify()
        raw = _raw_transcript(b"12.345")
        expected = raw.replace(b"12.345", b"<ELAPSED>", 1)
        actual = verify._framework_recovery_6_normalize_reproduction_transcript(raw)
        self.assertEqual(actual, expected)
        self.assertEqual(actual.count(b"<ELAPSED>"), 1)
        self.assertNotIn(b"12.345", actual)
        self.assertEqual(actual, _normalize_transcript_oracle(raw))

    def test_framework_recovery_6_normalization_is_pure_and_input_is_unchanged(
        self,
    ) -> None:
        verify = _load_verify()
        raw = _raw_transcript(b"2.003")
        before = bytes(raw)
        first = verify._framework_recovery_6_normalize_reproduction_transcript(raw)
        second = verify._framework_recovery_6_normalize_reproduction_transcript(raw)
        self.assertEqual(raw, before)
        self.assertEqual(first, second)
        self.assertIsNot(first, raw)
        self.assertEqual(
            verify._framework_recovery_6_normalize_reproduction_transcript(first),
            first,
        )

    def test_framework_recovery_6_normalization_rejects_zero_or_multiple_matches(
        self,
    ) -> None:
        verify = _load_verify()
        for payload in (
            b"no duration\n",
            _raw_transcript(b"0.001") + _raw_transcript(b"0.001"),
            _raw_transcript(b"0.001").replace(
                b"Ran 1 test in 0.001s", b"Ran 1 test"
            ),
        ):
            with self.subTest(size=len(payload)):
                with self.assertRaises(verify.CurrentAuditError):
                    verify._framework_recovery_6_normalize_reproduction_transcript(
                        payload
                    )
                with self.assertRaises(ValueError):
                    _normalize_transcript_oracle(payload)

    def test_framework_recovery_6_normalization_rejects_non_ascii_crlf_nul_and_trailing_bytes(
        self,
    ) -> None:
        verify = _load_verify()
        raw = _raw_transcript(b"0.001")
        invalid = (
            raw.replace(b"OK", b"\xffK"),
            raw.replace(b"\n", b"\r\n"),
            raw.replace(b"OK", b"O\x00K"),
            raw.replace(b"\n", b"\r", 1),
            raw + b" ",
        )
        for payload in invalid:
            with self.subTest(payload=payload[-8:]):
                with self.assertRaises(verify.CurrentAuditError):
                    verify._framework_recovery_6_normalize_reproduction_transcript(
                        payload
                    )

    def test_framework_recovery_6_normalized_transcript_digest_is_bound(
        self,
    ) -> None:
        verify = _load_verify()
        normalized = verify.FRAMEWORK_RECOVERY_6_REPRODUCTION_NORMALIZED_TRANSCRIPT
        self.assertEqual(
            normalized, _normalize_transcript_oracle(_raw_transcript(b"0.001"))
        )
        self.assertEqual(len(normalized), 102)
        self.assertEqual(len(normalized.splitlines()), 5)
        self.assertEqual(
            hashlib.sha256(normalized).hexdigest(),
            "3e0c311b413385b8632fb597dd4a716c0925df61dde35b5714039eb42aae110d",
        )
        self.assertEqual(
            verify.FRAMEWORK_RECOVERY_6_REPRODUCTION_NORMALIZED_SHA256,
            hashlib.sha256(normalized).hexdigest(),
        )

    def test_framework_recovery_6_semantic_receipt_has_exact_fields(self) -> None:
        verify = _load_verify()
        receipt = _provenance_v2_fixture(verify)["receipt"]
        self.assertEqual(
            set(receipt),
            {
                "schema_version",
                "receipt_id",
                "kind",
                "contract_id",
                "producer",
                "subject",
                "observation_binding",
                "contract_facts",
                "result",
            },
        )
        self.assertEqual(set(receipt["producer"]), {"recovery_id", "repair_commit", "verifier"})
        self.assertEqual(set(receipt["producer"]["verifier"]), {"path", "function", "file"})
        self.assertEqual(
            set(receipt["subject"]),
            {"recovery_id", "repair_commit", "repair_tree", "plan", "verifier", "test"},
        )
        self.assertEqual(
            set(receipt["observation_binding"]),
            {
                "command_argv_canonical_json_sha256",
                "capture_configuration_canonical_json_sha256",
                "exit_status",
                "raw_transcript",
                "normalized_transcript",
            },
        )
        self.assertEqual(receipt["kind"], "DETACHED_SEMANTIC_RECEIPT")

    def test_framework_recovery_6_semantic_receipt_binds_command_config_and_exit(
        self,
    ) -> None:
        verify = _load_verify()
        fixture = _provenance_v2_fixture(verify)
        binding = fixture["receipt"]["observation_binding"]
        reproduction = fixture["reproduction"]
        self.assertEqual(
            binding["command_argv_canonical_json_sha256"],
            reproduction["command"]["argv_canonical_json_sha256"],
        )
        self.assertEqual(
            binding["capture_configuration_canonical_json_sha256"],
            reproduction["capture_configuration"]["canonical_json_sha256"],
        )
        self.assertEqual(binding["exit_status"], reproduction["execution"]["exit_status"])
        self.assertEqual(binding["exit_status"], 0)

    def test_framework_recovery_6_semantic_receipt_binds_raw_and_normalized_digests(
        self,
    ) -> None:
        verify = _load_verify()
        fixture = _provenance_v2_fixture(verify)
        binding = fixture["receipt"]["observation_binding"]
        self.assertEqual(binding["raw_transcript"], fixture["reproduction"]["raw_transcript"]["uncompressed"])
        self.assertEqual(binding["normalized_transcript"], fixture["reproduction"]["normalization"]["normalized"])
        self.assertEqual(binding["raw_transcript"]["sha256"], hashlib.sha256(fixture["raw"]).hexdigest())
        self.assertEqual(binding["normalized_transcript"]["sha256"], hashlib.sha256(fixture["normalized"]).hexdigest())
        self.assertNotEqual(binding["raw_transcript"]["sha256"], binding["normalized_transcript"]["sha256"])

    def test_framework_recovery_6_reproduction_chronology_is_bound(self) -> None:
        verify = _load_verify()
        fixture = _provenance_v2_fixture(verify)
        _execute_provenance_validator(verify, fixture, None, None)
        invalid = copy.deepcopy(fixture["reproduction"])
        invalid["execution"]["started_at_utc"] = "2026-07-25T00:00:03Z"
        invalid["execution"]["completed_at_utc"] = "2026-07-25T00:00:02Z"
        with self.assertRaisesRegex(
            verify.CurrentAuditError,
            "CURRENT_AUDIT_FRAMEWORK_RECOVERY_6_REPRODUCTION_CHRONOLOGY",
        ):
            _execute_provenance_validator(verify, fixture, invalid, None)

    def test_framework_recovery_6_semantic_receipt_mutations_are_rejected(
        self,
    ) -> None:
        verify = _load_verify()
        for field, value in (
            ("result", "PASS"),
            ("contract_id", "WRONG"),
            ("kind", "INLINE_SEMANTIC_RECEIPT"),
        ):
            fixture = _provenance_v2_fixture(verify)
            fixture["receipt"][field] = value
            with self.subTest(field=field):
                with self.assertRaisesRegex(
                    verify.CurrentAuditError,
                    "CURRENT_AUDIT_FRAMEWORK_RECOVERY_6_SEMANTIC_RECEIPT_INVALID",
                ):
                    _execute_provenance_validator(verify, fixture, None, None)
        digest_mutation = _provenance_v2_fixture(verify)
        digest_mutation["receipt"]["observation_binding"]["raw_transcript"][
            "sha256"
        ] = "0" * 64
        with self.assertRaisesRegex(
            verify.CurrentAuditError,
            "CURRENT_AUDIT_FRAMEWORK_RECOVERY_6_SEMANTIC_RECEIPT_INVALID",
        ):
            _execute_provenance_validator(
                verify, digest_mutation, None, None
            )
        fact_mutation = _provenance_v2_fixture(verify)
        fact_mutation["receipt"]["contract_facts"][
            "private_helper_append_would_falsify_capture"
        ] = False
        with self.assertRaisesRegex(
            verify.CurrentAuditError,
            "CURRENT_AUDIT_FRAMEWORK_RECOVERY_6_SEMANTIC_RECEIPT_INVALID",
        ):
            _execute_provenance_validator(verify, fact_mutation, None, None)

    def test_framework_recovery_6_qualification_requires_provenance_v2(self) -> None:
        verify = _load_verify()
        requirement = verify.FRAMEWORK_RECOVERY_6_QUALIFICATION_REQUIREMENTS[0]
        self.assertEqual(requirement["id"], "FR-0006-E01")
        self.assertEqual(requirement["kind"], "PARENT_EVIDENCE_CONTRACT_PROVENANCE_REPRODUCTION_V2")
        self.assertEqual(requirement["max_bytes"], [65_536, 16_384, 65_536])
        self.assertEqual(
            requirement["paths"],
            [
                "release/0.9.0/current-head/evidence/framework-recovery-fr-0006-d-reproduction-v2.json",
                "release/0.9.0/current-head/evidence/framework-recovery-fr-0006-d-reproduction-v2-raw.log.gz",
                "release/0.9.0/current-head/evidence/framework-recovery-fr-0006-d-reproduction-v2-semantic-receipt.json",
            ],
        )

    def test_framework_recovery_6_evidence_catalog_binds_raw_and_receipt(self) -> None:
        verify = _load_verify()
        fixture = _provenance_v2_fixture(verify)
        _execute_provenance_validator(verify, fixture, None, None)
        catalog = fixture["catalog"]
        self.assertEqual(catalog["subject_commit"], PARENT_COMMIT)
        self.assertEqual(catalog["result"], "EXPECTED_DEFECT")
        self.assertEqual(len(catalog["files"]), 3)
        invalid = copy.deepcopy(catalog)
        invalid["subject_commit"] = fixture["repair_commit"]
        with self.assertRaisesRegex(
            verify.CurrentAuditError,
            "CURRENT_AUDIT_FRAMEWORK_RECOVERY_6_REPRODUCTION_CATALOG_BINDING",
        ):
            _execute_provenance_validator(verify, fixture, None, invalid)
        wrong_result = copy.deepcopy(catalog)
        wrong_result["result"] = "PASS"
        with self.assertRaisesRegex(
            verify.CurrentAuditError,
            "CURRENT_AUDIT_FRAMEWORK_RECOVERY_6_REPRODUCTION_CATALOG_BINDING",
        ):
            _execute_provenance_validator(verify, fixture, None, wrong_result)

    def test_framework_recovery_6_evidence_signatures_and_chronology_are_bound(
        self,
    ) -> None:
        verify = _load_verify()
        repair = _function_source(verify, "_verify_framework_recovery_6_repair")
        qualification = _function_source(
            verify, "_verify_framework_recovery_6_qualification"
        )
        activation = _function_source(
            verify, "_verify_framework_recovery_6_activation"
        )
        self.assertIn("_verify_named_commit_signature", repair)
        self.assertIn("haldir-framework-recovery-fr-0006-plan-v1", repair)
        self.assertIn("haldir-framework-recovery-fr-0006-qualification-v1", qualification)
        self.assertIn("haldir-framework-recovery-fr-0006-activation-v1", activation)
        self.assertIn("_commit_datetime", repair)
        self.assertIn("_commit_datetime", qualification)
        self.assertIn("_commit_datetime", activation)
        review = _function_source(verify, "_framework_recovery_6_validate_review")
        local = _function_source(
            verify, "_framework_recovery_6_validate_local_document"
        )
        self.assertIn("fr-0006-design@automated.invalid", review)
        self.assertIn("fr-0006-implementation@automated.invalid", review)
        self.assertIn(
            "haldir-framework-recovery-fr-0006-local-integrity-v1", review
        )
        self.assertIn("framework_recovery_6.review", review)
        self.assertNotIn("fr-0005", review)
        self.assertNotIn("framework_recovery_5", review)
        self.assertNotIn("framework_recovery_5", local)

    def test_framework_recovery_6_review_contracts_cite_real_tests(self) -> None:
        verify = _load_verify()
        contracts = verify._framework_recovery_6_review_contracts()
        self.assertEqual(set(contracts), {"FR-0006-R01", "FR-0006-R02"})
        self.assertEqual(set(contracts["FR-0006-R01"]), {"F001", "F002", "F003"})
        self.assertEqual(
            set(contracts["FR-0006-R02"]), {"F101", "F102", "F103", "F104"}
        )
        cited = {
            test_id
            for review in contracts.values()
            for finding in review.values()
            for test_id in finding["resolving_test_ids"]
        }
        evidence = {
            evidence_id
            for review in contracts.values()
            for finding in review.values()
            for evidence_id in finding["resolving_evidence_ids"]
        }
        self.assertTrue(cited)
        self.assertTrue(cited.issubset(REQUIRED_TEST_IDS))
        self.assertEqual(
            evidence,
            {
                "FR-0006-E01",
                "FR-0006-E02",
                "FR-0006-E03",
                "FR-0006-E04",
                "FR-0006-R01",
                "FR-0006-R02",
            },
        )

    def test_framework_recovery_6_review_keys_are_separate(self) -> None:
        verify = _load_verify()
        signer = {"public_key": "source-key", "key_fingerprint": "source-fp"}
        reviews = [
            {"public_key": "design-key", "key_fingerprint": "design-fp"},
            {
                "public_key": "implementation-key",
                "key_fingerprint": "implementation-fp",
            },
        ]
        verify._framework_recovery_6_verify_review_key_separation(signer, reviews)
        duplicate = copy.deepcopy(reviews)
        duplicate[1] = copy.deepcopy(duplicate[0])
        with self.assertRaisesRegex(
            verify.CurrentAuditError,
            "CURRENT_AUDIT_FRAMEWORK_RECOVERY_6_REVIEW_KEY_SEPARATION",
        ):
            verify._framework_recovery_6_verify_review_key_separation(
                signer, duplicate
            )
        source_reuse = copy.deepcopy(reviews)
        source_reuse[0]["public_key"] = "source-key"
        with self.assertRaises(verify.CurrentAuditError):
            verify._framework_recovery_6_verify_review_key_separation(
                signer, source_reuse
            )

    def test_framework_recovery_6_expected_gate_payload_is_exact(self) -> None:
        verify = _load_verify()
        expected = verify._framework_recovery_6_expected_gate_payload()
        observed = Path("tools/release/current-audit-gate.sh").read_bytes()
        self.assertEqual(observed, expected)
        self.assertTrue(expected.startswith(b"#!/usr/bin/env bash\n"))
        self.assertTrue(expected.endswith(b"tools/release/verify-current-audit.py\n"))

    def test_framework_recovery_6_gate_order_and_warning_policy_are_exact(
        self,
    ) -> None:
        verify = _load_verify()
        gate = verify._framework_recovery_6_expected_gate_payload()
        suites = (
            b'"$PYTHON3" -B -I -W error tools/release/test_verify_current_audit.py\n',
            b'"$PYTHON3" -B -I -W error::ResourceWarning \\\n'
            b'  "$FR2_COMPAT_DIR/test_verify_current_audit_fr_0002.py"\n',
            b'"$PYTHON3" -B -I -W error \\\n'
            b'  "$FR3_COMPAT_DIR/test_verify_current_audit_fr_0003.py"\n',
            b'"$PYTHON3" -B -I -W error '
            b"tools/release/test_current_audit_resource_profile.py\n",
            b'"$PYTHON3" -B -I -W error \\\n'
            b'  "$FR4_COMPAT_DIR/test_verify_current_audit_fr_0004.py"\n',
            b'"$PYTHON3" -B -I -W error \\\n'
            b'  "$FR5_COMPAT_DIR/test_verify_current_audit_fr_0005.py"\n',
            b'"$PYTHON3" -B -I -W error '
            b"tools/release/test_verify_current_audit_fr_0006.py\n",
            b'"$PYTHON3" -B -I -W error '
            b"tools/release/verify-current-audit.py\n",
        )
        positions = [gate.index(item) for item in suites]
        self.assertEqual(positions, sorted(positions))
        self.assertEqual(len(set(positions)), len(positions))
        for suite in suites[:-1]:
            with self.subTest(suite=suite):
                self.assertIn(b"-I", suite)
                self.assertIn(b"-W error", suite)
        self.assertEqual(gate.count(suites[-1]), 1)

    def test_framework_recovery_6_gate_rejects_missing_duplicate_or_reordered_suites(
        self,
    ) -> None:
        verify = _load_verify()
        gate = verify._framework_recovery_6_expected_gate_payload()
        fr_0006 = (
            b'"$PYTHON3" -B -I -W error '
            b"tools/release/test_verify_current_audit_fr_0006.py\n"
        )
        verifier = (
            b'"$PYTHON3" -B -I -W error '
            b"tools/release/verify-current-audit.py\n"
        )
        missing = _mutate_source_once(gate, fr_0006, b"")
        duplicate = _mutate_source_once(gate, fr_0006, fr_0006 + fr_0006)
        reordered = _mutate_source_once(
            gate, fr_0006 + verifier, verifier + fr_0006
        )
        for mutation in (missing, duplicate, reordered):
            with self.subTest(size=len(mutation)):
                self.assertNotEqual(mutation, gate)
                self.assertTrue(
                    mutation.count(fr_0006) != 1
                    or mutation.index(fr_0006) > mutation.index(verifier)
                )

    def test_framework_recovery_6_gate_runs_fr_0005_compatibility_exactly_once(
        self,
    ) -> None:
        verify = _load_verify()
        gate = verify._framework_recovery_6_expected_gate_payload()
        invocation = (
            b'"$PYTHON3" -B -I -W error \\\n'
            b'  "$FR5_COMPAT_DIR/test_verify_current_audit_fr_0005.py"\n'
        )
        self.assertEqual(gate.count(invocation), 1)
        self.assertEqual(
            gate.count(
                b"/usr/bin/git cat-file blob "
                b"98a71c9c83f9ff305a431b5a1ed473113b65b7a6"
            ),
            1,
        )
        self.assertEqual(gate.count(b"FR5_COMPAT_DIR=\"$(/usr/bin/mktemp"), 1)
        self.assertNotIn(
            b'"$PYTHON3" -B -I -W error '
            b"tools/release/test_verify_current_audit_fr_0005.py\n",
            gate,
        )

    def test_framework_recovery_6_preserves_all_prior_test_suites(self) -> None:
        verify = _load_verify()
        prior = (
            "tools/release/test_verify_current_audit.py",
            verify.FRAMEWORK_RECOVERY_2_TEST_PATH,
            verify.FRAMEWORK_RECOVERY_3_TEST_PATH,
            verify.FRAMEWORK_RECOVERY_3_RESOURCE_TEST_PATH,
            verify.FRAMEWORK_RECOVERY_4_TEST_PATH,
            verify.FRAMEWORK_RECOVERY_5_TEST_PATH,
        )
        self.assertEqual(len(prior), 6)
        self.assertEqual(len(set(prior)), 6)
        self.assertTrue(set(prior).issubset(set(verify.FRAMEWORK_RECOVERY_6_PRESERVED_PATHS)))
        gate = verify._framework_recovery_6_expected_gate_payload()
        self.assertIn(b"test_verify_current_audit.py", gate)
        self.assertIn(b"test_verify_current_audit_fr_0002.py", gate)
        self.assertIn(b"test_verify_current_audit_fr_0003.py", gate)
        self.assertIn(b"test_current_audit_resource_profile.py", gate)
        self.assertIn(b"test_verify_current_audit_fr_0004.py", gate)
        self.assertIn(b"test_verify_current_audit_fr_0005.py", gate)

    def test_framework_recovery_6_test_contract_requires_exact_discovery_count(
        self,
    ) -> None:
        verify = _load_verify()
        payload = Path(__file__).read_bytes()
        ids = verify._discover_unittest_test_ids(
            payload, verify.FRAMEWORK_RECOVERY_6_TEST_PATH, strict_runtime=True
        )
        self.assertEqual(len(ids), 56)
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(set(ids), REQUIRED_TEST_IDS)
        self.assertEqual(
            hashlib.sha256(("\n".join(sorted(ids)) + "\n").encode("utf-8")).hexdigest(),
            "d448898701a6cd7e4415d8bc383bd78456ab66645b9fe98171a474e51de179e8",
        )
        self.assertEqual(
            verify.FRAMEWORK_RECOVERY_6_REQUIRED_TEST_IDS_SHA256,
            "d448898701a6cd7e4415d8bc383bd78456ab66645b9fe98171a474e51de179e8",
        )

    def test_framework_recovery_6_local_markers_require_every_suite(self) -> None:
        verify = _load_verify()
        counts = (11, 22, 33, 44, 55, 66, 77)
        contract = {
            key: {"count": count}
            for key, count in zip(
                (
                    "legacy",
                    "fr_0002",
                    "fr_0003",
                    "resource",
                    "fr_0004",
                    "fr_0005",
                    "fr_0006",
                ),
                counts,
                strict=True,
            )
        }
        direct = (
            b"=== CURRENT_AUDIT_GATE ===\n$ tools/release/current-audit-gate.sh\n"
            + b"".join(
                f"Ran {count} tests in 0.001s\nOK\n".encode("ascii")
                for count in counts
            )
            + b"verify-current-audit: OK\n"
        )
        p0 = (
            b"=== P0R_EXIT_GATE ===\n$ tools/p0r-exit-gate.sh\n"
            + b"".join(
                f"Ran {count} tests in 0.001s\n".encode("ascii")
                for count in (*counts, counts[3])
            )
            + b"OK\n" * 14
            + b"verify-current-audit: OK\n"
            + b"P0-R exit gate: 30 passed, 0 failed\n"
        )
        resource = (
            b"=== RESOURCE_PROFILE ===\n"
            b"$ python3 -I tools/release/current-audit-resource-profile.py\n"
        )
        payload = direct + p0 + resource
        verify._framework_recovery_6_verify_local_markers(
            payload, test_contract=contract
        )
        missing = payload.replace(b"Ran 77 tests in 0.001s\nOK\n", b"", 1)
        with self.assertRaisesRegex(
            verify.CurrentAuditError,
            "CURRENT_AUDIT_FRAMEWORK_RECOVERY_6_LOCAL_LOG",
        ):
            verify._framework_recovery_6_verify_local_markers(
                missing, test_contract=contract
            )

    def test_framework_recovery_6_wrapper_accepts_epochs_2_through_7(self) -> None:
        verify = _load_verify()
        source = _function_source(verify, "_verify_post_activation_gate_retention")
        self.assertIn("framework_epoch not in {2, 3, 4, 5, 6, 7}", source)
        self.assertIn("7: _framework_recovery_6_expected_gate_payload()", source)
        self.assertIn("6: _framework_recovery_5_expected_gate_payload()", source)
        with self.assertRaisesRegex(
            verify.CurrentAuditError,
            "CURRENT_AUDIT_POST_ACTIVATION_EPOCH_INVALID",
        ):
            with mock.patch.object(verify, "_git_file"):
                verify._verify_post_activation_gate_retention(
                    Path("."), "a" * 40, framework_epoch=8
                )

    def test_framework_recovery_6_history_requires_exact_position(self) -> None:
        verify = _load_verify()
        plan = {"state": {"status": "PENDING_QUALIFICATION"}}
        with mock.patch.object(
            verify, "_verify_framework_recovery_6_repair", return_value=plan
        ):
            result = verify._verify_framework_recovery_6_history(
                Path("."), _history_chain("R"), framework_commit="f" * 40
            )
        self.assertEqual(result["repair_commit"], "6" * 40)
        self.assertEqual(result["state"], "PENDING_QUALIFICATION")
        bad = _history_chain("R")
        bad.insert(0, "a" * 40)
        with self.assertRaisesRegex(
            verify.CurrentAuditError, "CURRENT_AUDIT_FRAMEWORK_RECOVERY_6_POSITION"
        ):
            verify._verify_framework_recovery_6_history(
                Path("."), bad, framework_commit="f" * 40
            )

    def test_framework_recovery_6_history_states_are_contiguous(self) -> None:
        verify = _load_verify()
        plan = {"retired_recovery": {"state_after": "ABORTED_BEFORE_QUALIFICATION"}}
        qualification = {"evidence_catalog": []}
        with (
            mock.patch.object(
                verify, "_verify_framework_recovery_6_repair", return_value=plan
            ),
            mock.patch.object(
                verify,
                "_verify_framework_recovery_6_qualification",
                return_value=qualification,
            ),
            mock.patch.object(
                verify, "_verify_framework_recovery_6_activation", return_value={}
            ),
        ):
            r_state = verify._verify_framework_recovery_6_history(
                Path("."), _history_chain("R"), framework_commit="f" * 40
            )
            q_state = verify._verify_framework_recovery_6_history(
                Path("."), _history_chain("Q"), framework_commit="f" * 40
            )
            a_state = verify._verify_framework_recovery_6_history(
                Path("."), _history_chain("A"), framework_commit="f" * 40
            )
        self.assertEqual(
            [r_state["state"], q_state["state"], a_state["state"]],
            ["PENDING_QUALIFICATION", "QUALIFIED_PENDING_ACTIVATION", "ACTIVE"],
        )
        self.assertEqual(
            [r_state["active_framework_epoch"], q_state["active_framework_epoch"], a_state["active_framework_epoch"]],
            [2, 2, 7],
        )
        self.assertEqual(
            [r_state["successor_transitions_allowed"], q_state["successor_transitions_allowed"], a_state["successor_transitions_allowed"]],
            [False, False, True],
        )

    def test_framework_recovery_6_retires_fr_0005_without_qualification(
        self,
    ) -> None:
        verify = _load_verify()
        chain = _history_chain("R")
        repair = {"state": {"status": "PENDING_QUALIFICATION"}}
        metadata = {
            "parent": PARENT_COMMIT,
            "subject": REPAIR_SUBJECT,
        }
        with (
            mock.patch.object(
                verify, "_verify_framework_recovery_5_repair", return_value=repair
            ),
            mock.patch.object(
                verify, "_verify_framework_recovery_6_repair", return_value={}
            ) as authenticate,
            mock.patch.object(
                verify, "_commit_metadata", side_effect=[metadata, metadata]
            ),
            mock.patch.object(verify, "_git_path_exists", return_value=False),
        ):
            result = verify._verify_framework_recovery_5_history(
                Path("."), chain, framework_commit="f" * 40
            )
        self.assertEqual(result["state"], "ABORTED_BEFORE_QUALIFICATION")
        self.assertEqual(result["retirement_commit"], "6" * 40)
        self.assertIsNone(result["qualification_commit"])
        self.assertIsNone(result["activation_commit"])
        authenticate.assert_called_once()

    def test_framework_recovery_6_retirement_absorbs_no_fr_0005_q_or_a(
        self,
    ) -> None:
        verify = _load_verify()
        chain = _history_chain("Q")
        retirement = {"parent": PARENT_COMMIT, "subject": REPAIR_SUBJECT}
        later = {
            "parent": "6" * 40,
            "subject": verify.FRAMEWORK_RECOVERY_5_QUALIFICATION_SUBJECT,
        }
        with (
            mock.patch.object(
                verify, "_verify_framework_recovery_5_repair", return_value={}
            ),
            mock.patch.object(
                verify, "_verify_framework_recovery_6_repair", return_value={}
            ),
            mock.patch.object(
                verify,
                "_commit_metadata",
                side_effect=[retirement, retirement, later],
            ),
            mock.patch.object(verify, "_git_path_exists", return_value=False),
            self.assertRaisesRegex(
                verify.CurrentAuditError,
                "CURRENT_AUDIT_FRAMEWORK_RECOVERY_5_RETIREMENT_ABSORPTION",
            ),
        ):
            verify._verify_framework_recovery_5_history(
                Path("."), chain, framework_commit="f" * 40
            )

    def test_framework_recovery_6_successor_requires_activation(self) -> None:
        verify = _load_verify()
        chain = _history_chain("A") + ["9" * 40]
        with self.assertRaisesRegex(
            verify.CurrentAuditError,
            "CURRENT_AUDIT_FRAMEWORK_RECOVERY_6_SUCCESSOR_BEFORE_ACTIVATION",
        ):
            verify._framework_recovery_6_verify_successor_guard(
                chain,
                27,
                repair_commit="6" * 40,
                activation_commit="8" * 40,
                recovery_transition=None,
            )
        delayed_activation = chain[:28] + ["a" * 40] + chain[28:]
        with self.assertRaisesRegex(
            verify.CurrentAuditError,
            "CURRENT_AUDIT_FRAMEWORK_RECOVERY_6_SUCCESSOR_BEFORE_ACTIVATION",
        ):
            verify._framework_recovery_6_verify_successor_guard(
                delayed_activation,
                28,
                repair_commit="6" * 40,
                activation_commit="8" * 40,
                recovery_transition=None,
            )
        verify._framework_recovery_6_verify_successor_guard(
            chain,
            27,
            repair_commit="6" * 40,
            activation_commit="8" * 40,
            recovery_transition={"stage": "qualification"},
        )
        verify._framework_recovery_6_verify_successor_guard(
            chain,
            29,
            repair_commit="6" * 40,
            activation_commit="8" * 40,
            recovery_transition=None,
        )

    def test_framework_recovery_6_forward_replay_has_pre_activation_guard(
        self,
    ) -> None:
        verify = _load_verify()
        fixture = _protocol_fixture(verify)
        source = _function_source(verify, "_verify_forward_protocol_history")
        self.assertIn("_framework_recovery_6_verify_successor_guard", source)
        self.assertIn("recovery_5_terminal_commit", source)
        self.assertIn('descriptor.get("retirement_commit")', source)
        self.assertIn("framework_epoch = (", source)
        self.assertIn("if recovery_6_repair_commit is not None", source)
        self.assertIn("chain.index(recovery_6_repair_commit) <= position", source)
        self.assertEqual(fixture["claims"]["active_framework_epoch"], 2)
        self.assertFalse(fixture["claims"]["successor_transitions_allowed"])
        self.assertEqual(fixture["registry"]["framework_epoch"], 7)

    def test_framework_recovery_6_framework_history_requires_exact_retirement_relationship(
        self,
    ) -> None:
        verify = _load_verify()
        source = _function_source(verify, "_verify_framework_history")
        self.assertIn('recovery_5["state"] != "ABORTED_BEFORE_QUALIFICATION"', source)
        self.assertIn('recovery_5["qualification_commit"] is not None', source)
        self.assertIn('recovery_5["activation_commit"] is not None', source)
        self.assertIn('recovery_5["retirement_commit"] != recovery_6["repair_commit"]', source)
        self.assertIn("CURRENT_AUDIT_FRAMEWORK_RECOVERY_6_RETIREMENT_INVALID", source)
        self.assertIn("if recovery_6_commit is not None", source)
        self.assertIn("framework_epoch=(", source)

    def test_framework_recovery_6_source_retention_projects_all_recoveries_and_rejects_drift(
        self,
    ) -> None:
        verify = _load_verify()
        current = Path(verify.__file__).read_bytes()
        parent = verify._git_file(
            _repo(), PARENT_COMMIT, "tools/release/verify-current-audit.py"
        )
        verify._framework_recovery_6_validate_source_compatibility(parent, current)
        self.assertEqual(
            verify._framework_recovery_6_unwrap_source_layer(_repo(), current),
            parent,
        )
        for name in (
            "_framework_recovery_2_source_retention_manifest",
            "_framework_recovery_3_source_retention_manifest",
            "_framework_recovery_4_source_retention_manifest",
            "_framework_recovery_5_source_retention_manifest",
        ):
            with self.subTest(name=name):
                self.assertIn(
                    "_framework_recovery_6_unwrap_source_layer",
                    _function_source(verify, name),
                )
        sha_source = _function_source(verify, "_sha256").encode("utf-8")
        mutations = (
            _mutate_source_once(
                current,
                b"return hashlib.sha256(payload).hexdigest()",
                b"return hashlib.sha256(payload + b'x').hexdigest()",
            ),
            _mutate_source_once(
                current,
                b"MAX_JSON_DEPTH = 64",
                b"MAX_JSON_DEPTH = 63",
            ),
            _mutate_source_once(
                current,
                b"import ast\n",
                b"import ast\nimport fractions\n",
            ),
            _mutate_source_once(current, sha_source, b""),
            _mutate_source_once(
                current,
                sha_source,
                sha_source + b"\n\ndef _fr_0006_undeclared():\n    return None",
            ),
            _mutate_source_once(
                current,
                b"MAX_JSON_BYTES = 256 * 1024",
                b"MAX_JSON_BYTES = 256 * 1024\nFR_0006_UNDECLARED = 1",
            ),
            _mutate_source_once(
                current,
                b'FRAMEWORK_RECOVERY_6_PARENT = "5c0131d8b6a1a64d'
                b'9465a1eb5f7039dc72d8c41e"',
                b'FRAMEWORK_RECOVERY_6_PARENT = "6c0131d8b6a1a64d9465a1eb5f7039dc72d8c41e"',
            ),
            _mutate_source_once(
                current,
                b'"""Verify the current-head Haldir 0.9 audit cut without network access."""',
                b'"""Verify the current-head Haldir 0.9 audit cut without network access.""" ',
            ),
        )
        for mutation in mutations:
            with self.subTest(digest=hashlib.sha256(mutation).hexdigest()):
                with self.assertRaisesRegex(
                    verify.CurrentAuditError,
                    "CURRENT_AUDIT_FRAMEWORK_RECOVERY_6_SOURCE_COMPATIBILITY",
                ):
                    verify._framework_recovery_6_validate_source_compatibility(
                        parent, mutation
                    )

    def test_framework_recovery_6_test_source_ast_and_discovery_are_strict(
        self,
    ) -> None:
        verify = _load_verify()
        payload = Path(__file__).read_bytes()
        tree = verify._framework_recovery_6_validate_test_source(
            payload, verify.FRAMEWORK_RECOVERY_6_TEST_PATH
        )
        self.assertIsInstance(tree, ast.Module)
        ids = verify._discover_unittest_test_ids(
            payload, verify.FRAMEWORK_RECOVERY_6_TEST_PATH, strict_runtime=True
        )
        self.assertEqual(set(ids), REQUIRED_TEST_IDS)
        self.assertEqual(len(ids), 56)
        self.assertEqual(
            len(
                [
                    node
                    for node in tree.body
                    if isinstance(node, ast.FunctionDef)
                ]
            ),
            18,
        )
        self.assertEqual(
            len([node for node in tree.body if isinstance(node, ast.ClassDef)]),
            1,
        )
        self.assertEqual(
            len([node for node in tree.body if isinstance(node, ast.If)]), 1
        )
        repo_definition = b"def _repo()" + b" -> Path:"
        repo_return = b"    return Path(__file__)" + b".resolve().parents[2]"
        identity_definition = (
            b"    def test_framework_recovery_6_identity_"
            + b"constants_are_exact(self) -> None:"
        )
        parent_bytes_definition = (
            b"    def test_framework_recovery_6_parent_"
            + b"bytes_are_pinned(self) -> None:"
        )
        class_definition = (
            b"class FrameworkRecovery6Tests(" + b"unittest.TestCase):"
        )
        main_guard = b'if __name__ == "__' + b'main__":\n    unittest.main()'
        parent_tree_assignment = (
            b'PARENT_TREE = "eb20644bccf64c42998ab2c5e340165fb'
            + b'4886142"'
        )
        mutations = (
            _mutate_source_once(
                payload,
                b'"""Test the FR-0006 reproduction-evidence '
                b'provenance recovery."""',
                b'"""Changed FR-0006 module documentation."""',
            ),
            _mutate_source_once(payload, b"import inspect\n", b"import math\n"),
            _mutate_source_once(
                payload,
                b"import ast\nimport copy\n",
                b"import copy\nimport ast\n",
            ),
            _mutate_source_once(
                payload, b"import ast\n", b"import ast as syntax_tree\n"
            ),
            _mutate_source_once(payload, b"import inspect\n", b""),
            _mutate_source_once(
                payload,
                parent_tree_assignment,
                b"PARENT_TREE = hashlib.sha256(b'x').hexdigest()",
            ),
            _mutate_source_once(
                payload,
                parent_tree_assignment,
                parent_tree_assignment + b"\nEXTRA_ASSIGNMENT = 1",
            ),
            _mutate_source_once(
                payload,
                b"def _mutate_" + b"source_once(",
                b"def _mutate_source_twice(",
            ),
            _mutate_source_once(
                payload,
                repo_definition,
                b'@mock.patch("unused")\n' + repo_definition,
            ),
            _mutate_source_once(
                payload, repo_definition, b"async " + repo_definition
            ),
            _mutate_source_once(
                payload,
                repo_return,
                b"    def nested_helper():\n        return None\n" + repo_return,
            ),
            _mutate_source_once(
                payload,
                class_definition,
                b"def _extra_helper():\n    return None\n\n" + class_definition,
            ),
            _mutate_source_once(
                payload,
                b"def test_framework_recovery_6_identity_"
                + b"constants_are_exact(",
                b"def test_framework_recovery_6_identity_constants_changed(",
            ),
            _mutate_source_once(
                payload,
                identity_definition,
                b"    @unittest.expectedFailure\n" + identity_definition,
            ),
            _mutate_source_once(
                payload,
                identity_definition,
                b"    async " + identity_definition.removeprefix(b"    "),
            ),
            _mutate_source_once(
                payload, parent_bytes_definition, identity_definition
            ),
            _mutate_source_once(
                payload,
                b'class FrameworkRecovery6Tests('
                + b'unittest.TestCase):',
                b'class FrameworkRecovery6Tests(object):',
            ),
            _mutate_source_once(
                payload,
                main_guard,
                b"class ExtraTests(unittest.TestCase):\n    pass\n\n" + main_guard,
            ),
            _mutate_source_once(
                payload,
                repo_return,
                b"    eval('1')\n" + repo_return,
            ),
            _mutate_source_once(
                payload,
                repo_return,
                b"    sys.path = []\n" + repo_return,
            ),
            _mutate_source_once(
                payload,
                b'if __name__ == "__' + b'main__":',
                b'if __name__ == "changed":',
            ),
            _mutate_source_once(
                payload, main_guard, main_guard + b"\n\n" + main_guard
            ),
        )
        for mutation in mutations:
            with self.subTest(digest=hashlib.sha256(mutation).hexdigest()):
                with self.assertRaises(verify.CurrentAuditError):
                    verify._framework_recovery_6_validate_test_source(
                        mutation, verify.FRAMEWORK_RECOVERY_6_TEST_PATH
                    )


if __name__ == "__main__":
    unittest.main()
