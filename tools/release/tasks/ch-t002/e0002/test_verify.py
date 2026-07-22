#!/usr/bin/env python3
"""Pure and bounded tests for the independent CH-T002 registered verifier."""

from __future__ import annotations

import copy
import csv
import base64
import contextlib
import hashlib
import importlib.util
import io
import json
import math
import os
import subprocess
import sys
import tempfile
import unittest
import zipfile
from collections import Counter
from pathlib import Path
from unittest import mock


PRODUCT_SHA256 = (
    "76f78d6b5279bf9f1090974d55b4b972a4398c70d8cd353cab6462a75712c08c"
)
EXPECTED_MANIFEST_RECONCILIATION_KEYS = {
    "base_partition",
    "content_identity_mismatches",
    "counts",
    "current_freeze_regular_blobs",
    "current_subjects",
    "delta",
    "digests",
    "duplicate_current_paths",
    "implementation_boundary",
    "invalid_removed_tombstones",
    "missing_current_paths",
    "overlay_input",
    "removed_tombstones",
    "result",
    "scope_inclusion",
    "uncovered_freeze_tree_subjects",
}


def verifier_module():
    module_name = "ch_t002_registered_verifier"
    cached = sys.modules.get(module_name)
    if cached is not None:
        return cached
    path = Path(__file__).with_name("verify.py")
    spec = importlib.util.spec_from_file_location(module_name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(module_name, None)
        raise
    return module


def product_module():
    module_name = "ch_t002_exact_product"
    cached = sys.modules.get(module_name)
    if cached is not None:
        return cached
    product_root = Path(
        os.environ.get(
            "HALDIR_CH_T002_PRODUCT_ROOT", Path(__file__).resolve().parents[5]
        )
    )
    path = product_root / verifier_module().PRODUCT_TOOL
    payload = path.read_bytes()
    if hashlib.sha256(payload).hexdigest() != PRODUCT_SHA256:
        raise AssertionError("final product byte identity drifted")
    spec = importlib.util.spec_from_file_location(module_name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(module_name, None)
        raise
    return module


def render_ledger(rows):
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(
        stream,
        fieldnames=verifier_module().FIELDS,
        lineterminator="\n",
        extrasaction="raise",
    )
    writer.writeheader()
    writer.writerows(rows)
    return stream.getvalue().encode("utf-8")


def base_row(path: str) -> dict[str, str]:
    row = {field: "" for field in verifier_module().FIELDS}
    row.update(
        {
            "schema_version": "1.0.0",
            "source_commit": "1" * 40,
            "source_tree": "2" * 40,
            "object_format": "sha1",
            "ignored_policy": "reject",
            "inventory_digest": "3" * 64,
            "inventory_rows": "4",
            "source_inventory_digest": "4" * 64,
            "index_inventory_digest": "5" * 64,
            "untracked_inventory_digest": "6" * 64,
            "ignored_inventory_digest": "7" * 64,
            "filesystem_inventory_digest": "8" * 64,
            "filesystem_entries": "4",
            "ledger_self_path": verifier_module().LEDGER_PATH,
            "path": path,
            "source_tracked": "true",
            "source_git_mode": "100644",
            "source_object_type": "blob",
            "source_git_blob_id": "9" * 40,
            "source_sha256": "a" * 64,
            "source_bytes": "7",
            "source_lines": "1",
            "source_content_kind": "TEXT_UTF8",
            "index_tracked": "true",
            "index_git_mode": "100644",
            "index_git_blob_id": "b" * 40,
            "index_flags": "NONE",
            "index_sha256": "c" * 64,
            "index_bytes": "7",
            "index_lines": "1",
            "index_content_kind": "TEXT_UTF8",
            "source_index_state": "IDENTICAL",
            "current_scope": "TRACKED",
            "current_fs_type": "REGULAR",
            "current_fs_mode": "100644",
            "current_git_blob_id": "b" * 40,
            "current_sha256": "c" * 64,
            "current_bytes": "7",
            "current_lines": "1",
            "current_content_kind": "TEXT_UTF8",
            "worktree_state": "CLEAN_AGAINST_INDEX",
            "generated_candidate_reason": "NONE_OBSERVED_REVIEW_REQUIRED",
            "category": "REPOSITORY_SUPPORT",
            "provenance_class": "DECLARED_SOURCE_COMMIT_AND_CURRENT_VIEW",
            "git_blob_id": "b" * 40,
            "sha256": "c" * 64,
            "bytes": "7",
            "lines": "1",
            "language": "TEXT",
            "format": "TEXT_UTF8",
            "generated": "UNKNOWN",
            "public_surface": "UNKNOWN",
            "security_critical": "UNKNOWN",
            "science_critical": "UNKNOWN",
            "authority_critical": "UNKNOWN",
            "provenance_review_status": "UNREVIEWED",
            "license_review_status": "UNREVIEWED",
            "reviewer": "UNASSIGNED",
            "review_status": "UNREVIEWED",
        }
    )
    return row


def ledger_fixture():
    paths = [
        "a.txt",
        verifier_module().LEDGER_PATH,
        "b.bin",
        "tools/release/current-file-review-ledger.py",
    ]
    rows = [base_row(path) for path in paths]
    rows[0]["language"] = "TEXT"
    rows[1].update(
        {
            "index_tracked": "false",
            "index_git_mode": "",
            "index_git_blob_id": "",
            "index_flags": "",
            "index_sha256": "",
            "index_bytes": "",
            "index_lines": "0",
            "index_content_kind": "SELF_REFERENTIAL_CONTENT_EXCLUDED",
            "source_index_state": "SOURCE_PRESENT_SELF_INDEX_EXCLUDED",
            "current_scope": "LEDGER_SELF",
            "current_fs_type": "LEDGER_SELF",
            "current_fs_mode": "",
            "current_git_blob_id": "",
            "current_sha256": "",
            "current_bytes": "",
            "current_lines": "0",
            "current_content_kind": "SELF_REFERENTIAL_CONTENT_EXCLUDED",
            "worktree_state": "SELF_REFERENTIAL_CONTENT_EXCLUDED",
            "git_blob_id": "",
            "sha256": "",
            "bytes": "",
            "lines": "",
            "language": "CSV",
            "format": "SELF_REFERENTIAL_CSV",
            "generated": "YES",
            "generator": "tools/release/current-file-review-ledger.py",
        }
    )
    rows[2].update(
        {
            "current_git_blob_id": "d" * 40,
            "current_sha256": "e" * 64,
            "current_bytes": "4097",
            "current_lines": "0",
            "current_content_kind": "BINARY",
            "git_blob_id": "d" * 40,
            "sha256": "e" * 64,
            "bytes": "4097",
            "lines": "0",
            "language": "BINARY_DATA",
            "format": "BINARY",
            "generated": "NO",
        }
    )
    rows[3].update(
        {
            "current_git_blob_id": "f" * 40,
            "current_sha256": "0" * 64,
            "current_bytes": "20",
            "current_lines": "2",
            "git_blob_id": "f" * 40,
            "sha256": "0" * 64,
            "bytes": "20",
            "lines": "2",
            "language": "PYTHON",
            "format": "PYTHON",
            "generated": "NO",
        }
    )
    completed = copy.deepcopy(rows)
    reviewers = (
        "lane-01@example.invalid",
        "lane-02@example.invalid",
        "lane-03@example.invalid",
    )
    for index, row in enumerate(completed):
        if row["generated"] == "UNKNOWN":
            row["generated"] = "NO"
        row.update(
            {
                "public_surface": "YES" if index == 0 else "NO",
                "security_critical": "YES" if index in {2, 3} else "NO",
                "science_critical": "NO",
                "authority_critical": "YES" if index == 1 else "NO",
                "provenance_review_status": "CONFIRMED",
                "provenance_evidence": "CH-T002-E08",
                "license_review_status": "APPROVED" if index != 1 else "NOT_APPLICABLE",
                "license_expression": "Apache-2.0 OR MIT"
                if index != 1
                else "NOT_APPLICABLE",
                "license_evidence": "CH-T002-E08" if index != 1 else "",
                "reviewer": reviewers[index % 3],
                "review_status": "REVIEWED",
                "requirements": "CH-T002-N01",
                "assumptions": "CH-T002-N01",
                "defects": "NONE",
                "tests": "TEST_PTR",
                "evidence": "CH-T002-E08",
                "disposition": "ACCEPTED",
                "completed_at": "2026-07-22T00:00:00Z",
            }
        )
    base_payload = render_ledger(rows)
    completed_payload = render_ledger(completed)
    return rows, completed, base_payload, completed_payload, set(reviewers)


def classification_records(rows):
    records = {}
    for row in rows:
        records[row["path"]] = {
            "authority_critical": row["authority_critical"],
            "generated": row["generated"],
            "generator": row["generator"],
            "license_expression": row["license_expression"],
            "license_review_status": row["license_review_status"],
            "path": row["path"],
            "provenance_review_status": row["provenance_review_status"],
            "public_surface": row["public_surface"],
            "rule_ids": [
                "PUB_YES_TEST" if row["public_surface"] == "YES" else "PUB_NO_TEST",
                "SEC_YES_TEST" if row["security_critical"] == "YES" else "SEC_NO_TEST",
                "SCI_YES_TEST" if row["science_critical"] == "YES" else "SCI_NO_TEST",
                "AUTH_YES_TEST"
                if row["authority_critical"] == "YES"
                else "AUTH_NO_TEST",
                "GEN_YES_TEST" if row["generated"] == "YES" else "GEN_NO_TEST",
                "LIC_TEST",
            ],
            "science_critical": row["science_critical"],
            "security_critical": row["security_critical"],
            "source_basis": verifier_module().CURRENT_A_SOURCE_BASIS,
        }
    return records


def validate_fixture(base_payload, completed_payload, reviewers):
    _base_rows, expected_rows, _base, _completed, _reviewers = ledger_fixture()
    patches = (
        mock.patch.object(verifier_module(), "EXPECTED_LEDGER_ROWS", 4),
        mock.patch.object(
            verifier_module(),
            "CH_T001_LEDGER_SHA256",
            hashlib.sha256(base_payload).hexdigest(),
        ),
        mock.patch.object(
            verifier_module(),
            "CH_T001_LEDGER_OBJECT_ID",
            verifier_module()._git_blob_id(base_payload),
        ),
    )
    with patches[0], patches[1], patches[2]:
        return verifier_module().validate_completed_ledger(
            base_payload,
            completed_payload,
            reviewer_principals=reviewers,
            classification_by_path=classification_records(expected_rows),
        )


def fake_key(seed: int) -> tuple[str, str]:
    algorithm = b"ssh-ed25519"
    key = bytes([seed]) * 32
    blob = (
        len(algorithm).to_bytes(4, "big")
        + algorithm
        + len(key).to_bytes(4, "big")
        + key
    )
    encoded = base64.b64encode(blob).decode("ascii")
    public_key = f"ssh-ed25519 {encoded}"
    return public_key, verifier_module()._public_key_fingerprint(public_key)


def qualification_replacement_commands():
    python = "/opt/homebrew/bin/python3.14 -B -I -P"
    packet = (
        "--repo . --implementation-commit SIGNED_I_COMMIT "
        f"--ledger {verifier_module().LEDGER_PATH} "
        f"--overlay {verifier_module().OVERLAY_PATH} "
        "--output-dir RETAINED_PACKET_DIRECTORY "
        f"--reviewer-registry {verifier_module().FREEZE_PATH}"
    )
    return [
        f"{python} {verifier_module().PRODUCT_TESTS}",
        f"{python} {verifier_module().PRODUCT_TOOL} render {packet}",
        f"{python} {verifier_module().PRODUCT_TOOL} verify {packet}",
        f"{python} {verifier_module().REGISTERED_TESTS_PATH}",
        (
            f"{python} {verifier_module().VERIFIER_PATH} --repo . "
            "--freeze-commit SIGNED_F_COMMIT --implementation-commit "
            "SIGNED_I_COMMIT --inventory-only"
        ),
        f"{python} {verifier_module().REGISTERED_TESTS_PATH} -k reject",
        f"{python} {verifier_module().REGISTERED_TESTS_PATH} -k technique_",
    ]


def freeze_fixture():
    def requirements(specs, paths):
        return [
            {
                "id": identifier,
                "kind": kind,
                "path": paths[identifier],
                "max_bytes": 2 * 1024 * 1024
                if kind == "FULL_LOCKED_CI_LOG_ARCHIVE"
                else 4 * 1024 * 1024,
            }
            for identifier, kind, _name in specs
        ]

    registry = []
    for index, (identifier, kind, name) in enumerate(verifier_module().REVIEW_SPECS, 1):
        key, fingerprint = fake_key(index)
        classification = (
            "INDEPENDENT_AUTOMATED" if index <= 3 else "AUTOMATED_LEAD_SUPPORT"
        )
        registry.append(
            {
                "requirement_id": identifier,
                "kind": kind,
                "path": verifier_module().REVIEW_PATHS[identifier],
                "reviewer": {
                    "name": f"Reviewer {index}",
                    "principal": f"lane-{index:02d}@example.invalid",
                    "classification": classification,
                    "organization": "Automated Technical Review",
                },
                "public_key": key,
                "key_fingerprint": fingerprint,
                "trust_basis": "SOURCE_SIGNER_ASSERTED_KEY_FROZEN_IN_SIGNED_F",
            }
        )
    controls = [
        {
            "id": f"CH-T002-N{index:02d}",
            "statement": binding[0],
            "accepted_test_id": binding[1],
            "rejected_test_id": binding[2],
        }
        for index, binding in enumerate(verifier_module().NORMATIVE_CONTROL_BINDINGS, 1)
    ]
    counterfactuals = [
        {
            "id": f"CH-T002-CF{index:02d}",
            "statement": binding[0],
            "accepted_test_id": binding[1],
            "rejected_test_id": binding[2],
        }
        for index, binding in enumerate(verifier_module().COUNTERFACTUAL_BINDINGS, 1)
    ]
    lenses = [
        {"id": f"L{index:02d}", "question": f"Review lens {index:02d}?"}
        for index in range(1, 21)
    ]
    source_record_sha256 = verifier_module().SOURCE_RECORD_SHA256
    return {
        "schema_version": "1.0.0",
        "task_id": verifier_module().TASK_ID,
        "epoch": verifier_module().EPOCH,
        "release_target": verifier_module().RELEASE_TARGET,
        "author": copy.deepcopy(verifier_module().AUTHOR),
        "persistent_identifier": None,
        "effective_on": "SIGNED_COMMIT_FIRST_CONTAINING_EXACT_FREEZE_AND_REGISTRATION",
        "task_identity": copy.deepcopy(verifier_module().EXPECTED_TASK_IDENTITY),
        "handoff_task_contract": {
            "source_task_id": "T002",
            "lead_review_required": True,
            "source_record_sha256": source_record_sha256,
            "preconditions": ["The CH-T001 ledger is immutable."],
            "procedure": ["Review every frozen subject."],
            "mandatory_counterfactuals": [
                binding[0] for binding in verifier_module().COUNTERFACTUAL_BINDINGS
            ],
            "required_evidence": list(verifier_module().EVIDENCE_PATHS),
            "completion_rule": "Every subject has exact review evidence.",
            "twenty_lenses": lenses,
        },
        "prior_state": {
            "verified_prefix": 2,
            "active_claims": {
                "active_claims": [],
                "release_qualified_claims": [],
                "removed_claims": [],
                "non_claimed_claims": [],
                "narrowed_claims": [],
            },
        },
        "implementation_plan": copy.deepcopy(verifier_module().EXPECTED_I_DIFF),
        "empty_implementation_reason": None,
        "affected_surface_inventory": [
            {"path": path, "planned_status": status}
            for path, status in verifier_module().EXPECTED_I_DIFF.items()
        ],
        "normative_controls": controls,
        "lead_approval": {
            "kind": "AUTOMATED_NON_HUMAN_LEAD_SUPPORT",
            "human": False,
            "external_authority": False,
            "freeze_packet_sha256": "b" * 64,
            "effective_on": "SIGNED_F_COMMIT_CONTAINING_EXACT_PREIMPLEMENTATION_PACKET",
        },
        "mandatory_counterfactuals": counterfactuals,
        "combined_attack_matrix": ["Malformed identities fail closed."],
        "handoff_command_mapping": [
            {
                "id": "CH-T002-HCM01",
                "source_command": "Run exact CH-T002 qualification commands.",
                "disposition": "REPLACED_BY_EXACT_BOUNDED_COMMANDS",
                "replacement_commands": qualification_replacement_commands(),
                "evidence_ids": list(verifier_module().EVIDENCE_PATHS),
                "task_boundary": verifier_module().TASK_ID,
                "rationale": "Exact argv records make qualification reproducible.",
            }
        ],
        "threat_model": ["Untrusted artifacts may be adversarial."],
        "misuse_resistant_interfaces": ["All parsers are bounded and canonical."],
        "qualification_evidence_requirements": requirements(
            verifier_module().EVIDENCE_SPECS, verifier_module().EVIDENCE_PATHS
        ),
        "review_requirements": requirements(
            verifier_module().REVIEW_SPECS, verifier_module().REVIEW_PATHS
        ),
        "reviewer_registry": registry,
        "activation_evidence_requirements": requirements(
            verifier_module().ACTIVATION_SPECS, verifier_module().ACTIVATION_PATHS
        ),
        "lens_questions": lenses,
        "resource_budgets": {
            "json_bytes": 256 * 1024,
            "decompressed_evidence_bytes": 4 * 1024 * 1024,
            "protocol_path_bytes": 240,
            "verifier_output_bytes_per_stream": 64 * 1024,
            "verifier_seconds": 10,
        },
        "verification_triggers": {
            "paths": list(verifier_module().EXPECTED_I_DIFF),
            "roots": [],
        },
        "claim_outcomes": [
            {
                "id": "CH-T002-O01-NO-PUBLIC-CLAIM-CHANGE",
                "claim_disposition": "NO_PUBLIC_CLAIM_CHANGE",
                "overall_status": "NO_GO",
                "active_claims": [],
                "release_qualified_claims": [],
                "removed_claims": [],
                "non_claimed_claims": [],
                "narrowed_claims": [],
                "limitations": [verifier_module().HUMAN_REVIEW_LIMITATION],
                "public_surfaces": [],
                "migration": {
                    "required": True,
                    "paths": sorted(verifier_module().EXPECTED_I_DIFF),
                    "disposition": "INTERNAL_AUDIT_ARTIFACT_MIGRATION",
                },
                "rollback": {
                    "strategy": "RESTORE_EXACT_PRIOR_ACTIVATED_TREE_ENTRIES",
                    "paths": sorted(verifier_module().EXPECTED_I_DIFF),
                    "verification": "GIT_MODE_TYPE_AND_OBJECT_IDENTITY",
                },
            }
        ],
        "qualification_path": verifier_module().QUALIFICATION_PATH,
        "activation_path": verifier_module().ACTIVATION_PATH,
        "verifier_receipt_path": verifier_module().RECEIPT_PATH,
    }


def overlay_fixture(freeze):
    classification = {
        "authority_critical": "YES",
        "generated": "YES",
        "generator": "tools/release/current-file-review-ledger.py",
        "license_expression": "NOT_APPLICABLE",
        "license_review_status": "NOT_APPLICABLE",
        "path": verifier_module().LEDGER_PATH,
        "provenance_review_status": "CONFIRMED",
        "public_surface": "NO",
        "rule_ids": [
            "PUB_NO_TEST",
            "SEC_NO_TEST",
            "SCI_NO_TEST",
            "AUTH_YES_TEST",
            "GEN_YES_TEST",
            "LIC_TEST",
        ],
        "science_critical": "NO",
        "security_critical": "NO",
        "source_basis": verifier_module().CURRENT_A_SOURCE_BASIS,
    }
    entry = {
        "bytes": 10,
        "content_kind": "TEXT_UTF8",
        "criticality": ["AUTHORITY_CRITICAL"],
        "generated": classification["generated"],
        "generator": classification["generator"],
        "git_mode": "100644",
        "git_object_id": "d" * 40,
        "language": "CSV",
        "license_expression": classification["license_expression"],
        "license_review_status": classification["license_review_status"],
        "lines": 1,
        "path": verifier_module().LEDGER_PATH,
        "provenance_review_status": classification["provenance_review_status"],
        "rule_ids": classification["rule_ids"],
        "sha256": "e" * 64,
        "source_basis": classification["source_basis"],
        "status": "LEDGER_SELF_EXTERNAL_BINDING",
    }
    entry["subject_id"] = verifier_module()._subject_id(entry)
    return {
        "schema_id": verifier_module().OVERLAY_SCHEMA_ID,
        "schema_version": "1.0.0",
        "task_id": verifier_module().TASK_ID,
        "epoch": verifier_module().EPOCH,
        "release_target": verifier_module().RELEASE_TARGET,
        "author": copy.deepcopy(verifier_module().AUTHOR),
        "persistent_identifier": None,
        "scope": {
            "classification_audit_sha256": verifier_module().CLASSIFICATION_AUDIT_SHA256,
            "classification_policy": verifier_module().CLASSIFICATION_POLICY,
            "claim_outcome": "NO_PUBLIC_CLAIM_CHANGE",
            "evidence_catalog": sorted(verifier_module().EVIDENCE_PATHS),
            "generator_catalog": ["tools/release/current-file-review-ledger.py"],
            "inclusion": verifier_module().SCOPE_INCLUSION,
            "kind": verifier_module().OVERLAY_SCOPE,
            "path_order": verifier_module().PATH_ORDER,
            "requirement_catalog": [
                item["id"] for item in freeze["normative_controls"]
            ],
            "test_catalog": sorted(
                item[field]
                for item in freeze["normative_controls"]
                for field in ("accepted_test_id", "rejected_test_id")
            ),
        },
        "base_partition": {
            "commit": verifier_module().CH_T001_IMPLEMENTATION_COMMIT,
            "tree": verifier_module().CH_T001_IMPLEMENTATION_TREE,
            "ledger_path": verifier_module().LEDGER_PATH,
            "ledger_blob_id": verifier_module().CH_T001_LEDGER_OBJECT_ID,
            "ledger_sha256": verifier_module().CH_T001_LEDGER_SHA256,
            "ledger_rows": verifier_module().EXPECTED_LEDGER_ROWS,
            "ledger_self_path": verifier_module().LEDGER_PATH,
        },
        "delta": {
            "freeze_commit": "f" * 40,
            "freeze_tree": "e" * 40,
            "name_status_sha256": "a" * 64,
        },
        "review_policy": {
            "algorithm": verifier_module().ASSIGNMENT_ALGORITHM,
            "binary_unit_bytes": verifier_module().BINARY_UNIT_BYTES,
            "coverage": verifier_module().COVERAGE_RULE,
            "critical_secondary_required": True,
            "lanes": [
                {
                    "kind": spec[1],
                    "lane": index,
                    "requirement_id": spec[0],
                    "reviewer_fingerprint": freeze["reviewer_registry"][index - 1][
                        "key_fingerprint"
                    ],
                }
                for index, spec in enumerate(verifier_module().REVIEW_SPECS[:3], 1)
            ],
            "lead_requirement_id": verifier_module().REVIEW_SPECS[3][0],
            "primary_selection": verifier_module().PRIMARY_RULE,
            "registry": {
                "path": verifier_module().FREEZE_PATH,
                "git_blob_id": "c" * 40,
                "sha256": "b" * 64,
            },
            "removed_coverage": verifier_module().REMOVAL_POLICY,
            "secondary_selection": verifier_module().SECONDARY_RULE,
            "sort_order": verifier_module().SORT_RULE,
            "text_units": verifier_module().TEXT_UNIT_RULE,
        },
        "review_classification_contract": {
            "schema_id": verifier_module().CLASSIFICATION_CONTRACT_SCHEMA_ID,
            "source_audit": {
                "schema_id": verifier_module().CLASSIFICATION_AUDIT_SCHEMA_ID,
                "sha256": verifier_module().CLASSIFICATION_AUDIT_SHA256,
                "current_a_commit": verifier_module().CLASSIFICATION_AUDIT_COMMIT,
                "current_a_tree": verifier_module().CURRENT_A_TREE,
            },
            "counts": {
                "f_additions": verifier_module()._classification_counts([]),
                "final_current_a": verifier_module()._classification_counts(
                    [classification]
                ),
                "final_f": verifier_module()._classification_counts([classification]),
                "final_historical_ledger_subjects": verifier_module()._classification_counts(
                    [classification]
                ),
                "source_current_a": verifier_module()._classification_counts(
                    [classification]
                ),
            },
            "override_policy": {
                "policy_id": verifier_module().CLASSIFICATION_OVERRIDE_POLICY_ID,
                "field_override_count": 0,
                "order": verifier_module().CLASSIFICATION_OVERRIDE_ORDER,
                "overrides": [],
                "path_count": 0,
                "paths": [],
            },
            "semantics": {
                "generated": "YES identifies production or capture by the named tracked procedure; it does not assert byte-deterministic regeneration of a historical run.",
                "primary_capture": "The 12 retained live-campaign logs are generated captures and primary runtime observations; exact Git identities preserve the observed bytes, and their license review is NOT_APPLICABLE.",
            },
            "path_order": verifier_module().PATH_ORDER,
            "records": [classification],
            "classification_set_sha256": "4" * 64,
        },
        "entries": [entry],
        "removed_paths": [],
        "implementation_boundary": {
            "content_identities_in_overlay": False,
            "paths": [
                {"path": path, "status": status}
                for path, status in verifier_module().EXPECTED_I_DIFF.items()
            ],
            "review_kind": verifier_module().IMPLEMENTATION_REVIEW_KIND,
        },
        "counts": {
            "added_entries": 0,
            "base_rows": verifier_module().EXPECTED_LEDGER_ROWS,
            "critical_subjects": 1,
            "modified_entries": 0,
            "removed_paths": 0,
            "review_subjects": 1,
            "self_entries": 1,
            "supplemental_subjects": 1,
            "unchanged_subjects": 0,
        },
        "digests": {
            "classification_set_sha256": "4" * 64,
            "entry_set_sha256": "1" * 64,
            "removed_path_set_sha256": "2" * 64,
            "subject_set_sha256": "3" * 64,
        },
    }


def overlay_context(freeze, overlay):
    registry_payload = verifier_module()._canonical_json_bytes(freeze)
    entry = {
        "mode": "100644",
        "type": "blob",
        "oid": verifier_module()._git_blob_id(registry_payload),
        "size": len(registry_payload),
    }
    overlay["review_policy"]["registry"]["git_blob_id"] = entry["oid"]
    overlay["review_policy"]["registry"]["sha256"] = hashlib.sha256(
        registry_payload
    ).hexdigest()
    return {
        "freeze": freeze,
        "freeze_commit": overlay["delta"]["freeze_commit"],
        "freeze_tree": overlay["delta"]["freeze_tree"],
        "registry_entry": entry,
        "registry_payload": registry_payload,
        "classification_by_path": {
            record["path"]: record
            for record in overlay["review_classification_contract"]["records"]
        },
    }


def minimal_classification_contract_fixture():
    overlay = overlay_fixture(freeze_fixture())
    record = copy.deepcopy(overlay["review_classification_contract"]["records"][0])
    record["generated"] = "NO"
    record["generator"] = ""
    record["rule_ids"][4] = "GEN_NO_TEST"
    contract = overlay["review_classification_contract"]
    contract["override_policy"] = {
        "policy_id": verifier_module().CLASSIFICATION_OVERRIDE_POLICY_ID,
        "field_override_count": 0,
        "order": verifier_module().CLASSIFICATION_OVERRIDE_ORDER,
        "overrides": [],
        "path_count": 0,
        "paths": [],
    }
    contract["records"] = [record]
    count = verifier_module()._classification_counts([record])
    contract["counts"] = {
        "f_additions": verifier_module()._classification_counts([]),
        "final_current_a": count,
        "final_f": count,
        "final_historical_ledger_subjects": count,
        "source_current_a": count,
    }
    digest = verifier_module()._domain_digest(
        verifier_module().CLASSIFICATION_DIGEST_DOMAIN, [record]
    )
    contract["classification_set_sha256"] = digest
    overlay = json.loads(verifier_module()._canonical_json_bytes(overlay))
    return overlay, {record["path"]: {}}, digest


def generalized_classification_contract_fixture():
    overlay, _entries, _digest = minimal_classification_contract_fixture()
    template = overlay["review_classification_contract"]["records"][0]

    def record(path):
        value = copy.deepcopy(template)
        value["path"] = path
        return value

    authority = record("a.txt")
    authority["authority_critical"] = "NO"
    authority["rule_ids"][3] = "AUTH_NO_LOCAL_REVIEW_OVERRIDE"
    authority["source_basis"] = verifier_module().CLASSIFICATION_OVERRIDE_SOURCE_BASIS
    generated = record("b.txt")
    generated["generated"] = "YES"
    generated["generator"] = "generator.py"
    generated["rule_ids"][4] = "GEN_YES_LOCAL_REVIEW_OVERRIDE"
    generated["source_basis"] = verifier_module().CLASSIFICATION_OVERRIDE_SOURCE_BASIS
    generator = record("generator.py")
    records = [authority, generated, generator]
    rows = [
        {
            "after": "NO",
            "before": "YES",
            "field": "authority_critical",
            "path": "a.txt",
            "rule_id": authority["rule_ids"][3],
            "source_basis": verifier_module().CLASSIFICATION_OVERRIDE_SOURCE_BASIS,
        },
        {
            "after": "YES",
            "before": "NO",
            "field": "generated",
            "path": "b.txt",
            "rule_id": generated["rule_ids"][4],
            "source_basis": verifier_module().CLASSIFICATION_OVERRIDE_SOURCE_BASIS,
        },
        {
            "after": "generator.py",
            "before": "",
            "field": "generator",
            "path": "b.txt",
            "rule_id": generated["rule_ids"][4],
            "source_basis": verifier_module().CLASSIFICATION_OVERRIDE_SOURCE_BASIS,
        },
    ]
    source = copy.deepcopy(records)
    source_by_path = {item["path"]: item for item in source}
    for row in rows:
        source_by_path[row["path"]][row["field"]] = row["before"]
        source_by_path[row["path"]]["source_basis"] = (
            verifier_module().CURRENT_A_SOURCE_BASIS
        )
    historical = [authority, generator]
    contract = overlay["review_classification_contract"]
    contract["records"] = records
    contract["override_policy"] = {
        "field_override_count": len(rows),
        "order": verifier_module().CLASSIFICATION_OVERRIDE_ORDER,
        "overrides": rows,
        "path_count": 2,
        "paths": ["a.txt", "b.txt"],
        "policy_id": verifier_module().CLASSIFICATION_OVERRIDE_POLICY_ID,
    }
    contract["counts"] = {
        "f_additions": verifier_module()._classification_counts([]),
        "final_current_a": verifier_module()._classification_counts(records),
        "final_f": verifier_module()._classification_counts(records),
        "final_historical_ledger_subjects": verifier_module()._classification_counts(
            historical
        ),
        "source_current_a": verifier_module()._classification_counts(source),
    }
    digest = verifier_module()._domain_digest(
        verifier_module().CLASSIFICATION_DIGEST_DOMAIN, records
    )
    contract["classification_set_sha256"] = digest
    overlay = json.loads(verifier_module()._canonical_json_bytes(overlay))
    return (
        overlay,
        {item["path"]: {} for item in records},
        {item["path"]: {} for item in historical},
        digest,
    )


def subject_fixture(number: int, **options):
    critical = options.pop("critical", False)
    binary = options.pop("binary", False)
    if options:
        raise TypeError("unknown subject fixture option")
    size = 4097 if binary else number + 10
    lines = None if binary else number + 1
    record = {
        "bytes": size,
        "content_kind": "BINARY" if binary else "TEXT_UTF8",
        "criticality": ["SECURITY_CRITICAL"] if critical else [],
        "git_mode": "100644",
        "git_object_id": f"{number:x}" * 40,
        "language": "BINARY_DATA" if binary else "TEXT",
        "lines": lines,
        "path": f"file-{number:02d}.{'bin' if binary else 'txt'}",
        "sha256": f"{number:x}" * 64,
        "status": "UNCHANGED_BASE",
    }
    record["subject_id"] = verifier_module()._subject_id(record)
    record["units"] = verifier_module()._subject_units(record)
    return record


def subject_classification_records(subjects):
    return {
        subject["path"]: {
            "path": subject["path"],
            "generated": "NO",
            "generator": "",
            "public_surface": "NO",
            "security_critical": "YES"
            if "SECURITY_CRITICAL" in subject["criticality"]
            else "NO",
            "science_critical": "NO",
            "authority_critical": "NO",
            "provenance_review_status": "CONFIRMED",
            "license_review_status": "APPROVED",
            "license_expression": "Apache-2.0 OR MIT",
        }
        for subject in subjects
    }


def signed_review_vector(root: Path, **options):
    freeze_commit = options.pop("freeze_commit", "f" * 40)
    implementation_commit = options.pop("implementation_commit", "e" * 40)
    if options:
        raise TypeError("unknown signed-review option")
    private = root / "reviewer"
    subprocess.run(
        [
            verifier_module().SSH_KEYGEN_EXECUTABLE,
            "-q",
            "-t",
            "ed25519",
            "-N",
            "",
            "-f",
            private,
        ],
        check=True,
    )
    fields = private.with_suffix(".pub").read_text(encoding="ascii").split()
    public_key = " ".join(fields[:2])
    principal = "independent-reviewer@example.invalid"
    registry = {
        "key_fingerprint": verifier_module()._public_key_fingerprint(public_key),
        "public_key": public_key,
        "reviewer": {"principal": principal},
    }
    record = {
        "decision": "ACCEPT_TECHNICAL_TASK_QUALIFICATION",
        "id": "CH-T002-R01",
        "detached_signature": {
            "format": "ssh",
            "key_fingerprint": registry["key_fingerprint"],
            "namespace": "haldir-independent-review-v2",
            "principal": principal,
            "public_key": public_key,
            "signature": "",
        },
    }
    signature = subprocess.run(
        [
            verifier_module().SSH_KEYGEN_EXECUTABLE,
            "-Y",
            "sign",
            "-f",
            private,
            "-n",
            "haldir-independent-review-v2",
        ],
        input=verifier_module()._review_attestation_payload(
            record, freeze_commit, implementation_commit
        ),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    ).stdout.decode("ascii")
    record["detached_signature"]["signature"] = signature
    return record, registry


def activation_command_vector(**options):
    stdout = options.pop("stdout", "PASS\n")
    stderr = options.pop("stderr", "")
    if options:
        raise TypeError("unknown activation-command option")
    return {
        "argv": ["/bin/true"],
        "completed_at_utc": "2026-07-22T00:00:00Z",
        "cwd": ".",
        "exit_code": 0,
        "id": "VECTOR-CMD01",
        "phase": "VECTOR",
        "started_at_utc": "2026-07-22T00:00:00Z",
        "stderr": stderr,
        "stderr_sha256": hashlib.sha256(stderr.encode()).hexdigest(),
        "stdout": stdout,
        "stdout_sha256": hashlib.sha256(stdout.encode()).hexdigest(),
    }


def validate_activation_command_vector(command):
    return verifier_module()._validate_activation_command(
        command,
        command_id="VECTOR-CMD01",
        phase="VECTOR",
        argv=["/bin/true"],
        outer_started="2026-07-22T00:00:00Z",
        outer_completed="2026-07-22T00:00:00Z",
        previous_completed="2026-07-22T00:00:00Z",
    )


def retained_ci_vector():
    payload = verifier_module()._canonical_json_bytes(
        {"id": 1001, "status": "completed"}
    )
    source_url = "https://api.github.com/repos/sepahead/haldir/actions/runs/1001"
    api_path = "repos/sepahead/haldir/actions/runs/1001"
    timestamp = "2026-07-22T00:00:00Z"
    record = {
        "bytes": len(payload),
        "capture_argv": verifier_module()._ci_capture_argv(api_path),
        "completed_at_utc": timestamp,
        "content_base64": base64.b64encode(payload).decode("ascii"),
        "exit_code": 0,
        "kind": "RUN_API_JSON",
        "media_type": "application/vnd.github+json",
        "request_headers": [
            f"Accept: {verifier_module().GH_ACCEPT_HEADER}",
            f"X-GitHub-Api-Version: {verifier_module().GH_API_VERSION}",
        ],
        "sha256": hashlib.sha256(payload).hexdigest(),
        "source_url": source_url,
        "started_at_utc": timestamp,
        "stderr": "",
        "stderr_sha256": hashlib.sha256(b"").hexdigest(),
        "tool_version": verifier_module().GH_VERSION,
    }
    arguments = {
        "kind": "RUN_API_JSON",
        "source_url": source_url,
        "api_path": api_path,
        "media_type": "application/vnd.github+json",
        "maximum": 64 * 1024,
        "outer_started": timestamp,
        "outer_completed": timestamp,
        "previous_completed": timestamp,
    }
    return record, payload, arguments


def log_archive_vector(**options):
    ordinals = options.pop("ordinals", None)
    names = options.pop("names", None)
    include_directories = options.pop("include_directories", False)
    if options:
        raise TypeError("unknown log-archive option")
    jobs = [
        {"conclusion": "success", "job_id": 88000 + index, "name": name}
        for index, name in enumerate(verifier_module().CI_JOB_NAMES, 1)
    ]
    provider_names = list(names or verifier_module().CI_JOB_NAMES)
    provider_ordinals = list(ordinals or range(len(provider_names)))
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_STORED) as archive:
        for ordinal, name in zip(provider_ordinals, provider_names, strict=True):
            info = zipfile.ZipInfo(f"{ordinal}_{name}.txt")
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            archive.writestr(info, f"{name}: success\n")
            if include_directories:
                system = zipfile.ZipInfo(f"{name}/system.txt")
                system.create_system = 3
                system.external_attr = 0o100644 << 16
                archive.writestr(system, "system metadata\n")
    return stream.getvalue(), jobs


def catalog_binding_fixture():
    _base, rows, _base_payload, _completed_payload, _reviewers = ledger_fixture()
    subjects = []
    for row in rows:
        if row["current_content_kind"] in {
            "BINARY",
            "TEXT_UTF8",
            "TEXT_UTF8_WITH_ANSI_ESCAPE",
        }:
            subject = verifier_module()._ledger_subject(row)
        else:
            subject = {
                "criticality": [
                    name
                    for field, name in zip(
                        verifier_module().CRITICAL_FIELDS,
                        verifier_module().CRITICALITY_ORDER,
                        strict=True,
                    )
                    if row[field] == "YES"
                ],
                "path": row["path"],
                "subject_id": verifier_module()._domain_digest(
                    "haldir-ch-t002-test-ledger-self-subject-v1", row["path"]
                ),
            }
        subjects.append(subject)
        subject_id = subject["subject_id"]
        evidence = {
            f"CH-T002-E09#{subject_id}:PRIMARY",
            f"CH-T002-E10#{subject_id}:PRIMARY",
        }
        if subject["criticality"]:
            evidence.update(
                {
                    f"CH-T002-E09#{subject_id}:SECONDARY",
                    f"CH-T002-E11#{subject_id}:SECONDARY",
                }
            )
        row["provenance_evidence"] = f"CH-T002-E09#{subject_id}:PROVENANCE"
        row["license_evidence"] = (
            f"CH-T002-E09#{subject_id}:LICENSE"
            if row["license_review_status"] == "APPROVED"
            else ""
        )
        row["evidence"] = ";".join(sorted(evidence))
    catalogs = {
        "evidence_catalog": frozenset(verifier_module().EVIDENCE_PATHS),
        "generator_catalog": frozenset({"tools/release/current-file-review-ledger.py"}),
        "requirement_catalog": frozenset({"CH-T002-N01"}),
        "test_catalog": frozenset({"TEST_PTR"}),
    }
    return rows, catalogs, classification_records(rows), subjects


def synthetic_lifecycle_class():
    class SyntheticLifecycle:
        """Build a small real Git repository satisfying the registered protocol."""

        timestamp = "2026-07-22T00:00:00Z"
        ledger_generator = "tools/release/current-file-review-ledger.py"
        product_sha256 = PRODUCT_SHA256
        product_tests_sha256 = (
            "f9e4465df5ff10e3b2e298d58ba8f375748df5383378abd354d3af2862781fd5"
        )
        override_paths = (
            "docs/COMPLETION-CHECKLIST.md",
            "fixture/data-01.txt",
            "fixture/data-02.txt",
        )

        def __init__(self, root: Path):
            self.root = root
            self.repo = root / "repo"
            self.keys = root / "keys"
            self.repo.mkdir()
            self.keys.mkdir()
            subprocess.run(
                [
                    verifier_module().GIT_EXECUTABLE,
                    "init",
                    "-q",
                    "-b",
                    "main",
                    self.repo,
                ],
                check=True,
            )
            for key, value in (
                ("user.name", "Synthetic Fixture"),
                ("user.email", "fixture@example.invalid"),
            ):
                subprocess.run(
                    [
                        verifier_module().GIT_EXECUTABLE,
                        "-C",
                        self.repo,
                        "config",
                        key,
                        value,
                    ],
                    check=True,
                )
            self.private_keys = {}
            self.base_rows = []

        def write(self, path: str, payload: bytes):
            target = self.repo / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(payload)

        def commit(self, subject: str) -> str:
            subprocess.run(
                [verifier_module().GIT_EXECUTABLE, "-C", self.repo, "add", "-A"],
                check=True,
            )
            subprocess.run(
                [
                    verifier_module().GIT_EXECUTABLE,
                    "-C",
                    self.repo,
                    "commit",
                    "-q",
                    "-m",
                    subject,
                ],
                check=True,
            )
            return subprocess.check_output(
                [
                    verifier_module().GIT_EXECUTABLE,
                    "-C",
                    self.repo,
                    "rev-parse",
                    "HEAD",
                ],
                text=True,
            ).strip()

        def tree_id(self, commit: str) -> str:
            return subprocess.check_output(
                [
                    verifier_module().GIT_EXECUTABLE,
                    "-C",
                    self.repo,
                    "rev-parse",
                    f"{commit}^{{tree}}",
                ],
                text=True,
            ).strip()

        def blob_record(self, path: str, payload: bytes) -> dict:
            return {
                "mode": "100644",
                "type": "blob",
                "oid": verifier_module()._git_blob_id(payload),
                "size": len(payload),
            }

        def build_base(self):
            payloads = {
                verifier_module().REGISTRY_PATH: verifier_module()._pretty_json_bytes(
                    {
                        "append_only": True,
                        "registrations": [],
                        "schema_version": "1.0.0",
                    }
                ),
                verifier_module().REQUIREMENTS_PATH: verifier_module()._canonical_json_bytes(
                    {"task": verifier_module().TASK_ID, "status": "OPEN"}
                ),
                verifier_module().ACTIVE_CLAIMS_PATH: verifier_module()._canonical_json_bytes(
                    {"claims": [], "task": verifier_module().TASK_ID}
                ),
                self.ledger_generator: b"#!/usr/bin/env python3\n# synthetic ledger generator\n",
                self.override_paths[0]: b"# synthetic completion checklist\n",
                **{
                    f"fixture/data-{index:02d}.txt": f"fixture {index}\n".encode(
                        "utf-8"
                    )
                    for index in range(1, 10)
                },
                **{
                    f"fixture/large-{index:02d}.txt": b"x\n" * lines
                    for index, lines in ((1, 9000), (2, 8000), (3, 7000))
                },
            }
            for path, payload in payloads.items():
                self.write(path, payload)
            paths = sorted(
                [verifier_module().LEDGER_PATH, *payloads],
                key=lambda item: item.encode(),
            )
            rows = []
            for path in paths:
                row = base_row(path)
                row["language"] = verifier_module()._language(path)
                row["format"] = row["language"]
                if path == verifier_module().LEDGER_PATH:
                    row.update(
                        {
                            "index_tracked": "false",
                            "index_git_mode": "",
                            "index_git_blob_id": "",
                            "index_flags": "",
                            "index_sha256": "",
                            "index_bytes": "",
                            "index_lines": "0",
                            "index_content_kind": "SELF_REFERENTIAL_CONTENT_EXCLUDED",
                            "source_index_state": "SOURCE_PRESENT_SELF_INDEX_EXCLUDED",
                            "current_scope": "LEDGER_SELF",
                            "current_fs_type": "LEDGER_SELF",
                            "current_fs_mode": "",
                            "current_git_blob_id": "",
                            "current_sha256": "",
                            "current_bytes": "",
                            "current_lines": "0",
                            "current_content_kind": "SELF_REFERENTIAL_CONTENT_EXCLUDED",
                            "worktree_state": "SELF_REFERENTIAL_CONTENT_EXCLUDED",
                            "git_blob_id": "",
                            "sha256": "",
                            "bytes": "",
                            "lines": "",
                            "language": "CSV",
                            "format": "SELF_REFERENTIAL_CSV",
                            "generated": "YES",
                            "generator": self.ledger_generator,
                        }
                    )
                else:
                    payload = payloads[path]
                    oid = verifier_module()._git_blob_id(payload)
                    digest = hashlib.sha256(payload).hexdigest()
                    lines = str(verifier_module()._line_count(payload))
                    row.update(
                        {
                            "source_git_blob_id": oid,
                            "source_sha256": digest,
                            "source_bytes": str(len(payload)),
                            "source_lines": lines,
                            "index_git_blob_id": oid,
                            "index_sha256": digest,
                            "index_bytes": str(len(payload)),
                            "index_lines": lines,
                            "current_git_blob_id": oid,
                            "current_sha256": digest,
                            "current_bytes": str(len(payload)),
                            "current_lines": lines,
                            "git_blob_id": oid,
                            "sha256": digest,
                            "bytes": str(len(payload)),
                            "lines": lines,
                        }
                    )
                rows.append(row)
            ledger = render_ledger(rows)
            self.write(verifier_module().LEDGER_PATH, ledger)
            self.base_rows = rows
            self.base_ledger = ledger
            self.partition_commit = self.commit("fixture: CH-T001 partition")
            self.partition_tree = self.tree_id(self.partition_commit)
            prior_extensions = (
                verifier_module().PRIOR_FREEZE_PATH,
                verifier_module().PRIOR_REGISTERED_TESTS_PATH,
                verifier_module().PRIOR_VERIFIER_PATH,
                verifier_module().DEFECT_EVIDENCE_PATH,
            )
            for path in prior_extensions:
                self.write(path, f"frozen predecessor extension: {path}\n".encode())
            self.base_commit = self.commit("fixture: e0002 lifecycle baseline")
            self.base_tree = self.tree_id(self.base_commit)

        def classification_record(self, path: str) -> dict:
            floor = verifier_module()._mandatory_criticality_floor(path)
            generated = path == verifier_module().LEDGER_PATH
            public = "PUBLIC_SURFACE" in floor
            security = "SECURITY_CRITICAL" in floor
            authority = "AUTHORITY_CRITICAL" in floor
            if path == self.override_paths[1]:
                generated = True
            source_basis = (
                verifier_module().CLASSIFICATION_OVERRIDE_SOURCE_BASIS
                if path in self.override_paths
                else verifier_module().CURRENT_A_SOURCE_BASIS
            )
            return {
                "authority_critical": "YES" if authority else "NO",
                "generated": "YES" if generated else "NO",
                "generator": self.ledger_generator if generated else "",
                "license_expression": "Apache-2.0 OR MIT",
                "license_review_status": "APPROVED",
                "path": path,
                "provenance_review_status": "CONFIRMED",
                "public_surface": "YES" if public else "NO",
                "rule_ids": [
                    "PUB_YES_MANDATORY_DOCS_PUBLIC_SURFACE_FLOOR"
                    if path == self.override_paths[0]
                    else "PUB_YES_FIXTURE"
                    if public
                    else "PUB_NO_FIXTURE",
                    "SEC_YES_FIXTURE" if security else "SEC_NO_FIXTURE",
                    "SCI_NO_FIXTURE",
                    "AUTH_YES_FIXTURE"
                    if authority
                    else "AUTH_NO_BIDIRECTIONAL_OVERRIDE"
                    if path == self.override_paths[2]
                    else "AUTH_NO_FIXTURE",
                    "GEN_YES_ATOMIC_OVERRIDE"
                    if path == self.override_paths[1]
                    else "GEN_YES_FIXTURE"
                    if generated
                    else "GEN_NO_FIXTURE",
                    "LIC_FIXTURE",
                ],
                "science_critical": "NO",
                "security_critical": "YES" if security else "NO",
                "source_basis": source_basis,
            }

        def classification_override_rows(self, records):
            by_path = {record["path"]: record for record in records}
            specifications = {
                self.override_paths[0]: {"public_surface": "NO"},
                self.override_paths[1]: {"generated": "NO", "generator": ""},
                self.override_paths[2]: {"authority_critical": "YES"},
            }
            rows = []
            for path in self.override_paths:
                for field in sorted(
                    specifications[path], key=lambda item: item.encode("ascii")
                ):
                    index, _prefix = (
                        verifier_module().CLASSIFICATION_OVERRIDE_FIELD_SPECS[field]
                    )
                    rows.append(
                        {
                            "after": by_path[path][field],
                            "before": specifications[path][field],
                            "field": field,
                            "path": path,
                            "rule_id": by_path[path]["rule_ids"][index],
                            "source_basis": verifier_module().CLASSIFICATION_OVERRIDE_SOURCE_BASIS,
                        }
                    )
            return rows

        def generate_review_keys(self, freeze):
            for index, registry in enumerate(freeze["reviewer_registry"], 1):
                private = self.keys / f"reviewer-{index}"
                subprocess.run(
                    [
                        verifier_module().SSH_KEYGEN_EXECUTABLE,
                        "-q",
                        "-t",
                        "ed25519",
                        "-N",
                        "",
                        "-f",
                        private,
                    ],
                    check=True,
                )
                fields = private.with_suffix(".pub").read_text(encoding="ascii").split()
                public = " ".join(fields[:2])
                registry["public_key"] = public
                registry["key_fingerprint"] = verifier_module()._public_key_fingerprint(
                    public
                )
                self.private_keys[registry["requirement_id"]] = private

        def build_freeze_and_implementation(self):
            freeze = freeze_fixture()
            self.generate_review_keys(freeze)
            freeze_payload = verifier_module()._pretty_json_bytes(freeze)
            verifier_payload = Path(verifier_module().__file__).read_bytes()
            tests_payload = Path(__file__).read_bytes()
            base_registry = json.loads(
                (self.repo / verifier_module().REGISTRY_PATH).read_text(
                    encoding="utf-8"
                )
            )
            registry = copy.deepcopy(base_registry)
            registry["registrations"].append(
                {
                    "task_id": verifier_module().TASK_ID,
                    "epoch": verifier_module().EPOCH,
                    "verifier": verifier_module()._file_record(
                        verifier_module().VERIFIER_PATH,
                        self.blob_record(
                            verifier_module().VERIFIER_PATH, verifier_payload
                        ),
                        verifier_payload,
                    ),
                    "tests": verifier_module()._file_record(
                        verifier_module().REGISTERED_TESTS_PATH,
                        self.blob_record(
                            verifier_module().REGISTERED_TESTS_PATH, tests_payload
                        ),
                        tests_payload,
                    ),
                    "freeze_contract": verifier_module()._file_record(
                        verifier_module().FREEZE_PATH,
                        self.blob_record(verifier_module().FREEZE_PATH, freeze_payload),
                        freeze_payload,
                    ),
                    "qualification_path": verifier_module().QUALIFICATION_PATH,
                    "activation_path": verifier_module().ACTIVATION_PATH,
                    "verifier_receipt_path": verifier_module().RECEIPT_PATH,
                    "effective_on": "SIGNED_COMMIT_FIRST_CONTAINING_EXACT_REGISTRATION_FREEZE_AND_GATES",
                }
            )
            for path, payload in (
                (verifier_module().FREEZE_PATH, freeze_payload),
                (verifier_module().VERIFIER_PATH, verifier_payload),
                (verifier_module().REGISTERED_TESTS_PATH, tests_payload),
                (
                    verifier_module().REGISTRY_PATH,
                    verifier_module()._pretty_json_bytes(registry),
                ),
            ):
                self.write(path, payload)
            self.freeze = freeze
            self.freeze_commit = self.commit(
                verifier_module().EXPECTED_COMMIT_SUBJECTS["F"]
            )
            self.freeze_tree = self.tree_id(self.freeze_commit)

            _tree, f_entries = verifier_module()._tree(self.repo, self.freeze_commit)
            f_blobs = verifier_module()._blobs(
                self.repo, [entry["oid"] for entry in f_entries.values()]
            )
            current_records = [
                self.classification_record(path)
                for path in sorted(
                    {row["path"] for row in self.base_rows},
                    key=lambda item: item.encode(),
                )
            ]
            extension_records = [
                copy.deepcopy(
                    verifier_module().EXPECTED_F_EXTENSION_CLASSIFICATIONS[path]
                )
                for path in sorted(
                    verifier_module().EXPECTED_F_EXTENSION_CLASSIFICATIONS,
                    key=lambda item: item.encode(),
                )
            ]
            records = sorted(
                [*current_records, *extension_records],
                key=lambda item: item["path"].encode(),
            )
            self.override_rows = self.classification_override_rows(current_records)
            self.override_digest = verifier_module()._domain_digest(
                verifier_module().CLASSIFICATION_OVERRIDE_DIGEST_DOMAIN,
                self.override_rows,
            )
            source_records = copy.deepcopy(current_records)
            source_by_path = {record["path"]: record for record in source_records}
            for row in self.override_rows:
                source_by_path[row["path"]][row["field"]] = row["before"]
                source_by_path[row["path"]]["source_basis"] = (
                    verifier_module().CURRENT_A_SOURCE_BASIS
                )
            self.source_classification_counts = (
                verifier_module()._classification_counts(source_records)
            )
            self.classification_digest = verifier_module()._domain_digest(
                verifier_module().CLASSIFICATION_DIGEST_DOMAIN, records
            )
            classification_counts = {
                "f_additions": verifier_module()._classification_counts(
                    extension_records
                ),
                "final_current_a": verifier_module()._classification_counts(
                    current_records
                ),
                "final_f": verifier_module()._classification_counts(records),
                "final_historical_ledger_subjects": verifier_module()._classification_counts(
                    current_records
                ),
                "source_current_a": self.source_classification_counts,
            }
            classification_by_path = {record["path"]: record for record in records}
            raw_delta, delta = verifier_module()._raw_name_status(
                self.repo, self.partition_commit, self.freeze_commit
            )
            entries = []
            for path, status in delta.items():
                entry = f_entries[path]
                payload = f_blobs[entry["oid"]]
                kind, lines = verifier_module()._classify_content(payload)
                classification = classification_by_path[path]
                value = {
                    "bytes": len(payload),
                    "content_kind": kind,
                    "criticality": verifier_module()._classification_criticality(
                        classification
                    ),
                    "generated": classification["generated"],
                    "generator": classification["generator"],
                    "git_mode": entry["mode"],
                    "git_object_id": entry["oid"],
                    "language": verifier_module()._language(path),
                    "license_expression": classification["license_expression"],
                    "license_review_status": classification["license_review_status"],
                    "lines": lines,
                    "path": path,
                    "provenance_review_status": classification[
                        "provenance_review_status"
                    ],
                    "rule_ids": classification["rule_ids"],
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    "source_basis": classification["source_basis"],
                    "status": "ADDED_FREEZE_DELTA"
                    if status == "A"
                    else "MODIFIED_FREEZE_DELTA",
                }
                value["subject_id"] = verifier_module()._subject_id(value)
                entries.append(value)
            ledger_entry = f_entries[verifier_module().LEDGER_PATH]
            ledger_classification = classification_by_path[
                verifier_module().LEDGER_PATH
            ]
            ledger_value = {
                "bytes": len(self.base_ledger),
                "content_kind": "TEXT_UTF8",
                "criticality": verifier_module()._classification_criticality(
                    ledger_classification
                ),
                "generated": ledger_classification["generated"],
                "generator": ledger_classification["generator"],
                "git_mode": ledger_entry["mode"],
                "git_object_id": ledger_entry["oid"],
                "language": "CSV",
                "license_expression": ledger_classification["license_expression"],
                "license_review_status": ledger_classification["license_review_status"],
                "lines": verifier_module()._line_count(self.base_ledger),
                "path": verifier_module().LEDGER_PATH,
                "provenance_review_status": "CONFIRMED",
                "rule_ids": ledger_classification["rule_ids"],
                "sha256": hashlib.sha256(self.base_ledger).hexdigest(),
                "source_basis": ledger_classification["source_basis"],
                "status": "LEDGER_SELF_EXTERNAL_BINDING",
            }
            ledger_value["subject_id"] = verifier_module()._subject_id(ledger_value)
            entries.append(ledger_value)
            entries.sort(key=lambda item: item["path"].encode())
            requirements = [item["id"] for item in freeze["normative_controls"]]
            tests = sorted(
                item[field]
                for item in freeze["normative_controls"]
                for field in ("accepted_test_id", "rejected_test_id")
            )
            overlay = {
                "author": copy.deepcopy(verifier_module().AUTHOR),
                "base_partition": {
                    "commit": self.partition_commit,
                    "ledger_blob_id": verifier_module()._git_blob_id(self.base_ledger),
                    "ledger_path": verifier_module().LEDGER_PATH,
                    "ledger_rows": len(self.base_rows),
                    "ledger_self_path": verifier_module().LEDGER_PATH,
                    "ledger_sha256": hashlib.sha256(self.base_ledger).hexdigest(),
                    "tree": self.partition_tree,
                },
                "counts": {},
                "delta": {
                    "freeze_commit": self.freeze_commit,
                    "freeze_tree": self.freeze_tree,
                    "name_status_sha256": hashlib.sha256(raw_delta).hexdigest(),
                },
                "digests": {},
                "entries": entries,
                "epoch": verifier_module().EPOCH,
                "implementation_boundary": {
                    "content_identities_in_overlay": False,
                    "paths": [
                        {"path": path, "status": status}
                        for path, status in verifier_module().EXPECTED_I_DIFF.items()
                    ],
                    "review_kind": verifier_module().IMPLEMENTATION_REVIEW_KIND,
                },
                "persistent_identifier": None,
                "release_target": verifier_module().RELEASE_TARGET,
                "removed_paths": [],
                "review_classification_contract": {
                    "classification_set_sha256": self.classification_digest,
                    "counts": classification_counts,
                    "override_policy": {
                        "field_override_count": len(self.override_rows),
                        "order": verifier_module().CLASSIFICATION_OVERRIDE_ORDER,
                        "overrides": self.override_rows,
                        "path_count": len(self.override_paths),
                        "paths": list(self.override_paths),
                        "policy_id": verifier_module().CLASSIFICATION_OVERRIDE_POLICY_ID,
                    },
                    "path_order": verifier_module().PATH_ORDER,
                    "records": records,
                    "schema_id": verifier_module().CLASSIFICATION_CONTRACT_SCHEMA_ID,
                    "semantics": {
                        "generated": "YES identifies production or capture by the named tracked procedure; it does not assert byte-deterministic regeneration of a historical run.",
                        "primary_capture": "The 12 retained live-campaign logs are generated captures and primary runtime observations; exact Git identities preserve the observed bytes, and their license review is NOT_APPLICABLE.",
                    },
                    "source_audit": {
                        "current_a_commit": self.partition_commit,
                        "current_a_tree": self.partition_tree,
                        "schema_id": verifier_module().CLASSIFICATION_AUDIT_SCHEMA_ID,
                        "sha256": verifier_module().CLASSIFICATION_AUDIT_SHA256,
                    },
                },
                "review_policy": {
                    "algorithm": verifier_module().ASSIGNMENT_ALGORITHM,
                    "binary_unit_bytes": verifier_module().BINARY_UNIT_BYTES,
                    "coverage": verifier_module().COVERAGE_RULE,
                    "critical_secondary_required": True,
                    "lanes": [
                        {
                            "kind": spec[1],
                            "lane": index,
                            "requirement_id": spec[0],
                            "reviewer_fingerprint": freeze["reviewer_registry"][
                                index - 1
                            ]["key_fingerprint"],
                        }
                        for index, spec in enumerate(
                            verifier_module().REVIEW_SPECS[:3], 1
                        )
                    ],
                    "lead_requirement_id": verifier_module().REVIEW_SPECS[3][0],
                    "primary_selection": verifier_module().PRIMARY_RULE,
                    "registry": {
                        "git_blob_id": f_entries[verifier_module().FREEZE_PATH]["oid"],
                        "path": verifier_module().FREEZE_PATH,
                        "sha256": hashlib.sha256(
                            f_blobs[f_entries[verifier_module().FREEZE_PATH]["oid"]]
                        ).hexdigest(),
                    },
                    "removed_coverage": verifier_module().REMOVAL_POLICY,
                    "secondary_selection": verifier_module().SECONDARY_RULE,
                    "sort_order": verifier_module().SORT_RULE,
                    "text_units": verifier_module().TEXT_UNIT_RULE,
                },
                "schema_id": verifier_module().OVERLAY_SCHEMA_ID,
                "schema_version": verifier_module().OVERLAY_SCHEMA_VERSION,
                "scope": {
                    "claim_outcome": "NO_PUBLIC_CLAIM_CHANGE",
                    "classification_audit_sha256": verifier_module().CLASSIFICATION_AUDIT_SHA256,
                    "classification_policy": verifier_module().CLASSIFICATION_POLICY,
                    "evidence_catalog": sorted(verifier_module().EVIDENCE_PATHS),
                    "generator_catalog": [self.ledger_generator],
                    "inclusion": verifier_module().SCOPE_INCLUSION,
                    "kind": verifier_module().OVERLAY_SCOPE,
                    "path_order": verifier_module().PATH_ORDER,
                    "requirement_catalog": requirements,
                    "test_catalog": tests,
                },
                "task_id": verifier_module().TASK_ID,
            }
            provisional_rows = copy.deepcopy(self.base_rows)
            for row in provisional_rows:
                decision = classification_by_path[row["path"]]
                for field in (
                    "generated",
                    "generator",
                    *verifier_module().CRITICAL_FIELDS,
                    "provenance_review_status",
                    "license_review_status",
                    "license_expression",
                ):
                    row[field] = decision[field]
            entry_paths = {entry["path"] for entry in entries}
            subjects = [
                verifier_module()._ledger_subject(row)
                for row in provisional_rows
                if row["path"] not in entry_paths
                and row["path"] != verifier_module().LEDGER_PATH
            ]
            subjects.extend(
                verifier_module()._overlay_subject(entry) for entry in entries
            )
            subjects.sort(
                key=lambda item: (
                    item["path"].encode(),
                    item["subject_id"].encode(),
                )
            )
            statuses = Counter(entry["status"] for entry in entries)
            overlay["counts"] = {
                "added_entries": statuses["ADDED_FREEZE_DELTA"],
                "base_rows": len(self.base_rows),
                "critical_subjects": sum(
                    bool(subject["criticality"]) for subject in subjects
                ),
                "modified_entries": statuses["MODIFIED_FREEZE_DELTA"],
                "removed_paths": 0,
                "review_subjects": len(subjects),
                "self_entries": 1,
                "supplemental_subjects": len(entries),
                "unchanged_subjects": sum(
                    subject["status"] == "UNCHANGED_BASE" for subject in subjects
                ),
            }
            overlay["digests"] = {
                "classification_set_sha256": self.classification_digest,
                "entry_set_sha256": verifier_module()._domain_digest(
                    "haldir-ch-t002-overlay-entry-set-v1", entries
                ),
                "removed_path_set_sha256": verifier_module()._domain_digest(
                    "haldir-ch-t002-removed-path-set-v1", []
                ),
                "subject_set_sha256": verifier_module()._subject_set_digest(
                    subjects,
                    freeze_commit=self.freeze_commit,
                    freeze_tree=self.freeze_tree,
                ),
            }
            lanes = verifier_module().assign_subjects(
                subjects,
                freeze=freeze,
                overlay=overlay,
                rows=[],
                classification_by_path=classification_by_path,
            )
            primary = {
                subject["path"]: (lane, subject)
                for lane in lanes
                for subject in lane["primary"]
            }
            secondary = {
                subject["subject_id"]: lane
                for lane in lanes
                for subject in lane["secondary"]
            }
            completed_rows = copy.deepcopy(self.base_rows)
            for row in completed_rows:
                decision = classification_by_path[row["path"]]
                lane, subject = primary[row["path"]]
                second = secondary.get(subject["subject_id"])
                evidence = {
                    f"CH-T002-E09#{subject['subject_id']}:PRIMARY",
                    f"CH-T002-E{9 + lane['number']:02d}#{subject['subject_id']}:PRIMARY",
                }
                if second is not None:
                    evidence.update(
                        {
                            f"CH-T002-E09#{subject['subject_id']}:SECONDARY",
                            f"CH-T002-E{9 + second['number']:02d}#{subject['subject_id']}:SECONDARY",
                        }
                    )
                for field in (
                    "generated",
                    "generator",
                    *verifier_module().CRITICAL_FIELDS,
                    "provenance_review_status",
                    "license_review_status",
                    "license_expression",
                ):
                    row[field] = decision[field]
                critical = bool(subject["criticality"])
                row.update(
                    {
                        "provenance_evidence": f"CH-T002-E09#{subject['subject_id']}:PROVENANCE",
                        "license_evidence": f"CH-T002-E09#{subject['subject_id']}:LICENSE",
                        "reviewer": lane["reviewer"]["principal"],
                        "review_status": "REVIEWED",
                        "requirements": "CH-T002-N01" if critical else "",
                        "assumptions": "",
                        "defects": "NONE",
                        "tests": "test_n01_accepted" if critical else "",
                        "evidence": ";".join(sorted(evidence)),
                        "disposition": "ACCEPTED",
                        "completed_at": self.timestamp,
                    }
                )
            overlay_payload = verifier_module()._canonical_json_bytes(overlay)
            completed_ledger = render_ledger(completed_rows)
            product_root = Path(
                os.environ.get(
                    "HALDIR_CH_T002_PRODUCT_ROOT", Path(__file__).resolve().parents[5]
                )
            )
            product_tool = (product_root / verifier_module().PRODUCT_TOOL).read_bytes()
            product_tests = (
                product_root / verifier_module().PRODUCT_TESTS
            ).read_bytes()
            if (
                hashlib.sha256(product_tool).hexdigest() != self.product_sha256
                or hashlib.sha256(product_tests).hexdigest()
                != self.product_tests_sha256
            ):
                raise AssertionError("final product byte identities drifted")
            for path, payload in (
                (verifier_module().OVERLAY_PATH, overlay_payload),
                (verifier_module().LEDGER_PATH, completed_ledger),
                (verifier_module().PRODUCT_TOOL, product_tool),
                (verifier_module().PRODUCT_TESTS, product_tests),
            ):
                self.write(path, payload)
            self.overlay = overlay
            self.completed_rows = completed_rows
            self.product_tests_payload = product_tests
            self.implementation_commit = self.commit(
                verifier_module().EXPECTED_COMMIT_SUBJECTS["I"]
            )
            self.implementation_tree = self.tree_id(self.implementation_commit)

        def patched_constants(self):
            stack = contextlib.ExitStack()
            values = {
                "BASELINE_COMMIT": self.base_commit,
                "CLASSIFICATION_AUDIT_COMMIT": self.partition_commit,
                "CURRENT_A_TREE": self.partition_tree,
                "CH_T001_IMPLEMENTATION_COMMIT": self.partition_commit,
                "CH_T001_IMPLEMENTATION_TREE": self.partition_tree,
                "CH_T001_LEDGER_OBJECT_ID": verifier_module()._git_blob_id(
                    self.base_ledger
                ),
                "CH_T001_LEDGER_SHA256": hashlib.sha256(self.base_ledger).hexdigest(),
                "EXPECTED_LEDGER_ROWS": len(self.base_rows),
                "AUDITED_CURRENT_A_PATHS": len(self.base_rows),
                "EXPECTED_CLASSIFICATION_OVERRIDE_PATHS": len(self.override_paths),
                "EXPECTED_CLASSIFICATION_OVERRIDE_FIELDS": len(self.override_rows),
                "EXPECTED_CLASSIFICATION_OVERRIDE_SET_SHA256": self.override_digest,
                "EXPECTED_GITIGNORE_OVERRIDE": None,
                "EXPECTED_SOURCE_CURRENT_A_COUNTS": self.source_classification_counts,
                "EXPECTED_F_CLASSIFICATION_SET_SHA256": self.classification_digest,
            }
            for name, value in values.items():
                stack.enter_context(mock.patch.object(verifier_module(), name, value))
            return stack

        def command_record(self, identifier, phase, argv, stdout, stderr):
            return {
                "argv": list(argv),
                "completed_at_utc": self.timestamp,
                "cwd": ".",
                "exit_code": 0,
                "id": identifier,
                "phase": phase,
                "started_at_utc": self.timestamp,
                "stderr": stderr,
                "stderr_sha256": hashlib.sha256(stderr.encode()).hexdigest(),
                "stdout": stdout,
                "stdout_sha256": hashlib.sha256(stdout.encode()).hexdigest(),
            }

        def common_evidence(self, identifier):
            return {
                "completed_at_utc": self.timestamp,
                "epoch": verifier_module().EPOCH,
                "evidence_id": identifier,
                "freeze_commit": self.freeze_commit,
                "implementation_commit": self.implementation_commit,
                "result": "PASS",
                "schema_id": verifier_module().EVIDENCE_SCHEMA_IDS[identifier],
                "started_at_utc": self.timestamp,
                "task_id": verifier_module().TASK_ID,
            }

        @staticmethod
        def unittest_stream(count):
            return (
                "." * count
                + "\n----------------------------------------------------------------------\n"
                + f"Ran {count} tests in 0.001s\n\nOK\n"
            )

        def sign_review_record(self, record, registry, *, lead):
            namespace = (
                "haldir-automated-lead-support-v2"
                if lead
                else "haldir-independent-review-v2"
            )
            attestation = {
                "format": "ssh",
                "key_fingerprint": registry["key_fingerprint"],
                "namespace": namespace,
                "principal": registry["reviewer"]["principal"],
                "public_key": registry["public_key"],
                "signature": "",
            }
            record["detached_signature"] = attestation
            signature = subprocess.run(
                [
                    verifier_module().SSH_KEYGEN_EXECUTABLE,
                    "-Y",
                    "sign",
                    "-f",
                    self.private_keys[registry["requirement_id"]],
                    "-n",
                    namespace,
                ],
                input=verifier_module()._review_attestation_payload(
                    record, self.freeze_commit, self.implementation_commit
                ),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
            ).stdout.decode("ascii")
            attestation["signature"] = signature

        def build_qualification(self, state):
            packet_documents = {
                "CH-T002-E10": state["packet_bodies"]["lane-01"],
                "CH-T002-E11": state["packet_bodies"]["lane-02"],
                "CH-T002-E12": state["packet_bodies"]["lane-03"],
                "CH-T002-E13": state["packet_manifest"],
            }
            packet_payloads = {
                identifier: verifier_module()._canonical_json_bytes(document)
                for identifier, document in packet_documents.items()
            }
            assignments = verifier_module()._subject_assignments(
                state["subjects"], state["lanes"]
            )
            assignment_digest = verifier_module()._assignment_set_digest(assignments)
            completion_records = verifier_module()._expected_completion_records(
                document_completed_at=self.timestamp,
                freeze=state["freeze"],
                overlay=state["overlay"],
                subjects=state["subjects"],
                rows=state["rows"],
                assignments=assignments,
                packet_payloads={
                    identifier: packet_payloads[identifier]
                    for identifier in ("CH-T002-E10", "CH-T002-E11", "CH-T002-E12")
                },
                freeze_commit=self.freeze_commit,
                freeze_tree=state["freeze_tree"],
                classification_by_path=state["classification_by_path"],
            )
            completion_digest = verifier_module()._domain_digest(
                "haldir-ch-t002-file-review-completion-set-v1", completion_records
            )
            packet_set_digest = verifier_module()._domain_digest(
                "haldir-ch-t002-packet-set-v1",
                [
                    {
                        "evidence_id": identifier,
                        "path": verifier_module().EVIDENCE_PATHS[identifier],
                        "sha256": hashlib.sha256(
                            packet_payloads[identifier]
                        ).hexdigest(),
                    }
                    for identifier in (
                        "CH-T002-E10",
                        "CH-T002-E11",
                        "CH-T002-E12",
                        "CH-T002-E13",
                    )
                ],
            )
            implementation_result = {
                "schema_version": "1.0.0",
                "task_id": verifier_module().TASK_ID,
                "epoch": verifier_module().EPOCH,
                "freeze_commit": self.freeze_commit,
                "implementation_commit": self.implementation_commit,
                "freeze_tree": state["freeze_tree"],
                "implementation_tree": state["implementation_tree"],
                "ledger_rows": len(state["rows"]),
                "review_subjects": len(state["subjects"]),
                "critical_subjects": sum(
                    bool(item["criticality"]) for item in state["subjects"]
                ),
                "subject_set_sha256": state["overlay"]["digests"]["subject_set_sha256"],
                "result": "PASS",
            }
            expected_argv = verifier_module()._expected_qualification_argv(
                state["freeze"], self.freeze_commit, self.implementation_commit
            )
            registered_names = verifier_module()._python_test_names(
                Path(__file__).read_bytes(), __file__
            )
            product_names = verifier_module()._python_test_names(
                self.product_tests_payload, verifier_module().PRODUCT_TESTS
            )
            packet_summary = {
                "command": "render",
                "critical_subjects": implementation_result["critical_subjects"],
                "lane_units": [lane["total_units"] for lane in state["lanes"]],
                "packet_count": 3,
                "result": "PASS",
                "review_subjects": len(state["subjects"]),
                "subject_set_sha256": implementation_result["subject_set_sha256"],
            }
            commands = []
            for index, (phase, argv) in enumerate(expected_argv, 1):
                stdout = ""
                stderr = ""
                if phase == "PRODUCT_TESTS":
                    stderr = self.unittest_stream(len(product_names))
                elif phase == "REGISTERED_TESTS":
                    stderr = self.unittest_stream(len(registered_names))
                elif phase == "NEGATIVE_VECTORS":
                    stderr = self.unittest_stream(
                        sum("reject" in name for name in registered_names)
                    )
                elif phase == "TECHNIQUE_ANALYSIS":
                    stderr = self.unittest_stream(
                        sum("technique_" in name for name in registered_names)
                    )
                elif phase in {"PACKET_RENDER", "PACKET_VERIFY"}:
                    summary = dict(packet_summary)
                    summary["command"] = (
                        "render" if phase == "PACKET_RENDER" else "verify"
                    )
                    stdout = verifier_module()._canonical_json_bytes(summary).decode()
                else:
                    stdout = (
                        verifier_module()
                        ._canonical_json_bytes(implementation_result)
                        .decode()
                    )
                    if phase.startswith("RESOURCE_SAMPLE_"):
                        stderr = (
                            "0.01 real 0.00 user 0.00 sys\n"
                            "123 maximum resident set size\n"
                        )
                commands.append(
                    self.command_record(
                        f"CH-T002-CMD{index:02d}", phase, argv, stdout, stderr
                    )
                )
            command_by_phase = {command["phase"]: command["id"] for command in commands}
            documents = {}
            documents["CH-T002-E02"] = {
                **self.common_evidence("CH-T002-E02"),
                "commands": commands,
                "environment": {
                    "architecture": "synthetic",
                    "git_version": "git synthetic",
                    "platform": "synthetic",
                    "python_version": "CPython 3.14.6",
                },
            }
            documents["CH-T002-E09"] = {
                **self.common_evidence("CH-T002-E09"),
                "completion_records": completion_records,
                "counts": {
                    "base_ledger_subjects": sum(
                        item["source"] == "BASE_LEDGER" for item in completion_records
                    ),
                    "critical_subjects": sum(
                        bool(item["subject"]["criticality"])
                        for item in completion_records
                    ),
                    "live_subjects": len(completion_records),
                    "removed_subjects": 0,
                    "review_subjects": len(completion_records),
                    "supplemental_subjects": sum(
                        item["source"] == "SUPPLEMENTAL_F"
                        for item in completion_records
                    ),
                },
                "digests": {
                    "assignment_set_sha256": assignment_digest,
                    "completion_set_sha256": completion_digest,
                    "packet_set_sha256": packet_set_digest,
                    "subject_set_sha256": implementation_result["subject_set_sha256"],
                },
            }
            requirement_ids = list(state["overlay"]["scope"]["requirement_catalog"])
            test_ids = list(state["overlay"]["scope"]["test_catalog"])
            evidence_ids = list(state["overlay"]["scope"]["evidence_catalog"])
            ledger_payload = state["blobs"][
                state["implementation_entries"][verifier_module().LEDGER_PATH]["oid"]
            ]
            overlay_payload = state["blobs"][
                state["implementation_entries"][verifier_module().OVERLAY_PATH]["oid"]
            ]
            documents["CH-T002-E01"] = {
                **self.common_evidence("CH-T002-E01"),
                "implementation_plan": [
                    {"path": path, "status": status}
                    for path, status in verifier_module().EXPECTED_I_DIFF.items()
                ],
                "requirement_ids": requirement_ids,
                "test_ids": test_ids,
                "evidence_ids": evidence_ids,
                "immutable_fields": list(verifier_module().IMMUTABLE_FIELDS),
                "mutable_fields": list(verifier_module().MUTABLE_REVIEW_FIELDS),
                "counts": {
                    "base_rows": len(state["rows"]),
                    "critical_subjects": implementation_result["critical_subjects"],
                    "evidence_requirements": len(evidence_ids),
                    "review_subjects": len(state["subjects"]),
                    "reviewers": len(state["freeze"]["reviewer_registry"]),
                },
                "digests": {
                    "assignment_set_sha256": assignment_digest,
                    "completion_set_sha256": completion_digest,
                    "ledger_sha256": hashlib.sha256(ledger_payload).hexdigest(),
                    "overlay_sha256": hashlib.sha256(overlay_payload).hexdigest(),
                    "packet_set_sha256": packet_set_digest,
                    "subject_set_sha256": implementation_result["subject_set_sha256"],
                },
            }
            controls = state["freeze"]["normative_controls"]
            documents["CH-T002-E03"] = {
                **self.common_evidence("CH-T002-E03"),
                "accepted_vectors": [
                    {
                        "requirement_id": item["id"],
                        "result": "PASS",
                        "test_id": item["accepted_test_id"],
                    }
                    for item in controls
                ],
                "rejected_vectors": [
                    {
                        "requirement_id": item["id"],
                        "result": "PASS",
                        "test_id": item["rejected_test_id"],
                    }
                    for item in controls
                ],
                "command_ids": [
                    command_by_phase["PRODUCT_TESTS"],
                    command_by_phase["REGISTERED_TESTS"],
                    command_by_phase["NEGATIVE_VECTORS"],
                ],
            }
            documents["CH-T002-E04"] = {
                **self.common_evidence("CH-T002-E04"),
                "techniques": [
                    {
                        "cases": verifier_module().TECHNIQUE_COVERAGE[name]["cases"],
                        "command_ids": [command_by_phase["TECHNIQUE_ANALYSIS"]],
                        "limitations": [verifier_module().TECHNIQUE_LIMITATIONS[name]],
                        "name": name,
                        "requirement_ids": list(
                            verifier_module().TECHNIQUE_COVERAGE[name][
                                "requirement_ids"
                            ]
                        ),
                        "status": "PASS",
                        "test_ids": [
                            f"{verifier_module().REGISTERED_TESTS_PATH}::{test_id}"
                        ],
                    }
                    for name, test_id in verifier_module().TECHNIQUE_TEST_IDS.items()
                ],
                "covered_requirement_ids": sorted(
                    {
                        requirement_id
                        for coverage in verifier_module().TECHNIQUE_COVERAGE.values()
                        for requirement_id in coverage["requirement_ids"]
                    }
                ),
                "covered_test_ids": sorted(
                    f"{verifier_module().REGISTERED_TESTS_PATH}::{test_id}"
                    for test_id in verifier_module().TECHNIQUE_TEST_IDS.values()
                ),
            }
            packet_sizes = [len(payload) for payload in packet_payloads.values()]
            implementation_sizes = [
                entry["size"] for entry in state["implementation_entries"].values()
            ]
            documents["CH-T002-E05"] = {
                **self.common_evidence("CH-T002-E05"),
                "declared_maxima": {
                    "blob_bytes": verifier_module().MAX_BLOB_BYTES,
                    "command_seconds": verifier_module().COMMAND_SECONDS,
                    "evidence_file_bytes": 4 * 1024 * 1024,
                    "git_output_bytes": verifier_module().MAX_GIT_OUTPUT,
                    "json_bytes": 256 * 1024,
                    "ledger_bytes": verifier_module().MAX_LEDGER_BYTES,
                    "packet_bytes": verifier_module().MAX_PACKET_BYTES,
                    "resource_samples": verifier_module().RESOURCE_SAMPLE_COUNT,
                    "tree_bytes": verifier_module().MAX_TREE_BYTES,
                    "verifier_seconds": 10,
                },
                "observed_maxima": {
                    "commands": len(commands),
                    "largest_blob_bytes": max(implementation_sizes),
                    "ledger_bytes": len(ledger_payload),
                    "overlay_bytes": len(overlay_payload),
                    "packet_bytes": max(packet_sizes),
                    "peak_rss_bytes": 123,
                    "resource_real_seconds": 0.01,
                    "review_subjects": len(state["subjects"]),
                    "tree_total_bytes": sum(implementation_sizes),
                },
                "observed_distributions": {
                    "peak_rss_bytes": [123] * verifier_module().RESOURCE_SAMPLE_COUNT,
                    "resource_real_seconds": [0.01]
                    * verifier_module().RESOURCE_SAMPLE_COUNT,
                },
                "command_ids": [command["id"] for command in commands],
                "capacity_disposition": {
                    "fallback_permitted": False,
                    "hard_ceiling_success_claimed": False,
                    "qualified_candidate_only": True,
                    "result": "PASS",
                },
            }
            implementation_files = [
                verifier_module()._central_file_record(
                    path,
                    state["implementation_entries"][path],
                    state["blobs"][state["implementation_entries"][path]["oid"]],
                )
                for path in verifier_module().EXPECTED_I_DIFF
            ]
            registered_files = [
                verifier_module()._central_file_record(
                    path,
                    state["f_entries"][path],
                    state["blobs"][state["f_entries"][path]["oid"]],
                )
                for path in (
                    verifier_module().FREEZE_PATH,
                    verifier_module().REGISTRY_PATH,
                    verifier_module().REGISTERED_TESTS_PATH,
                    verifier_module().VERIFIER_PATH,
                )
            ]
            documents["CH-T002-E06"] = {
                **self.common_evidence("CH-T002-E06"),
                "baseline_commit": self.base_commit,
                "freeze_tree": state["freeze_tree"],
                "implementation_tree": state["implementation_tree"],
                "base_ledger": {
                    **verifier_module()._file_record(
                        verifier_module().LEDGER_PATH,
                        state["base_entries"][verifier_module().LEDGER_PATH],
                        self.base_ledger,
                    ),
                    "rows": len(state["rows"]),
                },
                "implementation_files": implementation_files,
                "registered_files": registered_files,
                "lifecycle_diffs": {
                    "baseline_to_freeze": verifier_module().EXPECTED_F_DIFF,
                    "freeze_to_implementation": verifier_module().EXPECTED_I_DIFF,
                },
                "digests": {
                    "assignment_set_sha256": assignment_digest,
                    "completion_set_sha256": completion_digest,
                    "packet_set_sha256": packet_set_digest,
                    "subject_set_sha256": implementation_result["subject_set_sha256"],
                },
            }
            documents["CH-T002-E07"] = {
                **self.common_evidence("CH-T002-E07"),
                "claim_outcome": state["freeze"]["claim_outcomes"][0],
                "implementation_paths": [
                    {"path": path, "status": status}
                    for path, status in verifier_module().EXPECTED_I_DIFF.items()
                ],
                "runtime_surface_changed": False,
                "release_authority": None,
                "publication_authority": None,
                "requirements_complete": True,
            }
            documents["CH-T002-E08"] = {
                **self.common_evidence("CH-T002-E08"),
                "assignments": [
                    {"path": row["path"], "reviewer": row["reviewer"]}
                    for row in state["rows"]
                ],
                "assigned_rows": len(state["rows"]),
                "reviewed_rows": len(state["rows"]),
                "assignment_set_sha256": assignment_digest,
            }
            documents.update(packet_documents)
            evidence_payloads = {
                identifier: verifier_module()._canonical_json_bytes(
                    documents[identifier]
                )
                for identifier, _kind, _name in verifier_module().EVIDENCE_SPECS
            }
            decisive_lines = verifier_module()._decisive_reproduction_lines(
                evidence_documents=documents,
                c_payloads={
                    verifier_module().EVIDENCE_PATHS[identifier]: payload
                    for identifier, payload in evidence_payloads.items()
                },
            )
            changed_records = implementation_files
            context_paths = sorted(
                {
                    verifier_module().FREEZE_PATH,
                    verifier_module().REGISTERED_TESTS_PATH,
                    verifier_module().REGISTRY_PATH,
                    verifier_module().VERIFIER_PATH,
                },
                key=lambda item: item.encode(),
            )
            context_records = [
                verifier_module()._central_file_record(
                    path,
                    state["f_entries"][path],
                    state["blobs"][state["f_entries"][path]["oid"]],
                )
                for path in context_paths
            ]
            review_payloads = {}
            review_records = []
            for index, requirement in enumerate(state["review_requirements"]):
                registry = state["freeze"]["reviewer_registry"][index]
                report = {
                    "all_changed_lines_reviewed": True,
                    "decision": "ACCEPT_TECHNICAL_TASK_QUALIFICATION",
                    "decisive_reproduction": {
                        "commands": decisive_lines,
                        "evidence_ids": [
                            item[0] for item in verifier_module().EVIDENCE_SPECS
                        ],
                        "result": "PASS",
                    },
                    "epoch": verifier_module().EPOCH,
                    "findings": [],
                    "freeze_commit": self.freeze_commit,
                    "implementation_commit": self.implementation_commit,
                    "implementation_diff": {
                        "changed_file_records": changed_records,
                        "deleted_paths": [],
                        "statuses": verifier_module().EXPECTED_I_DIFF,
                    },
                    "limitations": ["Synthetic fixture review scope."],
                    "relevant_unchanged_context_reviewed": True,
                    "requirement": {
                        key: requirement[key] for key in ("id", "kind", "path")
                    },
                    "reviewed_relevant_context": context_records,
                    "reviewer": registry["reviewer"],
                    "reviewer_provenance": {
                        "method": "SYNTHETIC_INDEPENDENT_REPRODUCTION",
                        "session_id": f"synthetic-session-{index + 1}",
                        "tool": "registered-verifier-test",
                        "version": "1.0.0",
                    },
                    "schema_version": "1.0.0",
                    "task_id": verifier_module().TASK_ID,
                }
                report_payload = verifier_module()._canonical_json_bytes(report)
                review_payloads[requirement["id"]] = report_payload
                lead = index == len(state["review_requirements"]) - 1
                record = {
                    "completed_at_utc": self.timestamp,
                    "decision": "ACCEPT_TECHNICAL_TASK_QUALIFICATION",
                    "detached_signature": {},
                    "external": False,
                    "file": verifier_module()._file_record(
                        requirement["path"],
                        self.blob_record(requirement["path"], report_payload),
                        report_payload,
                    ),
                    "human": False,
                    "id": requirement["id"],
                    "independent_from_release_author": not lead,
                    "kind": requirement["kind"],
                    "named_human_reviewer": False,
                    "release_approver": False,
                    "reproduced_decisive_evidence": True,
                    "reviewed_all_changed_lines_and_context": True,
                    "reviewer": registry["reviewer"],
                    "started_at_utc": self.timestamp,
                }
                self.sign_review_record(record, registry, lead=lead)
                review_records.append(record)
            evidence_records = []
            for requirement in state["evidence_requirements"]:
                payload = evidence_payloads[requirement["id"]]
                evidence_records.append(
                    {
                        "completed_at_utc": self.timestamp,
                        "file": verifier_module()._file_record(
                            requirement["path"],
                            self.blob_record(requirement["path"], payload),
                            payload,
                        ),
                        "id": requirement["id"],
                        "kind": requirement["kind"],
                        "result": "PASS",
                        "started_at_utc": self.timestamp,
                        "subject_commits": [
                            self.freeze_commit,
                            self.implementation_commit,
                        ],
                    }
                )
            qualification = {
                "author": copy.deepcopy(verifier_module().AUTHOR),
                "effective_on": "SIGNED_COMMIT_FIRST_CONTAINING_EXACT_QUALIFICATION_EVIDENCE_AND_REVIEWS",
                "epoch": verifier_module().EPOCH,
                "evidence_records": evidence_records,
                "freeze_commit": self.freeze_commit,
                "human_review_boundary": copy.deepcopy(
                    verifier_module().EXPECTED_HUMAN_REVIEW_BOUNDARY
                ),
                "implementation_commit": self.implementation_commit,
                "limitations": [
                    verifier_module().HUMAN_REVIEW_LIMITATION,
                    "Synthetic lifecycle fixture only.",
                ],
                "persistent_identifier": None,
                "registered_files": {
                    "verifier": verifier_module()._file_record(
                        verifier_module().VERIFIER_PATH,
                        state["f_entries"][verifier_module().VERIFIER_PATH],
                        state["blobs"][
                            state["f_entries"][verifier_module().VERIFIER_PATH]["oid"]
                        ],
                    ),
                    "tests": verifier_module()._file_record(
                        verifier_module().REGISTERED_TESTS_PATH,
                        state["f_entries"][verifier_module().REGISTERED_TESTS_PATH],
                        state["blobs"][
                            state["f_entries"][verifier_module().REGISTERED_TESTS_PATH][
                                "oid"
                            ]
                        ],
                    ),
                    "freeze_contract": verifier_module()._file_record(
                        verifier_module().FREEZE_PATH,
                        state["f_entries"][verifier_module().FREEZE_PATH],
                        state["blobs"][
                            state["f_entries"][verifier_module().FREEZE_PATH]["oid"]
                        ],
                    ),
                },
                "release_authority": None,
                "release_target": verifier_module().RELEASE_TARGET,
                "review_finding_dispositions": [
                    {
                        "disposition": "RESOLVED",
                        "evidence_ids": ["CH-T002-E01"],
                        "finding": "Technical review completed.",
                        "rationale": "Exact evidence reproduced.",
                        "residual_limitation": None,
                        "review_id": item[0],
                    }
                    for item in verifier_module().REVIEW_SPECS
                ],
                "review_records": review_records,
                "schema_version": "1.0.0",
                "selected_claim_outcome_id": state["freeze"]["claim_outcomes"][0]["id"],
                "task_id": verifier_module().TASK_ID,
                "twenty_lens_reviews": {
                    f"L{index:02d}": {
                        "evidence_ids": ["CH-T002-E01"],
                        "status": "RESOLVED",
                    }
                    for index in range(1, 21)
                },
            }
            for identifier, payload in evidence_payloads.items():
                self.write(verifier_module().EVIDENCE_PATHS[identifier], payload)
            for identifier, payload in review_payloads.items():
                self.write(verifier_module().REVIEW_PATHS[identifier], payload)
            self.write(
                verifier_module().QUALIFICATION_PATH,
                verifier_module()._canonical_json_bytes(qualification),
            )
            self.evidence_documents = documents
            self.qualification = qualification
            self.qualification_commit = self.commit(
                verifier_module().EXPECTED_COMMIT_SUBJECTS["C"]
            )

        def activation_common(self, identifier):
            return {
                "completed_at_utc": self.timestamp,
                "epoch": verifier_module().EPOCH,
                "evidence_id": identifier,
                "freeze_commit": self.freeze_commit,
                "implementation_commit": self.implementation_commit,
                "qualification_commit": self.qualification_commit,
                "result": "PASS",
                "schema_id": verifier_module().ACTIVATION_SCHEMA_IDS[identifier],
                "started_at_utc": self.timestamp,
                "task_id": verifier_module().TASK_ID,
            }

        def retained_ci_record(self, *, kind, source_url, api_path, payload):
            return {
                "bytes": len(payload),
                "capture_argv": verifier_module()._ci_capture_argv(api_path),
                "completed_at_utc": self.timestamp,
                "content_base64": base64.b64encode(payload).decode("ascii"),
                "exit_code": 0,
                "kind": kind,
                "media_type": "application/vnd.github+json",
                "request_headers": [
                    f"Accept: {verifier_module().GH_ACCEPT_HEADER}",
                    f"X-GitHub-Api-Version: {verifier_module().GH_API_VERSION}",
                ],
                "sha256": hashlib.sha256(payload).hexdigest(),
                "source_url": source_url,
                "started_at_utc": self.timestamp,
                "stderr": "",
                "stderr_sha256": hashlib.sha256(b"").hexdigest(),
                "tool_version": verifier_module().GH_VERSION,
            }

        def build_activation(self, state):
            expected_argv = dict(
                verifier_module()._expected_qualification_argv(
                    state["freeze"], self.freeze_commit, self.implementation_commit
                )
            )
            implementation_result = {
                "schema_version": "1.0.0",
                "task_id": verifier_module().TASK_ID,
                "epoch": verifier_module().EPOCH,
                "freeze_commit": self.freeze_commit,
                "implementation_commit": self.implementation_commit,
                "freeze_tree": state["freeze_tree"],
                "implementation_tree": state["implementation_tree"],
                "ledger_rows": len(state["rows"]),
                "review_subjects": len(state["subjects"]),
                "critical_subjects": sum(
                    bool(item["criticality"]) for item in state["subjects"]
                ),
                "subject_set_sha256": state["overlay"]["digests"]["subject_set_sha256"],
                "result": "PASS",
            }
            packet_summary = {
                "command": "verify",
                "critical_subjects": implementation_result["critical_subjects"],
                "lane_units": [lane["total_units"] for lane in state["lanes"]],
                "packet_count": 3,
                "result": "PASS",
                "review_subjects": len(state["subjects"]),
                "subject_set_sha256": implementation_result["subject_set_sha256"],
            }
            registered_count = len(
                verifier_module()._python_test_names(
                    Path(__file__).read_bytes(), __file__
                )
            )
            product_count = len(
                verifier_module()._python_test_names(
                    self.product_tests_payload, verifier_module().PRODUCT_TESTS
                )
            )
            subsystem_specs = (
                (
                    "PRODUCT_TESTS",
                    expected_argv["PRODUCT_TESTS"],
                    "",
                    self.unittest_stream(product_count),
                ),
                (
                    "PACKET_VERIFY",
                    expected_argv["PACKET_VERIFY"],
                    verifier_module()._canonical_json_bytes(packet_summary).decode(),
                    "",
                ),
                (
                    "REGISTERED_TESTS",
                    expected_argv["REGISTERED_TESTS"],
                    "",
                    self.unittest_stream(registered_count),
                ),
                (
                    "EXACT_IMPLEMENTATION_VERIFY",
                    expected_argv["INDEPENDENT_RECONCILIATION"],
                    verifier_module()
                    ._canonical_json_bytes(implementation_result)
                    .decode(),
                    "",
                ),
            )
            subsystem_commands = [
                self.command_record(
                    f"CH-T002-A01-CMD{index:02d}", phase, argv, stdout, stderr
                )
                for index, (phase, argv, stdout, stderr) in enumerate(
                    subsystem_specs, 1
                )
            ]
            a01 = {
                **self.activation_common("CH-T002-A01"),
                "checks": [item[0] for item in subsystem_specs],
                "commands": subsystem_commands,
            }
            wave_stdout = (
                "\n".join(
                    [
                        *(
                            f"  PASS: {name}"
                            for name in verifier_module().P0R_GATE_NAMES
                        ),
                        verifier_module().P0R_GATE_SUMMARY,
                        verifier_module().P0R_GATE_EPILOGUE,
                    ]
                )
                + "\n"
            )
            a02 = {
                **self.activation_common("CH-T002-A02"),
                "command": self.command_record(
                    "CH-T002-A02-CMD01",
                    "WAVE_GATE",
                    list(verifier_module().P0R_GATE_ARGV),
                    wave_stdout,
                    "",
                ),
                "scope": {
                    "execution_wave": 0,
                    "gate_scope": "FULL_REPOSITORY_LOCKED_GATE_AT_CH_T002_CANDIDATE",
                    "remaining_wave_tasks": [
                        f"CH-T{number:03d}" for number in range(3, 13)
                    ],
                    "wave_acceptance": "NOT_YET_ELIGIBLE",
                },
            }

            run_id = 1001
            run_attempt = 1
            run_url = f"https://github.com/sepahead/haldir/actions/runs/{run_id}"
            run_api_url = (
                f"https://api.github.com/repos/sepahead/haldir/actions/runs/{run_id}"
            )
            run_api_path = f"repos/sepahead/haldir/actions/runs/{run_id}"
            jobs_api_url = f"{run_api_url}/attempts/{run_attempt}/jobs?per_page=100"
            jobs_api_path = f"{run_api_path}/attempts/{run_attempt}/jobs?per_page=100"
            logs_api_url = f"{run_api_url}/attempts/{run_attempt}/logs"
            logs_api_path = f"{run_api_path}/attempts/{run_attempt}/logs"
            run_document = {
                "conclusion": "success",
                "created_at": self.timestamp,
                "event": "push",
                "head_branch": "main",
                "head_sha": self.qualification_commit,
                "html_url": run_url,
                "id": run_id,
                "path": ".github/workflows/ci.yml",
                "repository": {"full_name": "sepahead/haldir"},
                "run_attempt": run_attempt,
                "status": "completed",
                "updated_at": self.timestamp,
                "url": run_api_url,
            }
            raw_jobs = [
                {
                    "completed_at": self.timestamp,
                    "conclusion": "success",
                    "head_sha": self.qualification_commit,
                    "id": 2000 + index,
                    "name": name,
                    "run_attempt": run_attempt,
                    "run_id": run_id,
                    "started_at": self.timestamp,
                    "status": "completed",
                }
                for index, name in enumerate(verifier_module().CI_JOB_NAMES, 1)
            ]
            jobs_document = {"jobs": raw_jobs, "total_count": len(raw_jobs)}
            run_payload = verifier_module()._canonical_json_bytes(run_document)
            jobs_payload = verifier_module()._canonical_json_bytes(jobs_document)
            jobs = [
                {"conclusion": "success", "job_id": item["id"], "name": item["name"]}
                for item in raw_jobs
            ]
            archive_stream = io.BytesIO()
            with zipfile.ZipFile(
                archive_stream, "w", compression=zipfile.ZIP_STORED
            ) as archive:
                for ordinal, job in enumerate(jobs):
                    name = job["name"]
                    info = zipfile.ZipInfo(f"{ordinal}_{name}.txt")
                    info.create_system = 3
                    info.external_attr = 0o100644 << 16
                    archive.writestr(info, f"{name}: success\n".encode("utf-8"))
            archive_payload = archive_stream.getvalue()
            archive_manifest = verifier_module()._validate_log_archive(
                archive_payload, jobs=jobs
            )
            archive_file = verifier_module()._file_record(
                verifier_module().ACTIVATION_PATHS["CH-T002-A05"],
                self.blob_record(
                    verifier_module().ACTIVATION_PATHS["CH-T002-A05"], archive_payload
                ),
                archive_payload,
            )
            a03 = {
                **self.activation_common("CH-T002-A03"),
                "conclusion": "success",
                "head_sha": self.qualification_commit,
                "jobs": jobs,
                "log_archive_capture": {
                    "artifact_evidence_id": "CH-T002-A05",
                    "capture_argv": verifier_module()._ci_capture_argv(logs_api_path),
                    "completed_at_utc": self.timestamp,
                    "entry_manifest": archive_manifest,
                    "exit_code": 0,
                    "file": archive_file,
                    "kind": "ATTEMPT_LOG_ARCHIVE_ZIP",
                    "media_type": "application/zip",
                    "request_headers": [
                        f"Accept: {verifier_module().GH_ACCEPT_HEADER}",
                        f"X-GitHub-Api-Version: {verifier_module().GH_API_VERSION}",
                    ],
                    "source_url": logs_api_url,
                    "started_at_utc": self.timestamp,
                    "stderr": "",
                    "stderr_sha256": hashlib.sha256(b"").hexdigest(),
                    "tool_version": verifier_module().GH_VERSION,
                },
                "provider": "GITHUB_ACTIONS",
                "retained_records": [
                    self.retained_ci_record(
                        kind="RUN_API_JSON",
                        source_url=run_api_url,
                        api_path=run_api_path,
                        payload=run_payload,
                    ),
                    self.retained_ci_record(
                        kind="ATTEMPT_JOBS_API_JSON",
                        source_url=jobs_api_url,
                        api_path=jobs_api_path,
                        payload=jobs_payload,
                    ),
                ],
                "run_attempt": run_attempt,
                "run_id": run_id,
                "run_url": run_url,
                "workflow_path": ".github/workflows/ci.yml",
            }
            a04 = {
                **self.activation_common("CH-T002-A04"),
                "affected_downstreams": [],
                "disposition": "NO_RUNTIME_OR_EXTERNAL_DOWNSTREAM_CONFORMANCE_CHANGE",
                "implementation_paths": sorted(
                    verifier_module().EXPECTED_I_DIFF,
                    key=lambda item: item.encode("utf-8"),
                ),
                "rationale": "The candidate changes only release-review tooling and records.",
                "runtime_surface_changed": False,
            }
            documents = {
                "CH-T002-A01": a01,
                "CH-T002-A02": a02,
                "CH-T002-A03": a03,
                "CH-T002-A04": a04,
            }
            activation_payloads = {
                verifier_module().ACTIVATION_PATHS[
                    identifier
                ]: verifier_module()._canonical_json_bytes(document)
                for identifier, document in documents.items()
            }
            activation_payloads[verifier_module().ACTIVATION_PATHS["CH-T002-A05"]] = (
                archive_payload
            )
            receipt = {
                "schema_version": "1.0.0",
                "task_id": verifier_module().TASK_ID,
                "epoch": verifier_module().EPOCH,
                "freeze_commit": self.freeze_commit,
                "implementation_commit": self.implementation_commit,
                "qualification_commit": self.qualification_commit,
                "verifier_sha256": state["verifier_record"]["sha256"],
                "tests_sha256": state["tests_record"]["sha256"],
                "selected_claim_outcome_id": state["freeze"]["claim_outcomes"][0]["id"],
                "result": "PASS",
                "runtime_target_policy": "CENTRAL_VERIFIER_EXECUTES_EXACT_F_BLOBS_AT_D_AND_FROZEN_TRIGGERED_CHANGES",
            }
            receipt_payload = verifier_module()._canonical_json_bytes(receipt)
            requirements_payload = verifier_module()._canonical_json_bytes(
                {"status": "VERIFIED", "task": verifier_module().TASK_ID}
            )
            active_claims_payload = verifier_module()._canonical_json_bytes(
                {
                    "claims": [],
                    "task": verifier_module().TASK_ID,
                    "task_status": "VERIFIED",
                }
            )
            evidence_records = []
            for requirement in state["activation_requirements"]:
                payload = activation_payloads[requirement["path"]]
                evidence_records.append(
                    {
                        "completed_at_utc": self.timestamp,
                        "file": verifier_module()._file_record(
                            requirement["path"],
                            self.blob_record(requirement["path"], payload),
                            payload,
                        ),
                        "id": requirement["id"],
                        "kind": requirement["kind"],
                        "result": "PASS",
                        "started_at_utc": self.timestamp,
                        "subject_commit": self.qualification_commit,
                    }
                )
            qualification_payload = verifier_module()._canonical_json_bytes(
                self.qualification
            )
            activation = {
                "activation_evidence_records": evidence_records,
                "active_claims_record": verifier_module()._file_record(
                    verifier_module().ACTIVE_CLAIMS_PATH,
                    self.blob_record(
                        verifier_module().ACTIVE_CLAIMS_PATH, active_claims_payload
                    ),
                    active_claims_payload,
                ),
                "author": copy.deepcopy(verifier_module().AUTHOR),
                "decision": {
                    "task_status": "VERIFIED",
                    "claim_disposition": "NO_PUBLIC_CLAIM_CHANGE",
                    "overall_status": "NO_GO",
                    "tag_authorized": False,
                    "github_release_authorized": False,
                    "doi_authorized": False,
                    "zenodo_authorized": False,
                    "archive_authorized": False,
                },
                "effective_on": "SIGNED_COMMIT_FIRST_CONTAINING_EXACT_ACTIVATION_RECEIPTS_AND_TRANSITION",
                "epoch": verifier_module().EPOCH,
                "freeze_commit": self.freeze_commit,
                "implementation_commit": self.implementation_commit,
                "persistent_identifier": None,
                "qualification_commit": self.qualification_commit,
                "qualification_record": verifier_module()._file_record(
                    verifier_module().QUALIFICATION_PATH,
                    self.blob_record(
                        verifier_module().QUALIFICATION_PATH, qualification_payload
                    ),
                    qualification_payload,
                ),
                "release_target": verifier_module().RELEASE_TARGET,
                "requirements_record": verifier_module()._file_record(
                    verifier_module().REQUIREMENTS_PATH,
                    self.blob_record(
                        verifier_module().REQUIREMENTS_PATH, requirements_payload
                    ),
                    requirements_payload,
                ),
                "schema_version": "1.0.0",
                "selected_claim_outcome": state["freeze"]["claim_outcomes"][0],
                "task_id": verifier_module().TASK_ID,
                "verifier_receipt": verifier_module()._file_record(
                    verifier_module().RECEIPT_PATH,
                    self.blob_record(verifier_module().RECEIPT_PATH, receipt_payload),
                    receipt_payload,
                ),
            }
            for path, payload in activation_payloads.items():
                self.write(path, payload)
            for path, payload in (
                (verifier_module().RECEIPT_PATH, receipt_payload),
                (verifier_module().REQUIREMENTS_PATH, requirements_payload),
                (verifier_module().ACTIVE_CLAIMS_PATH, active_claims_payload),
                (
                    verifier_module().ACTIVATION_PATH,
                    verifier_module()._canonical_json_bytes(activation),
                ),
            ):
                self.write(path, payload)
            self.activation = activation
            self.activation_commit = self.commit(
                verifier_module().EXPECTED_COMMIT_SUBJECTS["D"]
            )

    return SyntheticLifecycle


class RegisteredVerifierTests(unittest.TestCase):
    def assert_rejects(self, code, function, *args, **kwargs):
        with self.assertRaisesRegex(verifier_module().VerificationError, code):
            function(*args, **kwargs)

    def test_unresolved_lifecycle_is_explicit(self):
        self.assertEqual(verifier_module().unresolved_lifecycle_fields(), ())

    def test_first_parent_limit_matches_central_registry_and_rejects_1025(self):
        self.assertEqual(verifier_module().MAX_FIRST_PARENT_COMMITS, 1024)
        payload = b"".join(f"{index:040x}\n".encode() for index in range(1025))
        with mock.patch.object(verifier_module(), "_git", return_value=payload):
            self.assert_rejects(
                "HISTORY_LIMIT", verifier_module()._first_parent, Path.cwd(), "f" * 40
            )

    def test_registered_verifier_accepts_complete_real_lifecycle(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = synthetic_lifecycle_class()(Path(temporary))
            fixture.build_base()
            fixture.build_freeze_and_implementation()
            with fixture.patched_constants():
                implementation_result = verifier_module().verify_implementation(
                    fixture.repo,
                    fixture.freeze_commit,
                    fixture.implementation_commit,
                )
                self.assertEqual(implementation_result["result"], "PASS")
                state = verifier_module()._implementation_state(
                    fixture.repo,
                    fixture.freeze_commit,
                    fixture.implementation_commit,
                )
                fixture.build_qualification(state)
                fixture.build_activation(state)
                result = verifier_module().verify_repository(
                    fixture.repo,
                    fixture.freeze_commit,
                    fixture.implementation_commit,
                    fixture.qualification_commit,
                    fixture.activation_commit,
                    fixture.activation_commit,
                )
        self.assertEqual(result["result"], "PASS")
        self.assertEqual(result["current_commit"], fixture.activation_commit)

    def test_ledger_fixture_passes(self):
        _base, rows, base_payload, completed_payload, reviewers = ledger_fixture()
        _frozen, observed = validate_fixture(base_payload, completed_payload, reviewers)
        self.assertEqual(observed, rows)

    def test_ledger_parser_rejects_crlf(self):
        _base, _rows, base_payload, _completed, _reviewers = ledger_fixture()
        with mock.patch.object(verifier_module(), "EXPECTED_LEDGER_ROWS", 4):
            self.assert_rejects(
                "LEDGER_ENCODING",
                verifier_module()._parse_ledger,
                base_payload.replace(b"\n", b"\r\n", 1),
            )

    def test_ledger_parser_rejects_noncanonical_quote(self):
        _base, _rows, base_payload, _completed, _reviewers = ledger_fixture()
        tampered = base_payload.replace(b"a.txt", b'"a.txt"', 1)
        with mock.patch.object(verifier_module(), "EXPECTED_LEDGER_ROWS", 4):
            self.assert_rejects(
                "LEDGER_NOT_CANONICAL", verifier_module()._parse_ledger, tampered
            )

    def test_ledger_parser_rejects_duplicate_path(self):
        base, _rows, _base_payload, _completed, _reviewers = ledger_fixture()
        base[1]["path"] = base[0]["path"]
        with mock.patch.object(verifier_module(), "EXPECTED_LEDGER_ROWS", 4):
            self.assert_rejects(
                "LEDGER_PATH_ORDER",
                verifier_module()._parse_ledger,
                render_ledger(base),
            )

    def test_immutable_drift_is_rejected(self):
        _base, rows, base_payload, _completed, reviewers = ledger_fixture()
        rows[0]["sha256"] = "f" * 64
        self.assert_rejects(
            "LEDGER_IMMUTABLE_DRIFT",
            validate_fixture,
            base_payload,
            render_ledger(rows),
            reviewers,
        )

    def test_unresolved_generated_is_rejected(self):
        _base, rows, base_payload, _completed, reviewers = ledger_fixture()
        rows[0]["generated"] = "UNKNOWN"
        self.assert_rejects(
            "LEDGER_UNRESOLVED_TRISTATE",
            validate_fixture,
            base_payload,
            render_ledger(rows),
            reviewers,
        )

    def test_known_generated_drift_is_rejected(self):
        _base, rows, base_payload, _completed, reviewers = ledger_fixture()
        rows[2]["generated"] = "YES"
        rows[2]["generator"] = "tools/release/current-file-review-ledger.py"
        self.assert_rejects(
            "LEDGER_CLASSIFICATION_CONTRACT",
            validate_fixture,
            base_payload,
            render_ledger(rows),
            reviewers,
        )

    def test_unknown_generated_resolution_needs_provenance(self):
        _base, rows, base_payload, _completed, reviewers = ledger_fixture()
        rows[0]["provenance_review_status"] = "NOT_APPLICABLE"
        rows[0]["provenance_evidence"] = ""
        self.assert_rejects(
            "LEDGER_CLASSIFICATION_CONTRACT",
            validate_fixture,
            base_payload,
            render_ledger(rows),
            reviewers,
        )

    def test_unregistered_reviewer_is_rejected(self):
        _base, rows, base_payload, _completed, reviewers = ledger_fixture()
        rows[0]["reviewer"] = "unknown@example.invalid"
        self.assert_rejects(
            "LEDGER_REVIEWER",
            validate_fixture,
            base_payload,
            render_ledger(rows),
            reviewers,
        )

    def test_adverse_disposition_is_rejected(self):
        _base, rows, base_payload, _completed, reviewers = ledger_fixture()
        rows[0]["disposition"] = "BLOCKED"
        self.assert_rejects(
            "LEDGER_DISPOSITION",
            validate_fixture,
            base_payload,
            render_ledger(rows),
            reviewers,
        )

    def test_invalid_completion_time_is_rejected(self):
        _base, rows, base_payload, _completed, reviewers = ledger_fixture()
        rows[0]["completed_at"] = "2026-02-30T00:00:00Z"
        self.assert_rejects(
            "LEDGER_COMPLETED_AT",
            validate_fixture,
            base_payload,
            render_ledger(rows),
            reviewers,
        )

    def test_provenance_na_cannot_keep_evidence(self):
        _base, rows, base_payload, _completed, reviewers = ledger_fixture()
        rows[2]["provenance_review_status"] = "NOT_APPLICABLE"
        self.assert_rejects(
            "LEDGER_CLASSIFICATION_CONTRACT",
            validate_fixture,
            base_payload,
            render_ledger(rows),
            reviewers,
        )

    def test_license_expression_is_frozen_spdx(self):
        _base, rows, base_payload, _completed, reviewers = ledger_fixture()
        rows[0]["license_expression"] = "Custom License"
        self.assert_rejects(
            "LEDGER_CLASSIFICATION_CONTRACT",
            validate_fixture,
            base_payload,
            render_ledger(rows),
            reviewers,
        )

    def test_license_na_has_exact_expression(self):
        _base, rows, base_payload, _completed, reviewers = ledger_fixture()
        rows[1]["license_expression"] = ""
        self.assert_rejects(
            "LEDGER_CLASSIFICATION_CONTRACT",
            validate_fixture,
            base_payload,
            render_ledger(rows),
            reviewers,
        )

    def test_generated_row_requires_inventory_generator(self):
        _base, rows, base_payload, _completed, reviewers = ledger_fixture()
        rows[1]["generator"] = "missing.py"
        self.assert_rejects(
            "LEDGER_CLASSIFICATION_CONTRACT",
            validate_fixture,
            base_payload,
            render_ledger(rows),
            reviewers,
        )

    def test_critical_row_requires_traceability(self):
        _base, rows, base_payload, _completed, reviewers = ledger_fixture()
        rows[0]["tests"] = ""
        self.assert_rejects(
            "LEDGER_CRITICAL_TRACEABILITY",
            validate_fixture,
            base_payload,
            render_ledger(rows),
            reviewers,
        )

    def test_unknown_language_is_rejected(self):
        _base, rows, base_payload, _completed, reviewers = ledger_fixture()
        rows[0]["language"] = "UNKNOWN"
        self.assert_rejects(
            "LEDGER_IMMUTABLE_DRIFT",
            validate_fixture,
            base_payload,
            render_ledger(rows),
            reviewers,
        )

    def test_formula_prefix_pointer_is_rejected(self):
        _base, rows, base_payload, _completed, reviewers = ledger_fixture()
        rows[0]["evidence"] = "=CH-T002-E08"
        self.assert_rejects(
            "LEDGER_REFERENCE",
            validate_fixture,
            base_payload,
            render_ledger(rows),
            reviewers,
        )

    def test_unsorted_pointer_tokens_are_rejected(self):
        self.assert_rejects(
            "TOKENS", verifier_module()._reference_tokens, "Z;A", "TOKENS"
        )

    def test_duplicate_pointer_tokens_are_rejected(self):
        self.assert_rejects(
            "TOKENS", verifier_module()._reference_tokens, "A;A", "TOKENS"
        )

    def test_canonical_json_round_trip(self):
        payload = b'{"a":1,"b":[true]}\n'
        self.assertEqual(
            verifier_module()._parse_canonical_json(payload, "JSON"),
            {"a": 1, "b": [True]},
        )

    def test_canonical_json_rejects_duplicate_key(self):
        self.assert_rejects(
            "JSON_DUPLICATE_KEY",
            verifier_module()._parse_canonical_json,
            b'{"a":1,"a":2}\n',
            "JSON",
        )

    def test_canonical_json_rejects_nonfinite(self):
        self.assert_rejects(
            "JSON_NONFINITE",
            verifier_module()._parse_canonical_json,
            b'{"a":NaN}\n',
            "JSON",
        )

    def test_canonical_json_rejects_pretty_encoding(self):
        self.assert_rejects(
            "JSON_NOT_CANONICAL",
            verifier_module()._parse_canonical_json,
            b'{\n  "a": 1\n}\n',
            "JSON",
        )

    def test_json_nesting_bound_is_enforced(self):
        payload = b'{"x":' + b"[" * 33 + b"0" + b"]" * 33 + b"}\n"
        self.assert_rejects(
            "TEST_DEPTH", verifier_module()._parse_json, payload, "TEST"
        )

    def test_path_rejects_escape(self):
        self.assert_rejects(
            "PATH_NOT_CANONICAL", verifier_module()._canonical_path, "../x"
        )

    def test_path_rejects_git_admin(self):
        self.assert_rejects(
            "PATH_NOT_CANONICAL", verifier_module()._canonical_path, ".git/config"
        )

    def test_portable_collision_is_rejected(self):
        self.assert_rejects(
            "COLLISION",
            verifier_module()._portable_unique,
            ["A.txt", "a.txt"],
            "COLLISION",
        )

    def test_freeze_fixture_passes(self):
        evidence, reviews, activation = verifier_module()._validate_freeze(
            freeze_fixture()
        )
        self.assertEqual((len(evidence), len(reviews), len(activation)), (13, 4, 5))

    def test_freeze_binds_human_review_focus_and_exact_limitation(self):
        freeze = freeze_fixture()
        verifier_module()._validate_freeze(freeze)
        self.assertEqual(
            freeze["task_identity"], verifier_module().EXPECTED_TASK_IDENTITY
        )
        self.assertIn(
            verifier_module().HUMAN_REVIEW_LIMITATION,
            freeze["claim_outcomes"][0]["limitations"],
        )

    def test_freeze_rejects_human_review_focus_or_limitation_drift(self):
        for target in ("focus", "limitation"):
            freeze = freeze_fixture()
            if target == "focus":
                freeze["task_identity"]["focus"] = "automated review coverage"
                code = "FREEZE_TASK_IDENTITY"
            else:
                freeze["claim_outcomes"][0]["limitations"] = ["Review complete."]
                code = "FREEZE_OUTCOME_BOUNDARY"
            with self.subTest(target=target):
                self.assert_rejects(code, verifier_module()._validate_freeze, freeze)

    def test_freeze_rejects_duplicate_reviewer_key(self):
        freeze = freeze_fixture()
        freeze["reviewer_registry"][1]["public_key"] = freeze["reviewer_registry"][0][
            "public_key"
        ]
        freeze["reviewer_registry"][1]["key_fingerprint"] = freeze["reviewer_registry"][
            0
        ]["key_fingerprint"]
        self.assert_rejects(
            "FREEZE_REVIEWER_SEPARATION", verifier_module()._validate_freeze, freeze
        )

    def test_freeze_rejects_non_resolvable_reviewer_principal(self):
        freeze = freeze_fixture()
        freeze["reviewer_registry"][0]["reviewer"]["principal"] = "not a principal"
        self.assert_rejects(
            "FREEZE_REVIEWER_PRINCIPAL", verifier_module()._validate_freeze, freeze
        )

    def test_freeze_rejects_nonautomated_reviewer_classification(self):
        freeze = freeze_fixture()
        freeze["reviewer_registry"][0]["reviewer"]["classification"] = (
            "INDEPENDENT_HUMAN"
        )
        self.assert_rejects(
            "FREEZE_REVIEWER_BINDING", verifier_module()._validate_freeze, freeze
        )

    def test_c_review_automation_boundary_rejects_boolean_drift(self):
        record = {
            "reviewer": {"classification": "INDEPENDENT_AUTOMATED"},
            "independent_from_release_author": True,
            "external": False,
            "human": False,
            "named_human_reviewer": False,
            "release_approver": False,
            "decision": "ACCEPT_TECHNICAL_TASK_QUALIFICATION",
        }
        verifier_module()._validate_automated_review_flags(record, lead=False)
        for field in ("external", "human", "named_human_reviewer", "release_approver"):
            mutated = copy.deepcopy(record)
            mutated[field] = True
            with self.subTest(field=field):
                self.assert_rejects(
                    "QUALIFICATION_REVIEW_AUTOMATION_BOUNDARY",
                    verifier_module()._validate_automated_review_flags,
                    mutated,
                    lead=False,
                )

    def test_freeze_rejects_go_outcome(self):
        freeze = freeze_fixture()
        freeze["claim_outcomes"][0]["overall_status"] = "GO"
        self.assert_rejects(
            "FREEZE_OUTCOME_BOUNDARY", verifier_module()._validate_freeze, freeze
        )

    def test_freeze_rejects_wrong_verifier_budget(self):
        freeze = freeze_fixture()
        freeze["resource_budgets"]["verifier_seconds"] = 11
        self.assert_rejects(
            "FREEZE_VERIFIER_BUDGET", verifier_module()._validate_freeze, freeze
        )

    def test_registration_is_exact_append_only(self):
        payloads = {
            verifier_module().VERIFIER_PATH: b"verifier\n",
            verifier_module().REGISTERED_TESTS_PATH: b"tests\n",
            verifier_module().FREEZE_PATH: b"freeze\n",
        }
        entries = {
            path: {
                "mode": "100644",
                "type": "blob",
                "oid": verifier_module()._git_blob_id(payload),
                "size": len(payload),
            }
            for path, payload in payloads.items()
        }
        blobs = {entries[path]["oid"]: payload for path, payload in payloads.items()}
        base = {"append_only": True, "registrations": []}
        current = copy.deepcopy(base)
        current["registrations"].append(
            {
                "task_id": verifier_module().TASK_ID,
                "epoch": verifier_module().EPOCH,
                "verifier": verifier_module()._file_record(
                    verifier_module().VERIFIER_PATH,
                    entries[verifier_module().VERIFIER_PATH],
                    payloads[verifier_module().VERIFIER_PATH],
                ),
                "tests": verifier_module()._file_record(
                    verifier_module().REGISTERED_TESTS_PATH,
                    entries[verifier_module().REGISTERED_TESTS_PATH],
                    payloads[verifier_module().REGISTERED_TESTS_PATH],
                ),
                "freeze_contract": verifier_module()._file_record(
                    verifier_module().FREEZE_PATH,
                    entries[verifier_module().FREEZE_PATH],
                    payloads[verifier_module().FREEZE_PATH],
                ),
                "qualification_path": verifier_module().QUALIFICATION_PATH,
                "activation_path": verifier_module().ACTIVATION_PATH,
                "verifier_receipt_path": verifier_module().RECEIPT_PATH,
                "effective_on": "SIGNED_COMMIT_FIRST_CONTAINING_EXACT_REGISTRATION_FREEZE_AND_GATES",
            }
        )
        verifier_module()._validate_registration(
            current, base, f_entries=entries, f_blobs=blobs
        )
        current["append_only"] = False
        self.assert_rejects(
            "REGISTRATION_METADATA_DRIFT",
            verifier_module()._validate_registration,
            current,
            base,
            f_entries=entries,
            f_blobs=blobs,
        )

    def test_overlay_structure_passes(self):
        freeze = freeze_fixture()
        overlay = overlay_fixture(freeze)
        context = overlay_context(freeze, overlay)
        catalogs, entries = verifier_module()._validate_overlay_structure(
            overlay, **context
        )
        self.assertEqual((len(catalogs), len(entries)), (4, 1))

    def test_overlay_rejects_second_ledger_semantics(self):
        freeze = freeze_fixture()
        overlay = overlay_fixture(freeze)
        overlay["scope"]["kind"] = "SECOND_LEDGER"
        context = overlay_context(freeze, overlay)
        self.assert_rejects(
            "OVERLAY_SCOPE",
            verifier_module()._validate_overlay_structure,
            overlay,
            **context,
        )

    def test_overlay_rejects_base_commit_drift(self):
        freeze = freeze_fixture()
        overlay = overlay_fixture(freeze)
        overlay["base_partition"]["commit"] = "0" * 40
        context = overlay_context(freeze, overlay)
        self.assert_rejects(
            "OVERLAY_BASE_BINDING",
            verifier_module()._validate_overlay_structure,
            overlay,
            **context,
        )

    def test_overlay_rejects_incomplete_evidence_catalog(self):
        freeze = freeze_fixture()
        overlay = overlay_fixture(freeze)
        overlay["scope"]["evidence_catalog"].pop()
        context = overlay_context(freeze, overlay)
        self.assert_rejects(
            "OVERLAY_EVIDENCE_CATALOG",
            verifier_module()._validate_overlay_structure,
            overlay,
            **context,
        )

    def test_overlay_rejects_non_normative_requirement_catalog(self):
        freeze = freeze_fixture()
        overlay = overlay_fixture(freeze)
        overlay["scope"]["requirement_catalog"] = ["CH-T002-R01"]
        context = overlay_context(freeze, overlay)
        self.assert_rejects(
            "OVERLAY_REQUIREMENT_CATALOG",
            verifier_module()._validate_overlay_structure,
            overlay,
            **context,
        )

    def test_overlay_rejects_central_registry_as_reviewer_registry(self):
        freeze = freeze_fixture()
        overlay = overlay_fixture(freeze)
        overlay["review_policy"]["registry"]["path"] = verifier_module().REGISTRY_PATH
        context = overlay_context(freeze, overlay)
        self.assert_rejects(
            "OVERLAY_REGISTRY_BINDING",
            verifier_module()._validate_overlay_structure,
            overlay,
            **context,
        )

    def test_overlay_rejects_lane_key_reuse(self):
        freeze = freeze_fixture()
        overlay = overlay_fixture(freeze)
        overlay["review_policy"]["lanes"][1]["reviewer_fingerprint"] = overlay[
            "review_policy"
        ]["lanes"][0]["reviewer_fingerprint"]
        context = overlay_context(freeze, overlay)
        self.assert_rejects(
            "OVERLAY_LANE_BINDING",
            verifier_module()._validate_overlay_structure,
            overlay,
            **context,
        )

    def test_overlay_rejects_subject_id_drift(self):
        freeze = freeze_fixture()
        overlay = overlay_fixture(freeze)
        overlay["entries"][0]["subject_id"] = "0" * 64
        context = overlay_context(freeze, overlay)
        self.assert_rejects(
            "OVERLAY_ENTRY_SUBJECT_ID",
            verifier_module()._validate_overlay_structure,
            overlay,
            **context,
        )

    def test_overlay_rejects_missing_criticality(self):
        freeze = freeze_fixture()
        overlay = overlay_fixture(freeze)
        overlay["entries"][0]["criticality"] = []
        context = overlay_context(freeze, overlay)
        self.assert_rejects(
            "OVERLAY_ENTRY_CLASSIFICATION",
            verifier_module()._validate_overlay_structure,
            overlay,
            **context,
        )

    def test_overlay_rejects_implementation_identity_claim(self):
        freeze = freeze_fixture()
        overlay = overlay_fixture(freeze)
        overlay["implementation_boundary"]["content_identities_in_overlay"] = True
        context = overlay_context(freeze, overlay)
        self.assert_rejects(
            "OVERLAY_IMPLEMENTATION_BOUNDARY",
            verifier_module()._validate_overlay_structure,
            overlay,
            **context,
        )

    def test_qualified_evidence_pointers_resolve_to_exact_subject_roles(self):
        rows, catalogs, classifications, subjects = catalog_binding_fixture()
        self.assertIsNone(
            verifier_module()._validate_catalog_bindings(
                rows, catalogs, classifications, subjects
            )
        )

    def test_malformed_qualified_evidence_pointer_is_rejected(self):
        rows, catalogs, classifications, subjects = catalog_binding_fixture()
        tokens = rows[0]["evidence"].split(";")
        tokens[0] = tokens[0].replace(tokens[0].split("#")[1][:64], "A" * 64)
        rows[0]["evidence"] = ";".join(sorted(tokens))
        self.assert_rejects(
            "CATALOG_POINTER",
            verifier_module()._validate_catalog_bindings,
            rows,
            catalogs,
            classifications,
            subjects,
        )

    def test_evidence_pointer_rejects_wrong_subject_hash(self):
        rows, catalogs, classifications, subjects = catalog_binding_fixture()
        rows[0]["provenance_evidence"] = f"CH-T002-E09#{'0' * 64}:PROVENANCE"
        self.assert_rejects(
            "CATALOG_POINTER",
            verifier_module()._validate_catalog_bindings,
            rows,
            catalogs,
            classifications,
            subjects,
        )

    def test_evidence_pointer_rejects_removed_role(self):
        rows, catalogs, classifications, subjects = catalog_binding_fixture()
        tokens = rows[0]["evidence"].split(";")
        tokens[0] = tokens[0].rsplit(":", 1)[0] + ":REMOVED"
        rows[0]["evidence"] = ";".join(sorted(tokens))
        self.assert_rejects(
            "CATALOG_POINTER",
            verifier_module()._validate_catalog_bindings,
            rows,
            catalogs,
            classifications,
            subjects,
        )

    def test_subject_id_is_domain_bound(self):
        subject = subject_fixture(1)
        identity = {
            key: subject[key]
            for key in (
                "bytes",
                "content_kind",
                "git_mode",
                "git_object_id",
                "lines",
                "path",
                "sha256",
            )
        }
        expected = verifier_module()._domain_digest(
            "haldir-ch-t002-review-subject-v1", identity
        )
        self.assertEqual(subject["subject_id"], expected)

    def test_content_classifier_text_binary_and_ansi(self):
        self.assertEqual(
            verifier_module()._classify_content(b"a\nb\n"), ("TEXT_UTF8", 2)
        )
        self.assertEqual(verifier_module()._classify_content(b"a\0b"), ("BINARY", None))
        self.assertEqual(
            verifier_module()._classify_content(b"\x1b[31mred\x1b[0m\n"),
            ("TEXT_UTF8_WITH_ANSI_ESCAPE", 1),
        )

    def test_binary_units_are_ceiling_chunks(self):
        subject = subject_fixture(1, binary=True)
        self.assertEqual(subject["units"], 2)

    def test_lane_assignment_is_complete_and_secondary_is_distinct(self):
        freeze = freeze_fixture()
        overlay = overlay_fixture(freeze)
        subjects = [
            subject_fixture(index, critical=index % 2 == 0) for index in range(1, 10)
        ]
        rows = [
            {"path": subject["path"], "reviewer": "", "evidence": ""}
            for subject in subjects
        ]
        provisional = verifier_module().assign_subjects(
            subjects,
            freeze=freeze,
            overlay=overlay,
            rows=[],
            classification_by_path=subject_classification_records(subjects),
        )
        primary_assignment = {
            item["path"]: (lane["number"], lane["reviewer"]["principal"], item)
            for lane in provisional
            for item in lane["primary"]
        }
        secondary_lane = {
            item["subject_id"]: lane["number"]
            for lane in provisional
            for item in lane["secondary"]
        }
        for row in rows:
            primary_lane, principal, subject = primary_assignment[row["path"]]
            row["reviewer"] = principal
            evidence = {
                f"CH-T002-E09#{subject['subject_id']}:PRIMARY",
                f"CH-T002-E{9 + primary_lane:02d}#{subject['subject_id']}:PRIMARY",
            }
            if subject["criticality"]:
                second = secondary_lane[subject["subject_id"]]
                evidence.update(
                    {
                        f"CH-T002-E09#{subject['subject_id']}:SECONDARY",
                        f"CH-T002-E{9 + second:02d}#{subject['subject_id']}:SECONDARY",
                    }
                )
            row["evidence"] = ";".join(sorted(evidence))
            row.update(
                {
                    "public_surface": "NO",
                    "security_critical": "YES"
                    if "SECURITY_CRITICAL" in subject["criticality"]
                    else "NO",
                    "science_critical": "NO",
                    "authority_critical": "NO",
                    "provenance_review_status": "CONFIRMED",
                    "provenance_evidence": f"CH-T002-E09#{subject['subject_id']}:PROVENANCE",
                    "license_review_status": "APPROVED",
                    "license_expression": "Apache-2.0 OR MIT",
                    "license_evidence": f"CH-T002-E09#{subject['subject_id']}:LICENSE",
                    "disposition": "ACCEPTED",
                }
            )
        lanes = verifier_module().assign_subjects(
            subjects,
            freeze=freeze,
            overlay=overlay,
            rows=rows,
            classification_by_path=subject_classification_records(subjects),
        )
        self.assertEqual(sum(len(lane["primary"]) for lane in lanes), len(subjects))
        for subject in (item for item in subjects if item["criticality"]):
            primary = next(
                lane["number"] for lane in lanes if subject in lane["primary"]
            )
            secondary = next(
                lane["number"] for lane in lanes if subject in lane["secondary"]
            )
            self.assertNotEqual(primary, secondary)

    def test_lane_assignment_rejects_missing_subject_evidence(self):
        freeze = freeze_fixture()
        overlay = overlay_fixture(freeze)
        subjects = [subject_fixture(index) for index in range(1, 4)]
        subject = subjects[0]
        provisional = verifier_module().assign_subjects(
            subjects,
            freeze=freeze,
            overlay=overlay,
            rows=[],
            classification_by_path=subject_classification_records(subjects),
        )
        principal = next(
            lane["reviewer"]["principal"]
            for lane in provisional
            if subject in lane["primary"]
        )
        rows = [
            {
                "path": subject["path"],
                "reviewer": principal,
                "evidence": "",
                "public_surface": "NO",
                "security_critical": "NO",
                "science_critical": "NO",
                "authority_critical": "NO",
                "provenance_review_status": "CONFIRMED",
                "provenance_evidence": f"CH-T002-E09#{subject['subject_id']}:PROVENANCE",
                "license_review_status": "APPROVED",
                "license_expression": "Apache-2.0 OR MIT",
                "license_evidence": f"CH-T002-E09#{subject['subject_id']}:LICENSE",
                "disposition": "ACCEPTED",
            }
        ]
        self.assert_rejects(
            "LEDGER_ASSIGNMENT_EVIDENCE",
            verifier_module().assign_subjects,
            subjects,
            freeze=freeze,
            overlay=overlay,
            rows=rows,
            classification_by_path=subject_classification_records(subjects),
        )

    def test_lane_assignment_rejects_wrong_ledger_principal(self):
        freeze = freeze_fixture()
        overlay = overlay_fixture(freeze)
        subject = subject_fixture(1)
        rows = [{"path": subject["path"], "reviewer": "wrong@example.invalid"}]
        self.assert_rejects(
            "LEDGER_ASSIGNMENT_REGISTRY",
            verifier_module().assign_subjects,
            [subject],
            freeze=freeze,
            overlay=overlay,
            rows=rows,
            classification_by_path=subject_classification_records([subject]),
        )

    def test_packet_subject_coverage_binds_full_blob(self):
        subject = subject_fixture(1)
        record = verifier_module()._subject_packet_record(
            subject, freeze_commit="f" * 40, freeze_tree="e" * 40
        )
        self.assertEqual(
            record["coverage"]["byte_interval"],
            {"start_inclusive": 0, "end_exclusive": subject["bytes"]},
        )
        self.assertEqual(
            record["coverage"]["line_interval"],
            {"start_inclusive": 1, "end_inclusive": subject["lines"]},
        )
        self.assertEqual(
            record["coverage"]["read_command"][-1], subject["git_object_id"]
        )

    def test_packet_binary_coverage_has_exact_chunks(self):
        subject = subject_fixture(1, binary=True)
        record = verifier_module()._subject_packet_record(
            subject, freeze_commit="f" * 40, freeze_tree="e" * 40
        )
        self.assertEqual(
            record["coverage"]["chunk_count"], math.ceil(subject["bytes"] / 4096)
        )
        self.assertIsNone(record["coverage"]["line_interval"])

    def test_packet_bodies_and_manifest_are_reproducible(self):
        freeze = freeze_fixture()
        overlay = overlay_fixture(freeze)
        subjects = [
            subject_fixture(index, critical=index == 2) for index in range(1, 7)
        ]
        lanes = verifier_module().assign_subjects(
            subjects,
            freeze=freeze,
            overlay=overlay,
            rows=[],
            classification_by_path=subject_classification_records(subjects),
        )
        blobs = {b"ledger\n": None, b"overlay\n": None}
        payloads = list(blobs)
        entries = {
            verifier_module().LEDGER_PATH: {
                "oid": verifier_module()._git_blob_id(payloads[0]),
                "mode": "100644",
                "type": "blob",
                "size": len(payloads[0]),
            },
            verifier_module().OVERLAY_PATH: {
                "oid": verifier_module()._git_blob_id(payloads[1]),
                "mode": "100644",
                "type": "blob",
                "size": len(payloads[1]),
            },
        }
        object_payloads = {
            entries[verifier_module().LEDGER_PATH]["oid"]: payloads[0],
            entries[verifier_module().OVERLAY_PATH]["oid"]: payloads[1],
        }
        registry_payload = b"registry\n"
        registry_entry = {
            "oid": verifier_module()._git_blob_id(registry_payload),
            "mode": "100644",
            "type": "blob",
            "size": len(registry_payload),
        }
        bodies, manifest = verifier_module().build_packet_bodies(
            subjects=subjects,
            lanes=lanes,
            overlay=overlay,
            freeze_commit="f" * 40,
            freeze_tree="e" * 40,
            implementation_commit="d" * 40,
            implementation_tree="c" * 40,
            implementation_entries=entries,
            implementation_blobs=object_payloads,
            registry_entry=registry_entry,
            registry_payload=registry_payload,
        )
        self.assertEqual(set(bodies), {"lane-01", "lane-02", "lane-03"})
        self.assertEqual(manifest["review_subjects"], len(subjects))
        self.assertTrue(all(body["result"] == "PASS" for body in bodies.values()))
        self.assertEqual(
            set(manifest["overlay_reconciliation"]),
            EXPECTED_MANIFEST_RECONCILIATION_KEYS,
        )
        self.assertEqual(
            set(product_module().SCHEMA["manifest"]["overlay_reconciliation"]),
            EXPECTED_MANIFEST_RECONCILIATION_KEYS,
        )

    def test_packet_cap_is_strict(self):
        freeze = freeze_fixture()
        overlay = overlay_fixture(freeze)
        subjects = [subject_fixture(index) for index in range(1, 4)]
        lanes = verifier_module().assign_subjects(
            subjects,
            freeze=freeze,
            overlay=overlay,
            rows=[],
            classification_by_path=subject_classification_records(subjects),
        )
        payload = b"x"
        entries = {
            verifier_module().LEDGER_PATH: {
                "oid": verifier_module()._git_blob_id(payload),
                "mode": "100644",
                "type": "blob",
                "size": 1,
            },
            verifier_module().OVERLAY_PATH: {
                "oid": verifier_module()._git_blob_id(payload),
                "mode": "100644",
                "type": "blob",
                "size": 1,
            },
        }
        blobs = {verifier_module()._git_blob_id(payload): payload}
        registry = {
            "oid": verifier_module()._git_blob_id(payload),
            "mode": "100644",
            "type": "blob",
            "size": 1,
        }
        with mock.patch.object(verifier_module(), "MAX_PACKET_BYTES", 1):
            self.assert_rejects(
                "PACKET_BYTE_BOUND",
                verifier_module().build_packet_bodies,
                subjects=subjects,
                lanes=lanes,
                overlay=overlay,
                freeze_commit="f" * 40,
                freeze_tree="e" * 40,
                implementation_commit="d" * 40,
                implementation_tree="c" * 40,
                implementation_entries=entries,
                implementation_blobs=blobs,
                registry_entry=registry,
                registry_payload=payload,
            )

    def test_review_attestation_payload_excludes_signature(self):
        record = {"id": "CH-T002-R01", "detached_signature": {"signature": "x"}}
        payload = verifier_module()._review_attestation_payload(
            record, "f" * 40, "e" * 40
        )
        parsed = json.loads(payload)
        self.assertNotIn("detached_signature", parsed["review_record"])

    def test_public_key_fingerprint_is_stable(self):
        key, fingerprint = fake_key(7)
        self.assertEqual(verifier_module()._public_key_fingerprint(key), fingerprint)

    def test_public_key_rejects_non_wire_ed25519_bytes(self):
        malformed = "ssh-ed25519 " + base64.b64encode(b"x" * 32).decode("ascii")
        self.assert_rejects(
            "PUBLIC_KEY", verifier_module()._public_key_fingerprint, malformed
        )

    def test_log_archive_rejects_non_zip(self):
        self.assert_rejects(
            "ACTIVATION_ARCHIVE_INVALID",
            verifier_module()._validate_log_archive,
            b"not zip",
        )

    def classification_patches(self, overlay, digest):
        contract = overlay["review_classification_contract"]
        policy = contract["override_policy"]
        stack = contextlib.ExitStack()
        for name, value in (
            (
                "AUDITED_CURRENT_A_PATHS",
                contract["counts"]["source_current_a"]["paths"],
            ),
            (
                "EXPECTED_LEDGER_ROWS",
                contract["counts"]["final_historical_ledger_subjects"]["paths"],
            ),
            ("EXPECTED_F_EXTENSION_CLASSIFICATIONS", {}),
            ("EXPECTED_GITIGNORE_OVERRIDE", None),
            ("EXPECTED_CLASSIFICATION_OVERRIDE_PATHS", policy["path_count"]),
            (
                "EXPECTED_CLASSIFICATION_OVERRIDE_FIELDS",
                policy["field_override_count"],
            ),
            (
                "EXPECTED_CLASSIFICATION_OVERRIDE_SET_SHA256",
                verifier_module()._domain_digest(
                    verifier_module().CLASSIFICATION_OVERRIDE_DIGEST_DOMAIN,
                    policy["overrides"],
                ),
            ),
            (
                "EXPECTED_SOURCE_CURRENT_A_COUNTS",
                contract["counts"]["source_current_a"],
            ),
            ("EXPECTED_F_CLASSIFICATION_SET_SHA256", digest),
        ):
            stack.enter_context(mock.patch.object(verifier_module(), name, value))
        return stack

    def test_frozen_vector_decision_tables_are_exact_and_resolvable(self):
        for prefix, bindings in (
            ("CH-T002-N", verifier_module().NORMATIVE_CONTROL_BINDINGS),
            ("CH-T002-CF", verifier_module().COUNTERFACTUAL_BINDINGS),
        ):
            for index, binding in enumerate(bindings, 1):
                statement, accepted, rejected, predicate, failure = binding
                self.assertTrue(statement)
                self.assertTrue(hasattr(self, accepted), f"{prefix}{index:02d}")
                self.assertTrue(hasattr(self, rejected), f"{prefix}{index:02d}")
                self.assertTrue(callable(getattr(verifier_module(), predicate)))
                self.assertTrue(failure)

    def test_n01_accepted(self):
        evidence, reviews, activation = verifier_module()._validate_freeze(
            freeze_fixture()
        )
        self.assertEqual((len(evidence), len(reviews), len(activation)), (13, 4, 5))

    def test_actual_frozen_command_mapping_matches_runnable_contract(self):
        root = Path(__file__).resolve().parents[5]
        freeze = verifier_module()._parse_pretty_json(
            (root / verifier_module().FREEZE_PATH).read_bytes(), "ACTUAL_FREEZE"
        )
        f_commit, i_commit = "1" * 40, "2" * 40
        observed = verifier_module()._expected_qualification_argv(
            freeze, f_commit, i_commit
        )[:7]
        expected = []
        for command in qualification_replacement_commands():
            argv = verifier_module()._substitute_lifecycle_tokens(
                command, freeze_commit=f_commit, implementation_commit=i_commit
            )
            expected.append((verifier_module()._qualification_phase(argv), argv))
        self.assertEqual(observed, expected)
        by_phase = dict(observed)
        for phase in ("PACKET_RENDER", "PACKET_VERIFY"):
            argv = by_phase[phase]
            self.assertNotIn("generate", argv)
            self.assertNotIn("--freeze-commit", argv)
            self.assertIn("--implementation-commit", argv)
            self.assertIn("--reviewer-registry", argv)

    def test_n01_rejected(self):
        freeze = freeze_fixture()
        freeze["author"]["name"] = "Different Author"
        self.assert_rejects(
            "FREEZE_IDENTITY", verifier_module()._validate_freeze, freeze
        )

    def test_n02_accepted(self):
        freeze = freeze_fixture()
        verifier_module()._validate_freeze(freeze)
        self.assertEqual(
            freeze["implementation_plan"], verifier_module().EXPECTED_I_DIFF
        )

    def test_n02_rejected(self):
        freeze = freeze_fixture()
        freeze["implementation_plan"].pop(next(iter(verifier_module().EXPECTED_I_DIFF)))
        self.assert_rejects(
            "FREEZE_IMPLEMENTATION_PLAN", verifier_module()._validate_freeze, freeze
        )

    def test_n03_accepts_exact_frozen_classification_contract(self):
        overlay, f_entries, digest = minimal_classification_contract_fixture()
        with self.classification_patches(overlay, digest):
            observed = verifier_module()._validate_classification_contract(
                overlay, f_entries, f_entries
            )
        self.assertEqual(set(observed), set(f_entries))

    def test_n03_rejects_classification_contract_drift(self):
        overlay, f_entries, digest = minimal_classification_contract_fixture()
        overlay["review_classification_contract"]["records"][0]["public_surface"] = (
            "YES"
        )
        with self.classification_patches(overlay, digest):
            self.assert_rejects(
                "CLASSIFICATION_RULE_FLAG",
                verifier_module()._validate_classification_contract,
                overlay,
                f_entries,
                f_entries,
            )

    def test_frozen_gitignore_public_surface_override_is_exact(self):
        self.assertNotEqual(
            verifier_module().BASELINE_COMMIT,
            verifier_module().CLASSIFICATION_AUDIT_COMMIT,
        )
        self.assertEqual(len(verifier_module().EXPECTED_F_EXTENSION_CLASSIFICATIONS), 7)
        self.assertEqual(
            verifier_module().EXPECTED_CLASSIFICATION_OVERRIDE_SET_SHA256,
            "a9887d37596ef35afc758828e2b1726bd917bd3374f83395db7765b6996761e6",
        )
        self.assertEqual(
            verifier_module().EXPECTED_F_CLASSIFICATION_SET_SHA256,
            "543e0946ed31da0fca3b7bdb184847d9fe68ab03154e3bf17b57869d0a77a051",
        )
        self.assertEqual(
            verifier_module().EXPECTED_GITIGNORE_OVERRIDE,
            {
                "after": "YES",
                "before": "NO",
                "field": "public_surface",
                "path": ".gitignore",
                "rule_id": "PUB_YES_BUILD_OR_DEPLOYMENT_AFFECTED_SURFACE",
                "source_basis": verifier_module().CLASSIFICATION_OVERRIDE_SOURCE_BASIS,
            },
        )

    def test_classification_accepts_bidirectional_and_atomic_overrides(self):
        overlay, f_entries, historical, digest = (
            generalized_classification_contract_fixture()
        )
        with self.classification_patches(overlay, digest):
            records = verifier_module()._validate_classification_contract(
                overlay, f_entries, historical
            )
        self.assertEqual(records["a.txt"]["authority_critical"], "NO")
        self.assertEqual(
            (records["b.txt"]["generated"], records["b.txt"]["generator"]),
            ("YES", "generator.py"),
        )
        counts = overlay["review_classification_contract"]["counts"]
        self.assertEqual(counts["final_historical_ledger_subjects"]["generated_yes"], 0)
        self.assertEqual(counts["final_current_a"]["generated_yes"], 1)

    def test_classification_rejects_nonatomic_generated_override(self):
        overlay, f_entries, historical, digest = (
            generalized_classification_contract_fixture()
        )
        policy = overlay["review_classification_contract"]["override_policy"]
        policy["overrides"] = [
            row for row in policy["overrides"] if row["field"] != "generator"
        ]
        policy["field_override_count"] -= 1
        with self.classification_patches(overlay, digest):
            self.assert_rejects(
                "CLASSIFICATION_OVERRIDE_GENERATOR_ATOMIC",
                verifier_module()._validate_classification_contract,
                overlay,
                f_entries,
                historical,
            )

    def test_classification_rejects_override_before_value_drift(self):
        overlay, f_entries, historical, digest = (
            generalized_classification_contract_fixture()
        )
        overlay["review_classification_contract"]["override_policy"]["overrides"][2][
            "before"
        ] = "old-generator.py"
        original, _entries, _historical, _digest = (
            generalized_classification_contract_fixture()
        )
        with self.classification_patches(original, digest):
            self.assert_rejects(
                "CLASSIFICATION_OVERRIDE_SET_DIGEST",
                verifier_module()._validate_classification_contract,
                overlay,
                f_entries,
                historical,
            )

    def test_classification_rejects_override_after_or_rule_mismatch(self):
        for field, value in (("after", "other.py"), ("rule_id", "GEN_YES_WRONG")):
            overlay, f_entries, historical, digest = (
                generalized_classification_contract_fixture()
            )
            overlay["review_classification_contract"]["override_policy"]["overrides"][
                2
            ][field] = value
            with self.classification_patches(overlay, digest):
                self.assert_rejects(
                    "CLASSIFICATION_OVERRIDE_BINDING",
                    verifier_module()._validate_classification_contract,
                    overlay,
                    f_entries,
                    historical,
                )

    def test_classification_rejects_override_order_duplicate_and_path_drift(self):
        for mutation, code in (
            (lambda policy: policy["overrides"].reverse(), "ROW_ORDER"),
            (
                lambda policy: policy["overrides"].append(
                    copy.deepcopy(policy["overrides"][-1])
                ),
                "ROW_ORDER",
            ),
            (lambda policy: policy["paths"].reverse(), "COUNTS"),
        ):
            overlay, f_entries, historical, digest = (
                generalized_classification_contract_fixture()
            )
            policy = overlay["review_classification_contract"]["override_policy"]
            mutation(policy)
            with self.classification_patches(overlay, digest):
                self.assert_rejects(
                    f"CLASSIFICATION_OVERRIDE_{code}",
                    verifier_module()._validate_classification_contract,
                    overlay,
                    f_entries,
                    historical,
                )

    def test_classification_rejects_unregistered_override_field(self):
        overlay, f_entries, historical, digest = (
            generalized_classification_contract_fixture()
        )
        overlay["review_classification_contract"]["override_policy"]["overrides"][0][
            "field"
        ] = "license_review_status"
        with self.classification_patches(overlay, digest):
            self.assert_rejects(
                "CLASSIFICATION_OVERRIDE_ROW_VALUE",
                verifier_module()._validate_classification_contract,
                overlay,
                f_entries,
                historical,
            )

    def test_classification_override_digest_rejects_coordinated_rule_drift(self):
        overlay, f_entries, historical, digest = (
            generalized_classification_contract_fixture()
        )
        original, _entries, _historical, _digest = (
            generalized_classification_contract_fixture()
        )
        record = overlay["review_classification_contract"]["records"][0]
        row = overlay["review_classification_contract"]["override_policy"]["overrides"][
            0
        ]
        record["rule_ids"][3] = row["rule_id"] = "AUTH_NO_COORDINATED_DRIFT"
        with self.classification_patches(original, digest):
            self.assert_rejects(
                "CLASSIFICATION_OVERRIDE_SET_DIGEST",
                verifier_module()._validate_classification_contract,
                overlay,
                f_entries,
                historical,
            )

    def test_n04_accepted(self):
        _base, _rows, base_payload, completed_payload, reviewers = ledger_fixture()
        base, completed = validate_fixture(base_payload, completed_payload, reviewers)
        self.assertEqual(len(base), len(completed))

    def test_n04_rejected(self):
        _base, rows, base_payload, _completed_payload, reviewers = ledger_fixture()
        rows[0]["sha256"] = "f" * 64
        self.assert_rejects(
            "LEDGER_IMMUTABLE_DRIFT",
            validate_fixture,
            base_payload,
            render_ledger(rows),
            reviewers,
        )

    def test_n05_accepted(self):
        freeze = freeze_fixture()
        overlay = overlay_fixture(freeze)
        catalogs, _entries = verifier_module()._validate_overlay_structure(
            overlay, **overlay_context(freeze, overlay)
        )
        self.assertEqual(
            catalogs["evidence_catalog"], frozenset(verifier_module().EVIDENCE_PATHS)
        )

    def test_n05_rejected(self):
        freeze = freeze_fixture()
        overlay = overlay_fixture(freeze)
        overlay["scope"]["evidence_catalog"].pop()
        self.assert_rejects(
            "OVERLAY_EVIDENCE_CATALOG",
            verifier_module()._validate_overlay_structure,
            overlay,
            **overlay_context(freeze, overlay),
        )

    def test_n06_accepted(self):
        freeze = freeze_fixture()
        overlay = overlay_fixture(freeze)
        verifier_module()._validate_overlay_structure(
            overlay, **overlay_context(freeze, overlay)
        )
        self.assertEqual(overlay["removed_paths"], [])

    def test_n06_rejected(self):
        freeze = freeze_fixture()
        overlay = overlay_fixture(freeze)
        overlay["removed_paths"] = [{"path": "deleted.txt"}]
        self.assert_rejects(
            "OVERLAY_REMOVALS_FORBIDDEN",
            verifier_module()._validate_overlay_structure,
            overlay,
            **overlay_context(freeze, overlay),
        )

    def test_n07_accepted(self):
        freeze = freeze_fixture()
        overlay = overlay_fixture(freeze)
        subjects = [
            subject_fixture(index, critical=index % 2 == 0) for index in range(1, 7)
        ]
        lanes = verifier_module().assign_subjects(
            subjects,
            freeze=freeze,
            overlay=overlay,
            rows=[],
            classification_by_path=subject_classification_records(subjects),
        )
        self.assertEqual(sum(len(lane["primary"]) for lane in lanes), len(subjects))
        self.assertEqual(
            sum(len(lane["secondary"]) for lane in lanes),
            sum(bool(subject["criticality"]) for subject in subjects),
        )

    def test_n07_rejected(self):
        freeze = freeze_fixture()
        overlay = overlay_fixture(freeze)
        subject = subject_fixture(1)
        self.assert_rejects(
            "PRIMARY_PARTITION",
            verifier_module().assign_subjects,
            [subject, copy.deepcopy(subject), copy.deepcopy(subject)],
            freeze=freeze,
            overlay=overlay,
            rows=[],
            classification_by_path=subject_classification_records([subject]),
        )

    def test_n08_accepted(self):
        subject = subject_fixture(1)
        subject.update(
            {
                "bytes": 0,
                "git_object_id": verifier_module()._git_blob_id(b""),
                "lines": 0,
                "sha256": hashlib.sha256(b"").hexdigest(),
            }
        )
        subject["subject_id"] = verifier_module()._subject_id(subject)
        subject["units"] = verifier_module()._subject_units(subject)
        record = verifier_module()._subject_packet_record(
            subject, freeze_commit="f" * 40, freeze_tree="e" * 40
        )
        self.assertEqual(record["coverage"]["byte_interval"]["end_exclusive"], 0)
        self.assertIsNone(record["coverage"]["line_interval"])

    def test_n08_rejected(self):
        subject = subject_fixture(1)
        subject["snapshot_state"] = "ABSENT_AT_CH_T002_F"
        self.assert_rejects(
            "SUBJECT_SNAPSHOT_STATE",
            verifier_module()._subject_packet_record,
            subject,
            freeze_commit="f" * 40,
            freeze_tree="e" * 40,
        )

    def test_n09_accepted(self):
        rows, catalogs, classifications, subjects = catalog_binding_fixture()
        self.assertIsNone(
            verifier_module()._validate_catalog_bindings(
                rows, catalogs, classifications, subjects
            )
        )

    def test_n09_rejected(self):
        rows, catalogs, classifications, subjects = catalog_binding_fixture()
        tokens = rows[0]["evidence"].split(";")
        tokens[-1] = (
            tokens[-1].replace(":SECONDARY", ":LICENSE").replace(":PRIMARY", ":LICENSE")
        )
        rows[0]["evidence"] = ";".join(sorted(tokens))
        self.assert_rejects(
            "CATALOG_POINTER",
            verifier_module()._validate_catalog_bindings,
            rows,
            catalogs,
            classifications,
            subjects,
        )

    def test_n10_accepted(self):
        evidence, reviews, activation = verifier_module()._validate_freeze(
            freeze_fixture()
        )
        self.assertEqual([len(evidence), len(reviews), len(activation)], [13, 4, 5])

    def test_n10_rejected(self):
        freeze = freeze_fixture()
        freeze["qualification_evidence_requirements"][0]["kind"] = "WRONG_KIND"
        self.assert_rejects(
            "FREEZE_EVIDENCE_REQUIREMENTS", verifier_module()._validate_freeze, freeze
        )

    def test_n11_accepted(self):
        names = verifier_module()._python_test_names(
            Path(__file__).read_bytes(), __file__
        )
        declared = {
            binding[index]
            for bindings in (
                verifier_module().NORMATIVE_CONTROL_BINDINGS,
                verifier_module().COUNTERFACTUAL_BINDINGS,
            )
            for binding in bindings
            for index in (1, 2)
        }
        self.assertTrue(declared.issubset(names))

    def test_n11_rejected(self):
        self.assert_rejects(
            "TEST_AST_INVALID",
            verifier_module()._python_test_names,
            b"def test_broken(:\n",
            "registered-tests",
        )

    def test_python_test_inventory_rejects_nested_dead_test(self):
        payload = b"""import unittest
class Tests(unittest.TestCase):
    def test_live(self):
        def test_dead():
            pass
"""
        self.assert_rejects(
            "TEST_ID_NOT_DISCOVERABLE",
            verifier_module()._python_test_names,
            payload,
            "nested-tests",
        )

    def test_python_test_inventory_rejects_non_testcase_method(self):
        payload = b"""class NotATestCase:
    def test_dead(self):
        pass
"""
        self.assert_rejects(
            "TEST_ID_NOT_DISCOVERABLE",
            verifier_module()._python_test_names,
            payload,
            "dead-tests",
        )

    def test_python_test_inventory_rejects_duplicate_discoverable_id(self):
        payload = b"""import unittest
class First(unittest.TestCase):
    def test_duplicate(self):
        pass
class Second(unittest.TestCase):
    def test_duplicate(self):
        pass
"""
        self.assert_rejects(
            "TEST_ID_DUPLICATE",
            verifier_module()._python_test_names,
            payload,
            "duplicate-tests",
        )

    def test_n12_accepted(self):
        freeze = freeze_fixture()
        verifier_module()._validate_freeze(freeze)
        self.assertEqual(
            freeze["resource_budgets"]["verifier_seconds"],
            verifier_module().VERIFIER_SECONDS,
        )

    def test_n12_rejected(self):
        freeze = freeze_fixture()
        freeze["resource_budgets"]["verifier_seconds"] += 1
        self.assert_rejects(
            "FREEZE_VERIFIER_BUDGET", verifier_module()._validate_freeze, freeze
        )

    def test_n13_accepted(self):
        freeze = freeze_fixture()
        verifier_module()._validate_freeze(freeze)
        self.assertEqual(
            len({item["key_fingerprint"] for item in freeze["reviewer_registry"]}),
            4,
        )
        self.assertEqual(
            [
                item["reviewer"]["classification"]
                for item in freeze["reviewer_registry"]
            ],
            ["INDEPENDENT_AUTOMATED"] * 3 + ["AUTOMATED_LEAD_SUPPORT"],
        )

    def test_n13_rejected(self):
        freeze = freeze_fixture()
        freeze["reviewer_registry"][1]["reviewer"]["classification"] = (
            "INDEPENDENT_HUMAN"
        )
        self.assert_rejects(
            "FREEZE_REVIEWER_BINDING", verifier_module()._validate_freeze, freeze
        )

    def test_n14_accepted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            record, registry = signed_review_vector(root)
            self.assertIsNone(
                verifier_module()._verify_review_signature(
                    root,
                    record,
                    registry,
                    freeze_commit="f" * 40,
                    implementation_commit="e" * 40,
                    lead=False,
                )
            )

    def test_n14_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            record, registry = signed_review_vector(root)
            record["decision"] = "MUTATED_AFTER_SIGNATURE"
            self.assert_rejects(
                "RUN_FAILED",
                verifier_module()._verify_review_signature,
                root,
                record,
                registry,
                freeze_commit="f" * 40,
                implementation_commit="e" * 40,
                lead=False,
            )

    def test_n15_accepted(self):
        value = {"finite": 1, "result": "PASS"}
        self.assertEqual(
            verifier_module()._parse_canonical_json(
                verifier_module()._canonical_json_bytes(value), "VECTOR"
            ),
            value,
        )

    def test_n15_rejected(self):
        self.assert_rejects(
            "VECTOR_DUPLICATE_KEY",
            verifier_module()._parse_canonical_json,
            b'{"finite":1,"finite":2}\n',
            "VECTOR",
        )

    def test_n16_accepted(self):
        self.assertEqual(
            verifier_module()._canonical_path("release/0.9.0/current-head/a.json"),
            "release/0.9.0/current-head/a.json",
        )

    def test_n16_rejected(self):
        self.assert_rejects(
            "PATH_NOT_CANONICAL", verifier_module()._canonical_path, ".git/config"
        )

    def test_n17_accepted(self):
        record, payload, arguments = retained_ci_vector()
        observed, completed = verifier_module()._retained_ci_payload(
            record, **arguments
        )
        self.assertEqual(observed, payload)
        self.assertEqual(completed, record["completed_at_utc"])

    def test_n17_rejected(self):
        record, _payload, arguments = retained_ci_vector()
        record["sha256"] = "0" * 64
        self.assert_rejects(
            "ACTIVATION_CI_RETAINED_BINDING",
            verifier_module()._retained_ci_payload,
            record,
            **arguments,
        )

    def test_n18_accepted(self):
        provider_order = (
            "feature-matrix",
            "macos-compile",
            "build-test",
            "interop",
            "supply-chain",
            "clean-build",
        )
        payload, jobs = log_archive_vector(
            names=provider_order, include_directories=True
        )
        manifest = verifier_module()._validate_log_archive(payload, jobs=jobs)
        self.assertEqual(len(manifest), 12)

    def test_n18_rejected(self):
        payload, jobs = log_archive_vector(ordinals=(0, 1, 2, 3, 4, 7))
        self.assert_rejects(
            "ACTIVATION_ARCHIVE_PRIMARY_ORDINALS",
            verifier_module()._validate_log_archive,
            payload,
            jobs=jobs,
        )

    def test_n19_accepted(self):
        command = activation_command_vector()
        self.assertEqual(validate_activation_command_vector(command), command)

    def test_n19_rejected(self):
        command = activation_command_vector()
        command["argv"] = ["/bin/false"]
        self.assert_rejects(
            "ACTIVATION_COMMAND_BINDING",
            validate_activation_command_vector,
            command,
        )

    def test_n20_accepted(self):
        freeze = freeze_fixture()
        verifier_module()._validate_freeze(freeze)
        self.assertEqual(freeze["claim_outcomes"][0]["overall_status"], "NO_GO")
        self.assertIn(
            verifier_module().HUMAN_REVIEW_LIMITATION,
            freeze["claim_outcomes"][0]["limitations"],
        )

    def test_n20_rejected(self):
        freeze = freeze_fixture()
        freeze["claim_outcomes"][0]["limitations"] = ["Technical checks pass."]
        self.assert_rejects(
            "FREEZE_OUTCOME_BOUNDARY", verifier_module()._validate_freeze, freeze
        )

    def test_cf01_accepted(self):
        overlay, _entries, _digest = minimal_classification_contract_fixture()
        record = overlay["review_classification_contract"]["records"][0]
        self.assertEqual(
            verifier_module()._validate_classification_record(record), record
        )

    def test_cf01_rejected(self):
        overlay, _entries, _digest = minimal_classification_contract_fixture()
        record = overlay["review_classification_contract"]["records"][0]
        record["public_surface"] = "YES"
        self.assert_rejects(
            "CLASSIFICATION_RULE_FLAG",
            verifier_module()._validate_classification_record,
            record,
        )

    def test_cf02_accepted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            record, registry = signed_review_vector(root)
            self.assertIsNone(
                verifier_module()._verify_review_signature(
                    root,
                    record,
                    registry,
                    freeze_commit="f" * 40,
                    implementation_commit="e" * 40,
                    lead=False,
                )
            )

    def test_cf02_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            record, registry = signed_review_vector(root)
            record["detached_signature"]["principal"] = "unauthorized@example.invalid"
            self.assert_rejects(
                "REVIEW_SIGNATURE_BINDING",
                verifier_module()._verify_review_signature,
                root,
                record,
                registry,
                freeze_commit="f" * 40,
                implementation_commit="e" * 40,
                lead=False,
            )

    def test_cf03_accepted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            record, registry = signed_review_vector(
                root, implementation_commit="d" * 40
            )
            self.assertIsNone(
                verifier_module()._verify_review_signature(
                    root,
                    record,
                    registry,
                    freeze_commit="f" * 40,
                    implementation_commit="d" * 40,
                    lead=False,
                )
            )

    def test_cf03_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            record, registry = signed_review_vector(
                root, implementation_commit="d" * 40
            )
            self.assert_rejects(
                "RUN_FAILED",
                verifier_module()._verify_review_signature,
                root,
                record,
                registry,
                freeze_commit="f" * 40,
                implementation_commit="e" * 40,
                lead=False,
            )

    def test_cf04_accepted(self):
        overlay, f_entries, digest = minimal_classification_contract_fixture()
        with self.classification_patches(overlay, digest):
            observed = verifier_module()._validate_classification_contract(
                overlay, f_entries, f_entries
            )
        self.assertIsInstance(observed, dict)
        self.assertEqual(set(observed), set(f_entries))

    def test_cf04_rejected(self):
        overlay, f_entries, digest = minimal_classification_contract_fixture()
        overlay["review_classification_contract"]["classification_set_sha256"] = (
            "0" * 64
        )
        with self.classification_patches(overlay, digest):
            self.assert_rejects(
                "CLASSIFICATION_SET_DIGEST",
                verifier_module()._validate_classification_contract,
                overlay,
                f_entries,
                f_entries,
            )

    def test_cf05_accepted(self):
        freeze = freeze_fixture()
        verifier_module()._validate_freeze(freeze)
        self.assertEqual(freeze["claim_outcomes"][0]["release_qualified_claims"], [])

    def test_cf05_rejected(self):
        freeze = freeze_fixture()
        freeze["claim_outcomes"][0]["overall_status"] = "GO"
        freeze["claim_outcomes"][0]["release_qualified_claims"] = ["synthetic"]
        self.assert_rejects(
            "FREEZE_OUTCOME_BOUNDARY", verifier_module()._validate_freeze, freeze
        )

    def test_cf06_accepted(self):
        stdout, stderr = verifier_module()._run(
            ["/bin/sh", "-c", "printf pass"], repo=Path.cwd(), seconds=0.5
        )
        self.assertEqual((stdout, stderr), (b"pass", b""))

    def test_cf06_rejected(self):
        self.assert_rejects(
            "RUN_TIMEOUT",
            verifier_module()._run,
            ["/bin/sh", "-c", "while :; do :; done"],
            repo=Path.cwd(),
            seconds=0.02,
        )

    def test_cf07_accepted(self):
        freeze = freeze_fixture()
        verifier_module()._validate_freeze(freeze)
        self.assertEqual(
            set(freeze["implementation_plan"]), set(verifier_module().EXPECTED_I_DIFF)
        )

    def test_cf07_rejected(self):
        freeze = freeze_fixture()
        freeze["implementation_plan"]["crates/privileged/src/lib.rs"] = "A"
        self.assert_rejects(
            "FREEZE_IMPLEMENTATION_PLAN", verifier_module()._validate_freeze, freeze
        )

    def test_cf08_accepted(self):
        _base, _rows, base_payload, completed_payload, reviewers = ledger_fixture()
        base_rows, completed_rows = validate_fixture(
            base_payload, completed_payload, reviewers
        )
        self.assertEqual(len(base_rows), len(completed_rows))

    def test_cf08_rejected(self):
        _base, rows, base_payload, _completed_payload, reviewers = ledger_fixture()
        rows[0]["generated"] = "UNKNOWN"
        self.assert_rejects(
            "LEDGER_UNRESOLVED_TRISTATE",
            validate_fixture,
            base_payload,
            render_ledger(rows),
            reviewers,
        )

    def test_cf09_accepted(self):
        command = activation_command_vector(stdout="durable receipt\n")
        self.assertEqual(validate_activation_command_vector(command), command)

    def test_cf09_rejected(self):
        command = activation_command_vector(stdout="", stderr="")
        self.assert_rejects(
            "ACTIVATION_COMMAND_EMPTY", validate_activation_command_vector, command
        )

    def test_cf10_accepted(self):
        subject = subject_fixture(1)
        subject["bytes"] = 0
        subject["lines"] = 0
        self.assertEqual(verifier_module()._subject_units(subject), 1)

    def test_cf10_rejected(self):
        subject = subject_fixture(1)
        subject["lines"] = None
        self.assert_rejects(
            "SUBJECT_TEXT_LINES", verifier_module()._subject_units, subject
        )

    def test_technique_boundary_value(self):
        self.assertEqual(verifier_module()._integer(0, "BOUNDARY"), 0)
        self.assert_rejects("BOUNDARY", verifier_module()._integer, True, "BOUNDARY")

    def test_technique_equivalence_partition(self):
        self.assertEqual(verifier_module()._classify_content(b"x\n"), ("TEXT_UTF8", 1))
        self.assertEqual(verifier_module()._classify_content(b"x\0"), ("BINARY", None))
        self.assertEqual(
            verifier_module()._classify_content(b"\x1b[31mred\x1b[0m\n"),
            ("TEXT_UTF8_WITH_ANSI_ESCAPE", 1),
        )

    def test_technique_decision_table(self):
        overlay, _entries, _digest = minimal_classification_contract_fixture()
        record = overlay["review_classification_contract"]["records"][0]
        self.assertEqual(
            verifier_module()._validate_classification_record(record), record
        )

    def test_technique_state_transition(self):
        self.assertEqual(
            tuple(verifier_module().EXPECTED_COMMIT_SUBJECTS), ("F", "I", "C", "D")
        )

    def test_technique_pairwise(self):
        freeze = freeze_fixture()
        overlay = overlay_fixture(freeze)
        subjects = [
            subject_fixture(index, critical=index % 2 == 0) for index in range(1, 10)
        ]
        lanes = verifier_module().assign_subjects(
            subjects,
            freeze=freeze,
            overlay=overlay,
            rows=[],
            classification_by_path=subject_classification_records(subjects),
        )
        self.assertEqual(sum(len(lane["secondary"]) for lane in lanes), 4)

    def test_technique_fuzz(self):
        for value in ("../x", "/x", ".git/x", "x\\y", "x/../y"):
            self.assert_rejects(
                "PATH_NOT_CANONICAL", verifier_module()._canonical_path, value
            )

    def test_technique_mutation(self):
        overlay, _entries, _digest = minimal_classification_contract_fixture()
        original = overlay["review_classification_contract"]["records"][0]
        mutated = copy.deepcopy(original)
        mutated["public_surface"] = "YES"
        self.assert_rejects(
            "CLASSIFICATION_RULE_FLAG",
            verifier_module()._validate_classification_record,
            mutated,
        )
        self.assertNotEqual(
            verifier_module()._domain_digest(
                verifier_module().CLASSIFICATION_DIGEST_DOMAIN, [original]
            ),
            verifier_module()._domain_digest(
                verifier_module().CLASSIFICATION_DIGEST_DOMAIN, [mutated]
            ),
        )

    def test_central_freeze_shape_and_byte_bound(self):
        freeze = freeze_fixture()
        self.assertEqual(len(verifier_module().FREEZE_KEYS), 31)
        self.assertEqual(tuple(freeze), verifier_module().FREEZE_KEYS)
        self.assertLessEqual(
            len(verifier_module()._pretty_json_bytes(freeze)), 256 * 1024
        )

    def test_central_registered_source_byte_bounds(self):
        verifier = Path(verifier_module().__file__).read_bytes()
        tests = Path(__file__).read_bytes()
        self.assertLessEqual(len(verifier), 256 * 1024)
        self.assertLessEqual(len(tests), 256 * 1024)

    def test_classification_contract_canonical_nested_order_round_trip(self):
        overlay, _entries, _digest = minimal_classification_contract_fixture()
        payload = verifier_module()._canonical_json_bytes(overlay)
        parsed = verifier_module()._parse_canonical_json(payload, "OVERLAY_GOLDEN")
        contract = parsed["review_classification_contract"]
        self.assertEqual(tuple(contract), tuple(sorted(contract)))
        self.assertTrue(
            all(
                tuple(record) == tuple(sorted(record)) for record in contract["records"]
            )
        )

    def test_classification_floor_rejects_docs_public_downgrade(self):
        overlay, _entries, _digest = minimal_classification_contract_fixture()
        record = copy.deepcopy(overlay["review_classification_contract"]["records"][0])
        record["path"] = "docs/example.md"
        record["public_surface"] = "NO"
        record["rule_ids"][0] = "PUB_NO_TEST"
        self.assert_rejects(
            "CLASSIFICATION_MANDATORY_FLOOR",
            verifier_module()._validate_classification_record,
            record,
        )

    def test_classification_floor_does_not_expand_to_historical_release(self):
        self.assertEqual(
            verifier_module()._mandatory_criticality_floor(
                "release/0.9.0/archive/record.json"
            ),
            frozenset(),
        )
        self.assertEqual(
            verifier_module()._mandatory_criticality_floor(
                "release/0.9.0/current-head/record.json"
            ),
            frozenset({"AUTHORITY_CRITICAL"}),
        )

    def test_whole_verifier_budget_cannot_be_relaxed(self):
        with self.assertRaisesRegex(
            verifier_module().VerificationError, "VERIFIER_BUDGET"
        ):
            with verifier_module()._verification_budget(
                verifier_module().VERIFIER_SECONDS + 1
            ):
                pass

    def test_subprocess_timeout_is_hard_and_bounded(self):
        with self.assertRaisesRegex(verifier_module().VerificationError, "RUN_TIMEOUT"):
            verifier_module()._run(
                ["/bin/sh", "-c", "while :; do :; done"],
                repo=Path.cwd(),
                seconds=0.02,
            )

    def test_log_archive_accepts_exact_six_job_primaries(self):
        provider_order = (
            "feature-matrix",
            "macos-compile",
            "build-test",
            "interop",
            "supply-chain",
            "clean-build",
        )
        payload, jobs = log_archive_vector(
            names=provider_order, include_directories=True
        )
        manifest = verifier_module()._validate_log_archive(payload, jobs=jobs)
        self.assertEqual(len(manifest), 2 * len(verifier_module().CI_JOB_NAMES))
        self.assertEqual(
            verifier_module()._validate_log_archive(
                payload, jobs=jobs, expected_manifest=manifest
            ),
            manifest,
        )

    def test_log_archive_rejects_noncontiguous_provider_ordinals(self):
        payload, jobs = log_archive_vector(ordinals=(0, 1, 2, 3, 4, 6))
        self.assert_rejects(
            "ACTIVATION_ARCHIVE_PRIMARY_ORDINALS",
            verifier_module()._validate_log_archive,
            payload,
            jobs=jobs,
        )

    def test_log_archive_rejects_duplicate_provider_ordinal(self):
        payload, jobs = log_archive_vector(ordinals=(0, 1, 2, 3, 4, 4))
        self.assert_rejects(
            "ACTIVATION_ARCHIVE_PRIMARY_ORDINALS",
            verifier_module()._validate_log_archive,
            payload,
            jobs=jobs,
        )

    def test_log_archive_rejects_wrong_job_name(self):
        names = (*verifier_module().CI_JOB_NAMES[:-1], "unexpected-job")
        payload, jobs = log_archive_vector(names=names)
        self.assert_rejects(
            "ACTIVATION_ARCHIVE_JOB_SCOPE",
            verifier_module()._validate_log_archive,
            payload,
            jobs=jobs,
        )

    def test_log_archive_rejects_missing_primary(self):
        payload, jobs = log_archive_vector(names=verifier_module().CI_JOB_NAMES[:-1])
        self.assert_rejects(
            "ACTIVATION_ARCHIVE_PRIMARY_SCOPE",
            verifier_module()._validate_log_archive,
            payload,
            jobs=jobs,
        )

    def test_log_archive_rejects_extra_primary(self):
        jobs = [
            {"conclusion": "success", "job_id": 100 + index, "name": name}
            for index, name in enumerate(verifier_module().CI_JOB_NAMES)
        ]
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_STORED) as archive:
            for ordinal, name in enumerate(verifier_module().CI_JOB_NAMES):
                info = zipfile.ZipInfo(f"{ordinal}_{name}.txt")
                info.create_system = 3
                info.external_attr = 0o100644 << 16
                archive.writestr(info, "passed\n")
            extra = zipfile.ZipInfo("6_build-test.txt")
            extra.create_system = 3
            extra.external_attr = 0o100644 << 16
            archive.writestr(extra, "duplicate\n")
        self.assert_rejects(
            "ACTIVATION_ARCHIVE_PRIMARY_SCOPE",
            verifier_module()._validate_log_archive,
            stream.getvalue(),
            jobs=jobs,
        )

    def test_log_archive_rejects_missing_job_id_binding(self):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            archive.writestr("1_build-test.txt", "passed\n")
        jobs = [
            {"conclusion": "success", "name": name}
            for name in verifier_module().CI_JOB_NAMES
        ]
        self.assert_rejects(
            "ACTIVATION_ARCHIVE_JOB_RECORD",
            verifier_module()._validate_log_archive,
            stream.getvalue(),
            jobs=jobs,
        )

    def test_log_archive_rejects_traversal(self):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            archive.writestr("../escape.txt", "x")
        self.assert_rejects(
            "PATH_NOT_CANONICAL",
            verifier_module()._validate_log_archive,
            stream.getvalue(),
        )

    def test_log_archive_rejects_portable_collision(self):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            archive.writestr("A.txt", "a")
            archive.writestr("a.txt", "b")
        self.assert_rejects(
            "ACTIVATION_ARCHIVE_PORTABLE_COLLISION",
            verifier_module()._validate_log_archive,
            stream.getvalue(),
        )

    def test_log_archive_rejects_symlink_mode(self):
        stream = io.BytesIO()
        info = zipfile.ZipInfo("link.txt")
        info.create_system = 3
        info.external_attr = 0o120777 << 16
        with zipfile.ZipFile(stream, "w") as archive:
            archive.writestr(info, "target")
        self.assert_rejects(
            "ACTIVATION_ARCHIVE_ENTRY",
            verifier_module()._validate_log_archive,
            stream.getvalue(),
        )

    def test_real_git_lifecycle_fixture_has_exact_linear_chain(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            subprocess.run(
                [verifier_module().GIT_EXECUTABLE, "init", "-q", repo], check=True
            )
            subprocess.run(
                [
                    verifier_module().GIT_EXECUTABLE,
                    "-C",
                    repo,
                    "config",
                    "user.name",
                    "Fixture",
                ],
                check=True,
            )
            subprocess.run(
                [
                    verifier_module().GIT_EXECUTABLE,
                    "-C",
                    repo,
                    "config",
                    "user.email",
                    "fixture@example.invalid",
                ],
                check=True,
            )
            commits = []
            for index, phase in enumerate(("F", "I", "C", "D"), 1):
                path = repo / f"{phase}.txt"
                path.write_text(f"phase {phase}\n", encoding="utf-8")
                subprocess.run(
                    [verifier_module().GIT_EXECUTABLE, "-C", repo, "add", path.name],
                    check=True,
                )
                subprocess.run(
                    [
                        verifier_module().GIT_EXECUTABLE,
                        "-C",
                        repo,
                        "commit",
                        "-q",
                        "-m",
                        verifier_module().EXPECTED_COMMIT_SUBJECTS[phase],
                    ],
                    check=True,
                )
                commits.append(
                    subprocess.check_output(
                        [
                            verifier_module().GIT_EXECUTABLE,
                            "-C",
                            repo,
                            "rev-parse",
                            "HEAD",
                        ],
                        text=True,
                    ).strip()
                )
            parents = verifier_module()._commit_parents(repo, commits[1:])
            self.assertEqual(parents[commits[1]], commits[0])
            self.assertEqual(parents[commits[2]], commits[1])
            self.assertEqual(parents[commits[3]], commits[2])
            self.assertEqual(
                verifier_module()._first_parent(repo, commits[3])[:4], commits[::-1]
            )
            for commit, phase in zip(commits, ("F", "I", "C", "D"), strict=True):
                self.assertEqual(
                    verifier_module()._commit_subject(repo, commit),
                    verifier_module().EXPECTED_COMMIT_SUBJECTS[phase],
                )


if __name__ == "__main__":
    unittest.main()
