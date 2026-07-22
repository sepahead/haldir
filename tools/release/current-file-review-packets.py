#!/usr/bin/env python3
"""Render and verify deterministic CH-T002 file-review packets.

The completed CH-T001 CSV remains the only review ledger.  The CH-T002
overlay is a frozen snapshot-delta and review-scope manifest; it does not
duplicate per-row review decisions.  This helper reconciles those two inputs,
applies the frozen three-lane assignment algorithm, and publishes create-once
packet bytes.  It neither signs reviews nor grants human, release, deployment,
or publication status.

All parsing is bounded and fail closed.  JSON and CSV inputs must already be
in their canonical encodings.  Rendering publishes a complete directory with
one native atomic no-replace rename, so an existing destination is never
updated or removed.

The supported host operating systems are Linux and macOS.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import csv
import ctypes
import errno
import hashlib
import io
import json
import math
import os
import re
import secrets
import selectors
import stat
import subprocess
import sys
import time
import unicodedata
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping, Sequence


SCHEMA_ID = "haldir.ch-t002.file-review-overlay.v1"
PACKET_SCHEMA_ID = "haldir.ch-t002.file-review-packet.v1"
MANIFEST_SCHEMA_ID = "haldir.ch-t002.file-review-packet-manifest.v1"
SCHEMA_VERSION = "1.0.0"
TASK_ID = "CH-T002"
EPOCH = 2
RELEASE_TARGET = "0.9.0"
EXPECTED_AUTHOR = {"email": "sepmhn@gmail.com", "name": "Sepehr Mahmoudian"}

LEDGER_PATH = "audit/generated/FILE_REVIEW_LEDGER.csv"
OVERLAY_PATH = "audit/generated/CH-T002_FILE_REVIEW_OVERLAY.json"
PRODUCT_PATH = "tools/release/current-file-review-packets.py"
PRODUCT_TEST_PATH = "tools/release/test_current_file_review_packets.py"
FREEZE_REGISTRY_PATH = "release/0.9.0/current-head/tasks/ch-t002/e0002/freeze.json"
CENTRAL_REGISTRY_PATH = (
    "release/0.9.0/current-head/closures/task-verifier-registry.json"
)
LEDGER_GENERATOR_PATH = "tools/release/current-file-review-ledger.py"
TEST_ONLY_AUTHORITY_FLOOR_EXCEPTION = "tools/release/current_audit_test_fixtures.py"
CH_T001_BASE_COMMIT = "ab4eb7a99bebae88c5aad3684bccf3a85a4e7dc9"
CH_T001_BASE_TREE = "844dbc2b50812e7bdf2a44deae8be831d8ff8349"
CH_T001_BASE_LEDGER_BLOB = "51c0278e16885231bb98b3c85ae64384e08bd97d"
CH_T001_BASE_LEDGER_SHA256 = (
    "0e0d5a0fb147157cc7d5506d271d64c24794b1261fc3713b2e097ca50b8d9a89"
)
CH_T001_BASE_LEDGER_ROWS = 356
IMPLEMENTATION_PLAN = (
    {"path": OVERLAY_PATH, "status": "A"},
    {"path": LEDGER_PATH, "status": "M"},
    {"path": PRODUCT_PATH, "status": "A"},
    {"path": PRODUCT_TEST_PATH, "status": "A"},
)

LANE_COUNT = 3
BINARY_UNIT_BYTES = 4096
ASSIGNMENT_ALGORITHM = "LARGEST_FIRST_LEAST_LOADED_V1"
TEXT_UNIT_RULE = "MAX_LINES_ONE"
BINARY_UNIT_RULE = "CEILING_BYTES_PER_4096_MIN_ONE"
SORT_RULE = "UNITS_DESC_LANGUAGE_ASC_SUBJECT_ID_RAW_UTF8_ASC"
PRIMARY_RULE = "MIN_TOTAL_UNITS_THEN_ITEM_COUNT_THEN_LANE"
SECONDARY_RULE = "MIN_TOTAL_UNITS_THEN_ITEM_COUNT_THEN_LANE_EXCLUDING_PRIMARY"
COVERAGE_RULE = "EXACT_GIT_BLOB_FULL_RECONSTRUCTION"
REMOVAL_POLICY = "NO_REMOVALS_PER_EXACT_BASELINE_TO_FREEZE_DIFF"
REMOVED_COVERAGE_RULE = REMOVAL_POLICY
SCOPE_KIND = "FROZEN_SNAPSHOT_DELTA_AND_REVIEW_SCOPE_MANIFEST"
SCOPE_INCLUSION = "ALL_REGULAR_GIT_BLOBS_AT_FREEZE_TREE"
PATH_ORDER = "RAW_UTF8_BYTE_ASC"
CLAIM_OUTCOME = "NO_PUBLIC_CLAIM_CHANGE"
IMPLEMENTATION_REVIEW_KIND = "CENTRAL_PROTOCOL_REVIEWS"
CLASSIFICATION_CONTRACT_SCHEMA_ID = "haldir.ch-t002.review-classification-contract.v1"
CLASSIFICATION_POLICY = (
    "HASH_PINNED_INDEPENDENT_AUDIT_PLUS_EXPLICIT_REVIEW_OVERRIDES_AND_F_EXTENSION_V1"
)
CLASSIFICATION_AUDIT_SCHEMA_ID = "HALDIR_CH_T002_INDEPENDENT_CLASSIFICATION_AUDIT_V1"
CLASSIFICATION_AUDIT_SHA256 = (
    "1222a6c9e6962a8c0ad6ac5196868084c03d230e0ba976baa8fe9b49be464441"
)
CLASSIFICATION_AUDIT_COMMIT = "2167b0b1b8580298b8474e676893f97292c3d7c7"
CLASSIFICATION_AUDIT_TREE = "66c906443dae3338117f8a43e740b9161811ef7a"
CLASSIFICATION_OVERRIDE_POLICY_ID = (
    "INDEPENDENT_AUTOMATED_PLUS_LOCAL_BYTE_REVIEW_OVERRIDES_V1"
)
CLASSIFICATION_OVERRIDE_SOURCE_BASIS = CLASSIFICATION_OVERRIDE_POLICY_ID
CLASSIFICATION_OVERRIDE_ORDER = "RAW_UTF8_BYTE_ASC_PATH_THEN_ASCII_FIELD_ASC"
CLASSIFICATION_GENERATED_SEMANTICS = (
    "YES identifies production or capture by the named tracked procedure; it does "
    "not assert byte-deterministic regeneration of a historical run."
)
CLASSIFICATION_PRIMARY_CAPTURE_SEMANTICS = (
    "The 12 retained live-campaign logs are generated captures and primary runtime "
    "observations; exact Git identities preserve the observed bytes, and their "
    "license review is NOT_APPLICABLE."
)
CLASSIFICATION_OVERRIDE_PATHS = (
    ".gitignore",
    "Cargo.lock",
    "crates/haldir-contracts/src/scalar.rs",
    "crates/haldir-evidence/src/gate_journal.rs",
    "crates/haldir-evidence/src/publication.rs",
    "crates/haldir-ncp08/tests/data/ncp-v0.8.0/command_frame.schema.json",
    "docs/ASSURANCE-PROFILES.md",
    "docs/AUTHORITY-GRAPH.md",
    "docs/COMPLETION-CHECKLIST.md",
    "docs/HALDIR-DISCUSSION-DECISIONS-2026.md",
    "docs/HALDIR-PROJECT-AUDIT-2026.md",
    "docs/IMPLEMENTATION-PUNCHLIST.md",
    "docs/NCP-COMPATIBILITY.md",
    "docs/ROADMAP-STATUS.md",
    "docs/adr/0001-fail-closed-gate-originated-authority.md",
    "docs/adr/0003-error-vs-deny-outcomes.md",
    "docs/adr/0007-p0-scope-and-deferrals.md",
    "docs/galadriels-mirror.md",
    "docs/release/0.9.0/AUTHORITY-CONTRACT.md",
    "docs/release/0.9.0/MIGRATION.md",
    "docs/release/0.9.0/PROTECTION-MODEL.md",
    "docs/release/0.9.0/THREAT-MODEL.md",
    "evidence/11-secure-zenoh-live/logs/docker-metadata.json",
    "evidence/11-secure-zenoh-live/logs/pki-verification.log",
    "evidence/11-secure-zenoh-live/logs/probe.stdout.log",
    "evidence/11-secure-zenoh-live/logs/router.log",
    "evidence/12-live-gate-dev-smoke/logs/bind.stderr.log",
    "evidence/12-live-gate-dev-smoke/logs/bind.stdout.log",
    "evidence/12-live-gate-dev-smoke/logs/docker-metadata.json",
    "evidence/12-live-gate-dev-smoke/logs/pki-verification.log",
    "evidence/12-live-gate-dev-smoke/logs/provision.stderr.log",
    "evidence/12-live-gate-dev-smoke/logs/provision.stdout.log",
    "evidence/12-live-gate-dev-smoke/logs/router.log",
    "evidence/README.md",
    "evidence/source-review/source-ledger.md",
    "release/0.9.0/allowed-signers",
    "release/0.9.0/authority-model.json",
    "release/0.9.0/current-head/closures/CH-T000-activation.json",
    "release/0.9.0/current-head/closures/CH-T000-qualification.json",
    "release/0.9.0/current-head/closures/framework-recovery/FR-0001-activation.json",
    "release/0.9.0/current-head/closures/framework-recovery/FR-0001-plan.json",
    "release/0.9.0/current-head/closures/framework-recovery/FR-0001-qualification.json",
    "release/0.9.0/current-head/evidence/ch-t000-resource-profile.json",
    "release/0.9.0/current-head/tasks/ch-t001/e0001/freeze.json",
    "release/0.9.0/current-head/tasks/ch-t001/e0002/activation-evidence/downstream-conformance-disposition.json",
    "release/0.9.0/current-head/tasks/ch-t001/e0002/activation-evidence/full-locked-ci-attempt-logs.zip",
    "release/0.9.0/current-head/tasks/ch-t001/e0002/activation-evidence/full-locked-ci.json",
    "release/0.9.0/current-head/tasks/ch-t001/e0002/activation-evidence/subsystem-gate.json",
    "release/0.9.0/current-head/tasks/ch-t001/e0002/activation-evidence/wave-gate.json",
    "release/0.9.0/current-head/tasks/ch-t001/e0002/activation.json",
    "release/0.9.0/current-head/tasks/ch-t001/e0002/evidence/claim-migration-disposition.json",
    "release/0.9.0/current-head/tasks/ch-t001/e0002/evidence/complete-command-log.json",
    "release/0.9.0/current-head/tasks/ch-t001/e0002/evidence/complete-file-inventory.json",
    "release/0.9.0/current-head/tasks/ch-t001/e0002/evidence/coverage-fuzz-mutation-model.json",
    "release/0.9.0/current-head/tasks/ch-t001/e0002/evidence/exact-identities-checksums.json",
    "release/0.9.0/current-head/tasks/ch-t001/e0002/evidence/file-review-traceability.json",
    "release/0.9.0/current-head/tasks/ch-t001/e0002/evidence/independent-ledger-reconciliation.json",
    "release/0.9.0/current-head/tasks/ch-t001/e0002/evidence/positive-negative-vectors.json",
    "release/0.9.0/current-head/tasks/ch-t001/e0002/evidence/resource-time-maxima.json",
    "release/0.9.0/current-head/tasks/ch-t001/e0002/freeze.json",
    "release/0.9.0/current-head/tasks/ch-t001/e0002/qualification.json",
    "release/0.9.0/current-head/tasks/ch-t001/e0002/reviews/independent-review.json",
    "release/0.9.0/current-head/tasks/ch-t001/e0002/reviews/lead-implementation-review.json",
    "release/0.9.0/current-head/tasks/ch-t001/e0002/verifier-receipt.json",
    "release/0.9.0/current-head/tasks/revocations/R0001/product-test-stderr-leak.json",
    "release/0.9.0/evidence/t000-generated-verification.json",
    "release/0.9.0/evidence/t000-verification.json",
    "release/0.9.0/evidence/t001-generated-verification.json",
    "release/0.9.0/evidence/t001-verification.json",
    "release/0.9.0/evidence/t002-generated-verification.json",
    "release/0.9.0/protection-model.json",
    "tools/release/current_audit_test_fixtures.py",
    "tools/release/verify-authority-model.py",
    "tools/release/verify-protection-model.py",
    "tools/secure_zenoh.py",
)
EXPECTED_CLASSIFICATION_OVERRIDE_FIELDS = 93
EXPECTED_CLASSIFICATION_OVERRIDE_SET_SHA256 = (
    "a9887d37596ef35afc758828e2b1726bd917bd3374f83395db7765b6996761e6"
)
CLASSIFICATION_F_EXTENSION_PATHS = (
    "release/0.9.0/current-head/tasks/ch-t002/e0001/freeze.json",
    "release/0.9.0/current-head/tasks/ch-t002/e0002/freeze.json",
    "release/0.9.0/current-head/tasks/revocations/R0002/classification-public-surface-conflict.json",
    "tools/release/tasks/ch-t002/e0001/test_verify.py",
    "tools/release/tasks/ch-t002/e0001/verify.py",
    "tools/release/tasks/ch-t002/e0002/test_verify.py",
    "tools/release/tasks/ch-t002/e0002/verify.py",
)
EXPECTED_CLASSIFICATION_RECORDS = 395
EXPECTED_CLASSIFICATION_SET_SHA256 = (
    "543e0946ed31da0fca3b7bdb184847d9fe68ab03154e3bf17b57869d0a77a051"
)
CLASSIFICATION_SET_DOMAIN = "haldir-ch-t002-classification-set-v1"
CLASSIFICATION_OVERRIDE_SET_DOMAIN = "haldir-ch-t002-classification-override-set-v1"
SOURCE_CURRENT_A_CLASSIFICATION_COUNTS = {
    "authority_critical_no": 127,
    "authority_critical_yes": 261,
    "generated_no": 326,
    "generated_yes": 62,
    "license_review_status_approved": 345,
    "license_review_status_not_applicable": 43,
    "paths": 388,
    "provenance_review_status_confirmed": 388,
    "public_surface_no": 214,
    "public_surface_yes": 174,
    "science_critical_no": 334,
    "science_critical_yes": 54,
    "security_critical_no": 124,
    "security_critical_yes": 264,
}
SOURCE_HISTORICAL_CLASSIFICATION_COUNTS = {
    "authority_critical_no": 127,
    "authority_critical_yes": 229,
    "generated_no": 294,
    "generated_yes": 62,
    "license_review_status_approved": 318,
    "license_review_status_not_applicable": 38,
    "paths": 356,
    "provenance_review_status_confirmed": 356,
    "public_surface_no": 184,
    "public_surface_yes": 172,
    "science_critical_no": 302,
    "science_critical_yes": 54,
    "security_critical_no": 92,
    "security_critical_yes": 264,
}
FINAL_HISTORICAL_CLASSIFICATION_COUNTS = {
    "authority_critical_no": 116,
    "authority_critical_yes": 240,
    "generated_no": 293,
    "generated_yes": 63,
    "license_review_status_approved": 318,
    "license_review_status_not_applicable": 38,
    "paths": 356,
    "provenance_review_status_confirmed": 356,
    "public_surface_no": 171,
    "public_surface_yes": 185,
    "science_critical_no": 279,
    "science_critical_yes": 77,
    "security_critical_no": 72,
    "security_critical_yes": 284,
}
FINAL_CURRENT_A_CLASSIFICATION_COUNTS = {
    "authority_critical_no": 116,
    "authority_critical_yes": 272,
    "generated_no": 325,
    "generated_yes": 63,
    "license_review_status_approved": 345,
    "license_review_status_not_applicable": 43,
    "paths": 388,
    "provenance_review_status_confirmed": 388,
    "public_surface_no": 201,
    "public_surface_yes": 187,
    "science_critical_no": 311,
    "science_critical_yes": 77,
    "security_critical_no": 82,
    "security_critical_yes": 306,
}
F_ADDITION_CLASSIFICATION_COUNTS = {
    "authority_critical_no": 0,
    "authority_critical_yes": 7,
    "generated_no": 7,
    "generated_yes": 0,
    "license_review_status_approved": 7,
    "license_review_status_not_applicable": 0,
    "paths": 7,
    "provenance_review_status_confirmed": 7,
    "public_surface_no": 7,
    "public_surface_yes": 0,
    "science_critical_no": 7,
    "science_critical_yes": 0,
    "security_critical_no": 0,
    "security_critical_yes": 7,
}
FINAL_F_CLASSIFICATION_COUNTS = {
    "authority_critical_no": 116,
    "authority_critical_yes": 279,
    "generated_no": 332,
    "generated_yes": 63,
    "license_review_status_approved": 352,
    "license_review_status_not_applicable": 43,
    "paths": 395,
    "provenance_review_status_confirmed": 395,
    "public_surface_no": 208,
    "public_surface_yes": 187,
    "science_critical_no": 318,
    "science_critical_yes": 77,
    "security_critical_no": 82,
    "security_critical_yes": 313,
}
EXPECTED_CLASSIFICATION_COUNT_SETS = {
    "f_additions": F_ADDITION_CLASSIFICATION_COUNTS,
    "final_current_a": FINAL_CURRENT_A_CLASSIFICATION_COUNTS,
    "final_f": FINAL_F_CLASSIFICATION_COUNTS,
    "final_historical_ledger_subjects": FINAL_HISTORICAL_CLASSIFICATION_COUNTS,
    "source_current_a": SOURCE_CURRENT_A_CLASSIFICATION_COUNTS,
}
CLASSIFICATION_CONTROL_ID = "CH-T002-N03"
CLASSIFICATION_CONTROL_ACCEPTED_TEST_ID = (
    "test_n03_accepts_exact_frozen_classification_contract"
)
CLASSIFICATION_CONTROL_REJECTED_TEST_ID = (
    "test_n03_rejects_classification_contract_drift"
)
ROW_REQUIREMENT_ID = "CH-T002-N01"
ROW_TEST_ID = "test_n01_accepted"
CLASSIFICATION_CONTROL_STATEMENT = (
    "The I overlay SHALL contain exactly 395 classification records, one for every "
    "regular Git blob at the signed F tree in RAW_UTF8_BYTE_ASC order; SHALL bind "
    "classification policy "
    "HASH_PINNED_INDEPENDENT_AUDIT_PLUS_EXPLICIT_REVIEW_OVERRIDES_AND_F_EXTENSION_V1, "
    "audit schema HALDIR_CH_T002_INDEPENDENT_CLASSIFICATION_AUDIT_V1, SHA-256 "
    "1222a6c9e6962a8c0ad6ac5196868084c03d230e0ba976baa8fe9b49be464441, "
    "audit commit 2167b0b1b8580298b8474e676893f97292c3d7c7, audit tree "
    "66c906443dae3338117f8a43e740b9161811ef7a, override policy "
    "INDEPENDENT_AUTOMATED_PLUS_LOCAL_BYTE_REVIEW_OVERRIDES_V1, exactly 93 field "
    "overrides across exactly 75 paths in "
    "RAW_UTF8_BYTE_ASC_PATH_THEN_ASCII_FIELD_ASC order, "
    "haldir-ch-t002-classification-override-set-v1 digest "
    "a9887d37596ef35afc758828e2b1726bd917bd3374f83395db7765b6996761e6, "
    "the explicit .gitignore public_surface NO-to-YES override with rule "
    "PUB_YES_BUILD_OR_DEPLOYMENT_AFFECTED_SURFACE, seven explicit F additions, "
    "NO_REMOVALS_PER_EXACT_BASELINE_TO_FREEZE_DIFF, the frozen generated and "
    "primary-capture semantics, and haldir-ch-t002-classification-set-v1 digest "
    "543e0946ed31da0fca3b7bdb184847d9fe68ab03154e3bf17b57869d0a77a051; and "
    "every ledger row, overlay entry, packet, and CH-T002-E09 decision SHALL agree "
    "exactly."
)
CENTRAL_FREEZE_KEY_ORDER = (
    "schema_version",
    "task_id",
    "epoch",
    "release_target",
    "author",
    "persistent_identifier",
    "effective_on",
    "task_identity",
    "handoff_task_contract",
    "prior_state",
    "implementation_plan",
    "empty_implementation_reason",
    "affected_surface_inventory",
    "normative_controls",
    "lead_approval",
    "mandatory_counterfactuals",
    "combined_attack_matrix",
    "handoff_command_mapping",
    "threat_model",
    "misuse_resistant_interfaces",
    "qualification_evidence_requirements",
    "review_requirements",
    "reviewer_registry",
    "activation_evidence_requirements",
    "lens_questions",
    "resource_budgets",
    "verification_triggers",
    "claim_outcomes",
    "qualification_path",
    "activation_path",
    "verifier_receipt_path",
)

OVERLAY_TOP_KEYS = frozenset(
    {
        "schema_id",
        "schema_version",
        "task_id",
        "epoch",
        "release_target",
        "author",
        "persistent_identifier",
        "scope",
        "base_partition",
        "delta",
        "review_classification_contract",
        "review_policy",
        "entries",
        "removed_paths",
        "implementation_boundary",
        "counts",
        "digests",
    }
)
SCOPE_KEYS = frozenset(
    {
        "claim_outcome",
        "classification_audit_sha256",
        "classification_policy",
        "evidence_catalog",
        "generator_catalog",
        "inclusion",
        "kind",
        "path_order",
        "requirement_catalog",
        "test_catalog",
    }
)
BASE_PARTITION_KEYS = frozenset(
    {
        "commit",
        "tree",
        "ledger_path",
        "ledger_blob_id",
        "ledger_sha256",
        "ledger_rows",
        "ledger_self_path",
    }
)
DELTA_KEYS = frozenset({"freeze_commit", "freeze_tree", "name_status_sha256"})
REVIEW_POLICY_KEYS = frozenset(
    {
        "algorithm",
        "binary_unit_bytes",
        "coverage",
        "critical_secondary_required",
        "lanes",
        "lead_requirement_id",
        "primary_selection",
        "registry",
        "removed_coverage",
        "secondary_selection",
        "sort_order",
        "text_units",
    }
)
LANE_POLICY_KEYS = frozenset({"kind", "lane", "requirement_id", "reviewer_fingerprint"})
REGISTRY_BINDING_KEYS = frozenset({"path", "git_blob_id", "sha256"})
ENTRY_KEYS = frozenset(
    {
        "bytes",
        "content_kind",
        "criticality",
        "generated",
        "generator",
        "git_mode",
        "git_object_id",
        "language",
        "license_expression",
        "license_review_status",
        "lines",
        "path",
        "provenance_review_status",
        "rule_ids",
        "sha256",
        "source_basis",
        "status",
        "subject_id",
    }
)
IMPLEMENTATION_BOUNDARY_KEYS = frozenset(
    {"content_identities_in_overlay", "paths", "review_kind"}
)
IMPLEMENTATION_PATH_KEYS = frozenset({"path", "status"})
COUNT_KEYS = frozenset(
    {
        "added_entries",
        "base_rows",
        "critical_subjects",
        "modified_entries",
        "removed_paths",
        "review_subjects",
        "self_entries",
        "supplemental_subjects",
        "unchanged_subjects",
    }
)
DIGEST_KEYS = frozenset(
    {
        "classification_set_sha256",
        "entry_set_sha256",
        "removed_path_set_sha256",
        "subject_set_sha256",
    }
)
PACKET_TOP_KEYS = frozenset(
    {
        "assignment",
        "coverage",
        "epoch",
        "lane",
        "release_target",
        "result",
        "reviewer",
        "schema_id",
        "schema_version",
        "snapshot",
        "task_id",
    }
)
ASSIGNMENT_KEYS = frozenset(
    {
        "algorithm",
        "binary_unit_bytes",
        "language_counts",
        "primary_entries",
        "primary_subjects",
        "primary_units",
        "secondary_entries",
        "secondary_subjects",
        "secondary_units",
        "subject_set_sha256",
        "total_subjects",
        "total_units",
    }
)
PACKET_SUBJECT_KEYS = frozenset(
    {
        "bytes",
        "content_kind",
        "coverage",
        "criticality",
        "content_commit",
        "content_tree",
        "git_mode",
        "git_object_id",
        "language",
        "lines",
        "path",
        "sha256",
        "status",
        "subject_id",
        "snapshot_state",
        "units",
    }
)
COVERAGE_KEYS = frozenset(
    {
        "byte_interval",
        "chunk_bytes",
        "chunk_count",
        "kind",
        "line_interval",
        "read_command",
    }
)
BYTE_INTERVAL_KEYS = frozenset({"end_exclusive", "start_inclusive"})
LINE_INTERVAL_KEYS = frozenset({"end_inclusive", "start_inclusive"})
REVIEWER_PACKET_KEYS = frozenset(
    {
        "classification",
        "key_fingerprint",
        "kind",
        "name",
        "organization",
        "principal",
        "requirement_id",
    }
)
SNAPSHOT_KEYS = frozenset(
    {
        "freeze_commit",
        "freeze_tree",
        "implementation_commit",
        "implementation_tree",
        "ledger",
        "overlay",
        "reviewer_registry",
    }
)
SNAPSHOT_ARTIFACT_KEYS = frozenset({"git_blob_id", "path", "sha256"})
LANGUAGE_COUNT_KEYS = frozenset({"language", "primary", "secondary", "total"})
PACKET_COVERAGE_KEYS = frozenset(
    {
        "invalid_secondary_subjects",
        "primary",
        "removed",
        "secondary",
        "uncovered_primary_subjects",
    }
)
MANIFEST_TOP_KEYS = frozenset(
    {
        "algorithm",
        "critical_subjects",
        "epoch",
        "lane_packets",
        "overlay_reconciliation",
        "release_target",
        "result",
        "review_subjects",
        "schema_id",
        "schema_version",
        "snapshot",
        "subject_set_sha256",
        "task_id",
    }
)
MANIFEST_LANE_KEYS = frozenset(
    {
        "bytes",
        "filename",
        "lane",
        "primary_subjects",
        "secondary_subjects",
        "sha256",
        "total_units",
    }
)
MANIFEST_RECONCILIATION_KEYS = frozenset(
    {
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
)
CLASSIFICATION_CONTRACT_KEY_ORDER = (
    "classification_set_sha256",
    "counts",
    "override_policy",
    "path_order",
    "records",
    "schema_id",
    "semantics",
    "source_audit",
)
CLASSIFICATION_COUNT_SET_KEY_ORDER = (
    "f_additions",
    "final_current_a",
    "final_f",
    "final_historical_ledger_subjects",
    "source_current_a",
)
CLASSIFICATION_COUNT_KEY_ORDER = (
    "authority_critical_no",
    "authority_critical_yes",
    "generated_no",
    "generated_yes",
    "license_review_status_approved",
    "license_review_status_not_applicable",
    "paths",
    "provenance_review_status_confirmed",
    "public_surface_no",
    "public_surface_yes",
    "science_critical_no",
    "science_critical_yes",
    "security_critical_no",
    "security_critical_yes",
)
CLASSIFICATION_SOURCE_KEY_ORDER = (
    "current_a_commit",
    "current_a_tree",
    "schema_id",
    "sha256",
)
CLASSIFICATION_OVERRIDE_KEY_ORDER = (
    "field_override_count",
    "order",
    "overrides",
    "path_count",
    "paths",
    "policy_id",
)
CLASSIFICATION_OVERRIDE_RECORD_KEY_ORDER = (
    "after",
    "before",
    "field",
    "path",
    "rule_id",
    "source_basis",
)
CLASSIFICATION_SEMANTICS_KEY_ORDER = ("generated", "primary_capture")
CLASSIFICATION_RECORD_KEY_ORDER = (
    "authority_critical",
    "generated",
    "generator",
    "license_expression",
    "license_review_status",
    "path",
    "provenance_review_status",
    "public_surface",
    "rule_ids",
    "science_critical",
    "security_critical",
    "source_basis",
)

# Exported, immutable schema description for independent implementations.  The
# registered verifier mirrors these declarations and never imports this module.
SCHEMA = {
    "overlay": {
        "top": tuple(sorted(OVERLAY_TOP_KEYS)),
        "scope": tuple(sorted(SCOPE_KEYS)),
        "base_partition": tuple(sorted(BASE_PARTITION_KEYS)),
        "delta": tuple(sorted(DELTA_KEYS)),
        "review_policy": tuple(sorted(REVIEW_POLICY_KEYS)),
        "lane": tuple(sorted(LANE_POLICY_KEYS)),
        "registry": tuple(sorted(REGISTRY_BINDING_KEYS)),
        "entry": tuple(sorted(ENTRY_KEYS)),
        "implementation_boundary": tuple(sorted(IMPLEMENTATION_BOUNDARY_KEYS)),
        "implementation_path": tuple(sorted(IMPLEMENTATION_PATH_KEYS)),
        "counts": tuple(sorted(COUNT_KEYS)),
        "digests": tuple(sorted(DIGEST_KEYS)),
    },
    "packet_filenames": tuple(
        f"review-lane-{lane:02d}.json" for lane in range(1, LANE_COUNT + 1)
    ),
    "manifest_filename": "file-review-packet-manifest.json",
    "digest_domains": {
        "classification_set": CLASSIFICATION_SET_DOMAIN,
        "entry_set": "haldir-ch-t002-overlay-entry-set-v1",
        "removed_path_set": "haldir-ch-t002-removed-path-set-v1",
        "subject": "haldir-ch-t002-review-subject-v1",
        "subject_set": "haldir-ch-t002-review-subject-set-v1",
        "lane_subject_set": "haldir-ch-t002-lane-subject-set-v1",
    },
    "packet": {
        "top": tuple(sorted(PACKET_TOP_KEYS)),
        "assignment": tuple(sorted(ASSIGNMENT_KEYS)),
        "subject": tuple(sorted(PACKET_SUBJECT_KEYS)),
        "coverage": tuple(sorted(COVERAGE_KEYS)),
        "byte_interval": tuple(sorted(BYTE_INTERVAL_KEYS)),
        "line_interval": tuple(sorted(LINE_INTERVAL_KEYS)),
        "reviewer": tuple(sorted(REVIEWER_PACKET_KEYS)),
        "snapshot": tuple(sorted(SNAPSHOT_KEYS)),
        "snapshot_artifact": tuple(sorted(SNAPSHOT_ARTIFACT_KEYS)),
        "language_count": tuple(sorted(LANGUAGE_COUNT_KEYS)),
        "coverage_summary": tuple(sorted(PACKET_COVERAGE_KEYS)),
    },
    "manifest": {
        "top": tuple(sorted(MANIFEST_TOP_KEYS)),
        "lane": tuple(sorted(MANIFEST_LANE_KEYS)),
        "overlay_reconciliation": tuple(sorted(MANIFEST_RECONCILIATION_KEYS)),
    },
    "classification_contract": {
        "top": CLASSIFICATION_CONTRACT_KEY_ORDER,
        "count_sets": CLASSIFICATION_COUNT_SET_KEY_ORDER,
        "count_vector": CLASSIFICATION_COUNT_KEY_ORDER,
        "source_audit": CLASSIFICATION_SOURCE_KEY_ORDER,
        "override_policy": CLASSIFICATION_OVERRIDE_KEY_ORDER,
        "override_record": CLASSIFICATION_OVERRIDE_RECORD_KEY_ORDER,
        "semantics": CLASSIFICATION_SEMANTICS_KEY_ORDER,
        "record": CLASSIFICATION_RECORD_KEY_ORDER,
    },
}

FIELDS = (
    "schema_version",
    "source_commit",
    "source_tree",
    "object_format",
    "ignored_policy",
    "inventory_digest",
    "inventory_rows",
    "source_inventory_digest",
    "index_inventory_digest",
    "untracked_inventory_digest",
    "ignored_inventory_digest",
    "filesystem_inventory_digest",
    "filesystem_entries",
    "ledger_self_path",
    "path",
    "source_tracked",
    "source_git_mode",
    "source_object_type",
    "source_git_blob_id",
    "source_sha256",
    "source_bytes",
    "source_lines",
    "source_content_kind",
    "index_tracked",
    "index_git_mode",
    "index_git_blob_id",
    "index_flags",
    "index_sha256",
    "index_bytes",
    "index_lines",
    "index_content_kind",
    "source_index_state",
    "current_scope",
    "current_fs_type",
    "current_fs_mode",
    "current_git_blob_id",
    "current_sha256",
    "current_bytes",
    "current_lines",
    "current_content_kind",
    "worktree_state",
    "ignore_rule_source",
    "ignore_pattern",
    "generated_candidate_reason",
    "category",
    "provenance_class",
    "git_blob_id",
    "sha256",
    "bytes",
    "lines",
    "language",
    "format",
    "generated",
    "generator",
    "public_surface",
    "security_critical",
    "science_critical",
    "authority_critical",
    "provenance_review_status",
    "provenance_evidence",
    "license_review_status",
    "license_expression",
    "license_evidence",
    "reviewer",
    "review_status",
    "requirements",
    "assumptions",
    "defects",
    "tests",
    "evidence",
    "disposition",
    "completed_at",
)
MUTABLE_FIELDS = frozenset(
    {
        "generated",
        "generator",
        "public_surface",
        "security_critical",
        "science_critical",
        "authority_critical",
        "provenance_review_status",
        "provenance_evidence",
        "license_review_status",
        "license_expression",
        "license_evidence",
        "reviewer",
        "review_status",
        "requirements",
        "assumptions",
        "defects",
        "tests",
        "evidence",
        "disposition",
        "completed_at",
    }
)
IMMUTABLE_FIELDS = tuple(field for field in FIELDS if field not in MUTABLE_FIELDS)

MAX_LEDGER_BYTES = 4 * 1024 * 1024
MAX_JSON_BYTES = 4 * 1024 * 1024
MAX_CENTRAL_FREEZE_BYTES = 256 * 1024
MAX_PACKET_BYTES = 4 * 1024 * 1024
MAX_PACKET_DIRECTORY_BYTES = 64 * 1024 * 1024
MAX_GIT_OUTPUT_BYTES = 64 * 1024 * 1024
MAX_GIT_STDERR_BYTES = 64 * 1024
MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_TOTAL_FILE_BYTES = 128 * 1024 * 1024
MAX_ROWS = 10_000
MAX_ENTRIES = 10_000
MAX_CELL_BYTES = 16 * 1024
MAX_PATH_BYTES = 4096
MAX_CATALOG_ITEMS = 4096
MAX_JSON_DEPTH = 32
GIT_TIMEOUT_SECONDS = 10.0
GIT_EXECUTABLE = "/usr/bin/git"
GIT_GLOBAL_OPTIONS = (
    "--no-replace-objects",
    "--literal-pathspecs",
    "-c",
    "core.fsmonitor=false",
    "-c",
    f"core.hooksPath={os.devnull}",
    "-c",
    "core.pager=cat",
    "-c",
    "pager.status=false",
    "-c",
    "diff.external=",
    "-c",
    "interactive.diffFilter=",
    "-c",
    "credential.helper=",
    "-c",
    "protocol.ext.allow=never",
)

HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
TOKEN = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
CLASSIFICATION_RULE_ID = re.compile(r"^[A-Z][A-Za-z0-9_]{0,127}$")
REQUIREMENT_ID = re.compile(r"^CH-T002-(?:N|R)[0-9]{2}$")
NORMATIVE_REQUIREMENT_ID = re.compile(r"^CH-T002-N[0-9]{2}$")
EVIDENCE_ID = re.compile(r"^CH-T002-E(?:0[1-9]|1[0-3])$")
EVIDENCE_POINTER = re.compile(
    r"^(CH-T002-E(?:0[1-9]|1[0-3]))#([0-9a-f]{64}):"
    r"(PRIMARY|SECONDARY|PROVENANCE|LICENSE)$"
)
EVIDENCE_FRAGMENT_ROLES = {
    "CH-T002-E09": frozenset({"PRIMARY", "SECONDARY", "PROVENANCE", "LICENSE"}),
    "CH-T002-E10": frozenset({"PRIMARY", "SECONDARY"}),
    "CH-T002-E11": frozenset({"PRIMARY", "SECONDARY"}),
    "CH-T002-E12": frozenset({"PRIMARY", "SECONDARY"}),
}
EVIDENCE_CATALOG = (
    "CH-T002-E01",
    "CH-T002-E02",
    "CH-T002-E03",
    "CH-T002-E04",
    "CH-T002-E05",
    "CH-T002-E06",
    "CH-T002-E07",
    "CH-T002-E08",
    "CH-T002-E09",
    "CH-T002-E10",
    "CH-T002-E11",
    "CH-T002-E12",
    "CH-T002-E13",
)
NORMATIVE_REQUIREMENT_CATALOG = (
    "CH-T002-N01",
    "CH-T002-N02",
    "CH-T002-N03",
    "CH-T002-N04",
    "CH-T002-N05",
    "CH-T002-N06",
    "CH-T002-N07",
    "CH-T002-N08",
    "CH-T002-N09",
    "CH-T002-N10",
    "CH-T002-N11",
    "CH-T002-N12",
    "CH-T002-N13",
    "CH-T002-N14",
    "CH-T002-N15",
    "CH-T002-N16",
    "CH-T002-N17",
    "CH-T002-N18",
    "CH-T002-N19",
    "CH-T002-N20",
)
NORMATIVE_CONTROL_KEYS = frozenset(
    {"accepted_test_id", "id", "rejected_test_id", "statement"}
)
MACHINE_POINTER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/#@+-]{0,511}$")
PRINCIPAL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.@+-]{0,254}$")
RFC3339_UTC = re.compile(
    r"^[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])"
    r"T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$"
)
FINGERPRINT = re.compile(r"^SHA256:[A-Za-z0-9+/]{43}$")
FORMULA_PREFIXES = frozenset("=+-@")
CONTENT_KINDS = frozenset({"BINARY", "TEXT_UTF8", "TEXT_UTF8_WITH_ANSI_ESCAPE"})
CRITICALITY_ORDER = (
    "PUBLIC_SURFACE",
    "SECURITY_CRITICAL",
    "SCIENCE_CRITICAL",
    "AUTHORITY_CRITICAL",
)
ENTRY_STATUSES = frozenset(
    {
        "ADDED_FREEZE_DELTA",
        "MODIFIED_FREEZE_DELTA",
        "LEDGER_SELF_EXTERNAL_BINDING",
    }
)
LANE_KINDS = {
    1: "INDEPENDENT_REVIEW",
    2: "INDEPENDENT_REVIEW_LANE_02",
    3: "INDEPENDENT_REVIEW_LANE_03",
}
LEAD_KIND = "LEAD_IMPLEMENTATION_REVIEW"
ALLOWED_REVIEW_DISPOSITIONS = frozenset({"ACCEPTED"})
ALLOWED_EXTERNAL_GENERATORS = frozenset(
    {"PINNED_CARGO_1.96.0_FROM_WORKSPACE_MANIFESTS"}
)
CLASSIFICATION_SOURCE_BASES = frozenset(
    {
        "EXPLICIT_CH_T002_F_ADDITION_POLICY_V1",
        "INDEPENDENT_AUDIT_CURRENT_A_ENTRY",
        CLASSIFICATION_OVERRIDE_SOURCE_BASIS,
    }
)

_DARWIN_RENAME_EXCL = 0x00000004
_LINUX_RENAME_NOREPLACE = 0x00000001
_ATOMIC_RENAME_UNSUPPORTED_ERRNOS = frozenset(
    {errno.ENOSYS, errno.ENOTSUP, errno.EOPNOTSUPP, errno.EINVAL}
)


class PacketError(RuntimeError):
    """A bounded validation or publication operation failed closed."""


class AtomicRenameUnavailable(PacketError):
    """The platform cannot prove an atomic no-replace publication."""


def _git_blob_read_command(object_id: str) -> list[str]:
    """Return the frozen replacement-disabled exact-blob reconstruction command."""

    return [GIT_EXECUTABLE, *GIT_GLOBAL_OPTIONS, "cat-file", "blob", object_id]


@dataclass(frozen=True)
class Subject:
    path: str
    git_mode: str
    git_object_id: str
    sha256: str
    size: int
    lines: int | None
    content_kind: str
    language: str
    criticality: tuple[str, ...]
    status: str
    subject_id: str
    units: int

    def packet_record(self, *, freeze_commit: str, freeze_tree: str) -> dict[str, Any]:
        byte_interval = {"end_exclusive": self.size, "start_inclusive": 0}
        if self.content_kind == "BINARY":
            coverage: dict[str, Any] = {
                "byte_interval": byte_interval,
                "chunk_bytes": BINARY_UNIT_BYTES,
                "chunk_count": max(math.ceil(self.size / BINARY_UNIT_BYTES), 1),
                "kind": COVERAGE_RULE,
                "line_interval": None,
                "read_command": _git_blob_read_command(self.git_object_id),
            }
        else:
            coverage = {
                "byte_interval": byte_interval,
                "chunk_bytes": None,
                "chunk_count": None,
                "kind": COVERAGE_RULE,
                "line_interval": (
                    None
                    if self.lines == 0
                    else {
                        "end_inclusive": self.lines,
                        "start_inclusive": 1,
                    }
                ),
                "read_command": _git_blob_read_command(self.git_object_id),
            }
        return {
            "bytes": self.size,
            "content_kind": self.content_kind,
            "content_commit": freeze_commit,
            "content_tree": freeze_tree,
            "coverage": coverage,
            "criticality": list(self.criticality),
            "git_mode": self.git_mode,
            "git_object_id": self.git_object_id,
            "language": self.language,
            "lines": self.lines,
            "path": self.path,
            "sha256": self.sha256,
            "status": self.status,
            "subject_id": self.subject_id,
            "snapshot_state": "PRESENT_AT_CH_T002_F",
            "units": self.units,
        }


@dataclass(frozen=True)
class Reviewer:
    lane: int
    requirement_id: str
    kind: str
    name: str
    principal: str
    classification: str
    organization: str
    key_fingerprint: str

    def packet_record(self) -> dict[str, Any]:
        return {
            "classification": self.classification,
            "key_fingerprint": self.key_fingerprint,
            "kind": self.kind,
            "name": self.name,
            "organization": self.organization,
            "principal": self.principal,
            "requirement_id": self.requirement_id,
        }


@dataclass
class Lane:
    number: int
    reviewer: Reviewer
    primary: list[Subject]
    secondary: list[Subject]
    total_units: int = 0
    item_count: int = 0

    @property
    def primary_units(self) -> int:
        return sum(subject.units for subject in self.primary)

    @property
    def secondary_units(self) -> int:
        return sum(subject.units for subject in self.secondary)


@dataclass(frozen=True)
class GitSnapshot:
    freeze_commit: str
    freeze_tree: str
    implementation_commit: str
    implementation_tree: str
    ledger_blob_id: str
    overlay_blob_id: str
    registry_blob_id: str


@dataclass(frozen=True)
class PreparedInputs:
    overlay: dict[str, Any]
    ledger_rows: tuple[dict[str, str], ...]
    subjects: tuple[Subject, ...]
    reviewers: tuple[Reviewer, ...]
    lanes: tuple[Lane, ...]
    snapshot: GitSnapshot
    ledger_sha256: str
    overlay_sha256: str
    registry_sha256: str
    freeze_regular_blobs: int


def _canonical_json(value: Any) -> bytes:
    try:
        rendered = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError, RecursionError) as exc:
        raise PacketError("value cannot be rendered as canonical JSON") from exc
    return rendered.encode("utf-8") + b"\n"


def _canonical_pretty_json(value: Any) -> bytes:
    """Render the central freeze format while preserving its frozen key order."""

    try:
        rendered = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            indent=2,
        )
    except (TypeError, ValueError, RecursionError) as exc:
        raise PacketError("value cannot be rendered as canonical pretty JSON") from exc
    return rendered.encode("utf-8") + b"\n"


def _canonical_payload(value: Any) -> bytes:
    return _canonical_json(value)[:-1]


def _pairs_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PacketError("JSON object contains a duplicate key")
        result[key] = value
    return result


def _json_depth(value: Any, depth: int = 0) -> int:
    if depth > MAX_JSON_DEPTH:
        raise PacketError("JSON nesting exceeds the configured bound")
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str):
                raise PacketError("JSON object key is not text")
            _json_depth(child, depth + 1)
    elif isinstance(value, list):
        for child in value:
            _json_depth(child, depth + 1)
    return depth


def _decode_json_object(data: bytes, *, label: str) -> dict[str, Any]:
    if len(data) > MAX_JSON_BYTES:
        raise PacketError(f"{label} exceeds the JSON byte bound")
    if not data.endswith(b"\n") or data.endswith(b"\n\n") or b"\r" in data:
        raise PacketError(f"{label} is not canonical JSON plus one LF")
    try:
        text = data.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise PacketError(f"{label} is not strict UTF-8") from exc
    try:
        value = json.loads(
            text,
            object_pairs_hook=_pairs_no_duplicates,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                PacketError(f"{label} contains a non-finite number")
            ),
        )
    except PacketError:
        raise
    except (json.JSONDecodeError, RecursionError) as exc:
        raise PacketError(f"{label} is not valid bounded JSON") from exc
    if not isinstance(value, dict):
        raise PacketError(f"{label} top level is not an object")
    _json_depth(value)
    return value


def _parse_canonical_json(data: bytes, *, label: str) -> dict[str, Any]:
    value = _decode_json_object(data, label=label)
    if _canonical_json(value) != data:
        raise PacketError(f"{label} is not in the frozen canonical encoding")
    return value


def _parse_pretty_canonical_json(data: bytes, *, label: str) -> dict[str, Any]:
    value = _decode_json_object(data, label=label)
    if _canonical_pretty_json(value) != data:
        raise PacketError(f"{label} is not in the central pretty canonical encoding")
    return value


def _parse_central_freeze_json(data: bytes) -> dict[str, Any]:
    if len(data) > MAX_CENTRAL_FREEZE_BYTES:
        raise PacketError("central freeze exceeds its 256-KiB byte bound")
    return _parse_pretty_canonical_json(data, label="central freeze reviewer registry")


def _expect_keys(value: Any, expected: frozenset[str], *, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise PacketError(f"{label} does not have the exact frozen key set")
    return value


def _expect_string(
    value: Any,
    *,
    label: str,
    maximum: int = MAX_CELL_BYTES,
    allow_empty: bool = False,
    formula_safe: bool = True,
) -> str:
    if not isinstance(value, str):
        raise PacketError(f"{label} is not text")
    encoded = value.encode("utf-8", "strict")
    if len(encoded) > maximum or (not allow_empty and not value):
        raise PacketError(f"{label} violates its text length bound")
    if value != value.strip():
        raise PacketError(f"{label} contains leading or trailing whitespace")
    if unicodedata.normalize("NFC", value) != value:
        raise PacketError(f"{label} is not NFC-normalized")
    if any(unicodedata.category(character).startswith("C") for character in value):
        raise PacketError(f"{label} contains a control character")
    if formula_safe and value and value[0] in FORMULA_PREFIXES:
        raise PacketError(f"{label} has a spreadsheet-formula prefix")
    return value


def _expect_int(
    value: Any, *, label: str, minimum: int = 0, maximum: int = 2**63 - 1
) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise PacketError(f"{label} is outside its integer bound")
    return value


def _expect_bool(value: Any, *, label: str) -> bool:
    if type(value) is not bool:
        raise PacketError(f"{label} is not a Boolean")
    return value


def _strict_equal(value: Any, expected: Any) -> bool:
    if type(value) is not type(expected):
        return False
    if isinstance(value, dict):
        return value.keys() == expected.keys() and all(
            _strict_equal(value[key], expected[key]) for key in value
        )
    if isinstance(value, (list, tuple)):
        return len(value) == len(expected) and all(
            _strict_equal(left, right)
            for left, right in zip(value, expected, strict=True)
        )
    return value == expected


def _expect_exact(value: Any, expected: Any, *, label: str) -> None:
    if not _strict_equal(value, expected):
        raise PacketError(f"{label} does not equal the frozen value")


def _expect_hex(value: Any, pattern: re.Pattern[str], *, label: str) -> str:
    text = _expect_string(value, label=label)
    if pattern.fullmatch(text) is None:
        raise PacketError(f"{label} is not a canonical object identity")
    return text


def _expect_path(value: Any, *, label: str) -> str:
    text = _expect_string(value, label=label, maximum=MAX_PATH_BYTES)
    if "\\" in text or text.startswith("/") or text.endswith("/"):
        raise PacketError(f"{label} is not a canonical repository path")
    path = PurePosixPath(text)
    if (
        not path.parts
        or any(part in {"", ".", ".."} for part in path.parts)
        or any(part.lower() == ".git" for part in path.parts)
        or path.as_posix() != text
    ):
        raise PacketError(f"{label} is not a safe repository path")
    return text


def _expect_sorted_unique_strings(
    value: Any,
    *,
    label: str,
    paths: bool = False,
    maximum_items: int = MAX_CATALOG_ITEMS,
) -> tuple[str, ...]:
    if not isinstance(value, list) or len(value) > maximum_items:
        raise PacketError(f"{label} is not a bounded list")
    parsed = tuple(
        _expect_path(item, label=f"{label} item")
        if paths
        else _expect_string(item, label=f"{label} item")
        for item in value
    )
    if tuple(sorted(parsed, key=lambda item: item.encode("utf-8"))) != parsed:
        raise PacketError(f"{label} is not raw-UTF-8 byte sorted")
    if len(set(parsed)) != len(parsed):
        raise PacketError(f"{label} contains a duplicate")
    if paths:
        _expect_portable_unique(parsed, label=label)
    return parsed


def _expect_portable_unique(values: Iterable[str], *, label: str) -> None:
    observed: dict[str, str] = {}
    for value in values:
        folded = unicodedata.normalize("NFC", value).casefold()
        previous = observed.get(folded)
        if previous is not None and previous != value:
            raise PacketError(f"{label} contains a portable casefold collision")
        observed[folded] = value


def _domain_digest(domain: str, value: Any) -> str:
    digest = hashlib.sha256()
    digest.update(domain.encode("ascii"))
    digest.update(b"\0")
    digest.update(_canonical_payload(value))
    return digest.hexdigest()


def _subject_identity(record: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "bytes": record["bytes"],
        "content_kind": record["content_kind"],
        "git_mode": record["git_mode"],
        "git_object_id": record["git_object_id"],
        "lines": record["lines"],
        "path": record["path"],
        "sha256": record["sha256"],
    }


def subject_id(record: Mapping[str, Any]) -> str:
    return _domain_digest(
        SCHEMA["digest_domains"]["subject"], _subject_identity(record)
    )


def _subject_set_digest(
    subjects: Iterable[Subject], *, freeze_commit: str, freeze_tree: str
) -> str:
    records = [
        subject.packet_record(
            freeze_commit=freeze_commit,
            freeze_tree=freeze_tree,
        )
        for subject in subjects
    ]
    records.sort(key=lambda record: record["subject_id"].encode("utf-8"))
    return _domain_digest(SCHEMA["digest_domains"]["subject_set"], records)


def _language(path: str) -> str:
    name = PurePosixPath(path).name.casefold()
    exact = {
        ".gitignore": "GITIGNORE",
        ".ncp-consumer": "NCP_CONSUMER_MARKER",
        "allowed-signers": "SSH_ALLOWED_SIGNERS",
        "cargo.lock": "TOML_LOCK",
        "cargo.toml": "TOML",
        "deny.toml": "TOML",
        "dockerfile": "DOCKERFILE",
        "justfile": "JUST",
        "license": "LICENSE_TEXT",
        "license-apache": "LICENSE_TEXT",
        "license-mit": "LICENSE_TEXT",
        "makefile": "MAKE",
        "readme": "TEXT",
        "security.md": "MARKDOWN",
    }
    if name in exact:
        return exact[name]
    suffix = PurePosixPath(path).suffix.casefold()
    by_suffix = {
        ".bash": "SHELL",
        ".bin": "BINARY_DATA",
        ".c": "C",
        ".cc": "CPP",
        ".cfg": "CONFIG",
        ".cpp": "CPP",
        ".css": "CSS",
        ".csv": "CSV",
        ".dat": "BINARY_DATA",
        ".dockerignore": "DOCKERIGNORE",
        ".gz": "GZIP",
        ".h": "C_HEADER",
        ".hex": "HEX",
        ".hpp": "CPP_HEADER",
        ".html": "HTML",
        ".js": "JAVASCRIPT",
        ".json": "JSON",
        ".json5": "JSON5",
        ".jsonl": "JSON_LINES",
        ".lock": "LOCKFILE",
        ".log": "LOG_TEXT",
        ".md": "MARKDOWN",
        ".pem": "PEM",
        ".proto": "PROTOBUF",
        ".py": "PYTHON",
        ".rs": "RUST",
        ".rst": "RESTRUCTURED_TEXT",
        ".sh": "SHELL",
        ".sha256": "SHA256SUMS",
        ".svg": "SVG",
        ".tla": "TLA_PLUS",
        ".toml": "TOML",
        ".ts": "TYPESCRIPT",
        ".tsx": "TYPESCRIPT_TSX",
        ".txt": "TEXT",
        ".xml": "XML",
        ".yaml": "YAML",
        ".yml": "YAML",
        ".zip": "ZIP",
        ".zsh": "SHELL",
    }
    return by_suffix.get(suffix, "UNKNOWN")


def _required_criticality(path: str) -> frozenset[str]:
    """Return only the explicit safety floors layered over the exact catalog."""

    required: set[str] = set()
    parts = PurePosixPath(path).parts
    if path.startswith("release/0.9.0/current-head/"):
        required.add("AUTHORITY_CRITICAL")
    if path.startswith("tools/release/"):
        required.add("SECURITY_CRITICAL")
        if path != TEST_ONLY_AUTHORITY_FLOOR_EXCEPTION:
            required.add("AUTHORITY_CRITICAL")
    if path == CENTRAL_REGISTRY_PATH:
        required.update({"SECURITY_CRITICAL", "AUTHORITY_CRITICAL"})
    if path in {".github/workflows/ci.yml", "justfile", "tools/p0r-exit-gate.sh"}:
        required.update({"SECURITY_CRITICAL", "AUTHORITY_CRITICAL"})
    if (
        path in {"README.md", "SECURITY.md"}
        or path.startswith("docs/")
        or (len(parts) == 4 and parts[0] == "crates" and parts[2:] == ("src", "lib.rs"))
    ):
        required.add("PUBLIC_SURFACE")
    return frozenset(required)


def _expect_key_order(
    value: Any, expected: Sequence[str], *, label: str
) -> dict[str, Any]:
    if not isinstance(value, dict) or tuple(value) != tuple(expected):
        raise PacketError(f"{label} does not have the exact frozen key order")
    return value


def _classification_criticality(record: Mapping[str, Any]) -> tuple[str, ...]:
    return tuple(
        token
        for field, token in (
            ("public_surface", "PUBLIC_SURFACE"),
            ("security_critical", "SECURITY_CRITICAL"),
            ("science_critical", "SCIENCE_CRITICAL"),
            ("authority_critical", "AUTHORITY_CRITICAL"),
        )
        if record[field] == "YES"
    )


def _validate_classification_record(value: Any) -> dict[str, Any]:
    record = _expect_key_order(
        value,
        CLASSIFICATION_RECORD_KEY_ORDER,
        label="review classification record",
    )
    path = _expect_path(record["path"], label="classification path")
    for field in (
        "authority_critical",
        "public_surface",
        "science_critical",
        "security_critical",
    ):
        if record[field] not in {"YES", "NO"}:
            raise PacketError("classification critical flag is not YES or NO")
    criticality = _classification_criticality(record)
    if not _required_criticality(path).issubset(criticality):
        raise PacketError("classification record is below a mandatory path floor")
    if record["generated"] not in {"YES", "NO"}:
        raise PacketError("classification generated decision is not YES or NO")
    generator = _expect_string(
        record["generator"], label="classification generator", allow_empty=True
    )
    if record["generated"] == "YES":
        if not generator:
            raise PacketError("generated classification lacks its generator")
        if generator not in ALLOWED_EXTERNAL_GENERATORS:
            _expect_path(generator, label="classification generator path")
    elif generator:
        raise PacketError("non-generated classification names a generator")
    _expect_exact(
        record["provenance_review_status"],
        "CONFIRMED",
        label="classification provenance decision",
    )
    license_status = record["license_review_status"]
    if license_status == "APPROVED":
        if record["license_expression"] not in {
            "Apache-2.0",
            "Apache-2.0 OR MIT",
            "MIT",
            "MIT OR Apache-2.0",
        }:
            raise PacketError("classification license expression is not approved")
    elif license_status == "NOT_APPLICABLE":
        _expect_exact(
            record["license_expression"],
            "NOT_APPLICABLE",
            label="classification not-applicable license expression",
        )
    else:
        raise PacketError("classification license decision is unresolved")
    rules = record["rule_ids"]
    if not isinstance(rules, list) or len(rules) != 6 or len(set(rules)) != 6:
        raise PacketError("classification record lacks six distinct audit rules")
    prefixes = ("PUB_", "SEC_", "SCI_", "AUTH_", "GEN_", "LIC_")
    for rule, prefix in zip(rules, prefixes, strict=True):
        text = _expect_string(rule, label="classification rule ID", maximum=128)
        if CLASSIFICATION_RULE_ID.fullmatch(text) is None or not text.startswith(
            prefix
        ):
            raise PacketError(
                "classification rule ID has invalid grammar or field prefix"
            )
    for flag, rule, prefix in (
        (record["public_surface"], rules[0], "PUB_"),
        (record["security_critical"], rules[1], "SEC_"),
        (record["science_critical"], rules[2], "SCI_"),
        (record["authority_critical"], rules[3], "AUTH_"),
        (record["generated"], rules[4], "GEN_"),
    ):
        if not rule.startswith(f"{prefix}{flag}_"):
            raise PacketError(
                "classification rule YES/NO role contradicts its decision"
            )
    license_rule = rules[5]
    if license_status == "NOT_APPLICABLE":
        if not license_rule.startswith("LIC_NA_"):
            raise PacketError(
                "classification license rule contradicts not-applicable status"
            )
    elif not license_rule.startswith(("LIC_REPOSITORY_", "LIC_PINNED_")):
        raise PacketError("classification license rule contradicts approved status")
    source_basis = _expect_string(
        record["source_basis"], label="classification source basis"
    )
    if source_basis not in CLASSIFICATION_SOURCE_BASES:
        raise PacketError("classification source basis is not frozen")
    return record


def _classification_counts(
    records: Iterable[Mapping[str, Any]],
) -> dict[str, int]:
    values = tuple(records)
    return {
        "authority_critical_no": sum(
            record["authority_critical"] == "NO" for record in values
        ),
        "authority_critical_yes": sum(
            record["authority_critical"] == "YES" for record in values
        ),
        "generated_no": sum(record["generated"] == "NO" for record in values),
        "generated_yes": sum(record["generated"] == "YES" for record in values),
        "license_review_status_approved": sum(
            record["license_review_status"] == "APPROVED" for record in values
        ),
        "license_review_status_not_applicable": sum(
            record["license_review_status"] == "NOT_APPLICABLE" for record in values
        ),
        "paths": len(values),
        "provenance_review_status_confirmed": sum(
            record["provenance_review_status"] == "CONFIRMED" for record in values
        ),
        "public_surface_no": sum(record["public_surface"] == "NO" for record in values),
        "public_surface_yes": sum(
            record["public_surface"] == "YES" for record in values
        ),
        "science_critical_no": sum(
            record["science_critical"] == "NO" for record in values
        ),
        "science_critical_yes": sum(
            record["science_critical"] == "YES" for record in values
        ),
        "security_critical_no": sum(
            record["security_critical"] == "NO" for record in values
        ),
        "security_critical_yes": sum(
            record["security_critical"] == "YES" for record in values
        ),
    }


def _validate_classification_count_vector(
    value: Any, *, population: int, label: str
) -> dict[str, int]:
    vector = _expect_key_order(value, CLASSIFICATION_COUNT_KEY_ORDER, label=label)
    if any(type(item) is not int or item < 0 for item in vector.values()):
        raise PacketError(f"{label} contains a noncanonical count")
    if (
        vector["paths"] != population
        or vector["provenance_review_status_confirmed"] != population
        or vector["authority_critical_no"] + vector["authority_critical_yes"]
        != population
        or vector["generated_no"] + vector["generated_yes"] != population
        or vector["license_review_status_approved"]
        + vector["license_review_status_not_applicable"]
        != population
        or vector["public_surface_no"] + vector["public_surface_yes"] != population
        or vector["science_critical_no"] + vector["science_critical_yes"] != population
        or vector["security_critical_no"] + vector["security_critical_yes"]
        != population
    ):
        raise PacketError(f"{label} does not sum to its declared population")
    return vector


def _sum_classification_counts(
    left: Mapping[str, int], right: Mapping[str, int]
) -> dict[str, int]:
    return {key: left[key] + right[key] for key in CLASSIFICATION_COUNT_KEY_ORDER}


def _validate_classification_overrides(
    value: Any,
    by_path: Mapping[str, Mapping[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    policy = _expect_key_order(
        value,
        CLASSIFICATION_OVERRIDE_KEY_ORDER,
        label="classification override policy",
    )
    _expect_exact(
        policy["policy_id"],
        CLASSIFICATION_OVERRIDE_POLICY_ID,
        label="classification override policy ID",
    )
    _expect_exact(
        policy["order"],
        CLASSIFICATION_OVERRIDE_ORDER,
        label="classification override order",
    )
    raw_paths = policy["paths"]
    if not isinstance(raw_paths, list):
        raise PacketError("classification override paths are not a list")
    paths = tuple(
        _expect_path(path, label="classification override path") for path in raw_paths
    )
    if paths != tuple(sorted(paths, key=lambda path: path.encode("utf-8"))):
        raise PacketError("classification override paths are not raw-byte sorted")
    if len(paths) != len(set(paths)):
        raise PacketError("classification override paths contain a duplicate")
    _expect_portable_unique(paths, label="classification override paths")
    _expect_exact(
        policy["path_count"], len(paths), label="classification override path count"
    )
    raw_rows = policy["overrides"]
    if not isinstance(raw_rows, list) or len(raw_rows) > MAX_ENTRIES:
        raise PacketError("classification override rows are not a bounded list")
    rows = [
        _expect_key_order(
            row,
            CLASSIFICATION_OVERRIDE_RECORD_KEY_ORDER,
            label="classification override row",
        )
        for row in raw_rows
    ]
    _expect_exact(
        policy["field_override_count"],
        len(rows),
        label="classification override field count",
    )
    row_order: list[tuple[bytes, bytes]] = []
    row_keys: set[tuple[str, str]] = set()
    row_paths: set[str] = set()
    source_by_path = {
        path: dict(record)
        for path, record in by_path.items()
        if record["source_basis"] != "EXPLICIT_CH_T002_F_ADDITION_POLICY_V1"
    }
    grouped_fields: dict[str, set[str]] = defaultdict(set)
    field_specs = {
        "public_surface": (0, "PUB_", True),
        "security_critical": (1, "SEC_", True),
        "science_critical": (2, "SCI_", True),
        "authority_critical": (3, "AUTH_", True),
        "generated": (4, "GEN_", True),
        "generator": (4, "GEN_", False),
    }
    for row in rows:
        path = _expect_path(row["path"], label="classification override row path")
        field = _expect_string(row["field"], label="classification override field")
        if field not in field_specs:
            raise PacketError("classification override changes a forbidden field")
        key = (path, field)
        if key in row_keys:
            raise PacketError("classification override repeats a path/field")
        row_keys.add(key)
        row_paths.add(path)
        grouped_fields[path].add(field)
        row_order.append((path.encode("utf-8"), field.encode("ascii")))
        record = by_path.get(path)
        if (
            record is None
            or record["source_basis"] != CLASSIFICATION_OVERRIDE_SOURCE_BASIS
        ):
            raise PacketError(
                "classification override path is not current-A override data"
            )
        index, prefix, boolean_field = field_specs[field]
        before = _expect_string(
            row["before"],
            label="classification override before value",
            allow_empty=not boolean_field,
        )
        after = _expect_string(
            row["after"],
            label="classification override after value",
            allow_empty=not boolean_field,
        )
        if boolean_field and ({before, after} - {"YES", "NO"} or before == after):
            raise PacketError("classification boolean override is not bidirectional")
        if not boolean_field:
            for generator in (before, after):
                if generator:
                    _expect_path(generator, label="classification override generator")
                    if generator not in by_path:
                        raise PacketError(
                            "classification override generator is not a tracked F path"
                        )
            if before == after:
                raise PacketError("classification generator override does not change")
        _expect_exact(record[field], after, label="classification override final value")
        rule = _expect_string(
            row["rule_id"], label="classification override rule", maximum=128
        )
        if (
            CLASSIFICATION_RULE_ID.fullmatch(rule) is None
            or not rule.startswith(prefix)
            or rule != record["rule_ids"][index]
        ):
            raise PacketError(
                "classification override rule contradicts its final record"
            )
        _expect_exact(
            row["source_basis"],
            CLASSIFICATION_OVERRIDE_SOURCE_BASIS,
            label="classification override source basis",
        )
        source_by_path[path][field] = before
    if row_order != sorted(row_order):
        raise PacketError("classification override rows are not path/field sorted")
    if row_paths != set(paths):
        raise PacketError("classification override rows and path catalog disagree")
    record_override_paths = {
        path
        for path, record in by_path.items()
        if record["source_basis"] == CLASSIFICATION_OVERRIDE_SOURCE_BASIS
    }
    if record_override_paths != set(paths):
        raise PacketError("classification override record partition is contradictory")
    for path, fields in grouped_fields.items():
        generator_fields = fields & {"generated", "generator"}
        if generator_fields and generator_fields != {"generated", "generator"}:
            raise PacketError(
                "classification generated/generator overrides are not atomic"
            )
        if generator_fields:
            for label, record in (
                ("before", source_by_path[path]),
                ("after", by_path[path]),
            ):
                generated = record["generated"]
                generator = record["generator"]
                if (generated == "YES") != bool(generator):
                    raise PacketError(
                        f"classification {label} generated/generator values disagree"
                    )
                if generator and generator not in by_path:
                    raise PacketError(
                        f"classification {label} generator is not a tracked F path"
                    )
    if tuple(paths) != tuple(CLASSIFICATION_OVERRIDE_PATHS):
        raise PacketError("classification override paths differ from the reviewed pin")
    if (
        EXPECTED_CLASSIFICATION_OVERRIDE_FIELDS is None
        or EXPECTED_CLASSIFICATION_OVERRIDE_SET_SHA256 is None
    ):
        raise PacketError("classification override pins are not finalized")
    _expect_exact(
        len(rows),
        EXPECTED_CLASSIFICATION_OVERRIDE_FIELDS,
        label="classification reviewed override field count",
    )
    _expect_exact(
        _domain_digest(CLASSIFICATION_OVERRIDE_SET_DOMAIN, rows),
        EXPECTED_CLASSIFICATION_OVERRIDE_SET_SHA256,
        label="classification reviewed override-set digest",
    )
    return rows, source_by_path


def _validate_classification_contract(
    overlay: Mapping[str, Any],
    freeze_inventory: Mapping[str, tuple[str, str]],
    historical_paths: Sequence[str],
) -> dict[str, Mapping[str, Any]]:
    contract = _expect_key_order(
        overlay.get("review_classification_contract"),
        CLASSIFICATION_CONTRACT_KEY_ORDER,
        label="review classification contract",
    )
    _expect_exact(
        contract["schema_id"],
        CLASSIFICATION_CONTRACT_SCHEMA_ID,
        label="classification contract schema",
    )
    source = _expect_key_order(
        contract["source_audit"],
        CLASSIFICATION_SOURCE_KEY_ORDER,
        label="classification source audit",
    )
    _expect_exact(
        source,
        {
            "schema_id": CLASSIFICATION_AUDIT_SCHEMA_ID,
            "sha256": CLASSIFICATION_AUDIT_SHA256,
            "current_a_commit": CLASSIFICATION_AUDIT_COMMIT,
            "current_a_tree": CLASSIFICATION_AUDIT_TREE,
        },
        label="classification source audit binding",
    )
    semantics = _expect_key_order(
        contract["semantics"],
        CLASSIFICATION_SEMANTICS_KEY_ORDER,
        label="classification semantics",
    )
    _expect_exact(
        semantics,
        {
            "generated": CLASSIFICATION_GENERATED_SEMANTICS,
            "primary_capture": CLASSIFICATION_PRIMARY_CAPTURE_SEMANTICS,
        },
        label="classification generated/capture semantics",
    )
    _expect_exact(contract["path_order"], PATH_ORDER, label="classification path order")
    records = contract["records"]
    if (
        not isinstance(records, list)
        or len(records) != EXPECTED_CLASSIFICATION_RECORDS
        or len(records) > MAX_ENTRIES
    ):
        raise PacketError("classification contract has the wrong record count")
    parsed = [_validate_classification_record(record) for record in records]
    paths = tuple(record["path"] for record in parsed)
    if paths != tuple(sorted(paths, key=lambda item: item.encode("utf-8"))):
        raise PacketError("classification records are not raw-UTF-8 path sorted")
    if len(set(paths)) != len(paths):
        raise PacketError("classification records contain a duplicate path")
    _expect_portable_unique(paths, label="classification record paths")
    if set(paths) != set(freeze_inventory):
        raise PacketError("classification records do not equal the freeze tree")
    by_path = {record["path"]: record for record in parsed}
    expected_extension_paths = {
        record["path"]
        for record in parsed
        if record["source_basis"] == "EXPLICIT_CH_T002_F_ADDITION_POLICY_V1"
    }
    if expected_extension_paths != set(CLASSIFICATION_F_EXTENSION_PATHS):
        raise PacketError("classification F-extension partition is contradictory")
    _override_rows, source_by_path = _validate_classification_overrides(
        contract["override_policy"], by_path
    )
    current_a_records = [
        record
        for record in parsed
        if record["source_basis"] != "EXPLICIT_CH_T002_F_ADDITION_POLICY_V1"
    ]
    f_additions = [
        record
        for record in parsed
        if record["source_basis"] == "EXPLICIT_CH_T002_F_ADDITION_POLICY_V1"
    ]
    historical = tuple(historical_paths)
    if len(historical) != len(set(historical)):
        raise PacketError("historical classification paths contain a duplicate")
    historical_current_a = tuple(path for path in historical if path in source_by_path)
    count_sets = _expect_key_order(
        contract["counts"],
        CLASSIFICATION_COUNT_SET_KEY_ORDER,
        label="classification count sets",
    )
    expected_counts = {
        "f_additions": _classification_counts(f_additions),
        "final_current_a": _classification_counts(current_a_records),
        "final_f": _classification_counts(parsed),
        "final_historical_ledger_subjects": _classification_counts(
            by_path[path] for path in historical_current_a
        ),
        "source_current_a": _classification_counts(source_by_path.values()),
    }
    populations = {
        "f_additions": len(f_additions),
        "final_current_a": len(current_a_records),
        "final_f": len(parsed),
        "final_historical_ledger_subjects": len(historical_current_a),
        "source_current_a": len(source_by_path),
    }
    for label in CLASSIFICATION_COUNT_SET_KEY_ORDER:
        vector = _validate_classification_count_vector(
            count_sets[label], population=populations[label], label=f"{label} counts"
        )
        _expect_exact(vector, expected_counts[label], label=f"{label} exact counts")
    _expect_exact(
        count_sets["final_f"],
        _sum_classification_counts(
            count_sets["final_current_a"], count_sets["f_additions"]
        ),
        label="classification final-F additive counts",
    )
    if len(parsed) == FINAL_F_CLASSIFICATION_COUNTS["paths"]:
        _expect_exact(
            count_sets,
            EXPECTED_CLASSIFICATION_COUNT_SETS,
            label="classification production count sets",
        )
    if len(current_a_records) == 388:
        _expect_exact(
            count_sets["source_current_a"],
            SOURCE_CURRENT_A_CLASSIFICATION_COUNTS,
            label="classification immutable current-A source counts",
        )
    if len(historical_current_a) == 356:
        _expect_exact(
            _classification_counts(
                source_by_path[path] for path in historical_current_a
            ),
            SOURCE_HISTORICAL_CLASSIFICATION_COUNTS,
            label="classification immutable historical source counts",
        )
    digest = _domain_digest(CLASSIFICATION_SET_DOMAIN, parsed)
    _expect_exact(
        contract["classification_set_sha256"],
        digest,
        label="classification contract digest",
    )
    _expect_exact(
        digest,
        EXPECTED_CLASSIFICATION_SET_SHA256,
        label="classification expected-set digest",
    )
    scope = overlay["scope"]
    _expect_exact(
        scope["classification_audit_sha256"],
        CLASSIFICATION_AUDIT_SHA256,
        label="overlay classification audit binding",
    )
    _expect_exact(
        scope["classification_policy"],
        CLASSIFICATION_POLICY,
        label="overlay classification policy",
    )
    _expect_exact(
        overlay["digests"]["classification_set_sha256"],
        digest,
        label="overlay classification-set digest",
    )
    for entry in overlay["entries"]:
        expected = by_path.get(entry["path"])
        if expected is None or not _strict_equal(
            _entry_classification_record(entry), expected
        ):
            raise PacketError(
                "overlay entry decision contradicts the classification contract"
            )
    return by_path


def _entry_classification_record(entry: Mapping[str, Any]) -> dict[str, Any]:
    criticality = set(entry["criticality"])
    return {
        "authority_critical": ("YES" if "AUTHORITY_CRITICAL" in criticality else "NO"),
        "generated": entry["generated"],
        "generator": entry["generator"],
        "license_expression": entry["license_expression"],
        "license_review_status": entry["license_review_status"],
        "path": entry["path"],
        "provenance_review_status": entry["provenance_review_status"],
        "public_surface": "YES" if "PUBLIC_SURFACE" in criticality else "NO",
        "rule_ids": entry["rule_ids"],
        "science_critical": ("YES" if "SCIENCE_CRITICAL" in criticality else "NO"),
        "security_critical": ("YES" if "SECURITY_CRITICAL" in criticality else "NO"),
        "source_basis": entry["source_basis"],
    }


def _text_line_count(text: str) -> int:
    """Count logical lines using the frozen accepted-text separator set.

    Accepted text can contain LF, CR, CRLF, U+2028, and U+2029 separators.
    CRLF is one separator, and a final separator does not create a trailing
    empty line.  Other Unicode control separators are classified as binary by
    :func:`_classify_content` before this function is used.
    """

    if not text:
        return 0
    separators = 0
    index = 0
    while index < len(text):
        character = text[index]
        if character == "\r":
            separators += 1
            index += 2 if index + 1 < len(text) and text[index + 1] == "\n" else 1
        elif character in {"\n", "\u2028", "\u2029"}:
            separators += 1
            index += 1
        else:
            index += 1
    if text.endswith(("\r", "\n", "\u2028", "\u2029")):
        return separators
    return separators + 1


def _classify_content(data: bytes) -> tuple[str, int | None]:
    if b"\x00" in data:
        return "BINARY", None
    try:
        text = data.decode("utf-8", "strict")
    except UnicodeDecodeError:
        return "BINARY", None
    controls = {
        character
        for character in text
        if character not in "\t\n\r" and unicodedata.category(character).startswith("C")
    }
    if controls == {"\x1b"}:
        return "TEXT_UTF8_WITH_ANSI_ESCAPE", _text_line_count(text)
    if controls:
        return "BINARY", None
    return "TEXT_UTF8", _text_line_count(text)


def _units(*, size: int, lines: int | None, content_kind: str) -> int:
    if content_kind == "BINARY":
        return max(math.ceil(size / BINARY_UNIT_BYTES), 1)
    if lines is None:
        raise PacketError("text subject has no line count")
    return max(lines, 1)


def _parse_decimal(value: str, *, label: str, maximum: int = 2**63 - 1) -> int:
    if (
        not value
        or (value != "0" and value.startswith("0"))
        or not value.isascii()
        or not value.isdecimal()
    ):
        raise PacketError(f"{label} is not a canonical unsigned decimal")
    number = int(value)
    if number > maximum:
        raise PacketError(f"{label} exceeds its integer bound")
    return number


def _render_ledger(rows: Sequence[Mapping[str, str]]) -> bytes:
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(
        stream,
        fieldnames=FIELDS,
        dialect="excel",
        lineterminator="\n",
        extrasaction="raise",
    )
    writer.writeheader()
    writer.writerows(rows)
    return stream.getvalue().encode("utf-8")


def _parse_ledger(data: bytes, *, label: str) -> tuple[dict[str, str], ...]:
    if len(data) > MAX_LEDGER_BYTES:
        raise PacketError(f"{label} exceeds the ledger byte bound")
    if (
        not data.endswith(b"\n")
        or data.endswith(b"\n\n")
        or b"\r" in data
        or b"\x00" in data
    ):
        raise PacketError(f"{label} is not canonical LF-only CSV")
    try:
        text = data.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise PacketError(f"{label} is not strict UTF-8") from exc
    previous_limit = csv.field_size_limit()
    try:
        csv.field_size_limit(MAX_CELL_BYTES)
        parsed = list(csv.reader(io.StringIO(text, newline=""), strict=True))
    except (csv.Error, OverflowError) as exc:
        raise PacketError(f"{label} is not valid bounded CSV") from exc
    finally:
        csv.field_size_limit(previous_limit)
    if not parsed or tuple(parsed[0]) != FIELDS:
        raise PacketError(f"{label} does not have the exact ledger header")
    if len(parsed) - 1 > MAX_ROWS:
        raise PacketError(f"{label} exceeds the row bound")
    rows: list[dict[str, str]] = []
    for number, cells in enumerate(parsed[1:], start=2):
        if len(cells) != len(FIELDS):
            raise PacketError(f"{label} row {number} has the wrong field count")
        row = dict(zip(FIELDS, cells, strict=True))
        for field, value in row.items():
            _expect_string(
                value,
                label=f"{label} row {number} field {field}",
                allow_empty=True,
            )
            if len(value.encode("utf-8")) > MAX_CELL_BYTES:
                raise PacketError(f"{label} contains an oversized cell")
        rows.append(row)
    if not rows:
        raise PacketError(f"{label} has no rows")
    paths = tuple(_expect_path(row["path"], label=f"{label} path") for row in rows)
    if paths != tuple(sorted(paths, key=lambda item: item.encode("utf-8"))):
        raise PacketError(f"{label} paths are not raw-UTF-8 byte sorted")
    if len(paths) != len(set(paths)):
        raise PacketError(f"{label} has duplicate paths")
    _expect_portable_unique(paths, label=f"{label} paths")
    if _render_ledger(rows) != data:
        raise PacketError(f"{label} is not in the frozen canonical CSV encoding")
    return tuple(rows)


def _split_catalog_cell(value: str, *, label: str) -> tuple[str, ...]:
    if not value:
        return ()
    tokens = tuple(value.split(";"))
    if any(not token for token in tokens):
        raise PacketError(f"{label} contains an empty pointer token")
    if len(set(tokens)) != len(tokens):
        raise PacketError(f"{label} contains a duplicate pointer token")
    if tokens != tuple(sorted(tokens, key=lambda item: item.encode("utf-8"))):
        raise PacketError(f"{label} pointer tokens are not byte sorted")
    return tokens


def _validate_pointer_cell(
    value: str,
    catalog: frozenset[str],
    *,
    label: str,
    required: bool,
    allow_evidence_fragments: bool = False,
    allowed_fragment_roles: frozenset[str] | None = None,
) -> None:
    tokens = _split_catalog_cell(value, label=label)
    if required and not tokens:
        raise PacketError(f"{label} is required but empty")
    for token in tokens:
        if token in catalog:
            continue
        match = EVIDENCE_POINTER.fullmatch(token) if allow_evidence_fragments else None
        if (
            match is None
            or match.group(1) not in catalog
            or match.group(1) not in EVIDENCE_FRAGMENT_ROLES
            or match.group(3) not in EVIDENCE_FRAGMENT_ROLES[match.group(1)]
            or (
                allowed_fragment_roles is not None
                and match.group(3) not in allowed_fragment_roles
            )
        ):
            raise PacketError(
                f"{label} contains a pointer absent from the frozen catalog"
            )


def _criticality_from_row(row: Mapping[str, str]) -> tuple[str, ...]:
    fields = (
        ("public_surface", "PUBLIC_SURFACE"),
        ("security_critical", "SECURITY_CRITICAL"),
        ("science_critical", "SCIENCE_CRITICAL"),
        ("authority_critical", "AUTHORITY_CRITICAL"),
    )
    return tuple(name for field, name in fields if row[field] == "YES")


def _validate_completed_ledger(
    rows: Sequence[dict[str, str]],
    original_rows: Sequence[dict[str, str]],
    overlay: Mapping[str, Any],
    classifications: Mapping[str, Mapping[str, Any]],
) -> None:
    if len(rows) != len(original_rows):
        raise PacketError("completed and frozen ledgers have different row counts")
    scope = overlay["scope"]
    catalogs = {
        "evidence": frozenset(scope["evidence_catalog"]),
        "generator": frozenset(scope["generator_catalog"]),
        "requirements": frozenset(scope["requirement_catalog"]),
        "tests": frozenset(scope["test_catalog"]),
    }
    review_pointer_catalog = (
        catalogs["evidence"] | catalogs["requirements"] | catalogs["tests"]
    )
    used_generators = frozenset(
        record["generator"]
        for record in classifications.values()
        if record["generated"] == "YES"
    )
    entry_by_path = {entry["path"]: entry for entry in overlay["entries"]}
    if overlay["removed_paths"]:
        raise PacketError("completed ledger requires the exact no-removals overlay")
    for row, original in zip(rows, original_rows, strict=True):
        classification = classifications.get(row["path"])
        if classification is None:
            raise PacketError("ledger path lacks its F classification")
        if row["path"] != original["path"]:
            raise PacketError("completed ledger reordered or substituted a frozen row")
        for field in IMMUTABLE_FIELDS:
            if row[field] != original[field]:
                raise PacketError("completed ledger changed a frozen immutable field")
        if row["schema_version"] != "1.0.0":
            raise PacketError("completed ledger row has the wrong schema version")
        if row["generated"] not in {"YES", "NO"}:
            raise PacketError("completed ledger has an unresolved generated value")
        if original["generated"] in {"YES", "NO"} and (
            row["generated"],
            row["generator"],
        ) != (original["generated"], original["generator"]):
            raise PacketError(
                "completed ledger changed a frozen generated classification"
            )
        if classification is not None and (row["generated"], row["generator"]) != (
            classification["generated"],
            classification["generator"],
        ):
            raise PacketError(
                "completed ledger generated decision contradicts its F classification"
            )
        if row["generated"] == "YES":
            if row["generator"] not in catalogs["generator"] or (
                row["generator"] not in classifications
                and row["generator"] not in ALLOWED_EXTERNAL_GENERATORS
            ):
                raise PacketError("completed ledger has an unknown generator pointer")
        elif row["generator"]:
            raise PacketError("non-generated ledger row names a generator")
        if row["path"] == LEDGER_PATH and (
            row["generated"] != "YES" or row["generator"] != LEDGER_GENERATOR_PATH
        ):
            raise PacketError("ledger self row lacks its exact frozen generator")
        for field in (
            "public_surface",
            "security_critical",
            "science_critical",
            "authority_critical",
        ):
            if row[field] not in {"YES", "NO"}:
                raise PacketError(
                    "completed ledger has an unresolved criticality value"
                )
        criticality = _criticality_from_row(row)
        if not _required_criticality(row["path"]).issubset(criticality):
            raise PacketError(
                "completed ledger criticality is below the mandatory path floor"
            )
        counterpart = entry_by_path.get(row["path"])
        if counterpart is not None and tuple(counterpart["criticality"]) != criticality:
            raise PacketError(
                "completed ledger and overlay criticality classifications disagree"
            )
        if classification is not None and criticality != _classification_criticality(
            classification
        ):
            raise PacketError(
                "completed ledger criticality contradicts its F classification"
            )
        if row["review_status"] != "REVIEWED":
            raise PacketError("completed ledger has a row not marked REVIEWED")
        if not row["reviewer"] or row["reviewer"] == "UNASSIGNED":
            raise PacketError("completed ledger has an unnamed assignment")
        if row["provenance_review_status"] not in {"CONFIRMED", "NOT_APPLICABLE"}:
            raise PacketError("completed ledger has unresolved provenance review")
        if row["path"] in entry_by_path:
            row_subject_id = entry_by_path[row["path"]]["subject_id"]
        else:
            row_subject_id = _subject_from_ledger(row).subject_id
        expected_provenance = f"CH-T002-E09#{row_subject_id}:PROVENANCE"
        if (
            row["provenance_review_status"]
            != classification["provenance_review_status"]
        ):
            raise PacketError(
                "live provenance decision contradicts its F classification"
            )
        elif row["provenance_review_status"] == "CONFIRMED":
            if row["provenance_evidence"] != expected_provenance:
                raise PacketError(
                    "confirmed provenance lacks its exact subject-qualified evidence"
                )
        else:
            raise PacketError("live provenance is not explicitly confirmed")
        if row["license_review_status"] not in {"APPROVED", "NOT_APPLICABLE"}:
            raise PacketError("completed ledger has unresolved license review")
        if (
            row["license_review_status"],
            row["license_expression"],
        ) != (
            classification["license_review_status"],
            classification["license_expression"],
        ):
            raise PacketError("live license decision contradicts its F classification")
        elif row["license_review_status"] == "APPROVED":
            if row["license_evidence"] != f"CH-T002-E09#{row_subject_id}:LICENSE":
                raise PacketError(
                    "approved license lacks its exact subject-qualified evidence"
                )
        elif row["license_evidence"]:
            raise PacketError("not-applicable live license has contradictory evidence")
        if row["disposition"] not in ALLOWED_REVIEW_DISPOSITIONS:
            raise PacketError("completed ledger has an adverse or empty disposition")
        if row["disposition"] != "ACCEPTED":
            raise PacketError("ledger subject is not explicitly accepted")
        if RFC3339_UTC.fullmatch(row["completed_at"]) is None:
            raise PacketError("completed ledger has a noncanonical completion time")
        try:
            datetime.strptime(row["completed_at"], "%Y-%m-%dT%H:%M:%SZ")
        except ValueError as exc:
            raise PacketError(
                "completed ledger has an impossible completion date"
            ) from exc
        if row["requirements"] != ROW_REQUIREMENT_ID:
            raise PacketError("completed ledger has the wrong frozen requirement")
        if row["tests"] != ROW_TEST_ID:
            raise PacketError("completed ledger has the wrong frozen test")
        critical = bool(criticality)
        _validate_pointer_cell(
            row["evidence"],
            catalogs["evidence"],
            label="evidence",
            required=critical,
            allow_evidence_fragments=True,
            allowed_fragment_roles=frozenset({"PRIMARY", "SECONDARY"}),
        )
        _validate_pointer_cell(
            row["assumptions"],
            review_pointer_catalog,
            label="assumptions",
            required=False,
            allow_evidence_fragments=True,
        )
        if row["defects"] != "NONE":
            raise PacketError("accepted ledger subject has a recorded defect")
    if catalogs["generator"] != used_generators:
        raise PacketError(
            "generator catalog is not the exact set used by completed ledger rows"
        )
    if any(
        generator not in classifications
        and generator not in ALLOWED_EXTERNAL_GENERATORS
        for generator in catalogs["generator"]
    ):
        raise PacketError("generator catalog contains an unresolvable generator")


def _validate_overlay_structure(value: dict[str, Any]) -> dict[str, Any]:
    overlay = _expect_keys(value, OVERLAY_TOP_KEYS, label="overlay")
    _expect_exact(overlay["schema_id"], SCHEMA_ID, label="overlay schema_id")
    _expect_exact(
        overlay["schema_version"], SCHEMA_VERSION, label="overlay schema_version"
    )
    _expect_exact(overlay["task_id"], TASK_ID, label="overlay task_id")
    _expect_exact(overlay["epoch"], EPOCH, label="overlay epoch")
    _expect_exact(
        overlay["release_target"], RELEASE_TARGET, label="overlay release_target"
    )
    _expect_exact(overlay["author"], EXPECTED_AUTHOR, label="overlay author")
    if overlay["persistent_identifier"] is not None:
        raise PacketError("overlay persistent_identifier must remain null")

    scope = _expect_keys(overlay["scope"], SCOPE_KEYS, label="overlay scope")
    _expect_exact(scope["claim_outcome"], CLAIM_OUTCOME, label="scope claim outcome")
    _expect_exact(
        scope["classification_audit_sha256"],
        CLASSIFICATION_AUDIT_SHA256,
        label="scope classification audit",
    )
    _expect_exact(
        scope["classification_policy"],
        CLASSIFICATION_POLICY,
        label="scope classification policy",
    )
    _expect_exact(scope["inclusion"], SCOPE_INCLUSION, label="scope inclusion")
    _expect_exact(scope["kind"], SCOPE_KIND, label="scope kind")
    _expect_exact(scope["path_order"], PATH_ORDER, label="scope path order")
    catalogs: dict[str, tuple[str, ...]] = {}
    for field in (
        "evidence_catalog",
        "generator_catalog",
        "requirement_catalog",
        "test_catalog",
    ):
        catalogs[field] = _expect_sorted_unique_strings(
            scope[field], label=f"scope {field}"
        )
        if not catalogs[field]:
            raise PacketError(f"scope {field} must not be empty")
    if any(
        EVIDENCE_ID.fullmatch(item) is None for item in catalogs["evidence_catalog"]
    ):
        raise PacketError("scope evidence catalog has an invalid task evidence ID")
    _expect_exact(
        catalogs["evidence_catalog"],
        EVIDENCE_CATALOG,
        label="scope evidence catalog",
    )
    if any(
        NORMATIVE_REQUIREMENT_ID.fullmatch(item) is None
        for item in catalogs["requirement_catalog"]
    ):
        raise PacketError("scope requirement catalog has an invalid normative ID")
    for field in ("generator_catalog", "test_catalog"):
        if any(MACHINE_POINTER.fullmatch(item) is None for item in catalogs[field]):
            raise PacketError(f"scope {field} contains a non-resolvable pointer")

    base = _expect_keys(
        overlay["base_partition"], BASE_PARTITION_KEYS, label="base partition"
    )
    _expect_exact(
        _expect_hex(base["commit"], HEX40, label="base commit"),
        CH_T001_BASE_COMMIT,
        label="base commit",
    )
    _expect_exact(
        _expect_hex(base["tree"], HEX40, label="base tree"),
        CH_T001_BASE_TREE,
        label="base tree",
    )
    _expect_exact(base["ledger_path"], LEDGER_PATH, label="base ledger path")
    _expect_exact(
        _expect_hex(base["ledger_blob_id"], HEX40, label="base ledger blob"),
        CH_T001_BASE_LEDGER_BLOB,
        label="base ledger blob",
    )
    _expect_exact(
        _expect_hex(base["ledger_sha256"], HEX64, label="base ledger SHA-256"),
        CH_T001_BASE_LEDGER_SHA256,
        label="base ledger SHA-256",
    )
    _expect_exact(
        _expect_int(
            base["ledger_rows"],
            label="base ledger rows",
            minimum=1,
            maximum=MAX_ROWS,
        ),
        CH_T001_BASE_LEDGER_ROWS,
        label="base ledger rows",
    )
    _expect_exact(base["ledger_self_path"], LEDGER_PATH, label="base ledger self path")

    delta = _expect_keys(overlay["delta"], DELTA_KEYS, label="overlay delta")
    _expect_hex(delta["freeze_commit"], HEX40, label="freeze commit")
    _expect_hex(delta["freeze_tree"], HEX40, label="freeze tree")
    _expect_hex(delta["name_status_sha256"], HEX64, label="delta name-status digest")
    if delta["freeze_commit"] == base["commit"]:
        raise PacketError("freeze commit must follow the base partition commit")

    policy = _expect_keys(
        overlay["review_policy"], REVIEW_POLICY_KEYS, label="review policy"
    )
    fixed_policy = {
        "algorithm": ASSIGNMENT_ALGORITHM,
        "binary_unit_bytes": BINARY_UNIT_BYTES,
        "coverage": COVERAGE_RULE,
        "critical_secondary_required": True,
        "primary_selection": PRIMARY_RULE,
        "removed_coverage": REMOVED_COVERAGE_RULE,
        "secondary_selection": SECONDARY_RULE,
        "sort_order": SORT_RULE,
        "text_units": TEXT_UNIT_RULE,
    }
    for key, expected in fixed_policy.items():
        _expect_exact(policy[key], expected, label=f"review policy {key}")
    lead_requirement = _expect_string(
        policy["lead_requirement_id"], label="lead requirement ID"
    )
    if REQUIREMENT_ID.fullmatch(lead_requirement) is None:
        raise PacketError("lead requirement ID has invalid grammar")
    registry = _expect_keys(
        policy["registry"], REGISTRY_BINDING_KEYS, label="reviewer registry binding"
    )
    _expect_exact(
        _expect_path(registry["path"], label="reviewer registry path"),
        FREEZE_REGISTRY_PATH,
        label="reviewer registry path",
    )
    _expect_hex(registry["git_blob_id"], HEX40, label="reviewer registry blob")
    _expect_hex(registry["sha256"], HEX64, label="reviewer registry SHA-256")
    lanes = policy["lanes"]
    if not isinstance(lanes, list) or len(lanes) != LANE_COUNT:
        raise PacketError("review policy must define exactly three lanes")
    requirements: set[str] = set()
    fingerprints: set[str] = set()
    for expected_lane, lane_value in enumerate(lanes, start=1):
        lane = _expect_keys(lane_value, LANE_POLICY_KEYS, label="lane policy")
        _expect_exact(lane["lane"], expected_lane, label="lane number")
        _expect_exact(lane["kind"], LANE_KINDS[expected_lane], label="lane kind")
        requirement = _expect_string(lane["requirement_id"], label="lane requirement")
        if REQUIREMENT_ID.fullmatch(requirement) is None:
            raise PacketError("lane requirement has invalid grammar")
        fingerprint = _expect_string(
            lane["reviewer_fingerprint"], label="lane reviewer fingerprint"
        )
        if FINGERPRINT.fullmatch(fingerprint) is None:
            raise PacketError("lane reviewer fingerprint has invalid grammar")
        requirements.add(requirement)
        fingerprints.add(fingerprint)
    if len(requirements) != LANE_COUNT or len(fingerprints) != LANE_COUNT:
        raise PacketError("lane reviewer requirements and keys must be distinct")
    if lead_requirement in requirements:
        raise PacketError("lead requirement cannot be a lane requirement")

    entries = overlay["entries"]
    if not isinstance(entries, list) or not 1 <= len(entries) <= MAX_ENTRIES:
        raise PacketError("overlay entries are not a nonempty bounded list")
    parsed_paths: list[str] = []
    parsed_subject_ids: list[str] = []
    for index, value_entry in enumerate(entries):
        entry = _expect_keys(value_entry, ENTRY_KEYS, label="overlay entry")
        path = _expect_path(entry["path"], label="overlay entry path")
        parsed_paths.append(path)
        mode = _expect_string(entry["git_mode"], label="entry Git mode")
        if mode not in {"100644", "100755"}:
            raise PacketError("entry is not a supported regular Git mode")
        _expect_hex(entry["git_object_id"], HEX40, label="entry blob ID")
        _expect_hex(entry["sha256"], HEX64, label="entry SHA-256")
        size = _expect_int(entry["bytes"], label="entry bytes", maximum=MAX_FILE_BYTES)
        kind = _expect_string(entry["content_kind"], label="entry content kind")
        if kind not in CONTENT_KINDS:
            raise PacketError("entry has unsupported content kind")
        if kind == "BINARY":
            if entry["lines"] is not None:
                raise PacketError("binary entry must use a null line count")
        else:
            _expect_int(entry["lines"], label="entry lines", maximum=2**31 - 1)
        language = _expect_string(entry["language"], label="entry language")
        if TOKEN.fullmatch(language) is None:
            raise PacketError("entry language is not a canonical token")
        if language != _language(path):
            raise PacketError("entry language contradicts its repository path")
        criticality_value = entry["criticality"]
        if not isinstance(criticality_value, list) or len(criticality_value) > len(
            CRITICALITY_ORDER
        ):
            raise PacketError("entry criticality is not a list")
        criticality = tuple(
            _expect_string(item, label="entry criticality item")
            for item in criticality_value
        )
        if tuple(criticality) != tuple(
            item for item in CRITICALITY_ORDER if item in criticality
        ):
            raise PacketError("entry criticality is not a canonical subset")
        if not _required_criticality(path).issubset(criticality):
            raise PacketError("entry criticality is below the mandatory path floor")
        status = _expect_string(entry["status"], label="entry status")
        if status not in ENTRY_STATUSES:
            raise PacketError("entry has an unknown delta status")
        _validate_classification_record(_entry_classification_record(entry))
        expected_id = subject_id(entry)
        _expect_exact(entry["subject_id"], expected_id, label="entry subject ID")
        parsed_subject_ids.append(expected_id)
        if size == 0 and kind == "BINARY":
            # Empty bytes are valid UTF-8 and cannot truthfully be binary.
            raise PacketError("empty entry is incorrectly classified as binary")
        if index >= MAX_ENTRIES:
            raise PacketError("overlay entry bound exceeded")
    if tuple(parsed_paths) != tuple(
        sorted(parsed_paths, key=lambda item: item.encode("utf-8"))
    ):
        raise PacketError("overlay entries are not raw-UTF-8 path sorted")
    if len(set(parsed_paths)) != len(parsed_paths) or len(
        set(parsed_subject_ids)
    ) != len(parsed_subject_ids):
        raise PacketError("overlay entries contain a duplicate path or subject")
    _expect_portable_unique(parsed_paths, label="overlay entry paths")

    _expect_exact(overlay["removed_paths"], [], label="overlay no-removals catalog")

    boundary = _expect_keys(
        overlay["implementation_boundary"],
        IMPLEMENTATION_BOUNDARY_KEYS,
        label="implementation boundary",
    )
    _expect_exact(
        boundary["content_identities_in_overlay"],
        False,
        label="implementation content identity exclusion",
    )
    _expect_exact(
        boundary["review_kind"],
        IMPLEMENTATION_REVIEW_KIND,
        label="implementation review kind",
    )
    paths = boundary["paths"]
    if not isinstance(paths, list) or len(paths) != len(IMPLEMENTATION_PLAN):
        raise PacketError("implementation boundary has the wrong path count")
    parsed_plan = []
    for item in paths:
        record = _expect_keys(
            item, IMPLEMENTATION_PATH_KEYS, label="implementation path"
        )
        parsed_plan.append(
            {
                "path": _expect_path(record["path"], label="implementation path value"),
                "status": _expect_string(
                    record["status"], label="implementation status"
                ),
            }
        )
    _expect_exact(tuple(parsed_plan), IMPLEMENTATION_PLAN, label="implementation plan")

    counts = _expect_keys(overlay["counts"], COUNT_KEYS, label="overlay counts")
    for key in COUNT_KEYS:
        _expect_int(counts[key], label=f"overlay count {key}", maximum=MAX_ENTRIES * 2)
    _expect_exact(counts["removed_paths"], 0, label="overlay removed-path count")
    digests = _expect_keys(overlay["digests"], DIGEST_KEYS, label="overlay digests")
    for key in DIGEST_KEYS:
        _expect_hex(digests[key], HEX64, label=f"overlay digest {key}")
    _expect_exact(
        digests["removed_path_set_sha256"],
        _domain_digest(SCHEMA["digest_domains"]["removed_path_set"], []),
        label="overlay empty removed-path digest",
    )
    return overlay


def _safe_environment() -> dict[str, str]:
    return {
        "GIT_CONFIG_COUNT": "0",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_LITERAL_PATHSPECS": "1",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "HOME": "/nonexistent",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }


def _run_git(
    repo: Path,
    arguments: Sequence[str],
    *,
    maximum: int = MAX_GIT_OUTPUT_BYTES,
) -> bytes:
    command = [GIT_EXECUTABLE, *GIT_GLOBAL_OPTIONS, "-C", str(repo), *arguments]
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_safe_environment(),
            close_fds=True,
        )
    except OSError as exc:
        raise PacketError("cannot start the bounded Git subprocess") from exc
    stdout = process.stdout
    stderr = process.stderr
    if stdout is None or stderr is None:
        process.kill()
        process.wait()
        raise PacketError("bounded Git subprocess did not expose output pipes")
    try:
        os.set_blocking(stdout.fileno(), False)
        os.set_blocking(stderr.fileno(), False)
    except OSError as exc:
        process.kill()
        process.wait()
        stdout.close()
        stderr.close()
        raise PacketError("cannot make Git output pipes nonblocking") from exc
    selector = selectors.DefaultSelector()
    selector.register(stdout, selectors.EVENT_READ, ("stdout", maximum))
    selector.register(stderr, selectors.EVENT_READ, ("stderr", MAX_GIT_STDERR_BYTES))
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    deadline = time.monotonic() + GIT_TIMEOUT_SECONDS
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                process.kill()
                process.wait()
                raise PacketError("Git subprocess exceeded its time bound")
            events = selector.select(min(remaining, 0.1))
            if not events and process.poll() is not None:
                events = [
                    (key, selectors.EVENT_READ) for key in selector.get_map().values()
                ]
            for key, _mask in events:
                label, bound = key.data
                try:
                    chunk = os.read(key.fd, 64 * 1024)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                buffers[label].extend(chunk)
                if len(buffers[label]) > bound:
                    process.kill()
                    process.wait()
                    raise PacketError(f"Git {label} exceeded its byte bound")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            process.kill()
            process.wait()
            raise PacketError("Git subprocess exceeded its time bound")
        return_code = process.wait(timeout=remaining)
    except BaseException:
        if process.poll() is None:
            process.kill()
            process.wait()
        raise
    finally:
        selector.close()
        stdout.close()
        stderr.close()
    if return_code != 0:
        raise PacketError("Git subprocess failed closed")
    return bytes(buffers["stdout"])


def _bind_repository(repo: Path) -> Path:
    lexical = Path(os.path.abspath(os.fspath(repo)))
    try:
        status = os.lstat(lexical)
    except OSError as exc:
        raise PacketError("cannot stat repository root") from exc
    if stat.S_ISLNK(status.st_mode) or not stat.S_ISDIR(status.st_mode):
        raise PacketError("repository root must be a real directory")
    raw = _run_git(
        lexical,
        ["rev-parse", "--path-format=absolute", "--show-toplevel"],
        maximum=MAX_PATH_BYTES,
    )
    try:
        top = raw.decode("utf-8", "strict").strip()
    except UnicodeDecodeError as exc:
        raise PacketError("Git returned a non-UTF-8 repository path") from exc
    canonical = Path(os.path.realpath(lexical))
    if not top or "\n" in top or Path(top) != canonical:
        raise PacketError("repository argument is not the exact Git top level")
    try:
        canonical_status = os.lstat(canonical)
    except OSError as exc:
        raise PacketError("cannot stat canonical repository root") from exc
    if (
        stat.S_ISLNK(canonical_status.st_mode)
        or not stat.S_ISDIR(canonical_status.st_mode)
        or (status.st_dev, status.st_ino)
        != (canonical_status.st_dev, canonical_status.st_ino)
    ):
        raise PacketError("repository argument does not bind the Git top-level inode")
    object_format = (
        _run_git(canonical, ["rev-parse", "--show-object-format"], maximum=32)
        .decode("ascii", "strict")
        .strip()
    )
    if object_format != "sha1":
        raise PacketError("review-packet schema requires the frozen SHA-1 Git format")
    return canonical


def _repo_relative_argument(
    repo: Path, argument: Path, *, expected: str, label: str
) -> str:
    lexical = Path(os.path.realpath(os.path.abspath(os.fspath(argument))))
    try:
        relative = lexical.relative_to(repo).as_posix()
    except ValueError as exc:
        raise PacketError(f"{label} is outside the repository") from exc
    if relative != expected:
        raise PacketError(f"{label} is not the frozen repository path")
    return relative


def _exact_commit(repo: Path, value: str, *, label: str) -> tuple[str, str]:
    _expect_hex(value, HEX40, label=label)
    commit = (
        _run_git(repo, ["rev-parse", "--verify", f"{value}^{{commit}}"], maximum=128)
        .decode("ascii", "strict")
        .strip()
    )
    if commit != value:
        raise PacketError(f"{label} does not resolve to itself")
    tree = (
        _run_git(repo, ["rev-parse", "--verify", f"{value}^{{tree}}"], maximum=128)
        .decode("ascii", "strict")
        .strip()
    )
    if HEX40.fullmatch(tree) is None:
        raise PacketError(f"{label} tree has invalid grammar")
    return commit, tree


def _commit_parents(repo: Path, commit: str) -> tuple[str, ...]:
    line = (
        _run_git(repo, ["rev-list", "--parents", "-n", "1", commit], maximum=1024)
        .decode("ascii", "strict")
        .strip()
    )
    fields = line.split(" ")
    if (
        not fields
        or fields[0] != commit
        or any(HEX40.fullmatch(field) is None for field in fields)
    ):
        raise PacketError("Git returned malformed commit-parent data")
    return tuple(fields[1:])


def _validate_linear_ancestry(repo: Path, base: str, target: str) -> None:
    raw = _run_git(
        repo,
        ["rev-list", "--first-parent", "--reverse", "--parents", f"{base}..{target}"],
        maximum=128 * 1024,
    )
    lines = raw.decode("ascii", "strict").splitlines()
    if not lines or len(lines) > 1024:
        raise PacketError("base-to-freeze first-parent history is empty or over bound")
    expected_parent = base
    for line in lines:
        fields = line.split(" ")
        if (
            len(fields) != 2
            or any(HEX40.fullmatch(field) is None for field in fields)
            or fields[1] != expected_parent
        ):
            raise PacketError("base-to-freeze history is not exact and merge-free")
        expected_parent = fields[0]
    if expected_parent != target:
        raise PacketError("base commit is not on the freeze first-parent chain")


def _blob_at(repo: Path, commit: str, path: str) -> tuple[str, str, bytes]:
    raw = _run_git(
        repo, ["ls-tree", "-z", commit, "--", path], maximum=MAX_PATH_BYTES + 256
    )
    if not raw.endswith(b"\0") or raw.count(b"\0") != 1:
        raise PacketError("Git tree path lookup is missing or ambiguous")
    metadata, raw_path = raw[:-1].split(b"\t", 1)
    fields = metadata.split(b" ")
    if len(fields) != 3 or fields[1] != b"blob":
        raise PacketError("Git tree path is not a blob")
    mode = fields[0].decode("ascii", "strict")
    oid = fields[2].decode("ascii", "strict")
    if mode not in {"100644", "100755"} or HEX40.fullmatch(oid) is None:
        raise PacketError("Git tree path is not a supported regular blob")
    if raw_path.decode("utf-8", "strict") != path:
        raise PacketError("Git tree path lookup returned a different path")
    data = _run_git(repo, ["cat-file", "blob", oid], maximum=MAX_FILE_BYTES)
    if len(data) > MAX_FILE_BYTES:
        raise PacketError("Git blob exceeds the file byte bound")
    expected_oid = hashlib.sha1(
        f"blob {len(data)}\0".encode("ascii") + data,
        usedforsecurity=False,
    ).hexdigest()
    if expected_oid != oid:
        raise PacketError("Git blob content does not match its object ID")
    return mode, oid, data


def _tree_entries(repo: Path, commit: str) -> dict[str, tuple[str, str]]:
    raw = _run_git(repo, ["ls-tree", "-rz", "--full-tree", commit])
    if not raw.endswith(b"\0"):
        raise PacketError("Git tree inventory is not NUL terminated")
    result: dict[str, tuple[str, str]] = {}
    for item in raw[:-1].split(b"\0"):
        try:
            metadata, raw_path = item.split(b"\t", 1)
            mode_raw, kind_raw, oid_raw = metadata.split(b" ")
            path = raw_path.decode("utf-8", "strict")
            mode = mode_raw.decode("ascii", "strict")
            kind = kind_raw.decode("ascii", "strict")
            oid = oid_raw.decode("ascii", "strict")
        except (ValueError, UnicodeDecodeError) as exc:
            raise PacketError("Git tree inventory has a malformed record") from exc
        _expect_path(path, label="Git tree path")
        if (
            kind != "blob"
            or mode not in {"100644", "100755"}
            or HEX40.fullmatch(oid) is None
        ):
            raise PacketError("freeze scope contains an unsupported non-regular entry")
        if path in result:
            raise PacketError("Git tree inventory contains a duplicate path")
        result[path] = (mode, oid)
        if len(result) > MAX_ENTRIES:
            raise PacketError("Git tree inventory exceeds the entry bound")
    paths = tuple(result)
    if paths != tuple(sorted(paths, key=lambda item: item.encode("utf-8"))):
        raise PacketError("Git tree inventory is not raw-UTF-8 path sorted")
    _expect_portable_unique(paths, label="Git tree paths")
    return result


def _diff_name_status(
    repo: Path, base: str, target: str
) -> tuple[bytes, dict[str, str]]:
    raw = _run_git(
        repo,
        [
            "diff",
            "--no-ext-diff",
            "--no-renames",
            "--name-status",
            "-z",
            base,
            target,
        ],
    )
    fields = raw.split(b"\0")
    if fields[-1] != b"":
        raise PacketError("Git name-status output is not NUL terminated")
    fields.pop()
    if len(fields) % 2:
        raise PacketError("Git name-status output is truncated")
    result: dict[str, str] = {}
    for index in range(0, len(fields), 2):
        try:
            status_text = fields[index].decode("ascii", "strict")
            path = fields[index + 1].decode("utf-8", "strict")
        except UnicodeDecodeError as exc:
            raise PacketError("Git name-status output is not canonical text") from exc
        if status_text not in {"A", "M", "D"}:
            raise PacketError("Git delta contains an unsupported status")
        _expect_path(path, label="Git delta path")
        if path in result:
            raise PacketError("Git delta contains a duplicate path")
        result[path] = status_text
    paths = tuple(result)
    if paths != tuple(sorted(paths, key=lambda item: item.encode("utf-8"))):
        raise PacketError("Git delta paths are not raw-UTF-8 byte sorted")
    _expect_portable_unique(paths, label="Git delta paths")
    return raw, result


def _criticality_entry(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise PacketError("review subject criticality is not a list")
    return tuple(value)


def _subject_from_record(
    record: Mapping[str, Any],
    *,
    status: str,
) -> Subject:
    size = int(record["bytes"])
    lines = record["lines"]
    kind = str(record["content_kind"])
    return Subject(
        path=str(record["path"]),
        git_mode=str(record["git_mode"]),
        git_object_id=str(record["git_object_id"]),
        sha256=str(record["sha256"]),
        size=size,
        lines=lines,
        content_kind=kind,
        language=str(record["language"]),
        criticality=_criticality_entry(record["criticality"]),
        status=status,
        subject_id=str(record["subject_id"]),
        units=_units(size=size, lines=lines, content_kind=kind),
    )


def _subject_from_ledger(row: Mapping[str, str]) -> Subject:
    kind = row["current_content_kind"]
    if kind not in CONTENT_KINDS:
        raise PacketError("ledger row has unsupported current content kind")
    size = _parse_decimal(
        row["current_bytes"], label="ledger current bytes", maximum=MAX_FILE_BYTES
    )
    raw_lines = _parse_decimal(
        row["current_lines"], label="ledger current lines", maximum=2**31 - 1
    )
    lines: int | None = None if kind == "BINARY" else raw_lines
    if kind == "BINARY" and raw_lines != 0:
        raise PacketError("binary ledger row has a nonzero line count")
    language = row["language"]
    if TOKEN.fullmatch(language) is None:
        raise PacketError("ledger language is not a canonical token")
    if language != _language(row["path"]):
        raise PacketError("ledger language contradicts its repository path")
    record: dict[str, Any] = {
        "bytes": size,
        "content_kind": kind,
        "git_mode": row["current_fs_mode"],
        "git_object_id": row["current_git_blob_id"],
        "lines": lines,
        "path": row["path"],
        "sha256": row["current_sha256"],
    }
    if record["git_mode"] not in {"100644", "100755"}:
        raise PacketError("ledger subject does not have a regular Git mode")
    _expect_hex(record["git_object_id"], HEX40, label="ledger current blob")
    _expect_hex(record["sha256"], HEX64, label="ledger current SHA-256")
    identifier = subject_id(record)
    criticality = _criticality_from_row(row)
    if not _required_criticality(row["path"]).issubset(criticality):
        raise PacketError("ledger criticality is below the mandatory path floor")
    return Subject(
        path=row["path"],
        git_mode=record["git_mode"],
        git_object_id=record["git_object_id"],
        sha256=record["sha256"],
        size=size,
        lines=lines,
        content_kind=kind,
        language=language,
        criticality=criticality,
        status="UNCHANGED_BASE",
        subject_id=identifier,
        units=_units(size=size, lines=lines, content_kind=kind),
    )


def _verify_subject_blob(repo: Path, freeze_commit: str, subject: Subject) -> None:
    mode, oid, data = _blob_at(repo, freeze_commit, subject.path)
    if mode != subject.git_mode or oid != subject.git_object_id:
        raise PacketError("review subject Git identity does not match its bound tree")
    if len(data) != subject.size or hashlib.sha256(data).hexdigest() != subject.sha256:
        raise PacketError(
            "review subject content identity does not match its bound blob"
        )
    kind, lines = _classify_content(data)
    if kind != subject.content_kind or lines != subject.lines:
        raise PacketError("review subject content classification is contradictory")
    if subject.language != _language(subject.path):
        raise PacketError("review subject language contradicts its repository path")
    if not _required_criticality(subject.path).issubset(subject.criticality):
        raise PacketError("review subject criticality is below its path floor")


def _build_subjects(
    repo: Path,
    rows: Sequence[dict[str, str]],
    overlay: Mapping[str, Any],
    freeze_inventory: Mapping[str, tuple[str, str]],
    delta_statuses: Mapping[str, str],
) -> tuple[Subject, ...]:
    entries = {entry["path"]: entry for entry in overlay["entries"]}
    if overlay["removed_paths"]:
        raise PacketError("overlay removal catalog must be exactly empty")
    self_path = overlay["base_partition"]["ledger_self_path"]
    ledger_paths = {row["path"] for row in rows}
    if self_path not in ledger_paths:
        raise PacketError("ledger self path is absent from the completed ledger")

    self_entries = [
        entry
        for entry in overlay["entries"]
        if entry["status"] == "LEDGER_SELF_EXTERNAL_BINDING"
    ]
    if len(self_entries) != 1 or self_entries[0]["path"] != self_path:
        raise PacketError("overlay must have one exact ledger-self binding")

    expected_delta_entries: dict[str, str] = {}
    for path, status in delta_statuses.items():
        if status == "D":
            raise PacketError("base-to-freeze diff contains a forbidden removal")
        expected_delta_entries[path] = (
            "ADDED_FREEZE_DELTA" if status == "A" else "MODIFIED_FREEZE_DELTA"
        )
    actual_delta_entries = {
        entry["path"]: entry["status"]
        for entry in overlay["entries"]
        if entry["status"] != "LEDGER_SELF_EXTERNAL_BINDING"
    }
    if actual_delta_entries != expected_delta_entries:
        raise PacketError(
            "overlay entries do not exactly reconcile the base-to-freeze delta"
        )
    subjects: list[Subject] = []
    for row in rows:
        path = row["path"]
        if path == self_path or path in entries:
            continue
        subject = _subject_from_ledger(row)
        if freeze_inventory.get(path) != (subject.git_mode, subject.git_object_id):
            raise PacketError("unchanged ledger subject does not match the freeze tree")
        subjects.append(subject)
    for entry in overlay["entries"]:
        subjects.append(_subject_from_record(entry, status=entry["status"]))

    subjects.sort(
        key=lambda subject: (
            subject.path.encode("utf-8"),
            subject.subject_id.encode("ascii"),
        )
    )
    if len(subjects) != len({subject.path for subject in subjects}):
        raise PacketError("reconciled review subjects contain a duplicate path")
    if set(freeze_inventory) != {subject.path for subject in subjects}:
        raise PacketError("review subjects do not exactly cover the freeze tree")
    _expect_portable_unique(
        (subject.path for subject in subjects), label="reconciled review subject paths"
    )
    total_bytes = 0
    for subject in subjects:
        total_bytes += subject.size
        if total_bytes > MAX_TOTAL_FILE_BYTES:
            raise PacketError("review subject bytes exceed the aggregate bound")
        _verify_subject_blob(repo, overlay["delta"]["freeze_commit"], subject)
    return tuple(subjects)


def _public_key_fingerprint(public_key: str) -> str:
    fields = public_key.split(" ")
    if len(fields) != 2 or fields[0] != "ssh-ed25519":
        raise PacketError("reviewer public key is not a bare Ed25519 key")
    try:
        decoded = base64.b64decode(fields[1], validate=True)
    except (binascii.Error, ValueError) as exc:
        raise PacketError("reviewer public key has invalid base64") from exc
    if len(decoded) != 4 + len(b"ssh-ed25519") + 4 + 32:
        raise PacketError("reviewer public key has the wrong Ed25519 wire length")
    algorithm_size = int.from_bytes(decoded[:4], "big")
    algorithm_end = 4 + algorithm_size
    if (
        algorithm_size != len(b"ssh-ed25519")
        or decoded[4:algorithm_end] != b"ssh-ed25519"
    ):
        raise PacketError("reviewer public key has the wrong wire algorithm")
    key_size = int.from_bytes(decoded[algorithm_end : algorithm_end + 4], "big")
    key_start = algorithm_end + 4
    if key_size != 32 or key_start + key_size != len(decoded):
        raise PacketError("reviewer public key has a malformed Ed25519 payload")
    digest = (
        base64.b64encode(hashlib.sha256(decoded).digest()).decode("ascii").rstrip("=")
    )
    return f"SHA256:{digest}"


def _validate_freeze_catalogs(
    freeze: Mapping[str, Any], overlay: Mapping[str, Any]
) -> None:
    """Bind every overlay catalog to the signed central F freeze contract."""

    freeze = _expect_key_order(freeze, CENTRAL_FREEZE_KEY_ORDER, label="central freeze")
    _expect_exact(freeze.get("task_id"), TASK_ID, label="freeze task ID")
    _expect_exact(freeze.get("epoch"), EPOCH, label="freeze epoch")
    _expect_exact(
        freeze.get("release_target"), RELEASE_TARGET, label="freeze release target"
    )
    _expect_exact(freeze.get("author"), EXPECTED_AUTHOR, label="freeze author")
    if freeze.get("persistent_identifier") is not None:
        raise PacketError("freeze persistent_identifier must remain null")
    controls = freeze.get("normative_controls")
    if not isinstance(controls, list) or len(controls) != len(
        NORMATIVE_REQUIREMENT_CATALOG
    ):
        raise PacketError("freeze must contain exactly N01 through N20")
    requirement_ids: list[str] = []
    test_ids: set[str] = set()
    classification_control: Mapping[str, Any] | None = None
    for expected_requirement, control in zip(
        NORMATIVE_REQUIREMENT_CATALOG, controls, strict=True
    ):
        if not isinstance(control, dict) or set(control) != NORMATIVE_CONTROL_KEYS:
            raise PacketError("freeze normative control has the wrong exact key set")
        requirement = _expect_string(control["id"], label="normative control ID")
        if requirement != expected_requirement:
            raise PacketError("freeze normative controls are not exact ordered N01-N20")
        requirement_ids.append(requirement)
        if requirement == CLASSIFICATION_CONTROL_ID:
            classification_control = control
        for field in ("accepted_test_id", "rejected_test_id"):
            test_id = _expect_string(control[field], label=f"normative {field}")
            if MACHINE_POINTER.fullmatch(test_id) is None:
                raise PacketError("freeze normative control has an invalid test ID")
            if test_id in test_ids:
                raise PacketError("freeze normative controls reuse a test ID")
            test_ids.add(test_id)
    expected_requirements = tuple(
        sorted(requirement_ids, key=lambda item: item.encode("utf-8"))
    )
    _expect_exact(
        expected_requirements,
        NORMATIVE_REQUIREMENT_CATALOG,
        label="freeze normative requirement catalog",
    )
    if classification_control is None:
        raise PacketError("freeze lacks the exact classification normative control")
    for field in ("statement", "accepted_test_id", "rejected_test_id"):
        if field not in classification_control:
            raise PacketError("classification normative control lacks a frozen field")
    _expect_exact(
        classification_control["statement"],
        CLASSIFICATION_CONTROL_STATEMENT,
        label="classification normative control statement",
    )
    _expect_exact(
        classification_control["accepted_test_id"],
        CLASSIFICATION_CONTROL_ACCEPTED_TEST_ID,
        label="classification normative accepted test",
    )
    _expect_exact(
        classification_control["rejected_test_id"],
        CLASSIFICATION_CONTROL_REJECTED_TEST_ID,
        label="classification normative rejected test",
    )
    row_control = controls[0]
    _expect_exact(
        row_control["id"],
        ROW_REQUIREMENT_ID,
        label="row requirement binding",
    )
    _expect_exact(
        row_control["accepted_test_id"],
        ROW_TEST_ID,
        label="row test binding",
    )
    expected_tests = tuple(sorted(test_ids, key=lambda item: item.encode("utf-8")))
    evidence_requirements = freeze.get("qualification_evidence_requirements")
    if not isinstance(evidence_requirements, list) or len(evidence_requirements) != len(
        EVIDENCE_CATALOG
    ):
        raise PacketError("freeze must contain exactly E01 through E13")
    evidence_ids: list[str] = []
    for evidence in evidence_requirements:
        if not isinstance(evidence, dict) or "id" not in evidence:
            raise PacketError("freeze qualification evidence row is malformed")
        evidence_ids.append(
            _expect_string(evidence["id"], label="qualification evidence ID")
        )
    _expect_exact(
        tuple(evidence_ids),
        EVIDENCE_CATALOG,
        label="freeze qualification evidence catalog",
    )
    scope = overlay["scope"]
    _expect_exact(
        tuple(scope["evidence_catalog"]),
        EVIDENCE_CATALOG,
        label="evidence catalog derived from freeze",
    )
    _expect_exact(
        tuple(scope["requirement_catalog"]),
        expected_requirements,
        label="requirement catalog derived from freeze",
    )
    _expect_exact(
        tuple(scope["test_catalog"]),
        expected_tests,
        label="test catalog derived from freeze",
    )


def _reviewers_from_registry(
    registry: Mapping[str, Any], overlay: Mapping[str, Any]
) -> tuple[Reviewer, ...]:
    _expect_exact(registry.get("task_id"), TASK_ID, label="registry task ID")
    _expect_exact(registry.get("epoch"), EPOCH, label="registry epoch")
    values = registry.get("reviewer_registry")
    if not isinstance(values, list) or len(values) != 4:
        raise PacketError("reviewer registry must freeze exactly four reviewers")
    by_requirement: dict[str, Mapping[str, Any]] = {}
    fingerprints: set[str] = set()
    principals: set[str] = set()
    for value in values:
        if not isinstance(value, dict):
            raise PacketError("reviewer registry entry is not an object")
        required_keys = {
            "requirement_id",
            "kind",
            "path",
            "reviewer",
            "public_key",
            "key_fingerprint",
            "trust_basis",
        }
        if set(value) != required_keys:
            raise PacketError("reviewer registry entry has the wrong key set")
        requirement = _expect_string(
            value["requirement_id"], label="registry requirement"
        )
        if (
            requirement in by_requirement
            or REQUIREMENT_ID.fullmatch(requirement) is None
        ):
            raise PacketError(
                "reviewer registry has a duplicate or invalid requirement"
            )
        _expect_path(value["path"], label="registry review path")
        _expect_string(value["kind"], label="registry review kind")
        reviewer = value["reviewer"]
        if not isinstance(reviewer, dict) or set(reviewer) != {
            "name",
            "principal",
            "classification",
            "organization",
        }:
            raise PacketError("registry reviewer identity has the wrong key set")
        for field in reviewer:
            _expect_string(reviewer[field], label=f"registry reviewer {field}")
        if PRINCIPAL.fullmatch(reviewer["principal"]) is None:
            raise PacketError("registry reviewer principal is not machine-resolvable")
        if (
            reviewer["name"] == EXPECTED_AUTHOR["name"]
            or reviewer["principal"] == EXPECTED_AUTHOR["email"]
        ):
            raise PacketError("registry reviewer is not independent from the author")
        public_key = _expect_string(
            value["public_key"], label="registry public key", formula_safe=False
        )
        fingerprint = _expect_string(
            value["key_fingerprint"], label="registry fingerprint"
        )
        if (
            FINGERPRINT.fullmatch(fingerprint) is None
            or _public_key_fingerprint(public_key) != fingerprint
        ):
            raise PacketError("registry fingerprint does not match the public key")
        _expect_exact(
            value["trust_basis"],
            "SOURCE_SIGNER_ASSERTED_KEY_FROZEN_IN_SIGNED_F",
            label="registry trust basis",
        )
        principal = reviewer["principal"]
        if fingerprint in fingerprints or principal in principals:
            raise PacketError("reviewer registry reuses a key or principal")
        fingerprints.add(fingerprint)
        principals.add(principal)
        by_requirement[requirement] = value

    reviewers: list[Reviewer] = []
    for policy in overlay["review_policy"]["lanes"]:
        requirement = policy["requirement_id"]
        if requirement not in by_requirement:
            raise PacketError("lane requirement is absent from the reviewer registry")
        entry = by_requirement[requirement]
        if not _strict_equal(entry["kind"], policy["kind"]) or not _strict_equal(
            entry["key_fingerprint"], policy["reviewer_fingerprint"]
        ):
            raise PacketError("lane policy contradicts the reviewer registry")
        identity = entry["reviewer"]
        if identity["classification"] != "INDEPENDENT_AUTOMATED":
            raise PacketError(
                "lane reviewer classification is not automated independent review"
            )
        reviewers.append(
            Reviewer(
                lane=policy["lane"],
                requirement_id=requirement,
                kind=entry["kind"],
                name=identity["name"],
                principal=identity["principal"],
                classification=identity["classification"],
                organization=identity["organization"],
                key_fingerprint=entry["key_fingerprint"],
            )
        )
    lead_requirement = overlay["review_policy"]["lead_requirement_id"]
    lead = by_requirement.get(lead_requirement)
    if (
        lead is None
        or not _strict_equal(lead["kind"], LEAD_KIND)
        or not _strict_equal(
            lead["reviewer"].get("classification"), "AUTOMATED_LEAD_SUPPORT"
        )
        or set(by_requirement)
        != {reviewer.requirement_id for reviewer in reviewers} | {lead_requirement}
    ):
        raise PacketError("lead-support registry entry is absent or contradictory")
    return tuple(reviewers)


def assign_subjects(
    subjects: Sequence[Subject], reviewers: Sequence[Reviewer]
) -> tuple[Lane, ...]:
    if len(reviewers) != LANE_COUNT or tuple(
        reviewer.lane for reviewer in reviewers
    ) != (1, 2, 3):
        raise PacketError("assignment requires the exact three ordered lane reviewers")
    lanes = [
        Lane(number=reviewer.lane, reviewer=reviewer, primary=[], secondary=[])
        for reviewer in reviewers
    ]
    ordered = sorted(
        subjects,
        key=lambda subject: (
            -subject.units,
            subject.language.encode("utf-8"),
            subject.subject_id.encode("utf-8"),
        ),
    )
    for subject in ordered:
        primary = min(
            lanes, key=lambda lane: (lane.total_units, lane.item_count, lane.number)
        )
        primary.primary.append(subject)
        primary.total_units += subject.units
        primary.item_count += 1
        if subject.criticality:
            secondary = min(
                (lane for lane in lanes if lane.number != primary.number),
                key=lambda lane: (lane.total_units, lane.item_count, lane.number),
            )
            secondary.secondary.append(subject)
            secondary.total_units += subject.units
            secondary.item_count += 1
    for lane in lanes:
        lane.primary.sort(key=lambda subject: subject.subject_id.encode("utf-8"))
        lane.secondary.sort(key=lambda subject: subject.subject_id.encode("utf-8"))
    primary_ids = [subject.subject_id for lane in lanes for subject in lane.primary]
    secondary_ids = [subject.subject_id for lane in lanes for subject in lane.secondary]
    critical_ids = {subject.subject_id for subject in subjects if subject.criticality}
    if len(primary_ids) != len(subjects) or set(primary_ids) != {
        subject.subject_id for subject in subjects
    }:
        raise PacketError("primary assignment is not a complete disjoint partition")
    if (
        len(secondary_ids) != len(set(secondary_ids))
        or set(secondary_ids) != critical_ids
    ):
        raise PacketError("critical secondary assignment is not exact")
    for subject_id_value in critical_ids:
        primary_lane = next(
            lane.number
            for lane in lanes
            if any(item.subject_id == subject_id_value for item in lane.primary)
        )
        secondary_lane = next(
            lane.number
            for lane in lanes
            if any(item.subject_id == subject_id_value for item in lane.secondary)
        )
        if primary_lane == secondary_lane:
            raise PacketError(
                "critical subject has the same primary and secondary lane"
            )
    return tuple(lanes)


def _verify_overlay_digests_and_counts(
    overlay: Mapping[str, Any], subjects: Sequence[Subject]
) -> None:
    entries = overlay["entries"]
    _expect_exact(overlay["removed_paths"], [], label="overlay no-removals catalog")
    counts = overlay["counts"]
    statuses = Counter(entry["status"] for entry in entries)
    expected_counts = {
        "added_entries": statuses["ADDED_FREEZE_DELTA"],
        "base_rows": overlay["base_partition"]["ledger_rows"],
        "critical_subjects": sum(bool(subject.criticality) for subject in subjects),
        "modified_entries": statuses["MODIFIED_FREEZE_DELTA"],
        "removed_paths": 0,
        "review_subjects": len(subjects),
        "self_entries": statuses["LEDGER_SELF_EXTERNAL_BINDING"],
        "supplemental_subjects": len(entries),
        "unchanged_subjects": sum(
            subject.status == "UNCHANGED_BASE" for subject in subjects
        ),
    }
    if counts != expected_counts:
        raise PacketError("overlay counts do not match the reconciled subject set")
    expected_digests = {
        "classification_set_sha256": overlay["digests"]["classification_set_sha256"],
        "entry_set_sha256": _domain_digest(
            SCHEMA["digest_domains"]["entry_set"], entries
        ),
        "removed_path_set_sha256": _domain_digest(
            SCHEMA["digest_domains"]["removed_path_set"], []
        ),
        "subject_set_sha256": _subject_set_digest(
            subjects,
            freeze_commit=overlay["delta"]["freeze_commit"],
            freeze_tree=overlay["delta"]["freeze_tree"],
        ),
    }
    if overlay["digests"] != expected_digests:
        raise PacketError("overlay digests do not match the reconciled content")


def _validate_ledger_reviewer_assignments(
    rows: Sequence[dict[str, str]], lanes: Sequence[Lane], overlay: Mapping[str, Any]
) -> None:
    _expect_exact(overlay["removed_paths"], [], label="overlay no-removals catalog")
    principals = {lane.reviewer.principal for lane in lanes}
    primary_assignment = {
        subject.path: (lane.number, lane.reviewer.principal, subject)
        for lane in lanes
        for subject in lane.primary
    }
    secondary_lane = {
        subject.subject_id: lane.number for lane in lanes for subject in lane.secondary
    }
    for row in rows:
        if row["reviewer"] not in principals:
            raise PacketError("ledger reviewer is absent from the frozen lane registry")
        path = row["path"]
        assignment = primary_assignment.get(path)
        if assignment is None or assignment[1] != row["reviewer"]:
            raise PacketError(
                "ledger reviewer does not match deterministic primary assignment"
            )
        primary_lane, _primary_principal, subject = assignment
        evidence = set(_split_catalog_cell(row["evidence"], label="evidence"))
        required = {
            f"CH-T002-E09#{subject.subject_id}:PRIMARY",
            f"CH-T002-E{9 + primary_lane:02d}#{subject.subject_id}:PRIMARY",
        }
        second: int | None = None
        if subject.criticality:
            second = secondary_lane.get(subject.subject_id)
            if second is None or second == primary_lane:
                raise PacketError(
                    "critical ledger subject lacks a distinct secondary assignment"
                )
            required.update(
                {
                    f"CH-T002-E09#{subject.subject_id}:SECONDARY",
                    f"CH-T002-E{9 + second:02d}#{subject.subject_id}:SECONDARY",
                }
            )
        if evidence != required:
            raise PacketError(
                "ledger evidence is not the exact primary/secondary subject binding"
            )


def _validate_implementation_statuses(statuses: Mapping[str, str]) -> None:
    expected = {item["path"]: item["status"] for item in IMPLEMENTATION_PLAN}
    if not _strict_equal(statuses, expected):
        raise PacketError(
            "implementation commit does not have the exact four-path diff"
        )


def _prepare_inputs(
    *,
    repo_argument: Path,
    implementation_commit_argument: str,
    ledger_argument: Path,
    overlay_argument: Path,
    registry_argument: Path,
) -> PreparedInputs:
    repo = _bind_repository(repo_argument)
    _repo_relative_argument(repo, ledger_argument, expected=LEDGER_PATH, label="ledger")
    _repo_relative_argument(
        repo, overlay_argument, expected=OVERLAY_PATH, label="overlay"
    )
    implementation_commit, implementation_tree = _exact_commit(
        repo, implementation_commit_argument, label="implementation commit"
    )
    parents = _commit_parents(repo, implementation_commit)
    if len(parents) != 1:
        raise PacketError("implementation commit must have exactly one parent")

    ledger_mode, ledger_oid, ledger_data = _blob_at(
        repo, implementation_commit, LEDGER_PATH
    )
    overlay_mode, overlay_oid, overlay_data = _blob_at(
        repo, implementation_commit, OVERLAY_PATH
    )
    if ledger_mode != "100644" or overlay_mode != "100644":
        raise PacketError("ledger and overlay must be non-executable regular blobs")
    overlay = _validate_overlay_structure(
        _parse_canonical_json(overlay_data, label="overlay")
    )
    registry_path = overlay["review_policy"]["registry"]["path"]
    _repo_relative_argument(
        repo, registry_argument, expected=registry_path, label="reviewer registry"
    )
    registry_mode, registry_oid, registry_data = _blob_at(
        repo, implementation_commit, registry_path
    )
    if registry_mode != "100644":
        raise PacketError("reviewer registry must be a non-executable regular blob")
    registry = _parse_central_freeze_json(registry_data)

    base = overlay["base_partition"]
    base_commit, base_tree = _exact_commit(repo, base["commit"], label="base commit")
    freeze_commit, freeze_tree = _exact_commit(
        repo, overlay["delta"]["freeze_commit"], label="freeze commit"
    )
    _validate_linear_ancestry(repo, base_commit, freeze_commit)
    if base_tree != base["tree"] or freeze_tree != overlay["delta"]["freeze_tree"]:
        raise PacketError("overlay commit/tree binding is contradictory")
    if parents != (freeze_commit,):
        raise PacketError("implementation parent is not the exact freeze commit")
    freeze_inventory = _tree_entries(repo, freeze_commit)

    base_mode, base_ledger_oid, base_ledger_data = _blob_at(
        repo, base_commit, LEDGER_PATH
    )
    if base_mode != "100644" or base_ledger_oid != base["ledger_blob_id"]:
        raise PacketError("base ledger Git binding is contradictory")
    if hashlib.sha256(base_ledger_data).hexdigest() != base["ledger_sha256"]:
        raise PacketError("base ledger SHA-256 binding is contradictory")
    original_rows = _parse_ledger(base_ledger_data, label="base ledger")
    ledger_rows = _parse_ledger(ledger_data, label="completed ledger")
    if len(original_rows) != base["ledger_rows"]:
        raise PacketError("base ledger row count is contradictory")
    _validate_freeze_catalogs(registry, overlay)
    classifications = _validate_classification_contract(
        overlay,
        freeze_inventory,
        [row["path"] for row in original_rows],
    )
    _validate_completed_ledger(ledger_rows, original_rows, overlay, classifications)

    registry_binding = overlay["review_policy"]["registry"]
    if (
        registry_oid != registry_binding["git_blob_id"]
        or hashlib.sha256(registry_data).hexdigest() != registry_binding["sha256"]
    ):
        raise PacketError("reviewer registry binding is contradictory")
    reviewers = _reviewers_from_registry(registry, overlay)

    raw_delta, delta_statuses = _diff_name_status(repo, base_commit, freeze_commit)
    if hashlib.sha256(raw_delta).hexdigest() != overlay["delta"]["name_status_sha256"]:
        raise PacketError("base-to-freeze name-status digest is contradictory")
    _raw_implementation, implementation_statuses = _diff_name_status(
        repo, freeze_commit, implementation_commit
    )
    _validate_implementation_statuses(implementation_statuses)

    subjects = _build_subjects(
        repo, ledger_rows, overlay, freeze_inventory, delta_statuses
    )
    _verify_overlay_digests_and_counts(overlay, subjects)
    lanes = assign_subjects(subjects, reviewers)
    _validate_ledger_reviewer_assignments(ledger_rows, lanes, overlay)

    return PreparedInputs(
        overlay=overlay,
        ledger_rows=tuple(ledger_rows),
        subjects=subjects,
        reviewers=reviewers,
        lanes=lanes,
        snapshot=GitSnapshot(
            freeze_commit=freeze_commit,
            freeze_tree=freeze_tree,
            implementation_commit=implementation_commit,
            implementation_tree=implementation_tree,
            ledger_blob_id=ledger_oid,
            overlay_blob_id=overlay_oid,
            registry_blob_id=registry_oid,
        ),
        ledger_sha256=hashlib.sha256(ledger_data).hexdigest(),
        overlay_sha256=hashlib.sha256(overlay_data).hexdigest(),
        registry_sha256=hashlib.sha256(registry_data).hexdigest(),
        freeze_regular_blobs=len(freeze_inventory),
    )


def _snapshot_record(prepared: PreparedInputs) -> dict[str, Any]:
    registry_path = prepared.overlay["review_policy"]["registry"]["path"]
    return {
        "freeze_commit": prepared.snapshot.freeze_commit,
        "freeze_tree": prepared.snapshot.freeze_tree,
        "implementation_commit": prepared.snapshot.implementation_commit,
        "implementation_tree": prepared.snapshot.implementation_tree,
        "ledger": {
            "git_blob_id": prepared.snapshot.ledger_blob_id,
            "path": LEDGER_PATH,
            "sha256": prepared.ledger_sha256,
        },
        "overlay": {
            "git_blob_id": prepared.snapshot.overlay_blob_id,
            "path": OVERLAY_PATH,
            "sha256": prepared.overlay_sha256,
        },
        "reviewer_registry": {
            "git_blob_id": prepared.snapshot.registry_blob_id,
            "path": registry_path,
            "sha256": prepared.registry_sha256,
        },
    }


def _language_counts(lane: Lane) -> list[dict[str, Any]]:
    primary = Counter(subject.language for subject in lane.primary)
    secondary = Counter(subject.language for subject in lane.secondary)
    languages = sorted(
        set(primary) | set(secondary), key=lambda item: item.encode("utf-8")
    )
    return [
        {
            "language": language,
            "primary": primary[language],
            "secondary": secondary[language],
            "total": primary[language] + secondary[language],
        }
        for language in languages
    ]


def _packet_value(prepared: PreparedInputs, lane: Lane) -> dict[str, Any]:
    primary_records = [
        subject.packet_record(
            freeze_commit=prepared.snapshot.freeze_commit,
            freeze_tree=prepared.snapshot.freeze_tree,
        )
        for subject in lane.primary
    ]
    secondary_records = [
        subject.packet_record(
            freeze_commit=prepared.snapshot.freeze_commit,
            freeze_tree=prepared.snapshot.freeze_tree,
        )
        for subject in lane.secondary
    ]
    lane_subject_digest = _domain_digest(
        SCHEMA["digest_domains"]["lane_subject_set"],
        {
            "primary": [record["subject_id"] for record in primary_records],
            "secondary": [record["subject_id"] for record in secondary_records],
        },
    )
    return {
        "assignment": {
            "algorithm": ASSIGNMENT_ALGORITHM,
            "binary_unit_bytes": BINARY_UNIT_BYTES,
            "language_counts": _language_counts(lane),
            "primary_entries": primary_records,
            "primary_subjects": len(primary_records),
            "primary_units": lane.primary_units,
            "secondary_entries": secondary_records,
            "secondary_subjects": len(secondary_records),
            "secondary_units": lane.secondary_units,
            "subject_set_sha256": lane_subject_digest,
            "total_subjects": len(primary_records) + len(secondary_records),
            "total_units": lane.total_units,
        },
        "coverage": {
            "invalid_secondary_subjects": 0,
            "primary": COVERAGE_RULE,
            "removed": REMOVED_COVERAGE_RULE,
            "secondary": COVERAGE_RULE,
            "uncovered_primary_subjects": 0,
        },
        "epoch": EPOCH,
        "lane": lane.number,
        "release_target": RELEASE_TARGET,
        "result": "PASS",
        "reviewer": lane.reviewer.packet_record(),
        "schema_id": PACKET_SCHEMA_ID,
        "schema_version": SCHEMA_VERSION,
        "snapshot": _snapshot_record(prepared),
        "task_id": TASK_ID,
    }


def build_outputs(prepared: PreparedInputs) -> dict[str, bytes]:
    outputs: dict[str, bytes] = {}
    packet_records: list[dict[str, Any]] = []
    for lane in prepared.lanes:
        filename = f"review-lane-{lane.number:02d}.json"
        data = _canonical_json(_packet_value(prepared, lane))
        if len(data) >= MAX_PACKET_BYTES:
            raise PacketError("rendered lane packet exceeds its byte bound")
        outputs[filename] = data
        packet_records.append(
            {
                "bytes": len(data),
                "filename": filename,
                "lane": lane.number,
                "primary_subjects": len(lane.primary),
                "secondary_subjects": len(lane.secondary),
                "sha256": hashlib.sha256(data).hexdigest(),
                "total_units": lane.total_units,
            }
        )
    snapshot = _snapshot_record(prepared)
    current_subjects = len(prepared.subjects)
    removed_tombstones = 0
    if (
        current_subjects != prepared.freeze_regular_blobs
        or prepared.overlay["removed_paths"]
    ):
        raise PacketError("manifest reconciliation counters are contradictory")
    manifest = {
        "algorithm": ASSIGNMENT_ALGORITHM,
        "critical_subjects": sum(
            bool(subject.criticality) for subject in prepared.subjects
        ),
        "epoch": EPOCH,
        "lane_packets": packet_records,
        "overlay_reconciliation": {
            "base_partition": dict(prepared.overlay["base_partition"]),
            "content_identity_mismatches": 0,
            "counts": dict(prepared.overlay["counts"]),
            "current_freeze_regular_blobs": prepared.freeze_regular_blobs,
            "current_subjects": current_subjects,
            "delta": dict(prepared.overlay["delta"]),
            "digests": dict(prepared.overlay["digests"]),
            "duplicate_current_paths": 0,
            "implementation_boundary": dict(
                prepared.overlay["implementation_boundary"]
            ),
            "invalid_removed_tombstones": 0,
            "missing_current_paths": 0,
            "overlay_input": dict(snapshot["overlay"]),
            "removed_tombstones": removed_tombstones,
            "result": "PASS",
            "scope_inclusion": SCOPE_INCLUSION,
            "uncovered_freeze_tree_subjects": 0,
        },
        "release_target": RELEASE_TARGET,
        "result": "PASS",
        "review_subjects": len(prepared.subjects),
        "schema_id": MANIFEST_SCHEMA_ID,
        "schema_version": SCHEMA_VERSION,
        "snapshot": snapshot,
        "subject_set_sha256": _subject_set_digest(
            prepared.subjects,
            freeze_commit=prepared.snapshot.freeze_commit,
            freeze_tree=prepared.snapshot.freeze_tree,
        ),
        "task_id": TASK_ID,
    }
    outputs[SCHEMA["manifest_filename"]] = _canonical_json(manifest)
    if any(len(value) >= MAX_PACKET_BYTES for value in outputs.values()):
        raise PacketError("rendered packet output reaches the retained-file byte cap")
    if sum(len(value) for value in outputs.values()) > MAX_PACKET_DIRECTORY_BYTES:
        raise PacketError("rendered packet directory exceeds its aggregate byte bound")
    return outputs


def _atomic_rename_noreplace(
    source_dir_fd: int,
    source: str,
    destination_dir_fd: int,
    destination: str,
) -> None:
    try:
        library = ctypes.CDLL(None, use_errno=True)
    except OSError as exc:
        raise AtomicRenameUnavailable(
            "native atomic no-replace rename is unavailable"
        ) from exc
    if sys.platform == "darwin":
        try:
            rename = library.renameatx_np
        except AttributeError as exc:
            raise AtomicRenameUnavailable(
                "native atomic no-replace rename is unavailable"
            ) from exc
        rename.argtypes = (
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        )
        flags = _DARWIN_RENAME_EXCL
    elif sys.platform.startswith("linux"):
        try:
            rename = library.renameat2
        except AttributeError as exc:
            raise AtomicRenameUnavailable(
                "native atomic no-replace rename is unavailable"
            ) from exc
        rename.argtypes = (
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        )
        flags = _LINUX_RENAME_NOREPLACE
    else:
        raise AtomicRenameUnavailable("native atomic no-replace rename is unsupported")
    rename.restype = ctypes.c_int
    ctypes.set_errno(0)
    result = rename(
        source_dir_fd,
        os.fsencode(source),
        destination_dir_fd,
        os.fsencode(destination),
        flags,
    )
    if result != 0:
        error = ctypes.get_errno()
        if error in _ATOMIC_RENAME_UNSUPPORTED_ERRNOS:
            raise AtomicRenameUnavailable(
                "native atomic no-replace rename is unsupported"
            )
        if error in {errno.EEXIST, errno.ENOTEMPTY}:
            raise PacketError("packet output directory already exists")
        raise PacketError("native atomic no-replace rename failed") from OSError(
            error, os.strerror(error)
        )


def _write_all(descriptor: int, data: bytes) -> None:
    offset = 0
    while offset < len(data):
        written = os.write(descriptor, data[offset:])
        if written <= 0:
            raise PacketError("packet file write made no progress")
        offset += written


def _read_all(descriptor: int, *, maximum: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        remaining = maximum + 1 - total
        if remaining <= 0:
            raise PacketError("packet file read exceeds its byte bound")
        chunk = os.read(descriptor, min(64 * 1024, remaining))
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)
        total += len(chunk)


def _inode_identity(value: os.stat_result) -> tuple[int, int]:
    return value.st_dev, value.st_ino


def _directory_open_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )


def _open_bound_output_parent(
    output_dir: Path,
) -> tuple[Path, str, int, tuple[int, int]]:
    lexical_target = Path(os.path.abspath(os.fspath(output_dir)))
    name = lexical_target.name
    if (
        name in {"", ".", ".."}
        or "/" in name
        or (os.altsep is not None and os.altsep in name)
        or unicodedata.normalize("NFC", name) != name
        or any(unicodedata.category(character).startswith("C") for character in name)
    ):
        raise PacketError("packet output directory has an invalid basename")
    lexical_parent = lexical_target.parent
    try:
        lexical_parent_status = os.lstat(lexical_parent)
    except OSError as exc:
        raise PacketError("packet output parent does not exist") from exc
    if stat.S_ISLNK(lexical_parent_status.st_mode):
        raise PacketError("packet output parent must not be a symlink")
    parent = Path(os.path.realpath(lexical_parent))
    try:
        parent_status = os.lstat(parent)
    except OSError as exc:
        raise PacketError("packet output parent cannot be resolved") from exc
    if (
        stat.S_ISLNK(parent_status.st_mode)
        or not stat.S_ISDIR(parent_status.st_mode)
        or parent_status.st_uid not in {0, os.geteuid()}
        or parent_status.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        raise PacketError("packet output parent is not a trusted real directory")
    try:
        parent_fd = os.open(parent, _directory_open_flags())
    except OSError as exc:
        raise PacketError("packet output parent cannot be opened") from exc
    opened = os.fstat(parent_fd)
    identity = _inode_identity(opened)
    if (
        not stat.S_ISDIR(opened.st_mode)
        or identity != _inode_identity(parent_status)
        or opened.st_uid != parent_status.st_uid
        or opened.st_mode != parent_status.st_mode
    ):
        os.close(parent_fd)
        raise PacketError("packet output parent changed while it was opened")
    return parent, name, parent_fd, identity


def _assert_parent_path_identity(
    parent: Path, parent_fd: int, expected_identity: tuple[int, int]
) -> None:
    descriptor_status = os.fstat(parent_fd)
    try:
        path_status = os.lstat(parent)
    except OSError as exc:
        raise PacketError("packet output parent path changed") from exc
    if (
        _inode_identity(descriptor_status) != expected_identity
        or _inode_identity(path_status) != expected_identity
        or not stat.S_ISDIR(path_status.st_mode)
        or stat.S_ISLNK(path_status.st_mode)
    ):
        raise PacketError("packet output parent path identity changed")


def _named_directory_identity(parent_fd: int, name: str) -> tuple[int, int]:
    status = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if not stat.S_ISDIR(status.st_mode) or stat.S_ISLNK(status.st_mode):
        raise PacketError("packet directory name is not bound to a real directory")
    return _inode_identity(status)


def _verify_output_directory_fd(
    directory_fd: int, outputs: Mapping[str, bytes]
) -> None:
    expected_names = sorted(outputs, key=lambda item: item.encode("utf-8"))
    names: list[str] = []
    scan_fd = os.open(".", _directory_open_flags(), dir_fd=directory_fd)
    try:
        if _inode_identity(os.fstat(scan_fd)) != _inode_identity(
            os.fstat(directory_fd)
        ):
            raise PacketError("packet directory scan escaped its bound descriptor")
        with os.scandir(scan_fd) as entries:
            for entry in entries:
                names.append(entry.name)
                if len(names) > len(expected_names):
                    raise PacketError("packet directory exceeds its entry-count bound")
    finally:
        os.close(scan_fd)
    names.sort(key=lambda item: item.encode("utf-8"))
    if names != expected_names:
        raise PacketError("packet directory has a missing or extra entry")
    for name in expected_names:
        before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o644
            or before.st_size != len(outputs[name])
        ):
            raise PacketError("packet entry metadata is contradictory")
        descriptor = os.open(
            name,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
            dir_fd=directory_fd,
        )
        try:
            opened = os.fstat(descriptor)
            if _inode_identity(opened) != _inode_identity(before):
                raise PacketError("packet entry changed while it was opened")
            data = _read_all(descriptor, maximum=MAX_PACKET_BYTES - 1)
            after = os.fstat(descriptor)
            named_after = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        finally:
            os.close(descriptor)
        if (
            _inode_identity(after) != _inode_identity(opened)
            or _inode_identity(named_after) != _inode_identity(opened)
            or after.st_size != opened.st_size
            or not stat.S_ISREG(named_after.st_mode)
            or named_after.st_nlink != 1
            or stat.S_IMODE(named_after.st_mode) != 0o644
            or named_after.st_size != len(outputs[name])
            or data != outputs[name]
        ):
            raise PacketError("packet entry changed or has unexpected bytes")


def publish_outputs(output_dir: Path, outputs: Mapping[str, bytes]) -> None:
    parent, target_name, parent_fd, parent_identity = _open_bound_output_parent(
        output_dir
    )
    try:
        os.stat(target_name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        pass
    except OSError as exc:
        os.close(parent_fd)
        raise PacketError("cannot inspect packet output destination") from exc
    else:
        os.close(parent_fd)
        raise PacketError("packet output directory already exists")

    temporary = f".haldir-review-packets-tmp-{os.getpid()}-{secrets.token_hex(8)}"
    temporary_fd: int | None = None
    temporary_identity: tuple[int, int] | None = None
    published = False
    created_names: list[str] = []
    try:
        os.mkdir(temporary, 0o700, dir_fd=parent_fd)
        os.fsync(parent_fd)
        created_status = os.stat(temporary, dir_fd=parent_fd, follow_symlinks=False)
        temporary_fd = os.open(temporary, _directory_open_flags(), dir_fd=parent_fd)
        opened_status = os.fstat(temporary_fd)
        if (
            not stat.S_ISDIR(created_status.st_mode)
            or stat.S_IMODE(created_status.st_mode) != 0o700
            or _inode_identity(created_status) != _inode_identity(opened_status)
        ):
            raise PacketError("temporary packet directory identity changed")
        temporary_identity = _inode_identity(opened_status)
        for name in sorted(outputs, key=lambda item: item.encode("utf-8")):
            if "/" in name or name in {"", ".", ".."}:
                raise PacketError("packet output filename is invalid")
            data = outputs[name]
            descriptor = os.open(
                name,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
                0o644,
                dir_fd=temporary_fd,
            )
            created_names.append(name)
            try:
                _write_all(descriptor, data)
                os.fchmod(descriptor, 0o644)
                os.fsync(descriptor)
                written_status = os.fstat(descriptor)
                named_status = os.stat(name, dir_fd=temporary_fd, follow_symlinks=False)
                if (
                    not stat.S_ISREG(written_status.st_mode)
                    or written_status.st_nlink != 1
                    or stat.S_IMODE(written_status.st_mode) != 0o644
                    or written_status.st_size != len(data)
                    or _inode_identity(written_status) != _inode_identity(named_status)
                ):
                    raise PacketError("packet file identity changed after its write")
            finally:
                os.close(descriptor)
        _verify_output_directory_fd(temporary_fd, outputs)
        os.fchmod(temporary_fd, 0o755)
        os.fsync(temporary_fd)
        if _named_directory_identity(parent_fd, temporary) != temporary_identity:
            raise PacketError("temporary packet directory name changed before publish")
        _assert_parent_path_identity(parent, parent_fd, parent_identity)
        _atomic_rename_noreplace(parent_fd, temporary, parent_fd, target_name)
        published = True
        if _named_directory_identity(parent_fd, target_name) != temporary_identity:
            raise PacketError("published packet directory identity is contradictory")
        published_fd = os.open(target_name, _directory_open_flags(), dir_fd=parent_fd)
        try:
            if _inode_identity(os.fstat(published_fd)) != temporary_identity:
                raise PacketError("published packet directory changed while opening")
            _verify_output_directory_fd(published_fd, outputs)
            os.fsync(published_fd)
        finally:
            os.close(published_fd)
        os.fsync(parent_fd)
        _assert_parent_path_identity(parent, parent_fd, parent_identity)
        if _named_directory_identity(parent_fd, target_name) != temporary_identity:
            raise PacketError("published packet directory changed after fsync")
    except PacketError:
        raise
    except OSError as exc:
        raise PacketError("atomic packet directory publication failed") from exc
    finally:
        if not published:
            if temporary_fd is not None:
                for name in created_names:
                    try:
                        os.unlink(name, dir_fd=temporary_fd)
                    except OSError:
                        pass
        if temporary_fd is not None:
            os.close(temporary_fd)
        if not published:
            try:
                if (
                    temporary_identity is not None
                    and _named_directory_identity(parent_fd, temporary)
                    == temporary_identity
                ):
                    os.rmdir(temporary, dir_fd=parent_fd)
            except (OSError, PacketError):
                pass
        os.close(parent_fd)


def verify_outputs(output_dir: Path, expected: Mapping[str, bytes]) -> None:
    parent, target_name, parent_fd, parent_identity = _open_bound_output_parent(
        output_dir
    )
    try:
        status = os.stat(target_name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError as exc:
        os.close(parent_fd)
        raise PacketError("packet output directory cannot be inspected") from exc
    if stat.S_ISLNK(status.st_mode) or not stat.S_ISDIR(status.st_mode):
        os.close(parent_fd)
        raise PacketError("packet output is not a real directory")
    directory_fd = os.open(target_name, _directory_open_flags(), dir_fd=parent_fd)
    try:
        opened = os.fstat(directory_fd)
        if _inode_identity(opened) != _inode_identity(status):
            raise PacketError("packet output directory changed while it was opened")
        _verify_output_directory_fd(directory_fd, expected)
        _assert_parent_path_identity(parent, parent_fd, parent_identity)
        if _named_directory_identity(parent_fd, target_name) != _inode_identity(opened):
            raise PacketError(
                "packet output directory name changed during verification"
            )
    finally:
        os.close(directory_fd)
        os.close(parent_fd)
    if sum(len(data) for data in expected.values()) > MAX_PACKET_DIRECTORY_BYTES:
        raise PacketError("packet output exceeds its aggregate byte bound")
    for data in expected.values():
        _parse_canonical_json(data, label="packet output")


def _summary(command: str, prepared: PreparedInputs) -> dict[str, Any]:
    return {
        "command": command,
        "critical_subjects": sum(
            bool(subject.criticality) for subject in prepared.subjects
        ),
        "lane_units": [lane.total_units for lane in prepared.lanes],
        "packet_count": LANE_COUNT,
        "result": "PASS",
        "review_subjects": len(prepared.subjects),
        "subject_set_sha256": _subject_set_digest(
            prepared.subjects,
            freeze_commit=prepared.snapshot.freeze_commit,
            freeze_tree=prepared.snapshot.freeze_tree,
        ),
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("render", "verify"):
        subparser = subparsers.add_parser(command)
        subparser.add_argument("--repo", type=Path, required=True)
        subparser.add_argument("--implementation-commit", required=True)
        subparser.add_argument("--ledger", type=Path, required=True)
        subparser.add_argument("--overlay", type=Path, required=True)
        subparser.add_argument("--output-dir", type=Path, required=True)
        subparser.add_argument("--reviewer-registry", type=Path, required=True)
    return parser


def main(arguments: Sequence[str] | None = None) -> int:
    parsed = _parser().parse_args(arguments)
    try:
        prepared = _prepare_inputs(
            repo_argument=parsed.repo,
            implementation_commit_argument=parsed.implementation_commit,
            ledger_argument=parsed.ledger,
            overlay_argument=parsed.overlay,
            registry_argument=parsed.reviewer_registry,
        )
        outputs = build_outputs(prepared)
        if parsed.command == "render":
            publish_outputs(parsed.output_dir, outputs)
        else:
            verify_outputs(parsed.output_dir, outputs)
        sys.stdout.buffer.write(_canonical_json(_summary(parsed.command, prepared)))
        return 0
    except PacketError as exc:
        print(f"current-file-review-packets: ERROR: {exc}", file=sys.stderr)
        return 2
    except (OSError, UnicodeError, ValueError) as exc:
        print(
            "current-file-review-packets: ERROR: bounded operating-system or "
            f"encoding operation failed closed ({type(exc).__name__})",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
