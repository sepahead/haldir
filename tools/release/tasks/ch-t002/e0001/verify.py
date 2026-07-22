#!/usr/bin/env python3
"""Independently verify CH-T002 review coverage and its signed lifecycle.

The verifier treats the CH-T001 ledger as the sole canonical file ledger.  It
does not import or execute the packet generator.  Instead it parses the
completed CSV, reconciles the F snapshot and overlay from Git objects, rebuilds
the three packet bodies, and checks the exact F/I/C/D chain and retained
qualification artifacts.  Later commits may add or change unrelated paths;
the historical CH-T002 snapshots and retained C/D records remain immutable.
"""

from __future__ import annotations

import argparse
import ast
import base64
import binascii
import contextvars
import copy
import csv
import hashlib
import io
import json
import math
import os
import re
import selectors
import shlex
import stat
import subprocess
import sys
import tempfile
import time
import unicodedata
import zipfile
from collections import Counter
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Iterable, Mapping, Sequence


TASK_ID = "CH-T002"
EPOCH = 1
RELEASE_TARGET = "0.9.0"
AUTHOR = {"name": "Sepehr Mahmoudian", "email": "sepmhn@gmail.com"}
PERSISTENT_IDENTIFIER = None
SOURCE_RECORD_SHA256 = (
    "3556d42ad367f1ecba0e1ac77bafa17e6bde15b064cc65dcc57abaeb57732bbc"
)
HUMAN_REVIEW_LIMITATION = (
    "LIMITATION (CH-T002/E07): requirements_complete=true attests frozen CH-T002 "
    "technical and evidence requirements only: deterministic complete byte/line "
    "packet coverage of every regular Git blob on the exact signed snapshot; "
    "primary-lane assignment for every subject and distinct secondary-lane "
    "assignment for every critical subject; three independent signed automated "
    "technical review records plus signed automated lead-support review under "
    "distinct frozen keys. Human review coverage is NOT performed and NOT claimed: "
    "automated_review_only=true; independent_human_review_performed=false; "
    "named_human_review_performed=false; "
    "required_external_human_review_satisfied=null. No human, named-human, external, "
    "organizational, release, or publication review or approval is asserted or "
    "implied. Overall release status remains NO_GO; named/external human review is "
    "deferred to designated successor tasks."
)
EXPECTED_TASK_IDENTITY = {
    "id": TASK_ID,
    "source_task_id": "T002",
    "source_record_sha256": SOURCE_RECORD_SHA256,
    "phase": "P0 Audit and scope",
    "title": (
        "Complete language-classified line-by-line review packets and reviewer "
        "assignments"
    ),
    "source_scope": "all text/code/config/docs",
    "focus": "human review coverage",
    "priority": "P0_RELEASE_BLOCKER",
    "dependencies": ["CH-T001"],
    "execution_wave": 0,
    "subagent_lane": 3,
    "lead_review_required": True,
}
EXPECTED_HUMAN_REVIEW_BOUNDARY = {
    "automated_review_only": True,
    "independent_automated_review_performed": True,
    "independent_human_review_performed": False,
    "named_human_review_performed": False,
    "required_external_human_review_satisfied": None,
}

# Exact registered predecessor of the CH-T002 F transition.  No I/C/D commit
# identity belongs in the F-frozen verifier: those identities are supplied by
# the signed protocol transition and checked against parents, diffs, and exact
# Git objects.
BASELINE_COMMIT = "2167b0b1b8580298b8474e676893f97292c3d7c7"

CH_T001_IMPLEMENTATION_COMMIT = "ab4eb7a99bebae88c5aad3684bccf3a85a4e7dc9"
CH_T001_IMPLEMENTATION_TREE = "844dbc2b50812e7bdf2a44deae8be831d8ff8349"
CH_T001_LEDGER_OBJECT_ID = "51c0278e16885231bb98b3c85ae64384e08bd97d"
CH_T001_LEDGER_SHA256 = (
    "0e0d5a0fb147157cc7d5506d271d64c24794b1261fc3713b2e097ca50b8d9a89"
)
EXPECTED_LEDGER_ROWS = 356

CLASSIFICATION_AUDIT_SCHEMA_ID = "HALDIR_CH_T002_INDEPENDENT_CLASSIFICATION_AUDIT_V1"
CLASSIFICATION_AUDIT_SHA256 = (
    "1222a6c9e6962a8c0ad6ac5196868084c03d230e0ba976baa8fe9b49be464441"
)
CURRENT_A_TREE = "66c906443dae3338117f8a43e740b9161811ef7a"
CLASSIFICATION_CONTRACT_SCHEMA_ID = "haldir.ch-t002.review-classification-contract.v1"
CLASSIFICATION_DIGEST_DOMAIN = "haldir-ch-t002-classification-set-v1"
CLASSIFICATION_POLICY = (
    "HASH_PINNED_INDEPENDENT_AUDIT_PLUS_EXPLICIT_REVIEW_OVERRIDES_AND_F_EXTENSION_V1"
)
EXPECTED_F_CLASSIFICATION_SET_SHA256 = (
    "c146353dc97fe3e9b2b75a025e7686e8ff217070a0a4d6e6686f5f14e946fb33"
)
AUDITED_CURRENT_A_PATHS = 388
CURRENT_A_SOURCE_BASIS = "INDEPENDENT_AUDIT_CURRENT_A_ENTRY"
F_EXTENSION_SOURCE_BASIS = "EXPLICIT_CH_T002_F_ADDITION_POLICY_V1"
CLASSIFICATION_OVERRIDE_POLICY_ID = (
    "INDEPENDENT_AUTOMATED_PLUS_LOCAL_BYTE_REVIEW_OVERRIDES_V1"
)
CLASSIFICATION_OVERRIDE_SOURCE_BASIS = CLASSIFICATION_OVERRIDE_POLICY_ID
CLASSIFICATION_OVERRIDE_ORDER = "RAW_UTF8_BYTE_ASC_PATH_THEN_ASCII_FIELD_ASC"
CLASSIFICATION_OVERRIDE_DIGEST_DOMAIN = "haldir-ch-t002-classification-override-set-v1"
# Unlike a redundant path literal, this digest pins every path, field,
# before/after value, final rule, and source basis in the closed override layer.
EXPECTED_CLASSIFICATION_OVERRIDE_SET_SHA256 = (
    "546a1e62fc78ef9f7921cfda1ce0cc3f75712c813565c69159fa353569ba32d6"
)
EXPECTED_CLASSIFICATION_OVERRIDE_PATHS = 74
EXPECTED_CLASSIFICATION_OVERRIDE_FIELDS = 92
EXPECTED_SOURCE_CURRENT_A_COUNTS = {
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
CLASSIFICATION_CONTROL_STATEMENT = (
    "The I overlay SHALL contain exactly 391 classification records, one for every "
    "regular Git blob at the signed F tree in RAW_UTF8_BYTE_ASC order; SHALL bind "
    "classification policy "
    "HASH_PINNED_INDEPENDENT_AUDIT_PLUS_EXPLICIT_REVIEW_OVERRIDES_AND_F_EXTENSION_V1, "
    "audit schema HALDIR_CH_T002_INDEPENDENT_CLASSIFICATION_AUDIT_V1, SHA-256 "
    "1222a6c9e6962a8c0ad6ac5196868084c03d230e0ba976baa8fe9b49be464441, "
    "current-A commit 2167b0b1b8580298b8474e676893f97292c3d7c7, current-A tree "
    "66c906443dae3338117f8a43e740b9161811ef7a, override policy "
    "INDEPENDENT_AUTOMATED_PLUS_LOCAL_BYTE_REVIEW_OVERRIDES_V1, exactly 92 field "
    "overrides across exactly 74 paths in "
    "RAW_UTF8_BYTE_ASC_PATH_THEN_ASCII_FIELD_ASC order, "
    "haldir-ch-t002-classification-override-set-v1 digest "
    "546a1e62fc78ef9f7921cfda1ce0cc3f75712c813565c69159fa353569ba32d6, "
    "NO_REMOVALS_PER_EXACT_BASELINE_TO_FREEZE_DIFF, the frozen generated and "
    "primary-capture semantics, and haldir-ch-t002-classification-set-v1 digest "
    "c146353dc97fe3e9b2b75a025e7686e8ff217070a0a4d6e6686f5f14e946fb33; and "
    "every ledger row, overlay entry, packet, and CH-T002-E09 decision SHALL agree "
    "exactly."
)
NORMATIVE_CONTROL_BINDINGS = (
    (
        "The signed F freeze SHALL have the exact registered schema, task identity, author, release target, and absent persistent identifier.",
        "test_n01_accepted",
        "test_n01_rejected",
        "_validate_freeze",
        "FREEZE_IDENTITY",
    ),
    (
        "The signed F freeze SHALL declare exactly the four I implementation paths and the same exact verification-trigger path set.",
        "test_n02_accepted",
        "test_n02_rejected",
        "_validate_freeze",
        "FREEZE_IMPLEMENTATION_PLAN",
    ),
    (
        CLASSIFICATION_CONTROL_STATEMENT,
        "test_n03_accepts_exact_frozen_classification_contract",
        "test_n03_rejects_classification_contract_drift",
        "_validate_classification_contract",
        "CLASSIFICATION_RULE_FLAG",
    ),
    (
        "The completed ledger SHALL preserve every immutable CH-T001 field and SHALL resolve every mutable review field under the frozen classification decisions.",
        "test_n04_accepted",
        "test_n04_rejected",
        "validate_completed_ledger",
        "LEDGER_IMMUTABLE_DRIFT",
    ),
    (
        "The I overlay SHALL contain the exact derived requirement, test, evidence, and generator catalogs and exact implementation boundary.",
        "test_n05_accepted",
        "test_n05_rejected",
        "_validate_overlay_structure",
        "OVERLAY_EVIDENCE_CATALOG",
    ),
    (
        "CH-T002 SHALL reject every removal because the exact baseline-to-F delta contains no deleted path; removed_paths SHALL be empty.",
        "test_n06_accepted",
        "test_n06_rejected",
        "_validate_overlay_structure",
        "OVERLAY_REMOVALS_FORBIDDEN",
    ),
    (
        "Every F subject SHALL receive exactly one deterministic primary assignment and every critical subject SHALL receive one distinct secondary assignment.",
        "test_n07_accepted",
        "test_n07_rejected",
        "assign_subjects",
        "PRIMARY_PARTITION",
    ),
    (
        "Every packet subject SHALL bind the complete Git blob byte interval and exact text line interval, including an empty text blob.",
        "test_n08_accepted",
        "test_n08_rejected",
        "_subject_packet_record",
        "SUBJECT_SNAPSHOT_STATE",
    ),
    (
        "Every ledger evidence pointer SHALL be canonical, typed, and resolvable through the frozen evidence catalog.",
        "test_n09_accepted",
        "test_n09_rejected",
        "_validate_catalog_bindings",
        "CATALOG_POINTER",
    ),
    (
        "The F freeze SHALL require exactly E01 through E13, four review records, and A01 through A05 with their exact kinds, paths, and byte bounds.",
        "test_n10_accepted",
        "test_n10_rejected",
        "_validate_freeze",
        "FREEZE_EVIDENCE_REQUIREMENTS",
    ),
    (
        "The registered Python test artifact SHALL parse as bounded Python syntax and expose every exact test identifier declared by the F freeze.",
        "test_n11_accepted",
        "test_n11_rejected",
        "_python_test_names",
        "TEST_AST_INVALID",
    ),
    (
        "The freeze SHALL retain the exact ten-second verifier budget and SHALL NOT permit a caller to relax the hard budget.",
        "test_n12_accepted",
        "test_n12_rejected",
        "_validate_freeze",
        "FREEZE_VERIFIER_BUDGET",
    ),
    (
        "The three independent automated lanes and automated non-human lead support SHALL use four distinct registered machine-operated, non-human, non-external principals, public keys, and fingerprints.",
        "test_n13_accepted",
        "test_n13_rejected",
        "_validate_freeze",
        "FREEZE_REVIEWER_SEPARATION",
    ),
    (
        "Each review acceptance SHALL carry a valid Ed25519 SSH signature bound to its registered principal, namespace, exact F commit, and exact I commit.",
        "test_n14_accepted",
        "test_n14_rejected",
        "_verify_review_signature",
        "RUN_FAILED",
    ),
    (
        "All protocol JSON outside the F pretty freeze and central pretty registry SHALL be finite, duplicate-free, bounded canonical JSON.",
        "test_n15_accepted",
        "test_n15_rejected",
        "_parse_canonical_json",
        "VECTOR_DUPLICATE_KEY",
    ),
    (
        "Every protocol path SHALL be NFC, repository-relative, portable, and outside Git administrative paths.",
        "test_n16_accepted",
        "test_n16_rejected",
        "_canonical_path",
        "PATH_NOT_CANONICAL",
    ),
    (
        "A03 retained run and attempt-job API records SHALL bind exact endpoints, headers, tool version, capture times, bytes, and SHA-256 digests.",
        "test_n17_accepted",
        "test_n17_rejected",
        "_retained_ci_payload",
        "ACTIVATION_CI_RETAINED_BINDING",
    ),
    (
        "A05 SHALL be a bounded safe ZIP with one nonempty primary per exact CI job name and unique contiguous provider ordinals zero through five.",
        "test_n18_accepted",
        "test_n18_rejected",
        "_validate_log_archive",
        "ACTIVATION_ARCHIVE_PRIMARY_ORDINALS",
    ),
    (
        "Every activation command SHALL bind its exact phase, argv, working directory, ordered time window, nonempty output, exit code, and stream digests.",
        "test_n19_accepted",
        "test_n19_rejected",
        "_validate_activation_command",
        "ACTIVATION_COMMAND_BINDING",
    ),
    (
        "CH-T002 SHALL remain NO_GO with no public claim change; only deterministic packet generation, assignment mechanics, and automated technical qualification may qualify; source human-review coverage SHALL remain NOT_CLAIMED and external human review DEFERRED; and CH-T002 SHALL authorize no tag, GitHub release, DOI, Zenodo record, or archive.",
        "test_n20_accepted",
        "test_n20_rejected",
        "_validate_freeze",
        "FREEZE_OUTCOME_BOUNDARY",
    ),
)
COUNTERFACTUAL_BINDINGS = (
    (
        "valid syntax with contradictory semantics",
        "test_cf01_accepted",
        "test_cf01_rejected",
        "_validate_classification_record",
        "CLASSIFICATION_RULE_FLAG",
    ),
    (
        "authenticated but unauthorized producer",
        "test_cf02_accepted",
        "test_cf02_rejected",
        "_verify_review_signature",
        "REVIEW_SIGNATURE_BINDING",
    ),
    (
        "stale yet correctly signed data",
        "test_cf03_accepted",
        "test_cf03_rejected",
        "_verify_review_signature",
        "RUN_FAILED",
    ),
    (
        "correct version string with wrong contract/algorithm digest",
        "test_cf04_accepted",
        "test_cf04_rejected",
        "_validate_classification_contract",
        "CLASSIFICATION_SET_DIGEST",
    ),
    (
        "clean synthetic result under nonrepresentative distribution",
        "test_cf05_accepted",
        "test_cf05_rejected",
        "_validate_freeze",
        "FREEZE_OUTCOME_BOUNDARY",
    ),
    (
        "timeout or capacity exhaustion followed by convenience fallback",
        "test_cf06_accepted",
        "test_cf06_rejected",
        "_run",
        "RUN_TIMEOUT",
    ),
    (
        "feature unification activating a privileged/experimental path",
        "test_cf07_accepted",
        "test_cf07_rejected",
        "_validate_freeze",
        "FREEZE_IMPLEMENTATION_PLAN",
    ),
    (
        "partial migration accepted through default values",
        "test_cf08_accepted",
        "test_cf08_rejected",
        "validate_completed_ledger",
        "LEDGER_UNRESOLVED_TRISTATE",
    ),
    (
        "crash between decision/output and durable evidence",
        "test_cf09_accepted",
        "test_cf09_rejected",
        "_validate_activation_command",
        "ACTIVATION_COMMAND_EMPTY",
    ),
    (
        "simple but odd input unlikely to resemble training examples",
        "test_cf10_accepted",
        "test_cf10_rejected",
        "_subject_units",
        "SUBJECT_TEXT_LINES",
    ),
)

LEDGER_PATH = "audit/generated/FILE_REVIEW_LEDGER.csv"
OVERLAY_PATH = "audit/generated/CH-T002_FILE_REVIEW_OVERLAY.json"
PRODUCT_TOOL = "tools/release/current-file-review-packets.py"
PRODUCT_TESTS = "tools/release/test_current_file_review_packets.py"
VERIFIER_PATH = "tools/release/tasks/ch-t002/e0001/verify.py"
REGISTERED_TESTS_PATH = "tools/release/tasks/ch-t002/e0001/test_verify.py"
TASK_ROOT = "release/0.9.0/current-head/tasks/ch-t002/e0001"
FREEZE_PATH = f"{TASK_ROOT}/freeze.json"
QUALIFICATION_PATH = f"{TASK_ROOT}/qualification.json"
ACTIVATION_PATH = f"{TASK_ROOT}/activation.json"
RECEIPT_PATH = f"{TASK_ROOT}/verifier-receipt.json"
REGISTRY_PATH = "release/0.9.0/current-head/closures/task-verifier-registry.json"
REQUIREMENTS_PATH = "release/0.9.0/current-head/requirements.json"
ACTIVE_CLAIMS_PATH = "release/0.9.0/current-head/closures/active-claims.json"

EXPECTED_F_DIFF = {
    REGISTRY_PATH: "M",
    FREEZE_PATH: "A",
    REGISTERED_TESTS_PATH: "A",
    VERIFIER_PATH: "A",
}
EXPECTED_I_DIFF = {
    OVERLAY_PATH: "A",
    LEDGER_PATH: "M",
    PRODUCT_TOOL: "A",
    PRODUCT_TESTS: "A",
}
EXPECTED_COMMIT_SUBJECTS = {
    "F": "release: freeze CH-T002 file-review coverage",
    "I": "release: implement CH-T002 file-review coverage",
    "C": "release: qualify CH-T002 file-review coverage",
    "D": "release: activate CH-T002 file-review coverage",
}

EVIDENCE_SPECS = (
    ("CH-T002-E01", "FILE_REVIEW_TRACEABILITY", "file-review-traceability.json"),
    ("CH-T002-E02", "COMPLETE_COMMAND_LOG", "complete-command-log.json"),
    ("CH-T002-E03", "POSITIVE_NEGATIVE_VECTORS", "positive-negative-vectors.json"),
    (
        "CH-T002-E04",
        "COVERAGE_FUZZ_MUTATION_MODEL",
        "coverage-fuzz-mutation-model.json",
    ),
    ("CH-T002-E05", "RESOURCE_TIME_MAXIMA", "resource-time-maxima.json"),
    (
        "CH-T002-E06",
        "EXACT_IDENTITIES_CHECKSUMS",
        "exact-identities-checksums.json",
    ),
    (
        "CH-T002-E07",
        "CLAIM_MIGRATION_DISPOSITION",
        "claim-migration-disposition.json",
    ),
    (
        "CH-T002-E08",
        "COMPLETE_EXPLICIT_ASSIGNMENTS",
        "complete-explicit-assignments.json",
    ),
    ("CH-T002-E09", "FILE_REVIEW_EVIDENCE", "file-review-evidence.json"),
    ("CH-T002-E10", "LANGUAGE_REVIEW_PACKET", "review-lane-01.json"),
    ("CH-T002-E11", "LANGUAGE_REVIEW_PACKET", "review-lane-02.json"),
    ("CH-T002-E12", "LANGUAGE_REVIEW_PACKET", "review-lane-03.json"),
    (
        "CH-T002-E13",
        "FILE_REVIEW_PACKET_MANIFEST",
        "file-review-packet-manifest.json",
    ),
)
REVIEW_SPECS = (
    ("CH-T002-R01", "INDEPENDENT_REVIEW", "lane-01-independent-review.json"),
    (
        "CH-T002-R02",
        "INDEPENDENT_REVIEW_LANE_02",
        "lane-02-independent-review.json",
    ),
    (
        "CH-T002-R03",
        "INDEPENDENT_REVIEW_LANE_03",
        "lane-03-independent-review.json",
    ),
    (
        "CH-T002-R04",
        "LEAD_IMPLEMENTATION_REVIEW",
        "lead-implementation-review.json",
    ),
)
ACTIVATION_SPECS = (
    ("CH-T002-A01", "SUBSYSTEM_GATE", "subsystem-gate.json"),
    ("CH-T002-A02", "WAVE_GATE", "wave-gate.json"),
    ("CH-T002-A03", "FULL_LOCKED_CI", "full-locked-ci.json"),
    (
        "CH-T002-A04",
        "DOWNSTREAM_CONFORMANCE_DISPOSITION",
        "downstream-conformance-disposition.json",
    ),
    (
        "CH-T002-A05",
        "FULL_LOCKED_CI_LOG_ARCHIVE",
        "full-locked-ci-attempt-logs.zip",
    ),
)

EVIDENCE_PATHS = {
    identifier: f"{TASK_ROOT}/evidence/{name}"
    for identifier, _kind, name in EVIDENCE_SPECS
}
REVIEW_PATHS = {
    identifier: f"{TASK_ROOT}/reviews/{name}"
    for identifier, _kind, name in REVIEW_SPECS
}
ACTIVATION_PATHS = {
    identifier: f"{TASK_ROOT}/activation-evidence/{name}"
    for identifier, _kind, name in ACTIVATION_SPECS
}

OVERLAY_SCHEMA_ID = "haldir.ch-t002.file-review-overlay.v1"
OVERLAY_SCHEMA_VERSION = "1.0.0"
OVERLAY_SCOPE = "FROZEN_SNAPSHOT_DELTA_AND_REVIEW_SCOPE_MANIFEST"
PACKET_SCHEMA_ID = "haldir.ch-t002.file-review-packet.v1"
PACKET_MANIFEST_SCHEMA_ID = "haldir.ch-t002.file-review-packet-manifest.v1"
ASSIGNMENT_ALGORITHM = "LARGEST_FIRST_LEAST_LOADED_V1"
BINARY_UNIT_BYTES = 4096
COVERAGE_RULE = "EXACT_GIT_BLOB_FULL_RECONSTRUCTION"
PRIMARY_RULE = "MIN_TOTAL_UNITS_THEN_ITEM_COUNT_THEN_LANE"
SECONDARY_RULE = "MIN_TOTAL_UNITS_THEN_ITEM_COUNT_THEN_LANE_EXCLUDING_PRIMARY"
SORT_RULE = "UNITS_DESC_LANGUAGE_ASC_SUBJECT_ID_RAW_UTF8_ASC"
TEXT_UNIT_RULE = "MAX_LINES_ONE"
SCOPE_INCLUSION = "ALL_REGULAR_GIT_BLOBS_AT_FREEZE_TREE"
REMOVAL_POLICY = "NO_REMOVALS_PER_EXACT_BASELINE_TO_FREEZE_DIFF"
PATH_ORDER = "RAW_UTF8_BYTE_ASC"
IMPLEMENTATION_REVIEW_KIND = "CENTRAL_PROTOCOL_REVIEWS"
CRITICALITY_ORDER = (
    "PUBLIC_SURFACE",
    "SECURITY_CRITICAL",
    "SCIENCE_CRITICAL",
    "AUTHORITY_CRITICAL",
)
CLASSIFICATION_RECORD_KEYS = (
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
CLASSIFICATION_COUNT_KEYS = tuple(EXPECTED_SOURCE_CURRENT_A_COUNTS)
CLASSIFICATION_OVERRIDE_FIELD_SPECS = {
    "authority_critical": (3, "AUTH_"),
    "generated": (4, "GEN_"),
    "generator": (4, "GEN_"),
    "public_surface": (0, "PUB_"),
    "science_critical": (2, "SCI_"),
    "security_critical": (1, "SEC_"),
}
_COMMON_F_EXTENSION_CLASSIFICATION = {
    "authority_critical": "YES",
    "generated": "NO",
    "generator": "",
    "license_expression": "Apache-2.0 OR MIT",
    "license_review_status": "APPROVED",
    "provenance_review_status": "CONFIRMED",
    "public_surface": "NO",
    "science_critical": "NO",
    "security_critical": "YES",
    "source_basis": F_EXTENSION_SOURCE_BASIS,
}
EXPECTED_F_EXTENSION_CLASSIFICATIONS = {
    FREEZE_PATH: {
        **_COMMON_F_EXTENSION_CLASSIFICATION,
        "path": FREEZE_PATH,
        "rule_ids": [
            "PUB_NO_INTERNAL_ASSURANCE_OR_IMPLEMENTATION_ARTIFACT",
            "SEC_YES_RELEASE_SECURITY_CONTROL_OR_DECISIVE_SUMMARY",
            "SCI_NO_NO_MODEL_CONTROL_NUMERIC_OR_RESEARCH_SEMANTICS",
            "AUTH_YES_MANDATORY_CURRENT_HEAD_RELEASE_STATE_FLOOR",
            "GEN_NO_AUTHORED_IMPORTED_OR_PRIMARY_RECORD",
            "LIC_REPOSITORY_DUAL_LICENSE_AND_GIT_PROVENANCE",
        ],
    },
    REGISTERED_TESTS_PATH: {
        **_COMMON_F_EXTENSION_CLASSIFICATION,
        "path": REGISTERED_TESTS_PATH,
        "rule_ids": [
            "PUB_NO_INTERNAL_ASSURANCE_OR_IMPLEMENTATION_ARTIFACT",
            "SEC_YES_SECURITY_TEST_VERIFIER_GENERATOR_OR_RELEASE_TOOL",
            "SCI_NO_NO_MODEL_CONTROL_NUMERIC_OR_RESEARCH_SEMANTICS",
            "AUTH_YES_RELEASE_STATE_GENERATOR_OR_VERIFIER",
            "GEN_NO_AUTHORED_IMPORTED_OR_PRIMARY_RECORD",
            "LIC_REPOSITORY_DUAL_LICENSE_AND_GIT_PROVENANCE",
        ],
    },
    VERIFIER_PATH: {
        **_COMMON_F_EXTENSION_CLASSIFICATION,
        "path": VERIFIER_PATH,
        "rule_ids": [
            "PUB_NO_INTERNAL_ASSURANCE_OR_IMPLEMENTATION_ARTIFACT",
            "SEC_YES_SECURITY_TEST_VERIFIER_GENERATOR_OR_RELEASE_TOOL",
            "SCI_NO_NO_MODEL_CONTROL_NUMERIC_OR_RESEARCH_SEMANTICS",
            "AUTH_YES_RELEASE_STATE_GENERATOR_OR_VERIFIER",
            "GEN_NO_AUTHORED_IMPORTED_OR_PRIMARY_RECORD",
            "LIC_REPOSITORY_DUAL_LICENSE_AND_GIT_PROVENANCE",
        ],
    },
}

MAX_LEDGER_BYTES = 4 * 1024 * 1024
MAX_JSON_BYTES = 4 * 1024 * 1024
MAX_PACKET_BYTES = 4 * 1024 * 1024
MAX_TREE_OUTPUT = 4 * 1024 * 1024
MAX_TREE_BYTES = 128 * 1024 * 1024
MAX_BLOB_BYTES = 4 * 1024 * 1024
MAX_GIT_OUTPUT = 160 * 1024 * 1024
MAX_PATH_BYTES = 4096
MAX_CELL_BYTES = 16 * 1024
MAX_JSON_DEPTH = 32
MAX_FIRST_PARENT_COMMITS = 1024
CENTRAL_ARTIFACT_BYTES = 256 * 1024
COMMAND_SECONDS = 3.0
VERIFIER_SECONDS = 10.0
GIT_EXECUTABLE = "/usr/bin/git"
SSH_KEYGEN_EXECUTABLE = "/usr/bin/ssh-keygen"
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
RFC3339_UTC = re.compile(
    r"^[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])"
    r"T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$"
)
SAFE_REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/#@+-]{0,4095}$")
EVIDENCE_POINTER = re.compile(
    r"^(CH-T002-E(?:0[1-9]|1[0-3]))#([0-9a-f]{64}):"
    r"(PRIMARY|SECONDARY|PROVENANCE|LICENSE)$"
)

FREEZE_KEYS = (
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

_ACTIVE_DEADLINE: contextvars.ContextVar[float | None] = contextvars.ContextVar(
    "haldir_ch_t002_verifier_deadline", default=None
)

EVIDENCE_SCHEMA_IDS = {
    "CH-T002-E01": "haldir.ch-t002.file-review-traceability.v1",
    "CH-T002-E02": "haldir.ch-t002.complete-command-log.v1",
    "CH-T002-E03": "haldir.ch-t002.positive-negative-vectors.v1",
    "CH-T002-E04": "haldir.ch-t002.coverage-fuzz-mutation-model.v1",
    "CH-T002-E05": "haldir.ch-t002.resource-time-maxima.v1",
    "CH-T002-E06": "haldir.ch-t002.exact-identities-checksums.v1",
    "CH-T002-E07": "haldir.ch-t002.claim-migration-disposition.v1",
    "CH-T002-E08": "haldir.ch-t002.complete-explicit-assignments.v1",
    "CH-T002-E09": "haldir.ch-t002.file-review-evidence.v1",
}
EVIDENCE_COMMON_KEYS = frozenset(
    {
        "schema_id",
        "evidence_id",
        "task_id",
        "epoch",
        "freeze_commit",
        "implementation_commit",
        "started_at_utc",
        "completed_at_utc",
        "result",
    }
)
EVIDENCE_SPECIFIC_KEYS = {
    "CH-T002-E01": frozenset(
        {
            "implementation_plan",
            "requirement_ids",
            "test_ids",
            "evidence_ids",
            "immutable_fields",
            "mutable_fields",
            "counts",
            "digests",
        }
    ),
    "CH-T002-E02": frozenset({"commands", "environment"}),
    "CH-T002-E03": frozenset({"accepted_vectors", "rejected_vectors", "command_ids"}),
    "CH-T002-E04": frozenset(
        {"techniques", "covered_requirement_ids", "covered_test_ids"}
    ),
    "CH-T002-E05": frozenset(
        {
            "declared_maxima",
            "observed_maxima",
            "observed_distributions",
            "command_ids",
            "capacity_disposition",
        }
    ),
    "CH-T002-E06": frozenset(
        {
            "baseline_commit",
            "freeze_tree",
            "implementation_tree",
            "base_ledger",
            "implementation_files",
            "registered_files",
            "lifecycle_diffs",
            "digests",
        }
    ),
    "CH-T002-E07": frozenset(
        {
            "claim_outcome",
            "implementation_paths",
            "runtime_surface_changed",
            "release_authority",
            "publication_authority",
            "requirements_complete",
        }
    ),
    "CH-T002-E08": frozenset(
        {"assignments", "assigned_rows", "reviewed_rows", "assignment_set_sha256"}
    ),
    "CH-T002-E09": frozenset({"completion_records", "counts", "digests"}),
}
RESOURCE_SAMPLE_COUNT = 5
TECHNIQUE_TEST_IDS = {
    "BOUNDARY_VALUE": "test_technique_boundary_value",
    "EQUIVALENCE_PARTITION": "test_technique_equivalence_partition",
    "DECISION_TABLE": "test_technique_decision_table",
    "STATE_TRANSITION": "test_technique_state_transition",
    "PAIRWISE": "test_technique_pairwise",
    "FUZZ": "test_technique_fuzz",
    "MUTATION": "test_technique_mutation",
}
TECHNIQUE_LIMITATIONS = {
    name: "BOUNDED_EXACT_CANDIDATE_TECHNICAL_EVIDENCE_NOT_FIELD_VALIDATION"
    for name in TECHNIQUE_TEST_IDS
}
TECHNIQUE_COVERAGE = {
    "BOUNDARY_VALUE": {
        "cases": 2,
        "requirement_ids": ("CH-T002-N17", "CH-T002-N18", "CH-T002-N19"),
    },
    "EQUIVALENCE_PARTITION": {
        "cases": 3,
        "requirement_ids": ("CH-T002-N08",),
    },
    "DECISION_TABLE": {
        "cases": 1,
        "requirement_ids": ("CH-T002-N03",),
    },
    "STATE_TRANSITION": {
        "cases": 4,
        "requirement_ids": ("CH-T002-N01", "CH-T002-N02", "CH-T002-N20"),
    },
    "PAIRWISE": {
        "cases": 9,
        "requirement_ids": ("CH-T002-N07", "CH-T002-N13"),
    },
    "FUZZ": {
        "cases": 5,
        "requirement_ids": ("CH-T002-N16",),
    },
    "MUTATION": {
        "cases": 2,
        "requirement_ids": ("CH-T002-N03",),
    },
}
P0R_GATE_NAMES = (
    "current-head audit gate",
    "rustfmt",
    "clippy (deny warns)",
    "tests",
    "doc tests",
    "docs (deny warns)",
    "no-default build",
    "default clippy",
    "clean build",
    "dependency policy",
    "source pins",
    "CI/formal pins",
    "release audit tests",
    "release audit cut",
    "release authority tests",
    "release authority model",
    "release evidence generator tests",
    "generated task evidence",
    "release protection tests",
    "release protection model",
    "evidence layout",
    "offline Zenoh profile tests",
    "live Gate dev smoke tests",
    "offline Zenoh profile",
    "retained live Zenoh evidence",
    "retained live Gate dev smoke",
    "forbidden claims",
    "generated vectors",
    "interop (COSE/CBOR)",
    "diff hygiene",
)
P0R_GATE_SUMMARY = "P0-R exit gate: 30 passed, 0 failed"
P0R_GATE_EPILOGUE = (
    "All offline P0-R gates passed. (TLA+ check runs in CI: CL-FORMAL-01.)"
)
P0R_GATE_ARGV = (
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
)
CI_JOB_NAMES = (
    "build-test",
    "clean-build",
    "feature-matrix",
    "interop",
    "macos-compile",
    "supply-chain",
)
GH_EXECUTABLE = "/opt/homebrew/bin/gh"
GH_VERSION = "gh version 2.95.0 (2026-06-17)"
GH_ACCEPT_HEADER = "application/vnd.github+json"
GH_API_VERSION = "2022-11-28"
ACTIVATION_SCHEMA_IDS = {
    "CH-T002-A01": "haldir.ch-t002.subsystem-gate.v1",
    "CH-T002-A02": "haldir.ch-t002.wave-gate.v2",
    "CH-T002-A03": "haldir.ch-t002.full-locked-ci.v2",
    "CH-T002-A04": "haldir.ch-t002.downstream-conformance-disposition.v1",
}
FORMULA_PREFIXES = frozenset("=+-@")

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
MUTABLE_REVIEW_FIELDS = tuple(field for field in FIELDS if field in MUTABLE_FIELDS)
IMMUTABLE_FIELDS = tuple(field for field in FIELDS if field not in MUTABLE_FIELDS)
TRISTATE_FIELDS = (
    "generated",
    "public_surface",
    "security_critical",
    "science_critical",
    "authority_critical",
)
REFERENCE_FIELDS = (
    "provenance_evidence",
    "license_evidence",
    "requirements",
    "assumptions",
    "defects",
    "tests",
    "evidence",
)
CRITICAL_FIELDS = (
    "public_surface",
    "security_critical",
    "science_critical",
    "authority_critical",
)
ALLOWED_EXTERNAL_GENERATORS = frozenset(
    {"PINNED_CARGO_1.96.0_FROM_WORKSPACE_MANIFESTS"}
)
ALLOWED_SPDX_EXPRESSIONS = frozenset(
    {
        "Apache-2.0",
        "Apache-2.0 OR MIT",
        "MIT",
        "MIT OR Apache-2.0",
    }
)


class VerificationError(RuntimeError):
    """A frozen review, artifact, or lifecycle binding is contradictory."""


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise VerificationError(code)


def _checkpoint(code: str = "VERIFIER_TIME_BOUND") -> float:
    """Fail closed when the active whole-verification budget is exhausted."""

    deadline = _ACTIVE_DEADLINE.get()
    if deadline is None:
        return COMMAND_SECONDS
    remaining = deadline - time.monotonic()
    _require(remaining > 0, code)
    return remaining


@contextmanager
def _verification_budget(seconds: float = VERIFIER_SECONDS) -> Iterable[None]:
    _require(0 < seconds <= VERIFIER_SECONDS, "VERIFIER_BUDGET")
    existing = _ACTIVE_DEADLINE.get()
    deadline = time.monotonic() + seconds
    if existing is not None:
        deadline = min(existing, deadline)
    token = _ACTIVE_DEADLINE.set(deadline)
    try:
        yield
        _checkpoint()
    finally:
        _ACTIVE_DEADLINE.reset(token)


def _bounded_verification(
    function: Callable[..., dict[str, Any]],
) -> Callable[..., dict[str, Any]]:
    def wrapped(*args: Any, **kwargs: Any) -> dict[str, Any]:
        with _verification_budget():
            return function(*args, **kwargs)

    return wrapped


def unresolved_lifecycle_fields() -> tuple[str, ...]:
    """Return pre-F values that must be resolved before registration."""

    unresolved: list[str] = []
    if HEX40.fullmatch(BASELINE_COMMIT) is None:
        unresolved.append("BASELINE_COMMIT")
    return tuple(unresolved)


def _canonical_path(raw: object) -> str:
    _require(isinstance(raw, str) and bool(raw), "PATH_INVALID")
    path = PurePosixPath(raw)
    _require(
        not path.is_absolute()
        and path.as_posix() == raw
        and "\\" not in raw
        and all(part not in {"", ".", ".."} for part in path.parts)
        and all(part.casefold() != ".git" for part in path.parts),
        "PATH_NOT_CANONICAL",
    )
    _require(
        len(raw.encode("utf-8")) <= MAX_PATH_BYTES
        and unicodedata.normalize("NFC", raw) == raw
        and not any(unicodedata.category(char).startswith("C") for char in raw),
        "PATH_ENCODING",
    )
    return raw


def _portable_unique(paths: Iterable[str], code: str) -> None:
    observed: dict[str, str] = {}
    for path in paths:
        folded = unicodedata.normalize("NFC", path).casefold()
        prior = observed.get(folded)
        _require(prior is None or prior == path, code)
        observed[folded] = path


def _canonical_order(paths: Iterable[str], code: str) -> list[str]:
    values = [_canonical_path(path) for path in paths]
    _require(len(values) == len(set(values)), code)
    _portable_unique(values, code)
    expected = sorted(values, key=lambda item: item.encode("utf-8"))
    _require(values == expected, code)
    return values


def _canonical_json_bytes(value: object) -> bytes:
    try:
        rendered = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        return (rendered + "\n").encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError) as error:
        raise VerificationError("JSON_RENDER") from error


def _pretty_json_bytes(value: object) -> bytes:
    """Render the source-order-preserving F contract representation."""

    try:
        rendered = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            indent=2,
        )
        return (rendered + "\n").encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError) as error:
        raise VerificationError("JSON_RENDER") from error


def _parse_json(payload: bytes, label: str, *, maximum: int = MAX_JSON_BYTES) -> Any:
    _require(0 < len(payload) <= maximum, f"{label}_BOUND")

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in items:
            _require(key not in value, f"{label}_DUPLICATE_KEY")
            value[key] = item
        return value

    def nonfinite(_raw: str) -> None:
        raise VerificationError(f"{label}_NONFINITE")

    try:
        value = json.loads(
            payload.decode("utf-8", "strict"),
            object_pairs_hook=pairs,
            parse_constant=nonfinite,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise VerificationError(f"{label}_INVALID") from error
    _json_depth(value, label=label)
    return value


def _json_depth(value: object, *, label: str, depth: int = 0) -> None:
    _require(depth <= MAX_JSON_DEPTH, f"{label}_DEPTH")
    if isinstance(value, dict):
        for key, child in value.items():
            _require(isinstance(key, str), f"{label}_KEY")
            _json_depth(child, label=label, depth=depth + 1)
    elif isinstance(value, list):
        for child in value:
            _json_depth(child, label=label, depth=depth + 1)


def _parse_canonical_json(
    payload: bytes, label: str, *, maximum: int = MAX_JSON_BYTES
) -> dict[str, Any]:
    value = _parse_json(payload, label, maximum=maximum)
    _require(isinstance(value, dict), f"{label}_NOT_OBJECT")
    _require(payload == _canonical_json_bytes(value), f"{label}_NOT_CANONICAL")
    return value


def _parse_pretty_json(
    payload: bytes, label: str, *, maximum: int = MAX_JSON_BYTES
) -> dict[str, Any]:
    value = _parse_json(payload, label, maximum=maximum)
    _require(isinstance(value, dict), f"{label}_NOT_OBJECT")
    _require(payload == _pretty_json_bytes(value), f"{label}_NOT_PRETTY")
    return value


def _exact_keys(value: object, keys: Iterable[str], code: str) -> dict[str, Any]:
    expected = frozenset(keys)
    _require(isinstance(value, dict) and frozenset(value) == expected, code)
    return value


def _strict_equal(left: object, right: object) -> bool:
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(
            _strict_equal(left[key], right[key]) for key in left
        )
    if isinstance(left, (list, tuple)):
        return len(left) == len(right) and all(
            _strict_equal(a, b) for a, b in zip(left, right, strict=True)
        )
    return left == right


def _text(value: object, code: str, *, maximum: int = 4096) -> str:
    _require(isinstance(value, str), code)
    _require(
        value == value.strip()
        and 0 < len(value.encode("utf-8")) <= maximum
        and unicodedata.normalize("NFC", value) == value
        and not any(unicodedata.category(char).startswith("C") for char in value)
        and re.search(r"\b(?:FIXME|PLACEHOLDER|TBD|TODO)\b", value, re.I) is None,
        code,
    )
    return value


def _timestamp(value: object, code: str) -> str:
    _require(isinstance(value, str) and RFC3339_UTC.fullmatch(value) is not None, code)
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as error:
        raise VerificationError(code) from error
    return value


def _integer(value: object, code: str, *, minimum: int = 0) -> int:
    _require(type(value) is int and value >= minimum, code)
    return value


def _hex(value: object, pattern: re.Pattern[str], code: str) -> str:
    _require(isinstance(value, str) and pattern.fullmatch(value) is not None, code)
    return value


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _git_blob_id(payload: bytes) -> str:
    header = f"blob {len(payload)}\0".encode("ascii")
    return hashlib.sha1(header + payload, usedforsecurity=False).hexdigest()


def _line_count(payload: bytes) -> int:
    return len(payload.splitlines())


def _environment(repo: Path) -> dict[str, str]:
    return {
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_CONFIG_COUNT": "5",
        "GIT_CONFIG_KEY_0": "core.excludesFile",
        "GIT_CONFIG_VALUE_0": "/dev/null",
        "GIT_CONFIG_KEY_1": "core.fsmonitor",
        "GIT_CONFIG_VALUE_1": "false",
        "GIT_CONFIG_KEY_2": "core.hooksPath",
        "GIT_CONFIG_VALUE_2": "/dev/null",
        "GIT_CONFIG_KEY_3": "core.untrackedCache",
        "GIT_CONFIG_VALUE_3": "false",
        "GIT_CONFIG_KEY_4": "safe.directory",
        "GIT_CONFIG_VALUE_4": os.path.abspath(os.fspath(repo)),
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_FLUSH": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_PAGER": "cat",
        "GIT_TERMINAL_PROMPT": "0",
        "HOME": "/nonexistent",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
        "XDG_CONFIG_HOME": "/nonexistent",
    }


def _run(
    command: Sequence[str],
    *,
    repo: Path,
    input_data: bytes | None = None,
    maximum: int = MAX_GIT_OUTPUT,
    seconds: float = COMMAND_SECONDS,
) -> tuple[bytes, bytes]:
    _require(
        0 < maximum <= MAX_GIT_OUTPUT and 0 < seconds <= COMMAND_SECONDS, "RUN_BOUND"
    )
    input_stream = None
    outer_remaining = _checkpoint()
    deadline = time.monotonic() + min(seconds, outer_remaining)
    try:
        if input_data is not None:
            _require(len(input_data) <= MAX_GIT_OUTPUT, "RUN_INPUT_BOUND")
            input_stream = tempfile.TemporaryFile()
            input_stream.write(input_data)
            input_stream.seek(0)
        process = subprocess.Popen(
            list(command),
            cwd=repo,
            env=_environment(repo),
            stdin=input_stream if input_stream is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as error:
        if input_stream is not None:
            input_stream.close()
        raise VerificationError("RUN_EXECUTION") from error
    assert process.stdout is not None and process.stderr is not None
    selector = selectors.DefaultSelector()
    stdout = bytearray()
    stderr = bytearray()
    try:
        selector.register(process.stdout, selectors.EVENT_READ, stdout)
        selector.register(process.stderr, selectors.EVENT_READ, stderr)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            _require(remaining > 0, "RUN_TIMEOUT")
            events = selector.select(remaining)
            for key, _mask in events:
                chunk = os.read(key.fd, 64 * 1024)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                target: bytearray = key.data
                _require(len(target) <= maximum - len(chunk), "RUN_OUTPUT_BOUND")
                target.extend(chunk)
        remaining = deadline - time.monotonic()
        _require(remaining > 0, "RUN_TIMEOUT")
        try:
            return_code = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired as error:
            raise VerificationError("RUN_TIMEOUT") from error
    except BaseException:
        if process.poll() is None:
            process.kill()
            process.wait()
        raise
    finally:
        selector.close()
        process.stdout.close()
        process.stderr.close()
        if input_stream is not None:
            input_stream.close()
    _require(return_code == 0, "RUN_FAILED")
    return bytes(stdout), bytes(stderr)


def _git(
    repo: Path,
    arguments: Sequence[str],
    *,
    input_data: bytes | None = None,
    maximum: int = MAX_GIT_OUTPUT,
) -> bytes:
    stdout, stderr = _run(
        [
            GIT_EXECUTABLE,
            *GIT_GLOBAL_OPTIONS,
            "-C",
            os.fspath(repo),
            *arguments,
        ],
        repo=repo,
        input_data=input_data,
        maximum=maximum,
    )
    _require(not stderr, "GIT_STDERR")
    return stdout


def _tree(repo: Path, commit: str) -> tuple[str, dict[str, dict[str, Any]]]:
    _hex(commit, HEX40, "TREE_COMMIT")
    raw_tree = _git(
        repo,
        ["rev-parse", "--verify", "--end-of-options", f"{commit}^{{tree}}"],
        maximum=128,
    )
    try:
        tree_id = raw_tree.decode("ascii", "strict").strip()
    except UnicodeDecodeError as error:
        raise VerificationError("TREE_ID") from error
    _hex(tree_id, HEX40, "TREE_ID")
    raw = _git(
        repo,
        ["ls-tree", "-lrz", "--full-tree", "--end-of-options", commit],
        maximum=MAX_TREE_OUTPUT,
    )
    _require(not raw or raw.endswith(b"\0"), "TREE_UNTERMINATED")
    entries: dict[str, dict[str, Any]] = {}
    total = 0
    for record in raw[:-1].split(b"\0") if raw else ():
        try:
            metadata, raw_path = record.split(b"\t", 1)
            mode_raw, kind_raw, oid_raw, size_raw = metadata.split()
            path = _canonical_path(raw_path.decode("utf-8", "strict"))
            mode = mode_raw.decode("ascii", "strict")
            kind = kind_raw.decode("ascii", "strict")
            oid = oid_raw.decode("ascii", "strict")
            size = int(size_raw.decode("ascii", "strict"))
        except (UnicodeDecodeError, ValueError) as error:
            raise VerificationError("TREE_ENTRY") from error
        _require(path not in entries, "TREE_DUPLICATE")
        _require(mode in {"100644", "100755"} and kind == "blob", "TREE_TYPE")
        _hex(oid, HEX40, "TREE_OBJECT")
        _require(0 <= size <= MAX_BLOB_BYTES, "TREE_BLOB_BOUND")
        total += size
        _require(total <= MAX_TREE_BYTES, "TREE_TOTAL_BOUND")
        entries[path] = {"mode": mode, "type": kind, "oid": oid, "size": size}
    _canonical_order(entries, "TREE_ORDER")
    return tree_id, entries


def _selected_tree_entries(
    repo: Path, commit: str, paths: Iterable[str]
) -> dict[str, dict[str, Any]]:
    selected = sorted({_canonical_path(path) for path in paths})
    raw = _git(
        repo,
        ["ls-tree", "-lz", "--end-of-options", commit, "--", *selected],
        maximum=MAX_TREE_OUTPUT,
    )
    _require(not raw or raw.endswith(b"\0"), "SELECTED_TREE_UNTERMINATED")
    entries: dict[str, dict[str, Any]] = {}
    for record in raw[:-1].split(b"\0") if raw else ():
        try:
            metadata, raw_path = record.split(b"\t", 1)
            mode_raw, kind_raw, oid_raw, size_raw = metadata.split()
            path = _canonical_path(raw_path.decode("utf-8", "strict"))
            mode = mode_raw.decode("ascii", "strict")
            kind = kind_raw.decode("ascii", "strict")
            oid = oid_raw.decode("ascii", "strict")
            size = int(size_raw.decode("ascii", "strict"))
        except (UnicodeDecodeError, ValueError) as error:
            raise VerificationError("SELECTED_TREE_ENTRY") from error
        _require(path in selected and path not in entries, "SELECTED_TREE_PATH")
        _require(mode in {"100644", "100755"} and kind == "blob", "SELECTED_TREE_TYPE")
        _hex(oid, HEX40, "SELECTED_TREE_OBJECT")
        _require(0 <= size <= MAX_BLOB_BYTES, "SELECTED_TREE_BOUND")
        entries[path] = {"mode": mode, "type": kind, "oid": oid, "size": size}
    return entries


def _blobs(repo: Path, object_ids: Iterable[str]) -> dict[str, bytes]:
    identifiers = sorted(set(object_ids))
    _require(
        bool(identifiers) and all(HEX40.fullmatch(item) for item in identifiers),
        "BLOB_IDS",
    )
    raw = _git(
        repo,
        ["cat-file", "--batch"],
        input_data=("\n".join(identifiers) + "\n").encode("ascii"),
        maximum=MAX_GIT_OUTPUT,
    )
    cursor = 0
    result: dict[str, bytes] = {}
    for expected in identifiers:
        end = raw.find(b"\n", cursor)
        _require(end >= 0, "BLOB_HEADER")
        try:
            oid, kind, size_text = raw[cursor:end].decode("ascii", "strict").split()
            size = int(size_text)
        except (UnicodeDecodeError, ValueError) as error:
            raise VerificationError("BLOB_HEADER") from error
        _require(
            oid == expected and kind == "blob" and 0 <= size <= MAX_BLOB_BYTES,
            "BLOB_HEADER",
        )
        start = end + 1
        finish = start + size
        _require(finish < len(raw) and raw[finish : finish + 1] == b"\n", "BLOB_BODY")
        payload = raw[start:finish]
        _require(_git_blob_id(payload) == oid, "BLOB_IDENTITY")
        result[oid] = payload
        cursor = finish + 1
    _require(cursor == len(raw), "BLOB_TRAILING")
    return result


def _commit_parents(repo: Path, commits: Sequence[str]) -> dict[str, str]:
    _require(
        bool(commits) and all(HEX40.fullmatch(item) for item in commits),
        "PARENT_ARGUMENT",
    )
    raw = _git(
        repo,
        ["rev-list", "--parents", "--no-walk", "--end-of-options", *commits],
        maximum=4096,
    )
    try:
        lines = raw.decode("ascii", "strict").splitlines()
    except UnicodeDecodeError as error:
        raise VerificationError("PARENT_ENCODING") from error
    result: dict[str, str] = {}
    for line in lines:
        fields = line.split()
        _require(
            len(fields) == 2 and all(HEX40.fullmatch(item) for item in fields),
            "PARENT_SHAPE",
        )
        _require(fields[0] not in result, "PARENT_DUPLICATE")
        result[fields[0]] = fields[1]
    _require(set(result) == set(commits), "PARENT_MISSING")
    return result


def _commit_subject(repo: Path, commit: str) -> str:
    _hex(commit, HEX40, "COMMIT_SUBJECT_ARGUMENT")
    raw = _git(
        repo,
        ["show", "-s", "--format=%s", "--end-of-options", commit],
        maximum=1024,
    )
    _require(raw.endswith(b"\n") and raw.count(b"\n") == 1, "COMMIT_SUBJECT")
    try:
        subject = raw[:-1].decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        raise VerificationError("COMMIT_SUBJECT") from error
    return _text(subject, "COMMIT_SUBJECT", maximum=512)


def _first_parent(repo: Path, commit: str) -> list[str]:
    raw = _git(
        repo,
        [
            "rev-list",
            "--first-parent",
            f"--max-count={MAX_FIRST_PARENT_COMMITS + 1}",
            "--end-of-options",
            commit,
        ],
        maximum=(MAX_FIRST_PARENT_COMMITS + 1) * 41,
    )
    try:
        values = raw.decode("ascii", "strict").splitlines()
    except UnicodeDecodeError as error:
        raise VerificationError("HISTORY_ENCODING") from error
    _require(
        bool(values) and all(HEX40.fullmatch(item) for item in values), "HISTORY_SHAPE"
    )
    _require(len(values) <= MAX_FIRST_PARENT_COMMITS, "HISTORY_LIMIT")
    return values


def _diff(repo: Path, parent: str, child: str) -> dict[str, str]:
    raw = _git(
        repo,
        [
            "diff-tree",
            "--no-commit-id",
            "--name-status",
            "-r",
            "-z",
            "--no-renames",
            parent,
            child,
        ],
        maximum=MAX_TREE_OUTPUT,
    )
    _require(not raw or raw.endswith(b"\0"), "DIFF_UNTERMINATED")
    fields = raw[:-1].split(b"\0") if raw else []
    _require(len(fields) % 2 == 0, "DIFF_SHAPE")
    result: dict[str, str] = {}
    for index in range(0, len(fields), 2):
        try:
            status = fields[index].decode("ascii", "strict")
            path = _canonical_path(fields[index + 1].decode("utf-8", "strict"))
        except UnicodeDecodeError as error:
            raise VerificationError("DIFF_ENCODING") from error
        _require(status in {"A", "D", "M", "T"} and path not in result, "DIFF_STATUS")
        result[path] = status
    return dict(sorted(result.items()))


def _file_record(path: str, entry: Mapping[str, Any], payload: bytes) -> dict[str, Any]:
    record: dict[str, Any] = {
        "path": _canonical_path(path),
        "sha256": _sha256(payload),
        "bytes": len(payload),
        "git_mode": entry["mode"],
        "git_object_type": entry["type"],
        "git_object_id": entry["oid"],
    }
    if b"\0" not in payload:
        try:
            payload.decode("utf-8", "strict")
        except UnicodeDecodeError:
            pass
        else:
            record["lines"] = _line_count(payload)
    return record


def _central_file_record(
    path: str, entry: Mapping[str, Any], payload: bytes
) -> dict[str, Any]:
    record = _file_record(path, entry, payload)
    if not path.endswith((".json", ".py", ".sh", ".yml", ".md")) and path != "justfile":
        record.pop("lines", None)
    return record


def _parse_ledger(payload: bytes) -> list[dict[str, str]]:
    _require(0 < len(payload) <= MAX_LEDGER_BYTES, "LEDGER_BOUND")
    _require(
        payload.endswith(b"\n") and b"\r" not in payload and b"\0" not in payload,
        "LEDGER_ENCODING",
    )
    try:
        text = payload.decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        raise VerificationError("LEDGER_ENCODING") from error
    old_limit = csv.field_size_limit()
    try:
        csv.field_size_limit(MAX_CELL_BYTES)
        records = list(csv.reader(io.StringIO(text, newline=""), strict=True))
    except (csv.Error, OverflowError) as error:
        raise VerificationError("LEDGER_CSV") from error
    finally:
        csv.field_size_limit(old_limit)
    _require(len(records) == EXPECTED_LEDGER_ROWS + 1, "LEDGER_ROWS")
    _require(records and tuple(records[0]) == FIELDS, "LEDGER_HEADER")
    _require(all(len(record) == len(FIELDS) for record in records[1:]), "LEDGER_WIDTH")
    rows = [dict(zip(FIELDS, record, strict=True)) for record in records[1:]]
    paths: list[str] = []
    for row_index, row in enumerate(rows, 2):
        for field, value in row.items():
            encoded = value.encode("utf-8", "strict")
            _require(
                len(encoded) <= MAX_CELL_BYTES, f"LEDGER_CELL_BOUND:{row_index}:{field}"
            )
            _require(
                unicodedata.normalize("NFC", value) == value,
                f"LEDGER_CELL_NFC:{row_index}:{field}",
            )
            _require(
                not any(unicodedata.category(char).startswith("C") for char in value),
                f"LEDGER_CELL_CONTROL:{row_index}:{field}",
            )
        paths.append(_canonical_path(row["path"]))
    _canonical_order(paths, "LEDGER_PATH_ORDER")
    rendered = io.StringIO(newline="")
    csv.writer(rendered, lineterminator="\n", quoting=csv.QUOTE_MINIMAL).writerows(
        records
    )
    _require(rendered.getvalue().encode("utf-8") == payload, "LEDGER_NOT_CANONICAL")
    return rows


def _reference_tokens(
    value: str, code: str, *, allow_none: bool = False
) -> tuple[str, ...]:
    _require(value == value.strip(), code)
    if not value:
        return ()
    if allow_none and value == "NONE":
        return (value,)
    _require(value[0] not in FORMULA_PREFIXES, code)
    tokens = tuple(value.split(";"))
    _require(
        all(
            token and token == token.strip() and SAFE_REFERENCE.fullmatch(token)
            for token in tokens
        )
        and len(tokens) == len(set(tokens))
        and list(tokens) == sorted(tokens),
        code,
    )
    return tokens


def _validate_completed_row(
    row: Mapping[str, str],
    *,
    base: Mapping[str, str],
    classification: Mapping[str, Any],
    ledger_paths: set[str],
    reviewer_principals: set[str],
) -> None:
    path = row["path"]
    _require(
        all(row[field] == base[field] for field in IMMUTABLE_FIELDS),
        "LEDGER_IMMUTABLE_DRIFT",
    )
    _require(
        all(row[field] in {"YES", "NO"} for field in TRISTATE_FIELDS),
        "LEDGER_UNRESOLVED_TRISTATE",
    )
    _require(row["reviewer"] in reviewer_principals, "LEDGER_REVIEWER")
    _require(row["review_status"] == "REVIEWED", "LEDGER_REVIEW_STATUS")
    _require(row["disposition"] == "ACCEPTED", "LEDGER_DISPOSITION")
    _timestamp(row["completed_at"], "LEDGER_COMPLETED_AT")
    _require(
        classification["path"] == path
        and all(
            row[field] == classification[field]
            for field in (
                "generated",
                "generator",
                *CRITICAL_FIELDS,
                "provenance_review_status",
                "license_review_status",
                "license_expression",
            )
        ),
        "LEDGER_CLASSIFICATION_CONTRACT",
    )
    if base["generated"] in {"YES", "NO"}:
        _require(
            (row["generated"], row["generator"])
            == (base["generated"], base["generator"]),
            "LEDGER_FROZEN_GENERATED_DRIFT",
        )
    else:
        _require(
            base["generated"] == "UNKNOWN" and base["generator"] == "",
            "LEDGER_BASE_GENERATED_STATE",
        )
    if row["generated"] == "YES":
        _require(
            bool(row["generator"])
            and (
                row["generator"] in ledger_paths
                or row["generator"] in ALLOWED_EXTERNAL_GENERATORS
            ),
            "LEDGER_GENERATOR",
        )
    else:
        _require(not row["generator"], "LEDGER_GENERATOR_CONTRADICTION")
    _require(bool(row["provenance_evidence"]), "LEDGER_PROVENANCE_EVIDENCE")
    if row["license_review_status"] == "APPROVED":
        _require(
            bool(row["license_evidence"]),
            "LEDGER_LICENSE_EVIDENCE",
        )
    else:
        _require(
            row["license_expression"] == "NOT_APPLICABLE"
            and not row["license_evidence"],
            "LEDGER_LICENSE_NA",
        )
    for field in REFERENCE_FIELDS:
        _reference_tokens(
            row[field],
            f"LEDGER_REFERENCE:{path}:{field}",
            allow_none=field == "defects",
        )
    critical = any(row[field] == "YES" for field in CRITICAL_FIELDS)
    if critical:
        _require(
            bool(row["requirements"] and row["tests"] and row["evidence"]),
            "LEDGER_CRITICAL_TRACEABILITY",
        )
    _require(
        row["language"] != "UNKNOWN" and row["format"] not in {"UNKNOWN", "ABSENT"},
        "LEDGER_CLASSIFICATION",
    )
    _require(
        not row["format"].startswith(
            ("ANSI_ESCAPE_WITH_", "BINARY_WITH_", "CONTROL_BEARING_", "TEXT_WITH_")
        ),
        "LEDGER_FORMAT_CONTRADICTION",
    )
    if path == LEDGER_PATH:
        _require(
            row["current_scope"] == "LEDGER_SELF"
            and row["format"] == "SELF_REFERENTIAL_CSV"
            and row["generated"] == "YES",
            "LEDGER_SELF",
        )


def validate_completed_ledger(
    base_payload: bytes,
    completed_payload: bytes,
    *,
    reviewer_principals: Iterable[str],
    classification_by_path: Mapping[str, Mapping[str, Any]],
) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    """Validate exact immutable retention and complete explicit review state."""

    _require(_sha256(base_payload) == CH_T001_LEDGER_SHA256, "BASE_LEDGER_SHA256")
    _require(
        _git_blob_id(base_payload) == CH_T001_LEDGER_OBJECT_ID, "BASE_LEDGER_OBJECT"
    )
    base_rows = _parse_ledger(base_payload)
    rows = _parse_ledger(completed_payload)
    _require(
        [row["path"] for row in rows] == [row["path"] for row in base_rows],
        "LEDGER_PATH_DRIFT",
    )
    principals = set(reviewer_principals)
    _require(
        len(principals) == 3
        and all(_text(item, "REVIEWER_PRINCIPAL", maximum=254) for item in principals),
        "REVIEWER_PRINCIPALS",
    )
    ledger_paths = {row["path"] for row in rows}
    _require(
        ledger_paths.issubset(classification_by_path),
        "LEDGER_CLASSIFICATION_COVERAGE",
    )
    for base, row in zip(base_rows, rows, strict=True):
        _validate_completed_row(
            row,
            base=base,
            classification=classification_by_path[row["path"]],
            ledger_paths=ledger_paths,
            reviewer_principals=principals,
        )
    _require(
        Counter(row["reviewer"] for row in rows).keys() == principals,
        "LEDGER_EMPTY_LANE",
    )
    return base_rows, rows


def _require_exact_requirements(
    value: object,
    specs: Sequence[tuple[str, str, str]],
    paths: Mapping[str, str],
    code: str,
) -> list[dict[str, Any]]:
    _require(isinstance(value, list) and len(value) == len(specs), code)
    result: list[dict[str, Any]] = []
    for observed, (identifier, kind, _name) in zip(value, specs, strict=True):
        record = _exact_keys(observed, {"id", "kind", "path", "max_bytes"}, code)
        maximum = _integer(record["max_bytes"], code, minimum=1)
        bound = (
            MAX_PACKET_BYTES
            if kind != "FULL_LOCKED_CI_LOG_ARCHIVE"
            else 2 * 1024 * 1024
        )
        _require(
            record["id"] == identifier
            and record["kind"] == kind
            and record["path"] == paths[identifier]
            and maximum == bound,
            code,
        )
        result.append(record)
    return result


def _validate_freeze(
    freeze: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    _require(tuple(freeze) == FREEZE_KEYS, "FREEZE_KEYS")
    _require(
        freeze.get("schema_version") == "1.0.0"
        and freeze.get("task_id") == TASK_ID
        and freeze.get("epoch") == EPOCH
        and freeze.get("release_target") == RELEASE_TARGET
        and _strict_equal(freeze.get("author"), AUTHOR)
        and freeze.get("persistent_identifier") is PERSISTENT_IDENTIFIER,
        "FREEZE_IDENTITY",
    )
    _require(
        freeze.get("effective_on")
        == "SIGNED_COMMIT_FIRST_CONTAINING_EXACT_FREEZE_AND_REGISTRATION",
        "FREEZE_EFFECTIVE_ON",
    )
    task_identity = freeze.get("task_identity")
    _require(
        _strict_equal(task_identity, EXPECTED_TASK_IDENTITY),
        "FREEZE_TASK_IDENTITY",
    )
    handoff = freeze.get("handoff_task_contract")
    _require(
        isinstance(handoff, dict)
        and handoff.get("source_task_id") == "T002"
        and handoff.get("lead_review_required") is True
        and isinstance(handoff.get("preconditions"), list)
        and bool(handoff["preconditions"])
        and isinstance(handoff.get("procedure"), list)
        and bool(handoff["procedure"])
        and isinstance(handoff.get("mandatory_counterfactuals"), list)
        and handoff["mandatory_counterfactuals"]
        == [binding[0] for binding in COUNTERFACTUAL_BINDINGS]
        and isinstance(handoff.get("required_evidence"), list)
        and bool(handoff["required_evidence"])
        and isinstance(handoff.get("completion_rule"), str)
        and isinstance(handoff.get("twenty_lenses"), list)
        and len(handoff["twenty_lenses"]) == 20,
        "FREEZE_HANDOFF_CONTRACT",
    )
    _hex(
        task_identity.get("source_record_sha256"),
        HEX64,
        "FREEZE_SOURCE_RECORD_SHA256",
    )
    _require(
        handoff.get("source_record_sha256")
        == task_identity.get("source_record_sha256"),
        "FREEZE_SOURCE_RECORD_BINDING",
    )
    prior_state = freeze.get("prior_state")
    _require(
        isinstance(prior_state, dict)
        and prior_state.get("verified_prefix") == 2
        and isinstance(prior_state.get("active_claims"), dict),
        "FREEZE_PRIOR_STATE",
    )
    _require(
        _strict_equal(freeze.get("implementation_plan"), EXPECTED_I_DIFF),
        "FREEZE_IMPLEMENTATION_PLAN",
    )
    _require(
        _strict_equal(
            freeze.get("verification_triggers"),
            {"paths": list(EXPECTED_I_DIFF), "roots": []},
        ),
        "FREEZE_TRIGGERS",
    )
    _require(freeze.get("empty_implementation_reason") is None, "FREEZE_NOT_EMPTY")
    controls = freeze.get("normative_controls")
    _require(isinstance(controls, list) and len(controls) == 20, "FREEZE_CONTROLS")
    accepted_tests: list[str] = []
    rejected_tests: list[str] = []
    for index, (control, binding) in enumerate(
        zip(controls, NORMATIVE_CONTROL_BINDINGS, strict=True), 1
    ):
        control = _exact_keys(
            control,
            {"id", "statement", "accepted_test_id", "rejected_test_id"},
            "FREEZE_CONTROL_KEYS",
        )
        statement, accepted_test, rejected_test, _predicate, _failure = binding
        _require(
            control["id"] == f"CH-T002-N{index:02d}"
            and control["statement"] == statement
            and control["accepted_test_id"] == accepted_test
            and control["rejected_test_id"] == rejected_test,
            "FREEZE_CONTROL_BINDING",
        )
        _text(control["statement"], "FREEZE_CONTROL_STATEMENT", maximum=8192)
        accepted_tests.append(
            _text(control["accepted_test_id"], "FREEZE_ACCEPTED_TEST", maximum=256)
        )
        rejected_tests.append(
            _text(control["rejected_test_id"], "FREEZE_REJECTED_TEST", maximum=256)
        )
    _require(
        len(set(accepted_tests + rejected_tests)) == 40
        and all(item.startswith("test_") for item in accepted_tests + rejected_tests),
        "FREEZE_CONTROL_TESTS",
    )
    counterfactuals = freeze.get("mandatory_counterfactuals")
    _require(
        isinstance(counterfactuals, list) and len(counterfactuals) == 10,
        "FREEZE_COUNTERFACTUALS",
    )
    counterfactual_tests: list[str] = []
    for index, (counterfactual, binding) in enumerate(
        zip(counterfactuals, COUNTERFACTUAL_BINDINGS, strict=True), 1
    ):
        counterfactual = _exact_keys(
            counterfactual,
            {"id", "statement", "accepted_test_id", "rejected_test_id"},
            "FREEZE_COUNTERFACTUAL_KEYS",
        )
        statement, accepted_test, rejected_test, _predicate, _failure = binding
        _require(
            counterfactual["id"] == f"CH-T002-CF{index:02d}"
            and counterfactual["statement"] == statement
            and counterfactual["accepted_test_id"] == accepted_test
            and counterfactual["rejected_test_id"] == rejected_test,
            "FREEZE_COUNTERFACTUAL_BINDING",
        )
        counterfactual_tests.extend(
            [
                counterfactual["accepted_test_id"],
                counterfactual["rejected_test_id"],
            ]
        )
        _text(counterfactual["statement"], "FREEZE_COUNTERFACTUAL_TEXT", maximum=8192)
    _require(
        len(counterfactual_tests) == len(set(counterfactual_tests)),
        "FREEZE_COUNTERFACTUAL_TESTS",
    )
    lead_approval = _exact_keys(
        freeze.get("lead_approval"),
        {"kind", "human", "external_authority", "freeze_packet_sha256", "effective_on"},
        "FREEZE_LEAD_APPROVAL_KEYS",
    )
    _require(
        lead_approval["kind"] == "AUTOMATED_NON_HUMAN_LEAD_SUPPORT"
        and lead_approval["human"] is False
        and lead_approval["external_authority"] is False
        and lead_approval["effective_on"]
        == "SIGNED_F_COMMIT_CONTAINING_EXACT_PREIMPLEMENTATION_PACKET",
        "FREEZE_LEAD_APPROVAL",
    )
    _hex(lead_approval["freeze_packet_sha256"], HEX64, "FREEZE_PACKET_SHA256")
    lenses = freeze.get("lens_questions")
    _require(
        isinstance(lenses, list)
        and len(lenses) == 20
        and [item.get("id") for item in lenses]
        == [f"L{index:02d}" for index in range(1, 21)]
        and _strict_equal(lenses, handoff["twenty_lenses"]),
        "FREEZE_LENSES",
    )
    for key in (
        "combined_attack_matrix",
        "threat_model",
        "misuse_resistant_interfaces",
    ):
        _require(
            isinstance(freeze.get(key), list) and bool(freeze[key]),
            f"FREEZE_{key.upper()}",
        )
    forbidden_sentinels = {"TODO", "TBD", "PLACEHOLDER", "UNRESOLVED"}
    _require(
        all(
            value not in forbidden_sentinels and not value.startswith("UNRESOLVED_")
            for value in _recursive_strings(freeze)
        ),
        "FREEZE_UNRESOLVED_SENTINEL",
    )
    inventory = freeze.get("affected_surface_inventory")
    _require(
        isinstance(inventory, list)
        and all(isinstance(item, dict) for item in inventory)
        and [item.get("path") for item in inventory] == list(EXPECTED_I_DIFF),
        "FREEZE_AFFECTED_SURFACE",
    )
    for item, (path, status) in zip(inventory, EXPECTED_I_DIFF.items(), strict=True):
        _require(
            item.get("path") == path and item.get("planned_status") == status,
            "FREEZE_AFFECTED_SURFACE",
        )
    _require(
        freeze.get("qualification_path") == QUALIFICATION_PATH,
        "FREEZE_QUALIFICATION_PATH",
    )
    _require(freeze.get("activation_path") == ACTIVATION_PATH, "FREEZE_ACTIVATION_PATH")
    _require(freeze.get("verifier_receipt_path") == RECEIPT_PATH, "FREEZE_RECEIPT_PATH")
    evidence = _require_exact_requirements(
        freeze.get("qualification_evidence_requirements"),
        EVIDENCE_SPECS,
        EVIDENCE_PATHS,
        "FREEZE_EVIDENCE_REQUIREMENTS",
    )
    reviews = _require_exact_requirements(
        freeze.get("review_requirements"),
        REVIEW_SPECS,
        REVIEW_PATHS,
        "FREEZE_REVIEW_REQUIREMENTS",
    )
    activation = _require_exact_requirements(
        freeze.get("activation_evidence_requirements"),
        ACTIVATION_SPECS,
        ACTIVATION_PATHS,
        "FREEZE_ACTIVATION_REQUIREMENTS",
    )
    registry = freeze.get("reviewer_registry")
    _require(
        isinstance(registry, list) and len(registry) == len(REVIEW_SPECS),
        "FREEZE_REVIEWER_REGISTRY",
    )
    principals: set[str] = set()
    keys: set[str] = set()
    fingerprints: set[str] = set()
    for index, (entry, requirement) in enumerate(zip(registry, reviews, strict=True)):
        entry = _exact_keys(
            entry,
            {
                "requirement_id",
                "kind",
                "path",
                "reviewer",
                "public_key",
                "key_fingerprint",
                "trust_basis",
            },
            "FREEZE_REVIEWER_REGISTRY_ENTRY",
        )
        reviewer = _exact_keys(
            entry["reviewer"],
            {"name", "principal", "classification", "organization"},
            "FREEZE_REVIEWER",
        )
        for field in ("name", "principal", "classification", "organization"):
            _text(reviewer[field], "FREEZE_REVIEWER_TEXT", maximum=254)
        _require(
            re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.@+-]{0,254}", reviewer["principal"])
            is not None,
            "FREEZE_REVIEWER_PRINCIPAL",
        )
        public_key = _text(entry["public_key"], "FREEZE_REVIEWER_KEY", maximum=1024)
        fingerprint = _text(
            entry["key_fingerprint"], "FREEZE_REVIEWER_FINGERPRINT", maximum=128
        )
        _require(
            re.fullmatch(r"ssh-ed25519 [A-Za-z0-9+/]+={0,2}", public_key) is not None,
            "FREEZE_REVIEWER_KEY",
        )
        _require(
            re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}", fingerprint) is not None,
            "FREEZE_REVIEWER_FINGERPRINT",
        )
        _require(
            _public_key_fingerprint(public_key) == fingerprint,
            "FREEZE_REVIEWER_FINGERPRINT",
        )
        expected_classification = (
            "INDEPENDENT_AUTOMATED" if index < 3 else "AUTOMATED_LEAD_SUPPORT"
        )
        _require(
            entry["requirement_id"] == requirement["id"]
            and entry["kind"] == requirement["kind"]
            and entry["path"] == requirement["path"]
            and entry["trust_basis"] == "SOURCE_SIGNER_ASSERTED_KEY_FROZEN_IN_SIGNED_F"
            and reviewer["classification"] == expected_classification
            and reviewer["name"] != AUTHOR["name"]
            and reviewer["principal"] != AUTHOR["email"],
            "FREEZE_REVIEWER_BINDING",
        )
        principals.add(reviewer["principal"])
        keys.add(public_key)
        fingerprints.add(fingerprint)
    _require(
        len(principals) == 4 and len(keys) == 4 and len(fingerprints) == 4,
        "FREEZE_REVIEWER_SEPARATION",
    )
    budgets = freeze.get("resource_budgets")
    _require(
        _strict_equal(
            budgets,
            {
                "json_bytes": 256 * 1024,
                "decompressed_evidence_bytes": 4 * 1024 * 1024,
                "protocol_path_bytes": 240,
                "verifier_output_bytes_per_stream": 64 * 1024,
                "verifier_seconds": 10,
            },
        ),
        "FREEZE_VERIFIER_BUDGET",
    )
    outcomes = freeze.get("claim_outcomes")
    _require(isinstance(outcomes, list) and len(outcomes) == 1, "FREEZE_OUTCOMES")
    outcome = _exact_keys(
        outcomes[0],
        {
            "id",
            "claim_disposition",
            "overall_status",
            "active_claims",
            "release_qualified_claims",
            "removed_claims",
            "non_claimed_claims",
            "narrowed_claims",
            "limitations",
            "public_surfaces",
            "migration",
            "rollback",
        },
        "FREEZE_OUTCOME_KEYS",
    )
    claim_lists = {
        field: _sorted_text_list(outcome[field], "FREEZE_OUTCOME_BOUNDARY")
        for field in (
            "active_claims",
            "release_qualified_claims",
            "removed_claims",
            "non_claimed_claims",
            "narrowed_claims",
        )
    }
    limitations = _sorted_text_list(
        outcome["limitations"], "FREEZE_OUTCOME_BOUNDARY", nonempty=True
    )
    migration = _exact_keys(
        outcome["migration"],
        {"required", "paths", "disposition"},
        "FREEZE_OUTCOME_MIGRATION",
    )
    _require(
        outcome["id"] == "CH-T002-O01-NO-PUBLIC-CLAIM-CHANGE"
        and outcome["overall_status"] == "NO_GO"
        and outcome["claim_disposition"] == "NO_PUBLIC_CLAIM_CHANGE"
        and HUMAN_REVIEW_LIMITATION in limitations
        and all(isinstance(values, list) for values in claim_lists.values())
        and _sorted_text_list(
            outcome["public_surfaces"], "FREEZE_OUTCOME_BOUNDARY", paths=True
        )
        == []
        and migration["required"] is True
        and migration["paths"] == sorted(EXPECTED_I_DIFF)
        and isinstance(migration["disposition"], str)
        and bool(migration["disposition"])
        and _strict_equal(
            outcome["rollback"],
            {
                "strategy": "RESTORE_EXACT_PRIOR_ACTIVATED_TREE_ENTRIES",
                "paths": sorted(EXPECTED_I_DIFF),
                "verification": "GIT_MODE_TYPE_AND_OBJECT_IDENTITY",
            },
        ),
        "FREEZE_OUTCOME_BOUNDARY",
    )
    return evidence, reviews, activation


def _reviewer_maps(
    freeze: Mapping[str, Any],
) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    by_requirement: dict[str, dict[str, Any]] = {}
    by_fingerprint: dict[str, dict[str, Any]] = {}
    for entry in freeze["reviewer_registry"]:
        by_requirement[entry["requirement_id"]] = entry
        by_fingerprint[entry["key_fingerprint"]] = entry
    return by_requirement, by_fingerprint


def _validate_registration(
    registry: dict[str, Any],
    base_registry: dict[str, Any],
    *,
    f_entries: Mapping[str, Mapping[str, Any]],
    f_blobs: Mapping[str, bytes],
) -> None:
    registrations = registry.get("registrations")
    base_registrations = base_registry.get("registrations")
    _require(
        set(registry) == set(base_registry)
        and all(
            _strict_equal(registry[key], base_registry[key])
            for key in registry
            if key != "registrations"
        ),
        "REGISTRATION_METADATA_DRIFT",
    )
    _require(
        isinstance(registrations, list)
        and isinstance(base_registrations, list)
        and _strict_equal(registrations[:-1], base_registrations)
        and len(registrations) == len(base_registrations) + 1,
        "REGISTRATION_HISTORY",
    )
    expected = {
        "task_id": TASK_ID,
        "epoch": EPOCH,
        "verifier": _file_record(
            VERIFIER_PATH,
            f_entries[VERIFIER_PATH],
            f_blobs[f_entries[VERIFIER_PATH]["oid"]],
        ),
        "tests": _file_record(
            REGISTERED_TESTS_PATH,
            f_entries[REGISTERED_TESTS_PATH],
            f_blobs[f_entries[REGISTERED_TESTS_PATH]["oid"]],
        ),
        "freeze_contract": _file_record(
            FREEZE_PATH, f_entries[FREEZE_PATH], f_blobs[f_entries[FREEZE_PATH]["oid"]]
        ),
        "qualification_path": QUALIFICATION_PATH,
        "activation_path": ACTIVATION_PATH,
        "verifier_receipt_path": RECEIPT_PATH,
        "effective_on": "SIGNED_COMMIT_FIRST_CONTAINING_EXACT_REGISTRATION_FREEZE_AND_GATES",
    }
    _require(_strict_equal(registrations[-1], expected), "REGISTRATION_BINDING")


def _recursive_strings(value: object) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        for item in value:
            yield from _recursive_strings(item)
    elif isinstance(value, dict):
        for key, item in value.items():
            yield key
            yield from _recursive_strings(item)


def _subject_id(identity: Mapping[str, Any]) -> str:
    selected = {
        key: identity[key]
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
    return _domain_digest("haldir-ch-t002-review-subject-v1", selected)


def _domain_digest(domain: str, value: object) -> str:
    payload = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return _sha256(domain.encode("ascii") + b"\0" + payload)


def _classification_criticality(record: Mapping[str, Any]) -> list[str]:
    return [
        name
        for field, name in zip(CRITICAL_FIELDS, CRITICALITY_ORDER, strict=True)
        if record[field] == "YES"
    ]


def _mandatory_criticality_floor(path: str) -> frozenset[str]:
    required: set[str] = set()
    parts = PurePosixPath(path).parts
    if path.startswith("release/0.9.0/current-head/"):
        required.add("AUTHORITY_CRITICAL")
    if path.startswith("tools/release/") or path == REGISTRY_PATH:
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


def _classification_values_equal(
    left: Mapping[str, Any], right: Mapping[str, Any]
) -> bool:
    return all(
        key in right and _strict_equal(left[key], right[key])
        for key in CLASSIFICATION_RECORD_KEYS
    )


def _validate_classification_record(record: object) -> dict[str, Any]:
    _require(
        isinstance(record, dict) and tuple(record) == CLASSIFICATION_RECORD_KEYS,
        "CLASSIFICATION_RECORD_KEYS",
    )
    path = _canonical_path(record["path"])
    for field in (*CRITICAL_FIELDS, "generated"):
        _require(record[field] in {"YES", "NO"}, f"CLASSIFICATION_FLAG:{path}")
    _require(
        _mandatory_criticality_floor(path).issubset(_classification_criticality(record))
        or record["source_basis"] == CLASSIFICATION_OVERRIDE_SOURCE_BASIS,
        f"CLASSIFICATION_MANDATORY_FLOOR:{path}",
    )
    if record["generated"] == "YES":
        _require(bool(record["generator"]), f"CLASSIFICATION_GENERATOR:{path}")
    else:
        _require(record["generator"] == "", f"CLASSIFICATION_GENERATOR:{path}")
    _require(
        record["provenance_review_status"] == "CONFIRMED",
        f"CLASSIFICATION_PROVENANCE:{path}",
    )
    license_status = record["license_review_status"]
    _require(
        license_status in {"APPROVED", "NOT_APPLICABLE"},
        f"CLASSIFICATION_LICENSE:{path}",
    )
    _require(
        (
            license_status == "APPROVED"
            and record["license_expression"] in ALLOWED_SPDX_EXPRESSIONS
        )
        or (
            license_status == "NOT_APPLICABLE"
            and record["license_expression"] == "NOT_APPLICABLE"
        ),
        f"CLASSIFICATION_LICENSE_EXPRESSION:{path}",
    )
    rules = record["rule_ids"]
    prefixes = ("PUB_", "SEC_", "SCI_", "AUTH_", "GEN_", "LIC_")
    _require(
        isinstance(rules, list)
        and len(rules) == len(prefixes)
        and len(rules) == len(set(rules))
        and all(
            isinstance(rule, str)
            and rule.startswith(prefix)
            and re.fullmatch(r"[A-Z][A-Za-z0-9_]{1,255}", rule) is not None
            for rule, prefix in zip(rules, prefixes, strict=True)
        ),
        f"CLASSIFICATION_RULES:{path}",
    )
    expected_yes = (
        (record["public_surface"], rules[0], "PUB_"),
        (record["security_critical"], rules[1], "SEC_"),
        (record["science_critical"], rules[2], "SCI_"),
        (record["authority_critical"], rules[3], "AUTH_"),
        (record["generated"], rules[4], "GEN_"),
    )
    _require(
        all(
            rule.startswith(prefix + ("YES_" if flag == "YES" else "NO_"))
            for flag, rule, prefix in expected_yes
        ),
        f"CLASSIFICATION_RULE_FLAG:{path}",
    )
    _require(
        record["source_basis"]
        in {
            CURRENT_A_SOURCE_BASIS,
            CLASSIFICATION_OVERRIDE_SOURCE_BASIS,
            F_EXTENSION_SOURCE_BASIS,
        },
        f"CLASSIFICATION_SOURCE:{path}",
    )
    return record


def _classification_counts(records: Iterable[Mapping[str, Any]]) -> dict[str, int]:
    values = tuple(records)
    return {
        "authority_critical_no": sum(x["authority_critical"] == "NO" for x in values),
        "authority_critical_yes": sum(x["authority_critical"] == "YES" for x in values),
        "generated_no": sum(x["generated"] == "NO" for x in values),
        "generated_yes": sum(x["generated"] == "YES" for x in values),
        "license_review_status_approved": sum(
            x["license_review_status"] == "APPROVED" for x in values
        ),
        "license_review_status_not_applicable": sum(
            x["license_review_status"] == "NOT_APPLICABLE" for x in values
        ),
        "paths": len(values),
        "provenance_review_status_confirmed": sum(
            x["provenance_review_status"] == "CONFIRMED" for x in values
        ),
        "public_surface_no": sum(x["public_surface"] == "NO" for x in values),
        "public_surface_yes": sum(x["public_surface"] == "YES" for x in values),
        "science_critical_no": sum(x["science_critical"] == "NO" for x in values),
        "science_critical_yes": sum(x["science_critical"] == "YES" for x in values),
        "security_critical_no": sum(x["security_critical"] == "NO" for x in values),
        "security_critical_yes": sum(x["security_critical"] == "YES" for x in values),
    }


def _validate_classification_count_vector(
    value: object, population: int, code: str
) -> dict[str, int]:
    _require(
        isinstance(value, dict)
        and tuple(value) == CLASSIFICATION_COUNT_KEYS
        and all(type(item) is int and item >= 0 for item in value.values()),
        code,
    )
    _require(
        value["paths"] == population
        and value["provenance_review_status_confirmed"] == population
        and all(
            value[f"{field}_no"] + value[f"{field}_yes"] == population
            for field in (
                "authority_critical",
                "generated",
                "public_surface",
                "science_critical",
                "security_critical",
            )
        )
        and value["license_review_status_approved"]
        + value["license_review_status_not_applicable"]
        == population,
        code,
    )
    return value


def _validate_classification_contract(
    overlay: Mapping[str, Any],
    f_entries: Mapping[str, Mapping[str, Any]],
    historical_paths: Iterable[str],
) -> dict[str, dict[str, Any]]:
    contract = overlay["review_classification_contract"]
    _require(
        isinstance(contract, dict)
        and tuple(contract)
        == (
            "classification_set_sha256",
            "counts",
            "override_policy",
            "path_order",
            "records",
            "schema_id",
            "semantics",
            "source_audit",
        ),
        "CLASSIFICATION_CONTRACT_KEYS",
    )
    _require(
        contract["schema_id"] == CLASSIFICATION_CONTRACT_SCHEMA_ID
        and contract["path_order"] == PATH_ORDER,
        "CLASSIFICATION_CONTRACT_IDENTITY",
    )
    _require(
        _strict_equal(
            contract["source_audit"],
            {
                "current_a_commit": BASELINE_COMMIT,
                "current_a_tree": CURRENT_A_TREE,
                "schema_id": CLASSIFICATION_AUDIT_SCHEMA_ID,
                "sha256": CLASSIFICATION_AUDIT_SHA256,
            },
        ),
        "CLASSIFICATION_AUDIT_BINDING",
    )
    _require(
        _strict_equal(
            contract["semantics"],
            {
                "generated": (
                    "YES identifies production or capture by the named tracked "
                    "procedure; it does not assert byte-deterministic regeneration "
                    "of a historical run."
                ),
                "primary_capture": (
                    "The 12 retained live-campaign logs are generated captures and "
                    "primary runtime observations; exact Git identities preserve the "
                    "observed bytes, and their license review is NOT_APPLICABLE."
                ),
            },
        ),
        "CLASSIFICATION_SEMANTICS",
    )
    raw_records = contract["records"]
    _require(isinstance(raw_records, list), "CLASSIFICATION_RECORDS")
    records = [_validate_classification_record(record) for record in raw_records]
    paths = _canonical_order(
        [record["path"] for record in records], "CLASSIFICATION_PATH_ORDER"
    )
    extension_paths = set(EXPECTED_F_EXTENSION_CLASSIFICATIONS)
    current_paths = set(paths) - extension_paths
    _require(
        len(records) == len(f_entries) == AUDITED_CURRENT_A_PATHS + len(extension_paths)
        and set(paths) == set(f_entries)
        and extension_paths.issubset(paths)
        and len(current_paths) == AUDITED_CURRENT_A_PATHS,
        "CLASSIFICATION_F_TREE_COVERAGE",
    )
    by_path = {record["path"]: record for record in records}
    _require(
        all(
            _classification_values_equal(by_path[path], expected)
            for path, expected in EXPECTED_F_EXTENSION_CLASSIFICATIONS.items()
        ),
        "CLASSIFICATION_F_EXTENSION_DECISIONS",
    )
    _require(
        all(
            record["generator"] in by_path
            or record["generator"] in ALLOWED_EXTERNAL_GENERATORS
            for record in records
            if record["generated"] == "YES"
        ),
        "CLASSIFICATION_GENERATOR_RESOLUTION",
    )

    override = contract["override_policy"]
    _require(
        isinstance(override, dict)
        and tuple(override)
        == (
            "field_override_count",
            "order",
            "overrides",
            "path_count",
            "paths",
            "policy_id",
        )
        and override["policy_id"] == CLASSIFICATION_OVERRIDE_POLICY_ID
        and override["order"] == CLASSIFICATION_OVERRIDE_ORDER,
        "CLASSIFICATION_OVERRIDE_POLICY",
    )
    raw_overrides = override["overrides"]
    _require(isinstance(raw_overrides, list), "CLASSIFICATION_OVERRIDE_ROWS")
    rows: list[dict[str, str]] = []
    row_keys: list[tuple[str, str]] = []
    for raw in raw_overrides:
        _require(
            isinstance(raw, dict)
            and tuple(raw)
            == ("after", "before", "field", "path", "rule_id", "source_basis"),
            "CLASSIFICATION_OVERRIDE_ROW_KEYS",
        )
        path = _canonical_path(raw["path"])
        field = raw["field"]
        _require(
            isinstance(field, str)
            and field in CLASSIFICATION_OVERRIDE_FIELD_SPECS
            and isinstance(raw["before"], str)
            and isinstance(raw["after"], str)
            and raw["before"] != raw["after"]
            and raw["source_basis"] == CLASSIFICATION_OVERRIDE_SOURCE_BASIS,
            "CLASSIFICATION_OVERRIDE_ROW_VALUE",
        )
        index, prefix = CLASSIFICATION_OVERRIDE_FIELD_SPECS[field]
        if field == "generator":
            for value in (raw["before"], raw["after"]):
                if value and value not in ALLOWED_EXTERNAL_GENERATORS:
                    _canonical_path(value)
        else:
            _require(
                raw["before"] in {"YES", "NO"} and raw["after"] in {"YES", "NO"},
                "CLASSIFICATION_OVERRIDE_ROW_VALUE",
            )
        final = by_path.get(path)
        _require(
            path in current_paths
            and final is not None
            and final[field] == raw["after"]
            and final["source_basis"] == CLASSIFICATION_OVERRIDE_SOURCE_BASIS
            and final["rule_ids"][index] == raw["rule_id"]
            and isinstance(raw["rule_id"], str)
            and raw["rule_id"].startswith(prefix),
            "CLASSIFICATION_OVERRIDE_BINDING",
        )
        rows.append(raw)
        row_keys.append((path, field))
    _require(
        row_keys
        == sorted(
            row_keys, key=lambda item: (item[0].encode(), item[1].encode("ascii"))
        )
        and len(row_keys) == len(set(row_keys)),
        "CLASSIFICATION_OVERRIDE_ROW_ORDER",
    )
    override_paths = sorted(
        {path for path, _field in row_keys}, key=lambda x: x.encode()
    )
    _require(
        override["field_override_count"]
        == len(rows)
        == EXPECTED_CLASSIFICATION_OVERRIDE_FIELDS
        and override["path_count"]
        == len(override_paths)
        == EXPECTED_CLASSIFICATION_OVERRIDE_PATHS
        and override["paths"] == override_paths,
        "CLASSIFICATION_OVERRIDE_COUNTS",
    )
    _require(
        _domain_digest(CLASSIFICATION_OVERRIDE_DIGEST_DOMAIN, rows)
        == EXPECTED_CLASSIFICATION_OVERRIDE_SET_SHA256,
        "CLASSIFICATION_OVERRIDE_SET_DIGEST",
    )
    override_path_set = set(override_paths)
    _require(
        all(
            by_path[path]["source_basis"]
            == (
                CLASSIFICATION_OVERRIDE_SOURCE_BASIS
                if path in override_path_set
                else CURRENT_A_SOURCE_BASIS
            )
            for path in current_paths
        ),
        "CLASSIFICATION_OVERRIDE_SOURCE",
    )
    row_fields = {path: set() for path in override_paths}
    source_records = {path: copy.deepcopy(by_path[path]) for path in current_paths}
    for row in rows:
        row_fields[row["path"]].add(row["field"])
        source_records[row["path"]][row["field"]] = row["before"]
    _require(
        all(
            ({"generated", "generator"} & fields) in (set(), {"generated", "generator"})
            for fields in row_fields.values()
        ),
        "CLASSIFICATION_OVERRIDE_GENERATOR_ATOMIC",
    )
    for record in source_records.values():
        record["source_basis"] = CURRENT_A_SOURCE_BASIS
        _require(
            (record["generated"] == "NO" and record["generator"] == "")
            or (
                record["generated"] == "YES"
                and bool(record["generator"])
                and (
                    record["generator"] in current_paths
                    or record["generator"] in ALLOWED_EXTERNAL_GENERATORS
                )
            ),
            "CLASSIFICATION_OVERRIDE_GENERATOR_SOURCE",
        )

    historical_values = [_canonical_path(path) for path in historical_paths]
    historical = _canonical_order(
        sorted(historical_values, key=lambda x: x.encode()),
        "CLASSIFICATION_HISTORICAL_PATHS",
    )
    _require(
        len(historical) == EXPECTED_LEDGER_ROWS
        and set(historical).issubset(current_paths),
        "CLASSIFICATION_HISTORICAL_COVERAGE",
    )
    additions = [by_path[path] for path in extension_paths]
    final_current = [by_path[path] for path in current_paths]
    final_historical = [by_path[path] for path in historical]
    calculated_counts = {
        "f_additions": _classification_counts(additions),
        "final_current_a": _classification_counts(final_current),
        "final_f": _classification_counts(records),
        "final_historical_ledger_subjects": _classification_counts(final_historical),
        "source_current_a": _classification_counts(source_records.values()),
    }
    counts = contract["counts"]
    _require(
        isinstance(counts, dict)
        and tuple(counts)
        == (
            "f_additions",
            "final_current_a",
            "final_f",
            "final_historical_ledger_subjects",
            "source_current_a",
        ),
        "CLASSIFICATION_COUNT_SETS",
    )
    for label, population in (
        ("f_additions", len(extension_paths)),
        ("final_current_a", AUDITED_CURRENT_A_PATHS),
        ("final_f", len(records)),
        ("final_historical_ledger_subjects", EXPECTED_LEDGER_ROWS),
        ("source_current_a", AUDITED_CURRENT_A_PATHS),
    ):
        _validate_classification_count_vector(
            counts[label], population, f"CLASSIFICATION_COUNTS:{label}"
        )
        _require(
            _strict_equal(counts[label], calculated_counts[label]),
            f"CLASSIFICATION_COUNTS:{label}",
        )
    _require(
        _strict_equal(counts["source_current_a"], EXPECTED_SOURCE_CURRENT_A_COUNTS)
        and all(
            counts["final_f"][key]
            == counts["final_current_a"][key] + counts["f_additions"][key]
            for key in CLASSIFICATION_COUNT_KEYS
        ),
        "CLASSIFICATION_COUNTS:RELATION",
    )
    _require(
        contract["classification_set_sha256"]
        == _domain_digest(CLASSIFICATION_DIGEST_DOMAIN, records)
        == EXPECTED_F_CLASSIFICATION_SET_SHA256,
        "CLASSIFICATION_SET_DIGEST",
    )
    return by_path


def _sorted_text_list(
    value: object, code: str, *, paths: bool = False, nonempty: bool = False
) -> list[str]:
    _require(isinstance(value, list) and (not nonempty or bool(value)), code)
    result: list[str] = []
    for item in value:
        text = _canonical_path(item) if paths else _text(item, code)
        _require(not text or text[0] not in FORMULA_PREFIXES, code)
        result.append(text)
    _require(
        result == sorted(result, key=lambda item: item.encode("utf-8"))
        and len(result) == len(set(result)),
        code,
    )
    return result


def _public_key_fingerprint(public_key: str) -> str:
    fields = public_key.split(" ")
    _require(len(fields) == 2 and fields[0] == "ssh-ed25519", "PUBLIC_KEY")
    try:
        decoded = base64.b64decode(fields[1], validate=True)
    except (binascii.Error, ValueError) as error:
        raise VerificationError("PUBLIC_KEY") from error
    algorithm = b"ssh-ed25519"
    _require(
        len(decoded) == 4 + len(algorithm) + 4 + 32,
        "PUBLIC_KEY",
    )
    algorithm_size = int.from_bytes(decoded[:4], "big")
    algorithm_end = 4 + algorithm_size
    _require(
        algorithm_size == len(algorithm) and decoded[4:algorithm_end] == algorithm,
        "PUBLIC_KEY",
    )
    key_size = int.from_bytes(decoded[algorithm_end : algorithm_end + 4], "big")
    key_start = algorithm_end + 4
    _require(
        key_size == 32 and key_start + key_size == len(decoded),
        "PUBLIC_KEY",
    )
    return "SHA256:" + base64.b64encode(hashlib.sha256(decoded).digest()).decode(
        "ascii"
    ).rstrip("=")


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


def _classify_content(payload: bytes) -> tuple[str, int | None]:
    if b"\0" in payload:
        return "BINARY", None
    try:
        text = payload.decode("utf-8", "strict")
    except UnicodeDecodeError:
        return "BINARY", None
    controls = {
        char
        for char in text
        if char not in "\t\n\r" and unicodedata.category(char).startswith("C")
    }
    if controls == {"\x1b"}:
        return "TEXT_UTF8_WITH_ANSI_ESCAPE", len(text.splitlines())
    if controls:
        return "BINARY", None
    return "TEXT_UTF8", len(text.splitlines())


def _subject_units(subject: Mapping[str, Any]) -> int:
    if subject["content_kind"] == "BINARY":
        return max(math.ceil(subject["bytes"] / BINARY_UNIT_BYTES), 1)
    _require(type(subject["lines"]) is int, "SUBJECT_TEXT_LINES")
    return max(subject["lines"], 1)


def _subject_packet_record(
    subject: Mapping[str, Any], *, freeze_commit: str, freeze_tree: str
) -> dict[str, Any]:
    _require(
        "snapshot_state" not in subject
        and "content_commit" not in subject
        and "content_tree" not in subject,
        "SUBJECT_SNAPSHOT_STATE",
    )
    byte_interval = {"end_exclusive": subject["bytes"], "start_inclusive": 0}
    if subject["content_kind"] == "BINARY":
        coverage: dict[str, Any] = {
            "byte_interval": byte_interval,
            "chunk_bytes": BINARY_UNIT_BYTES,
            "chunk_count": max(math.ceil(subject["bytes"] / BINARY_UNIT_BYTES), 1),
            "kind": COVERAGE_RULE,
            "line_interval": None,
            "read_command": [
                GIT_EXECUTABLE,
                *GIT_GLOBAL_OPTIONS,
                "cat-file",
                "blob",
                subject["git_object_id"],
            ],
        }
    else:
        coverage = {
            "byte_interval": byte_interval,
            "chunk_bytes": None,
            "chunk_count": None,
            "kind": COVERAGE_RULE,
            "line_interval": (
                None
                if subject["lines"] == 0
                else {
                    "end_inclusive": subject["lines"],
                    "start_inclusive": 1,
                }
            ),
            "read_command": [
                GIT_EXECUTABLE,
                *GIT_GLOBAL_OPTIONS,
                "cat-file",
                "blob",
                subject["git_object_id"],
            ],
        }
    return {
        "bytes": subject["bytes"],
        "content_kind": subject["content_kind"],
        "content_commit": freeze_commit,
        "content_tree": freeze_tree,
        "coverage": coverage,
        "criticality": list(subject["criticality"]),
        "git_mode": subject["git_mode"],
        "git_object_id": subject["git_object_id"],
        "language": subject["language"],
        "lines": subject["lines"],
        "path": subject["path"],
        "sha256": subject["sha256"],
        "status": subject["status"],
        "subject_id": subject["subject_id"],
        "snapshot_state": "PRESENT_AT_CH_T002_F",
        "units": subject["units"],
    }


def _subject_set_digest(
    subjects: Iterable[Mapping[str, Any]], *, freeze_commit: str, freeze_tree: str
) -> str:
    records = [
        _subject_packet_record(
            subject, freeze_commit=freeze_commit, freeze_tree=freeze_tree
        )
        for subject in subjects
    ]
    records.sort(key=lambda record: record["subject_id"].encode("utf-8"))
    return _domain_digest("haldir-ch-t002-review-subject-set-v1", records)


def _raw_name_status(
    repo: Path, base_commit: str, target_commit: str
) -> tuple[bytes, dict[str, str]]:
    raw = _git(
        repo,
        ["diff", "--no-renames", "--name-status", "-z", base_commit, target_commit],
        maximum=MAX_TREE_OUTPUT,
    )
    fields = raw.split(b"\0")
    _require(fields and fields[-1] == b"", "NAME_STATUS_TERMINATION")
    fields.pop()
    _require(len(fields) % 2 == 0, "NAME_STATUS_SHAPE")
    statuses: dict[str, str] = {}
    for index in range(0, len(fields), 2):
        try:
            status = fields[index].decode("ascii", "strict")
            path = _canonical_path(fields[index + 1].decode("utf-8", "strict"))
        except UnicodeDecodeError as error:
            raise VerificationError("NAME_STATUS_ENCODING") from error
        _require(
            status in {"A", "M", "D"} and path not in statuses, "NAME_STATUS_VALUE"
        )
        statuses[path] = status
    return raw, statuses


def _validate_overlay_structure(
    overlay: dict[str, Any],
    *,
    freeze: Mapping[str, Any],
    freeze_commit: str,
    freeze_tree: str,
    registry_entry: Mapping[str, Any],
    registry_payload: bytes,
    classification_by_path: Mapping[str, Mapping[str, Any]],
) -> tuple[dict[str, frozenset[str]], list[dict[str, Any]]]:
    _exact_keys(
        overlay,
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
            "review_policy",
            "review_classification_contract",
            "entries",
            "removed_paths",
            "implementation_boundary",
            "counts",
            "digests",
        },
        "OVERLAY_KEYS",
    )
    _require(
        overlay["schema_id"] == OVERLAY_SCHEMA_ID
        and overlay["schema_version"] == OVERLAY_SCHEMA_VERSION
        and overlay["task_id"] == TASK_ID
        and overlay["epoch"] == EPOCH
        and overlay["release_target"] == RELEASE_TARGET
        and overlay["author"] == AUTHOR
        and overlay["persistent_identifier"] is None,
        "OVERLAY_IDENTITY",
    )
    scope = _exact_keys(
        overlay["scope"],
        {
            "classification_audit_sha256",
            "classification_policy",
            "claim_outcome",
            "evidence_catalog",
            "generator_catalog",
            "inclusion",
            "kind",
            "path_order",
            "requirement_catalog",
            "test_catalog",
        },
        "OVERLAY_SCOPE_KEYS",
    )
    _require(
        scope["classification_audit_sha256"] == CLASSIFICATION_AUDIT_SHA256
        and scope["classification_policy"] == CLASSIFICATION_POLICY
        and scope["claim_outcome"] == "NO_PUBLIC_CLAIM_CHANGE"
        and scope["inclusion"] == SCOPE_INCLUSION
        and scope["kind"] == OVERLAY_SCOPE
        and scope["path_order"] == PATH_ORDER,
        "OVERLAY_SCOPE",
    )
    catalogs: dict[str, frozenset[str]] = {}
    for key in (
        "evidence_catalog",
        "generator_catalog",
        "requirement_catalog",
        "test_catalog",
    ):
        catalogs[key] = frozenset(
            _sorted_text_list(scope[key], f"OVERLAY_CATALOG:{key}", nonempty=True)
        )
    _require(
        catalogs["evidence_catalog"] == frozenset(EVIDENCE_PATHS),
        "OVERLAY_EVIDENCE_CATALOG",
    )
    controls = freeze["normative_controls"]
    expected_requirements = frozenset(item["id"] for item in controls)
    expected_tests = frozenset(
        item[field]
        for item in controls
        for field in ("accepted_test_id", "rejected_test_id")
    )
    _require(
        catalogs["requirement_catalog"] == expected_requirements,
        "OVERLAY_REQUIREMENT_CATALOG",
    )
    _require(catalogs["test_catalog"] == expected_tests, "OVERLAY_TEST_CATALOG")
    _require(
        all(
            re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:/#@+-]{0,511}", item)
            for key in ("generator_catalog", "test_catalog")
            for item in catalogs[key]
        ),
        "OVERLAY_MACHINE_CATALOG",
    )

    base = _exact_keys(
        overlay["base_partition"],
        {
            "commit",
            "tree",
            "ledger_path",
            "ledger_blob_id",
            "ledger_sha256",
            "ledger_rows",
            "ledger_self_path",
        },
        "OVERLAY_BASE_KEYS",
    )
    _require(
        _strict_equal(
            base,
            {
                "commit": CH_T001_IMPLEMENTATION_COMMIT,
                "tree": CH_T001_IMPLEMENTATION_TREE,
                "ledger_path": LEDGER_PATH,
                "ledger_blob_id": CH_T001_LEDGER_OBJECT_ID,
                "ledger_sha256": CH_T001_LEDGER_SHA256,
                "ledger_rows": EXPECTED_LEDGER_ROWS,
                "ledger_self_path": LEDGER_PATH,
            },
        ),
        "OVERLAY_BASE_BINDING",
    )
    delta = _exact_keys(
        overlay["delta"],
        {"freeze_commit", "freeze_tree", "name_status_sha256"},
        "OVERLAY_DELTA_KEYS",
    )
    _require(
        delta["freeze_commit"] == freeze_commit
        and delta["freeze_tree"] == freeze_tree
        and HEX64.fullmatch(delta["name_status_sha256"] or "") is not None,
        "OVERLAY_DELTA_BINDING",
    )
    policy = _exact_keys(
        overlay["review_policy"],
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
        },
        "OVERLAY_POLICY_KEYS",
    )
    _require(
        policy["algorithm"] == ASSIGNMENT_ALGORITHM
        and policy["binary_unit_bytes"] == BINARY_UNIT_BYTES
        and policy["coverage"] == COVERAGE_RULE
        and policy["removed_coverage"] == REMOVAL_POLICY
        and policy["critical_secondary_required"] is True
        and policy["primary_selection"] == PRIMARY_RULE
        and policy["secondary_selection"] == SECONDARY_RULE
        and policy["sort_order"] == SORT_RULE
        and policy["text_units"] == TEXT_UNIT_RULE,
        "OVERLAY_POLICY",
    )
    registry = _exact_keys(
        policy["registry"], {"path", "git_blob_id", "sha256"}, "OVERLAY_REGISTRY_KEYS"
    )
    _require(
        registry
        == {
            "path": FREEZE_PATH,
            "git_blob_id": registry_entry["oid"],
            "sha256": _sha256(registry_payload),
        },
        "OVERLAY_REGISTRY_BINDING",
    )
    reviewer_by_requirement, _by_fingerprint = _reviewer_maps(freeze)
    lanes = policy["lanes"]
    _require(isinstance(lanes, list) and len(lanes) == 3, "OVERLAY_LANES")
    expected_kinds = (
        "INDEPENDENT_REVIEW",
        "INDEPENDENT_REVIEW_LANE_02",
        "INDEPENDENT_REVIEW_LANE_03",
    )
    fingerprints: set[str] = set()
    for number, (lane, review_spec) in enumerate(
        zip(lanes, REVIEW_SPECS[:3], strict=True), 1
    ):
        lane = _exact_keys(
            lane,
            {"kind", "lane", "requirement_id", "reviewer_fingerprint"},
            "OVERLAY_LANE_KEYS",
        )
        registry_reviewer = reviewer_by_requirement[review_spec[0]]
        _require(
            _strict_equal(
                lane,
                {
                    "kind": expected_kinds[number - 1],
                    "lane": number,
                    "requirement_id": review_spec[0],
                    "reviewer_fingerprint": registry_reviewer["key_fingerprint"],
                },
            ),
            "OVERLAY_LANE_BINDING",
        )
        fingerprints.add(lane["reviewer_fingerprint"])
    _require(
        len(fingerprints) == 3 and policy["lead_requirement_id"] == REVIEW_SPECS[3][0],
        "OVERLAY_REVIEWER_SEPARATION",
    )

    entries = overlay["entries"]
    _require(isinstance(entries, list) and bool(entries), "OVERLAY_ENTRIES")
    paths: list[str] = []
    subject_ids: set[str] = set()
    for entry in entries:
        entry = _exact_keys(
            entry,
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
            },
            "OVERLAY_ENTRY_KEYS",
        )
        path = _canonical_path(entry["path"])
        paths.append(path)
        _require(entry["git_mode"] in {"100644", "100755"}, "OVERLAY_ENTRY_MODE")
        _hex(entry["git_object_id"], HEX40, "OVERLAY_ENTRY_OBJECT")
        _hex(entry["sha256"], HEX64, "OVERLAY_ENTRY_SHA256")
        _integer(entry["bytes"], "OVERLAY_ENTRY_BYTES")
        _require(
            entry["content_kind"]
            in {"BINARY", "TEXT_UTF8", "TEXT_UTF8_WITH_ANSI_ESCAPE"},
            "OVERLAY_ENTRY_CONTENT_KIND",
        )
        if entry["content_kind"] == "BINARY":
            _require(entry["lines"] is None, "OVERLAY_ENTRY_BINARY_LINES")
        else:
            _integer(entry["lines"], "OVERLAY_ENTRY_LINES")
        _require(
            re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", entry["language"] or "") is not None,
            "OVERLAY_ENTRY_LANGUAGE",
        )
        _require(
            entry["language"] == _language(path),
            "OVERLAY_ENTRY_LANGUAGE_CLASSIFICATION",
        )
        criticality = entry["criticality"]
        _require(
            isinstance(criticality, list)
            and criticality
            == [item for item in CRITICALITY_ORDER if item in criticality]
            and len(criticality) == len(set(criticality)),
            "OVERLAY_ENTRY_CRITICALITY",
        )
        _require(path in classification_by_path, "OVERLAY_ENTRY_CLASSIFICATION_PATH")
        classification = classification_by_path[path]
        _require(
            _strict_equal(criticality, _classification_criticality(classification))
            and all(
                _strict_equal(entry[field], classification[field])
                for field in (
                    "generated",
                    "generator",
                    "provenance_review_status",
                    "license_review_status",
                    "license_expression",
                    "rule_ids",
                    "source_basis",
                )
            ),
            "OVERLAY_ENTRY_CLASSIFICATION",
        )
        _require(
            entry["status"]
            in {
                "ADDED_FREEZE_DELTA",
                "MODIFIED_FREEZE_DELTA",
                "LEDGER_SELF_EXTERNAL_BINDING",
            },
            "OVERLAY_ENTRY_STATUS",
        )
        expected_subject = _subject_id(entry)
        _require(entry["subject_id"] == expected_subject, "OVERLAY_ENTRY_SUBJECT_ID")
        _require(expected_subject not in subject_ids, "OVERLAY_ENTRY_SUBJECT_DUPLICATE")
        subject_ids.add(expected_subject)
    _canonical_order(paths, "OVERLAY_ENTRY_ORDER")
    _require(overlay["removed_paths"] == [], "OVERLAY_REMOVALS_FORBIDDEN")
    boundary = _exact_keys(
        overlay["implementation_boundary"],
        {"content_identities_in_overlay", "paths", "review_kind"},
        "OVERLAY_BOUNDARY_KEYS",
    )
    _require(
        _strict_equal(
            boundary,
            {
                "content_identities_in_overlay": False,
                "paths": [
                    {"path": path, "status": status}
                    for path, status in EXPECTED_I_DIFF.items()
                ],
                "review_kind": IMPLEMENTATION_REVIEW_KIND,
            },
        ),
        "OVERLAY_IMPLEMENTATION_BOUNDARY",
    )
    _exact_keys(
        overlay["counts"],
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
        },
        "OVERLAY_COUNT_KEYS",
    )
    _exact_keys(
        overlay["digests"],
        {
            "classification_set_sha256",
            "entry_set_sha256",
            "removed_path_set_sha256",
            "subject_set_sha256",
        },
        "OVERLAY_DIGEST_KEYS",
    )
    _require(
        overlay["digests"]["classification_set_sha256"]
        == overlay["review_classification_contract"]["classification_set_sha256"],
        "OVERLAY_CLASSIFICATION_DIGEST",
    )
    return catalogs, entries


def _validate_catalog_bindings(
    rows: Sequence[Mapping[str, str]],
    catalogs: Mapping[str, frozenset[str]],
    classification_by_path: Mapping[str, Mapping[str, Any]],
    subjects: Sequence[Mapping[str, Any]],
) -> None:
    evidence = catalogs["evidence_catalog"]
    generators = catalogs["generator_catalog"]
    requirements = catalogs["requirement_catalog"]
    tests = catalogs["test_catalog"]
    resolvable = evidence | requirements | tests
    expected_generators = frozenset(
        record["generator"]
        for record in classification_by_path.values()
        if record["generator"]
    )
    _require(generators == expected_generators, "CATALOG_GENERATOR_EXACT")
    review_paths = set(classification_by_path)
    _require(
        all(
            generator in review_paths or generator in ALLOWED_EXTERNAL_GENERATORS
            for generator in generators
        ),
        "CATALOG_GENERATOR_RESOLUTION",
    )
    subject_by_path = {subject["path"]: subject for subject in subjects}
    _require(
        len(subject_by_path) == len(subjects)
        and {row["path"] for row in rows}.issubset(subject_by_path)
        and all(
            isinstance(subject["subject_id"], str)
            and HEX64.fullmatch(subject["subject_id"]) is not None
            for subject in subject_by_path.values()
        ),
        "CATALOG_SUBJECT_SET",
    )

    def pointers_resolve(
        tokens: Iterable[str], catalog: frozenset[str], subject_id: str
    ) -> bool:
        for token in tokens:
            if token in catalog:
                continue
            match = EVIDENCE_POINTER.fullmatch(token)
            if (
                match is None
                or match.group(1) not in evidence
                or match.group(2) != subject_id
            ):
                return False
        return True

    for row in rows:
        path = row["path"]
        subject_id = subject_by_path[path]["subject_id"]
        critical = any(row[item] == "YES" for item in CRITICAL_FIELDS)
        if row["generated"] == "YES":
            _require(row["generator"] in generators, f"CATALOG_GENERATOR:{path}")
        provenance_tokens = _reference_tokens(
            row["provenance_evidence"],
            f"CATALOG_POINTER:{path}:provenance_evidence",
        )
        expected_provenance = (
            (f"CH-T002-E09#{subject_id}:PROVENANCE",)
            if row["provenance_review_status"] == "CONFIRMED"
            else ()
        )
        _require(
            provenance_tokens == expected_provenance,
            f"CATALOG_POINTER:{path}:provenance_evidence",
        )
        license_tokens = _reference_tokens(
            row["license_evidence"], f"CATALOG_POINTER:{path}:license_evidence"
        )
        expected_license = (
            (f"CH-T002-E09#{subject_id}:LICENSE",)
            if row["license_review_status"] == "APPROVED"
            else ()
        )
        _require(
            license_tokens == expected_license,
            f"CATALOG_POINTER:{path}:license_evidence",
        )
        for field, catalog in (("requirements", requirements), ("tests", tests)):
            tokens = _reference_tokens(row[field], f"CATALOG_POINTER:{path}:{field}")
            _require(
                (not critical or bool(tokens))
                and all(token in catalog for token in tokens),
                f"CATALOG_POINTER:{path}:{field}",
            )
        assignment_tokens = _reference_tokens(
            row["evidence"], f"CATALOG_POINTER:{path}:evidence"
        )
        assignment_matches = [
            EVIDENCE_POINTER.fullmatch(token) for token in assignment_tokens
        ]
        _require(
            all(
                match is not None
                and match.group(1) in evidence
                and match.group(2) == subject_id
                for match in assignment_matches
            ),
            f"CATALOG_POINTER:{path}:evidence",
        )
        primary_lanes = [
            match.group(1)
            for match in assignment_matches
            if match is not None
            and match.group(1) in {"CH-T002-E10", "CH-T002-E11", "CH-T002-E12"}
            and match.group(3) == "PRIMARY"
        ]
        secondary_lanes = [
            match.group(1)
            for match in assignment_matches
            if match is not None
            and match.group(1) in {"CH-T002-E10", "CH-T002-E11", "CH-T002-E12"}
            and match.group(3) == "SECONDARY"
        ]
        expected_e09 = {f"CH-T002-E09#{subject_id}:PRIMARY"}
        if critical:
            expected_e09.add(f"CH-T002-E09#{subject_id}:SECONDARY")
        observed_e09 = {
            token for token in assignment_tokens if token.startswith("CH-T002-E09#")
        }
        _require(
            observed_e09 == expected_e09
            and len(primary_lanes) == 1
            and (
                len(secondary_lanes) == 1 and secondary_lanes[0] != primary_lanes[0]
                if critical
                else not secondary_lanes
            )
            and len(assignment_tokens) == (4 if critical else 2),
            f"CATALOG_POINTER:{path}:evidence",
        )
        assumption_tokens = _reference_tokens(
            row["assumptions"], f"CATALOG_POINTER:{path}:assumptions"
        )
        defect_tokens = _reference_tokens(
            row["defects"], f"CATALOG_POINTER:{path}:defects", allow_none=True
        )
        _require(
            pointers_resolve(assumption_tokens, resolvable, subject_id),
            f"CATALOG_POINTER:{path}:assumptions",
        )
        _require(
            defect_tokens == ("NONE",)
            or pointers_resolve(defect_tokens, resolvable, subject_id),
            f"CATALOG_POINTER:{path}:defects",
        )
        if row["license_review_status"] == "APPROVED":
            _require(
                row["license_expression"] in ALLOWED_SPDX_EXPRESSIONS,
                f"LICENSE_EXPRESSION:{path}",
            )


def _ledger_subject(row: Mapping[str, str]) -> dict[str, Any]:
    content_kind = row["current_content_kind"]
    _require(
        content_kind in {"BINARY", "TEXT_UTF8", "TEXT_UTF8_WITH_ANSI_ESCAPE"},
        "LEDGER_SUBJECT_CONTENT_KIND",
    )
    try:
        size = int(row["current_bytes"])
        raw_lines = int(row["current_lines"])
    except ValueError as error:
        raise VerificationError("LEDGER_SUBJECT_DECIMAL") from error
    _require(
        str(size) == row["current_bytes"]
        and str(raw_lines) == row["current_lines"]
        and size >= 0
        and raw_lines >= 0,
        "LEDGER_SUBJECT_DECIMAL",
    )
    lines: int | None = None if content_kind == "BINARY" else raw_lines
    if content_kind == "BINARY":
        _require(raw_lines == 0, "LEDGER_SUBJECT_BINARY_LINES")
    record: dict[str, Any] = {
        "bytes": size,
        "content_kind": content_kind,
        "criticality": [
            name
            for field, name in zip(CRITICAL_FIELDS, CRITICALITY_ORDER, strict=True)
            if row[field] == "YES"
        ],
        "git_mode": row["current_fs_mode"],
        "git_object_id": row["current_git_blob_id"],
        "language": row["language"],
        "lines": lines,
        "path": row["path"],
        "sha256": row["current_sha256"],
        "status": "UNCHANGED_BASE",
    }
    _require(record["git_mode"] in {"100644", "100755"}, "LEDGER_SUBJECT_MODE")
    _hex(record["git_object_id"], HEX40, "LEDGER_SUBJECT_OBJECT")
    _hex(record["sha256"], HEX64, "LEDGER_SUBJECT_SHA256")
    _require(record["language"] == _language(record["path"]), "LEDGER_SUBJECT_LANGUAGE")
    record["subject_id"] = _subject_id(record)
    record["units"] = _subject_units(record)
    return record


def _overlay_subject(entry: Mapping[str, Any]) -> dict[str, Any]:
    record = dict(entry)
    record["units"] = _subject_units(record)
    return record


def _verify_subject(
    subject: Mapping[str, Any],
    *,
    f_entries: Mapping[str, Mapping[str, Any]],
    f_blobs: Mapping[str, bytes],
    classification_by_path: Mapping[str, Mapping[str, Any]],
) -> None:
    path = subject["path"]
    _require(path in f_entries, f"SUBJECT_NOT_IN_FREEZE_TREE:{path}")
    entry = f_entries[path]
    payload = f_blobs[entry["oid"]]
    content_kind, lines = _classify_content(payload)
    _require(
        subject["git_mode"] == entry["mode"]
        and subject["git_object_id"] == entry["oid"]
        and subject["sha256"] == _sha256(payload)
        and subject["bytes"] == len(payload)
        and subject["content_kind"] == content_kind
        and subject["lines"] == lines
        and subject["subject_id"] == _subject_id(subject),
        f"SUBJECT_IDENTITY:{path}",
    )
    _require(subject["language"] == _language(path), f"SUBJECT_LANGUAGE:{path}")
    _require(
        path in classification_by_path
        and _strict_equal(
            subject["criticality"],
            _classification_criticality(classification_by_path[path]),
        ),
        f"SUBJECT_CLASSIFICATION:{path}",
    )


def reconcile_subjects(
    repo: Path,
    *,
    overlay: Mapping[str, Any],
    base_rows: Sequence[Mapping[str, str]],
    rows: Sequence[Mapping[str, str]],
    f_entries: Mapping[str, Mapping[str, Any]],
    f_blobs: Mapping[str, bytes],
    implementation_commit: str,
    implementation_tree: str,
    implementation_entries: Mapping[str, Mapping[str, Any]],
    implementation_blobs: Mapping[str, bytes],
    classification_by_path: Mapping[str, Mapping[str, Any]],
) -> list[dict[str, Any]]:
    raw_delta, delta = _raw_name_status(
        repo, CH_T001_IMPLEMENTATION_COMMIT, overlay["delta"]["freeze_commit"]
    )
    _require(
        _sha256(raw_delta) == overlay["delta"]["name_status_sha256"],
        "OVERLAY_NAME_STATUS_DIGEST",
    )
    _require(LEDGER_PATH not in delta, "OVERLAY_BASE_LEDGER_DRIFT")
    entries = overlay["entries"]
    self_entries = [
        entry for entry in entries if entry["status"] == "LEDGER_SELF_EXTERNAL_BINDING"
    ]
    _require(
        len(self_entries) == 1 and self_entries[0]["path"] == LEDGER_PATH,
        "OVERLAY_SELF_ENTRY",
    )
    _require(
        all(status != "D" for status in delta.values()),
        "FREEZE_DELTA_REMOVAL_FORBIDDEN",
    )
    expected_delta_entries = {
        path: "ADDED_FREEZE_DELTA" if status == "A" else "MODIFIED_FREEZE_DELTA"
        for path, status in delta.items()
    }
    actual_delta_entries = {
        entry["path"]: entry["status"]
        for entry in entries
        if entry["status"] != "LEDGER_SELF_EXTERNAL_BINDING"
    }
    _require(actual_delta_entries == expected_delta_entries, "OVERLAY_DELTA_ENTRIES")
    _require(overlay["removed_paths"] == [], "OVERLAY_REMOVALS_FORBIDDEN")
    entry_by_path = {entry["path"]: entry for entry in entries}
    subjects: list[dict[str, Any]] = []
    for row in rows:
        path = row["path"]
        if path == LEDGER_PATH or path in entry_by_path:
            continue
        subjects.append(_ledger_subject(row))
    subjects.extend(_overlay_subject(entry) for entry in entries)
    subjects.sort(
        key=lambda item: (
            item["path"].encode("utf-8"),
            item["subject_id"].encode("ascii"),
        )
    )
    _require(
        len(subjects) == len({item["path"] for item in subjects})
        and {item["path"] for item in subjects} == set(f_entries),
        "SUBJECT_FREEZE_COVERAGE",
    )
    for subject in subjects:
        _verify_subject(
            subject,
            f_entries=f_entries,
            f_blobs=f_blobs,
            classification_by_path=classification_by_path,
        )
    _require(
        [row["path"] for row in base_rows] == [row["path"] for row in rows],
        "BASE_ROW_ALIGNMENT",
    )

    forbidden_strings = {implementation_commit, implementation_tree}
    for path in EXPECTED_I_DIFF:
        entry = implementation_entries[path]
        payload = implementation_blobs[entry["oid"]]
        forbidden_strings.update({entry["oid"], _sha256(payload)})
    _require(
        forbidden_strings.isdisjoint(_recursive_strings(overlay)),
        "OVERLAY_FUTURE_IMPLEMENTATION_IDENTITY",
    )
    statuses = Counter(entry["status"] for entry in entries)
    expected_counts = {
        "added_entries": statuses["ADDED_FREEZE_DELTA"],
        "base_rows": len(base_rows),
        "critical_subjects": sum(bool(subject["criticality"]) for subject in subjects),
        "modified_entries": statuses["MODIFIED_FREEZE_DELTA"],
        "removed_paths": 0,
        "review_subjects": len(subjects),
        "self_entries": statuses["LEDGER_SELF_EXTERNAL_BINDING"],
        "supplemental_subjects": len(entries),
        "unchanged_subjects": sum(
            subject["status"] == "UNCHANGED_BASE" for subject in subjects
        ),
    }
    _require(_strict_equal(overlay["counts"], expected_counts), "OVERLAY_COUNTS")
    expected_digests = {
        "classification_set_sha256": EXPECTED_F_CLASSIFICATION_SET_SHA256,
        "entry_set_sha256": _domain_digest(
            "haldir-ch-t002-overlay-entry-set-v1", entries
        ),
        "removed_path_set_sha256": _domain_digest(
            "haldir-ch-t002-removed-path-set-v1", overlay["removed_paths"]
        ),
        "subject_set_sha256": _subject_set_digest(
            subjects,
            freeze_commit=overlay["delta"]["freeze_commit"],
            freeze_tree=overlay["delta"]["freeze_tree"],
        ),
    }
    _require(_strict_equal(overlay["digests"], expected_digests), "OVERLAY_DIGESTS")
    return subjects


def assign_subjects(
    subjects: Sequence[Mapping[str, Any]],
    *,
    freeze: Mapping[str, Any],
    overlay: Mapping[str, Any],
    rows: Sequence[Mapping[str, str]],
    classification_by_path: Mapping[str, Mapping[str, Any]],
) -> list[dict[str, Any]]:
    reviewer_by_requirement, _by_fingerprint = _reviewer_maps(freeze)
    lanes: list[dict[str, Any]] = []
    for policy in overlay["review_policy"]["lanes"]:
        registry_entry = reviewer_by_requirement[policy["requirement_id"]]
        reviewer = registry_entry["reviewer"]
        lanes.append(
            {
                "number": policy["lane"],
                "reviewer": {
                    "classification": reviewer["classification"],
                    "key_fingerprint": registry_entry["key_fingerprint"],
                    "kind": registry_entry["kind"],
                    "name": reviewer["name"],
                    "organization": reviewer["organization"],
                    "principal": reviewer["principal"],
                    "requirement_id": registry_entry["requirement_id"],
                },
                "primary": [],
                "secondary": [],
                "total_units": 0,
                "item_count": 0,
            }
        )
    ordered = sorted(
        subjects,
        key=lambda subject: (
            -subject["units"],
            subject["language"].encode("utf-8"),
            subject["subject_id"].encode("utf-8"),
        ),
    )
    for subject in ordered:
        primary = min(
            lanes,
            key=lambda lane: (lane["total_units"], lane["item_count"], lane["number"]),
        )
        primary["primary"].append(subject)
        primary["total_units"] += subject["units"]
        primary["item_count"] += 1
        if subject["criticality"]:
            secondary = min(
                (lane for lane in lanes if lane["number"] != primary["number"]),
                key=lambda lane: (
                    lane["total_units"],
                    lane["item_count"],
                    lane["number"],
                ),
            )
            secondary["secondary"].append(subject)
            secondary["total_units"] += subject["units"]
            secondary["item_count"] += 1
    for lane in lanes:
        lane["primary"].sort(key=lambda item: item["subject_id"].encode("utf-8"))
        lane["secondary"].sort(key=lambda item: item["subject_id"].encode("utf-8"))
    primary = [item["subject_id"] for lane in lanes for item in lane["primary"]]
    secondary = [item["subject_id"] for lane in lanes for item in lane["secondary"]]
    critical = {item["subject_id"] for item in subjects if item["criticality"]}
    _require(
        len(primary) == len(subjects)
        and len(set(primary)) == len(primary)
        and set(primary) == {item["subject_id"] for item in subjects},
        "PRIMARY_PARTITION",
    )
    _require(
        len(secondary) == len(set(secondary)) and set(secondary) == critical,
        "SECONDARY_PARTITION",
    )
    for subject_id in critical:
        primary_lane = next(
            lane["number"]
            for lane in lanes
            if any(item["subject_id"] == subject_id for item in lane["primary"])
        )
        secondary_lane = next(
            lane["number"]
            for lane in lanes
            if any(item["subject_id"] == subject_id for item in lane["secondary"])
        )
        _require(primary_lane != secondary_lane, "SECONDARY_LANE_SEPARATION")
    principals = {lane["reviewer"]["principal"] for lane in lanes}
    primary_assignment = {
        subject["path"]: (lane["number"], lane["reviewer"]["principal"], subject)
        for lane in lanes
        for subject in lane["primary"]
    }
    secondary_lane = {
        subject["subject_id"]: lane["number"]
        for lane in lanes
        for subject in lane["secondary"]
    }
    for row in rows:
        _require(row["reviewer"] in principals, "LEDGER_ASSIGNMENT_REGISTRY")
        assignment = primary_assignment.get(row["path"])
        _require(
            assignment is not None and assignment[1] == row["reviewer"],
            "LEDGER_PRIMARY_ASSIGNMENT",
        )
        primary_lane, primary_principal, subject = assignment
        row_criticality = [
            name
            for field, name in zip(CRITICAL_FIELDS, CRITICALITY_ORDER, strict=True)
            if row[field] == "YES"
        ]
        _require(
            _strict_equal(row_criticality, subject["criticality"]),
            "LEDGER_SUBJECT_CRITICALITY",
        )
        evidence = set(
            _reference_tokens(
                row["evidence"], f"LEDGER_ASSIGNMENT_EVIDENCE:{row['path']}"
            )
        )
        required_evidence = {
            f"CH-T002-E09#{subject['subject_id']}:PRIMARY",
            f"CH-T002-E{9 + primary_lane:02d}#{subject['subject_id']}:PRIMARY",
        }
        second: int | None = None
        if subject["criticality"]:
            second = secondary_lane.get(subject["subject_id"])
            _require(
                second is not None and second != primary_lane,
                "LEDGER_SECONDARY_ASSIGNMENT",
            )
            required_evidence.update(
                {
                    f"CH-T002-E09#{subject['subject_id']}:SECONDARY",
                    f"CH-T002-E{9 + second:02d}#{subject['subject_id']}:SECONDARY",
                }
            )
        classification = classification_by_path[row["path"]]
        _require(
            row["provenance_review_status"] == "CONFIRMED"
            and row["provenance_evidence"]
            == f"CH-T002-E09#{subject['subject_id']}:PROVENANCE"
            and row["license_review_status"] == classification["license_review_status"]
            and row["license_expression"] == classification["license_expression"]
            and (
                row["license_evidence"]
                == f"CH-T002-E09#{subject['subject_id']}:LICENSE"
                if classification["license_review_status"] == "APPROVED"
                else row["license_evidence"] == ""
            )
            and row["disposition"] == "ACCEPTED",
            "LIVE_LEDGER_DISPOSITION",
        )
        _require(evidence == required_evidence, "LEDGER_ASSIGNMENT_EVIDENCE")
    _require(all(lane["primary"] for lane in lanes), "EMPTY_PRIMARY_LANE")
    return lanes


def _snapshot_record(
    *,
    freeze_commit: str,
    freeze_tree: str,
    implementation_commit: str,
    implementation_tree: str,
    implementation_entries: Mapping[str, Mapping[str, Any]],
    implementation_blobs: Mapping[str, bytes],
    registry_entry: Mapping[str, Any],
    registry_payload: bytes,
) -> dict[str, Any]:
    return {
        "freeze_commit": freeze_commit,
        "freeze_tree": freeze_tree,
        "implementation_commit": implementation_commit,
        "implementation_tree": implementation_tree,
        "ledger": {
            "git_blob_id": implementation_entries[LEDGER_PATH]["oid"],
            "path": LEDGER_PATH,
            "sha256": _sha256(
                implementation_blobs[implementation_entries[LEDGER_PATH]["oid"]]
            ),
        },
        "overlay": {
            "git_blob_id": implementation_entries[OVERLAY_PATH]["oid"],
            "path": OVERLAY_PATH,
            "sha256": _sha256(
                implementation_blobs[implementation_entries[OVERLAY_PATH]["oid"]]
            ),
        },
        "reviewer_registry": {
            "git_blob_id": registry_entry["oid"],
            "path": FREEZE_PATH,
            "sha256": _sha256(registry_payload),
        },
    }


def _language_counts(lane: Mapping[str, Any]) -> list[dict[str, Any]]:
    primary = Counter(subject["language"] for subject in lane["primary"])
    secondary = Counter(subject["language"] for subject in lane["secondary"])
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


def build_packet_bodies(
    *,
    subjects: Sequence[Mapping[str, Any]],
    lanes: Sequence[Mapping[str, Any]],
    overlay: Mapping[str, Any],
    freeze_commit: str,
    freeze_tree: str,
    implementation_commit: str,
    implementation_tree: str,
    implementation_entries: Mapping[str, Mapping[str, Any]],
    implementation_blobs: Mapping[str, bytes],
    registry_entry: Mapping[str, Any],
    registry_payload: bytes,
) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    snapshot = _snapshot_record(
        freeze_commit=freeze_commit,
        freeze_tree=freeze_tree,
        implementation_commit=implementation_commit,
        implementation_tree=implementation_tree,
        implementation_entries=implementation_entries,
        implementation_blobs=implementation_blobs,
        registry_entry=registry_entry,
        registry_payload=registry_payload,
    )
    packet_bodies: dict[str, dict[str, Any]] = {}
    packet_records: list[dict[str, Any]] = []
    for lane in lanes:
        primary_records = [
            _subject_packet_record(
                subject, freeze_commit=freeze_commit, freeze_tree=freeze_tree
            )
            for subject in lane["primary"]
        ]
        secondary_records = [
            _subject_packet_record(
                subject, freeze_commit=freeze_commit, freeze_tree=freeze_tree
            )
            for subject in lane["secondary"]
        ]
        lane_digest = _domain_digest(
            "haldir-ch-t002-lane-subject-set-v1",
            {
                "primary": [record["subject_id"] for record in primary_records],
                "secondary": [record["subject_id"] for record in secondary_records],
            },
        )
        primary_units = sum(subject["units"] for subject in lane["primary"])
        secondary_units = sum(subject["units"] for subject in lane["secondary"])
        body = {
            "assignment": {
                "algorithm": ASSIGNMENT_ALGORITHM,
                "binary_unit_bytes": BINARY_UNIT_BYTES,
                "language_counts": _language_counts(lane),
                "primary_entries": primary_records,
                "primary_subjects": len(primary_records),
                "primary_units": primary_units,
                "secondary_entries": secondary_records,
                "secondary_subjects": len(secondary_records),
                "secondary_units": secondary_units,
                "subject_set_sha256": lane_digest,
                "total_subjects": len(primary_records) + len(secondary_records),
                "total_units": lane["total_units"],
            },
            "coverage": {
                "invalid_secondary_subjects": 0,
                "primary": COVERAGE_RULE,
                "removed": REMOVAL_POLICY,
                "secondary": COVERAGE_RULE,
                "uncovered_primary_subjects": 0,
            },
            "epoch": EPOCH,
            "lane": lane["number"],
            "release_target": RELEASE_TARGET,
            "result": "PASS",
            "reviewer": lane["reviewer"],
            "schema_id": PACKET_SCHEMA_ID,
            "schema_version": OVERLAY_SCHEMA_VERSION,
            "snapshot": snapshot,
            "task_id": TASK_ID,
        }
        payload = _canonical_json_bytes(body)
        _require(len(payload) < MAX_PACKET_BYTES, "PACKET_BYTE_BOUND")
        lane_name = f"lane-{lane['number']:02d}"
        packet_bodies[lane_name] = body
        packet_records.append(
            {
                "bytes": len(payload),
                "filename": f"review-lane-{lane['number']:02d}.json",
                "lane": lane["number"],
                "primary_subjects": len(lane["primary"]),
                "secondary_subjects": len(lane["secondary"]),
                "sha256": _sha256(payload),
                "total_units": lane["total_units"],
            }
        )
    manifest = {
        "algorithm": ASSIGNMENT_ALGORITHM,
        "critical_subjects": sum(bool(subject["criticality"]) for subject in subjects),
        "epoch": EPOCH,
        "lane_packets": packet_records,
        "overlay_reconciliation": {
            "base_partition": copy.deepcopy(overlay["base_partition"]),
            "content_identity_mismatches": 0,
            "counts": copy.deepcopy(overlay["counts"]),
            "current_freeze_regular_blobs": len(subjects),
            "current_subjects": len(subjects),
            "delta": copy.deepcopy(overlay["delta"]),
            "digests": copy.deepcopy(overlay["digests"]),
            "duplicate_current_paths": 0,
            "implementation_boundary": copy.deepcopy(
                overlay["implementation_boundary"]
            ),
            "unexpected_removal_paths": 0,
            "missing_current_paths": 0,
            "overlay_input": copy.deepcopy(snapshot["overlay"]),
            "removed_subjects": 0,
            "result": "PASS",
            "scope_inclusion": SCOPE_INCLUSION,
            "uncovered_freeze_tree_subjects": 0,
        },
        "release_target": RELEASE_TARGET,
        "result": "PASS",
        "review_subjects": len(subjects),
        "schema_id": PACKET_MANIFEST_SCHEMA_ID,
        "schema_version": OVERLAY_SCHEMA_VERSION,
        "snapshot": snapshot,
        "subject_set_sha256": _subject_set_digest(
            subjects, freeze_commit=freeze_commit, freeze_tree=freeze_tree
        ),
        "task_id": TASK_ID,
    }
    _require(
        len(_canonical_json_bytes(manifest)) < MAX_PACKET_BYTES, "MANIFEST_BYTE_BOUND"
    )
    return packet_bodies, manifest


def _require_common_evidence(
    document: Mapping[str, Any],
    *,
    identifier: str,
    freeze_commit: str,
    implementation_commit: str,
) -> None:
    _require(
        document.get("schema_id") == EVIDENCE_SCHEMA_IDS[identifier]
        and document.get("evidence_id") == identifier
        and document.get("task_id") == TASK_ID
        and document.get("epoch") == EPOCH
        and document.get("freeze_commit") == freeze_commit
        and document.get("implementation_commit") == implementation_commit
        and document.get("result") == "PASS",
        f"EVIDENCE_COMMON:{identifier}",
    )
    started = _timestamp(
        document.get("started_at_utc"), f"EVIDENCE_STARTED:{identifier}"
    )
    completed = _timestamp(
        document.get("completed_at_utc"), f"EVIDENCE_COMPLETED:{identifier}"
    )
    _require(started <= completed, f"EVIDENCE_TIME:{identifier}")


def _number(value: object, code: str, *, minimum: float = 0.0) -> float:
    _require(
        type(value) in {int, float}
        and math.isfinite(value)
        and float(value) >= minimum,
        code,
    )
    return float(value)


def _text_list(
    value: object,
    code: str,
    *,
    minimum: int = 0,
    sorted_unique: bool = False,
) -> list[str]:
    _require(isinstance(value, list) and len(value) >= minimum, code)
    parsed = [_text(item, code, maximum=4096) for item in value]
    if sorted_unique:
        _require(
            len(parsed) == len(set(parsed))
            and parsed == sorted(parsed, key=lambda item: item.encode("utf-8")),
            code,
        )
    return parsed


def _python_test_names(payload: bytes, label: str) -> list[str]:
    try:
        tree = ast.parse(payload, filename=label)
    except (SyntaxError, ValueError) as error:
        raise VerificationError("TEST_AST_INVALID") from error
    all_test_nodes = [
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name.startswith("test_")
    ]
    direct_nodes: list[ast.FunctionDef] = []
    for node in tree.body:
        if not isinstance(node, ast.ClassDef):
            continue
        is_test_case = any(
            (isinstance(base, ast.Name) and base.id == "TestCase")
            or (isinstance(base, ast.Attribute) and base.attr == "TestCase")
            for base in node.bases
        )
        if not is_test_case:
            continue
        direct_nodes.extend(
            child
            for child in node.body
            if isinstance(child, ast.FunctionDef) and child.name.startswith("test_")
        )
    _require(
        bool(direct_nodes)
        and {id(node) for node in all_test_nodes}
        == {id(node) for node in direct_nodes},
        "TEST_ID_NOT_DISCOVERABLE",
    )
    names = [node.name for node in direct_nodes]
    _require(len(names) == len(set(names)), "TEST_ID_DUPLICATE")
    return sorted(names)


def _substitute_lifecycle_tokens(
    command: str, *, freeze_commit: str, implementation_commit: str
) -> list[str]:
    rendered = command.replace("SIGNED_F_COMMIT", freeze_commit).replace(
        "SIGNED_I_COMMIT", implementation_commit
    )
    _require(
        "SIGNED_" not in rendered
        and not any(character in rendered for character in ("\n", "\r", "\0")),
        "HANDOFF_COMMAND_PLACEHOLDER",
    )
    try:
        argv = shlex.split(rendered, posix=True)
    except ValueError as error:
        raise VerificationError("HANDOFF_COMMAND_PARSE") from error
    _require(
        bool(argv)
        and all(0 < len(item.encode("utf-8")) <= 4096 for item in argv)
        and not any(item in {"|", ";", "&&", "||", ">", ">>"} for item in argv),
        "HANDOFF_COMMAND_ARGV",
    )
    return argv


def _qualification_phase(argv: Sequence[str]) -> str:
    joined = "\0".join(argv)
    if PRODUCT_TESTS in argv and "-k" not in argv:
        return "PRODUCT_TESTS"
    if PRODUCT_TOOL in argv and "render" in argv:
        return "PACKET_RENDER"
    if PRODUCT_TOOL in argv and "verify" in argv:
        return "PACKET_VERIFY"
    if REGISTERED_TESTS_PATH in argv:
        if "-k" in argv:
            index = argv.index("-k")
            _require(index + 1 < len(argv), "HANDOFF_COMMAND_PHASE")
            selector = argv[index + 1]
            if selector == "reject":
                return "NEGATIVE_VECTORS"
            if selector == "technique_":
                return "TECHNIQUE_ANALYSIS"
        return "REGISTERED_TESTS"
    if VERIFIER_PATH in argv and "--inventory-only" in argv:
        return "INDEPENDENT_RECONCILIATION"
    raise VerificationError(f"HANDOFF_COMMAND_PHASE:{joined[:256]}")


def _expected_qualification_argv(
    freeze: Mapping[str, Any], freeze_commit: str, implementation_commit: str
) -> list[tuple[str, list[str]]]:
    mapping = freeze.get("handoff_command_mapping")
    _require(isinstance(mapping, list) and bool(mapping), "HANDOFF_COMMAND_MAPPING")
    task_commands: list[tuple[str, list[str]]] = []
    mapping_ids: list[str] = []
    for raw in mapping:
        record = _exact_keys(
            raw,
            {
                "id",
                "source_command",
                "disposition",
                "replacement_commands",
                "evidence_ids",
                "task_boundary",
                "rationale",
            },
            "HANDOFF_COMMAND_MAPPING_KEYS",
        )
        mapping_ids.append(
            _text(record["id"], "HANDOFF_COMMAND_MAPPING_ID", maximum=32)
        )
        _text(record["source_command"], "HANDOFF_SOURCE_COMMAND", maximum=4096)
        _text(record["disposition"], "HANDOFF_DISPOSITION", maximum=128)
        _text(record["rationale"], "HANDOFF_RATIONALE", maximum=8192)
        replacements = _text_list(
            record["replacement_commands"], "HANDOFF_REPLACEMENTS"
        )
        evidence_ids = _text_list(record["evidence_ids"], "HANDOFF_EVIDENCE_IDS")
        _require(
            all(item in EVIDENCE_PATHS for item in evidence_ids),
            "HANDOFF_EVIDENCE_IDS",
        )
        boundary = _text(record["task_boundary"], "HANDOFF_TASK_BOUNDARY", maximum=32)
        if boundary != TASK_ID:
            continue
        for command in replacements:
            argv = _substitute_lifecycle_tokens(
                command,
                freeze_commit=freeze_commit,
                implementation_commit=implementation_commit,
            )
            task_commands.append((_qualification_phase(argv), argv))
    _require(len(mapping_ids) == len(set(mapping_ids)), "HANDOFF_COMMAND_MAPPING_IDS")
    required = (
        "PRODUCT_TESTS",
        "PACKET_RENDER",
        "PACKET_VERIFY",
        "REGISTERED_TESTS",
        "INDEPENDENT_RECONCILIATION",
        "NEGATIVE_VECTORS",
        "TECHNIQUE_ANALYSIS",
    )
    by_phase = {phase: argv for phase, argv in task_commands}
    _require(
        len(by_phase) == len(task_commands) and set(by_phase) == set(required),
        "HANDOFF_COMMAND_COVERAGE",
    )
    ordered = [(phase, by_phase[phase]) for phase in required]
    reconciliation = by_phase["INDEPENDENT_RECONCILIATION"]
    ordered.extend(
        (
            f"RESOURCE_SAMPLE_{number:02d}",
            ["/usr/bin/time", "-l", *reconciliation],
        )
        for number in range(1, RESOURCE_SAMPLE_COUNT + 1)
    )
    return ordered


def _contains_exact_mapping(value: object, expected: Mapping[str, Any]) -> bool:
    if isinstance(value, dict):
        if _strict_equal(value, dict(expected)):
            return True
        return any(_contains_exact_mapping(item, expected) for item in value.values())
    if isinstance(value, list):
        return any(_contains_exact_mapping(item, expected) for item in value)
    return False


def _require_unittest_stream(
    command: Mapping[str, Any], *, expected_tests: int, code: str
) -> float:
    _require(command["stdout"] == "", code)
    match = re.fullmatch(
        rf"{re.escape('.' * expected_tests)}\n-+\n"
        rf"Ran {expected_tests} tests in ([0-9]+(?:\.[0-9]+)?)s\n\nOK\n",
        command["stderr"],
    )
    _require(match is not None, code)
    return _number(float(match.group(1)), code)


def _command_json(command: Mapping[str, Any], code: str) -> dict[str, Any]:
    _require(command["stderr"] == "", code)
    return _parse_canonical_json(command["stdout"].encode("utf-8"), code)


def _resource_metrics(command: Mapping[str, Any]) -> tuple[float, int]:
    real = re.findall(
        r"(?m)^\s*([0-9]+(?:\.[0-9]+)?)\s+real\s+"
        r"[0-9]+(?:\.[0-9]+)?\s+user\s+"
        r"[0-9]+(?:\.[0-9]+)?\s+sys\s*$",
        command["stderr"],
    )
    rss = re.findall(
        r"(?m)^\s*([0-9]+)\s+maximum resident set size\s*$",
        command["stderr"],
    )
    _require(len(real) == 1 and len(rss) == 1, "COMMAND_RESOURCE_MARKERS")
    return _number(float(real[0]), "COMMAND_RESOURCE_REAL"), _integer(
        int(rss[0]), "COMMAND_RESOURCE_RSS", minimum=1
    )


def _validate_command_log(
    document: Mapping[str, Any],
    *,
    freeze: Mapping[str, Any],
    freeze_commit: str,
    implementation_commit: str,
    implementation_result: Mapping[str, Any],
    subjects: Sequence[Mapping[str, Any]],
    lanes: Sequence[Mapping[str, Any]],
    product_tests_payload: bytes,
    registered_tests_payload: bytes,
) -> tuple[dict[str, dict[str, Any]], dict[str, str]]:
    environment = _exact_keys(
        document.get("environment"),
        {"architecture", "git_version", "platform", "python_version"},
        "COMMAND_ENVIRONMENT_KEYS",
    )
    _require(
        environment["python_version"] == "CPython 3.14.6", "COMMAND_PYTHON_VERSION"
    )
    for field in ("architecture", "git_version", "platform"):
        _text(environment[field], "COMMAND_ENVIRONMENT_VALUE", maximum=1024)
    commands = document.get("commands")
    expected = _expected_qualification_argv(
        freeze, freeze_commit, implementation_commit
    )
    _require(
        isinstance(commands, list) and len(commands) == len(expected),
        "COMMAND_LOG_SHAPE",
    )
    by_id: dict[str, dict[str, Any]] = {}
    by_phase: dict[str, str] = {}
    previous_completed = _timestamp(document["started_at_utc"], "COMMAND_LOG_STARTED")
    envelope_completed = _timestamp(
        document["completed_at_utc"], "COMMAND_LOG_COMPLETED"
    )
    for index, (raw, (expected_phase, expected_argv)) in enumerate(
        zip(commands, expected, strict=True), 1
    ):
        command = _exact_keys(
            raw,
            {
                "id",
                "phase",
                "argv",
                "cwd",
                "started_at_utc",
                "completed_at_utc",
                "exit_code",
                "stdout",
                "stdout_sha256",
                "stderr",
                "stderr_sha256",
            },
            "COMMAND_LOG_ENTRY",
        )
        identifier = _text(command["id"], "COMMAND_ID", maximum=128)
        phase = _text(command["phase"], "COMMAND_PHASE", maximum=128)
        _require(
            identifier == f"CH-T002-CMD{index:02d}"
            and phase == expected_phase
            and _strict_equal(command["argv"], expected_argv)
            and command["cwd"] == "."
            and type(command["exit_code"]) is int
            and command["exit_code"] == 0,
            "COMMAND_BINDING",
        )
        started = _timestamp(command["started_at_utc"], "COMMAND_STARTED")
        completed = _timestamp(command["completed_at_utc"], "COMMAND_COMPLETED")
        _require(
            previous_completed <= started <= completed <= envelope_completed,
            "COMMAND_TIME",
        )
        previous_completed = completed
        _hex(command["stdout_sha256"], HEX64, "COMMAND_STDOUT")
        _hex(command["stderr_sha256"], HEX64, "COMMAND_STDERR")
        for stream in ("stdout", "stderr"):
            value = command[stream]
            _require(
                isinstance(value, str)
                and _sha256(value.encode("utf-8")) == command[f"{stream}_sha256"],
                "COMMAND_STREAM_BINDING",
            )
        joined = "\0".join(command["argv"]).casefold()
        retained_streams = (command["stdout"] + "\n" + command["stderr"]).casefold()
        _require(
            not any(
                token in joined or token in retained_streams
                for token in (
                    "anthropic_api_key",
                    "second_anthropic_api_key",
                    "sk-ant-",
                    "authorization:",
                )
            ),
            "COMMAND_SECRET_ARGUMENT",
        )
        _require(command["stdout"] or command["stderr"], "COMMAND_STREAMS_EMPTY")
        by_id[identifier] = command
        by_phase[phase] = identifier
    _require(
        len(by_id) == len(commands) and len(by_phase) == len(commands),
        "COMMAND_DUPLICATE",
    )

    def command(phase: str) -> dict[str, Any]:
        return by_id[by_phase[phase]]

    product_names = _python_test_names(product_tests_payload, PRODUCT_TESTS)
    registered_names = _python_test_names(
        registered_tests_payload, REGISTERED_TESTS_PATH
    )
    _require_unittest_stream(
        command("PRODUCT_TESTS"),
        expected_tests=len(product_names),
        code="COMMAND_PRODUCT_TESTS",
    )
    _require_unittest_stream(
        command("REGISTERED_TESTS"),
        expected_tests=len(registered_names),
        code="COMMAND_REGISTERED_TESTS",
    )
    _require_unittest_stream(
        command("NEGATIVE_VECTORS"),
        expected_tests=sum("reject" in name for name in registered_names),
        code="COMMAND_NEGATIVE_VECTORS",
    )
    _require_unittest_stream(
        command("TECHNIQUE_ANALYSIS"),
        expected_tests=sum("technique_" in name for name in registered_names),
        code="COMMAND_TECHNIQUE_ANALYSIS",
    )
    expected_packet_summary = {
        "command": "render",
        "critical_subjects": sum(bool(subject["criticality"]) for subject in subjects),
        "lane_units": [lane["total_units"] for lane in lanes],
        "packet_count": 3,
        "result": "PASS",
        "review_subjects": len(subjects),
        "subject_set_sha256": implementation_result["subject_set_sha256"],
    }
    _require(
        _strict_equal(
            _command_json(command("PACKET_RENDER"), "COMMAND_PACKET_RENDER"),
            expected_packet_summary,
        ),
        "COMMAND_PACKET_RENDER",
    )
    expected_packet_summary["command"] = "verify"
    _require(
        _strict_equal(
            _command_json(command("PACKET_VERIFY"), "COMMAND_PACKET_VERIFY"),
            expected_packet_summary,
        ),
        "COMMAND_PACKET_VERIFY",
    )
    _require(
        _strict_equal(
            _command_json(
                command("INDEPENDENT_RECONCILIATION"),
                "COMMAND_INDEPENDENT_RECONCILIATION",
            ),
            dict(implementation_result),
        ),
        "COMMAND_INDEPENDENT_RECONCILIATION",
    )
    for number in range(1, RESOURCE_SAMPLE_COUNT + 1):
        resource = command(f"RESOURCE_SAMPLE_{number:02d}")
        _require(
            _strict_equal(
                _parse_canonical_json(
                    resource["stdout"].encode("utf-8"),
                    f"COMMAND_RESOURCE_SAMPLE_{number:02d}",
                ),
                dict(implementation_result),
            ),
            "COMMAND_RESOURCE_RESULT",
        )
        _resource_metrics(resource)
    return by_id, by_phase


def _subject_assignments(
    subjects: Sequence[Mapping[str, Any]],
    lanes: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    primary = {
        subject["subject_id"]: (lane, subject)
        for lane in lanes
        for subject in lane["primary"]
    }
    secondary = {
        subject["subject_id"]: lane for lane in lanes for subject in lane["secondary"]
    }
    records: list[dict[str, Any]] = []
    for subject in subjects:
        lane, _assigned = primary[subject["subject_id"]]
        second = secondary.get(subject["subject_id"])
        records.append(
            {
                "path": subject["path"],
                "primary": {
                    "key_fingerprint": lane["reviewer"]["key_fingerprint"],
                    "lane": lane["number"],
                    "review_requirement_id": lane["reviewer"]["requirement_id"],
                    "reviewer_principal": lane["reviewer"]["principal"],
                },
                "secondary": (
                    None
                    if second is None
                    else {
                        "key_fingerprint": second["reviewer"]["key_fingerprint"],
                        "lane": second["number"],
                        "review_requirement_id": second["reviewer"]["requirement_id"],
                        "reviewer_principal": second["reviewer"]["principal"],
                    }
                ),
                "snapshot_state": "PRESENT_AT_CH_T002_F",
                "subject_id": subject["subject_id"],
            }
        )
    records.sort(key=lambda item: item["subject_id"].encode("ascii"))
    return records


def _assignment_set_digest(assignments: Sequence[Mapping[str, Any]]) -> str:
    return _domain_digest("haldir-ch-t002-assignment-set-v1", assignments)


def _review_binding(
    assignment: Mapping[str, Any],
    *,
    subject_id: str,
    role: str,
    packet_payloads: Mapping[str, bytes],
) -> dict[str, Any]:
    lane = assignment["lane"]
    evidence_id = f"CH-T002-E{9 + lane:02d}"
    return {
        "evidence_id": evidence_id,
        "key_fingerprint": assignment["key_fingerprint"],
        "lane": lane,
        "packet_path": EVIDENCE_PATHS[evidence_id],
        "packet_sha256": _sha256(packet_payloads[evidence_id]),
        "pointer": f"{evidence_id}#{subject_id}:{role}",
        "result": "PASS",
        "review_requirement_id": assignment["review_requirement_id"],
        "reviewer_principal": assignment["reviewer_principal"],
    }


def _expected_completion_records(
    *,
    document_completed_at: str,
    freeze: Mapping[str, Any],
    overlay: Mapping[str, Any],
    subjects: Sequence[Mapping[str, Any]],
    rows: Sequence[Mapping[str, str]],
    assignments: Sequence[Mapping[str, Any]],
    packet_payloads: Mapping[str, bytes],
    freeze_commit: str,
    freeze_tree: str,
    classification_by_path: Mapping[str, Mapping[str, Any]],
) -> list[dict[str, Any]]:
    row_by_path = {row["path"]: row for row in rows}
    assignment_by_subject = {item["subject_id"]: item for item in assignments}
    overlay_paths = {entry["path"] for entry in overlay["entries"]}
    requirement_catalog = list(overlay["scope"]["requirement_catalog"])
    test_catalog = list(overlay["scope"]["test_catalog"])
    records: list[dict[str, Any]] = []
    for subject in subjects:
        subject_id = subject["subject_id"]
        assignment = assignment_by_subject[subject_id]
        primary = _review_binding(
            assignment["primary"],
            subject_id=subject_id,
            role="PRIMARY",
            packet_payloads=packet_payloads,
        )
        secondary = (
            None
            if assignment["secondary"] is None
            else _review_binding(
                assignment["secondary"],
                subject_id=subject_id,
                role="SECONDARY",
                packet_payloads=packet_payloads,
            )
        )
        row = row_by_path.get(subject["path"])
        evidence_pointers = {
            f"CH-T002-E09#{subject_id}:PRIMARY",
            primary["pointer"],
        }
        if secondary is not None:
            evidence_pointers.update(
                {f"CH-T002-E09#{subject_id}:SECONDARY", secondary["pointer"]}
            )
        classification = classification_by_path[subject["path"]]
        if classification["provenance_review_status"] == "CONFIRMED":
            evidence_pointers.add(f"CH-T002-E09#{subject_id}:PROVENANCE")
        if classification["license_review_status"] == "APPROVED":
            evidence_pointers.add(f"CH-T002-E09#{subject_id}:LICENSE")
        if row is None:
            requirements = requirement_catalog
            tests = test_catalog
            assumptions: list[str] = []
            defects: list[str] = []
            completed_at = document_completed_at
        else:
            requirements = list(
                _reference_tokens(
                    row["requirements"], f"E09_REQUIREMENTS:{subject['path']}"
                )
            )
            tests = list(
                _reference_tokens(row["tests"], f"E09_TESTS:{subject['path']}")
            )
            assumptions = list(
                _reference_tokens(
                    row["assumptions"], f"E09_ASSUMPTIONS:{subject['path']}"
                )
            )
            defect_tokens = _reference_tokens(
                row["defects"], f"E09_DEFECTS:{subject['path']}", allow_none=True
            )
            defects = [] if defect_tokens == ("NONE",) else list(defect_tokens)
            completed_at = row["completed_at"]
            _require(
                set(_reference_tokens(row["evidence"], "E09_LEDGER_EVIDENCE"))
                == {
                    item
                    for item in evidence_pointers
                    if item.rsplit(":", 1)[-1] in {"PRIMARY", "SECONDARY"}
                },
                "E09_LEDGER_EVIDENCE",
            )
        provenance = {
            "evidence_pointer": (
                f"CH-T002-E09#{subject_id}:PROVENANCE"
                if classification["provenance_review_status"] == "CONFIRMED"
                else None
            ),
            "status": classification["provenance_review_status"],
        }
        license_record = {
            "evidence_pointer": (
                f"CH-T002-E09#{subject_id}:LICENSE"
                if classification["license_review_status"] == "APPROVED"
                else None
            ),
            "expression": classification["license_expression"],
            "status": classification["license_review_status"],
        }
        review_assignment = {"primary": primary, "secondary": secondary}
        source = "SUPPLEMENTAL_F" if subject["path"] in overlay_paths else "BASE_LEDGER"
        records.append(
            {
                "assignment_sha256": _domain_digest(
                    "haldir-ch-t002-subject-assignment-v1", review_assignment
                ),
                "assumptions": assumptions,
                "completed_at_utc": completed_at,
                "defects": defects,
                "disposition": "ACCEPTED",
                "evidence_pointers": sorted(
                    evidence_pointers, key=lambda item: item.encode("utf-8")
                ),
                "ledger_row_path": subject["path"] if row is not None else None,
                "license": license_record,
                "primary_review": primary,
                "provenance": provenance,
                "requirements": requirements,
                "secondary_review": secondary,
                "source": source,
                "subject": _subject_packet_record(
                    subject, freeze_commit=freeze_commit, freeze_tree=freeze_tree
                ),
                "subject_id": subject_id,
                "tests": tests,
            }
        )
    records.sort(key=lambda item: item["subject_id"].encode("ascii"))
    return records


def _validate_evidence_documents(
    *,
    freeze: Mapping[str, Any],
    overlay: Mapping[str, Any],
    freeze_commit: str,
    freeze_tree: str,
    implementation_commit: str,
    implementation_tree: str,
    evidence_requirements: Sequence[Mapping[str, Any]],
    c_entries: Mapping[str, Mapping[str, Any]],
    c_payloads: Mapping[str, bytes],
    base_entries: Mapping[str, Mapping[str, Any]],
    base_ledger_payload: bytes,
    f_entries: Mapping[str, Mapping[str, Any]],
    f_blobs: Mapping[str, bytes],
    implementation_entries: Mapping[str, Mapping[str, Any]],
    implementation_blobs: Mapping[str, bytes],
    rows: Sequence[Mapping[str, str]],
    subjects: Sequence[Mapping[str, Any]],
    lanes: Sequence[Mapping[str, Any]],
    packet_bodies: Mapping[str, dict[str, Any]],
    packet_manifest: dict[str, Any],
    verifier_payload: bytes,
    registered_tests_payload: bytes,
    product_tool_payload: bytes,
    product_tests_payload: bytes,
    classification_by_path: Mapping[str, Mapping[str, Any]],
) -> dict[str, dict[str, Any]]:
    documents: dict[str, dict[str, Any]] = {}
    raw_product_ids = {
        "CH-T002-E10",
        "CH-T002-E11",
        "CH-T002-E12",
        "CH-T002-E13",
    }
    for requirement in evidence_requirements:
        identifier = requirement["id"]
        path = requirement["path"]
        payload = c_payloads[path]
        document = _parse_canonical_json(
            payload, identifier, maximum=requirement["max_bytes"]
        )
        if identifier not in raw_product_ids:
            _exact_keys(
                document,
                EVIDENCE_COMMON_KEYS | EVIDENCE_SPECIFIC_KEYS[identifier],
                f"EVIDENCE_KEYS:{identifier}",
            )
            _require_common_evidence(
                document,
                identifier=identifier,
                freeze_commit=freeze_commit,
                implementation_commit=implementation_commit,
            )
        documents[identifier] = document

    for lane_index, evidence_id in enumerate(
        ("CH-T002-E10", "CH-T002-E11", "CH-T002-E12"), start=1
    ):
        lane = f"lane-{lane_index:02d}"
        _require(
            _strict_equal(documents[evidence_id], packet_bodies[lane]),
            f"PACKET_EVIDENCE:{lane}",
        )
    _require(
        _strict_equal(documents["CH-T002-E13"], packet_manifest),
        "PACKET_MANIFEST_EVIDENCE",
    )

    implementation_result = {
        "schema_version": "1.0.0",
        "task_id": TASK_ID,
        "epoch": EPOCH,
        "freeze_commit": freeze_commit,
        "implementation_commit": implementation_commit,
        "freeze_tree": freeze_tree,
        "implementation_tree": implementation_tree,
        "ledger_rows": len(rows),
        "review_subjects": len(subjects),
        "critical_subjects": sum(bool(item["criticality"]) for item in subjects),
        "subject_set_sha256": overlay["digests"]["subject_set_sha256"],
        "result": "PASS",
    }
    commands, command_by_phase = _validate_command_log(
        documents["CH-T002-E02"],
        freeze=freeze,
        freeze_commit=freeze_commit,
        implementation_commit=implementation_commit,
        implementation_result=implementation_result,
        subjects=subjects,
        lanes=lanes,
        product_tests_payload=product_tests_payload,
        registered_tests_payload=registered_tests_payload,
    )
    packet_payloads = {
        identifier: c_payloads[EVIDENCE_PATHS[identifier]]
        for identifier in ("CH-T002-E10", "CH-T002-E11", "CH-T002-E12")
    }
    assignments = _subject_assignments(subjects, lanes)
    assignment_digest = _assignment_set_digest(assignments)
    e09 = documents["CH-T002-E09"]
    completion_records = _expected_completion_records(
        document_completed_at=e09["completed_at_utc"],
        freeze=freeze,
        overlay=overlay,
        subjects=subjects,
        rows=rows,
        assignments=assignments,
        packet_payloads=packet_payloads,
        freeze_commit=freeze_commit,
        freeze_tree=freeze_tree,
        classification_by_path=classification_by_path,
    )
    completion_digest = _domain_digest(
        "haldir-ch-t002-file-review-completion-set-v1", completion_records
    )
    packet_set_digest = _domain_digest(
        "haldir-ch-t002-packet-set-v1",
        [
            {
                "evidence_id": identifier,
                "path": EVIDENCE_PATHS[identifier],
                "sha256": _sha256(c_payloads[EVIDENCE_PATHS[identifier]]),
            }
            for identifier in (
                "CH-T002-E10",
                "CH-T002-E11",
                "CH-T002-E12",
                "CH-T002-E13",
            )
        ],
    )
    expected_e09_counts = {
        "base_ledger_subjects": sum(
            item["source"] == "BASE_LEDGER" for item in completion_records
        ),
        "critical_subjects": sum(
            bool(item["subject"]["criticality"]) for item in completion_records
        ),
        "live_subjects": len(completion_records),
        "removed_subjects": 0,
        "review_subjects": len(completion_records),
        "supplemental_subjects": sum(
            item["source"] == "SUPPLEMENTAL_F" for item in completion_records
        ),
    }
    expected_e09_digests = {
        "assignment_set_sha256": assignment_digest,
        "completion_set_sha256": completion_digest,
        "packet_set_sha256": packet_set_digest,
        "subject_set_sha256": overlay["digests"]["subject_set_sha256"],
    }
    _require(
        _strict_equal(e09["completion_records"], completion_records)
        and _strict_equal(e09["counts"], expected_e09_counts)
        and _strict_equal(e09["digests"], expected_e09_digests),
        "E09_COMPLETION_BINDING",
    )

    requirement_ids = list(overlay["scope"]["requirement_catalog"])
    test_ids = list(overlay["scope"]["test_catalog"])
    evidence_ids = list(overlay["scope"]["evidence_catalog"])
    ledger_payload = implementation_blobs[implementation_entries[LEDGER_PATH]["oid"]]
    overlay_payload = implementation_blobs[implementation_entries[OVERLAY_PATH]["oid"]]
    traceability = documents["CH-T002-E01"]
    expected_traceability_counts = {
        "base_rows": len(rows),
        "critical_subjects": sum(bool(item["criticality"]) for item in subjects),
        "evidence_requirements": len(evidence_ids),
        "review_subjects": len(subjects),
        "reviewers": len(freeze["reviewer_registry"]),
    }
    expected_traceability_digests = {
        "assignment_set_sha256": assignment_digest,
        "completion_set_sha256": completion_digest,
        "ledger_sha256": _sha256(ledger_payload),
        "overlay_sha256": _sha256(overlay_payload),
        "packet_set_sha256": packet_set_digest,
        "subject_set_sha256": overlay["digests"]["subject_set_sha256"],
    }
    _require(
        _strict_equal(
            traceability["implementation_plan"],
            [
                {"path": path, "status": status}
                for path, status in EXPECTED_I_DIFF.items()
            ],
        )
        and _strict_equal(traceability["requirement_ids"], requirement_ids)
        and _strict_equal(traceability["test_ids"], test_ids)
        and _strict_equal(traceability["evidence_ids"], evidence_ids)
        and _strict_equal(traceability["immutable_fields"], list(IMMUTABLE_FIELDS))
        and _strict_equal(traceability["mutable_fields"], list(MUTABLE_REVIEW_FIELDS))
        and _strict_equal(traceability["counts"], expected_traceability_counts)
        and _strict_equal(traceability["digests"], expected_traceability_digests),
        "E01_TRACEABILITY_BINDING",
    )

    vectors = documents["CH-T002-E03"]
    controls = freeze["normative_controls"]
    expected_accepted = [
        {
            "requirement_id": item["id"],
            "result": "PASS",
            "test_id": item["accepted_test_id"],
        }
        for item in controls
    ]
    expected_rejected = [
        {
            "requirement_id": item["id"],
            "result": "PASS",
            "test_id": item["rejected_test_id"],
        }
        for item in controls
    ]
    _require(
        _strict_equal(vectors["accepted_vectors"], expected_accepted)
        and _strict_equal(vectors["rejected_vectors"], expected_rejected)
        and _strict_equal(
            vectors["command_ids"],
            [
                command_by_phase["PRODUCT_TESTS"],
                command_by_phase["REGISTERED_TESTS"],
                command_by_phase["NEGATIVE_VECTORS"],
            ],
        ),
        "E03_VECTOR_BINDING",
    )

    technique = documents["CH-T002-E04"]
    expected_techniques = [
        {
            "cases": TECHNIQUE_COVERAGE[name]["cases"],
            "command_ids": [command_by_phase["TECHNIQUE_ANALYSIS"]],
            "limitations": [TECHNIQUE_LIMITATIONS[name]],
            "name": name,
            "requirement_ids": list(TECHNIQUE_COVERAGE[name]["requirement_ids"]),
            "status": "PASS",
            "test_ids": [f"{REGISTERED_TESTS_PATH}::{test_id}"],
        }
        for name, test_id in TECHNIQUE_TEST_IDS.items()
    ]
    technique_requirement_ids = sorted(
        {
            requirement_id
            for coverage in TECHNIQUE_COVERAGE.values()
            for requirement_id in coverage["requirement_ids"]
        }
    )
    technique_test_ids = sorted(
        f"{REGISTERED_TESTS_PATH}::{test_id}" for test_id in TECHNIQUE_TEST_IDS.values()
    )
    registered_names = _python_test_names(
        registered_tests_payload, REGISTERED_TESTS_PATH
    )
    declared_freeze_tests = {
        item[field]
        for collection in (
            freeze["normative_controls"],
            freeze["mandatory_counterfactuals"],
        )
        for item in collection
        for field in ("accepted_test_id", "rejected_test_id")
    }
    _require(
        declared_freeze_tests.issubset(registered_names)
        and all(test_id in registered_names for test_id in TECHNIQUE_TEST_IDS.values())
        and set(technique_requirement_ids).issubset(requirement_ids)
        and _strict_equal(technique["techniques"], expected_techniques)
        and _strict_equal(
            technique["covered_requirement_ids"], technique_requirement_ids
        )
        and _strict_equal(technique["covered_test_ids"], technique_test_ids),
        "E04_TECHNIQUE_BINDING",
    )

    resources = documents["CH-T002-E05"]
    resource_commands = [
        commands[command_by_phase[f"RESOURCE_SAMPLE_{number:02d}"]]
        for number in range(1, RESOURCE_SAMPLE_COUNT + 1)
    ]
    resource_metrics = [_resource_metrics(command) for command in resource_commands]
    declared = {
        "blob_bytes": MAX_BLOB_BYTES,
        "command_seconds": COMMAND_SECONDS,
        "evidence_file_bytes": 4 * 1024 * 1024,
        "git_output_bytes": MAX_GIT_OUTPUT,
        "json_bytes": 256 * 1024,
        "ledger_bytes": MAX_LEDGER_BYTES,
        "packet_bytes": MAX_PACKET_BYTES,
        "resource_samples": RESOURCE_SAMPLE_COUNT,
        "tree_bytes": MAX_TREE_BYTES,
        "verifier_seconds": 10,
    }
    packet_sizes = [
        len(c_payloads[EVIDENCE_PATHS[identifier]])
        for identifier in (
            "CH-T002-E10",
            "CH-T002-E11",
            "CH-T002-E12",
            "CH-T002-E13",
        )
    ]
    observed = {
        "commands": len(commands),
        "largest_blob_bytes": max(
            entry["size"] for entry in implementation_entries.values()
        ),
        "ledger_bytes": len(ledger_payload),
        "overlay_bytes": len(overlay_payload),
        "packet_bytes": max(packet_sizes),
        "peak_rss_bytes": max(item[1] for item in resource_metrics),
        "resource_real_seconds": max(item[0] for item in resource_metrics),
        "review_subjects": len(subjects),
        "tree_total_bytes": sum(
            entry["size"] for entry in implementation_entries.values()
        ),
    }
    distributions = {
        "peak_rss_bytes": [item[1] for item in resource_metrics],
        "resource_real_seconds": [item[0] for item in resource_metrics],
    }
    capacity_disposition = {
        "fallback_permitted": False,
        "hard_ceiling_success_claimed": False,
        "qualified_candidate_only": True,
        "result": "PASS",
    }
    _require(
        _strict_equal(resources["declared_maxima"], declared)
        and _strict_equal(resources["observed_maxima"], observed)
        and _strict_equal(resources["observed_distributions"], distributions)
        and _strict_equal(resources["command_ids"], list(commands))
        and _strict_equal(resources["capacity_disposition"], capacity_disposition)
        and observed["ledger_bytes"] <= declared["ledger_bytes"]
        and observed["packet_bytes"] < declared["packet_bytes"]
        and observed["largest_blob_bytes"] <= declared["blob_bytes"]
        and observed["tree_total_bytes"] <= declared["tree_bytes"]
        and observed["resource_real_seconds"] < declared["verifier_seconds"],
        "E05_RESOURCE_BINDING",
    )

    base_record = {
        **_file_record(LEDGER_PATH, base_entries[LEDGER_PATH], base_ledger_payload),
        "rows": len(rows),
    }
    implementation_files = [
        _central_file_record(
            path,
            implementation_entries[path],
            implementation_blobs[implementation_entries[path]["oid"]],
        )
        for path in EXPECTED_I_DIFF
    ]
    registered_files = [
        _central_file_record(path, f_entries[path], f_blobs[f_entries[path]["oid"]])
        for path in (FREEZE_PATH, REGISTRY_PATH, REGISTERED_TESTS_PATH, VERIFIER_PATH)
    ]
    identities = documents["CH-T002-E06"]
    expected_identity_digests = {
        "assignment_set_sha256": assignment_digest,
        "completion_set_sha256": completion_digest,
        "packet_set_sha256": packet_set_digest,
        "subject_set_sha256": overlay["digests"]["subject_set_sha256"],
    }
    _require(
        identities["baseline_commit"] == BASELINE_COMMIT
        and identities["freeze_tree"] == freeze_tree
        and identities["implementation_tree"] == implementation_tree
        and _strict_equal(identities["base_ledger"], base_record)
        and _strict_equal(identities["implementation_files"], implementation_files)
        and _strict_equal(identities["registered_files"], registered_files)
        and _strict_equal(
            identities["lifecycle_diffs"],
            {
                "baseline_to_freeze": EXPECTED_F_DIFF,
                "freeze_to_implementation": EXPECTED_I_DIFF,
            },
        )
        and _strict_equal(identities["digests"], expected_identity_digests),
        "E06_IDENTITY_BINDING",
    )

    disposition = documents["CH-T002-E07"]
    outcome = freeze["claim_outcomes"][0]
    _require(
        _strict_equal(disposition["claim_outcome"], outcome)
        and _strict_equal(
            disposition["implementation_paths"],
            [
                {"path": path, "status": status}
                for path, status in EXPECTED_I_DIFF.items()
            ],
        )
        and disposition["runtime_surface_changed"] is False
        and disposition["release_authority"] is None
        and disposition["publication_authority"] is None
        and disposition["requirements_complete"] is True
        and outcome["overall_status"] == "NO_GO"
        and outcome["claim_disposition"] == "NO_PUBLIC_CLAIM_CHANGE"
        and outcome["release_qualified_claims"] == [],
        "E07_CLAIM_DISPOSITION",
    )

    assignment_evidence = documents["CH-T002-E08"]
    expected_row_assignments = [
        {"path": row["path"], "reviewer": row["reviewer"]} for row in rows
    ]
    _require(
        _strict_equal(assignment_evidence["assignments"], expected_row_assignments)
        and assignment_evidence["assigned_rows"] == len(rows)
        and assignment_evidence["reviewed_rows"] == len(rows)
        and assignment_evidence["assignment_set_sha256"] == assignment_digest,
        "E08_ASSIGNMENT_BINDING",
    )

    _require(
        _sha256(verifier_payload)
        == next(
            item["sha256"] for item in registered_files if item["path"] == VERIFIER_PATH
        )
        and _sha256(registered_tests_payload)
        == next(
            item["sha256"]
            for item in registered_files
            if item["path"] == REGISTERED_TESTS_PATH
        )
        and _sha256(product_tool_payload)
        == next(
            item["sha256"]
            for item in implementation_files
            if item["path"] == PRODUCT_TOOL
        )
        and _sha256(product_tests_payload)
        == next(
            item["sha256"]
            for item in implementation_files
            if item["path"] == PRODUCT_TESTS
        ),
        "EVIDENCE_PROGRAM_BINDING",
    )
    return documents


def _ssh_fingerprint(repo: Path, public_key: str) -> str:
    with tempfile.NamedTemporaryFile() as key_file:
        key_file.write((public_key + "\n").encode("ascii"))
        key_file.flush()
        stdout, stderr = _run(
            [SSH_KEYGEN_EXECUTABLE, "-E", "sha256", "-lf", key_file.name],
            repo=repo,
            maximum=4096,
        )
    output = (stdout + stderr).strip().split()
    _require(
        len(output) >= 4 and output[0] == b"256" and output[-1] == b"(ED25519)",
        "SSH_FINGERPRINT",
    )
    try:
        fingerprint = output[1].decode("ascii", "strict")
    except UnicodeDecodeError as error:
        raise VerificationError("SSH_FINGERPRINT") from error
    _require(
        re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}", fingerprint) is not None,
        "SSH_FINGERPRINT",
    )
    return fingerprint


def _review_attestation_payload(
    record: Mapping[str, Any], freeze_commit: str, implementation_commit: str
) -> bytes:
    unsigned = {
        key: copy.deepcopy(value)
        for key, value in record.items()
        if key != "detached_signature"
    }
    return _canonical_json_bytes(
        {
            "schema_version": "1.0.0",
            "purpose": "SUCCESSOR_IMPLEMENTATION_QUALIFICATION_REVIEW",
            "task_id": TASK_ID,
            "epoch": EPOCH,
            "freeze_commit": freeze_commit,
            "implementation_commit": implementation_commit,
            "review_record": unsigned,
        }
    )


def _verify_review_signature(
    repo: Path,
    record: Mapping[str, Any],
    registry_entry: Mapping[str, Any],
    *,
    freeze_commit: str,
    implementation_commit: str,
    lead: bool,
) -> None:
    attestation = _exact_keys(
        record.get("detached_signature"),
        {
            "format",
            "namespace",
            "principal",
            "public_key",
            "key_fingerprint",
            "signature",
        },
        "REVIEW_SIGNATURE_FIELDS",
    )
    reviewer = registry_entry["reviewer"]
    namespace = (
        "haldir-automated-lead-support-v2" if lead else "haldir-independent-review-v2"
    )
    _require(
        attestation["format"] == "ssh"
        and attestation["namespace"] == namespace
        and attestation["principal"] == reviewer["principal"]
        and attestation["public_key"] == registry_entry["public_key"]
        and attestation["key_fingerprint"] == registry_entry["key_fingerprint"],
        "REVIEW_SIGNATURE_BINDING",
    )
    signature = attestation["signature"]
    _require(
        isinstance(signature, str)
        and len(signature.encode("utf-8")) <= 16 * 1024
        and signature.startswith("-----BEGIN SSH SIGNATURE-----\n")
        and signature.endswith("-----END SSH SIGNATURE-----\n"),
        "REVIEW_SIGNATURE_ARMOR",
    )
    _require(
        _ssh_fingerprint(repo, registry_entry["public_key"])
        == registry_entry["key_fingerprint"],
        "REVIEW_KEY_FINGERPRINT",
    )
    with tempfile.TemporaryDirectory(prefix="haldir-ch-t002-signature-") as directory:
        root = Path(directory)
        allowed = root / "allowed-signers"
        signature_path = root / "review.sig"
        allowed.write_bytes(
            f"{reviewer['principal']} {registry_entry['public_key']}\n".encode("ascii")
        )
        signature_path.write_bytes(signature.encode("ascii"))
        stdout, stderr = _run(
            [
                SSH_KEYGEN_EXECUTABLE,
                "-Y",
                "verify",
                "-f",
                os.fspath(allowed),
                "-I",
                reviewer["principal"],
                "-n",
                namespace,
                "-s",
                os.fspath(signature_path),
            ],
            repo=repo,
            input_data=_review_attestation_payload(
                record, freeze_commit, implementation_commit
            ),
            maximum=4096,
        )
    expected = (
        f'Good "{namespace}" signature for {reviewer["principal"]} with ED25519 key '
        f"{registry_entry['key_fingerprint']}"
    ).encode("utf-8")
    _require((stdout + stderr).strip() == expected, "REVIEW_SIGNATURE_INVALID")


def _decisive_reproduction_lines(
    *,
    evidence_documents: Mapping[str, Mapping[str, Any]],
    c_payloads: Mapping[str, bytes],
) -> list[str]:
    lines: list[str] = []
    for identifier, _kind, _name in EVIDENCE_SPECS:
        path = EVIDENCE_PATHS[identifier]
        line = f"EVIDENCE {identifier} path={path} sha256={_sha256(c_payloads[path])}"
        if identifier == "CH-T002-E09":
            digests = evidence_documents[identifier]["digests"]
            line += (
                f" subject_set_sha256={digests['subject_set_sha256']}"
                f" assignment_set_sha256={digests['assignment_set_sha256']}"
                f" completion_set_sha256={digests['completion_set_sha256']}"
                f" packet_set_sha256={digests['packet_set_sha256']}"
            )
        elif identifier in {"CH-T002-E10", "CH-T002-E11", "CH-T002-E12"}:
            line += (
                " subject_set_sha256="
                f"{evidence_documents[identifier]['assignment']['subject_set_sha256']}"
            )
        elif identifier == "CH-T002-E13":
            line += (
                " subject_set_sha256="
                f"{evidence_documents[identifier]['subject_set_sha256']}"
            )
        lines.append(line)
    for command in evidence_documents["CH-T002-E02"]["commands"]:
        argv_digest = _sha256(_canonical_json_bytes(command["argv"]))
        lines.append(
            f"COMMAND {command['id']} phase={command['phase']} "
            f"argv_sha256={argv_digest} stdout_sha256={command['stdout_sha256']} "
            f"stderr_sha256={command['stderr_sha256']}"
        )
    return lines


def _validate_automated_review_flags(record: Mapping[str, Any], *, lead: bool) -> None:
    _require(
        record["reviewer"]["classification"]
        == ("AUTOMATED_LEAD_SUPPORT" if lead else "INDEPENDENT_AUTOMATED")
        and record["independent_from_release_author"] is (not lead)
        and record["external"] is False
        and record["human"] is False
        and record["named_human_reviewer"] is False
        and record["release_approver"] is False
        and record["decision"] == "ACCEPT_TECHNICAL_TASK_QUALIFICATION",
        "QUALIFICATION_REVIEW_AUTOMATION_BOUNDARY",
    )


def _validate_reviews(
    repo: Path,
    *,
    freeze: Mapping[str, Any],
    qualification: Mapping[str, Any],
    freeze_commit: str,
    implementation_commit: str,
    f_entries: Mapping[str, Mapping[str, Any]],
    implementation_entries: Mapping[str, Mapping[str, Any]],
    all_blobs: Mapping[str, bytes],
    c_entries: Mapping[str, Mapping[str, Any]],
    c_payloads: Mapping[str, bytes],
    evidence_documents: Mapping[str, Mapping[str, Any]],
) -> None:
    requirements = freeze["review_requirements"]
    registry_by_requirement, _by_fingerprint = _reviewer_maps(freeze)
    records = qualification.get("review_records")
    _require(
        isinstance(records, list) and len(records) == len(requirements),
        "QUALIFICATION_REVIEW_RECORDS",
    )
    changed_records = [
        _central_file_record(
            path,
            implementation_entries[path],
            all_blobs[implementation_entries[path]["oid"]],
        )
        for path in EXPECTED_I_DIFF
    ]
    context_required = {
        FREEZE_PATH,
        REGISTERED_TESTS_PATH,
        REGISTRY_PATH,
        VERIFIER_PATH,
    }
    sessions: set[str] = set()
    decisive_lines = _decisive_reproduction_lines(
        evidence_documents=evidence_documents, c_payloads=c_payloads
    )
    for index, (requirement, record) in enumerate(
        zip(requirements, records, strict=True)
    ):
        review_id = requirement["id"]
        registry_entry = registry_by_requirement[review_id]
        path = requirement["path"]
        payload = c_payloads[path]
        report = _parse_canonical_json(
            payload, review_id, maximum=requirement["max_bytes"]
        )
        report = _exact_keys(
            report,
            {
                "schema_version",
                "task_id",
                "epoch",
                "requirement",
                "reviewer",
                "reviewer_provenance",
                "freeze_commit",
                "implementation_commit",
                "implementation_diff",
                "reviewed_relevant_context",
                "all_changed_lines_reviewed",
                "relevant_unchanged_context_reviewed",
                "decisive_reproduction",
                "findings",
                "limitations",
                "decision",
            },
            "REVIEW_REPORT_KEYS",
        )
        _require(
            report["schema_version"] == "1.0.0"
            and report["task_id"] == TASK_ID
            and report["epoch"] == EPOCH
            and _strict_equal(
                report["requirement"],
                {key: requirement[key] for key in ("id", "kind", "path")},
            )
            and _strict_equal(report["reviewer"], registry_entry["reviewer"])
            and report["freeze_commit"] == freeze_commit
            and report["implementation_commit"] == implementation_commit
            and report["all_changed_lines_reviewed"] is True
            and report["relevant_unchanged_context_reviewed"] is True
            and report["decision"] == "ACCEPT_TECHNICAL_TASK_QUALIFICATION",
            "REVIEW_REPORT_BINDING",
        )
        diff = _exact_keys(
            report["implementation_diff"],
            {"changed_file_records", "deleted_paths", "statuses"},
            "REVIEW_DIFF_KEYS",
        )
        _require(
            _strict_equal(diff["statuses"], EXPECTED_I_DIFF)
            and _strict_equal(diff["changed_file_records"], changed_records)
            and _strict_equal(diff["deleted_paths"], []),
            "REVIEW_DIFF_BINDING",
        )
        context = report["reviewed_relevant_context"]
        _require(isinstance(context, list) and bool(context), "REVIEW_CONTEXT")
        context_paths: set[str] = set()
        for item in context:
            _require(
                isinstance(item, dict) and isinstance(item.get("path"), str),
                "REVIEW_CONTEXT_RECORD",
            )
            context_path = _canonical_path(item["path"])
            _require(
                context_path in f_entries
                and context_path not in EXPECTED_I_DIFF
                and _strict_equal(
                    item,
                    _central_file_record(
                        context_path,
                        f_entries[context_path],
                        all_blobs[f_entries[context_path]["oid"]],
                    ),
                ),
                "REVIEW_CONTEXT_BINDING",
            )
            context_paths.add(context_path)
        _require(context_required.issubset(context_paths), "REVIEW_CONTEXT_SCOPE")
        reproduction = _exact_keys(
            report["decisive_reproduction"],
            {"commands", "evidence_ids", "result"},
            "REVIEW_REPRODUCTION_KEYS",
        )
        _require(
            _strict_equal(
                reproduction["evidence_ids"], [item[0] for item in EVIDENCE_SPECS]
            )
            and _strict_equal(reproduction["commands"], decisive_lines)
            and reproduction["result"] == "PASS",
            "REVIEW_REPRODUCTION",
        )
        provenance = _exact_keys(
            report["reviewer_provenance"],
            {"method", "session_id", "tool", "version"},
            "REVIEW_PROVENANCE",
        )
        for field in provenance:
            _text(provenance[field], "REVIEW_PROVENANCE_TEXT", maximum=1024)
        _require(provenance["session_id"] not in sessions, "REVIEW_SESSION_REUSE")
        sessions.add(provenance["session_id"])
        _require(
            isinstance(report["findings"], list)
            and all(isinstance(item, str) and item for item in report["findings"])
            and isinstance(report["limitations"], list)
            and bool(report["limitations"])
            and all(isinstance(item, str) and item for item in report["limitations"]),
            "REVIEW_TEXT_LISTS",
        )

        record = _exact_keys(
            record,
            {
                "id",
                "kind",
                "file",
                "reviewer",
                "independent_from_release_author",
                "external",
                "human",
                "named_human_reviewer",
                "release_approver",
                "reproduced_decisive_evidence",
                "reviewed_all_changed_lines_and_context",
                "detached_signature",
                "decision",
                "started_at_utc",
                "completed_at_utc",
            },
            "QUALIFICATION_REVIEW_KEYS",
        )
        started = _timestamp(record["started_at_utc"], "QUALIFICATION_REVIEW_STARTED")
        completed = _timestamp(
            record["completed_at_utc"], "QUALIFICATION_REVIEW_COMPLETED"
        )
        lead = index == len(requirements) - 1
        _validate_automated_review_flags(record, lead=lead)
        _require(
            started <= completed
            and record["id"] == review_id
            and record["kind"] == requirement["kind"]
            and _strict_equal(
                record["file"], _file_record(path, c_entries[path], payload)
            )
            and _strict_equal(record["reviewer"], registry_entry["reviewer"])
            and record["reproduced_decisive_evidence"] is True
            and record["reviewed_all_changed_lines_and_context"] is True,
            "QUALIFICATION_REVIEW_BINDING",
        )
        _verify_review_signature(
            repo,
            record,
            registry_entry,
            freeze_commit=freeze_commit,
            implementation_commit=implementation_commit,
            lead=lead,
        )


def _validate_qualification(
    qualification: dict[str, Any],
    *,
    freeze: Mapping[str, Any],
    freeze_commit: str,
    implementation_commit: str,
    f_entries: Mapping[str, Mapping[str, Any]],
    f_blobs: Mapping[str, bytes],
    c_entries: Mapping[str, Mapping[str, Any]],
    c_payloads: Mapping[str, bytes],
) -> str:
    _exact_keys(
        qualification,
        {
            "author",
            "effective_on",
            "epoch",
            "evidence_records",
            "freeze_commit",
            "human_review_boundary",
            "implementation_commit",
            "limitations",
            "persistent_identifier",
            "registered_files",
            "release_authority",
            "release_target",
            "review_finding_dispositions",
            "review_records",
            "schema_version",
            "selected_claim_outcome_id",
            "task_id",
            "twenty_lens_reviews",
        },
        "QUALIFICATION_KEYS",
    )
    _require(
        qualification.get("schema_version") == "1.0.0"
        and qualification.get("task_id") == TASK_ID
        and qualification.get("epoch") == EPOCH
        and qualification.get("release_target") == RELEASE_TARGET
        and qualification.get("author") == AUTHOR
        and qualification.get("persistent_identifier") is None
        and qualification.get("freeze_commit") == freeze_commit
        and qualification.get("implementation_commit") == implementation_commit
        and qualification.get("effective_on")
        == "SIGNED_COMMIT_FIRST_CONTAINING_EXACT_QUALIFICATION_EVIDENCE_AND_REVIEWS"
        and qualification.get("release_authority") is None,
        "QUALIFICATION_IDENTITY",
    )
    selected = qualification.get("selected_claim_outcome_id")
    _require(
        isinstance(selected, str)
        and selected in {item["id"] for item in freeze["claim_outcomes"]},
        "QUALIFICATION_OUTCOME",
    )
    expected_registered = {
        "verifier": _file_record(
            VERIFIER_PATH,
            f_entries[VERIFIER_PATH],
            f_blobs[f_entries[VERIFIER_PATH]["oid"]],
        ),
        "tests": _file_record(
            REGISTERED_TESTS_PATH,
            f_entries[REGISTERED_TESTS_PATH],
            f_blobs[f_entries[REGISTERED_TESTS_PATH]["oid"]],
        ),
        "freeze_contract": _file_record(
            FREEZE_PATH, f_entries[FREEZE_PATH], f_blobs[f_entries[FREEZE_PATH]["oid"]]
        ),
    }
    _require(
        _strict_equal(qualification.get("registered_files"), expected_registered),
        "QUALIFICATION_REGISTERED_FILES",
    )
    evidence_records = qualification.get("evidence_records")
    _require(
        isinstance(evidence_records, list)
        and len(evidence_records) == len(freeze["qualification_evidence_requirements"]),
        "QUALIFICATION_EVIDENCE_RECORDS",
    )
    for record, requirement in zip(
        evidence_records, freeze["qualification_evidence_requirements"], strict=True
    ):
        record = _exact_keys(
            record,
            {
                "completed_at_utc",
                "file",
                "id",
                "kind",
                "result",
                "started_at_utc",
                "subject_commits",
            },
            "QUALIFICATION_EVIDENCE_RECORD_KEYS",
        )
        payload = c_payloads[requirement["path"]]
        started = _timestamp(record["started_at_utc"], "QUALIFICATION_EVIDENCE_STARTED")
        completed = _timestamp(
            record["completed_at_utc"], "QUALIFICATION_EVIDENCE_COMPLETED"
        )
        _require(
            started <= completed
            and record["id"] == requirement["id"]
            and record["kind"] == requirement["kind"]
            and _strict_equal(
                record["file"],
                _file_record(
                    requirement["path"], c_entries[requirement["path"]], payload
                ),
            )
            and _strict_equal(
                record["subject_commits"], [freeze_commit, implementation_commit]
            )
            and record["result"] == "PASS",
            "QUALIFICATION_EVIDENCE_BINDING",
        )
        if requirement["id"] in EVIDENCE_SCHEMA_IDS:
            body = _parse_canonical_json(
                payload, requirement["id"], maximum=requirement["max_bytes"]
            )
            _require(
                body.get("started_at_utc") == started
                and body.get("completed_at_utc") == completed,
                "QUALIFICATION_EVIDENCE_TIME_BINDING",
            )
    boundary = qualification.get("human_review_boundary")
    _require(
        _strict_equal(boundary, EXPECTED_HUMAN_REVIEW_BOUNDARY),
        "QUALIFICATION_REVIEW_BOUNDARY",
    )
    lenses = qualification.get("twenty_lens_reviews")
    evidence_catalog = {item[0] for item in EVIDENCE_SPECS}
    _require(
        isinstance(lenses, dict)
        and len(lenses) == 20
        and list(lenses) == [f"L{index:02d}" for index in range(1, 21)]
        and all(
            isinstance(item, dict)
            and item.get("status") == "RESOLVED"
            and isinstance(item.get("evidence_ids"), list)
            and bool(item["evidence_ids"])
            and all(
                evidence_id in evidence_catalog for evidence_id in item["evidence_ids"]
            )
            for item in lenses.values()
        ),
        "QUALIFICATION_LENSES",
    )
    findings = qualification["review_finding_dispositions"]
    _require(
        isinstance(findings, list)
        and len(findings) == len(REVIEW_SPECS)
        and [item.get("review_id") for item in findings]
        == [item[0] for item in REVIEW_SPECS],
        "QUALIFICATION_FINDINGS",
    )
    for finding in findings:
        finding = _exact_keys(
            finding,
            {
                "disposition",
                "evidence_ids",
                "finding",
                "rationale",
                "residual_limitation",
                "review_id",
            },
            "QUALIFICATION_FINDING_KEYS",
        )
        _require(
            finding["disposition"] == "RESOLVED"
            and isinstance(finding["evidence_ids"], list)
            and bool(finding["evidence_ids"])
            and all(item in evidence_catalog for item in finding["evidence_ids"])
            and finding["residual_limitation"] is None,
            "QUALIFICATION_FINDING",
        )
        _text(finding["finding"], "QUALIFICATION_FINDING_TEXT", maximum=8192)
        _text(finding["rationale"], "QUALIFICATION_FINDING_TEXT", maximum=8192)
    qualification_limitations = _text_list(
        qualification["limitations"],
        "QUALIFICATION_LIMITATIONS",
        minimum=1,
        sorted_unique=True,
    )
    _require(
        HUMAN_REVIEW_LIMITATION in qualification_limitations
        and set(freeze["claim_outcomes"][0]["limitations"]).issubset(
            qualification_limitations
        ),
        "QUALIFICATION_LIMITATIONS",
    )
    return selected


def _validate_activation_command(
    value: object,
    *,
    command_id: str,
    phase: str,
    argv: list[str],
    outer_started: str,
    outer_completed: str,
    previous_completed: str,
) -> dict[str, Any]:
    command = _exact_keys(
        value,
        {
            "argv",
            "completed_at_utc",
            "cwd",
            "exit_code",
            "id",
            "phase",
            "started_at_utc",
            "stderr",
            "stderr_sha256",
            "stdout",
            "stdout_sha256",
        },
        "ACTIVATION_COMMAND_KEYS",
    )
    started = _timestamp(command["started_at_utc"], "ACTIVATION_COMMAND_STARTED")
    completed = _timestamp(command["completed_at_utc"], "ACTIVATION_COMMAND_COMPLETED")
    _require(
        command["id"] == command_id
        and command["phase"] == phase
        and _strict_equal(command["argv"], argv)
        and command["cwd"] == "."
        and type(command["exit_code"]) is int
        and command["exit_code"] == 0
        and outer_started
        <= previous_completed
        <= started
        <= completed
        <= outer_completed,
        "ACTIVATION_COMMAND_BINDING",
    )
    for stream in ("stdout", "stderr"):
        stream_text = command[stream]
        digest = command[f"{stream}_sha256"]
        _require(
            isinstance(stream_text, str)
            and isinstance(digest, str)
            and HEX64.fullmatch(digest) is not None
            and _sha256(stream_text.encode("utf-8")) == digest,
            "ACTIVATION_COMMAND_STREAM",
        )
    _require(command["stdout"] or command["stderr"], "ACTIVATION_COMMAND_EMPTY")
    return command


def _require_wave_gate_result(command: Mapping[str, Any]) -> None:
    lines = command["stdout"].splitlines()
    pass_names = [
        line.removeprefix("  PASS: ") for line in lines if line.startswith("  PASS: ")
    ]
    fail_lines = [line for line in lines if line.startswith("  FAIL: ")]
    summary_lines = [line for line in lines if "P0-R exit gate:" in line]
    epilogue_lines = [
        line for line in lines if "All offline P0-R gates passed." in line
    ]
    _require(
        command["stderr"] == ""
        and pass_names == list(P0R_GATE_NAMES)
        and not fail_lines
        and summary_lines == [P0R_GATE_SUMMARY]
        and epilogue_lines == [P0R_GATE_EPILOGUE]
        and lines[-2:] == [P0R_GATE_SUMMARY, P0R_GATE_EPILOGUE],
        "ACTIVATION_WAVE_COMMAND_RESULT",
    )


def _ci_capture_argv(api_path: str) -> list[str]:
    return [
        GH_EXECUTABLE,
        "api",
        "--hostname",
        "github.com",
        "--method",
        "GET",
        "-H",
        f"Accept: {GH_ACCEPT_HEADER}",
        "-H",
        f"X-GitHub-Api-Version: {GH_API_VERSION}",
        api_path,
    ]


def _retained_ci_payload(
    value: object,
    *,
    kind: str,
    source_url: str,
    api_path: str,
    media_type: str,
    maximum: int,
    outer_started: str,
    outer_completed: str,
    previous_completed: str,
) -> tuple[bytes, str]:
    record = _exact_keys(
        value,
        {
            "bytes",
            "capture_argv",
            "completed_at_utc",
            "content_base64",
            "exit_code",
            "kind",
            "media_type",
            "request_headers",
            "sha256",
            "source_url",
            "started_at_utc",
            "stderr",
            "stderr_sha256",
            "tool_version",
        },
        "ACTIVATION_CI_RETAINED_KEYS",
    )
    started = _timestamp(record["started_at_utc"], "ACTIVATION_CI_CAPTURE_STARTED")
    completed = _timestamp(
        record["completed_at_utc"], "ACTIVATION_CI_CAPTURE_COMPLETED"
    )
    headers = [
        f"Accept: {GH_ACCEPT_HEADER}",
        f"X-GitHub-Api-Version: {GH_API_VERSION}",
    ]
    encoded = record["content_base64"]
    _require(
        record["kind"] == kind
        and record["source_url"] == source_url
        and record["media_type"] == media_type
        and _strict_equal(record["capture_argv"], _ci_capture_argv(api_path))
        and _strict_equal(record["request_headers"], headers)
        and record["tool_version"] == GH_VERSION
        and type(record["exit_code"]) is int
        and record["exit_code"] == 0
        and record["stderr"] == ""
        and record["stderr_sha256"] == _sha256(b"")
        and outer_started
        <= previous_completed
        <= started
        <= completed
        <= outer_completed
        and isinstance(encoded, str)
        and encoded.isascii()
        and len(encoded) <= 4 * ((maximum + 2) // 3),
        "ACTIVATION_CI_RETAINED_IDENTITY",
    )
    try:
        payload = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as error:
        raise VerificationError("ACTIVATION_CI_RETAINED_BASE64") from error
    _require(
        0 < len(payload) <= maximum
        and base64.b64encode(payload).decode("ascii") == encoded
        and _integer(record["bytes"], "ACTIVATION_CI_RETAINED_BYTES") == len(payload)
        and record["sha256"] == _sha256(payload),
        "ACTIVATION_CI_RETAINED_BINDING",
    )
    return payload, completed


def _validate_log_archive(
    payload: bytes,
    *,
    expected_manifest: object | None = None,
    jobs: Sequence[Mapping[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    _require(0 < len(payload) < 2 * 1024 * 1024, "ACTIVATION_ARCHIVE_BOUND")
    job_id_by_name: dict[str, int] = {}
    if jobs is not None:
        _require(
            isinstance(jobs, Sequence) and len(jobs) == len(CI_JOB_NAMES),
            "ACTIVATION_ARCHIVE_JOB_RECORD",
        )
        job_ids: set[int] = set()
        for raw_job in jobs:
            job = _exact_keys(
                raw_job,
                {"conclusion", "job_id", "name"},
                "ACTIVATION_ARCHIVE_JOB_RECORD",
            )
            name = job["name"]
            job_id = job["job_id"]
            _require(
                isinstance(name, str)
                and name in CI_JOB_NAMES
                and name not in job_id_by_name
                and type(job_id) is int
                and job_id > 0
                and job_id not in job_ids
                and job["conclusion"] == "success",
                "ACTIVATION_ARCHIVE_JOB_RECORD",
            )
            job_id_by_name[name] = job_id
            job_ids.add(job_id)
        _require(
            set(job_id_by_name) == set(CI_JOB_NAMES),
            "ACTIVATION_ARCHIVE_JOB_RECORD",
        )
    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            entries = archive.infolist()
            names = [entry.filename for entry in entries]
            _require(
                bool(entries)
                and len(entries) <= 128
                and len(names) == len(set(names))
                and sum(entry.file_size for entry in entries) < 4 * 1024 * 1024,
                "ACTIVATION_ARCHIVE_INVENTORY",
            )
            _portable_unique(names, "ACTIVATION_ARCHIVE_PORTABLE_COLLISION")
            job_names = set(job_id_by_name)
            primary: Counter[str] = Counter()
            primary_ordinals: set[int] = set()
            computed: list[dict[str, Any]] = []
            expanded = 0
            for entry in entries:
                name = _canonical_path(entry.filename)
                path = PurePosixPath(name)
                mode = entry.external_attr >> 16
                _require(
                    not path.is_absolute()
                    and ".." not in path.parts
                    and "\\" not in name
                    and not entry.is_dir()
                    and entry.file_size < 4 * 1024 * 1024
                    and not (entry.flag_bits & 0x1)
                    and entry.compress_type
                    in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
                    and (
                        mode == 0
                        or (
                            stat.S_ISREG(mode)
                            and mode & 0o111 == 0
                            and mode & ~0o100666 == 0
                        )
                    ),
                    "ACTIVATION_ARCHIVE_ENTRY",
                )
                expanded += entry.file_size
                _require(expanded < 4 * 1024 * 1024, "ACTIVATION_ARCHIVE_EXPANDED")
                if entry.file_size:
                    _require(
                        entry.compress_size > 0
                        and entry.file_size <= entry.compress_size * 100 + 1024,
                        "ACTIVATION_ARCHIVE_RATIO",
                    )
                try:
                    content = archive.read(entry)
                except (OSError, RuntimeError, zipfile.BadZipFile) as error:
                    raise VerificationError("ACTIVATION_ARCHIVE_READ") from error
                _require(len(content) == entry.file_size, "ACTIVATION_ARCHIVE_SIZE")
                computed.append(
                    {
                        "bytes": entry.file_size,
                        "crc32": entry.CRC,
                        "method": entry.compress_type,
                        "mode": mode,
                        "name": name,
                        "sha256": _sha256(content),
                    }
                )
                if jobs is not None:
                    matched_job: str | None = None
                    for job_name in job_names:
                        match = re.fullmatch(
                            rf"([0-9]+)_{re.escape(job_name)}\.txt", name
                        )
                        if match is not None:
                            matched_job = job_name
                            _require(
                                entry.file_size > 0, "ACTIVATION_ARCHIVE_PRIMARY_EMPTY"
                            )
                            ordinal = int(match.group(1), 10)
                            _require(
                                ordinal not in primary_ordinals,
                                "ACTIVATION_ARCHIVE_PRIMARY_ORDINALS",
                            )
                            primary_ordinals.add(ordinal)
                            primary[job_name] += 1
                            break
                        if name.startswith(f"{job_name}/"):
                            matched_job = job_name
                            break
                    _require(matched_job is not None, "ACTIVATION_ARCHIVE_JOB_SCOPE")
            _require(archive.testzip() is None, "ACTIVATION_ARCHIVE_CRC")
            if jobs is not None:
                _require(
                    set(job_names) == set(CI_JOB_NAMES)
                    and primary == Counter({name: 1 for name in CI_JOB_NAMES}),
                    "ACTIVATION_ARCHIVE_PRIMARY_SCOPE",
                )
                _require(
                    primary_ordinals == set(range(len(CI_JOB_NAMES))),
                    "ACTIVATION_ARCHIVE_PRIMARY_ORDINALS",
                )
            if expected_manifest is not None:
                _require(
                    _strict_equal(expected_manifest, computed),
                    "ACTIVATION_ARCHIVE_MANIFEST",
                )
            return computed
    except VerificationError:
        raise
    except (OSError, RuntimeError, zipfile.BadZipFile) as error:
        raise VerificationError("ACTIVATION_ARCHIVE_INVALID") from error


def _validate_activation(
    *,
    activation: dict[str, Any],
    selected_outcome: str,
    freeze: Mapping[str, Any],
    freeze_commit: str,
    implementation_commit: str,
    qualification_commit: str,
    activation_entries: Mapping[str, Mapping[str, Any]],
    activation_payloads: Mapping[str, bytes],
    qualification_entry: Mapping[str, Any],
    qualification_payload: bytes,
    verifier_record: Mapping[str, Any],
    tests_record: Mapping[str, Any],
    freeze_tree: str,
    implementation_tree: str,
    rows: Sequence[Mapping[str, str]],
    subjects: Sequence[Mapping[str, Any]],
    lanes: Sequence[Mapping[str, Any]],
    overlay: Mapping[str, Any],
    product_tests_payload: bytes,
    registered_tests_payload: bytes,
) -> dict[str, Any]:
    _exact_keys(
        activation,
        {
            "activation_evidence_records",
            "active_claims_record",
            "author",
            "decision",
            "effective_on",
            "epoch",
            "freeze_commit",
            "implementation_commit",
            "persistent_identifier",
            "qualification_commit",
            "qualification_record",
            "release_target",
            "requirements_record",
            "schema_version",
            "selected_claim_outcome",
            "task_id",
            "verifier_receipt",
        },
        "ACTIVATION_KEYS",
    )
    outcome = next(
        item for item in freeze["claim_outcomes"] if item["id"] == selected_outcome
    )
    _require(
        activation.get("schema_version") == "1.0.0"
        and activation.get("task_id") == TASK_ID
        and activation.get("epoch") == EPOCH
        and activation.get("release_target") == RELEASE_TARGET
        and _strict_equal(activation.get("author"), AUTHOR)
        and activation.get("persistent_identifier") is None
        and activation.get("freeze_commit") == freeze_commit
        and activation.get("implementation_commit") == implementation_commit
        and activation.get("qualification_commit") == qualification_commit
        and activation.get("effective_on")
        == "SIGNED_COMMIT_FIRST_CONTAINING_EXACT_ACTIVATION_RECEIPTS_AND_TRANSITION"
        and _strict_equal(activation.get("selected_claim_outcome"), outcome),
        "ACTIVATION_IDENTITY",
    )
    _require(
        _strict_equal(
            activation.get("decision"),
            {
                "task_status": "VERIFIED",
                "claim_disposition": "NO_PUBLIC_CLAIM_CHANGE",
                "overall_status": "NO_GO",
                "tag_authorized": False,
                "github_release_authorized": False,
                "doi_authorized": False,
                "zenodo_authorized": False,
                "archive_authorized": False,
            },
        ),
        "ACTIVATION_DECISION",
    )
    _require(
        _strict_equal(
            activation.get("qualification_record"),
            _file_record(
                QUALIFICATION_PATH, qualification_entry, qualification_payload
            ),
        ),
        "ACTIVATION_QUALIFICATION_RECORD",
    )
    for name, path in (
        ("requirements_record", REQUIREMENTS_PATH),
        ("active_claims_record", ACTIVE_CLAIMS_PATH),
        ("verifier_receipt", RECEIPT_PATH),
    ):
        _require(
            _strict_equal(
                activation.get(name),
                _file_record(path, activation_entries[path], activation_payloads[path]),
            ),
            f"ACTIVATION_RECORD:{name}",
        )
    evidence_records = activation.get("activation_evidence_records")
    requirements = freeze["activation_evidence_requirements"]
    _require(
        isinstance(evidence_records, list)
        and len(evidence_records) == len(requirements),
        "ACTIVATION_EVIDENCE_RECORDS",
    )
    documents: dict[str, dict[str, Any]] = {}
    times: dict[str, tuple[str, str]] = {}
    file_records: dict[str, dict[str, Any]] = {}
    common_keys = {
        "completed_at_utc",
        "epoch",
        "evidence_id",
        "freeze_commit",
        "implementation_commit",
        "qualification_commit",
        "result",
        "schema_id",
        "started_at_utc",
        "task_id",
    }
    specific_keys = {
        "CH-T002-A01": {"checks", "commands"},
        "CH-T002-A02": {"command", "scope"},
        "CH-T002-A03": {
            "conclusion",
            "head_sha",
            "jobs",
            "log_archive_capture",
            "provider",
            "retained_records",
            "run_attempt",
            "run_id",
            "run_url",
            "workflow_path",
        },
        "CH-T002-A04": {
            "affected_downstreams",
            "disposition",
            "implementation_paths",
            "rationale",
            "runtime_surface_changed",
        },
    }
    for record, requirement in zip(evidence_records, requirements, strict=True):
        path = requirement["path"]
        payload = activation_payloads[path]
        record = _exact_keys(
            record,
            {
                "completed_at_utc",
                "file",
                "id",
                "kind",
                "result",
                "started_at_utc",
                "subject_commit",
            },
            "ACTIVATION_EVIDENCE_RECORD_KEYS",
        )
        started = _timestamp(record["started_at_utc"], "ACTIVATION_EVIDENCE_STARTED")
        completed = _timestamp(
            record["completed_at_utc"], "ACTIVATION_EVIDENCE_COMPLETED"
        )
        expected_file = _file_record(path, activation_entries[path], payload)
        _require(
            0 < len(payload) <= requirement["max_bytes"]
            and started <= completed
            and record["id"] == requirement["id"]
            and record["kind"] == requirement["kind"]
            and _strict_equal(record["file"], expected_file)
            and record["subject_commit"] == qualification_commit
            and record["result"] == "PASS",
            "ACTIVATION_EVIDENCE_BINDING",
        )
        times[requirement["id"]] = (started, completed)
        file_records[requirement["id"]] = expected_file
        if requirement["kind"] == "FULL_LOCKED_CI_LOG_ARCHIVE":
            continue
        else:
            document = _parse_canonical_json(
                payload, requirement["id"], maximum=requirement["max_bytes"]
            )
            _exact_keys(
                document,
                common_keys | specific_keys[requirement["id"]],
                "ACTIVATION_EVIDENCE_BODY_KEYS",
            )
            _require(
                document["schema_id"] == ACTIVATION_SCHEMA_IDS[requirement["id"]]
                and document["task_id"] == TASK_ID
                and document["epoch"] == EPOCH
                and document["freeze_commit"] == freeze_commit
                and document["implementation_commit"] == implementation_commit
                and document["qualification_commit"] == qualification_commit
                and document["evidence_id"] == requirement["id"]
                and document["started_at_utc"] == started
                and document["completed_at_utc"] == completed
                and document["result"] == "PASS",
                "ACTIVATION_EVIDENCE_BODY",
            )
            documents[requirement["id"]] = document

    expected_argv = dict(
        _expected_qualification_argv(freeze, freeze_commit, implementation_commit)
    )
    subsystem = documents["CH-T002-A01"]
    subsystem_checks = [
        "PRODUCT_TESTS",
        "PACKET_VERIFY",
        "REGISTERED_TESTS",
        "EXACT_IMPLEMENTATION_VERIFY",
    ]
    _require(
        _strict_equal(subsystem["checks"], subsystem_checks)
        and isinstance(subsystem["commands"], list)
        and len(subsystem["commands"]) == 4,
        "ACTIVATION_SUBSYSTEM_SCOPE",
    )
    subsystem_argv = {
        "PRODUCT_TESTS": expected_argv["PRODUCT_TESTS"],
        "PACKET_VERIFY": expected_argv["PACKET_VERIFY"],
        "REGISTERED_TESTS": expected_argv["REGISTERED_TESTS"],
        "EXACT_IMPLEMENTATION_VERIFY": expected_argv["INDEPENDENT_RECONCILIATION"],
    }
    subsystem_commands: dict[str, dict[str, Any]] = {}
    previous = times["CH-T002-A01"][0]
    for index, phase in enumerate(subsystem_checks, 1):
        command = _validate_activation_command(
            subsystem["commands"][index - 1],
            command_id=f"CH-T002-A01-CMD{index:02d}",
            phase=phase,
            argv=subsystem_argv[phase],
            outer_started=times["CH-T002-A01"][0],
            outer_completed=times["CH-T002-A01"][1],
            previous_completed=previous,
        )
        subsystem_commands[phase] = command
        previous = command["completed_at_utc"]
    _require_unittest_stream(
        subsystem_commands["PRODUCT_TESTS"],
        expected_tests=len(_python_test_names(product_tests_payload, PRODUCT_TESTS)),
        code="ACTIVATION_PRODUCT_TESTS",
    )
    _require_unittest_stream(
        subsystem_commands["REGISTERED_TESTS"],
        expected_tests=len(
            _python_test_names(registered_tests_payload, REGISTERED_TESTS_PATH)
        ),
        code="ACTIVATION_REGISTERED_TESTS",
    )
    implementation_result = {
        "schema_version": "1.0.0",
        "task_id": TASK_ID,
        "epoch": EPOCH,
        "freeze_commit": freeze_commit,
        "implementation_commit": implementation_commit,
        "freeze_tree": freeze_tree,
        "implementation_tree": implementation_tree,
        "ledger_rows": len(rows),
        "review_subjects": len(subjects),
        "critical_subjects": sum(bool(item["criticality"]) for item in subjects),
        "subject_set_sha256": overlay["digests"]["subject_set_sha256"],
        "result": "PASS",
    }
    _require(
        _strict_equal(
            _command_json(
                subsystem_commands["EXACT_IMPLEMENTATION_VERIFY"],
                "ACTIVATION_EXACT_IMPLEMENTATION",
            ),
            implementation_result,
        ),
        "ACTIVATION_EXACT_IMPLEMENTATION",
    )
    packet_summary = {
        "command": "verify",
        "critical_subjects": implementation_result["critical_subjects"],
        "lane_units": [lane["total_units"] for lane in lanes],
        "packet_count": 3,
        "result": "PASS",
        "review_subjects": len(subjects),
        "subject_set_sha256": overlay["digests"]["subject_set_sha256"],
    }
    _require(
        _strict_equal(
            _command_json(
                subsystem_commands["PACKET_VERIFY"], "ACTIVATION_PACKET_VERIFY"
            ),
            packet_summary,
        ),
        "ACTIVATION_PACKET_VERIFY",
    )

    wave = documents["CH-T002-A02"]
    _require(
        _strict_equal(
            wave["scope"],
            {
                "execution_wave": 0,
                "gate_scope": "FULL_REPOSITORY_LOCKED_GATE_AT_CH_T002_CANDIDATE",
                "remaining_wave_tasks": [
                    f"CH-T{number:03d}" for number in range(3, 13)
                ],
                "wave_acceptance": "NOT_YET_ELIGIBLE",
            },
        ),
        "ACTIVATION_WAVE_SCOPE",
    )
    wave_command = _validate_activation_command(
        wave["command"],
        command_id="CH-T002-A02-CMD01",
        phase="WAVE_GATE",
        argv=list(P0R_GATE_ARGV),
        outer_started=times["CH-T002-A02"][0],
        outer_completed=times["CH-T002-A02"][1],
        previous_completed=times["CH-T002-A02"][0],
    )
    _require_wave_gate_result(wave_command)

    hosted = documents["CH-T002-A03"]
    run_id = _integer(hosted["run_id"], "ACTIVATION_CI_RUN_ID", minimum=1)
    run_attempt = _integer(hosted["run_attempt"], "ACTIVATION_CI_ATTEMPT", minimum=1)
    run_url = f"https://github.com/sepahead/haldir/actions/runs/{run_id}"
    run_api_url = f"https://api.github.com/repos/sepahead/haldir/actions/runs/{run_id}"
    run_api_path = f"repos/sepahead/haldir/actions/runs/{run_id}"
    jobs_api_url = f"{run_api_url}/attempts/{run_attempt}/jobs?per_page=100"
    jobs_api_path = f"{run_api_path}/attempts/{run_attempt}/jobs?per_page=100"
    logs_api_url = f"{run_api_url}/attempts/{run_attempt}/logs"
    logs_api_path = f"{run_api_path}/attempts/{run_attempt}/logs"
    retained = hosted["retained_records"]
    _require(
        isinstance(retained, list) and len(retained) == 2, "ACTIVATION_CI_RETAINED"
    )
    capture_completed = times["CH-T002-A03"][0]
    run_payload, capture_completed = _retained_ci_payload(
        retained[0],
        kind="RUN_API_JSON",
        source_url=run_api_url,
        api_path=run_api_path,
        media_type="application/vnd.github+json",
        maximum=64 * 1024,
        outer_started=times["CH-T002-A03"][0],
        outer_completed=times["CH-T002-A03"][1],
        previous_completed=capture_completed,
    )
    jobs_payload, capture_completed = _retained_ci_payload(
        retained[1],
        kind="ATTEMPT_JOBS_API_JSON",
        source_url=jobs_api_url,
        api_path=jobs_api_path,
        media_type="application/vnd.github+json",
        maximum=64 * 1024,
        outer_started=times["CH-T002-A03"][0],
        outer_completed=times["CH-T002-A03"][1],
        previous_completed=capture_completed,
    )
    run_document = _parse_json(run_payload, "ACTIVATION_CI_RAW_RUN", maximum=64 * 1024)
    jobs_document = _parse_json(
        jobs_payload, "ACTIVATION_CI_RAW_JOBS", maximum=64 * 1024
    )
    _require(
        isinstance(run_document, dict) and isinstance(jobs_document, dict),
        "ACTIVATION_CI_RAW_SHAPE",
    )
    repository = run_document.get("repository")
    run_created = _timestamp(run_document.get("created_at"), "ACTIVATION_CI_CREATED")
    run_updated = _timestamp(run_document.get("updated_at"), "ACTIVATION_CI_UPDATED")
    _require(
        run_document.get("id") == run_id
        and run_document.get("run_attempt") == run_attempt
        and run_document.get("url") == run_api_url
        and run_document.get("html_url") == run_url
        and run_document.get("path") == ".github/workflows/ci.yml"
        and run_document.get("event") == "push"
        and run_document.get("head_branch") == "main"
        and run_document.get("head_sha") == qualification_commit
        and run_document.get("status") == "completed"
        and run_document.get("conclusion") == "success"
        and isinstance(repository, dict)
        and repository.get("full_name") == "sepahead/haldir"
        and run_created <= run_updated <= times["CH-T002-A03"][0],
        "ACTIVATION_CI_RAW_RUN_BINDING",
    )
    raw_jobs = jobs_document.get("jobs")
    _require(
        jobs_document.get("total_count") == len(CI_JOB_NAMES)
        and isinstance(raw_jobs, list)
        and len(raw_jobs) == len(CI_JOB_NAMES),
        "ACTIVATION_CI_RAW_JOB_COUNT",
    )
    raw_by_name: dict[str, dict[str, Any]] = {}
    job_ids: set[int] = set()
    for raw_job in raw_jobs:
        _require(isinstance(raw_job, dict), "ACTIVATION_CI_RAW_JOB")
        name = _text(raw_job.get("name"), "ACTIVATION_CI_RAW_JOB_NAME")
        started = _timestamp(raw_job.get("started_at"), "ACTIVATION_CI_JOB_STARTED")
        completed = _timestamp(
            raw_job.get("completed_at"), "ACTIVATION_CI_JOB_COMPLETED"
        )
        job_id = raw_job.get("id")
        _require(
            name in CI_JOB_NAMES
            and name not in raw_by_name
            and type(job_id) is int
            and job_id > 0
            and job_id not in job_ids
            and raw_job.get("run_id") == run_id
            and raw_job.get("run_attempt") == run_attempt
            and raw_job.get("head_sha") == qualification_commit
            and raw_job.get("status") == "completed"
            and raw_job.get("conclusion") == "success"
            and run_created <= started <= completed <= run_updated,
            "ACTIVATION_CI_RAW_JOB_BINDING",
        )
        job_ids.add(job_id)
        raw_by_name[name] = raw_job
    jobs = hosted["jobs"]
    expected_jobs = [
        {"conclusion": "success", "job_id": raw_by_name[name]["id"], "name": name}
        for name in CI_JOB_NAMES
    ]
    _require(_strict_equal(jobs, expected_jobs), "ACTIVATION_CI_JOBS")
    capture = _exact_keys(
        hosted["log_archive_capture"],
        {
            "artifact_evidence_id",
            "capture_argv",
            "completed_at_utc",
            "entry_manifest",
            "exit_code",
            "file",
            "kind",
            "media_type",
            "request_headers",
            "source_url",
            "started_at_utc",
            "stderr",
            "stderr_sha256",
            "tool_version",
        },
        "ACTIVATION_CI_ARCHIVE_CAPTURE_KEYS",
    )
    capture_started = _timestamp(
        capture["started_at_utc"], "ACTIVATION_CI_ARCHIVE_STARTED"
    )
    capture_ended = _timestamp(
        capture["completed_at_utc"], "ACTIVATION_CI_ARCHIVE_COMPLETED"
    )
    archive_payload = activation_payloads[ACTIVATION_PATHS["CH-T002-A05"]]
    headers = [
        f"Accept: {GH_ACCEPT_HEADER}",
        f"X-GitHub-Api-Version: {GH_API_VERSION}",
    ]
    _require(
        capture["artifact_evidence_id"] == "CH-T002-A05"
        and capture["kind"] == "ATTEMPT_LOG_ARCHIVE_ZIP"
        and capture["source_url"] == logs_api_url
        and capture["media_type"] == "application/zip"
        and _strict_equal(capture["capture_argv"], _ci_capture_argv(logs_api_path))
        and _strict_equal(capture["request_headers"], headers)
        and capture["tool_version"] == GH_VERSION
        and type(capture["exit_code"]) is int
        and capture["exit_code"] == 0
        and capture["stderr"] == ""
        and capture["stderr_sha256"] == _sha256(b"")
        and _strict_equal(capture["file"], file_records["CH-T002-A05"])
        and capture_started == times["CH-T002-A05"][0]
        and capture_ended == times["CH-T002-A05"][1]
        and times["CH-T002-A03"][0]
        <= capture_completed
        <= capture_started
        <= capture_ended
        <= times["CH-T002-A03"][1],
        "ACTIVATION_CI_ARCHIVE_CAPTURE",
    )
    _validate_log_archive(
        archive_payload,
        expected_manifest=capture["entry_manifest"],
        jobs=jobs,
    )
    _require(
        hosted["provider"] == "GITHUB_ACTIONS"
        and hosted["workflow_path"] == ".github/workflows/ci.yml"
        and hosted["head_sha"] == qualification_commit
        and hosted["conclusion"] == "success"
        and hosted["run_url"] == run_url,
        "ACTIVATION_CI_BINDING",
    )

    downstream = documents["CH-T002-A04"]
    _require(
        _strict_equal(
            downstream["implementation_paths"],
            sorted(EXPECTED_I_DIFF, key=lambda item: item.encode("utf-8")),
        )
        and _strict_equal(downstream["affected_downstreams"], [])
        and downstream["runtime_surface_changed"] is False
        and downstream["disposition"]
        == "NO_RUNTIME_OR_EXTERNAL_DOWNSTREAM_CONFORMANCE_CHANGE",
        "ACTIVATION_DOWNSTREAM_BINDING",
    )
    _text(downstream["rationale"], "ACTIVATION_DOWNSTREAM_RATIONALE", maximum=8192)
    expected_receipt = {
        "schema_version": "1.0.0",
        "task_id": TASK_ID,
        "epoch": EPOCH,
        "freeze_commit": freeze_commit,
        "implementation_commit": implementation_commit,
        "qualification_commit": qualification_commit,
        "verifier_sha256": verifier_record["sha256"],
        "tests_sha256": tests_record["sha256"],
        "selected_claim_outcome_id": selected_outcome,
        "result": "PASS",
        "runtime_target_policy": "CENTRAL_VERIFIER_EXECUTES_EXACT_F_BLOBS_AT_D_AND_FROZEN_TRIGGERED_CHANGES",
    }
    receipt = _parse_canonical_json(activation_payloads[RECEIPT_PATH], "RECEIPT")
    _exact_keys(receipt, expected_receipt, "ACTIVATION_RECEIPT_KEYS")
    _require(_strict_equal(receipt, expected_receipt), "ACTIVATION_RECEIPT")
    return expected_receipt


def _require_retained(
    repo: Path,
    *,
    current_commit: str,
    expected_entries: Mapping[str, Mapping[str, Any]],
) -> None:
    current = _selected_tree_entries(repo, current_commit, expected_entries)
    _require(set(current) == set(expected_entries), "CURRENT_RETAINED_MISSING")
    for path, entry in expected_entries.items():
        _require(
            current[path]
            == {key: entry[key] for key in ("mode", "type", "oid", "size")},
            f"CURRENT_RETAINED_DRIFT:{path}",
        )


def _require_linear_history(repo: Path, start: str, current: str) -> None:
    history = _first_parent(repo, current)
    try:
        index = history.index(start)
    except ValueError as error:
        raise VerificationError("START_NOT_ANCESTOR") from error
    segment = history[:index]
    raw = _git(
        repo,
        [
            "rev-list",
            "--parents",
            f"--max-count={MAX_FIRST_PARENT_COMMITS}",
            f"{start}..{current}",
        ],
        maximum=MAX_FIRST_PARENT_COMMITS * 128,
    )
    try:
        lines = raw.decode("ascii", "strict").splitlines()
    except UnicodeDecodeError as error:
        raise VerificationError("LINEAR_HISTORY_ENCODING") from error
    for line in lines:
        fields = line.split()
        _require(
            len(fields) == 2 and all(HEX40.fullmatch(item) for item in fields),
            "LINEAR_HISTORY_MERGE",
        )
    _require(len(lines) == len(segment), "LINEAR_HISTORY_SHAPE")


def _implementation_state(
    repo: Path, freeze_commit: str, implementation_commit: str
) -> dict[str, Any]:
    _require(not unresolved_lifecycle_fields(), "UNRESOLVED_LIFECYCLE_FIELDS")
    _require(
        all(HEX40.fullmatch(item) for item in (freeze_commit, implementation_commit))
        and freeze_commit != implementation_commit,
        "IMPLEMENTATION_ARGUMENTS",
    )
    _require(
        _git(repo, ["rev-parse", "--show-object-format"], maximum=32) == b"sha1\n",
        "OBJECT_FORMAT",
    )
    parents = _commit_parents(repo, [freeze_commit, implementation_commit])
    _require(parents[freeze_commit] == BASELINE_COMMIT, "F_PARENT")
    _require(parents[implementation_commit] == freeze_commit, "I_PARENT")
    _require(
        _commit_subject(repo, freeze_commit) == EXPECTED_COMMIT_SUBJECTS["F"]
        and _commit_subject(repo, implementation_commit)
        == EXPECTED_COMMIT_SUBJECTS["I"],
        "F_I_COMMIT_SUBJECT",
    )
    baseline_history = _first_parent(repo, BASELINE_COMMIT)
    _require(
        CH_T001_IMPLEMENTATION_COMMIT in baseline_history, "BASE_PARTITION_NOT_ANCESTOR"
    )
    _require(_diff(repo, BASELINE_COMMIT, freeze_commit) == EXPECTED_F_DIFF, "F_DIFF")
    _require(
        _diff(repo, freeze_commit, implementation_commit) == EXPECTED_I_DIFF, "I_DIFF"
    )

    base_tree, base_entries = _tree(repo, CH_T001_IMPLEMENTATION_COMMIT)
    _require(base_tree == CH_T001_IMPLEMENTATION_TREE, "BASE_TREE")
    _require(
        len(base_entries) == EXPECTED_LEDGER_ROWS
        and base_entries[LEDGER_PATH]["oid"] == CH_T001_LEDGER_OBJECT_ID,
        "BASE_LEDGER_TREE_BINDING",
    )
    freeze_tree, f_entries = _tree(repo, freeze_commit)
    implementation_tree, implementation_entries = _tree(repo, implementation_commit)
    _require(
        all(
            path in f_entries
            and f_entries[path]["mode"] == "100644"
            and f_entries[path]["type"] == "blob"
            for path in EXPECTED_F_DIFF
        ),
        "F_PLANNED_PATH",
    )
    _require(
        all(
            f_entries[path]["size"] <= CENTRAL_ARTIFACT_BYTES
            for path in (
                FREEZE_PATH,
                REGISTRY_PATH,
                REGISTERED_TESTS_PATH,
                VERIFIER_PATH,
            )
        ),
        "CENTRAL_ARTIFACT_BOUND",
    )
    _require(
        set(implementation_entries)
        == set(f_entries) | (set(EXPECTED_I_DIFF) - set(f_entries)),
        "I_TREE_PATH_SET",
    )
    for path, f_entry in f_entries.items():
        if path not in EXPECTED_I_DIFF:
            _require(
                implementation_entries[path] == f_entry, f"I_UNPLANNED_DRIFT:{path}"
            )
    for path in EXPECTED_I_DIFF:
        _require(
            path in implementation_entries
            and implementation_entries[path]["mode"] == "100644"
            and implementation_entries[path]["type"] == "blob",
            f"I_PLANNED_PATH:{path}",
        )
    _require(
        f_entries[LEDGER_PATH]["oid"] == CH_T001_LEDGER_OBJECT_ID,
        "F_BASE_LEDGER_NOT_RETAINED",
    )

    baseline_registry_entry = _selected_tree_entries(
        repo, BASELINE_COMMIT, [REGISTRY_PATH]
    )
    _require(set(baseline_registry_entry) == {REGISTRY_PATH}, "BASE_REGISTRY_MISSING")
    object_ids = {entry["oid"] for entry in f_entries.values()}
    object_ids.update(entry["oid"] for entry in base_entries.values())
    object_ids.update(implementation_entries[path]["oid"] for path in EXPECTED_I_DIFF)
    object_ids.add(base_entries[LEDGER_PATH]["oid"])
    object_ids.add(baseline_registry_entry[REGISTRY_PATH]["oid"])
    blobs = _blobs(repo, object_ids)

    freeze_payload = blobs[f_entries[FREEZE_PATH]["oid"]]
    verifier_payload = blobs[f_entries[VERIFIER_PATH]["oid"]]
    tests_payload = blobs[f_entries[REGISTERED_TESTS_PATH]["oid"]]
    registry_payload = blobs[f_entries[REGISTRY_PATH]["oid"]]
    base_registry_payload = blobs[baseline_registry_entry[REGISTRY_PATH]["oid"]]
    freeze = _parse_pretty_json(freeze_payload, "FREEZE", maximum=256 * 1024)
    registry = _parse_pretty_json(registry_payload, "REGISTRY", maximum=256 * 1024)
    base_registry = _parse_pretty_json(
        base_registry_payload, "BASE_REGISTRY", maximum=256 * 1024
    )
    _require(
        isinstance(freeze, dict)
        and isinstance(registry, dict)
        and isinstance(base_registry, dict),
        "F_JSON_SHAPE",
    )
    evidence_requirements, review_requirements, activation_requirements = (
        _validate_freeze(freeze)
    )
    _validate_registration(
        registry,
        base_registry,
        f_entries=f_entries,
        f_blobs=blobs,
    )

    overlay_payload = blobs[implementation_entries[OVERLAY_PATH]["oid"]]
    overlay = _parse_canonical_json(overlay_payload, "OVERLAY")
    classification_by_path = _validate_classification_contract(
        overlay, f_entries, base_entries
    )
    catalogs, _overlay_entries = _validate_overlay_structure(
        overlay,
        freeze=freeze,
        freeze_commit=freeze_commit,
        freeze_tree=freeze_tree,
        registry_entry=f_entries[FREEZE_PATH],
        registry_payload=freeze_payload,
        classification_by_path=classification_by_path,
    )
    base_ledger_payload = blobs[CH_T001_LEDGER_OBJECT_ID]
    completed_ledger_payload = blobs[implementation_entries[LEDGER_PATH]["oid"]]
    lane_principals = {
        item["reviewer"]["principal"] for item in freeze["reviewer_registry"][:3]
    }
    base_rows, rows = validate_completed_ledger(
        base_ledger_payload,
        completed_ledger_payload,
        reviewer_principals=lane_principals,
        classification_by_path=classification_by_path,
    )
    subjects = reconcile_subjects(
        repo,
        overlay=overlay,
        base_rows=base_rows,
        rows=rows,
        f_entries=f_entries,
        f_blobs=blobs,
        implementation_commit=implementation_commit,
        implementation_tree=implementation_tree,
        implementation_entries=implementation_entries,
        implementation_blobs=blobs,
        classification_by_path=classification_by_path,
    )
    _validate_catalog_bindings(rows, catalogs, classification_by_path, subjects)
    lanes = assign_subjects(
        subjects,
        freeze=freeze,
        overlay=overlay,
        rows=rows,
        classification_by_path=classification_by_path,
    )
    packet_bodies, packet_manifest = build_packet_bodies(
        subjects=subjects,
        lanes=lanes,
        overlay=overlay,
        freeze_commit=freeze_commit,
        freeze_tree=freeze_tree,
        implementation_commit=implementation_commit,
        implementation_tree=implementation_tree,
        implementation_entries=implementation_entries,
        implementation_blobs=blobs,
        registry_entry=f_entries[FREEZE_PATH],
        registry_payload=freeze_payload,
    )
    return {
        "freeze_tree": freeze_tree,
        "implementation_tree": implementation_tree,
        "base_entries": base_entries,
        "f_entries": f_entries,
        "implementation_entries": implementation_entries,
        "blobs": blobs,
        "freeze": freeze,
        "evidence_requirements": evidence_requirements,
        "review_requirements": review_requirements,
        "activation_requirements": activation_requirements,
        "overlay": overlay,
        "classification_by_path": classification_by_path,
        "rows": rows,
        "subjects": subjects,
        "lanes": lanes,
        "packet_bodies": packet_bodies,
        "packet_manifest": packet_manifest,
        "verifier_record": _file_record(
            VERIFIER_PATH, f_entries[VERIFIER_PATH], verifier_payload
        ),
        "tests_record": _file_record(
            REGISTERED_TESTS_PATH, f_entries[REGISTERED_TESTS_PATH], tests_payload
        ),
    }


@_bounded_verification
def verify_implementation(
    repo: Path, freeze_commit: str, implementation_commit: str
) -> dict[str, Any]:
    started = time.monotonic()
    state = _implementation_state(repo, freeze_commit, implementation_commit)
    _require(time.monotonic() - started < VERIFIER_SECONDS, "VERIFIER_TIME_BOUND")
    return {
        "schema_version": "1.0.0",
        "task_id": TASK_ID,
        "epoch": EPOCH,
        "freeze_commit": freeze_commit,
        "implementation_commit": implementation_commit,
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


@_bounded_verification
def verify_repository(
    repo: Path,
    freeze_commit: str,
    implementation_commit: str,
    qualification_commit: str,
    activation_commit: str,
    current_commit: str,
) -> dict[str, Any]:
    started = time.monotonic()
    commits = (
        freeze_commit,
        implementation_commit,
        qualification_commit,
        activation_commit,
        current_commit,
    )
    _require(all(HEX40.fullmatch(item) for item in commits), "FULL_ARGUMENTS")
    state = _implementation_state(repo, freeze_commit, implementation_commit)
    parents = _commit_parents(
        repo,
        [freeze_commit, implementation_commit, qualification_commit, activation_commit],
    )
    _require(parents[qualification_commit] == implementation_commit, "C_PARENT")
    _require(parents[activation_commit] == qualification_commit, "D_PARENT")
    _require(
        _commit_subject(repo, qualification_commit) == EXPECTED_COMMIT_SUBJECTS["C"]
        and _commit_subject(repo, activation_commit) == EXPECTED_COMMIT_SUBJECTS["D"],
        "C_D_COMMIT_SUBJECT",
    )
    history = _first_parent(repo, current_commit)
    try:
        d_index = history.index(activation_commit)
    except ValueError as error:
        raise VerificationError("D_NOT_ANCESTOR") from error
    _require(
        history[d_index : d_index + 4]
        == [
            activation_commit,
            qualification_commit,
            implementation_commit,
            freeze_commit,
        ],
        "LIFECYCLE_NOT_ADJACENT",
    )
    _require_linear_history(repo, activation_commit, current_commit)

    c_expected = {QUALIFICATION_PATH: "A"}
    c_expected.update({item["path"]: "A" for item in state["evidence_requirements"]})
    c_expected.update({item["path"]: "A" for item in state["review_requirements"]})
    d_expected = {
        ACTIVATION_PATH: "A",
        RECEIPT_PATH: "A",
        REQUIREMENTS_PATH: "M",
        ACTIVE_CLAIMS_PATH: "M",
    }
    d_expected.update({item["path"]: "A" for item in state["activation_requirements"]})
    _require(
        _diff(repo, implementation_commit, qualification_commit)
        == dict(sorted(c_expected.items())),
        "C_DIFF",
    )
    _require(
        _diff(repo, qualification_commit, activation_commit)
        == dict(sorted(d_expected.items())),
        "D_DIFF",
    )

    c_entries = _selected_tree_entries(repo, qualification_commit, c_expected)
    d_entries = _selected_tree_entries(repo, activation_commit, d_expected)
    _require(
        set(c_entries) == set(c_expected) and set(d_entries) == set(d_expected),
        "C_D_PATH_MISSING",
    )
    _require(
        all(
            entry["mode"] == "100644"
            for entry in (*c_entries.values(), *d_entries.values())
        ),
        "C_D_FILE_MODE",
    )
    extra_blobs = _blobs(
        repo,
        {
            *(entry["oid"] for entry in c_entries.values()),
            *(entry["oid"] for entry in d_entries.values()),
        },
    )
    all_blobs = {**state["blobs"], **extra_blobs}
    c_payloads = {path: all_blobs[entry["oid"]] for path, entry in c_entries.items()}
    d_payloads = {path: all_blobs[entry["oid"]] for path, entry in d_entries.items()}
    qualification_payload = c_payloads[QUALIFICATION_PATH]
    qualification = _parse_canonical_json(qualification_payload, "QUALIFICATION")
    selected_outcome = _validate_qualification(
        qualification,
        freeze=state["freeze"],
        freeze_commit=freeze_commit,
        implementation_commit=implementation_commit,
        f_entries=state["f_entries"],
        f_blobs=all_blobs,
        c_entries=c_entries,
        c_payloads=c_payloads,
    )
    evidence_documents = _validate_evidence_documents(
        freeze=state["freeze"],
        overlay=state["overlay"],
        freeze_commit=freeze_commit,
        freeze_tree=state["freeze_tree"],
        implementation_commit=implementation_commit,
        implementation_tree=state["implementation_tree"],
        evidence_requirements=state["evidence_requirements"],
        c_entries=c_entries,
        c_payloads=c_payloads,
        base_entries=state["base_entries"],
        base_ledger_payload=all_blobs[CH_T001_LEDGER_OBJECT_ID],
        f_entries=state["f_entries"],
        f_blobs=all_blobs,
        implementation_entries=state["implementation_entries"],
        implementation_blobs=all_blobs,
        rows=state["rows"],
        subjects=state["subjects"],
        lanes=state["lanes"],
        packet_bodies=state["packet_bodies"],
        packet_manifest=state["packet_manifest"],
        verifier_payload=all_blobs[state["f_entries"][VERIFIER_PATH]["oid"]],
        registered_tests_payload=all_blobs[
            state["f_entries"][REGISTERED_TESTS_PATH]["oid"]
        ],
        product_tool_payload=all_blobs[
            state["implementation_entries"][PRODUCT_TOOL]["oid"]
        ],
        product_tests_payload=all_blobs[
            state["implementation_entries"][PRODUCT_TESTS]["oid"]
        ],
        classification_by_path=state["classification_by_path"],
    )
    _validate_reviews(
        repo,
        freeze=state["freeze"],
        qualification=qualification,
        freeze_commit=freeze_commit,
        implementation_commit=implementation_commit,
        f_entries=state["f_entries"],
        implementation_entries=state["implementation_entries"],
        all_blobs=all_blobs,
        c_entries=c_entries,
        c_payloads=c_payloads,
        evidence_documents=evidence_documents,
    )
    activation_payload = d_payloads[ACTIVATION_PATH]
    activation = _parse_canonical_json(activation_payload, "ACTIVATION")
    _validate_activation(
        activation=activation,
        selected_outcome=selected_outcome,
        freeze=state["freeze"],
        freeze_commit=freeze_commit,
        implementation_commit=implementation_commit,
        qualification_commit=qualification_commit,
        activation_entries=d_entries,
        activation_payloads=d_payloads,
        qualification_entry=c_entries[QUALIFICATION_PATH],
        qualification_payload=qualification_payload,
        verifier_record=state["verifier_record"],
        tests_record=state["tests_record"],
        freeze_tree=state["freeze_tree"],
        implementation_tree=state["implementation_tree"],
        rows=state["rows"],
        subjects=state["subjects"],
        lanes=state["lanes"],
        overlay=state["overlay"],
        product_tests_payload=all_blobs[
            state["implementation_entries"][PRODUCT_TESTS]["oid"]
        ],
        registered_tests_payload=all_blobs[
            state["f_entries"][REGISTERED_TESTS_PATH]["oid"]
        ],
    )

    retained: dict[str, Mapping[str, Any]] = {
        path: state["f_entries"][path]
        for path in (FREEZE_PATH, REGISTERED_TESTS_PATH, VERIFIER_PATH)
    }
    retained.update(
        {path: state["implementation_entries"][path] for path in EXPECTED_I_DIFF}
    )
    retained.update(c_entries)
    retained.update(
        {
            path: entry
            for path, entry in d_entries.items()
            if path not in {REQUIREMENTS_PATH, ACTIVE_CLAIMS_PATH}
        }
    )
    _require_retained(repo, current_commit=current_commit, expected_entries=retained)
    _require(time.monotonic() - started < VERIFIER_SECONDS, "VERIFIER_TIME_BOUND")
    return {
        "schema_version": "1.0.0",
        "task_id": TASK_ID,
        "epoch": EPOCH,
        "freeze_commit": freeze_commit,
        "implementation_commit": implementation_commit,
        "qualification_commit": qualification_commit,
        "activation_commit": activation_commit,
        "current_commit": current_commit,
        "verifier_sha256": state["verifier_record"]["sha256"],
        "tests_sha256": state["tests_record"]["sha256"],
        "selected_claim_outcome_id": selected_outcome,
        "result": "PASS",
    }


def _parse_git_toplevel(payload: bytes) -> Path:
    _require(
        len(payload) <= MAX_PATH_BYTES + 1
        and payload.endswith(b"\n")
        and payload.count(b"\n") == 1
        and b"\0" not in payload,
        "REPOSITORY_TOPLEVEL",
    )
    try:
        text = payload[:-1].decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        raise VerificationError("REPOSITORY_TOPLEVEL") from error
    parsed = Path(text)
    _require(
        parsed.is_absolute()
        and Path(os.path.abspath(text)) == parsed
        and unicodedata.normalize("NFC", text) == text,
        "REPOSITORY_TOPLEVEL",
    )
    return parsed


def _bind_git_toplevel(repo: Path) -> Path:
    lexical = Path(os.path.abspath(os.fspath(repo)))
    try:
        lexical_stat = os.lstat(lexical)
    except OSError as error:
        raise VerificationError("REPOSITORY_DIRECTORY") from error
    _require(
        stat.S_ISDIR(lexical_stat.st_mode) and not stat.S_ISLNK(lexical_stat.st_mode),
        "REPOSITORY_DIRECTORY",
    )
    top = _parse_git_toplevel(
        _git(
            lexical,
            ["rev-parse", "--path-format=absolute", "--show-toplevel"],
            maximum=MAX_PATH_BYTES + 1,
        )
    )
    real = Path(os.path.realpath(lexical))
    _require(top == real, "REPOSITORY_NOT_EXACT_TOPLEVEL")
    try:
        bound_stat = os.lstat(top)
    except OSError as error:
        raise VerificationError("REPOSITORY_DIRECTORY") from error
    _require(
        stat.S_ISDIR(bound_stat.st_mode)
        and not stat.S_ISLNK(bound_stat.st_mode)
        and (lexical_stat.st_dev, lexical_stat.st_ino)
        == (bound_stat.st_dev, bound_stat.st_ino),
        "REPOSITORY_NOT_EXACT_TOPLEVEL",
    )
    return top


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--freeze-commit", required=True)
    parser.add_argument("--implementation-commit", required=True)
    parser.add_argument("--qualification-commit")
    parser.add_argument("--activation-commit")
    parser.add_argument("--current-commit")
    parser.add_argument("--inventory-only", action="store_true")
    return parser.parse_args()


def main() -> int:
    arguments = _arguments()
    repo = _bind_git_toplevel(arguments.repo)
    if arguments.inventory_only:
        _require(
            arguments.qualification_commit is None
            and arguments.activation_commit is None
            and arguments.current_commit is None,
            "INVENTORY_ONLY_ARGUMENTS",
        )
        output = verify_implementation(
            repo, arguments.freeze_commit, arguments.implementation_commit
        )
    else:
        _require(
            all(
                isinstance(item, str) and bool(item)
                for item in (
                    arguments.qualification_commit,
                    arguments.activation_commit,
                    arguments.current_commit,
                )
            ),
            "FULL_ARGUMENTS",
        )
        output = verify_repository(
            repo,
            arguments.freeze_commit,
            arguments.implementation_commit,
            arguments.qualification_commit,
            arguments.activation_commit,
            arguments.current_commit,
        )
    sys.stdout.write(json.dumps(output, sort_keys=True, separators=(",", ":")) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
