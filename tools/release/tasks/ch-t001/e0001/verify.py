#!/usr/bin/env python3
"""Independently verify the frozen CH-T001 inventory qualification.

This registered verifier never imports or executes the product ledger helper.
It reconstructs the capture from Git objects, checks the exact F/I/C/D chain,
and permits later ledger edits only in the frozen review columns.
"""

from __future__ import annotations

import argparse
import ast
import base64
import binascii
import csv
import hashlib
import io
import json
import math
import os
import re
import selectors
import stat
import subprocess
import sys
import tempfile
import time
import unicodedata
import zipfile
from collections import Counter
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Sequence


TASK_ID = "CH-T001"
EPOCH = 1
BASELINE_COMMIT = "486c519082c7941575ea658e2290955fbd4ad553"
GITIGNORE_PATH = ".gitignore"
LEDGER_PATH = "audit/generated/FILE_REVIEW_LEDGER.csv"
PRODUCT_TOOL = "tools/release/current-file-review-ledger.py"
PRODUCT_TESTS = "tools/release/test_current_file_review_ledger.py"
EXPECTED_PRODUCT_SHA256 = {
    PRODUCT_TOOL: "56b8af777db52e6c1e721bcdae92636f84c4ded8a1b3bdfbc85689d2835910d7",
    PRODUCT_TESTS: "75ef5ac0bcf26c5a0a391306055dd226d14e1002958a7f763aa23c2a7b589192",
}
EXPECTED_PRODUCT_TEST_IDS = frozenset(
    {
        "test_atomic_noreplace_unavailable_fails_without_fallback",
        "test_bounded_integer_types_and_render_schema_are_exact",
        "test_category_rules_have_explicit_test_basename_precedence",
        "test_check_ignore_input_bound_and_contradiction_are_deterministic",
        "test_chunk_read_deadline_is_checked_before_every_read",
        "test_cli_and_ast_contain_no_replace_exchange_lock_or_rollback_authority",
        "test_cli_retention_verifies_exact_implementation_commit",
        "test_cli_round_trip_and_review_gate_exit_codes",
        "test_complete_inventory_is_deterministic_and_initially_unassigned",
        "test_concurrent_creators_allow_at_most_one_success_without_clobber",
        "test_conflict_plus_temporary_close_eio_keeps_typed_retention_report",
        "test_content_classification_and_digest_domains_are_strict",
        "test_create_absent_target_is_fsynced_and_exact",
        "test_create_refuses_every_existing_target_type_untouched",
        "test_current_verification_rejects_between_pass_worktree_change",
        "test_current_verification_rejects_ledger_change_during_inventory",
        "test_current_worktree_change_invalidates_existing_ledger",
        "test_deadline_at_rename_boundary_preserves_prepublication_state",
        "test_duplicate_header_key_and_noncanonical_encoding_are_rejected",
        "test_duplicate_traversal_git_admin_and_case_paths_are_rejected",
        "test_every_descriptor_closes_once_without_reused_fd_close",
        "test_every_mutable_cell_enforces_unicode_and_byte_grammar",
        "test_exact_implementation_snapshot_survives_later_protocol_files",
        "test_expired_deadline_during_rename_preserves_unknown_outcome",
        "test_final_verification_rejects_late_reserved_temporary",
        "test_format_is_content_aware_and_ansi_logs_preserve_lines",
        "test_generate_binds_created_state_before_delivering_sigint",
        "test_generate_preserves_typed_state_for_combined_postrename_faults",
        "test_generate_preserves_unknown_rename_outcome_wording",
        "test_generate_rejects_between_pass_worktree_change",
        "test_generated_defaults_require_frozen_positive_proof",
        "test_git_configuration_and_process_environment_are_isolated",
        "test_git_output_bounds_and_toplevel_parser_fail_closed",
        "test_git_timeout_kills_and_reaps_child_process",
        "test_gitlink_source_and_index_references_round_trip",
        "test_ignored_policy_defaults_to_reject_and_records_exact_rule",
        "test_immutable_identity_tamper_is_rejected",
        "test_independent_walk_rejects_git_omission",
        "test_intent_to_add_and_extended_index_flags_are_rejected",
        "test_invalid_generated_temporary_name_is_never_opened",
        "test_loser_of_parent_mkdir_race_fails_closed",
        "test_mid_verification_mode_and_hardlink_changes_are_rejected",
        "test_native_unsupported_rename_errnos_are_proven_nonpublication",
        "test_output_outside_repo_ignored_or_unsafe_parent_is_rejected",
        "test_parent_fsync_failure_reports_published_incomplete",
        "test_parent_or_repository_swap_fails_closed",
        "test_parent_swap_before_temporary_creation_fails_closed",
        "test_pin_regular_rejects_same_size_mode_distinct_inode_replacement",
        "test_post_creation_metadata_change_is_detected_without_unlink",
        "test_post_inventory_failure_never_unlinks_canonical_target",
        "test_post_rename_hardlink_is_incomplete_and_never_removed",
        "test_preexisting_parent_components_are_resynced_in_exact_order",
        "test_prepublication_failure_never_unlinks_reserved_name",
        "test_regular_inventory_read_rejects_path_change",
        "test_regular_type_swap_to_fifo_never_blocks_open",
        "test_removed_tracked_parent_is_recorded_as_deletion",
        "test_rename_conflict_errnos_are_proven_not_published",
        "test_rename_conflict_preserves_existing_target",
        "test_rename_success_followed_by_eio_is_publication_unknown",
        "test_repository_argument_must_equal_exact_git_toplevel",
        "test_repository_binding_accepts_ancestor_alias_but_rejects_leaf_symlink",
        "test_resource_bounds_fail_closed",
        "test_restart_detects_pre_rename_orphan",
        "test_restart_double_scan_rejects_reserved_name_instability",
        "test_restart_identifies_target_with_reserved_temporary",
        "test_restart_verification_rejects_mode_hardlink_and_symlink",
        "test_restart_verifies_but_never_regenerates_existing_output",
        "test_retained_blob_size_and_object_id_mismatches_are_rejected",
        "test_retention_ignores_replace_overlay_that_forges_valid_parent",
        "test_retention_rejects_merge_on_first_parent_chain",
        "test_retention_rejects_missing_or_executable_head_ledger",
        "test_retention_rejects_tampered_implementation_snapshot",
        "test_retention_rejects_worktree_ledger_substitution",
        "test_retention_requires_implementation_parent_to_equal_source",
        "test_retention_snapshot_uses_child_umask_and_preserves_parent_umask",
        "test_review_gate_rejects_adverse_or_incomplete_dispositions",
        "test_reviewed_rows_may_retain_recorded_defects",
        "test_rule_proven_generated_yes_cannot_evolve_to_no",
        "test_secure_view_exit_failure_still_closes_verification_pin",
        "test_self_row_survives_stage_commit_and_clean_clone",
        "test_sigint_at_each_ownership_and_rename_boundary_is_reconciled",
        "test_signed_commit_continuations_do_not_forge_parent_headers",
        "test_source_gitlink_size_field_uses_exact_padded_grammar",
        "test_staged_content_identity_is_distinct_from_source_and_worktree",
        "test_symlink_leaf_and_ancestor_are_never_followed",
        "test_temporary_collision_never_deletes_unowned_entry",
        "test_temporary_identity_fault_reports_preserved_orphan",
        "test_temporary_substitution_or_mutation_is_preserved",
        "test_unknown_generated_resolution_requires_completed_provenance",
        "test_unknown_rename_plus_close_eio_keeps_reserved_inspection_detail",
        "test_unsupported_prepublication_directory_fsync_fails_closed",
        "test_unterminated_nul_and_index_view_mismatches_fail_closed",
        "test_verification_failure_closes_pinned_descriptor",
        "test_verified_creation_finalization_is_definite",
        "test_verify_double_pass_reuses_exact_deadline_object",
        "test_walk_total_byte_and_parse_row_bounds_are_exact",
        "test_write_chmod_and_file_fsync_failures_are_bounded",
        "test_zero_oid_index_gitlink_is_rejected",
    }
)
EXPECTED_CREATE_ONCE_DEFINITIONS = frozenset(
    {
        "CreationIncompleteError",
        "SecureRepository",
        "_OwnedTemporary",
        "_atomic_rename_noreplace",
        "_create_regular_temporary",
        "_reject_reserved_creation_state",
        "_temporary_retention_detail",
        "atomic_create",
        "generate_ledger",
    }
)
EXPECTED_CREATE_ONCE_STATES = frozenset(
    {
        "OPEN",
        "TEMP_FSYNCED",
        "RENAME_OUTCOME_UNKNOWN",
        "RENAME_REJECTED",
        "RENAMED_UNSYNCED",
        "PARENT_FSYNCED",
        "VERIFIED_SUCCESS",
    }
)
EXPECTED_GITIGNORE_SHA256 = (
    "cfcafb758561ee79536d05b834cd618e995982df699c8f8f860088e60acfb9f9"
)
EXPECTED_GITIGNORE_BYTES = (
    b"/target\n"
    b"**/*.rs.bk\n"
    b"Cargo.lock.orig\n"
    b"\n"
    b"# Development PKI and secrets must never be committed outside "
    b"range/certs-dev fixtures.\n"
    b".env\n"
    b"*.pem\n"
    b"*.key\n"
    b"*.p12\n"
    b"*.pfx\n"
    b"!range/certs-dev/**/*.pub.pem\n"
    b"\n"
    b"# Local private evidence (owner-visible) must not enter public history.\n"
    b"evidence/**/*.private.*\n"
    b"*.private.jsonl\n"
    b"*.private.csv\n"
    b"\n"
    b"# OS / editor noise\n"
    b".DS_Store\n"
    b"*.swp\n"
    b"\n"
    b"# Python bytecode is interpreter-specific build output, never source "
    b"evidence.\n"
    b"__pycache__/\n"
    b"*.py[cod]\n"
    b"\n"
    b"# Python tool caches are local, reproducible analysis output.\n"
    b".mypy_cache/\n"
    b".ruff_cache/\n"
)
VERIFIER_PATH = "tools/release/tasks/ch-t001/e0001/verify.py"
REGISTERED_TESTS_PATH = "tools/release/tasks/ch-t001/e0001/test_verify.py"
FREEZE_PATH = "release/0.9.0/current-head/tasks/ch-t001/e0001/freeze.json"
QUALIFICATION_PATH = "release/0.9.0/current-head/tasks/ch-t001/e0001/qualification.json"
ACTIVATION_PATH = "release/0.9.0/current-head/tasks/ch-t001/e0001/activation.json"
RECEIPT_PATH = "release/0.9.0/current-head/tasks/ch-t001/e0001/verifier-receipt.json"
REGISTRY_PATH = "release/0.9.0/current-head/closures/task-verifier-registry.json"
REQUIREMENTS_PATH = "release/0.9.0/current-head/requirements.json"
ACTIVE_CLAIMS_PATH = "release/0.9.0/current-head/closures/active-claims.json"
EXPECTED_IMPLEMENTATION_PLAN = {
    GITIGNORE_PATH: "M",
    LEDGER_PATH: "A",
    PRODUCT_TOOL: "A",
    PRODUCT_TESTS: "A",
}
EXPECTED_SURFACE_CLASSIFICATIONS = {
    GITIGNORE_PATH: "BUILD_OR_DEPLOYMENT",
    LEDGER_PATH: "INTERNAL_IMPLEMENTATION",
    PRODUCT_TOOL: "TEST_OR_TOOLING",
    PRODUCT_TESTS: "TEST_OR_TOOLING",
}
EXPECTED_PUBLIC_SURFACES = [GITIGNORE_PATH]
GIT_EXECUTABLE = "/usr/bin/git"
GH_EXECUTABLE = "/opt/homebrew/bin/gh"
GH_VERSION = "gh version 2.95.0 (2026-06-17)"
GH_API_VERSION = "2022-11-28"
GH_ACCEPT_HEADER = "application/vnd.github+json"
EXPECTED_SOURCE_PATHS = 349
EXPECTED_IMPLEMENTATION_PATHS = 352
MAX_LEDGER_BYTES = 4 * 1024 * 1024
MAX_TREE_BYTES = 16 * 1024 * 1024
MAX_BLOB_BYTES = 4 * 1024 * 1024
MAX_GIT_OUTPUT = 24 * 1024 * 1024
MAX_PATH_BYTES = 4096
MAX_CELL_BYTES = 16 * 1024
MAX_ENUM_CELL_BYTES = 128
MAX_DECIMAL_CELL_BYTES = 32
MAX_IDENTITY_CELL_BYTES = 4096
MAX_JSON_BYTES = 256 * 1024
MAX_CI_LOG_ARCHIVE_BYTES = 128 * 1024
MAX_CI_LOG_EXPANDED_BYTES = 8 * 1024 * 1024
MAX_FIRST_PARENT_COMMITS = 1024
MAX_CI_LOG_FILES = 128
COMMAND_SECONDS = 3.0
INVENTORY_RECONCILIATION_MAX_RSS_BYTES = 512 * 1024 * 1024
RESOURCE_SAMPLE_COUNT = 5
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
RFC3339_UTC = re.compile(
    r"^[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])"
    r"T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$"
)

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
MUTABLE_REVIEW_FIELDS = tuple(field for field in FIELDS if field in MUTABLE_FIELDS)
DIGEST_FIELDS = tuple(
    field for field in IMMUTABLE_FIELDS if field != "inventory_digest"
)
FIELD_BYTE_LIMITS = {field: MAX_CELL_BYTES for field in FIELDS}
FIELD_BYTE_LIMITS.update(
    {
        field: MAX_ENUM_CELL_BYTES
        for field in (
            "schema_version",
            "object_format",
            "ignored_policy",
            "source_tracked",
            "source_git_mode",
            "source_object_type",
            "source_lines",
            "source_content_kind",
            "index_tracked",
            "index_git_mode",
            "index_flags",
            "index_lines",
            "index_content_kind",
            "source_index_state",
            "current_scope",
            "current_fs_type",
            "current_fs_mode",
            "current_lines",
            "current_content_kind",
            "worktree_state",
            "category",
            "provenance_class",
            "lines",
            "language",
            "format",
            "generated",
            "public_surface",
            "security_critical",
            "science_critical",
            "authority_critical",
            "provenance_review_status",
            "license_review_status",
            "review_status",
            "completed_at",
        )
    }
)
FIELD_BYTE_LIMITS.update(
    {
        field: MAX_DECIMAL_CELL_BYTES
        for field in (
            "inventory_rows",
            "filesystem_entries",
            "source_bytes",
            "index_bytes",
            "current_bytes",
            "bytes",
        )
    }
)
FIELD_BYTE_LIMITS.update(
    {
        field: MAX_IDENTITY_CELL_BYTES
        for field in (
            "ledger_self_path",
            "path",
            "ignore_rule_source",
            "ignore_pattern",
            "generated_candidate_reason",
            "generator",
            "license_expression",
            "reviewer",
            "disposition",
        )
    }
)
TRISTATE_FIELDS = (
    "generated",
    "public_surface",
    "security_critical",
    "science_critical",
    "authority_critical",
)
TRISTATE = frozenset({"UNKNOWN", "YES", "NO"})
REVIEW_STATUSES = frozenset(
    {"UNREVIEWED", "IN_REVIEW", "REVIEWED", "BLOCKED", "NOT_APPLICABLE"}
)
PROVENANCE_STATUSES = frozenset(
    {"UNREVIEWED", "CONFIRMED", "REJECTED", "NOT_APPLICABLE"}
)
LICENSE_STATUSES = frozenset({"UNREVIEWED", "APPROVED", "REJECTED", "NOT_APPLICABLE"})
LANGUAGE_BY_NAME = {
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
LANGUAGE_BY_SUFFIX = {
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
BINARY_LANGUAGES = frozenset({"BINARY_DATA", "GZIP", "ZIP"})
GENERATED_COMPONENTS = frozenset(
    {"build", "coverage", "dist", "gen", "generated", "node_modules", "out", "target"}
)
ALLOWED_EXTERNAL_GENERATORS = frozenset(
    {"PINNED_CARGO_1.96.0_FROM_WORKSPACE_MANIFESTS"}
)

EVIDENCE_SCHEMA_IDS = {
    "CH-T001-E01": "haldir.ch-t001.file-review-traceability.v1",
    "CH-T001-E02": "haldir.ch-t001.complete-command-log.v1",
    "CH-T001-E03": "haldir.ch-t001.positive-negative-vectors.v1",
    "CH-T001-E04": "haldir.ch-t001.coverage-fuzz-mutation-model.v1",
    "CH-T001-E05": "haldir.ch-t001.resource-time-maxima.v1",
    "CH-T001-E06": "haldir.ch-t001.exact-identities-checksums.v1",
    "CH-T001-E07": "haldir.ch-t001.claim-migration-disposition.v1",
    "CH-T001-E08": "haldir.ch-t001.complete-file-inventory.v1",
    "CH-T001-E09": "haldir.ch-t001.independent-ledger-reconciliation.v1",
}
REVIEW_LOGICAL_SCHEMA_IDS = {
    "CH-T001-R01": "haldir.ch-t001.independent-review.v1",
    "CH-T001-R02": "haldir.ch-t001.lead-implementation-review.v1",
}
ACTIVATION_SCHEMA_IDS = {
    "CH-T001-A01": "haldir.ch-t001.subsystem-gate.v1",
    "CH-T001-A02": "haldir.ch-t001.wave-gate.v1",
    "CH-T001-A03": "haldir.ch-t001.full-locked-ci.v1",
    "CH-T001-A04": "haldir.ch-t001.downstream-conformance-disposition.v1",
}
WAVE_REMAINING_TASKS = tuple(f"CH-T{index:03d}" for index in range(2, 13))
CI_JOB_NAMES = (
    "build-test",
    "clean-build",
    "feature-matrix",
    "interop",
    "macos-compile",
    "supply-chain",
)
RESOURCE_SAMPLE_PHASES = tuple(
    f"RESOURCE_SAMPLE_{index:02d}" for index in range(1, RESOURCE_SAMPLE_COUNT + 1)
)
REQUIRED_COMMAND_PHASES = (
    "LEDGER_GENERATE",
    "PRODUCT_TESTS",
    "EXACT_IMPLEMENTATION_VERIFY",
    "REGISTERED_TESTS",
    "INDEPENDENT_RECONCILIATION",
    "NEGATIVE_VECTORS",
    "TECHNIQUE_ANALYSIS",
    *RESOURCE_SAMPLE_PHASES,
)
EVIDENCE_PYTHON = "/opt/homebrew/bin/python3.14"
ANALYSIS_TECHNIQUES = (
    "UNIT_COVERAGE",
    "PROPERTY_METAMORPHIC",
    "DIFFERENTIAL_ORACLE",
    "FUZZ",
    "MUTATION",
    "MODEL",
    "CONCURRENCY",
)
TECHNIQUE_REGISTERED_TEST_IDS = {
    "PROPERTY_METAMORPHIC": "test_technique_property_metamorphic",
    "DIFFERENTIAL_ORACLE": "test_technique_differential_oracle",
    "FUZZ": "test_technique_fuzz",
    "MUTATION": "test_technique_mutation",
    "MODEL": "test_technique_model",
    "CONCURRENCY": "test_technique_concurrency",
}
TECHNIQUE_PRODUCT_CONCURRENCY_TEST_IDS = (
    "test_concurrent_creators_allow_at_most_one_success_without_clobber",
    "test_post_inventory_failure_never_unlinks_canonical_target",
    "test_restart_verifies_but_never_regenerates_existing_output",
)
TECHNIQUE_LIMITATIONS = {
    "UNIT_COVERAGE": (
        "Executed test identities establish case coverage but do not claim a branch-percentage metric."
    ),
    "PROPERTY_METAMORPHIC": (
        "Deterministic metamorphic cases do not prove behavior for every possible repository."
    ),
    "DIFFERENTIAL_ORACLE": (
        "The independent Git object oracle covers representative byte payloads rather than every blob."
    ),
    "FUZZ": (
        "Deterministic bounded fuzz cases are retained; exhaustive input coverage is not claimed."
    ),
    "MUTATION": (
        "The mutation set targets every frozen control but is not an exhaustive program mutation campaign."
    ),
    "MODEL": (
        "The independent content model covers the frozen representative corpus only."
    ),
    "CONCURRENCY": (
        "Concurrency tests cover deterministic classification and atomic ledger races on the recorded platform."
    ),
}

CONTROL_IDS = tuple(f"CH-T001-N{index:02d}" for index in range(1, 21))
COUNTERFACTUAL_IDS = tuple(f"CH-T001-CF{index:02d}" for index in range(1, 11))


class VerificationError(RuntimeError):
    """The frozen inventory or its lifecycle binding is contradictory."""


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise VerificationError(code)


def _canonical_path(raw: str) -> str:
    _require(isinstance(raw, str), "PATH_NOT_STRING")
    path = PurePosixPath(raw)
    _require(bool(raw), "PATH_EMPTY")
    _require(not path.is_absolute() and path.as_posix() == raw, "PATH_NOT_CANONICAL")
    _require("\\" not in raw, "PATH_BACKSLASH")
    _require(all(part not in {"", ".", ".."} for part in path.parts), "PATH_ESCAPE")
    _require(all(part.casefold() != ".git" for part in path.parts), "PATH_GIT_ADMIN")
    _require(unicodedata.normalize("NFC", raw) == raw, "PATH_NOT_NFC")
    _require(
        not any(unicodedata.category(character).startswith("C") for character in raw),
        "PATH_CONTROL_CHARACTER",
    )
    _require(len(raw.encode("utf-8")) <= MAX_PATH_BYTES, "PATH_TOO_LONG")
    return raw


def _require_portable_unique(paths: Iterable[str], code: str) -> None:
    portable: dict[str, str] = {}
    for path in paths:
        key = unicodedata.normalize("NFC", path).casefold()
        prior = portable.get(key)
        _require(prior is None or prior == path, code)
        portable[key] = path


def _environment(repo: Path) -> dict[str, str]:
    safe_directory = os.path.abspath(os.fspath(repo))
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
        "GIT_CONFIG_VALUE_4": safe_directory,
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


def _git(
    repo: Path,
    arguments: Sequence[str],
    *,
    input_data: bytes | None = None,
    maximum: int = MAX_GIT_OUTPUT,
) -> bytes:
    _require(maximum > 0 and maximum <= MAX_GIT_OUTPUT, "GIT_BOUND_INVALID")
    command = [GIT_EXECUTABLE, "-C", str(repo), *arguments]
    command_deadline = time.monotonic() + COMMAND_SECONDS
    input_stream = None
    try:
        if input_data is not None:
            _require(len(input_data) <= MAX_GIT_OUTPUT, "GIT_STDIN_BOUND")
            input_stream = tempfile.TemporaryFile()
            input_stream.write(input_data)
            input_stream.flush()
            input_stream.seek(0)
        process = subprocess.Popen(
            command,
            stdin=input_stream if input_stream is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_environment(repo),
        )
    except OSError as error:
        if input_stream is not None:
            input_stream.close()
        raise VerificationError("GIT_EXECUTION_FAILED") from error
    assert process.stdout is not None
    assert process.stderr is not None
    selector = selectors.DefaultSelector()
    stdout = bytearray()
    stderr = bytearray()
    return_code: int | None = None
    try:
        selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        while selector.get_map():
            remaining = command_deadline - time.monotonic()
            _require(remaining > 0, "GIT_TIMEOUT")
            events = selector.select(remaining)
            if not events:
                continue
            for key, _mask in events:
                chunk = os.read(key.fd, 64 * 1024)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                target = stdout if key.data == "stdout" else stderr
                limit = maximum if key.data == "stdout" else 64 * 1024
                _require(
                    len(target) <= limit - len(chunk), f"GIT_{key.data.upper()}_BOUND"
                )
                target.extend(chunk)
        remaining = command_deadline - time.monotonic()
        _require(remaining > 0, "GIT_TIMEOUT")
        try:
            return_code = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired as error:
            raise VerificationError("GIT_TIMEOUT") from error
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
    _require(return_code == 0 and not stderr, "GIT_COMMAND_FAILED")
    return bytes(stdout)


def _decode_path(raw: bytes) -> str:
    try:
        return _canonical_path(raw.decode("utf-8", "strict"))
    except UnicodeDecodeError as error:
        raise VerificationError("PATH_NOT_UTF8") from error


def _json(payload: bytes, label: str) -> dict[str, Any]:
    _require(len(payload) <= MAX_JSON_BYTES, f"{label}_JSON_BOUND")

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            _require(key not in result, f"{label}_JSON_DUPLICATE_KEY")
            result[key] = value
        return result

    def constant(_value: str) -> None:
        raise VerificationError(f"{label}_JSON_NONFINITE")

    try:
        value = json.loads(
            payload.decode("utf-8", "strict"),
            object_pairs_hook=pairs,
            parse_constant=constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise VerificationError(f"{label}_JSON_INVALID") from error
    _require(isinstance(value, dict), f"{label}_JSON_NOT_OBJECT")
    return value


def _canonical_json(payload: bytes, label: str) -> dict[str, Any]:
    value = _json(payload, label)
    canonical = (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")
    _require(payload == canonical, f"{label}_JSON_NOT_CANONICAL")
    return value


def _exact_keys(value: object, keys: Iterable[str], code: str) -> dict[str, Any]:
    expected = frozenset(keys)
    _require(isinstance(value, dict) and frozenset(value) == expected, code)
    return value


def _strict_equal(observed: object, expected: object) -> bool:
    if type(observed) is not type(expected):
        return False
    if isinstance(observed, dict):
        return observed.keys() == expected.keys() and all(
            _strict_equal(observed[key], expected[key]) for key in observed
        )
    if isinstance(observed, (list, tuple)):
        return len(observed) == len(expected) and all(
            _strict_equal(left, right)
            for left, right in zip(observed, expected, strict=True)
        )
    return observed == expected


def _text(value: object, code: str, *, maximum: int = 4096) -> str:
    _require(isinstance(value, str), code)
    stripped = value.strip()
    _require(
        value == stripped
        and 0 < len(value.encode("utf-8")) <= maximum
        and unicodedata.normalize("NFC", value) == value
        and not any(
            unicodedata.category(character).startswith("C") for character in value
        )
        and re.search(r"\b(?:FIXME|PLACEHOLDER|TBD|TODO)\b", value, re.IGNORECASE)
        is None,
        code,
    )
    return value


def _text_list(
    value: object,
    code: str,
    *,
    minimum: int = 0,
    unique: bool = True,
) -> list[str]:
    _require(isinstance(value, list) and len(value) >= minimum, code)
    result = [_text(item, code) for item in value]
    _require(not unique or len(result) == len(set(result)), code)
    return result


def _integer(value: object, code: str, *, minimum: int = 0) -> int:
    _require(type(value) is int and value >= minimum, code)
    return value


def _number(value: object, code: str, *, positive: bool = False) -> float:
    _require(type(value) in {int, float}, code)
    number = float(value)
    _require(
        math.isfinite(number) and number >= 0.0 and (not positive or number > 0.0),
        code,
    )
    return number


def _number_list(
    value: object,
    code: str,
    *,
    exact_length: int,
    positive: bool = False,
) -> list[float]:
    _require(isinstance(value, list) and len(value) == exact_length, code)
    return [_number(item, code, positive=positive) for item in value]


def _integer_list(
    value: object,
    code: str,
    *,
    exact_length: int,
    minimum: int = 0,
) -> list[int]:
    _require(isinstance(value, list) and len(value) == exact_length, code)
    return [_integer(item, code, minimum=minimum) for item in value]


def _timestamp(value: object, code: str) -> str:
    _require(isinstance(value, str) and RFC3339_UTC.fullmatch(value) is not None, code)
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as error:
        raise VerificationError(code) from error
    return value


def _number_expression(node: ast.AST) -> int | float:
    if isinstance(node, ast.Constant) and type(node.value) in {int, float}:
        return node.value
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub)):
        operand = _number_expression(node.operand)
        return operand if isinstance(node.op, ast.UAdd) else -operand
    if isinstance(node, ast.BinOp) and isinstance(
        node.op, (ast.Add, ast.Sub, ast.Mult, ast.FloorDiv)
    ):
        left = _number_expression(node.left)
        right = _number_expression(node.right)
        if isinstance(node.op, ast.Add):
            return left + right
        if isinstance(node.op, ast.Sub):
            return left - right
        if isinstance(node.op, ast.Mult):
            return left * right
        _require(right != 0, "PRODUCT_CONSTANT_DIVISION")
        return left // right
    raise VerificationError("PRODUCT_CONSTANT_NOT_LITERAL")


def _product_constants(payload: bytes) -> dict[str, int | float]:
    try:
        tree = ast.parse(payload, filename=PRODUCT_TOOL)
    except (SyntaxError, ValueError) as error:
        raise VerificationError("PRODUCT_AST_INVALID") from error
    wanted = {
        "HARD_MAX_FILE_BYTES",
        "HARD_MAX_ROWS",
        "HARD_MAX_SECONDS",
        "HARD_MAX_TOTAL_BYTES",
        "MAX_CELL_BYTES",
        "MAX_GIT_BLOB_READS",
        "MAX_GIT_INVENTORY_BYTES",
        "MAX_LEDGER_BYTES",
        "MAX_PATH_BYTES",
    }
    result: dict[str, int | float] = {}
    for node in tree.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if isinstance(target, ast.Name) and target.id in wanted:
            result[target.id] = _number_expression(node.value)
    _require(set(result) == wanted, "PRODUCT_RESOURCE_CONSTANTS_MISSING")
    _require(
        type(result["HARD_MAX_ROWS"]) is int
        and 1 <= result["HARD_MAX_ROWS"] <= 10_000
        and type(result["HARD_MAX_FILE_BYTES"]) is int
        and 1 <= result["HARD_MAX_FILE_BYTES"] <= 256 * 1024 * 1024
        and type(result["HARD_MAX_TOTAL_BYTES"]) is int
        and 1 <= result["HARD_MAX_TOTAL_BYTES"] <= 2 * 1024 * 1024 * 1024
        and 0 < result["HARD_MAX_SECONDS"] <= 3600
        and type(result["MAX_LEDGER_BYTES"]) is int
        and result["MAX_LEDGER_BYTES"] == MAX_LEDGER_BYTES == MAX_BLOB_BYTES,
        "PRODUCT_RESOURCE_CONSTANTS_UNBOUNDED",
    )
    return result


def _validate_product_identities(tool_payload: bytes, test_payload: bytes) -> None:
    observed = {
        PRODUCT_TOOL: hashlib.sha256(tool_payload).hexdigest(),
        PRODUCT_TESTS: hashlib.sha256(test_payload).hexdigest(),
    }
    _require(observed == EXPECTED_PRODUCT_SHA256, "PRODUCT_SHA256_MISMATCH")


def _validate_gitignore_identity(payload: bytes) -> None:
    _require(
        payload == EXPECTED_GITIGNORE_BYTES
        and hashlib.sha256(payload).hexdigest() == EXPECTED_GITIGNORE_SHA256,
        "GITIGNORE_SHA256_MISMATCH",
    )
    _require(
        payload.endswith(b"\n") and b"\r" not in payload and b"\0" not in payload,
        "GITIGNORE_ENCODING",
    )
    try:
        lines = payload.decode("utf-8", "strict").splitlines()
    except UnicodeDecodeError as error:
        raise VerificationError("GITIGNORE_ENCODING") from error
    _require(lines.count(".env") == 1, "GITIGNORE_ENV_PATTERN")
    _require(lines.count(".mypy_cache/") == 1, "GITIGNORE_MYPY_PATTERN")
    _require(lines.count(".ruff_cache/") == 1, "GITIGNORE_RUFF_PATTERN")
    _require(
        not any(
            line.startswith("!") and line.removeprefix("!") == ".env" for line in lines
        ),
        "GITIGNORE_ENV_NEGATION",
    )


def _validate_freeze_surface_contract(freeze: dict[str, Any]) -> None:
    _require(
        freeze.get("implementation_plan") == EXPECTED_IMPLEMENTATION_PLAN,
        "FREEZE_IMPLEMENTATION_PLAN",
    )
    surfaces = freeze.get("affected_surface_inventory")
    _require(
        isinstance(surfaces, list)
        and len(surfaces) == len(EXPECTED_IMPLEMENTATION_PLAN),
        "FREEZE_SURFACE_INVENTORY",
    )
    for record, (path, status) in zip(
        surfaces, EXPECTED_IMPLEMENTATION_PLAN.items(), strict=True
    ):
        record = _exact_keys(
            record,
            {
                "path",
                "planned_status",
                "classification",
                "claim_relevance",
                "in_repository_consumers",
                "external_consumers",
                "rationale",
            },
            "FREEZE_SURFACE_KEYS",
        )
        classification = EXPECTED_SURFACE_CLASSIFICATIONS[path]
        expected_relevance = (
            "PUBLIC_CLAIM_REVIEW_REQUIRED"
            if path in EXPECTED_PUBLIC_SURFACES
            else "SEMANTIC_REVIEW_REQUIRED"
        )
        in_repository = record["in_repository_consumers"]
        external = record["external_consumers"]
        _require(
            record["path"] == path
            and record["planned_status"] == status
            and record["classification"] == classification
            and record["claim_relevance"] == expected_relevance
            and isinstance(in_repository, list)
            and all(isinstance(item, str) and item for item in in_repository)
            and in_repository == sorted(set(in_repository))
            and isinstance(external, list)
            and all(isinstance(item, str) and item for item in external)
            and external == sorted(set(external))
            and isinstance(record["rationale"], str)
            and bool(record["rationale"].strip()),
            "FREEZE_SURFACE_BINDING",
        )
    outcomes = freeze.get("claim_outcomes")
    _require(isinstance(outcomes, list) and bool(outcomes), "FREEZE_CLAIM_OUTCOMES")
    for outcome in outcomes:
        _require(isinstance(outcome, dict), "FREEZE_CLAIM_OUTCOME")
        _require(
            outcome.get("public_surfaces") == EXPECTED_PUBLIC_SURFACES,
            "FREEZE_PUBLIC_SURFACES",
        )
        migration = outcome.get("migration")
        _require(isinstance(migration, dict), "FREEZE_MIGRATION_BINDING")
        disposition = migration.get("disposition")
        _require(
            migration
            == {
                "required": True,
                "paths": sorted(EXPECTED_IMPLEMENTATION_PLAN),
                "disposition": disposition,
            }
            and isinstance(disposition, str)
            and bool(disposition.strip()),
            "FREEZE_MIGRATION_BINDING",
        )
        _require(
            outcome.get("rollback")
            == {
                "strategy": "RESTORE_EXACT_PRIOR_ACTIVATED_TREE_ENTRIES",
                "paths": sorted(EXPECTED_IMPLEMENTATION_PLAN),
                "verification": "GIT_MODE_TYPE_AND_OBJECT_IDENTITY",
            },
            "FREEZE_ROLLBACK_BINDING",
        )


def _tree(repo: Path, commit: str) -> tuple[str, dict[str, dict[str, Any]]]:
    _require(HEX40.fullmatch(commit) is not None, "COMMIT_ID_INVALID")
    tree_id = _git(repo, ["rev-parse", "--verify", f"{commit}^{{tree}}"], maximum=128)
    try:
        tree = tree_id.decode("ascii", "strict").strip()
    except UnicodeDecodeError as error:
        raise VerificationError("TREE_ID_INVALID") from error
    _require(HEX40.fullmatch(tree) is not None, "TREE_ID_INVALID")
    raw = _git(
        repo,
        ["ls-tree", "-lrz", "--full-tree", commit],
        maximum=2 * 1024 * 1024,
    )
    _require(not raw or raw.endswith(b"\0"), "TREE_OUTPUT_UNTERMINATED")
    entries: dict[str, dict[str, Any]] = {}
    total = 0
    ordered: list[str] = []
    for record in raw[:-1].split(b"\0") if raw else ():
        try:
            metadata, raw_path = record.split(b"\t", 1)
            mode_raw, kind_raw, oid_raw, size_raw = metadata.split()
            mode = mode_raw.decode("ascii", "strict")
            kind = kind_raw.decode("ascii", "strict")
            oid = oid_raw.decode("ascii", "strict")
            size = int(size_raw.decode("ascii", "strict"))
        except (UnicodeDecodeError, ValueError) as error:
            raise VerificationError("TREE_ENTRY_INVALID") from error
        path = _decode_path(raw_path)
        _require(path not in entries, "TREE_PATH_DUPLICATE")
        _require(mode in {"100644", "100755"} and kind == "blob", "TREE_TYPE_INVALID")
        _require(HEX40.fullmatch(oid) is not None, "TREE_OBJECT_ID_INVALID")
        _require(0 <= size <= MAX_BLOB_BYTES, "TREE_BLOB_SIZE_BOUND")
        total += size
        _require(total <= MAX_TREE_BYTES, "TREE_TOTAL_SIZE_BOUND")
        entries[path] = {"mode": mode, "type": kind, "oid": oid, "size": size}
        ordered.append(path)
    _require(
        ordered == sorted(ordered, key=lambda item: item.encode("utf-8")), "TREE_ORDER"
    )
    _require_portable_unique(ordered, "TREE_PORTABLE_PATH_COLLISION")
    return tree, entries


def _selected_tree_entries(
    repo: Path, commit: str, paths: Iterable[str]
) -> dict[str, dict[str, Any]]:
    selected = sorted({_canonical_path(path) for path in paths})
    raw = _git(repo, ["ls-tree", "-z", commit, "--", *selected], maximum=128 * 1024)
    _require(not raw or raw.endswith(b"\0"), "SELECTED_TREE_UNTERMINATED")
    entries: dict[str, dict[str, Any]] = {}
    for record in raw[:-1].split(b"\0") if raw else ():
        try:
            metadata, raw_path = record.split(b"\t", 1)
            mode_raw, kind_raw, oid_raw = metadata.split()
            mode = mode_raw.decode("ascii", "strict")
            kind = kind_raw.decode("ascii", "strict")
            oid = oid_raw.decode("ascii", "strict")
        except (UnicodeDecodeError, ValueError) as error:
            raise VerificationError("SELECTED_TREE_ENTRY_INVALID") from error
        path = _decode_path(raw_path)
        _require(path in selected and path not in entries, "SELECTED_TREE_PATH_INVALID")
        _require(mode in {"100644", "100755"} and kind == "blob", "SELECTED_TREE_TYPE")
        _require(HEX40.fullmatch(oid) is not None, "SELECTED_TREE_OID")
        entries[path] = {"mode": mode, "type": kind, "oid": oid}
    return entries


def _blobs(repo: Path, object_ids: Iterable[str]) -> dict[str, bytes]:
    ordered = sorted(set(object_ids))
    _require(
        ordered and all(HEX40.fullmatch(oid) for oid in ordered), "BLOB_OID_INVALID"
    )
    raw = _git(
        repo,
        ["cat-file", "--batch"],
        input_data=("\n".join(ordered) + "\n").encode("ascii"),
        maximum=MAX_GIT_OUTPUT,
    )
    offset = 0
    result: dict[str, bytes] = {}
    for expected_oid in ordered:
        newline = raw.find(b"\n", offset)
        _require(newline >= 0, "BLOB_BATCH_HEADER")
        try:
            observed_oid, kind, size_raw = raw[offset:newline].decode("ascii").split()
            size = int(size_raw)
        except (UnicodeDecodeError, ValueError) as error:
            raise VerificationError("BLOB_BATCH_HEADER") from error
        _require(
            observed_oid == expected_oid
            and kind == "blob"
            and 0 <= size <= MAX_BLOB_BYTES,
            "BLOB_BATCH_IDENTITY",
        )
        start = newline + 1
        end = start + size
        _require(end < len(raw) and raw[end : end + 1] == b"\n", "BLOB_BATCH_PAYLOAD")
        payload = raw[start:end]
        _require(_git_blob_id(payload) == expected_oid, "BLOB_HASH_MISMATCH")
        result[expected_oid] = payload
        offset = end + 1
    _require(offset == len(raw), "BLOB_BATCH_TRAILING_DATA")
    return result


def _commit_parents(repo: Path, commits: Sequence[str]) -> dict[str, str]:
    _require(len(commits) == 4 and len(set(commits)) == 4, "CHAIN_COMMIT_SET")
    raw = _git(repo, ["rev-list", "--parents", "--no-walk", *commits], maximum=1024)
    result: dict[str, str] = {}
    try:
        lines = raw.decode("ascii", "strict").splitlines()
    except UnicodeDecodeError as error:
        raise VerificationError("CHAIN_PARENT_ENCODING") from error
    for line in lines:
        fields = line.split()
        _require(
            len(fields) == 2 and all(HEX40.fullmatch(item) for item in fields),
            "CHAIN_PARENT",
        )
        _require(fields[0] in commits and fields[0] not in result, "CHAIN_PARENT_SET")
        result[fields[0]] = fields[1]
    _require(set(result) == set(commits), "CHAIN_PARENT_MISSING")
    return result


def _first_parent(repo: Path, current: str) -> list[str]:
    raw = _git(
        repo,
        [
            "rev-list",
            "--first-parent",
            f"--max-count={MAX_FIRST_PARENT_COMMITS + 1}",
            current,
        ],
        maximum=64 * 1024,
    )
    try:
        commits = raw.decode("ascii", "strict").splitlines()
    except UnicodeDecodeError as error:
        raise VerificationError("FIRST_PARENT_ENCODING") from error
    _require(0 < len(commits) <= MAX_FIRST_PARENT_COMMITS, "FIRST_PARENT_BOUND")
    _require(all(HEX40.fullmatch(commit) for commit in commits), "FIRST_PARENT_ID")
    _require(len(commits) == len(set(commits)), "FIRST_PARENT_DUPLICATE")
    return commits


def _require_exact_linear_head(
    repo: Path, implementation_commit: str, current_commit: str
) -> None:
    head = (
        _git(
            repo,
            ["rev-parse", "--verify", "HEAD^{commit}"],
            maximum=128,
        )
        .decode("ascii", "strict")
        .strip()
    )
    _require(head == current_commit, "CURRENT_COMMIT_NOT_HEAD")
    merges = _git(
        repo,
        ["rev-list", "--min-parents=2", f"{implementation_commit}..{current_commit}"],
        maximum=64 * 1024,
    )
    _require(not merges, "POST_IMPLEMENTATION_MERGE")


def _diff(repo: Path, parent: str, commit: str) -> dict[str, str]:
    raw = _git(
        repo,
        [
            "diff-tree",
            "--no-commit-id",
            "--name-status",
            "--no-renames",
            "-r",
            "-z",
            parent,
            commit,
        ],
        maximum=512 * 1024,
    )
    _require(not raw or raw.endswith(b"\0"), "DIFF_UNTERMINATED")
    fields = raw[:-1].split(b"\0") if raw else []
    _require(len(fields) % 2 == 0, "DIFF_SHAPE")
    result: dict[str, str] = {}
    for index in range(0, len(fields), 2):
        try:
            status = fields[index].decode("ascii", "strict")
        except UnicodeDecodeError as error:
            raise VerificationError("DIFF_STATUS_ENCODING") from error
        path = _decode_path(fields[index + 1])
        _require(status in {"A", "M", "D"} and path not in result, "DIFF_STATUS")
        result[path] = status
    return dict(sorted(result.items()))


def _git_blob_id(payload: bytes) -> str:
    digest = hashlib.sha1()
    digest.update(f"blob {len(payload)}\0".encode("ascii"))
    digest.update(payload)
    return digest.hexdigest()


def _content(payload: bytes) -> dict[str, str]:
    if b"\0" in payload:
        kind, lines = "BINARY", 0
    else:
        try:
            text = payload.decode("utf-8", "strict")
        except UnicodeDecodeError:
            kind, lines = "BINARY", 0
        else:
            lines = len(text.splitlines())
            controls = {
                character
                for character in text
                if character not in "\t\n\r"
                and unicodedata.category(character).startswith("C")
            }
            if controls == {"\x1b"}:
                kind = "TEXT_UTF8_WITH_ANSI_ESCAPE"
            elif controls:
                kind = "TEXT_UTF8_WITH_CONTROLS"
            else:
                kind = "TEXT_UTF8"
    return {
        "git_blob_id": _git_blob_id(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "bytes": str(len(payload)),
        "lines": str(lines),
        "content_kind": kind,
    }


def _language(path: str) -> str:
    pure = PurePosixPath(path)
    return LANGUAGE_BY_NAME.get(
        pure.name.casefold(), LANGUAGE_BY_SUFFIX.get(pure.suffix.casefold(), "UNKNOWN")
    )


def _format(path: str, identity: dict[str, str] | None, *, self_row: bool) -> str:
    if self_row:
        return "SELF_REFERENTIAL_CSV"
    _require(identity is not None, "FORMAT_IDENTITY_MISSING")
    language = _language(path)
    content_kind = identity["content_kind"]
    if content_kind == "BINARY":
        return (
            language
            if language in BINARY_LANGUAGES
            else f"BINARY_WITH_{language}_SUFFIX"
        )
    if content_kind == "TEXT_UTF8_WITH_ANSI_ESCAPE":
        return (
            "ANSI_LOG_TEXT"
            if language == "LOG_TEXT"
            else f"ANSI_ESCAPE_WITH_{language}_SUFFIX"
        )
    if content_kind == "TEXT_UTF8_WITH_CONTROLS":
        return f"CONTROL_BEARING_{language}"
    if language in BINARY_LANGUAGES:
        return f"TEXT_WITH_{language}_SUFFIX"
    return language if language != "UNKNOWN" else content_kind


def _generated_reason(path: str) -> str:
    pure = PurePosixPath(path)
    parts = {part.casefold() for part in pure.parts}
    name = pure.name.casefold()
    reasons: list[str] = []
    if parts & GENERATED_COMPONENTS:
        reasons.append("GENERATED_PATH_COMPONENT")
    if name in {"cargo.lock", "package-lock.json", "pnpm-lock.yaml", "yarn.lock"}:
        reasons.append("LOCKFILE")
    if len(pure.parts) >= 2 and pure.parts[:2] == ("contracts", "vectors"):
        reasons.append("CONTRACT_VECTOR_PATH")
    if "evidence" in parts:
        reasons.append("RETAINED_EVIDENCE_PATH")
    if name.startswith("checksums.") or name in {
        "sha256sums.txt",
        "master_sha256sums.txt",
    }:
        reasons.append("CHECKSUM_MANIFEST")
    if ".generated." in name or name.endswith((".min.js", ".min.css", ".map")):
        reasons.append("GENERATED_FILENAME")
    return ";".join(reasons) if reasons else "NONE_OBSERVED_REVIEW_REQUIRED"


def _is_test_path(path: str) -> bool:
    pure = PurePosixPath(path)
    parts = tuple(part.casefold() for part in pure.parts)
    name = pure.name.casefold()
    if any(part in {"test", "tests"} for part in parts[:-1]):
        return True
    if name in {"test.py", "tests.py", "test.rs", "tests.rs"}:
        return True
    if name.startswith(("test_", "tests_", "test-", "tests-")):
        return True
    return name.endswith(
        (
            "_test.py",
            "_tests.py",
            "_test.rs",
            "_tests.rs",
            ".test.js",
            ".tests.js",
            ".spec.js",
            ".test.ts",
            ".tests.ts",
            ".spec.ts",
            ".test.tsx",
            ".spec.tsx",
        )
    )


def _category(path: str, reason: str) -> str:
    parts = PurePosixPath(path).parts
    if parts[:2] == (".github", "workflows"):
        return "CI_WORKFLOW"
    if parts and parts[0] == "release":
        return "RELEASE_EVIDENCE"
    if parts and parts[0] == "evidence":
        return "EVIDENCE"
    if parts and parts[0] == "docs":
        return "DOCUMENTATION"
    if parts and parts[0] == "formal":
        return "FORMAL_MODEL"
    if parts and parts[0] == "deploy":
        return "DEPLOYMENT"
    if _is_test_path(path):
        return "TEST"
    if parts and parts[0] == "tools":
        return "TOOLING"
    if parts and parts[0] == "crates":
        return "RUST_SOURCE"
    if reason != "NONE_OBSERVED_REVIEW_REQUIRED":
        return "GENERATED_CANDIDATE"
    if PurePosixPath(path).suffix.casefold() in {".toml", ".yaml", ".yml", ".json"}:
        return "CONFIGURATION_OR_DATA"
    return "REPOSITORY_SUPPORT"


def _generated(path: str, *, self_row: bool) -> tuple[str, str]:
    if self_row:
        return "YES", PRODUCT_TOOL
    exact = {
        "Cargo.lock": "PINNED_CARGO_1.96.0_FROM_WORKSPACE_MANIFESTS",
        "contracts/vectors/CHECKSUMS.sha256": "crates/haldir-contracts/src/tests_contracts.rs",
        "contracts/vectors/haldir-intent-v1.cbor.hex": "crates/haldir-contracts/src/tests_contracts.rs",
        "tools/interop/vectors.json": "crates/haldir-crypto/examples/emit_interop_vectors.rs",
    }
    if path in exact:
        return "YES", exact[path]
    for prefix, generator in {
        "evidence/11-secure-zenoh-live/": "tools/live_secure_zenoh.py",
        "evidence/12-live-gate-dev-smoke/": "tools/live_gate_dev_smoke.py",
    }.items():
        if path.startswith(prefix):
            return "YES", generator
    if (
        path.startswith("release/0.9.0/evidence/")
        and "-generated-" in PurePosixPath(path).name
    ):
        return "YES", "tools/release/generate-task-evidence.py"
    return "UNKNOWN", ""


def _digest(kind: str, records: object) -> str:
    _require(re.fullmatch(r"[a-z][a-z0-9-]*", kind) is not None, "DIGEST_KIND")
    payload = json.dumps(
        {
            "kind": kind,
            "records": records,
            "schema": "haldir-ch-t001-inventory-digest-v1",
        },
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _source_index_state(
    source_entry: dict[str, Any] | None,
    index_entry: dict[str, Any],
    *,
    self_row: bool,
) -> str:
    if self_row:
        return (
            "NEITHER" if source_entry is None else "SOURCE_PRESENT_SELF_INDEX_EXCLUDED"
        )
    if source_entry is None:
        return "ADDED_TO_INDEX"
    if (
        source_entry["mode"] == index_entry["mode"]
        and source_entry["oid"] == index_entry["oid"]
    ):
        return "IDENTICAL"
    return "MODIFIED_IN_INDEX"


def _expected_rows(
    freeze_commit: str,
    source_tree: str,
    source: dict[str, dict[str, Any]],
    implementation: dict[str, dict[str, Any]],
    blobs: dict[str, bytes],
) -> list[dict[str, str]]:
    implementation_identities = {
        path: _content(blobs[entry["oid"]])
        for path, entry in implementation.items()
        if path != LEDGER_PATH
    }
    source_records = [
        {
            "path": path,
            "mode": entry["mode"],
            "object_type": entry["type"],
            "oid": entry["oid"],
            "size": entry["size"],
        }
        for path, entry in source.items()
    ]
    index_records = [
        {"path": path, "mode": entry["mode"], "oid": entry["oid"], "flags": "NONE"}
        for path, entry in implementation.items()
        if path != LEDGER_PATH
    ]
    view_digests = {
        "source": _digest("source", source_records),
        "index": _digest("index", index_records),
        "untracked": _digest("untracked-extra", []),
        "ignored": _digest("ignored", []),
        "filesystem": _digest(
            "filesystem",
            [
                {
                    "bytes": implementation_identities[path]["bytes"],
                    "content_kind": implementation_identities[path]["content_kind"],
                    "fs_mode": implementation[path]["mode"],
                    "fs_type": "REGULAR",
                    "git_blob_id": implementation[path]["oid"],
                    "kind": "LEAF",
                    "lines": implementation_identities[path]["lines"],
                    "path": path,
                    "sha256": implementation_identities[path]["sha256"],
                }
                for path in implementation
                if path != LEDGER_PATH
            ]
            + [{"kind": "SELF_SENTINEL", "path": LEDGER_PATH}],
        ),
    }
    rows: list[dict[str, str]] = []
    for path, index_entry in implementation.items():
        self_row = path == LEDGER_PATH
        source_entry = source.get(path)
        source_identity = (
            _content(blobs[source_entry["oid"]]) if source_entry is not None else None
        )
        current_identity = None if self_row else implementation_identities[path]
        reason = _generated_reason(path)
        generated, generator = _generated(path, self_row=self_row)
        legacy = current_identity
        row = {field: "" for field in FIELDS}
        row.update(
            {
                "schema_version": "1.0.0",
                "source_commit": freeze_commit,
                "source_tree": source_tree,
                "object_format": "sha1",
                "ignored_policy": "reject",
                "inventory_rows": str(EXPECTED_IMPLEMENTATION_PATHS),
                "source_inventory_digest": view_digests["source"],
                "index_inventory_digest": view_digests["index"],
                "untracked_inventory_digest": view_digests["untracked"],
                "ignored_inventory_digest": view_digests["ignored"],
                "filesystem_inventory_digest": view_digests["filesystem"],
                "filesystem_entries": str(EXPECTED_IMPLEMENTATION_PATHS),
                "ledger_self_path": LEDGER_PATH,
                "path": path,
                "source_tracked": "true" if source_entry is not None else "false",
                "source_git_mode": source_entry["mode"] if source_entry else "",
                "source_object_type": source_entry["type"] if source_entry else "",
                "source_git_blob_id": source_entry["oid"] if source_entry else "",
                "source_sha256": source_identity["sha256"] if source_identity else "",
                "source_bytes": source_identity["bytes"] if source_identity else "",
                "source_lines": source_identity["lines"] if source_identity else "",
                "source_content_kind": source_identity["content_kind"]
                if source_identity
                else "",
                "index_tracked": "false" if self_row else "true",
                "index_git_mode": "" if self_row else index_entry["mode"],
                "index_git_blob_id": "" if self_row else index_entry["oid"],
                "index_flags": "" if self_row else "NONE",
                "index_sha256": "" if self_row else current_identity["sha256"],
                "index_bytes": "" if self_row else current_identity["bytes"],
                "index_lines": "0" if self_row else current_identity["lines"],
                "index_content_kind": (
                    "SELF_REFERENTIAL_CONTENT_EXCLUDED"
                    if self_row
                    else current_identity["content_kind"]
                ),
                "source_index_state": _source_index_state(
                    source_entry, index_entry, self_row=self_row
                ),
                "current_scope": "LEDGER_SELF" if self_row else "TRACKED",
                "current_fs_type": "LEDGER_SELF" if self_row else "REGULAR",
                "current_fs_mode": "" if self_row else index_entry["mode"],
                "current_git_blob_id": "" if self_row else index_entry["oid"],
                "current_sha256": "" if self_row else current_identity["sha256"],
                "current_bytes": "" if self_row else current_identity["bytes"],
                "current_lines": "0" if self_row else current_identity["lines"],
                "current_content_kind": (
                    "SELF_REFERENTIAL_CONTENT_EXCLUDED"
                    if self_row
                    else current_identity["content_kind"]
                ),
                "worktree_state": (
                    "SELF_REFERENTIAL_CONTENT_EXCLUDED"
                    if self_row
                    else "CLEAN_AGAINST_INDEX"
                ),
                "generated_candidate_reason": reason,
                "category": _category(path, reason),
                "provenance_class": (
                    "SELF_REFERENTIAL_LEDGER_ARTIFACT"
                    if self_row
                    else "DECLARED_SOURCE_COMMIT_AND_CURRENT_VIEW"
                    if source_entry is not None
                    else "POST_CUT_INDEX_ENTRY"
                ),
                "git_blob_id": legacy["git_blob_id"] if legacy else "",
                "sha256": legacy["sha256"] if legacy else "",
                "bytes": legacy["bytes"] if legacy else "",
                "lines": legacy["lines"] if legacy else "",
                "language": _language(path),
                "format": _format(path, current_identity, self_row=self_row),
                "generated": generated,
                "generator": generator,
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
        rows.append(row)
    digest = _digest(
        "inventory", [{field: row[field] for field in DIGEST_FIELDS} for row in rows]
    )
    for row in rows:
        row["inventory_digest"] = digest
    return rows


def _validate_cell(field: str, value: str, *, row_number: int) -> None:
    _require(field in FIELD_BYTE_LIMITS, "LEDGER_FIELD_UNKNOWN")
    _require(isinstance(value, str), "LEDGER_CELL_NOT_TEXT")
    try:
        encoded = value.encode("utf-8", "strict")
    except UnicodeEncodeError as error:
        raise VerificationError("LEDGER_CELL_NOT_UTF8") from error
    _require(
        len(encoded) <= FIELD_BYTE_LIMITS[field],
        f"LEDGER_CELL_BOUND:{row_number}:{field}",
    )
    _require(
        unicodedata.normalize("NFC", value) == value,
        f"LEDGER_CELL_NOT_NFC:{row_number}:{field}",
    )
    _require(
        not any(unicodedata.category(char).startswith("C") for char in value),
        f"LEDGER_CELL_CONTROL:{row_number}:{field}",
    )


def _parse_ledger(payload: bytes) -> list[dict[str, str]]:
    _require(0 < len(payload) <= MAX_LEDGER_BYTES, "LEDGER_BYTE_BOUND")
    _require(
        payload.endswith(b"\n") and b"\r" not in payload and b"\0" not in payload,
        "LEDGER_ENCODING",
    )
    try:
        text = payload.decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        raise VerificationError("LEDGER_NOT_UTF8") from error
    previous_limit = csv.field_size_limit()
    try:
        csv.field_size_limit(MAX_CELL_BYTES)
        records = list(csv.reader(io.StringIO(text, newline=""), strict=True))
    except (csv.Error, OverflowError) as error:
        raise VerificationError("LEDGER_CSV_INVALID") from error
    finally:
        csv.field_size_limit(previous_limit)
    _require(len(records) == EXPECTED_IMPLEMENTATION_PATHS + 1, "LEDGER_ROW_COUNT")
    _require(tuple(records[0]) == FIELDS, "LEDGER_HEADER")
    _require(
        all(len(record) == len(FIELDS) for record in records[1:]), "LEDGER_ROW_WIDTH"
    )
    rows = [dict(zip(FIELDS, record, strict=True)) for record in records[1:]]
    paths = [row["path"] for row in rows]
    for row_number, row in enumerate(rows, start=2):
        for field, value in row.items():
            _validate_cell(field, value, row_number=row_number)
        _canonical_path(row["path"])
    _require(len(paths) == len(set(paths)), "LEDGER_DUPLICATE_PATH")
    _require_portable_unique(paths, "LEDGER_PORTABLE_PATH_COLLISION")
    _require(
        paths == sorted(paths, key=lambda item: item.encode("utf-8")),
        "LEDGER_PATH_ORDER",
    )
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, lineterminator="\n", quoting=csv.QUOTE_MINIMAL)
    writer.writerows(records)
    _require(stream.getvalue().encode("utf-8") == payload, "LEDGER_NOT_CANONICAL")
    return rows


def _validate_mutable(row: dict[str, str], ledger_paths: set[str]) -> None:
    path = row["path"]
    _require(
        all(row[field] in TRISTATE for field in TRISTATE_FIELDS), "REVIEW_TRISTATE"
    )
    _require(row["review_status"] in REVIEW_STATUSES, "REVIEW_STATUS")
    _require(
        row["provenance_review_status"] in PROVENANCE_STATUSES, "PROVENANCE_STATUS"
    )
    _require(row["license_review_status"] in LICENSE_STATUSES, "LICENSE_STATUS")
    if path == GITIGNORE_PATH:
        _require(row["public_surface"] != "NO", "PUBLIC_SURFACE_CONTRADICTION")
    elif path in {LEDGER_PATH, PRODUCT_TOOL, PRODUCT_TESTS}:
        _require(row["public_surface"] != "YES", "PUBLIC_SURFACE_CONTRADICTION")
    assigned = row["reviewer"] not in {"", "UNASSIGNED"}
    if assigned:
        reviewer = row["reviewer"]
        _require(
            reviewer == reviewer.strip()
            and reviewer.casefold()
            not in {
                "n/a",
                "none",
                "self",
                "tbd",
                "todo",
                "unknown",
                "unassigned",
            },
            "REVIEWER_INVALID",
        )
    _require(
        not row["completed_at"]
        or RFC3339_UTC.fullmatch(row["completed_at"]) is not None,
        "REVIEW_TIME",
    )
    if row["completed_at"]:
        try:
            datetime.strptime(row["completed_at"], "%Y-%m-%dT%H:%M:%SZ")
        except ValueError as error:
            raise VerificationError("REVIEW_TIME") from error
        _require(row["review_status"] == "REVIEWED", "REVIEW_TIME_BEFORE_COMPLETION")
    _require(row["generated"] != "YES" or bool(row["generator"]), "GENERATOR_MISSING")
    _require(
        row["generated"] != "NO" or not row["generator"], "GENERATOR_CONTRADICTION"
    )
    _require(
        row["generated"] != "UNKNOWN" or not row["generator"],
        "GENERATOR_UNRESOLVED_CONTRADICTION",
    )
    if row["generated"] == "YES":
        _require(
            row["generator"] in ledger_paths
            or row["generator"] in ALLOWED_EXTERNAL_GENERATORS,
            "GENERATOR_NOT_IN_INVENTORY",
        )
    if row["provenance_review_status"] in {"CONFIRMED", "REJECTED"}:
        _require(bool(row["provenance_evidence"]), "PROVENANCE_EVIDENCE_MISSING")
    if row["license_review_status"] in {"APPROVED", "REJECTED"}:
        _require(bool(row["license_evidence"]), "LICENSE_EVIDENCE_MISSING")
    if row["license_review_status"] == "APPROVED":
        _require(bool(row["license_expression"]), "LICENSE_EXPRESSION_MISSING")
    if row["review_status"] == "REVIEWED":
        _require(assigned, "REVIEWER_MISSING")
        _require(
            bool(row["completed_at"] and row["disposition"]),
            "REVIEW_DISPOSITION_MISSING",
        )
        _require(
            row["disposition"] in {"ACCEPTED", "NOT_APPLICABLE"}, "REVIEW_NOT_ACCEPTED"
        )
        _require(
            all(row[field] != "UNKNOWN" for field in TRISTATE_FIELDS), "REVIEW_UNKNOWN"
        )
        _require(
            row["provenance_review_status"] in {"CONFIRMED", "NOT_APPLICABLE"},
            "REVIEW_PROVENANCE",
        )
        _require(
            row["license_review_status"] in {"APPROVED", "NOT_APPLICABLE"},
            "REVIEW_LICENSE",
        )
        critical = any(
            row[field] == "YES"
            for field in (
                "public_surface",
                "security_critical",
                "science_critical",
                "authority_critical",
            )
        )
        _require(
            not critical
            or bool(row["requirements"] and row["tests"] and row["evidence"]),
            "REVIEW_TRACEABILITY",
        )
        _require(
            row["language"] != "UNKNOWN"
            or row["format"]
            in {
                "GITLINK_COMMIT_REFERENCE_UNVERIFIED",
                "SELF_REFERENTIAL_CSV",
                "SYMLINK_TARGET_BYTES",
            },
            "REVIEW_LANGUAGE_UNKNOWN",
        )
        _require(row["format"] not in {"UNKNOWN", "ABSENT"}, "REVIEW_FORMAT_UNKNOWN")
        _require(
            not row["format"].startswith(
                (
                    "ANSI_ESCAPE_WITH_",
                    "BINARY_WITH_",
                    "CONTROL_BEARING_",
                    "TEXT_WITH_",
                )
            ),
            "REVIEW_CONTENT_FORMAT_CONTRADICTION",
        )
    _require(path == row["path"], "REVIEW_PATH_DRIFT")


def _validate_generated_evolution(
    current: dict[str, str], frozen: dict[str, str]
) -> None:
    initial = frozen["generated"]
    initial_generator = frozen["generator"]
    if initial in {"YES", "NO"}:
        _require(
            current["generated"] == initial
            and current["generator"] == initial_generator,
            "GENERATED_RULE_DRIFT",
        )
        return
    _require(initial == "UNKNOWN" and not initial_generator, "GENERATED_INITIAL_STATE")
    if current["generated"] == "UNKNOWN":
        _require(not current["generator"], "GENERATOR_UNRESOLVED_CONTRADICTION")
        return
    if current["generated"] not in {"YES", "NO"}:
        return
    _require(
        current["review_status"] == "REVIEWED"
        and current["reviewer"] not in {"", "UNASSIGNED"}
        and bool(current["completed_at"])
        and current["disposition"] in {"ACCEPTED", "NOT_APPLICABLE"}
        and current["provenance_review_status"] == "CONFIRMED"
        and bool(current["provenance_evidence"]),
        "GENERATED_RESOLUTION_REVIEW",
    )


def _validate_initial_review_state(rows: Sequence[dict[str, str]]) -> None:
    unresolved_fields = (
        "public_surface",
        "security_critical",
        "science_critical",
        "authority_critical",
    )
    empty_fields = (
        "provenance_evidence",
        "license_expression",
        "license_evidence",
        "requirements",
        "assumptions",
        "defects",
        "tests",
        "evidence",
        "disposition",
        "completed_at",
    )
    _require(
        all(
            row["reviewer"] == "UNASSIGNED"
            and row["review_status"] == "UNREVIEWED"
            and row["provenance_review_status"] == "UNREVIEWED"
            and row["license_review_status"] == "UNREVIEWED"
            and all(row[field] == "UNKNOWN" for field in unresolved_fields)
            and all(not row[field] for field in empty_fields)
            for row in rows
        ),
        "INITIAL_REVIEW_STATE",
    )


def _validate_product_asts(
    tool_payload: bytes, test_payload: bytes, verifier_payload: bytes
) -> None:
    try:
        tool_tree = ast.parse(tool_payload, filename=PRODUCT_TOOL)
        test_tree = ast.parse(test_payload, filename=PRODUCT_TESTS)
        verifier_tree = ast.parse(verifier_payload, filename=VERIFIER_PATH)
    except (SyntaxError, ValueError) as error:
        raise VerificationError("PRODUCT_AST_INVALID") from error
    field_value: tuple[str, ...] | None = None
    schema_value: str | None = None
    function_names: set[str] = set()
    for node in tool_tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            function_names.add(node.name)
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "FIELDS"
            for target in node.targets
        ):
            try:
                field_value = tuple(ast.literal_eval(node.value))
            except (ValueError, TypeError) as error:
                raise VerificationError("PRODUCT_FIELDS_NOT_LITERAL") from error
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "SCHEMA_VERSION"
            for target in node.targets
        ):
            try:
                schema_value = ast.literal_eval(node.value)
            except (ValueError, TypeError) as error:
                raise VerificationError("PRODUCT_SCHEMA_NOT_LITERAL") from error
    _require(field_value == FIELDS and schema_value == "1.0.0", "PRODUCT_SCHEMA_DRIFT")
    _require(
        {
            "_snapshot_inventory",
            "build_inventory",
            "generate_ledger",
            "verify_ledger",
            "main",
        }.issubset(function_names),
        "PRODUCT_API_MISSING",
    )
    definition_names = {
        node.name
        for node in ast.walk(tool_tree)
        if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
    }
    _require(
        EXPECTED_CREATE_ONCE_DEFINITIONS.issubset(definition_names),
        "PRODUCT_CREATE_ONCE_API_MISSING",
    )
    _require(
        not {
            "PublicationLock",
            "PublicationReceipt",
            "_atomic_exchange",
            "_rollback_publication",
            "rollback_publication",
        }.intersection(definition_names),
        "PRODUCT_RETIRED_AUTHORITY",
    )
    test_names = {
        node.name
        for node in ast.walk(test_tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name.startswith("test_")
    }
    _require(
        test_names == EXPECTED_PRODUCT_TEST_IDS,
        "PRODUCT_TEST_COVERAGE",
    )
    tool_strings = {
        node.value
        for node in ast.walk(tool_tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    }
    _require(
        "--implementation-commit" in tool_strings
        and "EXACT_IMPLEMENTATION_SNAPSHOT" in tool_strings,
        "PRODUCT_SNAPSHOT_INTERFACE_MISSING",
    )
    _require(
        "--replace" not in tool_strings
        and "POST_CREATION_TRIPLE_RECONCILIATION" in tool_strings
        and EXPECTED_CREATE_ONCE_STATES.issubset(tool_strings),
        "PRODUCT_CREATE_ONCE_INTERFACE",
    )
    tool_identifiers = {
        node.id for node in ast.walk(tool_tree) if isinstance(node, ast.Name)
    } | {node.attr for node in ast.walk(tool_tree) if isinstance(node, ast.Attribute)}
    _require(
        {
            "canonical_creation_verified",
            "creation_may_have_occurred",
            "target_creation_confirmed",
            "target_creation_was_confirmed",
            "canonical_creation_was_verified",
        }.issubset(tool_identifiers),
        "PRODUCT_CREATE_ONCE_STATE_BINDING",
    )
    for node in ast.walk(tool_tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            _require(
                node.func.attr not in {"link", "remove", "rename", "replace", "unlink"},
                "PRODUCT_RETIRED_MUTATION_PRIMITIVE",
            )
    forbidden_modules = {"importlib", "runpy"}
    for node in ast.walk(verifier_tree):
        if isinstance(node, ast.Import):
            _require(
                not any(
                    alias.name.split(".")[0] in forbidden_modules
                    for alias in node.names
                ),
                "VERIFIER_IMPORT_BOUNDARY",
            )
        if isinstance(node, ast.ImportFrom) and node.module:
            _require(
                node.module.split(".")[0] not in forbidden_modules,
                "VERIFIER_IMPORT_BOUNDARY",
            )
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            _require(
                node.func.id not in {"eval", "exec", "__import__"},
                "VERIFIER_EXECUTION_BOUNDARY",
            )
    for node in ast.walk(tool_tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            _require(
                "tools.release.tasks" not in node.module,
                "PRODUCT_IMPORTS_REGISTERED_ORACLE",
            )


def test_fixture() -> dict[str, Any]:
    return {
        "chain": "F>I>C>D<=CURRENT",
        "f_diff": {
            FREEZE_PATH: "A",
            REGISTRY_PATH: "M",
            REGISTERED_TESTS_PATH: "A",
            VERIFIER_PATH: "A",
        },
        "i_diff": dict(EXPECTED_IMPLEMENTATION_PLAN),
        "f_count": EXPECTED_SOURCE_PATHS,
        "i_count": EXPECTED_IMPLEMENTATION_PATHS,
        "schema": FIELDS,
        "rows": EXPECTED_IMPLEMENTATION_PATHS,
        "paths_equal": True,
        "canonical": True,
        "source_binding": True,
        "capture_binding": True,
        "self_binding": True,
        "zero_extras": True,
        "classifications": True,
        "generated_links": True,
        "independent": True,
        "digests": True,
        "bounded": True,
        "no_fallback": True,
        "output_binding": True,
        "retention": True,
        "regular_objects": True,
        "git_object_reads_only": True,
        "typed_evidence": True,
        "product_hashes": True,
        "create_once": True,
        "secret_ignore": True,
        "unassigned": True,
    }


def validate_control(control_id: str, facts: dict[str, Any]) -> bool:
    _require(control_id in CONTROL_IDS, "CONTROL_ID_UNKNOWN")
    checks = {
        "CH-T001-N01": facts.get("chain") == "F>I>C>D<=CURRENT"
        and facts.get("f_diff") == test_fixture()["f_diff"],
        "CH-T001-N02": facts.get("f_count") == EXPECTED_SOURCE_PATHS
        and facts.get("i_count") == EXPECTED_IMPLEMENTATION_PATHS
        and facts.get("i_diff") == test_fixture()["i_diff"],
        "CH-T001-N03": facts.get("schema") == FIELDS
        and facts.get("rows") == EXPECTED_IMPLEMENTATION_PATHS
        and facts.get("paths_equal") is True
        and facts.get("canonical") is True,
        "CH-T001-N04": facts.get("source_binding") is True,
        "CH-T001-N05": facts.get("capture_binding") is True,
        "CH-T001-N06": facts.get("self_binding") is True,
        "CH-T001-N07": facts.get("zero_extras") is True,
        "CH-T001-N08": facts.get("classifications") is True,
        "CH-T001-N09": facts.get("generated_links") is True,
        "CH-T001-N10": facts.get("independent") is True,
        "CH-T001-N11": facts.get("digests") is True,
        "CH-T001-N12": facts.get("bounded") is True
        and facts.get("no_fallback") is True,
        "CH-T001-N13": facts.get("output_binding") is True,
        "CH-T001-N14": facts.get("retention") is True,
        "CH-T001-N15": facts.get("regular_objects") is True
        and facts.get("git_object_reads_only") is True,
        "CH-T001-N16": facts.get("typed_evidence") is True,
        "CH-T001-N17": facts.get("product_hashes") is True,
        "CH-T001-N18": facts.get("create_once") is True
        and facts.get("no_fallback") is True,
        "CH-T001-N19": facts.get("secret_ignore") is True
        and facts.get("zero_extras") is True,
        "CH-T001-N20": facts.get("unassigned") is True,
    }
    _require(checks[control_id], f"CONTROL_FAILED:{control_id}")
    return True


def validate_counterfactual(counterfactual_id: str, facts: dict[str, Any]) -> bool:
    _require(counterfactual_id in COUNTERFACTUAL_IDS, "COUNTERFACTUAL_ID_UNKNOWN")
    checks = {
        "CH-T001-CF01": facts.get("source_binding") is True
        and facts.get("capture_binding") is True,
        "CH-T001-CF02": facts.get("chain") == "F>I>C>D<=CURRENT"
        and facts.get("output_binding") is True,
        "CH-T001-CF03": facts.get("retention") is True,
        "CH-T001-CF04": facts.get("digests") is True,
        "CH-T001-CF05": facts.get("paths_equal") is True
        and facts.get("rows") == EXPECTED_IMPLEMENTATION_PATHS,
        "CH-T001-CF06": facts.get("bounded") is True
        and facts.get("no_fallback") is True,
        "CH-T001-CF07": facts.get("zero_extras") is True
        and facts.get("regular_objects") is True,
        "CH-T001-CF08": facts.get("schema") == FIELDS
        and facts.get("canonical") is True,
        "CH-T001-CF09": facts.get("self_binding") is True
        and facts.get("retention") is True,
        "CH-T001-CF10": facts.get("canonical") is True
        and facts.get("classifications") is True
        and facts.get("regular_objects") is True,
    }
    _require(checks[counterfactual_id], f"COUNTERFACTUAL_FAILED:{counterfactual_id}")
    return True


def _file_record(path: str, entry: dict[str, Any], payload: bytes) -> dict[str, Any]:
    return {
        "path": path,
        "sha256": hashlib.sha256(payload).hexdigest(),
        "bytes": len(payload),
        "lines": len(payload.splitlines()),
        "git_mode": entry["mode"],
        "git_object_type": entry["type"],
        "git_object_id": entry["oid"],
    }


def _central_file_record(
    path: str, entry: dict[str, Any], payload: bytes
) -> dict[str, Any]:
    record = _file_record(path, entry, payload)
    if not path.endswith((".json", ".py", ".sh", ".yml", ".md")) and path != "justfile":
        record.pop("lines")
    return record


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


def _expected_qualification_argv(
    freeze_commit: str, implementation_commit: str
) -> dict[str, list[str]]:
    inventory_command = [
        EVIDENCE_PYTHON,
        "-B",
        "-I",
        "-P",
        VERIFIER_PATH,
        "--repo",
        ".",
        "--freeze-commit",
        freeze_commit,
        "--implementation-commit",
        implementation_commit,
        "--inventory-only",
    ]
    commands = {
        "LEDGER_GENERATE": [
            EVIDENCE_PYTHON,
            "-B",
            "-I",
            "-P",
            PRODUCT_TOOL,
            "generate",
            "--repo",
            ".",
            "--source-commit",
            freeze_commit,
            "--ignored-policy",
            "reject",
            "--output",
            LEDGER_PATH,
        ],
        "PRODUCT_TESTS": [EVIDENCE_PYTHON, "-B", "-I", "-P", PRODUCT_TESTS],
        "EXACT_IMPLEMENTATION_VERIFY": [
            EVIDENCE_PYTHON,
            "-B",
            "-I",
            "-P",
            PRODUCT_TOOL,
            "verify",
            "--repo",
            ".",
            "--source-commit",
            freeze_commit,
            "--implementation-commit",
            implementation_commit,
            "--ignored-policy",
            "reject",
            "--ledger",
            LEDGER_PATH,
        ],
        "REGISTERED_TESTS": [
            EVIDENCE_PYTHON,
            "-B",
            "-I",
            "-P",
            REGISTERED_TESTS_PATH,
        ],
        "INDEPENDENT_RECONCILIATION": inventory_command,
        "NEGATIVE_VECTORS": [
            EVIDENCE_PYTHON,
            "-B",
            "-I",
            "-P",
            REGISTERED_TESTS_PATH,
            "-k",
            "reject",
        ],
        "TECHNIQUE_ANALYSIS": [
            EVIDENCE_PYTHON,
            "-B",
            "-I",
            "-P",
            REGISTERED_TESTS_PATH,
            "-k",
            "technique_",
        ],
    }
    commands.update(
        {
            phase: ["/usr/bin/time", "-l", *inventory_command]
            for phase in RESOURCE_SAMPLE_PHASES
        }
    )
    return commands


def _validate_evidence_common(
    document: dict[str, Any],
    evidence_id: str,
    freeze_commit: str,
    implementation_commit: str,
) -> tuple[str, str]:
    _require(
        document.get("schema_id") == EVIDENCE_SCHEMA_IDS[evidence_id], "EVIDENCE_SCHEMA"
    )
    _require(document.get("evidence_id") == evidence_id, "EVIDENCE_ID")
    _require(
        document.get("task_id") == TASK_ID
        and _integer(document.get("epoch"), "EVIDENCE_EPOCH") == EPOCH,
        "EVIDENCE_TASK",
    )
    _require(
        document.get("freeze_commit") == freeze_commit
        and document.get("implementation_commit") == implementation_commit,
        "EVIDENCE_COMMIT_BINDING",
    )
    started = _timestamp(document.get("started_at_utc"), "EVIDENCE_STARTED_AT")
    completed = _timestamp(document.get("completed_at_utc"), "EVIDENCE_COMPLETED_AT")
    _require(started <= completed, "EVIDENCE_TIME_ORDER")
    _require(document.get("result") in {"PASS", "FAIL"}, "EVIDENCE_RESULT_TYPE")
    _require(document["result"] == "PASS", "EVIDENCE_RESULT_NOT_PASS")
    return started, completed


def _python_test_names(payload: bytes, label: str) -> list[str]:
    try:
        tree = ast.parse(payload, filename=label)
    except (SyntaxError, ValueError) as error:
        raise VerificationError("TEST_AST_INVALID") from error
    names = sorted(
        {
            node.name
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name.startswith("test_")
        }
    )
    _require(names, "TEST_IDS_EMPTY")
    return names


def _validate_command_log(
    document: dict[str, Any],
    started: str,
    completed: str,
    freeze_commit: str,
    implementation_commit: str,
) -> tuple[dict[str, dict[str, Any]], dict[str, str]]:
    environment = _exact_keys(
        document["environment"],
        {"architecture", "git_version", "platform", "python_version"},
        "COMMAND_ENVIRONMENT_KEYS",
    )
    _require(
        environment["python_version"] == "CPython 3.14.6", "COMMAND_PYTHON_VERSION"
    )
    for field in ("architecture", "git_version", "platform"):
        _text(environment[field], "COMMAND_ENVIRONMENT_VALUE", maximum=1024)
    commands = document["commands"]
    _require(
        isinstance(commands, list) and len(commands) == len(REQUIRED_COMMAND_PHASES),
        "COMMAND_COUNT",
    )
    by_id: dict[str, dict[str, Any]] = {}
    by_phase: dict[str, str] = {}
    expected_argv = _expected_qualification_argv(freeze_commit, implementation_commit)
    expected_ids = [
        f"CH-T001-CMD{index:02d}"
        for index in range(1, len(REQUIRED_COMMAND_PHASES) + 1)
    ]
    previous_completed = started
    for index, command in enumerate(commands):
        command = _exact_keys(
            command,
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
            "COMMAND_KEYS",
        )
        command_id = command["id"]
        phase = command["phase"]
        _require(command_id == expected_ids[index], "COMMAND_ID_ORDER")
        _require(phase == REQUIRED_COMMAND_PHASES[index], "COMMAND_PHASE_ORDER")
        argv = _text_list(command["argv"], "COMMAND_ARGV", minimum=1)
        _require(
            all(len(item.encode("utf-8")) <= 4096 for item in argv)
            and _strict_equal(argv, expected_argv[phase]),
            "COMMAND_ARG_BOUND",
        )
        _require(command["cwd"] == ".", "COMMAND_CWD")
        _require(
            command["exit_code"] == 0 and type(command["exit_code"]) is int,
            "COMMAND_EXIT",
        )
        command_started = _timestamp(command["started_at_utc"], "COMMAND_STARTED_AT")
        command_completed = _timestamp(
            command["completed_at_utc"], "COMMAND_COMPLETED_AT"
        )
        _require(
            started
            <= previous_completed
            <= command_started
            <= command_completed
            <= completed,
            "COMMAND_TIME_ORDER",
        )
        previous_completed = command_completed
        for stream in ("stdout", "stderr"):
            value = command[stream]
            _require(isinstance(value, str), "COMMAND_STREAM_TYPE")
            digest = command[f"{stream}_sha256"]
            _require(
                isinstance(digest, str) and HEX64.fullmatch(digest),
                "COMMAND_STREAM_HASH",
            )
            _require(
                hashlib.sha256(value.encode("utf-8")).hexdigest() == digest,
                "COMMAND_STREAM_BINDING",
            )
        _require(command["stdout"] or command["stderr"], "COMMAND_STREAMS_EMPTY")
        by_id[command_id] = command
        by_phase[phase] = command_id
    _require(
        len(by_id) == len(commands) and len(by_phase) == len(commands),
        "COMMAND_DUPLICATE",
    )
    return by_id, by_phase


def _classification_counts(rows: list[dict[str, str]]) -> dict[str, dict[str, int]]:
    return {
        field: dict(sorted(Counter(row[field] for row in rows).items()))
        for field in ("current_content_kind", "format", "generated", "language")
    }


def _require_unittest_stream(
    command: dict[str, Any], *, expected_tests: int, code: str
) -> float:
    _require(command["stdout"] == "", code)
    pattern = re.compile(
        rf"^{re.escape('.' * expected_tests)}\n-+\n"
        rf"Ran {expected_tests} tests in ([0-9]+(?:\.[0-9]+)?)s\n\nOK\n$"
    )
    match = pattern.fullmatch(command["stderr"])
    _require(match is not None, code)
    return _number(float(match.group(1)), code)


def _elapsed_seconds(started_at_utc: str, completed_at_utc: str) -> float:
    started = datetime.strptime(started_at_utc, "%Y-%m-%dT%H:%M:%SZ")
    completed = datetime.strptime(completed_at_utc, "%Y-%m-%dT%H:%M:%SZ")
    return (completed - started).total_seconds()


def _command_elapsed_seconds(command: dict[str, Any]) -> float:
    return _elapsed_seconds(command["started_at_utc"], command["completed_at_utc"])


def _resource_real_seconds(command: dict[str, Any]) -> float:
    matches = re.findall(
        r"(?m)^\s*([0-9]+(?:\.[0-9]+)?)\s+real\s+"
        r"[0-9]+(?:\.[0-9]+)?\s+user\s+"
        r"[0-9]+(?:\.[0-9]+)?\s+sys\s*$",
        command["stderr"],
    )
    _require(len(matches) == 1, "COMMAND_RESOURCE_REAL_BINDING")
    return _number(float(matches[0]), "COMMAND_RESOURCE_REAL_BINDING")


def _resource_peak_rss_bytes(command: dict[str, Any]) -> int:
    match = re.search(
        r"(?m)^\s*([0-9]+)\s+maximum resident set size\s*$",
        command["stderr"],
    )
    _require(
        match is not None and command["stderr"].count("maximum resident set size") == 1,
        "COMMAND_RESOURCE_RSS_BINDING",
    )
    return _integer(int(match.group(1)), "COMMAND_RESOURCE_RSS_BINDING", minimum=1)


def _require_command_stream_semantics(
    *,
    commands: dict[str, dict[str, Any]],
    command_by_phase: dict[str, str],
    freeze_commit: str,
    implementation_commit: str,
    source_tree: str,
    implementation_tree: str,
    source_entries: dict[str, dict[str, Any]],
    implementation_entries: dict[str, dict[str, Any]],
    ledger_payload: bytes,
    rows: list[dict[str, str]],
    product_tool_payload: bytes,
    product_tests_payload: bytes,
    registered_tests_payload: bytes,
    peak_rss_bytes: int,
) -> None:
    ledger_sha256 = hashlib.sha256(ledger_payload).hexdigest()
    inventory_digest = rows[0]["inventory_digest"]
    tool_sha256 = hashlib.sha256(product_tool_payload).hexdigest()
    tests_sha256 = hashlib.sha256(product_tests_payload).hexdigest()

    def command(phase: str) -> dict[str, Any]:
        return commands[command_by_phase[phase]]

    generation = command("LEDGER_GENERATE")
    _require(generation["stderr"] == "", "COMMAND_GENERATE_STDERR")
    _require(
        _strict_equal(
            _canonical_json(
                generation["stdout"].encode("utf-8"), "COMMAND_GENERATE_STDOUT"
            ),
            {
                "inventory_digest": inventory_digest,
                "ledger_bytes": len(ledger_payload),
                "ledger_sha256": ledger_sha256,
                "rows": len(rows),
                "source_commit": freeze_commit,
                "source_tree": source_tree,
                "verification_view": "POST_CREATION_TRIPLE_RECONCILIATION",
            },
        ),
        "COMMAND_GENERATE_RESULT",
    )
    _require_unittest_stream(
        command("PRODUCT_TESTS"),
        expected_tests=len(_python_test_names(product_tests_payload, PRODUCT_TESTS)),
        code="COMMAND_PRODUCT_TEST_RESULT",
    )
    exact_verify = command("EXACT_IMPLEMENTATION_VERIFY")
    _require(exact_verify["stderr"] == "", "COMMAND_EXACT_VERIFY_STDERR")
    _require(
        _strict_equal(
            _canonical_json(
                exact_verify["stdout"].encode("utf-8"),
                "COMMAND_EXACT_VERIFY_STDOUT",
            ),
            {
                "implementation_commit": implementation_commit,
                "implementation_ledger_sha256": ledger_sha256,
                "inventory_digest": inventory_digest,
                "ledger_bytes": len(ledger_payload),
                "ledger_sha256": ledger_sha256,
                "retained_head_commit": implementation_commit,
                "rows": len(rows),
                "source_commit": freeze_commit,
                "source_tree": source_tree,
                "verification_view": "EXACT_IMPLEMENTATION_SNAPSHOT",
            },
        ),
        "COMMAND_EXACT_VERIFY_RESULT",
    )
    registered_names = _python_test_names(
        registered_tests_payload, REGISTERED_TESTS_PATH
    )
    _require_unittest_stream(
        command("REGISTERED_TESTS"),
        expected_tests=len(registered_names),
        code="COMMAND_REGISTERED_TEST_RESULT",
    )
    expected_inventory = {
        "epoch": EPOCH,
        "freeze_commit": freeze_commit,
        "implementation_commit": implementation_commit,
        "implementation_tree": implementation_tree,
        "inventory_digest": inventory_digest,
        "ledger_sha256": ledger_sha256,
        "result": "PASS",
        "rows": len(rows),
        "schema_version": "1.0.0",
        "source_tree": source_tree,
        "task_id": TASK_ID,
        "tests_sha256": tests_sha256,
        "tool_sha256": tool_sha256,
        "unique_git_blobs": len(
            {
                *(entry["oid"] for entry in source_entries.values()),
                *(entry["oid"] for entry in implementation_entries.values()),
            }
        ),
    }
    reconciliation = command("INDEPENDENT_RECONCILIATION")
    _require(
        reconciliation["stderr"] == ""
        and _strict_equal(
            _canonical_json(
                reconciliation["stdout"].encode("utf-8"),
                "COMMAND_RECONCILIATION_STDOUT",
            ),
            expected_inventory,
        ),
        "COMMAND_RECONCILIATION_RESULT",
    )
    rejected_tests = sum("reject" in name for name in registered_names)
    _require(rejected_tests > 0, "COMMAND_NEGATIVE_TEST_COUNT")
    _require_unittest_stream(
        command("NEGATIVE_VECTORS"),
        expected_tests=rejected_tests,
        code="COMMAND_NEGATIVE_RESULT",
    )
    technique_tests = [
        name for name in registered_names if name.startswith("test_technique_")
    ]
    _require(
        technique_tests == sorted(TECHNIQUE_REGISTERED_TEST_IDS.values()),
        "COMMAND_TECHNIQUE_TEST_SET",
    )
    _require_unittest_stream(
        command("TECHNIQUE_ANALYSIS"),
        expected_tests=len(technique_tests),
        code="COMMAND_TECHNIQUE_RESULT",
    )
    observed_rss: list[int] = []
    for phase in RESOURCE_SAMPLE_PHASES:
        resource = command(phase)
        _require(
            _strict_equal(
                _canonical_json(
                    resource["stdout"].encode("utf-8"),
                    f"COMMAND_{phase}_STDOUT",
                ),
                expected_inventory,
            ),
            "COMMAND_RESOURCE_RESULT",
        )
        observed_rss.append(_resource_peak_rss_bytes(resource))
    _require(max(observed_rss) == peak_rss_bytes, "COMMAND_RESOURCE_RSS_MAXIMUM")


def _validate_typed_evidence_bodies(
    *,
    freeze: dict[str, Any],
    qualification: dict[str, Any],
    freeze_commit: str,
    implementation_commit: str,
    source_tree: str,
    implementation_tree: str,
    source_entries: dict[str, dict[str, Any]],
    implementation_entries: dict[str, dict[str, Any]],
    c_entries: dict[str, dict[str, Any]],
    c_payloads: dict[str, bytes],
    ledger_payload: bytes,
    rows: list[dict[str, str]],
    verifier_payload: bytes,
    registered_tests_payload: bytes,
    product_tool_payload: bytes,
    product_tests_payload: bytes,
) -> tuple[
    dict[str, dict[str, Any]],
    dict[str, dict[str, Any]],
    dict[str, str],
]:
    requirements = freeze["qualification_evidence_requirements"]
    _require(
        [item["id"] for item in requirements] == list(EVIDENCE_SCHEMA_IDS),
        "EVIDENCE_REQUIREMENT_ORDER",
    )
    qualification_records = qualification.get("evidence_records")
    _require(
        isinstance(qualification_records, list)
        and len(qualification_records) == len(requirements),
        "EVIDENCE_QUALIFICATION_RECORDS",
    )
    documents: dict[str, dict[str, Any]] = {}
    record_by_id: dict[str, dict[str, Any]] = {}
    times: dict[str, tuple[str, str]] = {}
    for requirement, qualification_record in zip(
        requirements, qualification_records, strict=True
    ):
        evidence_id = requirement["id"]
        path = requirement["path"]
        _require(path in c_entries and path in c_payloads, "EVIDENCE_FILE_MISSING")
        payload = c_payloads[path]
        _require(
            0 < len(payload) <= min(requirement["max_bytes"], 256 * 1024),
            "EVIDENCE_FILE_BOUND",
        )
        document = _canonical_json(payload, evidence_id)
        qualification_record = _exact_keys(
            qualification_record,
            {
                "completed_at_utc",
                "file",
                "id",
                "kind",
                "result",
                "started_at_utc",
                "subject_commits",
            },
            "EVIDENCE_QUALIFICATION_RECORD_KEYS",
        )
        expected_file = _file_record(path, c_entries[path], payload)
        _require(
            qualification_record["id"] == evidence_id
            and qualification_record["kind"] == requirement["kind"]
            and _strict_equal(qualification_record["file"], expected_file)
            and qualification_record["subject_commits"]
            == [freeze_commit, implementation_commit]
            and qualification_record["result"] == "PASS",
            "EVIDENCE_QUALIFICATION_RECORD_BINDING",
        )
        specific_keys = {
            "CH-T001-E01": {
                "assumptions",
                "counterfactuals",
                "immutable_fields",
                "implementation_paths",
                "ledger_path",
                "limitations",
                "mutable_review_fields",
                "required_evidence",
                "requirements",
            },
            "CH-T001-E02": {"commands", "environment"},
            "CH-T001-E03": {
                "accepted_vectors",
                "command_ids",
                "product_test_ids",
                "registered_test_ids",
                "representative_fail_closed_test_ids",
                "rejected_vectors",
            },
            "CH-T001-E04": {
                "covered_counterfactual_ids",
                "covered_requirement_ids",
                "techniques",
            },
            "CH-T001-E05": {
                "capacity_disposition",
                "command_ids",
                "declared_maxima",
                "observed_distributions",
                "observed_maxima",
            },
            "CH-T001-E06": {
                "implementation_tree",
                "ledger",
                "source_tree",
                "tests",
                "tool",
            },
            "CH-T001-E07": {
                "assumptions",
                "claim_outcome",
                "completion_rule",
                "required_evidence",
                "requirements_complete",
            },
            "CH-T001-E08": {
                "classification_counts",
                "digests",
                "filesystem_entries",
                "ignored_paths",
                "path_set_sha256",
                "paths",
                "rows",
                "source_rows",
                "untracked_paths",
            },
            "CH-T001-E09": {
                "command_ids",
                "distinct_from_release_author",
                "independent_oracle",
                "ledger",
                "reconciliation",
                "review_requirement_id",
                "reviewer",
                "reviewer_key_fingerprint",
                "reviewer_public_key",
            },
        }[evidence_id]
        _exact_keys(
            document, EVIDENCE_COMMON_KEYS | specific_keys, "EVIDENCE_BODY_KEYS"
        )
        started, completed = _validate_evidence_common(
            document, evidence_id, freeze_commit, implementation_commit
        )
        _require(
            qualification_record["started_at_utc"] == started
            and qualification_record["completed_at_utc"] == completed,
            "EVIDENCE_TIME_CROSS_RECORD",
        )
        documents[evidence_id] = document
        record_by_id[evidence_id] = qualification_record
        times[evidence_id] = (started, completed)

    selected_outcome_id = qualification.get("selected_claim_outcome_id")
    outcomes = {
        item["id"]: item
        for item in freeze["claim_outcomes"]
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }
    _require(selected_outcome_id in outcomes, "EVIDENCE_CLAIM_OUTCOME")
    selected_outcome = outcomes[selected_outcome_id]
    handoff = freeze["handoff_task_contract"]

    traceability = documents["CH-T001-E01"]
    expected_requirements = [
        {"id": item["id"], "statement": item["statement"]}
        for item in freeze["normative_controls"]
    ]
    expected_counterfactuals = [
        {"id": item["id"], "statement": item["statement"]}
        for item in freeze["mandatory_counterfactuals"]
    ]
    _require(
        traceability["ledger_path"] == LEDGER_PATH
        and _strict_equal(
            traceability["implementation_paths"], sorted(freeze["implementation_plan"])
        )
        and _strict_equal(traceability["immutable_fields"], list(IMMUTABLE_FIELDS))
        and _strict_equal(
            traceability["mutable_review_fields"], list(MUTABLE_REVIEW_FIELDS)
        )
        and _strict_equal(traceability["requirements"], expected_requirements)
        and _strict_equal(traceability["counterfactuals"], expected_counterfactuals)
        and _strict_equal(traceability["assumptions"], handoff["preconditions"])
        and _strict_equal(
            traceability["required_evidence"], handoff["required_evidence"]
        )
        and _strict_equal(traceability["limitations"], selected_outcome["limitations"]),
        "EVIDENCE_TRACEABILITY_BINDING",
    )

    command_log = documents["CH-T001-E02"]
    commands, command_by_phase = _validate_command_log(
        command_log,
        *times["CH-T001-E02"],
        freeze_commit,
        implementation_commit,
    )

    vectors = documents["CH-T001-E03"]
    control_cases = [
        *freeze["normative_controls"],
        *freeze["mandatory_counterfactuals"],
    ]
    expected_accepted = [
        {
            "requirement_id": item["id"],
            "result": "PASS",
            "test_id": item["accepted_test_id"],
        }
        for item in control_cases
    ]
    expected_rejected = [
        {
            "requirement_id": item["id"],
            "result": "PASS",
            "test_id": item["rejected_test_id"],
        }
        for item in control_cases
    ]
    expected_vector_commands = [
        command_by_phase["PRODUCT_TESTS"],
        command_by_phase["REGISTERED_TESTS"],
        command_by_phase["NEGATIVE_VECTORS"],
    ]
    expected_fail_closed_tests = [
        f"{REGISTERED_TESTS_PATH}::test_entrypoint_rejects_non_linear_chain",
        f"{REGISTERED_TESTS_PATH}::test_entrypoint_rejects_mutated_ledger_snapshot",
        f"{REGISTERED_TESTS_PATH}::test_entrypoint_rejects_product_snapshot_substitution",
        f"{REGISTERED_TESTS_PATH}::test_n16_empty_placeholder_or_cross_record_evidence_is_rejected",
        f"{REGISTERED_TESTS_PATH}::test_activation_command_chronology_is_fail_closed",
        f"{REGISTERED_TESTS_PATH}::test_retained_ci_records_and_logs_are_byte_bound",
        f"{REGISTERED_TESTS_PATH}::test_mutable_review_fields_match_product_fail_closed_rules",
    ]
    _require(
        _strict_equal(vectors["accepted_vectors"], expected_accepted)
        and _strict_equal(vectors["rejected_vectors"], expected_rejected)
        and _strict_equal(
            vectors["registered_test_ids"],
            _python_test_names(registered_tests_payload, REGISTERED_TESTS_PATH),
        )
        and _strict_equal(
            vectors["product_test_ids"],
            _python_test_names(product_tests_payload, PRODUCT_TESTS),
        )
        and _strict_equal(vectors["command_ids"], expected_vector_commands)
        and _strict_equal(
            vectors["representative_fail_closed_test_ids"], expected_fail_closed_tests
        ),
        "EVIDENCE_VECTOR_BINDING",
    )

    analysis = documents["CH-T001-E04"]
    techniques = analysis["techniques"]
    _require(
        isinstance(techniques, list) and len(techniques) == len(ANALYSIS_TECHNIQUES),
        "EVIDENCE_TECHNIQUE_COUNT",
    )
    product_test_names = _python_test_names(product_tests_payload, PRODUCT_TESTS)
    registered_test_names = _python_test_names(
        registered_tests_payload, REGISTERED_TESTS_PATH
    )

    def qualified(path: str, names: Iterable[str]) -> list[str]:
        return [f"{path}::{name}" for name in names]

    expected_technique_tests = {
        "UNIT_COVERAGE": [
            *qualified(PRODUCT_TESTS, product_test_names),
            *qualified(REGISTERED_TESTS_PATH, registered_test_names),
        ],
        **{
            name: [f"{REGISTERED_TESTS_PATH}::{test_id}"]
            for name, test_id in TECHNIQUE_REGISTERED_TEST_IDS.items()
            if name != "CONCURRENCY"
        },
        "CONCURRENCY": [
            *qualified(PRODUCT_TESTS, TECHNIQUE_PRODUCT_CONCURRENCY_TEST_IDS),
            f"{REGISTERED_TESTS_PATH}::{TECHNIQUE_REGISTERED_TEST_IDS['CONCURRENCY']}",
        ],
    }
    expected_technique_tests["MUTATION"] = [
        f"{REGISTERED_TESTS_PATH}::test_technique_mutation",
        f"{REGISTERED_TESTS_PATH}::test_entrypoint_rejects_non_linear_chain",
        f"{REGISTERED_TESTS_PATH}::test_entrypoint_rejects_mutated_ledger_snapshot",
        f"{REGISTERED_TESTS_PATH}::test_entrypoint_rejects_product_snapshot_substitution",
    ]
    expected_technique_commands = {
        "UNIT_COVERAGE": [
            command_by_phase["PRODUCT_TESTS"],
            command_by_phase["REGISTERED_TESTS"],
        ],
        "PROPERTY_METAMORPHIC": [command_by_phase["TECHNIQUE_ANALYSIS"]],
        "DIFFERENTIAL_ORACLE": [command_by_phase["TECHNIQUE_ANALYSIS"]],
        "FUZZ": [command_by_phase["TECHNIQUE_ANALYSIS"]],
        "MUTATION": [
            command_by_phase["REGISTERED_TESTS"],
            command_by_phase["TECHNIQUE_ANALYSIS"],
        ],
        "MODEL": [command_by_phase["TECHNIQUE_ANALYSIS"]],
        "CONCURRENCY": [
            command_by_phase["PRODUCT_TESTS"],
            command_by_phase["TECHNIQUE_ANALYSIS"],
        ],
    }
    for expected_name, technique in zip(ANALYSIS_TECHNIQUES, techniques, strict=True):
        technique = _exact_keys(
            technique,
            {
                "cases",
                "command_ids",
                "limitations",
                "name",
                "status",
                "test_ids",
            },
            "EVIDENCE_TECHNIQUE_KEYS",
        )
        test_ids = _text_list(
            technique["test_ids"], "EVIDENCE_TECHNIQUE_TEST_IDS", minimum=1
        )
        cases = _integer(technique["cases"], "EVIDENCE_TECHNIQUE_CASES")
        command_ids = _text_list(
            technique["command_ids"], "EVIDENCE_TECHNIQUE_COMMANDS", minimum=1
        )
        limitations = _text_list(
            technique["limitations"], "EVIDENCE_TECHNIQUE_LIMITATIONS", minimum=1
        )
        _require(
            technique["name"] == expected_name
            and technique["status"] == "PASS"
            and _strict_equal(test_ids, expected_technique_tests[expected_name])
            and cases == len(test_ids)
            and _strict_equal(command_ids, expected_technique_commands[expected_name])
            and all(command_id in commands for command_id in command_ids)
            and _strict_equal(limitations, [TECHNIQUE_LIMITATIONS[expected_name]]),
            "EVIDENCE_TECHNIQUE_BINDING",
        )
    _require(
        _strict_equal(analysis["covered_requirement_ids"], list(CONTROL_IDS))
        and _strict_equal(
            analysis["covered_counterfactual_ids"], list(COUNTERFACTUAL_IDS)
        ),
        "EVIDENCE_ANALYSIS_COVERAGE",
    )

    resources = documents["CH-T001-E05"]
    product_limits = _product_constants(product_tool_payload)
    expected_declared = {
        "evidence_file_bytes": freeze["resource_budgets"][
            "decompressed_evidence_bytes"
        ],
        "product_cell_bytes": product_limits["MAX_CELL_BYTES"],
        "product_file_bytes": product_limits["HARD_MAX_FILE_BYTES"],
        "product_git_blob_reads": product_limits["MAX_GIT_BLOB_READS"],
        "product_git_inventory_bytes": product_limits["MAX_GIT_INVENTORY_BYTES"],
        "product_ledger_bytes": product_limits["MAX_LEDGER_BYTES"],
        "product_path_bytes": product_limits["MAX_PATH_BYTES"],
        "product_rows": product_limits["HARD_MAX_ROWS"],
        "product_seconds": product_limits["HARD_MAX_SECONDS"],
        "product_total_bytes": product_limits["HARD_MAX_TOTAL_BYTES"],
        "central_registered_verifier_seconds": freeze["resource_budgets"][
            "verifier_seconds"
        ],
        "inventory_reconciliation_peak_rss_bytes": (
            INVENTORY_RECONCILIATION_MAX_RSS_BYTES
        ),
        "inventory_reconciliation_seconds": freeze["resource_budgets"][
            "verifier_seconds"
        ],
        "registered_test_seconds": 10,
        "resource_samples": RESOURCE_SAMPLE_COUNT,
    }
    observed = _exact_keys(
        resources["observed_maxima"],
        {
            "exact_snapshot_verify_seconds",
            "inventory_reconciliation_seconds",
            "largest_blob_bytes",
            "ledger_bytes",
            "ledger_generate_seconds",
            "peak_rss_bytes",
            "product_test_seconds",
            "registered_test_seconds",
            "rows",
            "tree_total_bytes",
            "unique_git_blobs",
        },
        "EVIDENCE_OBSERVED_RESOURCE_KEYS",
    )
    distributions = _exact_keys(
        resources["observed_distributions"],
        {"inventory_reconciliation_seconds", "peak_rss_bytes"},
        "EVIDENCE_RESOURCE_DISTRIBUTION_KEYS",
    )
    observed_sizes = {
        field: _integer(observed[field], "EVIDENCE_OBSERVED_RESOURCE_TYPE", minimum=1)
        for field in (
            "largest_blob_bytes",
            "ledger_bytes",
            "peak_rss_bytes",
            "rows",
            "tree_total_bytes",
            "unique_git_blobs",
        )
    }
    observed_timings = {
        field: _number(observed[field], "EVIDENCE_OBSERVED_TIMING_TYPE")
        for field in (
            "exact_snapshot_verify_seconds",
            "inventory_reconciliation_seconds",
            "ledger_generate_seconds",
            "product_test_seconds",
            "registered_test_seconds",
        )
    }
    retained_reconciliation_seconds = _number_list(
        distributions["inventory_reconciliation_seconds"],
        "EVIDENCE_RESOURCE_DISTRIBUTION_TYPE",
        exact_length=RESOURCE_SAMPLE_COUNT,
    )
    retained_peak_rss = _integer_list(
        distributions["peak_rss_bytes"],
        "EVIDENCE_RESOURCE_DISTRIBUTION_TYPE",
        exact_length=RESOURCE_SAMPLE_COUNT,
        minimum=1,
    )
    _require(
        _strict_equal(resources["declared_maxima"], expected_declared),
        "EVIDENCE_DECLARED_RESOURCES",
    )
    expected_capacity_disposition = {
        "distribution_scope": ("FIVE_EXACT_CANDIDATE_INVENTORY_RECONCILIATIONS"),
        "guard_tests": [
            {
                "command_id": command_by_phase["PRODUCT_TESTS"],
                "result": "PASS",
                "test_id": "test_resource_bounds_fail_closed",
                "test_path": PRODUCT_TESTS,
            },
            {
                "command_id": command_by_phase["REGISTERED_TESTS"],
                "result": "PASS",
                "test_id": "test_n12_capacity_fallback_is_rejected",
                "test_path": REGISTERED_TESTS_PATH,
            },
        ],
        "hard_ceiling_claim": "NOT_CLAIMED_SUCCESS_AT_HARD_CEILINGS",
        "qualified_workload": {
            "largest_blob_bytes": max(
                entry["size"] for entry in implementation_entries.values()
            ),
            "rows": len(rows),
            "tree_total_bytes": sum(
                entry["size"] for entry in implementation_entries.values()
            ),
        },
    }
    _require(
        _strict_equal(resources["capacity_disposition"], expected_capacity_disposition),
        "EVIDENCE_CAPACITY_DISPOSITION",
    )
    expected_unique_git_blobs = len(
        {
            *(entry["oid"] for entry in source_entries.values()),
            *(entry["oid"] for entry in implementation_entries.values()),
        }
    )
    _require(
        observed_sizes["ledger_bytes"] == len(ledger_payload)
        and observed_sizes["rows"] == len(rows)
        and observed_sizes["largest_blob_bytes"]
        == max(entry["size"] for entry in implementation_entries.values())
        and observed_sizes["tree_total_bytes"]
        == sum(entry["size"] for entry in implementation_entries.values())
        and observed_sizes["unique_git_blobs"] == expected_unique_git_blobs,
        "EVIDENCE_OBSERVED_RESOURCE_IDENTITY",
    )
    product_test_command = commands[command_by_phase["PRODUCT_TESTS"]]
    registered_test_command = commands[command_by_phase["REGISTERED_TESTS"]]
    product_test_reported = _require_unittest_stream(
        product_test_command,
        expected_tests=len(_python_test_names(product_tests_payload, PRODUCT_TESTS)),
        code="EVIDENCE_PRODUCT_TEST_TIMING",
    )
    registered_test_reported = _require_unittest_stream(
        registered_test_command,
        expected_tests=len(
            _python_test_names(registered_tests_payload, REGISTERED_TESTS_PATH)
        ),
        code="EVIDENCE_REGISTERED_TEST_TIMING",
    )
    resource_commands = [
        commands[command_by_phase[phase]] for phase in RESOURCE_SAMPLE_PHASES
    ]
    observed_reconciliation_seconds = [
        _resource_real_seconds(command) for command in resource_commands
    ]
    observed_peak_rss = [
        _resource_peak_rss_bytes(command) for command in resource_commands
    ]
    _require(
        retained_reconciliation_seconds == observed_reconciliation_seconds
        and retained_peak_rss == observed_peak_rss,
        "EVIDENCE_RESOURCE_DISTRIBUTION_BINDING",
    )
    expected_timings = {
        "exact_snapshot_verify_seconds": _command_elapsed_seconds(
            commands[command_by_phase["EXACT_IMPLEMENTATION_VERIFY"]]
        ),
        "ledger_generate_seconds": _command_elapsed_seconds(
            commands[command_by_phase["LEDGER_GENERATE"]]
        ),
        "product_test_seconds": product_test_reported,
        "registered_test_seconds": registered_test_reported,
        "inventory_reconciliation_seconds": max(observed_reconciliation_seconds),
    }
    _require(
        all(
            observed_timings[field] == value
            for field, value in expected_timings.items()
        )
        and observed_sizes["peak_rss_bytes"] == max(observed_peak_rss)
        and product_test_reported
        <= _command_elapsed_seconds(product_test_command) + 1.0
        and registered_test_reported
        <= _command_elapsed_seconds(registered_test_command) + 1.0
        and all(
            measured <= _command_elapsed_seconds(command) + 1.0
            for measured, command in zip(
                observed_reconciliation_seconds,
                resource_commands,
                strict=True,
            )
        ),
        "EVIDENCE_TIMING_BINDING",
    )
    _require(
        observed_sizes["peak_rss_bytes"]
        <= expected_declared["inventory_reconciliation_peak_rss_bytes"]
        and observed_timings["inventory_reconciliation_seconds"]
        < expected_declared["inventory_reconciliation_seconds"]
        and observed_timings["exact_snapshot_verify_seconds"]
        <= expected_declared["product_seconds"]
        and observed_timings["ledger_generate_seconds"]
        <= expected_declared["product_seconds"]
        and observed_timings["product_test_seconds"]
        <= expected_declared["product_seconds"]
        and observed_timings["registered_test_seconds"]
        < expected_declared["registered_test_seconds"],
        "EVIDENCE_TIMING_BOUND",
    )
    expected_resource_commands = [
        command_by_phase[phase]
        for phase in (
            "LEDGER_GENERATE",
            "PRODUCT_TESTS",
            "EXACT_IMPLEMENTATION_VERIFY",
            "REGISTERED_TESTS",
            "INDEPENDENT_RECONCILIATION",
            *RESOURCE_SAMPLE_PHASES,
        )
    ]
    _require(
        _strict_equal(resources["command_ids"], expected_resource_commands),
        "EVIDENCE_RESOURCE_COMMANDS",
    )

    identities = documents["CH-T001-E06"]
    ledger_record = {
        **_file_record(
            LEDGER_PATH, implementation_entries[LEDGER_PATH], ledger_payload
        ),
        "inventory_digest": rows[0]["inventory_digest"],
        "rows": len(rows),
    }
    tool_record = _file_record(
        PRODUCT_TOOL,
        implementation_entries[PRODUCT_TOOL],
        product_tool_payload,
    )
    product_tests_record = _file_record(
        PRODUCT_TESTS,
        implementation_entries[PRODUCT_TESTS],
        product_tests_payload,
    )
    _require(
        identities["source_tree"] == source_tree
        and identities["implementation_tree"] == implementation_tree
        and _strict_equal(identities["ledger"], ledger_record)
        and _strict_equal(identities["tool"], tool_record)
        and _strict_equal(identities["tests"], product_tests_record),
        "EVIDENCE_IDENTITY_BINDING",
    )

    claim = documents["CH-T001-E07"]
    _require(
        _strict_equal(claim["claim_outcome"], selected_outcome)
        and _strict_equal(claim["assumptions"], handoff["preconditions"])
        and _strict_equal(claim["required_evidence"], handoff["required_evidence"])
        and claim["completion_rule"] == handoff["completion_rule"]
        and claim["requirements_complete"] is True,
        "EVIDENCE_CLAIM_BINDING",
    )

    inventory = documents["CH-T001-E08"]
    paths = [row["path"] for row in rows]
    digest_fields = {
        field: rows[0][field]
        for field in (
            "filesystem_inventory_digest",
            "ignored_inventory_digest",
            "index_inventory_digest",
            "inventory_digest",
            "source_inventory_digest",
            "untracked_inventory_digest",
        )
    }
    _require(
        _strict_equal(inventory["paths"], paths)
        and inventory["path_set_sha256"] == _digest("path-set", paths)
        and _integer(inventory["rows"], "EVIDENCE_INVENTORY_ROWS") == len(rows)
        and _integer(inventory["source_rows"], "EVIDENCE_INVENTORY_SOURCE_ROWS")
        == sum(row["source_tracked"] == "true" for row in rows)
        and _integer(
            inventory["filesystem_entries"], "EVIDENCE_INVENTORY_FILESYSTEM_ENTRIES"
        )
        == int(rows[0]["filesystem_entries"])
        and _strict_equal(inventory["digests"], digest_fields)
        and _strict_equal(inventory["untracked_paths"], [])
        and _strict_equal(inventory["ignored_paths"], [])
        and _strict_equal(
            inventory["classification_counts"], _classification_counts(rows)
        ),
        "EVIDENCE_INVENTORY_BINDING",
    )

    reconciliation = documents["CH-T001-E09"]
    review_registry = {
        item["requirement_id"]: item for item in freeze["reviewer_registry"]
    }
    independent = review_registry["CH-T001-R01"]
    lead = review_registry["CH-T001-R02"]
    expected_reconciliation = {
        "extra_paths": [],
        "immutable_fields_compared": len(IMMUTABLE_FIELDS),
        "matched_rows": len(rows),
        "mismatched_rows": 0,
        "missing_paths": [],
        "mutable_fields_excluded": len(MUTABLE_REVIEW_FIELDS),
    }
    expected_reconciliation_commands = [
        command_by_phase["REGISTERED_TESTS"],
        command_by_phase["INDEPENDENT_RECONCILIATION"],
        command_by_phase["NEGATIVE_VECTORS"],
    ]
    expected_reconciliation_ledger = {
        "bytes": len(ledger_payload),
        "inventory_digest": rows[0]["inventory_digest"],
        "path": LEDGER_PATH,
        "rows": len(rows),
        "sha256": hashlib.sha256(ledger_payload).hexdigest(),
    }
    _require(
        reconciliation["review_requirement_id"] == "CH-T001-R01"
        and _strict_equal(reconciliation["reviewer"], independent["reviewer"])
        and reconciliation["reviewer_public_key"] == independent["public_key"]
        and reconciliation["reviewer_key_fingerprint"] == independent["key_fingerprint"]
        and reconciliation["distinct_from_release_author"] is True
        and independent["reviewer"]["principal"] != freeze["author"]["email"]
        and independent["public_key"] != lead["public_key"]
        and _strict_equal(reconciliation["ledger"], expected_reconciliation_ledger)
        and _strict_equal(
            reconciliation["independent_oracle"],
            _file_record(
                VERIFIER_PATH, source_entries[VERIFIER_PATH], verifier_payload
            ),
        )
        and _strict_equal(
            reconciliation["command_ids"], expected_reconciliation_commands
        )
        and _strict_equal(reconciliation["reconciliation"], expected_reconciliation),
        "EVIDENCE_RECONCILIATION_BINDING",
    )

    _require(
        identities["ledger"]["sha256"] != inventory["digests"]["inventory_digest"],
        "EVIDENCE_DIGEST_DOMAIN_COLLISION",
    )
    _require(
        identities["ledger"]["sha256"] == reconciliation["ledger"]["sha256"]
        and identities["ledger"]["bytes"] == reconciliation["ledger"]["bytes"]
        and identities["ledger"]["rows"] == reconciliation["ledger"]["rows"]
        and identities["ledger"]["inventory_digest"]
        == inventory["digests"]["inventory_digest"]
        == reconciliation["ledger"]["inventory_digest"]
        and resources["observed_maxima"]["ledger_bytes"]
        == identities["ledger"]["bytes"]
        and resources["observed_maxima"]["rows"] == identities["ledger"]["rows"],
        "EVIDENCE_CROSS_RECORD_DISAGREEMENT",
    )
    _require_command_stream_semantics(
        commands=commands,
        command_by_phase=command_by_phase,
        freeze_commit=freeze_commit,
        implementation_commit=implementation_commit,
        source_tree=source_tree,
        implementation_tree=implementation_tree,
        source_entries=source_entries,
        implementation_entries=implementation_entries,
        ledger_payload=ledger_payload,
        rows=rows,
        product_tool_payload=product_tool_payload,
        product_tests_payload=product_tests_payload,
        registered_tests_payload=registered_tests_payload,
        peak_rss_bytes=observed_sizes["peak_rss_bytes"],
    )
    return documents, commands, command_by_phase


def _validate_typed_review_bodies(
    *,
    freeze: dict[str, Any],
    qualification: dict[str, Any],
    freeze_commit: str,
    implementation_commit: str,
    source_entries: dict[str, dict[str, Any]],
    implementation_entries: dict[str, dict[str, Any]],
    c_entries: dict[str, dict[str, Any]],
    c_payloads: dict[str, bytes],
    blobs: dict[str, bytes],
    commands: dict[str, dict[str, Any]],
    evidence_documents: dict[str, dict[str, Any]],
) -> None:
    requirements = freeze["review_requirements"]
    _require(
        [item["id"] for item in requirements] == list(REVIEW_LOGICAL_SCHEMA_IDS),
        "REVIEW_REQUIREMENT_ORDER",
    )
    registry = freeze["reviewer_registry"]
    _require(
        isinstance(registry, list)
        and [item["requirement_id"] for item in registry]
        == list(REVIEW_LOGICAL_SCHEMA_IDS)
        and all(
            item.get("trust_basis") == "SOURCE_SIGNER_ASSERTED_KEY_FROZEN_IN_SIGNED_F"
            for item in registry
        ),
        "REVIEW_REGISTRY_ORDER",
    )
    records = qualification.get("review_records")
    _require(
        isinstance(records, list) and len(records) == len(requirements),
        "REVIEW_QUALIFICATION_RECORDS",
    )
    expected_changed_records = [
        _central_file_record(
            path,
            implementation_entries[path],
            blobs[implementation_entries[path]["oid"]],
        )
        for path, status in freeze["implementation_plan"].items()
        if status in {"A", "M"}
    ]
    expected_evidence_ids = list(EVIDENCE_SCHEMA_IDS)
    expected_evidence_descriptors = [
        "EVIDENCE "
        + json.dumps(
            {
                "evidence_id": requirement["id"],
                "file": _file_record(
                    requirement["path"],
                    c_entries[requirement["path"]],
                    c_payloads[requirement["path"]],
                ),
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        for requirement in freeze["qualification_evidence_requirements"]
    ]
    expected_command_descriptors = [
        "COMMAND "
        + json.dumps(
            {
                "argv": command["argv"],
                "completed_at_utc": command["completed_at_utc"],
                "cwd": command["cwd"],
                "exit_code": command["exit_code"],
                "id": command["id"],
                "phase": command["phase"],
                "started_at_utc": command["started_at_utc"],
                "stderr_sha256": command["stderr_sha256"],
                "stdout_sha256": command["stdout_sha256"],
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        for command in commands.values()
    ]
    expected_reproduction_descriptors = [
        *expected_evidence_descriptors,
        *expected_command_descriptors,
    ]
    required_context_paths = {
        FREEZE_PATH,
        REGISTERED_TESTS_PATH,
        REGISTRY_PATH,
        VERIFIER_PATH,
    }
    outcome = next(
        item
        for item in freeze["claim_outcomes"]
        if item["id"] == qualification["selected_claim_outcome_id"]
    )
    previous_review_completed = max(
        document["completed_at_utc"] for document in evidence_documents.values()
    )
    for requirement, registry_entry, record in zip(
        requirements, registry, records, strict=True
    ):
        review_id = requirement["id"]
        _require(
            REVIEW_LOGICAL_SCHEMA_IDS[review_id].endswith(".v1"), "REVIEW_SCHEMA_ID"
        )
        path = requirement["path"]
        _require(path in c_entries and path in c_payloads, "REVIEW_FILE_MISSING")
        payload = c_payloads[path]
        _require(
            0 < len(payload) <= min(requirement["max_bytes"], 256 * 1024),
            "REVIEW_FILE_BOUND",
        )
        report = _canonical_json(payload, review_id)
        report = _exact_keys(
            report,
            {
                "all_changed_lines_reviewed",
                "decision",
                "decisive_reproduction",
                "epoch",
                "findings",
                "freeze_commit",
                "implementation_commit",
                "implementation_diff",
                "limitations",
                "relevant_unchanged_context_reviewed",
                "requirement",
                "reviewed_relevant_context",
                "reviewer",
                "reviewer_provenance",
                "schema_version",
                "task_id",
            },
            "REVIEW_BODY_KEYS",
        )
        _require(
            report["schema_version"] == "1.0.0"
            and report["task_id"] == TASK_ID
            and _integer(report["epoch"], "REVIEW_EPOCH") == EPOCH
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
            "REVIEW_BODY_IDENTITY",
        )
        implementation_diff = _exact_keys(
            report["implementation_diff"],
            {"changed_file_records", "deleted_paths", "statuses"},
            "REVIEW_DIFF_KEYS",
        )
        _require(
            implementation_diff["statuses"] == freeze["implementation_plan"]
            and _strict_equal(
                implementation_diff["changed_file_records"], expected_changed_records
            )
            and _strict_equal(implementation_diff["deleted_paths"], []),
            "REVIEW_DIFF_BINDING",
        )
        context = report["reviewed_relevant_context"]
        _require(isinstance(context, list) and bool(context), "REVIEW_CONTEXT_EMPTY")
        context_paths: list[str] = []
        for item in context:
            _require(
                isinstance(item, dict) and isinstance(item.get("path"), str),
                "REVIEW_CONTEXT_RECORD",
            )
            context_path = _canonical_path(item["path"])
            _require(
                context_path not in freeze["implementation_plan"]
                and context_path in implementation_entries
                and _strict_equal(
                    item,
                    _central_file_record(
                        context_path,
                        implementation_entries[context_path],
                        blobs[implementation_entries[context_path]["oid"]],
                    ),
                ),
                "REVIEW_CONTEXT_BINDING",
            )
            context_paths.append(context_path)
        _require(
            len(context_paths) == len(set(context_paths))
            and required_context_paths.issubset(context_paths),
            "REVIEW_CONTEXT_SCOPE",
        )
        reproduction = _exact_keys(
            report["decisive_reproduction"],
            {"commands", "evidence_ids", "result"},
            "REVIEW_REPRODUCTION_KEYS",
        )
        _require(
            _strict_equal(reproduction["evidence_ids"], expected_evidence_ids)
            and _strict_equal(
                reproduction["commands"], expected_reproduction_descriptors
            )
            and reproduction["result"] == "PASS",
            "REVIEW_REPRODUCTION_BINDING",
        )
        provenance = _exact_keys(
            report["reviewer_provenance"],
            {"method", "session_id", "tool", "version"},
            "REVIEW_PROVENANCE_KEYS",
        )
        for field in provenance:
            _text(provenance[field], "REVIEW_PROVENANCE_VALUE", maximum=1024)
        _text_list(report["findings"], "REVIEW_FINDINGS")
        limitations = _text_list(report["limitations"], "REVIEW_LIMITATIONS")
        _require(
            set(outcome["limitations"]).issubset(limitations),
            "REVIEW_LIMITATION_OMISSION",
        )

        record = _exact_keys(
            record,
            {
                "completed_at_utc",
                "decision",
                "detached_signature",
                "external",
                "file",
                "human",
                "id",
                "independent_from_release_author",
                "kind",
                "named_human_reviewer",
                "release_approver",
                "reproduced_decisive_evidence",
                "reviewed_all_changed_lines_and_context",
                "reviewer",
                "started_at_utc",
            },
            "REVIEW_QUALIFICATION_RECORD_KEYS",
        )
        started = _timestamp(record["started_at_utc"], "REVIEW_STARTED_AT")
        completed = _timestamp(record["completed_at_utc"], "REVIEW_COMPLETED_AT")
        _require(
            previous_review_completed <= started <= completed,
            "REVIEW_TIME_ORDER",
        )
        previous_review_completed = completed
        _require(
            record["id"] == review_id
            and record["kind"] == requirement["kind"]
            and _strict_equal(
                record["file"], _file_record(path, c_entries[path], payload)
            )
            and _strict_equal(record["reviewer"], registry_entry["reviewer"])
            and record["reproduced_decisive_evidence"] is True
            and record["reviewed_all_changed_lines_and_context"] is True
            and record["decision"] == "ACCEPT_TECHNICAL_TASK_QUALIFICATION"
            and isinstance(record["detached_signature"], dict)
            and bool(record["detached_signature"]),
            "REVIEW_QUALIFICATION_RECORD_BINDING",
        )
        if review_id == "CH-T001-R01":
            _require(
                record["independent_from_release_author"] is True
                and record["human"] is False
                and record["named_human_reviewer"] is False
                and record["external"] is False
                and record["release_approver"] is False
                and registry_entry["reviewer"]["classification"]
                == "INDEPENDENT_AUTOMATED"
                and registry_entry["reviewer"]["principal"] != freeze["author"]["email"]
                and registry_entry["public_key"]
                != freeze["reviewer_registry"][1]["public_key"],
                "REVIEW_INDEPENDENCE_BOUNDARY",
            )
        else:
            _require(
                record["independent_from_release_author"] is False
                and record["human"] is False
                and record["named_human_reviewer"] is False
                and record["external"] is False
                and record["release_approver"] is False
                and registry_entry["reviewer"]["classification"]
                == "AUTOMATED_LEAD_SUPPORT"
                and registry_entry["reviewer"]["name"] != freeze["author"]["name"]
                and registry_entry["reviewer"]["principal"] != freeze["author"]["email"]
                and registry_entry["public_key"]
                != freeze["reviewer_registry"][0]["public_key"],
                "REVIEW_LEAD_BOUNDARY",
            )


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
        text = command[stream]
        digest = command[f"{stream}_sha256"]
        _require(
            isinstance(text, str)
            and isinstance(digest, str)
            and HEX64.fullmatch(digest) is not None
            and hashlib.sha256(text.encode("utf-8")).hexdigest() == digest,
            "ACTIVATION_COMMAND_STREAM",
        )
    _require(command["stdout"] or command["stderr"], "ACTIVATION_COMMAND_EMPTY")
    return command


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
        "ACTIVATION_CI_RETAINED_RECORD_KEYS",
    )
    encoded = record["content_base64"]
    expected_headers = [
        f"Accept: {GH_ACCEPT_HEADER}",
        f"X-GitHub-Api-Version: {GH_API_VERSION}",
    ]
    expected_argv = [
        GH_EXECUTABLE,
        "api",
        "--hostname",
        "github.com",
        "--method",
        "GET",
        "-H",
        expected_headers[0],
        "-H",
        expected_headers[1],
        api_path,
    ]
    started = _timestamp(record["started_at_utc"], "ACTIVATION_CI_CAPTURE_STARTED")
    completed = _timestamp(
        record["completed_at_utc"], "ACTIVATION_CI_CAPTURE_COMPLETED"
    )
    _require(
        record["kind"] == kind
        and record["source_url"] == source_url
        and record["media_type"] == media_type
        and _strict_equal(record["capture_argv"], expected_argv)
        and _strict_equal(record["request_headers"], expected_headers)
        and record["tool_version"] == GH_VERSION
        and type(record["exit_code"]) is int
        and record["exit_code"] == 0
        and record["stderr"] == ""
        and record["stderr_sha256"] == hashlib.sha256(b"").hexdigest()
        and outer_started
        <= previous_completed
        <= started
        <= completed
        <= outer_completed
        and isinstance(encoded, str)
        and encoded.isascii()
        and len(encoded) <= 4 * ((maximum + 2) // 3),
        "ACTIVATION_CI_RETAINED_RECORD_IDENTITY",
    )
    try:
        payload = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as error:
        raise VerificationError("ACTIVATION_CI_RETAINED_RECORD_BASE64") from error
    _require(
        0 < len(payload) <= maximum
        and base64.b64encode(payload).decode("ascii") == encoded
        and _integer(record["bytes"], "ACTIVATION_CI_RETAINED_RECORD_BYTES")
        == len(payload)
        and isinstance(record["sha256"], str)
        and HEX64.fullmatch(record["sha256"]) is not None
        and hashlib.sha256(payload).hexdigest() == record["sha256"],
        "ACTIVATION_CI_RETAINED_RECORD_BINDING",
    )
    return payload, completed


def _validate_ci_log_archive(payload: bytes) -> None:
    try:
        archive = zipfile.ZipFile(io.BytesIO(payload))
    except (OSError, zipfile.BadZipFile) as error:
        raise VerificationError("ACTIVATION_CI_LOG_ARCHIVE") from error
    with archive:
        infos = archive.infolist()
        _require(
            0 < len(infos) <= MAX_CI_LOG_FILES,
            "ACTIVATION_CI_LOG_ARCHIVE_COUNT",
        )
        names: list[str] = []
        file_sizes: dict[str, int] = {}
        expanded = 0
        for info in infos:
            name = info.filename
            pure = PurePosixPath(name)
            _require(
                isinstance(name, str)
                and bool(name)
                and not pure.is_absolute()
                and "\\" not in name
                and all(part not in {"", ".", ".."} for part in pure.parts)
                and name not in names
                and not (info.flag_bits & 0x1),
                "ACTIVATION_CI_LOG_ARCHIVE_ENTRY",
            )
            names.append(name)
            if info.is_dir():
                continue
            expanded += info.file_size
            _require(
                info.file_size <= MAX_CI_LOG_EXPANDED_BYTES
                and expanded <= MAX_CI_LOG_EXPANDED_BYTES,
                "ACTIVATION_CI_LOG_ARCHIVE_EXPANDED_BOUND",
            )
            try:
                content = archive.read(info)
            except (OSError, RuntimeError, zipfile.BadZipFile) as error:
                raise VerificationError("ACTIVATION_CI_LOG_ARCHIVE_READ") from error
            _require(
                len(content) == info.file_size,
                "ACTIVATION_CI_LOG_ARCHIVE_SIZE",
            )
            file_sizes[name] = len(content)
        _require(expanded > 0, "ACTIVATION_CI_LOG_ARCHIVE_EMPTY")
        primary_entries: list[str] = []
        for job_name in CI_JOB_NAMES:
            matches = [
                name
                for name in file_sizes
                if re.fullmatch(
                    rf"[0-9]+_{re.escape(job_name)}\.txt",
                    PurePosixPath(name).name,
                )
                is not None
                and file_sizes[name] > 0
            ]
            _require(
                len(matches) == 1,
                "ACTIVATION_CI_LOG_ARCHIVE_JOB_SCOPE",
            )
            primary_entries.extend(matches)
        _require(
            len(primary_entries) == len(set(primary_entries)) == len(CI_JOB_NAMES),
            "ACTIVATION_CI_LOG_ARCHIVE_JOB_DISTINCT",
        )


def _validate_typed_activation_bodies(
    *,
    freeze: dict[str, Any],
    activation: dict[str, Any],
    freeze_commit: str,
    implementation_commit: str,
    qualification_commit: str,
    activation_entries: dict[str, dict[str, Any]],
    activation_payloads: dict[str, bytes],
    source_tree: str,
    implementation_tree: str,
    source_entries: dict[str, dict[str, Any]],
    implementation_entries: dict[str, dict[str, Any]],
    ledger_payload: bytes,
    rows: list[dict[str, str]],
    product_tool_payload: bytes,
    product_tests_payload: bytes,
    registered_tests_payload: bytes,
) -> None:
    requirements = freeze["activation_evidence_requirements"]
    _require(
        [item["id"] for item in requirements] == list(ACTIVATION_SCHEMA_IDS),
        "ACTIVATION_REQUIREMENT_ORDER",
    )
    records = activation.get("activation_evidence_records")
    _require(
        isinstance(records, list) and len(records) == len(requirements),
        "ACTIVATION_RECORDS",
    )
    documents: dict[str, dict[str, Any]] = {}
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
        "CH-T001-A01": {"checks", "commands"},
        "CH-T001-A02": {"command", "scope"},
        "CH-T001-A03": {
            "conclusion",
            "head_sha",
            "jobs",
            "provider",
            "retained_records",
            "run_attempt",
            "run_id",
            "run_url",
            "workflow_path",
        },
        "CH-T001-A04": {
            "affected_downstreams",
            "disposition",
            "implementation_paths",
            "rationale",
            "runtime_surface_changed",
        },
    }
    times: dict[str, tuple[str, str]] = {}
    for requirement, record in zip(requirements, records, strict=True):
        evidence_id = requirement["id"]
        path = requirement["path"]
        _require(
            path in activation_entries and path in activation_payloads,
            "ACTIVATION_FILE_MISSING",
        )
        payload = activation_payloads[path]
        _require(
            0 < len(payload) <= min(requirement["max_bytes"], 256 * 1024),
            "ACTIVATION_FILE_BOUND",
        )
        document = _canonical_json(payload, evidence_id)
        _exact_keys(
            document,
            common_keys | specific_keys[evidence_id],
            "ACTIVATION_BODY_KEYS",
        )
        started = _timestamp(document["started_at_utc"], "ACTIVATION_STARTED")
        completed = _timestamp(document["completed_at_utc"], "ACTIVATION_COMPLETED")
        _require(
            document["schema_id"] == ACTIVATION_SCHEMA_IDS[evidence_id]
            and document["evidence_id"] == evidence_id
            and document["task_id"] == TASK_ID
            and _integer(document["epoch"], "ACTIVATION_EPOCH") == EPOCH
            and document["freeze_commit"] == freeze_commit
            and document["implementation_commit"] == implementation_commit
            and document["qualification_commit"] == qualification_commit
            and document["result"] == "PASS"
            and started <= completed,
            "ACTIVATION_BODY_IDENTITY",
        )
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
            "ACTIVATION_RECORD_KEYS",
        )
        _require(
            record["id"] == evidence_id
            and record["kind"] == requirement["kind"]
            and _strict_equal(
                record["file"], _file_record(path, activation_entries[path], payload)
            )
            and record["subject_commit"] == qualification_commit
            and record["result"] == "PASS"
            and record["started_at_utc"] == started
            and record["completed_at_utc"] == completed,
            "ACTIVATION_RECORD_BINDING",
        )
        documents[evidence_id] = document
        times[evidence_id] = (started, completed)

    expected_qualification_argv = _expected_qualification_argv(
        freeze_commit, implementation_commit
    )
    subsystem = documents["CH-T001-A01"]
    _require(
        _strict_equal(
            subsystem["checks"],
            [
                "PRODUCT_TESTS",
                "REGISTERED_TESTS",
                "EXACT_IMPLEMENTATION_VERIFY",
                "INDEPENDENT_RECONCILIATION",
            ],
        )
        and isinstance(subsystem["commands"], list)
        and len(subsystem["commands"]) == 4,
        "ACTIVATION_SUBSYSTEM_SCOPE",
    )
    subsystem_commands: dict[str, dict[str, Any]] = {}
    previous_subsystem_completed = times["CH-T001-A01"][0]
    for index, phase in enumerate(subsystem["checks"], start=1):
        subsystem_commands[phase] = _validate_activation_command(
            subsystem["commands"][index - 1],
            command_id=f"CH-T001-A01-CMD{index:02d}",
            phase=phase,
            argv=expected_qualification_argv[phase],
            outer_started=times["CH-T001-A01"][0],
            outer_completed=times["CH-T001-A01"][1],
            previous_completed=previous_subsystem_completed,
        )
        previous_subsystem_completed = subsystem_commands[phase]["completed_at_utc"]
    _require_unittest_stream(
        subsystem_commands["PRODUCT_TESTS"],
        expected_tests=len(_python_test_names(product_tests_payload, PRODUCT_TESTS)),
        code="ACTIVATION_PRODUCT_TEST_RESULT",
    )
    registered_names = _python_test_names(
        registered_tests_payload, REGISTERED_TESTS_PATH
    )
    _require_unittest_stream(
        subsystem_commands["REGISTERED_TESTS"],
        expected_tests=len(registered_names),
        code="ACTIVATION_REGISTERED_TEST_RESULT",
    )
    ledger_sha256 = hashlib.sha256(ledger_payload).hexdigest()
    inventory_digest = rows[0]["inventory_digest"]
    exact_verify = subsystem_commands["EXACT_IMPLEMENTATION_VERIFY"]
    _require(
        exact_verify["stderr"] == ""
        and _strict_equal(
            _canonical_json(
                exact_verify["stdout"].encode("utf-8"),
                "ACTIVATION_EXACT_VERIFY_STDOUT",
            ),
            {
                "implementation_commit": implementation_commit,
                "implementation_ledger_sha256": ledger_sha256,
                "inventory_digest": inventory_digest,
                "ledger_bytes": len(ledger_payload),
                "ledger_sha256": ledger_sha256,
                "retained_head_commit": qualification_commit,
                "rows": len(rows),
                "source_commit": freeze_commit,
                "source_tree": source_tree,
                "verification_view": "EXACT_IMPLEMENTATION_SNAPSHOT",
            },
        ),
        "ACTIVATION_EXACT_VERIFY_RESULT",
    )
    reconciliation = subsystem_commands["INDEPENDENT_RECONCILIATION"]
    _require(
        reconciliation["stderr"] == ""
        and _strict_equal(
            _canonical_json(
                reconciliation["stdout"].encode("utf-8"),
                "ACTIVATION_RECONCILIATION_STDOUT",
            ),
            {
                "epoch": EPOCH,
                "freeze_commit": freeze_commit,
                "implementation_commit": implementation_commit,
                "implementation_tree": implementation_tree,
                "inventory_digest": inventory_digest,
                "ledger_sha256": ledger_sha256,
                "result": "PASS",
                "rows": len(rows),
                "schema_version": "1.0.0",
                "source_tree": source_tree,
                "task_id": TASK_ID,
                "tests_sha256": hashlib.sha256(product_tests_payload).hexdigest(),
                "tool_sha256": hashlib.sha256(product_tool_payload).hexdigest(),
                "unique_git_blobs": len(
                    {
                        *(entry["oid"] for entry in source_entries.values()),
                        *(entry["oid"] for entry in implementation_entries.values()),
                    }
                ),
            },
        ),
        "ACTIVATION_RECONCILIATION_RESULT",
    )

    wave = documents["CH-T001-A02"]
    wave_scope = _exact_keys(
        wave["scope"],
        {
            "execution_wave",
            "gate_scope",
            "remaining_wave_tasks",
            "wave_acceptance",
        },
        "ACTIVATION_WAVE_SCOPE_KEYS",
    )
    _require(
        _strict_equal(
            wave_scope,
            {
                "execution_wave": 0,
                "gate_scope": "FULL_REPOSITORY_LOCKED_GATE_AT_CH_T001_CANDIDATE",
                "remaining_wave_tasks": list(WAVE_REMAINING_TASKS),
                "wave_acceptance": "NOT_YET_ELIGIBLE",
            },
        ),
        "ACTIVATION_WAVE_SCOPE",
    )
    wave_command = _validate_activation_command(
        wave["command"],
        command_id="CH-T001-A02-CMD01",
        phase="WAVE_GATE",
        argv=[
            "/usr/bin/env",
            "-u",
            "BASH_ENV",
            "-u",
            "ENV",
            "/bin/bash",
            "--noprofile",
            "--norc",
            "tools/p0r-exit-gate.sh",
        ],
        outer_started=times["CH-T001-A02"][0],
        outer_completed=times["CH-T001-A02"][1],
        previous_completed=times["CH-T001-A02"][0],
    )
    wave_diagnostic_text = wave_command["stdout"].replace(
        "P0-R exit gate: 30 passed, 0 failed", ""
    )
    _require(
        wave_command["stderr"] == ""
        and wave_command["stdout"].count("P0-R exit gate: 30 passed, 0 failed") == 1
        and wave_command["stdout"].count("All offline P0-R gates passed.") == 1
        and wave_command["stdout"].rstrip().endswith("All offline P0-R gates passed.")
        and re.search(
            r"(?i)(?:^|\W)(?:fail(?:ed|ure)?|traceback|panic)(?:\W|$)",
            wave_diagnostic_text,
        )
        is None,
        "ACTIVATION_WAVE_COMMAND_RESULT",
    )

    hosted = documents["CH-T001-A03"]
    run_id = _integer(hosted["run_id"], "ACTIVATION_CI_RUN_ID", minimum=1)
    run_attempt = _integer(hosted["run_attempt"], "ACTIVATION_CI_ATTEMPT", minimum=1)
    run_url = f"https://github.com/sepahead/haldir/actions/runs/{run_id}"
    run_api_url = f"https://api.github.com/repos/sepahead/haldir/actions/runs/{run_id}"
    run_api_path = f"repos/sepahead/haldir/actions/runs/{run_id}"
    jobs_api_url = f"{run_api_url}/attempts/{run_attempt}/jobs?per_page=100"
    jobs_api_path = f"{run_api_path}/attempts/{run_attempt}/jobs?per_page=100"
    logs_api_url = f"{run_api_url}/attempts/{run_attempt}/logs"
    logs_api_path = f"{run_api_path}/attempts/{run_attempt}/logs"
    retained_records = hosted["retained_records"]
    _require(
        isinstance(retained_records, list) and len(retained_records) == 3,
        "ACTIVATION_CI_RETAINED_RECORDS",
    )
    capture_completed = times["CH-T001-A03"][0]
    run_payload, capture_completed = _retained_ci_payload(
        retained_records[0],
        kind="RUN_API_JSON",
        source_url=run_api_url,
        api_path=run_api_path,
        media_type="application/vnd.github+json",
        maximum=64 * 1024,
        outer_started=times["CH-T001-A03"][0],
        outer_completed=times["CH-T001-A03"][1],
        previous_completed=capture_completed,
    )
    jobs_payload, capture_completed = _retained_ci_payload(
        retained_records[1],
        kind="ATTEMPT_JOBS_API_JSON",
        source_url=jobs_api_url,
        api_path=jobs_api_path,
        media_type="application/vnd.github+json",
        maximum=64 * 1024,
        outer_started=times["CH-T001-A03"][0],
        outer_completed=times["CH-T001-A03"][1],
        previous_completed=capture_completed,
    )
    log_payload, _capture_completed = _retained_ci_payload(
        retained_records[2],
        kind="ATTEMPT_LOG_ARCHIVE_ZIP",
        source_url=logs_api_url,
        api_path=logs_api_path,
        media_type="application/zip",
        maximum=MAX_CI_LOG_ARCHIVE_BYTES,
        outer_started=times["CH-T001-A03"][0],
        outer_completed=times["CH-T001-A03"][1],
        previous_completed=capture_completed,
    )
    run_document = _json(run_payload, "ACTIVATION_CI_RAW_RUN")
    repository = run_document.get("repository")
    run_created = _timestamp(
        run_document.get("created_at"), "ACTIVATION_CI_RAW_RUN_CREATED"
    )
    run_updated = _timestamp(
        run_document.get("updated_at"), "ACTIVATION_CI_RAW_RUN_UPDATED"
    )
    _require(
        _integer(run_document.get("id"), "ACTIVATION_CI_RAW_RUN_ID", minimum=1)
        == run_id
        and _integer(
            run_document.get("run_attempt"),
            "ACTIVATION_CI_RAW_RUN_ATTEMPT",
            minimum=1,
        )
        == run_attempt
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
        and run_created <= run_updated <= times["CH-T001-A03"][0],
        "ACTIVATION_CI_RAW_RUN_BINDING",
    )
    jobs_document = _json(jobs_payload, "ACTIVATION_CI_RAW_JOBS")
    raw_jobs = jobs_document.get("jobs")
    _require(
        _integer(
            jobs_document.get("total_count"),
            "ACTIVATION_CI_RAW_JOB_TOTAL",
            minimum=1,
        )
        == len(CI_JOB_NAMES)
        and isinstance(raw_jobs, list)
        and len(raw_jobs) == len(CI_JOB_NAMES),
        "ACTIVATION_CI_RAW_JOB_COUNT",
    )
    raw_jobs_by_name: dict[str, dict[str, Any]] = {}
    raw_job_ids: set[int] = set()
    latest_job_completion = run_created
    for raw_job in raw_jobs:
        _require(isinstance(raw_job, dict), "ACTIVATION_CI_RAW_JOB_TYPE")
        name = _text(raw_job.get("name"), "ACTIVATION_CI_RAW_JOB_NAME")
        started = _timestamp(raw_job.get("started_at"), "ACTIVATION_CI_RAW_JOB_STARTED")
        completed = _timestamp(
            raw_job.get("completed_at"), "ACTIVATION_CI_RAW_JOB_COMPLETED"
        )
        _require(
            name in CI_JOB_NAMES
            and name not in raw_jobs_by_name
            and type(raw_job.get("id")) is int
            and raw_job["id"] > 0
            and raw_job["id"] not in raw_job_ids
            and _integer(
                raw_job.get("run_id"), "ACTIVATION_CI_RAW_JOB_RUN_ID", minimum=1
            )
            == run_id
            and _integer(
                raw_job.get("run_attempt"),
                "ACTIVATION_CI_RAW_JOB_RUN_ATTEMPT",
                minimum=1,
            )
            == run_attempt
            and raw_job.get("head_sha") == qualification_commit
            and raw_job.get("status") == "completed"
            and raw_job.get("conclusion") == "success"
            and run_created <= started <= completed <= run_updated,
            "ACTIVATION_CI_RAW_JOB_BINDING",
        )
        raw_job_ids.add(raw_job["id"])
        latest_job_completion = max(latest_job_completion, completed)
        raw_jobs_by_name[name] = raw_job
    _require(
        latest_job_completion <= times["CH-T001-A03"][0],
        "ACTIVATION_CI_CAPTURE_ORDER",
    )
    jobs = hosted["jobs"]
    _require(
        isinstance(jobs, list) and len(jobs) == len(CI_JOB_NAMES), "ACTIVATION_CI_JOBS"
    )
    expected_jobs = [
        {
            "conclusion": "success",
            "job_id": raw_jobs_by_name[name]["id"],
            "name": name,
        }
        for name in CI_JOB_NAMES
    ]
    for job in jobs:
        _exact_keys(job, {"conclusion", "job_id", "name"}, "ACTIVATION_CI_JOB_KEYS")
    _validate_ci_log_archive(log_payload)
    _require(
        hosted["provider"] == "GITHUB_ACTIONS"
        and hosted["workflow_path"] == ".github/workflows/ci.yml"
        and hosted["head_sha"] == qualification_commit
        and hosted["conclusion"] == "success"
        and _strict_equal(jobs, expected_jobs)
        and hosted["run_url"] == run_url,
        "ACTIVATION_CI_BINDING",
    )

    downstream = documents["CH-T001-A04"]
    _require(
        _strict_equal(
            downstream["implementation_paths"], sorted(freeze["implementation_plan"])
        )
        and _strict_equal(downstream["affected_downstreams"], [])
        and downstream["runtime_surface_changed"] is False
        and downstream["disposition"]
        == "NO_RUNTIME_OR_EXTERNAL_DOWNSTREAM_CONFORMANCE_CHANGE"
        and bool(_text(downstream["rationale"], "ACTIVATION_DOWNSTREAM_RATIONALE")),
        "ACTIVATION_DOWNSTREAM_BINDING",
    )


def verify_inventory(
    repo: Path,
    freeze_commit: str,
    implementation_commit: str,
) -> dict[str, Any]:
    """Independently reconcile the exact F and I Git snapshots."""

    _require(
        HEX40.fullmatch(freeze_commit) is not None
        and HEX40.fullmatch(implementation_commit) is not None
        and freeze_commit != implementation_commit,
        "INVENTORY_ARGUMENT_COMMIT",
    )
    object_format = _git(repo, ["rev-parse", "--show-object-format"], maximum=32)
    _require(object_format == b"sha1\n", "OBJECT_FORMAT")
    raw_parents = _git(
        repo,
        [
            "rev-list",
            "--parents",
            "--no-walk",
            freeze_commit,
            implementation_commit,
        ],
        maximum=512,
    )
    try:
        parent_lines = raw_parents.decode("ascii", "strict").splitlines()
    except UnicodeDecodeError as error:
        raise VerificationError("INVENTORY_PARENT_ENCODING") from error
    parents: dict[str, str] = {}
    for line in parent_lines:
        fields = line.split()
        _require(
            len(fields) == 2
            and all(HEX40.fullmatch(item) for item in fields)
            and fields[0] not in parents,
            "INVENTORY_PARENT",
        )
        parents[fields[0]] = fields[1]
    _require(
        parents
        == {
            freeze_commit: BASELINE_COMMIT,
            implementation_commit: freeze_commit,
        },
        "INVENTORY_PARENT_CHAIN",
    )
    _require(
        _diff(repo, BASELINE_COMMIT, freeze_commit) == test_fixture()["f_diff"],
        "INVENTORY_F_DIFF",
    )
    _require(
        _diff(repo, freeze_commit, implementation_commit) == test_fixture()["i_diff"],
        "INVENTORY_I_DIFF",
    )
    source_tree, source_entries = _tree(repo, freeze_commit)
    implementation_tree, implementation_entries = _tree(repo, implementation_commit)
    _require(len(source_entries) == EXPECTED_SOURCE_PATHS, "INVENTORY_F_TREE_COUNT")
    _require(
        len(implementation_entries) == EXPECTED_IMPLEMENTATION_PATHS,
        "INVENTORY_I_TREE_COUNT",
    )
    _require(
        set(implementation_entries)
        == set(source_entries) | set(test_fixture()["i_diff"]),
        "INVENTORY_I_TREE_PATHS",
    )
    _require(
        all(
            implementation_entries[path]["mode"] == "100644"
            for path in test_fixture()["i_diff"]
        ),
        "INVENTORY_I_PLANNED_MODE",
    )
    for path, source_entry in source_entries.items():
        if path not in test_fixture()["i_diff"]:
            _require(
                implementation_entries[path] == source_entry,
                "INVENTORY_UNPLANNED_OBJECT_DRIFT",
            )
    object_ids = {entry["oid"] for entry in source_entries.values()}
    object_ids.update(entry["oid"] for entry in implementation_entries.values())
    blobs = _blobs(repo, object_ids)
    ledger_payload = blobs[implementation_entries[LEDGER_PATH]["oid"]]
    rows = _parse_ledger(ledger_payload)
    expected_rows = _expected_rows(
        freeze_commit,
        source_tree,
        source_entries,
        implementation_entries,
        blobs,
    )
    _require(rows == expected_rows, "INVENTORY_LEDGER_CAPTURE_MISMATCH")
    _validate_initial_review_state(rows)
    _require(
        [row["path"] for row in rows] == list(implementation_entries),
        "INVENTORY_LEDGER_TREE_PATH_SET",
    )
    tool_payload = blobs[implementation_entries[PRODUCT_TOOL]["oid"]]
    test_payload = blobs[implementation_entries[PRODUCT_TESTS]["oid"]]
    gitignore_payload = blobs[implementation_entries[GITIGNORE_PATH]["oid"]]
    verifier_payload = blobs[source_entries[VERIFIER_PATH]["oid"]]
    freeze_payload = blobs[source_entries[FREEZE_PATH]["oid"]]
    _validate_gitignore_identity(gitignore_payload)
    _validate_freeze_surface_contract(_json(freeze_payload, "FREEZE"))
    _validate_product_identities(tool_payload, test_payload)
    _validate_product_asts(tool_payload, test_payload, verifier_payload)
    return {
        "schema_version": "1.0.0",
        "task_id": TASK_ID,
        "epoch": EPOCH,
        "freeze_commit": freeze_commit,
        "implementation_commit": implementation_commit,
        "source_tree": source_tree,
        "implementation_tree": implementation_tree,
        "rows": len(rows),
        "ledger_sha256": hashlib.sha256(ledger_payload).hexdigest(),
        "inventory_digest": rows[0]["inventory_digest"],
        "tool_sha256": hashlib.sha256(tool_payload).hexdigest(),
        "tests_sha256": hashlib.sha256(test_payload).hexdigest(),
        "unique_git_blobs": len(object_ids),
        "result": "PASS",
    }


def verify_repository(
    repo: Path,
    freeze_commit: str,
    implementation_commit: str,
    qualification_commit: str,
    activation_commit: str,
    current_commit: str,
) -> dict[str, Any]:
    started = time.monotonic()
    commits = [
        freeze_commit,
        implementation_commit,
        qualification_commit,
        activation_commit,
    ]
    _require(
        all(HEX40.fullmatch(commit) for commit in [*commits, current_commit]),
        "ARGUMENT_COMMIT",
    )
    object_format = _git(repo, ["rev-parse", "--show-object-format"], maximum=32)
    _require(object_format == b"sha1\n", "OBJECT_FORMAT")
    parents = _commit_parents(repo, commits)
    _require(parents[freeze_commit] == BASELINE_COMMIT, "F_PARENT")
    _require(parents[implementation_commit] == freeze_commit, "I_PARENT")
    _require(parents[qualification_commit] == implementation_commit, "C_PARENT")
    _require(parents[activation_commit] == qualification_commit, "D_PARENT")
    history = _first_parent(repo, current_commit)
    try:
        d_index = history.index(activation_commit)
    except ValueError as error:
        raise VerificationError("D_NOT_FIRST_PARENT_ANCESTOR") from error
    _require(
        history[d_index : d_index + 4]
        == [
            activation_commit,
            qualification_commit,
            implementation_commit,
            freeze_commit,
        ],
        "TRANSITIONS_NOT_ADJACENT",
    )
    _require_exact_linear_head(repo, implementation_commit, current_commit)
    f_expected = test_fixture()["f_diff"]
    i_expected = test_fixture()["i_diff"]
    _require(_diff(repo, BASELINE_COMMIT, freeze_commit) == f_expected, "F_DIFF")
    _require(_diff(repo, freeze_commit, implementation_commit) == i_expected, "I_DIFF")

    source_tree, source_entries = _tree(repo, freeze_commit)
    implementation_tree, implementation_entries = _tree(repo, implementation_commit)
    _require(len(source_entries) == EXPECTED_SOURCE_PATHS, "F_TREE_COUNT")
    _require(
        len(implementation_entries) == EXPECTED_IMPLEMENTATION_PATHS, "I_TREE_COUNT"
    )
    _require(
        set(implementation_entries) == set(source_entries) | set(i_expected),
        "I_TREE_PATHS",
    )
    _require(
        all(implementation_entries[path]["mode"] == "100644" for path in i_expected),
        "I_PLANNED_MODE",
    )
    for path in source_entries:
        if path not in i_expected:
            _require(
                implementation_entries[path] == source_entries[path],
                "I_UNPLANNED_OBJECT_DRIFT",
            )

    current_entries = _selected_tree_entries(
        repo,
        current_commit,
        {
            GITIGNORE_PATH,
            VERIFIER_PATH,
            REGISTERED_TESTS_PATH,
            FREEZE_PATH,
            LEDGER_PATH,
            PRODUCT_TOOL,
            PRODUCT_TESTS,
        },
    )
    _require(len(current_entries) == 7, "CURRENT_REQUIRED_PATH_MISSING")
    for path in (VERIFIER_PATH, REGISTERED_TESTS_PATH, FREEZE_PATH):
        _require(
            current_entries[path]
            == {key: source_entries[path][key] for key in ("mode", "type", "oid")},
            "F_OBJECT_NOT_RETAINED",
        )
    for path in (GITIGNORE_PATH, PRODUCT_TOOL, PRODUCT_TESTS):
        _require(
            current_entries[path]
            == {
                key: implementation_entries[path][key]
                for key in ("mode", "type", "oid")
            },
            "I_PRODUCT_NOT_RETAINED",
        )
    _require(
        current_entries[LEDGER_PATH]["mode"]
        == implementation_entries[LEDGER_PATH]["mode"]
        and current_entries[LEDGER_PATH]["type"]
        == implementation_entries[LEDGER_PATH]["type"],
        "CURRENT_LEDGER_MODE_OR_TYPE_DRIFT",
    )

    object_ids = {entry["oid"] for entry in implementation_entries.values()}
    object_ids.update(entry["oid"] for entry in source_entries.values())
    object_ids.add(current_entries[LEDGER_PATH]["oid"])
    blobs = _blobs(repo, object_ids)
    ledger_payload = blobs[implementation_entries[LEDGER_PATH]["oid"]]
    actual_rows = _parse_ledger(ledger_payload)
    expected_rows = _expected_rows(
        freeze_commit, source_tree, source_entries, implementation_entries, blobs
    )
    _require(
        [row["path"] for row in actual_rows] == list(implementation_entries),
        "LEDGER_TREE_PATH_SET",
    )
    _require(actual_rows == expected_rows, "LEDGER_CAPTURE_MISMATCH")
    _validate_initial_review_state(actual_rows)
    _require(implementation_tree != source_tree, "IMPLEMENTATION_TREE_UNCHANGED")
    _require(
        all(
            row["language"] != "UNKNOWN" and row["format"] != "UNKNOWN"
            for row in actual_rows
        ),
        "LEDGER_CLASSIFICATION_UNKNOWN",
    )
    ledger_paths = {row["path"] for row in actual_rows}
    _require(
        len(ledger_paths) == EXPECTED_IMPLEMENTATION_PATHS, "LEDGER_PATH_CARDINALITY"
    )
    for row in actual_rows:
        _validate_mutable(row, ledger_paths)
    self_rows = [row for row in actual_rows if row["path"] == LEDGER_PATH]
    _require(len(self_rows) == 1, "LEDGER_SELF_ROW")
    _require(
        self_rows[0]["index_tracked"] == "false"
        and self_rows[0]["current_scope"] == "LEDGER_SELF"
        and self_rows[0]["format"] == "SELF_REFERENTIAL_CSV"
        and not self_rows[0]["sha256"],
        "LEDGER_SELF_BINDING",
    )

    current_ledger = blobs[current_entries[LEDGER_PATH]["oid"]]
    current_rows = _parse_ledger(current_ledger)
    _require(
        [row["path"] for row in current_rows] == [row["path"] for row in actual_rows],
        "CURRENT_LEDGER_PATH_DRIFT",
    )
    for frozen, current in zip(actual_rows, current_rows, strict=True):
        _require(
            all(frozen[field] == current[field] for field in IMMUTABLE_FIELDS),
            "CURRENT_LEDGER_IMMUTABLE_DRIFT",
        )
        _validate_mutable(current, ledger_paths)
        _validate_generated_evolution(current, frozen)

    verifier_payload = blobs[source_entries[VERIFIER_PATH]["oid"]]
    registered_tests_payload = blobs[source_entries[REGISTERED_TESTS_PATH]["oid"]]
    freeze_payload = blobs[source_entries[FREEZE_PATH]["oid"]]
    product_tool_payload = blobs[implementation_entries[PRODUCT_TOOL]["oid"]]
    product_tests_payload = blobs[implementation_entries[PRODUCT_TESTS]["oid"]]
    gitignore_payload = blobs[implementation_entries[GITIGNORE_PATH]["oid"]]
    _validate_gitignore_identity(gitignore_payload)
    _validate_product_identities(product_tool_payload, product_tests_payload)
    _validate_product_asts(
        product_tool_payload, product_tests_payload, verifier_payload
    )

    freeze = _json(freeze_payload, "FREEZE")
    _validate_freeze_surface_contract(freeze)
    _require(
        freeze.get("task_id") == TASK_ID
        and _integer(freeze.get("epoch"), "FREEZE_EPOCH") == EPOCH,
        "FREEZE_IDENTITY",
    )
    _require(
        freeze.get("implementation_plan") == i_expected, "FREEZE_IMPLEMENTATION_PLAN"
    )
    _require(
        freeze.get("verification_triggers")
        == {
            "paths": [GITIGNORE_PATH, LEDGER_PATH, PRODUCT_TOOL, PRODUCT_TESTS],
            "roots": [],
        },
        "FREEZE_TRIGGERS",
    )
    qualification_requirements = freeze.get("qualification_evidence_requirements")
    review_requirements = freeze.get("review_requirements")
    activation_requirements = freeze.get("activation_evidence_requirements")
    _require(
        all(
            isinstance(items, list) and items
            for items in (
                qualification_requirements,
                review_requirements,
                activation_requirements,
            )
        ),
        "FREEZE_REQUIREMENTS",
    )
    c_expected = {QUALIFICATION_PATH: "A"}
    c_expected.update({item["path"]: "A" for item in qualification_requirements})
    c_expected.update({item["path"]: "A" for item in review_requirements})
    d_expected = {
        ACTIVATION_PATH: "A",
        RECEIPT_PATH: "A",
        REQUIREMENTS_PATH: "M",
        ACTIVE_CLAIMS_PATH: "M",
    }
    d_expected.update({item["path"]: "A" for item in activation_requirements})
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

    registry_payload = blobs[source_entries[REGISTRY_PATH]["oid"]]
    registry = _json(registry_payload, "REGISTRY")
    registrations = registry.get("registrations")
    _require(
        isinstance(registrations, list) and len(registrations) == 1,
        "REGISTRY_CARDINALITY",
    )
    registration = registrations[0]
    _require(isinstance(registration, dict), "REGISTRATION_SHAPE")
    verifier_record = _file_record(
        VERIFIER_PATH, source_entries[VERIFIER_PATH], verifier_payload
    )
    tests_record = _file_record(
        REGISTERED_TESTS_PATH,
        source_entries[REGISTERED_TESTS_PATH],
        registered_tests_payload,
    )
    freeze_record = _file_record(
        FREEZE_PATH, source_entries[FREEZE_PATH], freeze_payload
    )
    _require(
        _strict_equal(
            registration,
            {
                "task_id": TASK_ID,
                "epoch": EPOCH,
                "verifier": verifier_record,
                "tests": tests_record,
                "freeze_contract": freeze_record,
                "qualification_path": QUALIFICATION_PATH,
                "activation_path": ACTIVATION_PATH,
                "verifier_receipt_path": RECEIPT_PATH,
                "effective_on": "SIGNED_COMMIT_FIRST_CONTAINING_EXACT_REGISTRATION_FREEZE_AND_GATES",
            },
        ),
        "REGISTRATION_BINDING",
    )

    qualification_entries = _selected_tree_entries(
        repo, qualification_commit, c_expected
    )
    activation_paths = [
        ACTIVATION_PATH,
        RECEIPT_PATH,
        *(item["path"] for item in activation_requirements),
    ]
    activation_entries = _selected_tree_entries(
        repo, activation_commit, activation_paths
    )
    _require(
        len(qualification_entries) == len(c_expected)
        and len(activation_entries) == len(activation_paths),
        "C_D_RECORD_MISSING",
    )
    extra_blobs = _blobs(
        repo,
        {
            *(entry["oid"] for entry in qualification_entries.values()),
            *(entry["oid"] for entry in activation_entries.values()),
        },
    )
    c_payloads = {
        path: extra_blobs[entry["oid"]] for path, entry in qualification_entries.items()
    }
    activation_payloads = {
        path: extra_blobs[entry["oid"]] for path, entry in activation_entries.items()
    }
    qualification = _json(c_payloads[QUALIFICATION_PATH], "QUALIFICATION")
    activation = _json(activation_payloads[ACTIVATION_PATH], "ACTIVATION")
    _require(
        qualification.get("task_id") == TASK_ID
        and _integer(qualification.get("epoch"), "QUALIFICATION_EPOCH") == EPOCH
        and qualification.get("freeze_commit") == freeze_commit
        and qualification.get("implementation_commit") == implementation_commit,
        "QUALIFICATION_BINDING",
    )
    selected_outcome = qualification.get("selected_claim_outcome_id")
    _require(
        isinstance(selected_outcome, str) and bool(selected_outcome),
        "QUALIFICATION_OUTCOME",
    )
    _require(
        activation.get("task_id") == TASK_ID
        and _integer(activation.get("epoch"), "ACTIVATION_EPOCH") == EPOCH
        and activation.get("freeze_commit") == freeze_commit
        and activation.get("implementation_commit") == implementation_commit
        and activation.get("qualification_commit") == qualification_commit
        and isinstance(activation.get("selected_claim_outcome"), dict)
        and activation["selected_claim_outcome"].get("id") == selected_outcome,
        "ACTIVATION_BINDING",
    )
    evidence_documents, evidence_commands, _command_by_phase = (
        _validate_typed_evidence_bodies(
            freeze=freeze,
            qualification=qualification,
            freeze_commit=freeze_commit,
            implementation_commit=implementation_commit,
            source_tree=source_tree,
            implementation_tree=implementation_tree,
            source_entries=source_entries,
            implementation_entries=implementation_entries,
            c_entries=qualification_entries,
            c_payloads=c_payloads,
            ledger_payload=ledger_payload,
            rows=actual_rows,
            verifier_payload=verifier_payload,
            registered_tests_payload=registered_tests_payload,
            product_tool_payload=product_tool_payload,
            product_tests_payload=product_tests_payload,
        )
    )
    _validate_typed_review_bodies(
        freeze=freeze,
        qualification=qualification,
        freeze_commit=freeze_commit,
        implementation_commit=implementation_commit,
        source_entries=source_entries,
        implementation_entries=implementation_entries,
        c_entries=qualification_entries,
        c_payloads=c_payloads,
        blobs=blobs,
        commands=evidence_commands,
        evidence_documents=evidence_documents,
    )
    _validate_typed_activation_bodies(
        freeze=freeze,
        activation=activation,
        freeze_commit=freeze_commit,
        implementation_commit=implementation_commit,
        qualification_commit=qualification_commit,
        activation_entries=activation_entries,
        activation_payloads=activation_payloads,
        source_tree=source_tree,
        implementation_tree=implementation_tree,
        source_entries=source_entries,
        implementation_entries=implementation_entries,
        ledger_payload=ledger_payload,
        rows=actual_rows,
        product_tool_payload=product_tool_payload,
        product_tests_payload=product_tests_payload,
        registered_tests_payload=registered_tests_payload,
    )

    output = {
        "schema_version": "1.0.0",
        "task_id": TASK_ID,
        "epoch": EPOCH,
        "freeze_commit": freeze_commit,
        "implementation_commit": implementation_commit,
        "qualification_commit": qualification_commit,
        "activation_commit": activation_commit,
        "current_commit": current_commit,
        "verifier_sha256": verifier_record["sha256"],
        "tests_sha256": tests_record["sha256"],
        "selected_claim_outcome_id": selected_outcome,
        "result": "PASS",
    }
    expected_receipt = {
        key: value
        for key, value in output.items()
        if key not in {"activation_commit", "current_commit"}
    }
    expected_receipt["runtime_target_policy"] = (
        "CENTRAL_VERIFIER_EXECUTES_EXACT_F_BLOBS_AT_D_AND_FROZEN_TRIGGERED_CHANGES"
    )
    receipt = _json(activation_payloads[RECEIPT_PATH], "RECEIPT")
    _require(_strict_equal(receipt, expected_receipt), "RECEIPT_BINDING")

    facts = test_fixture()
    for control_id in CONTROL_IDS:
        validate_control(control_id, facts)
    for counterfactual_id in COUNTERFACTUAL_IDS:
        validate_counterfactual(counterfactual_id, facts)
    _require(time.monotonic() - started < 9.0, "VERIFIER_TIME_BOUND")
    return output


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


def _parse_git_toplevel(payload: bytes) -> Path:
    _require(
        len(payload) <= MAX_PATH_BYTES + 1
        and payload.endswith(b"\n")
        and payload.count(b"\n") == 1
        and b"\0" not in payload,
        "REPOSITORY_TOPLEVEL_INVALID",
    )
    try:
        text = payload[:-1].decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        raise VerificationError("REPOSITORY_TOPLEVEL_INVALID") from error
    _require(
        bool(text)
        and unicodedata.normalize("NFC", text) == text
        and not any(unicodedata.category(char).startswith("C") for char in text),
        "REPOSITORY_TOPLEVEL_INVALID",
    )
    parsed = Path(text)
    _require(
        parsed.is_absolute() and Path(os.path.abspath(text)) == parsed,
        "REPOSITORY_TOPLEVEL_INVALID",
    )
    return parsed


def _bind_git_toplevel(repo: Path) -> Path:
    lexical = Path(os.path.abspath(os.fspath(repo)))
    try:
        lexical_stat = os.lstat(lexical)
    except OSError as error:
        raise VerificationError("REPOSITORY_NOT_DIRECTORY") from error
    _require(
        not stat.S_ISLNK(lexical_stat.st_mode) and stat.S_ISDIR(lexical_stat.st_mode),
        "REPOSITORY_NOT_DIRECTORY",
    )
    top_level = _parse_git_toplevel(
        _git(
            lexical,
            ["rev-parse", "--path-format=absolute", "--show-toplevel"],
            maximum=MAX_PATH_BYTES + 1,
        )
    )
    canonical = Path(os.path.realpath(lexical))
    _require(canonical == top_level, "REPOSITORY_NOT_EXACT_TOPLEVEL")
    try:
        root_stat = os.lstat(top_level)
    except OSError as error:
        raise VerificationError("REPOSITORY_NOT_DIRECTORY") from error
    _require(
        not stat.S_ISLNK(root_stat.st_mode)
        and stat.S_ISDIR(root_stat.st_mode)
        and (lexical_stat.st_dev, lexical_stat.st_ino)
        == (root_stat.st_dev, root_stat.st_ino),
        "REPOSITORY_NOT_EXACT_TOPLEVEL",
    )
    return top_level


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
        output = verify_inventory(
            repo,
            arguments.freeze_commit,
            arguments.implementation_commit,
        )
    else:
        _require(
            all(
                isinstance(value, str) and bool(value)
                for value in (
                    arguments.qualification_commit,
                    arguments.activation_commit,
                    arguments.current_commit,
                )
            ),
            "FULL_VERIFICATION_ARGUMENTS",
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
