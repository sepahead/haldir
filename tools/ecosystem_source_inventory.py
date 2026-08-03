#!/usr/bin/env python3
"""Capture, render, seal, and verify a privacy-scoped repository inventory.

The networked ``capture`` command invokes a pinned local ``gh`` executable with
bounded arguments that request GitHub-host API GET operations.  The executable
digest identifies the local bytes; it does not independently verify their
implementation or the resulting network semantics.
It retains public repository facts in a public JSONL file and all owner-visible
facts and detailed telemetry in designated owner-local mode-0600 paths.
``decision-template`` creates an explicit per-repository drafting skeleton.
``render`` joins reviewed decisions to retained observations without creating a
receipt.  ``seal`` checks the staged privacy closure and writes the audit last.
``check`` is deterministic and network-free; without owner-local files it
verifies only the committed private commitment.  ``verify-seal`` requires the
owner-local files and final staged audit.  ``diagram`` generates or byte-checks
the maintained assurance-flow SVG.

None of these operations grants task, release, publication, deployment, tag,
archive, DOI, or GitHub Release authority.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import csv
import datetime as dt
import functools
import hashlib
import io
import json
import os
import platform
from pathlib import Path
from pathlib import PurePosixPath
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any, NoReturn, Protocol, Sequence
from urllib.parse import quote


SCHEMA_VERSION = "1.0.0"
CAPTURE_SCHEMA = "haldir.ecosystem-source-capture.v1"
TEST_CAPTURE_SCHEMA = "TEST_ONLY.haldir.ecosystem-source-capture.v1"
COMMAND_LOG_SCHEMA = "haldir.ecosystem-source-command-log.public-redacted.v1"
PRIVATE_COMMAND_LOG_SCHEMA = (
    "haldir.ecosystem-source-command-log.owner-local-detailed.v1"
)
PRIVATE_TELEMETRY_SCHEMA = "haldir.ecosystem-source-private-telemetry.v1"
DECISIONS_SCHEMA = "haldir.ecosystem-source-decisions.v1"
CLASSIFICATION_SCHEMA = "haldir.ecosystem-repository-classification.v1"
AUDIT_SCHEMA = "haldir.ecosystem-source-audit.v1"
TEST_AUDIT_SCHEMA = "TEST_ONLY.haldir.ecosystem-source-audit.v1"
SUPERSESSION_SCHEMA = "haldir.ecosystem-source-supersession-audit.v1"
MAINTAINED_REVIEW_DATE = "2026-08-02"
SUPERSESSION_REVIEW_DATE = "2026-08-03"
OWNER = "sepahead"
API_HOST = "github.com"
PRODUCTION_CLOSURE_PROFILE = {
    "expected_owner_visible_repositories": 217,
    "expected_private_repositories": 43,
    "expected_public_repositories": 174,
    "expected_owner_node_id": "MDQ6VXNlcjEwMTA0NTY5",
    "expected_owner_account_id": 10_104_569,
    "issue_scope": "Haldir Issue 2 bounded ecosystem source-inventory closure",
    "owner": OWNER,
    "profile_id": "haldir.issue-2-ecosystem-source-closure",
    "profile_version": "1.0.0",
    "source_scope": "Credential-visible GitHub owner repositories via REST API 2026-03-10",
}
TEST_CLOSURE_PROFILE = {
    "expected_owner_visible_repositories": 2,
    "expected_private_repositories": 1,
    "expected_public_repositories": 1,
    "expected_owner_node_id": "MDQ6VXNlcjEwMTA0NTY5",
    "expected_owner_account_id": 10_104_569,
    "issue_scope": "TEST_ONLY synthetic ecosystem source-inventory fixture",
    "owner": OWNER,
    "profile_id": "TEST_ONLY.haldir.ecosystem-source-fixture",
    "profile_version": "1.0.0",
    "source_scope": "TEST_ONLY in-memory fixture; not production evidence",
}
MAX_PAGES_DEFAULT = 10
MAX_HEAD_WORKERS_DEFAULT = 8
MAX_GET_ATTEMPTS = 3
MAX_PAGE_NODES = 100
MAX_REPOSITORIES = 1_000
MAX_API_RESPONSE_BYTES = 16 * 1024 * 1024
MAX_API_STDERR_BYTES = 64 * 1024
MAX_JSON_BYTES = 64 * 1024 * 1024
MAX_JSONL_LINE_BYTES = 1024 * 1024
MAX_COMMAND_LOG_BYTES = 4 * 1024 * 1024
MAX_EXECUTABLE_BYTES = 256 * 1024 * 1024
MAX_TOKEN_BYTES = 4 * 1024
MAX_TEXT_FIELD = 2_048
MAX_TRACKED_FILES = 100_000
MAX_TRACKED_INDEX_BYTES = 16 * 1024 * 1024
MAX_TRACKED_FILE_BYTES = 16 * 1024 * 1024
MAX_TRACKED_SCAN_BYTES = 256 * 1024 * 1024
MAX_OPERATIONAL_JSON_CANDIDATES = MAX_TRACKED_FILE_BYTES
MAX_OPERATIONAL_JSON_NODES = MAX_TRACKED_FILE_BYTES
MAX_OPERATIONAL_JSON_WORK_BYTES = MAX_TRACKED_SCAN_BYTES
GIT_TIMEOUT_SECONDS = 60
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
RFC3339_UTC = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
JSON_CONTAINER_START = re.compile(r"[\[{]")

BRANCH_CONTEXT_KEYS = frozenset(
    {
        "baseref",
        "baserefname",
        "branch",
        "branches",
        "defaultbranch",
        "defaultbranchref",
        "headref",
        "headrefname",
        "ref",
        "refname",
        "sha",
    }
)
REPOSITORY_CONTEXT_KEYS = frozenset(
    {"repo", "reponame", "repos", "repositories", "repository", "repositoryname"}
)
OID_CONTEXT_KEYS = frozenset(
    {
        "commit",
        "commitoid",
        "commitsha",
        "head",
        "headoid",
        "headsha",
        "objectoid",
        "objectsha",
        "oid",
        "sha",
    }
)
REPOSITORY_ID_CONTEXT_KEYS = frozenset({"repoid", "repositoryid"})
REPOSITORY_ENTITY_CONTEXT_KEYS = frozenset(
    {"repo", "repos", "repositories", "repository"}
)
BRANCH_ENTITY_CONTEXT_KEYS = frozenset(
    {
        "baseref",
        "branch",
        "branches",
        "defaultbranchref",
        "headref",
        "ref",
        "refs",
    }
)
IDENTITY_TRANSPARENT_CONTEXT_KEYS = frozenset(
    {"edge", "edges", "metadata", "node", "nodes", "target"}
)

PUBLIC_HEADS_BASENAME = "repository-heads.jsonl"
OWNER_VISIBLE_BASENAME = "owner-visible-repositories.private.jsonl"
CAPTURE_METADATA_BASENAME = "capture-metadata.json"
COMMAND_LOG_BASENAME = "command-log.jsonl"
PUBLIC_DECISIONS_BASENAME = "repository-classification-decisions.json"
PRIVATE_DECISIONS_BASENAME = "repository-classification-decisions.private.json"
PUBLIC_CLASSIFICATION_JSON_BASENAME = "repository-classification.json"
PUBLIC_CLASSIFICATION_CSV_BASENAME = "repository-classification.csv"
PRIVATE_LEDGER_BASENAME = "local-private-source-ledger.private.csv"
PRIVATE_TELEMETRY_BASENAME = "capture-command-telemetry.private.json"
AUDIT_METADATA_BASENAME = "audit-metadata.json"
SUPERSESSION_BASENAME = "supersession-audit.json"
ECOSYSTEM_DIAGRAM_BASENAME = "ecosystem-source-inventory.svg"
CANONICAL_INVENTORY_SCRIPT_PATH = PurePosixPath("tools/ecosystem_source_inventory.py")
CANONICAL_DIAGRAM_PATH = PurePosixPath("docs/assets/ecosystem-source-inventory.svg")
EXPECTED_PRIVATE_IGNORE_PATTERNS = frozenset(
    {
        "*.private.csv",
        "*.private.json",
        "*.private.jsonl",
        "evidence/**/*.private.*",
    }
)

CAPTURE_OUTPUT_LABELS = {
    "capture_metadata": CAPTURE_METADATA_BASENAME,
    "command_log": COMMAND_LOG_BASENAME,
    "owner_visible": OWNER_VISIBLE_BASENAME,
    "private_telemetry": PRIVATE_TELEMETRY_BASENAME,
    "public_heads": PUBLIC_HEADS_BASENAME,
}
TOKEN_ENVIRONMENT_KEYS = frozenset(
    {
        "GH_ENTERPRISE_TOKEN",
        "GH_TOKEN",
        "GITHUB_ENTERPRISE_TOKEN",
        "GITHUB_TOKEN",
    }
)
GH_AMBIENT_ENVIRONMENT_KEYS = frozenset(
    {
        *TOKEN_ENVIRONMENT_KEYS,
        "CLICOLOR_FORCE",
        "DEBUG",
        "DO_NOT_TRACK",
        "GH_DEBUG",
        "GH_FORCE_TTY",
        "GH_NO_EXTENSION_UPDATE_NOTIFIER",
        "GH_NO_UPDATE_NOTIFIER",
        "GH_PATH",
        "GH_REPO",
        "GH_TELEMETRY",
    }
)
GH_AUTH_ENVIRONMENT_ALLOWLIST = frozenset(
    {
        "APPDATA",
        "GH_CONFIG_DIR",
        "HOME",
        "LOCALAPPDATA",
        "PATH",
        "TMPDIR",
        "XDG_CONFIG_HOME",
    }
)
GH_API_AMBIENT_ALLOWLIST: frozenset[str] = frozenset()
GH_FIXED_ENVIRONMENT = {
    "CLICOLOR": "0",
    "DO_NOT_TRACK": "1",
    "GH_HOST": API_HOST,
    "GH_NO_EXTENSION_UPDATE_NOTIFIER": "1",
    "GH_NO_UPDATE_NOTIFIER": "1",
    "GH_PAGER": "cat",
    "GH_PROMPT_DISABLED": "1",
    "GH_SPINNER_DISABLED": "1",
    "GH_TELEMETRY": "0",
    "LC_ALL": "C",
    "NO_COLOR": "1",
    "PAGER": "cat",
}
CREDENTIAL_BINDING = {
    "competing_token_environment_removed": True,
    "identity_reverified_after_capture": True,
    "method": "ONE_PINNED_GH_TOKEN_IN_MEMORY_AND_GH_TOKEN_ENVIRONMENT",
    "token_material_recorded": False,
}
GH_ENVIRONMENT_BINDING = {
    "api_ambient_allowlist": sorted(GH_API_AMBIENT_ALLOWLIST),
    "ambient_debug_and_force_tty_removed": True,
    "api_config": "PRIVATE_EMPTY_CONFIG_DIRECTORY",
    "auth_ambient_allowlist": sorted(GH_AUTH_ENVIRONMENT_ALLOWLIST),
    "auth_path": "ABSOLUTE_NON_GROUP_WORLD_WRITABLE_DIRECTORIES",
    "extension_update_notifier_disabled": True,
    "prompt_disabled": True,
    "telemetry_disabled": True,
    "update_notifier_disabled": True,
}
EXECUTABLE_BINDING_METHOD = (
    "PRIVATE_READ_ONLY_DIRECTORY_EXACT_COPY_WITH_OPEN_FD_EXEC_BOUNDARY_CHECK"
)
TOOL_API_REQUEST_CONTRACT = {
    "api_host_argument": API_HOST,
    "http_method_arguments": ["GET"],
    "mutation_argument_issued": False,
    "tool_semantics_independently_verified": False,
}
CROSS_LANE_SCAN_CONFIGURATION = {
    "audit_index_treatment": "EXCLUDED_FROM_DIGEST_COUNTS_AND_BLOB_SCAN",
    "binary_matching": (
        "UTF8_UNICODE_CASEFOLDED_NAMES_URLS_CONTEXTUAL_PRIVATE_ONLY_HEADS_"
        "AND_PREFIXES_STRUCTURED_IDS_JSON_STRING_ESCAPES_"
        "DISTINCTIVE_BRANCHES_OWNER_LOCAL_PATHS_COMPONENT_BYTES_AND_PRIVATE_"
        "OPERATIONAL_SUBOBJECTS_V8_COMPILED_LITERAL_POLICY"
    ),
    "compiled_literal_policy": (
        "DETERMINISTIC_ESCAPED_OR_COMBINATION_CACHED_PER_PRIVATE_TOKEN_SET"
    ),
    "git_index_scope": "ALL_STAGE_ZERO_REGULAR_BLOB_PATHS_AND_BYTES",
    "git_lazy_fetch_disabled": True,
    "git_replace_objects_disabled": True,
    "maximum_file_bytes": MAX_TRACKED_FILE_BYTES,
    "maximum_files": MAX_TRACKED_FILES,
    "maximum_index_bytes": MAX_TRACKED_INDEX_BYTES,
    "maximum_total_blob_bytes": MAX_TRACKED_SCAN_BYTES,
    "operational_json_candidate_bound": MAX_OPERATIONAL_JSON_CANDIDATES,
    "operational_json_node_bound": MAX_OPERATIONAL_JSON_NODES,
    "operational_json_work_byte_bound": MAX_OPERATIONAL_JSON_WORK_BYTES,
    "private_path_check_passes": 2,
    "private_write_policy": "TRACKED_STAGED_EQUAL_IGNORE_PREFLIGHT_BEFORE_AND_AFTER_EACH_OWNER_LOCAL_WRITE_PHASE",
    "private_path_checks": [
        "git check-ignore --verbose -z --no-index --stdin",
        "git ls-files --error-unmatch -- PRIVATE_PATH",
    ],
    "private_payload_checks": [
        "EXACT_OWNER_LOCAL_COMPONENT_BYTES",
        "REPRESENTATION_NORMALIZED_DETAILED_PRIVATE_TELEMETRY_SUBOBJECTS",
    ],
    "sealed_index_manifest": (
        "CANONICAL_MODE_PATH_SIZE_GIT_OID_AND_INDEPENDENT_BLOB_SHA256"
    ),
    "required_evidence_index_mode": "100644",
    "stable_index_observations": 2,
    "tracked_ignore_provenance_required": True,
    "diagram_index_binding": "EXACT_GENERATED_SVG_REQUIRED_100644",
    "tool_source_index_binding": "CURRENT_INVENTORY_SCRIPT_REQUIRED_100644",
    "worktree_difference_allowlist": [AUDIT_METADATA_BASENAME],
}

SUPERSESSION_SCOPE = "Account source-inventory history and current-observation boundary"
SUPERSESSION_SOURCE_CONTRACT = {
    "CURRENT_NCP_BOUNDARY": (
        "docs/ROADMAP-STATUS.md",
        "CURRENT_MAINTAINED_STATUS",
    ),
    "HISTORICAL_2026_07_12": (
        "docs/HALDIR-NCP-V0.8.0-TRIPLE-CHECKED-AUDIT-AND-IMPLEMENTATION-SPECIFICATION-2026.md",
        "DATED_HISTORICAL_OBSERVATION",
    ),
    "OWNER_LOCAL_PRIVATE_LEDGER": (
        "evidence/source-review/local-private-source-ledger.private.csv",
        "OWNER_LOCAL_MODE_0600_EVIDENCE",
    ),
    "P0_SOURCE_LEDGER": (
        "evidence/source-review/source-ledger.md",
        "P0_BASELINE_WITH_CURRENT_BOUNDARY",
    ),
    "PUBLIC_REPOSITORY_HEADS": (
        "evidence/source-review/repository-heads.jsonl",
        "RETAINED_PUBLIC_OBSERVATION",
    ),
}
SUPERSESSION_DECISION_CONTRACT = {
    "SA-001": "RETAIN_AS_HISTORY",
    "SA-002": "RETAIN_IMMUTABLE_V0_8_BASELINE",
    "SA-003": "SUPERSEDE_ONLY_CURRENT_HEAD_OBSERVATIONS",
    "SA-004": "KEEP_STORAGE_CLASSES_SEPARATE",
    "SA-005": "REMAIN_PARTIAL",
    "SA-006": "INVENTORY_ONLY",
}
SUPERSESSION_REVIEW_ATTESTATION = (
    "Automated factual review compared every supersession disposition and "
    "non-implication boundary with the declared source set. This is not human "
    "or owner approval, and reviewer identity is not independently authenticated."
)
SUPERSESSION_EXPECTED_DOCUMENT = {
    "authority": {
        "archive_authorized": False,
        "deployment_authorized": False,
        "doi_authorized": False,
        "github_release_authorized": False,
        "overall_release_status": "NO_GO",
        "publication_authorized": False,
        "release_authorized": False,
        "tag_authorized": False,
        "task_state_advanced": False,
    },
    "decisions": [
        {
            "disposition": "RETAIN_AS_HISTORY",
            "id": "SA-001",
            "must_not_imply": [
                "that the listed branch heads remain current",
                "that a later head migrated or qualified a runtime",
            ],
            "reason": "The table records what the audit observed at that time. Later branch heads do not make the historical observation false.",
            "subject": "The public baseline observed on 2026-07-12",
        },
        {
            "disposition": "RETAIN_IMMUTABLE_V0_8_BASELINE",
            "id": "SA-002",
            "must_not_imply": [
                "native Haldir wire-1.0 migration",
                "NCP 1.0 publication",
                "consumer or role qualification",
            ],
            "reason": "Haldir remains pinned to NCP v0.8.0. NCP repository HEAD is an unreleased and release-blocked wire-1.0 candidate.",
            "subject": "The Haldir NCP runtime baseline",
        },
        {
            "disposition": "SUPERSEDE_ONLY_CURRENT_HEAD_OBSERVATIONS",
            "id": "SA-003",
            "must_not_imply": [
                "continuous branch monitoring",
                "that the observed commit was installed or executed",
                "that copied protocol files prove migration",
            ],
            "reason": "Each retained 40-hex commit OID is immutable. The default-branch ref that selected it is mutable, so the observation is bounded by the capture interval in audit-metadata.json.",
            "subject": "Default-branch head records",
        },
        {
            "disposition": "KEEP_STORAGE_CLASSES_SEPARATE",
            "id": "SA-004",
            "must_not_imply": [
                "that a public placeholder describes a private implementation",
                "that a public commitment makes private evidence independently reproducible",
            ],
            "reason": "Public history may identify public repositories. Owner-visible private identities, URLs, branches, heads, paths, and classifications remain only in owner-local mode-0600 files.",
            "subject": "Public and owner-visible repository evidence",
        },
        {
            "disposition": "REMAIN_PARTIAL",
            "id": "SA-005",
            "must_not_imply": [
                "phase completion",
                "integration qualification",
                "release authorization",
            ],
            "reason": "A future completed, reviewed, and sealed inventory would remove only the missing-inventory reason. Separate review, source, claim, and assurance exit gates would remain.",
            "subject": "Roadmap phases -1 and 0",
        },
        {
            "disposition": "INVENTORY_ONLY",
            "id": "SA-006",
            "must_not_imply": [
                "CH-T003 completion",
                "a release GO decision",
                "security, safety, interoperability, or deployment certification",
            ],
            "reason": "Issue 2 can record bounded inventory completion only after the exact capture, review, and final seal exist. Any later closure would not modify the retired CH-T003 lifecycle, active claims, requirements, or release authority.",
            "subject": "Issue 2 closure authority",
        },
    ],
    "owner_approval_established": False,
    "prepared_at": MAINTAINED_REVIEW_DATE,
    "prepared_by": "Codex automated draft",
    "review_attestation": SUPERSESSION_REVIEW_ATTESTATION,
    "review_date": SUPERSESSION_REVIEW_DATE,
    "review_kind": "AUTOMATED_FACTUAL_REVIEW",
    "review_status": "REVIEWED",
    "reviewer": "Codex automated factual review",
    "reviewer_identity_authenticated": False,
    "schema_id": SUPERSESSION_SCHEMA,
    "schema_version": SCHEMA_VERSION,
    "scope": SUPERSESSION_SCOPE,
    "sources": [
        {"id": key, "path": path, "status": status}
        for key, (path, status) in SUPERSESSION_SOURCE_CONTRACT.items()
    ],
    "unresolved": [
        "Automated factual review is not human or owner approval; owner approval and authenticated reviewer identity are not established.",
        "A final staged seal, if later retained, would prove only the bounded inventory closure and would grant no release or integration authority.",
        "Native NCP 1.0 migrations and role qualifications remain separate work.",
        "Owner-local private evidence is not independently reproducible from the public repository.",
        "Mutable GitHub state can advance after the retained capture interval.",
        "Phase -1 and Phase 0 reviewer exit gates remain incomplete.",
        "The Haldir 0.9.0 release decision remains NO_GO.",
    ],
}
SUPERSESSION_UNREVIEWED_DOCUMENT = {
    **SUPERSESSION_EXPECTED_DOCUMENT,
    "review_attestation": None,
    "review_date": None,
    "review_kind": "AUTOMATED_DRAFT",
    "review_status": "UNREVIEWED",
    "reviewer": None,
    "unresolved": [
        "The supersession audit remains an automated draft; factual review, owner approval, and authenticated reviewer identity are not established.",
        "A final staged seal, if later retained, would prove only the bounded inventory closure and would grant no release or integration authority.",
        "Native NCP 1.0 migrations and role qualifications remain separate work.",
        "Owner-local private evidence is not independently reproducible from the public repository.",
        "Mutable GitHub state can advance after the retained capture interval.",
        "Phase -1 and Phase 0 reviewer exit gates remain incomplete.",
        "The Haldir 0.9.0 release decision remains NO_GO.",
    ],
}

RELEVANCE_FIELDS = (
    "controller_relevance",
    "transport_relevance",
    "plant_relevance",
    "state_relevance",
    "evidence_relevance",
    "supply_chain_relevance",
    "agentic_tool_relevance",
)
REVIEW_STATUS = "REVIEWED"
CLASSIFICATION_STATUS = "FINAL_FOR_INVENTORY"
CLASSIFICATION_REVIEW_BASIS = {
    "captured_observation_binding": "repository_heads_sha256",
    "completed_runtime_integration_inferred": False,
    "final_seal_binding": "PUBLIC_EVIDENCE_SUPERSESSION_SOURCES_EXACT_BYTES",
    "maintained_source_ids": [
        "CURRENT_NCP_BOUNDARY",
        "HISTORICAL_2026_07_12",
        "P0_SOURCE_LEDGER",
    ],
    "repository_content_reviewed": False,
    "scope": "CAPTURED_METADATA_PLUS_DECLARED_MAINTAINED_SOURCES",
}
REVIEW_ATTESTATION = (
    "I reviewed each classification against its bound captured observation and the "
    "declared maintained source set. I inferred no unobserved repository content or "
    "completed runtime integration; empty repositories are explicit and no field is "
    "unresolved."
)

DECISION_KEYS = {
    "repository_id",
    "repository",
    "first_party",
    *RELEVANCE_FIELDS,
    "tcb_class",
    "audit_depth",
    "classification_status",
    "justification",
    "reviewer",
    "review_date",
    "review_attestation",
    "review_status",
}

TCB_CLASSES = frozenset(
    {
        "GATE_RUNTIME_TCB",
        "PLANT_TCB",
        "AUTHORITY_TCB",
        "CONTROLLER_UNTRUSTED_PRODUCER",
        "TRUSTED_STATE_PRODUCER",
        "ADVISORY_EVIDENCE_PRODUCER",
        "OFFLINE_RESEARCH_TOOL",
        "READ_ONLY_VISUALIZER",
        "UNTRUSTED_FIXTURE_SOURCE",
        "LEGACY_BYPASS_RISK",
        "OUTSIDE_RUNTIME_TCB",
    }
)
AUDIT_DEPTHS = frozenset({"DEEP", "BOUNDARY", "INVENTORY_ONLY"})

CSV_COLUMNS = (
    "repository",
    "repository_id",
    "exact_head",
    "head_state",
    "default_branch",
    "archived",
    "fork",
    "visibility",
    "first_party",
    *RELEVANCE_FIELDS,
    "tcb_class",
    "audit_depth",
    "classification_status",
    "justification",
    "reviewer",
    "review_date",
    "review_attestation",
    "review_status",
)

AUTHORITY = {
    "archive_authorized": False,
    "deployment_authorized": False,
    "doi_authorized": False,
    "github_release_authorized": False,
    "overall_release_status": "NO_GO",
    "publication_authorized": False,
    "release_authorized": False,
    "tag_authorized": False,
    "task_state_advanced": False,
}

API_VERSION = "2026-03-10"
PUBLIC_ENDPOINT_TEMPLATE = (
    "/users/{owner}/repos?type=owner&sort=full_name&direction=asc"
    "&per_page=100&page={page}"
)
OWNER_ENDPOINT_TEMPLATE = (
    "/user/repos?visibility=all&affiliation=owner&sort=full_name&direction=asc"
    "&per_page=100&page={page}"
)
LIMITATIONS = [
    "Commit OIDs are immutable object identities; default branches and GitHub metadata remain mutable after the capture interval.",
    "The pinned gh executable is local trusted computing base. Its digest proves byte identity, but local evidence does not independently prove its implementation, TLS use, remote origin, GET-only behavior, or absence of mutations.",
    "Viewer-owner identity equality does not prove that the credential can see every private repository; the inventory covers the credential-visible set, and expected repository counts are operator assertions, not authentication-scope proof.",
    "Fork-parent identity is not retained; supply-chain review cannot infer ancestry from the fork flag.",
    "The tracked receipt binds each owner-local private component by label, classification, byte count, and SHA-256, and binds the private repository count; public checking cannot inspect absent private bytes.",
    "Private-path validation enforces exact basenames, a common evidence root, mode 0600, regular non-symlink files, and one link. Owner-local closure also requires ignore provenance from a tracked ignore file, an untracked private path, and staged/worktree equality for the ignore source; these local checks do not prove remote or historical absence.",
    "Production capture, private decision-template, and draft render operations require tracked, staged-equal ignore provenance and untracked private target paths before and after each owner-local write phase. The synthetic test profile bypasses this production preflight only inside isolated fixtures.",
    "The production orchestration token and exact GhClient type check prevent accidental direct production capture calls. They are cooperative same-process checks, not a security boundary against Python code that can inspect or mutate module state.",
    "On signal, the shutdown latch rejects queued command work and active process groups are killed and reaped. A worker already admitted at signal arrival can enter process creation before cleanup; the evidence does not claim zero transient post-signal process creation.",
    "The public commitment-only check cannot test cross-lane private-identifier absence; owner-local render and owner-local verification with the mode-0600 private inputs perform that check.",
    "Owner-local cross-lane verification requires two byte-identical stage-zero Git index observations around the regular-blob scan and repeats private ignore, worktree, and untracked checks. This is a bounded stability check, not an atomic index lock. It rejects tracked symlinks and non-regular entries, but does not inspect Git history, arbitrary encodings, or external publication channels.",
    "Whole-index verification rejects exact owner-local component bytes and bounded representation variants of all detailed private telemetry subobjects in tracked blobs, including embedded JSON, JSON strings, Markdown blockquotes, and diff additions or deletions. This structural check does not prove that every partial, transformed, or semantically equivalent private-derived value is absent.",
    "The local Git executable and current index are trusted inputs to owner-local closure. The receipt binds the audit-excluded staged manifest by mode, path, size, Git object identifier, and an independently computed blob SHA-256. The final audit payload is checked separately and must be staged last. These checks do not independently verify Git implementation semantics or history.",
    "The Python runtime and standard library, and the local operating-system process, signal, clock, filesystem, and permission semantics, are trusted inputs. A recorded Python implementation and version identify the observed runtime but do not independently prove those semantics.",
    "Whole-index matching subtracts tokens present in public records and excludes common or short branch names and shared classification enums from unstructured matching to avoid false positives. It checks short private-only names, branches, and unique commit prefixes in a finite grammar of repository identity fields and paths; branch, ref, and SHA fields and paths; Git clone, submodule, remote, fetch, and -C forms; and head, commit, object, OID, and rev-parse forms. Entity children such as repository owners and issues reset repository-identity context. A shared or bare ambiguous token without a listed context is not treated as a private leak.",
    "Exact decision status, attestation text, reviewer text, dates, and source digests do not authenticate reviewer identity or independently prove that a person performed the review. Owner approval of the exact final bytes remains separate evidence.",
    "Repository classification does not establish runtime integration, security qualification, release readiness, or semantic correctness.",
]


def ecosystem_source_inventory_svg() -> bytes:
    """Return the deterministic accessible source-inventory workflow diagram."""
    return """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1600 1100" role="img" aria-labelledby="diagram-title diagram-desc">
  <title id="diagram-title">Haldir ecosystem source-inventory assurance flow</title>
  <desc id="diagram-desc">Required workflow for the fixed production closure profile. The diagram distinguishes conditional capture completion, automated factual review, owner approval that is not established, and receipt-derived seal states; it does not itself assert that a current capture or seal passed. A tracked ignore preflight precedes bounded REST GET capture. Public and owner-local lanes remain separate. Reviewed final classifications and a separately reviewed automated supersession source feed draft rendering. Neither review authenticates a person or proves owner approval. Deterministic public outputs, the current tool source, and the exact generated diagram are staged as non-executable regular files. A stable stage-zero index scan rejects private identifiers, private component copies, and representation variants of detailed private telemetry, then binds a canonical index manifest. The audit is excluded from its own manifest, written last, staged exactly, and verified again. Public checking remains commitment-only; owner-local verify-seal requires the final staged audit. Every authority field remains false and release status remains NO_GO.</desc>
  <defs>
    <linearGradient id="canvas" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="#071426"/>
      <stop offset="1" stop-color="#10233d"/>
    </linearGradient>
    <filter id="shadow" x="-20%" y="-20%" width="140%" height="140%">
      <feDropShadow dx="0" dy="7" stdDeviation="7" flood-color="#020617" flood-opacity="0.35"/>
    </filter>
    <marker id="arrow-cyan" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse">
      <path d="M0 0 10 5 0 10Z" fill="#38bdf8"/>
    </marker>
    <marker id="arrow-amber" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse">
      <path d="M0 0 10 5 0 10Z" fill="#fbbf24"/>
    </marker>
    <style>
      .title{font:700 34px ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;fill:#f8fafc}.subtitle{font:500 16px ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;fill:#b8c8dc}.stateLine{font:700 13px ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;fill:#f8fafc;letter-spacing:.3px}.chip{fill:#142a46;stroke:#35506f;stroke-width:1}.chipText{font:650 12px ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;fill:#cbd5e1;letter-spacing:.35px}.box{filter:url(#shadow);stroke-width:2}.capture{fill:#102f48;stroke:#38bdf8}.public{fill:#0d3441;stroke:#22d3ee}.private{fill:#3a2612;stroke:#fbbf24}.review{fill:#14352f;stroke:#34d399}.stage{fill:#24244c;stroke:#a78bfa}.scan{fill:#222b3d;stroke:#94a3b8}.audit{fill:#38233f;stroke:#e879f9}.guard{fill:#421f29;stroke:#fb7185}.boxTitle{font:700 18px ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;fill:#f8fafc}.body{font:500 13.5px ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;fill:#d9e4f0}.mono{font:600 12.5px ui-monospace,SFMono-Regular,Menlo,monospace;fill:#bae6fd}.privateText{fill:#fde68a}.warningText{fill:#fecdd3}.muted{fill:#9fb1c7}.label{font:700 12px ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;letter-spacing:1.25px}.flow{fill:none;stroke:#38bdf8;stroke-width:3;stroke-linecap:round;stroke-linejoin:round;marker-end:url(#arrow-cyan);stroke-dasharray:9 7;animation:dash 2.8s linear infinite}.privateFlow{stroke:#fbbf24;marker-end:url(#arrow-amber)}.boundary{fill:none;stroke:#fbbf24;stroke-width:2;stroke-dasharray:8 8}.motion{fill:#e0f2fe;stroke:#0284c7;stroke-width:2}.motion.privateDot{fill:#fef3c7;stroke:#d97706}@keyframes dash{to{stroke-dashoffset:-32}}@media (prefers-reduced-motion:reduce){.flow{animation:none;stroke-dasharray:none}.motion{display:none}}
    </style>
  </defs>
  <rect width="1600" height="1100" rx="28" fill="url(#canvas)"/>
  <text class="title" x="800" y="48" text-anchor="middle">Ecosystem source-inventory assurance flow</text>
  <text class="subtitle" x="800" y="75" text-anchor="middle">Fixed closure profile • 174 public + 43 private = 217 owner-visible • REST 2026-03-10 • authority remains NO_GO</text>
  <text class="stateLine" x="800" y="99" text-anchor="middle">CAPTURE COMPLETE only with exact tool binding • AUTOMATED FACTUAL REVIEW • OWNER APPROVAL NOT ESTABLISHED • SEAL STATE FROM RECEIPT</text>

  <g aria-label="Twelve review lenses">
    <rect class="chip" x="50" y="106" width="118" height="30" rx="15"/><text class="chipText" x="109" y="126" text-anchor="middle">AUTHORITY</text>
    <rect class="chip" x="177" y="106" width="118" height="30" rx="15"/><text class="chipText" x="236" y="126" text-anchor="middle">PRIVACY</text>
    <rect class="chip" x="304" y="106" width="118" height="30" rx="15"/><text class="chipText" x="363" y="126" text-anchor="middle">PROVENANCE</text>
    <rect class="chip" x="431" y="106" width="118" height="30" rx="15"/><text class="chipText" x="490" y="126" text-anchor="middle">TOCTOU</text>
    <rect class="chip" x="558" y="106" width="118" height="30" rx="15"/><text class="chipText" x="617" y="126" text-anchor="middle">RATE BUDGET</text>
    <rect class="chip" x="685" y="106" width="118" height="30" rx="15"/><text class="chipText" x="744" y="126" text-anchor="middle">FACT REVIEW</text>
    <rect class="chip" x="812" y="106" width="118" height="30" rx="15"/><text class="chipText" x="871" y="126" text-anchor="middle">SUPERSESSION</text>
    <rect class="chip" x="939" y="106" width="118" height="30" rx="15"/><text class="chipText" x="998" y="126" text-anchor="middle">GIT SEMANTICS</text>
    <rect class="chip" x="1066" y="106" width="118" height="30" rx="15"/><text class="chipText" x="1125" y="126" text-anchor="middle">PROCESS EXIT</text>
    <rect class="chip" x="1193" y="106" width="118" height="30" rx="15"/><text class="chipText" x="1252" y="126" text-anchor="middle">ACCESSIBILITY</text>
    <rect class="chip" x="1320" y="106" width="118" height="30" rx="15"/><text class="chipText" x="1379" y="126" text-anchor="middle">REPRODUCIBLE</text>
    <rect class="chip" x="1447" y="106" width="103" height="30" rx="15"/><text class="chipText" x="1499" y="126" text-anchor="middle">NO_GO</text>
  </g>

  <g aria-label="Capture preflight">
    <rect class="box capture" x="50" y="185" width="300" height="285" rx="18"/>
    <text class="label" x="75" y="216" fill="#7dd3fc">01 • BEFORE NETWORK OR WRITE</text>
    <text class="boxTitle" x="75" y="247">Private-write preflight</text>
    <text class="body" x="75" y="276"><tspan x="75" dy="0">• exact private basenames and common root</tspan><tspan x="75" dy="23">• tracked ignore provenance; staged = worktree</tspan><tspan x="75" dy="23">• index flag H; targets ignored and untracked</tspan><tspan x="75" dy="23">• repeat after each private write phase</tspan></text>
    <line x1="75" y1="378" x2="325" y2="378" stroke="#31516c"/>
    <text class="body muted" x="75" y="404"><tspan x="75">Production orchestration closes the gh signal</tspan><tspan x="75" dy="21">guard before the Git postflight begins.</tspan></text>
  </g>

  <g aria-label="Bounded REST capture">
    <rect class="box capture" x="390" y="185" width="300" height="285" rx="18"/>
    <text class="label" x="415" y="216" fill="#7dd3fc">02 • BOUNDED OBSERVATION</text>
    <text class="boxTitle" x="415" y="247">Pinned gh • requested GET</text>
    <text class="body" x="415" y="276"><tspan x="415">• four ordered owner/viewer identity rates</tspan><tspan x="415" dy="23">• two stable snapshots per visibility scope</tspan><tspan x="415" dy="23">• exact default-branch commit or EMPTY state</tspan><tspan x="415" dy="23">• page, retry, response, and reserve bounds</tspan><tspan x="415" dy="23">• queued work rejected; groups reaped</tspan></text>
    <text class="mono" x="415" y="420">GET argv ≠ independent network proof</text>
    <text class="mono" x="415" y="445">COMPLETE iff metadata binds this tool</text>
  </g>

  <path id="capture-flow" class="flow" d="M350 327H390"/>
  <circle class="motion" cx="350" cy="327" r="5"><animateMotion dur="2.8s" repeatCount="indefinite" path="M0 0H40"/></circle>

  <g aria-label="Separated evidence lanes">
    <rect class="box public" x="730" y="170" width="350" height="150" rx="18"/>
    <text class="label" x="755" y="201" fill="#67e8f9">PUBLIC LANE</text>
    <text class="boxTitle" x="755" y="232">Redacted retained evidence</text>
    <text class="body" x="755" y="255"><tspan x="755">repository-heads.jsonl • capture metadata</tspan><tspan x="755" dy="19">redacted command log</tspan><tspan x="755" dy="19">no rate, page, or request detail</tspan><tspan x="755" dy="19">four public supersession blobs</tspan></text>

    <rect class="boundary" x="716" y="332" width="378" height="186" rx="22"/>
    <rect class="box private" x="730" y="344" width="350" height="166" rx="18"/>
    <text class="label privateText" x="755" y="375">OWNER-LOCAL • MODE 0600</text>
    <text class="boxTitle" x="755" y="405">Four private components</text>
    <text class="body privateText" x="755" y="434"><tspan x="755">owner-visible JSONL • private decisions</tspan><tspan x="755" dy="20">private classification CSV • detailed telemetry</tspan><tspan x="755" dy="20">owner-local ledger commitment</tspan><tspan x="755" dy="20">exact bytes stable through closure</tspan></text>
  </g>

  <path class="flow" d="M690 275H730"/>
  <path class="flow privateFlow" d="M690 380H730"/>

  <g aria-label="Automated factual review and owner-approval boundary">
    <rect class="box review" x="1120" y="185" width="430" height="331" rx="18"/>
    <text class="label" x="1145" y="216" fill="#6ee7b7">03 • AUTOMATED FACTUAL REVIEW</text>
    <text class="boxTitle" x="1145" y="247">REVIEWED • FINAL_FOR_INVENTORY</text>
    <text class="body" x="1145" y="276"><tspan x="1145">Every classification field and the supersession</tspan><tspan x="1145" dy="22">boundary bind explicit source observations.</tspan></text>
    <rect x="1145" y="323" width="380" height="118" rx="12" fill="#0b2823" stroke="#34d399"/>
    <text class="label" x="1163" y="348" fill="#6ee7b7">SOURCE-BOUND ATTESTATION</text>
    <text class="body" x="1163" y="374"><tspan x="1163">Captured observations + maintained source set;</tspan><tspan x="1163" dy="21">no unobserved content or completed integration.</tspan><tspan x="1163" dy="21">Status text does not authenticate a reviewer.</tspan></text>
    <text class="label warningText" x="1145" y="476">OWNER APPROVAL • NOT ESTABLISHED</text>
    <text class="body muted" x="1145" y="500">Path-free prose; mixed or contradictory states fail closed.</text>
  </g>

  <path class="flow" d="M1080 245H1120"/>
  <path class="flow privateFlow" d="M1080 426H1100V390H1120"/>

  <g aria-label="Draft render">
    <rect class="box review" x="50" y="580" width="280" height="195" rx="18"/>
    <text class="label" x="75" y="611" fill="#6ee7b7">04 • RENDER DRAFT</text>
    <text class="boxTitle" x="75" y="642">Deterministic views</text>
    <text class="body" x="75" y="671"><tspan x="75">public JSON + CSV</tspan><tspan x="75" dy="22">private CSV remains owner-local</tspan><tspan x="75" dy="22">public/private identifier scan</tspan><tspan x="75" dy="22">audit is not written yet</tspan></text>
  </g>

  <g aria-label="Required staged inputs">
    <rect class="box stage" x="370" y="565" width="310" height="225" rx="18"/>
    <text class="label" x="395" y="596" fill="#c4b5fd">05 • STAGE EXACT BYTES</text>
    <text class="boxTitle" x="395" y="627">Required regular mode 100644</text>
    <text class="body" x="395" y="655"><tspan x="395">captured inputs + reviewed decisions</tspan><tspan x="395" dy="22">generated public JSON and CSV</tspan><tspan x="395" dy="22">four public supersession blobs</tspan><tspan x="395" dy="22">current tool + exact generated SVG</tspan><tspan x="395" dy="22">no missing, alternate, or special modes</tspan></text>
  </g>

  <g aria-label="Stable index privacy scan">
    <rect class="box scan" x="710" y="535" width="400" height="285" rx="18"/>
    <text class="label" x="735" y="566" fill="#cbd5e1">06 • TWO STABLE INDEX OBSERVATIONS</text>
    <text class="boxTitle" x="735" y="597">Whole stage-zero regular-blob scan</text>
    <text class="body" x="735" y="626"><tspan x="735">lazy fetch + replace objects disabled</tspan><tspan x="735" dy="22">names • URLs • repository IDs • branches</tspan><tspan x="735" dy="22">OIDs + prefixes • paths • component bytes</tspan><tspan x="735" dy="22">quoted/diff telemetry forms + supersets</tspan><tspan x="735" dy="22">private inputs + index state checked twice</tspan></text>
    <rect x="735" y="750" width="350" height="52" rx="9" fill="#111827" stroke="#64748b"/>
    <text class="mono" x="750" y="771"><tspan x="750">manifest: mode | path | bytes | git_oid</tspan><tspan x="750" dy="19">| independently computed blob_sha256</tspan></text>
  </g>

  <g aria-label="Audit written and staged last">
    <rect class="box audit" x="1150" y="565" width="400" height="225" rx="18"/>
    <text class="label" x="1175" y="596" fill="#f0abfc">07 • AUDIT LAST</text>
    <text class="boxTitle" x="1175" y="627">Receipt-derived seal state</text>
    <text class="body" x="1175" y="656"><tspan x="1175">audit excluded from manifest/count/blob scan</tspan><tspan x="1175" dy="22">PRE_AUDIT_SEAL_READY before audit write</tspan><tspan x="1175" dy="22">audit then staged as exact mode-100644 blob</tspan><tspan x="1175" dy="22">AUDIT_STAGED_FINAL only after repeated checks</tspan></text>
  </g>

  <path class="flow" d="M1335 516V525H190V580"/>
  <path id="seal-flow" class="flow" d="M330 677H370M680 677H710M1110 677H1150"/>
  <circle class="motion" cx="330" cy="677" r="5"><animateMotion dur="4.2s" repeatCount="indefinite" path="M0 0H820"/></circle>

  <g aria-label="Verification scopes">
    <rect class="box public" x="170" y="850" width="520" height="105" rx="18"/>
    <text class="label" x="195" y="880" fill="#67e8f9">PUBLIC CHECK</text>
    <text class="boxTitle" x="195" y="909">COMMITMENT_ONLY_NOT_VERIFIED</text>
    <text class="body" x="195" y="935">Regenerates public bytes; cannot inspect absent private evidence.</text>

    <rect class="box private" x="910" y="850" width="520" height="105" rx="18"/>
    <text class="label privateText" x="935" y="880">OWNER-LOCAL VERIFY-SEAL</text>
    <text class="boxTitle" x="935" y="909">AUDIT_STAGED_FINAL required</text>
    <text class="body privateText" x="935" y="935">Recomputes commitments, privacy scan, manifest, and exact audit stage.</text>
  </g>
  <path class="flow" d="M1290 790V830H430V850"/>
  <path class="flow privateFlow" d="M1410 790V830H1170V850"/>

  <g aria-label="Trusted computing base and authority boundary">
    <rect class="box guard" x="50" y="995" width="1500" height="70" rx="18"/>
    <text class="boxTitle" x="75" y="1024">LOCAL TCB</text>
    <text class="body" x="190" y="1024">pinned gh bytes • Git executable/index • Python runtime/stdlib • OS process, signal, clock, filesystem, and permissions</text>
    <text class="boxTitle" x="75" y="1050" fill="#fecdd3">AUTHORITY</text>
    <text class="body" x="190" y="1050" fill="#fecdd3">all authority fields false • inventory-only evidence • no integration qualification • no publication, deployment, tag, archive, DOI, or release • NO_GO</text>
  </g>
</svg>
""".encode("utf-8")


class InventoryError(RuntimeError):
    """One fail-closed inventory error whose code contains no source data."""


_GH_SIGNAL_OWNER_LOCK = threading.RLock()
_GH_SIGNAL_OWNER: Any = None
_EXTERNAL_SIGNAL_OWNER_LOCK = threading.RLock()
_EXTERNAL_SIGNAL_OWNER: Any = None
_EXTERNAL_ACTIVE_PROCESS: subprocess.Popen[bytes] | None = None
_PRODUCTION_CAPTURE_ORCHESTRATION_TOKEN = object()


def _fail(code: str) -> NoReturn:
    if re.fullmatch(r"[A-Z0-9_]+", code) is None:
        raise RuntimeError("unsafe inventory error code")
    raise InventoryError(code)


def _sanitized_search_path() -> str:
    raw = os.environ.get("PATH", os.defpath)
    if (
        not isinstance(raw, str)
        or len(raw.encode("utf-8", errors="ignore")) > 64 * 1024
    ):
        _fail("TOOL_SEARCH_PATH")
    retained: list[str] = []
    seen: set[str] = set()
    for component in raw.split(os.pathsep):
        if not component:
            continue
        candidate = Path(component)
        if not candidate.is_absolute():
            continue
        try:
            resolved = candidate.resolve(strict=True)
            metadata = resolved.stat()
        except OSError:
            continue
        rendered = str(resolved)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or rendered in seen
        ):
            continue
        retained.append(rendered)
        seen.add(rendered)
    if not retained:
        _fail("TOOL_SEARCH_PATH")
    return os.pathsep.join(retained)


def _resolve_safe_executable(
    name: str, *, sanitized_path: str, test_executable: str | None = None
) -> Path:
    candidate_text = test_executable or shutil.which(name, path=sanitized_path)
    if not candidate_text:
        _fail("TOOL_EXECUTABLE")
    candidate = Path(candidate_text)
    try:
        resolved = candidate.resolve(strict=True)
        metadata = resolved.stat()
    except OSError:
        _fail("TOOL_EXECUTABLE")
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        or metadata.st_uid not in {0, os.getuid()}
        or not 1 <= metadata.st_size <= MAX_EXECUTABLE_BYTES
        or not os.access(resolved, os.X_OK)
    ):
        _fail("TOOL_EXECUTABLE")
    return resolved


def canonical_json(value: Any) -> bytes:
    """Return canonical project JSON bytes."""

    try:
        rendered = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
    except (TypeError, ValueError):
        _fail("JSON_CANONICALIZATION")
    return (rendered + "\n").encode("utf-8")


def canonical_json_line(value: Any) -> bytes:
    """Return one compact canonical JSONL record."""

    try:
        rendered = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError):
        _fail("JSONL_CANONICALIZATION")
    return (rendered + "\n").encode("utf-8")


def canonical_jsonl(records: Sequence[dict[str, Any]]) -> bytes:
    return b"".join(canonical_json_line(record) for record in records)


def sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def utc_now() -> str:
    return (
        dt.datetime.now(dt.timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def _exact_keys(value: Any, expected: set[str], code: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        _fail(code)
    return value


def _positive_int(value: Any, code: str) -> int:
    if type(value) is not int or value <= 0:
        _fail(code)
    return value


def _bounded_int(value: Any, minimum: int, maximum: int, code: str) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        _fail(code)
    return value


def _exact_int(value: Any, expected: int, code: str) -> int:
    if type(value) is not int or value != expected:
        _fail(code)
    return value


def _digest(value: Any, code: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        _fail(code)
    return value


def _validate_authority(value: Any, code: str) -> dict[str, Any]:
    authority = _exact_keys(value, set(AUTHORITY), code)
    for key, expected in AUTHORITY.items():
        observed = authority[key]
        if type(expected) is bool:
            if type(observed) is not bool or observed is not expected:
                _fail(code)
        elif type(expected) is str:
            if not isinstance(observed, str) or observed != expected:
                _fail(code)
        else:  # pragma: no cover - the fixed authority schema has no other type
            _fail(code)
    return authority


def _exact_constant(value: Any, expected: Any, code: str) -> Any:
    if type(value) is not type(expected):
        _fail(code)
    if isinstance(expected, dict):
        if set(value) != set(expected):
            _fail(code)
        for key, expected_item in expected.items():
            _exact_constant(value[key], expected_item, code)
    elif isinstance(expected, list):
        if len(value) != len(expected):
            _fail(code)
        for observed_item, expected_item in zip(value, expected, strict=True):
            _exact_constant(observed_item, expected_item, code)
    elif value != expected:
        _fail(code)
    return value


def _text(
    value: Any,
    code: str,
    *,
    minimum: int = 1,
    maximum: int = MAX_TEXT_FIELD,
) -> str:
    if (
        not isinstance(value, str)
        or not minimum <= len(value) <= maximum
        or value != value.strip()
        or any(
            ord(character) < 0x20 or 0x7F <= ord(character) <= 0x9F
            for character in value
        )
    ):
        _fail(code)
    return value


def _optional_text(
    value: Any, code: str, *, maximum: int = MAX_TEXT_FIELD
) -> str | None:
    if value is None:
        return None
    return _text(value, code, maximum=maximum)


def _timestamp(value: Any, code: str) -> str:
    text = _text(value, code, maximum=64)
    if RFC3339_UTC.fullmatch(text) is None:
        _fail(code)
    try:
        parsed = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        _fail(code)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        _fail(code)
    return text


def _timestamp_instant(value: Any, code: str) -> tuple[str, dt.datetime]:
    text = _timestamp(value, code)
    try:
        parsed = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:  # pragma: no cover - _timestamp already validated this value
        _fail(code)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        _fail(code)
    return text, parsed


def _latest_timestamp(values: Sequence[Any], code: str) -> str:
    parsed = [_timestamp_instant(value, code) for value in values]
    if not parsed:
        _fail(code)
    return max(parsed, key=lambda item: item[1])[0]


def _review_date(
    value: Any,
    code: str,
    *,
    not_before: dt.date | None = None,
    not_after: dt.date | None = None,
) -> str:
    text = _text(value, code, maximum=10)
    try:
        parsed = dt.date.fromisoformat(text)
    except ValueError:
        _fail(code)
    boundary = not_after or dt.date.fromisoformat(MAINTAINED_REVIEW_DATE)
    if (
        parsed.isoformat() != text
        or (not_before is not None and parsed < not_before)
        or parsed > boundary
    ):
        _fail(code)
    return text


def _authored_text(value: Any, code: str, *, maximum: int, minimum: int = 1) -> str:
    text = _text(value, code, maximum=maximum)
    normalized = re.sub(r"[^a-z0-9]+", " ", text.casefold()).strip()
    marker_tokens = set(normalized.split())
    if (
        len(text.strip()) < minimum
        or re.search(r"(?<![a-z0-9])n\s*/\s*a(?![a-z0-9])", text.casefold()) is not None
        or marker_tokens & {"none", "pending", "tbd", "todo", "unknown", "unresolved"}
        or re.search(r"(?:^| )(?:t b d|to do)(?: |$)", normalized) is not None
        or "not applicable" in normalized
    ):
        _fail(code)
    return text


def _reviewed_authored_text(
    value: Any, code: str, *, maximum: int, minimum: int
) -> str:
    text = _authored_text(value, code, maximum=maximum, minimum=minimum)
    normalized = re.sub(r"[^a-z0-9]+", " ", text.casefold()).strip()
    tokens = set(normalized.split())
    contradiction_phrases = (
        "awaiting review",
        "classification assumed",
        "classification draft",
        "classification guessed",
        "classification incomplete",
        "later review",
        "needs review",
        "not reviewed",
        "pending review",
        "placeholder classification",
        "provisional classification",
        "review deferred",
        "review later",
        "assumed classification",
        "draft classification",
        "guessed classification",
        "incomplete classification",
        "classification is not final",
        "further review is required",
        "open for revision",
        "preliminary classification",
        "review is still required",
        "review was not completed",
        "subject to confirmation",
        "subject to review",
        "temporary classification",
        "yet to be reviewed",
    )
    contradiction_patterns = (
        r"\bclassification (?:is |was )?(?:assumed|guessed|incomplete)\b",
        r"\brequires review before (?:this )?classification\b",
        r"\breview (?:is )?still required before\b",
    )
    if (
        "unreviewed" in tokens
        or any(phrase in normalized for phrase in contradiction_phrases)
        or any(re.search(pattern, normalized) for pattern in contradiction_patterns)
    ):
        _fail(code)
    folded = text.casefold()
    if (
        "/" in text
        or "\\" in text
        or re.search(r"(?i)(?:file:|localhost|\$home)", text) is not None
        or re.search(
            r"(?i)\b[a-z0-9_.-]+\.(?:csv|js|json|jsonl|key|md|pem|py|rs|toml|ts|yaml|yml)\b",
            text,
        )
        is not None
        or any(marker in folded for marker in ("%2f", "%5c", "%252f", "%255c"))
    ):
        _fail(code)
    return text


def _bool(value: Any, code: str) -> bool:
    if type(value) is not bool:
        _fail(code)
    return value


def _read_bounded(
    path: Path,
    maximum: int,
    code: str,
    *,
    required_mode: int | None = None,
) -> bytes:
    descriptor: int | None = None
    try:
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_ISLNK(before.st_mode)
            or before.st_size > maximum
            or (
                required_mode is not None
                and (
                    stat.S_IMODE(before.st_mode) != required_mode
                    or before.st_nlink != 1
                )
            )
        ):
            _fail(code)
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0),
        )
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
            or opened.st_size != before.st_size
            or opened.st_mtime_ns != before.st_mtime_ns
            or opened.st_ctime_ns != before.st_ctime_ns
            or opened.st_mode != before.st_mode
            or opened.st_nlink != before.st_nlink
            or (
                required_mode is not None
                and (
                    stat.S_IMODE(opened.st_mode) != required_mode
                    or opened.st_nlink != 1
                )
            )
        ):
            _fail(code)
        chunks: list[bytes] = []
        observed = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, maximum + 1 - observed))
            if not chunk:
                break
            chunks.append(chunk)
            observed += len(chunk)
            if observed > maximum:
                _fail(code)
        payload = b"".join(chunks)
        after = os.fstat(descriptor)
        final_path = path.lstat()
        if (
            (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
                after.st_mode,
                after.st_nlink,
            )
            != (
                opened.st_dev,
                opened.st_ino,
                opened.st_size,
                opened.st_mtime_ns,
                opened.st_ctime_ns,
                opened.st_mode,
                opened.st_nlink,
            )
            or (
                final_path.st_dev,
                final_path.st_ino,
                final_path.st_size,
                final_path.st_mtime_ns,
                final_path.st_ctime_ns,
                final_path.st_mode,
                final_path.st_nlink,
            )
            != (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
                after.st_mode,
                after.st_nlink,
            )
            or not stat.S_ISREG(final_path.st_mode)
            or stat.S_ISLNK(final_path.st_mode)
            or len(payload) != opened.st_size
            or (
                required_mode is not None
                and (
                    stat.S_IMODE(after.st_mode) != required_mode
                    or after.st_nlink != 1
                    or stat.S_IMODE(final_path.st_mode) != required_mode
                    or final_path.st_nlink != 1
                )
            )
        ):
            _fail(code)
    except OSError:
        _fail(code)
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                _fail(code)
    return payload


def _atomic_write(path: Path, payload: bytes, *, private: bool) -> None:
    mode = 0o600 if private else 0o644
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists() or path.is_symlink():
            metadata = path.lstat()
            if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                _fail("OUTPUT_TARGET")
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=".ecosystem-inventory-", dir=path.parent
        )
        temporary = Path(temporary_name)
        try:
            os.fchmod(descriptor, mode)
            with os.fdopen(descriptor, "wb", closefd=True) as output:
                output.write(payload)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, path)
            os.chmod(path, mode, follow_symlinks=False)
            directory = os.open(
                path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
            )
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if temporary.exists():
                temporary.unlink()
    except InventoryError:
        raise
    except OSError:
        _fail("OUTPUT_WRITE")


def _require_private_mode(path: Path) -> None:
    try:
        metadata = path.lstat()
    except OSError:
        _fail("PRIVATE_MODE")
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_nlink != 1
    ):
        _fail("PRIVATE_MODE")


def _require_common_evidence_root(
    paths: Sequence[tuple[Path, str]],
    *,
    expected_root: Path | None = None,
) -> Path:
    if not paths:
        _fail("EVIDENCE_LAYOUT")
    if expected_root is not None and not isinstance(expected_root, Path):
        _fail("EVIDENCE_LAYOUT")
    if any(not isinstance(path, Path) for path, _basename in paths):
        _fail("EVIDENCE_LAYOUT")
    root = (
        expected_root.resolve(strict=False)
        if expected_root is not None
        else paths[0][0].parent.resolve(strict=False)
    )
    for path, basename in paths:
        if path.name != basename or path.parent.resolve(strict=False) != root:
            _fail("EVIDENCE_LAYOUT")
    return root


def _file_record(label: str, payload: bytes, *, classification: str) -> dict[str, Any]:
    return {
        "bytes": len(payload),
        "classification": classification,
        "label": label,
        "sha256": sha256(payload),
    }


def _validate_file_record(
    value: Any,
    *,
    label: str,
    classification: str,
    maximum_bytes: int,
    code: str,
) -> dict[str, Any]:
    record = _exact_keys(value, {"bytes", "classification", "label", "sha256"}, code)
    _bounded_int(record["bytes"], 1, maximum_bytes, code)
    _digest(record["sha256"], code)
    if record["label"] != label or record["classification"] != classification:
        _fail(code)
    return record


def _canonical_inventory_location(candidate: Path) -> tuple[Path, Path]:
    absolute = Path(os.path.abspath(candidate))
    try:
        metadata = absolute.lstat()
    except OSError:
        _fail("INVENTORY_SCRIPT_LOCATION")
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o644
        or metadata.st_nlink != 1
    ):
        _fail("INVENTORY_SCRIPT_LOCATION")
    for project_root in absolute.parents:
        marker = project_root / ".git"
        try:
            marker_metadata = marker.lstat()
        except OSError:
            continue
        if stat.S_ISLNK(marker_metadata.st_mode) or not (
            stat.S_ISDIR(marker_metadata.st_mode)
            or stat.S_ISREG(marker_metadata.st_mode)
        ):
            _fail("INVENTORY_SCRIPT_LOCATION")
        expected = project_root / Path(CANONICAL_INVENTORY_SCRIPT_PATH)
        if absolute != expected:
            _fail("INVENTORY_SCRIPT_LOCATION")
        return project_root, absolute
    _fail("INVENTORY_SCRIPT_LOCATION")


def _inventory_script_payload() -> bytes:
    _project_root, script = _canonical_inventory_location(Path(__file__))
    return _read_bounded(
        script,
        MAX_JSON_BYTES,
        "INVENTORY_SCRIPT",
        required_mode=0o644,
    )


def _inventory_script_record() -> dict[str, Any]:
    payload = _inventory_script_payload()
    return _file_record(
        "ecosystem_source_inventory.py",
        payload,
        classification="PUBLIC_TOOL_SOURCE",
    )


def _production_maintained_artifact_payloads() -> dict[Path, bytes]:
    project_root, script = _canonical_inventory_location(Path(__file__))
    diagram = project_root / Path(CANONICAL_DIAGRAM_PATH)
    expected_diagram = ecosystem_source_inventory_svg()
    observed_diagram = _read_bounded(
        diagram,
        MAX_JSON_BYTES,
        "DIAGRAM_READ",
        required_mode=0o644,
    )
    if observed_diagram != expected_diagram:
        _fail("DIAGRAM_DRIFT")
    return {
        script: _inventory_script_payload(),
        diagram: observed_diagram,
    }


def _python_runtime_record() -> dict[str, str]:
    return {
        "implementation": _text(
            platform.python_implementation(), "PYTHON_IMPLEMENTATION", maximum=64
        ),
        "version": _text(platform.python_version(), "PYTHON_VERSION", maximum=64),
    }


def _capture_invocation_document(capture: dict[str, Any]) -> dict[str, Any]:
    return {
        "closure_profile": capture["closure_profile"],
        "credential_binding": capture["credential_binding"],
        "executable_binding": capture["executable_binding"],
        "expected_repository_counts": capture["expected_repository_counts"],
        "gh_environment_binding": capture["gh_environment_binding"],
        "inventory_script": capture["inventory_script"],
        "maximum_get_attempts": capture["maximum_get_attempts"],
        "maximum_head_workers": capture["maximum_head_workers"],
        "maximum_pages": capture["maximum_pages"],
        "minimum_rate_reserve": capture["minimum_rate_reserve"],
        "output_labels": capture["output_labels"],
        "owner": capture["owner"],
        "python_runtime": capture["python_runtime"],
        "request_timeout_seconds": capture["request_timeout_seconds"],
        "tool_api_request_contract": capture["tool_api_request_contract"],
        "tool": capture["tool"],
    }


def _load_json(
    path: Path, *, maximum: int = MAX_JSON_BYTES, private: bool = False
) -> tuple[Any, bytes]:
    payload = _read_bounded(
        path, maximum, "JSON_READ", required_mode=(0o600 if private else None)
    )
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError):
        _fail("JSON_PARSE")
    if canonical_json(value) != payload:
        _fail("JSON_NOT_CANONICAL")
    return value, payload


def _load_jsonl(
    path: Path, *, maximum: int = MAX_JSON_BYTES, private: bool = False
) -> tuple[list[Any], bytes]:
    payload = _read_bounded(
        path, maximum, "JSONL_READ", required_mode=(0o600 if private else None)
    )
    if not payload or not payload.endswith(b"\n"):
        _fail("JSONL_SHAPE")
    records: list[Any] = []
    for line in payload.splitlines(keepends=True):
        if len(line) > MAX_JSONL_LINE_BYTES:
            _fail("JSONL_LINE_BOUND")
        try:
            value = json.loads(line)
        except (UnicodeDecodeError, json.JSONDecodeError):
            _fail("JSONL_PARSE")
        if canonical_json_line(value) != line:
            _fail("JSONL_NOT_CANONICAL")
        records.append(value)
        if len(records) > MAX_REPOSITORIES * 4:
            _fail("JSONL_ROW_BOUND")
    return records, payload


class RestClient(Protocol):
    identity: dict[str, Any]
    head_workers: int
    timeout_seconds: int
    credential_binding: dict[str, Any]
    environment_binding: dict[str, Any]
    executable_binding: dict[str, Any]

    def get(
        self, endpoint: str, *, allow_empty_repository: bool = False
    ) -> tuple[Any, dict[str, Any]]: ...

    def verify_pins(self) -> None: ...


def _required_keys(value: Any, required: set[str], code: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not required.issubset(value):
        _fail(code)
    return value


def _parse_rate_headers(headers: dict[str, str]) -> dict[str, Any]:
    remaining_text = headers.get("x-ratelimit-remaining")
    reset_text = headers.get("x-ratelimit-reset")
    if (
        remaining_text is None
        or reset_text is None
        or re.fullmatch(r"[0-9]+", remaining_text) is None
        or re.fullmatch(r"[0-9]+", reset_text) is None
    ):
        _fail("RATE_HEADERS")
    remaining = _bounded_int(int(remaining_text), 0, 100_000, "RATE_REMAINING")
    reset_epoch = _bounded_int(int(reset_text), 1, 4_102_444_800, "RATE_RESET")
    reset_at = (
        dt.datetime.fromtimestamp(reset_epoch, dt.timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )
    return {"remaining": remaining, "reset_at_utc": reset_at}


def _rate(value: Any, minimum_remaining: int) -> dict[str, Any]:
    record = _exact_keys(value, {"attempts", "remaining", "reset_at_utc"}, "RATE_SHAPE")
    attempts = _bounded_int(record["attempts"], 1, MAX_GET_ATTEMPTS, "RATE_ATTEMPTS")
    remaining = _bounded_int(record["remaining"], 0, 100_000, "RATE_REMAINING")
    reset_at = _timestamp(record["reset_at_utc"], "RATE_RESET")
    if remaining < minimum_remaining:
        _fail("RATE_RESERVE")
    return {"attempts": attempts, "remaining": remaining, "reset_at_utc": reset_at}


class GhClient:
    """Bounded adapter that requests ``gh api --method GET`` operations."""

    def __init__(
        self,
        *,
        timeout_seconds: int = 60,
        head_workers: int = MAX_HEAD_WORKERS_DEFAULT,
        _test_executable: str | None = None,
    ):
        self._sanitized_path = _sanitized_search_path()
        resolved = _resolve_safe_executable(
            "gh",
            sanitized_path=self._sanitized_path,
            test_executable=_test_executable,
        )
        metadata = resolved.stat()
        self.timeout_seconds = _bounded_int(timeout_seconds, 1, 300, "GH_TIMEOUT")
        self.head_workers = _bounded_int(head_workers, 1, 16, "HEAD_WORKERS")
        self._temporary_directory: tempfile.TemporaryDirectory[str] | None = None
        self._active_processes: set[subprocess.Popen[bytes]] = set()
        self._process_lock = threading.RLock()
        self._shutdown_requested = False
        self._previous_signal_handlers: dict[int, Any] = {}
        self._signal_handler_callback: Any = None
        try:
            self._install_signal_guards()
            original_payload = _read_bounded(
                resolved, MAX_EXECUTABLE_BYTES, "GH_EXECUTABLE"
            )
            if len(original_payload) != metadata.st_size:
                _fail("GH_EXECUTABLE")
            self._temporary_directory = tempfile.TemporaryDirectory(
                prefix="haldir-gh-pin-"
            )
            temporary_root = Path(self._temporary_directory.name)
            temporary_metadata = temporary_root.lstat()
            if (
                not stat.S_ISDIR(temporary_metadata.st_mode)
                or stat.S_ISLNK(temporary_metadata.st_mode)
                or stat.S_IMODE(temporary_metadata.st_mode) != 0o700
            ):
                _fail("GH_EXECUTABLE_COPY")
            self._temporary_root = temporary_root
            self._executable_directory = temporary_root / "executable"
            self._executable_directory.mkdir(mode=0o700)
            self.executable = self._executable_directory / "gh"
            self._write_executable_copy(self.executable, original_payload)
            self._executable_directory.chmod(0o500)
            self._executable_directory_pin = self._metadata_pin(
                self._executable_directory.lstat()
            )
            self._executable_file_pin = self._metadata_pin(self.executable.lstat())
            self._executable_payload_sha256 = sha256(original_payload)
            self._executable_payload_bytes = len(original_payload)
            self._credential_token: str | None = None
            self._environment = self._base_environment(self._sanitized_path)
            self.identity = self._tool_identity()
            token_payload, token_status = self._run(
                ("auth", "token", "--hostname", API_HOST),
                stdout_limit=MAX_TOKEN_BYTES,
            )
            if token_status != 0:
                _fail("GH_AUTH_TOKEN")
            try:
                token = token_payload.decode("ascii")
            except UnicodeDecodeError:
                _fail("GH_AUTH_TOKEN")
            token = token.removesuffix("\n")
            if token.endswith("\r"):
                token = token[:-1]
            if (
                not token
                or len(token) > MAX_TOKEN_BYTES
                or any(not 0x21 <= ord(character) <= 0x7E for character in token)
            ):
                _fail("GH_AUTH_TOKEN")
            self._credential_token = token
            self._api_config_directory = temporary_root / "api-config"
            self._api_config_directory.mkdir(mode=0o700)
            self._environment = self._api_environment(token, self._api_config_directory)
            self.credential_binding = dict(CREDENTIAL_BINDING)
            self.environment_binding = dict(GH_ENVIRONMENT_BINDING)
            self.executable_binding = {
                "bytes": self._executable_payload_bytes,
                "method": EXECUTABLE_BINDING_METHOD,
                "mode": "0500",
                "sha256": self._executable_payload_sha256,
            }
            self.verify_pins()
        except BaseException:
            self.close()
            raise

    @staticmethod
    def _base_environment(sanitized_path: str) -> dict[str, str]:
        environment = {
            key: value
            for key, value in os.environ.items()
            if key in GH_AUTH_ENVIRONMENT_ALLOWLIST
            and key not in GH_AMBIENT_ENVIRONMENT_KEYS
            and key != "PATH"
        }
        environment.update(GH_FIXED_ENVIRONMENT)
        environment["PATH"] = sanitized_path
        return environment

    @staticmethod
    def _api_environment(token: str, config_directory: Path) -> dict[str, str]:
        environment = {
            key: value
            for key, value in os.environ.items()
            if key in GH_API_AMBIENT_ALLOWLIST
        }
        environment.update(GH_FIXED_ENVIRONMENT)
        environment["GH_CONFIG_DIR"] = str(config_directory)
        environment["GH_TOKEN"] = token
        return environment

    def _install_signal_guards(self) -> None:
        global _GH_SIGNAL_OWNER
        if threading.current_thread() is not threading.main_thread():
            _fail("GH_SIGNAL_GUARD")
        with _GH_SIGNAL_OWNER_LOCK:
            if _GH_SIGNAL_OWNER is not None or _EXTERNAL_SIGNAL_OWNER is not None:
                _fail("GH_SIGNAL_GUARD")
            guarded = [signal.SIGINT, signal.SIGTERM]
            if hasattr(signal, "SIGHUP"):
                guarded.append(signal.SIGHUP)
            self._guarded_signals = frozenset(guarded)
            self._signal_handler_callback = self._handle_signal
            _GH_SIGNAL_OWNER = self
            try:
                for signum in self._guarded_signals:
                    self._previous_signal_handlers[signum] = signal.getsignal(signum)
                    signal.signal(signum, self._signal_handler_callback)
            except (OSError, ValueError):
                for signum, handler in self._previous_signal_handlers.items():
                    try:
                        signal.signal(signum, handler)
                    except (OSError, ValueError):
                        pass
                self._previous_signal_handlers.clear()
                _GH_SIGNAL_OWNER = None
                _fail("GH_SIGNAL_GUARD")

    def _handle_signal(self, signum: int, _frame: Any) -> NoReturn:
        # Set the admission latch before waiting for the process lock. A queued
        # worker can otherwise acquire the lock ahead of the signal handler.
        self._shutdown_requested = True
        self._kill_active_processes(best_effort=True)
        if signum == signal.SIGINT:
            raise KeyboardInterrupt
        raise SystemExit(128 + signum)

    def _kill_active_processes(self, *, best_effort: bool) -> None:
        lock = getattr(self, "_process_lock", None)
        active = getattr(self, "_active_processes", None)
        if lock is None or active is None:
            return
        with lock:
            processes = list(active)
        for process in processes:
            try:
                self._kill_and_reap(process)
            except BaseException:
                if not best_effort:
                    raise

    def _restore_signal_guards(self) -> None:
        global _GH_SIGNAL_OWNER
        previous = getattr(self, "_previous_signal_handlers", {})
        callback = getattr(self, "_signal_handler_callback", None)
        if (
            not previous
            or callback is None
            or threading.current_thread() is not threading.main_thread()
        ):
            return
        mismatch = False
        with _GH_SIGNAL_OWNER_LOCK:
            if _GH_SIGNAL_OWNER is not self:
                _fail("GH_SIGNAL_GUARD")
            try:
                for signum, handler in previous.items():
                    if signal.getsignal(signum) != callback:
                        mismatch = True
                        continue
                    signal.signal(signum, handler)
            except (OSError, ValueError):
                mismatch = True
            finally:
                previous.clear()
                _GH_SIGNAL_OWNER = None
        if mismatch:
            _fail("GH_SIGNAL_GUARD")

    @staticmethod
    def _write_executable_copy(path: Path, payload: bytes) -> None:
        descriptor: int | None = None
        try:
            descriptor = os.open(
                path,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                0o500,
            )
            offset = 0
            while offset < len(payload):
                written = os.write(descriptor, payload[offset:])
                if written <= 0:
                    _fail("GH_EXECUTABLE_COPY")
                offset += written
            os.fsync(descriptor)
            os.fchmod(descriptor, 0o500)
        except InventoryError:
            raise
        except OSError:
            _fail("GH_EXECUTABLE_COPY")
        finally:
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    _fail("GH_EXECUTABLE_COPY")
        observed = _read_bounded(
            path,
            MAX_EXECUTABLE_BYTES,
            "GH_EXECUTABLE_COPY",
            required_mode=0o500,
        )
        if observed != payload or not os.access(path, os.X_OK):
            _fail("GH_EXECUTABLE_COPY")

    @staticmethod
    def _metadata_pin(metadata: os.stat_result) -> tuple[int, ...]:
        return (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_mode,
            metadata.st_nlink,
            metadata.st_uid,
            metadata.st_gid,
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
        )

    def _verify_api_config_directory(self) -> None:
        path = getattr(self, "_api_config_directory", None)
        if not isinstance(path, Path):
            return
        try:
            metadata = path.lstat()
            entries = list(path.iterdir())
        except OSError:
            _fail("GH_API_CONFIG")
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o700
            or entries
        ):
            _fail("GH_API_CONFIG")

    def _verify_executable_directory(self) -> None:
        path = self._executable_directory
        try:
            metadata = path.lstat()
            entries = list(path.iterdir())
        except OSError:
            _fail("GH_EXECUTABLE_PIN")
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o500
            or entries != [self.executable]
            or self._metadata_pin(metadata) != self._executable_directory_pin
        ):
            _fail("GH_EXECUTABLE_PIN")

    def _open_verified_executable(self) -> int:
        descriptor: int | None = None
        try:
            self._verify_executable_directory()
            descriptor = os.open(
                self.executable,
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
            )
            opened = os.fstat(descriptor)
            if (
                not stat.S_ISREG(opened.st_mode)
                or stat.S_IMODE(opened.st_mode) != 0o500
                or opened.st_nlink != 1
                or opened.st_size != self._executable_payload_bytes
            ):
                _fail("GH_EXECUTABLE_PIN")
            chunks: list[bytes] = []
            observed = 0
            while True:
                chunk = os.read(
                    descriptor,
                    min(
                        1024 * 1024,
                        self._executable_payload_bytes + 1 - observed,
                    ),
                )
                if not chunk:
                    break
                chunks.append(chunk)
                observed += len(chunk)
                if observed > self._executable_payload_bytes:
                    _fail("GH_EXECUTABLE_PIN")
            after = os.fstat(descriptor)
            final_path = self.executable.lstat()
            if (
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                != (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
                or (final_path.st_dev, final_path.st_ino)
                != (after.st_dev, after.st_ino)
                or self._metadata_pin(final_path) != self._executable_file_pin
                or self._metadata_pin(after) != self._executable_file_pin
                or stat.S_IMODE(final_path.st_mode) != 0o500
                or final_path.st_nlink != 1
                or observed != self._executable_payload_bytes
                or sha256(b"".join(chunks)) != self._executable_payload_sha256
            ):
                _fail("GH_EXECUTABLE_PIN")
            os.lseek(descriptor, 0, os.SEEK_SET)
            return descriptor
        except InventoryError:
            raise
        except OSError:
            _fail("GH_EXECUTABLE_PIN")
        finally:
            if descriptor is not None and sys.exc_info()[0] is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        _fail("GH_EXECUTABLE_PIN")  # pragma: no cover - fail-closed control guard

    def close(self) -> None:
        self._shutdown_requested = True
        lock = getattr(self, "_process_lock", None)
        if lock is not None:
            with lock:
                pass
        self._kill_active_processes(best_effort=True)
        environment = getattr(self, "_environment", None)
        if isinstance(environment, dict):
            environment.pop("GH_TOKEN", None)
        if hasattr(self, "_credential_token"):
            self._credential_token = None
        self._restore_signal_guards()
        temporary = getattr(self, "_temporary_directory", None)
        if temporary is not None:
            self._temporary_directory = None
            executable_directory = getattr(self, "_executable_directory", None)
            if isinstance(executable_directory, Path):
                try:
                    executable_directory.chmod(0o700)
                except OSError:
                    pass
            temporary.cleanup()

    def __del__(self) -> None:  # pragma: no cover - best-effort interpreter cleanup
        try:
            self.close()
        except Exception:
            pass

    @staticmethod
    def _kill_and_reap(process: subprocess.Popen[bytes]) -> None:
        try:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except OSError:
                try:
                    process.kill()
                except OSError:
                    pass
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                try:
                    process.kill()
                except OSError:
                    pass
                process.wait(timeout=10)
        except (OSError, subprocess.SubprocessError):
            _fail("GH_PROCESS_CLEANUP")

    def _run(
        self,
        arguments: Sequence[str],
        *,
        stdout_limit: int,
        allowed_return_codes: frozenset[int] = frozenset({0}),
    ) -> tuple[bytes, int]:
        stdout_limit = _bounded_int(
            stdout_limit, 1, MAX_API_RESPONSE_BYTES, "GH_OUTPUT_BOUND"
        )
        process: subprocess.Popen[bytes] | None = None
        executable_descriptor: int | None = None
        selector = selectors.DefaultSelector()
        stdout_payload = bytearray()
        stderr_payload = bytearray()
        try:
            self._verify_api_config_directory()
            executable_descriptor = self._open_verified_executable()
            guarded_signals = getattr(self, "_guarded_signals", frozenset())
            try:
                previous_mask = signal.pthread_sigmask(
                    signal.SIG_BLOCK, guarded_signals
                )
            except (AttributeError, OSError, ValueError):
                _fail("GH_SIGNAL_GUARD")
            try:
                with self._process_lock:
                    if getattr(self, "_shutdown_requested", False):
                        _fail("GH_SHUTDOWN")
                    process = subprocess.Popen(
                        (str(self.executable), *arguments),
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        env=dict(self._environment),
                        start_new_session=True,
                    )
                    self._active_processes.add(process)
                    opened = os.fstat(executable_descriptor)
                    executed_path = self.executable.lstat()
                    self._verify_executable_directory()
                    if (opened.st_dev, opened.st_ino) != (
                        executed_path.st_dev,
                        executed_path.st_ino,
                    ):
                        self._kill_and_reap(process)
                        _fail("GH_EXECUTABLE_PIN")
            finally:
                signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
            os.close(executable_descriptor)
            executable_descriptor = None
            if process.stdout is None or process.stderr is None:
                _fail("GH_COMMAND")
            for stream, label in (
                (process.stdout, "stdout"),
                (process.stderr, "stderr"),
            ):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, label)
            deadline = time.monotonic() + self.timeout_seconds
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    self._kill_and_reap(process)
                    _fail("GH_TIMEOUT")
                events = selector.select(min(remaining, 0.1))
                if not events and process.poll() is not None:
                    events = [
                        (key, selectors.EVENT_READ)
                        for key in list(selector.get_map().values())
                    ]
                for key, _mask in events:
                    stream = key.fileobj
                    try:
                        chunk = os.read(stream.fileno(), 64 * 1024)
                    except BlockingIOError:
                        continue
                    if not chunk:
                        selector.unregister(stream)
                        continue
                    target = stdout_payload if key.data == "stdout" else stderr_payload
                    target.extend(chunk)
                    limit = (
                        stdout_limit if key.data == "stdout" else MAX_API_STDERR_BYTES
                    )
                    if len(target) > limit:
                        self._kill_and_reap(process)
                        _fail(
                            "GH_OUTPUT_BOUND"
                            if key.data == "stdout"
                            else "GH_STDERR_BOUND"
                        )
            remaining = deadline - time.monotonic()
            if remaining <= 0 and process.poll() is None:
                self._kill_and_reap(process)
                _fail("GH_TIMEOUT")
            return_code = process.wait(timeout=max(remaining, 0.001))
            self._kill_and_reap(process)
            if return_code not in allowed_return_codes:
                _fail("GH_COMMAND")
            self._verify_api_config_directory()
            return bytes(stdout_payload), return_code
        except InventoryError:
            if process is not None:
                self._kill_and_reap(process)
            raise
        except subprocess.TimeoutExpired:
            if process is not None:
                self._kill_and_reap(process)
            _fail("GH_TIMEOUT")
        except (OSError, subprocess.SubprocessError):
            if process is not None:
                self._kill_and_reap(process)
            _fail("GH_COMMAND")
        except BaseException:
            if process is not None:
                self._kill_and_reap(process)
            raise
        finally:
            selector.close()
            if executable_descriptor is not None:
                try:
                    os.close(executable_descriptor)
                except OSError:
                    pass
            if process is not None:
                with self._process_lock:
                    self._active_processes.discard(process)
                for stream in (process.stdout, process.stderr):
                    if stream is not None:
                        stream.close()

    def _tool_identity(self) -> dict[str, Any]:
        version, return_code = self._run(("--version",), stdout_limit=4096)
        if return_code != 0:
            _fail("GH_VERSION")
        try:
            first_line = version.decode("utf-8").splitlines()[0]
        except (UnicodeDecodeError, IndexError):
            _fail("GH_VERSION")
        if not first_line.startswith("gh version "):
            _fail("GH_VERSION")
        return {
            "bytes": self._executable_payload_bytes,
            "name": "gh",
            "sha256": self._executable_payload_sha256,
            "version": _text(first_line, "GH_VERSION", maximum=256),
        }

    def verify_pins(self) -> None:
        descriptor = self._open_verified_executable()
        try:
            os.close(descriptor)
        except OSError:
            _fail("GH_EXECUTABLE_PIN")
        self._verify_api_config_directory()
        expected_environment_keys = {
            *GH_FIXED_ENVIRONMENT,
            "GH_CONFIG_DIR",
            "GH_TOKEN",
            *(key for key in GH_API_AMBIENT_ALLOWLIST if key in os.environ),
        }
        if (
            self._credential_token is None
            or self._environment.get("GH_TOKEN") != self._credential_token
            or self._environment.get("GH_CONFIG_DIR") != str(self._api_config_directory)
            or set(self._environment) != expected_environment_keys
            or any(
                self._environment.get(key) != value
                for key, value in GH_FIXED_ENVIRONMENT.items()
            )
            or self.environment_binding != GH_ENVIRONMENT_BINDING
        ):
            _fail("GH_PIN_MISMATCH")

    def get(
        self, endpoint: str, *, allow_empty_repository: bool = False
    ) -> tuple[Any, dict[str, Any]]:
        if (
            not isinstance(endpoint, str)
            or not endpoint.startswith("/")
            or len(endpoint) > 2_048
            or "://" in endpoint
            or any(ord(character) < 0x20 for character in endpoint)
        ):
            _fail("GH_ENDPOINT")
        arguments = (
            "api",
            "--hostname",
            API_HOST,
            "--method",
            "GET",
            "--header",
            "Accept: application/vnd.github+json",
            "--header",
            f"X-GitHub-Api-Version: {API_VERSION}",
            "--include",
            endpoint,
        )
        payload = b""
        return_code = -1
        separator = b""
        attempts = 0
        for attempts in range(1, MAX_GET_ATTEMPTS + 1):
            payload, return_code = self._run(
                arguments,
                stdout_limit=MAX_API_RESPONSE_BYTES,
                allowed_return_codes=frozenset({0, 1}),
            )
            separator = b"\r\n\r\n" if b"\r\n\r\n" in payload else b"\n\n"
            if separator in payload:
                break
            if return_code != 1 or attempts == MAX_GET_ATTEMPTS:
                _fail("GH_HTTP_HEADERS")
            time.sleep(0.25 * attempts)
        header_payload, body = payload.split(separator, 1)
        try:
            lines = header_payload.decode("ascii").replace("\r\n", "\n").splitlines()
        except UnicodeDecodeError:
            _fail("GH_HTTP_HEADERS")
        if not lines:
            _fail("GH_HTTP_HEADERS")
        status = re.fullmatch(r"HTTP/\S+ ([0-9]{3})(?: .*)?", lines[0])
        if status is None:
            _fail("GH_HTTP_STATUS")
        status_code = int(status.group(1))
        headers: dict[str, str] = {}
        for line in lines[1:]:
            if ":" not in line:
                _fail("GH_HTTP_HEADERS")
            name, value = line.split(":", 1)
            normalized_name = name.strip().lower()
            normalized_value = value.strip()
            if not normalized_name or normalized_name in headers:
                _fail("GH_HTTP_HEADERS")
            headers[normalized_name] = normalized_value
        try:
            value = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError):
            _fail("GH_JSON")
        rate = {**_parse_rate_headers(headers), "attempts": attempts}
        if status_code == 200 and return_code == 0:
            return value, rate
        if (
            allow_empty_repository
            and status_code == 409
            and return_code == 1
            and isinstance(value, dict)
            and value.get("message") == "Git Repository is empty."
        ):
            return None, rate
        _fail("GH_HTTP_STATUS")


def _identity_record(value: Any, code: str) -> dict[str, Any]:
    record = _required_keys(value, {"id", "node_id", "login", "type"}, code)
    if record["type"] != "User":
        _fail(code)
    return {
        "account_id": _positive_int(record["id"], code),
        "login": _text(record["login"], code, maximum=128),
        "node_id": _text(record["node_id"], code, maximum=256),
    }


def verify_identity(
    client: RestClient,
    owner: str,
    *,
    minimum_remaining: int,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})", owner) is None:
        _fail("OWNER_LOGIN")
    repository_owner_raw, owner_rate_raw = client.get(f"/users/{quote(owner, safe='')}")
    owner_rate = _rate(owner_rate_raw, minimum_remaining + MAX_GET_ATTEMPTS)
    viewer_raw, viewer_rate_raw = client.get("/user")
    repository_owner = _identity_record(repository_owner_raw, "OWNER_IDENTITY")
    viewer = _identity_record(viewer_raw, "VIEWER_IDENTITY")
    if repository_owner["login"] != owner or viewer != repository_owner:
        _fail("VIEWER_OWNER_MISMATCH")
    return repository_owner, [
        owner_rate,
        _rate(viewer_rate_raw, minimum_remaining),
    ]


def _repository_owner(value: Any, owner: dict[str, Any]) -> None:
    record = _required_keys(value, {"id", "node_id", "login", "type"}, "PAGE_OWNER")
    observed = _identity_record(record, "PAGE_OWNER")
    if observed != owner:
        _fail("PAGE_OWNER_MISMATCH")


def normalize_repository_metadata(
    value: Any,
    *,
    owner: dict[str, Any],
    public_output: bool,
) -> tuple[dict[str, Any], str | None]:
    record = _required_keys(
        value,
        {
            "archived",
            "default_branch",
            "fork",
            "full_name",
            "html_url",
            "id",
            "language",
            "license",
            "owner",
            "private",
            "pushed_at",
            "updated_at",
            "visibility",
        },
        "REPOSITORY_SHAPE",
    )
    _repository_owner(record["owner"], owner)
    repository = _text(record["full_name"], "REPOSITORY_NAME", maximum=256)
    if REPOSITORY.fullmatch(repository) is None:
        _fail("REPOSITORY_NAME")
    repository_owner, _separator, _name = repository.partition("/")
    if repository_owner != owner["login"]:
        _fail("REPOSITORY_OWNER")
    url = _text(record["html_url"], "REPOSITORY_URL", maximum=512)
    if url != f"https://github.com/{repository}":
        _fail("REPOSITORY_URL")
    raw_visibility = _text(record["visibility"], "REPOSITORY_VISIBILITY", maximum=16)
    if raw_visibility not in {"public", "private"}:
        _fail("REPOSITORY_VISIBILITY")
    visibility = raw_visibility.upper()
    is_private = _bool(record["private"], "REPOSITORY_PRIVATE")
    if is_private != (visibility == "PRIVATE"):
        _fail("REPOSITORY_VISIBILITY")
    if public_output and visibility != "PUBLIC":
        _fail("PUBLIC_CAPTURE_VISIBILITY")
    license_info = record["license"]
    if license_info is None:
        license_name = None
    else:
        license_record = _required_keys(license_info, {"spdx_id"}, "LICENSE_SHAPE")
        license_name = _optional_text(license_record["spdx_id"], "LICENSE", maximum=128)
    default_branch = _optional_text(
        record["default_branch"], "DEFAULT_BRANCH_NAME", maximum=256
    )
    return (
        {
            "archived": _bool(record["archived"], "REPOSITORY_ARCHIVED"),
            "canonical_url": url,
            "default_branch": None,
            "exact_head": None,
            "fork": _bool(record["fork"], "REPOSITORY_FORK"),
            "head_state": "EMPTY_REPOSITORY",
            "language": _optional_text(record["language"], "LANGUAGE", maximum=128),
            "license": license_name,
            "owner": owner["login"],
            "owner_id": owner["account_id"],
            "parent": None,
            "pushed_at": (
                None
                if record["pushed_at"] is None
                else _timestamp(record["pushed_at"], "PUSHED_AT")
            ),
            "repository": repository,
            "repository_id": _positive_int(record["id"], "REPOSITORY_ID"),
            "schema_version": SCHEMA_VERSION,
            "updated_at": _timestamp(record["updated_at"], "UPDATED_AT"),
            "visibility": visibility,
        },
        default_branch,
    )


def resolve_exact_head(
    client: RestClient,
    record: dict[str, Any],
    default_branch: str | None,
    *,
    minimum_remaining: int,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    encoded_repository = quote(record["repository"], safe="/")
    if default_branch is None:
        result = dict(record)
        result.update(
            {
                "default_branch": None,
                "exact_head": None,
                "head_state": "EMPTY_REPOSITORY",
            }
        )
        return result, []
    encoded_branch = quote(default_branch, safe="")
    ref_raw, ref_rate_raw = client.get(
        f"/repos/{encoded_repository}/git/ref/heads/{encoded_branch}",
        allow_empty_repository=True,
    )
    ref_rate = _rate(ref_rate_raw, minimum_remaining)
    if ref_raw is None:
        result = dict(record)
        result.update(
            {
                "default_branch": None,
                "exact_head": None,
                "head_state": "EMPTY_REPOSITORY",
            }
        )
        return result, [ref_rate]
    ref = _required_keys(ref_raw, {"ref", "object"}, "DEFAULT_REF")
    if ref["ref"] != f"refs/heads/{default_branch}":
        _fail("DEFAULT_REF_NAME")
    target = _required_keys(ref["object"], {"sha", "type"}, "DEFAULT_HEAD")
    exact_head = _text(target["sha"], "DEFAULT_HEAD_OID", maximum=40)
    if target["type"] != "commit" or HEX40.fullmatch(exact_head) is None:
        _fail("DEFAULT_HEAD_OID")
    result = dict(record)
    result.update(
        {
            "default_branch": default_branch,
            "exact_head": exact_head,
            "head_state": "COMMIT",
        }
    )
    return result, [ref_rate]


def collect_snapshot(
    client: RestClient,
    *,
    scope: str,
    owner: dict[str, Any],
    minimum_remaining: int,
    maximum_pages: int,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if scope not in {"PUBLIC", "OWNER_VISIBLE"}:
        _fail("SNAPSHOT_SCOPE")
    maximum_pages = _bounded_int(maximum_pages, 1, 100, "PAGE_LIMIT")
    records: list[dict[str, Any]] = []
    rates: list[dict[str, Any]] = []
    requests = 0
    page = 0
    while True:
        page += 1
        if page > maximum_pages:
            _fail("PAGE_LIMIT")
        if scope == "PUBLIC":
            endpoint = PUBLIC_ENDPOINT_TEMPLATE.format(
                owner=quote(owner["login"], safe=""), page=page
            )
        else:
            endpoint = OWNER_ENDPOINT_TEMPLATE.format(page=page)
        page_raw, page_rate_raw = client.get(endpoint)
        page_rate = _rate(page_rate_raw, minimum_remaining)
        requests += page_rate["attempts"]
        rates.append(page_rate)
        if not isinstance(page_raw, list) or len(page_raw) > MAX_PAGE_NODES:
            _fail("PAGE_NODES")
        pending: list[tuple[dict[str, Any], str | None]] = []
        for item in page_raw:
            metadata, default_branch = normalize_repository_metadata(
                item,
                owner=owner,
                public_output=(scope == "PUBLIC"),
            )
            pending.append((metadata, default_branch))
        required_head_requests = sum(
            1 for _metadata, default_branch in pending if default_branch is not None
        )
        required_next_page_request = 1 if len(page_raw) == MAX_PAGE_NODES else 0
        if page_rate["remaining"] < (
            minimum_remaining
            + MAX_GET_ATTEMPTS * (required_head_requests + required_next_page_request)
        ):
            _fail("RATE_PAGE_BUDGET")

        def resolve_pending(
            pending_record: tuple[dict[str, Any], str | None],
        ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
            metadata, default_branch = pending_record
            return resolve_exact_head(
                client,
                metadata,
                default_branch,
                minimum_remaining=minimum_remaining,
            )

        head_workers = _bounded_int(client.head_workers, 1, 16, "HEAD_WORKERS")
        if head_workers == 1 or len(pending) <= 1:
            resolved_page = [resolve_pending(item) for item in pending]
        else:
            executor = concurrent.futures.ThreadPoolExecutor(
                max_workers=min(head_workers, len(pending)),
                thread_name_prefix="ecosystem-head-get",
            )
            futures = [executor.submit(resolve_pending, item) for item in pending]
            try:
                resolved_page = [future.result() for future in futures]
            except BaseException:
                for future in futures:
                    future.cancel()
                executor.shutdown(wait=True, cancel_futures=True)
                raise
            else:
                executor.shutdown(wait=True, cancel_futures=True)
        for normalized, head_rates in resolved_page:
            records.append(normalized)
            rates.extend(head_rates)
            requests += sum(item["attempts"] for item in head_rates)
            if len(records) > MAX_REPOSITORIES:
                _fail("REPOSITORY_BOUND")
        if len(page_raw) < MAX_PAGE_NODES:
            break
    records.sort(
        key=lambda item: (item["repository"].encode("utf-8"), item["repository_id"])
    )
    ids = [item["repository_id"] for item in records]
    names = [item["repository"].casefold() for item in records]
    if len(ids) != len(set(ids)) or len(names) != len(set(names)):
        _fail("DUPLICATE_REPOSITORY")
    payload = canonical_jsonl(records)
    return records, {
        "pages": page,
        "rate_limit": {
            "minimum_remaining_observed": min(item["remaining"] for item in rates),
            "reset_at_utc": _latest_timestamp(
                [item["reset_at_utc"] for item in rates], "RATE_RESET"
            ),
        },
        "requests": requests,
        "rows": len(records),
        "sha256": sha256(payload),
    }


def _public_projection(record: dict[str, Any]) -> dict[str, Any]:
    projected = dict(record)
    parent = projected.get("parent")
    if isinstance(parent, dict) and parent.get("visibility") != "PUBLIC":
        projected["parent"] = {
            "canonical_url": None,
            "repository": None,
            "repository_id": None,
            "visibility": "NONPUBLIC_REDACTED",
        }
    return projected


def capture_account(
    client: RestClient,
    *,
    owner_name: str,
    minimum_remaining: int,
    maximum_pages: int,
) -> dict[str, Any]:
    operational_reserve = minimum_remaining + 2 * MAX_GET_ATTEMPTS
    owner, identity_rates = verify_identity(
        client, owner_name, minimum_remaining=operational_reserve
    )
    snapshots: dict[str, list[dict[str, Any]]] = {}
    summaries: dict[str, list[dict[str, Any]]] = {}
    for scope in ("PUBLIC", "OWNER_VISIBLE"):
        first, first_summary = collect_snapshot(
            client,
            scope=scope,
            owner=owner,
            minimum_remaining=operational_reserve,
            maximum_pages=maximum_pages,
        )
        second, second_summary = collect_snapshot(
            client,
            scope=scope,
            owner=owner,
            minimum_remaining=operational_reserve,
            maximum_pages=maximum_pages,
        )
        if first != second:
            _fail("SNAPSHOT_DRIFT")
        snapshots[scope] = first
        summaries[scope] = [first_summary, second_summary]
    public_from_owner = [
        _public_projection(record)
        for record in snapshots["OWNER_VISIBLE"]
        if record["visibility"] == "PUBLIC"
    ]
    public_from_owner.sort(
        key=lambda item: (item["repository"].encode("utf-8"), item["repository_id"])
    )
    if public_from_owner != snapshots["PUBLIC"]:
        _fail("PUBLIC_SUBSET_MISMATCH")
    private_records = [
        record
        for record in snapshots["OWNER_VISIBLE"]
        if record["visibility"] == "PRIVATE"
    ]
    if len(snapshots["PUBLIC"]) + len(private_records) != len(
        snapshots["OWNER_VISIBLE"]
    ):
        _fail("VISIBILITY_PARTITION")
    final_owner, final_identity_rates = verify_identity(
        client, owner_name, minimum_remaining=minimum_remaining
    )
    if final_owner != owner:
        _fail("FINAL_IDENTITY_MISMATCH")
    identity_rates.extend(final_identity_rates)
    identity_observations = [owner, final_owner]
    return {
        "identity_summary": {
            "pages": 2,
            "rate_limit": {
                "minimum_remaining_observed": min(
                    item["remaining"] for item in identity_rates
                ),
                "reset_at_utc": _latest_timestamp(
                    [item["reset_at_utc"] for item in identity_rates],
                    "RATE_RESET",
                ),
            },
            "requests": sum(item["attempts"] for item in identity_rates),
            "rows": 2,
            "sha256": sha256(canonical_json(identity_observations)),
        },
        "identity_rates": identity_rates,
        "owner": owner,
        "owner_records": snapshots["OWNER_VISIBLE"],
        "private_records": private_records,
        "public_records": snapshots["PUBLIC"],
        "summaries": summaries,
    }


def _request_plan(scope: str) -> dict[str, Any]:
    if scope == "IDENTITY":
        return {
            "api_version": API_VERSION,
            "endpoints": ["/users/OWNER", "/user"],
            "requested_http_method_argument": "GET",
            "maximum_get_attempts": MAX_GET_ATTEMPTS,
            "passes": 2,
            "scope": scope,
        }
    if scope in {"PUBLIC", "OWNER_VISIBLE"}:
        return {
            "api_version": API_VERSION,
            "head_resolution": ["git/ref/heads", "409-empty"],
            "requested_http_method_argument": "GET",
            "maximum_get_attempts": MAX_GET_ATTEMPTS,
            "scope": scope,
        }
    _fail("REQUEST_PLAN_SCOPE")


def _private_command_records(
    capture: dict[str, Any],
    started: str,
    completed: str,
    invocation_sha256: str,
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    sequence = 1
    identity_summary = capture["identity_summary"]
    records.append(
        {
            "argv_template": [
                "gh",
                "api",
                "--hostname",
                API_HOST,
                "--method",
                "GET",
                "REQUESTED_GET_ENDPOINT_BOUND_IN_TOOL",
            ],
            "completed_at_utc": completed,
            "exit_status": 0,
            "invocation_sha256": invocation_sha256,
            "normalized_output_sha256": identity_summary["sha256"],
            "operation": "IDENTITY",
            "pages": identity_summary["pages"],
            "pass": 1,
            "private_identifiers_logged": False,
            "request_plan_sha256": sha256(canonical_json(_request_plan("IDENTITY"))),
            "requests": identity_summary["requests"],
            "result": "PASS",
            "rows": identity_summary["rows"],
            "schema_id": PRIVATE_COMMAND_LOG_SCHEMA,
            "schema_version": SCHEMA_VERSION,
            "sequence": sequence,
            "started_at_utc": started,
        }
    )
    for scope in ("PUBLIC", "OWNER_VISIBLE"):
        for pass_index, summary in enumerate(capture["summaries"][scope], 1):
            sequence += 1
            records.append(
                {
                    "argv_template": [
                        "gh",
                        "api",
                        "--hostname",
                        API_HOST,
                        "--method",
                        "GET",
                        "REQUESTED_GET_ENDPOINT_BOUND_IN_TOOL",
                    ],
                    "completed_at_utc": completed,
                    "exit_status": 0,
                    "invocation_sha256": invocation_sha256,
                    "normalized_output_sha256": summary["sha256"],
                    "operation": scope,
                    "pages": summary["pages"],
                    "pass": pass_index,
                    "private_identifiers_logged": False,
                    "request_plan_sha256": sha256(canonical_json(_request_plan(scope))),
                    "requests": summary["requests"],
                    "result": "PASS",
                    "rows": summary["rows"],
                    "schema_id": PRIVATE_COMMAND_LOG_SCHEMA,
                    "schema_version": SCHEMA_VERSION,
                    "sequence": sequence,
                    "started_at_utc": started,
                }
            )
    return records


def _public_command_records(
    capture: dict[str, Any],
    started: str,
    completed: str,
    invocation_sha256: str,
) -> list[dict[str, Any]]:
    observations = [
        ("IDENTITY", 1, 2),
        *(
            (scope, pass_index, summary["rows"])
            for scope in ("PUBLIC", "OWNER_VISIBLE")
            for pass_index, summary in enumerate(capture["summaries"][scope], 1)
        ),
    ]
    return [
        {
            "argv_template": [
                "gh",
                "api",
                "--hostname",
                API_HOST,
                "--method",
                "GET",
                "REQUESTED_GET_ENDPOINT_BOUND_IN_TOOL",
            ],
            "completed_at_utc": completed,
            "invocation_sha256": invocation_sha256,
            "operation": operation,
            "pass": pass_index,
            "private_identifiers_logged": False,
            "result": "PASS",
            "rows": rows,
            "schema_id": COMMAND_LOG_SCHEMA,
            "schema_version": SCHEMA_VERSION,
            "sequence": sequence,
            "started_at_utc": started,
        }
        for sequence, (operation, pass_index, rows) in enumerate(observations, 1)
    ]


def _validated_client_evidence(client: RestClient) -> dict[str, Any]:
    credential = _exact_constant(
        client.credential_binding, CREDENTIAL_BINDING, "CLIENT_CREDENTIAL_BINDING"
    )
    environment = _exact_constant(
        client.environment_binding,
        GH_ENVIRONMENT_BINDING,
        "CLIENT_ENVIRONMENT_BINDING",
    )
    tool = _exact_keys(
        client.identity, {"bytes", "name", "sha256", "version"}, "CLIENT_TOOL"
    )
    tool_bytes = _bounded_int(tool["bytes"], 1, MAX_EXECUTABLE_BYTES, "CLIENT_TOOL")
    tool_digest = _digest(tool["sha256"], "CLIENT_TOOL")
    if tool["name"] != "gh":
        _fail("CLIENT_TOOL")
    _text(tool["version"], "CLIENT_TOOL", maximum=256)
    executable = _exact_keys(
        client.executable_binding,
        {"bytes", "method", "mode", "sha256"},
        "CLIENT_EXECUTABLE_BINDING",
    )
    if (
        _bounded_int(
            executable["bytes"],
            1,
            MAX_EXECUTABLE_BYTES,
            "CLIENT_EXECUTABLE_BINDING",
        )
        != tool_bytes
        or _digest(executable["sha256"], "CLIENT_EXECUTABLE_BINDING") != tool_digest
        or executable["method"] != EXECUTABLE_BINDING_METHOD
        or executable["mode"] != "0500"
    ):
        _fail("CLIENT_EXECUTABLE_BINDING")
    head_workers = _bounded_int(client.head_workers, 1, 16, "CLIENT_HEAD_WORKERS")
    timeout_seconds = _bounded_int(
        client.timeout_seconds, 1, 300, "CLIENT_REQUEST_TIMEOUT"
    )
    return {
        "credential_binding": dict(credential),
        "environment_binding": dict(environment),
        "executable_binding": dict(executable),
        "head_workers": head_workers,
        "timeout_seconds": timeout_seconds,
        "tool": dict(tool),
    }


_PRODUCTION_CAPTURE_CLIENT_TYPE = GhClient


def _require_production_capture_client(client: RestClient) -> None:
    with _GH_SIGNAL_OWNER_LOCK:
        signal_owned = _GH_SIGNAL_OWNER is client
    if (
        type(client) is not _PRODUCTION_CAPTURE_CLIENT_TYPE
        or not signal_owned
        or getattr(client, "_shutdown_requested", True)
    ):
        _fail("CAPTURE_ORCHESTRATION_REQUIRED")


def capture_files(
    *,
    client: RestClient,
    owner_name: str,
    public_heads: Path,
    owner_visible: Path,
    capture_metadata: Path,
    command_log: Path,
    private_telemetry: Path,
    minimum_remaining: int,
    maximum_pages: int,
    expected_public_repositories: int,
    expected_private_repositories: int,
    _test_profile: bool = False,
    _orchestration_token: object | None = None,
) -> dict[str, int]:
    _require_common_evidence_root(
        (
            (public_heads, PUBLIC_HEADS_BASENAME),
            (owner_visible, OWNER_VISIBLE_BASENAME),
            (capture_metadata, CAPTURE_METADATA_BASENAME),
            (command_log, COMMAND_LOG_BASENAME),
            (private_telemetry, PRIVATE_TELEMETRY_BASENAME),
        )
    )
    if (
        len(
            {
                path.resolve(strict=False)
                for path in (
                    public_heads,
                    owner_visible,
                    capture_metadata,
                    command_log,
                    private_telemetry,
                )
            }
        )
        != 5
    ):
        _fail("OUTPUT_COLLISION")
    expected_public = _bounded_int(
        expected_public_repositories,
        1,
        MAX_REPOSITORIES,
        "EXPECTED_PUBLIC_REPOSITORIES",
    )
    expected_private = _bounded_int(
        expected_private_repositories,
        0,
        MAX_REPOSITORIES,
        "EXPECTED_PRIVATE_REPOSITORIES",
    )
    closure_profile = (
        TEST_CLOSURE_PROFILE if _test_profile else PRODUCTION_CLOSURE_PROFILE
    )
    if (
        owner_name != closure_profile["owner"]
        or expected_public != closure_profile["expected_public_repositories"]
        or expected_private != closure_profile["expected_private_repositories"]
        or expected_public + expected_private
        != closure_profile["expected_owner_visible_repositories"]
    ):
        _fail("CLOSURE_PROFILE_MISMATCH")
    if not _test_profile and (
        _orchestration_token is not _PRODUCTION_CAPTURE_ORCHESTRATION_TOKEN
        or type(client) is not _PRODUCTION_CAPTURE_CLIENT_TYPE
    ):
        _fail("CAPTURE_ORCHESTRATION_REQUIRED")
    if not _test_profile:
        _require_production_capture_client(client)
    maximum_pages = _bounded_int(maximum_pages, 1, 100, "PAGE_LIMIT")
    minimum_remaining = _bounded_int(minimum_remaining, 0, 5_000, "RATE_ARGUMENT")
    client_evidence = _validated_client_evidence(client)
    script_record = _inventory_script_record()
    started = utc_now()
    capture = capture_account(
        client,
        owner_name=owner_name,
        minimum_remaining=minimum_remaining,
        maximum_pages=maximum_pages,
    )
    completed = utc_now()
    if (
        capture["owner"]["login"] != closure_profile["owner"]
        or capture["owner"]["account_id"]
        != closure_profile["expected_owner_account_id"]
        or capture["owner"]["node_id"] != closure_profile["expected_owner_node_id"]
        or len(capture["public_records"]) != expected_public
        or len(capture["private_records"]) != expected_private
    ):
        _fail("EXPECTED_REPOSITORY_COUNT_MISMATCH")
    client.verify_pins()
    if _inventory_script_record() != script_record:
        _fail("INVENTORY_SCRIPT_DRIFT")
    public_payload = canonical_jsonl(capture["public_records"])
    owner_payload = canonical_jsonl(capture["owner_records"])
    private_payload = canonical_jsonl(capture["private_records"])
    capture_core = {
        "completed_at_utc": completed,
        "closure_profile": dict(closure_profile),
        "credential_binding": client_evidence["credential_binding"],
        "executable_binding": client_evidence["executable_binding"],
        "expected_repository_counts": {
            "private": expected_private,
            "public": expected_public,
        },
        "gh_environment_binding": client_evidence["environment_binding"],
        "identity_observation_sha256": capture["identity_summary"]["sha256"],
        "inventory_script": script_record,
        "minimum_rate_reserve": minimum_remaining,
        "maximum_head_workers": client_evidence["head_workers"],
        "maximum_get_attempts": MAX_GET_ATTEMPTS,
        "maximum_pages": maximum_pages,
        "output_labels": dict(CAPTURE_OUTPUT_LABELS),
        "owner": capture["owner"],
        "python_runtime": _python_runtime_record(),
        "request_timeout_seconds": client_evidence["timeout_seconds"],
        "started_at_utc": started,
        "stable_tool_results_across_two_passes": True,
        "tool": client_evidence["tool"],
        "tool_api_request_contract": dict(TOOL_API_REQUEST_CONTRACT),
    }
    invocation_sha256 = sha256(
        canonical_json(_capture_invocation_document(capture_core))
    )
    capture_core["invocation_sha256"] = invocation_sha256
    private_command_records = _private_command_records(
        capture, started, completed, invocation_sha256
    )
    command_records = _public_command_records(
        capture, started, completed, invocation_sha256
    )
    command_payload = canonical_jsonl(command_records)
    private_telemetry_value = {
        "capture_interval": {
            "completed_at_utc": completed,
            "started_at_utc": started,
        },
        "closure_profile": closure_profile,
        "command_log": private_command_records,
        "identity_rates": capture["identity_rates"],
        "identity_summary": capture["identity_summary"],
        "schema_id": PRIVATE_TELEMETRY_SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "summaries": capture["summaries"],
    }
    private_telemetry_payload = canonical_json(private_telemetry_value)
    metadata = {
        "authority": AUTHORITY,
        "capture": capture_core,
        "command_log": _file_record(
            COMMAND_LOG_BASENAME, command_payload, classification="PUBLIC_REDACTED"
        ),
        "limitations": LIMITATIONS,
        "owner_visible": {
            "file": _file_record(
                OWNER_VISIBLE_BASENAME,
                owner_payload,
                classification="OWNER_LOCAL_PRIVATE_MODE_0600",
            ),
            "private_rows": len(capture["private_records"]),
            "private_rows_sha256": sha256(private_payload),
            "public_rows": len(capture["public_records"]),
            "rows": len(capture["owner_records"]),
            "stable_passes": 2,
        },
        "private_telemetry": _file_record(
            PRIVATE_TELEMETRY_BASENAME,
            private_telemetry_payload,
            classification="OWNER_LOCAL_PRIVATE_MODE_0600",
        ),
        "public": {
            "file": _file_record(
                PUBLIC_HEADS_BASENAME, public_payload, classification="PUBLIC"
            ),
            "rows": len(capture["public_records"]),
            "stable_passes": 2,
        },
        "schema_id": TEST_CAPTURE_SCHEMA if _test_profile else CAPTURE_SCHEMA,
        "schema_version": SCHEMA_VERSION,
    }
    metadata_payload = canonical_json(metadata)
    _atomic_write(public_heads, public_payload, private=False)
    _atomic_write(owner_visible, owner_payload, private=True)
    _atomic_write(command_log, command_payload, private=False)
    _atomic_write(private_telemetry, private_telemetry_payload, private=True)
    _atomic_write(capture_metadata, metadata_payload, private=False)
    _require_private_mode(owner_visible)
    _require_private_mode(private_telemetry)
    return {
        "owner_visible": len(capture["owner_records"]),
        "private": len(capture["private_records"]),
        "public": len(capture["public_records"]),
    }


def capture_production_files(
    *,
    public_heads: Path,
    owner_visible: Path,
    capture_metadata: Path,
    command_log: Path,
    private_telemetry: Path,
    minimum_remaining: int,
    maximum_pages: int,
    head_workers: int,
    timeout_seconds: int,
) -> dict[str, int]:
    _require_common_evidence_root(
        (
            (public_heads, PUBLIC_HEADS_BASENAME),
            (owner_visible, OWNER_VISIBLE_BASENAME),
            (capture_metadata, CAPTURE_METADATA_BASENAME),
            (command_log, COMMAND_LOG_BASENAME),
            (private_telemetry, PRIVATE_TELEMETRY_BASENAME),
        )
    )
    private_paths = (owner_visible, private_telemetry)
    _private_write_preflight(
        evidence_root=public_heads.parent,
        private_paths=private_paths,
    )
    _production_maintained_artifact_payloads()
    client: GhClient | None = None
    try:
        client = GhClient(
            head_workers=head_workers,
            timeout_seconds=timeout_seconds,
        )
        return capture_files(
            client=client,
            owner_name=OWNER,
            public_heads=public_heads,
            owner_visible=owner_visible,
            capture_metadata=capture_metadata,
            command_log=command_log,
            private_telemetry=private_telemetry,
            minimum_remaining=minimum_remaining,
            maximum_pages=maximum_pages,
            expected_public_repositories=PRODUCTION_CLOSURE_PROFILE[
                "expected_public_repositories"
            ],
            expected_private_repositories=PRODUCTION_CLOSURE_PROFILE[
                "expected_private_repositories"
            ],
            _orchestration_token=_PRODUCTION_CAPTURE_ORCHESTRATION_TOKEN,
        )
    finally:
        try:
            if client is not None:
                client.close()
        finally:
            _private_write_preflight(
                evidence_root=public_heads.parent,
                private_paths=private_paths,
            )


def validate_heads(
    records: Sequence[Any],
    *,
    visibility: str,
    expected_owner: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    if visibility not in {"PUBLIC", "PRIVATE", "OWNER_VISIBLE"}:
        _fail("HEADS_VISIBILITY")
    normalized: list[dict[str, Any]] = []
    expected_keys = {
        "archived",
        "canonical_url",
        "default_branch",
        "exact_head",
        "fork",
        "head_state",
        "language",
        "license",
        "owner",
        "owner_id",
        "parent",
        "pushed_at",
        "repository",
        "repository_id",
        "schema_version",
        "updated_at",
        "visibility",
    }
    for item in records:
        record = _exact_keys(item, expected_keys, "HEAD_RECORD_KEYS")
        if record["schema_version"] != SCHEMA_VERSION:
            _fail("HEAD_SCHEMA")
        repository = _text(record["repository"], "HEAD_REPOSITORY", maximum=256)
        if REPOSITORY.fullmatch(repository) is None:
            _fail("HEAD_REPOSITORY")
        _positive_int(record["repository_id"], "HEAD_REPOSITORY_ID")
        owner = _text(record["owner"], "HEAD_OWNER", maximum=128)
        owner_id = _positive_int(record["owner_id"], "HEAD_OWNER_ID")
        repository_owner, _separator, _name = repository.partition("/")
        if repository_owner != owner:
            _fail("HEAD_OWNER_MISMATCH")
        if expected_owner is not None and (
            owner != expected_owner["login"] or owner_id != expected_owner["account_id"]
        ):
            _fail("HEAD_OWNER_MISMATCH")
        observed_visibility = _text(record["visibility"], "HEAD_VISIBILITY", maximum=16)
        if observed_visibility not in {"PUBLIC", "PRIVATE"}:
            _fail("HEAD_VISIBILITY")
        if visibility in {"PUBLIC", "PRIVATE"} and observed_visibility != visibility:
            _fail("HEAD_VISIBILITY")
        head_state = _text(record["head_state"], "HEAD_STATE", maximum=32)
        default_branch = _optional_text(
            record["default_branch"], "HEAD_BRANCH", maximum=256
        )
        exact_head = _optional_text(record["exact_head"], "HEAD_OID", maximum=64)
        if head_state == "COMMIT":
            if (
                default_branch is None
                or exact_head is None
                or HEX40.fullmatch(exact_head) is None
            ):
                _fail("HEAD_COMMIT")
        elif head_state == "EMPTY_REPOSITORY":
            if default_branch is not None or exact_head is not None:
                _fail("HEAD_EMPTY")
        else:
            _fail("HEAD_STATE")
        canonical_url = _text(record["canonical_url"], "HEAD_URL", maximum=512)
        if canonical_url != f"https://github.com/{repository}":
            _fail("HEAD_URL")
        parent = record["parent"]
        if parent is not None:
            parent_record = _exact_keys(
                parent,
                {"canonical_url", "repository", "repository_id", "visibility"},
                "HEAD_PARENT",
            )
            parent_visibility = _text(
                parent_record["visibility"], "HEAD_PARENT_VISIBILITY", maximum=32
            )
            if parent_visibility == "NONPUBLIC_REDACTED":
                if any(
                    parent_record[key] is not None
                    for key in ("canonical_url", "repository", "repository_id")
                ):
                    _fail("HEAD_PARENT_REDACTION")
            else:
                if parent_visibility not in {"PUBLIC", "PRIVATE", "INTERNAL"}:
                    _fail("HEAD_PARENT_VISIBILITY")
                if observed_visibility == "PUBLIC" and parent_visibility != "PUBLIC":
                    _fail("HEAD_PUBLIC_PARENT")
                _positive_int(parent_record["repository_id"], "HEAD_PARENT_ID")
                parent_name = _text(
                    parent_record["repository"], "HEAD_PARENT_NAME", maximum=256
                )
                if REPOSITORY.fullmatch(parent_name) is None:
                    _fail("HEAD_PARENT_NAME")
                if (
                    parent_record["canonical_url"]
                    != f"https://github.com/{parent_name}"
                ):
                    _fail("HEAD_PARENT_URL")
        if not _bool(record["fork"], "HEAD_FORK") and parent is not None:
            _fail("HEAD_NONFORK_PARENT")
        _bool(record["archived"], "HEAD_ARCHIVED")
        _optional_text(record["language"], "HEAD_LANGUAGE", maximum=128)
        _optional_text(record["license"], "HEAD_LICENSE", maximum=128)
        _timestamp(record["updated_at"], "HEAD_UPDATED")
        if record["pushed_at"] is not None:
            _timestamp(record["pushed_at"], "HEAD_PUSHED")
        normalized.append(dict(record))
    ordered = sorted(
        normalized,
        key=lambda item: (item["repository"].encode("utf-8"), item["repository_id"]),
    )
    if ordered != list(normalized):
        _fail("HEAD_ORDER")
    ids = [item["repository_id"] for item in normalized]
    names = [item["repository"].casefold() for item in normalized]
    if len(ids) != len(set(ids)) or len(names) != len(set(names)):
        _fail("HEAD_DUPLICATE")
    return normalized


def decision_template(
    records: Sequence[dict[str, Any]], *, heads_sha256: str | None = None
) -> dict[str, Any]:
    if not records:
        _fail("TEMPLATE_EMPTY")
    owner = {
        "account_id": records[0]["owner_id"],
        "login": records[0]["owner"],
    }
    decisions = []
    for record in records:
        if (
            record["owner"] != owner["login"]
            or record["owner_id"] != owner["account_id"]
        ):
            _fail("TEMPLATE_OWNER")
        decisions.append(
            {
                "agentic_tool_relevance": None,
                "audit_depth": "UNRESOLVED",
                "classification_status": "UNRESOLVED",
                "controller_relevance": None,
                "evidence_relevance": None,
                "first_party": None,
                "justification": "",
                "plant_relevance": None,
                "repository": record["repository"],
                "repository_id": record["repository_id"],
                "review_date": None,
                "review_attestation": "",
                "review_status": "UNRESOLVED",
                "reviewer": "",
                "state_relevance": None,
                "supply_chain_relevance": None,
                "tcb_class": "UNRESOLVED",
                "transport_relevance": None,
            }
        )
    return {
        "classification_review_basis": CLASSIFICATION_REVIEW_BASIS,
        "owner": owner,
        "records": decisions,
        "repository_heads_sha256": (
            _digest(heads_sha256, "TEMPLATE_HEADS_DIGEST")
            if heads_sha256 is not None
            else sha256(canonical_jsonl(records))
        ),
        "schema_id": DECISIONS_SCHEMA,
        "schema_version": SCHEMA_VERSION,
    }


def validate_decisions(
    value: Any,
    captures: Sequence[dict[str, Any]],
    *,
    expected_heads_sha256: str | None = None,
    review_not_before: dt.date | None = None,
    review_not_after: dt.date | None = None,
) -> list[dict[str, Any]]:
    document = _exact_keys(
        value,
        {
            "classification_review_basis",
            "owner",
            "records",
            "repository_heads_sha256",
            "schema_id",
            "schema_version",
        },
        "DECISIONS_KEYS",
    )
    if (
        document["schema_id"] != DECISIONS_SCHEMA
        or document["schema_version"] != SCHEMA_VERSION
    ):
        _fail("DECISIONS_SCHEMA")
    _exact_constant(
        document["classification_review_basis"],
        CLASSIFICATION_REVIEW_BASIS,
        "DECISIONS_REVIEW_BASIS",
    )
    expected_digest = (
        _digest(expected_heads_sha256, "DECISIONS_HEADS_DIGEST")
        if expected_heads_sha256 is not None
        else sha256(canonical_jsonl(captures))
    )
    if (
        _digest(document["repository_heads_sha256"], "DECISIONS_HEADS_DIGEST")
        != expected_digest
    ):
        _fail("DECISIONS_HEADS_DIGEST")
    owner = _exact_keys(document["owner"], {"account_id", "login"}, "DECISIONS_OWNER")
    owner_login = _text(owner["login"], "DECISIONS_OWNER_LOGIN", maximum=128)
    owner_id = _positive_int(owner["account_id"], "DECISIONS_OWNER_ID")
    records = document["records"]
    if not isinstance(records, list) or len(records) != len(captures):
        _fail("DECISIONS_COUNT")
    captures_by_id = {record["repository_id"]: record for record in captures}
    decisions: list[dict[str, Any]] = []
    seen: set[int] = set()
    for item in records:
        record = _exact_keys(item, DECISION_KEYS, "DECISION_KEYS")
        repository_id = _positive_int(record["repository_id"], "DECISION_ID")
        repository = _text(record["repository"], "DECISION_REPOSITORY", maximum=256)
        if repository_id in seen:
            _fail("DECISION_DUPLICATE")
        seen.add(repository_id)
        capture = captures_by_id.get(repository_id)
        if (
            capture is None
            or capture["repository"] != repository
            or capture["owner"] != owner_login
            or capture["owner_id"] != owner_id
        ):
            _fail("DECISION_CAPTURE_MATCH")
        normalized = {
            "agentic_tool_relevance": _bool(
                record["agentic_tool_relevance"], "DECISION_AGENTIC"
            ),
            "audit_depth": _text(record["audit_depth"], "DECISION_DEPTH", maximum=32),
            "classification_status": _text(
                record["classification_status"],
                "DECISION_CLASSIFICATION_STATUS",
                maximum=32,
            ),
            "controller_relevance": _bool(
                record["controller_relevance"], "DECISION_CONTROLLER"
            ),
            "evidence_relevance": _bool(
                record["evidence_relevance"], "DECISION_EVIDENCE"
            ),
            "first_party": _bool(record["first_party"], "DECISION_FIRST_PARTY"),
            "justification": _reviewed_authored_text(
                record["justification"],
                "DECISION_JUSTIFICATION",
                maximum=MAX_TEXT_FIELD,
                minimum=24,
            ),
            "plant_relevance": _bool(record["plant_relevance"], "DECISION_PLANT"),
            "repository": repository,
            "repository_id": repository_id,
            "review_date": _review_date(
                record["review_date"],
                "DECISION_REVIEW_DATE",
                not_before=review_not_before,
                not_after=review_not_after,
            ),
            "review_attestation": _text(
                record["review_attestation"],
                "DECISION_REVIEW_ATTESTATION",
                maximum=256,
            ),
            "review_status": _text(
                record["review_status"], "DECISION_REVIEW_STATUS", maximum=32
            ),
            "reviewer": _reviewed_authored_text(
                record["reviewer"],
                "DECISION_REVIEWER",
                maximum=256,
                minimum=3,
            ),
            "state_relevance": _bool(record["state_relevance"], "DECISION_STATE"),
            "supply_chain_relevance": _bool(
                record["supply_chain_relevance"], "DECISION_SUPPLY_CHAIN"
            ),
            "tcb_class": _text(record["tcb_class"], "DECISION_TCB", maximum=64),
            "transport_relevance": _bool(
                record["transport_relevance"], "DECISION_TRANSPORT"
            ),
        }
        if normalized["tcb_class"] not in TCB_CLASSES:
            _fail("DECISION_TCB")
        if normalized["audit_depth"] not in AUDIT_DEPTHS:
            _fail("DECISION_DEPTH")
        if (
            normalized["review_status"] != REVIEW_STATUS
            or normalized["classification_status"] != CLASSIFICATION_STATUS
            or normalized["review_attestation"] != REVIEW_ATTESTATION
        ):
            _fail("DECISION_REVIEW_STATUS")
        decisions.append(normalized)
    decisions.sort(
        key=lambda item: (item["repository"].encode("utf-8"), item["repository_id"])
    )
    expected_ids = set(captures_by_id)
    if seen != expected_ids or decisions != records:
        _fail("DECISION_ORDER_OR_COVERAGE")
    return decisions


def joined_records(
    captures: Sequence[dict[str, Any]], decisions: Sequence[dict[str, Any]]
) -> list[dict[str, Any]]:
    by_id = {record["repository_id"]: record for record in decisions}
    joined = []
    for capture in captures:
        decision = by_id.get(capture["repository_id"])
        if decision is None or decision["repository"] != capture["repository"]:
            _fail("JOIN_COVERAGE")
        joined.append({**capture, **decision})
    return joined


def classification_json(
    records: Sequence[dict[str, Any]],
    *,
    heads_sha256: str,
    decisions_sha256: str,
) -> bytes:
    counts: dict[str, int] = {}
    for record in records:
        key = record["tcb_class"]
        counts[key] = counts.get(key, 0) + 1
    document = {
        "authority": AUTHORITY,
        "counts": {
            "by_tcb_class": dict(sorted(counts.items())),
            "first_party": sum(1 for record in records if record["first_party"]),
            "forks": sum(1 for record in records if record["fork"]),
            "repositories": len(records),
            "unresolved": 0,
        },
        "records": list(records),
        "schema_id": CLASSIFICATION_SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "sources": {
            "decisions_sha256": decisions_sha256,
            "repository_heads_sha256": heads_sha256,
        },
    }
    return canonical_json(document)


def classification_csv(records: Sequence[dict[str, Any]]) -> bytes:
    output = io.StringIO(newline="")
    writer = csv.DictWriter(
        output,
        fieldnames=list(CSV_COLUMNS),
        extrasaction="raise",
        lineterminator="\n",
    )
    writer.writeheader()
    for record in records:
        row: dict[str, str] = {}
        for column in CSV_COLUMNS:
            value = record[column]
            if value is None:
                row[column] = ""
            elif type(value) is bool:
                row[column] = "true" if value else "false"
            else:
                rendered = str(value)
                if rendered.startswith(("=", "+", "-", "@")):
                    rendered = "'" + rendered
                row[column] = rendered
        writer.writerow(row)
    return output.getvalue().encode("utf-8")


def _validate_authored_list(
    value: Any,
    code: str,
    *,
    maximum_items: int,
    maximum_text: int,
) -> list[str]:
    if not isinstance(value, list) or not 1 <= len(value) <= maximum_items:
        _fail(code)
    normalized = [_authored_text(item, code, maximum=maximum_text) for item in value]
    if len({item.casefold() for item in normalized}) != len(normalized):
        _fail(code)
    return normalized


def validate_supersession_audit(value: Any) -> dict[str, Any]:
    document = _exact_keys(
        value,
        {
            "authority",
            "decisions",
            "owner_approval_established",
            "prepared_at",
            "prepared_by",
            "review_attestation",
            "review_date",
            "review_kind",
            "review_status",
            "reviewer",
            "reviewer_identity_authenticated",
            "schema_id",
            "schema_version",
            "scope",
            "sources",
            "unresolved",
        },
        "SUPERSESSION_KEYS",
    )
    if (
        document["schema_id"] != SUPERSESSION_SCHEMA
        or document["schema_version"] != SCHEMA_VERSION
        or document["scope"] != SUPERSESSION_SCOPE
    ):
        _fail("SUPERSESSION_SCHEMA")
    _validate_authority(document["authority"], "SUPERSESSION_AUTHORITY")
    if (
        document["prepared_at"] != MAINTAINED_REVIEW_DATE
        or document["prepared_by"] != "Codex automated draft"
        or document["owner_approval_established"] is not False
        or document["reviewer_identity_authenticated"] is not False
    ):
        _fail("SUPERSESSION_REVIEW_STATUS")
    if document["review_status"] == "REVIEWED":
        if (
            document["review_attestation"] != SUPERSESSION_REVIEW_ATTESTATION
            or document["review_date"] != SUPERSESSION_REVIEW_DATE
            or document["review_kind"] != "AUTOMATED_FACTUAL_REVIEW"
            or document["reviewer"] != "Codex automated factual review"
        ):
            _fail("SUPERSESSION_REVIEW_STATUS")
        expected_document = SUPERSESSION_EXPECTED_DOCUMENT
    elif document["review_status"] == "UNREVIEWED":
        if (
            document["review_attestation"] is not None
            or document["review_date"] is not None
            or document["review_kind"] != "AUTOMATED_DRAFT"
            or document["reviewer"] is not None
        ):
            _fail("SUPERSESSION_REVIEW_STATUS")
        expected_document = SUPERSESSION_UNREVIEWED_DOCUMENT
    else:
        _fail("SUPERSESSION_REVIEW_STATUS")
    sources = document["sources"]
    expected_source_ids = list(SUPERSESSION_SOURCE_CONTRACT)
    if not isinstance(sources, list) or len(sources) != len(expected_source_ids):
        _fail("SUPERSESSION_SOURCES")
    observed_source_ids: list[str] = []
    for item, expected_id in zip(sources, expected_source_ids, strict=True):
        source = _exact_keys(item, {"id", "path", "status"}, "SUPERSESSION_SOURCE")
        source_id = _text(source["id"], "SUPERSESSION_SOURCE_ID", maximum=64)
        path = _text(source["path"], "SUPERSESSION_SOURCE_PATH", maximum=512)
        status = _text(source["status"], "SUPERSESSION_SOURCE_STATUS", maximum=64)
        expected_path, expected_status = SUPERSESSION_SOURCE_CONTRACT[expected_id]
        pure_path = PurePosixPath(path)
        if (
            source_id != expected_id
            or path != expected_path
            or status != expected_status
            or pure_path.is_absolute()
            or any(part in {"", ".", ".."} for part in pure_path.parts)
            or "\\" in path
            or str(pure_path) != path
        ):
            _fail("SUPERSESSION_SOURCE")
        observed_source_ids.append(source_id)
    if len(set(observed_source_ids)) != len(expected_source_ids):
        _fail("SUPERSESSION_SOURCES")
    decisions = document["decisions"]
    expected_decision_ids = list(SUPERSESSION_DECISION_CONTRACT)
    if not isinstance(decisions, list) or len(decisions) != len(expected_decision_ids):
        _fail("SUPERSESSION_DECISIONS")
    observed_decision_ids: list[str] = []
    for item, expected_id in zip(decisions, expected_decision_ids, strict=True):
        decision = _exact_keys(
            item,
            {"disposition", "id", "must_not_imply", "reason", "subject"},
            "SUPERSESSION_DECISION",
        )
        decision_id = _text(decision["id"], "SUPERSESSION_DECISION_ID", maximum=32)
        disposition = _text(
            decision["disposition"], "SUPERSESSION_DISPOSITION", maximum=64
        )
        if (
            decision_id != expected_id
            or disposition != SUPERSESSION_DECISION_CONTRACT[expected_id]
        ):
            _fail("SUPERSESSION_DECISION")
        _authored_text(decision["subject"], "SUPERSESSION_SUBJECT", maximum=512)
        _authored_text(
            decision["reason"], "SUPERSESSION_REASON", maximum=MAX_TEXT_FIELD
        )
        _validate_authored_list(
            decision["must_not_imply"],
            "SUPERSESSION_MUST_NOT_IMPLY",
            maximum_items=32,
            maximum_text=512,
        )
        observed_decision_ids.append(decision_id)
    if len(set(observed_decision_ids)) != len(expected_decision_ids):
        _fail("SUPERSESSION_DECISIONS")
    _validate_authored_list(
        document["unresolved"],
        "SUPERSESSION_UNRESOLVED",
        maximum_items=64,
        maximum_text=MAX_TEXT_FIELD,
    )
    _exact_constant(document, expected_document, "SUPERSESSION_CONTENT")
    return document


def _require_reviewed_supersession(document: dict[str, Any]) -> None:
    if document["review_status"] != "REVIEWED":
        _fail("SUPERSESSION_UNREVIEWED")


def _validate_capture_metadata(
    value: Any,
    *,
    public_payload: bytes,
    owner_payload: bytes | None,
    command_payload: bytes,
    owner_records: Sequence[dict[str, Any]] | None,
    private_telemetry_payload: bytes | None = None,
    _test_profile: bool = False,
) -> dict[str, Any]:
    document = _exact_keys(
        value,
        {
            "authority",
            "capture",
            "command_log",
            "limitations",
            "owner_visible",
            "private_telemetry",
            "public",
            "schema_id",
            "schema_version",
        },
        "CAPTURE_METADATA_KEYS",
    )
    if (
        document["schema_id"]
        != (TEST_CAPTURE_SCHEMA if _test_profile else CAPTURE_SCHEMA)
        or document["schema_version"] != SCHEMA_VERSION
    ):
        _fail("CAPTURE_METADATA_SCHEMA")
    _validate_authority(document["authority"], "CAPTURE_METADATA_SCHEMA")
    _exact_constant(document["limitations"], LIMITATIONS, "CAPTURE_METADATA_SCHEMA")
    capture = _exact_keys(
        document["capture"],
        {
            "closure_profile",
            "completed_at_utc",
            "credential_binding",
            "executable_binding",
            "expected_repository_counts",
            "gh_environment_binding",
            "identity_observation_sha256",
            "inventory_script",
            "invocation_sha256",
            "maximum_head_workers",
            "maximum_get_attempts",
            "maximum_pages",
            "minimum_rate_reserve",
            "output_labels",
            "owner",
            "python_runtime",
            "request_timeout_seconds",
            "stable_tool_results_across_two_passes",
            "started_at_utc",
            "tool",
            "tool_api_request_contract",
        },
        "CAPTURE_CORE_KEYS",
    )
    closure_profile_value = _exact_keys(
        capture["closure_profile"],
        set(PRODUCTION_CLOSURE_PROFILE),
        "CAPTURE_CLOSURE_PROFILE",
    )
    profile_id = closure_profile_value.get("profile_id")
    if profile_id == PRODUCTION_CLOSURE_PROFILE["profile_id"] and not _test_profile:
        closure_profile = PRODUCTION_CLOSURE_PROFILE
    elif profile_id == TEST_CLOSURE_PROFILE["profile_id"] and _test_profile:
        closure_profile = TEST_CLOSURE_PROFILE
    else:
        _fail("CAPTURE_CLOSURE_PROFILE")
    _exact_constant(closure_profile_value, closure_profile, "CAPTURE_CLOSURE_PROFILE")
    _started_text, started = _timestamp_instant(
        capture["started_at_utc"], "CAPTURE_STARTED"
    )
    _completed_text, completed = _timestamp_instant(
        capture["completed_at_utc"], "CAPTURE_COMPLETED"
    )
    if completed < started:
        _fail("CAPTURE_TIME_ORDER")
    _bounded_int(capture["minimum_rate_reserve"], 0, 5_000, "CAPTURE_RATE_RESERVE")
    _bounded_int(capture["maximum_pages"], 1, 100, "CAPTURE_MAXIMUM_PAGES")
    _bounded_int(capture["maximum_head_workers"], 1, 16, "CAPTURE_HEAD_WORKERS")
    _bounded_int(capture["request_timeout_seconds"], 1, 300, "CAPTURE_REQUEST_TIMEOUT")
    _exact_int(
        capture["maximum_get_attempts"],
        MAX_GET_ATTEMPTS,
        "CAPTURE_GET_ATTEMPTS",
    )
    _exact_constant(
        capture["tool_api_request_contract"],
        TOOL_API_REQUEST_CONTRACT,
        "CAPTURE_TOOL_REQUEST_CONTRACT",
    )
    if (
        type(capture["stable_tool_results_across_two_passes"]) is not bool
        or capture["stable_tool_results_across_two_passes"] is not True
    ):
        _fail("CAPTURE_TOOL_RESULTS")
    _exact_constant(
        capture["credential_binding"], CREDENTIAL_BINDING, "CAPTURE_CREDENTIAL_BINDING"
    )
    _exact_constant(
        capture["gh_environment_binding"],
        GH_ENVIRONMENT_BINDING,
        "CAPTURE_GH_ENVIRONMENT_BINDING",
    )
    _exact_constant(
        capture["output_labels"], CAPTURE_OUTPUT_LABELS, "CAPTURE_OUTPUT_LABELS"
    )
    owner = _exact_keys(
        capture["owner"], {"account_id", "login", "node_id"}, "CAPTURE_OWNER"
    )
    owner_login = _text(owner["login"], "CAPTURE_OWNER_LOGIN", maximum=128)
    if re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})", owner_login) is None:
        _fail("CAPTURE_OWNER_LOGIN")
    if owner_login != closure_profile["owner"]:
        _fail("CAPTURE_CLOSURE_PROFILE")
    _text(owner["node_id"], "CAPTURE_OWNER_NODE", maximum=256)
    owner_account_id = _positive_int(owner["account_id"], "CAPTURE_OWNER_ID")
    if (
        owner_account_id != closure_profile["expected_owner_account_id"]
        or owner["node_id"] != closure_profile["expected_owner_node_id"]
    ):
        _fail("CAPTURE_CLOSURE_PROFILE")
    identity_digest = _digest(
        capture["identity_observation_sha256"], "CAPTURE_IDENTITY_BINDING"
    )
    if identity_digest != sha256(canonical_json([owner, owner])):
        _fail("CAPTURE_IDENTITY_BINDING")
    tool = _exact_keys(
        capture["tool"], {"bytes", "name", "sha256", "version"}, "CAPTURE_TOOL"
    )
    tool_bytes = _bounded_int(tool["bytes"], 1, MAX_EXECUTABLE_BYTES, "CAPTURE_TOOL")
    tool_digest = _digest(tool["sha256"], "CAPTURE_TOOL")
    if tool["name"] != "gh":
        _fail("CAPTURE_TOOL")
    _text(tool["version"], "CAPTURE_TOOL", maximum=256)
    executable_binding = _exact_keys(
        capture["executable_binding"],
        {"bytes", "method", "mode", "sha256"},
        "CAPTURE_EXECUTABLE_BINDING",
    )
    if (
        _bounded_int(
            executable_binding["bytes"],
            1,
            MAX_EXECUTABLE_BYTES,
            "CAPTURE_EXECUTABLE_BINDING",
        )
        != tool_bytes
        or _digest(executable_binding["sha256"], "CAPTURE_EXECUTABLE_BINDING")
        != tool_digest
        or executable_binding["method"] != EXECUTABLE_BINDING_METHOD
        or executable_binding["mode"] != "0500"
    ):
        _fail("CAPTURE_EXECUTABLE_BINDING")
    inventory_script = _validate_file_record(
        capture["inventory_script"],
        label="ecosystem_source_inventory.py",
        classification="PUBLIC_TOOL_SOURCE",
        maximum_bytes=MAX_JSON_BYTES,
        code="CAPTURE_INVENTORY_SCRIPT",
    )
    if inventory_script != _inventory_script_record():
        _fail("CAPTURE_INVENTORY_SCRIPT")
    python_runtime = _exact_keys(
        capture["python_runtime"],
        {"implementation", "version"},
        "CAPTURE_PYTHON_RUNTIME",
    )
    _text(python_runtime["implementation"], "CAPTURE_PYTHON_RUNTIME", maximum=64)
    python_version = _text(
        python_runtime["version"], "CAPTURE_PYTHON_RUNTIME", maximum=64
    )
    if (
        re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+._A-Za-z0-9]*)?", python_version)
        is None
    ):
        _fail("CAPTURE_PYTHON_RUNTIME")
    expected_counts = _exact_keys(
        capture["expected_repository_counts"],
        {"private", "public"},
        "CAPTURE_EXPECTED_COUNTS",
    )
    expected_public = _bounded_int(
        expected_counts["public"], 1, MAX_REPOSITORIES, "CAPTURE_EXPECTED_COUNTS"
    )
    expected_private = _bounded_int(
        expected_counts["private"], 0, MAX_REPOSITORIES, "CAPTURE_EXPECTED_COUNTS"
    )
    if (
        expected_public != closure_profile["expected_public_repositories"]
        or expected_private != closure_profile["expected_private_repositories"]
    ):
        _fail("CAPTURE_CLOSURE_PROFILE")
    invocation_digest = _digest(
        capture["invocation_sha256"], "CAPTURE_INVOCATION_DIGEST"
    )
    if invocation_digest != sha256(
        canonical_json(_capture_invocation_document(capture))
    ):
        _fail("CAPTURE_INVOCATION_BINDING")
    public = _exact_keys(
        document["public"], {"file", "rows", "stable_passes"}, "CAPTURE_PUBLIC_KEYS"
    )
    owner_visible = _exact_keys(
        document["owner_visible"],
        {
            "file",
            "private_rows",
            "private_rows_sha256",
            "public_rows",
            "rows",
            "stable_passes",
        },
        "CAPTURE_PRIVATE_KEYS",
    )
    command_file = _validate_file_record(
        document["command_log"],
        label=COMMAND_LOG_BASENAME,
        classification="PUBLIC_REDACTED",
        maximum_bytes=MAX_COMMAND_LOG_BYTES,
        code="CAPTURE_COMMAND_FILE",
    )
    private_telemetry_file = _validate_file_record(
        document["private_telemetry"],
        label=PRIVATE_TELEMETRY_BASENAME,
        classification="OWNER_LOCAL_PRIVATE_MODE_0600",
        maximum_bytes=MAX_JSON_BYTES,
        code="CAPTURE_PRIVATE_TELEMETRY_FILE",
    )
    public_file = _validate_file_record(
        public["file"],
        label=PUBLIC_HEADS_BASENAME,
        classification="PUBLIC",
        maximum_bytes=MAX_JSON_BYTES,
        code="CAPTURE_PUBLIC_FILE",
    )
    owner_file = _validate_file_record(
        owner_visible["file"],
        label=OWNER_VISIBLE_BASENAME,
        classification="OWNER_LOCAL_PRIVATE_MODE_0600",
        maximum_bytes=MAX_JSON_BYTES,
        code="CAPTURE_PRIVATE_FILE",
    )
    if public_file != _file_record(
        PUBLIC_HEADS_BASENAME, public_payload, classification="PUBLIC"
    ):
        _fail("CAPTURE_PUBLIC_BINDING")
    if command_file != _file_record(
        COMMAND_LOG_BASENAME, command_payload, classification="PUBLIC_REDACTED"
    ):
        _fail("CAPTURE_COMMAND_BINDING")
    if owner_payload is not None and owner_file != _file_record(
        OWNER_VISIBLE_BASENAME,
        owner_payload,
        classification="OWNER_LOCAL_PRIVATE_MODE_0600",
    ):
        _fail("CAPTURE_PRIVATE_BINDING")
    if private_telemetry_payload is not None and private_telemetry_file != _file_record(
        PRIVATE_TELEMETRY_BASENAME,
        private_telemetry_payload,
        classification="OWNER_LOCAL_PRIVATE_MODE_0600",
    ):
        _fail("CAPTURE_PRIVATE_TELEMETRY_BINDING")
    public_rows = _bounded_int(
        public["rows"], 1, MAX_REPOSITORIES, "CAPTURE_PUBLIC_ROWS"
    )
    owner_rows = _bounded_int(
        owner_visible["rows"], 1, MAX_REPOSITORIES, "CAPTURE_OWNER_ROWS"
    )
    owner_public_rows = _bounded_int(
        owner_visible["public_rows"], 1, MAX_REPOSITORIES, "CAPTURE_OWNER_PUBLIC_ROWS"
    )
    private_rows = _bounded_int(
        owner_visible["private_rows"], 0, MAX_REPOSITORIES, "CAPTURE_PRIVATE_ROWS"
    )
    private_rows_digest = _digest(
        owner_visible["private_rows_sha256"], "CAPTURE_PRIVATE_ROWS_DIGEST"
    )
    _exact_int(public["stable_passes"], 2, "CAPTURE_PUBLIC_PASSES")
    _exact_int(owner_visible["stable_passes"], 2, "CAPTURE_PRIVATE_PASSES")
    if (
        public_rows != public_payload.count(b"\n")
        or owner_public_rows != public_rows
        or owner_public_rows + private_rows != owner_rows
        or owner_rows != closure_profile["expected_owner_visible_repositories"]
        or public_rows != expected_public
        or private_rows != expected_private
    ):
        _fail("CAPTURE_ROW_COUNTS")
    if owner_payload is not None:
        if owner_rows != owner_payload.count(b"\n") or owner_records is None:
            _fail("CAPTURE_ROW_COUNTS")
        private_payload = canonical_jsonl(
            [record for record in owner_records if record["visibility"] == "PRIVATE"]
        )
        if sha256(private_payload) != private_rows_digest:
            _fail("CAPTURE_PRIVATE_ROWS_BINDING")

    return document


def _command_log(records: Sequence[Any]) -> list[dict[str, Any]]:
    if not isinstance(records, list) or len(records) != 5:
        _fail("COMMAND_COUNT")
    expected_keys = {
        "argv_template",
        "completed_at_utc",
        "invocation_sha256",
        "operation",
        "pass",
        "private_identifiers_logged",
        "result",
        "rows",
        "schema_id",
        "schema_version",
        "sequence",
        "started_at_utc",
    }
    expected_operations = [
        ("IDENTITY", 1),
        ("PUBLIC", 1),
        ("PUBLIC", 2),
        ("OWNER_VISIBLE", 1),
        ("OWNER_VISIBLE", 2),
    ]
    normalized = []
    for expected_sequence, item in enumerate(records, 1):
        record = _exact_keys(item, expected_keys, "COMMAND_RECORD_KEYS")
        expected_operation, expected_pass = expected_operations[expected_sequence - 1]
        if (
            record["schema_id"] != COMMAND_LOG_SCHEMA
            or record["schema_version"] != SCHEMA_VERSION
            or record["operation"] != expected_operation
            or record["result"] != "PASS"
        ):
            _fail("COMMAND_RECORD")
        _exact_int(record["sequence"], expected_sequence, "COMMAND_RECORD")
        _exact_int(record["pass"], expected_pass, "COMMAND_RECORD")
        if (
            type(record["private_identifiers_logged"]) is not bool
            or record["private_identifiers_logged"] is not False
        ):
            _fail("COMMAND_RECORD")
        _digest(record["invocation_sha256"], "COMMAND_RECORD")
        _bounded_int(record["rows"], 0, MAX_REPOSITORIES, "COMMAND_ROWS")
        _started_text, started = _timestamp_instant(
            record["started_at_utc"], "COMMAND_STARTED"
        )
        _completed_text, completed = _timestamp_instant(
            record["completed_at_utc"], "COMMAND_COMPLETED"
        )
        if completed < started:
            _fail("COMMAND_TIME_ORDER")
        argv = record["argv_template"]
        if argv != [
            "gh",
            "api",
            "--hostname",
            API_HOST,
            "--method",
            "GET",
            "REQUESTED_GET_ENDPOINT_BOUND_IN_TOOL",
        ]:
            _fail("COMMAND_ARGV")
        normalized.append(dict(record))
    return normalized


def _validate_private_telemetry(
    value: Any,
    capture: dict[str, Any],
    *,
    public_records: Sequence[dict[str, Any]],
    owner_records: Sequence[dict[str, Any]],
) -> dict[str, Any]:
    document = _exact_keys(
        value,
        {
            "capture_interval",
            "closure_profile",
            "command_log",
            "identity_rates",
            "identity_summary",
            "schema_id",
            "schema_version",
            "summaries",
        },
        "PRIVATE_TELEMETRY_KEYS",
    )
    if (
        document["schema_id"] != PRIVATE_TELEMETRY_SCHEMA
        or document["schema_version"] != SCHEMA_VERSION
    ):
        _fail("PRIVATE_TELEMETRY_SCHEMA")
    _exact_constant(
        document["closure_profile"],
        capture["capture"]["closure_profile"],
        "PRIVATE_TELEMETRY_PROFILE",
    )
    _exact_constant(
        document["capture_interval"],
        {
            "completed_at_utc": capture["capture"]["completed_at_utc"],
            "started_at_utc": capture["capture"]["started_at_utc"],
        },
        "PRIVATE_TELEMETRY_INTERVAL",
    )
    identity_rates = document["identity_rates"]
    if not isinstance(identity_rates, list) or len(identity_rates) != 4:
        _fail("PRIVATE_TELEMETRY_IDENTITY_RATES")
    minimum_rate_reserve = capture["capture"]["minimum_rate_reserve"]
    maximum_pages = capture["capture"]["maximum_pages"]
    identity_minimums = [
        minimum_rate_reserve + 3 * MAX_GET_ATTEMPTS,
        minimum_rate_reserve + 2 * MAX_GET_ATTEMPTS,
        minimum_rate_reserve + MAX_GET_ATTEMPTS,
        minimum_rate_reserve,
    ]
    normalized_identity_rates = [
        _rate(rate, minimum_remaining)
        for rate, minimum_remaining in zip(
            identity_rates, identity_minimums, strict=True
        )
    ]
    identity_summary = _exact_keys(
        document["identity_summary"],
        {"pages", "rate_limit", "requests", "rows", "sha256"},
        "PRIVATE_TELEMETRY_IDENTITY",
    )
    _exact_int(identity_summary["pages"], 2, "PRIVATE_TELEMETRY_IDENTITY")
    _exact_int(identity_summary["rows"], 2, "PRIVATE_TELEMETRY_IDENTITY")
    _bounded_int(
        identity_summary["requests"],
        4,
        4 * MAX_GET_ATTEMPTS,
        "PRIVATE_TELEMETRY_IDENTITY",
    )
    if _digest(identity_summary["sha256"], "PRIVATE_TELEMETRY_IDENTITY") != capture[
        "capture"
    ]["identity_observation_sha256"] or identity_summary["requests"] != sum(
        rate["attempts"] for rate in normalized_identity_rates
    ):
        _fail("PRIVATE_TELEMETRY_IDENTITY")
    identity_rate = _exact_keys(
        identity_summary["rate_limit"],
        {"minimum_remaining_observed", "reset_at_utc"},
        "PRIVATE_TELEMETRY_IDENTITY",
    )
    _bounded_int(
        identity_rate["minimum_remaining_observed"],
        0,
        100_000,
        "PRIVATE_TELEMETRY_IDENTITY",
    )
    _timestamp(identity_rate["reset_at_utc"], "PRIVATE_TELEMETRY_IDENTITY")
    if identity_rate["minimum_remaining_observed"] != min(
        rate["remaining"] for rate in normalized_identity_rates
    ) or identity_rate["reset_at_utc"] != _latest_timestamp(
        [rate["reset_at_utc"] for rate in normalized_identity_rates],
        "PRIVATE_TELEMETRY_IDENTITY",
    ):
        _fail("PRIVATE_TELEMETRY_IDENTITY")
    summaries = _exact_keys(
        document["summaries"],
        {"OWNER_VISIBLE", "PUBLIC"},
        "PRIVATE_TELEMETRY_SUMMARIES",
    )
    for scope, rows, retained_records in (
        ("PUBLIC", capture["public"]["rows"], public_records),
        ("OWNER_VISIBLE", capture["owner_visible"]["rows"], owner_records),
    ):
        values = summaries[scope]
        if not isinstance(values, list) or len(values) != 2:
            _fail("PRIVATE_TELEMETRY_SUMMARIES")
        expected_digest = (
            capture["public"]["file"]["sha256"]
            if scope == "PUBLIC"
            else capture["owner_visible"]["file"]["sha256"]
        )
        for summary in values:
            record = _exact_keys(
                summary,
                {"pages", "rate_limit", "requests", "rows", "sha256"},
                "PRIVATE_TELEMETRY_SUMMARY",
            )
            pages = _bounded_int(record["pages"], 1, 100, "PRIVATE_TELEMETRY_SUMMARY")
            requests = _bounded_int(
                record["requests"],
                1,
                MAX_GET_ATTEMPTS * (100 + MAX_REPOSITORIES),
                "PRIVATE_TELEMETRY_SUMMARY",
            )
            if (
                _bounded_int(
                    record["rows"], 0, MAX_REPOSITORIES, "PRIVATE_TELEMETRY_SUMMARY"
                )
                != rows
                or pages > maximum_pages
                or pages != rows // MAX_PAGE_NODES + 1
                or requests
                < pages
                + sum(
                    1
                    for retained in retained_records
                    if retained["head_state"] == "COMMIT"
                )
                or requests > MAX_GET_ATTEMPTS * (pages + rows)
            ):
                _fail("PRIVATE_TELEMETRY_SUMMARY")
            if (
                _digest(record["sha256"], "PRIVATE_TELEMETRY_SUMMARY")
                != expected_digest
            ):
                _fail("PRIVATE_TELEMETRY_SUMMARY")
            rate = _exact_keys(
                record["rate_limit"],
                {"minimum_remaining_observed", "reset_at_utc"},
                "PRIVATE_TELEMETRY_SUMMARY",
            )
            _bounded_int(
                rate["minimum_remaining_observed"],
                0,
                100_000,
                "PRIVATE_TELEMETRY_SUMMARY",
            )
            _timestamp(rate["reset_at_utc"], "PRIVATE_TELEMETRY_SUMMARY")
            if (
                rate["minimum_remaining_observed"]
                < minimum_rate_reserve + 2 * MAX_GET_ATTEMPTS
            ):
                _fail("PRIVATE_TELEMETRY_SUMMARY")
    command_log = document["command_log"]
    if not isinstance(command_log, list) or len(command_log) != 5:
        _fail("PRIVATE_TELEMETRY_COMMAND_LOG")
    expected_summaries = [
        identity_summary,
        *summaries["PUBLIC"],
        *summaries["OWNER_VISIBLE"],
    ]
    expected_operations = [
        ("IDENTITY", 1),
        ("PUBLIC", 1),
        ("PUBLIC", 2),
        ("OWNER_VISIBLE", 1),
        ("OWNER_VISIBLE", 2),
    ]
    expected_keys = {
        "argv_template",
        "completed_at_utc",
        "exit_status",
        "invocation_sha256",
        "normalized_output_sha256",
        "operation",
        "pages",
        "pass",
        "private_identifiers_logged",
        "request_plan_sha256",
        "requests",
        "result",
        "rows",
        "schema_id",
        "schema_version",
        "sequence",
        "started_at_utc",
    }
    for sequence, (record_value, expected, operation_pass) in enumerate(
        zip(command_log, expected_summaries, expected_operations, strict=True), 1
    ):
        record = _exact_keys(
            record_value, expected_keys, "PRIVATE_TELEMETRY_COMMAND_LOG"
        )
        operation, pass_index = operation_pass
        if (
            record["schema_id"] != PRIVATE_COMMAND_LOG_SCHEMA
            or record["schema_version"] != SCHEMA_VERSION
            or record["operation"] != operation
            or record["result"] != "PASS"
            or record["started_at_utc"] != capture["capture"]["started_at_utc"]
            or record["completed_at_utc"] != capture["capture"]["completed_at_utc"]
            or record["invocation_sha256"] != capture["capture"]["invocation_sha256"]
            or record["normalized_output_sha256"] != expected["sha256"]
            or record["pages"] != expected["pages"]
            or record["requests"] != expected["requests"]
            or record["rows"] != expected["rows"]
            or record["argv_template"]
            != [
                "gh",
                "api",
                "--hostname",
                API_HOST,
                "--method",
                "GET",
                "REQUESTED_GET_ENDPOINT_BOUND_IN_TOOL",
            ]
            or record["request_plan_sha256"]
            != sha256(canonical_json(_request_plan(operation)))
            or type(record["private_identifiers_logged"]) is not bool
            or record["private_identifiers_logged"] is not False
        ):
            _fail("PRIVATE_TELEMETRY_COMMAND_LOG")
        _exact_int(record["sequence"], sequence, "PRIVATE_TELEMETRY_COMMAND_LOG")
        _exact_int(record["pass"], pass_index, "PRIVATE_TELEMETRY_COMMAND_LOG")
        _exact_int(record["exit_status"], 0, "PRIVATE_TELEMETRY_COMMAND_LOG")
    return document


def _bind_command_log_to_capture(
    command_records: Sequence[dict[str, Any]], capture: dict[str, Any]
) -> None:
    expected_rows = [
        2,
        capture["public"]["rows"],
        capture["public"]["rows"],
        capture["owner_visible"]["rows"],
        capture["owner_visible"]["rows"],
    ]
    if len(command_records) != len(expected_rows):
        _fail("COMMAND_CAPTURE_COUNT")
    started = capture["capture"]["started_at_utc"]
    completed = capture["capture"]["completed_at_utc"]
    for command, rows in zip(command_records, expected_rows, strict=True):
        if (
            command["started_at_utc"] != started
            or command["completed_at_utc"] != completed
            or command["invocation_sha256"] != capture["capture"]["invocation_sha256"]
            or command["rows"] != rows
        ):
            _fail("COMMAND_CAPTURE_BINDING")


def _kill_external_process(process: subprocess.Popen[bytes]) -> bool:
    group_existed = False
    try:
        try:
            os.killpg(process.pid, 0)
            group_existed = True
        except ProcessLookupError:
            pass
        except OSError:
            group_existed = process.returncode is None
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except OSError:
            try:
                process.kill()
            except OSError:
                pass
        process.wait(timeout=10)
    except (OSError, subprocess.SubprocessError):
        _fail("EXTERNAL_PROCESS_CLEANUP")
    return group_existed


def _install_external_signal_guard() -> tuple[
    object, frozenset[int], dict[int, Any], Any
]:
    global _EXTERNAL_SIGNAL_OWNER
    if threading.current_thread() is not threading.main_thread():
        _fail("EXTERNAL_SIGNAL_GUARD")
    token = object()
    guarded = [signal.SIGINT, signal.SIGTERM]
    if hasattr(signal, "SIGHUP"):
        guarded.append(signal.SIGHUP)
    guarded_signals = frozenset(guarded)
    previous: dict[int, Any] = {}

    def handle(signum: int, _frame: Any) -> NoReturn:
        with _EXTERNAL_SIGNAL_OWNER_LOCK:
            process = (
                _EXTERNAL_ACTIVE_PROCESS if _EXTERNAL_SIGNAL_OWNER is token else None
            )
        if process is not None:
            try:
                _kill_external_process(process)
            except BaseException:
                pass
        if signum == signal.SIGINT:
            raise KeyboardInterrupt
        raise SystemExit(128 + signum)

    with _EXTERNAL_SIGNAL_OWNER_LOCK:
        if _EXTERNAL_SIGNAL_OWNER is not None or _GH_SIGNAL_OWNER is not None:
            _fail("EXTERNAL_SIGNAL_GUARD")
        _EXTERNAL_SIGNAL_OWNER = token
        try:
            for signum in guarded_signals:
                previous[signum] = signal.getsignal(signum)
                signal.signal(signum, handle)
        except (OSError, ValueError):
            for signum, handler in previous.items():
                try:
                    signal.signal(signum, handler)
                except (OSError, ValueError):
                    pass
            _EXTERNAL_SIGNAL_OWNER = None
            _fail("EXTERNAL_SIGNAL_GUARD")
    return token, guarded_signals, previous, handle


def _restore_external_signal_guard(
    token: object, previous: dict[int, Any], callback: Any
) -> None:
    global _EXTERNAL_ACTIVE_PROCESS, _EXTERNAL_SIGNAL_OWNER
    mismatch = False
    with _EXTERNAL_SIGNAL_OWNER_LOCK:
        if _EXTERNAL_SIGNAL_OWNER is not token:
            _fail("EXTERNAL_SIGNAL_GUARD")
        try:
            for signum, handler in previous.items():
                if signal.getsignal(signum) != callback:
                    mismatch = True
                    continue
                signal.signal(signum, handler)
        except (OSError, ValueError):
            mismatch = True
        finally:
            _EXTERNAL_ACTIVE_PROCESS = None
            _EXTERNAL_SIGNAL_OWNER = None
    if mismatch:
        _fail("EXTERNAL_SIGNAL_GUARD")


def _run_bounded_process(
    executable: Path,
    arguments: Sequence[str],
    *,
    environment: dict[str, str],
    stdin_payload: bytes = b"",
    stdout_limit: int,
    stderr_limit: int,
    timeout_seconds: int,
    allowed_return_codes: frozenset[int] = frozenset({0}),
) -> tuple[bytes, int]:
    if (
        type(stdout_limit) is not int
        or not 1 <= stdout_limit <= MAX_TRACKED_SCAN_BYTES + MAX_TRACKED_INDEX_BYTES
        or type(stderr_limit) is not int
        or not 1 <= stderr_limit <= MAX_JSON_BYTES
        or type(timeout_seconds) is not int
        or not 1 <= timeout_seconds <= 300
        or not isinstance(stdin_payload, bytes)
        or len(stdin_payload) > MAX_TRACKED_INDEX_BYTES
        or not allowed_return_codes
        or any(type(item) is not int for item in allowed_return_codes)
    ):
        _fail("EXTERNAL_PROCESS_ARGUMENT")
    process: subprocess.Popen[bytes] | None = None
    signal_guard: tuple[object, frozenset[int], dict[int, Any], Any] | None = None
    selector = selectors.DefaultSelector()
    stdout_payload = bytearray()
    stderr_payload = bytearray()
    input_offset = 0
    try:
        signal_guard = _install_external_signal_guard()
        token, guarded_signals, _previous, _callback = signal_guard
        try:
            previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, guarded_signals)
        except (AttributeError, OSError, ValueError):
            _fail("EXTERNAL_SIGNAL_GUARD")
        try:
            process = subprocess.Popen(
                (str(executable), *arguments),
                stdin=subprocess.PIPE if stdin_payload else subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=dict(environment),
                start_new_session=True,
            )
            with _EXTERNAL_SIGNAL_OWNER_LOCK:
                if _EXTERNAL_SIGNAL_OWNER is not token:
                    _kill_external_process(process)
                    _fail("EXTERNAL_SIGNAL_GUARD")
                global _EXTERNAL_ACTIVE_PROCESS
                _EXTERNAL_ACTIVE_PROCESS = process
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
        if process.stdout is None or process.stderr is None:
            _fail("EXTERNAL_PROCESS")
        for stream, label in (
            (process.stdout, "stdout"),
            (process.stderr, "stderr"),
        ):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, label)
        if stdin_payload:
            if process.stdin is None:
                _fail("EXTERNAL_PROCESS")
            os.set_blocking(process.stdin.fileno(), False)
            selector.register(process.stdin, selectors.EVENT_WRITE, "stdin")
        deadline = time.monotonic() + timeout_seconds
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _kill_external_process(process)
                _fail("EXTERNAL_PROCESS_TIMEOUT")
            events = selector.select(min(remaining, 0.1))
            if not events and process.poll() is not None:
                events = [
                    (key, selectors.EVENT_READ)
                    for key in list(selector.get_map().values())
                ]
            for key, _mask in events:
                stream = key.fileobj
                if key.data == "stdin":
                    try:
                        written = os.write(
                            stream.fileno(),
                            stdin_payload[input_offset : input_offset + 64 * 1024],
                        )
                    except (BlockingIOError, InterruptedError):
                        continue
                    except BrokenPipeError:
                        written = 0
                        input_offset = len(stdin_payload)
                    else:
                        input_offset += written
                    if input_offset == len(stdin_payload) or written == 0:
                        selector.unregister(stream)
                        stream.close()
                    continue
                try:
                    chunk = os.read(stream.fileno(), 64 * 1024)
                except (BlockingIOError, InterruptedError):
                    continue
                if not chunk:
                    selector.unregister(stream)
                    continue
                target = stdout_payload if key.data == "stdout" else stderr_payload
                target.extend(chunk)
                limit = stdout_limit if key.data == "stdout" else stderr_limit
                if len(target) > limit:
                    _kill_external_process(process)
                    _fail("EXTERNAL_PROCESS_OUTPUT_BOUND")
        remaining = deadline - time.monotonic()
        if remaining <= 0 and process.poll() is None:
            _kill_external_process(process)
            _fail("EXTERNAL_PROCESS_TIMEOUT")
        return_code = process.wait(timeout=max(remaining, 0.001))
        group_survived = _kill_external_process(process)
        if group_survived:
            _fail("EXTERNAL_PROCESS_DESCENDANT")
        if return_code not in allowed_return_codes:
            _fail("EXTERNAL_PROCESS_STATUS")
        return bytes(stdout_payload), return_code
    except InventoryError:
        if process is not None and process.returncode is None:
            _kill_external_process(process)
        raise
    except subprocess.TimeoutExpired:
        if process is not None:
            _kill_external_process(process)
        _fail("EXTERNAL_PROCESS_TIMEOUT")
    except (OSError, subprocess.SubprocessError):
        if process is not None:
            _kill_external_process(process)
        _fail("EXTERNAL_PROCESS")
    except BaseException:
        if process is not None:
            _kill_external_process(process)
        raise
    finally:
        selector.close()
        if process is not None:
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None and not stream.closed:
                    stream.close()
        if signal_guard is not None:
            token, _guarded, previous, callback = signal_guard
            _restore_external_signal_guard(token, previous, callback)


def _git_environment(sanitized_path: str) -> dict[str, str]:
    return {
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "LC_ALL": "C",
        "PATH": sanitized_path,
    }


def _git_run(
    git: Path,
    repository_root: Path,
    arguments: Sequence[str],
    *,
    environment: dict[str, str],
    stdin_payload: bytes = b"",
    stdout_limit: int = MAX_TRACKED_INDEX_BYTES,
    allowed_return_codes: frozenset[int] = frozenset({0}),
) -> tuple[bytes, int]:
    return _run_bounded_process(
        git,
        ("--no-replace-objects", "-C", str(repository_root), *arguments),
        environment=environment,
        stdin_payload=stdin_payload,
        stdout_limit=stdout_limit,
        stderr_limit=64 * 1024,
        timeout_seconds=GIT_TIMEOUT_SECONDS,
        allowed_return_codes=allowed_return_codes,
    )


def _contains_private_identifier_bytes(
    value: bytes,
    *,
    private_names: frozenset[str],
    private_urls: frozenset[str],
    private_ids: frozenset[int] = frozenset(),
    private_bounded_tokens: frozenset[str] = frozenset(),
    private_exact_literals: frozenset[str] = frozenset(),
    private_contextual_tokens: frozenset[tuple[str, str]] = frozenset(),
) -> bool:
    return _contains_private_identifier_text(
        value.decode("utf-8", errors="surrogateescape"),
        private_names=private_names,
        private_urls=private_urls,
        private_ids=private_ids,
        private_bounded_tokens=private_bounded_tokens,
        private_exact_literals=private_exact_literals,
        private_contextual_tokens=private_contextual_tokens,
    )


def _git_repository_root(
    git: Path, evidence_root: Path, environment: dict[str, str]
) -> Path:
    try:
        evidence = evidence_root.resolve(strict=True)
    except OSError:
        _fail("GIT_EVIDENCE_ROOT")
    payload, _status = _git_run(
        git,
        evidence,
        ("rev-parse", "--show-toplevel"),
        environment=environment,
        stdout_limit=64 * 1024,
    )
    try:
        rendered = payload.decode("utf-8").removesuffix("\n")
    except UnicodeDecodeError:
        _fail("GIT_REPOSITORY_ROOT")
    if not rendered or "\n" in rendered:
        _fail("GIT_REPOSITORY_ROOT")
    try:
        repository = Path(rendered).resolve(strict=True)
        evidence.relative_to(repository)
    except (OSError, ValueError):
        _fail("GIT_REPOSITORY_ROOT")
    return repository


def _parse_git_index(payload: bytes) -> list[tuple[bytes, bytes, bytes]]:
    if payload and not payload.endswith(b"\0"):
        _fail("GIT_INDEX_FORMAT")
    records: list[tuple[bytes, bytes, bytes]] = []
    seen_paths: set[bytes] = set()
    for raw in payload.split(b"\0")[:-1]:
        try:
            header, path = raw.split(b"\t", 1)
            mode, oid, stage = header.split(b" ")
        except ValueError:
            _fail("GIT_INDEX_FORMAT")
        if (
            mode not in {b"100644", b"100755"}
            or stage != b"0"
            or re.fullmatch(rb"[0-9a-f]{40}|[0-9a-f]{64}", oid) is None
            or not path
            or len(path) > 4_096
            or path in seen_paths
        ):
            _fail("GIT_INDEX_ENTRY")
        try:
            rendered = path.decode("utf-8")
        except UnicodeDecodeError:
            _fail("GIT_INDEX_PATH")
        parsed = PurePosixPath(rendered)
        if parsed.is_absolute() or str(parsed) != rendered or ".." in parsed.parts:
            _fail("GIT_INDEX_PATH")
        records.append((mode, path, oid))
        seen_paths.add(path)
        if len(records) > MAX_TRACKED_FILES:
            _fail("GIT_INDEX_FILE_BOUND")
    return records


def _git_blob_sizes(
    git: Path,
    repository_root: Path,
    environment: dict[str, str],
    oids: Sequence[bytes],
) -> dict[bytes, int]:
    if not oids:
        return {}
    stdin_payload = b"\n".join(oids) + b"\n"
    payload, _status = _git_run(
        git,
        repository_root,
        ("cat-file", "--batch-check"),
        environment=environment,
        stdin_payload=stdin_payload,
        stdout_limit=len(oids) * 128 + 1,
    )
    lines = payload.splitlines()
    if len(lines) != len(oids):
        _fail("GIT_BLOB_SIZE_FORMAT")
    sizes: dict[bytes, int] = {}
    for expected_oid, line in zip(oids, lines, strict=True):
        try:
            observed_oid, object_type, size_text = line.split(b" ")
        except ValueError:
            _fail("GIT_BLOB_SIZE_FORMAT")
        if (
            observed_oid != expected_oid
            or object_type != b"blob"
            or re.fullmatch(rb"0|[1-9][0-9]*", size_text) is None
        ):
            _fail("GIT_BLOB_SIZE_FORMAT")
        size = int(size_text)
        if size > MAX_TRACKED_FILE_BYTES:
            _fail("GIT_BLOB_FILE_BOUND")
        sizes[expected_oid] = size
    return sizes


def _git_blob_payloads(
    git: Path,
    repository_root: Path,
    environment: dict[str, str],
    oids: Sequence[bytes],
    sizes: dict[bytes, int],
) -> dict[bytes, bytes]:
    if not oids:
        return {}
    stdin_payload = b"\n".join(oids) + b"\n"
    output_limit = sum(sizes.values()) + len(oids) * 128 + 1
    payload, _status = _git_run(
        git,
        repository_root,
        ("cat-file", "--batch"),
        environment=environment,
        stdin_payload=stdin_payload,
        stdout_limit=output_limit,
    )
    result: dict[bytes, bytes] = {}
    offset = 0
    for expected_oid in oids:
        newline = payload.find(b"\n", offset)
        if newline < 0:
            _fail("GIT_BLOB_FORMAT")
        try:
            observed_oid, object_type, size_text = payload[offset:newline].split(b" ")
        except ValueError:
            _fail("GIT_BLOB_FORMAT")
        expected_size = sizes[expected_oid]
        if (
            observed_oid != expected_oid
            or object_type != b"blob"
            or size_text != str(expected_size).encode("ascii")
        ):
            _fail("GIT_BLOB_FORMAT")
        start = newline + 1
        end = start + expected_size
        if end >= len(payload) or payload[end : end + 1] != b"\n":
            _fail("GIT_BLOB_FORMAT")
        result[expected_oid] = payload[start:end]
        offset = end + 1
    if offset != len(payload):
        _fail("GIT_BLOB_FORMAT")
    return result


def _private_git_paths(
    private_paths: Sequence[Path], repository_root: Path
) -> tuple[str, ...]:
    rendered_paths: list[str] = []
    for private_path in private_paths:
        try:
            relative = private_path.resolve(strict=False).relative_to(repository_root)
        except (OSError, ValueError):
            _fail("PRIVATE_GIT_PATH")
        rendered = relative.as_posix()
        if not rendered or rendered.startswith("../"):
            _fail("PRIVATE_GIT_PATH")
        rendered_paths.append(rendered)
    if len(set(rendered_paths)) != len(rendered_paths):
        _fail("PRIVATE_GIT_PATH")
    return tuple(rendered_paths)


def _verify_private_git_paths(
    git: Path,
    repository_root: Path,
    environment: dict[str, str],
    private_paths: Sequence[str],
) -> frozenset[bytes]:
    provenance: set[bytes] = set()
    for rendered in private_paths:
        ignored, ignore_status = _git_run(
            git,
            repository_root,
            ("check-ignore", "--verbose", "-z", "--no-index", "--stdin"),
            environment=environment,
            stdin_payload=rendered.encode("utf-8") + b"\0",
            stdout_limit=16_384,
            allowed_return_codes=frozenset({0, 1}),
        )
        fields = ignored.split(b"\0")
        if (
            ignore_status != 0
            or len(fields) != 5
            or fields[-1] != b""
            or fields[3] != rendered.encode("utf-8")
            or not fields[0]
            or not fields[1]
            or not fields[2]
            or re.fullmatch(rb"[1-9][0-9]*", fields[1]) is None
        ):
            _fail("PRIVATE_GIT_IGNORE")
        try:
            source_text = fields[0].decode("utf-8")
            ignore_pattern = fields[2].decode("utf-8")
        except UnicodeDecodeError:
            _fail("PRIVATE_GIT_IGNORE")
        if ignore_pattern not in EXPECTED_PRIVATE_IGNORE_PATTERNS:
            _fail("PRIVATE_GIT_IGNORE")
        source_path = PurePosixPath(source_text)
        if (
            source_path.is_absolute()
            or str(source_path) != source_text
            or ".." in source_path.parts
        ):
            _fail("PRIVATE_GIT_IGNORE")
        provenance.add(fields[0])
        tracked, status = _git_run(
            git,
            repository_root,
            ("ls-files", "--error-unmatch", "--", rendered),
            environment=environment,
            stdout_limit=4_096,
            allowed_return_codes=frozenset({0, 1}),
        )
        if tracked or status != 1:
            _fail("PRIVATE_GIT_TRACKING")
    return frozenset(provenance)


def _parse_git_nul_paths(payload: bytes, code: str) -> frozenset[bytes]:
    if payload and not payload.endswith(b"\0"):
        _fail(code)
    paths: set[bytes] = set()
    for path in payload.split(b"\0")[:-1]:
        if not path or path in paths or len(path) > 4_096:
            _fail(code)
        try:
            rendered = path.decode("utf-8")
        except UnicodeDecodeError:
            _fail(code)
        parsed = PurePosixPath(rendered)
        if parsed.is_absolute() or str(parsed) != rendered or ".." in parsed.parts:
            _fail(code)
        paths.add(path)
        if len(paths) > MAX_TRACKED_FILES:
            _fail(code)
    return frozenset(paths)


def _git_candidate_state(
    git: Path,
    repository_root: Path,
    environment: dict[str, str],
    *,
    audit_path: bytes,
) -> tuple[frozenset[bytes], frozenset[bytes]]:
    worktree_payload, _status = _git_run(
        git,
        repository_root,
        ("diff", "--no-ext-diff", "--name-only", "-z", "--"),
        environment=environment,
        stdout_limit=MAX_TRACKED_INDEX_BYTES,
    )
    untracked_payload, _status = _git_run(
        git,
        repository_root,
        ("ls-files", "--others", "--exclude-standard", "-z"),
        environment=environment,
        stdout_limit=MAX_TRACKED_INDEX_BYTES,
    )
    worktree = _parse_git_nul_paths(worktree_payload, "GIT_WORKTREE_STATE")
    untracked = _parse_git_nul_paths(untracked_payload, "GIT_UNTRACKED_STATE")
    allowed = frozenset({audit_path})
    if worktree - allowed:
        _fail("GIT_WORKTREE_STATE")
    if untracked - allowed:
        _fail("GIT_UNTRACKED_STATE")
    return worktree, untracked


def _relative_git_path(path: Path, repository_root: Path, code: str) -> bytes:
    try:
        relative = path.resolve(strict=False).relative_to(repository_root)
    except (OSError, ValueError):
        _fail(code)
    rendered = relative.as_posix()
    if not rendered or rendered.startswith("../"):
        _fail(code)
    return rendered.encode("utf-8")


def _sealed_index_digest(
    records: Sequence[tuple[bytes, bytes, bytes]],
    *,
    sizes: dict[bytes, int],
    blobs: dict[bytes, bytes],
) -> str:
    manifest = [
        {
            "blob_sha256": sha256(blobs[oid]),
            "bytes": sizes[oid],
            "git_oid": oid.decode("ascii"),
            "mode": mode.decode("ascii"),
            "path": path.decode("utf-8"),
        }
        for mode, path, oid in records
    ]
    return sha256(canonical_json(manifest))


def _verify_ignore_index_state(
    git: Path,
    repository_root: Path,
    environment: dict[str, str],
    provenance: frozenset[bytes],
    index_by_path: dict[bytes, tuple[bytes, bytes]],
    blobs: dict[bytes, bytes],
) -> None:
    rendered_sources = tuple(source.decode("utf-8") for source in sorted(provenance))
    flags_payload, _status = _git_run(
        git,
        repository_root,
        ("ls-files", "-v", "-z", "--", *rendered_sources),
        environment=environment,
        stdout_limit=MAX_TRACKED_INDEX_BYTES,
    )
    observed_flags = frozenset(flags_payload.split(b"\0")[:-1])
    expected_flags = frozenset(b"H " + source for source in provenance)
    if (
        flags_payload
        and not flags_payload.endswith(b"\0")
        or observed_flags != expected_flags
    ):
        _fail("PRIVATE_GIT_IGNORE_INDEX_FLAGS")
    for source in provenance:
        indexed = index_by_path.get(source)
        if indexed is None:
            _fail("PRIVATE_GIT_IGNORE_PROVENANCE")
        mode, oid = indexed
        if mode != b"100644":
            _fail("PRIVATE_GIT_IGNORE_INDEX_MODE")
        observed = _read_bounded(
            repository_root / source.decode("utf-8"),
            MAX_TRACKED_FILE_BYTES,
            "PRIVATE_GIT_IGNORE_WORKTREE",
        )
        if blobs.get(oid) != observed:
            _fail("PRIVATE_GIT_IGNORE_WORKTREE")


def _private_write_preflight(
    *, evidence_root: Path, private_paths: Sequence[Path]
) -> None:
    sanitized_path = _sanitized_search_path()
    git = _resolve_safe_executable("git", sanitized_path=sanitized_path)
    environment = _git_environment(sanitized_path)
    repository_root = _git_repository_root(git, evidence_root, environment)
    relative_private_paths = _private_git_paths(private_paths, repository_root)
    provenance = _verify_private_git_paths(
        git, repository_root, environment, relative_private_paths
    )
    if not provenance:
        _fail("PRIVATE_GIT_IGNORE_PROVENANCE")
    index_payload, _status = _git_run(
        git,
        repository_root,
        ("ls-files", "--stage", "-z"),
        environment=environment,
        stdout_limit=MAX_TRACKED_INDEX_BYTES,
    )
    index_records = _parse_git_index(index_payload)
    index_by_path = {path: (mode, oid) for mode, path, oid in index_records}
    if not provenance <= set(index_by_path):
        _fail("PRIVATE_GIT_IGNORE_PROVENANCE")
    provenance_oids = sorted({index_by_path[source][1] for source in provenance})
    sizes = _git_blob_sizes(git, repository_root, environment, provenance_oids)
    blobs = _git_blob_payloads(
        git, repository_root, environment, provenance_oids, sizes
    )
    _verify_ignore_index_state(
        git, repository_root, environment, provenance, index_by_path, blobs
    )
    repeated_provenance = _verify_private_git_paths(
        git, repository_root, environment, relative_private_paths
    )
    repeated_index, _status = _git_run(
        git,
        repository_root,
        ("ls-files", "--stage", "-z"),
        environment=environment,
        stdout_limit=MAX_TRACKED_INDEX_BYTES,
    )
    if repeated_provenance != provenance or repeated_index != index_payload:
        _fail("PRIVATE_GIT_PREFLIGHT_DRIFT")


def _private_component_scan_payloads(
    expected_private_payloads: dict[Path, bytes],
) -> tuple[frozenset[bytes], frozenset[bytes], tuple[Any, ...]]:
    component_payloads: set[bytes] = set()
    operational_payloads: set[bytes] = set()
    operational_values: list[Any] = []
    for path, expected_payload in expected_private_payloads.items():
        payload = _read_bounded(
            path,
            MAX_JSON_BYTES,
            "PRIVATE_COMPONENT_PAYLOAD",
            required_mode=0o600,
        )
        if payload != expected_payload:
            _fail("PRIVATE_COMPONENT_DRIFT")
        component_payloads.add(payload)
        if path.name != PRIVATE_TELEMETRY_BASENAME:
            continue
        try:
            telemetry = json.loads(payload)
        except (UnicodeDecodeError, json.JSONDecodeError):
            _fail("PRIVATE_TELEMETRY_SCAN")
        if not isinstance(telemetry, dict):
            _fail("PRIVATE_TELEMETRY_SCAN")
        summaries = telemetry.get("summaries")
        command_log = telemetry.get("command_log")
        identity_rates = telemetry.get("identity_rates")
        identity_summary = telemetry.get("identity_summary")
        if (
            not isinstance(summaries, dict)
            or not isinstance(summaries.get("OWNER_VISIBLE"), list)
            or not isinstance(command_log, list)
            or not isinstance(identity_rates, list)
            or not isinstance(identity_summary, dict)
        ):
            _fail("PRIVATE_TELEMETRY_SCAN")
        sensitive_values: list[Any] = [
            identity_rates,
            identity_summary,
            identity_summary.get("rate_limit"),
            summaries,
            summaries["PUBLIC"],
            summaries["OWNER_VISIBLE"],
            *identity_rates,
            *summaries["PUBLIC"],
            *summaries["OWNER_VISIBLE"],
        ]
        sensitive_values.extend(
            summary.get("rate_limit")
            for scope in ("PUBLIC", "OWNER_VISIBLE")
            for summary in summaries[scope]
            if isinstance(summary, dict)
        )
        for record in command_log:
            if not isinstance(record, dict):
                _fail("PRIVATE_TELEMETRY_SCAN")
            sensitive_values.append(record)
        for value in sensitive_values:
            if not isinstance(value, (dict, list)):
                _fail("PRIVATE_TELEMETRY_SCAN")
            operational_payloads.add(canonical_json(value))
            operational_values.append(value)
    return (
        frozenset(component_payloads),
        frozenset(operational_payloads),
        tuple(operational_values),
    )


def _contains_private_operational_payload(
    payload: bytes,
    forbidden_payloads: frozenset[bytes],
    forbidden_values: Sequence[Any],
) -> bool:
    if not forbidden_payloads and not forbidden_values:
        return False
    if payload in forbidden_payloads or any(
        forbidden in payload for forbidden in forbidden_payloads
    ):
        return True
    text = payload.decode("utf-8", errors="surrogateescape")
    decoder = json.JSONDecoder()
    pending_text = [text]
    seen_text: set[str] = set()
    stack: list[Any] = []
    remaining_candidates = MAX_OPERATIONAL_JSON_CANDIDATES
    remaining_text_bytes = MAX_OPERATIONAL_JSON_WORK_BYTES
    remaining_decoded_characters = MAX_OPERATIONAL_JSON_WORK_BYTES
    remaining_nodes = MAX_OPERATIONAL_JSON_NODES
    remaining_structural_matches = [MAX_OPERATIONAL_JSON_NODES]
    while pending_text or stack:
        if pending_text:
            candidate_text = pending_text.pop()
            if candidate_text in seen_text:
                continue
            seen_text.add(candidate_text)
            remaining_text_bytes -= len(
                candidate_text.encode("utf-8", errors="surrogatepass")
            )
            if remaining_text_bytes < 0:
                _fail("PRIVATE_TELEMETRY_SCAN_BOUND")
            normalized_lines = re.sub(
                r"(?m)^(?:[ \t]{0,3}[>+\-][ \t]?)+",
                "",
                candidate_text,
            )
            if normalized_lines != candidate_text and normalized_lines not in seen_text:
                pending_text.append(normalized_lines)
            offset = 0
            while offset < len(candidate_text):
                if candidate_text[offset] not in '{["':
                    offset += 1
                    continue
                remaining_candidates -= 1
                if remaining_candidates < 0:
                    _fail("PRIVATE_TELEMETRY_SCAN_BOUND")
                try:
                    value, end = decoder.raw_decode(candidate_text, offset)
                except (json.JSONDecodeError, RecursionError):
                    offset += 1
                    continue
                remaining_decoded_characters -= end - offset
                if remaining_decoded_characters < 0:
                    _fail("PRIVATE_TELEMETRY_SCAN_BOUND")
                if isinstance(value, (dict, list)) or (
                    isinstance(value, str) and any(marker in value for marker in "{[")
                ):
                    stack.append(value)
                offset = (
                    offset + 1
                    if isinstance(value, (dict, list))
                    else max(end, offset + 1)
                )
            continue
        remaining_nodes -= 1
        if remaining_nodes < 0:
            _fail("PRIVATE_TELEMETRY_SCAN_BOUND")
        value = stack.pop()
        if isinstance(value, str):
            if value not in seen_text:
                pending_text.append(value)
            continue
        if not isinstance(value, (dict, list)):
            continue
        for forbidden in forbidden_values:
            if _private_structural_contains(
                value, forbidden, remaining_structural_matches
            ):
                return True
    return False


def _private_structural_contains(
    candidate: Any, expected: Any, remaining: list[int]
) -> bool:
    remaining[0] -= 1
    if remaining[0] < 0:
        _fail("PRIVATE_TELEMETRY_SCAN_BOUND")
    if isinstance(expected, dict):
        return isinstance(candidate, dict) and all(
            key in candidate
            and _private_structural_contains(candidate[key], value, remaining)
            for key, value in expected.items()
        )
    if isinstance(expected, list):
        if not isinstance(candidate, list) or len(candidate) < len(expected):
            return False
        return any(
            all(
                _private_structural_contains(
                    candidate[start + offset], value, remaining
                )
                for offset, value in enumerate(expected)
            )
            for start in range(len(candidate) - len(expected) + 1)
        )
    return type(candidate) is type(expected) and candidate == expected


def _git_privacy_closure(
    *,
    evidence_root: Path,
    expected_private_payloads: dict[Path, bytes],
    private_records: Sequence[dict[str, Any]],
    public_records: Sequence[dict[str, Any]],
    audit_path: Path,
    required_staged_payloads: dict[Path, bytes],
    audit_payload: bytes | None,
) -> tuple[dict[str, Any], str]:
    (
        private_component_payloads,
        private_operational_payloads,
        private_operational_values,
    ) = _private_component_scan_payloads(expected_private_payloads)
    private_paths = tuple(expected_private_payloads)
    private_names, private_urls, private_ids = _private_identifier_tokens(
        private_records, public_records
    )
    (
        private_bounded_tokens,
        private_exact_literals,
        private_contextual_tokens,
    ) = _private_raw_identifier_tokens(private_records, public_records)
    local_path_literals: set[str] = set(private_exact_literals)
    for path in private_paths:
        try:
            resolved_private_path = path.resolve(strict=False)
            local_path_literals.add(str(resolved_private_path).casefold())
            local_path_literals.add(resolved_private_path.as_uri().casefold())
        except (OSError, ValueError):
            _fail("PRIVATE_GIT_PATH")
    private_exact_literals = frozenset(local_path_literals)
    sanitized_path = _sanitized_search_path()
    git = _resolve_safe_executable("git", sanitized_path=sanitized_path)
    environment = _git_environment(sanitized_path)
    repository_root = _git_repository_root(git, evidence_root, environment)
    relative_private_paths = _private_git_paths(private_paths, repository_root)
    expanded_path_literals = set(private_exact_literals)
    for rendered_private_path in relative_private_paths:
        if "/" in rendered_private_path and not rendered_private_path.endswith(
            PRIVATE_LEDGER_BASENAME
        ):
            expanded_path_literals.add(rendered_private_path.casefold())
            expanded_path_literals.add(quote(rendered_private_path, safe="").casefold())
    private_exact_literals = frozenset(expanded_path_literals)
    relative_audit_path = _relative_git_path(
        audit_path, repository_root, "GIT_AUDIT_PATH"
    )
    required_payloads: dict[bytes, bytes] = {}
    for path, payload in required_staged_payloads.items():
        relative = _relative_git_path(
            path, repository_root, "GIT_REQUIRED_STAGED_OUTPUT"
        )
        if relative == relative_audit_path or relative in required_payloads:
            _fail("GIT_REQUIRED_STAGED_OUTPUT")
        required_payloads[relative] = payload
    ignore_provenance = _verify_private_git_paths(
        git, repository_root, environment, relative_private_paths
    )
    worktree, untracked = _git_candidate_state(
        git,
        repository_root,
        environment,
        audit_path=relative_audit_path,
    )
    index_payload, _status = _git_run(
        git,
        repository_root,
        ("ls-files", "--stage", "-z"),
        environment=environment,
        stdout_limit=MAX_TRACKED_INDEX_BYTES,
    )
    index_records = _parse_git_index(index_payload)
    index_by_path = {path: (mode, oid) for mode, path, oid in index_records}
    filtered_records = [
        (mode, path, oid)
        for mode, path, oid in index_records
        if path != relative_audit_path
    ]
    if not ignore_provenance or not ignore_provenance <= set(index_by_path):
        _fail("PRIVATE_GIT_IGNORE_PROVENANCE")
    if not set(required_payloads) <= set(index_by_path):
        _fail("GIT_REQUIRED_STAGED_OUTPUT")
    for _mode, path, _oid in filtered_records:
        if _contains_private_identifier_bytes(
            path,
            private_names=private_names,
            private_urls=private_urls,
            private_ids=private_ids,
            private_bounded_tokens=private_bounded_tokens,
            private_exact_literals=private_exact_literals,
            private_contextual_tokens=private_contextual_tokens,
        ):
            _fail("PRIVATE_IDENTIFIER_TRACKED_LEAK")
    unique_oids = sorted({oid for _mode, _path, oid in filtered_records})
    sizes = _git_blob_sizes(git, repository_root, environment, unique_oids)
    total_bytes = sum(sizes[oid] for _mode, _path, oid in filtered_records)
    if total_bytes > MAX_TRACKED_SCAN_BYTES:
        _fail("GIT_BLOB_AGGREGATE_BOUND")
    blobs = _git_blob_payloads(git, repository_root, environment, unique_oids, sizes)
    _verify_ignore_index_state(
        git,
        repository_root,
        environment,
        ignore_provenance,
        index_by_path,
        blobs,
    )
    for payload in blobs.values():
        if payload in private_component_payloads:
            _fail("PRIVATE_COMPONENT_TRACKED_LEAK")
        if _contains_private_operational_payload(
            payload,
            private_operational_payloads,
            private_operational_values,
        ):
            _fail("PRIVATE_TELEMETRY_TRACKED_LEAK")
        if _contains_private_identifier_bytes(
            payload,
            private_names=private_names,
            private_urls=private_urls,
            private_ids=private_ids,
            private_bounded_tokens=private_bounded_tokens,
            private_exact_literals=private_exact_literals,
            private_contextual_tokens=private_contextual_tokens,
        ):
            _fail("PRIVATE_IDENTIFIER_TRACKED_LEAK")
    for path, expected_payload in required_payloads.items():
        mode, oid = index_by_path[path]
        if mode != b"100644":
            _fail("GIT_REQUIRED_STAGED_MODE")
        if blobs.get(oid) != expected_payload:
            _fail("GIT_REQUIRED_STAGED_OUTPUT")
    seal_state = "PRE_AUDIT_SEAL_READY"
    if audit_payload is not None:
        if relative_audit_path in worktree or relative_audit_path in untracked:
            try:
                observed_audit = _read_bounded(
                    audit_path, MAX_JSON_BYTES, "GIT_AUDIT_PAYLOAD"
                )
            except OSError:
                _fail("GIT_AUDIT_PAYLOAD")
            if observed_audit != audit_payload:
                _fail("GIT_AUDIT_PAYLOAD")
            seal_state = "AUDIT_UNSTAGED_READY"
        else:
            indexed_audit = index_by_path.get(relative_audit_path)
            if indexed_audit is None:
                _fail("GIT_AUDIT_STAGE")
            mode, audit_oid = indexed_audit
            if mode != b"100644":
                _fail("GIT_AUDIT_MODE")
            audit_size = _git_blob_sizes(
                git, repository_root, environment, (audit_oid,)
            )
            indexed_payload = _git_blob_payloads(
                git, repository_root, environment, (audit_oid,), audit_size
            ).get(audit_oid)
            if indexed_payload != audit_payload:
                _fail("GIT_AUDIT_STAGE")
            seal_state = "AUDIT_STAGED_FINAL"
    _verify_ignore_index_state(
        git,
        repository_root,
        environment,
        ignore_provenance,
        index_by_path,
        blobs,
    )
    repeated_provenance = _verify_private_git_paths(
        git, repository_root, environment, relative_private_paths
    )
    if repeated_provenance != ignore_provenance:
        _fail("PRIVATE_GIT_IGNORE_PROVENANCE")
    final_worktree, final_untracked = _git_candidate_state(
        git,
        repository_root,
        environment,
        audit_path=relative_audit_path,
    )
    if final_worktree != worktree or final_untracked != untracked:
        _fail("GIT_WORKTREE_STATE")
    final_index_payload, _status = _git_run(
        git,
        repository_root,
        ("ls-files", "--stage", "-z"),
        environment=environment,
        stdout_limit=MAX_TRACKED_INDEX_BYTES,
    )
    if final_index_payload != index_payload:
        _fail("GIT_INDEX_DRIFT")
    (
        repeated_components,
        repeated_operational,
        repeated_operational_values,
    ) = _private_component_scan_payloads(expected_private_payloads)
    if (
        repeated_components != private_component_payloads
        or repeated_operational != private_operational_payloads
        or repeated_operational_values != private_operational_values
    ):
        _fail("PRIVATE_COMPONENT_DRIFT")
    receipt = {
        "result": "PASS",
        "scan_configuration_sha256": sha256(
            canonical_json(CROSS_LANE_SCAN_CONFIGURATION)
        ),
        "sealed_index_sha256": _sealed_index_digest(
            filtered_records, sizes=sizes, blobs=blobs
        ),
        "tracked_bytes": total_bytes,
        "tracked_files": len(filtered_records),
    }
    return receipt, seal_state


def _private_identifier_tokens(
    private_records: Sequence[dict[str, Any]],
    public_records: Sequence[dict[str, Any]],
) -> tuple[frozenset[str], frozenset[str], frozenset[int]]:
    public_names = {str(record["repository"]).casefold() for record in public_records}
    public_urls = {str(record["canonical_url"]).casefold() for record in public_records}
    private_names = {str(record["repository"]).casefold() for record in private_records}
    private_urls = {
        str(record["canonical_url"]).casefold() for record in private_records
    }
    public_ids = {record["repository_id"] for record in public_records}
    private_ids = {
        record["repository_id"]
        for record in private_records
        if record["repository_id"] not in public_ids
    }
    if (
        private_names & public_names
        or private_urls & public_urls
        or len(private_names) != len(private_records)
        or len(private_urls) != len(private_records)
        or len(private_ids) != len(private_records)
    ):
        _fail("PRIVATE_IDENTIFIER_AMBIGUITY")
    return (
        frozenset(private_names),
        frozenset(private_urls),
        frozenset(private_ids),
    )


def _private_raw_identifier_tokens(
    private_records: Sequence[dict[str, Any]],
    public_records: Sequence[dict[str, Any]],
) -> tuple[
    frozenset[str],
    frozenset[str],
    frozenset[tuple[str, str]],
]:
    public_heads = {
        str(record["exact_head"]).casefold()
        for record in public_records
        if isinstance(record.get("exact_head"), str)
    }
    private_heads = {
        str(record["exact_head"]).casefold()
        for record in private_records
        if isinstance(record.get("exact_head"), str)
    }
    public_branches = {
        str(record["default_branch"]).casefold()
        for record in public_records
        if isinstance(record.get("default_branch"), str)
    }
    private_branches = {
        str(record["default_branch"]).casefold()
        for record in private_records
        if isinstance(record.get("default_branch"), str)
    }
    private_only_branches = private_branches - public_branches
    common_branches = {"develop", "development", "main", "master", "trunk"}
    distinctive_branches = {
        branch
        for branch in private_only_branches
        if branch not in common_branches
        and (
            len(branch) >= 6
            or (len(branch) >= 4 and any(character.isdigit() for character in branch))
        )
    }
    public_basenames = {
        str(record["repository"]).rsplit("/", 1)[-1].casefold()
        for record in public_records
        if isinstance(record.get("repository"), str)
    }
    private_basenames = {
        str(record["repository"]).rsplit("/", 1)[-1].casefold()
        for record in private_records
        if isinstance(record.get("repository"), str)
    }
    distinctive_basenames = {
        basename
        for basename in private_basenames - public_basenames
        if len(basename) >= 6
    }
    bounded_tokens = (
        (private_heads - public_heads) | distinctive_branches | distinctive_basenames
    )
    contextual_tokens: set[tuple[str, str]] = {
        *(("branch", branch) for branch in private_only_branches),
        *(
            ("repository", basename)
            for basename in private_basenames - public_basenames
        ),
        *(
            ("git_basename", basename)
            for basename in private_basenames - public_basenames
        ),
    }
    for private_head in private_heads - public_heads:
        for length in range(4, len(private_head)):
            prefix = private_head[:length]
            if not any(public_head.startswith(prefix) for public_head in public_heads):
                contextual_tokens.add(("oid_prefix", prefix))
    public_ids = {
        record["repository_id"]
        for record in public_records
        if type(record.get("repository_id")) is int
    }
    private_ids = {
        record["repository_id"]
        for record in private_records
        if type(record.get("repository_id")) is int
        and record["repository_id"] not in public_ids
    }
    contextual_tokens.update(
        ("repository_id", str(repository_id)) for repository_id in private_ids
    )
    exact_literals = {
        literal
        for repository_id in private_ids
        for literal in (
            f'"repository_id":{repository_id}',
            f'"repository_id": {repository_id}',
        )
    }
    for record in private_records:
        repository = str(record["repository"]).casefold()
        canonical_url = str(record["canonical_url"]).casefold()
        exact_literals.add(quote(repository, safe="").casefold())
        exact_literals.add(quote(canonical_url, safe="").casefold())
    exact_literals.update(
        literal
        for repository_id in private_ids
        for literal in (
            f"repository id {repository_id}",
            f"repository id: {repository_id}",
            f"repository-id={repository_id}",
            f"repository_id={repository_id}",
        )
    )
    exact_literals.update(
        literal
        for branch in private_only_branches
        for literal in (
            f'"default_branch":{json.dumps(branch)}',
            f'"default_branch": {json.dumps(branch)}',
            f"default_branch={branch}",
            f"default_branch,{branch}",
            f"refs/heads/{branch}",
            f"/git/ref/heads/{quote(branch, safe='').casefold()}",
        )
    )
    public_authored = {
        str(record[field]).casefold()
        for record in public_records
        for field in ("justification", "reviewer")
        if isinstance(record.get(field), str)
    }
    private_authored = {
        str(record[field]).casefold()
        for record in private_records
        for field in ("justification", "reviewer")
        if isinstance(record.get(field), str)
    }
    for authored in private_authored - public_authored:
        if len(authored) >= 8:
            exact_literals.add(authored)
        exact_literals.update(
            token
            for token in re.findall(r"[a-z0-9][a-z0-9_.-]{11,}", authored)
            if any(character.isdigit() for character in token)
            and any(character in "_-" for character in token)
        )
    return (
        frozenset(bounded_tokens),
        frozenset(exact_literals),
        frozenset(contextual_tokens),
    )


def _contains_private_identifier_text_direct(
    value: str,
    *,
    private_names: frozenset[str],
    private_urls: frozenset[str],
    private_bounded_tokens: frozenset[str] = frozenset(),
    private_exact_literals: frozenset[str] = frozenset(),
    private_contextual_tokens: frozenset[tuple[str, str]] = frozenset(),
) -> bool:
    folded = value.casefold()
    return any(
        pattern.search(folded) is not None
        for pattern in _compiled_private_text_patterns(
            private_names,
            private_urls,
            private_bounded_tokens,
            private_exact_literals,
            private_contextual_tokens,
        )
    )


def _literal_alternation(tokens: frozenset[str]) -> str:
    """Return one deterministic literal-only regular-expression alternative."""
    if not tokens:
        _fail("PRIVATE_IDENTIFIER_CONFIGURATION")
    return "(?:" + "|".join(
        re.escape(token) for token in sorted(tokens, key=lambda item: (-len(item), item))
    ) + ")"


@functools.lru_cache(maxsize=16)
def _compiled_private_text_patterns(
    private_names: frozenset[str],
    private_urls: frozenset[str],
    private_bounded_tokens: frozenset[str],
    private_exact_literals: frozenset[str],
    private_contextual_tokens: frozenset[tuple[str, str]],
) -> tuple[re.Pattern[str], ...]:
    """Compile one bounded deterministic scan policy per private token set.

    Each pattern is an OR-combination of the same escaped literal alternatives
    that the prior scanner evaluated one at a time.  Compiling once avoids a
    token-by-value multiplicative scan while retaining the original boundaries.
    """

    patterns: list[re.Pattern[str]] = []
    repository_end = r"(?:\.git)?(?![a-z0-9_-]|\.[a-z0-9_.-])"
    if private_urls:
        patterns.append(
            re.compile(rf"{_literal_alternation(private_urls)}{repository_end}")
        )
    if private_exact_literals:
        patterns.append(re.compile(_literal_alternation(private_exact_literals)))
    context_separator = r"(?:\s*[:=,]\s*|[\s_./-]+)"
    transparent_context = r"(?:edges?|metadata|nodes?|target|[0-9]+)"
    repository_context = r"(?:repositories|repository|repos?)"
    repository_identity_path = (
        rf"{repository_context}(?:{context_separator}{transparent_context}){{0,8}}"
    )
    git_path_prefix = r"/?(?:[a-z0-9_.~-]{1,128}/){0,8}"
    branch_context = (
        r"(?:branches?|default[\s_-]*branch[\s_-]*ref|"
        r"head[\s_-]*ref|base[\s_-]*ref|refs?)"
    )
    branch_identity_path = (
        rf"{branch_context}(?:{context_separator}{transparent_context}){{0,8}}"
    )
    contextual_lookup = _contextual_token_lookup(private_contextual_tokens)
    for kind in sorted(contextual_lookup):
        escaped = _literal_alternation(contextual_lookup[kind])
        if kind == "branch":
            pattern = (
                r"(?<![a-z0-9])(?:branch(?:es)?|default[\s_-]*branch|"
                r"head[\s_-]*ref(?:[\s_-]*name)?|"
                r"base[\s_-]*ref(?:[\s_-]*name)?|"
                r"refs?(?:[\s_-]*name)?|sha|"
                r"git\s+(?:checkout(?:\s+-b)?|switch(?:\s+-c)?))"
                rf"[\"']?{context_separator}[\"']?{escaped}[\"']?"
                r"(?![a-z0-9_-])"
                rf"|refs/(?:heads|remotes/[^/\s]{{1,128}})/{escaped}"
                r"(?![a-z0-9_-])"
                rf"|(?<![a-z0-9])(?:branches|commits|tree)/{escaped}"
                r"(?![a-z0-9_-])"
                rf"|(?<![a-z0-9]){branch_identity_path}"
                rf"{context_separator}names?{context_separator}{escaped}"
                r"(?![a-z0-9_-])"
            )
        elif kind == "repository":
            pattern = (
                rf"(?<![a-z0-9])(?:(?:private[\s_-]+)?{repository_context}|"
                r"(?:repository|repo)[\s_-]*names?|"
                r"(?:git|gh\s+repo)\s+clone|submodules?)"
                rf"[\"']?{context_separator}[\"']?{escaped}[\"']?"
                r"(?![a-z0-9_-])"
                rf"|(?<![a-z0-9]){repository_identity_path}"
                rf"{context_separator}names?{context_separator}{escaped}"
                r"(?:\.git)?(?![a-z0-9_.-])"
                rf"|(?<![a-z0-9])\[submodule\s+[\"']{escaped}[\"']\]"
                rf"|(?<![a-z0-9])remote[._/-][a-z0-9_.-]{{1,128}}"
                rf"[._/-]url[\"']?{context_separator}[\"']?(?:\.\./)*{escaped}"
                r"(?:\.git)?(?![a-z0-9_.-])"
                rf"|(?<![a-z0-9])git\s+remote\s+add\s+\S{{1,128}}\s+"
                rf"(?:\.\./)*{escaped}(?:\.git)?(?![a-z0-9_.-])"
                rf"|(?<![a-z0-9])git\s+fetch\s+[\"']?{git_path_prefix}"
                rf"{escaped}(?:\.git)?[\"']?(?![a-z0-9_.-])"
                rf"|(?<![a-z0-9])git\s+-c\s+[\"']?{git_path_prefix}"
                rf"{escaped}(?:\.git)?[\"']?(?=\s|$)"
            )
        elif kind == "git_basename":
            pattern = rf"(?<![a-z0-9_.-]){escaped}\.git(?![a-z0-9_.-])"
        elif kind == "oid_prefix":
            pattern = (
                r"(?<![a-z0-9])(?:heads?|commits?|objects?|oids?|sha|"
                r"head[\s_-]*(?:sha|oid)|commit[\s_-]*(?:sha|oid)|"
                r"object[\s_-]*(?:sha|oid))"
                rf"[\"']?{context_separator}[\"']?{escaped}[\"']?"
                r"(?![a-z0-9])"
                rf"|(?<![a-z0-9])git\s+rev-parse\s+{escaped}(?![a-z0-9])"
            )
        elif kind == "repository_id":
            pattern = (
                r"(?<![a-z0-9])(?:repository|repositories|repos?)[\s_-]*ids?[\"']?"
                rf"{context_separator}[\"']?{escaped}[\"']?"
                r"(?![0-9])"
                rf"|(?<![a-z0-9])repositories/{escaped}(?![0-9])"
                rf"|(?<![a-z0-9]){repository_identity_path}"
                rf"{context_separator}(?:database[\s_-]*id|id)"
                rf"{context_separator}{escaped}(?![0-9])"
                r"|(?m:^[\t ]*database[\s_-]*id[\"']?"
                rf"{context_separator}[\"']?{escaped}[\"']?(?![0-9]))"
            )
        else:
            _fail("PRIVATE_IDENTIFIER_CONFIGURATION")
        patterns.append(re.compile(pattern))
    bounded_hex = frozenset(
        token for token in private_bounded_tokens if HEX40.fullmatch(token) is not None
    )
    bounded_other = private_bounded_tokens - bounded_hex
    if bounded_hex:
        patterns.append(
            re.compile(
                rf"(?<![0-9a-f]){_literal_alternation(bounded_hex)}(?![0-9a-f])"
            )
        )
    if bounded_other:
        patterns.append(
            re.compile(
                rf"(?<![a-z0-9_.-]){_literal_alternation(bounded_other)}"
                r"(?![a-z0-9_.-])"
            )
        )
    if private_names:
        patterns.append(
            re.compile(
                rf"(?<![a-z0-9_.-]){_literal_alternation(private_names)}"
                rf"{repository_end}"
            )
        )
    return tuple(patterns)


def _decoded_json_string_representations(value: str) -> tuple[str, ...]:
    if "\\" not in value:
        return ()
    decoder = json.JSONDecoder()
    pending = [value]
    seen: set[str] = set()
    representations: list[str] = []
    remaining_candidates = MAX_OPERATIONAL_JSON_CANDIDATES
    remaining_bytes = MAX_OPERATIONAL_JSON_WORK_BYTES
    while pending:
        text = pending.pop()
        if text in seen:
            continue
        seen.add(text)
        remaining_bytes -= len(text.encode("utf-8", errors="surrogatepass"))
        if remaining_bytes < 0:
            _fail("PRIVATE_IDENTIFIER_JSON_BOUND")
        parts: list[str] = []
        cursor = 0
        offset = 0
        changed = False
        while offset < len(text):
            quote_offset = text.find('"', offset)
            if quote_offset < 0:
                break
            offset = quote_offset
            remaining_candidates -= 1
            if remaining_candidates < 0:
                _fail("PRIVATE_IDENTIFIER_JSON_BOUND")
            try:
                decoded, end = decoder.raw_decode(text, offset)
            except (json.JSONDecodeError, RecursionError):
                offset += 1
                continue
            if not isinstance(decoded, str):
                offset += 1
                continue
            original_token = text[offset:end]
            rendered_token = json.dumps(decoded, ensure_ascii=False)
            parts.append(text[cursor:offset])
            parts.append(rendered_token)
            cursor = end
            offset = end
            changed = changed or rendered_token != original_token
            representations.append(decoded)
            if "\\" in decoded and decoded not in seen:
                pending.append(decoded)
        if cursor:
            parts.append(text[cursor:])
            normalized = "".join(parts)
            if changed and normalized != text:
                representations.append(normalized)
                if "\\" in normalized and normalized not in seen:
                    pending.append(normalized)
    return tuple(representations)


def _contains_private_identifier_text(
    value: str,
    *,
    private_names: frozenset[str],
    private_urls: frozenset[str],
    private_ids: frozenset[int] = frozenset(),
    private_bounded_tokens: frozenset[str] = frozenset(),
    private_exact_literals: frozenset[str] = frozenset(),
    private_contextual_tokens: frozenset[tuple[str, str]] = frozenset(),
) -> bool:
    arguments = {
        "private_names": private_names,
        "private_urls": private_urls,
        "private_bounded_tokens": private_bounded_tokens,
        "private_exact_literals": private_exact_literals,
        "private_contextual_tokens": private_contextual_tokens,
    }
    representations = (value, *_decoded_json_string_representations(value))
    if any(
        _contains_private_identifier_text_direct(candidate, **arguments)
        for candidate in representations
    ):
        return True
    return _contains_private_identifier_in_embedded_json(
        representations,
        private_ids=private_ids,
        private_contextual_tokens=private_contextual_tokens,
    )


def _normalized_context_key(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    return re.sub(r"[\s_-]", "", value.casefold())


@functools.lru_cache(maxsize=16)
def _contextual_token_lookup(
    tokens: frozenset[tuple[str, str]],
) -> dict[str, frozenset[str]]:
    kinds: dict[str, set[str]] = {}
    for kind, token in tokens:
        kinds.setdefault(kind, set()).add(token)
    return {kind: frozenset(values) for kind, values in kinds.items()}


def _contextual_string_candidates(value: Any) -> frozenset[str]:
    if not isinstance(value, str):
        return frozenset()
    return frozenset(
        candidate.casefold()
        for candidate in (value, *_decoded_json_string_representations(value))
    )


def _identity_context_active(
    path: Sequence[Any],
    anchors: frozenset[str],
) -> bool:
    active = False
    for component in path:
        normalized = _normalized_context_key(component)
        if normalized in anchors:
            active = True
        elif active and (
            normalized in IDENTITY_TRANSPARENT_CONTEXT_KEYS
            or (isinstance(component, str) and component.isdecimal())
            or type(component) is int
        ):
            continue
        else:
            active = False
    return active


def _structured_private_identifier_match(
    key: Any,
    item: Any,
    *,
    path: Sequence[Any],
    contextual_lookup: dict[str, frozenset[str]],
    private_ids: frozenset[int],
) -> bool:
    normalized_key = _normalized_context_key(key)
    repository_identity = _identity_context_active(path, REPOSITORY_ENTITY_CONTEXT_KEYS)
    branch_identity = _identity_context_active(path, BRANCH_ENTITY_CONTEXT_KEYS)
    string_candidates = _contextual_string_candidates(item)
    branch_values = contextual_lookup.get("branch", frozenset())
    repository_values = contextual_lookup.get("repository", frozenset())
    oid_values = contextual_lookup.get("oid_prefix", frozenset())
    if (
        normalized_key in BRANCH_CONTEXT_KEYS
        or (normalized_key == "name" and branch_identity)
    ) and string_candidates & branch_values:
        return True
    if (
        normalized_key in REPOSITORY_CONTEXT_KEYS
        or (normalized_key == "name" and repository_identity)
    ) and string_candidates & repository_values:
        return True
    if normalized_key in OID_CONTEXT_KEYS and string_candidates & oid_values:
        return True
    numeric_candidates = {
        int(candidate)
        for candidate in string_candidates
        if re.fullmatch(r"[0-9]+", candidate) is not None
    }
    structured_repository_ids = {item} if type(item) is int else numeric_candidates
    root_sequence = not path or all(
        (isinstance(component, str) and component.isdecimal()) or type(component) is int
        for component in path
    )
    repository_id_context = (
        normalized_key in REPOSITORY_ID_CONTEXT_KEYS
        or (normalized_key in {"databaseid", "id"} and repository_identity)
        or (normalized_key == "databaseid" and root_sequence)
    )
    return bool(repository_id_context and structured_repository_ids & private_ids)


def _contains_private_identifier_in_structured_value(
    value: Any,
    *,
    contextual_lookup: dict[str, frozenset[str]],
    private_ids: frozenset[int],
    remaining_nodes: list[int],
) -> bool:
    stack: list[tuple[Any, tuple[Any, ...]]] = [(value, ())]
    while stack:
        remaining_nodes[0] -= 1
        if remaining_nodes[0] < 0:
            _fail("PRIVATE_IDENTIFIER_JSON_BOUND")
        node, path = stack.pop()
        if isinstance(node, list):
            stack.extend(
                (item, (*path, str(index)))
                for index, item in reversed(tuple(enumerate(node)))
            )
            continue
        if not isinstance(node, dict):
            continue
        for key, item in node.items():
            if _structured_private_identifier_match(
                key,
                item,
                path=path,
                contextual_lookup=contextual_lookup,
                private_ids=private_ids,
            ):
                return True
            stack.append((item, (*path, key)))
    return False


def _contains_private_identifier_in_embedded_json(
    values: Sequence[str],
    *,
    private_ids: frozenset[int],
    private_contextual_tokens: frozenset[tuple[str, str]],
) -> bool:
    decoder = json.JSONDecoder()
    contextual_lookup = _contextual_token_lookup(private_contextual_tokens)
    remaining_candidates = MAX_OPERATIONAL_JSON_CANDIDATES
    remaining_text_bytes = MAX_OPERATIONAL_JSON_WORK_BYTES
    remaining_decoded_characters = MAX_OPERATIONAL_JSON_WORK_BYTES
    remaining_nodes = [MAX_OPERATIONAL_JSON_NODES]
    seen: set[str] = set()
    for text in values:
        if text in seen:
            continue
        seen.add(text)
        remaining_text_bytes -= len(text.encode("utf-8", errors="surrogatepass"))
        if remaining_text_bytes < 0:
            _fail("PRIVATE_IDENTIFIER_JSON_BOUND")
        offset = 0
        while offset < len(text):
            match = JSON_CONTAINER_START.search(text, offset)
            if match is None:
                break
            offset = match.start()
            remaining_candidates -= 1
            if remaining_candidates < 0:
                _fail("PRIVATE_IDENTIFIER_JSON_BOUND")
            try:
                candidate, end = decoder.raw_decode(text, offset)
            except (json.JSONDecodeError, RecursionError):
                offset += 1
                continue
            remaining_decoded_characters -= end - offset
            if remaining_decoded_characters < 0:
                _fail("PRIVATE_IDENTIFIER_JSON_BOUND")
            if isinstance(candidate, (dict, list)) and (
                _contains_private_identifier_in_structured_value(
                    candidate,
                    contextual_lookup=contextual_lookup,
                    private_ids=private_ids,
                    remaining_nodes=remaining_nodes,
                )
            ):
                return True
            offset = max(end, offset + 1)
    return False


def _scan_public_value(
    value: Any,
    *,
    private_names: frozenset[str],
    private_urls: frozenset[str],
    private_ids: frozenset[int],
    private_bounded_tokens: frozenset[str] = frozenset(),
    private_exact_literals: frozenset[str] = frozenset(),
    private_contextual_tokens: frozenset[tuple[str, str]] = frozenset(),
    path: tuple[str, ...] = (),
    _contextual_lookup: dict[str, frozenset[str]] | None = None,
) -> None:
    contextual_lookup = (
        _contextual_token_lookup(private_contextual_tokens)
        if _contextual_lookup is None
        else _contextual_lookup
    )
    if isinstance(value, str):
        if _contains_private_identifier_text(
            value,
            private_names=private_names,
            private_urls=private_urls,
            private_ids=private_ids,
            private_bounded_tokens=private_bounded_tokens,
            private_exact_literals=private_exact_literals,
            private_contextual_tokens=private_contextual_tokens,
        ):
            _fail("PRIVATE_IDENTIFIER_PUBLIC_LEAK")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _scan_public_value(
                item,
                private_names=private_names,
                private_urls=private_urls,
                private_ids=private_ids,
                private_bounded_tokens=private_bounded_tokens,
                private_exact_literals=private_exact_literals,
                private_contextual_tokens=private_contextual_tokens,
                path=(*path, str(index)),
                _contextual_lookup=contextual_lookup,
            )
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if _structured_private_identifier_match(
                key,
                item,
                path=path,
                contextual_lookup=contextual_lookup,
                private_ids=private_ids,
            ):
                _fail("PRIVATE_IDENTIFIER_PUBLIC_LEAK")
            _scan_public_value(
                item,
                private_names=private_names,
                private_urls=private_urls,
                private_ids=private_ids,
                private_bounded_tokens=private_bounded_tokens,
                private_exact_literals=private_exact_literals,
                private_contextual_tokens=private_contextual_tokens,
                path=(*path, key),
                _contextual_lookup=contextual_lookup,
            )


def _scan_public_payloads(
    payloads: Sequence[bytes],
    *,
    private_names: frozenset[str],
    private_urls: frozenset[str],
    private_ids: frozenset[int] = frozenset(),
    private_bounded_tokens: frozenset[str] = frozenset(),
    private_exact_literals: frozenset[str] = frozenset(),
    private_contextual_tokens: frozenset[tuple[str, str]] = frozenset(),
) -> None:
    for payload in payloads:
        try:
            text = payload.decode("utf-8")
        except UnicodeDecodeError:
            _fail("PRIVATE_IDENTIFIER_PUBLIC_LEAK")
        if _contains_private_identifier_text(
            text,
            private_names=private_names,
            private_urls=private_urls,
            private_ids=private_ids,
            private_bounded_tokens=private_bounded_tokens,
            private_exact_literals=private_exact_literals,
            private_contextual_tokens=private_contextual_tokens,
        ):
            _fail("PRIVATE_IDENTIFIER_PUBLIC_LEAK")


def _verify_cross_lane_privacy(
    *,
    private_records: Sequence[dict[str, Any]],
    public_records: Sequence[dict[str, Any]],
    public_values: Sequence[Any],
    public_payloads: Sequence[bytes],
) -> None:
    private_names, private_urls, private_ids = _private_identifier_tokens(
        private_records, public_records
    )
    (
        private_bounded_tokens,
        private_exact_literals,
        private_contextual_tokens,
    ) = _private_raw_identifier_tokens(private_records, public_records)
    for value in public_values:
        _scan_public_value(
            value,
            private_names=private_names,
            private_urls=private_urls,
            private_ids=private_ids,
            private_bounded_tokens=private_bounded_tokens,
            private_exact_literals=private_exact_literals,
            private_contextual_tokens=private_contextual_tokens,
        )
    _scan_public_payloads(
        public_payloads,
        private_names=private_names,
        private_urls=private_urls,
        private_ids=private_ids,
        private_bounded_tokens=private_bounded_tokens,
        private_exact_literals=private_exact_literals,
        private_contextual_tokens=private_contextual_tokens,
    )


def _supersession_source_payloads(
    *,
    evidence_root: Path,
    supersession: dict[str, Any],
    public_heads: Path,
    private_ledger: Path,
    _test_profile: bool,
) -> tuple[dict[Path, bytes], list[dict[str, Any]]]:
    if _test_profile:
        return {}, []
    sanitized_path = _sanitized_search_path()
    git = _resolve_safe_executable("git", sanitized_path=sanitized_path)
    environment = _git_environment(sanitized_path)
    repository_root = _git_repository_root(git, evidence_root, environment)
    sources_by_id = {source["id"]: source for source in supersession["sources"]}
    payloads: dict[Path, bytes] = {}
    records: list[dict[str, Any]] = []
    for source_id in SUPERSESSION_SOURCE_CONTRACT:
        source = sources_by_id[source_id]
        candidate = repository_root / PurePosixPath(source["path"])
        try:
            candidate.relative_to(repository_root)
            resolved = candidate.resolve(strict=False)
            resolved.relative_to(repository_root)
        except (OSError, ValueError):
            _fail("SUPERSESSION_STAGED_SOURCE")
        if source_id == "OWNER_LOCAL_PRIVATE_LEDGER":
            if resolved != private_ledger.resolve(strict=False):
                _fail("SUPERSESSION_PRIVATE_SOURCE_BINDING")
            continue
        if source_id == "PUBLIC_REPOSITORY_HEADS" and resolved != public_heads.resolve(
            strict=False
        ):
            _fail("SUPERSESSION_PUBLIC_SOURCE_BINDING")
        payload = _read_bounded(candidate, MAX_JSON_BYTES, "SUPERSESSION_STAGED_SOURCE")
        payload_key = (
            public_heads if source_id == "PUBLIC_REPOSITORY_HEADS" else candidate
        )
        payloads[payload_key] = payload
        records.append(
            _file_record(
                source["path"],
                payload,
                classification="PUBLIC_SUPERSESSION_BOUND_SOURCE",
            )
        )
    return payloads, records


def render_files(
    *,
    public_heads: Path,
    owner_visible: Path,
    public_decisions: Path,
    private_decisions: Path,
    capture_metadata: Path,
    command_log: Path,
    output_root: Path,
    supersession_audit: Path,
    _seal: bool = False,
    _test_profile: bool = False,
) -> dict[str, Any]:
    _require_common_evidence_root(
        (
            (public_heads, PUBLIC_HEADS_BASENAME),
            (owner_visible, OWNER_VISIBLE_BASENAME),
            (public_decisions, PUBLIC_DECISIONS_BASENAME),
            (private_decisions, PRIVATE_DECISIONS_BASENAME),
            (capture_metadata, CAPTURE_METADATA_BASENAME),
            (command_log, COMMAND_LOG_BASENAME),
            (supersession_audit, SUPERSESSION_BASENAME),
            (output_root / PRIVATE_TELEMETRY_BASENAME, PRIVATE_TELEMETRY_BASENAME),
        ),
        expected_root=output_root,
    )
    if not _test_profile:
        _production_maintained_artifact_payloads()
    _require_private_mode(owner_visible)
    _require_private_mode(private_decisions)
    private_telemetry_path = output_root / PRIVATE_TELEMETRY_BASENAME
    _require_private_mode(private_telemetry_path)
    private_csv_path = output_root / PRIVATE_LEDGER_BASENAME
    if not _test_profile:
        _private_write_preflight(
            evidence_root=output_root,
            private_paths=(
                owner_visible,
                private_decisions,
                private_telemetry_path,
                private_csv_path,
            ),
        )
    public_raw, public_payload = _load_jsonl(public_heads)
    owner_raw, owner_payload = _load_jsonl(owner_visible, private=True)
    command_raw, command_payload = _load_jsonl(
        command_log, maximum=MAX_COMMAND_LOG_BYTES
    )
    capture_value, capture_payload = _load_json(capture_metadata)
    public_decision_value, public_decision_payload = _load_json(public_decisions)
    private_decision_value, private_decision_payload = _load_json(
        private_decisions, private=True
    )
    private_telemetry_value, private_telemetry_payload = _load_json(
        private_telemetry_path, private=True
    )
    supersession_value, supersession_payload = _load_json(supersession_audit)
    supersession_document = validate_supersession_audit(supersession_value)
    if _seal and not _test_profile:
        _require_reviewed_supersession(supersession_document)
    public_records = validate_heads(public_raw, visibility="PUBLIC")
    owner_records = validate_heads(owner_raw, visibility="OWNER_VISIBLE")
    owner_public = [
        _public_projection(item)
        for item in owner_records
        if item["visibility"] == "PUBLIC"
    ]
    owner_private = [item for item in owner_records if item["visibility"] == "PRIVATE"]
    if owner_public != public_records:
        _fail("RENDER_PUBLIC_SUBSET")
    command_records = _command_log(command_raw)
    capture = _validate_capture_metadata(
        capture_value,
        public_payload=public_payload,
        owner_payload=owner_payload,
        command_payload=command_payload,
        owner_records=owner_records,
        private_telemetry_payload=private_telemetry_payload,
        _test_profile=_test_profile,
    )
    _validate_private_telemetry(
        private_telemetry_value,
        capture,
        public_records=public_records,
        owner_records=owner_records,
    )
    _bind_command_log_to_capture(command_records, capture)
    expected_owner = capture["capture"]["owner"]
    public_records = validate_heads(
        public_raw, visibility="PUBLIC", expected_owner=expected_owner
    )
    owner_records = validate_heads(
        owner_raw, visibility="OWNER_VISIBLE", expected_owner=expected_owner
    )
    owner_public = [
        _public_projection(item)
        for item in owner_records
        if item["visibility"] == "PUBLIC"
    ]
    owner_private = [item for item in owner_records if item["visibility"] == "PRIVATE"]
    if owner_public != public_records:
        _fail("RENDER_PUBLIC_SUBSET")
    _completed_text, completed_instant = _timestamp_instant(
        capture["capture"]["completed_at_utc"], "CAPTURE_COMPLETED"
    )
    review_not_before = completed_instant.date()
    review_not_after = dt.date.fromisoformat(MAINTAINED_REVIEW_DATE)
    public_decision_records = validate_decisions(
        public_decision_value,
        public_records,
        expected_heads_sha256=sha256(public_payload),
        review_not_before=review_not_before,
        review_not_after=review_not_after,
    )
    private_decision_records = validate_decisions(
        private_decision_value,
        owner_private,
        expected_heads_sha256=sha256(owner_payload),
        review_not_before=review_not_before,
        review_not_after=review_not_after,
    )
    public_joined = joined_records(public_records, public_decision_records)
    private_joined = joined_records(owner_private, private_decision_records)
    public_json = classification_json(
        public_joined,
        heads_sha256=sha256(public_payload),
        decisions_sha256=sha256(public_decision_payload),
    )
    public_csv = classification_csv(public_joined)
    private_csv = classification_csv(private_joined)
    products = {
        "repository_classification_csv": _file_record(
            "repository-classification.csv",
            public_csv,
            classification="PUBLIC_GENERATED",
        ),
        "repository_classification_json": _file_record(
            "repository-classification.json",
            public_json,
            classification="PUBLIC_GENERATED",
        ),
    }
    source_records: dict[str, Any] = {
        "capture_metadata": _file_record(
            "capture-metadata.json",
            capture_payload,
            classification="PUBLIC_REDACTED",
        ),
        "command_log": _file_record(
            "command-log.jsonl", command_payload, classification="PUBLIC_REDACTED"
        ),
        "public_decisions": _file_record(
            "repository-classification-decisions.json",
            public_decision_payload,
            classification="PUBLIC_AUTHORED_SOURCE",
        ),
        "repository_heads": _file_record(
            "repository-heads.jsonl",
            public_payload,
            classification="PUBLIC_CAPTURED_SOURCE",
        ),
    }
    source_records["supersession_audit"] = _file_record(
        SUPERSESSION_BASENAME,
        supersession_payload,
        classification="PUBLIC_AUTHORED_SOURCE",
    )
    private_components = [
        _file_record(
            "owner-visible-repositories.private.jsonl",
            owner_payload,
            classification="OWNER_LOCAL_PRIVATE_MODE_0600",
        ),
        _file_record(
            "repository-classification-decisions.private.json",
            private_decision_payload,
            classification="OWNER_LOCAL_PRIVATE_MODE_0600",
        ),
        _file_record(
            "local-private-source-ledger.private.csv",
            private_csv,
            classification="OWNER_LOCAL_PRIVATE_MODE_0600",
        ),
        _file_record(
            PRIVATE_TELEMETRY_BASENAME,
            private_telemetry_payload,
            classification="OWNER_LOCAL_PRIVATE_MODE_0600",
        ),
    ]
    supersession_payloads, supersession_source_records = _supersession_source_payloads(
        evidence_root=output_root,
        supersession=supersession_value,
        public_heads=public_heads,
        private_ledger=private_csv_path,
        _test_profile=_test_profile,
    )
    _verify_cross_lane_privacy(
        private_records=private_joined,
        public_records=public_joined,
        public_values=(
            public_raw,
            public_decision_value,
            capture_value,
            command_raw,
            supersession_value,
            public_joined,
        ),
        public_payloads=(
            public_payload,
            public_decision_payload,
            capture_payload,
            command_payload,
            supersession_payload,
            public_json,
            public_csv,
            *supersession_payloads.values(),
        ),
    )
    _atomic_write(
        output_root / PUBLIC_CLASSIFICATION_JSON_BASENAME,
        public_json,
        private=False,
    )
    _atomic_write(
        output_root / PUBLIC_CLASSIFICATION_CSV_BASENAME,
        public_csv,
        private=False,
    )
    try:
        _atomic_write(private_csv_path, private_csv, private=True)
        _require_private_mode(private_csv_path)
    finally:
        if not _test_profile:
            _private_write_preflight(
                evidence_root=output_root,
                private_paths=(
                    owner_visible,
                    private_decisions,
                    private_telemetry_path,
                    private_csv_path,
                ),
            )
    result: dict[str, Any] = {
        "private": len(private_joined),
        "public": len(public_joined),
        "seal_state": "DRAFT_OUTPUTS_READY",
    }
    if not _seal:
        return result

    required_staged_payloads = {
        public_heads: public_payload,
        capture_metadata: capture_payload,
        command_log: command_payload,
        public_decisions: public_decision_payload,
        supersession_audit: supersession_payload,
        output_root / PUBLIC_CLASSIFICATION_JSON_BASENAME: public_json,
        output_root / PUBLIC_CLASSIFICATION_CSV_BASENAME: public_csv,
        **supersession_payloads,
    }
    if not _test_profile:
        required_staged_payloads.update(_production_maintained_artifact_payloads())
    cross_lane_scan, pre_audit_state = _git_privacy_closure(
        evidence_root=output_root,
        expected_private_payloads={
            owner_visible: owner_payload,
            private_decisions: private_decision_payload,
            private_csv_path: private_csv,
            private_telemetry_path: private_telemetry_payload,
        },
        private_records=private_joined,
        public_records=public_joined,
        audit_path=output_root / AUDIT_METADATA_BASENAME,
        required_staged_payloads=required_staged_payloads,
        audit_payload=None,
    )
    if pre_audit_state != "PRE_AUDIT_SEAL_READY":
        _fail("GIT_SEAL_STATE")
    private_commitment = sha256(canonical_json(private_components))
    audit = {
        "authority": AUTHORITY,
        "capture": capture["capture"],
        "command_log": source_records["command_log"],
        "limitations": capture["limitations"],
        "private_evidence": {
            "commitment_sha256": private_commitment,
            "components": [
                {
                    "bytes": item["bytes"],
                    "classification": item["classification"],
                    "label": item["label"],
                    "sha256": item["sha256"],
                }
                for item in private_components
            ],
            "cross_lane_scan": cross_lane_scan,
            "public_check_scope": "COMMITMENT_ONLY",
            "repositories": len(private_joined),
            "unresolved": 0,
        },
        "products": products,
        "public_evidence": {
            "repositories": len(public_joined),
            "sources": source_records,
            "supersession_sources": supersession_source_records,
            "unresolved": 0,
        },
        "schema_id": TEST_AUDIT_SCHEMA if _test_profile else AUDIT_SCHEMA,
        "schema_version": SCHEMA_VERSION,
    }
    audit_payload = canonical_json(audit)
    _verify_cross_lane_privacy(
        private_records=private_joined,
        public_records=public_joined,
        public_values=(
            public_raw,
            public_decision_value,
            capture_value,
            command_raw,
            supersession_value,
            public_joined,
            audit,
        ),
        public_payloads=(
            public_payload,
            public_decision_payload,
            capture_payload,
            command_payload,
            supersession_payload,
            public_json,
            public_csv,
            audit_payload,
        ),
    )
    audit_path = output_root / AUDIT_METADATA_BASENAME
    _atomic_write(audit_path, audit_payload, private=False)
    repeated_scan, seal_state = _git_privacy_closure(
        evidence_root=output_root,
        expected_private_payloads={
            owner_visible: owner_payload,
            private_decisions: private_decision_payload,
            private_csv_path: private_csv,
            private_telemetry_path: private_telemetry_payload,
        },
        private_records=private_joined,
        public_records=public_joined,
        audit_path=audit_path,
        required_staged_payloads=required_staged_payloads,
        audit_payload=audit_payload,
    )
    if repeated_scan != cross_lane_scan:
        _fail("GIT_SEAL_DRIFT")
    result["seal_state"] = seal_state
    return result


def seal_files(
    *,
    public_heads: Path,
    owner_visible: Path,
    public_decisions: Path,
    private_decisions: Path,
    capture_metadata: Path,
    command_log: Path,
    output_root: Path,
    supersession_audit: Path,
    _test_profile: bool = False,
) -> dict[str, Any]:
    return render_files(
        public_heads=public_heads,
        owner_visible=owner_visible,
        public_decisions=public_decisions,
        private_decisions=private_decisions,
        capture_metadata=capture_metadata,
        command_log=command_log,
        output_root=output_root,
        supersession_audit=supersession_audit,
        _seal=True,
        _test_profile=_test_profile,
    )


def _validate_audit_document(
    value: Any, *, _test_profile: bool = False
) -> dict[str, Any]:
    document = _exact_keys(
        value,
        {
            "authority",
            "capture",
            "command_log",
            "limitations",
            "private_evidence",
            "products",
            "public_evidence",
            "schema_id",
            "schema_version",
        },
        "AUDIT_KEYS",
    )
    if (
        document["schema_id"] != (TEST_AUDIT_SCHEMA if _test_profile else AUDIT_SCHEMA)
        or document["schema_version"] != SCHEMA_VERSION
    ):
        _fail("AUDIT_SCHEMA")
    _validate_authority(document["authority"], "AUDIT_SCHEMA")
    _exact_constant(document["limitations"], LIMITATIONS, "AUDIT_SCHEMA")
    if not isinstance(document["capture"], dict):
        _fail("AUDIT_CAPTURE")
    _validate_file_record(
        document["command_log"],
        label=COMMAND_LOG_BASENAME,
        classification="PUBLIC_REDACTED",
        maximum_bytes=MAX_COMMAND_LOG_BYTES,
        code="AUDIT_COMMAND_LOG",
    )
    products = _exact_keys(
        document["products"],
        {"repository_classification_csv", "repository_classification_json"},
        "AUDIT_PRODUCTS",
    )
    expected_products = {
        "repository_classification_csv": (
            "repository-classification.csv",
            "PUBLIC_GENERATED",
        ),
        "repository_classification_json": (
            "repository-classification.json",
            "PUBLIC_GENERATED",
        ),
    }
    for key, (label, classification) in expected_products.items():
        _validate_file_record(
            products[key],
            label=label,
            classification=classification,
            maximum_bytes=MAX_JSON_BYTES,
            code="AUDIT_PRODUCT",
        )
    public = _exact_keys(
        document["public_evidence"],
        {"repositories", "sources", "supersession_sources", "unresolved"},
        "AUDIT_PUBLIC_KEYS",
    )
    _bounded_int(public["repositories"], 1, MAX_REPOSITORIES, "AUDIT_PUBLIC_COUNT")
    _exact_int(public["unresolved"], 0, "AUDIT_PUBLIC")
    if not isinstance(public["sources"], dict):
        _fail("AUDIT_PUBLIC")
    supersession_sources = public["supersession_sources"]
    expected_supersession_paths = [
        path
        for source_id, (path, _status) in SUPERSESSION_SOURCE_CONTRACT.items()
        if source_id != "OWNER_LOCAL_PRIVATE_LEDGER"
    ]
    expected_supersession_count = (
        0 if _test_profile else len(expected_supersession_paths)
    )
    if (
        not isinstance(supersession_sources, list)
        or len(supersession_sources) != expected_supersession_count
    ):
        _fail("AUDIT_SUPERSESSION_SOURCES")
    for record, label in zip(
        supersession_sources,
        ([] if _test_profile else expected_supersession_paths),
        strict=True,
    ):
        _validate_file_record(
            record,
            label=label,
            classification="PUBLIC_SUPERSESSION_BOUND_SOURCE",
            maximum_bytes=MAX_JSON_BYTES,
            code="AUDIT_SUPERSESSION_SOURCE",
        )
    required_sources = {
        "capture_metadata": ("capture-metadata.json", "PUBLIC_REDACTED"),
        "command_log": ("command-log.jsonl", "PUBLIC_REDACTED"),
        "public_decisions": (
            "repository-classification-decisions.json",
            "PUBLIC_AUTHORED_SOURCE",
        ),
        "repository_heads": (
            "repository-heads.jsonl",
            "PUBLIC_CAPTURED_SOURCE",
        ),
        "supersession_audit": (
            "supersession-audit.json",
            "PUBLIC_AUTHORED_SOURCE",
        ),
    }
    if set(public["sources"]) != set(required_sources):
        _fail("AUDIT_PUBLIC_SOURCES")
    for key, (label, classification) in required_sources.items():
        _validate_file_record(
            public["sources"][key],
            label=label,
            classification=classification,
            maximum_bytes=(
                MAX_COMMAND_LOG_BYTES if key == "command_log" else MAX_JSON_BYTES
            ),
            code="AUDIT_PUBLIC_SOURCE",
        )
    private = _exact_keys(
        document["private_evidence"],
        {
            "commitment_sha256",
            "components",
            "cross_lane_scan",
            "public_check_scope",
            "repositories",
            "unresolved",
        },
        "AUDIT_PRIVATE_KEYS",
    )
    commitment = _digest(private["commitment_sha256"], "AUDIT_PRIVATE")
    repositories = _bounded_int(
        private["repositories"], 0, MAX_REPOSITORIES, "AUDIT_PRIVATE"
    )
    _exact_int(private["unresolved"], 0, "AUDIT_PRIVATE")
    scan = _exact_keys(
        private["cross_lane_scan"],
        {
            "result",
            "scan_configuration_sha256",
            "sealed_index_sha256",
            "tracked_bytes",
            "tracked_files",
        },
        "AUDIT_PRIVATE_SCAN",
    )
    if (
        _digest(scan["scan_configuration_sha256"], "AUDIT_PRIVATE_SCAN")
        != sha256(canonical_json(CROSS_LANE_SCAN_CONFIGURATION))
        or scan["result"] != "PASS"
    ):
        _fail("AUDIT_PRIVATE_SCAN")
    _digest(scan["sealed_index_sha256"], "AUDIT_PRIVATE_SCAN")
    _bounded_int(scan["tracked_bytes"], 0, MAX_TRACKED_SCAN_BYTES, "AUDIT_PRIVATE_SCAN")
    _bounded_int(scan["tracked_files"], 0, MAX_TRACKED_FILES, "AUDIT_PRIVATE_SCAN")
    if (
        private["public_check_scope"] != "COMMITMENT_ONLY"
        or not isinstance(private["components"], list)
        or len(private["components"]) != 4
    ):
        _fail("AUDIT_PRIVATE")
    del repositories
    expected_components = [
        (
            "owner-visible-repositories.private.jsonl",
            "OWNER_LOCAL_PRIVATE_MODE_0600",
        ),
        (
            "repository-classification-decisions.private.json",
            "OWNER_LOCAL_PRIVATE_MODE_0600",
        ),
        (
            "local-private-source-ledger.private.csv",
            "OWNER_LOCAL_PRIVATE_MODE_0600",
        ),
        (
            PRIVATE_TELEMETRY_BASENAME,
            "OWNER_LOCAL_PRIVATE_MODE_0600",
        ),
    ]
    for item, (label, classification) in zip(
        private["components"], expected_components, strict=True
    ):
        _validate_file_record(
            item,
            label=label,
            classification=classification,
            maximum_bytes=MAX_JSON_BYTES,
            code="AUDIT_PRIVATE_COMPONENT",
        )
    if sha256(canonical_json(private["components"])) != commitment:
        _fail("AUDIT_PRIVATE_COMMITMENT")
    return document


def check_files(
    *,
    root: Path,
    owner_visible: Path | None,
    private_decisions: Path | None,
    _test_profile: bool = False,
) -> dict[str, Any]:
    if not _test_profile:
        _production_maintained_artifact_payloads()
    public_heads = root / PUBLIC_HEADS_BASENAME
    public_decisions = root / PUBLIC_DECISIONS_BASENAME
    capture_metadata = root / CAPTURE_METADATA_BASENAME
    command_log = root / COMMAND_LOG_BASENAME
    classification_json_path = root / PUBLIC_CLASSIFICATION_JSON_BASENAME
    classification_csv_path = root / PUBLIC_CLASSIFICATION_CSV_BASENAME
    audit_path = root / AUDIT_METADATA_BASENAME
    supersession_path = root / SUPERSESSION_BASENAME
    if (owner_visible is None) != (private_decisions is None):
        _fail("PRIVATE_ARGUMENT_PAIR")
    if owner_visible is not None and private_decisions is not None:
        _require_common_evidence_root(
            (
                (owner_visible, OWNER_VISIBLE_BASENAME),
                (private_decisions, PRIVATE_DECISIONS_BASENAME),
                (root / PRIVATE_LEDGER_BASENAME, PRIVATE_LEDGER_BASENAME),
                (root / PRIVATE_TELEMETRY_BASENAME, PRIVATE_TELEMETRY_BASENAME),
            ),
            expected_root=root,
        )
    public_raw, public_payload = _load_jsonl(public_heads)
    public_decision_value, public_decision_payload = _load_json(public_decisions)
    capture_value, capture_payload = _load_json(capture_metadata)
    command_raw, command_payload = _load_jsonl(
        command_log, maximum=MAX_COMMAND_LOG_BYTES
    )
    classification_value, classification_payload = _load_json(classification_json_path)
    csv_payload = _read_bounded(classification_csv_path, MAX_JSON_BYTES, "CSV_READ")
    audit_value, audit_payload = _load_json(audit_path)
    supersession_value, supersession_payload = _load_json(supersession_path)
    supersession_document = validate_supersession_audit(supersession_value)
    if not _test_profile:
        _require_reviewed_supersession(supersession_document)
    command_records = _command_log(command_raw)
    capture = _validate_capture_metadata(
        capture_value,
        public_payload=public_payload,
        owner_payload=None,
        command_payload=command_payload,
        owner_records=None,
        _test_profile=_test_profile,
    )
    _bind_command_log_to_capture(command_records, capture)
    public_records = validate_heads(
        public_raw,
        visibility="PUBLIC",
        expected_owner=capture["capture"]["owner"],
    )
    _completed_text, completed_instant = _timestamp_instant(
        capture["capture"]["completed_at_utc"], "CAPTURE_COMPLETED"
    )
    review_not_before = completed_instant.date()
    review_not_after = dt.date.fromisoformat(MAINTAINED_REVIEW_DATE)
    public_decision_records = validate_decisions(
        public_decision_value,
        public_records,
        expected_heads_sha256=sha256(public_payload),
        review_not_before=review_not_before,
        review_not_after=review_not_after,
    )
    public_joined = joined_records(public_records, public_decision_records)
    expected_json = classification_json(
        public_joined,
        heads_sha256=sha256(public_payload),
        decisions_sha256=sha256(public_decision_payload),
    )
    expected_csv = classification_csv(public_joined)
    if classification_payload != expected_json or csv_payload != expected_csv:
        _fail("GENERATED_DRIFT")
    audit = _validate_audit_document(audit_value, _test_profile=_test_profile)
    supersession_payloads, supersession_source_records = _supersession_source_payloads(
        evidence_root=root,
        supersession=supersession_value,
        public_heads=public_heads,
        private_ledger=root / PRIVATE_LEDGER_BASENAME,
        _test_profile=_test_profile,
    )
    if audit["public_evidence"]["supersession_sources"] != supersession_source_records:
        _fail("AUDIT_SUPERSESSION_BINDING")
    _exact_constant(audit["capture"], capture["capture"], "AUDIT_CAPTURE_BINDING")
    _exact_constant(
        audit["limitations"], capture["limitations"], "AUDIT_CAPTURE_BINDING"
    )
    if audit["command_log"] != _file_record(
        "command-log.jsonl", command_payload, classification="PUBLIC_REDACTED"
    ):
        _fail("AUDIT_COMMAND_BINDING")
    expected_products = {
        "repository_classification_csv": _file_record(
            "repository-classification.csv",
            expected_csv,
            classification="PUBLIC_GENERATED",
        ),
        "repository_classification_json": _file_record(
            "repository-classification.json",
            expected_json,
            classification="PUBLIC_GENERATED",
        ),
    }
    if audit["products"] != expected_products:
        _fail("AUDIT_PRODUCT_BINDING")
    sources = audit["public_evidence"].get("sources")
    if not isinstance(sources, dict):
        _fail("AUDIT_PUBLIC_SOURCES")
    expected_source_subset = {
        "capture_metadata": _file_record(
            "capture-metadata.json",
            capture_payload,
            classification="PUBLIC_REDACTED",
        ),
        "command_log": _file_record(
            "command-log.jsonl", command_payload, classification="PUBLIC_REDACTED"
        ),
        "public_decisions": _file_record(
            "repository-classification-decisions.json",
            public_decision_payload,
            classification="PUBLIC_AUTHORED_SOURCE",
        ),
        "repository_heads": _file_record(
            "repository-heads.jsonl",
            public_payload,
            classification="PUBLIC_CAPTURED_SOURCE",
        ),
    }
    for key, expected in expected_source_subset.items():
        if sources.get(key) != expected:
            _fail("AUDIT_PUBLIC_BINDING")
    if sources.get("supersession_audit") != _file_record(
        SUPERSESSION_BASENAME,
        supersession_payload,
        classification="PUBLIC_AUTHORED_SOURCE",
    ):
        _fail("AUDIT_SUPERSESSION_BINDING")
    if (
        audit["public_evidence"].get("repositories") != len(public_joined)
        or audit["public_evidence"].get("unresolved") != 0
        or audit["public_evidence"].get("repositories") != capture["public"]["rows"]
    ):
        _fail("AUDIT_PUBLIC_COUNT")
    private_evidence = audit["private_evidence"]
    if (
        private_evidence["components"][0] != capture["owner_visible"]["file"]
        or private_evidence["components"][3] != capture["private_telemetry"]
        or private_evidence["repositories"] != capture["owner_visible"]["private_rows"]
    ):
        _fail("AUDIT_PRIVATE_CAPTURE_BINDING")
    private_scope = "COMMITMENT_ONLY"
    seal_state = "COMMITMENT_ONLY_NOT_VERIFIED"
    if owner_visible is not None and private_decisions is not None:
        _require_private_mode(owner_visible)
        _require_private_mode(private_decisions)
        owner_raw, owner_payload = _load_jsonl(owner_visible, private=True)
        private_value, private_decision_payload = _load_json(
            private_decisions, private=True
        )
        private_telemetry_path = root / PRIVATE_TELEMETRY_BASENAME
        _require_private_mode(private_telemetry_path)
        private_telemetry_value, private_telemetry_payload = _load_json(
            private_telemetry_path, private=True
        )
        owner_records = validate_heads(
            owner_raw,
            visibility="OWNER_VISIBLE",
            expected_owner=capture["capture"]["owner"],
        )
        _validate_capture_metadata(
            capture_value,
            public_payload=public_payload,
            owner_payload=owner_payload,
            command_payload=command_payload,
            owner_records=owner_records,
            private_telemetry_payload=private_telemetry_payload,
            _test_profile=_test_profile,
        )
        _validate_private_telemetry(
            private_telemetry_value,
            capture,
            public_records=public_records,
            owner_records=owner_records,
        )
        owner_public = [
            _public_projection(item)
            for item in owner_records
            if item["visibility"] == "PUBLIC"
        ]
        owner_private = [
            item for item in owner_records if item["visibility"] == "PRIVATE"
        ]
        if owner_public != public_records:
            _fail("CHECK_PUBLIC_SUBSET")
        private_decision_records = validate_decisions(
            private_value,
            owner_private,
            expected_heads_sha256=sha256(owner_payload),
            review_not_before=review_not_before,
            review_not_after=review_not_after,
        )
        private_joined = joined_records(owner_private, private_decision_records)
        private_csv = classification_csv(private_joined)
        private_csv_path = root / PRIVATE_LEDGER_BASENAME
        _require_private_mode(private_csv_path)
        observed_private_csv = _read_bounded(
            private_csv_path,
            MAX_JSON_BYTES,
            "PRIVATE_CSV",
            required_mode=0o600,
        )
        if observed_private_csv != private_csv:
            _fail("PRIVATE_GENERATED_DRIFT")
        components = [
            _file_record(
                "owner-visible-repositories.private.jsonl",
                owner_payload,
                classification="OWNER_LOCAL_PRIVATE_MODE_0600",
            ),
            _file_record(
                "repository-classification-decisions.private.json",
                private_decision_payload,
                classification="OWNER_LOCAL_PRIVATE_MODE_0600",
            ),
            _file_record(
                "local-private-source-ledger.private.csv",
                private_csv,
                classification="OWNER_LOCAL_PRIVATE_MODE_0600",
            ),
            _file_record(
                PRIVATE_TELEMETRY_BASENAME,
                private_telemetry_payload,
                classification="OWNER_LOCAL_PRIVATE_MODE_0600",
            ),
        ]
        private = private_evidence
        if (
            private["components"] != components
            or private["commitment_sha256"] != sha256(canonical_json(components))
            or private["repositories"] != len(private_joined)
        ):
            _fail("PRIVATE_COMMITMENT_MISMATCH")
        _verify_cross_lane_privacy(
            private_records=private_joined,
            public_records=public_joined,
            public_values=(
                public_raw,
                public_decision_value,
                capture_value,
                command_raw,
                supersession_value,
                classification_value,
                audit_value,
            ),
            public_payloads=(
                public_payload,
                public_decision_payload,
                capture_payload,
                command_payload,
                supersession_payload,
                classification_payload,
                csv_payload,
                audit_payload,
                *supersession_payloads.values(),
            ),
        )
        required_staged_payloads = {
            public_heads: public_payload,
            capture_metadata: capture_payload,
            command_log: command_payload,
            public_decisions: public_decision_payload,
            supersession_path: supersession_payload,
            classification_json_path: classification_payload,
            classification_csv_path: csv_payload,
            **supersession_payloads,
        }
        if not _test_profile:
            required_staged_payloads.update(_production_maintained_artifact_payloads())
        observed_cross_lane_scan, seal_state = _git_privacy_closure(
            evidence_root=root,
            expected_private_payloads={
                owner_visible: owner_payload,
                private_decisions: private_decision_payload,
                private_csv_path: private_csv,
                private_telemetry_path: private_telemetry_payload,
            },
            private_records=private_joined,
            public_records=public_joined,
            audit_path=audit_path,
            required_staged_payloads=required_staged_payloads,
            audit_payload=audit_payload,
        )
        if private["cross_lane_scan"] != observed_cross_lane_scan:
            _fail("PRIVATE_GIT_SCAN_DRIFT")
        if seal_state != "AUDIT_STAGED_FINAL":
            _fail("GIT_AUDIT_STAGE")
        private_scope = "OWNER_LOCAL_VERIFIED"
    return {
        "private_scope": private_scope,
        "public": len(public_joined),
        "seal_state": seal_state,
    }


class SafeArgumentParser(argparse.ArgumentParser):
    """Argparse variant that never reflects a rejected argument value."""

    def error(self, message: str) -> NoReturn:
        del message
        _fail("ARGUMENTS")


def _parser() -> argparse.ArgumentParser:
    parser = SafeArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    diagram = subparsers.add_parser(
        "diagram", help="write or verify the deterministic assurance-flow SVG"
    )
    diagram.add_argument("--output", type=Path, required=True)
    diagram.add_argument("--check", action="store_true")

    capture = subparsers.add_parser(
        "capture", help="capture two stable tool-result snapshots with GET arguments"
    )
    capture.add_argument("--public-heads", type=Path, required=True)
    capture.add_argument("--owner-visible", type=Path, required=True)
    capture.add_argument("--capture-metadata", type=Path, required=True)
    capture.add_argument("--command-log", type=Path, required=True)
    capture.add_argument("--private-telemetry", type=Path, required=True)
    capture.add_argument("--head-workers", type=int, default=MAX_HEAD_WORKERS_DEFAULT)
    capture.add_argument("--minimum-rate-remaining", type=int, default=100)
    capture.add_argument("--maximum-pages", type=int, default=MAX_PAGES_DEFAULT)
    capture.add_argument("--request-timeout-seconds", type=int, default=60)

    template = subparsers.add_parser(
        "decision-template", help="write an explicit unresolved decision skeleton"
    )
    template.add_argument("--heads", type=Path, required=True)
    template.add_argument(
        "--visibility", choices=("PUBLIC", "PRIVATE"), default="PUBLIC"
    )
    template.add_argument("--output", type=Path, required=True)

    def add_render_arguments(command: argparse.ArgumentParser) -> None:
        command.add_argument("--public-heads", type=Path, required=True)
        command.add_argument("--owner-visible", type=Path, required=True)
        command.add_argument("--public-decisions", type=Path, required=True)
        command.add_argument("--private-decisions", type=Path, required=True)
        command.add_argument("--capture-metadata", type=Path, required=True)
        command.add_argument("--command-log", type=Path, required=True)
        command.add_argument("--output-root", type=Path, required=True)
        command.add_argument("--supersession-audit", type=Path, required=True)

    render = subparsers.add_parser(
        "render", help="render draft products without creating the audit receipt"
    )
    add_render_arguments(render)
    seal = subparsers.add_parser(
        "seal", help="seal staged public products and write the final audit last"
    )
    add_render_arguments(seal)

    check = subparsers.add_parser(
        "check", help="perform a deterministic network-free check"
    )
    check.add_argument("--root", type=Path, required=True)
    check.add_argument("--owner-visible", type=Path)
    check.add_argument("--private-decisions", type=Path)
    verify_seal = subparsers.add_parser(
        "verify-seal", help="verify the final owner-local staged seal"
    )
    verify_seal.add_argument("--root", type=Path, required=True)
    verify_seal.add_argument("--owner-visible", type=Path, required=True)
    verify_seal.add_argument("--private-decisions", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    try:
        arguments = _parser().parse_args(argv)
        if arguments.command == "diagram":
            if arguments.output.name != ECOSYSTEM_DIAGRAM_BASENAME:
                _fail("DIAGRAM_OUTPUT")
            payload = ecosystem_source_inventory_svg()
            if arguments.check:
                observed = _read_bounded(
                    arguments.output, MAX_JSON_BYTES, "DIAGRAM_READ"
                )
                if observed != payload:
                    _fail("DIAGRAM_DRIFT")
                operation = "check"
            else:
                _atomic_write(arguments.output, payload, private=False)
                operation = "write"
            print(
                "ecosystem-source-inventory: OK "
                f"(diagram-{operation}; deterministic; release NO_GO)"
            )
            return 0
        if arguments.command == "capture":
            minimum = _bounded_int(
                arguments.minimum_rate_remaining, 0, 5_000, "RATE_ARGUMENT"
            )
            maximum_pages = _bounded_int(
                arguments.maximum_pages, 1, 100, "PAGE_ARGUMENT"
            )
            head_workers = _bounded_int(
                arguments.head_workers, 1, 16, "HEAD_WORKERS_ARGUMENT"
            )
            timeout_seconds = _bounded_int(
                arguments.request_timeout_seconds, 1, 300, "TIMEOUT_ARGUMENT"
            )
            result = capture_production_files(
                public_heads=arguments.public_heads,
                owner_visible=arguments.owner_visible,
                capture_metadata=arguments.capture_metadata,
                command_log=arguments.command_log,
                private_telemetry=arguments.private_telemetry,
                minimum_remaining=minimum,
                maximum_pages=maximum_pages,
                head_workers=head_workers,
                timeout_seconds=timeout_seconds,
            )
            print(
                "ecosystem-source-inventory: OK "
                f"(capture; public={result['public']}; "
                f"owner-visible={result['owner_visible']}; private={result['private']}; "
                "release NO_GO)"
            )
            return 0
        if arguments.command == "decision-template":
            _require_common_evidence_root(
                (
                    (
                        arguments.heads,
                        (
                            OWNER_VISIBLE_BASENAME
                            if arguments.visibility == "PRIVATE"
                            else PUBLIC_HEADS_BASENAME
                        ),
                    ),
                    (
                        arguments.output,
                        (
                            PRIVATE_DECISIONS_BASENAME
                            if arguments.visibility == "PRIVATE"
                            else PUBLIC_DECISIONS_BASENAME
                        ),
                    ),
                )
            )
            if arguments.visibility == "PRIVATE":
                _production_maintained_artifact_payloads()
                _require_private_mode(arguments.heads)
                _private_write_preflight(
                    evidence_root=arguments.heads.parent,
                    private_paths=(arguments.heads, arguments.output),
                )
            raw, heads_payload = _load_jsonl(
                arguments.heads, private=(arguments.visibility == "PRIVATE")
            )
            records = validate_heads(
                raw,
                visibility=(
                    "OWNER_VISIBLE" if arguments.visibility == "PRIVATE" else "PUBLIC"
                ),
            )
            if arguments.visibility == "PRIVATE":
                records = [
                    record for record in records if record["visibility"] == "PRIVATE"
                ]
            value = decision_template(records, heads_sha256=sha256(heads_payload))
            if arguments.visibility == "PRIVATE":
                try:
                    _atomic_write(
                        arguments.output,
                        canonical_json(value),
                        private=True,
                    )
                    _require_private_mode(arguments.output)
                finally:
                    _private_write_preflight(
                        evidence_root=arguments.heads.parent,
                        private_paths=(arguments.heads, arguments.output),
                    )
            else:
                _atomic_write(
                    arguments.output,
                    canonical_json(value),
                    private=False,
                )
            print(
                "ecosystem-source-inventory: OK "
                f"(decision-template; rows={len(records)}; all UNRESOLVED)"
            )
            return 0
        if arguments.command == "render":
            result = render_files(
                public_heads=arguments.public_heads,
                owner_visible=arguments.owner_visible,
                public_decisions=arguments.public_decisions,
                private_decisions=arguments.private_decisions,
                capture_metadata=arguments.capture_metadata,
                command_log=arguments.command_log,
                output_root=arguments.output_root,
                supersession_audit=arguments.supersession_audit,
            )
            print(
                "ecosystem-source-inventory: OK "
                f"(render; public={result['public']}; private={result['private']}; "
                f"state={result['seal_state']}; release NO_GO)"
            )
            return 0
        if arguments.command == "seal":
            result = seal_files(
                public_heads=arguments.public_heads,
                owner_visible=arguments.owner_visible,
                public_decisions=arguments.public_decisions,
                private_decisions=arguments.private_decisions,
                capture_metadata=arguments.capture_metadata,
                command_log=arguments.command_log,
                output_root=arguments.output_root,
                supersession_audit=arguments.supersession_audit,
            )
            print(
                "ecosystem-source-inventory: OK "
                f"(seal; public={result['public']}; private={result['private']}; "
                f"state={result['seal_state']}; release NO_GO)"
            )
            return 0
        if arguments.command in {"check", "verify-seal"}:
            result = check_files(
                root=arguments.root,
                owner_visible=arguments.owner_visible,
                private_decisions=arguments.private_decisions,
            )
            print(
                "ecosystem-source-inventory: OK "
                f"({arguments.command}; public={result['public']}; "
                f"private={result['private_scope']}; "
                f"state={result['seal_state']}; release NO_GO)"
            )
            return 0
        _fail("COMMAND")
    except InventoryError as error:
        print(f"ecosystem-source-inventory: ERROR {error}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("ecosystem-source-inventory: ERROR INTERRUPTED", file=sys.stderr)
        return 130
    except Exception:
        # Never emit exception values: an unexpected parser or I/O error may
        # contain an owner-local repository identifier or path.
        print("ecosystem-source-inventory: ERROR INTERNAL_FAILURE", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
