#!/usr/bin/env python3
"""Verify the current-head Haldir 0.9 audit cut without network access."""

from __future__ import annotations

import ast
import copy
import errno
import gzip
import hashlib
import io
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
import tomllib
import types
import unicodedata
import zipfile
import zlib
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from typing import Any


MAX_JSON_BYTES = 256 * 1024
MAX_JSON_DEPTH = 64
MAX_JSON_NODES = 32_768
MAX_JSON_STRING_BYTES = 256 * 1024
MAX_JSON_CONTAINER_ENTRIES = 16_384
MAX_REQUIREMENTS_BYTES = 4 * 1024 * 1024
MAX_COMPRESSED_LOG_BYTES = 256 * 1024
MAX_LOG_BYTES = 4 * 1024 * 1024
MAX_GIT_BYTES = 8 * 1024 * 1024
MAX_HYGIENE_TOTAL_BYTES = 512 * 1024 * 1024
MAX_FIRST_PARENT_COMMITS = 1024
MAX_REGISTRATIONS = 256
MAX_REVOCATIONS = 126
MAX_REVOCATION_CAUSE_FILES = 16
MAX_REVOCATION_CAUSE_FILE_BYTES = 4 * 1024 * 1024
MAX_REVOCATION_CAUSE_TOTAL_BYTES = 16 * 1024 * 1024
MAX_CHANGED_PATHS_PER_COMMIT = 4096
MAX_PROTOCOL_PATH_BYTES = 240
MAX_VERIFIER_OUTPUT_BYTES = 64 * 1024
MAX_VERIFIER_SECONDS = 10
MAX_VERIFIER_AGGREGATE_SECONDS = 7_680
MAX_ZIP_ENTRY_BYTES = 4 * 1024 * 1024
MAX_ZIP_TOTAL_BYTES = 16 * 1024 * 1024
DIRFD_OPEN_AVAILABLE = os.open in os.supports_dir_fd
PROHIBITED_GOVERNANCE_TOKEN = b"super" + b"visor"
PROHIBITED_DEGREE_TOKEN = b"phd"
STALE_ACCOUNT_TOKEN = b"sepehr" + b"mn"
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
GIT_EXECUTABLE = "/usr/bin/git"
SSH_KEYGEN_EXECUTABLE = "/usr/bin/ssh-keygen"
DOCKER_EXECUTABLE = str(Path(shutil.which("docker") or "/usr/bin/docker").resolve())
PYTHON_EXECUTABLE = str(Path(sys.executable).resolve())
EXPECTED_PYTHON_VERSION = (3, 14, 6)
REGISTERED_RUNNER_IMAGE = (
    "python@sha256:4a3a38c8710794e278c3651352dd6195d5798eb6ec5ad41db6258e753c9e4ceb"
)
REGISTERED_RUNNER_IMAGE_IDS = {
    "amd64": {
        "sha256:4a3a38c8710794e278c3651352dd6195d5798eb6ec5ad41db6258e753c9e4ceb",
        "sha256:055b7765de9ed837be8a0647f1fada7b250a02ea053343d93c61f845387cbbf7",
    },
    "arm64": {
        "sha256:4a3a38c8710794e278c3651352dd6195d5798eb6ec5ad41db6258e753c9e4ceb",
        "sha256:d41229b8b87f39e241faf16b5db46e7823f9d82b3774fbf3690edb92be068185",
    },
}
CI_GATE_SHA256 = "dabd674e79262f8684b3cda91ef3df906abea070bbd675a5e8a70d049fb6984b"
CI_GATE_BYTES = 6_802
JUST_GATE_SHA256 = "e96971c4caae3a209bbb52b073bb18116f71eb774ea29dfc55ee824de939186a"
JUST_GATE_BYTES = 2_693
P0_GATE_SHA256 = "8238fd229ffd1e95da26787d793af73523f6980cd6430ec220bd4fa2632e5a64"
P0_GATE_BYTES = 3_977
HISTORICAL_LINUX_IMAGE_REFERENCE = (
    "rust@sha256:5e2214abe154fe26e39f64488952e5c991eeed1d6d6da7cc8381ae83927f0cfc"
)
HISTORICAL_LINUX_IMAGE_ID = (
    "sha256:5e2214abe154fe26e39f64488952e5c991eeed1d6d6da7cc8381ae83927f0cfc"
)
QUALIFICATION_LINUX_IMAGE_REFERENCE = (
    "python@sha256:4a3a38c8710794e278c3651352dd6195d5798eb6ec5ad41db6258e753c9e4ceb"
)
QUALIFICATION_LINUX_IMAGE_ID = (
    "sha256:d41229b8b87f39e241faf16b5db46e7823f9d82b3774fbf3690edb92be068185"
)
QUALIFICATION_LINUX_IMAGE_CREATED_AT = "2026-07-14T04:47:15Z"
QUALIFICATION_LINUX_ARCHITECTURE = "arm64"
QUALIFICATION_LINUX_PYTHON = "3.14.6"
QUALIFICATION_LINUX_GIT = "2.39.5"
QUALIFICATION_LINUX_SSH_KEYGEN = "/usr/bin/ssh-keygen"

SOURCE_COMMIT = "2bfcabe5bf9fd6c428f7d50132bd36ec4e147438"
SOURCE_TREE = "8d8cdda01d25bc9f3c6a2911b2c4464f5c7505e5"
SOURCE_PARENT = "9cf56e149a105026b072c9073d7e87b93103966e"
CAPTURED_AT_UTC = "2026-07-14T15:10:06Z"
BASELINE_LOG_PATH = "release/0.9.0/current-head/evidence/source-cut-p0r.log.gz"
SOURCE_SIGNATURE = {
    "format": "ssh",
    "status": "verified",
    "principal": "sepmhn@gmail.com",
    "key_fingerprint": "SHA256:3gaatfl4IVnuBX4D60Jxw9oVIrvEE1ZphK8IuEyrfPU",
}
BASELINE_COMPRESSED_SHA256 = (
    "53d3bcba011be9ac83bbf4975080ff27b33bbf17a99ca2179026e0071ed7f1dc"
)
BASELINE_UNCOMPRESSED_SHA256 = (
    "fbf69d44b56e0abf41ff1efc5bfeced7e3931aff37af05df2d5c1d87a6f07dd8"
)
BASELINE_GATES = (
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
    "offline Zenoh profile",
    "retained live Zenoh evidence",
    "forbidden claims",
    "generated vectors",
    "interop (COSE/CBOR)",
    "diff hygiene",
)

IMPLEMENTATION_COMMIT = "bfe0b136213a823913cee0f2f7e21e2992c6aced"
IMPLEMENTATION_TREE = "02b19c32ab61e76ff217dacaef974f6dfc7b59e4"
BOOTSTRAP_REQUIREMENTS_SHA256 = (
    "61e9f56bce2edafb6ec94db0bd3c6ad991e65065f0bc44b807a84900abfa9f40"
)
BOOTSTRAP_REQUIREMENTS_BYTES = 122_010
BOOTSTRAP_REQUIREMENTS_LINES = 3_820
QUALIFICATION_PATH = "release/0.9.0/current-head/closures/CH-T000-qualification.json"
REVIEW_PATH = "release/0.9.0/current-head/reviews/CH-T000.json"
R02_BFE_REVIEW_PATH = "release/0.9.0/current-head/reviews/CH-T000-R02-bfe.json"
PINNED_BFE_EVIDENCE_RECORDS = {
    "release/0.9.0/current-head/evidence/ch-t000-implementation-p0r.json": {
        "path": "release/0.9.0/current-head/evidence/ch-t000-implementation-p0r.json",
        "sha256": "513096a816e24220c7d18f31290faa54546fd60670479ba7f45bada01a0befaf",
        "bytes": 2_545,
        "lines": 46,
    },
    "release/0.9.0/current-head/evidence/ch-t000-implementation-p0r.log.gz": {
        "path": "release/0.9.0/current-head/evidence/ch-t000-implementation-p0r.log.gz",
        "sha256": "417bde0ef2f6dd0f9ce59b95c4e209d15160ea5ae6ddbd63218bdc07ec307933",
        "bytes": 20_907,
    },
    "release/0.9.0/current-head/evidence/ch-t000-clean-linux-review.json": {
        "path": "release/0.9.0/current-head/evidence/ch-t000-clean-linux-review.json",
        "sha256": "9958d8752af1e4bbc4d4d66ae016f4da8b327f5eb120088ed82d0dd0de5ddc78",
        "bytes": 5_620,
        "lines": 93,
    },
    "release/0.9.0/current-head/evidence/ch-t000-clean-linux-review.log.gz": {
        "path": "release/0.9.0/current-head/evidence/ch-t000-clean-linux-review.log.gz",
        "sha256": "918bd15c9a46415282512666d3ade66021022b48bc7b5178047d2103a35da99c",
        "bytes": 379,
    },
    R02_BFE_REVIEW_PATH: {
        "path": R02_BFE_REVIEW_PATH,
        "sha256": "5e1deac021a91931f5d8c1a54e7a8278ae4bc434aec7f4b5a497e07af8d0c598",
        "bytes": 31_756,
        "lines": 507,
    },
}
ACTIVATION_PATH = "release/0.9.0/current-head/closures/CH-T000-activation.json"
REVOCATION_PATH = "release/0.9.0/current-head/closures/CH-T000-revocations.json"
SUCCESSOR_REGISTRY_PATH = (
    "release/0.9.0/current-head/closures/task-verifier-registry.json"
)
ACTIVE_CLAIMS_PATH = "release/0.9.0/current-head/closures/active-claims.json"
FINAL_FRAMEWORK_PATHS = {
    ".github/workflows/ci.yml",
    "README.md",
    "docs/COMPLETION-CHECKLIST.md",
    "docs/EVIDENCE-SEMANTICS.md",
    "docs/LIMITATIONS.md",
    "docs/PROJECT-CATALOG.md",
    "docs/ROADMAP-STATUS.md",
    "docs/galadriels-mirror.md",
    "docs/release/0.9.0/README.md",
    "docs/release/0.9.0/THREAT-MODEL.md",
    "justfile",
    "tools/p0r-exit-gate.sh",
    "tools/release/current-audit-gate.sh",
    "tools/release/verify-current-audit.py",
    "tools/release/test_verify_current_audit.py",
    "tools/release/current-audit-resource-profile.py",
    "tools/release/test_current_audit_resource_profile.py",
    "tools/release/current_audit_test_fixtures.py",
    "release/0.9.0/current-head/HANDOFF-ERRATA-QUALIFICATION-AMENDMENT.md",
    "release/0.9.0/current-head/HANDOFF-ERRATA.md",
    "release/0.9.0/current-head/README.md",
}
FRAMEWORK_PATH_STATUSES = {
    ".github/workflows/ci.yml": "M",
    "README.md": "M",
    "docs/COMPLETION-CHECKLIST.md": "M",
    "docs/EVIDENCE-SEMANTICS.md": "M",
    "docs/LIMITATIONS.md": "M",
    "docs/PROJECT-CATALOG.md": "M",
    "docs/ROADMAP-STATUS.md": "M",
    "docs/galadriels-mirror.md": "M",
    "docs/release/0.9.0/README.md": "M",
    "docs/release/0.9.0/THREAT-MODEL.md": "M",
    "justfile": "M",
    "release/0.9.0/current-head/HANDOFF-ERRATA-QUALIFICATION-AMENDMENT.md": "A",
    "release/0.9.0/current-head/HANDOFF-ERRATA.md": "M",
    "release/0.9.0/current-head/README.md": "M",
    "tools/p0r-exit-gate.sh": "M",
    "tools/release/current-audit-gate.sh": "A",
    "tools/release/current-audit-resource-profile.py": "A",
    "tools/release/current_audit_test_fixtures.py": "A",
    "tools/release/test_current_audit_resource_profile.py": "A",
    "tools/release/test_verify_current_audit.py": "M",
    "tools/release/verify-current-audit.py": "M",
}
FRAMEWORK_STAGE_FROZEN_PATHS = tuple(sorted(FINAL_FRAMEWORK_PATHS))
FRAMEWORK_CORE_FROZEN_PATHS = tuple(
    sorted(
        {
            "release/0.9.0/current-head/HANDOFF-ERRATA-QUALIFICATION-AMENDMENT.md",
            "release/0.9.0/current-head/HANDOFF-ERRATA.md",
            "tools/release/verify-current-audit.py",
            "tools/release/current-audit-gate.sh",
            "tools/release/test_verify_current_audit.py",
            "tools/release/current-audit-resource-profile.py",
            "tools/release/test_current_audit_resource_profile.py",
            "tools/release/current_audit_test_fixtures.py",
        }
    )
)
QUALIFICATION_AMENDMENT_RECORD = {
    "path": "release/0.9.0/current-head/HANDOFF-ERRATA-QUALIFICATION-AMENDMENT.md",
    "sha256": "550276a5d533e79784868f1125ee95c7df2b114f48e92cc3d989aa6cbd7ea6b7",
    "bytes": 3_915,
    "lines": 71,
}
IMPLEMENTATION_GATES = (
    BASELINE_GATES[:13]
    + (
        "current-head audit tests",
        "current-head audit cut",
    )
    + BASELINE_GATES[13:21]
    + ("live Gate dev smoke tests",)
    + BASELINE_GATES[21:23]
    + ("retained live Gate dev smoke",)
    + BASELINE_GATES[23:]
)
FRAMEWORK_GATES = (
    ("current-head audit gate",)
    + BASELINE_GATES[:21]
    + ("live Gate dev smoke tests",)
    + BASELINE_GATES[21:23]
    + ("retained live Gate dev smoke",)
    + BASELINE_GATES[23:]
)

QUALIFICATION_EVIDENCE_PATHS = (
    "release/0.9.0/current-head/evidence/ch-t000-implementation-p0r.json",
    "release/0.9.0/current-head/evidence/ch-t000-implementation-p0r.log.gz",
    "release/0.9.0/current-head/evidence/ch-t000-clean-linux-review.json",
    "release/0.9.0/current-head/evidence/ch-t000-clean-linux-review.log.gz",
    "release/0.9.0/current-head/evidence/ch-t000-implementation-ci.json",
    "release/0.9.0/current-head/evidence/ch-t000-implementation-ci-attempt.json",
    "release/0.9.0/current-head/evidence/ch-t000-implementation-ci.log.gz",
    "release/0.9.0/current-head/evidence/ch-t000-implementation-formal.json",
    "release/0.9.0/current-head/evidence/ch-t000-implementation-formal-attempt.json",
    "release/0.9.0/current-head/evidence/ch-t000-implementation-formal.log.gz",
)
FRAMEWORK_EVIDENCE_PATHS = (
    "release/0.9.0/current-head/evidence/ch-t000-framework-p0r.json",
    "release/0.9.0/current-head/evidence/ch-t000-framework-p0r.log.gz",
    "release/0.9.0/current-head/evidence/ch-t000-framework-clean-linux-review.json",
    "release/0.9.0/current-head/evidence/ch-t000-framework-clean-linux-review.log.gz",
    "release/0.9.0/current-head/evidence/ch-t000-framework-ci.json",
    "release/0.9.0/current-head/evidence/ch-t000-framework-ci-attempt.json",
    "release/0.9.0/current-head/evidence/ch-t000-framework-ci.log.gz",
    "release/0.9.0/current-head/evidence/ch-t000-framework-formal.json",
    "release/0.9.0/current-head/evidence/ch-t000-framework-formal-attempt.json",
    "release/0.9.0/current-head/evidence/ch-t000-framework-formal.log.gz",
    "release/0.9.0/current-head/evidence/ch-t000-resource-profile.json",
    "release/0.9.0/current-head/reviews/CH-T000-R01-framework.json",
    "release/0.9.0/current-head/reviews/CH-T000-R02-framework.json",
)
FRAMEWORK_CLEAN_LINUX_ATTEMPT_PATH = (
    "release/0.9.0/current-head/evidence/"
    "ch-t000-framework-clean-linux-review-attempt.json"
)
QUALIFIED_OPEN_DATA_PATHS = {
    QUALIFICATION_PATH,
    REVIEW_PATH,
    R02_BFE_REVIEW_PATH,
    *QUALIFICATION_EVIDENCE_PATHS,
    *FRAMEWORK_EVIDENCE_PATHS,
    FRAMEWORK_CLEAN_LINUX_ATTEMPT_PATH,
}
ACTIVATION_EVIDENCE_PATHS = (
    "release/0.9.0/current-head/evidence/ch-t000-qualification-p0r.json",
    "release/0.9.0/current-head/evidence/ch-t000-qualification-p0r.log.gz",
    "release/0.9.0/current-head/evidence/ch-t000-qualification-clean-linux.json",
    "release/0.9.0/current-head/evidence/ch-t000-qualification-clean-linux.log.gz",
    "release/0.9.0/current-head/evidence/ch-t000-qualification-ci.json",
    "release/0.9.0/current-head/evidence/ch-t000-qualification-ci-attempt.json",
    "release/0.9.0/current-head/evidence/ch-t000-qualification-ci.log.gz",
    "release/0.9.0/current-head/evidence/ch-t000-qualification-formal.json",
    "release/0.9.0/current-head/evidence/ch-t000-qualification-formal-attempt.json",
    "release/0.9.0/current-head/evidence/ch-t000-qualification-formal.log.gz",
)
ACTIVATION_DATA_PATHS = {
    ACTIVATION_PATH,
    REVOCATION_PATH,
    SUCCESSOR_REGISTRY_PATH,
    ACTIVE_CLAIMS_PATH,
    "release/0.9.0/current-head/requirements.json",
    *ACTIVATION_EVIDENCE_PATHS,
}

C_EVIDENCE_PATHS = (
    *QUALIFICATION_EVIDENCE_PATHS,
    R02_BFE_REVIEW_PATH,
    *FRAMEWORK_EVIDENCE_PATHS,
    FRAMEWORK_CLEAN_LINUX_ATTEMPT_PATH,
)
BASE_IMMUTABLE_PATHS = (
    "release/0.9.0/allowed-signers",
    "release/0.9.0/current-head/audit-inputs.json",
    "release/0.9.0/current-head/evidence/publication-state.json",
    "release/0.9.0/current-head/evidence/source-cut-ci.json",
    "release/0.9.0/current-head/evidence/source-cut-ci.log.gz",
    "release/0.9.0/current-head/evidence/source-cut-formal.json",
    "release/0.9.0/current-head/evidence/source-cut-formal.log.gz",
    "release/0.9.0/current-head/evidence/source-cut-p0r.log.gz",
    "release/0.9.0/current-head/handoff/HALDIR_V1_0_CURRENT_HEAD_MAX_EFFORT_HANDOFF.zip",
    "release/0.9.0/current-head/handoff/MASTER_CURRENT_HEADS.json",
    "release/0.9.0/current-head/handoff/MASTER_SHA256SUMS.txt",
    "release/0.9.0/current-head/handoff/PACKAGE_INDEX.json",
    "release/0.9.0/current-head/handoff/SEPAHEAD_V1_0_CURRENT_HEAD_CROSS_REPO_RECONCILIATION_HANDOFF.zip",
)
C_EVIDENCE_IDS = (
    "CH-T000-E01",
    "CH-T000-E02",
    "CH-T000-E03",
    "CH-T000-E04",
    "CH-T000-E05",
    "CH-T000-E06",
    "CH-T000-Q01",
    "CH-T000-Q02",
    "CH-T000-Q03",
    "CH-T000-Q04",
    "CH-T000-Q05",
    "CH-T000-Q06",
    "CH-T000-Q07",
    "CH-T000-Q08",
)
ACTIVATION_EVIDENCE_IDS = tuple(f"CH-T000-A{index:02d}" for index in range(1, 6))
TERMINAL_EVIDENCE_IDS = [*C_EVIDENCE_IDS, *ACTIVATION_EVIDENCE_IDS]


def _require_unique_catalog(label: str, values: tuple[str, ...] | list[str]) -> None:
    if len(values) != len(set(values)):
        raise CurrentAuditError(f"CURRENT_AUDIT_STATIC_CATALOG_DUPLICATE:{label}")


QUALIFICATION_SCOPE = (
    "Exact technical qualification of the CH-T000 current-head input freeze and "
    "its fail-closed qualification framework only; no runtime-correctness, safety, "
    "deployment, field-validation, security-certification, publication, named-human-"
    "approval, or release-readiness claim."
)
QUALIFICATION_EFFECTIVE_CONDITION = (
    "SIGNED_DATA_ONLY_ACTIVATION_COMMIT_BINDING_EXACT_QUALIFICATION_COMMIT_"
    "EVIDENCE_AND_TERMINAL_LEDGER_TRANSITION"
)
LEAD_APPROVAL_EFFECTIVE_ON = (
    "SIGNED_COMMIT_FIRST_CONTAINING_THIS_REVIEW_AND_QUALIFICATION"
)
HUMAN_REVIEW_BOUNDARY = {
    "named_human_approval": "NOT_PERFORMED",
    "independent_human_review": "NOT_PERFORMED",
    "release_approval": "NOT_GRANTED",
    "security_certification": "NOT_GRANTED",
    "automated_review_is_human_approval": False,
}
RELEASE_AUTHORITY_BOUNDARY = {
    "overall_release_status": "NO_GO",
    "public_claim_change": "NONE",
    "deployment_authorized": False,
    "publication_authorized": False,
    "tag_or_release_authorized": False,
    "doi_or_zenodo_authorized": False,
}
LENS_NAMES = (
    "Claims and scope",
    "First-principles semantics",
    "Mathematics and statistics",
    "Type and state integrity",
    "Time, ordering, and replay",
    "Identity and provenance",
    "Authentication and cryptography",
    "Authority and safety",
    "Hostile inputs and parsers",
    "Resource and denial-of-service bounds",
    "Concurrency and lifecycle",
    "Determinism and reproducibility",
    "API, FFI, and SemVer",
    "Schema, wire, and language parity",
    "Configuration and deployment",
    "Observability and forensics",
    "Verification and evidence quality",
    "Ecosystem composition",
    "Human factors and governance",
    "Counterfactual and quirky-case review",
)
HANDOFF_LENS_QUESTIONS = (
    "Can a reader infer more than the exact evidence tier supports? Separate implemented, verified, validated, deployment-qualified, field-validated, and not-claimed.",
    "Are inputs, state, transitions, outputs, invariants, units, and failure states explicit rather than implied by names?",
    "Are definitions, assumptions, estimands, finite-sample behavior, multiplicity, uncertainty, calibration, and failure regions correct and explicit?",
    "Can invalid combinations be constructed through safe APIs, deserialization, FFI, feature flags, defaults, or migration?",
    "Are clock domains, freshness, deadlines, sessions, epochs, generations, sequence numbers, duplicates, restart, and rollover unambiguous?",
    "Can every result, command, model, dataset, scene, schema, configuration, build, and evidence artifact be traced immutably?",
    "Are canonical bytes, domain separation, algorithms, identities, rotation, revocation, downgrade resistance, and failure semantics complete?",
    "Who may observe, advise, intend, authorize, publish, apply, and confirm? Can any fallback or optional component widen authority?",
    "What happens with duplicates, unknown fields, unsafe integers, NaN/Inf, Unicode ambiguity, malformed nesting, path tricks, and contradictory metadata?",
    "Are bytes, allocations, dimensions, states, queues, retries, threads, log volume, GPU/CPU work, and serialization bounded before expensive work?",
    "Are initialization, callback ownership, races, cancellation, selected events, cleanup, crash consistency, and shutdown fully specified?",
    "Can independent clean machines reproduce code generation, builds, fixtures, simulations, proofs, benchmarks, evidence, and archives?",
    "Is the stable surface minimal and are panic, ownership, allocation, thread safety, features, MSRV/runtime, and compatibility explicit?",
    "Is there one normative semantic source and do all languages/encodings accept and reject the same corpus?",
    "Can invalid profiles start? Are paths, secrets, permissions, ACLs, certificates, environments, startup order, and rollback safe?",
    "Can disabled, unavailable, stale, incompatible, insufficient, anomalous, denied, and internal-fault states be distinguished without leaking secrets?",
    "Does each claim have the right proof: theorem, model, property, fuzz, mutation, clean-room, real-router, statistical, or physical evidence?",
    "Are pid-rs, NCP, Engram, Prisoma, Crebain, Galadriel, Haldir, ROS, and external authority relationships explicit and acyclic?",
    "Are naming, docs, examples, runbooks, review roles, incident response, support, deprecation, and withdrawal usable under stress?",
    "How would a malicious peer, rushed operator, odd-but-simple dataset, future maintainer, or AI-generated patch falsify the intended claim?",
)
EXTERNAL_HUMAN_REVIEW_KINDS = frozenset(
    {
        "EXTERNAL_CRYPTOGRAPHIC_REVIEW",
        "EXTERNAL_FORMAL_METHODS_REVIEW",
        "EXTERNAL_SECURE_DEPLOYMENT_REVIEW",
        "EXTERNAL_CLEAN_ROOM_REPRODUCTION",
    }
)
LEAD_REVIEW_KINDS = frozenset(
    {
        "LEAD_IMPLEMENTATION_REVIEW",
        "LEAD_ONLY_TWENTY_LENS_DIFF_REVIEW",
        "SIGNED_RELEASE_DECISION_REVIEW",
    }
)
HANDOFF_PROCEDURE = (
    "Read every in-scope file line by line, including tests, examples, generated output, workflow, documentation, and relevant Git history; record blob and SHA-256 identities.",
    "Write a current-behavior table covering inputs, validation, state, transitions, outputs, errors, resources, time, identity, persistence, concurrency, and public claims.",
    "Enumerate all plausible semantic interpretations and construct at least one counterexample or misuse for each rejected interpretation.",
    "Write normative SHALL/SHALL NOT requirements with stable IDs and exact accepted/rejected cases; obtain lead approval before implementation.",
    "Implement the smallest coherent change and delete, quarantine, or version any contradictory legacy/default/fallback path.",
    "Add positive, malformed, empty, min/max, non-finite, duplicate, stale, reordered, replayed, future, capacity, cancellation, restart, and migration tests as applicable.",
    "Add property/metamorphic, differential/oracle, fuzz, mutation-sensitive, concurrency, resource, and integration tests appropriate to the claim tier.",
    "Generate evidence from a clean checkout with exact tools, commands, configs, seeds, data/models, platform/hardware, raw outputs, exit status, and checksums.",
    "Update schemas, API snapshots, migration, examples, README/docs, claim/evidence ledger, support matrix, and exact downstream pins.",
    "Have an independent reviewer reproduce the decisive evidence and review every changed line plus relevant unchanged context.",
    "Run the subsystem gate, complete wave gate, full locked CI, and every affected downstream conformance job.",
    "Close only after all twenty lenses are resolved with evidence; otherwise remove/narrow the claim and leave the task OPEN.",
)
HANDOFF_COUNTERFACTUALS = (
    "valid syntax with contradictory semantics",
    "authenticated but unauthorized producer",
    "stale yet correctly signed data",
    "correct version string with wrong contract/algorithm digest",
    "clean synthetic result under nonrepresentative distribution",
    "timeout or capacity exhaustion followed by convenience fallback",
    "feature unification activating a privileged/experimental path",
    "partial migration accepted through default values",
    "crash between decision/output and durable evidence",
    "simple but odd input unlikely to resemble training examples",
)
HANDOFF_REQUIRED_EVIDENCE = (
    "FILE_REVIEW_LEDGER and requirement traceability updates",
    "complete commands/logs/exit codes",
    "positive and negative vectors or fixtures",
    "coverage, fuzz/mutation or model results where applicable",
    "resource/time distributions at declared maxima",
    "exact identities and checksums",
    "independent reviewer record",
    "claim and migration disposition",
)
HANDOFF_PRECONDITIONS = (
    "HEAD equals 9cf56e149a105026b072c9073d7e87b93103966e or an approved updated audit cut exists.",
    "Every in-scope tracked/generated file is present in FILE_REVIEW_LEDGER.csv and assigned to a named reviewer.",
    "The current behavior, public claim tier, assumptions, affected consumers, and rollback are recorded before editing.",
)
HANDOFF_COMPLETION_RULE = (
    "No prose-only closure. Every acceptance condition and evidence item must "
    "pass on the exact candidate; otherwise mark NOT_CLAIMED or NO_GO."
)
BOOTSTRAP_AMENDMENT_SEMANTICS = {
    "CH-T000": {
        "exception": "INITIAL_FREEZE_AND_RETROSPECTIVE_TECHNICAL_QUALIFICATION_ONLY",
        "postconditions": [
            "CH-T001_AND_CH-T002_REPOSITORY_WIDE_REVIEW_DEFERRED_HARD_BLOCKER_FOR_CH-T003",
            "INDEPENDENT_AUTOMATED_FRAMEWORK_REVIEW_REQUIRED_BEFORE_D",
            "NO_RELEASE_OR_EXTERNAL_AUTHORITY",
        ],
    },
    "CH-T001": {
        "exception": "GENERATE_AND_RECONCILE_FILE_LEDGER_WITHOUT_PREEXISTING_LEDGER",
        "postconditions": [
            "COMPLETE_INVENTORY",
            "INDEPENDENT_RECONCILIATION_RETAINED",
        ],
    },
    "CH-T002": {
        "exception": "ASSIGN_AND_REVIEW_COMPLETED_CH-T001_INVENTORY",
        "postconditions": [
            "EVERY_IN_SCOPE_FILE_EXPLICITLY_ASSIGNED",
            "REQUIRED_REVIEW_EVIDENCE_RETAINED",
        ],
    },
    "CH-T003": {
        "exception": None,
        "postconditions": [
            "COMPLETE_CH-T001_INVENTORY_RETAINED",
            "COMPLETE_CH-T002_ASSIGNMENTS_AND_REVIEWS_RETAINED",
        ],
    },
}

EXPECTED_IMPLEMENTATION_RUNS = {
    "ci": {
        "kind": "EXACT_GITHUB_CI_RUN",
        "run_id": 29_344_463_711,
        "attempt": 1,
        "workflow_id": 311_605_710,
        "workflow_name": "ci",
        "event": "push",
        "head_sha": IMPLEMENTATION_COMMIT,
        "head_branch": "main",
        "status": "completed",
        "conclusion": "success",
        "created_at": "2026-07-14T15:14:30Z",
        "updated_at": "2026-07-14T15:15:41Z",
        "attempt_updated_at": "2026-07-14T15:15:41Z",
        "attempt_url": (
            "https://github.com/sepahead/haldir/actions/runs/29344463711/attempts/1"
        ),
        "job_ids": [
            87_124_395_207,
            87_124_395_225,
            87_124_395_275,
            87_124_395_298,
            87_124_395_299,
            87_124_395_367,
        ],
        "jobs": [
            "supply-chain",
            "feature-matrix",
            "interop",
            "clean-build",
            "build-test",
            "macos-compile",
        ],
    },
    "formal": {
        "kind": "EXACT_GITHUB_FORMAL_RUN",
        "run_id": 29_344_463_943,
        "attempt": 1,
        "workflow_id": 311_703_244,
        "workflow_name": "formal",
        "event": "push",
        "head_sha": IMPLEMENTATION_COMMIT,
        "head_branch": "main",
        "status": "completed",
        "conclusion": "success",
        "created_at": "2026-07-14T15:14:30Z",
        "updated_at": "2026-07-14T15:14:46Z",
        "attempt_updated_at": "2026-07-14T15:14:47Z",
        "attempt_url": (
            "https://github.com/sepahead/haldir/actions/runs/29344463943/attempts/1"
        ),
        "job_ids": [87_124_395_928],
        "jobs": ["tlc-model-check"],
    },
}

EXPECTED_HANDOFF = {
    "archive_sha256": "1de5cfc2a577621c24ef10e97fd2319799d02b602cfb3de54954928a0d988efe",
    "audit_cut_sha256": "b77dcffa56ec0eb0f80fbbd29ff6f7c98ebf8b894e23393f67685b952af80ca6",
    "ledger_sha256": "891601e322f453499fc7a3375728d43f7cfb0eaa193be5b96b1a5d6c7aae0f40",
    "readme_sha256": "bf1d3ea1d830d60a5e8ea9d41b32e5845748165a28d124e52497610b8c3e6f47",
    "sha256s_sha256": "5ed07cc488640d512342c8b3adc1feeda523f897f5f9734cdf62441766d216b0",
}

EXPECTED_SOURCE_FILES = {
    "Cargo.toml": "1712be900a8bab7aa0f5b12a6f1c6d47bbce4078a420936bc598673517f865a2",
    "Cargo.lock": "8767fc69ea7b90b374de6ca77e9d22dbfac0e3b1db236ea03d24f05470d2831f",
    "rust-toolchain.toml": "61d97acc9676fd1b6348a44dee3c372804b9a1e984385c7d73a2620b322d4927",
    "deny.toml": "08e563a6f20d8a5423b0a85a2c2183a9b3d82d0b40ca6efac0ab62976e863ae6",
    "tools/pins.toml": "0cd9c3279c61266c1e926fd1fcce8cd6cab38baf119d1be9e19c7ccc12d7fcb6",
    "deploy/secure-reference-v1/profile.json": "76a10873155ef5fe85f13117fdf6fcb6f3938399823cbb6af9bff523a3b54e06",
    "formal/HaldirAuthority.tla": "0ab0bc5826c356cab6e01555a32fbc489286988b575c62605e740b69c6e5e61e",
    "formal/HaldirAuthority.cfg": "20651c85285170ac0bbd35b6f6b9c31597fd63b28e7678b72388033dbad3c58f",
    ".github/workflows/ci.yml": "171618c83effa8579f492ad79a5e0df0a54a27f72a5b6d8989ffcbc5a5c8180b",
    ".github/workflows/formal.yml": "3de8203531471e675ee03b535fb7c690527a7fd6922a9dd3edb4be32a83443b5",
    "justfile": "4633a855139a3fd799f20f099ed1dc5ab7d5fb6960ceb0880dbd03ef9565c0ca",
    "release/0.9.0/allowed-signers": "88eddddf1b3a6d0176acf2ec88b1d3c120453e2658651c49b82d41057caa78ed",
}

PACKAGE_MANIFESTS = {
    "crates/haldir-admission/Cargo.toml": "haldir-admission",
    "crates/haldir-contracts/Cargo.toml": "haldir-contracts",
    "crates/haldir-core/Cargo.toml": "haldir-core",
    "crates/haldir-crypto/Cargo.toml": "haldir-crypto",
    "crates/haldir-deployment/Cargo.toml": "haldir-deployment",
    "crates/haldir-durable/Cargo.toml": "haldir-durable",
    "crates/haldir-evidence/Cargo.toml": "haldir-evidence",
    "crates/haldir-gate/Cargo.toml": "haldir-gate",
    "crates/haldir-ncp08/Cargo.toml": "haldir-ncp08",
    "crates/haldir-policy-native/Cargo.toml": "haldir-policy-native",
    "crates/haldir-range/Cargo.toml": "haldir-range",
    "crates/haldir-reference-plant/Cargo.toml": "haldir-reference-plant",
    "crates/haldir-state/Cargo.toml": "haldir-state",
    "crates/haldir-testkit/Cargo.toml": "haldir-testkit",
    "crates/haldir-transport-zenoh/Cargo.toml": "haldir-transport-zenoh",
    "tools/haldir-ctl/Cargo.toml": "haldir-ctl",
}

EXPECTED_MASTER_HANDOFF = {
    "prepared": "2026-07-14",
    "checksums_verified": True,
    "master_sha256s_sha256": "0d4d1c19600bd8e5d930cb269fcaa204e80e9728914572664af7961566d3ba57",
    "current_heads_sha256": "dc393b47bac804fa9dd47215e6eced584d0b6863cf57b383ff5957bcbae4bbf6",
    "package_index_sha256": "cec6b200866b0a34473c4429c74137c87790c1fe073a19453ed79e147e32411d",
    "master_validation_sha256": "e693dafd3d53ab031b499f358e3a680a5d2c5fd538023e83fd935f5fd020c777",
    "cross_archive_sha256": "ae06b5525537e88de4ae37aa49b40de01893061bdc3096bcf1059c5c6d71e3d4",
    "cross_sha256s_sha256": "40bd8855cb1ae574d7fb91688d8567a7267089bd80c739c8b1f3270a4efe42f6",
    "cross_ledger_sha256": "807d9e2087e932725513dba0eb0d9de252fed85fcce6b75d0121f252fd08f582",
    "cross_current_heads_sha256": "f43c85b88e71c002ef0f91b2f080526566b3f1e983ae0022f402eadc52efaffa",
    "frozen_heads": {
        "NCP": "0ba5ff6e963225b0635f8fec349278f1ac287df3",
        "crebain": "4c311900ade5668200a48d56fb191be1916b884a",
        "galadriel": "94e2f8cc01f352d2bf899b7f656997f143a2588f",
        "haldir": SOURCE_PARENT,
        "pid-rs": "64060035ea36e380004949f06dd226dcc7242b96",
    },
    "approved_audit_heads": {
        "NCP": "0ba5ff6e963225b0635f8fec349278f1ac287df3",
        "crebain": "4c311900ade5668200a48d56fb191be1916b884a",
        "galadriel": "94e2f8cc01f352d2bf899b7f656997f143a2588f",
        "haldir": SOURCE_COMMIT,
        "pid-rs": "64060035ea36e380004949f06dd226dcc7242b96",
    },
    "other_head_verification_scope": (
        "CHECKSUM_VERIFIED_HANDOFF_ASSERTIONS; NON_HALDIR_GIT_OBJECTS NOT VERIFIED HERE"
    ),
    "child_archives": {
        "NCP": {
            "sha256": "661c5a9bd6a62a8a973bc953fd45ba1a58d44592985c871fc6b039c9cbdd333b",
            "files": 23,
            "tasks": 146,
        },
        "crebain": {
            "sha256": "c7c8a342e5a4b94c2d4c411299c63ed1c01163acff847d9bf7389ed8ea8c052a",
            "files": 23,
            "tasks": 159,
        },
        "galadriel": {
            "sha256": "41bd414e38e7f46a0417005d59e2b0c0eb5e139ec38cce632e006b60a750cd94",
            "files": 23,
            "tasks": 116,
        },
        "haldir": {
            "sha256": EXPECTED_HANDOFF["archive_sha256"],
            "files": 23,
            "tasks": 126,
        },
        "pid-rs": {
            "sha256": "9fcdcaf1e5254942c8dbdf4cea3890f6a858674bd6fd613b14f353b2a60e4730",
            "files": 47,
            "tasks": 159,
        },
    },
    "cross_repo": {"files": 12, "tasks": 79},
    "retained_inputs": [
        {
            "path": "release/0.9.0/current-head/handoff/HALDIR_V1_0_CURRENT_HEAD_MAX_EFFORT_HANDOFF.zip",
            "sha256": EXPECTED_HANDOFF["archive_sha256"],
            "bytes": 43_202,
        },
        {
            "path": "release/0.9.0/current-head/handoff/MASTER_CURRENT_HEADS.json",
            "sha256": "dc393b47bac804fa9dd47215e6eced584d0b6863cf57b383ff5957bcbae4bbf6",
            "bytes": 402,
        },
        {
            "path": "release/0.9.0/current-head/handoff/MASTER_SHA256SUMS.txt",
            "sha256": "0d4d1c19600bd8e5d930cb269fcaa204e80e9728914572664af7961566d3ba57",
            "bytes": 1_356,
        },
        {
            "path": "release/0.9.0/current-head/handoff/PACKAGE_INDEX.json",
            "sha256": "cec6b200866b0a34473c4429c74137c87790c1fe073a19453ed79e147e32411d",
            "bytes": 1_345,
        },
        {
            "path": "release/0.9.0/current-head/handoff/SEPAHEAD_V1_0_CURRENT_HEAD_CROSS_REPO_RECONCILIATION_HANDOFF.zip",
            "sha256": "ae06b5525537e88de4ae37aa49b40de01893061bdc3096bcf1059c5c6d71e3d4",
            "bytes": 11_647,
        },
    ],
}

EXPECTED_INPUT_SCOPE = {
    "workspace_packages": {
        "count": 16,
        "source_version": "0.1.0-experimental",
        "registry_publication": False,
        "names": sorted(PACKAGE_MANIFESTS.values()),
    },
    "formal_artifacts": [
        "formal/HaldirAuthority.cfg",
        "formal/HaldirAuthority.tla",
        "formal/README.md",
    ],
    "test_data": [
        "crates/haldir-ncp08/tests/data/ncp-v0.8.0/README.md",
        "crates/haldir-ncp08/tests/data/ncp-v0.8.0/command_frame.json",
        "crates/haldir-ncp08/tests/data/ncp-v0.8.0/command_frame.schema.json",
    ],
    "deployment_profiles": ["deploy/secure-reference-v1/profile.json"],
    "interop_corpora": ["tools/interop/vectors.json"],
    "machine_learning_models": [],
    "papers": [],
    "paper_suffixes_scanned": [".bib", ".pdf", ".tex"],
    "scope_note": (
        "No ML model or paper artifact is tracked; the immutable source tree binds all "
        "other schemas, fixtures, generated evidence, and documentation."
    ),
}

EXPECTED_PUBLICATION_STATE = {
    "local_tags": [],
    "remote_tags": [],
    "github_releases": [],
    "cleanup_disposition": "VERIFIED_NO_OP",
    "evidence": {
        "path": "release/0.9.0/current-head/evidence/publication-state.json",
        "sha256": "2cd20381ce5001bdc36b080bfc0a887b06c6215e3c481a90f351353038e9dba1",
        "bytes": 530,
        "lines": 20,
    },
}

EXPECTED_REQUIREMENTS_LEDGER = {
    "path": "release/0.9.0/current-head/requirements.json",
    "schema_version": "1.0.0",
    "task_namespace": "CH-T000..CH-T125",
    "task_count": 126,
    "identity_sha256": "8b2c92a373514e30c1ab0f5e741ad595c0e3b2e67e37dc660deb43d64a7a6cfb",
    "source_ledger_sha256": EXPECTED_HANDOFF["ledger_sha256"],
    "legacy_ledger_sha256": "04454e6eeba74a1e36fccbfa7110437f3fffb00778ce019819852b7678b04b2d",
}

EXPECTED_GITHUB_CHECKS = {
    "ci": {
        "run_id": 29_327_196_587,
        "workflow": "ci",
        "event": "push",
        "status": "completed",
        "conclusion": "success",
        "head_sha": SOURCE_COMMIT,
        "head_branch": "main",
        "created_at": "2026-07-14T10:57:35Z",
        "updated_at": "2026-07-14T10:58:47Z",
        "url": "https://github.com/sepahead/haldir/actions/runs/29327196587",
        "jobs": [
            "interop",
            "macos-compile",
            "supply-chain",
            "feature-matrix",
            "build-test",
            "clean-build",
        ],
        "metadata_evidence": {
            "path": "release/0.9.0/current-head/evidence/source-cut-ci.json",
            "sha256": "55817853d79845b38141f9cc6ca0f25d2c05b9ebff3c815bf153ed625326daf1",
            "bytes": 16_469,
            "lines": 512,
        },
        "log_evidence": {
            "path": "release/0.9.0/current-head/evidence/source-cut-ci.log.gz",
            "compressed_sha256": "c7bd25803990b4bf314b06091f775476fba60b6cde9f83fed2ce11b60c97f6f5",
            "compressed_bytes": 65_961,
            "uncompressed_sha256": "4a5cbf61cb184821332ae851f5c1f57da7f94cb301113ed9b5b58281f3e57794",
            "uncompressed_bytes": 443_370,
            "uncompressed_lines": 3_870,
        },
    },
    "formal": {
        "run_id": 29_327_196_583,
        "workflow": "formal",
        "event": "push",
        "status": "completed",
        "conclusion": "success",
        "head_sha": SOURCE_COMMIT,
        "head_branch": "main",
        "created_at": "2026-07-14T10:57:35Z",
        "updated_at": "2026-07-14T10:57:48Z",
        "url": "https://github.com/sepahead/haldir/actions/runs/29327196583",
        "jobs": ["tlc-model-check"],
        "metadata_evidence": {
            "path": "release/0.9.0/current-head/evidence/source-cut-formal.json",
            "sha256": "dd09e6df9702e7017cab4489e0f98b768481d2ae35b01e2d4266acd055789378",
            "bytes": 3_023,
            "lines": 97,
        },
        "log_evidence": {
            "path": "release/0.9.0/current-head/evidence/source-cut-formal.log.gz",
            "compressed_sha256": "854b9eb9c482d43277e1f554e58b875198ce2efad586443466f7bc02666165d7",
            "compressed_bytes": 5_664,
            "uncompressed_sha256": "2e32e702bbe83e4f128e7d12126ae62451ab37e4d7bae86ea7b1b60e712bd00a",
            "uncompressed_bytes": 29_867,
            "uncompressed_lines": 267,
        },
    },
}

EXPECTED_TOP_LEVEL = {
    "schema_version",
    "release_target",
    "captured_at_utc",
    "author",
    "persistent_identifier",
    "source",
    "handoff",
    "master_handoff",
    "input_scope",
    "approved_cut_update",
    "toolchains",
    "locked_inputs",
    "ncp",
    "baseline",
    "requirements_ledger",
    "repository_publication_state",
    "github_source_cut_checks",
}


class CurrentAuditError(ValueError):
    """The current-head audit manifest is malformed or contradicts its cut."""


for _catalog_label, _catalog_values in (
    ("framework_paths", tuple(FINAL_FRAMEWORK_PATHS)),
    ("framework_evidence_paths", FRAMEWORK_EVIDENCE_PATHS),
    ("qualification_evidence_paths", QUALIFICATION_EVIDENCE_PATHS),
    ("activation_evidence_paths", ACTIVATION_EVIDENCE_PATHS),
    ("c_evidence_paths", C_EVIDENCE_PATHS),
    ("c_evidence_ids", C_EVIDENCE_IDS),
    ("activation_evidence_ids", ACTIVATION_EVIDENCE_IDS),
    ("terminal_evidence_ids", TERMINAL_EVIDENCE_IDS),
):
    _require_unique_catalog(_catalog_label, _catalog_values)


def _reject_json_constant(value: str) -> None:
    raise CurrentAuditError(f"CURRENT_AUDIT_JSON_CONSTANT_REJECTED:{value}")


def _reject_json_float(value: str) -> None:
    raise CurrentAuditError(f"CURRENT_AUDIT_JSON_FLOAT_REJECTED:{value}")


def _parse_json_int(value: str) -> int:
    digits = value.removeprefix("-")
    if len(digits) > 19:
        raise CurrentAuditError("CURRENT_AUDIT_JSON_INTEGER_OUT_OF_RANGE")
    parsed = int(value)
    if parsed < -(2**63) or parsed > 2**63 - 1:
        raise CurrentAuditError("CURRENT_AUDIT_JSON_INTEGER_OUT_OF_RANGE")
    return parsed


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CurrentAuditError(f"CURRENT_AUDIT_DUPLICATE_JSON_KEY:{key}")
        result[key] = value
    return result


def _read_bounded(path: Path, limit: int, label: str) -> bytes:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise CurrentAuditError(f"CURRENT_AUDIT_NOFOLLOW_UNAVAILABLE:{label}")
    flags = os.O_RDONLY | nofollow | getattr(os, "O_BINARY", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        if error.errno in {errno.ELOOP, errno.EMLINK}:
            raise CurrentAuditError(
                f"CURRENT_AUDIT_SYMLINK_REJECTED:{label}"
            ) from error
        raise CurrentAuditError(f"CURRENT_AUDIT_READ_FAILED:{label}") from error
    try:
        return _read_descriptor_bounded(descriptor, limit, label)
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass


def _read_descriptor_bounded(descriptor: int, limit: int, label: str) -> bytes:
    if type(limit) is not int or limit < 0:
        raise CurrentAuditError(f"CURRENT_AUDIT_RESOURCE_LIMIT_INVALID:{label}")
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise CurrentAuditError(f"CURRENT_AUDIT_NOT_REGULAR_FILE:{label}")
        if before.st_size > limit:
            raise CurrentAuditError(f"CURRENT_AUDIT_RESOURCE_BOUND:{label}")
        payload = bytearray()
        while len(payload) <= limit:
            try:
                chunk = os.read(descriptor, min(64 * 1024, limit + 1 - len(payload)))
            except InterruptedError:
                continue
            if not chunk:
                break
            payload.extend(chunk)
        after = os.fstat(descriptor)
    except CurrentAuditError:
        raise
    except OSError as error:
        raise CurrentAuditError(f"CURRENT_AUDIT_READ_FAILED:{label}") from error
    result = bytes(payload)
    if len(result) > limit:
        raise CurrentAuditError(f"CURRENT_AUDIT_RESOURCE_BOUND:{label}")
    stable_fields = (
        "st_dev",
        "st_ino",
        "st_mode",
        "st_nlink",
        "st_uid",
        "st_gid",
        "st_size",
        "st_mtime_ns",
        "st_ctime_ns",
    )
    if any(getattr(before, field) != getattr(after, field) for field in stable_fields):
        raise CurrentAuditError(f"CURRENT_AUDIT_FILE_CHANGED_DURING_READ:{label}")
    if len(result) != after.st_size:
        raise CurrentAuditError(f"CURRENT_AUDIT_FILE_SIZE_RACE:{label}")
    return result


def _require_canonical_repo_path(raw_path: Any, label: str) -> str:
    if not isinstance(raw_path, str):
        raise CurrentAuditError(f"CURRENT_AUDIT_EVIDENCE_PATH_INVALID:{label}")
    path = PurePosixPath(raw_path)
    if (
        not raw_path
        or path.is_absolute()
        or raw_path != path.as_posix()
        or any(part in {"", ".", ".."} for part in path.parts)
        or "\\" in raw_path
        or unicodedata.normalize("NFC", raw_path) != raw_path
        or any(
            unicodedata.category(character).startswith("C") for character in raw_path
        )
    ):
        raise CurrentAuditError(f"CURRENT_AUDIT_EVIDENCE_PATH_ESCAPE:{label}")
    return raw_path


def _require_protocol_path(raw_path: Any, label: str) -> str:
    path = _require_canonical_repo_path(raw_path, label)
    if len(path.encode("utf-8")) > MAX_PROTOCOL_PATH_BYTES:
        raise CurrentAuditError(f"CURRENT_AUDIT_PROTOCOL_PATH_BOUND:{label}")
    return path


def _require_verifier_output_bound(payload: bytes, label: str) -> bytes:
    if len(payload) > MAX_VERIFIER_OUTPUT_BYTES:
        raise CurrentAuditError(f"CURRENT_AUDIT_VERIFIER_OUTPUT_BOUND:{label}")
    return payload


def _bounded_revocation_cause_total(total: int, file_bytes: int) -> int:
    """Apply the per-file and aggregate revocation-evidence byte caps."""

    if type(total) is not int or total < 0 or type(file_bytes) is not int:
        raise CurrentAuditError("CURRENT_AUDIT_REVOCATION_CAUSE_SIZE_INVALID")
    if file_bytes < 0 or file_bytes > MAX_REVOCATION_CAUSE_FILE_BYTES:
        raise CurrentAuditError("CURRENT_AUDIT_REVOCATION_CAUSE_FILE_BOUND")
    updated = total + file_bytes
    if updated > MAX_REVOCATION_CAUSE_TOTAL_BYTES:
        raise CurrentAuditError("CURRENT_AUDIT_REVOCATION_CAUSE_TOTAL_BOUND")
    return updated


def _read_repo_relative_bounded(
    repo: Path, raw_path: str, limit: int, label: str
) -> bytes:
    """Open every repository-relative component through stable directory fds."""

    raw_path = _require_canonical_repo_path(raw_path, label)
    path = PurePosixPath(raw_path)
    nofollow = getattr(os, "O_NOFOLLOW", None)
    directory_flag = getattr(os, "O_DIRECTORY", None)
    if nofollow is None or directory_flag is None or not DIRFD_OPEN_AVAILABLE:
        raise CurrentAuditError(f"CURRENT_AUDIT_DIRFD_UNAVAILABLE:{label}")
    directory_descriptor: int | None = None
    file_descriptor: int | None = None
    try:
        directory_descriptor = os.open(repo, os.O_RDONLY | directory_flag | nofollow)
        if not stat.S_ISDIR(os.fstat(directory_descriptor).st_mode):
            raise CurrentAuditError(f"CURRENT_AUDIT_REPOSITORY_NOT_DIRECTORY:{label}")
        for component in path.parts[:-1]:
            next_descriptor = os.open(
                component,
                os.O_RDONLY | directory_flag | nofollow,
                dir_fd=directory_descriptor,
            )
            os.close(directory_descriptor)
            directory_descriptor = next_descriptor
            if not stat.S_ISDIR(os.fstat(directory_descriptor).st_mode):
                raise CurrentAuditError(
                    f"CURRENT_AUDIT_EVIDENCE_PARENT_NOT_DIRECTORY:{label}"
                )
        file_descriptor = os.open(
            path.parts[-1],
            os.O_RDONLY | nofollow | getattr(os, "O_BINARY", 0),
            dir_fd=directory_descriptor,
        )
        return _read_descriptor_bounded(file_descriptor, limit, label)
    except CurrentAuditError:
        raise
    except (NotImplementedError, TypeError) as error:
        raise CurrentAuditError(f"CURRENT_AUDIT_DIRFD_UNAVAILABLE:{label}") from error
    except OSError as error:
        if error.errno in {errno.ELOOP, errno.EMLINK}:
            raise CurrentAuditError(
                f"CURRENT_AUDIT_SYMLINK_REJECTED:{label}"
            ) from error
        raise CurrentAuditError(f"CURRENT_AUDIT_READ_FAILED:{label}") from error
    finally:
        for descriptor in (file_descriptor, directory_descriptor):
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass


def _validate_json_structure(value: Any, label: str) -> None:
    """Apply deterministic bounds to a parsed JSON value.

    The root value has depth one.  Every array element, object value, and object
    key has its parent's depth plus one.  Every value and object key is a node;
    object keys also contribute UTF-8 string bytes.  Container entries are the
    cumulative number of array elements plus object members.
    """

    nodes = 0
    string_bytes = 0
    container_entries = 0
    stack: list[tuple[Any, int]] = [(value, 1)]

    def encoded_length(text: str) -> int:
        try:
            return len(text.encode("utf-8"))
        except UnicodeEncodeError as error:
            raise CurrentAuditError(
                f"CURRENT_AUDIT_JSON_STRING_ENCODING_INVALID:{label}"
            ) from error

    while stack:
        item, depth = stack.pop()
        if depth > MAX_JSON_DEPTH:
            raise CurrentAuditError(f"CURRENT_AUDIT_JSON_DEPTH_BOUND:{label}")
        nodes += 1
        if nodes > MAX_JSON_NODES:
            raise CurrentAuditError(f"CURRENT_AUDIT_JSON_NODE_BOUND:{label}")
        if isinstance(item, str):
            string_bytes += encoded_length(item)
        elif isinstance(item, list):
            container_entries += len(item)
            stack.extend((child, depth + 1) for child in reversed(item))
        elif isinstance(item, dict):
            container_entries += len(item)
            for key, child in reversed(tuple(item.items())):
                key_depth = depth + 1
                if key_depth > MAX_JSON_DEPTH:
                    raise CurrentAuditError(f"CURRENT_AUDIT_JSON_DEPTH_BOUND:{label}")
                nodes += 1
                if nodes > MAX_JSON_NODES:
                    raise CurrentAuditError(f"CURRENT_AUDIT_JSON_NODE_BOUND:{label}")
                string_bytes += encoded_length(key)
                stack.append((child, depth + 1))
        elif item is None or isinstance(item, (bool, int)):
            pass
        else:  # pragma: no cover - json.loads cannot construct other values
            raise CurrentAuditError(f"CURRENT_AUDIT_JSON_TYPE_INVALID:{label}")
        if string_bytes > MAX_JSON_STRING_BYTES:
            raise CurrentAuditError(f"CURRENT_AUDIT_JSON_STRING_BYTES_BOUND:{label}")
        if container_entries > MAX_JSON_CONTAINER_ENTRIES:
            raise CurrentAuditError(
                f"CURRENT_AUDIT_JSON_CONTAINER_ENTRIES_BOUND:{label}"
            )


def _load_json_bytes(payload: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            payload,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_json_constant,
            parse_float=_reject_json_float,
            parse_int=_parse_json_int,
        )
    except CurrentAuditError:
        raise
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        RecursionError,
        ValueError,
    ) as error:
        raise CurrentAuditError(f"CURRENT_AUDIT_JSON_INVALID:{label}") from error
    if not isinstance(value, dict):
        raise CurrentAuditError(f"CURRENT_AUDIT_JSON_NOT_OBJECT:{label}")
    _validate_json_structure(value, label)
    return value


def _load_json(
    path: Path, limit: int = MAX_JSON_BYTES, label: str = "manifest"
) -> dict[str, Any]:
    return _load_json_bytes(_read_bounded(path, limit, label), label)


def _load_repo_json(
    repo: Path, path: Path, limit: int = MAX_JSON_BYTES, label: str = "manifest"
) -> dict[str, Any]:
    """Parse bytes obtained by one stable repository-relative dirfd walk."""

    try:
        relative = path.relative_to(repo)
    except ValueError as error:
        raise CurrentAuditError(
            f"CURRENT_AUDIT_PATH_OUTSIDE_REPOSITORY:{label}"
        ) from error
    return _load_json_bytes(
        _read_repo_relative_bounded(repo, relative.as_posix(), limit, label), label
    )


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _require_hex(value: Any, pattern: re.Pattern[str], label: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise CurrentAuditError(f"CURRENT_AUDIT_INVALID_HEX:{label}")
    return value


def _stop_bounded_process(
    process: subprocess.Popen[bytes], *, inherited_pipes_pending: bool = False
) -> None:
    """Stop a bounded child without blindly signalling a reused process group.

    A reader that remains blocked after the group leader exits proves that a
    descendant still holds an inherited pipe.  That is the only exited-leader
    case in which this helper escalates the original process group.
    """

    if os.name == "posix":
        if process.poll() is None or inherited_pipes_pending:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            except OSError:
                if process.poll() is None:
                    try:
                        process.terminate()
                    except OSError:
                        pass
    else:
        try:
            process.terminate()
        except OSError:
            pass
    try:
        process.wait(timeout=0.5)
    except subprocess.TimeoutExpired:
        pass
    if os.name == "posix" and (process.poll() is None or inherited_pipes_pending):
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except OSError:
            try:
                process.kill()
            except OSError:
                pass
    elif os.name != "posix" and process.poll() is None:
        try:
            process.kill()
        except OSError:
            pass
    try:
        process.wait(timeout=0.5)
    except (OSError, subprocess.TimeoutExpired):
        pass


def _process_group_exists(process_group: int) -> bool:
    """Return whether the POSIX group created for one bounded run still exists."""

    if os.name != "posix":
        return False
    try:
        os.killpg(process_group, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError as error:
        if error.errno == errno.ESRCH:
            return False
        raise CurrentAuditError("CURRENT_AUDIT_PROCESS_GROUP_CHECK_FAILED") from error
    return True


def _run_bounded(
    command: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    timeout_seconds: float,
    stdout_limit: int,
    stderr_limit: int,
    error_prefix: str,
    stdin_path: Path | None = None,
    _test_only_allow_uncontained_process: bool = False,
) -> tuple[int, bytes, bytes]:
    """Run one pinned host tool with concurrent, hard-capped stream capture.

    Arbitrary repository programs execute only inside the registered container;
    a portable host process group cannot contain a descendant that calls
    ``setsid``. The private test seam exists solely for disposable process-bound
    fixtures in this module's frozen adversarial suite.
    """

    if (
        not command
        or timeout_seconds <= 0
        or type(stdout_limit) is not int
        or type(stderr_limit) is not int
        or stdout_limit < 0
        or stderr_limit < 0
    ):
        raise CurrentAuditError(f"{error_prefix}_CONFIG_INVALID")
    trusted_host_tools = {
        GIT_EXECUTABLE,
        SSH_KEYGEN_EXECUTABLE,
        DOCKER_EXECUTABLE,
    }
    if (
        not _test_only_allow_uncontained_process
        and command[0] not in trusted_host_tools
    ):
        raise CurrentAuditError(f"{error_prefix}_UNTRUSTED_HOST_EXECUTABLE")
    stdin_handle: Any = None
    try:
        if stdin_path is not None:
            stdin_handle = open(stdin_path, "rb")  # noqa: SIM115 - closed after spawn
        process = subprocess.Popen(
            command,
            cwd=cwd,
            stdin=stdin_handle if stdin_handle is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            bufsize=0,
            start_new_session=os.name == "posix",
        )
    except OSError as error:
        raise CurrentAuditError(f"{error_prefix}_START_FAILED") from error
    finally:
        if stdin_handle is not None:
            stdin_handle.close()
    if process.stdout is None or process.stderr is None:  # pragma: no cover - API guard
        _stop_bounded_process(process)
        raise CurrentAuditError(f"{error_prefix}_PIPE_FAILED")

    overflow = threading.Event()
    pipe_failure = threading.Event()
    stdout_buffer = bytearray()
    stderr_buffer = bytearray()

    def drain(stream: Any, destination: bytearray, limit: int) -> None:
        try:
            while True:
                chunk = stream.read(64 * 1024)
                if not chunk:
                    return
                remaining = limit + 1 - len(destination)
                if remaining > 0:
                    destination.extend(chunk[:remaining])
                if len(destination) > limit:
                    overflow.set()
                    return
        except OSError:
            pipe_failure.set()
        finally:
            try:
                stream.close()
            except OSError:
                pipe_failure.set()

    readers = [
        threading.Thread(
            target=drain,
            args=(process.stdout, stdout_buffer, stdout_limit),
            daemon=True,
            name="current-audit-stdout",
        ),
        threading.Thread(
            target=drain,
            args=(process.stderr, stderr_buffer, stderr_limit),
            daemon=True,
            name="current-audit-stderr",
        ),
    ]
    try:
        for reader in readers:
            reader.start()

        deadline = time.monotonic() + timeout_seconds
        timed_out = False
        while process.poll() is None:
            if overflow.is_set() or pipe_failure.is_set():
                _stop_bounded_process(process)
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                _stop_bounded_process(process)
                break
            overflow.wait(min(remaining, 0.01))

        inherited_pipes_detected = False
        for reader in readers:
            reader.join(timeout=1)
        if any(reader.is_alive() for reader in readers):
            inherited_pipes_detected = True
            _stop_bounded_process(process, inherited_pipes_pending=True)
            for stream in (process.stdout, process.stderr):
                try:
                    stream.close()
                except OSError:
                    pass
            for reader in readers:
                reader.join(timeout=1)
            if any(reader.is_alive() for reader in readers):
                raise CurrentAuditError(f"{error_prefix}_PIPE_TIMEOUT")
        group_present = os.name == "posix" and _process_group_exists(process.pid)
        if group_present:
            group_deadline = time.monotonic() + 0.25
            while group_present and time.monotonic() < group_deadline:
                time.sleep(0.01)
                group_present = _process_group_exists(process.pid)
        orphaned_group = group_present
        if orphaned_group:
            _stop_bounded_process(process, inherited_pipes_pending=True)
        if timed_out:
            raise CurrentAuditError(f"{error_prefix}_TIMEOUT")
        if overflow.is_set():
            raise CurrentAuditError(f"{error_prefix}_OUTPUT_BOUND")
        if pipe_failure.is_set():
            raise CurrentAuditError(f"{error_prefix}_PIPE_FAILED")
        if inherited_pipes_detected or orphaned_group:
            raise CurrentAuditError(f"{error_prefix}_ORPHANED_PROCESS_GROUP")
        return process.returncode, bytes(stdout_buffer), bytes(stderr_buffer)
    except BaseException:
        _stop_bounded_process(process, inherited_pipes_pending=True)
        for stream in (process.stdout, process.stderr):
            try:
                stream.close()
            except OSError:
                pass
        for reader in readers:
            if reader.is_alive():
                reader.join(timeout=1)
        raise


def _sanitized_git_environment() -> dict[str, str]:
    """Return a minimal environment that cannot redirect Git repository state."""

    allowed = {
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "TMPDIR",
        "WINDIR",
    }
    environment = {key: value for key, value in os.environ.items() if key in allowed}
    environment.update(
        {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_LITERAL_PATHSPECS": "1",
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
            "LANG": "C",
            "LC_ALL": "C",
        }
    )
    return environment


def _trusted_executable_metadata_is_valid(
    candidate: Path,
    metadata: os.stat_result,
    *,
    allow_current_user_owner: bool,
) -> bool:
    """Validate an executable against the caller's explicit local trust root."""

    owner_allowed = metadata.st_uid == 0 or (
        allow_current_user_owner and metadata.st_uid == os.geteuid()
    )
    return not (
        not candidate.is_absolute()
        or candidate.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or (os.name == "posix" and not owner_allowed)
        or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    )


def _verify_trusted_executable(
    path: str, label: str, *, allow_current_user_owner: bool = False
) -> None:
    candidate = Path(path)
    try:
        metadata = candidate.stat()
    except OSError as error:
        raise CurrentAuditError(
            f"CURRENT_AUDIT_TRUSTED_TOOL_MISSING:{label}"
        ) from error
    if not _trusted_executable_metadata_is_valid(
        candidate,
        metadata,
        allow_current_user_owner=allow_current_user_owner,
    ):
        raise CurrentAuditError(f"CURRENT_AUDIT_TRUSTED_TOOL_INVALID:{label}")


def _verified_python_executable() -> tuple[str, tuple[int, ...]]:
    executable = str(Path(PYTHON_EXECUTABLE).resolve())
    _verify_trusted_executable(executable, "python", allow_current_user_owner=True)
    if (
        sys.implementation.name != "cpython"
        or tuple(sys.version_info[:3]) != EXPECTED_PYTHON_VERSION
        or executable != str(Path(sys.executable).resolve())
    ):
        raise CurrentAuditError("CURRENT_AUDIT_PYTHON_IDENTITY_INVALID")
    metadata = os.stat(executable)
    snapshot = (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )
    return executable, snapshot


def _git_command(*arguments: str) -> list[str]:
    """Build one Git command with executable local-config surfaces disabled."""

    return [
        GIT_EXECUTABLE,
        "--no-replace-objects",
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
        *arguments,
    ]


def _git(repo: Path, *arguments: str) -> bytes:
    _verify_trusted_executable(GIT_EXECUTABLE, "git")
    returncode, stdout, _stderr = _run_bounded(
        _git_command(*arguments),
        cwd=repo,
        env=_sanitized_git_environment(),
        timeout_seconds=30,
        stdout_limit=MAX_GIT_BYTES,
        stderr_limit=MAX_GIT_BYTES,
        error_prefix="CURRENT_AUDIT_GIT",
    )
    if returncode != 0:
        raise CurrentAuditError(f"CURRENT_AUDIT_GIT_FAILED:{' '.join(arguments)}")
    return stdout


def _git_file(repo: Path, commit: str, path: str) -> bytes:
    entry = _git_tree_entry(repo, commit, path)
    if entry is None or entry["type"] != "blob":
        raise CurrentAuditError(f"CURRENT_AUDIT_GIT_FILE_MISSING:{path}")
    return _git(repo, "cat-file", "blob", entry["oid"])


def _git_tree_entry(repo: Path, commit: str, path: str) -> dict[str, str] | None:
    """Return the exact literal tree entry, including mode and object identity."""

    _require_hex(commit, HEX40, "tree_entry.commit")
    path = _require_canonical_repo_path(path, "tree_entry.path")
    raw = _git(repo, "ls-tree", "-z", commit, "--", path)
    if not raw:
        return None
    if not raw.endswith(b"\0") or raw.count(b"\0") != 1:
        raise CurrentAuditError("CURRENT_AUDIT_GIT_TREE_PATH_AMBIGUOUS")
    row = raw[:-1]
    try:
        metadata_raw, observed_path_raw = row.split(b"\t", 1)
        mode_raw, type_raw, oid_raw = metadata_raw.split(b" ", 2)
        observed_path = observed_path_raw.decode("utf-8")
        mode = mode_raw.decode("ascii")
        object_type = type_raw.decode("ascii")
        oid = oid_raw.decode("ascii")
    except (UnicodeDecodeError, ValueError) as error:
        raise CurrentAuditError("CURRENT_AUDIT_GIT_TREE_ENTRY_INVALID") from error
    if (
        observed_path != path
        or re.fullmatch(r"[0-7]{6}", mode) is None
        or object_type not in {"blob", "tree", "commit"}
        or HEX40.fullmatch(oid) is None
    ):
        raise CurrentAuditError("CURRENT_AUDIT_GIT_TREE_ENTRY_INVALID")
    return {"mode": mode, "type": object_type, "oid": oid}


def _payload_file_record(path: str, payload: bytes) -> dict[str, Any]:
    record: dict[str, Any] = {
        "path": path,
        "sha256": _sha256(payload),
        "bytes": len(payload),
    }
    if path.endswith((".json", ".py", ".sh", ".yml", ".md")) or path in {"justfile"}:
        record["lines"] = len(payload.splitlines())
    return record


def _commit_file_record(repo: Path, commit: str, path: str) -> dict[str, Any]:
    return _payload_file_record(path, _git_file(repo, commit, path))


def _commit_regular_file_record(repo: Path, commit: str, path: str) -> dict[str, Any]:
    entry = _git_tree_entry(repo, commit, path)
    if (
        entry is None
        or entry["type"] != "blob"
        or entry["mode"] not in {"100644", "100755"}
    ):
        raise CurrentAuditError(f"CURRENT_AUDIT_PROTOCOL_FILE_MODE_INVALID:{path}")
    return {
        **_commit_file_record(repo, commit, path),
        "git_mode": entry["mode"],
        "git_object_type": entry["type"],
        "git_object_id": entry["oid"],
    }


def _commit_protocol_file_record(repo: Path, commit: str, path: str) -> dict[str, Any]:
    return _commit_regular_file_record(repo, commit, path)


def _read_commit_json(
    repo: Path, commit: str, path: str, label: str
) -> tuple[dict[str, Any], bytes]:
    _commit_regular_file_record(repo, commit, path)
    payload = _git_file(repo, commit, path)
    if len(payload) > MAX_JSON_BYTES:
        raise CurrentAuditError(f"CURRENT_AUDIT_RESOURCE_BOUND:{label}")
    return _load_json_bytes(payload, label), payload


def _read_commit_file_bound(
    repo: Path,
    commit: str,
    record: dict[str, Any],
    label: str,
    limit: int,
) -> bytes:
    path = record.get("path")
    if not isinstance(path, str):
        raise CurrentAuditError(f"CURRENT_AUDIT_EVIDENCE_PATH_INVALID:{label}")
    payload = _git_file(repo, commit, path)
    if len(payload) > limit:
        raise CurrentAuditError(f"CURRENT_AUDIT_RESOURCE_BOUND:{label}")
    _require_int(record.get("bytes"), len(payload), f"{label}.bytes")
    if _sha256(payload) != _require_hex(record.get("sha256"), HEX64, label):
        raise CurrentAuditError(f"CURRENT_AUDIT_EVIDENCE_DIGEST_MISMATCH:{label}")
    if "lines" in record:
        _require_int(record.get("lines"), len(payload.splitlines()), f"{label}.lines")
    return payload


def _require_int(value: Any, expected: int, label: str) -> None:
    if type(value) is not int or value != expected:
        raise CurrentAuditError(f"CURRENT_AUDIT_INTEGER_INVALID:{label}")


def _strict_equal(actual: Any, expected: Any) -> bool:
    if type(actual) is not type(expected):
        return False
    if isinstance(expected, dict):
        return set(actual) == set(expected) and all(
            _strict_equal(actual[key], value) for key, value in expected.items()
        )
    if isinstance(expected, list):
        return len(actual) == len(expected) and all(
            _strict_equal(item, expected_item)
            for item, expected_item in zip(actual, expected, strict=True)
        )
    return bool(actual == expected)


def ch_t000_normative_controls() -> list[dict[str, Any]]:
    """Return the closed CH-T000 control set used by review and activation."""

    rows = (
        (
            "N01",
            "Bind the approved source, signed input-freeze implementation, and signed qualification-framework commits by exact Git identity and ancestry.",
            "test_qualification_implementation_commit_mutation_is_rejected",
        ),
        (
            "N02",
            "Bind every declared review and evidence payload by repository path, SHA-256 digest, byte count, and line count where textual.",
            "test_qualification_evidence_digest_mutation_is_rejected",
        ),
        (
            "N03",
            "Parse JSON, gzip, ZIP, filesystem paths, Git output, and child-process output with explicit fail-closed syntax, identity, timeout, and resource bounds.",
            "test_qualification_exact_resource_boundaries",
        ),
        (
            "N04",
            "Accept local, independent Linux, CI, and formal evidence only when exact commit provenance, direct exit status, complete nested success, and retained-log identity agree.",
            "test_qualification_nested_failed_step_is_rejected",
        ),
        (
            "N05",
            "Keep every automated reviewer outside named-human authority and keep the public, release, deployment, publication, DOI, and Zenodo dispositions at no authority and NO_GO.",
            "test_qualification_named_human_impersonation_is_rejected",
        ),
        (
            "N06",
            "Permit CH-T000 closure only through a later signed data-only activation commit; preserve exact closure evidence and reopen a dependency-closed suffix on signed revocation.",
            "test_terminal_closure_commit_must_contain_bound_artifacts",
        ),
    )
    return [
        {
            "id": f"CH-T000-{short_id}",
            "requirement": requirement,
            "accepted_case": {
                "id": f"CH-T000-{short_id}-A01",
                "expected": "ACCEPT_EXACT_BOUND_STATE_ONLY",
                "test_id": "test_qualification_exact_record_verifies",
            },
            "rejected_case": {
                "id": f"CH-T000-{short_id}-R01",
                "expected": "REJECT_MUTATED_OR_UNBOUND_STATE",
                "test_id": test_id,
            },
        }
        for short_id, requirement, test_id in rows
    ]


def ch_t000_counterfactuals() -> list[dict[str, str]]:
    """Return the exact mandatory quirky-case/counterfactual dispositions."""

    rows = (
        (
            "valid syntax with contradictory semantics",
            "N03",
            "test_qualification_behavior_mutation_is_rejected",
        ),
        (
            "authenticated but unauthorized producer",
            "N05",
            "test_qualification_human_reviewer_impersonation_is_rejected",
        ),
        (
            "stale yet correctly signed data",
            "N01",
            "test_stale_correctly_signed_implementation_commit_is_rejected",
        ),
        (
            "correct version string with wrong contract or algorithm digest",
            "N02",
            "test_qualification_evidence_digest_mutation_is_rejected",
        ),
        (
            "clean result under a nonrepresentative environment",
            "N04",
            "test_qualification_clean_linux_provenance_mutation_is_rejected",
        ),
        (
            "timeout or capacity exhaustion followed by convenience fallback",
            "N03",
            "test_qualification_git_timeout_is_rejected",
        ),
        (
            "feature unification activating a privileged or experimental path",
            "N05",
            "test_qualification_undeclared_artifact_class_is_rejected",
        ),
        (
            "partial migration accepted through default values",
            "N06",
            "test_qualification_legacy_closure_transfer_is_rejected",
        ),
        (
            "crash between decision and durable activation evidence",
            "N06",
            "test_framework_pending_rejects_premature_packet_or_activation",
        ),
        (
            "simple but odd input unlikely to resemble expected examples",
            "N03",
            "test_duplicate_json_key_is_rejected",
        ),
    )
    return [
        {
            "id": f"CH-T000-CF{index:02d}",
            "scenario": scenario,
            "expected": "FAIL_CLOSED_WITH_NO_PUBLIC_CLAIM_CHANGE",
            "control_id": f"CH-T000-{control}",
            "test_id": test_id,
            "disposition": "RESOLVED",
        }
        for index, (scenario, control, test_id) in enumerate(rows, start=1)
    ]


def ch_t000_control_digest() -> str:
    payload = json.dumps(
        {
            "normative_controls": ch_t000_normative_controls(),
            "mandatory_counterfactuals": ch_t000_counterfactuals(),
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return _sha256(payload)


def ch_t000_lens_reviews() -> dict[str, dict[str, Any]]:
    rows = (
        (
            "Which exact cut and claim boundary is qualified?",
            (1, 5, 6),
            ("E01", "E02", "Q01", "Q07", "Q08"),
            "Exact source, implementation, framework, and no-authority boundary are bound.",
            "The task is applicable because CH-T000 establishes the audit root.",
            "No runtime or release-readiness claim is evaluated.",
        ),
        (
            "Do the verifier and gates accept only the intended valid state?",
            (1, 2, 4, 6),
            ("E03", "E04", "E05", "Q02", "Q03", "Q04"),
            "Independent and local accepted-state paths agree on exact identities.",
            "Functional acceptance is limited to the audit verifier and its gates.",
            "Product runtime correctness remains outside this task.",
        ),
        (
            "Are counts, digests, and bounds mathematically consistent?",
            (2, 3),
            ("E02", "Q06", "Q07"),
            "Digest, byte, line, and exact/+1 resource relations are closed.",
            "Numeric consistency is applicable to every retained record and parser bound.",
            "The profile makes no cross-machine latency claim.",
        ),
        (
            "Can schema or state typing admit an ambiguous transition?",
            (2, 3, 6),
            ("E02", "Q01", "Q07", "Q08"),
            "Closed fields and exact OPEN-to-D transition typing reject ambiguity.",
            "State integrity is central to preventing premature closure.",
            "Only CH-T000 transition semantics are qualified here.",
        ),
        (
            "Are run, review, capture, and commit times ordered and replay-safe?",
            (1, 2, 4),
            ("E03", "E04", "E05", "E06", "Q02", "Q03", "Q04", "Q05"),
            "Subject, execution, capture, review, and retention ordering is explicit.",
            "All retained execution evidence is time-bearing and therefore applicable.",
            "Platform clocks are trusted inputs, not independently attested time.",
        ),
        (
            "Are source, signer, runner, and reviewer identities exact?",
            (1, 2, 5),
            ("E01", "E04", "Q01", "Q03", "Q07", "Q08"),
            "Git, runner, and automated reviewer identities remain distinct and bound.",
            "Identity provenance is required for every qualified commit and review.",
            "Automated identities do not imply named-human review.",
        ),
        (
            "Are cryptographic signatures and digests checked against frozen trust?",
            (1, 2),
            ("E01", "E02", "Q01", "Q07"),
            "Signed commits and SHA-256 file identities bind the qualified graph.",
            "Authentication is applicable to commit and evidence provenance.",
            "Key custody and organizational revocation are not certified.",
        ),
        (
            "Can technical evidence be mistaken for deployment or release authority?",
            (5, 6),
            ("Q01", "Q07", "Q08"),
            "Every authority-bearing field remains false and release remains NO_GO.",
            "Authority separation is applicable because the task changes audit state.",
            "No deployment, tag, publication, DOI, or archive authority is granted.",
        ),
        (
            "Do hostile syntax, aliases, or contradictory records fail closed?",
            (2, 3),
            ("Q06", "Q07", "Q08"),
            "Duplicate keys, path aliases, malformed compression, and contradictory state reject.",
            "The verifier consumes adversary-controlled repository bytes.",
            "Unknown future formats require a new protocol version.",
        ),
        (
            "Are per-file, aggregate, process, Git, gzip, and ZIP resources bounded?",
            (3,),
            ("Q02", "Q03", "Q06", "Q08"),
            "Every parser and subprocess boundary has an explicit exact/+1 disposition.",
            "Resource exhaustion is applicable to offline verification of retained evidence.",
            "Configured maxima are protocol limits, not capacity guarantees.",
        ),
        (
            "Can concurrency, process descendants, or filesystem swaps evade binding?",
            (3, 6),
            ("Q06", "Q07", "Q08"),
            "Dirfd snapshots and bounded process-group cleanup close reviewed races.",
            "Concurrent filesystem and child-process behavior affects verifier integrity.",
            "Kernel and filesystem primitives remain trusted dependencies.",
        ),
        (
            "Are artifacts and profiles reproducible from exact immutable bytes?",
            (1, 2, 4),
            ("E03", "E04", "E05", "E06", "Q02", "Q03", "Q04", "Q05", "Q06"),
            "Local, clean Linux, hosted, formal, and profile records bind reproducible subjects.",
            "Reproducibility is applicable to each independent evidence class.",
            "Hosted services and container runtime are not independently attested.",
        ),
        (
            "Does the framework alter API, FFI, or semantic-version promises?",
            (5, 6),
            ("E01", "Q01", "Q07"),
            "No API, FFI, or version compatibility claim changes at CH-T000.",
            "Compatibility is reviewed because the framework is release-bound infrastructure.",
            "Later product compatibility tasks remain OPEN.",
        ),
        (
            "Can schema, wire, or language representations diverge silently?",
            (2, 3),
            ("E02", "Q06", "Q07"),
            "Canonical JSON and exact artifact records reject silent representation drift.",
            "Multiple serialized evidence classes make parity applicable.",
            "Product wire and language parity are not established by CH-T000.",
        ),
        (
            "Can configuration or deployment context broaden the qualified scope?",
            (4, 5),
            ("E04", "E05", "Q03", "Q04", "Q07"),
            "Runner restrictions and claim boundaries prevent deployment-context promotion.",
            "Configuration is applicable to clean and hosted reproduction evidence.",
            "No field deployment profile is qualified.",
        ),
        (
            "Are failures, statuses, and retained logs sufficient for forensics?",
            (2, 4),
            ("E03", "E04", "E05", "E06", "Q02", "Q03", "Q04", "Q05"),
            "Direct statuses, complete logs, and exact markers preserve reviewed outcomes.",
            "Forensics is applicable because evidence must survive beyond execution.",
            "Logs prove named commands only and may omit external platform internals.",
        ),
        (
            "Does evidence quality support exactly the stated technical decision?",
            (1, 2, 4, 6),
            tuple(C_EVIDENCE_IDS),
            "Two automated reviews and all execution classes support only technical qualification.",
            "Evidence quality is the direct subject of CH-T000.",
            "Independent named-human assurance is absent and not inferred.",
        ),
        (
            "Can downstream repositories or consumers inherit this closure?",
            (1, 5, 6),
            ("E01", "E02", "Q01", "Q07"),
            "Closure transfer is forbidden; downstream work remains independently open.",
            "The handoff explicitly spans a multi-repository program.",
            "Non-Haldir Git objects are not verified here.",
        ),
        (
            "Are reviewer roles, author identity, and approval boundaries truthful?",
            (2, 5, 6),
            ("E04", "Q07", "Q08"),
            "Author and automated reviewer roles are separate and no human status is fabricated.",
            "Governance truthfulness is applicable to all qualification records.",
            "Organizational approval remains outside repository evidence.",
        ),
        (
            "Which plausible odd or counterfactual states could still create a false green?",
            (1, 2, 3, 4, 5, 6),
            ("Q06", "Q07", "Q08"),
            "All ten mandatory counterfactuals have explicit fail-closed tests and dispositions.",
            "Quirky-case review is applicable to a security-sensitive offline verifier.",
            "Unenumerated future protocol changes require renewed adversarial review.",
        ),
    )
    result: dict[str, dict[str, Any]] = {}
    for index, (name, row) in enumerate(zip(LENS_NAMES, rows, strict=True), start=1):
        _review_prompt, controls, evidence, finding, rationale, limitation = row
        evidence_ids = [
            item if item.startswith("CH-T000-") else f"CH-T000-{item}"
            for item in evidence
        ]
        result[f"L{index:02d}"] = {
            "name": name,
            "question": HANDOFF_LENS_QUESTIONS[index - 1],
            "status": "C_REVIEW_COMPLETE_D_ACTIVATION_PENDING",
            "claim_impact": "NO_PUBLIC_CLAIM_CHANGE",
            "control_ids": [f"CH-T000-N{item:02d}" for item in controls],
            "evidence_ids": evidence_ids,
            "finding": finding,
            "applicability_rationale": rationale,
            "residual_limitation": limitation,
        }
    return result


def ch_t000_lens_projection() -> dict[str, dict[str, Any]]:
    return {
        lens_id: {
            "name": value["name"],
            "question": value["question"],
            "status": "RESOLVED_AT_D",
            "claim_impact": value["claim_impact"],
            "control_ids": value["control_ids"],
            "c_evidence_ids": value["evidence_ids"],
            "activation_evidence_ids": list(ACTIVATION_EVIDENCE_IDS),
            "c_finding": value["finding"],
            "applicability_rationale": value["applicability_rationale"],
            "residual_limitation": value["residual_limitation"],
            "activation_finding": "SIGNED_D_EVIDENCE_ACTIVATES_ONLY_THE_REVIEWED_CH_T000_TECHNICAL_TRANSITION",
            "review_record": REVIEW_PATH,
        }
        for lens_id, value in ch_t000_lens_reviews().items()
    }


def ch_t000_c_finding_dispositions() -> list[dict[str, Any]]:
    evidence_map = {
        1: ["CH-T000-Q01"],
        2: ["CH-T000-Q07", "CH-T000-Q08"],
        3: ["CH-T000-E03"],
        4: ["CH-T000-E05", "CH-T000-E06"],
        5: ["CH-T000-E04"],
        6: ["CH-T000-Q07", "CH-T000-Q08"],
        7: ["CH-T000-Q07", "CH-T000-Q08"],
        8: ["CH-T000-Q01", "CH-T000-Q07"],
        9: ["CH-T000-Q06"],
        10: ["CH-T000-Q06"],
        11: ["CH-T000-Q01", "CH-T000-Q02", "CH-T000-Q04", "CH-T000-Q05"],
        12: ["CH-T000-Q07", "CH-T000-Q08"],
        13: ["CH-T000-Q01", "CH-T000-Q07", "CH-T000-Q08"],
        14: ["CH-T000-Q02", "CH-T000-Q03", "CH-T000-Q04", "CH-T000-Q05"],
        15: ["CH-T000-Q01", "CH-T000-Q07"],
        16: ["CH-T000-Q01", "CH-T000-Q07"],
        17: ["CH-T000-Q01", "CH-T000-Q07", "CH-T000-Q08"],
        18: ["CH-T000-Q01", "CH-T000-Q07"],
        19: ["CH-T000-Q01", "CH-T000-Q07", "CH-T000-Q08"],
        20: ["CH-T000-Q01", "CH-T000-Q07", "CH-T000-Q08"],
        21: ["CH-T000-Q01", "CH-T000-Q02", "CH-T000-Q03"],
        22: ["CH-T000-Q06", "CH-T000-Q08"],
        23: ["CH-T000-Q02", "CH-T000-Q03", "CH-T000-Q04", "CH-T000-Q05"],
    }
    test_map = {
        1: ["test_qualification_control_mutation_is_rejected"],
        2: ["test_qualification_each_missing_lens_is_rejected"],
        3: ["test_qualification_p0_exit_mutation_is_rejected"],
        4: ["test_qualification_attempt_mutation_is_rejected"],
        5: ["test_qualification_clean_linux_provenance_mutation_is_rejected"],
        6: ["test_qualification_clean_linux_reviewer_mutation_is_rejected"],
        7: ["test_qualification_implementation_diff_mutation_is_rejected"],
        8: ["test_qualification_evidence_digest_mutation_is_rejected"],
        9: ["test_qualification_exact_resource_boundaries"],
        10: ["test_qualification_gzip_expansion_over_limit_is_rejected"],
        11: [
            "test_public_c_missing_qualification_is_rejected",
            "test_public_c_malformed_qualification_is_rejected",
            "test_public_d_missing_activation_is_rejected",
            "test_public_d_malformed_activation_is_rejected",
        ],
        12: [
            "test_bounded_runner_kills_inheriting_grandchild",
            "test_bounded_runner_kills_descendant_after_leader_exit",
            "test_qualification_git_output_over_limit_is_rejected",
            "test_qualification_git_stderr_over_limit_is_rejected",
            "test_qualification_git_timeout_is_rejected",
            "test_evidence_read_uses_stable_parent_dirfd_across_swap",
            "test_duplicate_json_key_is_rejected",
            "test_verifier_snapshot_aba_is_rejected",
        ],
        13: ["test_qualification_behavior_mutation_is_rejected"],
        14: ["test_qualification_missing_job_is_rejected"],
        15: ["test_qualification_control_mutation_is_rejected"],
        16: ["test_qualification_decision_mutation_is_rejected"],
        17: ["test_framework_pending_to_qualified_open_to_terminal_stage_sequence"],
        18: ["test_terminal_closure_commit_must_contain_bound_artifacts"],
        19: ["test_revocation_cascade_accepts_forward_reopen_of_all_descendants"],
        20: ["test_qualified_or_terminal_stage_rejects_qualification_deletion"],
        21: ["test_evidence_read_uses_stable_parent_dirfd_across_swap"],
        22: ["test_qualification_exact_resource_boundaries"],
        23: ["test_terminal_exact_ch_t000_state_verifies"],
    }
    control_map = {
        1: ["CH-T000-N01", "CH-T000-N05", "CH-T000-N06"],
        2: ["CH-T000-N02", "CH-T000-N04"],
        3: ["CH-T000-N04"],
        4: ["CH-T000-N02", "CH-T000-N04"],
        5: ["CH-T000-N02", "CH-T000-N04"],
        6: ["CH-T000-N02", "CH-T000-N05"],
        7: ["CH-T000-N01", "CH-T000-N02"],
        8: ["CH-T000-N02"],
        9: ["CH-T000-N02", "CH-T000-N03"],
        10: ["CH-T000-N03"],
        11: ["CH-T000-N06"],
        12: ["CH-T000-N03"],
        13: ["CH-T000-N05", "CH-T000-N06"],
        14: ["CH-T000-N04"],
        15: ["CH-T000-N02", "CH-T000-N05"],
        16: ["CH-T000-N06"],
        17: ["CH-T000-N06"],
        18: ["CH-T000-N06"],
        19: ["CH-T000-N06"],
        20: ["CH-T000-N01", "CH-T000-N02", "CH-T000-N06"],
        21: ["CH-T000-N03"],
        22: ["CH-T000-N03"],
        23: ["CH-T000-N02", "CH-T000-N04", "CH-T000-N06"],
    }
    deferred = {17: "DEFERRED_TO_D", 20: "DEFERRED_TO_D", 23: "DEFERRED_TO_D"}
    result: list[dict[str, Any]] = []
    for index in range(1, 24):
        status = deferred.get(index, "RESOLVED_AT_C")
        if index == 19:
            status = "UNRESOLVED_PENDING_SIGNED_D_REVOCATION_PROTOCOL"
        result.append(
            {
                "id": f"CH-T000-R02-B{index:02d}",
                "status": status,
                "evidence_ids": evidence_map.get(index, []),
                "control_ids": control_map.get(index, []),
                "test_ids": test_map.get(index, []),
                "scope": "SIGNED_B_FRAMEWORK_AND_SIGNED_C_EVIDENCE_ONLY",
            }
        )
    return result


def _discover_unittest_test_cases(
    payload: bytes, path: str, *, strict_runtime: bool = False
) -> tuple[tuple[str, str], ...]:
    """Return exact unittest class/method pairs from a constrained test module."""

    try:
        tree = ast.parse(payload, filename=path)
    except (SyntaxError, ValueError) as error:
        raise CurrentAuditError("CURRENT_AUDIT_FROZEN_TEST_AST_INVALID") from error

    def exact_main_guard(node: ast.AST) -> bool:
        if not isinstance(node, ast.If):
            return False
        test = node.test
        return (
            isinstance(test, ast.Compare)
            and isinstance(test.left, ast.Name)
            and test.left.id == "__name__"
            and len(test.ops) == 1
            and isinstance(test.ops[0], ast.Eq)
            and len(test.comparators) == 1
            and isinstance(test.comparators[0], ast.Constant)
            and test.comparators[0].value == "__main__"
            and len(node.body) == 1
            and not node.orelse
            and isinstance(node.body[0], ast.Expr)
            and isinstance(node.body[0].value, ast.Call)
            and isinstance(node.body[0].value.func, ast.Attribute)
            and isinstance(node.body[0].value.func.value, ast.Name)
            and node.body[0].value.func.value.id == "unittest"
            and node.body[0].value.func.attr == "main"
            and not node.body[0].value.args
            and not node.body[0].value.keywords
        )

    def literal_value(node: ast.AST) -> bool:
        if isinstance(node, ast.Constant):
            return isinstance(node.value, (bool, bytes, float, int, str, type(None)))
        if isinstance(node, (ast.List, ast.Set, ast.Tuple)):
            return all(literal_value(item) for item in node.elts)
        if isinstance(node, ast.Dict):
            return all(
                key is not None and literal_value(key) and literal_value(value)
                for key, value in zip(node.keys, node.values, strict=True)
            )
        return (
            isinstance(node, ast.UnaryOp)
            and isinstance(node.op, (ast.UAdd, ast.USub))
            and isinstance(node.operand, ast.Constant)
            and type(node.operand.value) in {float, int}
        )

    def definition_has_runtime_expression(
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        *,
        annotations_are_strings: bool,
    ) -> bool:
        arguments = node.args
        annotated_arguments = [
            *arguments.posonlyargs,
            *arguments.args,
            *arguments.kwonlyargs,
            *([arguments.vararg] if arguments.vararg is not None else []),
            *([arguments.kwarg] if arguments.kwarg is not None else []),
        ]
        return bool(
            node.decorator_list
            or arguments.defaults
            or any(value is not None for value in arguments.kw_defaults)
            or getattr(node, "type_params", ())
            or (
                not annotations_are_strings
                and (
                    node.returns is not None
                    or any(
                        argument.annotation is not None
                        for argument in annotated_arguments
                    )
                )
            )
        )

    if strict_runtime:
        annotations_are_strings = any(
            isinstance(node, ast.ImportFrom)
            and node.module == "__future__"
            and any(alias.name == "annotations" for alias in node.names)
            for node in tree.body
        )
        for node in tree.body:
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                continue
            if (
                isinstance(node, ast.Expr)
                and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)
            ):
                continue
            if isinstance(node, ast.Assign):
                if (
                    not node.targets
                    or any(not isinstance(target, ast.Name) for target in node.targets)
                    or not literal_value(node.value)
                ):
                    raise CurrentAuditError(
                        "CURRENT_AUDIT_FROZEN_TEST_MODULE_BODY_INVALID"
                    )
                continue
            if isinstance(node, ast.AnnAssign):
                if (
                    not isinstance(node.target, ast.Name)
                    or node.value is None
                    or not literal_value(node.value)
                    or (not annotations_are_strings and node.annotation is not None)
                ):
                    raise CurrentAuditError(
                        "CURRENT_AUDIT_FROZEN_TEST_MODULE_BODY_INVALID"
                    )
                continue
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if definition_has_runtime_expression(
                    node, annotations_are_strings=annotations_are_strings
                ):
                    raise CurrentAuditError(
                        "CURRENT_AUDIT_FROZEN_TEST_MODULE_BODY_INVALID"
                    )
                continue
            if isinstance(node, ast.ClassDef):
                base_names = {
                    base.id
                    if isinstance(base, ast.Name)
                    else base.attr
                    if isinstance(base, ast.Attribute)
                    else ""
                    for base in node.bases
                }
                class_body_is_static = all(
                    (
                        isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
                        and not definition_has_runtime_expression(
                            child, annotations_are_strings=annotations_are_strings
                        )
                    )
                    or (
                        isinstance(child, ast.Expr)
                        and isinstance(child.value, ast.Constant)
                        and isinstance(child.value.value, str)
                    )
                    for child in node.body
                )
                if (
                    node.decorator_list
                    or node.keywords
                    or len(node.bases) != 1
                    or not base_names.issubset({"TestCase", "IsolatedAsyncioTestCase"})
                    or not class_body_is_static
                ):
                    raise CurrentAuditError(
                        "CURRENT_AUDIT_FROZEN_TEST_MODULE_BODY_INVALID"
                    )
                continue
            if exact_main_guard(node):
                continue
            raise CurrentAuditError("CURRENT_AUDIT_FROZEN_TEST_MODULE_BODY_INVALID")

    test_cases: list[tuple[str, str]] = []
    has_exact_main = False
    class_names: set[str] = set()
    forbidden_test_controls = {
        "SkipTest",
        "expectedFailure",
        "skip",
        "skipIf",
        "skipTest",
        "skipUnless",
    }
    forbidden_runtime_builtins = {"exit", "input", "print", "quit"}
    forbidden_runtime_overrides = {
        "__call__",
        "__delattr__",
        "__getattr__",
        "__getattribute__",
        "__init__",
        "__init_subclass__",
        "__new__",
        "__setattr__",
        "_callCleanup",
        "_callSetUp",
        "_callTearDown",
        "_callTestMethod",
        "addCleanup",
        "countTestCases",
        "debug",
        "defaultTestResult",
        "doCleanups",
        "enterContext",
        "id",
        "run",
        "shortDescription",
    }
    for node in tree.body:
        if (
            strict_runtime
            and isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name in {"__getattr__", "load_tests"}
        ):
            raise CurrentAuditError("CURRENT_AUDIT_FROZEN_TEST_LOADER_OVERRIDE")
        if exact_main_guard(node):
            has_exact_main = True
        if not isinstance(node, ast.ClassDef):
            continue
        bases = {
            base.id
            if isinstance(base, ast.Name)
            else base.attr
            if isinstance(base, ast.Attribute)
            else ""
            for base in node.bases
        }
        if not bases.intersection({"TestCase", "IsolatedAsyncioTestCase"}):
            continue
        if node.name in class_names or (
            strict_runtime
            and (
                node.decorator_list
                or node.keywords
                or len(node.bases) != 1
                or not bases.issubset({"TestCase", "IsolatedAsyncioTestCase"})
            )
        ):
            raise CurrentAuditError("CURRENT_AUDIT_FROZEN_TEST_CLASS_INVALID")
        class_names.add(node.name)
        for child in node.body:
            if (
                strict_runtime
                and isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
                and child.name in forbidden_runtime_overrides
            ):
                raise CurrentAuditError(
                    f"CURRENT_AUDIT_FROZEN_TEST_RUNTIME_OVERRIDE:{child.name}"
                )
            if not (
                isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
                and child.name.startswith("test_")
            ):
                continue
            if strict_runtime and (
                child.decorator_list
                or any(
                    (
                        isinstance(descendant, ast.Name)
                        and descendant.id in forbidden_test_controls
                    )
                    or (
                        isinstance(descendant, ast.Attribute)
                        and descendant.attr in forbidden_test_controls
                    )
                    for descendant in ast.walk(child)
                )
            ):
                raise CurrentAuditError(
                    f"CURRENT_AUDIT_FROZEN_TEST_CONTROL_INVALID:{child.name}"
                )
            meaningful = any(
                isinstance(descendant, (ast.Assert, ast.Raise))
                or (
                    isinstance(descendant, ast.Call)
                    and isinstance(descendant.func, ast.Attribute)
                    and descendant.func.attr.startswith("assert")
                )
                for descendant in ast.walk(child)
            )
            if not meaningful:
                raise CurrentAuditError(
                    f"CURRENT_AUDIT_FROZEN_TEST_NO_ASSERTION:{child.name}"
                )
            test_cases.append((node.name, child.name))
    if not has_exact_main:
        raise CurrentAuditError("CURRENT_AUDIT_FROZEN_TEST_MAIN_INVALID")
    if not test_cases or len(test_cases) != len(set(test_cases)):
        raise CurrentAuditError("CURRENT_AUDIT_FROZEN_TEST_DISCOVERY_INVALID")
    test_ids = [method_name for _class_name, method_name in test_cases]
    if len(test_ids) != len(set(test_ids)):
        raise CurrentAuditError("CURRENT_AUDIT_FROZEN_TEST_ID_DUPLICATE")
    for descendant in ast.walk(tree):
        if strict_runtime and (
            (
                isinstance(descendant, ast.Attribute)
                and isinstance(descendant.ctx, ast.Store)
                and isinstance(descendant.value, ast.Name)
                and descendant.value.id == "unittest"
            )
            or (
                isinstance(descendant, ast.Call)
                and isinstance(descendant.func, ast.Attribute)
                and descendant.func.attr == "_exit"
            )
            or (
                isinstance(descendant, ast.Call)
                and isinstance(descendant.func, ast.Name)
                and descendant.func.id in forbidden_runtime_builtins
            )
            or (
                isinstance(descendant, ast.Raise)
                and (
                    isinstance(descendant.exc, ast.Name)
                    and descendant.exc.id == "SystemExit"
                    or isinstance(descendant.exc, ast.Call)
                    and isinstance(descendant.exc.func, ast.Name)
                    and descendant.exc.func.id == "SystemExit"
                )
            )
        ):
            raise CurrentAuditError("CURRENT_AUDIT_FROZEN_TEST_RUNTIME_OVERRIDE")
    return tuple(test_cases)


def _discover_unittest_test_ids(
    payload: bytes, path: str, *, strict_runtime: bool = False
) -> tuple[str, ...]:
    return tuple(
        method_name
        for _class_name, method_name in _discover_unittest_test_cases(
            payload, path, strict_runtime=strict_runtime
        )
    )


def _discover_frozen_test_ids(
    repo: Path, framework_commit: str
) -> dict[str, tuple[str, ...]]:
    discovered: dict[str, tuple[str, ...]] = {}
    all_ids: list[str] = []
    for path in (
        "tools/release/test_verify_current_audit.py",
        "tools/release/test_current_audit_resource_profile.py",
    ):
        test_ids = _discover_unittest_test_ids(
            _git_file(repo, framework_commit, path), path
        )
        discovered[path] = test_ids
        all_ids.extend(test_ids)
    if len(all_ids) != len(set(all_ids)):
        raise CurrentAuditError("CURRENT_AUDIT_FROZEN_TEST_ID_DUPLICATE")
    return discovered


def _frozen_test_run_counts(repo: Path, framework_commit: str) -> tuple[int, ...]:
    """Return the unittest count emitted by each separately executed module."""

    return tuple(
        len(test_ids)
        for test_ids in _discover_frozen_test_ids(repo, framework_commit).values()
    )


def _verify_cited_test_ids(repo: Path, framework_commit: str) -> None:
    discovered = _discover_frozen_test_ids(repo, framework_commit)
    observed = {test_id for values in discovered.values() for test_id in values}
    cited: set[str] = set()
    for control in ch_t000_normative_controls():
        cited.add(control["accepted_case"]["test_id"])
        cited.add(control["rejected_case"]["test_id"])
    cited.update(item["test_id"] for item in ch_t000_counterfactuals())
    for finding in ch_t000_c_finding_dispositions():
        cited.update(finding["test_ids"])
    for resolution in _activation_blocker_resolutions():
        cited.update(resolution["test_ids"])
    missing = sorted(cited - observed)
    if missing:
        raise CurrentAuditError(
            "CURRENT_AUDIT_CITED_TEST_ID_MISSING:" + ",".join(missing)
        )


def _reject_symlink_components(repo: Path, path: Path, label: str) -> None:
    try:
        relative = path.relative_to(repo)
    except ValueError as error:
        raise CurrentAuditError(
            f"CURRENT_AUDIT_PATH_OUTSIDE_REPOSITORY:{label}"
        ) from error
    current = repo
    for component in relative.parts:
        current /= component
        if current.is_symlink():
            raise CurrentAuditError(f"CURRENT_AUDIT_SYMLINK_REJECTED:{label}")


def _read_evidence_file(
    repo: Path, record: dict[str, Any], label: str, limit: int
) -> bytes:
    raw_path = record.get("path")
    if not isinstance(raw_path, str):
        raise CurrentAuditError(f"CURRENT_AUDIT_EVIDENCE_PATH_INVALID:{label}")
    payload = _read_repo_relative_bounded(repo, raw_path, limit, label)
    _require_int(record.get("bytes"), len(payload), f"{label}.bytes")
    if _sha256(payload) != _require_hex(record.get("sha256"), HEX64, label):
        raise CurrentAuditError(f"CURRENT_AUDIT_EVIDENCE_DIGEST_MISMATCH:{label}")
    if "lines" in record:
        _require_int(record.get("lines"), len(payload.splitlines()), f"{label}.lines")
    return payload


def _read_gzip_evidence(
    repo: Path, record: dict[str, Any], label: str, decompressed_limit: int
) -> bytes:
    compressed_record = {
        "path": record.get("path"),
        "sha256": record.get("compressed_sha256"),
        "bytes": record.get("compressed_bytes"),
    }
    compressed = _read_evidence_file(
        repo, compressed_record, f"{label}.gz", MAX_COMPRESSED_LOG_BYTES
    )
    return _decode_gzip_evidence(compressed, record, label, decompressed_limit)


def _decode_gzip_evidence(
    compressed: bytes,
    record: dict[str, Any],
    label: str,
    decompressed_limit: int,
) -> bytes:
    if not compressed.startswith(b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\x03"):
        raise CurrentAuditError(f"CURRENT_AUDIT_GZIP_HEADER_INVALID:{label}")
    try:
        decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
        payload = decoder.decompress(compressed, decompressed_limit + 1)
    except zlib.error as error:
        raise CurrentAuditError(f"CURRENT_AUDIT_GZIP_INVALID:{label}") from error
    if len(payload) > decompressed_limit:
        raise CurrentAuditError(f"CURRENT_AUDIT_GZIP_RESOURCE_BOUND:{label}")
    if not decoder.eof or decoder.unconsumed_tail or decoder.unused_data:
        raise CurrentAuditError(f"CURRENT_AUDIT_GZIP_SINGLE_MEMBER_INVALID:{label}")
    _require_int(
        record.get("uncompressed_bytes"), len(payload), f"{label}.uncompressed_bytes"
    )
    _require_int(
        record.get("uncompressed_lines"),
        len(payload.splitlines()),
        f"{label}.uncompressed_lines",
    )
    if _sha256(payload) != _require_hex(
        record.get("uncompressed_sha256"), HEX64, f"{label}.uncompressed"
    ):
        raise CurrentAuditError(f"CURRENT_AUDIT_GZIP_DIGEST_MISMATCH:{label}")
    return payload


def _verify_handoff_zip(payload: bytes, expected_files: int, label: str) -> None:
    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            entries = archive.infolist()
            names = [entry.filename for entry in entries]
            if (
                len(entries) != expected_files
                or len(names) != len(set(names))
                or sum(entry.file_size for entry in entries) > MAX_ZIP_TOTAL_BYTES
            ):
                raise CurrentAuditError(f"CURRENT_AUDIT_ZIP_INVENTORY_INVALID:{label}")
            for entry in entries:
                path = PurePosixPath(entry.filename)
                mode = entry.external_attr >> 16
                if (
                    path.is_absolute()
                    or ".." in path.parts
                    or "\\" in entry.filename
                    or entry.is_dir()
                    or entry.file_size > MAX_ZIP_ENTRY_BYTES
                    or mode & 0o170000 == 0o120000
                ):
                    raise CurrentAuditError(f"CURRENT_AUDIT_ZIP_ENTRY_INVALID:{label}")
            if archive.testzip() is not None:
                raise CurrentAuditError(f"CURRENT_AUDIT_ZIP_CRC_INVALID:{label}")
    except (OSError, zipfile.BadZipFile, RuntimeError) as error:
        raise CurrentAuditError(f"CURRENT_AUDIT_ZIP_INVALID:{label}") from error


def _verify_source_signature(repo: Path) -> None:
    _verify_trusted_executable(GIT_EXECUTABLE, "git")
    _verify_trusted_executable(SSH_KEYGEN_EXECUTABLE, "ssh-keygen")
    allowed_signers = _git_file(repo, SOURCE_COMMIT, "release/0.9.0/allowed-signers")
    if (
        _sha256(allowed_signers)
        != EXPECTED_SOURCE_FILES["release/0.9.0/allowed-signers"]
    ):
        raise CurrentAuditError("CURRENT_AUDIT_ALLOWED_SIGNERS_MISMATCH")
    with tempfile.NamedTemporaryFile() as handle:
        handle.write(allowed_signers)
        handle.flush()
        environment = _sanitized_git_environment()
        result_code, result_stdout, result_stderr = _run_bounded(
            _git_command(
                "-c",
                f"gpg.ssh.allowedSignersFile={handle.name}",
                "-c",
                f"gpg.ssh.program={SSH_KEYGEN_EXECUTABLE}",
                "-c",
                f"gpg.ssh.revocationFile={os.devnull}",
                "-c",
                "gpg.format=ssh",
                "verify-commit",
                SOURCE_COMMIT,
            ),
            cwd=repo,
            env=environment,
            timeout_seconds=30,
            stdout_limit=MAX_GIT_BYTES,
            stderr_limit=MAX_GIT_BYTES,
            error_prefix="CURRENT_AUDIT_SIGNATURE_CHECK",
        )
        key_code, key_stdout, key_stderr = _run_bounded(
            [SSH_KEYGEN_EXECUTABLE, "-E", "sha256", "-lf", handle.name],
            cwd=repo,
            env=environment,
            timeout_seconds=30,
            stdout_limit=MAX_GIT_BYTES,
            stderr_limit=MAX_GIT_BYTES,
            error_prefix="CURRENT_AUDIT_SIGNATURE_KEY_CHECK",
        )
    output = (result_stdout + result_stderr).strip()
    key_output = (key_stdout + key_stderr).strip()
    expected_signature = (
        b'Good "git" signature for sepmhn@gmail.com with ED25519 key '
        b"SHA256:3gaatfl4IVnuBX4D60Jxw9oVIrvEE1ZphK8IuEyrfPU"
    )
    expected_key = (
        b"256 SHA256:3gaatfl4IVnuBX4D60Jxw9oVIrvEE1ZphK8IuEyrfPU "
        b"sepmhn@gmail.com (ED25519)"
    )
    if (
        result_code != 0
        or key_code != 0
        or output != expected_signature
        or key_output != expected_key
    ):
        raise CurrentAuditError("CURRENT_AUDIT_SOURCE_SIGNATURE_INVALID")


def _ssh_public_key_fingerprint(repo: Path, public_key: str, label: str) -> str:
    """Return the verified SHA-256 fingerprint for one exact Ed25519 key."""

    if re.fullmatch(r"ssh-ed25519 [A-Za-z0-9+/]+={0,2}", public_key) is None:
        raise CurrentAuditError(f"CURRENT_AUDIT_DETACHED_KEY_INVALID:{label}")
    _verify_trusted_executable(SSH_KEYGEN_EXECUTABLE, "ssh-keygen")
    with tempfile.NamedTemporaryFile() as key_handle:
        key_handle.write(f"{public_key}\n".encode("utf-8"))
        key_handle.flush()
        key_code, key_stdout, key_stderr = _run_bounded(
            [SSH_KEYGEN_EXECUTABLE, "-E", "sha256", "-lf", key_handle.name],
            cwd=repo,
            env=_sanitized_git_environment(),
            timeout_seconds=30,
            stdout_limit=MAX_GIT_BYTES,
            stderr_limit=MAX_GIT_BYTES,
            error_prefix="CURRENT_AUDIT_DETACHED_KEY",
        )
    key_fields = (key_stdout + key_stderr).strip().split()
    if (
        key_code != 0
        or len(key_fields) < 4
        or key_fields[0] != b"256"
        or key_fields[-1] != b"(ED25519)"
    ):
        raise CurrentAuditError(f"CURRENT_AUDIT_DETACHED_KEY_INVALID:{label}")
    try:
        fingerprint = key_fields[1].decode("ascii")
    except UnicodeDecodeError as error:
        raise CurrentAuditError(
            f"CURRENT_AUDIT_DETACHED_KEY_INVALID:{label}"
        ) from error
    if re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}", fingerprint) is None:
        raise CurrentAuditError(f"CURRENT_AUDIT_DETACHED_KEY_INVALID:{label}")
    return fingerprint


def _verify_ssh_detached_attestation(
    repo: Path,
    attestation: Any,
    payload: bytes,
    *,
    namespace: str,
    label: str,
    expected_principal: str | None = None,
    expected_public_key: str | None = None,
    expected_fingerprint: str | None = None,
) -> dict[str, Any]:
    value = _require_fields(
        attestation,
        {
            "format",
            "namespace",
            "principal",
            "public_key",
            "key_fingerprint",
            "signature",
        },
        label,
    )
    principal = value.get("principal")
    public_key = value.get("public_key")
    fingerprint = value.get("key_fingerprint")
    signature = value.get("signature")
    if (
        value.get("format") != "ssh"
        or value.get("namespace") != namespace
        or not isinstance(principal, str)
        or re.fullmatch(r"[^\s\x00-\x1f\x7f]{3,254}", principal) is None
        or (expected_principal is not None and principal != expected_principal)
        or not isinstance(public_key, str)
        or re.fullmatch(r"ssh-ed25519 [A-Za-z0-9+/]+={0,2}", public_key) is None
        or (expected_public_key is not None and public_key != expected_public_key)
        or not isinstance(fingerprint, str)
        or re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}", fingerprint) is None
        or (expected_fingerprint is not None and fingerprint != expected_fingerprint)
        or not isinstance(signature, str)
        or len(signature.encode("utf-8")) > 16 * 1024
        or not signature.startswith("-----BEGIN SSH SIGNATURE-----\n")
        or not signature.endswith("-----END SSH SIGNATURE-----\n")
        or len(payload) > MAX_JSON_BYTES
    ):
        raise CurrentAuditError(f"CURRENT_AUDIT_DETACHED_SIGNATURE_FIELDS:{label}")
    _verify_trusted_executable(SSH_KEYGEN_EXECUTABLE, "ssh-keygen")
    if _ssh_public_key_fingerprint(repo, public_key, label) != fingerprint:
        raise CurrentAuditError(f"CURRENT_AUDIT_DETACHED_SIGNATURE_INVALID:{label}")
    environment = _sanitized_git_environment()
    with tempfile.TemporaryDirectory(prefix="haldir-signature-") as directory:
        root = Path(directory)
        allowed_path = root / "allowed-signers"
        signature_path = root / "attestation.sig"
        payload_path = root / "payload"
        allowed_path.write_bytes(f"{principal} {public_key}\n".encode("utf-8"))
        signature_path.write_bytes(signature.encode("utf-8"))
        payload_path.write_bytes(payload)
        verify_code, verify_stdout, verify_stderr = _run_bounded(
            [
                SSH_KEYGEN_EXECUTABLE,
                "-Y",
                "verify",
                "-f",
                str(allowed_path),
                "-I",
                principal,
                "-n",
                namespace,
                "-s",
                str(signature_path),
            ],
            cwd=repo,
            env=environment,
            timeout_seconds=30,
            stdout_limit=MAX_GIT_BYTES,
            stderr_limit=MAX_GIT_BYTES,
            error_prefix="CURRENT_AUDIT_DETACHED_SIGNATURE",
            stdin_path=payload_path,
        )
    expected_verify = (
        f'Good "{namespace}" signature for {principal} with ED25519 key {fingerprint}'
    ).encode("utf-8")
    if verify_code != 0 or (verify_stdout + verify_stderr).strip() != expected_verify:
        raise CurrentAuditError(f"CURRENT_AUDIT_DETACHED_SIGNATURE_INVALID:{label}")
    return value


def _review_attestation_payload(
    record: dict[str, Any],
    *,
    task_id: str,
    epoch: int,
    freeze_commit: str,
    implementation_commit: str,
) -> bytes:
    """Bind a detached review signature to its exact purpose and outer claims."""

    unsigned_record = {
        key: copy.deepcopy(value)
        for key, value in record.items()
        if key != "detached_signature"
    }
    return (
        json.dumps(
            {
                "schema_version": "1.0.0",
                "purpose": "SUCCESSOR_IMPLEMENTATION_QUALIFICATION_REVIEW",
                "task_id": task_id,
                "epoch": epoch,
                "freeze_commit": freeze_commit,
                "implementation_commit": implementation_commit,
                "review_record": unsigned_record,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def _source_inventory(repo: Path) -> tuple[int, int, list[str]]:
    entries = _git(repo, "ls-tree", "-r", "-z", "--long", SOURCE_COMMIT).split(b"\0")
    tracked_files = 0
    tracked_bytes = 0
    submodules: list[str] = []
    try:
        for entry in entries:
            if not entry:
                continue
            header, raw_path = entry.split(b"\t", 1)
            _mode, object_type, _object_id, raw_size = header.split()
            tracked_files += 1
            if object_type == b"blob":
                tracked_bytes += int(raw_size)
            elif object_type == b"commit":
                submodules.append(raw_path.decode("utf-8"))
            else:
                raise ValueError("unexpected Git object type")
    except (UnicodeDecodeError, ValueError) as error:
        raise CurrentAuditError("CURRENT_AUDIT_SOURCE_INVENTORY_INVALID") from error
    return tracked_files, tracked_bytes, submodules


def _verify_source(manifest: dict[str, Any], repo: Path) -> None:
    source = manifest.get("source")
    expected_fields = {
        "repository",
        "remote",
        "branch",
        "commit",
        "tree",
        "parent",
        "tree_clean",
        "origin_main_commit",
        "tracked_files",
        "tracked_bytes",
        "submodules",
        "source_commit_signature",
    }
    if not isinstance(source, dict) or set(source) != expected_fields:
        raise CurrentAuditError("CURRENT_AUDIT_SOURCE_FIELDS_INVALID")
    if (
        source.get("repository") != "https://github.com/sepahead/haldir"
        or source.get("remote") != "git@github.com:sepahead/haldir.git"
        or source.get("branch") != "main"
        or source.get("commit") != SOURCE_COMMIT
        or source.get("tree") != SOURCE_TREE
        or source.get("parent") != SOURCE_PARENT
        or source.get("tree_clean") is not True
        or source.get("origin_main_commit") != SOURCE_COMMIT
        or source.get("tracked_files") != 283
        or source.get("tracked_bytes") != 5_562_467
        or source.get("submodules") != []
        or source.get("source_commit_signature") != SOURCE_SIGNATURE
    ):
        raise CurrentAuditError("CURRENT_AUDIT_SOURCE_IDENTITY_INVALID")
    _require_int(source.get("tracked_files"), 283, "source.tracked_files")
    _require_int(source.get("tracked_bytes"), 5_562_467, "source.tracked_bytes")
    actual_tree = _git(repo, "rev-parse", f"{SOURCE_COMMIT}^{{tree}}").decode().strip()
    if actual_tree != SOURCE_TREE:
        raise CurrentAuditError("CURRENT_AUDIT_SOURCE_TREE_MISMATCH")
    parents = (
        _git(repo, "rev-list", "--parents", "-n", "1", SOURCE_COMMIT).decode().split()
    )
    if parents != [SOURCE_COMMIT, SOURCE_PARENT]:
        raise CurrentAuditError("CURRENT_AUDIT_SOURCE_PARENT_MISMATCH")
    if _source_inventory(repo) != (283, 5_562_467, []):
        raise CurrentAuditError("CURRENT_AUDIT_SOURCE_INVENTORY_MISMATCH")
    _verify_source_signature(repo)


def _verify_handoff(manifest: dict[str, Any]) -> None:
    handoff = manifest.get("handoff")
    expected_fields = {
        "package",
        "prepared",
        "original_release_target",
        "adapted_release_target",
        "original_frozen_commit",
        "task_namespace",
        "original_task_count",
        "checksums_verified",
        *EXPECTED_HANDOFF,
    }
    if not isinstance(handoff, dict) or set(handoff) != expected_fields:
        raise CurrentAuditError("CURRENT_AUDIT_HANDOFF_FIELDS_INVALID")
    if (
        handoff.get("package") != "HALDIR_V1_0_CURRENT_HEAD_MAX_EFFORT_HANDOFF"
        or handoff.get("prepared") != "2026-07-14"
        or handoff.get("original_release_target") != "1.0.0"
        or handoff.get("adapted_release_target") != "0.9.0"
        or handoff.get("original_frozen_commit") != SOURCE_PARENT
        or handoff.get("task_namespace") != "CH-T000..CH-T125"
        or handoff.get("original_task_count") != 126
        or handoff.get("checksums_verified") is not True
    ):
        raise CurrentAuditError("CURRENT_AUDIT_HANDOFF_IDENTITY_INVALID")
    _require_int(handoff.get("original_task_count"), 126, "handoff.task_count")
    for field, expected in EXPECTED_HANDOFF.items():
        if _require_hex(handoff.get(field), HEX64, field) != expected:
            raise CurrentAuditError(f"CURRENT_AUDIT_HANDOFF_DIGEST_MISMATCH:{field}")


def _verify_master_handoff(manifest: dict[str, Any], repo: Path) -> None:
    master = manifest.get("master_handoff")
    if not _strict_equal(master, EXPECTED_MASTER_HANDOFF):
        raise CurrentAuditError("CURRENT_AUDIT_MASTER_HANDOFF_INVALID")
    retained_payloads: dict[str, bytes] = {}
    for index, record in enumerate(EXPECTED_MASTER_HANDOFF["retained_inputs"]):
        payload = _read_evidence_file(
            repo, record, f"master_handoff[{index}]", 128 * 1024
        )
        retained_payloads[record["path"]] = payload
        if record["path"].endswith("HALDIR_V1_0_CURRENT_HEAD_MAX_EFFORT_HANDOFF.zip"):
            _verify_handoff_zip(payload, 23, "haldir_handoff")
        elif record["path"].endswith("CROSS_REPO_RECONCILIATION_HANDOFF.zip"):
            _verify_handoff_zip(payload, 12, "cross_repo_handoff")

    heads_path = "release/0.9.0/current-head/handoff/MASTER_CURRENT_HEADS.json"
    heads = _load_json_bytes(retained_payloads[heads_path], "master_handoff.heads")
    if not _strict_equal(
        heads,
        {
            "heads": EXPECTED_MASTER_HANDOFF["frozen_heads"],
            "prepared": "2026-07-14",
            "status": "frozen audit cuts; abort and re-audit on change",
        },
    ):
        raise CurrentAuditError("CURRENT_AUDIT_MASTER_HEADS_CONTENT_INVALID")

    package_index_path = "release/0.9.0/current-head/handoff/PACKAGE_INDEX.json"
    package_index = _load_json_bytes(
        retained_payloads[package_index_path], "master_handoff.package_index"
    )
    child_filenames = {
        "NCP": "NCP_V1_0_CURRENT_HEAD_MAX_EFFORT_HANDOFF.zip",
        "crebain": "CREBAIN_V1_0_CURRENT_HEAD_MAX_EFFORT_HANDOFF.zip",
        "galadriel": "GALADRIEL_V1_0_CURRENT_HEAD_MAX_EFFORT_HANDOFF.zip",
        "haldir": "HALDIR_V1_0_CURRENT_HEAD_MAX_EFFORT_HANDOFF.zip",
        "pid-rs": "PID_RS_V1_0_CURRENT_HEAD_MAX_EFFORT_HANDOFF.zip",
    }
    expected_children = {
        name: {"filename": child_filenames[name], **record}
        for name, record in EXPECTED_MASTER_HANDOFF["child_archives"].items()
    }
    if not _strict_equal(
        package_index,
        {
            "children": expected_children,
            "cross_repo": {
                "filename": "SEPAHEAD_V1_0_CURRENT_HEAD_CROSS_REPO_RECONCILIATION_HANDOFF.zip",
                "files": 12,
                "sha256": EXPECTED_MASTER_HANDOFF["cross_archive_sha256"],
                "tasks": 79,
            },
            "prepared": "2026-07-14",
        },
    ):
        raise CurrentAuditError("CURRENT_AUDIT_PACKAGE_INDEX_CONTENT_INVALID")


def _verify_input_scope(manifest: dict[str, Any], repo: Path) -> None:
    scope = manifest.get("input_scope")
    if not _strict_equal(scope, EXPECTED_INPUT_SCOPE):
        raise CurrentAuditError("CURRENT_AUDIT_INPUT_SCOPE_INVALID")
    try:
        root_manifest = tomllib.loads(
            _git_file(repo, SOURCE_COMMIT, "Cargo.toml").decode()
        )
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise CurrentAuditError("CURRENT_AUDIT_ROOT_MANIFEST_INVALID") from error
    workspace = root_manifest.get("workspace")
    if not isinstance(workspace, dict):
        raise CurrentAuditError("CURRENT_AUDIT_WORKSPACE_MISSING")
    package_defaults = workspace.get("package")
    if not _strict_equal(
        package_defaults,
        {
            "version": "0.1.0-experimental",
            "edition": "2024",
            "rust-version": "1.96",
            "license": "Apache-2.0 OR MIT",
            "repository": "https://github.com/sepahead/haldir",
            "authors": ["Sepahead"],
            "publish": False,
        },
    ):
        raise CurrentAuditError("CURRENT_AUDIT_WORKSPACE_DEFAULTS_INVALID")
    if set(workspace.get("members", [])) != {
        path.removesuffix("/Cargo.toml") for path in PACKAGE_MANIFESTS
    }:
        raise CurrentAuditError("CURRENT_AUDIT_WORKSPACE_MEMBERS_INVALID")
    for path, expected_name in PACKAGE_MANIFESTS.items():
        try:
            member = tomllib.loads(_git_file(repo, SOURCE_COMMIT, path).decode())
        except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
            raise CurrentAuditError(
                f"CURRENT_AUDIT_PACKAGE_MANIFEST_INVALID:{path}"
            ) from error
        package = member.get("package")
        if not isinstance(package, dict) or (
            package.get("name") != expected_name
            or package.get("version") != {"workspace": True}
            or package.get("authors") != {"workspace": True}
            or package.get("publish") != {"workspace": True}
        ):
            raise CurrentAuditError(f"CURRENT_AUDIT_PACKAGE_IDENTITY_INVALID:{path}")

    tree_paths = set(
        _git(repo, "ls-tree", "-r", "--name-only", SOURCE_COMMIT).decode().splitlines()
    )
    declared_paths = (
        EXPECTED_INPUT_SCOPE["formal_artifacts"]
        + EXPECTED_INPUT_SCOPE["test_data"]
        + EXPECTED_INPUT_SCOPE["deployment_profiles"]
        + EXPECTED_INPUT_SCOPE["interop_corpora"]
    )
    if any(path not in tree_paths for path in declared_paths):
        raise CurrentAuditError("CURRENT_AUDIT_DECLARED_INPUT_MISSING")
    if any(
        path.lower().endswith(tuple(EXPECTED_INPUT_SCOPE["paper_suffixes_scanned"]))
        for path in tree_paths
    ):
        raise CurrentAuditError("CURRENT_AUDIT_UNRECORDED_PAPER_FOUND")
    if any(
        path.lower().endswith(
            (".onnx", ".pb", ".pt", ".pth", ".safetensors", ".tflite")
        )
        for path in tree_paths
    ):
        raise CurrentAuditError("CURRENT_AUDIT_UNRECORDED_ML_MODEL_FOUND")


def _verify_cut_update(manifest: dict[str, Any], repo: Path) -> None:
    update = manifest.get("approved_cut_update")
    if not isinstance(update, dict):
        raise CurrentAuditError("CURRENT_AUDIT_UPDATE_INVALID")
    if update != {
        "status": "LEAD_APPROVED_AFTER_COMPLETE_DIFF_AND_REBASELINE",
        "from_commit": SOURCE_PARENT,
        "to_commit": SOURCE_COMMIT,
        "commit_count": 1,
        "insertions": 340,
        "deletions": 58,
        "patch_sha256": "621264b02620212b5cf2255cfc37c492f66f2d52160e14f2e7ff464e44cee413",
        "files": [
            {
                "path": "docs/THREAT-MODEL.md",
                "change": "modified",
                "sha256": "b5d7b83d29a95a58cb2c8d3ecfa470db0c2d8b76e09abed5e9af58ee00abb70b",
            },
            {
                "path": "docs/release/0.9.0/THREAT-MODEL.md",
                "change": "added",
                "sha256": "cd7010762be3bc3cd278d932fa1e3f0c8014d5277799405822148c28bdeffbc0",
            },
        ],
    }:
        raise CurrentAuditError("CURRENT_AUDIT_UPDATE_RECORD_MISMATCH")
    _require_int(update.get("commit_count"), 1, "approved_cut_update.commit_count")
    _require_int(update.get("insertions"), 340, "approved_cut_update.insertions")
    _require_int(update.get("deletions"), 58, "approved_cut_update.deletions")
    commit_count = (
        _git(repo, "rev-list", "--count", f"{SOURCE_PARENT}..{SOURCE_COMMIT}")
        .decode()
        .strip()
    )
    if commit_count != "1":
        raise CurrentAuditError("CURRENT_AUDIT_UPDATE_COMMIT_COUNT_MISMATCH")
    name_status = (
        _git(
            repo,
            "diff",
            "--no-renames",
            "--no-color",
            "--name-status",
            f"{SOURCE_PARENT}..{SOURCE_COMMIT}",
        )
        .decode()
        .splitlines()
    )
    if name_status != [
        "M\tdocs/THREAT-MODEL.md",
        "A\tdocs/release/0.9.0/THREAT-MODEL.md",
    ]:
        raise CurrentAuditError("CURRENT_AUDIT_UPDATE_DIFF_MISMATCH")
    numstat = (
        _git(
            repo,
            "-c",
            "diff.algorithm=myers",
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "--no-renames",
            "--no-color",
            "--numstat",
            f"{SOURCE_PARENT}..{SOURCE_COMMIT}",
        )
        .decode()
        .splitlines()
    )
    if numstat != [
        "19\t58\tdocs/THREAT-MODEL.md",
        "321\t0\tdocs/release/0.9.0/THREAT-MODEL.md",
    ]:
        raise CurrentAuditError("CURRENT_AUDIT_UPDATE_NUMSTAT_MISMATCH")
    patch = _git(
        repo,
        "-c",
        "diff.algorithm=myers",
        "diff",
        "--no-ext-diff",
        "--no-textconv",
        "--no-renames",
        "--no-color",
        "--src-prefix=a/",
        "--dst-prefix=b/",
        "--binary",
        "--full-index",
        f"{SOURCE_PARENT}..{SOURCE_COMMIT}",
    )
    if _sha256(patch) != update["patch_sha256"]:
        raise CurrentAuditError("CURRENT_AUDIT_UPDATE_PATCH_MISMATCH")
    for record in update["files"]:
        if _sha256(_git_file(repo, SOURCE_COMMIT, record["path"])) != record["sha256"]:
            raise CurrentAuditError("CURRENT_AUDIT_UPDATE_FILE_MISMATCH")


def _verify_locked_inputs(manifest: dict[str, Any], repo: Path) -> None:
    locked = manifest.get("locked_inputs")
    if not isinstance(locked, list) or len(locked) != len(EXPECTED_SOURCE_FILES):
        raise CurrentAuditError("CURRENT_AUDIT_LOCKED_INPUTS_INVALID")
    observed: dict[str, str] = {}
    for record in locked:
        if not isinstance(record, dict) or set(record) != {"path", "sha256"}:
            raise CurrentAuditError("CURRENT_AUDIT_LOCKED_INPUT_ENTRY_INVALID")
        path = record.get("path")
        digest = _require_hex(record.get("sha256"), HEX64, "locked_input")
        if not isinstance(path, str) or path in observed:
            raise CurrentAuditError("CURRENT_AUDIT_LOCKED_INPUT_DUPLICATE")
        observed[path] = digest
    if observed != EXPECTED_SOURCE_FILES:
        raise CurrentAuditError("CURRENT_AUDIT_LOCKED_INPUT_SET_MISMATCH")
    for path, expected in observed.items():
        if _sha256(_git_file(repo, SOURCE_COMMIT, path)) != expected:
            raise CurrentAuditError(f"CURRENT_AUDIT_LOCKED_INPUT_MISMATCH:{path}")


REQUIREMENT_IDENTITY_FIELDS = (
    "id",
    "source_task_id",
    "source_record_sha256",
    "phase",
    "title",
    "source_scope",
    "focus",
    "priority",
    "dependencies",
    "execution_wave",
    "subagent_lane",
    "lead_review_required",
)
REQUIREMENT_MUTABLE_FIELDS = {
    "status",
    "claim_disposition",
    "assigned_reviewers",
    "implementation_commits",
    "evidence",
    "closure_commit",
    "twenty_lens_reviews",
}
OPEN_REQUIREMENT_STATE = {
    "status": "OPEN",
    "claim_disposition": "UNRESOLVED",
    "assigned_reviewers": [],
    "implementation_commits": [],
    "evidence": [],
    "closure_commit": None,
    "twenty_lens_reviews": {},
}


def _verify_dependency_cascade(tasks: list[dict[str, Any]]) -> None:
    """Require terminal tasks to form a dependency-closed prefix."""

    open_seen = False
    for index, task in enumerate(tasks):
        status = task.get("status")
        if status == "OPEN":
            open_seen = True
        elif status == "VERIFIED":
            if open_seen:
                raise CurrentAuditError(
                    f"CURRENT_AUDIT_DEPENDENCY_CASCADE_INVALID:CH-T{index:03d}"
                )
        else:
            raise CurrentAuditError(
                f"CURRENT_AUDIT_REQUIREMENT_STATUS_INVALID:CH-T{index:03d}"
            )


def _verify_terminal_requirement_state(
    ledger: dict[str, Any],
    bootstrap: dict[str, Any],
    *,
    framework_commit: str,
    qualification_commit: str,
    evidence_ids: list[str],
    lens_projection: dict[str, Any],
) -> None:
    """Validate the exact dormant CH-T000-only terminal transition."""

    tasks = ledger["tasks"]
    bootstrap_tasks = bootstrap["tasks"]
    if set(ledger) != set(bootstrap) or not _strict_equal(
        {key: value for key, value in ledger.items() if key != "tasks"},
        {key: value for key, value in bootstrap.items() if key != "tasks"},
    ):
        raise CurrentAuditError("CURRENT_AUDIT_TERMINAL_LEDGER_METADATA_INVALID")
    if not _strict_equal(
        {field: tasks[0][field] for field in REQUIREMENT_IDENTITY_FIELDS},
        {field: bootstrap_tasks[0][field] for field in REQUIREMENT_IDENTITY_FIELDS},
    ):
        raise CurrentAuditError("CURRENT_AUDIT_TERMINAL_TASK_ZERO_IDENTITY_INVALID")
    expected_mutable_task_zero = {
        "status": "VERIFIED",
        "claim_disposition": "NO_PUBLIC_CLAIM_CHANGE",
        "assigned_reviewers": ["CH-T000-R01", "CH-T000-R02", "CH-T000-R03"],
        "implementation_commits": [IMPLEMENTATION_COMMIT, framework_commit],
        "evidence": evidence_ids,
        "closure_commit": qualification_commit,
        "twenty_lens_reviews": lens_projection,
    }
    expected_task_zero = copy.deepcopy(bootstrap_tasks[0])
    expected_task_zero.update(expected_mutable_task_zero)
    expected_tasks = [expected_task_zero, *copy.deepcopy(bootstrap_tasks[1:])]
    if not _strict_equal(tasks, expected_tasks):
        raise CurrentAuditError("CURRENT_AUDIT_TERMINAL_TASKS_INVALID")
    _verify_dependency_cascade(tasks)
    if ledger.get("overall_status") != "NO_GO":
        raise CurrentAuditError("CURRENT_AUDIT_TERMINAL_OVERALL_STATUS_INVALID")


def _verify_requirements_ledger(manifest: dict[str, Any], repo: Path) -> str:
    record = manifest.get("requirements_ledger")
    if not _strict_equal(record, EXPECTED_REQUIREMENTS_LEDGER):
        raise CurrentAuditError("CURRENT_AUDIT_REQUIREMENTS_RECORD_INVALID")
    current_payload = _read_repo_relative_bounded(
        repo,
        EXPECTED_REQUIREMENTS_LEDGER["path"],
        MAX_REQUIREMENTS_BYTES,
        "requirements",
    )
    bootstrap_payload = _git_file(
        repo, IMPLEMENTATION_COMMIT, EXPECTED_REQUIREMENTS_LEDGER["path"]
    )
    if (
        _sha256(bootstrap_payload) != BOOTSTRAP_REQUIREMENTS_SHA256
        or len(bootstrap_payload) != BOOTSTRAP_REQUIREMENTS_BYTES
        or len(bootstrap_payload.splitlines()) != BOOTSTRAP_REQUIREMENTS_LINES
    ):
        raise CurrentAuditError("CURRENT_AUDIT_REQUIREMENTS_BOOTSTRAP_FILE_INVALID")
    ledger = _load_json_bytes(current_payload, "requirements")
    bootstrap = _load_json_bytes(bootstrap_payload, "requirements.bootstrap")
    expected_top_level = {
        "schema_version",
        "project",
        "release_target",
        "author",
        "persistent_identifier",
        "source_handoff",
        "approved_cut",
        "legacy_ledger",
        "task_identity",
        "overall_status",
        "tasks",
    }
    if set(ledger) != expected_top_level:
        raise CurrentAuditError("CURRENT_AUDIT_REQUIREMENTS_FIELDS_INVALID")
    expected_metadata = {
        "schema_version": "1.0.0",
        "project": "Haldir",
        "release_target": "0.9.0",
        "author": {"name": "Sepehr Mahmoudian", "email": "sepmhn@gmail.com"},
        "persistent_identifier": None,
        "source_handoff": {
            "archive_path": "release/0.9.0/current-head/handoff/HALDIR_V1_0_CURRENT_HEAD_MAX_EFFORT_HANDOFF.zip",
            "archive_sha256": EXPECTED_HANDOFF["archive_sha256"],
            "ledger_path_in_archive": "MASTER_TASK_LEDGER.yaml",
            "ledger_sha256": EXPECTED_HANDOFF["ledger_sha256"],
            "original_release_target": "1.0.0",
            "original_frozen_commit": SOURCE_PARENT,
        },
        "approved_cut": {
            "commit": SOURCE_COMMIT,
            "tree": SOURCE_TREE,
            "errata_path": "release/0.9.0/current-head/HANDOFF-ERRATA.md",
        },
        "legacy_ledger": {
            "path": "release/0.9.0/requirements.json",
            "source_commit_sha256": EXPECTED_REQUIREMENTS_LEDGER[
                "legacy_ledger_sha256"
            ],
            "task_namespace": "T000..T119",
            "task_count": 120,
            "closure_transfer_permitted": False,
        },
        "task_identity": {
            "namespace": "CH-T000..CH-T125",
            "count": 126,
            "dependency_model": "STRICT_SINGLE_CHAIN",
            "source_ids_preserved": True,
            "closure_requires_all_twenty_lenses": True,
        },
    }
    for key, expected in expected_metadata.items():
        if not _strict_equal(ledger.get(key), expected):
            raise CurrentAuditError(f"CURRENT_AUDIT_REQUIREMENTS_METADATA:{key}")
    if ledger.get("overall_status") not in {"NO_GO", "NARROWED_GO", "GO"}:
        raise CurrentAuditError("CURRENT_AUDIT_REQUIREMENTS_OVERALL_STATUS_INVALID")
    tasks = ledger.get("tasks")
    if not isinstance(tasks, list) or len(tasks) != 126:
        raise CurrentAuditError("CURRENT_AUDIT_REQUIREMENTS_TASK_COUNT_INVALID")
    identities: list[dict[str, Any]] = []
    for index, task in enumerate(tasks):
        if (
            not isinstance(task, dict)
            or set(task)
            != set(REQUIREMENT_IDENTITY_FIELDS) | REQUIREMENT_MUTABLE_FIELDS
        ):
            raise CurrentAuditError(f"CURRENT_AUDIT_REQUIREMENTS_TASK_FIELDS:{index}")
        expected_id = f"CH-T{index:03d}"
        expected_source_id = f"T{index:03d}"
        expected_dependencies = [] if index == 0 else [f"CH-T{index - 1:03d}"]
        if (
            task.get("id") != expected_id
            or task.get("source_task_id") != expected_source_id
            or task.get("dependencies") != expected_dependencies
        ):
            raise CurrentAuditError(
                f"CURRENT_AUDIT_REQUIREMENTS_TASK_INVALID:{expected_id}"
            )
        _require_hex(task.get("source_record_sha256"), HEX64, expected_id)
        identities.append({field: task[field] for field in REQUIREMENT_IDENTITY_FIELDS})
    identity_payload = json.dumps(
        identities, sort_keys=True, separators=(",", ":")
    ).encode()
    if _sha256(identity_payload) != EXPECTED_REQUIREMENTS_LEDGER["identity_sha256"]:
        raise CurrentAuditError("CURRENT_AUDIT_REQUIREMENTS_IDENTITY_MISMATCH")
    if not _strict_equal(
        {
            key: bootstrap[key]
            for key in expected_top_level - {"tasks", "overall_status"}
        },
        {key: ledger[key] for key in expected_top_level - {"tasks", "overall_status"}},
    ):
        raise CurrentAuditError("CURRENT_AUDIT_REQUIREMENTS_METADATA_DRIFT")
    for index, (task, bootstrap_task) in enumerate(
        zip(tasks, bootstrap["tasks"], strict=True)
    ):
        if not _strict_equal(
            {field: task[field] for field in REQUIREMENT_IDENTITY_FIELDS},
            {field: bootstrap_task[field] for field in REQUIREMENT_IDENTITY_FIELDS},
        ):
            raise CurrentAuditError(
                f"CURRENT_AUDIT_REQUIREMENTS_IMMUTABLE_DRIFT:CH-T{index:03d}"
            )
    _verify_dependency_cascade(tasks)
    if all(
        _strict_equal(
            {field: task[field] for field in REQUIREMENT_MUTABLE_FIELDS},
            OPEN_REQUIREMENT_STATE,
        )
        for task in tasks
    ):
        if current_payload != bootstrap_payload:
            raise CurrentAuditError("CURRENT_AUDIT_REQUIREMENTS_OPEN_BYTES_DRIFT")
        return "OPEN"
    return "TERMINAL_PENDING_ACTIVATION_VALIDATION"


def _verify_baseline(manifest: dict[str, Any], repo: Path) -> None:
    baseline = manifest.get("baseline")
    if not isinstance(baseline, dict) or set(baseline) != {
        "source_commit",
        "command",
        "exit_status",
        "passed_gates",
        "failed_gates",
        "log",
    }:
        raise CurrentAuditError("CURRENT_AUDIT_BASELINE_INVALID")
    if (
        baseline.get("source_commit") != SOURCE_COMMIT
        or baseline.get("command") != "bash tools/p0r-exit-gate.sh"
        or baseline.get("exit_status") != 0
        or baseline.get("passed_gates") != 27
        or baseline.get("failed_gates") != 0
    ):
        raise CurrentAuditError("CURRENT_AUDIT_BASELINE_RESULT_INVALID")
    _require_int(baseline.get("exit_status"), 0, "baseline.exit_status")
    _require_int(baseline.get("passed_gates"), 27, "baseline.passed_gates")
    _require_int(baseline.get("failed_gates"), 0, "baseline.failed_gates")
    log = baseline.get("log")
    if not isinstance(log, dict) or set(log) != {
        "path",
        "compressed_sha256",
        "compressed_bytes",
        "uncompressed_sha256",
        "uncompressed_bytes",
        "uncompressed_lines",
    }:
        raise CurrentAuditError("CURRENT_AUDIT_BASELINE_LOG_RECORD_INVALID")
    if log != {
        "path": BASELINE_LOG_PATH,
        "compressed_sha256": BASELINE_COMPRESSED_SHA256,
        "compressed_bytes": 20_018,
        "uncompressed_sha256": BASELINE_UNCOMPRESSED_SHA256,
        "uncompressed_bytes": 130_401,
        "uncompressed_lines": 2_409,
    }:
        raise CurrentAuditError("CURRENT_AUDIT_BASELINE_LOG_RECORD_MISMATCH")
    _require_int(log.get("compressed_bytes"), 20_018, "baseline.log.compressed_bytes")
    _require_int(
        log.get("uncompressed_bytes"), 130_401, "baseline.log.uncompressed_bytes"
    )
    _require_int(log.get("uncompressed_lines"), 2_409, "baseline.log.lines")
    payload = _read_gzip_evidence(repo, log, "baseline.log", MAX_LOG_BYTES)
    try:
        lines = payload.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise CurrentAuditError("CURRENT_AUDIT_BASELINE_LOG_NOT_UTF8") from error
    passed = [
        line.removeprefix("  PASS: ") for line in lines if line.startswith("  PASS: ")
    ]
    failed = [line for line in lines if line.startswith("  FAIL: ")]
    if (
        len(payload) != log.get("uncompressed_bytes")
        or len(payload.splitlines()) != log.get("uncompressed_lines")
        or _sha256(payload)
        != _require_hex(log.get("uncompressed_sha256"), HEX64, "baseline.log")
        or passed != list(BASELINE_GATES)
        or failed
        or payload.count(b"P0-R exit gate: 27 passed, 0 failed") != 1
        or not payload.rstrip().endswith(
            b"All offline P0-R gates passed. (TLA+ check runs in CI: CL-FORMAL-01.)"
        )
    ):
        raise CurrentAuditError("CURRENT_AUDIT_BASELINE_LOG_MISMATCH")


def _verify_publication_state(manifest: dict[str, Any], repo: Path) -> None:
    publication = manifest.get("repository_publication_state")
    if not _strict_equal(publication, EXPECTED_PUBLICATION_STATE):
        raise CurrentAuditError("CURRENT_AUDIT_PUBLICATION_STATE_INVALID")
    publication_payload = _read_evidence_file(
        repo,
        EXPECTED_PUBLICATION_STATE["evidence"],
        "publication_state",
        MAX_JSON_BYTES,
    )
    raw = _load_json_bytes(publication_payload, "publication_state")
    if not _strict_equal(
        raw,
        {
            "captured_at_utc": "2026-07-14T14:47:49Z",
            "cleanup_disposition": "VERIFIED_NO_OP",
            "github_releases": {
                "command": "gh release list --repo sepahead/haldir --limit 100 --json tagName,name,isDraft,isPrerelease,publishedAt",
                "exit_status": 0,
                "values": [],
            },
            "local_tags": {
                "command": "git tag --list",
                "exit_status": 0,
                "values": [],
            },
            "remote_tags": {
                "command": "gh api --paginate repos/sepahead/haldir/tags",
                "exit_status": 0,
                "values": [],
            },
            "schema_version": "1.0.0",
        },
    ):
        raise CurrentAuditError("CURRENT_AUDIT_PUBLICATION_EVIDENCE_INVALID")


def _verify_github_checks(manifest: dict[str, Any], repo: Path) -> None:
    checks = manifest.get("github_source_cut_checks")
    if not _strict_equal(checks, EXPECTED_GITHUB_CHECKS):
        raise CurrentAuditError("CURRENT_AUDIT_GITHUB_CHECKS_INVALID")
    for label, expected in EXPECTED_GITHUB_CHECKS.items():
        metadata_payload = _read_evidence_file(
            repo,
            expected["metadata_evidence"],
            f"github.{label}.metadata",
            MAX_JSON_BYTES,
        )
        raw = _load_json_bytes(metadata_payload, f"github.{label}.metadata")
        expected_fields = {
            "conclusion",
            "createdAt",
            "databaseId",
            "event",
            "headBranch",
            "headSha",
            "jobs",
            "status",
            "updatedAt",
            "url",
            "workflowName",
        }
        if not isinstance(raw, dict) or set(raw) != expected_fields:
            raise CurrentAuditError(f"CURRENT_AUDIT_GITHUB_METADATA_FIELDS:{label}")
        if not _strict_equal(
            {key: raw[key] for key in expected_fields - {"jobs"}},
            {
                "conclusion": expected["conclusion"],
                "createdAt": expected["created_at"],
                "databaseId": expected["run_id"],
                "event": expected["event"],
                "headBranch": expected["head_branch"],
                "headSha": expected["head_sha"],
                "status": expected["status"],
                "updatedAt": expected["updated_at"],
                "url": expected["url"],
                "workflowName": expected["workflow"],
            },
        ):
            raise CurrentAuditError(f"CURRENT_AUDIT_GITHUB_METADATA_MISMATCH:{label}")
        jobs = raw.get("jobs")
        if (
            not isinstance(jobs, list)
            or [job.get("name") for job in jobs] != expected["jobs"]
        ):
            raise CurrentAuditError(f"CURRENT_AUDIT_GITHUB_JOBS_INVALID:{label}")
        for job in jobs:
            if (
                not isinstance(job, dict)
                or job.get("status") != "completed"
                or job.get("conclusion") != "success"
                or not isinstance(job.get("steps"), list)
                or any(step.get("conclusion") != "success" for step in job["steps"])
            ):
                raise CurrentAuditError(f"CURRENT_AUDIT_GITHUB_JOB_FAILED:{label}")
        _read_gzip_evidence(
            repo,
            expected["log_evidence"],
            f"github.{label}.log",
            MAX_LOG_BYTES,
        )


def _require_nonempty_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CurrentAuditError(f"CURRENT_AUDIT_STRING_INVALID:{label}")
    return value


def _require_fields(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise CurrentAuditError(f"CURRENT_AUDIT_FIELDS_INVALID:{label}")
    return value


def _require_string_list(
    value: Any, label: str, *, minimum: int = 1, unique: bool = False
) -> list[str]:
    if (
        not isinstance(value, list)
        or len(value) < minimum
        or any(not isinstance(item, str) or not item.strip() for item in value)
        or (unique and len(value) != len(set(value)))
    ):
        raise CurrentAuditError(f"CURRENT_AUDIT_STRING_LIST_INVALID:{label}")
    return value


def _parse_utc(value: Any, label: str) -> datetime:
    if (
        not isinstance(value, str)
        or re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z", value)
        is None
    ):
        raise CurrentAuditError(f"CURRENT_AUDIT_TIMESTAMP_INVALID:{label}")
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as error:
        raise CurrentAuditError(f"CURRENT_AUDIT_TIMESTAMP_INVALID:{label}") from error
    if parsed.tzinfo != timezone.utc:
        raise CurrentAuditError(f"CURRENT_AUDIT_TIMESTAMP_INVALID:{label}")
    return parsed


def _require_file_record(
    record: Any, expected_path: str, label: str, *, lines: bool
) -> dict[str, Any]:
    expected_fields = {"path", "sha256", "bytes"} | ({"lines"} if lines else set())
    value = _require_fields(record, expected_fields, label)
    if value.get("path") != expected_path:
        raise CurrentAuditError(f"CURRENT_AUDIT_EVIDENCE_PATH_INVALID:{label}")
    _require_hex(value.get("sha256"), HEX64, f"{label}.sha256")
    if type(value.get("bytes")) is not int or value["bytes"] < 0:
        raise CurrentAuditError(f"CURRENT_AUDIT_EVIDENCE_BYTES_INVALID:{label}")
    if lines and (type(value.get("lines")) is not int or value["lines"] < 0):
        raise CurrentAuditError(f"CURRENT_AUDIT_EVIDENCE_LINES_INVALID:{label}")
    return value


def _require_protocol_file_record(
    record: Any, expected_path: str, label: str, *, lines: bool
) -> dict[str, Any]:
    expected_fields = {
        "path",
        "sha256",
        "bytes",
        "git_mode",
        "git_object_type",
        "git_object_id",
    } | ({"lines"} if lines else set())
    value = _require_fields(record, expected_fields, label)
    if value.get("path") != expected_path:
        raise CurrentAuditError(f"CURRENT_AUDIT_EVIDENCE_PATH_INVALID:{label}")
    _require_hex(value.get("sha256"), HEX64, f"{label}.sha256")
    _require_hex(value.get("git_object_id"), HEX40, f"{label}.git_object_id")
    if (
        type(value.get("bytes")) is not int
        or value["bytes"] < 0
        or value.get("git_object_type") != "blob"
        or value.get("git_mode") not in {"100644", "100755"}
    ):
        raise CurrentAuditError(f"CURRENT_AUDIT_PROTOCOL_FILE_RECORD_INVALID:{label}")
    if lines and (type(value.get("lines")) is not int or value["lines"] < 0):
        raise CurrentAuditError(f"CURRENT_AUDIT_EVIDENCE_LINES_INVALID:{label}")
    return value


def _require_gzip_record(record: Any, expected_path: str, label: str) -> dict[str, Any]:
    value = _require_fields(
        record,
        {
            "path",
            "compressed_sha256",
            "compressed_bytes",
            "uncompressed_sha256",
            "uncompressed_bytes",
            "uncompressed_lines",
        },
        label,
    )
    if value.get("path") != expected_path:
        raise CurrentAuditError(f"CURRENT_AUDIT_EVIDENCE_PATH_INVALID:{label}")
    for field in ("compressed_sha256", "uncompressed_sha256"):
        _require_hex(value.get(field), HEX64, f"{label}.{field}")
    for field in ("compressed_bytes", "uncompressed_bytes", "uncompressed_lines"):
        if type(value.get(field)) is not int or value[field] < 0:
            raise CurrentAuditError(
                f"CURRENT_AUDIT_EVIDENCE_INTEGER_INVALID:{label}.{field}"
            )
    return value


def _require_historical_gzip_record(
    record: Any, expected_path: str, label: str
) -> dict[str, Any]:
    """Validate the immutable BFE record's additional compression provenance."""

    historical = _require_fields(
        record,
        {
            "path",
            "compression_command",
            "compression_tool",
            "compression_exit_status",
            "compressed_sha256",
            "compressed_bytes",
            "uncompressed_sha256",
            "uncompressed_bytes",
            "uncompressed_lines",
        },
        label,
    )
    if (
        historical.get("compression_exit_status") != 0
        or type(historical.get("compression_exit_status")) is not int
        or "gzip -n -9 -c " not in str(historical.get("compression_command"))
        or not str(historical.get("compression_command")).endswith(f"> {expected_path}")
        or not isinstance(historical.get("compression_tool"), str)
        or not historical["compression_tool"].strip()
    ):
        raise CurrentAuditError("CURRENT_AUDIT_HISTORICAL_LOG_PROVENANCE")
    return _require_gzip_record(
        {
            key: historical[key]
            for key in (
                "path",
                "compressed_sha256",
                "compressed_bytes",
                "uncompressed_sha256",
                "uncompressed_bytes",
                "uncompressed_lines",
            )
        },
        expected_path,
        label,
    )


def _gzip_as_file_record(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "path": record.get("path"),
        "sha256": record.get("compressed_sha256"),
        "bytes": record.get("compressed_bytes"),
    }


def _verify_bound_file_record(
    record: dict[str, Any],
    evidence_by_path: dict[str, dict[str, Any]],
    label: str,
    *,
    gzip_record: bool = False,
) -> None:
    normalized = _gzip_as_file_record(record) if gzip_record else record
    path = normalized.get("path")
    if not isinstance(path, str) or path not in evidence_by_path:
        raise CurrentAuditError(f"CURRENT_AUDIT_EVIDENCE_DANGLING:{label}")
    if not _strict_equal(normalized, evidence_by_path[path]):
        raise CurrentAuditError(f"CURRENT_AUDIT_EVIDENCE_BINDING:{label}")


def _parse_git_identity_header(raw: bytes, label: str) -> tuple[str, str, str]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise CurrentAuditError("CURRENT_AUDIT_COMMIT_METADATA_UTF8_INVALID") from error
    match = re.fullmatch(
        r"(.+) <([^<>\x00-\x1f\x7f]+)> (-?\d{1,12}) ([+-])(\d{2})(\d{2})",
        text,
    )
    if match is None:
        raise CurrentAuditError(f"CURRENT_AUDIT_COMMIT_IDENTITY_INVALID:{label}")
    name, email, timestamp_raw, sign, hours_raw, minutes_raw = match.groups()
    hours = int(hours_raw)
    minutes = int(minutes_raw)
    if hours > 23 or minutes > 59:
        raise CurrentAuditError(f"CURRENT_AUDIT_COMMIT_TIME_INVALID:{label}")
    offset = timedelta(hours=hours, minutes=minutes)
    if sign == "-":
        offset = -offset
    try:
        instant = datetime.fromtimestamp(int(timestamp_raw), timezone(offset))
    except (OverflowError, OSError, ValueError) as error:
        raise CurrentAuditError(f"CURRENT_AUDIT_COMMIT_TIME_INVALID:{label}") from error
    return name, email, instant.isoformat()


def _commit_metadata(repo: Path, commit: str) -> dict[str, str]:
    """Parse immutable raw commit-object headers without pretty-format rewrites."""

    commit = _require_hex(commit, HEX40, "commit")
    raw = _git(repo, "cat-file", "commit", commit)
    try:
        header_block, message = raw.split(b"\n\n", 1)
    except ValueError as error:
        raise CurrentAuditError(
            "CURRENT_AUDIT_COMMIT_METADATA_FIELDS_INVALID"
        ) from error
    headers: dict[bytes, list[bytes]] = {}
    active_key: bytes | None = None
    for row in header_block.split(b"\n"):
        if row.startswith(b" "):
            if active_key is None:
                raise CurrentAuditError("CURRENT_AUDIT_COMMIT_METADATA_FIELDS_INVALID")
            headers[active_key][-1] += b"\n" + row
            continue
        try:
            key, value = row.split(b" ", 1)
        except ValueError as error:
            raise CurrentAuditError(
                "CURRENT_AUDIT_COMMIT_METADATA_FIELDS_INVALID"
            ) from error
        if re.fullmatch(rb"[a-z][a-z0-9-]*", key) is None:
            raise CurrentAuditError("CURRENT_AUDIT_COMMIT_METADATA_FIELDS_INVALID")
        headers.setdefault(key, []).append(value)
        active_key = key
    if (
        len(headers.get(b"tree", [])) != 1
        or len(headers.get(b"parent", [])) != 1
        or len(headers.get(b"author", [])) != 1
        or len(headers.get(b"committer", [])) != 1
    ):
        raise CurrentAuditError("CURRENT_AUDIT_COMMIT_METADATA_FIELDS_INVALID")
    try:
        tree = headers[b"tree"][0].decode("ascii")
        parent = headers[b"parent"][0].decode("ascii")
        subject = message.split(b"\n", 1)[0].decode("utf-8")
    except UnicodeDecodeError as error:
        raise CurrentAuditError("CURRENT_AUDIT_COMMIT_METADATA_UTF8_INVALID") from error
    _require_hex(tree, HEX40, "commit.tree")
    _require_hex(parent, HEX40, "commit.parent")
    author_name, author_email, authored_at = _parse_git_identity_header(
        headers[b"author"][0], "author"
    )
    committer_name, committer_email, committed_at = _parse_git_identity_header(
        headers[b"committer"][0], "committer"
    )
    return {
        "commit": commit,
        "tree": tree,
        "parent": parent,
        "author_name": author_name,
        "author_email": author_email,
        "authored_at": authored_at,
        "committer_name": committer_name,
        "committer_email": committer_email,
        "committed_at": committed_at,
        "subject": subject,
    }


def _commit_datetime(repo: Path, commit: str) -> datetime:
    raw = _commit_metadata(repo, commit)["committed_at"]
    try:
        value = datetime.fromisoformat(raw)
    except ValueError as error:
        raise CurrentAuditError("CURRENT_AUDIT_COMMIT_TIME_INVALID") from error
    if value.tzinfo is None:
        raise CurrentAuditError("CURRENT_AUDIT_COMMIT_TIME_INVALID")
    return value.astimezone(timezone.utc)


def _changed_path_statuses(repo: Path, older: str, newer: str) -> dict[str, str]:
    raw = _git(
        repo,
        "-c",
        "diff.algorithm=myers",
        "diff",
        "--no-ext-diff",
        "--no-textconv",
        "--no-renames",
        "--no-color",
        "--name-status",
        "-z",
        f"{older}..{newer}",
    )
    if raw and not raw.endswith(b"\0"):
        raise CurrentAuditError("CURRENT_AUDIT_DIFF_PATHS_INVALID")
    fields = raw.removesuffix(b"\0").split(b"\0") if raw else []
    if len(fields) % 2:
        raise CurrentAuditError("CURRENT_AUDIT_DIFF_PATHS_INVALID")
    rows: list[tuple[str, str]] = []
    try:
        for index in range(0, len(fields), 2):
            status = fields[index].decode("ascii")
            path = fields[index + 1].decode("utf-8")
            if status not in {"A", "M", "D", "T"}:
                raise CurrentAuditError("CURRENT_AUDIT_DIFF_PATHS_INVALID")
            rows.append((status, _require_canonical_repo_path(path, "diff.path")))
    except UnicodeDecodeError as error:
        raise CurrentAuditError("CURRENT_AUDIT_DIFF_PATHS_UTF8_INVALID") from error
    paths = [row[1] for row in rows]
    if len(paths) != len(set(paths)):
        raise CurrentAuditError("CURRENT_AUDIT_DIFF_PATHS_DUPLICATE")
    return {row[1]: row[0] for row in rows}


def _changed_paths(repo: Path, older: str, newer: str) -> list[str]:
    return list(_changed_path_statuses(repo, older, newer))


def _signature_binding() -> dict[str, Any]:
    return {
        "format": "ssh",
        "status": "verified",
        "principal": "sepmhn@gmail.com",
        "key_fingerprint": SOURCE_SIGNATURE["key_fingerprint"],
        "allowed_signers_path": "release/0.9.0/allowed-signers",
        "allowed_signers_sha256": EXPECTED_SOURCE_FILES[
            "release/0.9.0/allowed-signers"
        ],
    }


def _signed_commit_binding(repo: Path, commit: str, parent: str) -> dict[str, Any]:
    """Build the deterministic record a signed governance artifact must carry."""

    metadata = _commit_metadata(repo, commit)
    if metadata["parent"] != parent:
        raise CurrentAuditError("CURRENT_AUDIT_COMMIT_BINDING_PARENT_INVALID")
    patch_arguments = (
        "-c",
        "diff.algorithm=myers",
        "diff",
        "--no-ext-diff",
        "--no-textconv",
        "--no-renames",
        "--no-color",
        "--src-prefix=a/",
        "--dst-prefix=b/",
        "--binary",
        "--full-index",
        f"{parent}..{commit}",
    )
    patch = _git(repo, *patch_arguments)
    name_status = _git(
        repo,
        "-c",
        "diff.algorithm=myers",
        "diff",
        "--no-ext-diff",
        "--no-textconv",
        "--no-renames",
        "--no-color",
        "--name-status",
        f"{parent}..{commit}",
    )
    numstat = _git(
        repo,
        "-c",
        "diff.algorithm=myers",
        "diff",
        "--no-ext-diff",
        "--no-textconv",
        "--no-renames",
        "--no-color",
        "--numstat",
        f"{parent}..{commit}",
    )
    statuses = _changed_path_statuses(repo, parent, commit)
    return {
        **metadata,
        "signature": _signature_binding(),
        "diff": {
            "base": parent,
            "path_statuses": statuses,
            "patch_command": "git " + " ".join(patch_arguments),
            "patch_sha256": _sha256(patch),
            "patch_bytes": len(patch),
            "patch_lines": len(patch.splitlines()),
            "name_status_sha256": _sha256(name_status),
            "numstat_sha256": _sha256(numstat),
        },
        "changed_files": [
            {
                "status": status,
                **_commit_file_record(repo, commit, path),
            }
            for path, status in statuses.items()
        ],
    }


def _verify_named_commit_signature(repo: Path, commit: str, label: str) -> None:
    _verify_trusted_executable(GIT_EXECUTABLE, "git")
    _verify_trusted_executable(SSH_KEYGEN_EXECUTABLE, "ssh-keygen")
    _require_hex(commit, HEX40, f"{label}.commit")
    allowed_signers = _git_file(repo, SOURCE_COMMIT, "release/0.9.0/allowed-signers")
    if (
        _sha256(allowed_signers)
        != EXPECTED_SOURCE_FILES["release/0.9.0/allowed-signers"]
    ):
        raise CurrentAuditError(f"CURRENT_AUDIT_{label}_SIGNERS_MISMATCH")
    try:
        with tempfile.NamedTemporaryFile() as handle:
            handle.write(allowed_signers)
            handle.flush()
            returncode, stdout, stderr = _run_bounded(
                _git_command(
                    "-c",
                    f"gpg.ssh.allowedSignersFile={handle.name}",
                    "-c",
                    f"gpg.ssh.program={SSH_KEYGEN_EXECUTABLE}",
                    "-c",
                    f"gpg.ssh.revocationFile={os.devnull}",
                    "-c",
                    "gpg.format=ssh",
                    "verify-commit",
                    commit,
                ),
                cwd=repo,
                env=_sanitized_git_environment(),
                timeout_seconds=30,
                stdout_limit=MAX_GIT_BYTES,
                stderr_limit=MAX_GIT_BYTES,
                error_prefix=f"CURRENT_AUDIT_{label}_SIGNATURE_CHECK",
            )
    except CurrentAuditError:
        raise
    except OSError as error:
        raise CurrentAuditError(f"CURRENT_AUDIT_{label}_SIGNATURE_IO_FAILED") from error
    expected = (
        b'Good "git" signature for sepmhn@gmail.com with ED25519 key '
        b"SHA256:3gaatfl4IVnuBX4D60Jxw9oVIrvEE1ZphK8IuEyrfPU"
    )
    if returncode != 0 or (stdout + stderr).strip() != expected:
        raise CurrentAuditError(f"CURRENT_AUDIT_{label}_SIGNATURE_INVALID")


def _verify_framework_history(repo: Path) -> tuple[str, str, list[str]]:
    try:
        head = _git(repo, "rev-parse", "HEAD").decode("ascii").strip()
        chain = (
            _git(
                repo,
                "rev-list",
                "--first-parent",
                "--reverse",
                f"{IMPLEMENTATION_COMMIT}..{head}",
            )
            .decode("ascii")
            .splitlines()
        )
    except UnicodeDecodeError as error:
        raise CurrentAuditError(
            "CURRENT_AUDIT_FRAMEWORK_HISTORY_UTF8_INVALID"
        ) from error
    _require_hex(head, HEX40, "framework.head")
    if not chain or any(HEX40.fullmatch(item) is None for item in chain):
        raise CurrentAuditError("CURRENT_AUDIT_FRAMEWORK_HISTORY_INVALID")
    framework_commit = chain[0]
    metadata = _commit_metadata(repo, framework_commit)
    if (
        metadata["parent"] != IMPLEMENTATION_COMMIT
        or metadata["author_name"] != "Sepehr Mahmoudian"
        or metadata["author_email"] != "sepmhn@gmail.com"
        or metadata["committer_name"] != "Sepehr Mahmoudian"
        or metadata["committer_email"] != "sepmhn@gmail.com"
        or not metadata["subject"].startswith("release: ")
    ):
        raise CurrentAuditError("CURRENT_AUDIT_FRAMEWORK_COMMIT_IDENTITY_INVALID")
    _verify_named_commit_signature(repo, framework_commit, "FRAMEWORK")
    changed_statuses = _changed_path_statuses(
        repo, IMPLEMENTATION_COMMIT, framework_commit
    )
    if not _strict_equal(changed_statuses, FRAMEWORK_PATH_STATUSES):
        raise CurrentAuditError("CURRENT_AUDIT_FRAMEWORK_DIFF_SCOPE_INVALID")
    if _git_file(
        repo, framework_commit, EXPECTED_REQUIREMENTS_LEDGER["path"]
    ) != _git_file(repo, IMPLEMENTATION_COMMIT, EXPECTED_REQUIREMENTS_LEDGER["path"]):
        raise CurrentAuditError("CURRENT_AUDIT_FRAMEWORK_REQUIREMENTS_MUTATED")
    for path in FINAL_FRAMEWORK_PATHS:
        _git_file(repo, framework_commit, path)
    if not _strict_equal(
        _commit_file_record(
            repo,
            framework_commit,
            QUALIFICATION_AMENDMENT_RECORD["path"],
        ),
        QUALIFICATION_AMENDMENT_RECORD,
    ):
        raise CurrentAuditError("CURRENT_AUDIT_FRAMEWORK_AMENDMENT_MISMATCH")
    frozen_paths = (
        FRAMEWORK_STAGE_FROZEN_PATHS if len(chain) <= 3 else FRAMEWORK_CORE_FROZEN_PATHS
    )
    for path in frozen_paths:
        if _git_file(repo, head, path) != _git_file(repo, framework_commit, path):
            raise CurrentAuditError(f"CURRENT_AUDIT_FRAMEWORK_CODE_DRIFT:{path}")
        worktree_payload = _read_repo_relative_bounded(
            repo, path, MAX_GIT_BYTES, f"framework.worktree.{path}"
        )
        if worktree_payload != _git_file(repo, framework_commit, path):
            raise CurrentAuditError(f"CURRENT_AUDIT_FRAMEWORK_WORKTREE_DRIFT:{path}")
    _verify_post_activation_gate_retention(repo, head)
    _verify_cited_test_ids(repo, framework_commit)
    return head, framework_commit, chain


def _select_qualification_stage(
    *,
    requirement_state: str,
    chain_length: int,
    qualification_present: bool,
    activation_present: bool,
) -> str:
    """Select the only valid B, C, or D state without trusting file prose."""

    state = (
        requirement_state,
        chain_length,
        qualification_present,
        activation_present,
    )
    if state == ("OPEN", 1, False, False):
        return "FRAMEWORK_PENDING_QUALIFICATION"
    if state == ("OPEN", 2, True, False):
        return "QUALIFIED_OPEN"
    if state == ("TERMINAL_PENDING_ACTIVATION_VALIDATION", 3, True, True):
        return "TERMINAL_ACTIVATION"
    if (
        requirement_state == "TERMINAL_PENDING_ACTIVATION_VALIDATION"
        and chain_length > 3
        and qualification_present
        and activation_present
    ):
        return "POST_ACTIVATION"
    if (
        requirement_state == "OPEN"
        and chain_length > 3
        and qualification_present
        and activation_present
    ):
        return "REVOKED_OPEN"
    raise CurrentAuditError("CURRENT_AUDIT_QUALIFICATION_STAGE_INVALID")


def _verify_data_only_commit(
    repo: Path,
    *,
    commit: str,
    parent: str,
    expected_statuses: dict[str, str],
    label: str,
) -> dict[str, str]:
    metadata = _commit_metadata(repo, commit)
    if (
        metadata["parent"] != parent
        or metadata["author_name"] != "Sepehr Mahmoudian"
        or metadata["author_email"] != "sepmhn@gmail.com"
        or metadata["committer_name"] != "Sepehr Mahmoudian"
        or metadata["committer_email"] != "sepmhn@gmail.com"
        or not metadata["subject"].startswith("release: ")
    ):
        raise CurrentAuditError(f"CURRENT_AUDIT_{label}_COMMIT_IDENTITY_INVALID")
    _verify_named_commit_signature(repo, commit, label)
    if not _strict_equal(
        _changed_path_statuses(repo, parent, commit), expected_statuses
    ):
        raise CurrentAuditError(f"CURRENT_AUDIT_{label}_DATA_ONLY_DIFF_INVALID")
    for path, status in expected_statuses.items():
        if status != "D":
            _git_file(repo, commit, path)
    return metadata


def _catalog_layout(framework_commit: str) -> dict[str, dict[str, Any]]:
    """Return the closed E/Q catalog layout for the signed C packet."""

    return {
        "CH-T000-E01": {
            "kind": "SIGNED_INPUT_FREEZE_IMPLEMENTATION",
            "subject_commit": IMPLEMENTATION_COMMIT,
            "paths": [],
        },
        "CH-T000-E02": {
            "kind": "FROZEN_INPUT_MANIFEST_AND_BOOTSTRAP_LEDGER",
            "subject_commit": IMPLEMENTATION_COMMIT,
            "paths": [
                "release/0.9.0/current-head/audit-inputs.json",
                "release/0.9.0/current-head/requirements.json",
            ],
        },
        "CH-T000-E03": {
            "kind": "EXACT_LOCAL_P0R_GATE",
            "subject_commit": IMPLEMENTATION_COMMIT,
            "paths": list(QUALIFICATION_EVIDENCE_PATHS[0:2]),
        },
        "CH-T000-E04": {
            "kind": "INDEPENDENT_CLEAN_LINUX_REPRODUCTION_AND_REVIEW",
            "subject_commit": IMPLEMENTATION_COMMIT,
            "paths": [*QUALIFICATION_EVIDENCE_PATHS[2:4], R02_BFE_REVIEW_PATH],
        },
        "CH-T000-E05": {
            "kind": "EXACT_GITHUB_CI_RUN",
            "subject_commit": IMPLEMENTATION_COMMIT,
            "paths": list(QUALIFICATION_EVIDENCE_PATHS[4:7]),
        },
        "CH-T000-E06": {
            "kind": "EXACT_GITHUB_FORMAL_RUN",
            "subject_commit": IMPLEMENTATION_COMMIT,
            "paths": list(QUALIFICATION_EVIDENCE_PATHS[7:10]),
        },
        "CH-T000-Q01": {
            "kind": "SIGNED_QUALIFICATION_FRAMEWORK_COMMIT",
            "subject_commit": framework_commit,
            "paths": [],
        },
        "CH-T000-Q02": {
            "kind": "EXACT_FRAMEWORK_LOCAL_P0R_GATE",
            "subject_commit": framework_commit,
            "paths": list(FRAMEWORK_EVIDENCE_PATHS[0:2]),
        },
        "CH-T000-Q03": {
            "kind": "INDEPENDENT_FRAMEWORK_CLEAN_LINUX_REPRODUCTION",
            "subject_commit": framework_commit,
            "paths": [
                FRAMEWORK_EVIDENCE_PATHS[2],
                FRAMEWORK_CLEAN_LINUX_ATTEMPT_PATH,
                FRAMEWORK_EVIDENCE_PATHS[3],
            ],
        },
        "CH-T000-Q04": {
            "kind": "EXACT_FRAMEWORK_GITHUB_CI_RUN",
            "subject_commit": framework_commit,
            "paths": list(FRAMEWORK_EVIDENCE_PATHS[4:7]),
        },
        "CH-T000-Q05": {
            "kind": "EXACT_FRAMEWORK_GITHUB_FORMAL_RUN",
            "subject_commit": framework_commit,
            "paths": list(FRAMEWORK_EVIDENCE_PATHS[7:10]),
        },
        "CH-T000-Q06": {
            "kind": "BOUNDED_VERIFIER_RESOURCE_PROFILE",
            "subject_commit": framework_commit,
            "paths": [FRAMEWORK_EVIDENCE_PATHS[10]],
        },
        "CH-T000-Q07": {
            "kind": "R01_EXACT_FRAMEWORK_AUDIT",
            "subject_commit": framework_commit,
            "paths": [FRAMEWORK_EVIDENCE_PATHS[11]],
        },
        "CH-T000-Q08": {
            "kind": "R02_INDEPENDENT_FRAMEWORK_AUDIT",
            "subject_commit": framework_commit,
            "paths": [FRAMEWORK_EVIDENCE_PATHS[12]],
        },
    }


def ch_t000_review_fixed_template(framework_commit: str) -> dict[str, Any]:
    """Expose the exact non-evidence portion used to author the signed C review."""

    return {
        "schema_version": "2.0.0",
        "record_id": "CH-T000-TECHNICAL-QUALIFICATION-REVIEW",
        "task_id": "CH-T000",
        "source_task_id": "T000",
        "release_target": "0.9.0",
        "author": {"name": "Sepehr Mahmoudian", "email": "sepmhn@gmail.com"},
        "persistent_identifier": None,
        "review_started_at_utc": None,
        "review_completed_at_utc": None,
        "review_classification": "AUTOMATED_TECHNICAL_SUPPORT_ONLY",
        "scope": QUALIFICATION_SCOPE,
        "effective_only_when": QUALIFICATION_EFFECTIVE_CONDITION,
        "reviewed_commits": {
            "approved_source_cut": SOURCE_COMMIT,
            "input_freeze_implementation": IMPLEMENTATION_COMMIT,
            "qualification_framework": framework_commit,
        },
        "process_deviation": {
            "classification": "RETROSPECTIVE_CH_T000_BOOTSTRAP_AMENDMENT",
            "pre_edit_behavior_packet_existed": False,
            "pre_edit_normative_approval_existed": False,
            "complete_file_review_ledger_existed": False,
            "resolution": "AMENDED_NOT_SATISFIED",
            "amendment_path": "release/0.9.0/current-head/HANDOFF-ERRATA-QUALIFICATION-AMENDMENT.md",
            "scope": "CH_T000_ONLY_NO_TRANSFER_TO_LATER_TASKS",
            "residual_limitation": "RETROSPECTIVE_RECONSTRUCTION_DOES_NOT_PROVE_PRE_EDIT_KNOWLEDGE",
        },
        "current_behavior": {
            "input_identity": "EXACT_SOURCE_HANDOFF_HEADS_PACKAGES_TOOLCHAINS_AND_PUBLICATION_STATE_ARE_FROZEN_BY_SIGNED_GIT_OBJECTS",
            "validation": "OFFLINE_FAIL_CLOSED_TYPED_VALIDATION_WITH_EXPLICIT_RESOURCE_LIMITS",
            "state_transition": "CH_T000_REMAINS_OPEN_UNTIL_SEPARATE_SIGNED_DATA_ONLY_ACTIVATION",
            "failure_behavior": "ANY_IDENTITY_SCHEMA_PROVENANCE_RESOURCE_OR_GOVERNANCE_MISMATCH_REJECTS",
            "public_claims": "NO_PUBLIC_CLAIM_CHANGE_RELEASE_REMAINS_NO_GO",
        },
        "normative_controls": ch_t000_normative_controls(),
        "mandatory_counterfactuals": ch_t000_counterfactuals(),
        "lead_approval": {
            "approver_id": "CH-T000-R03",
            "kind": "AUTOMATED_LEAD_AGENT",
            "human": False,
            "named_human_approver": False,
            "decision": "APPROVE_EXACT_N01_N06_AND_COUNTERFACTUALS_FOR_TECHNICAL_QUALIFICATION_ONLY",
            "controls_and_cases_sha256": ch_t000_control_digest(),
            "approval_effective_on": LEAD_APPROVAL_EFFECTIVE_ON,
        },
        "reviewers": [
            {
                "id": "CH-T000-R01",
                "kind": "AUTOMATED_PRIMARY_FRAMEWORK_REVIEWER",
                "human": False,
                "named_human_approver": False,
                "report_path": FRAMEWORK_EVIDENCE_PATHS[11],
            },
            {
                "id": "CH-T000-R02",
                "kind": "AUTOMATED_INDEPENDENT_ADVERSARIAL_REVIEWER",
                "human": False,
                "named_human_approver": False,
                "report_paths": [R02_BFE_REVIEW_PATH, FRAMEWORK_EVIDENCE_PATHS[12]],
            },
            {
                "id": "CH-T000-R03",
                "kind": "AUTOMATED_LEAD_AGENT",
                "human": False,
                "named_human_approver": False,
                "report_path": REVIEW_PATH,
            },
        ],
        "human_review_boundary": HUMAN_REVIEW_BOUNDARY,
        "release_authority_boundary": RELEASE_AUTHORITY_BOUNDARY,
        "review_limitations": [
            "AUTOMATED_REVIEW_IS_NOT_INDEPENDENT_OR_NAMED_HUMAN_REVIEW",
            "RETAINED_RUN_OUTPUT_IS_NOT_REMOTE_PLATFORM_ATTESTATION",
            "RESOURCE_PROFILE_ESTABLISHES_DECLARED_BOUNDARY_BEHAVIOR_NOT_GLOBAL_PERFORMANCE",
            "TECHNICAL_INPUT_FREEZE_QUALIFICATION_DOES_NOT_ESTABLISH_RUNTIME_PRODUCT_CORRECTNESS",
            "NO_TAG_RELEASE_DOI_ZENODO_DEPLOYMENT_PUBLICATION_OR_SECURITY_CERTIFICATION_IS_GRANTED",
        ],
        "finding_dispositions": ch_t000_c_finding_dispositions(),
        "twenty_lens_reviews": ch_t000_lens_reviews(),
        "task_disposition": "C_EVIDENCE_COMPLETE_ACTIVATION_BLOCKERS_DEFERRED",
        "claim_disposition": "NO_PUBLIC_CLAIM_CHANGE",
        "overall_release_status": "NO_GO",
    }


def ch_t000_initial_residual_limitations() -> list[str]:
    """Return the complete CH-T000 risk union that every successor must carry."""

    review = ch_t000_review_fixed_template(SOURCE_COMMIT)
    return sorted(
        {
            review["process_deviation"]["residual_limitation"],
            *review["review_limitations"],
            *(
                lens["residual_limitation"]
                for lens in review["twenty_lens_reviews"].values()
            ),
        }
    )


def _verify_capture_operations(
    value: Any,
    *,
    run_id: int,
    workflow: str,
    paths: tuple[str, str, str],
    head: str,
    label: str,
    not_before: datetime,
    retained_by: datetime,
) -> None:
    operations = _require_fields(
        value,
        {"ordinary_metadata", "attempt_metadata", "raw_log"},
        f"{label}.capture_operations",
    )
    json_fields = (
        "conclusion,createdAt,databaseId,event,headBranch,headSha,jobs,status,"
        "updatedAt,url,workflowName"
    )
    attempt_fields = (
        "attempt,conclusion,createdAt,databaseId,event,headBranch,headSha,jobs,"
        "startedAt,status,updatedAt,url,workflowDatabaseId,workflowName"
    )
    ordinary = _require_fields(
        operations.get("ordinary_metadata"),
        {
            "raw_path",
            "normalized_path",
            "retained_path",
            "capture_command",
            "capture_exit_status",
            "normalize_command",
            "normalize_exit_status",
            "compare_command",
            "compare_exit_status",
            "byte_equal",
            "started_at_utc",
            "completed_at_utc",
        },
        f"{label}.ordinary_metadata",
    )
    attempt = _require_fields(
        operations.get("attempt_metadata"),
        {
            "raw_path",
            "retained_path",
            "capture_command",
            "capture_exit_status",
            "retain_command",
            "retain_exit_status",
            "compare_command",
            "compare_exit_status",
            "byte_equal",
            "started_at_utc",
            "completed_at_utc",
        },
        f"{label}.attempt_metadata",
    )
    log = _require_fields(
        operations.get("raw_log"),
        {
            "raw_path",
            "retained_path",
            "decompressed_path",
            "capture_command",
            "capture_exit_status",
            "compression_command",
            "compression_exit_status",
            "decompress_command",
            "decompress_exit_status",
            "compare_command",
            "compare_exit_status",
            "byte_equal",
            "started_at_utc",
            "completed_at_utc",
        },
        f"{label}.raw_log",
    )
    all_temp_paths = [
        ordinary.get("raw_path"),
        ordinary.get("normalized_path"),
        attempt.get("raw_path"),
        log.get("raw_path"),
        log.get("decompressed_path"),
    ]
    for raw_path in all_temp_paths:
        parsed = PurePosixPath(raw_path) if isinstance(raw_path, str) else None
        if (
            parsed is None
            or raw_path != parsed.as_posix()
            or parsed.parent != PurePosixPath("/private/tmp")
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", parsed.name) is None
        ):
            raise CurrentAuditError(f"CURRENT_AUDIT_CAPTURE_PATH_INVALID:{label}")
    expected_temp_paths = [
        f"/private/tmp/{PurePosixPath(paths[0]).name}.raw",
        f"/private/tmp/{PurePosixPath(paths[0]).name}.normalized",
        f"/private/tmp/{PurePosixPath(paths[1]).name}.raw",
        f"/private/tmp/{PurePosixPath(paths[2]).name}.raw",
        f"/private/tmp/{PurePosixPath(paths[2]).name}.decompressed",
    ]
    if all_temp_paths != expected_temp_paths or len(all_temp_paths) != len(
        set(all_temp_paths)
    ):
        raise CurrentAuditError(f"CURRENT_AUDIT_CAPTURE_PATH_DUPLICATE:{label}")
    if (
        ordinary.get("retained_path") != paths[0]
        or attempt.get("retained_path") != paths[1]
        or log.get("retained_path") != paths[2]
        or ordinary.get("capture_command")
        != f"gh run view {run_id} --repo sepahead/haldir --json {json_fields} > {ordinary['raw_path']}"
        or ordinary.get("normalize_command")
        != f"jq . {ordinary['raw_path']} > {ordinary['normalized_path']}"
        or ordinary.get("compare_command")
        != f"cmp {ordinary['normalized_path']} {paths[0]}"
        or attempt.get("capture_command")
        != f"gh run view {run_id} --repo sepahead/haldir --attempt 1 --json {attempt_fields} > {attempt['raw_path']}"
        or attempt.get("retain_command") != f"cp {attempt['raw_path']} {paths[1]}"
        or attempt.get("compare_command") != f"cmp {attempt['raw_path']} {paths[1]}"
        or log.get("capture_command")
        != f"gh run view {run_id} --repo sepahead/haldir --attempt 1 --log > {log['raw_path']}"
        or log.get("compression_command")
        != f"gzip -n -9 -c {log['raw_path']} > {paths[2]}"
        or log.get("decompress_command")
        != f"gzip -cd {paths[2]} > {log['decompressed_path']}"
        or log.get("compare_command")
        != f"cmp {log['raw_path']} {log['decompressed_path']}"
    ):
        raise CurrentAuditError(f"CURRENT_AUDIT_CAPTURE_COMMAND_INVALID:{label}")
    status_fields = (
        (ordinary, "capture_exit_status"),
        (ordinary, "normalize_exit_status"),
        (ordinary, "compare_exit_status"),
        (attempt, "capture_exit_status"),
        (attempt, "retain_exit_status"),
        (attempt, "compare_exit_status"),
        (log, "capture_exit_status"),
        (log, "compression_exit_status"),
        (log, "decompress_exit_status"),
        (log, "compare_exit_status"),
    )
    if any(
        type(record.get(field)) is not int or record[field] != 0
        for record, field in status_fields
    ):
        raise CurrentAuditError(f"CURRENT_AUDIT_CAPTURE_EXIT_INVALID:{label}")
    if any(record.get("byte_equal") is not True for record in (ordinary, attempt, log)):
        raise CurrentAuditError(f"CURRENT_AUDIT_CAPTURE_COMPARISON_INVALID:{label}")
    observed_times: list[datetime] = []
    for operation_name, operation in (
        ("ordinary_metadata", ordinary),
        ("attempt_metadata", attempt),
        ("raw_log", log),
    ):
        started = _parse_utc(
            operation.get("started_at_utc"), f"{label}.{operation_name}.started"
        )
        completed = _parse_utc(
            operation.get("completed_at_utc"), f"{label}.{operation_name}.completed"
        )
        if started > completed:
            raise CurrentAuditError(f"CURRENT_AUDIT_CAPTURE_TIME_INVALID:{label}")
        observed_times.extend((started, completed))
    if any(
        observed_times[index] > observed_times[index + 1]
        for index in range(len(observed_times) - 1)
    ):
        raise CurrentAuditError(f"CURRENT_AUDIT_CAPTURE_TIME_ORDER_INVALID:{label}")
    if observed_times[0] < not_before:
        raise CurrentAuditError(f"CURRENT_AUDIT_CAPTURE_BEFORE_RUN_COMPLETE:{label}")
    if observed_times[-1] > retained_by:
        raise CurrentAuditError(f"CURRENT_AUDIT_CAPTURE_AFTER_RETENTION:{label}")
    if head == IMPLEMENTATION_COMMIT:
        bounds = {
            "ci": ("2026-07-14T16:35:02Z", "2026-07-14T16:35:12Z"),
            "formal": ("2026-07-14T16:35:12Z", "2026-07-14T16:35:18Z"),
        }[workflow]
        lower = _parse_utc(bounds[0], f"{label}.recapture.lower")
        upper = _parse_utc(bounds[1], f"{label}.recapture.upper")
        if any(value < lower or value > upper for value in observed_times):
            raise CurrentAuditError(f"CURRENT_AUDIT_CAPTURE_WINDOW_INVALID:{label}")


def _verify_nested_jobs(
    raw: dict[str, Any], label: str, *, lower: datetime, upper: datetime
) -> None:
    jobs = raw.get("jobs")
    if not isinstance(jobs, list) or not jobs:
        raise CurrentAuditError(f"CURRENT_AUDIT_HOSTED_JOBS_INVALID:{label}")
    job_ids: list[int] = []
    for job in jobs:
        if (
            not isinstance(job, dict)
            or set(job)
            != {
                "completedAt",
                "conclusion",
                "databaseId",
                "name",
                "startedAt",
                "status",
                "steps",
                "url",
            }
            or type(job.get("databaseId")) is not int
            or job["databaseId"] <= 0
            or job.get("status") != "completed"
            or job.get("conclusion") != "success"
            or not isinstance(job.get("name"), str)
            or not job["name"].strip()
            or not isinstance(job.get("steps"), list)
            or not job["steps"]
        ):
            raise CurrentAuditError(f"CURRENT_AUDIT_HOSTED_JOB_FAILED:{label}")
        job_started = _parse_utc(job.get("startedAt"), f"{label}.job.started")
        job_completed = _parse_utc(job.get("completedAt"), f"{label}.job.completed")
        if job_started > job_completed or job_started < lower or job_completed > upper:
            raise CurrentAuditError(f"CURRENT_AUDIT_HOSTED_JOB_TIME:{label}")
        step_numbers: list[int] = []
        for step in job["steps"]:
            if (
                not isinstance(step, dict)
                or set(step)
                != {
                    "completedAt",
                    "conclusion",
                    "name",
                    "number",
                    "startedAt",
                    "status",
                }
                or step.get("status") != "completed"
                or step.get("conclusion") != "success"
                or type(step.get("number")) is not int
                or step["number"] <= 0
                or not isinstance(step.get("name"), str)
                or not step["name"].strip()
            ):
                raise CurrentAuditError(f"CURRENT_AUDIT_HOSTED_STEP_FAILED:{label}")
            step_started = _parse_utc(step.get("startedAt"), f"{label}.step.started")
            step_completed = _parse_utc(
                step.get("completedAt"), f"{label}.step.completed"
            )
            if (
                step_started > step_completed
                or step_started < job_started
                or step_completed > job_completed
            ):
                raise CurrentAuditError(f"CURRENT_AUDIT_HOSTED_STEP_TIME:{label}")
            step_numbers.append(step["number"])
        if len(step_numbers) != len(set(step_numbers)) or step_numbers != sorted(
            step_numbers
        ):
            raise CurrentAuditError(f"CURRENT_AUDIT_HOSTED_STEP_DUPLICATE:{label}")
        job_ids.append(job["databaseId"])
    if len(job_ids) != len(set(job_ids)):
        raise CurrentAuditError(f"CURRENT_AUDIT_HOSTED_JOB_DUPLICATE:{label}")


def _hosted_ci_job_names_are_complete(job_names: list[str]) -> bool:
    """Treat hosted API job order as non-semantic while rejecting loss or reuse."""

    return len(job_names) == 6 and set(job_names) == {
        "supply-chain",
        "feature-matrix",
        "interop",
        "clean-build",
        "build-test",
        "macos-compile",
    }


def _hosted_step_log_lines(log: bytes, job_name: str, step_name: str) -> bytes:
    """Return only raw GitHub log lines attributed to one exact job step."""

    prefix = f"{job_name}\t{step_name}\t".encode("utf-8")
    return b"\n".join(line for line in log.splitlines() if line.startswith(prefix))


def _verify_hosted_evidence_v2(
    repo: Path,
    commit: str,
    entry: dict[str, Any],
    *,
    expected_head: str,
    workflow: str,
    label: str,
    expected_event: str = "push",
) -> None:
    files = entry["files"]
    if len(files) != 3:
        raise CurrentAuditError(f"CURRENT_AUDIT_HOSTED_FILE_COUNT:{label}")
    metadata_payload = _read_commit_file_bound(
        repo, commit, files[0], f"{label}.metadata", MAX_JSON_BYTES
    )
    attempt_payload = _read_commit_file_bound(
        repo, commit, files[1], f"{label}.attempt", MAX_JSON_BYTES
    )
    compressed = _read_commit_file_bound(
        repo, commit, files[2], f"{label}.log", MAX_COMPRESSED_LOG_BYTES
    )
    metadata = _load_json_bytes(metadata_payload, f"{label}.metadata")
    attempt = _load_json_bytes(attempt_payload, f"{label}.attempt")
    common_fields = {
        "conclusion",
        "createdAt",
        "databaseId",
        "event",
        "headBranch",
        "headSha",
        "jobs",
        "status",
        "updatedAt",
        "url",
        "workflowName",
    }
    if set(metadata) != common_fields or set(attempt) != common_fields | {
        "attempt",
        "startedAt",
        "workflowDatabaseId",
    }:
        raise CurrentAuditError(f"CURRENT_AUDIT_HOSTED_FIELDS_INVALID:{label}")
    run_id = metadata.get("databaseId")
    if (
        type(run_id) is not int
        or run_id <= 0
        or attempt.get("attempt") != 1
        or type(attempt.get("attempt")) is not int
        or metadata.get("headSha") != expected_head
        or metadata.get("headBranch") != "main"
        or metadata.get("event") != expected_event
        or metadata.get("status") != "completed"
        or metadata.get("conclusion") != "success"
        or metadata.get("workflowName") != workflow
        or attempt.get("workflowDatabaseId")
        != EXPECTED_IMPLEMENTATION_RUNS[workflow]["workflow_id"]
        or type(attempt.get("workflowDatabaseId")) is not int
        or metadata.get("url")
        != f"https://github.com/sepahead/haldir/actions/runs/{run_id}"
    ):
        raise CurrentAuditError(f"CURRENT_AUDIT_HOSTED_IDENTITY_INVALID:{label}")
    for field in common_fields - {"jobs", "updatedAt", "url"}:
        if not _strict_equal(attempt.get(field), metadata.get(field)):
            raise CurrentAuditError(f"CURRENT_AUDIT_HOSTED_ATTEMPT_MISMATCH:{label}")
    if attempt.get("url") != (
        f"https://github.com/sepahead/haldir/actions/runs/{run_id}/attempts/1"
    ):
        raise CurrentAuditError(f"CURRENT_AUDIT_HOSTED_ATTEMPT_URL:{label}")
    created = _parse_utc(metadata.get("createdAt"), f"{label}.created")
    updated = _parse_utc(metadata.get("updatedAt"), f"{label}.updated")
    attempt_started = _parse_utc(attempt.get("startedAt"), f"{label}.attempt.started")
    attempt_updated = _parse_utc(attempt.get("updatedAt"), f"{label}.attempt.updated")
    if not (
        _commit_datetime(repo, expected_head)
        <= created
        <= attempt_started
        <= updated
        <= attempt_updated
        <= _commit_datetime(repo, commit)
    ):
        raise CurrentAuditError(f"CURRENT_AUDIT_HOSTED_ATTEMPT_STARTED:{label}")
    _verify_nested_jobs(metadata, label, lower=created, upper=updated)
    _verify_nested_jobs(
        attempt, f"{label}.attempt", lower=attempt_started, upper=attempt_updated
    )
    if not _strict_equal(metadata["jobs"], attempt["jobs"]):
        raise CurrentAuditError(f"CURRENT_AUDIT_HOSTED_ATTEMPT_JOBS:{label}")
    if expected_head == IMPLEMENTATION_COMMIT:
        expected = EXPECTED_IMPLEMENTATION_RUNS[workflow]
        if (
            run_id != expected["run_id"]
            or metadata["createdAt"] != expected["created_at"]
            or metadata["updatedAt"] != expected["updated_at"]
            or attempt["updatedAt"] != expected["attempt_updated_at"]
            or [job["databaseId"] for job in metadata["jobs"]] != expected["job_ids"]
            or [job["name"] for job in metadata["jobs"]] != expected["jobs"]
        ):
            raise CurrentAuditError(f"CURRENT_AUDIT_HOSTED_BFE_MISMATCH:{label}")
    elif workflow == "formal" and [job["name"] for job in metadata["jobs"]] != [
        "tlc-model-check"
    ]:
        raise CurrentAuditError(f"CURRENT_AUDIT_HOSTED_FORMAL_JOBS:{label}")
    elif workflow == "ci":
        job_names = [job["name"] for job in metadata["jobs"]]
        if not _hosted_ci_job_names_are_complete(job_names):
            raise CurrentAuditError(f"CURRENT_AUDIT_HOSTED_CI_JOBS:{label}")
    job_by_name = {job["name"]: job for job in metadata["jobs"]}
    critical_step = (
        "Verify current-head 0.9 audit cut"
        if workflow == "ci"
        else "Model-check HaldirAuthority"
    )
    critical_job = "supply-chain" if workflow == "ci" else "tlc-model-check"
    if critical_job not in job_by_name or [
        step["name"]
        for step in job_by_name[critical_job]["steps"]
        if step["name"] == critical_step
    ] != [critical_step]:
        raise CurrentAuditError(f"CURRENT_AUDIT_HOSTED_CRITICAL_STEP:{label}")
    log_integrity = _require_gzip_record(
        entry.get("log_integrity"), files[2]["path"], f"{label}.log_integrity"
    )
    if not _strict_equal(_gzip_as_file_record(log_integrity), files[2]):
        raise CurrentAuditError(f"CURRENT_AUDIT_HOSTED_LOG_BINDING:{label}")
    log = _decode_gzip_evidence(compressed, log_integrity, label, MAX_LOG_BYTES)
    if expected_head.encode() not in log or b"##[error]" in log:
        raise CurrentAuditError(f"CURRENT_AUDIT_HOSTED_LOG_INVALID:{label}")
    if workflow == "ci":
        if expected_head == IMPLEMENTATION_COMMIT:
            expected_counts = (34, 26)
            marker_log = log
        else:
            expected_counts = _frozen_test_run_counts(repo, commit)
            marker_log = _hosted_step_log_lines(
                log, "supply-chain", "Verify current-head 0.9 audit cut"
            )
        if marker_log.count(b"verify-current-audit: OK") != 1 or any(
            marker_log.count(f"Ran {count} tests".encode()) != 1
            for count in expected_counts
        ):
            raise CurrentAuditError(f"CURRENT_AUDIT_HOSTED_CI_LOG_MARKERS:{label}")
    elif (
        log.count(b"Model checking completed. No error has been found.") < 1
        or b"Finished in" not in log
    ):
        raise CurrentAuditError(f"CURRENT_AUDIT_HOSTED_FORMAL_LOG_MARKERS:{label}")
    _verify_capture_operations(
        entry.get("capture_operations"),
        run_id=run_id,
        workflow=workflow,
        paths=(files[0]["path"], files[1]["path"], files[2]["path"]),
        head=expected_head,
        label=label,
        not_before=attempt_updated,
        retained_by=_commit_datetime(repo, commit),
    )


def _verify_log_pair_v2(
    repo: Path,
    commit: str,
    entry: dict[str, Any],
    *,
    expected_head: str,
    evidence_id: str,
    linux: bool,
    label: str,
) -> None:
    files = entry["files"]
    expected_file_count = 3 if evidence_id == "CH-T000-E04" else 2
    if len(files) != expected_file_count:
        raise CurrentAuditError(f"CURRENT_AUDIT_LOCAL_FILE_COUNT:{label}")
    metadata_payload = _read_commit_file_bound(
        repo, commit, files[0], f"{label}.metadata", MAX_JSON_BYTES
    )
    compressed = _read_commit_file_bound(
        repo, commit, files[1], f"{label}.log", MAX_COMPRESSED_LOG_BYTES
    )
    metadata = _load_json_bytes(metadata_payload, f"{label}.metadata")
    p0_fields = {
        "schema_version",
        "task_id",
        "evidence_id",
        "runner_class",
        "source_commit",
        "source_tree",
        "worktree_creation_command",
        "worktree_path",
        "command",
        "capture_method",
        "shell",
        "started_at_utc",
        "completed_at_utc",
        "exit_status",
        "passed_gates",
        "failed_gates",
        "terminal_markers",
        "environment",
        "log",
        "scope_limitations",
    }
    linux_fields = {
        "schema_version",
        "task_id",
        "evidence_id",
        "evidence_role",
        "reviewer_id",
        "runner_id",
        "runner_kind",
        "human",
        "named_human_reviewer",
        "release_authority",
        "runner_class",
        "source_commit",
        "source_tree",
        "source_checkout",
        "container",
        "command",
        "capture_method",
        "started_at_utc",
        "completed_at_utc",
        "exit_status",
        "results",
        "log",
        "scope_limitations",
    }
    if (
        set(metadata) != (linux_fields if linux else p0_fields)
        or not isinstance(metadata.get("scope_limitations"), list)
        or not metadata["scope_limitations"]
        or any(
            not isinstance(item, str) or not item.strip()
            for item in metadata["scope_limitations"]
        )
        or metadata.get("schema_version") != "1.0.0"
        or metadata.get("task_id") != "CH-T000"
        or metadata.get("evidence_id") != evidence_id
        or metadata.get("source_commit") != expected_head
        or metadata.get("source_tree") != _commit_metadata(repo, expected_head)["tree"]
        or metadata.get("exit_status") != 0
        or type(metadata.get("exit_status")) is not int
    ):
        raise CurrentAuditError(f"CURRENT_AUDIT_LOCAL_IDENTITY_INVALID:{label}")
    started = _parse_utc(metadata.get("started_at_utc"), f"{label}.started")
    completed = _parse_utc(metadata.get("completed_at_utc"), f"{label}.completed")
    if not (
        _commit_datetime(repo, expected_head)
        <= started
        <= completed
        <= _commit_datetime(repo, commit)
    ):
        raise CurrentAuditError(f"CURRENT_AUDIT_LOCAL_TIME_INVALID:{label}")
    if linux:
        if (
            metadata.get("reviewer_id") != "CH-T000-R02"
            or metadata.get("runner_kind") != "automated_agent"
            or metadata.get("human") is not False
            or metadata.get("named_human_reviewer") is not False
            or metadata.get("release_authority") is not False
            or metadata.get("runner_class")
            != "FRESH_OBJECT_ISOLATED_NETWORK_DISABLED_READ_ONLY_LINUX_CONTAINER"
            or metadata.get("results", {}).get("commit_identity") != "MATCH"
            or metadata.get("results", {}).get("tree_identity") != "MATCH"
            or metadata.get("results", {}).get("checkout_clean") is not True
            or metadata.get("results", {}).get("verifier") != "PASS"
        ):
            raise CurrentAuditError(f"CURRENT_AUDIT_LINUX_PROVENANCE_INVALID:{label}")
        checkout = metadata.get("source_checkout")
        container = metadata.get("container")
        results = metadata.get("results")
        expected_test_counts = (
            (34,)
            if evidence_id == "CH-T000-E04"
            else _frozen_test_run_counts(repo, commit)
        )
        expected_test_count = sum(expected_test_counts)
        historical_linux_record = evidence_id == "CH-T000-E04"
        expected_container_fields = {
            "architecture",
            "client_version",
            "git",
            "image_created_at",
            "image_id",
            "image_reference",
            "kernel",
            "network",
            "os",
            "python",
            "root_filesystem",
            "runtime",
            "server_version",
            "source_mount",
            "temporary_filesystem",
        }
        if not historical_linux_record:
            expected_container_fields.add("ssh_keygen")
        if (
            not isinstance(checkout, dict)
            or set(checkout)
            != {
                "checkout_command",
                "checkout_result",
                "clean_check_command",
                "clean_check_result",
                "clone_command",
                "clone_result",
                "head",
                "host_path",
                "method",
                "source_repository",
                "tree",
            }
            or checkout.get("head") != expected_head
            or checkout.get("tree") != _commit_metadata(repo, expected_head)["tree"]
            or checkout.get("clean_check_result")
            != {
                "exit_status": 0,
                "combined_output": "",
                "sha256": _sha256(b""),
                "bytes": 0,
                "lines": 0,
            }
            or not isinstance(container, dict)
            or set(container) != expected_container_fields
            or container.get("image_reference")
            != (
                HISTORICAL_LINUX_IMAGE_REFERENCE
                if historical_linux_record
                else QUALIFICATION_LINUX_IMAGE_REFERENCE
            )
            or container.get("image_id")
            != (
                HISTORICAL_LINUX_IMAGE_ID
                if historical_linux_record
                else QUALIFICATION_LINUX_IMAGE_ID
            )
            or (
                not historical_linux_record
                and (
                    container.get("image_created_at")
                    != QUALIFICATION_LINUX_IMAGE_CREATED_AT
                    or container.get("architecture") != QUALIFICATION_LINUX_ARCHITECTURE
                    or container.get("python") != QUALIFICATION_LINUX_PYTHON
                    or container.get("git") != QUALIFICATION_LINUX_GIT
                    or container.get("ssh_keygen") != QUALIFICATION_LINUX_SSH_KEYGEN
                )
            )
            or container.get("network") != "none"
            or container.get("root_filesystem") != "read-only"
            or container.get("source_mount") != "read-only"
            or "direct" not in str(metadata.get("capture_method")).lower()
            or "pipeline" not in str(metadata.get("capture_method")).lower()
            or not isinstance(results, dict)
            or set(results)
            != {
                "adversarial_tests_failed",
                "adversarial_tests_passed",
                "checkout_clean",
                "commit_identity",
                "tree_identity",
                "verifier",
            }
            or type(results.get("adversarial_tests_passed")) is not int
            or results["adversarial_tests_passed"] != expected_test_count
            or results.get("adversarial_tests_failed") != 0
            or type(results.get("adversarial_tests_failed")) is not int
        ):
            raise CurrentAuditError(f"CURRENT_AUDIT_LINUX_DETAIL_INVALID:{label}")
        for result_name in ("clone_result", "checkout_result", "clean_check_result"):
            result = checkout.get(result_name)
            if not isinstance(result, dict) or set(result) != {
                "exit_status",
                "combined_output",
                "sha256",
                "bytes",
                "lines",
            }:
                raise CurrentAuditError(f"CURRENT_AUDIT_LINUX_CHECKOUT_RESULT:{label}")
            output = result.get("combined_output")
            if (
                result.get("exit_status") != 0
                or type(result.get("exit_status")) is not int
                or not isinstance(output, str)
                or result.get("sha256") != _sha256(output.encode())
                or result.get("bytes") != len(output.encode())
                or result.get("lines") != len(output.encode().splitlines())
            ):
                raise CurrentAuditError(
                    f"CURRENT_AUDIT_LINUX_CHECKOUT_INTEGRITY:{label}"
                )
        command = str(metadata.get("command"))
        host_path = checkout.get("host_path")
        expected_test_commands = [
            (
                "python3 -m unittest tools/release/test_verify_current_audit.py"
                if historical_linux_record
                else "python3 -I tools/release/test_verify_current_audit.py"
            )
        ]
        if not historical_linux_record:
            expected_test_commands.append(
                "python3 -I tools/release/test_current_audit_resource_profile.py"
            )
        expected_verifier_command = (
            "python3 tools/release/verify-current-audit.py"
            if historical_linux_record
            else "python3 -I tools/release/verify-current-audit.py"
        )
        if (
            not isinstance(host_path, str)
            or f"-v {host_path}:/repo:ro" not in command
            or "--network=none" not in command
            or "--read-only" not in command
            or ":/repo:ro" not in command
            or f'test "$(git rev-parse HEAD)" = {expected_head}' not in command
            or command.count(expected_verifier_command) != 1
            or any(command.count(item) != 1 for item in expected_test_commands)
            or "--no-local --no-hardlinks" not in str(checkout.get("clone_command"))
            or (
                not historical_linux_record
                and (
                    command.count(QUALIFICATION_LINUX_IMAGE_REFERENCE) != 1
                    or "python3 --version" not in command
                    or "git --version" not in command
                    or "test -x /usr/bin/ssh-keygen" not in command
                )
            )
        ):
            raise CurrentAuditError(f"CURRENT_AUDIT_LINUX_COMMAND_INVALID:{label}")
    else:
        expected_gates = (
            IMPLEMENTATION_GATES
            if evidence_id == "CH-T000-E03"
            else FRAMEWORK_GATES
        )
        if (
            metadata.get("failed_gates") != 0
            or type(metadata.get("failed_gates")) is not int
            or metadata.get("passed_gates") != len(expected_gates)
            or type(metadata.get("passed_gates")) is not int
            or "tools/p0r-exit-gate.sh" not in str(metadata.get("command"))
        ):
            raise CurrentAuditError(f"CURRENT_AUDIT_LOCAL_GATE_INVALID:{label}")
    log_integrity = (
        _require_historical_gzip_record(
            metadata.get("log"), files[1]["path"], f"{label}.log_integrity"
        )
        if evidence_id == "CH-T000-E04"
        else _require_gzip_record(
            metadata.get("log"), files[1]["path"], f"{label}.log_integrity"
        )
    )
    if not _strict_equal(_gzip_as_file_record(log_integrity), files[1]):
        raise CurrentAuditError(f"CURRENT_AUDIT_LOCAL_LOG_BINDING:{label}")
    log = _decode_gzip_evidence(compressed, log_integrity, label, MAX_LOG_BYTES)
    if expected_head.encode() not in log:
        raise CurrentAuditError(f"CURRENT_AUDIT_LOCAL_LOG_COMMIT:{label}")
    if linux:
        if (
            log.count(b"verify-current-audit: OK") != 1
            or any(
                log.count(f"Ran {count} tests".encode()) != 1
                for count in expected_test_counts
            )
            or not log.rstrip().endswith(b"OK")
        ):
            raise CurrentAuditError(f"CURRENT_AUDIT_LINUX_LOG_RESULT:{label}")
    else:
        expected_tree = _commit_metadata(repo, expected_head)["tree"].encode()
        lines = log.splitlines()
        try:
            status_begin = lines.index(b"STATUS_BEGIN")
            status_end = lines.index(b"STATUS_END")
        except ValueError as error:
            raise CurrentAuditError(
                f"CURRENT_AUDIT_LOCAL_LOG_STATUS_MISSING:{label}"
            ) from error
        pass_lines = [line for line in lines if line.startswith(b"  PASS: ")]
        fail_lines = [line for line in lines if line.startswith(b"  FAIL: ")]
        if (
            status_end != status_begin + 1
            or lines.count(b"STATUS_BEGIN") != 1
            or lines.count(b"STATUS_END") != 1
            or log.count(b"PWD=" + str(metadata.get("worktree_path")).encode()) != 1
            or log.count(b"HEAD=" + expected_head.encode()) != 1
            or log.count(b"TREE=" + expected_tree) != 1
            or log.count(b"TARGET_PRESENT_BEFORE_GATE=no") != 1
            or log.count(
                b"GATE_COMMAND=CARGO_TERM_COLOR=never TERM=dumb bash tools/p0r-exit-gate.sh"
            )
            != 1
            or len(pass_lines) != len(expected_gates)
            or [line.removeprefix(b"  PASS: ").decode("utf-8") for line in pass_lines]
            != list(expected_gates)
            or fail_lines
            or log.count(
                f"P0-R exit gate: {len(expected_gates)} passed, 0 failed".encode()
            )
            != 1
        ):
            raise CurrentAuditError(f"CURRENT_AUDIT_LOCAL_LOG_RESULT:{label}")
        expected_worktree = (
            "/private/tmp/haldir-bfe0b13-e03-final-clean"
            if evidence_id == "CH-T000-E03"
            else f"/private/tmp/haldir-{expected_head[:7]}-{evidence_id.lower()}-clean"
        )
        if (
            metadata.get("runner_class") != "LOCAL_MACOS_DETACHED_WORKTREE"
            or metadata.get("worktree_path") != expected_worktree
            or metadata.get("worktree_creation_command")
            != f"git worktree add --detach {expected_worktree} {expected_head}"
            or metadata.get("command")
            != "CARGO_TERM_COLOR=never TERM=dumb bash tools/p0r-exit-gate.sh"
            or metadata.get("shell") != "/bin/zsh (gate invoked with /bin/bash)"
            or "not a tee or pipeline status" not in str(metadata.get("capture_method"))
        ):
            raise CurrentAuditError("CURRENT_AUDIT_LOCAL_PROVENANCE_INVALID")


def _load_exact_module(payload: bytes, filename: str, label: str) -> types.ModuleType:
    module = types.ModuleType(f"haldir_{label}_{_sha256(payload)[:16]}")
    module.__file__ = filename
    try:
        exec(compile(payload, filename, "exec", dont_inherit=True), module.__dict__)
    except Exception as error:
        raise CurrentAuditError(f"CURRENT_AUDIT_MODULE_LOAD_FAILED:{label}") from error
    return module


def _verify_resource_profile_v2(
    repo: Path, commit: str, framework_commit: str, entry: dict[str, Any]
) -> None:
    files = entry["files"]
    if len(files) != 1:
        raise CurrentAuditError("CURRENT_AUDIT_RESOURCE_PROFILE_FILES")
    payload = _read_commit_file_bound(
        repo, commit, files[0], "resource_profile", MAX_JSON_BYTES
    )
    profile = _load_json_bytes(payload, "resource_profile")
    profiler_payload = _git_file(
        repo, framework_commit, "tools/release/current-audit-resource-profile.py"
    )
    verifier_payload = _git_file(
        repo, framework_commit, "tools/release/verify-current-audit.py"
    )
    profiler = _load_exact_module(
        profiler_payload,
        "tools/release/current-audit-resource-profile.py",
        "resource_profiler",
    )
    try:
        profiler.validate_profile(profile, verifier_payload=verifier_payload)
    except Exception as error:
        raise CurrentAuditError("CURRENT_AUDIT_RESOURCE_PROFILE_INVALID") from error
    generated = _parse_utc(
        profile.get("generated_at_utc"), "resource_profile.generated"
    )
    if (
        not (
            _commit_datetime(repo, framework_commit)
            <= generated
            <= _commit_datetime(repo, commit)
        )
        or profile.get("overall_pass") is not True
        or len(profile.get("cases", [])) != 34
        or profile.get("configuration", {}).get("samples_per_case") != 3
        or not _strict_equal(
            profile.get("configuration", {}).get("limits_bytes"),
            {
                "MAX_JSON_BYTES": MAX_JSON_BYTES,
                "MAX_JSON_STRING_BYTES": MAX_JSON_STRING_BYTES,
                "MAX_REQUIREMENTS_BYTES": MAX_REQUIREMENTS_BYTES,
                "MAX_COMPRESSED_LOG_BYTES": MAX_COMPRESSED_LOG_BYTES,
                "MAX_LOG_BYTES": MAX_LOG_BYTES,
                "MAX_GIT_BYTES": MAX_GIT_BYTES,
                "MAX_HYGIENE_TOTAL_BYTES": MAX_HYGIENE_TOTAL_BYTES,
                "MAX_REVOCATION_CAUSE_FILE_BYTES": MAX_REVOCATION_CAUSE_FILE_BYTES,
                "MAX_REVOCATION_CAUSE_TOTAL_BYTES": MAX_REVOCATION_CAUSE_TOTAL_BYTES,
                "MAX_PROTOCOL_PATH_BYTES": MAX_PROTOCOL_PATH_BYTES,
                "MAX_VERIFIER_OUTPUT_BYTES": MAX_VERIFIER_OUTPUT_BYTES,
                "MAX_ZIP_ENTRY_BYTES": MAX_ZIP_ENTRY_BYTES,
                "MAX_ZIP_TOTAL_BYTES": MAX_ZIP_TOTAL_BYTES,
            },
        )
        or not _strict_equal(
            profile.get("configuration", {}).get("json_structure_limits"),
            {
                "MAX_JSON_DEPTH": MAX_JSON_DEPTH,
                "MAX_JSON_NODES": MAX_JSON_NODES,
                "MAX_JSON_CONTAINER_ENTRIES": MAX_JSON_CONTAINER_ENTRIES,
            },
        )
        or not _strict_equal(
            entry.get("verification"),
            {
                "overall_pass": True,
                "boundary_cases": 34,
                "samples_per_case": 3,
                "profiler_tests_passed": 26,
                "profiler_tests_failed": 0,
            },
        )
    ):
        raise CurrentAuditError("CURRENT_AUDIT_RESOURCE_PROFILE_RESULT")


def _reviewed_diff_record(repo: Path, parent: str, commit: str) -> dict[str, Any]:
    binding = _signed_commit_binding(repo, commit, parent)
    numstat = _git(
        repo,
        "-c",
        "diff.algorithm=myers",
        "diff",
        "--no-ext-diff",
        "--no-textconv",
        "--no-renames",
        "--no-color",
        "--numstat",
        f"{parent}..{commit}",
    ).decode("utf-8")
    additions = 0
    deletions = 0
    binary_files = 0
    for line in numstat.splitlines():
        added, deleted, _path = line.split("\t", 2)
        if added == "-" or deleted == "-":
            binary_files += 1
        else:
            additions += int(added)
            deletions += int(deleted)
    return {
        "base": parent,
        "commit": commit,
        "tree": binding["tree"],
        "path_statuses": binding["diff"]["path_statuses"],
        "patch_sha256": binding["diff"]["patch_sha256"],
        "patch_bytes": binding["diff"]["patch_bytes"],
        "patch_lines": binding["diff"]["patch_lines"],
        "reviewed_paths": len(binding["diff"]["path_statuses"]),
        "reviewed_text_additions": additions,
        "reviewed_text_deletions": deletions,
        "reviewed_binary_files": binary_files,
    }


def _path_review_facts(repo: Path, parent: str, commit: str) -> list[dict[str, Any]]:
    statuses = _changed_path_statuses(repo, parent, commit)
    numstat_raw = _git(
        repo,
        "-c",
        "diff.algorithm=myers",
        "diff",
        "--no-ext-diff",
        "--no-textconv",
        "--no-renames",
        "--no-color",
        "--numstat",
        f"{parent}..{commit}",
    ).decode("utf-8")
    numstat: dict[str, tuple[str, str]] = {}
    for line in numstat_raw.splitlines():
        added, deleted, path = line.split("\t", 2)
        numstat[path] = (added, deleted)
    result: list[dict[str, Any]] = []
    for path, status in statuses.items():
        added, deleted = numstat[path]
        binary = added == "-" or deleted == "-"
        patch = _git(
            repo,
            "-c",
            "diff.algorithm=myers",
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "--no-renames",
            "--no-color",
            "--unified=0",
            f"{parent}..{commit}",
            "--",
            path,
        )
        result.append(
            {
                "base": parent,
                "commit": commit,
                "path": path,
                "status": status,
                "text_additions": None if binary else int(added),
                "text_deletions": None if binary else int(deleted),
                "hunks": 0
                if binary
                else sum(line.startswith(b"@@") for line in patch.splitlines()),
                "binary": binary,
                "blob": _commit_file_record(repo, commit, path),
            }
        )
    return result


def _unchanged_context_facts(repo: Path, framework_commit: str) -> list[dict[str, Any]]:
    paths = (
        "release/0.9.0/current-head/audit-inputs.json",
        "release/0.9.0/current-head/requirements.json",
        "release/0.9.0/allowed-signers",
        ".github/workflows/formal.yml",
        "tools/pins.toml",
    )
    return [
        {
            "commit": framework_commit,
            **_commit_file_record(repo, framework_commit, path),
        }
        for path in paths
    ]


def ch_t000_framework_reviewer_skeleton(
    repo: Path, framework_commit: str, reviewer_id: str
) -> dict[str, Any]:
    """Return immutable scope facts with explicitly pending reviewer fields."""

    if reviewer_id not in {"CH-T000-R01", "CH-T000-R02"}:
        raise CurrentAuditError("CURRENT_AUDIT_REVIEWER_TEMPLATE_ID")
    primary = reviewer_id == "CH-T000-R01"
    reviewed_diffs = [
        _reviewed_diff_record(repo, SOURCE_COMMIT, IMPLEMENTATION_COMMIT),
        _reviewed_diff_record(repo, IMPLEMENTATION_COMMIT, framework_commit),
    ]
    return {
        "schema_version": "1.0.0",
        "record_id": f"{reviewer_id}-SIGNED-FRAMEWORK-REVIEW",
        "task_id": "CH-T000",
        "source_task_id": "T000",
        "release_target": "0.9.0",
        "persistent_identifier": None,
        "classification": "AUTOMATED_SUPPORTING_REVIEW_ONLY",
        "reviewer": {
            "id": reviewer_id,
            "agent_task_path": "/root" if primary else "/root/t000_final_audit",
            "role": (
                "primary exact changed-line and context reviewer"
                if primary
                else "independent adversarial framework and reproduction reviewer"
            ),
            "human": False,
            "named_human_approver": False,
            "security_certifier": False,
            "release_approver": False,
        },
        "reviewed_commit": framework_commit,
        "reviewed_tree": _commit_metadata(repo, framework_commit)["tree"],
        "reviewed_parent": IMPLEMENTATION_COMMIT,
        "review_started_at_utc": None,
        "review_completed_at_utc": None,
        "immutable_scope": {
            "kind": "EXACT_BFE_AND_FRAMEWORK_CHANGED_LINE_CONTEXT_AND_BINARY_REVIEW",
            "reviewed_diffs": reviewed_diffs,
            "unchanged_context_paths": [
                "release/0.9.0/current-head/audit-inputs.json",
                "release/0.9.0/current-head/requirements.json",
                "release/0.9.0/allowed-signers",
                ".github/workflows/formal.yml",
                "tools/pins.toml",
            ],
        },
        "path_reviews": [
            {
                **facts,
                "review_completed": False,
                "review_method": None,
                "unchanged_context_considered": False,
                "finding_ids": [],
            }
            for facts in (
                _path_review_facts(repo, SOURCE_COMMIT, IMPLEMENTATION_COMMIT)
                + _path_review_facts(repo, IMPLEMENTATION_COMMIT, framework_commit)
            )
        ],
        "unchanged_context_reviews": [
            {
                **facts,
                "review_completed": False,
                "review_method": None,
                "finding_ids": [],
            }
            for facts in _unchanged_context_facts(repo, framework_commit)
        ],
        "findings": [],
        "test_results": {
            "commands": [],
            "passed": 0,
            "failed": None,
            "exact_commit": framework_commit,
            "evidence_ids": [],
        },
        "blocker_dispositions": [
            {
                **{key: value for key, value in disposition.items() if key != "status"},
                "status": "PENDING_REVIEW",
                "rationale": None,
            }
            for disposition in ch_t000_c_finding_dispositions()
        ],
        "activation_blockers": [
            "CH-T000-R02-B17",
            "CH-T000-R02-B19",
            "CH-T000-R02-B20",
            "CH-T000-R02-B23",
        ],
        "human_review_boundary": HUMAN_REVIEW_BOUNDARY,
        "release_authority_boundary": RELEASE_AUTHORITY_BOUNDARY,
        "decisive_reproduction": None,
        "disposition": "PENDING_REVIEW",
    }


def _verify_reviewer_report_v2(
    repo: Path,
    commit: str,
    record: dict[str, Any],
    *,
    reviewer_id: str,
    framework_commit: str,
    label: str,
) -> None:
    payload = _read_commit_file_bound(repo, commit, record, label, MAX_JSON_BYTES)
    report = _load_json_bytes(payload, label)
    skeleton = ch_t000_framework_reviewer_skeleton(repo, framework_commit, reviewer_id)
    if set(report) != set(skeleton):
        raise CurrentAuditError(f"CURRENT_AUDIT_REVIEWER_REPORT_FIELDS:{label}")
    immutable_keys = {
        "schema_version",
        "record_id",
        "task_id",
        "source_task_id",
        "release_target",
        "persistent_identifier",
        "classification",
        "reviewer",
        "reviewed_commit",
        "reviewed_tree",
        "reviewed_parent",
        "immutable_scope",
        "activation_blockers",
        "human_review_boundary",
        "release_authority_boundary",
    }
    for key in immutable_keys:
        if not _strict_equal(report.get(key), skeleton[key]):
            raise CurrentAuditError(
                f"CURRENT_AUDIT_REVIEWER_REPORT_IMMUTABLE:{label}:{key}"
            )
    review_started = _parse_utc(
        report.get("review_started_at_utc"), f"{label}.review_started"
    )
    review_completed = _parse_utc(
        report.get("review_completed_at_utc"), f"{label}.review_completed"
    )
    if not (
        _commit_datetime(repo, framework_commit)
        <= review_started
        <= review_completed
        <= _commit_datetime(repo, commit)
    ):
        raise CurrentAuditError(f"CURRENT_AUDIT_REVIEWER_TIME_INVALID:{label}")
    blocker_dispositions = report.get("blocker_dispositions")
    required_dispositions = ch_t000_c_finding_dispositions()
    if not isinstance(blocker_dispositions, list) or len(blocker_dispositions) != len(
        required_dispositions
    ):
        raise CurrentAuditError(f"CURRENT_AUDIT_REVIEWER_BLOCKER_COVERAGE:{label}")
    for index, (observed, required) in enumerate(
        zip(blocker_dispositions, required_dispositions, strict=True)
    ):
        immutable = {key: value for key, value in required.items() if key != "status"}
        if (
            not isinstance(observed, dict)
            or set(observed) != set(required) | {"rationale"}
            or not _strict_equal(
                {key: observed.get(key) for key in immutable}, immutable
            )
            or observed.get("status") != required["status"]
        ):
            raise CurrentAuditError(
                f"CURRENT_AUDIT_REVIEWER_BLOCKER_DISPOSITION:{label}:{index}"
            )
        rationale = _require_nonempty_string(
            observed.get("rationale"), f"{label}.blocker.{index}.rationale"
        )
        if (
            len(rationale) < 24
            or any(
                phrase in rationale.lower()
                for phrase in (
                    "human approved",
                    "release approved",
                    "security certified",
                    "full release go",
                )
            )
            or observed["id"] not in rationale
            or not any(
                token in rationale
                for token in (
                    *observed["evidence_ids"],
                    *observed["control_ids"],
                    *observed["test_ids"],
                )
            )
        ):
            raise CurrentAuditError(
                f"CURRENT_AUDIT_REVIEWER_BLOCKER_RATIONALE:{label}:{index}"
            )
    expected_path_facts = [
        {
            key: value
            for key, value in item.items()
            if key
            not in {
                "review_completed",
                "review_method",
                "unchanged_context_considered",
                "finding_ids",
            }
        }
        for item in skeleton["path_reviews"]
    ]
    path_reviews = report.get("path_reviews")
    if not isinstance(path_reviews, list) or len(path_reviews) != len(
        expected_path_facts
    ):
        raise CurrentAuditError(f"CURRENT_AUDIT_REVIEWER_PATH_COVERAGE:{label}")
    referenced_findings: list[str] = []
    for index, (record, facts) in enumerate(
        zip(path_reviews, expected_path_facts, strict=True)
    ):
        if not isinstance(record, dict) or set(record) != set(facts) | {
            "review_completed",
            "review_method",
            "unchanged_context_considered",
            "finding_ids",
        }:
            raise CurrentAuditError(f"CURRENT_AUDIT_REVIEWER_PATH_FIELDS:{label}")
        if not _strict_equal({key: record[key] for key in facts}, facts):
            raise CurrentAuditError(f"CURRENT_AUDIT_REVIEWER_PATH_FACTS:{label}")
        expected_method = (
            "BOUNDED_BINARY_PARSER_AND_EXACT_BLOB_IDENTITY"
            if facts["binary"]
            else "EVERY_CHANGED_TEXT_LINE_WITH_RELEVANT_UNCHANGED_CONTEXT"
        )
        finding_ids = _require_string_list(
            record.get("finding_ids"),
            f"{label}.path_reviews.{index}.findings",
            minimum=0,
            unique=True,
        )
        if (
            record.get("review_completed") is not True
            or record.get("unchanged_context_considered") is not True
            or record.get("review_method") != expected_method
        ):
            raise CurrentAuditError(f"CURRENT_AUDIT_REVIEWER_PATH_INCOMPLETE:{label}")
        referenced_findings.extend(finding_ids)
    context_reviews = report.get("unchanged_context_reviews")
    expected_context = skeleton["unchanged_context_reviews"]
    if not isinstance(context_reviews, list) or len(context_reviews) != len(
        expected_context
    ):
        raise CurrentAuditError(f"CURRENT_AUDIT_REVIEWER_CONTEXT_COVERAGE:{label}")
    for index, (record, pending) in enumerate(
        zip(context_reviews, expected_context, strict=True)
    ):
        facts = {
            key: value
            for key, value in pending.items()
            if key not in {"review_completed", "review_method", "finding_ids"}
        }
        if not isinstance(record, dict) or set(record) != set(facts) | {
            "review_completed",
            "review_method",
            "finding_ids",
        }:
            raise CurrentAuditError(f"CURRENT_AUDIT_REVIEWER_CONTEXT_FIELDS:{label}")
        finding_ids = _require_string_list(
            record.get("finding_ids"),
            f"{label}.contexts.{index}.findings",
            minimum=0,
            unique=True,
        )
        if (
            not _strict_equal({key: record[key] for key in facts}, facts)
            or record.get("review_completed") is not True
            or record.get("review_method")
            != "LINE_BY_LINE_NORMATIVE_AND_EXECUTION_CONTEXT_REVIEW"
        ):
            raise CurrentAuditError(
                f"CURRENT_AUDIT_REVIEWER_CONTEXT_INCOMPLETE:{label}"
            )
        referenced_findings.extend(finding_ids)
    findings = report.get("findings")
    if not isinstance(findings, list):
        raise CurrentAuditError(f"CURRENT_AUDIT_REVIEWER_FINDINGS:{label}")
    observed_ids: list[str] = []
    reviewed_paths = {item["path"] for item in [*path_reviews, *context_reviews]}
    allowed_controls = {control["id"] for control in ch_t000_normative_controls()}
    allowed_evidence = set(C_EVIDENCE_IDS)
    for finding in findings:
        finding = _require_fields(
            finding,
            {
                "id",
                "severity",
                "disposition",
                "summary",
                "paths",
                "control_ids",
                "evidence_ids",
            },
            f"{label}.finding",
        )
        finding_id = _require_nonempty_string(finding.get("id"), f"{label}.finding.id")
        summary = _require_nonempty_string(
            finding.get("summary"), f"{label}.finding.summary"
        )
        if (
            finding.get("severity") not in {"P0", "P1", "P2", "P3", "INFO"}
            or finding.get("disposition")
            not in {"RESOLVED_AT_C", "DEFERRED_TO_D", "INFORMATIONAL"}
            or any(
                phrase in summary.lower()
                for phrase in (
                    (PROHIBITED_GOVERNANCE_TOKEN + b" approved").decode(),
                    "human approved",
                    "release approved",
                    "full release go",
                    "security certified",
                )
            )
        ):
            raise CurrentAuditError(f"CURRENT_AUDIT_REVIEWER_FINDING_INVALID:{label}")
        paths = _require_string_list(
            finding.get("paths"), f"{label}.finding.paths", minimum=1, unique=True
        )
        controls = _require_string_list(
            finding.get("control_ids"),
            f"{label}.finding.controls",
            minimum=1,
            unique=True,
        )
        evidence = _require_string_list(
            finding.get("evidence_ids"),
            f"{label}.finding.evidence",
            minimum=1,
            unique=True,
        )
        if (
            any(path not in reviewed_paths for path in paths)
            or any(control not in allowed_controls for control in controls)
            or any(item not in allowed_evidence for item in evidence)
            or (
                finding.get("severity") in {"P0", "P1"}
                and finding.get("disposition") == "INFORMATIONAL"
            )
            or (
                finding.get("disposition") == "DEFERRED_TO_D"
                and (
                    finding_id not in report["activation_blockers"]
                    or finding_id
                    not in {
                        resolution["id"]
                        for resolution in _activation_blocker_resolutions()
                    }
                )
            )
        ):
            raise CurrentAuditError(f"CURRENT_AUDIT_REVIEWER_FINDING_REFERENCE:{label}")
        observed_ids.append(finding_id)
    if len(observed_ids) != len(set(observed_ids)) or set(referenced_findings) != set(
        observed_ids
    ):
        raise CurrentAuditError(f"CURRENT_AUDIT_REVIEWER_FINDING_BINDING:{label}")
    test_results = _require_fields(
        report.get("test_results"),
        {"commands", "passed", "failed", "exact_commit", "evidence_ids"},
        f"{label}.test_results",
    )
    expected_commands = [
        "python3 -I tools/release/test_verify_current_audit.py",
        "python3 -I tools/release/test_current_audit_resource_profile.py",
        "python3 -I tools/release/verify-current-audit.py",
    ]
    frozen_test_count = sum(
        len(test_ids)
        for test_ids in _discover_frozen_test_ids(repo, framework_commit).values()
    )
    if (
        test_results.get("commands") != expected_commands
        or type(test_results.get("passed")) is not int
        or test_results["passed"] != frozen_test_count
        or type(test_results.get("failed")) is not int
        or test_results["failed"] != 0
        or test_results.get("exact_commit") != framework_commit
        or test_results.get("evidence_ids") != ["CH-T000-Q03", "CH-T000-Q06"]
    ):
        raise CurrentAuditError(f"CURRENT_AUDIT_REVIEWER_TEST_RESULT:{label}")
    q03_metadata_path = FRAMEWORK_EVIDENCE_PATHS[2]
    q03_log_path = FRAMEWORK_EVIDENCE_PATHS[3]
    expected_reproduction = (
        None
        if reviewer_id == "CH-T000-R01"
        else {
            "evidence_id": "CH-T000-Q03",
            "exact_commit": framework_commit,
            "result": "PASS",
            "tests_passed": sum(
                len(test_ids)
                for test_ids in _discover_frozen_test_ids(
                    repo, framework_commit
                ).values()
            ),
            "metadata": _commit_file_record(repo, commit, q03_metadata_path),
            "log": _commit_file_record(repo, commit, q03_log_path),
        }
    )
    if not _strict_equal(report.get("decisive_reproduction"), expected_reproduction):
        raise CurrentAuditError(f"CURRENT_AUDIT_REVIEWER_REPRODUCTION:{label}")
    if report.get("disposition") != "C_REVIEW_COMPLETE_WITH_D_ACTIVATION_BLOCKERS":
        raise CurrentAuditError(f"CURRENT_AUDIT_REVIEWER_DISPOSITION:{label}")


def _verify_bfe_r02_report_v2(repo: Path, commit: str, record: dict[str, Any]) -> None:
    payload = _read_commit_file_bound(
        repo, commit, record, "r02_bfe_review", MAX_JSON_BYTES
    )
    report = _load_json_bytes(payload, "r02_bfe_review")
    reviewer = report.get("reviewer")
    blockers = report.get("blockers")
    if (
        report.get("schema_version") != "1.0.0"
        or report.get("task_id") != "CH-T000"
        or report.get("classification") != "AUTOMATED_SUPPORTING_REVIEW_ONLY"
        or not isinstance(reviewer, dict)
        or reviewer.get("id") != "CH-T000-R02"
        or reviewer.get("human") is not False
        or reviewer.get("named_human_reviewer") is not False
        or reviewer.get("release_approver") is not False
        or report.get("review_scope", {}).get("implementation_commit")
        != IMPLEMENTATION_COMMIT
        or not isinstance(blockers, list)
        or len(blockers) != 23
        or [blocker.get("id") for blocker in blockers]
        != [f"CH-T000-R02-B{index:02d}" for index in range(1, 24)]
    ):
        raise CurrentAuditError("CURRENT_AUDIT_R02_BFE_REVIEW_INVALID")
    reviewed_at = _parse_utc(report.get("reviewed_at_utc"), "r02_bfe.reviewed")
    if not (
        _commit_datetime(repo, IMPLEMENTATION_COMMIT)
        <= reviewed_at
        <= _commit_datetime(repo, commit)
    ):
        raise CurrentAuditError("CURRENT_AUDIT_R02_BFE_REVIEW_TIME")


def _verify_evidence_catalog_v2(
    repo: Path,
    qualification_commit: str,
    framework_commit: str,
    catalog: Any,
) -> None:
    layout = _catalog_layout(framework_commit)
    if not isinstance(catalog, dict) or list(catalog) != list(layout):
        raise CurrentAuditError("CURRENT_AUDIT_QUALIFICATION_CATALOG_IDS")
    for evidence_id, expected in layout.items():
        entry = _require_fields(
            catalog.get(evidence_id),
            {
                "id",
                "kind",
                "subject_commit",
                "result",
                "files",
                "capture_operations",
                "log_integrity",
                "verification",
            },
            f"catalog.{evidence_id}",
        )
        expected_paths = expected["paths"]
        if (
            entry.get("id") != evidence_id
            or entry.get("kind") != expected["kind"]
            or entry.get("subject_commit") != expected["subject_commit"]
            or entry.get("result") != "PASS"
            or not isinstance(entry.get("files"), list)
            or [item.get("path") for item in entry["files"] if isinstance(item, dict)]
            != expected_paths
        ):
            raise CurrentAuditError(
                f"CURRENT_AUDIT_QUALIFICATION_CATALOG_ENTRY:{evidence_id}"
            )
        file_records = []
        for path in expected_paths:
            source_commit = (
                IMPLEMENTATION_COMMIT
                if evidence_id == "CH-T000-E02"
                else qualification_commit
            )
            file_records.append(_commit_file_record(repo, source_commit, path))
        if not _strict_equal(entry["files"], file_records):
            raise CurrentAuditError(
                f"CURRENT_AUDIT_QUALIFICATION_CATALOG_FILES:{evidence_id}"
            )
        for record in entry["files"]:
            pinned = PINNED_BFE_EVIDENCE_RECORDS.get(record["path"])
            if pinned is not None and not _strict_equal(record, pinned):
                raise CurrentAuditError(
                    f"CURRENT_AUDIT_PINNED_BFE_EVIDENCE_MISMATCH:{evidence_id}"
                )
        hosted = evidence_id in {
            "CH-T000-E05",
            "CH-T000-E06",
            "CH-T000-Q03",
            "CH-T000-Q04",
            "CH-T000-Q05",
        }
        if not hosted and entry.get("capture_operations") is not None:
            raise CurrentAuditError(
                f"CURRENT_AUDIT_QUALIFICATION_CAPTURE_UNEXPECTED:{evidence_id}"
            )
        if not hosted and entry.get("log_integrity") is not None:
            raise CurrentAuditError(
                f"CURRENT_AUDIT_QUALIFICATION_LOG_UNEXPECTED:{evidence_id}"
            )
        if evidence_id != "CH-T000-Q06" and entry.get("verification") is not None:
            raise CurrentAuditError(
                f"CURRENT_AUDIT_QUALIFICATION_VERIFICATION_UNEXPECTED:{evidence_id}"
            )
        if evidence_id == "CH-T000-E03":
            _verify_log_pair_v2(
                repo,
                qualification_commit,
                entry,
                expected_head=IMPLEMENTATION_COMMIT,
                evidence_id=evidence_id,
                linux=False,
                label="e03",
            )
        elif evidence_id == "CH-T000-E04":
            _verify_log_pair_v2(
                repo,
                qualification_commit,
                entry,
                expected_head=IMPLEMENTATION_COMMIT,
                evidence_id=evidence_id,
                linux=True,
                label="e04",
            )
            _verify_bfe_r02_report_v2(repo, qualification_commit, entry["files"][2])
        elif evidence_id in {"CH-T000-E05", "CH-T000-E06"}:
            _verify_hosted_evidence_v2(
                repo,
                qualification_commit,
                entry,
                expected_head=IMPLEMENTATION_COMMIT,
                workflow="ci" if evidence_id.endswith("05") else "formal",
                label=evidence_id.lower(),
            )
        elif evidence_id == "CH-T000-Q02":
            _verify_log_pair_v2(
                repo,
                qualification_commit,
                entry,
                expected_head=framework_commit,
                evidence_id=evidence_id,
                linux=False,
                label="q02",
            )
        elif evidence_id == "CH-T000-Q03":
            _verify_hosted_evidence_v2(
                repo,
                qualification_commit,
                entry,
                expected_head=framework_commit,
                workflow="ci",
                label="q03",
                expected_event="workflow_dispatch",
            )
        elif evidence_id in {"CH-T000-Q04", "CH-T000-Q05"}:
            _verify_hosted_evidence_v2(
                repo,
                qualification_commit,
                entry,
                expected_head=framework_commit,
                workflow="ci" if evidence_id.endswith("04") else "formal",
                label=evidence_id.lower(),
            )
        elif evidence_id == "CH-T000-Q06":
            _verify_resource_profile_v2(
                repo, qualification_commit, framework_commit, entry
            )
        elif evidence_id == "CH-T000-Q07":
            _verify_reviewer_report_v2(
                repo,
                qualification_commit,
                entry["files"][0],
                reviewer_id="CH-T000-R01",
                framework_commit=framework_commit,
                label="q07_r01",
            )
        elif evidence_id == "CH-T000-Q08":
            _verify_reviewer_report_v2(
                repo,
                qualification_commit,
                entry["files"][0],
                reviewer_id="CH-T000-R02",
                framework_commit=framework_commit,
                label="q08_r02",
            )


def _verify_qualification_review_v2(
    review: dict[str, Any],
    repo: Path,
    framework_commit: str,
    qualification_commit: str,
) -> None:
    fixed = ch_t000_review_fixed_template(framework_commit)
    if set(review) != set(fixed) | {"evidence_catalog"}:
        raise CurrentAuditError("CURRENT_AUDIT_QUALIFICATION_REVIEW_V2_FIELDS")
    for key, expected in fixed.items():
        if key in {"review_started_at_utc", "review_completed_at_utc"}:
            continue
        if not _strict_equal(review.get(key), expected):
            raise CurrentAuditError(
                f"CURRENT_AUDIT_QUALIFICATION_REVIEW_V2_MISMATCH:{key}"
            )
    review_started = _parse_utc(
        review.get("review_started_at_utc"), "qualification.review_started"
    )
    review_completed = _parse_utc(
        review.get("review_completed_at_utc"), "qualification.review_completed"
    )
    if not (
        _commit_datetime(repo, framework_commit)
        <= review_started
        <= review_completed
        <= _commit_datetime(repo, qualification_commit)
    ):
        raise CurrentAuditError("CURRENT_AUDIT_QUALIFICATION_REVIEW_TIME")
    if review["lead_approval"].get("controls_and_cases_sha256") != (
        ch_t000_control_digest()
    ):
        raise CurrentAuditError("CURRENT_AUDIT_QUALIFICATION_CONTROL_DIGEST")
    _verify_evidence_catalog_v2(
        repo,
        qualification_commit,
        framework_commit,
        review.get("evidence_catalog"),
    )


def _qualification_expected_v2(
    repo: Path, framework_commit: str, qualification_commit: str
) -> dict[str, Any]:
    evidence_files = [
        _commit_file_record(repo, qualification_commit, path)
        for path in C_EVIDENCE_PATHS
    ]
    review_record = {
        **_commit_file_record(repo, qualification_commit, REVIEW_PATH),
        "classification": "AUTOMATED_TECHNICAL_SUPPORT_ONLY",
        "reviewer_ids": ["CH-T000-R01", "CH-T000-R02", "CH-T000-R03"],
    }
    return {
        "schema_version": "2.0.0",
        "record_id": "CH-T000-TECHNICAL-QUALIFICATION",
        "task_id": "CH-T000",
        "source_task_id": "T000",
        "release_target": "0.9.0",
        "author": {"name": "Sepehr Mahmoudian", "email": "sepmhn@gmail.com"},
        "persistent_identifier": None,
        "scope": QUALIFICATION_SCOPE,
        "qualified_source_cut": {
            "commit": SOURCE_COMMIT,
            "tree": SOURCE_TREE,
            "parent": SOURCE_PARENT,
            "approved_update": "release/0.9.0/current-head/HANDOFF-ERRATA.md",
        },
        "qualified_implementation": _signed_commit_binding(
            repo, IMPLEMENTATION_COMMIT, SOURCE_COMMIT
        ),
        "qualified_framework": _signed_commit_binding(
            repo, framework_commit, IMPLEMENTATION_COMMIT
        ),
        "evidence_files": evidence_files,
        "review_record": review_record,
        "lead_disposition": {
            "kind": "AUTOMATED_LEAD_AGENT",
            "reviewer_id": "CH-T000-R03",
            "decision": "ACCEPT_TECHNICAL_CH_T000_QUALIFICATION_PENDING_ACTIVATION",
            "human": False,
            "named_human_approver": False,
        },
        "decision": {
            "current_ledger_status": "OPEN",
            "recommended_terminal_status": "VERIFIED",
            "claim_disposition": "NO_PUBLIC_CLAIM_CHANGE",
            "effective_only_when": QUALIFICATION_EFFECTIVE_CONDITION,
            "release_status_after_activation": "NO_GO",
            "next_open_task": "CH-T001",
        },
        "human_review_boundary": HUMAN_REVIEW_BOUNDARY,
        "release_authority_boundary": RELEASE_AUTHORITY_BOUNDARY,
    }


def _verify_ch_t000_qualification_v2(
    repo: Path, framework_commit: str, qualification_commit: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    qualification, _qualification_payload = _read_commit_json(
        repo,
        qualification_commit,
        QUALIFICATION_PATH,
        "ch_t000.qualification.v2",
    )
    expected = _qualification_expected_v2(repo, framework_commit, qualification_commit)
    if not _strict_equal(qualification, expected):
        raise CurrentAuditError("CURRENT_AUDIT_QUALIFICATION_V2_MISMATCH")
    review, review_payload = _read_commit_json(
        repo, qualification_commit, REVIEW_PATH, "ch_t000.review.v2"
    )
    if not _strict_equal(
        _payload_file_record(REVIEW_PATH, review_payload),
        {
            key: qualification["review_record"][key]
            for key in _payload_file_record(REVIEW_PATH, review_payload)
        },
    ):
        raise CurrentAuditError("CURRENT_AUDIT_QUALIFICATION_REVIEW_BINDING_V2")
    _verify_qualification_review_v2(
        review, repo, framework_commit, qualification_commit
    )
    _verify_named_commit_signature(repo, IMPLEMENTATION_COMMIT, "IMPLEMENTATION_V2")
    _verify_named_commit_signature(repo, framework_commit, "FRAMEWORK_V2")
    return qualification, review


def _activation_catalog_layout(
    qualification_commit: str,
) -> dict[str, dict[str, Any]]:
    return {
        "CH-T000-A01": {
            "kind": "SIGNED_QUALIFICATION_COMMIT",
            "paths": [],
        },
        "CH-T000-A02": {
            "kind": "EXACT_QUALIFICATION_LOCAL_P0R_GATE",
            "paths": list(ACTIVATION_EVIDENCE_PATHS[0:2]),
        },
        "CH-T000-A03": {
            "kind": "INDEPENDENT_QUALIFICATION_CLEAN_LINUX_REPRODUCTION",
            "paths": list(ACTIVATION_EVIDENCE_PATHS[2:4]),
        },
        "CH-T000-A04": {
            "kind": "EXACT_QUALIFICATION_GITHUB_CI_RUN",
            "paths": list(ACTIVATION_EVIDENCE_PATHS[4:7]),
        },
        "CH-T000-A05": {
            "kind": "EXACT_QUALIFICATION_GITHUB_FORMAL_RUN",
            "paths": list(ACTIVATION_EVIDENCE_PATHS[7:10]),
        },
    }


def _activation_blocker_resolutions() -> list[dict[str, Any]]:
    return [
        {
            "id": "CH-T000-R02-B17",
            "status": "RESOLVED_AT_D",
            "evidence_ids": ["CH-T000-A01", "CH-T000-A02", "CH-T000-A03"],
            "control_ids": ["CH-T000-N06"],
            "test_ids": [
                "test_framework_pending_to_qualified_open_to_terminal_stage_sequence"
            ],
        },
        {
            "id": "CH-T000-R02-B19",
            "status": "RESOLVED_AT_D",
            "evidence_ids": ["CH-T000-A01", "CH-T000-A02", "CH-T000-A03"],
            "control_ids": ["CH-T000-N06"],
            "test_ids": [
                "test_forward_protocol_real_git_revocation_refreeze_modes_and_head_force"
            ],
        },
        {
            "id": "CH-T000-R02-B20",
            "status": "RESOLVED_AT_D",
            "evidence_ids": [
                "CH-T000-A01",
                "CH-T000-A02",
                "CH-T000-A04",
                "CH-T000-A05",
            ],
            "control_ids": ["CH-T000-N01", "CH-T000-N02", "CH-T000-N06"],
            "test_ids": [
                "test_qualified_or_terminal_stage_rejects_qualification_deletion"
            ],
        },
        {
            "id": "CH-T000-R02-B23",
            "status": "RESOLVED_AT_D",
            "evidence_ids": list(ACTIVATION_EVIDENCE_IDS),
            "control_ids": ["CH-T000-N02", "CH-T000-N04", "CH-T000-N06"],
            "test_ids": ["test_terminal_exact_ch_t000_state_verifies"],
        },
    ]


def _expected_empty_revocation_ledger(
    framework_commit: str, qualification_commit: str
) -> dict[str, Any]:
    return {
        "schema_version": "2.0.0",
        "release_target": "0.9.0",
        "persistent_identifier": None,
        "policy": "APPEND_ONLY_SIGNED_ANY_VERIFIED_SUFFIX_REOPEN_WITH_EPOCH_ROLLBACK",
        "framework_commit": framework_commit,
        "qualification_commit": qualification_commit,
        "activation_commit": "DERIVED_AS_SIGNED_COMMIT_FIRST_CONTAINING_THIS_LEDGER",
        "limits": {
            "records": MAX_REVOCATIONS,
            "cause_files_per_record": MAX_REVOCATION_CAUSE_FILES,
            "cause_file_bytes": MAX_REVOCATION_CAUSE_FILE_BYTES,
            "cause_total_bytes_per_record": MAX_REVOCATION_CAUSE_TOTAL_BYTES,
        },
        "records": [],
        "human_review_boundary": HUMAN_REVIEW_BOUNDARY,
        "release_authority_boundary": RELEASE_AUTHORITY_BOUNDARY,
    }


def _expected_empty_successor_registry(
    framework_commit: str, qualification_commit: str
) -> dict[str, Any]:
    return {
        "schema_version": "2.0.0",
        "release_target": "0.9.0",
        "persistent_identifier": None,
        "framework_commit": framework_commit,
        "qualification_commit": qualification_commit,
        "activation_commit": "DERIVED_AS_SIGNED_COMMIT_FIRST_CONTAINING_THIS_REGISTRY",
        "append_only": True,
        "epoch_model": "MONOTONIC_PER_TASK_F_I_C_D",
        "integration_model": "CENTRAL_ISOLATED_REGISTRY_DISPATCH",
        "limits": {
            "registrations": MAX_REGISTRATIONS,
            "first_parent_commits": MAX_FIRST_PARENT_COMMITS,
            "changed_paths_per_commit": MAX_CHANGED_PATHS_PER_COMMIT,
            "path_bytes": MAX_PROTOCOL_PATH_BYTES,
            "verifier_output_bytes_per_stream": MAX_VERIFIER_OUTPUT_BYTES,
            "verifier_seconds": MAX_VERIFIER_SECONDS,
            "verifier_aggregate_seconds": MAX_VERIFIER_AGGREGATE_SECONDS,
        },
        "registrations": [],
        "release_authority_boundary": RELEASE_AUTHORITY_BOUNDARY,
    }


def _claim_inventory(repo: Path, commit: str) -> list[dict[str, str]]:
    payload = _git_file(repo, commit, "docs/CLAIM-LEDGER.md")
    if len(payload) > MAX_REQUIREMENTS_BYTES:
        raise CurrentAuditError("CURRENT_AUDIT_CLAIM_LEDGER_RESOURCE_BOUND")
    claims: list[dict[str, str]] = []
    allowed_statuses = {
        "PROVEN",
        "PARTIAL",
        "PENDING",
        "UNPROVEN",
        "OUT OF SCOPE",
        "NARROWED",
        "REMOVED",
        "NOT_CLAIMED",
    }
    for raw_line in payload.decode("utf-8").splitlines():
        if not raw_line.startswith("| CL-"):
            continue
        parts = [part.strip() for part in raw_line.strip().strip("|").split("|")]
        status_positions = [
            index for index, part in enumerate(parts) if part in allowed_statuses
        ]
        if (
            len(parts) < 4
            or len(status_positions) != 1
            or status_positions[0] < 2
            or status_positions[0] >= len(parts) - 1
        ):
            raise CurrentAuditError("CURRENT_AUDIT_CLAIM_LEDGER_ROW_INVALID")
        status_index = status_positions[0]
        statement = "|".join(parts[1:status_index]).strip()
        support = "|".join(parts[status_index + 1 :]).strip()
        if not statement or not support:
            raise CurrentAuditError("CURRENT_AUDIT_CLAIM_LEDGER_ROW_INVALID")
        claims.append(
            {
                "id": parts[0],
                "status": parts[status_index],
                "statement_sha256": _sha256(statement.encode("utf-8")),
                "support_sha256": _sha256(support.encode("utf-8")),
            }
        )
    ids = [item["id"] for item in claims]
    if not claims or len(ids) != len(set(ids)):
        raise CurrentAuditError("CURRENT_AUDIT_CLAIM_LEDGER_INVENTORY_INVALID")
    return sorted(claims, key=lambda item: item["id"])


def _claim_ledger_scaffold_sha256(payload: bytes) -> str:
    """Bind every non-row byte while allowing typed claim-row transitions."""

    try:
        lines = payload.decode("utf-8").splitlines(keepends=True)
    except UnicodeDecodeError as error:
        raise CurrentAuditError("CURRENT_AUDIT_CLAIM_LEDGER_UTF8") from error
    normalized = "".join(
        "| <CLAIM_ROW>\n" if line.startswith("| CL-") else line for line in lines
    ).encode("utf-8")
    return _sha256(normalized)


def _source_claim_inventory(repo: Path, commit: str) -> list[dict[str, str]]:
    claims = _claim_inventory(repo, commit)
    ids = [item["id"] for item in claims]
    status_counts = {
        status: sum(item["status"] == status for item in claims)
        for status in {item["status"] for item in claims}
    }
    if (
        len(claims) != 52
        or len(ids) != len(set(ids))
        or status_counts != {"PROVEN": 45, "UNPROVEN": 5, "OUT OF SCOPE": 2}
    ):
        raise CurrentAuditError("CURRENT_AUDIT_CLAIM_LEDGER_INVENTORY_INVALID")
    return claims


def _claim_ids_with_statuses(
    inventory: list[dict[str, str]], statuses: set[str]
) -> list[str]:
    """Return ordered claim identifiers whose exact ledger rows have a status."""

    return [item["id"] for item in inventory if item["status"] in statuses]


def _expected_initial_active_claims(repo: Path, commit: str) -> dict[str, Any]:
    inventory = _source_claim_inventory(repo, commit)
    non_claimed = _claim_ids_with_statuses(inventory, {"OUT OF SCOPE"})
    active = [item["id"] for item in inventory if item["id"] not in non_claimed]
    return {
        "schema_version": "1.0.0",
        "release_target": "0.9.0",
        "persistent_identifier": None,
        "verified_prefix": 1,
        "overall_status": "NO_GO",
        "claim_ledger": _commit_regular_file_record(
            repo, commit, "docs/CLAIM-LEDGER.md"
        ),
        "public_surface_records": [
            _commit_regular_file_record(repo, commit, "docs/CLAIM-LEDGER.md")
        ],
        "claim_inventory": inventory,
        "asserted_claims": [item for item in inventory if item["id"] in active],
        "active_claims": active,
        "release_qualified_claims": [],
        "removed_claims": [],
        "non_claimed_claims": non_claimed,
        "narrowed_claims": [],
        "residual_limitations": ch_t000_initial_residual_limitations(),
        "current_epochs": {"CH-T000": 1},
        "tag_authorized": False,
        "github_release_authorized": False,
        "doi_authorized": False,
        "zenodo_authorized": False,
        "archive_authorized": False,
    }


def _activation_expected_fixed(
    repo: Path,
    framework_commit: str,
    qualification_commit: str,
    activation_commit: str,
) -> dict[str, Any]:
    evidence_files = [
        _commit_file_record(repo, activation_commit, path)
        for path in ACTIVATION_EVIDENCE_PATHS
    ]
    return {
        "schema_version": "1.0.0",
        "record_id": "CH-T000-SIGNED-TECHNICAL-ACTIVATION",
        "task_id": "CH-T000",
        "source_task_id": "T000",
        "release_target": "0.9.0",
        "author": {"name": "Sepehr Mahmoudian", "email": "sepmhn@gmail.com"},
        "persistent_identifier": None,
        "activation_effective_on": "SIGNED_COMMIT_FIRST_CONTAINING_THIS_RECORD_EXACT_EVIDENCE_AND_LEDGER_TRANSITION",
        "framework_commit": framework_commit,
        "qualification_commit": _signed_commit_binding(
            repo, qualification_commit, framework_commit
        ),
        "qualification_records": {
            "qualification": _commit_file_record(
                repo, qualification_commit, QUALIFICATION_PATH
            ),
            "review": _commit_file_record(repo, qualification_commit, REVIEW_PATH),
        },
        "evidence_files": evidence_files,
        "requirements_record": _commit_file_record(
            repo,
            activation_commit,
            EXPECTED_REQUIREMENTS_LEDGER["path"],
        ),
        "revocation_ledger_record": _commit_file_record(
            repo, activation_commit, REVOCATION_PATH
        ),
        "successor_registry_record": _commit_file_record(
            repo, activation_commit, SUCCESSOR_REGISTRY_PATH
        ),
        "active_claims_record": _commit_file_record(
            repo, activation_commit, ACTIVE_CLAIMS_PATH
        ),
        "terminal_transition": {
            "task_id": "CH-T000",
            "from": "OPEN",
            "to": "VERIFIED",
            "closure_commit": qualification_commit,
            "implementation_commits": [IMPLEMENTATION_COMMIT, framework_commit],
            "evidence_ids": list(TERMINAL_EVIDENCE_IDS),
            "reviewer_ids": ["CH-T000-R01", "CH-T000-R02", "CH-T000-R03"],
            "lens_projection": ch_t000_lens_projection(),
            "next_open_task": "CH-T001",
            "overall_release_status": "NO_GO",
        },
        "activation_blocker_resolutions": _activation_blocker_resolutions(),
        "decision": {
            "kind": "ACTIVATE_CH_T000_TECHNICAL_QUALIFICATION_ONLY",
            "claim_disposition": "NO_PUBLIC_CLAIM_CHANGE",
            "release_status": "NO_GO",
            "human": False,
            "named_human_approver": False,
        },
        "human_review_boundary": HUMAN_REVIEW_BOUNDARY,
        "release_authority_boundary": RELEASE_AUTHORITY_BOUNDARY,
        "revocation_policy": {
            "kind": "SIGNED_ANY_VERIFIED_SUFFIX_REOPEN_WITH_FRESH_EPOCH_REQUALIFICATION",
            "dedicated_commit_required": True,
            "reopen_target_and_all_descendants": True,
            "historical_evidence_retained": True,
            "in_flight_epoch_aborted": True,
            "product_and_claim_rollback_required": True,
            "overall_status_after_revocation": "NO_GO",
            "ledger_path": REVOCATION_PATH,
        },
    }


def _verify_activation_catalog_v2(
    repo: Path,
    activation_commit: str,
    qualification_commit: str,
    catalog: Any,
) -> None:
    layout = _activation_catalog_layout(qualification_commit)
    if not isinstance(catalog, dict) or list(catalog) != list(layout):
        raise CurrentAuditError("CURRENT_AUDIT_ACTIVATION_CATALOG_IDS")
    for evidence_id, expected in layout.items():
        entry = _require_fields(
            catalog.get(evidence_id),
            {
                "id",
                "kind",
                "subject_commit",
                "result",
                "files",
                "capture_operations",
                "log_integrity",
            },
            f"activation.catalog.{evidence_id}",
        )
        paths = expected["paths"]
        expected_files = [
            _commit_file_record(repo, activation_commit, path) for path in paths
        ]
        if not _strict_equal(
            entry,
            {
                "id": evidence_id,
                "kind": expected["kind"],
                "subject_commit": qualification_commit,
                "result": "PASS",
                "files": expected_files,
                "capture_operations": entry.get("capture_operations"),
                "log_integrity": entry.get("log_integrity"),
            },
        ):
            raise CurrentAuditError(
                f"CURRENT_AUDIT_ACTIVATION_CATALOG_ENTRY:{evidence_id}"
            )
        hosted = evidence_id in {"CH-T000-A04", "CH-T000-A05"}
        if not hosted and (
            entry.get("capture_operations") is not None
            or entry.get("log_integrity") is not None
        ):
            raise CurrentAuditError(
                f"CURRENT_AUDIT_ACTIVATION_CATALOG_UNEXPECTED:{evidence_id}"
            )
        if evidence_id == "CH-T000-A02":
            _verify_log_pair_v2(
                repo,
                activation_commit,
                entry,
                expected_head=qualification_commit,
                evidence_id=evidence_id,
                linux=False,
                label="a02",
            )
        elif evidence_id == "CH-T000-A03":
            _verify_log_pair_v2(
                repo,
                activation_commit,
                entry,
                expected_head=qualification_commit,
                evidence_id=evidence_id,
                linux=True,
                label="a03",
            )
        elif evidence_id in {"CH-T000-A04", "CH-T000-A05"}:
            _verify_hosted_evidence_v2(
                repo,
                activation_commit,
                entry,
                expected_head=qualification_commit,
                workflow="ci" if evidence_id.endswith("04") else "formal",
                label=evidence_id.lower(),
            )


def _verify_ch_t000_activation_v2(
    repo: Path,
    framework_commit: str,
    qualification_commit: str,
    activation_commit: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    activation, _payload = _read_commit_json(
        repo, activation_commit, ACTIVATION_PATH, "ch_t000.activation"
    )
    fixed = _activation_expected_fixed(
        repo, framework_commit, qualification_commit, activation_commit
    )
    if set(activation) != set(fixed) | {"evidence_catalog"}:
        raise CurrentAuditError("CURRENT_AUDIT_ACTIVATION_FIELDS")
    for key, expected in fixed.items():
        if not _strict_equal(activation.get(key), expected):
            raise CurrentAuditError(f"CURRENT_AUDIT_ACTIVATION_MISMATCH:{key}")
    _verify_activation_catalog_v2(
        repo,
        activation_commit,
        qualification_commit,
        activation.get("evidence_catalog"),
    )
    revocation, _revocation_payload = _read_commit_json(
        repo, activation_commit, REVOCATION_PATH, "ch_t000.revocation.empty"
    )
    if not _strict_equal(
        revocation,
        _expected_empty_revocation_ledger(framework_commit, qualification_commit),
    ):
        raise CurrentAuditError("CURRENT_AUDIT_EMPTY_REVOCATION_LEDGER_INVALID")
    registry, _registry_payload = _read_commit_json(
        repo, activation_commit, SUCCESSOR_REGISTRY_PATH, "task_registry.empty"
    )
    if not _strict_equal(
        registry,
        _expected_empty_successor_registry(framework_commit, qualification_commit),
    ):
        raise CurrentAuditError("CURRENT_AUDIT_EMPTY_SUCCESSOR_REGISTRY_INVALID")
    active_claims, _active_claims_payload = _read_commit_json(
        repo, activation_commit, ACTIVE_CLAIMS_PATH, "active_claims.initial"
    )
    if not _strict_equal(
        active_claims, _expected_initial_active_claims(repo, framework_commit)
    ):
        raise CurrentAuditError("CURRENT_AUDIT_INITIAL_ACTIVE_CLAIMS_INVALID")
    requirements_payload = _git_file(
        repo, activation_commit, EXPECTED_REQUIREMENTS_LEDGER["path"]
    )
    if len(requirements_payload) > MAX_REQUIREMENTS_BYTES:
        raise CurrentAuditError("CURRENT_AUDIT_RESOURCE_BOUND:activation.requirements")
    ledger = _load_json_bytes(requirements_payload, "activation.requirements")
    bootstrap = _load_json_bytes(
        _git_file(repo, IMPLEMENTATION_COMMIT, EXPECTED_REQUIREMENTS_LEDGER["path"]),
        "activation.requirements.bootstrap",
    )
    _verify_terminal_requirement_state(
        ledger,
        bootstrap,
        framework_commit=framework_commit,
        qualification_commit=qualification_commit,
        evidence_ids=list(TERMINAL_EVIDENCE_IDS),
        lens_projection=ch_t000_lens_projection(),
    )
    return activation, ledger


def _git_path_exists(repo: Path, commit: str, path: str) -> bool:
    return _git_tree_entry(repo, commit, path) is not None


def _require_commit_paths_unchanged(
    repo: Path, source_commit: str, head: str, paths: set[str], label: str
) -> None:
    for path in paths:
        if _git_tree_entry(repo, head, path) != _git_tree_entry(
            repo, source_commit, path
        ):
            raise CurrentAuditError(f"CURRENT_AUDIT_{label}_PROTECTED_DRIFT:{path}")


def _decompress_unbound_gzip(payload: bytes, label: str) -> bytes:
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(payload), mode="rb") as handle:
            result = handle.read(MAX_LOG_BYTES + 1)
            if len(result) > MAX_LOG_BYTES or handle.read(1):
                raise CurrentAuditError(f"CURRENT_AUDIT_GZIP_RESOURCE_BOUND:{label}")
    except CurrentAuditError:
        raise
    except (EOFError, OSError, gzip.BadGzipFile) as error:
        raise CurrentAuditError(f"CURRENT_AUDIT_GZIP_INVALID:{label}") from error
    return result


def _bounded_hygiene_total(current: int, increment: int) -> int:
    if (
        type(current) is not int
        or type(increment) is not int
        or current < 0
        or increment < 0
        or current > MAX_HYGIENE_TOTAL_BYTES
        or increment > MAX_HYGIENE_TOTAL_BYTES - current
    ):
        raise CurrentAuditError("CURRENT_AUDIT_HYGIENE_AGGREGATE_BOUND")
    return current + increment


def _verify_repository_hygiene(repo: Path, head: str) -> None:
    raw_tree = _git(repo, "ls-tree", "-r", "-l", "-z", head)
    gzip_paths: list[str] = []
    total = 0
    try:
        for raw_entry in raw_tree.removesuffix(b"\0").split(b"\0"):
            if not raw_entry:
                continue
            metadata, raw_path = raw_entry.split(b"\t", 1)
            mode, object_type, _oid, raw_size = metadata.split(b" ", 3)
            path = raw_path.decode("utf-8")
            size = int(raw_size)
            if object_type != b"blob" or mode not in {b"100644", b"100755", b"120000"}:
                raise CurrentAuditError("CURRENT_AUDIT_HYGIENE_TREE_INVALID")
            total = _bounded_hygiene_total(total, size)
            if path.lower().endswith(".log.gz"):
                gzip_paths.append(path)
    except (UnicodeDecodeError, ValueError) as error:
        raise CurrentAuditError("CURRENT_AUDIT_HYGIENE_TREE_INVALID") from error

    def matching_paths(token: bytes, label: str) -> list[str]:
        code, stdout, stderr = _run_bounded(
            _git_command(
                "grep",
                "-I",
                "-i",
                "-F",
                "-l",
                "-z",
                "-e",
                token.decode("ascii"),
                head,
                "--",
            ),
            cwd=repo,
            env=_sanitized_git_environment(),
            timeout_seconds=30,
            stdout_limit=MAX_GIT_BYTES,
            stderr_limit=MAX_GIT_BYTES,
            error_prefix=f"CURRENT_AUDIT_HYGIENE_GREP_{label}",
        )
        if code == 1 and not stdout and not stderr:
            return []
        if code != 0 or stderr or not stdout.endswith(b"\0"):
            raise CurrentAuditError(f"CURRENT_AUDIT_HYGIENE_GREP_FAILED:{label}")
        prefix = head.encode("ascii") + b":"
        try:
            paths = [
                item.removeprefix(prefix).decode("utf-8")
                for item in stdout.removesuffix(b"\0").split(b"\0")
            ]
        except UnicodeDecodeError as error:
            raise CurrentAuditError(
                f"CURRENT_AUDIT_HYGIENE_GREP_PATH:{label}"
            ) from error
        if any(not item.startswith(prefix) for item in stdout[:-1].split(b"\0")):
            raise CurrentAuditError(f"CURRENT_AUDIT_HYGIENE_GREP_PATH:{label}")
        return paths

    stale_paths = matching_paths(STALE_ACCOUNT_TOKEN, "ACCOUNT")
    restricted_paths = [
        path
        for path in matching_paths(PROHIBITED_GOVERNANCE_TOKEN, "DOCUMENT")
        if path.lower().endswith((".md", ".markdown", ".txt", ".log"))
    ]
    if stale_paths or restricted_paths:
        raise CurrentAuditError(
            "CURRENT_AUDIT_HYGIENE_TOKEN:" + (stale_paths + restricted_paths)[0]
        )
    for path in gzip_paths:
        lowered = _decompress_unbound_gzip(
            _git_file(repo, head, path), f"hygiene.{path}"
        ).lower()
        if STALE_ACCOUNT_TOKEN in lowered or PROHIBITED_GOVERNANCE_TOKEN in lowered:
            raise CurrentAuditError(f"CURRENT_AUDIT_HYGIENE_TOKEN:{path}")
    messages = _git(
        repo,
        "log",
        "--first-parent",
        "--format=%B%x00",
        f"{SOURCE_COMMIT}..{head}",
    )
    lowered_messages = messages.lower()
    if (
        PROHIBITED_GOVERNANCE_TOKEN in lowered_messages
        or PROHIBITED_DEGREE_TOKEN in lowered_messages
        or STALE_ACCOUNT_TOKEN in lowered_messages
    ):
        raise CurrentAuditError("CURRENT_AUDIT_HYGIENE_COMMIT_MESSAGE")


def _verify_changed_hygiene(
    repo: Path,
    commit: str,
    statuses: dict[str, str],
    current_total: int,
) -> int:
    """Scan each newly introduced/modified payload once while streaming history."""

    total = current_total
    for path, status in statuses.items():
        if status not in {"A", "M"}:
            continue
        payload = _git_file(repo, commit, path)
        lowered_path = path.lower()
        if lowered_path.endswith(".log.gz"):
            payload = _decompress_unbound_gzip(payload, f"hygiene.changed.{path}")
            plaintext = True
        else:
            try:
                payload.decode("utf-8")
                plaintext = b"\0" not in payload
            except UnicodeDecodeError:
                plaintext = False
        if not plaintext:
            continue
        total = _bounded_hygiene_total(total, len(payload))
        lowered = payload.lower()
        restricted_document = lowered_path.endswith(
            (".md", ".markdown", ".txt", ".log", ".log.gz")
        )
        if STALE_ACCOUNT_TOKEN in lowered or (
            restricted_document and PROHIBITED_GOVERNANCE_TOKEN in lowered
        ):
            raise CurrentAuditError(f"CURRENT_AUDIT_HYGIENE_TOKEN:{path}")
    return total


def _verify_post_activation_gate_retention(repo: Path, head: str) -> None:
    gate_records = {
        ".github/workflows/ci.yml": ("100644", CI_GATE_SHA256, CI_GATE_BYTES),
        "justfile": ("100644", JUST_GATE_SHA256, JUST_GATE_BYTES),
        "tools/p0r-exit-gate.sh": ("100755", P0_GATE_SHA256, P0_GATE_BYTES),
    }
    gate_payloads: dict[str, bytes] = {}
    for path, (expected_mode, expected_sha256, expected_bytes) in gate_records.items():
        payload = _git_file(repo, head, path)
        entry = _git_tree_entry(repo, head, path)
        worktree_payload = _read_repo_relative_bounded(
            repo, path, MAX_GIT_BYTES, f"post_activation.worktree.{path}"
        )
        if (
            entry is None
            or entry["mode"] != expected_mode
            or entry["type"] != "blob"
            or len(payload) != expected_bytes
            or _sha256(payload) != expected_sha256
            or worktree_payload != payload
        ):
            raise CurrentAuditError("CURRENT_AUDIT_POST_ACTIVATION_GATE_FILE_DRIFT")
        gate_payloads[path] = payload
    try:
        ci = gate_payloads[".github/workflows/ci.yml"].decode("utf-8")
        just = gate_payloads["justfile"].decode("utf-8")
        p0 = gate_payloads["tools/p0r-exit-gate.sh"].decode("utf-8")
    except UnicodeDecodeError as error:
        raise CurrentAuditError(
            "CURRENT_AUDIT_POST_ACTIVATION_GATE_ENCODING"
        ) from error
    wrapper_path = "tools/release/current-audit-gate.sh"
    wrapper = _git_file(repo, head, wrapper_path)
    expected_wrapper = (
        "#!/usr/bin/env bash\n"
        "# Immutable entry point for the current-head qualification framework.\n"
        "set -euo pipefail\n"
        "\n"
        "builtin unset BASH_ENV ENV CDPATH GLOBIGNORE\n"
        "builtin unalias -a 2>/dev/null || true\n"
        "builtin unset -f python3 2>/dev/null || true\n"
        "builtin hash -r\n"
        'PYTHON3="$(builtin type -P python3)"\n'
        "readonly PYTHON3\n"
        "\n"
        '"$PYTHON3" -I tools/release/test_verify_current_audit.py\n'
        '"$PYTHON3" -I tools/release/test_current_audit_resource_profile.py\n'
        '"$PYTHON3" -I tools/release/verify-current-audit.py\n'
    ).encode("utf-8")
    wrapper_entry = _git_tree_entry(repo, head, wrapper_path)
    wrapper_worktree = _read_repo_relative_bounded(
        repo,
        wrapper_path,
        MAX_GIT_BYTES,
        "post_activation.worktree.current_audit_wrapper",
    )
    if (
        wrapper != expected_wrapper
        or wrapper_worktree != wrapper
        or wrapper_entry is None
        or wrapper_entry["mode"] != "100755"
        or wrapper_entry["type"] != "blob"
    ):
        raise CurrentAuditError("CURRENT_AUDIT_POST_ACTIVATION_WRAPPER_DRIFT")
    ci_job_match = re.search(
        r"(?ms)^  supply-chain:\n(?P<body>.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)", ci
    )
    launcher = (
        "/usr/bin/env -u BASH_ENV -u ENV /bin/bash --noprofile --norc "
        "tools/release/current-audit-gate.sh"
    )
    ci_prefix = (
        "    permissions:\n"
        "      contents: read\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7.0.0\n"
        "        with:\n"
        "          fetch-depth: 0\n"
        "          persist-credentials: false\n"
        "      - name: Install pinned Python\n"
        "        uses: actions/setup-python@a309ff8b426b58ec0e2a45f0f869d46889d02405 # v6.2.0\n"
        "        with:\n"
        '          python-version: "3.14.6"\n'
        "          check-latest: false\n"
        "      - name: Harden pinned Python permissions\n"
        "        shell: /bin/bash --noprofile --norc -euo pipefail {0}\n"
        "        run: |\n"
        '          PYTHON3="$(/usr/bin/readlink -f "${pythonLocation}/bin/python3")"\n'
        '          /usr/bin/chmod go-w "$PYTHON3"\n'
        '          /usr/bin/test -x "$PYTHON3"\n'
        "      - name: Preload isolated task-runner image\n"
        "        run: /usr/bin/docker pull python@sha256:4a3a38c8710794e278c3651352dd6195d5798eb6ec5ad41db6258e753c9e4ceb\n"
        "      - name: Verify current-head 0.9 audit cut\n"
        f"        run: {launcher}\n"
    )
    if ci_job_match is None:
        raise CurrentAuditError("CURRENT_AUDIT_POST_ACTIVATION_CI_GATE_DRIFT")
    ci_body = ci_job_match.group("body")
    ci_gate_step = (
        f"      - name: Verify current-head 0.9 audit cut\n        run: {launcher}\n"
    )
    gate_steps = re.findall(
        r"(?ms)^      - name: Verify current-head 0\.9 audit cut\n"
        r".*?(?=^      - |\Z)",
        ci_body,
    )
    if (
        ci.count('on:\n  push:\n    branches: ["**"]\n  pull_request:\n') != 1
        or ci.count("  supply-chain:\n") != 1
        or not ci_body.startswith(ci_prefix)
        or gate_steps != [ci_gate_step]
        or re.search(
            r"(?m)^    (?:if|needs|continue-on-error|env|defaults|timeout-minutes):\s*",
            ci_body,
        )
        or re.search(r"(?m)^(?:env|defaults):\s*", ci)
    ):
        raise CurrentAuditError("CURRENT_AUDIT_POST_ACTIVATION_CI_GATE_DRIFT")
    just_verify = f"verify-current-audit:\n    {launcher}\n"
    just_ci = (
        f"ci:\n    {launcher}\n"
        "    /usr/bin/env -u BASH_ENV -u ENV /bin/bash --noprofile --norc "
        "tools/p0r-exit-gate.sh\n"
    )
    shell_lines = re.findall(r"(?m)^set shell\s*:=.*$", just)
    if (
        just.count(just_verify) != 1
        or just.count(just_ci) != 1
        or just.count("default: ci\n") != 1
        or shell_lines
        != [
            'set shell := ["/usr/bin/env", "-u", "BASH_ENV", "-u", "ENV", '
            '"/bin/bash", "--noprofile", "--norc", "-uc"]'
        ]
    ):
        raise CurrentAuditError("CURRENT_AUDIT_POST_ACTIVATION_JUST_GATE_DRIFT")
    p0_gate = f'run "current-head audit gate" {launcher}\n'
    p0_baseline_runs = [
        p0_gate.rstrip("\n"),
        'run "rustfmt"              cargo fmt --all --check',
        'run "clippy (deny warns)" cargo clippy --workspace --all-targets --all-features --locked -- -D warnings',
        'run "tests"               cargo test --workspace --all-targets --all-features --locked',
        'run "doc tests"           cargo test --workspace --doc --locked',
        'run "docs (deny warns)"   env "RUSTDOCFLAGS=-D warnings" cargo doc --workspace --no-deps --all-features --locked',
        'run "no-default build"    cargo build --workspace --no-default-features --locked',
        'run "default clippy"      cargo clippy --workspace --locked -- -D warnings',
        'run "clean build"         clean_build_gate',
        'run "dependency policy"   cargo deny --all-features check',
        'run "source pins"         python3 tools/verify-pins.py',
        'run "CI/formal pins"       python3 tools/verify-ci-pins.py',
        'run "release audit tests" python3 -m unittest tools/release/test_verify_audit_inputs.py',
        'run "release audit cut"   python3 tools/release/verify-audit-inputs.py',
        'run "release authority tests" python3 -m unittest tools/release/test_verify_authority_model.py',
        'run "release authority model" python3 tools/release/verify-authority-model.py',
        'run "release evidence generator tests" python3 -m unittest tools/release/test_generate_task_evidence.py',
        'run "generated task evidence" python3 tools/release/verify-task-evidence.py --all-present',
        'run "release protection tests" python3 -m unittest tools/release/test_verify_protection_model.py',
        'run "release protection model" python3 tools/release/verify-protection-model.py',
        'run "evidence layout"     python3 tools/verify-evidence.py',
        'run "offline Zenoh profile tests" python3 -m unittest tools/test_secure_zenoh.py tools/test_live_secure_zenoh.py',
        'run "live Gate dev smoke tests" python3 -m unittest tools/test_live_gate_dev_smoke.py tools/test_live_gate_dev_smoke_verifier.py',
        'run "offline Zenoh profile" python3 tools/verify-secure-zenoh.py',
        'run "retained live Zenoh evidence" python3 tools/verify-live-secure-zenoh.py',
        'run "retained live Gate dev smoke" python3 tools/verify-live-gate-dev-smoke.py',
        'run "forbidden claims"    python3 tools/verify-claims.py',
        'run "generated vectors"   python3 tools/verify-generated.py',
        'run "interop (COSE/CBOR)" interop_gate',
        'run "diff hygiene"        git diff --check',
    ]
    run_helper = (
        "run() {\n"
        '  local name="$1"\n'
        "  shift\n"
        "  printf '\\n=== %s ===\\n' \"$name\"\n"
        '  if "$@"; then\n'
        "    printf '  PASS: %s\\n' \"$name\"\n"
        "    pass=$((pass + 1))\n"
        "  else\n"
        "    printf '  FAIL: %s\\n' \"$name\"\n"
        "    fail=$((fail + 1))\n"
        '    failed+=("$name")\n'
        "  fi\n"
        "}\n"
    )
    interop_helper = (
        "interop_gate() {\n"
        "  local tmp\n"
        '  tmp="$(mktemp)"\n'
        '  cargo run -q -p haldir-crypto --example emit_interop_vectors >"$tmp" 2>/dev/null || return 1\n'
        '  diff -u tools/interop/vectors.json "$tmp" || { rm -f "$tmp"; return 1; }\n'
        '  rm -f "$tmp"\n'
        "  python3 tools/interop/verify_cose.py tools/interop/vectors.json\n"
        "}\n"
    )
    clean_build_helper = (
        "clean_build_gate() {\n"
        "  local tmp\n"
        '  tmp="$(mktemp -d)" || return 1\n'
        '  CARGO_TARGET_DIR="$tmp" cargo build --workspace --locked\n'
        "  local status=$?\n"
        '  rm -rf "$tmp"\n'
        '  return "$status"\n'
        "}\n"
    )
    p0_epilogue = (
        "printf '\\n============================================================\\n'\n"
        'printf \'P0-R exit gate: %d passed, %d failed\\n\' "$pass" "$fail"\n'
        "if (( fail != 0 )); then\n"
        "  printf 'failed: %s\\n' \"${failed[*]}\"\n"
        "  printf 'Note: the TLA+ check (CL-FORMAL-01) runs in CI, not here.\\n'\n"
        "  builtin exit 1\n"
        "fi\n"
        "printf 'All offline P0-R gates passed. (TLA+ check runs in CI: CL-FORMAL-01.)\\n'\n"
    )
    first_run = re.search(r'(?m)^run "[^\n]+$', p0)
    job_keys = re.findall(r"(?m)^    ([A-Za-z0-9_-]+):", ci_body)
    fail_assignments = re.findall(r"(?m)^[ \t]*fail=.*$", p0)
    pass_assignments = re.findall(r"(?m)^[ \t]*pass=.*$", p0)
    observed_runs = re.findall(r"(?m)^run [^\n]+$", p0)
    function_definitions = re.findall(r"(?m)^([A-Za-z_][A-Za-z0-9_]*)\s*\(\)\s*\{", p0)
    if (
        p0.count(p0_gate) != 1
        or len(p0.encode("utf-8")) != P0_GATE_BYTES
        or _sha256(p0.encode("utf-8")) != P0_GATE_SHA256
        or p0.count(run_helper) != 1
        or p0.count(interop_helper) != 1
        or p0.count(clean_build_helper) != 1
        or observed_runs != p0_baseline_runs
        or function_definitions != ["run", "interop_gate", "clean_build_gate"]
        or re.search(r"(?m)^\s*function\b", p0)
        or len(re.findall(r"(?m)\(\)\s*\{", p0)) != 3
        or job_keys != ["permissions", "runs-on", "steps"]
        or len(
            re.findall(
                r"(?m)^(?:function\s+run\s*(?:\(\))?|run\s*\(\))\s*\{",
                p0,
            )
        )
        != 1
        or first_run is None
        or first_run.group(0) + "\n" != p0_gate
        or re.search(
            r"(?m)^(?:function\s+(?:python3|bash)\s*(?:\(\))?|(?:python3|bash)\s*\(\))\s*\{",
            p0,
        )
        or re.search(r"(?m)^\s*export\s+-f\b", p0)
        or re.search(r"(?m)^\s*alias\s+(?:run|python3|bash)=", p0)
        or re.search(r"(?m)^\s*(?:export\s+)?PATH=", p0)
        or re.search(r"(?m)^\s*(?:eval|source|trap)\b", p0)
        or re.search(r"(?m)^\s*\.\s+", p0)
        or p0.count("set -u\n") != 1
        or p0.count("pass=0\nfail=0\ndeclare -a failed\n") != 1
        or fail_assignments != ["fail=0", "    fail=$((fail + 1))"]
        or pass_assignments != ["pass=0", "    pass=$((pass + 1))"]
        or p0.count('    failed+=("$name")\n') != 1
        or not p0.endswith(p0_epilogue)
        or re.search(r"(?m)^\s*(?:exit\s+0|return\s+0)\s*$", p0)
    ):
        raise CurrentAuditError("CURRENT_AUDIT_POST_ACTIVATION_P0_GATE_DRIFT")


def _task_epoch_paths(task_id: str, epoch: int) -> dict[str, str]:
    if (
        re.fullmatch(r"CH-T(?:00\d|0[1-9]\d|1[01]\d|12[0-5])", task_id) is None
        or type(epoch) is not int
        or epoch < 1
        or epoch > MAX_REGISTRATIONS
    ):
        raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_TASK_EPOCH_INVALID")
    task_slug = task_id.lower()
    epoch_slug = f"e{epoch:04d}"
    tool_root = f"tools/release/tasks/{task_slug}/{epoch_slug}"
    data_root = f"release/0.9.0/current-head/tasks/{task_slug}/{epoch_slug}"
    return {
        "tool_root": tool_root,
        "data_root": data_root,
        "verifier": f"{tool_root}/verify.py",
        "tests": f"{tool_root}/test_verify.py",
        "freeze": f"{data_root}/freeze.json",
        "qualification": f"{data_root}/qualification.json",
        "activation": f"{data_root}/activation.json",
        "verifier_receipt": f"{data_root}/verifier-receipt.json",
    }


def _protocol_registration_key(task_id: str, epoch: int) -> str:
    return f"{task_id}:e{epoch:04d}"


def _require_protocol_path_list(
    value: Any, label: str, *, prefix: str, maximum: int
) -> list[str]:
    paths = _require_string_list(value, label, minimum=0, unique=True)
    if len(paths) > maximum or paths != sorted(paths):
        raise CurrentAuditError(f"CURRENT_AUDIT_PROTOCOL_PATH_LIST_INVALID:{label}")
    for index, path in enumerate(paths):
        _require_protocol_path(path, f"{label}.{index}")
        if not path.startswith(prefix):
            raise CurrentAuditError(f"CURRENT_AUDIT_PROTOCOL_PATH_SCOPE:{label}")
    return paths


def _protocol_file_records(
    repo: Path, commit: str, paths: list[str]
) -> list[dict[str, Any]]:
    return [_commit_regular_file_record(repo, commit, path) for path in paths]


def _verified_prefix(tasks: list[dict[str, Any]]) -> int:
    _verify_dependency_cascade(tasks)
    return sum(task.get("status") == "VERIFIED" for task in tasks)


def _initial_claims_before_ch_t000(repo: Path, framework_commit: str) -> dict[str, Any]:
    initial = _expected_initial_active_claims(repo, framework_commit)
    initial["verified_prefix"] = 0
    initial["current_epochs"] = {}
    initial["residual_limitations"] = []
    return initial


def _source_release_signer(repo: Path) -> dict[str, str]:
    """Return the single immutable signer anchored by the source cut."""

    try:
        principal, public_key = (
            _git_file(repo, SOURCE_COMMIT, "release/0.9.0/allowed-signers")
            .decode("utf-8")
            .strip()
            .split(" ", 1)
        )
    except (UnicodeDecodeError, ValueError) as error:
        raise CurrentAuditError("CURRENT_AUDIT_SOURCE_SIGNER_INVALID") from error
    if (
        principal != SOURCE_SIGNATURE["principal"]
        or re.fullmatch(r"ssh-ed25519 [A-Za-z0-9+/]+={0,2}", public_key) is None
    ):
        raise CurrentAuditError("CURRENT_AUDIT_SOURCE_SIGNER_INVALID")
    return {
        "principal": principal,
        "public_key": public_key,
        "key_fingerprint": SOURCE_SIGNATURE["key_fingerprint"],
    }


def _validate_frozen_reviewer_registry(
    repo: Path,
    value: Any,
    *,
    task_id: str,
    requirements: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Anchor every later review identity and key in the signed F contract."""

    if not isinstance(value, list) or len(value) != len(requirements):
        raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_REVIEWER_REGISTRY")
    source_signer = _source_release_signer(repo)
    observed: list[dict[str, Any]] = []
    key_identities: dict[tuple[str, str], dict[str, Any]] = {}
    principal_bindings: dict[str, tuple[dict[str, Any], str, str]] = {}
    fingerprint_cache: dict[str, str] = {}
    for index, (raw_record, requirement) in enumerate(
        zip(value, requirements, strict=True)
    ):
        record = _require_fields(
            raw_record,
            {
                "requirement_id",
                "kind",
                "path",
                "reviewer",
                "public_key",
                "key_fingerprint",
                "trust_basis",
            },
            f"protocol.reviewer_registry.{index}",
        )
        reviewer = _require_fields(
            record.get("reviewer"),
            {"name", "principal", "classification", "organization"},
            f"protocol.reviewer_registry.{index}.reviewer",
        )
        for field in ("name", "principal", "organization"):
            identity_value = _require_nonempty_string(
                reviewer.get(field), f"protocol.reviewer_registry.{index}.{field}"
            )
            if (
                identity_value != identity_value.strip()
                or unicodedata.normalize("NFC", identity_value) != identity_value
                or any(
                    unicodedata.category(character).startswith("C")
                    for character in identity_value
                )
            ):
                raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_REVIEWER_REGISTRY")
        public_key = record.get("public_key")
        fingerprint = record.get("key_fingerprint")
        kind = requirement["kind"]
        if (
            record.get("requirement_id") != requirement["id"]
            or record.get("kind") != kind
            or record.get("path") != requirement["path"]
            or not isinstance(public_key, str)
            or re.fullmatch(r"ssh-ed25519 [A-Za-z0-9+/]+={0,2}", public_key) is None
            or not isinstance(fingerprint, str)
            or re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}", fingerprint) is None
            or re.fullmatch(r"[^\s\x00-\x1f\x7f]{3,254}", reviewer["principal"]) is None
        ):
            raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_REVIEWER_REGISTRY")
        actual_fingerprint = fingerprint_cache.get(public_key)
        if actual_fingerprint is None:
            actual_fingerprint = _ssh_public_key_fingerprint(
                repo, public_key, f"protocol.reviewer_registry.{index}"
            )
            fingerprint_cache[public_key] = actual_fingerprint
        if fingerprint != actual_fingerprint:
            raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_REVIEWER_REGISTRY")
        if kind in LEAD_REVIEW_KINDS:
            if (
                reviewer
                != {
                    "name": "Sepehr Mahmoudian",
                    "principal": "sepmhn@gmail.com",
                    "classification": "RELEASE_LEAD",
                    "organization": "SEPAHEAD",
                }
                or public_key != source_signer["public_key"]
                or fingerprint != source_signer["key_fingerprint"]
                or record.get("trust_basis") != "SOURCE_RELEASE_SIGNER"
            ):
                raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_REVIEWER_REGISTRY")
        else:
            classification = reviewer.get("classification")
            if (
                classification
                not in {"INDEPENDENT_AUTOMATED", "INDEPENDENT_NAMED_HUMAN"}
                or (
                    kind in EXTERNAL_HUMAN_REVIEW_KINDS
                    and classification != "INDEPENDENT_NAMED_HUMAN"
                )
                or reviewer["name"] == "Sepehr Mahmoudian"
                or reviewer["principal"] == source_signer["principal"]
                or reviewer["organization"].casefold() == "sepahead"
                or public_key == source_signer["public_key"]
                or fingerprint == source_signer["key_fingerprint"]
                or record.get("trust_basis") != "AUTHOR_VERIFIED_OUT_OF_BAND_BEFORE_F"
            ):
                raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_REVIEWER_REGISTRY")
        key_identity = key_identities.get((public_key, fingerprint))
        if key_identity is not None and not _strict_equal(key_identity, reviewer):
            raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_REVIEWER_KEY_ALIAS")
        principal_binding = principal_bindings.get(reviewer["principal"])
        current_binding = (copy.deepcopy(reviewer), public_key, fingerprint)
        if principal_binding is not None and not _strict_equal(
            principal_binding, current_binding
        ):
            raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_REVIEWER_PRINCIPAL_ALIAS")
        key_identities[(public_key, fingerprint)] = copy.deepcopy(reviewer)
        principal_bindings[reviewer["principal"]] = current_binding
        observed.append(copy.deepcopy(record))
    if [item["requirement_id"] for item in observed] != sorted(
        item["requirement_id"] for item in observed
    ):
        raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_REVIEWER_REGISTRY_ORDER")
    return observed


def _expected_handoff_task_contract(
    bootstrap_task: dict[str, Any],
) -> dict[str, Any]:
    return {
        "source_task_id": bootstrap_task["source_task_id"],
        "source_record_sha256": bootstrap_task["source_record_sha256"],
        "lead_review_required": bootstrap_task["lead_review_required"],
        "preconditions": list(HANDOFF_PRECONDITIONS),
        "procedure": list(HANDOFF_PROCEDURE),
        "mandatory_counterfactuals": list(HANDOFF_COUNTERFACTUALS),
        "required_evidence": list(HANDOFF_REQUIRED_EVIDENCE),
        "completion_rule": HANDOFF_COMPLETION_RULE,
        "bootstrap_amendment": copy.deepcopy(
            BOOTSTRAP_AMENDMENT_SEMANTICS.get(
                bootstrap_task["id"],
                {"exception": None, "postconditions": []},
            )
        ),
        "twenty_lenses": [
            {"id": f"L{index:02d}", "name": name, "question": question}
            for index, (name, question) in enumerate(
                zip(LENS_NAMES, HANDOFF_LENS_QUESTIONS, strict=True), start=1
            )
        ],
    }


def _require_source_review_kinds(task_id: str, observed_kinds: list[str]) -> None:
    """Require the handoff's independent and post-implementation review roles."""

    required = {"INDEPENDENT_REVIEW", "LEAD_IMPLEMENTATION_REVIEW"}
    required.update(
        {
            "CH-T115": {
                "INDEPENDENT_REVIEW",
                "LEAD_IMPLEMENTATION_REVIEW",
                "EXTERNAL_CRYPTOGRAPHIC_REVIEW",
                "EXTERNAL_FORMAL_METHODS_REVIEW",
                "EXTERNAL_SECURE_DEPLOYMENT_REVIEW",
            },
            "CH-T120": {
                "INDEPENDENT_REVIEW",
                "EXTERNAL_CLEAN_ROOM_REPRODUCTION",
                "LEAD_IMPLEMENTATION_REVIEW",
            },
            "CH-T124": {
                "INDEPENDENT_REVIEW",
                "LEAD_IMPLEMENTATION_REVIEW",
                "LEAD_ONLY_TWENTY_LENS_DIFF_REVIEW",
            },
            "CH-T125": {
                "INDEPENDENT_REVIEW",
                "LEAD_IMPLEMENTATION_REVIEW",
                "SIGNED_RELEASE_DECISION_REVIEW",
            },
        }.get(task_id, set())
    )
    if not required.issubset(observed_kinds):
        raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_SOURCE_REVIEW_INCOMPLETE")


def _implementation_path_is_forbidden(path: str) -> bool:
    exact = {
        *BASE_IMMUTABLE_PATHS,
        *FRAMEWORK_CORE_FROZEN_PATHS,
        *QUALIFIED_OPEN_DATA_PATHS,
        ACTIVATION_PATH,
        REVOCATION_PATH,
        SUCCESSOR_REGISTRY_PATH,
        ACTIVE_CLAIMS_PATH,
        EXPECTED_REQUIREMENTS_LEDGER["path"],
        *ACTIVATION_EVIDENCE_PATHS,
        ".github/workflows/ci.yml",
        "justfile",
        "tools/p0r-exit-gate.sh",
        "tools/release/current-audit-gate.sh",
    }
    prefixes = (
        "tools/release/tasks/",
        "release/0.9.0/current-head/tasks/",
        "release/0.9.0/current-head/closures/",
        "release/0.9.0/current-head/evidence/",
        "release/0.9.0/current-head/reviews/",
        "release/0.9.0/current-head/handoff/",
    )
    return path in exact or path.startswith(prefixes)


def _surface_classification(path: str) -> str:
    """Conservatively classify a planned product path for consumer review."""

    lowered = path.casefold()
    name = PurePosixPath(path).name.casefold()
    if name.startswith("readme") or lowered.startswith("docs/"):
        return "PUBLIC_DOCUMENTATION"
    if lowered.startswith(("crates/", "schemas/", "include/", "ffi/")):
        return "PUBLIC_API_OR_SCHEMA"
    if lowered.startswith(
        (".github/", "config/", "configs/", "deploy/", "profiles/")
    ) or name in {"cargo.toml", "cargo.lock", "justfile"}:
        return "BUILD_OR_DEPLOYMENT"
    if (
        lowered.startswith("tools/")
        or "/tests/" in f"/{lowered}"
        or name.startswith("test_")
    ):
        return "TEST_OR_TOOLING"
    return "INTERNAL_IMPLEMENTATION"


def _validate_affected_surface_inventory(
    repo: Path,
    commit: str,
    value: Any,
    *,
    plan: dict[str, str],
) -> list[dict[str, Any]]:
    """Require an exact per-path consumer and public-surface disposition."""

    if not isinstance(value, list) or len(value) != len(plan):
        raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_SURFACE_INVENTORY")
    observed: list[dict[str, Any]] = []
    public_classes = {
        "PUBLIC_DOCUMENTATION",
        "PUBLIC_API_OR_SCHEMA",
        "BUILD_OR_DEPLOYMENT",
    }
    for index, (raw_record, (plan_path, plan_status)) in enumerate(
        zip(value, plan.items(), strict=True)
    ):
        record = _require_fields(
            raw_record,
            {
                "path",
                "planned_status",
                "classification",
                "claim_relevance",
                "in_repository_consumers",
                "external_consumers",
                "rationale",
            },
            f"protocol.surface_inventory.{index}",
        )
        in_repository = _require_string_list(
            record.get("in_repository_consumers"),
            f"protocol.surface_inventory.{index}.in_repository_consumers",
            minimum=0,
            unique=True,
        )
        external = _require_string_list(
            record.get("external_consumers"),
            f"protocol.surface_inventory.{index}.external_consumers",
            minimum=0,
            unique=True,
        )
        classification = _surface_classification(plan_path)
        expected_relevance = (
            "PUBLIC_CLAIM_REVIEW_REQUIRED"
            if classification in public_classes
            else "SEMANTIC_REVIEW_REQUIRED"
        )
        rationale = _require_nonempty_string(
            record.get("rationale"), f"protocol.surface_inventory.{index}.rationale"
        )
        if (
            record.get("path") != plan_path
            or record.get("planned_status") != plan_status
            or record.get("classification") != classification
            or record.get("claim_relevance") != expected_relevance
            or in_repository != sorted(in_repository)
            or external != sorted(external)
            or any(
                consumer in plan or not _git_path_exists(repo, commit, consumer)
                for consumer in in_repository
            )
            or (classification in public_classes and not in_repository and not external)
            or any(len(consumer.encode("utf-8")) > 1024 for consumer in external)
            or len(rationale.encode("utf-8")) > 4096
        ):
            raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_SURFACE_INVENTORY")
        for consumer in in_repository:
            _require_protocol_path(consumer, "protocol.surface_inventory.consumer")
        observed.append(copy.deepcopy(record))
    return observed


def _validate_successor_freeze_contract(
    repo: Path,
    commit: str,
    contract_path: str,
    *,
    task_id: str,
    epoch: int,
    bootstrap_task: dict[str, Any],
    prior_claims: dict[str, Any],
    prior_claims_record: dict[str, Any],
) -> dict[str, Any]:
    contract, _payload = _read_commit_json(
        repo, commit, contract_path, f"protocol.freeze.{task_id}.{epoch}"
    )
    fields = {
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
    }
    if set(contract) != fields:
        raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_FREEZE_FIELDS")
    paths = _task_epoch_paths(task_id, epoch)
    if not _strict_equal(
        {
            "schema_version": contract.get("schema_version"),
            "task_id": contract.get("task_id"),
            "epoch": contract.get("epoch"),
            "release_target": contract.get("release_target"),
            "author": contract.get("author"),
            "persistent_identifier": contract.get("persistent_identifier"),
            "effective_on": contract.get("effective_on"),
            "task_identity": contract.get("task_identity"),
            "handoff_task_contract": contract.get("handoff_task_contract"),
            "prior_state": contract.get("prior_state"),
            "qualification_path": contract.get("qualification_path"),
            "activation_path": contract.get("activation_path"),
            "verifier_receipt_path": contract.get("verifier_receipt_path"),
        },
        {
            "schema_version": "1.0.0",
            "task_id": task_id,
            "epoch": epoch,
            "release_target": "0.9.0",
            "author": {"name": "Sepehr Mahmoudian", "email": "sepmhn@gmail.com"},
            "persistent_identifier": None,
            "effective_on": "SIGNED_COMMIT_FIRST_CONTAINING_EXACT_FREEZE_AND_REGISTRATION",
            "task_identity": {
                field: bootstrap_task[field] for field in REQUIREMENT_IDENTITY_FIELDS
            },
            "handoff_task_contract": _expected_handoff_task_contract(bootstrap_task),
            "prior_state": {
                "verified_prefix": int(task_id.removeprefix("CH-T")),
                "active_claims": prior_claims_record,
            },
            "qualification_path": paths["qualification"],
            "activation_path": paths["activation"],
            "verifier_receipt_path": paths["verifier_receipt"],
        },
    ):
        raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_FREEZE_IDENTITY")
    plan = contract.get("implementation_plan")
    empty_reason = contract.get("empty_implementation_reason")
    if (
        not isinstance(plan, dict)
        or len(plan) > MAX_CHANGED_PATHS_PER_COMMIT
        or (
            not plan and (not isinstance(empty_reason, str) or not empty_reason.strip())
        )
        or (plan and empty_reason is not None)
    ):
        raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_IMPLEMENTATION_PLAN")
    observed_plan: dict[str, str] = {}
    for raw_path, status in plan.items():
        path = _require_protocol_path(raw_path, "protocol.implementation_plan")
        if (
            status not in {"A", "M", "D"}
            or path in observed_plan
            or _implementation_path_is_forbidden(path)
        ):
            raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_IMPLEMENTATION_PLAN")
        observed_plan[path] = status
    if list(plan) != sorted(plan):
        raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_IMPLEMENTATION_PLAN_ORDER")
    if plan.get("docs/CLAIM-LEDGER.md") == "D":
        raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_CLAIM_LEDGER_DELETION")
    contract["affected_surface_inventory"] = _validate_affected_surface_inventory(
        repo,
        commit,
        contract.get("affected_surface_inventory"),
        plan=observed_plan,
    )
    triggers = _require_fields(
        contract.get("verification_triggers"),
        {"paths", "roots"},
        "protocol.verification_triggers",
    )
    trigger_paths = _require_string_list(
        triggers.get("paths"),
        "protocol.verification_triggers.paths",
        minimum=0,
        unique=True,
    )
    trigger_roots = _require_string_list(
        triggers.get("roots"),
        "protocol.verification_triggers.roots",
        minimum=0,
        unique=True,
    )
    if (
        not trigger_paths
        and not trigger_roots
        or trigger_paths != sorted(trigger_paths)
        or trigger_roots != sorted(trigger_roots)
        or len(trigger_paths) + len(trigger_roots) > MAX_CHANGED_PATHS_PER_COMMIT
    ):
        raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_VERIFICATION_TRIGGERS")
    for trigger_path in trigger_paths:
        _require_protocol_path(trigger_path, "protocol.verification_trigger.path")
    for trigger_root in trigger_roots:
        if (
            not trigger_root.endswith("/")
            or _require_protocol_path(
                trigger_root.removesuffix("/"),
                "protocol.verification_trigger.root",
            )
            + "/"
            != trigger_root
        ):
            raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_VERIFICATION_TRIGGERS")
    if any(
        path not in trigger_paths
        and not any(path.startswith(root) for root in trigger_roots)
        for path in plan
    ):
        raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_VERIFICATION_TRIGGER_SCOPE")
    controls = contract.get("normative_controls")
    counterfactuals = contract.get("mandatory_counterfactuals")
    if (
        not isinstance(controls, list)
        or not controls
        or len(controls) > 64
        or not isinstance(counterfactuals, list)
        or not counterfactuals
        or len(counterfactuals) > 64
    ):
        raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_CONTROLS_INVALID")
    for kind, items in (("control", controls), ("counterfactual", counterfactuals)):
        ids: list[str] = []
        for item in items:
            item = _require_fields(
                item,
                {"id", "statement", "accepted_test_id", "rejected_test_id"},
                f"protocol.{kind}",
            )
            item_id = _require_nonempty_string(item.get("id"), f"protocol.{kind}.id")
            ids.append(item_id)
            statement = _require_nonempty_string(
                item.get("statement"), f"protocol.{kind}.statement"
            )
            if (
                kind == "control"
                and re.search(r"\bSHALL(?: NOT)?\b", statement) is None
            ):
                raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_CONTROL_NOT_NORMATIVE")
            _require_nonempty_string(
                item.get("accepted_test_id"), f"protocol.{kind}.accepted"
            )
            _require_nonempty_string(
                item.get("rejected_test_id"), f"protocol.{kind}.rejected"
            )
            if (
                re.fullmatch(rf"{task_id}-(?:N|CF)\d{{2,3}}", item_id) is None
                or item["accepted_test_id"] == item["rejected_test_id"]
            ):
                raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_CONTROL_ID_INVALID")
        if len(ids) != len(set(ids)):
            raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_CONTROL_DUPLICATE")
        if kind == "counterfactual" and [item["statement"] for item in items] != list(
            HANDOFF_COUNTERFACTUALS
        ):
            raise CurrentAuditError(
                "CURRENT_AUDIT_PROTOCOL_COUNTERFACTUALS_NOT_SOURCE_EXACT"
            )
    test_payload = _git_file(repo, commit, paths["tests"])
    if len(test_payload) > MAX_JSON_BYTES:
        raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_TEST_FILE_BOUND")
    discovered_test_ids = set(
        _discover_unittest_test_ids(test_payload, paths["tests"], strict_runtime=True)
    )
    cited_test_ids = {
        item[field]
        for items in (controls, counterfactuals)
        for item in items
        for field in ("accepted_test_id", "rejected_test_id")
    }
    if not cited_test_ids.issubset(discovered_test_ids):
        raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_CITED_TEST_MISSING")
    controls_digest = _sha256(
        json.dumps(
            {"controls": controls, "counterfactuals": counterfactuals},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    )
    if not _strict_equal(
        contract.get("lead_approval"),
        {
            "approver": {
                "name": "Sepehr Mahmoudian",
                "email": "sepmhn@gmail.com",
            },
            "normative_controls_sha256": controls_digest,
            "effective_on": "SIGNED_F_COMMIT_CONTAINING_EXACT_CONTROLS_BEFORE_IMPLEMENTATION",
        },
    ):
        raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_LEAD_APPROVAL")
    data_root = paths["data_root"]
    requirement_kinds: dict[str, list[str]] = {}
    for field, prefix, maximum in (
        ("qualification_evidence_requirements", f"{data_root}/evidence/", 64),
        ("review_requirements", f"{data_root}/reviews/", 16),
        ("activation_evidence_requirements", f"{data_root}/activation-evidence/", 64),
    ):
        requirements = contract.get(field)
        if (
            not isinstance(requirements, list)
            or not requirements
            or len(requirements) > maximum
        ):
            raise CurrentAuditError(f"CURRENT_AUDIT_PROTOCOL_REQUIREMENTS:{field}")
        requirement_ids: list[str] = []
        requirement_paths: list[str] = []
        requirement_kinds[field] = []
        for item in requirements:
            item = _require_fields(
                item,
                {"id", "path", "kind", "max_bytes"},
                f"protocol.{field}",
            )
            requirement_ids.append(
                _require_nonempty_string(item.get("id"), f"protocol.{field}.id")
            )
            path = _require_protocol_path(item.get("path"), f"protocol.{field}.path")
            requirement_paths.append(path)
            requirement_kinds[field].append(str(item.get("kind")))
            if (
                not path.startswith(prefix)
                or not isinstance(item.get("kind"), str)
                or re.fullmatch(r"[A-Z][A-Z0-9_]{2,63}", item["kind"]) is None
                or type(item.get("max_bytes")) is not int
                or item["max_bytes"] < 1
                or item["max_bytes"] > MAX_LOG_BYTES
            ):
                raise CurrentAuditError(
                    f"CURRENT_AUDIT_PROTOCOL_REQUIREMENT_ENTRY:{field}"
                )
        if (
            len(requirement_ids) != len(set(requirement_ids))
            or len(requirement_paths) != len(set(requirement_paths))
            or requirement_ids != sorted(requirement_ids)
        ):
            raise CurrentAuditError(f"CURRENT_AUDIT_PROTOCOL_REQUIREMENT_ORDER:{field}")
    required_qualification_kinds = {
        "FILE_REVIEW_TRACEABILITY",
        "COMPLETE_COMMAND_LOG",
        "POSITIVE_NEGATIVE_VECTORS",
        "COVERAGE_FUZZ_MUTATION_MODEL",
        "RESOURCE_TIME_MAXIMA",
        "EXACT_IDENTITIES_CHECKSUMS",
        "CLAIM_MIGRATION_DISPOSITION",
    }
    if not required_qualification_kinds.issubset(
        requirement_kinds["qualification_evidence_requirements"]
    ):
        raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_SOURCE_EVIDENCE_INCOMPLETE")
    bootstrap_evidence_kinds = {
        "CH-T001": {
            "COMPLETE_FILE_INVENTORY",
            "INDEPENDENT_LEDGER_RECONCILIATION",
        },
        "CH-T002": {
            "COMPLETE_EXPLICIT_ASSIGNMENTS",
            "FILE_REVIEW_EVIDENCE",
        },
        "CH-T003": {"COMPLETE_REVIEWED_ASSIGNED_FILE_LEDGER"},
    }
    if task_id in bootstrap_evidence_kinds and not bootstrap_evidence_kinds[
        task_id
    ].issubset(requirement_kinds["qualification_evidence_requirements"]):
        raise CurrentAuditError(
            "CURRENT_AUDIT_PROTOCOL_BOOTSTRAP_POSTCONDITION_EVIDENCE_MISSING"
        )
    _require_source_review_kinds(task_id, requirement_kinds["review_requirements"])
    contract["reviewer_registry"] = _validate_frozen_reviewer_registry(
        repo,
        contract.get("reviewer_registry"),
        task_id=task_id,
        requirements=contract["review_requirements"],
    )
    lenses = contract.get("lens_questions")
    if (
        not isinstance(lenses, list)
        or len(lenses) != 20
        or [item.get("id") for item in lenses if isinstance(item, dict)]
        != [f"L{index:02d}" for index in range(1, 21)]
    ):
        raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_LENSES_INVALID")
    for lens in lenses:
        lens = _require_fields(lens, {"id", "name", "question"}, "protocol.lens")
        lens_index = int(lens["id"].removeprefix("L")) - 1
        if (
            lens.get("name") != LENS_NAMES[lens_index]
            or lens.get("question") != HANDOFF_LENS_QUESTIONS[lens_index]
        ):
            raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_LENS_NOT_SOURCE_EXACT")
    if not _strict_equal(
        contract.get("resource_budgets"),
        {
            "json_bytes": MAX_JSON_BYTES,
            "decompressed_evidence_bytes": MAX_LOG_BYTES,
            "protocol_path_bytes": MAX_PROTOCOL_PATH_BYTES,
            "verifier_output_bytes_per_stream": MAX_VERIFIER_OUTPUT_BYTES,
            "verifier_seconds": MAX_VERIFIER_SECONDS,
        },
    ):
        raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_RESOURCE_BUDGET")
    outcomes = contract.get("claim_outcomes")
    if not isinstance(outcomes, list) or not outcomes or len(outcomes) > 16:
        raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_CLAIM_OUTCOMES")
    outcome_ids: list[str] = []
    prior_active = set(prior_claims["active_claims"])
    prior_removed = set(prior_claims["removed_claims"])
    prior_non_claimed = set(prior_claims["non_claimed_claims"])
    prior_narrowed = set(prior_claims["narrowed_claims"])
    prior_inventory_ids = {item["id"] for item in prior_claims["claim_inventory"]}
    if (
        prior_inventory_ids != prior_active | prior_removed | prior_non_claimed
        or prior_active & prior_removed
        or prior_active & prior_non_claimed
        or prior_removed & prior_non_claimed
        or prior_narrowed - prior_active
    ):
        raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_PRIOR_CLAIM_STATE_INVALID")
    for outcome in outcomes:
        outcome = _require_fields(
            outcome,
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
            "protocol.claim_outcome",
        )
        outcome_id = _require_nonempty_string(outcome.get("id"), "protocol.outcome.id")
        outcome_ids.append(outcome_id)
        disposition = outcome.get("claim_disposition")
        overall = outcome.get("overall_status")
        if (
            disposition
            not in {
                "NO_PUBLIC_CLAIM_CHANGE",
                "PUBLIC_CLAIMS_NARROWED",
                "PUBLIC_CLAIMS_REMOVED",
                "PUBLIC_CLAIMS_QUALIFIED",
            }
            or (task_id != "CH-T125" and overall != "NO_GO")
            or (task_id == "CH-T125" and overall not in {"GO", "NARROWED_GO", "NO_GO"})
        ):
            raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_CLAIM_OUTCOME_STATE")
        observed_lists: dict[str, list[str]] = {}
        for list_field in (
            "active_claims",
            "release_qualified_claims",
            "removed_claims",
            "non_claimed_claims",
            "narrowed_claims",
            "limitations",
            "public_surfaces",
        ):
            observed_lists[list_field] = _require_string_list(
                outcome.get(list_field),
                f"protocol.outcome.{list_field}",
                minimum=0,
                unique=True,
            )
            if observed_lists[list_field] != sorted(observed_lists[list_field]):
                raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_CLAIM_ORDER")
        active = set(outcome["active_claims"])
        qualified = set(outcome["release_qualified_claims"])
        removed = set(outcome["removed_claims"])
        non_claimed = set(outcome["non_claimed_claims"])
        narrowed = set(outcome["narrowed_claims"])
        expected_public_surfaces = sorted(plan)
        if outcome["public_surfaces"] != expected_public_surfaces:
            raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_PUBLIC_SURFACE_BINDING")
        if (
            not active.issubset(prior_active)
            or not set(prior_claims["release_qualified_claims"]).issubset(qualified)
            or not qualified.issubset(active)
            or not prior_removed.issubset(removed)
            or non_claimed != prior_non_claimed
            or not prior_narrowed.issubset(narrowed)
            or active & removed
            or active & non_claimed
            or removed & non_claimed
            or removed & narrowed
            or (active | removed | non_claimed) != prior_inventory_ids
        ):
            raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_CLAIM_EXPANSION")
        claims_changed = (
            active != prior_active
            or removed != prior_removed
            or non_claimed != prior_non_claimed
            or narrowed != prior_narrowed
        )
        if claims_changed and plan.get("docs/CLAIM-LEDGER.md") != "M":
            raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_CLAIM_LEDGER_NOT_PLANNED")
        if disposition == "NO_PUBLIC_CLAIM_CHANGE" and (
            active != prior_active
            or removed != prior_removed
            or non_claimed != prior_non_claimed
            or narrowed != prior_narrowed
            or qualified != set(prior_claims["release_qualified_claims"])
        ):
            raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_CLAIM_TRANSITION")
        if disposition == "PUBLIC_CLAIMS_NARROWED" and (
            active != prior_active
            or removed != prior_removed
            or non_claimed != prior_non_claimed
            or not prior_narrowed < narrowed
            or not (narrowed - prior_narrowed).issubset(prior_active)
            or qualified != set(prior_claims["release_qualified_claims"])
        ):
            raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_CLAIM_TRANSITION")
        if disposition == "PUBLIC_CLAIMS_REMOVED" and (
            not active < prior_active
            or removed != prior_removed | (prior_active - active)
            or non_claimed != prior_non_claimed
            or narrowed != prior_narrowed - removed
            or qualified != set(prior_claims["release_qualified_claims"]) - removed
        ):
            raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_CLAIM_TRANSITION")
        if disposition == "PUBLIC_CLAIMS_QUALIFIED" and (
            active != prior_active
            or removed != prior_removed
            or non_claimed != prior_non_claimed
            or narrowed != prior_narrowed
            or not set(prior_claims["release_qualified_claims"]) < qualified
        ):
            raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_CLAIM_TRANSITION")
        if task_id == "CH-T125" and overall in {"GO", "NARROWED_GO"}:
            if qualified != active:
                raise CurrentAuditError(
                    "CURRENT_AUDIT_PROTOCOL_FINAL_CLAIMS_INCOMPLETE"
                )
        migration = _require_fields(
            outcome.get("migration"),
            {"required", "paths", "disposition"},
            "protocol.outcome.migration",
        )
        if (
            type(migration.get("required")) is not bool
            or migration.get("paths") != sorted(plan)
            or migration["required"] != bool(plan)
        ):
            raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_MIGRATION_BINDING")
        _require_nonempty_string(
            migration.get("disposition"), "protocol.outcome.migration.disposition"
        )
        if not _strict_equal(
            outcome.get("rollback"),
            {
                "strategy": "RESTORE_EXACT_PRIOR_ACTIVATED_TREE_ENTRIES",
                "paths": sorted(plan),
                "verification": "GIT_MODE_TYPE_AND_OBJECT_IDENTITY",
            },
        ):
            raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_ROLLBACK_BINDING")
    if len(outcome_ids) != len(set(outcome_ids)):
        raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_CLAIM_OUTCOME_DUPLICATE")
    return contract


def _validate_successor_registration_v2(
    repo: Path,
    commit: str,
    value: Any,
    *,
    bootstrap_task: dict[str, Any],
    prior_claims: dict[str, Any],
    prior_claims_record: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    registration = _require_fields(
        value,
        {
            "task_id",
            "epoch",
            "verifier",
            "tests",
            "freeze_contract",
            "qualification_path",
            "activation_path",
            "verifier_receipt_path",
            "effective_on",
        },
        "protocol.registration",
    )
    task_id = registration.get("task_id")
    epoch = registration.get("epoch")
    if not isinstance(task_id, str) or type(epoch) is not int:
        raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_REGISTRATION_ID")
    paths = _task_epoch_paths(task_id, epoch)
    verifier = _require_protocol_file_record(
        registration.get("verifier"), paths["verifier"], "protocol.verifier", lines=True
    )
    tests = _require_protocol_file_record(
        registration.get("tests"), paths["tests"], "protocol.tests", lines=True
    )
    freeze = _require_protocol_file_record(
        registration.get("freeze_contract"),
        paths["freeze"],
        "protocol.freeze",
        lines=True,
    )
    if (
        registration.get("qualification_path") != paths["qualification"]
        or registration.get("activation_path") != paths["activation"]
        or registration.get("verifier_receipt_path") != paths["verifier_receipt"]
        or registration.get("effective_on")
        != "SIGNED_COMMIT_FIRST_CONTAINING_EXACT_REGISTRATION_FREEZE_AND_GATES"
        or not _strict_equal(
            verifier, _commit_protocol_file_record(repo, commit, paths["verifier"])
        )
        or not _strict_equal(
            tests, _commit_protocol_file_record(repo, commit, paths["tests"])
        )
        or not _strict_equal(
            freeze, _commit_protocol_file_record(repo, commit, paths["freeze"])
        )
    ):
        raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_REGISTRATION_BINDING")
    contract = _validate_successor_freeze_contract(
        repo,
        commit,
        paths["freeze"],
        task_id=task_id,
        epoch=epoch,
        bootstrap_task=bootstrap_task,
        prior_claims=prior_claims,
        prior_claims_record=prior_claims_record,
    )
    return registration, contract


def _validate_independent_review_report(
    repo: Path,
    payload: bytes,
    *,
    task_id: str,
    epoch: int,
    reviewer: dict[str, Any],
    freeze_commit: str,
    implementation_commit: str,
    implementation_plan: dict[str, str],
    surface_inventory: list[dict[str, Any]],
    evidence_ids: list[str],
    requirement: dict[str, Any],
) -> dict[str, list[str]]:
    report = _load_json_bytes(payload, f"protocol.review_report.{task_id}.{epoch}")
    report = _require_fields(
        report,
        {
            "schema_version",
            "task_id",
            "epoch",
            "requirement",
            "reviewer",
            "freeze_commit",
            "implementation_commit",
            "implementation_diff",
            "all_changed_lines_reviewed",
            "reviewed_relevant_context",
            "relevant_unchanged_context_reviewed",
            "decisive_reproduction",
            "reviewer_provenance",
            "findings",
            "limitations",
            "decision",
        },
        "protocol.review_report",
    )
    if not _strict_equal(
        {
            "schema_version": report.get("schema_version"),
            "task_id": report.get("task_id"),
            "epoch": report.get("epoch"),
            "requirement": report.get("requirement"),
            "reviewer": report.get("reviewer"),
            "freeze_commit": report.get("freeze_commit"),
            "implementation_commit": report.get("implementation_commit"),
            "all_changed_lines_reviewed": report.get("all_changed_lines_reviewed"),
            "relevant_unchanged_context_reviewed": report.get(
                "relevant_unchanged_context_reviewed"
            ),
            "decision": report.get("decision"),
        },
        {
            "schema_version": "1.0.0",
            "task_id": task_id,
            "epoch": epoch,
            "requirement": {
                "id": requirement["id"],
                "kind": requirement["kind"],
                "path": requirement["path"],
            },
            "reviewer": reviewer,
            "freeze_commit": freeze_commit,
            "implementation_commit": implementation_commit,
            "all_changed_lines_reviewed": True,
            "relevant_unchanged_context_reviewed": True,
            "decision": "ACCEPT_TECHNICAL_TASK_QUALIFICATION",
        },
    ):
        raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_REVIEW_REPORT_IDENTITY")
    expected_changed = [
        _commit_regular_file_record(repo, implementation_commit, path)
        for path, status in implementation_plan.items()
        if status in {"A", "M"}
    ]
    diff = _require_fields(
        report.get("implementation_diff"),
        {"statuses", "changed_file_records", "deleted_paths"},
        "protocol.review_report.diff",
    )
    if not _strict_equal(
        diff,
        {
            "statuses": implementation_plan,
            "changed_file_records": expected_changed,
            "deleted_paths": [
                path for path, status in implementation_plan.items() if status == "D"
            ],
        },
    ):
        raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_REVIEW_REPORT_DIFF")
    context = report.get("reviewed_relevant_context")
    if not isinstance(context, list) or not context:
        raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_REVIEW_REPORT_CONTEXT")
    context_paths: list[str] = []
    for record in context:
        if not isinstance(record, dict) or not isinstance(record.get("path"), str):
            raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_REVIEW_REPORT_CONTEXT")
        path = _require_protocol_path(record["path"], "protocol.review.context")
        context_paths.append(path)
        if path in implementation_plan or not _strict_equal(
            record, _commit_regular_file_record(repo, implementation_commit, path)
        ):
            raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_REVIEW_REPORT_CONTEXT")
    if len(context_paths) != len(set(context_paths)):
        raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_REVIEW_REPORT_CONTEXT")
    required_consumer_context = {
        consumer
        for surface in surface_inventory
        for consumer in surface["in_repository_consumers"]
    }
    if not required_consumer_context.issubset(context_paths):
        raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_REVIEW_CONSUMER_OMISSION")
    reproduction = _require_fields(
        report.get("decisive_reproduction"),
        {"evidence_ids", "commands", "result"},
        "protocol.review_report.reproduction",
    )
    reproduced_ids = _require_string_list(
        reproduction.get("evidence_ids"),
        "protocol.review_report.reproduction.evidence",
        unique=True,
    )
    commands = _require_string_list(
        reproduction.get("commands"),
        "protocol.review_report.reproduction.commands",
        unique=True,
    )
    if (
        reproduction.get("result") != "PASS"
        or any(item not in evidence_ids for item in reproduced_ids)
        or any(len(command.encode("utf-8")) > 4096 for command in commands)
    ):
        raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_REVIEW_REPORT_REPRODUCTION")
    provenance = _require_fields(
        report.get("reviewer_provenance"),
        {"method", "tool", "version", "session_id"},
        "protocol.review_report.provenance",
    )
    for field in provenance:
        value = _require_nonempty_string(
            provenance[field], f"protocol.review_report.provenance.{field}"
        )
        if len(value.encode("utf-8")) > 1024:
            raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_REVIEW_REPORT_PROVENANCE")
    result: dict[str, list[str]] = {}
    for field in ("findings", "limitations"):
        values = _require_string_list(
            report.get(field), f"protocol.review_report.{field}", unique=True
        )
        if any(len(value.encode("utf-8")) > 4096 for value in values):
            raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_REVIEW_REPORT_TEXT_BOUND")
        result[field] = values
    return result


def _require_complete_qualification_limitations(
    value: Any,
    *,
    prior_limitations: list[str],
    outcome_limitations: list[str],
    review_reports: dict[str, dict[str, list[str]]],
    disposition_residuals: set[str],
    lens_residuals: set[str],
) -> list[str]:
    """Require the qualification to preserve the complete cumulative risk union."""

    limitations = _require_string_list(
        value,
        "protocol.qualification.limitations",
        minimum=1,
        unique=True,
    )
    required = {
        *prior_limitations,
        *outcome_limitations,
        *disposition_residuals,
        *lens_residuals,
        *(
            limitation
            for report in review_reports.values()
            for limitation in report["limitations"]
        ),
    }
    if not required.issubset(limitations):
        raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_LIMITATIONS")
    return limitations


def _validate_successor_qualification_v2(
    repo: Path,
    commit: str,
    *,
    registration: dict[str, Any],
    contract: dict[str, Any],
    freeze_commit: str,
    implementation_commit: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    task_id = registration["task_id"]
    epoch = registration["epoch"]
    path = registration["qualification_path"]
    qualification, _payload = _read_commit_json(
        repo, commit, path, f"protocol.qualification.{task_id}.{epoch}"
    )
    fields = {
        "schema_version",
        "task_id",
        "epoch",
        "release_target",
        "author",
        "persistent_identifier",
        "effective_on",
        "freeze_commit",
        "implementation_commit",
        "registered_files",
        "selected_claim_outcome_id",
        "evidence_records",
        "review_records",
        "review_finding_dispositions",
        "twenty_lens_reviews",
        "human_review_boundary",
        "limitations",
        "release_authority",
    }
    if set(qualification) != fields or not _strict_equal(
        {
            "schema_version": qualification.get("schema_version"),
            "task_id": qualification.get("task_id"),
            "epoch": qualification.get("epoch"),
            "release_target": qualification.get("release_target"),
            "author": qualification.get("author"),
            "persistent_identifier": qualification.get("persistent_identifier"),
            "effective_on": qualification.get("effective_on"),
            "freeze_commit": qualification.get("freeze_commit"),
            "implementation_commit": qualification.get("implementation_commit"),
            "registered_files": qualification.get("registered_files"),
        },
        {
            "schema_version": "1.0.0",
            "task_id": task_id,
            "epoch": epoch,
            "release_target": "0.9.0",
            "author": {"name": "Sepehr Mahmoudian", "email": "sepmhn@gmail.com"},
            "persistent_identifier": None,
            "effective_on": "SIGNED_COMMIT_FIRST_CONTAINING_EXACT_QUALIFICATION_EVIDENCE_AND_REVIEWS",
            "freeze_commit": freeze_commit,
            "implementation_commit": implementation_commit,
            "registered_files": {
                "verifier": registration["verifier"],
                "tests": registration["tests"],
                "freeze_contract": registration["freeze_contract"],
            },
        },
    ):
        raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_QUALIFICATION_IDENTITY")
    outcomes = {item["id"]: item for item in contract["claim_outcomes"]}
    selected_id = qualification.get("selected_claim_outcome_id")
    if selected_id not in outcomes:
        raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_QUALIFICATION_OUTCOME")
    selected_outcome = outcomes[selected_id]
    freeze_parent = _commit_metadata(repo, freeze_commit)["parent"]
    if freeze_parent is None:
        raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_FREEZE_PARENT_MISSING")
    prior_claims = _load_json_bytes(
        _git_file(repo, freeze_parent, ACTIVE_CLAIMS_PATH),
        "protocol.qualification.prior_claims",
    )
    current_inventory = _claim_inventory(repo, implementation_commit)
    current_statuses = {item["id"]: item["status"] for item in current_inventory}
    prior_inventory_records = prior_claims.get("claim_inventory", [])
    prior_active_ordered = prior_claims.get("active_claims", [])
    prior_residual_limitations = _require_string_list(
        prior_claims.get("residual_limitations"),
        "protocol.qualification.prior_residual_limitations",
        minimum=1,
        unique=True,
    )
    if (
        not isinstance(prior_inventory_records, list)
        or not isinstance(prior_active_ordered, list)
        or any(
            not isinstance(item, dict) or not isinstance(item.get("id"), str)
            for item in prior_inventory_records
        )
    ):
        raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_PRIOR_CLAIM_STATE_INVALID")
    prior_inventory = {item["id"]: item for item in prior_inventory_records}
    expected_prior_asserted = [
        item
        for item in prior_inventory_records
        if item.get("id") in prior_active_ordered
    ]
    if len(prior_inventory) != len(prior_inventory_records) or not _strict_equal(
        prior_claims.get("asserted_claims"), expected_prior_asserted
    ):
        raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_PRIOR_CLAIM_STATE_INVALID")
    current_inventory_by_id = {item["id"]: item for item in current_inventory}
    semantically_changed_claims = {
        claim_id
        for claim_id in set(prior_inventory) | set(current_inventory_by_id)
        if prior_inventory.get(claim_id) != current_inventory_by_id.get(claim_id)
    }
    active_claims = set(selected_outcome["active_claims"])
    qualified_claims = set(selected_outcome["release_qualified_claims"])
    removed_claims = set(selected_outcome["removed_claims"])
    non_claimed_claims = set(selected_outcome["non_claimed_claims"])
    narrowed_claims = set(selected_outcome["narrowed_claims"])
    prior_removed_claims = set(prior_claims.get("removed_claims", []))
    prior_narrowed_claims = set(prior_claims.get("narrowed_claims", []))
    prior_qualified_claims = set(prior_claims.get("release_qualified_claims", []))
    newly_removed_claims = removed_claims - prior_removed_claims
    newly_narrowed_claims = narrowed_claims - prior_narrowed_claims
    newly_qualified_claims = qualified_claims - prior_qualified_claims
    disposition = selected_outcome["claim_disposition"]
    prior_ledger_payload = _git_file(repo, freeze_parent, "docs/CLAIM-LEDGER.md")
    current_ledger_payload = _git_file(
        repo, implementation_commit, "docs/CLAIM-LEDGER.md"
    )
    if (
        set(current_statuses) != active_claims | removed_claims | non_claimed_claims
        or active_claims & removed_claims
        or active_claims & non_claimed_claims
        or removed_claims & non_claimed_claims
        or narrowed_claims - active_claims
        or any(
            current_statuses[claim_id]
            in {
                "REMOVED",
                "NOT_CLAIMED",
                "OUT OF SCOPE",
            }
            for claim_id in active_claims
        )
        or any(current_statuses[claim_id] != "REMOVED" for claim_id in removed_claims)
        or any(
            current_statuses[claim_id] not in {"NOT_CLAIMED", "OUT OF SCOPE"}
            for claim_id in non_claimed_claims
        )
        or any(current_statuses[claim_id] != "PROVEN" for claim_id in qualified_claims)
    ):
        raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_CURRENT_CLAIM_STATE_INVALID")
    if disposition == "NO_PUBLIC_CLAIM_CHANGE":
        if current_ledger_payload != prior_ledger_payload:
            raise CurrentAuditError(
                "CURRENT_AUDIT_PROTOCOL_NO_CHANGE_CLAIM_LEDGER_DRIFT"
            )
    elif _claim_ledger_scaffold_sha256(
        current_ledger_payload
    ) != _claim_ledger_scaffold_sha256(prior_ledger_payload):
        raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_CLAIM_SCAFFOLD_DRIFT")
    if (
        (disposition == "NO_PUBLIC_CLAIM_CHANGE" and semantically_changed_claims)
        or (
            disposition == "PUBLIC_CLAIMS_NARROWED"
            and (
                not newly_narrowed_claims
                or not newly_narrowed_claims.issubset(semantically_changed_claims)
                or not semantically_changed_claims.issubset(newly_narrowed_claims)
            )
        )
        or (
            disposition == "PUBLIC_CLAIMS_REMOVED"
            and (
                not newly_removed_claims
                or not semantically_changed_claims.issubset(newly_removed_claims)
            )
        )
        or (
            disposition == "PUBLIC_CLAIMS_QUALIFIED"
            and not semantically_changed_claims.issubset(newly_qualified_claims)
        )
    ):
        raise CurrentAuditError(
            "CURRENT_AUDIT_PROTOCOL_CLAIM_LEDGER_TRANSITION_INVALID"
        )
    if task_id == "CH-T125":
        overall = selected_outcome["overall_status"]
        narrowed = bool(removed_claims or narrowed_claims)
        if (overall == "GO" and (narrowed or qualified_claims != active_claims)) or (
            overall == "NARROWED_GO"
            and (not narrowed or qualified_claims != active_claims)
        ):
            raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_FINAL_STATUS_LABEL_INVALID")
    expected_evidence = contract["qualification_evidence_requirements"]
    evidence_records = qualification.get("evidence_records")
    if not isinstance(evidence_records, list) or len(evidence_records) != len(
        expected_evidence
    ):
        raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_QUALIFICATION_EVIDENCE")
    for index, (record, requirement) in enumerate(
        zip(evidence_records, expected_evidence, strict=True)
    ):
        record = _require_fields(
            record,
            {
                "id",
                "kind",
                "file",
                "subject_commits",
                "result",
                "started_at_utc",
                "completed_at_utc",
            },
            f"protocol.qualification.evidence.{index}",
        )
        expected_file = _commit_regular_file_record(repo, commit, requirement["path"])
        started = _parse_utc(record.get("started_at_utc"), "protocol.evidence.started")
        completed = _parse_utc(
            record.get("completed_at_utc"), "protocol.evidence.completed"
        )
        if (
            record.get("id") != requirement["id"]
            or record.get("kind") != requirement["kind"]
            or not _strict_equal(record.get("file"), expected_file)
            or record.get("subject_commits") != [freeze_commit, implementation_commit]
            or record.get("result") != "PASS"
            or expected_file["bytes"] > requirement["max_bytes"]
            or not (
                _commit_datetime(repo, implementation_commit)
                <= started
                <= completed
                <= _commit_datetime(repo, commit)
            )
        ):
            raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_QUALIFICATION_EVIDENCE")
    qualification_evidence_ids = [item["id"] for item in evidence_records]
    expected_reviews = contract["review_requirements"]
    review_records = qualification.get("review_records")
    if not isinstance(review_records, list) or len(review_records) != len(
        expected_reviews
    ):
        raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_QUALIFICATION_REVIEWS")
    reviewer_ids: list[str] = []
    review_reports: dict[str, dict[str, list[str]]] = {}
    source_signer = _source_release_signer(repo)
    for index, (record, requirement) in enumerate(
        zip(review_records, expected_reviews, strict=True)
    ):
        record = _require_fields(
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
            f"protocol.qualification.review.{index}",
        )
        expected_file = _commit_regular_file_record(repo, commit, requirement["path"])
        review_payload = _git_file(repo, commit, requirement["path"])
        started = _parse_utc(record.get("started_at_utc"), "protocol.review.started")
        completed = _parse_utc(
            record.get("completed_at_utc"), "protocol.review.completed"
        )
        reviewer = _require_fields(
            record.get("reviewer"),
            {"name", "principal", "classification", "organization"},
            f"protocol.qualification.review.{index}.reviewer",
        )
        for identity_field in ("name", "principal", "organization"):
            _require_nonempty_string(
                reviewer.get(identity_field),
                f"protocol.qualification.review.{index}.{identity_field}",
            )
        classification = reviewer.get("classification")
        registry_entry = contract["reviewer_registry"][index]
        if classification not in {
            "INDEPENDENT_AUTOMATED",
            "INDEPENDENT_NAMED_HUMAN",
            "RELEASE_LEAD",
        } or not _strict_equal(reviewer, registry_entry["reviewer"]):
            raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_REVIEWER_IDENTITY")
        reviewer_ids.append(str(record.get("id")))
        if (
            record.get("id") != requirement["id"]
            or record.get("kind") != requirement["kind"]
            or not _strict_equal(record.get("file"), expected_file)
            or record.get("reproduced_decisive_evidence") is not True
            or record.get("reviewed_all_changed_lines_and_context") is not True
            or record.get("decision") != "ACCEPT_TECHNICAL_TASK_QUALIFICATION"
            or expected_file["bytes"] > requirement["max_bytes"]
            or not (
                _commit_datetime(repo, implementation_commit)
                <= started
                <= completed
                <= _commit_datetime(repo, commit)
            )
        ):
            raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_QUALIFICATION_REVIEWS")
        review_reports[str(record["id"])] = _validate_independent_review_report(
            repo,
            review_payload,
            task_id=task_id,
            epoch=epoch,
            reviewer=reviewer,
            freeze_commit=freeze_commit,
            implementation_commit=implementation_commit,
            implementation_plan=contract["implementation_plan"],
            surface_inventory=contract["affected_surface_inventory"],
            evidence_ids=qualification_evidence_ids,
            requirement=requirement,
        )
        attestation_payload = _review_attestation_payload(
            record,
            task_id=task_id,
            epoch=epoch,
            freeze_commit=freeze_commit,
            implementation_commit=implementation_commit,
        )
        kind = requirement["kind"]
        independent = record.get("independent_from_release_author") is True
        human = record.get("human") is True
        named_human = record.get("named_human_reviewer") is True
        external = record.get("external") is True
        if record.get("release_approver") is not (
            kind == "SIGNED_RELEASE_DECISION_REVIEW"
        ):
            raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_REVIEW_AUTHORITY_BOUNDARY")
        if kind == "INDEPENDENT_REVIEW" and (
            not independent
            or reviewer["name"] == "Sepehr Mahmoudian"
            or classification
            not in {
                "INDEPENDENT_AUTOMATED",
                "INDEPENDENT_NAMED_HUMAN",
            }
        ):
            raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_INDEPENDENT_REVIEW")
        human_signature_kinds = EXTERNAL_HUMAN_REVIEW_KINDS
        lead_signature_kinds = LEAD_REVIEW_KINDS
        if classification == "INDEPENDENT_AUTOMATED" and (
            human
            or named_human
            or external
            or record.get("release_approver") is not False
            or record.get("detached_signature") is None
        ):
            raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_AUTOMATED_REVIEW_BOUNDARY")
        if classification == "INDEPENDENT_AUTOMATED":
            attestation = record["detached_signature"]
            if (
                reviewer["organization"].casefold() == "sepahead"
                or reviewer["principal"] == "sepmhn@gmail.com"
                or not isinstance(attestation, dict)
                or attestation.get("public_key") == source_signer["public_key"]
                or attestation.get("key_fingerprint")
                == SOURCE_SIGNATURE["key_fingerprint"]
            ):
                raise CurrentAuditError(
                    "CURRENT_AUDIT_PROTOCOL_INDEPENDENT_KEY_NOT_DISTINCT"
                )
        if classification == "INDEPENDENT_NAMED_HUMAN" and (
            not human
            or not named_human
            or not independent
            or record.get("detached_signature") is None
        ):
            raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_NAMED_HUMAN_BOUNDARY")
        if classification == "INDEPENDENT_NAMED_HUMAN":
            attestation = record["detached_signature"]
            if (
                reviewer["organization"].casefold() == "sepahead"
                or not isinstance(attestation, dict)
                or attestation.get("public_key") == source_signer["public_key"]
                or attestation.get("key_fingerprint")
                == SOURCE_SIGNATURE["key_fingerprint"]
                or reviewer["principal"] == "sepmhn@gmail.com"
            ):
                raise CurrentAuditError(
                    "CURRENT_AUDIT_PROTOCOL_INDEPENDENT_KEY_NOT_DISTINCT"
                )
        if classification == "RELEASE_LEAD" and kind not in lead_signature_kinds:
            raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_PREMATURE_LEAD_AUTHORITY")
        if kind in human_signature_kinds:
            if (
                not independent
                or not human
                or not named_human
                or not external
                or classification != "INDEPENDENT_NAMED_HUMAN"
                or record.get("release_approver") is not False
                or reviewer["name"] == "Sepehr Mahmoudian"
            ):
                raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_EXTERNAL_HUMAN_REVIEW")
            _verify_ssh_detached_attestation(
                repo,
                record.get("detached_signature"),
                attestation_payload,
                namespace="haldir-independent-review-v2",
                label=f"protocol.review.{task_id}.{kind}",
                expected_principal=reviewer["principal"],
                expected_public_key=registry_entry["public_key"],
                expected_fingerprint=registry_entry["key_fingerprint"],
            )
        elif kind in lead_signature_kinds:
            if (
                reviewer
                != {
                    "name": "Sepehr Mahmoudian",
                    "principal": "sepmhn@gmail.com",
                    "classification": "RELEASE_LEAD",
                    "organization": "SEPAHEAD",
                }
                or independent
                or not human
                or not named_human
                or external
                or record.get("release_approver")
                is not (kind == "SIGNED_RELEASE_DECISION_REVIEW")
            ):
                raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_LEAD_ONLY_REVIEW")
            _verify_ssh_detached_attestation(
                repo,
                record.get("detached_signature"),
                attestation_payload,
                namespace="haldir-lead-review-v2",
                label=f"protocol.review.{task_id}.{kind}",
                expected_principal="sepmhn@gmail.com",
                expected_public_key=source_signer["public_key"],
                expected_fingerprint=source_signer["key_fingerprint"],
            )
        elif record.get("detached_signature") is not None:
            _verify_ssh_detached_attestation(
                repo,
                record["detached_signature"],
                attestation_payload,
                namespace="haldir-independent-review-v2",
                label=f"protocol.review.{task_id}.{kind}",
                expected_principal=reviewer["principal"],
                expected_public_key=registry_entry["public_key"],
                expected_fingerprint=registry_entry["key_fingerprint"],
            )
    expected_findings = [
        (review_id, finding)
        for review_id in reviewer_ids
        for finding in review_reports[review_id]["findings"]
    ]
    finding_dispositions = qualification.get("review_finding_dispositions")
    if not isinstance(finding_dispositions, list) or len(finding_dispositions) != len(
        expected_findings
    ):
        raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_REVIEW_FINDING_DISPOSITIONS")
    disposition_residuals: set[str] = set()
    observed_findings: list[tuple[str, str]] = []
    for index, disposition in enumerate(finding_dispositions):
        disposition = _require_fields(
            disposition,
            {
                "review_id",
                "finding",
                "disposition",
                "evidence_ids",
                "rationale",
                "residual_limitation",
            },
            f"protocol.review_finding_disposition.{index}",
        )
        review_id = disposition.get("review_id")
        finding = disposition.get("finding")
        observed_findings.append((str(review_id), str(finding)))
        disposition_evidence = _require_string_list(
            disposition.get("evidence_ids"),
            f"protocol.review_finding_disposition.{index}.evidence",
            unique=True,
        )
        rationale = _require_nonempty_string(
            disposition.get("rationale"),
            f"protocol.review_finding_disposition.{index}.rationale",
        )
        resolution = disposition.get("disposition")
        residual = disposition.get("residual_limitation")
        if (
            len(rationale.encode("utf-8")) > 4096
            or any(
                item not in qualification_evidence_ids for item in disposition_evidence
            )
            or resolution not in {"RESOLVED", "RESIDUAL_LIMITATION"}
            or (resolution == "RESOLVED" and residual is not None)
            or (
                resolution == "RESIDUAL_LIMITATION"
                and (not isinstance(residual, str) or not residual.strip())
            )
        ):
            raise CurrentAuditError(
                "CURRENT_AUDIT_PROTOCOL_REVIEW_FINDING_DISPOSITIONS"
            )
        if isinstance(residual, str):
            disposition_residuals.add(residual)
    if observed_findings != expected_findings:
        raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_REVIEW_FINDING_DISPOSITIONS")
    lenses = qualification.get("twenty_lens_reviews")
    if not isinstance(lenses, dict) or list(lenses) != [
        f"L{i:02d}" for i in range(1, 21)
    ]:
        raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_QUALIFICATION_LENSES")
    evidence_ids = [item["id"] for item in evidence_records]
    allowed_control_ids = {item["id"] for item in contract["normative_controls"]}
    allowed_counterfactual_ids = {
        item["id"] for item in contract["mandatory_counterfactuals"]
    }
    covered_control_ids: set[str] = set()
    covered_counterfactual_ids: set[str] = set()
    covered_evidence_ids: set[str] = set()
    lens_residuals: set[str] = set()
    for lens_id, lens in lenses.items():
        lens = _require_fields(
            lens,
            {
                "name",
                "question",
                "status",
                "claim_impact",
                "control_ids",
                "counterfactual_ids",
                "reviewer_ids",
                "evidence_ids",
                "finding",
                "residual_limitation",
            },
            f"protocol.qualification.{lens_id}",
        )
        lens_index = int(lens_id.removeprefix("L")) - 1
        if (
            lens.get("name") != LENS_NAMES[lens_index]
            or lens.get("question") != HANDOFF_LENS_QUESTIONS[lens_index]
            or lens.get("status") != "RESOLVED"
            or lens.get("claim_impact") != outcomes[selected_id]["claim_disposition"]
            or not isinstance(lens.get("control_ids"), list)
            or not lens["control_ids"]
            or len(lens["control_ids"]) != len(set(lens["control_ids"]))
            or any(item not in allowed_control_ids for item in lens["control_ids"])
            or not isinstance(lens.get("counterfactual_ids"), list)
            or not lens["counterfactual_ids"]
            or len(lens["counterfactual_ids"]) != len(set(lens["counterfactual_ids"]))
            or any(
                item not in allowed_counterfactual_ids
                for item in lens["counterfactual_ids"]
            )
            or lens.get("reviewer_ids") != reviewer_ids
            or not isinstance(lens.get("evidence_ids"), list)
            or not lens["evidence_ids"]
            or any(item not in evidence_ids for item in lens["evidence_ids"])
            or not isinstance(lens.get("finding"), str)
            or not lens["finding"].strip()
            or not isinstance(lens.get("residual_limitation"), str)
            or not lens["residual_limitation"].strip()
        ):
            raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_QUALIFICATION_LENSES")
        covered_control_ids.update(lens["control_ids"])
        covered_counterfactual_ids.update(lens["counterfactual_ids"])
        covered_evidence_ids.update(lens["evidence_ids"])
        lens_residuals.add(lens["residual_limitation"])
    if (
        covered_control_ids != allowed_control_ids
        or covered_counterfactual_ids != allowed_counterfactual_ids
        or covered_evidence_ids != set(evidence_ids)
    ):
        raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_QUALIFICATION_LENS_COVERAGE")
    named_human_performed = any(
        item["human"] is True and item["named_human_reviewer"] is True
        for item in review_records
    )
    independent_human_performed = any(
        item["human"] is True
        and item["named_human_reviewer"] is True
        and item["independent_from_release_author"] is True
        for item in review_records
    )
    independent_automated_performed = any(
        item["reviewer"]["classification"] == "INDEPENDENT_AUTOMATED"
        and item["independent_from_release_author"] is True
        for item in review_records
    )
    human_required = task_id in {"CH-T115", "CH-T120"}
    if not _strict_equal(
        qualification.get("human_review_boundary"),
        {
            "named_human_review_performed": named_human_performed,
            "independent_human_review_performed": independent_human_performed,
            "independent_automated_review_performed": independent_automated_performed,
            "automated_review_only": not named_human_performed,
            "required_external_human_review_satisfied": (
                independent_human_performed if human_required else None
            ),
        },
    ) or (human_required and not independent_human_performed):
        raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_HUMAN_BOUNDARY")
    _require_complete_qualification_limitations(
        qualification.get("limitations"),
        prior_limitations=prior_residual_limitations,
        outcome_limitations=outcomes[selected_id]["limitations"],
        review_reports=review_reports,
        disposition_residuals=disposition_residuals,
        lens_residuals=lens_residuals,
    )
    authority = qualification.get("release_authority")
    if task_id != "CH-T125":
        if authority is not None:
            raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_PREMATURE_AUTHORITY")
    else:
        outcome = outcomes[selected_id]
        authorized = outcome["overall_status"] in {"GO", "NARROWED_GO"}
        authority_fields = {
            "schema_version",
            "release_target",
            "persistent_identifier",
            "author",
            "task_id",
            "epoch",
            "freeze_commit",
            "implementation_commit",
            "selected_claim_outcome_id",
            "decision",
            "active_claims",
            "release_qualified_claims",
            "removed_claims",
            "narrowed_claims",
            "residual_risks",
            "tag_authorized",
            "github_release_authorized",
            "doi_authorized",
            "zenodo_authorized",
            "archive_authorized",
            "detached_signature",
        }
        if not isinstance(authority, dict) or set(authority) != authority_fields:
            raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_FINAL_AUTHORITY_MISSING")
        unsigned_authority = {
            key: value
            for key, value in authority.items()
            if key != "detached_signature"
        }
        expected_unsigned = {
            "schema_version": "1.0.0",
            "release_target": "0.9.0",
            "persistent_identifier": None,
            "author": {"name": "Sepehr Mahmoudian", "email": "sepmhn@gmail.com"},
            "task_id": task_id,
            "epoch": epoch,
            "freeze_commit": freeze_commit,
            "implementation_commit": implementation_commit,
            "selected_claim_outcome_id": selected_id,
            "decision": outcome["overall_status"],
            "active_claims": outcome["active_claims"],
            "release_qualified_claims": outcome["release_qualified_claims"],
            "removed_claims": outcome["removed_claims"],
            "narrowed_claims": outcome["narrowed_claims"],
            "residual_risks": qualification["limitations"],
            "tag_authorized": authorized,
            "github_release_authorized": authorized,
            "doi_authorized": False,
            "zenodo_authorized": False,
            "archive_authorized": False,
        }
        if not _strict_equal(unsigned_authority, expected_unsigned):
            raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_FINAL_AUTHORITY_INVALID")
        source_allowed = (
            _git_file(repo, SOURCE_COMMIT, "release/0.9.0/allowed-signers")
            .decode("utf-8")
            .strip()
        )
        _source_principal, source_public_key = source_allowed.split(" ", 1)
        authority_payload = (
            json.dumps(unsigned_authority, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        _verify_ssh_detached_attestation(
            repo,
            authority["detached_signature"],
            authority_payload,
            namespace="haldir-release-authority-v1",
            label="protocol.final_authority",
            expected_principal="sepmhn@gmail.com",
            expected_public_key=source_public_key,
        )
    return qualification, outcomes[selected_id]


def _registered_verifier_expected_output(
    registration: dict[str, Any],
    freeze_commit: str,
    implementation_commit: str,
    qualification_commit: str,
    activation_commit: str,
    current_commit: str,
    qualification: dict[str, Any],
) -> dict[str, Any]:
    return {
        "schema_version": "1.0.0",
        "task_id": registration["task_id"],
        "epoch": registration["epoch"],
        "freeze_commit": freeze_commit,
        "implementation_commit": implementation_commit,
        "qualification_commit": qualification_commit,
        "activation_commit": activation_commit,
        "current_commit": current_commit,
        "verifier_sha256": registration["verifier"]["sha256"],
        "tests_sha256": registration["tests"]["sha256"],
        "selected_claim_outcome_id": qualification["selected_claim_outcome_id"],
        "result": "PASS",
    }


def _registered_verifier_receipt(output: dict[str, Any]) -> dict[str, Any]:
    """Project runtime output into a precomputable, no-self-hash D receipt."""

    receipt = {
        key: value
        for key, value in output.items()
        if key not in {"activation_commit", "current_commit"}
    }
    receipt["runtime_target_policy"] = (
        "CENTRAL_VERIFIER_EXECUTES_EXACT_F_BLOBS_AT_D_AND_FROZEN_TRIGGERED_CHANGES"
    )
    return receipt


def _repository_execution_state(repo: Path) -> tuple[bytes, bytes, bytes, bytes]:
    """Capture repository state observable to an executed registered program."""

    return (
        _git(repo, "rev-parse", "HEAD"),
        _git(
            repo,
            "for-each-ref",
            "--format=%(refname)%00%(objectname)%00%(objecttype)",
        ),
        _git(
            repo,
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
            "--ignored=matching",
        ),
        _git(repo, "config", "--local", "--list", "-z"),
    )


def _repository_git_roots(repo: Path) -> tuple[Path, ...]:
    """Return every distinct worktree-private and shared Git administrative root."""

    try:
        roots = {
            Path(
                _git(repo, "rev-parse", "--absolute-git-dir").decode("utf-8").strip()
            ).resolve(),
            Path(
                _git(repo, "rev-parse", "--path-format=absolute", "--git-common-dir")
                .decode("utf-8")
                .strip()
            ).resolve(),
        }
    except UnicodeDecodeError as error:
        raise CurrentAuditError("CURRENT_AUDIT_REGISTERED_LIVE_GITDIR") from error
    if not roots or any(not path.is_absolute() or not path.is_dir() for path in roots):
        raise CurrentAuditError("CURRENT_AUDIT_REGISTERED_LIVE_GITDIR")
    return tuple(sorted(roots))


def _bounded_filesystem_state(root: Path, label: str) -> tuple[tuple[Any, ...], ...]:
    """Hash a small repository snapshot, including administrative files."""

    if root.is_symlink() or not root.is_dir():
        raise CurrentAuditError(f"CURRENT_AUDIT_FILESYSTEM_STATE_ROOT:{label}")
    pending: list[tuple[Path, str]] = [(root, "")]
    records: list[tuple[Any, ...]] = []
    total_bytes = 0
    while pending:
        path, relative = pending.pop()
        try:
            metadata = path.lstat()
        except OSError as error:
            raise CurrentAuditError(
                f"CURRENT_AUDIT_FILESYSTEM_STATE_READ:{label}"
            ) from error
        common = (
            relative,
            stat.S_IMODE(metadata.st_mode),
            metadata.st_uid,
            metadata.st_gid,
            metadata.st_nlink,
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
        )
        if stat.S_ISDIR(metadata.st_mode):
            records.append(("directory", *common))
            try:
                with os.scandir(path) as iterator:
                    children: list[tuple[str, str]] = []
                    for child in iterator:
                        if (
                            len(records) + len(pending) + len(children)
                            >= MAX_JSON_NODES
                        ):
                            raise CurrentAuditError(
                                f"CURRENT_AUDIT_FILESYSTEM_STATE_BOUND:{label}"
                            )
                        children.append((child.name, child.path))
                    children.sort(key=lambda item: item[0])
            except OSError as error:
                raise CurrentAuditError(
                    f"CURRENT_AUDIT_FILESYSTEM_STATE_READ:{label}"
                ) from error
            for child_name, child_path in reversed(children):
                child_relative = (
                    child_name if not relative else f"{relative}/{child_name}"
                )
                if len(child_relative.encode("utf-8")) > 4096:
                    raise CurrentAuditError(
                        f"CURRENT_AUDIT_FILESYSTEM_STATE_BOUND:{label}"
                    )
                pending.append((Path(child_path), child_relative))
        elif stat.S_ISREG(metadata.st_mode):
            remaining = MAX_HYGIENE_TOTAL_BYTES - total_bytes
            payload = _read_bounded(path, remaining, f"filesystem.{label}")
            total_bytes = _bounded_hygiene_total(total_bytes, len(payload))
            records.append(("file", *common, _sha256(payload)))
        else:
            raise CurrentAuditError(
                f"CURRENT_AUDIT_FILESYSTEM_STATE_TYPE:{label}:{relative}"
            )
    return tuple(sorted(records))


def _make_snapshot_world_readable(root: Path) -> None:
    """Make a disposable snapshot traversable by the unprivileged container UID."""

    pending = [root]
    observed = 0
    while pending:
        path = pending.pop()
        observed += 1
        if observed > MAX_JSON_NODES:
            raise CurrentAuditError("CURRENT_AUDIT_SNAPSHOT_PERMISSION_BOUND")
        try:
            metadata = path.lstat()
        except OSError as error:
            raise CurrentAuditError("CURRENT_AUDIT_SNAPSHOT_PERMISSION_READ") from error
        if stat.S_ISLNK(metadata.st_mode):
            continue
        if stat.S_ISDIR(metadata.st_mode):
            mode = stat.S_IMODE(metadata.st_mode) | 0o055
            try:
                os.chmod(path, mode, follow_symlinks=False)
                with os.scandir(path) as iterator:
                    for entry in iterator:
                        if observed + len(pending) >= MAX_JSON_NODES:
                            raise CurrentAuditError(
                                "CURRENT_AUDIT_SNAPSHOT_PERMISSION_BOUND"
                            )
                        pending.append(Path(entry.path))
            except OSError as error:
                raise CurrentAuditError(
                    "CURRENT_AUDIT_SNAPSHOT_PERMISSION_UPDATE"
                ) from error
        elif stat.S_ISREG(metadata.st_mode):
            mode = stat.S_IMODE(metadata.st_mode) | 0o044
            try:
                os.chmod(path, mode, follow_symlinks=False)
            except OSError as error:
                raise CurrentAuditError(
                    "CURRENT_AUDIT_SNAPSHOT_PERMISSION_UPDATE"
                ) from error
        else:
            raise CurrentAuditError("CURRENT_AUDIT_SNAPSHOT_PERMISSION_TYPE")


def _registered_test_runner_payload() -> bytes:
    """Return the central in-container runner for one exact frozen test blob."""

    return b"""from __future__ import annotations

import importlib.util
import io
import json
import os
import re
import secrets
import subprocess
import sys
import unittest
from pathlib import Path

def load_cases(raw: str):
    cases = json.loads(raw)
    if not isinstance(cases, list) or not cases:
        raise SystemExit(2)
    for case in cases:
        if not isinstance(case, list) or len(case) != 2 or not all(isinstance(item, str) and item for item in case):
            raise SystemExit(2)
    return cases

def child_main(test_path: Path, expected_cases):
    trusted_test_case = unittest.TestCase
    trusted_async_case = unittest.IsolatedAsyncioTestCase
    trusted_bases = (trusted_test_case, trusted_async_case)
    protected_names = (
        "__call__", "__delattr__", "__getattr__", "__getattribute__",
        "__init__", "__init_subclass__", "__new__", "__setattr__",
        "_callCleanup", "_callSetUp", "_callTearDown", "_callTestMethod",
        "addCleanup", "countTestCases", "debug", "defaultTestResult",
        "doCleanups", "enterContext", "id", "run", "shortDescription",
    )
    base_fingerprint = {
        (base, name): vars(base).get(name)
        for base in trusted_bases
        for name in protected_names
    }
    suite = unittest.TestSuite()
    add_test = suite.addTest
    stream = io.StringIO()
    runner = unittest.TextTestRunner(stream=stream, verbosity=0)
    run_suite = runner.run
    spec = importlib.util.spec_from_file_location("registered_task_tests", test_path)
    if spec is None or spec.loader is None:
        raise SystemExit(2)
    module = importlib.util.module_from_spec(spec)
    trusted_streams = (
        sys.stdin, sys.stdout, sys.stderr,
        sys.__stdin__, sys.__stdout__, sys.__stderr__,
    )
    trusted_fds = tuple(os.dup(descriptor) for descriptor in (0, 1, 2))
    result = None
    execution_failed = False
    try:
        with open(os.devnull, "r", encoding="utf-8") as isolated_stdin, open(
            os.devnull, "w", encoding="utf-8"
        ) as isolated_output:
            os.dup2(isolated_stdin.fileno(), 0)
            os.dup2(isolated_output.fileno(), 1)
            os.dup2(isolated_output.fileno(), 2)
            sys.stdin = sys.__stdin__ = isolated_stdin
            sys.stdout = sys.__stdout__ = isolated_output
            sys.stderr = sys.__stderr__ = isolated_output
            spec.loader.exec_module(module)
            if any(
                vars(base).get(name) is not value
                for (base, name), value in base_fingerprint.items()
            ):
                raise RuntimeError("base class changed")
            for class_name, method_name in expected_cases:
                test_class = vars(module).get(class_name)
                if (
                    not isinstance(test_class, type)
                    or test_class.__bases__
                    not in ((trusted_test_case,), (trusted_async_case,))
                    or any(name in vars(test_class) for name in protected_names)
                ):
                    raise RuntimeError("test class changed")
                method = vars(test_class).get(method_name)
                if not callable(method):
                    raise RuntimeError("test method changed")
                add_test(test_class(method_name))
            result = run_suite(suite)
    except BaseException:
        execution_failed = True
    finally:
        for saved_descriptor, target_descriptor in zip(trusted_fds, (0, 1, 2)):
            os.dup2(saved_descriptor, target_descriptor)
            os.close(saved_descriptor)
        (
            sys.stdin, sys.stdout, sys.stderr,
            sys.__stdin__, sys.__stdout__, sys.__stderr__,
        ) = trusted_streams
    if execution_failed or result is None:
        raise SystemExit(2)
    observed_count = len(expected_cases)
    if (
        result.testsRun != observed_count
        or result.failures
        or result.errors
        or result.skipped
        or result.expectedFailures
        or result.unexpectedSuccesses
        or not result.wasSuccessful()
    ):
        sys.stderr.write(stream.getvalue())
        raise SystemExit(1)
    sys.stdout.write("READY\\n")
    sys.stdout.flush()
    nonce = sys.stdin.readline(80).strip()
    if re.fullmatch(r"[0-9a-f]{64}", nonce) is None or sys.stdin.read(1):
        raise SystemExit(2)
    sys.stdout.write(nonce + "\\n")

if len(sys.argv) == 4 and sys.argv[1] == "--child":
    child_main(Path(sys.argv[2]), load_cases(sys.argv[3]))
    raise SystemExit(0)

if len(sys.argv) != 3:
    raise SystemExit(2)
test_path = Path(sys.argv[1])
expected_cases = load_cases(sys.argv[2])
child = subprocess.Popen(
    [sys.executable, "-I", "-B", "-X", "utf8", str(Path(__file__)), "--child", str(test_path), sys.argv[2]],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    env={"HOME": "/tmp", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
)
if child.stdin is None or child.stdout is None or child.stderr is None:
    child.kill()
    raise SystemExit(2)
ready = child.stdout.readline(128)
if ready != b"READY\\n":
    child.kill()
    child.wait()
    raise SystemExit(2)
nonce = secrets.token_hex(32).encode("ascii")
try:
    child.stdin.write(nonce + b"\\n")
    child.stdin.close()
    child.stdin = None
    stdout, stderr = child.communicate()
except BaseException:
    child.kill()
    child.wait()
    raise
if child.returncode != 0 or stderr or stdout != nonce + b"\\n":
    raise SystemExit(1)
sys.stdout.write(
    json.dumps(
        {"result": "PASS", "tests": len(expected_cases)},
        separators=(",", ":"),
        sort_keys=True,
    )
    + "\\n"
)
"""


def _registered_socket_is_trusted(
    socket_path: Path, socket_metadata: os.stat_result
) -> bool:
    """Accept only a local socket writable by root/current user or its groups."""

    try:
        accessible_groups = {os.getegid(), *os.getgroups()}
    except OSError:
        return False
    return (
        not socket_path.is_symlink()
        and stat.S_ISSOCK(socket_metadata.st_mode)
        and socket_metadata.st_uid in {0, os.geteuid()}
        and not socket_metadata.st_mode & stat.S_IWOTH
        and (
            not socket_metadata.st_mode & stat.S_IWGRP
            or socket_metadata.st_gid in accessible_groups
        )
    )


def _registered_image_state() -> dict[str, Any]:
    """Require the locally preloaded, exact multi-architecture image selection."""

    _verify_trusted_executable(
        DOCKER_EXECUTABLE, "docker", allow_current_user_owner=True
    )
    environment = _sanitized_git_environment()

    def docker_stdout(
        arguments: list[str], label: str, *, host: str | None = None
    ) -> bytes:
        code, stdout, stderr = _run_bounded(
            [
                DOCKER_EXECUTABLE,
                *(["--host", host] if host is not None else []),
                *arguments,
            ],
            cwd=Path(tempfile.gettempdir()),
            env=environment,
            timeout_seconds=30,
            stdout_limit=MAX_GIT_BYTES,
            stderr_limit=MAX_GIT_BYTES,
            error_prefix=f"CURRENT_AUDIT_REGISTERED_{label}",
        )
        if code != 0 or stderr or not stdout:
            raise CurrentAuditError(f"CURRENT_AUDIT_REGISTERED_{label}_FAILED")
        return stdout

    try:
        context = (
            docker_stdout(["context", "show"], "CONTEXT_SHOW").decode("utf-8").strip()
        )
    except UnicodeDecodeError as error:
        raise CurrentAuditError("CURRENT_AUDIT_REGISTERED_CONTEXT_INVALID") from error
    if re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", context) is None:
        raise CurrentAuditError("CURRENT_AUDIT_REGISTERED_CONTEXT_INVALID")
    endpoint_payload = docker_stdout(
        [
            "context",
            "inspect",
            "--format",
            "{{json .Endpoints.docker.Host}}",
            context,
        ],
        "CONTEXT_INSPECT",
    )
    try:
        endpoint = json.loads(endpoint_payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CurrentAuditError("CURRENT_AUDIT_REGISTERED_ENDPOINT_INVALID") from error
    if not isinstance(endpoint, str) or not endpoint.startswith("unix:///"):
        raise CurrentAuditError("CURRENT_AUDIT_REGISTERED_ENDPOINT_NOT_LOCAL")
    socket_path = Path(endpoint.removeprefix("unix://"))
    try:
        socket_metadata = socket_path.lstat()
    except OSError as error:
        raise CurrentAuditError("CURRENT_AUDIT_REGISTERED_ENDPOINT_MISSING") from error
    if not _registered_socket_is_trusted(socket_path, socket_metadata):
        raise CurrentAuditError("CURRENT_AUDIT_REGISTERED_ENDPOINT_INVALID")
    daemon_template = (
        '{"architecture":{{json .Architecture}},"id":{{json .ID}},'
        '"name":{{json .Name}},"os_type":{{json .OSType}},'
        '"root":{{json .DockerRootDir}},"security":{{json .SecurityOptions}},'
        '"server_version":{{json .ServerVersion}}}'
    )
    daemon_state = _load_json_bytes(
        docker_stdout(
            ["info", "--format", daemon_template],
            "DAEMON_INSPECT",
            host=endpoint,
        ),
        "registered.daemon",
    )
    template = (
        '{"architecture":{{json .Architecture}},"id":{{json .Id}},'
        '"os":{{json .Os}},"repo_digests":{{json .RepoDigests}}}'
    )
    state = _load_json_bytes(
        docker_stdout(
            [
                "image",
                "inspect",
                "--format",
                template,
                REGISTERED_RUNNER_IMAGE,
            ],
            "IMAGE_INSPECT",
            host=endpoint,
        ),
        "registered.image",
    )
    architecture = state.get("architecture")
    daemon_architectures = {
        "amd64": {"amd64", "x86_64"},
        "arm64": {"aarch64", "arm64"},
    }
    if (
        daemon_state.get("os_type") != "linux"
        or state.get("os") != "linux"
        or architecture not in REGISTERED_RUNNER_IMAGE_IDS
        or daemon_state.get("architecture") not in daemon_architectures[architecture]
        or any(
            not isinstance(daemon_state.get(field), str) or not daemon_state[field]
            for field in ("id", "name", "root", "server_version")
        )
        or not isinstance(daemon_state.get("security"), list)
        or state.get("id") not in REGISTERED_RUNNER_IMAGE_IDS[architecture]
        or not isinstance(state.get("repo_digests"), list)
        or REGISTERED_RUNNER_IMAGE not in state["repo_digests"]
    ):
        raise CurrentAuditError("CURRENT_AUDIT_REGISTERED_IMAGE_IDENTITY")
    state["context"] = context
    state["endpoint"] = endpoint
    state["daemon_architecture"] = daemon_state["architecture"]
    state["daemon_id"] = daemon_state["id"]
    state["daemon_name"] = daemon_state["name"]
    state["daemon_root"] = daemon_state["root"]
    state["daemon_security"] = daemon_state["security"]
    state["daemon_server_version"] = daemon_state["server_version"]
    state["socket"] = {
        "path": str(socket_path),
        "device": socket_metadata.st_dev,
        "inode": socket_metadata.st_ino,
        "mode": stat.S_IMODE(socket_metadata.st_mode),
        "uid": socket_metadata.st_uid,
        "gid": socket_metadata.st_gid,
        "mtime_ns": socket_metadata.st_mtime_ns,
        "ctime_ns": socket_metadata.st_ctime_ns,
    }
    return state


def _run_registered_container(
    temporary_root: Path,
    snapshot_repo: Path,
    *,
    command: list[str],
    label: str,
) -> tuple[int, bytes, bytes]:
    """Run one bounded command in a fresh, networkless, read-only container."""

    docker_state = _registered_image_state()
    endpoint = docker_state["endpoint"]
    docker_prefix = [DOCKER_EXECUTABLE, "--host", endpoint]
    name = "haldir-current-audit-" + hashlib.sha256(os.urandom(32)).hexdigest()[:24]
    cidfile = temporary_root / f"{name}.cid"
    if cidfile.exists() or cidfile.is_symlink():
        raise CurrentAuditError(f"CURRENT_AUDIT_REGISTERED_{label}_CIDFILE_INVALID")
    mount = (
        f"type=bind,src={snapshot_repo},dst=/repo,readonly,bind-propagation=rprivate"
    )
    runner_mount = (
        f"type=bind,src={temporary_root / 'registered-test-runner.py'},"
        "dst=/audit-test-runner.py,readonly,bind-propagation=rprivate"
    )
    docker_command = [
        *docker_prefix,
        "run",
        "--rm",
        "--pull",
        "never",
        "--name",
        name,
        "--cidfile",
        str(cidfile),
        "--log-driver",
        "none",
        "--network",
        "none",
        "--read-only",
        "--pids-limit",
        "64",
        "--memory",
        "512m",
        "--memory-swap",
        "512m",
        "--cpus",
        "1",
        "--ulimit",
        "core=0:0",
        "--ulimit",
        "nofile=256:256",
        "--ulimit",
        "nproc=64:64",
        "--ulimit",
        "fsize=67108864:67108864",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--ipc",
        "none",
        "--user",
        "65534:65534",
        "--workdir",
        "/repo",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,nodev,size=67108864,mode=1777",
        "--mount",
        mount,
        "--mount",
        runner_mount,
        "--env",
        "HOME=/tmp",
        "--env",
        "LANG=C.UTF-8",
        "--env",
        "LC_ALL=C.UTF-8",
        "--env",
        "GIT_CONFIG_COUNT=1",
        "--env",
        "GIT_CONFIG_KEY_0=safe.directory",
        "--env",
        "GIT_CONFIG_VALUE_0=/repo",
        "--entrypoint",
        "/usr/bin/timeout",
        REGISTERED_RUNNER_IMAGE,
        "--signal=KILL",
        f"{MAX_VERIFIER_SECONDS:.1f}s",
        "/usr/local/bin/python3",
        "-I",
        "-B",
        "-X",
        "utf8",
        *command,
    ]
    result: tuple[int, bytes, bytes] | None = None
    run_error: BaseException | None = None
    try:
        result = _run_bounded(
            docker_command,
            cwd=temporary_root,
            env=_sanitized_git_environment(),
            timeout_seconds=MAX_VERIFIER_SECONDS + 15,
            stdout_limit=MAX_VERIFIER_OUTPUT_BYTES,
            stderr_limit=MAX_VERIFIER_OUTPUT_BYTES,
            error_prefix=f"CURRENT_AUDIT_REGISTERED_{label}_CONTAINER",
        )
    except BaseException as error:  # teardown must run even on interruption
        run_error = error
    container_id: str | None = None
    try:
        if cidfile.is_symlink():
            raise CurrentAuditError(f"CURRENT_AUDIT_REGISTERED_{label}_CIDFILE_INVALID")
        if cidfile.exists():
            raw_container_id = _read_bounded(
                cidfile, 128, f"registered.{label}.cidfile"
            )
            try:
                candidate_id = raw_container_id.decode("ascii").strip()
            except UnicodeDecodeError as error:
                raise CurrentAuditError(
                    f"CURRENT_AUDIT_REGISTERED_{label}_CIDFILE_INVALID"
                ) from error
            if re.fullmatch(r"[0-9a-f]{64}", candidate_id) is None:
                raise CurrentAuditError(
                    f"CURRENT_AUDIT_REGISTERED_{label}_CIDFILE_INVALID"
                )
            container_id = candidate_id
        elif run_error is None:
            raise CurrentAuditError(f"CURRENT_AUDIT_REGISTERED_{label}_CIDFILE_MISSING")
    except BaseException as error:
        run_error = run_error or error
    cleanup_error: BaseException | None = None
    cleanup_code = -1
    try:
        cleanup_code, _cleanup_stdout, _cleanup_stderr = _run_bounded(
            [*docker_prefix, "rm", "--force", container_id or name],
            cwd=temporary_root,
            env=_sanitized_git_environment(),
            timeout_seconds=30,
            stdout_limit=MAX_GIT_BYTES,
            stderr_limit=MAX_GIT_BYTES,
            error_prefix=f"CURRENT_AUDIT_REGISTERED_{label}_CLEANUP",
        )
    except BaseException as error:  # still prove the teardown postcondition below
        cleanup_error = error
    code = -1
    remaining = b""
    inspect_stderr = b""
    inspection_deadline = time.monotonic() + 2
    while True:
        try:
            code, remaining, inspect_stderr = _run_bounded(
                [
                    *docker_prefix,
                    "ps",
                    "--all",
                    "--quiet",
                    "--filter",
                    f"id={container_id}"
                    if container_id is not None
                    else f"name=^/{name}$",
                ],
                cwd=temporary_root,
                env=_sanitized_git_environment(),
                timeout_seconds=30,
                stdout_limit=MAX_GIT_BYTES,
                stderr_limit=MAX_GIT_BYTES,
                error_prefix=f"CURRENT_AUDIT_REGISTERED_{label}_TEARDOWN",
            )
        except BaseException as error:
            cleanup_error = cleanup_error or error
            break
        if code != 0 or inspect_stderr or not remaining:
            break
        if time.monotonic() >= inspection_deadline:
            break
        time.sleep(0.02)
    try:
        if _registered_image_state() != docker_state:
            raise CurrentAuditError(f"CURRENT_AUDIT_REGISTERED_{label}_DAEMON_CHANGED")
    except BaseException as error:
        cleanup_error = cleanup_error or error
    if cleanup_error is not None:
        raise CurrentAuditError(
            f"CURRENT_AUDIT_REGISTERED_{label}_TEARDOWN_COMMAND_FAILED"
        ) from cleanup_error
    if cleanup_code not in {0, 1}:
        raise CurrentAuditError(
            f"CURRENT_AUDIT_REGISTERED_{label}_CLEANUP_STATUS_INVALID"
        )
    if code != 0 or inspect_stderr:
        raise CurrentAuditError(
            f"CURRENT_AUDIT_REGISTERED_{label}_TEARDOWN_INSPECTION_FAILED"
        )
    if remaining:
        raise CurrentAuditError(f"CURRENT_AUDIT_REGISTERED_{label}_CONTAINER_REMAINS")
    if run_error is not None:
        raise run_error.with_traceback(run_error.__traceback__)
    if result is None:  # pragma: no cover - guarded by the try/finally contract
        raise CurrentAuditError(f"CURRENT_AUDIT_REGISTERED_{label}_NO_RESULT")
    return result


def _run_registered_verifier_v2(
    repo: Path,
    current_commit: str,
    *,
    registration: dict[str, Any],
    freeze_commit: str,
    implementation_commit: str,
    qualification_commit: str,
    activation_commit: str,
    qualification: dict[str, Any],
) -> tuple[dict[str, Any], float]:
    verifier_path = registration["verifier"]["path"]
    verifier_payload = _git_file(repo, freeze_commit, verifier_path)
    test_path = registration["tests"]["path"]
    test_payload = _git_file(repo, freeze_commit, test_path)
    if (
        len(verifier_payload) > MAX_JSON_BYTES
        or len(test_payload) > MAX_JSON_BYTES
        or not _strict_equal(
            _commit_protocol_file_record(repo, freeze_commit, verifier_path),
            registration["verifier"],
        )
        or not _strict_equal(
            _commit_protocol_file_record(repo, freeze_commit, test_path),
            registration["tests"],
        )
        or _git_tree_entry(repo, current_commit, verifier_path)
        != _git_tree_entry(repo, freeze_commit, verifier_path)
        or _git_tree_entry(repo, current_commit, test_path)
        != _git_tree_entry(repo, freeze_commit, test_path)
    ):
        raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_VERIFIER_OBJECT_DRIFT")
    discovered_test_cases = _discover_unittest_test_cases(
        test_payload, test_path, strict_runtime=True
    )
    expected_test_stdout = (
        json.dumps(
            {"result": "PASS", "tests": len(discovered_test_cases)},
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")
    expected = _registered_verifier_expected_output(
        registration,
        freeze_commit,
        implementation_commit,
        qualification_commit,
        activation_commit,
        current_commit,
        qualification,
    )
    expected_stdout = (
        json.dumps(expected, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    live_state_before = _repository_execution_state(repo)
    live_git_roots = _repository_git_roots(repo)
    live_git_state_before = {
        str(path): _bounded_filesystem_state(path, f"live.git.{index}")
        for index, path in enumerate(live_git_roots)
    }
    image_state_before = _registered_image_state()
    started = time.monotonic()
    with tempfile.TemporaryDirectory(
        prefix="haldir-current-audit-", dir=repo.parent
    ) as directory:
        temporary_root = Path(directory)
        snapshot_repo = temporary_root / "exact-repository"
        for command, error_prefix in (
            (
                _git_command(
                    "clone",
                    "--no-local",
                    "--no-hardlinks",
                    "--no-checkout",
                    str(repo),
                    str(snapshot_repo),
                ),
                "CURRENT_AUDIT_REGISTERED_SNAPSHOT_CLONE",
            ),
            (
                _git_command(
                    "checkout",
                    "--detach",
                    current_commit,
                ),
                "CURRENT_AUDIT_REGISTERED_SNAPSHOT_CHECKOUT",
            ),
        ):
            command_cwd = temporary_root if "clone" in command else snapshot_repo
            command_code, _command_stdout, _command_stderr = _run_bounded(
                command,
                cwd=command_cwd,
                env=_sanitized_git_environment(),
                timeout_seconds=30,
                stdout_limit=MAX_GIT_BYTES,
                stderr_limit=MAX_GIT_BYTES,
                error_prefix=error_prefix,
            )
            if command_code != 0:
                raise CurrentAuditError(f"{error_prefix}_FAILED")
        _git(snapshot_repo, "remote", "remove", "origin")
        raw_refs = _git(snapshot_repo, "for-each-ref", "--format=%(refname)")
        try:
            refs = raw_refs.decode("utf-8").splitlines()
        except UnicodeDecodeError as error:
            raise CurrentAuditError("CURRENT_AUDIT_REGISTERED_SNAPSHOT_REFS") from error
        for ref in refs:
            _git(snapshot_repo, "update-ref", "-d", ref)
        _git(snapshot_repo, "config", "--local", "core.logAllRefUpdates", "false")
        _git(snapshot_repo, "reflog", "expire", "--expire=now", "--all")
        _git(snapshot_repo, "repack", "-Ad")
        _git(snapshot_repo, "prune", "--expire=now")
        logs = snapshot_repo / ".git/logs"
        if logs.exists():
            shutil.rmtree(logs)
        for administrative_name in ("FETCH_HEAD", "ORIG_HEAD"):
            administrative_path = snapshot_repo / ".git" / administrative_name
            if administrative_path.exists():
                administrative_path.unlink()
        snapshot_config = _git(snapshot_repo, "config", "--local", "--list", "-z")
        snapshot_worktrees = _git(snapshot_repo, "worktree", "list", "--porcelain")
        snapshot_common_dir = (
            _git(
                snapshot_repo, "rev-parse", "--path-format=absolute", "--git-common-dir"
            )
            .decode("utf-8")
            .strip()
        )
        alternates = snapshot_repo / ".git/objects/info/alternates"
        http_alternates = snapshot_repo / ".git/objects/info/http-alternates"
        if (
            _git(snapshot_repo, "remote")
            or _git(snapshot_repo, "for-each-ref")
            or b"remote." in snapshot_config.lower()
            or str(repo).encode("utf-8") in snapshot_config
            or snapshot_worktrees.count(b"worktree ") != 1
            or str(repo).encode("utf-8") in snapshot_worktrees
            or Path(snapshot_common_dir) != snapshot_repo / ".git"
            or alternates.exists()
            or http_alternates.exists()
            or (snapshot_repo / ".git/shallow").exists()
            or b"promisor" in snapshot_config.lower()
            or _git(snapshot_repo, "rev-parse", "--is-shallow-repository").strip()
            != b"false"
        ):
            raise CurrentAuditError("CURRENT_AUDIT_REGISTERED_SNAPSHOT_ORIGIN")
        fsck_code, fsck_stdout, fsck_stderr = _run_bounded(
            _git_command(
                "fsck",
                "--full",
                "--no-reflogs",
                "--unreachable",
                "--no-progress",
            ),
            cwd=snapshot_repo,
            env=_sanitized_git_environment(),
            timeout_seconds=30,
            stdout_limit=MAX_GIT_BYTES,
            stderr_limit=MAX_GIT_BYTES,
            error_prefix="CURRENT_AUDIT_REGISTERED_SNAPSHOT_FSCK",
        )
        if fsck_code != 0 or fsck_stdout or fsck_stderr:
            raise CurrentAuditError("CURRENT_AUDIT_REGISTERED_SNAPSHOT_CLOSURE")
        _make_snapshot_world_readable(snapshot_repo)
        snapshot_head = _git(snapshot_repo, "rev-parse", "HEAD").decode("ascii").strip()
        snapshot_status = _git(
            snapshot_repo,
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
            "--ignored=matching",
        )
        if snapshot_head != current_commit or snapshot_status:
            raise CurrentAuditError("CURRENT_AUDIT_REGISTERED_SNAPSHOT_INVALID")
        snapshot_state_before = _repository_execution_state(snapshot_repo)
        snapshot_files_before = _bounded_filesystem_state(
            snapshot_repo, "registered.snapshot"
        )
        runner = temporary_root / "registered-test-runner.py"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(runner, flags, 0o444)
        try:
            os.fchmod(descriptor, 0o444)
            view = memoryview(_registered_test_runner_payload())
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise CurrentAuditError(
                        "CURRENT_AUDIT_REGISTERED_TEST_RUNNER_MATERIALIZE"
                    )
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        test_code, test_stdout, test_stderr = _run_registered_container(
            temporary_root,
            snapshot_repo,
            command=[
                "/audit-test-runner.py",
                f"/repo/{test_path}",
                json.dumps(discovered_test_cases, separators=(",", ":")),
            ],
            label="TESTS",
        )
        if (
            test_code != 0
            or test_stderr
            or test_stdout != expected_test_stdout
            or _repository_execution_state(snapshot_repo) != snapshot_state_before
            or _bounded_filesystem_state(snapshot_repo, "registered.snapshot.tests")
            != snapshot_files_before
        ):
            raise CurrentAuditError("CURRENT_AUDIT_REGISTERED_TESTS_FAILED")
        code, stdout, stderr = _run_registered_container(
            temporary_root,
            snapshot_repo,
            command=[
                f"/repo/{verifier_path}",
                "--repo",
                "/repo",
                "--freeze-commit",
                freeze_commit,
                "--implementation-commit",
                implementation_commit,
                "--qualification-commit",
                qualification_commit,
                "--activation-commit",
                activation_commit,
                "--current-commit",
                current_commit,
            ],
            label="VERIFIER",
        )
        after_head = _git(snapshot_repo, "rev-parse", "HEAD").decode("ascii").strip()
        after_status = _git(
            snapshot_repo,
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
            "--ignored=matching",
        )
        if (
            after_head != current_commit
            or after_status
            or _repository_execution_state(snapshot_repo) != snapshot_state_before
            or _bounded_filesystem_state(snapshot_repo, "registered.snapshot.verifier")
            != snapshot_files_before
        ):
            raise CurrentAuditError("CURRENT_AUDIT_REGISTERED_SNAPSHOT_MUTATED")
    if (
        _repository_execution_state(repo) != live_state_before
        or {
            str(path): _bounded_filesystem_state(path, f"live.git.after.{index}")
            for index, path in enumerate(sorted(live_git_roots))
        }
        != live_git_state_before
    ):
        raise CurrentAuditError("CURRENT_AUDIT_REGISTERED_LIVE_REPOSITORY_MUTATED")
    if _registered_image_state() != image_state_before:
        raise CurrentAuditError("CURRENT_AUDIT_REGISTERED_IMAGE_CHANGED")
    _require_verifier_output_bound(stdout, "registered_verifier.stdout")
    _require_verifier_output_bound(stderr, "registered_verifier.stderr")
    if code != 0 or stderr or stdout != expected_stdout:
        raise CurrentAuditError("CURRENT_AUDIT_REGISTERED_VERIFIER_FAILED")
    return expected, time.monotonic() - started


def _successor_terminal_task(
    bootstrap_task: dict[str, Any],
    *,
    task_id: str,
    freeze_commit: str,
    implementation_commit: str,
    qualification_commit: str,
    registration: dict[str, Any],
    contract: dict[str, Any],
    qualification: dict[str, Any],
    outcome: dict[str, Any],
) -> dict[str, Any]:
    task = copy.deepcopy(bootstrap_task)
    task.update(
        {
            "status": "VERIFIED",
            "claim_disposition": outcome["claim_disposition"],
            "assigned_reviewers": [
                item["id"] for item in qualification["review_records"]
            ],
            "implementation_commits": [freeze_commit, implementation_commit],
            "evidence": [
                *[item["id"] for item in qualification["evidence_records"]],
                *[item["id"] for item in contract["activation_evidence_requirements"]],
            ],
            "closure_commit": qualification_commit,
            "twenty_lens_reviews": qualification["twenty_lens_reviews"],
        }
    )
    if task["id"] != task_id:
        raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_TASK_IDENTITY")
    return task


def _successor_active_claims(
    prior: dict[str, Any],
    *,
    repo: Path,
    implementation_commit: str,
    task_id: str,
    epoch: int,
    outcome: dict[str, Any],
    qualification: dict[str, Any],
) -> dict[str, Any]:
    current_inventory = _claim_inventory(repo, implementation_commit)
    next_claims = copy.deepcopy(prior)
    next_claims.update(
        {
            "verified_prefix": int(task_id.removeprefix("CH-T")) + 1,
            "overall_status": outcome["overall_status"],
            "claim_inventory": current_inventory,
            "asserted_claims": [
                item
                for item in current_inventory
                if item["id"] in outcome["active_claims"]
            ],
            "active_claims": outcome["active_claims"],
            "release_qualified_claims": outcome["release_qualified_claims"],
            "removed_claims": outcome["removed_claims"],
            "non_claimed_claims": outcome["non_claimed_claims"],
            "narrowed_claims": outcome["narrowed_claims"],
            "residual_limitations": qualification["limitations"],
        }
    )
    next_claims["current_epochs"] = {
        **prior["current_epochs"],
        task_id: epoch,
    }
    public_records = {
        item["path"]: copy.deepcopy(item) for item in prior["public_surface_records"]
    }
    for path in outcome["public_surfaces"]:
        if _git_path_exists(repo, implementation_commit, path):
            public_records[path] = _commit_regular_file_record(
                repo, implementation_commit, path
            )
        else:
            public_records.pop(path, None)
    claim_ledger_record = _commit_regular_file_record(
        repo, implementation_commit, "docs/CLAIM-LEDGER.md"
    )
    public_records["docs/CLAIM-LEDGER.md"] = claim_ledger_record
    next_claims["public_surface_records"] = [
        public_records[path] for path in sorted(public_records)
    ]
    next_claims["claim_ledger"] = claim_ledger_record
    authorized = task_id == "CH-T125" and outcome["overall_status"] in {
        "GO",
        "NARROWED_GO",
    }
    next_claims.update(
        {
            "tag_authorized": authorized,
            "github_release_authorized": authorized,
            "doi_authorized": False,
            "zenodo_authorized": False,
            "archive_authorized": False,
        }
    )
    return next_claims


def _validate_successor_activation_v2(
    repo: Path,
    commit: str,
    *,
    registration: dict[str, Any],
    contract: dict[str, Any],
    freeze_commit: str,
    implementation_commit: str,
    qualification_commit: str,
    qualification: dict[str, Any],
    outcome: dict[str, Any],
    expected_ledger: dict[str, Any],
    expected_claims: dict[str, Any],
    verifier_output: dict[str, Any],
) -> None:
    task_id = registration["task_id"]
    epoch = registration["epoch"]
    receipt_path = registration["verifier_receipt_path"]
    receipt_payload = _git_file(repo, commit, receipt_path)
    expected_receipt = (
        json.dumps(
            _registered_verifier_receipt(verifier_output),
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")
    if receipt_payload != expected_receipt:
        raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_VERIFIER_RECEIPT")
    activation, _payload = _read_commit_json(
        repo,
        commit,
        registration["activation_path"],
        f"protocol.activation.{task_id}.{epoch}",
    )
    fields = {
        "schema_version",
        "task_id",
        "epoch",
        "release_target",
        "author",
        "persistent_identifier",
        "effective_on",
        "freeze_commit",
        "implementation_commit",
        "qualification_commit",
        "qualification_record",
        "verifier_receipt",
        "activation_evidence_records",
        "requirements_record",
        "active_claims_record",
        "selected_claim_outcome",
        "decision",
    }
    expected_activation_evidence = contract["activation_evidence_requirements"]
    activation_records = activation.get("activation_evidence_records")
    if not isinstance(activation_records, list) or len(activation_records) != len(
        expected_activation_evidence
    ):
        raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_ACTIVATION_EVIDENCE")
    for index, (record, requirement) in enumerate(
        zip(activation_records, expected_activation_evidence, strict=True)
    ):
        record = _require_fields(
            record,
            {
                "id",
                "kind",
                "file",
                "subject_commit",
                "result",
                "started_at_utc",
                "completed_at_utc",
            },
            f"protocol.activation.evidence.{index}",
        )
        started = _parse_utc(
            record.get("started_at_utc"), "protocol.activation.started"
        )
        completed = _parse_utc(
            record.get("completed_at_utc"), "protocol.activation.completed"
        )
        expected_file = _commit_regular_file_record(repo, commit, requirement["path"])
        if (
            record.get("id") != requirement["id"]
            or record.get("kind") != requirement["kind"]
            or not _strict_equal(record.get("file"), expected_file)
            or record.get("subject_commit") != qualification_commit
            or record.get("result") != "PASS"
            or expected_file["bytes"] > requirement["max_bytes"]
            or not (
                _commit_datetime(repo, qualification_commit)
                <= started
                <= completed
                <= _commit_datetime(repo, commit)
            )
        ):
            raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_ACTIVATION_EVIDENCE")
    expected = {
        "schema_version": "1.0.0",
        "task_id": task_id,
        "epoch": epoch,
        "release_target": "0.9.0",
        "author": {"name": "Sepehr Mahmoudian", "email": "sepmhn@gmail.com"},
        "persistent_identifier": None,
        "effective_on": "SIGNED_COMMIT_FIRST_CONTAINING_EXACT_ACTIVATION_RECEIPTS_AND_TRANSITION",
        "freeze_commit": freeze_commit,
        "implementation_commit": implementation_commit,
        "qualification_commit": qualification_commit,
        "qualification_record": _commit_regular_file_record(
            repo, qualification_commit, registration["qualification_path"]
        ),
        "verifier_receipt": _commit_regular_file_record(repo, commit, receipt_path),
        "activation_evidence_records": activation_records,
        "requirements_record": _commit_regular_file_record(
            repo, commit, EXPECTED_REQUIREMENTS_LEDGER["path"]
        ),
        "active_claims_record": _commit_regular_file_record(
            repo, commit, ACTIVE_CLAIMS_PATH
        ),
        "selected_claim_outcome": outcome,
        "decision": {
            "task_status": "VERIFIED",
            "claim_disposition": outcome["claim_disposition"],
            "overall_status": outcome["overall_status"],
            "tag_authorized": expected_claims["tag_authorized"],
            "github_release_authorized": expected_claims["github_release_authorized"],
            "doi_authorized": False,
            "zenodo_authorized": False,
            "archive_authorized": False,
        },
    }
    if set(activation) != fields or not _strict_equal(activation, expected):
        raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_ACTIVATION_INVALID")
    ledger = _load_json_bytes(
        _git_file(repo, commit, EXPECTED_REQUIREMENTS_LEDGER["path"]),
        "protocol.activation.requirements",
    )
    claims = _load_json_bytes(
        _git_file(repo, commit, ACTIVE_CLAIMS_PATH),
        "protocol.activation.claims",
    )
    if not _strict_equal(ledger, expected_ledger) or not _strict_equal(
        claims, expected_claims
    ):
        raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_ACTIVATION_STATE")


def _verify_protocol_commit_identity(repo: Path, commit: str, parent: str) -> None:
    metadata = _commit_metadata(repo, commit)
    if (
        metadata["parent"] != parent
        or metadata["author_name"] != "Sepehr Mahmoudian"
        or metadata["author_email"] != "sepmhn@gmail.com"
        or metadata["committer_name"] != "Sepehr Mahmoudian"
        or metadata["committer_email"] != "sepmhn@gmail.com"
        or not metadata["subject"].startswith("release: ")
    ):
        raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_COMMIT_IDENTITY")
    _verify_named_commit_signature(repo, commit, "PROTOCOL")


def _validate_protocol_changed_paths(statuses: dict[str, str]) -> None:
    if len(statuses) > MAX_CHANGED_PATHS_PER_COMMIT:
        raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_CHANGED_PATH_COUNT")
    for path, status in statuses.items():
        _require_protocol_path(path, "protocol.changed_path")
        if status == "T":
            raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_GIT_TYPE_CHANGE_FORBIDDEN")
        if status not in {"A", "M", "D"}:
            raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_CHANGED_PATH_STATUS")


def _reverse_path_status(
    repo: Path, parent: str, rollback: str, path: str
) -> str | None:
    parent_entry = _git_tree_entry(repo, parent, path)
    rollback_entry = _git_tree_entry(repo, rollback, path)
    if parent_entry is not None and rollback_entry is not None:
        return None if parent_entry == rollback_entry else "M"
    if parent_entry is not None:
        return "D"
    if rollback_entry is not None:
        return "A"
    return None


def _verify_protocol_revocation(
    repo: Path,
    commit: str,
    parent: str,
    statuses: dict[str, str],
    *,
    framework_commit: str,
    qualification_commit: str,
    bootstrap: dict[str, Any],
    current_ledger: dict[str, Any],
    current_claims: dict[str, Any],
    verified_prefix: int,
    inflight: dict[str, Any] | None,
    revocations: list[dict[str, Any]],
    snapshots: dict[int, tuple[str, dict[str, Any], dict[str, Any]]],
    activated_plans: dict[int, dict[str, str]],
    registration_map: dict[str, dict[str, Any]],
    active_registration_keys: set[str],
) -> tuple[
    dict[str, Any],
    dict[str, Any],
    int,
    None,
    list[dict[str, Any]],
    dict[int, tuple[str, dict[str, Any], dict[str, Any]]],
    dict[int, dict[str, str]],
    set[str],
    set[str],
]:
    if len(revocations) >= MAX_REVOCATIONS or verified_prefix < 1:
        raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_REVOCATION_BOUND")
    ledger = _load_json_bytes(
        _git_file(repo, commit, REVOCATION_PATH), "protocol.revocation.ledger"
    )
    expected_top = _expected_empty_revocation_ledger(
        framework_commit, qualification_commit
    )
    if set(ledger) != set(expected_top) or not _strict_equal(
        {key: value for key, value in ledger.items() if key != "records"},
        {key: value for key, value in expected_top.items() if key != "records"},
    ):
        raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_REVOCATION_METADATA")
    records = ledger.get("records")
    if (
        not isinstance(records, list)
        or len(records) != len(revocations) + 1
        or not _strict_equal(records[:-1], revocations)
    ):
        raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_REVOCATION_APPEND")
    record = _require_fields(
        records[-1],
        {
            "record_id",
            "record_type",
            "author",
            "target_task",
            "target_epoch",
            "reason",
            "prior_head",
            "previous_verified_prefix",
            "retained_prefix",
            "invalidated_epochs",
            "deactivated_registrations",
            "aborted_candidate",
            "rollback_source",
            "restored_product_paths",
            "cause_evidence_records",
            "requirements_record",
            "active_claims_record",
            "effective_on",
        },
        "protocol.revocation.record",
    )
    target_task = record.get("target_task")
    if (
        not isinstance(target_task, str)
        or re.fullmatch(r"CH-T(?:00\d|0[1-9]\d|1[01]\d|12[0-5])", target_task) is None
    ):
        raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_REVOCATION_TARGET")
    target_index = int(target_task.removeprefix("CH-T"))
    if target_index >= verified_prefix or target_index not in snapshots:
        raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_REVOCATION_TARGET")
    rollback_source, expected_ledger, expected_claims = snapshots[target_index]
    expected_ledger = copy.deepcopy(expected_ledger)
    expected_claims = copy.deepcopy(expected_claims)
    expected_ledger["overall_status"] = "NO_GO"
    expected_claims.update(
        {
            "overall_status": "NO_GO",
            "tag_authorized": False,
            "github_release_authorized": False,
            "doi_authorized": False,
            "zenodo_authorized": False,
            "archive_authorized": False,
        }
    )
    observed_requirements = _load_json_bytes(
        _git_file(repo, commit, EXPECTED_REQUIREMENTS_LEDGER["path"]),
        "protocol.revocation.requirements",
    )
    observed_claims = _load_json_bytes(
        _git_file(repo, commit, ACTIVE_CLAIMS_PATH),
        "protocol.revocation.claims",
    )
    if not _strict_equal(observed_requirements, expected_ledger) or not _strict_equal(
        observed_claims, expected_claims
    ):
        raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_REVOCATION_STATE")
    invalidated_epochs = [
        {"task_id": task_id, "epoch": epoch}
        for task_id, epoch in current_claims["current_epochs"].items()
        if int(task_id.removeprefix("CH-T")) >= target_index
    ]
    invalidated_epochs.sort(key=lambda item: item["task_id"])
    deactivated_registrations = sorted(
        key
        for key in active_registration_keys
        if int(registration_map[key]["task_id"].removeprefix("CH-T")) >= target_index
    )
    next_active_registration_keys = active_registration_keys - set(
        deactivated_registrations
    )
    expected_aborted = None
    if inflight is not None:
        expected_aborted = {
            "task_id": inflight["task_id"],
            "epoch": inflight["epoch"],
            "stage": inflight["stage"],
            "freeze_commit": inflight["freeze_commit"],
            "implementation_commit": inflight["implementation_commit"],
            "qualification_commit": inflight["qualification_commit"],
        }
    product_paths = {
        path
        for task_index, plan in activated_plans.items()
        if task_index >= target_index
        for path in plan
    }
    if inflight is not None and inflight["stage"] in {"I", "C"}:
        freeze_path = _task_epoch_paths(inflight["task_id"], inflight["epoch"])[
            "freeze"
        ]
        contract = _load_json_bytes(
            _git_file(repo, inflight["freeze_commit"], freeze_path),
            "protocol.revocation.freeze",
        )
        product_paths.update(contract["implementation_plan"])
    expected_product_statuses: dict[str, str] = {}
    for path in sorted(product_paths):
        status = _reverse_path_status(repo, parent, rollback_source, path)
        if status is not None:
            expected_product_statuses[path] = status
            if _git_tree_entry(repo, commit, path) != _git_tree_entry(
                repo, rollback_source, path
            ):
                raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_REVOCATION_ROLLBACK")
    cause_records = record.get("cause_evidence_records")
    if (
        not isinstance(cause_records, list)
        or not 1 <= len(cause_records) <= MAX_REVOCATION_CAUSE_FILES
    ):
        raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_REVOCATION_EVIDENCE")
    cause_paths: list[str] = []
    cause_bytes = 0
    expected_record_id = f"R{len(revocations) + 1:04d}"
    for index, cause in enumerate(cause_records):
        cause = _require_fields(
            cause, {"id", "kind", "file"}, f"protocol.revocation.cause.{index}"
        )
        path = (
            _require_protocol_path(
                cause.get("file", {}).get("path"), "protocol.revocation.cause.path"
            )
            if isinstance(cause.get("file"), dict)
            else ""
        )
        expected_cause_file = (
            _commit_regular_file_record(repo, commit, path) if path else {}
        )
        if (
            cause.get("id") != f"{expected_record_id}-E{index + 1:02d}"
            or not isinstance(cause.get("kind"), str)
            or re.fullmatch(r"[A-Z][A-Z0-9_]{2,63}", cause["kind"]) is None
            or not path.startswith(
                f"release/0.9.0/current-head/tasks/revocations/{expected_record_id}/"
            )
            or not _strict_equal(cause["file"], expected_cause_file)
        ):
            raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_REVOCATION_EVIDENCE")
        cause_paths.append(path)
        cause_bytes = _bounded_revocation_cause_total(
            cause_bytes, expected_cause_file["bytes"]
        )
    if len(cause_paths) != len(set(cause_paths)):
        raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_REVOCATION_EVIDENCE")
    expected_statuses = {
        **expected_product_statuses,
        **{path: "A" for path in cause_paths},
        REVOCATION_PATH: "M",
        EXPECTED_REQUIREMENTS_LEDGER["path"]: "M",
        ACTIVE_CLAIMS_PATH: "M",
    }
    if not _strict_equal(statuses, dict(sorted(expected_statuses.items()))):
        raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_REVOCATION_DIFF")
    target_epoch = current_claims["current_epochs"].get(target_task)
    expected_record = {
        "record_id": expected_record_id,
        "record_type": "VERIFIED_SUFFIX_REVOCATION",
        "author": {"name": "Sepehr Mahmoudian", "email": "sepmhn@gmail.com"},
        "target_task": target_task,
        "target_epoch": target_epoch,
        "reason": record.get("reason"),
        "prior_head": parent,
        "previous_verified_prefix": verified_prefix,
        "retained_prefix": target_index,
        "invalidated_epochs": invalidated_epochs,
        "deactivated_registrations": deactivated_registrations,
        "aborted_candidate": expected_aborted,
        "rollback_source": rollback_source,
        "restored_product_paths": sorted(expected_product_statuses),
        "cause_evidence_records": cause_records,
        "requirements_record": _commit_regular_file_record(
            repo, commit, EXPECTED_REQUIREMENTS_LEDGER["path"]
        ),
        "active_claims_record": _commit_regular_file_record(
            repo, commit, ACTIVE_CLAIMS_PATH
        ),
        "effective_on": "SIGNED_COMMIT_FIRST_CONTAINING_EXACT_REVOCATION_AND_ROLLBACK",
    }
    if record.get("reason") not in {
        "EVIDENCE_INVALIDATED",
        "IMPLEMENTATION_DEFECT",
        "CLAIM_INVALIDATED",
        "REVIEW_INVALIDATED",
    } or not _strict_equal(record, expected_record):
        raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_REVOCATION_RECORD")
    updated_snapshots = {
        prefix: value for prefix, value in snapshots.items() if prefix <= target_index
    }
    updated_plans = {
        index: plan for index, plan in activated_plans.items() if index < target_index
    }
    return (
        expected_ledger,
        expected_claims,
        target_index,
        None,
        [*revocations, copy.deepcopy(record)],
        updated_snapshots,
        updated_plans,
        set(cause_paths),
        next_active_registration_keys,
    )


def _verify_protocol_inflight_abort(
    repo: Path,
    commit: str,
    parent: str,
    statuses: dict[str, str],
    *,
    framework_commit: str,
    qualification_commit: str,
    current_ledger: dict[str, Any],
    current_claims: dict[str, Any],
    verified_prefix: int,
    inflight: dict[str, Any] | None,
    contract: dict[str, Any] | None,
    revocations: list[dict[str, Any]],
    snapshots: dict[int, tuple[str, dict[str, Any], dict[str, Any]]],
    activated_plans: dict[int, dict[str, str]],
    active_registration_keys: set[str],
) -> tuple[
    dict[str, Any],
    dict[str, Any],
    int,
    None,
    list[dict[str, Any]],
    dict[int, tuple[str, dict[str, Any], dict[str, Any]]],
    dict[int, dict[str, str]],
    set[str],
    set[str],
]:
    """Abort one unusable F/I/C epoch without revoking a valid predecessor."""

    if (
        inflight is None
        or contract is None
        or len(revocations) >= MAX_REVOCATIONS
        or verified_prefix not in snapshots
        or inflight["key"] not in active_registration_keys
    ):
        raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_ABORT_STATE")
    ledger = _load_json_bytes(
        _git_file(repo, commit, REVOCATION_PATH), "protocol.abort.ledger"
    )
    expected_top = _expected_empty_revocation_ledger(
        framework_commit, qualification_commit
    )
    if set(ledger) != set(expected_top) or not _strict_equal(
        {key: value for key, value in ledger.items() if key != "records"},
        {key: value for key, value in expected_top.items() if key != "records"},
    ):
        raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_ABORT_METADATA")
    records = ledger.get("records")
    if (
        not isinstance(records, list)
        or len(records) != len(revocations) + 1
        or not _strict_equal(records[:-1], revocations)
    ):
        raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_ABORT_APPEND")
    record = _require_fields(
        records[-1],
        {
            "record_id",
            "record_type",
            "author",
            "target_task",
            "target_epoch",
            "reason",
            "prior_head",
            "previous_verified_prefix",
            "retained_prefix",
            "invalidated_epochs",
            "deactivated_registrations",
            "aborted_candidate",
            "rollback_source",
            "restored_product_paths",
            "cause_evidence_records",
            "requirements_record",
            "active_claims_record",
            "effective_on",
        },
        "protocol.abort.record",
    )
    rollback_source, snapshot_ledger, snapshot_claims = snapshots[verified_prefix]
    if not _strict_equal(current_ledger, snapshot_ledger) or not _strict_equal(
        current_claims, snapshot_claims
    ):
        raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_ABORT_SNAPSHOT_STATE")
    observed_requirements = _load_json_bytes(
        _git_file(repo, commit, EXPECTED_REQUIREMENTS_LEDGER["path"]),
        "protocol.abort.requirements",
    )
    observed_claims = _load_json_bytes(
        _git_file(repo, commit, ACTIVE_CLAIMS_PATH),
        "protocol.abort.claims",
    )
    if not _strict_equal(observed_requirements, current_ledger) or not _strict_equal(
        observed_claims, current_claims
    ):
        raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_ABORT_STATE_DRIFT")
    product_paths = (
        set(contract["implementation_plan"])
        if inflight["stage"] in {"I", "C"}
        else set()
    )
    product_statuses: dict[str, str] = {}
    for path in sorted(product_paths):
        status = _reverse_path_status(repo, parent, rollback_source, path)
        if status is None or _git_tree_entry(repo, commit, path) != _git_tree_entry(
            repo, rollback_source, path
        ):
            raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_ABORT_ROLLBACK")
        product_statuses[path] = status
    expected_record_id = f"R{len(revocations) + 1:04d}"
    cause_records = record.get("cause_evidence_records")
    if (
        not isinstance(cause_records, list)
        or not 1 <= len(cause_records) <= MAX_REVOCATION_CAUSE_FILES
    ):
        raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_ABORT_EVIDENCE")
    cause_paths: list[str] = []
    cause_bytes = 0
    for index, cause in enumerate(cause_records):
        cause = _require_fields(
            cause, {"id", "kind", "file"}, f"protocol.abort.cause.{index}"
        )
        file_value = cause.get("file")
        path = (
            _require_protocol_path(file_value.get("path"), "protocol.abort.cause.path")
            if isinstance(file_value, dict)
            else ""
        )
        expected_file = _commit_regular_file_record(repo, commit, path) if path else {}
        if (
            cause.get("id") != f"{expected_record_id}-E{index + 1:02d}"
            or not isinstance(cause.get("kind"), str)
            or re.fullmatch(r"[A-Z][A-Z0-9_]{2,63}", cause["kind"]) is None
            or not path.startswith(
                f"release/0.9.0/current-head/tasks/revocations/{expected_record_id}/"
            )
            or not _strict_equal(file_value, expected_file)
        ):
            raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_ABORT_EVIDENCE")
        cause_paths.append(path)
        cause_bytes = _bounded_revocation_cause_total(
            cause_bytes, expected_file["bytes"]
        )
    if len(cause_paths) != len(set(cause_paths)):
        raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_ABORT_EVIDENCE")
    expected_statuses = {
        **product_statuses,
        **{path: "A" for path in cause_paths},
        REVOCATION_PATH: "M",
    }
    if not _strict_equal(statuses, dict(sorted(expected_statuses.items()))):
        raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_ABORT_DIFF")
    aborted_candidate = {
        "task_id": inflight["task_id"],
        "epoch": inflight["epoch"],
        "stage": inflight["stage"],
        "freeze_commit": inflight["freeze_commit"],
        "implementation_commit": inflight["implementation_commit"],
        "qualification_commit": inflight["qualification_commit"],
    }
    expected_record = {
        "record_id": expected_record_id,
        "record_type": "INFLIGHT_ABORT",
        "author": {"name": "Sepehr Mahmoudian", "email": "sepmhn@gmail.com"},
        "target_task": inflight["task_id"],
        "target_epoch": inflight["epoch"],
        "reason": record.get("reason"),
        "prior_head": parent,
        "previous_verified_prefix": verified_prefix,
        "retained_prefix": verified_prefix,
        "invalidated_epochs": [],
        "deactivated_registrations": [inflight["key"]],
        "aborted_candidate": aborted_candidate,
        "rollback_source": rollback_source,
        "restored_product_paths": sorted(product_paths),
        "cause_evidence_records": cause_records,
        "requirements_record": _commit_regular_file_record(
            repo, commit, EXPECTED_REQUIREMENTS_LEDGER["path"]
        ),
        "active_claims_record": _commit_regular_file_record(
            repo, commit, ACTIVE_CLAIMS_PATH
        ),
        "effective_on": "SIGNED_COMMIT_FIRST_CONTAINING_EXACT_INFLIGHT_ABORT_AND_ROLLBACK",
    }
    if record.get("reason") not in {
        "CONTRACT_DEFECT",
        "EVIDENCE_DEFECT",
        "IMPLEMENTATION_DEFECT",
        "REVIEW_DEFECT",
        "VERIFIER_DEFECT",
    } or not _strict_equal(record, expected_record):
        raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_ABORT_RECORD")
    return (
        current_ledger,
        current_claims,
        verified_prefix,
        None,
        [*revocations, copy.deepcopy(record)],
        snapshots,
        activated_plans,
        set(cause_paths),
        active_registration_keys - {inflight["key"]},
    )


def _revocation_transition(record_type: Any) -> Any:
    """Select only a recognized signed rollback transition type."""

    if record_type == "INFLIGHT_ABORT":
        return _verify_protocol_inflight_abort
    if record_type == "VERIFIED_SUFFIX_REVOCATION":
        return _verify_protocol_revocation
    raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_REVOCATION_DISPATCH_TYPE")


def _verify_forward_protocol_history(
    repo: Path,
    chain: list[str],
    *,
    framework_commit: str,
    qualification_commit: str,
    activation_commit: str,
) -> None:
    """Stream the exact post-D F/I/C/D/R state machine once."""

    if len(chain) > MAX_FIRST_PARENT_COMMITS:
        raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_COMMIT_BOUND")
    requirements_path = EXPECTED_REQUIREMENTS_LEDGER["path"]
    bootstrap = _load_json_bytes(
        _git_file(repo, IMPLEMENTATION_COMMIT, requirements_path),
        "protocol.bootstrap",
    )
    current_ledger = _load_json_bytes(
        _git_file(repo, activation_commit, requirements_path),
        "protocol.initial.requirements",
    )
    _verify_terminal_requirement_state(
        current_ledger,
        bootstrap,
        framework_commit=framework_commit,
        qualification_commit=qualification_commit,
        evidence_ids=list(TERMINAL_EVIDENCE_IDS),
        lens_projection=ch_t000_lens_projection(),
    )
    current_claims = _load_json_bytes(
        _git_file(repo, activation_commit, ACTIVE_CLAIMS_PATH),
        "protocol.initial.claims",
    )
    if not _strict_equal(
        current_claims, _expected_initial_active_claims(repo, framework_commit)
    ):
        raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_INITIAL_CLAIMS")
    registry_top = _expected_empty_successor_registry(
        framework_commit, qualification_commit
    )
    revocation_top = _expected_empty_revocation_ledger(
        framework_commit, qualification_commit
    )
    registrations: list[dict[str, Any]] = []
    registration_map: dict[str, dict[str, Any]] = {}
    active_registration_keys: set[str] = set()
    contracts: dict[str, dict[str, Any]] = {}
    max_epoch: dict[str, int] = {"CH-T000": 1}
    revocations: list[dict[str, Any]] = []
    protected_paths = {
        *BASE_IMMUTABLE_PATHS,
        *FRAMEWORK_CORE_FROZEN_PATHS,
        *QUALIFIED_OPEN_DATA_PATHS,
        ACTIVATION_PATH,
        *ACTIVATION_EVIDENCE_PATHS,
    }
    verified_prefix = 1
    inflight: dict[str, Any] | None = None
    verifier_seconds = 0.0
    hygiene_total = 0
    snapshots: dict[int, tuple[str, dict[str, Any], dict[str, Any]]] = {
        0: (
            framework_commit,
            bootstrap,
            _initial_claims_before_ch_t000(repo, framework_commit),
        ),
        1: (
            activation_commit,
            copy.deepcopy(current_ledger),
            copy.deepcopy(current_claims),
        ),
    }
    activated_plans: dict[int, dict[str, str]] = {}
    active_verifiers: dict[int, dict[str, Any]] = {}
    previous = activation_commit

    def rerun_active_verifiers(
        target_commit: str,
        changed_paths: set[str],
        *,
        force: bool = False,
    ) -> None:
        nonlocal verifier_seconds
        for _task_index, active in sorted(active_verifiers.items()):
            if active["last_run_commit"] == target_commit:
                continue
            triggers = active["verification_triggers"]
            if not force and not any(
                path in triggers["paths"]
                or any(path.startswith(root) for root in triggers["roots"])
                for path in changed_paths
            ):
                continue
            _output, elapsed = _run_registered_verifier_v2(
                repo,
                target_commit,
                registration=active["registration"],
                freeze_commit=active["freeze_commit"],
                implementation_commit=active["implementation_commit"],
                qualification_commit=active["qualification_commit"],
                activation_commit=active["activation_commit"],
                qualification=active["qualification"],
            )
            verifier_seconds += elapsed
            active["last_run_commit"] = target_commit
            if verifier_seconds > MAX_VERIFIER_AGGREGATE_SECONDS:
                raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_VERIFIER_TIME_BOUND")

    for position, commit in enumerate(chain[3:], start=3):
        _verify_protocol_commit_identity(repo, commit, previous)
        _verify_post_activation_gate_retention(repo, commit)
        statuses = _changed_path_statuses(repo, previous, commit)
        _validate_protocol_changed_paths(statuses)
        hygiene_total = _verify_changed_hygiene(repo, commit, statuses, hygiene_total)
        touched_protected = sorted(set(statuses) & protected_paths)
        if touched_protected:
            raise CurrentAuditError(
                "CURRENT_AUDIT_PROTOCOL_PROTECTED_PATH:" + touched_protected[0]
            )
        registry_changed = SUCCESSOR_REGISTRY_PATH in statuses
        revocation_changed = REVOCATION_PATH in statuses
        if registry_changed and revocation_changed:
            raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_STAGE_AMBIGUOUS")
        if revocation_changed:
            candidate_revocation = _load_json_bytes(
                _git_file(repo, commit, REVOCATION_PATH),
                "protocol.revocation.dispatch",
            )
            candidate_records = candidate_revocation.get("records")
            record_type = (
                candidate_records[-1].get("record_type")
                if isinstance(candidate_records, list)
                and candidate_records
                and isinstance(candidate_records[-1], dict)
                else None
            )
            transition = _revocation_transition(record_type)
            transition_arguments: dict[str, Any] = {
                "framework_commit": framework_commit,
                "qualification_commit": qualification_commit,
                "current_ledger": current_ledger,
                "current_claims": current_claims,
                "verified_prefix": verified_prefix,
                "inflight": inflight,
                "revocations": revocations,
                "snapshots": snapshots,
                "activated_plans": activated_plans,
                "active_registration_keys": active_registration_keys,
            }
            if transition is _verify_protocol_inflight_abort:
                transition_arguments["contract"] = (
                    contracts.get(inflight["key"]) if inflight is not None else None
                )
            else:
                transition_arguments.update(
                    {
                        "bootstrap": bootstrap,
                        "registration_map": registration_map,
                    }
                )
            (
                current_ledger,
                current_claims,
                verified_prefix,
                inflight,
                revocations,
                snapshots,
                activated_plans,
                added_protected,
                active_registration_keys,
            ) = transition(
                repo,
                commit,
                previous,
                statuses,
                **transition_arguments,
            )
            protected_paths.update(added_protected)
            active_verifiers = {
                index: value
                for index, value in active_verifiers.items()
                if index < verified_prefix
            }
        elif registry_changed:
            if inflight is not None or verified_prefix >= len(bootstrap["tasks"]):
                raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_FREEZE_ORDER")
            task_id = f"CH-T{verified_prefix:03d}"
            epoch = max_epoch.get(task_id, 0) + 1
            paths = _task_epoch_paths(task_id, epoch)
            expected_statuses = {
                SUCCESSOR_REGISTRY_PATH: "M",
                paths["verifier"]: "A",
                paths["tests"]: "A",
                paths["freeze"]: "A",
            }
            if not _strict_equal(statuses, dict(sorted(expected_statuses.items()))):
                raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_FREEZE_DIFF")
            registry = _load_json_bytes(
                _git_file(repo, commit, SUCCESSOR_REGISTRY_PATH),
                "protocol.registry",
            )
            if set(registry) != set(registry_top) or not _strict_equal(
                {
                    key: value
                    for key, value in registry.items()
                    if key != "registrations"
                },
                {
                    key: value
                    for key, value in registry_top.items()
                    if key != "registrations"
                },
            ):
                raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_REGISTRY_METADATA")
            observed_registrations = registry.get("registrations")
            if (
                not isinstance(observed_registrations, list)
                or len(observed_registrations) != len(registrations) + 1
                or len(observed_registrations) > MAX_REGISTRATIONS
                or not _strict_equal(observed_registrations[:-1], registrations)
            ):
                raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_REGISTRY_APPEND")
            registration, contract = _validate_successor_registration_v2(
                repo,
                commit,
                observed_registrations[-1],
                bootstrap_task=bootstrap["tasks"][verified_prefix],
                prior_claims=current_claims,
                prior_claims_record=_commit_file_record(
                    repo, previous, ACTIVE_CLAIMS_PATH
                ),
            )
            if registration["task_id"] != task_id or registration["epoch"] != epoch:
                raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_REGISTRATION_SEQUENCE")
            key = _protocol_registration_key(task_id, epoch)
            registrations.append(copy.deepcopy(registration))
            registration_map[key] = registration
            active_registration_keys.add(key)
            contracts[key] = contract
            max_epoch[task_id] = epoch
            protected_paths.update({paths["verifier"], paths["tests"], paths["freeze"]})
            inflight = {
                "task_id": task_id,
                "task_index": verified_prefix,
                "epoch": epoch,
                "key": key,
                "stage": "F",
                "freeze_commit": commit,
                "implementation_commit": None,
                "qualification_commit": None,
                "qualification": None,
                "outcome": None,
            }
        elif inflight is None:
            raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_UNCLASSIFIED_COMMIT")
        elif inflight["stage"] == "F":
            contract = contracts[inflight["key"]]
            if not _strict_equal(statuses, contract["implementation_plan"]):
                raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_IMPLEMENTATION_DIFF")
            if set(statuses) & protected_paths:
                raise CurrentAuditError(
                    "CURRENT_AUDIT_PROTOCOL_IMPLEMENTATION_PROTECTED"
                )
            inflight["implementation_commit"] = commit
            inflight["stage"] = "I"
        elif inflight["stage"] == "I":
            registration = registration_map[inflight["key"]]
            contract = contracts[inflight["key"]]
            expected_paths = [
                registration["qualification_path"],
                *[
                    item["path"]
                    for item in contract["qualification_evidence_requirements"]
                ],
                *[item["path"] for item in contract["review_requirements"]],
            ]
            expected_statuses = {path: "A" for path in expected_paths}
            if not _strict_equal(statuses, dict(sorted(expected_statuses.items()))):
                raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_QUALIFICATION_DIFF")
            qualification, outcome = _validate_successor_qualification_v2(
                repo,
                commit,
                registration=registration,
                contract=contract,
                freeze_commit=inflight["freeze_commit"],
                implementation_commit=inflight["implementation_commit"],
            )
            protected_paths.update(expected_paths)
            inflight["qualification_commit"] = commit
            inflight["qualification"] = qualification
            inflight["outcome"] = outcome
            inflight["stage"] = "C"
        elif inflight["stage"] == "C":
            registration = registration_map[inflight["key"]]
            contract = contracts[inflight["key"]]
            expected_paths = [
                registration["activation_path"],
                registration["verifier_receipt_path"],
                *[
                    item["path"]
                    for item in contract["activation_evidence_requirements"]
                ],
            ]
            expected_statuses = {
                **{path: "A" for path in expected_paths},
                requirements_path: "M",
                ACTIVE_CLAIMS_PATH: "M",
            }
            if not _strict_equal(statuses, dict(sorted(expected_statuses.items()))):
                raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_ACTIVATION_DIFF")
            verifier_output, elapsed = _run_registered_verifier_v2(
                repo,
                commit,
                registration=registration,
                freeze_commit=inflight["freeze_commit"],
                implementation_commit=inflight["implementation_commit"],
                qualification_commit=inflight["qualification_commit"],
                activation_commit=commit,
                qualification=inflight["qualification"],
            )
            verifier_seconds += elapsed
            if verifier_seconds > MAX_VERIFIER_AGGREGATE_SECONDS:
                raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_VERIFIER_TIME_BOUND")
            expected_ledger = copy.deepcopy(current_ledger)
            expected_ledger["tasks"][verified_prefix] = _successor_terminal_task(
                bootstrap["tasks"][verified_prefix],
                task_id=inflight["task_id"],
                freeze_commit=inflight["freeze_commit"],
                implementation_commit=inflight["implementation_commit"],
                qualification_commit=inflight["qualification_commit"],
                registration=registration,
                contract=contract,
                qualification=inflight["qualification"],
                outcome=inflight["outcome"],
            )
            expected_ledger["overall_status"] = inflight["outcome"]["overall_status"]
            expected_claims = _successor_active_claims(
                current_claims,
                repo=repo,
                implementation_commit=inflight["implementation_commit"],
                task_id=inflight["task_id"],
                epoch=inflight["epoch"],
                outcome=inflight["outcome"],
                qualification=inflight["qualification"],
            )
            _validate_successor_activation_v2(
                repo,
                commit,
                registration=registration,
                contract=contract,
                freeze_commit=inflight["freeze_commit"],
                implementation_commit=inflight["implementation_commit"],
                qualification_commit=inflight["qualification_commit"],
                qualification=inflight["qualification"],
                outcome=inflight["outcome"],
                expected_ledger=expected_ledger,
                expected_claims=expected_claims,
                verifier_output=verifier_output,
            )
            protected_paths.update(expected_paths)
            activated_plans[verified_prefix] = contract["implementation_plan"]
            verified_prefix += 1
            current_ledger = expected_ledger
            current_claims = expected_claims
            snapshots[verified_prefix] = (
                commit,
                copy.deepcopy(current_ledger),
                copy.deepcopy(current_claims),
            )
            active_verifiers[verified_prefix - 1] = {
                "registration": registration,
                "freeze_commit": inflight["freeze_commit"],
                "implementation_commit": inflight["implementation_commit"],
                "qualification_commit": inflight["qualification_commit"],
                "activation_commit": commit,
                "qualification": inflight["qualification"],
                "last_run_commit": commit,
                "verification_triggers": copy.deepcopy(
                    contract["verification_triggers"]
                ),
            }
            inflight = None
        else:
            raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_STAGE_INVALID")
        if not registry_changed:
            current_registry = _load_json_bytes(
                _git_file(repo, commit, SUCCESSOR_REGISTRY_PATH),
                "protocol.registry.stable",
            )
            expected_registry = copy.deepcopy(registry_top)
            expected_registry["registrations"] = registrations
            if not _strict_equal(current_registry, expected_registry):
                raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_REGISTRY_DRIFT")
        if not revocation_changed:
            current_revocations = _load_json_bytes(
                _git_file(repo, commit, REVOCATION_PATH),
                "protocol.revocations.stable",
            )
            expected_revocations = copy.deepcopy(revocation_top)
            expected_revocations["records"] = revocations
            if not _strict_equal(current_revocations, expected_revocations):
                raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_REVOCATION_DRIFT")
        rerun_active_verifiers(commit, set(statuses))
        previous = commit
    head = chain[-1]
    rerun_active_verifiers(head, set(), force=True)
    head_ledger = _load_json_bytes(
        _git_file(repo, head, requirements_path), "protocol.head.requirements"
    )
    head_claims = _load_json_bytes(
        _git_file(repo, head, ACTIVE_CLAIMS_PATH), "protocol.head.claims"
    )
    if not _strict_equal(head_ledger, current_ledger) or not _strict_equal(
        head_claims, current_claims
    ):
        raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_HEAD_STATE")
    public_records = head_claims.get("public_surface_records")
    if not isinstance(public_records, list):
        raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_PUBLIC_SURFACE_STATE")
    pending_plan: dict[str, str] = {}
    pending_rollback = head
    if inflight is not None and inflight["stage"] in {"I", "C"}:
        pending_plan = contracts[inflight["key"]]["implementation_plan"]
        pending_rollback = snapshots[verified_prefix][0]
    for record in public_records:
        record_path = record.get("path") if isinstance(record, dict) else None
        record_commit = (
            pending_rollback
            if isinstance(record_path, str) and record_path in pending_plan
            else head
        )
        if (
            not isinstance(record, dict)
            or not isinstance(record_path, str)
            or not _strict_equal(
                record,
                _commit_regular_file_record(repo, record_commit, record_path),
            )
        ):
            raise CurrentAuditError("CURRENT_AUDIT_PROTOCOL_PUBLIC_SURFACE_STATE")


def _verify_qualification_lifecycle(
    manifest: dict[str, Any], repo: Path, requirement_state: str
) -> None:
    head, framework_commit, chain = _verify_framework_history(repo)
    _verify_repository_hygiene(repo, head)
    _require_commit_paths_unchanged(
        repo,
        IMPLEMENTATION_COMMIT,
        head,
        set(BASE_IMMUTABLE_PATHS),
        "BASE_INPUT",
    )
    for path in BASE_IMMUTABLE_PATHS:
        worktree_payload = _read_repo_relative_bounded(
            repo, path, MAX_GIT_BYTES, f"base.worktree.{path}"
        )
        if worktree_payload != _git_file(repo, head, path):
            raise CurrentAuditError(f"CURRENT_AUDIT_BASE_WORKTREE_HEAD_DRIFT:{path}")
    requirements_path = EXPECTED_REQUIREMENTS_LEDGER["path"]
    worktree_requirements = _read_repo_relative_bounded(
        repo, requirements_path, MAX_REQUIREMENTS_BYTES, "requirements.head"
    )
    if worktree_requirements != _git_file(repo, head, requirements_path):
        raise CurrentAuditError("CURRENT_AUDIT_REQUIREMENTS_WORKTREE_HEAD_DRIFT")
    qualification_present = _git_path_exists(repo, head, QUALIFICATION_PATH)
    activation_present = _git_path_exists(repo, head, ACTIVATION_PATH)
    stage = _select_qualification_stage(
        requirement_state=requirement_state,
        chain_length=len(chain),
        qualification_present=qualification_present,
        activation_present=activation_present,
    )
    if stage == "FRAMEWORK_PENDING_QUALIFICATION":
        forbidden = {
            *QUALIFIED_OPEN_DATA_PATHS,
            *(ACTIVATION_DATA_PATHS - {EXPECTED_REQUIREMENTS_LEDGER["path"]}),
        }
        if head != framework_commit or any(
            _git_path_exists(repo, head, path) for path in forbidden
        ):
            raise CurrentAuditError("CURRENT_AUDIT_FRAMEWORK_PREMATURE_ARTIFACT")
        return

    qualification_commit = chain[1]
    _verify_data_only_commit(
        repo,
        commit=qualification_commit,
        parent=framework_commit,
        expected_statuses={path: "A" for path in QUALIFIED_OPEN_DATA_PATHS},
        label="QUALIFICATION_COMMIT",
    )
    if _git_file(repo, qualification_commit, requirements_path) != _git_file(
        repo, IMPLEMENTATION_COMMIT, requirements_path
    ):
        raise CurrentAuditError("CURRENT_AUDIT_QUALIFICATION_LEDGER_MUTATED")
    if _git_path_exists(
        repo, qualification_commit, ACTIVATION_PATH
    ) or _git_path_exists(repo, qualification_commit, REVOCATION_PATH):
        raise CurrentAuditError("CURRENT_AUDIT_QUALIFICATION_PREMATURE_ACTIVATION")
    _verify_ch_t000_qualification_v2(repo, framework_commit, qualification_commit)
    if stage == "QUALIFIED_OPEN":
        if head != qualification_commit:
            raise CurrentAuditError("CURRENT_AUDIT_QUALIFICATION_HEAD_INVALID")
        return

    activation_commit = chain[2]
    activation_statuses = {path: "A" for path in ACTIVATION_DATA_PATHS}
    activation_statuses[requirements_path] = "M"
    _verify_data_only_commit(
        repo,
        commit=activation_commit,
        parent=qualification_commit,
        expected_statuses=activation_statuses,
        label="ACTIVATION_COMMIT",
    )
    _verify_ch_t000_activation_v2(
        repo, framework_commit, qualification_commit, activation_commit
    )
    _require_commit_paths_unchanged(
        repo,
        qualification_commit,
        head,
        QUALIFIED_OPEN_DATA_PATHS,
        "QUALIFICATION",
    )
    _require_commit_paths_unchanged(
        repo,
        activation_commit,
        head,
        {ACTIVATION_PATH, *ACTIVATION_EVIDENCE_PATHS},
        "ACTIVATION",
    )
    worktree_claims = _read_repo_relative_bounded(
        repo, ACTIVE_CLAIMS_PATH, MAX_REQUIREMENTS_BYTES, "active_claims.head"
    )
    if worktree_claims != _git_file(repo, head, ACTIVE_CLAIMS_PATH):
        raise CurrentAuditError("CURRENT_AUDIT_ACTIVE_CLAIMS_WORKTREE_HEAD_DRIFT")
    if stage == "TERMINAL_ACTIVATION":
        if head != activation_commit:
            raise CurrentAuditError("CURRENT_AUDIT_ACTIVATION_HEAD_INVALID")
        return
    if stage not in {"POST_ACTIVATION", "REVOKED_OPEN"}:
        raise CurrentAuditError("CURRENT_AUDIT_QUALIFICATION_STAGE_UNREACHABLE")
    _verify_forward_protocol_history(
        repo,
        chain,
        framework_commit=framework_commit,
        qualification_commit=qualification_commit,
        activation_commit=activation_commit,
    )


def verify(manifest_path: Path, repo: Path) -> None:
    """Verify ``manifest_path`` against immutable objects available in ``repo``."""

    manifest = _load_repo_json(repo, manifest_path, MAX_JSON_BYTES, "manifest")
    if set(manifest) != EXPECTED_TOP_LEVEL:
        raise CurrentAuditError("CURRENT_AUDIT_TOP_LEVEL_FIELDS_INVALID")
    if (
        manifest.get("schema_version") != "2.0.0"
        or manifest.get("release_target") != "0.9.0"
    ):
        raise CurrentAuditError("CURRENT_AUDIT_VERSION_INVALID")
    if manifest.get("captured_at_utc") != CAPTURED_AT_UTC:
        raise CurrentAuditError("CURRENT_AUDIT_CAPTURE_TIME_INVALID")
    if manifest.get("author") != {
        "name": "Sepehr Mahmoudian",
        "email": "sepmhn@gmail.com",
    }:
        raise CurrentAuditError("CURRENT_AUDIT_AUTHOR_INVALID")
    if manifest.get("persistent_identifier") is not None:
        raise CurrentAuditError("CURRENT_AUDIT_PERSISTENT_IDENTIFIER_MUST_BE_ABSENT")
    _verify_source(manifest, repo)
    _verify_handoff(manifest)
    _verify_master_handoff(manifest, repo)
    _verify_input_scope(manifest, repo)
    _verify_cut_update(manifest, repo)
    _verify_locked_inputs(manifest, repo)
    requirement_state = _verify_requirements_ledger(manifest, repo)
    _verify_baseline(manifest, repo)
    _verify_publication_state(manifest, repo)
    _verify_github_checks(manifest, repo)
    ncp = manifest.get("ncp")
    if not _strict_equal(
        ncp,
        {
            "protocol": "0.8",
            "package_version": "0.8.0",
            "commit": "2f5bd586d4bb20c90362bb6f5698b7f64057ba4e",
            "protocol_1_0_qualified": False,
        },
    ):
        raise CurrentAuditError("CURRENT_AUDIT_NCP_RECORD_INVALID")
    if not _strict_equal(
        manifest.get("toolchains"),
        {
            "rustc": "1.96.0 (ac68faa20 2026-05-25)",
            "cargo": "1.96.0 (30a34c682 2026-05-25)",
            "python": "3.14.6",
            "cargo_deny": "0.19.9",
            "host": "aarch64-apple-darwin",
        },
    ):
        raise CurrentAuditError("CURRENT_AUDIT_TOOLCHAINS_INVALID")
    _verify_qualification_lifecycle(manifest, repo, requirement_state)


def main() -> int:
    repo = Path(__file__).resolve().parents[2]
    manifest = repo / "release/0.9.0/current-head/audit-inputs.json"
    try:
        if not sys.flags.isolated or not sys.flags.safe_path:
            raise CurrentAuditError("CURRENT_AUDIT_PYTHON_ISOLATION_REQUIRED")
        _verified_python_executable()
        verify(manifest, repo)
    except CurrentAuditError as error:
        print(f"verify-current-audit: FAIL: {error}", file=sys.stderr)
        return 1
    print("verify-current-audit: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
