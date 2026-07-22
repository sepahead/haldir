#!/usr/bin/env python3
"""Adversarial tests for current-file-review-packets.py."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from typing import Any
from unittest import mock


SCRIPT = Path(__file__).with_name("current-file-review-packets.py")
SPEC = importlib.util.spec_from_file_location("current_file_review_packets", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
packets = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = packets
SPEC.loader.exec_module(packets)

GIT_ENV = {
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
REGISTRY_PATH = "release/0.9.0/current-head/tasks/ch-t002/e0002/freeze.json"


def run_git(repo: Path, *arguments: str) -> str:
    completed = subprocess.run(
        [
            packets.GIT_EXECUTABLE,
            *packets.GIT_GLOBAL_OPTIONS,
            "-C",
            str(repo),
            *arguments,
        ],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=GIT_ENV,
    )
    return completed.stdout.strip()


def write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def commit_all(repo: Path, message: str) -> str:
    run_git(repo, "add", "--all")
    run_git(repo, "commit", "-m", message)
    return run_git(repo, "rev-parse", "HEAD")


def git_blob_record(repo: Path, commit: str, path: str) -> tuple[str, str, bytes]:
    return packets._blob_at(repo, commit, path)


def public_key(number: int) -> tuple[str, str]:
    algorithm = b"ssh-ed25519"
    key_bytes = bytes([number]) * 32
    payload = (
        len(algorithm).to_bytes(4, "big")
        + algorithm
        + len(key_bytes).to_bytes(4, "big")
        + key_bytes
    )
    encoded = base64.b64encode(payload).decode("ascii")
    key = f"ssh-ed25519 {encoded}"
    fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(payload).digest()).decode(
        "ascii"
    ).rstrip("=")
    return key, fingerprint


def reviewer_registry() -> tuple[dict[str, Any], list[str]]:
    entries = []
    fingerprints = []
    definitions = (
        ("CH-T002-R01", "INDEPENDENT_REVIEW", "lane-01", "INDEPENDENT_AUTOMATED"),
        (
            "CH-T002-R02",
            "INDEPENDENT_REVIEW_LANE_02",
            "lane-02",
            "INDEPENDENT_AUTOMATED",
        ),
        (
            "CH-T002-R03",
            "INDEPENDENT_REVIEW_LANE_03",
            "lane-03",
            "INDEPENDENT_AUTOMATED",
        ),
        (
            "CH-T002-R04",
            "LEAD_IMPLEMENTATION_REVIEW",
            "lead-support",
            "AUTOMATED_LEAD_SUPPORT",
        ),
    )
    for number, (requirement, kind, stem, classification) in enumerate(
        definitions, start=1
    ):
        key, fingerprint = public_key(number)
        fingerprints.append(fingerprint)
        entries.append(
            {
                "key_fingerprint": fingerprint,
                "kind": kind,
                "path": f"release/reviews/{stem}.json",
                "public_key": key,
                "requirement_id": requirement,
                "reviewer": {
                    "classification": classification,
                    "name": f"Fixture {stem}",
                    "organization": "Fixture Review",
                    "principal": f"{stem}@local.invalid",
                },
                "trust_basis": "SOURCE_SIGNER_ASSERTED_KEY_FROZEN_IN_SIGNED_F",
            }
        )
    controls = []
    for number, requirement in enumerate(
        packets.NORMATIVE_REQUIREMENT_CATALOG, start=1
    ):
        accepted_test = f"test_n{number:02d}_accepted"
        rejected_test = f"test_n{number:02d}_rejected"
        statement = f"Fixture normative control {number:02d}."
        if requirement == packets.CLASSIFICATION_CONTROL_ID:
            accepted_test = packets.CLASSIFICATION_CONTROL_ACCEPTED_TEST_ID
            rejected_test = packets.CLASSIFICATION_CONTROL_REJECTED_TEST_ID
            statement = packets.CLASSIFICATION_CONTROL_STATEMENT
        controls.append(
            {
                "accepted_test_id": accepted_test,
                "id": requirement,
                "rejected_test_id": rejected_test,
                "statement": statement,
            }
        )
    return (
        {
            "schema_version": "1.0.0",
            "task_id": packets.TASK_ID,
            "epoch": packets.EPOCH,
            "release_target": packets.RELEASE_TARGET,
            "author": dict(packets.EXPECTED_AUTHOR),
            "persistent_identifier": None,
            "effective_on": "2026-07-22",
            "task_identity": {},
            "handoff_task_contract": {},
            "prior_state": {},
            "implementation_plan": [],
            "empty_implementation_reason": None,
            "affected_surface_inventory": [],
            "normative_controls": controls,
            "lead_approval": {},
            "mandatory_counterfactuals": [],
            "combined_attack_matrix": [],
            "handoff_command_mapping": [],
            "threat_model": {},
            "misuse_resistant_interfaces": [],
            "qualification_evidence_requirements": [
                {"id": evidence_id} for evidence_id in packets.EVIDENCE_CATALOG
            ],
            "review_requirements": [],
            "reviewer_registry": entries,
            "activation_evidence_requirements": [],
            "lens_questions": [],
            "resource_budgets": {},
            "verification_triggers": [],
            "claim_outcomes": {},
            "qualification_path": "release/qualification.json",
            "activation_path": "release/activation.json",
            "verifier_receipt_path": "release/verifier-receipt.json",
        },
        fingerprints,
    )


def content_record(
    repo: Path, commit: str, path: str, *, language: str
) -> dict[str, Any]:
    mode, oid, data = git_blob_record(repo, commit, path)
    kind, lines = packets._classify_content(data)
    return {
        "bytes": len(data),
        "content_kind": kind,
        "criticality": [],
        "git_mode": mode,
        "git_object_id": oid,
        "language": language,
        "lines": lines,
        "path": path,
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def fixture_classification_record(
    path: str,
    *,
    criticality: tuple[str, ...] = (),
    generated: str = "NO",
    generator: str = "",
    license_status: str = "APPROVED",
    source_basis: str = "INDEPENDENT_AUDIT_CURRENT_A_ENTRY",
) -> dict[str, Any]:
    public = "YES" if "PUBLIC_SURFACE" in criticality else "NO"
    security = "YES" if "SECURITY_CRITICAL" in criticality else "NO"
    science = "YES" if "SCIENCE_CRITICAL" in criticality else "NO"
    authority = "YES" if "AUTHORITY_CRITICAL" in criticality else "NO"
    return {
        "authority_critical": authority,
        "generated": generated,
        "generator": generator,
        "license_expression": (
            "Apache-2.0 OR MIT" if license_status == "APPROVED" else "NOT_APPLICABLE"
        ),
        "license_review_status": license_status,
        "path": path,
        "provenance_review_status": "CONFIRMED",
        "public_surface": public,
        "rule_ids": [
            f"PUB_{public}_FIXTURE_DECISION",
            f"SEC_{security}_FIXTURE_DECISION",
            f"SCI_{science}_FIXTURE_DECISION",
            f"AUTH_{authority}_FIXTURE_DECISION",
            f"GEN_{generated}_FIXTURE_DECISION",
            (
                "LIC_REPOSITORY_FIXTURE_DECISION"
                if license_status == "APPROVED"
                else "LIC_NA_FIXTURE_DECISION"
            ),
        ],
        "science_critical": science,
        "security_critical": security,
        "source_basis": source_basis,
    }


class RepositoryFixture:
    def __init__(self, root: Path):
        self.repo = root / "repo"
        self.repo.mkdir()
        run_git(self.repo, "init", "--initial-branch=main")
        run_git(self.repo, "config", "user.name", "Packet Fixture")
        run_git(self.repo, "config", "user.email", "packet@local.invalid")

        write_bytes(self.repo / "assets/blob.bin", b"\x00" + b"B" * 5000)
        self.source_alpha_data = (
            b"\n".join(f"alpha_{number} = {number}".encode() for number in range(8))
            + b"\n"
        )
        write_bytes(self.repo / "src/alpha.py", self.source_alpha_data)
        write_bytes(self.repo / "src/critical.md", b"one\ntwo\nthree\n")
        write_bytes(self.repo / "src/empty.txt", b"")
        write_bytes(
            self.repo / packets.LEDGER_GENERATOR_PATH,
            b"#!/usr/bin/env python3\n# fixture ledger generator\n",
        )
        self.source = commit_all(self.repo, "fixture source")

        rows = [
            self._ledger_row("assets/blob.bin", language="BINARY_DATA"),
            self._ledger_self_row(),
            self._ledger_row(
                "src/alpha.py",
                language="PYTHON",
                generated="YES",
                generator="src/alpha.py",
            ),
            self._ledger_row("src/critical.md", language="MARKDOWN"),
            self._ledger_row("src/empty.txt", language="TEXT"),
            self._ledger_row(packets.LEDGER_GENERATOR_PATH, language="PYTHON"),
        ]
        rows.sort(key=lambda row: row["path"].encode("utf-8"))
        self.original_rows = rows
        self.original_ledger = packets._render_ledger(rows)
        write_bytes(self.repo / packets.LEDGER_PATH, self.original_ledger)
        self.base = commit_all(self.repo, "fixture base")
        self.base_tree = run_git(self.repo, "rev-parse", f"{self.base}^{{tree}}")
        _, self.base_ledger_oid, base_ledger_bytes = git_blob_record(
            self.repo, self.base, packets.LEDGER_PATH
        )
        assert base_ledger_bytes == self.original_ledger

        self.freeze_alpha_data = (
            b"\n".join(f"changed_{number} = {number}".encode() for number in range(13))
            + b"\n"
        )
        write_bytes(self.repo / "src/alpha.py", self.freeze_alpha_data)
        write_bytes(self.repo / "docs/new.txt", b"new evidence scope\n")
        self.classification_records = sorted(
            [
                fixture_classification_record("assets/blob.bin"),
                fixture_classification_record(
                    packets.LEDGER_PATH,
                    criticality=("AUTHORITY_CRITICAL",),
                    generated="YES",
                    generator=packets.LEDGER_GENERATOR_PATH,
                ),
                fixture_classification_record(
                    "docs/new.txt", criticality=("PUBLIC_SURFACE",)
                ),
                fixture_classification_record(
                    REGISTRY_PATH,
                    criticality=("SECURITY_CRITICAL", "AUTHORITY_CRITICAL"),
                ),
                fixture_classification_record(
                    "src/alpha.py", generated="YES", generator="src/alpha.py"
                ),
                fixture_classification_record(
                    "src/critical.md",
                    criticality=("SECURITY_CRITICAL",),
                    source_basis=packets.CLASSIFICATION_OVERRIDE_SOURCE_BASIS,
                ),
                fixture_classification_record(
                    "src/empty.txt", license_status="NOT_APPLICABLE"
                ),
                fixture_classification_record(
                    packets.LEDGER_GENERATOR_PATH,
                    criticality=("SECURITY_CRITICAL", "AUTHORITY_CRITICAL"),
                ),
            ],
            key=lambda record: record["path"].encode("utf-8"),
        )
        self.classification_by_path = {
            record["path"]: record for record in self.classification_records
        }
        self.classification_digest = packets._domain_digest(
            packets.CLASSIFICATION_SET_DOMAIN, self.classification_records
        )
        self.override_paths = ("src/critical.md",)
        self.override_rows = [
            {
                "after": "YES",
                "before": "NO",
                "field": "security_critical",
                "path": "src/critical.md",
                "rule_id": "SEC_YES_FIXTURE_DECISION",
                "source_basis": packets.CLASSIFICATION_OVERRIDE_SOURCE_BASIS,
            }
        ]
        self.override_digest = packets._domain_digest(
            packets.CLASSIFICATION_OVERRIDE_SET_DOMAIN, self.override_rows
        )
        source_records = [dict(record) for record in self.classification_records]
        next(
            record for record in source_records if record["path"] == "src/critical.md"
        )["security_critical"] = "NO"
        historical_paths = tuple(row["path"] for row in rows)
        self.classification_counts = {
            "f_additions": packets._classification_counts([]),
            "final_current_a": packets._classification_counts(
                self.classification_records
            ),
            "final_f": packets._classification_counts(self.classification_records),
            "final_historical_ledger_subjects": packets._classification_counts(
                self.classification_by_path[path] for path in historical_paths
            ),
            "source_current_a": packets._classification_counts(source_records),
        }
        base_registry, fingerprints = reviewer_registry()
        self.registry = base_registry
        self.registry["affected_surface_inventory"] = [
            record["path"] for record in self.classification_records
        ]
        self.registry_data = packets._canonical_pretty_json(self.registry)
        write_bytes(self.repo / REGISTRY_PATH, self.registry_data)
        self.freeze = commit_all(self.repo, "fixture freeze")
        self.freeze_tree = run_git(self.repo, "rev-parse", f"{self.freeze}^{{tree}}")
        _, registry_oid, _ = git_blob_record(self.repo, self.freeze, REGISTRY_PATH)

        entries = []
        specifications = (
            (packets.LEDGER_PATH, "CSV", "LEDGER_SELF_EXTERNAL_BINDING"),
            ("docs/new.txt", "TEXT", "ADDED_FREEZE_DELTA"),
            (REGISTRY_PATH, "JSON", "ADDED_FREEZE_DELTA"),
            ("src/alpha.py", "PYTHON", "MODIFIED_FREEZE_DELTA"),
        )
        for path, language, status in specifications:
            entry = content_record(self.repo, self.freeze, path, language=language)
            decision = self.classification_by_path[path]
            entry["criticality"] = list(packets._classification_criticality(decision))
            for field in (
                "generated",
                "generator",
                "license_expression",
                "license_review_status",
                "provenance_review_status",
                "rule_ids",
                "source_basis",
            ):
                entry[field] = decision[field]
            entry["status"] = status
            entry["subject_id"] = packets.subject_id(entry)
            entries.append(entry)
        entries.sort(key=lambda entry: entry["path"].encode("utf-8"))

        raw_delta, _ = packets._diff_name_status(self.repo, self.base, self.freeze)
        self.overlay = {
            "author": dict(packets.EXPECTED_AUTHOR),
            "base_partition": {
                "commit": self.base,
                "ledger_blob_id": self.base_ledger_oid,
                "ledger_path": packets.LEDGER_PATH,
                "ledger_rows": len(rows),
                "ledger_self_path": packets.LEDGER_PATH,
                "ledger_sha256": hashlib.sha256(self.original_ledger).hexdigest(),
                "tree": self.base_tree,
            },
            "counts": {
                "added_entries": 0,
                "base_rows": 0,
                "critical_subjects": 0,
                "modified_entries": 0,
                "removed_paths": 0,
                "review_subjects": 0,
                "self_entries": 0,
                "supplemental_subjects": 0,
                "unchanged_subjects": 0,
            },
            "delta": {
                "freeze_commit": self.freeze,
                "freeze_tree": self.freeze_tree,
                "name_status_sha256": hashlib.sha256(raw_delta).hexdigest(),
            },
            "digests": {
                "classification_set_sha256": self.classification_digest,
                "entry_set_sha256": "0" * 64,
                "removed_path_set_sha256": "0" * 64,
                "subject_set_sha256": "0" * 64,
            },
            "entries": entries,
            "epoch": packets.EPOCH,
            "implementation_boundary": {
                "content_identities_in_overlay": False,
                "paths": [dict(item) for item in packets.IMPLEMENTATION_PLAN],
                "review_kind": packets.IMPLEMENTATION_REVIEW_KIND,
            },
            "persistent_identifier": None,
            "release_target": packets.RELEASE_TARGET,
            "removed_paths": [],
            "review_classification_contract": {
                "classification_set_sha256": self.classification_digest,
                "counts": self.classification_counts,
                "override_policy": {
                    "field_override_count": len(self.override_rows),
                    "order": packets.CLASSIFICATION_OVERRIDE_ORDER,
                    "overrides": self.override_rows,
                    "path_count": len(self.override_paths),
                    "paths": list(self.override_paths),
                    "policy_id": packets.CLASSIFICATION_OVERRIDE_POLICY_ID,
                },
                "path_order": packets.PATH_ORDER,
                "records": self.classification_records,
                "schema_id": packets.CLASSIFICATION_CONTRACT_SCHEMA_ID,
                "source_audit": {
                    "schema_id": packets.CLASSIFICATION_AUDIT_SCHEMA_ID,
                    "sha256": packets.CLASSIFICATION_AUDIT_SHA256,
                    "current_a_commit": packets.CLASSIFICATION_AUDIT_COMMIT,
                    "current_a_tree": packets.CLASSIFICATION_AUDIT_TREE,
                },
                "semantics": {
                    "generated": packets.CLASSIFICATION_GENERATED_SEMANTICS,
                    "primary_capture": (
                        packets.CLASSIFICATION_PRIMARY_CAPTURE_SEMANTICS
                    ),
                },
            },
            "review_policy": {
                "algorithm": packets.ASSIGNMENT_ALGORITHM,
                "binary_unit_bytes": packets.BINARY_UNIT_BYTES,
                "coverage": packets.COVERAGE_RULE,
                "critical_secondary_required": True,
                "lanes": [
                    {
                        "kind": packets.LANE_KINDS[lane],
                        "lane": lane,
                        "requirement_id": f"CH-T002-R0{lane}",
                        "reviewer_fingerprint": fingerprints[lane - 1],
                    }
                    for lane in range(1, 4)
                ],
                "lead_requirement_id": "CH-T002-R04",
                "primary_selection": packets.PRIMARY_RULE,
                "removed_coverage": packets.REMOVED_COVERAGE_RULE,
                "registry": {
                    "git_blob_id": registry_oid,
                    "path": REGISTRY_PATH,
                    "sha256": hashlib.sha256(self.registry_data).hexdigest(),
                },
                "secondary_selection": packets.SECONDARY_RULE,
                "sort_order": packets.SORT_RULE,
                "text_units": packets.TEXT_UNIT_RULE,
            },
            "schema_id": packets.SCHEMA_ID,
            "schema_version": packets.SCHEMA_VERSION,
            "scope": {
                "claim_outcome": packets.CLAIM_OUTCOME,
                "classification_audit_sha256": packets.CLASSIFICATION_AUDIT_SHA256,
                "classification_policy": packets.CLASSIFICATION_POLICY,
                "evidence_catalog": list(packets.EVIDENCE_CATALOG),
                "generator_catalog": sorted(
                    [packets.LEDGER_GENERATOR_PATH, "src/alpha.py"],
                    key=lambda item: item.encode("utf-8"),
                ),
                "inclusion": packets.SCOPE_INCLUSION,
                "kind": packets.SCOPE_KIND,
                "path_order": packets.PATH_ORDER,
                "requirement_catalog": [
                    control["id"] for control in self.registry["normative_controls"]
                ],
                "test_catalog": sorted(
                    [
                        control[field]
                        for control in self.registry["normative_controls"]
                        for field in ("accepted_test_id", "rejected_test_id")
                    ],
                    key=lambda item: item.encode("utf-8"),
                ),
            },
            "task_id": packets.TASK_ID,
        }
        self.overlay = packets._parse_canonical_json(
            packets._canonical_json(self.overlay), label="fixture overlay"
        )

        completed_rows = [dict(row) for row in rows]
        for row in completed_rows:
            decision = self.classification_by_path.get(row["path"])
            if decision is not None:
                row["generated"] = decision["generated"]
                row["generator"] = decision["generator"]
            elif row["generated"] == "UNKNOWN":
                row["generated"] = "NO"
                row["generator"] = ""
            for field in (
                "public_surface",
                "security_critical",
                "science_critical",
                "authority_critical",
            ):
                row[field] = "NO" if decision is None else decision[field]
            row["requirements"] = packets.ROW_REQUIREMENT_ID
            row["tests"] = packets.ROW_TEST_ID
            row["provenance_review_status"] = (
                "CONFIRMED"
                if decision is None
                else decision["provenance_review_status"]
            )
            row["license_review_status"] = (
                "APPROVED" if decision is None else decision["license_review_status"]
            )
            row["license_expression"] = (
                "Apache-2.0 OR MIT"
                if decision is None
                else decision["license_expression"]
            )
            row["reviewer"] = "lane-01@local.invalid"
            row["review_status"] = "REVIEWED"
            row["defects"] = "NONE"
            row["disposition"] = "ACCEPTED"
            row["completed_at"] = "2026-07-22T00:00:00Z"

        entry_paths = {entry["path"] for entry in entries}
        subjects = list(
            packets._subject_from_ledger(row)
            for row in completed_rows
            if row["path"] not in entry_paths
        )
        subjects.extend(
            packets._subject_from_record(entry, status=entry["status"])
            for entry in entries
        )
        subjects.sort(key=lambda subject: subject.path.encode("utf-8"))
        reviewers = packets._reviewers_from_registry(self.registry, self.overlay)
        lanes = packets.assign_subjects(subjects, reviewers)
        subject_by_path = {subject.path: subject for subject in subjects}
        primary_by_path = {
            subject.path: (lane, subject) for lane in lanes for subject in lane.primary
        }
        secondary_by_id = {
            subject.subject_id: lane for lane in lanes for subject in lane.secondary
        }
        for row in completed_rows:
            subject = subject_by_path[row["path"]]
            primary_lane, _subject = primary_by_path[row["path"]]
            row["reviewer"] = primary_lane.reviewer.principal
            row["provenance_evidence"] = f"CH-T002-E09#{subject.subject_id}:PROVENANCE"
            row["license_evidence"] = (
                f"CH-T002-E09#{subject.subject_id}:LICENSE"
                if row["license_review_status"] == "APPROVED"
                else ""
            )
            evidence = {
                f"CH-T002-E09#{subject.subject_id}:PRIMARY",
                f"CH-T002-E{9 + primary_lane.number:02d}#{subject.subject_id}:PRIMARY",
            }
            secondary_lane = secondary_by_id.get(subject.subject_id)
            if secondary_lane is not None:
                evidence.update(
                    {
                        f"CH-T002-E09#{subject.subject_id}:SECONDARY",
                        f"CH-T002-E{9 + secondary_lane.number:02d}#{subject.subject_id}:SECONDARY",
                    }
                )
            row["evidence"] = ";".join(
                sorted(evidence, key=lambda item: item.encode("utf-8"))
            )

        self.completed_rows = completed_rows
        self.completed_ledger = packets._render_ledger(completed_rows)
        statuses = {
            status: sum(entry["status"] == status for entry in entries)
            for status in packets.ENTRY_STATUSES
        }
        self.overlay["counts"] = {
            "added_entries": statuses["ADDED_FREEZE_DELTA"],
            "base_rows": len(rows),
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
        self.overlay["digests"] = {
            "classification_set_sha256": self.classification_digest,
            "entry_set_sha256": packets._domain_digest(
                packets.SCHEMA["digest_domains"]["entry_set"], entries
            ),
            "removed_path_set_sha256": packets._domain_digest(
                packets.SCHEMA["digest_domains"]["removed_path_set"],
                [],
            ),
            "subject_set_sha256": packets._subject_set_digest(
                subjects,
                freeze_commit=self.freeze,
                freeze_tree=self.freeze_tree,
            ),
        }
        self.overlay_data = packets._canonical_json(self.overlay)

        write_bytes(self.repo / packets.LEDGER_PATH, self.completed_ledger)
        write_bytes(self.repo / packets.OVERLAY_PATH, self.overlay_data)
        write_bytes(self.repo / packets.PRODUCT_PATH, b"#!/usr/bin/env python3\n")
        write_bytes(self.repo / packets.PRODUCT_TEST_PATH, b"# fixture test\n")
        self.implementation = commit_all(self.repo, "fixture implementation")
        self.implementation_tree = run_git(
            self.repo, "rev-parse", f"{self.implementation}^{{tree}}"
        )

    def _ledger_row(
        self,
        path: str,
        *,
        language: str,
        generated: str = "UNKNOWN",
        generator: str = "",
    ) -> dict[str, str]:
        mode, oid, data = git_blob_record(self.repo, self.source, path)
        kind, lines = packets._classify_content(data)
        row = {field: "" for field in packets.FIELDS}
        row.update(
            {
                "schema_version": "1.0.0",
                "source_commit": self.source,
                "source_tree": run_git(
                    self.repo, "rev-parse", f"{self.source}^{{tree}}"
                ),
                "object_format": "sha1",
                "ignored_policy": "reject",
                "inventory_rows": "6",
                "filesystem_entries": "6",
                "ledger_self_path": packets.LEDGER_PATH,
                "path": path,
                "source_tracked": "true",
                "source_git_mode": mode,
                "source_object_type": "blob",
                "source_git_blob_id": oid,
                "source_sha256": hashlib.sha256(data).hexdigest(),
                "source_bytes": str(len(data)),
                "source_lines": str(lines or 0),
                "source_content_kind": kind,
                "index_tracked": "true",
                "index_git_mode": mode,
                "index_git_blob_id": oid,
                "index_flags": "NONE",
                "index_sha256": hashlib.sha256(data).hexdigest(),
                "index_bytes": str(len(data)),
                "index_lines": str(lines or 0),
                "index_content_kind": kind,
                "source_index_state": "IDENTICAL",
                "current_scope": "TRACKED",
                "current_fs_type": "REGULAR",
                "current_fs_mode": mode,
                "current_git_blob_id": oid,
                "current_sha256": hashlib.sha256(data).hexdigest(),
                "current_bytes": str(len(data)),
                "current_lines": str(lines or 0),
                "current_content_kind": kind,
                "worktree_state": "CLEAN_AGAINST_INDEX",
                "category": "SOURCE",
                "provenance_class": "DECLARED_SOURCE_COMMIT_AND_CURRENT_VIEW",
                "git_blob_id": oid,
                "sha256": hashlib.sha256(data).hexdigest(),
                "bytes": str(len(data)),
                "lines": str(lines or 0),
                "language": language,
                "format": language,
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
        return row

    def _ledger_self_row(self) -> dict[str, str]:
        row = {field: "" for field in packets.FIELDS}
        row.update(
            {
                "schema_version": "1.0.0",
                "source_commit": self.source,
                "source_tree": run_git(
                    self.repo, "rev-parse", f"{self.source}^{{tree}}"
                ),
                "object_format": "sha1",
                "ignored_policy": "reject",
                "inventory_rows": "6",
                "filesystem_entries": "6",
                "ledger_self_path": packets.LEDGER_PATH,
                "path": packets.LEDGER_PATH,
                "source_tracked": "false",
                "source_lines": "0",
                "index_tracked": "true",
                "index_flags": "NONE",
                "index_lines": "0",
                "index_content_kind": "SELF_REFERENTIAL_CONTENT_EXCLUDED",
                "source_index_state": "ADDED",
                "current_scope": "TRACKED",
                "current_fs_type": "REGULAR",
                "current_fs_mode": "100644",
                "current_lines": "0",
                "current_content_kind": "SELF_REFERENTIAL_CONTENT_EXCLUDED",
                "worktree_state": "SELF_REFERENTIAL_CONTENT_EXCLUDED",
                "category": "GENERATED_AUDIT",
                "provenance_class": "SELF_REFERENTIAL_CONTENT_EXCLUDED",
                "lines": "0",
                "language": "CSV",
                "format": "SELF_REFERENTIAL_CSV",
                "generated": "YES",
                "generator": packets.LEDGER_GENERATOR_PATH,
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

    def prepare(self) -> Any:
        return packets._prepare_inputs(
            repo_argument=self.repo,
            implementation_commit_argument=self.implementation,
            ledger_argument=self.repo / packets.LEDGER_PATH,
            overlay_argument=self.repo / packets.OVERLAY_PATH,
            registry_argument=self.repo / REGISTRY_PATH,
        )


class PacketUnitTests(unittest.TestCase):
    def reviewer(self, lane: int) -> Any:
        return packets.Reviewer(
            lane=lane,
            requirement_id=f"CH-T002-R0{lane}",
            kind=packets.LANE_KINDS[lane],
            name=f"Lane {lane}",
            principal=f"lane-{lane}@local.invalid",
            classification="INDEPENDENT_AUTOMATED",
            organization="Fixture",
            key_fingerprint="SHA256:" + chr(64 + lane) * 43,
        )

    def subject(
        self,
        name: str,
        *,
        units: int,
        language: str = "TEXT",
        critical: bool = False,
    ) -> Any:
        size = units
        record = {
            "bytes": size,
            "content_kind": "TEXT_UTF8",
            "git_mode": "100644",
            "git_object_id": hashlib.sha1(name.encode()).hexdigest(),
            "lines": units,
            "path": f"src/{name}.txt",
            "sha256": hashlib.sha256(name.encode()).hexdigest(),
        }
        return packets.Subject(
            path=record["path"],
            git_mode="100644",
            git_object_id=record["git_object_id"],
            sha256=record["sha256"],
            size=size,
            lines=units,
            content_kind="TEXT_UTF8",
            language=language,
            criticality=("SECURITY_CRITICAL",) if critical else (),
            status="UNCHANGED_BASE",
            subject_id=packets.subject_id(record),
            units=max(units, 1),
        )

    def test_units_are_exact_for_empty_text_and_binary_chunks(self) -> None:
        self.assertEqual(packets._units(size=0, lines=0, content_kind="TEXT_UTF8"), 1)
        self.assertEqual(packets._units(size=0, lines=None, content_kind="BINARY"), 1)
        self.assertEqual(
            packets._units(size=4097, lines=None, content_kind="BINARY"), 2
        )

    def test_text_line_boundaries_are_explicit_and_stable(self) -> None:
        cases = (
            (b"", "TEXT_UTF8", 0),
            (b"alpha\rbeta", "TEXT_UTF8", 2),
            (b"alpha\r\nbeta", "TEXT_UTF8", 2),
            ("alpha\u2028beta\u2029".encode(), "TEXT_UTF8", 2),
            (b"alpha\rbeta\n", "TEXT_UTF8", 2),
            (b"alpha\x0bbeta", "BINARY", None),
        )
        for data, expected_kind, expected_lines in cases:
            with self.subTest(data=data):
                self.assertEqual(
                    packets._classify_content(data),
                    (expected_kind, expected_lines),
                )

    def test_release_catalogs_and_ch_t001_base_are_exact_constants(self) -> None:
        self.assertEqual(
            packets.NORMATIVE_REQUIREMENT_CATALOG,
            tuple(f"CH-T002-N{number:02d}" for number in range(1, 21)),
        )
        self.assertEqual(
            packets.EVIDENCE_CATALOG,
            tuple(f"CH-T002-E{number:02d}" for number in range(1, 14)),
        )
        self.assertEqual(
            (
                packets.CH_T001_BASE_COMMIT,
                packets.CH_T001_BASE_TREE,
                packets.CH_T001_BASE_LEDGER_BLOB,
                packets.CH_T001_BASE_LEDGER_SHA256,
                packets.CH_T001_BASE_LEDGER_ROWS,
            ),
            (
                "ab4eb7a99bebae88c5aad3684bccf3a85a4e7dc9",
                "844dbc2b50812e7bdf2a44deae8be831d8ff8349",
                "51c0278e16885231bb98b3c85ae64384e08bd97d",
                "0e0d5a0fb147157cc7d5506d271d64c24794b1261fc3713b2e097ca50b8d9a89",
                356,
            ),
        )

    def test_git_blob_file_cap_accepts_boundary_and_rejects_cap_plus_one(
        self,
    ) -> None:
        data = b"x" * packets.MAX_FILE_BYTES
        oid = hashlib.sha1(
            f"blob {len(data)}\0".encode("ascii") + data,
            usedforsecurity=False,
        ).hexdigest()
        tree_record = f"100644 blob {oid}\tboundary.bin\0".encode("ascii")
        with mock.patch.object(packets, "_run_git", side_effect=(tree_record, data)):
            self.assertEqual(
                packets._blob_at(Path("/fixture"), "a" * 40, "boundary.bin")[2],
                data,
            )
        with (
            mock.patch.object(
                packets, "_run_git", side_effect=(tree_record, data + b"x")
            ),
            self.assertRaisesRegex(packets.PacketError, "file byte bound"),
        ):
            packets._blob_at(Path("/fixture"), "a" * 40, "boundary.bin")

    def test_empty_text_subject_has_golden_identity_and_truthful_coverage(self) -> None:
        record = {
            "bytes": 0,
            "content_kind": "TEXT_UTF8",
            "git_mode": "100644",
            "git_object_id": "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391",
            "lines": 0,
            "path": "src/empty.txt",
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        }
        self.assertEqual(
            packets.subject_id(record),
            "cd491c5efb7c1b048a580f1d642e0916186859b8dd1cc468ef1c8e82389d7884",
        )
        subject = packets.Subject(
            path=record["path"],
            git_mode=record["git_mode"],
            git_object_id=record["git_object_id"],
            sha256=record["sha256"],
            size=0,
            lines=0,
            content_kind="TEXT_UTF8",
            language="TEXT",
            criticality=(),
            status="UNCHANGED_BASE",
            subject_id=packets.subject_id(record),
            units=1,
        )
        packet = subject.packet_record(freeze_commit="1" * 40, freeze_tree="2" * 40)
        self.assertEqual(
            packet["coverage"]["byte_interval"],
            {"end_exclusive": 0, "start_inclusive": 0},
        )
        self.assertIsNone(packet["coverage"]["line_interval"])
        self.assertEqual(packet["units"], 1)

    def test_implementation_plan_is_independently_golden_and_byte_sorted(self) -> None:
        expected = (
            {"path": "audit/generated/CH-T002_FILE_REVIEW_OVERLAY.json", "status": "A"},
            {"path": "audit/generated/FILE_REVIEW_LEDGER.csv", "status": "M"},
            {"path": "tools/release/current-file-review-packets.py", "status": "A"},
            {
                "path": "tools/release/test_current_file_review_packets.py",
                "status": "A",
            },
        )
        self.assertEqual(packets.IMPLEMENTATION_PLAN, expected)
        self.assertEqual(
            [item["path"] for item in expected],
            sorted(
                (item["path"] for item in expected),
                key=lambda item: item.encode("utf-8"),
            ),
        )

    def test_subject_id_is_path_and_identity_specific(self) -> None:
        first = self.subject("a", units=1)
        second = self.subject("b", units=1)
        self.assertNotEqual(first.subject_id, second.subject_id)
        self.assertRegex(first.subject_id, r"^[0-9a-f]{64}$")

    def test_largest_first_assignment_is_deterministic_and_balanced(self) -> None:
        reviewers = tuple(self.reviewer(lane) for lane in range(1, 4))
        subjects = [self.subject(str(number), units=number) for number in range(1, 10)]
        first = packets.assign_subjects(subjects, reviewers)
        second = packets.assign_subjects(list(reversed(subjects)), reviewers)
        self.assertEqual(
            [[item.subject_id for item in lane.primary] for lane in first],
            [[item.subject_id for item in lane.primary] for lane in second],
        )
        self.assertEqual(
            len({item.subject_id for lane in first for item in lane.primary}), 9
        )
        self.assertLessEqual(
            max(lane.total_units for lane in first)
            - min(lane.total_units for lane in first),
            max(subject.units for subject in subjects),
        )

    def test_assignment_matches_independent_golden_corpus(self) -> None:
        reviewers = tuple(self.reviewer(lane) for lane in range(1, 4))
        subjects = [
            replace(
                self.subject(name, units=units, critical=name == "b"),
                subject_id=name * 64,
                language=language,
            )
            for name, units, language in (
                ("a", 5, "PYTHON"),
                ("b", 4, "TEXT"),
                ("c", 3, "RUST"),
                ("d", 2, "TEXT"),
                ("e", 1, "TEXT"),
            )
        ]
        lanes = packets.assign_subjects(list(reversed(subjects)), reviewers)
        self.assertEqual(
            [[subject.subject_id[0] for subject in lane.primary] for lane in lanes],
            [["a", "e"], ["b", "c"], ["d"]],
        )
        self.assertEqual(
            [[subject.subject_id[0] for subject in lane.secondary] for lane in lanes],
            [[], [], ["b"]],
        )

    def test_critical_secondary_is_unique_and_different_lane(self) -> None:
        reviewers = tuple(self.reviewer(lane) for lane in range(1, 4))
        critical = self.subject("critical", units=8, critical=True)
        lanes = packets.assign_subjects(
            [critical, self.subject("other", units=2)], reviewers
        )
        primary = [lane.number for lane in lanes if critical in lane.primary]
        secondary = [lane.number for lane in lanes if critical in lane.secondary]
        self.assertEqual(len(primary), 1)
        self.assertEqual(len(secondary), 1)
        self.assertNotEqual(primary, secondary)

    def test_packet_record_has_reconstructable_full_intervals_without_content(
        self,
    ) -> None:
        subject = self.subject("record", units=3)
        record = subject.packet_record(freeze_commit="a" * 40, freeze_tree="b" * 40)
        self.assertNotIn("content", record)
        self.assertEqual(record["coverage"]["kind"], packets.COVERAGE_RULE)
        self.assertEqual(
            record["coverage"]["byte_interval"],
            {"end_exclusive": 3, "start_inclusive": 0},
        )
        self.assertEqual(
            record["coverage"]["line_interval"],
            {"end_inclusive": 3, "start_inclusive": 1},
        )
        self.assertEqual(record["content_commit"], "a" * 40)
        self.assertEqual(record["content_tree"], "b" * 40)
        self.assertEqual(record["snapshot_state"], "PRESENT_AT_CH_T002_F")

    def test_binary_packet_record_has_full_byte_chunks_and_no_line_interval(
        self,
    ) -> None:
        record = {
            "bytes": 4097,
            "content_kind": "BINARY",
            "git_mode": "100644",
            "git_object_id": "a" * 40,
            "lines": None,
            "path": "assets/data.bin",
            "sha256": "b" * 64,
        }
        subject = packets.Subject(
            path=record["path"],
            git_mode=record["git_mode"],
            git_object_id=record["git_object_id"],
            sha256=record["sha256"],
            size=record["bytes"],
            lines=None,
            content_kind="BINARY",
            language="BINARY_DATA",
            criticality=(),
            status="UNCHANGED_BASE",
            subject_id=packets.subject_id(record),
            units=2,
        )
        packet = subject.packet_record(freeze_commit="c" * 40, freeze_tree="d" * 40)
        self.assertIsNone(packet["coverage"]["line_interval"])
        self.assertEqual(packet["coverage"]["chunk_bytes"], 4096)
        self.assertEqual(packet["coverage"]["chunk_count"], 2)

    def test_canonical_json_rejects_duplicate_keys_nonfinite_and_spacing(self) -> None:
        for data in (b'{"a":1,"a":2}\n', b'{"a":NaN}\n', b'{"a": 1}\n'):
            with self.subTest(data=data), self.assertRaises(packets.PacketError):
                packets._parse_canonical_json(data, label="fixture")

    def test_central_freeze_requires_pretty_source_order_json(self) -> None:
        value = {"task_id": "CH-T002", "epoch": 1, "nested": {"z": 1, "a": 2}}
        pretty = packets._canonical_pretty_json(value)
        self.assertEqual(
            packets._parse_pretty_canonical_json(pretty, label="freeze"), value
        )
        with self.assertRaisesRegex(packets.PacketError, "pretty canonical"):
            packets._parse_pretty_canonical_json(
                packets._canonical_json(value), label="freeze"
            )

    def test_central_freeze_byte_cap_accepts_boundary_and_rejects_cap_plus_one(
        self,
    ) -> None:
        skeleton = packets._canonical_pretty_json({"padding": ""})
        padding = "x" * (packets.MAX_CENTRAL_FREEZE_BYTES - len(skeleton))
        boundary = packets._canonical_pretty_json({"padding": padding})
        self.assertEqual(len(boundary), packets.MAX_CENTRAL_FREEZE_BYTES)
        self.assertEqual(
            packets._parse_central_freeze_json(boundary), {"padding": padding}
        )
        over = packets._canonical_pretty_json({"padding": padding + "x"})
        self.assertEqual(len(over), packets.MAX_CENTRAL_FREEZE_BYTES + 1)
        with self.assertRaisesRegex(packets.PacketError, "256-KiB"):
            packets._parse_central_freeze_json(over)

    def test_type_aware_equality_rejects_boolean_integer_aliases(self) -> None:
        with self.assertRaises(packets.PacketError):
            packets._expect_exact(True, 1, label="type fixture")

    def test_classification_rule_accepts_pinned_lowercase_git_identity(self) -> None:
        record = fixture_classification_record("Cargo.toml")
        record["rule_ids"][5] = (
            "LIC_PINNED_NCP_2f5bd586d4bb20c90362bb6f5698b7f64057ba4e_"
            "CARGO_AND_LICENSE_FILES"
        )
        self.assertEqual(packets._validate_classification_record(record), record)
        record["rule_ids"][5] = "LIC_INVALID-HYPHEN"
        with self.assertRaisesRegex(packets.PacketError, "invalid grammar"):
            packets._validate_classification_record(record)

    def test_classification_rule_prefix_flag_and_order_are_exact(self) -> None:
        wrong_prefix = fixture_classification_record("fixture.txt")
        wrong_prefix["rule_ids"][0] = "SEC_NO_WRONG_FIELD_FIXTURE_DECISION"
        with self.assertRaisesRegex(packets.PacketError, "field prefix"):
            packets._validate_classification_record(wrong_prefix)

        wrong_flag = fixture_classification_record(
            "fixture.txt", criticality=("PUBLIC_SURFACE",)
        )
        wrong_flag["rule_ids"][0] = "PUB_NO_FIXTURE_DECISION"
        with self.assertRaisesRegex(packets.PacketError, "YES/NO role"):
            packets._validate_classification_record(wrong_flag)

        wrong_order = fixture_classification_record("fixture.txt")
        wrong_order["rule_ids"][1], wrong_order["rule_ids"][2] = (
            wrong_order["rule_ids"][2],
            wrong_order["rule_ids"][1],
        )
        with self.assertRaisesRegex(packets.PacketError, "field prefix"):
            packets._validate_classification_record(wrong_order)

    def test_classification_license_rule_role_is_exact(self) -> None:
        approved = fixture_classification_record("fixture.txt")
        approved["rule_ids"][5] = "LIC_NA_FIXTURE_DECISION"
        with self.assertRaisesRegex(packets.PacketError, "approved status"):
            packets._validate_classification_record(approved)

        not_applicable = fixture_classification_record(
            "fixture.txt", license_status="NOT_APPLICABLE"
        )
        not_applicable["rule_ids"][5] = "LIC_REPOSITORY_FIXTURE_DECISION"
        with self.assertRaisesRegex(packets.PacketError, "not-applicable status"):
            packets._validate_classification_record(not_applicable)

    def test_final_classification_commitments_are_exact(self) -> None:
        self.assertIn("Linux and macOS", packets.__doc__ or "")
        self.assertEqual(packets.EPOCH, 2)
        self.assertEqual(
            packets.FREEZE_REGISTRY_PATH,
            "release/0.9.0/current-head/tasks/ch-t002/e0002/freeze.json",
        )
        self.assertEqual(
            packets.CLASSIFICATION_F_EXTENSION_PATHS,
            (
                "release/0.9.0/current-head/tasks/ch-t002/e0001/freeze.json",
                "release/0.9.0/current-head/tasks/ch-t002/e0002/freeze.json",
                "release/0.9.0/current-head/tasks/revocations/R0002/classification-public-surface-conflict.json",
                "tools/release/tasks/ch-t002/e0001/test_verify.py",
                "tools/release/tasks/ch-t002/e0001/verify.py",
                "tools/release/tasks/ch-t002/e0002/test_verify.py",
                "tools/release/tasks/ch-t002/e0002/verify.py",
            ),
        )
        self.assertEqual(len(packets.CLASSIFICATION_OVERRIDE_PATHS), 75)
        self.assertIn(".gitignore", packets.CLASSIFICATION_OVERRIDE_PATHS)
        self.assertEqual(
            packets.CLASSIFICATION_OVERRIDE_PATHS,
            tuple(
                sorted(
                    packets.CLASSIFICATION_OVERRIDE_PATHS,
                    key=lambda path: path.encode("utf-8"),
                )
            ),
        )
        self.assertEqual(len(set(packets.CLASSIFICATION_OVERRIDE_PATHS)), 75)
        self.assertEqual(packets.EXPECTED_CLASSIFICATION_OVERRIDE_FIELDS, 93)
        self.assertEqual(
            packets.EXPECTED_CLASSIFICATION_OVERRIDE_SET_SHA256,
            "a9887d37596ef35afc758828e2b1726bd917bd3374f83395db7765b6996761e6",
        )
        self.assertEqual(
            packets.EXPECTED_CLASSIFICATION_SET_SHA256,
            "543e0946ed31da0fca3b7bdb184847d9fe68ab03154e3bf17b57869d0a77a051",
        )
        expected_vectors = {
            "f_additions": (0, 7, 7, 0, 7, 0, 7, 7, 7, 0, 7, 0, 0, 7),
            "final_current_a": (
                116,
                272,
                325,
                63,
                345,
                43,
                388,
                388,
                201,
                187,
                311,
                77,
                82,
                306,
            ),
            "final_f": (
                116,
                279,
                332,
                63,
                352,
                43,
                395,
                395,
                208,
                187,
                318,
                77,
                82,
                313,
            ),
            "final_historical_ledger_subjects": (
                116,
                240,
                293,
                63,
                318,
                38,
                356,
                356,
                171,
                185,
                279,
                77,
                72,
                284,
            ),
            "source_current_a": (
                127,
                261,
                326,
                62,
                345,
                43,
                388,
                388,
                214,
                174,
                334,
                54,
                124,
                264,
            ),
        }
        self.assertEqual(
            tuple(packets.EXPECTED_CLASSIFICATION_COUNT_SETS),
            packets.CLASSIFICATION_COUNT_SET_KEY_ORDER,
        )
        for label, expected in expected_vectors.items():
            self.assertEqual(
                tuple(
                    packets.EXPECTED_CLASSIFICATION_COUNT_SETS[label][key]
                    for key in packets.CLASSIFICATION_COUNT_KEY_ORDER
                ),
                expected,
            )
        self.assertEqual(
            packets.CLASSIFICATION_CONTROL_STATEMENT,
            "The I overlay SHALL contain exactly 395 classification records, one "
            "for every regular Git blob at the signed F tree in RAW_UTF8_BYTE_ASC "
            "order; SHALL bind classification policy "
            "HASH_PINNED_INDEPENDENT_AUDIT_PLUS_EXPLICIT_REVIEW_OVERRIDES_AND_F_"
            "EXTENSION_V1, audit schema "
            "HALDIR_CH_T002_INDEPENDENT_CLASSIFICATION_AUDIT_V1, SHA-256 "
            "1222a6c9e6962a8c0ad6ac5196868084c03d230e0ba976baa8fe9b49be464441, "
            "audit commit 2167b0b1b8580298b8474e676893f97292c3d7c7, audit tree "
            "66c906443dae3338117f8a43e740b9161811ef7a, override policy "
            "INDEPENDENT_AUTOMATED_PLUS_LOCAL_BYTE_REVIEW_OVERRIDES_V1, exactly "
            "93 field overrides across exactly 75 paths in "
            "RAW_UTF8_BYTE_ASC_PATH_THEN_ASCII_FIELD_ASC order, haldir-ch-t002-"
            "classification-override-set-v1 digest "
            "a9887d37596ef35afc758828e2b1726bd917bd3374f83395db7765b6996761e6, "
            "the explicit .gitignore public_surface NO-to-YES override with rule "
            "PUB_YES_BUILD_OR_DEPLOYMENT_AFFECTED_SURFACE, seven explicit F "
            "additions, "
            "NO_REMOVALS_PER_EXACT_BASELINE_TO_FREEZE_DIFF, the frozen generated "
            "and primary-capture semantics, and haldir-ch-t002-classification-set-"
            "v1 digest "
            "543e0946ed31da0fca3b7bdb184847d9fe68ab03154e3bf17b57869d0a77a051; "
            "and every ledger row, overlay entry, packet, and CH-T002-E09 decision "
            "SHALL agree exactly.",
        )

    def test_git_environment_and_reconstruction_command_are_fully_frozen(
        self,
    ) -> None:
        self.assertEqual(packets._safe_environment(), GIT_ENV)
        command = packets._git_blob_read_command("a" * 40)
        self.assertEqual(command[0], "/usr/bin/git")
        self.assertIn("--no-replace-objects", command)
        self.assertIn("--literal-pathspecs", command)
        self.assertEqual(command[-3:], ["cat-file", "blob", "a" * 40])

    def test_text_validation_rejects_formula_control_trim_and_non_nfc(self) -> None:
        for value in (
            "=SUM(A1)",
            " leading",
            "trailing ",
            "line\nfeed",
            "e\u0301",
            "bidirectional\u202etext",
        ):
            with self.subTest(value=value), self.assertRaises(packets.PacketError):
                packets._expect_string(value, label="fixture")

    def test_path_validation_rejects_traversal_git_and_backslash(self) -> None:
        for value in ("../secret", ".git/config", "a\\b", "/absolute", "a/../b"):
            with self.subTest(value=value), self.assertRaises(packets.PacketError):
                packets._expect_path(value, label="fixture")

    def test_catalog_cell_rejects_empty_duplicate_unsorted_and_unknown(self) -> None:
        for value in ("a;;b", "a;a", "b;a"):
            with self.subTest(value=value), self.assertRaises(packets.PacketError):
                packets._split_catalog_cell(value, label="fixture")
        with self.assertRaises(packets.PacketError):
            packets._validate_pointer_cell(
                "missing", frozenset({"known"}), label="fixture", required=True
            )

    def test_evidence_fragments_require_catalog_base_subject_and_role(self) -> None:
        subject = "a" * 64
        for evidence_id, roles in packets.EVIDENCE_FRAGMENT_ROLES.items():
            for role in roles:
                packets._validate_pointer_cell(
                    f"{evidence_id}#{subject}:{role}",
                    frozenset({evidence_id}),
                    label="fixture",
                    required=True,
                    allow_evidence_fragments=True,
                )
        for value in (
            f"CH-T002-E99#{subject}:PRIMARY",
            "CH-T002-E10#short:PRIMARY",
            f"CH-T002-E10#{subject}:LEAD",
            f"CH-T002-E09#{subject}:REMOVED",
            f"CH-T002-E10#{subject}:PROVENANCE",
            f"CH-T002-E11#{subject}:LICENSE",
            f"CH-T002-E08#{subject}:PRIMARY",
            f"CH-T002-E13#{subject}:SECONDARY",
        ):
            with self.subTest(value=value), self.assertRaises(packets.PacketError):
                packets._validate_pointer_cell(
                    value,
                    frozenset(packets.EVIDENCE_CATALOG),
                    label="fixture",
                    required=True,
                    allow_evidence_fragments=True,
                )

    def test_ledger_parser_rejects_formula_prefix_and_duplicate_path(self) -> None:
        rows = [{field: "" for field in packets.FIELDS} for _ in range(2)]
        for index, row in enumerate(rows):
            row["path"] = "same" if index else "=formula"
        with self.assertRaises(packets.PacketError):
            packets._parse_ledger(packets._render_ledger(rows), label="fixture")

    def test_ledger_parser_rejects_portable_casefold_collision(self) -> None:
        rows = [{field: "" for field in packets.FIELDS} for _ in range(2)]
        rows[0]["path"] = "A.txt"
        rows[1]["path"] = "a.txt"
        with self.assertRaisesRegex(packets.PacketError, "casefold collision"):
            packets._parse_ledger(packets._render_ledger(rows), label="fixture")
        for row in rows:
            row["path"] = "same"
        with self.assertRaises(packets.PacketError):
            packets._parse_ledger(packets._render_ledger(rows), label="fixture")

    def test_atomic_publish_refuses_existing_destination(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "packets"
            target.mkdir()
            marker = target / "marker"
            marker.write_bytes(b"original")
            with self.assertRaises(packets.PacketError):
                packets.publish_outputs(target, {"packet.json": b"{}\n"})
            self.assertEqual(marker.read_bytes(), b"original")

    def test_publish_rejects_symlink_parent_and_destination(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            real_parent = root / "real"
            real_parent.mkdir()
            linked_parent = root / "linked"
            os.symlink(real_parent, linked_parent)
            with self.assertRaisesRegex(packets.PacketError, "parent.*symlink"):
                packets.publish_outputs(
                    linked_parent / "packets", {"packet.json": b"{}\n"}
                )
            target = real_parent / "packets"
            os.symlink("missing", target)
            with self.assertRaisesRegex(packets.PacketError, "already exists"):
                packets.publish_outputs(target, {"packet.json": b"{}\n"})

    def test_publish_rejects_group_or_world_writable_parent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory) / "parent"
            parent.mkdir(mode=0o700)
            try:
                parent.chmod(0o770)
                with self.assertRaisesRegex(packets.PacketError, "trusted"):
                    packets.publish_outputs(
                        parent / "packets", {"packet.json": b"{}\n"}
                    )
            finally:
                parent.chmod(0o700)

    def test_parent_path_swap_cannot_redirect_publication(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            parent = root / "parent"
            parent.mkdir(mode=0o700)
            moved = root / "moved"
            target = parent / "packets"
            original = packets._atomic_rename_noreplace

            def swap_then_rename(*arguments: Any) -> None:
                parent.rename(moved)
                parent.mkdir(mode=0o700)
                original(*arguments)

            with (
                mock.patch.object(
                    packets,
                    "_atomic_rename_noreplace",
                    side_effect=swap_then_rename,
                ),
                mock.patch.object(packets.os, "fsync", return_value=None),
                self.assertRaisesRegex(packets.PacketError, "parent path identity"),
            ):
                packets.publish_outputs(target, {"packet.json": b"{}\n"})
            self.assertFalse((parent / "packets").exists())
            self.assertEqual((moved / "packets" / "packet.json").read_bytes(), b"{}\n")

    def test_atomic_publish_failure_has_no_partial_destination(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "packets"
            with (
                mock.patch.object(
                    packets,
                    "_atomic_rename_noreplace",
                    side_effect=packets.AtomicRenameUnavailable("unavailable"),
                ),
                mock.patch.object(packets.os, "fsync", return_value=None),
                self.assertRaises(packets.AtomicRenameUnavailable),
            ):
                packets.publish_outputs(target, {"packet.json": b"{}\n"})
            self.assertFalse(target.exists())
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_post_write_name_swap_is_rejected_and_cleaned(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "packets"
            original_write = packets._write_all

            def write_then_swap(descriptor: int, data: bytes) -> None:
                original_write(descriptor, data)
                temporary = next(root.glob(".haldir-review-packets-tmp-*"))
                named = temporary / "packet.json"
                named.unlink()
                named.write_bytes(b"swapped\n")

            with (
                mock.patch.object(packets, "_write_all", side_effect=write_then_swap),
                mock.patch.object(packets.os, "fsync", return_value=None),
                self.assertRaisesRegex(packets.PacketError, "identity changed"),
            ):
                packets.publish_outputs(target, {"packet.json": b"{}\n"})
            self.assertFalse(target.exists())
            self.assertEqual(list(root.iterdir()), [])

    def test_post_read_name_swap_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "packets"
            outputs = {"packet.json": b"{}\n"}
            with mock.patch.object(packets.os, "fsync", return_value=None):
                packets.publish_outputs(target, outputs)
            original_read = packets._read_all
            swapped = False

            def read_then_swap(descriptor: int, *, maximum: int) -> bytes:
                nonlocal swapped
                data = original_read(descriptor, maximum=maximum)
                if not swapped:
                    swapped = True
                    named = target / "packet.json"
                    named.unlink()
                    named.write_bytes(data)
                    named.chmod(0o644)
                return data

            with (
                mock.patch.object(packets, "_read_all", side_effect=read_then_swap),
                self.assertRaisesRegex(packets.PacketError, "changed"),
            ):
                packets.verify_outputs(target, outputs)

    def test_concurrent_publishers_allow_exactly_one_no_replace_winner(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "packets"
            outputs = {"packet.json": b"{}\n"}
            original = packets._atomic_rename_noreplace
            boundary = threading.Barrier(2)

            def synchronized_rename(*arguments: Any) -> None:
                boundary.wait(timeout=5)
                original(*arguments)

            def publish() -> str:
                try:
                    packets.publish_outputs(target, outputs)
                except packets.PacketError:
                    return "rejected"
                return "published"

            with (
                mock.patch.object(
                    packets,
                    "_atomic_rename_noreplace",
                    side_effect=synchronized_rename,
                ),
                mock.patch.object(packets.os, "fsync", return_value=None),
                ThreadPoolExecutor(max_workers=2) as executor,
            ):
                outcomes = list(executor.map(lambda _item: publish(), range(2)))
            self.assertEqual(sorted(outcomes), ["published", "rejected"])
            self.assertEqual((target / "packet.json").read_bytes(), b"{}\n")
            self.assertEqual(
                [path.name for path in Path(directory).iterdir()], ["packets"]
            )


class PacketIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temporary.name)
        cls.fixture = RepositoryFixture(cls.root)
        cls.classification_patchers = [
            mock.patch.object(packets, "CH_T001_BASE_COMMIT", cls.fixture.base),
            mock.patch.object(packets, "CH_T001_BASE_TREE", cls.fixture.base_tree),
            mock.patch.object(
                packets,
                "CH_T001_BASE_LEDGER_BLOB",
                cls.fixture.base_ledger_oid,
            ),
            mock.patch.object(
                packets,
                "CH_T001_BASE_LEDGER_SHA256",
                hashlib.sha256(cls.fixture.original_ledger).hexdigest(),
            ),
            mock.patch.object(
                packets,
                "CH_T001_BASE_LEDGER_ROWS",
                len(cls.fixture.original_rows),
            ),
            mock.patch.object(
                packets,
                "CLASSIFICATION_OVERRIDE_PATHS",
                cls.fixture.override_paths,
            ),
            mock.patch.object(
                packets,
                "EXPECTED_CLASSIFICATION_OVERRIDE_FIELDS",
                len(cls.fixture.override_rows),
            ),
            mock.patch.object(
                packets,
                "EXPECTED_CLASSIFICATION_OVERRIDE_SET_SHA256",
                cls.fixture.override_digest,
            ),
            mock.patch.object(packets, "CLASSIFICATION_F_EXTENSION_PATHS", ()),
            mock.patch.object(
                packets,
                "EXPECTED_CLASSIFICATION_RECORDS",
                len(cls.fixture.classification_records),
            ),
            mock.patch.object(
                packets,
                "EXPECTED_CLASSIFICATION_SET_SHA256",
                cls.fixture.classification_digest,
            ),
        ]
        for patcher in cls.classification_patchers:
            patcher.start()
        try:
            cls.prepared = cls.fixture.prepare()
        except BaseException:
            for patcher in reversed(cls.classification_patchers):
                patcher.stop()
            cls.temporary.cleanup()
            raise

    @classmethod
    def tearDownClass(cls) -> None:
        for patcher in reversed(cls.classification_patchers):
            patcher.stop()
        cls.temporary.cleanup()

    def output_target(self) -> Path:
        parent = self.root / self._testMethodName
        parent.mkdir(exist_ok=True)
        return parent / "packets"

    def test_exact_fixture_prepares_all_subjects_and_assignments(self) -> None:
        prepared = self.prepared
        self.assertEqual(len(prepared.subjects), 8)
        self.assertEqual(
            {subject.path for subject in prepared.subjects},
            {
                "assets/blob.bin",
                packets.LEDGER_PATH,
                packets.LEDGER_GENERATOR_PATH,
                "docs/new.txt",
                REGISTRY_PATH,
                "src/alpha.py",
                "src/critical.md",
                "src/empty.txt",
            },
        )
        self.assertEqual(sum(len(lane.primary) for lane in prepared.lanes), 8)
        self.assertEqual(sum(len(lane.secondary) for lane in prepared.lanes), 5)

    def test_n03_accepts_exact_frozen_classification_contract(self) -> None:
        self.assertNotIn("review_classification_contract", self.fixture.registry)
        self.assertEqual(tuple(self.fixture.registry), packets.CENTRAL_FREEZE_KEY_ORDER)
        classifications = packets._validate_classification_contract(
            self.fixture.overlay,
            packets._tree_entries(self.fixture.repo, self.fixture.freeze),
            [row["path"] for row in self.fixture.original_rows],
        )
        self.assertEqual(classifications, self.fixture.classification_by_path)
        packets._validate_freeze_catalogs(self.fixture.registry, self.fixture.overlay)

    def test_n03_rejects_classification_contract_drift(self) -> None:
        overlay = json.loads(json.dumps(self.fixture.overlay))
        contract = overlay["review_classification_contract"]
        target = next(
            record
            for record in contract["records"]
            if record["path"] == "assets/blob.bin"
        )
        target["public_surface"] = "YES"
        target["rule_ids"][0] = "PUB_YES_FIXTURE_DOWNGRADE"
        by_path = {record["path"]: record for record in contract["records"]}
        source_records = [dict(record) for record in contract["records"]]
        next(
            record for record in source_records if record["path"] == "src/critical.md"
        )["security_critical"] = "NO"
        historical = [row["path"] for row in self.fixture.original_rows]
        contract["counts"] = {
            "f_additions": packets._classification_counts([]),
            "final_current_a": packets._classification_counts(contract["records"]),
            "final_f": packets._classification_counts(contract["records"]),
            "final_historical_ledger_subjects": packets._classification_counts(
                by_path[path] for path in historical
            ),
            "source_current_a": packets._classification_counts(source_records),
        }
        changed_digest = packets._domain_digest(
            packets.CLASSIFICATION_SET_DOMAIN, contract["records"]
        )
        contract["classification_set_sha256"] = changed_digest
        overlay["digests"]["classification_set_sha256"] = changed_digest
        with self.assertRaisesRegex(packets.PacketError, "expected-set digest"):
            packets._validate_classification_contract(
                overlay,
                packets._tree_entries(self.fixture.repo, self.fixture.freeze),
                [row["path"] for row in self.fixture.original_rows],
            )

    def test_all_six_override_fields_are_exact_and_bidirectional(self) -> None:
        by_path = json.loads(json.dumps(self.fixture.classification_by_path))
        final = by_path["src/critical.md"]
        rows = [
            {
                "after": "NO",
                "before": "YES",
                "field": "authority_critical",
                "path": final["path"],
                "rule_id": final["rule_ids"][3],
                "source_basis": packets.CLASSIFICATION_OVERRIDE_SOURCE_BASIS,
            },
            {
                "after": "NO",
                "before": "YES",
                "field": "generated",
                "path": final["path"],
                "rule_id": final["rule_ids"][4],
                "source_basis": packets.CLASSIFICATION_OVERRIDE_SOURCE_BASIS,
            },
            {
                "after": "",
                "before": "src/alpha.py",
                "field": "generator",
                "path": final["path"],
                "rule_id": final["rule_ids"][4],
                "source_basis": packets.CLASSIFICATION_OVERRIDE_SOURCE_BASIS,
            },
            {
                "after": "NO",
                "before": "YES",
                "field": "public_surface",
                "path": final["path"],
                "rule_id": final["rule_ids"][0],
                "source_basis": packets.CLASSIFICATION_OVERRIDE_SOURCE_BASIS,
            },
            {
                "after": "NO",
                "before": "YES",
                "field": "science_critical",
                "path": final["path"],
                "rule_id": final["rule_ids"][2],
                "source_basis": packets.CLASSIFICATION_OVERRIDE_SOURCE_BASIS,
            },
            {
                "after": "YES",
                "before": "NO",
                "field": "security_critical",
                "path": final["path"],
                "rule_id": final["rule_ids"][1],
                "source_basis": packets.CLASSIFICATION_OVERRIDE_SOURCE_BASIS,
            },
        ]
        policy = {
            "field_override_count": len(rows),
            "order": packets.CLASSIFICATION_OVERRIDE_ORDER,
            "overrides": rows,
            "path_count": 1,
            "paths": [final["path"]],
            "policy_id": packets.CLASSIFICATION_OVERRIDE_POLICY_ID,
        }
        digest = packets._domain_digest(
            packets.CLASSIFICATION_OVERRIDE_SET_DOMAIN, rows
        )
        with (
            mock.patch.object(
                packets, "EXPECTED_CLASSIFICATION_OVERRIDE_FIELDS", len(rows)
            ),
            mock.patch.object(
                packets, "EXPECTED_CLASSIFICATION_OVERRIDE_SET_SHA256", digest
            ),
        ):
            validated, reconstructed = packets._validate_classification_overrides(
                policy, by_path
            )
        self.assertEqual(validated, rows)
        source = reconstructed[final["path"]]
        self.assertEqual(
            {
                field: source[field]
                for field in (
                    "authority_critical",
                    "generated",
                    "generator",
                    "public_surface",
                    "science_critical",
                    "security_critical",
                )
            },
            {
                "authority_critical": "YES",
                "generated": "YES",
                "generator": "src/alpha.py",
                "public_surface": "YES",
                "science_critical": "YES",
                "security_critical": "NO",
            },
        )

    def test_override_forbidden_field_before_value_and_order_are_rejected(
        self,
    ) -> None:
        by_path = json.loads(json.dumps(self.fixture.classification_by_path))
        original = self.fixture.overlay["review_classification_contract"][
            "override_policy"
        ]

        forbidden = json.loads(json.dumps(original))
        forbidden["overrides"][0]["field"] = "license_review_status"
        with self.assertRaisesRegex(packets.PacketError, "forbidden field"):
            packets._validate_classification_overrides(forbidden, by_path)

        not_bidirectional = json.loads(json.dumps(original))
        not_bidirectional["overrides"][0]["before"] = "YES"
        with self.assertRaisesRegex(packets.PacketError, "not bidirectional"):
            packets._validate_classification_overrides(not_bidirectional, by_path)

        final_mismatch = json.loads(json.dumps(original))
        final_mismatch["overrides"][0]["after"] = "NO"
        final_mismatch["overrides"][0]["before"] = "YES"
        with self.assertRaisesRegex(packets.PacketError, "final value"):
            packets._validate_classification_overrides(final_mismatch, by_path)

        unordered = json.loads(json.dumps(original))
        final = by_path["src/critical.md"]
        unordered["overrides"].append(
            {
                "after": "NO",
                "before": "YES",
                "field": "authority_critical",
                "path": final["path"],
                "rule_id": final["rule_ids"][3],
                "source_basis": packets.CLASSIFICATION_OVERRIDE_SOURCE_BASIS,
            }
        )
        unordered["field_override_count"] = 2
        with self.assertRaisesRegex(packets.PacketError, "not path/field sorted"):
            packets._validate_classification_overrides(unordered, by_path)

    def test_generated_generator_override_is_atomic_and_hash_pinned(self) -> None:
        by_path = json.loads(json.dumps(self.fixture.classification_by_path))
        final = by_path["src/critical.md"]
        generated = {
            "after": "NO",
            "before": "YES",
            "field": "generated",
            "path": final["path"],
            "rule_id": final["rule_ids"][4],
            "source_basis": packets.CLASSIFICATION_OVERRIDE_SOURCE_BASIS,
        }
        generator = {
            "after": "",
            "before": "src/alpha.py",
            "field": "generator",
            "path": final["path"],
            "rule_id": final["rule_ids"][4],
            "source_basis": packets.CLASSIFICATION_OVERRIDE_SOURCE_BASIS,
        }
        security = json.loads(
            json.dumps(
                self.fixture.overlay["review_classification_contract"][
                    "override_policy"
                ]["overrides"][0]
            )
        )
        atomic_rows = [generated, generator, security]
        policy = {
            "field_override_count": len(atomic_rows),
            "order": packets.CLASSIFICATION_OVERRIDE_ORDER,
            "overrides": atomic_rows,
            "path_count": 1,
            "paths": [final["path"]],
            "policy_id": packets.CLASSIFICATION_OVERRIDE_POLICY_ID,
        }
        missing_pair = json.loads(json.dumps(policy))
        missing_pair["overrides"].pop(1)
        missing_pair["field_override_count"] -= 1
        with self.assertRaisesRegex(packets.PacketError, "not atomic"):
            packets._validate_classification_overrides(missing_pair, by_path)

        untracked = json.loads(json.dumps(policy))
        untracked["overrides"][1]["before"] = "src/missing.py"
        with self.assertRaisesRegex(packets.PacketError, "not a tracked F path"):
            packets._validate_classification_overrides(untracked, by_path)

        digest = packets._domain_digest(
            packets.CLASSIFICATION_OVERRIDE_SET_DOMAIN, atomic_rows
        )
        changed_before = json.loads(json.dumps(policy))
        changed_before["overrides"][1]["before"] = "docs/new.txt"
        with (
            mock.patch.object(
                packets,
                "EXPECTED_CLASSIFICATION_OVERRIDE_FIELDS",
                len(atomic_rows),
            ),
            mock.patch.object(
                packets, "EXPECTED_CLASSIFICATION_OVERRIDE_SET_SHA256", digest
            ),
            self.assertRaisesRegex(packets.PacketError, "override-set digest"),
        ):
            packets._validate_classification_overrides(changed_before, by_path)

    def test_historical_counts_use_the_current_a_path_intersection(self) -> None:
        overlay = json.loads(json.dumps(self.fixture.overlay))
        contract = overlay["review_classification_contract"]
        addition = next(
            record
            for record in contract["records"]
            if record["path"] == "src/empty.txt"
        )
        addition["source_basis"] = "EXPLICIT_CH_T002_F_ADDITION_POLICY_V1"
        by_path = {record["path"]: record for record in contract["records"]}
        current_a = [
            record
            for record in contract["records"]
            if record["source_basis"] != "EXPLICIT_CH_T002_F_ADDITION_POLICY_V1"
        ]
        source_current_a = [dict(record) for record in current_a]
        next(
            record for record in source_current_a if record["path"] == "src/critical.md"
        )["security_critical"] = "NO"
        historical_paths = [row["path"] for row in self.fixture.original_rows]
        historical_current_a = [
            path for path in historical_paths if path != addition["path"]
        ]
        contract["counts"] = {
            "f_additions": packets._classification_counts([addition]),
            "final_current_a": packets._classification_counts(current_a),
            "final_f": packets._classification_counts(contract["records"]),
            "final_historical_ledger_subjects": packets._classification_counts(
                by_path[path] for path in historical_current_a
            ),
            "source_current_a": packets._classification_counts(source_current_a),
        }
        digest = packets._domain_digest(
            packets.CLASSIFICATION_SET_DOMAIN, contract["records"]
        )
        contract["classification_set_sha256"] = digest
        overlay["digests"]["classification_set_sha256"] = digest
        with (
            mock.patch.object(
                packets, "CLASSIFICATION_F_EXTENSION_PATHS", (addition["path"],)
            ),
            mock.patch.object(packets, "EXPECTED_CLASSIFICATION_SET_SHA256", digest),
        ):
            validated = packets._validate_classification_contract(
                overlay,
                packets._tree_entries(self.fixture.repo, self.fixture.freeze),
                historical_paths,
            )
        self.assertEqual(validated[addition["path"]], addition)

    def test_classification_contract_nested_keys_follow_canonical_order(
        self,
    ) -> None:
        parsed = packets._parse_canonical_json(
            packets._canonical_json(self.fixture.overlay), label="golden overlay"
        )
        contract = parsed["review_classification_contract"]
        self.assertEqual(tuple(contract), packets.CLASSIFICATION_CONTRACT_KEY_ORDER)
        self.assertEqual(
            tuple(contract["source_audit"]),
            packets.CLASSIFICATION_SOURCE_KEY_ORDER,
        )
        self.assertEqual(
            tuple(contract["override_policy"]),
            packets.CLASSIFICATION_OVERRIDE_KEY_ORDER,
        )
        self.assertEqual(
            tuple(contract["semantics"]), packets.CLASSIFICATION_SEMANTICS_KEY_ORDER
        )
        self.assertEqual(
            tuple(contract["records"][0]),
            packets.CLASSIFICATION_RECORD_KEY_ORDER,
        )

    def test_classification_contract_rejects_path_projection_and_semantic_drift(
        self,
    ) -> None:
        inventory = packets._tree_entries(self.fixture.repo, self.fixture.freeze)
        mutations: list[tuple[str, Any]] = []

        wrong_path = json.loads(json.dumps(self.fixture.overlay))
        target = next(
            record
            for record in wrong_path["review_classification_contract"]["records"]
            if record["path"] == "src/empty.txt"
        )
        target["path"] = "src/missing.txt"
        wrong_path["review_classification_contract"]["records"].sort(
            key=lambda record: record["path"].encode("utf-8")
        )
        mutations.append(("freeze tree", wrong_path))

        wrong_projection = json.loads(json.dumps(self.fixture.overlay))
        next(
            entry
            for entry in wrong_projection["entries"]
            if entry["path"] == "docs/new.txt"
        )["source_basis"] = "EXPLICIT_CH_T002_F_ADDITION_POLICY_V1"
        mutations.append(("entry decision", wrong_projection))

        wrong_semantics = json.loads(json.dumps(self.fixture.overlay))
        wrong_semantics["review_classification_contract"]["semantics"]["generated"] = (
            "Different semantics."
        )
        mutations.append(("semantics", wrong_semantics))

        for expected, overlay in mutations:
            with (
                self.subTest(expected=expected),
                self.assertRaisesRegex(packets.PacketError, expected),
            ):
                packets._validate_classification_contract(
                    overlay,
                    inventory,
                    [row["path"] for row in self.fixture.original_rows],
                )

    def test_generated_and_primary_capture_semantics_are_distinct(self) -> None:
        records = self.fixture.classification_by_path
        self.assertEqual(records["src/alpha.py"]["generated"], "YES")
        self.assertEqual(records["src/alpha.py"]["generator"], "src/alpha.py")
        self.assertEqual(records["src/critical.md"]["generated"], "NO")
        self.assertEqual(records["src/critical.md"]["generator"], "")
        semantics = self.fixture.overlay["review_classification_contract"]["semantics"]
        self.assertEqual(
            semantics["primary_capture"],
            packets.CLASSIFICATION_PRIMARY_CAPTURE_SEMANTICS,
        )

    def test_real_empty_git_blob_is_one_unit_with_no_synthetic_line(self) -> None:
        subject = next(
            subject
            for subject in self.prepared.subjects
            if subject.path == "src/empty.txt"
        )
        self.assertEqual((subject.size, subject.lines, subject.units), (0, 0, 1))
        packet_record = subject.packet_record(
            freeze_commit=self.fixture.freeze,
            freeze_tree=self.fixture.freeze_tree,
        )
        self.assertEqual(
            packet_record["coverage"]["byte_interval"],
            {"end_exclusive": 0, "start_inclusive": 0},
        )
        self.assertIsNone(packet_record["coverage"]["line_interval"])

    def test_git_blob_hash_uses_nonsecurity_sha1_mode(self) -> None:
        original_sha1 = hashlib.sha1
        data = b"fixture\n"
        oid = original_sha1(
            f"blob {len(data)}\0".encode("ascii") + data,
            usedforsecurity=False,
        ).hexdigest()
        tree_record = f"100644 blob {oid}\tsrc/alpha.py\0".encode("ascii")
        with (
            mock.patch.object(packets, "_run_git", side_effect=(tree_record, data)),
            mock.patch.object(packets.hashlib, "sha1", wraps=original_sha1) as sha1,
        ):
            packets._blob_at(self.fixture.repo, self.fixture.source, "src/alpha.py")
        self.assertEqual(sha1.call_count, 1)
        self.assertIs(sha1.call_args.kwargs["usedforsecurity"], False)

    def test_git_reads_ignore_replace_refs_and_hostile_ambient_configuration(
        self,
    ) -> None:
        repo = self.fixture.repo
        source_row = next(
            row for row in self.fixture.original_rows if row["path"] == "src/alpha.py"
        )
        source_oid = source_row["current_git_blob_id"]
        replacement_entry = next(
            entry
            for entry in self.fixture.overlay["entries"]
            if entry["path"] == "src/alpha.py"
        )
        replacement_oid = replacement_entry["git_object_id"]
        source_data = self.fixture.source_alpha_data
        replacement_data = self.fixture.freeze_alpha_data
        self.assertNotEqual(source_data, replacement_data)
        replace_ref = repo / ".git" / "refs" / "replace" / source_oid
        write_bytes(replace_ref, f"{replacement_oid}\n".encode("ascii"))
        hostile_root = self.root / self._testMethodName
        hostile_root.mkdir()
        marker = hostile_root / "invoked"
        helper = hostile_root / "hostile-helper"
        write_bytes(
            helper,
            b'#!/bin/sh\nprintf invoked > "$HALDIR_HOSTILE_MARKER"\nexit 97\n',
        )
        helper.chmod(0o755)
        hostile_config = hostile_root / "hostile.gitconfig"
        write_bytes(
            hostile_config,
            (f"[diff]\n\texternal = {helper}\n[core]\n\tfsmonitor = {helper}\n").encode(
                "utf-8"
            ),
        )
        unsafe_environment = {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "HOME": str(hostile_root),
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/usr/bin:/bin",
        }
        try:
            unsafe = subprocess.run(
                [
                    packets.GIT_EXECUTABLE,
                    "-C",
                    str(repo),
                    "cat-file",
                    "blob",
                    source_oid,
                ],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=unsafe_environment,
            ).stdout
            self.assertEqual(unsafe, replacement_data)
            with mock.patch.dict(
                os.environ,
                {
                    "GIT_CONFIG_COUNT": "1",
                    "GIT_CONFIG_GLOBAL": str(hostile_config),
                    "GIT_CONFIG_KEY_0": "diff.external",
                    "GIT_CONFIG_VALUE_0": str(helper),
                    "GIT_OBJECT_DIRECTORY": str(hostile_root / "missing-objects"),
                    "HALDIR_HOSTILE_MARKER": str(marker),
                },
                clear=False,
            ):
                observed_data = packets._run_git(repo, ["cat-file", "blob", source_oid])
                packets._diff_name_status(repo, self.fixture.base, self.fixture.freeze)
            self.assertEqual(observed_data, source_data)
            self.assertFalse(marker.exists())
        finally:
            replace_ref.unlink(missing_ok=True)

    def test_git_deadline_survives_an_inherited_pipe_writer(self) -> None:
        helper = self.root / f"{self._testMethodName}.py"
        write_bytes(
            helper,
            (
                f"#!{sys.executable}\n"
                "import os\n"
                "import time\n"
                "os.write(1, b'x')\n"
                "if os.fork() == 0:\n"
                "    time.sleep(0.25)\n"
                "    os._exit(0)\n"
                "os._exit(0)\n"
            ).encode("utf-8"),
        )
        helper.chmod(0o755)
        started = time.monotonic()
        with (
            mock.patch.object(packets, "GIT_EXECUTABLE", sys.executable),
            mock.patch.object(packets, "GIT_GLOBAL_OPTIONS", (str(helper),)),
            mock.patch.object(packets, "GIT_TIMEOUT_SECONDS", 0.05),
            self.assertRaisesRegex(packets.PacketError, "time bound"),
        ):
            packets._run_git(self.fixture.repo, ["fixture"])
        self.assertLess(time.monotonic() - started, 1.0)

    def test_unchanged_subject_is_bound_to_the_exact_freeze_snapshot(self) -> None:
        subject = next(
            subject
            for subject in self.prepared.subjects
            if subject.path == "assets/blob.bin"
        )
        self.assertEqual(subject.status, "UNCHANGED_BASE")
        record = subject.packet_record(
            freeze_commit=self.fixture.freeze,
            freeze_tree=self.fixture.freeze_tree,
        )
        self.assertEqual(record["content_commit"], self.fixture.freeze)
        self.assertEqual(record["content_tree"], self.fixture.freeze_tree)
        self.assertEqual(record["snapshot_state"], "PRESENT_AT_CH_T002_F")
        self.assertEqual(record["coverage"]["kind"], packets.COVERAGE_RULE)

    def test_manifest_is_raw_e13_reconciliation_record(self) -> None:
        manifest = json.loads(
            packets.build_outputs(self.prepared)["file-review-packet-manifest.json"]
        )
        reconciliation = manifest["overlay_reconciliation"]
        self.assertEqual(
            set(reconciliation),
            set(packets.SCHEMA["manifest"]["overlay_reconciliation"]),
        )
        self.assertEqual(
            reconciliation["overlay_input"], manifest["snapshot"]["overlay"]
        )
        self.assertEqual(reconciliation["counts"], self.fixture.overlay["counts"])
        self.assertEqual(reconciliation["digests"], self.fixture.overlay["digests"])
        self.assertEqual(reconciliation["current_freeze_regular_blobs"], 8)
        self.assertEqual(reconciliation["current_subjects"], 8)
        self.assertEqual(reconciliation["removed_tombstones"], 0)
        for field in (
            "content_identity_mismatches",
            "duplicate_current_paths",
            "invalid_removed_tombstones",
            "missing_current_paths",
            "uncovered_freeze_tree_subjects",
        ):
            self.assertEqual(reconciliation[field], 0)

    def test_render_and_verify_round_trip_is_exact_and_bounded(self) -> None:
        prepared = self.prepared
        outputs = packets.build_outputs(prepared)
        expected_names = {
            "review-lane-01.json",
            "review-lane-02.json",
            "review-lane-03.json",
            "file-review-packet-manifest.json",
        }
        self.assertEqual(set(outputs), expected_names)
        self.assertTrue(all(len(data) < 4 * 1024 * 1024 for data in outputs.values()))
        target = self.output_target()
        with mock.patch.object(packets.os, "fsync", return_value=None) as fsync:
            packets.publish_outputs(target, outputs)
        self.assertGreaterEqual(fsync.call_count, len(outputs) + 2)
        packets.verify_outputs(target, outputs)
        self.assertTrue(
            all(
                stat.S_IMODE((target / name).stat().st_mode) == 0o644
                for name in outputs
            )
        )
        manifest = json.loads(outputs["file-review-packet-manifest.json"])
        self.assertEqual(
            manifest["snapshot"]["implementation_commit"], self.fixture.implementation
        )
        self.assertEqual(manifest["result"], "PASS")

    def test_every_packet_subject_binds_git_identity_and_exact_coverage(self) -> None:
        outputs = packets.build_outputs(self.prepared)
        primary = []
        secondary = []
        for lane in range(1, 4):
            value = json.loads(outputs[f"review-lane-{lane:02d}.json"])
            for key, collection in (
                ("primary_entries", primary),
                ("secondary_entries", secondary),
            ):
                for record in value["assignment"][key]:
                    collection.append(record["subject_id"])
                    self.assertEqual(record["snapshot_state"], "PRESENT_AT_CH_T002_F")
                    self.assertEqual(record["content_commit"], self.fixture.freeze)
                    self.assertEqual(record["content_tree"], self.fixture.freeze_tree)
                    self.assertEqual(record["coverage"]["kind"], packets.COVERAGE_RULE)
                    self.assertEqual(
                        record["coverage"]["byte_interval"]["start_inclusive"], 0
                    )
                    self.assertEqual(
                        record["coverage"]["byte_interval"]["end_exclusive"],
                        record["bytes"],
                    )
                    self.assertEqual(
                        record["coverage"]["read_command"],
                        packets._git_blob_read_command(record["git_object_id"]),
                    )
                    self.assertNotIn("content", record)
        self.assertEqual(len(primary), len(set(primary)))
        self.assertEqual(len(secondary), len(set(secondary)))
        self.assertEqual(len(primary), 8)
        self.assertEqual(len(secondary), 5)

    def test_render_is_create_once_and_verify_detects_tampering(self) -> None:
        outputs = packets.build_outputs(self.prepared)
        target = self.output_target()
        with mock.patch.object(packets.os, "fsync", return_value=None):
            packets.publish_outputs(target, outputs)
        with self.assertRaises(packets.PacketError):
            packets.publish_outputs(target, outputs)
        lane = target / "review-lane-01.json"
        lane.write_bytes(lane.read_bytes() + b" ")
        with self.assertRaises(packets.PacketError):
            packets.verify_outputs(target, outputs)

    def test_cli_render_and_verify_have_canonical_summaries(self) -> None:
        target = self.output_target()
        common = [
            "--repo",
            str(self.fixture.repo),
            "--implementation-commit",
            self.fixture.implementation,
            "--ledger",
            str(self.fixture.repo / packets.LEDGER_PATH),
            "--overlay",
            str(self.fixture.repo / packets.OVERLAY_PATH),
            "--output-dir",
            str(target),
            "--reviewer-registry",
            str(self.fixture.repo / REGISTRY_PATH),
        ]
        for command in ("render", "verify"):
            capture = mock.Mock()
            capture.buffer = io.BytesIO()
            capture.fileno.return_value = -1
            errors = io.StringIO()
            with (
                mock.patch.object(
                    packets, "_prepare_inputs", return_value=self.prepared
                ),
                mock.patch.object(packets.sys, "stdout", capture),
                mock.patch.object(packets.sys, "stderr", errors),
                mock.patch.object(packets.os, "fsync", return_value=None),
            ):
                return_code = packets.main([command, *common])
            self.assertEqual(return_code, 0, errors.getvalue())
            self.assertEqual(errors.getvalue(), "")
            value = packets._parse_canonical_json(
                capture.buffer.getvalue(), label="CLI summary"
            )
            self.assertEqual(value["command"], command)
            self.assertEqual(value["result"], "PASS")

    def test_cli_subprocess_renders_and_verifies_with_canonical_output(self) -> None:
        runner = self.root / f"{self._testMethodName}.py"
        runner_source = f'''#!/usr/bin/env python3
import importlib.util
import pathlib
import sys

script = pathlib.Path({str(SCRIPT.resolve())!r})
spec = importlib.util.spec_from_file_location("packet_cli_subprocess", script)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
module.CH_T001_BASE_COMMIT = {self.fixture.base!r}
module.CH_T001_BASE_TREE = {self.fixture.base_tree!r}
module.CH_T001_BASE_LEDGER_BLOB = {self.fixture.base_ledger_oid!r}
module.CH_T001_BASE_LEDGER_SHA256 = {hashlib.sha256(self.fixture.original_ledger).hexdigest()!r}
module.CH_T001_BASE_LEDGER_ROWS = {len(self.fixture.original_rows)!r}
module.CLASSIFICATION_OVERRIDE_PATHS = {self.fixture.override_paths!r}
module.EXPECTED_CLASSIFICATION_OVERRIDE_FIELDS = {len(self.fixture.override_rows)!r}
module.EXPECTED_CLASSIFICATION_OVERRIDE_SET_SHA256 = {self.fixture.override_digest!r}
module.CLASSIFICATION_F_EXTENSION_PATHS = ()
module.EXPECTED_CLASSIFICATION_RECORDS = {len(self.fixture.classification_records)!r}
module.EXPECTED_CLASSIFICATION_SET_SHA256 = {self.fixture.classification_digest!r}
raise SystemExit(module.main())
'''
        write_bytes(runner, runner_source.encode("utf-8"))
        target = self.output_target()
        common = [
            "--repo",
            str(self.fixture.repo),
            "--implementation-commit",
            self.fixture.implementation,
            "--ledger",
            str(self.fixture.repo / packets.LEDGER_PATH),
            "--overlay",
            str(self.fixture.repo / packets.OVERLAY_PATH),
            "--output-dir",
            str(target),
            "--reviewer-registry",
            str(self.fixture.repo / REGISTRY_PATH),
        ]
        for command in ("render", "verify"):
            completed = subprocess.run(
                [sys.executable, "-B", "-I", "-P", str(runner), command, *common],
                check=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=GIT_ENV,
                timeout=30,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr.decode())
            self.assertEqual(completed.stderr, b"")
            value = packets._parse_canonical_json(
                completed.stdout, label="subprocess CLI summary"
            )
            self.assertEqual(completed.stdout, packets._canonical_json(value))
            self.assertEqual((value["command"], value["result"]), (command, "PASS"))

    def test_live_provenance_must_match_exact_confirmed_contract(self) -> None:
        rows = [dict(row) for row in self.fixture.completed_rows]
        target = next(row for row in rows if row["path"] == "src/critical.md")
        target["provenance_review_status"] = "NOT_APPLICABLE"
        target["provenance_evidence"] = ""
        with self.assertRaisesRegex(packets.PacketError, "F classification"):
            packets._validate_completed_ledger(
                rows,
                self.fixture.original_rows,
                self.fixture.overlay,
                self.fixture.classification_by_path,
            )

    def test_semantic_provenance_and_license_pointers_are_exact(self) -> None:
        target_path = "src/critical.md"
        subject = next(
            item for item in self.prepared.subjects if item.path == target_path
        )
        for field, value in (
            (
                "provenance_evidence",
                f"CH-T002-E09#{subject.subject_id}:LICENSE",
            ),
            ("license_evidence", "CH-T002-E09"),
        ):
            rows = [dict(row) for row in self.fixture.completed_rows]
            next(row for row in rows if row["path"] == target_path)[field] = value
            with (
                self.subTest(field=field),
                self.assertRaisesRegex(packets.PacketError, "subject-qualified"),
            ):
                packets._validate_completed_ledger(
                    rows,
                    self.fixture.original_rows,
                    self.fixture.overlay,
                    self.fixture.classification_by_path,
                )

    def test_live_not_applicable_provenance_is_never_inferred(self) -> None:
        for evidence in (
            "",
            next(
                row["provenance_evidence"]
                for row in self.fixture.completed_rows
                if row["path"] == "src/alpha.py"
            ),
        ):
            rows = [dict(row) for row in self.fixture.completed_rows]
            target = next(row for row in rows if row["path"] == "src/alpha.py")
            target["provenance_review_status"] = "NOT_APPLICABLE"
            target["provenance_evidence"] = evidence
            with (
                self.subTest(evidence=evidence),
                self.assertRaisesRegex(packets.PacketError, "F classification"),
            ):
                packets._validate_completed_ledger(
                    rows,
                    self.fixture.original_rows,
                    self.fixture.overlay,
                    self.fixture.classification_by_path,
                )

    def test_all_base_ledger_subjects_remain_live_and_reviewed(self) -> None:
        rows = [dict(row) for row in self.fixture.completed_rows]
        live = next(row for row in rows if row["path"] == "assets/blob.bin")
        subject = next(
            item for item in self.prepared.subjects if item.path == live["path"]
        )
        self.assertEqual(live["provenance_review_status"], "CONFIRMED")
        self.assertEqual(
            live["provenance_evidence"],
            f"CH-T002-E09#{subject.subject_id}:PROVENANCE",
        )
        self.assertEqual(live["license_review_status"], "APPROVED")
        self.assertEqual(live["license_expression"], "Apache-2.0 OR MIT")
        self.assertEqual(
            live["license_evidence"],
            f"CH-T002-E09#{subject.subject_id}:LICENSE",
        )
        packets._validate_completed_ledger(
            rows,
            self.fixture.original_rows,
            self.fixture.overlay,
            self.fixture.classification_by_path,
        )
        live["provenance_review_status"] = "NOT_APPLICABLE"
        live["provenance_evidence"] = ""
        with self.assertRaisesRegex(packets.PacketError, "F classification"):
            packets._validate_completed_ledger(
                rows,
                self.fixture.original_rows,
                self.fixture.overlay,
                self.fixture.classification_by_path,
            )

    def test_every_ledger_disposition_must_be_accepted(self) -> None:
        for path in ("src/empty.txt", "assets/blob.bin"):
            rows = [dict(row) for row in self.fixture.completed_rows]
            next(row for row in rows if row["path"] == path)["disposition"] = (
                "NOT_APPLICABLE"
            )
            with self.subTest(path=path), self.assertRaises(packets.PacketError):
                packets._validate_completed_ledger(
                    rows,
                    self.fixture.original_rows,
                    self.fixture.overlay,
                    self.fixture.classification_by_path,
                )

    def test_accepted_disposition_requires_no_recorded_defect(self) -> None:
        packets._validate_completed_ledger(
            self.fixture.completed_rows,
            self.fixture.original_rows,
            self.fixture.overlay,
            self.fixture.classification_by_path,
        )
        rows = [dict(row) for row in self.fixture.completed_rows]
        rows[0]["defects"] = packets.ROW_REQUIREMENT_ID
        with self.assertRaisesRegex(packets.PacketError, "recorded defect"):
            packets._validate_completed_ledger(
                rows,
                self.fixture.original_rows,
                self.fixture.overlay,
                self.fixture.classification_by_path,
            )

    def test_ledger_rows_require_the_exact_frozen_requirement_and_test(self) -> None:
        for field, value, message in (
            ("requirements", "CH-T002-N02", "frozen requirement"),
            ("tests", "test_n02_accepted", "frozen test"),
        ):
            rows = [dict(row) for row in self.fixture.completed_rows]
            rows[0][field] = value
            with (
                self.subTest(field=field),
                self.assertRaisesRegex(packets.PacketError, message),
            ):
                packets._validate_completed_ledger(
                    rows,
                    self.fixture.original_rows,
                    self.fixture.overlay,
                    self.fixture.classification_by_path,
                )

    def test_ledger_self_requires_exact_generator(self) -> None:
        rows = [dict(row) for row in self.fixture.completed_rows]
        original_rows = [dict(row) for row in self.fixture.original_rows]
        target = next(row for row in rows if row["path"] == packets.LEDGER_PATH)
        original_target = next(
            row for row in original_rows if row["path"] == packets.LEDGER_PATH
        )
        target["generator"] = "src/alpha.py"
        original_target["generator"] = "src/alpha.py"
        classifications = json.loads(json.dumps(self.fixture.classification_by_path))
        classifications[packets.LEDGER_PATH]["generator"] = "src/alpha.py"
        with self.assertRaisesRegex(packets.PacketError, "ledger self row lacks"):
            packets._validate_completed_ledger(
                rows,
                original_rows,
                self.fixture.overlay,
                classifications,
            )

    def test_generator_catalog_is_exact_used_and_resolvable(self) -> None:
        overlay = json.loads(json.dumps(self.fixture.overlay))
        overlay["scope"]["generator_catalog"].append("src/empty.txt")
        overlay["scope"]["generator_catalog"].sort(key=lambda item: item.encode())
        with self.assertRaisesRegex(packets.PacketError, "exact set used"):
            packets._validate_completed_ledger(
                self.fixture.completed_rows,
                self.fixture.original_rows,
                overlay,
                self.fixture.classification_by_path,
            )
        rows = [dict(row) for row in self.fixture.completed_rows]
        target = next(
            row for row in rows if row["path"] == packets.LEDGER_GENERATOR_PATH
        )
        target["generated"] = "YES"
        target["generator"] = "not/in/the/ledger.py"
        classifications = json.loads(json.dumps(self.fixture.classification_by_path))
        classifications[target["path"]]["generated"] = "YES"
        classifications[target["path"]]["generator"] = target["generator"]
        overlay = json.loads(json.dumps(self.fixture.overlay))
        overlay["scope"]["generator_catalog"].append(target["generator"])
        overlay["scope"]["generator_catalog"].sort(key=lambda item: item.encode())
        with self.assertRaisesRegex(packets.PacketError, "unknown generator"):
            packets._validate_completed_ledger(
                rows,
                self.fixture.original_rows,
                overlay,
                classifications,
            )

    def test_freeze_catalogs_are_exact_not_arbitrary_machine_tokens(self) -> None:
        self.assertEqual(len(self.fixture.registry), 31)
        self.assertEqual(tuple(self.fixture.registry), packets.CENTRAL_FREEZE_KEY_ORDER)
        self.assertNotIn("review_classification_contract", self.fixture.registry)
        packets._validate_freeze_catalogs(self.fixture.registry, self.fixture.overlay)
        for field, value in (
            ("requirement_catalog", ["CH-T002-N02"]),
            (
                "test_catalog",
                [packets.CLASSIFICATION_CONTROL_ACCEPTED_TEST_ID, "test_unfrozen"],
            ),
        ):
            overlay = json.loads(json.dumps(self.fixture.overlay))
            overlay["scope"][field] = value
            with self.subTest(field=field), self.assertRaises(packets.PacketError):
                packets._validate_freeze_catalogs(self.fixture.registry, overlay)

        registry = json.loads(json.dumps(self.fixture.registry))
        registry["normative_controls"][0], registry["normative_controls"][1] = (
            registry["normative_controls"][1],
            registry["normative_controls"][0],
        )
        with self.assertRaisesRegex(packets.PacketError, "ordered N01-N20"):
            packets._validate_freeze_catalogs(registry, self.fixture.overlay)

        registry = json.loads(json.dumps(self.fixture.registry))
        registry["qualification_evidence_requirements"].pop()
        with self.assertRaisesRegex(packets.PacketError, "E01 through E13"):
            packets._validate_freeze_catalogs(registry, self.fixture.overlay)

        registry = json.loads(json.dumps(self.fixture.registry))
        registry["normative_controls"][0]["accepted_test_id"] = "test_n01_alternate"
        with self.assertRaisesRegex(packets.PacketError, "row test binding"):
            packets._validate_freeze_catalogs(registry, self.fixture.overlay)

        for mutation in ("extra_key", "statement", "accepted_test"):
            registry = json.loads(json.dumps(self.fixture.registry))
            if mutation == "extra_key":
                registry["review_classification_contract"] = {}
                expected = "exact frozen key order"
            else:
                control = next(
                    item
                    for item in registry["normative_controls"]
                    if item["id"] == packets.CLASSIFICATION_CONTROL_ID
                )
                if mutation == "statement":
                    control["statement"] += " drift"
                    expected = "control statement"
                else:
                    control["accepted_test_id"] = "test_unfrozen"
                    expected = "accepted test"
            with (
                self.subTest(mutation=mutation),
                self.assertRaisesRegex(packets.PacketError, expected),
            ):
                packets._validate_freeze_catalogs(registry, self.fixture.overlay)

    def test_base_partition_is_pinned_to_exact_ch_t001_identity(self) -> None:
        for field, value in (
            ("commit", "0" * 40),
            ("tree", "1" * 40),
            ("ledger_blob_id", "2" * 40),
            ("ledger_sha256", "3" * 64),
            ("ledger_rows", self.fixture.overlay["base_partition"]["ledger_rows"] + 1),
        ):
            overlay = json.loads(json.dumps(self.fixture.overlay))
            overlay["base_partition"][field] = value
            with (
                self.subTest(field=field),
                self.assertRaisesRegex(
                    packets.PacketError, f"base {field.split('_')[0]}"
                ),
            ):
                packets._validate_overlay_structure(overlay)

    def test_completion_time_must_be_a_real_calendar_date(self) -> None:
        rows = [dict(row) for row in self.fixture.completed_rows]
        rows[0]["completed_at"] = "2026-02-31T00:00:00Z"
        with self.assertRaisesRegex(packets.PacketError, "impossible completion date"):
            packets._validate_completed_ledger(
                rows,
                self.fixture.original_rows,
                self.fixture.overlay,
                self.fixture.classification_by_path,
            )

    def test_known_generated_classification_and_generator_are_immutable(self) -> None:
        for field, value in (("generated", "NO"), ("generator", "unknown")):
            rows = [dict(row) for row in self.fixture.completed_rows]
            target = next(row for row in rows if row["path"] == "src/alpha.py")
            target[field] = value
            with (
                self.subTest(field=field),
                self.assertRaisesRegex(
                    packets.PacketError, "frozen generated classification"
                ),
            ):
                packets._validate_completed_ledger(
                    rows,
                    self.fixture.original_rows,
                    self.fixture.overlay,
                    self.fixture.classification_by_path,
                )

    def test_unknown_evidence_pointer_is_rejected(self) -> None:
        rows = [dict(row) for row in self.fixture.completed_rows]
        target = next(row for row in rows if row["path"] == "src/critical.md")
        target["provenance_evidence"] = "CH-T002-E99"
        with self.assertRaisesRegex(packets.PacketError, "subject-qualified"):
            packets._validate_completed_ledger(
                rows,
                self.fixture.original_rows,
                self.fixture.overlay,
                self.fixture.classification_by_path,
            )

    def test_assumption_and_defect_prose_must_resolve_through_catalogs(self) -> None:
        for field, value, expected in (
            ("assumptions", "free prose", "absent from the frozen catalog"),
            ("defects", "unknown", "recorded defect"),
        ):
            rows = [dict(row) for row in self.fixture.completed_rows]
            rows[0][field] = value
            with (
                self.subTest(field=field),
                self.assertRaisesRegex(
                    packets.PacketError, expected
                ),
            ):
                packets._validate_completed_ledger(
                    rows,
                    self.fixture.original_rows,
                    self.fixture.overlay,
                    self.fixture.classification_by_path,
                )
        rows = [dict(row) for row in self.fixture.completed_rows]
        rows[0]["assumptions"] = packets.CLASSIFICATION_CONTROL_ID
        rows[0]["defects"] = "NONE"
        packets._validate_completed_ledger(
            rows,
            self.fixture.original_rows,
            self.fixture.overlay,
            self.fixture.classification_by_path,
        )

    def test_live_license_expression_and_not_applicable_are_exact(
        self,
    ) -> None:
        not_applicable = next(
            row for row in self.fixture.completed_rows if row["path"] == "src/empty.txt"
        )
        self.assertEqual(not_applicable["license_review_status"], "NOT_APPLICABLE")
        self.assertEqual(not_applicable["license_expression"], "NOT_APPLICABLE")
        self.assertEqual(not_applicable["license_evidence"], "")
        packets._validate_completed_ledger(
            self.fixture.completed_rows,
            self.fixture.original_rows,
            self.fixture.overlay,
            self.fixture.classification_by_path,
        )
        rows = [dict(row) for row in self.fixture.completed_rows]
        live = next(row for row in rows if row["path"] == "src/critical.md")
        live["license_expression"] = "MIT"
        with self.assertRaisesRegex(packets.PacketError, "F classification"):
            packets._validate_completed_ledger(
                rows,
                self.fixture.original_rows,
                self.fixture.overlay,
                self.fixture.classification_by_path,
            )
        rows = [dict(row) for row in self.fixture.completed_rows]
        live = next(row for row in rows if row["path"] == "src/critical.md")
        live["license_review_status"] = "NOT_APPLICABLE"
        live["license_expression"] = "NOT_APPLICABLE"
        live["license_evidence"] = ""
        with self.assertRaisesRegex(packets.PacketError, "F classification"):
            packets._validate_completed_ledger(
                rows,
                self.fixture.original_rows,
                self.fixture.overlay,
                self.fixture.classification_by_path,
            )
        rows = [dict(row) for row in self.fixture.completed_rows]
        live = next(row for row in rows if row["path"] == "src/empty.txt")
        live["license_review_status"] = "APPROVED"
        live["license_expression"] = "Apache-2.0 OR MIT"
        subject = next(
            item for item in self.prepared.subjects if item.path == live["path"]
        )
        live["license_evidence"] = f"CH-T002-E09#{subject.subject_id}:LICENSE"
        with self.assertRaisesRegex(packets.PacketError, "F classification"):
            packets._validate_completed_ledger(
                rows,
                self.fixture.original_rows,
                self.fixture.overlay,
                self.fixture.classification_by_path,
            )
        rows = [dict(row) for row in self.fixture.completed_rows]
        live = next(row for row in rows if row["path"] == "assets/blob.bin")
        live["license_review_status"] = "NOT_APPLICABLE"
        live["license_expression"] = "NOT_APPLICABLE"
        live["license_evidence"] = ""
        with self.assertRaisesRegex(packets.PacketError, "F classification"):
            packets._validate_completed_ledger(
                rows,
                self.fixture.original_rows,
                self.fixture.overlay,
                self.fixture.classification_by_path,
            )

    def test_immutable_ledger_field_change_is_rejected(self) -> None:
        rows = [dict(row) for row in self.fixture.completed_rows]
        rows[0]["current_sha256"] = "f" * 64
        with self.assertRaisesRegex(packets.PacketError, "immutable"):
            packets._validate_completed_ledger(
                rows,
                self.fixture.original_rows,
                self.fixture.overlay,
                self.fixture.classification_by_path,
            )

    def test_overlay_count_digest_and_delta_tampering_are_rejected(self) -> None:
        prepared = self.prepared
        for mutation in ("count", "digest"):
            overlay = json.loads(json.dumps(self.fixture.overlay))
            if mutation == "count":
                overlay["counts"]["review_subjects"] += 1
            else:
                overlay["digests"]["subject_set_sha256"] = "f" * 64
            with (
                self.subTest(mutation=mutation),
                self.assertRaises(packets.PacketError),
            ):
                packets._verify_overlay_digests_and_counts(overlay, prepared.subjects)

    def test_overlay_epoch_rejects_boolean_integer_alias(self) -> None:
        overlay = json.loads(json.dumps(self.fixture.overlay))
        overlay["epoch"] = True
        with self.assertRaisesRegex(packets.PacketError, "overlay epoch"):
            packets._validate_overlay_structure(overlay)

    def test_registry_reused_key_and_wrong_lane_classification_are_rejected(
        self,
    ) -> None:
        for mutation in ("key", "classification"):
            registry = json.loads(json.dumps(self.fixture.registry))
            if mutation == "key":
                registry["reviewer_registry"][1]["public_key"] = registry[
                    "reviewer_registry"
                ][0]["public_key"]
                registry["reviewer_registry"][1]["key_fingerprint"] = registry[
                    "reviewer_registry"
                ][0]["key_fingerprint"]
            else:
                registry["reviewer_registry"][0]["reviewer"]["classification"] = (
                    "AUTOMATED_LEAD_SUPPORT"
                )
            with (
                self.subTest(mutation=mutation),
                self.assertRaises(packets.PacketError),
            ):
                packets._reviewers_from_registry(registry, self.fixture.overlay)

    def test_registry_rejects_base64_that_is_not_an_ed25519_wire_key(self) -> None:
        registry = json.loads(json.dumps(self.fixture.registry))
        malformed = base64.b64encode(b"not-an-ssh-wire-key").decode("ascii")
        registry["reviewer_registry"][0]["public_key"] = f"ssh-ed25519 {malformed}"
        with self.assertRaisesRegex(packets.PacketError, "wire length"):
            packets._reviewers_from_registry(registry, self.fixture.overlay)

    def test_overlay_rejects_non_resolvable_catalog_and_malformed_values(
        self,
    ) -> None:
        for mutation in ("catalog", "criticality", "mode"):
            overlay = json.loads(json.dumps(self.fixture.overlay))
            if mutation == "catalog":
                overlay["scope"]["test_catalog"] = ["free prose"]
            elif mutation == "criticality":
                overlay["entries"][0]["criticality"] = [{}]
            else:
                overlay["entries"][0]["git_mode"] = {}
            with (
                self.subTest(mutation=mutation),
                self.assertRaises(packets.PacketError),
            ):
                packets._validate_overlay_structure(overlay)

    def test_mandatory_path_criticality_floor_applies_to_rows_and_overlay(self) -> None:
        rows = [dict(row) for row in self.fixture.completed_rows]
        tool = next(row for row in rows if row["path"] == packets.LEDGER_GENERATOR_PATH)
        tool["security_critical"] = "NO"
        with self.assertRaisesRegex(packets.PacketError, "mandatory path floor"):
            packets._validate_completed_ledger(
                rows,
                self.fixture.original_rows,
                self.fixture.overlay,
                self.fixture.classification_by_path,
            )
        overlay = json.loads(json.dumps(self.fixture.overlay))
        docs = next(
            entry for entry in overlay["entries"] if entry["path"] == "docs/new.txt"
        )
        docs["criticality"] = []
        with self.assertRaisesRegex(packets.PacketError, "mandatory path floor"):
            packets._validate_overlay_structure(overlay)

    def test_test_fixture_authority_floor_exception_is_exact(self) -> None:
        self.assertEqual(
            packets.TEST_ONLY_AUTHORITY_FLOOR_EXCEPTION,
            "tools/release/current_audit_test_fixtures.py",
        )
        self.assertEqual(
            packets._required_criticality(packets.TEST_ONLY_AUTHORITY_FLOOR_EXCEPTION),
            frozenset({"SECURITY_CRITICAL"}),
        )
        for path in (
            "tools/release/current-audit-test-fixtures.py",
            "tools/release/current_audit_test_fixture.py",
            "tools/release/current_audit_test_fixtures.py.backup",
            "tools/release/current_audit_test_fixtures.py/subpath",
            "tools/release/test_current_audit_test_fixtures.py",
        ):
            with self.subTest(path=path):
                self.assertEqual(
                    packets._required_criticality(path),
                    frozenset({"SECURITY_CRITICAL", "AUTHORITY_CRITICAL"}),
                )

    def test_supplemental_language_and_content_are_derived_from_git(self) -> None:
        overlay = json.loads(json.dumps(self.fixture.overlay))
        docs = next(
            entry for entry in overlay["entries"] if entry["path"] == "docs/new.txt"
        )
        docs["language"] = "JSON"
        with self.assertRaisesRegex(packets.PacketError, "repository path"):
            packets._validate_overlay_structure(overlay)
        subject = next(
            subject
            for subject in self.prepared.subjects
            if subject.path == "docs/new.txt"
        )
        contradictory = replace(subject, content_kind="BINARY", lines=None)
        with (
            mock.patch.object(
                packets,
                "_blob_at",
                return_value=(
                    subject.git_mode,
                    subject.git_object_id,
                    b"new evidence scope\n",
                ),
            ),
            self.assertRaisesRegex(packets.PacketError, "classification"),
        ):
            packets._verify_subject_blob(
                self.fixture.repo, self.fixture.freeze, contradictory
            )

    def test_wrong_ledger_reviewer_for_unchanged_subject_is_rejected(self) -> None:
        prepared = self.prepared
        rows = [dict(row) for row in self.fixture.completed_rows]
        target = next(row for row in rows if row["path"] == "src/critical.md")
        current = target["reviewer"]
        target["reviewer"] = next(
            reviewer.principal
            for reviewer in prepared.reviewers
            if reviewer.principal != current
        )
        with self.assertRaisesRegex(packets.PacketError, "primary assignment"):
            packets._validate_ledger_reviewer_assignments(
                rows, prepared.lanes, self.fixture.overlay
            )

    def test_supplemental_modified_assignment_is_not_skipped(self) -> None:
        rows = [dict(row) for row in self.fixture.completed_rows]
        target = next(row for row in rows if row["path"] == "src/alpha.py")
        target["reviewer"] = next(
            reviewer.principal
            for reviewer in self.prepared.reviewers
            if reviewer.principal != target["reviewer"]
        )
        with self.assertRaisesRegex(packets.PacketError, "primary assignment"):
            packets._validate_ledger_reviewer_assignments(
                rows, self.prepared.lanes, self.fixture.overlay
            )

    def test_no_removals_catalog_and_git_delta_are_exact(self) -> None:
        overlay = json.loads(json.dumps(self.fixture.overlay))
        overlay["removed_paths"] = [{"path": "assets/blob.bin"}]
        with self.assertRaisesRegex(packets.PacketError, "no-removals"):
            packets._validate_overlay_structure(overlay)

        raw, statuses = packets._diff_name_status(
            self.fixture.repo, self.fixture.base, self.fixture.freeze
        )
        self.assertTrue(raw)
        statuses["assets/blob.bin"] = "D"
        with self.assertRaisesRegex(packets.PacketError, "forbidden removal"):
            packets._build_subjects(
                self.fixture.repo,
                self.fixture.completed_rows,
                self.fixture.overlay,
                packets._tree_entries(self.fixture.repo, self.fixture.freeze),
                statuses,
            )

        self.assertEqual(self.fixture.overlay["removed_paths"], [])
        self.assertEqual(self.fixture.overlay["counts"]["removed_paths"], 0)
        self.assertEqual(
            self.fixture.overlay["digests"]["removed_path_set_sha256"],
            packets._domain_digest(
                packets.SCHEMA["digest_domains"]["removed_path_set"], []
            ),
        )

    def test_ledger_evidence_requires_exact_primary_and_secondary_fragments(
        self,
    ) -> None:
        rows = [dict(row) for row in self.fixture.completed_rows]
        target = next(row for row in rows if row["path"] == "src/critical.md")
        target["evidence"] = "CH-T002-E09"
        with self.assertRaisesRegex(packets.PacketError, "exact primary/secondary"):
            packets._validate_ledger_reviewer_assignments(
                rows, self.prepared.lanes, self.fixture.overlay
            )

    def test_lane_evidence_roles_are_typed_and_exact(self) -> None:
        rows = [dict(row) for row in self.fixture.completed_rows]
        target = next(row for row in rows if row["path"] == "src/alpha.py")
        tokens = target["evidence"].split(";")
        subject = next(
            item for item in self.prepared.subjects if item.path == target["path"]
        )
        primary = next(lane for lane in self.prepared.lanes if subject in lane.primary)
        exact = f"CH-T002-E{9 + primary.number:02d}#{subject.subject_id}:PRIMARY"
        wrong_lane = primary.number % 3 + 1
        tokens[tokens.index(exact)] = (
            f"CH-T002-E{9 + wrong_lane:02d}#{subject.subject_id}:PRIMARY"
        )
        target["evidence"] = ";".join(
            sorted(tokens, key=lambda item: item.encode("utf-8"))
        )
        with self.assertRaisesRegex(packets.PacketError, "exact primary/secondary"):
            packets._validate_ledger_reviewer_assignments(
                rows, self.prepared.lanes, self.fixture.overlay
            )

        for evidence_id, role in (
            ("CH-T002-E10", "PROVENANCE"),
            ("CH-T002-E11", "LICENSE"),
        ):
            rows = [dict(row) for row in self.fixture.completed_rows]
            target = next(row for row in rows if row["path"] == "assets/blob.bin")
            target_subject = next(
                item for item in self.prepared.subjects if item.path == target["path"]
            )
            target["assumptions"] = f"{evidence_id}#{target_subject.subject_id}:{role}"
            with (
                self.subTest(evidence_id=evidence_id, role=role),
                self.assertRaisesRegex(
                    packets.PacketError, "absent from the frozen catalog"
                ),
            ):
                packets._validate_completed_ledger(
                    rows,
                    self.fixture.original_rows,
                    self.fixture.overlay,
                    self.fixture.classification_by_path,
                )

    def test_packet_retained_file_cap_is_hard(self) -> None:
        prepared = self.prepared
        outputs = packets.build_outputs(prepared)
        largest = max(len(value) for value in outputs.values())
        with mock.patch.object(packets, "MAX_PACKET_BYTES", largest + 1):
            self.assertEqual(packets.build_outputs(prepared), outputs)
        with (
            mock.patch.object(packets, "MAX_PACKET_BYTES", largest),
            self.assertRaisesRegex(packets.PacketError, "byte bound|byte cap"),
        ):
            packets.build_outputs(prepared)
        with (
            mock.patch.object(packets, "MAX_PACKET_BYTES", 512),
            self.assertRaisesRegex(packets.PacketError, "byte bound"),
        ):
            packets.build_outputs(prepared)

    def test_noncanonical_overlay_and_csv_are_rejected(self) -> None:
        spaced = json.dumps(self.fixture.overlay, sort_keys=True).encode() + b"\n"
        with self.assertRaisesRegex(packets.PacketError, "canonical"):
            packets._parse_canonical_json(spaced, label="overlay")
        with self.assertRaisesRegex(packets.PacketError, "LF-only"):
            packets._parse_ledger(
                self.fixture.completed_ledger.replace(b"\n", b"\r\n"),
                label="ledger",
            )

    def test_verify_rejects_extra_symlink_and_hardlink_entries(self) -> None:
        for mutation in ("extra", "symlink", "hardlink"):
            outputs = packets.build_outputs(self.prepared)
            parent = self.root / f"{self._testMethodName}-{mutation}"
            parent.mkdir()
            target = parent / "packets"
            with mock.patch.object(packets.os, "fsync", return_value=None):
                packets.publish_outputs(target, outputs)
            lane = target / "review-lane-01.json"
            if mutation == "extra":
                (target / "extra.json").write_bytes(b"{}\n")
            elif mutation == "symlink":
                lane.unlink()
                os.symlink("review-lane-02.json", lane)
            else:
                lane.unlink()
                os.link(target / "review-lane-02.json", lane)
            with (
                self.subTest(mutation=mutation),
                self.assertRaises(packets.PacketError),
            ):
                packets.verify_outputs(target, outputs)

    def test_exported_schema_matches_all_rendered_key_sets(self) -> None:
        outputs = packets.build_outputs(self.prepared)
        packet = json.loads(outputs["review-lane-01.json"])
        manifest = json.loads(outputs["file-review-packet-manifest.json"])
        contract = self.fixture.overlay["review_classification_contract"]
        self.assertEqual(
            set(self.fixture.overlay), set(packets.SCHEMA["overlay"]["top"])
        )
        self.assertEqual(
            set(self.fixture.overlay["entries"][0]),
            set(packets.SCHEMA["overlay"]["entry"]),
        )
        self.assertEqual(
            tuple(contract), packets.SCHEMA["classification_contract"]["top"]
        )
        self.assertEqual(
            tuple(contract["source_audit"]),
            packets.SCHEMA["classification_contract"]["source_audit"],
        )
        self.assertEqual(
            tuple(contract["override_policy"]),
            packets.SCHEMA["classification_contract"]["override_policy"],
        )
        self.assertEqual(
            tuple(contract["counts"]),
            packets.SCHEMA["classification_contract"]["count_sets"],
        )
        self.assertEqual(
            tuple(contract["counts"]["source_current_a"]),
            packets.SCHEMA["classification_contract"]["count_vector"],
        )
        override = contract["override_policy"]["overrides"][0]
        self.assertEqual(
            tuple(override),
            packets.SCHEMA["classification_contract"]["override_record"],
        )
        self.assertEqual(
            tuple(contract["semantics"]),
            packets.SCHEMA["classification_contract"]["semantics"],
        )
        self.assertEqual(
            tuple(contract["records"][0]),
            packets.SCHEMA["classification_contract"]["record"],
        )
        self.assertEqual(set(packet), set(packets.SCHEMA["packet"]["top"]))
        self.assertEqual(
            set(packet["assignment"]),
            set(packets.SCHEMA["packet"]["assignment"]),
        )
        subject = (
            packet["assignment"]["primary_entries"]
            or packet["assignment"]["secondary_entries"]
        )[0]
        self.assertEqual(set(subject), set(packets.SCHEMA["packet"]["subject"]))
        self.assertEqual(
            set(subject["coverage"]), set(packets.SCHEMA["packet"]["coverage"])
        )
        self.assertEqual(set(manifest), set(packets.SCHEMA["manifest"]["top"]))
        self.assertEqual(
            set(manifest["lane_packets"][0]),
            set(packets.SCHEMA["manifest"]["lane"]),
        )
        self.assertEqual(
            set(manifest["overlay_reconciliation"]),
            set(packets.SCHEMA["manifest"]["overlay_reconciliation"]),
        )
        self.assertEqual(self.fixture.overlay["removed_paths"], [])
        self.assertNotIn("removed_path", packets.SCHEMA["overlay"])
        self.assertNotIn("removed_assignment", packets.SCHEMA["overlay"])

    def test_extra_implementation_path_is_rejected(self) -> None:
        statuses = {
            item["path"]: item["status"] for item in packets.IMPLEMENTATION_PLAN
        }
        statuses["unexpected.txt"] = "A"
        with self.assertRaisesRegex(packets.PacketError, "exact four-path diff"):
            packets._validate_implementation_statuses(statuses)

    def test_wrong_argument_paths_are_rejected(self) -> None:
        with self.assertRaisesRegex(packets.PacketError, "frozen repository path"):
            packets._prepare_inputs(
                repo_argument=self.fixture.repo,
                implementation_commit_argument=self.fixture.implementation,
                ledger_argument=self.fixture.repo / packets.OVERLAY_PATH,
                overlay_argument=self.fixture.repo / packets.OVERLAY_PATH,
                registry_argument=self.fixture.repo / REGISTRY_PATH,
            )


if __name__ == "__main__":
    unittest.main()
