#!/usr/bin/env python3
"""Adversarial tests for the current-head audit-cut verifier."""

from __future__ import annotations

import copy
import gzip
import hashlib
import importlib.util
import json
import os
import signal
import sys
import tempfile
import threading
import time
import unittest
import zipfile
from pathlib import Path
from unittest import mock


MODULE_PATH = Path(__file__).with_name("verify-current-audit.py")
SPEC = importlib.util.spec_from_file_location("verify_current_audit", MODULE_PATH)
if SPEC is None or SPEC.loader is None:  # pragma: no cover - import guard
    raise RuntimeError("unable to load current-audit verifier")
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)

FIXTURE_PATH = Path(__file__).with_name("current_audit_test_fixtures.py")
FIXTURE_SPEC = importlib.util.spec_from_file_location(
    "current_audit_test_fixtures", FIXTURE_PATH
)
if FIXTURE_SPEC is None or FIXTURE_SPEC.loader is None:  # pragma: no cover
    raise RuntimeError("unable to load current-audit test fixtures")
FIXTURES = importlib.util.module_from_spec(FIXTURE_SPEC)
sys.modules[FIXTURE_SPEC.name] = FIXTURES
FIXTURE_SPEC.loader.exec_module(FIXTURES)


class CurrentAuditVerifierTests(unittest.TestCase):
    """Prove fail-closed behavior for identity and evidence mutations."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.repo = Path(__file__).resolve().parents[2]
        cls.manifest_path = cls.repo / "release/0.9.0/current-head/audit-inputs.json"
        cls.manifest = json.loads(cls.manifest_path.read_text(encoding="utf-8"))

    def write_manifest(self, value: object, directory: str) -> Path:
        path = Path(directory) / "audit-inputs.json"
        path.write_text(
            json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        return path

    def assert_rejected(self, value: object) -> None:
        with tempfile.TemporaryDirectory(
            prefix=".current-audit-test-", dir=self.repo
        ) as directory:
            path = self.write_manifest(value, directory)
            with self.assertRaises(VERIFY.CurrentAuditError):
                VERIFY.verify(path, self.repo)

    def assert_raw_rejected(self, payload: str | bytes) -> None:
        with tempfile.TemporaryDirectory(
            prefix=".current-audit-test-", dir=self.repo
        ) as directory:
            path = Path(directory) / "audit-inputs.json"
            if isinstance(payload, str):
                path.write_text(payload, encoding="utf-8")
            else:
                path.write_bytes(payload)
            with self.assertRaises(VERIFY.CurrentAuditError):
                VERIFY.verify(path, self.repo)

    def run_container_probe(
        self, payload: str, *, label: str
    ) -> tuple[int, bytes, bytes]:
        with tempfile.TemporaryDirectory(
            prefix="haldir-container-test-", dir=self.repo.parent
        ) as raw:
            root = Path(raw)
            snapshot = root / "snapshot"
            snapshot.mkdir(mode=0o700)
            probe = snapshot / "probe.py"
            probe.write_text(payload, encoding="utf-8")
            runner = root / "registered-test-runner.py"
            runner.write_bytes(VERIFY._registered_test_runner_payload())
            runner.chmod(0o444)
            VERIFY._make_snapshot_world_readable(snapshot)
            return VERIFY._run_registered_container(
                root, snapshot, command=["/repo/probe.py"], label=label
            )

    def qualification_documents(self) -> tuple[dict[str, object], dict[str, object]]:
        framework_commit = "1" * 40
        review = VERIFY.ch_t000_review_fixed_template(framework_commit)
        review["review_started_at_utc"] = "2026-07-14T18:00:00Z"
        review["review_completed_at_utc"] = "2026-07-14T18:30:00Z"
        review["evidence_catalog"] = {}
        review_payload = (json.dumps(review, indent=2, sort_keys=True) + "\n").encode(
            "utf-8"
        )
        qualification: dict[str, object] = {
            "schema_version": "2.0.0",
            "qualified_implementation": {
                "commit": VERIFY.IMPLEMENTATION_COMMIT,
                "tree": VERIFY.IMPLEMENTATION_TREE,
                "parent": VERIFY.SOURCE_COMMIT,
                "diff": {"patch_sha256": "1" * 64},
                "signature": copy.deepcopy(VERIFY.SOURCE_SIGNATURE),
            },
            "evidence_files": [
                {
                    "path": "release/0.9.0/current-head/evidence/synthetic.json",
                    "sha256": "2" * 64,
                    "bytes": 2,
                    "lines": 1,
                }
            ],
            "review_record": {
                **VERIFY._payload_file_record(VERIFY.REVIEW_PATH, review_payload),
                "classification": "AUTOMATED_TECHNICAL_SUPPORT_ONLY",
                "reviewer_ids": ["CH-T000-R01", "CH-T000-R02", "CH-T000-R03"],
            },
            "decision": {
                "current_ledger_status": "OPEN",
                "release_status_after_activation": "NO_GO",
            },
        }
        return qualification, review

    def verify_qualification_documents(
        self,
        qualification: dict[str, object],
        review: dict[str, object],
        *,
        signature_failure: bool = False,
    ) -> tuple[dict[str, object], dict[str, object]]:
        framework_commit = "1" * 40
        qualification_commit = "2" * 40
        expected_qualification, expected_review = self.qualification_documents()
        review_payload = (json.dumps(review, indent=2, sort_keys=True) + "\n").encode(
            "utf-8"
        )
        qualification_payload = (
            json.dumps(qualification, indent=2, sort_keys=True) + "\n"
        ).encode("utf-8")

        def read_commit_json(
            _repo: Path, _commit: str, path: str, _label: str
        ) -> tuple[dict[str, object], bytes]:
            if path == VERIFY.QUALIFICATION_PATH:
                return copy.deepcopy(qualification), qualification_payload
            if path == VERIFY.REVIEW_PATH:
                return copy.deepcopy(review), review_payload
            raise AssertionError(path)

        framework_time = VERIFY.datetime.fromisoformat("2026-07-14T17:00:00+00:00")
        qualification_time = VERIFY.datetime.fromisoformat("2026-07-14T19:00:00+00:00")

        def commit_datetime(_repo: Path, commit: str) -> object:
            return framework_time if commit == framework_commit else qualification_time

        def verify_signature(*_args: object, **_kwargs: object) -> None:
            if signature_failure:
                raise VERIFY.CurrentAuditError("CURRENT_AUDIT_TEST_SIGNATURE")

        with (
            mock.patch.object(
                VERIFY, "_read_commit_json", side_effect=read_commit_json
            ),
            mock.patch.object(
                VERIFY,
                "_qualification_expected_v2",
                return_value=copy.deepcopy(expected_qualification),
            ),
            mock.patch.object(VERIFY, "_commit_datetime", side_effect=commit_datetime),
            mock.patch.object(VERIFY, "_verify_evidence_catalog_v2"),
            mock.patch.object(
                VERIFY, "_verify_named_commit_signature", side_effect=verify_signature
            ),
        ):
            observed = VERIFY._verify_ch_t000_qualification_v2(
                self.repo, framework_commit, qualification_commit
            )
        self.assertEqual(expected_review["schema_version"], "2.0.0")
        return observed

    def assert_qualification_rejected(
        self, overrides: dict[str, dict[str, object]]
    ) -> None:
        qualification, review = self.qualification_documents()
        qualification = copy.deepcopy(
            overrides.get("ch_t000.qualification", qualification)
        )
        review = copy.deepcopy(overrides.get("ch_t000.review", review))
        with self.assertRaises(VERIFY.CurrentAuditError):
            self.verify_qualification_documents(qualification, review)

    @staticmethod
    def deterministic_gzip(payload: bytes) -> bytes:
        compressed = bytearray(gzip.compress(payload, compresslevel=9, mtime=0))
        compressed[9] = 3
        return bytes(compressed)

    @staticmethod
    def preimplementation_schema_fixture() -> dict[str, object]:
        attacks = []
        for index, statement in enumerate(VERIFY.HANDOFF_COMBINED_ATTACKS, start=1):
            applicable = index == 1
            attacks.append(
                {
                    "id": f"CH-T001-CA{index:02d}",
                    "statement": statement,
                    "disposition": "APPLICABLE" if applicable else "NOT_APPLICABLE",
                    "rationale": "Bound to the exact T001 creation-only scope.",
                    "falsifier": (
                        None
                        if applicable
                        else "Becomes applicable if T001 obtains this interaction."
                    ),
                    "control_ids": ["CH-T001-N01"],
                    "evidence_ids": ["CH-T001-E01"],
                    "accepted_test_id": "test_accept" if applicable else None,
                    "rejected_test_id": "test_reject" if applicable else None,
                }
            )
        commands = [
            {
                "id": "HC01",
                "source_command": VERIFY.HANDOFF_REQUIRED_COMMANDS[0],
                "disposition": "SATISFIED_BY_RETAINED_SIGNED_ARTIFACT",
                "replacement_commands": [
                    "python3 tools/release/verify-current-audit.py --repo ."
                ],
                "evidence_ids": ["CH-T001-E01"],
                "task_boundary": "CH-T000",
                "rationale": "The signed updated audit cut supersedes the stale source hash.",
            },
            {
                "id": "HC02",
                "source_command": VERIFY.HANDOFF_REQUIRED_COMMANDS[1],
                "disposition": "SUPERSEDED_BY_STRONGER_BOUND_EQUIVALENT",
                "replacement_commands": [
                    "python3 tools/release/current-file-review-ledger.py generate --repo ."
                ],
                "evidence_ids": ["CH-T001-E01"],
                "task_boundary": "CH-T001",
                "rationale": "The replacement reconciles Git and physical views.",
            },
            {
                "id": "HC03",
                "source_command": VERIFY.HANDOFF_REQUIRED_COMMANDS[2],
                "disposition": "DEFERRED_TO_NAMED_SUCCESSOR_TASK",
                "replacement_commands": [],
                "evidence_ids": [],
                "task_boundary": "CH-T002",
                "rationale": "T002 owns reviewer assignment and packet construction.",
            },
            {
                "id": "HC04",
                "source_command": VERIFY.HANDOFF_REQUIRED_COMMANDS[3],
                "disposition": "DEFERRED_TO_NAMED_SUCCESSOR_TASK",
                "replacement_commands": [],
                "evidence_ids": [],
                "task_boundary": "CH-T003",
                "rationale": "The named claim-language task owns this scan.",
            },
        ]
        threats = [
            {
                "threat_id": "CH-T001-TH01",
                "asset_or_claim": "create-once ledger identity",
                "actor": "concurrent local writer",
                "preconditions": "write access to the repository",
                "sequence": "race publication after candidate construction",
                "trust_boundary": "repository namespace",
                "observable_symptoms": "atomic no-replace conflict",
                "worst_consequence": "generation fails closed",
                "preventive_controls": ["CH-T001-N01"],
                "detective_controls": ["CH-T001-N01"],
                "recovery": "verify the surviving target explicitly",
                "tests": ["test_reject"],
                "evidence": ["CH-T001-E01"],
                "residual_risk": "same-UID namespace mutation remains possible",
                "claim_impact": "no rollback guarantee is claimed",
                "owner": "CH-T001",
            }
        ]
        interfaces = [
            {
                "id": "CH-T001-MI01",
                "surface": "current-file-review-ledger generate CLI",
                "disposition": "APPLICABLE",
                "justification": "The operator-facing creation command can be misused.",
                "falsifier": None,
                "correct_example": "generate into an absent canonical target",
                "wrong_example": "generate over an existing target",
                "exact_refusal_or_error": "CURRENT_FILE_REVIEW_LEDGER_TARGET_EXISTS",
                "non_proofs": ["successful creation is not file review"],
                "evidence_tier": "repository-local technical verification",
                "evidence_ids": ["CH-T001-E01"],
                "invariant_ids": ["CH-T001-N01"],
                "test_ids": ["test_reject"],
            },
            {
                "id": "CH-T001-MI02",
                "surface": "runtime API",
                "disposition": "NOT_APPLICABLE",
                "justification": "T001 adds no runtime API.",
                "falsifier": "A runtime-callable T001 surface is added.",
                "correct_example": None,
                "wrong_example": None,
                "exact_refusal_or_error": None,
                "non_proofs": [],
                "evidence_tier": None,
                "evidence_ids": [],
                "invariant_ids": [],
                "test_ids": [],
            },
        ]
        return {
            "attacks": attacks,
            "commands": commands,
            "threats": threats,
            "interfaces": interfaces,
        }

    @staticmethod
    def nested_jobs_document() -> dict[str, object]:
        return {
            "jobs": [
                {
                    "completedAt": "2026-07-14T18:01:00Z",
                    "conclusion": "success",
                    "databaseId": 1,
                    "name": "synthetic",
                    "startedAt": "2026-07-14T18:00:00Z",
                    "status": "completed",
                    "steps": [
                        {
                            "completedAt": "2026-07-14T18:01:00Z",
                            "conclusion": "success",
                            "name": "synthetic step",
                            "number": 1,
                            "startedAt": "2026-07-14T18:00:00Z",
                            "status": "completed",
                        }
                    ],
                    "url": "https://example.invalid/job/1",
                }
            ]
        }

    def assert_gate_file_rejected(
        self,
        path: str,
        *,
        payload: bytes | None = None,
        mode: str | None = None,
        dirty_worktree: bool = False,
    ) -> None:
        head = VERIFY._git(self.repo, "rev-parse", "HEAD").decode("ascii").strip()
        original_git_file = VERIFY._git_file
        original_tree_entry = VERIFY._git_tree_entry
        original_read = VERIFY._read_repo_relative_bounded
        committed_payload = original_git_file(self.repo, head, path)
        replacement = payload if payload is not None else committed_payload

        def git_file(repo: Path, commit: str, candidate: str) -> bytes:
            if commit == head and candidate == path:
                return replacement
            return original_git_file(repo, commit, candidate)

        def tree_entry(
            repo: Path, commit: str, candidate: str
        ) -> dict[str, str] | None:
            entry = original_tree_entry(repo, commit, candidate)
            if commit == head and candidate == path and mode is not None:
                if entry is None:
                    raise AssertionError(candidate)
                entry = dict(entry)
                entry["mode"] = mode
            return entry

        def read_repo(repo: Path, candidate: str, limit: int, label: str) -> bytes:
            if candidate == path:
                return (
                    committed_payload + b"\n# dirty\n"
                    if dirty_worktree
                    else replacement
                )
            return original_read(repo, candidate, limit, label)

        with (
            mock.patch.object(VERIFY, "_git_file", side_effect=git_file),
            mock.patch.object(VERIFY, "_git_tree_entry", side_effect=tree_entry),
            mock.patch.object(
                VERIFY, "_read_repo_relative_bounded", side_effect=read_repo
            ),
            self.assertRaises(VERIFY.CurrentAuditError),
        ):
            VERIFY._verify_post_activation_gate_retention(self.repo, head)

    def test_exact_manifest_verifies(self) -> None:
        self.assertIsNone(VERIFY.verify(self.manifest_path, self.repo))

    def test_duplicate_json_key_is_rejected(self) -> None:
        payload = self.manifest_path.read_text(encoding="utf-8")
        duplicate = payload.replace("{\n", '{\n  "schema_version": "duplicate",\n', 1)
        with tempfile.TemporaryDirectory(
            prefix=".current-audit-test-", dir=self.repo
        ) as directory:
            path = Path(directory) / "duplicate.json"
            path.write_text(duplicate, encoding="utf-8")
            with self.assertRaisesRegex(VERIFY.CurrentAuditError, "DUPLICATE_JSON_KEY"):
                VERIFY.verify(path, self.repo)

    def test_persistent_identifier_is_rejected_before_assignment(self) -> None:
        value = copy.deepcopy(self.manifest)
        value["persistent_identifier"] = "10.5281/zenodo.not-assigned"
        self.assert_rejected(value)

    def test_capture_time_substitution_is_rejected(self) -> None:
        value = copy.deepcopy(self.manifest)
        value["captured_at_utc"] = "2026-07-14T15:10:07Z"
        self.assert_rejected(value)

    def test_unknown_top_level_field_is_rejected(self) -> None:
        value = copy.deepcopy(self.manifest)
        value["unexpected"] = None
        self.assert_rejected(value)

    def test_source_tree_substitution_is_rejected(self) -> None:
        value = copy.deepcopy(self.manifest)
        value["source"]["tree"] = "0" * 40
        self.assert_rejected(value)

    def test_source_signature_substitution_is_rejected(self) -> None:
        value = copy.deepcopy(self.manifest)
        value["source"]["source_commit_signature"]["status"] = "unverified"
        self.assert_rejected(value)

    def test_handoff_digest_substitution_is_rejected(self) -> None:
        value = copy.deepcopy(self.manifest)
        value["handoff"]["ledger_sha256"] = "0" * 64
        self.assert_rejected(value)

    def test_master_head_substitution_is_rejected(self) -> None:
        value = copy.deepcopy(self.manifest)
        value["master_handoff"]["frozen_heads"]["NCP"] = "0" * 40
        self.assert_rejected(value)

    def test_input_scope_substitution_is_rejected(self) -> None:
        value = copy.deepcopy(self.manifest)
        value["input_scope"]["workspace_packages"]["count"] = 15
        self.assert_rejected(value)

    def test_unapproved_intervening_file_is_rejected(self) -> None:
        value = copy.deepcopy(self.manifest)
        value["approved_cut_update"]["files"][0]["path"] = "README.md"
        self.assert_rejected(value)

    def test_intervening_patch_digest_substitution_is_rejected(self) -> None:
        value = copy.deepcopy(self.manifest)
        value["approved_cut_update"]["patch_sha256"] = "0" * 64
        self.assert_rejected(value)

    def test_locked_input_omission_is_rejected(self) -> None:
        value = copy.deepcopy(self.manifest)
        value["locked_inputs"].pop()
        self.assert_rejected(value)

    def test_locked_input_duplicate_is_rejected(self) -> None:
        value = copy.deepcopy(self.manifest)
        value["locked_inputs"][-1]["path"] = value["locked_inputs"][0]["path"]
        self.assert_rejected(value)

    def test_requirement_identity_substitution_is_rejected(self) -> None:
        path = self.repo / self.manifest["requirements_ledger"]["path"]
        original = path.read_text(encoding="utf-8")
        mutated = original.replace(
            "Freeze exact audit inputs and produce a signed immutable input manifest",
            "Substituted task title",
            1,
        )
        original_loader = VERIFY._load_json_bytes

        def load_with_mutation(payload: bytes, label: str) -> dict[str, object]:
            if label == "requirements":
                return json.loads(mutated)
            return original_loader(payload, label)

        with mock.patch.object(
            VERIFY, "_load_json_bytes", side_effect=load_with_mutation
        ):
            with self.assertRaises(VERIFY.CurrentAuditError):
                VERIFY.verify(self.manifest_path, self.repo)

    def test_terminal_requirement_without_evidence_is_rejected(self) -> None:
        ledger, bootstrap, framework, qualification, evidence, lenses = (
            self.terminal_fixture()
        )
        ledger["tasks"][0]["evidence"] = []
        with self.assertRaises(VERIFY.CurrentAuditError):
            VERIFY._verify_terminal_requirement_state(
                ledger,
                bootstrap,
                framework_commit=framework,
                qualification_commit=qualification,
                evidence_ids=evidence,
                lens_projection=lenses,
            )

    def test_counterfeit_fully_qualified_go_is_rejected(self) -> None:
        ledger, bootstrap, framework, qualification, evidence, lenses = (
            self.terminal_fixture()
        )
        ledger["overall_status"] = "GO"
        for task in ledger["tasks"]:
            task["status"] = "VERIFIED"
            task["claim_disposition"] = "anything"
            task["assigned_reviewers"] = [None]
            task["evidence"] = [None]
            task["closure_commit"] = "0" * 40
            task["twenty_lens_reviews"] = {
                f"L{lens:02d}": None for lens in range(1, 21)
            }
        with self.assertRaises(VERIFY.CurrentAuditError):
            VERIFY._verify_terminal_requirement_state(
                ledger,
                bootstrap,
                framework_commit=framework,
                qualification_commit=qualification,
                evidence_ids=evidence,
                lens_projection=lenses,
            )

    def test_baseline_digest_substitution_is_rejected(self) -> None:
        value = copy.deepcopy(self.manifest)
        value["baseline"]["log"]["uncompressed_sha256"] = "f" * 64
        self.assert_rejected(value)

    def test_baseline_path_escape_is_rejected(self) -> None:
        value = copy.deepcopy(self.manifest)
        value["baseline"]["log"]["path"] = "../../outside.log.gz"
        self.assert_rejected(value)

    def test_baseline_extra_field_is_rejected(self) -> None:
        value = copy.deepcopy(self.manifest)
        value["baseline"]["unreviewed"] = True
        self.assert_rejected(value)

    def test_boolean_integer_confusion_is_rejected(self) -> None:
        value = copy.deepcopy(self.manifest)
        value["baseline"]["exit_status"] = False
        self.assert_rejected(value)

    def test_float_is_rejected(self) -> None:
        value = copy.deepcopy(self.manifest)
        value["baseline"]["passed_gates"] = 27.0
        self.assert_rejected(value)

    def test_corrupted_compressed_evidence_is_rejected(self) -> None:
        payload = bytearray(self.deterministic_gzip(b"retained baseline\n"))
        payload[-1] ^= 1
        with self.assertRaises(VERIFY.CurrentAuditError):
            VERIFY._decompress_unbound_gzip(bytes(payload), "baseline.log.gz")

    def test_old_remote_tag_is_not_silently_accepted(self) -> None:
        value = copy.deepcopy(self.manifest)
        value["repository_publication_state"]["remote_tags"] = ["v0.1.0"]
        self.assert_rejected(value)

    def test_publication_evidence_digest_substitution_is_rejected(self) -> None:
        value = copy.deepcopy(self.manifest)
        value["repository_publication_state"]["evidence"]["sha256"] = "0" * 64
        self.assert_rejected(value)

    def test_failed_source_cut_ci_is_rejected(self) -> None:
        value = copy.deepcopy(self.manifest)
        value["github_source_cut_checks"]["ci"]["conclusion"] = "failure"
        self.assert_rejected(value)

    def test_source_cut_run_id_substitution_is_rejected(self) -> None:
        value = copy.deepcopy(self.manifest)
        value["github_source_cut_checks"]["ci"]["run_id"] += 1
        self.assert_rejected(value)

    def test_source_cut_head_substitution_is_rejected(self) -> None:
        value = copy.deepcopy(self.manifest)
        value["github_source_cut_checks"]["formal"]["head_sha"] = "0" * 40
        self.assert_rejected(value)

    def test_malformed_json_is_rejected(self) -> None:
        self.assert_raw_rejected("{")

    def test_non_object_json_is_rejected(self) -> None:
        self.assert_raw_rejected("[]\n")

    def test_nan_is_rejected(self) -> None:
        payload = self.manifest_path.read_text(encoding="utf-8").replace(
            '"captured_at_utc": "2026-07-14T15:10:06Z"',
            '"captured_at_utc": NaN',
        )
        self.assert_raw_rejected(payload)

    def test_huge_integer_is_rejected(self) -> None:
        payload = self.manifest_path.read_text(encoding="utf-8").replace(
            '"run_id": 29327196587', '"run_id": ' + "9" * 100, 1
        )
        self.assert_raw_rejected(payload)

    def test_oversized_json_is_rejected(self) -> None:
        self.assert_raw_rejected(b'{"padding":"' + b"a" * VERIFY.MAX_JSON_BYTES + b'"}')

    def test_manifest_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix=".current-audit-test-", dir=self.repo
        ) as directory:
            root = Path(directory)
            target = root / "target.json"
            target.write_text("{}\n", encoding="utf-8")
            link = root / "link.json"
            link.symlink_to(target)
            with self.assertRaisesRegex(VERIFY.CurrentAuditError, "SYMLINK_REJECTED"):
                VERIFY.verify(link, self.repo)

    def test_qualification_exact_record_verifies(self) -> None:
        qualification, review = self.qualification_documents()
        observed = self.verify_qualification_documents(qualification, review)
        self.assertEqual(observed, (qualification, review))

    def test_qualification_human_reviewer_impersonation_is_rejected(self) -> None:
        _qualification, review = self.qualification_documents()
        review["reviewers"][0]["human"] = True
        self.assert_qualification_rejected({"ch_t000.review": review})

    def test_qualification_named_human_impersonation_is_rejected(self) -> None:
        _qualification, review = self.qualification_documents()
        review["lead_approval"]["named_human_approver"] = True
        self.assert_qualification_rejected({"ch_t000.review": review})

    def test_qualification_missing_evidence_is_rejected(self) -> None:
        qualification, _review = self.qualification_documents()
        qualification["evidence_files"].pop()
        self.assert_qualification_rejected({"ch_t000.qualification": qualification})

    def test_qualification_dangling_evidence_is_rejected(self) -> None:
        _qualification, review = self.qualification_documents()
        review["evidence_catalog"]["CH-T000-E99"] = {"unexpected": True}
        self.assert_qualification_rejected({"ch_t000.review": review})

    def test_qualification_each_missing_lens_is_rejected(self) -> None:
        qualification, original_review = self.qualification_documents()
        for index in range(1, 21):
            with self.subTest(lens=index):
                review = copy.deepcopy(original_review)
                review["twenty_lens_reviews"].pop(f"L{index:02d}")
                self.assert_qualification_rejected(
                    {
                        "ch_t000.qualification": qualification,
                        "ch_t000.review": review,
                    }
                )

    def test_qualification_behavior_mutation_is_rejected(self) -> None:
        _qualification, review = self.qualification_documents()
        review["current_behavior"]["validation"] = ""
        self.assert_qualification_rejected({"ch_t000.review": review})

    def test_qualification_control_mutation_is_rejected(self) -> None:
        _qualification, review = self.qualification_documents()
        review["normative_controls"][0]["requirement"] = ""
        self.assert_qualification_rejected({"ch_t000.review": review})

    def test_qualification_counterfactual_mutation_is_rejected(self) -> None:
        _qualification, review = self.qualification_documents()
        review["mandatory_counterfactuals"][0]["scenario"] = "substituted"
        self.assert_qualification_rejected({"ch_t000.review": review})

    def test_qualification_counterfactual_dangling_evidence_is_rejected(self) -> None:
        _qualification, review = self.qualification_documents()
        review["mandatory_counterfactuals"][0]["test_id"] = "test_missing"
        self.assert_qualification_rejected({"ch_t000.review": review})

    def test_qualification_decision_mutation_is_rejected(self) -> None:
        qualification, _review = self.qualification_documents()
        qualification["decision"]["release_status_after_activation"] = "GO"
        self.assert_qualification_rejected({"ch_t000.qualification": qualification})

    def test_qualification_current_status_must_remain_open(self) -> None:
        qualification, _review = self.qualification_documents()
        qualification["decision"]["current_ledger_status"] = "VERIFIED"
        self.assert_qualification_rejected({"ch_t000.qualification": qualification})

    def test_qualification_required_evidence_cannot_remain_pending(self) -> None:
        _qualification, review = self.qualification_documents()
        review["task_disposition"] = "PENDING"
        self.assert_qualification_rejected({"ch_t000.review": review})

    def test_qualification_implementation_commit_mutation_is_rejected(self) -> None:
        qualification, _review = self.qualification_documents()
        qualification["qualified_implementation"]["commit"] = "0" * 40
        self.assert_qualification_rejected({"ch_t000.qualification": qualification})

    def test_qualification_implementation_tree_mutation_is_rejected(self) -> None:
        qualification, _review = self.qualification_documents()
        qualification["qualified_implementation"]["tree"] = "0" * 40
        self.assert_qualification_rejected({"ch_t000.qualification": qualification})

    def test_qualification_implementation_parent_mutation_is_rejected(self) -> None:
        qualification, _review = self.qualification_documents()
        qualification["qualified_implementation"]["parent"] = "0" * 40
        self.assert_qualification_rejected({"ch_t000.qualification": qualification})

    def test_qualification_implementation_diff_mutation_is_rejected(self) -> None:
        qualification, _review = self.qualification_documents()
        qualification["qualified_implementation"]["diff"]["patch_sha256"] = "0" * 64
        self.assert_qualification_rejected({"ch_t000.qualification": qualification})

    def test_qualification_signature_principal_mutation_is_rejected(self) -> None:
        qualification, _review = self.qualification_documents()
        qualification["qualified_implementation"]["signature"]["principal"] = (
            "attacker@example.invalid"
        )
        self.assert_qualification_rejected({"ch_t000.qualification": qualification})

    def test_qualification_signature_fingerprint_mutation_is_rejected(self) -> None:
        qualification, _review = self.qualification_documents()
        qualification["qualified_implementation"]["signature"]["key_fingerprint"] = (
            "SHA256:substituted"
        )
        self.assert_qualification_rejected({"ch_t000.qualification": qualification})

    def test_stale_correctly_signed_implementation_commit_is_rejected(self) -> None:
        qualification, _review = self.qualification_documents()
        qualification["qualified_implementation"]["commit"] = VERIFY.SOURCE_COMMIT
        self.assert_qualification_rejected({"ch_t000.qualification": qualification})

    def test_qualification_implementation_signature_failure_is_rejected(self) -> None:
        qualification, review = self.qualification_documents()
        with self.assertRaises(VERIFY.CurrentAuditError):
            self.verify_qualification_documents(
                qualification, review, signature_failure=True
            )

    def test_qualification_evidence_digest_mutation_is_rejected(self) -> None:
        qualification, _review = self.qualification_documents()
        qualification["evidence_files"][0]["sha256"] = "0" * 64
        self.assert_qualification_rejected({"ch_t000.qualification": qualification})

    def test_qualification_undeclared_artifact_class_is_rejected(self) -> None:
        value = copy.deepcopy(self.manifest)
        value["input_scope"]["machine_learning_models"] = ["weights.bin"]
        self.assert_rejected(value)

    def test_qualification_legacy_closure_transfer_is_rejected(self) -> None:
        path = self.repo / self.manifest["requirements_ledger"]["path"]
        ledger = json.loads(path.read_text(encoding="utf-8"))
        ledger["legacy_ledger"]["closure_transfer_permitted"] = True
        payload = (json.dumps(ledger, sort_keys=True) + "\n").encode("utf-8")
        with mock.patch.object(
            VERIFY, "_read_repo_relative_bounded", return_value=payload
        ):
            with self.assertRaises(VERIFY.CurrentAuditError):
                VERIFY._verify_requirements_ledger(self.manifest, self.repo)

    def test_qualification_attempt_mutation_is_rejected(self) -> None:
        _qualification, review = self.qualification_documents()
        review["finding_dispositions"][0]["status"] = "PENDING"
        self.assert_qualification_rejected({"ch_t000.review": review})

    def test_qualification_attempt_url_mutation_is_rejected(self) -> None:
        _qualification, review = self.qualification_documents()
        review["reviewed_commits"]["qualification_framework"] = "0" * 40
        self.assert_qualification_rejected({"ch_t000.review": review})

    def test_qualification_attempt_timestamp_mutation_is_rejected(self) -> None:
        _qualification, review = self.qualification_documents()
        review["review_completed_at_utc"] = "2026-07-14T16:00:00Z"
        self.assert_qualification_rejected({"ch_t000.review": review})

    def test_qualification_missing_job_is_rejected(self) -> None:
        now = VERIFY.datetime.fromisoformat("2026-07-14T18:00:00+00:00")
        with self.assertRaisesRegex(VERIFY.CurrentAuditError, "JOBS_INVALID"):
            VERIFY._verify_nested_jobs({"jobs": []}, "synthetic", lower=now, upper=now)

    def test_qualification_nested_failed_job_is_rejected(self) -> None:
        lower = VERIFY.datetime.fromisoformat("2026-07-14T18:00:00+00:00")
        upper = VERIFY.datetime.fromisoformat("2026-07-14T18:01:00+00:00")
        raw = self.nested_jobs_document()
        raw["jobs"][0]["conclusion"] = "failure"
        with self.assertRaisesRegex(VERIFY.CurrentAuditError, "JOB_FAILED"):
            VERIFY._verify_nested_jobs(raw, "synthetic", lower=lower, upper=upper)

    def test_qualification_nested_failed_step_is_rejected(self) -> None:
        lower = VERIFY.datetime.fromisoformat("2026-07-14T18:00:00+00:00")
        upper = VERIFY.datetime.fromisoformat("2026-07-14T18:01:00+00:00")
        raw = self.nested_jobs_document()
        raw["jobs"][0]["steps"][0]["conclusion"] = "failure"
        with self.assertRaisesRegex(VERIFY.CurrentAuditError, "STEP_FAILED"):
            VERIFY._verify_nested_jobs(raw, "synthetic", lower=lower, upper=upper)

    def test_qualification_p0_exit_mutation_is_rejected(self) -> None:
        _qualification, review = self.qualification_documents()
        review["finding_dispositions"][2]["status"] = "FAILED"
        self.assert_qualification_rejected({"ch_t000.review": review})

    def test_qualification_p0_gate_mutation_is_rejected(self) -> None:
        _qualification, review = self.qualification_documents()
        review["finding_dispositions"][2]["evidence_ids"] = []
        self.assert_qualification_rejected({"ch_t000.review": review})

    def test_qualification_clean_linux_provenance_mutation_is_rejected(self) -> None:
        _qualification, review = self.qualification_documents()
        review["finding_dispositions"][4]["status"] = "UNREPRESENTATIVE"
        self.assert_qualification_rejected({"ch_t000.review": review})

    def test_qualification_clean_linux_reviewer_mutation_is_rejected(self) -> None:
        _qualification, review = self.qualification_documents()
        review["reviewers"][0]["id"] = "CH-T000-R99"
        self.assert_qualification_rejected({"ch_t000.review": review})

    def test_qualification_corrupt_log_is_rejected(self) -> None:
        payload = bytearray(self.deterministic_gzip(b"exact retained log\n"))
        payload[-1] ^= 1
        with self.assertRaises(VERIFY.CurrentAuditError):
            VERIFY._decompress_unbound_gzip(bytes(payload), "corrupt")

    def test_qualification_dependency_mutation_is_rejected(self) -> None:
        path = self.repo / self.manifest["requirements_ledger"]["path"]
        ledger = json.loads(path.read_text(encoding="utf-8"))
        ledger["tasks"][1]["dependencies"] = []
        payload = (json.dumps(ledger, sort_keys=True) + "\n").encode("utf-8")
        with mock.patch.object(
            VERIFY, "_read_repo_relative_bounded", return_value=payload
        ):
            with self.assertRaises(VERIFY.CurrentAuditError):
                VERIFY._verify_requirements_ledger(self.manifest, self.repo)

    def test_qualification_replace_ref_influence_is_rejected(self) -> None:
        with mock.patch.object(
            VERIFY, "_run_bounded", return_value=(0, b"immutable\n", b"")
        ) as runner:
            self.assertEqual(
                VERIFY._git(self.repo, "rev-parse", "HEAD"), b"immutable\n"
            )
        command = runner.call_args.args[0]
        self.assertEqual(command[:2], [VERIFY.GIT_EXECUTABLE, "--no-replace-objects"])

    def test_qualification_exact_resource_boundaries(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            exact = root / "exact.bin"
            exact.write_bytes(b"x" * 64)
            self.assertEqual(VERIFY._read_bounded(exact, 64, "exact"), b"x" * 64)
            over = root / "over.bin"
            over.write_bytes(b"x" * 65)
            with self.assertRaisesRegex(VERIFY.CurrentAuditError, "RESOURCE_BOUND"):
                VERIFY._read_bounded(over, 64, "over")

            payload = b"z" * 64
            compressed = self.deterministic_gzip(payload)
            gzip_path = root / "exact.log.gz"
            gzip_path.write_bytes(compressed)
            record = {
                "path": gzip_path.name,
                "compressed_sha256": hashlib.sha256(compressed).hexdigest(),
                "compressed_bytes": len(compressed),
                "uncompressed_sha256": hashlib.sha256(payload).hexdigest(),
                "uncompressed_bytes": len(payload),
                "uncompressed_lines": len(payload.splitlines()),
            }
            self.assertEqual(
                VERIFY._read_gzip_evidence(root, record, "exact-gzip", 64), payload
            )

    def test_qualification_gzip_expansion_over_limit_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            payload = b"z" * 65
            compressed = self.deterministic_gzip(payload)
            path = root / "over.log.gz"
            path.write_bytes(compressed)
            record = {
                "path": path.name,
                "compressed_sha256": hashlib.sha256(compressed).hexdigest(),
                "compressed_bytes": len(compressed),
                "uncompressed_sha256": hashlib.sha256(payload).hexdigest(),
                "uncompressed_bytes": len(payload),
                "uncompressed_lines": len(payload.splitlines()),
            }
            with self.assertRaisesRegex(
                VERIFY.CurrentAuditError, "GZIP_RESOURCE_BOUND"
            ):
                VERIFY._read_gzip_evidence(root, record, "over-gzip", 64)

    def test_qualification_git_output_over_limit_is_rejected(self) -> None:
        command = [
            sys.executable,
            "-c",
            "import os; os.write(1, b'x' * 4096)",
        ]
        started = time.monotonic()
        with self.assertRaisesRegex(VERIFY.CurrentAuditError, "OUTPUT_BOUND"):
            VERIFY._run_bounded(
                command,
                cwd=self.repo,
                env=os.environ.copy(),
                timeout_seconds=2,
                stdout_limit=64,
                stderr_limit=64,
                error_prefix="TEST_GIT",
                _test_only_allow_uncontained_process=True,
            )
        self.assertLess(time.monotonic() - started, 2)

    def test_qualification_git_stderr_over_limit_is_rejected(self) -> None:
        command = [
            sys.executable,
            "-c",
            "import os; os.write(2, b'x' * 4096)",
        ]
        with self.assertRaisesRegex(VERIFY.CurrentAuditError, "OUTPUT_BOUND"):
            VERIFY._run_bounded(
                command,
                cwd=self.repo,
                env=os.environ.copy(),
                timeout_seconds=2,
                stdout_limit=64,
                stderr_limit=64,
                error_prefix="TEST_GIT",
                _test_only_allow_uncontained_process=True,
            )

    def test_qualification_git_timeout_is_rejected(self) -> None:
        started = time.monotonic()
        with self.assertRaisesRegex(VERIFY.CurrentAuditError, "TIMEOUT"):
            VERIFY._run_bounded(
                [sys.executable, "-c", "import time; time.sleep(10)"],
                cwd=self.repo,
                env=os.environ.copy(),
                timeout_seconds=0.05,
                stdout_limit=64,
                stderr_limit=64,
                error_prefix="TEST_GIT",
                _test_only_allow_uncontained_process=True,
            )
        self.assertLess(time.monotonic() - started, 2)

    @unittest.skipUnless(os.name == "posix", "process groups require POSIX")
    def test_bounded_runner_kills_inheriting_grandchild(self) -> None:
        script = (
            "import subprocess,sys,time; "
            "subprocess.Popen([sys.executable,'-c','import time; time.sleep(10)']); "
            "time.sleep(10)"
        )
        started = time.monotonic()
        with self.assertRaisesRegex(VERIFY.CurrentAuditError, "TIMEOUT"):
            VERIFY._run_bounded(
                [sys.executable, "-c", script],
                cwd=self.repo,
                env=os.environ.copy(),
                timeout_seconds=0.05,
                stdout_limit=64,
                stderr_limit=64,
                error_prefix="TEST_GROUP",
                _test_only_allow_uncontained_process=True,
            )
        self.assertLess(time.monotonic() - started, 2)

    def test_read_bounded_rejects_path_swap_after_open(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            path = root / "record.json"
            replacement = root / "replacement.json"
            path.write_bytes(b"original")
            replacement.write_bytes(b"substitute")
            original_read = os.read
            swapped = False

            def swap_then_read(descriptor: int, count: int) -> bytes:
                nonlocal swapped
                if not swapped:
                    os.replace(replacement, path)
                    swapped = True
                return original_read(descriptor, count)

            with mock.patch.object(os, "read", side_effect=swap_then_read):
                with self.assertRaisesRegex(
                    VERIFY.CurrentAuditError, "FILE_CHANGED_DURING_READ"
                ):
                    VERIFY._read_bounded(path, 64, "swap")
            self.assertEqual(path.read_bytes(), b"substitute")

    @unittest.skipUnless(os.name == "posix", "O_NOFOLLOW requires POSIX")
    def test_read_bounded_rejects_symlink_swapped_before_open(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            path = root / "record.json"
            target = root / "target.json"
            path.write_bytes(b"original")
            target.write_bytes(b"substitute")
            original_open = os.open
            swapped = False

            def swap_then_open(candidate: object, flags: int, *args: object) -> int:
                nonlocal swapped
                if not swapped and Path(candidate) == path:
                    path.unlink()
                    path.symlink_to(target)
                    swapped = True
                return original_open(candidate, flags, *args)

            with mock.patch.object(os, "open", side_effect=swap_then_open):
                with self.assertRaisesRegex(
                    VERIFY.CurrentAuditError, "SYMLINK_REJECTED"
                ):
                    VERIFY._read_bounded(path, 64, "swap-link")

    @unittest.skipUnless(os.name == "posix", "dirfd traversal requires POSIX")
    def test_evidence_read_rejects_intermediate_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            repo = Path(raw)
            outside = repo / "outside"
            outside.mkdir()
            (outside / "record.bin").write_bytes(b"outside")
            (repo / "linked").symlink_to(outside, target_is_directory=True)
            record = {
                "path": "linked/record.bin",
                "sha256": hashlib.sha256(b"outside").hexdigest(),
                "bytes": 7,
            }
            with self.assertRaises(VERIFY.CurrentAuditError):
                VERIFY._read_evidence_file(repo, record, "parent-link", 64)

    @unittest.skipUnless(os.name == "posix", "dirfd traversal requires POSIX")
    def test_evidence_read_uses_stable_parent_dirfd_across_swap(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            repo = Path(raw)
            parent = repo / "parent"
            parent.mkdir()
            (parent / "record.bin").write_bytes(b"original")
            attacker = repo / "attacker"
            attacker.mkdir()
            (attacker / "record.bin").write_bytes(b"substitute")
            displaced = repo / "displaced"
            record = {
                "path": "parent/record.bin",
                "sha256": hashlib.sha256(b"original").hexdigest(),
                "bytes": 8,
            }
            original_open = os.open
            swapped = False

            def swap_parent(
                candidate: object, flags: int, *args: object, **kwargs: object
            ) -> int:
                nonlocal swapped
                if candidate == "record.bin" and not swapped:
                    parent.rename(displaced)
                    parent.symlink_to(attacker, target_is_directory=True)
                    swapped = True
                return original_open(candidate, flags, *args, **kwargs)

            with mock.patch.object(os, "open", side_effect=swap_parent):
                self.assertEqual(
                    VERIFY._read_evidence_file(repo, record, "parent-swap", 64),
                    b"original",
                )
            self.assertEqual((parent / "record.bin").read_bytes(), b"substitute")

    def test_zip_entry_and_aggregate_exact_and_over_boundaries(self) -> None:
        def archive(sizes: list[int]) -> bytes:
            with tempfile.SpooledTemporaryFile(max_size=1024 * 1024) as handle:
                with zipfile.ZipFile(
                    handle, "w", compression=zipfile.ZIP_DEFLATED
                ) as zipped:
                    for index, size in enumerate(sizes):
                        zipped.writestr(f"entry-{index}.bin", b"x" * size)
                handle.seek(0)
                return handle.read()

        entry_exact = archive([VERIFY.MAX_ZIP_ENTRY_BYTES])
        VERIFY._verify_handoff_zip(entry_exact, 1, "entry-exact")
        entry_over = archive([VERIFY.MAX_ZIP_ENTRY_BYTES + 1])
        with self.assertRaises(VERIFY.CurrentAuditError):
            VERIFY._verify_handoff_zip(entry_over, 1, "entry-over")

        aggregate_exact = archive([VERIFY.MAX_ZIP_ENTRY_BYTES] * 4)
        VERIFY._verify_handoff_zip(aggregate_exact, 4, "aggregate-exact")
        aggregate_over = archive([VERIFY.MAX_ZIP_ENTRY_BYTES] * 4 + [1])
        with self.assertRaises(VERIFY.CurrentAuditError):
            VERIFY._verify_handoff_zip(aggregate_over, 5, "aggregate-over")

    def terminal_fixture(
        self,
    ) -> tuple[
        dict[str, object],
        dict[str, object],
        str,
        str,
        list[str],
        dict[str, object],
    ]:
        bootstrap = json.loads(
            VERIFY._git_file(
                self.repo,
                VERIFY.IMPLEMENTATION_COMMIT,
                VERIFY.EXPECTED_REQUIREMENTS_LEDGER["path"],
            )
        )
        ledger = copy.deepcopy(bootstrap)
        framework_commit = "1" * 40
        qualification_commit = "2" * 40
        evidence_ids = [
            *[f"CH-T000-E{index:02d}" for index in range(1, 7)],
            *[f"CH-T000-Q{index:02d}" for index in range(1, 9)],
            *[f"CH-T000-A{index:02d}" for index in range(1, 6)],
        ]
        lenses = {
            f"L{index:02d}": {
                "status": "RESOLVED",
                "source_question": f"question-{index}",
                "finding": f"finding-{index}",
                "evidence_ids": ["CH-T000-A01"],
            }
            for index in range(1, 21)
        }
        task = ledger["tasks"][0]
        task.update(
            {
                "status": "VERIFIED",
                "claim_disposition": "NO_PUBLIC_CLAIM_CHANGE",
                "assigned_reviewers": [
                    "CH-T000-R01",
                    "CH-T000-R02",
                    "CH-T000-R03",
                ],
                "implementation_commits": [
                    VERIFY.IMPLEMENTATION_COMMIT,
                    framework_commit,
                ],
                "evidence": evidence_ids,
                "closure_commit": qualification_commit,
                "twenty_lens_reviews": lenses,
            }
        )
        return (
            ledger,
            bootstrap,
            framework_commit,
            qualification_commit,
            evidence_ids,
            lenses,
        )

    def test_terminal_exact_ch_t000_state_verifies(self) -> None:
        ledger, bootstrap, framework, qualification, evidence, lenses = (
            self.terminal_fixture()
        )
        self.assertIsNone(
            VERIFY._verify_terminal_requirement_state(
                ledger,
                bootstrap,
                framework_commit=framework,
                qualification_commit=qualification,
                evidence_ids=evidence,
                lens_projection=lenses,
            )
        )

    def test_terminal_later_task_mutation_is_rejected(self) -> None:
        ledger, bootstrap, framework, qualification, evidence, lenses = (
            self.terminal_fixture()
        )
        ledger["tasks"][1]["status"] = "VERIFIED"
        with self.assertRaises(VERIFY.CurrentAuditError):
            VERIFY._verify_terminal_requirement_state(
                ledger,
                bootstrap,
                framework_commit=framework,
                qualification_commit=qualification,
                evidence_ids=evidence,
                lens_projection=lenses,
            )

    def test_terminal_closure_commit_must_contain_bound_artifacts(self) -> None:
        ledger, bootstrap, framework, qualification, evidence, lenses = (
            self.terminal_fixture()
        )
        ledger["tasks"][0]["closure_commit"] = "3" * 40
        with self.assertRaises(VERIFY.CurrentAuditError):
            VERIFY._verify_terminal_requirement_state(
                ledger,
                bootstrap,
                framework_commit=framework,
                qualification_commit=qualification,
                evidence_ids=evidence,
                lens_projection=lenses,
            )

    def test_revocation_cascade_rejects_open_prerequisite_with_terminal_descendant(
        self,
    ) -> None:
        _ledger, bootstrap, *_rest = self.terminal_fixture()
        tasks = copy.deepcopy(bootstrap["tasks"])
        tasks[1]["status"] = "VERIFIED"
        with self.assertRaisesRegex(VERIFY.CurrentAuditError, "DEPENDENCY_CASCADE"):
            VERIFY._verify_dependency_cascade(tasks)

    def test_revocation_cascade_accepts_forward_reopen_of_all_descendants(self) -> None:
        _ledger, bootstrap, *_rest = self.terminal_fixture()
        self.assertIsNone(
            VERIFY._verify_dependency_cascade(copy.deepcopy(bootstrap["tasks"]))
        )

    def test_framework_pending_to_qualified_open_to_terminal_stage_sequence(
        self,
    ) -> None:
        self.assertEqual(
            VERIFY._select_qualification_stage(
                requirement_state="OPEN",
                chain_length=1,
                qualification_present=False,
                activation_present=False,
            ),
            "FRAMEWORK_PENDING_QUALIFICATION",
        )
        self.assertEqual(
            VERIFY._select_qualification_stage(
                requirement_state="OPEN",
                chain_length=2,
                qualification_present=True,
                activation_present=False,
            ),
            "QUALIFIED_OPEN",
        )
        self.assertEqual(
            VERIFY._select_qualification_stage(
                requirement_state="TERMINAL_PENDING_ACTIVATION_VALIDATION",
                chain_length=3,
                qualification_present=True,
                activation_present=True,
            ),
            "TERMINAL_ACTIVATION",
        )

    def test_qualified_or_terminal_stage_rejects_qualification_deletion(self) -> None:
        for state, chain, activation in (
            ("OPEN", 2, False),
            ("TERMINAL_PENDING_ACTIVATION_VALIDATION", 3, True),
        ):
            with self.subTest(state=state):
                with self.assertRaises(VERIFY.CurrentAuditError):
                    VERIFY._select_qualification_stage(
                        requirement_state=state,
                        chain_length=chain,
                        qualification_present=False,
                        activation_present=activation,
                    )

    def test_framework_pending_rejects_premature_packet_or_activation(self) -> None:
        for qualification, activation in ((True, False), (False, True), (True, True)):
            with self.subTest(qualification=qualification, activation=activation):
                with self.assertRaises(VERIFY.CurrentAuditError):
                    VERIFY._select_qualification_stage(
                        requirement_state="OPEN",
                        chain_length=1,
                        qualification_present=qualification,
                        activation_present=activation,
                    )

    def test_public_c_missing_qualification_is_rejected(self) -> None:
        with self.assertRaises(VERIFY.CurrentAuditError):
            VERIFY._select_qualification_stage(
                requirement_state="OPEN",
                chain_length=2,
                qualification_present=False,
                activation_present=False,
            )

    def test_public_c_malformed_qualification_is_rejected(self) -> None:
        with self.assertRaises(VERIFY.CurrentAuditError):
            VERIFY._select_qualification_stage(
                requirement_state="OPEN",
                chain_length=2,
                qualification_present=True,
                activation_present=True,
            )

    def test_public_d_missing_activation_is_rejected(self) -> None:
        with self.assertRaises(VERIFY.CurrentAuditError):
            VERIFY._select_qualification_stage(
                requirement_state="TERMINAL_PENDING_ACTIVATION_VALIDATION",
                chain_length=3,
                qualification_present=True,
                activation_present=False,
            )

    def test_public_d_malformed_activation_is_rejected(self) -> None:
        with self.assertRaises(VERIFY.CurrentAuditError):
            VERIFY._select_qualification_stage(
                requirement_state="OPEN",
                chain_length=3,
                qualification_present=True,
                activation_present=True,
            )

    def test_bounded_runner_kills_descendant_after_leader_exit(self) -> None:
        script = (
            "import subprocess,sys; "
            "subprocess.Popen([sys.executable,'-c','import time; time.sleep(10)']); "
            "print('leader complete')"
        )
        with self.assertRaisesRegex(VERIFY.CurrentAuditError, "ORPHANED_PROCESS_GROUP"):
            VERIFY._run_bounded(
                [sys.executable, "-c", script],
                cwd=self.repo,
                env=os.environ.copy(),
                timeout_seconds=2,
                stdout_limit=64,
                stderr_limit=64,
                error_prefix="TEST_EXITED_LEADER",
                _test_only_allow_uncontained_process=True,
            )

    def test_bounded_runner_rejects_uncontained_host_executable(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            marker = Path(raw) / "spawned"
            with self.assertRaisesRegex(
                VERIFY.CurrentAuditError, "UNTRUSTED_HOST_EXECUTABLE"
            ):
                VERIFY._run_bounded(
                    [
                        sys.executable,
                        "-c",
                        f"from pathlib import Path; Path({str(marker)!r}).touch()",
                    ],
                    cwd=Path(raw),
                    env=os.environ.copy(),
                    timeout_seconds=2,
                    stdout_limit=64,
                    stderr_limit=64,
                    error_prefix="TEST_UNCONTAINED",
                )
            self.assertFalse(marker.exists())

    def test_trusted_executable_metadata_enforces_type_owner_and_mode(self) -> None:
        candidate = mock.Mock()
        candidate.is_absolute.return_value = True
        candidate.is_symlink.return_value = False
        metadata = mock.Mock(
            st_mode=VERIFY.stat.S_IFREG | 0o750,
            st_uid=1000,
            st_gid=123,
        )
        with mock.patch.object(VERIFY.os, "geteuid", return_value=1000):
            self.assertTrue(
                VERIFY._trusted_executable_metadata_is_valid(
                    candidate, metadata, allow_current_user_owner=True
                )
            )
            self.assertFalse(
                VERIFY._trusted_executable_metadata_is_valid(
                    candidate, metadata, allow_current_user_owner=False
                )
            )
            metadata.st_uid = 2000
            self.assertFalse(
                VERIFY._trusted_executable_metadata_is_valid(
                    candidate, metadata, allow_current_user_owner=True
                )
            )
            metadata.st_uid = 0
            self.assertTrue(
                VERIFY._trusted_executable_metadata_is_valid(
                    candidate, metadata, allow_current_user_owner=False
                )
            )
            metadata.st_mode = VERIFY.stat.S_IFREG | 0o770
            self.assertFalse(
                VERIFY._trusted_executable_metadata_is_valid(
                    candidate, metadata, allow_current_user_owner=True
                )
            )
            metadata.st_mode = VERIFY.stat.S_IFREG | 0o752
            self.assertFalse(
                VERIFY._trusted_executable_metadata_is_valid(
                    candidate, metadata, allow_current_user_owner=True
                )
            )
            metadata.st_mode = VERIFY.stat.S_IFDIR | 0o750
            self.assertFalse(
                VERIFY._trusted_executable_metadata_is_valid(
                    candidate, metadata, allow_current_user_owner=True
                )
            )
            metadata.st_mode = VERIFY.stat.S_IFREG | 0o750
            candidate.is_symlink.return_value = True
            self.assertFalse(
                VERIFY._trusted_executable_metadata_is_valid(
                    candidate, metadata, allow_current_user_owner=True
                )
            )
            candidate.is_symlink.return_value = False
            candidate.is_absolute.return_value = False
            self.assertFalse(
                VERIFY._trusted_executable_metadata_is_valid(
                    candidate, metadata, allow_current_user_owner=True
                )
            )

    def test_bounded_runner_interrupt_cleans_owned_process_group(self) -> None:
        if os.name != "posix":
            self.skipTest("process-group interruption requires POSIX")
        with tempfile.TemporaryDirectory() as raw:
            pid_path = Path(raw) / "pid"
            script = (
                "import os,time; "
                f"open({str(pid_path)!r},'w').write(str(os.getpid())); "
                "time.sleep(30)"
            )
            timer = threading.Timer(0.25, lambda: os.kill(os.getpid(), signal.SIGINT))
            timer.start()
            try:
                with self.assertRaises(KeyboardInterrupt):
                    VERIFY._run_bounded(
                        [sys.executable, "-c", script],
                        cwd=Path(raw),
                        env=os.environ.copy(),
                        timeout_seconds=10,
                        stdout_limit=64,
                        stderr_limit=64,
                        error_prefix="TEST_INTERRUPT",
                        _test_only_allow_uncontained_process=True,
                    )
            finally:
                timer.cancel()
                timer.join()
            pid = int(pid_path.read_text(encoding="utf-8"))
            with self.assertRaises(OSError):
                os.kill(pid, 0)

    def test_git_state_disables_repository_fsmonitor_hook(self) -> None:
        with FIXTURES.signed_repository(self.repo.parent) as fixture:
            head = FIXTURES.signed_commit(
                fixture,
                {"tracked.txt": b"tracked\n"},
                "release: create fsmonitor isolation fixture",
            )
            marker = fixture.path.parent / "fsmonitor-ran"
            hook = fixture.path.parent / "fsmonitor-hook.py"
            hook.write_text(
                f"#!{sys.executable}\n"
                "from pathlib import Path\n"
                f"Path({str(marker)!r}).touch()\n",
                encoding="utf-8",
            )
            hook.chmod(0o755)
            VERIFY._git(fixture.path, "config", "--local", "core.fsmonitor", str(hook))

            FIXTURES._run(fixture.path, "status", "--porcelain=v1")
            self.assertTrue(marker.exists())
            marker.unlink()

            state = VERIFY._repository_execution_state(fixture.path)
            self.assertEqual(state[0].decode("ascii").strip(), head)
            self.assertFalse(marker.exists())

    def test_repository_git_roots_include_linked_worktree_common_directory(
        self,
    ) -> None:
        with FIXTURES.signed_repository(self.repo.parent) as fixture:
            head = FIXTURES.signed_commit(
                fixture,
                {"tracked.txt": b"tracked\n"},
                "release: create linked-worktree fixture",
            )
            linked = fixture.path.parent / "linked"
            FIXTURES._run(
                fixture.path,
                "worktree",
                "add",
                "--detach",
                str(linked),
                head,
            )
            observed = VERIFY._repository_git_roots(linked)
            expected = tuple(
                sorted(
                    {
                        Path(
                            FIXTURES._run(linked, "rev-parse", "--absolute-git-dir")
                            .decode("utf-8")
                            .strip()
                        ).resolve(),
                        (fixture.path / ".git").resolve(),
                    }
                )
            )
            self.assertEqual(observed, expected)
            self.assertEqual(len(observed), 2)

    def test_protocol_file_record_rejects_nonregular_modes(self) -> None:
        for mode, object_type in (("120000", "blob"), ("040000", "tree")):
            with self.subTest(mode=mode, object_type=object_type):
                with mock.patch.object(
                    VERIFY,
                    "_git_tree_entry",
                    return_value={
                        "mode": mode,
                        "type": object_type,
                        "oid": "1" * 40,
                    },
                ):
                    with self.assertRaises(VERIFY.CurrentAuditError):
                        VERIFY._commit_protocol_file_record(
                            self.repo, "2" * 40, "registered/test.py"
                        )

    def test_frozen_reviewer_registry_binds_keys_roles_and_identities(self) -> None:
        with (
            FIXTURES.signed_repository(self.repo.parent) as first,
            FIXTURES.signed_repository(self.repo.parent) as second,
            FIXTURES.signed_repository(self.repo.parent) as lead_support,
        ):
            first_key = FIXTURES.detached_attestation(
                first,
                b"registry-one\n",
                namespace="haldir-independent-review-v2",
                principal="reviewer-one@example.test",
            )
            second_key = FIXTURES.detached_attestation(
                second,
                b"registry-two\n",
                namespace="haldir-independent-review-v2",
                principal="reviewer-one@example.test",
            )
            lead_support_key = FIXTURES.detached_attestation(
                lead_support,
                b"registry-lead-support\n",
                namespace="haldir-automated-lead-support-v2",
                principal="lead-support@local.invalid",
            )
            source = VERIFY._source_release_signer(self.repo)
            requirements = [
                {
                    "id": "CH-T001-R01",
                    "path": "release/0.9.0/current-head/tasks/ch-t001/e0001/reviews/r01.json",
                    "kind": "INDEPENDENT_REVIEW",
                    "max_bytes": 4096,
                },
                {
                    "id": "CH-T001-R02",
                    "path": "release/0.9.0/current-head/tasks/ch-t001/e0001/reviews/r02.json",
                    "kind": "SECONDARY_AUTOMATED_REVIEW",
                    "max_bytes": 4096,
                },
                {
                    "id": "CH-T001-R03",
                    "path": "release/0.9.0/current-head/tasks/ch-t001/e0001/reviews/r03.json",
                    "kind": "LEAD_IMPLEMENTATION_REVIEW",
                    "max_bytes": 4096,
                },
            ]
            independent_identity = {
                "name": "Reviewer One",
                "principal": "reviewer-one@example.test",
                "classification": "INDEPENDENT_AUTOMATED",
                "organization": "Independent Lab",
            }
            registry = [
                {
                    "requirement_id": requirement["id"],
                    "kind": requirement["kind"],
                    "path": requirement["path"],
                    "reviewer": copy.deepcopy(independent_identity),
                    "public_key": first_key["public_key"],
                    "key_fingerprint": first_key["key_fingerprint"],
                    "trust_basis": VERIFY.NON_SOURCE_REVIEWER_TRUST_BASIS,
                }
                for requirement in requirements[:2]
            ]
            registry.append(
                {
                    "requirement_id": requirements[2]["id"],
                    "kind": requirements[2]["kind"],
                    "path": requirements[2]["path"],
                    "reviewer": {
                        "name": "CH-T001 Automated Lead-Support Reviewer",
                        "principal": "lead-support@local.invalid",
                        "classification": "AUTOMATED_LEAD_SUPPORT",
                        "organization": "SEPAHEAD",
                    },
                    "public_key": lead_support_key["public_key"],
                    "key_fingerprint": lead_support_key["key_fingerprint"],
                    "trust_basis": VERIFY.NON_SOURCE_REVIEWER_TRUST_BASIS,
                }
            )
            self.assertEqual(
                VERIFY._validate_frozen_reviewer_registry(
                    self.repo,
                    registry,
                    task_id="CH-T001",
                    requirements=requirements,
                ),
                registry,
            )
            human_lead_registry = copy.deepcopy(registry)
            human_lead_registry[2].update(
                {
                    "reviewer": {
                        "name": "Sepehr Mahmoudian",
                        "principal": "sepmhn@gmail.com",
                        "classification": "RELEASE_LEAD",
                        "organization": "SEPAHEAD",
                    },
                    "public_key": source["public_key"],
                    "key_fingerprint": source["key_fingerprint"],
                    "trust_basis": "SOURCE_RELEASE_SIGNER",
                }
            )
            self.assertEqual(
                VERIFY._validate_frozen_reviewer_registry(
                    self.repo,
                    human_lead_registry,
                    task_id="CH-T001",
                    requirements=requirements,
                ),
                human_lead_registry,
            )

            mutations: list[tuple[str, list[dict[str, object]]]] = []
            reordered = copy.deepcopy(registry)
            reordered[0], reordered[1] = reordered[1], reordered[0]
            mutations.append(("reordered", reordered))
            wrong_kind = copy.deepcopy(registry)
            wrong_kind[0]["kind"] = "EXTERNAL_FORMAL_METHODS_REVIEW"
            mutations.append(("wrong-kind", wrong_kind))
            key_alias = copy.deepcopy(registry)
            key_alias[1]["reviewer"] = {
                **independent_identity,
                "name": "Different Reviewer",
                "principal": "different@example.test",
            }
            mutations.append(("key-alias", key_alias))
            principal_alias = copy.deepcopy(registry)
            principal_alias[1]["public_key"] = second_key["public_key"]
            principal_alias[1]["key_fingerprint"] = second_key["key_fingerprint"]
            mutations.append(("principal-alias", principal_alias))
            noncanonical = copy.deepcopy(registry)
            noncanonical[0]["reviewer"]["organization"] = "Independent Lab "
            mutations.append(("noncanonical", noncanonical))
            nfd_identity = copy.deepcopy(registry)
            nfd_identity[0]["reviewer"]["name"] = "Jose\u0301"
            mutations.append(("nfd", nfd_identity))
            wrong_role = copy.deepcopy(registry)
            wrong_role[2]["reviewer"] = copy.deepcopy(independent_identity)
            wrong_role[2]["public_key"] = first_key["public_key"]
            wrong_role[2]["key_fingerprint"] = first_key["key_fingerprint"]
            wrong_role[2]["trust_basis"] = VERIFY.NON_SOURCE_REVIEWER_TRUST_BASIS
            mutations.append(("wrong-role", wrong_role))
            source_key_reuse = copy.deepcopy(registry)
            source_key_reuse[2]["public_key"] = source["public_key"]
            source_key_reuse[2]["key_fingerprint"] = source["key_fingerprint"]
            mutations.append(("source-key-reuse", source_key_reuse))
            wrong_support_trust = copy.deepcopy(registry)
            wrong_support_trust[2]["trust_basis"] = "SOURCE_RELEASE_SIGNER"
            mutations.append(("wrong-support-trust", wrong_support_trust))
            support_key_alias = copy.deepcopy(registry)
            support_key_alias[2]["public_key"] = first_key["public_key"]
            support_key_alias[2]["key_fingerprint"] = first_key["key_fingerprint"]
            mutations.append(("support-key-alias", support_key_alias))
            support_principal_alias = copy.deepcopy(registry)
            support_principal_alias[2]["reviewer"]["principal"] = independent_identity[
                "principal"
            ]
            mutations.append(("support-principal-alias", support_principal_alias))
            support_source_name_alias = copy.deepcopy(registry)
            support_source_name_alias[2]["reviewer"]["name"] = "sepehr mahmoudian"
            mutations.append(("support-source-name-alias", support_source_name_alias))
            support_source_principal_alias = copy.deepcopy(registry)
            support_source_principal_alias[2]["reviewer"]["principal"] = source[
                "principal"
            ].upper()
            mutations.append(
                ("support-source-principal-alias", support_source_principal_alias)
            )
            for label, mutation in mutations:
                with self.subTest(label=label):
                    with self.assertRaises(VERIFY.CurrentAuditError):
                        VERIFY._validate_frozen_reviewer_registry(
                            self.repo,
                            mutation,
                            task_id="CH-T001",
                            requirements=requirements,
                        )

    def test_review_signature_policy_enforces_exact_role_booleans_and_authority(
        self,
    ) -> None:
        source = VERIFY._source_release_signer(self.repo)
        registry = {
            "public_key": "ssh-ed25519 automated-review-key",
            "key_fingerprint": "SHA256:" + "a" * 43,
        }
        automated_reviewer = {
            "name": "CH-T001 Automated Lead-Support Reviewer",
            "principal": "lead-support@local.invalid",
            "classification": "AUTOMATED_LEAD_SUPPORT",
            "organization": "SEPAHEAD",
        }
        automated_record = {
            "independent_from_release_author": False,
            "external": False,
            "human": False,
            "named_human_reviewer": False,
            "release_approver": False,
            "detached_signature": {"signature": "test-only"},
        }
        self.assertEqual(
            VERIFY._qualification_review_signature_policy(
                automated_record,
                kind="LEAD_IMPLEMENTATION_REVIEW",
                reviewer=automated_reviewer,
                registry_entry=registry,
                source_signer=source,
            ),
            (
                "haldir-automated-lead-support-v2",
                automated_reviewer["principal"],
                registry["public_key"],
                registry["key_fingerprint"],
            ),
        )
        flag_fields = (
            "independent_from_release_author",
            "external",
            "human",
            "named_human_reviewer",
            "release_approver",
        )
        for field in flag_fields:
            for invalid in (0, 1, None, "false"):
                mutation = copy.deepcopy(automated_record)
                mutation[field] = invalid
                with self.subTest(field=field, invalid=invalid):
                    with self.assertRaisesRegex(
                        VERIFY.CurrentAuditError,
                        "REVIEW_AUTHORITY_BOUNDARY",
                    ):
                        VERIFY._qualification_review_signature_policy(
                            mutation,
                            kind="LEAD_IMPLEMENTATION_REVIEW",
                            reviewer=automated_reviewer,
                            registry_entry=registry,
                            source_signer=source,
                        )
        for field in (
            "independent_from_release_author",
            "external",
            "human",
            "named_human_reviewer",
            "release_approver",
        ):
            mutation = copy.deepcopy(automated_record)
            mutation[field] = True
            with self.subTest(invalid_true_flag=field):
                with self.assertRaises(VERIFY.CurrentAuditError):
                    VERIFY._qualification_review_signature_policy(
                        mutation,
                        kind="LEAD_IMPLEMENTATION_REVIEW",
                        reviewer=automated_reviewer,
                        registry_entry=registry,
                        source_signer=source,
                    )
        for designated_kind in (
            "LEAD_ONLY_TWENTY_LENS_DIFF_REVIEW",
            "SIGNED_RELEASE_DECISION_REVIEW",
        ):
            mutation = copy.deepcopy(automated_record)
            mutation["release_approver"] = (
                designated_kind == "SIGNED_RELEASE_DECISION_REVIEW"
            )
            with self.subTest(automated_designated_kind=designated_kind):
                with self.assertRaisesRegex(
                    VERIFY.CurrentAuditError,
                    "AUTOMATED_LEAD_SUPPORT",
                ):
                    VERIFY._qualification_review_signature_policy(
                        mutation,
                        kind=designated_kind,
                        reviewer=automated_reviewer,
                        registry_entry=registry,
                        source_signer=source,
                    )

        human_reviewer = {
            "name": "Sepehr Mahmoudian",
            "principal": "sepmhn@gmail.com",
            "classification": "RELEASE_LEAD",
            "organization": "SEPAHEAD",
        }
        human_registry = {
            "public_key": source["public_key"],
            "key_fingerprint": source["key_fingerprint"],
        }
        human_record = {
            **automated_record,
            "human": True,
            "named_human_reviewer": True,
        }
        for kind in (
            "LEAD_IMPLEMENTATION_REVIEW",
            "LEAD_ONLY_TWENTY_LENS_DIFF_REVIEW",
            "SIGNED_RELEASE_DECISION_REVIEW",
        ):
            record = copy.deepcopy(human_record)
            record["release_approver"] = kind == "SIGNED_RELEASE_DECISION_REVIEW"
            with self.subTest(human_lead_kind=kind):
                self.assertEqual(
                    VERIFY._qualification_review_signature_policy(
                        record,
                        kind=kind,
                        reviewer=human_reviewer,
                        registry_entry=human_registry,
                        source_signer=source,
                    ),
                    (
                        "haldir-lead-review-v2",
                        source["principal"],
                        source["public_key"],
                        source["key_fingerprint"],
                    ),
                )
        wrong_release_flag = copy.deepcopy(human_record)
        with self.assertRaises(VERIFY.CurrentAuditError):
            VERIFY._qualification_review_signature_policy(
                wrong_release_flag,
                kind="SIGNED_RELEASE_DECISION_REVIEW",
                reviewer=human_reviewer,
                registry_entry=human_registry,
                source_signer=source,
            )

        independent_reviewer = {
            "name": "Independent Automated Reviewer",
            "principal": "independent@local.invalid",
            "classification": "INDEPENDENT_AUTOMATED",
            "organization": "Independent Lab",
        }
        independent_record = {
            **automated_record,
            "independent_from_release_author": True,
        }
        self.assertEqual(
            VERIFY._qualification_review_signature_policy(
                independent_record,
                kind="INDEPENDENT_REVIEW",
                reviewer=independent_reviewer,
                registry_entry=registry,
                source_signer=source,
            )[0],
            "haldir-independent-review-v2",
        )
        source_key_reuse = {
            "public_key": source["public_key"],
            "key_fingerprint": source["key_fingerprint"],
        }
        with self.assertRaisesRegex(
            VERIFY.CurrentAuditError,
            "INDEPENDENT_KEY_NOT_DISTINCT",
        ):
            VERIFY._qualification_review_signature_policy(
                independent_record,
                kind="INDEPENDENT_REVIEW",
                reviewer=independent_reviewer,
                registry_entry=source_key_reuse,
                source_signer=source,
            )
        missing_signature = copy.deepcopy(independent_record)
        missing_signature["detached_signature"] = None
        with self.assertRaisesRegex(
            VERIFY.CurrentAuditError,
            "REVIEW_AUTHORITY_BOUNDARY",
        ):
            VERIFY._qualification_review_signature_policy(
                missing_signature,
                kind="INDEPENDENT_REVIEW",
                reviewer=independent_reviewer,
                registry_entry=registry,
                source_signer=source,
            )

    def test_automated_lead_support_attestation_uses_distinct_signature_domain(
        self,
    ) -> None:
        with FIXTURES.signed_repository(self.repo.parent) as fixture:
            reviewer = {
                "name": "CH-T001 Automated Lead-Support Reviewer",
                "principal": "lead-support@local.invalid",
                "classification": "AUTOMATED_LEAD_SUPPORT",
                "organization": "SEPAHEAD",
            }
            record = {
                "id": "CH-T001-R03",
                "kind": "LEAD_IMPLEMENTATION_REVIEW",
                "file": {
                    "path": "review.json",
                    "sha256": "1" * 64,
                    "bytes": 10,
                    "lines": 1,
                    "git_mode": "100644",
                    "git_object_type": "blob",
                    "git_object_id": "2" * 40,
                },
                "reviewer": reviewer,
                "independent_from_release_author": False,
                "external": False,
                "human": False,
                "named_human_reviewer": False,
                "release_approver": False,
                "reproduced_decisive_evidence": True,
                "reviewed_all_changed_lines_and_context": True,
                "decision": "ACCEPT_TECHNICAL_TASK_QUALIFICATION",
                "started_at_utc": "2026-07-14T20:00:00Z",
                "completed_at_utc": "2026-07-14T20:01:00Z",
                "detached_signature": None,
            }
            context = {
                "task_id": "CH-T001",
                "epoch": 1,
                "freeze_commit": "3" * 40,
                "implementation_commit": "4" * 40,
            }
            payload = VERIFY._review_attestation_payload(record, **context)
            attestation = FIXTURES.detached_attestation(
                fixture,
                payload,
                namespace="haldir-automated-lead-support-v2",
                principal=reviewer["principal"],
            )
            record["detached_signature"] = attestation
            registry = {
                "public_key": attestation["public_key"],
                "key_fingerprint": attestation["key_fingerprint"],
            }
            policy = VERIFY._qualification_review_signature_policy(
                record,
                kind="LEAD_IMPLEMENTATION_REVIEW",
                reviewer=reviewer,
                registry_entry=registry,
                source_signer=VERIFY._source_release_signer(self.repo),
            )
            self.assertEqual(policy[0], "haldir-automated-lead-support-v2")
            VERIFY._verify_ssh_detached_attestation(
                self.repo,
                attestation,
                payload,
                namespace=policy[0],
                label="test.automated-lead-support",
                expected_principal=policy[1],
                expected_public_key=policy[2],
                expected_fingerprint=policy[3],
            )
            for wrong_namespace in (
                "haldir-independent-review-v2",
                "haldir-lead-review-v2",
            ):
                with self.subTest(wrong_namespace=wrong_namespace):
                    with self.assertRaises(VERIFY.CurrentAuditError):
                        VERIFY._verify_ssh_detached_attestation(
                            self.repo,
                            attestation,
                            payload,
                            namespace=wrong_namespace,
                            label="test.automated-lead-support.cross-domain",
                            expected_principal=policy[1],
                            expected_public_key=policy[2],
                            expected_fingerprint=policy[3],
                        )

    def test_review_attestation_replay_is_context_bound(self) -> None:
        with FIXTURES.signed_repository(self.repo.parent) as fixture:
            record = {
                "id": "CH-T001-R01",
                "kind": "INDEPENDENT_REVIEW",
                "file": {
                    "path": "review.json",
                    "sha256": "1" * 64,
                    "bytes": 10,
                    "lines": 1,
                    "git_mode": "100644",
                    "git_object_type": "blob",
                    "git_object_id": "2" * 40,
                },
                "reviewer": {
                    "name": "Reviewer One",
                    "principal": "reviewer-one@example.test",
                    "classification": "INDEPENDENT_AUTOMATED",
                    "organization": "Independent Lab",
                },
                "independent_from_release_author": True,
                "external": False,
                "human": False,
                "named_human_reviewer": False,
                "release_approver": False,
                "reproduced_decisive_evidence": True,
                "reviewed_all_changed_lines_and_context": True,
                "decision": "ACCEPT_TECHNICAL_TASK_QUALIFICATION",
                "started_at_utc": "2026-07-14T20:00:00Z",
                "completed_at_utc": "2026-07-14T20:01:00Z",
                "detached_signature": None,
            }
            context = {
                "task_id": "CH-T001",
                "epoch": 1,
                "freeze_commit": "3" * 40,
                "implementation_commit": "4" * 40,
            }
            payload = VERIFY._review_attestation_payload(record, **context)
            attestation = FIXTURES.detached_attestation(
                fixture,
                payload,
                namespace="haldir-independent-review-v2",
                principal="reviewer-one@example.test",
            )
            self.assertEqual(
                VERIFY._verify_ssh_detached_attestation(
                    self.repo,
                    attestation,
                    payload,
                    namespace="haldir-independent-review-v2",
                    label="test.review-envelope",
                    expected_principal=attestation["principal"],
                    expected_public_key=attestation["public_key"],
                    expected_fingerprint=attestation["key_fingerprint"],
                ),
                attestation,
            )
            with self.assertRaises(VERIFY.CurrentAuditError):
                VERIFY._verify_ssh_detached_attestation(
                    self.repo,
                    attestation,
                    payload,
                    namespace="haldir-automated-lead-support-v2",
                    label="test.review-envelope.cross-domain",
                    expected_principal=attestation["principal"],
                    expected_public_key=attestation["public_key"],
                    expected_fingerprint=attestation["key_fingerprint"],
                )
            mutations: list[tuple[str, dict[str, object], dict[str, object]]] = []
            for field, replacement in (
                ("task_id", "CH-T002"),
                ("epoch", 2),
                ("freeze_commit", "5" * 40),
                ("implementation_commit", "6" * 40),
            ):
                changed_context = copy.deepcopy(context)
                changed_context[field] = replacement
                mutations.append((field, copy.deepcopy(record), changed_context))
            for label, mutate in (
                ("id", lambda value: value.__setitem__("id", "CH-T001-R02")),
                (
                    "kind",
                    lambda value: value.__setitem__(
                        "kind", "LEAD_IMPLEMENTATION_REVIEW"
                    ),
                ),
                (
                    "file-path",
                    lambda value: value["file"].__setitem__("path", "other.json"),
                ),
                (
                    "file-digest",
                    lambda value: value["file"].__setitem__("sha256", "7" * 64),
                ),
                (
                    "reviewer",
                    lambda value: value["reviewer"].__setitem__(
                        "principal", "other@example.test"
                    ),
                ),
                (
                    "timestamp",
                    lambda value: value.__setitem__(
                        "completed_at_utc", "2026-07-14T20:02:00Z"
                    ),
                ),
            ):
                changed_record = copy.deepcopy(record)
                mutate(changed_record)
                mutations.append((label, changed_record, copy.deepcopy(context)))
            for label, changed_record, changed_context in mutations:
                with self.subTest(label=label):
                    changed_payload = VERIFY._review_attestation_payload(
                        changed_record, **changed_context
                    )
                    with self.assertRaises(VERIFY.CurrentAuditError):
                        VERIFY._verify_ssh_detached_attestation(
                            self.repo,
                            attestation,
                            changed_payload,
                            namespace="haldir-independent-review-v2",
                            label=f"test.review-envelope.{label}",
                            expected_principal=attestation["principal"],
                            expected_public_key=attestation["public_key"],
                            expected_fingerprint=attestation["key_fingerprint"],
                        )

    def test_qualification_limitations_preserve_complete_cumulative_union(self) -> None:
        prior = ["prior-a", "prior-b"]
        outcome = ["outcome-a"]
        reports = {
            "R01": {"findings": ["finding-a"], "limitations": ["review-a"]},
            "R02": {"findings": ["finding-b"], "limitations": ["review-b"]},
        }
        dispositions = {"finding-residual"}
        lenses = {"lens-a", "lens-b"}
        complete = sorted(
            {
                *prior,
                *outcome,
                "review-a",
                "review-b",
                *dispositions,
                *lenses,
            }
        )
        self.assertEqual(
            VERIFY._require_complete_qualification_limitations(
                complete,
                prior_limitations=prior,
                outcome_limitations=outcome,
                review_reports=reports,
                disposition_residuals=dispositions,
                lens_residuals=lenses,
            ),
            complete,
        )
        for omitted in complete:
            with self.subTest(omitted=omitted):
                with self.assertRaises(VERIFY.CurrentAuditError):
                    VERIFY._require_complete_qualification_limitations(
                        [item for item in complete if item != omitted],
                        prior_limitations=prior,
                        outcome_limitations=outcome,
                        review_reports=reports,
                        disposition_residuals=dispositions,
                        lens_residuals=lenses,
                    )

    def test_ch_t000_residual_union_seeds_and_propagates_active_claims(self) -> None:
        review = VERIFY.ch_t000_review_fixed_template(VERIFY.SOURCE_COMMIT)
        expected = sorted(
            {
                review["process_deviation"]["residual_limitation"],
                *review["review_limitations"],
                *(
                    lens["residual_limitation"]
                    for lens in review["twenty_lens_reviews"].values()
                ),
            }
        )
        self.assertEqual(VERIFY.ch_t000_initial_residual_limitations(), expected)
        initial = VERIFY._expected_initial_active_claims(
            self.repo, VERIFY.SOURCE_COMMIT
        )
        self.assertEqual(initial["residual_limitations"], expected)
        before = VERIFY._initial_claims_before_ch_t000(self.repo, VERIFY.SOURCE_COMMIT)
        self.assertEqual(before["residual_limitations"], [])

        successor_limitations = [*expected, "CH-T001-RESIDUAL"]
        outcome = {
            "overall_status": "NO_GO",
            "active_claims": initial["active_claims"],
            "release_qualified_claims": initial["release_qualified_claims"],
            "removed_claims": initial["removed_claims"],
            "non_claimed_claims": initial["non_claimed_claims"],
            "narrowed_claims": initial["narrowed_claims"],
            "public_surfaces": [],
        }
        advanced = VERIFY._successor_active_claims(
            initial,
            repo=self.repo,
            implementation_commit=VERIFY.SOURCE_COMMIT,
            task_id="CH-T001",
            epoch=1,
            outcome=outcome,
            qualification={"limitations": successor_limitations},
        )
        self.assertEqual(advanced["residual_limitations"], successor_limitations)

    def test_each_successor_requires_post_implementation_lead_review(self) -> None:
        for task_id, extra in (
            ("CH-T001", set()),
            (
                "CH-T115",
                {
                    "EXTERNAL_CRYPTOGRAPHIC_REVIEW",
                    "EXTERNAL_FORMAL_METHODS_REVIEW",
                    "EXTERNAL_SECURE_DEPLOYMENT_REVIEW",
                },
            ),
            ("CH-T120", {"EXTERNAL_CLEAN_ROOM_REPRODUCTION"}),
            ("CH-T124", {"LEAD_ONLY_TWENTY_LENS_DIFF_REVIEW"}),
            ("CH-T125", {"SIGNED_RELEASE_DECISION_REVIEW"}),
        ):
            complete = sorted(
                {"INDEPENDENT_REVIEW", "LEAD_IMPLEMENTATION_REVIEW", *extra}
            )
            with self.subTest(task_id=task_id, state="complete"):
                self.assertIsNone(
                    VERIFY._require_source_review_kinds(task_id, complete)
                )
            with self.subTest(task_id=task_id, state="missing-lead"):
                with self.assertRaises(VERIFY.CurrentAuditError):
                    VERIFY._require_source_review_kinds(
                        task_id,
                        [
                            kind
                            for kind in complete
                            if kind != "LEAD_IMPLEMENTATION_REVIEW"
                        ],
                    )
        ordinary = ["INDEPENDENT_REVIEW", "LEAD_IMPLEMENTATION_REVIEW"]
        for task_id, required_designated, wrong_designated in (
            ("CH-T001", None, "LEAD_ONLY_TWENTY_LENS_DIFF_REVIEW"),
            (
                "CH-T124",
                "LEAD_ONLY_TWENTY_LENS_DIFF_REVIEW",
                "SIGNED_RELEASE_DECISION_REVIEW",
            ),
            (
                "CH-T125",
                "SIGNED_RELEASE_DECISION_REVIEW",
                "LEAD_ONLY_TWENTY_LENS_DIFF_REVIEW",
            ),
        ):
            observed = [*ordinary]
            if required_designated is not None:
                observed.append(required_designated)
            observed.append(wrong_designated)
            with self.subTest(task_id=task_id, premature=wrong_designated):
                with self.assertRaisesRegex(
                    VERIFY.CurrentAuditError,
                    "PREMATURE_LEAD_AUTHORITY",
                ):
                    VERIFY._require_source_review_kinds(task_id, observed)

    def test_surface_inventory_binds_public_consumers_and_gate_paths(self) -> None:
        plan = {
            "README.md": "M",
            "src/internal-probe.bin": "A",
        }
        inventory = [
            {
                "path": "README.md",
                "planned_status": "M",
                "classification": "PUBLIC_DOCUMENTATION",
                "claim_relevance": "PUBLIC_CLAIM_REVIEW_REQUIRED",
                "in_repository_consumers": [
                    "docs/CLAIM-LEDGER.md",
                    "src/internal-probe.bin",
                ],
                "external_consumers": ["repository users"],
                "rationale": "Public wording and its claim inventory require joint review.",
            },
            {
                "path": "src/internal-probe.bin",
                "planned_status": "A",
                "classification": "INTERNAL_IMPLEMENTATION",
                "claim_relevance": "SEMANTIC_REVIEW_REQUIRED",
                "in_repository_consumers": ["README.md"],
                "external_consumers": [],
                "rationale": "Synthetic internal path used to exercise exact inventory binding.",
            },
        ]
        self.assertEqual(
            VERIFY._validate_affected_surface_inventory(
                self.repo,
                VERIFY.SOURCE_COMMIT,
                inventory,
                plan=plan,
            ),
            inventory,
        )
        for label, mutation in (
            (
                "missing-consumers",
                {
                    **inventory[0],
                    "in_repository_consumers": [],
                    "external_consumers": [],
                },
            ),
            (
                "wrong-class",
                {**inventory[0], "classification": "INTERNAL_IMPLEMENTATION"},
            ),
            (
                "self-consumer",
                {**inventory[0], "in_repository_consumers": ["README.md"]},
            ),
            (
                "absent-non-plan-consumer",
                {
                    **inventory[0],
                    "in_repository_consumers": ["missing-consumer.txt"],
                },
            ),
            (
                "escaping-consumer",
                {**inventory[0], "in_repository_consumers": ["../outside"]},
            ),
        ):
            changed = copy.deepcopy(inventory)
            changed[0] = mutation
            with self.subTest(label=label):
                with self.assertRaises(VERIFY.CurrentAuditError):
                    VERIFY._validate_affected_surface_inventory(
                        self.repo,
                        VERIFY.SOURCE_COMMIT,
                        changed,
                        plan=plan,
                    )
        deleted_plan = {**plan, "src/deleted-consumer.bin": "D"}
        deleted_inventory = copy.deepcopy(inventory)
        deleted_inventory.append(
            {
                "path": "src/deleted-consumer.bin",
                "planned_status": "D",
                "classification": "INTERNAL_IMPLEMENTATION",
                "claim_relevance": "SEMANTIC_REVIEW_REQUIRED",
                "in_repository_consumers": [],
                "external_consumers": [],
                "rationale": "Deleted fixture path.",
            }
        )
        deleted_inventory[0]["in_repository_consumers"] = ["src/deleted-consumer.bin"]
        with self.assertRaises(VERIFY.CurrentAuditError):
            VERIFY._validate_affected_surface_inventory(
                self.repo,
                VERIFY.SOURCE_COMMIT,
                deleted_inventory,
                plan=deleted_plan,
            )
        for path in (
            "release/0.9.0/allowed-signers",
            ".github/workflows/ci.yml",
            "justfile",
            "tools/p0r-exit-gate.sh",
            "tools/release/current-audit-gate.sh",
        ):
            with self.subTest(forbidden=path):
                self.assertTrue(VERIFY._implementation_path_is_forbidden(path))

    def test_surface_classification_covers_public_docs_build_policy_and_api(
        self,
    ) -> None:
        cases = {
            "README.md": "PUBLIC_DOCUMENTATION",
            "SECURITY.md": "PUBLIC_DOCUMENTATION",
            "CONTRIBUTING.md": "PUBLIC_DOCUMENTATION",
            "LICENSE-APACHE": "PUBLIC_DOCUMENTATION",
            "assets/logo-light.svg": "PUBLIC_DOCUMENTATION",
            "docs/THREAT-MODEL.md": "PUBLIC_DOCUMENTATION",
            "evidence/README.md": "PUBLIC_DOCUMENTATION",
            "formal/README.md": "PUBLIC_DOCUMENTATION",
            "tools/live-secure-zenoh/README.md": "PUBLIC_DOCUMENTATION",
            "tools/live-gate-dev-smoke/README.md": "PUBLIC_DOCUMENTATION",
            "crates/haldir-core/src/lib.rs": "PUBLIC_API_OR_SCHEMA",
            "contracts/vectors/example.cbor": "PUBLIC_API_OR_SCHEMA",
            "release/0.9.0/authority-model.json": "PUBLIC_API_OR_SCHEMA",
            "tools/haldir-ctl/src/main.rs": "PUBLIC_API_OR_SCHEMA",
            "Cargo.toml": "BUILD_OR_DEPLOYMENT",
            "deny.toml": "BUILD_OR_DEPLOYMENT",
            "rust-toolchain.toml": "BUILD_OR_DEPLOYMENT",
            ".github/workflows/ci.yml": "BUILD_OR_DEPLOYMENT",
            "deploy/secure/profile.json": "BUILD_OR_DEPLOYMENT",
            "tools/release/verify.py": "TEST_OR_TOOLING",
            "formal/HaldirAuthority.tla": "INTERNAL_IMPLEMENTATION",
        }
        inventory = []
        for path, expected in cases.items():
            with self.subTest(path=path):
                self.assertEqual(VERIFY._surface_classification(path), expected)
            inventory.append({"path": path, "classification": expected})
        self.assertEqual(
            VERIFY._expected_public_surface_paths(inventory),
            sorted(
                path
                for path, classification in cases.items()
                if classification in VERIFY.PUBLIC_SURFACE_CLASSIFICATIONS
            ),
        )

    def test_control_and_counterfactual_ids_are_category_exact_and_disjoint(
        self,
    ) -> None:
        controls = [
            {
                "id": "CH-T001-N01",
                "statement": "The implementation SHALL fail closed.",
                "accepted_test_id": "test_accept",
                "rejected_test_id": "test_reject",
            }
        ]
        counterfactuals = [
            {
                "id": f"CH-T001-CF{index:02d}",
                "statement": statement,
                "accepted_test_id": "test_accept",
                "rejected_test_id": "test_reject",
            }
            for index, statement in enumerate(
                VERIFY.HANDOFF_COUNTERFACTUALS,
                start=1,
            )
        ]
        self.assertEqual(
            VERIFY._validate_normative_controls_and_counterfactuals(
                controls,
                counterfactuals,
                task_id="CH-T001",
            ),
            (controls, counterfactuals),
        )
        swapped_control = copy.deepcopy(controls)
        swapped_control[0]["id"] = "CH-T001-CF01"
        with self.assertRaises(VERIFY.CurrentAuditError):
            VERIFY._validate_normative_controls_and_counterfactuals(
                swapped_control,
                counterfactuals,
                task_id="CH-T001",
            )
        cross_list_collision = copy.deepcopy(counterfactuals)
        cross_list_collision[0]["id"] = "CH-T001-N01"
        with self.assertRaises(VERIFY.CurrentAuditError):
            VERIFY._validate_normative_controls_and_counterfactuals(
                controls,
                cross_list_collision,
                task_id="CH-T001",
            )
        shifted_counterfactuals = copy.deepcopy(counterfactuals)
        for index, record in enumerate(shifted_counterfactuals, start=11):
            record["id"] = f"CH-T001-CF{index:02d}"
        with self.assertRaises(VERIFY.CurrentAuditError):
            VERIFY._validate_normative_controls_and_counterfactuals(
                controls,
                shifted_counterfactuals,
                task_id="CH-T001",
            )

    def test_combined_attack_matrix_binds_all_source_attacks(self) -> None:
        fixture = self.preimplementation_schema_fixture()
        attacks = fixture["attacks"]
        self.assertEqual(
            VERIFY._validate_combined_attack_matrix(attacks, task_id="CH-T001"),
            (attacks, {"test_accept", "test_reject"}),
        )
        mutations = []
        wrong_statement = copy.deepcopy(attacks)
        wrong_statement[0]["statement"] = "substituted attack"
        mutations.append(wrong_statement)
        not_applicable_with_tests = copy.deepcopy(attacks)
        not_applicable_with_tests[1]["accepted_test_id"] = "test_accept"
        mutations.append(not_applicable_with_tests)
        applicable_without_tests = copy.deepcopy(attacks)
        applicable_without_tests[0]["accepted_test_id"] = None
        mutations.append(applicable_without_tests)
        missing_attack = copy.deepcopy(attacks[:-1])
        mutations.append(missing_attack)
        for mutation in mutations:
            with self.subTest(mutation=mutations.index(mutation)):
                with self.assertRaises(VERIFY.CurrentAuditError):
                    VERIFY._validate_combined_attack_matrix(
                        mutation,
                        task_id="CH-T001",
                    )

    def test_handoff_command_mapping_binds_exact_command_and_task_boundary(
        self,
    ) -> None:
        fixture = self.preimplementation_schema_fixture()
        commands = fixture["commands"]
        self.assertEqual(
            VERIFY._validate_handoff_command_mapping(
                commands,
                task_id="CH-T001",
            ),
            commands,
        )
        mutations = []
        wrong_source = copy.deepcopy(commands)
        wrong_source[0]["source_command"] += " --changed"
        mutations.append(wrong_source)
        deferred_to_current = copy.deepcopy(commands)
        deferred_to_current[2]["task_boundary"] = "CH-T001"
        mutations.append(deferred_to_current)
        retained_from_future = copy.deepcopy(commands)
        retained_from_future[0]["task_boundary"] = "CH-T002"
        mutations.append(retained_from_future)
        false_exact_execution = copy.deepcopy(commands)
        false_exact_execution[1].update(
            {
                "disposition": "EXECUTED_EXACTLY",
                "replacement_commands": ["different command"],
            }
        )
        mutations.append(false_exact_execution)
        multiline_replacement = copy.deepcopy(commands)
        multiline_replacement[1]["replacement_commands"] = [
            "python3 safe-command.py\npython3 hidden-command.py"
        ]
        mutations.append(multiline_replacement)
        noncanonical_rationale = copy.deepcopy(commands)
        noncanonical_rationale[1]["rationale"] += " "
        mutations.append(noncanonical_rationale)
        for mutation in mutations:
            with self.subTest(mutation=mutations.index(mutation)):
                with self.assertRaises(VERIFY.CurrentAuditError):
                    VERIFY._validate_handoff_command_mapping(
                        mutation,
                        task_id="CH-T001",
                    )

    def test_threat_model_requires_every_mandatory_field_and_bound_list(self) -> None:
        fixture = self.preimplementation_schema_fixture()
        threats = fixture["threats"]
        self.assertEqual(
            VERIFY._validate_threat_model(threats, task_id="CH-T001"),
            threats,
        )
        mutations = []
        missing_field = copy.deepcopy(threats)
        del missing_field[0]["owner"]
        mutations.append(missing_field)
        empty_test_set = copy.deepcopy(threats)
        empty_test_set[0]["tests"] = []
        mutations.append(empty_test_set)
        duplicate_id = copy.deepcopy(threats)
        duplicate_id.append(copy.deepcopy(duplicate_id[0]))
        mutations.append(duplicate_id)
        wrong_task = copy.deepcopy(threats)
        wrong_task[0]["threat_id"] = "CH-T002-TH01"
        mutations.append(wrong_task)
        oversized_text = copy.deepcopy(threats)
        oversized_text[0]["asset_or_claim"] = "x" * 4097
        mutations.append(oversized_text)
        oversized_list_item = copy.deepcopy(threats)
        oversized_list_item[0]["tests"] = ["x" * 4097]
        mutations.append(oversized_list_item)
        for mutation in mutations:
            with self.subTest(mutation=mutations.index(mutation)):
                with self.assertRaises(VERIFY.CurrentAuditError):
                    VERIFY._validate_threat_model(mutation, task_id="CH-T001")

    def test_misuse_interfaces_bind_examples_refusals_and_nonproofs(self) -> None:
        fixture = self.preimplementation_schema_fixture()
        interfaces = fixture["interfaces"]
        self.assertEqual(
            VERIFY._validate_misuse_resistant_interfaces(
                interfaces,
                task_id="CH-T001",
            ),
            interfaces,
        )
        mutations = []
        duplicate_surface = copy.deepcopy(interfaces)
        duplicate_surface[1]["surface"] = duplicate_surface[0]["surface"]
        mutations.append(duplicate_surface)
        not_applicable_with_example = copy.deepcopy(interfaces)
        not_applicable_with_example[1]["wrong_example"] = "hidden runtime call"
        mutations.append(not_applicable_with_example)
        applicable_without_nonproof = copy.deepcopy(interfaces)
        applicable_without_nonproof[0]["non_proofs"] = []
        mutations.append(applicable_without_nonproof)
        indistinguishable_examples = copy.deepcopy(interfaces)
        indistinguishable_examples[0]["wrong_example"] = (
            "  GENERATE INTO AN ABSENT CANONICAL TARGET  "
        )
        mutations.append(indistinguishable_examples)
        oversized_nonproof = copy.deepcopy(interfaces)
        oversized_nonproof[0]["non_proofs"] = ["x" * 4097]
        mutations.append(oversized_nonproof)
        wrong_task = copy.deepcopy(interfaces)
        wrong_task[0]["id"] = "CH-T002-MI01"
        mutations.append(wrong_task)
        for mutation in mutations:
            with self.subTest(mutation=mutations.index(mutation)):
                with self.assertRaises(VERIFY.CurrentAuditError):
                    VERIFY._validate_misuse_resistant_interfaces(
                        mutation,
                        task_id="CH-T001",
                    )

    def test_preimplementation_references_reject_every_dangling_link(self) -> None:
        fixture = self.preimplementation_schema_fixture()
        controls = [
            {
                "id": "CH-T001-N01",
                "statement": "The product SHALL fail closed.",
                "accepted_test_id": "test_accept",
                "rejected_test_id": "test_reject",
            }
        ]
        counterfactuals = [
            {
                "id": "CH-T001-CF01",
                "statement": VERIFY.HANDOFF_COUNTERFACTUALS[0],
                "accepted_test_id": "test_accept",
                "rejected_test_id": "test_reject",
            }
        ]
        base = {
            "controls": controls,
            "counterfactuals": counterfactuals,
            "combined_attacks": fixture["attacks"],
            "combined_attack_test_ids": {"test_accept", "test_reject"},
            "handoff_commands": fixture["commands"],
            "threats": fixture["threats"],
            "misuse_interfaces": fixture["interfaces"],
            "discovered_test_ids": {"test_accept", "test_reject"},
            "qualification_evidence_ids": {"CH-T001-E01"},
        }
        self.assertIsNone(VERIFY._validate_preimplementation_references(**base))
        mutations: list[tuple[str, dict[str, object]]] = []
        attack_control = copy.deepcopy(base)
        attack_control["combined_attacks"][0]["control_ids"] = ["CH-T001-N99"]
        mutations.append(("attack-control", attack_control))
        attack_test = copy.deepcopy(base)
        attack_test["combined_attack_test_ids"] = {"missing_test"}
        mutations.append(("attack-test", attack_test))
        attack_evidence = copy.deepcopy(base)
        attack_evidence["combined_attacks"][0]["evidence_ids"] = ["CH-T001-E99"]
        mutations.append(("attack-evidence", attack_evidence))
        threat_preventive = copy.deepcopy(base)
        threat_preventive["threats"][0]["preventive_controls"] = ["CH-T001-N99"]
        mutations.append(("threat-preventive", threat_preventive))
        threat_detective = copy.deepcopy(base)
        threat_detective["threats"][0]["detective_controls"] = ["CH-T001-N99"]
        mutations.append(("threat-detective", threat_detective))
        threat_test = copy.deepcopy(base)
        threat_test["threats"][0]["tests"] = ["missing_test"]
        mutations.append(("threat-test", threat_test))
        threat_evidence = copy.deepcopy(base)
        threat_evidence["threats"][0]["evidence"] = ["CH-T001-E99"]
        mutations.append(("threat-evidence", threat_evidence))
        misuse_invariant = copy.deepcopy(base)
        misuse_invariant["misuse_interfaces"][0]["invariant_ids"] = ["CH-T001-N99"]
        mutations.append(("misuse-invariant", misuse_invariant))
        misuse_test = copy.deepcopy(base)
        misuse_test["misuse_interfaces"][0]["test_ids"] = ["missing_test"]
        mutations.append(("misuse-test", misuse_test))
        misuse_evidence = copy.deepcopy(base)
        misuse_evidence["misuse_interfaces"][0]["evidence_ids"] = ["CH-T001-E99"]
        mutations.append(("misuse-evidence", misuse_evidence))
        command_evidence = copy.deepcopy(base)
        command_evidence["handoff_commands"][0]["evidence_ids"] = ["CH-T001-E99"]
        mutations.append(("command-evidence", command_evidence))
        for label, mutation in mutations:
            with self.subTest(label=label):
                with self.assertRaisesRegex(
                    VERIFY.CurrentAuditError,
                    "PREIMPLEMENTATION_REFERENCES",
                ):
                    VERIFY._validate_preimplementation_references(**mutation)

    def test_requirement_ids_are_globally_disjoint_across_categories(self) -> None:
        catalog = {
            "qualification_evidence_requirements": {"CH-T001-E01"},
            "review_requirements": {"CH-T001-R01"},
            "activation_evidence_requirements": {"CH-T001-A01"},
        }
        self.assertIsNone(VERIFY._require_disjoint_requirement_ids(catalog))
        duplicate = copy.deepcopy(catalog)
        duplicate["activation_evidence_requirements"].add("CH-T001-R01")
        with self.assertRaises(VERIFY.CurrentAuditError):
            VERIFY._require_disjoint_requirement_ids(duplicate)

    def test_requirement_catalog_entries_bind_task_category_and_path(self) -> None:
        cases = (
            (
                "E",
                "qualification_evidence_requirements",
                "release/0.9.0/current-head/tasks/ch-t001/e0001/evidence/",
            ),
            (
                "R",
                "review_requirements",
                "release/0.9.0/current-head/tasks/ch-t001/e0001/reviews/",
            ),
            (
                "A",
                "activation_evidence_requirements",
                "release/0.9.0/current-head/tasks/ch-t001/e0001/activation-evidence/",
            ),
        )
        for identifier_class, field, prefix in cases:
            item = {
                "id": f"CH-T001-{identifier_class}01",
                "path": f"{prefix}{identifier_class.lower()}01.json",
                "kind": "EXACT_TEST_EVIDENCE",
                "max_bytes": 4096,
            }
            with self.subTest(identifier_class=identifier_class, state="valid"):
                self.assertEqual(
                    VERIFY._validate_requirement_catalog_entry(
                        item,
                        task_id="CH-T001",
                        identifier_class=identifier_class,
                        path_prefix=prefix,
                        field=field,
                    ),
                    item,
                )
            for label, mutate in (
                (
                    "wrong-task",
                    lambda value: value.__setitem__(
                        "id", f"CH-T002-{identifier_class}01"
                    ),
                ),
                (
                    "wrong-category",
                    lambda value: value.__setitem__(
                        "id",
                        f"CH-T001-{'R' if identifier_class != 'R' else 'E'}01",
                    ),
                ),
                (
                    "wrong-path",
                    lambda value: value.__setitem__("path", "outside/e01.json"),
                ),
                (
                    "boolean-max",
                    lambda value: value.__setitem__("max_bytes", True),
                ),
            ):
                mutation = copy.deepcopy(item)
                mutate(mutation)
                with self.subTest(identifier_class=identifier_class, state=label):
                    with self.assertRaises(VERIFY.CurrentAuditError):
                        VERIFY._validate_requirement_catalog_entry(
                            mutation,
                            task_id="CH-T001",
                            identifier_class=identifier_class,
                            path_prefix=prefix,
                            field=field,
                        )

    def test_migration_disposition_allows_none_or_scoped_subset_only(self) -> None:
        plan = {"docs/MIGRATION.md": "M", "src/internal.bin": "A"}
        no_migration = {
            "required": False,
            "paths": [],
            "disposition": "No preexisting interface or data requires migration.",
        }
        scoped = {
            "required": True,
            "paths": ["docs/MIGRATION.md"],
            "disposition": "The documented public transition requires migration.",
        }
        for value in (no_migration, scoped):
            with self.subTest(valid=value["required"]):
                self.assertEqual(
                    VERIFY._validate_migration_disposition(value, plan=plan),
                    value,
                )
        mutations = []
        outside = copy.deepcopy(scoped)
        outside["paths"] = ["outside/path"]
        mutations.append(outside)
        unsorted = copy.deepcopy(scoped)
        unsorted["paths"] = ["src/internal.bin", "docs/MIGRATION.md"]
        mutations.append(unsorted)
        false_with_paths = copy.deepcopy(scoped)
        false_with_paths["required"] = False
        mutations.append(false_with_paths)
        true_without_paths = copy.deepcopy(no_migration)
        true_without_paths["required"] = True
        mutations.append(true_without_paths)
        nonboolean = copy.deepcopy(no_migration)
        nonboolean["required"] = 0
        mutations.append(nonboolean)
        for mutation in mutations:
            with self.subTest(mutation=mutations.index(mutation)):
                with self.assertRaises(VERIFY.CurrentAuditError):
                    VERIFY._validate_migration_disposition(mutation, plan=plan)

    def test_freeze_packet_digest_binds_complete_contract_except_self_reference(
        self,
    ) -> None:
        contract = {
            "implementation_plan": {"tool.py": "A"},
            "verification_triggers": {"paths": ["tool.py"], "roots": []},
            "resource_budgets": {"json_bytes": 1024},
            "reviewer_registry": [{"requirement_id": "CH-T001-R01"}],
            "claim_outcomes": [{"id": "CH-T001-O01"}],
            "lead_approval": {"freeze_packet_sha256": "0" * 64},
        }
        digest = VERIFY._freeze_packet_digest(contract)
        for field in (
            "implementation_plan",
            "verification_triggers",
            "resource_budgets",
            "reviewer_registry",
            "claim_outcomes",
        ):
            mutation = copy.deepcopy(contract)
            mutation[field] = {"changed": field}
            with self.subTest(field=field):
                self.assertNotEqual(VERIFY._freeze_packet_digest(mutation), digest)
        self_reference_only = copy.deepcopy(contract)
        self_reference_only["lead_approval"] = {"freeze_packet_sha256": "f" * 64}
        self.assertEqual(
            VERIFY._freeze_packet_digest(self_reference_only),
            digest,
        )

    def test_review_report_covers_planned_consumers_in_diff_and_existing_context(
        self,
    ) -> None:
        implementation_plan = {
            "README.md": "M",
            "src/new-consumer.bin": "A",
        }
        surface_inventory = [
            {
                "path": "README.md",
                "in_repository_consumers": [
                    "docs/CLAIM-LEDGER.md",
                    "src/new-consumer.bin",
                ],
            },
            {
                "path": "src/new-consumer.bin",
                "in_repository_consumers": ["README.md"],
            },
        ]
        reviewer = {
            "name": "Independent Reviewer",
            "principal": "independent@local.invalid",
            "classification": "INDEPENDENT_AUTOMATED",
            "organization": "Independent Lab",
        }
        requirement = {
            "id": "CH-T001-R01",
            "kind": "INDEPENDENT_REVIEW",
            "path": "release/0.9.0/current-head/tasks/ch-t001/e0001/reviews/r01.json",
        }

        def file_record(_repo: Path, _commit: str, path: str) -> dict[str, object]:
            digest = hashlib.sha256(path.encode("utf-8")).hexdigest()
            return {
                "path": path,
                "sha256": digest,
                "bytes": len(path.encode("utf-8")),
                "git_mode": "100644",
                "git_object_type": "blob",
                "git_object_id": digest[:40],
            }

        changed_records = [
            file_record(self.repo, "4" * 40, path) for path in implementation_plan
        ]
        existing_context = file_record(
            self.repo,
            "4" * 40,
            "docs/CLAIM-LEDGER.md",
        )
        report = {
            "schema_version": "1.0.0",
            "task_id": "CH-T001",
            "epoch": 1,
            "requirement": requirement,
            "reviewer": reviewer,
            "freeze_commit": "3" * 40,
            "implementation_commit": "4" * 40,
            "implementation_diff": {
                "statuses": implementation_plan,
                "changed_file_records": changed_records,
                "deleted_paths": [],
            },
            "all_changed_lines_reviewed": True,
            "reviewed_relevant_context": [existing_context],
            "relevant_unchanged_context_reviewed": True,
            "decisive_reproduction": {
                "evidence_ids": ["CH-T001-E01"],
                "commands": ["python3 -m unittest"],
                "result": "PASS",
            },
            "reviewer_provenance": {
                "method": "deterministic agent review",
                "tool": "codex",
                "version": "test-only",
                "session_id": "test-session",
            },
            "findings": ["NO_OPEN_FINDING"],
            "limitations": ["AUTOMATED_REVIEW_ONLY"],
            "decision": "ACCEPT_TECHNICAL_TASK_QUALIFICATION",
        }
        payload = (json.dumps(report, sort_keys=True) + "\n").encode("utf-8")
        with mock.patch.object(
            VERIFY,
            "_commit_regular_file_record",
            side_effect=file_record,
        ):
            self.assertEqual(
                VERIFY._validate_independent_review_report(
                    self.repo,
                    payload,
                    task_id="CH-T001",
                    epoch=1,
                    reviewer=reviewer,
                    freeze_commit="3" * 40,
                    implementation_commit="4" * 40,
                    implementation_plan=implementation_plan,
                    surface_inventory=surface_inventory,
                    evidence_ids=["CH-T001-E01"],
                    requirement={**requirement, "max_bytes": 4096},
                ),
                {
                    "findings": ["NO_OPEN_FINDING"],
                    "limitations": ["AUTOMATED_REVIEW_ONLY"],
                },
            )
            missing_context = copy.deepcopy(report)
            missing_context["reviewed_relevant_context"] = [
                file_record(
                    self.repo,
                    "4" * 40,
                    "docs/LIMITATIONS.md",
                )
            ]
            with self.assertRaisesRegex(
                VERIFY.CurrentAuditError,
                "REVIEW_CONSUMER_OMISSION",
            ):
                VERIFY._validate_independent_review_report(
                    self.repo,
                    (json.dumps(missing_context, sort_keys=True) + "\n").encode(
                        "utf-8"
                    ),
                    task_id="CH-T001",
                    epoch=1,
                    reviewer=reviewer,
                    freeze_commit="3" * 40,
                    implementation_commit="4" * 40,
                    implementation_plan=implementation_plan,
                    surface_inventory=surface_inventory,
                    evidence_ids=["CH-T001-E01"],
                    requirement={**requirement, "max_bytes": 4096},
                )

    def test_filesystem_walkers_reject_high_fanout_at_node_bound(self) -> None:
        with tempfile.TemporaryDirectory(dir=self.repo.parent) as raw:
            root = Path(raw)
            for index in range(16):
                (root / f"entry-{index:02d}").write_bytes(b"x")
            with mock.patch.object(VERIFY, "MAX_JSON_NODES", 4):
                with self.assertRaisesRegex(
                    VERIFY.CurrentAuditError, "FILESYSTEM_STATE_BOUND"
                ):
                    VERIFY._bounded_filesystem_state(root, "high-fanout")
                with self.assertRaisesRegex(
                    VERIFY.CurrentAuditError, "SNAPSHOT_PERMISSION_BOUND"
                ):
                    VERIFY._make_snapshot_world_readable(root)

    def test_protocol_identity_accepts_real_signed_linear_stage_dag(self) -> None:
        with FIXTURES.signed_repository(shared_root=self.repo.parent) as fixture:
            root = FIXTURES.signed_commit(
                fixture,
                {"framework.txt": b"framework\n"},
                "release: establish disposable framework",
            )
            subjects = (
                "release: freeze disposable successor",
                "release: implement disposable successor",
                "release: qualify disposable successor",
                "release: activate disposable successor",
                "release: revoke disposable successor",
                "release: refreeze disposable successor",
            )
            commits: list[str] = []
            for index, subject in enumerate(subjects, start=1):
                commits.append(
                    FIXTURES.signed_commit(
                        fixture,
                        {"state.txt": f"stage-{index}\n".encode("ascii")},
                        subject,
                    )
                )
            self.assertEqual(FIXTURES.first_parent_chain(fixture), (root, *commits))

            verified: list[str] = []

            def verify_real_signature(_repo: Path, commit: str, _label: str) -> None:
                FIXTURES.verify_signed_commit(fixture, commit)
                verified.append(commit)

            with mock.patch.object(
                VERIFY,
                "_verify_named_commit_signature",
                side_effect=verify_real_signature,
            ):
                parent = root
                for commit in commits:
                    VERIFY._verify_protocol_commit_identity(
                        fixture.path, commit, parent
                    )
                    parent = commit
            self.assertEqual(verified, commits)

    def test_protocol_identity_rejects_real_commit_object_mutations(self) -> None:
        with FIXTURES.signed_repository(shared_root=self.repo.parent) as fixture:
            root = FIXTURES.signed_commit(
                fixture,
                {"root.txt": b"root\n"},
                "release: create disposable root",
            )
            valid = FIXTURES.signed_commit(
                fixture,
                {"state.txt": b"valid\n"},
                "release: create valid disposable stage",
            )
            wrong_identity = FIXTURES.signed_commit(
                fixture,
                {"state.txt": b"wrong identity\n"},
                "release: create wrong identity stage",
                author_name="Different Author",
                author_email="different@example.invalid",
                committer_name="Different Author",
                committer_email="different@example.invalid",
            )
            wrong_subject = FIXTURES.signed_commit(
                fixture,
                {"state.txt": b"wrong subject\n"},
                "invalid disposable subject",
                require_release_subject=False,
            )
            unsigned = FIXTURES.signed_commit(
                fixture,
                {"state.txt": b"unsigned\n"},
                "release: create unsigned disposable stage",
                signed=False,
            )
            merge = FIXTURES.signed_merge_commit(
                fixture,
                unsigned,
                root,
                "release: create forbidden disposable merge",
            )

            def verify_real_signature(_repo: Path, commit: str, _label: str) -> None:
                try:
                    FIXTURES.verify_signed_commit(fixture, commit)
                except FIXTURES.TestFixtureError as error:
                    raise VERIFY.CurrentAuditError(
                        "CURRENT_AUDIT_TEST_SIGNATURE_INVALID"
                    ) from error

            with mock.patch.object(
                VERIFY,
                "_verify_named_commit_signature",
                side_effect=verify_real_signature,
            ):
                VERIFY._verify_protocol_commit_identity(fixture.path, valid, root)
                with self.assertRaises(VERIFY.CurrentAuditError):
                    VERIFY._verify_protocol_commit_identity(
                        fixture.path, valid, "0" * 40
                    )
                with self.assertRaises(VERIFY.CurrentAuditError):
                    VERIFY._verify_protocol_commit_identity(
                        fixture.path, wrong_identity, valid
                    )
                with self.assertRaises(VERIFY.CurrentAuditError):
                    VERIFY._verify_protocol_commit_identity(
                        fixture.path, wrong_subject, wrong_identity
                    )
                with self.assertRaises(VERIFY.CurrentAuditError):
                    VERIFY._verify_protocol_commit_identity(
                        fixture.path, unsigned, wrong_subject
                    )
                with self.assertRaises(VERIFY.CurrentAuditError):
                    VERIFY._verify_protocol_commit_identity(
                        fixture.path, merge, unsigned
                    )

    def test_protocol_resource_budgets_are_strict_json_integers(self) -> None:
        registry = VERIFY._expected_empty_successor_registry("1" * 40, "2" * 40)
        limits = registry["limits"]
        self.assertTrue(all(type(value) is int for value in limits.values()))
        self.assertEqual(
            VERIFY._load_json_bytes(
                FIXTURES.canonical_json(registry), "test.strict-integer-registry"
            ),
            registry,
        )

    def test_frozen_test_counts_preserve_separate_run_summaries(self) -> None:
        head = VERIFY._git(self.repo, "rev-parse", "HEAD").decode("ascii").strip()
        framework_counts = VERIFY._frozen_test_run_counts(self.repo, head)
        self.assertEqual(len(framework_counts), 2)
        self.assertGreater(framework_counts[0], 34)
        self.assertEqual(framework_counts[1], 26)
        self.assertNotEqual(framework_counts, (sum(framework_counts),))

    def test_framework_p0_gate_count_matches_frozen_wrapper_sequence(self) -> None:
        self.assertEqual(len(VERIFY.IMPLEMENTATION_GATES), 31)
        self.assertEqual(len(VERIFY.FRAMEWORK_GATES), 30)
        self.assertEqual(VERIFY.FRAMEWORK_GATES[0], "current-head audit gate")
        self.assertNotIn("current-head audit tests", VERIFY.FRAMEWORK_GATES)
        self.assertNotIn("current-head audit cut", VERIFY.FRAMEWORK_GATES)
        self.assertEqual(VERIFY.FRAMEWORK_GATES[-1], "diff hygiene")

    def test_hosted_ci_job_order_is_nonsemantic_but_membership_is_exact(self) -> None:
        canonical = [
            "supply-chain",
            "feature-matrix",
            "interop",
            "clean-build",
            "build-test",
            "macos-compile",
        ]
        self.assertTrue(VERIFY._hosted_ci_job_names_are_complete(canonical))
        self.assertTrue(
            VERIFY._hosted_ci_job_names_are_complete(
                [canonical[index] for index in (0, 2, 1, 4, 5, 3)]
            )
        )
        self.assertFalse(VERIFY._hosted_ci_job_names_are_complete(canonical[:-1]))
        self.assertFalse(
            VERIFY._hosted_ci_job_names_are_complete([*canonical[:-1], canonical[0]])
        )

    def test_hosted_ci_test_markers_are_scoped_to_the_critical_step(self) -> None:
        critical_prefix = b"supply-chain\tVerify current-head 0.9 audit cut\t"
        unrelated_prefix = (
            b"supply-chain\tVerify normative 0.9 protection model and evidence "
            b"generator\t"
        )
        log = b"\n".join(
            (
                critical_prefix + b"2026-07-15T00:00:00Z Ran 134 tests in 1.0s",
                critical_prefix + b"2026-07-15T00:00:01Z Ran 26 tests in 1.0s",
                critical_prefix + b"2026-07-15T00:00:02Z verify-current-audit: OK",
                unrelated_prefix + b"2026-07-15T00:00:03Z Ran 26 tests in 1.0s",
            )
        )
        critical = VERIFY._hosted_step_log_lines(
            log, "supply-chain", "Verify current-head 0.9 audit cut"
        )
        self.assertEqual(critical.count(b"Ran 134 tests"), 1)
        self.assertEqual(critical.count(b"Ran 26 tests"), 1)
        self.assertEqual(critical.count(b"verify-current-audit: OK"), 1)
        self.assertNotIn(b"protection model", critical)

    def test_q03_uses_a_distinct_hosted_attempt_record(self) -> None:
        layout = VERIFY._catalog_layout("1" * 40)
        self.assertEqual(
            layout["CH-T000-Q03"]["paths"],
            [
                VERIFY.FRAMEWORK_EVIDENCE_PATHS[2],
                VERIFY.FRAMEWORK_CLEAN_LINUX_ATTEMPT_PATH,
                VERIFY.FRAMEWORK_EVIDENCE_PATHS[3],
            ],
        )
        self.assertIn(
            VERIFY.FRAMEWORK_CLEAN_LINUX_ATTEMPT_PATH, VERIFY.C_EVIDENCE_PATHS
        )

    def test_historical_gzip_record_accepts_bound_compression_provenance(self) -> None:
        path = "release/0.9.0/current-head/evidence/historical.log.gz"
        record = {
            "path": path,
            "compression_command": f"gzip -n -9 -c /tmp/raw.log > {path}",
            "compression_tool": "gzip fixture",
            "compression_exit_status": 0,
            "compressed_sha256": "1" * 64,
            "compressed_bytes": 10,
            "uncompressed_sha256": "2" * 64,
            "uncompressed_bytes": 20,
            "uncompressed_lines": 2,
        }
        observed = VERIFY._require_historical_gzip_record(
            record, path, "test.historical"
        )
        self.assertEqual(
            set(observed),
            set(record)
            - {
                "compression_command",
                "compression_tool",
                "compression_exit_status",
            },
        )
        for field, replacement in (
            ("compression_exit_status", 1),
            ("compression_tool", ""),
            ("compression_command", "gzip raw.log"),
        ):
            with self.subTest(field=field):
                mutation = copy.deepcopy(record)
                mutation[field] = replacement
                with self.assertRaises(VERIFY.CurrentAuditError):
                    VERIFY._require_historical_gzip_record(
                        mutation, path, "test.historical"
                    )

    def test_revocation_dispatch_rejects_unknown_record_type(self) -> None:
        self.assertIs(
            VERIFY._revocation_transition("INFLIGHT_ABORT"),
            VERIFY._verify_protocol_inflight_abort,
        )
        self.assertIs(
            VERIFY._revocation_transition("VERIFIED_SUFFIX_REVOCATION"),
            VERIFY._verify_protocol_revocation,
        )
        for value in (None, "UNKNOWN", "", 1):
            with self.subTest(value=value):
                with self.assertRaisesRegex(
                    VERIFY.CurrentAuditError,
                    "CURRENT_AUDIT_PROTOCOL_REVOCATION_DISPATCH_TYPE",
                ):
                    VERIFY._revocation_transition(value)

    def test_forward_protocol_real_git_revocation_refreeze_modes_and_head_force(
        self,
    ) -> None:
        with FIXTURES.signed_repository(shared_root=self.repo.parent) as fixture:
            requirements_path = VERIFY.EXPECTED_REQUIREMENTS_LEDGER["path"]
            claim_path = "docs/CLAIM-LEDGER.md"
            mode_path = "src/mode-probe.bin"
            oid_path = "src/oid-probe.bin"
            claim_payload = (
                b"# Claims\n\n"
                b"| ID | Statement | Status | Support |\n"
                b"| --- | --- | --- | --- |\n"
                b"| CL-TEST-01 | Tiny fixture claim. | PROVEN | fixture |\n"
            )
            bootstrap = {
                "overall_status": "NO_GO",
                "tasks": [
                    {"id": f"CH-T{index:03d}", "status": "OPEN"} for index in range(3)
                ],
            }
            framework = FIXTURES.signed_commit(
                fixture,
                {
                    requirements_path: FIXTURES.canonical_json(bootstrap),
                    claim_path: claim_payload,
                    mode_path: b"stable-mode-payload\n",
                    oid_path: b"original-oid-payload\n",
                },
                "release: establish disposable protocol framework",
            )
            qualification_zero = FIXTURES.signed_commit(
                fixture,
                {},
                "release: qualify disposable protocol framework",
                allow_empty=True,
            )
            initial_ledger = copy.deepcopy(bootstrap)
            initial_ledger["tasks"][0]["status"] = "VERIFIED"
            inventory = VERIFY._claim_inventory(fixture.path, framework)
            initial_claims = {
                "schema_version": "1.0.0",
                "release_target": "0.9.0",
                "persistent_identifier": None,
                "verified_prefix": 1,
                "overall_status": "NO_GO",
                "claim_ledger": VERIFY._commit_regular_file_record(
                    fixture.path, framework, claim_path
                ),
                "public_surface_records": [
                    VERIFY._commit_regular_file_record(fixture.path, framework, path)
                    for path in (claim_path, mode_path, oid_path)
                ],
                "claim_inventory": inventory,
                "asserted_claims": inventory,
                "active_claims": ["CL-TEST-01"],
                "release_qualified_claims": [],
                "removed_claims": [],
                "non_claimed_claims": [],
                "narrowed_claims": [],
                "residual_limitations": ["DISPOSABLE_INITIAL_LIMITATION"],
                "current_epochs": {"CH-T000": 1},
                "tag_authorized": False,
                "github_release_authorized": False,
                "doi_authorized": False,
                "zenodo_authorized": False,
                "archive_authorized": False,
            }
            registry_top = VERIFY._expected_empty_successor_registry(
                framework, qualification_zero
            )
            revocation_top = VERIFY._expected_empty_revocation_ledger(
                framework, qualification_zero
            )
            activation_zero = FIXTURES.signed_commit(
                fixture,
                {
                    requirements_path: FIXTURES.canonical_json(initial_ledger),
                    VERIFY.ACTIVE_CLAIMS_PATH: FIXTURES.canonical_json(initial_claims),
                    VERIFY.SUCCESSOR_REGISTRY_PATH: FIXTURES.canonical_json(
                        registry_top
                    ),
                    VERIFY.REVOCATION_PATH: FIXTURES.canonical_json(revocation_top),
                },
                "release: activate disposable protocol framework",
            )

            registrations: list[dict[str, object]] = []

            def freeze_task(task_id: str, epoch: int) -> tuple[str, dict[str, object]]:
                paths = VERIFY._task_epoch_paths(task_id, epoch)
                verifier_payload = b"#!/usr/bin/env python3\nprint('fixture')\n"
                tests_payload = b"import unittest\n"
                freeze_payload = b"{}\n"
                registration = {
                    "task_id": task_id,
                    "epoch": epoch,
                    "verifier": FIXTURES.protocol_blob_record(
                        fixture, paths["verifier"], verifier_payload
                    ),
                    "tests": FIXTURES.protocol_blob_record(
                        fixture, paths["tests"], tests_payload
                    ),
                    "freeze_contract": FIXTURES.protocol_blob_record(
                        fixture, paths["freeze"], freeze_payload
                    ),
                    "qualification_path": paths["qualification"],
                    "activation_path": paths["activation"],
                    "verifier_receipt_path": paths["verifier_receipt"],
                    "effective_on": "SIGNED_COMMIT_FIRST_CONTAINING_EXACT_REGISTRATION_FREEZE_AND_GATES",
                }
                registrations.append(copy.deepcopy(registration))
                registry = copy.deepcopy(registry_top)
                registry["registrations"] = copy.deepcopy(registrations)
                commit = FIXTURES.signed_commit(
                    fixture,
                    {
                        paths["verifier"]: verifier_payload,
                        paths["tests"]: tests_payload,
                        paths["freeze"]: freeze_payload,
                        VERIFY.SUCCESSOR_REGISTRY_PATH: FIXTURES.canonical_json(
                            registry
                        ),
                    },
                    f"release: freeze {task_id.lower()} disposable epoch {epoch}",
                )
                return commit, registration

            plan_one = {mode_path: "M", oid_path: "M"}
            outcome_one = {
                "id": "NO-CHANGE",
                "claim_disposition": "NO_PUBLIC_CLAIM_CHANGE",
                "overall_status": "NO_GO",
                "active_claims": initial_claims["active_claims"],
                "release_qualified_claims": [],
                "removed_claims": [],
                "non_claimed_claims": [],
                "narrowed_claims": [],
                "limitations": ["DISPOSABLE_TASK_LIMITATION"],
                "public_surfaces": sorted(plan_one),
                "migration": {
                    "required": True,
                    "paths": sorted(plan_one),
                    "disposition": "DISPOSABLE_FIXTURE_ONLY",
                },
                "rollback": {
                    "strategy": "RESTORE_EXACT_PRIOR_ACTIVATED_TREE_ENTRIES",
                    "paths": sorted(plan_one),
                    "verification": "GIT_MODE_TYPE_AND_OBJECT_IDENTITY",
                },
            }
            contract_one = {
                "implementation_plan": plan_one,
                "qualification_evidence_requirements": [],
                "review_requirements": [],
                "activation_evidence_requirements": [],
                "verification_triggers": {
                    "paths": sorted(plan_one),
                    "roots": [],
                },
            }
            freeze_one, registration_one = freeze_task("CH-T001", 1)
            implementation_one = FIXTURES.signed_commit(
                fixture,
                {
                    mode_path: b"stable-mode-payload\n",
                    oid_path: b"changed-oid-payload\n",
                },
                "release: implement ch-t001 disposable changes",
                executable_paths=frozenset({mode_path}),
            )
            paths_one = VERIFY._task_epoch_paths("CH-T001", 1)
            qualification_one = {
                "selected_claim_outcome_id": outcome_one["id"],
                "evidence_records": [],
                "review_records": [],
                "twenty_lens_reviews": {},
                "limitations": [
                    *initial_claims["residual_limitations"],
                    *outcome_one["limitations"],
                ],
            }
            qualification_one_commit = FIXTURES.signed_commit(
                fixture,
                {paths_one["qualification"]: b"{}\n"},
                "release: qualify ch-t001 disposable changes",
            )
            expected_ledger = copy.deepcopy(initial_ledger)
            expected_ledger["tasks"][1] = VERIFY._successor_terminal_task(
                bootstrap["tasks"][1],
                task_id="CH-T001",
                freeze_commit=freeze_one,
                implementation_commit=implementation_one,
                qualification_commit=qualification_one_commit,
                registration=registration_one,
                contract=contract_one,
                qualification=qualification_one,
                outcome=outcome_one,
            )
            expected_ledger["overall_status"] = "NO_GO"
            expected_claims = VERIFY._successor_active_claims(
                initial_claims,
                repo=fixture.path,
                implementation_commit=implementation_one,
                task_id="CH-T001",
                epoch=1,
                outcome=outcome_one,
                qualification=qualification_one,
            )
            placeholder_output = VERIFY._registered_verifier_expected_output(
                registration_one,
                freeze_one,
                implementation_one,
                qualification_one_commit,
                "0" * 40,
                "0" * 40,
                qualification_one,
            )
            receipt_payload = FIXTURES.canonical_json(
                VERIFY._registered_verifier_receipt(placeholder_output)
            )
            requirements_payload = FIXTURES.canonical_json(expected_ledger)
            claims_payload = FIXTURES.canonical_json(expected_claims)
            activation_payload = FIXTURES.canonical_json(
                {
                    "schema_version": "1.0.0",
                    "task_id": "CH-T001",
                    "epoch": 1,
                    "release_target": "0.9.0",
                    "author": {
                        "name": "Sepehr Mahmoudian",
                        "email": "sepmhn@gmail.com",
                    },
                    "persistent_identifier": None,
                    "effective_on": "SIGNED_COMMIT_FIRST_CONTAINING_EXACT_ACTIVATION_RECEIPTS_AND_TRANSITION",
                    "freeze_commit": freeze_one,
                    "implementation_commit": implementation_one,
                    "qualification_commit": qualification_one_commit,
                    "qualification_record": VERIFY._commit_regular_file_record(
                        fixture.path,
                        qualification_one_commit,
                        paths_one["qualification"],
                    ),
                    "verifier_receipt": FIXTURES.protocol_blob_record(
                        fixture, paths_one["verifier_receipt"], receipt_payload
                    ),
                    "activation_evidence_records": [],
                    "requirements_record": FIXTURES.protocol_blob_record(
                        fixture, requirements_path, requirements_payload
                    ),
                    "active_claims_record": FIXTURES.protocol_blob_record(
                        fixture, VERIFY.ACTIVE_CLAIMS_PATH, claims_payload
                    ),
                    "selected_claim_outcome": outcome_one,
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
                }
            )
            activation_one = FIXTURES.signed_commit(
                fixture,
                {
                    paths_one["activation"]: activation_payload,
                    paths_one["verifier_receipt"]: receipt_payload,
                    requirements_path: requirements_payload,
                    VERIFY.ACTIVE_CLAIMS_PATH: claims_payload,
                },
                "release: activate ch-t001 disposable changes",
            )
            contract_two = {
                "implementation_plan": {},
                "qualification_evidence_requirements": [],
                "review_requirements": [],
                "activation_evidence_requirements": [],
                "verification_triggers": {
                    "paths": ["src/unrelated-probe.bin"],
                    "roots": [],
                },
            }
            freeze_two, _registration_two = freeze_task("CH-T002", 1)
            cause_path = "release/0.9.0/current-head/tasks/revocations/R0001/cause.json"
            cause_payload = FIXTURES.canonical_json(
                {"reason": "disposable implementation defect"}
            )
            initial_requirements_payload = FIXTURES.canonical_json(initial_ledger)
            initial_claims_payload = FIXTURES.canonical_json(initial_claims)
            cause_record = {
                "id": "R0001-E01",
                "kind": "IMPLEMENTATION_DEFECT_EVIDENCE",
                "file": FIXTURES.protocol_blob_record(
                    fixture, cause_path, cause_payload
                ),
            }
            revocation_record = {
                "record_id": "R0001",
                "record_type": "VERIFIED_SUFFIX_REVOCATION",
                "author": {
                    "name": "Sepehr Mahmoudian",
                    "email": "sepmhn@gmail.com",
                },
                "target_task": "CH-T001",
                "target_epoch": 1,
                "reason": "IMPLEMENTATION_DEFECT",
                "prior_head": freeze_two,
                "previous_verified_prefix": 2,
                "retained_prefix": 1,
                "invalidated_epochs": [{"task_id": "CH-T001", "epoch": 1}],
                "deactivated_registrations": [
                    VERIFY._protocol_registration_key("CH-T001", 1),
                    VERIFY._protocol_registration_key("CH-T002", 1),
                ],
                "aborted_candidate": {
                    "task_id": "CH-T002",
                    "epoch": 1,
                    "stage": "F",
                    "freeze_commit": freeze_two,
                    "implementation_commit": None,
                    "qualification_commit": None,
                },
                "rollback_source": activation_zero,
                "restored_product_paths": sorted(plan_one),
                "cause_evidence_records": [cause_record],
                "requirements_record": FIXTURES.protocol_blob_record(
                    fixture, requirements_path, initial_requirements_payload
                ),
                "active_claims_record": FIXTURES.protocol_blob_record(
                    fixture, VERIFY.ACTIVE_CLAIMS_PATH, initial_claims_payload
                ),
                "effective_on": "SIGNED_COMMIT_FIRST_CONTAINING_EXACT_REVOCATION_AND_ROLLBACK",
            }
            revocation_ledger = copy.deepcopy(revocation_top)
            revocation_ledger["records"] = [copy.deepcopy(revocation_record)]
            revocation_commit = FIXTURES.signed_commit(
                fixture,
                {
                    mode_path: b"stable-mode-payload\n",
                    oid_path: b"original-oid-payload\n",
                    cause_path: cause_payload,
                    requirements_path: initial_requirements_payload,
                    VERIFY.ACTIVE_CLAIMS_PATH: initial_claims_payload,
                    VERIFY.REVOCATION_PATH: FIXTURES.canonical_json(revocation_ledger),
                },
                "release: revoke disposable verified suffix",
            )
            contract_refreeze = {
                "implementation_plan": {},
                "qualification_evidence_requirements": [],
                "review_requirements": [],
                "activation_evidence_requirements": [],
                "verification_triggers": {
                    "paths": ["src/refreeze-probe.bin"],
                    "roots": [],
                },
            }
            refreeze_one, _registration_refreeze = freeze_task("CH-T001", 2)

            base_mode = VERIFY._git_tree_entry(fixture.path, framework, mode_path)
            changed_mode = VERIFY._git_tree_entry(
                fixture.path, implementation_one, mode_path
            )
            base_oid = VERIFY._git_tree_entry(fixture.path, framework, oid_path)
            changed_oid = VERIFY._git_tree_entry(
                fixture.path, implementation_one, oid_path
            )
            self.assertEqual(base_mode["oid"], changed_mode["oid"])
            self.assertNotEqual(base_mode["mode"], changed_mode["mode"])
            self.assertEqual(base_oid["mode"], changed_oid["mode"])
            self.assertNotEqual(base_oid["oid"], changed_oid["oid"])
            self.assertEqual(
                VERIFY._git_tree_entry(fixture.path, revocation_commit, mode_path),
                base_mode,
            )
            self.assertEqual(
                VERIFY._git_tree_entry(fixture.path, revocation_commit, oid_path),
                base_oid,
            )

            contracts = {
                ("CH-T001", 1): contract_one,
                ("CH-T002", 1): contract_two,
                ("CH-T001", 2): contract_refreeze,
            }
            runner_targets: list[str] = []

            def validate_freeze(
                _repo: Path,
                _commit: str,
                _contract_path: str,
                *,
                task_id: str,
                epoch: int,
                **_kwargs: object,
            ) -> dict[str, object]:
                return copy.deepcopy(contracts[(task_id, epoch)])

            def validate_qualification(
                _repo: Path,
                commit: str,
                **_kwargs: object,
            ) -> tuple[dict[str, object], dict[str, object]]:
                self.assertEqual(commit, qualification_one_commit)
                return copy.deepcopy(qualification_one), copy.deepcopy(outcome_one)

            def run_registered(
                _repo: Path,
                current_commit: str,
                *,
                registration: dict[str, object],
                freeze_commit: str,
                implementation_commit: str,
                qualification_commit: str,
                activation_commit: str,
                qualification: dict[str, object],
            ) -> tuple[dict[str, object], float]:
                runner_targets.append(current_commit)
                return (
                    VERIFY._registered_verifier_expected_output(
                        registration,
                        freeze_commit,
                        implementation_commit,
                        qualification_commit,
                        activation_commit,
                        current_commit,
                        qualification,
                    ),
                    0.01,
                )

            chain = [
                framework,
                qualification_zero,
                activation_zero,
                freeze_one,
                implementation_one,
                qualification_one_commit,
                activation_one,
                freeze_two,
            ]
            extended_chain = [*chain, revocation_commit, refreeze_one]
            with (
                mock.patch.object(VERIFY, "IMPLEMENTATION_COMMIT", framework),
                mock.patch.object(VERIFY, "_verify_terminal_requirement_state"),
                mock.patch.object(
                    VERIFY,
                    "_expected_initial_active_claims",
                    return_value=copy.deepcopy(initial_claims),
                ),
                mock.patch.object(
                    VERIFY,
                    "_initial_claims_before_ch_t000",
                    return_value={
                        **copy.deepcopy(initial_claims),
                        "verified_prefix": 0,
                        "current_epochs": {},
                        "residual_limitations": [],
                    },
                ),
                mock.patch.object(VERIFY, "_verify_post_activation_gate_retention"),
                mock.patch.object(
                    VERIFY,
                    "_validate_successor_freeze_contract",
                    side_effect=validate_freeze,
                ),
                mock.patch.object(
                    VERIFY,
                    "_validate_successor_qualification_v2",
                    side_effect=validate_qualification,
                ),
                mock.patch.object(
                    VERIFY, "_run_registered_verifier_v2", side_effect=run_registered
                ),
                mock.patch.object(
                    VERIFY,
                    "_verify_named_commit_signature",
                    side_effect=lambda _repo, commit, _label: (
                        FIXTURES.verify_signed_commit(fixture, commit)
                    ),
                ),
            ):
                for partial_chain in (chain[:5], chain[:6]):
                    runner_targets.clear()
                    self.assertIsNone(
                        VERIFY._verify_forward_protocol_history(
                            fixture.path,
                            partial_chain,
                            framework_commit=framework,
                            qualification_commit=qualification_zero,
                            activation_commit=activation_zero,
                        )
                    )
                    self.assertEqual(runner_targets, [])
                runner_targets.clear()
                self.assertIsNone(
                    VERIFY._verify_forward_protocol_history(
                        fixture.path,
                        chain,
                        framework_commit=framework,
                        qualification_commit=qualification_zero,
                        activation_commit=activation_zero,
                    )
                )
                self.assertEqual(runner_targets, [activation_one, freeze_two])
                runner_targets.clear()
                self.assertIsNone(
                    VERIFY._verify_forward_protocol_history(
                        fixture.path,
                        extended_chain,
                        framework_commit=framework,
                        qualification_commit=qualification_zero,
                        activation_commit=activation_zero,
                    )
                )
                self.assertEqual(runner_targets, [activation_one])

    def test_protocol_type_change_status_is_rejected(self) -> None:
        with self.assertRaises(VERIFY.CurrentAuditError):
            VERIFY._validate_protocol_changed_paths({"src/state.py": "T"})

    def test_protocol_inflight_abort_accepts_exact_f_i_c_and_prefix_zero(self) -> None:
        framework_commit = "a" * 40
        qualification_commit = "b" * 40
        parent = "c" * 40
        commit = "d" * 40
        rollback_source = "e" * 40
        cause_path = "release/0.9.0/current-head/tasks/revocations/R0001/cause.json"

        def record(path: str) -> dict[str, object]:
            return FIXTURES.file_record(path, (path + "\n").encode("utf-8"))

        for verified_prefix, stage in (
            (0, "F"),
            (0, "I"),
            (0, "C"),
            (1, "F"),
            (1, "I"),
            (1, "C"),
        ):
            with self.subTest(verified_prefix=verified_prefix, stage=stage):
                task_id = f"CH-T{verified_prefix:03d}"
                epoch = 2 if verified_prefix == 0 else 1
                key = VERIFY._protocol_registration_key(task_id, epoch)
                implementation_commit = "1" * 40 if stage in {"I", "C"} else None
                successor_qualification = "2" * 40 if stage == "C" else None
                inflight = {
                    "task_id": task_id,
                    "task_index": verified_prefix,
                    "epoch": epoch,
                    "key": key,
                    "stage": stage,
                    "freeze_commit": "3" * 40,
                    "implementation_commit": implementation_commit,
                    "qualification_commit": successor_qualification,
                    "qualification": None,
                    "outcome": None,
                }
                implementation_plan = (
                    {"src/disposable.rs": "M"} if stage in {"I", "C"} else {}
                )
                contract = {"implementation_plan": implementation_plan}
                ledger = {"state": f"ledger-{verified_prefix}"}
                claims = {"state": f"claims-{verified_prefix}"}
                cause_file = record(cause_path)
                record_value = {
                    "record_id": "R0001",
                    "record_type": "INFLIGHT_ABORT",
                    "author": {
                        "name": "Sepehr Mahmoudian",
                        "email": "sepmhn@gmail.com",
                    },
                    "target_task": task_id,
                    "target_epoch": epoch,
                    "reason": "VERIFIER_DEFECT",
                    "prior_head": parent,
                    "previous_verified_prefix": verified_prefix,
                    "retained_prefix": verified_prefix,
                    "invalidated_epochs": [],
                    "deactivated_registrations": [key],
                    "aborted_candidate": {
                        "task_id": task_id,
                        "epoch": epoch,
                        "stage": stage,
                        "freeze_commit": inflight["freeze_commit"],
                        "implementation_commit": implementation_commit,
                        "qualification_commit": successor_qualification,
                    },
                    "rollback_source": rollback_source,
                    "restored_product_paths": sorted(implementation_plan),
                    "cause_evidence_records": [
                        {
                            "id": "R0001-E01",
                            "kind": "VERIFIER_DEFECT_EVIDENCE",
                            "file": cause_file,
                        }
                    ],
                    "requirements_record": record(
                        VERIFY.EXPECTED_REQUIREMENTS_LEDGER["path"]
                    ),
                    "active_claims_record": record(VERIFY.ACTIVE_CLAIMS_PATH),
                    "effective_on": (
                        "SIGNED_COMMIT_FIRST_CONTAINING_EXACT_INFLIGHT_ABORT_AND_ROLLBACK"
                    ),
                }
                revocation = VERIFY._expected_empty_revocation_ledger(
                    framework_commit, qualification_commit
                )
                revocation["records"] = [record_value]
                payloads = {
                    VERIFY.REVOCATION_PATH: FIXTURES.canonical_json(revocation),
                    VERIFY.EXPECTED_REQUIREMENTS_LEDGER["path"]: (
                        FIXTURES.canonical_json(ledger)
                    ),
                    VERIFY.ACTIVE_CLAIMS_PATH: FIXTURES.canonical_json(claims),
                }
                statuses = {
                    **{path: "M" for path in implementation_plan},
                    cause_path: "A",
                    VERIFY.REVOCATION_PATH: "M",
                }

                def git_file(_repo: Path, _commit: str, path: str) -> bytes:
                    return payloads[path]

                with (
                    mock.patch.object(VERIFY, "_git_file", side_effect=git_file),
                    mock.patch.object(
                        VERIFY,
                        "_commit_regular_file_record",
                        side_effect=lambda _repo, _commit, path: record(path),
                    ),
                    mock.patch.object(VERIFY, "_reverse_path_status", return_value="M"),
                    mock.patch.object(
                        VERIFY, "_git_tree_entry", return_value=("100644", "blob")
                    ),
                ):
                    result = VERIFY._verify_protocol_inflight_abort(
                        self.repo,
                        commit,
                        parent,
                        statuses,
                        framework_commit=framework_commit,
                        qualification_commit=qualification_commit,
                        current_ledger=ledger,
                        current_claims=claims,
                        verified_prefix=verified_prefix,
                        inflight=inflight,
                        contract=contract,
                        revocations=[],
                        snapshots={verified_prefix: (rollback_source, ledger, claims)},
                        activated_plans={},
                        active_registration_keys={key},
                    )
                self.assertEqual(result[0], ledger)
                self.assertEqual(result[1], claims)
                self.assertEqual(result[2], verified_prefix)
                self.assertIsNone(result[3])
                self.assertEqual(result[4], [record_value])
                self.assertEqual(result[7], {cause_path})
                self.assertEqual(result[8], set())

    def test_verifier_snapshot_aba_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            record = root / "record"
            record.write_bytes(b"first")
            before = VERIFY._bounded_filesystem_state(root, "aba.before")
            record.write_bytes(b"second")
            after = VERIFY._bounded_filesystem_state(root, "aba.after")
            self.assertNotEqual(before, after)

    def test_post_activation_gate_exact_files_verify(self) -> None:
        head = VERIFY._git(self.repo, "rev-parse", "HEAD").decode("ascii").strip()
        self.assertIsNone(
            VERIFY._verify_post_activation_gate_retention(self.repo, head)
        )

    def test_post_activation_gate_payload_mutations_are_rejected(self) -> None:
        paths = (
            ".github/workflows/ci.yml",
            "justfile",
            "tools/p0r-exit-gate.sh",
            "tools/release/current-audit-gate.sh",
        )
        head = VERIFY._git(self.repo, "rev-parse", "HEAD").decode("ascii").strip()
        for path in paths:
            with self.subTest(path=path):
                payload = VERIFY._git_file(self.repo, head, path) + b"\n"
                self.assert_gate_file_rejected(path, payload=payload)

    def test_post_activation_gate_mode_mutations_are_rejected(self) -> None:
        for path in (
            ".github/workflows/ci.yml",
            "justfile",
            "tools/p0r-exit-gate.sh",
            "tools/release/current-audit-gate.sh",
        ):
            with self.subTest(path=path):
                self.assert_gate_file_rejected(path, mode="120000")

    def test_post_activation_gate_dirty_worktree_is_rejected(self) -> None:
        for path in (
            ".github/workflows/ci.yml",
            "justfile",
            "tools/p0r-exit-gate.sh",
        ):
            with self.subTest(path=path):
                self.assert_gate_file_rejected(path, dirty_worktree=True)

    def test_registered_tests_reject_loader_and_skip_bypasses(self) -> None:
        exact = b"""import unittest\n\nclass ExactTests(unittest.TestCase):\n    def test_exact(self):\n        self.assertTrue(True)\n\nif __name__ == "__main__":\n    unittest.main()\n"""
        load_override = exact.replace(
            b"if __name__",
            b"def load_tests(loader, tests, pattern):\n    return unittest.TestSuite()\n\nif __name__",
        )
        skipped = exact.replace(
            b"    def test_exact",
            b'    @unittest.skip("not executed")\n    def test_exact',
        )
        run_override = exact.replace(
            b"    def test_exact",
            b"    def run(self, result=None):\n        return result\n\n    def test_exact",
        )
        exit_override = exact.replace(
            b"import unittest",
            b"import os\nimport unittest\nos._exit(0)",
        )
        handshake_override = exact.replace(
            b"import unittest",
            b'import unittest\nprint("READY", flush=True)\nnonce = input()\nprint(nonce, flush=True)\nraise SystemExit(0)',
        ).replace(b"self.assertTrue(True)", b"self.assertTrue(False)")
        indirect_handshake_override = exact.replace(
            b"import unittest",
            b'import sys\nimport unittest\nsys.__stdout__.write("READY\\n")\nsys.__stdout__.flush()\nnonce = sys.__stdin__.readline()\nsys.__stdout__.write(nonce)\nsys.__stdout__.flush()\ngetattr(__import__("os"), "_exit")(0)',
        ).replace(b"self.assertTrue(True)", b"self.assertTrue(False)")
        for label, payload in (
            ("loader", load_override),
            ("skip", skipped),
            ("run", run_override),
            ("exit", exit_override),
            ("handshake", handshake_override),
            ("indirect-handshake", indirect_handshake_override),
        ):
            with self.subTest(label=label):
                with self.assertRaises(VERIFY.CurrentAuditError):
                    VERIFY._discover_unittest_test_cases(
                        payload, "test_registered.py", strict_runtime=True
                    )

    def test_registered_test_parent_rejects_import_exit_and_run_spoofs(self) -> None:
        valid = b"""import unittest\n\nclass ExactTests(unittest.TestCase):\n    def test_exact(self):\n        self.assertTrue(True)\n\nif __name__ == "__main__":\n    unittest.main()\n"""
        run_spoof = valid.replace(
            b"    def test_exact(self):\n        self.assertTrue(True)",
            b"    def run(self, result=None):\n        if result is not None:\n            result.startTest(self)\n            result.stopTest(self)\n        return result\n\n    def test_exact(self):\n        self.assertTrue(False)",
        )
        exit_spoof = valid.replace(
            b"import unittest",
            b'import os\nimport unittest\nprint(\'{"result":"PASS","tests":1}\', flush=True)\nos._exit(0)',
        ).replace(b"self.assertTrue(True)", b"self.assertTrue(False)")
        handshake_spoof = valid.replace(
            b"import unittest",
            b'import unittest\nprint("READY", flush=True)\nnonce = input()\nprint(nonce, flush=True)\nraise SystemExit(0)',
        ).replace(b"self.assertTrue(True)", b"self.assertTrue(False)")
        indirect_handshake_spoof = valid.replace(
            b"import unittest",
            b'import sys\nimport unittest\nsys.__stdout__.write("READY\\n")\nsys.__stdout__.flush()\nnonce = sys.__stdin__.readline()\nsys.__stdout__.write(nonce)\nsys.__stdout__.flush()\ngetattr(__import__("os"), "_exit")(0)',
        ).replace(b"self.assertTrue(True)", b"self.assertTrue(False)")
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            runner = root / "runner.py"
            runner.write_bytes(VERIFY._registered_test_runner_payload())
            cases = '[["ExactTests","test_exact"]]'
            for label, payload, expected_code in (
                ("valid", valid, 0),
                ("run", run_spoof, 2),
                ("exit", exit_spoof, 2),
                ("handshake", handshake_spoof, 2),
                ("indirect-handshake", indirect_handshake_spoof, 2),
            ):
                with self.subTest(label=label):
                    test_path = root / f"test-{label}.py"
                    test_path.write_bytes(payload)
                    if label == "valid":
                        nonce = b"a" * 64
                        nonce_path = root / "nonce.txt"
                        nonce_path.write_bytes(nonce + b"\n")
                        child_code, child_stdout, child_stderr = VERIFY._run_bounded(
                            [
                                sys.executable,
                                str(runner),
                                "--child",
                                str(test_path),
                                cases,
                            ],
                            cwd=root,
                            env=os.environ.copy(),
                            timeout_seconds=5,
                            stdout_limit=4096,
                            stderr_limit=4096,
                            error_prefix="TEST_REGISTERED_CHILD",
                            stdin_path=nonce_path,
                            _test_only_allow_uncontained_process=True,
                        )
                        self.assertEqual(
                            (child_code, child_stdout, child_stderr),
                            (0, b"READY\n" + nonce + b"\n", b""),
                        )
                    code, stdout, stderr = VERIFY._run_bounded(
                        [sys.executable, str(runner), str(test_path), cases],
                        cwd=root,
                        env=os.environ.copy(),
                        timeout_seconds=5,
                        stdout_limit=4096,
                        stderr_limit=4096,
                        error_prefix="TEST_REGISTERED_PARENT",
                        _test_only_allow_uncontained_process=True,
                    )
                    self.assertEqual(code, expected_code, (stdout, stderr))
                    if label == "valid":
                        self.assertEqual(
                            (stdout, stderr),
                            (b'{"result":"PASS","tests":1}\n', b""),
                        )
                    else:
                        self.assertNotEqual(
                            (stdout, stderr),
                            (b'{"result":"PASS","tests":1}\n', b""),
                        )

    def test_registered_image_identity_is_exact(self) -> None:
        state = VERIFY._registered_image_state()
        self.assertEqual(state["os"], "linux")
        self.assertIn(state["architecture"], VERIFY.REGISTERED_RUNNER_IMAGE_IDS)
        self.assertIn(VERIFY.REGISTERED_RUNNER_IMAGE, state["repo_digests"])

    def test_registered_socket_accepts_only_accessible_group_write(self) -> None:
        socket_path = mock.Mock()
        socket_path.is_symlink.return_value = False
        metadata = mock.Mock(
            st_mode=VERIFY.stat.S_IFSOCK | 0o660,
            st_uid=0,
            st_gid=123,
        )
        with (
            mock.patch.object(VERIFY.os, "geteuid", return_value=1000),
            mock.patch.object(VERIFY.os, "getegid", return_value=1000),
            mock.patch.object(VERIFY.os, "getgroups", return_value=[123]),
        ):
            self.assertTrue(VERIFY._registered_socket_is_trusted(socket_path, metadata))
            metadata.st_mode = VERIFY.stat.S_IFSOCK | 0o662
            self.assertFalse(
                VERIFY._registered_socket_is_trusted(socket_path, metadata)
            )
            metadata.st_mode = VERIFY.stat.S_IFSOCK | 0o660
            with mock.patch.object(VERIFY.os, "getgroups", return_value=[]):
                self.assertFalse(
                    VERIFY._registered_socket_is_trusted(socket_path, metadata)
                )
            socket_path.is_symlink.return_value = True
            self.assertFalse(
                VERIFY._registered_socket_is_trusted(socket_path, metadata)
            )

    def test_registered_container_is_read_only_and_cleans_up(self) -> None:
        code, stdout, stderr = self.run_container_probe(
            "from pathlib import Path\n"
            "try:\n"
            "    Path('/repo/forbidden').write_text('x')\n"
            "except OSError:\n"
            "    print('READ_ONLY')\n"
            "else:\n"
            "    raise SystemExit(3)\n",
            label="PUBLIC_READ_ONLY",
        )
        self.assertEqual((code, stdout, stderr), (0, b"READ_ONLY\n", b""))

    def test_registered_container_has_no_external_network(self) -> None:
        code, stdout, stderr = self.run_container_probe(
            "import socket\n"
            "probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
            "probe.settimeout(0.25)\n"
            "try:\n"
            "    result = probe.connect_ex(('1.1.1.1', 53))\n"
            "finally:\n"
            "    probe.close()\n"
            "if result == 0:\n"
            "    raise SystemExit(4)\n"
            "print('NETWORK_NONE')\n",
            label="PUBLIC_NETWORK_NONE",
        )
        self.assertEqual((code, stdout, stderr), (0, b"NETWORK_NONE\n", b""))

    def test_registered_container_kills_detached_descendant_on_exit(self) -> None:
        code, stdout, stderr = self.run_container_probe(
            "import subprocess, sys\n"
            "subprocess.Popen(\n"
            "    [sys.executable, '-c', 'import time; time.sleep(30)'],\n"
            "    start_new_session=True,\n"
            "    stdin=subprocess.DEVNULL,\n"
            "    stdout=subprocess.DEVNULL,\n"
            "    stderr=subprocess.DEVNULL,\n"
            ")\n"
            "print('DETACHED_CHILD_STARTED')\n",
            label="PUBLIC_DETACHED_CHILD",
        )
        self.assertEqual((code, stdout, stderr), (0, b"DETACHED_CHILD_STARTED\n", b""))

    def test_registered_container_timeout_is_bounded_and_cleans_up(self) -> None:
        with mock.patch.object(VERIFY, "MAX_VERIFIER_SECONDS", 0.5):
            code, stdout, stderr = self.run_container_probe(
                "import time\ntime.sleep(30)\n",
                label="PUBLIC_TIMEOUT",
            )
        self.assertEqual((code, stdout, stderr), (137, b"", b""))

    def test_registered_container_output_flood_is_bounded_and_cleans_up(self) -> None:
        with mock.patch.object(VERIFY, "MAX_VERIFIER_OUTPUT_BYTES", 64):
            with self.assertRaisesRegex(
                VERIFY.CurrentAuditError, "PUBLIC_OUTPUT_CONTAINER_OUTPUT_BOUND"
            ):
                self.run_container_probe(
                    "import sys\nsys.stdout.write('x' * 65536)\n",
                    label="PUBLIC_OUTPUT",
                )


if __name__ == "__main__":
    unittest.main()
