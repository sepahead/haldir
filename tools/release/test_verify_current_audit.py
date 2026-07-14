#!/usr/bin/env python3
"""Adversarial tests for the current-head audit-cut verifier."""

from __future__ import annotations

import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock


MODULE_PATH = Path(__file__).with_name("verify-current-audit.py")
SPEC = importlib.util.spec_from_file_location("verify_current_audit", MODULE_PATH)
if SPEC is None or SPEC.loader is None:  # pragma: no cover - import guard
    raise RuntimeError("unable to load current-audit verifier")
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)


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
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_manifest(value, directory)
            with self.assertRaises(VERIFY.CurrentAuditError):
                VERIFY.verify(path, self.repo)

    def assert_raw_rejected(self, payload: str | bytes) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit-inputs.json"
            if isinstance(payload, str):
                path.write_text(payload, encoding="utf-8")
            else:
                path.write_bytes(payload)
            with self.assertRaises(VERIFY.CurrentAuditError):
                VERIFY.verify(path, self.repo)

    def test_exact_manifest_verifies(self) -> None:
        VERIFY.verify(self.manifest_path, self.repo)

    def test_duplicate_json_key_is_rejected(self) -> None:
        payload = self.manifest_path.read_text(encoding="utf-8")
        duplicate = payload.replace("{\n", '{\n  "schema_version": "duplicate",\n', 1)
        with tempfile.TemporaryDirectory() as directory:
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
        original_loader = VERIFY._load_json

        def load_with_mutation(
            candidate: Path, *args: object, **kwargs: object
        ) -> dict[str, object]:
            if candidate == path:
                return json.loads(mutated)
            return original_loader(candidate, *args, **kwargs)

        with mock.patch.object(VERIFY, "_load_json", side_effect=load_with_mutation):
            with self.assertRaises(VERIFY.CurrentAuditError):
                VERIFY.verify(self.manifest_path, self.repo)

    def test_terminal_requirement_without_evidence_is_rejected(self) -> None:
        path = self.repo / self.manifest["requirements_ledger"]["path"]
        ledger = json.loads(path.read_text(encoding="utf-8"))
        ledger["tasks"][0]["status"] = "VERIFIED"
        original_loader = VERIFY._load_json

        def load_with_mutation(
            candidate: Path, *args: object, **kwargs: object
        ) -> dict[str, object]:
            if candidate == path:
                return ledger
            return original_loader(candidate, *args, **kwargs)

        with mock.patch.object(VERIFY, "_load_json", side_effect=load_with_mutation):
            with self.assertRaises(VERIFY.CurrentAuditError):
                VERIFY.verify(self.manifest_path, self.repo)

    def test_counterfeit_fully_qualified_go_is_rejected(self) -> None:
        path = self.repo / self.manifest["requirements_ledger"]["path"]
        ledger = json.loads(path.read_text(encoding="utf-8"))
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
        original_loader = VERIFY._load_json

        def load_with_counterfeit(
            candidate: Path, *args: object, **kwargs: object
        ) -> dict[str, object]:
            if candidate == path:
                return ledger
            return original_loader(candidate, *args, **kwargs)

        with mock.patch.object(VERIFY, "_load_json", side_effect=load_with_counterfeit):
            with self.assertRaises(VERIFY.CurrentAuditError):
                VERIFY.verify(self.manifest_path, self.repo)

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
        original = VERIFY._read_bounded

        def corrupt(path: Path, limit: int, label: str) -> bytes:
            payload = original(path, limit, label)
            if label == "baseline.log.gz":
                return payload[:-1] + bytes([payload[-1] ^ 1])
            return payload

        with mock.patch.object(VERIFY, "_read_bounded", side_effect=corrupt):
            with self.assertRaises(VERIFY.CurrentAuditError):
                VERIFY.verify(self.manifest_path, self.repo)

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
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target.json"
            target.write_text("{}\n", encoding="utf-8")
            link = root / "link.json"
            link.symlink_to(target)
            with self.assertRaisesRegex(VERIFY.CurrentAuditError, "SYMLINK_REJECTED"):
                VERIFY.verify(link, self.repo)


if __name__ == "__main__":
    unittest.main()
