#!/usr/bin/env python3
"""Positive, negative, boundary, adversarial, and regression tests for T001."""

from __future__ import annotations

import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from typing import Any


MODULE_PATH = Path(__file__).with_name("verify-authority-model.py")
SPEC = importlib.util.spec_from_file_location("verify_authority_model", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)


class AuthorityModelVerificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.repo = Path(__file__).resolve().parents[2]
        cls.model_path = cls.repo / "release/0.9.0/authority-model.json"
        cls.profile_path = cls.repo / "deploy/secure-reference-v1/profile.json"
        cls.result_path = cls.repo / "evidence/11-secure-zenoh-live/result.json"
        cls.requirements_path = cls.repo / "release/0.9.0/requirements.json"
        cls.model = json.loads(cls.model_path.read_text(encoding="utf-8"))
        cls.profile = json.loads(cls.profile_path.read_text(encoding="utf-8"))
        cls.result = json.loads(cls.result_path.read_text(encoding="utf-8"))
        cls.requirements = json.loads(cls.requirements_path.read_text(encoding="utf-8"))

    @staticmethod
    def write_json(value: Any, directory: str, name: str) -> Path:
        path = Path(directory) / name
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def test_positive_current_model_and_evidence_verify(self) -> None:
        VERIFY.verify(self.model_path, self.repo)

    def test_negative_second_final_publisher_is_rejected(self) -> None:
        profile = copy.deepcopy(self.profile)
        profile["principals"]["controller-a"]["publish"].append("final_command")
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_json(profile, directory, "profile.json")
            with self.assertRaisesRegex(
                VERIFY.AuthorityModelError,
                "AUTHORITY_PROFILE_FINAL_PUBLISHERS_INVALID",
            ):
                VERIFY.verify(self.model_path, self.repo, profile_path=path)

    def test_adversarial_gate_identity_spoof_is_rejected(self) -> None:
        profile = copy.deepcopy(self.profile)
        profile["principals"]["gate"]["role"] = "controller"
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_json(profile, directory, "profile.json")
            with self.assertRaisesRegex(
                VERIFY.AuthorityModelError,
                "AUTHORITY_PROFILE_GATE_IDENTITY_INVALID",
            ):
                VERIFY.verify(self.model_path, self.repo, profile_path=path)

    def test_boundary_oversized_model_is_rejected_before_decode(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "authority-model.json"
            path.write_bytes(b"{" + b" " * VERIFY.MAX_MODEL_BYTES + b"}")
            with self.assertRaisesRegex(VERIFY.AuthorityModelError, "AUTHORITY_RESOURCE_BOUND"):
                VERIFY.verify(path, self.repo)

    def test_malformed_model_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "authority-model.json"
            path.write_bytes(b'{"schema_version":')
            with self.assertRaisesRegex(VERIFY.AuthorityModelError, "AUTHORITY_JSON_INVALID"):
                VERIFY.verify(path, self.repo)

    def test_regression_hold_cannot_be_added_to_decision_outcomes(self) -> None:
        model = copy.deepcopy(self.model)
        model["decision_action_separation"]["decision_outcomes"].append("HOLD")
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_json(model, directory, "authority-model.json")
            with self.assertRaisesRegex(
                VERIFY.AuthorityModelError,
                "AUTHORITY_DECISION_ACTION_CONFLATION",
            ):
                VERIFY.verify(path, self.repo)

    def test_negative_missing_non_gate_denial_is_rejected(self) -> None:
        result = copy.deepcopy(self.result)
        missing = "final-denied-observer"
        result["attempts"] = [item for item in result["attempts"] if item["case_id"] != missing]
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_json(result, directory, "result.json")
            with self.assertRaisesRegex(
                VERIFY.AuthorityModelError,
                "AUTHORITY_EVIDENCE_NON_GATE_DENIAL_INVALID",
            ):
                VERIFY.verify(self.model_path, self.repo, result_path=path)

    def test_regression_unverified_predecessor_is_rejected(self) -> None:
        requirements = copy.deepcopy(self.requirements)
        requirements["tasks"][0]["status"] = "open"
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_json(requirements, directory, "requirements.json")
            with self.assertRaisesRegex(
                VERIFY.AuthorityModelError,
                "AUTHORITY_PREDECESSOR_NOT_VERIFIED",
            ):
                VERIFY.verify(self.model_path, self.repo, requirements_path=path)

    def test_metamorphic_principal_object_order_does_not_change_authority(self) -> None:
        profile = copy.deepcopy(self.profile)
        profile["principals"] = dict(reversed(list(profile["principals"].items())))
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_json(profile, directory, "profile.json")
            VERIFY.verify(self.model_path, self.repo, profile_path=path)

    def test_negative_normative_document_digest_substitution_is_rejected(self) -> None:
        model = copy.deepcopy(self.model)
        model["normative_document"]["sha256"] = "0" * 64
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_json(model, directory, "authority-model.json")
            with self.assertRaisesRegex(
                VERIFY.AuthorityModelError,
                "AUTHORITY_DOCUMENT_DIGEST_MISMATCH",
            ):
                VERIFY.verify(path, self.repo)


if __name__ == "__main__":
    unittest.main()
