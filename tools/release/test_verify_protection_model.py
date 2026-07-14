#!/usr/bin/env python3
"""Positive, negative, boundary, adversarial, and regression tests for T002."""

from __future__ import annotations

import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from typing import Any


MODULE_PATH = Path(__file__).with_name("verify-protection-model.py")
SPEC = importlib.util.spec_from_file_location("verify_protection_model", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)


class ProtectionModelVerificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.repo = Path(__file__).resolve().parents[2]
        cls.model_path = cls.repo / "release/0.9.0/protection-model.json"
        cls.profile_path = cls.repo / "deploy/secure-reference-v1/profile.json"
        cls.requirements_path = cls.repo / "release/0.9.0/requirements.json"
        cls.model = json.loads(cls.model_path.read_text(encoding="utf-8"))
        cls.profile = json.loads(cls.profile_path.read_text(encoding="utf-8"))
        cls.requirements = json.loads(cls.requirements_path.read_text(encoding="utf-8"))

    @staticmethod
    def write_json(value: Any, directory: str, name: str) -> Path:
        path = Path(directory) / name
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def test_positive_current_model_profile_sources_and_ledger_verify(self) -> None:
        VERIFY.verify(self.model_path, self.repo)

    def test_negative_second_final_publisher_is_rejected(self) -> None:
        profile = copy.deepcopy(self.profile)
        profile["principals"]["controller-a"]["publish"].append("final_command")
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_json(profile, directory, "profile.json")
            with self.assertRaisesRegex(
                VERIFY.ProtectionModelError,
                "PRINCIPAL_PROFILE_DRIFT",
            ):
                VERIFY.verify(self.model_path, self.repo, profile_path=path)

    def test_adversarial_route_confusion_is_rejected(self) -> None:
        profile = copy.deepcopy(self.profile)
        profile["routes"]["final_command"] = profile["routes"]["controller_a_intent"]
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_json(profile, directory, "profile.json")
            with self.assertRaisesRegex(
                VERIFY.ProtectionModelError,
                "ROUTE_RESOURCE_INVALID",
            ):
                VERIFY.verify(self.model_path, self.repo, profile_path=path)

    def test_malformed_duplicate_json_key_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "protection-model.json"
            path.write_text(
                '{"schema_version":"1.0.0","schema_version":"1.0.0"}',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                VERIFY.ProtectionModelError,
                "PROTECTION_JSON_DUPLICATE_KEY:schema_version",
            ):
                VERIFY.verify(path, self.repo)

    def test_malformed_truncated_json_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "protection-model.json"
            path.write_bytes(b'{"schema_version":')
            with self.assertRaisesRegex(VERIFY.ProtectionModelError, "PROTECTION_JSON_INVALID"):
                VERIFY.verify(path, self.repo)

    def test_boundary_oversized_model_is_rejected_before_decode(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "protection-model.json"
            path.write_bytes(b"{" + b" " * VERIFY.MAX_MODEL_BYTES + b"}")
            with self.assertRaisesRegex(
                VERIFY.ProtectionModelError,
                "PROTECTION_RESOURCE_BOUND",
            ):
                VERIFY.verify(path, self.repo)

    def test_state_transition_default_deny_cannot_become_allow(self) -> None:
        model = copy.deepcopy(self.model)
        model["access_policy"]["default_effect"] = "ALLOW"
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_json(model, directory, "protection-model.json")
            with self.assertRaisesRegex(
                VERIFY.ProtectionModelError,
                "DEFAULT_DENY_OR_COMMAND_CUSTODY_INVALID",
            ):
                VERIFY.verify(path, self.repo)

    def test_adversarial_wildcard_authority_grant_is_rejected(self) -> None:
        model = copy.deepcopy(self.model)
        model["access_policy"]["wildcard_authority_grants"] = True
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_json(model, directory, "protection-model.json")
            with self.assertRaisesRegex(
                VERIFY.ProtectionModelError,
                "DEFAULT_DENY_OR_COMMAND_CUSTODY_INVALID",
            ):
                VERIFY.verify(path, self.repo)

    def test_regression_controller_clock_cannot_authorize_freshness(self) -> None:
        model = copy.deepcopy(self.model)
        domain = next(
            item
            for item in model["time_domains"]
            if item["time_domain_id"] == "controller_local_provenance"
        )
        domain["hot_path_authority"] = True
        domain["authority_uses"] = ["state_freshness"]
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_json(model, directory, "protection-model.json")
            with self.assertRaisesRegex(
                VERIFY.ProtectionModelError,
                "TIME_DOMAIN_SEMANTICS_INVALID|AUTHORITY_CLOCK_AMBIGUOUS",
            ):
                VERIFY.verify(path, self.repo)

    def test_adversarial_controller_field_cannot_become_trust_root(self) -> None:
        model = copy.deepcopy(self.model)
        model["trust_roots"][0]["derivable_from_controller_fields"] = True
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_json(model, directory, "protection-model.json")
            with self.assertRaisesRegex(
                VERIFY.ProtectionModelError,
                "TRUST_ROOT_SEMANTICS_INVALID",
            ):
                VERIFY.verify(path, self.repo)

    def test_negative_ownerless_resource_is_rejected(self) -> None:
        model = copy.deepcopy(self.model)
        model["resources"]["state_resources"][0]["runtime_custodian"] = ""
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_json(model, directory, "protection-model.json")
            with self.assertRaisesRegex(
                VERIFY.ProtectionModelError,
                "STATE_RESOURCE_OWNERSHIP_INVALID",
            ):
                VERIFY.verify(path, self.repo)

    def test_negative_unknown_access_resource_is_rejected(self) -> None:
        model = copy.deepcopy(self.model)
        model["access_policy"]["component_rules"][0]["grants"][0]["resource_ids"] = [
            "state:unknown"
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_json(model, directory, "protection-model.json")
            with self.assertRaisesRegex(
                VERIFY.ProtectionModelError,
                "ACCESS_RULE_UNKNOWN_RESOURCE",
            ):
                VERIFY.verify(path, self.repo)

    def test_adversarial_controller_command_construction_is_rejected(self) -> None:
        model = copy.deepcopy(self.model)
        controller = next(
            rule
            for rule in model["access_policy"]["component_rules"]
            if rule["rule_id"] == "component:controller_intent_only"
        )
        controller["grants"].append(
            {
                "resource_ids": ["state:final_command_frame"],
                "operations": ["construct_frame"],
            }
        )
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_json(model, directory, "protection-model.json")
            with self.assertRaisesRegex(
                VERIFY.ProtectionModelError,
                "ACCESS_TUPLE_SET_DRIFT|COMMAND_AUTHORITY_ESCALATION",
            ):
                VERIFY.verify(path, self.repo)

    def test_adversarial_non_gate_final_publication_is_rejected(self) -> None:
        model = copy.deepcopy(self.model)
        mission = next(
            rule
            for rule in model["access_policy"]["component_rules"]
            if rule["rule_id"] == "component:mission_objects_only"
        )
        mission["grants"].append(
            {
                "resource_ids": ["route:final_command"],
                "operations": ["publish_once"],
            }
        )
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_json(model, directory, "protection-model.json")
            with self.assertRaisesRegex(
                VERIFY.ProtectionModelError,
                "ACCESS_TUPLE_SET_DRIFT|COMMAND_AUTHORITY_ESCALATION",
            ):
                VERIFY.verify(path, self.repo)

    def test_negative_unknown_route_custodian_is_rejected(self) -> None:
        model = copy.deepcopy(self.model)
        model["resources"]["route_resources"][0]["runtime_custodian"] = (
            "attacker_not_a_subject"
        )
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_json(model, directory, "protection-model.json")
            with self.assertRaisesRegex(
                VERIFY.ProtectionModelError,
                "ROUTE_RESOURCE_INVALID",
            ):
                VERIFY.verify(path, self.repo)

    def test_adversarial_constraint_semantics_substitution_is_rejected(self) -> None:
        model = copy.deepcopy(self.model)
        model["constraints"][0]["rule"] = (
            "controller_supplied_kid_grants_unconditional_command_authority"
        )
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_json(model, directory, "protection-model.json")
            with self.assertRaisesRegex(
                VERIFY.ProtectionModelError,
                "CONSTRAINT_SEMANTICS_DRIFT",
            ):
                VERIFY.verify(path, self.repo)

    def test_adversarial_trust_root_scope_substitution_is_rejected(self) -> None:
        model = copy.deepcopy(self.model)
        model["trust_roots"][0]["authority_scope"] = (
            "controller_role_name_authorizes_final_route"
        )
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_json(model, directory, "protection-model.json")
            with self.assertRaisesRegex(
                VERIFY.ProtectionModelError,
                "TRUST_ROOT_SEMANTICS_DRIFT",
            ):
                VERIFY.verify(path, self.repo)

    def test_regression_required_final_constraint_cannot_be_removed(self) -> None:
        model = copy.deepcopy(self.model)
        model["access_policy"]["final_command_transition"][
            "required_constraint_ids"
        ].pop()
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_json(model, directory, "protection-model.json")
            with self.assertRaisesRegex(
                VERIFY.ProtectionModelError,
                "FINAL_COMMAND_TRANSITION_INVALID",
            ):
                VERIFY.verify(path, self.repo)

    def test_adversarial_subject_type_role_spoof_is_rejected(self) -> None:
        model = copy.deepcopy(self.model)
        controller = next(
            binding
            for binding in model["subjects"]["subject_type_bindings"]
            if binding["subject_id"] == "controller"
        )
        controller["application_key_roles"] = ["GATE_APPLICATION"]
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_json(model, directory, "protection-model.json")
            with self.assertRaisesRegex(
                VERIFY.ProtectionModelError,
                "KEY_ROLE_COVERAGE_INVALID|COMPONENT_BINDINGS_SEMANTICS_DRIFT",
            ):
                VERIFY.verify(path, self.repo)

    def test_adversarial_role_object_subject_domain_drift_is_rejected(self) -> None:
        model = copy.deepcopy(self.model)
        gate_role = next(
            binding
            for binding in model["subjects"]["application_role_bindings"]
            if binding["role"] == "GATE_APPLICATION"
        )
        gate_role["signed_objects"][0]["subject_binding"] = (
            "controller_role_name_is_sufficient"
        )
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_json(model, directory, "protection-model.json")
            with self.assertRaisesRegex(
                VERIFY.ProtectionModelError,
                "APPLICATION_ROLE_SEMANTICS_DRIFT",
            ):
                VERIFY.verify(path, self.repo)

    def test_regression_durable_ratchets_remain_cross_boot_scoped(self) -> None:
        model = copy.deepcopy(self.model)
        ratchets = next(
            domain
            for domain in model["time_domains"]
            if domain["time_domain_id"] == "durable_logical_ratchets"
        )
        ratchets["cross_boot_comparable"] = False
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_json(model, directory, "protection-model.json")
            with self.assertRaisesRegex(
                VERIFY.ProtectionModelError,
                "TIME_DOMAIN_SEMANTICS_INVALID",
            ):
                VERIFY.verify(path, self.repo)

    def test_regression_authorization_revision_remains_boot_scoped(self) -> None:
        model = copy.deepcopy(self.model)
        counters = next(
            domain
            for domain in model["time_domains"]
            if domain["time_domain_id"]
            == "boot_or_epoch_scoped_logical_counters"
        )
        counters["cross_boot_comparable"] = True
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_json(model, directory, "protection-model.json")
            with self.assertRaisesRegex(
                VERIFY.ProtectionModelError,
                "TIME_DOMAIN_SEMANTICS_INVALID",
            ):
                VERIFY.verify(path, self.repo)

    def test_regression_unverified_predecessor_is_rejected(self) -> None:
        requirements = copy.deepcopy(self.requirements)
        t001 = next(task for task in requirements["tasks"] if task["id"] == "T001")
        t001["status"] = "implemented"
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_json(requirements, directory, "requirements.json")
            with self.assertRaisesRegex(
                VERIFY.ProtectionModelError,
                "PREDECESSOR_NOT_VERIFIED",
            ):
                VERIFY.verify(self.model_path, self.repo, requirements_path=path)

    def test_negative_normative_document_digest_substitution_is_rejected(self) -> None:
        model = copy.deepcopy(self.model)
        model["normative_document"]["sha256"] = "0" * 64
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_json(model, directory, "protection-model.json")
            with self.assertRaisesRegex(
                VERIFY.ProtectionModelError,
                "DOCUMENT_DIGEST_MISMATCH",
            ):
                VERIFY.verify(path, self.repo)

    def test_metamorphic_access_rule_order_does_not_change_policy(self) -> None:
        model = copy.deepcopy(self.model)
        model["access_policy"]["component_rules"].reverse()
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_json(model, directory, "protection-model.json")
            VERIFY.verify(path, self.repo)

    def test_metamorphic_profile_object_order_does_not_change_grants(self) -> None:
        profile = copy.deepcopy(self.profile)
        profile["routes"] = dict(reversed(list(profile["routes"].items())))
        profile["principals"] = dict(reversed(list(profile["principals"].items())))
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_json(profile, directory, "profile.json")
            VERIFY.verify(self.model_path, self.repo, profile_path=path)


if __name__ == "__main__":
    unittest.main()
