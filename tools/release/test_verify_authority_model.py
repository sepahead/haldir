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
            with self.assertRaisesRegex(
                VERIFY.AuthorityModelError, "AUTHORITY_RESOURCE_BOUND"
            ):
                VERIFY.verify(path, self.repo)

    def test_malformed_model_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "authority-model.json"
            path.write_bytes(b'{"schema_version":')
            with self.assertRaisesRegex(
                VERIFY.AuthorityModelError, "AUTHORITY_JSON_INVALID"
            ):
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
        result["attempts"] = [
            item for item in result["attempts"] if item["case_id"] != missing
        ]
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

    def test_regression_gate_pipeline_requires_fallible_retained_policy(self) -> None:
        actor_path = self.repo / "crates/haldir-gate/src/actor.rs"
        actor_source = actor_path.read_text(encoding="utf-8")
        mutations = (
            (
                "try_decide_validated(&PolicyInput",
                "decide_validated(&PolicyInput",
            ),
            (
                "policy: &self.policy",
                "policy: &untrusted_policy",
            ),
            (
                "Err(error) =>",
                "Ok(error) =>",
            ),
            (
                "self.latch_fault(error.detail_reason_code())",
                "self.latch_fault(error.reason_code())",
            ),
            (
                "self.latch_fault(error.detail_reason_code());\n"
                "                return self.respond(&draft, R::ErrorInternalFault, now);",
                "self.latch_fault(error.detail_reason_code());\n"
                "                return self.respond(&draft, R::DenyPolicyDiagnostic, now);",
            ),
        )
        pipeline_start = actor_source.index("fn decide_intent_inner")
        for original, replacement in mutations:
            with self.subTest(removed_contract=original):
                contract_start = actor_source.index(original, pipeline_start)
                contract_end = contract_start + len(original)
                mutated = (
                    actor_source[:contract_start]
                    + replacement
                    + actor_source[contract_end:]
                )
                with self.assertRaisesRegex(
                    VERIFY.AuthorityModelError,
                    "AUTHORITY_RUST_GATE_PIPELINE_DRIFT",
                ):
                    VERIFY._verify_gate_pipeline_source(mutated)

    def test_regression_gate_pipeline_rejects_inert_source_decoys(self) -> None:
        actor_path = self.repo / "crates/haldir-gate/src/actor.rs"
        actor_source = actor_path.read_text(encoding="utf-8")
        pipeline_start = actor_source.index("fn decide_intent_inner")
        contract_start = actor_source.index(
            "try_decide_validated(&PolicyInput", pipeline_start
        )
        without_real_call = (
            actor_source[:contract_start]
            + "decide_validated(&PolicyInput"
            + actor_source[contract_start + len("try_decide_validated(&PolicyInput") :]
        )
        opening = without_real_call.index("{", pipeline_start) + 1
        marker_text = "\n".join(VERIFY.GATE_PIPELINE_ORDERED_MARKERS)
        decoys = (
            f"\n/*\n{marker_text}\n*/\n",
            f'\nlet _authority_pipeline_decoy = r####"\n{marker_text}\n"####;\n',
            "\nstringify!(let decision = match "
            "try_decide_validated(&PolicyInput));\n",
            "\n#[cfg(any())]\n"
            "{ let decision = match try_decide_validated(&PolicyInput); }\n",
        )

        for decoy in decoys:
            with self.subTest(decoy=decoy.splitlines()[1]):
                mutated = without_real_call[:opening] + decoy + without_real_call[opening:]
                with self.assertRaisesRegex(
                    VERIFY.AuthorityModelError,
                    "AUTHORITY_RUST_GATE_PIPELINE_DRIFT",
                ):
                    VERIFY._verify_gate_pipeline_source(mutated)

    def test_regression_gate_pipeline_rejects_dead_or_duplicate_items(self) -> None:
        actor_path = self.repo / "crates/haldir-gate/src/actor.rs"
        actor_source = actor_path.read_text(encoding="utf-8")
        code = VERIFY._rust_code_without_comments_or_literals(actor_source)
        pipeline_start = code.index(VERIFY.GATE_PIPELINE_FUNCTION_MARKER)
        body_start, body_end = VERIFY._rust_block_bounds(
            code, VERIFY.GATE_PIPELINE_FUNCTION_MARKER
        )
        contract_start = actor_source.index(
            "try_decide_validated(&PolicyInput", body_start
        )
        mutated_real_call = (
            actor_source[:contract_start]
            + "decide_validated(&PolicyInput"
            + actor_source[contract_start + len("try_decide_validated(&PolicyInput") :]
        )
        dead_code_decoy = (
            "\n        if false {\n"
            "            let _ = try_decide_validated(&PolicyInput);\n"
            "        }\n"
        )
        duplicate_item = actor_source[pipeline_start : body_end + 1]
        mutations = (
            (
                mutated_real_call[:body_start]
                + dead_code_decoy
                + mutated_real_call[body_start:]
            ),
            (
                mutated_real_call[:pipeline_start]
                + "#[cfg(any())]\n"
                + duplicate_item
                + "\n"
                + mutated_real_call[pipeline_start:]
            ),
            (
                actor_source[:pipeline_start]
                + "#[cfg(any())]\n"
                + actor_source[pipeline_start:]
            ),
        )

        for mutated in mutations:
            with self.subTest(mutated_sha256=VERIFY._sha256(mutated.encode("utf-8"))):
                with self.assertRaisesRegex(
                    VERIFY.AuthorityModelError,
                    "AUTHORITY_RUST_GATE_PIPELINE_DRIFT",
                ):
                    VERIFY._verify_gate_pipeline_source(mutated)

    def test_regression_gate_pipeline_rejects_item_tokens_inside_macro(self) -> None:
        actor_path = self.repo / "crates/haldir-gate/src/actor.rs"
        actor_source = actor_path.read_text(encoding="utf-8")
        code = VERIFY._rust_code_without_comments_or_literals(actor_source)
        pipeline_start = code.index(VERIFY.GATE_PIPELINE_FUNCTION_MARKER)
        _, body_end = VERIFY._rust_block_bounds(
            code, VERIFY.GATE_PIPELINE_FUNCTION_MARKER
        )
        function_item = actor_source[pipeline_start : body_end + 1]
        renamed = actor_source.replace(
            "decide_intent_inner", "evaluate_intent_inner"
        )
        renamed_start = renamed.index("fn evaluate_intent_inner")
        attribute_start = renamed.rfind(
            "#[allow(clippy::too_many_lines)]", 0, renamed_start
        )
        self.assertGreaterEqual(attribute_start, 0)
        inert_item = (
            "    const _AUTHORITY_PIPELINE_DECOY: &str = stringify!("
            "{} #[allow(clippy::too_many_lines)] "
            f"{function_item});\n\n"
        )
        mutated = renamed[:attribute_start] + inert_item + renamed[attribute_start:]

        with self.assertRaisesRegex(
            VERIFY.AuthorityModelError,
            "AUTHORITY_RUST_GATE_PIPELINE_DRIFT",
        ):
            VERIFY._verify_gate_pipeline_source(mutated)

    def test_rust_lexical_filter_preserves_code_offsets_and_lifetimes(self) -> None:
        source = (
            "fn checked<'a>(value: &'a str) {\n"
            "  let brace = '}'; // fn decide_intent_inner { decoy }\n"
            '  let raw = r##"fn decide_intent_inner { decoy }"##;\n'
            "  /* outer /* nested */ marker */\n"
            "  let retained_code = value;\n"
            "}\n"
        )
        filtered = VERIFY._rust_code_without_comments_or_literals(source)

        self.assertEqual(len(filtered), len(source))
        self.assertEqual(filtered.count("\n"), source.count("\n"))
        self.assertIn("fn checked<'a>(value: &'a str)", filtered)
        self.assertIn("let retained_code = value", filtered)
        self.assertNotIn("decoy", filtered)
        self.assertNotIn("marker", filtered)


if __name__ == "__main__":
    unittest.main()
