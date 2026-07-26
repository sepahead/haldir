"""Test the FR-0007 local-marker cardinality recovery."""

from __future__ import annotations

import ast
import hashlib
import importlib.util
import inspect
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


PARENT_COMMIT = "c11907924e86e117d092ae4153581f1bad257e5a"
PARENT_TREE = "ab572f00a2d288049455e8bf35805024fc75a10b"
DEFECT_CODE = "FR_0006_LOCAL_VALIDATION_P0_OK_CARDINALITY_UNSATISFIABLE"
REPAIR_SUBJECT = "release: repair local validation marker cardinality"
SUITE_KEYS = (
    "legacy",
    "fr_0002",
    "fr_0003",
    "resource",
    "fr_0004",
    "fr_0005",
    "fr_0006",
    "fr_0007",
)
P0_EXTRA_UNITTEST_COMMAND_COUNT = 6
REQUIRED_TEST_IDS = {
    "test_framework_recovery_7_activation_scope_is_exact",
    "test_framework_recovery_7_code_diff_excludes_plan",
    "test_framework_recovery_7_decision_is_fail_closed",
    "test_framework_recovery_7_epoch_7_is_not_reusable",
    "test_framework_recovery_7_expected_gate_payload_is_exact",
    "test_framework_recovery_7_expected_local_marker_counts_are_derived",
    "test_framework_recovery_7_expected_plan_has_exact_contract",
    "test_framework_recovery_7_forward_replay_has_pre_activation_guard",
    "test_framework_recovery_7_framework_history_requires_retirement",
    "test_framework_recovery_7_gate_order_and_warning_policy_are_exact",
    "test_framework_recovery_7_history_requires_exact_position",
    "test_framework_recovery_7_history_states_are_contiguous",
    "test_framework_recovery_7_hosted_and_review_contracts_are_purpose_separated",
    "test_framework_recovery_7_identity_constants_are_exact",
    "test_framework_recovery_7_local_markers_accept_epoch_8_topology",
    "test_framework_recovery_7_local_markers_reject_excess_ok",
    "test_framework_recovery_7_local_markers_reject_failure_tokens",
    "test_framework_recovery_7_local_markers_reject_parent_cardinality",
    "test_framework_recovery_7_local_markers_reject_suite_mutations",
    "test_framework_recovery_7_parent_bytes_are_pinned",
    "test_framework_recovery_7_parent_defect_arithmetic_is_exact",
    "test_framework_recovery_7_current_fr_0006_accepts_genuine_13",
    "test_framework_recovery_7_parent_fr_0006_accepts_synthetic_14",
    "test_framework_recovery_7_parent_has_no_fr_0006_q_or_a",
    "test_framework_recovery_7_p0_gate_is_unchanged_and_pinned",
    "test_framework_recovery_7_preserves_all_prior_test_suites",
    "test_framework_recovery_7_qualification_scope_is_exact",
    "test_framework_recovery_7_repair_scope_is_exact",
    "test_framework_recovery_7_retirement_absorbs_no_fr_0006_q_or_a",
    "test_framework_recovery_7_retires_fr_0006_without_qualification",
    "test_framework_recovery_7_signatures_and_chronology_are_bound",
    "test_framework_recovery_7_source_compatibility_rejects_drift",
    "test_framework_recovery_7_source_retention_is_exact",
    "test_framework_recovery_7_successor_requires_activation",
    "test_framework_recovery_7_test_source_ast_and_discovery_are_strict",
    "test_framework_recovery_7_transition_creates_epoch_8",
    "test_framework_recovery_7_wrapper_accepts_epochs_2_through_8",
}


def _repo() -> Path:
    return Path(__file__).resolve().parents[2]


def _load_verify():
    path = Path(__file__).with_name("verify-current-audit.py")
    spec = importlib.util.spec_from_file_location("verify_current_audit_fr_0007", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load verifier")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _git(*arguments: str) -> bytes:
    return subprocess.run(
        ["/usr/bin/git", "-C", str(_repo()), *arguments],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout


def _function_source(module: object, name: str) -> str:
    return inspect.getsource(getattr(module, name))


def _mutate_source_once(payload: bytes, old: bytes, new: bytes) -> bytes:
    if payload.count(old) != 1:
        raise AssertionError("mutation anchor is not unique")
    return payload.replace(old, new)


def _parent_counts() -> tuple[int, ...]:
    return (163, 78, 94, 26, 30, 44, 56)


def _marker_contract(counts: tuple[int, ...]) -> dict[str, object]:
    return {
        **{
            key: {"count": count}
            for key, count in zip(SUITE_KEYS, counts, strict=True)
        },
        "p0_extra_unittest_counts": [6, 10, 23, 26, 22, 24],
    }


def _marker_log(counts: tuple[int, ...], *, direct_ok: int, p0_ok: int) -> bytes:
    direct = (
        b"=== CURRENT_AUDIT_GATE ===\n"
        b"$ tools/release/current-audit-gate.sh\n"
        + b"".join(
            f"Ran {count} tests in 0.001s\n".encode("ascii") for count in counts
        )
        + b"OK\n" * direct_ok
        + b"verify-current-audit: OK\n"
    )
    p0_counts = (*counts, 6, 10, 23, 26, 22, 24)
    p0 = (
        b"=== P0R_EXIT_GATE ===\n$ tools/p0r-exit-gate.sh\n"
        + b"".join(
            f"Ran {count} tests in 0.001s\n".encode("ascii")
            for count in p0_counts
        )
        + b"OK\n" * p0_ok
        + b"verify-current-audit: OK\n"
        + b"P0-R exit gate: 30 passed, 0 failed\n"
    )
    return (
        direct
        + p0
        + b"=== RESOURCE_PROFILE ===\n"
        b"$ python3 -I tools/release/current-audit-resource-profile.py\n"
    )


def _history_chain(stage: str) -> list[str]:
    chain = _git(
        "rev-list",
        "--first-parent",
        "--reverse",
        "bfe0b136213a823913cee0f2f7e21e2992c6aced.." + PARENT_COMMIT,
    ).decode("ascii").splitlines()
    if stage in {"R", "Q", "A"}:
        chain.append("7" * 40)
    if stage in {"Q", "A"}:
        chain.append("8" * 40)
    if stage == "A":
        chain.append("9" * 40)
    return chain


class FrameworkRecovery7Tests(unittest.TestCase):
    def test_framework_recovery_7_identity_constants_are_exact(self) -> None:
        verify = _load_verify()
        self.assertEqual(verify.FRAMEWORK_RECOVERY_7_PARENT, PARENT_COMMIT)
        self.assertEqual(verify.FRAMEWORK_RECOVERY_7_PARENT_TREE, PARENT_TREE)
        self.assertEqual(verify.FRAMEWORK_RECOVERY_7_ID, "FR-0007")
        self.assertEqual(verify.FRAMEWORK_RECOVERY_7_DEFECT_CODE, DEFECT_CODE)
        self.assertEqual(verify.FRAMEWORK_RECOVERY_7_SUBJECT, REPAIR_SUBJECT)
        self.assertEqual(tuple(verify.FRAMEWORK_RECOVERY_7_SUITE_KEYS), SUITE_KEYS)
        self.assertEqual(
            verify.FRAMEWORK_RECOVERY_7_P0_EXTRA_UNITTEST_COMMAND_COUNT,
            P0_EXTRA_UNITTEST_COMMAND_COUNT,
        )

    def test_framework_recovery_7_parent_bytes_are_pinned(self) -> None:
        verify = _load_verify()
        pins = (
            (
                "tools/release/verify-current-audit.py",
                verify.FRAMEWORK_RECOVERY_7_PARENT_VERIFIER_BYTES,
                verify.FRAMEWORK_RECOVERY_7_PARENT_VERIFIER_SHA256,
                verify.FRAMEWORK_RECOVERY_7_PARENT_VERIFIER_OID,
            ),
            (
                "tools/release/test_verify_current_audit_fr_0006.py",
                verify.FRAMEWORK_RECOVERY_7_PARENT_FR6_TEST_BYTES,
                verify.FRAMEWORK_RECOVERY_7_PARENT_FR6_TEST_SHA256,
                verify.FRAMEWORK_RECOVERY_7_PARENT_FR6_TEST_OID,
            ),
            (
                "tools/release/current-audit-gate.sh",
                verify.FRAMEWORK_RECOVERY_7_PARENT_GATE_BYTES,
                verify.FRAMEWORK_RECOVERY_7_PARENT_GATE_SHA256,
                verify.FRAMEWORK_RECOVERY_7_PARENT_GATE_OID,
            ),
            (
                "tools/p0r-exit-gate.sh",
                verify.FRAMEWORK_RECOVERY_7_PARENT_P0_GATE_BYTES,
                verify.FRAMEWORK_RECOVERY_7_PARENT_P0_GATE_SHA256,
                verify.FRAMEWORK_RECOVERY_7_PARENT_P0_GATE_OID,
            ),
            (
                "release/0.9.0/current-head/closures/framework-recovery/FR-0006-plan.json",
                verify.FRAMEWORK_RECOVERY_7_PARENT_FR6_PLAN_BYTES,
                verify.FRAMEWORK_RECOVERY_7_PARENT_FR6_PLAN_SHA256,
                verify.FRAMEWORK_RECOVERY_7_PARENT_FR6_PLAN_OID,
            ),
        )
        for path, size, digest, oid in pins:
            with self.subTest(path=path):
                payload = _git("show", f"{PARENT_COMMIT}:{path}")
                entry = _git("ls-tree", PARENT_COMMIT, path).decode("ascii")
                self.assertEqual(len(payload), size)
                self.assertEqual(hashlib.sha256(payload).hexdigest(), digest)
                self.assertIn(f" blob {oid}\t", entry)

    def test_framework_recovery_7_parent_has_no_fr_0006_q_or_a(self) -> None:
        verify = _load_verify()
        self.assertFalse(
            verify._git_path_exists(
                _repo(), PARENT_COMMIT, verify.FRAMEWORK_RECOVERY_6_QUALIFICATION_PATH
            )
        )
        self.assertFalse(
            verify._git_path_exists(
                _repo(), PARENT_COMMIT, verify.FRAMEWORK_RECOVERY_6_ACTIVATION_PATH
            )
        )

    def test_framework_recovery_7_parent_defect_arithmetic_is_exact(self) -> None:
        verify = _load_verify()
        defect = verify._framework_recovery_7_parent_marker_defect(_repo())
        self.assertEqual(defect["code"], DEFECT_CODE)
        self.assertEqual(defect["parent_gate_unittest_suite_count"], 7)
        self.assertEqual(defect["p0_extra_unittest_command_count"], 6)
        self.assertEqual(defect["genuine_p0_bare_ok_count"], 13)
        self.assertEqual(defect["parent_required_p0_bare_ok_count"], 14)
        self.assertEqual(defect["cardinality_difference"], 1)
        self.assertFalse(defect["fr_0006_local_validation_contract_satisfiable"])

    def test_framework_recovery_7_parent_fr_0006_accepts_synthetic_14(self) -> None:
        verify = _load_verify()
        contract = {
            key: {"count": count}
            for key, count in zip(SUITE_KEYS[:-1], _parent_counts(), strict=True)
        }
        synthetic = _marker_log(_parent_counts(), direct_ok=7, p0_ok=14)
        genuine = _marker_log(_parent_counts(), direct_ok=7, p0_ok=13)
        parent = _git("show", f"{PARENT_COMMIT}:tools/release/verify-current-audit.py")
        current = Path(verify.__file__).read_bytes()
        self.assertIn(
            b'len(re.findall(rb"^OK$", p0, flags=re.MULTILINE)) != 14', parent
        )
        self.assertIn(
            b'len(re.findall(rb"^OK$", p0, flags=re.MULTILINE)) != 13', current
        )
        verify._framework_recovery_7_verify_frozen_parent_markers(
            parent, synthetic, genuine, test_contract=contract
        )

    def test_framework_recovery_7_current_fr_0006_accepts_genuine_13(self) -> None:
        verify = _load_verify()
        contract = {
            key: {"count": count}
            for key, count in zip(SUITE_KEYS[:-1], _parent_counts(), strict=True)
        }
        genuine = _marker_log(_parent_counts(), direct_ok=7, p0_ok=13)
        synthetic = _marker_log(_parent_counts(), direct_ok=7, p0_ok=14)
        verify._framework_recovery_6_verify_local_markers(
            genuine, test_contract=contract
        )
        with self.assertRaisesRegex(
            verify.CurrentAuditError,
            "CURRENT_AUDIT_FRAMEWORK_RECOVERY_6_LOCAL_LOG",
        ):
            verify._framework_recovery_6_verify_local_markers(
                synthetic, test_contract=contract
            )

    def test_framework_recovery_7_expected_local_marker_counts_are_derived(self) -> None:
        verify = _load_verify()
        contract = _marker_contract((*_parent_counts(), len(REQUIRED_TEST_IDS)))
        self.assertEqual(
            verify._framework_recovery_7_expected_local_marker_counts(contract),
            {
                "direct_suite_run_multiplicity": [1] * 8,
                "direct_bare_ok": 8,
                "p0_suite_run_multiplicity": [1, 1, 1, 2, 1, 1, 1, 1],
                "p0_bare_ok": 14,
                "p0_extra_unittest_command_count": 6,
            },
        )
        inherited = (
            _repo() / "tools/release/test_verify_audit_inputs.py"
        ).read_bytes()
        self.assertEqual(
            verify._framework_recovery_7_count_pinned_unittest_methods(
                inherited,
                "tools/release/test_verify_audit_inputs.py",
                expected_count=6,
            ),
            6,
        )
        positive_method = (
            b"    def test_positive_exact_audit_cut_verifies(self) -> None:\n"
            b"        VERIFY.verify(self.manifest_path, self.repo)\n"
        )
        mutations = (
            inherited
            + b"\ndef load_tests(loader, tests, pattern):\n    return tests\n",
            _mutate_source_once(
                inherited,
                b"class AuditInputVerificationTests(unittest.TestCase):\n",
                b"@unittest.skip('changed')\n"
                b"class AuditInputVerificationTests(unittest.TestCase):\n",
            ),
            _mutate_source_once(
                inherited,
                b"    def test_positive_exact_audit_cut_verifies(self) -> None:\n",
                b"    @unittest.skip('changed')\n"
                b"    def test_positive_exact_audit_cut_verifies(self) -> None:\n",
            ),
            _mutate_source_once(
                inherited,
                b"    def test_positive_exact_audit_cut_verifies(self) -> None:\n",
                b"    async def test_positive_exact_audit_cut_verifies(self) -> None:\n",
            ),
            _mutate_source_once(
                inherited,
                positive_method,
                positive_method + b"\n" + positive_method,
            ),
            _mutate_source_once(inherited, positive_method, b""),
            _mutate_source_once(
                inherited,
                positive_method,
                positive_method
                + b"\n"
                + b"    def test_added_topology_case(self) -> None:\n"
                + b"        self.assertTrue(True)\n",
            ),
        )
        for mutation in mutations:
            with self.subTest(digest=hashlib.sha256(mutation).hexdigest()):
                with self.assertRaisesRegex(
                    verify.CurrentAuditError,
                    "CURRENT_AUDIT_FRAMEWORK_RECOVERY_7_P0_TEST_TOPOLOGY",
                ):
                    verify._framework_recovery_7_count_pinned_unittest_methods(
                        mutation,
                        "tools/release/test_verify_audit_inputs.py",
                        expected_count=6,
                    )

    def test_framework_recovery_7_local_markers_accept_epoch_8_topology(self) -> None:
        verify = _load_verify()
        counts = (*_parent_counts(), len(REQUIRED_TEST_IDS))
        contract = _marker_contract(counts)
        self.assertIsNone(
            verify._framework_recovery_7_verify_local_markers(
                _marker_log(counts, direct_ok=8, p0_ok=14),
                test_contract=contract,
            )
        )

    def test_framework_recovery_7_local_markers_reject_parent_cardinality(self) -> None:
        verify = _load_verify()
        counts = (*_parent_counts(), len(REQUIRED_TEST_IDS))
        contract = _marker_contract(counts)
        with self.assertRaisesRegex(
            verify.CurrentAuditError,
            "CURRENT_AUDIT_FRAMEWORK_RECOVERY_7_LOCAL_LOG",
        ):
            verify._framework_recovery_7_verify_local_markers(
                _marker_log(counts, direct_ok=8, p0_ok=13), test_contract=contract
            )

    def test_framework_recovery_7_local_markers_reject_excess_ok(self) -> None:
        verify = _load_verify()
        counts = (*_parent_counts(), len(REQUIRED_TEST_IDS))
        contract = _marker_contract(counts)
        with self.assertRaises(verify.CurrentAuditError):
            verify._framework_recovery_7_verify_local_markers(
                _marker_log(counts, direct_ok=8, p0_ok=15), test_contract=contract
            )

    def test_framework_recovery_7_local_markers_reject_suite_mutations(self) -> None:
        verify = _load_verify()
        counts = (*_parent_counts(), len(REQUIRED_TEST_IDS))
        contract = _marker_contract(counts)
        valid = _marker_log(counts, direct_ok=8, p0_ok=14)
        fr7_marker = f"Ran {len(REQUIRED_TEST_IDS)} tests in 0.001s\n".encode(
            "ascii"
        )
        mutations = (
            valid.replace(fr7_marker, b"", 1),
            valid.replace(
                fr7_marker,
                fr7_marker + fr7_marker,
                1,
            ),
            valid.replace(
                b"=== P0R_EXIT_GATE ===\n$ tools/p0r-exit-gate.sh\n",
                b"=== P0R_EXIT_GATE ===\n$ tools/p0r-exit-gate.sh --changed\n",
                1,
            ),
            valid.replace(
                b"Ran 163 tests in 0.001s\nRan 78 tests in 0.001s\n",
                b"Ran 78 tests in 0.001s\nRan 163 tests in 0.001s\n",
                1,
            ),
            valid.replace(
                b"P0-R exit gate: 30 passed, 0 failed\n",
                b"Ran 999 tests in 0.001s\n"
                b"P0-R exit gate: 30 passed, 0 failed\n",
                1,
            ),
        )
        for payload in mutations:
            self.assertNotEqual(payload, valid)
            with self.subTest(payload=hashlib.sha256(payload).hexdigest()):
                with self.assertRaises(verify.CurrentAuditError):
                    verify._framework_recovery_7_verify_local_markers(
                        payload, test_contract=contract
                    )

    def test_framework_recovery_7_local_markers_reject_failure_tokens(self) -> None:
        verify = _load_verify()
        counts = (*_parent_counts(), len(REQUIRED_TEST_IDS))
        contract = _marker_contract(counts)
        valid = _marker_log(counts, direct_ok=8, p0_ok=14)
        for token in (b"\nFAILED", b"Traceback", b"skipped=1", b"##[error]"):
            with self.subTest(token=token), self.assertRaises(
                verify.CurrentAuditError
            ):
                verify._framework_recovery_7_verify_local_markers(
                    valid + token, test_contract=contract
                )

    def test_framework_recovery_7_p0_gate_is_unchanged_and_pinned(self) -> None:
        verify = _load_verify()
        payload = (_repo() / "tools/p0r-exit-gate.sh").read_bytes()
        self.assertEqual(len(payload), verify.FRAMEWORK_RECOVERY_7_PARENT_P0_GATE_BYTES)
        self.assertEqual(
            hashlib.sha256(payload).hexdigest(),
            verify.FRAMEWORK_RECOVERY_7_PARENT_P0_GATE_SHA256,
        )
        commands = re.findall(rb'^run .* python3 -m unittest .+$', payload, re.M)
        self.assertEqual(len(commands), P0_EXTRA_UNITTEST_COMMAND_COUNT)

    def test_framework_recovery_7_transition_creates_epoch_8(self) -> None:
        verify = _load_verify()
        transition = verify._framework_recovery_7_transition_identity()
        self.assertEqual(transition["epoch_7_state"], "ABORTED_BEFORE_QUALIFICATION")
        self.assertFalse(transition["epoch_7_reused"])
        self.assertTrue(transition["epoch_8_candidate_created"])
        self.assertEqual(transition["active_epoch_before_activation"], 2)

    def test_framework_recovery_7_epoch_7_is_not_reusable(self) -> None:
        verify = _load_verify()
        transition = verify._framework_recovery_7_transition_identity()
        self.assertFalse(transition["fr_0006_mechanism_reused"])
        self.assertFalse(transition["epoch_7_reused"])
        self.assertEqual(verify._framework_recovery_7_decision("ACTIVE")["framework_epoch"], 8)

    def test_framework_recovery_7_decision_is_fail_closed(self) -> None:
        verify = _load_verify()
        for state, active, allowed in (
            ("PENDING_QUALIFICATION", 2, False),
            ("QUALIFIED_PENDING_ACTIVATION", 2, False),
            ("ACTIVE", 8, True),
        ):
            with self.subTest(state=state):
                value = verify._framework_recovery_7_decision(state)
                self.assertEqual(value["active_framework_epoch"], active)
                self.assertIs(value["successor_transitions_allowed"], allowed)
                self.assertEqual(value["overall_release_status"], "NO_GO")
        with self.assertRaises(verify.CurrentAuditError):
            verify._framework_recovery_7_decision("UNKNOWN")

    def test_framework_recovery_7_expected_plan_has_exact_contract(self) -> None:
        verify = _load_verify()
        with tempfile.TemporaryDirectory() as directory:
            clone = Path(directory) / "repo"
            subprocess.run(
                [
                    "/usr/bin/git",
                    "clone",
                    "--quiet",
                    "--no-local",
                    str(_repo()),
                    str(clone),
                ],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            subprocess.run(
                [
                    "/usr/bin/git",
                    "-C",
                    str(clone),
                    "checkout",
                    "--quiet",
                    PARENT_COMMIT,
                ],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            for path in verify.FRAMEWORK_RECOVERY_7_CORE_PATHS:
                target = clone / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((_repo() / path).read_bytes())
            subprocess.run(
                [
                    "/usr/bin/git",
                    "-C",
                    str(clone),
                    "add",
                    "--",
                    *verify.FRAMEWORK_RECOVERY_7_CORE_PATHS,
                ],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            subprocess.run(
                [
                    "/usr/bin/git",
                    "-C",
                    str(clone),
                    "-c",
                    "user.name=Sepehr Mahmoudian",
                    "-c",
                    "user.email=sepmhn@gmail.com",
                    "commit",
                    "--quiet",
                    "--no-gpg-sign",
                    "-m",
                    REPAIR_SUBJECT,
                ],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            repair_commit = subprocess.run(
                ["/usr/bin/git", "-C", str(clone), "rev-parse", "HEAD"],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ).stdout.decode("ascii").strip()
            plan = verify._framework_recovery_7_expected_plan(
                clone, repair_commit, "f" * 40
            )
        self.assertEqual(
            [
                plan["test_contract"][key]["count"]
                for key in SUITE_KEYS
            ],
            [163, 78, 94, 26, 30, 44, 56, len(REQUIRED_TEST_IDS)],
        )
        self.assertEqual(
            plan["test_contract"]["p0_extra_unittest_counts"],
            [6, 10, 23, 26, 22, 24],
        )
        self.assertEqual(
            plan["correction"]["expected_local_marker_counts"],
            {
                "direct_suite_run_multiplicity": [1] * 8,
                "direct_bare_ok": 8,
                "p0_suite_run_multiplicity": [1, 1, 1, 2, 1, 1, 1, 1],
                "p0_bare_ok": 14,
                "p0_extra_unittest_command_count": 6,
            },
        )
        self.assertEqual(plan["framework_epoch"]["retired_candidate"], 7)
        self.assertEqual(plan["framework_epoch"]["next_candidate"], 8)
        self.assertEqual(plan["state"]["candidate_epoch"], 8)

    def test_framework_recovery_7_code_diff_excludes_plan(self) -> None:
        verify = _load_verify()
        self.assertNotIn(
            verify.FRAMEWORK_RECOVERY_7_PLAN_PATH,
            verify.FRAMEWORK_RECOVERY_7_CORE_PATHS,
        )
        self.assertEqual(
            set(verify.FRAMEWORK_RECOVERY_7_CORE_PATHS),
            {
                "tools/release/verify-current-audit.py",
                "tools/release/test_verify_current_audit_fr_0007.py",
                "tools/release/current-audit-gate.sh",
            },
        )

    def test_framework_recovery_7_repair_scope_is_exact(self) -> None:
        verify = _load_verify()
        self.assertEqual(
            verify.FRAMEWORK_RECOVERY_7_REPAIR_STATUSES,
            {
                verify.FRAMEWORK_RECOVERY_7_PLAN_PATH: "A",
                verify.FRAMEWORK_RECOVERY_7_TEST_PATH: "A",
                "tools/release/current-audit-gate.sh": "M",
                "tools/release/verify-current-audit.py": "M",
            },
        )

    def test_framework_recovery_7_qualification_scope_is_exact(self) -> None:
        verify = _load_verify()
        self.assertEqual(len(verify.FRAMEWORK_RECOVERY_7_QUALIFICATION_STATUSES), 14)
        self.assertTrue(
            all(
                status == "A"
                for status in verify.FRAMEWORK_RECOVERY_7_QUALIFICATION_STATUSES.values()
            )
        )
        expected = dict(sorted(verify.FRAMEWORK_RECOVERY_7_QUALIFICATION_STATUSES.items()))
        with mock.patch.object(
            verify, "_verify_data_only_commit", side_effect=RuntimeError("boundary")
        ) as boundary, self.assertRaisesRegex(RuntimeError, "boundary"):
            verify._verify_framework_recovery_7_qualification(
                _repo(), "7" * 40, "8" * 40, plan={}
            )
        boundary.assert_called_once_with(
            _repo(),
            commit="8" * 40,
            parent="7" * 40,
            expected_statuses=expected,
            label="FRAMEWORK_RECOVERY_7_QUALIFICATION",
        )
        regular = {"mode": "100644", "type": "blob", "oid": "a" * 40}
        with mock.patch.object(verify, "_git_tree_entry", return_value=regular):
            verify._framework_recovery_7_verify_stage_modes(
                _repo(), "8" * 40, {path: "100644" for path in expected},
                label="qualification",
            )
        with mock.patch.object(
            verify,
            "_git_tree_entry",
            return_value={"mode": "120000", "type": "blob", "oid": "a" * 40},
        ), self.assertRaisesRegex(
            verify.CurrentAuditError,
            "CURRENT_AUDIT_FRAMEWORK_RECOVERY_7_MODE",
        ):
            verify._framework_recovery_7_verify_stage_modes(
                _repo(), "8" * 40, {next(iter(expected)): "100644"},
                label="qualification",
            )

    def test_framework_recovery_7_activation_scope_is_exact(self) -> None:
        verify = _load_verify()
        self.assertEqual(len(verify.FRAMEWORK_RECOVERY_7_ACTIVATION_STATUSES), 7)
        self.assertTrue(
            all(
                status == "A"
                for status in verify.FRAMEWORK_RECOVERY_7_ACTIVATION_STATUSES.values()
            )
        )
        expected = dict(sorted(verify.FRAMEWORK_RECOVERY_7_ACTIVATION_STATUSES.items()))
        with mock.patch.object(
            verify, "_verify_data_only_commit", side_effect=RuntimeError("boundary")
        ) as boundary, self.assertRaisesRegex(RuntimeError, "boundary"):
            verify._verify_framework_recovery_7_activation(
                _repo(), "7" * 40, "8" * 40, "9" * 40, qualification={}
            )
        boundary.assert_called_once_with(
            _repo(),
            commit="9" * 40,
            parent="8" * 40,
            expected_statuses=expected,
            label="FRAMEWORK_RECOVERY_7_ACTIVATION",
        )

    def test_framework_recovery_7_expected_gate_payload_is_exact(self) -> None:
        verify = _load_verify()
        payload = (_repo() / "tools/release/current-audit-gate.sh").read_bytes()
        self.assertEqual(payload, verify._framework_recovery_7_expected_gate_payload())
        verify._framework_recovery_7_verify_gate_payload(payload)
        frozen = (
            b"(\n"
            b'  builtin cd -- "$FR6_COMPAT_DIR"\n'
            b'  "$PYTHON3" -B -I -W error \\\n'
            b'    "$FR6_COMPAT_DIR/tools/release/'
            b'test_verify_current_audit_fr_0006.py"\n'
            b")\n"
        )
        current = (
            b'"$PYTHON3" -B -I -W error '
            b"tools/release/test_verify_current_audit_fr_0007.py\n"
        )
        required_fragments = (
            b'/bin/mkdir -- "$FR6_COMPAT_DIR/tools"\n',
            b'/bin/mkdir -- "$FR6_COMPAT_DIR/tools/release"\n',
            b'  "$FR6_COMPAT_DIR/tools/release/'
            b'test_verify_current_audit_fr_0006.py")" \\\n'
            b"  == b9689ba7461cc16130efa9c128d41690635d2d3b ]]\n",
            b"/usr/bin/git cat-file blob "
            b"6260a482a62c10cea8961ad0be136ac0b3023ba7 \\\n",
            b'  "$FR6_COMPAT_DIR/tools/release/current-audit-gate.sh")" \\\n'
            b"  == 6260a482a62c10cea8961ad0be136ac0b3023ba7 ]]\n",
            b'    if [[ -d "$FR6_COMPAT_DIR/tools/release" ]]; then\n',
            b'      "$FR6_COMPAT_DIR/tools/release/'
            b'current-audit-gate.sh" \\\n',
            b'      /bin/rmdir -- "$FR6_COMPAT_DIR/tools/release"\n',
            b'    if [[ -d "$FR6_COMPAT_DIR/tools" ]]; then\n',
            b'      /bin/rmdir -- "$FR6_COMPAT_DIR/tools"\n',
            b'    /bin/rmdir -- "$FR6_COMPAT_DIR"\n',
            frozen,
        )
        for fragment in required_fragments:
            with self.subTest(fragment=hashlib.sha256(fragment).hexdigest()):
                self.assertEqual(payload.count(fragment), 1)
        mutations = (
            payload.replace(current, b"", 1),
            payload.replace(current, current + current, 1),
            payload.replace(frozen + current, current + frozen, 1),
        )
        for mutation in mutations:
            with self.subTest(digest=hashlib.sha256(mutation).hexdigest()):
                with self.assertRaisesRegex(
                    verify.CurrentAuditError,
                    "CURRENT_AUDIT_FRAMEWORK_RECOVERY_7_GATE_WIRING",
                ):
                    verify._framework_recovery_7_verify_gate_payload(mutation)

        cleanup_start = payload.index(b"FR2_COMPAT_DIR=\n")
        cleanup_end = payload.index(
            b'FR2_COMPAT_DIR="$(/usr/bin/mktemp -d '
            b'/tmp/haldir-fr2-gate.XXXXXX)"\n'
        )
        cleanup_prelude = payload[cleanup_start:cleanup_end]
        signal_statuses = {"HUP": 129, "INT": 130, "TERM": 143}
        with tempfile.TemporaryDirectory(
            prefix="haldir-fr7-fr6-cleanup-regression-"
        ) as directory:
            regression_root = Path(directory)
            script_path = regression_root / "exercise-cleanup.sh"
            script_path.write_bytes(
                b"#!/bin/bash\n"
                b"set -euo pipefail\n"
                + cleanup_prelude
                + b'FR6_COMPAT_DIR="$1"\n'
                + b'builtin kill -s "$2" "$$"\n'
                + b"builtin exit 99\n"
            )
            for phase in ("root", "tools", "release", "files"):
                for signal_name, expected_status in signal_statuses.items():
                    with self.subTest(phase=phase, signal=signal_name):
                        compatibility_root = (
                            regression_root / f"{phase}-{signal_name.lower()}"
                        )
                        compatibility_root.mkdir()
                        tools_root = compatibility_root / "tools"
                        release_root = tools_root / "release"
                        if phase in {"tools", "release", "files"}:
                            tools_root.mkdir()
                        if phase in {"release", "files"}:
                            release_root.mkdir()
                        if phase == "files":
                            for name in (
                                "current-audit-gate.sh",
                                "test_verify_current_audit_fr_0006.py",
                                "verify-current-audit.py",
                            ):
                                (release_root / name).write_bytes(b"")
                        completed = subprocess.run(
                            [
                                "/bin/bash",
                                "--noprofile",
                                "--norc",
                                str(script_path),
                                str(compatibility_root),
                                signal_name,
                            ],
                            check=False,
                            stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            timeout=30,
                            env={
                                "BASH_ENV": "/dev/null",
                                "ENV": "/dev/null",
                                "HOME": "/nonexistent",
                                "LANG": "C",
                                "LC_ALL": "C",
                                "PATH": "/usr/bin:/bin",
                            },
                        )
                        self.assertEqual(completed.stdout, b"")
                        self.assertEqual(
                            completed.returncode,
                            expected_status,
                            completed.stderr.decode("utf-8", errors="replace"),
                        )
                        self.assertFalse(compatibility_root.exists())

        with tempfile.TemporaryDirectory(
            prefix="haldir-fr7-fr6-compat-regression-"
        ) as directory:
            compatibility_root = Path(directory)
            release_root = compatibility_root / "tools/release"
            release_root.mkdir(parents=True)
            test_name = "test_verify_current_audit_fr_0006.py"
            test_source = _repo() / "tools/release" / test_name
            parent_test = _git("show", f"{PARENT_COMMIT}:tools/release/{test_name}")
            self.assertEqual(test_source.read_bytes(), parent_test)
            (release_root / test_name).symlink_to(test_source)
            parent_verifier = _git(
                "cat-file", "blob", verify.FRAMEWORK_RECOVERY_7_PARENT_VERIFIER_OID
            )
            parent_gate = _git(
                "cat-file", "blob", verify.FRAMEWORK_RECOVERY_7_PARENT_GATE_OID
            )
            self.assertEqual(
                hashlib.sha256(parent_verifier).hexdigest(),
                verify.FRAMEWORK_RECOVERY_7_PARENT_VERIFIER_SHA256,
            )
            self.assertEqual(
                hashlib.sha256(parent_gate).hexdigest(),
                verify.FRAMEWORK_RECOVERY_7_PARENT_GATE_SHA256,
            )
            (release_root / "verify-current-audit.py").write_bytes(parent_verifier)
            (release_root / "current-audit-gate.sh").write_bytes(parent_gate)
            completed = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    "-I",
                    "-W",
                    "error",
                    str(release_root / test_name),
                    (
                        "FrameworkRecovery6Tests."
                        "test_framework_recovery_6_expected_gate_payload_is_exact"
                    ),
                ],
                cwd=compatibility_root,
                check=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=300,
                env={
                    "GIT_CONFIG_GLOBAL": "/dev/null",
                    "GIT_CONFIG_NOSYSTEM": "1",
                    "GIT_NO_REPLACE_OBJECTS": "1",
                    "HOME": "/nonexistent",
                    "LANG": "C",
                    "LC_ALL": "C",
                    "PATH": "/usr/bin:/bin",
                },
            )
            self.assertEqual(completed.stdout, b"")
            self.assertEqual(
                completed.returncode,
                0,
                completed.stderr.decode("utf-8", errors="replace"),
            )
            self.assertRegex(completed.stderr, rb"Ran 1 test in [0-9.]+s\n")
            self.assertTrue(completed.stderr.rstrip().endswith(b"OK"))

    def test_framework_recovery_7_gate_order_and_warning_policy_are_exact(self) -> None:
        payload = (_repo() / "tools/release/current-audit-gate.sh").read_bytes()
        frozen_execution = (
            b"(\n"
            b'  builtin cd -- "$FR6_COMPAT_DIR"\n'
            b'  "$PYTHON3" -B -I -W error \\\n'
            b'    "$FR6_COMPAT_DIR/tools/release/'
            b'test_verify_current_audit_fr_0006.py"\n'
            b")\n"
        )
        current = b"tools/release/test_verify_current_audit_fr_0007.py"
        verifier = b"tools/release/verify-current-audit.py"
        self.assertEqual(payload.count(frozen_execution), 1)
        self.assertEqual(payload.count(current), 1)
        self.assertLess(payload.index(frozen_execution), payload.index(current))
        self.assertLess(payload.index(current), payload.rindex(verifier))
        self.assertIn(b'"$PYTHON3" -B -I -W error ', payload)

    def test_framework_recovery_7_preserves_all_prior_test_suites(self) -> None:
        verify = _load_verify()
        prior = (
            "tools/release/test_verify_current_audit.py",
            verify.FRAMEWORK_RECOVERY_2_TEST_PATH,
            verify.FRAMEWORK_RECOVERY_3_TEST_PATH,
            verify.FRAMEWORK_RECOVERY_3_RESOURCE_TEST_PATH,
            verify.FRAMEWORK_RECOVERY_4_TEST_PATH,
            verify.FRAMEWORK_RECOVERY_5_TEST_PATH,
            verify.FRAMEWORK_RECOVERY_6_TEST_PATH,
        )
        head = _git("rev-parse", "HEAD").decode("ascii").strip()
        for path in prior:
            self.assertEqual(
                verify._git_tree_entry(_repo(), PARENT_COMMIT, path),
                verify._git_tree_entry(_repo(), head, path),
            )

    def test_framework_recovery_7_test_source_ast_and_discovery_are_strict(self) -> None:
        verify = _load_verify()
        payload = Path(__file__).read_bytes()
        tree = verify._framework_recovery_7_validate_test_source(payload, __file__)
        ids = verify._discover_unittest_test_ids(payload, __file__, strict_runtime=True)
        self.assertEqual(set(ids), REQUIRED_TEST_IDS)
        self.assertEqual(len(ids), len(REQUIRED_TEST_IDS))
        self.assertEqual(
            hashlib.sha256(ast.dump(tree, include_attributes=False).encode()).hexdigest(),
            verify.FRAMEWORK_RECOVERY_7_TEST_AST_SHA256,
        )

    def test_framework_recovery_7_history_requires_exact_position(self) -> None:
        verify = _load_verify()
        with mock.patch.object(verify, "_verify_framework_recovery_7_repair", return_value={}):
            result = verify._verify_framework_recovery_7_history(
                _repo(), _history_chain("R"), framework_commit="f" * 40
            )
        self.assertEqual(result["repair_commit"], "7" * 40)
        invalid = _history_chain("R")
        invalid.insert(26, "a" * 40)
        with self.assertRaises(verify.CurrentAuditError):
            verify._verify_framework_recovery_7_history(
                _repo(), invalid, framework_commit="f" * 40
            )

    def test_framework_recovery_7_history_states_are_contiguous(self) -> None:
        verify = _load_verify()
        with (
            mock.patch.object(verify, "_verify_framework_recovery_7_repair", return_value={}),
            mock.patch.object(
                verify, "_verify_framework_recovery_7_qualification", return_value={}
            ),
            mock.patch.object(
                verify, "_verify_framework_recovery_7_activation", return_value={}
            ),
        ):
            states = [
                verify._verify_framework_recovery_7_history(
                    _repo(), _history_chain(stage), framework_commit="f" * 40
                )
                for stage in ("R", "Q", "A")
            ]
        self.assertEqual(
            [item["state"] for item in states],
            ["PENDING_QUALIFICATION", "QUALIFIED_PENDING_ACTIVATION", "ACTIVE"],
        )
        self.assertEqual([item["active_framework_epoch"] for item in states], [2, 2, 8])

    def test_framework_recovery_7_retires_fr_0006_without_qualification(self) -> None:
        verify = _load_verify()
        metadata = {"parent": PARENT_COMMIT, "subject": REPAIR_SUBJECT}
        with (
            mock.patch.object(verify, "_verify_framework_recovery_6_repair", return_value={}),
            mock.patch.object(verify, "_verify_framework_recovery_7_repair", return_value={}),
            mock.patch.object(verify, "_commit_metadata", side_effect=[metadata, metadata]),
            mock.patch.object(verify, "_git_path_exists", return_value=False),
        ):
            result = verify._verify_framework_recovery_6_history(
                _repo(), _history_chain("R"), framework_commit="f" * 40
            )
        self.assertEqual(result["state"], "ABORTED_BEFORE_QUALIFICATION")
        self.assertEqual(result["retirement_commit"], "7" * 40)
        self.assertIsNone(result["qualification_commit"])

    def test_framework_recovery_7_retirement_absorbs_no_fr_0006_q_or_a(self) -> None:
        verify = _load_verify()
        retirement = {"parent": PARENT_COMMIT, "subject": REPAIR_SUBJECT}
        later = {
            "parent": "7" * 40,
            "subject": verify.FRAMEWORK_RECOVERY_6_QUALIFICATION_SUBJECT,
        }
        with (
            mock.patch.object(verify, "_verify_framework_recovery_6_repair", return_value={}),
            mock.patch.object(verify, "_verify_framework_recovery_7_repair", return_value={}),
            mock.patch.object(
                verify, "_commit_metadata", side_effect=[retirement, retirement, later]
            ),
            mock.patch.object(verify, "_git_path_exists", return_value=False),
            self.assertRaisesRegex(
                verify.CurrentAuditError,
                "CURRENT_AUDIT_FRAMEWORK_RECOVERY_6_RETIREMENT_ABSORPTION",
            ),
        ):
            verify._verify_framework_recovery_6_history(
                _repo(), _history_chain("Q"), framework_commit="f" * 40
            )

    def test_framework_recovery_7_successor_requires_activation(self) -> None:
        verify = _load_verify()
        chain = _history_chain("A") + ["a" * 40]
        with self.assertRaisesRegex(
            verify.CurrentAuditError,
            "CURRENT_AUDIT_FRAMEWORK_RECOVERY_7_SUCCESSOR_BEFORE_ACTIVATION",
        ):
            verify._framework_recovery_7_verify_successor_guard(
                chain,
                28,
                repair_commit="7" * 40,
                activation_commit="9" * 40,
                recovery_transition=None,
            )
        verify._framework_recovery_7_verify_successor_guard(
            chain,
            28,
            repair_commit="7" * 40,
            activation_commit="9" * 40,
            recovery_transition={"stage": "QUALIFICATION"},
        )

    def test_framework_recovery_7_forward_replay_has_pre_activation_guard(self) -> None:
        verify = _load_verify()
        source = _function_source(verify, "_verify_forward_protocol_history")
        self.assertIn("_framework_recovery_7_verify_successor_guard", source)
        self.assertIn("recovery_7_repair_commit", source)
        self.assertIn("recovery_6_terminal_commit", source)
        self.assertIn("recovery_6_terminal_commit = descriptor.get(", source)
        self.assertIn(') or descriptor.get("retirement_commit")', source)
        self.assertIn("activation_commit=recovery_6_terminal_commit", source)
        self.assertIn("framework_epoch = (", source)
        self.assertIn("chain.index(recovery_7_repair_commit) <= position", source)
        chain = _history_chain("A") + ["a" * 40]
        verify._framework_recovery_6_verify_successor_guard(
            chain,
            30,
            repair_commit=PARENT_COMMIT,
            activation_commit="7" * 40,
            recovery_transition=None,
        )
        verify._framework_recovery_7_verify_successor_guard(
            chain,
            30,
            repair_commit="7" * 40,
            activation_commit="9" * 40,
            recovery_transition=None,
        )

    def test_framework_recovery_7_framework_history_requires_retirement(self) -> None:
        verify = _load_verify()
        source = _function_source(verify, "_verify_framework_history")
        self.assertIn('recovery_6["state"] != "ABORTED_BEFORE_QUALIFICATION"', source)
        self.assertIn('recovery_6["retirement_commit"] != recovery_7["repair_commit"]', source)
        self.assertIn("CURRENT_AUDIT_FRAMEWORK_RECOVERY_7_RETIREMENT_INVALID", source)

    def test_framework_recovery_7_source_retention_is_exact(self) -> None:
        verify = _load_verify()
        parent = _git("show", f"{PARENT_COMMIT}:tools/release/verify-current-audit.py")
        current = Path(verify.__file__).read_bytes()
        verify._framework_recovery_7_validate_source_compatibility(parent, current)
        self.assertEqual(
            verify._framework_recovery_7_unwrap_source_layer(_repo(), current), parent
        )
        self.assertIn(
            "_framework_recovery_6_verify_local_markers",
            verify.FRAMEWORK_RECOVERY_7_MODIFIED_DEFINITIONS,
        )

    def test_framework_recovery_7_source_compatibility_rejects_drift(self) -> None:
        verify = _load_verify()
        parent = _git("show", f"{PARENT_COMMIT}:tools/release/verify-current-audit.py")
        current = Path(verify.__file__).read_bytes()
        mutation = _mutate_source_once(
            current,
            b"return hashlib.sha256(payload).hexdigest()",
            b"return hashlib.sha256(payload + b'x').hexdigest()",
        )
        with self.assertRaises(verify.CurrentAuditError):
            verify._framework_recovery_7_validate_source_compatibility(parent, mutation)

    def test_framework_recovery_7_wrapper_accepts_epochs_2_through_8(self) -> None:
        verify = _load_verify()
        source = _function_source(verify, "_verify_post_activation_gate_retention")
        self.assertIn("framework_epoch not in {2, 3, 4, 5, 6, 7, 8}", source)
        self.assertIn("8: _framework_recovery_7_expected_gate_payload()", source)

    def test_framework_recovery_7_signatures_and_chronology_are_bound(self) -> None:
        verify = _load_verify()
        combined = "\n".join(
            _function_source(verify, name)
            for name in (
                "_verify_framework_recovery_7_repair",
                "_verify_framework_recovery_7_qualification",
                "_verify_framework_recovery_7_activation",
            )
        )
        for namespace in (
            "haldir-framework-recovery-fr-0007-plan-v1",
            "haldir-framework-recovery-fr-0007-qualification-v1",
            "haldir-framework-recovery-fr-0007-activation-v1",
        ):
            self.assertIn(namespace, combined)
        self.assertIn("_commit_datetime", combined)
        self.assertIn("_verify_named_commit_signature", combined)
        repair_time = verify._parse_utc(
            "2026-07-26T12:00:00Z", "fr_0007.test.repair"
        )
        qualification_time = verify._parse_utc(
            "2026-07-26T12:10:00Z", "fr_0007.test.qualification"
        )
        boundary_execution = {
            "started_at_utc": "2026-07-26T12:00:00Z",
            "completed_at_utc": "2026-07-26T12:00:00Z",
        }
        with mock.patch.object(
            verify,
            "_commit_datetime",
            side_effect=[repair_time, qualification_time],
        ):
            self.assertIsNone(
                verify._framework_recovery_7_validate_parent_reproduction_chronology(
                    _repo(), "7" * 40, "8" * 40, boundary_execution
                )
            )
        straddling_execution = {
            "started_at_utc": "2026-07-26T11:59:59Z",
            "completed_at_utc": "2026-07-26T12:00:01Z",
        }
        with mock.patch.object(
            verify,
            "_commit_datetime",
            side_effect=[repair_time, qualification_time],
        ), self.assertRaisesRegex(
            verify.CurrentAuditError,
            "CURRENT_AUDIT_FRAMEWORK_RECOVERY_7_REPRODUCTION_CHRONOLOGY",
        ):
            verify._framework_recovery_7_validate_parent_reproduction_chronology(
                _repo(), "7" * 40, "8" * 40, straddling_execution
            )

    def test_framework_recovery_7_hosted_and_review_contracts_are_purpose_separated(
        self,
    ) -> None:
        verify = _load_verify()
        self.assertEqual(
            set(verify._framework_recovery_7_review_contracts()),
            {"FR-0007-R01", "FR-0007-R02"},
        )
        source = _function_source(verify, "_framework_recovery_7_validate_review")
        self.assertIn("fr-0007-design@automated.invalid", source)
        self.assertIn("fr-0007-implementation@automated.invalid", source)
        self.assertIn("haldir-framework-recovery-fr-0007-local-integrity-v1", source)
        self.assertIn(
            "_framework_recovery_7_verify_run_attempt_uniqueness",
            _function_source(verify, "_verify_framework_recovery_7_activation"),
        )
        limitations = verify._framework_recovery_7_review_limitations()
        self.assertEqual(
            limitations.count(
                "REVIEW_MODEL_PROVENANCE_IS_NOT_INDEPENDENTLY_ATTESTED"
            ),
            1,
        )
        self.assertEqual(
            limitations.count(
                "LOCAL_PLATFORM_AND_TOOL_VERSIONS_ARE_SELF_REPORTED"
            ),
            1,
        )
        self.assertEqual(
            limitations.count(
                "LOCAL_EXECUTION_CHECKOUT_AND_TRANSCRIPT_PROVENANCE_"
                "ARE_SIGNER_ATTESTED_ONLY"
            ),
            1,
        )
        plan = {
            "code_diff": {},
            "source_retention": {},
            "transition_identity": {},
            "defect": {},
            "correction": {},
            "test_contract": {
                "required_regression_test_ids": sorted(REQUIRED_TEST_IDS)
            },
        }
        review_specs = (
            (
                "FR-0007-R01",
                "INTERNAL_AUTOMATED_DESIGN_REVIEW",
                "claude-fable-5",
                "claude-opus-5",
            ),
            (
                "FR-0007-R02",
                "INTERNAL_AUTOMATED_IMPLEMENTATION_REVIEW",
                "claude-opus-5",
                "claude-fable-5",
            ),
        )
        for review_id, kind, model, swapped_model in review_specs:
            contract = verify._framework_recovery_7_review_contracts()[review_id]
            narratives = {
                finding_id: {
                    "summary": "Substantive automated review finding.",
                    "disposition": "Resolved by the bound repair and evidence.",
                }
                for finding_id in contract
            }
            value = verify._framework_recovery_7_expected_review(
                review_id=review_id,
                kind=kind,
                repair_commit="7" * 40,
                plan=plan,
                narratives=narratives,
            )
            self.assertEqual(
                value["reviewer"],
                {
                    "provider": "Anthropic",
                    "model_requested": model,
                    "model_resolved": model,
                    "fallback_used": False,
                    "classification": "INTERNAL_AUTOMATED",
                    "human_review_performed": False,
                    "named_human_review_performed": False,
                    "external_independence": False,
                    "release_authority": False,
                    "capture_key_role": "LOCAL_RECORD_INTEGRITY_ONLY",
                },
            )
            for field, invalid in (
                ("model_resolved", swapped_model),
                ("fallback_used", True),
            ):
                mutation = verify._framework_recovery_7_expected_review(
                    review_id=review_id,
                    kind=kind,
                    repair_commit="7" * 40,
                    plan=plan,
                    narratives=narratives,
                )
                mutation["reviewer"][field] = invalid
                mutation["detached_signature"] = {}
                with self.subTest(review_id=review_id, field=field), self.assertRaisesRegex(
                    verify.CurrentAuditError,
                    "CURRENT_AUDIT_FRAMEWORK_RECOVERY_7_REVIEW_INVALID",
                ):
                    verify._framework_recovery_7_validate_review(
                        _repo(),
                        mutation,
                        review_id=review_id,
                        kind=kind,
                        repair_commit="7" * 40,
                        plan=plan,
                    )


if __name__ == "__main__":
    unittest.main()
