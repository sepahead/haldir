#!/usr/bin/env python3
"""Test the FR-0004 review-traceability recovery."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock


PARENT_COMMIT = "555108666cb82e8a36dcd4b08b5b30c62367a6f4"
PARENT_TREE = "579e182affefb69cf4113446eebfad0215b00cc6"


def _load_verify():
    """Load one isolated verifier module for a test."""

    module_path = Path(__file__).with_name("verify-current-audit.py")
    spec = importlib.util.spec_from_file_location(
        "verify_current_audit_fr_0004",
        module_path,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load the current-audit verifier")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _repo() -> Path:
    """Return the repository root."""

    return Path(__file__).resolve().parents[2]


def _git(*arguments: str) -> str:
    """Run one read-only Git query."""

    return subprocess.run(
        ["/usr/bin/git", *arguments],
        cwd=_repo(),
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/usr/bin:/bin",
        },
    ).stdout.decode("ascii").strip()


def _repair_commit() -> str:
    """Return the first child of the immutable FR-0004 parent."""

    commits = _git(
        "rev-list",
        "--first-parent",
        "--reverse",
        f"{PARENT_COMMIT}..HEAD",
    ).splitlines()
    if not commits:
        raise RuntimeError("FR-0004 repair commit is not present")
    return commits[0]


def _framework_commit(verify) -> str:
    """Return the original framework commit."""

    commits = _git(
        "rev-list",
        "--first-parent",
        "--reverse",
        f"{verify.IMPLEMENTATION_COMMIT}..{_repair_commit()}",
    ).splitlines()
    if not commits:
        raise RuntimeError("framework commit is not present")
    return commits[0]


def _repair_plan(verify) -> dict:
    """Read the canonical signed repair plan."""

    value, _payload = verify._read_commit_json(
        _repo(),
        _repair_commit(),
        verify.FRAMEWORK_RECOVERY_4_PLAN_PATH,
        "fr_0004.test.plan",
    )
    return value


def _function_source(verify, name: str) -> str:
    """Return one current verifier definition source segment."""

    payload = Path(verify.__file__).read_bytes()
    index = verify._framework_recovery_2_source_index(
        payload, label="fr_0004.test.current"
    )
    record = index["definitions"].get(name)
    if record is None:
        raise RuntimeError(f"missing verifier definition: {name}")
    source = payload.decode("utf-8")
    marker = f"def {name}("
    start = source.index(marker)
    next_definition = source.find("\ndef ", start + len(marker))
    return source[start:] if next_definition < 0 else source[start:next_definition]


class FrameworkRecovery4Tests(unittest.TestCase):
    """Keep the epoch-5 review-traceability recovery exact."""

    def test_framework_recovery_4_identity_constants_are_exact(self) -> None:
        verify = _load_verify()
        self.assertEqual(verify.FRAMEWORK_RECOVERY_4_PARENT, PARENT_COMMIT)
        self.assertEqual(verify.FRAMEWORK_RECOVERY_4_PARENT_TREE, PARENT_TREE)
        self.assertEqual(verify.FRAMEWORK_RECOVERY_4_ID, "FR-0004")
        self.assertEqual(
            verify.FRAMEWORK_RECOVERY_4_SUBJECT,
            "release: repair framework review traceability",
        )

    def test_framework_recovery_4_parent_bytes_are_pinned(self) -> None:
        verify = _load_verify()
        verifier = verify._git_file(
            _repo(), PARENT_COMMIT, "tools/release/verify-current-audit.py"
        )
        prior_test = verify._git_file(
            _repo(), PARENT_COMMIT, verify.FRAMEWORK_RECOVERY_3_TEST_PATH
        )
        self.assertEqual(
            (len(verifier), hashlib.sha256(verifier).hexdigest()),
            (
                verify.FRAMEWORK_RECOVERY_4_PARENT_VERIFIER_BYTES,
                verify.FRAMEWORK_RECOVERY_4_PARENT_VERIFIER_SHA256,
            ),
        )
        self.assertEqual(
            (len(prior_test), hashlib.sha256(prior_test).hexdigest()),
            (
                verify.FRAMEWORK_RECOVERY_4_PARENT_FR3_TEST_BYTES,
                verify.FRAMEWORK_RECOVERY_4_PARENT_FR3_TEST_SHA256,
            ),
        )

    def test_framework_recovery_4_parent_has_no_q_or_a(self) -> None:
        verify = _load_verify()
        for path in (
            verify.FRAMEWORK_RECOVERY_3_QUALIFICATION_PATH,
            verify.FRAMEWORK_RECOVERY_3_ACTIVATION_PATH,
        ):
            self.assertFalse(
                verify._git_path_exists(_repo(), PARENT_COMMIT, path)
            )

    def test_framework_recovery_4_defect_reproduction_is_exact(self) -> None:
        verify = _load_verify()
        defect = verify._framework_recovery_4_parent_defect(_repo())
        self.assertEqual(
            defect["parent_resolving_test_ids"],
            list(verify.FRAMEWORK_RECOVERY_4_FALSE_F104_TEST_IDS),
        )
        self.assertEqual(
            defect["required_resolving_test_ids"],
            list(verify.FRAMEWORK_RECOVERY_4_REQUIRED_F104_TEST_IDS),
        )
        self.assertTrue(
            defect["required_test_directly_calls_uniqueness_validator"]
        )
        self.assertFalse(
            defect["historical_false_tests_call_uniqueness_validator"]
        )
        for command, exit_status in (
            (["python3", "-I", "wrong.py"], 0),
            (
                list(
                    verify._framework_recovery_4_parent_reproduction_command()
                ),
                1,
            ),
        ):
            with (
                self.subTest(command=command, exit_status=exit_status),
                mock.patch.object(
                    verify, "_git_file", return_value=b"compressed"
                ),
                mock.patch.object(
                    verify,
                    "_decompress_unbound_gzip",
                    return_value=b"raw",
                ),
                mock.patch.object(
                    verify,
                    "_framework_recovery_4_parent_defect",
                    return_value=defect,
                ),
                self.assertRaisesRegex(
                    verify.CurrentAuditError, "REPRODUCTION_EXECUTION"
                ),
            ):
                verify._framework_recovery_4_expected_parent_reproduction(
                    _repo(),
                    "a" * 40,
                    "b" * 40,
                    defect=defect,
                    command=command,
                    exit_status=exit_status,
                    started_at_utc="2026-07-24T00:00:00Z",
                    completed_at_utc="2026-07-24T00:00:01Z",
                )
        with self.assertRaisesRegex(
            verify.CurrentAuditError, "REPRODUCTION_INVALID"
        ):
            verify._framework_recovery_4_validate_parent_reproduction(
                Path("."),
                "a" * 40,
                "b" * 40,
                [],
                evidence_record={},
            )
        value = {
            "schema_version": "1.0.0",
            "evidence_id": "FR-0004-E01",
            "kind": "DETERMINISTIC_PARENT_DEFECT_REPRODUCTION",
            "parent_commit": PARENT_COMMIT,
            "parent_tree": PARENT_TREE,
            "repair_commit": "a" * 40,
            "parent_verifier_record": {},
            "parent_fr_0003_test_record": {},
            "defect": {},
            "test_id": "test",
            "command": [],
            "capture": "MERGED_STDOUT_STDERR_RAW_BYTES",
            "exit_status": 0,
            "raw_log": {"file": {}, "uncompressed": {}},
            "started_at_utc": "2026-07-24T00:00:00Z",
            "completed_at_utc": "2026-07-24T00:00:01Z",
            "result": "PARENT_DEFECT_REPRODUCED",
        }
        with (
            mock.patch.object(
                verify,
                "_framework_recovery_4_expected_parent_reproduction",
                return_value=copy.deepcopy(value),
            ),
            mock.patch.object(verify, "_git_file", return_value=b"compressed"),
            mock.patch.object(
                verify,
                "_decompress_unbound_gzip",
                return_value=b"semantic-only fabrication\n",
            ),
            mock.patch.object(
                verify,
                "_framework_recovery_4_parent_reproduction_log",
                return_value=b"receipt\n",
            ),
            self.assertRaisesRegex(
                verify.CurrentAuditError, "REPRODUCTION_LOG"
            ),
        ):
            verify._framework_recovery_4_validate_parent_reproduction(
                Path("."),
                "a" * 40,
                "b" * 40,
                value,
                evidence_record={
                    "files": [None, {}],
                    "uncompressed": [None, {}],
                },
            )
        sys.stdout.write(
            verify._framework_recovery_4_parent_reproduction_log(
                _repo()
            ).decode("ascii")
        )

    def test_framework_recovery_4_f104_mapping_is_corrected(self) -> None:
        verify = _load_verify()
        contracts = verify._framework_recovery_3_review_contracts()
        self.assertEqual(
            contracts["FR-0003-R02"]["F104"]["resolving_test_ids"],
            list(verify.FRAMEWORK_RECOVERY_4_REQUIRED_F104_TEST_IDS),
        )
        for review_id, finding_id in (
            ("FR-0003-R01", "F001"),
            ("FR-0003-R02", "F105"),
        ):
            with self.subTest(review_id=review_id, finding_id=finding_id):
                mutated = copy.deepcopy(contracts)
                mutated[review_id][finding_id]["resolving_test_ids"].append(
                    "test_unrelated_mutation"
                )
                with (
                    mock.patch.object(
                        verify,
                        "_framework_recovery_3_review_contracts",
                        return_value=mutated,
                    ),
                    self.assertRaisesRegex(
                        verify.CurrentAuditError,
                        "UNRELATED_CONTRACT_CHANGE",
                    ),
                ):
                    verify._framework_recovery_4_historical_f104_mapping(
                        _repo()
                    )

    def test_framework_recovery_4_review_contract_cites_actual_test(
        self,
    ) -> None:
        verify = _load_verify()
        finding = verify._framework_recovery_4_review_contracts()[
            "FR-0004-R02"
        ]["F101"]
        self.assertIn(
            verify.FRAMEWORK_RECOVERY_4_REQUIRED_F104_TEST_IDS[0],
            finding["resolving_test_ids"],
        )
        self.assertEqual(
            set(verify._framework_recovery_4_review_contracts()),
            {"FR-0004-R01", "FR-0004-R02"},
        )
        self.assertTrue(
            all(
                len(findings) == 5
                for findings in verify._framework_recovery_4_review_contracts().values()
            )
        )
        plan = {
            "code_diff": {},
            "source_retention": {},
            "transition_identity": {},
            "defect": {},
            "correction": {},
            "test_contract": {
                "required_regression_test_ids": sorted(
                    verify.FRAMEWORK_RECOVERY_4_REQUIRED_TEST_IDS
                )
            },
        }
        narratives = {
            finding_id: {"summary": "summary", "disposition": "disposition"}
            for finding_id in verify._framework_recovery_4_review_contracts()[
                "FR-0004-R01"
            ]
        }
        malformed = verify._framework_recovery_4_expected_review(
            review_id="FR-0004-R01",
            kind="INTERNAL_AUTOMATED_DESIGN_REVIEW",
            repair_commit="a" * 40,
            plan=plan,
            narratives=narratives,
        )
        malformed["detached_signature"] = {}
        malformed["findings"][0]["id"] = []
        with self.assertRaisesRegex(
            verify.CurrentAuditError, "REVIEW_FINDINGS"
        ):
            verify._framework_recovery_4_validate_review(
                Path("."),
                malformed,
                review_id="FR-0004-R01",
                kind="INTERNAL_AUTOMATED_DESIGN_REVIEW",
                repair_commit="a" * 40,
                plan=plan,
            )
        source_key = {"public_key": "source", "key_fingerprint": "source-fp"}
        with self.assertRaisesRegex(
            verify.CurrentAuditError, "REVIEW_KEY_SEPARATION"
        ):
            verify._framework_recovery_4_verify_review_key_separation(
                source_key,
                [
                    {"public_key": "same", "key_fingerprint": "same-fp"},
                    {"public_key": "same", "key_fingerprint": "same-fp"},
                ],
            )
        with self.assertRaisesRegex(
            verify.CurrentAuditError, "REVIEW_KEY_SEPARATION"
        ):
            verify._framework_recovery_4_verify_review_key_separation(
                source_key,
                [
                    {"public_key": "source", "key_fingerprint": "source-fp"},
                    {"public_key": "other", "key_fingerprint": "other-fp"},
                ],
            )

    def test_framework_recovery_4_transition_creates_epoch_5(self) -> None:
        verify = _load_verify()
        transition = verify._framework_recovery_4_transition_identity()
        self.assertEqual(len(transition), 8)
        self.assertTrue(transition["epoch_5_candidate_created"])
        self.assertFalse(transition["epoch_4_reused"])
        self.assertEqual(transition["active_epoch_before_activation"], 2)

    def test_framework_recovery_4_epoch_4_is_not_reusable(self) -> None:
        verify = _load_verify()
        transition = verify._framework_recovery_4_transition_identity()
        self.assertEqual(
            transition["epoch_4_state"], "ABORTED_BEFORE_QUALIFICATION"
        )
        plan = _repair_plan(verify)
        self.assertFalse(plan["retired_recovery"]["epoch_reusable"])

    def test_framework_recovery_4_decision_is_fail_closed(self) -> None:
        verify = _load_verify()
        for state, active in (
            ("PENDING_QUALIFICATION", 2),
            ("QUALIFIED_PENDING_ACTIVATION", 2),
            ("ACTIVE", 5),
        ):
            with self.subTest(state=state):
                decision = verify._framework_recovery_4_decision(state)
                self.assertEqual(decision["active_framework_epoch"], active)
                self.assertEqual(decision["overall_release_status"], "NO_GO")
                self.assertFalse(decision["publication_authorized"])
                self.assertFalse(decision["doi_authorized"])
        with self.assertRaisesRegex(
            verify.CurrentAuditError, "DECISION_STATE"
        ):
            verify._framework_recovery_4_decision("UNKNOWN")

    def test_framework_recovery_4_expected_gate_payload_is_exact(self) -> None:
        verify = _load_verify()
        payload = verify._git_file(
            _repo(),
            _repair_commit(),
            "tools/release/current-audit-gate.sh",
        )
        self.assertEqual(
            payload, verify._framework_recovery_4_expected_gate_payload()
        )
        self.assertEqual(
            payload.count(
                b"tools/release/test_verify_current_audit_fr_0004.py"
            ),
            1,
        )
        fr2_invocation = (
            b'"$PYTHON3" -B -I -W error::ResourceWarning \\\n'
            b'  "$FR2_COMPAT_DIR/test_verify_current_audit_fr_0002.py"\n'
        )
        fr3_invocation = (
            b'"$PYTHON3" -B -I -W error \\\n'
            b'  "$FR3_COMPAT_DIR/test_verify_current_audit_fr_0003.py"\n'
        )
        fr3_cleanup = (
            b'  if [[ -n "$FR3_COMPAT_DIR" ]]; then\n'
            b"    /bin/rm -f -- \\\n"
            b'      "$FR3_COMPAT_DIR/current-audit-gate.sh" \\\n'
            b'      "$FR3_COMPAT_DIR/current-audit-resource-profile.py" \\\n'
            b'      "$FR3_COMPAT_DIR/test_current_audit_resource_profile.py" \\\n'
            b'      "$FR3_COMPAT_DIR/test_verify_current_audit_fr_0003.py" \\\n'
            b'      "$FR3_COMPAT_DIR/verify-current-audit.py"\n'
            b'    /bin/rmdir -- "$FR3_COMPAT_DIR"\n'
            b"  fi\n"
        )
        exit_trap = b"builtin trap cleanup_fr2_compat EXIT\n"
        self.assertEqual(payload.count(fr2_invocation), 1)
        self.assertEqual(payload.count(fr3_invocation), 1)
        self.assertEqual(payload.count(b'"$PYTHON3" -B -I'), 2)
        self.assertEqual(payload.count(fr3_cleanup), 1)
        self.assertEqual(payload.count(exit_trap), 1)
        self.assertLess(payload.index(fr3_cleanup), payload.index(exit_trap))
        self.assertLess(payload.index(exit_trap), payload.index(fr3_invocation))
        self.assertNotIn(b"__pycache__", payload)

    def test_framework_recovery_4_repair_scope_is_exact(self) -> None:
        verify = _load_verify()
        self.assertEqual(
            verify._changed_path_statuses(
                _repo(), PARENT_COMMIT, _repair_commit()
            ),
            dict(sorted(verify.FRAMEWORK_RECOVERY_4_REPAIR_STATUSES.items())),
        )
        self.assertEqual(len(verify.FRAMEWORK_RECOVERY_4_REPAIR_STATUSES), 4)

    def test_framework_recovery_4_qualification_scope_is_exact(self) -> None:
        verify = _load_verify()
        self.assertEqual(
            len(verify.FRAMEWORK_RECOVERY_4_QUALIFICATION_STATUSES), 13
        )
        self.assertTrue(
            all(
                status == "A"
                for status in verify.FRAMEWORK_RECOVERY_4_QUALIFICATION_STATUSES.values()
            )
        )

    def test_framework_recovery_4_activation_scope_is_exact(self) -> None:
        verify = _load_verify()
        self.assertEqual(
            len(verify.FRAMEWORK_RECOVERY_4_ACTIVATION_STATUSES), 7
        )
        self.assertTrue(
            all(
                status == "A"
                for status in verify.FRAMEWORK_RECOVERY_4_ACTIVATION_STATUSES.values()
            )
        )

    def test_framework_recovery_4_stage_modes_are_regular(self) -> None:
        verify = _load_verify()
        regular = {"mode": "100644", "type": "blob"}
        with mock.patch.object(
            verify, "_git_tree_entry", return_value=regular
        ):
            verify._framework_recovery_4_verify_stage_modes(
                Path("."), "a" * 40, {"x": "100644"}, label="test"
            )
        with (
            mock.patch.object(
                verify,
                "_git_tree_entry",
                return_value={"mode": "120000", "type": "blob"},
            ),
            self.assertRaisesRegex(verify.CurrentAuditError, "MODE:test:x"),
        ):
            verify._framework_recovery_4_verify_stage_modes(
                Path("."), "a" * 40, {"x": "100644"}, label="test"
            )

    def test_framework_recovery_4_code_diff_excludes_plan(self) -> None:
        verify = _load_verify()
        diff = verify._framework_recovery_4_code_diff(
            _repo(), _repair_commit()
        )
        self.assertEqual(
            diff["paths"], list(verify.FRAMEWORK_RECOVERY_4_CORE_PATHS)
        )
        self.assertNotIn(
            verify.FRAMEWORK_RECOVERY_4_PLAN_PATH, diff["paths"]
        )
        self.assertGreater(diff["patch_bytes"], 0)

    def test_framework_recovery_4_expected_plan_has_exact_fields(self) -> None:
        verify = _load_verify()
        expected = verify._framework_recovery_4_expected_plan(
            _repo(), _repair_commit(), _framework_commit(verify)
        )
        plan = _repair_plan(verify)
        comparable = {
            key: value
            for key, value in plan.items()
            if key not in {"created_at_utc", "detached_signature"}
        }
        self.assertEqual(comparable, expected)
        self.assertEqual(len(plan), 30)

    def test_framework_recovery_4_preserves_prior_test_suites(self) -> None:
        verify = _load_verify()
        for path in (
            "tools/release/test_verify_current_audit.py",
            verify.FRAMEWORK_RECOVERY_2_TEST_PATH,
            verify.FRAMEWORK_RECOVERY_3_TEST_PATH,
            verify.FRAMEWORK_RECOVERY_3_RESOURCE_TEST_PATH,
        ):
            with self.subTest(path=path):
                self.assertEqual(
                    verify._git_tree_entry(_repo(), PARENT_COMMIT, path),
                    verify._git_tree_entry(
                        _repo(), _repair_commit(), path
                    ),
                )
        for retention_manifest in (
            verify._framework_recovery_2_source_retention_manifest,
            verify._framework_recovery_3_source_retention_manifest,
        ):
            with self.subTest(retention_manifest=retention_manifest.__name__):
                manifest = retention_manifest(_repo(), _repair_commit())
                self.assertTrue(
                    manifest["protected_residual"]["byte_exact"]
                )

    def test_framework_recovery_4_test_contract_is_warning_strict(self) -> None:
        verify = _load_verify()
        contract = verify._framework_recovery_4_test_contract(
            _repo(), _repair_commit()
        )
        self.assertEqual(contract["warning_policy"], "-W error")
        self.assertEqual(
            set(contract["required_regression_test_ids"]),
            verify.FRAMEWORK_RECOVERY_4_REQUIRED_TEST_IDS,
        )
        self.assertEqual(contract["fr_0004"]["count"], 30)

    def test_framework_recovery_4_source_retention_rejects_unrelated_change(
        self,
    ) -> None:
        verify = _load_verify()
        parent_payload = verify._git_file(
            _repo(), PARENT_COMMIT, "tools/release/verify-current-audit.py"
        )
        target_payload = Path(verify.__file__).read_bytes()
        self.assertEqual(
            verify.FRAMEWORK_RECOVERY_4_MODIFIED_DEFINITIONS,
            {
                "_framework_recovery_2_source_retention_manifest",
                "_framework_recovery_3_review_contracts",
                "_framework_recovery_3_source_retention_manifest",
                "_verify_forward_protocol_history",
                "_verify_framework_history",
                "_verify_framework_recovery_3_history",
                "_verify_post_activation_gate_retention",
            },
        )
        gap_mutations = (
            target_payload.replace(
                b"\ndef _framework_recovery_4_expected_gate_payload(",
                b"\n# unauthorized interstitial drift\n"
                b"def _framework_recovery_4_expected_gate_payload(",
                1,
            ),
            target_payload.replace(
                b'\nif __name__ == "__main__":\n',
                b"\n# unauthorized main-guard drift\n"
                b'if __name__ == "__main__":\n',
                1,
            ),
        )
        self.assertTrue(
            all(mutation != target_payload for mutation in gap_mutations)
        )
        for mutation in gap_mutations:
            with (
                self.subTest(kind="protected_residual"),
                self.assertRaisesRegex(
                    verify.CurrentAuditError,
                    "^CURRENT_AUDIT_FRAMEWORK_RECOVERY_4_"
                    "SOURCE_COMPATIBILITY$",
                ),
            ):
                verify._framework_recovery_4_validate_source_compatibility(
                    parent_payload, mutation
                )
        parent_index = verify._framework_recovery_2_source_index(
            parent_payload, label="test.parent"
        )
        target_index = verify._framework_recovery_2_source_index(
            target_payload, label="test.target"
        )
        mutated = copy.deepcopy(target_index)
        mutated["definitions"]["_framework_recovery_4_hidden"] = {
            "kind": "FunctionDef",
            "source_sha256": "0" * 64,
            "ast_sha256": "1" * 64,
        }

        def git_file(_repo_path, commit, _path):
            return parent_payload if commit == PARENT_COMMIT else target_payload

        with (
            mock.patch.object(verify, "_git_file", side_effect=git_file),
            mock.patch.object(
                verify,
                "_framework_recovery_2_source_index",
                side_effect=(parent_index, mutated),
            ),
            self.assertRaisesRegex(
                verify.CurrentAuditError,
                "^CURRENT_AUDIT_FRAMEWORK_RECOVERY_4_"
                "SOURCE_COMPATIBILITY$",
            ),
        ):
            verify._framework_recovery_4_source_retention_manifest(
                Path("."), "a" * 40
            )

        path = "tools/release/verify-current-audit.py"
        fr_0002_parent = verify._git_file(
            _repo(), verify.FRAMEWORK_RECOVERY_2_PARENT, path
        )
        missing_anchor = target_payload.replace(
            b'\nFRAMEWORK_RECOVERY_4_PARENT = "',
            b'\nFRAMEWORK_RECOVERY_4_PARENT_REMOVED = "',
            1,
        )
        wrong_anchor = target_payload.replace(
            (
                b'\nFRAMEWORK_RECOVERY_4_PARENT = "'
                + PARENT_COMMIT.encode("ascii")
                + b'"\n'
            ),
            (
                b'\nFRAMEWORK_RECOVERY_4_PARENT = "'
                + b"0" * 40
                + b'"\n'
            ),
            1,
        )
        self.assertNotEqual(missing_anchor, target_payload)
        self.assertNotEqual(wrong_anchor, target_payload)

        def historical_git_file(_repo_path, commit, selected_path):
            self.assertEqual(selected_path, path)
            if commit == verify.FRAMEWORK_RECOVERY_2_PARENT:
                return fr_0002_parent
            return missing_anchor

        with (
            mock.patch.object(
                verify, "_git_file", side_effect=historical_git_file
            ),
            self.assertRaisesRegex(
                verify.CurrentAuditError,
                "^CURRENT_AUDIT_FRAMEWORK_RECOVERY_4_"
                "SOURCE_COMPATIBILITY$",
            ),
        ):
            verify._framework_recovery_2_source_retention_manifest(
                _repo(), "a" * 40
            )

        def wrong_anchor_git_file(_repo_path, commit, selected_path):
            self.assertEqual(selected_path, path)
            if commit == verify.FRAMEWORK_RECOVERY_2_PARENT:
                return fr_0002_parent
            return wrong_anchor

        with (
            mock.patch.object(
                verify, "_git_file", side_effect=wrong_anchor_git_file
            ),
            mock.patch.object(
                verify, "FRAMEWORK_RECOVERY_4_PARENT", "0" * 40
            ),
            mock.patch.object(verify, "_git_tree_entry", return_value=None),
            self.assertRaisesRegex(
                verify.CurrentAuditError,
                "^CURRENT_AUDIT_FRAMEWORK_RECOVERY_4_"
                "SOURCE_COMPATIBILITY$",
            ),
        ):
            verify._framework_recovery_2_source_retention_manifest(
                _repo(), "a" * 40
            )

        def current_target_git_file(_repo_path, commit, selected_path):
            self.assertEqual(selected_path, path)
            if commit == verify.FRAMEWORK_RECOVERY_2_PARENT:
                return fr_0002_parent
            return target_payload

        for bad_entry in (
            {"mode": "100755", "type": "blob", "oid": "a" * 40},
            {"mode": "100644", "type": "tree", "oid": "b" * 40},
        ):
            with (
                self.subTest(bad_anchor_entry=bad_entry),
                mock.patch.object(
                    verify,
                    "_git_file",
                    side_effect=current_target_git_file,
                ),
                mock.patch.object(
                    verify, "_git_tree_entry", return_value=bad_entry
                ),
                self.assertRaisesRegex(
                    verify.CurrentAuditError,
                    "^CURRENT_AUDIT_FRAMEWORK_RECOVERY_4_"
                    "SOURCE_COMPATIBILITY$",
                ),
            ):
                verify._framework_recovery_2_source_retention_manifest(
                    _repo(), "a" * 40
                )

    def test_framework_recovery_4_retires_fr_0003_without_qualification(
        self,
    ) -> None:
        verify = _load_verify()
        source = _function_source(
            verify, "_verify_framework_recovery_3_history"
        )
        self.assertIn("FRAMEWORK_RECOVERY_4_SUBJECT", source)
        self.assertIn('"state": "ABORTED_BEFORE_QUALIFICATION"', source)
        self.assertLess(
            source.index("_verify_framework_recovery_4_repair"),
            source.index("_verify_framework_recovery_3_qualification"),
        )
        chain = [f"{index + 1:040x}" for index in range(25)]
        chain[21] = verify.FRAMEWORK_RECOVERY_2_PARENT
        chain[22] = verify.FRAMEWORK_RECOVERY_3_PARENT
        chain[23] = verify.FRAMEWORK_RECOVERY_4_PARENT
        chain[24] = "f" * 40
        with (
            mock.patch.object(
                verify,
                "_verify_framework_recovery_3_repair",
                return_value={},
            ),
            mock.patch.object(
                verify,
                "_commit_metadata",
                return_value={
                    "parent": verify.FRAMEWORK_RECOVERY_4_PARENT,
                    "subject": verify.FRAMEWORK_RECOVERY_4_SUBJECT,
                },
            ),
            mock.patch.object(
                verify, "_verify_framework_recovery_4_repair", return_value={}
            ) as retirement,
        ):
            result = verify._verify_framework_recovery_3_history(
                Path("."), chain, framework_commit="e" * 40
            )
        self.assertEqual(result["state"], "ABORTED_BEFORE_QUALIFICATION")
        self.assertEqual(result["retirement_commit"], "f" * 40)
        retirement.assert_called_once()

    def test_framework_recovery_4_history_requires_exact_position(self) -> None:
        verify = _load_verify()
        source = _function_source(
            verify, "_verify_framework_recovery_4_history"
        )
        self.assertIn("parent_index != 23", source)
        self.assertIn("chain[parent_index - 1]", source)
        self.assertIn("FRAMEWORK_RECOVERY_3_PARENT", source)

    def test_framework_recovery_4_forward_replay_has_pre_activation_guard(
        self,
    ) -> None:
        verify = _load_verify()
        source = _function_source(
            verify, "_verify_forward_protocol_history"
        )
        self.assertIn("recovery_4_activation_commit", source)
        self.assertIn("_framework_recovery_4_verify_successor_guard", source)
        self.assertIn("FRAMEWORK_RECOVERY_4_QUALIFICATION_STATUSES", source)

    def test_framework_recovery_4_successor_requires_activation(self) -> None:
        verify = _load_verify()
        chain = ["a" * 40, "b" * 40]
        with self.assertRaisesRegex(
            verify.CurrentAuditError,
            "FRAMEWORK_RECOVERY_4_SUCCESSOR_BEFORE_ACTIVATION",
        ):
            verify._framework_recovery_4_verify_successor_guard(
                chain,
                1,
                repair_commit=chain[0],
                activation_commit=None,
                recovery_transition=None,
            )
        verify._framework_recovery_4_verify_successor_guard(
            chain,
            1,
            repair_commit=chain[0],
            activation_commit=None,
            recovery_transition={"stage": "QUALIFICATION"},
        )
        activated = [*chain, "c" * 40]
        verify._framework_recovery_4_verify_successor_guard(
            activated,
            2,
            repair_commit=activated[0],
            activation_commit=activated[1],
            recovery_transition=None,
        )

    def test_framework_recovery_4_wrapper_accepts_epochs_2_through_5(
        self,
    ) -> None:
        verify = _load_verify()
        source = _function_source(
            verify, "_verify_post_activation_gate_retention"
        )
        self.assertIn("{2, 3, 4, 5}", source)
        self.assertIn(
            "5: _framework_recovery_4_expected_gate_payload()", source
        )
        with self.assertRaisesRegex(
            verify.CurrentAuditError, "EPOCH_INVALID"
        ):
            verify._verify_post_activation_gate_retention(
                Path("."), "a" * 40, framework_epoch=6
            )

    def test_framework_recovery_4_rejects_cross_phase_run_reuse(self) -> None:
        verify = _load_verify()
        entries = [
            ("repair_ci", "a" * 40, {}),
            ("repair_formal", "b" * 40, {}),
            ("qualification_ci", "c" * 40, {}),
            ("qualification_formal", "d" * 40, {}),
        ]
        with mock.patch.object(
            verify,
            "_framework_recovery_4_run_attempt_identity",
            side_effect=((10, 1), (11, 1), (12, 1), (13, 1)),
        ):
            verify._framework_recovery_4_verify_run_attempt_uniqueness(
                Path("."), entries
            )
        for identities in (
            ((30_093_828_629, 1), (11, 1), (12, 1), (13, 1)),
            ((10, 1), (11, 1), (10, 1), (13, 1)),
        ):
            with (
                self.subTest(identities=identities),
                mock.patch.object(
                    verify,
                    "_framework_recovery_4_run_attempt_identity",
                    side_effect=identities,
                ),
                self.assertRaisesRegex(
                    verify.CurrentAuditError, "RUN_ATTEMPT_REUSED"
                ),
            ):
                verify._framework_recovery_4_verify_run_attempt_uniqueness(
                    Path("."), entries
                )

    def test_framework_recovery_4_hosted_entries_bind_subject(self) -> None:
        verify = _load_verify()
        captured = (
            {"subject_commit": "b" * 40},
            verify._commit_datetime(_repo(), PARENT_COMMIT),
        )
        with mock.patch.object(
            verify,
            "_framework_recovery_3_verify_hosted_entry",
            return_value=captured,
        ) as delegated:
            result = verify._framework_recovery_4_verify_hosted_entry(
                Path("."),
                "c" * 40,
                {},
                paths=("a", "b", "c"),
                subject_commit="b" * 40,
                workflow="ci",
                lane="repair_ci",
            )
        self.assertEqual(result, captured)
        self.assertEqual(
            delegated.call_args.kwargs["subject_commit"], "b" * 40
        )
        self.assertEqual(delegated.call_args.kwargs["workflow"], "ci")

    def test_framework_recovery_4_evidence_signatures_and_chronology_are_bound(
        self,
    ) -> None:
        verify = _load_verify()
        qualification = _function_source(
            verify, "_verify_framework_recovery_4_qualification"
        )
        activation = _function_source(
            verify, "_verify_framework_recovery_4_activation"
        )
        self.assertIn(
            "haldir-framework-recovery-fr-0004-qualification-v1",
            qualification,
        )
        self.assertIn(
            "haldir-framework-recovery-fr-0004-activation-v1",
            activation,
        )
        self.assertIn("_commit_datetime", qualification)
        self.assertIn("_commit_datetime", activation)

    def test_framework_recovery_4_materialization_is_inherited(self) -> None:
        verify = _load_verify()
        plan = _repair_plan(verify)
        parent, _payload = verify._read_commit_json(
            _repo(),
            PARENT_COMMIT,
            verify.FRAMEWORK_RECOVERY_3_PLAN_PATH,
            "fr_0004.test.parent_plan",
        )
        self.assertEqual(
            plan["registered_snapshot_materialization"],
            parent["registered_snapshot_materialization"],
        )

    def test_framework_recovery_4_resource_bounds_are_inherited(self) -> None:
        verify = _load_verify()
        materialization = _repair_plan(verify)[
            "registered_snapshot_materialization"
        ]
        bounds = materialization["bounds"]
        self.assertEqual(bounds["minimum_daemon_cpus"], 2)
        self.assertEqual(
            bounds["minimum_daemon_memory_bytes"], 1280 * 1024 * 1024
        )
        self.assertEqual(bounds["maximum_directory_depth"], 64)
        self.assertEqual(bounds["maximum_file_component_depth"], 65)
        self.assertEqual(
            materialization["execution_policy"]["failure_policy"],
            "FAIL_CLOSED",
        )

    def test_framework_recovery_4_local_markers_reject_missing_suite(
        self,
    ) -> None:
        verify = _load_verify()
        counts = {
            "legacy": {"count": 163},
            "fr_0002": {"count": 78},
            "fr_0003": {"count": 94},
            "resource": {"count": 26},
            "fr_0004": {"count": 30},
        }

        def suite(count: int) -> bytes:
            return (
                f"Ran {count} tests in 1.000s\n".encode("ascii")
                + b"OK\n"
            )

        direct = b"".join(suite(count) for count in (163, 78, 94, 26, 30))
        direct += b"verify-current-audit: OK\n"
        p0 = b"".join(suite(count) for count in (163, 78, 94, 26, 26, 30))
        p0 += b"OK\n" * 5
        p0 += (
            b"verify-current-audit: OK\n"
            b"P0-R exit gate: 30 passed, 0 failed\n"
        )
        payload = (
            b"=== CURRENT_AUDIT_GATE ===\n"
            b"$ tools/release/current-audit-gate.sh\n"
            + direct
            + b"=== P0R_EXIT_GATE ===\n$ tools/p0r-exit-gate.sh\n"
            + p0
            + b"=== RESOURCE_PROFILE ===\n"
            b"$ python3 -I tools/release/current-audit-resource-profile.py\n"
            b"{}\n"
        )
        verify._framework_recovery_4_verify_local_markers(
            payload, test_contract=counts
        )
        missing = payload.replace(
            b"Ran 30 tests in 1.000s\nOK\n", b"", 1
        )
        with self.assertRaisesRegex(
            verify.CurrentAuditError, "LOCAL_LOG"
        ):
            verify._framework_recovery_4_verify_local_markers(
                missing, test_contract=counts
            )


if __name__ == "__main__":
    unittest.main()
