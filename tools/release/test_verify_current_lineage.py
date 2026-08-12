#!/usr/bin/env -S python3 -I -B
"""Focused pure tests for the compact signed-lineage verifier."""

from __future__ import annotations

import importlib.util
import sys
import types
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
VERIFIER_PATH = ROOT / "tools" / "release" / "verify-current-lineage.py"
RESULT_PATH = ROOT / "tools" / "release" / "current_audit_result.py"


def _load_verifier() -> types.ModuleType:
    name = "_haldir_test_current_lineage"
    specification = importlib.util.spec_from_file_location(name, VERIFIER_PATH)
    if specification is None or specification.loader is None:
        raise RuntimeError("cannot load current-lineage verifier")
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


VERIFIER = _load_verifier()


def _load_result_emitter() -> types.ModuleType:
    name = "_haldir_test_current_audit_result"
    specification = importlib.util.spec_from_file_location(name, RESULT_PATH)
    if specification is None or specification.loader is None:
        raise RuntimeError("cannot load current audit-result emitter")
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


RESULT = _load_result_emitter()


def _hosted_run(workflow: str, recovery: str, run_id: int) -> dict[str, object]:
    return {
        "conclusion": "success",
        "event": "push",
        "head_sha": recovery,
        "run_attempt": 1,
        "run_id": run_id,
        "url": f"https://github.com/sepahead/haldir/actions/runs/{run_id}",
        "workflow": workflow,
    }


def _activation_record(recovery: str, tree: str) -> dict[str, object]:
    return {
        "authority": {
            "deployment": False,
            "publication": False,
            "release": False,
            "tag": False,
        },
        "hosted_qualification": {
            "ci": _hosted_run("ci", recovery, 101),
            "formal": _hosted_run("formal", recovery, 102),
        },
        "limitations": [
            "HOSTED_RESULTS_ARE_OWNER_OBSERVED_NOT_CRYPTOGRAPHICALLY_IMPORTED",
            "HOSTED_SETTINGS_REMAIN_MUTABLE_EXTERNAL_STATE",
            "HOSTED_COMMIT_METADATA_RULE_UNAVAILABLE_ON_USER_REPOSITORY",
            "WEB_REBASE_BUTTON_REMAINS_A_HOSTED_DELIVERY_RISK",
            "NO_INDEPENDENT_REVIEWER_AT_ACTIVATION",
            "NO_RELEASE_OR_DEPLOYMENT_AUTHORITY",
        ],
        "observed_at_utc": "2026-08-10T12:00:00Z",
        "protocol": VERIFIER.PROTOCOL,
        "recovery_commit": recovery,
        "recovery_id": VERIFIER.RECOVERY_ID,
        "recovery_tree": tree,
        "repository_settings": {
            "allow_deletions": False,
            "allow_force_pushes": False,
            "allow_merge_commit": False,
            "allow_rebase_merge": True,
            "allow_squash_merge": False,
            "captured_at_utc": "2026-08-10T12:00:00Z",
            "commit_metadata_identity_rule_available": False,
            "enforce_admins": True,
            "observation_is_mutable_external_state": True,
            "repository_database_id": VERIFIER.REPOSITORY_DATABASE_ID,
            "repository_owner_database_id": VERIFIER.REPOSITORY_OWNER_DATABASE_ID,
            "repository_owner_type": "User",
            "required_conversation_resolution": False,
            "required_linear_history": True,
            "required_pull_request_reviews": False,
            "required_signatures": True,
            "required_status_checks": [
                {"app_id": VERIFIER.GITHUB_ACTIONS_APP_ID, "context": context}
                for context in VERIFIER.REQUIRED_HOSTED_CHECKS
            ],
            "strict_required_status_checks": True,
            "writer_allowlist_ruleset_bypass_actor_id": (
                VERIFIER.REPOSITORY_OWNER_DATABASE_ID
            ),
            "writer_allowlist_ruleset_bypass_actor_type": "User",
            "writer_allowlist_ruleset_bypass_mode": "always",
            "writer_allowlist_ruleset_current_user_can_bypass": "always",
            "writer_allowlist_ruleset_excluded_refs": [],
            "writer_allowlist_ruleset_enforcement": "active",
            "writer_allowlist_ruleset_id": 123,
            "writer_allowlist_ruleset_included_refs": ["refs/heads/main"],
            "writer_allowlist_ruleset_name": "haldir-main-writer-allowlist",
            "writer_allowlist_ruleset_owner_bypass": True,
            "writer_allowlist_ruleset_rules": ["update"],
            "writer_allowlist_ruleset_source": VERIFIER.REPOSITORY,
            "writer_allowlist_ruleset_source_type": "Repository",
            "writer_allowlist_ruleset_target": "branch",
        },
        "schema_version": "1.0.0",
        "stage": "ACTIVATION",
        "state_after": "ACTIVE_NO_RELEASE_AUTHORITY",
    }


class CurrentLineageTests(unittest.TestCase):
    def test_recovery_record_is_canonical_and_matches_the_committed_declaration(
        self,
    ) -> None:
        expected = VERIFIER.canonical_json_bytes(VERIFIER.expected_recovery_record())
        observed = (ROOT / VERIFIER.RECOVERY_RECORD_PATH).read_bytes()
        self.assertEqual(observed, expected)

    def test_historical_recovery_roots_are_frozen(self) -> None:
        self.assertTrue(
            VERIFIER._historical_path_is_frozen(
                "tools/release/verify-framework-recovery-fr-0017.py"
            )
        )
        self.assertTrue(
            VERIFIER._historical_path_is_frozen(
                "release/0.9.0/current-head/closures/framework-recovery/FR-0017-plan.json"
            )
        )
        self.assertFalse(
            VERIFIER._historical_path_is_frozen(VERIFIER.RECOVERY_RECORD_PATH)
        )

    def test_post_activation_governance_paths_are_protected(self) -> None:
        for path in (
            ".github/workflows/ci.yml",
            ".github/workflows/new-privileged-workflow.yml",
            "CONTRIBUTING.md",
            VERIFIER.GATE_PATH,
            VERIFIER.VERIFIER_PATH,
            VERIFIER.ACTIVATION_RECORD_PATH,
            "justfile",
            "release/0.9.0/current-head/README.md",
            "tools/pinned_cargo_deny.py",
            "tools/pins.toml",
            "tools/run_formal.py",
            "tools/test_run_formal.py",
            "tools/verify-pins.py",
        ):
            with self.subTest(path=path):
                self.assertTrue(VERIFIER._successor_path_is_protected(path))
        self.assertFalse(
            VERIFIER._successor_path_is_protected("crates/example/src/lib.rs")
        )

    def test_recovery_cannot_collapse_activation_into_the_bootstrap_commit(
        self,
    ) -> None:
        required = {
            VERIFIER.RECOVERY_RECORD_PATH: "A",
            VERIFIER.VERIFIER_PATH: "A",
            VERIFIER.VERIFIER_TEST_PATH: "A",
        }
        VERIFIER._validate_recovery_paths(required)

        with self.assertRaisesRegex(VERIFIER.LineageError, "LINEAGE_RECOVERY_SCOPE"):
            VERIFIER._validate_recovery_paths(
                {**required, VERIFIER.ACTIVATION_RECORD_PATH: "A"}
            )

    def test_result_stage_comes_from_lineage_position_and_record_agreement(
        self,
    ) -> None:
        recovery = "1" * 40
        activation = "2" * 40
        cases = (
            ([recovery], False, "RECOVERED_PENDING_HOSTED_QUALIFICATION"),
            ([recovery, activation], True, "ACTIVE_NO_RELEASE_AUTHORITY"),
        )
        for chain, record_exists, expected in cases:
            with (
                self.subTest(chain=chain),
                mock.patch.object(
                    RESULT, "_git", return_value=("\n".join(chain) + "\n").encode()
                ),
                mock.patch.object(RESULT, "_path_exists", return_value=record_exists),
            ):
                self.assertEqual(RESULT._lineage_state(ROOT, chain[-1]), expected)

        for chain, record_exists in (
            ([recovery], True),
            ([recovery, activation], False),
        ):
            with (
                self.subTest(mismatch=(chain, record_exists)),
                mock.patch.object(
                    RESULT, "_git", return_value=("\n".join(chain) + "\n").encode()
                ),
                mock.patch.object(RESULT, "_path_exists", return_value=record_exists),
                self.assertRaisesRegex(RESULT.ResultError, "CURRENT_RESULT_STAGE"),
            ):
                RESULT._lineage_state(ROOT, chain[-1])

    def test_result_requires_exact_numeric_repository_identity(self) -> None:
        environment = {
            "GITHUB_REPOSITORY_ID": str(RESULT.REPOSITORY_DATABASE_ID),
            "GITHUB_REPOSITORY_OWNER_ID": str(RESULT.REPOSITORY_OWNER_DATABASE_ID),
        }
        self.assertEqual(
            RESULT._repository_identity(environment),
            {
                "database_id": RESULT.REPOSITORY_DATABASE_ID,
                "name": RESULT.REPOSITORY,
                "owner_database_id": RESULT.REPOSITORY_OWNER_DATABASE_ID,
            },
        )
        for field in ("GITHUB_REPOSITORY_ID", "GITHUB_REPOSITORY_OWNER_ID"):
            with (
                self.subTest(field=field),
                self.assertRaisesRegex(
                    RESULT.ResultError,
                    "CURRENT_RESULT_REPOSITORY_IDENTITY",
                ),
            ):
                mismatched = dict(environment)
                mismatched[field] = "1"
                RESULT._repository_identity(mismatched)

    def test_authoritative_process_runners_enforce_the_output_bound(self) -> None:
        command = (
            sys.executable,
            "-I",
            "-B",
            "-c",
            "import os; os.write(1, b'x' * 257)",
        )
        environment = {"LC_ALL": "C", "PATH": "/usr/bin:/bin"}
        for module in (VERIFIER, RESULT):
            with (
                self.subTest(module=module.__name__),
                self.assertRaisesRegex(module._BoundedProcessError, "output exceeded"),
            ):
                module._run_bounded(
                    command,
                    cwd=ROOT,
                    environment=environment,
                    stdout_limit=256,
                    stderr_limit=256,
                )

    def test_activation_record_requires_exact_recovery_and_hosted_settings(
        self,
    ) -> None:
        recovery = "1" * 40
        tree = "2" * 40
        VERIFIER._validate_activation_record(
            _activation_record(recovery, tree),
            recovery_commit=recovery,
            recovery_tree=tree,
        )

    def test_activation_record_rejects_false_metadata_rule_availability(
        self,
    ) -> None:
        recovery = "1" * 40
        tree = "2" * 40
        record = _activation_record(recovery, tree)
        settings = record["repository_settings"]
        assert isinstance(settings, dict)
        settings["commit_metadata_identity_rule_available"] = True
        with self.assertRaisesRegex(VERIFIER.LineageError, "LINEAGE_SETTINGS_VALUE"):
            VERIFIER._validate_activation_record(
                record,
                recovery_commit=recovery,
                recovery_tree=tree,
            )


if __name__ == "__main__":
    unittest.main()
