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

    def test_activation_record_is_bound_to_its_own_recovery(self) -> None:
        recovery = "1" * 40
        tree = "2" * 40
        record = _activation_record(recovery, tree)
        with self.assertRaisesRegex(VERIFIER.LineageError, "LINEAGE_ACTIVATION_VALUE"):
            VERIFIER._validate_activation_record(
                record,
                recovery_commit=recovery,
                recovery_tree=tree,
                recovery_id=VERIFIER.EPOCH20_RECOVERY_ID,
            )
        record["recovery_id"] = VERIFIER.EPOCH20_RECOVERY_ID
        VERIFIER._validate_activation_record(
            record,
            recovery_commit=recovery,
            recovery_tree=tree,
            recovery_id=VERIFIER.EPOCH20_RECOVERY_ID,
        )


class Epoch20LineageTests(unittest.TestCase):
    TRANSITION = VERIFIER.EPOCH20_TRANSITION_COMMIT
    RECOVERY = "3" * 40
    ACTIVATION = "4" * 40
    SIGNERS = b"signers"

    def _bootstrap(self, **extra: str) -> dict[str, str]:
        return {
            VERIFIER.EPOCH20_RECOVERY_RECORD_PATH: "A",
            VERIFIER.VERIFIER_PATH: "M",
            VERIFIER.VERIFIER_TEST_PATH: "M",
            **extra,
        }

    def test_recovery_record_is_canonical_and_matches_the_committed_declaration(
        self,
    ) -> None:
        expected = VERIFIER.canonical_json_bytes(
            VERIFIER.expected_epoch20_recovery_record()
        )
        observed = (ROOT / VERIFIER.EPOCH20_RECOVERY_RECORD_PATH).read_bytes()
        self.assertEqual(observed, expected)

    def test_transition_declares_exactly_the_protected_pin_changes(self) -> None:
        for path in VERIFIER.EPOCH20_TRANSITION_PROTECTED_PATHS:
            with self.subTest(path=path):
                self.assertTrue(VERIFIER._successor_path_is_protected(path))
        transition = VERIFIER.expected_epoch20_recovery_record()["transition"]
        self.assertEqual(
            {item["path"]: item["status"] for item in transition["protected_paths"]},
            VERIFIER.EPOCH20_TRANSITION_PROTECTED_PATHS,
        )

    def test_epoch20_records_are_protected_after_activation(self) -> None:
        for path in (
            VERIFIER.EPOCH20_RECOVERY_RECORD_PATH,
            VERIFIER.EPOCH20_ACTIVATION_RECORD_PATH,
        ):
            with self.subTest(path=path):
                self.assertTrue(VERIFIER._successor_path_is_protected(path))

    def test_recovery_may_only_rewrite_listed_governance_files(self) -> None:
        VERIFIER._validate_epoch20_recovery_paths(self._bootstrap())
        VERIFIER._validate_epoch20_recovery_paths(
            self._bootstrap(
                **{
                    ".github/workflows/ci.yml": "M",
                    ".github/workflows/formal.yml": "M",
                    "CONTRIBUTING.md": "M",
                    VERIFIER.GATE_PATH: "M",
                    VERIFIER.CURRENT_RESULT_PATH: "M",
                    "release/0.9.0/current-head/README.md": "M",
                    "docs/CLAIM-LEDGER.md": "M",
                    "evidence/13-live-gate-dev-smoke-ncp-1.0/manifest.json": "A",
                }
            )
        )
        rejected = (
            {VERIFIER.EPOCH20_RECOVERY_RECORD_PATH: "M"},
            {VERIFIER.VERIFIER_PATH: "A"},
            {VERIFIER.EPOCH20_ACTIVATION_RECORD_PATH: "A"},
            {VERIFIER.RECOVERY_RECORD_PATH: "M"},
            {VERIFIER.ACTIVATION_RECORD_PATH: "M"},
            {VERIFIER.ALLOWED_SIGNERS_PATH: "M"},
            {"tools/pins.toml": "M"},
            {"tools/verify-pins.py": "M"},
            {"justfile": "M"},
            {".github/workflows/new-privileged-workflow.yml": "A"},
            {"CONTRIBUTING.md": "D"},
            {"tools/release/verify-framework-recovery-fr-0017.py": "M"},
        )
        for change in rejected:
            with (
                self.subTest(change=change),
                self.assertRaisesRegex(VERIFIER.LineageError, "LINEAGE_RECOVERY_SCOPE"),
            ):
                VERIFIER._validate_epoch20_recovery_paths(self._bootstrap(**change))
        with self.assertRaisesRegex(VERIFIER.LineageError, "LINEAGE_RECOVERY_SCOPE"):
            VERIFIER._validate_epoch20_recovery_paths({})

    def _patched(self, *, changes: dict[tuple[str, str], dict[str, str]], trees=None):
        trees = trees or {}

        def signed(repo, commit, *, parent, subject, allowed_signers):
            return {"commit": commit, "parents": parent, "subject": subject or "",
                    "tree": trees.get(commit, "5" * 40)}

        def changed(repo, parent, commit):
            return changes[(parent, commit)]

        records = {
            (self.RECOVERY, VERIFIER.EPOCH20_RECOVERY_RECORD_PATH): (
                VERIFIER.expected_epoch20_recovery_record()
            ),
        }
        return (
            mock.patch.object(VERIFIER, "_verify_signed_commit", side_effect=signed),
            mock.patch.object(VERIFIER, "_changed_paths", side_effect=changed),
            mock.patch.object(
                VERIFIER,
                "_read_canonical_json",
                side_effect=lambda repo, commit, path: records[(commit, path)],
            ),
        )

    def _changes(self) -> dict[tuple[str, str], dict[str, str]]:
        return {
            (VERIFIER.EPOCH20_PRIOR_VALID_COMMIT, self.TRANSITION): {
                **VERIFIER.EPOCH20_TRANSITION_PROTECTED_PATHS,
                "Cargo.lock": "M",
                "crates/haldir-ncp10/src/lease.rs": "A",
            },
            (self.TRANSITION, self.RECOVERY): self._bootstrap(),
        }

    def _verify(self, tail, *, changes, trees=None, previous=None):
        signed, changed, records = self._patched(changes=changes, trees=trees)
        with signed, changed, records:
            return VERIFIER._verify_epoch20(
                ROOT,
                tail,
                previous=previous or VERIFIER.EPOCH20_PRIOR_VALID_COMMIT,
                allowed_signers=self.SIGNERS,
            )

    def test_recovery_child_starts_epoch20_pending_hosted_qualification(self) -> None:
        trees = {self.TRANSITION: VERIFIER.EPOCH20_TRANSITION_TREE}
        self.assertEqual(
            self._verify(
                [self.TRANSITION, self.RECOVERY], changes=self._changes(), trees=trees
            ),
            (self.RECOVERY, None, "RECOVERED_PENDING_HOSTED_QUALIFICATION"),
        )

    def test_transition_without_its_recovery_is_never_a_valid_head(self) -> None:
        trees = {self.TRANSITION: VERIFIER.EPOCH20_TRANSITION_TREE}
        with self.assertRaisesRegex(
            VERIFIER.LineageError, "LINEAGE_TRANSITION_UNRECOVERED"
        ):
            self._verify([self.TRANSITION], changes=self._changes(), trees=trees)

    def test_transition_is_bound_to_its_parent_tree_and_protected_scope(self) -> None:
        trees = {self.TRANSITION: VERIFIER.EPOCH20_TRANSITION_TREE}
        with self.assertRaisesRegex(VERIFIER.LineageError, "LINEAGE_TRANSITION_PARENT"):
            self._verify(
                [self.TRANSITION, self.RECOVERY],
                changes=self._changes(),
                trees=trees,
                previous="6" * 40,
            )
        with self.assertRaisesRegex(VERIFIER.LineageError, "LINEAGE_TRANSITION_TREE"):
            self._verify([self.TRANSITION, self.RECOVERY], changes=self._changes())
        widened = self._changes()
        widened[(VERIFIER.EPOCH20_PRIOR_VALID_COMMIT, self.TRANSITION)][
            ".github/workflows/ci.yml"
        ] = "M"
        with self.assertRaisesRegex(VERIFIER.LineageError, "LINEAGE_TRANSITION_SCOPE"):
            self._verify([self.TRANSITION, self.RECOVERY], changes=widened, trees=trees)

    def test_activation_must_add_only_its_record(self) -> None:
        trees = {self.TRANSITION: VERIFIER.EPOCH20_TRANSITION_TREE}
        changes = self._changes()
        changes[(self.RECOVERY, self.ACTIVATION)] = {
            VERIFIER.EPOCH20_ACTIVATION_RECORD_PATH: "A",
            "README.md": "M",
        }
        with self.assertRaisesRegex(VERIFIER.LineageError, "LINEAGE_ACTIVATION_SCOPE"):
            self._verify(
                [self.TRANSITION, self.RECOVERY, self.ACTIVATION],
                changes=changes,
                trees=trees,
            )

    def test_result_stage_follows_the_epoch20_position(self) -> None:
        before = ["1" * 40, "2" * 40, VERIFIER.EPOCH20_PRIOR_VALID_COMMIT]
        recovery, activation = self.RECOVERY, self.ACTIVATION
        present = {
            (recovery, RESULT.EPOCH20_RECOVERY_RECORD): True,
            (recovery, RESULT.EPOCH20_ACTIVATION_RECORD): False,
            (activation, RESULT.EPOCH20_RECOVERY_RECORD): True,
            (activation, RESULT.EPOCH20_ACTIVATION_RECORD): True,
        }
        for head, expected, records in (
            (
                recovery,
                "RECOVERED_PENDING_HOSTED_QUALIFICATION",
                (RESULT.ACTIVATION_RECORD, RESULT.EPOCH20_RECOVERY_RECORD),
            ),
            (
                activation,
                "ACTIVE_NO_RELEASE_AUTHORITY",
                (
                    RESULT.ACTIVATION_RECORD,
                    RESULT.EPOCH20_RECOVERY_RECORD,
                    RESULT.EPOCH20_ACTIVATION_RECORD,
                ),
            ),
        ):
            chain = before + [self.TRANSITION, recovery] + (
                [activation] if head == activation else []
            )
            with (
                self.subTest(head=head),
                mock.patch.object(
                    RESULT, "_git", return_value=("\n".join(chain) + "\n").encode()
                ),
                mock.patch.object(
                    RESULT,
                    "_path_exists",
                    side_effect=lambda repo, commit, path: present[(commit, path)],
                ),
            ):
                self.assertEqual(RESULT._lineage_stage(ROOT, head), (expected, records))

        chain = before + [self.TRANSITION]
        with (
            mock.patch.object(
                RESULT, "_git", return_value=("\n".join(chain) + "\n").encode()
            ),
            mock.patch.object(RESULT, "_path_exists", return_value=True),
            self.assertRaisesRegex(RESULT.ResultError, "CURRENT_RESULT_STAGE"),
        ):
            RESULT._lineage_state(ROOT, self.TRANSITION)


if __name__ == "__main__":
    unittest.main()
