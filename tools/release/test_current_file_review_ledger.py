#!/usr/bin/env python3
"""Adversarial tests for current-file-review-ledger.py."""

from __future__ import annotations

import hashlib
import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).with_name("current-file-review-ledger.py")
SPEC = importlib.util.spec_from_file_location("current_file_review_ledger", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
ledger = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = ledger
SPEC.loader.exec_module(ledger)

GIT_ENV = {
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_SYSTEM": os.devnull,
    "GIT_TERMINAL_PROMPT": "0",
    "HOME": "/nonexistent",
    "LANG": "C",
    "LC_ALL": "C",
    "PATH": "/usr/bin:/bin",
}


def run_git(repo: Path, *arguments: str) -> str:
    return subprocess.run(
        ["/usr/bin/git", "-C", str(repo), *arguments],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=GIT_ENV,
    ).stdout.strip()


def clone_repository(source: Path, destination: Path) -> None:
    subprocess.run(
        ["/usr/bin/git", "clone", "--quiet", str(source), str(destination)],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=GIT_ENV,
    )


class CurrentFileReviewLedgerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        run_git(self.repo, "init", "--initial-branch=main")
        run_git(self.repo, "config", "user.name", "Ledger Test")
        run_git(self.repo, "config", "user.email", "ledger@example.invalid")

        (self.root / "secret.txt").write_text(
            "must never be followed\n", encoding="utf-8"
        )
        (self.repo / ".gitignore").write_text("build/\n", encoding="utf-8")
        (self.repo / "tracked.txt").write_text("source\n", encoding="utf-8")
        (self.repo / "binary.dat").write_bytes(b"\x00source-binary\xff")
        executable = self.repo / "run.sh"
        executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        executable.chmod(0o755)
        (self.repo / "nested").mkdir()
        (self.repo / "nested" / "item.txt").write_text("inside\n", encoding="utf-8")
        os.symlink("../secret.txt", self.repo / "external-link")
        run_git(self.repo, "add", ".")
        run_git(self.repo, "commit", "-m", "fixture")
        self.source = run_git(self.repo, "rev-parse", "HEAD")

        (self.repo / "tracked.txt").write_text("current\n", encoding="utf-8")
        (self.repo / "binary.dat").unlink()
        (self.repo / "untracked.txt").write_text("untracked\n", encoding="utf-8")
        (self.repo / "build").mkdir()
        (self.repo / "build" / "generated.bin").write_bytes(b"\x00generated")
        self.output = self.repo / "audit" / "FILE_REVIEW_LEDGER.csv"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def create_clean_repository(
        self, name: str, *, prior_ledger: bool = False
    ) -> tuple[Path, str, Path]:
        repo = self.root / name
        repo.mkdir()
        run_git(repo, "init", "--initial-branch=main")
        run_git(repo, "config", "user.name", "Ledger Test")
        run_git(repo, "config", "user.email", "ledger@example.invalid")
        (repo / "tracked.txt").write_text("tracked\n", encoding="utf-8")
        output = repo / "audit" / "FILE_REVIEW_LEDGER.csv"
        if prior_ledger:
            output.parent.mkdir()
            output.write_bytes(b"prior retained ledger bytes\n")
        run_git(repo, "add", ".")
        run_git(repo, "commit", "-m", "source")
        return repo, run_git(repo, "rev-parse", "HEAD"), output

    def generate(self, *, replace: bool = False) -> bytes:
        result = ledger.generate_ledger(
            self.repo,
            self.source,
            self.output,
            ignored_policy="inventory",
            replace=replace,
        )
        data = self.output.read_bytes()
        self.assertEqual(result["ledger_sha256"], hashlib.sha256(data).hexdigest())
        return data

    def verify(self, **arguments: object) -> dict[str, str | int]:
        return ledger.verify_ledger(
            self.repo,
            self.source,
            self.output,
            ignored_policy="inventory",
            **arguments,
        )

    def rows(self, data: bytes | None = None) -> dict[str, dict[str, str]]:
        parsed = ledger.parse_ledger(
            data if data is not None else self.output.read_bytes()
        )
        return {row["path"]: row for row in parsed}

    def write_rows(self, rows: list[dict[str, str]]) -> None:
        with ledger.SecureRepository(self.repo) as secure:
            secure.atomic_write(
                "audit/FILE_REVIEW_LEDGER.csv",
                ledger.render_ledger(rows),
                replace=True,
            )

    @staticmethod
    def complete_reviews(rows: list[dict[str, str]]) -> None:
        for row in rows:
            if row["generated"] == "UNKNOWN":
                row["generated"] = "NO"
                row["generator"] = ""
            for field in (
                "public_surface",
                "security_critical",
                "science_critical",
                "authority_critical",
            ):
                row[field] = "NO"
            row["reviewer"] = "Independent Reviewer"
            row["review_status"] = "REVIEWED"
            row["provenance_review_status"] = "CONFIRMED"
            row["provenance_evidence"] = "review/provenance-record"
            row["license_review_status"] = "APPROVED"
            row["license_expression"] = "Apache-2.0 OR MIT"
            row["license_evidence"] = "review/license-record"
            row["disposition"] = "ACCEPTED"
            row["completed_at"] = "2026-07-14T12:00:00Z"

    def test_complete_inventory_is_deterministic_and_verifies(self) -> None:
        first = self.generate()
        with self.assertRaisesRegex(ledger.LedgerError, "replacement authority"):
            self.generate()
        second = self.generate(replace=True)
        self.assertEqual(first, second)
        result = self.verify()
        self.assertEqual(result["ledger_sha256"], hashlib.sha256(second).hexdigest())

        rows = self.rows(second)
        self.assertEqual(len(ledger.FIELDS), 72)
        self.assertEqual(
            set(rows),
            {
                ".gitignore",
                "audit/FILE_REVIEW_LEDGER.csv",
                "binary.dat",
                "build/generated.bin",
                "external-link",
                "nested/item.txt",
                "run.sh",
                "tracked.txt",
                "untracked.txt",
            },
        )
        self.assertEqual(rows["tracked.txt"]["source_index_state"], "IDENTICAL")
        self.assertEqual(
            rows["tracked.txt"]["worktree_state"],
            "CONTENT_OR_TYPE_CHANGED_AGAINST_INDEX",
        )
        self.assertEqual(rows["binary.dat"]["worktree_state"], "DELETED_FROM_WORKTREE")
        self.assertEqual(rows["binary.dat"]["source_content_kind"], "BINARY")
        self.assertEqual(rows["run.sh"]["source_git_mode"], "100755")
        self.assertEqual(rows["untracked.txt"]["current_scope"], "UNTRACKED")
        ignored = rows["build/generated.bin"]
        self.assertEqual(ignored["current_scope"], "IGNORED")
        self.assertEqual(ignored["ignore_pattern"], "build/")
        self.assertTrue(ignored["ignore_rule_source"].endswith(".gitignore:1"))
        self.assertIn("IGNORED_WORKTREE_ENTRY", ignored["generated_candidate_reason"])
        self.assertEqual(rows["external-link"]["current_fs_type"], "SYMLINK")
        self.assertEqual(
            rows["external-link"]["current_sha256"],
            hashlib.sha256(b"../secret.txt").hexdigest(),
        )
        self.assertNotEqual(
            rows["external-link"]["current_sha256"],
            hashlib.sha256((self.root / "secret.txt").read_bytes()).hexdigest(),
        )
        self_row = rows["audit/FILE_REVIEW_LEDGER.csv"]
        self.assertEqual(self_row["index_tracked"], "false")
        self.assertEqual(self_row["source_index_state"], "NEITHER")
        self.assertEqual(
            self_row["worktree_state"], "SELF_REFERENTIAL_CONTENT_EXCLUDED"
        )
        self.assertEqual(self_row["format"], "SELF_REFERENTIAL_CSV")
        digests = {
            row[field]
            for row in rows.values()
            for field in (
                "inventory_digest",
                "source_inventory_digest",
                "index_inventory_digest",
                "untracked_inventory_digest",
                "ignored_inventory_digest",
                "filesystem_inventory_digest",
            )
        }
        self.assertTrue(all(len(value) == 64 for value in digests))
        self.assertTrue(
            all(row["review_status"] == "UNREVIEWED" for row in rows.values())
        )

    def test_atomic_creation_does_not_clobber_a_racing_writer(self) -> None:
        competing_bytes = b"independently-created-ledger\n"

        def competing_link(*_arguments: object, **_keywords: object) -> None:
            self.output.write_bytes(competing_bytes)
            raise FileExistsError("simulated atomic create race")

        with mock.patch.object(ledger.os, "link", side_effect=competing_link):
            with self.assertRaisesRegex(ledger.LedgerError, "appeared during atomic"):
                ledger.generate_ledger(
                    self.repo,
                    self.source,
                    self.output,
                    ignored_policy="inventory",
                )
        self.assertEqual(self.output.read_bytes(), competing_bytes)

    def test_postpublication_reconciliation_rolls_back_a_stale_ledger(self) -> None:
        original = ledger.SecureRepository.atomic_write
        late_path = self.repo / "late-release-input.txt"

        def mutate_then_publish(
            secure: ledger.SecureRepository,
            path: str,
            data: bytes,
            *,
            replace: bool = False,
            deadline: ledger.Deadline | None = None,
        ) -> None:
            late_path.write_text("appeared during publication\n", encoding="utf-8")
            original(
                secure,
                path,
                data,
                replace=replace,
                deadline=deadline,
            )

        with mock.patch.object(
            ledger.SecureRepository,
            "atomic_write",
            new=mutate_then_publish,
        ):
            with self.assertRaisesRegex(
                ledger.LedgerError, "changed across ledger publication"
            ):
                ledger.generate_ledger(
                    self.repo,
                    self.source,
                    self.output,
                    ignored_policy="inventory",
                )
        self.assertTrue(late_path.is_file())
        self.assertFalse(self.output.exists())

    def test_postpublication_failure_restores_a_replaced_ledger(self) -> None:
        self.generate()
        retained_rows = ledger.parse_ledger(self.output.read_bytes())
        retained_rows[0]["reviewer"] = "Retained Reviewer Assignment"
        self.write_rows(retained_rows)
        retained_bytes = self.output.read_bytes()
        original = ledger.SecureRepository.atomic_write
        late_path = self.repo / "late-replacement-input.txt"
        publication_calls = 0

        def mutate_first_publication(
            secure: ledger.SecureRepository,
            path: str,
            data: bytes,
            *,
            replace: bool = False,
            deadline: ledger.Deadline | None = None,
        ) -> None:
            nonlocal publication_calls
            publication_calls += 1
            if publication_calls == 1:
                late_path.write_text("appeared during replacement\n", encoding="utf-8")
            original(
                secure,
                path,
                data,
                replace=replace,
                deadline=deadline,
            )

        with mock.patch.object(
            ledger.SecureRepository,
            "atomic_write",
            new=mutate_first_publication,
        ):
            with self.assertRaisesRegex(
                ledger.LedgerError, "changed across ledger publication"
            ):
                ledger.generate_ledger(
                    self.repo,
                    self.source,
                    self.output,
                    ignored_policy="inventory",
                    replace=True,
                )
        self.assertGreaterEqual(publication_calls, 2)
        self.assertEqual(self.output.read_bytes(), retained_bytes)

    def test_self_row_survives_stage_commit_and_clean_clone(self) -> None:
        repo, source, output = self.create_clean_repository("lifecycle")
        original = ledger.generate_ledger(repo, source, output)["ledger_sha256"]
        self.assertEqual(
            ledger.verify_ledger(repo, source, output)["ledger_sha256"], original
        )
        run_git(repo, "add", "audit/FILE_REVIEW_LEDGER.csv")
        self.assertEqual(
            ledger.verify_ledger(repo, source, output)["ledger_sha256"], original
        )
        run_git(repo, "commit", "-m", "retain ledger")
        self.assertEqual(
            ledger.verify_ledger(repo, source, output)["ledger_sha256"], original
        )

        clone = self.root / "lifecycle-clone"
        clone_repository(repo, clone)
        cloned_output = clone / "audit" / "FILE_REVIEW_LEDGER.csv"
        self.assertEqual(
            ledger.verify_ledger(clone, source, cloned_output)["ledger_sha256"],
            original,
        )

    def test_source_tracked_self_row_survives_replacement_lifecycle(self) -> None:
        repo, source, output = self.create_clean_repository(
            "source-tracked", prior_ledger=True
        )
        result = ledger.generate_ledger(repo, source, output, replace=True)
        expected = result["ledger_sha256"]
        rows = ledger.parse_ledger(output.read_bytes())
        self_row = next(
            row for row in rows if row["path"] == "audit/FILE_REVIEW_LEDGER.csv"
        )
        self.assertEqual(self_row["source_tracked"], "true")
        self.assertTrue(self_row["source_git_blob_id"])
        self.assertEqual(self_row["index_tracked"], "false")
        self.assertEqual(
            self_row["source_index_state"],
            "SOURCE_PRESENT_SELF_INDEX_EXCLUDED",
        )
        run_git(repo, "add", "audit/FILE_REVIEW_LEDGER.csv")
        self.assertEqual(
            ledger.verify_ledger(repo, source, output)["ledger_sha256"], expected
        )
        run_git(repo, "commit", "-m", "replace ledger")
        self.assertEqual(
            ledger.verify_ledger(repo, source, output)["ledger_sha256"], expected
        )

        clone = self.root / "source-tracked-clone"
        clone_repository(repo, clone)
        self.assertEqual(
            ledger.verify_ledger(
                clone, source, clone / "audit" / "FILE_REVIEW_LEDGER.csv"
            )["ledger_sha256"],
            expected,
        )

    def test_current_worktree_change_invalidates_existing_ledger(self) -> None:
        self.generate()
        (self.repo / "tracked.txt").write_text("changed again\n", encoding="utf-8")
        with self.assertRaisesRegex(ledger.LedgerError, "immutable field mismatch"):
            self.verify()

    def test_exact_implementation_snapshot_survives_later_protocol_files(self) -> None:
        repo, source, output = self.create_clean_repository("snapshot-retention")
        generated = ledger.generate_ledger(repo, source, output)
        run_git(repo, "add", "audit/FILE_REVIEW_LEDGER.csv")
        run_git(repo, "commit", "-m", "implementation")
        implementation = run_git(repo, "rev-parse", "HEAD")
        (repo / "qualification.json").write_text("{}\n", encoding="utf-8")
        run_git(repo, "add", "qualification.json")
        run_git(repo, "commit", "-m", "qualification")

        with self.assertRaisesRegex(ledger.LedgerError, "row count"):
            ledger.verify_ledger(repo, source, output)
        snapshot = ledger.verify_ledger(
            repo,
            source,
            output,
            implementation_commit=implementation,
        )
        self.assertEqual(snapshot["implementation_commit"], implementation)
        self.assertEqual(
            snapshot["implementation_ledger_sha256"], generated["ledger_sha256"]
        )
        self.assertEqual(snapshot["verification_view"], "EXACT_IMPLEMENTATION_SNAPSHOT")
        cli = subprocess.run(
            [
                sys.executable,
                "-I",
                str(SCRIPT),
                "verify",
                "--repo",
                str(repo),
                "--source-commit",
                source,
                "--implementation-commit",
                implementation,
                "--ledger",
                str(output),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        self.assertEqual(cli.returncode, 0, cli.stderr)
        self.assertIn('"verification_view":"EXACT_IMPLEMENTATION_SNAPSHOT"', cli.stdout)
        with self.assertRaisesRegex(ledger.LedgerError, "full lowercase"):
            ledger.verify_ledger(
                repo,
                source,
                output,
                implementation_commit=implementation[:12],
            )
        current_commit = run_git(repo, "rev-parse", "HEAD")
        with self.assertRaisesRegex(ledger.LedgerError, "single-parent child"):
            ledger.verify_ledger(
                repo,
                source,
                output,
                implementation_commit=current_commit,
            )

        rows = ledger.parse_ledger(output.read_bytes())
        for row in rows:
            row["reviewer"] = "Assigned Reviewer"
        with ledger.SecureRepository(repo) as secure:
            secure.atomic_write(
                "audit/FILE_REVIEW_LEDGER.csv",
                ledger.render_ledger(rows),
                replace=True,
            )
        with self.assertRaisesRegex(ledger.LedgerError, "captured current-HEAD blob"):
            ledger.verify_ledger(
                repo,
                source,
                output,
                implementation_commit=implementation,
                require_assigned=True,
            )
        run_git(repo, "add", "audit/FILE_REVIEW_LEDGER.csv")
        run_git(repo, "commit", "-m", "retain assignments")
        ledger.verify_ledger(
            repo,
            source,
            output,
            implementation_commit=implementation,
            require_assigned=True,
        )
        rows[0]["current_sha256"] = "0" * 64
        with ledger.SecureRepository(repo) as secure:
            secure.atomic_write(
                "audit/FILE_REVIEW_LEDGER.csv",
                ledger.render_ledger(rows),
                replace=True,
            )
        with self.assertRaisesRegex(ledger.LedgerError, "captured current-HEAD blob"):
            ledger.verify_ledger(
                repo,
                source,
                output,
                implementation_commit=implementation,
            )
        run_git(repo, "add", "audit/FILE_REVIEW_LEDGER.csv")
        run_git(repo, "commit", "-m", "retain identity tamper")
        with self.assertRaisesRegex(ledger.LedgerError, "immutable field mismatch"):
            ledger.verify_ledger(
                repo,
                source,
                output,
                implementation_commit=implementation,
            )

    def test_staged_content_identity_is_distinct_from_source_and_worktree(self) -> None:
        (self.repo / "tracked.txt").write_text("staged\n", encoding="utf-8")
        run_git(self.repo, "add", "tracked.txt")
        (self.repo / "tracked.txt").write_text("worktree\n", encoding="utf-8")
        rows = ledger.build_inventory(
            self.repo,
            self.source,
            ledger_self_path="audit/FILE_REVIEW_LEDGER.csv",
            ignored_policy="inventory",
        )
        row = next(item for item in rows if item["path"] == "tracked.txt")
        self.assertEqual(row["source_index_state"], "MODIFIED_IN_INDEX")
        self.assertEqual(row["index_flags"], "NONE")
        self.assertEqual(row["index_sha256"], hashlib.sha256(b"staged\n").hexdigest())
        self.assertEqual(
            row["current_sha256"], hashlib.sha256(b"worktree\n").hexdigest()
        )
        self.assertNotEqual(row["source_sha256"], row["index_sha256"])
        self.assertEqual(row["worktree_state"], "CONTENT_OR_TYPE_CHANGED_AGAINST_INDEX")

    def test_intent_to_add_and_extended_index_flags_are_rejected(self) -> None:
        (self.repo / "intent.txt").write_text("intent\n", encoding="utf-8")
        run_git(self.repo, "add", "-N", "intent.txt")
        with self.assertRaisesRegex(ledger.LedgerError, "index flags"):
            ledger.build_inventory(
                self.repo,
                self.source,
                ledger_self_path="audit/FILE_REVIEW_LEDGER.csv",
                ignored_policy="inventory",
            )

        run_git(self.repo, "reset", "intent.txt")
        run_git(self.repo, "checkout", "--", "tracked.txt")
        run_git(self.repo, "update-index", "--skip-worktree", "tracked.txt")
        with self.assertRaisesRegex(ledger.LedgerError, "index flag|index state"):
            ledger.build_inventory(
                self.repo,
                self.source,
                ledger_self_path="audit/FILE_REVIEW_LEDGER.csv",
                ignored_policy="inventory",
            )
        run_git(self.repo, "update-index", "--no-skip-worktree", "tracked.txt")
        run_git(self.repo, "update-index", "--assume-unchanged", "tracked.txt")
        with self.assertRaisesRegex(ledger.LedgerError, "index flag|index state"):
            ledger.build_inventory(
                self.repo,
                self.source,
                ledger_self_path="audit/FILE_REVIEW_LEDGER.csv",
                ignored_policy="inventory",
            )

    def test_independent_walk_rejects_git_omission(self) -> None:
        original = ledger._run_git

        def deceptive(repo: Path, arguments: list[str], **kwargs: object) -> bytes:
            if arguments == ["ls-files", "--others", "--exclude-standard", "-z"]:
                return b""
            return original(repo, arguments, **kwargs)

        with mock.patch.object(ledger, "_run_git", side_effect=deceptive):
            with self.assertRaisesRegex(ledger.LedgerError, "omitted by Git"):
                ledger.build_inventory(
                    self.repo,
                    self.source,
                    ledger_self_path="audit/FILE_REVIEW_LEDGER.csv",
                    ignored_policy="inventory",
                )

    def test_ignored_policy_defaults_to_reject_and_records_exact_rule(self) -> None:
        with self.assertRaisesRegex(ledger.LedgerError, "explicit inventory policy"):
            ledger.build_inventory(
                self.repo,
                self.source,
                ledger_self_path="audit/FILE_REVIEW_LEDGER.csv",
            )
        self.generate()
        ignored = self.rows()["build/generated.bin"]
        self.assertEqual(ignored["ignored_policy"], "inventory")
        self.assertEqual(ignored["ignore_pattern"], "build/")
        self.assertTrue(ignored["ignore_rule_source"].endswith(".gitignore:1"))

    def test_ignored_ledger_output_is_rejected_without_leaving_artifact(self) -> None:
        (self.repo / ".gitignore").write_text("build/\naudit/\n", encoding="utf-8")
        with self.assertRaisesRegex(ledger.LedgerError, "output path is ignored"):
            ledger.generate_ledger(
                self.repo,
                self.source,
                self.output,
                ignored_policy="inventory",
            )
        self.assertFalse(self.output.exists())

    def test_generated_candidates_default_unknown_without_frozen_provenance(
        self,
    ) -> None:
        candidate = self.repo / "generated" / "output.bin"
        candidate.parent.mkdir()
        candidate.write_bytes(b"\x00candidate")
        self.generate()
        row = self.rows()["generated/output.bin"]
        self.assertEqual(row["generated_candidate_reason"], "GENERATED_PATH_COMPONENT")
        self.assertEqual(row["generated"], "UNKNOWN")
        self.assertEqual(row["generator"], "")

    def test_format_is_content_aware_and_ansi_logs_preserve_line_count(self) -> None:
        (self.repo / "bad.json").write_bytes(b"\x00not-json")
        (self.repo / "ansi.log").write_bytes(b"first \x1b[31mred\x1b[0m\nsecond\n")
        self.generate()
        rows_by_path = self.rows()
        bad = rows_by_path["bad.json"]
        self.assertEqual(bad["current_content_kind"], "BINARY")
        self.assertEqual(bad["language"], "JSON")
        self.assertEqual(bad["format"], "BINARY_WITH_JSON_SUFFIX")
        ansi = rows_by_path["ansi.log"]
        self.assertEqual(ansi["current_content_kind"], "TEXT_UTF8_WITH_ANSI_ESCAPE")
        self.assertEqual(ansi["current_lines"], "2")
        self.assertEqual(ansi["format"], "ANSI_LOG_TEXT")

        rows = ledger.parse_ledger(self.output.read_bytes())
        self.complete_reviews(rows)
        self.write_rows(rows)
        with self.assertRaisesRegex(ledger.LedgerError, "content/format contradiction"):
            self.verify(require_reviewed=True)

    def test_git_configuration_and_process_environment_are_isolated(self) -> None:
        global_excludes = self.root / "global-excludes"
        global_excludes.write_text("*.cache\n", encoding="utf-8")
        malicious_config = self.root / "malicious.gitconfig"
        malicious_config.write_text(
            f"[core]\n\texcludesFile = {global_excludes}\n", encoding="utf-8"
        )
        (self.repo / "release-input.cache").write_text("retain\n", encoding="utf-8")
        with mock.patch.dict(
            os.environ,
            {
                "GIT_CONFIG_GLOBAL": str(malicious_config),
                "GIT_DIR": str(self.root / "wrong-git-dir"),
                "GIT_INDEX_FILE": str(self.root / "wrong-index"),
                "PATH": str(self.root),
            },
            clear=False,
        ):
            rows = ledger.build_inventory(
                self.repo,
                self.source,
                ledger_self_path="audit/FILE_REVIEW_LEDGER.csv",
                ignored_policy="inventory",
            )
        row = next(item for item in rows if item["path"] == "release-input.cache")
        self.assertEqual(row["current_scope"], "UNTRACKED")

    def test_human_fields_can_be_completed_but_not_fabricated_by_generator(
        self,
    ) -> None:
        self.generate()
        rows = ledger.parse_ledger(self.output.read_bytes())
        with self.assertRaisesRegex(ledger.LedgerError, "reviewer is not assigned"):
            self.verify(require_assigned=True)
        with self.assertRaisesRegex(ledger.LedgerError, "reviewer is not assigned"):
            self.verify(require_reviewed=True)

        self.complete_reviews(rows)
        self.write_rows(rows)
        result = self.verify(require_reviewed=True)
        self.assertEqual(result["rows"], len(rows))

    def test_review_gate_rejects_adverse_or_unresolved_dispositions(self) -> None:
        self.generate()
        baseline = ledger.parse_ledger(self.output.read_bytes())
        self.complete_reviews(baseline)
        cases = (
            ("disposition", "REJECTED", "non-accepting disposition"),
            ("defects", "open defect", "unresolved defects"),
            ("provenance_review_status", "REJECTED", "accepted provenance"),
            ("license_review_status", "REJECTED", "accepted licensing"),
        )
        for field, value, message in cases:
            with self.subTest(field=field):
                rows = [dict(row) for row in baseline]
                rows[0][field] = value
                self.write_rows(rows)
                with self.assertRaisesRegex(ledger.LedgerError, message):
                    self.verify(require_reviewed=True)

    def test_generated_classification_requires_consistent_existing_source(self) -> None:
        self.generate()
        baseline = ledger.parse_ledger(self.output.read_bytes())
        target_index = next(
            index for index, row in enumerate(baseline) if row["path"] == "tracked.txt"
        )

        missing = [dict(row) for row in baseline]
        missing[target_index]["generated"] = "YES"
        missing[target_index]["generator"] = "missing-generator.py"
        self.write_rows(missing)
        with self.assertRaisesRegex(ledger.LedgerError, "missing generator"):
            self.verify()

        contradictory = [dict(row) for row in baseline]
        contradictory[target_index]["generated"] = "NO"
        contradictory[target_index]["generator"] = "generator.py"
        self.write_rows(contradictory)
        with self.assertRaisesRegex(ledger.LedgerError, "contradictory generator"):
            self.verify()

    def test_immutable_identity_tamper_is_rejected(self) -> None:
        self.generate()
        rows = ledger.parse_ledger(self.output.read_bytes())
        target = next(row for row in rows if row["path"] == "tracked.txt")
        target["current_sha256"] = "0" * 64
        self.write_rows(rows)
        with self.assertRaisesRegex(ledger.LedgerError, "immutable field mismatch"):
            self.verify()

    def test_duplicate_header_key_and_noncanonical_encoding_are_rejected(self) -> None:
        data = self.generate()
        header, remainder = data.split(b"\n", 1)
        names = header.decode("utf-8").split(",")
        names[0] = names[1]
        forged = (",".join(names) + "\n").encode("utf-8") + remainder
        with self.assertRaisesRegex(ledger.LedgerError, "duplicate keys"):
            ledger.parse_ledger(forged)
        with self.assertRaisesRegex(ledger.LedgerError, "canonical encoding"):
            ledger.parse_ledger(data.replace(b"\n", b"\r\n"))

    def test_duplicate_traversal_and_git_admin_paths_are_rejected(self) -> None:
        self.generate()
        rows = ledger.parse_ledger(self.output.read_bytes())
        duplicate = [dict(row) for row in rows]
        duplicate.insert(1, dict(duplicate[0]))
        with self.assertRaisesRegex(ledger.LedgerError, "duplicate ledger path"):
            ledger.parse_ledger(ledger.render_ledger(duplicate))

        traversal = [dict(row) for row in rows]
        traversal[0]["path"] = "../escape"
        with self.assertRaisesRegex(ledger.LedgerError, "traversal"):
            ledger.parse_ledger(ledger.render_ledger(traversal))
        for path in (".GIT/config", "nested/.git/object"):
            with self.subTest(path=path):
                with self.assertRaisesRegex(
                    ledger.LedgerError, "administrative storage"
                ):
                    ledger._validate_path(path)

    def test_ledger_symlink_is_rejected_without_following(self) -> None:
        self.generate()
        alternate = self.repo / "alternate.csv"
        alternate.write_bytes(self.output.read_bytes())
        self.output.unlink()
        os.symlink("../alternate.csv", self.output)
        with self.assertRaisesRegex(ledger.LedgerError, "regular file, not a symlink"):
            self.verify()

    def test_symlink_ancestor_is_rejected_without_following(self) -> None:
        external = self.root / "external"
        external.mkdir()
        (external / "item.txt").write_text("outside\n", encoding="utf-8")
        (self.repo / "nested" / "item.txt").unlink()
        (self.repo / "nested").rmdir()
        os.symlink(external, self.repo / "nested")
        with self.assertRaisesRegex(ledger.LedgerError, "omitted by Git|unsafe"):
            ledger.generate_ledger(
                self.repo,
                self.source,
                self.output,
                ignored_policy="inventory",
            )

    def test_removed_tracked_parent_is_recorded_as_a_deletion(self) -> None:
        (self.repo / "nested" / "item.txt").unlink()
        (self.repo / "nested").rmdir()
        self.generate()
        row = self.rows()["nested/item.txt"]
        self.assertEqual(row["current_fs_type"], "")
        self.assertEqual(row["worktree_state"], "DELETED_FROM_WORKTREE")

    def test_resource_bounds_fail_closed(self) -> None:
        with self.assertRaisesRegex(ledger.LedgerError, "exceeding limit"):
            ledger.build_inventory(
                self.repo,
                self.source,
                ledger_self_path="audit/FILE_REVIEW_LEDGER.csv",
                ignored_policy="inventory",
                max_rows=1,
            )
        with self.assertRaisesRegex(ledger.LedgerError, "source blob exceeds"):
            ledger.build_inventory(
                self.repo,
                self.source,
                ledger_self_path="audit/FILE_REVIEW_LEDGER.csv",
                ignored_policy="inventory",
                max_file_bytes=1,
            )
        with mock.patch.object(ledger, "MAX_LEDGER_BYTES", 8):
            with self.assertRaisesRegex(ledger.LedgerError, "ledger size"):
                ledger.parse_ledger(b"123456789")
        with self.assertRaisesRegex(ledger.LedgerError, "finite"):
            ledger.build_inventory(
                self.repo,
                self.source,
                ledger_self_path="audit/FILE_REVIEW_LEDGER.csv",
                ignored_policy="inventory",
                max_seconds=float("inf"),
            )
        with self.assertRaisesRegex(ledger.LedgerError, "deadline exceeded"):
            ledger.build_inventory(
                self.repo,
                self.source,
                ledger_self_path="audit/FILE_REVIEW_LEDGER.csv",
                ignored_policy="inventory",
                _deadline=ledger.Deadline(0.0),
            )
        with mock.patch.object(ledger.subprocess, "Popen") as popen:
            with self.assertRaisesRegex(ledger.LedgerError, "deadline exceeded"):
                ledger._run_git(
                    self.repo,
                    ["status"],
                    deadline=ledger.Deadline(0.0),
                )
            popen.assert_not_called()

    def test_line_count_source_binding_and_digest_domain_separation(self) -> None:
        self.assertEqual(ledger._classify_content(b"a\rb\rc\r"), ("TEXT_UTF8", 3))
        first = ledger._canonical_digest("source", [{"path": "a"}])
        second = ledger._canonical_digest("index", [{"path": "a"}])
        self.assertNotEqual(first, second)
        with self.assertRaisesRegex(ledger.LedgerError, "full lowercase"):
            ledger.build_inventory(
                self.repo,
                self.source[:12],
                ledger_self_path="audit/FILE_REVIEW_LEDGER.csv",
                ignored_policy="inventory",
            )

    def test_output_outside_repository_and_case_collisions_are_rejected(self) -> None:
        with self.assertRaisesRegex(ledger.LedgerError, "inside the repository"):
            ledger.generate_ledger(
                self.repo,
                self.source,
                self.root / "outside-ledger.csv",
                ignored_policy="inventory",
            )
        with self.assertRaisesRegex(ledger.LedgerError, "case path collision"):
            ledger._validate_unique_paths(["Alpha", "alpha"], label="test")

    def test_cli_round_trip_isolated_runtime_and_review_gate_exit_codes(self) -> None:
        generate = subprocess.run(
            [
                sys.executable,
                "-I",
                str(SCRIPT),
                "generate",
                "--repo",
                str(self.repo),
                "--source-commit",
                self.source,
                "--ignored-policy",
                "inventory",
                "--output",
                str(self.output),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        self.assertEqual(generate.returncode, 0, generate.stderr)
        verify_command = [
            sys.executable,
            "-I",
            str(SCRIPT),
            "verify",
            "--repo",
            str(self.repo),
            "--source-commit",
            self.source,
            "--ignored-policy",
            "inventory",
            "--ledger",
            str(self.output),
        ]
        verify = subprocess.run(
            verify_command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        self.assertEqual(verify.returncode, 0, verify.stderr)
        assigned = subprocess.run(
            [*verify_command, "--require-assigned"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        self.assertEqual(assigned.returncode, 2)
        self.assertIn("reviewer is not assigned", assigned.stderr)
        nonisolated = subprocess.run(
            [item for item in verify_command if item != "-I"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        self.assertEqual(nonisolated.returncode, 2)
        self.assertIn("isolated safe-path mode", nonisolated.stderr)


if __name__ == "__main__":
    unittest.main()
