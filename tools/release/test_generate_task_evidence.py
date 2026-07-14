#!/usr/bin/env python3
"""Fail-closed, determinism, provenance, and boundary tests for task evidence."""

from __future__ import annotations

import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
import zipfile
from copy import deepcopy
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("generate-task-evidence.py")
SPEC = importlib.util.spec_from_file_location("generate_task_evidence", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
GENERATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GENERATE)

VERIFY_PATH = Path(__file__).with_name("verify-task-evidence.py")
VERIFY_SPEC = importlib.util.spec_from_file_location("verify_task_evidence", VERIFY_PATH)
assert VERIFY_SPEC is not None and VERIFY_SPEC.loader is not None
VERIFY = importlib.util.module_from_spec(VERIFY_SPEC)
VERIFY_SPEC.loader.exec_module(VERIFY)


class TaskEvidenceGenerationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.repo = Path(__file__).resolve().parents[2]
        cls.spec_path = cls.repo / "release/0.9.0/evidence-specs/t002.json"
        cls.commit = "a" * 40
        cls.workflow = {
            "workflow_name": "ci",
            "workflow_path": ".github/workflows/ci.yml",
            "workflow_id": 11,
            "expected_jobs": ["build-test", "supply-chain"],
            "required_steps_by_job": {
                "build-test": ["Tests"],
                "supply-chain": ["Verify protection"],
            },
            "marker_job": "supply-chain",
            "marker_step": "Verify protection",
            "success_marker": "verify-protection-model: OK",
        }
        cls.scope = {
            "repository": GENERATE.REPOSITORY,
            "event": "push",
            "branch": "main",
        }

    def run_metadata(self, *, attempt: int = 1) -> dict[str, object]:
        run_id = 7
        base = f"https://github.com/{GENERATE.REPOSITORY}/actions/runs/{run_id}"
        return {
            "id": run_id,
            "run_attempt": attempt,
            "status": "completed",
            "conclusion": "success",
            "head_sha": self.commit,
            "name": "ci",
            "path": ".github/workflows/ci.yml",
            "event": "push",
            "head_branch": "main",
            "repository": {"full_name": GENERATE.REPOSITORY},
            "html_url": base if attempt == 1 else f"{base}/attempts/{attempt}",
            "url": f"https://api.github.com/repos/{GENERATE.REPOSITORY}/actions/runs/{run_id}",
            "workflow_id": 11,
        }

    @staticmethod
    def jobs_metadata() -> dict[str, object]:
        jobs = [
            {
                "id": 22,
                "name": "supply-chain",
                "status": "completed",
                "conclusion": "success",
                "steps": [
                    {
                        "number": 1,
                        "name": "Verify protection",
                        "status": "completed",
                        "conclusion": "success",
                    }
                ],
            },
            {
                "id": 21,
                "name": "build-test",
                "status": "completed",
                "conclusion": "success",
                "steps": [
                    {
                        "number": 1,
                        "name": "Tests",
                        "status": "completed",
                        "conclusion": "success",
                    }
                ],
            },
        ]
        return {"total_count": len(jobs), "jobs": jobs}

    @staticmethod
    def log_zip(*, marker: bool = True, traversal: bool = False) -> bytes:
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            if traversal:
                archive.writestr("../escape.txt", b"bad")
            else:
                archive.writestr("0_build-test.txt", b"combined build\n")
                archive.writestr("build-test/system.txt", b"system\n")
                archive.writestr("build-test/1_Tests.txt", b"tests pass\n")
                archive.writestr(
                    "1_supply-chain.txt", b"combined supply\nverify-protection-model: OK\n"
                )
                archive.writestr("supply-chain/system.txt", b"system\n")
                value = b"verify-protection-model: OK\n" if marker else b"wrong\n"
                archive.writestr("supply-chain/1_Verify protection.txt", value)
        return output.getvalue()

    def test_checked_in_specs_are_strict_and_valid(self) -> None:
        for task in ("t000", "t001", "t002"):
            spec = GENERATE.load_spec(
                self.repo / f"release/0.9.0/evidence-specs/{task}.json"
            )
            self.assertEqual(spec["task_id"].lower(), task)
            self.assertEqual(spec["github"]["repository"], GENERATE.REPOSITORY)
            self.assertEqual(
                [item["path"] for item in spec["implementation_artifacts"]],
                sorted(item["path"] for item in spec["implementation_artifacts"]),
            )

    def test_duplicate_and_nonfinite_json_are_rejected(self) -> None:
        with self.assertRaisesRegex(
            GENERATE.EvidenceGenerationError, "EVIDENCE_JSON_DUPLICATE_KEY"
        ):
            GENERATE.load_spec_bytes(b'{"schema_version":"2.0.0","schema_version":"2.0.0"}')
        with self.assertRaisesRegex(
            GENERATE.EvidenceGenerationError, "EVIDENCE_JSON_NONFINITE"
        ):
            GENERATE.load_spec_bytes(b'{"schema_version":NaN}')

    def test_unknown_spec_field_is_rejected(self) -> None:
        value = json.loads(self.spec_path.read_bytes())
        value["caller_conclusion"] = "success"
        with self.assertRaisesRegex(
            GENERATE.EvidenceGenerationError, "EVIDENCE_SPEC_FIELDS_INVALID"
        ):
            GENERATE.load_spec_bytes(json.dumps(value).encode())

    def test_canonical_gzip_is_exact_and_cross_runtime_independent(self) -> None:
        fixture = b"abc\n" * 20000
        first = GENERATE.canonical_gzip(fixture)
        second = GENERATE.canonical_gzip(fixture)
        self.assertEqual(first, second)
        self.assertEqual(first[:10], b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff")
        self.assertEqual(GENERATE.decode_canonical_gzip(first), fixture)

    def test_noncanonical_or_concatenated_gzip_is_rejected(self) -> None:
        member = GENERATE.canonical_gzip(b"payload")
        changed_mtime = bytearray(member)
        changed_mtime[4] = 1
        for invalid in (bytes(changed_mtime), member + GENERATE.canonical_gzip(b"")):
            with self.assertRaises(GENERATE.EvidenceGenerationError):
                GENERATE.decode_canonical_gzip(invalid)

    def test_gzip_decode_enforces_output_bound(self) -> None:
        member = GENERATE.canonical_gzip(b"12345")
        with self.assertRaisesRegex(
            GENERATE.EvidenceGenerationError, "EVIDENCE_RESOURCE_BOUND:gzip"
        ):
            GENERATE.decode_canonical_gzip(member, limit=4)

    def test_source_log_archive_is_validated_and_round_trips(self) -> None:
        payload, entries = GENERATE._canonicalize_log_zip(self.log_zip())
        self.assertEqual(GENERATE._parse_canonical_log(payload), entries)
        self.assertEqual(
            [entry["path"] for entry in json.loads(payload)["entries"]],
            sorted(entries),
        )
        self.assertIn("supply-chain/1_Verify protection.txt", entries)

    def test_zip_traversal_and_missing_marker_are_rejected(self) -> None:
        with self.assertRaisesRegex(
            GENERATE.EvidenceGenerationError, "EVIDENCE_LOG_ARCHIVE_ENTRY_INVALID"
        ):
            GENERATE._canonicalize_log_zip(self.log_zip(traversal=True))
        with self.assertRaisesRegex(
            GENERATE.EvidenceGenerationError, "EVIDENCE_RUN_LOG_MARKER_MISSING"
        ):
            GENERATE._normalize_run(
                self.run_metadata(),
                self.jobs_metadata(),
                self.log_zip(marker=False),
                run_id=7,
                attempt=1,
                expected_commit=self.commit,
                workflow=self.workflow,
                    github_scope=self.scope,
                )

    def test_combined_only_legacy_logs_pass_but_partial_step_logs_fail(self) -> None:
        jobs = GENERATE._normalize_jobs(
            self.jobs_metadata(), self.workflow["expected_jobs"]
        )
        combined = {
            "0_build-test.txt": b"complete build log\n",
            "build-test/system.txt": b"system\n",
            "1_supply-chain.txt": b"verify-protection-model: OK\n",
            "supply-chain/system.txt": b"system\n",
        }
        GENERATE._validate_log_coverage(combined, jobs, self.workflow)

        # Once a job exposes detailed files, every metadata step must have one.
        build = next(job for job in jobs if job["name"] == "build-test")
        build["steps"].append(
            {
                "number": 2,
                "name": "Complete job",
                "status": "completed",
                "conclusion": "success",
            }
        )
        partial = dict(combined)
        partial["build-test/1_Tests.txt"] = b"tests\n"
        with self.assertRaisesRegex(
            GENERATE.EvidenceGenerationError, "EVIDENCE_LOG_STEP_COVERAGE_INVALID"
        ):
            GENERATE._validate_log_coverage(partial, jobs, self.workflow)

    def test_redundant_detailed_and_aggregate_only_layouts_normalize_identically(self) -> None:
        jobs = GENERATE._normalize_jobs(
            self.jobs_metadata(), self.workflow["expected_jobs"]
        )
        _, detailed = GENERATE._canonicalize_log_zip(self.log_zip())
        aggregate_only = {
            path: content
            for path, content in detailed.items()
            if "/" not in path or path.endswith("/system.txt")
        }
        GENERATE._validate_log_coverage(detailed, jobs, self.workflow)
        GENERATE._validate_log_coverage(aggregate_only, jobs, self.workflow)
        detailed_logical = GENERATE._canonical_log_payload(
            GENERATE._logical_job_logs(detailed, jobs)
        )
        aggregate_logical = GENERATE._canonical_log_payload(
            GENERATE._logical_job_logs(aggregate_only, jobs)
        )
        self.assertEqual(detailed_logical, aggregate_logical)

    def test_exact_repo_workflow_event_branch_attempt_and_jobs_are_enforced(self) -> None:
        record, payload = GENERATE._normalize_run(
            self.run_metadata(),
            self.jobs_metadata(),
            self.log_zip(),
            run_id=7,
            attempt=1,
            expected_commit=self.commit,
            workflow=self.workflow,
            github_scope=self.scope,
        )
        self.assertEqual(record["workflow_path"], ".github/workflows/ci.yml")
        self.assertEqual([job["name"] for job in record["jobs"]], self.workflow["expected_jobs"])
        self.assertGreater(len(payload), 0)

        mutations = (
            ("path", ".github/workflows/other.yml"),
            ("event", "workflow_dispatch"),
            ("head_branch", "side"),
            ("run_attempt", 2),
        )
        for field, value in mutations:
            with self.subTest(field=field):
                metadata = self.run_metadata()
                metadata[field] = value
                with self.assertRaisesRegex(
                    GENERATE.EvidenceGenerationError, "EVIDENCE_RUN_METADATA_INVALID"
                ):
                    GENERATE._normalize_run(
                        metadata,
                        self.jobs_metadata(),
                        self.log_zip(),
                        run_id=7,
                        attempt=1,
                        expected_commit=self.commit,
                        workflow=self.workflow,
                        github_scope=self.scope,
                    )

    def test_failed_or_missing_job_step_is_rejected(self) -> None:
        failed = self.jobs_metadata()
        failed["jobs"][0]["steps"][0]["conclusion"] = "failure"
        with self.assertRaisesRegex(
            GENERATE.EvidenceGenerationError, "EVIDENCE_RUN_STEP_INVALID"
        ):
            GENERATE._normalize_jobs(failed, self.workflow["expected_jobs"])
        missing = self.jobs_metadata()
        missing["jobs"].pop()
        missing["total_count"] = 1
        with self.assertRaisesRegex(
            GENERATE.EvidenceGenerationError, "EVIDENCE_RUN_JOB_SET_INVALID"
        ):
            GENERATE._normalize_jobs(missing, self.workflow["expected_jobs"])

    def test_removed_critical_step_is_rejected_even_when_jobs_and_marker_pass(self) -> None:
        missing_step = self.jobs_metadata()
        build = next(job for job in missing_step["jobs"] if job["name"] == "build-test")
        build["steps"] = [
            {
                "number": 1,
                "name": "Set up job",
                "status": "completed",
                "conclusion": "success",
            }
        ]
        with self.assertRaisesRegex(
            GENERATE.EvidenceGenerationError, "EVIDENCE_RUN_REQUIRED_STEP_SET_INVALID"
        ):
            GENERATE._normalize_run(
                self.run_metadata(),
                missing_step,
                self.log_zip(),
                run_id=7,
                attempt=1,
                expected_commit=self.commit,
                workflow=self.workflow,
                github_scope=self.scope,
            )

    def test_stdout_and_stderr_are_bounded_while_streaming(self) -> None:
        for stream in ("stdout", "stderr"):
            code = (
                "import sys; "
                f"sys.{stream}.buffer.write(b'x'*131072); sys.{stream}.flush()"
            )
            with self.subTest(stream=stream), self.assertRaisesRegex(
                GENERATE.EvidenceGenerationError, "EVIDENCE_RESOURCE_BOUND"
            ):
                GENERATE._run_bounded(
                    [sys.executable, "-c", code],
                    self.repo,
                    1024 if stream == "stdout" else 256 * 1024,
                    "boundary",
                    stderr_limit=1024 if stream == "stderr" else 256 * 1024,
                )

    def test_repo_file_symlinks_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "real").write_text("value", encoding="utf-8")
            (root / "link").symlink_to(root / "real")
            with self.assertRaisesRegex(
                GENERATE.EvidenceGenerationError, "EVIDENCE_PATH_SYMLINK"
            ):
                GENERATE._regular_repo_file(root, "link")

    def test_repository_pinned_signer_cryptographically_verifies_history(self) -> None:
        record = GENERATE._verify_signed_commit(
            self.repo,
            "da40bd8494f894c48add09fc26ce19b161ad91c8",
            GENERATE.ALLOWED_SIGNERS,
        )
        self.assertEqual(record["fingerprint"], GENERATE.SIGNER_FINGERPRINT)

    def test_forged_signature_header_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
            tree = subprocess.run(
                ["git", "mktree"], cwd=repo, input=b"", check=True, stdout=subprocess.PIPE
            ).stdout.decode().strip()
            commit = (
                f"tree {tree}\n"
                "author Sepehr Mahmoudian <sepmhn@gmail.com> 1 +0000\n"
                "committer Sepehr Mahmoudian <sepmhn@gmail.com> 1 +0000\n"
                "gpgsig -----BEGIN SSH SIGNATURE-----\n"
                " forged\n"
                " -----END SSH SIGNATURE-----\n\n"
                "forged signature marker\n"
            ).encode()
            object_id = subprocess.run(
                ["git", "hash-object", "-t", "commit", "-w", "--stdin"],
                cwd=repo,
                input=commit,
                check=True,
                stdout=subprocess.PIPE,
            ).stdout.decode().strip()
            with self.assertRaisesRegex(
                GENERATE.EvidenceGenerationError, "EVIDENCE_COMMAND_FAILED:verify_commit"
            ):
                GENERATE._verify_signed_commit(repo, object_id, GENERATE.ALLOWED_SIGNERS)

    def test_wrong_pinned_signer_file_is_rejected_before_git(self) -> None:
        with self.assertRaisesRegex(
            GENERATE.EvidenceGenerationError, "EVIDENCE_ALLOWED_SIGNERS_INVALID"
        ):
            GENERATE._verify_signed_commit(
                self.repo,
                "da40bd8494f894c48add09fc26ce19b161ad91c8",
                b"attacker ssh-ed25519 AAAA\n",
            )

    def test_central_verifier_rejects_spec_review_and_risk_tampering(self) -> None:
        spec = GENERATE.load_spec(self.spec_path)
        record = {
            "verification_scope": deepcopy(spec["verification_scope"]),
            "review": deepcopy(spec["review"]),
            "residual_risks": deepcopy(spec["residual_risks"]),
        }
        GENERATE._verify_spec_derived_fields(record, spec)
        for field in ("verification_scope", "review", "residual_risks"):
            with self.subTest(field=field):
                changed = deepcopy(record)
                if isinstance(changed[field], dict):
                    first = next(iter(changed[field]))
                    changed[field][first] += " tampered"
                else:
                    changed[field][0] += " tampered"
                with self.assertRaisesRegex(
                    GENERATE.EvidenceGenerationError,
                    "EVIDENCE_RECORD_SPEC_FIELD_MISMATCH",
                ):
                    GENERATE._verify_spec_derived_fields(changed, spec)

    def test_central_verifier_rejects_artifact_digest_and_must_match_drift(self) -> None:
        commit = "da40bd8494f894c48add09fc26ce19b161ad91c8"
        stable_spec = [
            {
                "path": "release/0.9.0/evidence/baseline-p0r.json",
                "worktree_policy": "MUST_MATCH",
            }
        ]
        records = GENERATE._implementation_artifacts(self.repo, commit, stable_spec)
        GENERATE._verify_artifact_manifest(self.repo, records, commit, stable_spec)
        tampered = deepcopy(records)
        tampered[0]["sha256"] = "0" * 64
        with self.assertRaisesRegex(
            GENERATE.EvidenceGenerationError,
            "EVIDENCE_RECORD_IMPLEMENTATION_ARTIFACTS_INVALID",
        ):
            GENERATE._verify_artifact_manifest(self.repo, tampered, commit, stable_spec)

        drifted_spec = [
            {"path": ".github/workflows/ci.yml", "worktree_policy": "MUST_MATCH"}
        ]
        drifted = GENERATE._implementation_artifacts(self.repo, commit, drifted_spec)
        with self.assertRaisesRegex(
            GENERATE.EvidenceGenerationError,
            "EVIDENCE_RECORD_ARTIFACT_WORKTREE_DRIFT",
        ):
            GENERATE._verify_artifact_manifest(self.repo, drifted, commit, drifted_spec)

    def test_central_verifier_rejects_run_url_jobs_steps_log_path_and_gzip_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            run, payload = GENERATE._normalize_run(
                self.run_metadata(),
                self.jobs_metadata(),
                self.log_zip(),
                run_id=7,
                attempt=1,
                expected_commit=self.commit,
                workflow=self.workflow,
                github_scope=self.scope,
            )
            relative = (
                f"{GENERATE.EVIDENCE_DIRECTORY}/t002-generated-ci-{self.commit}-"
                "run7-attempt1.log.gz"
            )
            compressed = GENERATE.canonical_gzip(payload)
            output = repo / relative
            output.parent.mkdir(parents=True)
            output.write_bytes(compressed)
            run["log"] = GENERATE._log_record(
                relative,
                payload,
                compressed,
                len(GENERATE._parse_canonical_log(payload)),
            )
            GENERATE._verify_run_record(
                repo,
                run,
                implementation_commit=self.commit,
                workflow=self.workflow,
                github_scope=self.scope,
                kind="ci",
                task="t002",
            )
            mutations = []
            wrong_url = deepcopy(run)
            wrong_url["url"] = "https://github.com/attacker/repo/actions/runs/7"
            mutations.append(wrong_url)
            missing_job = deepcopy(run)
            missing_job["jobs"].pop()
            mutations.append(missing_job)
            missing_step = deepcopy(run)
            missing_step["jobs"][0]["steps"].pop()
            mutations.append(missing_step)
            wrong_path = deepcopy(run)
            wrong_path["log"]["path"] = "../escape.log.gz"
            mutations.append(wrong_path)
            extra = deepcopy(run)
            extra["caller_conclusion"] = "success"
            mutations.append(extra)
            for changed in mutations:
                with self.assertRaises(GENERATE.EvidenceGenerationError):
                    GENERATE._verify_run_record(
                        repo,
                        changed,
                        implementation_commit=self.commit,
                        workflow=self.workflow,
                        github_scope=self.scope,
                        kind="ci",
                        task="t002",
                    )
            output.write_bytes(compressed[:-1] + bytes([compressed[-1] ^ 1]))
            with self.assertRaises(GENERATE.EvidenceGenerationError):
                GENERATE._verify_run_record(
                    repo,
                    run,
                    implementation_commit=self.commit,
                    workflow=self.workflow,
                    github_scope=self.scope,
                    kind="ci",
                    task="t002",
                )

    def test_central_verifier_rejects_extra_top_level_record_fields(self) -> None:
        record = {field: None for field in GENERATE.EXPECTED_RECORD_FIELDS}
        record.update(
            {
                "schema_version": "2.0.0",
                "task_id": "T002",
                "requirement_id": "HALDIR-0.9-T002",
                "status": "verified",
                "generated_by": GENERATE.GENERATOR_PATH,
            }
        )
        path = f"{GENERATE.EVIDENCE_DIRECTORY}/t002-generated-verification.json"
        GENERATE._verify_record_identity(record, path)
        record["manual_override"] = True
        with self.assertRaisesRegex(
            GENERATE.EvidenceGenerationError, "EVIDENCE_RECORD_FIELDS_INVALID"
        ):
            GENERATE._verify_record_identity(record, path)

    @staticmethod
    def _write_minimal_requirements(repo: Path, status: str, evidence: list[dict[str, object]]) -> None:
        release = repo / "release/0.9.0"
        (release / "evidence").mkdir(parents=True)
        (release / "requirements.json").write_text(
            json.dumps(
                {
                    "tasks": [
                        {"id": "T002", "status": status, "evidence": evidence}
                    ]
                }
            ),
            encoding="utf-8",
        )

    def test_all_present_reconciles_ledger_and_rejects_missing_or_stale_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            self._write_minimal_requirements(repo, "implemented", [])
            self.assertEqual(VERIFY.reconcile_all(repo), [])
            stale = repo / GENERATE.EVIDENCE_DIRECTORY / "t002-generated-ci-stale.log.gz"
            stale.write_bytes(b"stale")
            with self.assertRaisesRegex(
                VERIFY.CORE.EvidenceGenerationError, "EVIDENCE_LEDGER_GENERATED_FILE_STALE"
            ):
                VERIFY.reconcile_all(repo)

        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            self._write_minimal_requirements(repo, "verified", [])
            with self.assertRaisesRegex(
                VERIFY.CORE.EvidenceGenerationError, "EVIDENCE_LEDGER_T002_CLOSURE_MISSING"
            ):
                VERIFY.reconcile_all(repo)

        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            missing = {
                "kind": "generated_exact_commit_verification",
                "path": "release/0.9.0/evidence/t002-generated-verification.json",
                "implementation_commit": "a" * 40,
                "evidence_tool_commit": "b" * 40,
            }
            self._write_minimal_requirements(repo, "verified", [missing])
            with self.assertRaisesRegex(
                VERIFY.CORE.EvidenceGenerationError,
                "EVIDENCE_LEDGER_RECORD_RECONCILIATION_FAILED",
            ):
                VERIFY.reconcile_all(repo)


if __name__ == "__main__":
    unittest.main()
