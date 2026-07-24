#!/usr/bin/env python3
"""Adversarial tests for current-audit-resource-profile.py."""

from __future__ import annotations

import copy
import gzip
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import types
import unittest
import zipfile
from pathlib import Path
from typing import Any, Callable, cast
from unittest import mock


SCRIPT = Path(__file__).with_name("current-audit-resource-profile.py")
VERIFIER = Path(__file__).with_name("verify-current-audit.py")
SPEC = importlib.util.spec_from_file_location("current_audit_resource_profile", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
profiler = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = profiler
SPEC.loader.exec_module(profiler)


class ExpectedBoundaryError(RuntimeError):
    """Fixture exception used to test fail-closed outcome accounting."""


def _verifier_fixture(marker: str, *, omit: str | None = None) -> bytes:
    lines = [
        f"{name} = {profiler.EXPECTED_LIMITS_BYTES[name]}"
        for name in profiler.LIMIT_NAMES
        if name != omit
    ]
    lines.extend(
        f"{name} = {profiler.EXPECTED_JSON_STRUCTURE_LIMITS[name]}"
        for name in profiler.JSON_STRUCTURE_LIMIT_NAMES
        if name != omit
    )
    if omit != "CurrentAuditError":
        lines.extend(["class CurrentAuditError(RuntimeError):", "    pass"])
    if omit != "GIT_EXECUTABLE":
        lines.append(f"GIT_EXECUTABLE = {profiler.EXPECTED_GIT_EXECUTABLE!r}")
    functions = {
        "_load_json": "def _load_json(*args, **kwargs):\n    return {}",
        "_validate_json_structure": (
            "def _validate_json_structure(*args, **kwargs):\n    return None"
        ),
        "_read_gzip_evidence": (
            "def _read_gzip_evidence(*args, **kwargs):\n    return b''"
        ),
        "_verify_handoff_zip": (
            "def _verify_handoff_zip(*args, **kwargs):\n    return None"
        ),
        "_git": "def _git(*args, **kwargs):\n    return b''",
        "_bounded_hygiene_total": (
            "def _bounded_hygiene_total(*args, **kwargs):\n    return 0"
        ),
        "_bounded_revocation_cause_total": (
            "def _bounded_revocation_cause_total(total, file_bytes):\n"
            "    return total + file_bytes"
        ),
        "_require_protocol_path": (
            "def _require_protocol_path(*args, **kwargs):\n    return ''"
        ),
        "_require_verifier_output_bound": (
            "def _require_verifier_output_bound(*args, **kwargs):\n    return b''"
        ),
        "_registered_snapshot_materialization_receipt": (
            "def _registered_snapshot_materialization_receipt(*args, **kwargs):\n"
            "    return {}"
        ),
        "_run_bounded": (
            "def _run_bounded(*args, **kwargs):\n"
            "    return (0, b'git version fixture', b'')"
        ),
        "_sanitized_git_environment": (
            "def _sanitized_git_environment():\n    return {'LANG': 'C', 'LC_ALL': 'C'}"
        ),
        "_verify_trusted_executable": (
            "def _verify_trusted_executable(*args, **kwargs):\n    return None"
        ),
    }
    lines.extend(value for name, value in functions.items() if name != omit)
    lines.append(f"SNAPSHOT_MARKER = {marker!r}")
    return ("\n".join(lines) + "\n").encode()


class CurrentAuditResourceProfileTests(unittest.TestCase):
    profile: dict[str, Any]
    verifier_payload: bytes
    snapshot: Path
    temporary: tempfile.TemporaryDirectory[str]

    @classmethod
    def setUpClass(cls) -> None:
        # A private immutable copy keeps this suite deterministic while the
        # independently owned verifier is being edited in the shared worktree.
        cls.verifier_payload = VERIFIER.read_bytes()
        cls.temporary = tempfile.TemporaryDirectory()
        cls.snapshot = Path(cls.temporary.name) / "verify-current-audit.py"
        cls.snapshot.write_bytes(cls.verifier_payload)
        cls.profile = profiler.generate_profile(cls.snapshot)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    def clone(self) -> dict[str, Any]:
        return copy.deepcopy(self.profile)

    def case(self, case_id: str) -> dict[str, Any]:
        return next(case for case in self.profile["cases"] if case["id"] == case_id)

    def test_schema_verifier_identity_and_environment_are_strict(self) -> None:
        profiler.validate_profile(self.profile, verifier_payload=self.verifier_payload)
        self.assertEqual(self.profile["schema_version"], "1.0.0")
        self.assertEqual(
            self.profile["profile_id"],
            "HALDIR_CURRENT_AUDIT_RESOURCE_BOUNDARY_PROFILE",
        )
        self.assertTrue(self.profile["overall_pass"])
        verifier = self.profile["verifier"]
        self.assertEqual(verifier["bytes"], len(self.verifier_payload))
        self.assertEqual(
            verifier["sha256"], hashlib.sha256(self.verifier_payload).hexdigest()
        )
        self.assertEqual(
            verifier["identity"],
            f"sha256:{verifier['sha256']}/{verifier['bytes']}",
        )
        self.assertEqual(
            set(self.profile["environment"]),
            {"platform", "hardware", "python", "tools"},
        )
        hardware = self.profile["environment"]["hardware"]
        self.assertGreater(hardware["logical_cpu_count"], 0)
        self.assertGreater(hardware["physical_memory_bytes"], 0)
        self.assertTrue(hardware["physical_memory_source"])
        self.assertIn("git", self.profile["environment"]["tools"])

    def test_timing_and_timeout_claims_are_exact_and_typed(self) -> None:
        interpretation = self.profile["interpretation"]
        self.assertEqual(
            interpretation["timings"]["classification"],
            "DIAGNOSTIC_NON_COMPARABLE",
        )
        self.assertIs(interpretation["timings"]["cross_run_comparable"], False)
        self.assertIs(interpretation["timings"]["latency_acceptance_claim"], False)
        self.assertIn(
            "diagnostic and non-comparable", interpretation["timings"]["statement"]
        )
        self.assertEqual(
            interpretation["timeout"]["classification"],
            "OUT_OF_SCOPE_REQUIRES_SEPARATE_TEST_EVIDENCE",
        )
        self.assertIs(interpretation["timeout"]["included_in_profile_cases"], False)
        self.assertIs(interpretation["timeout"]["profiled_as_resource_maximum"], False)
        self.assertIn(
            "must be established by the exact verifier test suite",
            interpretation["timeout"]["statement"],
        )
        self.assertNotIn(
            "TIMEOUT", {case["limit_name"] for case in self.profile["cases"]}
        )

    def test_dynamic_import_binds_the_exact_verifier_bytes(self) -> None:
        module_name = (
            "haldir_current_audit_verifier_"
            + hashlib.sha256(self.verifier_payload).hexdigest()[:16]
        )
        prior_module = types.ModuleType("preexisting_digest_module")
        sys.modules[module_name] = prior_module
        try:
            module, imported_payload = profiler._load_verifier(self.snapshot)
            self.assertIs(sys.modules[module_name], prior_module)
        finally:
            sys.modules.pop(module_name, None)
        self.assertEqual(imported_payload, self.verifier_payload)
        self.assertEqual(
            hashlib.sha256(imported_payload).hexdigest(),
            hashlib.sha256(self.verifier_payload).hexdigest(),
        )
        for name in (
            *profiler.LIMIT_NAMES,
            *profiler.JSON_STRUCTURE_LIMIT_NAMES,
            *profiler.REQUIRED_CALLABLES,
        ):
            self.assertTrue(hasattr(module, name), name)

        sys.modules[module_name] = None  # type: ignore[assignment]
        try:
            profiler._load_verifier(self.snapshot)
            self.assertIn(module_name, sys.modules)
            self.assertIsNone(sys.modules[module_name])
        finally:
            sys.modules.pop(module_name, None)

    def test_verifier_snapshot_resists_aba_path_substitution(self) -> None:
        original = _verifier_fixture("HASHED_AND_EXECUTED")
        substitute = _verifier_fixture("PATH_SUBSTITUTE")
        with tempfile.TemporaryDirectory() as raw:
            snapshot = Path(raw) / "verify-current-audit.py"
            snapshot.write_bytes(original)
            path_type = type(snapshot)
            original_read_bytes = path_type.read_bytes
            calls = 0

            def aba_read_bytes(path: Path) -> bytes:
                nonlocal calls
                if path != snapshot:
                    return original_read_bytes(path)
                calls += 1
                if calls == 1:
                    payload = original_read_bytes(path)
                    path.write_bytes(substitute)
                    return payload
                if calls == 2:
                    path.write_bytes(original)
                    return original_read_bytes(path)
                return original_read_bytes(path)

            with mock.patch.object(path_type, "read_bytes", aba_read_bytes):
                module, imported_payload = profiler._load_verifier(snapshot)

        self.assertEqual(calls, 2)
        self.assertEqual(imported_payload, original)
        self.assertEqual(module.SNAPSHOT_MARKER, "HASHED_AND_EXECUTED")

    def test_verifier_snapshot_rejects_a_persistent_concurrent_change(self) -> None:
        original = _verifier_fixture("ORIGINAL")
        substitute = _verifier_fixture("SUBSTITUTE")
        with tempfile.TemporaryDirectory() as raw:
            snapshot = Path(raw) / "verify-current-audit.py"
            snapshot.write_bytes(original)
            path_type = type(snapshot)
            original_read_bytes = path_type.read_bytes
            calls = 0

            def changed_read_bytes(path: Path) -> bytes:
                nonlocal calls
                if path != snapshot:
                    return original_read_bytes(path)
                calls += 1
                return original if calls == 1 else substitute

            with mock.patch.object(path_type, "read_bytes", changed_read_bytes):
                with self.assertRaisesRegex(
                    profiler.ProfileError, "verifier changed while"
                ):
                    profiler._load_verifier(snapshot)
        self.assertEqual(calls, 2)

    def test_verifier_requires_all_limits_and_end_to_end_callables(self) -> None:
        for missing in (
            "MAX_ZIP_TOTAL_BYTES",
            "MAX_REGISTERED_MATERIALIZED_FILE_BYTES",
            "MAX_REGISTERED_MATERIALIZED_TOTAL_BYTES",
            "MAX_JSON_DEPTH",
            "GIT_EXECUTABLE",
            "_load_json",
            "_validate_json_structure",
            "_read_gzip_evidence",
            "_verify_handoff_zip",
            "_git",
            "_bounded_hygiene_total",
            "_bounded_revocation_cause_total",
            "_require_protocol_path",
            "_require_verifier_output_bound",
            "_registered_snapshot_materialization_receipt",
            "_run_bounded",
            "_sanitized_git_environment",
            "_verify_trusted_executable",
        ):
            with self.subTest(missing=missing), tempfile.TemporaryDirectory() as raw:
                snapshot = Path(raw) / "verify-current-audit.py"
                snapshot.write_bytes(_verifier_fixture("MISSING", omit=missing))
                expected = (
                    "does not declare every profiled limit"
                    if missing in profiler.LIMIT_NAMES
                    else "does not declare every profiled JSON limit"
                    if missing == "MAX_JSON_DEPTH"
                    else f"verifier member is missing: {missing}"
                )
                with self.assertRaisesRegex(profiler.ProfileError, expected):
                    profiler._load_verifier(snapshot)

        invalid = _verifier_fixture("INVALID").replace(
            b"MAX_JSON_BYTES = 262144", b"MAX_JSON_BYTES = True"
        )
        with tempfile.TemporaryDirectory() as raw:
            snapshot = Path(raw) / "verify-current-audit.py"
            snapshot.write_bytes(invalid)
            with self.assertRaisesRegex(
                profiler.ProfileError, "not a literal integer expression"
            ):
                profiler._load_verifier(snapshot)

        hostile_fixtures = (
            (
                _verifier_fixture("EXIT") + b"raise SystemExit(0)\n",
                "cannot execute verifier snapshot",
            ),
            (
                _verifier_fixture("DYNAMIC")
                + b"globals()['MAX_JSON_BYTES'] = 10 ** 100\n",
                "runtime limits contradict",
            ),
            (
                _verifier_fixture("BASE_EXCEPTION").replace(
                    b"class CurrentAuditError(RuntimeError):",
                    b"class CurrentAuditError(BaseException):",
                ),
                "CurrentAuditError is not an exception type",
            ),
            (
                _verifier_fixture("NONCALLABLE_RECEIPT").replace(
                    (
                        b"def _registered_snapshot_materialization_receipt"
                        b"(*args, **kwargs):\n    return {}\n"
                    ),
                    b"_registered_snapshot_materialization_receipt = None\n",
                ),
                (
                    "verifier member is not callable: "
                    "_registered_snapshot_materialization_receipt"
                ),
            ),
        )
        for payload, expected in hostile_fixtures:
            with self.subTest(expected=expected), tempfile.TemporaryDirectory() as raw:
                snapshot = Path(raw) / "verify-current-audit.py"
                snapshot.write_bytes(payload)
                with self.assertRaisesRegex(profiler.ProfileError, expected):
                    profiler._load_verifier(snapshot)

    def test_tool_environment_uses_the_verifiers_bounded_runner(self) -> None:
        calls: list[tuple[list[str], dict[str, Any]]] = []
        trust_calls: list[tuple[str, str]] = []

        class FixtureVerifier:
            CurrentAuditError = ExpectedBoundaryError
            GIT_EXECUTABLE = "/fixture/git"

            @staticmethod
            def _sanitized_git_environment() -> dict[str, str]:
                return {"LANG": "C", "LC_ALL": "C"}

            @staticmethod
            def _verify_trusted_executable(path: str, label: str) -> None:
                trust_calls.append((path, label))

            @staticmethod
            def _run_bounded(
                command: list[str], **kwargs: Any
            ) -> tuple[int, bytes, bytes]:
                calls.append((command, kwargs))
                return 0, b"git version bounded-fixture\n", b""

        environment = profiler._tool_environment(FixtureVerifier)

        self.assertEqual(environment["tools"]["git"], "git version bounded-fixture")
        self.assertEqual(environment["tools"]["git_path"], "/fixture/git")
        self.assertEqual(
            trust_calls, [("/fixture/git", "git"), ("/fixture/git", "git")]
        )
        self.assertEqual(len(calls), 1)
        command, kwargs = calls[0]
        self.assertEqual(command, ["/fixture/git", "--version"])
        self.assertEqual(kwargs["env"], {"LANG": "C", "LC_ALL": "C"})
        self.assertEqual(kwargs["timeout_seconds"], 10)
        self.assertEqual(kwargs["stdout_limit"], 256)
        self.assertEqual(kwargs["stderr_limit"], 256)
        self.assertEqual(kwargs["error_prefix"], "CURRENT_AUDIT_PROFILE_GIT_VERSION")

    def test_tool_environment_rejects_bounded_runner_failures_and_stderr(
        self,
    ) -> None:
        class EnvironmentVerifier:
            CurrentAuditError = ExpectedBoundaryError
            GIT_EXECUTABLE = "/fixture/git"

            @staticmethod
            def _sanitized_git_environment() -> dict[str, str]:
                return {"LANG": "C", "LC_ALL": "C"}

            @staticmethod
            def _verify_trusted_executable(path: str, label: str) -> None:
                return None

        class FailedVerifier(EnvironmentVerifier):
            @staticmethod
            def _run_bounded(*args: Any, **kwargs: Any) -> tuple[int, bytes, bytes]:
                raise ExpectedBoundaryError("CURRENT_AUDIT_PROFILE_GIT_VERSION_TIMEOUT")

        class StderrVerifier(EnvironmentVerifier):
            @staticmethod
            def _run_bounded(*args: Any, **kwargs: Any) -> tuple[int, bytes, bytes]:
                return 0, b"git version fixture\n", b"unexpected stderr"

        class UntrustedVerifier(EnvironmentVerifier):
            @staticmethod
            def _verify_trusted_executable(path: str, label: str) -> None:
                raise ExpectedBoundaryError("CURRENT_AUDIT_TRUSTED_TOOL_INVALID:git")

        with self.assertRaisesRegex(
            profiler.ProfileError, "cannot determine bounded git version"
        ):
            profiler._tool_environment(FailedVerifier)
        with self.assertRaisesRegex(
            profiler.ProfileError, "git version output is invalid"
        ):
            profiler._tool_environment(StderrVerifier)
        with self.assertRaisesRegex(
            profiler.ProfileError, "Git executable is untrusted"
        ):
            profiler._tool_environment(UntrustedVerifier)

    def test_all_exact_and_one_unit_over_cases_are_exercised(self) -> None:
        cases = {case["id"]: case for case in self.profile["cases"]}
        self.assertEqual(len(cases), 38)
        self.assertEqual(
            set(self.profile["configuration"]["limits_bytes"]),
            set(profiler.LIMIT_NAMES),
        )
        self.assertEqual(
            self.profile["configuration"]["limits_bytes"][
                "MAX_REGISTERED_MATERIALIZED_FILE_BYTES"
            ],
            self.profile["configuration"]["limits_bytes"][
                "MAX_HYGIENE_TOTAL_BYTES"
            ],
        )
        self.assertEqual(
            self.profile["configuration"]["limits_bytes"][
                "MAX_REGISTERED_MATERIALIZED_TOTAL_BYTES"
            ],
            self.profile["configuration"]["limits_bytes"][
                "MAX_HYGIENE_TOTAL_BYTES"
            ],
        )
        self.assertEqual(
            set(self.profile["configuration"]["json_structure_limits"]),
            set(profiler.JSON_STRUCTURE_LIMIT_NAMES),
        )
        self.assertEqual(
            self.profile["configuration"]["git_fixture_seam"],
            profiler.GIT_FIXTURE_SEAM,
        )
        self.assertEqual(
            {case["primitive"] for case in cases.values()},
            {
                "_load_json",
                "_read_gzip_evidence",
                "_verify_handoff_zip",
                "_git",
                "_bounded_hygiene_total",
                "_bounded_revocation_cause_total",
                "_require_protocol_path",
                "_require_verifier_output_bound",
                "_registered_snapshot_materialization_receipt",
                "_validate_json_structure",
            },
        )
        self.assertEqual(
            {case["unit"] for case in cases.values()},
            {"BYTES", "LEVELS", "NODES", "ENTRIES"},
        )

        for case in cases.values():
            with self.subTest(case=case["id"]):
                self.assertEqual(len(case["elapsed_ns"]["samples"]), 3)
                self.assertEqual(case["accepted_samples"] + case["rejected_samples"], 3)
                self.assertTrue(case["pass"])
                if case["id"].endswith(".exact"):
                    self.assertEqual(case["input_value"], case["limit_value"])
                    self.assertEqual(case["expected_outcome"], "ACCEPT")
                    self.assertEqual(case["observed_outcome"], "ACCEPT")
                    self.assertEqual(case["observed_error_codes"], [])
                else:
                    self.assertEqual(case["input_value"], case["limit_value"] + 1)
                    self.assertEqual(case["expected_outcome"], "REJECT")
                    self.assertEqual(case["observed_outcome"], "REJECT")
                    self.assertEqual(
                        case["observed_error_codes"],
                        [case["expected_error_code"]],
                    )

        materialized_file_exact = cases[
            "registered_materialization."
            "MAX_REGISTERED_MATERIALIZED_FILE_BYTES.exact"
        ]
        materialized_file_over = cases[
            "registered_materialization."
            "MAX_REGISTERED_MATERIALIZED_FILE_BYTES.over"
        ]
        for case in (materialized_file_exact, materialized_file_over):
            self.assertEqual(
                case["fixture"]["materialized_file_bytes"],
                case["input_value"],
            )
            self.assertEqual(
                case["fixture"]["materialized_total_bytes"],
                case["input_value"],
            )
        materialized_total_exact = cases[
            "registered_materialization."
            "MAX_REGISTERED_MATERIALIZED_TOTAL_BYTES.exact"
        ]
        materialized_total_over = cases[
            "registered_materialization."
            "MAX_REGISTERED_MATERIALIZED_TOTAL_BYTES.over"
        ]
        for case in (materialized_total_exact, materialized_total_over):
            self.assertEqual(
                case["fixture"]["materialized_file_bytes"],
                profiler.EXPECTED_LIMITS_BYTES[
                    "MAX_REGISTERED_MATERIALIZED_TOTAL_BYTES"
                ]
                // 2,
            )
            self.assertEqual(
                case["fixture"]["materialized_total_bytes"],
                case["input_value"],
            )

    def test_json_path_and_gzip_boundaries_are_distinct_and_non_confounding(
        self,
    ) -> None:
        limits = self.profile["configuration"]["limits_bytes"]
        for name in ("MAX_JSON_BYTES", "MAX_REQUIREMENTS_BYTES"):
            size = limits[name] + 1
            payload = profiler._valid_root_json(size)
            self.assertEqual(len(payload), size)
            self.assertEqual(len(payload.decode("utf-8")), size - 1)

        compressed_exact = self.case(
            "read_gzip_evidence.MAX_COMPRESSED_LOG_BYTES.exact"
        )
        compressed_over = self.case("read_gzip_evidence.MAX_COMPRESSED_LOG_BYTES.over")
        decompressed_exact = self.case("read_gzip_evidence.MAX_LOG_BYTES.exact")
        decompressed_over = self.case("read_gzip_evidence.MAX_LOG_BYTES.over")
        self.assertEqual(
            compressed_exact["fixture"]["file_bytes"],
            limits["MAX_COMPRESSED_LOG_BYTES"],
        )
        self.assertEqual(
            compressed_over["fixture"]["file_bytes"],
            limits["MAX_COMPRESSED_LOG_BYTES"] + 1,
        )
        self.assertGreater(compressed_exact["fixture"]["decompressed_bytes"], 0)
        self.assertLessEqual(
            compressed_exact["fixture"]["decompressed_bytes"],
            limits["MAX_LOG_BYTES"],
        )
        self.assertLessEqual(
            decompressed_exact["fixture"]["file_bytes"],
            limits["MAX_COMPRESSED_LOG_BYTES"],
        )
        self.assertLessEqual(
            decompressed_over["fixture"]["file_bytes"],
            limits["MAX_COMPRESSED_LOG_BYTES"],
        )
        self.assertEqual(
            decompressed_over["fixture"]["decompressed_bytes"],
            limits["MAX_LOG_BYTES"] + 1,
        )

        limit = profiler.EXPECTED_LIMITS_BYTES["MAX_JSON_STRING_BYTES"]
        for size in (limit, limit + 1):
            with self.subTest(size=size):
                fixture, dimensions = profiler._json_string_fixture(size)
                [(key, value)] = fixture.items()
                key_bytes = len(key.encode("utf-8"))
                value_bytes = len(value.encode("utf-8"))
                self.assertEqual(key_bytes + value_bytes, size)
                self.assertLess(key_bytes, limit)
                self.assertLess(value_bytes, limit)
                self.assertLess(len(key) + len(value), limit)
                self.assertEqual(dimensions["json_string_bytes"], size)

        # The over-limit fixture remains acceptable to both defective
        # alternatives—character counting and value-only byte counting—so the
        # recorded production rejection rules out both mutations.
        over = self.case("json_structure.MAX_JSON_STRING_BYTES.over")
        self.assertEqual(
            over["observed_error_codes"],
            ["CURRENT_AUDIT_JSON_STRING_BYTES_BOUND:profile.json.strings"],
        )

        path_limit = profiler.EXPECTED_LIMITS_BYTES["MAX_PROTOCOL_PATH_BYTES"]
        for size in (path_limit, path_limit + 1):
            with self.subTest(path_size=size):
                path = profiler._protocol_path_fixture(size)
                components = path.split("/")
                self.assertEqual(len(components), 2)
                self.assertEqual(len(path.encode("utf-8")), size)
                self.assertLess(
                    max(len(component.encode("utf-8")) for component in components),
                    path_limit,
                )
                self.assertLess(len(path), path_limit)
        path_over = self.case("protocol_path.MAX_PROTOCOL_PATH_BYTES.over")
        self.assertEqual(
            path_over["observed_error_codes"],
            ["CURRENT_AUDIT_PROTOCOL_PATH_BOUND:profile.protocol.path"],
        )

    def test_zip_boundaries_are_distinct_and_non_confounding(self) -> None:
        limits = self.profile["configuration"]["limits_bytes"]
        entry_over = self.case("verify_handoff_zip.MAX_ZIP_ENTRY_BYTES.over")
        total_exact = self.case("verify_handoff_zip.MAX_ZIP_TOTAL_BYTES.exact")
        total_over = self.case("verify_handoff_zip.MAX_ZIP_TOTAL_BYTES.over")
        self.assertLessEqual(
            entry_over["fixture"]["zip_total_uncompressed_bytes"],
            limits["MAX_ZIP_TOTAL_BYTES"],
        )
        for case in (total_exact, total_over):
            self.assertLessEqual(
                case["fixture"]["zip_largest_entry_bytes"],
                limits["MAX_ZIP_ENTRY_BYTES"],
            )
        self.assertEqual(
            total_over["fixture"]["zip_total_uncompressed_bytes"],
            limits["MAX_ZIP_TOTAL_BYTES"] + 1,
        )

    def test_git_stdout_and_stderr_are_bounded_independently(self) -> None:
        limit = self.profile["configuration"]["limits_bytes"]["MAX_GIT_BYTES"]
        for stream in ("stdout", "stderr"):
            exact = self.case(f"git.MAX_GIT_BYTES.{stream}.exact")
            over = self.case(f"git.MAX_GIT_BYTES.{stream}.over")
            selected = f"git_{stream}_bytes"
            other = "git_stderr_bytes" if stream == "stdout" else "git_stdout_bytes"
            self.assertEqual(exact["fixture"][selected], limit)
            self.assertEqual(over["fixture"][selected], limit + 1)
            self.assertEqual(exact["fixture"][other], 0)
            self.assertEqual(over["fixture"][other], 0)

    def test_deterministic_gzip_is_reproducible_canonical_and_exact_size(self) -> None:
        first = profiler._deterministic_gzip(b"resource-boundary\n" * 16)
        second = profiler._deterministic_gzip(b"resource-boundary\n" * 16)
        self.assertEqual(first, second)
        self.assertTrue(first.startswith(b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\x03"))
        payload, exact_size = profiler._exact_size_canonical_gzip(4096)
        self.assertEqual(len(exact_size), 4096)
        self.assertEqual(gzip.decompress(exact_size), payload)
        self.assertLess(len(payload.decode("utf-8")), len(payload))

    def test_deterministic_zip_is_reproducible_and_has_exact_dimensions(self) -> None:
        sizes = [0, 1, 1024, 4096]
        first = profiler._deterministic_zip(sizes)
        second = profiler._deterministic_zip(sizes)
        self.assertEqual(first, second)
        # ZipFile accepts a seekable bytes stream; use the profiler's imported
        # io module so the fixture path is the same as production generation.
        with zipfile.ZipFile(profiler.io.BytesIO(first)) as archive:
            self.assertEqual([entry.file_size for entry in archive.infolist()], sizes)
            for index, size in enumerate(sizes):
                self.assertEqual(
                    archive.read(f"entry-{index:03d}.bin"),
                    profiler._utf8_payload_exact(size),
                )
            self.assertIsNone(archive.testzip())

    def test_fake_git_selects_exactly_one_requested_stream(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            for stream in ("stdout", "stderr"):
                executable = profiler._write_fake_git(
                    Path(raw), size=17, stream_name=stream
                )
                result = subprocess.run(
                    [str(executable), "ignored"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                )
                self.assertEqual(result.returncode, 0)
                expected = profiler._utf8_payload_exact(17)
                self.assertEqual(result.stdout, expected if stream == "stdout" else b"")
                self.assertEqual(result.stderr, expected if stream == "stderr" else b"")
            for size, stream in ((True, "stdout"), (-1, "stdout"), (1, "both")):
                with (
                    self.subTest(size=size, stream=stream),
                    self.assertRaisesRegex(
                        profiler.ProfileError, "fixture parameters are invalid"
                    ),
                ):
                    profiler._write_fake_git(Path(raw), size=size, stream_name=stream)

    def test_render_is_canonical_json_and_round_trips(self) -> None:
        rendered = profiler.render_profile(self.profile)
        self.assertTrue(rendered.endswith(b"\n"))
        parsed = json.loads(rendered)
        self.assertEqual(parsed, self.profile)
        self.assertEqual(rendered, profiler.render_profile(parsed))

    def test_schema_rejects_extra_keys_and_boundary_tamper(self) -> None:
        extra = self.clone()
        extra["unreviewed_extension"] = True
        with self.assertRaisesRegex(profiler.ProfileError, "profile has invalid keys"):
            profiler.validate_profile(extra)

        boundary = self.clone()
        boundary["cases"][0]["input_value"] += 1
        with self.assertRaisesRegex(profiler.ProfileError, "input_value is invalid"):
            profiler.validate_profile(boundary)

        limit = self.clone()
        limit["configuration"]["limits_bytes"]["MAX_JSON_BYTES"] = True
        with self.assertRaisesRegex(profiler.ProfileError, "must be an integer"):
            profiler.validate_profile(limit)

        structural_limit = self.clone()
        structural_limit["configuration"]["json_structure_limits"]["MAX_JSON_DEPTH"] = (
            65
        )
        with self.assertRaisesRegex(
            profiler.ProfileError, "JSON structural limits are unsupported"
        ):
            profiler.validate_profile(structural_limit)

        seam = self.clone()
        seam["configuration"]["git_fixture_seam"]["ambient_path_lookup"] = True
        with self.assertRaisesRegex(
            profiler.ProfileError, "git_fixture_seam is invalid"
        ):
            profiler.validate_profile(seam)

        fractional_samples = self.clone()
        fractional_samples["configuration"]["samples_per_case"] = 3.0
        with self.assertRaisesRegex(
            profiler.ProfileError, "samples_per_case is invalid"
        ):
            profiler.validate_profile(fractional_samples)

    def test_schema_rejects_verifier_identity_and_snapshot_tamper(self) -> None:
        identity = self.clone()
        identity["verifier"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(profiler.ProfileError, "identity contradicts"):
            profiler.validate_profile(identity)

        snapshot = self.clone()
        with self.assertRaisesRegex(
            profiler.ProfileError, "record contradicts the executed snapshot"
        ):
            profiler.validate_profile(snapshot, verifier_payload=b"different")

        altered_payload = self.verifier_payload.replace(
            b"MAX_PROTOCOL_PATH_BYTES = 240",
            b"MAX_PROTOCOL_PATH_BYTES = 241",
            1,
        )
        self.assertNotEqual(altered_payload, self.verifier_payload)
        altered = self.clone()
        altered_digest = hashlib.sha256(altered_payload).hexdigest()
        altered["verifier"]["sha256"] = altered_digest
        altered["verifier"]["bytes"] = len(altered_payload)
        altered["verifier"]["identity"] = (
            f"sha256:{altered_digest}/{len(altered_payload)}"
        )
        with self.assertRaisesRegex(
            profiler.ProfileError, "limits contradict the verifier snapshot"
        ):
            profiler.validate_profile(altered, verifier_payload=altered_payload)

        altered_json_payload = self.verifier_payload.replace(
            b"MAX_JSON_DEPTH = 64",
            b"MAX_JSON_DEPTH = 65",
            1,
        )
        self.assertNotEqual(altered_json_payload, self.verifier_payload)
        altered_json = self.clone()
        altered_json_digest = hashlib.sha256(altered_json_payload).hexdigest()
        altered_json["verifier"]["sha256"] = altered_json_digest
        altered_json["verifier"]["bytes"] = len(altered_json_payload)
        altered_json["verifier"]["identity"] = (
            f"sha256:{altered_json_digest}/{len(altered_json_payload)}"
        )
        with self.assertRaisesRegex(
            profiler.ProfileError, "JSON limits contradict the verifier snapshot"
        ):
            profiler.validate_profile(
                altered_json, verifier_payload=altered_json_payload
            )

        future_payload = self.verifier_payload.replace(
            b"MAX_JSON_BYTES = 256 * 1024",
            b"MAX_FUTURE_BYTES = 1\nMAX_JSON_BYTES = 256 * 1024",
            1,
        )
        self.assertNotEqual(future_payload, self.verifier_payload)
        future = self.clone()
        future_digest = hashlib.sha256(future_payload).hexdigest()
        future["verifier"]["sha256"] = future_digest
        future["verifier"]["bytes"] = len(future_payload)
        future["verifier"]["identity"] = f"sha256:{future_digest}/{len(future_payload)}"
        with self.assertRaisesRegex(
            profiler.ProfileError, "does not declare every profiled limit"
        ):
            profiler.validate_profile(future, verifier_payload=future_payload)

    def test_schema_rejects_each_fixture_family_tamper(self) -> None:
        mutations = (
            (0, "file_bytes", 1),
            (4, "decompressed_bytes", 1),
            (6, "json_depth", 1),
            (8, "json_nodes", 1),
            (10, "json_string_bytes", 1),
            (12, "json_container_entries", 1),
            (14, "decompressed_bytes", 1),
            (16, "zip_entry_count", 2),
            (18, "zip_total_uncompressed_bytes", 1),
            (20, "git_stderr_bytes", 1),
            (22, "git_stdout_bytes", 1),
            (24, "hygiene_total_bytes", 1),
            (24, "hygiene_current_bytes", 1),
            (24, "hygiene_increment_bytes", 1),
            (26, "revocation_cause_file_bytes", 1),
            (26, "revocation_cause_total_bytes", 1),
            (28, "revocation_cause_current_bytes", 1),
            (28, "revocation_cause_total_bytes", 1),
            (30, "protocol_path_bytes", 1),
            (32, "verifier_output_bytes", 1),
            (34, "materialized_file_bytes", 1),
            (34, "materialized_total_bytes", 1),
            (36, "materialized_file_bytes", 1),
            (36, "materialized_total_bytes", 1),
        )
        for index, field, delta in mutations:
            with self.subTest(index=index, field=field):
                tampered = self.clone()
                tampered["cases"][index]["fixture"][field] += delta
                with self.assertRaisesRegex(profiler.ProfileError, "fixture"):
                    profiler.validate_profile(tampered)

        compressed_support = self.clone()
        compressed_support["cases"][14]["fixture"]["file_bytes"] = (
            compressed_support["configuration"]["limits_bytes"][
                "MAX_COMPRESSED_LOG_BYTES"
            ]
            + 1
        )
        with self.assertRaisesRegex(profiler.ProfileError, "fixture"):
            profiler.validate_profile(compressed_support)

        unrelated = self.clone()
        unrelated["cases"][0]["fixture"]["git_stdout_bytes"] = 0
        with self.assertRaisesRegex(profiler.ProfileError, "dimensions unrelated"):
            profiler.validate_profile(unrelated)

        nonaggregate = self.clone()
        nonaggregate["cases"][24]["fixture"]["hygiene_current_bytes"] = 0
        nonaggregate["cases"][24]["fixture"]["hygiene_increment_bytes"] = nonaggregate[
            "cases"
        ][24]["input_value"]
        with self.assertRaisesRegex(profiler.ProfileError, "hygiene aggregate"):
            profiler.validate_profile(nonaggregate)

        revocation_file = self.clone()
        revocation_file["cases"][26]["fixture"]["revocation_cause_current_bytes"] = 1
        with self.assertRaisesRegex(profiler.ProfileError, "cause-file"):
            profiler.validate_profile(revocation_file)

        revocation_total = self.clone()
        revocation_total["cases"][28]["fixture"]["revocation_cause_file_bytes"] = 2
        with self.assertRaisesRegex(profiler.ProfileError, "cause-total"):
            profiler.validate_profile(revocation_total)

    def test_schema_rejects_outcome_error_and_timing_tamper(self) -> None:
        outcome = self.clone()
        outcome["cases"][0]["observed_outcome"] = "REJECT"
        with self.assertRaisesRegex(profiler.ProfileError, "contradicts counts"):
            profiler.validate_profile(outcome)

        errors = self.clone()
        errors["cases"][1]["observed_error_codes"] = ["wrong-error"]
        with self.assertRaisesRegex(profiler.ProfileError, "pass is invalid"):
            profiler.validate_profile(errors)

        timing = self.clone()
        timing["cases"][0]["elapsed_ns"]["median"] += 1
        with self.assertRaisesRegex(profiler.ProfileError, "distribution is invalid"):
            profiler.validate_profile(timing)

        overall = self.clone()
        overall["overall_pass"] = False
        with self.assertRaisesRegex(profiler.ProfileError, "contradicts cases"):
            profiler.validate_profile(overall)

    def test_schema_rejects_case_reordering_and_duplicate_errors(self) -> None:
        reordered = self.clone()
        reordered["cases"][0], reordered["cases"][1] = (
            reordered["cases"][1],
            reordered["cases"][0],
        )
        with self.assertRaisesRegex(profiler.ProfileError, r"cases\[0\].id is invalid"):
            profiler.validate_profile(reordered)

        duplicate = self.clone()
        duplicate["cases"][1]["observed_error_codes"] *= 2
        with self.assertRaisesRegex(profiler.ProfileError, "not canonical"):
            profiler.validate_profile(duplicate)

    def test_schema_rejects_environment_and_interpretation_tamper(self) -> None:
        cpu = self.clone()
        cpu["environment"]["hardware"]["logical_cpu_count"] = True
        with self.assertRaisesRegex(profiler.ProfileError, "must be an integer"):
            profiler.validate_profile(cpu)

        timing_claim = self.clone()
        timing_claim["interpretation"]["timings"]["latency_acceptance_claim"] = True
        with self.assertRaisesRegex(profiler.ProfileError, "timings is invalid"):
            profiler.validate_profile(timing_claim)

        timeout_claim = self.clone()
        timeout_claim["interpretation"]["timeout"]["included_in_profile_cases"] = True
        with self.assertRaisesRegex(profiler.ProfileError, "timeout is invalid"):
            profiler.validate_profile(timeout_claim)

        impossible_date = self.clone()
        impossible_date["generated_at_utc"] = "2026-02-31T12:00:00Z"
        with self.assertRaisesRegex(profiler.ProfileError, "valid calendar time"):
            profiler.validate_profile(impossible_date)

        git_path = self.clone()
        git_path["environment"]["tools"]["git_path"] = "/tmp/git"
        with self.assertRaisesRegex(profiler.ProfileError, "git_path is invalid"):
            profiler.validate_profile(git_path)

    def test_faulty_primitive_is_recorded_as_a_failed_case(self) -> None:
        wrongly_accepted = profiler._measure_case(
            case_id="fixture",
            primitive="fixture",
            limit_name="MAX_JSON_BYTES",
            subject="JSON_FILE_BYTES",
            unit="BYTES",
            limit_value=1,
            input_value=2,
            fixture=profiler._fixture(file_bytes=2),
            expected_outcome="REJECT",
            expected_error_code="EXPECTED_BOUND",
            action=lambda: None,
            expected_exception=ExpectedBoundaryError,
        )
        self.assertEqual(wrongly_accepted["observed_outcome"], "ACCEPT")
        self.assertFalse(wrongly_accepted["pass"])

        def wrong_error() -> None:
            raise ValueError("not-the-verifier-error")

        unexpected = profiler._measure_case(
            case_id="fixture",
            primitive="fixture",
            limit_name="MAX_JSON_BYTES",
            subject="JSON_FILE_BYTES",
            unit="BYTES",
            limit_value=1,
            input_value=2,
            fixture=profiler._fixture(file_bytes=2),
            expected_outcome="REJECT",
            expected_error_code="EXPECTED_BOUND",
            action=wrong_error,
            expected_exception=ExpectedBoundaryError,
        )
        self.assertEqual(unexpected["observed_outcome"], "REJECT")
        self.assertEqual(
            unexpected["observed_error_codes"],
            ["UNEXPECTED_ValueError:not-the-verifier-error"],
        )
        self.assertFalse(unexpected["pass"])

        def exits() -> None:
            raise SystemExit(0)

        terminated = profiler._measure_case(
            case_id="fixture",
            primitive="fixture",
            limit_name="MAX_JSON_BYTES",
            subject="JSON_FILE_BYTES",
            unit="BYTES",
            limit_value=1,
            input_value=2,
            fixture=profiler._fixture(file_bytes=2),
            expected_outcome="REJECT",
            expected_error_code="EXPECTED_BOUND",
            action=exits,
            expected_exception=ExpectedBoundaryError,
        )
        self.assertEqual(
            terminated["observed_error_codes"],
            ["UNEXPECTED_SystemExit:0"],
        )
        self.assertFalse(terminated["pass"])

    def test_cli_output_is_atomic_and_valid(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            output = root / "nested" / "profile.json"
            result = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    str(SCRIPT),
                    "--verifier",
                    str(self.snapshot),
                    "--output",
                    str(output),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "")
            parsed = json.loads(output.read_bytes())
            profiler.validate_profile(parsed, verifier_payload=self.verifier_payload)
            self.assertTrue(parsed["overall_pass"])
            self.assertEqual(list(output.parent.glob(f".{output.name}.*.tmp")), [])

            unsafe_output = root / "unsafe-profile.json"
            unsafe = subprocess.run(
                [
                    sys.executable,
                    "-E",
                    "-s",
                    "-S",
                    "-P",
                    str(SCRIPT),
                    "--verifier",
                    str(self.snapshot),
                    "--output",
                    str(unsafe_output),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                text=True,
            )
            self.assertEqual(unsafe.returncode, 2)
            self.assertEqual(unsafe.stdout, "")
            self.assertIn("profiler Python isolation is required", unsafe.stderr)
            self.assertFalse(unsafe_output.exists())

    def test_invalid_verifier_fails_without_replacing_output(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            invalid = root / "tampered-verifier.py"
            invalid.write_text("MAX_JSON_BYTES = 1\n", encoding="utf-8")
            output = root / "profile.json"
            output.write_bytes(b"preserve-existing-evidence\n")
            result = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    str(SCRIPT),
                    "--verifier",
                    str(invalid),
                    "--output",
                    str(output),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                text=True,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("does not declare every profiled limit", result.stderr)
            self.assertEqual(output.read_bytes(), b"preserve-existing-evidence\n")

            exiting = root / "exiting-verifier.py"
            exiting.write_bytes(_verifier_fixture("EXIT") + b"raise SystemExit(0)\n")
            result = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    str(SCRIPT),
                    "--verifier",
                    str(exiting),
                    "--output",
                    str(output),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                text=True,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("cannot execute verifier snapshot", result.stderr)
            self.assertEqual(output.read_bytes(), b"preserve-existing-evidence\n")

    @unittest.skipUnless(os.name == "posix", "symlink semantics require POSIX")
    def test_atomic_output_replaces_symlink_without_following_it(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            target = root / "outside.json"
            target.write_bytes(b"external-evidence\n")
            output = root / "profile.json"
            output.symlink_to(target)
            profiler.atomic_write(output, b"new-profile\n")
            self.assertFalse(output.is_symlink())
            self.assertEqual(output.read_bytes(), b"new-profile\n")
            self.assertEqual(target.read_bytes(), b"external-evidence\n")

            outside = root / "outside-directory"
            outside.mkdir()
            linked_parent = root / "linked-parent"
            linked_parent.symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(
                profiler.ProfileError, "parent traversal failed"
            ):
                profiler.atomic_write(
                    linked_parent / "escaped.json", b"must-not-escape\n"
                )
            self.assertFalse((outside / "escaped.json").exists())

            preserved = root / "preserved.json"
            preserved.write_bytes(b"preserved\n")
            with (
                mock.patch.object(
                    profiler, "_rename_atomic", side_effect=OSError("replace failure")
                ),
                self.assertRaisesRegex(OSError, "replace failure"),
            ):
                profiler.atomic_write(preserved, b"replacement\n")
            self.assertEqual(preserved.read_bytes(), b"preserved\n")
            self.assertEqual(list(root.glob(f".{preserved.name}.*.tmp")), [])

            sync_target = root / "sync-failure.json"
            sync_target.write_bytes(b"old\n")
            real_fsync = profiler.os.fsync
            sync_calls = 0

            def fail_directory_sync(descriptor: int) -> None:
                nonlocal sync_calls
                sync_calls += 1
                if sync_calls == 2:
                    raise OSError("directory sync failure")
                real_fsync(descriptor)

            with (
                mock.patch.object(
                    profiler.os, "fsync", side_effect=fail_directory_sync
                ),
                self.assertRaisesRegex(OSError, "directory sync failure"),
            ):
                profiler.atomic_write(sync_target, b"new-before-sync-error\n")
            self.assertEqual(sync_target.read_bytes(), b"new-before-sync-error\n")
            self.assertEqual(list(root.glob(f".{sync_target.name}.*.tmp")), [])

            file_sync_target = root / "file-sync-failure.json"
            file_sync_target.write_bytes(b"old\n")
            with (
                mock.patch.object(
                    profiler.os,
                    "fsync",
                    side_effect=OSError("file sync failure"),
                ),
                self.assertRaisesRegex(OSError, "file sync failure"),
            ):
                profiler.atomic_write(file_sync_target, b"must-not-replace\n")
            self.assertEqual(file_sync_target.read_bytes(), b"old\n")
            self.assertEqual(list(root.glob(f".{file_sync_target.name}.*.tmp")), [])

            parent_race_target = root / "parent-race.json"
            parent_race_target.write_bytes(b"old\n")
            alternate_parent = root / "alternate-parent"
            alternate_parent.mkdir()
            original_open_parent = cast(
                Callable[..., tuple[Path, int]], profiler._open_output_parent
            )
            open_parent_calls = 0

            def swap_reopened_parent(
                requested: Path, *, create: bool
            ) -> tuple[Path, int]:
                nonlocal open_parent_calls
                open_parent_calls += 1
                if open_parent_calls == 1:
                    return original_open_parent(requested, create=create)
                self.assertFalse(create)
                return original_open_parent(
                    alternate_parent / requested.name,
                    create=False,
                )

            with (
                mock.patch.object(
                    profiler,
                    "_open_output_parent",
                    side_effect=swap_reopened_parent,
                ),
                self.assertRaisesRegex(
                    profiler.ProfileError,
                    "atomic output parent changed during replacement",
                ),
            ):
                profiler.atomic_write(parent_race_target, b"new-before-race-error\n")
            self.assertEqual(open_parent_calls, 2)
            self.assertEqual(
                parent_race_target.read_bytes(), b"new-before-race-error\n"
            )
            self.assertEqual(list(root.glob(f".{parent_race_target.name}.*.tmp")), [])


if __name__ == "__main__":
    unittest.main()
