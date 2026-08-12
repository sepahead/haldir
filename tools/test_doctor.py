#!/usr/bin/env -S python3 -I -B
"""Hermetic and adversarial tests for the development prerequisite doctor."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import re
import subprocess
import sys
import tempfile
import time
import types
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
DOCTOR_PATH = ROOT / "tools" / "doctor.py"


def _load_doctor() -> types.ModuleType:
    """Load the doctor by exact path under isolated Python."""

    name = "_haldir_test_doctor"
    specification = importlib.util.spec_from_file_location(name, DOCTOR_PATH)
    if specification is None or specification.loader is None:
        raise RuntimeError("cannot load tools/doctor.py")
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


DOCTOR = _load_doctor()


class ProbeTests(unittest.TestCase):
    def test_probe_reports_the_first_nonempty_line_without_a_shell(self) -> None:
        result = DOCTOR.probe(
            sys.executable,
            "-I",
            "-B",
            "-c",
            "print(); print('tool 1.2.3'); print('ignored detail')",
        )

        self.assertEqual(result, DOCTOR.CommandResult(True, "tool 1.2.3"))

    def test_probe_launches_an_isolated_process_group_without_a_shell(self) -> None:
        with mock.patch.object(
            DOCTOR.subprocess, "Popen", side_effect=FileNotFoundError
        ) as popen:
            result = DOCTOR.probe("missing-tool", "--version")

        self.assertEqual(result, DOCTOR.CommandResult(False, "FileNotFoundError"))
        popen.assert_called_once_with(
            ("missing-tool", "--version"),
            cwd=DOCTOR.ROOT,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            shell=False,
            start_new_session=True,
        )

    def test_probe_accepts_the_exact_output_boundary_and_bounds_its_summary(
        self,
    ) -> None:
        limit = 512
        result = DOCTOR.probe(
            sys.executable,
            "-I",
            "-B",
            "-c",
            f"import os; os.write(1, b'x' * {limit})",
            output_limit_bytes=limit,
        )

        self.assertTrue(result.ok)
        self.assertEqual(len(result.output), DOCTOR.SUMMARY_LIMIT_CHARACTERS)

    @staticmethod
    def _descendant_script(marker: Path, parent_action: str) -> str:
        spawned = marker.with_name(f"{marker.name}-spawned")
        descendant = (
            "import pathlib,time; "
            "time.sleep(1.0); "
            f"pathlib.Path({str(marker)!r}).write_text('survived', encoding='utf-8')"
        )
        return (
            "import pathlib,subprocess,sys,time; "
            f"subprocess.Popen((sys.executable, '-I', '-B', '-c', {descendant!r})); "
            f"pathlib.Path({str(spawned)!r}).write_text('spawned', encoding='utf-8'); "
            f"{parent_action}; "
            "time.sleep(60)"
        )

    def test_output_overflow_terminates_the_descendant_process_group(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "descendant-survived"
            spawned = marker.with_name(f"{marker.name}-spawned")
            script = self._descendant_script(
                marker, "__import__('os').write(1, b'x' * 65536)"
            )

            result = DOCTOR.probe(
                sys.executable,
                "-I",
                "-B",
                "-c",
                script,
                timeout_seconds=2,
                output_limit_bytes=1024,
            )
            time.sleep(1.2)

            self.assertEqual(
                result, DOCTOR.CommandResult(False, "output exceeded 1024 bytes")
            )
            self.assertTrue(spawned.exists(), "fixture never spawned its descendant")
            self.assertFalse(marker.exists(), "overflow left a live descendant")

    def test_timeout_terminates_the_descendant_process_group(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "descendant-survived"
            spawned = marker.with_name(f"{marker.name}-spawned")
            script = self._descendant_script(
                marker, "print('parent-ready', flush=True)"
            )

            result = DOCTOR.probe(
                sys.executable,
                "-I",
                "-B",
                "-c",
                script,
                timeout_seconds=0.4,
                output_limit_bytes=1024,
            )
            time.sleep(1.2)

            self.assertEqual(
                result, DOCTOR.CommandResult(False, "timed out after 0.4s")
            )
            self.assertTrue(spawned.exists(), "fixture never spawned its descendant")
            self.assertFalse(marker.exists(), "timeout left a live descendant")

    def test_probe_rejects_invalid_limits_without_starting_a_process(self) -> None:
        invalid = (
            {"timeout_seconds": 0},
            {"timeout_seconds": float("inf")},
            {"timeout_seconds": True},
            {"timeout_seconds": DOCTOR.MAX_PROBE_TIMEOUT_SECONDS + 1},
            {"output_limit_bytes": 0},
            {"output_limit_bytes": True},
            {"output_limit_bytes": DOCTOR.MAX_PROBE_OUTPUT_LIMIT_BYTES + 1},
        )
        with mock.patch.object(DOCTOR.subprocess, "Popen") as popen:
            for limits in invalid:
                with self.subTest(limits=limits):
                    self.assertEqual(
                        DOCTOR.probe("tool", **limits),
                        DOCTOR.CommandResult(False, "invalid probe limits"),
                    )
        popen.assert_not_called()

    def test_interrupt_terminates_the_probe_group_before_propagating(self) -> None:
        process = mock.MagicMock()
        pipe = mock.MagicMock()
        process.stdout = pipe
        selected = mock.MagicMock()
        selected.select.side_effect = KeyboardInterrupt

        with (
            mock.patch.object(DOCTOR.subprocess, "Popen", return_value=process),
            mock.patch.object(
                DOCTOR.selectors, "DefaultSelector", return_value=selected
            ),
            mock.patch.object(DOCTOR, "_terminate_process_group") as terminate,
            self.assertRaises(KeyboardInterrupt),
        ):
            DOCTOR.probe("tool", "--version")

        terminate.assert_called_once_with(process)
        selected.close.assert_called_once_with()
        pipe.close.assert_called_once_with()

    def test_successful_probe_terminates_a_background_descendant(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "successful-descendant-survived"
            descendant = (
                "import pathlib,time; time.sleep(0.8); "
                f"pathlib.Path({str(marker)!r}).write_text('survived', encoding='utf-8')"
            )
            script = (
                "import os,subprocess,sys; "
                "sink=os.open(os.devnull, os.O_WRONLY); "
                f"subprocess.Popen((sys.executable, '-I', '-B', '-c', {descendant!r}), "
                "stdin=subprocess.DEVNULL, stdout=sink, stderr=sink); "
                "os.close(sink); print('complete', flush=True)"
            )

            result = DOCTOR.probe(
                sys.executable,
                "-I",
                "-B",
                "-c",
                script,
                timeout_seconds=2,
            )
            time.sleep(1.0)

            self.assertEqual(result, DOCTOR.CommandResult(True, "complete"))
            self.assertFalse(marker.exists(), "successful probe left a live descendant")


class VersionExpectationTests(unittest.TestCase):
    def assert_expectation(
        self,
        pattern: re.Pattern[str],
        expected_version: str | None,
        accepted: tuple[str, ...],
        rejected: tuple[str, ...],
        expected_commit: str | None = None,
    ) -> None:
        expectation = DOCTOR.OutputExpectation(
            "test expectation", pattern, expected_version, expected_commit
        )
        for value in accepted:
            with self.subTest(value=value, accepted=True):
                self.assertTrue(expectation.matches(value))
        for value in rejected:
            with self.subTest(value=value, accepted=False):
                self.assertFalse(expectation.matches(value))

    def test_rust_tool_versions_require_exact_full_line_grammars(self) -> None:
        self.assert_expectation(
            DOCTOR.CARGO_VERSION_PATTERN,
            "1.96.0",
            ("cargo 1.96.0 (30a34c682 2026-05-25)",),
            (
                "cargo 1.96.00 (30a34c682 2026-05-25)",
                "cargo 1.96.0-malicious (30a34c682 2026-05-25)",
                "prefix cargo 1.96.0 (30a34c682 2026-05-25)",
            ),
        )
        self.assert_expectation(
            DOCTOR.RUSTC_VERSION_PATTERN,
            "1.96.0",
            ("rustc 1.96.0 (ac68faa20 2026-05-25)",),
            ("rustc 1.96.1 (ac68faa20 2026-05-25)",),
        )
        self.assert_expectation(
            DOCTOR.RUSTFMT_VERSION_PATTERN,
            None,
            ("rustfmt 1.9.0-stable (ac68faa20c 2026-05-25)",),
            (
                "rustfmt 1.9.0-stable (fffffffff 2026-05-25)",
                "rustfmt 1.9.0-stable (ac68faa 2026-05-25)",
                "rustfmt 1.9.0-stable",
            ),
            expected_commit="ac68faa20",
        )
        self.assert_expectation(
            DOCTOR.CLIPPY_VERSION_PATTERN,
            "0.1.96",
            ("clippy 0.1.96 (ac68faa20c 2026-05-25)",),
            (
                "clippy 0.1.960 (ac68faa20c 2026-05-25)",
                "clippy 0.1.96 (fffffffff 2026-05-25)",
            ),
            expected_commit="ac68faa20",
        )

    def test_optional_versions_reject_numeric_prefix_false_greens(self) -> None:
        self.assert_expectation(
            DOCTOR.CARGO_DENY_VERSION_PATTERN,
            "0.20.2",
            ("cargo-deny 0.20.2",),
            ("cargo-deny 0.20.20", "cargo-deny 0.20.2-local"),
        )
        self.assert_expectation(
            DOCTOR.JAVA_VERSION_PATTERN,
            "21",
            (
                'openjdk version "21"',
                'openjdk version "21.0.11" 2026-04-21 LTS',
                'java version "21-ea" 2026-01-01',
            ),
            (
                'openjdk version "121"',
                'openjdk version "210.0.1"',
                "runtime 21",
            ),
        )


class ReportingTests(unittest.TestCase):
    def test_required_version_mismatch_fails_with_exact_expectation(self) -> None:
        expectation = DOCTOR.OutputExpectation(
            "exact rustc 1.96.0 version line",
            DOCTOR.RUSTC_VERSION_PATTERN,
            "1.96.0",
        )
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            ready = DOCTOR.required(
                "rustc", DOCTOR.CommandResult(True, "rustc 1.95.0"), expectation
            )

        self.assertFalse(ready)
        self.assertIn("FAIL rustc", output.getvalue())
        self.assertIn("expected exact rustc 1.96.0 version line", output.getvalue())

    def test_optional_mismatch_is_informational(self) -> None:
        expectation = DOCTOR.OutputExpectation(
            "exact cargo-deny 0.20.2 version line",
            DOCTOR.CARGO_DENY_VERSION_PATTERN,
            "0.20.2",
        )
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = DOCTOR.optional(
                "cargo-deny",
                DOCTOR.CommandResult(True, "cargo-deny 0.19.9"),
                expectation,
            )

        self.assertIsNone(result)
        self.assertIn("INFO cargo-deny", output.getvalue())


class MainTests(unittest.TestCase):
    @staticmethod
    def _write_configuration(
        root: Path,
        *,
        rust_toolchain: str | None = None,
        pins: str | None = None,
    ) -> None:
        (root / "tools").mkdir(exist_ok=True)
        (root / "rust-toolchain.toml").write_text(
            (
                '[toolchain]\nchannel = "1.96.0"\ncomponents = ["rustfmt", "clippy"]\n'
                if rust_toolchain is None
                else rust_toolchain
            ),
            encoding="utf-8",
        )
        (root / "tools" / "pins.toml").write_text(
            """
[toolchain]
rust_channel = "1.96.0"

[supply_chain.cargo_deny]
version = "0.20.2"

[formal]
java_specification_version = "21"
""".lstrip()
            if pins is None
            else pins,
            encoding="utf-8",
        )

    @staticmethod
    def _successful_probe(*command: str, **_limits: object) -> object:
        prefix = ("/bin/rustup", "run", "1.96.0")
        rendered = {
            (*prefix, "cargo", "--version"): "cargo 1.96.0 (30a34c682 2026-05-25)",
            (*prefix, "rustc", "--version"): "rustc 1.96.0 (ac68faa20 2026-05-25)",
            (*prefix, "rustfmt", "--version"): (
                "rustfmt 1.9.0-stable (ac68faa20c 2026-05-25)"
            ),
            (*prefix, "cargo-clippy", "--version"): (
                "clippy 0.1.96 (ac68faa20c 2026-05-25)"
            ),
            (
                *prefix,
                "cargo",
                "metadata",
                "--locked",
                "--offline",
                "--format-version",
                "1",
            ): "{}",
            ("git", "--version"): "git version 2.51.0",
            ("just", "--version"): "just 1.40.0",
            ("cargo-deny", "--version"): "cargo-deny 0.20.2",
            ("java", "-version"): 'openjdk version "21.0.11" 2026-04-21 LTS',
            ("gh", "--version"): "gh version 2.95.0",
        }
        return DOCTOR.CommandResult(True, rendered[command])

    def test_optional_absence_does_not_fail_ready_core(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_configuration(root)
            observed_commands: list[tuple[str, ...]] = []

            def probe(*command: str, **limits: object) -> object:
                del limits
                observed_commands.append(command)
                if command[0] in {"just", "gh", "cargo-deny"}:
                    return DOCTOR.CommandResult(False, "FileNotFoundError")
                return self._successful_probe(*command)

            output = io.StringIO()
            with (
                mock.patch.object(DOCTOR, "ROOT", root),
                mock.patch.object(DOCTOR.shutil, "which", return_value="/bin/rustup"),
                mock.patch.object(DOCTOR, "probe", side_effect=probe),
                contextlib.redirect_stdout(output),
            ):
                status = DOCTOR.main([])

        self.assertEqual(status, 0)
        self.assertIn(
            "doctor: core development prerequisites are ready", output.getvalue()
        )
        self.assertNotIn("Java", output.getvalue())
        self.assertNotIn(("java", "-version"), observed_commands)

    def test_formal_lane_is_explicit_and_java_is_required(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_configuration(root)

            def missing_java(*command: str, **limits: object) -> object:
                del limits
                if command == ("java", "-version"):
                    return DOCTOR.CommandResult(False, "FileNotFoundError")
                return self._successful_probe(*command)

            output = io.StringIO()
            error_output = io.StringIO()
            with (
                mock.patch.object(DOCTOR, "ROOT", root),
                mock.patch.object(DOCTOR.shutil, "which", return_value="/bin/rustup"),
                mock.patch.object(DOCTOR, "probe", side_effect=missing_java),
                contextlib.redirect_stdout(output),
                contextlib.redirect_stderr(error_output),
            ):
                status = DOCTOR.main(["--formal"])

        self.assertEqual(status, 1)
        self.assertIn("FAIL formal Java specification", output.getvalue())
        self.assertIn(
            "required development prerequisites are not ready", error_output.getvalue()
        )

    def test_formal_lane_reports_its_narrow_java_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_configuration(root)
            output = io.StringIO()
            with (
                mock.patch.object(DOCTOR, "ROOT", root),
                mock.patch.object(DOCTOR.shutil, "which", return_value="/bin/rustup"),
                mock.patch.object(DOCTOR, "probe", side_effect=self._successful_probe),
                contextlib.redirect_stdout(output),
            ):
                status = DOCTOR.main(["--formal"])

        self.assertEqual(status, 0)
        self.assertIn("PASS formal Java specification", output.getvalue())
        self.assertIn("runner separately verifies exact vendor", output.getvalue())

    def test_unknown_lane_fails_before_configuration_or_probe(self) -> None:
        stderr = io.StringIO()
        with (
            mock.patch.object(DOCTOR, "_load_configuration") as load,
            mock.patch.object(DOCTOR, "probe") as probe,
            contextlib.redirect_stderr(stderr),
        ):
            status = DOCTOR.main(["--unknown"])

        self.assertEqual(status, 2)
        self.assertEqual(stderr.getvalue(), "usage: doctor.py [--formal]\n")
        load.assert_not_called()
        probe.assert_not_called()

    def test_locked_workspace_failure_makes_core_not_ready(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_configuration(root)

            def probe(*command: str, **limits: object) -> object:
                del limits
                if "metadata" in command:
                    return DOCTOR.CommandResult(False, "lock file needs update")
                return self._successful_probe(*command)

            stdout = io.StringIO()
            stderr = io.StringIO()
            with (
                mock.patch.object(DOCTOR, "ROOT", root),
                mock.patch.object(DOCTOR.shutil, "which", return_value="/bin/rustup"),
                mock.patch.object(DOCTOR, "probe", side_effect=probe),
                contextlib.redirect_stdout(stdout),
                contextlib.redirect_stderr(stderr),
            ):
                status = DOCTOR.main()

        self.assertEqual(status, 1)
        self.assertIn("FAIL locked workspace", stdout.getvalue())
        self.assertIn("not ready", stderr.getvalue())

    def test_missing_repository_configuration_is_a_clean_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            stderr = io.StringIO()
            with (
                mock.patch.object(DOCTOR, "ROOT", Path(directory)),
                contextlib.redirect_stderr(stderr),
            ):
                status = DOCTOR.main()

        self.assertEqual(status, 1)
        self.assertIn(
            "FAIL repository configuration: ConfigurationError: "
            "rust-toolchain.toml must be a readable regular file",
            stderr.getvalue(),
        )

    def test_malformed_toml_is_a_clean_failure_before_any_probe(self) -> None:
        documents = (
            ("[toolchain\n", None),
            (None, "[formal\n"),
        )
        for rust_toolchain, pins in documents:
            with self.subTest(rust_toolchain=rust_toolchain, pins=pins):
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    self._write_configuration(
                        root, rust_toolchain=rust_toolchain, pins=pins
                    )
                    stderr = io.StringIO()
                    with (
                        mock.patch.object(DOCTOR, "ROOT", root),
                        mock.patch.object(DOCTOR, "probe") as probe,
                        contextlib.redirect_stderr(stderr),
                    ):
                        status = DOCTOR.main()

                self.assertEqual(status, 1)
                self.assertIn("TOMLDecodeError", stderr.getvalue())
                probe.assert_not_called()

    def test_non_utf8_toml_is_a_clean_failure_before_any_probe(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_configuration(root)
            (root / "rust-toolchain.toml").write_bytes(b"\xff")
            stderr = io.StringIO()
            with (
                mock.patch.object(DOCTOR, "ROOT", root),
                mock.patch.object(DOCTOR, "probe") as probe,
                contextlib.redirect_stderr(stderr),
            ):
                status = DOCTOR.main()

        self.assertEqual(status, 1)
        self.assertIn("UnicodeDecodeError", stderr.getvalue())
        probe.assert_not_called()

    def test_oversized_or_symlinked_configuration_is_rejected_before_probe(
        self,
    ) -> None:
        for mode in ("oversized", "symlink"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self._write_configuration(root)
                pins = root / "tools" / "pins.toml"
                if mode == "oversized":
                    pins.write_bytes(b"#" * (DOCTOR.CONFIGURATION_LIMIT_BYTES + 1))
                else:
                    target = root / "actual-pins.toml"
                    pins.replace(target)
                    pins.symlink_to(target)
                stderr = io.StringIO()
                with (
                    mock.patch.object(DOCTOR, "ROOT", root),
                    mock.patch.object(DOCTOR, "probe") as probe,
                    contextlib.redirect_stderr(stderr),
                ):
                    status = DOCTOR.main()

                self.assertEqual(status, 1)
                self.assertIn("ConfigurationError", stderr.getvalue())
                probe.assert_not_called()

    def test_missing_nested_configuration_is_a_clean_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_configuration(
                root,
                pins=(
                    '[toolchain]\nrust_channel = "1.96.0"\n'
                    "[supply_chain]\n"
                    '[formal]\njava_specification_version = "21"\n'
                ),
            )
            stderr = io.StringIO()
            with (
                mock.patch.object(DOCTOR, "ROOT", root),
                mock.patch.object(DOCTOR, "probe") as probe,
                contextlib.redirect_stderr(stderr),
            ):
                status = DOCTOR.main()

        self.assertEqual(status, 1)
        self.assertIn("ConfigurationError", stderr.getvalue())
        self.assertIn("cargo_deny must be a TOML table", stderr.getvalue())
        probe.assert_not_called()

    def test_wrong_scalar_types_are_rejected_before_any_probe(self) -> None:
        configurations = (
            (
                '[toolchain]\nchannel = 196\ncomponents = ["rustfmt", "clippy"]\n',
                None,
            ),
            (
                None,
                """
[toolchain]
rust_channel = 196
[supply_chain.cargo_deny]
version = "0.20.2"
[formal]
java_specification_version = "21"
""".lstrip(),
            ),
            (
                None,
                """
[toolchain]
rust_channel = "1.96.0"
[supply_chain.cargo_deny]
version = 20
[formal]
java_specification_version = "21"
""".lstrip(),
            ),
        )
        for rust_toolchain, pins in configurations:
            with self.subTest(rust_toolchain=rust_toolchain, pins=pins):
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    self._write_configuration(
                        root, rust_toolchain=rust_toolchain, pins=pins
                    )
                    stderr = io.StringIO()
                    with (
                        mock.patch.object(DOCTOR, "ROOT", root),
                        mock.patch.object(DOCTOR, "probe") as probe,
                        contextlib.redirect_stderr(stderr),
                    ):
                        status = DOCTOR.main()

                self.assertEqual(status, 1)
                self.assertIn("must be a TOML string", stderr.getvalue())
                probe.assert_not_called()

    def test_formal_pin_type_is_checked_only_for_the_explicit_formal_lane(self) -> None:
        pins = """
[toolchain]
rust_channel = "1.96.0"
[supply_chain.cargo_deny]
version = "0.20.2"
[formal]
java_specification_version = 21
""".lstrip()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_configuration(root, pins=pins)
            with (
                mock.patch.object(DOCTOR, "ROOT", root),
                mock.patch.object(DOCTOR.shutil, "which", return_value="/bin/rustup"),
                mock.patch.object(DOCTOR, "probe", side_effect=self._successful_probe),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                default_status = DOCTOR.main([])

            stderr = io.StringIO()
            with (
                mock.patch.object(DOCTOR, "ROOT", root),
                mock.patch.object(DOCTOR, "probe") as probe,
                contextlib.redirect_stderr(stderr),
            ):
                formal_status = DOCTOR.main(["--formal"])

        self.assertEqual(default_status, 0)
        self.assertEqual(formal_status, 1)
        self.assertIn("must be a TOML string", stderr.getvalue())
        probe.assert_not_called()

    def test_toolchain_pin_mismatch_is_rejected_before_any_probe(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_configuration(
                root,
                pins="""
[toolchain]
rust_channel = "1.95.0"
[supply_chain.cargo_deny]
version = "0.20.2"
[formal]
java_specification_version = "21"
""".lstrip(),
            )
            stderr = io.StringIO()
            with (
                mock.patch.object(DOCTOR, "ROOT", root),
                mock.patch.object(DOCTOR, "probe") as probe,
                contextlib.redirect_stderr(stderr),
            ):
                status = DOCTOR.main()

        self.assertEqual(status, 1)
        self.assertIn("does not match tools/pins.toml", stderr.getvalue())
        probe.assert_not_called()

    def test_rustup_selection_never_requests_installation(self) -> None:
        with mock.patch.object(DOCTOR.shutil, "which", return_value="/bin/rustup"):
            command = DOCTOR._rust_command("1.96.0", "cargo", "--version")

        self.assertEqual(
            command, ("/bin/rustup", "run", "1.96.0", "cargo", "--version")
        )
        self.assertNotIn("--install", command)

    def test_hidden_rustup_proxy_is_not_invoked_directly(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            rustup = root / "rustup"
            rustup.touch()
            cargo = root / "cargo"
            cargo.symlink_to(rustup.name)

            def which(command: str) -> str | None:
                return None if command == "rustup" else str(cargo)

            with mock.patch.object(DOCTOR.shutil, "which", side_effect=which):
                command = DOCTOR._rust_command("1.96.0", "cargo", "--version")

        self.assertEqual(
            command,
            (str(rustup.resolve()), "run", "1.96.0", "cargo", "--version"),
        )
        self.assertNotEqual(command[0], str(cargo))


if __name__ == "__main__":
    unittest.main()
