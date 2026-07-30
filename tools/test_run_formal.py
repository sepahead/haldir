#!/usr/bin/env -S python3 -I -B
"""Hermetic adversarial tests for ``tools/run_formal.py``.

The suite uses only temporary files, in-process HTTP fakes, and short-lived
``/bin/sh`` children.  It never contacts the network and never requires a JRE.
"""

from __future__ import annotations

import email.message
import hashlib
import http.client
import importlib.util
import io
import json
import os
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest
import urllib.request
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
RUNNER_PATH = ROOT / "tools" / "run_formal.py"


def _load_runner() -> types.ModuleType:
    """Load the hyphen-free runner by exact path under isolated Python."""

    name = "_haldir_test_run_formal"
    specification = importlib.util.spec_from_file_location(name, RUNNER_PATH)
    if specification is None or specification.loader is None:
        raise RuntimeError("cannot load tools/run_formal.py")
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


RUNNER = _load_runner()


def _tiny_pins(payload: bytes = b"verified-tla-tools") -> tuple[object, bytes]:
    pins = RUNNER.FormalPins(
        version="1.2.3",
        sha256=hashlib.sha256(payload).hexdigest(),
        size=len(payload),
        java_distribution=RUNNER.ADMITTED_JAVA_DISTRIBUTION,
        java_release_tag=RUNNER.ADMITTED_JAVA_RELEASE_TAG,
        java_archive_package=RUNNER.ADMITTED_JAVA_ARCHIVE_PACKAGE,
        java_archive_architecture=RUNNER.ADMITTED_JAVA_ARCHIVE_ARCHITECTURE,
        java_archive_name=RUNNER.ADMITTED_JAVA_ARCHIVE_NAME,
        java_archive_root=RUNNER.ADMITTED_JAVA_ARCHIVE_ROOT,
        java_archive_url=RUNNER.ADMITTED_JAVA_ARCHIVE_URL,
        java_archive_bytes=RUNNER.ADMITTED_JAVA_ARCHIVE_BYTES,
        java_archive_sha256=RUNNER.ADMITTED_JAVA_ARCHIVE_SHA256,
        java_runtime_vendor=RUNNER.ADMITTED_JAVA_RUNTIME_VENDOR,
        java_runtime_version=RUNNER.ADMITTED_JAVA_RUNTIME_VERSION,
        java_specification_version=RUNNER.ADMITTED_JAVA_SPECIFICATION_VERSION,
        java_runtime_architecture=RUNNER.ADMITTED_HOSTED_JAVA_RUNTIME_ARCHITECTURE,
    )
    return pins, payload


def _write(path: Path, payload: bytes, mode: int = 0o600) -> Path:
    path.write_bytes(payload)
    path.chmod(mode)
    return path


class _Headers:
    def __init__(self, values: dict[str, list[str]] | None = None) -> None:
        self._values = {
            key.lower(): list(items) for key, items in (values or {}).items()
        }

    def get_all(self, name: str) -> list[str] | None:
        values = self._values.get(name.lower())
        return None if values is None else list(values)


class _Response:
    def __init__(
        self,
        payload: bytes,
        *,
        status: int = 200,
        url: str = "https://release-assets.githubusercontent.com/asset",
        headers: _Headers | None = None,
        close_error: BaseException | None = None,
    ) -> None:
        self.status = status
        self.headers = headers or _Headers()
        self._payload = payload
        self._offset = 0
        self._url = url
        self._close_error = close_error
        self.closed = False

    def read(self, maximum: int) -> bytes:
        chunk = self._payload[self._offset : self._offset + maximum]
        self._offset += len(chunk)
        return chunk

    def geturl(self) -> str:
        return self._url

    def close(self) -> None:
        self.closed = True
        if self._close_error is not None:
            raise self._close_error


class _Opener:
    def __init__(self, response: _Response) -> None:
        self.response = response
        self.request: urllib.request.Request | None = None
        self.timeout: float | None = None

    def open(
        self,
        request: urllib.request.Request,
        *,
        timeout: float,
    ) -> _Response:
        self.request = request
        self.timeout = timeout
        return self.response


class _BufferedStdout:
    """Minimal text stream with a byte buffer for TLC's raw tee."""

    def __init__(self) -> None:
        self.buffer = io.BytesIO()

    def write(self, value: str) -> int:
        return len(value)

    def flush(self) -> None:
        return None


class RunnerTestCase(unittest.TestCase):
    def assert_formal_error(
        self, code: str, function: object, *args: object, **kwargs: object
    ) -> None:
        with self.assertRaises(RUNNER.FormalRunnerError) as raised:
            function(*args, **kwargs)
        self.assertEqual(raised.exception.code, code)


class PinPolicyTests(RunnerTestCase):
    def _repository(self, root: Path, document: bytes) -> Path:
        tools = root / "tools"
        tools.mkdir()
        _write(tools / "pins.toml", document)
        return root

    @staticmethod
    def _valid_document() -> bytes:
        return (
            "schema_version = 3\n"
            "[formal]\n"
            f'tla_tools_version = "{RUNNER.ADMITTED_TLA_VERSION}"\n'
            f"tla_tools_bytes = {RUNNER.ADMITTED_TLA_BYTES}\n"
            f'tla_tools_sha256 = "{RUNNER.ADMITTED_TLA_SHA256}"\n'
            f'java_distribution = "{RUNNER.ADMITTED_JAVA_DISTRIBUTION}"\n'
            f'java_release_tag = "{RUNNER.ADMITTED_JAVA_RELEASE_TAG}"\n'
            f'java_archive_package = "{RUNNER.ADMITTED_JAVA_ARCHIVE_PACKAGE}"\n'
            "java_archive_architecture = "
            f'"{RUNNER.ADMITTED_JAVA_ARCHIVE_ARCHITECTURE}"\n'
            f'java_archive_name = "{RUNNER.ADMITTED_JAVA_ARCHIVE_NAME}"\n'
            f'java_archive_root = "{RUNNER.ADMITTED_JAVA_ARCHIVE_ROOT}"\n'
            f'java_archive_url = "{RUNNER.ADMITTED_JAVA_ARCHIVE_URL}"\n'
            f"java_archive_bytes = {RUNNER.ADMITTED_JAVA_ARCHIVE_BYTES}\n"
            f'java_archive_sha256 = "{RUNNER.ADMITTED_JAVA_ARCHIVE_SHA256}"\n'
            f'java_runtime_vendor = "{RUNNER.ADMITTED_JAVA_RUNTIME_VENDOR}"\n'
            f'java_runtime_version = "{RUNNER.ADMITTED_JAVA_RUNTIME_VERSION}"\n'
            "java_specification_version = "
            f'"{RUNNER.ADMITTED_JAVA_SPECIFICATION_VERSION}"\n'
            "java_runtime_architecture = "
            f'"{RUNNER.ADMITTED_HOSTED_JAVA_RUNTIME_ARCHITECTURE}"\n'
        ).encode()

    def test_repository_pin_file_is_the_closed_admitted_identity(self) -> None:
        pins = RUNNER.load_pins(ROOT)
        self.assertEqual(
            pins,
            RUNNER.FormalPins(
                version="1.7.4",
                sha256=RUNNER.ADMITTED_TLA_SHA256,
                size=2_274_532,
                java_distribution="temurin",
                java_release_tag="jdk-21.0.11+10",
                java_archive_package="jre",
                java_archive_architecture="x64",
                java_archive_name=(
                    "OpenJDK21U-jre_x64_linux_hotspot_21.0.11_10.tar.gz"
                ),
                java_archive_root="jdk-21.0.11+10-jre",
                java_archive_url=(
                    "https://github.com/adoptium/temurin21-binaries/releases/"
                    "download/jdk-21.0.11%2B10/"
                    "OpenJDK21U-jre_x64_linux_hotspot_21.0.11_10.tar.gz"
                ),
                java_archive_bytes=52_099_793,
                java_archive_sha256=RUNNER.ADMITTED_JAVA_ARCHIVE_SHA256,
                java_runtime_vendor="Eclipse Adoptium",
                java_runtime_version="21.0.11+10-LTS",
                java_specification_version="21",
                java_runtime_architecture="amd64",
            ),
        )
        self.assertEqual(
            RUNNER._asset_url(pins),
            "https://github.com/tlaplus/tlaplus/releases/download/v1.7.4/tla2tools.jar",
        )

    def test_exact_schema_v3_formal_table_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory(prefix="haldir-formal-pins-") as directory:
            repository = self._repository(Path(directory), self._valid_document())
            pins = RUNNER.load_pins(repository)
            self.assertEqual(pins.version, RUNNER.ADMITTED_TLA_VERSION)
            self.assertEqual(pins.size, RUNNER.ADMITTED_TLA_BYTES)
            self.assertEqual(
                pins.java_archive_sha256,
                RUNNER.ADMITTED_JAVA_ARCHIVE_SHA256,
            )

    def test_schema_type_and_value_are_exact(self) -> None:
        mutations = (
            self._valid_document().replace(
                b"schema_version = 3", b"schema_version = true"
            ),
            self._valid_document().replace(
                b"schema_version = 3", b"schema_version = 1"
            ),
            self._valid_document().replace(
                b"schema_version = 3", b"schema_version = 2"
            ),
            self._valid_document().replace(
                b"schema_version = 3", b"schema_version = 4"
            ),
            self._valid_document().replace(b"schema_version = 3\n", b""),
        )
        for index, document in enumerate(mutations):
            with (
                self.subTest(index=index),
                tempfile.TemporaryDirectory(prefix="haldir-formal-pins-") as directory,
            ):
                repository = self._repository(Path(directory), document)
                self.assert_formal_error(
                    "FORMAL_PINS_SCHEMA",
                    RUNNER.load_pins,
                    repository,
                )

    def test_formal_table_rejects_missing_and_unknown_fields(self) -> None:
        valid = self._valid_document()
        fields = (
            b"tla_tools_version",
            b"tla_tools_bytes",
            b"tla_tools_sha256",
            b"java_distribution",
            b"java_release_tag",
            b"java_archive_package",
            b"java_archive_architecture",
            b"java_archive_name",
            b"java_archive_root",
            b"java_archive_url",
            b"java_archive_bytes",
            b"java_archive_sha256",
            b"java_runtime_vendor",
            b"java_runtime_version",
            b"java_specification_version",
            b"java_runtime_architecture",
        )
        self.assertEqual(len(fields), 16)
        mutations = [
            b"\n".join(
                line
                for line in valid.splitlines()
                if not line.startswith(field + b" =")
            )
            + b"\n"
            for field in fields
        ]
        mutations.extend(
            (
                valid.replace(b"[formal]\n", b""),
                b"schema_version = 3\nformal = 7\n",
                valid + b'unknown = "value"\n',
            )
        )
        for index, document in enumerate(mutations):
            with (
                self.subTest(index=index),
                tempfile.TemporaryDirectory(prefix="haldir-formal-pins-") as directory,
            ):
                repository = self._repository(Path(directory), document)
                self.assert_formal_error(
                    "FORMAL_PINS_FIELDS",
                    RUNNER.load_pins,
                    repository,
                )

    def test_formal_values_reject_wrong_types_and_noncanonical_text(self) -> None:
        valid = self._valid_document()
        mutations = (
            valid.replace(b'tla_tools_version = "1.7.4"', b"tla_tools_version = 174"),
            valid.replace(b"tla_tools_bytes = 2274532", b'tla_tools_bytes = "2274532"'),
            valid.replace(b"tla_tools_bytes = 2274532", b"tla_tools_bytes = true"),
            valid.replace(b"tla_tools_bytes = 2274532", b"tla_tools_bytes = 0"),
            valid.replace(
                f'tla_tools_sha256 = "{RUNNER.ADMITTED_TLA_SHA256}"'.encode(),
                b"tla_tools_sha256 = 123",
            ),
            valid.replace(b'"1.7.4"', b'"01.7.4"'),
            valid.replace(
                RUNNER.ADMITTED_TLA_SHA256.encode(),
                RUNNER.ADMITTED_TLA_SHA256.upper().encode(),
            ),
            valid.replace(b'java_distribution = "temurin"', b"java_distribution = 21"),
            valid.replace(
                b'java_release_tag = "jdk-21.0.11+10"',
                b"java_release_tag = 21",
            ),
            valid.replace(b'"jdk-21.0.11+10"', b'"jdk-21.00.11+10"'),
            valid.replace(
                b'java_archive_package = "jre"',
                b"java_archive_package = false",
            ),
            valid.replace(
                b'java_archive_architecture = "x64"',
                b"java_archive_architecture = 64",
            ),
            valid.replace(b"java_archive_name = ", b"java_archive_name = false # "),
            valid.replace(b"java_archive_root = ", b"java_archive_root = 21 # "),
            valid.replace(b"java_archive_url = ", b"java_archive_url = false # "),
            valid.replace(
                b"java_archive_bytes = 52099793",
                b'java_archive_bytes = "52099793"',
            ),
            valid.replace(
                b"java_archive_bytes = 52099793", b"java_archive_bytes = true"
            ),
            valid.replace(b"java_archive_bytes = 52099793", b"java_archive_bytes = 0"),
            valid.replace(
                RUNNER.ADMITTED_JAVA_ARCHIVE_SHA256.encode(),
                RUNNER.ADMITTED_JAVA_ARCHIVE_SHA256.upper().encode(),
            ),
            valid.replace(
                b'java_runtime_vendor = "Eclipse Adoptium"',
                b"java_runtime_vendor = false",
            ),
            valid.replace(
                b'java_runtime_version = "21.0.11+10-LTS"',
                b"java_runtime_version = 21",
            ),
            valid.replace(
                b'java_specification_version = "21"',
                b"java_specification_version = false",
            ),
            valid.replace(
                b'java_specification_version = "21"',
                b'java_specification_version = "021"',
            ),
            valid.replace(
                b'java_runtime_architecture = "amd64"',
                b"java_runtime_architecture = 64",
            ),
        )
        for index, document in enumerate(mutations):
            with (
                self.subTest(index=index),
                tempfile.TemporaryDirectory(prefix="haldir-formal-pins-") as directory,
            ):
                repository = self._repository(Path(directory), document)
                self.assert_formal_error(
                    "FORMAL_PINS_TYPES",
                    RUNNER.load_pins,
                    repository,
                )

    def test_well_formed_but_unadmitted_identities_are_rejected(self) -> None:
        valid = self._valid_document()
        mutations = (
            valid.replace(b'"1.7.4"', b'"1.7.5"'),
            valid.replace(b"tla_tools_bytes = 2274532", b"tla_tools_bytes = 2274533"),
            valid.replace(
                RUNNER.ADMITTED_TLA_SHA256.encode(),
                b"0" * 64,
            ),
            valid.replace(b'"temurin"', b'"zulu"'),
            valid.replace(
                b'java_release_tag = "jdk-21.0.11+10"',
                b'java_release_tag = "jdk-21.0.11+11"',
            ),
            valid.replace(
                b'java_archive_package = "jre"',
                b'java_archive_package = "jdk"',
            ),
            valid.replace(
                b'java_archive_architecture = "x64"',
                b'java_archive_architecture = "aarch64"',
            ),
            valid.replace(
                b"java_archive_name = "
                b'"OpenJDK21U-jre_x64_linux_hotspot_21.0.11_10.tar.gz"',
                b"java_archive_name = "
                b'"OpenJDK21U-jre_x64_linux_hotspot_21.0.11_11.tar.gz"',
            ),
            valid.replace(
                b'java_archive_root = "jdk-21.0.11+10-jre"',
                b'java_archive_root = "jdk-21.0.11+11-jre"',
            ),
            valid.replace(
                b"jdk-21.0.11%2B10/OpenJDK21U",
                b"jdk-21.0.11%2B11/OpenJDK21U",
            ),
            valid.replace(
                b"java_archive_bytes = 52099793", b"java_archive_bytes = 52099794"
            ),
            valid.replace(
                RUNNER.ADMITTED_JAVA_ARCHIVE_SHA256.encode(),
                b"0" * 64,
            ),
            valid.replace(b'"Eclipse Adoptium"', b'"Other Vendor"'),
            valid.replace(b'"21.0.11+10-LTS"', b'"21.0.11+11-LTS"'),
            valid.replace(
                b'java_specification_version = "21"',
                b'java_specification_version = "22"',
            ),
            valid.replace(
                b'java_runtime_architecture = "amd64"',
                b'java_runtime_architecture = "x86_64"',
            ),
        )
        for index, document in enumerate(mutations):
            with (
                self.subTest(index=index),
                tempfile.TemporaryDirectory(prefix="haldir-formal-pins-") as directory,
            ):
                repository = self._repository(Path(directory), document)
                self.assert_formal_error(
                    "FORMAL_PINS_UNADMITTED",
                    RUNNER.load_pins,
                    repository,
                )

    def test_asset_size_pin_cannot_exceed_the_download_hard_cap(self) -> None:
        document = self._valid_document().replace(
            b"tla_tools_bytes = 2274532",
            f"tla_tools_bytes = {RUNNER.TLA_ASSET_HARD_CAP + 1}".encode(),
        )
        with tempfile.TemporaryDirectory(prefix="haldir-formal-pins-") as directory:
            repository = self._repository(Path(directory), document)
            self.assert_formal_error(
                "FORMAL_PINS_TYPES",
                RUNNER.load_pins,
                repository,
            )

    def test_nul_and_oversized_pin_files_are_rejected(self) -> None:
        cases = (
            (self._valid_document() + b"\0", "FORMAL_PINS_NUL"),
            (b"x" * (RUNNER.PINS_FILE_CAP + 1), "FORMAL_FILE_TYPE:pins.toml"),
        )
        for payload, code in cases:
            with tempfile.TemporaryDirectory(prefix="haldir-formal-pins-") as directory:
                repository = self._repository(Path(directory), payload)
                self.assert_formal_error(code, RUNNER.load_pins, repository)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks unavailable")
    def test_symlink_pin_file_is_not_followed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="haldir-formal-pins-") as directory:
            root = Path(directory)
            tools = root / "tools"
            tools.mkdir()
            target = _write(root / "real-pins.toml", self._valid_document())
            (tools / "pins.toml").symlink_to(target)
            self.assert_formal_error(
                "FORMAL_FILE_OPEN:pins.toml",
                RUNNER.load_pins,
                root,
            )

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFOs unavailable")
    def test_fifo_pin_file_fails_without_blocking(self) -> None:
        with tempfile.TemporaryDirectory(prefix="haldir-formal-pins-") as directory:
            root = Path(directory)
            tools = root / "tools"
            tools.mkdir()
            os.mkfifo(tools / "pins.toml", 0o600)
            started = time.monotonic()
            self.assert_formal_error(
                "FORMAL_FILE_TYPE:pins.toml",
                RUNNER.load_pins,
                root,
            )
            self.assertLess(time.monotonic() - started, 1.0)


class OutputPathAndLockTests(RunnerTestCase):
    def test_output_paths_are_direct_children_and_collision_free(self) -> None:
        pins, payload = _tiny_pins()
        with tempfile.TemporaryDirectory(prefix="haldir-formal-output-") as directory:
            base = Path(directory)
            formal_root = base / "formal"
            formal_root.mkdir(mode=0o700)
            asset = _write(
                formal_root / RUNNER._asset_name(pins),
                payload,
            )
            log, runtime, lock = RUNNER._resolve_log_path(
                None,
                formal_root=formal_root,
            )
            self.assertEqual(log, formal_root.resolve() / "tlc.log")
            self.assertEqual(
                runtime,
                formal_root.resolve() / "formal-runtime.json",
            )
            self.assertEqual(
                lock,
                formal_root.resolve() / ".formal-runner.lock",
            )
            invalid = (
                base / "outside.log",
                formal_root / "nested" / "tlc.log",
                runtime,
                lock,
                asset,
            )
            for candidate in invalid:
                with self.subTest(candidate=candidate):
                    self.assert_formal_error(
                        "FORMAL_OUTPUT_PATH",
                        RUNNER._resolve_log_path,
                        candidate,
                        formal_root=formal_root,
                        asset=asset,
                    )

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks unavailable")
    def test_output_path_rejects_symlink_and_unsafe_existing_file(self) -> None:
        with tempfile.TemporaryDirectory(prefix="haldir-formal-output-") as directory:
            root = Path(directory)
            formal_root = root / "formal"
            formal_root.mkdir(mode=0o700)
            outside = _write(root / "outside.log", b"outside")
            link = formal_root / "tlc.log"
            link.symlink_to(outside)
            self.assert_formal_error(
                "FORMAL_OUTPUT_PATH",
                RUNNER._resolve_log_path,
                link,
                formal_root=formal_root,
            )
            link.unlink()
            _write(link, b"old", 0o622)
            self.assert_formal_error(
                "FORMAL_OUTPUT_PATH",
                RUNNER._resolve_log_path,
                link,
                formal_root=formal_root,
            )

    def test_run_lock_is_exclusive_and_reacquirable_after_release(self) -> None:
        with tempfile.TemporaryDirectory(prefix="haldir-formal-lock-") as directory:
            lock = Path(directory) / ".formal-runner.lock"
            first = RUNNER._acquire_run_lock(lock)
            try:
                self.assert_formal_error(
                    "FORMAL_RUN_BUSY",
                    RUNNER._acquire_run_lock,
                    lock,
                )
                self.assertFalse(stat.S_IMODE(lock.stat().st_mode) & 0o022)
            finally:
                RUNNER._release_run_lock(first)
            second = RUNNER._acquire_run_lock(lock)
            RUNNER._release_run_lock(second)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks unavailable")
    def test_run_lock_does_not_follow_symlinks(self) -> None:
        with tempfile.TemporaryDirectory(prefix="haldir-formal-lock-") as directory:
            root = Path(directory)
            target = _write(root / "target", b"sentinel")
            lock = root / "lock"
            lock.symlink_to(target)
            self.assert_formal_error(
                "FORMAL_RUN_LOCK",
                RUNNER._acquire_run_lock,
                lock,
            )
            self.assertEqual(target.read_bytes(), b"sentinel")


class CacheTests(RunnerTestCase):
    def test_exact_cache_entry_is_accepted(self) -> None:
        pins, payload = _tiny_pins()
        with tempfile.TemporaryDirectory(prefix="haldir-formal-cache-") as directory:
            path = _write(Path(directory) / RUNNER._asset_name(pins), payload)
            self.assertEqual(RUNNER.validate_cached_asset(path, pins), path)

    def test_missing_corrupt_and_writable_cache_entries_are_rejected(self) -> None:
        pins, payload = _tiny_pins()
        with tempfile.TemporaryDirectory(prefix="haldir-formal-cache-") as directory:
            root = Path(directory)
            self.assert_formal_error(
                "FORMAL_ASSET_OPEN",
                RUNNER.validate_cached_asset,
                root / "missing",
                pins,
            )
            corrupt = _write(root / "corrupt", b"x" * len(payload))
            self.assert_formal_error(
                "FORMAL_ASSET_DIGEST",
                RUNNER.validate_cached_asset,
                corrupt,
                pins,
            )
            corrupt.chmod(0o622)
            self.assert_formal_error(
                "FORMAL_ASSET_TYPE",
                RUNNER.validate_cached_asset,
                corrupt,
                pins,
            )

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks unavailable")
    def test_symlink_cache_entry_is_not_followed(self) -> None:
        pins, payload = _tiny_pins()
        with tempfile.TemporaryDirectory(prefix="haldir-formal-cache-") as directory:
            root = Path(directory)
            target = _write(root / "target", payload)
            link = root / "cache-link"
            link.symlink_to(target)
            self.assert_formal_error(
                "FORMAL_ASSET_OPEN",
                RUNNER.validate_cached_asset,
                link,
                pins,
            )

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFOs unavailable")
    def test_fifo_cache_entry_fails_without_blocking(self) -> None:
        pins, _payload = _tiny_pins()
        with tempfile.TemporaryDirectory(prefix="haldir-formal-cache-") as directory:
            fifo = Path(directory) / "cache-fifo"
            os.mkfifo(fifo, 0o600)
            started = time.monotonic()
            self.assert_formal_error(
                "FORMAL_ASSET_TYPE",
                RUNNER.validate_cached_asset,
                fifo,
                pins,
            )
            self.assertLess(time.monotonic() - started, 1.0)

    def test_valid_cache_hit_never_calls_download(self) -> None:
        pins, payload = _tiny_pins()
        with tempfile.TemporaryDirectory(prefix="haldir-formal-cache-") as directory:
            cache = Path(directory)
            expected = _write(cache / RUNNER._asset_name(pins), payload)
            with mock.patch.object(
                RUNNER,
                "_download_to_descriptor",
                side_effect=AssertionError("network path called"),
            ):
                observed = RUNNER.ensure_asset(cache, pins=pins, offline=False)
            self.assertEqual(observed, expected)

    def test_offline_mode_rejects_missing_and_corrupt_cache(self) -> None:
        pins, payload = _tiny_pins()
        with tempfile.TemporaryDirectory(prefix="haldir-formal-cache-") as directory:
            cache = Path(directory)
            with mock.patch.object(
                RUNNER,
                "_download_to_descriptor",
                side_effect=AssertionError(
                    "offline mode attempted network acquisition"
                ),
            ):
                self.assert_formal_error(
                    "FORMAL_OFFLINE_CACHE",
                    RUNNER.ensure_asset,
                    cache,
                    pins=pins,
                    offline=True,
                )
            _write(cache / RUNNER._asset_name(pins), b"x" * len(payload))
            with mock.patch.object(
                RUNNER,
                "_download_to_descriptor",
                side_effect=AssertionError(
                    "offline mode attempted network acquisition"
                ),
            ):
                self.assert_formal_error(
                    "FORMAL_OFFLINE_CACHE",
                    RUNNER.ensure_asset,
                    cache,
                    pins=pins,
                    offline=True,
                )

    def test_verified_download_atomically_replaces_corrupt_regular_cache(self) -> None:
        pins, payload = _tiny_pins()
        with tempfile.TemporaryDirectory(prefix="haldir-formal-cache-") as directory:
            cache = Path(directory)
            destination = _write(
                cache / RUNNER._asset_name(pins),
                b"x" * len(payload),
            )

            def download(descriptor: int, **_kwargs: object) -> None:
                RUNNER._write_all(descriptor, payload)
                os.fsync(descriptor)

            with (
                mock.patch.object(RUNNER, "_download_to_descriptor", download),
                mock.patch.object(RUNNER, "DOWNLOAD_ATTEMPTS", 1),
            ):
                observed = RUNNER.ensure_asset(cache, pins=pins, offline=False)
            self.assertEqual(observed, destination)
            self.assertEqual(destination.read_bytes(), payload)
            self.assertFalse(
                any(path.name.startswith(".tla2tools.") for path in cache.iterdir())
            )

    def test_failed_download_preserves_existing_cache_and_cleans_temp(self) -> None:
        pins, payload = _tiny_pins()
        old = b"x" * len(payload)
        with tempfile.TemporaryDirectory(prefix="haldir-formal-cache-") as directory:
            cache = Path(directory)
            destination = _write(cache / RUNNER._asset_name(pins), old)
            with (
                mock.patch.object(
                    RUNNER,
                    "_download_to_descriptor",
                    side_effect=RUNNER.FormalRunnerError("FORMAL_DOWNLOAD_READ"),
                ),
                mock.patch.object(RUNNER, "DOWNLOAD_ATTEMPTS", 1),
            ):
                self.assert_formal_error(
                    "FORMAL_DOWNLOAD_READ",
                    RUNNER.ensure_asset,
                    cache,
                    pins=pins,
                    offline=False,
                )
            self.assertEqual(destination.read_bytes(), old)
            self.assertEqual(
                sorted(path.name for path in cache.iterdir()), [destination.name]
            )

    def test_partial_download_failure_preserves_cache_and_cleans_temp(self) -> None:
        pins, payload = _tiny_pins()
        old = b"x" * len(payload)
        with tempfile.TemporaryDirectory(prefix="haldir-formal-cache-") as directory:
            cache = Path(directory)
            destination = _write(cache / RUNNER._asset_name(pins), old)

            def partial(descriptor: int, **_kwargs: object) -> None:
                RUNNER._write_all(descriptor, payload[:3])
                raise RUNNER.FormalRunnerError("FORMAL_DOWNLOAD_TRUNCATED")

            with (
                mock.patch.object(RUNNER, "_download_to_descriptor", partial),
                mock.patch.object(RUNNER, "DOWNLOAD_ATTEMPTS", 1),
            ):
                self.assert_formal_error(
                    "FORMAL_DOWNLOAD_TRUNCATED",
                    RUNNER.ensure_asset,
                    cache,
                    pins=pins,
                    offline=False,
                )
            self.assertEqual(destination.read_bytes(), old)
            self.assertEqual(
                sorted(path.name for path in cache.iterdir()), [destination.name]
            )

    def test_directory_fsync_failure_is_not_retried_or_laundered(self) -> None:
        pins, payload = _tiny_pins()
        calls = 0
        with tempfile.TemporaryDirectory(prefix="haldir-formal-cache-") as directory:
            cache = Path(directory)

            def download(descriptor: int, **_kwargs: object) -> None:
                nonlocal calls
                calls += 1
                RUNNER._write_all(descriptor, payload)
                os.fsync(descriptor)

            with (
                mock.patch.object(RUNNER, "_download_to_descriptor", download),
                mock.patch.object(
                    RUNNER,
                    "_fsync_directory",
                    side_effect=RUNNER.FormalRunnerError("FORMAL_DIRECTORY_FSYNC"),
                ),
            ):
                self.assert_formal_error(
                    "FORMAL_DIRECTORY_FSYNC",
                    RUNNER.ensure_asset,
                    cache,
                    pins=pins,
                    offline=False,
                )
            self.assertEqual(calls, 1)

    def test_concurrent_publishers_converge_on_one_verified_entry(self) -> None:
        pins, payload = _tiny_pins()
        barrier = threading.Barrier(2)
        results: list[Path] = []
        errors: list[BaseException] = []
        with tempfile.TemporaryDirectory(prefix="haldir-formal-cache-") as directory:
            cache = Path(directory)

            def download(descriptor: int, **_kwargs: object) -> None:
                barrier.wait(timeout=2)
                RUNNER._write_all(descriptor, payload)
                os.fsync(descriptor)

            def worker() -> None:
                try:
                    results.append(RUNNER.ensure_asset(cache, pins=pins, offline=False))
                except BaseException as error:  # collected and asserted below
                    errors.append(error)

            with (
                mock.patch.object(RUNNER, "_download_to_descriptor", download),
                mock.patch.object(RUNNER, "DOWNLOAD_ATTEMPTS", 1),
            ):
                threads = [threading.Thread(target=worker) for _index in range(2)]
                for thread in threads:
                    thread.start()
                for thread in threads:
                    thread.join(timeout=3)
            self.assertFalse(any(thread.is_alive() for thread in threads))
            self.assertEqual(errors, [])
            self.assertEqual(len(results), 2)
            self.assertEqual(results[0], results[1])
            self.assertEqual(results[0].read_bytes(), payload)
            RUNNER.validate_cached_asset(results[0], pins)
            self.assertFalse(
                any(path.name.startswith(".tla2tools.") for path in cache.iterdir())
            )

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks unavailable")
    def test_online_replacement_never_writes_through_cache_symlink(self) -> None:
        pins, payload = _tiny_pins()
        with tempfile.TemporaryDirectory(prefix="haldir-formal-cache-") as directory:
            cache = Path(directory)
            victim = _write(cache / "victim", b"do-not-touch")
            destination = cache / RUNNER._asset_name(pins)
            destination.symlink_to(victim)

            def download(descriptor: int, **_kwargs: object) -> None:
                RUNNER._write_all(descriptor, payload)
                os.fsync(descriptor)

            with (
                mock.patch.object(RUNNER, "_download_to_descriptor", download),
                mock.patch.object(RUNNER, "DOWNLOAD_ATTEMPTS", 1),
            ):
                observed = RUNNER.ensure_asset(cache, pins=pins, offline=False)
            self.assertEqual(observed, destination)
            self.assertFalse(destination.is_symlink())
            self.assertEqual(destination.read_bytes(), payload)
            self.assertEqual(victim.read_bytes(), b"do-not-touch")


class DownloadTests(RunnerTestCase):
    def _download(
        self,
        response: _Response,
        *,
        pins: object,
    ) -> tuple[bytes, _Opener]:
        opener = _Opener(response)
        with tempfile.TemporaryDirectory(prefix="haldir-formal-download-") as directory:
            output = Path(directory) / "asset"
            descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                with mock.patch.object(
                    RUNNER.urllib.request,
                    "build_opener",
                    return_value=opener,
                ):
                    RUNNER._download_to_descriptor(
                        descriptor,
                        pins=pins,
                        deadline=time.monotonic() + 5.0,
                    )
            finally:
                os.close(descriptor)
            return output.read_bytes(), opener

    def test_exact_download_uses_identity_encoding_and_pinned_url(self) -> None:
        pins, payload = _tiny_pins()
        response = _Response(
            payload,
            headers=_Headers(
                {
                    "Content-Length": [str(len(payload))],
                    "Content-Encoding": ["identity"],
                }
            ),
        )
        observed, opener = self._download(response, pins=pins)
        self.assertEqual(observed, payload)
        self.assertTrue(response.closed)
        self.assertIsNotNone(opener.request)
        assert opener.request is not None
        self.assertEqual(opener.request.full_url, RUNNER._asset_url(pins))
        self.assertEqual(opener.request.get_header("Accept-encoding"), "identity")
        self.assertGreater(opener.timeout or 0.0, 0.0)
        self.assertLessEqual(
            opener.timeout or 0.0,
            RUNNER.DOWNLOAD_SOCKET_TIMEOUT_SECONDS,
        )

    def test_missing_content_length_is_safe_because_stream_size_is_exact(self) -> None:
        pins, payload = _tiny_pins()
        observed, _opener = self._download(_Response(payload), pins=pins)
        self.assertEqual(observed, payload)

    def test_length_header_is_single_canonical_and_exact(self) -> None:
        pins, payload = _tiny_pins()
        invalid = (
            (["0" + str(len(payload))], "FORMAL_DOWNLOAD_LENGTH"),
            ([str(len(payload) + 1)], "FORMAL_DOWNLOAD_LENGTH"),
            (["not-a-number"], "FORMAL_DOWNLOAD_LENGTH"),
            ([str(len(payload)), str(len(payload))], "FORMAL_DOWNLOAD_HEADERS"),
            (["9" * 21], "FORMAL_DOWNLOAD_LENGTH"),
        )
        for headers, expected_code in invalid:
            with self.subTest(headers=headers):
                response = _Response(
                    payload,
                    headers=_Headers({"Content-Length": headers}),
                )
                with self.assertRaises(RUNNER.FormalRunnerError) as raised:
                    self._download(response, pins=pins)
                self.assertEqual(raised.exception.code, expected_code)

    def test_truncation_growth_and_digest_mismatch_fail_closed(self) -> None:
        pins, payload = _tiny_pins()
        cases = (
            (_Response(payload[:-1]), "FORMAL_DOWNLOAD_TRUNCATED"),
            (_Response(payload + b"x"), "FORMAL_DOWNLOAD_GROWTH"),
            (_Response(b"x" * len(payload)), "FORMAL_DOWNLOAD_DIGEST"),
        )
        for response, code in cases:
            with (
                self.subTest(code=code),
                self.assertRaises(RUNNER.FormalRunnerError) as raised,
            ):
                self._download(response, pins=pins)
            self.assertEqual(raised.exception.code, code)
            self.assertTrue(response.closed)

    def test_status_encoding_and_final_url_are_enforced(self) -> None:
        pins, payload = _tiny_pins()
        cases = (
            (_Response(payload, status=206), "FORMAL_DOWNLOAD_STATUS"),
            (
                _Response(
                    payload,
                    headers=_Headers({"Content-Encoding": ["gzip"]}),
                ),
                "FORMAL_DOWNLOAD_ENCODING",
            ),
            (
                _Response(payload, url="http://release-assets.githubusercontent.com/x"),
                "FORMAL_DOWNLOAD_URL",
            ),
        )
        for response, code in cases:
            with (
                self.subTest(code=code),
                self.assertRaises(RUNNER.FormalRunnerError) as raised,
            ):
                self._download(response, pins=pins)
            self.assertEqual(raised.exception.code, code)

    def test_header_object_must_support_unambiguous_get_all(self) -> None:
        pins, payload = _tiny_pins()
        response = _Response(payload)
        response.headers = {"Content-Length": str(len(payload))}
        with self.assertRaises(RUNNER.FormalRunnerError) as raised:
            self._download(response, pins=pins)
        self.assertEqual(raised.exception.code, "FORMAL_DOWNLOAD_HEADERS")

    def test_canonical_initial_and_https_redirect_urls(self) -> None:
        pins, _payload = _tiny_pins()
        RUNNER._validate_download_url(
            RUNNER._asset_url(pins),
            initial=True,
            pins=pins,
        )
        RUNNER._validate_download_url(
            "https://release-assets.githubusercontent.com/asset?token=opaque",
            initial=False,
            pins=pins,
        )

    def test_url_policy_rejects_downgrade_authority_and_path_confusion(self) -> None:
        pins, _payload = _tiny_pins()
        invalid = (
            (
                "http://github.com/tlaplus/tlaplus/releases/download/v1.2.3/tla2tools.jar",
                True,
            ),
            (
                "https://user@github.com/tlaplus/tlaplus/releases/download/v1.2.3/tla2tools.jar",
                True,
            ),
            (
                "https://github.com:444/tlaplus/tlaplus/releases/download/v1.2.3/tla2tools.jar",
                True,
            ),
            ("https://example.com/asset", False),
            ("https://release-assets.githubusercontent.com/asset#fragment", False),
            (
                "https://github.com/tlaplus/tlaplus/releases/latest/download/tla2tools.jar",
                True,
            ),
            (
                "https://github.com/tlaplus/tlaplus/releases/download/v1.2.3/tla2tools.jar?q=1",
                True,
            ),
        )
        for url, initial in invalid:
            with self.subTest(url=url):
                self.assert_formal_error(
                    "FORMAL_DOWNLOAD_URL",
                    RUNNER._validate_download_url,
                    url,
                    initial=initial,
                    pins=pins,
                )

    def test_redirect_handler_has_a_strict_hop_limit(self) -> None:
        pins, _payload = _tiny_pins()
        handler = RUNNER._StrictRedirectHandler(pins)
        request = urllib.request.Request(RUNNER._asset_url(pins))
        headers = email.message.Message()
        target = "https://release-assets.githubusercontent.com/asset"
        for _index in range(RUNNER.MAX_REDIRECTS):
            redirected = handler.redirect_request(
                request,
                None,
                302,
                "Found",
                headers,
                target,
            )
            self.assertIsNotNone(redirected)
        self.assert_formal_error(
            "FORMAL_DOWNLOAD_REDIRECTS",
            handler.redirect_request,
            request,
            None,
            302,
            "Found",
            headers,
            target,
        )

    def test_tls_context_requires_at_least_tls_1_2(self) -> None:
        context = RUNNER._ssl_context()
        self.assertGreaterEqual(
            context.minimum_version,
            ssl.TLSVersion.TLSv1_2,
        )
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(context.check_hostname)

    def test_opener_contains_https_and_strict_redirect_handlers(self) -> None:
        pins, payload = _tiny_pins()
        response = _Response(payload)
        opener = _Opener(response)
        observed_handlers: tuple[object, ...] = ()

        def build_opener(*handlers: object) -> _Opener:
            nonlocal observed_handlers
            observed_handlers = handlers
            return opener

        with tempfile.TemporaryDirectory(prefix="haldir-formal-download-") as directory:
            output = Path(directory) / "asset"
            descriptor = os.open(
                output,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
            try:
                with mock.patch.object(
                    RUNNER.urllib.request,
                    "build_opener",
                    build_opener,
                ):
                    RUNNER._download_to_descriptor(
                        descriptor,
                        pins=pins,
                        deadline=time.monotonic() + 5,
                    )
            finally:
                os.close(descriptor)
        self.assertEqual(len(observed_handlers), 2)
        self.assertIsInstance(
            observed_handlers[0],
            urllib.request.HTTPSHandler,
        )
        self.assertIsInstance(
            observed_handlers[1],
            RUNNER._StrictRedirectHandler,
        )

    def test_open_geturl_read_and_close_failures_are_normalized(self) -> None:
        pins, payload = _tiny_pins()

        class BrokenOpener:
            def open(self, *_args: object, **_kwargs: object) -> object:
                raise urllib.error.URLError("offline fake")

        with tempfile.TemporaryDirectory(prefix="haldir-formal-download-") as directory:
            output = Path(directory) / "asset"
            descriptor = os.open(
                output,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
            try:
                with mock.patch.object(
                    RUNNER.urllib.request,
                    "build_opener",
                    return_value=BrokenOpener(),
                ):
                    self.assert_formal_error(
                        "FORMAL_DOWNLOAD_OPEN",
                        RUNNER._download_to_descriptor,
                        descriptor,
                        pins=pins,
                        deadline=time.monotonic() + 5,
                    )
            finally:
                os.close(descriptor)

        class BadUrl(_Response):
            def geturl(self) -> str:
                raise ValueError("bad redirect URL")

        class BadRead(_Response):
            def read(self, maximum: int) -> bytes:
                raise http.client.IncompleteRead(b"partial", maximum)

        cases = (
            (BadUrl(payload), "FORMAL_DOWNLOAD_URL"),
            (BadRead(payload), "FORMAL_DOWNLOAD_READ"),
            (
                _Response(
                    payload,
                    close_error=http.client.IncompleteRead(b"", 1),
                ),
                "FORMAL_DOWNLOAD_CLOSE",
            ),
        )
        for response, code in cases:
            with (
                self.subTest(code=code),
                self.assertRaises(RUNNER.FormalRunnerError) as raised,
            ):
                self._download(response, pins=pins)
            self.assertEqual(raised.exception.code, code)

    def test_non_bytes_body_and_expired_deadlines_fail_closed(self) -> None:
        pins, payload = _tiny_pins()

        class TextResponse(_Response):
            def read(self, maximum: int) -> object:
                del maximum
                return "not bytes"

        with self.assertRaises(RUNNER.FormalRunnerError) as raised:
            self._download(TextResponse(payload), pins=pins)
        self.assertEqual(raised.exception.code, "FORMAL_DOWNLOAD_READ")

        with tempfile.TemporaryDirectory(prefix="haldir-formal-download-") as directory:
            output = Path(directory) / "asset"
            descriptor = os.open(
                output,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
            try:
                with mock.patch.object(
                    RUNNER.urllib.request,
                    "build_opener",
                    side_effect=AssertionError("expired request opened a socket"),
                ):
                    self.assert_formal_error(
                        "FORMAL_DOWNLOAD_TIMEOUT",
                        RUNNER._download_to_descriptor,
                        descriptor,
                        pins=pins,
                        deadline=time.monotonic() - 1,
                    )
            finally:
                os.close(descriptor)

    def test_midstream_deadline_is_enforced(self) -> None:
        pins, payload = _tiny_pins(b"0123456789")

        class SlowResponse(_Response):
            def read(self, maximum: int) -> bytes:
                chunk = super().read(min(maximum, 1))
                time.sleep(0.02)
                return chunk

        response = SlowResponse(payload)
        opener = _Opener(response)
        with tempfile.TemporaryDirectory(prefix="haldir-formal-download-") as directory:
            output = Path(directory) / "asset"
            descriptor = os.open(
                output,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
            try:
                with mock.patch.object(
                    RUNNER.urllib.request,
                    "build_opener",
                    return_value=opener,
                ):
                    self.assert_formal_error(
                        "FORMAL_DOWNLOAD_TIMEOUT",
                        RUNNER._download_to_descriptor,
                        descriptor,
                        pins=pins,
                        deadline=time.monotonic() + 0.005,
                    )
            finally:
                os.close(descriptor)
        self.assertTrue(response.closed)


class JavaTests(RunnerTestCase):
    @staticmethod
    def _java_output(
        specification: str = "21",
        *,
        vendor: str = "Eclipse Adoptium",
        runtime_version: str = "21.0.11+10-LTS",
        architecture: str = "amd64",
    ) -> bytes:
        return (
            b"Property settings:\n"
            + f"    java.specification.version = {specification}\n".encode()
            + f"    java.vendor = {vendor}\n".encode()
            + f"    java.runtime.version = {runtime_version}\n".encode()
            + b"    java.vm.name = Test VM\n"
            + f"    os.arch = {architecture}\n".encode()
        )

    def _java_file(self, root: Path) -> Path:
        return _write(root / "java", b"#!/bin/sh\nexit 0\n", 0o700)

    def test_child_environment_is_allowlisted_and_drops_injection_variables(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(prefix="haldir-formal-java-") as directory:
            root = Path(directory)
            java = self._java_file(root)
            with mock.patch.dict(
                os.environ,
                {
                    "JAVA_TOOL_OPTIONS": "-javaagent:evil",
                    "JDK_JAVA_OPTIONS": "-XX:evil",
                    "_JAVA_OPTIONS": "-Dwrong=true",
                    "CLASSPATH": "wrong",
                    "TLA_LIBRARY": "wrong",
                },
                clear=False,
            ):
                environment = RUNNER._child_environment(root / "private", java)
            self.assertEqual(
                set(environment),
                {"HOME", "LANG", "LC_ALL", "PATH", "TMPDIR", "TZ"},
            )
            self.assertEqual(environment["LANG"], "C")
            self.assertEqual(environment["LC_ALL"], "C")
            self.assertEqual(environment["TZ"], "UTC")

    def test_validate_java_requires_the_exact_pinned_runtime_identity(self) -> None:
        pins, _payload = _tiny_pins()
        with tempfile.TemporaryDirectory(prefix="haldir-formal-java-") as directory:
            root = Path(directory)
            java = self._java_file(root)
            observed: dict[str, object] = {}

            def run(command: tuple[str, ...], **kwargs: object) -> object:
                observed["command"] = command
                observed["kwargs"] = kwargs
                output = self._java_output()
                return RUNNER.ProcessResult(0, output, len(output), "EXITED")

            with mock.patch.object(RUNNER, "_run_bounded", run):
                identity, environment = RUNNER.validate_java(
                    str(java),
                    pins=pins,
                    private_root=root / "private",
                )
            self.assertEqual(
                observed["command"],
                (str(java.resolve()), "-XshowSettings:properties", "-version"),
            )
            self.assertEqual(identity.specification_version, "21")
            self.assertEqual(identity.vendor, "Eclipse Adoptium")
            self.assertEqual(identity.runtime_version, "21.0.11+10-LTS")
            self.assertEqual(identity.vm_name, "Test VM")
            self.assertEqual(identity.architecture, "amd64")
            self.assertEqual(identity.executable_bytes, java.stat().st_size)
            self.assertEqual(
                environment["PATH"].split(":")[0],
                str(java.resolve().parent),
            )
            kwargs = observed["kwargs"]
            assert isinstance(kwargs, dict)
            self.assertEqual(kwargs["timeout_seconds"], RUNNER.JAVA_TIMEOUT_SECONDS)
            self.assertEqual(kwargs["output_limit"], RUNNER.JAVA_OUTPUT_CAP)
            self.assertTrue(kwargs["capture"])

    def test_local_runtime_architectures_are_admitted_and_measured_separately(
        self,
    ) -> None:
        self.assertEqual(
            RUNNER.ADMITTED_LOCAL_JAVA_RUNTIME_ARCHITECTURES,
            frozenset({"aarch64", "amd64", "x86_64"}),
        )
        self.assertEqual(RUNNER.ADMITTED_HOSTED_JAVA_RUNTIME_ARCHITECTURE, "amd64")
        self.assertIn(
            RUNNER.ADMITTED_HOSTED_JAVA_RUNTIME_ARCHITECTURE,
            RUNNER.ADMITTED_LOCAL_JAVA_RUNTIME_ARCHITECTURES,
        )
        pins, _payload = _tiny_pins()
        with tempfile.TemporaryDirectory(prefix="haldir-formal-java-") as directory:
            root = Path(directory)
            java = self._java_file(root)
            for architecture in ("aarch64", "x86_64"):
                output = self._java_output(architecture=architecture)
                result = RUNNER.ProcessResult(0, output, len(output), "EXITED")
                with (
                    self.subTest(architecture=architecture),
                    mock.patch.object(RUNNER, "_run_bounded", return_value=result),
                ):
                    identity, _environment = RUNNER.validate_java(
                        str(java),
                        pins=pins,
                        private_root=root / "private",
                    )
                    self.assertEqual(identity.architecture, architecture)

    def test_wrong_or_duplicate_java_specification_is_rejected(self) -> None:
        pins, _payload = _tiny_pins()
        outputs = (
            self._java_output("17"),
            self._java_output("22"),
            self._java_output() + b"java.specification.version = 21\n",
            b"openjdk version test\n",
        )
        with tempfile.TemporaryDirectory(prefix="haldir-formal-java-") as directory:
            root = Path(directory)
            java = self._java_file(root)
            for output in outputs:
                with self.subTest(output=output):
                    result = RUNNER.ProcessResult(0, output, len(output), "EXITED")
                    with mock.patch.object(RUNNER, "_run_bounded", return_value=result):
                        self.assert_formal_error(
                            "FORMAL_JAVA_VERSION",
                            RUNNER.validate_java,
                            str(java),
                            pins=pins,
                            private_root=root / "private",
                        )

    def test_wrong_java_runtime_identity_is_rejected(self) -> None:
        pins, _payload = _tiny_pins()
        outputs = (
            self._java_output(vendor="Not Adoptium"),
            self._java_output(runtime_version="21.0.11+11-LTS"),
            self._java_output(runtime_version="21.0.11+10"),
            self._java_output(architecture="sparcv9"),
        )
        with tempfile.TemporaryDirectory(prefix="haldir-formal-java-") as directory:
            root = Path(directory)
            java = self._java_file(root)
            for output in outputs:
                with (
                    self.subTest(output=output),
                    mock.patch.object(
                        RUNNER,
                        "_run_bounded",
                        return_value=RUNNER.ProcessResult(
                            0,
                            output,
                            len(output),
                            "EXITED",
                        ),
                    ),
                ):
                    self.assert_formal_error(
                        "FORMAL_JAVA_IDENTITY",
                        RUNNER.validate_java,
                        str(java),
                        pins=pins,
                        private_root=root / "private",
                    )

    def test_missing_and_duplicate_required_java_identity_properties_are_rejected(
        self,
    ) -> None:
        pins, _payload = _tiny_pins()
        complete = self._java_output()
        cases = (
            (
                complete.replace(b"    java.vendor = Eclipse Adoptium\n", b""),
                "FORMAL_JAVA_PROPERTY:java.vendor",
            ),
            (
                complete.replace(b"    java.runtime.version = 21.0.11+10-LTS\n", b""),
                "FORMAL_JAVA_PROPERTY:java.runtime.version",
            ),
            (
                complete.replace(b"    os.arch = amd64\n", b""),
                "FORMAL_JAVA_PROPERTY:os.arch",
            ),
            (
                complete + b"java.vendor = Eclipse Adoptium\n",
                "FORMAL_JAVA_PROPERTY:java.vendor",
            ),
            (
                complete + b"java.runtime.version = 21.0.11+10-LTS\n",
                "FORMAL_JAVA_PROPERTY:java.runtime.version",
            ),
            (
                complete + b"os.arch = amd64\n",
                "FORMAL_JAVA_PROPERTY:os.arch",
            ),
        )
        with tempfile.TemporaryDirectory(prefix="haldir-formal-java-") as directory:
            root = Path(directory)
            java = self._java_file(root)
            for output, code in cases:
                with (
                    self.subTest(code=code, output=output),
                    mock.patch.object(
                        RUNNER,
                        "_run_bounded",
                        return_value=RUNNER.ProcessResult(
                            0,
                            output,
                            len(output),
                            "EXITED",
                        ),
                    ),
                ):
                    self.assert_formal_error(
                        code,
                        RUNNER.validate_java,
                        str(java),
                        pins=pins,
                        private_root=root / "private",
                    )

    def test_java_nonzero_timeout_and_output_limit_are_rejected(self) -> None:
        pins, _payload = _tiny_pins()
        results = (
            RUNNER.ProcessResult(1, b"", 0, "EXITED"),
            RUNNER.ProcessResult(-9, b"", 0, "TIMEOUT"),
            RUNNER.ProcessResult(-9, b"x", 1, "OUTPUT_LIMIT"),
        )
        with tempfile.TemporaryDirectory(prefix="haldir-formal-java-") as directory:
            root = Path(directory)
            java = self._java_file(root)
            for result in results:
                with (
                    self.subTest(result=result),
                    mock.patch.object(
                        RUNNER,
                        "_run_bounded",
                        return_value=result,
                    ),
                ):
                    self.assert_formal_error(
                        "FORMAL_JAVA_EXECUTION",
                        RUNNER.validate_java,
                        str(java),
                        pins=pins,
                        private_root=root / "private",
                    )

    def test_duplicate_optional_java_identity_property_is_rejected(self) -> None:
        pins, _payload = _tiny_pins()
        output = self._java_output() + b"java.vm.name = Other VM\n"
        result = RUNNER.ProcessResult(0, output, len(output), "EXITED")
        with tempfile.TemporaryDirectory(prefix="haldir-formal-java-") as directory:
            root = Path(directory)
            java = self._java_file(root)
            with mock.patch.object(RUNNER, "_run_bounded", return_value=result):
                self.assert_formal_error(
                    "FORMAL_JAVA_PROPERTY:java.vm.name",
                    RUNNER.validate_java,
                    str(java),
                    pins=pins,
                    private_root=root / "private",
                )

    def test_missing_and_writable_java_executables_are_rejected(self) -> None:
        with mock.patch.object(RUNNER.shutil, "which", return_value=None):
            self.assert_formal_error("FORMAL_JAVA_MISSING", RUNNER._resolve_java, None)
        with tempfile.TemporaryDirectory(prefix="haldir-formal-java-") as directory:
            java = self._java_file(Path(directory))
            java.chmod(0o722)
            self.assert_formal_error(
                "FORMAL_JAVA_TYPE",
                RUNNER._resolve_java,
                str(java),
            )


class BoundedProcessTests(RunnerTestCase):
    @staticmethod
    def _environment() -> dict[str, str]:
        return {"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"}

    def test_success_and_nonzero_exit_are_reported_without_shell_wrapping(self) -> None:
        with tempfile.TemporaryDirectory(prefix="haldir-formal-process-") as directory:
            root = Path(directory)
            success = RUNNER._run_bounded(
                ("/bin/sh", "-c", "printf success"),
                cwd=root,
                environment=self._environment(),
                timeout_seconds=2.0,
                output_limit=128,
                capture=True,
            )
            failure = RUNNER._run_bounded(
                ("/bin/sh", "-c", "printf failure; exit 7"),
                cwd=root,
                environment=self._environment(),
                timeout_seconds=2.0,
                output_limit=128,
                capture=True,
            )
        self.assertEqual(success, RUNNER.ProcessResult(0, b"success", 7, "EXITED"))
        self.assertEqual(failure.returncode, 7)
        self.assertEqual(failure.output, b"failure")
        self.assertEqual(failure.termination, "EXITED")

    def test_timeout_kills_the_process_group(self) -> None:
        with tempfile.TemporaryDirectory(prefix="haldir-formal-process-") as directory:
            started = time.monotonic()
            result = RUNNER._run_bounded(
                ("/bin/sh", "-c", "sleep 5"),
                cwd=Path(directory),
                environment=self._environment(),
                timeout_seconds=0.1,
                output_limit=128,
                capture=True,
            )
        self.assertEqual(result.termination, "TIMEOUT")
        self.assertLess(result.returncode, 0)
        self.assertLess(time.monotonic() - started, 2.0)

    def test_output_limit_is_exact_and_sink_receives_only_admitted_bytes(self) -> None:
        chunks: list[bytes] = []
        with tempfile.TemporaryDirectory(prefix="haldir-formal-process-") as directory:
            result = RUNNER._run_bounded(
                ("/bin/sh", "-c", "printf 0123456789"),
                cwd=Path(directory),
                environment=self._environment(),
                timeout_seconds=2.0,
                output_limit=5,
                sink=chunks.append,
                capture=True,
            )
        self.assertEqual(result.termination, "OUTPUT_LIMIT")
        self.assertEqual(result.output, b"01234")
        self.assertEqual(result.output_bytes, 5)
        self.assertEqual(b"".join(chunks), b"01234")

    def test_output_exactly_at_limit_completes_normally(self) -> None:
        with tempfile.TemporaryDirectory(prefix="haldir-formal-process-") as directory:
            result = RUNNER._run_bounded(
                ("/bin/sh", "-c", "printf 01234"),
                cwd=Path(directory),
                environment=self._environment(),
                timeout_seconds=2.0,
                output_limit=5,
                capture=True,
            )
        self.assertEqual(result, RUNNER.ProcessResult(0, b"01234", 5, "EXITED"))

    def test_fast_exit_output_overflow_cleanup_is_race_safe(self) -> None:
        with tempfile.TemporaryDirectory(prefix="haldir-formal-process-") as directory:
            root = Path(directory)
            for iteration in range(32):
                with self.subTest(iteration=iteration):
                    result = RUNNER._run_bounded(
                        ("/bin/sh", "-c", "printf 0123456789"),
                        cwd=root,
                        environment=self._environment(),
                        timeout_seconds=2.0,
                        output_limit=5,
                        capture=True,
                    )
                    self.assertEqual(result.termination, "OUTPUT_LIMIT")
                    self.assertEqual(result.output, b"01234")

    def test_launch_and_sink_errors_are_normalized_after_cleanup(self) -> None:
        with tempfile.TemporaryDirectory(prefix="haldir-formal-process-") as directory:
            root = Path(directory)
            self.assert_formal_error(
                "FORMAL_PROCESS_LAUNCH",
                RUNNER._run_bounded,
                (str(root / "missing-executable"),),
                cwd=root,
                environment=self._environment(),
                timeout_seconds=1.0,
                output_limit=32,
                capture=True,
            )

            def broken_sink(_chunk: bytes) -> None:
                raise OSError("fake sink failure")

            self.assert_formal_error(
                "FORMAL_PROCESS_SINK",
                RUNNER._run_bounded,
                ("/bin/sh", "-c", "printf output"),
                cwd=root,
                environment=self._environment(),
                timeout_seconds=1.0,
                output_limit=32,
                sink=broken_sink,
                capture=False,
            )

    @unittest.skipUnless(hasattr(os, "fork"), "fork unavailable")
    def test_descendant_holding_output_pipe_is_killed_after_leader_exit(self) -> None:
        program = (
            "import os,time\n"
            "if os.fork() == 0:\n"
            "    time.sleep(5)\n"
            "else:\n"
            "    print('leader-exited', flush=True)\n"
        )
        with tempfile.TemporaryDirectory(prefix="haldir-formal-process-") as directory:
            started = time.monotonic()
            result = RUNNER._run_bounded(
                (sys.executable, "-I", "-c", program),
                cwd=Path(directory),
                environment=self._environment(),
                timeout_seconds=2.0,
                output_limit=128,
                capture=True,
            )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.termination, "EXITED")
        self.assertEqual(result.output, b"leader-exited\n")
        self.assertLess(time.monotonic() - started, 1.5)

    def test_invalid_process_bounds_are_rejected_before_launch(self) -> None:
        invalid = (
            {"timeout_seconds": 0.0, "output_limit": 1, "capture": True},
            {"timeout_seconds": float("nan"), "output_limit": 1, "capture": True},
            {"timeout_seconds": 1.0, "output_limit": True, "capture": True},
            {"timeout_seconds": 1.0, "output_limit": 1, "capture": 1},
        )
        for arguments in invalid:
            with self.subTest(arguments=arguments):
                self.assert_formal_error(
                    "FORMAL_PROCESS_ARGUMENT",
                    RUNNER._run_bounded,
                    ("/bin/true",),
                    cwd=ROOT,
                    environment=self._environment(),
                    **arguments,
                )


class TlcTests(RunnerTestCase):
    def _fixture(self, root: Path) -> tuple[Path, Path, Path, object, object]:
        tools = root / "tools"
        tools.mkdir()
        _write(tools / "run_formal.py", b"test runner material\n")
        _write(tools / "pins.toml", PinPolicyTests._valid_document())
        formal = root / "formal"
        formal.mkdir()
        _write(formal / "HaldirAuthority.tla", b"---- MODULE HaldirAuthority ----\n")
        _write(formal / "HaldirAuthority.cfg", b"SPECIFICATION Spec\n")
        asset = _write(root / "tla2tools.jar", b"jar")
        java = _write(root / "java", b"java", 0o700)
        pins, _payload = _tiny_pins(b"jar")
        metadata = java.stat()
        identity_values = {
            "executable": java,
            "executable_bytes": metadata.st_size,
            "executable_sha256": hashlib.sha256(java.read_bytes()).hexdigest(),
            "device": metadata.st_dev,
            "inode": metadata.st_ino,
            "modified_ns": metadata.st_mtime_ns,
            "specification_version": "21",
            "vendor": "Eclipse Adoptium",
            "runtime_version": "21.0.11+10-LTS",
            "vm_name": "Test VM",
            "architecture": "amd64",
            "properties_output_sha256": "0" * 64,
        }
        identity = RUNNER.JavaIdentity(
            **{
                key: value
                for key, value in identity_values.items()
                if key in RUNNER.JavaIdentity._fields
            }
        )
        scratch = root / "scratch"
        scratch.mkdir(mode=0o700)
        return asset, java, scratch, pins, identity

    def _invoke(
        self,
        root: Path,
        *,
        output: bytes,
        returncode: int = 0,
        termination: str = "EXITED",
        log_name: str = "tlc.log",
        mutation: str | None = None,
        accounted_delta: int = 0,
        atomic_error: str | None = None,
    ) -> tuple[dict[str, object], Path, tuple[str, ...]]:
        asset, java, scratch, pins, identity = self._fixture(root)
        observed: dict[str, object] = {}

        def run(command: tuple[str, ...], **kwargs: object) -> object:
            observed["command"] = command
            self.assertEqual(kwargs["cwd"], root)
            self.assertEqual(kwargs["environment"], {"PATH": "/usr/bin:/bin"})
            self.assertEqual(
                kwargs["timeout_seconds"],
                RUNNER.TLC_TIMEOUT_SECONDS,
            )
            self.assertEqual(kwargs["output_limit"], RUNNER.TLC_OUTPUT_CAP)
            self.assertFalse(kwargs["capture"])
            snapshot_asset = Path(command[3])
            snapshot_config = Path(command[-2])
            snapshot_spec = Path(command[-1])
            self.assertTrue(snapshot_asset.is_relative_to(scratch))
            self.assertTrue(snapshot_config.is_relative_to(scratch))
            self.assertTrue(snapshot_spec.is_relative_to(scratch))
            self.assertEqual(snapshot_asset.read_bytes(), b"jar")
            self.assertEqual(snapshot_config.read_bytes(), b"SPECIFICATION Spec\n")
            self.assertEqual(
                snapshot_spec.read_bytes(),
                b"---- MODULE HaldirAuthority ----\n",
            )
            sink = kwargs.get("sink")
            if callable(sink):
                sink(output)
            if mutation == "spec":
                _write(
                    root / "formal" / "HaldirAuthority.tla",
                    b"changed specification\n",
                )
            elif mutation == "java":
                _write(java, b"changed java", 0o700)
            return RUNNER.ProcessResult(
                returncode,
                b"",
                len(output) + accounted_delta,
                termination,
            )

        log = root / "out" / log_name
        runtime_path = root / "out" / "formal-runtime.json"
        if atomic_error is not None:
            log.parent.mkdir()
            _write(log, b"old log\n")
            _write(runtime_path, b'{"old":true}\n')
            atomic = mock.patch.object(
                RUNNER,
                "_atomic_json",
                side_effect=RUNNER.FormalRunnerError(atomic_error),
            )
        else:
            atomic = mock.patch.object(
                RUNNER,
                "_atomic_json",
                wraps=RUNNER._atomic_json,
            )
        stdout = _BufferedStdout()
        with (
            mock.patch.object(RUNNER, "_run_bounded", run),
            mock.patch.object(RUNNER.sys, "stdout", stdout),
            atomic,
        ):
            runtime = RUNNER.run_tlc(
                repository=root,
                pins=pins,
                asset=asset,
                java_identity=identity,
                environment={"PATH": "/usr/bin:/bin"},
                log_path=log,
                runtime_path=runtime_path,
                scratch_root=scratch,
            )
        command = observed["command"]
        assert isinstance(command, tuple)
        return runtime, log, command

    def test_exact_marker_and_zero_exit_publish_matching_log_and_runtime(self) -> None:
        output = b"start\n" + RUNNER.SUCCESS_MARKER + b"\nstats after marker\n"
        with tempfile.TemporaryDirectory(prefix="haldir-formal-tlc-") as directory:
            root = Path(directory)
            runtime, log, command = self._invoke(root, output=output)
            runtime_file = log.parent / "formal-runtime.json"
            persisted = json.loads(runtime_file.read_text())
            self.assertEqual(runtime, persisted)
            self.assertEqual(runtime["schema"], "HALDIR_FORMAL_RUNTIME_V2")
            self.assertEqual(log.read_bytes(), output)
            self.assertEqual(runtime["result"], "PASS")
            self.assertEqual(runtime["tlc"]["success_marker_count"], 1)
            self.assertEqual(runtime["tlc"]["log_bytes"], len(output))
            self.assertEqual(
                runtime["tlc"]["log_sha256"],
                hashlib.sha256(output).hexdigest(),
            )
            self.assertEqual(runtime["tlc"]["log_path"], "out/tlc.log")
            self.assertEqual(runtime["java"]["architecture"], "amd64")
            materials = {item["path"]: item for item in runtime["materials"]}
            expected_materials = {
                "tools/run_formal.py": b"test runner material\n",
                "tools/pins.toml": PinPolicyTests._valid_document(),
                "formal/HaldirAuthority.cfg": b"SPECIFICATION Spec\n",
                "formal/HaldirAuthority.tla": b"---- MODULE HaldirAuthority ----\n",
            }
            self.assertEqual(set(materials), set(expected_materials))
            for path, payload in expected_materials.items():
                self.assertEqual(materials[path]["bytes"], len(payload))
                self.assertEqual(
                    materials[path]["sha256"],
                    hashlib.sha256(payload).hexdigest(),
                )
            self.assertEqual(command[4:7], ("tlc2.TLC", "-workers", "auto"))
            self.assertIn("-metadir", command)
            self.assertEqual(command[-3], "-config")
            self.assertEqual(Path(command[-2]).name, "HaldirAuthority.cfg")
            self.assertEqual(Path(command[-1]).name, "HaldirAuthority.tla")
            self.assertFalse(
                any(path.name.startswith(".tlc.log.") for path in log.parent.iterdir())
            )
            self.assertFalse(stat.S_IMODE(log.stat().st_mode) & 0o022)
            self.assertFalse(stat.S_IMODE(runtime_file.stat().st_mode) & 0o022)

    def test_marker_is_a_complete_line_and_must_appear_exactly_once(self) -> None:
        cases = (
            b"prefix " + RUNNER.SUCCESS_MARKER + b" suffix\n",
            RUNNER.SUCCESS_MARKER + b"\n" + RUNNER.SUCCESS_MARKER + b"\n",
            b"no success marker\n",
        )
        for index, output in enumerate(cases):
            with (
                self.subTest(index=index),
                tempfile.TemporaryDirectory(prefix="haldir-formal-tlc-") as directory,
            ):
                root = Path(directory)
                with self.assertRaises(RUNNER.FormalRunnerError) as raised:
                    self._invoke(root, output=output)
                self.assertEqual(raised.exception.code, "FORMAL_TLC_MARKER")
                runtime = json.loads((root / "out" / "formal-runtime.json").read_text())
                self.assertEqual(runtime["result"], "FAIL")

    def test_nonzero_exit_cannot_be_laundered_by_success_marker(self) -> None:
        output = RUNNER.SUCCESS_MARKER + b"\n"
        with tempfile.TemporaryDirectory(prefix="haldir-formal-tlc-") as directory:
            root = Path(directory)
            with self.assertRaises(RUNNER.FormalRunnerError) as raised:
                self._invoke(root, output=output, returncode=7)
            self.assertEqual(raised.exception.code, "FORMAL_TLC_EXIT")
            runtime = json.loads((root / "out" / "formal-runtime.json").read_text())
            self.assertEqual(runtime["result"], "FAIL")
            self.assertEqual(runtime["tlc"]["exit_status"], 7)
            self.assertEqual(runtime["tlc"]["success_marker_count"], 1)

    def test_timeout_and_output_limit_publish_fail_runtime(self) -> None:
        for termination in ("TIMEOUT", "OUTPUT_LIMIT"):
            with (
                self.subTest(termination=termination),
                tempfile.TemporaryDirectory(prefix="haldir-formal-tlc-") as directory,
            ):
                root = Path(directory)
                with self.assertRaises(RUNNER.FormalRunnerError) as raised:
                    self._invoke(
                        root,
                        output=b"partial",
                        returncode=-9,
                        termination=termination,
                    )
                self.assertEqual(
                    raised.exception.code,
                    "FORMAL_TLC_" + termination,
                )
                self.assertEqual((root / "out" / "tlc.log").read_bytes(), b"partial")
                runtime = json.loads((root / "out" / "formal-runtime.json").read_text())
                self.assertEqual(runtime["result"], "FAIL")
                self.assertEqual(runtime["tlc"]["termination"], termination)

    def test_material_and_java_mutation_fail_and_are_recorded(self) -> None:
        cases = (
            (
                "spec",
                "FORMAL_MATERIAL_CHANGED:formal/HaldirAuthority.tla",
            ),
            ("java", "FORMAL_JAVA_CHANGED"),
        )
        for mutation, code in cases:
            with (
                self.subTest(mutation=mutation),
                tempfile.TemporaryDirectory(prefix="haldir-formal-tlc-") as directory,
            ):
                root = Path(directory)
                with self.assertRaises(RUNNER.FormalRunnerError) as raised:
                    self._invoke(
                        root,
                        output=RUNNER.SUCCESS_MARKER + b"\n",
                        mutation=mutation,
                    )
                self.assertEqual(raised.exception.code, code)
                runtime = json.loads((root / "out" / "formal-runtime.json").read_text())
                self.assertEqual(runtime["result"], "FAIL")
                self.assertEqual(runtime["error"], code)

    def test_log_accounting_mismatch_fails_and_is_recorded(self) -> None:
        with tempfile.TemporaryDirectory(prefix="haldir-formal-tlc-") as directory:
            root = Path(directory)
            with self.assertRaises(RUNNER.FormalRunnerError) as raised:
                self._invoke(
                    root,
                    output=RUNNER.SUCCESS_MARKER + b"\n",
                    accounted_delta=1,
                )
            self.assertEqual(raised.exception.code, "FORMAL_LOG_ACCOUNTING")
            runtime = json.loads((root / "out" / "formal-runtime.json").read_text())
            self.assertEqual(runtime["result"], "FAIL")
            self.assertEqual(runtime["error"], "FORMAL_LOG_ACCOUNTING")

    def test_runtime_publication_failure_never_leaves_stale_record_for_new_log(
        self,
    ) -> None:
        output = RUNNER.SUCCESS_MARKER + b"\n"
        with tempfile.TemporaryDirectory(prefix="haldir-formal-tlc-") as directory:
            root = Path(directory)
            with self.assertRaises(RUNNER.FormalRunnerError) as raised:
                self._invoke(
                    root,
                    output=output,
                    atomic_error="FORMAL_RUNTIME_FSYNC",
                )
            self.assertEqual(raised.exception.code, "FORMAL_RUNTIME_FSYNC")
            self.assertEqual((root / "out" / "tlc.log").read_bytes(), output)
            self.assertFalse((root / "out" / "formal-runtime.json").exists())

    def test_reserved_runtime_filename_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="haldir-formal-tlc-") as directory:
            root = Path(directory)
            with self.assertRaises(RUNNER.FormalRunnerError):
                self._invoke(
                    root,
                    output=RUNNER.SUCCESS_MARKER + b"\n",
                    log_name="formal-runtime.json",
                )


class AtomicPublicationTests(RunnerTestCase):
    def test_runtime_write_fsync_and_close_failures_preserve_old_file_and_clean_temp(
        self,
    ) -> None:
        original_close = RUNNER.os.close

        def close_then_raise(descriptor: int) -> None:
            original_close(descriptor)
            raise OSError("injected close failure")

        injections = (
            mock.patch.object(
                RUNNER,
                "_write_all",
                side_effect=OSError("injected write failure"),
            ),
            mock.patch.object(
                RUNNER.os,
                "fsync",
                side_effect=OSError("injected fsync failure"),
            ),
            mock.patch.object(
                RUNNER.os,
                "close",
                side_effect=close_then_raise,
            ),
        )
        for index, injection in enumerate(injections):
            with (
                self.subTest(index=index),
                tempfile.TemporaryDirectory(
                    prefix="haldir-formal-runtime-"
                ) as directory,
            ):
                root = Path(directory)
                destination = _write(
                    root / "formal-runtime.json",
                    b'{"old":true}\n',
                )
                with injection, self.assertRaises(RUNNER.FormalRunnerError) as raised:
                    RUNNER._atomic_json(destination, {"new": True})
                self.assertTrue(
                    raised.exception.code.startswith("FORMAL_RUNTIME_"),
                    raised.exception.code,
                )
                self.assertEqual(destination.read_bytes(), b'{"old":true}\n')
                self.assertEqual(
                    sorted(path.name for path in root.iterdir()),
                    ["formal-runtime.json"],
                )


class CliTests(unittest.TestCase):
    @staticmethod
    def _standalone_repository(root: Path) -> Path:
        (root / "formal").mkdir()
        (root / "Cargo.toml").write_text("[workspace]\nmembers = []\n")
        tools = root / "tools"
        tools.mkdir()
        runner = tools / "run_formal.py"
        runner.write_bytes(RUNNER_PATH.read_bytes())
        runner.chmod(0o700)
        (tools / "pins.toml").write_bytes(PinPolicyTests._valid_document())
        return runner

    def test_local_runner_recipes_and_documentation_disable_bytecode(self) -> None:
        expected = [
            "python3 -I -B tools/run_formal.py",
            "python3 -I -B tools/run_formal.py --offline",
        ]
        for path in (ROOT / "justfile", ROOT / "formal" / "README.md"):
            with self.subTest(path=path.relative_to(ROOT)):
                lines = [
                    line.strip()
                    for line in path.read_text().splitlines()
                    if "tools/run_formal.py" in line
                ]
                self.assertEqual(lines, expected)

    def test_help_runs_under_isolated_mode_without_importing_siblings(self) -> None:
        completed = subprocess.run(
            (sys.executable, "-I", "-B", str(RUNNER_PATH), "--help"),
            cwd=ROOT,
            env={"LC_ALL": "C", "PATH": "/usr/bin:/bin"},
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=10,
        )
        self.assertEqual(
            completed.returncode, 0, completed.stderr.decode(errors="replace")
        )
        self.assertIn(b"--offline", completed.stdout)
        self.assertNotIn(b"Traceback", completed.stderr)

    def test_nonisolated_python_is_rejected_before_any_runner_work(self) -> None:
        completed = subprocess.run(
            (sys.executable, "-B", str(RUNNER_PATH), "--help"),
            cwd=ROOT,
            env={"LC_ALL": "C", "PATH": "/usr/bin:/bin"},
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=10,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertIn(b"FORMAL_PYTHON_NOT_ISOLATED", completed.stderr)
        self.assertNotIn(b"Traceback", completed.stderr)

    def test_offline_cli_failure_is_stable_and_never_reaches_java(self) -> None:
        with tempfile.TemporaryDirectory(prefix="haldir-formal-cli-") as directory:
            root = Path(directory)
            runner = self._standalone_repository(root)
            completed = subprocess.run(
                (
                    sys.executable,
                    "-I",
                    "-B",
                    str(runner),
                    "--offline",
                    "--cache-dir",
                    str(root / "empty-cache"),
                ),
                cwd=root,
                env={
                    "JAVA_TOOL_OPTIONS": "-javaagent:must-not-run",
                    "LC_ALL": "C",
                    "PATH": "/usr/bin:/bin",
                },
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=10,
            )
        self.assertEqual(completed.returncode, 1)
        self.assertIn(b"formal-runner: FORMAL_OFFLINE_CACHE", completed.stderr)
        self.assertNotIn(b"Traceback", completed.stderr)
        self.assertNotIn(b"Picked up", completed.stderr)

    def test_main_holds_lock_across_tlc_and_releases_it_afterward(self) -> None:
        pins, payload = _tiny_pins()
        with tempfile.TemporaryDirectory(prefix="haldir-formal-main-") as directory:
            root = Path(directory)
            (root / "formal").mkdir()
            (root / "Cargo.toml").write_text("[workspace]\nmembers = []\n")
            asset = _write(root / "asset.jar", payload)
            java = _write(root / "java", b"java", 0o700)
            metadata = java.stat()
            identity = RUNNER.JavaIdentity(
                executable=java,
                executable_bytes=metadata.st_size,
                executable_sha256=hashlib.sha256(java.read_bytes()).hexdigest(),
                device=metadata.st_dev,
                inode=metadata.st_ino,
                modified_ns=metadata.st_mtime_ns,
                specification_version="21",
                vendor="Eclipse Adoptium",
                runtime_version="21.0.11+10-LTS",
                vm_name="Test VM",
                architecture="amd64",
                properties_output_sha256="0" * 64,
            )
            observed: dict[str, object] = {}

            def run_tlc(**kwargs: object) -> dict[str, object]:
                observed.update(kwargs)
                lock_path = root / "target" / "formal" / ".formal-runner.lock"
                with self.assertRaises(RUNNER.FormalRunnerError) as raised:
                    RUNNER._acquire_run_lock(lock_path)
                self.assertEqual(raised.exception.code, "FORMAL_RUN_BUSY")
                log_path = kwargs["log_path"]
                runtime_path = kwargs["runtime_path"]
                assert isinstance(log_path, Path)
                assert isinstance(runtime_path, Path)
                _write(log_path, RUNNER.SUCCESS_MARKER + b"\n")
                RUNNER._atomic_json(runtime_path, {"result": "PASS"})
                return {"result": "PASS"}

            with (
                mock.patch.object(RUNNER, "_repository_root", return_value=root),
                mock.patch.object(RUNNER, "load_pins", return_value=pins),
                mock.patch.object(RUNNER, "ensure_asset", return_value=asset),
                mock.patch.object(
                    RUNNER,
                    "validate_java",
                    return_value=(identity, {"PATH": "/usr/bin:/bin"}),
                ),
                mock.patch.object(RUNNER, "run_tlc", run_tlc),
            ):
                result = RUNNER.main(["--offline"])
            self.assertEqual(result, 0)
            self.assertEqual(observed["repository"], root)
            self.assertEqual(observed["asset"], asset)
            self.assertEqual(observed["pins"], pins)
            self.assertEqual(observed["java_identity"], identity)
            lock_path = root / "target" / "formal" / ".formal-runner.lock"
            descriptor = RUNNER._acquire_run_lock(lock_path)
            RUNNER._release_run_lock(descriptor)


if __name__ == "__main__":
    unittest.main()
