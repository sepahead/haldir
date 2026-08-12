#!/usr/bin/env python3
"""Bounded local prerequisite checks for Haldir development.

The default lane checks the Rust workspace only. ``--formal`` additionally
checks the Java specification major needed to invoke the separate TLA+ runner.
"""

from __future__ import annotations

import math
import os
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

if sys.version_info < (3, 11):
    print(
        "FAIL python: Haldir tooling requires Python 3.11 or newer "
        f"(found {sys.version.split()[0]})",
        file=sys.stderr,
    )
    raise SystemExit(1)

import tomllib


ROOT = Path(__file__).resolve().parent.parent
COMMAND_TIMEOUT_SECONDS = 15.0
COMMAND_OUTPUT_LIMIT_BYTES = 8 * 1024
METADATA_OUTPUT_LIMIT_BYTES = 8 * 1024 * 1024
MAX_PROBE_TIMEOUT_SECONDS = 300.0
MAX_PROBE_OUTPUT_LIMIT_BYTES = METADATA_OUTPUT_LIMIT_BYTES
CONFIGURATION_LIMIT_BYTES = 64 * 1024
SUMMARY_LIMIT_CHARACTERS = 240
PROCESS_REAP_TIMEOUT_SECONDS = 1.0
READ_CHUNK_BYTES = 4096

SEMVER_COMPONENT = r"(?:0|[1-9][0-9]*)"
SEMVER = rf"{SEMVER_COMPONENT}\.{SEMVER_COMPONENT}\.{SEMVER_COMPONENT}"
COMMIT = r"[0-9a-f]{7,40}"
DATE = r"[0-9]{4}-[0-9]{2}-[0-9]{2}"
PINNED_VERSION_PATTERN = re.compile(rf"{SEMVER}")
JAVA_SPECIFICATION_PATTERN = re.compile(r"[1-9][0-9]*")
CARGO_VERSION_PATTERN = re.compile(
    rf"cargo (?P<version>{SEMVER}) \((?P<commit>{COMMIT}) {DATE}\)"
)
RUSTC_VERSION_PATTERN = re.compile(
    rf"rustc (?P<version>{SEMVER}) \((?P<commit>{COMMIT}) {DATE}\)"
)
RUSTFMT_VERSION_PATTERN = re.compile(
    rf"rustfmt (?P<version>{SEMVER}(?:-[0-9A-Za-z.-]+)?) "
    rf"\((?P<commit>{COMMIT}) {DATE}\)"
)
CLIPPY_VERSION_PATTERN = re.compile(
    rf"clippy (?P<version>{SEMVER}) \((?P<commit>{COMMIT}) {DATE}\)"
)
CARGO_DENY_VERSION_PATTERN = re.compile(rf"cargo-deny (?P<version>{SEMVER})")
JAVA_VERSION_PATTERN = re.compile(
    r'(?:openjdk|java) version "(?P<version>[1-9][0-9]*)'
    r'(?:[._+\-][0-9A-Za-z._+\-]+)?"(?: [^"\r\n]*)?'
)


class ConfigurationError(ValueError):
    """Repository prerequisite configuration is missing or ill-typed."""


@dataclass(frozen=True)
class CommandResult:
    """One bounded command probe."""

    ok: bool
    output: str


@dataclass(frozen=True)
class OutputExpectation:
    """An exact, full-line tool identity expectation."""

    description: str
    pattern: re.Pattern[str]
    expected_version: str | None = None
    expected_commit: str | None = None

    def matches(self, output: str) -> bool:
        """Return whether `output` exactly satisfies this expectation."""

        matched = self.pattern.fullmatch(output)
        if matched is None:
            return False
        if (
            self.expected_version is not None
            and matched.group("version") != self.expected_version
        ):
            return False
        if self.expected_commit is None:
            return True
        actual_commit = matched.groupdict().get("commit")
        return actual_commit is not None and actual_commit.startswith(
            self.expected_commit
        )


@dataclass(frozen=True)
class RepositoryConfiguration:
    """Strictly decoded local prerequisite pins."""

    rust_channel: str
    cargo_deny_version: str
    java_specification_version: str | None


def _terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    """Kill the probe's isolated POSIX process group and reap its leader."""

    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except OSError:
        # `start_new_session=True` makes killpg the normal macOS/Linux path.
        # Retain a bounded leader fallback for an unexpected platform failure.
        try:
            process.kill()
        except OSError:
            pass

    try:
        process.wait(timeout=PROCESS_REAP_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        try:
            process.kill()
            process.wait(timeout=PROCESS_REAP_TIMEOUT_SECONDS)
        except (OSError, subprocess.TimeoutExpired):
            pass
    except OSError:
        pass


def _first_output_line(raw_output: bytes, returncode: int) -> CommandResult:
    """Decode bounded output and select its first nonempty line."""

    try:
        decoded = raw_output.decode("utf-8")
    except UnicodeDecodeError:
        return CommandResult(False, "invalid UTF-8 output")
    first_line = next(
        (line.strip() for line in decoded.splitlines() if line.strip()), None
    )
    summary = (
        first_line[:SUMMARY_LIMIT_CHARACTERS]
        if first_line is not None
        else f"exit {returncode}"
    )
    return CommandResult(returncode == 0, summary)


def probe(
    *command: str,
    timeout_seconds: float = COMMAND_TIMEOUT_SECONDS,
    output_limit_bytes: int = COMMAND_OUTPUT_LIMIT_BYTES,
) -> CommandResult:
    """Run one shell-free command with hard time, byte, and process-group bounds."""

    if not command or any(type(argument) is not str for argument in command):
        return CommandResult(False, "invalid command")
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not math.isfinite(timeout_seconds)
        or timeout_seconds <= 0
        or timeout_seconds > MAX_PROBE_TIMEOUT_SECONDS
        or isinstance(output_limit_bytes, bool)
        or not isinstance(output_limit_bytes, int)
        or output_limit_bytes <= 0
        or output_limit_bytes > MAX_PROBE_OUTPUT_LIMIT_BYTES
    ):
        return CommandResult(False, "invalid probe limits")

    deadline = time.monotonic() + timeout_seconds
    try:
        process = subprocess.Popen(
            command,
            cwd=ROOT,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            shell=False,
            start_new_session=True,
        )
    except (OSError, ValueError) as error:
        return CommandResult(False, type(error).__name__)

    pipe = process.stdout
    if pipe is None:
        _terminate_process_group(process)
        return CommandResult(False, "missing output pipe")

    try:
        selected = selectors.DefaultSelector()
    except OSError as error:
        _terminate_process_group(process)
        try:
            pipe.close()
        except OSError:
            pass
        return CommandResult(False, type(error).__name__)
    captured = bytearray()
    failure: str | None = None
    returncode: int | None = None
    try:
        selected.register(pipe, selectors.EVENT_READ)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                failure = f"timed out after {timeout_seconds:g}s"
                break
            if not selected.select(remaining):
                continue

            allowance = output_limit_bytes + 1 - len(captured)
            try:
                chunk = os.read(pipe.fileno(), min(READ_CHUNK_BYTES, allowance))
            except BlockingIOError:
                continue
            if not chunk:
                break
            captured.extend(chunk)
            if len(captured) > output_limit_bytes:
                failure = f"output exceeded {output_limit_bytes} bytes"
                break

        if failure is None:
            remaining = max(0.0, deadline - time.monotonic())
            try:
                returncode = process.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                failure = f"timed out after {timeout_seconds:g}s"
    except (OSError, ValueError) as error:
        failure = type(error).__name__
    except BaseException:
        # An interrupt must not orphan the isolated probe or any descendant it
        # spawned. Preserve KeyboardInterrupt/SystemExit semantics after cleanup.
        _terminate_process_group(process)
        raise
    finally:
        try:
            selected.close()
        except OSError:
            pass
        finally:
            try:
                pipe.close()
            except OSError:
                pass

    if failure is not None:
        _terminate_process_group(process)
        return CommandResult(False, failure)
    if returncode is None:
        _terminate_process_group(process)
        return CommandResult(False, "missing process status")
    # A successful command may still have detached descendants that closed the
    # inherited output pipe. The isolated process group is probe-owned, so tear
    # down any survivors before reporting success.
    _terminate_process_group(process)
    return _first_output_line(bytes(captured), returncode)


def required(
    label: str,
    result: CommandResult,
    expectation: OutputExpectation | None = None,
) -> bool:
    """Print and classify a required probe."""

    identity_matches = expectation is None or expectation.matches(result.output)
    matches = result.ok and identity_matches
    detail = result.output
    if expectation is not None and not identity_matches:
        detail = f"{detail}; expected {expectation.description}"
    print(f"{'PASS' if matches else 'FAIL'} {label}: {detail}")
    return matches


def optional(
    label: str,
    result: CommandResult,
    expectation: OutputExpectation | None = None,
) -> None:
    """Print an optional-lane probe without changing core readiness."""

    identity_matches = expectation is None or expectation.matches(result.output)
    matches = result.ok and identity_matches
    state = "PASS" if matches else "INFO"
    detail = result.output
    if expectation is not None and not identity_matches:
        detail = f"{detail}; optional lane expects {expectation.description}"
    print(f"{state} {label}: {detail}")


def _required_table(table: dict[str, object], key: str, path: str) -> dict[str, object]:
    value = table.get(key)
    if type(value) is not dict:
        raise ConfigurationError(f"{path}.{key} must be a TOML table")
    return value


def _required_string(table: dict[str, object], key: str, path: str) -> str:
    value = table.get(key)
    if type(value) is not str:
        raise ConfigurationError(f"{path}.{key} must be a TOML string")
    return value


def _read_bounded_regular_file(path: Path, label: str) -> bytes:
    """Read one no-follow regular file without first allocating its stated size."""

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    before: os.stat_result | None = None
    if nofollow:
        flags |= nofollow
    else:
        # The inode comparison below closes the ordinary lstat/open replacement
        # race on platforms without O_NOFOLLOW as far as the host API permits.
        before = os.lstat(path)
        if not stat.S_ISREG(before.st_mode):
            raise ConfigurationError(f"{label} must be a regular file")

    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ConfigurationError(f"{label} must be a readable regular file") from error

    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise ConfigurationError(f"{label} must be a regular file")
        if before is not None and (before.st_dev, before.st_ino) != (
            opened.st_dev,
            opened.st_ino,
        ):
            raise ConfigurationError(f"{label} changed while it was opened")
        if not 1 <= opened.st_size <= CONFIGURATION_LIMIT_BYTES:
            raise ConfigurationError(f"{label} violates the configuration byte bound")

        payload = bytearray()
        while len(payload) <= CONFIGURATION_LIMIT_BYTES:
            allowance = CONFIGURATION_LIMIT_BYTES + 1 - len(payload)
            try:
                chunk = os.read(descriptor, min(READ_CHUNK_BYTES, allowance))
            except InterruptedError:
                continue
            if not chunk:
                break
            payload.extend(chunk)
        if not 1 <= len(payload) <= CONFIGURATION_LIMIT_BYTES:
            raise ConfigurationError(f"{label} violates the configuration byte bound")

        after = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (after.st_dev, after.st_ino) or (
            opened.st_size,
            opened.st_mtime_ns,
        ) != (after.st_size, after.st_mtime_ns):
            raise ConfigurationError(f"{label} changed while it was read")
        if len(payload) != after.st_size:
            raise ConfigurationError(f"{label} was truncated while it was read")
        return bytes(payload)
    finally:
        os.close(descriptor)


def _load_toml(path: Path, label: str) -> dict[str, object]:
    """Decode one bounded, no-follow, regular UTF-8 TOML document."""

    payload = _read_bounded_regular_file(path, label)
    if b"\0" in payload:
        raise ConfigurationError(f"{label} contains a NUL byte")
    document = tomllib.loads(payload.decode("utf-8"))
    if type(document) is not dict:
        raise ConfigurationError(f"{label} must contain a TOML table")
    return document


def _load_configuration(*, include_formal: bool = False) -> RepositoryConfiguration:
    """Load and strictly validate the pins needed by the requested lane."""

    rust_document = _load_toml(ROOT / "rust-toolchain.toml", "rust-toolchain.toml")
    pins = _load_toml(ROOT / "tools" / "pins.toml", "tools/pins.toml")

    rust = _required_table(rust_document, "toolchain", "rust-toolchain.toml")
    channel = _required_string(rust, "channel", "rust-toolchain.toml.toolchain")
    if PINNED_VERSION_PATTERN.fullmatch(channel) is None:
        raise ConfigurationError(
            "rust-toolchain.toml.toolchain.channel must be exact X.Y.Z"
        )
    components = rust.get("components")
    if type(components) is not list or any(
        type(item) is not str for item in components
    ):
        raise ConfigurationError(
            "rust-toolchain.toml.toolchain.components must be an array of strings"
        )
    missing_components = {"clippy", "rustfmt"}.difference(components)
    if missing_components:
        rendered = ", ".join(sorted(missing_components))
        raise ConfigurationError(
            f"rust-toolchain.toml is missing components: {rendered}"
        )

    pinned_toolchain = _required_table(pins, "toolchain", "tools/pins.toml")
    pinned_channel = _required_string(
        pinned_toolchain, "rust_channel", "tools/pins.toml.toolchain"
    )
    if pinned_channel != channel:
        raise ConfigurationError(
            "rust-toolchain.toml channel does not match tools/pins.toml"
        )

    supply_chain = _required_table(pins, "supply_chain", "tools/pins.toml")
    cargo_deny = _required_table(
        supply_chain, "cargo_deny", "tools/pins.toml.supply_chain"
    )
    deny_version = _required_string(
        cargo_deny, "version", "tools/pins.toml.supply_chain.cargo_deny"
    )
    if PINNED_VERSION_PATTERN.fullmatch(deny_version) is None:
        raise ConfigurationError("cargo-deny version must be exact X.Y.Z")

    java_version = None
    if include_formal:
        formal = _required_table(pins, "formal", "tools/pins.toml")
        java_version = _required_string(
            formal, "java_specification_version", "tools/pins.toml.formal"
        )
        if JAVA_SPECIFICATION_PATTERN.fullmatch(java_version) is None:
            raise ConfigurationError(
                "Java specification version must be a positive integer string"
            )

    return RepositoryConfiguration(channel, deny_version, java_version)


def _rustup_executable(command_name: str) -> str | None:
    """Find rustup directly, including a proxy's hidden sibling executable."""

    rustup = shutil.which("rustup")
    if rustup is not None:
        return rustup

    executable = shutil.which(command_name)
    if executable is None:
        return None
    try:
        resolved = Path(executable).resolve(strict=True)
        if resolved.name in {"rustup", "rustup-init"}:
            return str(resolved)
        sibling = Path(executable).with_name("rustup")
        if sibling.is_file() and os.path.samefile(executable, sibling):
            return str(sibling)
    except OSError:
        pass
    return None


def _rust_command(channel: str, *command: str) -> tuple[str, ...]:
    """Select an installed rustup toolchain without requesting installation."""

    rustup = _rustup_executable(command[0])
    if rustup is not None:
        # `rustup run` installs nothing unless its explicit `--install` flag is used.
        return (rustup, "run", channel, *command)
    return command


def _probe_rust(
    channel: str,
    *command: str,
    output_limit_bytes: int = COMMAND_OUTPUT_LIMIT_BYTES,
) -> CommandResult:
    selected = _rust_command(channel, *command)
    return probe(*selected, output_limit_bytes=output_limit_bytes)


def _matched_group(
    result: CommandResult, pattern: re.Pattern[str], group: str
) -> str | None:
    if not result.ok:
        return None
    matched = pattern.fullmatch(result.output)
    return None if matched is None else matched.group(group)


def _clippy_version_for(rust_channel: str) -> str:
    _, minor, _ = rust_channel.split(".")
    return f"0.1.{int(minor)}"


def _requested_formal_lane(argv: Sequence[str]) -> bool | None:
    """Parse the deliberately tiny, closed doctor command line."""

    arguments = tuple(argv)
    if not arguments:
        return False
    if arguments == ("--formal",):
        return True
    print("usage: doctor.py [--formal]", file=sys.stderr)
    return None


def main(argv: Sequence[str] | None = None) -> int:
    """Check the fast Rust lane and, only when requested, formal Java."""

    formal_requested = _requested_formal_lane(sys.argv[1:] if argv is None else argv)
    if formal_requested is None:
        return 2

    try:
        config = _load_configuration(include_formal=formal_requested)
    except (
        ConfigurationError,
        OSError,
        tomllib.TOMLDecodeError,
        UnicodeError,
    ) as error:
        print(
            f"FAIL repository configuration: {type(error).__name__}: {error}",
            file=sys.stderr,
        )
        return 1

    cargo = _probe_rust(config.rust_channel, "cargo", "--version")
    rustc = _probe_rust(config.rust_channel, "rustc", "--version")
    rustfmt = _probe_rust(config.rust_channel, "rustfmt", "--version")
    clippy = _probe_rust(config.rust_channel, "cargo-clippy", "--version")
    rustc_commit = _matched_group(rustc, RUSTC_VERSION_PATTERN, "commit")
    component_commit = rustc_commit or "<invalid-rustc-identity>"

    locked_workspace = _probe_rust(
        config.rust_channel,
        "cargo",
        "metadata",
        "--locked",
        "--offline",
        "--format-version",
        "1",
        output_limit_bytes=METADATA_OUTPUT_LIMIT_BYTES,
    )
    if locked_workspace.ok:
        locked_workspace = CommandResult(True, "resolved with --locked --offline")

    checks = [
        required("python", CommandResult(True, sys.version.split()[0])),
        required("git", probe("git", "--version")),
        required(
            "cargo",
            cargo,
            OutputExpectation(
                f"exact cargo {config.rust_channel} version line",
                CARGO_VERSION_PATTERN,
                config.rust_channel,
            ),
        ),
        required(
            "rustc",
            rustc,
            OutputExpectation(
                f"exact rustc {config.rust_channel} version line",
                RUSTC_VERSION_PATTERN,
                config.rust_channel,
            ),
        ),
        required(
            "rustfmt",
            rustfmt,
            OutputExpectation(
                "an exact rustfmt version line from the selected rustc commit",
                RUSTFMT_VERSION_PATTERN,
                expected_commit=component_commit,
            ),
        ),
        required(
            "clippy",
            clippy,
            OutputExpectation(
                "an exact clippy version line from the selected rustc commit",
                CLIPPY_VERSION_PATTERN,
                _clippy_version_for(config.rust_channel),
                component_commit,
            ),
        ),
        required("locked workspace", locked_workspace),
    ]

    optional("just recipes", probe("just", "--version"))
    optional(
        "cargo-deny supply-chain lane",
        probe("cargo-deny", "--version"),
        OutputExpectation(
            f"exact cargo-deny {config.cargo_deny_version} version line",
            CARGO_DENY_VERSION_PATTERN,
            config.cargo_deny_version,
        ),
    )
    optional("GitHub CLI availability", probe("gh", "--version"))

    if formal_requested:
        java_version = config.java_specification_version
        if java_version is None:
            print(
                "FAIL repository configuration: missing formal Java pin",
                file=sys.stderr,
            )
            return 1
        checks.append(
            required(
                "formal Java specification",
                probe("java", "-version"),
                OutputExpectation(
                    f"Java specification version {java_version}",
                    JAVA_VERSION_PATTERN,
                    java_version,
                ),
            )
        )

    if all(checks):
        print("doctor: core development prerequisites are ready")
        print(
            "doctor: INFO optional tools do not establish the pinned hosted "
            "supply-chain environment"
        )
        if formal_requested:
            print(
                "doctor: formal Java major is present; the TLA+ runner separately "
                "verifies exact vendor, runtime, architecture, jar, and model inputs"
            )
        return 0
    print("doctor: required development prerequisites are not ready", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
