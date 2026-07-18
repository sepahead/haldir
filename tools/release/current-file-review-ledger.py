#!/usr/bin/env python3
"""Generate and verify the fail-closed current-head file review ledger.

The ledger is an inventory and review worksheet, not proof that review occurred.
It binds each path to both a declared Git source commit and the current index /
worktree view.  Generation and verification use only the Python standard library
and local Git objects.

Capture-time verification reconciles the live index and worktree.  Retention
verification instead accepts an exact implementation commit, reconstructs that
snapshot in an isolated local clone, binds the verified ledger bytes to the exact
captured current-HEAD blob, and permits only the ledger's enumerated review fields
to evolve in later linear protocol commits.

The ledger contains an explicit row for its own repository path.  Its current
bytes are marked self-referential (a file cannot contain its own digest); the
generator and verifier instead report the ledger SHA-256 for retention in task
evidence.  If a prior ledger exists in the declared source commit, that source
blob identity remains recorded normally.

Create-once publication requires successful ``os.fsync`` calls for the temporary
file and affected directories.  Those calls and subsequent namespace checks are
the declared completion boundary; they do not claim a physical-media flush or
power-loss guarantee.  In particular, the Python standard library does not expose
Darwin's stronger ``F_FULLFSYNC`` operation.  A filesystem that rejects directory
``fsync`` is unsupported and generation fails closed before publication.
"""

from __future__ import annotations

import argparse
import ctypes
import csv
import errno
import hashlib
import io
import json
import math
import os
import re
import secrets
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unicodedata
from dataclasses import dataclass, field as dataclass_field
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Iterable, Sequence


SCHEMA_VERSION = "1.0.0"
GIT_EXECUTABLE = "/usr/bin/git"
DEFAULT_MAX_ROWS = 10_000
HARD_MAX_ROWS = 10_000
DEFAULT_MAX_FILE_BYTES = 64 * 1024 * 1024
HARD_MAX_FILE_BYTES = 256 * 1024 * 1024
DEFAULT_MAX_TOTAL_BYTES = 512 * 1024 * 1024
HARD_MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
MAX_GIT_INVENTORY_BYTES = 64 * 1024 * 1024
MAX_GIT_STDERR_BYTES = 64 * 1024
MAX_LEDGER_BYTES = 4 * 1024 * 1024
MAX_PATH_BYTES = 4096
MAX_CELL_BYTES = 16 * 1024
MAX_ENUM_CELL_BYTES = 128
MAX_DECIMAL_CELL_BYTES = 32
MAX_IDENTITY_CELL_BYTES = 4096
GIT_TIMEOUT_SECONDS = 60.0
GIT_CHILD_UMASK = 0o022
DEFAULT_MAX_SECONDS = 300.0
HARD_MAX_SECONDS = 3600.0
MAX_GIT_BLOB_READS = 20_000
FILESYSTEM_NODE_MULTIPLIER = 4
IGNORED_POLICIES = frozenset({"inventory", "reject"})

HEX_OID = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
INDEX_DEBUG_RECORD = re.compile(
    rb"  ctime: [0-9]+:[0-9]+\n"
    rb"  mtime: [0-9]+:[0-9]+\n"
    rb"  dev: [0-9]+\tino: [0-9]+\n"
    rb"  uid: [0-9]+\tgid: [0-9]+\n"
    rb"  size: [0-9]+\tflags: ([0-9A-Fa-f]+)\n"
)
RFC3339_UTC = re.compile(
    r"^[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])"
    r"T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$"
)
TEMPORARY_BASENAME = re.compile(r"^\.haldir-ledger-tmp-[1-9][0-9]*-[0-9a-f]{16}$")

FIELDS = (
    "schema_version",
    "source_commit",
    "source_tree",
    "object_format",
    "ignored_policy",
    "inventory_digest",
    "inventory_rows",
    "source_inventory_digest",
    "index_inventory_digest",
    "untracked_inventory_digest",
    "ignored_inventory_digest",
    "filesystem_inventory_digest",
    "filesystem_entries",
    "ledger_self_path",
    "path",
    "source_tracked",
    "source_git_mode",
    "source_object_type",
    "source_git_blob_id",
    "source_sha256",
    "source_bytes",
    "source_lines",
    "source_content_kind",
    "index_tracked",
    "index_git_mode",
    "index_git_blob_id",
    "index_flags",
    "index_sha256",
    "index_bytes",
    "index_lines",
    "index_content_kind",
    "source_index_state",
    "current_scope",
    "current_fs_type",
    "current_fs_mode",
    "current_git_blob_id",
    "current_sha256",
    "current_bytes",
    "current_lines",
    "current_content_kind",
    "worktree_state",
    "ignore_rule_source",
    "ignore_pattern",
    "generated_candidate_reason",
    "category",
    "provenance_class",
    # Compatibility columns required by the handoff review-packet tooling.
    "git_blob_id",
    "sha256",
    "bytes",
    "lines",
    "language",
    "format",
    # Human-maintained review columns begin here.
    "generated",
    "generator",
    "public_surface",
    "security_critical",
    "science_critical",
    "authority_critical",
    "provenance_review_status",
    "provenance_evidence",
    "license_review_status",
    "license_expression",
    "license_evidence",
    "reviewer",
    "review_status",
    "requirements",
    "assumptions",
    "defects",
    "tests",
    "evidence",
    "disposition",
    "completed_at",
)

MUTABLE_FIELDS = frozenset(
    {
        "generated",
        "generator",
        "public_surface",
        "security_critical",
        "science_critical",
        "authority_critical",
        "provenance_review_status",
        "provenance_evidence",
        "license_review_status",
        "license_expression",
        "license_evidence",
        "reviewer",
        "review_status",
        "requirements",
        "assumptions",
        "defects",
        "tests",
        "evidence",
        "disposition",
        "completed_at",
    }
)
IMMUTABLE_FIELDS = tuple(field for field in FIELDS if field not in MUTABLE_FIELDS)
DIGEST_FIELDS = tuple(
    field for field in IMMUTABLE_FIELDS if field != "inventory_digest"
)

FIELD_BYTE_LIMITS = {field: MAX_CELL_BYTES for field in FIELDS}
FIELD_BYTE_LIMITS.update(
    {
        field: MAX_ENUM_CELL_BYTES
        for field in (
            "schema_version",
            "object_format",
            "ignored_policy",
            "source_tracked",
            "source_git_mode",
            "source_object_type",
            "source_lines",
            "source_content_kind",
            "index_tracked",
            "index_git_mode",
            "index_flags",
            "index_lines",
            "index_content_kind",
            "source_index_state",
            "current_scope",
            "current_fs_type",
            "current_fs_mode",
            "current_lines",
            "current_content_kind",
            "worktree_state",
            "category",
            "provenance_class",
            "lines",
            "language",
            "format",
            "generated",
            "public_surface",
            "security_critical",
            "science_critical",
            "authority_critical",
            "provenance_review_status",
            "license_review_status",
            "review_status",
            "completed_at",
        )
    }
)
FIELD_BYTE_LIMITS.update(
    {
        field: MAX_DECIMAL_CELL_BYTES
        for field in (
            "inventory_rows",
            "filesystem_entries",
            "source_bytes",
            "index_bytes",
            "current_bytes",
            "bytes",
        )
    }
)
FIELD_BYTE_LIMITS.update(
    {
        field: MAX_IDENTITY_CELL_BYTES
        for field in (
            "ledger_self_path",
            "path",
            "ignore_rule_source",
            "ignore_pattern",
            "generated_candidate_reason",
            "generator",
            "license_expression",
            "reviewer",
            "disposition",
        )
    }
)

TRISTATE = frozenset({"UNKNOWN", "YES", "NO"})
REVIEW_STATUSES = frozenset(
    {"UNREVIEWED", "IN_REVIEW", "REVIEWED", "BLOCKED", "NOT_APPLICABLE"}
)
PROVENANCE_STATUSES = frozenset(
    {"UNREVIEWED", "CONFIRMED", "REJECTED", "NOT_APPLICABLE"}
)
LICENSE_STATUSES = frozenset({"UNREVIEWED", "APPROVED", "REJECTED", "NOT_APPLICABLE"})

LANGUAGE_BY_NAME = {
    ".gitignore": "GITIGNORE",
    ".ncp-consumer": "NCP_CONSUMER_MARKER",
    "allowed-signers": "SSH_ALLOWED_SIGNERS",
    "cargo.lock": "TOML_LOCK",
    "cargo.toml": "TOML",
    "deny.toml": "TOML",
    "dockerfile": "DOCKERFILE",
    "justfile": "JUST",
    "license": "LICENSE_TEXT",
    "license-apache": "LICENSE_TEXT",
    "license-mit": "LICENSE_TEXT",
    "makefile": "MAKE",
    "readme": "TEXT",
    "security.md": "MARKDOWN",
}
LANGUAGE_BY_SUFFIX = {
    ".bash": "SHELL",
    ".bin": "BINARY_DATA",
    ".c": "C",
    ".cc": "CPP",
    ".cfg": "CONFIG",
    ".dockerignore": "DOCKERIGNORE",
    ".cpp": "CPP",
    ".css": "CSS",
    ".dat": "BINARY_DATA",
    ".csv": "CSV",
    ".h": "C_HEADER",
    ".hpp": "CPP_HEADER",
    ".html": "HTML",
    ".js": "JAVASCRIPT",
    ".json": "JSON",
    ".json5": "JSON5",
    ".jsonl": "JSON_LINES",
    ".lock": "LOCKFILE",
    ".log": "LOG_TEXT",
    ".md": "MARKDOWN",
    ".pem": "PEM",
    ".proto": "PROTOBUF",
    ".py": "PYTHON",
    ".rs": "RUST",
    ".rst": "RESTRUCTURED_TEXT",
    ".sh": "SHELL",
    ".svg": "SVG",
    ".sha256": "SHA256SUMS",
    ".tla": "TLA_PLUS",
    ".toml": "TOML",
    ".ts": "TYPESCRIPT",
    ".tsx": "TYPESCRIPT_TSX",
    ".txt": "TEXT",
    ".xml": "XML",
    ".yaml": "YAML",
    ".yml": "YAML",
    ".zsh": "SHELL",
    ".gz": "GZIP",
    ".hex": "HEX",
    ".zip": "ZIP",
}
GENERATED_COMPONENTS = frozenset(
    {
        "build",
        "coverage",
        "dist",
        "gen",
        "generated",
        "node_modules",
        "out",
        "target",
    }
)
BINARY_LANGUAGES = frozenset({"BINARY_DATA", "GZIP", "ZIP"})


class LedgerError(RuntimeError):
    """A fail-closed inventory or ledger validation error."""


class ConcurrentWriterError(LedgerError):
    """The target changed after capture and the competing state was preserved."""


class _AtomicRenameUnavailableError(LedgerError):
    """The required rename primitive had a proven non-publication outcome."""

    def __init__(
        self,
        message: str,
        *,
        native_call_attempted: bool = False,
    ) -> None:
        super().__init__(message)
        self.native_call_attempted = native_call_attempted


class CreationIncompleteError(LedgerError):
    """A rename was attempted or creation succeeded without full reconciliation."""

    def __init__(
        self,
        message: str,
        *,
        target_creation_confirmed: bool = False,
        canonical_creation_verified: bool = False,
    ) -> None:
        super().__init__(message)
        self.target_creation_confirmed = (
            target_creation_confirmed or canonical_creation_verified
        )
        self.canonical_creation_verified = canonical_creation_verified


@dataclass
class _OwnedDescriptor:
    descriptor: int = -1

    def close(self) -> None:
        if self.descriptor >= 0:
            previous_mask = signal.pthread_sigmask(
                signal.SIG_BLOCK,
                {signal.SIGINT},
            )
            try:
                descriptor = self.descriptor
                self.descriptor = -1
                os.close(descriptor)
            finally:
                signal.pthread_sigmask(
                    signal.SIG_SETMASK,
                    previous_mask,
                )

    def transfer_to(self, target: object, attribute: str) -> None:
        if self.descriptor < 0:
            raise LedgerError("descriptor ownership was already transferred")
        previous_mask = signal.pthread_sigmask(
            signal.SIG_BLOCK,
            {signal.SIGINT},
        )
        try:
            setattr(target, attribute, self.descriptor)
            self.descriptor = -1
        finally:
            # A pending SIGINT may be raised by this restoration call.  At that
            # point the target already owns the descriptor, so callers can close
            # the target deterministically without relying on traceback lifetime
            # or garbage collection.
            signal.pthread_sigmask(
                signal.SIG_SETMASK,
                previous_mask,
            )

    def __enter__(self) -> _OwnedDescriptor:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except BaseException:
            pass


@dataclass(frozen=True)
class SourceEntry:
    mode: str
    object_type: str
    oid: str
    size: int | None


@dataclass(frozen=True)
class IndexEntry:
    mode: str
    oid: str
    flags: str


@dataclass(frozen=True)
class ContentIdentity:
    fs_type: str
    fs_mode: str
    git_mode: str
    git_blob_id: str
    sha256: str
    size: str
    lines: str
    content_kind: str


@dataclass(frozen=True)
class RegularSnapshot:
    device: int
    inode: int
    mode: int
    data: bytes
    stat_identity: tuple[int, int, int, int, int, int, int] = dataclass_field(
        compare=False,
        repr=False,
    )

    def matches_stat(self, value: os.stat_result) -> bool:
        return (
            self.device == value.st_dev
            and self.inode == value.st_ino
            and self.mode == value.st_mode
        )

    def matches_full_stat(self, value: os.stat_result) -> bool:
        return self.stat_identity == _stat_identity(value)


@dataclass
class PinnedRegularSnapshot:
    snapshot: RegularSnapshot
    descriptor: int

    def close(self) -> None:
        if self.descriptor >= 0:
            previous_mask = signal.pthread_sigmask(
                signal.SIG_BLOCK,
                {signal.SIGINT},
            )
            try:
                descriptor = self.descriptor
                self.descriptor = -1
                os.close(descriptor)
            finally:
                signal.pthread_sigmask(
                    signal.SIG_SETMASK,
                    previous_mask,
                )

    def __enter__(self) -> PinnedRegularSnapshot:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except BaseException:
            pass


@dataclass
class _OwnedTemporary:
    parent_descriptor: int
    name: str
    path: str
    descriptor: int
    expected_identity: tuple[int, int, int, int, int, int, int]
    snapshot: RegularSnapshot | None = None
    state: str = "OPEN"

    def record_owned_mutation(self) -> os.stat_result:
        current = os.fstat(self.descriptor)
        self.expected_identity = _stat_identity(current)
        return current

    def close(self) -> None:
        if self.descriptor < 0:
            return
        previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT})
        owner = _OwnedDescriptor()
        try:
            owner.descriptor = self.descriptor
            self.descriptor = -1
        finally:
            try:
                signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
            except BaseException:
                owner.close()
                raise
        owner.close()

    def mark_renamed(self) -> None:
        if self.state != "RENAME_OUTCOME_UNKNOWN":
            raise LedgerError("temporary has no pending creation rename")
        self.state = "RENAMED_UNSYNCED"

    def mark_rename_attempted(self) -> None:
        if self.state != "TEMP_FSYNCED":
            raise LedgerError("temporary is not ready for its creation rename")
        self.state = "RENAME_OUTCOME_UNKNOWN"


_DARWIN_RENAME_EXCL = 0x00000004
_LINUX_RENAME_NOREPLACE = 0x00000001
_ATOMIC_RENAME_UNSUPPORTED_ERRNOS = frozenset(
    {
        errno.ENOSYS,
        errno.EINVAL,
        getattr(errno, "ENOTSUP", errno.EINVAL),
        getattr(errno, "EOPNOTSUPP", errno.EINVAL),
    }
)


def _open_interrupt_safe(
    path: str | bytes | Path,
    flags: int,
    mode: int = 0o777,
    *,
    dir_fd: int | None = None,
) -> _OwnedDescriptor:
    if not hasattr(signal, "pthread_sigmask"):
        raise LedgerError("signal-masked descriptor acquisition is unavailable")
    previous_mask = signal.pthread_sigmask(
        signal.SIG_BLOCK,
        {signal.SIGINT},
    )
    owner = _OwnedDescriptor()
    try:
        owner.descriptor = os.open(path, flags, mode, dir_fd=dir_fd)
    finally:
        try:
            signal.pthread_sigmask(
                signal.SIG_SETMASK,
                previous_mask,
            )
        except BaseException:
            owner.close()
            raise
    return owner


def _duplicate_interrupt_safe(descriptor: int) -> _OwnedDescriptor:
    previous_mask = signal.pthread_sigmask(
        signal.SIG_BLOCK,
        {signal.SIGINT},
    )
    owner = _OwnedDescriptor()
    try:
        owner.descriptor = os.dup(descriptor)
    finally:
        try:
            signal.pthread_sigmask(
                signal.SIG_SETMASK,
                previous_mask,
            )
        except BaseException:
            owner.close()
            raise
    return owner


@dataclass
class ByteBudget:
    maximum: int
    used: int = 0

    def consume(self, count: int, label: str) -> None:
        if count < 0 or self.used > self.maximum - count:
            raise LedgerError(
                f"content byte budget exceeded while reading {label!r}: "
                f"limit={self.maximum}"
            )
        self.used += count


@dataclass(frozen=True)
class Deadline:
    ends_at: float

    @classmethod
    def after(cls, seconds: float) -> Deadline:
        return cls(time.monotonic() + seconds)

    def check(self, label: str) -> None:
        if time.monotonic() >= self.ends_at:
            raise LedgerError(f"inventory deadline exceeded while {label}")

    def timeout(self, maximum: float, label: str) -> float:
        remaining = self.ends_at - time.monotonic()
        if remaining <= 0:
            raise LedgerError(f"inventory deadline exceeded while {label}")
        return min(maximum, max(0.001, remaining))


def _bounded_int(value: int, *, name: str, lower: int, upper: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise LedgerError(f"{name} must be an integer")
    if not lower <= value <= upper:
        raise LedgerError(f"{name} must be in [{lower}, {upper}]")
    return value


def _bounded_float(value: float, *, name: str, lower: float, upper: float) -> float:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise LedgerError(f"{name} must be a finite number")
    result = float(value)
    if not math.isfinite(result) or not lower <= result <= upper:
        raise LedgerError(f"{name} must be finite and in [{lower:g}, {upper:g}]")
    return result


def _validate_path(path: str) -> str:
    if not isinstance(path, str) or not path:
        raise LedgerError("repository path must be a non-empty UTF-8 string")
    try:
        encoded = path.encode("utf-8", "strict")
    except UnicodeEncodeError as exc:
        raise LedgerError(f"repository path is not strict UTF-8: {path!r}") from exc
    if len(encoded) > MAX_PATH_BYTES:
        raise LedgerError(f"repository path exceeds {MAX_PATH_BYTES} bytes: {path!r}")
    if unicodedata.normalize("NFC", path) != path:
        raise LedgerError(f"repository path is not Unicode NFC: {path!r}")
    if "\\" in path or path.startswith("/"):
        raise LedgerError(f"repository path is not canonical POSIX-relative: {path!r}")
    if any(unicodedata.category(char).startswith("C") for char in path):
        raise LedgerError(
            f"repository path contains a Unicode category-C character: {path!r}"
        )
    pure = PurePosixPath(path)
    parts = pure.parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise LedgerError(
            f"repository path contains traversal or empty components: {path!r}"
        )
    if any(part.casefold() == ".git" for part in parts):
        raise LedgerError(
            f"repository path enters Git administrative storage: {path!r}"
        )
    if pure.as_posix() != path:
        raise LedgerError(f"repository path is not canonical: {path!r}")
    return path


def _validate_unique_paths(paths: Iterable[str], *, label: str) -> list[str]:
    result: list[str] = []
    exact: set[str] = set()
    portable: dict[str, str] = {}
    for candidate in paths:
        path = _validate_path(candidate)
        if path in exact:
            raise LedgerError(f"duplicate {label} path: {path!r}")
        collision_key = unicodedata.normalize("NFC", path).casefold()
        prior = portable.get(collision_key)
        if prior is not None and prior != path:
            raise LedgerError(
                f"portable Unicode/case path collision in {label}: {prior!r}, {path!r}"
            )
        exact.add(path)
        portable[collision_key] = path
        result.append(path)
    return result


def _safe_git_environment() -> dict[str, str]:
    return {
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_FLUSH": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_PAGER": "cat",
        "GIT_TERMINAL_PROMPT": "0",
        "HOME": "/nonexistent",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
        "XDG_CONFIG_HOME": "/nonexistent",
    }


def _git_command(repo: Path, arguments: Sequence[str]) -> list[str]:
    return [
        GIT_EXECUTABLE,
        "-c",
        "core.excludesFile=/dev/null",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.untrackedCache=false",
        "-C",
        os.fspath(repo),
        *arguments,
    ]


def _run_git(
    repo: Path,
    arguments: Sequence[str],
    *,
    max_stdout: int = MAX_GIT_INVENTORY_BYTES,
    timeout: float = GIT_TIMEOUT_SECONDS,
    deadline: Deadline | None = None,
    input_data: bytes | None = None,
    accepted_returncodes: frozenset[int] = frozenset({0}),
) -> bytes:
    """Run a local Git command with wall-clock and output bounds."""

    if not accepted_returncodes or any(
        not isinstance(value, int) for value in accepted_returncodes
    ):
        raise LedgerError("accepted Git return codes must be a non-empty integer set")
    if input_data is not None and len(input_data) > 4 * 1024 * 1024:
        raise LedgerError("Git stdin chunk exceeds 4 MiB")
    command_timeout = (
        deadline.timeout(timeout, f"running Git {arguments!r}")
        if deadline is not None
        else timeout
    )
    command_deadline = time.monotonic() + command_timeout
    command = _git_command(repo, arguments)
    input_stream = None
    try:
        if input_data is not None:
            input_stream = tempfile.TemporaryFile()
            input_stream.write(input_data)
            input_stream.flush()
            input_stream.seek(0)
            if deadline is not None:
                deadline.check(f"preparing Git input for {arguments!r}")
        process = subprocess.Popen(
            command,
            stdin=input_stream if input_stream is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_safe_git_environment(),
            umask=GIT_CHILD_UMASK,
        )
    except BaseException:
        if input_stream is not None:
            input_stream.close()
        raise
    assert process.stdout is not None
    assert process.stderr is not None
    selector = selectors.DefaultSelector()
    stdout = bytearray()
    stderr = bytearray()
    try:
        selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        while selector.get_map():
            remaining = command_deadline - time.monotonic()
            if remaining <= 0:
                raise LedgerError(
                    f"Git command timed out after {command_timeout:g}s: {arguments!r}"
                )
            events = selector.select(remaining)
            if not events:
                continue
            for key, _ in events:
                chunk = os.read(key.fd, 64 * 1024)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                target = stdout if key.data == "stdout" else stderr
                limit = max_stdout if key.data == "stdout" else MAX_GIT_STDERR_BYTES
                if len(target) > limit - len(chunk):
                    raise LedgerError(
                        f"Git {key.data} exceeded {limit} bytes: {arguments!r}"
                    )
                target.extend(chunk)
        remaining = max(0.001, command_deadline - time.monotonic())
        try:
            return_code = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired as exc:
            raise LedgerError(
                f"Git command timed out after {command_timeout:g}s: {arguments!r}"
            ) from exc
    except BaseException:
        if process.poll() is None:
            process.kill()
            process.wait()
        raise
    finally:
        try:
            selector.close()
        finally:
            try:
                process.stdout.close()
            finally:
                try:
                    process.stderr.close()
                finally:
                    if input_stream is not None:
                        input_stream.close()
    if return_code not in accepted_returncodes:
        detail = stderr.decode("utf-8", "replace").strip()
        raise LedgerError(
            f"Git command failed with exit {return_code}: {arguments!r}"
            + (f": {detail}" if detail else "")
        )
    return bytes(stdout)


def _run_git_input(
    repo: Path,
    arguments: Sequence[str],
    input_data: bytes,
    *,
    max_stdout: int,
    timeout: float = GIT_TIMEOUT_SECONDS,
    deadline: Deadline | None = None,
) -> bytes:
    return _run_git(
        repo,
        arguments,
        max_stdout=max_stdout,
        timeout=timeout,
        deadline=deadline,
        input_data=input_data,
    )


def _parse_git_toplevel(raw: bytes) -> Path:
    """Parse one bounded, canonical absolute path from ``git rev-parse``."""

    if len(raw) > MAX_PATH_BYTES + 1:
        raise LedgerError(f"Git top-level path exceeds {MAX_PATH_BYTES} bytes")
    if not raw.endswith(b"\n") or raw.count(b"\n") != 1 or b"\0" in raw:
        raise LedgerError("Git returned a malformed top-level path")
    try:
        text = raw[:-1].decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise LedgerError("Git top-level path is not strict UTF-8") from exc
    if (
        not text
        or unicodedata.normalize("NFC", text) != text
        or any(unicodedata.category(character).startswith("C") for character in text)
    ):
        raise LedgerError("Git returned a non-canonical top-level path")
    parsed = Path(text)
    if not parsed.is_absolute() or Path(os.path.abspath(text)) != parsed:
        raise LedgerError("Git top-level path is not canonical and absolute")
    return parsed


def _bind_git_toplevel(repo: Path, *, deadline: Deadline) -> Path:
    """Require the supplied repository root to equal Git's exact top level."""

    lexical = Path(os.path.abspath(os.fspath(repo)))
    try:
        lexical_stat = os.lstat(lexical)
    except OSError as exc:
        raise LedgerError(f"cannot stat repository root {lexical}: {exc}") from exc
    if stat.S_ISLNK(lexical_stat.st_mode) or not stat.S_ISDIR(lexical_stat.st_mode):
        raise LedgerError("repository root argument is not a real directory")
    raw = _run_git(
        lexical,
        ["rev-parse", "--path-format=absolute", "--show-toplevel"],
        max_stdout=MAX_PATH_BYTES + 1,
        deadline=deadline,
    )
    top_level = _parse_git_toplevel(raw)
    canonical = Path(os.path.realpath(lexical))
    if canonical != top_level:
        raise LedgerError(
            "repository path must equal Git's exact top-level worktree path"
        )
    try:
        root_stat = os.lstat(top_level)
    except OSError as exc:
        raise LedgerError(f"cannot stat repository root {top_level}: {exc}") from exc
    if (
        stat.S_ISLNK(root_stat.st_mode)
        or not stat.S_ISDIR(root_stat.st_mode)
        or (lexical_stat.st_dev, lexical_stat.st_ino)
        != (root_stat.st_dev, root_stat.st_ino)
    ):
        raise LedgerError("Git top-level worktree path is not a real directory")
    return top_level


def _atomic_rename_noreplace(
    source_dir_fd: int,
    source: str,
    destination_dir_fd: int,
    destination: str,
) -> None:
    """Atomically move one entry only when the destination remains absent."""

    try:
        library = ctypes.CDLL(None, use_errno=True)
    except OSError as exc:
        raise _AtomicRenameUnavailableError(
            "atomic no-replace rename is unavailable; refusing unsafe creation"
        ) from exc
    if sys.platform == "darwin":
        try:
            rename = library.renameatx_np
        except AttributeError as exc:
            raise _AtomicRenameUnavailableError(
                "atomic no-replace rename is unavailable; refusing unsafe creation"
            ) from exc
        rename.argtypes = (
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        )
        rename.restype = ctypes.c_int
        flags = _DARWIN_RENAME_EXCL
    elif sys.platform.startswith("linux"):
        try:
            rename = library.renameat2
        except AttributeError as exc:
            raise _AtomicRenameUnavailableError(
                "atomic no-replace rename is unavailable; refusing unsafe creation"
            ) from exc
        rename.argtypes = (
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        )
        rename.restype = ctypes.c_int
        flags = _LINUX_RENAME_NOREPLACE
    else:
        raise _AtomicRenameUnavailableError(
            "atomic no-replace rename is unsupported on this platform; refusing "
            "unsafe creation"
        )
    ctypes.set_errno(0)
    result = rename(
        source_dir_fd,
        os.fsencode(source),
        destination_dir_fd,
        os.fsencode(destination),
        flags,
    )
    if result != 0:
        error = ctypes.get_errno()
        failure = OSError(
            error,
            os.strerror(error),
            source,
            destination,
        )
        if error in _ATOMIC_RENAME_UNSUPPORTED_ERRNOS:
            raise _AtomicRenameUnavailableError(
                "the native atomic no-replace call reported an unsupported "
                "operation with no namespace effect",
                native_call_attempted=True,
            ) from failure
        raise failure


class SecureRepository:
    """Open worktree entries relative to a trusted root without following links."""

    def __init__(self, root: Path):
        self.root = Path(os.path.abspath(os.fspath(root)))
        self._root_fd: int | None = None

    def __enter__(self) -> SecureRepository:
        try:
            root_stat = os.lstat(self.root)
        except OSError as exc:
            raise LedgerError(
                f"cannot stat repository root {self.root}: {exc}"
            ) from exc
        if stat.S_ISLNK(root_stat.st_mode) or not stat.S_ISDIR(root_stat.st_mode):
            raise LedgerError("repository root must be a real directory, not a symlink")
        flags = (
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        )
        root_owner: _OwnedDescriptor | None = None
        try:
            try:
                root_owner = _open_interrupt_safe(self.root, flags)
            except OSError as exc:
                raise LedgerError(
                    f"cannot securely open repository root {self.root}: {exc}"
                ) from exc
            root_owner.transfer_to(self, "_root_fd")
            assert self._root_fd is not None
            opened = os.fstat(self._root_fd)
            if _stat_identity(root_stat) != _stat_identity(opened):
                raise LedgerError("repository root changed while it was being opened")
            return self
        except BaseException:
            if root_owner is not None:
                root_owner.close()
            self.__exit__(BaseException, None, None)
            raise

    def __exit__(
        self,
        exception_type: type[BaseException] | None = None,
        _exception: BaseException | None = None,
        _traceback: object = None,
    ) -> None:
        binding_lost = (
            self._root_fd is not None and not self._root_descriptor_matches_path()
        )
        if self._root_fd is not None:
            owner = _OwnedDescriptor()
            try:
                previous_mask = signal.pthread_sigmask(
                    signal.SIG_BLOCK,
                    {signal.SIGINT},
                )
                try:
                    owner.descriptor = self._root_fd
                    self._root_fd = None
                finally:
                    signal.pthread_sigmask(
                        signal.SIG_SETMASK,
                        previous_mask,
                    )
            finally:
                owner.close()
        if binding_lost and exception_type is None:
            raise ConcurrentWriterError(
                "repository root changed while the secure view was active"
            )

    def __del__(self) -> None:
        try:
            self.__exit__()
        except BaseException:
            pass

    @property
    def root_fd(self) -> int:
        if self._root_fd is None:
            raise LedgerError("secure repository is not open")
        return self._root_fd

    def _root_descriptor_matches_path(self) -> bool:
        try:
            opened = os.fstat(self.root_fd)
            current = os.stat(self.root, follow_symlinks=False)
        except OSError:
            return False
        return stat.S_ISDIR(opened.st_mode) and _stat_identity(
            opened
        ) == _stat_identity(current)

    def _open_parent(
        self,
        path: str,
        *,
        create: bool = False,
    ) -> tuple[_OwnedDescriptor, str]:
        parts = _validate_path(path).split("/")
        current: _OwnedDescriptor | None = None
        child: _OwnedDescriptor | None = None
        directory_flags = (
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            if not self._root_descriptor_matches_path():
                raise ConcurrentWriterError(
                    "repository root lost its canonical pathname binding"
                )
            current = _duplicate_interrupt_safe(self.root_fd)
            for component in parts[:-1]:
                try:
                    before = os.stat(
                        component,
                        dir_fd=current.descriptor,
                        follow_symlinks=False,
                    )
                except FileNotFoundError:
                    if not create:
                        raise
                    os.mkdir(component, 0o755, dir_fd=current.descriptor)
                    before = os.stat(
                        component,
                        dir_fd=current.descriptor,
                        follow_symlinks=False,
                    )
                if not stat.S_ISDIR(before.st_mode):
                    raise OSError(
                        f"parent component is not a real directory: {component!r}"
                    )
                child = _open_interrupt_safe(
                    component,
                    directory_flags,
                    dir_fd=current.descriptor,
                )
                opened = os.fstat(child.descriptor)
                current_entry = os.stat(
                    component,
                    dir_fd=current.descriptor,
                    follow_symlinks=False,
                )
                if _stat_identity(before) != _stat_identity(opened) or _stat_identity(
                    opened
                ) != _stat_identity(current_entry):
                    child.close()
                    raise ConcurrentWriterError(
                        f"parent component changed while opening {path!r}: "
                        f"{component!r}"
                    )
                if create:
                    # A directory becomes eligible as a creation namespace only
                    # after fsync succeeds for it and its containing directory.
                    # Re-sync reused components because an earlier failed parent
                    # fsync may have left a visible link outside this boundary.
                    # No physical-media or power-loss guarantee is claimed.
                    try:
                        os.fsync(child.descriptor)
                        os.fsync(current.descriptor)
                    except OSError as exc:
                        child.close()
                        raise LedgerError(
                            "required directory fsync is unavailable "
                            f"while preparing {path!r}: {component!r}: {exc}"
                        ) from exc
                    except BaseException:
                        child.close()
                        raise
                    current_entry = os.stat(
                        component,
                        dir_fd=current.descriptor,
                        follow_symlinks=False,
                    )
                    if _stat_identity(opened) != _stat_identity(current_entry):
                        child.close()
                        raise ConcurrentWriterError(
                            "parent component changed during fsync "
                            f"synchronization for {path!r}: {component!r}"
                        )
                current.close()
                current = child
                child = None
            assert current is not None
            if not self._root_descriptor_matches_path():
                raise ConcurrentWriterError(
                    "repository root changed while opening a parent directory"
                )
            return current, parts[-1]
        except OSError as exc:
            try:
                if child is not None:
                    child.close()
            finally:
                if current is not None:
                    current.close()
            raise LedgerError(
                f"unsafe or unavailable parent component for {path!r}: {exc}"
            ) from exc
        except BaseException:
            try:
                if child is not None:
                    child.close()
            finally:
                if current is not None:
                    current.close()
            raise

    def lstat(self, path: str) -> os.stat_result | None:
        try:
            parent_owner, name = self._open_parent(path)
        except LedgerError as exc:
            if isinstance(exc.__cause__, FileNotFoundError):
                return None
            raise
        try:
            try:
                return os.stat(
                    name,
                    dir_fd=parent_owner.descriptor,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                return None
            except OSError as exc:
                raise LedgerError(
                    f"cannot lstat worktree path {path!r}: {exc}"
                ) from exc
        finally:
            parent_owner.close()

    def creation_restart_state(
        self,
        path: str,
        *,
        deadline: Deadline,
    ) -> tuple[os.stat_result | None, tuple[str, ...]]:
        """Capture the canonical target and reserved sibling names without mutation."""

        try:
            parent_owner, name = self._open_parent(path)
        except LedgerError as exc:
            if isinstance(exc.__cause__, FileNotFoundError):
                return None, ()
            raise

        def target_stat(parent_fd: int) -> os.stat_result | None:
            try:
                return os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                return None

        def reserved_names(parent_fd: int) -> tuple[str, ...]:
            directory_flags = (
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            scan_owner = _open_interrupt_safe(
                ".",
                directory_flags,
                dir_fd=parent_fd,
            )
            try:
                if _stat_identity(os.fstat(scan_owner.descriptor)) != _stat_identity(
                    os.fstat(parent_fd)
                ):
                    raise ConcurrentWriterError(
                        "restart-state scan opened a different parent directory"
                    )
                with os.scandir(scan_owner.descriptor) as iterator:
                    return tuple(
                        sorted(
                            (
                                entry.name
                                for entry in iterator
                                if TEMPORARY_BASENAME.fullmatch(entry.name)
                            ),
                            key=lambda value: value.encode("utf-8"),
                        )
                    )
            finally:
                scan_owner.close()

        try:
            parent_fd = parent_owner.descriptor
            deadline.check(f"capturing create-once restart state for {path!r}")
            before = target_stat(parent_fd)
            first_reserved = reserved_names(parent_fd)
            deadline.check(f"revalidating create-once restart state for {path!r}")
            second_reserved = reserved_names(parent_fd)
            after = target_stat(parent_fd)
            target_changed = (before is None) != (after is None)
            if before is not None and after is not None:
                target_changed = target_changed or _stat_identity(
                    before
                ) != _stat_identity(after)
            if target_changed or first_reserved != second_reserved:
                raise ConcurrentWriterError(
                    f"create-once restart state changed while inspecting {path!r}"
                )
            if not self._parent_descriptor_matches_path(parent_fd, path):
                raise ConcurrentWriterError(
                    "create-once restart-state parent lost its canonical binding"
                )
            return before, tuple(
                self._sibling_path(path, temporary_name)
                for temporary_name in first_reserved
            )
        except OSError as exc:
            raise LedgerError(
                f"cannot inspect create-once restart state for {path!r}: {exc}"
            ) from exc
        finally:
            parent_owner.close()

    def walk_leaf_paths(
        self, *, index_gitlinks: set[str], max_nodes: int, deadline: Deadline
    ) -> tuple[list[str], int]:
        """Walk the worktree independently of Git without following symlinks."""

        max_nodes = _bounded_int(
            max_nodes,
            name="max_nodes",
            lower=1,
            upper=HARD_MAX_ROWS * FILESYSTEM_NODE_MULTIPLIER,
        )
        pending = [""]
        leaves: list[str] = []
        observed_nodes = 0
        directory_flags = (
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        )
        while pending:
            deadline.check("walking the independent filesystem view")
            prefix = pending.pop()
            if prefix:
                parent_owner, name = self._open_parent(prefix)
                directory_owner: _OwnedDescriptor | None = None
                try:
                    before = os.stat(
                        name,
                        dir_fd=parent_owner.descriptor,
                        follow_symlinks=False,
                    )
                    if not stat.S_ISDIR(before.st_mode):
                        raise LedgerError(
                            f"filesystem directory changed type while walking {prefix!r}"
                        )
                    directory_owner = _open_interrupt_safe(
                        name,
                        directory_flags,
                        dir_fd=parent_owner.descriptor,
                    )
                    opened = os.fstat(directory_owner.descriptor)
                    if _stat_identity(before) != _stat_identity(opened):
                        directory_owner.close()
                        directory_owner = None
                        raise LedgerError(f"directory changed while opening {prefix!r}")
                except OSError as exc:
                    if directory_owner is not None:
                        directory_owner.close()
                    raise LedgerError(
                        f"cannot securely open filesystem directory {prefix!r}: {exc}"
                    ) from exc
                finally:
                    parent_owner.close()
                assert directory_owner is not None
            else:
                directory_owner = _duplicate_interrupt_safe(self.root_fd)
            try:
                validated: list[tuple[bytes, str, str]] = []
                try:
                    with os.scandir(directory_owner.descriptor) as iterator:
                        for entry in iterator:
                            deadline.check("classifying independent filesystem entries")
                            if not prefix and entry.name == ".git":
                                continue
                            observed_nodes += 1
                            if observed_nodes > max_nodes:
                                raise LedgerError(
                                    "independent filesystem walk exceeds node limit "
                                    f"{max_nodes}"
                                )
                            path = (
                                entry.name if not prefix else f"{prefix}/{entry.name}"
                            )
                            path = _validate_path(path)
                            validated.append((path.encode("utf-8"), entry.name, path))
                except OSError as exc:
                    raise LedgerError(
                        f"cannot independently walk worktree directory {prefix!r}: {exc}"
                    ) from exc
                validated.sort(key=lambda item: item[0])
                for _encoded, name, path in validated:
                    try:
                        before = os.stat(
                            name,
                            dir_fd=directory_owner.descriptor,
                            follow_symlinks=False,
                        )
                    except OSError as exc:
                        raise LedgerError(
                            f"cannot lstat filesystem entry {path!r}: {exc}"
                        ) from exc
                    if stat.S_ISDIR(before.st_mode) and path not in index_gitlinks:
                        pending.append(path)
                    else:
                        leaves.append(path)
            finally:
                directory_owner.close()
        _validate_unique_paths(leaves, label="independent filesystem")
        leaves.sort(key=lambda value: value.encode("utf-8"))
        return leaves, observed_nodes

    def read_entry(
        self,
        path: str,
        *,
        object_format: str,
        max_file_bytes: int,
        budget: ByteBudget,
        deadline: Deadline,
    ) -> ContentIdentity | None:
        deadline.check(f"opening worktree entry {path!r}")
        try:
            parent_owner, name = self._open_parent(path)
        except LedgerError as exc:
            # A tracked path whose parent was removed is an auditable deletion.
            # A symlink/non-directory parent remains a hard error.
            if isinstance(exc.__cause__, FileNotFoundError):
                return None
            raise
        try:
            try:
                before = os.stat(
                    name,
                    dir_fd=parent_owner.descriptor,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                return None
            mode = before.st_mode
            mode_string = f"{mode & 0o177777:06o}"
            if stat.S_ISLNK(mode):
                try:
                    target = os.readlink(
                        name,
                        dir_fd=parent_owner.descriptor,
                    )
                    after = os.stat(
                        name,
                        dir_fd=parent_owner.descriptor,
                        follow_symlinks=False,
                    )
                except OSError as exc:
                    raise LedgerError(
                        f"cannot securely read symlink {path!r}: {exc}"
                    ) from exc
                if _stat_identity(before) != _stat_identity(after):
                    raise LedgerError(f"symlink changed while inventorying {path!r}")
                data = os.fsencode(target)
                if len(data) > max_file_bytes:
                    raise LedgerError(f"symlink target exceeds file bound for {path!r}")
                budget.consume(len(data), path)
                return _content_identity(
                    data,
                    object_format=object_format,
                    fs_type="SYMLINK",
                    fs_mode=mode_string,
                    git_mode="120000",
                    forced_kind="SYMLINK_TARGET_BYTES",
                )
            if stat.S_ISREG(mode):
                if before.st_size < 0 or before.st_size > max_file_bytes:
                    raise LedgerError(
                        f"regular file exceeds {max_file_bytes} bytes: {path!r}"
                    )
                budget.consume(before.st_size, path)
                flags = (
                    os.O_RDONLY
                    | getattr(os, "O_NOFOLLOW", 0)
                    | getattr(os, "O_NONBLOCK", 0)
                )
                try:
                    descriptor_owner = _open_interrupt_safe(
                        name,
                        flags,
                        dir_fd=parent_owner.descriptor,
                    )
                except OSError as exc:
                    raise LedgerError(
                        f"cannot securely open regular file {path!r}: {exc}"
                    ) from exc
                try:
                    opened = os.fstat(descriptor_owner.descriptor)
                    if not stat.S_ISREG(opened.st_mode):
                        raise LedgerError(
                            f"file changed to a non-regular type while opening {path!r}"
                        )
                    if _stat_identity(before) != _stat_identity(opened):
                        raise LedgerError(f"file changed while opening {path!r}")
                    chunks: list[bytes] = []
                    remaining = before.st_size
                    while remaining:
                        deadline.check(f"reading worktree entry {path!r}")
                        chunk = os.read(
                            descriptor_owner.descriptor,
                            min(1024 * 1024, remaining),
                        )
                        if not chunk:
                            raise LedgerError(
                                f"file truncated while inventorying {path!r}"
                            )
                        chunks.append(chunk)
                        remaining -= len(chunk)
                    if os.read(descriptor_owner.descriptor, 1):
                        raise LedgerError(f"file grew while inventorying {path!r}")
                    after = os.fstat(descriptor_owner.descriptor)
                    try:
                        path_after = os.stat(
                            name,
                            dir_fd=parent_owner.descriptor,
                            follow_symlinks=False,
                        )
                    except OSError as exc:
                        raise LedgerError(
                            f"file path changed while inventorying {path!r}: {exc}"
                        ) from exc
                finally:
                    descriptor_owner.close()
                if _stat_identity(after) != _stat_identity(path_after):
                    raise LedgerError(f"file path changed while inventorying {path!r}")
                if _stat_identity(before) != _stat_identity(after):
                    raise LedgerError(f"file changed while inventorying {path!r}")
                data = b"".join(chunks)
                git_mode = "100755" if mode & 0o111 else "100644"
                return _content_identity(
                    data,
                    object_format=object_format,
                    fs_type="REGULAR",
                    fs_mode=mode_string,
                    git_mode=git_mode,
                )
            if stat.S_ISDIR(mode):
                fs_type = "DIRECTORY"
            elif stat.S_ISFIFO(mode):
                fs_type = "FIFO"
            elif stat.S_ISSOCK(mode):
                fs_type = "SOCKET"
            elif stat.S_ISCHR(mode):
                fs_type = "CHAR_DEVICE"
            elif stat.S_ISBLK(mode):
                fs_type = "BLOCK_DEVICE"
            else:
                fs_type = "SPECIAL"
            return ContentIdentity(
                fs_type=fs_type,
                fs_mode=mode_string,
                git_mode="",
                git_blob_id="",
                sha256="",
                size=str(before.st_size),
                lines="0",
                content_kind="NON_REGULAR_NO_CONTENT_READ",
            )
        finally:
            parent_owner.close()

    @staticmethod
    def _snapshot_descriptor(
        descriptor: int,
        *,
        label: str,
        maximum: int,
        deadline: Deadline,
    ) -> RegularSnapshot:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise LedgerError(f"ledger must be a regular file: {label}")
        if before.st_size < 0 or before.st_size > maximum:
            raise LedgerError(f"ledger exceeds {maximum} bytes")
        os.lseek(descriptor, 0, os.SEEK_SET)
        chunks: list[bytes] = []
        total = 0
        while True:
            deadline.check(f"reading ledger {label}")
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > maximum:
                raise LedgerError(f"ledger exceeds {maximum} bytes")
            chunks.append(chunk)
        after = os.fstat(descriptor)
        if _stat_identity(before) != _stat_identity(after):
            raise LedgerError(f"ledger changed while reading {label}")
        data = b"".join(chunks)
        if len(data) != after.st_size:
            raise LedgerError(f"ledger size changed while reading {label}")
        return RegularSnapshot(
            after.st_dev,
            after.st_ino,
            after.st_mode,
            data,
            _stat_identity(after),
        )

    def _pin_regular_at(
        self,
        parent_fd: int,
        name: str,
        *,
        label: str,
        maximum: int,
        deadline: Deadline,
    ) -> PinnedRegularSnapshot:
        deadline.check(f"opening ledger {label}")
        try:
            before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError as exc:
            raise LedgerError(f"ledger does not exist: {label}") from exc
        if not stat.S_ISREG(before.st_mode):
            raise LedgerError(f"ledger must be a regular file, not a symlink: {label}")
        if stat.S_IMODE(before.st_mode) != 0o644:
            raise LedgerError(f"ledger mode must be exactly 0644: {label}")
        if before.st_nlink != 1:
            raise LedgerError(f"ledger hard-link count must be exactly one: {label}")
        flags = (
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        )
        try:
            descriptor_owner = _open_interrupt_safe(
                name,
                flags,
                dir_fd=parent_fd,
            )
        except OSError as exc:
            raise LedgerError(f"cannot securely open ledger {label}: {exc}") from exc
        result: PinnedRegularSnapshot | None = None
        try:
            opened = os.fstat(descriptor_owner.descriptor)
            if not stat.S_ISREG(opened.st_mode):
                raise LedgerError(
                    f"ledger changed to a non-regular type while opening {label}"
                )
            if _stat_identity(before) != _stat_identity(opened):
                raise LedgerError(f"ledger changed while opening {label}")
            if stat.S_IMODE(opened.st_mode) != 0o644 or opened.st_nlink != 1:
                raise LedgerError(
                    f"ledger mode or hard-link count changed while opening {label}"
                )
            snapshot = self._snapshot_descriptor(
                descriptor_owner.descriptor,
                label=label,
                maximum=maximum,
                deadline=deadline,
            )
            current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            pinned = os.fstat(descriptor_owner.descriptor)
            if (
                stat.S_IMODE(current.st_mode) != 0o644
                or current.st_nlink != 1
                or stat.S_IMODE(pinned.st_mode) != 0o644
                or pinned.st_nlink != 1
                or not snapshot.matches_full_stat(current)
                or not snapshot.matches_full_stat(pinned)
                or _stat_identity(current) != _stat_identity(pinned)
            ):
                raise LedgerError(f"ledger path changed while reading {label}")
            result = PinnedRegularSnapshot(snapshot, -1)
            descriptor_owner.transfer_to(result, "descriptor")
            return result
        except BaseException:
            try:
                descriptor_owner.close()
            finally:
                if result is not None:
                    result.close()
            raise

    def pin_regular(
        self, path: str, *, maximum: int, deadline: Deadline
    ) -> PinnedRegularSnapshot:
        parent_owner, name = self._open_parent(path)
        try:
            return self._pin_regular_at(
                parent_owner.descriptor,
                name,
                label=repr(path),
                maximum=maximum,
                deadline=deadline,
            )
        finally:
            parent_owner.close()

    def read_regular_snapshot(
        self, path: str, *, maximum: int, deadline: Deadline
    ) -> RegularSnapshot:
        with self.pin_regular(path, maximum=maximum, deadline=deadline) as pinned:
            return pinned.snapshot

    def read_regular(self, path: str, *, maximum: int, deadline: Deadline) -> bytes:
        return self.read_regular_snapshot(path, maximum=maximum, deadline=deadline).data

    @staticmethod
    def _temporary_name() -> str:
        return f".haldir-ledger-tmp-{os.getpid()}-{secrets.token_hex(8)}"

    @staticmethod
    def _sibling_path(path: str, sibling: str) -> str:
        parent = PurePosixPath(path).parent
        return sibling if parent == PurePosixPath(".") else f"{parent}/{sibling}"

    def _parent_descriptor_matches_path(
        self,
        descriptor: int,
        path: str,
    ) -> bool:
        if not self._root_descriptor_matches_path():
            return False
        try:
            current_owner, _name = self._open_parent(path)
        except (LedgerError, OSError):
            return False
        try:
            opened = os.fstat(descriptor)
            current = os.fstat(current_owner.descriptor)
            return stat.S_ISDIR(opened.st_mode) and _stat_identity(
                opened
            ) == _stat_identity(current)
        except OSError:
            return False
        finally:
            current_owner.close()

    def _temporary_retention_detail(self, temporary: _OwnedTemporary) -> str:
        candidate = self._sibling_path(temporary.path, temporary.name)
        if self._parent_descriptor_matches_path(
            temporary.parent_descriptor,
            temporary.path,
        ):
            return (
                "no unlink was attempted for the reserved temporary name; inspect "
                f"the canonical candidate {candidate!r}"
            )
        return (
            "no unlink was attempted for reserved basename "
            f"{temporary.name!r} in a displaced parent directory; no canonical "
            "pathname is claimed"
        )

    def _create_regular_temporary(
        self,
        parent_fd: int,
        data: bytes,
        *,
        path: str,
        file_mode: int,
        deadline: Deadline,
    ) -> _OwnedTemporary:
        temporary_name = self._temporary_name()
        if not TEMPORARY_BASENAME.fullmatch(temporary_name):
            raise LedgerError("generated temporary name is not a reserved basename")
        descriptor_owner = _OwnedDescriptor()
        temporary: _OwnedTemporary | None = None
        entry_created = False
        try:
            flags = (
                os.O_RDWR
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0)
            )
            previous_mask = signal.pthread_sigmask(
                signal.SIG_BLOCK,
                {signal.SIGINT},
            )
            try:
                descriptor_owner.descriptor = os.open(
                    temporary_name,
                    flags,
                    0o600,
                    dir_fd=parent_fd,
                )
                entry_created = True
                opened = os.fstat(descriptor_owner.descriptor)
                temporary = _OwnedTemporary(
                    parent_descriptor=parent_fd,
                    name=temporary_name,
                    path=path,
                    descriptor=descriptor_owner.descriptor,
                    expected_identity=_stat_identity(opened),
                )
                descriptor_owner.descriptor = -1
            except FileExistsError as exc:
                raise ConcurrentWriterError(
                    "temporary name collision was preserved without modification: "
                    f"{self._sibling_path(path, temporary_name)!r}"
                ) from exc
            finally:
                signal.pthread_sigmask(
                    signal.SIG_SETMASK,
                    previous_mask,
                )

            offset = 0
            while offset < len(data):
                deadline.check(f"writing ledger {path!r}")
                written = os.write(temporary.descriptor, data[offset:])
                if written <= 0:
                    raise LedgerError(f"short write while creating ledger {path!r}")
                offset += written
                temporary.record_owned_mutation()

            os.fchmod(temporary.descriptor, file_mode)
            temporary.record_owned_mutation()
            os.fsync(temporary.descriptor)
            temporary.record_owned_mutation()
            snapshot = self._snapshot_descriptor(
                temporary.descriptor,
                label=f"temporary for {path!r}",
                maximum=MAX_LEDGER_BYTES,
                deadline=deadline,
            )
            if (
                snapshot.data != data
                or stat.S_IMODE(snapshot.mode) != file_mode
                or os.fstat(temporary.descriptor).st_nlink != 1
            ):
                raise LedgerError(
                    f"temporary ledger bytes or mode are invalid: {path!r}"
                )
            temporary.snapshot = snapshot
            temporary.expected_identity = snapshot.stat_identity
            os.fsync(parent_fd)
            if not self._parent_descriptor_matches_path(parent_fd, path):
                raise ConcurrentWriterError(
                    "creation parent changed after temporary and parent fsync"
                )
            temporary.state = "TEMP_FSYNCED"
            return temporary
        except BaseException as error:
            if temporary is not None:
                retention_detail = self._temporary_retention_detail(temporary)
                try:
                    temporary.close()
                except BaseException as close_error:
                    raise ConcurrentWriterError(
                        "temporary creation failed before publication and descriptor "
                        f"finalization was interrupted; {retention_detail}"
                    ) from close_error
                raise ConcurrentWriterError(
                    f"temporary creation failed before publication; {retention_detail}"
                ) from error
            descriptor_owner.close()
            if entry_created:
                candidate = self._sibling_path(path, temporary_name)
                if self._parent_descriptor_matches_path(parent_fd, path):
                    detail = (
                        "no unlink was attempted for the reserved temporary name; "
                        f"inspect the canonical candidate {candidate!r}"
                    )
                else:
                    detail = (
                        "no unlink was attempted for reserved basename "
                        f"{temporary_name!r} in a displaced parent directory; no "
                        "canonical pathname is claimed"
                    )
                raise ConcurrentWriterError(
                    "temporary identity acquisition failed before publication; "
                    f"{detail}"
                ) from error
            raise

    def atomic_create(
        self,
        path: str,
        data: bytes,
        *,
        deadline: Deadline | None = None,
    ) -> RegularSnapshot:
        if len(data) > MAX_LEDGER_BYTES:
            raise LedgerError(f"ledger exceeds {MAX_LEDGER_BYTES} bytes")
        effective_deadline = deadline or Deadline.after(GIT_TIMEOUT_SECONDS)
        effective_deadline.check(f"starting create-once operation for {path!r}")
        parent_owner, name = self._open_parent(path, create=True)
        temporary: _OwnedTemporary | None = None
        retention_detail: str | None = None
        try:
            parent_fd = parent_owner.descriptor
            if not self._parent_descriptor_matches_path(parent_fd, path):
                raise ConcurrentWriterError(
                    "creation parent lost its canonical pathname binding"
                )
            try:
                existing = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                existing = None
            if existing is not None:
                raise LedgerError(
                    f"ledger already exists; create-once generation refuses {path!r}"
                )

            try:
                temporary = self._create_regular_temporary(
                    parent_fd,
                    data,
                    path=path,
                    file_mode=0o644,
                    deadline=effective_deadline,
                )
                if temporary.snapshot is None or temporary.state != "TEMP_FSYNCED":
                    raise LedgerError("temporary did not reach its fsync boundary")
                if not self._parent_descriptor_matches_path(parent_fd, path):
                    raise ConcurrentWriterError(
                        "creation parent changed before the no-replace rename"
                    )
                effective_deadline.check(f"renaming the fsynced temporary for {path!r}")

                previous_mask = signal.pthread_sigmask(
                    signal.SIG_BLOCK,
                    {signal.SIGINT},
                )
                try:
                    descriptor_stat = os.fstat(temporary.descriptor)
                    path_stat = os.stat(
                        temporary.name,
                        dir_fd=parent_fd,
                        follow_symlinks=False,
                    )
                    if (
                        _stat_identity(descriptor_stat) != temporary.expected_identity
                        or _stat_identity(path_stat) != temporary.expected_identity
                    ):
                        raise ConcurrentWriterError(
                            "temporary changed at the canonical rename boundary"
                        )
                    temporary.mark_rename_attempted()
                    _atomic_rename_noreplace(parent_fd, temporary.name, parent_fd, name)
                    temporary.mark_renamed()
                    renamed_stat = temporary.record_owned_mutation()
                    if (
                        not stat.S_ISREG(renamed_stat.st_mode)
                        or renamed_stat.st_nlink != 1
                    ):
                        raise ConcurrentWriterError(
                            "created ledger has an unexpected hard-link count"
                        )
                finally:
                    signal.pthread_sigmask(
                        signal.SIG_SETMASK,
                        previous_mask,
                    )

                os.fsync(parent_fd)
                temporary.state = "PARENT_FSYNCED"
                if not self._parent_descriptor_matches_path(parent_fd, path):
                    raise ConcurrentWriterError(
                        "creation parent changed after the canonical rename"
                    )
                with self._pin_regular_at(
                    parent_fd,
                    name,
                    label=repr(path),
                    maximum=MAX_LEDGER_BYTES,
                    deadline=effective_deadline,
                ) as pinned:
                    expected = temporary.snapshot
                    assert expected is not None
                    if (
                        pinned.snapshot != expected
                        or pinned.snapshot.stat_identity != temporary.expected_identity
                    ):
                        raise ConcurrentWriterError(
                            "canonical ledger differs from the created temporary"
                        )
                    if not self._parent_descriptor_matches_path(parent_fd, path):
                        raise ConcurrentWriterError(
                            "creation parent changed during final verification"
                        )
                    temporary.state = "VERIFIED_SUCCESS"
                    return pinned.snapshot
            except BaseException as error:
                conflict = isinstance(error, OSError) and error.errno in {
                    errno.EEXIST,
                    errno.ENOTEMPTY,
                }
                if temporary is not None and temporary.state in {
                    "OPEN",
                    "TEMP_FSYNCED",
                }:
                    retention_detail = self._temporary_retention_detail(temporary)
                    if conflict:
                        raise ConcurrentWriterError(
                            "another entry won create-once target creation for "
                            f"{path!r}; {retention_detail}"
                        ) from error
                    raise ConcurrentWriterError(
                        "create-once operation stopped before the rename attempt; "
                        f"{retention_detail}"
                    ) from error
                if (
                    temporary is not None
                    and temporary.state == "RENAME_OUTCOME_UNKNOWN"
                ):
                    retention_detail = self._temporary_retention_detail(temporary)
                    if isinstance(error, _AtomicRenameUnavailableError):
                        temporary.state = "TEMP_FSYNCED"
                        if error.native_call_attempted:
                            boundary = (
                                "the native atomic no-replace call reported an "
                                "unsupported operation with no namespace effect"
                            )
                        else:
                            boundary = (
                                "the atomic no-replace primitive was unavailable "
                                "before any rename syscall"
                            )
                        raise ConcurrentWriterError(
                            f"{boundary}, proving this attempt did not publish "
                            f"{path!r}; {retention_detail}"
                        ) from error
                    if conflict:
                        temporary.state = "RENAME_REJECTED"
                        raise ConcurrentWriterError(
                            "the atomic no-replace rename reported a target conflict, "
                            f"proving this attempt did not publish {path!r}; "
                            f"{retention_detail}"
                        ) from error
                    raise CreationIncompleteError(
                        "the atomic no-replace rename outcome is unknown for "
                        f"{path!r}; the canonical target and reserved temporary name "
                        "were left untouched after the attempt and both must be "
                        f"inspected; {retention_detail}"
                    ) from error
                if temporary is not None and temporary.state in {
                    "RENAMED_UNSYNCED",
                    "PARENT_FSYNCED",
                    "VERIFIED_SUCCESS",
                }:
                    raise CreationIncompleteError(
                        "create-once operation crossed the canonical rename "
                        f"boundary for {path!r}; the target was created and must be "
                        "verified, never regenerated automatically",
                        target_creation_confirmed=True,
                        canonical_creation_verified=(
                            temporary.state == "VERIFIED_SUCCESS"
                        ),
                    ) from error
                raise
        finally:
            if temporary is not None and temporary.state in {
                "OPEN",
                "TEMP_FSYNCED",
                "RENAME_REJECTED",
                "RENAME_OUTCOME_UNKNOWN",
            }:
                retention_detail = self._temporary_retention_detail(temporary)
            finalization_error: BaseException | None = None
            try:
                if temporary is not None:
                    temporary.close()
            except BaseException as exc:
                finalization_error = exc
            try:
                parent_owner.close()
            except BaseException as exc:
                if finalization_error is None:
                    finalization_error = exc
            if finalization_error is not None:
                if (
                    temporary is not None
                    and temporary.state == "RENAME_OUTCOME_UNKNOWN"
                ):
                    assert retention_detail is not None
                    raise CreationIncompleteError(
                        "create-once publication may have occurred for "
                        f"{path!r}; descriptor finalization was interrupted and the "
                        "canonical target and reserved temporary state must be "
                        f"inspected; {retention_detail}"
                    ) from finalization_error
                if temporary is not None and temporary.state in {
                    "RENAMED_UNSYNCED",
                    "PARENT_FSYNCED",
                    "VERIFIED_SUCCESS",
                }:
                    if temporary.state == "VERIFIED_SUCCESS":
                        detail = "was verified as created"
                    else:
                        detail = "was created"
                    raise CreationIncompleteError(
                        f"the canonical target {path!r} {detail}; descriptor "
                        "finalization was interrupted and the target was left in "
                        "place",
                        target_creation_confirmed=True,
                        canonical_creation_verified=(
                            temporary.state == "VERIFIED_SUCCESS"
                        ),
                    ) from finalization_error
                if temporary is not None and temporary.state in {
                    "OPEN",
                    "TEMP_FSYNCED",
                    "RENAME_REJECTED",
                }:
                    assert retention_detail is not None
                    raise ConcurrentWriterError(
                        "create-once publication did not complete and descriptor "
                        f"finalization was interrupted; "
                        f"{retention_detail}"
                    ) from finalization_error
                raise finalization_error

    def atomic_write(
        self,
        path: str,
        data: bytes,
        *,
        deadline: Deadline | None = None,
    ) -> RegularSnapshot:
        return self.atomic_create(path, data, deadline=deadline)


def _stat_identity(value: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _classify_content(data: bytes) -> tuple[str, int]:
    if b"\x00" in data:
        return "BINARY", 0
    try:
        text = data.decode("utf-8", "strict")
    except UnicodeDecodeError:
        return "BINARY", 0
    lines = len(text.splitlines())
    controls = {
        char
        for char in text
        if char not in "\t\n\r" and unicodedata.category(char).startswith("C")
    }
    if controls == {"\x1b"}:
        return "TEXT_UTF8_WITH_ANSI_ESCAPE", lines
    if controls:
        return "TEXT_UTF8_WITH_CONTROLS", lines
    return "TEXT_UTF8", lines


def _git_object_id(data: bytes, object_type: str, object_format: str) -> str:
    if object_format not in {"sha1", "sha256"}:
        raise LedgerError(f"unsupported Git object format: {object_format!r}")
    if not re.fullmatch(r"[a-z][a-z0-9-]*", object_type):
        raise LedgerError(f"invalid Git object type: {object_type!r}")
    digest = hashlib.new(object_format)
    digest.update(f"{object_type} {len(data)}\0".encode("ascii"))
    digest.update(data)
    return digest.hexdigest()


def _git_blob_id(data: bytes, object_format: str) -> str:
    return _git_object_id(data, "blob", object_format)


def _content_identity(
    data: bytes,
    *,
    object_format: str,
    fs_type: str,
    fs_mode: str,
    git_mode: str,
    forced_kind: str | None = None,
) -> ContentIdentity:
    kind, lines = _classify_content(data)
    if forced_kind is not None:
        kind = forced_kind
        lines = 0
    return ContentIdentity(
        fs_type=fs_type,
        fs_mode=fs_mode,
        git_mode=git_mode,
        git_blob_id=_git_blob_id(data, object_format),
        sha256=hashlib.sha256(data).hexdigest(),
        size=str(len(data)),
        lines=str(lines),
        content_kind=kind,
    )


def _decode_git_path(raw: bytes, *, label: str) -> str:
    try:
        return raw.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise LedgerError(f"{label} contains a non-UTF-8 Git path") from exc


def _parse_z_paths(raw: bytes, *, label: str) -> list[str]:
    if not raw:
        return []
    if not raw.endswith(b"\0"):
        raise LedgerError(f"unterminated NUL-delimited output for {label}")
    paths = [_decode_git_path(item, label=label) for item in raw[:-1].split(b"\0")]
    return _validate_unique_paths(paths, label=label)


_CHECK_IGNORE_RECORD_MAX_BYTES = (
    FIELD_BYTE_LIMITS["ignore_rule_source"]
    - 1  # The rendered source field includes one separating colon.
    + FIELD_BYTE_LIMITS["ignore_pattern"]
    + FIELD_BYTE_LIMITS["path"]
    + 4  # Four NUL field terminators per check-ignore record.
)


def _check_ignore_stdout_bound(row_count: int) -> int:
    if not isinstance(row_count, int) or isinstance(row_count, bool) or row_count < 1:
        raise LedgerError("check-ignore row count must be a positive integer")
    return min(
        MAX_GIT_INVENTORY_BYTES,
        row_count * _CHECK_IGNORE_RECORD_MAX_BYTES,
    )


def _canonical_digest(kind: str, records: object) -> str:
    if not re.fullmatch(r"[a-z][a-z0-9-]*", kind):
        raise LedgerError(f"invalid inventory digest kind: {kind!r}")
    payload = json.dumps(
        {
            "kind": kind,
            "records": records,
            "schema": "haldir-ch-t001-inventory-digest-v1",
        },
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _ignored_rule_records(
    repo: Path, paths: Sequence[str], *, deadline: Deadline
) -> dict[str, tuple[str, str]]:
    records: dict[str, tuple[str, str]] = {}
    chunk: list[str] = []
    chunk_bytes = 0

    def consume(items: list[str]) -> None:
        if not items:
            return
        input_data = b"".join(path.encode("utf-8") + b"\0" for path in items)
        raw = _run_git_input(
            repo,
            ["check-ignore", "-z", "-v", "--stdin"],
            input_data,
            max_stdout=_check_ignore_stdout_bound(len(items)),
            deadline=deadline,
        )
        if not raw.endswith(b"\0"):
            raise LedgerError("unterminated git check-ignore output")
        fields = raw[:-1].split(b"\0")
        if len(fields) != len(items) * 4:
            raise LedgerError("git check-ignore did not classify every ignored path")
        for index, expected_path in enumerate(items):
            source_raw, line_raw, pattern_raw, path_raw = fields[
                index * 4 : index * 4 + 4
            ]
            source = _decode_git_path(source_raw, label="ignore rule source")
            pattern = _decode_git_path(pattern_raw, label="ignore pattern")
            observed_path = _decode_git_path(path_raw, label="ignored rule path")
            try:
                line = line_raw.decode("ascii", "strict")
            except UnicodeDecodeError as exc:
                raise LedgerError("ignore rule line is not ASCII") from exc
            if observed_path != expected_path or not line.isdecimal():
                raise LedgerError(
                    "git check-ignore returned a contradictory classification"
                )
            if expected_path in records:
                raise LedgerError(
                    f"duplicate ignore classification for {expected_path!r}"
                )
            records[expected_path] = (f"{source}:{line}", pattern)

    for path in paths:
        encoded_size = len(path.encode("utf-8")) + 1
        if chunk and chunk_bytes + encoded_size > 4 * 1024 * 1024:
            consume(chunk)
            chunk = []
            chunk_bytes = 0
        chunk.append(path)
        chunk_bytes += encoded_size
    consume(chunk)
    return records


def _ignore_rule_for_path(
    repo: Path, path: str, *, deadline: Deadline
) -> tuple[str, str] | None:
    input_data = path.encode("utf-8") + b"\0"
    raw = _run_git(
        repo,
        ["check-ignore", "-z", "-v", "--no-index", "--stdin"],
        max_stdout=MAX_PATH_BYTES * 4 + MAX_CELL_BYTES,
        deadline=deadline,
        input_data=input_data,
        accepted_returncodes=frozenset({0, 1}),
    )
    if not raw:
        return None
    if not raw.endswith(b"\0"):
        raise LedgerError("unterminated ledger-path ignore classification")
    fields = raw[:-1].split(b"\0")
    if len(fields) != 4:
        raise LedgerError("malformed ledger-path ignore classification")
    source_raw, line_raw, pattern_raw, path_raw = fields
    source = _decode_git_path(source_raw, label="ledger ignore rule source")
    pattern = _decode_git_path(pattern_raw, label="ledger ignore pattern")
    observed_path = _decode_git_path(path_raw, label="ledger ignored path")
    try:
        line = line_raw.decode("ascii", "strict")
    except UnicodeDecodeError as exc:
        raise LedgerError("ledger ignore rule line is not ASCII") from exc
    if observed_path != path or not line.isdecimal():
        raise LedgerError("contradictory ledger-path ignore classification")
    if pattern.startswith("!"):
        return None
    return f"{source}:{line}", pattern


def _source_entries(
    repo: Path, commit: str, *, deadline: Deadline
) -> dict[str, SourceEntry]:
    raw = _run_git(repo, ["ls-tree", "-lrz", "--full-tree", commit], deadline=deadline)
    entries: dict[str, SourceEntry] = {}
    paths: list[str] = []
    if raw and not raw.endswith(b"\0"):
        raise LedgerError("unterminated git ls-tree output")
    for record in raw[:-1].split(b"\0") if raw else ():
        try:
            metadata, raw_path = record.split(b"\t", 1)
            mode, object_type, oid, raw_size = metadata.split(b" ", 3)
        except ValueError as exc:
            raise LedgerError("malformed git ls-tree record") from exc
        path = _decode_git_path(raw_path, label="source tree")
        paths.append(path)
        mode_text = mode.decode("ascii", "strict")
        type_text = object_type.decode("ascii", "strict")
        oid_text = oid.decode("ascii", "strict")
        if mode_text not in {"100644", "100755", "120000", "160000"}:
            raise LedgerError(f"unsupported source Git mode {mode_text!r} for {path!r}")
        expected_type = "commit" if mode_text == "160000" else "blob"
        if type_text != expected_type or not HEX_OID.fullmatch(oid_text):
            raise LedgerError(f"invalid source object identity for {path!r}")
        stripped_size = raw_size.strip()
        canonical_padded_size = stripped_size.rjust(
            max(7, len(stripped_size)),
            b" ",
        )
        if (
            not stripped_size
            or raw_size != canonical_padded_size
            or (
                stripped_size != b"-"
                and (
                    not stripped_size.isdigit()
                    or len(stripped_size) > 20
                    or (len(stripped_size) > 1 and stripped_size.startswith(b"0"))
                )
            )
        ):
            raise LedgerError(f"invalid source object size for {path!r}")
        if stripped_size == b"-":
            if mode_text != "160000":
                raise LedgerError(f"invalid source blob size for {path!r}")
            size = None
        else:
            if mode_text == "160000":
                raise LedgerError(f"invalid source gitlink size for {path!r}")
            size = int(stripped_size, 10)
        entries[path] = SourceEntry(mode_text, type_text, oid_text, size)
    _validate_unique_paths(paths, label="source tree")
    return entries


def _index_entries(repo: Path, *, deadline: Deadline) -> dict[str, IndexEntry]:
    raw = _run_git(repo, ["ls-files", "--stage", "-v", "-z"], deadline=deadline)
    entries: dict[str, IndexEntry] = {}
    paths: list[str] = []
    if raw and not raw.endswith(b"\0"):
        raise LedgerError("unterminated git ls-files --stage output")
    for record in raw[:-1].split(b"\0") if raw else ():
        try:
            tag, tagged = record[:1], record[1:]
            if tagged[:1] != b" ":
                raise ValueError("missing index tag separator")
            metadata, raw_path = tagged[1:].split(b"\t", 1)
            mode, oid, stage = metadata.split(b" ", 2)
        except ValueError as exc:
            raise LedgerError("malformed git index record") from exc
        path = _decode_git_path(raw_path, label="Git index")
        paths.append(path)
        mode_text = mode.decode("ascii", "strict")
        oid_text = oid.decode("ascii", "strict")
        stage_text = stage.decode("ascii", "strict")
        if stage_text != "0":
            raise LedgerError(f"unmerged index entry is not auditable: {path!r}")
        if mode_text not in {"100644", "100755", "120000", "160000"}:
            raise LedgerError(f"unsupported index Git mode {mode_text!r} for {path!r}")
        if not HEX_OID.fullmatch(oid_text) or set(oid_text) == {"0"}:
            raise LedgerError(f"invalid index object identity for {path!r}")
        if tag != b"H":
            raise LedgerError(
                f"non-default index flag/state {tag!r} is not auditable: {path!r}"
            )
        if path in entries:
            raise LedgerError(f"duplicate Git index path: {path!r}")
        entries[path] = IndexEntry(mode_text, oid_text, "NONE")
    _validate_unique_paths(paths, label="Git index")
    fsmonitor_raw = _run_git(repo, ["ls-files", "-f", "-z"], deadline=deadline)
    fsmonitor_paths: list[str] = []
    if fsmonitor_raw and not fsmonitor_raw.endswith(b"\0"):
        raise LedgerError("unterminated git ls-files -f output")
    for record in fsmonitor_raw[:-1].split(b"\0") if fsmonitor_raw else ():
        if len(record) < 3 or record[1:2] != b" ":
            raise LedgerError("malformed git fsmonitor index record")
        path = _decode_git_path(record[2:], label="Git fsmonitor index")
        fsmonitor_paths.append(path)
        if record[:1] != b"H":
            raise LedgerError(
                f"fsmonitor-valid or non-default index state is not auditable: {path!r}"
            )
    if fsmonitor_paths != paths:
        raise LedgerError("Git index views disagree while inventorying flags")

    debug_raw = _run_git(repo, ["ls-files", "--debug", "-z"], deadline=deadline)
    cursor = 0
    for path in paths:
        prefix = path.encode("utf-8") + b"\0"
        if not debug_raw.startswith(prefix, cursor):
            raise LedgerError("Git debug index view disagrees on path ordering")
        cursor += len(prefix)
        matched = INDEX_DEBUG_RECORD.match(debug_raw, cursor)
        if matched is None:
            raise LedgerError(f"malformed Git debug index record for {path!r}")
        if int(matched.group(1), 16) != 0:
            raise LedgerError(
                f"extended or non-default index flags are not auditable: {path!r}"
            )
        cursor = matched.end()
    if cursor != len(debug_raw):
        raise LedgerError("Git debug index view contains unexpected trailing data")
    return entries


def _resolve_source(
    repo: Path, source_commit: str, *, deadline: Deadline
) -> tuple[str, str, str]:
    if not HEX_OID.fullmatch(source_commit):
        raise LedgerError(
            "source commit must be a full lowercase SHA-1 or SHA-256 object ID"
        )
    commit = (
        _run_git(
            repo,
            [
                "rev-parse",
                "--verify",
                "--end-of-options",
                f"{source_commit}^{{commit}}",
            ],
            max_stdout=256,
            deadline=deadline,
        )
        .decode("ascii", "strict")
        .strip()
    )
    if commit != source_commit:
        raise LedgerError(
            f"source commit did not resolve exactly: {source_commit!r} -> {commit!r}"
        )
    tree = (
        _run_git(
            repo,
            ["rev-parse", "--verify", "--end-of-options", f"{commit}^{{tree}}"],
            max_stdout=256,
            deadline=deadline,
        )
        .decode("ascii", "strict")
        .strip()
    )
    object_format = (
        _run_git(
            repo,
            ["rev-parse", "--show-object-format"],
            max_stdout=32,
            deadline=deadline,
        )
        .decode("ascii", "strict")
        .strip()
    )
    if object_format not in {"sha1", "sha256"}:
        raise LedgerError(f"unsupported Git object format: {object_format!r}")
    expected_length = 40 if object_format == "sha1" else 64
    if len(commit) != expected_length or len(tree) != expected_length:
        raise LedgerError("source identities do not match the repository object format")
    return commit, tree, object_format


def _source_content(
    repo: Path,
    path: str,
    entry: SourceEntry,
    *,
    object_format: str,
    max_file_bytes: int,
    budget: ByteBudget,
    deadline: Deadline,
) -> ContentIdentity:
    if entry.mode == "160000":
        expected_oid_length = 40 if object_format == "sha1" else 64
        if len(entry.oid) != expected_oid_length:
            raise LedgerError(
                f"source gitlink ID does not match the object format for {path!r}"
            )
        # ls-tree identifies the entry as a commit reference from its tree mode;
        # the referenced repository object need not exist in this object database.
        return ContentIdentity(
            fs_type="GITLINK",
            fs_mode="160000",
            git_mode="160000",
            git_blob_id=entry.oid,
            sha256="",
            size="",
            lines="0",
            content_kind="GITLINK_COMMIT_REFERENCE_UNVERIFIED",
        )
    if entry.size is None or entry.size > max_file_bytes:
        raise LedgerError(f"source blob exceeds {max_file_bytes} bytes: {path!r}")
    budget.consume(entry.size, f"source:{path}")
    data = _run_git(
        repo,
        ["cat-file", "blob", entry.oid],
        max_stdout=max_file_bytes,
        deadline=deadline,
    )
    if len(data) != entry.size:
        raise LedgerError(f"source blob size mismatch for {path!r}")
    calculated_oid = _git_blob_id(data, object_format)
    if calculated_oid != entry.oid:
        raise LedgerError(f"source blob ID mismatch for {path!r}")
    forced_kind = "SYMLINK_TARGET_BYTES" if entry.mode == "120000" else None
    fs_type = "SYMLINK" if entry.mode == "120000" else "REGULAR"
    return _content_identity(
        data,
        object_format=object_format,
        fs_type=fs_type,
        fs_mode=entry.mode,
        git_mode=entry.mode,
        forced_kind=forced_kind,
    )


def _index_content(
    repo: Path,
    path: str,
    entry: IndexEntry,
    *,
    object_format: str,
    max_file_bytes: int,
    budget: ByteBudget,
    deadline: Deadline,
) -> ContentIdentity:
    if entry.mode == "160000":
        expected_oid_length = 40 if object_format == "sha1" else 64
        if len(entry.oid) != expected_oid_length:
            raise LedgerError(
                f"index gitlink ID does not match the object format for {path!r}"
            )
        # A gitlink OID belongs to the referenced repository and normally need
        # not exist in the superproject object database.  Mode 160000 plus the
        # validated full nonzero OID is recorded as an unverified commit
        # reference; no local object-content or object-presence claim is made.
        return ContentIdentity(
            fs_type="GITLINK",
            fs_mode="160000",
            git_mode="160000",
            git_blob_id=entry.oid,
            sha256="",
            size="",
            lines="0",
            content_kind="GITLINK_COMMIT_REFERENCE_UNVERIFIED",
        )
    data = _run_git(
        repo,
        ["cat-file", "blob", entry.oid],
        max_stdout=max_file_bytes,
        deadline=deadline,
    )
    if len(data) > max_file_bytes:
        raise LedgerError(f"index blob exceeds {max_file_bytes} bytes: {path!r}")
    budget.consume(len(data), f"index:{path}")
    if _git_blob_id(data, object_format) != entry.oid:
        raise LedgerError(f"index blob ID mismatch for {path!r}")
    forced_kind = "SYMLINK_TARGET_BYTES" if entry.mode == "120000" else None
    fs_type = "SYMLINK" if entry.mode == "120000" else "REGULAR"
    return _content_identity(
        data,
        object_format=object_format,
        fs_type=fs_type,
        fs_mode=entry.mode,
        git_mode=entry.mode,
        forced_kind=forced_kind,
    )


def _language(path: str) -> str:
    name = PurePosixPath(path).name.casefold()
    if name in LANGUAGE_BY_NAME:
        return LANGUAGE_BY_NAME[name]
    suffix = PurePosixPath(path).suffix.casefold()
    return LANGUAGE_BY_SUFFIX.get(suffix, "UNKNOWN")


def _format(path: str, identity: ContentIdentity, *, self_row: bool) -> str:
    if self_row:
        return "SELF_REFERENTIAL_CSV"
    if identity.content_kind == "SYMLINK_TARGET_BYTES":
        return "SYMLINK_TARGET_BYTES"
    if identity.content_kind == "GITLINK_COMMIT_REFERENCE_UNVERIFIED":
        return "GITLINK_COMMIT_REFERENCE_UNVERIFIED"
    if identity.content_kind == "NON_REGULAR_NO_CONTENT_READ":
        return identity.fs_type or "SPECIAL_FILESYSTEM_ENTRY"
    language = _language(path)
    if not identity.content_kind:
        return "ABSENT"
    if identity.content_kind == "BINARY":
        return (
            language
            if language in BINARY_LANGUAGES
            else f"BINARY_WITH_{language}_SUFFIX"
        )
    if identity.content_kind == "TEXT_UTF8_WITH_ANSI_ESCAPE":
        return (
            "ANSI_LOG_TEXT"
            if language == "LOG_TEXT"
            else f"ANSI_ESCAPE_WITH_{language}_SUFFIX"
        )
    if identity.content_kind == "TEXT_UTF8_WITH_CONTROLS":
        return f"CONTROL_BEARING_{language}"
    if language in BINARY_LANGUAGES:
        return f"TEXT_WITH_{language}_SUFFIX"
    return language if language != "UNKNOWN" else identity.content_kind


def _generated_candidate_reason(path: str, current_scope: str) -> str:
    pure = PurePosixPath(path)
    casefolded_parts = {part.casefold() for part in pure.parts}
    name = pure.name.casefold()
    reasons: list[str] = []
    if current_scope == "IGNORED":
        reasons.append("IGNORED_WORKTREE_ENTRY")
    if casefolded_parts & GENERATED_COMPONENTS:
        reasons.append("GENERATED_PATH_COMPONENT")
    if name in {"cargo.lock", "package-lock.json", "pnpm-lock.yaml", "yarn.lock"}:
        reasons.append("LOCKFILE")
    if len(pure.parts) >= 2 and pure.parts[:2] == ("contracts", "vectors"):
        reasons.append("CONTRACT_VECTOR_PATH")
    if "evidence" in casefolded_parts:
        reasons.append("RETAINED_EVIDENCE_PATH")
    if name.startswith("checksums.") or name in {
        "sha256sums.txt",
        "master_sha256sums.txt",
    }:
        reasons.append("CHECKSUM_MANIFEST")
    if ".generated." in name or name.endswith((".min.js", ".min.css", ".map")):
        reasons.append("GENERATED_FILENAME")
    return ";".join(reasons) if reasons else "NONE_OBSERVED_REVIEW_REQUIRED"


def _is_test_path(path: str) -> bool:
    pure = PurePosixPath(path)
    parts = tuple(part.casefold() for part in pure.parts)
    name = pure.name.casefold()
    if any(part in {"test", "tests"} for part in parts[:-1]):
        return True
    if name in {"test.py", "tests.py", "test.rs", "tests.rs"}:
        return True
    if name.startswith(("test_", "tests_", "test-", "tests-")):
        return True
    return name.endswith(
        (
            "_test.py",
            "_tests.py",
            "_test.rs",
            "_tests.rs",
            ".test.js",
            ".tests.js",
            ".spec.js",
            ".test.ts",
            ".tests.ts",
            ".spec.ts",
            ".test.tsx",
            ".spec.tsx",
        )
    )


def _category(path: str, generated_reason: str) -> str:
    parts = PurePosixPath(path).parts
    if parts[:2] == (".github", "workflows"):
        return "CI_WORKFLOW"
    if parts and parts[0] == "release":
        return "RELEASE_EVIDENCE"
    if parts and parts[0] == "evidence":
        return "EVIDENCE"
    if parts and parts[0] == "docs":
        return "DOCUMENTATION"
    if parts and parts[0] == "formal":
        return "FORMAL_MODEL"
    if parts and parts[0] == "deploy":
        return "DEPLOYMENT"
    if _is_test_path(path):
        return "TEST"
    if parts and parts[0] == "tools":
        return "TOOLING"
    if parts and parts[0] == "crates":
        return "RUST_SOURCE"
    if generated_reason != "NONE_OBSERVED_REVIEW_REQUIRED":
        return "GENERATED_CANDIDATE"
    if PurePosixPath(path).suffix.casefold() in {".toml", ".yaml", ".yml", ".json"}:
        return "CONFIGURATION_OR_DATA"
    return "REPOSITORY_SUPPORT"


def _initial_generated_classification(
    path: str, current_scope: str, *, self_row: bool
) -> tuple[str, str]:
    if self_row:
        return "YES", "tools/release/current-file-review-ledger.py"
    exact = {
        "Cargo.lock": "PINNED_CARGO_1.96.0_FROM_WORKSPACE_MANIFESTS",
        "contracts/vectors/CHECKSUMS.sha256": "crates/haldir-contracts/src/tests_contracts.rs",
        "contracts/vectors/haldir-intent-v1.cbor.hex": "crates/haldir-contracts/src/tests_contracts.rs",
        "tools/interop/vectors.json": "crates/haldir-crypto/examples/emit_interop_vectors.rs",
    }
    if path in exact:
        return "YES", exact[path]
    prefixes = {
        "evidence/11-secure-zenoh-live/": "tools/live_secure_zenoh.py",
        "evidence/12-live-gate-dev-smoke/": "tools/live_gate_dev_smoke.py",
    }
    for prefix, generator in prefixes.items():
        if path.startswith(prefix):
            return "YES", generator
    name = PurePosixPath(path).name
    if path.startswith("release/0.9.0/evidence/") and "-generated-" in name:
        return "YES", "tools/release/generate-task-evidence.py"
    return "UNKNOWN", ""


def _current_scope(
    path: str,
    *,
    index: dict[str, IndexEntry],
    untracked: set[str],
    ignored: set[str],
    ledger_self_path: str,
) -> str:
    if path == ledger_self_path:
        return "LEDGER_SELF"
    if path in index:
        return "TRACKED"
    if path in untracked:
        return "UNTRACKED"
    if path in ignored:
        return "IGNORED"
    return "ABSENT"


def _provenance_class(source_tracked: bool, current_scope: str) -> str:
    if current_scope == "LEDGER_SELF":
        return "SELF_REFERENTIAL_LEDGER_ARTIFACT"
    if source_tracked:
        return "DECLARED_SOURCE_COMMIT_AND_CURRENT_VIEW"
    return {
        "TRACKED": "POST_CUT_INDEX_ENTRY",
        "UNTRACKED": "UNTRACKED_WORKTREE_ENTRY",
        "IGNORED": "IGNORED_WORKTREE_ENTRY",
        "ABSENT": "SOURCE_ONLY_ENTRY",
    }[current_scope]


def _source_index_state(source: SourceEntry | None, index: IndexEntry | None) -> str:
    if source is None and index is None:
        return "NEITHER"
    if source is None:
        return "ADDED_TO_INDEX"
    if index is None:
        return "REMOVED_FROM_INDEX"
    if source.mode == index.mode and source.oid == index.oid:
        return "IDENTICAL"
    return "MODIFIED_IN_INDEX"


def _worktree_state(
    index: IndexEntry | None, current: ContentIdentity | None, *, self_row: bool
) -> str:
    if self_row:
        return "SELF_REFERENTIAL_CONTENT_EXCLUDED"
    if index is None:
        return "PRESENT_OUTSIDE_INDEX" if current is not None else "ABSENT"
    if current is None:
        return "DELETED_FROM_WORKTREE"
    if index.mode == "160000":
        return (
            "GITLINK_DIRECTORY_PRESENT_COMMIT_UNVERIFIED"
            if current.fs_type == "DIRECTORY"
            else "GITLINK_TYPE_CHANGED"
        )
    if current.git_blob_id == index.oid and current.git_mode == index.mode:
        return "CLEAN_AGAINST_INDEX"
    if current.git_blob_id == index.oid:
        return "MODE_CHANGED_AGAINST_INDEX"
    return "CONTENT_OR_TYPE_CHANGED_AGAINST_INDEX"


def _legacy_identity(
    source: ContentIdentity | None, current: ContentIdentity | None
) -> ContentIdentity | None:
    if current is not None and current.git_blob_id:
        return current
    return source


def _empty_content() -> ContentIdentity:
    return ContentIdentity("", "", "", "", "", "", "", "")


def _build_row(
    *,
    path: str,
    source_commit: str,
    source_tree: str,
    object_format: str,
    ignored_policy: str,
    view_digests: dict[str, str],
    filesystem_entries: int,
    ledger_self_path: str,
    source_entry: SourceEntry | None,
    source_content: ContentIdentity | None,
    index_entry: IndexEntry | None,
    index_content: ContentIdentity | None,
    current_content: ContentIdentity | None,
    current_scope: str,
    ignore_rule: tuple[str, str] | None,
) -> dict[str, str]:
    source = source_content or _empty_content()
    index_identity = index_content or _empty_content()
    current = current_content or _empty_content()
    self_row = path == ledger_self_path
    reason = _generated_candidate_reason(path, current_scope)
    legacy = _legacy_identity(source_content, current_content) or _empty_content()
    generated, generator = _initial_generated_classification(
        path, current_scope, self_row=self_row
    )
    row = {field: "" for field in FIELDS}
    row.update(
        {
            "schema_version": SCHEMA_VERSION,
            "source_commit": source_commit,
            "source_tree": source_tree,
            "object_format": object_format,
            "ignored_policy": ignored_policy,
            "inventory_digest": "",
            "inventory_rows": "",
            "source_inventory_digest": view_digests["source"],
            "index_inventory_digest": view_digests["index"],
            "untracked_inventory_digest": view_digests["untracked"],
            "ignored_inventory_digest": view_digests["ignored"],
            "filesystem_inventory_digest": view_digests["filesystem"],
            "filesystem_entries": str(filesystem_entries),
            "ledger_self_path": ledger_self_path,
            "path": path,
            "source_tracked": "true" if source_entry is not None else "false",
            "source_git_mode": source_entry.mode if source_entry else "",
            "source_object_type": source_entry.object_type if source_entry else "",
            "source_git_blob_id": source_entry.oid if source_entry else "",
            "source_sha256": source.sha256,
            "source_bytes": source.size,
            "source_lines": source.lines,
            "source_content_kind": source.content_kind,
            "index_tracked": "false"
            if self_row
            else "true"
            if index_entry
            else "false",
            "index_git_mode": ""
            if self_row
            else index_entry.mode
            if index_entry
            else "",
            "index_git_blob_id": ""
            if self_row
            else index_entry.oid
            if index_entry
            else "",
            "index_flags": "" if self_row else index_entry.flags if index_entry else "",
            "index_sha256": "" if self_row else index_identity.sha256,
            "index_bytes": "" if self_row else index_identity.size,
            "index_lines": "0" if self_row else index_identity.lines,
            "index_content_kind": (
                "SELF_REFERENTIAL_CONTENT_EXCLUDED"
                if self_row
                else index_identity.content_kind
            ),
            "source_index_state": (
                "NEITHER"
                if source_entry is None
                else "SOURCE_PRESENT_SELF_INDEX_EXCLUDED"
            )
            if self_row
            else _source_index_state(source_entry, index_entry),
            "current_scope": current_scope,
            "current_fs_type": "LEDGER_SELF" if self_row else current.fs_type,
            "current_fs_mode": "" if self_row else current.fs_mode,
            "current_git_blob_id": "" if self_row else current.git_blob_id,
            "current_sha256": "" if self_row else current.sha256,
            "current_bytes": "" if self_row else current.size,
            "current_lines": "0" if self_row else current.lines,
            "current_content_kind": (
                "SELF_REFERENTIAL_CONTENT_EXCLUDED"
                if self_row
                else current.content_kind
            ),
            "worktree_state": _worktree_state(
                index_entry, current_content, self_row=self_row
            ),
            "ignore_rule_source": ignore_rule[0] if ignore_rule else "",
            "ignore_pattern": ignore_rule[1] if ignore_rule else "",
            "generated_candidate_reason": reason,
            "category": _category(path, reason),
            "provenance_class": _provenance_class(
                source_entry is not None, current_scope
            ),
            "git_blob_id": legacy.git_blob_id,
            "sha256": legacy.sha256,
            "bytes": legacy.size,
            "lines": legacy.lines,
            "language": _language(path),
            "format": _format(path, legacy, self_row=self_row),
            "generated": generated,
            "generator": generator,
            "public_surface": "UNKNOWN",
            "security_critical": "UNKNOWN",
            "science_critical": "UNKNOWN",
            "authority_critical": "UNKNOWN",
            "provenance_review_status": "UNREVIEWED",
            "provenance_evidence": "",
            "license_review_status": "UNREVIEWED",
            "license_expression": "",
            "license_evidence": "",
            "reviewer": "UNASSIGNED",
            "review_status": "UNREVIEWED",
            "requirements": "",
            "assumptions": "",
            "defects": "",
            "tests": "",
            "evidence": "",
            "disposition": "",
            "completed_at": "",
        }
    )
    return row


def _inventory_digest(rows: Sequence[dict[str, str]]) -> str:
    records = [{field: row[field] for field in DIGEST_FIELDS} for row in rows]
    return _canonical_digest("inventory", records)


def build_inventory(
    repo: Path,
    source_commit: str,
    *,
    ledger_self_path: str,
    ignored_policy: str = "reject",
    max_rows: int = DEFAULT_MAX_ROWS,
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
    max_seconds: float = DEFAULT_MAX_SECONDS,
    _deadline: Deadline | None = None,
) -> list[dict[str, str]]:
    """Build deterministic rows without writing a ledger."""

    max_rows = _bounded_int(max_rows, name="max_rows", lower=1, upper=HARD_MAX_ROWS)
    max_file_bytes = _bounded_int(
        max_file_bytes, name="max_file_bytes", lower=1, upper=HARD_MAX_FILE_BYTES
    )
    max_total_bytes = _bounded_int(
        max_total_bytes, name="max_total_bytes", lower=1, upper=HARD_MAX_TOTAL_BYTES
    )
    max_seconds = _bounded_float(
        max_seconds, name="max_seconds", lower=0.001, upper=HARD_MAX_SECONDS
    )
    deadline = _deadline or Deadline.after(max_seconds)
    deadline.check("starting the inventory")
    repo = _bind_git_toplevel(repo, deadline=deadline)
    ledger_self_path = _validate_path(ledger_self_path)
    if ignored_policy not in IGNORED_POLICIES:
        raise LedgerError(f"ignored_policy must be one of {sorted(IGNORED_POLICIES)!r}")
    commit, tree, object_format = _resolve_source(
        repo, source_commit, deadline=deadline
    )
    source = _source_entries(repo, commit, deadline=deadline)
    index = _index_entries(repo, deadline=deadline)
    untracked = set(
        _parse_z_paths(
            _run_git(
                repo,
                ["ls-files", "--others", "--exclude-standard", "-z"],
                deadline=deadline,
            ),
            label="untracked worktree",
        )
    )
    ignored = set(
        _parse_z_paths(
            _run_git(
                repo,
                ["ls-files", "--others", "--ignored", "--exclude-standard", "-z"],
                deadline=deadline,
            ),
            label="ignored worktree",
        )
    )
    overlap = (untracked & ignored) | (untracked & set(index)) | (ignored & set(index))
    if overlap:
        raise LedgerError(f"Git inventory categories overlap: {sorted(overlap)!r}")
    if ignored and ignored_policy == "reject":
        raise LedgerError(
            f"ignored worktree entries require explicit inventory policy: count={len(ignored)}"
        )
    ignored_rules = (
        _ignored_rule_records(
            repo,
            sorted(ignored, key=lambda value: value.encode("utf-8")),
            deadline=deadline,
        )
        if ignored
        else {}
    )
    node_limit = max(1024, max_rows * FILESYSTEM_NODE_MULTIPLIER)
    with SecureRepository(repo) as secure:
        filesystem_paths_list, _walk_nodes = secure.walk_leaf_paths(
            index_gitlinks={
                path for path, entry in index.items() if entry.mode == "160000"
            },
            max_nodes=node_limit,
            deadline=deadline,
        )
    filesystem_paths = set(filesystem_paths_list)
    temporary_paths = {
        path
        for path in (set(source) | set(index) | untracked | ignored | filesystem_paths)
        if TEMPORARY_BASENAME.fullmatch(PurePosixPath(path).name)
    }
    if temporary_paths:
        raise LedgerError(
            "create-once temporary artifact requires inspection before proceeding: "
            f"{sorted(temporary_paths)!r}"
        )
    unclassified = (
        filesystem_paths - set(index) - untracked - ignored - {ledger_self_path}
    )
    missing_from_filesystem = (untracked | ignored) - filesystem_paths
    if unclassified:
        raise LedgerError(
            "independent filesystem walk found paths omitted by Git classification: "
            f"{sorted(unclassified)!r}"
        )
    if missing_from_filesystem:
        raise LedgerError(
            "Git listed worktree paths absent from the independent filesystem walk: "
            f"{sorted(missing_from_filesystem)!r}"
        )
    normalized_index = {
        path: entry for path, entry in index.items() if path != ledger_self_path
    }
    normalized_untracked = sorted(
        untracked - {ledger_self_path}, key=lambda value: value.encode("utf-8")
    )
    normalized_ignored = sorted(
        ignored - {ledger_self_path}, key=lambda value: value.encode("utf-8")
    )
    normalized_filesystem = sorted(
        filesystem_paths - {ledger_self_path}, key=lambda value: value.encode("utf-8")
    )
    view_digests = {
        "source": _canonical_digest(
            "source",
            [
                {
                    "path": path,
                    "mode": entry.mode,
                    "object_type": entry.object_type,
                    "oid": entry.oid,
                    "size": entry.size,
                }
                for path, entry in sorted(
                    source.items(), key=lambda item: item[0].encode("utf-8")
                )
            ],
        ),
        "index": _canonical_digest(
            "index",
            [
                {
                    "path": path,
                    "mode": entry.mode,
                    "oid": entry.oid,
                    "flags": entry.flags,
                }
                for path, entry in sorted(
                    normalized_index.items(), key=lambda item: item[0].encode("utf-8")
                )
            ],
        ),
        "untracked": _canonical_digest("untracked-extra", normalized_untracked),
        "ignored": _canonical_digest(
            "ignored",
            [
                {
                    "path": path,
                    "rule_source": ignored_rules[path][0],
                    "pattern": ignored_rules[path][1],
                }
                for path in normalized_ignored
            ],
        ),
        "filesystem": "",
    }
    all_paths = set(source) | set(index) | filesystem_paths | {ledger_self_path}
    canonical_paths = _validate_unique_paths(all_paths, label="combined inventory")
    canonical_paths.sort(key=lambda value: value.encode("utf-8"))
    if len(canonical_paths) > max_rows:
        raise LedgerError(
            f"inventory has {len(canonical_paths)} rows, exceeding limit {max_rows}"
        )

    budget = ByteBudget(max_total_bytes)
    blob_reads = sum(entry.mode != "160000" for entry in source.values()) + sum(
        entry.mode != "160000" for entry in index.values()
    )
    if blob_reads > MAX_GIT_BLOB_READS:
        raise LedgerError(
            f"inventory requires {blob_reads} Git blob reads, exceeding limit "
            f"{MAX_GIT_BLOB_READS}"
        )
    rows: list[dict[str, str]] = []
    with SecureRepository(repo) as secure:
        for path in canonical_paths:
            source_entry = source.get(path)
            source_identity = (
                _source_content(
                    repo,
                    path,
                    source_entry,
                    object_format=object_format,
                    max_file_bytes=max_file_bytes,
                    budget=budget,
                    deadline=deadline,
                )
                if source_entry is not None
                else None
            )
            index_entry = index.get(path)
            index_identity = (
                _index_content(
                    repo,
                    path,
                    index_entry,
                    object_format=object_format,
                    max_file_bytes=max_file_bytes,
                    budget=budget,
                    deadline=deadline,
                )
                if index_entry is not None and path != ledger_self_path
                else None
            )
            scope = _current_scope(
                path,
                index=index,
                untracked=untracked,
                ignored=ignored,
                ledger_self_path=ledger_self_path,
            )
            current_identity = (
                None
                if path == ledger_self_path
                else secure.read_entry(
                    path,
                    object_format=object_format,
                    max_file_bytes=max_file_bytes,
                    budget=budget,
                    deadline=deadline,
                )
            )
            if scope in {"UNTRACKED", "IGNORED"} and current_identity is None:
                raise LedgerError(
                    f"Git listed a worktree path that disappeared: {path!r}"
                )
            rows.append(
                _build_row(
                    path=path,
                    source_commit=commit,
                    source_tree=tree,
                    object_format=object_format,
                    ignored_policy=ignored_policy,
                    view_digests=view_digests,
                    filesystem_entries=len(normalized_filesystem) + 1,
                    ledger_self_path=ledger_self_path,
                    source_entry=source_entry,
                    source_content=source_identity,
                    index_entry=index_entry,
                    index_content=index_identity,
                    current_content=current_identity,
                    current_scope=scope,
                    ignore_rule=(
                        None if path == ledger_self_path else ignored_rules.get(path)
                    ),
                )
            )
    rows_by_path = {row["path"]: row for row in rows}
    filesystem_records = [
        {
            "bytes": rows_by_path[path]["current_bytes"],
            "content_kind": rows_by_path[path]["current_content_kind"],
            "fs_mode": rows_by_path[path]["current_fs_mode"],
            "fs_type": rows_by_path[path]["current_fs_type"],
            "git_blob_id": rows_by_path[path]["current_git_blob_id"],
            "kind": "LEAF",
            "lines": rows_by_path[path]["current_lines"],
            "path": path,
            "sha256": rows_by_path[path]["current_sha256"],
        }
        for path in normalized_filesystem
    ]
    filesystem_records.append({"kind": "SELF_SENTINEL", "path": ledger_self_path})
    filesystem_digest = _canonical_digest("filesystem", filesystem_records)
    for row in rows:
        row["filesystem_inventory_digest"] = filesystem_digest
        row["inventory_rows"] = str(len(rows))
    digest = _inventory_digest(rows)
    for row in rows:
        row["inventory_digest"] = digest
    return rows


def render_ledger(rows: Sequence[dict[str, str]]) -> bytes:
    if not rows:
        raise LedgerError("ledger must contain at least one row")
    for row_number, row in enumerate(rows, start=2):
        if set(row) != set(FIELDS):
            raise LedgerError(
                f"row {row_number} does not exactly match the ledger schema"
            )
        for field in FIELDS:
            _validate_cell(field, row[field], row_number=row_number)
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(
        stream,
        fieldnames=FIELDS,
        extrasaction="raise",
        lineterminator="\n",
        quoting=csv.QUOTE_MINIMAL,
    )
    writer.writeheader()
    writer.writerows(rows)
    data = stream.getvalue().encode("utf-8", "strict")
    if len(data) > MAX_LEDGER_BYTES:
        raise LedgerError(f"rendered ledger exceeds {MAX_LEDGER_BYTES} bytes")
    return data


def _repo_relative_file(repo: Path, candidate: Path) -> str:
    root = Path(os.path.abspath(os.fspath(repo)))
    lexical_parts = candidate.parts
    if (
        ".." in lexical_parts
        or "." in lexical_parts
        or any("\\" in part for part in lexical_parts)
    ):
        raise LedgerError(
            "ledger path argument contains traversal or non-POSIX components"
        )
    absolute = Path(
        os.path.abspath(
            os.fspath(candidate if candidate.is_absolute() else root / candidate)
        )
    )
    try:
        common = Path(os.path.commonpath((root, absolute)))
    except ValueError as exc:
        raise LedgerError("ledger path is outside the repository") from exc
    if common != root or absolute == root:
        raise LedgerError("ledger path must be a file inside the repository")
    return _validate_path(absolute.relative_to(root).as_posix())


def _reject_reserved_creation_state(
    path: str,
    target: os.stat_result | None,
    reserved_paths: tuple[str, ...],
) -> None:
    if not reserved_paths:
        return
    if target is None:
        state = "RESERVED_TEMPORARY_WITHOUT_TARGET"
        detail = "the reserved entries were preserved without modification"
    else:
        state = "TARGET_AND_RESERVED_TEMPORARY"
        detail = "the canonical target and reserved entries were both preserved"
    raise LedgerError(
        f"create-once restart state {state} for {path!r}; {detail}: "
        f"{list(reserved_paths)!r}"
    )


def generate_ledger(
    repo: Path,
    source_commit: str,
    output: Path,
    *,
    ignored_policy: str = "reject",
    max_rows: int = DEFAULT_MAX_ROWS,
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
    max_seconds: float = DEFAULT_MAX_SECONDS,
) -> dict[str, str | int]:
    max_seconds = _bounded_float(
        max_seconds, name="max_seconds", lower=0.001, upper=HARD_MAX_SECONDS
    )
    deadline = Deadline.after(max_seconds)
    lexical_repo = Path(os.path.abspath(os.fspath(repo)))
    repo = _bind_git_toplevel(repo, deadline=deadline)
    self_path = _repo_relative_file(lexical_repo, output)
    with SecureRepository(repo) as secure:
        existing, reserved_paths = secure.creation_restart_state(
            self_path,
            deadline=deadline,
        )
        _reject_reserved_creation_state(self_path, existing, reserved_paths)
        if existing is not None:
            raise LedgerError(
                f"ledger already exists; create-once generation refuses {self_path!r}"
            )

    ignored_output = _ignore_rule_for_path(repo, self_path, deadline=deadline)
    if ignored_output is not None:
        raise LedgerError(
            "ledger output path is ignored and cannot become a retained inventory "
            f"artifact: {self_path!r} via {ignored_output[0]!r}"
        )

    rows = build_inventory(
        repo,
        source_commit,
        ledger_self_path=self_path,
        ignored_policy=ignored_policy,
        max_rows=max_rows,
        max_file_bytes=max_file_bytes,
        max_total_bytes=max_total_bytes,
        max_seconds=max_seconds,
        _deadline=deadline,
    )
    _verify_rows(
        rows,
        rows,
        self_path=self_path,
        require_assigned=False,
        require_reviewed=False,
    )
    deadline.check("rendering the first reconciled inventory")
    rendered = render_ledger(rows)

    repeated_rows = build_inventory(
        repo,
        source_commit,
        ledger_self_path=self_path,
        ignored_policy=ignored_policy,
        max_rows=max_rows,
        max_file_bytes=max_file_bytes,
        max_total_bytes=max_total_bytes,
        max_seconds=max_seconds,
        _deadline=deadline,
    )
    _verify_rows(
        repeated_rows,
        repeated_rows,
        self_path=self_path,
        require_assigned=False,
        require_reviewed=False,
    )
    deadline.check("rendering the repeated reconciled inventory")
    repeated = render_ledger(repeated_rows)
    if repeated != rendered:
        raise LedgerError(
            "source, index, or worktree changed between independent inventory passes"
        )

    created: RegularSnapshot | None = None
    target_creation_was_confirmed = False
    canonical_creation_was_verified = False
    creation_may_have_occurred = False
    try:
        with SecureRepository(repo) as secure:
            previous_mask = signal.pthread_sigmask(
                signal.SIG_BLOCK,
                {signal.SIGINT},
            )
            try:
                try:
                    created = secure.atomic_create(
                        self_path,
                        rendered,
                        deadline=deadline,
                    )
                except CreationIncompleteError as exc:
                    if exc.target_creation_confirmed:
                        target_creation_was_confirmed = True
                        canonical_creation_was_verified = (
                            exc.canonical_creation_verified
                        )
                    else:
                        creation_may_have_occurred = True
                    raise
            finally:
                signal.pthread_sigmask(
                    signal.SIG_SETMASK,
                    previous_mask,
                )
            persisted = secure.read_regular_snapshot(
                self_path,
                maximum=MAX_LEDGER_BYTES,
                deadline=deadline,
            )
        if persisted != created or persisted.stat_identity != created.stat_identity:
            raise ConcurrentWriterError(
                "created ledger identity changed immediately after creation"
            )

        ignored_after_creation = _ignore_rule_for_path(
            repo,
            self_path,
            deadline=deadline,
        )
        if ignored_after_creation is not None:
            raise LedgerError(
                "ledger became ignored during creation: "
                f"{self_path!r} via {ignored_after_creation[0]!r}"
            )

        postcreation_rows = build_inventory(
            repo,
            source_commit,
            ledger_self_path=self_path,
            ignored_policy=ignored_policy,
            max_rows=max_rows,
            max_file_bytes=max_file_bytes,
            max_total_bytes=max_total_bytes,
            max_seconds=max_seconds,
            _deadline=deadline,
        )
        deadline.check("rendering the post-creation reconciled inventory")
        postcreation = render_ledger(postcreation_rows)
        if postcreation != rendered:
            raise LedgerError(
                "source, index, or worktree changed across ledger creation"
            )

        with SecureRepository(repo) as secure:
            persisted = secure.read_regular_snapshot(
                self_path,
                maximum=MAX_LEDGER_BYTES,
                deadline=deadline,
            )
        if persisted != created or persisted.stat_identity != created.stat_identity:
            raise ConcurrentWriterError(
                "created ledger identity changed during post-creation reconciliation"
            )
    except BaseException as error:
        if created is not None or canonical_creation_was_verified:
            raise CreationIncompleteError(
                "the canonical ledger was created but final reconciliation failed; "
                f"{self_path!r} was left in place and must be verified",
                target_creation_confirmed=True,
                canonical_creation_verified=True,
            ) from error
        if target_creation_was_confirmed:
            raise CreationIncompleteError(
                "a create-once destination entry was created in the pinned parent, "
                "but canonical-path verification did not complete; "
                f"{self_path!r} and every reserved temporary name were left "
                "untouched and must be inspected",
                target_creation_confirmed=True,
            ) from error
        if creation_may_have_occurred:
            raise CreationIncompleteError(
                "canonical ledger creation may have occurred but could not be "
                f"confirmed; {self_path!r} and every reserved temporary name were "
                "left untouched and must be inspected"
            ) from error
        raise

    return {
        "inventory_digest": rows[0]["inventory_digest"],
        "ledger_bytes": len(rendered),
        "ledger_sha256": hashlib.sha256(rendered).hexdigest(),
        "rows": len(rows),
        "source_commit": rows[0]["source_commit"],
        "source_tree": rows[0]["source_tree"],
        "verification_view": "POST_CREATION_TRIPLE_RECONCILIATION",
    }


def _validate_cell(field: str, value: str, *, row_number: int) -> None:
    if field not in FIELD_BYTE_LIMITS:
        raise LedgerError(f"unknown ledger field {field!r}")
    if not isinstance(value, str):
        raise LedgerError(f"row {row_number} field {field!r} is not text")
    try:
        encoded = value.encode("utf-8", "strict")
    except UnicodeEncodeError as exc:
        raise LedgerError(
            f"row {row_number} field {field!r} is not strict UTF-8"
        ) from exc
    limit = FIELD_BYTE_LIMITS[field]
    if len(encoded) > limit:
        raise LedgerError(f"row {row_number} field {field!r} exceeds {limit} bytes")
    if unicodedata.normalize("NFC", value) != value:
        raise LedgerError(f"row {row_number} field {field!r} is not Unicode NFC")
    if any(unicodedata.category(char).startswith("C") for char in value):
        raise LedgerError(
            f"row {row_number} field {field!r} contains a Unicode category-C character"
        )


def parse_ledger(
    data: bytes, *, max_rows: int = DEFAULT_MAX_ROWS
) -> list[dict[str, str]]:
    max_rows = _bounded_int(max_rows, name="max_rows", lower=1, upper=HARD_MAX_ROWS)
    if not data or len(data) > MAX_LEDGER_BYTES:
        raise LedgerError(f"ledger size must be in [1, {MAX_LEDGER_BYTES}] bytes")
    try:
        text = data.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise LedgerError("ledger is not strict UTF-8") from exc
    if text.startswith("\ufeff") or "\x00" in text:
        raise LedgerError("ledger contains a BOM or NUL byte")
    reader = csv.reader(io.StringIO(text, newline=""), strict=True)
    try:
        header = next(reader)
    except (StopIteration, csv.Error) as exc:
        raise LedgerError("ledger is missing a valid header") from exc
    if tuple(header) != FIELDS:
        duplicates = sorted({field for field in header if header.count(field) > 1})
        detail = f"; duplicate keys={duplicates!r}" if duplicates else ""
        raise LedgerError(f"ledger header does not exactly match the schema{detail}")
    rows: list[dict[str, str]] = []
    seen: set[str] = set()
    previous: bytes | None = None
    try:
        for row_number, values in enumerate(reader, start=2):
            if len(rows) >= max_rows:
                raise LedgerError(f"ledger exceeds row limit {max_rows}")
            if len(values) != len(FIELDS):
                raise LedgerError(
                    f"row {row_number} has {len(values)} cells; expected {len(FIELDS)}"
                )
            row = dict(zip(FIELDS, values, strict=True))
            for field, value in row.items():
                _validate_cell(field, value, row_number=row_number)
            path = _validate_path(row["path"])
            if path in seen:
                raise LedgerError(f"duplicate ledger path: {path!r}")
            encoded_path = path.encode("utf-8")
            if previous is not None and encoded_path <= previous:
                raise LedgerError("ledger paths are not in canonical bytewise order")
            previous = encoded_path
            seen.add(path)
            rows.append(row)
    except csv.Error as exc:
        raise LedgerError(f"malformed CSV ledger: {exc}") from exc
    if not rows:
        raise LedgerError("ledger must contain at least one row")
    _validate_unique_paths(seen, label="ledger")
    if render_ledger(rows) != data:
        raise LedgerError("ledger CSV is not in the deterministic canonical encoding")
    return rows


def _validate_decimal(value: str, *, field: str, allow_empty: bool = True) -> None:
    if allow_empty and value == "":
        return
    if (
        not value.isascii()
        or not value.isdecimal()
        or (len(value) > 1 and value.startswith("0"))
    ):
        raise LedgerError(
            f"field {field!r} is not canonical unsigned decimal: {value!r}"
        )


def _validate_mutable_row(
    row: dict[str, str], *, require_assigned: bool, require_reviewed: bool
) -> None:
    path = row["path"]
    for field in (
        "generated",
        "public_surface",
        "security_critical",
        "science_critical",
        "authority_critical",
    ):
        if row[field] not in TRISTATE:
            raise LedgerError(f"invalid {field} classification for {path!r}")
    if row["review_status"] not in REVIEW_STATUSES:
        raise LedgerError(f"invalid review_status for {path!r}")
    if row["provenance_review_status"] not in PROVENANCE_STATUSES:
        raise LedgerError(f"invalid provenance_review_status for {path!r}")
    if row["license_review_status"] not in LICENSE_STATUSES:
        raise LedgerError(f"invalid license_review_status for {path!r}")
    assigned = row["reviewer"] not in {"", "UNASSIGNED"}
    if assigned:
        reviewer = row["reviewer"]
        if reviewer != reviewer.strip() or reviewer.casefold() in {
            "n/a",
            "none",
            "self",
            "tbd",
            "todo",
            "unknown",
            "unassigned",
        }:
            raise LedgerError(f"reviewer is not a valid named assignment for {path!r}")
    if require_assigned and not assigned:
        raise LedgerError(f"reviewer is not assigned for {path!r}")
    if row["completed_at"] and not RFC3339_UTC.fullmatch(row["completed_at"]):
        raise LedgerError(f"completed_at is not canonical UTC RFC3339 for {path!r}")
    if row["completed_at"]:
        try:
            datetime.strptime(row["completed_at"], "%Y-%m-%dT%H:%M:%SZ")
        except ValueError as exc:
            raise LedgerError(
                f"completed_at is not a real UTC date for {path!r}"
            ) from exc
    if row["completed_at"] and row["review_status"] != "REVIEWED":
        raise LedgerError(f"incomplete review has a completion time for {path!r}")
    if row["generated"] == "YES" and not row["generator"]:
        raise LedgerError(f"generated row lacks a generator for {path!r}")
    if row["generated"] == "NO" and row["generator"]:
        raise LedgerError(
            f"non-generated row names a contradictory generator for {path!r}"
        )
    if row["generated"] == "UNKNOWN" and row["generator"]:
        raise LedgerError(f"unresolved generated row names a generator for {path!r}")
    if (
        row["provenance_review_status"] in {"CONFIRMED", "REJECTED"}
        and not row["provenance_evidence"]
    ):
        raise LedgerError(f"provenance disposition lacks evidence for {path!r}")
    if (
        row["license_review_status"] in {"APPROVED", "REJECTED"}
        and not row["license_evidence"]
    ):
        raise LedgerError(f"license disposition lacks evidence for {path!r}")
    if row["license_review_status"] == "APPROVED" and not row["license_expression"]:
        raise LedgerError(f"approved license review lacks an expression for {path!r}")
    if row["review_status"] == "REVIEWED" or require_reviewed:
        if row["review_status"] != "REVIEWED":
            raise LedgerError(f"review is incomplete for {path!r}")
        if not assigned:
            raise LedgerError(f"reviewed row has no named reviewer: {path!r}")
        if not row["completed_at"] or not row["disposition"]:
            raise LedgerError(f"reviewed row lacks completion/disposition: {path!r}")
        if row["disposition"] not in {"ACCEPTED", "NOT_APPLICABLE"}:
            raise LedgerError(f"reviewed row has a non-accepting disposition: {path!r}")
        if any(row[field] == "UNKNOWN" for field in TRISTATE_FIELDS):
            raise LedgerError(f"reviewed row retains UNKNOWN classification: {path!r}")
        if row["provenance_review_status"] not in {"CONFIRMED", "NOT_APPLICABLE"}:
            raise LedgerError(f"reviewed row lacks accepted provenance: {path!r}")
        if row["license_review_status"] not in {"APPROVED", "NOT_APPLICABLE"}:
            raise LedgerError(f"reviewed row lacks accepted licensing: {path!r}")
        if any(
            row[field] == "YES"
            for field in (
                "public_surface",
                "security_critical",
                "science_critical",
                "authority_critical",
            )
        ) and (not row["requirements"] or not row["tests"] or not row["evidence"]):
            raise LedgerError(
                "critical/public reviewed row lacks requirement, test, or evidence "
                f"linkage: {path!r}"
            )
        language_exempt_formats = {
            "GITLINK_COMMIT_REFERENCE_UNVERIFIED",
            "SELF_REFERENTIAL_CSV",
            "SYMLINK_TARGET_BYTES",
        }
        if (
            row["language"] == "UNKNOWN"
            and row["format"] not in language_exempt_formats
            or row["format"] in {"UNKNOWN", "ABSENT"}
        ):
            raise LedgerError(
                f"reviewed row lacks language/format classification: {path!r}"
            )
        contradictory_format_prefixes = (
            "ANSI_ESCAPE_WITH_",
            "BINARY_WITH_",
            "CONTROL_BEARING_",
            "TEXT_WITH_",
        )
        if row["format"].startswith(contradictory_format_prefixes):
            raise LedgerError(
                f"reviewed row retains a content/format contradiction: {path!r}"
            )


TRISTATE_FIELDS = (
    "generated",
    "public_surface",
    "security_critical",
    "science_critical",
    "authority_critical",
)

ALLOWED_EXTERNAL_GENERATORS = frozenset(
    {"PINNED_CARGO_1.96.0_FROM_WORKSPACE_MANIFESTS"}
)


def _validate_generated_evolution(
    actual: dict[str, str], expected: dict[str, str]
) -> None:
    path = actual["path"]
    initial = expected["generated"]
    initial_generator = expected["generator"]
    if initial in {"YES", "NO"}:
        if actual["generated"] != initial or actual["generator"] != initial_generator:
            raise LedgerError(
                f"rule-proven generated classification changed for {path!r}"
            )
        return
    if initial != "UNKNOWN" or initial_generator:
        raise LedgerError(f"invalid initial generated classification for {path!r}")
    if actual["generated"] == "UNKNOWN":
        if actual["generator"]:
            raise LedgerError(
                f"unresolved generated row names a generator for {path!r}"
            )
        return
    if actual["generated"] not in {"YES", "NO"}:
        return
    if (
        actual["review_status"] != "REVIEWED"
        or actual["reviewer"] in {"", "UNASSIGNED"}
        or not actual["completed_at"]
        or actual["disposition"] not in {"ACCEPTED", "NOT_APPLICABLE"}
        or actual["provenance_review_status"] != "CONFIRMED"
        or not actual["provenance_evidence"]
    ):
        raise LedgerError(
            "resolving an initial UNKNOWN generated classification requires an "
            f"evidence-backed completed review for {path!r}"
        )


def _verify_rows(
    actual: Sequence[dict[str, str]],
    expected: Sequence[dict[str, str]],
    *,
    self_path: str,
    require_assigned: bool,
    require_reviewed: bool,
) -> None:
    if len(actual) != len(expected):
        raise LedgerError(
            f"ledger row count {len(actual)} does not match inventory {len(expected)}"
        )
    ledger_paths = {row["path"] for row in actual}
    for actual_row, expected_row in zip(actual, expected, strict=True):
        for field in IMMUTABLE_FIELDS:
            if actual_row[field] != expected_row[field]:
                raise LedgerError(
                    f"immutable field mismatch for {actual_row['path']!r}: {field!r}"
                )
        _validate_mutable_row(
            actual_row,
            require_assigned=require_assigned or require_reviewed,
            require_reviewed=require_reviewed,
        )
        _validate_generated_evolution(actual_row, expected_row)
        if (
            actual_row["generated"] == "YES"
            and actual_row["generator"] not in ledger_paths
            and actual_row["generator"] not in ALLOWED_EXTERNAL_GENERATORS
            and not (
                actual_row["path"] == self_path
                and actual_row["generator"]
                == "tools/release/current-file-review-ledger.py"
            )
        ):
            raise LedgerError(
                f"generated row names a missing generator: {actual_row['path']!r}"
            )
        for field in (
            "inventory_rows",
            "filesystem_entries",
            "source_bytes",
            "source_lines",
            "index_bytes",
            "index_lines",
            "current_bytes",
            "current_lines",
            "bytes",
            "lines",
        ):
            _validate_decimal(actual_row[field], field=field)


def _exact_commit(repo: Path, oid: str, *, label: str, deadline: Deadline) -> str:
    if not HEX_OID.fullmatch(oid):
        raise LedgerError(f"{label} must be a full lowercase Git object ID")
    resolved = (
        _run_git(
            repo,
            ["rev-parse", "--verify", "--end-of-options", f"{oid}^{{commit}}"],
            max_stdout=256,
            deadline=deadline,
        )
        .decode("ascii", "strict")
        .strip()
    )
    if resolved != oid:
        raise LedgerError(f"{label} did not resolve exactly: {oid!r} -> {resolved!r}")
    return resolved


def _parse_raw_commit_parents(
    data: bytes,
    *,
    oid: str,
    object_format: str,
) -> tuple[str, ...]:
    if _git_object_id(data, "commit", object_format) != oid:
        raise LedgerError(f"raw commit object does not match its object ID: {oid!r}")
    header_end = data.find(b"\n\n")
    if header_end < 0:
        raise LedgerError(f"raw commit object has no header terminator: {oid!r}")
    headers = data[:header_end].split(b"\n")
    expected_length = 40 if object_format == "sha1" else 64
    if not headers or not headers[0].startswith(b"tree "):
        raise LedgerError(f"raw commit object has no canonical tree header: {oid!r}")
    try:
        tree = headers[0][5:].decode("ascii", "strict")
    except UnicodeDecodeError as exc:
        raise LedgerError(f"raw commit tree is not ASCII: {oid!r}") from exc
    if len(tree) != expected_length or not HEX_OID.fullmatch(tree):
        raise LedgerError(f"raw commit tree has an invalid object ID: {oid!r}")
    parents: list[str] = []
    for header in headers[1:]:
        if header.startswith(b"tree "):
            raise LedgerError(f"raw commit has duplicate tree headers: {oid!r}")
        if not header.startswith(b"parent "):
            continue
        try:
            parent = header[7:].decode("ascii", "strict")
        except UnicodeDecodeError as exc:
            raise LedgerError(f"raw commit parent is not ASCII: {oid!r}") from exc
        if len(parent) != expected_length or not HEX_OID.fullmatch(parent):
            raise LedgerError(f"raw commit parent has an invalid object ID: {oid!r}")
        parents.append(parent)
    return tuple(parents)


def _raw_commit_parent_map(
    repo: Path,
    commits: Sequence[str],
    *,
    deadline: Deadline,
) -> dict[str, tuple[str, ...]]:
    if not commits:
        return {}
    if len(set(commits)) != len(commits):
        raise LedgerError("raw commit chain contains a repeated object ID")
    object_format = "sha1" if len(commits[0]) == 40 else "sha256"
    expected_length = 40 if object_format == "sha1" else 64
    for commit in commits:
        if len(commit) != expected_length or not HEX_OID.fullmatch(commit):
            raise LedgerError("raw commit chain contains an invalid object ID")
    raw = _run_git(
        repo,
        ["cat-file", "--batch"],
        max_stdout=MAX_GIT_INVENTORY_BYTES,
        deadline=deadline,
        input_data=b"".join(commit.encode("ascii") + b"\n" for commit in commits),
    )
    cursor = 0
    result: dict[str, tuple[str, ...]] = {}
    for expected in commits:
        line_end = raw.find(b"\n", cursor)
        if line_end < 0:
            raise LedgerError("unterminated Git cat-file batch header")
        fields = raw[cursor:line_end].split(b" ")
        if len(fields) != 3:
            raise LedgerError("malformed Git cat-file batch header")
        try:
            observed = fields[0].decode("ascii", "strict")
            object_type = fields[1].decode("ascii", "strict")
            size_text = fields[2].decode("ascii", "strict")
        except UnicodeDecodeError as exc:
            raise LedgerError("non-ASCII Git cat-file batch header") from exc
        if observed != expected or object_type != "commit" or not size_text.isdecimal():
            raise LedgerError("Git cat-file returned a contradictory commit object")
        size = int(size_text, 10)
        payload_start = line_end + 1
        payload_end = payload_start + size
        if payload_end >= len(raw) or raw[payload_end : payload_end + 1] != b"\n":
            raise LedgerError("truncated Git cat-file commit payload")
        payload = raw[payload_start:payload_end]
        result[expected] = _parse_raw_commit_parents(
            payload,
            oid=expected,
            object_format=object_format,
        )
        cursor = payload_end + 1
    if cursor != len(raw):
        raise LedgerError("unexpected trailing Git cat-file batch output")
    return result


def _commit_regular_blob(
    repo: Path,
    commit: str,
    path: str,
    *,
    maximum: int,
    deadline: Deadline,
) -> bytes:
    """Read an exact non-executable regular blob from a captured commit."""

    entries = _source_entries(repo, commit, deadline=deadline)
    entry = entries.get(path)
    if (
        entry is None
        or entry.mode != "100644"
        or entry.object_type != "blob"
        or entry.size is None
    ):
        raise LedgerError(
            "retention verification requires a 100644 ledger blob in the "
            f"captured current HEAD: {path!r}"
        )
    if entry.size > maximum:
        raise LedgerError(f"retained ledger blob exceeds {maximum} bytes")
    data = _run_git(
        repo,
        ["cat-file", "blob", entry.oid],
        max_stdout=maximum,
        deadline=deadline,
    )
    if len(data) != entry.size:
        raise LedgerError("retained ledger blob size does not match its tree entry")
    object_format = "sha1" if len(entry.oid) == 40 else "sha256"
    if _git_blob_id(data, object_format) != entry.oid:
        raise LedgerError("retained ledger blob does not match its Git object ID")
    return data


def _snapshot_inventory(
    repo: Path,
    source_commit: str,
    implementation_commit: str,
    *,
    self_path: str,
    ignored_policy: str,
    max_rows: int,
    max_file_bytes: int,
    max_total_bytes: int,
    max_seconds: float,
    deadline: Deadline,
) -> tuple[list[dict[str, str]], bytes, str, str]:
    source = _exact_commit(
        repo, source_commit, label="source commit", deadline=deadline
    )
    implementation = _exact_commit(
        repo,
        implementation_commit,
        label="implementation commit",
        deadline=deadline,
    )
    head = (
        _run_git(
            repo,
            ["rev-parse", "--verify", "HEAD^{commit}"],
            max_stdout=256,
            deadline=deadline,
        )
        .decode("ascii", "strict")
        .strip()
    )
    if not HEX_OID.fullmatch(head):
        raise LedgerError("current HEAD is not a full lowercase Git object ID")
    ancestry = (
        _run_git(
            repo,
            ["rev-list", "--first-parent", "--max-count=10001", head],
            max_stdout=700_000,
            deadline=deadline,
        )
        .decode("ascii", "strict")
        .splitlines()
    )
    if (
        len(ancestry) > 10_000
        or not ancestry
        or ancestry[0] != head
        or implementation not in ancestry
    ):
        raise LedgerError(
            "current HEAD must retain the implementation on its bounded first-parent chain"
        )
    for commit in ancestry:
        if len(commit) != len(head) or not HEX_OID.fullmatch(commit):
            raise LedgerError("Git returned an invalid first-parent object ID")
    implementation_index = ancestry.index(implementation)
    raw_chain = ancestry[: implementation_index + 1]
    raw_parents = _raw_commit_parent_map(
        repo,
        raw_chain,
        deadline=deadline,
    )
    for child, parent in zip(raw_chain, raw_chain[1:]):
        if raw_parents[child] != (parent,):
            raise LedgerError(
                "current HEAD raw first-parent chain must remain merge-free and "
                "must not use history overlays"
            )
    if raw_parents[implementation] != (source,):
        raise LedgerError(
            "implementation commit must be a single-parent child of the exact "
            "source commit in the raw commit graph"
        )

    with tempfile.TemporaryDirectory(prefix="haldir-ledger-snapshot-") as temporary:
        snapshot_repo = Path(temporary) / "repo"
        _run_git(
            repo,
            [
                "clone",
                "--quiet",
                "--local",
                "--no-hardlinks",
                "--no-checkout",
                os.path.abspath(os.fspath(repo)),
                os.fspath(snapshot_repo),
            ],
            max_stdout=1024 * 1024,
            deadline=deadline,
        )
        _run_git(
            snapshot_repo,
            ["checkout", "--quiet", "--detach", implementation],
            max_stdout=1024 * 1024,
            deadline=deadline,
        )
        status = _run_git(
            snapshot_repo,
            ["status", "--porcelain=v1", "-z", "--untracked-files=all"],
            deadline=deadline,
        )
        if status:
            raise LedgerError("implementation snapshot checkout is not clean")
        expected = build_inventory(
            snapshot_repo,
            source,
            ledger_self_path=self_path,
            ignored_policy=ignored_policy,
            max_rows=max_rows,
            max_file_bytes=max_file_bytes,
            max_total_bytes=max_total_bytes,
            max_seconds=max_seconds,
            _deadline=deadline,
        )
        with SecureRepository(snapshot_repo) as secure:
            reference_data = secure.read_regular(
                self_path, maximum=MAX_LEDGER_BYTES, deadline=deadline
            )
    return expected, reference_data, implementation, head


def _revalidate_ledger_pin(
    repo: Path,
    self_path: str,
    pinned: PinnedRegularSnapshot,
    *,
    deadline: Deadline,
) -> None:
    descriptor_before = os.fstat(pinned.descriptor)
    if not pinned.snapshot.matches_full_stat(descriptor_before):
        raise LedgerError("ledger changed during verification")
    current: PinnedRegularSnapshot | None = None
    try:
        with SecureRepository(repo) as secure:
            current = secure.pin_regular(
                self_path,
                maximum=MAX_LEDGER_BYTES,
                deadline=deadline,
            )
            descriptor_after = os.fstat(pinned.descriptor)
            current_descriptor = os.fstat(current.descriptor)
            if (
                current.snapshot != pinned.snapshot
                or current.snapshot.stat_identity != pinned.snapshot.stat_identity
                or not pinned.snapshot.matches_full_stat(descriptor_after)
                or not current.snapshot.matches_full_stat(current_descriptor)
            ):
                raise LedgerError("ledger changed during verification")
            restart_target, reserved_paths = secure.creation_restart_state(
                self_path,
                deadline=deadline,
            )
            _reject_reserved_creation_state(
                self_path,
                restart_target,
                reserved_paths,
            )
            if (
                restart_target is None
                or current.snapshot.stat_identity != _stat_identity(restart_target)
            ):
                raise LedgerError(
                    "ledger target changed during final restart-state verification"
                )
    finally:
        if current is not None:
            current.close()


def verify_ledger(
    repo: Path,
    source_commit: str,
    ledger: Path,
    *,
    ignored_policy: str = "reject",
    max_rows: int = DEFAULT_MAX_ROWS,
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
    max_seconds: float = DEFAULT_MAX_SECONDS,
    implementation_commit: str | None = None,
    require_assigned: bool = False,
    require_reviewed: bool = False,
    _deadline: Deadline | None = None,
) -> dict[str, str | int]:
    max_seconds = _bounded_float(
        max_seconds, name="max_seconds", lower=0.001, upper=HARD_MAX_SECONDS
    )
    deadline = _deadline or Deadline.after(max_seconds)
    lexical_repo = Path(os.path.abspath(os.fspath(repo)))
    repo = _bind_git_toplevel(repo, deadline=deadline)
    self_path = _repo_relative_file(lexical_repo, ledger)
    pinned: PinnedRegularSnapshot | None = None
    try:
        with SecureRepository(repo) as secure:
            existing, reserved_paths = secure.creation_restart_state(
                self_path,
                deadline=deadline,
            )
            _reject_reserved_creation_state(self_path, existing, reserved_paths)
            pinned = secure.pin_regular(
                self_path,
                maximum=MAX_LEDGER_BYTES,
                deadline=deadline,
            )
        if pinned is None:
            raise LedgerError("ledger pin was not acquired")
        return _verify_pinned_ledger(
            repo,
            source_commit,
            pinned=pinned,
            self_path=self_path,
            ignored_policy=ignored_policy,
            max_rows=max_rows,
            max_file_bytes=max_file_bytes,
            max_total_bytes=max_total_bytes,
            max_seconds=max_seconds,
            implementation_commit=implementation_commit,
            require_assigned=require_assigned,
            require_reviewed=require_reviewed,
            deadline=deadline,
        )
    finally:
        if pinned is not None:
            pinned.close()


def _verify_pinned_ledger(
    repo: Path,
    source_commit: str,
    *,
    pinned: PinnedRegularSnapshot,
    self_path: str,
    ignored_policy: str,
    max_rows: int,
    max_file_bytes: int,
    max_total_bytes: int,
    max_seconds: float,
    implementation_commit: str | None,
    require_assigned: bool,
    require_reviewed: bool,
    deadline: Deadline,
) -> dict[str, str | int]:
    data = pinned.snapshot.data
    deadline.check("parsing the ledger")
    actual = parse_ledger(data, max_rows=max_rows)
    reference_sha256: str | None = None
    exact_implementation: str | None = None
    retained_head: str | None = None
    if implementation_commit is None:
        expected = build_inventory(
            repo,
            source_commit,
            ledger_self_path=self_path,
            ignored_policy=ignored_policy,
            max_rows=max_rows,
            max_file_bytes=max_file_bytes,
            max_total_bytes=max_total_bytes,
            max_seconds=max_seconds,
            _deadline=deadline,
        )
        deadline.check("starting the repeated current-view verification inventory")
        repeated_expected = build_inventory(
            repo,
            source_commit,
            ledger_self_path=self_path,
            ignored_policy=ignored_policy,
            max_rows=max_rows,
            max_file_bytes=max_file_bytes,
            max_total_bytes=max_total_bytes,
            max_seconds=max_seconds,
            _deadline=deadline,
        )
        if render_ledger(repeated_expected) != render_ledger(expected):
            raise LedgerError(
                "source, index, or worktree changed between independent "
                "current-view verification inventory passes"
            )
    else:
        expected, reference_data, exact_implementation, retained_head = (
            _snapshot_inventory(
                repo,
                source_commit,
                implementation_commit,
                self_path=self_path,
                ignored_policy=ignored_policy,
                max_rows=max_rows,
                max_file_bytes=max_file_bytes,
                max_total_bytes=max_total_bytes,
                max_seconds=max_seconds,
                deadline=deadline,
            )
        )
        retained_data = _commit_regular_blob(
            repo,
            retained_head,
            self_path,
            maximum=MAX_LEDGER_BYTES,
            deadline=deadline,
        )
        if data != retained_data:
            raise LedgerError(
                "retention verification requires ledger bytes identical to the "
                "captured current-HEAD blob"
            )
        reference = parse_ledger(reference_data, max_rows=max_rows)
        _verify_rows(
            reference,
            expected,
            self_path=self_path,
            require_assigned=False,
            require_reviewed=False,
        )
        reference_sha256 = hashlib.sha256(reference_data).hexdigest()
    _verify_rows(
        actual,
        expected,
        self_path=self_path,
        require_assigned=require_assigned,
        require_reviewed=require_reviewed,
    )
    result: dict[str, str | int] = {
        "inventory_digest": expected[0]["inventory_digest"],
        "ledger_bytes": len(data),
        "ledger_sha256": hashlib.sha256(data).hexdigest(),
        "rows": len(actual),
        "source_commit": expected[0]["source_commit"],
        "source_tree": expected[0]["source_tree"],
    }
    if (
        exact_implementation is not None
        and reference_sha256 is not None
        and retained_head is not None
    ):
        result["implementation_commit"] = exact_implementation
        result["implementation_ledger_sha256"] = reference_sha256
        result["retained_head_commit"] = retained_head
        result["verification_view"] = "EXACT_IMPLEMENTATION_SNAPSHOT"
    else:
        result["verification_view"] = "CURRENT_INDEX_AND_WORKTREE"
    _revalidate_ledger_pin(
        repo,
        self_path,
        pinned,
        deadline=deadline,
    )
    return result


def _add_common_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--repo", type=Path, default=Path("."))
    parser.add_argument("--source-commit", required=True)
    parser.add_argument(
        "--ignored-policy", choices=sorted(IGNORED_POLICIES), default="reject"
    )
    parser.add_argument("--max-rows", type=int, default=DEFAULT_MAX_ROWS)
    parser.add_argument("--max-file-bytes", type=int, default=DEFAULT_MAX_FILE_BYTES)
    parser.add_argument("--max-total-bytes", type=int, default=DEFAULT_MAX_TOTAL_BYTES)
    parser.add_argument("--max-seconds", type=float, default=DEFAULT_MAX_SECONDS)


def _argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    generate = subparsers.add_parser("generate", help="generate an unreviewed ledger")
    _add_common_arguments(generate)
    generate.add_argument("--output", type=Path, required=True)
    verify = subparsers.add_parser("verify", help="verify inventory and review fields")
    _add_common_arguments(verify)
    verify.add_argument("--ledger", type=Path, required=True)
    verify.add_argument(
        "--implementation-commit",
        help="verify retained immutable fields against this exact implementation snapshot",
    )
    verify.add_argument("--require-assigned", action="store_true")
    verify.add_argument("--require-reviewed", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _argument_parser().parse_args(argv)
    try:
        if (
            not sys.flags.isolated
            or not sys.flags.safe_path
            or sys.version_info[:3] != (3, 14, 6)
        ):
            raise LedgerError("CPython 3.14.6 isolated safe-path mode is required")
        if arguments.command == "generate":
            result = generate_ledger(
                arguments.repo,
                arguments.source_commit,
                arguments.output,
                ignored_policy=arguments.ignored_policy,
                max_rows=arguments.max_rows,
                max_file_bytes=arguments.max_file_bytes,
                max_total_bytes=arguments.max_total_bytes,
                max_seconds=arguments.max_seconds,
            )
        else:
            result = verify_ledger(
                arguments.repo,
                arguments.source_commit,
                arguments.ledger,
                ignored_policy=arguments.ignored_policy,
                max_rows=arguments.max_rows,
                max_file_bytes=arguments.max_file_bytes,
                max_total_bytes=arguments.max_total_bytes,
                max_seconds=arguments.max_seconds,
                implementation_commit=arguments.implementation_commit,
                require_assigned=arguments.require_assigned,
                require_reviewed=arguments.require_reviewed,
            )
    except (LedgerError, OSError, UnicodeError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
